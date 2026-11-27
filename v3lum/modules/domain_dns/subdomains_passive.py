"""Keyless passive subdomain aggregation (P016): THC ip.thc.org (this default module) and the shared
engine of ``subdomains_passive_extra`` (AnubisDB, Subdomain Center, subdomain.app, ScanMalware, and
the myssl.com / RapidDNS toggles).

Final conditions (council #1, P016) and where they live:

1. One adapter per source, each with its own budget/pacing (the provider ``http_profile``
   ``min_interval`` plus the provider ``quota`` token bucket, enforced by the core per provider = per
   source) and its own status (``res.source_status``): a blocked source is BLOCKED, never zero names,
   and coverage reads 'k/N sources answered' (attribute ``subdomain_coverage``). Adapters run
   concurrently inside one 30 s budget (setting ``subdomains_passive_budget``); runs once per
   registrable domain (a subdomain entity is not applicable).
2. THC: ``POST /api/v1/lookup/subdomains`` ``{domain, limit, page_state}`` -> ``{domains[{domain,
   last_seen_on}], next_page_state}``; loop while ``next_page_state`` is set, at most 10 pages
   (``max_requests`` 10); paging stops when ``x-ratelimit-remaining`` runs out (partial
   'rate_limited'); 429 = RATE_LIMITED; ``last_seen_on`` older than 365 days flags a stale host.
3./4. The extra module and its per-feed terms/tiers: provider fragments under v3lum/data/providers/.
5. Every name goes through the P001 shared hostname sink (:class:`HostnameSink` of ``ct_logs``:
   Entity + PSL/IANA TLD validation, label-boundary apex match, provenance) and is recorded in the
   core attribute ``subdomains``, which the case graph merges with ct_logs into one deduplicated
   list; ``subdomain_provenance`` carries the per-name sources. Per-source cap 5000 names; partial
   flags are honoured (``Feed.partial_reasons``).
6. Wildcard detection: ``ctx.dns.wildcard_info`` (P029) plus a second random 16-character label;
   answers are compared (a zone answering NOERROR/NODATA for random labels - Cloudflare - is not a
   wildcard, it only never says NXDOMAIN). Names resolving only to wildcard answers are dropped. DoH
   resolution is capped at 300 names per run (telling labels first); the rest stay unresolved.
7. Names seen only in one unknown-tier or noisy source are 'unconfirmed' unless they resolve
   (non-wildcard) or a second source agrees: listed apart (``subdomains_unconfirmed``), never assets.
   NXDOMAIN (confirmed by a second resolver) = historical; DoH errors/timeouts = unresolved (rule 5).
8. Only resolving, confirmed, non-CDN-only names pivot (cap 12, telling labels vpn, sso, mail,
   admin, dev, api first); pivots are domains, which the engine investigates with passive modules
   only (LIGHT/ACTIVE never run on pivots, A7). Names resolving to private, CGNAT, loopback or
   link-local addresses give a LOW 'Internal address in public DNS' finding and never pivot.
9. Challenge pages are BLOCKED 'challenge' (core P321 classification) and never retried with another
   UA or identity (A9); the extra module demotes a source after 5 consecutive blocked runs.
10. Each adapter ships its own trimmed fixture under tests/fixtures/<module>/.

No code was copied from subfinder, theHarvester or any GPL/AGPL project: the THC client was written
from the research record (C0020) and the live answers of 2026-11-26.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import re
import secrets
import string
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core import noise, psl
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
from v3lum.modules.domain_dns.ct_logs import HostnameSink, in_apex, looks_like_html, registrable

__all__ = [
    "DEFAULT_BUDGET",
    "DOH_NAME_CAP",
    "PER_SOURCE_CAP",
    "PIVOT_CAP",
    "SRC_THC",
    "STALE_DAYS",
    "TELLING_LABELS",
    "THC_URL",
    "Feed",
    "PassiveRun",
    "SubdomainsPassive",
    "UnexpectedAnswer",
    "address_kind",
    "classify_answers",
    "confirmed",
    "is_registrable_apex",
    "label_priority",
    "parse_thc_page",
    "resolution_order",
    "run_feed",
    "wildcard_state",
]

SRC_THC = "thc.subdomains"
THC_URL = "https://ip.thc.org/api/v1/lookup/subdomains"
THC_PAGE_LIMIT = 1000
THC_MAX_PAGES = 10
PER_SOURCE_CAP = 5000  # P016 cond 5
RAW_ITEM_CAP = 60_000  # raw entries read from one answer before the 5000-name cap (AnubisDB: 22k names)
DOH_NAME_CAP = 300  # P016 cond 6
PIVOT_CAP = 12  # P016 cond 8 (engine cap)
TELLING_LABELS = ("vpn", "sso", "mail", "admin", "dev", "api")  # P016 cond 8, in this order
STALE_DAYS = 365
DEFAULT_BUDGET = 30.0  # P016 cond 1
MIN_BUDGET = 8.0
MAX_BUDGET = 60.0
RESOLUTION_RESERVE = 6.0  # seconds of the budget kept for the DoH phase after the adapters
QUERY_GUARD = 1.0  # do not start a DoH query with less than this left in the budget
RESOLVE_WORKERS = 8
CACHE_TTL = 86400
ATTR_CAP = 5000
UNCONFIRMED_CAP = 500
PROVENANCE_CAP = 1000
EVIDENCE_NAME_CAP = 2000
INTERNAL_FINDING_CAP = 20
WILDCARD_LABEL_LEN = 16

#: states a name can end in (attribute subdomain_provenance)
RESOLVING_STATES = frozenset({"live", "internal"})

#: P016 cond 8: internal ranges as an explicit table (``ipaddress.is_private`` also covers the
#: documentation ranges, which are not internal networks). CGNAT (RFC 6598 shared address space,
#: also used by overlay VPNs) counts as internal: it is never reachable from the Internet.
_INTERNAL_NETS: tuple[tuple[str, Any], ...] = tuple(
    (kind, ipaddress.ip_network(net))
    for kind, net in (
        ("private", "10.0.0.0/8"),
        ("private", "172.16.0.0/12"),
        ("private", "192.168.0.0/16"),
        ("private", "fc00::/7"),
        ("cgnat", "100.64.0.0/10"),
        ("loopback", "127.0.0.0/8"),
        ("loopback", "::1/128"),
        ("link_local", "169.254.0.0/16"),
        ("link_local", "fe80::/10"),
    )
)
_INTERNAL_KINDS = frozenset({"private", "cgnat", "loopback", "link_local"})
_NULL_ADDRESSES = frozenset({"0.0.0.0", "::"})

# ======================================================================================
# small helpers
# ======================================================================================


def _now(ctx: Any) -> datetime:
    try:
        now = ctx.now()
    except Exception:  # noqa: BLE001 - a context without a clock (direct helper tests)
        now = None
    return now if isinstance(now, datetime) else datetime.now(timezone.utc)


def _mono(ctx: Any) -> float:
    clock = getattr(getattr(ctx, "http", None), "clock", None)
    try:
        return float(clock.monotonic()) if clock is not None else time.monotonic()
    except Exception:  # noqa: BLE001
        return time.monotonic()


def _float_setting(ctx: Any, name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(ctx.setting(name, default))
    except (TypeError, ValueError):
        value = default
    return max(low, min(high, value))


def _int_setting(ctx: Any, name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(ctx.setting(name, default))
    except (TypeError, ValueError):
        value = default
    return max(low, min(high, value))


def _text(raw: Any) -> str:
    if isinstance(raw, (bytes, bytearray, memoryview)):
        text = bytes(raw).decode("utf-8", "replace")
    elif isinstance(raw, str):
        text = raw
    else:
        return ""
    return text[1:] if text.startswith("﻿") else text


def _short(value: Any, limit: int = 160) -> str:
    text = re.sub(r"[\x00-\x1f\x7f-\x9f]+", " ", str(value or "")).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _header_int(headers: Any, name: str) -> int | None:
    try:
        value = (headers or {}).get(name)
    except AttributeError:
        return None
    try:
        return int(str(value).strip()) if value is not None else None
    except ValueError:
        return None


def parse_day(value: Any) -> date | None:
    """'YYYY-MM-DD' (or an ISO date-time) -> date; None when absent or invalid."""
    if not isinstance(value, str):
        return None
    m = re.match(r"^\s*(\d{4})-(\d{2})-(\d{2})", value)
    if not m:
        return None
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def is_registrable_apex(name: str) -> bool:
    """P016 cond 1: the module runs once per registrable domain (a known TLD and name == eTLD+1)."""
    name = str(name or "").strip().lower().rstrip(".")
    if not name or "." not in name:
        return False
    return psl.is_known_tld(name.rsplit(".", 1)[-1]) and registrable(name) == name


class UnexpectedAnswer(Exception):
    """A source answered something that is not its documented shape: could not verify."""


# ======================================================================================
# per-source outcome and runner (rule 5: every failure is 'could not verify', never zero names)
# ======================================================================================


@dataclass
class Feed:
    """What one passive source returned inside the shared budget."""

    source: str  # registry source id
    label: str  # human label (coverage line, evidence)
    noisy: bool = False  # unknown-tier or noisy feed: single-source names stay unconfirmed (cond 7)
    status: str = "not_run"  # ok | empty | error | timeout | rate_limited | quota | blocked | skipped | not_run
    reason: str = ""
    reason_code: str = ""
    partial: bool = False
    partial_reasons: list[str] = field(default_factory=list)
    pages: int = 0
    raw_count: int = 0
    capped: int = 0
    sink: HostnameSink | None = None
    attrs: dict[str, dict[str, Any]] = field(default_factory=dict)  # name -> per-source facts
    meta: dict[str, Any] = field(default_factory=dict)
    stop: BaseException | None = None  # Cancelled / RequestCapReached re-raised after merging

    @property
    def answered(self) -> bool:
        return self.status in ("ok", "empty")

    @property
    def failed(self) -> bool:
        return self.status in ("error", "timeout", "rate_limited", "quota", "blocked")

    def flag(self, reason: str) -> None:
        """Mark the answer partial (cap, truncated answer, provider partial flag...)."""
        self.partial = True
        if reason and reason not in self.partial_reasons:
            self.partial_reasons.append(reason)

    def add(self, raw: Any, attrs: Mapping[str, Any] | None = None) -> str | None:
        """Put one raw name through the shared hostname sink with this source's provenance, keeping
        the per-source cap of 5000 in-apex names. Returns the kept label or None."""
        if self.sink is None:
            return None
        self.raw_count += 1
        if self.raw_count > RAW_ITEM_CAP:
            self.capped += 1
            self.flag("name_cap")
            return None
        candidate = raw.strip().lower().rstrip(".") if isinstance(raw, str) else raw
        if isinstance(candidate, str) and candidate.startswith("*."):
            candidate_name = candidate[2:]
        else:
            candidate_name = candidate
        known = isinstance(candidate_name, str) and (candidate_name in self.sink.names or candidate_name in self.sink.wildcards)
        if not known and len(self.sink.names) + len(self.sink.wildcards) >= PER_SOURCE_CAP:
            self.capped += 1
            self.flag("name_cap")
            return None
        label = self.sink.add(raw, self.source)
        if label and attrs and not label.startswith("*.") and in_apex(label, self.sink.apex):
            _merge_attrs(self.attrs.setdefault(label, {}), attrs)
        return label

    @property
    def names(self) -> list[str]:
        return self.sink.subdomains() if self.sink is not None else []

    @property
    def wildcards(self) -> list[str]:
        return self.sink.wildcard_labels() if self.sink is not None else []


def _merge_attrs(dst: dict[str, Any], attrs: Mapping[str, Any]) -> None:
    for key, value in attrs.items():
        if value is None or value == "" or value == [] or value == {}:
            continue
        if isinstance(value, list):
            current = dst.setdefault(key, [])
            if isinstance(current, list):
                for item in value:
                    if item not in current and len(current) < 20:
                        current.append(item)
        elif key not in dst:
            dst[key] = value


STATUS_FOR: dict[str, Status] = {
    "error": Status.ERROR,
    "timeout": Status.ERROR,
    "rate_limited": Status.RATE_LIMITED,
    "quota": Status.QUOTA,
    "blocked": Status.BLOCKED,
}
FAILURE_ORDER = ("rate_limited", "quota", "blocked", "timeout", "error")


def run_feed(feed: Feed, fn: Callable[[Feed], None]) -> Feed:
    """Run ``fn(feed)`` and translate the core's exceptions into the feed outcome. A failure after
    data was collected (a later page) keeps the data, flagged partial; Cancelled/RequestCapReached are
    kept in ``feed.stop`` so the module re-raises them after merging (the engine keeps the partial
    result). PolicyError/ConfigError propagate (SKIPPED by the engine)."""

    def keep_partial(status: str, reason: str, code: str, partial_reason: str) -> None:
        has_data = feed.sink is not None and bool(feed.sink.names or feed.sink.wildcards)
        feed.reason, feed.reason_code = reason, code
        if has_data:
            feed.status = "ok"
            feed.flag(partial_reason)
        else:
            feed.status = status

    try:
        fn(feed)
    except Cancelled as exc:
        feed.stop = exc
        keep_partial("error", f"{feed.label}: stopped (kill switch or scan deadline)", "error", "cancelled")
    except RequestCapReached as exc:
        keep_partial("error", f"{feed.label}: request cap reached ({_short(exc)})", "error", "request_cap")
    except RateLimited as exc:
        keep_partial("rate_limited", f"{feed.label}: rate limited ({_short(exc)}): could not verify", "rate_limited", "rate_limited")
    except QuotaExceeded as exc:
        keep_partial("quota", f"{feed.label}: quota exhausted ({_short(exc)}): could not verify", "quota", "quota")
    except Blocked as exc:
        code = str(getattr(exc, "reason_code", "") or "challenge")
        if code not in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host"):
            code = "challenge"
        keep_partial("blocked", f"{feed.label}: blocked ({_short(exc)}): could not verify", code, "blocked")
    except AuthRequired as exc:  # keyless sources: a 401/403 is a refusal, never 'no names' (rule 5)
        keep_partial("blocked", f"{feed.label}: refused the keyless request ({_short(exc)}): could not verify", "challenge", "blocked")
    except DeadlineExceeded as exc:
        keep_partial("timeout", f"{feed.label}: no answer within the budget ({_short(exc)}): could not verify", "timeout", "deadline")
    except (PolicyError, ConfigError):
        raise
    except NetworkError as exc:
        kind = str(getattr(exc, "kind", "") or "").lower()
        timed_out = "timeout" in kind or "timed out" in str(exc).lower()
        keep_partial("timeout" if timed_out else "error", f"{feed.label}: {_short(exc)}: could not verify",
                     "timeout" if timed_out else "error", "page_failed")
    except HttpError as exc:
        code = str(getattr(exc, "reason_code", "") or "error")
        keep_partial("timeout" if code == "timeout" else "error", f"{feed.label}: {_short(exc)}: could not verify",
                     code if code in ("timeout", "error") else "error", "page_failed")
    except UnexpectedAnswer as exc:
        keep_partial("error", f"{feed.label}: {_short(exc)}: could not verify", "error", "page_failed")
    except Exception as exc:  # noqa: BLE001 - untrusted data: a parser surprise is 'could not verify', never a crash
        keep_partial("error", f"{feed.label}: unexpected answer ({type(exc).__name__}): could not verify", "error", "page_failed")
    if feed.status == "not_run":
        feed.status = "ok" if (feed.sink is not None and (feed.sink.names or feed.sink.wildcards)) else "empty"
    return feed


def record_feed_status(res: ModuleResult, feed: Feed) -> None:
    """Per-feed outcome in ``res.source_statuses`` (P016 cond 1: a blocked feed is BLOCKED, never zero names)."""
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
# THC (P016 cond 2)
# ======================================================================================


def parse_thc_page(raw: Any) -> dict[str, Any]:
    """One THC lookup page -> ``{domains: [(name, last_seen_on)], next, matching_records,
    processed_domain}``. HTML, malformed JSON, a non-object body or an error object instead of the
    documented shape raise :class:`UnexpectedAnswer` (could not verify, never 'no names')."""
    text = _text(raw).strip()
    if not text:
        raise UnexpectedAnswer("empty body instead of a THC lookup object")
    if looks_like_html(text):
        raise UnexpectedAnswer("HTML instead of JSON")
    try:
        obj = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise UnexpectedAnswer("malformed JSON (answer cut or corrupted)") from exc
    if not isinstance(obj, dict):
        raise UnexpectedAnswer(f"{type(obj).__name__} instead of a THC lookup object")
    domains = obj.get("domains")
    if domains is None and obj.get("error"):
        raise UnexpectedAnswer(f"THC error object in HTTP 200: {_short(obj.get('error'), 120)}")
    if not isinstance(domains, list):
        raise UnexpectedAnswer("THC answer without a 'domains' list")
    rows: list[tuple[Any, str | None]] = []
    for item in domains:
        if isinstance(item, str):
            rows.append((item, None))
        elif isinstance(item, dict):
            seen = parse_day(item.get("last_seen_on"))
            rows.append((item.get("domain"), seen.isoformat() if seen else None))
    cursor = obj.get("next_page_state")
    total = obj.get("matching_records")
    processed = obj.get("processed_domain")
    return {
        "domains": rows,
        "next": cursor if isinstance(cursor, str) and cursor.strip() else None,
        "matching_records": total if isinstance(total, int) and not isinstance(total, bool) else None,
        "processed_domain": processed if isinstance(processed, str) else None,
    }


def _thc_cacheable(resp: Any) -> bool:
    """Cache only a real THC page (never an error object, HTML or a cut body)."""
    try:
        parse_thc_page(getattr(resp, "content", b""))
    except UnexpectedAnswer:
        return False
    return getattr(resp, "status", 0) == 200


def fetch_thc(feed: Feed, ctx: Any, apex: str, deadline: float, *, max_pages: int = THC_MAX_PAGES) -> None:
    """P016 cond 2: cursor paging of the THC lookup, at most ``max_pages`` pages."""
    feed.sink = HostnameSink(apex)
    today = _now(ctx).date()
    cursor: str | None = None
    for page in range(max_pages):
        if page and deadline - _mono(ctx) < 2.0:
            feed.flag("deadline")
            feed.reason = f"THC paging stopped by the time budget after {page} page(s)"
            return
        body: dict[str, Any] = {"domain": apex, "limit": THC_PAGE_LIMIT}
        if cursor:
            body["page_state"] = cursor
        resp = ctx.http.post(THC_URL, json_body=body, source=SRC_THC, ttl=CACHE_TTL, deadline=deadline, cache_if=_thc_cacheable)
        ctx.http.check(resp)  # 429 -> RateLimited, challenge -> Blocked, 5xx -> HttpError (could not verify)
        parsed = parse_thc_page(resp.content)
        feed.pages += 1
        if parsed["matching_records"] is not None:
            feed.meta["matching_records"] = parsed["matching_records"]
        for name, seen in parsed["domains"]:
            seen_day = parse_day(seen)
            stale = bool(seen_day and (today - seen_day).days > STALE_DAYS)
            feed.add(name, {"last_seen": seen, "stale": stale if seen_day else None})
        remaining = _header_int(getattr(resp, "headers", None), "x-ratelimit-remaining")
        if remaining is not None:
            feed.meta["ratelimit_remaining"] = remaining
        cursor = parsed["next"]
        if not cursor:
            return  # last page: complete
        if feed.capped or (feed.sink is not None and len(feed.sink.names) >= PER_SOURCE_CAP):
            feed.flag("name_cap")
            return
        if remaining is not None and remaining <= 1:
            feed.flag("rate_limited")  # x-ratelimit-remaining honoured (cond 2): more pages exist
            feed.reason = "THC x-ratelimit-remaining exhausted: paging stopped (more names exist)"
            return
    if cursor:
        feed.flag("request_cap")
        feed.reason = f"THC page cap reached ({max_pages} pages): more names exist"


# ======================================================================================
# DoH resolution, wildcard detection, confirmation (P016 cond 6-8)
# ======================================================================================


def address_kind(value: Any) -> str:
    """'private' | 'cgnat' | 'loopback' | 'link_local' | 'null' | 'public' | 'invalid' for one address."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return "invalid"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if str(ip) in _NULL_ADDRESSES:
        return "null"
    for kind, net in _INTERNAL_NETS:
        if ip.version == net.version and ip in net:
            return kind
    return "public"


def _random_label() -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(WILDCARD_LABEL_LEN))


def _probe_outcome(answers: list[Any]) -> tuple[str, list[str]]:
    """One random-label probe (A, then AAAA) -> ('records' | 'nxdomain' | 'nodata' | 'failed', answers)."""
    records: list[str] = []
    for ans in answers:
        if getattr(ans, "ok", False):
            records.extend(str(r) for r in list(getattr(ans, "records", []) or []) + list(getattr(ans, "cnames", []) or []))
    if records:
        return "records", sorted(set(records))
    if answers and all(getattr(a, "nxdomain", False) for a in answers):
        return "nxdomain", []
    if any(getattr(a, "could_not_verify", True) for a in answers):
        return "failed", []
    return "nodata", []


def wildcard_state(first: tuple[str, list[str]], second: tuple[str, list[str]]) -> dict[str, Any]:
    """P016 cond 6: compare two random-label probes.

    ``state``: 'wildcard' (random labels get records; ``answers`` = union of their addresses and
    CNAME targets), 'none' (both NXDOMAIN, or NOERROR/NODATA: ``nodata_quirk`` - the zone never says
    NXDOMAIN, so NODATA proves nothing there) or 'unknown' (a probe failed or the probes contradict
    each other: resolution then never confirms a single-source name)."""
    kinds = {first[0], second[0]}
    answers = sorted(set(first[1]) | set(second[1]))
    if kinds == {"records"}:
        stable = bool(set(first[1]) & set(second[1]))
        return {"state": "wildcard", "answers": answers, "nodata_quirk": False,
                "reason": "random labels resolve" + ("" if stable else " (answers differ between the probes)")}
    if "records" in kinds:
        if "nxdomain" in kinds:
            return {"state": "unknown", "answers": answers, "nodata_quirk": False,
                    "reason": "one random label resolved and the other answered NXDOMAIN: could not verify"}
        return {"state": "wildcard", "answers": answers, "nodata_quirk": False, "reason": "a random label resolves"}
    if "failed" in kinds:
        return {"state": "unknown", "answers": [], "nodata_quirk": False, "reason": "wildcard probe could not be verified"}
    if kinds == {"nxdomain"}:
        return {"state": "none", "answers": [], "nodata_quirk": False, "reason": "random labels answer NXDOMAIN"}
    return {"state": "none", "answers": [], "nodata_quirk": True,
            "reason": "random labels answer NOERROR/NODATA: the zone never says NXDOMAIN (not a wildcard)"}


def probe_wildcard(ctx: Any, apex: str) -> dict[str, Any]:
    """Two random 16-character labels: ``ctx.dns.wildcard_info`` (P029) and one more probe here."""
    first: tuple[str, list[str]]
    try:
        info = ctx.dns.wildcard_info(apex)
        if info.wildcard is True:
            first = ("records", sorted(str(r) for r in info.records))
        elif info.wildcard is False:
            first = ("nxdomain", [])
        elif getattr(info, "nodata", False):
            first = ("nodata", [])
        else:
            first = ("failed", [])
    except (Cancelled, DeadlineExceeded, RequestCapReached):
        raise
    except Exception:  # noqa: BLE001 - a resolver problem is 'could not verify'
        first = ("failed", [])
    label = f"{_random_label()}.{apex}"
    try:
        answers = [ctx.dns.query(label, "A")]
        if answers[0].ok and not (answers[0].records or answers[0].cnames):
            answers.append(ctx.dns.query(label, "AAAA"))
        second = _probe_outcome(answers)
    except (Cancelled, DeadlineExceeded, RequestCapReached):
        raise
    except Exception:  # noqa: BLE001
        second = ("failed", [])
    out = wildcard_state(first, second)
    out["probes"] = [first[0], second[0]]
    return out


def classify_answers(a: Any, aaaa: Any = None, *, confirmed_nx: bool | None = None, wildcard: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """State of one name from its DoH answers (P016 cond 6-8).

    live | internal (private/CGNAT/loopback/link-local: LOW finding, never pivoted) | null_address
    (0.0.0.0/::) | wildcard_only (only wildcard answers: dropped) | no_address (NOERROR/NODATA) |
    historical (NXDOMAIN confirmed by a second resolver) | unresolved (SERVFAIL, timeouts, refusals,
    an unconfirmed NXDOMAIN: could not verify)."""
    answers = [x for x in (a, aaaa) if x is not None]
    addresses: list[str] = []
    cnames: list[str] = []
    for ans in answers:
        if getattr(ans, "ok", False):
            for r in getattr(ans, "records", []) or []:
                if address_kind(r) != "invalid" and str(r) not in addresses:
                    addresses.append(str(r))
            for c in getattr(ans, "cnames", []) or []:
                if str(c) not in cnames:
                    cnames.append(str(c))
    base = {"addresses": addresses[:8], "cnames": cnames[:4]}
    if not addresses:
        if a is not None and getattr(a, "nxdomain", False):
            if confirmed_nx is True:
                return {**base, "state": "historical", "basis": "NXDOMAIN (confirmed by a second resolver)"}
            return {**base, "state": "unresolved", "basis": "NXDOMAIN not confirmed by a second resolver: could not verify"}
        failures = [x for x in answers if getattr(x, "could_not_verify", True)]
        if failures:
            return {**base, "state": "unresolved", "basis": _short(getattr(failures[0], "error", "") or getattr(failures[0], "status", ""), 120) or "could not verify"}
        quirk = bool(wildcard and wildcard.get("nodata_quirk"))
        return {**base, "state": "no_address",
                "basis": "NOERROR/NODATA" + (" (the zone answers NODATA for names that do not exist)" if quirk else "")}
    kinds = {x: address_kind(x) for x in addresses}
    internal = [x for x, k in kinds.items() if k in _INTERNAL_KINDS]
    if internal:
        return {**base, "state": "internal", "internal": internal, "kinds": sorted({kinds[x] for x in internal}),
                "basis": "internal address in public DNS"}
    if all(k == "null" for k in kinds.values()):
        return {**base, "state": "null_address", "basis": "0.0.0.0 / :: (placeholder or sinkhole)"}
    if wildcard and wildcard.get("state") == "wildcard":
        wset = set(wildcard.get("answers") or [])
        if set(addresses) <= wset or (cnames and set(cnames) <= wset):
            return {**base, "state": "wildcard_only", "basis": "only the zone's wildcard answers"}
    return {**base, "state": "live", "basis": "resolves"}


def resolve_one(ctx: Any, name: str, wildcard: Mapping[str, Any]) -> dict[str, Any]:
    """A first, AAAA when A has no address, a second resolver for NXDOMAIN (P029 confirm_nxdomain)."""
    a = ctx.dns.query(name, "A")
    aaaa = None
    confirmed_nx: bool | None = None
    if a.ok and not a.records:
        aaaa = ctx.dns.query(name, "AAAA")
    elif a.nxdomain:
        confirmed_nx = ctx.dns.confirm_nxdomain(name, "A")
    return classify_answers(a, aaaa, confirmed_nx=confirmed_nx, wildcard=wildcard)


def label_priority(name: str, apex: str) -> tuple[int, int, str]:
    """P016 cond 8 ordering key: telling labels (vpn, sso, mail, admin, dev, api, in that order) on any
    label left of the apex (prefix + digits: vpn2, mail-01), then shallow names, then alphabetical."""
    left = name[: -len(apex) - 1] if apex and name.endswith("." + apex) else name
    parts = [p for p in re.split(r"[.\-]", left) if p]
    for idx, lab in enumerate(TELLING_LABELS):
        if any(p == lab or (p.startswith(lab) and p[len(lab):].isdigit()) for p in parts):
            return (idx, left.count("."), name)
    return (len(TELLING_LABELS), left.count("."), name)


def resolution_order(names: Iterable[str], apex: str, cap: int = DOH_NAME_CAP) -> tuple[list[str], list[str]]:
    """P016 cond 6: (names to resolve, deferred) - telling labels first, capped at ``cap`` per run."""
    ordered = sorted({n for n in names if isinstance(n, str)}, key=lambda n: label_priority(n, apex))
    return ordered[:cap], ordered[cap:]


def confirmed(sources: Iterable[str], state: str, wildcard: str, noisy: Iterable[str]) -> bool:
    """P016 cond 7: a name is unconfirmed when its ONLY source is an unknown-tier/noisy feed and it does
    not resolve (non-wildcard; a wildcard probe that could not be verified confirms nothing)."""
    distinct = {s for s in sources if s}
    if len(distinct) >= 2:
        return True
    if not distinct:
        return False
    only = next(iter(distinct))
    if only not in set(noisy):
        return True
    return state in RESOLVING_STATES and wildcard in ("none", "wildcard")


_CDN_CACHE_LOCK = threading.Lock()


def _cdn_address(ip: str, cache: dict[str, bool]) -> bool:
    """Shared CDN/cloud/hosting address: the core noise lists, then the local cloud-range dataset copies
    of cloud_ranges (P034; never a download)."""
    with _CDN_CACHE_LOCK:
        if ip in cache:
            return cache[ip]
    verdict = False
    ent = Entity.try_make(T.IPV6 if ":" in ip else T.IPV4, ip)
    if ent is not None:
        try:
            verdict = bool(noise.is_cdn(ent))
        except Exception:  # noqa: BLE001 - noise lists unavailable: not known as CDN
            verdict = False
    if not verdict:
        try:
            from v3lum.modules.ip_network.cloud_ranges import local_classification

            cls = local_classification(ip)
            verdict = bool(cls and cls.get("noise"))
        except Exception:  # noqa: BLE001 - dataset missing or helper unavailable: not known as CDN
            verdict = False
    with _CDN_CACHE_LOCK:
        cache[ip] = verdict
    return verdict


#: CDN edge namespaces a CNAME may point into (V3LUM-authored). Many sit under public-suffix entries
#: (cloudfront.net, azureedge.net...), where the noise lists stop at the PSL registrable domain.
CDN_CNAME_SUFFIXES: tuple[str, ...] = (
    "cloudfront.net", "akamai.net", "akamaiedge.net", "akamaihd.net", "akamaized.net", "edgekey.net", "edgesuite.net",
    "fastly.net", "fastlylb.net", "cloudflare.net", "cdn.cloudflare.net", "azureedge.net", "azurefd.net", "b-cdn.net",
    "cdn77.org", "incapdns.net", "impervadns.net", "sucuri.net", "stackpathdns.com", "kxcdn.com", "llnwd.net",
    "edgecastcdn.net", "footprint.net", "hwcdn.net", "cdnetworks.net", "gcdn.co", "alicdn.com", "kunlunsl.com",
)


def _cdn_cname(cname: str) -> bool:
    name = str(cname or "").strip().lower().rstrip(".")
    if not name:
        return False
    if any(name == s or name.endswith("." + s) for s in CDN_CNAME_SUFFIXES):
        return True
    ent = Entity.try_make(T.DOMAIN, name)
    try:
        return ent is not None and noise.is_cdn(ent)
    except Exception:  # noqa: BLE001 - noise lists unavailable: not known as CDN
        return False


def is_cdn_only(addresses: Iterable[str], cnames: Iterable[str], cache: dict[str, bool] | None = None) -> bool:
    """P016 cond 8: hosted only on shared CDN infrastructure (a CNAME into a CDN namespace, or every
    address on a CDN/cloud edge): such names are listed, never pivoted."""
    cache = cache if cache is not None else {}
    if any(_cdn_cname(c) for c in cnames):
        return True
    addrs = [a for a in addresses if address_kind(a) == "public"]
    return bool(addrs) and all(_cdn_address(a, cache) for a in addrs)


# ======================================================================================
# the shared run (both modules)
# ======================================================================================


class PassiveRun:
    """One run of a passive subdomain module: concurrent feeds, merge through the shared sink,
    wildcard probe, capped DoH resolution, output (attributes, pivots, findings, evidence)."""

    def __init__(self, module: Any, res: ModuleResult, ctx: Any, apex: str, *, budget: float, resolve_cap: int,
                 setting_prefix: str) -> None:
        self.module = module
        self.res = res
        self.ctx = ctx
        self.apex = apex
        self.budget = budget
        self.resolve_cap = resolve_cap
        self.prefix = setting_prefix
        self.start = _mono(ctx)
        self.end = self.start + budget
        self.feeds: list[tuple[Feed, Callable[[Feed], None]]] = []
        self.skipped: list[Feed] = []
        self.wildcard: dict[str, Any] = {"state": "unknown", "answers": [], "nodata_quirk": False, "reason": "not probed"}
        self.resolution: dict[str, dict[str, Any]] = {}
        self.not_resolved: list[str] = []
        self.doh_failures = 0
        self.stop: BaseException | None = None
        self.unrecorded: list[Feed] = []
        self._cdn_checked: dict[str, bool] = {}

    # ---- planning -------------------------------------------------------------------------------
    @property
    def adapter_deadline(self) -> float:
        return self.end - min(RESOLUTION_RESERVE, self.budget / 3.0)

    def add_feed(self, feed: Feed, fn: Callable[[Feed, Any, str, float], None]) -> None:
        self.feeds.append((feed, lambda f, fn=fn: fn(f, self.ctx, self.apex, self.adapter_deadline)))

    def skip_feed(self, feed: Feed, reason: str, reason_code: str = "config", *, record: bool = True) -> None:
        """A feed this run does not query: toggled off (config), demoted, or outside ctx.allowed_sources
        (record=False: the engine itself reports licence-blocked feeds, WP07/WP08)."""
        feed.status, feed.reason, feed.reason_code = "skipped", reason, reason_code
        if record:
            self.skipped.append(feed)
        else:
            self.unrecorded.append(feed)

    # ---- execution ------------------------------------------------------------------------------
    def execute(self) -> ModuleResult:
        res = self.res
        if not self.feeds:
            for feed in self.skipped:
                record_feed_status(res, feed)
            why = "; ".join(f.reason for f in self.skipped + self.unrecorded if f.reason) or "no source"
            return res.mark("skipped", f"no passive subdomain source is allowed or enabled for this run ({why})", reason_code="config")
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.feeds), thread_name_prefix=self.prefix) as pool:
            futures = [pool.submit(run_feed, feed, fn) for feed, fn in self.feeds]
            for fut in futures:
                fut.result()  # workers never raise, except PolicyError/ConfigError (engine: SKIPPED)
        feeds = [f for f, _fn in self.feeds]
        self.stop = next((f.stop for f in feeds if f.stop is not None), None)
        for feed in feeds + self.skipped:
            record_feed_status(res, feed)
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
        return self._finish()

    def _finish(self) -> ModuleResult:
        if self.stop is not None:
            raise self.stop  # the engine keeps the result built above (partial, stop reason)
        return self.res

    def _mark_no_answer(self, feeds: list[Feed]) -> None:
        """Rule 5: no source answered - could not verify, never 'no subdomains'."""
        failures = [f for f in feeds if f.failed]
        reasons = "; ".join(f.reason for f in failures if f.reason) or "no passive subdomain source answered"
        for wanted in FAILURE_ORDER:
            hit = next((f for f in failures if f.status == wanted), None)
            if hit is not None:
                status = STATUS_FOR[wanted]
                code = hit.reason_code if valid_reason(status, hit.reason_code) else ""
                self.res.mark(status, f"could not verify: {reasons}", reason_code=code)
                return
        self.res.mark("error", f"could not verify: {reasons}", reason_code="error")

    # ---- DoH ------------------------------------------------------------------------------------------
    def _time_left(self) -> float:
        return self.end - _mono(self.ctx)

    def _resolve(self, names: list[str]) -> None:
        try:
            if self._time_left() > QUERY_GUARD:
                self.wildcard = probe_wildcard(self.ctx, self.apex)
            else:
                self.wildcard = {"state": "unknown", "answers": [], "nodata_quirk": False, "reason": "time budget used up"}
        except (Cancelled, DeadlineExceeded, RequestCapReached) as exc:
            self.wildcard = {"state": "unknown", "answers": [], "nodata_quirk": False, "reason": f"stopped ({type(exc).__name__})"}
            if isinstance(exc, Cancelled):
                self.stop = exc
                return
        todo, deferred = resolution_order(names, self.apex, self.resolve_cap)
        self.not_resolved = list(deferred)
        lock = threading.Lock()
        stopped = threading.Event()

        def check(name: str) -> None:
            if stopped.is_set() or self._time_left() <= QUERY_GUARD or self.ctx.cancelled():
                with lock:
                    self.not_resolved.append(name)
                return
            try:
                out = resolve_one(self.ctx, name, self.wildcard)
            except Cancelled as exc:
                stopped.set()
                with lock:
                    self.stop = self.stop or exc
                    self.not_resolved.append(name)
                return
            except Exception as exc:  # noqa: BLE001 - deadline, transport, resolver bug: could not verify
                out = {"state": "unresolved", "addresses": [], "cnames": [], "basis": f"could not verify ({type(exc).__name__})"}
            with lock:
                self.resolution[name] = out
                if out["state"] == "unresolved":
                    self.doh_failures += 1

        if not todo:
            return
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(RESOLVE_WORKERS, len(todo)), thread_name_prefix=self.prefix + "_dns") as pool:
            list(pool.map(check, todo))

    # ---- output ---------------------------------------------------------------------------------------
    def _state(self, name: str) -> str:
        if name in self.resolution:
            return str(self.resolution[name]["state"])
        return "not_resolved"

    def _output(self, feeds: list[Feed], sink: HostnameSink, names: list[str]) -> None:
        res, apex = self.res, self.apex
        answered = [f for f in feeds if f.answered]
        attempted = [f for f in feeds if f.answered or f.failed]
        noisy = {f.source for f in feeds if f.noisy}
        wstate = str(self.wildcard.get("state") or "unknown")
        per_name_attrs: dict[str, dict[str, Any]] = {}
        for feed in answered:
            for name, attrs in feed.attrs.items():
                _merge_attrs(per_name_attrs.setdefault(name, {}), attrs)

        assets: list[str] = []
        unconfirmed: list[str] = []
        dropped: list[str] = []
        provenance: dict[str, dict[str, Any]] = {}
        for name in names:
            sources = list(sink.names[name].sources)
            state = self._state(name)
            if state == "wildcard_only":
                dropped.append(name)
                continue
            ok = confirmed(sources, state, wstate, noisy)
            (assets if ok else unconfirmed).append(name)
            row: dict[str, Any] = {"sources": sources, "state": state, "confirmed": ok}
            facts = per_name_attrs.get(name) or {}
            if facts.get("last_seen"):
                row["last_seen"] = facts["last_seen"]
            if facts.get("stale") is True:
                row["stale"] = True
            details = self.resolution.get(name) or {}
            if details.get("addresses"):
                row["addresses"] = list(details["addresses"])[:4]
            if details.get("cnames"):
                row["cnames"] = list(details["cnames"])[:2]
            for key in ("tls_grade", "ssl_vpn", "rr", "sm_observed", "sm_resolved", "ports"):
                if facts.get(key) not in (None, "", [], {}):
                    row[key] = facts[key]
            provenance[name] = row

        pivots = self._pivots(assets)
        for name in pivots:
            provenance[name]["pivot"] = True
        for name, row in provenance.items():
            if row["state"] == "live" and row.get("cdn_only") is None and name in self._cdn_checked:
                row["cdn_only"] = self._cdn_checked[name]

        historical = sorted(n for n in assets if self._state(n) == "historical")
        unresolved = sorted(n for n in assets if self._state(n) in ("unresolved", "not_resolved"))
        resolved_count = sum(1 for n in names if self._state(n) not in ("unresolved", "not_resolved"))
        line = f"{len(answered)}/{len(attempted)} sources answered" if attempted else "0/0 sources answered"
        failed = [f for f in feeds if f.failed]
        if failed:
            line += " (" + "; ".join(f"{f.label} {f.reason_code or f.status}" for f in failed) + ")"
        coverage: dict[str, Any] = {
            "line": line,
            "sources": {f.source: {"label": f.label, "status": f.status, "reason": f.reason, "partial": f.partial_reasons}
                        for f in feeds + self.skipped},
            "names": len(names),
            "assets": len(assets),
            "unconfirmed": len(unconfirmed),
            "resolved": resolved_count,
            "resolution_cap": self.resolve_cap,
            "not_resolved": len(self.not_resolved),
            "doh_could_not_verify": self.doh_failures,
            "wildcard_only_dropped": len(dropped),
            "internal": sum(1 for n in assets if self._state(n) == "internal"),
            "partial": any(f.partial for f in answered) or bool(failed),
        }
        res.attr("subdomain_coverage", coverage)
        res.attr("dns_wildcard", self.wildcard)
        res.attr("subdomain_wildcards", sorted(sink.wildcard_labels()))
        ordered_assets = sorted(assets, key=lambda n: label_priority(n, apex))
        res.attr("subdomains", sorted(ordered_assets[:ATTR_CAP]))
        res.attr("subdomains_historical", historical[:ATTR_CAP])
        res.attr("subdomains_unresolved", unresolved[:ATTR_CAP])
        res.attr("subdomains_unconfirmed", sorted(unconfirmed)[:UNCONFIRMED_CAP])
        keep = (ordered_assets + sorted(unconfirmed, key=lambda n: label_priority(n, apex)))[:PROVENANCE_CAP]
        res.attr("subdomain_provenance", {n: provenance[n] for n in sorted(keep)})

        for name in pivots:
            row = provenance[name]
            res.pivot(T.DOMAIN, name, "subdomain", confidence="probable",
                      note=f"resolves; seen in {', '.join(row['sources'])} (passive DNS): a discovered name gets passive modules only")
        self._internal_findings(assets, provenance)
        self._summary_finding(answered, coverage, assets, historical, unconfirmed, dropped)

        incomplete = [f for f in feeds if f.partial or f.failed]
        if incomplete or self.not_resolved or self.doh_failures:
            notes = [f"{f.label}: {f.reason or ', '.join(f.partial_reasons)}" for f in incomplete]
            if self.not_resolved:
                notes.append(f"{len(self.not_resolved)} name(s) not resolved (DoH cap {self.resolve_cap} or time budget)")
            if self.doh_failures:
                notes.append(f"{self.doh_failures} name(s) could not be verified through DoH")
            if incomplete:
                res.partial = True
                stop = _stop_reason(incomplete)
                if stop:
                    res.stop(stop)
                res.error = "partial: " + "; ".join(notes)
        self._raw(feeds, sink)
        if not names and not sink.wildcards:
            res.mark("empty")  # every answering source answered: no names under this domain

    def _pivots(self, assets: list[str]) -> list[str]:
        """P016 cond 8: resolving, confirmed, non-internal, non-CDN-only names, telling labels first, cap 12."""
        self._cdn_checked = {}
        cache: dict[str, bool] = {}
        chosen: list[str] = []
        for name in sorted(assets, key=lambda n: label_priority(n, self.apex)):
            if len(chosen) >= PIVOT_CAP:
                break
            if self._state(name) != "live":
                continue
            details = self.resolution.get(name) or {}
            cdn = is_cdn_only(details.get("addresses") or [], details.get("cnames") or [], cache)
            self._cdn_checked[name] = cdn
            if not cdn:
                chosen.append(name)
        return chosen

    def _internal_findings(self, assets: list[str], provenance: Mapping[str, Mapping[str, Any]]) -> None:
        internal = [n for n in sorted(assets, key=lambda n: label_priority(n, self.apex)) if self._state(n) == "internal"]
        for name in internal[:INTERNAL_FINDING_CAP]:
            details = self.resolution.get(name) or {}
            addrs = list(details.get("internal") or [])
            kinds = list(details.get("kinds") or [])
            row = provenance.get(name) or {}
            self.res.finding(
                "Internal address in public DNS",
                "low",
                f"{name} resolves in public DNS to {', '.join(addrs)} ({', '.join(kinds)}): the public zone leaks an internal "
                "address. The name is never contacted or pivoted.",
                confidence="probable",
                criterion="public DoH A/AAAA answer inside a private (RFC 1918/4193), CGNAT (RFC 6598), loopback or link-local range",
                data={"name": name, "addresses": addrs, "kinds": kinds, "sources": list(row.get("sources") or [])},
                tags=["misconfiguration"],
                source=(list(row.get("sources") or []) or [""])[0],
                key=name,
            )

    def _summary_finding(self, answered: list[Feed], coverage: Mapping[str, Any], assets: list[str], historical: list[str],
                         unconfirmed: list[str], dropped: list[str]) -> None:
        live = sum(1 for n in assets if self._state(n) == "live")
        desc = (
            f"{len(assets)} subdomain name(s) from passive DNS sources ({coverage['line']}): {live} resolve, "
            f"{len(historical)} historical (NXDOMAIN), {coverage['not_resolved']} not resolved (DoH cap or budget), "
            f"{len(unconfirmed)} unconfirmed single-source name(s) listed apart, {len(dropped)} wildcard-only name(s) dropped. "
            "A name seen in passive DNS is not proof that it belongs to the organisation today."
        )
        self.res.finding(
            "Passive DNS subdomains",
            "info",
            desc,
            confidence="probable",
            data={k: coverage[k] for k in ("line", "names", "assets", "unconfirmed", "resolved", "not_resolved", "wildcard_only_dropped")},
            tags=["info"],
            source=answered[0].source if answered else "",
        )

    def _raw(self, feeds: list[Feed], sink: HostnameSink) -> None:
        names = sink.subdomains()[:EVIDENCE_NAME_CAP]
        self.res.raw = {
            "apex": self.apex,
            "budget_s": self.budget,
            "sources": {
                f.source: {"label": f.label, "status": f.status, "reason": f.reason, "reason_code": f.reason_code,
                           "partial_reasons": f.partial_reasons, "pages": f.pages, "raw_count": f.raw_count, "capped": f.capped,
                           "names": len(f.names), "wildcards": f.wildcards, "meta": f.meta,
                           "rejected": dict(f.sink.rejected) if f.sink is not None else {}}
                for f in feeds + self.skipped
            },
            "wildcard": self.wildcard,
            "names": {n: {"sources": list(sink.names[n].sources), **(self.resolution.get(n) or {"state": "not_resolved"})} for n in names},
            "names_total": len(sink.subdomains()),
            "not_resolved": len(self.not_resolved),
        }


def _stop_reason(feeds: list[Feed]) -> str:
    """Canonical stop reason of a partial run ('' when none fits, e.g. a blocked source next to an answer)."""
    seen = {f.status for f in feeds} | {f.reason_code for f in feeds} | {r for f in feeds for r in f.partial_reasons}
    for stop, keys in (("rate_limited", {"rate_limited"}), ("quota", {"quota"}), ("deadline", {"timeout", "deadline"}),
                       ("request_cap", {"request_cap"})):
        if seen & keys:
            return stop
    return ""


def budget_of(ctx: Any, setting: str) -> float:
    return _float_setting(ctx, setting, DEFAULT_BUDGET, MIN_BUDGET, MAX_BUDGET)


def resolve_cap_of(ctx: Any, setting: str) -> int:
    return _int_setting(ctx, setting, DOH_NAME_CAP, 0, DOH_NAME_CAP)


# ======================================================================================
# the default module (THC)
# ======================================================================================


@register
class SubdomainsPassive(Module):
    name = "subdomains_passive"
    title = "Passive subdomains (THC)"
    description = (
        "Subdomains of a registrable domain from THC's keyless subdomain database (ip.thc.org), validated through the shared "
        "hostname sink, wildcard-checked and resolved through DoH (capped); resolving names pivot."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN}
    produces = {T.DOMAIN}
    tags = {"free"}
    reference = "https://ip.thc.org/"
    terms = "open"  # THC: 'open' (legal_dpo: free service, no contractual bar; P016 cond 2/4)
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # THC receives the registrable domain; DoH resolvers receive discovered names
    provider = "thc"
    sources = (SRC_THC,)
    hosts = ("ip.thc.org",)
    access_model = "free_noauth_limited"
    max_requests = THC_MAX_PAGES  # P016 cond 2: at most 10 pages
    expected_latency = 4.0  # one page 0.5-0.9 s; DoH resolution of the names (core, cached 1 h)
    timeout = DEFAULT_BUDGET + 8.0  # hard run deadline; the shared budget is the setting (30 s)
    min_interval = 1.0
    cache_ttl = CACHE_TTL
    max_pivots = PIVOT_CAP
    default_enabled = True
    notice = (
        "THC is a free community service ('Free Service!, Do not abuse'): one lookup per registrable domain, at most 10 pages, "
        "paging stops when its rate-limit header runs out. Discovered names are resolved through the core DoH resolvers (the "
        "resolver operators see them) and only resolving, non-CDN names pivot."
    )
    settings = {
        "subdomains_passive_budget": SettingSpec(int(DEFAULT_BUDGET), "subdomains_passive: seconds for THC and the DoH resolution (P016 cond 1: 30)"),
        "subdomains_passive_resolve": SettingSpec(DOH_NAME_CAP, "subdomains_passive: names resolved through DoH per run (P016 cond 6: at most 300)"),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        """Once per registrable domain (P016 cond 1): a subdomain is covered by its apex run."""
        return is_registrable_apex(str(entity.value))

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        apex = str(entity.value).strip().lower().rstrip(".")
        run = PassiveRun(self, res, ctx, apex, budget=budget_of(ctx, "subdomains_passive_budget"),
                         resolve_cap=resolve_cap_of(ctx, "subdomains_passive_resolve"), setting_prefix="subdomains_passive")
        feed = Feed(SRC_THC, "THC")
        if SRC_THC in ctx.allowed_sources:
            run.add_feed(feed, fetch_thc)
        else:
            run.skip_feed(feed, "THC is not allowed for this run (licence profile)", "licence", record=False)
        return run.execute()
