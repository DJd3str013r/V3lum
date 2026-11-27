"""Opt-in passive subdomain feeds (P016 cond 3): AnubisDB, Subdomain Center, subdomain.app and
ScanMalware, plus the myssl.com and RapidDNS toggles - same engine as ``subdomains_passive``.

Every feed here is unknown tier until a promotion is recorded (chair decision), so the module is
opt-in (``default_enabled = False``) and the policy gate excludes it at TLP:AMBER and above. Registry
terms per feed (P016 cond 4): AnubisDB and Subdomain Center 'open' (legal_dpo: free services, no
contractual bar); subdomain.app and ScanMalware 'unknown' until legal records an entry with evidence;
myssl.com (CN operator) and RapidDNS (HTML scraping, ToS/robots review pending) 'unknown' and off
unless their toggle settings are enabled. ``ctx.allowed_sources`` decides which feeds run; the engine
reports the licence-blocked rest.

Per feed (P016 cond 5, 9): AnubisDB and Subdomain Center are noisy (names seen only there stay
unconfirmed until they resolve or a second source agrees); subdomain.app ``total > count`` and
ScanMalware ``degraded``/``partial``/``stale``/``subdomains_truncated`` are partial flags (a degraded
answer without names is 'could not verify', never zero names); myssl ``code != 0`` is a partial or
error flag; RapidDNS 'Total' above the rows shown is partial, a page without the result table is an
error. Challenge pages (AnubisDB's Cloudflare 'Attention Required', RapidDNS challenges) are BLOCKED
'challenge', never retried with another UA or identity; a feed BLOCKED on 5 consecutive runs is demoted
(skipped, reason 'demoted') unless the module is selected explicitly with -M.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from html.parser import HTMLParser
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, HttpError, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.domain_dns.ct_logs import HostnameSink, looks_like_html
from v3lum.modules.domain_dns.subdomains_passive import (
    CACHE_TTL,
    DEFAULT_BUDGET,
    DOH_NAME_CAP,
    PER_SOURCE_CAP,
    PIVOT_CAP,
    Feed,
    PassiveRun,
    UnexpectedAnswer,
    budget_of,
    is_registrable_apex,
    resolve_cap_of,
)

__all__ = [
    "DEMOTION_RUNS",
    "SubdomainsPassiveExtra",
    "parse_anubis",
    "parse_myssl",
    "parse_rapiddns",
    "parse_scanmalware_ct",
    "parse_scanmalware_hosts",
    "parse_subdomain_app",
    "parse_subdomain_center",
]

SRC_ANUBIS = "anubisdb.subdomains"
SRC_SUBCENTER = "subdomain_center.subdomains"
SRC_SUBAPP = "subdomain_app.query"
SRC_SCANMALWARE = "scanmalware.subdomains"
SRC_MYSSL = "myssl.discover_sub_domain"
SRC_RAPIDDNS = "rapiddns.subdomain_pages"

ANUBIS_URL = "https://anubisdb.com/anubis/subdomains/{apex}"
SUBCENTER_URL = "https://api.subdomain.center/"
SUBAPP_URL = "https://api.subdomain.app/v1/query"
SM_CT_URL = "https://scanmalware.com/api/v1/ct/dns/{apex}"
SM_HOSTS_URL = "https://scanmalware.com/api/v1/hosts/{apex}"
MYSSL_URL = "https://myssl.com/api/v1/discover_sub_domain"
RAPIDDNS_URL = "https://rapiddns.io/subdomain/{apex}"

DEMOTION_RUNS = 5  # P016 cond 9 / A3: consecutive BLOCKED runs before a feed is demoted
_STREAKS_KEY = "blocked_streaks"
_SM_FLAGS = ("degraded", "partial", "stale", "subdomains_truncated")
_RAPID_TOTAL_RE = re.compile(r"Total:\s*(?:<[^>]+>\s*)*(\d+)", re.I)

# ======================================================================================
# parsers (pure, untrusted input: unexpected shapes raise UnexpectedAnswer)
# ======================================================================================


def json_body(raw: Any, label: str) -> Any:
    """Body -> JSON value; HTML, an empty body or malformed JSON raise UnexpectedAnswer."""
    if isinstance(raw, (list, dict)):
        return raw
    if isinstance(raw, (bytes, bytearray, memoryview)):
        text = bytes(raw).decode("utf-8", "replace")
    else:
        text = str(raw or "")
    text = text.lstrip("﻿").strip()
    if not text:
        raise UnexpectedAnswer(f"{label}: empty body instead of JSON")
    if looks_like_html(text):
        raise UnexpectedAnswer(f"{label}: HTML instead of JSON")
    try:
        return json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise UnexpectedAnswer(f"{label}: malformed JSON") from exc


def _error_text(obj: Mapping[str, Any]) -> str:
    for key in ("error", "message", "msg", "detail"):
        value = obj.get(key)
        if value:
            return str(value)[:160]
    return "error object"


def _name_list(obj: Any, label: str) -> list[Any]:
    if isinstance(obj, dict):
        raise UnexpectedAnswer(f"{label} error object in HTTP 200: {_error_text(obj)}")
    if not isinstance(obj, list):
        raise UnexpectedAnswer(f"{label}: {type(obj).__name__} instead of a name list")
    return obj


def parse_anubis(obj: Any) -> list[Any]:
    """AnubisDB: a JSON array of names (very noisy: validated and capped by the sink); an object is an
    error-in-200."""
    return _name_list(obj, "AnubisDB")


def parse_subdomain_center(obj: Any) -> list[Any]:
    """Subdomain Center: a JSON array of names; an object ({"error": ...}) is an error-in-200."""
    return _name_list(obj, "Subdomain Center")


def parse_subdomain_app(obj: Any) -> dict[str, Any]:
    """subdomain.app ``{domain, count, total, subdomains[]}``; ``total > count`` (or more than the list
    holds) means a truncated answer (P016 cond 5)."""
    if not isinstance(obj, dict):
        raise UnexpectedAnswer(f"subdomain.app: {type(obj).__name__} instead of a query object")
    subs = obj.get("subdomains")
    if obj.get("error") and not subs:
        raise UnexpectedAnswer(f"subdomain.app error in HTTP 200: {_error_text(obj)}")
    if not isinstance(subs, list):
        raise UnexpectedAnswer("subdomain.app answer without a 'subdomains' list")
    total = obj.get("total") if isinstance(obj.get("total"), int) and not isinstance(obj.get("total"), bool) else None
    count = obj.get("count") if isinstance(obj.get("count"), int) and not isinstance(obj.get("count"), bool) else None
    truncated = total is not None and ((count is not None and total > count) or total > len(subs))
    return {"names": subs, "total": total, "count": count, "truncated": truncated}


def _sm_entry(entry: Any) -> tuple[Any, dict[str, Any]]:
    if isinstance(entry, str):
        return entry, {}
    if isinstance(entry, dict):
        name = entry.get("subdomain") or entry.get("name") or entry.get("domain") or entry.get("host")
        ips = entry.get("ips") or entry.get("ip_addresses") or entry.get("addresses") or []
        return name, {"sm_ips": [x for x in ips if isinstance(x, str)][:8] if isinstance(ips, list) else []}
    return None, {}


def parse_scanmalware_ct(obj: Any) -> dict[str, Any]:
    """ScanMalware ``/api/v1/ct/dns/{domain}`` -> {names [(name, facts)], flags, degraded, reason}.
    ``degraded``/``partial``/``stale``/``subdomains_truncated`` are partial flags (P016 cond 5)."""
    if not isinstance(obj, dict):
        raise UnexpectedAnswer(f"ScanMalware CT: {type(obj).__name__} instead of an object")
    rows: list[tuple[Any, dict[str, Any]]] = []
    for key, resolved in (("subdomains", True), ("subdomains_unresolved", False)):
        items = obj.get(key)
        for entry in items if isinstance(items, list) else []:
            name, facts = _sm_entry(entry)
            facts["sm_resolved"] = resolved
            rows.append((name, facts))
    flags = [flag for flag in _SM_FLAGS if obj.get(flag) is True]
    degraded = obj.get("degraded") is True
    why = str(obj.get("degraded_reason") or "") if degraded else ""
    error = str(obj.get("error") or "")[:160]
    if not rows and error and not degraded:
        raise UnexpectedAnswer(f"ScanMalware CT error in HTTP 200: {error}")
    return {"names": rows, "flags": flags, "degraded": degraded, "reason": why, "error": error}


def parse_scanmalware_hosts(obj: Any) -> dict[str, Any]:
    """ScanMalware ``/api/v1/hosts/{domain}`` (hosts its browser scans requested): {names, flags}."""
    if not isinstance(obj, dict):
        raise UnexpectedAnswer(f"ScanMalware hosts: {type(obj).__name__} instead of an object")
    subs = obj.get("subdomains")
    if obj.get("error") and not subs:
        raise UnexpectedAnswer(f"ScanMalware hosts error in HTTP 200: {_error_text(obj)}")
    if not isinstance(subs, list):
        raise UnexpectedAnswer("ScanMalware hosts answer without a 'subdomains' list")
    truncated = obj.get("truncated") if isinstance(obj.get("truncated"), dict) else {}
    flags = ["hosts_truncated_" + str(k) for k, v in sorted(truncated.items()) if v is True]
    scans = obj.get("scans_examined")
    return {"names": subs, "flags": flags, "scans_examined": scans if isinstance(scans, int) else None}


def parse_myssl(obj: Any) -> dict[str, Any]:
    """myssl ``{code, data[{domain, ip, port, level_str, is_sslvpn, evaluate_date}]}``: ``code != 0``
    is a partial flag with data and an error without (P016 cond 5). IPs and TLS grades stay facts."""
    if not isinstance(obj, dict):
        raise UnexpectedAnswer(f"myssl: {type(obj).__name__} instead of an object")
    code = obj.get("code")
    data = obj.get("data")
    rows_in = data if isinstance(data, list) else []
    ok_code = code in (0, "0")
    if not ok_code and not rows_in:
        raise UnexpectedAnswer(f"myssl code {str(code)[:20]}: {_error_text(obj)}")
    rows: list[tuple[Any, dict[str, Any]]] = []
    for rec in rows_in:
        if not isinstance(rec, dict):
            continue
        facts: dict[str, Any] = {}
        port = rec.get("port")
        if isinstance(port, (int, str)) and str(port).strip().isdigit():
            facts["ports"] = [str(port).strip()]
        grade = rec.get("level_str")
        if isinstance(grade, str) and grade.strip():
            facts["tls_grade"] = grade.strip()[:4]
        if rec.get("is_sslvpn") is True:
            facts["ssl_vpn"] = True
        rows.append((rec.get("domain"), facts))
    return {"names": rows, "code": code, "flags": [] if ok_code else [f"code_{str(code)[:12]}"]}


class _RapidTable(HTMLParser):
    """Rows of <table id="table"> (cell text only; scripts and attributes are never interpreted)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_table = False
        self.depth = 0
        self.found = False
        self.rows: list[list[str]] = []
        self.row: list[str] | None = None
        self.cell: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "table":
            if self.in_table:
                self.depth += 1
            elif dict(attrs).get("id") == "table":
                self.in_table = self.found = True
        elif self.in_table and tag == "tr":
            self.row = []
        elif self.in_table and tag in ("td", "th") and self.row is not None:
            self.cell = []

    def handle_endtag(self, tag: str) -> None:
        if not self.in_table:
            return
        if tag == "table":
            if self.depth:
                self.depth -= 1
            else:
                self.in_table = False
        elif tag in ("td", "th") and self.cell is not None and self.row is not None:
            self.row.append(" ".join("".join(self.cell).split()))
            self.cell = None
        elif tag == "tr" and self.row is not None:
            if len(self.rows) < 20_000:
                self.rows.append(self.row)
            self.row = None

    def handle_data(self, data: str) -> None:
        if self.cell is not None:
            self.cell.append(data)


def parse_rapiddns(raw: Any) -> dict[str, Any]:
    """RapidDNS ``/subdomain/{domain}?full=1`` HTML -> {names [(name, facts)], total, rows,
    truncated, guest_limited}. A page without the result table (layout change, cut page) raises
    UnexpectedAnswer: never 'no names'."""
    text = bytes(raw).decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray, memoryview)) else str(raw or "")
    if not text.strip():
        raise UnexpectedAnswer("RapidDNS: empty page")
    parser = _RapidTable()
    try:
        parser.feed(text[:5_000_000])
        parser.close()
    except Exception:  # noqa: BLE001 - html.parser is lenient; a crash on junk is a layout problem
        pass
    if not parser.found:
        raise UnexpectedAnswer("RapidDNS: result table not found (layout change or cut page)")
    rows: list[tuple[Any, dict[str, Any]]] = []
    data_rows = 0
    for row in parser.rows:
        if len(row) >= 2 and [c.lower() for c in row[:2]] == ["#", "domain"]:
            continue
        if len(row) < 4:
            continue
        data_rows += 1
        rtype = row[3].upper()[:10] if len(row) > 3 and row[3] else ""
        value = row[2][:255] if len(row) > 2 else ""
        seen = row[4][:32] if len(row) > 4 else ""
        rows.append((row[1], {"rr": [{"type": rtype, "value": value, "date": seen}]}))
    m = _RAPID_TOTAL_RE.search(text)
    total = int(m.group(1)) if m else None
    return {"names": rows, "total": total, "rows": data_rows, "truncated": bool(total is not None and total > data_rows),
            "guest_limited": "Limited Access" in text}


# ======================================================================================
# adapters (one per source; exceptions are mapped by run_feed)
# ======================================================================================


def _get(ctx: Any, url: str, source: str, deadline: float, **kw: Any) -> Any:
    resp = ctx.http.get(url, source=source, deadline=deadline, **kw)
    ctx.http.check(resp)  # 429 -> RateLimited, challenge/403 -> Blocked/AuthRequired, 5xx -> HttpError
    return resp


def _cache_ok(parse: Any, label: str) -> Any:
    """cache_if: cache only answers that parse (never error objects, HTML or degraded answers)."""

    def check(resp: Any) -> bool:
        try:
            out = parse(json_body(getattr(resp, "content", b""), label))
        except UnexpectedAnswer:
            return False
        except Exception:  # noqa: BLE001
            return False
        return not (isinstance(out, dict) and (out.get("degraded") or out.get("flags")))

    return check


def fetch_anubis(feed: Feed, ctx: Any, apex: str, deadline: float) -> None:
    feed.sink = HostnameSink(apex)
    resp = _get(ctx, ANUBIS_URL.format(apex=apex), SRC_ANUBIS, deadline, cache_if=_cache_ok(parse_anubis, "AnubisDB"))
    names = parse_anubis(json_body(resp.content, "AnubisDB"))
    feed.pages = 1
    feed.meta["raw_names"] = len(names)
    for name in names:
        feed.add(name)


def fetch_subdomain_center(feed: Feed, ctx: Any, apex: str, deadline: float) -> None:
    feed.sink = HostnameSink(apex)
    resp = _get(ctx, SUBCENTER_URL, SRC_SUBCENTER, deadline, params={"domain": apex},
                cache_if=_cache_ok(parse_subdomain_center, "Subdomain Center"))
    names = parse_subdomain_center(json_body(resp.content, "Subdomain Center"))
    feed.pages = 1
    feed.meta["raw_names"] = len(names)
    for name in names:
        feed.add(name)


def fetch_subdomain_app(feed: Feed, ctx: Any, apex: str, deadline: float) -> None:
    feed.sink = HostnameSink(apex)
    resp = _get(ctx, SUBAPP_URL, SRC_SUBAPP, deadline, params={"domain": apex}, cache_if=_cache_ok(parse_subdomain_app, "subdomain.app"))
    out = parse_subdomain_app(json_body(resp.content, "subdomain.app"))
    feed.pages = 1
    feed.meta.update({"total": out["total"], "count": out["count"]})
    for name in out["names"]:
        feed.add(name)
    if out["truncated"]:
        feed.flag("truncated")
        feed.reason = f"subdomain.app answered {out['count']} of {out['total']} names (truncated)"


def fetch_scanmalware(feed: Feed, ctx: Any, apex: str, deadline: float) -> None:
    """Two read-only endpoints in one feed: CT subdomains, then hosts seen in its scans. A degraded CT
    answer without names is 'could not verify' for that endpoint (flag 'degraded'), never zero names."""
    feed.sink = HostnameSink(apex)
    problems: list[str] = []
    try:
        resp = _get(ctx, SM_CT_URL.format(apex=apex), SRC_SCANMALWARE, deadline, params={"subdomain_limit": str(PER_SOURCE_CAP)},
                    cache_if=_cache_ok(parse_scanmalware_ct, "ScanMalware CT"))
        ct = parse_scanmalware_ct(json_body(resp.content, "ScanMalware CT"))
        feed.pages += 1
        for name, facts in ct["names"]:
            feed.add(name, facts)
        for flag in ct["flags"]:
            feed.flag(flag)
        if ct["degraded"]:
            problems.append(f"CT endpoint degraded ({ct['reason'] or 'no reason given'}): could not verify")
    except (RateLimited, QuotaExceeded, Blocked, AuthRequired):
        raise  # the host refused us: the hosts endpoint would be refused too
    except (HttpError, NetworkError, UnexpectedAnswer) as exc:
        feed.flag("page_failed")
        problems.append(f"CT endpoint: {str(exc)[:120]}: could not verify")
    resp = _get(ctx, SM_HOSTS_URL.format(apex=apex), SRC_SCANMALWARE, deadline,
                params={"sources": "observed,scripts", "subdomains_only": "true"},
                cache_if=_cache_ok(parse_scanmalware_hosts, "ScanMalware hosts"))
    hosts = parse_scanmalware_hosts(json_body(resp.content, "ScanMalware hosts"))
    feed.pages += 1
    if hosts["scans_examined"] is not None:
        feed.meta["scans_examined"] = hosts["scans_examined"]
    for name in hosts["names"]:
        feed.add(name, {"sm_observed": True})
    for flag in hosts["flags"]:
        feed.flag(flag)
    if problems:
        feed.reason = "; ".join(problems)


def fetch_myssl(feed: Feed, ctx: Any, apex: str, deadline: float) -> None:
    feed.sink = HostnameSink(apex)
    resp = _get(ctx, MYSSL_URL, SRC_MYSSL, deadline, params={"domain": apex}, cache_if=_cache_ok(parse_myssl, "myssl"))
    out = parse_myssl(json_body(resp.content, "myssl"))
    feed.pages = 1
    feed.meta["code"] = out["code"]
    for name, facts in out["names"]:
        feed.add(name, facts)
    for flag in out["flags"]:
        feed.flag(flag)
        feed.reason = f"myssl answered code {out['code']} (partial)"


def fetch_rapiddns(feed: Feed, ctx: Any, apex: str, deadline: float) -> None:
    """One page per registrable domain (>= 2 s politeness from the provider profile); a challenge
    raises Blocked in ``ctx.http.check`` and stops the source (no retry, no other UA)."""
    feed.sink = HostnameSink(apex)

    def cacheable(resp: Any) -> bool:
        try:
            return not parse_rapiddns(getattr(resp, "content", b""))["truncated"]
        except UnexpectedAnswer:
            return False

    resp = _get(ctx, RAPIDDNS_URL.format(apex=apex), SRC_RAPIDDNS, deadline, params={"full": "1"}, cache_if=cacheable)
    out = parse_rapiddns(resp.content)
    feed.pages = 1
    feed.meta.update({"total": out["total"], "rows": out["rows"], "guest_limited": out["guest_limited"]})
    for name, facts in out["names"]:
        feed.add(name, facts)
    if out["truncated"]:
        feed.flag("truncated")
        feed.reason = f"RapidDNS showed {out['rows']} of {out['total']} rows (truncated guest page)"


#: (source, label, adapter, toggle setting or '')
ADAPTERS: tuple[tuple[str, str, Any, str], ...] = (
    (SRC_ANUBIS, "AnubisDB", fetch_anubis, ""),
    (SRC_SUBCENTER, "Subdomain Center", fetch_subdomain_center, ""),
    (SRC_SUBAPP, "subdomain.app", fetch_subdomain_app, ""),
    (SRC_SCANMALWARE, "ScanMalware", fetch_scanmalware, ""),
    (SRC_MYSSL, "myssl.com", fetch_myssl, "subdomains_passive_extra_myssl"),
    (SRC_RAPIDDNS, "RapidDNS", fetch_rapiddns, "subdomains_passive_extra_rapiddns"),
)

# ======================================================================================
# per-feed demotion (P016 cond 9 / A3): 5 consecutive BLOCKED runs
# ======================================================================================


def _streaks(ctx: Any) -> dict[str, int]:
    try:
        value = ctx.state.get(_STREAKS_KEY, {})
    except Exception:  # noqa: BLE001 - unreadable state: nothing is demoted
        return {}
    if not isinstance(value, dict):
        return {}
    return {str(k): int(v) for k, v in value.items() if isinstance(v, int) and not isinstance(v, bool)}


def _save_streaks(ctx: Any, feeds: list[Feed], before: Mapping[str, int]) -> None:
    streaks = dict(before)
    for feed in feeds:
        if feed.status == "blocked":
            streaks[feed.source] = streaks.get(feed.source, 0) + 1
        elif feed.status in ("ok", "empty"):
            streaks[feed.source] = 0
    if streaks != dict(before):
        try:
            ctx.state.set(_STREAKS_KEY, streaks)
        except Exception:  # noqa: BLE001 - state is best effort; never fail the run for it
            pass


def _explicit(ctx: Any, name: str) -> bool:
    include = getattr(getattr(ctx, "options", None), "include", None) or set()
    return name in include


# ======================================================================================
# the module
# ======================================================================================


@register
class SubdomainsPassiveExtra(Module):
    name = "subdomains_passive_extra"
    title = "Passive subdomains (extra feeds: AnubisDB, Subdomain Center, subdomain.app, ScanMalware, myssl, RapidDNS)"
    description = (
        "Opt-in keyless subdomain feeds of unknown tier (AnubisDB, Subdomain Center, subdomain.app, ScanMalware; myssl.com and "
        "RapidDNS behind toggles), merged through the shared hostname sink with per-name provenance; noisy single-source names "
        "stay unconfirmed until they resolve or a second source agrees."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN}
    produces = {T.DOMAIN}
    tags = {"free", "noisy"}
    reference = "https://github.com/jonluca/Anubis"
    terms = "unknown"  # most restrictive feed: subdomain.app, ScanMalware, myssl.com, RapidDNS (P016 cond 4)
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "anubisdb"
    sources = (SRC_ANUBIS, SRC_SUBCENTER, SRC_SUBAPP, SRC_SCANMALWARE, SRC_MYSSL, SRC_RAPIDDNS)
    hosts = ("anubisdb.com", "api.subdomain.center", "api.subdomain.app", "scanmalware.com", "myssl.com", "rapiddns.io")
    access_model = "free_noauth_limited"
    max_requests = 7  # AnubisDB 1 + Subdomain Center 1 + subdomain.app 1 + ScanMalware 2 + myssl 1 + RapidDNS 1
    expected_latency = 18.0  # Subdomain Center answers in 15-18 s (live 2026-11-26)
    timeout = DEFAULT_BUDGET + 8.0
    min_interval = 1.0
    cache_ttl = CACHE_TTL
    max_pivots = PIVOT_CAP
    default_enabled = False  # unknown tier and unknown terms (A3, chair decision P016)
    notice = (
        "Unknown-tier feeds: opt-in, excluded at TLP:AMBER and above, never sent personal values. myssl.com is run by a Chinese "
        "operator (the queried domain is disclosed there) and RapidDNS is HTML scraping: both stay off unless their settings "
        "are enabled and legal records their terms. Names seen only in AnubisDB or Subdomain Center are unconfirmed until they "
        "resolve or a second source agrees."
    )
    settings = {
        "subdomains_passive_extra_budget": SettingSpec(int(DEFAULT_BUDGET), "subdomains_passive_extra: seconds for the feeds and the DoH resolution (P016 cond 1: 30)"),
        "subdomains_passive_extra_resolve": SettingSpec(DOH_NAME_CAP, "subdomains_passive_extra: names resolved through DoH per run (P016 cond 6: at most 300)"),
        "subdomains_passive_extra_myssl": SettingSpec(False, "subdomains_passive_extra: query myssl.com (CN operator; terms 'unknown' until legal records them, P016 cond 3)"),
        "subdomains_passive_extra_rapiddns": SettingSpec(False, "subdomains_passive_extra: scrape RapidDNS (terms 'unknown' until a recorded ToS/robots review, P016 cond 3)"),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        """Once per registrable domain (P016 cond 1)."""
        return is_registrable_apex(str(entity.value))

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        apex = str(entity.value).strip().lower().rstrip(".")
        run = PassiveRun(self, res, ctx, apex, budget=budget_of(ctx, "subdomains_passive_extra_budget"),
                         resolve_cap=resolve_cap_of(ctx, "subdomains_passive_extra_resolve"), setting_prefix="subdomains_passive_extra")
        allowed = ctx.allowed_sources
        streaks = _streaks(ctx)
        explicit = _explicit(ctx, self.name)
        for source, label, fn, toggle in ADAPTERS:
            feed = Feed(source, label, noisy=True)  # every extra feed is unknown tier (P016 cond 3, 7)
            if source not in allowed:
                run.skip_feed(feed, f"{label} is not allowed for this run (licence profile or policy)", "licence", record=False)
            elif toggle and not bool(ctx.setting(toggle, False)):
                run.skip_feed(feed, f"{label} is off (setting {toggle}; terms 'unknown' until legal records them)", "config")
            elif streaks.get(source, 0) >= DEMOTION_RUNS and not explicit:
                run.skip_feed(feed, f"{label} demoted after {streaks[source]} consecutive blocked runs (A3); select -M {self.name} to retry", "demoted")
            else:
                run.add_feed(feed, fn)
        try:
            return run.execute()
        finally:
            _save_streaks(ctx, [f for f, _fn in run.feeds], streaks)
