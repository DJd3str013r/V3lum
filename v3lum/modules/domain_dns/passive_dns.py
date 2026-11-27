"""Passive DNS from mnemonic, Robtex and CIRCL: historical resolutions of a domain or an IP (P015).

Batch p2-G01-2, proposal P015 ``passive_dns``. Final conditions implemented here:

* c1 - one aggregator with a per-source status, terms label and budget (provider registry): mnemonic
  (``mnemonic.pdns``, tier trusted), Robtex free API (``robtex.pdns``: noncommercial, 'non-commercial,
  low volume', tier community) and CIRCL pDNS (``circl.pdns``: license, CSIRT access on request, tier
  trusted). The module queries only ``ctx.allowed_sources`` and records each feed's outcome with
  ``res.source_status``, so legal can disable one feed without losing the others.
* c2 - mnemonic is classed 'license' (provisional) until legal records its terms with evidence: under
  the corporate profile it is skipped with reason_code 'licence' by the policy gate.
* c3 - Robtex is off under the corporate profile until licence-cleared (licence_allow entry or a Pro
  plan); while skipped its web pages (robtex.com/dns-lookup/{domain}, /ip-lookup/{ip}) are the manual
  links (pack ``passive_dns_robtex``). CIRCL runs only with the team's own vetted account (keys
  ``circl_pdns_user`` + ``circl_pdns_pass``) and a licence_allow entry recording the CIRCL grant.
* c4 - mnemonic: limit 25 per page, offset pagination capped at 4 pages (setting
  ``passive_dns_mnemonic_pages``, all four with ``--preset deep``; pages after the first only when at
  least 15 s of the run remain), epoch-millisecond timestamps, optional key ``mnemonic`` in the
  Argus-API-Key header. Robtex: NDJSON parsed line by line, malformed or truncated lines skipped;
  min_interval >= 2 s and the published 10 requests/hour per egress IP as the provider's P334 budget.
* c5 - CIRCL credentials go only into the Authorization header (HTTP basic auth), never into a URL;
  CIRCL-sourced records are marked ``export_restricted`` and the result carries TLP:AMBER (CIRCL TLP
  and handling rules: not exported outside the team unless CIRCL allows). One COF/NDJSON parser for
  every provider (mnemonic maps into the same record shape).
* c6 - every record keeps first_seen/last_seen and its sources; records are ordered by last_seen;
  records last seen more than 12 months ago are historical, never current infrastructure, and do not
  pivot. Robtex forward answers carry the same recent time_last on every record (a refresh time, not
  an observation): a Robtex-only last_seen is 'uncertain' and never makes a record current.
* c7 - IP -> domains on CDN/shared-hosting/resolver addresses (core noise kinds, P034) or with more
  than 50 names are counts (attribute ``cohosting``), never pivots, and stay out of shared-infrastructure
  correlations; on dedicated IPs the current co-hosted names become ``hosted_domain`` pivots (the 10
  most recently seen expand, the rest are listed for the analyst).
* c8 - resolutions to known sinkhole addresses (core sinkhole lists) tag the domain (finding tag
  ``sinkhole``, attribute ``sinkholed``) and never pivot; at most 200 records per entity; the report
  shows 'resolved to N IPs since <date>' (``pdns_summary``) and a table of at most 20 rows
  (``passive_dns``).
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from v3lum.core import noise
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    Cancelled,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    QuotaExceeded,
    RateLimited,
    RequestCapReached,
)
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

MNEMONIC = "mnemonic.pdns"
ROBTEX = "robtex.pdns"
CIRCL = "circl.pdns"
SOURCE_LABELS = {MNEMONIC: "mnemonic", ROBTEX: "robtex", CIRCL: "circl"}
MNEMONIC_URL = "https://api.mnemonic.no/pdns/v3/{value}"
ROBTEX_FORWARD = "https://freeapi.robtex.com/pdns/forward/{value}"
ROBTEX_REVERSE = "https://freeapi.robtex.com/pdns/reverse/{value}"
CIRCL_URL = "https://www.circl.lu/pdns/query/{value}"
ROBTEX_PAGE_DOMAIN = "https://www.robtex.com/dns-lookup/{value}"
ROBTEX_PAGE_IP = "https://www.robtex.com/ip-lookup/{value}"
PAGE_LIMIT = 25
MAX_PAGES = 4
#: Pages after the first only when this much of the run deadline remains (later pages took ~7 s).
EXTRA_PAGE_MIN_REMAINING = 15.0
RECORD_CAP = 200
TABLE_ROWS = 20
HISTORICAL_DAYS = 365
COHOST_LIMIT = 50
EXPAND_COHOSTED = 10
SHARED_KINDS = frozenset({"cdn", "cloud", "hosting", "saas", "resolver"})
WEAK_RELATIONS = {"cname": "cname_to", "ns": "nameserver", "mx": "mx_host"}
STOP_EXCEPTIONS = (Cancelled, DeadlineExceeded, RequestCapReached)
#: Failure rank when no feed answered (the most specific 'could not verify' wins).
_FAILURE_RANK = {Status.RATE_LIMITED: 5, Status.QUOTA: 4, Status.BLOCKED: 3, Status.ERROR: 2, Status.NEEDS_KEY: 1}
_NAME = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9_-]{1,63}$")


# ======================================================================================
# records: one shape for every provider (P015 c5, c6)
# ======================================================================================


def _epoch(value: Any, *, millis: bool) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if not isinstance(value, (int, float)):
        return None
    seconds = int(value / 1000) if millis else int(value)
    return seconds if 0 < seconds <= 4_102_444_800 else None


def iso(epoch: int | None) -> str | None:
    if not epoch:
        return None
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return None


def _name(value: Any) -> str | None:
    text = str(value or "").strip().lower().rstrip(".")
    return text if _NAME.match(text) else None


def record(rrname: Any, rrtype: Any, rdata: Any, first: Any, last: Any, count: Any, source: str, *, millis: bool = False,
           timestamps: str = "observed") -> dict[str, Any] | None:
    """One normalised pDNS record, or None when it has neither a name nor data."""
    name = _name(rrname)
    rtype = str(rrtype).strip().lower()[:10] if isinstance(rrtype, str) and rrtype.strip() else "unknown"
    data: str | None = None
    if isinstance(rdata, str) and rdata.strip():
        data = _ip(rdata) or rdata.strip().rstrip(".").lower()[:300]
    if not name and not data:
        return None
    return {
        "rrname": name,
        "rrtype": rtype,
        "rdata": data,
        "first": _epoch(first, millis=millis),
        "last": _epoch(last, millis=millis),
        "count": count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else None,
        "source": source,
        "timestamps": timestamps,
        "last_reliable": True,
    }


def _shape_type(rrname: str | None, rdata: str | None) -> str:
    if rdata and _ip(rdata):
        return "aaaa" if ":" in rdata else "a"
    if rrname and rrname.endswith((".in-addr.arpa", ".ip6.arpa")):
        return "ptr"
    return "unknown"


def parse_mnemonic(content: Any) -> dict[str, Any]:
    """One mnemonic PassiveDNS v3 page: {state ok|empty|error, count, offset, records, masked, reason}.

    Anonymous offset-0 pages came back masked on 2026-11-26 (every rrtype 'a', first/lastSeenTimestamp 0,
    flag partialResult): their times fall back to createdTimestamp/lastUpdatedTimestamp (approximate
    database times, flagged) and the rrtype is inferred from the answer's shape.
    """
    data = _json(content)
    out: dict[str, Any] = {"state": "error", "count": None, "offset": None, "records": [], "masked": 0, "reason": ""}
    if not isinstance(data, dict) or not isinstance(data.get("data", []), list):
        out["reason"] = "the mnemonic answer is not a PassiveDNS envelope"
        return out
    count = data.get("count")
    out["count"] = count if isinstance(count, int) and not isinstance(count, bool) else None
    offset = data.get("offset")
    out["offset"] = offset if isinstance(offset, int) and not isinstance(offset, bool) else None
    rows = data.get("data") or []
    for row in rows:
        if not isinstance(row, dict):
            continue
        first, last = row.get("firstSeenTimestamp"), row.get("lastSeenTimestamp")
        masked = not first and not last
        stamps = "observed"
        if masked:
            first, last, stamps = row.get("createdTimestamp"), row.get("lastUpdatedTimestamp"), "approx_db"
        qname = row.get("query") if isinstance(row.get("query"), str) else None
        answer = row.get("answer") if isinstance(row.get("answer"), str) else None
        rtype = row.get("rrtype") if isinstance(row.get("rrtype"), str) else None
        shape = _shape_type(_name(qname), _ip(answer) if answer else None)
        if masked or not rtype or (rtype.lower() == "a" and shape != "a"):
            rtype = shape
        rec = record(qname, rtype, answer, first, last, row.get("times"), "mnemonic", millis=True, timestamps=stamps)
        if rec is not None:
            out["records"].append(rec)
            out["masked"] += 1 if masked else 0
    out["state"] = "ok" if out["records"] else ("empty" if not rows else "error")
    if out["state"] == "error":
        out["reason"] = "mnemonic answered rows without usable records"
    return out


def parse_cof(content: Any, source: str) -> dict[str, Any]:
    """One parser for Robtex and CIRCL (COF/NDJSON, P015 c5): line by line, malformed or truncated lines
    skipped and counted; a JSON array (Robtex's empty answer '[]') is accepted too."""
    text = content.decode("utf-8", errors="replace") if isinstance(content, (bytes, bytearray)) else str(content or "")
    text = text.lstrip("﻿")
    out: dict[str, Any] = {"records": [], "malformed": 0, "truncated_tail": False, "format": "empty", "uniform_last": False}
    stripped = text.strip()
    if not stripped:
        return out
    objects: list[Any] = []
    if stripped.startswith("["):
        parsed = _json(stripped)
        if isinstance(parsed, list):
            objects, out["format"] = parsed, "json_array"
    if out["format"] != "json_array":
        out["format"] = "ndjson"
        lines = text.split("\n")
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            try:
                objects.append(json.loads(line))
            except (ValueError, RecursionError):
                out["malformed"] += 1
                if i == len(lines) - 1 and not text.endswith("\n"):
                    out["truncated_tail"] = True
    for obj in objects:
        if not isinstance(obj, dict):
            out["malformed"] += 1
            continue
        data = obj.get("rdata", obj.get("rrdata"))
        values = data if isinstance(data, list) else [data]
        first, last, millis = obj.get("time_first"), obj.get("time_last"), False
        if first is None and last is None and ("time_first_ms" in obj or "time_last_ms" in obj):
            first, last, millis = obj.get("time_first_ms"), obj.get("time_last_ms"), True
        if first is None and last is None:
            first, last = obj.get("zone_time_first"), obj.get("zone_time_last")
        for value in values[:50]:
            if value is not None and not isinstance(value, str):
                out["malformed"] += 1  # COF rdata is a string or a list of strings
                continue
            rec = record(obj.get("rrname"), obj.get("rrtype"), value, first, last, obj.get("count"), source, millis=millis)
            if rec is None:
                out["malformed"] += 1
            else:
                out["records"].append(rec)
    recs = out["records"]
    lasts = {r["last"] for r in recs}
    firsts = {r["first"] for r in recs}
    if len(recs) >= 3 and len(lasts) == 1 and len(firsts) > 1:
        out["uniform_last"] = True  # one refresh time on every record: not a last observation
        for r in recs:
            r["last_reliable"] = False
    return out


def merge(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge by (rrname, rrtype, rdata) keeping per-source first/last seen (P015 c6)."""
    merged: dict[tuple[Any, Any, Any], dict[str, Any]] = {}
    for r in records:
        key = (r["rrname"], r["rrtype"], r["rdata"])
        m = merged.setdefault(key, {"rrname": key[0], "rrtype": key[1], "rdata": key[2], "first": None, "_rel": None, "_unrel": None,
                                    "count": 0, "sources": {}, "export_restricted": False})
        m["sources"][r["source"]] = {"first_seen": iso(r["first"]), "last_seen": iso(r["last"]), "count": r["count"],
                                     "timestamps": r["timestamps"], "last_seen_reliable": r["last_reliable"]}
        if r["first"] and (m["first"] is None or r["first"] < m["first"]):
            m["first"] = r["first"]
        slot = "_rel" if r["last_reliable"] else "_unrel"
        if r["last"] and (m[slot] is None or r["last"] > m[slot]):
            m[slot] = r["last"]
        if isinstance(r["count"], int):
            m["count"] += r["count"]
        m["export_restricted"] = m["export_restricted"] or r["source"] == "circl"
    out = []
    for m in merged.values():
        rel, unrel = m.pop("_rel"), m.pop("_unrel")
        m["last"] = rel or unrel
        m["last_uncertain"] = rel is None and unrel is not None
        out.append(m)
    return out


def age_mark(records: list[dict[str, Any]], now_epoch: int) -> None:
    """historical True (reliably last seen > 12 months ago), False (seen inside the window), None (age unknown)."""
    horizon = now_epoch - HISTORICAL_DAYS * 86400
    for r in records:
        if r["first"] and r["first"] >= horizon:
            r["historical"] = False
        elif r["last"] and not r["last_uncertain"]:
            r["historical"] = r["last"] < horizon
        else:
            r["historical"] = None


def _json(content: Any) -> Any:
    if isinstance(content, (dict, list)):
        return content
    try:
        text = content.decode("utf-8", errors="replace") if isinstance(content, (bytes, bytearray)) else str(content or "")
        text = text.lstrip("﻿").strip()
        return json.loads(text) if text[:1] in "{[" else None
    except (ValueError, RecursionError):
        return None


def failure(exc: BaseException, source: str) -> tuple[Status, str, str]:
    """(status, reason_code, reason) of a failed feed: 'could not verify', never an absence (rule 5)."""
    text = str(exc)[:200]
    if isinstance(exc, RateLimited):
        return Status.RATE_LIMITED, "rate_limited", text
    if isinstance(exc, QuotaExceeded):
        return Status.QUOTA, "quota", text
    if isinstance(exc, Blocked):
        return Status.BLOCKED, getattr(exc, "reason_code", "challenge") or "challenge", text
    if isinstance(exc, AuthRequired):
        if source == CIRCL:
            return Status.NEEDS_KEY, "needs_key", "CIRCL pDNS refused the credentials (circl_pdns_user / circl_pdns_pass)"
        return Status.BLOCKED, "challenge", text
    if isinstance(exc, NetworkError) and "timed out" in text.lower():
        return Status.ERROR, "timeout", text
    return Status.ERROR, "error", text


def basic_auth(user: str, password: str) -> str:
    """Authorization header value for CIRCL (credentials never go into a URL, P015 c5)."""
    if not user or not password or ":" in user or any(c in user + password for c in "\r\n"):
        raise ValueError("passive_dns: CIRCL needs circl_pdns_user and circl_pdns_pass (no ':' in the user, no line breaks)")
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode("ascii")


@register
class PassiveDns(Module):
    name = "passive_dns"
    title = "Passive DNS (mnemonic, Robtex, CIRCL)"
    description = (
        "Historical DNS resolutions of a domain (past IPs, CNAME/NS/MX) or the names seen on an IP from mnemonic, Robtex "
        "and CIRCL passive DNS, with first/last seen per record and source."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN, T.IPV4, T.IPV6}
    produces = {T.IPV4, T.IPV6, T.DOMAIN}
    tags = {"free"}
    reference = "https://www.circl.lu/services/passive-dns/"
    terms = "noncommercial"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "mnemonic"
    sources = (MNEMONIC, ROBTEX, CIRCL)
    hosts = ("api.mnemonic.no", "freeapi.robtex.com", "www.circl.lu")
    access_model = "free_noauth_limited"
    optional_keys = ("mnemonic", "circl_pdns_user", "circl_pdns_pass")
    max_requests = 6
    expected_latency = 3.0
    timeout = 45.0
    cache_ttl = 86400
    max_pivots = 100
    manual_link = "passive_dns_robtex:robtex_dns_lookup"
    default_enabled = True
    settings = {"passive_dns_mnemonic_pages": 2}
    notice = (
        "Feeds and terms: mnemonic PassiveDNS (trusted; 'license' until legal records its terms), Robtex free API "
        "(noncommercial, 10 requests/hour per egress IP; off under the corporate profile until licence-cleared: the Robtex "
        "web pages are the manual links) and CIRCL pDNS (license: the team's own vetted account plus a licence_allow entry; "
        "CIRCL records are TLP:AMBER and never exported outside the team). Records last seen more than 12 months ago are "
        "historical and never pivot."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.DOMAIN:
            return bool(_name(entity.value))
        return noise.is_public_ip(entity.value)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        allowed = set(ctx.allowed_sources)
        domain = entity.type is T.DOMAIN
        value = entity.value
        if ROBTEX not in allowed:
            # P015 c3: while the Robtex automation is skipped, its web page is the manual link
            page = ROBTEX_PAGE_DOMAIN if domain else ROBTEX_PAGE_IP
            res.link("Robtex lookup (manual: automation skipped)", page.format(value=quote(value, safe=":")))
        if not allowed:
            return res.mark("skipped", "no passive DNS feed is allowed by the licence profile", reason_code="licence")
        records: list[dict[str, Any]] = []
        failures: list[Status] = []
        answered = 0
        info: dict[str, Any] = {}
        provider_total = None
        mnemonic_state: dict[str, Any] | None = None
        if MNEMONIC in allowed:
            mnemonic_state = self._mnemonic_first(ctx, res, value, records, failures, info)
            if mnemonic_state is not None:
                answered += 1
                provider_total = mnemonic_state.get("count")
        if ROBTEX in allowed and self._robtex(ctx, res, value, domain, records, failures, info):
            answered += 1
        if CIRCL in allowed and self._circl(ctx, res, value, records, failures, info):
            answered += 1
        if mnemonic_state is not None and mnemonic_state.get("state") == "ok":
            self._mnemonic_more(ctx, res, value, mnemonic_state, records, info, ip=not domain)
        res.raw = {"query": value, "sources": info}
        if not answered:
            worst = max(failures, key=lambda s: _FAILURE_RANK.get(s, 0)) if failures else Status.ERROR
            return res.mark(worst, "no passive DNS feed answered: could not verify")
        if not records:
            return res.mark("empty")
        self._report(entity, ctx, res, records, provider_total)
        return res

    # ------------------------------------------------------------------ feeds
    def _record_failure(self, res: ModuleResult, source: str, exc: BaseException, failures: list[Status], info: dict[str, Any]) -> None:
        status, code, reason = failure(exc, source)
        res.source_status(source, status, reason_code=code, reason=reason)
        failures.append(status)
        info[SOURCE_LABELS[source]] = {"status": status.value, "reason": reason}

    def _mnemonic_get(self, ctx: Any, value: str, offset: int) -> Any:
        headers = {}
        key = ctx.key("mnemonic")
        if key:
            headers["Argus-API-Key"] = key  # header only, never in the URL
        url = MNEMONIC_URL.format(value=quote(value, safe=":"))
        resp = ctx.http.get(url, params={"limit": PAGE_LIMIT, "offset": offset}, headers=headers, source=MNEMONIC)
        ctx.http.check(resp)  # 429/402 envelopes and ERROR messages are provider markers (P321)
        return resp

    def _mnemonic_first(self, ctx: Any, res: ModuleResult, value: str, records: list[dict[str, Any]], failures: list[Status],
                        info: dict[str, Any]) -> dict[str, Any] | None:
        try:
            page = parse_mnemonic(self._mnemonic_get(ctx, value, 0).content)
        except STOP_EXCEPTIONS:
            raise
        except (HttpError, NetworkError) as exc:
            self._record_failure(res, MNEMONIC, exc, failures, info)
            return None
        if page["state"] == "error":
            res.source_status(MNEMONIC, Status.ERROR, reason=f"{page['reason']}: could not verify")
            failures.append(Status.ERROR)
            info["mnemonic"] = {"status": "error", "reason": page["reason"]}
            return None
        records.extend(page["records"])
        info["mnemonic"] = {"status": page["state"], "pages": 1, "count": page["count"], "records": len(page["records"]),
                            "masked": page["masked"]}
        res.source_status(MNEMONIC, Status.OK if page["records"] else Status.EMPTY)
        return page

    def _mnemonic_more(self, ctx: Any, res: ModuleResult, value: str, first: dict[str, Any], records: list[dict[str, Any]],
                       info: dict[str, Any], *, ip: bool) -> None:
        """Pages 2..4 (P015 c4): only while the total says more, under the record cap and the run budget.
        An IP whose total already exceeds the co-hosting limit is shared (counts only): no more pages."""
        wanted = 4 if str(getattr(getattr(ctx, "options", None), "preset", "") or "") == "deep" else ctx.setting("passive_dns_mnemonic_pages", 2)
        try:
            pages = max(1, min(MAX_PAGES, int(wanted)))
        except (TypeError, ValueError):
            pages = 2
        count = first.get("count") or 0
        if ip and count > COHOST_LIMIT:
            info["mnemonic"]["stopped"] = f"shared IP ({count} records): counts only"
            return
        page = first
        done = 1
        while done < pages:
            offset = done * PAGE_LIMIT  # our own offsets: never trust the echoed one to advance
            got = sum(1 for r in records if r["source"] == "mnemonic")
            if len(page["records"]) < PAGE_LIMIT or offset >= count or got >= RECORD_CAP:
                break
            remaining = ctx.remaining()
            if remaining is not None and remaining < EXTRA_PAGE_MIN_REMAINING:
                info["mnemonic"]["stopped"] = "run budget"
                break
            try:
                page = parse_mnemonic(self._mnemonic_get(ctx, value, offset).content)
            except STOP_EXCEPTIONS:
                raise
            except (HttpError, NetworkError) as exc:
                info["mnemonic"]["stopped"] = f"page {done + 1}: {str(exc)[:120]}"
                break
            if page["state"] != "ok":
                break
            records.extend(page["records"])
            done += 1
            info["mnemonic"].update({"pages": done, "records": info["mnemonic"]["records"] + len(page["records"]),
                                     "masked": info["mnemonic"]["masked"] + page["masked"]})

    def _robtex(self, ctx: Any, res: ModuleResult, value: str, domain: bool, records: list[dict[str, Any]], failures: list[Status],
                info: dict[str, Any]) -> bool:
        url = (ROBTEX_FORWARD if domain else ROBTEX_REVERSE).format(value=quote(value, safe=":"))
        try:
            resp = ctx.http.get(url, source=ROBTEX)
            ctx.http.check(resp)  # 429, Cloudflare challenges, 5xx: could not verify
        except STOP_EXCEPTIONS:
            raise
        except (HttpError, NetworkError) as exc:
            self._record_failure(res, ROBTEX, exc, failures, info)
            return False
        if _looks_html(resp.content):
            res.source_status(ROBTEX, Status.ERROR, reason="Robtex answered an HTML page: could not verify")
            failures.append(Status.ERROR)
            info["robtex"] = {"status": "error", "reason": "HTML page"}
            return False
        parsed = parse_cof(resp.content, "robtex")
        records.extend(parsed["records"])
        info["robtex"] = {"status": "ok" if parsed["records"] else "empty", "records": len(parsed["records"]), "malformed": parsed["malformed"],
                          "truncated_tail": parsed["truncated_tail"], "uniform_time_last": parsed["uniform_last"]}
        if parsed["records"]:
            note = f"{parsed['malformed']} malformed line(s) skipped" if parsed["malformed"] else ""
            res.source_status(ROBTEX, Status.OK, reason=note)
        elif parsed["malformed"]:
            res.source_status(ROBTEX, Status.ERROR, reason="Robtex answered only malformed lines: could not verify")
            failures.append(Status.ERROR)
            return False
        else:
            res.source_status(ROBTEX, Status.EMPTY)
        return True

    def _circl(self, ctx: Any, res: ModuleResult, value: str, records: list[dict[str, Any]], failures: list[Status],
               info: dict[str, Any]) -> bool:
        user, password = ctx.key("circl_pdns_user"), ctx.key("circl_pdns_pass")
        if not user or not password:
            res.source_status(CIRCL, Status.NEEDS_KEY, reason="CIRCL pDNS needs the team's own account: keys circl_pdns_user and circl_pdns_pass")
            failures.append(Status.NEEDS_KEY)
            info["circl"] = {"status": "needs_key"}
            return False
        try:
            auth = basic_auth(user, password)
        except ValueError as exc:
            res.source_status(CIRCL, Status.NEEDS_KEY, reason=str(exc))
            failures.append(Status.NEEDS_KEY)
            info["circl"] = {"status": "needs_key"}
            return False
        try:
            resp = ctx.http.get(CIRCL_URL.format(value=quote(value, safe=":")), headers={"Authorization": auth, "Accept": "application/x-ndjson"},
                                source=CIRCL)
            ctx.http.check(resp)
        except STOP_EXCEPTIONS:
            raise
        except (HttpError, NetworkError) as exc:
            self._record_failure(res, CIRCL, exc, failures, info)
            return False
        if _looks_html(resp.content):
            res.source_status(CIRCL, Status.ERROR, reason="CIRCL answered an HTML page: could not verify")
            failures.append(Status.ERROR)
            info["circl"] = {"status": "error", "reason": "HTML page"}
            return False
        parsed = parse_cof(resp.content, "circl")
        records.extend(parsed["records"])
        info["circl"] = {"status": "ok" if parsed["records"] else "empty", "records": len(parsed["records"]), "malformed": parsed["malformed"]}
        res.source_status(CIRCL, Status.OK if parsed["records"] else Status.EMPTY)
        if parsed["records"]:
            res.set_marking("amber")  # P015 c5: CIRCL TLP/handling rules - never exported outside the team
        return True

    # ------------------------------------------------------------------ results
    def _report(self, entity: Entity, ctx: Any, res: ModuleResult, records: list[dict[str, Any]], provider_total: int | None) -> None:
        now = int(ctx.now().timestamp())
        merged = merge(records)
        age_mark(merged, now)
        merged.sort(key=lambda r: (r["last"] or 0, r["first"] or 0), reverse=True)
        total = len(merged)
        kept = merged[:RECORD_CAP]
        value = entity.value
        if entity.type is T.DOMAIN:
            summary = self._domain_view(entity, res, kept)
        else:
            summary = self._ip_view(entity, res, kept, provider_total)
        res.attr("pdns_summary", summary)
        counts: dict[str, int] = {}
        for r in kept:
            for src in r["sources"]:
                counts[src] = counts.get(src, 0) + 1
        res.attr("pdns_record_count", {
            "total": total, "kept": len(kept), "cap": RECORD_CAP,
            "historical": sum(1 for r in kept if r["historical"] is True),
            "current": sum(1 for r in kept if r["historical"] is False),
            "unknown_age": sum(1 for r in kept if r["historical"] is None),
            "sources": counts, "provider_total": provider_total,
        })
        res.attr("passive_dns", [_row(r) for r in kept[:TABLE_ROWS]])
        res.raw["records"] = [_row(r) for r in kept]
        res.raw["capped"] = total > RECORD_CAP
        res.raw["query"] = value

    def _domain_view(self, entity: Entity, res: ModuleResult, kept: list[dict[str, Any]]) -> str:
        name = entity.value
        addresses = [r for r in kept if r["rrname"] == name and r["rrtype"] in ("a", "aaaa") and _ip(r["rdata"])]
        sink: list[dict[str, Any]] = []
        for r in addresses:
            ent = Entity.try_make(T.IPV6 if ":" in r["rdata"] else T.IPV4, r["rdata"])
            r["sinkhole"] = bool(ent is not None and noise.is_sinkhole(ent))
            if r["sinkhole"]:
                sink.append(r)
        if sink:
            latest = addresses[0]
            current = bool(latest["sinkhole"] and latest["historical"] is not True)
            since = min((r["first"] for r in sink if r["first"]), default=None)
            res.attr("sinkholed", {"current": current, "since": (iso(since) or "")[:10] or None,
                                   "ips": sorted({r["rdata"] for r in sink}), "last_seen": iso(max((r["last"] or 0) for r in sink)) or None})
            res.finding(
                "Domain resolved to a known sinkhole",
                "info",
                f"{name} resolved to sinkhole address(es) {', '.join(sorted({r['rdata'] for r in sink})[:5])}"
                + (" and still does (latest record)" if current else " in the past")
                + ": the domain was taken over by researchers or law enforcement, usually after malicious use. Sinkhole "
                "addresses are not attacker infrastructure and never pivot.",
                confidence="probable",
                tags=["sinkhole"],
                data={"ips": sorted({r["rdata"] for r in sink}), "current": current},
                source=MNEMONIC if any("mnemonic" in r["sources"] for r in sink) else (ROBTEX if any("robtex" in r["sources"] for r in sink) else CIRCL),
                observed_first=since,
                observed_last=max((r["last"] or 0) for r in sink) or None,
            )
        pivoted: set[str] = set()
        for r in addresses:
            if r["historical"] is not False or r["sinkhole"] or r["rdata"] in pivoted:
                continue
            pivoted.add(r["rdata"])
            res.pivot(T.IPV6 if ":" in r["rdata"] else T.IPV4, r["rdata"], "resolves_to", confidence="probable",
                      note=f"passive DNS {_span(r)} ({', '.join(sorted(r['sources']))})")
        for r in kept:
            relation = WEAK_RELATIONS.get(r["rrtype"])
            if r["rrname"] != name or relation is None or r["historical"] is not False or not r["rdata"]:
                continue
            target = _name(r["rdata"].split()[-1])
            if target and target not in pivoted:
                pivoted.add(target)
                res.pivot(T.DOMAIN, target, relation, confidence="probable", expand=False, note=f"passive DNS {_span(r)}")
        pointing = {r["rrname"] for r in kept if r["rdata"] == name and r["rrname"] and r["rrname"] != name}
        if pointing:
            res.attr("names_pointing_here", len(pointing))
        ips = list(dict.fromkeys(r["rdata"] for r in addresses))
        firsts = [r["first"] for r in addresses if r["first"]]
        since = (iso(min(firsts)) or "")[:10] if firsts else ""
        return f"resolved to {len(ips)} IPs since {since}" if since else f"resolved to {len(ips)} IPs"

    def _ip_view(self, entity: Entity, res: ModuleResult, kept: list[dict[str, Any]], provider_total: int | None) -> str:
        ip = entity.value
        names = [r for r in kept if r["rdata"] == ip and r["rrtype"] in ("a", "aaaa") and r["rrname"]]
        all_names = list(dict.fromkeys(r["rrname"] for r in names))
        current = [r for r in names if r["historical"] is False]
        kinds = sorted(noise.noise_kinds(entity) & SHARED_KINDS)
        known = max(len(all_names), provider_total or 0)
        shared = bool(kinds) or known > COHOST_LIMIT
        reason = f"{'/'.join(kinds)} address" if kinds else (f"more than {COHOST_LIMIT} names" if shared else "")
        res.attr("cohosting", {
            "count": known,
            "mode": "count_only" if shared else "pivot",
            "reason": reason,
            "sources": sorted({s for r in names for s in r["sources"]}),
            "exclude_from_shared_infra": shared,
        })
        if shared:
            res.attr("shared_ip", True)  # P015 c7: counts only, no pivots, no shared-infrastructure correlation
        else:
            seen: set[str] = set()
            for r in current:
                if r["rrname"] in seen:
                    continue
                seen.add(r["rrname"])
                res.pivot(T.DOMAIN, r["rrname"], "hosted_domain", confidence=0.6, expand=len(seen) <= EXPAND_COHOSTED,
                          note=f"co-hosted on a dedicated IP, passive DNS {_span(r)}")
        ptr = sorted({r["rdata"] for r in kept if r["rrtype"] == "ptr" and r["rdata"]})
        res.attr("ptr_names", ptr[:20])
        firsts = [r["first"] for r in names if r["first"]]
        since = (iso(min(firsts)) or "")[:10] if firsts else ""
        line = f"{len(all_names)} names seen on this IP since {since}" if since else f"{len(all_names)} names seen on this IP"
        if provider_total and provider_total > len(names):
            line += f" (mnemonic reports {provider_total} records)"
        return line


def _span(r: dict[str, Any]) -> str:
    first = (iso(r["first"]) or "?")[:10]
    last = (iso(r["last"]) or "?")[:10]
    return f"{first} .. {last}" + (" (last seen uncertain)" if r.get("last_uncertain") else "")


def _row(r: dict[str, Any]) -> dict[str, Any]:
    row = {
        "hostname": r["rrname"],
        "address": r["rdata"],
        "record_type": r["rrtype"].upper(),
        "first_seen": iso(r["first"]),
        "last_seen": iso(r["last"]),
        "historical": r["historical"],
        "sources": sorted(r["sources"]),
    }
    if r.get("last_uncertain"):
        row["last_seen_uncertain"] = True
    if r.get("export_restricted"):
        row["export_restricted"] = True
    if any(s.get("timestamps") == "approx_db" for s in r["sources"].values()):
        row["timestamps"] = "approximate"
    return row


def _looks_html(content: Any) -> bool:
    head = (content[:512].decode("utf-8", errors="replace") if isinstance(content, (bytes, bytearray)) else str(content or "")[:512]).lstrip().lower()
    return head.startswith("<") and any(t in head for t in ("<!doctype html", "<html", "<head", "<body", "<title"))


__all__ = ["PassiveDns", "age_mark", "basic_auth", "failure", "merge", "parse_cof", "parse_mnemonic", "record"]
