"""SANS Internet Storm Center / DShield API: sensor reports, threat-feed memberships and AS data of an IP;
reported addresses of an AS.

Batch p2-G02-3, proposal P151 (council final conditions):

* c1-c2 - ``terms='noncommercial'`` (SANS ISC data is CC BY-NC-SA 4.0, A1 initial class): off under the
  corporate profile until licence-cleared. The ISC API page allows commercial use 'to protect your own
  company's network ... do not resell': legal records a licence_allow entry for ``sans_isc.api`` (basis
  terms_clause) citing that clause, scope 'defence of the company's own networks only, no resale, no
  inclusion in paid deliverables to third parties' (day-1 queue).
* c3 - every call sends ``Accept: application/json`` (provider profile, binding for isc.sans.edu) and
  ``?json`` on /api/ip/{ip}, /api/asnum/{count}/{asn} and /api/threatcategory/research. A redirect to
  /blockme.html is detected by the core from the redirect Location / final URL (P321, not only body
  markers): BLOCKED 'challenge' ('could not verify') and the host is short-circuited for the rest of the
  run (backoff, never retried with other headers). The documented ASN path is
  /api/asnum/{count}/{asn} (the condition's '/api/asnum/{asn}' form is read by ISC as a count).
* c4 - ISC asks API users to identify themselves: the provider profile uses the identifying contact UA
  (setting ``contact_email``, a team role mailbox, P326); without it the module is SKIPPED reason_code
  'config' before any request. No personal data is hard-coded.
* c5 - ``min_interval = 2.0`` (>= 1 s), cache 24 h. Attack counts carry first/last seen
  (observed_first/observed_last); DShield sightings are opportunistic scanning: tag ``scanner``, at most
  MEDIUM alone (MEDIUM when last seen within 30 days, LOW within 90 days, INFO and 'historical' beyond).
  Threat-feed memberships are context (``context_only``), never verdicts. An IP of the ISC 'research'
  threat category is a known benign research scanner (tag ``benign_scanner``; rule
  ``isc_research_scanner`` of ``v3lum/correlations/p2_g02_3.py`` caps blocklist-derived findings on it at
  LOW, never deleting them).
* c6 - attribution 'SANS ISC / DShield' (attribute ``data_attribution``, finding texts). Tests use the
  recorded IP, ASN and threat-category fixtures plus a blockme redirect.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, DeadlineExceeded, HttpError, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.core.noise import is_public_ip

SOURCE = "sans_isc.api"
BASE = "https://isc.sans.edu"
IP_API = BASE + "/api/ip/{ip}?json"
ASN_API = BASE + "/api/asnum/{count}/{asn}?json"
RESEARCH_API = BASE + "/api/threatcategory/research?json"
IPINFO = BASE + "/ipinfo/{ip}"
ATTRIBUTION = "SANS ISC / DShield"
LICENCE = "CC BY-NC-SA 4.0"
ASNUM_COUNT = 100
RECENT_DAYS = 30
HISTORICAL_DAYS = 90
MAX_ASN_TOP = 10
#: Rule id of the named suppression rule applied by ``v3lum.correlations.p2_g02_3`` to research scanners.
RULE_RESEARCH = "isc_research_scanner"
FEED_NOTES = {
    "openresolver": "open DNS resolver list",
    "mastodon": "Mastodon instance list",
    "myip": "what-is-my-IP service list",
    "miner": "crypto-mining related list",
    "research": "research scanner list",
}
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")
_DATE_RE = re.compile(r"^\s*(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?)?")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,63}$")
_FEED_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


# --------------------------------------------------------------------------------------
# pure helpers (stdlib only; ported from the batch prep parsers)
# --------------------------------------------------------------------------------------


def clean_text(value: Any, limit: int = 200) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(_CTRL_RE.sub(" ", value).split())
    return text[:limit] or None


def to_int(value: Any) -> int | None:
    """int from int/float/'5,008'; None for None, bool, '' and anything else."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value == value and abs(value) < 1e18 else None
    if isinstance(value, str):
        text = value.strip().replace(",", "").replace("_", "")
        if re.fullmatch(r"[+-]?\d{1,18}", text):
            return int(text)
    return None


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    m = _DATE_RE.match(value)
    if not m:
        return None
    try:
        y, mo, d, hh, mm, ss = (int(g) if g else 0 for g in m.groups())
        return datetime(y, mo, d, hh, mm, ss, tzinfo=timezone.utc)
    except ValueError:
        return None


def iso_date(value: Any) -> str | None:
    dt = _when(value)
    return dt.strftime("%Y-%m-%d") if dt else None


def iso_utc(value: Any) -> str | None:
    dt = _when(value)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def normalise_ipv4(value: Any) -> str | None:
    """Canonical dotted IPv4; accepts ISC's zero-padded octets ('203.000.113.005')."""
    if not isinstance(value, str):
        return None
    parts = value.strip().split(".")
    if len(parts) != 4 or not all(re.fullmatch(r"\d{1,3}", p) for p in parts):
        return None
    octets = [int(p) for p in parts]
    return ".".join(str(o) for o in octets) if all(o <= 255 for o in octets) else None


def parse_asn(value: Any) -> int | None:
    """'AS15169' / '15169' / 15169 -> 15169 (1..2**32-1), else None."""
    if isinstance(value, str):
        value = re.sub(r"^\s*[Aa][Ss]\s*", "", value)
    asn = to_int(value)
    return asn if asn is not None and 0 < asn < 2**32 else None


def load_json(content: Any) -> tuple[Any, str | None]:
    """(value, None) or (None, reason) for empty, HTML, XML (``?json`` missing) and malformed bodies."""
    if content is None:
        return None, "empty body"
    text = content.decode("utf-8", errors="replace") if isinstance(content, (bytes, bytearray)) else str(content)
    text = text.lstrip("﻿").strip()
    if not text:
        return None, "empty body"
    low = text[:512].lower()
    if low.startswith("<!doctype html") or low.startswith("<html") or "<body" in low or "<head" in low:
        return None, "HTML instead of JSON"
    if text.startswith("<"):
        return None, "XML instead of JSON (the ?json parameter is missing)"
    try:
        return json.loads(text), None
    except (ValueError, RecursionError):
        return None, "malformed JSON"


def parse_ip(data: Any) -> dict[str, Any]:
    """Normalise /api/ip/{ip}?json. Returns the fields below plus ``error`` (None when usable)."""
    out: dict[str, Any] = {
        "ip": None, "reports": None, "targets": None, "first_seen": None, "last_seen": None, "updated": None,
        "comment": None, "maxrisk": None, "asn": None, "as_name": None, "as_country": None, "as_size": None,
        "abuse_contact": None, "network": None, "threatfeeds": [], "has_reports": False, "error": None,
    }
    rec = data.get("ip") if isinstance(data, dict) else None
    if isinstance(data, dict) and data.get("error") and not isinstance(rec, dict):
        out["error"] = clean_text(str(data.get("error")), 120) or "error"
        return out
    if not isinstance(rec, dict):
        out["error"] = "unexpected SANS ISC /api/ip answer (no 'ip' object)"
        return out
    if rec.get("error"):
        out["error"] = clean_text(str(rec.get("error")), 120) or "error"
        return out
    out["ip"] = normalise_ipv4(rec.get("number"))
    out["reports"] = to_int(rec.get("count"))
    out["targets"] = to_int(rec.get("attacks"))
    out["first_seen"] = iso_date(rec.get("mindate"))
    out["last_seen"] = iso_date(rec.get("maxdate"))
    out["updated"] = iso_utc(rec.get("updated"))
    out["comment"] = clean_text(rec.get("comment"), 200)
    out["maxrisk"] = to_int(rec.get("maxrisk"))
    out["asn"] = parse_asn(rec.get("as"))
    out["as_name"] = clean_text(rec.get("asname"), 120)
    country = rec.get("ascountry")
    out["as_country"] = country.strip().upper() if isinstance(country, str) and re.fullmatch(r"\s*[A-Za-z]{2}\s*", country) else None
    out["as_size"] = to_int(rec.get("assize"))
    contact = rec.get("asabusecontact")
    out["abuse_contact"] = contact.strip().lower() if isinstance(contact, str) and _EMAIL_RE.match(contact.strip()) else None
    try:
        out["network"] = str(ipaddress.ip_network(str(rec.get("network") or "").strip(), strict=False)) if rec.get("network") else None
    except ValueError:
        out["network"] = None
    feeds = rec.get("threatfeeds")
    if isinstance(feeds, dict):
        for name, seen in sorted(feeds.items(), key=lambda kv: str(kv[0])):
            if not isinstance(name, str) or not _FEED_RE.match(name):
                continue
            seen = seen if isinstance(seen, dict) else {}
            feed = name.lower()
            out["threatfeeds"].append({
                "feed": feed, "first_seen": iso_date(seen.get("firstseen")), "last_seen": iso_date(seen.get("lastseen")),
                "note": FEED_NOTES.get(feed),
            })
    out["has_reports"] = (out["reports"] or 0) > 0 or (out["targets"] or 0) > 0
    return out


def parse_asnum(data: Any) -> dict[str, Any]:
    """Normalise /api/asnum/{count}/{asn}?json (shape unverified live: '[]' or blockme were the only
    answers). Accepts a list of records, {'asnum': ...}, {'data': ...} and index-keyed dicts."""
    out: dict[str, Any] = {"records": [], "error": None}
    items = data
    for _ in range(3):
        if isinstance(items, dict):
            for key in ("asnum", "data"):
                if key in items:
                    items = items[key]
                    break
            else:
                if items and all(isinstance(k, str) and k.isdigit() for k in items):
                    items = [items[k] for k in sorted(items, key=int)]
                break
    if isinstance(items, dict) and "ip" in items:
        items = [items]
    if not isinstance(items, list):
        out["error"] = "unexpected SANS ISC /api/asnum answer"
        return out
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        ip = normalise_ipv4(item.get("ip"))
        if not ip or ip in seen:
            continue
        seen.add(ip)
        out["records"].append({
            "ip": ip, "reports": to_int(item.get("reports")), "targets": to_int(item.get("targets")),
            "first_seen": iso_date(item.get("firstseen")), "last_seen": iso_date(item.get("lastseen")),
        })
    return out


def parse_threatcategory(data: Any) -> dict[str, dict[str, Any]]:
    """/api/threatcategory/research?json -> {ip: {type, added, last_seen}} (latest last_seen wins).
    Accepts the live list form and {'research': [...]} / {'threatcategory': {...}}."""
    items = data
    if isinstance(items, dict):
        items = items.get("threatcategory", items)
        if isinstance(items, dict):
            items = items.get("research") if "research" in items else next((v for v in items.values() if isinstance(v, list)), [])
    index: dict[str, dict[str, Any]] = {}
    if not isinstance(items, list):
        return index
    for item in items:
        if not isinstance(item, dict):
            continue
        ip = normalise_ipv4(item.get("ipv4", item.get("ip")))
        if not ip:
            continue
        kind = item.get("type")
        rec = {
            "type": kind.strip().lower() if isinstance(kind, str) and re.fullmatch(r"\s*[A-Za-z0-9_.-]{1,40}\s*", kind) else None,
            "added": iso_date(item.get("added", item.get("date"))),
            "last_seen": iso_date(item.get("lastseen")),
        }
        old = index.get(ip)
        if old is None or (rec["last_seen"] or "") > (old["last_seen"] or ""):
            index[ip] = rec
    return index


def report_severity(last_seen: str | None, now: datetime) -> tuple[str, bool]:
    """(severity, historical) of DShield reports by age (c5: at most MEDIUM alone)."""
    seen = _when(last_seen)
    if seen is None:
        return "low", False
    age = (now - seen).days
    if age <= RECENT_DAYS:
        return "medium", False
    if age <= HISTORICAL_DAYS:
        return "low", False
    return "info", True


# --------------------------------------------------------------------------------------
# module
# --------------------------------------------------------------------------------------


@register
class IscDshield(Module):
    name = "isc_dshield"
    title = "SANS ISC / DShield"
    description = (
        "DShield sensor reports (counts, first/last seen), threat-feed memberships, research-scanner status and "
        "AS data for an IP, or reported addresses of an AS, from the SANS Internet Storm Center API."
    )
    category = "threat_intel_ioc"
    accepts = {T.IPV4, T.ASN}
    produces = {T.ASN}
    terms = "noncommercial"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "sans_isc"
    sources = (SOURCE,)
    hosts = ("isc.sans.edu",)
    access_model = "free_noauth_limited"
    max_requests = 2
    expected_latency = 0.5
    timeout = 15.0
    min_interval = 2.0
    cache_ttl = 86400
    manual_link = "scanner_intel_g02_3:isc_ipinfo"
    default_enabled = True
    tags = {"reputation"}
    reference = "https://isc.sans.edu/api/"
    notice = (
        "SANS ISC data is CC BY-NC-SA 4.0 (noncommercial): off under the corporate profile until legal records a "
        "licence_allow entry for sans_isc.api citing the API page clause ('ok ... to protect your own company's "
        "network ... do not resell'): own-network defence only, no resale, not in paid deliverables to third "
        "parties. ISC asks API users to identify themselves: set contact_email (a team role mailbox). "
        "Attribution: SANS ISC / DShield."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.IPV4:
            return is_public_ip(entity.value)
        return parse_asn(entity.value) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if not str(ctx.setting("contact_email", "") or "").strip():
            # c4: ISC asks API users to identify themselves; never call it anonymously
            return res.mark(
                "skipped",
                "SANS ISC asks API users to identify themselves: set contact_email (a team role mailbox) - not queried",
                reason_code="config",
            )
        if entity.type is T.ASN:
            return self._asn(res, entity, ctx)
        return self._ip(res, entity, ctx)

    # ---------------------------------------------------------------- IPv4
    def _ip(self, res: ModuleResult, entity: Entity, ctx: Any) -> ModuleResult:
        ip = entity.value
        page = IPINFO.format(ip=ip)
        resp = ctx.http.get(IP_API.format(ip=ip), source=SOURCE)
        ctx.http.check(resp)  # blockme redirect, 429, 403, 5xx raise: could not verify (rule 5)
        data, problem = load_json(resp.content)
        if problem:
            return res.mark("error", f"SANS ISC /api/ip: {problem}: could not verify")
        parsed = parse_ip(data)
        if parsed["error"]:
            return res.mark("error", f"SANS ISC answered an error for the IP ({parsed['error']}): could not verify")
        research, research_problem = self._research(ctx)
        hit = research.get(ip) if research is not None else None
        now = ctx.now()
        res.raw = {
            "ip": {k: v for k, v in parsed.items() if k not in ("error", "has_reports")},
            "research_category": hit,
            "research_list": "checked" if research is not None else research_problem,
            "attribution": ATTRIBUTION,
            "licence": LICENCE,
        }
        res.attr("data_attribution", ATTRIBUTION)
        res.attr("dshield_reports", {
            "reports": parsed["reports"] or 0, "targets": parsed["targets"] or 0, "first_seen": parsed["first_seen"],
            "last_seen": parsed["last_seen"], "updated": parsed["updated"], "maxrisk": parsed["maxrisk"],
            "comment": parsed["comment"], "network": parsed["network"],
        })
        if parsed["asn"]:
            res.attr("asn", f"AS{parsed['asn']}")
            res.pivot(T.ASN, f"AS{parsed['asn']}", "belongs_to_asn", confidence="probable", note=parsed["as_name"] or "")
        res.attr("as_org", parsed["as_name"])
        res.attr("as_country", parsed["as_country"])
        res.attr("abuse_contact", parsed["abuse_contact"])  # a network role mailbox: attribute only, never a pivot
        res.attr("isc_threatfeeds", parsed["threatfeeds"])
        if parsed["has_reports"]:
            severity, historical = report_severity(parsed["last_seen"], now)
            res.finding(
                "Reported by DShield sensors (opportunistic scanning)",
                severity,
                f"{ATTRIBUTION}: {parsed['reports'] or 0} report(s) against {parsed['targets'] or 0} target(s), first seen "
                f"{parsed['first_seen'] or 'unknown'}, last seen {parsed['last_seen'] or 'unknown'}. DShield sensors see "
                "opportunistic internet-wide scanning, not activity targeting you specifically."
                + (" Last report older than 90 days: historical." if historical else ""),
                confidence="possible" if historical else "probable",
                criterion=(
                    f"DShield sensor reports ({parsed['reports'] or 0} reports, {parsed['targets'] or 0} targets, last seen "
                    f"{parsed['last_seen'] or 'unknown'}): opportunistic scanning, at most MEDIUM alone"
                ),
                data={"reports": parsed["reports"], "targets": parsed["targets"], "maxrisk": parsed["maxrisk"], "historical": historical},
                tags=["scanner"] + (["historical"] if historical else []),
                references=[page],
                source=SOURCE,
                observed_first=parsed["first_seen"],
                observed_last=parsed["last_seen"],
            )
        if parsed["threatfeeds"]:
            names = ", ".join(
                f"{f['feed']} ({f['first_seen'] or '?'} - {f['last_seen'] or '?'})" for f in parsed["threatfeeds"][:15]
            )
            res.finding(
                "Listed in SANS ISC threat feeds (context)",
                "info",
                f"{ATTRIBUTION} threat feeds listing this IP: {names}. Feed membership is context, not a verdict "
                "(e.g. open resolvers and what-is-my-IP services are listed too).",
                data={"feeds": parsed["threatfeeds"][:50]},
                tags=["context_only"],
                references=[page],
                source=SOURCE,
                observed_last=max((f["last_seen"] for f in parsed["threatfeeds"] if f["last_seen"]), default=None),
            )
        if hit is not None:
            label = hit.get("type") or "research"
            res.attr("isc_research_scanner", hit)
            res.attr("is_scanner", True)
            res.finding(
                f"Known research scanner ({label})",
                "info",
                f"{ATTRIBUTION} threat category 'research' lists this IP as a research scanner ({label}, added "
                f"{hit.get('added') or 'unknown'}, last seen {hit.get('last_seen') or 'unknown'}). Blocklist-derived "
                f"findings on this IP are capped at LOW (rule {RULE_RESEARCH}); nothing is deleted.",
                confidence="probable",
                criterion=f"SANS ISC threat category 'research' entry ({label})",
                data={"type": hit.get("type"), "suppression_rule": RULE_RESEARCH, "scope": "ip"},
                tags=["benign_scanner"],
                references=[page],
                source=SOURCE,
                observed_last=hit.get("last_seen"),
            )
        if research is None and research_problem:
            res.error = f"SANS ISC research-scanner list: {research_problem}"
        res.link("SANS ISC IP report (manual)", page)
        return res

    def _research(self, ctx: Any) -> tuple[dict[str, dict[str, Any]] | None, str]:
        """The 'research' threat category (cached 24 h). A failure never hides the IP answer: it is named as
        'could not verify' (the core keeps the blockme circuit for the rest of the run)."""
        try:
            resp = ctx.http.get(RESEARCH_API, source=SOURCE)
            ctx.http.check(resp)
        except DeadlineExceeded:
            raise
        except (Blocked, RateLimited, QuotaExceeded, AuthRequired, HttpError, NetworkError) as exc:
            return None, f"could not verify ({str(exc)[:160]})"
        data, problem = load_json(resp.content)
        if problem or not isinstance(data, (list, dict)):
            return None, f"could not verify ({problem or 'unexpected answer'})"
        return parse_threatcategory(data), ""

    # ---------------------------------------------------------------- ASN
    def _asn(self, res: ModuleResult, entity: Entity, ctx: Any) -> ModuleResult:
        asn = parse_asn(entity.value)
        resp = ctx.http.get(ASN_API.format(count=ASNUM_COUNT, asn=asn), source=SOURCE)
        ctx.http.check(resp)
        data, problem = load_json(resp.content)
        if problem:
            return res.mark("error", f"SANS ISC /api/asnum: {problem}: could not verify")
        if isinstance(data, dict) and data.get("error"):
            return res.mark("error", f"SANS ISC answered an error for AS{asn} ({clean_text(str(data.get('error')), 120)}): could not verify")
        parsed = parse_asnum(data)
        if parsed["error"]:
            return res.mark("error", f"{parsed['error']}: could not verify")
        records = parsed["records"]
        res.attr("data_attribution", ATTRIBUTION)
        top = sorted(records, key=lambda r: (-(r["reports"] or 0), r["ip"]))[:MAX_ASN_TOP]
        res.attr("isc_asn_reports", {
            "asn": f"AS{asn}", "listed": len(records), "reports": sum(r["reports"] or 0 for r in records),
            "targets": sum(r["targets"] or 0 for r in records), "top": top, "requested": ASNUM_COUNT,
        })
        res.raw = {"asn": f"AS{asn}", "records": records[:ASNUM_COUNT], "attribution": ATTRIBUTION, "licence": LICENCE}
        if not records:
            # the source answered '[]': no reported addresses in ISC's list for this AS (never 'clean')
            return res.mark("empty")
        last = max((r["last_seen"] for r in records if r["last_seen"]), default=None)
        res.finding(
            "Addresses of the AS reported by DShield sensors",
            "info",
            f"{ATTRIBUTION}: {len(records)} reported address(es) returned for AS{asn} (top by reports: "
            + ", ".join(f"{r['ip']} ({r['reports'] or 0})" for r in top[:5])
            + "). Opportunistic scanning sources; the addresses are third parties and are not investigated automatically.",
            data={"listed": len(records), "top": top[:5]},
            tags=["context_only"],
            source=SOURCE,
            observed_last=last,
        )
        return res
