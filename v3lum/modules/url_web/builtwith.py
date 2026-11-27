"""builtwith: BuiltWith Free / Domain / Relationships APIs, keyed (P073, batch p3-G03-1).

Sources: ``builtwith.api`` (provider seed ``builtwith``, terms ``key-terms``). Two modes (setting
``builtwith_mode``):

* ``free`` (default) - Free API ``/free1/api.json``: technology groups and categories with live/dead
  counts and first/last detection dates (no credits).
* ``domain`` - Domain API ``/v21/api.json`` (technologies, crawled hosts, organisation metadata) and
  Relationships API ``/rv5/api.json`` page 1 (domains sharing analytics/AdSense ids): paid credits,
  counted against setting ``builtwith_daily_credits`` per UTC day (``ctx.state``) on top of the
  provider's P334 rate budget.

Final conditions implemented (P073):

* c1 - key ``builtwith`` (``config.KNOWN_KEYS`` + the provider fragment, env ``V3LUM_BUILTWITH_KEY``),
  ``requires_keys``. BuiltWith takes ``KEY=`` in the URL: the central redactor masks it (AR01,
  ``v3lum.core.redact.KEY_PARAMS``) in every log line, cache row, evidence record and report.
* c2 - key-terms: POL-04 runs the module under the corporate profile only when the key's recorded
  plan is ``business`` (``v3lum keys`` plan flag / setting ``key_plans``), i.e. legal recorded a
  company/team plan. The Free API returns technology groups only; Domain/Relationships lookups spend
  paid credits under a local daily budget and the provider's ~1 request/s budget; the answer's
  ``X-API-CREDITS-REMAINING: 0`` stops further paid lookups for the day.
* c3 - every call carries ``NOPII=yes`` and ``HIDETEXT=yes``; personal Meta fields returned anyway
  (e-mails, phones, names, address, social profiles) are dropped, counted (``pii_dropped``) and such
  an answer is never cached.
* c4 - ``Errors[]`` arrays inside HTTP 200 bodies are never EMPTY: code -2 ('You need to login or
  create an account', wrong key) and -5 (plan upgrade) -> NEEDS_KEY; -3 credits -> QUOTA and -7
  (one lookup at a time) -> RATE_LIMITED through the provider markers (``builtwith__p3-G03-1.json``);
  every other code (-1, -4, -6, -8, -99, unknown) -> ERROR. Non-200 answers: 401/403 NEEDS_KEY,
  429 RATE_LIMITED, 5xx/HTML ERROR (challenge pages BLOCKED).
* c5 - relationship data follows the P061 rules: an id on more than 50 domains is a 'shared ID' (no
  pivots, confidence <= 0.3, ``shared_tracking_ids``); otherwise at most 10 ``same_analytics`` pivots
  per id, overlapping dates only, ``expand=False``, PROBABLE at most; with an org profile a non-own
  site carrying an own site's id is a 'possible clone (copied tracking ID)', never a same-owner link;
  IP/infrastructure and tracker ids never create relations. The relationships web page is the manual
  link (``url_web:builtwith_relationships``).
* c6 - fixtures: real keyless error answers and BuiltWith's official documented samples; a trimmed
  real success fixture captured with the team key does not exist yet (backlog p3-G03-1).
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, HttpError, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SOURCE = "builtwith.api"
KEY_NAME = "builtwith"
BUILTWITH_BASE = "https://api.builtwith.com"
ENDPOINTS = {"free": "/free1/api.json", "domain": "/v21/api.json", "relationships": "/rv5/api.json"}
PAID_ENDPOINTS = frozenset({"domain", "relationships"})
PRIVACY_PARAMS = (("NOPII", "yes"), ("HIDETEXT", "yes"))  # c3: on every call
CACHE_TTL = 604800  # 7 days: technology profiles change slowly and lookups cost credits
DEFAULT_DAILY_CREDITS = 100
SHARED_ID_MIN_MATCHES = 51  # P061 c5: more than 50 domains -> 'shared ID'
PIVOTS_PER_ID = 10  # P061 c5
SAME_ANALYTICS_MAX_CONFIDENCE = 0.7  # P061 c7: PROBABLE at most
SHARED_ID_MAX_CONFIDENCE = 0.3  # P061 c5
CLONE_FINDING_CAP = 20  # per run (at most 10 per id, PIVOTS_PER_ID)
TECH_CAP = 200
HOST_PIVOT_CAP = 50
STATE_BUDGET = "credits"

#: official error table (api.builtwith.com/errorCodes): code -> (status, reason code, kind, label)
_ERROR_CODES: dict[int, tuple[Status, str, str, str]] = {
    -1: (Status.ERROR, "error", "format", "not a supported return type"),
    -2: (Status.NEEDS_KEY, "needs_key", "login", "API key missing or wrong ('You need to login or create an account')"),
    -3: (Status.QUOTA, "quota", "credits", "out of API credits"),
    -4: (Status.ERROR, "error", "technology", "technology name not found"),
    -5: (Status.NEEDS_KEY, "needs_key", "plan", "plan upgrade needed"),
    -6: (Status.ERROR, "error", "server", "BuiltWith could not record usage"),
    -7: (Status.RATE_LIMITED, "rate_limited", "concurrency", "only one lookup at a time"),
    -8: (Status.ERROR, "error", "invalid_lookup", "invalid or unsupported domain"),
    -99: (Status.ERROR, "error", "server", "BuiltWith internal error"),
}
_ANALYTICS_TYPES = {"UA": "UA", "GOOGLE ANALYTICS": "UA", "GOOGLE-ANALYTICS": "UA", "GA": "UA", "GTM": "GTM",
                    "GOOGLE TAG MANAGER": "GTM", "GOOGLE-TAG-MANAGER": "GTM", "CA-PUB": "PUB", "GOOGLE ADSENSE": "PUB",
                    "GOOGLE-ADSENSE": "PUB", "ADSENSE": "PUB", "G": "G", "GA4": "G"}
_REGISTRATION_ABBR = frozenset({"CNPJ", "ABN", "ACN", "EIN", "CRN", "VAT", "NIP", "NIPC", "RFC", "BRN", "RU", "GLEIF", "GLEIFP", "KVK",
                                "SIREN", "SIRET", "UEN", "GST", "GSTIN", "CIF", "NIF", "PIVA", "UID", "CVR", "ORGNR", "KRS", "REGON",
                                "ICO", "OIB", "UTR", "CEGJEGYZEKSZAM"})
_SANCTION_ABBR = frozenset({"OFS", "OFCON", "FCDO", "TRES"})
_INFRA_ABBR = frozenset({"IP", "CF", "MX", "AZ", "APS", "WX", "CLOUDFRONT", "MAXCDN", "WIX", "AMAZON ASSOCIATES"})
_PII_META_KEYS = ("Emails", "Telephones", "Names", "City", "State", "Postcode", "Social")


# ================================================================================================ helpers
def _decode(raw: Any) -> str:
    if isinstance(raw, (bytes, bytearray)):
        text = bytes(raw).decode("utf-8", "replace")
    elif isinstance(raw, str):
        text = raw
    else:
        return ""
    return text[1:] if text.startswith("﻿") else text  # the official v5 sample is served with a BOM


def load_json(raw: Any) -> tuple[Any, str | None]:
    """``(obj, None)`` or ``(None, reason)``; HTML bodies are told apart from broken JSON."""
    if isinstance(raw, (dict, list)):
        return raw, None
    text = _decode(raw)
    if not text.strip():
        return None, "empty body"
    if text.lstrip()[:1] == "<":
        return None, "html instead of json"
    try:
        return json.loads(text), None
    except (ValueError, RecursionError) as exc:
        return None, f"invalid json ({str(exc)[:80]})"


def _int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def epoch_to_iso(value: Any) -> str | None:
    """Epoch seconds or milliseconds (auto-detected) -> 'YYYY-MM-DDTHH:MM:SSZ'; None for 0/invalid."""
    v = _int(value) if not isinstance(value, float) else value
    if not v or v <= 0:
        return None
    if v > 1e11:  # milliseconds (Domain/Relationships APIs)
        v = v / 1000.0
    try:
        return datetime.fromtimestamp(v, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def is_under(host: str, domain: str) -> bool:
    """Label-wise membership (``host == domain`` or a subdomain of it), never a string suffix."""
    if not host or not domain:
        return False
    h, d = host.lower().rstrip("."), domain.lower().rstrip(".")
    return h == d or h.endswith("." + d)


def builtwith_params(endpoint: str, lookup: str, key: str, page: int | None = None) -> dict[str, str]:
    """Query parameters of one call (c1, c3): one LOOKUP domain, NOPII=yes and HIDETEXT=yes always."""
    if endpoint not in ENDPOINTS:
        raise ValueError(f"unknown BuiltWith endpoint {endpoint!r}")
    if not isinstance(lookup, str) or not lookup.strip() or "," in lookup:
        raise ValueError("one LOOKUP domain per request")
    params = {"KEY": key, "LOOKUP": lookup.strip().lower()}
    params.update(dict(PRIVACY_PARAMS))
    if page is not None:
        params["PAGE"] = str(int(page))
    return params


def builtwith_errors(obj: Any) -> dict[str, Any] | None:
    """Classify an ``Errors[]`` array (HTTP 200 bodies) -> {status, reason_code, kind, code, reason}; None
    when there is no error. Unknown codes fall back to message keywords; never EMPTY (c4)."""
    if not isinstance(obj, dict):
        return None
    errors = obj.get("Errors")
    if not isinstance(errors, list) or not errors:
        return None
    first = errors[0] if isinstance(errors[0], dict) else {"Message": str(errors[0])}
    code = _int(first.get("Code"))
    msg = str(first.get("Message") or "")[:300]
    if code in _ERROR_CODES:
        status, reason_code, kind, label = _ERROR_CODES[code]
    else:
        low = msg.lower()
        if any(k in low for k in ("login", "api key", "create an account", "signup", "key is")):
            status, reason_code, kind, label = Status.NEEDS_KEY, "needs_key", "login", "API key missing or wrong"
        elif "credit" in low:
            status, reason_code, kind, label = Status.QUOTA, "quota", "credits", "out of API credits"
        elif any(k in low for k in ("too many", "rate limit", "concurrent", "one lookup at a time")):
            status, reason_code, kind, label = Status.RATE_LIMITED, "rate_limited", "concurrency", "rate limited"
        else:
            status, reason_code, kind, label = Status.ERROR, "error", "other", "provider error"
    return {"status": status, "reason_code": reason_code, "kind": kind, "code": code, "errors": len(errors),
            "reason": f"BuiltWith: {label} (code {code}): {msg}"}


def rate_headers(headers: Any) -> dict[str, int | None]:
    """X-RATELIMIT-* and X-API-CREDITS-* headers -> ints for the budget attribute (c2, P334)."""
    names = {"x-ratelimit-limit-persecond": "limit_per_second", "x-ratelimit-limit-concurrent": "limit_concurrent",
             "x-api-credits-available": "credits_available", "x-api-credits-used": "credits_used",
             "x-api-credits-remaining": "credits_remaining"}
    lower = {str(k).lower(): v for k, v in (headers or {}).items()} if isinstance(headers, dict) else {}
    out: dict[str, int | None] = {}
    for hname, key in names.items():
        m = re.search(r"-?\d+", str(lower.get(hname) or ""))
        out[key] = int(m.group(0)) if m else None
    return out


def has_personal_meta(obj: Any) -> bool:
    """True when a Domain API answer carries personal Meta fields despite NOPII=yes (never cached)."""
    for r in obj.get("Results") or [] if isinstance(obj, dict) else []:
        meta = r.get("Meta") if isinstance(r, dict) else None
        if isinstance(meta, dict) and any(meta.get(k) not in (None, "", [], {}) for k in _PII_META_KEYS):
            return True
    return False


# ================================================================================================ parsers
def parse_free(raw: Any) -> dict[str, Any]:
    """Free API (``free1``) -> technology groups with live/dead counts and dates (c2, c4)."""
    obj, why = load_json(raw)
    if obj is None:
        return {"status": Status.ERROR, "reason_code": "error", "reason": f"BuiltWith answer is not JSON (schema changed: {why}): could not verify"}
    err = builtwith_errors(obj)
    if err:
        return err
    if not isinstance(obj, dict) or not isinstance(obj.get("groups"), list):
        return {"status": Status.ERROR, "reason_code": "error", "reason": "BuiltWith Free API: schema changed ('groups' missing): could not verify"}
    groups = []
    for g in obj["groups"]:
        if not isinstance(g, dict) or not isinstance(g.get("name"), str):
            continue
        cats = [{"name": c["name"][:100], "live": _int(c.get("live")), "dead": _int(c.get("dead")), "latest": epoch_to_iso(c.get("latest")),
                 "oldest": epoch_to_iso(c.get("oldest"))}
                for c in g.get("categories") or [] if isinstance(c, dict) and isinstance(c.get("name"), str)]
        groups.append({"name": g["name"][:100], "live": _int(g.get("live")), "dead": _int(g.get("dead")),
                       "latest": epoch_to_iso(g.get("latest")), "oldest": epoch_to_iso(g.get("oldest")), "categories": cats[:50]})
    return {"status": Status.OK if groups else Status.EMPTY, "reason_code": "", "groups": groups[:100],
            "reason": "" if groups else "no technology groups indexed by BuiltWith for this domain",
            "first": epoch_to_iso(obj.get("first")), "last": epoch_to_iso(obj.get("last"))}


def parse_domain(raw: Any) -> dict[str, Any]:
    """Domain API (v21/v22/v26 shapes) -> technologies, crawled hosts and organisation metadata (c2-c4).

    Personal Meta fields are dropped even when returned despite NOPII (``pii_dropped`` counts them);
    Description/Link texts are never kept (HIDETEXT).
    """
    obj, why = load_json(raw)
    if obj is None:
        return {"status": Status.ERROR, "reason_code": "error", "reason": f"BuiltWith answer is not JSON (schema changed: {why}): could not verify"}
    err = builtwith_errors(obj)
    results = obj.get("Results") if isinstance(obj, dict) else None
    if err and not results:
        return err
    if not isinstance(results, list):
        return {"status": Status.ERROR, "reason_code": "error", "reason": "BuiltWith Domain API: schema changed ('Results' missing): could not verify"}
    if not results:
        return {"status": Status.EMPTY, "reason_code": "", "reason": "domain not indexed by BuiltWith (no data)"}
    r0 = results[0]
    if not isinstance(r0, dict):
        return {"status": Status.ERROR, "reason_code": "error", "reason": "BuiltWith Domain API: schema changed (Results[0] is not an object)"}
    res = r0.get("Result") if isinstance(r0.get("Result"), dict) else {}
    paths = res.get("Paths") if isinstance(res.get("Paths"), list) else []
    techs: dict[tuple[str, Any], dict[str, Any]] = {}
    hosts: set[str] = set()
    for p in paths:
        if not isinstance(p, dict):
            continue
        dom = p.get("Domain") if isinstance(p.get("Domain"), str) else ""
        sub = p.get("SubDomain") if isinstance(p.get("SubDomain"), str) else ""
        host = (f"{sub}.{dom}" if sub else dom).lower().strip(".")
        if host:
            hosts.add(host)
        for t in p.get("Technologies") or []:
            if not isinstance(t, dict) or not isinstance(t.get("Name"), str):
                continue
            key = (t["Name"][:120], t.get("Tag") if isinstance(t.get("Tag"), str) else None)
            first, last = _int(t.get("FirstDetected")), _int(t.get("LastDetected"))
            cur = techs.get(key)
            if cur is None:
                cats = t.get("Categories")
                cur = techs[key] = {"name": key[0], "tag": key[1], "parent": t.get("Parent") if isinstance(t.get("Parent"), str) else None,
                                    "categories": [c[:80] for c in cats if isinstance(c, str)][:10] if isinstance(cats, list) else [],
                                    "premium": str(t.get("IsPremium") or "").lower() in ("yes", "true"),
                                    "confidence": t.get("confidence") if isinstance(t.get("confidence"), (int, float)) else None,
                                    "_first": first, "_last": last, "hosts": set()}
            else:
                if first and (cur["_first"] is None or first < cur["_first"]):
                    cur["_first"] = first
                if last and (cur["_last"] is None or last > cur["_last"]):
                    cur["_last"] = last
            if host:
                cur["hosts"].add(host)
    tech_list = []
    for t in techs.values():
        t["first_detected"], t["last_detected"] = epoch_to_iso(t.pop("_first")), epoch_to_iso(t.pop("_last"))
        t["hosts"] = sorted(t["hosts"])[:20]
        tech_list.append(t)
    tech_list.sort(key=lambda t: (str(t["tag"]), t["name"]))
    meta = r0.get("Meta") if isinstance(r0.get("Meta"), dict) else {}
    pii = 0
    for k in _PII_META_KEYS:
        v = meta.get(k)
        pii += len(v) if isinstance(v, list) else (1 if isinstance(v, str) and v.strip() else 0)
    regs = [{"type": str(c.get("type"))[:20], "number": str(c.get("number"))[:40]} for c in meta.get("company_reg") or []
            if isinstance(c, dict) and c.get("number") is not None][:10]
    vertical = meta.get("Vertical") or meta.get("PrimaryBusiness")
    company = {"name": meta.get("CompanyName") if isinstance(meta.get("CompanyName"), str) else None,
               "vertical": vertical if isinstance(vertical, str) else None,
               "country": meta.get("Country") if isinstance(meta.get("Country"), str) else None, "registrations": regs}
    lookup = (r0.get("Lookup") if isinstance(r0.get("Lookup"), str) else "").lower()
    return {
        "status": Status.OK if tech_list else Status.EMPTY, "reason_code": "",
        "reason": "" if tech_list else "no technologies indexed by BuiltWith for this domain",
        "lookup": lookup or None, "first_indexed": epoch_to_iso(r0.get("FirstIndexed")), "last_indexed": epoch_to_iso(r0.get("LastIndexed")),
        "technologies": tech_list, "hosts": sorted(hosts),
        "new_hosts": sorted(h for h in hosts if lookup and h != lookup and is_under(h, lookup)),
        "company": company, "pii_dropped": pii, "partial_errors": err["reason"] if err else None,
    }


def identifier_kind(type_str: Any) -> str:
    """Relationship identifier type -> analytics | company_registration | sanction | infrastructure | tracker."""
    t = str(type_str or "").strip().upper()
    if t in _ANALYTICS_TYPES:
        return "analytics"
    if t in _REGISTRATION_ABBR or any(w in t for w in ("REGISTRATION", "BUSINESS NUMBER", "COMPANY NUMBER", "CADASTRO", "EMPLOYER ID")):
        return "company_registration"
    if t in _SANCTION_ABBR or "SANCTION" in t:
        return "sanction"
    if t in _INFRA_ABBR:
        return "infrastructure"
    return "tracker"


def analytics_label(type_str: Any, value: Any) -> str | None:
    """P061 forms: 'UA-<account>[-<property>]', 'GTM-XXXX', 'G-XXXX', 'pub-<16 digits>'; else None."""
    kind = _ANALYTICS_TYPES.get(str(type_str or "").strip().upper())
    v = str(value or "").strip()
    if not kind or not v:
        return None
    if kind == "UA":
        m = re.fullmatch(r"(?i)(?:UA-)?(\d{4,10})(-\d{1,4})?", v)
        return f"UA-{m.group(1)}{m.group(2) or ''}" if m else None
    if kind == "GTM":
        m = re.fullmatch(r"(?i)(?:GTM-)?([A-Z0-9]{4,9})", v)
        return f"GTM-{m.group(1).upper()}" if m else None
    if kind == "G":
        m = re.fullmatch(r"(?i)(?:G-)?([A-Z0-9]{6,12})", v)
        return f"G-{m.group(1).upper()}" if m else None
    m = re.fullmatch(r"(?i)(?:ca-)?(?:pub-)?(\d{16})", v)
    return f"pub-{m.group(1)}" if m else None


def _overlaps(match: dict[str, Any], ident: dict[str, Any]) -> bool:
    ov = match.get("Overlap")
    if isinstance(ov, bool):
        return ov
    a1, a2, b1, b2 = _int(ident.get("First")), _int(ident.get("Last")), _int(match.get("First")), _int(match.get("Last"))
    if None in (a1, a2, b1, b2):
        return False
    return a1 <= b2 and b1 <= a2  # type: ignore[operator]


def parse_relationships(raw: Any, lookup: str, own: Any = None) -> dict[str, Any]:
    """Relationships API (rv5; rv2 has the same shape) under the P061 rules (c4, c5).

    ``own(domain) -> bool`` tells org-profile own sites apart (None = no org profile: no clone rule).
    Returns identifiers (attribute rows), ``related`` (same_analytics pivots: overlapping dates,
    <= 10 per id, not shared), ``clones`` (one own and one non-own side) and paging facts.
    """
    obj, why = load_json(raw)
    if obj is None:
        return {"status": Status.ERROR, "reason_code": "error", "reason": f"BuiltWith answer is not JSON (schema changed: {why}): could not verify"}
    err = builtwith_errors(obj)
    rels = obj.get("Relationships") if isinstance(obj, dict) else None
    if err and not rels:
        return err
    if not isinstance(rels, list):
        return {"status": Status.ERROR, "reason_code": "error", "reason": "BuiltWith Relationships API: schema changed ('Relationships' missing): could not verify"}
    more = obj.get("more_results") is True
    identifiers: list[dict[str, Any]] = []
    related: dict[str, dict[str, Any]] = {}
    clones: list[dict[str, Any]] = []
    shared_ids: list[str] = []
    lk = (lookup or "").lower()
    lookup_own = bool(own(lk)) if own and lk else False
    flat = [(rel, ident) for rel in rels if isinstance(rel, dict) for ident in (rel.get("Identifiers") or []) if isinstance(ident, dict)]
    for pos, (_rel, ident) in enumerate(flat):
        itype, value = ident.get("Type"), ident.get("Value")
        if not isinstance(itype, str) or not itype.strip() or value in (None, ""):
            continue  # an identifier without type or value carries no evidence
        kind = identifier_kind(itype)
        matches = [m for m in ident.get("Matches") or [] if isinstance(m, dict) and isinstance(m.get("Domain"), str) and m["Domain"].strip()]
        n = len(matches)
        # paging is ordered identifier then domain: the last identifier of a page with more results may continue
        truncated = more and pos == len(flat) - 1
        shared = n >= SHARED_ID_MIN_MATCHES
        relational = kind == "analytics" and not shared and not truncated
        label = analytics_label(itype, value) if kind == "analytics" else None
        ordered = sorted(matches, key=lambda m: (not _overlaps(m, ident), m["Domain"].lower()))
        clone_side = [m for m in ordered if own and lk and lookup_own != bool(own(m["Domain"].lower().strip(".")))] if relational else []
        same_side = [m for m in ordered if m not in clone_side]
        pivots = [m for m in same_side if _overlaps(m, ident)][:PIVOTS_PER_ID] if relational else []
        row = {"type": itype[:40], "kind": kind, "value": None if kind == "infrastructure" else str(value)[:80], "analytics_id": label,
               "first": epoch_to_iso(ident.get("First")), "last": epoch_to_iso(ident.get("Last")), "match_count": n, "shared": shared,
               "label": "shared ID" if shared else None,
               "confidence": SAME_ANALYTICS_MAX_CONFIDENCE if relational else SHARED_ID_MAX_CONFIDENCE,
               "pivots": [m["Domain"].lower() for m in pivots], "clone_candidates": len(clone_side), "truncated": truncated}
        identifiers.append(row)
        if kind == "analytics" and shared and label:
            shared_ids.append(label)
        for m in clone_side[:PIVOTS_PER_ID]:
            other = m["Domain"].lower().strip(".")
            clones.append({"site": lk if not lookup_own else other, "own_site": other if not lookup_own else lk, "via": label or f"{itype}:{value}",
                           "overlap": _overlaps(m, ident), "lookup_is_clone": not lookup_own,
                           "first": epoch_to_iso(m.get("First")), "last": epoch_to_iso(m.get("Last"))})
        for m in pivots:
            dom = m["Domain"].lower().strip(".")
            rec = related.setdefault(dom, {"domain": dom, "via": [], "first": None, "last": None})
            rec["via"].append(label or f"{itype}:{value}")
            first, last = epoch_to_iso(m.get("First")), epoch_to_iso(m.get("Last"))
            rec["first"] = min(filter(None, [rec["first"], first]), default=None)
            rec["last"] = max(filter(None, [rec["last"], last]), default=None)
    paging = {"page": _int(obj.get("page")), "next_page": _int(obj.get("next_page")), "more_results": more,
              "results": _int(obj.get("results")), "max_per_page": _int(obj.get("max_per_page"))}
    return {"status": Status.OK if identifiers else Status.EMPTY, "reason_code": "", "reason": "" if identifiers else "no shared identifiers indexed",
            "identifiers": identifiers, "related": sorted(related.values(), key=lambda r: r["domain"]), "clones": clones,
            "shared_ids": sorted(set(shared_ids)), "paging": paging}


# ================================================================================================= module
@register
class BuiltWith(Module):
    name = "builtwith"
    title = "BuiltWith technology profile and relationships"
    description = ("Technology groups (Free API) or technologies, crawled hosts and shared analytics/AdSense ids (Domain and "
                   "Relationships APIs, paid credits) of a domain from BuiltWith, with NOPII and HIDETEXT on every call.")
    category = "url_web"
    accepts = {T.DOMAIN}
    produces = {T.DOMAIN, T.ANALYTICS_ID}
    reference = "https://api.builtwith.com/"
    notice = ("BuiltWith key-terms: runs under the corporate profile only with a company/team plan recorded as business "
              "(key_plans.builtwith). Domain/Relationships lookups spend paid credits (setting builtwith_daily_credits).")
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    hosts = ("api.builtwith.com",)
    provider = "builtwith"
    sources = (SOURCE,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,)
    max_requests = 2  # free: 1; domain: v21 + rv5 page 1
    expected_latency = 1.5
    timeout = 30.0
    min_interval = 1.0  # c2: ~1 request/s
    cache_ttl = CACHE_TTL
    max_pivots = 80
    manual_link = "url_web:builtwith_relationships"
    default_enabled = False
    settings = {
        "builtwith_mode": SettingSpec("free", "free = Free API technology groups (no credits); domain = Domain API v21 technologies "
                                              "+ Relationships API rv5 page 1 (paid credits, P073)", choices=("free", "domain")),
        "builtwith_daily_credits": SettingSpec(DEFAULT_DAILY_CREDITS, "paid BuiltWith lookups allowed per UTC day (local budget on top "
                                                                      "of the provider rate budget, P073 cond 2 / P334)"),
    }

    # ------------------------------------------------------------------------------------ budget
    @staticmethod
    def _budget(ctx: Any) -> dict[str, Any]:
        today = ctx.now().strftime("%Y-%m-%d")
        state = ctx.state.get(STATE_BUDGET) or {}
        if not isinstance(state, dict) or state.get("day") != today:
            state = {"day": today, "used": 0, "exhausted": False}
        return state

    @staticmethod
    def _save_budget(ctx: Any, state: dict[str, Any]) -> None:
        ctx.state.set(STATE_BUDGET, {"day": state["day"], "used": int(state.get("used") or 0), "exhausted": bool(state.get("exhausted"))})

    # ---------------------------------------------------------------------------------------- calls
    def _call(self, ctx: Any, endpoint: str, domain: str, key: str, budget: dict[str, Any], page: int | None = None) -> tuple[Any, dict[str, Any]]:
        resp = ctx.http.get(
            BUILTWITH_BASE + ENDPOINTS[endpoint],
            params=builtwith_params(endpoint, domain, key, page),
            source=SOURCE,
            cache_if=lambda r: not has_personal_meta(load_json(r.content)[0]),  # c3: a body with personal Meta is never cached
        )
        ctx.http.check(resp)  # classification (provider markers -3/-7, challenges), 401/403, 429, 5xx
        headers = rate_headers(resp.headers)
        if endpoint in PAID_ENDPOINTS and not resp.from_cache:
            budget["used"] = int(budget.get("used") or 0) + 1
        if headers.get("credits_remaining") == 0:
            budget["exhausted"] = True
        self._save_budget(ctx, budget)
        return resp.content, headers

    # ------------------------------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = ctx.key(KEY_NAME)
        if not key:
            return res.mark(Status.NEEDS_KEY, "BuiltWith API key not configured (v3lum keys set builtwith)", reason_code="needs_key")
        domain = entity.value
        mode = str(ctx.setting("builtwith_mode", "free") or "free")
        budget = self._budget(ctx)
        if mode != "domain":
            body, headers = self._call(ctx, "free", domain, key, budget)
            parsed = parse_free(body)
            if parsed["status"] not in (Status.OK, Status.EMPTY):
                return res.mark(parsed["status"], parsed["reason"], reason_code=parsed["reason_code"])
            self._budget_attr(res, ctx, headers, budget)
            if parsed["status"] is Status.EMPTY:
                return res.mark(Status.EMPTY, parsed["reason"])
            res.attr("builtwith_groups", {"endpoint": "free1", "first": parsed["first"], "last": parsed["last"], "groups": parsed["groups"]})
            res.raw = {"endpoint": "free1", "groups": parsed["groups"], "first": parsed["first"], "last": parsed["last"]}
            return res
        limit = _int(ctx.setting("builtwith_daily_credits", DEFAULT_DAILY_CREDITS)) or 0
        if budget.get("exhausted"):
            return res.mark(Status.QUOTA, "BuiltWith reported no API credits left today (X-API-CREDITS-REMAINING 0): paid lookups resume tomorrow", reason_code="quota")
        if int(budget.get("used") or 0) >= limit:
            return res.mark(Status.QUOTA, f"local BuiltWith credit budget used ({limit} paid lookups today, setting builtwith_daily_credits)", reason_code="quota")
        body, headers = self._call(ctx, "domain", domain, key, budget)
        parsed = parse_domain(body)
        if parsed["status"] not in (Status.OK, Status.EMPTY):
            return res.mark(parsed["status"], parsed["reason"], reason_code=parsed["reason_code"])
        if "technologies" in parsed:  # an EMPTY answer without Results has no profile to record
            self._record_domain(res, ctx, entity, parsed)
        rel_error = ""
        if budget.get("exhausted") or int(budget.get("used") or 0) >= limit:
            rel_error = "relationships not looked up: credit budget used"
        else:
            try:
                rbody, rheaders = self._call(ctx, "relationships", domain, key, budget, page=1)
                headers = {k: rheaders.get(k) if rheaders.get(k) is not None else v for k, v in headers.items()}
            except (Blocked, AuthRequired) as exc:
                rel_error = f"relationships could not be verified: {exc}"
            except (QuotaExceeded, RateLimited):
                raise  # the engine keeps the domain data and marks the run partial (stop reason quota/rate_limited)
            except (HttpError, NetworkError) as exc:
                rel_error = f"relationships could not be verified: {exc}"
            else:
                rel = parse_relationships(rbody, domain, self._own_checker(ctx))
                if rel["status"] in (Status.OK, Status.EMPTY):
                    self._record_relationships(res, ctx, entity, rel)
                else:
                    rel_error = rel["reason"]
        self._budget_attr(res, ctx, headers, budget)
        if rel_error:
            ctx.log(f"builtwith: {rel_error}", "warning")
            profile = dict(res.attributes.get("builtwith_profile") or {"endpoint": "v21", "lookup": domain})
            profile["relationships_error"] = rel_error[:300]
            res.attr("builtwith_profile", profile)
        if parsed["status"] is Status.EMPTY and not res.pivots and not res.findings and not res.attributes.get("builtwith_identifiers"):
            return res.mark(Status.EMPTY, parsed["reason"])
        return res

    # --------------------------------------------------------------------------------------- record
    @staticmethod
    def _own_checker(ctx: Any) -> Any:
        org = getattr(ctx, "org", None)
        if org is None or getattr(org, "is_empty", True):
            return None
        suppliers = set(org.supplier_domains())

        def own(domain: str) -> bool:
            if any(is_under(domain, s) for s in suppliers):
                return True  # a supplier site sharing an own id is not a clone (P061 c6)
            ent = Entity.try_make(T.DOMAIN, domain)
            owned = org.owns(ent) if ent is not None else None
            return bool(getattr(owned, "own", False))

        return own

    def _budget_attr(self, res: ModuleResult, ctx: Any, headers: dict[str, Any], budget: dict[str, Any]) -> None:
        limit = _int(ctx.setting("builtwith_daily_credits", DEFAULT_DAILY_CREDITS))
        res.attr("builtwith_budget", {**{k: v for k, v in headers.items() if v is not None},
                                      "local_used_today": int(budget.get("used") or 0), "local_daily_budget": limit})

    def _record_domain(self, res: ModuleResult, ctx: Any, entity: Entity, parsed: dict[str, Any]) -> None:
        if parsed["pii_dropped"]:
            ctx.log(f"builtwith: {parsed['pii_dropped']} personal Meta value(s) returned despite NOPII=yes were dropped", "warning")
        profile = {"endpoint": "v21", "lookup": parsed["lookup"], "first_indexed": parsed["first_indexed"],
                   "last_indexed": parsed["last_indexed"], "hosts": parsed["hosts"][:HOST_PIVOT_CAP], "company": parsed["company"],
                   "pii_dropped": parsed["pii_dropped"], "partial_errors": parsed["partial_errors"]}
        res.attr("builtwith_profile", {k: v for k, v in profile.items() if v not in (None, "")})
        if parsed["technologies"]:
            res.attr("technologies", parsed["technologies"][:TECH_CAP])
        for host in parsed["new_hosts"][:HOST_PIVOT_CAP]:
            res.pivot(T.DOMAIN, host, "subdomain", confidence=0.7)
        res.raw = {"endpoint": "v21", "technologies": len(parsed["technologies"]), "hosts": parsed["hosts"][:HOST_PIVOT_CAP],
                   "company": parsed["company"], "pii_dropped": parsed["pii_dropped"]}

    def _record_relationships(self, res: ModuleResult, ctx: Any, entity: Entity, rel: dict[str, Any]) -> None:
        res.attr("builtwith_identifiers", rel["identifiers"])
        if rel["shared_ids"]:
            res.attr("shared_tracking_ids", rel["shared_ids"])
            res.attr("analytics_shared_id", [{"id": row["analytics_id"], "domains": row["match_count"], "shared": True, "label": "shared ID",
                                             "reason": f"seen on {row['match_count']} domains (BuiltWith Relationships, > 50)"}
                                            for row in rel["identifiers"] if row["shared"] and row["analytics_id"]])
        for row in rel["identifiers"]:
            if row["kind"] == "analytics" and row["analytics_id"] and not row["shared"]:
                res.pivot(T.ANALYTICS_ID, row["analytics_id"], "mentions", confidence="probable", expand=False,
                          note="tracking id indexed by BuiltWith for this site (reverse lookup already done)")
        for rec in rel["related"]:
            res.pivot(T.DOMAIN, rec["domain"], "same_analytics", confidence=SAME_ANALYTICS_MAX_CONFIDENCE, expand=False,
                      note=f"shares {', '.join(rec['via'])} with {entity.value} (BuiltWith, overlapping dates): a shared tracking id, never proof of the same owner")
        clones = [c for c in rel["clones"] if c["overlap"]]
        for clone in clones[:CLONE_FINDING_CAP]:
            if clone["lookup_is_clone"]:
                res.finding(
                    "Possible clone of an organisation site (copied tracking ID)",
                    "medium",
                    f"{entity.value} carries {clone['via']}, the tracking id of own site {clone['own_site']} (BuiltWith Relationships, "
                    "overlapping dates): a phishing indicator (pages copied with their tracking code), never a same-owner link.",
                    confidence="possible",
                    criterion="tracking id of an org-profile own site on this non-own site with overlapping detection dates (P061 cond 6)",
                    tags=["possible_clone", "brand_abuse", "suspicious"],
                    source=SOURCE, data=clone, key=f"{clone['via']}|{clone['own_site']}",
                )
            else:
                res.pivot(T.DOMAIN, clone["site"], "copied_tracking_id", confidence="possible", expand=False,
                          note=f"non-own site carrying own tracking id {clone['via']}: possible clone, never a same-owner link")
                res.finding(
                    "Own tracking ID found on a non-own site (possible clone)",
                    "medium",
                    f"{clone['site']} carries {clone['via']}, a tracking id of this own site (BuiltWith Relationships, overlapping dates): "
                    "review it for brand abuse (possible clone, never a same-owner link).",
                    confidence="possible",
                    criterion="tracking id of this org-profile own site on a non-own, non-supplier site with overlapping detection dates (P061 cond 6)",
                    tags=["possible_clone", "brand_abuse"],
                    source=SOURCE, data=clone, key=f"{clone['via']}|{clone['site']}",
                )
        res.raw = {**(res.raw if isinstance(res.raw, dict) else {}), "relationships": {
            "identifiers": len(rel["identifiers"]), "related": [r["domain"] for r in rel["related"]], "clones": len(clones), "paging": rel["paging"]}}
