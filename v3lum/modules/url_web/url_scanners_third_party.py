"""Third-party URL scanners: lookups of EXISTING captures only (P078, batch p9-G03-3).

Two modules share this file (one source family, P078):

* ``url_scanners_third_party`` - urlDNA search (``POST /v1/search`` + ``GET /v1/scan/{id}`` of the
  newest DONE scans) and urlquery report search (``GET /public/v2/reports/search``), both through
  company-owned keys (terms ``key-terms``, tier community).
* ``url_scanners_lookyloo`` - lookups of existing captures on CIRCL's public Lookyloo instance
  (``POST /json/url_info`` / ``/json/hostname_info`` with ``cached_captures_only`` and
  ``GET /json/{uuid}/redirects``). A separate module because its registry terms are ``unknown`` until
  legal records CIRCL's terms for that instance (P078 cond 5): the policy gate keeps it off in every
  licence profile until then, while the key-terms module keeps the council's ``key-terms`` class.

Final conditions (P078):

* c1 - search/cached-result endpoints only. Every request is built by :func:`build_request`, which
  accepts only the endpoints of :data:`ALLOWED_REQUESTS` (https) and refuses every submission or scan
  endpoint (:data:`SUBMISSION_RULES`: urlDNA ``POST /v1/scan``, ``/v1/fast-check``, ``/v1/query*``;
  urlquery ``/submissions``, deletes, ``/detection/*``; Lookyloo ``/submit``, ``/capture``,
  ``/json/upload``, ``/admin/*`` and push/report actions) and the dropped hosts; the core lint table
  (:func:`v3lum.core.lint.forbidden_probe`) is applied as well. Tests assert none can be built.
* c2 - Sucuri SiteCheck, Web-Check and CheckPhish are not implemented (each makes the provider fetch
  or port-scan the target); their hosts are refused by the same guard.
* c3 - no submission module exists; the legal_dpo conditions for any future one are in
  docs/backlog/p9-G03-3.md.
* c4 - keys ``urldna`` / ``urlquery`` (provider fragments ``urldna.json`` / ``urlquery.json``, env
  ``V3LUM_URLDNA_KEY`` / ``V3LUM_URLQUERY_KEY``); a missing or refused key is NEEDS_KEY for that source
  (urlDNA keyless 422 'authorization header field required', urlquery 401 empty body or v2
  MISSING/INVALID_API_KEY). Each adapter has its own status (``res.source_status``) and its own budget
  (the provider quota blocks: urlDNA 100/day, urlquery RateLimit-Policy 500/day; Lookyloo 200/day).
* c5 - terms per source: urlDNA and urlquery ``key-terms``; CIRCL Lookyloo ``unknown`` (registry seed
  ``circl.lookyloo``) until legal records its terms.
* c6 - results are third-party verdicts kept as attributes with their scan dates (older than 30 days
  = historical); one vote per source (attribute ``third_party_scan_votes``, ``ground_truth`` false); an
  urlquery report without alerts is 'no_alerts', never 'benign'; Lookyloo gives captures, no vote.
  Lookyloo lists every capture whose tree CONTAINS the value (observed live): each capture carries its
  ``subject_role`` and only captures of the value itself (captured / redirect) give pivots.
  E-mails, recipient tokens and key-like values in result URLs are redacted (url_unwrap's
  ``redact_url_values`` plus the core ``redact_url``) before attributes, pivots and evidence.
* c7 - ``default_enabled = False``; documented-shape success fixtures and the recorded no-key fixtures.

Opsec: the council labelled the G03 group 'light'; after c1/c2 no code path makes any provider or
V3LUM touch the target, so both modules are PASSIVE third-party lookups (a LIGHT module may only
contact the investigated host itself, contract v2 rule 3). They keep the LIGHT intent of
analyst-typed seeds only (``run_on = 'seeds'``) and stay opt-in.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlsplit

from v3lum.core import lint as _lint
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    OfflineError,
    PolicyError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.core.redact import redact_url
from v3lum.modules.url_web.url_unwrap import redact_url_values

UTC = _dt.timezone.utc
HISTORICAL_DAYS = 30

SRC_URLDNA = "urldna.search"
SRC_URLQUERY = "urlquery.search"
SRC_LOOKYLOO = "circl.lookyloo"

URLDNA_SEARCH = "https://api.urldna.io/v1/search"
URLDNA_SCAN = "https://api.urldna.io/v1/scan/{scan_id}"
URLQUERY_SEARCH = "https://api.urlquery.net/public/v2/reports/search"
LOOKYLOO_BASE = "https://lookyloo.circl.lu"
LOOKYLOO_URL_INFO = LOOKYLOO_BASE + "/json/url_info"
LOOKYLOO_HOST_INFO = LOOKYLOO_BASE + "/json/hostname_info"
LOOKYLOO_REDIRECTS = LOOKYLOO_BASE + "/json/{uuid}/redirects"

SEARCH_TTL = 86400  # search answers: 24 h
RESULT_TTL = 7 * 86400  # an existing DONE scan result does not change: 7 d
URLDNA_DETAIL_SCANS = 2  # newest DONE scans whose verdict is read
LOOKYLOO_DETAIL_CAPTURES = 2
MAX_RECORDS = 25  # records kept per source in the attributes

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
URLDNA_ID_RE = re.compile(r"^[0-9A-Za-z_-]{8,64}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,190}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")

# =============================================================================================
# c1/c2 request guard: the ONLY requests these modules can build
# =============================================================================================

DROPPED_HOSTS = {
    "sitecheck.sucuri.net": "Sucuri SiteCheck starts a scan when no recent result exists (P078 cond 2)",
    "web-check.as93.net": "Web-Check makes its server fetch or port-scan the target (P078 cond 2)",
    "developers.checkphish.ai": "CheckPhish only scans: Bolster visits the URL (P078 cond 2)",
    "checkphish.ai": "CheckPhish only scans: Bolster visits the URL (P078 cond 2)",
    "checkphish.bolster.ai": "CheckPhish only scans: Bolster visits the URL (P078 cond 2)",
}

ALLOWED_REQUESTS = (
    ("POST", "api.urldna.io", re.compile(r"^/v1/search$")),
    ("GET", "api.urldna.io", re.compile(r"^/v1/scan/[0-9A-Za-z_-]{8,64}$")),
    ("GET", "api.urlquery.net", re.compile(r"^/public/v2/reports/search$")),
    ("POST", "lookyloo.circl.lu", re.compile(r"^/json/(?:url_info|hostname_info)$")),
    ("GET", "lookyloo.circl.lu", re.compile(r"^/json/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/redirects$")),
)

SUBMISSION_RULES = (  # (host, method or None for any, path regex, reason)
    ("api.urldna.io", "POST", re.compile(r"^/v1/scan/?$"), "urlDNA create scan (urlDNA fetches the URL)"),
    ("api.urldna.io", None, re.compile(r"^/v1/fast-check"), "urlDNA fast-check is not an approved endpoint (P078 cond 1)"),
    ("api.urldna.io", None, re.compile(r"^/v1/query"), "urlDNA saved queries store data at the provider"),
    ("api.urlquery.net", None, re.compile(r"^/public/v\d+/(?:submit|submissions)"), "urlquery submission (urlquery fetches the URL)"),
    ("api.urlquery.net", "DELETE", re.compile(r"."), "urlquery delete"),
    ("api.urlquery.net", None, re.compile(r"^/public/v\d+/detection/"), "urlquery YARA rule management"),
    ("lookyloo.circl.lu", None, re.compile(r"^/submit"), "Lookyloo /submit (CIRCL's crawler visits the URL; captures may be public)"),
    ("lookyloo.circl.lu", None, re.compile(r"^/capture"), "Lookyloo capture form"),
    ("lookyloo.circl.lu", None, re.compile(r"^/json/upload"), "Lookyloo upload"),
    ("lookyloo.circl.lu", None, re.compile(r"^/admin/"), "Lookyloo admin"),
    ("lookyloo.circl.lu", None, re.compile(r"^/json/[^/]+/(?:trigger_modules|misp_push|report|ollama_report)"),
     "Lookyloo action that pushes or sends data to third parties"),
)


def submission_reason(method: str, url: str) -> str | None:
    """c1/c2: why ``(method, url)`` is a submission, a scan trigger or a dropped source (else None)."""
    m = str(method or "").upper()
    try:
        parts = urlsplit(str(url or ""))
    except ValueError:
        return "unparseable URL"
    host = (parts.hostname or "").lower()
    path = parts.path or "/"
    if host in DROPPED_HOSTS:
        return f"dropped source: {DROPPED_HOSTS[host]}"
    for rhost, rmethod, rpath, reason in SUBMISSION_RULES:
        if host == rhost and (rmethod is None or rmethod == m) and rpath.search(path):
            return reason
    if _lint.forbidden_probe(str(url), method=m or "GET"):
        return "forbidden by the core probe table (submission/publication endpoint)"
    return None


def allowed_request(method: str, url: str) -> str | None:
    """c1: None when ``(method, url)`` is one of the approved search/cached-result endpoints, else why not."""
    reason = submission_reason(method, url)
    if reason:
        return reason
    try:
        parts = urlsplit(str(url or ""))
    except ValueError:
        return "unparseable URL"
    if parts.scheme != "https" or parts.username or parts.password or parts.port not in (None, 443):
        return "https on the default port only"
    host = (parts.hostname or "").lower()
    m = str(method or "").upper()
    for amethod, ahost, apath in ALLOWED_REQUESTS:
        if m == amethod and host == ahost and apath.match(parts.path or ""):
            return None
    return f"not an approved search/cached-result endpoint: {m} {host}{parts.path}"


def build_request(method: str, url: str) -> tuple[str, str]:
    """The single request builder of both modules: refuses (PolicyError 'policy') anything that is not
    an approved lookup endpoint, so no submission or scan request can ever be sent (c1)."""
    reason = allowed_request(method, url)
    if reason:
        raise PolicyError("policy", f"url_scanners: refused {str(method).upper()} {redact_url(url)[:120]}: {reason}")
    return str(method).upper(), str(url)


# =============================================================================================
# pure helpers (ported from the batch prep parsers, adapted to contract v2)
# =============================================================================================


def _s(value: Any) -> str:
    return value if isinstance(value, str) else ""


def load_json_text(raw: Any) -> tuple[Any, str | None]:
    """Body -> (data, None) or (None, 'empty' | 'html' | 'malformed')."""
    if isinstance(raw, (dict, list)):
        return raw, None
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("utf-8", "replace")
    if not isinstance(raw, str):
        return None, "malformed"
    text = raw.strip()
    if not text:
        return None, "empty"
    if text[:1] == "<":
        return None, "html"
    try:
        return json.loads(text), None
    except ValueError:
        return None, "malformed"


def parse_time(value: Any) -> _dt.datetime | None:
    """ISO 8601 / RFC 3339 or epoch seconds -> aware UTC datetime (None when unreadable)."""
    if value is None or value == "" or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return _dt.datetime.fromtimestamp(float(value), UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    s = value.strip()
    if s[-1:] in ("Z", "z"):
        s = s[:-1] + "+00:00"
    try:
        d = _dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=UTC)
    return d.astimezone(UTC)


def age_marker(value: Any, now: _dt.datetime) -> dict[str, Any]:
    """c6: scan date -> {scan_date, age_days, historical}; older than 30 days = historical."""
    d = parse_time(value)
    if d is None:
        return {"scan_date": None, "age_days": None, "historical": False}
    age = (now - d).total_seconds() / 86400.0
    return {"scan_date": d.isoformat().replace("+00:00", "Z"), "age_days": int(age), "historical": age > HISTORICAL_DAYS}


def clean_url(url: Any) -> tuple[str | None, bool]:
    """c6: a result URL with e-mails, recipient tokens, userinfo and key-like values redacted.
    Returns (url or None, redacted?)."""
    if not isinstance(url, str) or not url.strip():
        return None, False
    red, kinds = redact_url_values(url.strip())
    red = redact_url(red if isinstance(red, str) else url)
    return red, bool(kinds) or red != url.strip()


def _host(url: Any) -> str:
    try:
        return (urlsplit(str(url)).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def query_value(entity: Entity) -> tuple[str, str] | None:
    """('domain', host) or ('url', url) to look up; None when the value cannot be expressed safely."""
    if entity.type is T.DOMAIN:
        d = str(entity.value).strip().lower().rstrip(".")
        return ("domain", d) if _DOMAIN_RE.match(d) else None
    if entity.type is T.URL:
        u = str(entity.value).strip()
        if not u.lower().startswith(("http://", "https://")) or any(c in u for c in "\"\\\r\n") or len(u) > 2000:
            return None
        return ("url", u)
    return None


# ---- urlDNA -----------------------------------------------------------------------------------


def urldna_search_body(kind: str, value: str, max_results: int = 32) -> dict[str, Any] | None:
    """c1: CQL body for POST /v1/search (``domain = x`` | ``submitted_url = "x"``; CQL max 200 chars)."""
    if kind == "domain":
        q = f"domain = {value}"
    elif kind == "url":
        if len(value) > 180:
            return None
        q = f'submitted_url = "{value}"'
    else:
        return None
    if len(q) > 200:
        return None
    return {"query": q, "max_results": max(1, min(int(max_results), 32)), "page": 1}


def urldna_missing_auth(body: Any) -> bool:
    """c4: the observed keyless answer - 422 FastAPI 'Field required' on header 'authorization'."""
    data, _why = load_json_text(body)
    detail = data.get("detail") if isinstance(data, dict) else None
    for item in detail if isinstance(detail, list) else []:
        loc = item.get("loc") if isinstance(item, dict) else None
        if isinstance(loc, list) and [str(x).lower() for x in loc[:2]] == ["header", "authorization"]:
            return True
    return False


def parse_urldna_search(body: Any, now: _dt.datetime) -> dict[str, Any]:
    """POST /v1/search -> {'scans': [...newest first], 'reason': None | why}. Search results carry no verdict."""
    data, why = load_json_text(body)
    if why or not isinstance(data, list):
        return {"scans": [], "reason": why or "unexpected answer (not a list)"}
    scans = []
    for it in data:
        if not isinstance(it, dict) or not URLDNA_ID_RE.match(_s(it.get("id"))):
            continue
        rec = {
            "scan_id": it["id"],
            "submitted_url": _s(it.get("submitted_url")) or None,
            "domain": _s(it.get("domain")).lower() or None,
            "target_url": _s(it.get("target_url")) or None,
            "status": _s(it.get("status")) or None,
            "private_scan": bool(it.get("private_scan")),
            "error_code": _s(it.get("error_code")) or None,
        }
        rec.update(age_marker(it.get("submitted_date"), now))
        scans.append(rec)
    scans.sort(key=lambda r: r["scan_date"] or "", reverse=True)
    return {"scans": scans, "reason": None}


def parse_urldna_scan_result(body: Any, now: _dt.datetime) -> dict[str, Any]:
    """GET /v1/scan/{id} (an existing result) -> third-party verdict 'malicious' | 'safe' | None with its date."""
    data, why = load_json_text(body)
    if why or not isinstance(data, dict):
        return {"reason": why or "unexpected answer (not an object)"}
    scan = data.get("scan") if isinstance(data.get("scan"), dict) else {}
    cls = data.get("classification") if isinstance(data.get("classification"), dict) else {}
    raw = _s(cls.get("verdict")).upper()
    verdict = {"MALICIOUS": "malicious", "SAFE": "safe", "CLEAN": "safe"}.get(raw)
    if verdict is None and isinstance(data.get("malicious"), bool):
        verdict = "malicious" if data["malicious"] else "safe"
    ipobj = data.get("ip_address") if isinstance(data.get("ip_address"), dict) else {}
    page = data.get("page") if isinstance(data.get("page"), dict) else {}
    chain = [c.get("redirect_url") for c in (data.get("redirect_chains") if isinstance(data.get("redirect_chains"), list) else [])
             if isinstance(c, dict) and isinstance(c.get("redirect_url"), str)]
    final = _s(scan.get("target_url")) or (chain[-1] if chain else "") or _s(scan.get("submitted_url"))
    techs = data.get("technologies") if isinstance(data.get("technologies"), list) else []
    out: dict[str, Any] = {
        "reason": None,
        "source": SRC_URLDNA,
        "scan_id": _s(scan.get("id")) or None,
        "status": _s(scan.get("status")) or None,
        "verdict": verdict,
        "final_url": final or None,
        "redirect_count": max(0, len(chain) - 1),
        "title": _s(page.get("title")) or None,
        "ip": _s(ipobj.get("ip")) or None,
        "asn": _s(ipobj.get("asn")) or None,
        "country_code": _s(ipobj.get("country_code")) or None,
        "technologies": sorted({t["name"] for t in techs if isinstance(t, dict) and isinstance(t.get("name"), str)})[:20],
        "private_scan": bool(scan.get("private_scan")),
    }
    out.update(age_marker(scan.get("submitted_date"), now))
    return out


# ---- urlquery ---------------------------------------------------------------------------------

URLQUERY_BAD_VERDICTS = frozenset({"phishing", "scam", "fraud", "malware", "malicious"})


def urlquery_error_code(body: Any) -> str:
    """The v2 error envelope code ('MISSING_API_KEY', 'INVALID_API_KEY', ...) or ''."""
    data, _why = load_json_text(body)
    err = data.get("error") if isinstance(data, dict) and isinstance(data.get("error"), dict) else {}
    return _s(err.get("error")).upper()


def urlquery_search_params(kind: str, value: str, now: _dt.datetime, days: int = 365, limit: int = 25) -> dict[str, Any] | None:
    """c1: GET /public/v2/reports/search parameters (url.domain / url.addr with a date range)."""
    if kind == "domain":
        q = f"url.domain:{value}"
    elif kind == "url":
        addr = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", value)
        if not addr:
            return None
        q = f'url.addr:"{addr}"'
    else:
        return None
    start = (now - _dt.timedelta(days=days)).date().isoformat()
    q += f" AND date:[{start} TO {now.date().isoformat()}]"
    return {"query": q, "limit": max(1, min(int(limit), 100)), "offset": 0}


def _alerts(det: Any, key: str) -> list[dict[str, Any]]:
    if not isinstance(det, dict) or not isinstance(det.get(key), list):
        return []
    return [a for a in det[key] if isinstance(a, dict)]


def parse_urlquery_overview(item: Any, now: _dt.datetime) -> dict[str, Any] | None:
    """One report overview -> dated third-party verdict summary ('malicious' | 'suspicious' | 'no_alerts')."""
    if not isinstance(item, dict) or not _s(item.get("report_id")):
        return None
    det = item.get("detection")
    alerts = {k: _alerts(det, k) for k in ("ids", "urlquery", "analyzer")}
    verdicts = sorted({_s(a.get("verdict")).lower() for k in ("urlquery", "analyzer") for a in alerts[k] if _s(a.get("verdict"))})
    if any(v in URLQUERY_BAD_VERDICTS for v in verdicts):
        summary = "malicious"
    elif "suspicious" in verdicts or alerts["ids"]:
        summary = "suspicious"
    else:
        summary = "no_alerts"  # never 'benign': no alert is not a verdict of safety

    def _url(obj: Any) -> str | None:
        if not isinstance(obj, dict):
            return None
        sch, addr = _s(obj.get("schema")) or "http", _s(obj.get("addr"))
        return f"{sch}://{addr}" if addr else None

    final = item.get("final") if isinstance(item.get("final"), dict) else {}
    ip = item.get("ip") if isinstance(item.get("ip"), dict) else {}
    settings = item.get("settings") if isinstance(item.get("settings"), dict) else {}
    rid = _s(item.get("report_id"))
    rec: dict[str, Any] = {
        "source": SRC_URLQUERY,
        "report_id": rid,
        "report_url": f"https://urlquery.net/report/{rid}" if UUID_RE.match(rid) else None,
        "status": _s(item.get("status")) or None,
        "url": _url(item.get("url")),
        "final_url": _url(final.get("url")),
        "title": _s(final.get("title")) or None,
        "ip": _s(ip.get("addr")) or None,
        "asn": ip.get("asn") if isinstance(ip.get("asn"), int) and not isinstance(ip.get("asn"), bool) else None,
        "country_code": _s(ip.get("country_code")) or None,
        "access": _s(settings.get("access")) or None,
        "alert_counts": {k: len(v) for k, v in alerts.items()},
        "verdicts": verdicts,
        "verdict_summary": summary,
    }
    rec.update(age_marker(item.get("date"), now))
    return rec


def parse_urlquery_search(body: Any, now: _dt.datetime) -> dict[str, Any]:
    """v2 search envelope -> {'total_hits', 'items', 'hidden_matches', 'reason'}. hidden_matches = matches
    the key may not see (visibility filter after matching): reported as such, never as 'not found'."""
    data, why = load_json_text(body)
    if why or not isinstance(data, dict):
        return {"total_hits": 0, "items": [], "hidden_matches": 0, "reason": why or "unexpected answer (not an object)"}
    if data.get("success") is not True:
        return {"total_hits": 0, "items": [], "hidden_matches": 0, "reason": "success flag missing"}
    payload = data.get("data") if isinstance(data.get("data"), dict) else None
    if payload is None or not isinstance(payload.get("items", []), list):
        return {"total_hits": 0, "items": [], "hidden_matches": 0, "reason": "unexpected answer (no data.items)"}
    page = payload.get("page") if isinstance(payload.get("page"), dict) else {}
    total = page.get("total_hits") if isinstance(page.get("total_hits"), int) and not isinstance(page.get("total_hits"), bool) else 0
    items = [r for r in (parse_urlquery_overview(i, now) for i in payload.get("items") or []) if r]
    return {"total_hits": total, "items": items, "hidden_matches": max(0, total - len(items)) if total and not items else 0, "reason": None}


# ---- Lookyloo ---------------------------------------------------------------------------------


def lookyloo_lookup_body(kind: str, value: str, limit: int = 20) -> dict[str, Any] | None:
    """c1: body of POST /json/url_info | /json/hostname_info; cached_captures_only stays True (never re-caches)."""
    base = {"cached_captures_only": True, "with_urls_occurrences": False, "limit": max(1, min(int(limit), 50)), "offset": 0}
    if kind == "url":
        return {"url": value, **base}
    if kind == "domain":
        return {"hostname": value, **base}
    return None


def parse_lookyloo_occurrences(body: Any, now: _dt.datetime) -> dict[str, Any]:
    """url_info / hostname_info -> existing captures (newest first); partial when some were not cached."""
    data, why = load_json_text(body)
    if why or not isinstance(data, dict):
        return {"total": 0, "captures": [], "partial": False, "reason": why or "unexpected answer (not an object)"}
    if _s(data.get("error")):
        return {"total": 0, "captures": [], "partial": False, "reason": f"Lookyloo error: {_s(data.get('error'))[:120]}"}
    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    resp = data.get("response")
    if not isinstance(resp, list):
        return {"total": 0, "captures": [], "partial": False, "reason": "unexpected answer (no response list)"}
    caps = []
    seen: set[str] = set()
    for it in resp:
        if not isinstance(it, dict):
            continue
        uid = _s(it.get("capture_uuid"))
        if not UUID_RE.match(uid) or uid.lower() in seen:
            continue  # the public instance can list one capture twice (observed 2026-11-26)
        seen.add(uid.lower())
        rec: dict[str, Any] = {"capture_uuid": uid.lower(), "title": _s(it.get("title")) or None, "tree_url": f"{LOOKYLOO_BASE}/tree/{uid.lower()}"}
        rec.update(age_marker(it.get("start_timestamp"), now))
        caps.append(rec)
    caps.sort(key=lambda r: r["scan_date"] or "", reverse=True)
    total = meta.get("total") if isinstance(meta.get("total"), int) and not isinstance(meta.get("total"), bool) else len(caps)
    return {"total": total, "captures": caps, "partial": bool(_s(meta.get("warning"))), "reason": None}


def parse_lookyloo_redirects(body: Any) -> dict[str, Any]:
    """/json/{uuid}/redirects -> {'url', 'redirects', 'final_url'} or a reason."""
    data, why = load_json_text(body)
    resp = data.get("response") if isinstance(data, dict) and isinstance(data.get("response"), dict) else None
    if why or resp is None:
        err = _s(data.get("error")) if isinstance(data, dict) else ""
        return {"reason": why or err or "unexpected answer", "redirects": []}
    reds = [r for r in (resp.get("redirects") if isinstance(resp.get("redirects"), list) else []) if isinstance(r, str)]
    final = reds[-1] if reds else (_s(resp.get("url")) or None)
    return {"reason": None, "url": _s(resp.get("url")) or None, "redirects": reds, "final_url": final}


def _host_within(host: str, subject: str) -> bool:
    return bool(host and subject) and (host == subject or host.endswith("." + subject))


def capture_subject_role(red: dict[str, Any], subject_host: str) -> str:
    """How the looked-up host appears in an existing capture (Lookyloo url_info/hostname_info list every
    capture whose tree CONTAINS the host, also as a sub-resource of an unrelated site - observed live):
    'captured' (the capture was submitted for it), 'redirect' (a hop of its redirect chain), 'resource'
    (only inside the page: a script, image or link) or 'unknown' (redirect data not read)."""
    if not red or red.get("reason"):
        return "unknown"
    if _host_within(_host(red.get("url")), subject_host):
        return "captured"
    if any(_host_within(_host(u), subject_host) for u in red.get("redirects") or []):
        return "redirect"
    return "resource"


def consensus_votes(records: list[dict[str, Any]]) -> dict[str, Any]:
    """c6: the newest non-historical vote per source; never ground truth. Lookyloo has no vote."""
    best: dict[str, dict[str, Any]] = {}
    for r in records:
        src = r.get("source")
        if src == SRC_URLDNA:
            vote = r.get("verdict")
        elif src == SRC_URLQUERY:
            vote = {"malicious": "malicious", "suspicious": "suspicious"}.get(str(r.get("verdict_summary")))
        else:
            vote = None
        if not src or vote is None or r.get("historical"):
            continue
        if src not in best or (r.get("scan_date") or "") > (best[src].get("scan_date") or ""):
            best[src] = {"source": src, "vote": vote, "scan_date": r.get("scan_date")}
    return {"votes": sorted(best.values(), key=lambda x: x["source"]), "ground_truth": False}


# =============================================================================================
# shared run helpers
# =============================================================================================

#: per-source failure -> (Status, reason_code); the most telling failure decides when no source answered
_FAILURE_ORDER = ("rate_limited", "quota", "blocked", "timeout", "error", "offline", "needs_key", "not_applicable")


def _fail_from_exception(exc: Exception) -> tuple[Status, str, str]:
    if isinstance(exc, OfflineError):  # before NetworkError: its subclass
        return Status.UNAVAILABLE, "offline", "offline mode: could not verify"
    if isinstance(exc, DeadlineExceeded):
        return Status.ERROR, "timeout", "run deadline reached: could not verify"
    if isinstance(exc, QuotaExceeded):
        return Status.QUOTA, "quota", "quota exhausted"
    if isinstance(exc, RateLimited):
        return Status.RATE_LIMITED, "rate_limited", "rate limited: could not verify"
    if isinstance(exc, Blocked):
        code = getattr(exc, "reason_code", "") or "challenge"
        return Status.BLOCKED, code if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge", "blocked: could not verify"
    if isinstance(exc, AuthRequired):
        return Status.NEEDS_KEY, "needs_key", "key refused (invalid key or plan)"
    if isinstance(exc, (HttpError, NetworkError)):
        return Status.ERROR, "error", f"could not verify ({type(exc).__name__})"
    return Status.ERROR, "error", "could not verify"


class _Outcome:
    """Per-source outcome collector of one run (c4: each adapter has its own status)."""

    def __init__(self) -> None:
        self.answered: list[str] = []
        self.failed: dict[str, tuple[Status, str, str]] = {}

    def fail(self, res: ModuleResult, source: str, status: Status, code: str, reason: str) -> None:
        self.failed[source] = (status, code, reason)
        res.source_status(source, status, reason_code=code, reason=reason[:300])

    def finish(self, res: ModuleResult, has_data: bool) -> ModuleResult:
        if self.answered:
            return res if has_data else res.mark("empty")
        if not self.failed:
            return res.mark("error", "no source answered: could not verify")
        by_code = {code: (st, code, why) for st, code, why in self.failed.values()}
        for code in _FAILURE_ORDER:
            if code in by_code:
                st, c, _why = by_code[code]
                text = "; ".join(f"{src}: {why}" for src, (_s2, _c2, why) in sorted(self.failed.items()))
                if c == "not_applicable":
                    return res.mark("skipped", text[:400], reason_code="not_applicable")
                return res.mark(st.value, f"could not verify - {text}"[:400], reason_code=c)
        return res.mark("error", "could not verify")


def _record_scan(res: ModuleResult, rec: dict[str, Any], *, relation_prefix: str = "scanner", pivots: bool = True) -> dict[str, Any]:
    """Redact the URLs of one record (c6) and add its pivots (final URL, host, server IPv4)."""
    out = dict(rec)
    for key in ("final_url", "url", "submitted_url", "target_url", "capture_url"):
        if key in out:
            clean, _red = clean_url(out.get(key))
            out[key] = clean
    if not pivots:
        return out
    historical = bool(rec.get("historical"))
    raw_final = rec.get("final_url")
    final, redacted = clean_url(raw_final)
    if final and not redacted:
        res.pivot(T.URL, final, f"{relation_prefix}_final_url", confidence="possible", expand=not historical,
                  note="final URL recorded by a third-party scanner" + (" (historical)" if historical else ""))
    host = _host(raw_final) if raw_final else ""
    if host and not _is_ip(host):
        res.pivot(T.DOMAIN, host, f"{relation_prefix}_final_host", confidence="possible", expand=not historical)
    ip = rec.get("ip")
    if isinstance(ip, str) and _is_ip(ip) and ipaddress.ip_address(ip).version == 4:
        res.pivot(T.IPV4, ip, f"{relation_prefix}_server_ip", confidence="possible", expand=False,
                  note="server address recorded by a third-party scanner (may be a CDN or shared host)")
    return out


# =============================================================================================
# module 1: urlDNA + urlquery (key-terms)
# =============================================================================================


@register
class UrlScannersThirdParty(Module):
    name = "url_scanners_third_party"
    title = "Third-party URL scanners (urlDNA, urlquery): existing scans"
    description = ("Dated verdicts of EXISTING third-party captures of a URL or domain: urlDNA scan search (+ the newest "
                   "results' verdicts) and urlquery report search, through company keys. Search only: nothing is submitted "
                   "and no provider is made to visit the target.")
    category = "url_web"
    accepts = frozenset({T.URL, T.DOMAIN})
    produces = frozenset({T.URL, T.DOMAIN, T.IPV4})
    tags = frozenset({"reputation", "cached_only"})
    reference = "https://docs.urldna.io/api-reference/endpoint/search"
    notice = ("Third-party scanner verdicts are opinions of other users' captures: one vote per source, never ground "
              "truth; results older than 30 days are historical. Search endpoints only (P078): no URL is ever submitted. "
              "Keys are company-owned (key-terms): record the plan with key_plans.<key> = 'business'.")
    run_on = "seeds"
    # ---- MUST be declared ---------------------------------------------------------------------
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    hosts = ("api.urldna.io", "api.urlquery.net")
    max_requests = 1 + URLDNA_DETAIL_SCANS + 1  # urlDNA search + 2 results, urlquery search
    expected_latency = 2.0
    # ---- registry and behaviour -----------------------------------------------------------------
    provider = "urldna"
    sources = (SRC_URLDNA, SRC_URLQUERY)
    access_model = "free_auth_limited"
    optional_keys = ("urldna", "urlquery")
    cache_ttl = SEARCH_TTL
    min_interval = 1.0
    timeout = 45.0
    max_pivots = 30
    default_enabled = False

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        q = query_value(entity)
        if q is None:
            return res.mark("skipped", "value cannot be expressed as a scanner search query", reason_code="not_applicable")
        kind, value = q
        now = ctx.now()
        allowed = getattr(ctx, "allowed_sources", None) or frozenset(self.sources)
        outcome = _Outcome()
        records: list[dict[str, Any]] = []
        summary: dict[str, Any] = {}
        raw: dict[str, Any] = {}
        if SRC_URLDNA in allowed:
            self._urldna(ctx, res, kind, value, now, outcome, records, summary, raw)
        if SRC_URLQUERY in allowed:
            self._urlquery(ctx, res, kind, value, now, outcome, records, summary, raw)
        if not outcome.answered and not outcome.failed:
            return res.mark("skipped", "no allowed source", reason_code="licence")
        cleaned = [_record_scan(res, r) for r in records]
        if cleaned:
            res.attr("third_party_scans", cleaned[: MAX_RECORDS * 2])
            votes = consensus_votes(records)
            res.attr("third_party_scan_votes", votes)
            self._findings(res, records, votes)
        if summary:
            res.attr("third_party_scan_summary", summary)
        if raw:
            res.raw = raw
        has_data = bool(cleaned) or any(int(v.get("hidden_matches") or 0) for v in summary.values() if isinstance(v, dict))
        return outcome.finish(res, has_data)

    # ---- urlDNA --------------------------------------------------------------------------------
    def _urldna(self, ctx: Any, res: ModuleResult, kind: str, value: str, now: _dt.datetime, outcome: _Outcome,
                records: list[dict[str, Any]], summary: dict[str, Any], raw: dict[str, Any]) -> None:
        sid = SRC_URLDNA
        if not ctx.has_key("urldna"):
            outcome.fail(res, sid, Status.NEEDS_KEY, "needs_key", "urlDNA: key 'urldna' not configured (V3LUM_URLDNA_KEY)")
            return
        body = urldna_search_body(kind, value)
        if body is None:
            outcome.fail(res, sid, Status.SKIPPED, "not_applicable", "urlDNA: value too long for a CQL query (200 characters)")
            return
        headers = {"Authorization": f"Bearer {ctx.key('urldna')}"}
        try:
            method, url = build_request("POST", URLDNA_SEARCH)
            resp = ctx.http.request(method, url, json_body=body, headers=headers, ttl=SEARCH_TTL, source=sid)
            if resp.status == 422 and urldna_missing_auth(resp.text):
                outcome.fail(res, sid, Status.NEEDS_KEY, "needs_key", "urlDNA: authorization header field required (422)")
                return
            ctx.http.check(resp)
            parsed = parse_urldna_search(resp.text, now)
        except (AuthRequired, RateLimited, QuotaExceeded, Blocked, HttpError, NetworkError) as exc:
            st, code, why = _fail_from_exception(exc)
            outcome.fail(res, sid, st, code, f"urlDNA search: {why}")
            return
        if parsed["reason"]:
            outcome.fail(res, sid, Status.ERROR, "error", f"urlDNA search: {parsed['reason']}: could not verify")
            return
        outcome.answered.append(sid)
        scans = parsed["scans"]
        # c4: each adapter has its own status - an answering source is reported too, so coverage counts it
        res.source_status(sid, Status.OK if scans else Status.EMPTY)
        summary["urldna"] = {"total": len(scans), "returned": len(scans), "hidden_matches": 0, "partial": False,
                             "checked_at": now.isoformat().replace("+00:00", "Z")}
        raw["urldna_search"] = [{k: v for k, v in s.items() if k in ("scan_id", "status", "scan_date", "private_scan", "error_code")} for s in scans[:MAX_RECORDS]]
        details: dict[str, dict[str, Any]] = {}
        done = [s for s in scans if s.get("status") == "DONE"][:URLDNA_DETAIL_SCANS]
        for scan in done:
            try:
                method, url = build_request("GET", URLDNA_SCAN.format(scan_id=scan["scan_id"]))
                resp = ctx.http.request(method, url, headers=headers, ttl=RESULT_TTL, source=sid)
                if resp.status == 404:
                    continue  # the scan expired between search and read
                ctx.http.check(resp)
                detail = parse_urldna_scan_result(resp.text, now)
            except (AuthRequired, RateLimited, QuotaExceeded, Blocked, HttpError, NetworkError) as exc:
                _st, _code, why = _fail_from_exception(exc)
                summary["urldna"]["partial"] = True
                summary["urldna"]["detail_error"] = f"verdict of scan {scan['scan_id']} not read: {why}"
                break
            if detail.get("reason"):
                summary["urldna"]["partial"] = True
                summary["urldna"]["detail_error"] = f"verdict of scan {scan['scan_id']}: {detail['reason']}"
                continue
            details[scan["scan_id"]] = detail
        for scan in scans[:MAX_RECORDS]:
            detail = details.get(scan["scan_id"])
            rec: dict[str, Any] = {
                "source": sid,
                "scan_id": scan["scan_id"],
                "status": scan.get("status"),
                "verdict": detail.get("verdict") if detail else None,
                "scan_date": scan.get("scan_date"),
                "age_days": scan.get("age_days"),
                "historical": scan.get("historical"),
                "report_url": f"https://urldna.io/scan/{scan['scan_id']}",
                "final_url": (detail or {}).get("final_url") or scan.get("target_url") or scan.get("submitted_url"),
                "private_scan": scan.get("private_scan"),
            }
            if detail:
                for key in ("title", "ip", "asn", "country_code", "technologies", "redirect_count"):
                    rec[key] = detail.get(key)
            records.append({k: v for k, v in rec.items() if v not in (None, "", [])} | {"historical": bool(rec["historical"])})

    # ---- urlquery ------------------------------------------------------------------------------
    def _urlquery(self, ctx: Any, res: ModuleResult, kind: str, value: str, now: _dt.datetime, outcome: _Outcome,
                  records: list[dict[str, Any]], summary: dict[str, Any], raw: dict[str, Any]) -> None:
        sid = SRC_URLQUERY
        if not ctx.has_key("urlquery"):
            outcome.fail(res, sid, Status.NEEDS_KEY, "needs_key", "urlquery: key 'urlquery' not configured (V3LUM_URLQUERY_KEY)")
            return
        params = urlquery_search_params(kind, value, now)
        if params is None:
            outcome.fail(res, sid, Status.SKIPPED, "not_applicable", "urlquery: value cannot be expressed as a search")
            return
        try:
            method, url = build_request("GET", URLQUERY_SEARCH)
            resp = ctx.http.request(method, url, params=params, headers={"x-apikey": ctx.key("urlquery")}, ttl=SEARCH_TTL, source=sid)
            code = urlquery_error_code(resp.text) if resp.status >= 400 else ""
            if resp.status == 401 or (resp.status == 403 and code == "INVALID_API_KEY"):
                outcome.fail(res, sid, Status.NEEDS_KEY, "needs_key", f"urlquery: key refused ({code or 'HTTP 401'})")
                return
            if resp.status == 403:
                outcome.fail(res, sid, Status.ERROR, "error", f"urlquery: forbidden for this key/plan ({code or 'HTTP 403'}): could not verify")
                return
            if resp.status == 503 and code == "RATE_LIMIT_UNAVAILABLE":
                outcome.fail(res, sid, Status.RATE_LIMITED, "rate_limited", "urlquery: quota enforcement unavailable (503): could not verify")
                return
            ctx.http.check(resp)
            parsed = parse_urlquery_search(resp.text, now)
        except (AuthRequired, RateLimited, QuotaExceeded, Blocked, HttpError, NetworkError) as exc:
            st, code2, why = _fail_from_exception(exc)
            outcome.fail(res, sid, st, code2, f"urlquery search: {why}")
            return
        if parsed["reason"]:
            outcome.fail(res, sid, Status.ERROR, "error", f"urlquery search: {parsed['reason']}: could not verify")
            return
        outcome.answered.append(sid)
        items = parsed["items"]
        res.source_status(sid, Status.OK if (items or parsed["hidden_matches"]) else Status.EMPTY,
                          reason=f"{parsed['hidden_matches']} match(es) not visible to this key (not 'not found')" if parsed["hidden_matches"] else "")
        summary["urlquery"] = {"total": parsed["total_hits"], "returned": len(items), "hidden_matches": parsed["hidden_matches"],
                               "partial": parsed["total_hits"] > len(items), "checked_at": now.isoformat().replace("+00:00", "Z")}
        raw["urlquery_search"] = [{k: v for k, v in i.items() if k in ("report_id", "status", "scan_date", "verdict_summary", "alert_counts")}
                                  for i in items[:MAX_RECORDS]]
        for item in items[:MAX_RECORDS]:
            records.append({k: v for k, v in item.items() if v not in (None, "", [])} | {"historical": bool(item.get("historical"))})

    # ---- findings ------------------------------------------------------------------------------
    @staticmethod
    def _findings(res: ModuleResult, records: list[dict[str, Any]], votes: dict[str, Any]) -> None:
        for vote in votes.get("votes", []):
            label = "urlDNA" if vote["source"] == SRC_URLDNA else "urlquery"
            if vote["vote"] == "malicious":
                sev, tags = "medium", ["third_party_verdict", "malicious"]
            elif vote["vote"] == "suspicious":
                sev, tags = "low", ["third_party_verdict", "suspicious"]
            else:
                continue
            res.finding(
                f"{label}: existing scan verdict '{vote['vote']}'",
                sev,
                f"An existing {label} capture from {vote.get('scan_date') or 'an unknown date'} was rated '{vote['vote']}'. "
                "Third-party opinion of another user's capture: one vote, never ground truth.",
                confidence="possible",
                criterion=f"{label} verdict '{vote['vote']}' on a capture of at most {HISTORICAL_DAYS} days (one vote per source, P078 cond 6)",
                tags=tags,
                source=vote["source"],
                observed_last=vote.get("scan_date"),
                key=vote["source"],
            )
        historical = [r for r in records if r.get("historical") and (r.get("verdict") == "malicious" or r.get("verdict_summary") == "malicious")]
        if historical:
            newest = max((r.get("scan_date") or "" for r in historical), default="")
            res.finding(
                "Historical third-party 'malicious' verdicts (older than 30 days)",
                "info",
                f"{len(historical)} older capture(s) rated malicious (newest {newest or 'unknown'}): context only, not the current state.",
                confidence="possible",
                tags=["third_party_verdict", "historical", "context_only"],
                key="historical",
            )


# =============================================================================================
# module 2: CIRCL Lookyloo captures (terms unknown until legal records them)
# =============================================================================================


@register
class UrlScannersLookyloo(Module):
    name = "url_scanners_lookyloo"
    title = "CIRCL Lookyloo: existing captures"
    description = ("Existing captures of a URL or host on CIRCL's public Lookyloo instance (cached captures only) with their "
                   "dates, titles and redirect chains. Lookups only: /submit is never built and nothing is re-captured.")
    category = "url_web"
    accepts = frozenset({T.URL, T.DOMAIN})
    produces = frozenset({T.URL, T.DOMAIN})
    tags = frozenset({"cached_only"})
    reference = "https://lookyloo.circl.lu/doc/"
    notice = ("Runs only once legal records CIRCL's terms for the public Lookyloo instance (registry source circl.lookyloo "
              "is 'unknown' until then, P078 cond 5). Captures are other users' recordings, older than 30 days = historical; "
              "Lookyloo gives no verdict.")
    run_on = "seeds"
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    hosts = ("lookyloo.circl.lu",)
    max_requests = 1 + LOOKYLOO_DETAIL_CAPTURES
    expected_latency = 2.0
    provider = "circl"
    sources = (SRC_LOOKYLOO,)
    access_model = "free_noauth_limited"
    cache_ttl = SEARCH_TTL
    min_interval = 2.0  # CERT-run instance, fair use
    daily_quota = 200
    timeout = 45.0
    max_pivots = 20
    default_enabled = False

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        q = query_value(entity)
        body = lookyloo_lookup_body(*q) if q else None
        if body is None:
            return res.mark("skipped", "value cannot be expressed as a Lookyloo lookup", reason_code="not_applicable")
        now = ctx.now()
        target = LOOKYLOO_URL_INFO if q[0] == "url" else LOOKYLOO_HOST_INFO
        method, url = build_request("POST", target)
        resp = ctx.http.request(method, url, json_body=body, ttl=SEARCH_TTL, source=SRC_LOOKYLOO)
        if resp.status in (400, 401) and isinstance(load_json_text(resp.text)[0], dict):
            # Lookyloo has no key: its 401 means 'field missing' ({'error': 'No URL provided.'}), never NEEDS_KEY
            err = _s(load_json_text(resp.text)[0].get("error")) or f"HTTP {resp.status}"
            return res.mark("error", f"Lookyloo refused the lookup ({err[:120]}): could not verify")
        ctx.http.check(resp)
        parsed = parse_lookyloo_occurrences(resp.text, now)
        if parsed["reason"]:
            return res.mark("error", f"{parsed['reason']}: could not verify")
        captures = parsed["captures"]
        res.raw = {"total": parsed["total"], "partial": parsed["partial"],
                   "captures": [{k: c.get(k) for k in ("capture_uuid", "scan_date")} for c in captures[:MAX_RECORDS]]}
        if not captures:
            if parsed["partial"]:
                return res.mark("error", "Lookyloo: captures exist but are not cached (never re-cached by V3LUM): could not verify")
            return res.mark("empty")
        subject = q[1] if q[0] == "domain" else _host(q[1])
        detail_error = ""
        for cap in captures[:LOOKYLOO_DETAIL_CAPTURES]:
            try:
                method, url = build_request("GET", LOOKYLOO_REDIRECTS.format(uuid=cap["capture_uuid"]))
                r2 = ctx.http.request(method, url, ttl=RESULT_TTL, source=SRC_LOOKYLOO)
                if r2.status == 400 and "missing in cache" in r2.text.lower():
                    continue
                ctx.http.check(r2)
            except (RateLimited, QuotaExceeded, Blocked, HttpError, NetworkError) as exc:
                # the captures already listed are kept; the redirect details stay unread (could not verify)
                detail_error = f"redirects of capture {cap['capture_uuid']} not read: {_fail_from_exception(exc)[2]}"
                break
            red = parse_lookyloo_redirects(r2.text)
            if red.get("reason"):
                continue
            cap["capture_url"] = red.get("url")
            cap["final_url"] = red.get("final_url")
            cap["redirect_count"] = max(0, len(red.get("redirects") or []) - 1)
            cap["subject_role"] = capture_subject_role(red, subject)
        out = []
        for cap in captures[:MAX_RECORDS]:
            # pivots only from captures OF the looked-up value: a capture of another site that merely loads
            # or links the host is context, never a lead (its final URL is that other site)
            of_subject = cap.get("subject_role") in ("captured", "redirect")
            rec = _record_scan(res, cap, relation_prefix="scanner", pivots=of_subject) if cap.get("final_url") else dict(cap)
            rec.setdefault("subject_role", "unknown")
            if cap.get("title"):
                rec["title"] = str(cap["title"])[:200]
            out.append({k: v for k, v in rec.items() if v not in (None, "")})
            if len(out) <= 5:
                res.link(f"Lookyloo capture {rec.get('scan_date') or rec['capture_uuid']}", rec["tree_url"])
        res.attr("lookyloo_captures", out)
        summary = {"total": parsed["total"], "returned": len(captures), "hidden_matches": 0,
                   "partial": parsed["partial"] or bool(detail_error), "checked_at": now.isoformat().replace("+00:00", "Z")}
        if detail_error:
            summary["detail_error"] = detail_error
        res.attr("third_party_scan_summary", {"lookyloo": summary})
        return res
