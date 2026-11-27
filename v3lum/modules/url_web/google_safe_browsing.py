"""google_safe_browsing: Google Web Risk (corporate) and Safe Browsing v4 (research) URL checks (P067,
batch p2-G03-1).

Final conditions implemented (P067):

* c1 - Google Web Risk ``uris.search`` (class ``license``, A1 BR15) is the corporate path, off under the
  corporate profile until licence-cleared (a licence_allow entry for ``google_webrisk.uris_search`` with
  the company billing account) and key ``webrisk`` (provider fragment, env ``V3LUM_WEBRISK_KEY``). The key
  is the ``key`` URL parameter, masked by the central redactor (AR01) in every log, cache row and report.
* c2 - Safe Browsing v4 ``threatMatches:find`` (``noncommercial``; v4 deprecated) runs only when the policy
  gate passes it (licence_allow or the research profile): this aggregator queries only
  ``ctx.allowed_sources`` and prefers Web Risk when both are allowed (one request, one vote).
* c3 - the Transparency Report status endpoint is not automated: the public Site Status page is the
  manual link (pack ``url_reporting_g03``, ``Module.manual_link``).
* c4 - before the lookup, recipient identifiers and token-like query values are removed (A7 BR15:
  :func:`minimise_lookup_url` plus the policy ``recipient_token`` check); when they match, the URL sent is
  reduced to ``scheme://host/path`` (a sensitive path segment cuts the path); userinfo and fragments are
  never sent. The hash-prefix Update API is deferred to the backlog.
* c5 - a hit names the threat type and check time ('Google Web Risk: SOCIAL_ENGINEERING at 03:12 UTC'); a
  miss reads "not on Google's lists at <time>", never 'safe'. Both APIs share the upstream family
  ``google_safe_browsing``: one vote in consensus.
* c6 - no usable key: one coverage line ('needs Web Risk key', NEEDS_KEY). Keyless or unregistered calls
  (403 PERMISSION_DENIED) and invalid keys (400 'API key not valid') map to NEEDS_KEY; an empty ``{}``
  answer is a miss; 429 is RATE_LIMITED (QUOTA for a daily limit); 5xx/HTML/malformed = could not verify.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.url_web.phishstats import HEX_RUN_RE, classify_sensitive_value

SOURCE_WEBRISK = "google_webrisk.uris_search"
SOURCE_GSB = "google_safebrowsing.v4_lookup"
KEY_WEBRISK = "webrisk"
KEY_GSB = "google_safebrowsing"
WEBRISK_SEARCH_URL = "https://webrisk.googleapis.com/v1/uris:search"
GSB_V4_FIND_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
GOOGLE_THREAT_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE")
GOOGLE_FAMILY = "google_safe_browsing"  # c5: Web Risk and Safe Browsing are one upstream family (P171)
MISS_TTL = 1800
THREAT_SEVERITY = {"SOCIAL_ENGINEERING": "high", "MALWARE": "high", "UNWANTED_SOFTWARE": "medium", "POTENTIALLY_HARMFUL_APPLICATION": "medium",
                   "SOCIAL_ENGINEERING_EXTENDED_COVERAGE": "medium"}
THREAT_TAGS = {"SOCIAL_ENGINEERING": ["phishing", "malicious"], "SOCIAL_ENGINEERING_EXTENDED_COVERAGE": ["phishing", "suspicious"],
               "MALWARE": ["malware", "malicious"], "UNWANTED_SOFTWARE": ["suspicious"], "POTENTIALLY_HARMFUL_APPLICATION": ["suspicious"]}
API_LABEL = {SOURCE_WEBRISK: "Google Web Risk", SOURCE_GSB: "Google Safe Browsing"}


def parse_iso(value: Any) -> datetime | None:
    """RFC 3339 with nanoseconds ('2026-11-26T03:42:10.123456789Z') or offsets -> aware datetime."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str):
        return None
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2})(?:[T ](\d{2}:\d{2}(?::\d{2})?)(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?", value.strip())
    if not m:
        return None
    date, clock, frac, tz = m.groups()
    clock = clock or "00:00:00"
    clock += ":00" if len(clock) == 5 else ""
    try:
        dt = datetime.strptime(f"{date}T{clock}", "%Y-%m-%dT%H:%M:%S").replace(microsecond=int((frac or ".0")[1:7].ljust(6, "0")))
    except ValueError:
        return None
    if tz in (None, "Z"):
        return dt.replace(tzinfo=timezone.utc)
    sign = 1 if tz[0] == "+" else -1
    return dt.replace(tzinfo=timezone(sign * timedelta(hours=int(tz[1:3]), minutes=int(tz[-2:]))))


def _hhmm(checked_at: Any) -> str:
    dt = parse_iso(checked_at)
    return dt.astimezone(timezone.utc).strftime("%H:%M UTC") if dt else "an unknown time"


def minimise_lookup_url(url: Any, extra_terms: Any = ()) -> dict[str, Any]:
    """c4: before uris.search remove recipient identifiers and token-like query values (A7 BR15): when any
    match the URL is reduced to scheme://host/path; a sensitive path segment cuts the path before it.
    Userinfo and the fragment are never sent. Returns ``{"url", "reduced", "reasons"}``."""
    if not isinstance(url, str) or not url.strip():
        return {"url": None, "reduced": False, "reasons": ["no url"]}
    try:
        parts = urllib.parse.urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return {"url": None, "reduced": False, "reasons": ["unparsable url"]}
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return {"url": None, "reduced": False, "reasons": ["not an http(s) url"]}
    reasons: list[str] = []
    netloc = parts.hostname + (f":{port}" if port else "")
    if parts.username or parts.password:
        reasons.append("userinfo removed")
    path_segs = parts.path.split("/")
    kept: list[str] = []
    for seg in path_segs:
        kind = classify_sensitive_value(seg, extra_terms) if seg else None
        if kind:
            reasons.append(f"path segment with {kind}: path cut")
            break
        kept.append(seg)
    path_cut = len(kept) < len(path_segs)
    path = "/".join(kept) or "/"
    if path_cut and not path.endswith("/"):
        path += "/"
    hits: list[str] = []
    for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        kind = classify_sensitive_value(v, extra_terms) or ("token" if HEX_RUN_RE.search(k) else None) or classify_sensitive_value(k, extra_terms)
        if kind:
            hits.append(kind)
    frag_kind = classify_sensitive_value(urllib.parse.unquote(parts.fragment), extra_terms) if parts.fragment else None
    if hits or frag_kind:
        reasons.append(f"query/fragment with {', '.join(sorted(set(hits + ([frag_kind] if frag_kind else []))))}: reduced to scheme://host/path")
        query = ""
    elif path_cut and parts.query:
        reasons.append("query dropped with the cut path: reduced to scheme://host/path")
        query = ""
    else:
        query = parts.query
    if parts.fragment:
        reasons.append("fragment dropped")
    new = urllib.parse.urlunsplit((parts.scheme.lower(), netloc.lower(), path, query, ""))
    reduced = any(r.endswith("scheme://host/path") or "path cut" in r or r == "userinfo removed" for r in reasons)
    return {"url": new, "reduced": reduced, "reasons": reasons}


def lookup_url_for(entity: Entity, org: Any = None) -> dict[str, Any]:
    """The URL actually sent to Google for a URL or domain entity (c4), with the policy recipient-token
    check as a second net: a URL it flags is cut to scheme://host/."""
    if entity.type is T.DOMAIN:
        return {"url": f"http://{entity.value.strip('.').lower()}/", "reduced": False, "reasons": []}
    out = minimise_lookup_url(entity.value)
    if out["url"] and not out["reduced"]:
        try:
            from v3lum.core.policy import recipient_token

            flagged = recipient_token(out["url"], org)
        except Exception:  # noqa: BLE001 - the local heuristics already ran
            flagged = False
        if flagged:
            parts = urllib.parse.urlsplit(out["url"])
            out = {"url": urllib.parse.urlunsplit((parts.scheme, parts.netloc, "/", "", "")), "reduced": True,
                   "reasons": out["reasons"] + ["recipient token (A7 BR15): reduced to scheme://host/"]}
    return out


def webrisk_query_params(uri: str, key: str, threat_types: tuple[str, ...] = GOOGLE_THREAT_TYPES) -> list[tuple[str, str]]:
    """c1: uris.search parameters (repeated threatTypes, uri, key). The key travels as the 'key' URL parameter,
    which the core redactor masks everywhere (AR01)."""
    return [("threatTypes", t) for t in threat_types] + [("uri", uri), ("key", key)]


def gsb_v4_request_body(urls: list[str], client_id: str = "v3lum", client_version: str = "2") -> dict[str, Any]:
    """c2: threatMatches:find JSON body (<= 500 URLs)."""
    entries = [{"url": u} for u in (urls or [])[:500] if isinstance(u, str) and u]
    return {"client": {"clientId": client_id, "clientVersion": client_version},
            "threatInfo": {"threatTypes": list(GOOGLE_THREAT_TYPES), "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": entries}}


def _load_json(raw: Any) -> tuple[Any, str | None]:
    if isinstance(raw, (dict, list)):
        return raw, None
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw or "")
    if not text.strip():
        return None, "empty body"
    head = text[:600].lstrip().lower()
    if head.startswith(("<!doctype html", "<html", "<head", "<body")):
        return None, "html instead of json"
    try:
        return json.loads(text), None
    except ValueError as exc:
        return None, f"invalid json: {str(exc)[:80]}"


def google_api_error(status: int, body: Any) -> dict[str, Any] | None:
    """c6: Google API errors -> {status, reason_code, reason}; None when the answer is not an error.
    Keyless/unregistered (403 PERMISSION_DENIED) and invalid keys (400 'API key not valid') -> needs_key;
    API or billing not enabled for the key's project -> needs_key; 429 RESOURCE_EXHAUSTED -> rate_limited
    (per minute) or quota (per day); 5xx / HTML / malformed -> error ('could not verify')."""
    obj, err = _load_json(body)
    code = int(status or 0)
    if obj is None and code == 200:
        return {"status": "error", "reason_code": "error", "reason": f"malformed Google answer ({err}): could not verify"}
    e = obj.get("error") if isinstance(obj, dict) and isinstance(obj.get("error"), dict) else None
    if e is None and code < 400:
        return None
    e = e or {}
    msg = str(e.get("message") or err or "")
    gstatus = str(e.get("status") or "")
    reasons = {d.get("reason") for d in (e.get("details") or []) if isinstance(d, dict)}
    try:
        code = int(e.get("code") or code)
    except (TypeError, ValueError):
        pass
    low = msg.lower()
    if "API_KEY_INVALID" in reasons or "api key not valid" in low or "api key expired" in low:
        return {"status": "needs_key", "reason_code": "needs_key", "reason": "Google API key not valid"}
    if reasons & {"SERVICE_DISABLED", "BILLING_DISABLED", "API_KEY_SERVICE_BLOCKED"} or "has not been used" in low:
        return {"status": "needs_key", "reason_code": "needs_key", "reason": "API not enabled (or billing disabled) for the key's Google Cloud project"}
    if code == 403 or gstatus == "PERMISSION_DENIED":
        return {"status": "needs_key", "reason_code": "needs_key", "reason": "unregistered or keyless call refused (403 PERMISSION_DENIED): needs a valid key"}
    if code == 429 or gstatus == "RESOURCE_EXHAUSTED":
        daily = "per day" in low or "daily" in low
        return {"status": "quota" if daily else "rate_limited", "reason_code": "quota" if daily else "rate_limited",
                "reason": "Google API daily quota exhausted" if daily else "Google API rate limit (per minute)"}
    if code == 400:
        return {"status": "error", "reason_code": "error", "reason": f"Google API bad request: {msg[:120]}"}
    return {"status": "error", "reason_code": "error", "reason": f"Google API HTTP {code or '?'} {gstatus or err or ''}: could not verify".strip()}


def parse_webrisk_search(status: int, body: Any, checked_at: Any = None) -> dict[str, Any]:
    """c5/c6: uris.search -> {"status": hit|miss|<error>, "threat_types", "expire_time", "text"}; {} is a miss."""
    err = google_api_error(status, body)
    if err:
        return dict(err, threat_types=[], expire_time=None, text=None)
    obj, _ = _load_json(body)
    if not isinstance(obj, dict):
        return {"status": "error", "reason_code": "error", "reason": "unexpected Web Risk answer shape: could not verify", "threat_types": [],
                "expire_time": None, "text": None}
    threat = obj.get("threat") if isinstance(obj.get("threat"), dict) else None
    if not threat:
        return {"status": "miss", "reason_code": None, "reason": None, "threat_types": [], "expire_time": None,
                "text": f"not on Google's lists at {_hhmm(checked_at)}"}
    types = [t for t in (threat.get("threatTypes") or []) if isinstance(t, str)][:10]
    return {"status": "hit", "reason_code": None, "reason": None, "threat_types": types, "expire_time": threat.get("expireTime"),
            "text": f"Google Web Risk: {', '.join(types) or 'THREAT'} at {_hhmm(checked_at)}"}


def parse_gsb_v4_find(status: int, body: Any, checked_at: Any = None) -> dict[str, Any]:
    """c2/c5/c6: threatMatches:find -> the same shape as :func:`parse_webrisk_search` plus 'matches'."""
    err = google_api_error(status, body)
    if err:
        return dict(err, threat_types=[], matches=[], text=None, expire_time=None)
    obj, _ = _load_json(body)
    if not isinstance(obj, dict):
        return {"status": "error", "reason_code": "error", "reason": "unexpected Safe Browsing answer shape: could not verify", "threat_types": [],
                "matches": [], "text": None, "expire_time": None}
    matches = []
    for mt in (obj.get("matches") or [])[:50] if isinstance(obj.get("matches"), list) else []:
        if isinstance(mt, dict):
            threat = mt.get("threat") if isinstance(mt.get("threat"), dict) else {}
            matches.append({"threat_type": mt.get("threatType"), "platform": mt.get("platformType"), "url": threat.get("url"),
                            "cache_duration": mt.get("cacheDuration")})
    if not matches:
        return {"status": "miss", "reason_code": None, "reason": None, "threat_types": [], "matches": [], "expire_time": None,
                "text": f"not on Google's lists at {_hhmm(checked_at)}"}
    types = sorted({str(m["threat_type"]) for m in matches if m["threat_type"]})
    return {"status": "hit", "reason_code": None, "reason": None, "threat_types": types, "matches": matches, "expire_time": None,
            "text": f"Google Safe Browsing: {', '.join(types)} at {_hhmm(checked_at)}"}


def google_coverage_line(profile: str, has_webrisk_key: bool, webrisk_licence_allowed: bool) -> str | None:
    """c1/c6: the single coverage line when Web Risk cannot run (None when it can)."""
    if profile == "corporate" and not webrisk_licence_allowed:
        return "Google Web Risk skipped: licence (needs a licence_allow entry for the company billing account)"
    if not has_webrisk_key:
        return "needs Web Risk key"
    return None


@register
class GoogleSafeBrowsing(Module):
    name = "google_safe_browsing"
    title = "Google Web Risk / Safe Browsing"
    description = (
        "Checks a URL or domain against Google's Safe Browsing lists through Web Risk uris.search (licensed corporate path) or "
        "Safe Browsing v4 (non-commercial, research only); the URL is minimised first and a miss is never 'safe'."
    )
    category = "url_web"
    accepts = {T.URL, T.DOMAIN}
    produces = frozenset()
    tags = {"reputation"}
    reference = "https://cloud.google.com/web-risk/docs/lookup-api"
    notice = (
        "Web Risk is licensed (company billing account in licence_allow); Safe Browsing v4 is non-commercial (research profile only). "
        "The Transparency Report status endpoint is never automated: use the Site Status manual link."
    )
    terms = "noncommercial"  # most restrictive of license (Web Risk) and noncommercial (Safe Browsing v4)
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "google_webrisk"
    sources = (SOURCE_WEBRISK, SOURCE_GSB)
    hosts = ("webrisk.googleapis.com", "safebrowsing.googleapis.com")
    access_model = "free_auth_limited"
    optional_keys = (KEY_WEBRISK, KEY_GSB)
    max_requests = 1  # one API per run (same lists, one vote)
    expected_latency = 0.5
    timeout = 20.0
    min_interval = 0.5
    cache_ttl = MISS_TTL
    manual_link = "url_reporting_g03:safe_browsing_status"
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.URL:
            return minimise_lookup_url(entity.value)["url"] is not None
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        allowed = ctx.allowed_sources
        candidates = [(s, k) for s, k in ((SOURCE_WEBRISK, KEY_WEBRISK), (SOURCE_GSB, KEY_GSB)) if allowed is None or s in allowed]
        if not candidates:
            return res.mark(Status.SKIPPED, "no Google list source allowed by the licence profile (Web Risk needs a licence_allow entry)", reason_code="licence")
        chosen: tuple[str, str] | None = None
        for source, key_name in candidates:
            if ctx.key(key_name):
                chosen = (source, key_name)
                break
            res.source_status(source, Status.NEEDS_KEY, reason_code="needs_key",
                              reason="needs Web Risk key" if source == SOURCE_WEBRISK else "needs a Safe Browsing key (research profile only)")
        if chosen is None:
            return res.mark(Status.NEEDS_KEY, "needs Web Risk key", reason_code="needs_key")
        source, key_name = chosen
        try:
            org = ctx.org
        except Exception:  # noqa: BLE001
            org = None
        lookup = lookup_url_for(entity, org)
        if not lookup["url"]:  # pragma: no cover - applies() filters these
            return res.mark(Status.SKIPPED, "not an http(s) URL", reason_code="not_applicable")
        checked_at = ctx.now()
        if source == SOURCE_WEBRISK:
            resp = ctx.http.get(WEBRISK_SEARCH_URL, params=webrisk_query_params(lookup["url"], ctx.key(key_name)), source=source, ttl=MISS_TTL)
        else:
            resp = ctx.http.post(GSB_V4_FIND_URL, params={"key": ctx.key(key_name)}, json_body=gsb_v4_request_body([lookup["url"]]), source=source)
        _, err = _load_json(resp.content)
        if err == "html instead of json" or (resp.status >= 400 and resp.status not in (400, 403, 429) and resp.status < 500):
            ctx.http.check(resp)  # challenge pages and odd statuses: Blocked / AuthRequired / HttpError (rule 5)
        parser = parse_webrisk_search if source == SOURCE_WEBRISK else parse_gsb_v4_find
        out = parser(resp.status, resp.content, checked_at=checked_at)
        res.raw = {"api": source, "status": resp.status, "lookup_reduced": lookup["reduced"], "result": {k: out.get(k) for k in ("status", "threat_types", "expire_time", "text", "reason")}}
        if lookup["reduced"]:
            res.attr("lookup_minimisation", {"reduced": True, "reasons": lookup["reasons"]})
        if out["status"] not in ("hit", "miss"):
            status = Status(out["status"])
            code = out["reason_code"] or "error"
            if status is Status.ERROR and resp.status >= 500:
                code = "error"
            res.source_status(source, status, reason_code=code, reason=f"{API_LABEL[source]}: {out['reason']}")
            ctx.http.evict(resp)
            return res.mark(status, f"{API_LABEL[source]}: {out['reason']}", reason_code=code)
        when = checked_at.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        verdict = {"api": "web_risk" if source == SOURCE_WEBRISK else "safe_browsing_v4", "status": out["status"], "threat_types": out["threat_types"],
                   "checked_at": when, "expire_time": out.get("expire_time"), "text": out["text"], "url_sent_reduced": lookup["reduced"],
                   "reasons": lookup["reasons"], "family": GOOGLE_FAMILY}
        res.attr("google_safe_browsing", verdict)
        if out["status"] == "hit":
            types = out["threat_types"] or ["THREAT"]
            order = ["high", "medium", "low", "info"]
            severity = min((THREAT_SEVERITY.get(t, "medium") for t in types), key=order.index)
            tags = sorted({tag for t in types for tag in THREAT_TAGS.get(t, ["suspicious"])})
            res.finding(
                "Listed on Google's Safe Browsing lists",
                severity,
                f"{out['text']} (URL checked: {lookup['url']}{', minimised' if lookup['reduced'] else ''}).",
                confidence="probable",
                criterion=f"{API_LABEL[source]} threat match {', '.join(types)} for the checked URL (one vote in consensus, family {GOOGLE_FAMILY})",
                tags=tags,
                data={"threat_types": types, "api": verdict["api"], "checked_at": when, "expire_time": out.get("expire_time")},
                source=source,
                observed_last=when,
            )
        return res
