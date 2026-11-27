"""phishstats: PhishStats phishing URL search (P074, batch p2-G03-1) + the batch's URL-redaction helpers.

Final conditions implemented (P074):

* c1 - ``api.phishstats.info`` only (the ``phishstats.info:2096`` host is unusable behind HTTPS-only
  proxies). ``_where`` filter values are validated and URL-encoded (:func:`phishstats_query`), never
  concatenated from raw input; exact ``host``/``ip`` filters first, ``url`` LIKE only for keywords and for
  hosts on shared platforms (the provider's ``host`` field is the registrable domain: ``workers.dev`` for
  every ``*.workers.dev`` URL). Brand monitoring uses the org profile: an own domain adds one LIKE query on
  its brand label, and keywords that are org brand terms are flagged ``brand_abuse``.
* c2 - search only: no submission endpoint exists in this file (rule 7).
* c3 - victims' e-mails (plain, URL-encoded, base64) and token-like query/fragment values in result URLs
  are redacted by :func:`redact_victim_url` (url_unwrap's shared ``redact_url_values`` plus CPF/phone/token
  handling and the core key redactor) before pivots, attributes, ``res.raw``, the cache, evidence and
  reports; the raw HTTP body is never cached (``cache_if``), only the redacted records (module state, 1 h).
* c4 - <= 20 req/min (provider ``min_interval`` 3 s, RateLimit headers recorded), the anonymous 50/day per
  egress IP is the provider quota block (P334, 80 % margin), cache 1 h, result cap 100; timeouts/5xx are
  'could not verify'. An invalid filter that the API silently ignores (HTTP 200 with unrelated records) is
  detected by re-checking every record: all-mismatch = ERROR.
* c5 - a score below the phishing threshold is 'suspicious' at most; the verdict stays at URL level
  (P071): the exact URL or a non-shared FQDN carries it, never a shared platform, a registrable parent or
  an IP (IPs get context only).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re
import urllib.parse
from typing import Any

from v3lum.core import psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.core.redact import redact_url as core_redact_url
from v3lum.modules.url_web.url_unwrap import redact_url_values

SOURCE = "phishstats.api"
PHISHSTATS_API = "https://api.phishstats.info/api/phishing"
PHISHSTATS_MAX_RESULTS = 100  # c4
#: c5: PhishStats does not publish its phishing threshold any more (the old CSV legend read 4-6 'phishing');
#: the provider's own API example filters (score,gt,5): 5.0 until the CTI lead records the value.
PHISHSTATS_PHISHING_THRESHOLD = 5.0
CACHE_SECONDS = 3600  # c4: 1 h, redacted records only
CACHE_ENTRIES = 8
PIVOT_CAP = 25
EXPAND_CAP = 10
_KEYWORD_RE = re.compile(r"[a-z0-9][a-z0-9.\-]{1,251}[a-z0-9]\Z")
_HOST_RE = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}[a-z0-9]\Z")
#: shared-platform suffixes seen in phishing feeds that the PSL lists as private (the PSL heuristic below
#: covers most; these are explicit for clarity)
SHARED_SUFFIXES = frozenset({
    "workers.dev", "pages.dev", "r2.dev", "github.io", "gitlab.io", "netlify.app", "vercel.app", "web.app", "firebaseapp.com",
    "glitch.me", "herokuapp.com", "azurewebsites.net", "blogspot.com", "wixsite.com", "weebly.com", "ngrok-free.app", "ngrok.io",
    "onrender.com", "webflow.io", "square.site", "godaddysites.com", "000webhostapp.com", "duckdns.org", "ddns.net", "ipv64.net",
    "home64.de", "appspot.com", "translate.goog", "sites.google.com", "docs.google.com", "forms.gle", "ipfs.io", "dweb.link",
    "replit.app", "repl.co", "surge.sh", "framer.app", "carrd.co", "notion.site",
})

# ============================================================================================ URL redaction
# Shared by P074 c3 (victim e-mails/tokens in PhishStats URLs), P067 c4 (minimisation before uris.search,
# A7 BR15 heuristics) and P345 c6 (takedown packet minimisation).
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}")
CPF_RE = re.compile(r"(?<!\d)\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?!\d)")
PHONE_RE = re.compile(r"^\+?\d{10,14}$")
TOKEN_CHARS_RE = re.compile(r"^[A-Za-z0-9_\-.~+/=%]+$")
HEX_RUN_RE = re.compile(r"[0-9a-fA-F]{16,}")
REDACTED = {"email": "REDACTED_EMAIL", "token": "REDACTED_TOKEN", "cpf": "REDACTED_ID", "phone": "REDACTED_PHONE", "term": "REDACTED"}


def _b64_decodes_to_email(value: str) -> bool:
    v = value.strip()
    if len(v) < 8 or len(v) > 4096 or not re.fullmatch(r"[A-Za-z0-9+/_\-]+={0,2}", v):
        return False
    padded = v + "=" * (-len(v) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            dec = decoder(padded).decode("utf-8", "strict")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if EMAIL_RE.search(dec):
            return True
    return False


def is_token_like(value: Any, min_len: int = 16) -> bool:
    """A7 BR15: an opaque token of >= 16 chars (letters and digits mixed, long hex, base64-looking)."""
    if not isinstance(value, str):
        return False
    v = value.strip()
    if len(v) < min_len or not TOKEN_CHARS_RE.match(v):
        return False
    if HEX_RUN_RE.fullmatch(v):
        return True
    if any(c.isdigit() for c in v) and any(c.isalpha() for c in v):
        return True
    return bool(re.fullmatch(r"[A-Za-z0-9+/_\-]{20,}={0,2}", v) and not re.fullmatch(r"[a-z\-]+", v))


def classify_sensitive_value(value: Any, extra_terms: Any = ()) -> str | None:
    """Kind of personal/secret data in one URL component ('email' | 'term' | 'cpf' | 'phone' | 'token'),
    checking the plain, URL-decoded and base64 forms (A7 BR15); None when nothing is found."""
    if not isinstance(value, str) or not value:
        return None
    candidates = [value]
    dec = urllib.parse.unquote_plus(value)
    if dec != value:
        candidates.append(dec)
    for c in candidates:
        if EMAIL_RE.search(c):
            return "email"
        low = c.lower()
        for term in extra_terms or ():
            if term and str(term).lower() in low:
                return "term"
        if CPF_RE.fullmatch(c.strip()):
            return "cpf"
        if PHONE_RE.match(c.strip()):
            return "phone"
    if _b64_decodes_to_email(value) or _b64_decodes_to_email(dec):
        return "email"
    if is_token_like(dec):
        return "token"
    return None


def redact_victim_url(url: Any, extra_terms: Any = ()) -> tuple[str, list[str]]:
    """c3: victims' e-mails (plain, %40, %2540, base64), CPFs, phones, per-recipient/click tokens, opaque
    token-like values and URL userinfo removed from a URL; key-like parameters masked by the core
    redactor. Returns ``(redacted_url, kinds)`` - the kinds of what was removed, never the values."""
    if not isinstance(url, str) or not url.strip():
        return "", []
    first, kinds = redact_url_values(url.strip(), True)  # url_unwrap's shared helper (P066/P346)
    first = str(first or "")
    found = set(kinds)
    try:
        parts = urllib.parse.urlsplit(first)
    except ValueError:
        return core_redact_url(EMAIL_RE.sub(REDACTED["email"], first)), sorted(found | {"unparsable"})
    netloc = parts.netloc.rsplit("@", 1)[-1]
    segs = []
    for seg in parts.path.split("/"):
        kind = classify_sensitive_value(seg, extra_terms) if seg and not seg.startswith("REDACTED") else None
        if kind:
            found.add(kind)
        segs.append(REDACTED[kind] if kind else seg)
    pairs = []
    for raw_pair in (parts.query or "").split("&"):
        if not raw_pair:
            continue
        k, sep, v = raw_pair.partition("=")
        new_k = k
        if HEX_RUN_RE.search(urllib.parse.unquote_plus(k)) or classify_sensitive_value(k, extra_terms) in ("email", "cpf", "term"):
            new_k = EMAIL_RE.sub(REDACTED["email"], HEX_RUN_RE.sub(REDACTED["token"], urllib.parse.unquote_plus(k)))
            found.add("token_in_key")
        kind = classify_sensitive_value(v, extra_terms) if v and not v.startswith("REDACTED") else None
        if kind:
            found.add(kind)
            v = REDACTED[kind]
        pairs.append(new_k + (sep + v if sep else ""))
    frag = parts.fragment
    if frag:
        kind = classify_sensitive_value(frag, extra_terms)
        if not kind:
            kind = next((k for k in (classify_sensitive_value(x, extra_terms) for x in re.split(r"[&=/?;]", frag) if x) if k), None)
        if kind:
            found.add(kind)
            frag = REDACTED[kind]
    out = urllib.parse.urlunsplit((parts.scheme, netloc, "/".join(segs), "&".join(pairs), frag))
    return core_redact_url(out), sorted(found)


def defang_url(url: Any) -> str:
    """hxxps://evil[.]example/... rendering for copy-paste templates (AR13)."""
    if not isinstance(url, str):
        return ""
    u = re.sub(r"^http", "hxxp", url, flags=re.I)
    try:
        parts = urllib.parse.urlsplit(u)
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc.replace(".", "[.]"), parts.path, parts.query, parts.fragment))
    except ValueError:
        return u.replace(".", "[.]")


# ============================================================================================ PhishStats
def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip()) if value is not None and not isinstance(value, bool) else None
    except (TypeError, ValueError):
        return None


def _float(value: Any) -> float | None:
    try:
        return float(value) if value is not None and not isinstance(value, bool) else None
    except (TypeError, ValueError):
        return None


def _hostname(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip().rstrip(".").lower()
    if not v or len(v) > 253:
        return None
    try:
        v = v.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    return v if _HOST_RE.match(v) else None


def _under(host: str | None, suffix: str) -> bool:
    return bool(host) and (host == suffix or host.endswith("." + suffix))  # type: ignore[union-attr]


def is_shared_platform(host: Any) -> bool:
    """A host on a platform where third parties publish their own sites (PSL private suffixes such as
    workers.dev / github.io, plus :data:`SHARED_SUFFIXES`): PhishStats files them under the platform."""
    h = _hostname(host)
    if not h:
        return False
    if any(_under(h, s) for s in SHARED_SUFFIXES):
        return True
    suffix = psl.public_suffix(h)
    # a multi-label suffix whose second-level label is a word (not com/net/gov/co/ac...) is a private suffix
    return "." in suffix and len(suffix.split(".")[0]) > 3


def phishstats_query(kind: str, value: Any, size: int = PHISHSTATS_MAX_RESULTS) -> dict[str, Any]:
    """c1: the request URL with an encoded ``_where`` filter, never concatenated from raw input.
    kind 'host' (exact, the provider's registrable-domain field), 'ip' (exact) or 'url_like' (keyword, slow).
    Returns ``{"url", "where", "field", "op", "value"}`` or ``{"error": reason}``."""
    if not isinstance(value, str) or not value.strip():
        return {"error": "empty value"}
    v = value.strip()
    if any(ch in v for ch in "(),~ \t\r\n"):
        return {"error": "value contains filter syntax characters"}
    if kind == "host":
        h = _hostname(v)
        if not h:
            return {"error": "not a host name"}
        field, op, val = "host", "eq", h
    elif kind == "ip":
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            return {"error": "not an IP address"}
        field, op, val = "ip", "eq", ip.compressed
    elif kind == "url_like":
        kw = v.lower()
        if not _KEYWORD_RE.match(kw):
            return {"error": "keyword must be 3-253 characters of [a-z0-9.-]"}
        field, op, val = "url", "like", kw
    else:
        return {"error": "unsupported kind"}
    where = f"({field},{op},{'~' + val + '~' if op == 'like' else val})"
    n = max(1, min(_int(size) or PHISHSTATS_MAX_RESULTS, PHISHSTATS_MAX_RESULTS))
    qs = urllib.parse.urlencode([("_where", where), ("_sort", "-id"), ("_size", str(n))])
    return {"url": f"{PHISHSTATS_API}?{qs}", "where": where, "field": field, "op": op, "value": val}


def plan_for_entity(etype: T, value: str) -> dict[str, Any]:
    """c1: one query per entity, exact filters first. Returns ``{"query", "match": (field, value), "shared"}``."""
    if etype is T.IPV4:
        q = phishstats_query("ip", value)
        return {"query": q if "url" in q else None, "match": ("ip", q.get("value")), "shared": False}
    if etype in (T.URL, T.DOMAIN):
        try:
            host = urllib.parse.urlsplit(value).hostname if etype is T.URL else value
        except ValueError:
            host = None
        fqdn = _hostname(host or "")
        if not fqdn:
            return {"query": None, "match": None, "shared": False}
        shared = is_shared_platform(fqdn)
        reg = psl.registrable_domain(fqdn)
        q = phishstats_query("url_like", fqdn) if shared or not reg else phishstats_query("host", reg)
        return {"query": q if "url" in q else None, "match": ("url_host", fqdn), "shared": shared}
    if etype is T.KEYWORD:
        q = phishstats_query("url_like", value)
        return {"query": q if "url" in q else None, "match": ("url", str(value).strip().lower()), "shared": False}
    return {"query": None, "match": None, "shared": False}


def brand_label(domain: str) -> str | None:
    """c1 brand monitoring: the registrable label of an own domain ('examplebank' for examplebank.com.br)."""
    reg = psl.registrable_domain(domain) or ""
    label = reg.split(".")[0] if reg else ""
    return label if len(label) >= 4 and _KEYWORD_RE.match(label) else None


def _yes_no(v: Any) -> bool | None:
    if isinstance(v, str):
        low = v.strip().lower()
        if low == "yes":
            return True
        if low == "no":
            return False
    return None


def _url_host(url: Any) -> str | None:
    try:
        return _hostname(urllib.parse.urlsplit(str(url)).hostname or "")
    except ValueError:
        return None


def _record_matches(rec: dict[str, Any], field: str | None, value: Any) -> bool:
    if not field:
        return True
    if field == "host":
        return str(rec.get("host") or "").strip().lower() == value
    if field == "ip":
        try:
            return ipaddress.ip_address(str(rec.get("ip") or "").strip()).compressed == value
        except ValueError:
            return False
    if field == "url":
        return str(value) in str(rec.get("url") or "").lower()
    return True


def parse_phishstats(body: Any, field: str | None = None, value: Any = None, threshold: float = PHISHSTATS_PHISHING_THRESHOLD,
                     max_results: int = PHISHSTATS_MAX_RESULTS) -> dict[str, Any]:
    """c3-c5: PhishStats records -> normalised, redacted records.

    Every record is re-checked against the requested filter (the API silently ignores an invalid filter
    and answers unrelated records with HTTP 200): all-mismatch = error. URLs are redacted before anything
    else sees them. verdict 'phishing' only at score >= threshold, else 'suspicious'.
    Returns ``{"status", "reason", "records", "dropped_mismatch", "truncated"}``."""
    if isinstance(body, dict):
        msg = str(body.get("message") or body.get("error") or "object instead of a record list")[:160]
        return {"status": "error", "reason": f"PhishStats error answer: {msg}: could not verify", "records": [], "dropped_mismatch": 0, "truncated": False}
    if not isinstance(body, list):
        return {"status": "error", "reason": "unexpected PhishStats answer shape: could not verify", "records": [], "dropped_mismatch": 0, "truncated": False}
    val = value.lower() if isinstance(value, str) else value
    out: list[dict[str, Any]] = []
    dropped = 0
    for rec in body:
        if not isinstance(rec, dict):
            continue
        if not _record_matches(rec, field, val):
            dropped += 1
            continue
        url, kinds = redact_victim_url(rec.get("url") or "")
        redirect, rkinds = redact_victim_url(rec.get("redirect_url")) if rec.get("redirect_url") else ("", [])
        score = _float(rec.get("score"))
        ip = rec.get("ip") if isinstance(rec.get("ip"), str) else None
        out.append({
            "id": _int(rec.get("id")), "url": url or None, "url_redactions": sorted(set(kinds) | set(rkinds)), "redirect_url": redirect or None,
            "url_host": _url_host(url), "host": _hostname(rec.get("host")), "ip": ip, "asn": rec.get("asn") if isinstance(rec.get("asn"), str) else None,
            "isp": str(rec.get("isp"))[:120] if rec.get("isp") else None, "countrycode": rec.get("countrycode") if isinstance(rec.get("countrycode"), str) else None,
            "score": score, "verdict": "phishing" if score is not None and score >= threshold else "suspicious",
            "date": rec.get("date") if isinstance(rec.get("date"), str) else None,
            "date_update": rec.get("date_update") if isinstance(rec.get("date_update"), str) else None,
            "title": str(rec.get("title"))[:200] if rec.get("title") else None,
            "tags": [t.strip() for t in str(rec.get("tags") or "").split(",") if t.strip()][:10],
            "google_safebrowsing": _yes_no(rec.get("google_safebrowsing")), "virus_total": _yes_no(rec.get("virus_total")),
            "domain_age_days": _int(rec.get("domain_registered_n_days_ago")),
            "times_seen": {"ip": _int(rec.get("n_times_seen_ip")), "host": _int(rec.get("n_times_seen_host")), "domain": _int(rec.get("n_times_seen_domain"))},
        })
    truncated = len(out) > max_results
    out = out[:max_results]
    if body and not out and dropped:
        return {"status": "error", "reason": f"PhishStats ignored the filter ({dropped} unrelated record(s)): could not verify", "records": [],
                "dropped_mismatch": dropped, "truncated": False}
    return {"status": "ok" if out else "empty", "reason": None, "records": out, "dropped_mismatch": dropped, "truncated": truncated}


def ratelimit_headers(headers: Any) -> dict[str, int | None]:
    """c4: Kong RateLimit headers -> ``{limit_minute, remaining_minute, reset_s}``."""
    h = {str(k).lower(): v for k, v in (headers or {}).items()} if isinstance(headers, dict) else {}
    return {"limit_minute": _int(h.get("x-ratelimit-limit-minute") or h.get("ratelimit-limit")),
            "remaining_minute": _int(h.get("x-ratelimit-remaining-minute") or h.get("ratelimit-remaining")),
            "reset_s": _int(h.get("ratelimit-reset") or h.get("retry-after"))}


def _cache_key(where: str) -> str:
    return "q_" + hashlib.sha256(where.encode("utf-8")).hexdigest()[:20]


@register
class PhishStats(Module):
    name = "phishstats"
    title = "PhishStats phishing URL search"
    description = (
        "Searches PhishStats for phishing URLs by host, IP or keyword (exact filters first, URL-encoded): scores below the "
        "phishing threshold are 'suspicious'; victims' e-mails and tokens in result URLs are redacted; URLs are never submitted."
    )
    category = "url_web"
    accepts = {T.URL, T.DOMAIN, T.IPV4, T.KEYWORD}
    produces = {T.URL, T.IPV4}
    tags = {"reputation"}
    reference = "https://phishstats.info/"
    notice = "PhishStats data is licensed for lawful security research and threat intelligence; V3LUM never submits URLs to PhishStats."
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "phishstats"
    sources = (SOURCE,)
    hosts = ("api.phishstats.info",)
    access_model = "free_noauth_limited"
    max_requests = 2  # exact filter, plus one brand LIKE query for an own domain (c1)
    expected_latency = 0.5
    timeout = 45.0
    min_interval = 3.0  # 20 req/min (c4)
    cache_ttl = CACHE_SECONDS
    default_enabled = True
    max_pivots = PIVOT_CAP

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.IPV4:
            try:
                return ipaddress.ip_address(entity.value).is_global
            except ValueError:
                return False
        return plan_for_entity(entity.type, entity.value)["query"] is not None

    # ---------------------------------------------------------------- fetching (c3/c4)
    def _cached(self, ctx: Any, where: str) -> dict[str, Any] | None:
        try:
            item = ctx.state.get(_cache_key(where))
        except Exception:  # noqa: BLE001 - a state problem only means no cache
            return None
        now = ctx.now().timestamp()
        if isinstance(item, dict) and isinstance(item.get("t"), (int, float)) and 0 <= now - item["t"] <= CACHE_SECONDS and isinstance(item.get("parsed"), dict):
            return item["parsed"]
        return None

    def _store(self, ctx: Any, where: str, parsed: dict[str, Any]) -> None:
        try:
            now = ctx.now().timestamp()
            all_items = ctx.state.all() or {}
            stale = [k for k, v in all_items.items() if k.startswith("q_") and (not isinstance(v, dict) or now - float(v.get("t") or 0) > CACHE_SECONDS)]
            for k in stale:
                ctx.state.delete(k)
            fresh = sorted(((float(v.get("t") or 0), k) for k, v in all_items.items() if k.startswith("q_") and k not in stale and isinstance(v, dict)))
            for _t, k in fresh[: max(0, len(fresh) - CACHE_ENTRIES + 1)]:
                ctx.state.delete(k)
            ctx.state.set(_cache_key(where), {"t": now, "parsed": parsed})
        except Exception:  # noqa: BLE001 - redacted cache is best effort (StateError, size cap)
            return

    def _search(self, ctx: Any, query: dict[str, Any], field: str | None, value: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        cached = self._cached(ctx, query["where"])
        if cached is not None:
            return cached, {"cached": True}
        # the raw body may hold victims' e-mails: it is never cached (c3); the redacted records are
        resp = ctx.http.get(query["url"], source=SOURCE, cache_if=lambda _r: False, headers={"Accept": "application/json"})
        ctx.http.check(resp)  # 429 RateLimited, challenge Blocked, 403 blocked (keyless), 5xx HttpError: could not verify
        meta: dict[str, Any] = {"cached": False, "ratelimit": ratelimit_headers(resp.headers)}
        try:
            body = resp.json()
        except ValueError:
            return {"status": "error", "reason": "PhishStats answered something that is not JSON: could not verify", "records": [],
                    "dropped_mismatch": 0, "truncated": False}, meta
        parsed = parse_phishstats(body, field, value)
        if parsed["status"] in ("ok", "empty"):
            self._store(ctx, query["where"], parsed)
        return parsed, meta

    # ---------------------------------------------------------------- run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        plan = plan_for_entity(entity.type, entity.value)
        query = plan["query"]
        if query is None:  # pragma: no cover - applies() filters these
            return res.mark(Status.SKIPPED, "value not usable in a PhishStats filter", reason_code="not_applicable")
        # the request filter is re-checked locally: exact host filters compare the provider's host field
        field, value = (query["field"], query["value"]) if query["field"] in ("host", "ip") else ("url", query["value"])
        parsed, meta = self._search(ctx, query, field, value)
        if parsed["status"] == "error":
            return res.mark(Status.ERROR, parsed["reason"])
        records = list(parsed["records"])
        queries = [{"field": query["field"], "op": query["op"], "value": query["value"], "dropped_mismatch": parsed["dropped_mismatch"],
                    "truncated": parsed["truncated"], "cached": meta.get("cached", False)}]
        brand_records: list[dict[str, Any]] = []
        own = self._own_domain(ctx, entity)
        if own and entity.type is T.DOMAIN:
            label = brand_label(entity.value)
            bq = phishstats_query("url_like", label) if label else {}
            if "url" in bq:
                bparsed, bmeta = self._search(ctx, bq, "url", bq["value"])
                if bparsed["status"] == "error":
                    res.source_status(SOURCE, Status.ERROR, reason_code="error", reason=f"brand query: {bparsed['reason']}")
                else:
                    reg = psl.registrable_domain(entity.value) or entity.value
                    brand_records = [r for r in bparsed["records"] if not _under(r.get("url_host"), reg)]
                    queries.append({"field": "url", "op": "like", "value": bq["value"], "dropped_mismatch": bparsed["dropped_mismatch"],
                                    "truncated": bparsed["truncated"], "cached": bmeta.get("cached", False)})
        if plan["match"] and plan["match"][0] == "url_host":
            fqdn = plan["match"][1]
            records = [r for r in records if _under(r.get("url_host"), fqdn)]
        res.attr("phishstats_query", queries[0] if len(queries) == 1 else queries)
        res.raw = {"queries": queries, "records": records[:PHISHSTATS_MAX_RESULTS], "brand_records": brand_records[:PHISHSTATS_MAX_RESULTS],
                   "ratelimit": meta.get("ratelimit")}
        if not records and not brand_records:
            return res.mark(Status.EMPTY, f"no PhishStats record for {query['where']} (latest {PHISHSTATS_MAX_RESULTS})")
        res.attr("phishstats_records", records[:PHISHSTATS_MAX_RESULTS])
        self._verdict(entity, res, records, shared=plan["shared"])
        self._pivots(entity, res, records + brand_records)
        if brand_records:
            self._brand(entity, res, brand_records)
        elif entity.type is T.KEYWORD:
            self._keyword(entity, ctx, res, records)
        return res

    @staticmethod
    def _own_domain(ctx: Any, entity: Entity) -> bool:
        try:
            return bool(entity.type is T.DOMAIN and ctx.org.owns(entity).own)
        except Exception:  # noqa: BLE001 - no profile / odd profile: not own
            return False

    def _verdict(self, entity: Entity, res: ModuleResult, records: list[dict[str, Any]], *, shared: bool) -> None:
        """c5 + P071: URL-level verdicts only; the run entity carries one when it IS the listed URL or a
        non-shared FQDN that hosts it; shared platforms and IPs get context only."""
        if entity.type is T.URL:
            want = _norm_url(redact_victim_url(entity.value)[0])
            exact = [r for r in records if r.get("url") and _norm_url(r["url"]) == want]
            if exact:
                self._listed(res, exact, scope="URL")
            elif records:
                self._context(res, records, "other phishing URLs on the same host are listed (the verdict stays URL-level)")
            return
        if entity.type is T.DOMAIN and not shared:
            fqdn = entity.value.lower()
            on_host = [r for r in records if r.get("url_host") == fqdn]
            if on_host:
                self._listed(res, on_host, scope="host")
            below = [r for r in records if r.get("url_host") != fqdn]
            if below:
                self._context(res, below, "phishing URLs listed on subdomains (no verdict propagated to the parent domain)")
            return
        if entity.type is T.DOMAIN:
            self._context(res, records, "host on a shared platform: URL-level listings only, never a verdict on the platform or host")
            return
        if entity.type is T.IPV4:
            self._context(res, records, "phishing URLs that resolved to this IP when listed: the IP never inherits the verdict (shared hosting, CDN, dynamic DNS)")

    def _listed(self, res: ModuleResult, recs: list[dict[str, Any]], *, scope: str) -> None:
        best = max(recs, key=lambda r: r.get("score") if r.get("score") is not None else -1.0)
        phishing = best["verdict"] == "phishing"
        corroborated = any(r.get("google_safebrowsing") or r.get("virus_total") for r in recs)
        dates = sorted(d for d in (r.get("date") for r in recs) if d)
        res.finding(
            "Listed by PhishStats as phishing" if phishing else "Listed by PhishStats (score below the phishing threshold)",
            "high" if phishing else "medium",
            f"{len(recs)} PhishStats record(s) for this {scope}; highest phishscore {best.get('score')} "
            f"({'>=' if phishing else '<'} {PHISHSTATS_PHISHING_THRESHOLD}); first listed {dates[0] if dates else '?'}.",
            confidence="probable" if phishing and corroborated else "possible",
            criterion=(f"PhishStats ML phishscore {best.get('score')} for the exact {scope} (threshold {PHISHSTATS_PHISHING_THRESHOLD}; "
                       "a single community feed, one vote in consensus)"),
            tags=["phishing"] if phishing else ["suspicious"],
            data={"records": len(recs), "max_score": best.get("score"), "verdict": best["verdict"], "urls": [r.get("url") for r in recs[:10]]},
            source=SOURCE,
            observed_first=dates[0] if dates else None,
            observed_last=dates[-1] if dates else None,
            key=scope,
        )

    def _context(self, res: ModuleResult, recs: list[dict[str, Any]], why: str) -> None:
        dates = sorted(d for d in (r.get("date") for r in recs) if d)
        res.finding(
            "PhishStats phishing URLs related to this entity",
            "info",
            f"{len(recs)} record(s): {why}.",
            confidence="possible",
            tags=["context_only"],
            data={"records": len(recs), "max_score": max((r.get("score") or 0.0) for r in recs), "urls": [r.get("url") for r in recs[:10]]},
            source=SOURCE,
            observed_first=dates[0] if dates else None,
            observed_last=dates[-1] if dates else None,
            key="context",
        )

    def _brand(self, entity: Entity, res: ModuleResult, recs: list[dict[str, Any]]) -> None:
        phishing = [r for r in recs if r["verdict"] == "phishing"]
        res.finding(
            "Possible brand impersonation listed by PhishStats",
            "medium" if phishing else "low",
            f"{len(recs)} phishing URL(s) outside the organisation's domain mention its brand label ({len(phishing)} at or above the "
            "phishing threshold): candidates for brand-abuse review and takedown (P345).",
            confidence="possible",
            criterion="PhishStats URL LIKE query on the org-profile domain's brand label, own registrable domain excluded",
            tags=["brand_abuse", "phishing" if phishing else "suspicious"],
            data={"records": len(recs), "urls": [r.get("url") for r in recs[:10]]},
            source=SOURCE,
            key="brand",
        )

    def _keyword(self, entity: Entity, ctx: Any, res: ModuleResult, recs: list[dict[str, Any]]) -> None:
        try:
            brand = entity.value.strip().lower() in {str(t).lower() for t in ctx.org.brand_terms()}
        except Exception:  # noqa: BLE001
            brand = False
        phishing = [r for r in recs if r["verdict"] == "phishing"]
        res.finding(
            "PhishStats phishing URLs mention the keyword",
            ("medium" if phishing else "low") if brand else "info",
            f"{len(recs)} listed URL(s) contain '{entity.value}' ({len(phishing)} at or above the phishing threshold)"
            + (": the keyword is an org-profile brand term (brand monitoring)." if brand else "."),
            confidence="possible",
            criterion="PhishStats URL LIKE query on the keyword (URL-level listings; the keyword itself has no verdict)",
            tags=(["brand_abuse"] if brand else ["context_only"]),
            data={"records": len(recs), "urls": [r.get("url") for r in recs[:10]]},
            source=SOURCE,
            key="keyword",
        )

    def _pivots(self, entity: Entity, res: ModuleResult, recs: list[dict[str, Any]]) -> None:
        ranked = sorted(recs, key=lambda r: -(r.get("score") or 0.0))
        expanded = 0
        for r in ranked[:PIVOT_CAP]:
            url = r.get("url")
            if url and (entity.type is not T.URL or _norm_url(url) != _norm_url(entity.value)):
                expand = r["verdict"] == "phishing" and expanded < EXPAND_CAP
                expanded += 1 if expand else 0
                res.pivot(T.URL, url, "listed_phishing_url", confidence="probable" if r["verdict"] == "phishing" else "possible", expand=expand,
                          note=f"PhishStats {r['verdict']} (score {r.get('score')}, listed {str(r.get('date') or '?')[:10]}); URL-level verdict, victims' data redacted")
            ip = r.get("ip")
            if ip and entity.type is not T.IPV4:
                try:
                    is_v4 = ipaddress.ip_address(ip).version == 4
                except ValueError:
                    is_v4 = False
                if is_v4:
                    res.pivot(T.IPV4, ip, "resolves_to", confidence="possible", expand=False,
                              note=f"address of a listed phishing URL when PhishStats saw it ({str(r.get('date') or '?')[:10]}): never inherits the verdict")


def _norm_url(url: Any) -> str:
    try:
        p = urllib.parse.urlsplit(str(url).strip())
    except ValueError:
        return str(url).strip().lower()
    path = p.path.rstrip("/") or "/"
    return urllib.parse.urlunsplit((p.scheme.lower(), p.netloc.lower(), path, p.query, ""))
