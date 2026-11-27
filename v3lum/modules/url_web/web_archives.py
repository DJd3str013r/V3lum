"""Web archives (P059): Wayback availability + CDX summary + archived homepage, and Arquivo.pt CDX.

Default scan (P059 c1, c2, c9; one run per analyst-typed seed domain/URL, inside a 15 s budget):

* the Wayback availability API (archive.org/wayback/available): the closest (newest) snapshot and
  ``archive_last``;
* one CDX summary query (web.archive.org/cdx/search/cdx, collapse=urlkey,
  fl=original,timestamp,statuscode,mimetype, limit/resumeKey, total row cap 20,000): ``archive_first``
  (a lower bound of web presence, never a registration date), ``archive_count`` (distinct archived
  URLs, capped) and ``archived_url`` pivots (expand=False, capped; the full redacted list goes to the
  ``archived_urls`` attribute for JSON/appendix, P060). A body truncated at the core cap is partial;
* the closest archived homepage snapshot (``id_`` raw body from the archive host only, 1 MB cap):
  indicators plus SHA-256 (title, language, analytics ids, CNPJ text, favicon hrefs, meta refresh,
  generator) for passive consumers (P072 matchers); the body itself is never stored, rendered or
  executed;
* Arquivo.pt CDX (NDJSON) for .br/.pt and Portuguese-language sites even when Wayback answers, and as
  the fallback when web.archive.org is unreachable; its ``id_`` replay is the homepage fallback.

Per-source status (c4): resets, 5xx and timeouts are 'archive unreachable' (could not verify), never
'never archived' or 'no captures'; an empty answer never means a new domain. Every archived URL passes
the core redaction helper (key-like parameters, URL passwords) plus this module's archive masking
(URL credentials, session ids, JWTs, e-mail addresses, opaque secret values) before it reaches pivots,
attributes, evidence or reports (c5). Archived URLs are never requested from the live target and no
Save Page Now / 'archive now' endpoint exists here (c6, c7). Common Crawl and CarbonDate (deep/-M
only) live in ``web_archives_deep``; UKWA in ``web_archives_ukwa`` (disabled until it answers).
"""

from __future__ import annotations

import hashlib
import html
import json
import re
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, unquote_plus, urlsplit, urlunsplit

from v3lum.config import SettingSpec
from v3lum.core import psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.core.redact import MASK, redact_url

SRC_WAYBACK = "internet_archive.wayback"
SRC_CDX = "internet_archive.web_archives_cdx"
SRC_ARQUIVO = "arquivo_pt.cdx"
AVAILABLE = "https://archive.org/wayback/available"
CDX = "https://web.archive.org/cdx/search/cdx"
ARQUIVO_CDX = "https://arquivo.pt/wayback/cdx"
HOMEPAGE_MAX_BYTES = 1_048_576
ROW_CAP = 20_000
_EVIDENCE_ROWS = 1500
_ATTRIBUTE_URLS = 500

# =====================================================================================
# helpers: text, time, redaction
# =====================================================================================

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def text_of(raw: Any) -> str:
    """bytes/str -> str (UTF-8, errors replaced); anything else -> ''."""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8", errors="replace")
    return raw if isinstance(raw, str) else ""


def clean(value: Any, limit: int = 300) -> str:
    """Untrusted string -> one line without control characters, capped."""
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", " ", _CTRL.sub("", value)).strip()[:limit]


def looks_like_html(text: str) -> bool:
    t = text.lstrip()[:512].lower()
    return t.startswith("<!doctype html") or t.startswith("<html") or "<head" in t[:200] or "<body" in t[:200]


def wayback_ts_to_iso(ts: Any) -> str | None:
    """CDX/Wayback timestamp (4-14 digits, missing parts padded) -> 'YYYY-MM-DDTHH:MM:SSZ'."""
    if not isinstance(ts, str) or not re.fullmatch(r"(?:\d\d){2,7}", ts.strip()):
        return None
    t = ts.strip()
    if len(t) < 14:
        t = t + "0101000000"[len(t) - 4:]
    try:
        dt = datetime.strptime(t, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


#: query/fragment parameter names whose values are masked in archived URLs (P312-style detectors)
SECRET_PARAMS = frozenset({
    "token", "access_token", "id_token", "refresh_token", "auth", "authorization", "auth_token", "apikey", "api_key", "key",
    "secret", "client_secret", "password", "passwd", "pwd", "pass", "sig", "signature", "session", "sessionid", "session_id",
    "sid", "jsessionid", "phpsessid", "aspsessionid", "code", "ticket", "otp", "hash", "x-amz-signature", "x-amz-credential",
    "x-amz-security-token", "awsaccesskeyid", "email", "e-mail", "mail", "user", "username", "login", "cpf", "cnpj",
    "telefone", "phone", "tel", "celular", "recipient", "rcpt", "uid", "userid", "user_id",
})
_SAFE_PARAMS = frozenset({"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "page", "lang", "hl", "format",
                          "output", "limit", "offset", "sort", "q", "s", "id", "p"})
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+(?:@|%40)[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_OPAQUE_RE = re.compile(r"^(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9_\-+/=.%]{16,}$")
_PATH_SESSION_RE = re.compile(r";(jsessionid|phpsessid|sid|sessionid)=[^/;?#]*", re.I)


def _split(url: str) -> Any:
    try:
        parts = urlsplit(url)
        _ = parts.port  # raises ValueError on a bad port
        return parts
    except ValueError:
        return None


def redact_archived_url(url: Any) -> tuple[str, list[str]]:
    """Mask secrets in an archived URL (P059 c5) -> (redacted URL, kinds masked).

    The core helper (``v3lum.core.redact.redact_url``: configured keys, key-like parameters, URL
    passwords) runs first; then the whole userinfo (user:pass@), ``;jsessionid``-style path parameters,
    JWTs, e-mail addresses, secret/session/recipient parameters and opaque >= 16-character values are
    replaced by the core mask. Non-strings give ('', [])."""
    if not isinstance(url, str) or not url.strip():
        return "", []
    raw = url.strip()[:2048]
    found: list[str] = []
    core = redact_url(raw)
    if core != raw:  # name what the core helper masked (URL password, key-like parameter, configured key)
        before, after = _split(raw), _split(core)
        if before is not None and after is not None and before.netloc != after.netloc:
            found.append("userinfo")
        if before is None or after is None or (before.query, before.fragment, before.path) != (after.query, after.fragment, after.path):
            found.append("query_secret")
    parts = _split(core)
    if parts is None:
        masked = _EMAIL_RE.sub(MASK, core)
        return masked, sorted(set(found + (["email"] if masked != core else []) + ["unparseable"]))
    netloc = parts.netloc
    if "@" in netloc:
        netloc = MASK + "@" + netloc.rsplit("@", 1)[1]
        found.append("userinfo")
    path = parts.path
    new_path = _PATH_SESSION_RE.sub(lambda m: f";{m.group(1)}={MASK}", path)
    if new_path != path:
        found.append("path_session_id")
    if _JWT_RE.search(new_path):
        new_path = _JWT_RE.sub(MASK, new_path)
        found.append("jwt")
    if _EMAIL_RE.search(new_path):
        new_path = _EMAIL_RE.sub(MASK, new_path)
        found.append("email")
    pieces = []
    for piece in parts.query.split("&") if parts.query else []:
        k_raw, _eq, v_raw = piece.partition("=")
        key, value = unquote_plus(k_raw), unquote_plus(v_raw)
        kl = key.lower()
        kind = None
        if value == MASK or v_raw == MASK:
            kind = None
        elif kl in SECRET_PARAMS and value:
            kind = "query_secret"
        elif _JWT_RE.search(value):
            kind = "jwt"
        elif _EMAIL_RE.search(value):
            kind = "email"
        elif kl not in _SAFE_PARAMS and not kl.startswith("utm_") and _OPAQUE_RE.match(value):
            kind = "opaque_token"
        if kind:
            found.append(kind)
            pieces.append(f"{k_raw}={MASK}")
        else:
            pieces.append(piece)
    frag = parts.fragment
    if frag and (_EMAIL_RE.search(frag) or _JWT_RE.search(frag) or "token" in frag.lower() or "=" in frag):
        frag = MASK
        found.append("fragment_secret")
    out = urlunsplit((parts.scheme, netloc, new_path, "&".join(pieces), frag))
    return out, sorted(set(found))


def is_masked(kinds: Iterable[str]) -> bool:
    """True when redaction removed something sensitive (credentials, tokens, ids, e-mails)."""
    return any(k != "unparseable" for k in kinds)


# =====================================================================================
# parsers (pure, never raise on junk)
# =====================================================================================

_IA_SNAPSHOT = re.compile(r"^https?://web\.archive\.org/web/(\d{4,14})(?:[a-z]{2}_)?/(.+)$", re.I)


def archive_marker(status: Any, raw: Any) -> str | None:
    """Exclusion/maintenance/error-in-200 markers of archive answers (P321 style); None when clean."""
    t = text_of(raw)
    low = t[:4000].lower()
    if "under maintenance" in low or "temporarily offline for maintenance" in low:
        return "maintenance"
    if "blocked site error" in low or "administrativeaccesscontrolexception" in low:
        return "excluded_by_archive"
    if "robotaccesscontrolexception" in low:
        return "excluded_by_robots"
    if status == 200 and re.match(r"\s*error[:\s]", t[:200], re.I):
        return "error_in_200: " + clean(t, 120)
    return None


def parse_wayback_available(raw: Any) -> dict[str, Any]:
    """archive.org/wayback/available -> {state: ok|empty|error, closest, error}.

    ``closest`` = {status, timestamp, captured_at, snapshot_url (https web.archive.org link), original
    (redacted), raw_snapshot (id_ URL on the archive host, None when the original carries secrets)}.
    'empty' means no capture of THAT URL, never 'never archived'."""
    t = text_of(raw) if not isinstance(raw, (dict, list)) else ""
    if t:
        marker = archive_marker(200, t)
        if marker:
            return {"state": "error", "closest": None, "error": marker}
        if looks_like_html(t):
            return {"state": "error", "closest": None, "error": "HTML instead of JSON"}
        try:
            obj: Any = json.loads(t)
        except ValueError:
            return {"state": "error", "closest": None, "error": "malformed JSON"}
    else:
        obj = raw
    if not isinstance(obj, Mapping) or not isinstance(obj.get("archived_snapshots"), Mapping):
        return {"state": "error", "closest": None, "error": "unexpected answer (no archived_snapshots object)"}
    c = obj["archived_snapshots"].get("closest")
    if not isinstance(c, Mapping) or c.get("available") is not True:
        return {"state": "empty", "closest": None, "error": None}
    url = c.get("url") if isinstance(c.get("url"), str) else ""
    if url.startswith("http://web.archive.org/"):
        url = "https://" + url[len("http://"):]
    m = _IA_SNAPSHOT.match(url) if url.startswith("https://web.archive.org/") else None
    if not m:
        return {"state": "error", "closest": None, "error": "snapshot link is not a web.archive.org URL"}
    ts = c.get("timestamp") if isinstance(c.get("timestamp"), str) and c["timestamp"].isdigit() else m.group(1)
    original = m.group(2)
    redacted, kinds = redact_archived_url(original)
    masked = is_masked(kinds)
    return {"state": "ok", "error": None, "closest": {
        "status": clean(str(c.get("status")), 8) if c.get("status") is not None else None,
        "timestamp": ts, "captured_at": wayback_ts_to_iso(ts),
        "snapshot_url": None if masked else f"https://web.archive.org/web/{ts}/{original}",
        "original": redacted, "secret_masked": masked,
        "raw_snapshot": None if masked else archive_snapshot_url("wayback", ts, original),
    }}


def _row(original: Any, timestamp: Any, status: Any, mime: Any) -> dict[str, Any] | None:
    if not isinstance(original, str) or not isinstance(timestamp, str):
        return None
    captured = wayback_ts_to_iso(timestamp)
    if captured is None:
        return None
    redacted, kinds = redact_archived_url(original)
    if not redacted:
        return None
    return {
        "url": redacted, "secret_masked": is_masked(kinds), "masked": [k for k in kinds if k != "unparseable"],
        "timestamp": timestamp, "captured_at": captured,
        "statuscode": status if isinstance(status, str) and status.isdigit() else None,
        "mimetype": clean(mime, 80) if isinstance(mime, str) and mime not in ("-", "") else None,
        "_original": original,  # in memory only (homepage snapshot choice); never reaches results
    }


def _cdx_result(rows: list[dict[str, Any]], *, partial: bool = False, stop: str | None = None, error: str | None = None,
                resume_key: str | None = None, state: str | None = None) -> dict[str, Any]:
    if state is None:
        state = "error" if error and not rows else ("ok" if rows else "empty")
    return {"state": state, "rows": rows, "partial": partial, "stop": stop, "error": error, "resume_key": resume_key}


def parse_wayback_cdx(raw: Any, row_cap: int = ROW_CAP, body_truncated: bool = False) -> dict[str, Any]:
    """Wayback CDX (output=json, optional showResumeKey) -> {state, rows, partial, stop, error, resume_key}.

    A body truncated at the core cap (or cut mid-way) keeps its complete rows and is partial
    ('body_truncated'), never complete; ``row_cap`` stops at 20,000 rows ('row_cap'). The resume key
    after the empty row is returned URL-decoded. Every row URL is redacted."""
    text = text_of(raw) if not isinstance(raw, list) else ""
    data: Any = raw if isinstance(raw, list) else None
    partial = bool(body_truncated)
    stop = "body_truncated" if body_truncated else None
    if data is None:
        if not text.strip():
            return _cdx_result([], partial=partial, stop=stop, state="empty")
        marker = archive_marker(200, text)
        if marker:
            return _cdx_result([], error=marker)
        if looks_like_html(text):
            return _cdx_result([], error="HTML instead of JSON")
        if not text.lstrip().startswith("["):
            return _cdx_result([], error="unexpected CDX answer (not a JSON array)")
        try:
            data = json.loads(text)
        except ValueError:  # truncated or malformed: salvage the complete rows
            data = []
            dec = json.JSONDecoder()
            s = text.lstrip()
            pos = 1
            while pos < len(s):
                while pos < len(s) and s[pos] in " \t\r\n,":
                    pos += 1
                if pos >= len(s) or s[pos] != "[":
                    break
                try:
                    item, pos = dec.raw_decode(s, pos)
                except ValueError:
                    break
                data.append(item)
            partial, stop = True, "body_truncated"
    if not isinstance(data, list):
        return _cdx_result([], error="unexpected CDX answer")
    header: list[str] | None = None
    rows: list[dict[str, Any]] = []
    resume = None
    for i, item in enumerate(data):
        if not isinstance(item, list):
            continue
        if item == []:
            nxt = data[i + 1] if i + 1 < len(data) else None
            if isinstance(nxt, list) and len(nxt) == 1 and isinstance(nxt[0], str):
                resume = unquote_plus(nxt[0])[:512]
            break
        if header is None and all(isinstance(x, str) for x in item) and "timestamp" in item:
            header = [str(x) for x in item]
            continue
        if header is None:
            header = ["original", "timestamp", "statuscode", "mimetype", "digest"][: len(item)]
        rec = dict(zip(header, item))
        if len(rows) >= row_cap:
            partial, stop = True, "row_cap"
            break
        row = _row(rec.get("original"), rec.get("timestamp"), rec.get("statuscode"), rec.get("mimetype"))
        if row is not None:
            rows.append(row)
    if partial and not rows and stop == "body_truncated" and not text.strip().startswith("[["):
        return _cdx_result([], partial=True, stop=stop, error="malformed CDX answer")
    return _cdx_result(rows, partial=partial, stop=stop, resume_key=resume)


def parse_arquivo_cdx(raw: Any, row_cap: int = ROW_CAP, body_truncated: bool = False) -> dict[str, Any]:
    """Arquivo.pt CDX (output=json: NDJSON lines) -> the same shape as :func:`parse_wayback_cdx`.

    No captures = HTTP 200 with an empty body ('empty'); a line cut mid-object marks the result
    partial; an HTML or error body is an error, never empty."""
    text = text_of(raw)
    if not text.strip():
        return _cdx_result([], partial=bool(body_truncated), stop="body_truncated" if body_truncated else None, state="empty")
    marker = archive_marker(200, text)
    if marker:
        return _cdx_result([], error=marker)
    if looks_like_html(text):
        return _cdx_result([], error="HTML instead of NDJSON")
    rows: list[dict[str, Any]] = []
    partial = bool(body_truncated)
    stop = "body_truncated" if body_truncated else None
    lines = text.split("\n")
    for idx, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            partial = True
            stop = "body_truncated" if idx >= len(lines) - 1 else "malformed_line"
            continue
        if not isinstance(obj, Mapping):
            continue
        if len(rows) >= row_cap:
            partial, stop = True, "row_cap"
            break
        row = _row(obj.get("url"), obj.get("timestamp"), obj.get("status"), obj.get("mime"))
        if row is not None:
            rows.append(row)
    if not rows and partial:
        return _cdx_result([], partial=True, stop=stop, error="malformed NDJSON")
    return _cdx_result(rows, partial=partial, stop=stop)


def archive_snapshot_url(source: str, timestamp: Any, original: Any) -> str | None:
    """Raw (``id_``) snapshot URL on the ARCHIVE host (P059 c6/c9); None for an unknown source, a bad
    timestamp, a non-http(s) original or an original carrying credentials/tokens/e-mails (never
    fetched, c7)."""
    if not isinstance(original, str) or not isinstance(timestamp, str) or not wayback_ts_to_iso(timestamp):
        return None
    parts = _split(original.strip())
    if parts is None or parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    if is_masked(redact_archived_url(original)[1]):
        return None
    if source == "wayback":
        return f"https://web.archive.org/web/{timestamp}id_/{original.strip()}"
    if source == "arquivo":
        return f"https://arquivo.pt/wayback/{timestamp}id_/{original.strip()}"
    return None


_ANALYTICS = (
    ("ga_universal", re.compile(r"\bUA-\d{4,10}-\d{1,4}\b")),
    ("ga4", re.compile(r"\bG-[A-Z0-9]{8,12}\b")),
    ("gtm", re.compile(r"\bGTM-[A-Z0-9]{4,9}\b")),
    ("google_ads", re.compile(r"\bAW-\d{6,12}\b")),
    ("adsense", re.compile(r"\b(?:ca-)?pub-\d{16}\b")),
)
_CNPJ_FMT = re.compile(r"(?<![\d.])\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}(?![\d-])")
_CNPJ_BARE = re.compile(r"CNPJ[^0-9A-Za-z]{0,12}(\d{14})\b", re.I)


def cnpj_valid(value: Any) -> bool:
    d = re.sub(r"\D", "", value) if isinstance(value, str) else ""
    if len(d) != 14 or len(set(d)) == 1:
        return False
    nums = [int(c) for c in d]
    for n in (12, 13):
        weights = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2][13 - n:]
        dv = 11 - sum(a * b for a, b in zip(nums[:n], weights)) % 11
        if (0 if dv >= 10 else dv) != nums[n]:
            return False
    return True


def homepage_indicators(body: Any, max_bytes: int = HOMEPAGE_MAX_BYTES, content_type: Any = None) -> dict[str, Any]:
    """Indicators from an archived homepage body (P059 c6/c9). The body is untrusted: parsed with
    regular expressions only, never executed or rendered, and NOT returned; the cap applies before
    hashing (``truncated`` True, the hash covers the capped bytes). Returns {sha256, bytes, truncated,
    charset, title, lang, analytics_ids, cnpjs, favicon_hrefs, meta_refresh, generator, script_count}."""
    data = body.encode("utf-8", errors="replace") if isinstance(body, str) else bytes(body) if isinstance(body, (bytes, bytearray)) else b""
    truncated = len(data) > max_bytes
    data = data[:max_bytes]
    charset = None
    if isinstance(content_type, str):
        m = re.search(r"charset=([\w.:-]+)", content_type, re.I)
        charset = m.group(1).lower() if m else None
    if not charset:
        m = re.search(rb"<meta[^>]+charset=[\"']?([\w.:-]+)", data[:4096], re.I)
        charset = m.group(1).decode("ascii", "ignore").lower() if m else None
    try:
        text = data.decode(charset or "utf-8", errors="replace")
    except LookupError:
        charset = None
        text = data.decode("utf-8", errors="replace")
    title = None
    m = re.search(r"<title[^>]*>(.*?)</title\s*>", text, re.I | re.S)
    if m:
        title = clean(html.unescape(re.sub(r"<[^>]+>", "", m.group(1))), 300) or None
    lang = None
    m = re.search(r"<html\b[^>]*\blang\s*=\s*[\"']?([A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})?)", text[:8192], re.I)
    if m:
        lang = m.group(1).lower()
    ids: list[dict[str, str]] = []
    seen: set[str] = set()
    for kind, rx in _ANALYTICS:
        for v in rx.findall(text):
            if v not in seen and len(ids) < 50:
                seen.add(v)
                ids.append({"kind": kind, "id": v})
    cnpjs: list[str] = []
    for v in _CNPJ_FMT.findall(text) + _CNPJ_BARE.findall(text):
        d = re.sub(r"\D", "", v)
        if cnpj_valid(d):
            f = f"{d[:2]}.{d[2:5]}.{d[5:8]}/{d[8:12]}-{d[12:]}"
            if f not in cnpjs and len(cnpjs) < 20:
                cnpjs.append(f)
    favicons: list[str] = []
    for tag in re.findall(r"<link\b[^>]{0,500}>", text, re.I)[:200]:
        rel = re.search(r"rel\s*=\s*[\"']([^\"']+)[\"']", tag, re.I)
        href = re.search(r"href\s*=\s*[\"']([^\"']+)[\"']", tag, re.I)
        if rel and href and "icon" in rel.group(1).lower() and len(favicons) < 10:
            favicons.append(redact_archived_url(clean(html.unescape(href.group(1)), 300))[0] if "://" in href.group(1) else clean(html.unescape(href.group(1)), 300))
    refresh = None
    for tag in re.findall(r"<meta\b[^>]{0,500}>", text, re.I)[:200]:
        if re.search(r"http-equiv\s*=\s*[\"']?refresh", tag, re.I):
            c = re.search(r"content\s*=\s*[\"']([^\"']*)[\"']", tag, re.I)
            u = re.search(r"url\s*=\s*(\S+)", c.group(1), re.I) if c else None
            if u:
                refresh = redact_archived_url(html.unescape(u.group(1)).strip("'\""))[0] or None
    generator = None
    m = re.search(r"<meta\b[^>]*name\s*=\s*[\"']generator[\"'][^>]*content\s*=\s*[\"']([^\"']+)[\"']", text, re.I)
    if m:
        generator = clean(html.unescape(m.group(1)), 120)
    return {
        "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "truncated": truncated, "charset": charset,
        "title": title, "lang": lang, "analytics_ids": ids, "cnpjs": cnpjs, "favicon_hrefs": favicons, "meta_refresh": refresh,
        "generator": generator, "script_count": len(re.findall(r"<script\b", text, re.I)),
    }


def failure(source: str, exc: BaseException) -> dict[str, Any]:
    """Rule-5 outcome of a failed archive call (P059 c4): resets, 5xx and timeouts are 'archive
    unreachable' (could not verify), 429 rate limited, challenges blocked - never 'no captures'."""
    text = clean(str(exc), 200)
    if isinstance(exc, RateLimited):
        return {"status": "rate_limited", "reason_code": "rate_limited", "reason": f"{source}: rate limited ({text})"}
    if isinstance(exc, QuotaExceeded):
        return {"status": "quota", "reason_code": "quota", "reason": f"{source}: quota ({text})"}
    if isinstance(exc, (Blocked, AuthRequired)):
        code = str(getattr(exc, "reason_code", "") or "challenge")
        if code not in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host"):
            code = "challenge"
        return {"status": "blocked", "reason_code": code, "reason": f"{source}: blocked ({text})"}
    if isinstance(exc, DeadlineExceeded):
        return {"status": "could_not_verify", "reason_code": "timeout", "reason": f"{source}: archive unreachable (run deadline)"}
    if isinstance(exc, HttpError):
        status = int(getattr(exc, "status", 0) or 0)
        if status >= 500 or status == 0:
            return {"status": "could_not_verify", "reason_code": "error", "reason": f"{source}: archive unreachable ({text})"}
        return {"status": "could_not_verify", "reason_code": "error", "reason": f"{source}: archive error ({text})"}
    if isinstance(exc, NetworkError):
        timeout = bool(re.search(r"time[d ]?\s?out", text, re.I))
        return {"status": "could_not_verify", "reason_code": "timeout" if timeout else "error", "reason": f"{source}: archive unreachable ({text})"}
    return {"status": "could_not_verify", "reason_code": "error", "reason": f"{source}: archive error ({text})"}


_STATUS = {"rate_limited": Status.RATE_LIMITED, "quota": Status.QUOTA, "blocked": Status.BLOCKED, "could_not_verify": Status.ERROR}


def report_failure(res: ModuleResult, source_id: str, outcome: Mapping[str, Any]) -> None:
    """Record a failed source in ``res.source_statuses`` (coverage: could not verify)."""
    status = _STATUS.get(str(outcome.get("status")), Status.ERROR)
    code = str(outcome.get("reason_code") or "")
    if status is Status.ERROR and code not in ("timeout", "error"):
        code = "error"
    res.source_status(source_id, status, reason_code=code, reason=str(outcome.get("reason") or "could not verify"))


# =====================================================================================
# the module
# =====================================================================================

_INTERESTING_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|csv|txt|sql|bak|zip|rar|7z|tar|gz|env|json|xml|conf|cfg|ini|log|js|php|aspx?|jsp)(?:$|[?#])", re.I)
_BORING_EXT = re.compile(r"\.(png|jpe?g|gif|svg|ico|webp|bmp|woff2?|ttf|eot|otf|css|mp4|mp3|avi|mov)(?:$|[?#])", re.I)
_INTERESTING_PATH = re.compile(r"/(login|signin|admin|wp-admin|wp-login|webmail|portal|api|backup|old|dev|test|staging|upload|download|private)\b", re.I)
_PT_TLDS = ("br", "pt")


def _budget_now(ctx: Any) -> datetime:
    try:
        return ctx.now()
    except Exception:
        return datetime.now(timezone.utc)


class _Budget:
    """The module's time budget (15 s default sources) on the run clock, capped by the run deadline."""

    def __init__(self, ctx: Any, seconds: float) -> None:
        self.ctx = ctx
        self.seconds = float(seconds)
        self.start = _budget_now(ctx)

    def left(self) -> float:
        spent = (_budget_now(self.ctx) - self.start).total_seconds()
        left = self.seconds - spent
        remaining = self.ctx.remaining()
        if remaining is not None:
            left = min(left, float(remaining) - 2.0)
        return left

    def timeout(self, wanted: float) -> float | None:
        """Per-request timeout, or None when no time is left for another request."""
        left = self.left()
        return None if left < 1.0 else max(1.0, min(wanted, left))


def query_target(entity: Entity) -> dict[str, Any] | None:
    """What the archives are asked for: a registrable domain (domain seeds) or the URL (URL seeds,
    without query/fragment/userinfo when they carry secrets)."""
    if entity.type is T.DOMAIN:
        dom = entity.value.strip(".").lower()
        reg = psl.registrable_domain(dom) or dom
        return {"kind": "domain", "domain": reg, "query": reg, "match": "domain", "homepage": f"http://{reg}/", "note": "" if reg == dom else f"registrable domain {reg} of {dom}"}
    parts = _split(entity.value)
    if parts is None or parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    host = parts.hostname.lower()
    redacted, kinds = redact_archived_url(entity.value)
    note = ""
    query = entity.value
    if is_masked(kinds) or parts.username or parts.password:
        query = urlunsplit((parts.scheme, host + (f":{parts.port}" if parts.port else ""), parts.path or "/", "", ""))
        note = "query string, fragment and credentials left out of the archive lookup (they carry secrets or identifiers)"
    return {"kind": "url", "domain": host, "query": query, "match": "prefix", "homepage": query, "note": note, "redacted": redacted}


@register
class WebArchives(Module):
    name = "web_archives"
    title = "Web archives (Wayback Machine, Arquivo.pt)"
    description = (
        "Archive history of a domain or URL: Wayback availability and CDX summary (first/last capture, archived URLs), the "
        "closest archived homepage's indicators, and Arquivo.pt for Portuguese-language sites or when Wayback is unreachable."
    )
    category = "url_web"
    accepts = {T.DOMAIN, T.URL}
    produces = {T.URL, T.DOMAIN, T.ANALYTICS_ID, T.CNPJ}
    run_on = "seeds"
    tags = {"free"}
    reference = "https://archive.org/help/wayback_api.php"
    notice = (
        "The Internet Archive grants access for research: legal records internal CTI research as the purpose (P059). "
        "Archived bodies are fetched only from the archive hosts and kept as indicators plus SHA-256; archived URLs are never "
        "requested from the live site and Save Page Now is never called. Arquivo.pt asks to be cited as [source: Arquivo.pt, date]."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "internet_archive"
    sources = (SRC_WAYBACK, SRC_CDX, SRC_ARQUIVO)
    hosts = ("archive.org", "web.archive.org", "arquivo.pt")
    access_model = "free_noauth_limited"
    max_requests = 10
    expected_latency = 9.0
    timeout = 30.0
    cache_ttl = 86400
    max_pivots = 60
    default_enabled = True
    settings = {
        "web_archives_budget": SettingSpec(15.0, "web_archives: seconds for the default sources (P059 c1)"),
        "web_archives_budget_deep": SettingSpec(26.0, "web_archives: seconds with --preset deep (CDX pages up to the row cap)"),
        "web_archives_cdx_limit": SettingSpec(5000, "web_archives: CDX rows per page (collapse=urlkey)"),
        "web_archives_row_cap": SettingSpec(ROW_CAP, "web_archives: total CDX row cap (P059 c1: 20,000)"),
        "web_archives_url_pivots": SettingSpec(25, "web_archives: archived_url pivots kept (expand=False)"),
        "web_archives_homepage": SettingSpec(True, "web_archives: fetch the closest archived homepage (id_, 1 MB) for indicators (P059 c9)"),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return query_target(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        q = query_target(entity)
        if q is None:
            return res.mark("skipped", "not an http(s) URL or a domain", reason_code="not_applicable")
        deep = str(getattr(getattr(ctx, "options", None), "preset", "") or "") == "deep"
        seconds = _float(ctx.setting("web_archives_budget_deep" if deep else "web_archives_budget", 26.0 if deep else 15.0), 15.0)
        budget = _Budget(ctx, seconds)
        row_cap = max(1, min(ROW_CAP, _int(ctx.setting("web_archives_row_cap", ROW_CAP), ROW_CAP)))
        page = max(1, min(row_cap, _int(ctx.setting("web_archives_cdx_limit", 5000), 5000)))
        state = _Run(ctx, res, q, budget, row_cap=row_cap, page=page, deep=deep)
        state.execute()
        return state.finish()


def _int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class _Run:
    """One web_archives run: requests in a budget-friendly order, per-source outcomes, output."""

    def __init__(self, ctx: Any, res: ModuleResult, q: dict[str, Any], budget: _Budget, *, row_cap: int, page: int, deep: bool) -> None:
        self.ctx, self.res, self.q, self.budget = ctx, res, q, budget
        self.row_cap, self.page, self.deep = row_cap, page, deep
        self.sources: dict[str, Any] = {}  # endpoint -> outcome text
        self.failures: dict[str, dict[str, Any]] = {}  # registry source id -> failure
        self.avail: dict[str, Any] | None = None
        self.avail_first: dict[str, Any] | None = None
        self.cdx: dict[str, Any] | None = None
        self.arquivo: dict[str, Any] | None = None
        self.homepage: dict[str, Any] | None = None
        self.partial = False
        self.answered: set[str] = set()  # registry sources with at least one endpoint that answered

    # ---- plumbing -----------------------------------------------------------------------------
    def _get(self, endpoint: str, source_id: str, url: str, *, params: Mapping[str, Any] | None = None, wanted: float = 8.0,
             ttl: int | None = None, max_bytes: int | None = None, retries: int | None = None) -> Any:
        timeout = self.budget.timeout(wanted)
        if timeout is None:
            self.sources[endpoint] = "not_run: time budget used up"
            return None
        kw: dict[str, Any] = {"source": source_id, "timeout": timeout}
        if params:
            kw["params"] = dict(params)
        if ttl is not None:
            kw["ttl"] = ttl
        if max_bytes is not None:
            kw["max_bytes"] = max_bytes
        if retries is not None:
            kw["retries"] = retries
        try:
            resp = self.ctx.http.get(url, **kw)
            self.ctx.http.check(resp)
            return resp
        except (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError, DeadlineExceeded) as exc:
            out = failure(endpoint, exc)
            self.sources[endpoint] = f"{out['status']}: {out['reason']}"
            self.failures.setdefault(source_id, out)
            return None

    # ---- sources ------------------------------------------------------------------------------
    def availability(self, *, earliest: bool = False) -> None:
        endpoint = "wayback_availability_first" if earliest else "wayback_availability"
        params = {"url": self.q["query"]}
        if earliest:
            params["timestamp"] = "19960101"
        resp = self._get(endpoint, SRC_WAYBACK, AVAILABLE, params=params, wanted=8.0, ttl=21600)
        if resp is None:
            return
        parsed = parse_wayback_available(resp.content)
        if parsed["state"] == "error":
            self.sources[endpoint] = f"could_not_verify: {parsed['error']}"
            self.failures.setdefault(SRC_WAYBACK, {"status": "could_not_verify", "reason_code": "error", "reason": f"{endpoint}: {parsed['error']}"})
            return
        self.sources[endpoint] = "ok" if parsed["state"] == "ok" else "empty (no capture of this URL)"
        self.answered.add(SRC_WAYBACK)
        if earliest:
            self.avail_first = parsed
        else:
            self.avail = parsed

    def wayback_cdx(self) -> None:
        params: dict[str, Any] = {
            "url": self.q["query"], "matchType": self.q["match"], "output": "json", "fl": "original,timestamp,statuscode,mimetype",
            "collapse": "urlkey", "limit": str(self.page), "showResumeKey": "true",
        }
        rows: list[dict[str, Any]] = []
        pages = 4 if self.deep else 1
        result: dict[str, Any] | None = None
        for _ in range(pages):
            resp = self._get("wayback_cdx", SRC_CDX, CDX, params=params, wanted=8.0, ttl=86400, max_bytes=8 * 1024 * 1024,
                             retries=None if self.deep else 0)
            if resp is None:
                break
            result = parse_wayback_cdx(resp.content, self.row_cap - len(rows), body_truncated=bool(getattr(resp, "truncated", False)))
            if result["state"] == "error":
                self.sources["wayback_cdx"] = f"could_not_verify: {result['error']}"
                self.failures.setdefault(SRC_CDX, {"status": "could_not_verify", "reason_code": "error", "reason": f"wayback_cdx: {result['error']}"})
                break
            rows.extend(result["rows"])
            if result["partial"] or not result["resume_key"] or len(rows) >= self.row_cap:
                break
            params = dict(params, resumeKey=result["resume_key"])
        if result is None or result["state"] == "error":
            if rows:
                self.cdx = _cdx_result(rows, partial=True, stop="body_truncated")
                self.partial = True
            return
        more_pages = bool(result.get("resume_key")) and not result["partial"]
        partial = bool(result["partial"]) or more_pages  # unread pages: the summary is a lower bound, never complete
        stop = result.get("stop") or ("row_cap" if len(rows) >= self.row_cap else "more_pages" if more_pages else None)
        self.cdx = _cdx_result(rows, partial=partial, stop=stop)
        self.sources["wayback_cdx"] = ("ok" if rows else "empty (no captures in the CDX index)") + (f", partial: {stop}" if partial else "")
        self.answered.add(SRC_CDX)
        if partial:
            self.partial = True

    def arquivo_cdx(self) -> None:
        query = f"{self.q['domain']}/*" if self.q["kind"] == "domain" else self.q["query"]
        params = {"url": query, "output": "json", "limit": str(min(self.page, 2000))}
        resp = self._get("arquivo_pt", SRC_ARQUIVO, ARQUIVO_CDX, params=params, wanted=10.0, ttl=86400, max_bytes=4 * 1024 * 1024)
        if resp is None:
            return
        result = parse_arquivo_cdx(resp.content, self.row_cap, body_truncated=bool(getattr(resp, "truncated", False)))
        if result["state"] == "error":
            self.sources["arquivo_pt"] = f"could_not_verify: {result['error']}"
            self.failures.setdefault(SRC_ARQUIVO, {"status": "could_not_verify", "reason_code": "error", "reason": f"arquivo_pt: {result['error']}"})
            return
        self.arquivo = result
        self.answered.add(SRC_ARQUIVO)
        self.sources["arquivo_pt"] = ("ok" if result["rows"] else "empty (no captures in Arquivo.pt)") + (
            f", partial: {result['stop']}" if result["partial"] else "")
        if result["partial"]:
            self.partial = True

    def snapshot(self, source: str, raw_url: str, captured_at: str | None) -> None:
        endpoint = f"{source}_homepage_snapshot"
        source_id = SRC_WAYBACK if source == "wayback" else SRC_ARQUIVO
        resp = self._get(endpoint, source_id, raw_url, wanted=8.0, ttl=86400, max_bytes=HOMEPAGE_MAX_BYTES + 1)
        if resp is None:
            return
        indicators = homepage_indicators(resp.content, content_type=(getattr(resp, "headers", None) or {}).get("content-type"))
        if getattr(resp, "truncated", False):
            indicators["truncated"] = True
        page_url, _kinds = redact_archived_url(raw_url)
        self.homepage = {"source": source, "snapshot": page_url, "captured_at": captured_at, **indicators}
        self.sources[endpoint] = "ok"
        self.answered.add(source_id)

    # ---- orchestration ------------------------------------------------------------------------
    def execute(self) -> None:
        q = self.q
        pt_tld = (q["domain"].rsplit(".", 1)[-1] in _PT_TLDS)
        self.availability()
        if pt_tld:
            self.arquivo_cdx()  # interleaved: no Internet Archive wait in between (provider pacing)
        self.wayback_cdx()
        homepage_on = bool(self.ctx.setting("web_archives_homepage", True))
        closest = (self.avail or {}).get("closest") or {}
        wayback_host_down = self._unreachable(SRC_CDX)
        if homepage_on and closest.get("raw_snapshot"):
            if wayback_host_down:  # same host as the CDX: do not spend the budget on another reset
                self.sources["wayback_homepage_snapshot"] = "not_run: web.archive.org unreachable (see wayback_cdx)"
            else:
                self.snapshot("wayback", closest["raw_snapshot"], closest.get("captured_at"))
        wayback_down = wayback_host_down or SRC_CDX in self.failures or "wayback_homepage_snapshot" in self.failures_endpoints()
        portuguese = bool(self.homepage and str(self.homepage.get("lang") or "").startswith("pt"))
        if self.arquivo is None and SRC_ARQUIVO not in self.failures and (wayback_down or portuguese or SRC_WAYBACK in self.failures):
            self.arquivo_cdx()
        if homepage_on and self.homepage is None and self.arquivo and self.arquivo["rows"]:
            row = _newest_homepage(self.arquivo["rows"], q)
            if row is not None:
                raw = archive_snapshot_url("arquivo", row["timestamp"], row["_original"])
                if raw:
                    self.snapshot("arquivo", raw, row["captured_at"])
        if self.cdx is None and self.avail_first is None and SRC_WAYBACK not in self.failures:
            self.availability(earliest=True)  # earliest homepage capture when the CDX could not answer

    def _unreachable(self, source_id: str) -> bool:
        out = self.failures.get(source_id) or {}
        return out.get("status") == "could_not_verify" and "unreachable" in str(out.get("reason") or "")

    def failures_endpoints(self) -> set[str]:
        return {k for k, v in self.sources.items() if isinstance(v, str) and not v.startswith(("ok", "empty", "not_run"))}

    # ---- output -------------------------------------------------------------------------------
    def finish(self) -> ModuleResult:
        res, q = self.res, self.q
        rows = list((self.cdx or {}).get("rows") or []) + list((self.arquivo or {}).get("rows") or [])
        stamps = [r["captured_at"] for r in rows if r.get("captured_at")]
        closest = (self.avail or {}).get("closest") or {}
        first_closest = (self.avail_first or {}).get("closest") or {}
        if first_closest.get("captured_at"):
            stamps.append(first_closest["captured_at"])
        if closest.get("captured_at"):
            stamps.append(closest["captured_at"])
        answered = [k for k, v in self.sources.items() if isinstance(v, str) and v.startswith(("ok", "empty"))]
        captured = bool(stamps)
        for source_id, out in self.failures.items():
            if source_id not in self.answered:  # an endpoint of the source answered: per-endpoint detail in archive_sources
                report_failure(res, source_id, out)
        if not answered and not captured:
            reasons = "; ".join(str(f.get("reason")) for f in self.failures.values()) or "no archive answered"
            code = "timeout" if all(f.get("reason_code") == "timeout" for f in self.failures.values()) and self.failures else "error"
            status = "error"
            if self.failures and all(f.get("status") == "rate_limited" for f in self.failures.values()):
                status, code = "rate_limited", "rate_limited"
            res.mark(status, f"could not verify: {reasons}", reason_code=code)
            return res
        if q.get("note"):
            self.sources["query_note"] = q["note"]
        res.attr("archive_sources", self.sources)
        if not captured:
            if self.failures:  # rule 5: some archives did not answer and the others had nothing
                return res.mark("error", "could not verify: no captures in the archives that answered, and "
                                + "; ".join(str(f.get("reason")) for f in self.failures.values()), reason_code="error")
            return res.mark("empty")  # every archive answered and none holds a capture: empty, never 'never archived'
        res.attr("archive_first", min(stamps))
        res.attr("archive_last", max(stamps))
        distinct = sorted({r["url"] for r in rows})
        if rows:
            res.attr("archive_count", len(distinct))
        if closest.get("snapshot_url"):
            res.attr("archive_snapshot", {"url": closest["snapshot_url"], "captured_at": closest.get("captured_at"),
                                          "status": closest.get("status"), "source": "wayback"})
            res.link("Wayback Machine: closest snapshot", closest["snapshot_url"])
        res.link("Wayback Machine: capture calendar", f"https://web.archive.org/web/*/{quote(q['query'], safe=':/')}")
        if self.arquivo and self.arquivo["rows"]:
            res.link("Arquivo.pt: captures", f"https://arquivo.pt/wayback/*/{quote(q['query'], safe=':/')}")
        if distinct:
            res.attr("archived_urls", distinct[:_ATTRIBUTE_URLS])
        if self.homepage:
            res.attr("homepage_indicators", self.homepage)
        self._pivots(rows)
        masked = [r for r in rows if r.get("secret_masked")]
        description = (
            f"First capture {min(stamps)[:10]} (a lower bound of web presence, never a registration date); last capture "
            f"{max(stamps)[:10]}; {len(distinct)} distinct archived URL(s) seen" + (" (partial: cap or truncated answer)" if self.partial else "")
            + ("." if not self.failures else "; some archives could not be verified.")
        )
        res.finding(
            "Web archive history",
            "info",
            description,
            confidence="confirmed",
            data={"archive_first": min(stamps), "archive_last": max(stamps), "archived_urls": len(distinct), "sources": self.sources},
            tags=["info"],
            source=SRC_CDX if self.cdx and self.cdx["rows"] else (SRC_ARQUIVO if self.arquivo and self.arquivo["rows"] else SRC_WAYBACK),
            observed_first=min(stamps),
            observed_last=max(stamps),
        )
        if masked:
            kinds = sorted({k for r in masked for k in r.get("masked") or []} or {"secret"})
            res.finding(
                "Archived URLs carried credentials, tokens or personal identifiers",
                "info",
                f"{len(masked)} archived URL(s) embedded {', '.join(kinds)}; the values were masked before storage and are never "
                "replayed against the site (replaying archived tokens is credential use).",
                confidence="probable",
                data={"count": len(masked), "kinds": kinds},
                tags=["info", "exposure"],
                source=SRC_CDX,
            )
        res.raw = {
            "query": {"kind": q["kind"], "query": redact_archived_url(q["query"])[0], "note": q.get("note") or ""},
            "sources": self.sources,
            "availability": closest or None,
            "availability_first": first_closest or None,
            "rows": [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows[:_EVIDENCE_ROWS]],
            "row_count": len(rows),
            "homepage": self.homepage,
        }
        if self.partial:
            res.stop("request_cap")  # a truncated body or the row cap: partial, never complete
        return res

    def _pivots(self, rows: list[dict[str, Any]]) -> None:
        res, q = self.res, self.q
        cap = max(0, min(100, _int(self.ctx.setting("web_archives_url_pivots", 25), 25)))
        scored = []
        seen: set[str] = set()
        for r in rows:
            url = r["url"]
            if r.get("secret_masked") or url in seen or _BORING_EXT.search(url):
                continue
            seen.add(url)
            score = (2 if _INTERESTING_EXT.search(url) else 0) + (2 if _INTERESTING_PATH.search(url) else 0) + (1 if "?" in url else 0)
            scored.append((-score, url))
        scored.sort()
        for _score, url in scored[:cap]:
            res.pivot(T.URL, url, "archived_url", confidence="probable", expand=False,
                      note="historical URL from a web archive: never requested from the live site")
        if q["kind"] == "domain":
            subs: list[str] = []
            for r in rows:
                host = (_split(r["url"]) or urlsplit("http://x")).hostname or ""
                host = host.lower().strip(".")
                if host and host != q["domain"] and host.endswith("." + q["domain"]) and host not in subs and not host.startswith("www."):
                    subs.append(host)
            for host in subs[:20]:
                res.pivot(T.DOMAIN, host, "subdomain", confidence="probable", expand=False, note="subdomain seen in web-archive captures (may be gone)")
        if self.homepage:
            when = str(self.homepage.get("captured_at") or "")[:10]
            for item in (self.homepage.get("analytics_ids") or [])[:10]:
                res.pivot(T.ANALYTICS_ID, item["id"], "same_analytics", confidence="probable", expand=False,
                          note=f"tracking id on the archived homepage ({when})")
            for cnpj in (self.homepage.get("cnpjs") or [])[:5]:
                res.pivot(T.CNPJ, cnpj, "company_of", confidence="possible", expand=False,
                          note=f"CNPJ printed on the archived homepage ({when}): analyst selection required")


def _newest_homepage(rows: list[dict[str, Any]], q: Mapping[str, Any]) -> dict[str, Any] | None:
    """Newest HTML capture of the homepage (path '/' or the queried URL) among CDX rows."""
    best = None
    for r in rows:
        parts = _split(r.get("_original") or "")
        if parts is None or not parts.hostname:
            continue
        if r.get("statuscode") not in (None, "200") or (r.get("mimetype") and "html" not in str(r.get("mimetype"))):
            continue
        is_home = parts.path in ("", "/") and not parts.query
        if q["kind"] == "url":
            is_home = (r.get("_original") or "").rstrip("/") == str(q["query"]).rstrip("/") or is_home
        if not is_home:
            continue
        if best is None or r["timestamp"] > best["timestamp"]:
            best = r
    return best
