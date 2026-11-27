"""Community profile enrichers (P116 ``community_profiles_pack``): one module per platform.

Each module enriches one **profile URL** of its platform - the ``has_account`` URL pivots that
username_check emits for FOUND sites, or a profile URL the analyst typed (FC3: the gate needs no
inter-module call: ``applies()`` matches the URL's host and path). One GET per URL, the platform's own
found/absent rule, one row per site with identity-raising fields only (FC8). ``default_enabled = False``
for every platform (FC3, legal_dpo, A3).

| module | request | found / absent (FC5) | terms (FC4) / tier (FC9) |
|---|---|---|---|
| ``steam_community_profile`` | ``steamcommunity.com/id/{vanity}/?xml=1``, ``/profiles/{steamid64}/?xml=1`` | always HTTP 200: FOUND iff ``<steamID64>``, ``<error>`` 'could not be found' = ABSENT (safe XML helper) | open / trusted (Valve) |
| ``chesscom_player`` | ``api.chess.com/pub/player/{u}`` | 404 = ABSENT; serial requests only | open / trusted |
| ``lichess_user`` | ``lichess.org/api/user/{u}`` | 404 = ABSENT; one request at a time; 429 = RATE_LIMITED and no Lichess call for 60 s | open / community |
| ``medium_feed`` | ``medium.com/feed/@{u}`` (RSS, safe XML helper) | 404 = ABSENT | open / trusted |
| ``snapchat_profile`` | ``www.snapchat.com/@{u}`` (``__NEXT_DATA__``) | schema check: a layout change is ERROR, never empty; walls BLOCKED | **unknown** (disabled in every profile) / trusted |
| ``disqus_profile`` | ``disqus.com/by/{u}/``; with key ``disqus``: ``disqus.com/api/3.0/users/details.json`` | page 404 'Page not found' = ABSENT; API code 2 = ABSENT, key codes = NEEDS_KEY | **unknown** / trusted |
| ``mojang_profile`` | ``api.mojang.com/users/profiles/minecraft/{u}`` | 404 'Couldn't find any profile' (or 204) = ABSENT | open / trusted (Microsoft) |
| ``pinterest_profile`` | ``widgets.pinterest.com/v3/pidgets/users/{u}/pins/`` | 404 code 30 = ABSENT; failure inside a 200 = ERROR | open / trusted |
| ``stackexchange_user`` | ``api.stackexchange.com/2.3/users/{id}`` or ``users?inname=`` (+ ``/associated`` with key ``stackexchange``) | no item = ABSENT; several exact display-name matches = nothing listed | open / trusted; CC BY-SA attributed |

Twitch Helix joins when the team's own app yields found/absent fixtures (FC1) and Duolingo is **not built**
(FC2: its ``?email=`` variant is an account-enumeration oracle): :func:`lint_pack_specs` over
:data:`PLATFORM_SPECS` (the per-platform declarative table: own status, terms, min_interval, error
markers, found/absent rules) proves no spec accepts e-mail or phone inputs or builds an ``email=`` URL.
These are Python modules rather than compiled P331 specs because the compiler has no placeholder that
extracts a handle from a URL entity (core request in the batch manifest); the table keeps their rules
declarative.

Rules shared by every platform: a challenge, captcha, login wall or geo-block is BLOCKED (P321, never
retried, never bypassed) and emits the profile URL as a manual link (A9); 401/403/429/timeouts/5xx are
"could not verify", never ABSENT; HTML where JSON/XML was expected, error-in-200 bodies, truncated or
malformed answers and handle mismatches are ERROR. Linked accounts and websites the owner declared become
URL pivots with ``expand=False`` (POSSIBLE, PROBABLE only when equal to a login already in the case).
Bios, locations, real names and posts are content: shown only when they mention a case entity or an
organisation brand/domain, otherwise only the withheld field names are recorded (FC8).
SnapIntel (AGPL-3.0) was read for field names only; no code was copied (A6, FC6).
"""

from __future__ import annotations

import html as _html
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, ClassVar
from urllib.parse import parse_qs, quote, unquote, urlsplit

from v3lum.core.entities import Entity, platform_for_url
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, HttpError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.username_social.dev_registries import case_keys

FOUND = "found"
ABSENT = "absent"
AMBIGUOUS = "ambiguous"
BLOCKED = "blocked"
RATE_LIMITED = "rate_limited"
QUOTA = "quota"
NEEDS_KEY = "needs_key"
ERROR = "error"
LAYOUT_CHANGED = "layout changed"
PAGE_CAP = 8 * 1024 * 1024  # read cap of any page handed to a parser
XML_CAP = 2 * 1024 * 1024  # safe XML helper cap (Steam XML, Medium RSS)
SCRIPT_JSON_CAP = 2 * 1024 * 1024  # embedded JSON cap (__NEXT_DATA__, TikTok hydration)
LINK_CAP = 20  # linked URLs kept per profile
LICHESS_COOLDOWN_S = 60  # FC5: after a 429, no Lichess call for 60 s
STACKEXCHANGE_ATTRIBUTION = ("Stack Exchange user data, CC BY-SA 4.0 "
                             "(https://stackoverflow.com/legal/terms-of-service/public#licensing)")

SRC_STEAM = "valve.steam_community_xml"
SRC_CHESSCOM = "chesscom.pubapi_player"
SRC_LICHESS = "lichess.user_api"
SRC_MEDIUM = "medium.user_rss"
SRC_SNAPCHAT = "snap.public_profile_page"
SRC_DISQUS_PAGE = "disqus.profile_page"
SRC_DISQUS_API = "disqus.users_api"
SRC_MOJANG = "mojang.profile_api"
SRC_PINTEREST = "pinterest.widget_pins"
SRC_STACKEXCHANGE = "stackexchange.users_api"

_HTML_START_RE = re.compile(
    r"^\s*(?:<!doctype\s+html|<html\b|<head\b|<body\b|<!--|<meta\b|<title\b|<script\b|<div\b|<noscript\b)", re.I)


# ======================================================================================
# generic helpers (defensive: never raise on hostile input)
# ======================================================================================


def to_text(raw: Any, cap: int | None = None) -> tuple[str, bool]:
    """bytes / str / parsed JSON -> (text, truncated). Bytes decode as UTF-8 with replacement."""
    if raw is None:
        return "", False
    if isinstance(raw, (dict, list)):
        try:
            raw = json.dumps(raw)
        except (TypeError, ValueError):
            return "", False
    if isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
        truncated = cap is not None and len(data) > cap
        return (data[:cap] if truncated else data).decode("utf-8", "replace"), truncated
    if not isinstance(raw, str):
        raw = str(raw)
    truncated = cap is not None and len(raw) > cap
    return (raw[:cap] if truncated else raw), truncated


def looks_like_html(raw: Any) -> bool:
    """True when the body starts like an HTML document (also after a BOM or whitespace)."""
    return bool(_HTML_START_RE.match(to_text(raw, 4096)[0].lstrip("﻿")))


def load_json(raw: Any) -> Any:
    """Parsed JSON (dict/list) or None. Accepts already-parsed values; never raises."""
    if isinstance(raw, (dict, list)):
        return raw
    text = to_text(raw, 64 * 1024 * 1024)[0].strip().lstrip("﻿")
    if not text or text[0] not in "{[":
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def _not_json_reason(raw: Any, what: str) -> str:
    if looks_like_html(raw):
        return f"HTML page instead of {what} (could not verify)"
    if not to_text(raw, 64)[0].strip():
        return f"empty body instead of {what} (could not verify)"
    return f"malformed {what} (could not verify)"


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value == value and abs(value) < 1e18:
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"\s*-?\d{1,19}\s*", value):
        return int(value)
    return None


def _str(value: Any, cap: int = 500) -> str | None:
    if not isinstance(value, str):
        return None
    s = value.strip()
    return s[:cap] if s else None


def _clean(d: dict[str, Any]) -> dict[str, Any]:
    """Drop None / empty values from a flat dict (keeps False and 0)."""
    return {k: v for k, v in d.items() if v is not None and v != "" and v != [] and v != {}}


_MIN_TS, _MAX_TS = 631152000, 4102444800  # 1990-01-01 .. 2100-01-01


def iso_from_epoch(value: Any, ms: bool = False) -> str | None:
    """Epoch seconds (or milliseconds with ms=True) -> 'YYYY-MM-DDTHH:MM:SSZ', None when implausible."""
    n = _int(value)
    if n is None:
        return None
    if ms:
        n //= 1000
    if not _MIN_TS <= n <= _MAX_TS:
        return None
    return datetime.fromtimestamp(n, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_from_text(value: Any) -> str | None:
    """ISO 8601 or RFC 2822 date text -> 'YYYY-MM-DDTHH:MM:SSZ' (naive values are taken as UTC)."""
    s = _str(value, 100)
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith(("Z", "z")) else s)
    except ValueError:
        try:
            dt = parsedate_to_datetime(s)
        except (TypeError, ValueError, IndexError):
            return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        return None


_SCHEMELESS_RE = re.compile(
    r"^(?:www\.)?[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
    r"\.[A-Za-z]{2,24}(?:[/?#]\S*)?$")


def clean_url(value: Any, allow_schemeless: bool = True) -> str | None:
    """http(s) URL or None. Scheme-less 'host.tld/path' gets https://; credentials and odd hosts refused."""
    s = _str(value, 2048)
    if not s:
        return None
    s = s.strip().strip("<>\"'").rstrip(".,;")
    if re.match(r"^https?://", s, re.I):
        url = s
    elif allow_schemeless and _SCHEMELESS_RE.match(s):
        url = "https://" + s
    else:
        return None
    try:
        sp = urlsplit(url)
        host = (sp.hostname or "").lower()
        port = sp.port
    except ValueError:
        return None
    if sp.scheme.lower() not in ("http", "https") or not host or sp.username or sp.password:
        return None
    if port not in (None, 80, 443) or "." not in host or not re.fullmatch(r"[a-z0-9.-]+", host):
        return None
    return url


def url_domain(url: Any) -> str | None:
    """Lower-case host of a URL without a leading 'www.', or None."""
    if not isinstance(url, str):
        return None
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return None
    return (host[4:] if host.startswith("www.") else host) or None


_URL_IN_TEXT_RE = re.compile(
    r"https?://[^\s<>\"'`]{3,2048}|(?<![@\w.-])(?:www\.)?[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}/[^\s<>\"'`]{0,2048}",
    re.I)
_HREF_RE = re.compile(r"""href\s*=\s*(?:"([^"]{1,2048})"|'([^']{1,2048})')""", re.I)


def extract_links(text: Any, cap: int = LINK_CAP, lines: bool = False) -> list[str]:
    """URLs from free text (with or without scheme), de-duplicated, http(s) only. ``lines=True`` treats
    every line as one declared link first (the Lichess 'links' field), then scans the line."""
    s = to_text(text, 65536)[0]
    out: list[str] = []

    def add(u: str) -> None:
        c = clean_url(u)
        if c and c not in out and len(out) < cap:
            out.append(c)

    for line in (s.replace("\r", "\n").split("\n") if lines else [s]):
        line = line.strip()
        if not line:
            continue
        if lines and " " not in line and clean_url(line):
            add(line)
            continue
        for m in _URL_IN_TEXT_RE.finditer(line):
            add(m.group(0))
    return out


def hrefs(html_text: Any, cap: int = 200) -> list[str]:
    """href values of anchors in an HTML fragment (entity-decoded), in order."""
    out: list[str] = []
    for m in _HREF_RE.finditer(to_text(html_text, 1024 * 1024)[0]):
        out.append(_html.unescape(m.group(1) or m.group(2) or "").strip())
        if len(out) >= cap:
            break
    return out


def strip_tags(html_text: Any, cap: int = 5000) -> str:
    s = to_text(html_text, 1024 * 1024)[0]
    s = re.sub(r"<(script|style)\b.{0,200000}?</\1>", " ", s, flags=re.I | re.S)
    s = re.sub(r"<br\s*/?>", "\n", s, flags=re.I)
    s = re.sub(r"<[^>]{0,2000}>", " ", s)
    s = _html.unescape(s)
    return re.sub(r"[ \t\r\f\v]+", " ", s).strip()[:cap]


_TITLE_RE = re.compile(r"<title\b[^>]{0,500}>(.{0,2000}?)</title>", re.I | re.S)


def extract_title(body: Any, cap: int = 262144) -> str | None:
    m = _TITLE_RE.search(to_text(body, cap)[0])
    if not m:
        return None
    return re.sub(r"\s+", " ", _html.unescape(m.group(1))).strip() or None


# P321-style wall markers (second net behind the core classifier). Passive scripts injected into ordinary
# pages (Cloudflare '/cdn-cgi/challenge-platform/scripts/...', reCAPTCHA includes) are NOT markers: Medium's
# normal 404 page carries the precursor script.
_CHALLENGE_MARKERS = (
    ("_cf_chl_opt", "Cloudflare challenge page"),
    ("/cdn-cgi/challenge-platform/h/", "Cloudflare challenge page"),
    ("cf-browser-verification", "Cloudflare browser check"),
    ("vercel security checkpoint", "Vercel security checkpoint"),
    ("tiktok-verify-page", "TikTok verify page"),
    ("captcha_container", "captcha page"),
    ("secsdk-captcha", "TikTok captcha"),
    ("px-captcha", "PerimeterX captcha"),
    ("/_incapsula_resource", "Imperva/Incapsula bot wall"),
    ("pardon our interruption", "bot wall (Imperva/Distil)"),
)
_CHALLENGE_TITLES = (
    ("just a moment", "Cloudflare challenge page"),
    ("attention required! | cloudflare", "Cloudflare block page"),
    ("ddos-guard", "DDoS-Guard check"),
    ("security check", "security check page"),
    ("verify you are human", "human verification page"),
)
_GEO_RE = re.compile(r"not available in your (?:country|region)|unavailable in your (?:country|region)", re.I)


def classify_block(status: Any, headers: Any = None, body: Any = None) -> tuple[str, str] | None:
    """P321/A9 second net: ('challenge'|'geo_block', reason) for wall pages, else None (JSON/XML never)."""
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()} if isinstance(headers, dict) else {}
    if h.get("cf-mitigated", "").strip().lower() == "challenge":
        return "challenge", "Cloudflare managed challenge (cf-mitigated)"
    if _int(status) == 451:
        return "geo_block", "HTTP 451 unavailable for legal reasons"
    text = to_text(body, 262144)[0]
    if not text.strip() or not looks_like_html(text):
        return None
    title = (extract_title(text) or "").lower()
    for marker, reason in _CHALLENGE_TITLES:
        if title.startswith(marker):
            return "challenge", reason
    low = text[:131072].lower()
    for marker, reason in _CHALLENGE_MARKERS:
        if marker in low:
            return "challenge", reason
    if _GEO_RE.search(low):
        return "geo_block", "page says the content is not available in this country"
    return None


def safe_xml_root(raw: Any, cap: int = XML_CAP) -> tuple[ET.Element | None, str | None]:
    """Safe XML helper (P116 FC1): (root Element, None) or (None, reason).

    Refuses DTDs and entity declarations outright (no XXE, no entity expansion), HTML pages and bodies over
    ``cap`` bytes. ElementTree never fetches external resources.
    """
    if isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
        if len(data) > cap:
            return None, f"XML over the {cap}-byte cap"
        text = data.decode("utf-8", "replace")
    else:
        text, truncated = to_text(raw, cap)
        if truncated:
            return None, f"XML over the {cap}-byte cap"
    stripped = text.lstrip("﻿ \t\r\n")
    if not stripped:
        return None, "empty body instead of XML"
    low = stripped[:65536].lower()
    if "<!doctype" in low or "<!entity" in low:
        if looks_like_html(stripped):
            return None, "HTML page instead of XML"
        return None, "XML with a DTD/entity declaration refused (safe XML helper)"
    if looks_like_html(stripped):
        return None, "HTML page instead of XML"
    stripped = re.sub(r"^<\?xml[^>]{0,200}\?>", "", stripped)
    try:
        return ET.fromstring(stripped), None
    except ET.ParseError as exc:
        return None, f"malformed XML ({str(exc)[:80]})"
    except (ValueError, RecursionError):
        return None, "malformed XML"


def extract_script_json(body: Any, script_re: re.Pattern[str], cap: int = SCRIPT_JSON_CAP) -> tuple[Any, str | None]:
    """(data, None) or (None, 'missing'|'unterminated'|'oversize'|'empty'|'malformed').

    Finds the opening tag with ``script_re`` and reads up to the next '</script>'; the element body is capped
    at ``cap`` bytes before any JSON parsing.
    """
    text = to_text(body, PAGE_CAP)[0]
    m = script_re.search(text)
    if not m:
        return None, "missing"
    end = text.find("</script>", m.end())
    if end < 0:
        return None, "unterminated"
    raw = text[m.end():end]
    if len(raw) > cap or len(raw.encode("utf-8", "replace")) > cap:
        return None, "oversize"
    raw = raw.strip()
    if not raw:
        return None, "empty"
    data = load_json(raw)
    if data is None:
        return None, "malformed"
    return data, None


def _result(platform: str, state: str, reason: str | None = None, reason_code: str | None = None, **extra: Any) -> dict[str, Any]:
    res: dict[str, Any] = {"platform": platform, "state": state, "reason": reason, "reason_code": reason_code,
                           "facts": {}, "linked": [], "content": {}}
    res.update(extra)
    res["facts"] = _clean(res.get("facts") or {})
    res["content"] = _clean(res.get("content") or {})
    return res


def _linked(url: str, source: str) -> dict[str, Any]:
    return {"url": url, "source": source}


# ======================================================================================
# platform URLs (FC3 gate) and the declarative per-platform table (FC1/FC2/FC4/FC5)
# ======================================================================================

_HANDLE_RES = {
    "steam": re.compile(r"^[A-Za-z0-9_-]{2,32}$"),
    "steam_id64": re.compile(r"^7656119\d{10}$"),
    "chesscom": re.compile(r"^[A-Za-z0-9_-]{3,25}$"),
    "lichess": re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,29}$"),
    "medium": re.compile(r"^[A-Za-z0-9_.]{1,30}$"),
    "snapchat": re.compile(r"^[A-Za-z][A-Za-z0-9._-]{2,14}$"),
    "disqus": re.compile(r"^[A-Za-z0-9_-]{1,64}$"),
    "mojang": re.compile(r"^[A-Za-z0-9_]{1,16}$"),
    "pinterest": re.compile(r"^[A-Za-z0-9_]{3,30}$"),
    "stackexchange_id": re.compile(r"^-?\d{1,10}$"),
}
_PINTEREST_RESERVED = frozenset({"pin", "search", "ideas", "login", "business", "settings", "today", "about", "_", "explore",
                                 "categories", "topics", "password", "signup", "logout"})

# (platform, host regex, path regex, kind): the has_account URL shapes of username_check FOUND rows (FC3).
_PROFILE_URL_RULES = (
    ("steam", r"(?:www\.)?steamcommunity\.com", r"/id/([A-Za-z0-9_-]{2,32})/?", "username"),
    ("steam", r"(?:www\.)?steamcommunity\.com", r"/profiles/(7656119\d{10})/?", "steam_id64"),
    ("chesscom", r"(?:www\.)?chess\.com", r"/member/([A-Za-z0-9_-]{3,25})/?", "username"),
    ("chesscom", r"api\.chess\.com", r"/pub/player/([A-Za-z0-9_-]{3,25})/?", "username"),
    ("lichess", r"lichess\.org", r"/@/([A-Za-z0-9][A-Za-z0-9_-]{1,29})/?", "username"),
    ("medium", r"medium\.com", r"/@([A-Za-z0-9_.]{1,30})(?:/about)?/?", "username"),
    ("medium", r"medium\.com", r"/feed/@([A-Za-z0-9_.]{1,30})/?", "username"),
    ("snapchat", r"(?:www\.)?snapchat\.com", r"/@([A-Za-z][A-Za-z0-9._-]{2,14})/?", "username"),
    ("snapchat", r"(?:www\.)?snapchat\.com", r"/add/([A-Za-z][A-Za-z0-9._-]{2,14})/?", "username"),
    ("disqus", r"disqus\.com", r"/by/([A-Za-z0-9_-]{1,64})/?", "username"),
    ("mojang", r"api\.mojang\.com", r"/users/profiles/minecraft/([A-Za-z0-9_]{1,16})", "username"),
    ("mojang", r"(?:www\.)?namemc\.com", r"/profile/([A-Za-z0-9_]{1,16})(?:\.\d{1,4})?/?", "username"),
    ("pinterest", r"(?:[a-z]{2}\.|www\.)?pinterest\.com", r"/([A-Za-z0-9_]{3,30})/?", "username"),
    ("stackexchange", r"(?:www\.)?stackoverflow\.com", r"/users/(-?\d{1,10})(?:/[^/?#]{0,100})?/?", "user_id"),
)


def profile_url_to_handle(url: Any) -> dict[str, str] | None:
    """FC3: a has_account profile URL -> {'platform', 'kind', 'handle', 'url'} or None.

    Strict host + path match (http/https only, no credentials). Duolingo URLs give None (FC2: not built);
    the Stack Overflow 'users/filter?search=' search URL gives kind 'display_name'.
    """
    if not isinstance(url, str):
        return None
    try:
        sp = urlsplit(url.strip())
        host = (sp.hostname or "").lower()
        _ = sp.port
    except ValueError:
        return None
    if sp.scheme.lower() not in ("http", "https") or not host or sp.username or sp.password:
        return None
    if host == "duolingo.com" or host.endswith(".duolingo.com"):
        return None
    path = sp.path or "/"
    if host in ("stackoverflow.com", "www.stackoverflow.com") and path.rstrip("/") == "/users/filter":
        q = (parse_qs(sp.query).get("search") or [""])[0].strip()
        if q and len(q) <= 100 and not re.search(r"[\x00-\x1f<>]", q):
            return {"platform": "stackexchange", "kind": "display_name", "handle": q, "url": url}
        return None
    for platform, host_re, path_re, kind in _PROFILE_URL_RULES:
        if not re.fullmatch(host_re, host):
            continue
        m = re.fullmatch(path_re, path)
        if not m:
            continue
        handle = m.group(1)
        if platform == "pinterest" and handle.lower() in _PINTEREST_RESERVED:
            return None
        return {"platform": platform, "kind": kind, "handle": handle, "url": url}
    return None


def platform_request_url(platform: str, handle: Any, kind: str = "username") -> str | None:
    """The one request URL a platform module builds: literal host, validated and URL-encoded handle."""
    if not isinstance(handle, str):
        return None
    h = handle.strip()
    q = quote(h, safe="")
    if platform == "steam":
        if kind == "steam_id64" or _HANDLE_RES["steam_id64"].match(h):
            return f"https://steamcommunity.com/profiles/{h}/?xml=1" if _HANDLE_RES["steam_id64"].match(h) else None
        return f"https://steamcommunity.com/id/{q}/?xml=1" if _HANDLE_RES["steam"].match(h) else None
    if platform == "stackexchange":
        if kind == "user_id":
            return f"https://api.stackexchange.com/2.3/users/{h}?site=stackoverflow" if _HANDLE_RES["stackexchange_id"].match(h) else None
        if kind == "account_id":
            return f"https://api.stackexchange.com/2.3/users/{h}/associated?pagesize=100" if _HANDLE_RES["stackexchange_id"].match(h) else None
        if 0 < len(h) <= 100 and not re.search(r"[\x00-\x1f]", h):
            return f"https://api.stackexchange.com/2.3/users?order=desc&sort=name&inname={q}&site=stackoverflow"
        return None
    rx = _HANDLE_RES.get(platform)
    if rx is None or not rx.match(h):
        return None
    templates = {
        "chesscom": "https://api.chess.com/pub/player/{}",
        "lichess": "https://lichess.org/api/user/{}",
        "medium": "https://medium.com/feed/@{}",
        "snapchat": "https://www.snapchat.com/@{}",
        "disqus": "https://disqus.com/by/{}/",
        "mojang": "https://api.mojang.com/users/profiles/minecraft/{}",
        "pinterest": "https://widgets.pinterest.com/v3/pidgets/users/{}/pins/",
    }
    tpl = templates.get(platform)
    return tpl.format(q.lower() if platform == "chesscom" else q) if tpl else None


def manual_link(platform: str, handle: Any) -> str | None:
    """Human profile URL used as the manual pivot link (A9: emitted with every BLOCKED result)."""
    if not isinstance(handle, str) or not handle.strip():
        return None
    h = quote(handle.strip(), safe="")
    links = {
        "steam": (f"https://steamcommunity.com/profiles/{h}/" if _HANDLE_RES["steam_id64"].match(handle.strip())
                  else f"https://steamcommunity.com/id/{h}/"),
        "chesscom": f"https://www.chess.com/member/{h}",
        "lichess": f"https://lichess.org/@/{h}",
        "medium": f"https://medium.com/@{h}",
        "snapchat": f"https://www.snapchat.com/@{h}",
        "disqus": f"https://disqus.com/by/{h}/",
        "pinterest": f"https://www.pinterest.com/{h}/",
        "stackexchange": (f"https://stackoverflow.com/users/{h}" if _HANDLE_RES["stackexchange_id"].match(handle.strip())
                          else f"https://stackoverflow.com/users/filter?search={h}"),
    }
    return links.get(platform)


#: The P331-style declarative table of the pack (FC1): one entry per platform with its own status, terms,
#: min_interval, error markers and found/absent rules. ``build`` says whether the platform is in this build.
PLATFORM_SPECS: tuple[dict[str, Any], ...] = (
    {"id": "steam", "module": "steam_community_profile", "build": "this_build", "status": "ok", "inputs": ["url", "steam_profile"],
     "hosts": ["steamcommunity.com"], "terms": "open", "tier": "trusted", "min_interval": 2.0,
     "request": {"url": "https://steamcommunity.com/id/{handle}/?xml=1", "method": "GET"},
     "found": "HTTP 200 with <steamID64>", "absent": "HTTP 200 <error> 'The specified profile could not be found.'",
     "error_markers": ["any other <error> inside the 200 (error-in-200)", "HTML or DTD/entity XML (safe XML helper)"]},
    {"id": "chesscom", "module": "chesscom_player", "build": "this_build", "status": "ok", "inputs": ["url"],
     "hosts": ["api.chess.com"], "terms": "open", "tier": "trusted", "min_interval": 1.0,
     "request": {"url": "https://api.chess.com/pub/player/{handle}", "method": "GET"},
     "found": "HTTP 200 player object", "absent": "HTTP 404 PubAPI JSON",
     "error_markers": ["HTML instead of JSON", "handle mismatch"]},
    {"id": "lichess", "module": "lichess_user", "build": "this_build", "status": "ok", "inputs": ["url"],
     "hosts": ["lichess.org"], "terms": "open", "tier": "community", "min_interval": 1.0, "cooldown_after_429_s": LICHESS_COOLDOWN_S,
     "request": {"url": "https://lichess.org/api/user/{handle}", "method": "GET"},
     "found": "HTTP 200 user object", "absent": "HTTP 404 {'error': 'Not found'}",
     "error_markers": ["HTML instead of JSON", "handle mismatch"]},
    {"id": "medium", "module": "medium_feed", "build": "this_build", "status": "ok", "inputs": ["url"],
     "hosts": ["medium.com"], "terms": "open", "tier": "trusted", "min_interval": 2.0,
     "request": {"url": "https://medium.com/feed/@{handle}", "method": "GET"},
     "found": "RSS channel 'Stories by X on Medium' for the handle", "absent": "HTTP 404",
     "error_markers": ["not an RSS channel (layout changed)", "HTML or DTD/entity XML (safe XML helper)"]},
    {"id": "snapchat", "module": "snapchat_profile", "build": "this_build", "status": "disabled_until_legal", "inputs": ["url"],
     "hosts": ["www.snapchat.com"], "terms": "unknown", "tier": "trusted", "min_interval": 5.0,
     "request": {"url": "https://www.snapchat.com/@{handle}", "method": "GET"},
     "found": "__NEXT_DATA__ userProfile $case publicProfileInfo|userInfo with the username",
     "absent": "HTTP 404 with pageMetadata.pageType NOT_FOUND", "error_markers": ["layout changed (schema check)"]},
    {"id": "disqus", "module": "disqus_profile", "build": "this_build", "status": "disabled_until_legal", "inputs": ["url"],
     "hosts": ["disqus.com"], "terms": "unknown", "tier": "trusted", "min_interval": 2.0,
     "request": {"url": "https://disqus.com/by/{handle}/", "method": "GET"},
     "found": "<title>Disqus Profile - {handle}</title>", "absent": "HTTP 404 'Page not found' title; API code 2",
     "error_markers": ["API codes 4/5/9/11/12 = NEEDS_KEY", "API codes 13/14/19 = RATE_LIMITED"]},
    {"id": "mojang", "module": "mojang_profile", "build": "this_build", "status": "ok", "inputs": ["url"],
     "hosts": ["api.mojang.com"], "terms": "open", "tier": "trusted", "min_interval": 1.0,
     "request": {"url": "https://api.mojang.com/users/profiles/minecraft/{handle}", "method": "GET"},
     "found": "HTTP 200 {id, name}", "absent": "HTTP 404 'Couldn't find any profile' or HTTP 204",
     "error_markers": ["HTTP 400 invalid name"]},
    {"id": "pinterest", "module": "pinterest_profile", "build": "this_build", "status": "ok", "inputs": ["url"],
     "hosts": ["widgets.pinterest.com"], "terms": "open", "tier": "trusted", "min_interval": 2.0,
     "request": {"url": "https://widgets.pinterest.com/v3/pidgets/users/{handle}/pins/", "method": "GET"},
     "found": "status 'success' with data.user", "absent": "HTTP 404 code 30 'User not found.'",
     "error_markers": ["failure status inside a 200 (error-in-200)"]},
    {"id": "stackexchange", "module": "stackexchange_user", "build": "this_build", "status": "ok", "inputs": ["url"],
     "hosts": ["api.stackexchange.com"], "terms": "open", "tier": "trusted", "min_interval": 1.0,
     "request": {"url": "https://api.stackexchange.com/2.3/users/{handle}?site=stackoverflow", "method": "GET"},
     "found": "one item (id) or exactly one exact display-name match (inname)", "absent": "no item / no exact match",
     "error_markers": ["error_id 502 throttle_violation = RATE_LIMITED or QUOTA", "error_id 4xx key errors = NEEDS_KEY"]},
    {"id": "twitch", "module": "", "build": "when_fixtures", "status": "backlog", "inputs": ["url"],
     "hosts": ["api.twitch.tv"], "terms": "open", "tier": "trusted", "min_interval": 1.0,
     "request": None,  # Helix users lookup with the team's app token: built once found/absent fixtures exist
     "found": "data[0] with the account", "absent": "data []", "error_markers": ["401 = NEEDS_KEY (team app token only)"]},
)

_FORBIDDEN_INPUTS = frozenset({"email", "e-mail", "phone", "msisdn", "whatsapp", "telephone", "phone_number"})
_FORBIDDEN_PARAM_RE = re.compile(r"(?:^|[?&;])(?:e-?mail|phone|msisdn|tel|telephone)=", re.I)


def lint_pack_specs(specs: Any) -> list[tuple[str, str]]:
    """FC2 lint: [(spec_id, problem)] - empty means clean.

    Flags specs that accept e-mail/phone inputs, build an 'email=' (or phone) URL or parameter, target
    duolingo.com (not built), template the host or use plain http (P331 FC3).
    """
    problems: list[tuple[str, str]] = []
    if not isinstance(specs, (list, tuple)):
        return [("?", "specs is not a list")]
    for spec in specs:
        if not isinstance(spec, dict):
            problems.append(("?", "spec is not an object"))
            continue
        sid = str(spec.get("id") or "?")
        for inp in spec.get("inputs") or ():
            if isinstance(inp, str) and inp.strip().lower() in _FORBIDDEN_INPUTS:
                problems.append((sid, f"accepts {inp.strip().lower()} input (P116 FC2)"))
        req = spec.get("request") if isinstance(spec.get("request"), dict) else {}
        for u in [req.get("url"), *list(spec.get("urls") or [])]:
            if not isinstance(u, str):
                continue
            low = unquote(u).lower()
            if _FORBIDDEN_PARAM_RE.search(low) or "email=" in low:
                problems.append((sid, "builds an 'email=' or phone URL (P116 FC2)"))
            if not low.startswith("https://"):
                problems.append((sid, "request URL is not https (P331 FC3)"))
            host = low.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0]
            if "{" in host or "%" in host:
                problems.append((sid, "templated request host (P331 FC3)"))
            if host == "duolingo.com" or host.endswith(".duolingo.com"):
                problems.append((sid, "Duolingo is not built (P116 FC2)"))
        params = req.get("params") if isinstance(req.get("params"), dict) else {}
        for k in params:
            if isinstance(k, str) and re.search(r"e-?mail|phone|msisdn|^tel$", k, re.I):
                problems.append((sid, f"builds an e-mail/phone parameter '{k}' (P116 FC2)"))
        for h in spec.get("hosts") or ():
            if isinstance(h, str) and (h.lower() == "duolingo.com" or h.lower().endswith(".duolingo.com")):
                problems.append((sid, "Duolingo is not built (P116 FC2)"))
    return problems


# ======================================================================================
# platform parsers: (status, headers, body, handle) -> result dict; walls are raised by the core first
# ======================================================================================

_STEAM_ID64_RE = re.compile(r"^7656119\d{10}$")


def _steam_date(text: Any) -> str | None:
    s = _str(text, 60)
    if not s:
        return None
    s = re.sub(r"\s+", " ", s)
    for fmt in ("%B %d, %Y", "%d %B, %Y", "%B %d %Y", "%d %B %Y", "%b %d, %Y"):
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return None


def _unwrap_redirector(url: str) -> str | None:
    """steamcommunity.com/linkfilter/?u=<target> -> target (Steam wraps external links)."""
    try:
        sp = urlsplit(url)
    except ValueError:
        return None
    if (sp.hostname or "").lower() == "steamcommunity.com" and sp.path.startswith("/linkfilter"):
        q = parse_qs(sp.query)
        return clean_url((q.get("u") or q.get("url") or [None])[0], allow_schemeless=False)
    return clean_url(url, allow_schemeless=False)


def parse_steam_profile_xml(status: Any, headers: Any = None, body: Any = None, handle: Any = None) -> dict[str, Any]:
    """steamcommunity.com /id/{vanity}/?xml=1 or /profiles/{id64}/?xml=1 (FC5: always HTTP 200).

    FOUND iff <steamID64>; <error> 'The specified profile could not be found.' = ABSENT; any other <error>
    (e.g. 'Failed loading profile data') is an error-in-200 = ERROR, never ABSENT.
    """
    st = _int(status)
    if st != 200:
        return _result("steam", ERROR, f"unexpected HTTP {st} (Steam XML is always 200)")
    root, why = safe_xml_root(body)
    if root is None:
        return _result("steam", ERROR, f"{why} (could not verify)")
    if root.tag == "response":
        err = _str(root.findtext("error"), 300)
        if err and "could not be found" in err.lower():
            return _result("steam", ABSENT, "profile not found")
        return _result("steam", ERROR, f"Steam error in 200: {err or 'empty <error>'}")
    if root.tag != "profile":
        return _result("steam", ERROR, f"{LAYOUT_CHANGED}: root element <{root.tag[:40]}>")
    sid = (root.findtext("steamID64") or "").strip()
    if not _STEAM_ID64_RE.match(sid):
        return _result("steam", ERROR, f"{LAYOUT_CHANGED}: no valid <steamID64>")
    if isinstance(handle, str) and _STEAM_ID64_RE.match(handle.strip()) and handle.strip() != sid:
        return _result("steam", ERROR, f"handle mismatch ({sid})")

    def t(tag: str, cap: int = 500) -> str | None:
        return _str(root.findtext(tag), cap)

    summary = root.findtext("summary") or ""
    links: list[str] = []
    for u in hrefs(summary) + extract_links(strip_tags(summary)):
        u2 = _unwrap_redirector(u)
        if u2 and u2 not in links and len(links) < LINK_CAP:
            links.append(u2)
    summary_text = strip_tags(summary, 500)
    facts = {"account_id": sid, "display_name": t("steamID", 200), "custom_url": t("customURL", 64),
             "created": _steam_date(t("memberSince", 60)), "privacy_state": t("privacyState", 30),
             "profile_url": "https://steamcommunity.com/profiles/" + sid}
    content = {"real_name": t("realname", 200), "location": t("location", 200), "headline": t("headline", 300),
               "summary": summary_text if summary_text and summary_text != "No information given." else None}
    return _result("steam", FOUND, facts=facts, content=content, linked=[_linked(u, "summary") for u in links])


def parse_chesscom_player(status: Any, headers: Any = None, body: Any = None, handle: Any = None) -> dict[str, Any]:
    """api.chess.com/pub/player/{u}. 404 PubAPI JSON = ABSENT (FC5); twitch/streaming channels are linked."""
    st = _int(status)
    data = load_json(body)
    if st in (404, 410):
        if isinstance(data, dict):
            return _result("chesscom", ABSENT, "player not found" if st == 404 else "gone")
        return _result("chesscom", ERROR, f"{st} without the PubAPI JSON body (could not verify)")
    if st != 200:
        return _result("chesscom", ERROR, f"unexpected HTTP {st}")
    if not isinstance(data, dict):
        return _result("chesscom", ERROR, _not_json_reason(body, "player JSON"))
    pid = _int(data.get("player_id"))
    user = _str(data.get("username"), 60)
    if pid is None or not user:
        return _result("chesscom", ERROR, f"{LAYOUT_CHANGED}: no player_id/username")
    if isinstance(handle, str) and user.lower() != handle.strip().lower():
        return _result("chesscom", ERROR, f"handle mismatch ({user})")
    country = data.get("country")
    m = re.search(r"/pub/country/([A-Z]{2})/?$", country) if isinstance(country, str) else None
    linked: list[dict[str, Any]] = []
    tw = clean_url(data.get("twitch_url"), False)
    if tw:
        linked.append(_linked(tw, "twitch_url"))
    for sp in data.get("streaming_platforms") or ():
        if isinstance(sp, dict):
            u = clean_url(sp.get("channel_url"), False)
            if u and all(x["url"] != u for x in linked):
                linked.append(_linked(u, "streaming_platforms"))
    facts = {"account_id": pid, "username": user, "display_name": _str(data.get("name"), 200),
             "profile_url": clean_url(data.get("url"), False) or f"https://www.chess.com/member/{user}",
             "created": iso_from_epoch(data.get("joined")), "last_online": iso_from_epoch(data.get("last_online")),
             "status": _str(data.get("status"), 60), "title": _str(data.get("title"), 10),
             "verified": data.get("verified") is True, "is_streamer": data.get("is_streamer") is True,
             "country": m.group(1) if m else None, "followers": _int(data.get("followers"))}
    return _result("chesscom", FOUND, facts=facts, linked=linked[:LINK_CAP], content={"location": _str(data.get("location"), 200)})


def parse_lichess_user(status: Any, headers: Any = None, body: Any = None, handle: Any = None) -> dict[str, Any]:
    """lichess.org/api/user/{u}. 404 = ABSENT (FC5); closed accounts stay FOUND with closed=True."""
    st = _int(status)
    data = load_json(body)
    if st == 404:
        if isinstance(data, dict):
            return _result("lichess", ABSENT, "user not found")
        return _result("lichess", ERROR, "404 without the API JSON body (could not verify)")
    if st != 200:
        return _result("lichess", ERROR, f"unexpected HTTP {st}")
    if not isinstance(data, dict):
        return _result("lichess", ERROR, _not_json_reason(body, "user JSON"))
    uid, user = _str(data.get("id"), 60), _str(data.get("username"), 60)
    if not uid or not user:
        return _result("lichess", ERROR, f"{LAYOUT_CHANGED}: no id/username")
    if isinstance(handle, str) and uid != handle.strip().lower() and user.lower() != handle.strip().lower():
        return _result("lichess", ERROR, f"handle mismatch ({user})")
    prof = data.get("profile") if isinstance(data.get("profile"), dict) else {}
    links = extract_links(prof.get("links"), lines=True) if isinstance(prof.get("links"), str) else []
    names = " ".join(x for x in (_str(prof.get("firstName"), 100), _str(prof.get("lastName"), 100)) if x)
    facts = {"account_id": uid, "username": user, "created": iso_from_epoch(data.get("createdAt"), ms=True),
             "last_activity": iso_from_epoch(data.get("seenAt"), ms=True),
             "profile_url": clean_url(data.get("url"), False) or "https://lichess.org/@/" + user,
             "verified": data.get("verified") is True, "closed": data.get("disabled") is True,
             "tos_violation": data.get("tosViolation") is True, "title": _str(data.get("title"), 10)}
    content = {"bio": _str(prof.get("bio"), 1000), "real_name": _str(prof.get("realName"), 200) or names or None,
               "location": _str(prof.get("location"), 200), "flag": _str(prof.get("flag") or prof.get("country"), 10)}
    return _result("lichess", FOUND, facts=facts, content=content, linked=[_linked(u, "profile.links") for u in links])


_MEDIUM_TITLE_RE = re.compile(r"^Stories by (.{1,200}?) on Medium$")
_MEDIUM_LINK_RE = re.compile(r"^https://medium\.com/@([A-Za-z0-9_.-]{1,60})(?:[/?#]|$)")
_MEDIUM_UID_RE = re.compile(r"[?&]source=rss-([0-9a-f]{6,24})-")
_RSS_CONTENT = "{http://purl.org/rss/1.0/modules/content/}encoded"
MEDIUM_ITEMS_CAP = 20


def parse_medium_feed(status: Any, headers: Any = None, body: Any = None, handle: Any = None) -> dict[str, Any]:
    """medium.com/feed/@{u} (RSS 2.0, safe XML helper). 404 = ABSENT (FC5).

    Facts: display name ('Stories by X on Medium'), username, hex user id (source=rss-<id>-), posts in the
    feed and the newest/oldest post dates. Post titles, categories and outbound link domains are content;
    mailto: links are counted, never extracted.
    """
    st = _int(status)
    if st in (404, 410):
        return _result("medium", ABSENT, "user not found" if st == 404 else "gone (removed or suspended)")
    if st != 200:
        return _result("medium", ERROR, f"unexpected HTTP {st}")
    root, why = safe_xml_root(body)
    if root is None:
        return _result("medium", ERROR, f"{why} (could not verify)")
    ch = root.find("channel") if root.tag == "rss" else None
    if ch is None:
        return _result("medium", ERROR, f"{LAYOUT_CHANGED}: not an RSS channel")
    m = _MEDIUM_TITLE_RE.match((ch.findtext("title") or "").strip())
    link = (ch.findtext("link") or "").strip()
    ml = _MEDIUM_LINK_RE.match(link)
    if not m or not ml:
        return _result("medium", ERROR, f"{LAYOUT_CHANGED}: channel title/link")
    if isinstance(handle, str) and ml.group(1).lower() != handle.strip().lstrip("@").lower():
        return _result("medium", ERROR, f"handle mismatch ({ml.group(1)})")
    uid = _MEDIUM_UID_RE.search(link)
    items = ch.findall("item")
    posts: list[dict[str, Any]] = []
    dates: list[str] = []
    domains: Counter[str] = Counter()
    cats: Counter[str] = Counter()
    mailto = 0
    for it in items[:MEDIUM_ITEMS_CAP]:
        d = iso_from_text(it.findtext("pubDate"))
        if d:
            dates.append(d)
        purl = clean_url(it.findtext("link"), False)
        posts.append(_clean({"title": _str(it.findtext("title"), 300), "url": purl.split("?", 1)[0] if purl else None, "published": d}))
        for c in it.findall("category"):
            cs = _str(c.text, 80)
            if cs:
                cats[cs] += 1
        for href in hrefs(it.findtext(_RSS_CONTENT) or ""):
            if href.lower().startswith("mailto:"):
                mailto += 1
                continue
            dom = url_domain(clean_url(href, False))
            if dom and dom != "medium.com" and not dom.endswith(".medium.com"):
                domains[dom] += 1
    facts = {"display_name": m.group(1).strip(), "username": ml.group(1), "account_id": uid.group(1) if uid else None,
             "profile_url": "https://medium.com/@" + ml.group(1), "posts_in_feed": len(items),
             "last_activity": max(dates) if dates else None, "oldest_post_in_feed": min(dates) if dates else None}
    content = {"posts": posts[:10], "categories": dict(cats.most_common(10)),
               "content_link_domains": dict(domains.most_common(LINK_CAP)), "mailto_links": mailto or None}
    return _result("medium", FOUND, facts=facts, content=content)


_PINTEREST_PROFILE_RE = re.compile(r"^https://(?:[a-z]{2,3}\.|www\.)?pinterest\.[a-z.]{2,10}/([A-Za-z0-9_]{1,30})/?$")


def parse_pinterest_widget(status: Any, headers: Any = None, body: Any = None, handle: Any = None) -> dict[str, Any]:
    """widgets.pinterest.com/v3/pidgets/users/{u}/pins/: 'success' with data.user = FOUND; code 30 = ABSENT;
    any other failure inside a 200 is an error-in-200 = ERROR. Pin link domains are content."""
    st = _int(status)
    data = load_json(body)
    if isinstance(data, dict) and _int(data.get("code")) == 30 and st in (200, 404):
        return _result("pinterest", ABSENT, "user not found")
    if st != 200:
        return _result("pinterest", ERROR, f"unexpected HTTP {st}")
    if not isinstance(data, dict):
        return _result("pinterest", ERROR, _not_json_reason(body, "widget JSON"))
    if data.get("status") != "success":
        return _result("pinterest", ERROR, f"Pinterest error in 200: {_str(data.get('message'), 120) or '?'} (code {data.get('code')})")
    d = data.get("data") if isinstance(data.get("data"), dict) else None
    if d is None:
        return _result("pinterest", ERROR, f"{LAYOUT_CHANGED}: no data object")
    pins = d.get("pins") if isinstance(d.get("pins"), list) else []
    user = d.get("user") if isinstance(d.get("user"), dict) else None
    if user is None and pins and isinstance(pins[0], dict) and isinstance(pins[0].get("pinner"), dict):
        user = pins[0]["pinner"]
    purl = clean_url((user or {}).get("profile_url"), False)
    pm = _PINTEREST_PROFILE_RE.match(purl or "")
    if not user or not pm:
        return _result("pinterest", ERROR, f"{LAYOUT_CHANGED}: no user/profile_url")
    if isinstance(handle, str) and pm.group(1).lower() != handle.strip().lower():
        return _result("pinterest", ERROR, f"handle mismatch ({pm.group(1)})")
    domains: Counter[str] = Counter()
    for p in pins[:100]:
        if not isinstance(p, dict):
            continue
        dom = _str(p.get("domain"), 200) or url_domain(clean_url(p.get("link"), False))
        dom = dom.lower() if dom else None
        if dom and dom.startswith("www."):
            dom = dom[4:]
        if dom and "pinterest." not in dom and dom != "uploaded by user":
            domains[dom] += 1
    about = _str(user.get("about"), 1000)
    facts = {"account_id": _str(str(user.get("id")) if user.get("id") is not None else None, 40),
             "display_name": _html.unescape(_str(user.get("full_name"), 200) or "") or None, "username": pm.group(1),
             "profile_url": purl, "followers": _int(user.get("follower_count")), "pin_count": _int(user.get("pin_count"))}
    content = {"about": _html.unescape(about) if about else None, "pins_seen": len(pins) or None,
               "pin_link_domains": dict(domains.most_common(LINK_CAP))}
    return _result("pinterest", FOUND, facts=facts, content=content)


_NEXT_DATA_RE = re.compile(r"<script\b[^>]{0,500}\bid\s*=\s*[\"']__NEXT_DATA__[\"'][^>]{0,500}>", re.I)


def parse_snapchat_profile(status: Any, headers: Any = None, body: Any = None, handle: Any = None) -> dict[str, Any]:
    """www.snapchat.com/@{u}, parsing <script id="__NEXT_DATA__"> props.pageProps (FC6 schema check).

    FOUND needs userProfile.$case 'publicProfileInfo' or 'userInfo' with a username; ABSENT needs
    pageMetadata.pageType 'NOT_FOUND'; anything else is ERROR 'layout changed', never empty. Snapchat's
    suggestions of other accounts (relatedAccountsInfo) are counted, never linked.
    """
    st = _int(status)
    if st not in (200, 404):
        return _result("snapchat", ERROR, f"unexpected HTTP {st}")
    nd, why = extract_script_json(body, _NEXT_DATA_RE)
    if nd is None:
        blk = classify_block(st, headers, body)
        if blk:
            return _result("snapchat", BLOCKED, blk[1], blk[0])
        return _result("snapchat", ERROR, f"{LAYOUT_CHANGED}: __NEXT_DATA__ {why}")
    props = nd.get("props") if isinstance(nd, dict) and isinstance(nd.get("props"), dict) else None
    pp = props.get("pageProps") if props and isinstance(props.get("pageProps"), dict) else None
    if pp is None:
        return _result("snapchat", ERROR, f"{LAYOUT_CHANGED}: no props.pageProps")
    inner = pp.get("pageProps") if isinstance(pp.get("pageProps"), dict) else {}
    meta = pp.get("pageMetadata") if isinstance(pp.get("pageMetadata"), dict) else inner.get("pageMetadata")
    page_type = meta.get("pageType") if isinstance(meta, dict) else None
    if page_type == "NOT_FOUND":
        return _result("snapchat", ABSENT, "profile not found")
    if st == 404:
        return _result("snapchat", ERROR, f"{LAYOUT_CHANGED}: 404 without pageType NOT_FOUND")
    up = pp.get("userProfile") if isinstance(pp.get("userProfile"), dict) else None
    case = up.get("$case") if up else None
    info = up.get(case) if up and isinstance(case, str) and isinstance(up.get(case), dict) else None
    if case not in ("publicProfileInfo", "userInfo") or info is None:
        return _result("snapchat", ERROR, f"{LAYOUT_CHANGED}: userProfile case {case!r}")
    user = _str(info.get("username"), 60)
    if not user:
        return _result("snapchat", ERROR, f"{LAYOUT_CHANGED}: no username")
    if isinstance(handle, str) and user.lower() != handle.strip().lstrip("@").lower():
        return _result("snapchat", ERROR, f"handle mismatch ({user})")

    def ms(obj: Any) -> str | None:
        return iso_from_epoch(obj.get("value") if isinstance(obj, dict) else obj, ms=True)

    linked: list[dict[str, Any]] = []
    web = clean_url(info.get("websiteUrl"))
    if web:
        linked.append(_linked(web, "websiteUrl"))
    for item in info.get("sameAsLinks") or ():
        raw = item if isinstance(item, str) else (item.get("url") or item.get("link")) if isinstance(item, dict) else None
        u = clean_url(raw)
        if u and all(x["url"] != u for x in linked) and len(linked) < LINK_CAP:
            linked.append(_linked(u, "sameAsLinks"))
    related = info.get("relatedAccountsInfo")
    facts = {"username": user, "display_name": _str(info.get("title") or info.get("displayName"), 200),
             "public_profile": case == "publicProfileInfo", "page_type": page_type,
             "subscriber_count": _int(info.get("subscriberCount")), "badge": _int(info.get("badge")),
             "category": _str(info.get("categoryStringId"), 120), "created": ms(info.get("creationTimestampMs")),
             "last_updated": ms(info.get("lastUpdateTimestampMs")), "account_id": _str(info.get("hostUserId"), 64),
             "business_profile_id": _str(info.get("businessProfileId"), 64), "profile_url": "https://www.snapchat.com/@" + user,
             "related_accounts_counted": len(related) if isinstance(related, list) else None}
    content = {"bio": _str(info.get("bio"), 1000), "address": _str(info.get("address"), 300)}
    return _result("snapchat", FOUND, facts=facts, content=content, linked=linked)


_DISQUS_TITLE_RE = re.compile(r"^Disqus Profile - (.{1,100})$")
_DISQUS_CONFIG_RE = re.compile(r"window\.home_config\s*=\s*JSON\.parse\('((?:[^'\\]|\\.){0,4000})'\)")
_DISQUS_NEEDS_KEY = frozenset({4, 5, 9, 11, 12})
_DISQUS_RATE = frozenset({13, 14, 19})


def _js_unescape(s: str) -> str:
    simple = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}

    def rep(m: re.Match[str]) -> str:
        g = m.group(1)
        if g[0] in "ux" and len(g) > 1:
            return chr(int(g[1:], 16))
        return simple.get(g, g)

    return re.sub(r"\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)", rep, s, flags=re.S)


def parse_disqus_profile_page(status: Any, headers: Any = None, body: Any = None, handle: Any = None) -> dict[str, Any]:
    """disqus.com/by/{u}/: FOUND iff <title>Disqus Profile - {u}</title>; HTTP 404 with Disqus's 'Page not
    found' title = ABSENT. The page carries existence and is_private only (window.home_config)."""
    st = _int(status)
    title = extract_title(body) or ""
    if st == 404:
        if "not found" in title.lower() and "disqus" in title.lower():
            return _result("disqus", ABSENT, "profile not found")
        return _result("disqus", ERROR, "404 without the Disqus not-found page (could not verify)")
    if st != 200:
        return _result("disqus", ERROR, f"unexpected HTTP {st}")
    m = _DISQUS_TITLE_RE.match(title)
    if not m:
        blk = classify_block(st, headers, body)
        if blk:
            return _result("disqus", BLOCKED, blk[1], blk[0])
        return _result("disqus", ERROR, f"{LAYOUT_CHANGED}: profile title")
    user = m.group(1).strip()
    if isinstance(handle, str) and user.lower() != handle.strip().lower():
        return _result("disqus", ERROR, f"handle mismatch ({user})")
    is_private = None
    cm = _DISQUS_CONFIG_RE.search(to_text(body, 1048576)[0])
    if cm:
        cfg = load_json(_js_unescape(cm.group(1)))
        if isinstance(cfg, dict) and isinstance(cfg.get("is_private"), bool):
            is_private = cfg["is_private"]
    facts = {"username": user, "profile_url": f"https://disqus.com/by/{quote(user, safe='')}/", "is_private": is_private}
    return _result("disqus", FOUND, facts=facts)


def parse_disqus_user_details(status: Any, headers: Any = None, body: Any = None, handle: Any = None) -> dict[str, Any]:
    """disqus.com/api/3.0/users/details.json (FC7): code 0 = FOUND; code 2 'does not exist' and code 8 =
    ABSENT; codes 4/5/9/11/12 (missing/invalid key) = NEEDS_KEY, never absent; 13/14/19 = RATE_LIMITED."""
    data = load_json(body)
    if not isinstance(data, dict) or _int(data.get("code")) is None:
        return _result("disqus", ERROR, _not_json_reason(body, "API JSON"))
    code = _int(data.get("code")) or 0
    resp = data.get("response")
    msg = resp if isinstance(resp, str) else ""
    if code == 0 and isinstance(resp, dict):
        uname = _str(resp.get("username"), 64)
        if not uname:
            return _result("disqus", ERROR, f"{LAYOUT_CHANGED}: no username")
        if isinstance(handle, str) and uname.lower() != handle.strip().lower():
            return _result("disqus", ERROR, f"handle mismatch ({uname})")
        web = clean_url(resp.get("url"), False)
        facts = {"account_id": _str(str(resp.get("id")) if resp.get("id") is not None else None, 40), "username": uname,
                 "display_name": _str(resp.get("name"), 200),
                 "profile_url": clean_url(resp.get("profileUrl"), False) or f"https://disqus.com/by/{uname}/",
                 "created": iso_from_text(resp.get("joinedAt")), "is_private": resp.get("isPrivate") is True}
        content = {"about": _str(resp.get("about"), 1000), "location": _str(resp.get("location"), 200)}
        return _result("disqus", FOUND, facts=facts, content=content, linked=[_linked(web, "url")] if web else [])
    if code == 8 or (code == 2 and re.search(r"does not exist|unable to find", msg, re.I)):
        return _result("disqus", ABSENT, "user not found")
    if code in _DISQUS_NEEDS_KEY:
        return _result("disqus", NEEDS_KEY, f"Disqus API key missing or invalid (code {code})", "needs_key")
    if code in _DISQUS_RATE:
        return _result("disqus", RATE_LIMITED, f"Disqus API rate limit (code {code})", "rate_limited")
    return _result("disqus", ERROR, f"Disqus API error code {code}: {msg[:120]}")


def parse_mojang_profile(status: Any, headers: Any = None, body: Any = None, handle: Any = None) -> dict[str, Any]:
    """api.mojang.com/users/profiles/minecraft/{u}: 404 'Couldn't find any profile' (or the legacy 204) = ABSENT;
    400 (invalid name) = ERROR. Facts: the UUID (dashed and hex) and the canonical name."""
    st = _int(status)
    data = load_json(body)
    if st == 204:
        return _result("mojang", ABSENT, "no profile (204, legacy answer)")
    if st == 404:
        msg = _str(data.get("errorMessage"), 200) if isinstance(data, dict) else None
        if msg and "couldn't find any profile" in msg.lower():
            return _result("mojang", ABSENT, "profile not found")
        return _result("mojang", ERROR, "404 without Mojang's not-found message (could not verify)")
    if st == 400:
        return _result("mojang", ERROR, "invalid profile name (HTTP 400)")
    if st != 200:
        return _result("mojang", ERROR, f"unexpected HTTP {st}")
    if not isinstance(data, dict):
        return _result("mojang", ERROR, _not_json_reason(body, "profile JSON"))
    hexid = _str(data.get("id"), 40)
    name = _str(data.get("name"), 32)
    if not hexid or not re.fullmatch(r"[0-9a-fA-F]{32}", hexid) or not name:
        return _result("mojang", ERROR, f"{LAYOUT_CHANGED}: no id/name")
    if isinstance(handle, str) and name.lower() != handle.strip().lower():
        return _result("mojang", ERROR, f"handle mismatch ({name})")
    h = hexid.lower()
    facts = {"uuid": f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}", "account_id": h, "display_name": name,
             "legacy": data.get("legacy") is True or None, "demo": data.get("demo") is True or None}
    return _result("mojang", FOUND, facts=facts)


_SE_ERRORS = {400: (ERROR, "bad parameter"), 401: (NEEDS_KEY, "access token required"), 402: (NEEDS_KEY, "invalid access token"),
              403: (NEEDS_KEY, "access denied"), 404: (ERROR, "no such method"), 405: (NEEDS_KEY, "key required"),
              406: (NEEDS_KEY, "access token compromised"), 409: (ERROR, "duplicate request"), 500: (ERROR, "internal error"),
              502: (RATE_LIMITED, "throttle violation"), 503: (ERROR, "temporarily unavailable")}


def _se_budget(data: dict[str, Any]) -> dict[str, Any]:
    return {"quota_max": _int(data.get("quota_max")), "quota_remaining": _int(data.get("quota_remaining")),
            "backoff_s": _int(data.get("backoff"))}


def stackexchange_error(data: Any) -> dict[str, Any] | None:
    """A Stack Exchange error body {error_id, error_name, error_message} -> result, else None. error_id 502
    throttle_violation = RATE_LIMITED, QUOTA when the advertised wait exceeds one hour (daily quota)."""
    if not isinstance(data, dict) or data.get("error_id") is None:
        return None
    eid = _int(data.get("error_id"))
    msg = _str(data.get("error_message"), 300) or ""
    state, label = _SE_ERRORS.get(eid or 0, (ERROR, f"error {eid}"))
    m = re.search(r"available in (\d{1,9}) seconds", msg)
    wait = int(m.group(1)) if m else None
    if eid == 502 and wait is not None and wait > 3600:
        state = QUOTA
    code = {ERROR: "error", NEEDS_KEY: "needs_key", RATE_LIMITED: "rate_limited", QUOTA: "quota"}[state]
    return _result("stackexchange", state, f"Stack Exchange {label}: {msg[:160]}", code, retry_after_s=wait, budget=_se_budget(data))


def _se_user_facts(it: dict[str, Any]) -> dict[str, Any]:
    return {"account_id": _int(it.get("account_id")), "user_id": _int(it.get("user_id")),
            "display_name": _html.unescape(_str(it.get("display_name"), 200) or "") or None,
            "profile_url": clean_url(it.get("link"), False), "created": iso_from_epoch(it.get("creation_date")),
            "last_activity": iso_from_epoch(it.get("last_access_date")), "reputation": _int(it.get("reputation")),
            "user_type": _str(it.get("user_type"), 30)}


def parse_stackexchange_users(status: Any, headers: Any = None, body: Any = None, handle: Any = None, mode: str = "inname") -> dict[str, Any]:
    """api.stackexchange.com/2.3/users (site=stackoverflow).

    mode 'inname' (display-name search): exactly one exact (case-insensitive) match = FOUND; none = ABSENT;
    several = AMBIGUOUS (display names are not unique: nothing is listed). mode 'ids' (/users/{id}): an item
    = FOUND, none = ABSENT.
    """
    data = load_json(body)
    err = stackexchange_error(data)
    if err is not None:
        return err
    if _int(status) != 200:
        return _result("stackexchange", ERROR, f"unexpected HTTP {_int(status)}")
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        return _result("stackexchange", ERROR, _not_json_reason(body, "API JSON") if not isinstance(data, dict)
                       else f"{LAYOUT_CHANGED}: no items")
    budget = _se_budget(data)
    items = [i for i in data["items"] if isinstance(i, dict)]
    if mode == "inname":
        want = (handle or "").strip().casefold() if isinstance(handle, str) else ""
        if not want:
            return _result("stackexchange", ERROR, "inname mode needs the searched display name", budget=budget)
        exact = [i for i in items if _html.unescape(_str(i.get("display_name"), 200) or "").casefold() == want]
        if not exact:
            return _result("stackexchange", ABSENT, f"no exact display-name match ({len(items)} partial)", budget=budget)
        if len(exact) > 1:
            return _result("stackexchange", AMBIGUOUS, f"{len(exact)} accounts share this display name: nothing listed", budget=budget)
        chosen = exact[0]
    else:
        if not items:
            return _result("stackexchange", ABSENT, "user not found", budget=budget)
        chosen = items[0]
        if isinstance(handle, str) and _int(handle) is not None and _int(chosen.get("user_id")) != _int(handle):
            return _result("stackexchange", ERROR, f"handle mismatch ({chosen.get('user_id')})", budget=budget)
    facts = _se_user_facts(chosen)
    if facts.get("user_id") is None:
        return _result("stackexchange", ERROR, f"{LAYOUT_CHANGED}: no user_id", budget=budget)
    web = clean_url(chosen.get("website_url"), False)
    content = {"location": _html.unescape(_str(chosen.get("location"), 200) or "") or None}
    return _result("stackexchange", FOUND, facts=facts, content=content, budget=budget,
                   linked=[_linked(web, "website_url")] if web else [])


def parse_stackexchange_associated(status: Any, headers: Any = None, body: Any = None) -> dict[str, Any]:
    """/2.3/users/{account_id}/associated: the same person's accounts across Stack Exchange sites (linked,
    expand=False); 'earliest_created' is the oldest site creation date. Empty items = ABSENT."""
    data = load_json(body)
    err = stackexchange_error(data)
    if err is not None:
        return err
    if _int(status) != 200 or not isinstance(data, dict) or not isinstance(data.get("items"), list):
        return _result("stackexchange", ERROR, _not_json_reason(body, "API JSON") if not isinstance(data, dict) else "unexpected answer")
    budget = _se_budget(data)
    items = [i for i in data["items"] if isinstance(i, dict)]
    if not items:
        return _result("stackexchange", ABSENT, "no associated accounts", budget=budget)
    linked: list[dict[str, Any]] = []
    created: list[str] = []
    for it in items[:100]:
        site = clean_url(it.get("site_url"), False)
        uid = _int(it.get("user_id"))
        c = iso_from_epoch(it.get("creation_date"))
        if c:
            created.append(c)
        if site and uid is not None and len(linked) < 50:
            linked.append(_linked(f"{site.rstrip('/')}/users/{uid}", "associated"))
    facts = {"sites": len(items), "earliest_created": min(created) if created else None, "has_more": data.get("has_more") is True}
    return _result("stackexchange", FOUND, facts=facts, linked=linked, budget=budget)


def profile_row(result: dict[str, Any]) -> dict[str, Any]:
    """FC8 'one row per site': site, state, created date, display name, profile URL, linked URLs."""
    facts = result.get("facts") or {}
    return _clean({"site": result.get("platform"), "state": result.get("state"), "created": facts.get("created"),
                   "display_name": facts.get("display_name") or facts.get("username"), "profile_url": facts.get("profile_url"),
                   "linked": [x["url"] for x in result.get("linked") or ()]})


# ======================================================================================
# shared module behaviour
# ======================================================================================

_STATUS_FOR = {ERROR: "error", NEEDS_KEY: "needs_key", RATE_LIMITED: "rate_limited", QUOTA: "quota", BLOCKED: "blocked"}
_TITLES = {"steam": "Steam", "chesscom": "Chess.com", "lichess": "Lichess", "medium": "Medium", "snapchat": "Snapchat",
           "disqus": "Disqus", "mojang": "Minecraft (Mojang)", "pinterest": "Pinterest", "stackexchange": "Stack Overflow"}
_FACT_ATTRS = (("display_name", "display_name"), ("account_id", "account_id"), ("created", "created"),
               ("last_activity", "last_activity"), ("profile_url", "profile_url"), ("verified", "verified"),
               ("followers", "followers"))


def case_terms(ctx: Any, entity: Entity, handle: str = "") -> set[str]:
    """Lower-case values that make profile content relevant to the case (FC8): the other seeds and
    provenance entities, organisation brand terms and own domains. The profile's own handle is excluded."""
    terms: set[str] = set()
    for key in case_keys(ctx, entity):
        if key == entity.key:
            continue
        etype, _, value = key.partition(":")
        if etype == T.SOCIAL_ACCOUNT.value:
            value = value.partition(":")[2]
        elif etype == T.URL.value:
            value = url_domain(value) or ""
        if value and len(value) >= 4:
            terms.add(value.casefold())
    org = getattr(ctx, "org", None)
    try:
        terms |= {t.casefold() for t in (org.brand_terms() if org is not None else []) if isinstance(t, str) and len(t) >= 4}
        for d in getattr(org, "domains", None) or ():
            name = getattr(d, "name", None)
            if isinstance(name, str) and len(name) >= 4:
                terms.add(name.casefold())
    except Exception:  # noqa: BLE001 - a broken organisation profile never stops the run
        pass
    terms.discard(handle.casefold())
    return terms


def relevant_content(content: dict[str, Any], terms: set[str]) -> bool:
    """True when any case term appears in the content (FC8 'only when relevant to the case')."""
    if not content or not terms:
        return False
    text = json.dumps(content, ensure_ascii=False, default=str).casefold()
    return any(t in text for t in terms)


class _CommunityProfile(Module):
    """Shared declarations of the P116 platform modules (abstract: no ``name``, never registered)."""

    category = "username_social"
    accepts = frozenset({T.URL})
    produces = frozenset({T.URL})
    run_on = "any"  # FC3: profile URLs (username_check has_account pivots or analyst-typed URLs)
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    access_model = "free_noauth_limited"
    max_requests = 1
    expected_latency = 0.5
    timeout = 30.0
    cache_ttl = 86400
    max_pivots = 30
    default_enabled = False  # FC3 (legal_dpo, A3); personal_data_review before any default use (FC9)
    platform: ClassVar[str] = ""
    source: ClassVar[str] = ""
    #: statuses whose body the platform parser reads itself (absence pages, error bodies)
    page_statuses: ClassVar[frozenset[int]] = frozenset({404, 410})

    # ------------------------------------------------------------------ gate (FC3)
    def target_of(self, entity: Entity) -> dict[str, str] | None:
        if entity.type is T.URL:
            hit = profile_url_to_handle(entity.value)
            return hit if hit and hit["platform"] == self.platform else None
        return None

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return self.target_of(entity) is not None

    # ------------------------------------------------------------------ HTTP
    def fetch(self, ctx: Any, url: str, *, source: str = "", headers: dict[str, str] | None = None,
              page_statuses: frozenset[int] | None = None) -> Any:
        """GET one URL: classified answers (challenge, rate limit, quota) and statuses outside
        ``page_statuses`` raise like ``ctx.http``; the parser reads the rest (absence pages, error bodies)."""
        kw: dict[str, Any] = {"source": source or self.source}
        if headers:
            kw["headers"] = headers
        resp = ctx.http.get(url, **kw)
        try:
            ctx.http.check(resp)
        except (Blocked, RateLimited, QuotaExceeded):
            raise
        except HttpError:
            if resp.status not in (page_statuses if page_statuses is not None else self.page_statuses):
                raise
        return resp

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        target = self.target_of(entity)
        if target is None:
            return res.mark("skipped", f"not a {_TITLES.get(self.platform, self.platform)} profile URL", reason_code="not_applicable")
        manual = manual_link(self.platform, target["handle"]) or entity.value
        try:
            result = self.lookup(ctx, target, res)
        except Blocked as exc:  # A9: never bypassed; the manual link replaces the automated answer
            res.link(f"{_TITLES.get(self.platform, self.platform)} profile (manual check)", manual)
            return res.mark("blocked", str(exc), reason_code=exc.reason_code)
        if result is None:  # the lookup already marked the result (cooldown, backoff...)
            return res
        return self.emit(res, ctx, entity, target, result, manual)

    def lookup(self, ctx: Any, target: dict[str, str], res: ModuleResult) -> dict[str, Any] | None:
        raise NotImplementedError

    # ------------------------------------------------------------------ output (FC8)
    def emit(self, res: ModuleResult, ctx: Any, entity: Entity, target: dict[str, str], result: dict[str, Any], manual: str) -> ModuleResult:
        title = _TITLES.get(self.platform, self.platform)
        state = result["state"]
        res.raw = {"platform": self.platform, "handle": target["handle"], "state": state, "reason": result.get("reason")}
        if state == ABSENT:
            res.presence("absent", marker=str(result.get("reason") or "documented absence"), url=manual, checked_at=ctx.now(),
                         source=self.source)
            res.error = f"no {title} account for this profile URL"
            return res.mark("empty")
        if state == AMBIGUOUS:
            res.presence("unknown", marker=str(result.get("reason") or "ambiguous"), url=manual, checked_at=ctx.now(), source=self.source)
            res.error = str(result.get("reason") or "ambiguous answer: nothing listed")
            return res.mark("empty")
        if state == BLOCKED:
            res.link(f"{title} profile (manual check)", manual)
            return res.mark("blocked", str(result.get("reason") or "wall page"), reason_code=result.get("reason_code") or "challenge")
        if state != FOUND:
            reason = str(result.get("reason") or "could not verify")
            return res.mark(_STATUS_FOR.get(state, "error"), reason, reason_code=result.get("reason_code") or "")
        facts = result["facts"]
        profile = facts.get("profile_url") or manual
        res.presence("found", marker=f"{title} account object", url=profile, checked_at=ctx.now(), source=self.source)
        for key, attr in _FACT_ATTRS:
            res.attr(attr, facts.get(key))
        res.attr("platform_facts", facts)
        row = profile_row(result)
        res.attr("profile_row", row)
        res.raw["facts"] = facts
        self._linked(res, ctx, entity, profile, result.get("linked") or [])
        content = result.get("content") or {}
        if content:
            if relevant_content(content, case_terms(ctx, entity, target["handle"])):
                res.attr("profile_content", content)
                res.attr("bio", content.get("bio") or content.get("about") or content.get("summary"))
                res.attr("location", content.get("location"))
            else:
                res.attr("content_withheld", sorted(content))
        self.extra(res, ctx, result)
        created = f", created {facts['created'][:10]}" if facts.get("created") else ""
        res.finding(
            f"Account on {title}",
            "info",
            f"{title} account {facts.get('username') or facts.get('display_name') or target['handle']}{created}. The same handle "
            "elsewhere does not prove the same person; profile fields are self-declared.",
            confidence="confirmed",
            criterion=f"{title} answered with the account object for this profile URL",
            data={"row": row},
            tags=["account"],
            references=[profile],
            source=self.source,
        )
        return res

    def _linked(self, res: ModuleResult, ctx: Any, entity: Entity, profile: str, linked: list[dict[str, Any]]) -> None:
        """Declared links and accounts: URL pivots with expand=False (FC8); POSSIBLE unless equal to a login
        already in the case (PROBABLE)."""
        if not linked:
            return
        known: dict[str, set[str]] = {}
        for key in case_keys(ctx, entity):
            etype, _, value = key.partition(":")
            hit = None
            if etype == T.SOCIAL_ACCOUNT.value and ":" in value:
                plat, _, handle = value.partition(":")
                hit = (plat, handle)
            elif etype == T.URL.value:
                hit = platform_for_url(value)
            if hit is not None:
                known.setdefault(hit[0], set()).add(hit[1].lower())
        accounts = []
        for item in linked[:LINK_CAP]:
            url = item["url"]
            hit = platform_for_url(url)
            if hit is not None:
                confidence = "probable" if hit[1].lower() in known.get(hit[0], set()) else "possible"
                accounts.append({"platform": hit[0], "handle": hit[1], "url": url, "source_page": profile})
                res.pivot(T.URL, url, "linked_account_on_profile", confidence=confidence, expand=False,
                          note=f"{hit[0]} account the owner linked on the profile ({item['source']}): self-declared")
            else:
                res.pivot(T.URL, url, "link_on_profile", confidence="possible", expand=False,
                          note=f"link the owner put on the profile ({item['source']}): self-declared, never fetched")
        res.attr("linked_accounts", accounts)

    def extra(self, res: ModuleResult, ctx: Any, result: dict[str, Any]) -> None:
        """Platform-specific additions to a FOUND result (attribution, cross-site accounts...)."""


# ======================================================================================
# the platforms
# ======================================================================================


@register
class SteamCommunityProfile(_CommunityProfile):
    name = "steam_community_profile"
    title = "Steam Community profile"
    description = ("Steam Community profile XML of a Steam profile URL or steam_profile: stable steamID64 (survives renames), "
                   "persona name, member-since date, privacy state and the links of the summary.")
    accepts = frozenset({T.URL, T.STEAM_PROFILE})
    terms = "open"
    provider = "valve"
    sources = (SRC_STEAM,)
    source = SRC_STEAM
    hosts = ("steamcommunity.com",)
    min_interval = 2.0
    expected_latency = 0.6
    reference = "https://steamcommunity.com/dev"
    notice = ("Steam vanity names are first-come: never assume brand ownership. Always HTTP 200: FOUND only with <steamID64>, "
              "ABSENT only with Steam's 'could not be found' error. personal_data_review comes before default use.")
    platform = "steam"
    page_statuses = frozenset()

    def target_of(self, entity: Entity) -> dict[str, str] | None:
        if entity.type is T.STEAM_PROFILE:
            kind, _, ident = entity.value.partition(":")
            return {"platform": "steam", "kind": "steam_id64" if kind == "profiles" else "username", "handle": ident, "url": ""}
        return super().target_of(entity)

    def lookup(self, ctx: Any, target: dict[str, str], res: ModuleResult) -> dict[str, Any] | None:
        url = platform_request_url("steam", target["handle"], target["kind"])
        if not url:
            res.mark("skipped", "not a valid Steam vanity name or SteamID64", reason_code="not_applicable")
            return None
        resp = self.fetch(ctx, url)
        return parse_steam_profile_xml(resp.status, resp.headers, resp.content, target["handle"])


@register
class ChesscomPlayer(_CommunityProfile):
    name = "chesscom_player"
    title = "Chess.com player"
    description = ("Chess.com PubAPI player of a chess.com profile URL: player id, joined and last-online dates, status, title, "
                   "verified/streamer flags and the Twitch/streaming channels the owner linked.")
    terms = "open"
    provider = "chesscom"
    sources = (SRC_CHESSCOM,)
    source = SRC_CHESSCOM
    hosts = ("api.chess.com",)
    min_interval = 1.0
    expected_latency = 0.3
    reference = "https://www.chess.com/news/view/published-data-api"
    notice = "Chess.com PubAPI: serial requests only (parallel requests get 429). personal_data_review comes before default use."
    platform = "chesscom"

    def lookup(self, ctx: Any, target: dict[str, str], res: ModuleResult) -> dict[str, Any] | None:
        url = platform_request_url("chesscom", target["handle"])
        if not url:
            res.mark("skipped", "not a valid Chess.com username", reason_code="not_applicable")
            return None
        resp = self.fetch(ctx, url)
        return parse_chesscom_player(resp.status, resp.headers, resp.content, target["handle"])


@register
class LichessUser(_CommunityProfile):
    name = "lichess_user"
    title = "Lichess user"
    description = ("Lichess user API of a lichess.org profile URL: id, created and last-seen dates, verified/closed/ToS flags, "
                   "title and the links of the profile; after a 429 no Lichess request for 60 s.")
    terms = "open"
    provider = "lichess"
    sources = (SRC_LICHESS,)
    source = SRC_LICHESS
    hosts = ("lichess.org",)
    min_interval = 1.0
    expected_latency = 0.3
    reference = "https://lichess.org/api"
    notice = "Lichess API: one request at a time; after a 429 no Lichess request for 60 s (documented). Community tier."
    platform = "lichess"

    def lookup(self, ctx: Any, target: dict[str, str], res: ModuleResult) -> dict[str, Any] | None:
        url = platform_request_url("lichess", target["handle"])
        if not url:
            res.mark("skipped", "not a valid Lichess username", reason_code="not_applicable")
            return None
        now = ctx.now().timestamp()
        until = ctx.state.get("cooldown_until")
        if isinstance(until, (int, float)) and now < until:  # FC5: no Lichess call for 60 s after a 429
            res.mark("rate_limited", f"Lichess cooldown after a 429: {int(until - now)} s left, nothing sent")
            return None
        sent = getattr(ctx.http, "requests", 0)
        try:
            resp = self.fetch(ctx, url)
        except RateLimited as exc:
            if getattr(ctx.http, "requests", 0) > sent:  # Lichess itself answered 429
                ctx.state.set("cooldown_until", now + LICHESS_COOLDOWN_S)
                res.mark("rate_limited", "Lichess 429: no Lichess request for 60 s")
            else:  # the core's backoff refused the call before sending
                res.mark("rate_limited", str(exc))
            return None
        return parse_lichess_user(resp.status, resp.headers, resp.content, target["handle"])


@register
class MediumFeed(_CommunityProfile):
    name = "medium_feed"
    title = "Medium user feed"
    description = ("Medium RSS feed of a medium.com/@user URL: display name, user id, posts in the feed and the newest/oldest "
                   "post dates; post titles and outbound link domains only when relevant to the case.")
    terms = "open"
    provider = "medium"
    sources = (SRC_MEDIUM,)
    source = SRC_MEDIUM
    hosts = ("medium.com",)
    min_interval = 2.0
    expected_latency = 0.3
    reference = "https://help.medium.com/hc/en-us/articles/214874118-Using-RSS-feeds-of-profiles-publications-and-topics"
    notice = ("Medium profile pages may be served a Cloudflare managed challenge: BLOCKED (never retried with another user "
              "agent), use the manual link. personal_data_review comes before default use.")
    platform = "medium"

    def lookup(self, ctx: Any, target: dict[str, str], res: ModuleResult) -> dict[str, Any] | None:
        url = platform_request_url("medium", target["handle"])
        if not url:
            res.mark("skipped", "not a valid Medium username", reason_code="not_applicable")
            return None
        resp = self.fetch(ctx, url)
        return parse_medium_feed(resp.status, resp.headers, resp.content, target["handle"])


@register
class SnapchatProfile(_CommunityProfile):
    name = "snapchat_profile"
    title = "Snapchat public profile"
    description = ("Snapchat public profile page of a snapchat.com/@user URL (Next.js data, schema-checked): username, display "
                   "name, creation/update dates, subscriber count and declared website/links.")
    terms = "unknown"  # FC4: disabled in every profile until legal records the terms
    provider = "snap"
    sources = (SRC_SNAPCHAT,)
    source = SRC_SNAPCHAT
    hosts = ("www.snapchat.com",)
    min_interval = 5.0
    expected_latency = 0.8
    reference = "https://snap.com/en-US/terms"
    notice = ("Scrape of the public profile page: terms 'unknown', disabled in every licence profile until legal records them "
              "(P116 FC4). A layout change is ERROR, never empty; challenge pages are BLOCKED and never bypassed. SnapIntel "
              "(AGPL-3.0) was used for ideas only.")
    platform = "snapchat"

    def lookup(self, ctx: Any, target: dict[str, str], res: ModuleResult) -> dict[str, Any] | None:
        url = platform_request_url("snapchat", target["handle"])
        if not url:
            res.mark("skipped", "not a valid Snapchat username", reason_code="not_applicable")
            return None
        resp = self.fetch(ctx, url)
        return parse_snapchat_profile(resp.status, resp.headers, resp.content, target["handle"])


@register
class DisqusProfile(_CommunityProfile):
    name = "disqus_profile"
    title = "Disqus profile"
    description = ("Disqus profile of a disqus.com/by/user URL: existence and privacy flag from the profile page, or with the "
                   "team's public API key (disqus) the users/details record (id, name, joined date, declared website).")
    terms = "unknown"  # FC4: disabled in every profile until legal records the terms
    provider = "disqus"
    sources = (SRC_DISQUS_PAGE, SRC_DISQUS_API)
    source = SRC_DISQUS_PAGE
    hosts = ("disqus.com",)
    optional_keys = ("disqus",)
    min_interval = 2.0
    expected_latency = 0.3
    reference = "https://disqus.com/api/docs/users/details/"
    notice = ("Profile page and API terms 'unknown': disabled in every licence profile until legal records them (P116 FC4). "
              "A missing or invalid API key is NEEDS_KEY, never absent (FC7).")
    platform = "disqus"
    page_statuses = frozenset({400, 404, 410})

    def lookup(self, ctx: Any, target: dict[str, str], res: ModuleResult) -> dict[str, Any] | None:
        handle = target["handle"]
        if not _HANDLE_RES["disqus"].match(handle):
            res.mark("skipped", "not a valid Disqus username", reason_code="not_applicable")
            return None
        key = ctx.key("disqus")
        if key:
            url = f"https://disqus.com/api/3.0/users/details.json?user=username:{quote(handle, safe='')}&api_key={quote(key, safe='')}"
            try:
                resp = self.fetch(ctx, url, source=SRC_DISQUS_API)
            except AuthRequired as exc:  # 401/403 with a Disqus key error code: NEEDS_KEY, never absent (FC7)
                parsed = parse_disqus_user_details(exc.status, None, exc.body, handle)
                if parsed["state"] in (NEEDS_KEY, RATE_LIMITED, ERROR):
                    return parsed if parsed["state"] != ERROR else _result("disqus", NEEDS_KEY, f"Disqus API refused the key: {exc}", "needs_key")
                raise
            return parse_disqus_user_details(resp.status, resp.headers, resp.content, handle)
        url = platform_request_url("disqus", handle) or ""
        resp = self.fetch(ctx, url, page_statuses=frozenset({404, 410}))
        return parse_disqus_profile_page(resp.status, resp.headers, resp.content, handle)


@register
class MojangProfile(_CommunityProfile):
    name = "mojang_profile"
    title = "Minecraft (Mojang) profile"
    description = ("Mojang profile API of a Minecraft name (api.mojang.com or namemc.com profile URL): the account UUID and "
                   "canonical name; the name history API no longer exists.")
    terms = "open"
    provider = "mojang"
    sources = (SRC_MOJANG,)
    source = SRC_MOJANG
    hosts = ("api.mojang.com",)
    min_interval = 1.0
    expected_latency = 0.3
    reference = "https://minecraft.wiki/w/Mojang_API"
    notice = "About 600 requests per 10 minutes (community-reported). NameMC (Cloudflare-gated) is a manual source only."
    platform = "mojang"
    page_statuses = frozenset({400, 404})

    def lookup(self, ctx: Any, target: dict[str, str], res: ModuleResult) -> dict[str, Any] | None:
        url = platform_request_url("mojang", target["handle"])
        if not url:
            res.mark("skipped", "not a valid Minecraft name", reason_code="not_applicable")
            return None
        resp = self.fetch(ctx, url)
        return parse_mojang_profile(resp.status, resp.headers, resp.content, target["handle"])


@register
class PinterestProfile(_CommunityProfile):
    name = "pinterest_profile"
    title = "Pinterest profile"
    description = ("Pinterest public widget API of a pinterest.com/user URL: user id, display name, follower and pin counts; "
                   "the 'about' text and pin link domains (brand-abuse shops) only when relevant to the case.")
    terms = "open"
    provider = "pinterest"
    sources = (SRC_PINTEREST,)
    source = SRC_PINTEREST
    hosts = ("widgets.pinterest.com",)
    min_interval = 2.0
    expected_latency = 0.5
    reference = "https://developers.pinterest.com/docs/web-features/add-ons-overview/"
    notice = "Public widget API (no key). A failure status inside an HTTP 200 is ERROR, never absent."
    platform = "pinterest"

    def lookup(self, ctx: Any, target: dict[str, str], res: ModuleResult) -> dict[str, Any] | None:
        url = platform_request_url("pinterest", target["handle"])
        if not url:
            res.mark("skipped", "not a valid Pinterest username", reason_code="not_applicable")
            return None
        resp = self.fetch(ctx, url)
        return parse_pinterest_widget(resp.status, resp.headers, resp.content, target["handle"])


@register
class StackexchangeUser(_CommunityProfile):
    name = "stackexchange_user"
    title = "Stack Overflow user"
    description = ("Stack Exchange API user of a stackoverflow.com/users URL (or a users/filter search URL: exact display-name "
                   "match only): account id across sites, creation and last-access dates, reputation; with the key "
                   "(stackexchange) also the same account on every Stack Exchange site. CC BY-SA attributed.")
    terms = "open"
    provider = "stackexchange"
    sources = (SRC_STACKEXCHANGE,)
    source = SRC_STACKEXCHANGE
    hosts = ("api.stackexchange.com",)
    optional_keys = ("stackexchange",)
    max_requests = 2  # users (+ /associated with the key)
    min_interval = 1.0
    expected_latency = 0.5
    reference = "https://api.stackexchange.com/docs/users"
    notice = ("Keyless quota 300 requests/day per IP (shared egress): configure the free key before regular use. The 'backoff' "
              "field is honoured. Display names are not unique: several exact matches list nothing. Content is CC BY-SA 4.0.")
    platform = "stackexchange"
    page_statuses = frozenset({400, 401, 402, 403, 404, 405, 406, 409, 502, 503})

    def _get(self, ctx: Any, url: str) -> Any:
        try:
            return self.fetch(ctx, url)
        except AuthRequired as exc:  # key errors arrive as 401/403 with an error_id body
            parsed = stackexchange_error(load_json(exc.body))
            if parsed is not None:
                return parsed
            raise

    def lookup(self, ctx: Any, target: dict[str, str], res: ModuleResult) -> dict[str, Any] | None:
        kind = "user_id" if target["kind"] == "user_id" else "display_name"
        url = platform_request_url("stackexchange", target["handle"], kind)
        if not url:
            res.mark("skipped", "not a valid Stack Overflow user id or search", reason_code="not_applicable")
            return None
        now = ctx.now().timestamp()
        until = ctx.state.get("backoff_until")
        if isinstance(until, (int, float)) and now < until:  # Stack Exchange 'backoff': honoured before the next call
            res.mark("rate_limited", f"Stack Exchange backoff: {int(until - now)} s left, nothing sent")
            return None
        key = ctx.key("stackexchange")
        if key:
            url += f"&key={quote(key, safe='')}"
        got = self._get(ctx, url)
        if isinstance(got, dict):
            return got
        parsed = parse_stackexchange_users(got.status, got.headers, got.content, target["handle"],
                                           mode="ids" if kind == "user_id" else "inname")
        self._note_budget(ctx, parsed.get("budget"))
        if parsed["state"] == FOUND and key and parsed["facts"].get("account_id") is not None:
            assoc_url = platform_request_url("stackexchange", str(parsed["facts"]["account_id"]), "account_id")
            if assoc_url:
                try:
                    a = self._get(ctx, assoc_url + f"&key={quote(key, safe='')}")
                except (HttpError, RateLimited, QuotaExceeded) as exc:
                    parsed["associated_error"] = str(exc)[:200]
                else:
                    assoc = a if isinstance(a, dict) else parse_stackexchange_associated(a.status, a.headers, a.content)
                    if assoc["state"] == FOUND:
                        parsed["linked"] = list(parsed["linked"]) + list(assoc["linked"])
                        parsed["associated"] = assoc["facts"]
                    elif assoc["state"] != ABSENT:
                        parsed["associated_error"] = str(assoc.get("reason") or "")[:200]
        return parsed

    def _note_budget(self, ctx: Any, budget: Any) -> None:
        if isinstance(budget, dict) and budget.get("backoff_s"):
            ctx.state.set("backoff_until", ctx.now().timestamp() + min(int(budget["backoff_s"]), 86400))

    def extra(self, res: ModuleResult, ctx: Any, result: dict[str, Any]) -> None:
        res.attr("data_attribution", STACKEXCHANGE_ATTRIBUTION)  # FC8: Stack Exchange content is CC BY-SA
        if result.get("associated"):
            res.attr("platform_facts", {**result["facts"], "associated": result["associated"]})
        if result.get("associated_error"):
            res.source_status(SRC_STACKEXCHANGE, "error", reason=f"associated accounts: {result['associated_error']}")
