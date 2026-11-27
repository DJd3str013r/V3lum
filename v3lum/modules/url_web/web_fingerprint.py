"""Web fingerprint (P072, batch p9-G03-2): one matcher library, two modules.

* ``web_fingerprint_archive`` (PASSIVE, default): runs the matchers over the closest archived homepage
  snapshot (Wayback ``id_`` raw body + ``x-archive-orig-*`` headers, the P059 web_archives client
  helpers); no target contact.
* ``web_fingerprint`` (LIGHT, opt-in, default_enabled False): one homepage GET through the shared
  safe-fetch helper (``light_fetch.fetch_homepage`` over ``ctx.http``: LIGHT egress profile, setting
  ``ua_light``, analyst-typed seeds only, redirects followed by hand - at most 5 hops, each hop
  re-checked before it is sent (seed binding, same site, ports, per-recipient token URLs) and by the
  core SSRF guard after resolution; private, loopback, link-local, CGNAT and metadata addresses
  refused; 25 requests per target host per scan).

Final conditions (P072) and where they live:

1. two modules over one library: :func:`fingerprint_page` (headers, body, URL, DNS -> verdict,
   technologies, WAF/CDN, own-rule hits, CVE summaries) serves both modules.
2. the LIGHT GET uses the shared safe-fetch helper ``light_fetch.fetch_homepage`` (the one
   security_headers, js_endpoints and favicon_fetch use: same URL, no Accept header, same 1 MB cap and
   TTL, one cache row per hop, so the page another LIGHT module of the scan fetched is a cache hit and
   a cached redirect is followed, never read as the homepage). P376 guard and P334 budget are core.
   No socket, subprocess or client of its own.
3. the UA is the core's ``ua_light``; a challenge or block page gives BLOCKED 'challenge' and is
   never retried with another UA or a headless browser (no retry at all in this module).
4. technology data: enthec/webappanalyzer JSON (GPL-3.0 DATA) registered as runtime datasets
   (``webappanalyzer.*``), downloaded into ~/.v3lum/datasets, never bundled (notice
   v3lum/data/notices/webappanalyzer.json). Tests use a hand-written file in the same format. The
   own MIT phishing-kit/panel rules live apart in v3lum/data/web_fingerprint/own_rules.json.
5. matchers: headers, cookies, meta, html, scriptSrc, url, dns (``ctx.dns``) and certIssuer (fed
   only when an issuer is handed in: no new socket); js/dom/probe/xhr/... keys are never evaluated.
   JS regexes go through :func:`js_regex_to_python` (failures skipped and counted), HTML is scanned
   up to 500 KB, every HTML pattern passes a scaling time-budget screen when the data is loaded
   (:func:`budget_screen`) and a per-page budget at match time (slow patterns are remembered in
   ``ctx.state`` and skipped on later runs).
6. passive WAF/CDN: the header/cookie-only subset of the wafw00f signatures (BSD-3,
   v3lum/data/web_fingerprint/wafw00f_passive.json, notice wafw00f_passive_signatures) plus CNAME
   suffix attribution; no attack-payload probe exists here.
7. corporate secure-web-gateway pages (Zscaler, Netskope, Fortinet, Palo Alto... configurable with
   setting ``web_fingerprint_proxy_signatures``) read 'blocked by corporate proxy' (BLOCKED) and are
   never fingerprinted; 4xx/5xx and proxy error bodies are inconclusive (headers only).
8. one compact technology list; version-inferred CVEs (RetireJS repository, local copy or bundled
   snapshot; CISA KEV local copy) collapse into one finding per technology ('jQuery 1.12.4: 4 CVEs,
   max severity medium'), POSSIBLE, at most MEDIUM unless KEV (then at most HIGH, tag kev). Hostile
   pages (own phishing-kit rule hit) and archived snapshots get them as an attribute instead.
9. fixtures: trimmed real homepages (tests/fixtures/web_fingerprint/), a challenge page and
   corporate-proxy block pages (synthetic shapes, see the fixture notes).
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import time
import urllib.parse
import warnings
from collections.abc import Iterable, Mapping
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core import psl
from v3lum.core.datasets import DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import DeadlineExceeded, NetworkError, OfflineError
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, HealthResult, Module, register
from v3lum.modules.url_web.light_fetch import HOMEPAGE_MAX_BYTES, HOMEPAGE_TTL, fetch_homepage, safe_get

# ============================================================================================ constants
WA_SOURCE = "github.web_fingerprint_webappanalyzer"
WA_BASE = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src"
WA_ATTRIBUTION = "Technology fingerprints: enthec/webappanalyzer (https://github.com/enthec/webappanalyzer), GPL-3.0 data, runtime download"
WA_LETTERS = "_abcdefghijklmnopqrstuvwxyz"
WA_CATEGORIES = "webappanalyzer.categories"
RETIRE_SOURCE = "github.retirejs_check_jsrepository"
KEV_SOURCE = "cisa.kev"  # the local CISA KEV copy read by version_cves (dataset cisa_kev, never downloaded here)
SRC_WAYBACK = "internet_archive.wayback"
WAYBACK_AVAILABLE = "https://archive.org/wayback/available"
BUNDLED_WAF = "web_fingerprint/wafw00f_passive.json"
BUNDLED_RULES = "web_fingerprint/own_rules.json"

MAX_HTML_BYTES = 500_000  # FC5: scan at most the first 500 KB of HTML
FETCH_MAX_BYTES = HOMEPAGE_MAX_BYTES  # 1 MB: the shared homepage fetch of light_fetch (same cache key in every LIGHT module)
MAX_SCRIPT_SRC_CHARS = 1024
MAX_HEADER_VALUE_CHARS = 8192
MAX_SCRIPTS = 200
SLOW_PATTERN_MS = 250.0  # one HTML pattern slower than this on a page is skipped from then on
SCREEN_LIMIT_MS = 100.0  # extrapolated cost of one HTML pattern on 500 KB (FC5 time budget)
CVE_PIVOT_CAP = 20


def _wa_name(letter: str) -> str:
    return f"webappanalyzer.technologies_{'other' if letter == '_' else letter}"


WA_TECH_DATASETS = tuple(_wa_name(c) for c in WA_LETTERS)


def _validate_technologies(path: Path) -> bool:
    """register_dataset(validate=): a JSON object whose values are technology objects."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(doc, dict) and all(isinstance(v, dict) for v in list(doc.values())[:50])


def _validate_categories(path: Path) -> bool:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(doc, dict) and len(doc) >= 10 and all(isinstance(v, dict) for v in doc.values())


for _letter in WA_LETTERS:
    register_dataset(
        _wa_name(_letter),
        f"{WA_BASE}/technologies/{_letter}.json",
        ttl=7 * 86400,
        description=f"webappanalyzer technology fingerprints, file technologies/{_letter}.json (Wappalyzer format, P072)",
        licence="GPL-3.0-only",
        terms_class="open",
        attribution=WA_ATTRIBUTION,
        provider="github",
        source=WA_SOURCE,
        validate=_validate_technologies,
        min_bytes=2,
        expect="json",
        max_bytes=2 * 1024 * 1024,
        large=False,
    )
register_dataset(
    WA_CATEGORIES,
    f"{WA_BASE}/categories.json",
    ttl=7 * 86400,
    description="webappanalyzer technology categories (ids, names, priorities; P072)",
    licence="GPL-3.0-only",
    terms_class="open",
    attribution=WA_ATTRIBUTION,
    provider="github",
    source=WA_SOURCE,
    validate=_validate_categories,
    min_bytes=500,
    expect="json",
    max_bytes=512 * 1024,
    large=False,
)

# ============================================================================================ text helpers
_BOM = "\ufeff"


def _as_text(raw: Any, limit: int | None = None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray, memoryview)):
        b = bytes(raw)[:limit] if limit is not None else bytes(raw)
        try:
            return b.decode("utf-8").lstrip(_BOM)
        except UnicodeDecodeError:
            return b.decode("cp1252", errors="replace").lstrip(_BOM)
    if isinstance(raw, str):
        return (raw[:limit] if limit is not None else raw).lstrip(_BOM)
    return ""


def clean(value: Any, limit: int = 200) -> str:
    """Untrusted value -> one printable line, capped."""
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", " ", re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)).strip()[:limit]


def looks_html(text: str) -> bool:
    head = text[:512].lstrip().lower()
    return head.startswith(("<!doctype html", "<html", "<?xml", "<!--")) or "<head" in head or "<body" in head


def load_json(raw: Any) -> tuple[Any, str | None]:
    """Defensive JSON -> (obj, error); error in None | 'empty' | 'html_instead_of_json' | 'malformed'."""
    if isinstance(raw, (dict, list)):
        return raw, None
    text = _as_text(raw).strip()
    if not text:
        return None, "empty"
    if text[0] == "<":
        return None, "html_instead_of_json"
    try:
        return json.loads(text), None
    except (ValueError, RecursionError):
        return None, "malformed"


def decode_body(body: Any, content_type: Any = None) -> str:
    """HTML bytes -> str: charset from Content-Type, then <meta charset>, then UTF-8, then cp1252."""
    if isinstance(body, str):
        return body.lstrip(_BOM)
    if not isinstance(body, (bytes, bytearray, memoryview)):
        return ""
    b = bytes(body)
    cs = None
    if content_type:
        m = re.search(r"charset\s*=\s*[\"']?([\w.:-]+)", str(content_type), re.I)
        cs = m.group(1) if m else None
    if not cs:
        m = re.search(rb"<meta[^>]{0,200}charset\s*=\s*[\"']?([\w.:-]+)", b[:4096], re.I)
        cs = m.group(1).decode("ascii", "ignore") if m else None
    if cs:
        try:
            return b.decode(cs, errors="replace").lstrip(_BOM)
        except LookupError:
            pass
    try:
        return b.decode("utf-8").lstrip(_BOM)
    except UnicodeDecodeError:
        return b.decode("cp1252", errors="replace").lstrip(_BOM)


# ============================================================================================ headers
def normalise_headers(headers: Any) -> dict[str, list[str]]:
    """Headers (dict, list of pairs or a raw block) -> {lower-name: [values]}."""
    out: dict[str, list[str]] = {}

    def add(n: Any, v: Any) -> None:
        name = str(n or "").strip().lower()
        if not name:
            return
        if isinstance(v, (list, tuple)):
            for x in v:
                add(name, x)
            return
        out.setdefault(name, []).append("" if v is None else str(v).strip())

    if isinstance(headers, Mapping):
        for k, v in headers.items():
            add(k, v)
    elif isinstance(headers, (list, tuple)):
        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                add(item[0], item[1])
    elif isinstance(headers, (str, bytes, bytearray)):
        text = _as_text(headers).replace("\r\n", "\n")
        blocks = [b for b in re.split(r"\n\s*\n", text) if b.strip()]
        for line in (blocks[-1] if blocks else "").split("\n"):
            if ":" in line and not line.upper().startswith("HTTP/"):
                n, v = line.split(":", 1)
                add(n, v)
    return out


def _norm(headers: Any) -> dict[str, list[str]]:
    if isinstance(headers, dict) and all(isinstance(v, list) for v in headers.values()) and all(k == k.lower() for k in headers):
        return headers
    return normalise_headers(headers or {})


def header_first(headers: Any, name: str, default: str | None = None) -> str | None:
    vals = _norm(headers).get(name.lower())
    return vals[0] if vals else default


ARCHIVE_ORIG_PREFIX = "x-archive-orig-"


def archive_original_headers(headers: Any) -> dict[str, Any]:
    """Wayback/pywb ``id_`` snapshot headers -> the ORIGINAL site's headers (FC1): only
    ``x-archive-orig-*`` headers are kept (prefix removed); the archive's own Server/Via/HSTS are
    never attributed to the target. Returns {headers, memento_datetime, dropped}."""
    h = normalise_headers(headers)
    orig: dict[str, list[str]] = {}
    dropped = 0
    for k, vals in h.items():
        if k.startswith(ARCHIVE_ORIG_PREFIX) and len(k) > len(ARCHIVE_ORIG_PREFIX):
            orig.setdefault(k[len(ARCHIVE_ORIG_PREFIX):], []).extend(vals)
        else:
            dropped += 1
    md = (h.get("memento-datetime") or [None])[0]
    return {"headers": orig, "memento_datetime": md, "dropped": dropped}


_COOKIE_SPLIT = re.compile(r",\s*(?=[^;,=\s]{1,128}=)")


def cookie_values(headers: Any) -> list[str]:
    """Set-Cookie header values, splitting values a client joined with ', '."""
    out: list[str] = []
    for v in _norm(headers).get("set-cookie", []):
        out.extend(p for p in _COOKIE_SPLIT.split(v) if p.strip())
    return out


def cookie_jar(headers: Any) -> dict[str, str]:
    """Set-Cookie -> {name: value}: values only for in-memory matching, never output (FC8, AR20 e)."""
    jar: dict[str, str] = {}
    for v in cookie_values(headers):
        first = v.split(";", 1)[0]
        if "=" in first:
            n, val = first.split("=", 1)
            if n.strip():
                jar[n.strip()] = val.strip()
    return jar


# ============================================================================================ FC5 patterns
_PY_ESCAPES = set("abBdDfnrsStvwWxuUNAZ0123456789")


def split_wa_pattern(pattern: Any) -> dict[str, Any]:
    """'regex\\;version:\\1\\;confidence:50' -> {regex, version, confidence (default 100)}."""
    if not isinstance(pattern, str):
        pattern = "" if pattern is None else str(pattern)
    parts = pattern.split("\\;")
    out: dict[str, Any] = {"regex": parts[0], "version": None, "confidence": 100}
    for tag in parts[1:]:
        if ":" not in tag:
            continue
        k, v = tag.split(":", 1)
        k = k.strip().lower()
        if k == "version":
            out["version"] = v
        elif k == "confidence":
            try:
                out["confidence"] = max(0, min(100, int(v)))
            except ValueError:
                pass
    return out


def js_regex_to_python(rx: Any) -> str:
    """JS (Wappalyzer) regex source -> Python ``re`` syntax; ValueError when unsupported (FC5).

    Handles (?<n>..) -> (?P<n>..), \\k<n> -> (?P=n), [^] -> [\\s\\S], [] -> (?!), \\/ -> /,
    \\u{XXXX}, \\cX and JS identity escapes Python rejects; \\p{..} is refused."""
    if not isinstance(rx, str):
        raise ValueError("not a string")
    out: list[str] = []
    i, n = 0, len(rx)
    in_class = False
    while i < n:
        c = rx[i]
        if c == "\\":
            if i + 1 >= n:
                raise ValueError("trailing backslash")
            d = rx[i + 1]
            if d in "pP" and i + 2 < n and rx[i + 2] == "{":
                raise ValueError("unicode property escape")
            if d == "k" and i + 2 < n and rx[i + 2] == "<":
                j = rx.find(">", i + 3)
                if j < 0:
                    raise ValueError("bad \\k<name>")
                out.append(f"(?P={rx[i + 3:j]})")
                i = j + 1
                continue
            if d == "u" and i + 2 < n and rx[i + 2] == "{":
                j = rx.find("}", i + 3)
                if j < 0:
                    raise ValueError("bad \\u{}")
                out.append(f"\\U{int(rx[i + 3:j], 16):08x}")
                i = j + 1
                continue
            if d == "u" and not re.match(r"[0-9a-fA-F]{4}", rx[i + 2:i + 6]):
                out.append("u")
                i += 2
                continue
            if d == "x" and not re.match(r"[0-9a-fA-F]{2}", rx[i + 2:i + 4]):
                out.append("x")
                i += 2
                continue
            if d == "c" and i + 2 < n and rx[i + 2].isalpha():
                out.append(f"\\x{ord(rx[i + 2].upper()) % 32:02x}")
                i += 3
                continue
            if d == "/":
                out.append("/")
                i += 2
                continue
            if d.isalpha() and d not in _PY_ESCAPES:
                out.append(re.escape(d))
                i += 2
                continue
            if in_class and d in "BAZ":
                out.append(d)
                i += 2
                continue
            out.append(c + d)
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            elif c == "[":
                out.append("\\[")
                i += 1
                continue
            out.append(c)
            i += 1
            continue
        if c == "[":
            if rx.startswith("[^]", i):
                out.append("[\\s\\S]")
                i += 3
                continue
            if rx.startswith("[]", i):
                out.append("(?!)")
                i += 2
                continue
            in_class = True
            out.append(c)
            i += 1
            continue
        if c == "(" and rx.startswith("(?<", i) and i + 3 < n and rx[i + 3] not in "=!":
            out.append("(?P<")
            i += 3
            continue
        out.append(c)
        i += 1
    return "".join(out)


_NESTED_Q = re.compile(r"[*+]|\{\d*,\}")
_OPTIONAL_Q = re.compile(r"[*?]|\{0?,")


def redos_suspect(rx: Any) -> str | None:
    """Static check for catastrophic-backtracking shapes ((a+)+, (\\w+\\s?)*...); reason or None."""
    if not isinstance(rx, str):
        return "not a string"
    stack: list[list[bool]] = [[False, False, False]]
    i, n, in_class = 0, len(rx), False
    closed: list[bool] | None = None
    pending_literal = False
    while i < n:
        c = rx[i]
        if in_class:
            if c == "\\":
                i += 2
                continue
            if c == "]":
                in_class = False
            i += 1
            continue
        if pending_literal and not _OPTIONAL_Q.match(rx, i) and not _NESTED_Q.match(rx, i):
            stack[-1][1] = True
        pending_literal = False
        if c == "\\":
            d = rx[i + 1] if i + 1 < n else ""
            if d and not d.isalnum():
                pending_literal = True
            i += 2
            closed = None
            continue
        if c == "[":
            in_class = True
            i += 1
            closed = None
            continue
        if c == "(":
            stack.append([False, False, False])
            i += 1
            if rx.startswith("?", i):
                m = re.match(r"\?(?:P<\w+>|<\w+>|[:=!]|<[=!]|[aiLmsux-]+[:)])", rx[i:])
                if m:
                    i += m.end()
            closed = None
            continue
        if c == ")":
            info = stack.pop() if len(stack) > 1 else [False, False, False]
            if info[0]:
                stack[-1][0] = True
            closed = info
            i += 1
            if not _NESTED_Q.match(rx, i) and not _OPTIONAL_Q.match(rx, i) and info[1] and not info[2]:
                stack[-1][1] = True
            continue
        if c == "|":
            stack[-1][2] = True
            i += 1
            closed = None
            continue
        m = _NESTED_Q.match(rx, i)
        if m:
            if closed is not None and closed[0] and (not closed[1] or closed[2]):
                return f"nested unbounded quantifier near offset {i}"
            stack[-1][0] = True
            i = m.end()
            if i < n and rx[i] in "?+":
                i += 1
            closed = None
            continue
        if c in "?{":
            i += 1
            closed = None
            continue
        if c not in ".^$":
            pending_literal = True
        closed = None
        i += 1
    return None


def compile_wa_pattern(pattern: Any) -> dict[str, Any]:
    """One Wappalyzer pattern -> {ok, regex, version, confidence, error, source}; never raises (FC5:
    the caller skips and counts failures). Case-insensitive like Wappalyzer's /i; a static ReDoS
    suspect is refused too."""
    parts = split_wa_pattern(pattern)
    res: dict[str, Any] = {"ok": False, "regex": None, "version": parts["version"], "confidence": parts["confidence"], "error": None,
                           "source": pattern if isinstance(pattern, str) else None}
    try:
        py = js_regex_to_python(parts["regex"])
    except (ValueError, OverflowError) as exc:
        res["error"] = f"convert: {exc}"
        return res
    suspect = redos_suspect(py)
    if suspect:
        res["error"] = f"redos: {suspect}"
        return res
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            res["regex"] = re.compile(py, re.I)
    except (re.error, OverflowError, RecursionError, ValueError) as exc:
        res["error"] = f"compile: {exc}"
        return res
    res["ok"] = True
    return res


def resolve_version(template: Any, match: Any) -> str | None:
    """Version template ('\\1', '\\1?a:b', literal) applied to a match."""
    if not template or match is None:
        return None
    version = str(template)
    groups = match.groups()
    for idx in range(1, len(groups) + 1):
        g = groups[idx - 1]
        tern = re.search(rf"\\{idx}\?([^:]*):(.*)$", version)
        if tern:
            version = version.replace(tern.group(0), tern.group(1) if g else tern.group(2))
        version = version.strip().replace(f"\\{idx}", g or "")
    version = re.sub(r"\\\d", "", version).strip()
    return clean(version, 40) or None


# ---- time budget ------------------------------------------------------------------------------------
#: adversarial blobs, the tag-shaped ones first (they expose ``<[^>]*x``-style backtracking soonest)
_SCREEN_UNITS = ("<a ", '<a href="', "<div class=\"x\">", "\n<", '"a', "a", "1.", "a-", " ", "aA1")


def _blob(unit: str, size: int) -> str:
    return (unit * (size // len(unit) + 1))[:size]


def pattern_time_ms(compiled: Any, samples: Iterable[str], repeat: int = 3) -> float:
    """Best-of-``repeat`` wall time (ms) of ``compiled.search`` over the samples (measured, never
    interrupted; the minimum filters scheduler noise)."""
    items = list(samples)
    best = float("inf")
    for _ in range(max(1, repeat)):
        start = time.perf_counter()
        for s in items:
            compiled.search(s)
        best = min(best, (time.perf_counter() - start) * 1000.0)
        if best > SCREEN_LIMIT_MS:
            break
    return best


def budget_screen(compiled: Any, *, small: int = 2048, large: int = 8192, target: int = MAX_HTML_BYTES,
                  limit_ms: float = SCREEN_LIMIT_MS) -> tuple[bool, float]:
    """FC5 per-pattern time budget for HTML patterns: time on adversarial blobs of growing sizes, the
    growth exponent between them, and the cost extrapolated to ``target`` bytes (the 500 KB scan cap).
    Returns (ok, extrapolated_ms). Super-linear patterns (``<[^>]*x`` on a tag-less blob) fail; linear
    ones pass whatever their constant.

    Sizes escalate (``small/4``, ``small``, ``large``) and the screen stops at the first blob that fails:
    a pattern already super-linear on a few KB (or over the limit even with linear growth) fails without
    the uninterruptible slow search on the large blob, so the whole webappanalyzer set screens in a few
    seconds instead of ~30 s (measured on the 2026-11 data: 461 HTML patterns, the same 60+ refused)."""
    worst = 0.0
    probe = max(64, small // 4)

    def confirmed(text: str, first: float) -> float:
        # a refusal is decided on the best of several runs (a scheduler hiccup never fails a pattern)
        return min(first, pattern_time_ms(compiled, [text], repeat=3))

    for unit in _SCREEN_UNITS:
        p_blob, s_blob = _blob(unit, probe), _blob(unit, small)
        t_probe = pattern_time_ms(compiled, [p_blob], repeat=1)
        if t_probe * (large / probe) > limit_ms:
            t_probe = confirmed(p_blob, t_probe)
            if t_probe * (large / probe) > limit_ms:  # even linear growth passes the limit at the large size
                return False, round(t_probe * (large / probe), 3)
        t_small = pattern_time_ms(compiled, [s_blob], repeat=2)
        if t_small * (large / small) > limit_ms:
            t_small = confirmed(s_blob, t_small)
            if t_small * (large / small) > limit_ms:
                return False, round(t_small * (large / small), 3)
        if t_small >= 2.0 and t_probe >= 0.05:
            t_probe, t_small = confirmed(p_blob, t_probe), confirmed(s_blob, t_small)
            exponent = min(max(math.log(max(t_small / max(t_probe, 1e-6), 1.0)) / math.log(small / probe), 1.0), 3.0)
            if t_small >= 2.0 and exponent >= 1.5:  # super-linear already on a few KB: far over the budget at 500 KB
                return False, round(t_small * (target / small) ** exponent, 3)
        big = _blob(unit, large)
        t_large = pattern_time_ms(compiled, [big], repeat=1)
        if t_large > limit_ms:
            return False, round(t_large, 3)
        if t_large < 0.3:  # too fast to measure growth reliably: harmless at 500 KB even if quadratic-ish
            continue
        t_large = min(t_large, pattern_time_ms(compiled, [big], repeat=2))
        t_small = min(t_small, pattern_time_ms(compiled, [_blob(unit, small)], repeat=1))
        if t_large < 0.3:
            continue
        ratio = max(t_large / max(t_small, 1e-6), 1.0)
        exponent = min(max(math.log(ratio) / math.log(large / small), 1.0), 3.0)
        projected = t_large * (target / large) ** exponent
        if exponent >= 1.5:
            worst = max(worst, projected)
            if worst > limit_ms:
                return False, round(worst, 3)
    return worst <= limit_ms, round(worst, 3)


# ============================================================================================ FC4/FC5 DB
WA_IGNORED_KEYS = ("js", "dom", "probe", "xhr", "scripts", "css", "text", "robots")
WA_LIST_KEYS = ("html", "scriptSrc", "url", "certIssuer")
WA_MAP_KEYS = ("headers", "cookies", "meta", "dns")


def _as_list(v: Any) -> list[str]:
    if isinstance(v, (list, tuple)):
        return [x for x in v if isinstance(x, str)]
    if isinstance(v, str):
        return [v]
    return []


def pattern_id(tech: str, key: str, source: Any) -> str:
    return hashlib.sha1(f"{tech}|{key}|{source}".encode("utf-8", "replace"), usedforsecurity=False).hexdigest()[:16]


def build_fingerprint_db(technologies: Any, categories: Any = None, *, screen: bool = True, skip_ids: Iterable[str] = ()) -> dict[str, Any]:
    """Wappalyzer-format technologies (+ categories) -> compiled matcher DB (FC4/FC5).

    Unsupported keys are counted in ``ignored_keys``; failing patterns land in ``skipped`` (reason);
    HTML patterns failing :func:`budget_screen` in ``budget_skipped``; ``skip_ids`` (patterns found
    slow on earlier pages) are left out."""
    skip = set(skip_ids or ())
    db: dict[str, Any] = {"techs": {}, "categories": {}, "skipped": [], "budget_skipped": [], "ignored_keys": {},
                          "stats": {"technologies": 0, "patterns": 0, "compiled": 0}, "index": {"headers": {}, "cookies": {}, "cookie_wild": [], "meta": {}}}
    cats, _ = load_json(categories) if categories is not None else ({}, None)
    if isinstance(cats, dict):
        for cid, c in cats.items():
            if isinstance(c, dict):
                prio = c.get("priority")
                db["categories"][str(cid)] = {"name": clean(str(c.get("name") or cid), 60), "priority": prio if isinstance(prio, int) else 99}
    techs, _ = load_json(technologies)
    if not isinstance(techs, dict):
        return db

    def comp(tech: str, key: str, p: str) -> dict[str, Any] | None:
        db["stats"]["patterns"] += 1
        pid = pattern_id(tech, key, p)
        if pid in skip:
            db["budget_skipped"].append({"tech": tech, "key": key, "id": pid, "reason": "time budget (earlier screen or page)"})
            return None
        r = compile_wa_pattern(p)
        if not r["ok"]:
            db["skipped"].append({"tech": tech, "key": key, "reason": r["error"]})
            return None
        if screen and key == "html":
            ok, ms = budget_screen(r["regex"])
            if not ok:
                db["budget_skipped"].append({"tech": tech, "key": key, "id": pid, "reason": f"time budget: ~{ms:.0f} ms on 500 KB"})
                return None
        r["id"] = pid
        db["stats"]["compiled"] += 1
        return r

    for name, t in techs.items():
        if not isinstance(t, dict) or not isinstance(name, str) or not name.strip():
            continue
        name = clean(name, 80)
        entry: dict[str, Any] = {
            "cats": [str(c) for c in (t.get("cats") if isinstance(t.get("cats"), list) else []) if isinstance(c, (int, str))],
            "cpe": t.get("cpe") if isinstance(t.get("cpe"), str) else None,
            "implies": [],
            "requires": _as_list(t.get("requires")),
            "requiresCategory": [str(c) for c in (t.get("requiresCategory") if isinstance(t.get("requiresCategory"), list) else []) if isinstance(c, (int, str))],
            "excludes": _as_list(t.get("excludes")),
        }
        for imp in _as_list(t.get("implies")):
            sp = split_wa_pattern(imp)
            entry["implies"].append((sp["regex"], sp["confidence"]))
        for key in WA_IGNORED_KEYS:
            if key in t:
                db["ignored_keys"][key] = db["ignored_keys"].get(key, 0) + 1
        for key in WA_LIST_KEYS:
            pats = [c for c in (comp(name, key, p) for p in _as_list(t.get(key))) if c]
            if pats:
                entry[key] = pats
        for key in WA_MAP_KEYS:
            m = t.get(key)
            if not isinstance(m, dict):
                continue
            cm: dict[str, list[dict[str, Any]]] = {}
            for k, v in m.items():
                pats = [c for c in (comp(name, f"{key}:{k}", p) for p in _as_list(v)) if c]
                if pats:
                    cm[str(k) if key == "cookies" else str(k).lower()] = pats
            if cm:
                entry[key] = cm
                idx = db["index"]
                for k2, pats in cm.items():
                    if key == "headers":
                        idx["headers"].setdefault(k2, []).append((name, pats))
                    elif key == "meta":
                        idx["meta"].setdefault(k2, []).append((name, pats))
                    elif key == "cookies":
                        if "*" in k2:
                            rx = re.compile("^" + ".*".join(re.escape(x) for x in k2.split("*")) + "$", re.I)
                            idx["cookie_wild"].append((rx, name, k2, pats))
                        else:
                            idx["cookies"].setdefault(k2.lower(), []).append((name, k2, pats))
        db["techs"][name] = entry
    db["stats"]["technologies"] = len(db["techs"])
    return db


_DB_MEMO: dict[str, dict[str, Any]] = {}
_DB_LOCK = threading.Lock()
_STATE_KEY = "slow_patterns"


def _saved(ctx: Any, db_key: str) -> dict[str, Any]:
    try:
        saved = ctx.state.get(_STATE_KEY)
    except Exception:  # noqa: BLE001 - state is a convenience
        return {}
    return saved if isinstance(saved, dict) and saved.get("db") == db_key else {}


def _slow_ids(ctx: Any, db_key: str) -> list[str]:
    ids = _saved(ctx, db_key).get("ids")
    return [str(x) for x in ids if isinstance(x, str)][:2000] if isinstance(ids, list) else []


def _screened(ctx: Any, db_key: str) -> bool:
    """Has the time-budget screen already run on this dataset version (its refusals are in ``ids``)?"""
    return _saved(ctx, db_key).get("screened") is True


def remember_slow(ctx: Any, db_key: str, ids: Iterable[str], *, screened: bool | None = None) -> None:
    """Persist pattern ids (hashes only) that are slow on a page or failed the time-budget screen (FC5),
    so later runs and later processes skip them; ``screened`` records that this dataset version was
    screened (the screen then never runs again for it: it costs seconds of CPU per process)."""
    new = [i for i in ids if isinstance(i, str)]
    done = _screened(ctx, db_key) if screened is None else (screened or _screened(ctx, db_key))
    if not new and screened is None:
        return
    try:
        merged = sorted(set(_slow_ids(ctx, db_key)) | set(new))[:2000]
        ctx.state.set(_STATE_KEY, {"db": db_key, "ids": merged, "screened": bool(done)})
    except Exception:  # noqa: BLE001
        pass
    if new:
        with _DB_LOCK:
            _DB_MEMO.pop(db_key, None)


def load_fingerprint_db(ctx: Any) -> dict[str, Any]:
    """The compiled webappanalyzer DB from ``ctx.data`` (FC4: runtime download, never bundled).

    Every technologies file and the categories are fetched through the registered datasets (a stale
    or missing copy is downloaded by the core, passive route, no case value sent); a file that
    cannot be obtained is listed in ``missing``. Raises DatasetUnavailable when no technologies file
    is usable. Memoised per process by the SHA-256 of the files (and the slow-pattern list)."""
    blobs: list[tuple[str, bytes]] = []
    missing: list[str] = []
    for name in WA_TECH_DATASETS:
        try:
            blobs.append((name, Path(ctx.data.fetch(name)).read_bytes()))
        except (DatasetError, OSError, ValueError) as exc:
            missing.append(f"{name}: {clean(str(exc), 120)}")
    if not blobs:
        raise DatasetUnavailable(WA_TECH_DATASETS[1], f"webappanalyzer fingerprints are not available: run v3lum data update ({'; '.join(missing[:2])})")
    try:
        cats_raw: bytes | None = Path(ctx.data.fetch(WA_CATEGORIES)).read_bytes()
    except (DatasetError, OSError, ValueError) as exc:
        cats_raw = None
        missing.append(f"{WA_CATEGORIES}: {clean(str(exc), 120)}")
    h = hashlib.sha256()
    for name, raw in blobs:
        h.update(name.encode())
        h.update(hashlib.sha256(raw).digest())
    h.update(hashlib.sha256(cats_raw or b"").digest())
    db_key = h.hexdigest()[:24]
    skip_ids = _slow_ids(ctx, db_key)
    memo_key = db_key
    with _DB_LOCK:
        cached = _DB_MEMO.get(memo_key)
    if cached is None:
        merged: dict[str, Any] = {}
        for _name, raw in blobs:
            obj, _err = load_json(raw)
            if isinstance(obj, dict):
                merged.update(obj)
        screened = _screened(ctx, db_key)
        cached = build_fingerprint_db(merged, cats_raw, skip_ids=skip_ids, screen=not screened)
        if not screened:  # screen once per dataset version, then reuse its refusals (ctx.state, hashes only)
            remember_slow(ctx, db_key, [b["id"] for b in cached["budget_skipped"] if isinstance(b.get("id"), str)], screened=True)
        cached["key"] = db_key
        cached["source"] = "webappanalyzer"
        with _DB_LOCK:
            _DB_MEMO[memo_key] = cached
    db = dict(cached)
    db["missing"] = missing
    return db


def db_summary(db: Mapping[str, Any]) -> dict[str, Any]:
    stats = db.get("stats") or {}
    return {
        "source": db.get("source", "webappanalyzer"), "technologies": stats.get("technologies", 0), "patterns": stats.get("patterns", 0),
        "compiled": stats.get("compiled", 0), "skipped": len(db.get("skipped") or []), "budget_skipped": len(db.get("budget_skipped") or []),
        "ignored_keys": dict(db.get("ignored_keys") or {}), "missing_files": len(db.get("missing") or []),
    }


# ============================================================================================ page facts
class _PageParser(HTMLParser):
    """stdlib html.parser facts: title, meta, script src, link href, anchors (footer flag), text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: str | None = None
        self._in_title = False
        self.meta: dict[str, list[str]] = {}
        self.script_src: list[str] = []
        self.link_href: list[tuple[str, str]] = []
        self.anchors: list[dict[str, Any]] = []
        self.footer_depth = 0
        self._a: dict[str, Any] | None = None
        self.text_parts: list[str] = []
        self._skip = 0
        self.cfemails: list[str] = []
        self.jsonld: list[str] = []
        self._ld: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs if k}
        if tag == "title" and self.title is None:
            self._in_title, self.title = True, ""
        elif tag == "meta":
            name = (a.get("name") or a.get("property") or a.get("http-equiv") or "").strip().lower()
            if name and "content" in a and len(self.meta) < 300:
                self.meta.setdefault(name, []).append(a["content"][:2048])
            if "charset" in a:
                self.meta.setdefault("charset", []).append(a["charset"][:64])
        elif tag == "script":
            if a.get("src") and len(self.script_src) < MAX_SCRIPTS:
                self.script_src.append(a["src"].strip()[:MAX_SCRIPT_SRC_CHARS])
            if "ld+json" in a.get("type", "").lower() and len(self.jsonld) < 10:
                self._ld = []
            self._skip += 1
        elif tag == "style":
            self._skip += 1
        elif tag == "link" and a.get("href") and len(self.link_href) < MAX_SCRIPTS:
            self.link_href.append((a.get("rel", "").lower(), a["href"].strip()[:MAX_SCRIPT_SRC_CHARS]))
        elif tag == "footer":
            self.footer_depth += 1
        elif tag == "a":
            self._a = {"href": a.get("href", "").strip()[:2048], "text": "", "footer": self.footer_depth > 0}
            if a.get("data-cfemail"):
                self.cfemails.append(a["data-cfemail"][:256])
        elif a.get("data-cfemail"):
            self.cfemails.append(a["data-cfemail"][:256])

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag in ("script", "style") and self._skip:
            self._skip -= 1
            if tag == "script" and self._ld is not None:
                self.jsonld.append("".join(self._ld)[:65536])
                self._ld = None
        elif tag == "footer" and self.footer_depth:
            self.footer_depth -= 1
        elif tag == "a" and self._a is not None:
            if len(self.anchors) < 2000:
                self.anchors.append(self._a)
            self._a = None

    def handle_data(self, data: str) -> None:
        if self._in_title and self.title is not None and len(self.title) < 1000:
            self.title += data
        if self._ld is not None:
            self._ld.append(data)
        if self._skip:
            return
        if self._a is not None and len(self._a["text"]) < 500:
            self._a["text"] += data
        self.text_parts.append(data)


def extract_page_facts(body: Any, url: str | None = None, content_type: Any = None, max_bytes: int = MAX_HTML_BYTES) -> dict[str, Any]:
    """HTML -> facts for the matchers (FC5) and the contact extractor (P077). Only the first
    ``max_bytes`` bytes are parsed; the body is untrusted, never executed or rendered."""
    raw_len = len(body) if isinstance(body, (bytes, bytearray, str)) else 0
    if isinstance(body, (bytes, bytearray, memoryview)):
        text = decode_body(bytes(body)[:max_bytes], content_type)
    else:
        text = _as_text(body)[:max_bytes]
    facts: dict[str, Any] = {"is_html": False, "title": None, "meta": {}, "script_src": [], "link_href": [], "anchors": [], "text": "",
                             "html": text, "truncated": raw_len > max_bytes, "bytes_scanned": len(text), "url": url, "cfemails": [], "jsonld": []}
    if not text.strip() or "\x00" in text[:2048]:
        return facts
    facts["is_html"] = bool(re.search(r"<(html|head|body|title|meta|script|div|p|a)\b", text[:65536], re.I))
    p = _PageParser()
    try:
        p.feed(text)
        p.close()
    except Exception:  # noqa: BLE001 - html.parser is lenient; pathological input must not break a run
        pass
    facts.update({
        "title": clean(p.title, 300) if p.title else None, "meta": p.meta, "script_src": p.script_src, "link_href": p.link_href,
        "anchors": p.anchors, "cfemails": p.cfemails, "jsonld": p.jsonld,
        "text": "\n".join(t for t in (re.sub(r"\s+", " ", x).strip() for x in p.text_parts) if t),
    })
    return facts


# ============================================================================================ matching
def match_technologies(db: Mapping[str, Any], facts: Mapping[str, Any] | None = None, headers: Any = None, url: str | None = None,
                       dns: Mapping[str, Any] | None = None, cert_issuer: str | None = None, *, budget_s: float = 5.0) -> dict[str, Any]:
    """headers/cookies/meta/html/scriptSrc/url/dns/certIssuer matchers (FC5) with implies, requires,
    requiresCategory and excludes. Every pattern of a key is evaluated (a version-less presence pattern
    never hides a later versioned one); each pattern adds its confidence once (cap 100).

    Returns {detections: [{name, version, confidence, categories, cpe, evidence, implied_by}], slow:
    [pattern ids slower than SLOW_PATTERN_MS on this page], budget_hit: bool}."""
    techs = (db or {}).get("techs", {})
    index = (db or {}).get("index", {})
    facts = facts or {}
    h = _norm(headers)
    jar = cookie_jar(h)
    html_text = str(facts.get("html") or "")[:MAX_HTML_BYTES]
    scripts = [str(x)[:MAX_SCRIPT_SRC_CHARS] for x in (facts.get("script_src") or [])[:MAX_SCRIPTS] if isinstance(x, str) and not x.lower().startswith("data:")]
    meta = facts.get("meta") or {}
    page_url = str(url or facts.get("url") or "")[:2048]
    dns_u = {str(k).upper(): [str(x)[:1024] for x in _as_list(v)] for k, v in (dns or {}).items()}
    found: dict[str, dict[str, Any]] = {}
    slow: list[str] = []

    def hit(name: str, key: str, p: Mapping[str, Any], m: Any, label: str | None) -> None:
        d = found.setdefault(name, {"name": name, "versions": [], "confidence": 0, "evidence": [], "implied_by": [], "_seen": set()})
        if p.get("id") not in d["_seen"]:
            d["_seen"].add(p.get("id"))
            d["confidence"] = min(100, d["confidence"] + int(p.get("confidence") or 0))
        v = resolve_version(p.get("version"), m)
        if v:
            d["versions"].append(v)
        ev = {"key": key, "name": clean(label, 120) if label else None}
        if ev not in d["evidence"] and len(d["evidence"]) < 10:
            d["evidence"].append(ev)

    def scan(name: str, key: str, pats: Iterable[Mapping[str, Any]], values: Iterable[str], label: Any = None) -> None:
        for v in values:
            for p in pats:
                m = p["regex"].search(v)
                if m:
                    hit(name, key, p, m, label(v) if callable(label) else label)

    for hn, vals in h.items():
        for name, pats in index.get("headers", {}).get(hn, []):
            scan(name, "headers", pats, [v[:MAX_HEADER_VALUE_CHARS] for v in vals], hn)
    for cname, cval in jar.items():
        for name, key, pats in index.get("cookies", {}).get(cname.lower(), []):
            scan(name, "cookies", pats, [cval[:MAX_HEADER_VALUE_CHARS]], key)
        for rx, name, key, pats in index.get("cookie_wild", []):
            if rx.match(cname):
                scan(name, "cookies", pats, [cval[:MAX_HEADER_VALUE_CHARS]], key)
    for mn, vals in meta.items():
        for name, pats in index.get("meta", {}).get(str(mn).lower(), []):
            scan(name, "meta", pats, [str(x)[:MAX_HEADER_VALUE_CHARS] for x in vals], mn)
    for name, t in techs.items():
        if scripts and t.get("scriptSrc"):
            scan(name, "scriptSrc", t["scriptSrc"], scripts, lambda v: v[:200])
        if page_url and t.get("url"):
            scan(name, "url", t["url"], [page_url])
        for rtype, pats in (t.get("dns") or {}).items():
            vals = dns_u.get(str(rtype).upper(), [])
            if vals:
                scan(name, "dns", pats, vals, str(rtype).upper())
        if cert_issuer and t.get("certIssuer"):
            scan(name, "certIssuer", t["certIssuer"], [str(cert_issuer)[:256]])
    budget_hit = False
    if html_text:
        deadline = time.perf_counter() + max(0.1, float(budget_s))
        for name, t in techs.items():
            pats = t.get("html")
            if not pats:
                continue
            for p in pats:
                if time.perf_counter() > deadline:
                    budget_hit = True
                    break
                start = time.perf_counter()
                m = p["regex"].search(html_text)
                if (time.perf_counter() - start) * 1000.0 > SLOW_PATTERN_MS and p.get("id"):
                    slow.append(p["id"])
                if m:
                    hit(name, "html", p, m, None)
            if budget_hit:
                break
    for d in found.values():
        d.pop("_seen", None)
    # implies (recursive; implied confidence = min(parent, implied tag))
    queue = list(found)
    seen: set[str] = set()
    while queue:
        n = queue.pop(0)
        if n in seen or n not in techs:
            continue
        seen.add(n)
        for imp, conf in techs[n].get("implies", []):
            imp = clean(imp, 80)
            if not imp:
                continue
            if imp in found:
                if n not in found[imp]["implied_by"]:
                    found[imp]["implied_by"].append(n)
                continue
            found[imp] = {"name": imp, "versions": [], "confidence": min(found[n]["confidence"], conf), "evidence": [], "implied_by": [n]}
            queue.append(imp)
    changed = True
    while changed:
        changed = False
        present_cats = {c for n in found for c in techs.get(n, {}).get("cats", [])}
        for n in list(found):
            t = techs.get(n, {})
            missing_req = bool(t.get("requires")) and not all(r in found for r in t["requires"])
            missing_cat = bool(t.get("requiresCategory")) and not any(c in present_cats for c in t["requiresCategory"])
            if missing_req or missing_cat:
                del found[n]
                changed = True
    for n in list(found):
        if n in found:
            for ex in techs.get(n, {}).get("excludes", []):
                found.pop(ex, None)
    cats = (db or {}).get("categories", {})
    out = []
    for n, d in found.items():
        t = techs.get(n, {})
        vs = sorted(set(d["versions"]), key=lambda v: (len(v.split(".")), len(v), v), reverse=True)
        out.append({"name": n, "version": vs[0] if vs else None, "confidence": d["confidence"],
                    "categories": [cats.get(c, {}).get("name", c) for c in t.get("cats", [])], "cpe": t.get("cpe"),
                    "evidence": d["evidence"], "implied_by": d["implied_by"]})
    prio = {n: min([cats.get(c, {}).get("priority", 99) for c in techs.get(n, {}).get("cats", [])] or [99]) for n in found}
    out.sort(key=lambda d: (prio.get(d["name"], 99), d["name"].lower()))
    return {"detections": out, "slow": slow, "budget_hit": budget_hit}


def tech_list_compact(detections: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """FC8: one compact technology list [{name, version, category}]."""
    out = []
    for d in detections or []:
        if isinstance(d, Mapping) and d.get("name"):
            cats = d.get("categories") or []
            out.append({"name": d["name"], "version": d.get("version"), "category": cats[0] if cats else None})
    return out


def cpe_with_version(cpe: Any, version: Any) -> str | None:
    """CPE 2.3 template + detected version -> CPE guess (CR16, low confidence)."""
    if not isinstance(cpe, str) or not cpe.startswith("cpe:2.3:") or not version:
        return None
    if not re.fullmatch(r"[0-9][0-9A-Za-z._-]{0,30}", str(version)):
        return None
    parts = cpe.split(":")
    if len(parts) < 6:
        return None
    parts[5] = str(version)
    return ":".join(parts)


DNS_TYPES = ("MX", "TXT", "NS", "SOA", "CNAME")


def dns_facts(ctx: Any, host: str) -> dict[str, Any]:
    """DNS records for the dns matcher and the CNAME attribution through ``ctx.dns`` (FC5: no new
    socket): MX/TXT/NS/SOA of the registrable domain, CNAME of the host. Unverified answers are
    simply absent (never 'no records')."""
    reg = psl.registrable_domain(host) or host
    out: dict[str, Any] = {}
    unverified: list[str] = []
    for rtype in DNS_TYPES:
        name = host if rtype == "CNAME" else reg
        try:
            ans = ctx.dns.query(name, rtype)
        except Exception:  # noqa: BLE001 - DNS is an optional matcher input
            unverified.append(rtype)
            continue
        if getattr(ans, "could_not_verify", False):
            unverified.append(rtype)
            continue
        recs = [str(r) for r in (getattr(ans, "records", None) or [])][:50]
        if rtype == "CNAME":
            recs = list(dict.fromkeys([str(c) for c in (getattr(ans, "cnames", None) or [])] + recs))[:10]
        if recs:
            out[rtype] = [r.strip('"') for r in recs]
    return {"records": out, "unverified": unverified}


# ============================================================================================ FC8 CVEs
_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _sev_from_cvss(score: float | None) -> str:
    if score is None:
        return "low"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "info"


def collapse_cves(tech: str, version: str | None, cves: Iterable[Mapping[str, Any]], hostile: bool = False) -> dict[str, Any] | None:
    """Version-inferred CVEs -> ONE finding per technology (FC8): title 'jQuery 1.12.4: 4 CVEs, max
    CVSS 6.1' (or 'max severity medium' when the source has no CVSS), confidence 0.5 (POSSIBLE),
    severity at most MEDIUM unless a CVE is in CISA KEV (then at most HIGH, label kev). Hostile pages
    get an attribute instead of a vulnerability finding. None when nothing to report."""
    rows = []
    for c in cves or []:
        if isinstance(c, Mapping) and isinstance(c.get("id"), str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", c["id"]):
            try:
                score = float(c["cvss"]) if c.get("cvss") is not None else None
            except (TypeError, ValueError):
                score = None
            sev = str(c.get("severity") or "").lower()
            rows.append((c["id"], score, bool(c.get("kev")), sev if sev in _SEV_ORDER else None))
    ids = sorted({r[0] for r in rows})
    if not ids or not tech:
        return None
    scores = [r[1] for r in rows if r[1] is not None]
    max_cvss = max(scores) if scores else None
    sevs = [r[3] for r in rows if r[3]]
    max_sev = max(sevs, key=_SEV_ORDER.index) if sevs else None
    kev = any(r[2] for r in rows)
    label = f"{tech}{f' {version}' if version else ''}: {len(ids)} CVE{'' if len(ids) == 1 else 's'}"
    if max_cvss is not None:
        label += f", max CVSS {max_cvss:g}"
    elif max_sev:
        label += f", max severity {max_sev}"
    if hostile:
        return {"kind": "attribute", "technology": tech, "version": version, "cve_count": len(ids), "cve_ids": ids, "max_cvss": max_cvss,
                "max_severity": max_sev, "kev": kev, "label": label}
    sev = _sev_from_cvss(max_cvss) if max_cvss is not None else (max_sev or "low")
    cap = "high" if kev else "medium"
    if _SEV_ORDER.index(sev) > _SEV_ORDER.index(cap):
        sev = cap
    return {"kind": "finding", "title": label, "severity": sev, "confidence": 0.5, "cve_ids": ids, "cve_count": len(ids), "max_cvss": max_cvss,
            "max_severity": max_sev, "kev": kev, "labels": ["kev"] if kev else []}


def version_cves(data: Any, detections: Iterable[Mapping[str, Any]], scripts: Iterable[str]) -> dict[str, list[dict[str, Any]]]:
    """Version-inferred CVEs per 'Technology version' from the RetireJS repository (local copy or the
    bundled snapshot, never downloaded here) for JS libraries detected in script URLs and in the
    technology list, marked with CISA KEV from its local copy (P291). Returns {label: [cve rows]}."""
    try:
        from v3lum.modules.url_web.retirejs_check import kev_cves, load_repository, retire_check, retire_scan
    except ImportError:  # pragma: no cover - sibling module missing
        return {}
    try:
        repo, _info = load_repository(data)
    except (DatasetError, OSError, ValueError):
        return {}
    kev = kev_cves(data)
    seen: dict[tuple[str, str], str] = {}
    for d in detections or []:
        name, version = d.get("name"), d.get("version")
        if isinstance(name, str) and isinstance(version, str):
            comp = re.sub(r"[^a-z0-9.-]+", "-", name.lower()).strip("-")
            seen.setdefault((comp, version), name)
    for src in list(scripts or [])[:50]:
        try:
            for det in retire_scan(repo, uri=str(src)[:MAX_SCRIPT_SRC_CHARS]):
                comp, version = det.get("component"), det.get("version")
                if isinstance(comp, str) and isinstance(version, str):
                    seen.setdefault((comp, version), comp)
        except Exception:  # noqa: BLE001 - a bad script URL never breaks the run
            continue
    out: dict[str, list[dict[str, Any]]] = {}
    for (comp, version), display in seen.items():
        try:
            advisories = retire_check(repo, comp, version)
        except Exception:  # noqa: BLE001
            continue
        rows = []
        for adv in advisories:
            for cve in adv.get("cves") or []:
                rows.append({"id": cve, "cvss": None, "severity": adv.get("severity"), "kev": cve in kev})
        if rows:
            out.setdefault(f"{display}|{version}", []).extend(rows)
    return out


# ============================================================================================ FC3/FC7 verdict
DEFAULT_PROXY_SIGNATURES: list[dict[str, Any]] = [
    {"vendor": "Zscaler", "any": [r"Internet Security by Zscaler", r"gateway\.zscaler(?:two|three)?\.net", r"login\.zscloud\.net",
                                  r"zscaler[^<]{0,80}(?:blocked|not allowed|policy)", r"(?:blocked|not allowed|policy)[^<]{0,80}zscaler"]},
    {"vendor": "Netskope", "any": [r"notify\.netskope", r"goskope\.com", r"netskope[^<]{0,80}(?:blocked|policy)", r"(?:blocked|policy)[^<]{0,120}netskope"]},
    {"vendor": "Fortinet", "any": [r"FortiGuard (?:Web Filtering|Intrusion Prevention)", r"//globalurl\.fortinet\.net",
                                   r"Web Page Blocked![^<]{0,400}Fortinet", r"fgtauth", r"Web Filter Block Override"]},
    {"vendor": "Palo Alto Networks", "any": [r"Access to the web page you were trying to visit has been blocked in accordance with company policy",
                                             r"paloaltonetworks[^<]{0,200}(?:URL Filtering|blocked)", r"PAN-OS[^<]{0,80}(?:block|URL)"]},
    {"vendor": "Cisco Umbrella", "any": [r"block\.opendns\.com", r"This site is blocked[^<]{0,200}(?:Umbrella|OpenDNS)", r"umbrella[^<]{0,60}block page"]},
    {"vendor": "Forcepoint", "any": [r"Forcepoint[^<]{0,120}(?:blocked|Content blocked)", r"Websense[^<]{0,80}blocked"]},
    {"vendor": "Broadcom/Symantec WSS", "any": [r"Symantec Web Security Service", r"Blue ?Coat[^<]{0,80}(?:blocked|denied)", r"cfauth\.com"]},
    {"vendor": "Skyhigh/McAfee Web Gateway", "any": [r"McAfee Web Gateway", r"Skyhigh Secure Web Gateway"]},
    {"vendor": "Sophos", "any": [r"Sophos[^<]{0,120}(?:blocked|Web Protection)"]},
    {"vendor": "Check Point", "any": [r"Check Point[^<]{0,120}(?:blocked|URL Filtering|Application Control)"]},
]

CHALLENGE_SIGNATURES: list[dict[str, Any]] = [
    {"vendor": "Cloudflare", "header": ("cf-mitigated", r"challenge")},
    {"vendor": "Cloudflare", "body": r"<title>\s*(?:Just a moment\.\.\.|Attention Required! \| Cloudflare)"},
    {"vendor": "Cloudflare", "body": r"/cdn-cgi/challenge-platform/"},
    {"vendor": "AWS WAF", "header": ("x-amzn-waf-action", r"captcha|challenge")},
    {"vendor": "Akamai", "body": r"You don't have permission to access[\s\S]{0,600}Reference(?:\s|&#32;)(?:#|&#35;)|errors\.edgesuite\.net"},
    {"vendor": "Imperva", "body": r"Incapsula incident ID|/_Incapsula_Resource\?"},
    {"vendor": "DataDome", "body": r"captcha-delivery\.com"},
    {"vendor": "HUMAN/PerimeterX", "body": r"px-captcha|_pxCaptcha|Press & Hold"},
    {"vendor": "Sucuri", "body": r"Sucuri WebSite Firewall - Access Denied"},
    {"vendor": "DDoS-Guard", "body": r"<title>\s*DDoS-Guard\s*</title>|check\.ddos-guard\.net"},
    {"vendor": "Vercel", "body": r"Vercel Security Checkpoint"},
    {"vendor": "Anubis", "body": r"Making sure you(?:&#39;|')re not a bot"},
]

PROXY_PAGE_MAX_BYTES = 100_000
PROXY_ERROR_MARKERS = (r"ERROR: The requested URL could not be retrieved", r"Generated [^<]{0,80} by [^<]{0,80}\(squid",
                       r"<title>\s*Proxy Error\s*</title>", r"The proxy server received an invalid response")


def proxy_signatures(extra: Any = None) -> list[dict[str, Any]]:
    """Built-in SWG signatures + configured ones (setting web_fingerprint_proxy_signatures:
    [{vendor, any: [regex]}]); invalid entries are ignored."""
    sigs = list(DEFAULT_PROXY_SIGNATURES)
    for s in extra if isinstance(extra, list) else []:
        if isinstance(s, Mapping) and isinstance(s.get("vendor"), str) and _as_list(s.get("any")):
            sigs.append({"vendor": clean(s["vendor"], 60), "any": _as_list(s.get("any"))[:20]})
    return sigs


def classify_response(status_code: Any, headers: Any = None, body: Any = None, signatures: Any = None) -> dict[str, Any]:
    """May this page be fingerprinted? (FC3, FC7)

    verdict 'corporate_proxy' (a SWG block/warning page: BLOCKED, 'blocked by corporate proxy
    (<vendor>)', never the target's), 'challenge' (anti-bot page: BLOCKED, never retried),
    'proxy_error' and 'inconclusive' (4xx/5xx: no body fingerprint, headers still usable for the
    WAF/CDN attribution), 'not_html' or 'ok'."""
    h = _norm(headers)
    full_len = len(body) if isinstance(body, (bytes, bytearray, str)) else 0
    text = decode_body(body[:65536] if isinstance(body, (bytes, bytearray, str)) else "", header_first(h, "content-type"))
    sigs = signatures if signatures is not None else DEFAULT_PROXY_SIGNATURES
    base = {"vendor": None, "fingerprint_body": False, "fingerprint_headers": False}
    if full_len <= PROXY_PAGE_MAX_BYTES:  # block pages are small; a big page merely mentioning a vendor is not one
        for s in sigs:
            for rx in s.get("any", []):
                try:
                    if re.search(rx, text, re.I):
                        return dict(base, verdict="corporate_proxy", status="blocked", reason_code="challenge",
                                    reason=f"blocked by corporate proxy ({s.get('vendor', '?')})", vendor=s.get("vendor"))
                except re.error:
                    continue
    for s in CHALLENGE_SIGNATURES:
        found = False
        if "header" in s:
            found = any(re.search(s["header"][1], v, re.I) for v in h.get(s["header"][0], []))
        if not found and "body" in s:
            found = bool(re.search(s["body"], text, re.I))
        if found:
            return dict(base, verdict="challenge", status="blocked", reason_code="challenge",
                        reason=f"anti-bot challenge page ({s['vendor']}); not retried", vendor=s["vendor"])
    for rx in PROXY_ERROR_MARKERS:
        if re.search(rx, text, re.I):
            return dict(base, verdict="proxy_error", status="error", reason_code="error", reason="proxy error page (inconclusive)")
    try:
        code = int(status_code)
    except (TypeError, ValueError):
        code = 0
    if code >= 400 or code == 0:
        return dict(base, verdict="inconclusive", status="error", reason_code="error",
                    reason=f"HTTP {code or '?'}: an error body is inconclusive (headers only)", fingerprint_headers=code >= 400)
    ctype = (header_first(h, "content-type") or "").lower()
    if ctype and "html" not in ctype and "xml" not in ctype and not looks_html(text):
        return dict(base, verdict="not_html", status="ok", reason_code=None, reason=f"not an HTML page ({clean(ctype, 60)})", fingerprint_headers=True)
    return dict(base, verdict="ok", status="ok", reason_code=None, reason=None, fingerprint_body=True, fingerprint_headers=True)


# ============================================================================================ FC6 WAF/CDN
def _eval_rule(e: Mapping[str, Any], h: Mapping[str, list[str]], cookies_raw: list[str]) -> bool:
    if "kind" in e:
        rx = str(e.get("regex", ""))
        try:
            if e["kind"] == "header":
                return any(re.search(rx, v[:MAX_HEADER_VALUE_CHARS], re.I) for v in h.get(str(e.get("name", "")).lower(), []))
            if e["kind"] == "cookie":
                return any(re.search(rx, v[:MAX_HEADER_VALUE_CHARS], re.I) for v in cookies_raw)
        except re.error:
            return False
        return False
    if "all" in e:
        return bool(e["all"]) and all(_eval_rule(x, h, cookies_raw) for x in e["all"] if isinstance(x, Mapping))
    if "any" in e:
        return any(_eval_rule(x, h, cookies_raw) for x in e["any"] if isinstance(x, Mapping))
    return False


def _rule_text(e: Mapping[str, Any]) -> str:
    if "kind" in e:
        return f"{e['kind']} {e.get('name', 'set-cookie')}~/{e.get('regex', '')}/"
    k = "all" if "all" in e else "any"
    inner = ", ".join(_rule_text(x) for x in e.get(k, []) if isinstance(x, Mapping))
    return f"{k}({inner})"


def waf_passive_detect(signatures_doc: Any, headers: Any, findall: bool = True) -> list[dict[str, Any]]:
    """Header/cookie-only wafw00f subset over a NORMAL response's headers (FC6). Works on headers
    already in hand (live or archived); never sends anything. [{name, kind, evidence, source}]."""
    doc, _ = load_json(signatures_doc)
    sigs = doc.get("signatures", []) if isinstance(doc, Mapping) else []
    h = _norm(headers)
    cookies_raw = cookie_values(h)
    out: list[dict[str, Any]] = []
    for s in sigs if isinstance(sigs, list) else []:
        if not isinstance(s, Mapping):
            continue
        for r in s.get("rules", []) if isinstance(s.get("rules"), list) else []:
            if isinstance(r, Mapping) and _eval_rule(r, h, cookies_raw):
                ev = _rule_text(r)
                out.append({"name": clean(str(s.get("name") or "?"), 80), "kind": "cdn_or_proxy" if s.get("kind") == "cdn_or_proxy" else "waf",
                            "evidence": clean(ev, 160), "source": "cookie" if ev.startswith("cookie") else "header"})
                break
        if out and not findall:
            break
    return out


#: own CNAME-suffix table (MIT); IP-range attribution is P034's
CDN_CNAME_SUFFIXES = {
    "cloudfront.net": "Amazon CloudFront", "akamaiedge.net": "Akamai", "edgekey.net": "Akamai", "edgesuite.net": "Akamai",
    "akamai.net": "Akamai", "akamaized.net": "Akamai", "akamaihd.net": "Akamai", "fastly.net": "Fastly", "fastlylb.net": "Fastly",
    "azureedge.net": "Azure CDN", "azurefd.net": "Azure Front Door", "b-cdn.net": "Bunny CDN", "cdn.cloudflare.net": "Cloudflare",
    "incapdns.net": "Imperva", "impervadns.net": "Imperva", "sucuri.net": "Sucuri", "cdn77.org": "CDN77", "edgecastcdn.net": "Edgecast",
    "stackpathdns.com": "StackPath", "ghs.googlehosted.com": "Google", "vercel-dns.com": "Vercel", "netlify.app": "Netlify",
    "github.io": "GitHub Pages", "azurewebsites.net": "Azure App Service", "herokudns.com": "Heroku", "myshopify.com": "Shopify",
    "wpengine.com": "WP Engine", "kxcdn.com": "KeyCDN", "cdngc.net": "CDNetworks", "gcdn.co": "G-Core", "azioncdn.net": "Azion",
}


def cname_attribution(cname_chain: Any) -> list[dict[str, Any]]:
    """CNAME chain (from ctx.dns) -> [{name, kind 'cdn', evidence, source 'cname'}] by suffix."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for c in _as_list(cname_chain):
        name = c.strip().rstrip(".").lower()
        for suf, prov in CDN_CNAME_SUFFIXES.items():
            if name == suf or name.endswith("." + suf):
                if prov not in seen:
                    seen.add(prov)
                    out.append({"name": prov, "kind": "cdn", "evidence": f"CNAME {clean(name, 120)}", "source": "cname"})
                break
    return out


# ============================================================================================ FC4 own rules
def match_own_rules(rules_doc: Any, facts: Mapping[str, Any], url: str | None = None) -> list[dict[str, Any]]:
    """Own (MIT) phishing-kit/panel signatures over title, asset paths and HTML (FC4)."""
    doc, _ = load_json(rules_doc)
    rules = doc.get("rules", []) if isinstance(doc, Mapping) else []
    title = str(facts.get("title") or "")
    assets = [str(x) for x in (facts.get("script_src") or [])] + [str(h) for _r, h in (facts.get("link_href") or [])]
    page = url or facts.get("url")
    if page:
        try:
            assets.append(urllib.parse.urlsplit(str(page)).path)
        except ValueError:
            pass
    html_text = str(facts.get("html") or "")[:MAX_HTML_BYTES]
    out = []
    for r in rules if isinstance(rules, list) else []:
        if not isinstance(r, Mapping):
            continue
        hits: list[str] = []
        try:
            if title and any(re.search(rx, title, re.I) for rx in _as_list(r.get("title"))):
                hits.append("title")
            for rx in _as_list(r.get("assets")):
                if any(re.search(rx, a[:MAX_SCRIPT_SRC_CHARS], re.I) for a in assets):
                    hits.append("asset:" + rx[:80])
            if html_text and any(re.search(rx, html_text, re.I) for rx in _as_list(r.get("html"))):
                hits.append("html")
        except re.error:
            continue
        try:
            need = max(1, int(r.get("min_hits", 1) or 1))
        except (TypeError, ValueError):
            need = 1
        if hits and len(hits) >= need:
            out.append({"name": clean(str(r.get("name") or "?"), 80), "kind": "phishing_kit" if r.get("kind") == "phishing_kit" else "panel", "hits": hits})
    return out


# ============================================================================================ pipeline
def fingerprint_page(*, db: Mapping[str, Any], waf_doc: Any, rules_doc: Any, status: Any, headers: Any, body: Any, url: str,
                     dns: Mapping[str, Any] | None = None, cname_chain: Any = None, cert_issuer: str | None = None,
                     signatures: Any = None, budget_s: float = 5.0) -> dict[str, Any]:
    """One page (live or archived) -> {verdict, facts, detections, waf_cdn, own_hits, slow, budget_hit}.
    Pure: no network. The body is fingerprinted only when the verdict allows it (FC3, FC7)."""
    h = _norm(headers)
    verdict = classify_response(status, h, body, signatures)
    out: dict[str, Any] = {"verdict": verdict, "facts": {}, "detections": [], "waf_cdn": [], "own_hits": [], "slow": [], "budget_hit": False}
    if verdict["verdict"] in ("corporate_proxy", "challenge", "proxy_error"):
        return out
    out["waf_cdn"] = waf_passive_detect(waf_doc, h) + cname_attribution(cname_chain)
    facts = extract_page_facts(body, url, header_first(h, "content-type")) if verdict["fingerprint_body"] else {"url": url}
    out["facts"] = facts
    if verdict["fingerprint_headers"] or verdict["fingerprint_body"]:
        hdrs = h if verdict["fingerprint_headers"] else {}
        if not verdict["fingerprint_body"]:
            facts = {"url": url}
        m = match_technologies(db, facts, hdrs, url=url, dns=dns, cert_issuer=cert_issuer, budget_s=budget_s)
        out["detections"], out["slow"], out["budget_hit"] = m["detections"], m["slow"], m["budget_hit"]
    if verdict["fingerprint_body"]:
        out["own_hits"] = match_own_rules(rules_doc, facts, url)
    return out


BLOCK_CODES = ("challenge", "geo_block", "login_wall", "circuit", "hostile_host")


def fetch_block(fetched: Any) -> tuple[str, str, str] | None:
    """A safe-fetch answer (``light_fetch.Fetched``) that must not be read: the core classified it
    (challenge, rate limit, quota, error-in-200) or it is a block/login-wall page. Returns (status,
    reason_code, reason) - always 'could not verify', never an absence (rule 5), never retried (rule 1)
    - or None."""
    text = clean(str(getattr(fetched, "blocked", "") or ""), 200)
    if not text:
        return None
    st = str(getattr(fetched, "blocked_status", "") or "")
    if st == "rate_limited":
        return "rate_limited", "rate_limited", f"rate limited ({text}): could not verify"
    if st == "quota":
        return "quota", "quota", f"quota exhausted ({text}): could not verify"
    if st == "error":
        return "error", "error", f"error answer ({text}): could not verify"
    code = str(getattr(fetched, "blocked_code", "") or "")
    if code not in BLOCK_CODES:
        code = "login_wall" if text.startswith("login_wall") else "challenge"
    return "blocked", code, f"block page ({text}): could not verify, never retried"


def fetch_refusal(fetched: Any) -> tuple[str, str, str]:
    """(status, reason_code, reason) of a safe fetch the helper refused to send (a seed URL with a
    per-recipient token or an odd port; a redirect hop outside the analyst-typed seed, off the site,
    downgraded to http or past 5 hops): nothing was read, so never an absence."""
    reason = clean(str(getattr(fetched, "refused", "") or "refused"), 240)
    if "more than" in reason and "redirect" in reason:
        return "error", "error", f"{reason}: could not verify"
    if "outside the analyst-typed seed" in reason or "registrable domain" in reason:
        return "skipped", "scope", f"{reason} (LIGHT contact stays on the analyst-typed seed, A7): type the target as a seed to read it"
    return "skipped", "policy", reason


def safe_headers(headers: Any) -> dict[str, str]:
    """Response headers for evidence: cookie values never kept (names only), values capped."""
    out: dict[str, str] = {}
    for k, vals in _norm(headers).items():
        if k in ("set-cookie", "cookie"):
            out[k] = ", ".join(sorted(cookie_jar({"set-cookie": vals}).keys()))[:300]
        elif k not in ("authorization", "proxy-authorization"):
            out[k] = clean(", ".join(vals), 300)
    return out


def _detections_evidence(detections: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [{"name": d.get("name"), "version": d.get("version"), "confidence": d.get("confidence"), "categories": d.get("categories"),
             "evidence": d.get("evidence"), "implied_by": d.get("implied_by")} for d in detections][:200]


def emit(res: ModuleResult, ctx: Any, entity: Entity, page: Mapping[str, Any], *, live: bool, observed: str | None = None,
         final_url: str | None = None, http_status: int | None = None, hostile_hint: bool = False) -> bool:
    """Translate a :func:`fingerprint_page` result into attributes, findings and pivots. Returns True
    when something was recorded."""
    verdict = page["verdict"]
    dets = page.get("detections") or []
    facts = page.get("facts") or {}
    own_hits = page.get("own_hits") or []
    hostile = hostile_hint or any(h["kind"] == "phishing_kit" for h in own_hits)
    res.attr("fingerprint_verdict", {"verdict": verdict["verdict"], "reason": verdict.get("reason"), "vendor": verdict.get("vendor"),
                                     "http_status": http_status, "final_url": final_url})
    if http_status is not None:
        res.attr("http_status", http_status)
    if facts.get("title"):
        res.attr("title", facts["title"])
    compact = tech_list_compact(dets)
    res.attr("technologies", compact)
    waf = page.get("waf_cdn") or []
    res.attr("waf_cdn", waf)
    if waf:
        res.attr("waf", waf[0]["name"])
    cpes = []
    for d in dets:
        guess = cpe_with_version(d.get("cpe"), d.get("version"))
        if guess:
            cpes.append({"technology": d["name"], "version": d.get("version"), "cpe": guess})
    res.attr("cpe_guesses", cpes[:50])
    res.attr("own_rule_hits", own_hits)
    recorded = bool(compact or waf or own_hits or facts.get("title"))
    where = "page" if live else "archived snapshot"
    for hit in own_hits:
        if hit["kind"] == "phishing_kit":
            res.finding(
                f"Phishing-kit signature on the {where}: {hit['name']}", "high" if live else "medium",
                f"V3LUM own phishing-kit rule '{hit['name']}' matched ({', '.join(hit['hits'])})" + ("" if live else f" in the snapshot of {observed or '?'}"),
                confidence="probable", criterion="own MIT phishing-kit rule (title/asset/form-field signatures, at least min_hits parts)",
                tags=["phishing"], data=dict(hit), key=hit["name"], observed_last=observed,
            )
        else:
            res.finding(
                f"Administration panel exposed: {hit['name']}", "low" if live else "info",
                f"V3LUM own panel rule '{hit['name']}' matched ({', '.join(hit['hits'])}) on the {where}",
                confidence="probable", criterion="own MIT panel rule (title and asset-path signatures)", tags=["exposure"], data=dict(hit),
                key=hit["name"], observed_last=observed,
            )
    # FC8: version-inferred CVEs, one finding per technology
    if dets or facts.get("script_src"):
        summaries = version_cves(ctx.data, dets, facts.get("script_src") or [])
        attr_rows = []
        cve_pivots = 0
        for key, rows in summaries.items():
            tech, _sep, version = key.partition("|")
            collapsed = collapse_cves(tech, version or None, rows, hostile=hostile or not live)
            if collapsed is None:
                continue
            if collapsed["kind"] == "attribute":
                attr_rows.append(collapsed)
                continue
            tags = ["version_inferred"] + list(collapsed["labels"])
            res.finding(
                collapsed["title"], collapsed["severity"],
                f"{tech} {version} is affected by {collapsed['cve_count']} known CVE(s) according to the RetireJS repository "
                f"({', '.join(collapsed['cve_ids'][:10])}{'...' if collapsed['cve_count'] > 10 else ''}).",
                confidence=collapsed["confidence"],
                criterion="version-inferred (RetireJS ranges, CR16): distro backports and patched builds are not considered - confirm on the host",
                tags=tags, data={k: collapsed[k] for k in ("cve_ids", "cve_count", "max_cvss", "max_severity", "kev")}, key=f"{tech}@{version}",
            )
            for cve in collapsed["cve_ids"]:
                if cve_pivots < CVE_PIVOT_CAP and res.pivot(T.CVE, cve, "has_vuln", confidence="possible", expand=False,
                                                            note=f"version-inferred from {tech} {version}") is not None:
                    cve_pivots += 1
        res.attr("technology_cves", attr_rows)
    return recorded


def run_dns(ctx: Any, host: str, enabled: bool) -> dict[str, Any]:
    if not enabled or not host:
        return {"records": {}, "unverified": []}
    return dns_facts(ctx, host)


def _bundled(ctx: Any, name: str) -> Any:
    try:
        return ctx.data.bundled_json(name)
    except Exception:  # noqa: BLE001 - a missing bundled table only disables that matcher
        return {}


def _float_setting(ctx: Any, name: str, default: float) -> float:
    try:
        return float(ctx.setting(name, default))
    except (TypeError, ValueError):
        return default


def _host_of(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def target_url(entity: Entity) -> str | None:
    """The page the LIGHT fetch asks for: a domain seed's homepage (https://<domain>/) or the URL seed
    without its fragment (the core refuses per-recipient token URLs without --confirm-url)."""
    if entity.type is T.DOMAIN:
        return f"https://{entity.value.strip('.').lower()}/"
    try:
        parts = urllib.parse.urlsplit(entity.value)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _selftest(ctx: Any) -> HealthResult:
    """Offline self-test (A7): the matcher library on an in-memory page; no network at all."""
    try:
        db = build_fingerprint_db({"Selftest Server": {"cats": [22], "headers": {"Server": "^selftest/([\\d.]+)\\;version:\\1"}},
                                   "Selftest JS": {"cats": [59], "scriptSrc": ["selftest-([\\d.]+)\\.js\\;version:\\1"]}},
                                  {"22": {"name": "Web servers", "priority": 8}, "59": {"name": "JavaScript libraries", "priority": 9}})
        page = fingerprint_page(db=db, waf_doc=_bundled(ctx, BUNDLED_WAF), rules_doc=_bundled(ctx, BUNDLED_RULES), status=200,
                                headers={"Server": "selftest/1.2", "CF-Ray": "abc", "Content-Type": "text/html"},
                                body="<html><head><title>t</title><script src='/selftest-3.4.js'></script></head></html>", url="https://selftest.invalid/")
        names = {d["name"]: d["version"] for d in page["detections"]}
        if names.get("Selftest Server") != "1.2" or names.get("Selftest JS") != "3.4":
            return HealthResult("dead", f"matcher self-test failed: {names}")
        if classify_response(200, {}, "<title>Just a moment...</title>")["verdict"] != "challenge":
            return HealthResult("dead", "challenge classification self-test failed")
        return HealthResult("ok", f"matcher ok; {len(page['waf_cdn'])} WAF/CDN signature hit(s) on the sample")
    except Exception as exc:  # noqa: BLE001
        return HealthResult("dead", f"self-test error: {type(exc).__name__}: {clean(str(exc), 120)}")


# ============================================================================================ modules
_SETTINGS = {
    "web_fingerprint_dns": SettingSpec(True, "web_fingerprint: run the dns matcher (MX/TXT/NS/SOA/CNAME through ctx.dns, P072 cond 5)"),
    "web_fingerprint_match_budget": SettingSpec(5.0, "web_fingerprint: seconds of HTML pattern matching per page (P072 cond 5 time budget)"),
    "web_fingerprint_proxy_signatures": SettingSpec([], "web_fingerprint: extra corporate secure-web-gateway block-page signatures [{vendor, any: [regex]}] (P072 cond 7)"),
}


class _FingerprintBase:
    """Shared plumbing of the two P072 modules (not a module itself)."""

    def _db(self, ctx: Any, res: ModuleResult) -> dict[str, Any] | None:
        try:
            return load_fingerprint_db(ctx)
        except DatasetUnavailable as exc:
            res.mark("unavailable", str(exc), reason_code="dataset")
            return None


@register
class WebFingerprint(_FingerprintBase, Module):
    name = "web_fingerprint"
    title = "Light web fingerprint (homepage GET)"
    description = (
        "One homepage GET of an analyst-typed domain/URL (LIGHT): status, title, server, technologies from the Wappalyzer-format "
        "webappanalyzer data, passive WAF/CDN signatures, own phishing-kit/panel rules and version-inferred CVEs."
    )
    category = "url_web"
    accepts = {T.DOMAIN, T.URL}
    produces = {T.CVE, T.DOMAIN, T.ANALYTICS_ID}
    run_on = "seeds"
    reference = "https://github.com/enthec/webappanalyzer"
    notice = (
        "LIGHT: contacts the target with one normal homepage GET (browser-like ua_light, light egress profile, redirects re-checked by the "
        "core). Opt-in only (--mode light), analyst-typed seeds only. Technology data is GPL-3.0 (webappanalyzer), downloaded at runtime."
    )
    terms = "open"
    opsec = Opsec.LIGHT
    disclosure = "target"
    hosts = ()
    sources = (WA_SOURCE, RETIRE_SOURCE, KEV_SOURCE)  # datasets only: none of them receives the target
    max_requests = 12  # https (+ <= 5 hops) and, only after a connection failure, http (+ hops)
    expected_latency = 3.0
    timeout = 60.0
    min_interval = 1.0
    max_rate = 1.0
    cache_ttl = 86400
    max_pivots = 60
    default_enabled = False  # A3: LIGHT is never default
    settings = _SETTINGS

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=True, selftest=_selftest)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return target_url(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        url = target_url(entity)
        if url is None:
            return res.mark("skipped", "not an http(s) URL or a domain", reason_code="not_applicable")
        db = self._db(ctx, res)
        if db is None:
            return res
        fetched = self._fetch(ctx, entity, url)
        if fetched.refused:
            return self._refused(res, url, fetched)
        final_url = str(fetched.url or url)
        chain = list(dict.fromkeys([str(u) for u in fetched.history] + [final_url]))[:7]
        blocked = fetch_block(fetched)
        if blocked is not None and blocked[0] != "blocked":  # rate limit, quota, error-in-200: never read
            res.raw = {"request_url": url, "final_url": final_url, "status": fetched.status, "headers": safe_headers(fetched.headers),
                       "redirect_chain": chain, "blocked": clean(fetched.blocked, 300)}
            return res.mark(blocked[0], blocked[2], reason_code=blocked[1])
        signatures = proxy_signatures(ctx.setting("web_fingerprint_proxy_signatures", []))
        pre = classify_response(fetched.status, fetched.headers, fetched.body, signatures)
        base_raw = {"request_url": url, "final_url": final_url, "status": fetched.status, "headers": safe_headers(fetched.headers),
                    "redirect_chain": chain, "from_cache": bool(fetched.from_cache), "truncated": bool(fetched.truncated)}
        if pre["verdict"] in ("corporate_proxy", "challenge") or blocked is not None:
            # FC3/FC7: a challenge, block, login-wall or corporate secure-web-gateway page is never fingerprinted
            # as the target and never retried with another UA, headers or a browser
            vendor_page = pre["verdict"] in ("corporate_proxy", "challenge")
            reason = pre["reason"] if vendor_page else blocked[2]  # type: ignore[index]
            code = "challenge" if vendor_page else blocked[1]  # type: ignore[index]
            res.raw = dict(base_raw, verdict=pre, blocked=clean(fetched.blocked, 300))
            res.attr("fingerprint_verdict", {"verdict": pre["verdict"] if vendor_page else "challenge", "reason": reason,
                                             "vendor": pre["vendor"], "http_status": fetched.status, "final_url": final_url})
            return res.mark("blocked", reason, reason_code=code)
        if pre["verdict"] == "proxy_error":
            res.raw = dict(base_raw, verdict=pre)
            return res.mark("error", "proxy error page: inconclusive, could not verify", reason_code="error")
        host = _host_of(final_url) or _host_of(url)
        dns = run_dns(ctx, host, bool(ctx.setting("web_fingerprint_dns", True)))
        records = dns["records"]
        page = fingerprint_page(
            db=db, waf_doc=_bundled(ctx, BUNDLED_WAF), rules_doc=_bundled(ctx, BUNDLED_RULES), status=fetched.status, headers=fetched.headers,
            body=fetched.body, url=final_url, dns=records, cname_chain=records.get("CNAME"), signatures=signatures,
            budget_s=_float_setting(ctx, "web_fingerprint_match_budget", 5.0),
        )
        if page["slow"]:
            remember_slow(ctx, str(db.get("key") or ""), page["slow"])
        verdict = page["verdict"]
        res.raw = dict(base_raw, verdict=verdict, detections=_detections_evidence(page["detections"]), waf_cdn=page["waf_cdn"],
                       own_rule_hits=page["own_hits"], dns=records, dns_unverified=dns["unverified"], fingerprint_db=db_summary(db))
        res.attr("redirect_chain", chain if len(chain) > 1 else [])
        server = header_first(fetched.headers, "server")
        if server:
            res.attr("server", clean(server, 120))
        summary = db_summary(db)
        summary["time_budget_hit"] = bool(page["budget_hit"])
        res.attr("fingerprint_db", summary)
        recorded = emit(res, ctx, entity, page, live=True, final_url=final_url, http_status=int(fetched.status))
        self._pivots(res, url, chain, records, fetched.body if verdict["fingerprint_body"] else None, final_url, ctx)
        if verdict["verdict"] == "inconclusive":
            if not recorded:
                return res.mark("error", verdict["reason"] + ": could not verify", reason_code="error")
            res.finding("Homepage answered with an error status (fingerprint inconclusive)", "info",
                        f"{verdict['reason']}; only headers were used (WAF/CDN, server).", confidence="probable", tags=["inconclusive"],
                        key="inconclusive")
        return res

    def _fetch(self, ctx: Any, entity: Entity, url: str) -> Any:
        """One GET of the homepage through the shared safe-fetch helper (FC2): redirects followed by hand,
        at most 5 hops, each hop checked before it is sent and by the core after resolution; one cache row
        per hop shared with the other LIGHT modules. A domain seed whose https homepage cannot be reached
        at all (connection or TLS failure, not a timeout, a deadline or a proxy failure) gets one http
        attempt."""
        try:
            return fetch_homepage(ctx, entity)
        except NetworkError as exc:
            if (entity.type is not T.DOMAIN or isinstance(exc, (DeadlineExceeded, OfflineError)) or getattr(exc, "proxy_unreachable", False)
                    or getattr(exc, "reason_code", "") == "timeout"):
                raise
            return safe_get(ctx, "http://" + url[len("https://"):], accept=None, max_bytes=HOMEPAGE_MAX_BYTES, entity=entity, ttl=HOMEPAGE_TTL)

    @staticmethod
    def _refused(res: ModuleResult, url: str, fetched: Any) -> ModuleResult:
        """The helper refused to send the seed or a redirect hop: what was learnt is kept (the redirect
        chain and the refused hop as an expand=False pivot), the status says why nothing was read."""
        st, code, reason = fetch_refusal(fetched)
        refused_url = str(getattr(fetched, "refused_url", "") or "")
        answered = [str(u) for u in fetched.history] + ([str(fetched.url)] if fetched.url and refused_url != str(fetched.url) else [])
        shown = refused_url
        if refused_url:  # a hop that was never requested is recorded without its query, and without its path when it may
            try:  # carry a per-recipient token, credentials or an e-mail address (never written to evidence)
                parts = urllib.parse.urlsplit(refused_url)
                personal = "token" in reason or "credentials" in reason or "@" in urllib.parse.unquote(parts.path)
                shown = urllib.parse.urlunsplit((parts.scheme, parts.hostname or "", "/[path withheld]" if personal else parts.path, "", ""))
            except ValueError:
                shown = ""
        chain = list(dict.fromkeys(answered + ([shown] if shown else [])))[:7]
        if refused_url and answered:
            res.attr("redirect_chain", chain)
            hop = _host_of(refused_url)
            if hop and hop != _host_of(url):
                res.pivot(T.DOMAIN, hop, "redirects_to", confidence="confirmed", expand=False,
                          note="redirect target of the LIGHT homepage fetch (not followed: outside the analyst-typed seed or site)")
        res.raw = {"request_url": url, "redirect_chain": chain, "refused": reason}
        return res.mark(st, reason, reason_code=code)

    def _pivots(self, res: ModuleResult, url: str, chain: list[str], records: Mapping[str, Any], body: Any, final_url: str, ctx: Any) -> None:
        own = _host_of(url)
        for hop in chain[1:]:
            h = _host_of(hop)
            if h and h != own:
                res.pivot(T.DOMAIN, h, "redirects_to", confidence="confirmed", expand=False, note="redirect hop of the LIGHT homepage fetch")
        for cname in (records.get("CNAME") or [])[:5]:
            res.pivot(T.DOMAIN, str(cname).rstrip("."), "cname_to", confidence="confirmed", expand=False, note="CNAME of the fetched host")
        if body:
            try:
                from v3lum.modules.url_web.analytics_ids import extract_analytics_ids

                found = extract_analytics_ids(body, where="live", url=final_url, seen_at=ctx.now().isoformat())
            except Exception:  # noqa: BLE001 - optional enrichment
                return
            for item in (found.get("ids") or [])[:20]:
                if isinstance(item, Mapping) and item.get("id"):
                    res.pivot(T.ANALYTICS_ID, str(item["id"]), "same_analytics", confidence="confirmed", expand=not item.get("template"),
                              note="tracking id on the homepage" + (" (template/shared id)" if item.get("template") else ""))


@register
class WebFingerprintArchive(_FingerprintBase, Module):
    name = "web_fingerprint_archive"
    title = "Web fingerprint of the archived homepage (Wayback)"
    description = (
        "Technologies, passive WAF/CDN signatures and own phishing-kit/panel rules matched on the closest archived homepage snapshot "
        "(Wayback id_ body and its x-archive-orig headers): no contact with the target."
    )
    category = "url_web"
    accepts = {T.DOMAIN, T.URL}
    produces = {T.CVE}
    run_on = "seeds"
    tags = {"free"}
    reference = "https://archive.org/help/wayback_api.php"
    notice = (
        "Fingerprints a historical snapshot served by the Internet Archive (never the live site): technologies are dated by the capture; "
        "version-inferred CVEs of a snapshot are context, not findings. Technology data is GPL-3.0 (webappanalyzer), downloaded at runtime."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "internet_archive"
    sources = (SRC_WAYBACK, WA_SOURCE, RETIRE_SOURCE, KEV_SOURCE)
    hosts = ("archive.org", "web.archive.org")
    access_model = "free_noauth_limited"
    max_requests = 4  # availability + id_ snapshot (+ archive-internal redirects)
    expected_latency = 8.0
    timeout = 45.0
    cache_ttl = 7 * 86400
    max_pivots = 30
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return target_url(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        from v3lum.modules.url_web.web_archives import archive_snapshot_url, parse_wayback_available, query_target

        res = self.result(entity)
        q = query_target(entity)
        if q is None:
            return res.mark("skipped", "not an http(s) URL or a domain", reason_code="not_applicable")
        db = self._db(ctx, res)
        if db is None:
            return res
        homepage = q["homepage"] if q["kind"] == "domain" else q["query"]
        resp = ctx.http.get(WAYBACK_AVAILABLE, params={"url": homepage}, source=SRC_WAYBACK)
        if resp.classification is not None:
            ctx.http.check(resp)
        if resp.status >= 400:
            return res.mark("error", f"Wayback availability API HTTP {resp.status}: archive unreachable, could not verify", reason_code="error")
        parsed = parse_wayback_available(resp.content)
        if parsed["state"] == "error":
            return res.mark("error", f"Wayback availability: {parsed['error']} (could not verify)", reason_code="error")
        closest = parsed.get("closest")
        if parsed["state"] == "empty" or not closest:
            res.attr("archive_snapshot", {"url": None, "captured_at": None, "status": "no capture of this URL", "source": "wayback"})
            return res.mark("empty")
        raw_url = closest.get("raw_snapshot") or archive_snapshot_url("wayback", closest.get("timestamp"), homepage)
        if not raw_url:
            # a capture exists but its URL carries credentials/tokens/e-mails (P059 c7): never fetched, not an absence
            return res.mark("skipped", "the closest snapshot URL carries secrets or personal identifiers: not fetched", reason_code="policy")
        snap = ctx.http.get(raw_url, source=SRC_WAYBACK, max_bytes=FETCH_MAX_BYTES)
        if snap.classification is not None:
            ctx.http.check(snap)
        orig = archive_original_headers(snap.headers)
        captured = closest.get("captured_at")
        res.attr("archive_snapshot", {"url": closest.get("snapshot_url"), "captured_at": captured, "status": closest.get("status"), "source": "wayback"})
        if snap.status >= 500:
            return res.mark("error", f"archived snapshot HTTP {snap.status}: archive unreachable, could not verify", reason_code="error")
        page = fingerprint_page(db=db, waf_doc=_bundled(ctx, BUNDLED_WAF), rules_doc=_bundled(ctx, BUNDLED_RULES), status=snap.status,
                                headers=orig["headers"], body=snap.content, url=homepage, budget_s=_float_setting(ctx, "web_fingerprint_match_budget", 5.0))
        if page["slow"]:
            remember_slow(ctx, str(db.get("key") or ""), page["slow"])
        res.raw = {"snapshot": closest.get("snapshot_url"), "captured_at": captured, "memento_datetime": orig["memento_datetime"],
                   "archive_status": snap.status, "original_headers": safe_headers(orig["headers"]), "verdict": page["verdict"],
                   "detections": _detections_evidence(page["detections"]), "waf_cdn": page["waf_cdn"], "own_rule_hits": page["own_hits"],
                   "fingerprint_db": db_summary(db)}
        verdict = page["verdict"]
        if verdict["verdict"] in ("corporate_proxy", "challenge", "proxy_error"):
            # an archived block/challenge page says nothing about the site's stack: the closest capture could not
            # be fingerprinted, which is 'could not verify', never 'no technologies' (rule 5)
            res.attr("fingerprint_verdict", {"verdict": verdict["verdict"], "reason": verdict["reason"], "vendor": verdict["vendor"],
                                             "http_status": snap.status, "final_url": closest.get("snapshot_url")})
            return res.mark("error", f"the closest archived snapshot is a {verdict['verdict'].replace('_', ' ')} page: inconclusive, could not verify",
                            reason_code="error")
        summary = db_summary(db)
        summary["time_budget_hit"] = bool(page["budget_hit"])
        res.attr("fingerprint_db", summary)
        server = header_first(orig["headers"], "server")
        if server:
            res.attr("server", clean(server, 120))
        recorded = emit(res, ctx, entity, page, live=False, observed=captured, final_url=closest.get("snapshot_url"), http_status=int(snap.status))
        if not recorded and verdict["verdict"] == "inconclusive":
            return res.mark("error", f"the closest archived snapshot answered HTTP {snap.status}: inconclusive, could not verify", reason_code="error")
        return res


__all__ = [
    "WebFingerprint", "WebFingerprintArchive", "archive_original_headers", "build_fingerprint_db", "budget_screen", "classify_response",
    "cname_attribution", "collapse_cves", "compile_wa_pattern", "cookie_jar", "cpe_with_version", "decode_body", "extract_page_facts",
    "fingerprint_page", "js_regex_to_python", "load_fingerprint_db", "match_own_rules", "match_technologies", "normalise_headers",
    "proxy_signatures", "redos_suspect", "resolve_version", "split_wa_pattern", "tech_list_compact", "waf_passive_detect",
]
