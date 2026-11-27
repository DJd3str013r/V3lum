"""Favicon hashes (P062, batch p9-G03-1): ``favicon_hash`` (PASSIVE, default) and ``favicon_fetch``
(LIGHT, opt-in) over one hashing core.

Final conditions (P062) and where they live:

1. One pure-Python MurmurHash3 helper (``mmh3_32`` / ``shodan_favicon_hash`` of archive_mining, P060:
   mmh3 over ``base64.encodebytes`` with the trailing newline; Shodan test vector Google favicon ->
   708578229, see the tests) plus MD5 and SHA-256 of the bytes (:func:`favicon_hashes`). archive_mining
   and this file share it; the engine pivot links (:func:`engine_pivot_links`) use its output.
2. ``favicon_hash`` (PASSIVE, default): the newest archived ``/favicon.ico`` of the site from the
   Wayback Machine (the CDX query of the P059/P060 client, then one raw ``id_`` snapshot - the live
   site is never contacted) and typed ``favicon_hash`` values, hashed into engine pivot links. urlscan
   results already in a case are not reachable by a module (no case-data API): backlog p9-G03-1.
3. ``favicon_fetch`` (LIGHT, default_enabled=False): one GET of the icon, analyst-typed seeds only
   (``run_on='seeds'`` and the core LIGHT seed binding), after the entity's passive lane and through
   the hostile-host guard (engine two-phase scheduling, P376), counted in the LIGHT budget (core: 25
   requests per target host per scan, 1 req/s).
4. The icon URL comes from ``<link rel=icon>`` on the shared homepage fetch (``light_fetch``) or
   ``/favicon.ico``, and is fetched only through the safe-fetch helper: http/https, ports 80/443,
   same registrable domain (or a listed CDN suffix, setting ``favicon_fetch_cdn_suffixes``) and inside
   the seed, every redirect hop re-checked, public addresses only (core SSRF guard after resolution),
   1 MB cap, an image content type and image magic bytes (:func:`classify_favicon_response`).
5. The bundled default/blank favicon list (``v3lum/data/favicon_hash/favicon_defaults.json``: nuclei
   favicon-detect, MIT, plus computed blank icons; web servers, CMS, hosting panels, routers, platforms)
   marks noise: recorded (attribute ``favicon_noise``), never pivoted. A hash a keyed engine reports
   on more than 1,000 hosts is noise too (:func:`favicon_noise`, ``reported_hosts``).
6. Engine pivot links (Shodan, FOFA, Criminal IP, Netlas, ZoomEye) for every hash; reverse queries
   happen only in enabled keyed engine modules (shodan_api accepts favicon_hash seeds) and are
   hypotheses: relation ``similar_favicon`` (registered by this batch), expand=False, never scope.
7. Tests: the recorded design_pivots_and_js shape, the Shodan test vector, a default-favicon
   suppression and hostile hrefs refused by the safe fetch (tests/modules/test_favicon_*.py).

Engine URL templates follow the research row C0634 (favihunter engines.yaml, MIT, attribution in the
notice fragment ``js_endpoints_design_refs``); the Criminal IP and ZoomEye syntaxes are unverified.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

from v3lum.config import SettingSpec
from v3lum.core.datasets import DataStore
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
)
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, HealthResult, Module, register
from v3lum.modules.url_web.archive_mining import distinct_versions, mmh3_32, parse_cdx_rows, shodan_favicon_hash
from v3lum.modules.url_web.light_fetch import (
    Fetched,
    attrs,
    base_for,
    check_target,
    internal_seed_hosts,
    content_type,
    detect_block,
    fetch_homepage,
    looks_like_html,
    mask_text_urls,
    masked_url,
    safe_get,
    to_text,
)
from v3lum.modules.url_web.web_archives import (
    CDX,
    SRC_CDX,
    SRC_WAYBACK,
    archive_snapshot_url,
    failure,
    report_failure,
    wayback_ts_to_iso,
)

__all__ = [
    "DEFAULTS_FILE",
    "ENGINE_TEMPLATES",
    "FaviconFetch",
    "FaviconHash",
    "classify_favicon_response",
    "emit_favicon",
    "engine_pivot_links",
    "extract_icon_links",
    "favicon_hashes",
    "favicon_noise",
    "load_favicon_defaults",
    "mmh3_32",
    "parse_favicon_hash_input",
    "shodan_favicon_hash",
    "sniff_image",
]

DEFAULTS_FILE = "favicon_hash/favicon_defaults.json"
MAX_FAVICON_BYTES = 1_048_576  # P062 c4
MASS_THRESHOLD = 1000  # P062 c5: a hash reported on more than 1,000 hosts is noise
CURRENT_DAYS = 365  # an archived favicon newer than this is read as the site's current icon
ICON_ACCEPT = "image/avif,image/webp,image/png,image/x-icon,image/*;q=0.9,*/*;q=0.5"

# ======================================================================================
# hashing (c1)
# ======================================================================================


def sniff_image(data: bytes) -> str | None:
    """Image format from the magic bytes ('ico', 'png', 'gif', 'jpeg', 'webp', 'bmp', 'svg') or None."""
    head = bytes(data or b"")[:512]
    if head.startswith((b"\x00\x00\x01\x00", b"\x00\x00\x02\x00")):
        return "ico"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "webp"
    if head.startswith(b"BM"):
        return "bmp"
    low = head.lstrip().lower()
    if low.startswith(b"<svg") or (low.startswith(b"<?xml") and b"<svg" in low):
        return "svg"
    return None


def favicon_hashes(data: bytes) -> dict[str, Any]:
    """Shodan-compatible mmh3 (signed int32 over base64.encodebytes, trailing newline included) plus
    MD5 and SHA-256 of the raw bytes, the size and the sniffed format (c1)."""
    raw = bytes(data or b"")
    mmh3 = shodan_favicon_hash(raw)
    return {
        "mmh3": mmh3,
        "mmh3_hex_unsigned": format(mmh3 & 0xFFFFFFFF, "08x"),
        "md5": hashlib.md5(raw).hexdigest(),  # noqa: S324 - an identifier the engines index, not security
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "format": sniff_image(raw),
    }


def parse_favicon_hash_input(value: Any) -> dict[str, Any] | None:
    """A typed favicon hash -> {'mmh3': signed int} | {'md5': hex} | {'sha256': hex} | None. Accepts
    signed or unsigned decimal and the engine prefixes 'http.favicon.hash:', 'icon_hash=', 'iconhash:'."""
    text = str(value or "").strip()
    text = re.sub(r"^(?:http\.favicon\.hash:|icon_hash=|iconhash:|favicon:)", "", text, flags=re.I).strip("\"' ")
    if re.fullmatch(r"-?\d{1,10}", text):
        n = int(text)
        if -(2**31) <= n < 2**32:
            return {"mmh3": n - 2**32 if n >= 2**31 else n}
        return None
    if re.fullmatch(r"[0-9a-fA-F]{32}", text):
        return {"md5": text.lower()}
    if re.fullmatch(r"[0-9a-fA-F]{64}", text):
        return {"sha256": text.lower()}
    return None


# ======================================================================================
# noise (c5)
# ======================================================================================

_DEFAULTS_CACHE: dict[str, dict[int, dict[str, Any]]] = {}


def load_favicon_defaults(data: Any = None) -> dict[int, dict[str, Any]]:
    """Index of the bundled default/blank favicon list by mmh3 (``data`` overrides the bundled file)."""
    if data is None:
        cached = _DEFAULTS_CACHE.get("bundled")
        if cached is not None:
            return cached
        try:
            data = DataStore.bundled_json(DEFAULTS_FILE)
        except (OSError, ValueError):
            data = {}
    out: dict[int, dict[str, Any]] = {}
    entries = data.get("entries") if isinstance(data, Mapping) else None
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, Mapping):
            continue
        try:
            out.setdefault(int(entry["mmh3"]), dict(entry))
        except (KeyError, TypeError, ValueError):
            continue
    if isinstance(data, Mapping) and entries is not None and "bundled" not in _DEFAULTS_CACHE:
        _DEFAULTS_CACHE["bundled"] = out
    return out


def favicon_noise(mmh3: int, defaults: Mapping[int, Mapping[str, Any]] | None = None, reported_hosts: Any = None,
                  threshold: int = MASS_THRESHOLD) -> dict[str, Any] | None:
    """c5: why a hash is noise ({reason: blank | default | mass, name, category, hosts}) or None.
    Product entries of the list (C2 panels, appliances) are labels, not noise: they stay pivotable."""
    entry = (defaults or {}).get(int(mmh3))
    if entry and entry.get("noise", True):
        reason = "blank" if entry.get("category") == "blank" else "default"
        return {"reason": reason, "name": str(entry.get("name") or ""), "category": str(entry.get("category") or "")}
    try:
        if reported_hosts is not None and int(reported_hosts) > threshold:
            return {"reason": "mass", "name": "", "category": "mass", "hosts": int(reported_hosts)}
    except (TypeError, ValueError):
        pass
    return None


# ======================================================================================
# engine pivot links (c6) - favihunter engines.yaml templates (MIT), research row C0634
# ======================================================================================


def _b64(text: str) -> str:
    return quote(base64.b64encode(text.encode("utf-8")).decode("ascii"), safe="")


ENGINE_TEMPLATES: dict[str, tuple[str, str, Any]] = {
    "shodan": ("Shodan: hosts serving this favicon (http.favicon.hash)", "mmh3",
               lambda h: f"https://www.shodan.io/search?query=http.favicon.hash%3A{h}"),
    "fofa": ("FOFA: hosts serving this favicon (icon_hash)", "mmh3",
             lambda h: "https://en.fofa.info/result?qbase64=" + _b64(f'icon_hash="{h}"')),
    "criminalip": ("Criminal IP: assets with this favicon", "mmh3",
                   lambda h: f"https://search.criminalip.io/asset/search?query=favicon%3A+{h}"),
    "netlas": ("Netlas: responses with this favicon (SHA-256)", "sha256",
               lambda h: f"https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A{h}"),
    "zoomeye": ("ZoomEye: hosts with this favicon (iconhash)", "mmh3",
                lambda h: f"https://www.zoomeye.ai/searchResult?q=iconhash%3A%22{h}%22"),
}
DEFAULT_ENGINES = ("shodan", "fofa", "criminalip", "netlas", "zoomeye")


def engine_pivot_links(hashes: Mapping[str, Any], engines: tuple[str, ...] = DEFAULT_ENGINES) -> list[dict[str, str]]:
    """c6: manual engine links for one favicon (never requested). Engines whose hash kind is unknown
    (Netlas needs the SHA-256 of the bytes) are skipped."""
    out = []
    for name in engines:
        label, kind, template = ENGINE_TEMPLATES[name]
        value = hashes.get(kind)
        if value is None or value == "":
            continue
        out.append({"engine": name, "label": label, "hash_kind": kind, "url": template(value)})
    return out


# ======================================================================================
# icon links and responses (c4)
# ======================================================================================

_LINK_TAG_RE = re.compile(r"<link\b[^<>]{0,2048}>", re.I)
_ICON_RELS = {"icon", "apple-touch-icon", "apple-touch-icon-precomposed", "mask-icon", "fluid-icon"}


def extract_icon_links(html: Any, page_url: str) -> dict[str, list[dict[str, Any]]]:
    """Icon candidates of a page: ``rel=icon`` first, then apple-touch icons, then ``/favicon.ico``
    (``<base href>`` honoured). data: URIs, SVG/mask icons and non-http schemes are skipped. Hostile
    pages control these hrefs: every candidate still goes through :func:`check_target` before a GET."""
    text = to_text(html, 2 * 1024 * 1024)
    base = base_for(text, page_url)
    primary: list[dict[str, Any]] = []
    secondary: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for found in _LINK_TAG_RE.finditer(text):
        tag = attrs(found.group(0))
        rels = set((tag.get("rel") or "").lower().split())
        if not rels & _ICON_RELS:
            continue
        href = tag.get("href") or ""
        if not href:
            continue
        if href.lower().startswith("data:"):
            skipped.append({"href": "data:...", "reason": "data URI (not fetched)"})
            continue
        try:
            url = urljoin(base, href)
            scheme = urlsplit(url).scheme
        except ValueError:
            skipped.append({"href": href[:200], "reason": "unparsable href"})
            continue
        if scheme not in ("http", "https"):
            skipped.append({"href": href[:200], "reason": f"scheme {scheme or 'none'} (http/https only)"})
            continue
        kind = (tag.get("type") or "").lower()
        if "mask-icon" in rels or kind == "image/svg+xml" or urlsplit(url).path.lower().endswith(".svg"):
            skipped.append({"href": href[:200], "reason": "SVG icon (not hashed)"})
            continue
        entry = {"url": url, "rel": " ".join(sorted(rels)), "type": kind or None, "source": "link"}
        (primary if "icon" in rels else secondary).append(entry)
    default = {"url": urljoin(page_url, "/favicon.ico"), "rel": None, "type": None, "source": "default"}
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in [*primary, *secondary, default]:
        if entry["url"] not in seen:
            seen.add(entry["url"])
            out.append(entry)
    return {"candidates": out, "skipped": skipped}


def classify_favicon_response(status: Any, headers: Any, body: bytes, *, max_bytes: int = MAX_FAVICON_BYTES,
                              allow_octet_stream: bool = False) -> tuple[str | None, str | None]:
    """c4: (format, None) when the answer is a hashable icon, else (None, reason): status 200, an
    ``image/*`` content type (``application/octet-stream`` only with ``allow_octet_stream`` and image
    magic bytes), image magic bytes, non-empty, at most 1 MB; challenge pages, HTML/JSON error bodies
    and SVG are refused (a JSON 403 is never hashed)."""
    block = detect_block(status, headers, body[:65536] if body else b"")
    if block:
        return None, block
    try:
        st = int(status)
    except (TypeError, ValueError):
        return None, "no status"
    if st != 200:
        return None, f"HTTP {st}"
    raw = bytes(body or b"")
    if not raw:
        return None, "empty body"
    if len(raw) > max_bytes:
        return None, f"larger than {max_bytes} bytes"
    ctype = content_type(headers)
    fmt = sniff_image(raw)
    if not ctype.startswith("image/") and not (allow_octet_stream and ctype in ("application/octet-stream", "") and fmt not in (None, "svg")):
        return None, f"content type {ctype or 'none'} (not an image)"
    if fmt is None:
        return None, "the body is not an image"
    if fmt == "svg":
        return None, "SVG icon (not hashed)"
    return fmt, None


# ======================================================================================
# output shared by both modules
# ======================================================================================


def emit_favicon(res: ModuleResult, hashes: Mapping[str, Any], *, source: Mapping[str, Any], relation: str = "favicon",
                 confidence: str = "probable", expand: bool = True, defaults: Mapping[int, Mapping[str, Any]] | None = None,
                 links: bool = True) -> dict[str, Any] | None:
    """Attributes, the favicon_hash pivot (none for noise, c5) and the engine links (c6)."""
    mmh3 = hashes.get("mmh3")
    noise = favicon_noise(int(mmh3), defaults if defaults is not None else load_favicon_defaults()) if mmh3 is not None else None
    record = {k: hashes.get(k) for k in ("mmh3", "mmh3_hex_unsigned", "md5", "sha256", "size", "format") if hashes.get(k) is not None}
    record.update({k: v for k, v in source.items() if v not in (None, "")})
    res.attr("favicon", record)
    if mmh3 is not None:
        res.attr("favicon_mmh3", int(mmh3))
        entry = (defaults if defaults is not None else load_favicon_defaults()).get(int(mmh3))
        if entry and not entry.get("noise", True):
            res.attr("favicon_product", {"name": str(entry.get("name") or ""), "category": str(entry.get("category") or ""),
                                         "source": str(entry.get("source") or "")})
    if noise:
        res.attr("favicon_noise", noise)
    elif mmh3 is not None:
        res.pivot(T.FAVICON_HASH, str(int(mmh3)), relation, confidence=confidence, expand=expand,
                  note="" if expand else "historical favicon: listed, not investigated")
    if links:
        for link in engine_pivot_links(hashes):
            res.link(link["label"], link["url"])
    return noise


def _failure_mark(res: ModuleResult, outcome: Mapping[str, Any]) -> ModuleResult:
    status = str(outcome.get("status"))
    reason = str(outcome.get("reason") or "could not verify")
    code = str(outcome.get("reason_code") or "")
    if status == "rate_limited":
        return res.mark("rate_limited", f"could not verify: {reason}", reason_code="rate_limited")
    if status == "quota":
        return res.mark("quota", f"could not verify: {reason}", reason_code="quota")
    if status == "blocked":
        return res.mark("blocked", f"could not verify: {reason}", reason_code=code or "challenge")
    return res.mark("error", f"could not verify: {reason}", reason_code="timeout" if code == "timeout" else "error")


_ARCHIVE_ERRORS = (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError, DeadlineExceeded)


# ======================================================================================
# favicon_hash (PASSIVE, default)
# ======================================================================================


@register
class FaviconHash(Module):
    name = "favicon_hash"
    title = "Favicon hash (Shodan mmh3, MD5, SHA-256) from archived snapshots and typed hashes"
    description = (
        "Hashes the newest archived /favicon.ico of a site (Wayback Machine CDX + raw id_ snapshot; the live site is never "
        "contacted) or a typed favicon hash, flags default/blank icons as noise and adds Shodan, FOFA, Criminal IP, Netlas "
        "and ZoomEye pivot links."
    )
    category = "url_web"
    accepts = {T.URL, T.DOMAIN, T.FAVICON_HASH}
    produces = {T.FAVICON_HASH}
    tags = {"free"}
    reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/technologies/favicon-detect.yaml"
    terms = "open"  # P062: Internet Archive, tier trusted, terms open; own code; links only
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # the Internet Archive sees the site's favicon URL
    provider = "internet_archive"
    sources = (SRC_CDX, SRC_WAYBACK)
    hosts = ("web.archive.org",)
    access_model = "free_noauth_limited"
    max_requests = 2  # one CDX listing (shared with archive_mining through the HTTP cache) + one id_ snapshot
    expected_latency = 7.0  # the provider quota paces Wayback at one request per 5 s
    timeout = 40.0
    cache_ttl = 86400
    max_pivots = 1
    default_enabled = True
    notice = (
        "Archive hosts only: the live site is never contacted (favicon_fetch is the LIGHT opt-in). Engine links are manual "
        "pivots; Shodan/ZoomEye/Criminal IP pages may need the analyst's own account. Default favicon list: nuclei-templates "
        "favicon-detect (MIT, Copyright (c) ProjectDiscovery)."
    )

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type is T.FAVICON_HASH:
            return self._typed(res, entity)
        host = (urlsplit(entity.value).hostname or "") if entity.type is T.URL else entity.value
        host = host.lower().strip(".")
        if not host:
            return res.mark("skipped", "no host in the input", reason_code="not_applicable")
        return self._archived(res, ctx, host)

    # ---- typed favicon_hash: no request (c2, c6) --------------------------------------------------
    @staticmethod
    def _typed(res: ModuleResult, entity: Entity) -> ModuleResult:
        parsed = parse_favicon_hash_input(entity.value)
        if not parsed or "mmh3" not in parsed:
            return res.mark("error", "not a Shodan-style favicon hash (signed or unsigned 32-bit mmh3)", reason_code="error")
        mmh3 = int(parsed["mmh3"])
        hashes = {"mmh3": mmh3, "mmh3_hex_unsigned": format(mmh3 & 0xFFFFFFFF, "08x")}
        defaults = load_favicon_defaults()
        res.attr("favicon_mmh3", mmh3)
        noise = favicon_noise(mmh3, defaults)
        entry = defaults.get(mmh3)
        if noise:
            res.attr("favicon_noise", noise)
        elif entry:
            res.attr("favicon_product", {"name": str(entry.get("name") or ""), "category": str(entry.get("category") or ""),
                                         "source": str(entry.get("source") or "")})
        for link in engine_pivot_links(hashes):
            res.link(link["label"], link["url"])
        return res

    # ---- archived favicon (c2) ----------------------------------------------------------------------
    def _archived(self, res: ModuleResult, ctx: Any, host: str) -> ModuleResult:
        # the same CDX query as archive_mining (P060): an identical request is served from the HTTP cache
        params: list[tuple[str, str]] = [("url", f"{host}/favicon.ico"), ("output", "json"),
                                         ("fl", "timestamp,original,digest,statuscode,mimetype"), ("filter", "statuscode:200"),
                                         ("filter", "!mimetype:warc/revisit"), ("collapse", "digest"), ("limit", "500")]
        try:
            resp = ctx.http.get(CDX, params=params, source=SRC_CDX, ttl=86400, max_bytes=2 * 1024 * 1024)
            ctx.http.check(resp)
        except _ARCHIVE_ERRORS as exc:
            out = failure("wayback_favicon_versions", exc)
            report_failure(res, SRC_CDX, out)
            return _failure_mark(res, out)
        parsed = parse_cdx_rows(resp.content)
        if parsed["state"] == "error":
            return res.mark("error", f"could not verify: Wayback CDX answer unusable ({parsed['error']})", reason_code="error")
        versions = distinct_versions(parsed["rows"], by="digest")
        if not versions:
            res.attr("archive_sources", {"wayback_favicon_versions": "empty (no capture of /favicon.ico)"})
            return res.mark("empty")  # the archive holds no capture: never 'the site has no favicon'
        newest = max(versions, key=lambda v: str(v.get("last_ts") or ""))
        snapshot = archive_snapshot_url("wayback", str(newest.get("last_ts") or ""), newest.get("url"))
        if not snapshot:
            return res.mark("error", "could not verify: the archived favicon URL cannot be replayed safely", reason_code="error")
        try:
            body_resp = ctx.http.get(snapshot, source=SRC_WAYBACK, ttl=86400, max_bytes=MAX_FAVICON_BYTES + 1)
            ctx.http.check(body_resp)
        except _ARCHIVE_ERRORS as exc:
            out = failure("wayback_favicon_snapshot", exc)
            report_failure(res, SRC_WAYBACK, out)
            return _failure_mark(res, out)
        body = bytes(body_resp.content or b"")
        if len(body) > MAX_FAVICON_BYTES or body_resp.truncated:
            return res.mark("error", "could not verify: the archived favicon is larger than 1 MB (not hashed)", reason_code="error")
        fmt = sniff_image(body)
        if fmt is None:
            what = "an HTML page (archive error or soft 404)" if looks_like_html(body) else "not an image"
            return res.mark("error", f"could not verify: the Wayback snapshot of /favicon.ico is {what}", reason_code="error")
        captured = wayback_ts_to_iso(str(newest.get("last_ts") or ""))
        versions_seen = len(versions)
        if fmt == "svg":
            res.attr("favicon", {"format": "svg", "source": "wayback", "snapshot": captured, "versions": versions_seen,
                                 "note": "SVG icon: not hashed (Shodan hashes raster icons)"})
            return res
        hashes = favicon_hashes(body)
        current = _is_recent(captured, ctx)
        emit_favicon(res, hashes, source={"source": "wayback", "snapshot": captured, "versions": versions_seen,
                                          "archived_url": snapshot},
                     relation="favicon" if current else "historical_favicon", confidence="probable" if current else "possible",
                     expand=current)
        res.raw = {"cdx_rows": len(parsed["rows"]), "versions": versions_seen, "snapshot": snapshot,
                   "sha256": hashes["sha256"], "bytes": hashes["size"]}
        return res


def _is_recent(captured: str | None, ctx: Any) -> bool:
    if not captured:
        return False
    try:
        when = datetime.strptime(captured, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        now = ctx.now()
    except (ValueError, TypeError, AttributeError):
        return False
    return (now - when).days <= CURRENT_DAYS


# ======================================================================================
# favicon_fetch (LIGHT, opt-in)
# ======================================================================================


def _selftest(ctx: Any) -> HealthResult:
    """Offline self-test: the MurmurHash3 reference vectors and the blank-GIF default entry."""
    if mmh3_32(b"foo") != -156908512 or mmh3_32(b"hello") != 613153351:
        return HealthResult("dead", "MurmurHash3 reference vectors do not match")
    gif = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
    noise = favicon_noise(shodan_favicon_hash(gif), load_favicon_defaults())
    if not noise:
        return HealthResult("dead", "bundled default favicon list unreadable")
    return HealthResult("ok", "hash vectors and default list ok")


def _mark_blocked(res: ModuleResult, fetched: Fetched, what: str) -> ModuleResult:
    """A classified or block-page answer: could not verify, never 'no favicon' (rule 5, A9)."""
    status = fetched.blocked_status
    if status == "rate_limited":
        return res.mark("rate_limited", f"could not verify: {what} rate limited ({fetched.blocked})", reason_code="rate_limited")
    if status == "quota":
        return res.mark("quota", f"could not verify: {what}: {fetched.blocked}", reason_code="quota")
    if status == "error":
        return res.mark("error", f"could not verify: {what}: {fetched.blocked}", reason_code="error")
    code = fetched.blocked_code if fetched.blocked_code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge"
    if fetched.blocked.startswith("login_wall"):
        code = "login_wall"
    return res.mark("blocked", f"could not verify: {what} answered a block page ({fetched.blocked})", reason_code=code)


@register
class FaviconFetch(Module):
    name = "favicon_fetch"
    title = "Favicon fetch (LIGHT): one GET of the site's icon, hashed like Shodan"
    description = (
        "LIGHT, analyst-typed seeds only: reads <link rel=icon> on the shared homepage fetch (or /favicon.ico) and makes one "
        "safe GET of the icon (same site, public addresses, 1 MB, image types only), then hashes it (Shodan mmh3, MD5, "
        "SHA-256) with engine pivot links."
    )
    category = "url_web"
    accepts = {T.URL, T.DOMAIN}
    produces = {T.FAVICON_HASH}
    run_on = "seeds"
    tags = {"free"}
    reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/technologies/favicon-detect.yaml"
    terms = "open"
    opsec = Opsec.LIGHT
    disclosure = "target"
    hosts = ()
    max_requests = 8  # shared homepage GET (cache hit when another LIGHT module fetched it) + redirect hops + one icon GET
    expected_latency = 2.0
    timeout = 45.0
    min_interval = 1.0
    max_rate = 1.0
    cache_ttl = 86400
    max_pivots = 1
    default_enabled = False  # LIGHT is never default (A3); not enabled before the AR20 safety suite passes
    notice = (
        "LIGHT: contacts the target (homepage + one icon GET) with the ua_light browser UA, on analyst-typed seeds only, after "
        "the passive lane and through the hostile-host guard. Prefer favicon_hash (archived, PASSIVE)."
    )
    settings = {
        "favicon_fetch_cdn_suffixes": SettingSpec([], "favicon_fetch: CDN host suffixes of the site allowed for the icon (still inside the seed: LIGHT binding)"),
        "favicon_fetch_octet_stream": SettingSpec(False, "favicon_fetch: also hash icons served as application/octet-stream when the magic bytes are an image"),
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
            return _mark_blocked(res, page, "the homepage")
        site_host = (urlsplit(page.url).hostname or "").lower()
        html = page.body if (200 <= page.status < 300 and looks_like_html(page.body)) else b""
        icons = extract_icon_links(html, page.url) if html else {"candidates": [{"url": urljoin(page.url, "/favicon.ico"), "source": "default"}],
                                                                  "skipped": []}
        cdns = ctx.setting("favicon_fetch_cdn_suffixes", []) or []
        cdns = [str(c) for c in cdns] if isinstance(cdns, list) else []
        refused: list[dict[str, Any]] = list(icons["skipped"])
        if page.refused:
            # the homepage answered a redirect the safe fetch does not follow (another site, a downgrade, a token
            # URL): nothing was sent there; the icon is still looked up on the seed itself (/favicon.ico)
            refused.append({"href": (page.refused_url or page.url)[:200], "reason": page.refused[:300]})
        allowed: list[dict[str, Any]] = []
        for cand in icons["candidates"]:
            why = check_target(cand["url"], site_host=site_host, seed_hosts=_seed_hosts(entity), cdn_suffixes=cdns,
                               allowed_ports=_ports(entity), internal_hosts=internal_seed_hosts(ctx, entity))
            if why:
                refused.append({"href": cand["url"][:200], "reason": why})
            else:
                allowed.append(cand)
        res.raw = {"homepage": {"url": masked_url(page.url), "status": page.status, "from_cache": page.from_cache, "hops": len(page.history)}}
        icon: Fetched | None = None
        chosen: dict[str, Any] | None = None
        for cand in allowed[:3]:
            before = int(getattr(ctx.http, "requests", 0) or 0)
            try:
                fetched = safe_get(ctx, cand["url"], accept=ICON_ACCEPT, max_bytes=MAX_FAVICON_BYTES, entity=entity, site_host=site_host,
                                   cdn_suffixes=cdns, max_hops=2)
            except PolicyError as exc:
                # refused by the core (SSRF guard after resolution, guard, scope) before anything was sent
                refused.append({"href": cand["url"][:200], "reason": f"refused by the core safe-fetch rules: {str(exc)[:200]}"})
                if int(getattr(ctx.http, "requests", 0) or 0) != before:
                    raise
                continue
            if fetched.refused and int(getattr(ctx.http, "requests", 0) or 0) == before:
                refused.append({"href": (fetched.refused_url or cand["url"])[:200], "reason": fetched.refused})
                continue
            icon, chosen = fetched, cand
            break  # one icon GET (c3): the first candidate that was actually requested decides
        if refused:
            res.attr("favicon_refused_hrefs", _masked_refusals(refused[:20]))
        res.raw["refused_hrefs"] = _masked_refusals(refused[:20])
        if icon is None or chosen is None:
            # the safe-fetch rules refused every candidate: could not verify, never 'the site has no favicon'
            return res.mark("skipped", "no icon URL the safe fetch allows (every candidate refused, nothing requested)",
                            reason_code="policy")
        if icon.refused:
            refused.append({"href": (icon.refused_url or chosen["url"])[:200], "reason": icon.refused})
            res.attr("favicon_refused_hrefs", _masked_refusals(refused[:20]))
            res.raw["refused_hrefs"] = _masked_refusals(refused[:20])
            return res.mark("skipped", f"icon not fetched: {mask_text_urls(icon.refused)}", reason_code="policy")
        if icon.blocked:
            return _mark_blocked(res, icon, "the icon URL")
        allow_octet = bool(ctx.setting("favicon_fetch_octet_stream", False))
        fmt, why = classify_favicon_response(icon.status, icon.headers, icon.body if not icon.truncated else icon.body + b"x",
                                             allow_octet_stream=allow_octet)
        res.raw["icon"] = {"url": masked_url(icon.url), "status": icon.status, "content_type": content_type(icon.headers), "bytes": len(icon.body),
                           "candidate": chosen.get("source")}
        if fmt is None:
            if icon.status in (401, 403, 407, 451):
                return res.mark("blocked", f"could not verify: the icon URL answered HTTP {icon.status}", reason_code="challenge")
            if icon.status == 429:
                return res.mark("rate_limited", "could not verify: the icon URL answered HTTP 429", reason_code="rate_limited")
            if icon.status >= 500 or icon.status == 0:
                return res.mark("error", f"could not verify: the icon URL answered HTTP {icon.status}", reason_code="error")
            return res.mark("empty", f"no hashable icon at {icon.url}: {why}")
        hashes = favicon_hashes(icon.body)
        emit_favicon(res, hashes, source={"source": "live", "url": icon.url, "candidate": chosen.get("source")},
                     relation="favicon", confidence="probable", expand=True)
        res.raw["icon"]["sha256"] = hashes["sha256"]
        return res


def _masked_refusals(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Refused hrefs as stored: hostile pages control them, so e-mails, tokens and secrets are masked (P062 c4)."""
    out = []
    for row in rows:
        href = str(row.get("href") or "")
        out.append({**row, "href": href if href in ("data:...",) else masked_url(href), "reason": mask_text_urls(row.get("reason"))})
    return out


def _seed_hosts(entity: Entity) -> tuple[str, ...]:
    from v3lum.core.http import entity_hosts

    return entity_hosts(entity)


def _ports(entity: Entity) -> tuple[int, ...]:
    ports = [80, 443]
    if entity.type is T.URL:
        try:
            port = urlsplit(entity.value).port
        except ValueError:
            port = None
        if port:
            ports.append(int(port))
    return tuple(ports)

