"""Archive mining (P060): waymore-style URL filtering, historical robots.txt (Robofinder technique)
and historical favicons and analytics ids (chronos technique) - a library on top of ``web_archives``.

Final conditions (council #1, P060) and where they live:

1. Built on the P059 client of ``web_archives``: the same CDX query (an identical request is served
   from the HTTP cache when web_archives ran first), the same failure mapping (``failure``,
   ``report_failure``: resets/5xx/timeouts are 'archive unreachable', never 'no captures'; an archive
   that failed that way, or answered 429 or a challenge, is not asked again in the run) and the same
   archive hosts (web.archive.org, Arquivo.pt as its fallback). OTX, urlscan and ghostarchive are not
   hosts of this module (their URL lists reach the graph through their own modules); Intelligence X
   is never used.
2. At most 20 archived bodies per run (setting ``archive_mining_max_bodies``, default 10) through raw
   ``id_`` snapshot URLs on the archive hosts only (``archive_snapshot_url`` refuses originals that
   carry credentials or tokens), 1 MB each, never cached, parsed as untrusted data (never executed or
   rendered); only indicators and digests are kept.
3. The waymore filter and keyword lists (MIT, ``v3lum/data/archive_mining/waymore_filters.json``,
   notice fragment ``waymore_filters``) keep interesting URLs. Harvested URLs are masked before
   storage (``redact_archived_url`` of P059 plus the core secret detectors) and scanned with the P312
   secret_scanner engine, which reports only masked values.
4. Robofinder: robots.txt versions through CDX ``collapse=digest`` (deduplicated again locally:
   Arquivo.pt ignores collapse), parsed with a 500 KiB cap; Disallow/Allow/Sitemap lines are unioned
   and literal disallowed paths become url entities with ``expand=False``.
5. chronos: archived favicons are hashed with the pure-Python MurmurHash3 helper in the Shodan form
   (mmh3 over ``base64.encodebytes`` with the trailing newline) and become ``favicon_hash`` pivots with
   ``expand=False``.
6. Historical analytics ids (P061 regexes) and favicon hashes carry their snapshot dates and are
   historical: ``expand=False``, first/last seen, noise favicon hashes (setting
   ``archive_mining_noise_favicons``) recorded but never pivoted; ids are never linked across eras here:
   the pivots use the dedicated relations ``historical_favicon`` / ``historical_analytics_id`` with
   confidence 'possible' (rules reading current ``favicon``/``same_analytics`` edges and ``seeds_linked``
   never use them), and the dates travel in ``archived_favicons`` / ``archived_analytics_ids`` for an
   overlap-aware P061/P062 rule.
7. Harvested URLs, disallowed paths and endpoints are never requested from the live target: every
   entity is ``expand=False`` and the only fetches go to archive hosts.
8. One grouped attribute ``interesting_archived_urls`` (config, backup, admin, api, robots_disallow),
   capped at 50 in the report (full lists in the evidence); no per-URL findings except masked secrets.
   ``default_enabled = False``.
9. Fixtures: CDX slices in the web_archives shapes plus one archived robots.txt and one archived
   favicon (tests/fixtures/archive_mining/).

MurmurHash3 x86_32 is Austin Appleby's public-domain algorithm, implemented here from its
specification. The Robofinder and chronos techniques (MIT) were read; no code was copied.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import quote, urlsplit

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
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.core.redact import MASK
from v3lum.core.sanitize import find_secrets
from v3lum.modules.url_web.web_archives import (
    ARQUIVO_CDX,
    CDX,
    SRC_ARQUIVO,
    SRC_CDX,
    SRC_WAYBACK,
    archive_snapshot_url,
    failure,
    parse_wayback_cdx,
    query_target,
    redact_archived_url,
    report_failure,
    wayback_ts_to_iso,
)

__all__ = [
    "ArchiveMining",
    "WAYMORE_FILE",
    "categorise_url",
    "check_body",
    "distinct_versions",
    "extract_analytics_ids",
    "favicon_record",
    "load_waymore",
    "mask_harvested_url",
    "mask_robots_path",
    "mmh3_32",
    "parse_cdx_rows",
    "parse_robots",
    "plan_bodies",
    "robots_union",
    "shodan_favicon_hash",
    "waymore_keep",
]

WAYMORE_FILE = "archive_mining/waymore_filters.json"
BODY_MAX_BYTES = 1_048_576  # P060 cond 2
MAX_BODIES = 20  # P060 cond 2 (hard cap)
DEFAULT_BODIES = 10
ROBOTS_MAX_BYTES = 512_000  # 500 KiB parse cap (Google's robots.txt limit)
ROBOTS_MAX_LINES = 10_000
VERSION_ROW_CAP = 500
REPORT_CAP = 50  # P060 cond 8
FULL_CAP = 2000
ROBOTS_ENTITY_CAP = 40
FAVICON_PIVOT_CAP = 10
ANALYTICS_PIVOT_CAP = 10
SECRET_URL_CAP = 5000
DEFAULT_BUDGET = 75.0  # the provider quota paces Wayback at one request per 5 s (0.25/s x 0.8 margin): 4 CDX + 10 bodies = 65 s
MAX_BUDGET = 115.0  # 4 CDX + the 20-body hard cap: the last request starts at 110 s; inside the module timeout (120 s)
CATEGORIES = ("config", "backup", "admin", "api", "robots_disallow")
_PT_TLDS = ("br", "pt")

# ======================================================================================
# MurmurHash3 x86_32 (public-domain algorithm) and the Shodan favicon form (P060 cond 5)
# ======================================================================================


def mmh3_32(data: bytes | str, seed: int = 0, signed: bool = True) -> int:
    """MurmurHash3 x86_32 of ``data`` (str is UTF-8 encoded); signed like ``mmh3.hash`` by default."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    data = bytes(data)
    c1, c2, mask = 0xCC9E2D51, 0x1B873593, 0xFFFFFFFF
    h = seed & mask
    n = len(data)
    nblocks = n // 4
    for i in range(nblocks):
        k = int.from_bytes(data[4 * i: 4 * i + 4], "little")
        k = (k * c1) & mask
        k = ((k << 15) | (k >> 17)) & mask
        k = (k * c2) & mask
        h ^= k
        h = ((h << 13) | (h >> 19)) & mask
        h = (h * 5 + 0xE6546B64) & mask
    tail = data[4 * nblocks:]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if tail:
        k ^= tail[0]
        k = (k * c1) & mask
        k = ((k << 15) | (k >> 17)) & mask
        k = (k * c2) & mask
        h ^= k
    h ^= n
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & mask
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & mask
    h ^= h >> 16
    return h - 0x100000000 if signed and h & 0x80000000 else h


def shodan_favicon_hash(data: bytes) -> int:
    """Shodan ``http.favicon.hash``: mmh3 over ``base64.encodebytes(data)`` - MIME base64 with a
    newline every 76 characters AND a trailing newline (dropping it, as chronos does, gives another
    value that matches nothing in Shodan)."""
    return mmh3_32(base64.encodebytes(bytes(data)))


# ======================================================================================
# CDX rows with digests, version collapse, body plan (P060 cond 2, 4, 5)
# ======================================================================================


def _text(raw: Any) -> str:
    if isinstance(raw, (bytes, bytearray, memoryview)):
        return bytes(raw).decode("utf-8", "replace")
    return raw if isinstance(raw, str) else ""


def _looks_html(text: str) -> bool:
    head = text.lstrip()[:512].lower()
    return head.startswith(("<!doctype html", "<html", "<head", "<body", "<?xml")) or "<title" in head[:200]


def _row(rec: Mapping[str, Any]) -> dict[str, Any] | None:
    url = rec.get("original") or rec.get("url")
    ts = rec.get("timestamp")
    if not isinstance(url, str) or not isinstance(ts, str) or wayback_ts_to_iso(ts) is None:
        return None
    status = rec.get("statuscode", rec.get("status"))
    mime = rec.get("mimetype", rec.get("mime"))
    digest = rec.get("digest")
    return {
        "url": url.strip()[:2048], "timestamp": ts,
        "statuscode": str(status) if isinstance(status, (str, int)) and str(status).isdigit() else None,
        "mimetype": mime if isinstance(mime, str) and mime not in ("", "-") else None,
        "digest": digest if isinstance(digest, str) and digest.strip() else None,
    }


def parse_cdx_rows(raw: Any, row_cap: int = VERSION_ROW_CAP) -> dict[str, Any]:
    """Version rows (with digests) of a CDX answer: the Wayback JSON array (header row first) or
    Arquivo.pt NDJSON. -> {state: ok|empty|error, rows, partial, error}. HTML or an archive error page
    is an error (could not verify), never an empty history."""
    text = _text(raw)
    if not text.strip():
        return {"state": "empty", "rows": [], "partial": False, "error": None}
    if _looks_html(text):
        return {"state": "error", "rows": [], "partial": False, "error": "HTML instead of a CDX answer"}
    rows: list[dict[str, Any]] = []
    partial = False
    stripped = text.lstrip()
    if stripped.startswith("["):
        try:
            data = json.loads(stripped)
        except (ValueError, RecursionError):
            return {"state": "error", "rows": [], "partial": True, "error": "malformed CDX JSON (cut answer)"}
        if not isinstance(data, list):
            return {"state": "error", "rows": [], "partial": False, "error": "unexpected CDX answer"}
        header: list[str] | None = None
        for item in data:
            if not isinstance(item, list):
                continue
            if item == []:
                break  # resume key follows
            if header is None and all(isinstance(x, str) for x in item) and "timestamp" in item:
                header = [str(x) for x in item]
                continue
            rec = dict(zip(header or ["timestamp", "original", "digest", "statuscode", "mimetype"], item))
            row = _row(rec)
            if row is None:
                continue
            if len(rows) >= row_cap:
                partial = True
                break
            rows.append(row)
    elif stripped.startswith("{"):
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except (ValueError, RecursionError):
                partial = True  # a cut last line
                continue
            row = _row(rec) if isinstance(rec, dict) else None
            if row is None:
                continue
            if len(rows) >= row_cap:
                partial = True
                break
            rows.append(row)
    else:
        return {"state": "error", "rows": [], "partial": False, "error": "unexpected CDX answer (" + re.sub(r"\s+", " ", text[:60]) + ")"}
    return {"state": "ok" if rows else "empty", "rows": rows, "partial": partial, "error": None}


def distinct_versions(rows: Iterable[Mapping[str, Any]], *, by: str = "digest") -> list[dict[str, Any]]:
    """Distinct versions of a path: status-200, non-revisit captures grouped by digest (``by='digest'``,
    the local collapse Arquivo.pt needs) or by capture year (``by='year'``, homepage eras), sorted by
    first capture -> [{key, first_ts, last_ts, url, captures}] (``url`` is the first capture's original)."""
    groups: dict[str, dict[str, Any]] = {}
    for row in rows:
        status = row.get("statuscode")
        if status not in (None, "200"):
            continue
        if (row.get("mimetype") or "").lower() == "warc/revisit":
            continue
        ts = str(row.get("timestamp") or "")
        if by == "year":
            key = ts[:4]
        else:
            key = str(row.get("digest") or f"{row.get('url')}@{ts}")
        if not key:
            continue
        group = groups.get(key)
        if group is None:
            groups[key] = {"key": key, "first_ts": ts, "last_ts": ts, "url": row.get("url"), "captures": 1}
            continue
        group["captures"] += 1
        if ts < group["first_ts"]:
            group["first_ts"], group["url"] = ts, row.get("url")
        if ts > group["last_ts"]:
            group["last_ts"] = ts
    return sorted(groups.values(), key=lambda g: g["first_ts"])


def _order(versions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Newest, oldest, then the rest newest first (the most telling eras within a small cap)."""
    vs = sorted(versions, key=lambda v: v["first_ts"])
    if not vs:
        return []
    out = [vs[-1]]
    if len(vs) > 1:
        out.append(vs[0])
    out += list(reversed(vs[1:-1]))
    return out


def plan_bodies(kinds: Mapping[str, tuple[str, list[dict[str, Any]]]], max_bodies: int) -> list[dict[str, Any]]:
    """P060 cond 2: at most ``max_bodies`` (<= 20) raw ``id_`` snapshot URLs on archive hosts, kinds
    interleaved (robots, favicon, homepage), each kind newest + oldest first. ``kinds`` maps a kind to
    (archive 'wayback' | 'arquivo', versions). Originals carrying credentials or tokens are never
    planned (``archive_snapshot_url``)."""
    limit = max(0, min(MAX_BODIES, int(max_bodies)))
    queues = [(kind, archive, _order(versions)) for kind, (archive, versions) in kinds.items()]
    plan: list[dict[str, Any]] = []
    while len(plan) < limit and any(q for _k, _a, q in queues):
        for kind, archive, queue in queues:
            if not queue or len(plan) >= limit:
                continue
            version = queue.pop(0)
            url = archive_snapshot_url(archive, version["first_ts"], version.get("url"))
            if url:
                plan.append({"kind": kind, "archive": archive, "timestamp": version["first_ts"], "original": version.get("url"), "url": url})
    return plan


_IMAGE_MAGIC = ((b"\x00\x00\x01\x00", "ico"), (b"\x89PNG\r\n\x1a\n", "png"), (b"GIF87a", "gif"), (b"GIF89a", "gif"),
                (b"\xff\xd8\xff", "jpeg"), (b"BM", "bmp"))


def check_body(body: Any, kind: str, max_bytes: int = BODY_MAX_BYTES) -> dict[str, Any]:
    """P060 cond 2: an archived body is untrusted data (never executed or rendered), at most 1 MB.
    favicon -> image bytes only (an HTML soft 404 under /favicon.ico is rejected); robots -> text, no
    NUL bytes, not HTML; homepage -> any text (truncated at the cap)."""
    if not isinstance(body, (bytes, bytearray, memoryview, str)):
        return {"ok": False, "reason": "no body", "format": None, "bytes": 0, "truncated": False}
    data = body.encode("utf-8") if isinstance(body, str) else bytes(body)
    size = len(data)
    if size == 0:
        return {"ok": False, "reason": "empty body", "format": None, "bytes": 0, "truncated": False}
    truncated = size > max_bytes
    if kind == "favicon":
        if truncated:
            return {"ok": False, "reason": f"larger than {max_bytes} bytes", "format": None, "bytes": size, "truncated": True}
        for magic, fmt in _IMAGE_MAGIC:
            if data.startswith(magic):
                return {"ok": True, "reason": None, "format": fmt, "bytes": size, "truncated": False}
        if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            return {"ok": True, "reason": None, "format": "webp", "bytes": size, "truncated": False}
        head = data[:512].decode("utf-8", "replace").lstrip().lower()
        if head.startswith("<svg") or (head.startswith("<?xml") and "<svg" in head):
            return {"ok": True, "reason": None, "format": "svg", "bytes": size, "truncated": False}
        if _looks_html(head):
            return {"ok": False, "reason": "HTML instead of an image (soft 404)", "format": "html", "bytes": size, "truncated": False}
        return {"ok": False, "reason": "not an image", "format": None, "bytes": size, "truncated": False}
    if kind == "robots":
        if b"\x00" in data[:4096]:
            return {"ok": False, "reason": "binary body", "format": None, "bytes": size, "truncated": truncated}
        if _looks_html(data[:2048].decode("utf-8", "replace")):
            return {"ok": False, "reason": "HTML instead of robots.txt (soft 404 or error page)", "format": "html", "bytes": size, "truncated": truncated}
        return {"ok": True, "reason": None, "format": "text", "bytes": size, "truncated": truncated}
    if kind == "homepage":
        return {"ok": True, "reason": None, "format": "html", "bytes": size, "truncated": truncated}
    return {"ok": False, "reason": "unknown kind", "format": None, "bytes": size, "truncated": truncated}


# ======================================================================================
# robots.txt (Robofinder technique, P060 cond 4)
# ======================================================================================

_ROBOTS_LINE = re.compile(r"^\s*([A-Za-z-]{1,40})\s*:\s*(.*?)\s*$")


def parse_robots(raw: Any, max_bytes: int = ROBOTS_MAX_BYTES, max_lines: int = ROBOTS_MAX_LINES) -> dict[str, Any]:
    """robots.txt -> {disallow, allow, sitemap, user_agents, truncated, invalid}; comments and blank lines
    ignored, directives case-insensitive, an empty Disallow (allow all) skipped, paths kept verbatim."""
    data = raw.encode("utf-8", "replace") if isinstance(raw, str) else bytes(raw or b"")
    truncated = len(data) > max_bytes
    text = data[:max_bytes].decode("utf-8", "ignore")
    out: dict[str, Any] = {"disallow": [], "allow": [], "sitemap": [], "user_agents": [], "truncated": truncated, "invalid": 0}
    for idx, line in enumerate(text.splitlines()):
        if idx >= max_lines:
            out["truncated"] = True
            break
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = _ROBOTS_LINE.match(line)
        if not m:
            out["invalid"] += 1
            continue
        key, value = m.group(1).lower(), m.group(2)[:2048]
        if key == "user-agent":
            if value and value not in out["user_agents"] and len(out["user_agents"]) < 100:
                out["user_agents"].append(value)
        elif key in ("disallow", "allow"):
            if not value:
                continue
            if not value.startswith(("/", "*")):
                out["invalid"] += 1
                continue
            if value not in out[key]:
                out[key].append(value)
        elif key == "sitemap" and value.startswith(("http://", "https://")) and value not in out["sitemap"]:
            out["sitemap"].append(value)
    return out


_PATH_ORIGIN = "https://robots.invalid"


def mask_robots_path(path: str) -> str:
    """A robots.txt path masked like a harvested URL (P060 cond 3): a token or key in an archived
    Disallow/Allow line is never stored. Unchanged paths are returned verbatim; a masked path carries
    the mask and so is kept as a pattern, never as a url entity."""
    masked, changed = mask_harvested_url(_PATH_ORIGIN + path)
    if not changed:
        return path
    return masked[len(_PATH_ORIGIN):] if masked.startswith(_PATH_ORIGIN) else MASK


def robots_union(versions: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, dict[str, Any]]]:
    """Union of Disallow/Allow/Sitemap lines over the archived versions -> {kind: {value: {first_seen,
    last_seen, versions, origin}}}; ``origin`` is scheme://host of the newest version listing it. Values
    are masked before they are kept (``mask_robots_path``, ``mask_harvested_url`` for sitemaps)."""
    out: dict[str, dict[str, dict[str, Any]]] = {"disallow": {}, "allow": {}, "sitemap": {}}
    for version in sorted(versions, key=lambda v: str(v.get("timestamp") or "")):
        day = (wayback_ts_to_iso(str(version.get("timestamp") or "")) or "")[:10] or None
        try:
            parts = urlsplit(str(version.get("url") or ""))
            origin = f"{parts.scheme or 'https'}://{parts.hostname}" if parts.hostname else None
        except ValueError:
            origin = None
        parsed = version.get("parsed") or {}
        for kind in ("disallow", "allow", "sitemap"):
            for value in parsed.get(kind) or []:
                value = mask_harvested_url(value)[0] if kind == "sitemap" else mask_robots_path(value)
                entry = out[kind].get(value)
                if entry is None:
                    out[kind][value] = {"first_seen": day, "last_seen": day, "versions": 1, "origin": origin}
                else:
                    entry["versions"] += 1
                    entry["last_seen"] = day or entry["last_seen"]
                    entry["origin"] = origin or entry["origin"]
    return out


def robots_disallow_urls(union: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Literal disallowed paths -> (url rows for entities, wildcard/'$' patterns kept as attributes)."""
    rows: list[dict[str, Any]] = []
    patterns: list[dict[str, Any]] = []
    for path, meta in sorted((union.get("disallow") or {}).items()):
        if path == "/" or "*" in path or "$" in path or not meta.get("origin"):
            patterns.append({"path": path, "first_seen": meta.get("first_seen"), "last_seen": meta.get("last_seen")})
            continue
        url = str(meta["origin"]) + quote(path, safe="/%?=&;:@+,-._~!")
        masked, _kinds = mask_harvested_url(url)
        rows.append({"url": masked, "path": path, "first_seen": meta.get("first_seen"), "last_seen": meta.get("last_seen"),
                     "versions": meta.get("versions")})
    return rows, patterns


# ======================================================================================
# favicons and analytics ids (chronos technique, P060 cond 5-6)
# ======================================================================================


def favicon_record(body: bytes, timestamp: str, url: str | None = None) -> dict[str, Any]:
    """Hashes of one archived favicon version (Shodan mmh3 as a string, MD5, SHA-256), dated."""
    chk = check_body(body, "favicon")
    day = (wayback_ts_to_iso(timestamp) or "")[:10] or None
    if not chk["ok"]:
        return {"ok": False, "reason": chk["reason"], "snapshot": day}
    data = bytes(body)
    return {"ok": True, "favicon_hash": str(shodan_favicon_hash(data)), "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - identifier, not security
            "sha256": hashlib.sha256(data).hexdigest(), "format": chk["format"], "bytes": len(data), "snapshot": day, "url": url}


#: P061 regexes (bounded, case-sensitive): UA-, G- (6-12, the digits-only regex fixed), GTM-, pub-/ca-pub-.
_ANALYTICS = (
    ("ga_universal", re.compile(r"(?<![A-Za-z0-9-])UA-\d{4,10}-\d{1,4}(?![0-9])")),
    ("ga4", re.compile(r"(?<![A-Za-z0-9-])G-[A-Z0-9]{6,12}(?![A-Za-z0-9])")),
    ("gtm", re.compile(r"(?<![A-Za-z0-9-])GTM-[A-Z0-9]{4,9}(?![A-Za-z0-9])")),
    ("adsense", re.compile(r"(?<![A-Za-z0-9-])(?:ca-)?pub-\d{16}(?![0-9])")),
)


def extract_analytics_ids(body: Any, max_bytes: int = BODY_MAX_BYTES, max_ids: int = 50) -> list[dict[str, str]]:
    """Analytics ids in an archived body (P061 regexes; 'ca-pub-X' and 'pub-X' are one AdSense id)."""
    data = body.encode("utf-8", "replace") if isinstance(body, str) else bytes(body or b"")
    text = data[:max_bytes].decode("utf-8", "replace")
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for kind, rx in _ANALYTICS:
        for m in rx.finditer(text):
            value = m.group(0)
            if kind == "adsense" and value.startswith("ca-"):
                value = value[3:]
            if value in seen:
                continue
            seen.add(value)
            out.append({"id": value, "kind": kind})
            if len(out) >= max_ids:
                return out
    return out


def _merge_dated(store: dict[str, dict[str, Any]], key: str, day: str | None, extra: Mapping[str, Any]) -> None:
    entry = store.setdefault(key, {**extra, "first_seen": day, "last_seen": day, "snapshots": 0})
    entry["snapshots"] += 1
    if day and (not entry["first_seen"] or day < entry["first_seen"]):
        entry["first_seen"] = day
    if day and (not entry["last_seen"] or day > entry["last_seen"]):
        entry["last_seen"] = day


# ======================================================================================
# waymore filters, categories and masking (P060 cond 3, 8)
# ======================================================================================


def load_waymore() -> dict[str, tuple[str, ...]]:
    """The bundled waymore lists (MIT); an unreadable file gives empty lists (no URL is kept)."""
    try:
        data = DataStore.bundled_json(WAYMORE_FILE)
    except (OSError, ValueError):
        data = {}
    out: dict[str, tuple[str, ...]] = {}
    for key in ("filter_code", "filter_mime", "filter_url", "filter_keywords"):
        values = data.get(key) if isinstance(data, dict) else None
        out[key] = tuple(str(v).lower() for v in values if isinstance(v, str) and v) if isinstance(values, list) else ()
    return out


#: Backup/config extensions are kept whatever their archived MIME type (waymore's FILTER_MIME drops
#: application/octet-stream, i.e. most backups and dumps): a V3LUM rule on top of the waymore lists.
_KEEP_ANY_MIME = re.compile(r"(?:\.(?:bak|backup|old|orig|save|swp|tmp|zip|tar|tgz|gz|rar|7z|sql|dump|env|config|conf|cfg|ini|"
                            r"properties|ya?ml|pem|key|kdbx)$|/\.env$|~$)", re.I)


def waymore_keep(url: str, status: str | None, mime: str | None, lists: Mapping[str, tuple[str, ...]]) -> tuple[bool, str]:
    """waymore semantics, reimplemented: drop FILTER_CODE statuses, FILTER_MIME types (unless the path
    is a backup/config extension) and URLs containing a FILTER_URL string; keep only URLs containing a
    FILTER_KEYWORDS string. Returns (keep, reason)."""
    low = url.lower()
    if status and status in lists.get("filter_code", ()):
        return False, f"status {status}"
    try:
        path = urlsplit(url).path or ""
    except ValueError:
        return False, "unparseable URL"
    keep_any = bool(_KEEP_ANY_MIME.search(path))
    if (mime or "").lower() in lists.get("filter_mime", ()) and not keep_any:
        return False, f"mime {mime}"
    for needle in lists.get("filter_url", ()):
        if needle in low:
            return False, f"url filter {needle}"
    if not keep_any and not any(k in low for k in lists.get("filter_keywords", ())):
        return False, "no keyword"
    return True, ""


_CATEGORY_RULES = (
    ("backup", re.compile(r"(?:\.(?:bak|backup|old|orig|save|swp|tmp|zip|tar|tgz|gz|rar|7z|sql|dump)$|~$|/(?:backup|backups|bkp|bak)(?:/|$))", re.I)),
    ("config", re.compile(r"(?:/\.env$|/\.git/|/\.svn/|/\.htaccess$|/\.htpasswd$|web\.config$|wp-config\.php|/config(?:uration)?(?:\.[a-z]{2,5})?$|"
                          r"/settings\.(?:py|php|json|ya?ml)$|\.(?:conf|cfg|ini|properties|env|ya?ml)$|docker-compose\.ya?ml$|/phpinfo\.php$)", re.I)),
    ("admin", re.compile(r"/(?:admin|administrator|wp-admin|wp-login\.php|login|signin|dashboard|panel|cpanel|phpmyadmin|manager/html|"
                         r"jenkins|console|webadmin|backoffice|painel)(?:[/.?]|$)", re.I)),
    ("api", re.compile(r"(?:/api(?:/|$|\.)|^https?://api[.-]|/v[0-9]+/|/graphql|/gql(?:/|$)|/swagger|/openapi|/api-docs|/rest/|\.wsdl$|/odata/)", re.I)),
)


def categorise_url(url: str) -> str:
    """config | backup | admin | api | other (first matching rule wins: a backup copy of a config file
    is a backup)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "other"
    path = parts.path or "/"
    for category, rx in _CATEGORY_RULES:
        if category == "api":
            if rx.search(url.split("?", 1)[0]) or rx.search(path) or re.search(r"(?:^|&)wsdl\b", parts.query or "", re.I):
                return category
        elif rx.search(path):
            return category
    return "other"


def mask_harvested_url(url: str) -> tuple[str, bool]:
    """Masking before storage (P060 cond 3): the P059 archive redaction (configured keys, key-like and
    session/recipient parameters, userinfo, JWTs, e-mail addresses, opaque tokens) plus every secret
    the core detectors find in the path or query. -> (masked URL, anything masked)."""
    masked, kinds = redact_archived_url(url)
    changed = any(k != "unparseable" for k in kinds)
    for hit in find_secrets(masked):
        value = getattr(hit, "value", "")
        if value and value in masked:
            masked = masked.replace(value, MASK)
            changed = True
    return masked, changed


def group_urls(entries: Mapping[str, Mapping[str, dict[str, Any]]], cap: int = REPORT_CAP) -> dict[str, Any]:
    """P060 cond 8: one grouped view, round-robin over the categories so each shows within the cap."""
    per_cat = {c: sorted((entries.get(c) or {}).values(), key=lambda e: (str(e.get("first_seen") or ""), str(e.get("url")))) for c in CATEGORIES}
    shown: dict[str, list[dict[str, Any]]] = {}
    idx = {c: 0 for c in CATEGORIES}
    budget = cap
    while budget > 0 and any(idx[c] < len(per_cat[c]) for c in CATEGORIES):
        for c in CATEGORIES:
            if budget > 0 and idx[c] < len(per_cat[c]):
                shown.setdefault(c, []).append(dict(per_cat[c][idx[c]]))
                idx[c] += 1
                budget -= 1
    total = sum(len(v) for v in per_cat.values())
    return {"categories": shown, "counts": {c: len(per_cat[c]) for c in CATEGORIES}, "total": total, "shown": cap - budget,
            "truncated": total > cap, "full": {c: per_cat[c][:FULL_CAP] for c in CATEGORIES}}


# ======================================================================================
# the run
# ======================================================================================


class _Budget:
    def __init__(self, ctx: Any, seconds: float) -> None:
        self.ctx = ctx
        self.seconds = float(seconds)
        self.start = self._now()

    def _now(self) -> float:
        clock = getattr(getattr(self.ctx, "http", None), "clock", None)
        try:
            return float(clock.monotonic())
        except Exception:  # noqa: BLE001 - a context without a clock (direct helper use)
            return time.monotonic()

    def timeout(self, wanted: float) -> float | None:
        left = self.seconds - (self._now() - self.start)
        remaining = self.ctx.remaining()
        if remaining is not None:
            left = min(left, float(remaining) - 2.0)
        return None if left < 1.0 else max(1.0, min(wanted, left))


def _stops_source(exc: BaseException) -> bool:
    """A source that refused us (429, quota, challenge, login wall), was unreachable (reset, timeout)
    or overloaded (5xx) is not asked again in the run: one failure per archive, never a retry storm.
    A 4xx for one snapshot (a missing capture) does not stop the others."""
    if isinstance(exc, (RateLimited, QuotaExceeded, Blocked, AuthRequired, DeadlineExceeded, NetworkError)):
        return True
    if isinstance(exc, HttpError):
        status = int(getattr(exc, "status", 0) or 0)
        return status == 0 or status >= 500
    return False


def _int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class _Mine:
    """One archive_mining run: CDX versions, the body plan, the URL harvest, output."""

    def __init__(self, ctx: Any, res: ModuleResult, entity: Entity, q: dict[str, Any]) -> None:
        self.ctx, self.res, self.entity, self.q = ctx, res, entity, q
        try:
            seconds = float(ctx.setting("archive_mining_budget", DEFAULT_BUDGET))
        except (TypeError, ValueError):
            seconds = DEFAULT_BUDGET
        self.budget = _Budget(ctx, max(10.0, min(MAX_BUDGET, seconds)))
        self.max_bodies = max(0, min(MAX_BODIES, _int(ctx.setting("archive_mining_max_bodies", DEFAULT_BODIES), DEFAULT_BODIES)))
        raw_noise = ctx.setting("archive_mining_noise_favicons", []) or []
        self.noise = {str(_int(x, 0)) for x in raw_noise if str(x).strip().lstrip("-").isdigit()} if isinstance(raw_noise, list) else set()
        self.host = (q.get("domain") or "").lower()
        self.sources: dict[str, str] = {}
        self.failures: dict[str, dict[str, Any]] = {}
        self.answered: set[str] = set()
        self.dead: dict[str, str] = {}  # source id -> why it is not asked again in this run
        self.versions: dict[str, tuple[str, list[dict[str, Any]]]] = {}
        self.partial = False

    # ---- plumbing ----------------------------------------------------------------------------
    def _get(self, endpoint: str, source_id: str, url: str, *, params: Any = None, wanted: float = 10.0, ttl: int | None = None,
             max_bytes: int | None = None) -> Any:
        if source_id in self.dead:
            self.sources[endpoint] = f"not_run: {self.dead[source_id]}"
            self.partial = True
            return None
        timeout = self.budget.timeout(wanted)
        if timeout is None:
            self.sources[endpoint] = "not_run: time budget used up"
            self.partial = True
            return None
        kw: dict[str, Any] = {"source": source_id, "timeout": timeout}
        if params:
            kw["params"] = params
        if ttl is not None:
            kw["ttl"] = ttl
        if max_bytes is not None:
            kw["max_bytes"] = max_bytes
        try:
            resp = self.ctx.http.get(url, **kw)
            self.ctx.http.check(resp)
            return resp
        except (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError, DeadlineExceeded) as exc:
            out = failure(endpoint, exc)
            self.sources[endpoint] = f"{out['status']}: {out['reason']}"
            self.failures.setdefault(source_id, out)
            if _stops_source(exc):
                self.dead[source_id] = f"{source_id} failed earlier in this run ({out['status']}, {out['reason_code']})"
            return None

    def _cdx_failed(self, source_id: str, endpoint: str, problem: str) -> None:
        self.sources[endpoint] = f"could_not_verify: {problem}"
        self.failures.setdefault(source_id, {"status": "could_not_verify", "reason_code": "error", "reason": f"{endpoint}: {problem}"})

    # ---- versions (robots, favicon, homepage) -----------------------------------------------------
    _KINDS = {
        "robots": ("/robots.txt", "digest"),
        "favicon": ("/favicon.ico", "digest"),
        "homepage": ("/", "year"),
    }

    def wayback_versions(self, kind: str) -> list[dict[str, Any]] | None:
        path, by = self._KINDS[kind]
        params: list[tuple[str, str]] = [("url", f"{self.host}{path}"), ("output", "json"),
                                         ("fl", "timestamp,original,digest,statuscode,mimetype"), ("filter", "statuscode:200")]
        if kind == "favicon":
            params.append(("filter", "!mimetype:warc/revisit"))
        if kind == "homepage":
            params += [("filter", "mimetype:text/html"), ("collapse", "timestamp:4")]
        else:
            params.append(("collapse", "digest"))
        params.append(("limit", str(VERSION_ROW_CAP)))
        endpoint = f"wayback_{kind}_versions"
        resp = self._get(endpoint, SRC_CDX, CDX, params=params, wanted=12.0, ttl=86400, max_bytes=2 * 1024 * 1024)
        if resp is None:
            return None
        parsed = parse_cdx_rows(resp.content)
        if parsed["state"] == "error":
            self._cdx_failed(SRC_CDX, endpoint, str(parsed["error"]))
            return None
        self.answered.add(SRC_CDX)
        versions = distinct_versions(parsed["rows"], by=by)
        self.sources[endpoint] = f"ok: {len(versions)} version(s)" if versions else "empty (no capture of this path)"
        if parsed["partial"]:
            self.partial = True
            self.sources[endpoint] += ", partial (row cap)"
        return versions

    def arquivo_versions(self, kind: str) -> list[dict[str, Any]] | None:
        path, by = self._KINDS[kind]
        endpoint = f"arquivo_{kind}_versions"
        params = [("url", f"{self.host}{path}"), ("output", "json"), ("limit", str(VERSION_ROW_CAP))]
        resp = self._get(endpoint, SRC_ARQUIVO, ARQUIVO_CDX, params=params, wanted=12.0, ttl=86400, max_bytes=2 * 1024 * 1024)
        if resp is None:
            return None
        parsed = parse_cdx_rows(resp.content)
        if parsed["state"] == "error":
            self._cdx_failed(SRC_ARQUIVO, endpoint, str(parsed["error"]))
            return None
        self.answered.add(SRC_ARQUIVO)
        versions = distinct_versions(parsed["rows"], by=by)  # Arquivo.pt ignores collapse: done locally
        self.sources[endpoint] = f"ok: {len(versions)} version(s)" if versions else "empty (no capture of this path)"
        if parsed["partial"]:
            self.partial = True
        return versions

    def collect_versions(self) -> None:
        pt_tld = self.host.rsplit(".", 1)[-1] in _PT_TLDS
        for kind in ("robots", "favicon", "homepage"):
            wayback = self.wayback_versions(kind)
            if wayback:
                self.versions[kind] = ("wayback", wayback)
                continue
            if wayback is None or pt_tld:  # Wayback unreachable, or a .br/.pt site Wayback holds nothing of (P059)
                arquivo = self.arquivo_versions(kind)
                if arquivo:
                    self.versions[kind] = ("arquivo", arquivo)

    # ---- bodies ------------------------------------------------------------------------------------
    def fetch_bodies(self) -> dict[str, list[dict[str, Any]]]:
        out: dict[str, list[dict[str, Any]]] = {"robots": [], "favicon": [], "homepage": []}
        for item in plan_bodies(self.versions, self.max_bodies):
            host = (urlsplit(item["url"]).hostname or "").lower()
            if host not in ("web.archive.org", "arquivo.pt"):
                continue  # archive hosts only (cond 2); the live target is never contacted
            source_id = SRC_WAYBACK if item["archive"] == "wayback" else SRC_ARQUIVO
            endpoint = f"{item['archive']}_{item['kind']}_body"
            resp = self._get(endpoint, source_id, item["url"], wanted=10.0, ttl=0, max_bytes=BODY_MAX_BYTES + 1)
            if resp is None:
                continue
            self.answered.add(source_id)
            out[item["kind"]].append({**item, "body": resp.content, "truncated": bool(getattr(resp, "truncated", False))})
            self.sources[endpoint] = "ok"
        return out

    # ---- URL harvest (waymore) -----------------------------------------------------------------------
    def harvest(self) -> list[dict[str, Any]] | None:
        """The P059 CDX listing (same request as web_archives: served from the HTTP cache when it ran)."""
        try:
            page = int(self.ctx.setting("web_archives_cdx_limit", 5000))
        except (TypeError, ValueError):
            page = 5000
        page = max(1, min(20_000, page))
        params = {
            "url": self.q["query"], "matchType": self.q["match"], "output": "json", "fl": "original,timestamp,statuscode,mimetype",
            "collapse": "urlkey", "limit": str(page), "showResumeKey": "true",
        }
        resp = self._get("wayback_cdx", SRC_CDX, CDX, params=params, wanted=12.0, ttl=86400, max_bytes=8 * 1024 * 1024)
        if resp is None:
            return None
        result = parse_wayback_cdx(resp.content, page, body_truncated=bool(getattr(resp, "truncated", False)))
        if result["state"] == "error":
            self._cdx_failed(SRC_CDX, "wayback_cdx", str(result["error"]))
            return None
        self.answered.add(SRC_CDX)
        rows = list(result["rows"])
        self.sources["wayback_cdx"] = (f"ok: {len(rows)} URL(s)" if rows else "empty (no captures in the CDX index)") + (
            f", partial: {result['stop'] or 'more pages'}" if result["partial"] or result.get("resume_key") else "")
        if result["partial"] or result.get("resume_key"):
            self.partial = True
        return rows

    # ---- output --------------------------------------------------------------------------------------
    def finish(self, bodies: Mapping[str, list[dict[str, Any]]], rows: list[dict[str, Any]] | None) -> ModuleResult:
        res = self.res
        body_log: list[dict[str, Any]] = []
        robots_versions: list[dict[str, Any]] = []
        for item in bodies.get("robots") or []:
            chk = check_body(item["body"], "robots")
            body_log.append(self._log(item, chk))
            if chk["ok"]:
                robots_versions.append({"timestamp": item["timestamp"], "url": item["original"], "parsed": parse_robots(item["body"])})
        union = robots_union(robots_versions)
        disallow_rows, patterns = robots_disallow_urls(union)

        favicons: dict[str, dict[str, Any]] = {}
        for item in bodies.get("favicon") or []:
            rec = favicon_record(item["body"], item["timestamp"], item["original"])
            body_log.append(self._log(item, check_body(item["body"], "favicon")))
            if rec["ok"]:
                _merge_dated(favicons, rec["favicon_hash"], rec["snapshot"], {
                    "favicon_hash": rec["favicon_hash"], "md5": rec["md5"], "sha256": rec["sha256"], "format": rec["format"],
                    "bytes": rec["bytes"], "noise": rec["favicon_hash"] in self.noise})

        analytics: dict[str, dict[str, Any]] = {}
        for item in bodies.get("homepage") or []:
            body_log.append(self._log(item, check_body(item["body"], "homepage")))
            day = (wayback_ts_to_iso(item["timestamp"]) or "")[:10] or None
            for found in extract_analytics_ids(item["body"]):
                _merge_dated(analytics, found["id"], day, {"id": found["id"], "kind": found["kind"]})

        lists = load_waymore()
        entries: dict[str, dict[str, dict[str, Any]]] = {c: {} for c in CATEGORIES}
        originals: list[str] = []
        counts = {"rows": 0, "dropped_by_filters": 0, "other": 0, "masked": 0}
        for row in rows or []:
            original = str(row.get("_original") or row.get("url") or "")
            if not original:
                continue
            counts["rows"] += 1
            if len(originals) < SECRET_URL_CAP:
                originals.append(original)
            keep, _why = waymore_keep(original, row.get("statuscode"), row.get("mimetype"), lists)
            if not keep:
                counts["dropped_by_filters"] += 1
                continue
            category = categorise_url(original)
            if category == "other":
                counts["other"] += 1
                continue
            masked, changed = mask_harvested_url(original)
            counts["masked"] += int(changed)
            day = str(row.get("captured_at") or "")[:10] or None
            _merge_url(entries[category], masked, day)
        for row in disallow_rows:
            entry = entries["robots_disallow"].setdefault(row["url"], {"url": row["url"], "first_seen": row["first_seen"],
                                                                        "last_seen": row["last_seen"], "captures": 0})
            entry["captures"] = max(int(entry.get("captures") or 0), int(row.get("versions") or 0))
        grouped = group_urls(entries)

        found_anything = bool(self.versions or rows)
        if not self.answered:
            self._no_answer()
            res.raw = self._raw(body_log, union, favicons, analytics, grouped, counts)
            return res
        for source_id, out in self.failures.items():
            if source_id not in self.answered:
                report_failure(res, source_id, out)
        res.attr("archive_sources", dict(self.sources))
        if grouped["total"]:
            res.attr("interesting_archived_urls", {k: grouped[k] for k in ("categories", "counts", "total", "shown", "truncated")})
        if robots_versions:
            res.attr("archived_robots", {
                "versions": [{"timestamp": v["timestamp"], "captured_at": wayback_ts_to_iso(v["timestamp"]),
                              "url": mask_harvested_url(str(v["url"] or ""))[0]}
                             for v in sorted(robots_versions, key=lambda v: str(v["timestamp"]))],
                "disallow": dict(list(sorted(union["disallow"].items()))[:200]),
                "allow": dict(list(sorted(union["allow"].items()))[:100]),
                "sitemap": [mask_harvested_url(s)[0] for s in sorted(union["sitemap"])[:50]],
                "patterns": patterns[:100],
            })
        if favicons:
            res.attr("archived_favicons", sorted(favicons.values(), key=lambda f: str(f.get("first_seen") or "")))
        if analytics:
            res.attr("archived_analytics_ids", sorted(analytics.values(), key=lambda a: (str(a.get("first_seen") or ""), a["id"])))
        self._pivots(disallow_rows, favicons, analytics)
        secrets = self._secrets(originals)
        if found_anything or grouped["total"]:
            self._summary(robots_versions, union, favicons, analytics, grouped, counts, secrets)
        res.raw = self._raw(body_log, union, favicons, analytics, grouped, counts)
        if self.failures or self.partial:
            res.partial = True
            notes = [str(v.get("reason")) for v in self.failures.values()]
            if self.partial and not notes:
                notes.append("a CDX answer was capped or the time budget ran out")
            res.error = "partial: " + "; ".join(notes)
        if not (robots_versions or favicons or analytics or grouped["total"] or rows or self.versions):
            if self.failures:
                return res.mark("error", "could not verify: no archived history in the archives that answered, and "
                                + "; ".join(str(v.get("reason")) for v in self.failures.values()), reason_code="error")
            return res.mark("empty")  # the archives answered and hold nothing for this host: never 'never archived'
        return res

    @staticmethod
    def _log(item: Mapping[str, Any], chk: Mapping[str, Any]) -> dict[str, Any]:
        body = item.get("body") or b""
        return {"kind": item.get("kind"), "archive": item.get("archive"), "timestamp": item.get("timestamp"),
                "snapshot": redact_archived_url(str(item.get("url") or ""))[0], "ok": bool(chk.get("ok")), "reason": chk.get("reason"),
                "bytes": len(body), "sha256": hashlib.sha256(bytes(body)).hexdigest() if body else None,
                "truncated": bool(item.get("truncated") or chk.get("truncated"))}

    def _no_answer(self) -> None:
        """Rule 5: no archive answered - could not verify, never 'no history'."""
        res = self.res
        for source_id, out in self.failures.items():
            report_failure(res, source_id, out)
        reasons = "; ".join(str(f.get("reason")) for f in self.failures.values()) or "no archive answered"
        if self.failures and all(f.get("status") == "rate_limited" for f in self.failures.values()):
            res.mark("rate_limited", f"could not verify: {reasons}", reason_code="rate_limited")
            return
        timeout = self.failures and all(f.get("reason_code") == "timeout" for f in self.failures.values())
        res.mark("error", f"could not verify: {reasons}", reason_code="timeout" if timeout else "error")

    def _pivots(self, disallow_rows: list[dict[str, Any]], favicons: Mapping[str, Mapping[str, Any]],
                analytics: Mapping[str, Mapping[str, Any]]) -> None:
        res = self.res
        for row in disallow_rows[:ROBOTS_ENTITY_CAP]:
            if MASK in row["url"]:
                continue  # a masked value is no indicator: kept in the attribute only
            res.pivot(T.URL, row["url"], "robots_disallow", confidence="probable", expand=False,
                      note=f"historical robots.txt Disallow (first seen {row['first_seen']}, last seen {row['last_seen']}): "
                           "never requested from the live site")
        for fav in sorted(favicons.values(), key=lambda f: str(f.get("first_seen") or ""))[:FAVICON_PIVOT_CAP]:
            if fav.get("noise"):
                continue  # P062 noise rule: recorded, never pivoted
            # A dedicated relation and a weak edge: a historical favicon never feeds the current-favicon clone rule
            # (CR29 reads 'favicon' edges) nor links two inputs (seeds_linked skips edges below 0.6): cond 6.
            res.pivot(T.FAVICON_HASH, fav["favicon_hash"], "historical_favicon", confidence="possible", expand=False,
                      note=f"archived favicon, snapshots {fav['first_seen']}..{fav['last_seen']} ({fav['snapshots']}): historical")
        for item in sorted(analytics.values(), key=lambda a: (str(a.get("first_seen") or ""), a["id"]))[:ANALYTICS_PIVOT_CAP]:
            res.pivot(T.ANALYTICS_ID, item["id"], "historical_analytics_id", confidence="possible", expand=False,
                      note=f"in archived homepage snapshots {item['first_seen']}..{item['last_seen']}: historical (link only with "
                           "overlapping dates)")

    def _secrets(self, originals: list[str]) -> int:
        """Masked secrets in harvested URLs (the P312 secret_scanner engine reports masked values only)."""
        if not originals:
            return 0
        try:
            from v3lum.modules.utility.secret_scanner import scan_text, secret_severity
        except Exception:  # noqa: BLE001 - the shared engine is unavailable: URLs are still masked
            return 0
        try:
            out = scan_text("\n".join(originals), path="archived URLs")
        except Exception:  # noqa: BLE001 - never fail the run on the scanner
            return 0
        try:
            own = bool(getattr(self.ctx.org.owns(self.entity), "own", False))
        except Exception:  # noqa: BLE001
            own = False
        reported = 0
        for item in out.get("findings") or []:
            if item.get("generic"):
                continue
            sev = secret_severity(item["rule_id"], "own" if own else "third_party", generic=False)
            masked = item.get("masked") or {}
            self.res.finding(
                f"Secret exposed in an archived URL: {item['rule_id']}",
                sev["severity"],
                f"{item.get('description') or item['rule_id']}: {masked.get('display', '[redacted]')} in {item.get('count', 1)} archived "
                f"URL(s) of {self.host}. The value is masked and was never used or validated; {sev['recommendation']}.",
                confidence="probable",
                criterion=f"secret_scanner rule '{item['rule_id']}' (gitleaks, MIT) matched a URL from the web-archive CDX index; format only, "
                          "never validated (P312 c6)",
                data={"rule": item["rule_id"], "kind": item.get("kind"), "masked": masked, "count": item.get("count"),
                      "owner": "own" if own else "third_party"},
                tags=["credential_exposure"],
                source=SRC_CDX,
                key=str(masked.get("sha256") or item["rule_id"])[:16],
            )
            reported += 1
            if reported >= 20:
                break
        return reported

    def _summary(self, robots_versions: list[Any], union: Mapping[str, Any], favicons: Mapping[str, Any], analytics: Mapping[str, Any],
                 grouped: Mapping[str, Any], counts: Mapping[str, Any], secrets: int) -> None:
        cats = ", ".join(f"{c} {grouped['counts'][c]}" for c in CATEGORIES if grouped["counts"].get(c))
        desc = (
            f"{len(robots_versions)} archived robots.txt version(s) parsed ({len(union['disallow'])} disallowed path(s)), "
            f"{len(favicons)} distinct archived favicon hash(es), {len(analytics)} historical analytics id(s), "
            f"{grouped['total']} interesting archived URL(s)" + (f" ({cats})" if cats else "") + ". Everything is historical and "
            "never requested from the live site" + (f"; {secrets} masked secret finding(s)." if secrets else ".")
        )
        self.res.finding(
            "Archive mining",
            "info",
            desc,
            confidence="probable",
            data={"robots_versions": len(robots_versions), "disallowed_paths": len(union["disallow"]), "favicons": len(favicons),
                  "analytics_ids": len(analytics), "interesting_urls": grouped["counts"], "harvest": dict(counts)},
            tags=["info", "historical"],
            source=SRC_CDX,
        )

    def _raw(self, body_log: list[dict[str, Any]], union: Mapping[str, Any], favicons: Mapping[str, Any], analytics: Mapping[str, Any],
             grouped: Mapping[str, Any], counts: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "query": {"kind": self.q["kind"], "host": self.host, "query": redact_archived_url(str(self.q["query"]))[0]},
            "sources": dict(self.sources),
            "versions": {kind: {"archive": archive, "versions": [{k: (redact_archived_url(str(v[k]))[0] if k == "url" else v[k])
                                                                    for k in ("first_ts", "last_ts", "url", "captures")} for v in versions[:100]]}
                         for kind, (archive, versions) in self.versions.items()},
            "bodies": body_log,
            "robots": {"disallow": len(union.get("disallow") or {}), "allow": len(union.get("allow") or {}), "sitemap": len(union.get("sitemap") or {})},
            "favicons": list(favicons.values()),
            "analytics_ids": list(analytics.values()),
            "interesting_urls": grouped.get("full") or {},
            "harvest": dict(counts),
        }


def _merge_url(store: dict[str, dict[str, Any]], url: str, day: str | None) -> None:
    entry = store.setdefault(url, {"url": url, "first_seen": day, "last_seen": day, "captures": 0})
    entry["captures"] += 1
    if day and (not entry["first_seen"] or day < entry["first_seen"]):
        entry["first_seen"] = day
    if day and (not entry["last_seen"] or day > entry["last_seen"]):
        entry["last_seen"] = day


# ======================================================================================
# the module
# ======================================================================================


@register
class ArchiveMining(Module):
    name = "archive_mining"
    title = "Archive mining (robots.txt history, archived favicons, interesting archived URLs)"
    description = (
        "Mines the web archives behind web_archives: distinct archived robots.txt versions (disallowed paths), archived favicon "
        "hashes (Shodan mmh3) and homepage analytics ids by era, and waymore-filtered interesting archived URLs - all historical."
    )
    category = "url_web"
    accepts = {T.DOMAIN, T.URL}
    produces = {T.URL, T.FAVICON_HASH, T.ANALYTICS_ID}
    run_on = "seeds"
    tags = {"free", "slow"}
    reference = "https://github.com/xnl-h4ck3r/waymore"
    terms = "open"  # archive hosts only: the Internet Archive and Arquivo.pt (P060: tier trusted, terms open)
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "internet_archive"
    sources = (SRC_CDX, SRC_WAYBACK, SRC_ARQUIVO)
    hosts = ("web.archive.org", "arquivo.pt")
    access_model = "free_noauth_limited"
    max_requests = 27  # URL listing 1 + Wayback versions 3 + Arquivo.pt fallback 3 + bodies <= 20 (P060 cond 2)
    expected_latency = 70.0  # Wayback paced at one request per 5 s (provider quota): 4 CDX queries + 10 bodies by default
    timeout = 120.0  # room for the 20-body hard cap with archive_mining_budget raised to its 115 s maximum
    cache_ttl = 86400  # CDX answers; archived bodies are never cached
    max_pivots = ROBOTS_ENTITY_CAP + FAVICON_PIVOT_CAP + ANALYTICS_PIVOT_CAP
    default_enabled = False  # P060 cond 8: opt-in
    notice = (
        "Archive hosts only (Internet Archive, Arquivo.pt): archived bodies are fetched as raw id_ snapshots (at most 20, 1 MB "
        "each), parsed as untrusted data and never stored; harvested URLs and disallowed paths are never requested from the "
        "live site. waymore filter lists: MIT, Copyright (c) 2022 /XNL-h4ck3r."
    )
    settings = {
        "archive_mining_budget": SettingSpec(int(DEFAULT_BUDGET), "archive_mining: seconds for the archive requests, 10-115 (Wayback is paced at one request per 5 s: 75 s fit the default 10 bodies, the 20-body cap needs 115 s)"),
        "archive_mining_max_bodies": SettingSpec(DEFAULT_BODIES, "archive_mining: archived bodies fetched per run (robots.txt, favicon, homepage versions; at most 20, P060 cond 2)"),
        "archive_mining_noise_favicons": SettingSpec([], "archive_mining: favicon hashes treated as noise (default/blank icons, P062): recorded, never pivoted"),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return query_target(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        q = query_target(entity)
        if q is None:
            return res.mark("skipped", "not an http(s) URL or a domain", reason_code="not_applicable")
        mine = _Mine(ctx, res, entity, q)
        rows = mine.harvest()
        mine.collect_versions()
        bodies = mine.fetch_bodies()
        return mine.finish(bodies, rows)
