"""abuse.ch platforms with one Auth-Key (P156): URLhaus, ThreatFox and MalwareBazaar query APIs, their v2
exports for pasted lists, and Feodo Tracker + SSLBL matched locally.

* One key ``abusech`` (header ``Auth-Key`` on every API call, terms s.2.1), shared with yaraify,
  offline_hash_sets and structural_hash_pivots. Without it the module emits one coverage reason
  (:data:`NO_KEY_LINE`) and the manual URLhaus/ThreatFox/MalwareBazaar links (pack
  ``threat_intel_g07``) instead of per-entity errors (cond 9).
* Licence per source (cond 2, A1 BR14): MalwareBazaar, URLhaus and ThreatFox are 'license' (terms
  2026-10-21 s.4.1: off under the corporate profile until licence-cleared); Feodo Tracker and SSLBL
  are 'open' (CC0, s.3.4). The module queries only ``ctx.allowed_sources``.
* Read-only by construction (cond 4): :func:`build_request` builds only the queries of
  :data:`QUERY_ALLOWLIST`; sample downloads, uploads and every submission are never built.
* ``query_status`` is mapped centrally (cond 5, :func:`map_query_status`): ok; no_result(s) and the
  documented '*_not_found' answers -> EMPTY; illegal_*/invalid_*/missing-input answers -> SKIPPED
  'not_applicable'; key problems -> NEEDS_KEY; anything else -> ERROR. HTTP 401 -> NEEDS_KEY. The
  legacy keyless exports (410 Gone) are never used.
* Bulk (cond 6): IOCs beyond :data:`BULK_THRESHOLD` from one pasted list (or scan) are matched against
  the local v2 exports, never per-IOC API calls (terms s.7.3). The export URLs embed the key in the
  path (:data:`EXPORT_TEMPLATES` keep the ``{AUTH_KEY}`` placeholder, cond 3); their download waits
  for keyed dataset templates in the core dataset manager (backlog), so the module reads a local copy
  when one exists and reports UNAVAILABLE 'dataset' otherwise.
* Severity (cond 7): URLhaus online or last online <= 30 days -> high, offline > 90 days -> low
  'historical'; ThreatFox confidence_level < 50 -> suspicious; a URLhaus host that is a popular
  file-hosting/CDN domain (warninglists, P169) -> info 'abused legitimate service', never malicious.
* All abuse.ch platforms are one upstream family (``abuse.ch``, P171). Returned URLs, domains and IPs
  are listed as hostile infrastructure (subject findings carry malicious/c2/suspicious tags and the
  ``blocklists`` attribute for the P376 guard). Feodo Tracker and SSLBL are one registration each
  (datasets ``ip_blocklists.feodo.json`` and ``ip_blocklists.sslbl.csv``, the names ip_blocklists uses)
  shared by abusech, ip_blocklists (P149) and ioc_feeds_offline (P159).
"""

from __future__ import annotations

import csv
import datetime as _dt
import json
import re
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from v3lum.core import links, noise
from v3lum.core.datasets import register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    OfflineError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

PROVIDER = "abusech"
SOURCES: dict[str, str] = {
    "urlhaus": "abusech.urlhaus",
    "threatfox": "abusech.threatfox",
    "malwarebazaar": "abusech.malwarebazaar",
    "feodotracker": "abusech.feodotracker",
    "sslbl": "abusech.sslbl",
}
PLATFORM_TITLES = {"urlhaus": "URLhaus", "threatfox": "ThreatFox", "malwarebazaar": "MalwareBazaar",
                   "feodotracker": "Feodo Tracker", "sslbl": "SSLBL"}
API_URLS: dict[str, str] = {
    "urlhaus": "https://urlhaus-api.abuse.ch/v1/",
    "threatfox": "https://threatfox-api.abuse.ch/api/v1/",
    "malwarebazaar": "https://mb-api.abuse.ch/api/v1/",
}
API_HOSTS = ("urlhaus-api.abuse.ch", "threatfox-api.abuse.ch", "mb-api.abuse.ch")
KEY_NAME = "abusech"
KEY_HEADER = "Auth-Key"
#: cond 9: the single coverage line shown when the key is missing
NO_KEY_LINE = "needs abuse.ch Auth-Key, free: v3lum keys setup"
#: cond 6: more IOCs than this from one pasted list are matched against the local exports only
BULK_THRESHOLD = 20
UPSTREAM = "abuse.ch"
#: per-platform cache TTL: URLhaus online/offline drives severity, so it is refreshed hourly
CACHE_TTL = {"urlhaus": 3600, "threatfox": 21600, "malwarebazaar": 21600}
#: family/tag queries return at most this many records
LIST_LIMIT = 25

#: cond 4: every query the module may build, with its allowed parameters (read-only APIs only)
QUERY_ALLOWLIST: dict[str, dict[str, frozenset[str]]] = {
    "urlhaus": {"url": frozenset({"url"}), "host": frozenset({"host"}), "payload": frozenset({"md5_hash", "sha256_hash"})},
    "threatfox": {"search_ioc": frozenset({"search_term"}), "search_hash": frozenset({"hash"}), "malwareinfo": frozenset({"malware", "limit"})},
    "malwarebazaar": {"get_info": frozenset({"hash"}), "get_siginfo": frozenset({"signature", "limit"})},
}

#: cond 3: v2 export URL templates; the key lives only in the path at download time (never stored)
KEY_PLACEHOLDER = "{AUTH_KEY}"
EXPORT_TEMPLATES: dict[str, str] = {
    "urlhaus": "https://urlhaus-api.abuse.ch/v2/files/exports/{AUTH_KEY}/recent.csv",
    "threatfox": "https://threatfox-api.abuse.ch/v2/files/exports/{AUTH_KEY}/recent.csv",
    "malwarebazaar": "https://mb-api.abuse.ch/v2/files/exports/{AUTH_KEY}/recent.csv",
}
#: local names of the exports (not registered until the core supports keyed dataset templates)
EXPORT_DATASETS: dict[str, str] = {
    "urlhaus": "abusech_urlhaus_recent.csv",
    "threatfox": "abusech_threatfox_recent.csv",
    "malwarebazaar": "abusech_malwarebazaar_recent.csv",
}
_EXPORT_COLUMNS = {
    "urlhaus": ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"],
    "threatfox": ["first_seen_utc", "ioc_id", "ioc_value", "ioc_type", "threat_type", "fk_malware", "malware_alias",
                  "malware_printable", "last_seen_utc", "confidence_level", "is_compromised", "reference", "tags", "anonymous", "reporter"],
    "malwarebazaar": ["first_seen_utc", "sha256_hash", "md5_hash", "sha1_hash", "reporter", "file_name", "file_type_guess",
                      "mime_type", "signature", "clamav", "vtpercent", "imphash", "ssdeep", "tlsh"],
}

_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_LAST_UPDATED_RE = re.compile(r"Last updated:\s*(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})", re.I)
_END_RE = re.compile(r"^#\s*END\s*\(?\s*(\d+)\s*\)?\s*entries", re.I | re.M)
_DEPRECATED_RE = re.compile(r"deprecated on (\d{4}-\d{2}-\d{2})", re.I)


# --------------------------------------------------------------------------------------
# small defensive helpers (shared with ioc_feeds_offline)
# --------------------------------------------------------------------------------------


def text(value: Any, limit: int = 300) -> str:
    """Untrusted scalar -> printable text ('' for None, containers, booleans and placeholders)."""
    if value is None or isinstance(value, (dict, list, bool)):
        return ""
    out = _CTRL_RE.sub("", str(value)).strip()[:limit]
    return "" if out.lower() in ("none", "null", "n/a") else out


def as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def parse_ts(value: Any) -> _dt.datetime | None:
    """abuse.ch / feed timestamps -> aware UTC datetime or None: ISO 8601, 'YYYY-MM-DD HH:MM:SS[ UTC]',
    'YYYY-MM-DD', 'DD-MM-YYYY', '08 February 2026 03:26 PM' and epoch seconds."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, _dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=_dt.timezone.utc)
    if isinstance(value, (int, float)):
        try:
            return _dt.datetime.fromtimestamp(float(value), _dt.timezone.utc) if 0 < value < 32503680000 else None
        except (OverflowError, OSError, ValueError):
            return None
    raw = text(value, 64)
    if not raw:
        return None
    if re.fullmatch(r"\d{9,11}", raw):
        return parse_ts(int(raw))
    raw = re.sub(r"\s*UTC$", "", raw, flags=re.I).strip()
    match = re.fullmatch(r"(\d{2})-(\d{2})-(\d{4})", raw)
    if match:
        try:
            return _dt.datetime(int(match.group(3)), int(match.group(2)), int(match.group(1)), tzinfo=_dt.timezone.utc)
        except ValueError:
            return None
    match = re.fullmatch(r"(\d{1,2}) ([A-Za-z]+) (\d{4})(?: (\d{1,2}):(\d{2})(?: ?([AaPp][Mm]))?)?", raw)
    if match:
        months = ("january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december")
        name = match.group(2).lower()
        if name not in months:
            return None
        hour, minute = int(match.group(4) or 0), int(match.group(5) or 0)
        ampm = (match.group(6) or "").lower()
        hour = hour + 12 if ampm == "pm" and hour < 12 else (0 if ampm == "am" and hour == 12 else hour)
        try:
            return _dt.datetime(int(match.group(3)), months.index(name) + 1, int(match.group(1)), hour, minute, tzinfo=_dt.timezone.utc)
        except ValueError:
            return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = _dt.datetime.fromisoformat(raw)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=_dt.timezone.utc)


def iso(value: Any) -> str | None:
    parsed = value if isinstance(value, _dt.datetime) else parse_ts(value)
    return parsed.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if parsed else None


def age_days(value: Any, now: _dt.datetime) -> float | None:
    parsed = value if isinstance(value, _dt.datetime) else parse_ts(value)
    return None if parsed is None else (now - parsed).total_seconds() / 86400.0


def split_tags(value: Any) -> list[str]:
    items = value if isinstance(value, list) else (value.split(",") if isinstance(value, str) else [])
    out: list[str] = []
    for item in items:
        tag = text(item, 80)
        if tag and tag not in out:
            out.append(tag)
    return out[:20]


def host_entity(host: str) -> Entity | None:
    """IPv4/IPv6/domain entity of a URL host or IOC value (None for junk)."""
    host = (host or "").strip().strip("[]").lower().rstrip(".")
    for etype in (T.IPV4, T.IPV6, T.DOMAIN):
        ent = Entity.try_make(etype, host)
        if ent is not None:
            return ent
    return None


def url_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def legit_service(host: str) -> str:
    """Why a host is a popular legitimate service (P169 warninglists, file-hosting/CDN/SaaS noise
    kinds, legitimate hosting platforms), '' otherwise (cond 7: abused legitimate service)."""
    ent = host_entity(host)
    if ent is None:
        return ""
    try:
        lists = noise.warninglists(ent)
        if lists:
            return f"warninglist {lists[0]}"
        kind = noise.noise_kind(ent)
        if kind in ("cdn", "cloud", "hosting", "saas"):
            return f"{kind} service"
        platform = noise.legit_platform(ent)
        if platform:
            return f"legitimate platform {platform}"
    except Exception:  # noqa: BLE001 - a list problem never turns a listing into 'benign'
        return ""
    return ""


# --------------------------------------------------------------------------------------
# local dataset copies (never downloaded by a module; `v3lum data update` refreshes them)
# --------------------------------------------------------------------------------------

_MEMO_LOCK = threading.Lock()
_MEMO: OrderedDict[tuple[str, str, str], Any] = OrderedDict()
_MEMO_MAX = 48


def local_copy(ctx: Any, name: str) -> tuple[Path | None, Any]:
    """(path, DatasetInfo) of the local copy of a dataset, or (None, info) when it was never
    downloaded. Never downloads (refresh runs out of band through `v3lum data update`), so an
    offline module stays offline at every TLP. The copy used is cited in ``ctx.data.used``."""
    info = ctx.data.info(name)
    if not getattr(info, "present", False):
        return None, info
    path = ctx.data.store.path(name)
    if not path.is_file():
        return None, info
    used = getattr(ctx.data, "used", None)
    if isinstance(used, list) and not any(isinstance(c, dict) and c.get("name") == name for c in used):
        used.append({"name": name, "sha256": info.sha256, "fetched_at": info.fetched_at, "licence": info.licence})
    return path, info


def memoized(name: str, version: str, kind: str, build: Callable[[], Any]) -> Any:
    """Parse a dataset version once per process (keyed by name, sha256 and reader kind)."""
    key = (name, version, kind)
    with _MEMO_LOCK:
        if key in _MEMO:
            _MEMO.move_to_end(key)
            return _MEMO[key]
    value = build()
    with _MEMO_LOCK:
        _MEMO[key] = value
        while len(_MEMO) > _MEMO_MAX:
            _MEMO.popitem(last=False)
    return value


def read_text(path: Path, limit: int = 200_000_000) -> str:
    with open(path, "rb") as fh:
        data = fh.read(limit)
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    return data.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------------------
# abuse.ch list files (Feodo Tracker, SSLBL, exports)
# --------------------------------------------------------------------------------------


def list_header(body: str) -> dict[str, Any]:
    """abuse.ch '#' banner -> {last_updated, end_count, deprecated, columns}. ``end_count`` is the
    '# END (N) entries' trailer: when it differs from the parsed rows the copy is incomplete."""
    head = body[:6000]
    columns = None
    for line in head.splitlines()[:40]:
        stripped = line.strip().lstrip("#").strip()
        if "," in stripped and re.match(r'^"?[A-Za-z_][A-Za-z0-9_]*"?\s*,', stripped):
            columns = [c.strip().strip('"').strip() for c in next(csv.reader([stripped], skipinitialspace=True))]
            break
    updated = _LAST_UPDATED_RE.search(head)
    end = _END_RE.search(body)
    deprecated = _DEPRECATED_RE.search(head)
    return {"last_updated": iso(updated.group(1)) if updated else None, "end_count": int(end.group(1)) if end else None,
            "deprecated": deprecated.group(1) if deprecated else None, "columns": columns}


def data_lines(body: str) -> list[str]:
    return [line for line in body.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def reason_family(reason: str) -> str:
    """'Vidar C&C' -> 'Vidar' (SSLBL listing reasons)."""
    family = re.sub(r"(?i)\s*(?:C&C|C2|botnet c&c|cnc)\s*$", "", reason or "").strip()
    return "" if family.lower() in ("", "malware", "unknown") else family[:60]


def parse_sslbl(body: str) -> dict[str, Any]:
    """SSLBL SSL Certificate Blacklist (Listingdate,SHA1,Listingreason) -> {meta, rows: {sha1: row},
    complete}. The only SSLBL list still maintained (the IP list is deprecated, JA3 stale since 2021)."""
    meta = list_header(body)
    rows: dict[str, dict[str, Any]] = {}
    for rec in csv.reader(data_lines(body)):
        if len(rec) < 2 or not re.fullmatch(r"[0-9a-fA-F]{40}", rec[1].strip()):
            continue
        reason = text(rec[2], 120) if len(rec) > 2 else ""
        rows[rec[1].strip().lower()] = {"listed": iso(rec[0]), "reason": reason, "family": reason_family(reason)}
    complete = meta["end_count"] is not None and meta["end_count"] == len(rows)
    return {"meta": meta, "rows": rows, "complete": complete}


def parse_feodo(obj: Any) -> dict[str, dict[str, Any]]:
    """Feodo Tracker ipblocklist.json -> {ip: row} (status, family, port, first_seen, last_online, AS)."""
    rows: dict[str, dict[str, Any]] = {}
    for raw in obj if isinstance(obj, list) else []:
        if not isinstance(raw, dict):
            continue
        ent = Entity.try_make(T.IPV4, text(raw.get("ip_address"), 60))
        if ent is None:
            continue
        rows[ent.value] = {
            "status": text(raw.get("status"), 20).lower(), "family": text(raw.get("malware"), 60), "port": as_int(raw.get("port")),
            "first_seen": iso(raw.get("first_seen")), "last_online": iso(raw.get("last_online")),
            "as_name": text(raw.get("as_name"), 120), "country": text(raw.get("country"), 4),
        }
    return rows


def _sslbl_valid(path: Path) -> bool:
    """Dataset validator: a copy that parses to 0 certificates never replaces a good one."""
    return bool(parse_sslbl(read_text(path, 50_000_000))["rows"])


def _feodo_valid(path: Path) -> bool:
    obj = json.loads(read_text(path, 20_000_000))
    return isinstance(obj, list)  # Feodo may legitimately list no IP at all


#: Feodo Tracker and SSLBL are registered once and shared with ip_blocklists (P149) and ioc_feeds_offline
#: (P159) (cond 8): the names and URLs are the ones ip_blocklists registers, so both registrations are one
#: dataset entry and `v3lum data update` downloads each list once.
FEODO_DATASET = register_dataset(
    "ip_blocklists.feodo.json",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    ttl=900,
    description="abuse.ch Feodo Tracker botnet C2 IP blocklist (JSON)",
    licence="CC0-1.0",
    terms_class="open",
    attribution="abuse.ch Feodo Tracker (https://feodotracker.abuse.ch/), CC0",
    provider=PROVIDER,
    source=SOURCES["feodotracker"],
    validate=_feodo_valid,
    min_bytes=2,
    expect="json",
    max_bytes=5_000_000,
)
SSLBL_DATASET = register_dataset(
    "ip_blocklists.sslbl.csv",
    "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
    ttl=86400,
    description="abuse.ch SSLBL SSL certificate blacklist (SHA1 fingerprints of C&C certificates)",
    licence="CC0-1.0",
    terms_class="open",
    attribution="abuse.ch SSL Blacklist (https://sslbl.abuse.ch/), CC0",
    provider=PROVIDER,
    source=SOURCES["sslbl"],
    validate=_sslbl_valid,
    min_bytes=100,
    expect="text",
    max_bytes=5_000_000,
)


def parse_export(body: str, platform: str) -> dict[str, list[dict[str, Any]]]:
    """URLhaus / ThreatFox / MalwareBazaar recent.csv -> {entity key: [rows]} (cond 6). Columns come
    from the '#' header line when present (the v2 layout is behind a login), else the legacy order."""
    meta = list_header(body)
    columns = meta.get("columns") or _EXPORT_COLUMNS.get(platform) or []
    out: dict[str, list[dict[str, Any]]] = {}

    def add(ent: Entity | None, row: dict[str, Any]) -> None:
        if ent is not None:
            out.setdefault(ent.key, []).append(row)

    for rec in csv.reader(data_lines(body), skipinitialspace=True):
        item = {columns[i]: rec[i].strip() for i in range(min(len(columns), len(rec)))}
        if platform == "urlhaus":
            url = text(item.get("url"), 2000)
            if url:
                add(Entity.try_make(T.URL, url), {"status": text(item.get("url_status"), 20).lower(), "threat": text(item.get("threat"), 40),
                                                  "first_seen": iso(item.get("dateadded")), "last_online": iso(item.get("last_online")),
                                                  "tags": split_tags(item.get("tags")), "reference": text(item.get("urlhaus_link"), 200)})
        elif platform == "threatfox":
            value, _port, etype = threatfox_value(text(item.get("ioc_value"), 2000), text(item.get("ioc_type"), 20))
            if value and etype:
                add(Entity.try_make(etype, value), {"family": text(item.get("malware_printable"), 80), "family_id": text(item.get("fk_malware"), 80),
                                                    "threat": text(item.get("threat_type"), 40), "confidence": as_int(item.get("confidence_level")),
                                                    "first_seen": iso(item.get("first_seen_utc")), "last_seen": iso(item.get("last_seen_utc")),
                                                    "tags": split_tags(item.get("tags"))})
        elif platform == "malwarebazaar":
            row = {"family": text(item.get("signature"), 80), "first_seen": iso(item.get("first_seen_utc")),
                   "file_type": text(item.get("file_type_guess"), 30), "sha256": text(item.get("sha256_hash"), 64).lower()}
            for column, etype in (("sha256_hash", T.SHA256), ("md5_hash", T.MD5), ("sha1_hash", T.SHA1)):
                add(Entity.try_make(etype, text(item.get(column), 64)), row)
    return out


# --------------------------------------------------------------------------------------
# requests (cond 4: read-only by construction)
# --------------------------------------------------------------------------------------


class QueryRefused(ValueError):
    """Any abuse.ch request outside :data:`QUERY_ALLOWLIST` (cond 4)."""


@dataclass(frozen=True)
class ApiRequest:
    platform: str
    query: str
    url: str
    form: dict[str, str] | None = None
    json: dict[str, Any] | None = None
    params: dict[str, Any] = field(default_factory=dict)


def build_request(platform: str, query: str, **params: Any) -> ApiRequest:
    """A read-only abuse.ch API request (POST): URLhaus form to /v1/{query}/, ThreatFox JSON
    {"query": ...}, MalwareBazaar form query=... . Raises QueryRefused for anything that is not in
    the allow-list (sample downloads, uploads, submissions, unknown parameters)."""
    p, q = str(platform or "").lower(), str(query or "").lower()
    allowed = QUERY_ALLOWLIST.get(p)
    if allowed is None or q not in allowed:
        raise QueryRefused(f"abuse.ch {platform}/{query} is not an allow-listed read-only query")
    extra = set(params) - allowed[q]
    if extra:
        raise QueryRefused(f"parameters {sorted(extra)} are not allowed for abuse.ch {p}/{q}")
    clean = {k: v for k, v in params.items() if v is not None and v != ""}
    if not clean:
        raise QueryRefused(f"abuse.ch {p}/{q} needs a parameter")
    if p == "urlhaus":
        return ApiRequest(p, q, f"{API_URLS[p]}{q}/", form={k: str(v) for k, v in clean.items()}, params=clean)
    if p == "threatfox":
        return ApiRequest(p, q, API_URLS[p], json={"query": q, **clean}, params=clean)
    return ApiRequest(p, q, API_URLS[p], form={"query": q, **{k: str(v) for k, v in clean.items()}}, params=clean)


def export_url(platform: str, key: str) -> str:
    """Key-bearing v2 export URL, for the download call only (never logged, cached or stored: the core
    redactor masks the configured key in every URL it emits, AR01)."""
    template = EXPORT_TEMPLATES.get(platform)
    if template is None:
        raise QueryRefused(f"unknown abuse.ch export {platform!r}")
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", key or ""):
        raise QueryRefused("the abuse.ch Auth-Key has an unexpected format")
    return template.replace(KEY_PLACEHOLDER, key)


def plan(entity: Entity, allowed: Iterable[str]) -> list[ApiRequest]:
    """API requests for an entity, restricted to the allowed platforms (C1 inputs per platform)."""
    ok = set(allowed)
    out: list[ApiRequest] = []

    def want(platform: str) -> bool:
        return SOURCES[platform] in ok

    value = entity.value
    if entity.type is T.URL:
        if want("urlhaus"):
            out.append(build_request("urlhaus", "url", url=value))
        if want("threatfox"):
            out.append(build_request("threatfox", "search_ioc", search_term=value))
    elif entity.type in (T.DOMAIN, T.IPV4):
        if want("urlhaus"):
            out.append(build_request("urlhaus", "host", host=value))
        if want("threatfox"):
            out.append(build_request("threatfox", "search_ioc", search_term=value))
    elif entity.type in (T.MD5, T.SHA256):
        if want("urlhaus"):
            out.append(build_request("urlhaus", "payload", **({"md5_hash": value} if entity.type is T.MD5 else {"sha256_hash": value})))
        if want("threatfox"):
            out.append(build_request("threatfox", "search_hash", hash=value))
        if want("malwarebazaar"):
            out.append(build_request("malwarebazaar", "get_info", hash=value))
    elif entity.type is T.SHA1:
        if want("malwarebazaar"):
            out.append(build_request("malwarebazaar", "get_info", hash=value))
    elif entity.type is T.MALWARE:
        if want("threatfox"):
            out.append(build_request("threatfox", "malwareinfo", malware=value, limit=LIST_LIMIT))
        if want("malwarebazaar"):
            out.append(build_request("malwarebazaar", "get_siginfo", signature=value, limit=LIST_LIMIT))
    return out


def api_platforms_for(entity: Entity) -> list[str]:
    """API platforms that answer this entity type (whatever the key, licence and bulk state)."""
    return sorted({r.platform for r in plan(entity, SOURCES.values())})


# --------------------------------------------------------------------------------------
# answers (cond 5: one central query_status mapping)
# --------------------------------------------------------------------------------------

EMPTY_STATUSES = frozenset({"no_result", "no_results"})
KEY_STATUSES = frozenset({"no_api_key", "no_auth_key", "unknown_auth_key", "invalid_auth_key", "unknown_key", "unauthorized"})


def map_query_status(obj: Any) -> tuple[Status, str, str]:
    """(Status, reason_code, text) of an abuse.ch JSON answer (cond 5).

    ok -> OK; no_result(s) and the documented '*_not_found' answers (MalwareBazaar hash/tag/signature
    not found) -> EMPTY; illegal_*, invalid_* and missing-input answers ('no_hash_provided'...) ->
    SKIPPED 'not_applicable' (the input was rejected); key problems -> NEEDS_KEY; anything else ->
    ERROR (never read as 'not listed')."""
    if not isinstance(obj, dict):
        return Status.ERROR, "error", "unexpected abuse.ch answer (not a JSON object): could not verify"
    if text(obj.get("error"), 40).lower() == "unauthorized":
        return Status.NEEDS_KEY, "needs_key", "abuse.ch Auth-Key missing or rejected (Unauthorized)"
    status = obj.get("query_status", obj.get("query_staus"))  # 'query_staus' is a typo found in the URLhaus docs
    status = status.strip().lower() if isinstance(status, str) else ""
    if status == "ok":
        return Status.OK, "", "ok"
    if status in EMPTY_STATUSES or (status.endswith("_not_found") and status != "file_not_found"):
        return Status.EMPTY, "", f"not listed ({status})"
    if status in KEY_STATUSES:
        return Status.NEEDS_KEY, "needs_key", f"abuse.ch Auth-Key problem ({status})"
    if status.startswith(("illegal_", "invalid_")) or (status.startswith("no_") and status.endswith("_provided")):
        return Status.SKIPPED, "not_applicable", f"abuse.ch rejected the input ({status})"
    return Status.ERROR, "error", f"abuse.ch query_status {status or 'missing'}: could not verify"


def threatfox_value(ioc: str, ioc_type: str) -> tuple[str, int | None, T | None]:
    """ThreatFox IOC -> (value, port, entity type); 'ip:port' keeps the IP only."""
    if not ioc:
        return "", None, None
    kind = (ioc_type or "").lower()
    if kind == "ip:port":
        host, _, port = ioc.rpartition(":")
        host = host.strip("[]")
        return host, as_int(port), (T.IPV6 if ":" in host else T.IPV4)
    if kind in ("md5_hash", "sha256_hash", "sha1_hash"):
        return ioc.lower(), None, {"md5_hash": T.MD5, "sha256_hash": T.SHA256, "sha1_hash": T.SHA1}[kind]
    if kind == "url":
        return ioc, None, T.URL
    if kind == "domain":
        return ioc.lower(), None, T.DOMAIN
    ent = host_entity(ioc)
    return (ent.value, None, ent.type) if ent else ("", None, None)


def parse_urlhaus(obj: dict[str, Any]) -> dict[str, Any]:
    """URLhaus url / host / payload answers -> {kind, records, payloads, ...}. Reporter handles and every
    download link are dropped (cond 4: sample downloads are never built)."""
    def record(raw: dict[str, Any]) -> dict[str, Any]:
        url = text(raw.get("url"), 2000)
        return {"url": url, "host": text(raw.get("host"), 300).lower() or url_host(url), "status": text(raw.get("url_status"), 20).lower(),
                "first_seen": iso(raw.get("date_added") or raw.get("firstseen")), "last_online": iso(raw.get("last_online") or raw.get("lastseen")),
                "threat": text(raw.get("threat"), 40), "tags": split_tags(raw.get("tags")), "reference": text(raw.get("urlhaus_reference"), 200)}

    out: dict[str, Any] = {"kind": "", "records": [], "payloads": [], "host": "", "first_seen": None, "url_count": None,
                           "blacklists": {}, "signature": "", "hashes": {}, "file_type": "", "file_size": None}
    for name, value in (obj.get("blacklists") or {}).items() if isinstance(obj.get("blacklists"), dict) else []:
        listing = text(value, 40)
        if listing and listing.lower() != "not listed":
            out["blacklists"][text(name, 40)] = listing
    if "payloads" in obj or ("url" in obj and "url_status" in obj):
        out["kind"] = "url"
        out["records"] = [record(obj)]
        out["host"] = out["records"][0]["host"]
        for raw in obj.get("payloads") or [] if isinstance(obj.get("payloads"), list) else []:
            if isinstance(raw, dict):
                out["payloads"].append({"sha256": text(raw.get("response_sha256"), 64).lower(), "md5": text(raw.get("response_md5"), 32).lower(),
                                        "file_type": text(raw.get("file_type"), 20), "signature": text(raw.get("signature"), 80),
                                        "first_seen": iso(raw.get("firstseen"))})
    elif "md5_hash" in obj or "sha256_hash" in obj:
        out["kind"] = "payload"
        out["hashes"] = {"md5": text(obj.get("md5_hash"), 32).lower(), "sha256": text(obj.get("sha256_hash"), 64).lower()}
        out["signature"] = text(obj.get("signature"), 80)
        out["file_type"] = text(obj.get("file_type"), 20)
        out["file_size"] = as_int(obj.get("file_size"))
        out["first_seen"] = iso(obj.get("firstseen"))
        out["last_seen"] = iso(obj.get("lastseen"))
        out["url_count"] = as_int(obj.get("url_count"))
        out["records"] = [record(r) for r in obj.get("urls") or [] if isinstance(r, dict)] if isinstance(obj.get("urls"), list) else []
    else:
        out["kind"] = "host"
        out["host"] = text(obj.get("host"), 300).lower()
        out["first_seen"] = iso(obj.get("firstseen"))
        out["url_count"] = as_int(obj.get("url_count"))
        out["records"] = [record(r) for r in obj.get("urls") or [] if isinstance(r, dict)] if isinstance(obj.get("urls"), list) else []
        for rec in out["records"]:
            rec["host"] = rec["host"] or out["host"]
    return out


def urlhaus_severity(status: str, last_online: Any, first_seen: Any, now: _dt.datetime, legit: str = "") -> dict[str, Any]:
    """cond 7: online, or last online <= 30 days -> high; offline > 90 days -> low 'historical';
    in between -> medium. Without last_online (host/payload answers) the listing date is the
    reference. A popular legitimate service -> info 'abused legitimate service', never malicious."""
    if legit:
        return {"severity": "info", "label": "abused legitimate service", "malicious": False, "basis": legit}
    if status == "online":
        return {"severity": "high", "label": "online", "malicious": True, "basis": "url_status"}
    ref, basis = parse_ts(last_online), "last_online"
    if ref is None:
        ref, basis = parse_ts(first_seen), "date_added"
    days = age_days(ref, now) if ref else None
    if days is None:
        return {"severity": "medium", "label": "offline (last activity unknown)", "malicious": True, "basis": "unknown"}
    if days <= 30:
        return {"severity": "high", "label": f"offline, active {int(days)} days ago", "malicious": True, "basis": basis}
    if days > 90:
        return {"severity": "low", "label": "historical", "malicious": True, "basis": basis}
    return {"severity": "medium", "label": f"offline for {int(days)} days", "malicious": True, "basis": basis}


def threatfox_label(confidence: Any) -> dict[str, Any]:
    """cond 7: confidence_level < 50 (or missing) -> 'suspicious' (medium, P322 'possible'), else malicious."""
    value = as_int(confidence)
    if value is None or value < 50:
        return {"label": "suspicious", "severity": "medium", "confidence": value, "p322": "possible"}
    return {"label": "malicious", "severity": "high", "confidence": value, "p322": "probable"}


def parse_threatfox(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """ThreatFox data[] -> records {value, port, type, threat, family, family_id, aliases, confidence,
    label, first/last seen, tags, reference, link, samples}. Reporter handles are dropped."""
    out = []
    for raw in obj.get("data") if isinstance(obj.get("data"), list) else []:
        if not isinstance(raw, dict):
            continue
        value, port, etype = threatfox_value(text(raw.get("ioc"), 2000), text(raw.get("ioc_type"), 20))
        if not value or etype is None:
            continue
        label = threatfox_label(raw.get("confidence_level"))
        ioc_id = text(raw.get("id"), 20)
        out.append({
            "value": value, "port": port, "type": etype, "threat": text(raw.get("threat_type"), 40),
            "family": text(raw.get("malware_printable"), 80), "family_id": text(raw.get("malware"), 80),
            "aliases": split_tags(raw.get("malware_alias")), "confidence": label["confidence"], "label": label["label"],
            "first_seen": iso(raw.get("first_seen")), "last_seen": iso(raw.get("last_seen")), "tags": split_tags(raw.get("tags")),
            "reference": text(raw.get("reference"), 500),
            "link": f"https://threatfox.abuse.ch/ioc/{ioc_id}/" if ioc_id.isdigit() else "",
            "samples": [{"md5": text(s.get("md5_hash"), 32).lower(), "sha256": text(s.get("sha256_hash"), 64).lower()}
                        for s in (raw.get("malware_samples") or []) if isinstance(s, dict)][:20] if isinstance(raw.get("malware_samples"), list) else [],
        })
    return out


_C2_KEYS = frozenset({"c2", "c2s", "c2_list", "c2_servers", "cncs", "cnc", "c2_urls"})


def vendor_c2(vendor_intel: Any) -> list[str]:
    """Strings under C2-like keys anywhere inside MalwareBazaar vendor_intel (and only there)."""
    found: list[str] = []
    stack = [(v, False) for v in vendor_intel.values()] if isinstance(vendor_intel, dict) else []
    while stack:
        item, under = stack.pop()
        if isinstance(item, dict):
            stack.extend((v, under or (isinstance(k, str) and k.lower() in _C2_KEYS)) for k, v in item.items())
        elif isinstance(item, list):
            stack.extend((v, under) for v in item)
        elif under and isinstance(item, str):
            value = text(item, 500)
            if value and value not in found:
                found.append(value)
    return found[:50]


def parse_malwarebazaar(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """MalwareBazaar get_info / get_siginfo data[] -> sample records. Dropped on purpose: comments
    (handles and display names), reporter, file_information and every download/get-file path."""
    out = []
    for raw in obj.get("data") if isinstance(obj.get("data"), list) else []:
        if not isinstance(raw, dict):
            continue
        sha256 = text(raw.get("sha256_hash"), 64).lower()
        intel = raw.get("intelligence") if isinstance(raw.get("intelligence"), dict) else {}
        out.append({
            "sha256": sha256, "sha1": text(raw.get("sha1_hash"), 40).lower(), "md5": text(raw.get("md5_hash"), 32).lower(),
            "first_seen": iso(raw.get("first_seen")), "last_seen": iso(raw.get("last_seen")),
            "file_name": text(raw.get("file_name"), 200), "file_type": text(raw.get("file_type"), 30), "file_size": as_int(raw.get("file_size")),
            "signature": text(raw.get("signature"), 80), "tags": split_tags(raw.get("tags")), "delivery_method": text(raw.get("delivery_method"), 40),
            "similarity": {k: text(raw.get(k), 200) for k in ("imphash", "tlsh", "ssdeep", "telfhash", "gimphash", "dhash_icon") if text(raw.get(k), 200)},
            "yara": [text(y.get("rule_name"), 120) for y in raw.get("yara_rules") or [] if isinstance(y, dict) and text(y.get("rule_name"), 120)][:20]
            if isinstance(raw.get("yara_rules"), list) else [],
            "clamav": [c for c in (text(x, 120) for x in intel.get("clamav") or [] ) if c][:20] if isinstance(intel.get("clamav"), list) else [],
            "vendor_c2": vendor_c2(raw.get("vendor_intel")),
            "link": f"https://bazaar.abuse.ch/sample/{sha256}/" if re.fullmatch(r"[0-9a-f]{64}", sha256) else "",
        })
    return out


# --------------------------------------------------------------------------------------
# bulk lists (cond 6)
# --------------------------------------------------------------------------------------

_BULK_LOCK = threading.Lock()
_BULK_SEEN: OrderedDict[tuple[str, str], set[str]] = OrderedDict()
_TEXT_PARENTS = ("text_blob:", "file:", "email_headers:")


def bulk_position(ctx: Any, entity: Entity) -> int:
    """How many IOCs of the same analyst input this module has seen in the scan so far (this one
    included); 0 outside a scan. IOCs of one pasted text/file count per parent; typed seeds count per
    scan. Above the threshold the run uses the local exports only (cond 6, terms s.7.3)."""
    case = str(getattr(ctx, "case_id", "") or "")
    if not case:
        return 0
    provenance = tuple(getattr(ctx, "provenance", ()) or ())
    if provenance and str(provenance[0][0]).startswith(_TEXT_PARENTS):
        group = str(provenance[0][0])
    elif getattr(ctx, "is_seed", False):
        group = "<seeds>"
    else:
        return 0
    key = (case, group)
    with _BULK_LOCK:
        seen = _BULK_SEEN.setdefault(key, set())
        _BULK_SEEN.move_to_end(key)
        seen.add(entity.key)
        while len(_BULK_SEEN) > 64:
            _BULK_SEEN.popitem(last=False)
        return len(seen)


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------

_FAILURE_ORDER = (Status.NEEDS_KEY, Status.QUOTA, Status.RATE_LIMITED, Status.BLOCKED, Status.UNAVAILABLE, Status.ERROR, Status.SKIPPED)


@register
class Abusech(Module):
    name = "abusech"
    title = "abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker, SSLBL)"
    description = (
        "abuse.ch platforms with one Auth-Key: URLhaus, ThreatFox and MalwareBazaar lookups (v2 exports for pasted "
        "lists), plus Feodo Tracker botnet C2 IPs and SSLBL certificate SHA1s matched locally."
    )
    category = "threat_intel_ioc"
    accepts = {T.URL, T.DOMAIN, T.IPV4, T.MD5, T.SHA1, T.SHA256, T.MALWARE, T.CERT_FP}
    produces = {T.URL, T.DOMAIN, T.IPV4, T.IPV6, T.MD5, T.SHA1, T.SHA256, T.MALWARE, T.IMPHASH, T.TLSH, T.SSDEEP, T.TELFHASH, T.GIMPHASH, T.ICON_DHASH}
    tags = {"reputation", "free"}
    reference = "https://abuse.ch/terms-of-use/"
    notice = (
        "MalwareBazaar, URLhaus and ThreatFox are 'license' (abuse.ch terms 2026-10-21 s.4.1): off under the corporate "
        "profile until licence-cleared (Spamhaus subscription or a written abuse.ch decision in licence_allow). Feodo "
        "Tracker and SSLBL are CC0 and run meanwhile. Read-only: samples are never downloaded, nothing is submitted."
    )
    terms = "license"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = PROVIDER
    sources = tuple(SOURCES.values())
    hosts = API_HOSTS
    access_model = "free_auth_limited"
    optional_keys = (KEY_NAME,)  # without the key: one coverage line + manual links (cond 9), never NEEDS_KEY before the run
    max_requests = 4
    expected_latency = 1.0
    timeout = 60.0
    min_interval = 1.0
    daily_quota = 2000
    cache_ttl = 3600
    max_pivots = 60
    manual_link = "threat_intel_g07:threatfox_ioc_search"
    default_enabled = True
    settings = {"abusech_bulk_threshold": BULK_THRESHOLD}

    # ---- run ---------------------------------------------------------------------------------
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        allowed = set(ctx.allowed_sources)
        now = ctx.now()
        answered: list[str] = []
        failures: list[tuple[Status, str, str]] = []
        hits = 0
        # ---- local open feeds (Feodo Tracker, SSLBL): no request, any key state
        if entity.type is T.IPV4 and SOURCES["feodotracker"] in allowed:
            hits += self._feodo(res, entity, ctx, now, answered, failures)
        if entity.type in (T.SHA1, T.CERT_FP) and SOURCES["sslbl"] in allowed:
            hits += self._sslbl(res, entity, ctx, now, answered, failures)
        # ---- licence-gated APIs
        platforms = [p for p in api_platforms_for(entity) if SOURCES[p] in allowed]
        blocked = [p for p in api_platforms_for(entity) if SOURCES[p] not in allowed]
        key = ctx.key(KEY_NAME)
        threshold = _threshold(ctx)
        bulk = bulk_position(ctx, entity) > threshold if platforms else False
        if platforms and bulk:
            hits += self._exports(res, entity, ctx, now, platforms, answered, failures, threshold)
        elif platforms and not key:
            for platform in platforms:
                res.source_status(SOURCES[platform], Status.NEEDS_KEY, reason_code="needs_key", reason=NO_KEY_LINE)
                failures.append((Status.NEEDS_KEY, "needs_key", NO_KEY_LINE))
            self._manual_links(res, entity)
        elif platforms:
            for request in plan(entity, (SOURCES[p] for p in platforms)):
                hits += self._query(res, entity, ctx, now, request, key, answered, failures)
        if blocked and not platforms:
            self._manual_links(res, entity)
        return self._outcome(res, entity, answered, failures, hits, blocked)

    def _outcome(self, res: ModuleResult, entity: Entity, answered: list[str], failures: list[tuple[Status, str, str]], hits: int,
                 blocked: list[str]) -> ModuleResult:
        if hits:
            return res
        if answered:
            return res.mark(Status.EMPTY)  # every source that answered: not listed (could-not-verify sources stay in source_statuses)
        if failures:
            failures.sort(key=lambda f: _FAILURE_ORDER.index(f[0]) if f[0] in _FAILURE_ORDER else len(_FAILURE_ORDER))
            status, code, reason = failures[0]
            return res.mark(status, reason, reason_code=code)
        if blocked:
            names = ", ".join(PLATFORM_TITLES[p] for p in blocked)
            return res.mark(Status.SKIPPED, f"{names}: licence-blocked under the active licence profile (manual links shown)", reason_code="licence")
        return res.mark(Status.SKIPPED, "no allowed abuse.ch source covers this entity type", reason_code="not_applicable")

    # ---- API queries ----------------------------------------------------------------------
    def _query(self, res: ModuleResult, entity: Entity, ctx: Any, now: _dt.datetime, request: ApiRequest, key: str,
               answered: list[str], failures: list[tuple[Status, str, str]]) -> int:
        source = SOURCES[request.platform]
        title = PLATFORM_TITLES[request.platform]
        try:
            resp = ctx.http.post(request.url, data=request.form, json_body=request.json, headers={KEY_HEADER: key},
                                 ttl=CACHE_TTL[request.platform], source=source)
            if resp.status == 401:
                raise AuthRequired(f"HTTP 401 from {url_host(request.url)}", 401, request.url)
            ctx.http.check(resp)
            try:
                obj = json.loads(resp.text)
            except (ValueError, RecursionError):
                obj = None
        except DeadlineExceeded:
            raise
        except (AuthRequired, RateLimited, QuotaExceeded, Blocked, OfflineError, HttpError, NetworkError) as exc:
            status, code = _exception_status(exc)
            reason = NO_KEY_LINE if status is Status.NEEDS_KEY and not key else f"{title}: {str(exc)[:160]}"
            if status is Status.NEEDS_KEY and key:
                reason = f"{title}: the abuse.ch Auth-Key was rejected (401): could not verify"
            res.source_status(source, status, reason_code=code, reason=reason)
            failures.append((status, code, reason))
            return 0
        status, code, reason = map_query_status(obj)
        if status is Status.OK:
            found = self._record(res, entity, ctx, now, request, obj)
            res.source_status(source, Status.OK if found else Status.EMPTY)
            answered.append(request.platform)
            return found
        if status is Status.EMPTY:
            res.source_status(source, Status.EMPTY)
            answered.append(request.platform)
            return 0
        reason = f"{title}: {reason}"
        res.source_status(source, status, reason_code=code, reason=reason)
        failures.append((status, code, reason))
        return 0

    def _record(self, res: ModuleResult, entity: Entity, ctx: Any, now: _dt.datetime, request: ApiRequest, obj: dict[str, Any]) -> int:
        if request.platform == "urlhaus":
            return self._urlhaus(res, entity, now, parse_urlhaus(obj))
        if request.platform == "threatfox":
            return self._threatfox(res, entity, now, parse_threatfox(obj), family_query=request.query == "malwareinfo")
        return self._malwarebazaar(res, entity, parse_malwarebazaar(obj), family_query=request.query == "get_siginfo")

    # ---- URLhaus ---------------------------------------------------------------------------
    def _urlhaus(self, res: ModuleResult, entity: Entity, now: _dt.datetime, parsed: dict[str, Any]) -> int:
        source = SOURCES["urlhaus"]
        records = [r for r in parsed["records"] if r.get("url")]
        if parsed["kind"] == "payload":
            hashes = parsed["hashes"]
            family = parsed["signature"]
            res.attr("malware_family", [family] if family else None)
            res.attr("file_type", parsed["file_type"] or None)
            res.attr("file_size", parsed["file_size"])
            res.attr("url_count", parsed["url_count"])
            _add_list(res, "blocklists", ["URLhaus"])
            res.attr("malicious", True)
            res.finding(
                "Payload listed on URLhaus",
                "high",
                f"URLhaus lists this file as a payload served by {parsed['url_count'] or len(records)} malware URL(s)"
                + (f"; family {family}" if family else "") + f"; first seen {parsed['first_seen'] or '?'}, last seen {parsed.get('last_seen') or '?'}.",
                confidence="probable",
                criterion="URLhaus payload listing: the file was downloaded from URLs reported as malware distribution",
                data={"platform": "URLhaus", "family": family, "url_count": parsed["url_count"], "hashes": hashes,
                      "urls": [r["url"] for r in records[:10]]},
                tags=["malware", "malicious"],
                source=source,
                observed_first=parsed["first_seen"],
                observed_last=parsed.get("last_seen"),
            )
            for other, etype in ((hashes.get("md5"), T.MD5), (hashes.get("sha256"), T.SHA256)):
                if other and other != entity.value:
                    res.pivot(etype, other, "same_file", confidence="confirmed")
            if family:
                res.pivot(T.MALWARE, family, "family", confidence="probable", expand=False)
            for rec in records[:15]:
                res.pivot(T.URL, rec["url"], "served_from", confidence="probable", expand=False,
                          note="hostile: malware distribution URL listed by URLhaus (never contact from the corporate egress)")
            return 1
        if not records:
            return 0
        assessed = []
        for rec in records:
            legit = legit_service(rec.get("host") or "")
            assessed.append((rec, urlhaus_severity(rec["status"], rec.get("last_online"), rec.get("first_seen"), now, legit)))
        order = ("info", "low", "medium", "high")
        worst_rec, worst = max(assessed, key=lambda item: order.index(item[1]["severity"]))
        online = sum(1 for rec, _ in assessed if rec["status"] == "online")
        statuses = sorted({rec["status"] or "unknown" for rec, _ in assessed})
        threats = sorted({rec["threat"] for rec, _ in assessed if rec.get("threat")})
        tags = sorted({t for rec, _ in assessed for t in rec["tags"]})
        first = min((rec["first_seen"] for rec, _ in assessed if rec.get("first_seen")), default=None)
        last = max((rec.get("last_online") or rec.get("first_seen") for rec, _ in assessed if rec.get("last_online") or rec.get("first_seen")), default=None)
        res.attr("url_status", statuses[0] if len(statuses) == 1 else statuses)
        res.attr("threat_type", threats[0] if len(threats) == 1 else threats)
        res.attr("tags", tags[:20])
        res.attr("url_count", parsed["url_count"] or len(records))
        res.attr("first_seen", first)
        res.attr("last_seen", last)
        if parsed["blacklists"]:
            res.attr("reputation", {f"urlhaus:{k}": v for k, v in parsed["blacklists"].items()})
        refs = [rec["reference"] for rec, _ in assessed if rec.get("reference", "").startswith("https://urlhaus.abuse.ch/")][:5]
        data = {"platform": "URLhaus", "status": statuses, "online": online, "listed_urls": len(records),
                "threat": threats, "tags": tags[:20], "first_seen": first, "last_activity": last, "basis": worst["basis"]}
        if worst["severity"] == "info":
            res.attr("reputation", {"urlhaus": "abused legitimate service"})
            res.finding(
                "Legitimate service abused to host malware (URLhaus)",
                "info",
                f"URLhaus lists {len(records)} malware URL(s) on this host, a popular legitimate service ({worst['basis']}): "
                "the listings concern individual files, not the service itself.",
                confidence="probable",
                data=data,
                tags=["abused_legit_service", "info"],
                references=refs,
                source=source,
                observed_first=first,
                observed_last=last,
            )
        else:
            historical = worst["label"] == "historical"
            _add_list(res, "blocklists", ["URLhaus"])
            res.attr("malicious", True)
            kind = "URL" if parsed["kind"] == "url" else "host"
            res.finding(
                f"Listed on URLhaus (malware {kind})",
                worst["severity"],
                f"URLhaus: {len(records)} listed URL(s), {online} online; status {', '.join(statuses)}; "
                + (f"threat {', '.join(threats)}; " if threats else "") + f"first seen {first or '?'}, last activity {last or '?'} ({worst['label']}).",
                confidence="probable",
                criterion=f"URLhaus listing {worst['label']} (online or active <= 30 days: high; offline > 90 days: historical)",
                data=data,
                tags=["malware", "malicious"] + (["historical"] if historical else []),
                references=refs,
                source=source,
                observed_first=first,
                observed_last=last,
            )
        hostile_note = "hostile: listed by URLhaus (never contact from the corporate egress)"
        if parsed["kind"] == "url":
            host = host_entity(parsed["host"]) if parsed["host"] else None
            if host is not None and worst["severity"] != "info":
                res.pivot(host.type, host.value, "url_host", confidence="probable", note=hostile_note)
            for payload in parsed["payloads"][:10]:
                if payload.get("sha256"):
                    res.pivot(T.SHA256, payload["sha256"], "serves_payload", confidence="probable", note="payload served by a URLhaus-listed URL")
                if payload.get("signature"):
                    res.pivot(T.MALWARE, payload["signature"], "family", confidence="possible", expand=False)
        else:
            for rec, _sev in assessed[:25]:
                if rec["url"] != entity.value:
                    res.pivot(T.URL, rec["url"], "hosts_url", confidence="probable", expand=False, note=hostile_note)
        return 1

    # ---- ThreatFox -------------------------------------------------------------------------
    def _threatfox(self, res: ModuleResult, entity: Entity, now: _dt.datetime, records: list[dict[str, Any]], *, family_query: bool) -> int:
        source = SOURCES["threatfox"]
        if family_query:
            if not records:
                return 0
            res.attr("ioc_count", {"ThreatFox": len(records)})
            res.finding(
                "Malware family tracked on ThreatFox",
                "info",
                f"ThreatFox lists {len(records)} recent IOC(s) for this family (up to {LIST_LIMIT} shown as pivots).",
                confidence="probable",
                data={"platform": "ThreatFox", "count": len(records), "threat_types": sorted({r["threat"] for r in records if r["threat"]})},
                source=source,
            )
            for rec in records[:LIST_LIMIT]:
                res.pivot(rec["type"], rec["value"], "contacted_by" if rec["type"] in (T.IPV4, T.IPV6, T.DOMAIN, T.URL) else "related",
                          confidence="possible", expand=False, note="hostile: ThreatFox IOC of the family (never contact from the corporate egress)")
            return 1
        exact = [r for r in records if _same_ioc(entity, r)]
        related = [r for r in records if r not in exact]
        hash_query = entity.type in (T.MD5, T.SHA256)
        if hash_query:  # search_hash: the records are the C2s/IOCs of this sample
            exact, related = records, []
        if not exact and not related:
            return 0
        main = exact or related
        labels = [threatfox_label(r["confidence"]) for r in main]
        best = max(labels, key=lambda lab: (lab["label"] == "malicious", lab["confidence"] or 0))
        families = sorted({r["family"] for r in main if r["family"]})
        family_ids = sorted({r["family_id"] for r in main if r["family_id"]})
        threats = sorted({r["threat"] for r in main if r["threat"]})
        first = min((r["first_seen"] for r in main if r["first_seen"]), default=None)
        last = max((r["last_seen"] or r["first_seen"] for r in main if r["last_seen"] or r["first_seen"]), default=None)
        infra = entity.type in (T.IPV4, T.IPV6, T.DOMAIN, T.URL)
        days = age_days(last, now)
        historical = infra and days is not None and days > 90
        severity = "low" if historical else best["severity"]
        res.attr("malware_family", families)
        res.attr("threat_type", threats[0] if len(threats) == 1 else threats)
        res.attr("source_confidence", best["confidence"])
        res.attr("first_seen", first)
        res.attr("last_seen", last)
        _add_list(res, "blocklists", ["ThreatFox"])
        if best["label"] == "malicious":
            res.attr("malicious", True)
        else:
            res.attr("suspicious", True)
        tags = ["c2"] if any(r["threat"] == "botnet_cc" for r in main) and infra else []
        tags += ["malicious"] if best["label"] == "malicious" else ["suspicious"]
        tags += ["historical"] if historical else []
        if hash_query:
            title, what = "Sample with ThreatFox IOCs", f"ThreatFox lists {len(main)} IOC(s) (C2s, payload URLs) for this sample"
        elif exact:
            title, what = "Listed on ThreatFox", f"ThreatFox lists the indicator ({len(exact)} record(s))"
        else:
            title, what = "Related IOCs on ThreatFox", f"ThreatFox lists {len(related)} related IOC(s) (e.g. URLs on this host)"
        res.finding(
            title,
            severity,
            f"{what}; family {', '.join(families) or '?'}; threat {', '.join(threats) or '?'}; confidence {best['confidence']}; "
            f"first seen {first or '?'}, last seen {last or '?'}" + (" (historical)" if historical else "") + ".",
            confidence=best["p322"],
            criterion=f"ThreatFox confidence_level {best['confidence']} ({best['label']}: < 50 is suspicious)"
                      + ("; last activity > 90 days ago: historical" if historical else ""),
            data={"platform": "ThreatFox", "families": families, "family_ids": family_ids, "threat_types": threats,
                  "confidence_level": best["confidence"], "label": best["label"], "records": len(main)},
            tags=tags,
            references=[r["link"] for r in main if r["link"]][:5],
            source=source,
            observed_first=first,
            observed_last=last,
        )
        for name in families:
            res.pivot(T.MALWARE, name, "family", confidence="probable", expand=False)
        relation = "communicates_with" if hash_query else "hosts_url"
        for rec in (main if hash_query else related)[:15]:
            if rec["value"] != entity.value:
                res.pivot(rec["type"], rec["value"], relation, confidence=best["p322"], expand=hash_query,
                          note="hostile: ThreatFox IOC (never contact from the corporate egress)")
        for rec in main[:5]:
            for sample in rec["samples"][:5]:
                if sample.get("sha256") and infra:
                    res.pivot(T.SHA256, sample["sha256"], "contacted_by", confidence="possible", expand=False, note="ThreatFox: sample associated with this IOC")
        return 1

    # ---- MalwareBazaar ----------------------------------------------------------------------
    def _malwarebazaar(self, res: ModuleResult, entity: Entity, records: list[dict[str, Any]], *, family_query: bool) -> int:
        source = SOURCES["malwarebazaar"]
        if not records:
            return 0
        if family_query:
            res.attr("ioc_count", {"MalwareBazaar": len(records)})
            res.finding(
                "Malware family tracked on MalwareBazaar",
                "info",
                f"MalwareBazaar lists {len(records)} recent sample(s) with this signature (up to {LIST_LIMIT} shown as pivots).",
                confidence="probable",
                data={"platform": "MalwareBazaar", "count": len(records)},
                source=source,
            )
            for rec in records[:LIST_LIMIT]:
                if rec["sha256"]:
                    res.pivot(T.SHA256, rec["sha256"], "related", confidence="possible", expand=False, note="MalwareBazaar sample of the family")
            return 1
        rec = records[0]
        family = rec["signature"]
        res.attr("malware_family", [family] if family else None)
        res.attr("file_type", rec["file_type"] or None)
        res.attr("file_size", rec["file_size"])
        res.attr("names", [rec["file_name"]] if rec["file_name"] else None)
        res.attr("tags", rec["tags"])
        res.attr("first_seen", rec["first_seen"])
        res.attr("last_seen", rec["last_seen"])
        res.attr("similarity_hashes", rec["similarity"])
        res.attr("yara_rules", rec["yara"])
        res.attr("av_signatures", rec["clamav"])
        res.attr("delivery_method", rec["delivery_method"] or None)
        res.attr("malicious", True)
        _add_list(res, "blocklists", ["MalwareBazaar"])
        res.finding(
            "Known malware sample on MalwareBazaar",
            "high",
            f"MalwareBazaar sample{(' of ' + family) if family else ''} ({rec['file_type'] or '?'}); first seen {rec['first_seen'] or '?'}"
            + (f"; YARA: {', '.join(rec['yara'][:3])}" if rec["yara"] else "") + ".",
            confidence="probable",
            criterion="the hash is a malware sample shared on MalwareBazaar (metadata only: samples are never downloaded)",
            data={"platform": "MalwareBazaar", "family": family, "file_type": rec["file_type"], "tags": rec["tags"],
                  "vendor_c2": rec["vendor_c2"][:10]},
            tags=["malware", "malicious"],
            references=[rec["link"]] if rec["link"] else [],
            source=source,
            observed_first=rec["first_seen"],
            observed_last=rec["last_seen"],
        )
        for value, etype in ((rec["sha256"], T.SHA256), (rec["sha1"], T.SHA1), (rec["md5"], T.MD5)):
            if value and value != entity.value:
                res.pivot(etype, value, "same_file", confidence="confirmed", expand=False)
        if family:
            res.pivot(T.MALWARE, family, "family", confidence="probable", expand=False)
        kinds = {"imphash": T.IMPHASH, "tlsh": T.TLSH, "ssdeep": T.SSDEEP, "telfhash": T.TELFHASH, "gimphash": T.GIMPHASH, "dhash_icon": T.ICON_DHASH}
        for name, value in rec["similarity"].items():
            res.pivot(kinds[name], value, "similarity_hash", confidence="confirmed", expand=False)
        for c2 in rec["vendor_c2"][:10]:
            target = Entity.try_make(T.URL, c2) if "://" in c2 else host_entity(c2.rsplit(":", 1)[0] if c2.count(":") == 1 else c2)
            if target is not None:
                res.pivot(target.type, target.value, "communicates_with", confidence="probable",
                          note="hostile: C2 reported by a sandbox vendor on MalwareBazaar (never contact from the corporate egress)")
        return 1

    # ---- local feeds (open, CC0) -----------------------------------------------------------
    def _feodo(self, res: ModuleResult, entity: Entity, ctx: Any, now: _dt.datetime, answered: list[str],
               failures: list[tuple[Status, str, str]]) -> int:
        source = SOURCES["feodotracker"]
        path, info = local_copy(ctx, FEODO_DATASET)
        if path is None:
            reason = f"Feodo Tracker list not downloaded: run v3lum data update {FEODO_DATASET}"
            res.source_status(source, Status.UNAVAILABLE, reason_code="dataset", reason=reason)
            failures.append((Status.UNAVAILABLE, "dataset", reason))
            return 0
        try:
            rows = memoized(FEODO_DATASET, info.sha256, "feodo", lambda: parse_feodo(json.loads(read_text(path, 20_000_000))))
        except (ValueError, OSError, RecursionError) as exc:
            reason = f"Feodo Tracker local copy unreadable ({type(exc).__name__}): run v3lum data update {FEODO_DATASET}"
            res.source_status(source, Status.ERROR, reason_code="error", reason=reason)
            failures.append((Status.ERROR, "error", reason))
            return 0
        answered.append("feodotracker")
        row = rows.get(entity.value)
        if row is None:
            res.source_status(source, Status.EMPTY)
            return 0
        res.source_status(source, Status.OK)
        last = row["last_online"] or row["first_seen"]
        days = age_days(last, now)
        if row["status"] == "online" or (days is not None and days <= 30):
            severity, label = "high", "online" if row["status"] == "online" else f"active {int(days or 0)} days ago"
        elif days is not None and days > 90:
            severity, label = "low", "historical"
        else:
            severity, label = "medium", f"offline for {int(days)} days" if days is not None else "offline"
        _add_list(res, "blocklists", ["Feodo Tracker"])
        res.attr("malware_family", [row["family"]] if row["family"] else None)
        res.attr("first_seen", row["first_seen"])
        res.attr("last_seen", row["last_online"])
        res.attr("malicious", True)
        res.finding(
            "Listed on Feodo Tracker (botnet C2)",
            severity,
            f"Feodo Tracker lists this IP as a {row['family'] or 'botnet'} C2 (port {row['port'] or '?'}, status {row['status'] or '?'}); "
            f"first seen {row['first_seen'] or '?'}, last online {row['last_online'] or '?'} ({label}). List copy fetched {info.fetched_at or '?'}.",
            confidence="probable",
            criterion=f"Feodo Tracker C2 listing ({label}: online or active <= 30 days high, > 90 days historical)",
            data={"platform": "Feodo Tracker", "status": row["status"], "family": row["family"], "port": row["port"],
                  "dataset_fetched_at": info.fetched_at},
            tags=["c2", "botnet", "malicious"] + (["historical"] if label == "historical" else []),
            references=["https://feodotracker.abuse.ch/"],
            source=source,
            observed_first=row["first_seen"],
            observed_last=row["last_online"],
        )
        if row["family"]:
            res.pivot(T.MALWARE, row["family"], "family", confidence="probable", expand=False)
        return 1

    def _sslbl(self, res: ModuleResult, entity: Entity, ctx: Any, now: _dt.datetime, answered: list[str],
               failures: list[tuple[Status, str, str]]) -> int:
        source = SOURCES["sslbl"]
        path, info = local_copy(ctx, SSLBL_DATASET)
        if path is None:
            reason = f"SSLBL certificate list not downloaded: run v3lum data update {SSLBL_DATASET}"
            res.source_status(source, Status.UNAVAILABLE, reason_code="dataset", reason=reason)
            failures.append((Status.UNAVAILABLE, "dataset", reason))
            return 0
        parsed = memoized(SSLBL_DATASET, info.sha256, "sslbl", lambda: parse_sslbl(read_text(path, 50_000_000)))
        if not parsed["rows"]:
            reason = f"SSLBL local copy parsed to 0 certificates (unhealthy): run v3lum data update {SSLBL_DATASET}"
            res.source_status(source, Status.ERROR, reason_code="error", reason=reason)
            failures.append((Status.ERROR, "error", reason))
            return 0
        answered.append("sslbl")
        row = parsed["rows"].get(entity.value.lower())
        if row is None:
            res.source_status(source, Status.EMPTY)
            return 0
        res.source_status(source, Status.OK)
        days = age_days(row["listed"], now)
        severity = "high" if days is None or days <= 365 else "medium"
        _add_list(res, "blocklists", ["SSLBL"])
        res.attr("malware_family", [row["family"]] if row["family"] else None)
        res.attr("first_seen", row["listed"])
        res.attr("malicious", True)
        res.finding(
            "Certificate listed on SSLBL",
            severity,
            f"abuse.ch SSLBL lists this certificate SHA1 ({row['reason'] or 'malicious certificate'}), listed {row['listed'] or '?'}.",
            confidence="probable",
            criterion="SSLBL listing of the certificate fingerprint (C&C certificate seen by abuse.ch)",
            data={"platform": "SSLBL", "reason": row["reason"], "family": row["family"], "listed": row["listed"],
                  "list_last_updated": parsed["meta"].get("last_updated"), "dataset_fetched_at": info.fetched_at},
            tags=["c2", "malicious"],
            references=["https://sslbl.abuse.ch/"],
            source=source,
            observed_first=row["listed"],
        )
        if row["family"]:
            res.pivot(T.MALWARE, row["family"], "family", confidence="probable", expand=False)
        return 1

    # ---- exports (bulk lists, cond 6) ------------------------------------------------------
    def _exports(self, res: ModuleResult, entity: Entity, ctx: Any, now: _dt.datetime, platforms: list[str],
                 answered: list[str], failures: list[tuple[Status, str, str]], threshold: int) -> int:
        hits = 0
        for platform in platforms:
            source, name, title = SOURCES[platform], EXPORT_DATASETS[platform], PLATFORM_TITLES[platform]
            path, info = local_copy(ctx, name)
            if path is None:
                reason = (f"{title}: pasted list of more than {threshold} IOCs is matched only against the local abuse.ch export "
                          f"(no per-IOC API calls, terms s.7.3); export {name} not downloaded")
                res.source_status(source, Status.UNAVAILABLE, reason_code="dataset", reason=reason)
                failures.append((Status.UNAVAILABLE, "dataset", reason))
                continue
            index = memoized(name, info.sha256, "export", lambda p=path, pl=platform: parse_export(read_text(p), pl))
            answered.append(platform)
            rows = index.get(entity.key) or []
            if not rows:
                res.source_status(source, Status.EMPTY)
                continue
            res.source_status(source, Status.OK)
            hits += 1
            row = rows[0]
            _add_list(res, "blocklists", [title])
            if platform == "urlhaus":
                sev = urlhaus_severity(row["status"], row.get("last_online"), row.get("first_seen"), now, legit_service(url_host(entity.value)))
                severity, conf, label = sev["severity"], "probable", sev["label"]
            elif platform == "threatfox":
                lab = threatfox_label(row.get("confidence"))
                severity, conf, label = lab["severity"], lab["p322"], lab["label"]
            else:
                severity, conf, label = "high", "probable", "malware sample"
            family = row.get("family") or ""
            res.finding(
                f"Listed in the {title} export",
                severity,
                f"{title} recent export lists the indicator ({label}" + (f", family {family}" if family else "")
                + f"); first seen {row.get('first_seen') or '?'}. Export copy fetched {info.fetched_at or '?'}.",
                confidence=conf,
                criterion=f"{title} recent export listing ({label}); matched locally for a pasted list (no per-IOC API call)",
                data={"platform": title, "family": family, "label": label, "dataset_fetched_at": info.fetched_at},
                tags=["malicious"] if severity in ("medium", "high") and label != "suspicious" else ["suspicious"],
                source=source,
                observed_first=row.get("first_seen"),
                observed_last=row.get("last_seen") or row.get("last_online"),
            )
            if family:
                res.pivot(T.MALWARE, family, "family", confidence="possible", expand=False)
        return hits

    # ---- manual links (cond 9) -------------------------------------------------------------
    def _manual_links(self, res: ModuleResult, entity: Entity) -> None:
        refs = {
            T.URL: ("urlhaus_search", "threatfox_ioc_search"),
            T.DOMAIN: ("urlhaus_search", "threatfox_ioc_search"),
            T.IPV4: ("urlhaus_search", "threatfox_ioc_search"),
            T.MD5: ("bazaar_md5_search", "threatfox_ioc_search", "urlhaus_search"),
            T.SHA256: ("bazaar_sha256_search", "threatfox_ioc_search", "urlhaus_search"),
            T.SHA1: ("bazaar_sha1_search",),
            T.MALWARE: ("bazaar_signature_search", "threatfox_malware_search"),
        }.get(entity.type, ())
        for ref in refs:
            rendered = links.render(f"threat_intel_g07:{ref}", entity)
            if rendered is not None:
                res.link(rendered.label, rendered.url)


def _threshold(ctx: Any) -> int:
    value = ctx.setting("abusech_bulk_threshold", BULK_THRESHOLD)
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return BULK_THRESHOLD


def _same_ioc(entity: Entity, record: dict[str, Any]) -> bool:
    value = record.get("value") or ""
    if entity.type is T.URL:
        other = Entity.try_make(T.URL, value)
        return other is not None and other.value == entity.value
    return value.lower() == entity.value.lower()


def _add_list(res: ModuleResult, attribute: str, values: list[str]) -> None:
    current = res.attributes.get(attribute)
    merged = list(current) if isinstance(current, list) else []
    for value in values:
        if value not in merged:
            merged.append(value)
    res.attr(attribute, merged)


def _exception_status(exc: Exception) -> tuple[Status, str]:
    if isinstance(exc, AuthRequired):
        return Status.NEEDS_KEY, "needs_key"
    if isinstance(exc, RateLimited):
        return Status.RATE_LIMITED, "rate_limited"
    if isinstance(exc, QuotaExceeded):
        return Status.QUOTA, "quota"
    if isinstance(exc, Blocked):
        code = getattr(exc, "reason_code", "challenge")
        return Status.BLOCKED, code if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge"
    if isinstance(exc, OfflineError):
        return Status.UNAVAILABLE, "offline"
    code = getattr(exc, "reason_code", "error")
    return Status.ERROR, code if code in ("timeout", "error") else "error"


def legacy_export_gone(body: Any) -> bool:
    """Recognise the 410 body of the legacy keyless exports (never used by this module, cond 5)."""
    return bool(re.search(r"410 Gone: legacy \w[\w ]*? file exports are no longer available", str(body or "")[:4000], re.I))
