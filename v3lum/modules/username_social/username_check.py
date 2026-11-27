"""P113 username_check: one tri-state username checker engine, two packs (A5).

``username_check`` is the default pack (run_on seeds, default_enabled True, at most setting
``username_default_sites`` sites, default 100, hard max 150, 150 requests and 120 s per handle);
``username_check_extended`` (v3lum/modules/username_social/username_check_extended.py) is the
opt-in pack (-M or --preset deep, 600 requests and 600 s per handle). Both run this engine.

What a run does (final conditions FC1-FC16 of P113, batch p1-G05-2):

* the packs are V3LUM selection lists (``v3lum/data/username_check/packs.json``: site ids plus
  the SHA-256 of the datasets they were built from, never merged data, FC3); site definitions come
  from the V3LUM overlay (``v3lum/data/username_check/overlay.json``: V3LUM-measured two-sided
  markers, per-site tiers and exclusions, FC4), from the WhatsMyName dataset (CC BY-SA 4.0,
  archived, downloaded at runtime, pinned by SHA-256, never bundled) and, for the extended pack,
  from the Maigret database (MIT, updated only by ``v3lum data update`` after its db_meta SHA-256
  check). Sherlock data supplies only username-syntax regexes (nested quantifiers dropped) and its
  false-positive exclusions list (FC5);
* every site is re-checked at runtime before it receives the handle: rule-2 oracle lint (FC6),
  legal floor (unauthenticated GET of a public profile only, FC7), excluded platforms (FC5/FC16),
  NSFW/sensitive categories (settings nsfw_sites / sensitive_sites), tier for the run's TLP (FC8),
  registry terms (FC16: 'unknown' never runs; the default pack only 'open'), the health record
  (FC15) and the handle syntax;
* one GET per handle per site, no retries, redirects not followed but evaluated, per-site timeout
  10 s, one request in flight per host and >= 1 s between requests to a host, global concurrency
  <= 8 across both packs, one control request with a random 20-character handle on FOUND sites
  (counted in the cap), a host stops after a 403, 429 or challenge, and the pack deadline is
  checked before every request (FC9/FC10);
* tri-state per site (FC11): FOUND only on the presence marker with no absence marker, ABSENT only
  on the absence marker, anything else (blocks, challenges, login redirects, 401/403/429/5xx,
  timeouts, odd answers) is UNKNOWN; evidence per site keeps the matched marker, URL, status,
  checked_at and the body SHA-256, never the body;
* output (FC12/FC13): one counts line, FOUND rows (site, URL, display name) as ``profiles``,
  has_account URL pivots with expand=False, POSSIBLE findings reading 'same handle does not prove
  identity', high-collision handles flagged (and never above info), UNKNOWN reasons aggregated for
  the coverage appendix.

Adapted behaviour (A6): the Maigret check types (message / status_code / response_url with
presenseStrs, absenceStrs and errors) and the WhatsMyName e_code/e_string/m_code/m_string rules are
re-implemented here from the projects' documentation (https://github.com/soxoj/maigret, MIT,
Copyright (c) 2020-2026 Soxoj; https://github.com/WebBreacher/WhatsMyName, CC BY-SA 4.0 data,
Copyright (C) 2015-2026 Micah Hoffman; https://github.com/sherlock-project/sherlock, MIT,
Copyright (c) 2019 Sherlock Project), as studied by research records C0226, C0228, C0256 and C0257
on 2026-11-25: no code or data of these projects is copied into this file. Notices:
v3lum/data/notices/username_check_*.json.

Pack build (maintainers, then commit the JSON)::

    from v3lum.modules.username_social import username_check as uc
    packs = uc.build_selection(wmn=wmn_bytes, maigret=maigret_bytes, sherlock=sherlock_bytes,
                               exclusions=exclusions_bytes, overlay=uc.load_overlay())
    # -> write v3lum/data/username_check/packs.json (the build log lists every dropped site)
"""

from __future__ import annotations

import functools
import hashlib
import html as _html
import json
import random
import re
import threading
from collections.abc import Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import parse_qsl, quote, urlsplit

from v3lum.config import SettingSpec
from v3lum.core import providers as _providers
from v3lum.core.context import ModuleState, StateError
from v3lum.core.datasets import DatasetError, DatasetUnavailable, DataStore, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    Blocked,
    Cancelled,
    ConfigError,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    PolicyError,
    QuotaExceeded,
    RateLimited,
    RequestCapReached,
)
from v3lum.core.lint import forbidden_probe
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, HealthResult, Module, register

# --------------------------------------------------------------------------------------------- constants

FOUND, ABSENT, UNKNOWN = "found", "absent", "unknown"
STATES = (FOUND, ABSENT, UNKNOWN)

DEFAULT_PACK = "username_check"
EXTENDED_PACK = "username_check_extended"
#: FC1: the default pack holds at most setting ``username_default_sites`` sites (default 100, hard max 150).
DEFAULT_SITES = 100
HARD_MAX_SITES = 150
SITES_SETTING = "username_default_sites"
#: FC10/FC1: request caps per username (sites + controls) and pack deadlines (seconds).
DEFAULT_CAP = 150
EXTENDED_CAP = 600
DEFAULT_DEADLINE = 120.0
EXTENDED_DEADLINE = 600.0
#: Module.timeout = pack deadline + GRACE: no new request starts when less than GRACE seconds remain.
GRACE = 15.0
#: FC9: per-site timeout, politeness and the global concurrency of the username lane (P339).
SITE_TIMEOUT = 10.0
MIN_INTERVAL = 1.0
MAX_CONCURRENCY = 8
CONTROL_LEN = 20
MAX_BODY_BYTES = 2_000_000
MAX_SCAN = 2_000_000
MAX_USERNAME_LEN = 64
HIGH_COLLISION_MIN_LEN = 5
#: FC15: doctor --sources re-tests at most 25 sites a day; 3 wrong marks disable a site.
SELFTEST_PER_DAY = 25
WRONG_LIMIT = 3
#: links emitted for sites that refused the check (A9 manual follow-up), at most this many.
MAX_MANUAL_LINKS = 25

TIERS_QUERYABLE = ("trusted", "community")
TERMS_CLASSES = ("open", "key-terms", "license", "noncommercial", "unknown")
SAME_HANDLE_NOTE = "same handle does not prove identity"
PROBABLE_SIGNALS = frozenset({"avatar_match_non_default", "extracted_id_match", "bio_link_known_entity"})  # P258
WMN_NSFW_CATEGORY = "xx NSFW xx"

#: Bundled V3LUM data (v3lum/data/username_check/).
OVERLAY_FILE = "username_check/overlay.json"
PACKS_FILE = "username_check/packs.json"
COLLISION_FILE = "username_check/collision.json"
#: ctx.state store shared by both packs (health records and the daily self-test).
ENGINE_STATE = DEFAULT_PACK

# ------------------------------------------------------------------------------------------- datasets

WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
WMN_SHA256 = "a8b8385bee4b4c79f1fcdd458749ec89ba9d8dab94230353d09020b90b436324"
MAIGRET_META_URL = "https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/db_meta.json"
MAIGRET_DATA_URL = "https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/data.json"
SHERLOCK_URL = "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json"
SHERLOCK_EXCLUSIONS_URL = "https://raw.githubusercontent.com/sherlock-project/sherlock/refs/heads/exclusions/false_positive_exclusions.txt"

WMN_ATTRIBUTION = (
    "WhatsMyName site data (https://github.com/WebBreacher/WhatsMyName, archived 2026-11-09), Copyright (C) 2015-2026 "
    "Micah Hoffman and contributors, CC BY-SA 4.0; downloaded at runtime, unmodified, never bundled"
)
MAIGRET_ATTRIBUTION = "Maigret site database (https://github.com/soxoj/maigret), Copyright (c) 2020-2026 Soxoj, MIT licence"
SHERLOCK_ATTRIBUTION = "Sherlock site manifest and exclusions (https://github.com/sherlock-project/sherlock), Copyright (c) 2019 Sherlock Project, MIT licence"

SRC_WMN = "github.username_check_wmn"
SRC_MAIGRET_META = "github.username_check_maigret_meta"
SRC_MAIGRET = "github.username_check_maigret"
SRC_SHERLOCK = "github.username_check_sherlock"
SRC_SHERLOCK_EXCLUSIONS = "github.username_check_sherlock_exclusions"


def _validate_with(parser_name: str) -> Any:
    """A dataset validator calling one of this file's parsers (resolved when a download is checked)."""

    def check(path: Path) -> bool:
        parsed = globals()[parser_name](path.read_bytes())
        if not parsed.get("ok"):
            raise ValueError(str(parsed.get("error") or "unusable dataset"))
        return True

    return check


def _validate_maigret(path: Path) -> bool:
    """FC3: the database is installed only when its SHA-256 equals db_meta's data_sha256 (the
    manifest is refreshed first by ``v3lum data update``: its dataset name sorts first)."""
    meta_path = path.parent / MAIGRET_META
    meta = parse_maigret_db_meta(meta_path.read_bytes()) if meta_path.is_file() else {"ok": False, "error": "db_meta.json not downloaded"}
    plan = maigret_update_plan(meta, None, path.read_bytes())
    if plan["action"] != "apply":
        raise ValueError(f"{plan['reason']} (run v3lum data update {MAIGRET_META} first)")
    parsed = parse_maigret_db(path.read_bytes())
    if not parsed["ok"]:
        raise ValueError(str(parsed["error"]))
    return True


WMN = register_dataset(
    "username_check.wmn-data.json",
    WMN_URL,
    ttl=30 * 86400,
    description="WhatsMyName site dataset (archived 2026-11-09): username pack site definitions (P113)",
    licence="CC-BY-SA-4.0",
    terms_class="open",
    attribution=WMN_ATTRIBUTION,
    provider="github",
    source=SRC_WMN,
    validate=_validate_with("parse_wmn_dataset"),
    min_bytes=5_000,
    expect="json",
    pinned_sha256=WMN_SHA256,
    max_bytes=2_000_000,
)
MAIGRET_META = register_dataset(
    "username_check.maigret-meta.json",
    MAIGRET_META_URL,
    ttl=86400,
    description="Maigret db_meta.json manifest: data_sha256 of the Maigret site database (P113 FC3)",
    licence="MIT",
    terms_class="open",
    attribution=MAIGRET_ATTRIBUTION,
    provider="github",
    source=SRC_MAIGRET_META,
    validate=_validate_with("parse_maigret_db_meta"),
    min_bytes=50,
    expect="json",
    max_bytes=100_000,
)
MAIGRET_DATA = register_dataset(
    "username_check.maigret-sites.json",
    MAIGRET_DATA_URL,
    ttl=86400,
    description="Maigret site database data.json (extended username pack; installed only after its db_meta SHA-256 check)",
    licence="MIT",
    terms_class="open",
    attribution=MAIGRET_ATTRIBUTION,
    provider="github",
    source=SRC_MAIGRET,
    validate=_validate_maigret,
    min_bytes=10_000,
    expect="json",
    max_bytes=20_000_000,
    large=True,
)
SHERLOCK_DATA = register_dataset(
    "username_check.sherlock-data.json",
    SHERLOCK_URL,
    ttl=7 * 86400,
    description="Sherlock site manifest: username-syntax regexCheck patterns and the exclusion name->host map only (P113 FC5)",
    licence="MIT",
    terms_class="open",
    attribution=SHERLOCK_ATTRIBUTION,
    provider="github",
    source=SRC_SHERLOCK,
    validate=_validate_with("parse_sherlock_manifest"),
    min_bytes=1_000,
    expect="json",
    max_bytes=2_000_000,
)
SHERLOCK_EXCLUSIONS = register_dataset(
    "username_check.sherlock-exclusions.txt",
    SHERLOCK_EXCLUSIONS_URL,
    ttl=86400,
    description="Sherlock false-positive exclusions list (refreshed at most daily; P113 FC5)",
    licence="MIT",
    terms_class="open",
    attribution=SHERLOCK_ATTRIBUTION,
    provider="github",
    source=SRC_SHERLOCK_EXCLUSIONS,
    validate=_validate_with("parse_sherlock_exclusions"),
    min_bytes=10,
    expect="text",
    max_bytes=100_000,
)

# --------------------------------------------------------------------------------------- generic helpers


def as_text(body: Any) -> str:
    """Body as text (bytes decoded as UTF-8 with replacement); '' for None."""
    if body is None:
        return ""
    if isinstance(body, (bytes, bytearray)):
        return bytes(body).decode("utf-8", errors="replace")
    if isinstance(body, str):
        return body
    if isinstance(body, (dict, list)):
        return json.dumps(body, ensure_ascii=False)
    return str(body)


def load_json(raw: Any) -> Any:
    """Parsed JSON from dict/list/str/bytes, or None for HTML, empty or truncated input."""
    if isinstance(raw, (dict, list)):
        return raw
    text = as_text(raw).lstrip("﻿").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def sha256_hex(data: Any) -> str:
    """SHA-256 of bytes/str (FC3 dataset pin, FC11 body hash)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, (bytes, bytearray)):
        data = as_text(data).encode("utf-8")
    return hashlib.sha256(bytes(data)).hexdigest()


def norm_host(url: Any) -> str:
    """Lower-case host of a URL template without 'www.' and without a leading handle placeholder label."""
    if not isinstance(url, str) or not url.strip():
        return ""
    u = url.strip()
    if "://" not in u:
        u = "https://" + u
    try:
        host = urlsplit(u).hostname or ""
    except ValueError:
        return ""
    host = host.lower().rstrip(".")
    for p in ("{account}.", "{username}.", "{}."):
        if host.startswith(p):
            host = host[len(p):]
    return host[4:] if host.startswith("www.") else host


def url_host(url: Any) -> str:
    """Exact lower-case host of a URL (no normalisation): what ctx.http checks against Module.hosts."""
    if not isinstance(url, str):
        return ""
    try:
        return (urlsplit(url.strip()).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def host_matches(host: str, suffix: str) -> bool:
    host, suffix = (host or "").lower(), (suffix or "").lower()
    return bool(host) and (host == suffix or host.endswith("." + suffix))


def _int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().isdigit():
        return int(v.strip())
    return None


def _seq(v: Any) -> list[Any]:
    """List of an iterable argument; [] for None, scalars, text, bytes and mappings."""
    if v is None or isinstance(v, (str, bytes, bytearray, dict, int, float, bool)):
        return []
    try:
        return list(v)
    except TypeError:
        return []


def _str_list(v: Any) -> list[str]:
    if isinstance(v, str):
        return [v] if v else []
    if isinstance(v, (list, tuple)):
        return [x for x in v if isinstance(x, str) and x]
    return []


def _lower_headers(headers: Any) -> dict[str, str]:
    if not isinstance(headers, Mapping):
        return {}
    return {k.lower(): (v if isinstance(v, str) else str(v)) for k, v in headers.items() if isinstance(k, str)}


# ---------------------------------------------------------------------------------- dataset parsers (FC3)

_RAW_GH_STATUS = re.compile(r"^\d{3}: [A-Za-z][A-Za-z ]{2,40}$")


def dataset_error_marker(raw: Any, expect: str = "json", min_bytes: int = 2) -> str | None:
    """Why a dataset download is unusable, else None: raw.githubusercontent.com status text
    ('404: Not Found'), an HTML page, an empty or tiny body, or (expect='json') invalid JSON."""
    if isinstance(raw, (dict, list)):
        return None
    text = as_text(raw).lstrip("﻿").strip()
    if not text:
        return "empty download"
    first = text.splitlines()[0].strip()
    if len(text) < 80 and _RAW_GH_STATUS.match(first):
        return f"download answered '{first}'"
    head = text[:300].lower()
    if head.startswith("<!doctype html") or "<html" in head:
        return "HTML page instead of dataset"
    if len(text.encode("utf-8")) < min_bytes:
        return "download too small"
    if expect == "json":
        try:
            json.loads(text)
        except (ValueError, RecursionError) as exc:
            return f"malformed JSON ({getattr(exc, 'msg', 'error')} at char {getattr(exc, 'pos', '?')})"
    return None


def parse_maigret_db_meta(raw: Any) -> dict[str, Any]:
    """Maigret db_meta.json -> {ok, error, version, updated_at, sites_count, data_sha256, data_url}."""
    out: dict[str, Any] = {"ok": False, "error": None, "version": None, "updated_at": None, "sites_count": None, "data_sha256": None, "data_url": None}
    marker = dataset_error_marker(raw)
    if marker:
        out["error"] = marker
        return out
    d = load_json(raw)
    if not isinstance(d, dict):
        out["error"] = "manifest is not a JSON object"
        return out
    sha, url = d.get("data_sha256"), d.get("data_url")
    out.update(
        version=_int(d.get("version")),
        updated_at=d.get("updated_at") if isinstance(d.get("updated_at"), str) else None,
        sites_count=_int(d.get("sites_count")),
    )
    if not (isinstance(sha, str) and re.fullmatch(r"[0-9a-fA-F]{64}", sha)):
        out["error"] = "data_sha256 missing or not 64 hex characters"
        return out
    if not (isinstance(url, str) and url.startswith("https://raw.githubusercontent.com/")):
        out["error"] = "data_url missing or not on raw.githubusercontent.com"
        return out
    out.update(ok=True, data_sha256=sha.lower(), data_url=url)
    return out


def maigret_update_plan(meta: Mapping[str, Any], pinned_sha256: Any, downloaded: bytes | None = None) -> dict[str, str]:
    """FC3: 'keep' | 'download' | 'apply' | 'reject' for ``v3lum data update`` (never mid-run).

    Without ``downloaded``: 'keep' when the manifest hash equals the pinned one, else 'download'.
    With the downloaded bytes: 'apply' only when their SHA-256 equals the manifest data_sha256."""
    if not isinstance(meta, Mapping) or not meta.get("ok"):
        return {"action": "keep", "reason": "manifest unusable: " + str((meta or {}).get("error"))}
    want = str(meta["data_sha256"])
    if downloaded is None:
        if isinstance(pinned_sha256, str) and pinned_sha256.lower() == want:
            return {"action": "keep", "reason": "pinned copy is current"}
        return {"action": "download", "reason": f"manifest {meta.get('updated_at')} has a new data_sha256"}
    got = sha256_hex(downloaded)
    if got != want:
        return {"action": "reject", "reason": f"sha256 mismatch with db_meta (got {got[:12]}, manifest {want[:12]})"}
    marker = dataset_error_marker(downloaded)
    if marker:
        return {"action": "reject", "reason": marker}
    return {"action": "apply", "reason": "sha256 verified against db_meta", "sha256": got}


def normalise_wmn_site(entry: Any) -> dict[str, Any] | None:
    """One WhatsMyName site -> normalised site dict (None when unusable)."""
    if not isinstance(entry, dict):
        return None
    name, uri = entry.get("name"), entry.get("uri_check")
    if not isinstance(name, str) or not name.strip() or not isinstance(uri, str) or not uri.startswith(("http://", "https://")):
        return None
    e_code, m_code = _int(entry.get("e_code")), _int(entry.get("m_code"))
    if e_code is None or m_code is None:
        return None
    e_string = entry.get("e_string") if isinstance(entry.get("e_string"), str) else ""
    m_string = entry.get("m_string") if isinstance(entry.get("m_string"), str) else ""
    pretty = entry.get("uri_pretty") if isinstance(entry.get("uri_pretty"), str) and entry.get("uri_pretty") else None
    post_body = entry.get("post_body") if isinstance(entry.get("post_body"), str) and entry.get("post_body") else None
    headers = {str(k): str(v) for k, v in entry["headers"].items()} if isinstance(entry.get("headers"), dict) else {}
    cat = entry.get("cat") if isinstance(entry.get("cat"), str) else ""
    sbc = entry.get("strip_bad_char") if isinstance(entry.get("strip_bad_char"), str) else ""
    return {
        "id": "wmn:" + name.strip(), "source": "wmn", "name": name.strip(),
        "check_url": uri, "profile_url": pretty or uri,
        "method": "POST" if post_body else "GET", "body": post_body, "headers": headers,
        "check_type": "markers",
        "presence": {"status": e_code, "strings": [e_string] if e_string else []},
        "absence": {"status": m_code, "strings": [m_string] if m_string else []},
        "errors": {}, "regex_check": None,
        "tags": [cat] if cat else [], "category": cat,
        "protection": _str_list(entry.get("protection")), "activation": False, "engine": None,
        "disabled": False, "id_type": "username", "protocol": None,
        "host": norm_host(uri), "profile_host": norm_host(pretty or uri),
        "strip_bad_char": sbc, "valid": entry.get("valid") is not False, "nsfw": False,
    }


def parse_wmn_dataset(raw: Any) -> dict[str, Any]:
    """WhatsMyName wmn-data.json -> {ok, error, license, sites, invalid, malformed}.
    'valid': false entries go to ``invalid`` (never queried)."""
    out: dict[str, Any] = {"ok": False, "error": None, "license": [], "sites": [], "invalid": [], "malformed": []}
    marker = dataset_error_marker(raw)
    if marker:
        out["error"] = marker
        return out
    data = load_json(raw)
    if not isinstance(data, dict) or not isinstance(data.get("sites"), list):
        out["error"] = "not a WhatsMyName dataset (no sites list)"
        return out
    out["license"] = _str_list(data.get("license"))
    for i, entry in enumerate(data["sites"]):
        site = normalise_wmn_site(entry)
        if site is None:
            out["malformed"].append(i)
        elif not site["valid"]:
            out["invalid"].append(site["name"])
        else:
            out["sites"].append(site)
    out["ok"] = True
    return out


def _merge_engine(site: dict[str, Any], engine_site: dict[str, Any]) -> dict[str, Any]:
    """Maigret engine template merge: engine scalars override, lists concatenate, dicts merge."""
    merged = {k: (list(v) if isinstance(v, list) else dict(v) if isinstance(v, dict) else v) for k, v in site.items()}
    for k, v in engine_site.items():
        if isinstance(v, dict):
            base = merged.get(k) if isinstance(merged.get(k), dict) else {}
            merged[k] = {**base, **v}
        elif isinstance(v, list):
            base = merged.get(k) if isinstance(merged.get(k), list) else []
            merged[k] = base + [x for x in v if x not in base]
        else:
            merged[k] = v
    return merged


def _fill_maigret(template: Any, url_main: str, url_subpath: str) -> str | None:
    if not isinstance(template, str) or not template:
        return None
    out = template.replace("{urlMain}", url_main).replace("{urlSubpath}", url_subpath)
    return re.sub(r"(?<!:)/{2,}", "/", out)


def normalise_maigret_site(name: Any, entry: Any, engines: Any = None) -> dict[str, Any] | None:
    """One Maigret site (engine template merged) -> normalised site dict, or None when unusable."""
    if not isinstance(name, str) or not isinstance(entry, dict):
        return None
    eng = entry.get("engine") if isinstance(entry.get("engine"), str) else None
    merged = dict(entry)
    if eng and isinstance(engines, dict) and isinstance(engines.get(eng), dict) and isinstance(engines[eng].get("site"), dict):
        merged = _merge_engine(entry, engines[eng]["site"])
    url_main = merged.get("urlMain") if isinstance(merged.get("urlMain"), str) else ""
    url_sub = merged.get("urlSubpath") if isinstance(merged.get("urlSubpath"), str) else ""
    url = _fill_maigret(merged.get("url"), url_main, url_sub)
    if not url:
        return None
    probe = _fill_maigret(merged.get("urlProbe"), url_main, url_sub) or url
    ct = merged.get("checkType") if merged.get("checkType") in ("message", "status_code", "response_url") else None
    method = str(merged.get("requestMethod") or "GET").upper()
    payload = merged.get("requestPayload")
    body = json.dumps(payload, ensure_ascii=False) if isinstance(payload, (dict, list)) else (payload if isinstance(payload, str) and payload else None)
    if body and method == "GET":
        method = "POST"
    errors = {str(k): str(v) for k, v in merged["errors"].items()} if isinstance(merged.get("errors"), dict) else {}
    headers = {str(k): str(v) for k, v in merged["headers"].items()} if isinstance(merged.get("headers"), dict) else {}
    protocol = merged.get("protocol").lower() if isinstance(merged.get("protocol"), str) else None
    return {
        "id": "maigret:" + name, "source": "maigret", "name": name,
        "check_url": probe, "profile_url": url, "method": method, "body": body, "headers": headers,
        "check_type": ct,
        "presence": {"status": None, "strings": _str_list(merged.get("presenseStrs"))},
        "absence": {"status": None, "strings": _str_list(merged.get("absenceStrs"))},
        "errors": errors,
        "regex_check": merged.get("regexCheck") if isinstance(merged.get("regexCheck"), str) else None,
        "tags": _str_list(merged.get("tags")), "category": "",
        "protection": _str_list(merged.get("protection")), "activation": bool(merged.get("activation")),
        "engine": eng, "disabled": bool(merged.get("disabled")),
        "id_type": merged.get("type") if isinstance(merged.get("type"), str) and merged.get("type") else "username",
        "protocol": protocol, "host": norm_host(probe), "profile_host": norm_host(url), "strip_bad_char": "", "valid": True,
        "nsfw": False,
    }


def parse_maigret_db(raw: Any) -> dict[str, Any]:
    """Maigret data.json -> {ok, error, sites, engines, malformed}."""
    out: dict[str, Any] = {"ok": False, "error": None, "sites": [], "engines": [], "malformed": []}
    marker = dataset_error_marker(raw)
    if marker:
        out["error"] = marker
        return out
    data = load_json(raw)
    if not isinstance(data, dict) or not isinstance(data.get("sites"), dict):
        out["error"] = "not a Maigret database (no sites object)"
        return out
    engines = data.get("engines") if isinstance(data.get("engines"), dict) else {}
    out["engines"] = sorted(engines)
    for name, entry in data["sites"].items():
        site = normalise_maigret_site(name, entry, engines)
        if site is None:
            out["malformed"].append(name)
        else:
            out["sites"].append(site)
    out["ok"] = True
    return out


def parse_sherlock_manifest(raw: Any) -> dict[str, Any]:
    """Sherlock data.json -> {ok, error, sites: {name: {name, host, regex_check, nsfw, probe, method, body}}}.
    V3LUM uses only regex_check (by host) and the name->host map of the exclusions (FC5)."""
    out: dict[str, Any] = {"ok": False, "error": None, "sites": {}}
    marker = dataset_error_marker(raw)
    if marker:
        out["error"] = marker
        return out
    data = load_json(raw)
    if not isinstance(data, dict):
        out["error"] = "not a Sherlock manifest (no object)"
        return out
    for name, s in data.items():
        if not isinstance(name, str) or name.startswith("$") or not isinstance(s, dict):
            continue
        url = s.get("url") if isinstance(s.get("url"), str) else ""
        main = s.get("urlMain") if isinstance(s.get("urlMain"), str) else ""
        out["sites"][name] = {
            "name": name, "url": url, "host": norm_host(url) or norm_host(main),
            "regex_check": s.get("regexCheck") if isinstance(s.get("regexCheck"), str) and s.get("regexCheck") else None,
            "nsfw": bool(s.get("isNSFW")), "probe": s.get("urlProbe") if isinstance(s.get("urlProbe"), str) else None,
            "method": str(s.get("request_method") or "GET").upper(),
            "body": json.dumps(s["request_payload"]) if isinstance(s.get("request_payload"), (dict, list)) else None,
        }
    out["ok"] = bool(out["sites"])
    if not out["ok"]:
        out["error"] = "no sites in the Sherlock manifest"
    return out


def has_nested_quantifier(pattern: Any) -> bool:
    """FC5: True when a quantified group contains a quantifier ('(a+)+', '(-[a-z]+)*'): ReDoS-prone,
    so the pattern is dropped. Escapes and character classes are skipped; lookarounds are not quantifiers."""
    if not isinstance(pattern, str):
        return False
    stack = [False]  # per open group: does its content hold a repeating quantifier?
    i, n = 0, len(pattern)
    closed: bool | None = None  # content flag of the group that just closed
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            closed = None
            continue
        if c == "[":
            j = i + 1
            if j < n and pattern[j] == "^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 2 if pattern[j] == "\\" else 1
            i = j + 1
            closed = None
            continue
        if c == "(":
            stack.append(False)
            i += 1
            closed = None
            continue
        if c == ")":
            inner = stack.pop() if len(stack) > 1 else False
            closed = inner
            if inner and len(stack) >= 1:
                stack[-1] = stack[-1] or inner
            i += 1
            continue
        repeats = False
        if c in "*+":
            repeats = True
        elif c == "{":
            m = re.match(r"\{(\d*)(,?)(\d*)\}", pattern[i:])
            if m:
                lo, comma, hi = m.group(1), m.group(2), m.group(3)
                repeats = bool((comma and (not hi or int(hi or 0) > 1)) or (not comma and lo and int(lo) > 1))
                i += len(m.group(0)) - 1
        if repeats:
            if closed:
                return True
            stack[-1] = True
        closed = None
        i += 1
    return False


def safe_regex(pattern: Any) -> re.Pattern[str] | None:
    """Compiled pattern, or None when it is invalid, too long or has a nested quantifier (FC5)."""
    if not isinstance(pattern, str) or not pattern or len(pattern) > 500 or has_nested_quantifier(pattern):
        return None
    try:
        return re.compile(pattern)
    except re.error:
        return None


def sherlock_username_regexes(manifest: Any) -> dict[str, Any]:
    """FC5: {'by_host': {host: pattern}, 'dropped': [{name, pattern, reason}]} from a parsed manifest."""
    out: dict[str, Any] = {"by_host": {}, "dropped": []}
    sites = manifest.get("sites") if isinstance(manifest, Mapping) else None
    if not isinstance(sites, Mapping):
        return out
    for name, s in sorted(sites.items()):
        pat = s.get("regex_check") if isinstance(s, Mapping) else None
        if not pat:
            continue
        if has_nested_quantifier(pat):
            out["dropped"].append({"name": name, "pattern": pat, "reason": "nested quantifier (ReDoS risk)"})
        elif safe_regex(pat) is None:
            out["dropped"].append({"name": name, "pattern": pat, "reason": "invalid pattern"})
        elif s.get("host"):
            out["by_host"].setdefault(s["host"], pat)
    return out


def parse_sherlock_exclusions(raw: Any) -> dict[str, Any]:
    """false_positive_exclusions.txt -> {ok, error, names}. A '404: Not Found' or HTML body is an
    error, never a site name."""
    out: dict[str, Any] = {"ok": False, "error": None, "names": []}
    marker = dataset_error_marker(raw, expect="text")
    if marker:
        out["error"] = marker
        return out
    names = []
    for line in as_text(raw).splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if len(s) > 80 or "<" in s or ">" in s:
            out["error"] = "not a plain list of site names"
            return out
        names.append(s)
    out.update(ok=bool(names), names=names, error=None if names else "empty exclusions list")
    return out


def sherlock_excluded_hosts(names: Any, manifest: Any) -> dict[str, Any]:
    """FC5: Sherlock exclusion names -> hosts through the manifest: {'hosts', 'by_name', 'unmapped'}."""
    sites = manifest.get("sites") if isinstance(manifest, Mapping) else {}
    sites = sites if isinstance(sites, Mapping) else {}
    lower = {k.lower(): k for k in sites}
    by_name: dict[str, str] = {}
    unmapped: list[str] = []
    for n in _seq(names):
        if not isinstance(n, str):
            continue
        key = n if n in sites else lower.get(n.lower())
        host = sites[key]["host"] if key else ""
        if host:
            by_name[n] = host
        else:
            unmapped.append(n)
    return {"hosts": sorted(set(by_name.values())), "by_name": by_name, "unmapped": unmapped}


# ------------------------------------------------------------------------- rule-2 lint and filters (FC5-FC7)

# V3LUM additions to the shared P327 tables (v3lum.core.lint.forbidden_probe) for the endpoint words
# FC6 names that the shared tables leave to the site-list lint: 'attempt', 'exists' and 'is_taken'
# in any URL part, and host labels of sign-up/login/registration services (signup.<host>, login.<host>).
_EXTRA_ORACLE_RULES: tuple[tuple[str, re.Pattern[str], tuple[str, ...]], ...] = (
    ("attempt", re.compile(r"attempt", re.I), ("path", "qkeys", "qvals")),
    ("exists", re.compile(r"exist(?:s|ence)?", re.I), ("path", "qkeys", "qvals")),
    ("is_taken", re.compile(r"is[-_]?taken|(?:user[-_]?)?name[-_]?taken|taken[-_]?(?:user[-_]?)?name", re.I), ("path", "qkeys", "qvals")),
    ("check_username", re.compile(r"check[-_]?(?:user[-_]?name|nick(?:[-_]?name)?|e?mail|handle)", re.I), ("path", "qkeys", "qvals")),
    ("login", re.compile(r"(?<![a-z])(?:log[-_]?in|sign[-_]?in(?![a-z])|authwall)", re.I), ("path", "qvals")),
    ("host_label", re.compile(r"(?<![a-z])(?:sign[-_]?up|register|log[-_]?in|sign[-_]?in)(?![a-z])", re.I), ("host",)),
)


def _url_parts(url: str) -> dict[str, list[str]]:
    try:
        sp = urlsplit(url)
        q = parse_qsl(sp.query, keep_blank_values=True)
    except ValueError:
        return {"host": [], "path": [url], "qkeys": [], "qvals": []}
    host = (sp.hostname or "").lower()
    return {"host": [h for h in host.split(".") if h], "path": [p for p in sp.path.split("/") if p], "qkeys": [k for k, _ in q], "qvals": [v for _, v in q]}


def oracle_lint(site: Any) -> str | None:
    """FC6 (rule 2, P327): 'oracle:<rule> (<where>)' when the probe URL or body is a sign-up, register,
    availability, check_username, validate, password-reset, login, exists, attempt or is_taken
    endpoint (the shared ``forbidden_probe`` tables plus the V3LUM additions above), else None.
    The Wayback availability API (an archive lookup, not an account oracle) is exempt from the
    V3LUM 'exists' additions only."""
    if not isinstance(site, Mapping):
        return "oracle:unreadable site entry"
    url = site.get("check_url") if isinstance(site.get("check_url"), str) else ""
    method = str(site.get("method") or "GET").upper()
    rule = forbidden_probe(url, method=method) if url else None
    if rule:
        return f"oracle:{rule} (url)"
    body = site.get("body") if isinstance(site.get("body"), str) else ""
    if body:
        rule = forbidden_probe("https://body.invalid/" + body.lstrip("/"), method="GET") or forbidden_probe("https://body.invalid/?" + body, method="GET")
        if rule:
            return f"oracle:{rule} (body)"
    parts = _url_parts(url)
    for name, rx, where in _EXTRA_ORACLE_RULES:
        for part in where:
            for token in parts.get(part, []):
                if rx.search(token):
                    return f"oracle:{name} ({part} '{token[:48]}')"
    if body:
        for name, rx, where in _EXTRA_ORACLE_RULES:
            if where != ("host",) and rx.search(body):
                return f"oracle:{name} (body)"
    return None


_CRED_HEADER_NAMES = frozenset({
    "cookie", "authorization", "proxy-authorization", "x-api-key", "api-key", "apikey", "app-token", "x-guest-token",
    "x-csrf-token", "x-xsrf-token", "x-auth-token", "x-access-token", "x-ig-app-id", "x-vt-anti-abuse-header",
})
_CRED_HEADER_RX = re.compile(r"token|secret|session|bearer|api[-_]?key|anti[-_]?abuse", re.I)
_CRED_QUERY_KEYS = frozenset({
    "api_key", "apikey", "key", "token", "access_token", "auth", "sig", "signature", "client_id", "client_secret",
    "app_key", "appkey", "app_id", "appid", "secret",
})
#: Dataset headers that may be sent (the UA comes from the provider http_profile, never from a dataset).
_ALLOWED_DATASET_HEADERS = frozenset({"accept", "accept-language"})
#: WhatsMyName 'protection: user-agent' means a public page needs a browser UA (overlay ua), not a wall.
_WMN_PASSABLE_PROTECTION = frozenset({"user-agent"})


def credential_findings(site: Any) -> list[str]:
    """FC7/A15: credential-bearing headers or URL parameters of a dataset entry (names only, never values)."""
    if not isinstance(site, Mapping):
        return []
    found = []
    for k in site.get("headers") or {}:
        kl = str(k).lower()
        if kl in _CRED_HEADER_NAMES or _CRED_HEADER_RX.search(kl):
            found.append("header:" + kl)
    url = site.get("check_url") if isinstance(site.get("check_url"), str) else ""
    try:
        q = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        q = []
    for k, v in q:
        if k.lower() in _CRED_QUERY_KEYS and v and "{" not in v:
            found.append("query:" + k.lower())
    return found


def legal_floor_reasons(site: Any) -> list[str]:
    """FC7 (+A9, A15, rule 3): reasons an entry may never be queried by either pack ([] = passes): only
    unauthenticated GETs of public profile pages/APIs; no POST body, cookie, token or key, activation
    flow, anti-bot-protected site (manual link only), Tor/I2P, DNS-protocol check, non-username
    identifier, e-mail lookup or the HudsonRock stealer API."""
    if not isinstance(site, Mapping):
        return ["unreadable site entry"]
    reasons = []
    if str(site.get("method") or "GET").upper() != "GET" or site.get("body"):
        reasons.append(f"legal floor: request method {site.get('method', '?')} with a body (only GET)")
    creds = credential_findings(site)
    if creds:
        reasons.append("legal floor: credential " + ", ".join(sorted(set(creds))))
    if site.get("activation"):
        reasons.append("legal floor: activation/token flow")
    prot = [p for p in _str_list(site.get("protection"))]
    if site.get("source") == "wmn":
        prot = [p for p in prot if p not in _WMN_PASSABLE_PROTECTION]
    if prot:
        reasons.append(f"anti-bot protection {','.join(sorted(set(prot)))} (A9: manual pivot link only)")
    hosts = [str(site.get("host") or ""), str(site.get("profile_host") or "")]
    tags = set(_str_list(site.get("tags")))
    if site.get("protocol") in ("tor", "i2p") or tags & {"tor", "i2p"} or any(h.endswith((".onion", ".i2p")) for h in hosts):
        reasons.append("legal floor: Tor/I2P site (opt-in only)")
    if site.get("protocol") == "dns":
        reasons.append("legal floor: DNS-protocol check (not a profile GET)")
    if site.get("id_type", "username") != "username":
        reasons.append(f"not a username lookup (identifier type {site.get('id_type')})")
    url = str(site.get("check_url") or "")
    if "{email}" in url or re.search(r"[?&](?:e?mail|email_address)=\{(?:account|username)\}", url, re.I):
        reasons.append("legal floor: e-mail lookup")
    if any(host_matches(h, "hudsonrock.com") for h in hosts) or re.search(r"info-?stealer", url, re.I):
        reasons.append("rule 3: stealer-log API (HudsonRock)")
    return reasons


#: FC5/FC16/FC7: platforms whose dedicated module checks presence itself, and pages never queried.
EXCLUDED_PLATFORMS: tuple[tuple[str, str], ...] = (
    ("bsky.app", "P099 bluesky"), ("bsky.social", "P099 bluesky"),
    ("npmjs.com", "P100 npm"), ("npmjs.org", "P100 npm"), ("pypi.org", "P100 PyPI"),
    ("codeberg.org", "P100 Codeberg"), ("dev.to", "P100 DEV"), ("huggingface.co", "P100 Hugging Face"),
    ("hackerone.com", "P100 HackerOne"),
    ("docker.com", "P102 dockerhub"), ("gitlab.com", "P103 gitlab_user"), ("keybase.io", "P104 keybase"),
    ("ycombinator.com", "P109 hackernews"), ("hacker-news.firebaseio.com", "P109 hackernews"),
    ("github.com", "P111 github_user"), ("github.io", "P111 github_user"),
    ("t.me", "P112 telegram_public"), ("telegram.me", "P112 telegram_public"), ("telegram.org", "P112 telegram_public"),
    ("wikipedia.org", "P120 wikimedia"), ("wikimedia.org", "P120 wikimedia"), ("wikidata.org", "P120 wikimedia"),
    ("wiktionary.org", "P120 wikimedia"), ("wikiquote.org", "P120 wikimedia"), ("wikibooks.org", "P120 wikimedia"),
    ("wikisource.org", "P120 wikimedia"), ("wikinews.org", "P120 wikimedia"), ("wikiversity.org", "P120 wikimedia"),
    ("wikivoyage.org", "P120 wikimedia"), ("mediawiki.org", "P120 wikimedia"),
    ("youtube.com", "FC16 YouTube pages (P110 legal floor)"), ("youtu.be", "FC16 YouTube pages (P110 legal floor)"),
    ("x.com", "FC16 x.com/twitter.com pages (P119)"), ("twitter.com", "FC16 x.com/twitter.com pages (P119)"),
    ("twimg.com", "FC16 x.com/twitter.com pages (P119)"),
    ("linkedin.com", "FC16 login-walled LinkedIn"),
    ("instagram.com", "FC7 login-only profiles (Instagram login interstitial)"),
    ("facebook.com", "FC7 login-only profiles (Facebook login interstitial)"),
)
_NEVER_WRAPPED = ("x.com", "twitter.com", "youtube.com", "youtu.be", "linkedin.com")
_FEDIVERSE_PATH = re.compile(r"/api/v1/accounts/lookup|/api/v2/search\?[^ ]*type=accounts|/\.well-known/webfinger", re.I)


def excluded_platform_reason(site: Any) -> str | None:
    """FC5/FC16: the reason when the entry targets a platform owned by a dedicated module or never
    queried (also wrapped in another service's query string), else None. Fediverse belongs to P105."""
    if not isinstance(site, Mapping):
        return None
    for h in (str(site.get("host") or ""), str(site.get("profile_host") or "")):
        for suffix, why in EXCLUDED_PLATFORMS:
            if host_matches(h, suffix):
                return "excluded platform: " + why
    url = str(site.get("check_url") or "")
    try:
        inner = " ".join(v for _, v in parse_qsl(urlsplit(url).query))
    except ValueError:
        inner = ""
    for suffix in _NEVER_WRAPPED:
        if re.search(r"(?:^|//|\.)" + re.escape(suffix) + r"(?:/|$)", inner, re.I):
            return f"excluded platform: FC16 page wrapped in another service ({suffix})"
    name = str(site.get("name") or "")
    if _FEDIVERSE_PATH.search(url) or "mastodon" in name.lower() or site.get("engine") == "Mastodon" or "mastodon" in _str_list(site.get("tags")):
        return "excluded platform: P105 mastodon (fediverse)"
    return None


_NSFW_TAGS = frozenset({"porn", "erotic", "webcam", "nsfw", "sex", "adult"})
_NSFW_RX = re.compile(
    r"porn|xxx|(?<![a-z])sex|nude|naked|nsfw|hentai|escort|camgirl|(?<![a-z])cams?(?![a-z])|"
    r"(?:web|live|sex|free|royal|bonga|my|stream)cams?|onlyfans|fansly|"
    r"erotic|fetish|bdsm|xhamster|xvideos|xnxx|stripchat|chaturbate|bongacams|myfreecams|"
    r"(?<![a-z])adult|milf|(?<![a-z])bbw",
    re.I,
)
_SENSITIVE: dict[str, tuple[frozenset[str], frozenset[str], re.Pattern[str]]] = {
    "dating": (frozenset({"dating"}), frozenset({"dating"}),
               re.compile(r"dating|tinder|badoo|okcupid|grindr|bumble|zoosk|meetic|friendfinder|plentyoffish|lovoo|mamba\.ru|singles", re.I)),
    "religion": (frozenset(), frozenset({"religion", "esoteric"}),
                 re.compile(r"church|christian|bible|catholic|gospel|islam(?!abad)|muslim|quran|koran|jewish|torah|synagog|"
                            r"mosque|religio|pastor|evangel|mormon|buddhis|(?<![a-z])hindu(?!stan)|sikh|umbanda|candombl|igreja|"
                            r"cat[oó]lic|crist[aã]o|b[ií]blia|esoteric|astrolog|tarot", re.I)),
    "health": (frozenset({"health"}), frozenset({"medicine", "psychology"}),
               re.compile(r"health|sa[uú]de|(?<![a-z])medic|hospital(?!ity)|clinic|(?<![a-z])therap|psych|(?<![a-z])mental|depress|"
                          r"anxiety|diabet|cancer|(?<![a-z])hiv(?![a-z])|(?<![a-z])addict|rehab|sober|alcoholic|7cups|patient", re.I)),
    "politics": (frozenset({"political"}), frozenset({"politics"}),
                 re.compile(r"politic|pol[ií]tic|partido|elei[cç]|senado|parliament|democrat|republican|"
                            r"conservative|socialist|communis|patriot|truthsocial|truth social|parler|gettr|gab\.com|sindicat", re.I)),
}


def sensitive_reasons(site: Any, *, nsfw_sites: bool = False, sensitive_sites: bool = False) -> list[str]:
    """FC7/A5: 'nsfw' and 'sensitive:<dating|religion|health|politics>' reasons (off by default; tags,
    WMN categories and a name/URL keyword filter because dataset NSFW tagging is incomplete)."""
    if not isinstance(site, Mapping):
        return []
    text = " ".join(str(site.get(k) or "") for k in ("name", "host", "profile_host", "check_url"))
    cat = str(site.get("category") or "")
    tags = set(_str_list(site.get("tags")))
    out = []
    if not nsfw_sites and (cat == WMN_NSFW_CATEGORY or tags & _NSFW_TAGS or site.get("nsfw") or _NSFW_RX.search(text)):
        out.append("nsfw")
    if not sensitive_sites:
        for label, (cats, mtags, rx) in _SENSITIVE.items():
            if cat in cats or tags & mtags or rx.search(text):
                out.append("sensitive:" + label)
    return out


def two_sided_markers(site: Any) -> bool:
    """FC2: explicit presence AND absence markers (body strings on both sides, distinct from each other)."""
    if not isinstance(site, Mapping):
        return False
    p = (site.get("presence") or {}).get("strings") or []
    a = (site.get("absence") or {}).get("strings") or []
    if not p or not a:
        return False
    if site.get("check_type") == "markers":
        same_status = (site.get("presence") or {}).get("status") == (site.get("absence") or {}).get("status")
        return not (same_status and any(x in y or y in x for x in p for y in a))
    return site.get("check_type") == "message"


def pack_filter_reasons(site: Any, *, pack: str = DEFAULT_PACK, sherlock_hosts: Iterable[str] = (), nsfw_sites: bool = False,
                        sensitive_sites: bool = False, maigret_backfill_approved: bool = False, override_sherlock: bool = False) -> list[str]:
    """FC1/FC2/FC5-FC7/FC16: every static reason an entry cannot enter ``pack`` ([] = may be considered;
    tier, terms and measured precision are checked against the overlay and the registry)."""
    if not isinstance(site, Mapping):
        return ["unreadable site entry"]
    reasons = []
    if not site.get("valid", True):
        reasons.append("invalid in dataset")
    if site.get("disabled"):
        reasons.append("disabled in dataset")
    if site.get("source") == "maigret" and site.get("engine"):
        reasons.append("engine entry (FC1: outside the curated profile)")
    if site.get("source") == "maigret" and site.get("check_type") is None:
        reasons.append("no checkType")
    reasons += legal_floor_reasons(site)
    lint = oracle_lint(site)
    if lint:
        reasons.append(lint)
    plat = excluded_platform_reason(site)
    if plat:
        reasons.append(plat)
    reasons += sensitive_reasons(site, nsfw_sites=nsfw_sites, sensitive_sites=sensitive_sites)
    hosts = {h for h in _seq(sherlock_hosts) if isinstance(h, str)}
    if not override_sherlock and any(host_matches(str(site.get(k) or ""), h) for h in hosts for k in ("host", "profile_host")):
        reasons.append("Sherlock false-positive exclusion list (FC5)")
    if pack == DEFAULT_PACK:
        if not two_sided_markers(site):
            reasons.append("FC2: needs explicit presence AND absence markers")
        if site.get("source") == "maigret" and not maigret_backfill_approved:
            reasons.append("FC2: Maigret back-fill needs legal_dpo approval in docs/LEGAL.md")
        if site.get("category") == "archived":
            reasons.append("archive lookup, not an account presence check")
    return reasons


# --------------------------------------------------------------------------------- probes (FC7, FC9)

_BAD_USERNAME = re.compile(r"[\s/\\?#%&=+<>\"'`{}|^\x00-\x1f\x7f]")


def render_probe(site: Any, username: Any, *, extra_regex: str | None = None) -> dict[str, Any]:
    """FC7/FC9: the single unauthenticated GET for one handle on one site.

    -> {'ok': True, url, profile_url, headers} or {'ok': False, 'reason'} when the handle does not fit
    the site syntax (dataset regexCheck, Sherlock regex by host; unsafe patterns ignored), the entry
    is not a GET or the handle carries URL metacharacters. Dataset User-Agent/Origin/Referer/Cookie
    headers are dropped (the UA comes from the provider http_profile, P326); http:// becomes https://."""
    if not isinstance(site, Mapping):
        return {"ok": False, "reason": "unreadable site entry"}
    if not isinstance(username, str):
        return {"ok": False, "reason": "username is not text"}
    u = username.strip().lstrip("@")
    for ch in str(site.get("strip_bad_char") or ""):
        u = u.replace(ch, "")
    if not u or len(u) > MAX_USERNAME_LEN or _BAD_USERNAME.search(u):
        return {"ok": False, "reason": "handle syntax"}
    if str(site.get("method") or "GET").upper() != "GET" or site.get("body"):
        return {"ok": False, "reason": "legal floor: only GET"}
    for pat in (site.get("regex_check"), extra_regex):
        if pat:
            rx = safe_regex(pat)
            if rx is not None and rx.search(u) is None:
                return {"ok": False, "reason": "site username syntax"}
    q = quote(u, safe="")
    placeholder = "{username}" if site.get("source") == "maigret" else "{account}"

    def fill(t: Any) -> str:
        out = str(t or "").replace(placeholder, q)
        return "https://" + out[len("http://"):] if out.startswith("http://") else out

    headers = {str(k): str(v) for k, v in (site.get("headers") or {}).items() if str(k).lower() in _ALLOWED_DATASET_HEADERS}
    return {"ok": True, "url": fill(site.get("check_url")), "profile_url": fill(site.get("profile_url")), "headers": headers}


def make_control_handle(rng: random.Random, length: int = CONTROL_LEN) -> str:
    """FC2/FC9: random control handle (a lower-case letter, then letters and digits)."""
    letters, digits = "abcdefghijklmnopqrstuvwxyz", "0123456789"
    length = max(8, min(int(length), MAX_USERNAME_LEN))
    return rng.choice(letters) + "".join(rng.choice(letters + digits) for _ in range(length - 1))


def control_probe(site: Any, rng: random.Random, *, extra_regex: str | None = None) -> dict[str, Any]:
    """A control probe with a random handle that fits the site syntax (20 characters, shorter when the
    site's pattern asks for it); {'ok': False} when none fits."""
    for length in (CONTROL_LEN, 15, 12, 10, 8):
        handle = make_control_handle(rng, length)
        probe = render_probe(site, handle, extra_regex=extra_regex)
        if probe.get("ok"):
            return {**probe, "handle": handle}
    return {"ok": False, "reason": "no random handle fits the site syntax"}


# ------------------------------------------------------------------------------- evaluation (FC9-FC11)

#: core P321 classification (status, reason_code) -> UNKNOWN reason
_CLASSIFIED_REASONS = {
    ("blocked", "challenge"): "challenge", ("blocked", "circuit"): "challenge", ("blocked", "hostile_host"): "challenge",
    ("blocked", "geo_block"): "geo_block", ("blocked", "login_wall"): "login_wall",
    ("rate_limited", "rate_limited"): "rate_limited", ("quota", "quota"): "quota",
}
#: UNKNOWN reasons after which the host's remaining sites stop (FC10)
STOP_HOST_REASONS = frozenset({"challenge", "geo_block", "rate_limited", "quota", "blocked"})


def _result(state: str, reason: str | None = None, marker: str | None = None, status: int | None = None, stop_host: bool = False, detail: str | None = None) -> dict[str, Any]:
    return {"state": state, "reason": reason, "marker": marker, "status": status, "stop_host": bool(stop_host), "detail": detail}


def _eval_markers(site: Mapping[str, Any], status: int, text: str) -> dict[str, Any]:
    p = site.get("presence") or {}
    a = site.get("absence") or {}
    p_strings, a_strings = p.get("strings") or [], a.get("strings") or []
    p_hit = next((s for s in p_strings if s in text), None)
    a_hit = next((s for s in a_strings if s in text), None)
    presence = status == p.get("status") and (p_hit is not None if p_strings else True)
    absence = status == a.get("status") and (a_hit is not None if a_strings else True)
    if presence and (absence or a_hit is not None):
        return _result(UNKNOWN, "both_markers", status=status)
    if presence:
        return _result(FOUND, marker=f"HTTP {status} + {p_hit!r}" if p_hit else f"HTTP {status}", status=status)
    if absence:
        return _result(ABSENT, marker=f"HTTP {status} + {a_hit!r}" if a_hit else f"HTTP {status}", status=status)
    return _result(UNKNOWN, "redirect" if 300 <= status < 400 else "no_marker", status=status)


def _eval_maigret(site: Mapping[str, Any], status: int, text: str, username: str | None) -> dict[str, Any]:
    p_strings = (site.get("presence") or {}).get("strings") or []
    a_strings = (site.get("absence") or {}).get("strings") or []
    ct = site.get("check_type")
    ok2xx = 200 <= status < 300
    if ct == "message":
        if p_strings:
            p_hit = next((s for s in p_strings if s in text), None)
        else:  # no presence string: a 2xx page that echoes the handle is the presence marker
            p_hit = "HTTP 2xx + handle echoed" if ok2xx and username and username.lower() in text.lower() else None
        a_hit = next((s for s in a_strings if s in text), None)
        if p_hit and a_hit and p_strings:
            return _result(UNKNOWN, "both_markers", status=status)
        if a_hit:
            return _result(ABSENT, marker=repr(a_hit), status=status)
        if p_hit and ok2xx:
            return _result(FOUND, marker=repr(p_hit) if p_strings else p_hit, status=status)
        return _result(UNKNOWN, "redirect" if 300 <= status < 400 else "no_marker", status=status)
    if ct == "status_code":
        if ok2xx and not any(s in text for s in a_strings):
            return _result(FOUND, marker=f"HTTP {status}", status=status)
        if status in (404, 410):
            return _result(ABSENT, marker=f"HTTP {status}", status=status)
        return _result(UNKNOWN, "redirect" if 300 <= status < 400 else "http_status", status=status)
    if ct == "response_url":
        if ok2xx:
            if not p_strings or any(s in text for s in p_strings):
                return _result(FOUND, marker=f"HTTP {status} (no redirect)", status=status)
            return _result(UNKNOWN, "no_marker", status=status)
        if 300 <= status < 400 or status == 404:
            return _result(ABSENT, marker=f"HTTP {status} (redirect/404)", status=status)
        return _result(UNKNOWN, "http_status", status=status)
    return _result(UNKNOWN, "malformed", status=status, detail="no checkType")


def evaluate_response(site: Any, status: Any, headers: Any = None, body: Any = None, *, username: str | None = None,
                      classification: Any = None, error: Any = None, truncated: bool = False) -> dict[str, Any]:
    """FC9-FC11: one site response -> {state, reason, marker, status, stop_host, detail}.

    UNKNOWN on a network error or timeout, on the core P321 classification (challenge, login wall,
    geo-block, rate limit, quota, error marker), on 401/403/429/5xx/999, on both or no markers and on
    a truncated body without a marker. FOUND only on the presence marker with no absence marker;
    ABSENT only on the absence marker. Redirects are not followed: a 3xx is evaluated against the
    markers. ``stop_host`` is set after a 403, 429, challenge, geo-block or quota signal (FC10)."""
    if error:
        e = str(error).lower()
        return _result(UNKNOWN, "timeout" if "timeout" in e or "timed out" in e else "network", detail=str(error)[:120])
    if not isinstance(status, int) or isinstance(status, bool):
        return _result(UNKNOWN, "network", detail="no HTTP status")
    if not isinstance(site, Mapping):
        return _result(UNKNOWN, "malformed", status=status, detail="unreadable site entry")
    if classification is not None:
        cls_status = str(getattr(classification, "status", "") or "")
        code = str(getattr(classification, "reason_code", "") or "")
        reason = _CLASSIFIED_REASONS.get((cls_status, code), "site_error" if cls_status == "error" else "blocked")
        stop = reason in STOP_HOST_REASONS or status in (403, 429)
        return _result(UNKNOWN, reason, status=status, stop_host=stop, detail=str(getattr(classification, "reason", "") or "")[:160])
    if status == 429:
        return _result(UNKNOWN, "rate_limited", status=status, stop_host=True)
    if status in (401, 403, 407, 430, 451, 999):
        return _result(UNKNOWN, "geo_block" if status == 451 else "blocked", status=status, stop_host=status in (403, 451))
    if status >= 500:
        return _result(UNKNOWN, "server_error", status=status)
    text = as_text(body)[:MAX_SCAN]
    for marker, msg in (site.get("errors") or {}).items():
        if marker and marker in text:
            return _result(UNKNOWN, "site_error", status=status, detail=str(msg)[:80])
    if site.get("check_type") == "markers":
        result = _eval_markers(site, status, text)
    else:
        result = _eval_maigret(site, status, text, username if isinstance(username, str) else None)
    if truncated and result["state"] == UNKNOWN:
        result["reason"] = "truncated"
    return result


def apply_control(found: Mapping[str, Any], control: Mapping[str, Any] | None) -> dict[str, Any]:
    """FC9/FC2: fold the single control request (random handle, same site) into a FOUND result.
    Control ABSENT -> FOUND confirmed; control FOUND -> UNKNOWN 'control_found' (the site answers
    FOUND for anything: a health strike, FC15); control UNKNOWN -> FOUND kept, control 'unverified'."""
    out = dict(found or {})
    if out.get("state") != FOUND:
        return out
    cs = (control or {}).get("state")
    if cs == FOUND:
        out.update(state=UNKNOWN, reason="control_found", control="found", health_strike=True)
    elif cs == ABSENT:
        out.update(control="absent")
    else:
        out.update(control="unverified", control_reason=(control or {}).get("reason") or "not sent")
    return out


def evidence_record(site_id: str, result: Mapping[str, Any], url: str, checked_at: str, body: Any = None) -> dict[str, Any]:
    """FC11: evidence per site, never the body: site, state, matched marker, reason, URL, status,
    checked_at and the body SHA-256."""
    return {
        "site": site_id, "state": result.get("state"), "marker": result.get("marker"), "reason": result.get("reason"),
        "url": url, "status": result.get("status"), "checked_at": checked_at,
        "body_sha256": sha256_hex(body) if body is not None else None,
    }


# ------------------------------------------------------------------------------- display names (FC12)

_META_TAG = re.compile(r"<meta\b[^>]{0,1000}>", re.I)
_ATTR = re.compile(r"([a-zA-Z_:.-]+)\s*=\s*(\"[^\"]*\"|'[^']*')")
_TITLE = re.compile(r"<title\b[^>]*>([^<]{0,300})</title>", re.I)


def meta_tags(html_text: Any) -> dict[str, str]:
    """{'og:title': ..., 'og:type': ...} from <meta property|name=... content=...> in any attribute order."""
    out: dict[str, str] = {}
    for tag in _META_TAG.findall(as_text(html_text)[:MAX_SCAN]):
        attrs = {k.lower(): v[1:-1] for k, v in _ATTR.findall(tag)}
        key = (attrs.get("property") or attrs.get("name") or "").lower()
        if key and "content" in attrs and key not in out:
            out[key] = _html.unescape(attrs["content"]).strip()
    return out


def clean_display_name(title: Any, username: str | None = None) -> str:
    """Strip site suffixes from a page title; '' when it only repeats the handle."""
    t = _html.unescape(str(title or "")).strip()
    t = re.sub(r"\s+on\s+about\.me$", "", t, flags=re.I)
    t = re.split(r"\s+[|•·]\s+", t)[0].strip()
    t = re.sub(r"\s+[-–—]\s+(?:Profile|Linktree|Dribbble|Kaggle|Medium|TikTok|Pinterest)\b.*$", "", t, flags=re.I)
    t = re.sub(r"\s*\(@?[\w.\-]+\)$", "", t).strip()
    if not t or "profile -" in t.lower() or len(t) > 120:
        return ""
    if isinstance(username, str) and t.lower().lstrip("@") == username.lower().lstrip("@"):
        return ""
    return t


_JSON_NAME_KEYS = ("displayName", "display_name", "author_name", "full_name", "fullName", "name")


def extract_display_name(body: Any, username: str | None = None) -> str:
    """FC12: display name of a FOUND page: JSON profile fields (Gravatar entry[0].displayName,
    oEmbed author_name...), else og:title, else <title>."""
    data = load_json(body)
    if isinstance(data, Mapping):
        entry = data.get("entry")
        if isinstance(entry, list) and entry and isinstance(entry[0], Mapping):
            data = entry[0]
        for key in _JSON_NAME_KEYS:
            value = data.get(key)
            if isinstance(value, Mapping):
                value = value.get("formatted")
            if isinstance(value, str) and value.strip():
                return clean_display_name(value, username)
        return ""
    tags = meta_tags(body)
    title = tags.get("og:title")
    if not title:
        m = _TITLE.search(as_text(body)[:MAX_SCAN])
        title = m.group(1) if m else ""
    return clean_display_name(title, username)


# ---------------------------------------------------------------------------------- output (FC12, FC13)

#: UNKNOWN reason -> (singular, plural) for the coverage appendix
UNKNOWN_LABELS: dict[str, tuple[str, str]] = {
    "challenge": ("blocked/WAF", "blocked/WAF"), "blocked": ("blocked/WAF", "blocked/WAF"),
    "rate_limited": ("rate limited", "rate limited"), "quota": ("quota exhausted", "quota exhausted"),
    "login_wall": ("login wall", "login walls"), "geo_block": ("geo-blocked", "geo-blocked"),
    "server_error": ("server error", "server errors"), "timeout": ("timeout", "timeouts"),
    "network": ("network error", "network errors"), "no_marker": ("no marker matched", "no marker matched"),
    "both_markers": ("conflicting markers", "conflicting markers"), "site_error": ("site error page", "site error pages"),
    "redirect": ("unexpected redirect", "unexpected redirects"), "http_status": ("unexpected HTTP status", "unexpected HTTP statuses"),
    "malformed": ("malformed response", "malformed responses"), "truncated": ("truncated page", "truncated pages"),
    "host_stopped": ("host stopped after a block", "hosts stopped after a block"),
    "control_found": ("control handle also found", "control handle also found"),
    "policy": ("request refused by policy", "requests refused by policy"), "error": ("error", "errors"),
}


def summarize_states(results: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    out = {FOUND: 0, ABSENT: 0, UNKNOWN: 0}
    for r in _seq(results):
        st = r.get("state") if isinstance(r, Mapping) else None
        if st in out:
            out[st] += 1
    return out


def counts_line(label: str, results: Iterable[Mapping[str, Any]], not_checked: int = 0) -> str:
    """FC12/FC15: the one counts line of a pack run."""
    c = summarize_states(results)
    return f"{label}: {c[FOUND]} found · {c[UNKNOWN]} could not verify · {c[ABSENT]} absent · {int(not_checked or 0)} not checked: budget"


def unknown_breakdown(results: Iterable[Mapping[str, Any]]) -> str:
    """FC12: aggregated UNKNOWN reasons for the coverage appendix, e.g. '22 blocked/WAF, 3 timeouts'."""
    counts: dict[tuple[str, str], int] = {}
    for r in _seq(results):
        if isinstance(r, Mapping) and r.get("state") == UNKNOWN:
            label = UNKNOWN_LABELS.get(str(r.get("reason") or ""), ("other", "other"))
            counts[label] = counts.get(label, 0) + 1
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0][0]))
    return ", ".join(f"{n} {label[0] if n == 1 else label[1]}" for label, n in ordered)


def found_rows(results: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    """FC12: FOUND rows only (site, URL, display name)."""
    return [
        {"site": str(r.get("name") or r.get("site") or ""), "url": str(r.get("profile_url") or r.get("url") or ""), "display_name": str(r.get("display_name") or "")}
        for r in _seq(results)
        if isinstance(r, Mapping) and r.get("state") == FOUND
    ]


def high_collision_reason(handle: Any, *, common: Iterable[str] = (), first_names: Iterable[str] = (), dictionary: Iterable[str] = ()) -> str | None:
    """FC13: the reason a handle is high-collision (shorter than 5 characters, a common username, a
    common first name or a dictionary word), else None; such hits never rise above info."""
    if not isinstance(handle, str) or not handle.strip():
        return "empty handle"
    h = handle.strip().lstrip("@").lower()
    if len(h) < HIGH_COLLISION_MIN_LEN:
        return f"short handle (< {HIGH_COLLISION_MIN_LEN} characters)"
    if h in {str(x).lower() for x in common or ()}:
        return "common username"
    if h in {str(x).lower() for x in first_names or ()}:
        return "common first name"
    if h in {str(x).lower() for x in dictionary or ()}:
        return "dictionary word"
    return None


def hit_confidence(linkage_signals: Iterable[str] = (), collision_reason: str | None = None) -> dict[str, Any]:
    """FC13: POSSIBLE unless a P258 linkage signal (non-default avatar match, extracted id match, bio
    link to a known entity) makes it PROBABLE; a high-collision handle caps the severity at info."""
    sig = {x for x in _seq(linkage_signals) if isinstance(x, str)} & PROBABLE_SIGNALS
    return {"confidence": "probable" if sig else "possible", "note": SAME_HANDLE_NOTE, "signals": sorted(sig),
            "severity_cap": "info" if collision_reason else None, "collision": collision_reason}


_TEXT_PARENTS = ("text:", "file:", "email_headers:")


def pack_run_gate(*, is_seed: bool, provenance: Iterable[Any] = (), entity_key: str = "", unconfirmed: Iterable[str] = ()) -> str | None:
    """FC14: why a pack must not run on this username, else None: packs run only on analyst-typed,
    confirmed seeds - never on pivots, never on usernames found in pasted text or files, and a token
    read as a username below 0.75 needs a TTY confirmation or a 'username:' prefix (the CLI lists the
    unconfirmed ones in ScanOptions.unconfirmed_seeds)."""
    if not is_seed:
        return "username packs run only on analyst-typed seeds, never on pivots (P113 FC14)"
    for step in _seq(provenance):
        parent = step[0] if isinstance(step, (list, tuple)) and step else step
        if isinstance(parent, str) and parent.startswith(_TEXT_PARENTS):
            return "usernames found in pasted text or files never run a username pack (P113 FC14)"
    if entity_key and entity_key in set(_seq(unconfirmed)):
        return "read as a username with low confidence: confirm it in a TTY or type 'username:<value>' (P113 FC14)"
    return None


# ------------------------------------------------------------------------------ health (FC2, FC15)


def calibration_verdict(claimed: Mapping[str, Any] | None, control: Mapping[str, Any] | None) -> str:
    """FC2/FC15: 'correct' (claimed FOUND, control ABSENT) | 'false_positive' (control FOUND) |
    'stale_fixture' (claimed ABSENT) | 'unknown' (anything else)."""
    c = (claimed or {}).get("state")
    n = (control or {}).get("state")
    if n == FOUND:
        return "false_positive"
    if c == FOUND and n == ABSENT:
        return "correct"
    if c == ABSENT:
        return "stale_fixture"
    return "unknown"


def health_update(record: Any, verdict: str, *, strikes: int = 0, checked_at: str = "") -> dict[str, Any]:
    """FC15: a site's health record after a self-test verdict or runtime strikes. Disabled when the
    self-test is a failure ('false_positive' or 'stale_fixture') or the site was marked wrong
    WRONG_LIMIT times; re-enabled when it passes again ('correct' clears the strikes). An 'unknown'
    verdict (blocked, timeout) keeps the previous state: could not verify is never a failure."""
    rec = dict(record) if isinstance(record, Mapping) else {}
    rec["strikes"] = max(0, int(rec.get("strikes") or 0)) + max(0, int(strikes or 0))
    if verdict:
        rec["last_verdict"] = verdict
        if checked_at:
            rec["checked_at"] = checked_at
    if verdict == "correct":
        rec["strikes"] = 0
        rec["disabled"] = False
    elif verdict in ("false_positive", "stale_fixture"):
        rec["disabled"] = True
    if rec["strikes"] >= WRONG_LIMIT:
        rec["disabled"] = True
    rec.setdefault("disabled", False)
    rec["reason"] = None if not rec["disabled"] else (
        f"marked wrong {rec['strikes']} times" if rec["strikes"] >= WRONG_LIMIT else f"self-test {rec.get('last_verdict')}")
    return rec


def doctor_rotation(site_ids: Iterable[str], day_index: int, per_day: int = SELFTEST_PER_DAY) -> list[str]:
    """FC15: deterministic rotating sample of <= 25 site ids for one day's self-test."""
    ids = sorted({str(s) for s in _seq(site_ids)})
    if not ids:
        return []
    per_day = max(1, min(int(per_day), SELFTEST_PER_DAY))
    if len(ids) <= per_day:
        return ids
    start = (int(day_index) * per_day) % len(ids)
    return [ids[(start + i) % len(ids)] for i in range(per_day)]


def simulate_schedule(jobs: Iterable[Any], *, concurrency: int = MAX_CONCURRENCY, min_interval: float = MIN_INTERVAL,
                      timeout: float = SITE_TIMEOUT, deadline: float = DEFAULT_DEADLINE) -> dict[str, Any]:
    """FC9/FC10/FC15: deterministic makespan of a pack run from recorded latencies (no clock, no
    threads): jobs [(host, latency_s)] in pack order, controls included; global concurrency, one
    request in flight per host, >= min_interval between request starts on a host, latency capped by
    the per-site timeout; jobs that would start at or after the deadline are 'not_checked'."""
    import heapq

    slots = [0.0] * max(1, int(concurrency))
    heapq.heapify(slots)
    host_next: dict[str, float] = {}
    makespan, completed, not_checked = 0.0, 0, 0
    for job in _seq(jobs):
        host, lat = (job[0], job[1]) if isinstance(job, (tuple, list)) and len(job) >= 2 else ("", 0.0)
        free = heapq.heappop(slots)
        start = max(free, host_next.get(host, 0.0))
        if start >= deadline:
            not_checked += 1
            heapq.heappush(slots, free)
            continue
        try:
            dur = min(max(0.0, float(lat)), float(timeout))
        except (TypeError, ValueError):
            dur = float(timeout)
        end = start + dur
        host_next[host] = max(end, start + float(min_interval))
        heapq.heappush(slots, end)
        makespan = max(makespan, end)
        completed += 1
    return {"makespan": round(makespan, 3), "completed": completed, "not_checked": not_checked}


# ------------------------------------------------------------------------------- overlay (FC4, FC8, FC16)


def _normalise_v3lum_definition(sid: str, d: Any) -> dict[str, Any] | None:
    if not isinstance(d, Mapping):
        return None
    uri = d.get("check_url")
    p, a = d.get("presence") or {}, d.get("absence") or {}
    if not isinstance(uri, str) or not uri.startswith("https://") or not isinstance(p, Mapping) or not isinstance(a, Mapping):
        return None
    if _int(p.get("status")) is None or _int(a.get("status")) is None:
        return None
    pretty = d.get("profile_url") if isinstance(d.get("profile_url"), str) and str(d.get("profile_url")).startswith("https://") else uri
    return {
        "id": sid, "source": "v3lum", "name": str(d.get("name") or sid), "check_url": uri, "profile_url": pretty,
        "method": "GET", "body": None, "headers": {}, "check_type": "markers",
        "presence": {"status": _int(p.get("status")), "strings": _str_list(p.get("strings"))},
        "absence": {"status": _int(a.get("status")), "strings": _str_list(a.get("strings"))},
        "errors": {}, "regex_check": d.get("regex_check") if isinstance(d.get("regex_check"), str) else None,
        "tags": _str_list(d.get("tags")), "category": d.get("category") if isinstance(d.get("category"), str) else "",
        "protection": [], "activation": False, "engine": None, "disabled": False, "id_type": "username", "protocol": None,
        "host": norm_host(uri), "profile_host": norm_host(pretty), "strip_bad_char": "", "valid": True, "nsfw": False,
    }


def parse_overlay(raw: Any) -> dict[str, Any]:
    """FC4/FC8/FC16: the V3LUM overlay -> {ok, error, sites, definitions, exclusions, maigret_backfill_approved}.

    sites: {site_id: {name, provider, source, hosts, tier, tier_rationale, terms_class, verdict,
    claimed, team_egress, br, cti, disabled, wrong_votes, override_sherlock, ua}}; unknown tiers and
    terms classes are coerced to 'unknown' (fail closed); definitions: normalised V3LUM sites."""
    out: dict[str, Any] = {"ok": False, "error": None, "sites": {}, "definitions": {}, "exclusions": {}, "maigret_backfill_approved": False}
    d = load_json(raw)
    if not isinstance(d, dict) or not isinstance(d.get("sites"), dict):
        out["error"] = "overlay is not an object with a sites map"
        return out
    for sid, s in d["sites"].items():
        if not isinstance(sid, str) or not isinstance(s, dict):
            continue
        terms = s.get("terms") if isinstance(s.get("terms"), dict) else {}
        cal = s.get("calibration") if isinstance(s.get("calibration"), dict) else {}
        hosts = tuple(h.lower() for h in _str_list(s.get("hosts")))
        out["sites"][sid] = {
            "name": str(s.get("name") or sid),
            "provider": s.get("provider") if isinstance(s.get("provider"), str) else "",
            "source": s.get("source") if isinstance(s.get("source"), str) else "",
            "hosts": hosts,
            "tier": s.get("tier") if s.get("tier") in ("trusted", "community", "unknown") else "unknown",
            "tier_rationale": s.get("tier_rationale") if isinstance(s.get("tier_rationale"), str) else "",
            "terms_class": terms.get("class") if terms.get("class") in TERMS_CLASSES else "unknown",
            "verdict": cal.get("verdict") if isinstance(cal.get("verdict"), str) else None,
            "claimed": cal.get("claimed") if isinstance(cal.get("claimed"), str) and cal.get("claimed") else None,
            "team_egress": cal.get("team_egress") is True,
            "br": s.get("br") is True, "cti": s.get("cti") is True,
            "disabled": s.get("disabled") is True, "wrong_votes": _int(s.get("wrong_votes")) or 0,
            "override_sherlock": isinstance(s.get("override_sherlock_exclusion"), dict),
            "ua": s.get("ua") if s.get("ua") in ("neutral", "browser") else "neutral",
        }
        site = _normalise_v3lum_definition(sid, s.get("definition")) if sid.startswith("v3lum:") else None
        if site is not None:
            out["definitions"][sid] = site
    if isinstance(d.get("exclusions"), dict):
        out["exclusions"] = {str(k): str(v) for k, v in d["exclusions"].items()}
    out["maigret_backfill_approved"] = d.get("maigret_backfill_approved") is True
    out["ok"] = True
    return out


def tier_allows(tier: Any, rationale: Any, tlp: str = "amber") -> bool:
    """FC8: only trusted/community sites with a recorded rationale receive a username; AMBER+STRICT
    allows trusted only; RED allows none (third-party disclosure)."""
    if tier not in TIERS_QUERYABLE or not rationale:
        return False
    t = str(tlp or "amber").lower()
    if t == "red":
        return False
    if t == "amber+strict":
        return tier == "trusted"
    return True


_TIER_RANK = {"trusted": 0, "community": 1, "unknown": 2}


def effective_tier(overlay_tier: str, provider_tier: str | None) -> str:
    """The lower of the overlay tier and the registry tier of the site's provider (fail closed)."""
    tiers = [t if t in _TIER_RANK else "unknown" for t in (overlay_tier, provider_tier or "unknown")]
    return max(tiers, key=lambda t: _TIER_RANK[t])


def site_registry_problems(sid: str, rec: Mapping[str, Any], registry: Any) -> list[str]:
    """Registry consistency of an overlay site: source registered, hosts owned by its provider, tiers equal."""
    problems = []
    src = registry.source(rec.get("source") or "") if rec.get("source") else None
    if src is None:
        return [f"{sid}: source {rec.get('source')!r} is not in the provider registry"]
    prov = registry.get(src.provider)
    if prov is None:
        return [f"{sid}: provider {src.provider!r} is not registered"]
    if rec.get("provider") and rec["provider"] != prov.id:
        problems.append(f"{sid}: overlay provider {rec['provider']!r} differs from the source's provider {prov.id!r}")
    for host in rec.get("hosts") or ():
        owner = registry.provider_for_host(host)
        if owner is None or owner.id != prov.id:
            problems.append(f"{sid}: host {host!r} is not owned by provider {prov.id!r}")
    if not rec.get("hosts"):
        problems.append(f"{sid}: no hosts recorded")
    if rec.get("tier") != prov.tier:
        problems.append(f"{sid}: overlay tier {rec.get('tier')!r} differs from the registry tier {prov.tier!r}")
    return problems


def _ordering_key(site: Mapping[str, Any], ov: Mapping[str, Any]) -> tuple[bool, bool, str]:
    is_br = bool(ov.get("br")) or "br" in _str_list(site.get("tags")) or str(site.get("host") or "").endswith(".br")
    return (not is_br, not bool(ov.get("cti")), str(site.get("name") or "").lower())


def build_selection(*, overlay: Mapping[str, Any], wmn: Any = None, maigret: Any = None, sherlock: Any = None, exclusions: Any = None,
                    registry: Any = None, built_at: str = "", nsfw_sites: bool = False, sensitive_sites: bool = False) -> dict[str, Any]:
    """FC1-FC3, FC6, FC8, FC16 pack build: V3LUM selection lists, never merged data.

    ``overlay`` is :func:`parse_overlay` output; ``wmn``/``maigret``/``sherlock``/``exclusions`` the
    raw dataset bytes (optional). A site is selected only when it passes every static filter
    (:func:`pack_filter_reasons`: oracle lint, legal floor, excluded platforms, NSFW/sensitive,
    Sherlock exclusions, two-sided markers for the default pack), is not an overlay exclusion, is
    recorded in the overlay with a trusted/community tier and rationale whose provider registry entry
    agrees (FC8), and - for the default pack - has registry terms 'open' (FC16) and a 'correct'
    calibration (FC2). One definition per host (V3LUM definitions first, then WhatsMyName, then
    Maigret); BR-tagged then CTI-relevant sites first. The default list holds at most 150 sites (the
    runtime takes ``username_default_sites``); the extended list holds the other eligible sites.
    The build log names every dropped entry and why (FC6: dropped and logged)."""
    reg = registry or _providers.registry()
    ov_sites = overlay.get("sites") or {}
    exclusions_ov = overlay.get("exclusions") or {}
    backfill = bool(overlay.get("maigret_backfill_approved"))
    datasets: dict[str, Any] = {}
    pool: list[dict[str, Any]] = list((overlay.get("definitions") or {}).values())
    log: dict[str, Any] = {"lint_dropped": {}, "not_selected": {}, "unmapped_exclusions": []}
    if wmn is not None:
        parsed = parse_wmn_dataset(wmn)
        datasets["wmn"] = {"name": WMN, "sha256": sha256_hex(wmn), "ok": parsed["ok"], "sites": len(parsed["sites"])}
        pool += parsed["sites"]
    if maigret is not None:
        parsed = parse_maigret_db(maigret)
        datasets["maigret"] = {"name": MAIGRET_DATA, "sha256": sha256_hex(maigret), "ok": parsed["ok"], "sites": len(parsed["sites"])}
        pool += parsed["sites"]
    sherlock_hosts: list[str] = []
    if sherlock is not None:
        manifest = parse_sherlock_manifest(sherlock)
        datasets["sherlock"] = {"name": SHERLOCK_DATA, "sha256": sha256_hex(sherlock), "ok": manifest["ok"]}
        if exclusions is not None:
            excl = parse_sherlock_exclusions(exclusions)
            datasets["sherlock_exclusions"] = {"name": SHERLOCK_EXCLUSIONS, "sha256": sha256_hex(exclusions), "ok": excl["ok"]}
            mapped = sherlock_excluded_hosts(excl["names"], manifest)
            sherlock_hosts = mapped["hosts"]
            log["unmapped_exclusions"] = mapped["unmapped"]
    rank = {"v3lum": 0, "wmn": 1, "maigret": 2}
    pool.sort(key=lambda s: (rank.get(str(s.get("source")), 3), str(s.get("name") or "").lower()))
    eligible: dict[str, list[dict[str, Any]]] = {DEFAULT_PACK: [], EXTENDED_PACK: []}
    seen_hosts: dict[str, set[str]] = {DEFAULT_PACK: set(), EXTENDED_PACK: set()}
    reasons_by_site: dict[str, list[str]] = {}
    for site in pool:
        sid = str(site.get("id"))
        ov = ov_sites.get(sid)
        for pack in (DEFAULT_PACK, EXTENDED_PACK):
            reasons = pack_filter_reasons(site, pack=pack, sherlock_hosts=sherlock_hosts, nsfw_sites=nsfw_sites, sensitive_sites=sensitive_sites,
                                          maigret_backfill_approved=backfill, override_sherlock=bool(ov and ov.get("override_sherlock")))
            lint = next((r for r in reasons if r.startswith("oracle:")), None)
            if lint and site.get("valid", True) and not site.get("disabled") and not site.get("engine"):
                log["lint_dropped"][sid] = lint  # FC6: dropped and logged (curated candidates; engine entries are out anyway)
            if sid in exclusions_ov:
                reasons.append("overlay exclusion: " + exclusions_ov[sid])
            if not ov:
                reasons.append("FC8: tier unknown (not in the overlay)")
            else:
                reasons += site_registry_problems(sid, ov, reg)
                if not tier_allows(ov.get("tier"), ov.get("tier_rationale")):
                    reasons.append(f"FC8: tier {ov.get('tier')} is never queried")
                src = reg.source(ov.get("source") or "") if ov.get("source") else None
                terms_class = src.terms.class_ if src is not None else "unknown"
                if pack == DEFAULT_PACK:
                    if terms_class != "open":
                        reasons.append(f"FC16: terms {terms_class!r} (the default pack holds only 'open' sites)")
                    if ov.get("verdict") != "correct":
                        reasons.append(f"FC2: calibration {ov.get('verdict') or 'missing'}")
                elif ov.get("verdict") == "false_positive":
                    reasons.append("FC2: calibration false_positive")
                if ov.get("disabled") or int(ov.get("wrong_votes") or 0) >= WRONG_LIMIT:
                    reasons.append("FC15: disabled by health")
                site_hosts = {url_host(site.get("check_url"))}
                if not site_hosts <= set(ov.get("hosts") or ()):
                    reasons.append(f"probe host {sorted(site_hosts)} not recorded in the overlay hosts")
            host = str(site.get("host") or "")
            if not reasons and host in seen_hosts[pack]:
                reasons.append("duplicate host (one definition per host)")
            if reasons:
                reasons_by_site.setdefault(sid, reasons)
                continue
            seen_hosts[pack].add(host)
            eligible[pack].append(site)
    default = sorted(eligible[DEFAULT_PACK], key=lambda s: _ordering_key(s, ov_sites.get(str(s.get("id"))) or {}))[:HARD_MAX_SITES]
    default_ids = [str(s["id"]) for s in default]
    default_hosts = {str(s.get("host") or "") for s in default}
    extended = [s for s in eligible[EXTENDED_PACK] if str(s["id"]) not in default_ids and str(s.get("host") or "") not in default_hosts]
    extended = sorted(extended, key=lambda s: _ordering_key(s, ov_sites.get(str(s.get("id"))) or {}))
    for sid, reasons in reasons_by_site.items():
        if sid in default_ids or sid in {str(s["id"]) for s in extended}:
            continue
        first = reasons[0].split(" (", 1)[0] if reasons else "other"
        log["not_selected"][first] = log["not_selected"].get(first, 0) + 1
    log["not_selected"] = dict(sorted(log["not_selected"].items()))
    log["lint_dropped"] = dict(sorted(log["lint_dropped"].items()))
    return {
        "schema": "v3lum.username_packs/1",
        "built_at": built_at,
        "datasets": datasets,
        "packs": {DEFAULT_PACK: {"site_ids": default_ids}, EXTENDED_PACK: {"site_ids": [str(s["id"]) for s in extended]}},
        "build_log": log,
    }


# ----------------------------------------------------------------------------------- bundled data


@functools.lru_cache(maxsize=1)
def _bundled() -> dict[str, Any]:
    """The bundled overlay, selection lists and collision lists (read once; fail closed to empty)."""
    out: dict[str, Any] = {"overlay": parse_overlay(None), "packs": {}, "datasets": {}, "collision": {}, "errors": []}
    try:
        out["overlay"] = parse_overlay(DataStore.bundled_json(OVERLAY_FILE))
    except (OSError, ValueError) as exc:
        out["errors"].append(f"{OVERLAY_FILE}: {exc}")
    if out["overlay"].get("error"):
        out["errors"].append(f"{OVERLAY_FILE}: {out['overlay']['error']}")
    try:
        packs = DataStore.bundled_json(PACKS_FILE)
    except (OSError, ValueError) as exc:
        packs = {}
        out["errors"].append(f"{PACKS_FILE}: {exc}")
    if isinstance(packs, Mapping) and isinstance(packs.get("packs"), Mapping):
        for name, spec in packs["packs"].items():
            ids = spec.get("site_ids") if isinstance(spec, Mapping) else None
            out["packs"][str(name)] = tuple(str(i) for i in _seq(ids) if isinstance(i, str))
        out["datasets"] = {str(k): str((v or {}).get("sha256") or "") for k, v in (packs.get("datasets") or {}).items() if isinstance(v, Mapping)}
    try:
        lists = DataStore.bundled_json(COLLISION_FILE)
    except (OSError, ValueError) as exc:
        lists = {}
        out["errors"].append(f"{COLLISION_FILE}: {exc}")
    if isinstance(lists, Mapping):
        out["collision"] = {k: frozenset(str(x).lower() for x in _seq(lists.get(k)) if isinstance(x, str))
                            for k in ("common_usernames", "first_names", "dictionary_words")}
    return out


def load_overlay() -> dict[str, Any]:
    """The parsed bundled overlay (FC4)."""
    return _bundled()["overlay"]


def pack_site_ids(pack_id: str) -> tuple[str, ...]:
    """Site ids of a bundled selection list (FC3)."""
    return tuple(_bundled()["packs"].get(pack_id, ()))


def pack_hosts(pack_id: str) -> tuple[str, ...]:
    """Every host the pack's sites contact (Module.hosts is generated from the selection list)."""
    sites = load_overlay().get("sites") or {}
    return tuple(sorted({h for sid in pack_site_ids(pack_id) for h in (sites.get(sid) or {}).get("hosts", ())}))


def pack_sources(pack_id: str) -> tuple[str, ...]:
    """The registry source of every site of the pack (each site is a provider receiving the handle, A8)."""
    sites = load_overlay().get("sites") or {}
    return tuple(sorted({str((sites.get(sid) or {}).get("source")) for sid in pack_site_ids(pack_id) if (sites.get(sid) or {}).get("source")}))


@dataclass(frozen=True)
class Pack:
    """A pack as the engine runs it: selection list + overlay + build-time dataset hashes."""

    pack_id: str
    site_ids: tuple[str, ...]
    overlay: Mapping[str, Any]
    datasets: Mapping[str, str] = field(default_factory=dict)
    default: bool = True
    collision: Mapping[str, frozenset[str]] = field(default_factory=dict)


# ------------------------------------------------------------------------------- runtime engine

#: Global concurrency of the username lane, shared by both packs and every run of the process (FC9).
_GLOBAL_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENCY)
_SKIP_STATUS = {
    "licence": (Status.SKIPPED, "licence"), "tier": (Status.SKIPPED, "tier"), "tlp": (Status.SKIPPED, "tlp"),
    "disabled": (Status.SKIPPED, "demoted"), "excluded": (Status.SKIPPED, "policy"), "syntax": (Status.SKIPPED, "not_applicable"),
    "dataset": (Status.UNAVAILABLE, "dataset"), "policy": (Status.SKIPPED, "policy"),
}
_UNKNOWN_STATUS = {
    "challenge": (Status.BLOCKED, "challenge"), "blocked": (Status.BLOCKED, "challenge"), "host_stopped": (Status.BLOCKED, "challenge"),
    "control_found": (Status.ERROR, "error"), "login_wall": (Status.BLOCKED, "login_wall"), "geo_block": (Status.BLOCKED, "geo_block"),
    "rate_limited": (Status.RATE_LIMITED, "rate_limited"), "quota": (Status.QUOTA, "quota"), "timeout": (Status.ERROR, "timeout"),
}


class _Budget:
    """Request budget and stop flag of one run (FC10): sites and controls share the cap."""

    def __init__(self, cap: int) -> None:
        self.cap = max(0, int(cap))
        self.used = 0
        self.stop_reason = ""
        self._lock = threading.Lock()

    def reserve(self) -> bool:
        with self._lock:
            if self.stop_reason or self.used >= self.cap:
                return False
            self.used += 1
            return True

    def release(self) -> None:
        with self._lock:
            self.used = max(0, self.used - 1)

    def stop(self, reason: str) -> None:
        with self._lock:
            if not self.stop_reason:
                self.stop_reason = reason


@dataclass
class _Job:
    index: int
    site: dict[str, Any]
    rec: Mapping[str, Any]
    probe: dict[str, Any]
    control: dict[str, Any]
    result: dict[str, Any] | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)


class _EngineState:
    """Health records of the engine in ctx.state (FC15), shared by both packs; refusals never break a run."""

    def __init__(self, entity: Any) -> None:
        try:
            self._state: ModuleState | None = ModuleState(ENGINE_STATE, entity=entity)
        except (StateError, ValueError):
            self._state = None

    def health(self) -> dict[str, Any]:
        if self._state is None:
            return {}
        try:
            value = self._state.get("health", {})
        except (StateError, ValueError, OSError):
            return {}
        return value if isinstance(value, dict) else {}

    def get(self, key: str, default: Any = None) -> Any:
        if self._state is None:
            return default
        try:
            return self._state.get(key, default)
        except (StateError, ValueError, OSError):
            return default

    def set(self, key: str, value: Any) -> bool:
        if self._state is None:
            return False
        try:
            self._state.set(key, value)
            return True
        except (StateError, ValueError, OSError):
            return False


def _iso(dt: Any) -> str:
    try:
        return dt.isoformat().replace("+00:00", "Z")
    except AttributeError:
        return str(dt)


class _PackRun:
    """One pack run for one username (FC9-FC14)."""

    def __init__(self, module: Module, pack: Pack, entity: Entity, ctx: Any, *, rng: random.Random | None = None) -> None:
        self.module = module
        self.cls = type(module)
        self.pack = pack
        self.entity = entity
        self.ctx = ctx
        self.handle = str(entity.value)
        self.rng = rng or random.SystemRandom()
        self.reg = _providers.registry()
        self.skipped: list[tuple[str, str, str]] = []  # (site id, category, reason)
        self.source_problems: dict[str, tuple[Status, str, str]] = {}
        self.state = _EngineState(entity)

    # ---- datasets -------------------------------------------------------------------------
    def _dataset(self, name: str, source_id: str, kind: str, *, ttl: float | None = None) -> Any:
        try:
            if kind == "json":
                return self.ctx.data.fetch_json(name, ttl=ttl)
            return self.ctx.data.fetch_text(name, ttl=ttl)
        except DatasetUnavailable as exc:
            self.source_problems[source_id] = (Status.UNAVAILABLE, "dataset", str(exc)[:200])
        except DatasetError as exc:
            self.source_problems[source_id] = (Status.ERROR, "error", f"dataset {name}: {str(exc)[:200]}")
        return None

    def _sherlock(self) -> tuple[dict[str, str], list[str]]:
        """FC5: (regex by host, excluded hosts) from the Sherlock datasets; ({}, []) when unavailable."""
        manifest_raw = self._dataset(SHERLOCK_DATA, SRC_SHERLOCK, "json")
        if manifest_raw is None:
            return {}, []
        manifest = parse_sherlock_manifest(manifest_raw)
        if not manifest["ok"]:
            self.source_problems[SRC_SHERLOCK] = (Status.ERROR, "error", f"Sherlock manifest unusable: {manifest['error']}")
            return {}, []
        regexes = sherlock_username_regexes(manifest)["by_host"]
        excl_raw = self._dataset(SHERLOCK_EXCLUSIONS, SRC_SHERLOCK_EXCLUSIONS, "text")
        hosts: list[str] = []
        if excl_raw is not None:
            excl = parse_sherlock_exclusions(excl_raw)
            if excl["ok"]:
                hosts = sherlock_excluded_hosts(excl["names"], manifest)["hosts"]
            else:
                self.source_problems[SRC_SHERLOCK_EXCLUSIONS] = (Status.ERROR, "error", f"exclusions list unusable: {excl['error']}")
        return regexes, hosts

    def _definitions(self) -> dict[str, dict[str, Any]]:
        """Site definitions of the pack's ids (V3LUM overlay, WhatsMyName, Maigret), loading a dataset
        only when the pack holds one of its ids; ids whose dataset is unavailable are skipped."""
        ids = self.pack.site_ids
        defs: dict[str, dict[str, Any]] = {sid: dict(site) for sid, site in (self.pack.overlay.get("definitions") or {}).items() if sid in ids}
        if any(sid.startswith("wmn:") for sid in ids):
            raw = self._dataset(WMN, SRC_WMN, "json")
            parsed = parse_wmn_dataset(raw) if raw is not None else {"ok": False, "sites": []}
            for site in parsed["sites"]:
                if site["id"] in ids:
                    defs[site["id"]] = site
        if any(sid.startswith("maigret:") for sid in ids):
            info = self.ctx.data.info(MAIGRET_DATA)
            if not info.present:
                self.source_problems[SRC_MAIGRET] = (Status.UNAVAILABLE, "dataset", f"dataset {MAIGRET_DATA} is not downloaded: run v3lum data update")
            else:
                raw = self._dataset(MAIGRET_DATA, SRC_MAIGRET, "json", ttl=10 * 365 * 86400.0)  # FC3: never refreshed mid-run
                parsed = parse_maigret_db(raw) if raw is not None else {"ok": False, "sites": []}
                for site in parsed["sites"]:
                    if site["id"] in ids:
                        defs[site["id"]] = site
        for sid in ids:
            if sid not in defs:
                self.skipped.append((sid, "dataset", "site definition unavailable (dataset not loaded or entry gone)"))
        return defs

    # ---- selection at runtime (defence in depth) -------------------------------------------
    def _site_skip(self, sid: str, site: Mapping[str, Any], rec: Mapping[str, Any] | None, *, sherlock_hosts: list[str], health: Mapping[str, Any]) -> tuple[str, str] | None:
        ctx = self.ctx
        if rec is None:
            return "tier", "FC8: tier unknown (not in the overlay)"
        if sid in (self.pack.overlay.get("exclusions") or {}):
            return "excluded", "overlay exclusion: " + str(self.pack.overlay["exclusions"][sid])
        reasons = pack_filter_reasons(
            site, pack=DEFAULT_PACK if self.pack.default else EXTENDED_PACK, sherlock_hosts=sherlock_hosts,
            nsfw_sites=bool(ctx.setting("nsfw_sites", False)), sensitive_sites=bool(ctx.setting("sensitive_sites", False)),
            maigret_backfill_approved=bool(self.pack.overlay.get("maigret_backfill_approved")), override_sherlock=bool(rec.get("override_sherlock")),
        )
        if reasons:
            return "excluded", reasons[0]
        src = self.reg.source(rec.get("source") or "") if rec.get("source") else None
        prov = self.reg.get(src.provider) if src is not None else None
        if src is None or prov is None:
            return "policy", f"source {rec.get('source')!r} is not registered"
        host = url_host(site.get("check_url"))
        if host not in set(rec.get("hosts") or ()) or host not in set(getattr(self.cls, "hosts", ()) or ()):
            return "policy", f"probe host {host!r} is not declared for this pack"
        tier = effective_tier(str(rec.get("tier")), prov.tier)
        if tier not in TIERS_QUERYABLE or not rec.get("tier_rationale"):
            return "tier", f"FC8: tier {tier} never receives a username"
        if not tier_allows(tier, rec.get("tier_rationale"), ctx.tlp):
            return "tlp", f"TLP:{ctx.tlp.upper()}: a {tier}-tier site does not receive the username (FC8)"
        terms = src.terms.class_
        if terms == "unknown":
            return "licence", "terms not reviewed (A1 'unknown': never runs in any profile)"
        if self.pack.default and terms != "open":
            return "licence", f"terms {terms!r}: the default pack holds only 'open' sites (FC16)"
        if src.id not in ctx.allowed_sources:
            return "licence", f"terms {terms!r} not allowed under the licence profile (A1)"
        if rec.get("disabled") or int(rec.get("wrong_votes") or 0) >= WRONG_LIMIT:
            return "disabled", "disabled in the overlay (FC15)"
        if (health.get(sid) or {}).get("disabled"):
            return "disabled", f"disabled by health: {(health.get(sid) or {}).get('reason') or 'self-test failed'} (FC15)"
        return None

    def plan(self) -> list[_Job]:
        """The jobs of this run in pack order, after every runtime filter (skips are recorded)."""
        regexes, sherlock_hosts = self._sherlock()
        defs = self._definitions()
        health = self.state.health()
        ov_sites = self.pack.overlay.get("sites") or {}
        limit = len(self.pack.site_ids)
        if self.pack.default:
            try:
                configured = int(self.ctx.setting(SITES_SETTING, DEFAULT_SITES))
            except (TypeError, ValueError):
                configured = DEFAULT_SITES
            limit = max(0, min(configured, HARD_MAX_SITES))
        jobs: list[_Job] = []
        for sid in self.pack.site_ids:
            site = defs.get(sid)
            if site is None:
                continue
            if len(jobs) >= limit:
                self.skipped.append((sid, "excluded", f"over the pack size ({SITES_SETTING}={limit})"))
                continue
            rec = ov_sites.get(sid)
            skip = self._site_skip(sid, site, rec, sherlock_hosts=sherlock_hosts, health=health)
            if skip is not None:
                self.skipped.append((sid, skip[0], skip[1]))
                continue
            regex = regexes.get(str(site.get("host") or ""))
            probe = render_probe(site, self.handle, extra_regex=regex)
            if not probe.get("ok"):
                self.skipped.append((sid, "syntax", f"handle not applicable: {probe.get('reason')}"))
                continue
            control = control_probe(site, self.rng, extra_regex=regex)
            jobs.append(_Job(len(jobs), site, rec or {}, probe, control))
        return jobs

    # ---- requests ----------------------------------------------------------------------------
    def _remaining(self) -> float | None:
        try:
            return self.ctx.remaining()
        except Exception:  # noqa: BLE001 - a context without a deadline
            return None

    def _cache_veto(self, site: Mapping[str, Any]) -> Any:
        handle = self.handle

        def cacheable(resp: Any) -> bool:
            # FC11/P326: only answers that read FOUND or ABSENT are cached, never 'could not verify'
            ev = evaluate_response(site, int(getattr(resp, "status", 0) or 0), getattr(resp, "headers", {}), getattr(resp, "content", b""),
                                   username=handle, classification=getattr(resp, "classification", None), truncated=bool(getattr(resp, "truncated", False)))
            return ev["state"] != UNKNOWN

        return cacheable

    def _send(self, job: _Job, url: str, headers: Mapping[str, str], budget: _Budget, *, control: bool) -> dict[str, Any] | None:
        """One GET (no retry, redirects not followed). None when the run stopped before sending."""
        ctx = self.ctx
        if ctx.cancelled():
            budget.stop("cancelled")
            return None
        remaining = self._remaining()
        if remaining is not None and remaining <= GRACE:
            budget.stop("deadline")
            return None
        if not budget.reserve():
            if not budget.stop_reason:
                budget.stop("request_cap")
            return None
        wait = 60.0 if remaining is None else max(0.1, remaining - GRACE)
        if not _GLOBAL_SLOTS.acquire(timeout=wait):
            budget.release()
            budget.stop("deadline")
            return None
        source = str(job.rec.get("source") or "")
        resp = None
        error: Any = None
        reason: str | None = None
        try:
            timeout = SITE_TIMEOUT if remaining is None else max(1.0, min(SITE_TIMEOUT, remaining - GRACE / 2))
            kwargs: dict[str, Any] = {"source": source, "allow_redirects": False, "timeout": timeout, "retries": 0, "max_bytes": MAX_BODY_BYTES}
            if headers:
                kwargs["headers"] = dict(headers)
            if control:
                kwargs["ttl"] = 0  # a random handle is never worth a cache row
            else:
                kwargs["cache_if"] = self._cache_veto(job.site)
            resp = ctx.http.get(url, **kwargs)
        except Cancelled:
            budget.stop("cancelled")
            budget.release()
            return None
        except DeadlineExceeded:
            budget.stop("deadline")
            budget.release()
            return None
        except RequestCapReached:
            budget.stop("request_cap")
            budget.release()
            return None
        except Blocked as exc:
            budget.release()  # short-circuited host: no request was sent
            reason, error = "challenge", exc
        except RateLimited as exc:
            budget.release()  # the provider's own rate-limit window: refused before sending
            reason, error = "rate_limited", exc
        except QuotaExceeded as exc:
            budget.release()
            reason, error = "quota", exc
        except (PolicyError, ConfigError) as exc:
            budget.release()
            reason, error = "policy", exc
        except HttpError as exc:
            reason, error = "error", exc
        except NetworkError as exc:
            kind = str(getattr(exc, "kind", "") or "")
            reason, error = ("timeout" if "timeout" in kind.lower() or "timed out" in str(exc).lower() or "timeout" in str(exc).lower() else "network"), exc
        except Exception as exc:  # noqa: BLE001 - a broken answer must never crash the pack: could not verify
            reason, error = "error", exc
        finally:
            _GLOBAL_SLOTS.release()
        checked_at = _iso(ctx.now())
        if resp is None:
            result = _result(UNKNOWN, reason or "error", stop_host=reason in STOP_HOST_REASONS, detail=f"{type(error).__name__}: {str(error)[:120]}")
            job.evidence.append({**evidence_record(str(job.site.get("id")), result, url, checked_at), "control": control})
            return result
        if getattr(resp, "from_cache", False):
            budget.release()  # cache hits are free (the scoped client counts only network sends)
        body = bytes(getattr(resp, "content", b"") or b"")
        handle = str(job.control.get("handle") or "") if control else self.handle  # the control is judged like the claimed handle
        result = evaluate_response(job.site, int(resp.status), resp.headers, body, username=handle,
                                   classification=getattr(resp, "classification", None), truncated=bool(getattr(resp, "truncated", False)))
        if result["state"] == FOUND and not control:
            result["display_name"] = extract_display_name(body, self.handle)
        result["from_cache"] = bool(getattr(resp, "from_cache", False))
        job.evidence.append({**evidence_record(str(job.site.get("id")), result, url, checked_at, body), "control": control, "from_cache": result["from_cache"]})
        return result

    def _host_worker(self, jobs: list[_Job], budget: _Budget) -> None:
        """One host's sites in pack order: one request in flight per host (FC9), stop after a block (FC10)."""
        stopped = False
        for job in jobs:
            try:
                if stopped:
                    job.result = _result(UNKNOWN, "host_stopped")
                    continue
                result = self._send(job, job.probe["url"], job.probe.get("headers") or {}, budget, control=False)
                if result is None:
                    job.result = {"state": "not_checked", "reason": budget.stop_reason or "deadline"}
                    continue
                control_stop = False
                if result["state"] == FOUND:
                    control = None
                    if job.control.get("ok"):
                        control = self._send(job, job.control["url"], job.control.get("headers") or {}, budget, control=True)
                    result = apply_control(result, control)
                    control_stop = bool((control or {}).get("stop_host"))
                    if control is None and result.get("control") == "unverified":
                        result["control_reason"] = budget.stop_reason or job.control.get("reason") or "not sent"
                job.result = result
                stopped = bool(result.get("stop_host")) or control_stop
            except Exception as exc:  # noqa: BLE001 - never crash the engine on one site
                job.result = _result(UNKNOWN, "error", detail=f"{type(exc).__name__}: {str(exc)[:120]}")

    def schedule(self, jobs: list[_Job], budget: _Budget) -> None:
        """Run the jobs: hosts in parallel (<= 8 workers, global slots shared by every pack run), each
        host's sites one after the other; the HttpClient keeps >= 1 s between requests to a host."""
        by_host: dict[str, list[_Job]] = {}
        for job in jobs:
            by_host.setdefault(url_host(job.probe["url"]), []).append(job)
        if not by_host:
            return
        workers = max(1, min(MAX_CONCURRENCY, len(by_host)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="v3lum-username") as pool:
            futures = [pool.submit(self._host_worker, host_jobs, budget) for host_jobs in by_host.values()]
            for future in futures:
                try:
                    future.result()
                except Exception:  # noqa: BLE001 - the worker records per-site errors itself
                    pass

    # ---- the run ------------------------------------------------------------------------------
    def execute(self) -> ModuleResult:
        ctx = self.ctx
        res: ModuleResult = self.module.result(self.entity)
        gate = pack_run_gate(is_seed=bool(ctx.is_seed), provenance=ctx.provenance, entity_key=self.entity.key,
                             unconfirmed=getattr(ctx.options, "unconfirmed_seeds", ()) or ())
        if gate:
            return res.mark(Status.SKIPPED, gate, reason_code="privacy")
        if str(ctx.tlp).lower() == "red":
            return res.mark(Status.SKIPPED, "TLP:RED: no third-party site may receive the username", reason_code="tlp")
        if not self.pack.site_ids:
            return res.mark(Status.SKIPPED, f"{self.cls.name}: the selection list holds no site yet (see docs/backlog/p1-G05-2.md)", reason_code="not_applicable")
        jobs = self.plan()
        budget = _Budget(int(getattr(self.cls, "max_requests", DEFAULT_CAP) or 0))
        if jobs:
            if ctx.cancelled():
                raise Cancelled()
            self.schedule(jobs, budget)
        return self._assemble(res, jobs, budget)

    def _assemble(self, res: ModuleResult, jobs: list[_Job], budget: _Budget) -> ModuleResult:
        ctx = self.ctx
        label = str(self.cls.name)
        collision = high_collision_reason(self.handle, common=self.pack.collision.get("common_usernames", ()),
                                          first_names=self.pack.collision.get("first_names", ()), dictionary=self.pack.collision.get("dictionary_words", ()))
        rows: list[dict[str, Any]] = []
        not_checked: dict[str, int] = {}
        for job in jobs:
            r = dict(job.result or {"state": "not_checked", "reason": budget.stop_reason or "deadline"})
            r.update(site=str(job.site.get("id")), name=str(job.rec.get("name") or job.site.get("name") or job.site.get("id")),
                     url=job.probe["url"], profile_url=job.probe.get("profile_url") or job.probe["url"], source=str(job.rec.get("source") or ""))
            if r["state"] == "not_checked":
                not_checked[r["reason"]] = not_checked.get(r["reason"], 0) + 1
            rows.append(r)
        checked = [r for r in rows if r["state"] in STATES]
        counts = summarize_states(checked)
        n_not_checked = sum(not_checked.values())
        line = counts_line(label, checked, n_not_checked)
        res.attr("site_checks", line)
        coverage = [part for part in (unknown_breakdown(checked),) if part]
        skipped_by: dict[str, int] = {}
        for _sid, category, _why in self.skipped:
            skipped_by[category] = skipped_by.get(category, 0) + 1
        if skipped_by:
            coverage.append("skipped: " + ", ".join(f"{n} {k}" for k, n in sorted(skipped_by.items())))
        if not_checked:
            coverage.append("not checked: " + ", ".join(f"{n} {k}" for k, n in sorted(not_checked.items())))
        res.attr("site_checks_coverage", "; ".join(coverage))
        if collision:
            res.attr("collision_reason", collision)
        conf = hit_confidence((), collision)
        found = [r for r in checked if r["state"] == FOUND]
        res.attr("profiles", [{"platform": r["name"], "url": r["profile_url"], "display_name": r.get("display_name") or "", "site_id": r["site"]} for r in found])
        tags = ["weak_signal"] + (["high_collision"] if collision else [])
        for r in found:
            control = r.get("control") or "unverified"
            desc = f"{r['profile_url']}" + (f" · {r['display_name']}" if r.get("display_name") else "") + f" · {SAME_HANDLE_NOTE}"
            if control != "absent":
                desc += " (random control handle not verified)"
            if collision:
                desc += f" · high-collision handle: {collision}"
            res.finding(
                f"Same handle found on {r['name']}",
                "info",
                desc,
                confidence=conf["confidence"],
                criterion=f"{SAME_HANDLE_NOTE}: presence marker {r.get('marker')} without the absence marker; random control handle {control} (P113 FC11/FC13)",
                data={"site": r["site"], "url": r["profile_url"], "display_name": r.get("display_name") or "", "marker": r.get("marker"), "control": control},
                tags=tags,
                source=r["source"],
                key=r["site"],
            )
            res.pivot(T.URL, r["profile_url"], "has_account", confidence=conf["confidence"], expand=False, note=SAME_HANDLE_NOTE)
        links = 0
        for r in checked:
            if r["state"] == UNKNOWN and r.get("reason") in ("challenge", "blocked", "login_wall", "geo_block", "rate_limited", "host_stopped") and links < MAX_MANUAL_LINKS:
                res.link(f"{r['name']}: could not verify ({UNKNOWN_LABELS.get(r['reason'], ('?', '?'))[0]}), check manually", r["profile_url"])
                links += 1
        self._source_statuses(res, rows)
        self._record_strikes(rows)
        res.raw = {
            "pack": self.pack.pack_id,
            "handle_collision": collision,
            "counts": {**counts, "not_checked": n_not_checked},
            "counts_line": line,
            "coverage": res.attributes.get("site_checks_coverage", ""),
            "datasets_at_build": dict(self.pack.datasets),
            "requests_budget": {"cap": budget.cap, "used": budget.used, "stop_reason": budget.stop_reason},
            "sites": [ev for job in jobs for ev in job.evidence],
            "not_checked": [{"site": r["site"], "reason": r["reason"]} for r in rows if r["state"] == "not_checked"],
            "skipped": [{"site": sid, "category": cat, "reason": why} for sid, cat, why in self.skipped],
            "dataset_problems": {k: v[2] for k, v in self.source_problems.items()},
        }
        try:
            ctx.log(line)
        except Exception:  # noqa: BLE001 - the live feed is best effort
            pass
        if budget.stop_reason in ("request_cap", "deadline", "cancelled") and n_not_checked:
            res.stop(budget.stop_reason)
        return self._status(res, counts, checked, n_not_checked)

    def _status(self, res: ModuleResult, counts: Mapping[str, int], checked: list[dict[str, Any]], n_not_checked: int) -> ModuleResult:
        if counts[FOUND]:
            return res
        if counts[ABSENT]:
            return res.mark(Status.EMPTY)
        if counts[UNKNOWN]:
            reasons: dict[str, int] = {}
            for r in checked:
                reasons[str(r.get("reason"))] = reasons.get(str(r.get("reason")), 0) + 1
            top = max(sorted(reasons), key=lambda k: reasons[k])
            status, code = _UNKNOWN_STATUS.get(top, (Status.ERROR, "error"))
            return res.mark(status, f"could not verify on {counts[UNKNOWN]} site(s): {unknown_breakdown(checked)}", reason_code=code)
        if n_not_checked:
            return res.mark(Status.SKIPPED, "no site was checked before the deadline or the request cap", reason_code="deadline")
        if self.skipped:
            cats: dict[str, int] = {}
            for _sid, category, _why in self.skipped:
                cats[category] = cats.get(category, 0) + 1
            top = max(sorted(cats), key=lambda k: cats[k])
            status, code = _SKIP_STATUS.get(top, (Status.SKIPPED, "policy"))
            sample = next(why for _sid, category, why in self.skipped if category == top)
            return res.mark(status, f"no site checked: {len(self.skipped)} skipped ({sample})", reason_code=code)
        return res.mark(Status.SKIPPED, "no site to check", reason_code="not_applicable")

    def _source_statuses(self, res: ModuleResult, rows: list[dict[str, Any]]) -> None:
        declared = set(getattr(self.cls, "sources", ()) or ())
        for sid, (status, code, why) in self.source_problems.items():
            if sid in declared:
                res.source_status(sid, status, reason_code=code, reason=why)
        ov_sites = self.pack.overlay.get("sites") or {}
        for site_id, category, why in self.skipped:
            source = str((ov_sites.get(site_id) or {}).get("source") or "")
            if source in declared and source not in res.source_statuses and category in ("licence", "tier", "tlp", "disabled", "policy"):
                status, code = _SKIP_STATUS[category]
                res.source_status(source, status, reason_code=code, reason=why)
        for r in rows:
            if r["state"] == UNKNOWN and r.get("source") in declared and r["source"] not in res.source_statuses:
                status, code = _UNKNOWN_STATUS.get(str(r.get("reason")), (Status.ERROR, "error"))
                res.source_status(r["source"], status, reason_code=code, reason=f"could not verify: {UNKNOWN_LABELS.get(str(r.get('reason')), ('error', 'errors'))[0]}")

    def _record_strikes(self, rows: list[dict[str, Any]]) -> None:
        """FC15: a FOUND site whose random control handle was FOUND too is marked wrong once."""
        strikes = [r["site"] for r in rows if r.get("health_strike")]
        if not strikes:
            return
        health = self.state.health()
        now = _iso(self.ctx.now())
        for sid in strikes:
            health[sid] = {**health_update(health.get(sid), "", strikes=1), "last_strike_at": now}
        # a refusal (the record would carry the investigated handle) loses the strike, never the run
        self.state.set("health", health)


# ------------------------------------------------------------------------------- self-test (FC15)


def _probe_once(ctx: Any, site: Mapping[str, Any], rec: Mapping[str, Any], handle: str) -> dict[str, Any]:
    probe = render_probe(site, handle)
    if not probe.get("ok"):
        return _result(UNKNOWN, "syntax")
    try:
        resp = ctx.http.get(probe["url"], source=str(rec.get("source") or ""), allow_redirects=False, timeout=SITE_TIMEOUT, retries=0, max_bytes=MAX_BODY_BYTES, ttl=0)
    except (Cancelled, DeadlineExceeded, RequestCapReached):
        raise
    except Exception as exc:  # noqa: BLE001 - a self-test answer that fails is 'could not verify'
        return _result(UNKNOWN, "network", detail=f"{type(exc).__name__}: {str(exc)[:80]}")
    return evaluate_response(site, int(resp.status), resp.headers, resp.content, username=handle, classification=getattr(resp, "classification", None))


def run_selftest(module_cls: Any, ctx: Any, *, rng: random.Random | None = None) -> HealthResult:
    """FC15 self-test (HealthCheck(offline=False)): at most once a day, re-test <= 25 sites of the
    pack in rotation with their official claimed account and a random control; failing sites are
    disabled in the shared health record until they pass again."""
    pack = module_cls.load_pack()
    state = _EngineState(None)
    today = ctx.now().date().isoformat()
    runs = state.get("selftest", {}) or {}
    previous = runs.get(module_cls.name) if isinstance(runs, dict) else None
    if isinstance(previous, dict) and previous.get("date") == today and previous.get("status") in ("ok", "blocked", "dead"):
        return HealthResult(previous["status"], str(previous.get("detail") or "") + " (cached: at most one self-test a day)")
    ov_sites = pack.overlay.get("sites") or {}
    defs = pack.overlay.get("definitions") or {}
    reg = _providers.registry()

    def reviewed(sid: str) -> bool:
        # A1: sources whose terms are still 'unknown' stay disabled, doctor health checks included
        src = reg.source(str((ov_sites.get(sid) or {}).get("source") or ""))
        return src is not None and src.terms.class_ != "unknown"

    candidates = [sid for sid in pack.site_ids if (ov_sites.get(sid) or {}).get("claimed") and sid in defs and reviewed(sid)]
    if not candidates:
        return HealthResult("ok", f"{module_cls.name}: no site to self-test (none with reviewed terms and a claimed account)")
    sample = doctor_rotation(candidates, ctx.now().date().toordinal(), SELFTEST_PER_DAY)
    rng = rng or random.SystemRandom()
    health = state.health()
    verdicts: dict[str, str] = {}
    for sid in sample:
        site, rec = defs[sid], ov_sites[sid]
        claimed = _probe_once(ctx, site, rec, str(rec["claimed"]))
        control = None
        if claimed["state"] == FOUND:
            ctl = control_probe(site, rng)
            control = _probe_once(ctx, site, rec, ctl["handle"]) if ctl.get("ok") else None
        verdict = calibration_verdict(claimed, control) if control is not None else ("stale_fixture" if claimed["state"] == ABSENT else "unknown")
        verdicts[sid] = verdict
        health[sid] = health_update(health.get(sid), verdict, checked_at=_iso(ctx.now()))
    state.set("health", health)
    correct = sorted(s for s, v in verdicts.items() if v == "correct")
    failed = sorted(s for s, v in verdicts.items() if v in ("false_positive", "stale_fixture"))
    unknown = sorted(s for s, v in verdicts.items() if v == "unknown")
    detail = f"{len(correct)}/{len(sample)} sites correct" + (f"; disabled: {', '.join(failed)}" if failed else "") + (f"; could not verify: {', '.join(unknown)}" if unknown else "")
    status = "ok" if correct or not sample else ("blocked" if unknown and not failed else "dead")
    runs = runs if isinstance(runs, dict) else {}
    runs[module_cls.name] = {"date": today, "status": status, "detail": detail}
    state.set("selftest", runs)
    return HealthResult(status, detail)


# ------------------------------------------------------------------------------- the modules


class UsernamePackBase(Module):
    """The checker engine shared by the username packs (no ``name``: never registered itself)."""

    #: selection list id in v3lum/data/username_check/packs.json
    pack_id: ClassVar[str] = ""
    #: default-pack rules (two-sided markers, 'open' terms only, the username_default_sites limit)
    default_pack: ClassVar[bool] = True

    @classmethod
    def load_pack(cls) -> Pack:
        bundle = _bundled()
        return Pack(pack_id=cls.pack_id, site_ids=pack_site_ids(cls.pack_id), overlay=bundle["overlay"],
                    datasets=dict(bundle["datasets"]), default=cls.default_pack, collision=dict(bundle["collision"]))

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        return _PackRun(self, self.load_pack(), entity, ctx).execute()

    @classmethod
    def health_check(cls) -> HealthCheck | None:
        # FC15: the pack self-tests its sites (claimed + control) instead of probing one benign handle
        return HealthCheck(offline=False, selftest=functools.partial(run_selftest, cls))


#: dataset sources the default pack reads (WhatsMyName only when its selection holds wmn ids)
DEFAULT_DATASET_SOURCES = (SRC_SHERLOCK, SRC_SHERLOCK_EXCLUSIONS, SRC_WMN)


@register
class UsernameCheck(UsernamePackBase):
    # ---- identity -----------------------------------------------------------------------------
    name = "username_check"
    title = "Username check (default pack)"
    description = (
        "Tri-state check of a typed handle on a small calibrated site pack (V3LUM-measured two-sided markers, "
        "WhatsMyName entries by id): FOUND rows, a counts line and has_account pivots; a same handle is a weak signal."
    )
    category = "username_social"
    accepts = {T.USERNAME}
    produces = {T.URL, T.USERNAME}
    tags = {"pack", "curated_pack", "free"}
    reference = "https://github.com/WebBreacher/WhatsMyName"
    notice = (
        "Weak signal: the same handle on another site does not prove identity (POSSIBLE). Runs only on analyst-typed "
        "seeds; each site receives the handle (one GET, no login, no retries). WhatsMyName data (CC BY-SA 4.0) is "
        "downloaded at runtime, unmodified and attributed; sites without reviewed 'open' terms never run here."
    )
    run_on = "seeds"
    # ---- MUST be declared ------------------------------------------------------------------
    terms = "open"  # FC16: the default selection holds only sites recorded 'open'
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # every site of the pack receives the handle (A8)
    hosts = pack_hosts(DEFAULT_PACK)  # generated from the selection list (FC3)
    max_requests = DEFAULT_CAP  # FC10: sites + controls per username
    expected_latency = 8.0  # A3 default gate (<= 10 s); FC10 target p50 <= 30 s
    # ---- registry and behaviour -------------------------------------------------------------
    provider = "github"  # the datasets' host; each site is its own provider (sources below)
    sources = DEFAULT_DATASET_SOURCES + pack_sources(DEFAULT_PACK)
    access_model = "free_noauth_limited"
    timeout = DEFAULT_DEADLINE + GRACE  # FC10: Module.timeout >= pack deadline
    min_interval = MIN_INTERVAL
    cache_ttl = 86400  # FOUND/ABSENT answers only (cache_if veto), within the profile ttl and retention
    max_pivots = 200
    default_enabled = True
    settings = {SITES_SETTING: SettingSpec(DEFAULT_SITES, "sites the default username pack checks per handle (P113 FC1: default 100, hard max 150)")}
    # ---- engine --------------------------------------------------------------------------------
    pack_id = DEFAULT_PACK
    default_pack = True

