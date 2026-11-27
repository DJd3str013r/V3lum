"""P127 ``brasilapi_ddd``: BrasilAPI city lists per Brazilian DDD, prefetched offline data for phone_parse (P126).

There is no scan-time module (FC1: "folded into phone_parse as offline data: no per-scan network call").
This file registers the data, refreshes it out of band and answers offline lookups:

* **FC1 - prefetched dataset.** One registered dataset per allocated DDD, ``brasilapi_ddd.<DDD>`` (67 parts),
  each the unmodified answer of ``GET https://brasilapi.com.br/api/ddd/v1/<DDD>`` (30-day TTL, conditional
  GET with the stored ETag, validated before it replaces the previous copy). Every request carries only the
  2-digit DDD, never a phone number (:func:`ddd_url_problem` guards every registered URL). The parts are
  ``large=True``: the dataset manager never downloads them during a scan, so the DDD of an investigated
  number never reaches BrasilAPI on demand. ``v3lum data update`` fetches them with the provider's HTTP
  profile (``brasilapi``: min_interval 1.0 s, concurrency 1 -> at most 1 request/s);
  :func:`refresh_parts` (``python -m v3lum.modules.phone.brasilapi_ddd``) runs the 67 updates in fixed
  sorted order and stops at a challenge (A9), at a rate limit (the core backs the provider off for the run)
  or after 3 consecutive failures.
  Contract gap: ``register_dataset`` takes one URL, so the single dataset name ``brasilapi_ddd`` that the
  final conditions and phone_parse's hint use is a family of 67 parts until the core offers a multi-URL
  (builder) dataset; see ``docs/backlog/p3-G06-1.md``.
* **FC2 - offline scan-time answers (disclosure none).** :func:`installed_part` / :func:`installed_records`
  read only parts that are already downloaded (presence checked first, never refreshed from the read path);
  :func:`lookup_ddd` answers UF, UF list and main city from phone_parse's bundled Anatel table and the city
  list from the dataset, and says :data:`CITY_LIST_UNAVAILABLE` (phone_parse's verbatim FC2 text) when the
  part is missing.
* **FC3 - report shapes.** :func:`ddd_report`: 'UF + main city + N cities in DDD' for terminal/Markdown, the
  full list only as an HTML toggle and in JSON. Attribution: BrasilAPI (MIT code) over Anatel data
  (:data:`ATTRIBUTION`; notice fragment ``v3lum/data/notices/brasilapi_ddd.json``). Registry provider
  ``brasilapi`` (tier community, source ``brasilapi.ddd`` terms open) is the existing seed fragment.

City names are public municipality names (no personal data). The answers are untrusted: names are cleaned
(:func:`clean_city_names`) and every render escapes them (AR13).
"""

from __future__ import annotations

import html as _html
import json
import os
import re
import sys
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from v3lum.core.datasets import DATASETS, DatasetError, register_dataset

# ----------------------------------------------------------------------------------------------------------
# constants
# ----------------------------------------------------------------------------------------------------------

PROVIDER = "brasilapi"  # registry provider (seed fragment, tier community)
SOURCE = "brasilapi.ddd"  # registry source (terms open, upstream family 'anatel')
HOST = "brasilapi.com.br"
DDD_URL_TEMPLATE = "https://brasilapi.com.br/api/ddd/v1/{ddd}"  # no trailing slash: '/api/ddd/v1/' answers 308
DATASET = "brasilapi_ddd"  # the logical dataset name of the final conditions (FC1)
PART_PREFIX = DATASET + "."  # one registered part per DDD: brasilapi_ddd.11 ... brasilapi_ddd.99
DATASET_TTL = 30 * 86400  # FC1: 30 days
NEVER_REFRESH_TTL = 10 * 365 * 86400  # read path: serve the local copy whatever its age, never download
REQUEST_INTERVAL = 1.0  # FC1: <= 1 request/s (provider http_profile min_interval 1.0 s, concurrency 1)
MAX_CONSECUTIVE_FAILURES = 3  # refresh job: stop after this many failed parts in a row
DDD_TABLE = "phone_parse/br_ddd.json"  # phone_parse's bundled Anatel DDD -> UF(s)/main city table (P126 FC3)
#: phone_parse's verbatim FC2 coverage text (v3lum.modules.phone.phone_parse.CITY_LIST_UNAVAILABLE).
CITY_LIST_UNAVAILABLE = "city list unavailable (run v3lum data update brasilapi_ddd)"
LICENCE = "MIT (BrasilAPI code); Anatel numbering-plan data (Brazilian open government data)"
ATTRIBUTION = (
    "City lists per DDD: BrasilAPI (https://brasilapi.com.br, MIT-licensed code, https://github.com/BrasilAPI/BrasilAPI) "
    "over Anatel numbering-plan data (Fonte: Anatel)."
)
DESCRIPTION = "BrasilAPI DDD {ddd}: state and municipalities served by the area code (P127; offline city list for phone_parse)"

UF_CODES: frozenset[str] = frozenset((
    "AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ",
    "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO",
))
#: The 67 allocated DDDs (the same set as phone_parse.BR_DDD_CODES and /api/ddd/v1's state index).
BR_DDD_CODES: frozenset[str] = frozenset(
    [str(d) for d in range(11, 20)] + ["21", "22", "24", "27", "28"] + ["31", "32", "33", "34", "35", "37", "38"]
    + [str(d) for d in range(41, 50)] + ["51", "53", "54", "55"] + [str(d) for d in range(61, 70)]
    + ["71", "73", "74", "75", "77", "79"] + [str(d) for d in range(81, 90)] + [str(d) for d in range(91, 100)]
)

MAX_CITIES_PER_DDD = 1000  # observed maximum 223 (DDD 83, all of Paraíba)
MAX_CITY_NAME_LEN = 80
MAX_BODY_BYTES = 256 * 1024  # one answer is a few KB (DDD 83: 3,253 bytes)
MIN_BODY_BYTES = 20  # '{"state":"XX","cities":["A"]}' is 29 bytes
#: Sanity bounds of a complete set (about 5,570 municipalities, each in one DDD; the first full update on
#: 2026-11-26 installed 67/67 DDDs with 5,565 names, 13-223 per DDD); informational only.
MIN_TOTAL_CITIES = 5000
MAX_TOTAL_CITIES = 6000

# Letters first, then letters/space/apostrophe/period/hyphen ("OLHO D'ÁGUA", "EMBU-GUAÇU"); digits, markup and
# control characters are refused (untrusted data).
_CITY_NAME_RE = re.compile(r"^[^\W\d_](?:[^\W\d_]|[ '’.\-])*$")
_PART_RE = re.compile(r"^brasilapi_ddd\.([1-9][0-9])$")
_BR_E164_RE = re.compile(r"^\+55([1-9][1-9])([2-9]\d{7}|9\d{8})$")
_PARTICLES = frozenset(("de", "da", "do", "das", "dos", "e", "d"))

# ----------------------------------------------------------------------------------------------------------
# small helpers
# ----------------------------------------------------------------------------------------------------------


def as_text(raw: Any) -> str:
    """bytes/str/None -> str (UTF-8 with BOM stripped, else ISO-8859-1). Never raises."""
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw[1:] if raw.startswith("﻿") else raw
    if isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
        try:
            return data.decode("utf-8-sig")
        except UnicodeDecodeError:
            return data.decode("iso-8859-1")
    return str(raw)


def looks_like_html(text: Any) -> bool:
    """True for an HTML page (block page, platform error page) instead of data."""
    head = as_text(text)[:2048].lstrip().lower()
    return head.startswith(("<!doctype html", "<html")) or "<head" in head or "<body" in head


def _html_title(text: str) -> str | None:
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", text[:65536])
    return re.sub(r"\s+", " ", _html.unescape(m.group(1))).strip()[:120] if m else None


def fold(value: Any) -> str:
    """Accent-fold + casefold + collapse spaces + unify apostrophes ('SÃO PAULO' == 'Sao Paulo')."""
    s = unicodedata.normalize("NFKD", as_text(value)).replace("’", "'").replace("´", "'")
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return re.sub(r"\s+", " ", s).strip().casefold()


def _str(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


# ----------------------------------------------------------------------------------------------------------
# FC1 - the parts, the fetch plan and the 'only the 2-digit DDD' guard
# ----------------------------------------------------------------------------------------------------------


def part_name(ddd: Any) -> str:
    """'11' -> 'brasilapi_ddd.11' (ValueError for anything but an allocated DDD)."""
    code = as_text(ddd).strip()
    if code not in BR_DDD_CODES:
        raise ValueError(f"DDD {code!r} is not an allocated Brazilian area code")
    return PART_PREFIX + code


def ddd_of_part(name: Any) -> str | None:
    """'brasilapi_ddd.11' -> '11' (None for any other name)."""
    m = _PART_RE.match(as_text(name))
    return m.group(1) if m and m.group(1) in BR_DDD_CODES else None


def ddd_fetch_plan() -> list[dict[str, str]]:
    """FC1: one GET per allocated DDD, all 67 in a fixed sorted order (never a subset chosen from case data, so
    an update reveals nothing about any investigated number): [{'ddd', 'name', 'url'}, ...]."""
    return [{"ddd": code, "name": PART_PREFIX + code, "url": DDD_URL_TEMPLATE.format(ddd=code)} for code in sorted(BR_DDD_CODES)]


def ddd_url_problem(url: Any) -> str | None:
    """FC1 guard: None only for exactly https://brasilapi.com.br/api/ddd/v1/<allocated DDD> (no query, fragment,
    userinfo, port or trailing slash); otherwise why the URL could carry more than the DDD or leave the host."""
    if not isinstance(url, str):
        return "URL is not a string"
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return "unparseable URL"
    if parts.scheme != "https":
        return "not https"
    if parts.hostname != HOST or parts.username or parts.password or port not in (None, 443):
        return f"not the declared host {HOST}"
    if parts.query or parts.fragment or "?" in url or "#" in url:
        return "query or fragment present (only the 2-digit DDD may be sent)"
    m = re.fullmatch(r"/api/ddd/v1/([0-9]+)", parts.path)
    if not m:
        return "path is not /api/ddd/v1/<DDD>"
    if len(m.group(1)) != 2:
        return f"path value has {len(m.group(1))} digits: only a 2-digit DDD may be sent, never a phone number"
    if m.group(1) not in BR_DDD_CODES:
        return f"DDD {m.group(1)} is not allocated"
    return None


# ----------------------------------------------------------------------------------------------------------
# FC1 - parsing and validation of one /api/ddd/v1/{ddd} answer
# ----------------------------------------------------------------------------------------------------------


def clean_city_names(values: Any) -> dict[str, list[str]]:
    """Untrusted city list -> {'cities': unique names as published, sorted by folded name, 'dropped': [...]}.

    Names stay as BrasilAPI publishes them (upper case, accents, a few legacy spellings); duplicates are removed
    by folded form; the upstream order is not meaningful. Non-strings, empty or over-long names and names with
    digits, markup or control characters are dropped."""
    seen: set[str] = set()
    kept: list[str] = []
    dropped: list[str] = []
    for value in values if isinstance(values, list) else []:
        if not isinstance(value, str):
            dropped.append(repr(value)[:40])
            continue
        name = re.sub(r"\s+", " ", unicodedata.normalize("NFC", value)).strip()
        if not name or len(name) > MAX_CITY_NAME_LEN or not _CITY_NAME_RE.match(name):
            dropped.append(name[:40])
            continue
        key = fold(name)
        if key in seen:
            continue
        seen.add(key)
        kept.append(name)
    kept.sort(key=lambda n: (fold(n), n))
    return {"cities": kept, "dropped": dropped}


def _brasilapi_error(data: Any) -> dict[str, str | None] | None:
    """BrasilAPI's error object {'message', 'type', 'name'} (seen: 404 DDD_NOT_FOUND / ddd_error)."""
    if not isinstance(data, dict) or "state" in data or "cities" in data:
        return None
    name, etype, msg = data.get("name"), data.get("type"), data.get("message")
    if any(isinstance(v, str) and v for v in (name, etype)) and (msg is None or isinstance(msg, str)):
        return {"name": _str(name), "type": _str(etype), "message": _str(msg)}
    return None


def parse_ddd_payload(payload: Any) -> dict[str, Any]:
    """One /api/ddd/v1/{ddd} body (bytes, str or parsed JSON) -> {'ok', 'reason', 'state', 'cities', 'dropped',
    'error'}. {'state': 'SP', 'cities': [...]} -> ok; {'name': 'DDD_NOT_FOUND', ...} -> reason 'not_found'.
    HTML, truncated JSON, an error object, wrong types, an empty or implausible list -> ok False with a reason,
    never an empty success (rule 5: could not verify is not absence)."""
    out: dict[str, Any] = {"ok": False, "reason": None, "state": None, "cities": [], "dropped": [], "error": None}
    data = payload
    if isinstance(payload, (bytes, bytearray, memoryview, str)):
        size = len(payload.encode("utf-8", "replace")) if isinstance(payload, str) else len(bytes(payload))
        if size > MAX_BODY_BYTES:
            out["reason"] = f"body too large ({size} bytes) for one DDD"
            return out
        text = as_text(payload)
        if not text.strip():
            out["reason"] = "empty body"
            return out
        if looks_like_html(text):
            title = _html_title(text)
            out["reason"] = "HTML page instead of JSON" + (f" ({title})" if title else "")
            return out
        try:
            data = json.loads(text)
        except (ValueError, RecursionError):
            out["reason"] = "malformed JSON"
            return out
    err = _brasilapi_error(data)
    if err is not None:
        out["error"] = err
        label = err.get("name") or err.get("type")
        if err.get("name") == "DDD_NOT_FOUND" or err.get("type") == "ddd_error":
            out["reason"] = "not_found"
        elif err.get("name") == "TooManyRequestsError" or err.get("type") == "too_many_requests":
            out["reason"] = f"rate_limited: BrasilAPI {label} in the body (could not verify)"
        else:
            out["reason"] = f"BrasilAPI error {label} in the body (could not verify)"
        return out
    if not isinstance(data, dict):
        out["reason"] = "unexpected JSON shape (not an object)"
        return out
    state = data.get("state").strip().upper() if isinstance(data.get("state"), str) else None
    if state not in UF_CODES:
        out["reason"] = "missing or invalid state"
        return out
    if not isinstance(data.get("cities"), list):
        out["reason"] = "missing cities list"
        return out
    cleaned = clean_city_names(data["cities"])
    out.update(state=state, cities=cleaned["cities"], dropped=cleaned["dropped"])
    if not cleaned["cities"]:
        out["reason"] = "empty city list"
        return out
    if len(cleaned["cities"]) > MAX_CITIES_PER_DDD:
        out.update(reason=f"implausible city count {len(cleaned['cities'])}", cities=[])
        return out
    out["ok"] = True
    return out


def part_problems(data: Any) -> list[str]:
    """Why a downloaded part must not replace the installed copy ([] = install it)."""
    parsed = parse_ddd_payload(data)
    if parsed["ok"]:
        return []
    return [str(parsed["reason"] or "unusable answer")]


def _validator(ddd: str) -> Callable[[Path], bool]:
    """register_dataset(validate=): raises with the reason so `v3lum data update` shows why a copy was kept."""

    def validate(path: Path) -> bool:
        problems = part_problems(Path(path).read_bytes())
        if problems:
            raise ValueError(f"DDD {ddd}: {problems[0]}")
        return True

    validate.__name__ = f"validate_brasilapi_ddd_{ddd}"
    return validate


def register_parts() -> dict[str, str]:
    """Register ``brasilapi_ddd.<DDD>`` for the 67 allocated DDDs (idempotent). Returns {ddd: dataset name}."""
    parts: dict[str, str] = {}
    for item in ddd_fetch_plan():
        problem = ddd_url_problem(item["url"])
        if problem:  # pragma: no cover - the plan is built from the allocated codes only
            raise ValueError(f"{item['name']}: {problem}")
        if item["name"] not in DATASETS:
            register_dataset(
                item["name"], item["url"], ttl=DATASET_TTL, description=DESCRIPTION.format(ddd=item["ddd"]),
                licence=LICENCE, terms_class="open", attribution=ATTRIBUTION, provider=PROVIDER, source=SOURCE,
                validate=_validator(item["ddd"]), min_bytes=MIN_BODY_BYTES, expect="json", max_bytes=MAX_BODY_BYTES,
                large=True, essential=False,
            )
        parts[item["ddd"]] = item["name"]
    return parts


#: {ddd: dataset name} of the 67 registered parts.
PARTS: dict[str, str] = register_parts()


# ----------------------------------------------------------------------------------------------------------
# FC1 - the out-of-band refresh job (`python -m v3lum.modules.phone.brasilapi_ddd`)
# ----------------------------------------------------------------------------------------------------------

_BLOCKED_WORDS = ("anti-bot", "challenge page", "captcha", "geo_block", "geo-block", "geo-blocked", "login_wall", "login wall",
                  "circuit", "hostile", "access denied", "http 401", "http 403", "http 451", "blocked")
_RATE_WORDS = ("429", "rate_limited", "rate limited", "rate-limited", "too many requests", "quota")


def update_outcome(result: Any) -> str:
    """A dataset-manager UpdateResult -> 'ok' | 'not_modified' | 'not_found' | 'rate_limited' | 'blocked' | 'error'."""
    status = getattr(result, "status", "")
    if status == "updated":
        return "ok"
    if status == "unchanged":
        return "not_modified"
    reason = str(getattr(result, "reason", "") or "").lower()
    if any(w in reason for w in _BLOCKED_WORDS):
        return "blocked"
    if any(w in reason for w in _RATE_WORDS):
        return "rate_limited"
    if "http 404" in reason:
        return "not_found"
    return "error"


def update_abort_reason(records: Iterable[Mapping[str, Any]], max_consecutive_failures: int = MAX_CONSECUTIVE_FAILURES) -> str | None:
    """Why the 67-part refresh must stop now (the installed copies stay), or None to continue. A challenge or
    firewall answer stops at once (A9: never retried with other headers, UA, proxy or IP); so does a rate limit
    (rule 6: the core backs the provider off for the rest of the run, the next update retries); so do
    ``max_consecutive_failures`` failed parts in a row (the host is struggling)."""
    streak = 0
    for rec in records:
        outcome = rec.get("outcome") if isinstance(rec, Mapping) else None
        if outcome == "blocked":
            return f"stopped at DDD {rec.get('ddd')}: {rec.get('reason') or 'blocked'} (never bypassed)"
        if outcome == "rate_limited":
            return f"stopped at DDD {rec.get('ddd')}: rate limited ({rec.get('reason') or 'HTTP 429'}); the next update retries"
        streak = streak + 1 if outcome == "error" else 0
        if streak >= max_consecutive_failures:
            return f"stopped after {streak} consecutive failures (last: DDD {rec.get('ddd')}: {rec.get('reason')})"
    return None


def refresh_parts(store: Any, *, log: Callable[[str], None] | None = None) -> dict[str, Any]:
    """FC1: refresh the 67 parts through the dataset manager (``store`` = the runtime DataStore), in fixed sorted
    order: conditional GETs with the stored ETag, validation before install, the provider profile's pacing
    (<= 1 request/s). Refused inside a scan and offline. A part that fails keeps its installed copy; the job
    stops at a challenge, at a rate limit or after 3 consecutive failures (:func:`update_abort_reason`).

    Returns {'status': 'ok' | 'partial' | 'stopped' | 'refused', 'updated', 'unchanged', 'failed' {ddd: reason},
    'not_found', 'stopped_reason', 'records', 'installed' (installed_summary), 'line'}."""
    summary: dict[str, Any] = {"status": "ok", "updated": [], "unchanged": [], "failed": {}, "not_found": [],
                               "stopped_reason": None, "records": [], "installed": None, "line": ""}
    runtime = getattr(store, "runtime", None)
    refusal = None
    if store is None or runtime is None:
        refusal = "no runtime"
    elif getattr(runtime, "in_scan", False):
        refusal = "refused inside a scan (the DDD city lists are refreshed out of band only)"
    elif getattr(runtime, "offline", False):
        refusal = "offline mode: nothing can be downloaded"
    if refusal:
        summary.update(status="refused", stopped_reason=refusal, line=f"brasilapi_ddd: {refusal}")
        return summary
    for item in ddd_fetch_plan():
        try:
            result = store.update(item["name"])
        except Exception as exc:  # noqa: BLE001 - one broken part never crashes the job
            result = type("Failed", (), {"status": "failed", "reason": f"{type(exc).__name__}: {' '.join(str(exc).split())[:200]}"})()
        outcome = update_outcome(result)
        reason = " ".join(str(getattr(result, "reason", "") or "").split())[:240]
        rec = {"ddd": item["ddd"], "name": item["name"], "outcome": outcome, "reason": reason or None}
        summary["records"].append(rec)
        if outcome == "ok":
            summary["updated"].append(item["ddd"])
        elif outcome == "not_modified":
            summary["unchanged"].append(item["ddd"])
        else:
            summary["failed"][item["ddd"]] = reason or outcome
            if outcome == "not_found":  # a retired DDD needs maintainer review; the installed copy stays
                summary["not_found"].append(item["ddd"])
        if log:
            log(f"  {item['name']}: {outcome}" + (f" ({reason})" if reason and outcome not in ("ok", "not_modified") else ""))
        stop = update_abort_reason(summary["records"])
        if stop:
            summary["stopped_reason"] = stop
            break
    summary["installed"] = installed_summary(store)
    if summary["stopped_reason"]:
        summary["status"] = "stopped"
    elif summary["failed"]:
        summary["status"] = "partial"
    inst = summary["installed"]
    summary["line"] = (
        f"brasilapi_ddd: {summary['status']}: {len(summary['updated'])} updated, {len(summary['unchanged'])} unchanged, "
        f"{len(summary['failed'])} failed; installed {inst['present']}/{len(BR_DDD_CODES)} DDDs, {inst['total_cities']} cities"
        + (f"; {summary['stopped_reason']}" if summary["stopped_reason"] else "")
        + (f"; {inst['note']}" if inst.get("note") else "")
    )
    return summary


def installed_summary(store_or_view: Any) -> dict[str, Any]:
    """How much of the dataset is installed: {'present', 'missing' [ddd], 'total_cities', 'complete', 'note'}.
    Reads local copies only (never downloads)."""
    present: list[str] = []
    missing: list[str] = []
    total = 0
    for code in sorted(BR_DDD_CODES):
        rec = installed_part(store_or_view, code)
        if rec and rec.get("ok"):
            present.append(code)
            total += len(rec["cities"])
        else:
            missing.append(code)
    note = None
    if not missing and not (MIN_TOTAL_CITIES <= total <= MAX_TOTAL_CITIES):
        note = f"national total {total} outside the sanity range {MIN_TOTAL_CITIES}-{MAX_TOTAL_CITIES}: maintainer check"
    return {"present": len(present), "missing": missing, "total_cities": total, "complete": not missing, "note": note}


# ----------------------------------------------------------------------------------------------------------
# FC2 - offline scan-time reads and lookups (disclosure none)
# ----------------------------------------------------------------------------------------------------------


def installed_part(view: Any, ddd: Any) -> dict[str, Any] | None:
    """The installed part of one DDD, read locally (``view`` = ``ctx.data`` or a DataStore), or None when it is
    not downloaded. Never downloads: presence is checked first and the copy is served whatever its age (the
    refresh belongs to `v3lum data update`). Reading through ``ctx.data`` cites the part in ``res.datasets``.

    -> {'ok', 'reason', 'ddd', 'name', 'state', 'cities', 'fetched_at', 'age_hours', 'stale', 'sha256'};
    an unusable local copy gives ok False with the reason (never an empty city list)."""
    code = as_text(ddd).strip()
    if code not in BR_DDD_CODES or view is None:
        return None
    name = PART_PREFIX + code
    if name not in DATASETS:
        return None
    try:
        info = view.info(name)
        if not getattr(info, "present", False):
            return None
        data = view.fetch_json(name, ttl=NEVER_REFRESH_TTL)
    except (DatasetError, OSError, ValueError):
        return None
    parsed = parse_ddd_payload(data)
    return {"ok": parsed["ok"], "reason": parsed["reason"], "ddd": code, "name": name, "state": parsed["state"],
            "cities": parsed["cities"] if parsed["ok"] else [], "fetched_at": getattr(info, "fetched_at", None),
            "age_hours": getattr(info, "age_hours", None), "stale": bool(getattr(info, "stale", False)),
            "sha256": getattr(info, "sha256", None)}


def installed_records(view: Any, ddds: Iterable[Any] | None = None) -> dict[str, dict[str, Any]]:
    """{ddd: {'state', 'cities'}} for the installed parts (all DDDs, or only ``ddds``), in the shape that
    ``phone_parse.parse_ddd_dataset`` reads. Local reads only; missing or unusable parts are left out."""
    codes = sorted(BR_DDD_CODES) if ddds is None else sorted({as_text(d).strip() for d in ddds} & BR_DDD_CODES)
    out: dict[str, dict[str, Any]] = {}
    for code in codes:
        rec = installed_part(view, code)
        if rec and rec.get("ok"):
            out[code] = {"state": rec["state"], "cities": list(rec["cities"])}
    return out


def ddd_from_e164(e164: Any) -> str | None:
    """The DDD of a geographic Brazilian number from the core's canonical E.164 (+55 DD NNNNNNNN[N]); read-only
    (P126 FC1: no second normalisation). Non-BR, non-geographic (0800, 400x...) and unallocated codes -> None."""
    if not isinstance(e164, str):
        return None
    m = _BR_E164_RE.match(e164.strip())
    return m.group(1) if m and m.group(1) in BR_DDD_CODES else None


def _table_entry(bundled_table: Any, code: str) -> Mapping[str, Any] | None:
    entries = bundled_table.get("ddd") if isinstance(bundled_table, Mapping) else None
    entry = entries.get(code) if isinstance(entries, Mapping) else None
    return entry if isinstance(entry, Mapping) else None


def lookup_ddd(ddd: Any, record: Mapping[str, Any] | None = None, bundled_table: Any = None, *,
               ttl_s: float = DATASET_TTL) -> dict[str, Any]:
    """FC2: the scan-time answer for one DDD, fully offline.

    UF, UF list and main city come from phone_parse's bundled Anatel table; the city list and its count from
    the installed part (``record`` = :func:`installed_part`). Without a usable part the table answers and
    ``coverage`` = :data:`CITY_LIST_UNAVAILABLE`. A copy older than the TTL is still served with ``stale`` and an
    age note (AR10). A part whose state differs from the table UFs adds a maintainer note, never a finding."""
    code = as_text(ddd).strip()
    info: dict[str, Any] = {"ddd": code, "allocated": code in BR_DDD_CODES, "uf": None, "ufs": [], "main_city": None,
                            "uf_source": None, "city_count": None, "cities": None, "cities_source": None,
                            "main_city_in_list": None, "dataset": None, "stale": False, "coverage": None, "notes": [],
                            "attribution": None}
    if not info["allocated"]:
        info["notes"].append(f"DDD {code!r} is not an allocated Brazilian area code")
        return info
    entry = _table_entry(bundled_table, code)
    if entry is not None and entry.get("uf") in UF_CODES:
        ufs = [u for u in entry.get("ufs") or [] if u in UF_CODES] if isinstance(entry.get("ufs"), list) else []
        info.update(uf=entry["uf"], ufs=ufs if entry["uf"] in ufs else [entry["uf"], *ufs],
                    main_city=_str(entry.get("main_city")), uf_source="bundled_table")
    rec = record if isinstance(record, Mapping) else None
    if rec is not None and rec.get("ok") and rec.get("state") in UF_CODES and rec.get("cities"):
        cities = clean_city_names(list(rec["cities"]))["cities"]
        age_h = rec.get("age_hours")
        age_days = round(float(age_h) / 24.0, 1) if isinstance(age_h, (int, float)) else None
        stale = bool(rec.get("stale")) or (age_days is not None and age_days * 86400.0 >= ttl_s)
        info.update(cities=cities, city_count=len(cities), cities_source=DATASET, stale=stale, attribution=ATTRIBUTION,
                    dataset={"name": rec.get("name") or PART_PREFIX + code, "fetched_at": rec.get("fetched_at"),
                             "age_days": age_days, "stale": stale, "sha256": rec.get("sha256")})
        if info["uf"] is None:
            info.update(uf=rec["state"], ufs=[rec["state"]], uf_source=DATASET)
        elif rec["state"] not in info["ufs"]:
            info["notes"].append(f"BrasilAPI state {rec['state']} differs from the bundled table UF {info['uf']} "
                                 "(maintainer check; the table answers)")
        if info["main_city"]:
            info["main_city_in_list"] = fold(info["main_city"]) in {fold(c) for c in cities}
        if stale:
            info["notes"].append(f"city list is {age_days if age_days is not None else '?'} days old (older than "
                                 f"{int(ttl_s // 86400)} days): refresh with v3lum data update")
    else:
        info["coverage"] = CITY_LIST_UNAVAILABLE
        if rec is not None and not rec.get("ok"):
            info["notes"].append(f"installed city list of DDD {code} is unusable ({rec.get('reason') or 'invalid'}): ignored")
    if info["uf"] is None:
        info["notes"].append(f"no UF for DDD {code}: bundled DDD table missing or incomplete")
    return info


def lookup_phone(view: Any, e164: Any, bundled_table: Any = None) -> dict[str, Any] | None:
    """FC2 convenience: the offline lookup of a +55 geographic number's DDD (only that DDD's part is read), or
    None for numbers without a DDD. ``bundled_table`` defaults to phone_parse's bundled table."""
    code = ddd_from_e164(e164)
    if code is None:
        return None
    if bundled_table is None and view is not None:
        try:
            bundled_table = view.bundled_json(DDD_TABLE)
        except (OSError, ValueError):
            bundled_table = None
    return lookup_ddd(code, installed_part(view, code), bundled_table)


# ----------------------------------------------------------------------------------------------------------
# FC3 - report shapes
# ----------------------------------------------------------------------------------------------------------


def cities_label(n: Any) -> str:
    """'N cities in DDD' (singular for 1)."""
    return "1 city in DDD" if n == 1 else f"{int(n)} cities in DDD"


def display_city(name: Any) -> str:
    """Display form of a published upper-case name: 'SÃO JOSÉ DOS CAMPOS' -> 'São José dos Campos',
    "OLHO D'ÁGUA" -> "Olho d'Água", 'EMBU-GUAÇU' -> 'Embu-Guaçu'. The JSON value stays as published."""
    words = re.sub(r"\s+", " ", as_text(name)).strip().split(" ")
    out: list[str] = []
    for i, word in enumerate(words):
        parts: list[str] = []
        for part in word.split("-"):
            quote = "'" if "'" in part else ("’" if "’" in part else "")
            if quote:
                head, tail = part.split(quote, 1)
                head_s = head.lower() if head.lower() in _PARTICLES and (i or parts) else head.capitalize()
                parts.append(head_s + quote + tail.capitalize())
            elif part.lower() in _PARTICLES and (i or parts):
                parts.append(part.lower())
            else:
                parts.append(part.capitalize())
        out.append("-".join(parts))
    return " ".join(w for w in out if w)


def city_in_ddd(city: Any, lookup: Mapping[str, Any] | None) -> bool | None:
    """Weak consistency helper (info only, never a fraud signal: Anatel names can be legacy spellings): True or
    False when the city list is installed, None when it is not."""
    cities = lookup.get("cities") if isinstance(lookup, Mapping) else None
    if not cities or not _str(city):
        return None
    return fold(city) in {fold(c) for c in cities}


def ddd_report(lookup: Mapping[str, Any] | None) -> dict[str, Any]:
    """FC3: report shapes for one :func:`lookup_ddd` result.

    'terminal'/'markdown': UF + main city + 'N cities in DDD' only (never the list); 'html': the same summary plus
    a toggle {'label', 'items'} for a collapsed <details>; 'json': everything, the full list as published and the
    dataset citation included; 'coverage' and 'attribution' for the coverage line and the report notices."""
    lk = lookup if isinstance(lookup, Mapping) else {}
    code = lk.get("ddd") or "?"
    uf = lk.get("uf")
    extra = [u for u in lk.get("ufs") or [] if u != uf]
    pieces = [(uf or "UF unknown") + (f" (also {', '.join(extra)})" if extra else "")]
    if lk.get("main_city"):
        pieces.append(str(lk["main_city"]))
    if isinstance(lk.get("city_count"), int):
        pieces.append(cities_label(lk["city_count"]))
    summary = f"DDD {code}: " + " - ".join(pieces)
    if not lk.get("allocated", False):
        summary = f"DDD {code}: not an allocated Brazilian area code"
    toggle = None
    if lk.get("cities"):
        toggle = {"label": f"{cities_label(len(lk['cities']))} {code}", "items": [display_city(c) for c in lk["cities"]]}
    return {
        "terminal": summary,
        "markdown": summary,
        "html": {"summary": summary, "toggle": toggle},
        "json": {"ddd": code, "allocated": bool(lk.get("allocated")), "uf": uf, "ufs": list(lk.get("ufs") or []),
                 "main_city": lk.get("main_city"), "city_count": lk.get("city_count"), "cities": lk.get("cities"),
                 "cities_source": lk.get("cities_source"), "dataset": lk.get("dataset"), "stale": bool(lk.get("stale")),
                 "coverage": lk.get("coverage"), "notes": list(lk.get("notes") or []), "attribution": lk.get("attribution")},
        "coverage": lk.get("coverage"),
        "attribution": lk.get("attribution"),
    }


# ----------------------------------------------------------------------------------------------------------
# manual entry point (until `v3lum data update brasilapi_ddd` selects the parts: core request)
# ----------------------------------------------------------------------------------------------------------


def main(argv: list[str] | None = None, *, runtime: Any = None) -> int:
    """``python -m v3lum.modules.phone.brasilapi_ddd``: refresh the 67 parts now (outside any scan) through a
    runtime built from the user's configuration (proxy, egress and provider profiles of the core)."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m v3lum.modules.phone.brasilapi_ddd",
        description="Refresh the BrasilAPI DDD city lists: one GET per allocated DDD (67), <= 1 request/s, outside any scan.",
    )
    parser.parse_args(argv)
    try:
        os.umask(0o077)
    except AttributeError:  # pragma: no cover - platforms without umask
        pass

    def out(line: str) -> None:
        sys.stdout.write(line + "\n")

    if runtime is None:
        from v3lum.config import Config
        from v3lum.core.context import Runtime

        runtime = Runtime(Config.load())  # v3lum-lint: allow LINT-01 -- out-of-band `python -m` dataset refresh entry point (main), never run during a scan; downloads only the registered DDD datasets
    summary = refresh_parts(runtime.data, log=out)
    out(summary["line"])
    return 0 if summary["status"] == "ok" else 1


if __name__ == "__main__":  # pragma: no cover - manual entry point
    raise SystemExit(main())


__all__ = [
    "ATTRIBUTION", "BR_DDD_CODES", "CITY_LIST_UNAVAILABLE", "DATASET", "DATASET_TTL", "DDD_TABLE", "DDD_URL_TEMPLATE",
    "HOST", "LICENCE", "PART_PREFIX", "PARTS", "PROVIDER", "SOURCE", "UF_CODES", "cities_label", "city_in_ddd",
    "clean_city_names", "ddd_fetch_plan", "ddd_from_e164", "ddd_of_part", "ddd_report", "ddd_url_problem",
    "display_city", "fold", "installed_part", "installed_records", "installed_summary", "lookup_ddd", "lookup_phone",
    "main", "parse_ddd_payload", "part_name", "part_problems", "refresh_parts", "register_parts", "update_abort_reason",
    "update_outcome",
]
