"""Internal SIEM look-back (P349): "did this touch us?" through SOC-approved saved searches.

One read-only adapter for the team's **primary** SIEM (A12): OpenSearch/Elasticsearch ``_search`` or
Splunk saved-search dispatch. Final conditions of P349 implemented here:

* C1 module ``cti_framework/siem_search``, ``default_enabled = False``, disclosure ``internal``
  (provider ``internal_siem``, ``internal: true``, host only from setting ``siem_url``), a read-only
  token in key ``siem`` (``v3lum keys``; env ``V3LUM_SIEM_TOKEN``), TLS verification always on
  (core client, setting ``ca_bundle``). "Primary SIEM only": the template file names exactly one
  backend and entries for another backend are refused (:func:`validate_templates`).
* C2 only SOC-approved, versioned templates (setting ``siem_search_templates``, schema
  ``v3lum.siem_templates/1``, refused when group/world-writable). OpenSearch/Elasticsearch templates
  are declarative (approved index patterns, explicit fields, time field, constant term filters):
  V3LUM builds a JSON-DSL ``term`` query itself (:func:`build_es_search`); raw queries, Lucene/
  ``query_string`` and every text clause are refused. Splunk runs only SOC-approved saved searches
  dispatched with one argument (:func:`build_splunk_dispatch`), and only for IP, domain, hash and
  e-mail values whose canonical form matches a strict charset (:func:`splunk_value_allowed`); URL,
  username and user-agent values are never sent to Splunk.
* C3 values enter templates only as parameters: the JSON ``value`` leaf of a term query (a ``*``
  is a literal there) or a strict-charset Splunk argument without any SPL metacharacter. Every
  request passes the read-only allow-list :func:`request_allowed` before it is sent; the health
  check and a daily runtime check lint the saved-search definitions (:func:`splunk_saved_search_lint`:
  token quoted, no subsearch, no side-effect command, ends in ``stats count``).
* C4 one query per entity, at most 20 per scan (QUOTA ``quota`` beyond, never an absence), 30-day
  window by default (capped at 90), <= 1,000 results (``track_total_hits`` / ``dispatch.max_count``),
  one query at a time (provider concurrency 1), 15 s by default and never above 30 s. Any failure
  is "could not verify" (needs_key / rate_limited / blocked / error, never EMPTY). Output: counts
  and first/last seen only (``size: 0``; Splunk columns outside the contract are dropped), with the
  report line 'seen in our logs: N events, first ..., last ...' (:func:`summary_line`).
* C5 results are recorded as an internal sighting (attribute ``siem_sighting``, an
  ``internal_sightings`` entry with platform 'siem', finding tags ``internal_sighting`` and
  ``seen_in_logs``), never as raw events; the module produces no pivots at all (internal hostnames
  and usernames are never auto-pivoted).
* C6 personal identifiers (e-mail, username, user agent) are searched only for analyst-typed seeds
  of a case with a recorded purpose and ticket (:func:`lookup_refusal`; purposes that read as HR or
  performance monitoring are refused); each query is logged with analyst and case id in the
  evidence (``raw['query_log']``, the value only as its keyed HMAC) and in the live feed. Results
  are case data and follow the case retention (no HTTP cache: ``cache_ttl = 0``).
* C7 the covert-exercise flag of P348 (``ScanOptions.covert`` / ``no_internal``) skips SIEM lookups
  too (SKIPPED ``policy``). Synthetic fixtures for both backends (tests/fixtures/siem_search/).
"""

from __future__ import annotations

import getpass
import ipaddress
import json
import math
import os
import re
import stat as _stat
import threading
import unicodedata
from collections import OrderedDict
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from v3lum.config import SettingSpec
from v3lum.core import hmacid
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import HttpError, NetworkError, PolicyError
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, HealthResult, Module, register

PROVIDER = "internal_siem"
SOURCE = "internal_siem.search"
KEY_NAME = "siem"
URL_SETTING = "siem_url"
TEMPLATES_SETTING = "siem_search_templates"

BACKENDS = ("elasticsearch", "opensearch", "splunk")
INPUT_TYPES = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha256", "username", "user_agent")
#: C6: personal identifiers, searched only inside a case with an incident purpose
PERSONAL_TYPES = frozenset({"email", "username", "user_agent"})
#: C2: Splunk arguments only for strict-charset types (IP, domain, hash, e-mail)
SPLUNK_TYPES = frozenset({"ipv4", "ipv6", "domain", "md5", "sha256", "email"})
MAX_QUERIES_PER_SCAN = 20  # C4
DEFAULT_WINDOW_DAYS = 30  # C4 / A12
MAX_WINDOW_DAYS = 90  # an explicit longer window is capped here (the spec sets only the default)
MAX_RESULTS = 1000  # C4 / A12
DEFAULT_TIMEOUT = 15.0  # C4
MAX_TIMEOUT = 30.0  # C4 / A12: never above 30 s
MIN_INTERVAL = 1.0  # one query at a time, at least 1 s apart per SIEM host
MAX_POLLS = 8  # Splunk: 1 dispatch + <= 8 job polls + 1 results
LINT_TTL = timedelta(days=1)
TEMPLATE_SCHEMA = "v3lum.siem_templates/1"
TEMPLATE_MAX_BYTES = 1_000_000
ES_PARAMS = {"ignore_unavailable": "true", "allow_no_indices": "true", "allow_partial_search_results": "false"}
COVERT_REASON = "covert exercise (--covert / --no-internal): internal SIEM lookups skipped (P348 C8, P349 C7)"
TLP_CHOICES = ("amber", "amber+strict", "red")

#: Elasticsearch/OpenSearch clauses that interpret text (Lucene syntax, wildcards, scripts): never built (C2)
ES_FORBIDDEN_CLAUSES = frozenset({
    "query_string", "simple_query_string", "script", "script_score", "wildcard", "regexp", "fuzzy", "prefix",
    "match", "match_phrase", "match_phrase_prefix", "match_bool_prefix", "multi_match", "combined_fields",
    "intervals", "more_like_this", "percolate", "function_score", "span_multi",
})
#: characters that could change an SPL search after the textual $args.x$ substitution (C2/C3)
SPL_META = frozenset("\"'\\|[]`$*=()<>,;!?^~{}#&% \t\r\n")
_SPLUNK_STRICT = {
    "ipv4": re.compile(r"[0-9.]{7,15}"),
    "ipv6": re.compile(r"[0-9a-f:.]{2,45}"),
    "domain": re.compile(r"[a-z0-9.-]{1,253}"),
    "md5": re.compile(r"[0-9a-f]{32}"),
    "sha256": re.compile(r"[0-9a-f]{64}"),
    "email": re.compile(r"[a-z0-9._+-]{1,64}@[a-z0-9.-]{1,253}"),
}
_HASH_LEN = {"md5": 32, "sha256": 64}
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_LABEL = r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:" + _LABEL + r"\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_INDEX_PATTERN_RE = re.compile(r"^[a-z0-9][a-z0-9._*-]{0,254}$")
_FIELD_RE = re.compile(r"^[A-Za-z0-9_@][A-Za-z0-9_.@-]{0,254}$")
_SPLUNK_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$")
_SPLUNK_ARG_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_SID_RE = re.compile(r"^[A-Za-z0-9_@-][A-Za-z0-9_.@-]{0,255}$")
_RAW_QUERY_KEYS = frozenset({"query", "dsl", "body", "search", "spl", "script", "source", "q", "lucene"})
_MIN_TS = datetime(1990, 1, 1, tzinfo=timezone.utc)
_MAX_TS = datetime(2100, 1, 1, tzinfo=timezone.utc)

#: C6: purposes that would mean HR / performance monitoring (accent-folded, lower-case; a guard, not proof)
HR_PURPOSE_PATTERNS = (
    r"\brh\b", r"\bhr\b", r"recursos humanos", r"human resources?", r"avaliacao de desempenho",
    r"desempenho (do|da|de) (colaborador|funcionari|empregad)", r"performance (review|evaluation|appraisal)",
    r"produtividade", r"productivity", r"disciplinar", r"disciplinary", r"controle de jornada", r"banco de horas",
)


# ======================================================================================
# small defensive helpers (untrusted answers)
# ======================================================================================


def _as_text(body: Any, limit: int = 8 * 1024 * 1024) -> str:
    if body is None:
        return ""
    if isinstance(body, (bytes, bytearray, memoryview)):
        body = bytes(body[:limit]).decode("utf-8", "replace")
    elif isinstance(body, (dict, list)):
        body = json.dumps(body)
    elif not isinstance(body, str):
        body = str(body)
    if body.startswith("﻿"):
        body = body[1:]
    return body[:limit]


def _as_json(body: Any) -> Any:
    if isinstance(body, (dict, list)):
        return body
    text = _as_text(body).strip()
    if not text or text[0] not in "{[":
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def _looks_like_html(body: Any, content_type: str | None = None) -> bool:
    if "html" in (content_type or "").lower():
        return True
    head = _as_text(body, 4096).lstrip()[:600].lower()
    return head.startswith(("<!doctype html", "<html", "<head", "<body")) or "<html" in head[:300]


def _short(value: Any, n: int = 200) -> str:
    text = _CTRL_RE.sub(" ", _as_text(value, 20000))
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= n else text[: n - 3] + "..."


def _to_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if math.isfinite(value) and value == int(value) else None
    if isinstance(value, str) and re.fullmatch(r"\s*-?\d{1,18}\s*", value):
        return int(value)
    return None


def _to_float(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value) if math.isfinite(float(value)) else None
    if isinstance(value, str):
        try:
            out = float(value.strip())
        except ValueError:
            return None
        return out if math.isfinite(out) else None
    return None


def _iso(d: datetime) -> str | None:
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    d = d.astimezone(timezone.utc)
    if not (_MIN_TS <= d < _MAX_TS):
        return None
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso_from_epoch(value: Any, unit: str = "auto") -> str | None:
    v = _to_float(value)
    if v is None:
        return None
    if unit == "ms" or (unit == "auto" and abs(v) > 1e11):
        v = v / 1000.0
    try:
        return _iso(datetime.fromtimestamp(v, tz=timezone.utc))
    except (OverflowError, OSError, ValueError):
        return None


def parse_ts(value: Any) -> str | None:
    """'2026-10-28T09:14:03.000Z', '2026-11-26T06:41:12.000+00:00', epoch seconds/milliseconds -> ISO UTC."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return _iso_from_epoch(value)
    text = _short(value, 64)
    if not text:
        return None
    if re.fullmatch(r"-?\d+(\.\d+)?", text):
        return _iso_from_epoch(text)
    text = text.replace(" UTC", "").replace("Z", "+00:00")
    if re.match(r"^\d{4}-\d{2}-\d{2} \d", text):
        text = text.replace(" ", "T", 1)
    try:
        return _iso(datetime.fromisoformat(text))
    except ValueError:
        return None


def reason_code(reason: str | None) -> str | None:
    """'rate_limited: ...' -> 'rate_limited' (markers and refusals start with a canonical A3 code)."""
    if not reason:
        return None
    return reason.split(":", 1)[0].strip() or None


def _reason_text(reason: str) -> str:
    return reason.split(":", 1)[1].strip() if ":" in reason else reason


# ======================================================================================
# C2/C3: canonical values and strict charsets
# ======================================================================================


def _canonical_domain(value: str) -> str | None:
    d = value.strip().lower().rstrip(".")
    if not d or len(d) > 253:
        return None
    try:
        d = d.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    return d if _DOMAIN_RE.match(d) else None


def canonical_value(entity_type: str, value: Any) -> tuple[str | None, str | None]:
    """Canonical form of an investigated value before it enters any template, or a refusal
    ('not_applicable: ...'). IPs via ipaddress, domains lower-case IDNA, hashes lower-case hex of
    exact length, e-mail lower-case; url/username/user_agent are kept literally (they only ever reach
    an Elasticsearch term value). Control characters, empty values and values made only of wildcard
    or punctuation characters (a bare ``*``) never reach a SIEM."""
    t = (entity_type or "").lower()
    if not isinstance(value, str):
        return None, "not_applicable: value is not text"
    v = value.strip()
    if t not in INPUT_TYPES:
        return None, f"not_applicable: {t or '?'} is not a siem_search input type"
    if not v:
        return None, "not_applicable: empty value"
    if _CTRL_RE.search(v):
        return None, "not_applicable: control characters in value"
    if re.fullmatch(r"[\W_]+", v):
        return None, "not_applicable: value has no word characters (wildcard/punctuation only)"
    if t == "ipv4":
        try:
            return str(ipaddress.IPv4Address(v)), None
        except ValueError:
            return None, "not_applicable: not an IPv4 address"
    if t == "ipv6":
        if "%" in v:
            return None, "not_applicable: IPv6 zone ids are not searched"
        try:
            return ipaddress.IPv6Address(v).compressed, None
        except ValueError:
            return None, "not_applicable: not an IPv6 address"
    if t == "domain":
        d = _canonical_domain(v)
        return (d, None) if d else (None, "not_applicable: not a valid domain name")
    if t in _HASH_LEN:
        h = v.lower()
        if len(h) == _HASH_LEN[t] and _HEX_RE.match(h):
            return h, None
        return None, f"not_applicable: not a {t} hash"
    if t == "email":
        if v.count("@") != 1 or len(v) > 254:
            return None, "not_applicable: not an e-mail address"
        local, dom = v.rsplit("@", 1)
        d = _canonical_domain(dom)
        if not local or len(local) > 64 or not d or re.search(r"\s", local):
            return None, "not_applicable: not an e-mail address"
        return local.lower() + "@" + d, None
    if t == "url":
        if len(v) > 2048 or re.search(r"\s", v) or not re.match(r"(?i)^https?://[^/?#]+", v):
            return None, "not_applicable: not an http(s) URL"
        return v, None
    if t == "username":
        return (v, None) if len(v) <= 256 else (None, "not_applicable: username longer than 256 characters")
    return (v, None) if len(v) <= 1024 else (None, "not_applicable: user agent longer than 1024 characters")


def splunk_value_allowed(entity_type: str, value: Any) -> tuple[str | None, str | None]:
    """C2/C3: Splunk ``args.*`` are substituted TEXTUALLY into SPL, so only IP, domain, hash and e-mail
    values whose canonical form matches a strict charset (no quote, space, pipe, bracket, ``$``, ``*``,
    ``=``...) are accepted; url, username and user_agent are refused for Splunk."""
    t = (entity_type or "").lower()
    if t not in SPLUNK_TYPES:
        return None, (f"not_applicable: {t or '?'} values are not sent to Splunk saved searches "
                      "(strict-charset types only: IP, domain, hash, e-mail)")
    canon, why = canonical_value(t, value)
    if canon is None:
        return None, why
    if not _SPLUNK_STRICT[t].fullmatch(canon) or set(canon) & SPL_META:
        return None, "not_applicable: value outside the strict Splunk charset"
    return canon, None


def effective_timeout(requested: Any = None) -> float:
    """C4 / A12: 15 s by default, never above 30 s (and at least 1 s)."""
    v = _to_float(requested)
    if v is None or v <= 0:
        return DEFAULT_TIMEOUT
    return max(1.0, min(v, MAX_TIMEOUT))


def effective_window(window_days: Any) -> int:
    """C4: 30 days by default; an explicit longer window is capped at 90 days."""
    v = _to_int(window_days)
    if v is None or v <= 0:
        return DEFAULT_WINDOW_DAYS
    return min(v, MAX_WINDOW_DAYS)


def _walk_keys(obj: Any, depth: int = 0) -> Iterable[str]:
    if depth > 40:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _walk_keys(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_keys(v, depth + 1)


# ======================================================================================
# C1/C2: the SOC-approved, versioned template file
# ======================================================================================


def validate_templates(doc: Any) -> dict[str, Any]:
    """Validate the template file (schema ``v3lum.siem_templates/1``). Returns ``{version, backend,
    approved_by, approved_at, templates: {id: tpl}, splunk: {id: saved}, errors: [...], fatal: bool}``;
    only error-free entries are returned. ``fatal`` is True when the file itself is unusable (no
    schema, version or backend): the adapter then stays disabled."""
    out: dict[str, Any] = {"version": None, "backend": None, "approved_by": None, "approved_at": None,
                           "templates": {}, "splunk": {}, "errors": [], "fatal": False}
    errs: list[str] = out["errors"]
    if not isinstance(doc, dict):
        errs.append("template file is not a JSON object")
        out["fatal"] = True
        return out
    if doc.get("schema") != TEMPLATE_SCHEMA:
        errs.append(f"schema must be {TEMPLATE_SCHEMA}")
        out["fatal"] = True
    ver = doc.get("version")
    if not isinstance(ver, str) or not ver.strip():
        errs.append("version missing (templates must be versioned)")
        out["fatal"] = True
    else:
        out["version"] = ver.strip()[:64]
    backend = doc.get("backend")
    if backend not in BACKENDS:
        errs.append("backend must be one of " + ", ".join(BACKENDS) + " (one file = the primary SIEM)")
        out["fatal"] = True
    else:
        out["backend"] = backend
    for k in ("approved_by", "approved_at"):
        out[k] = _short(doc.get(k), 120) if isinstance(doc.get(k), str) else None

    def personal_ok(tpl: dict[str, Any], types: list[str]) -> bool:
        return not (set(types) & PERSONAL_TYPES) or tpl.get("personal") is True

    seen: set[str] = set()
    raw_templates = doc.get("templates") or []
    for tpl in raw_templates if isinstance(raw_templates, list) else []:
        if not isinstance(tpl, dict):
            errs.append("template entry is not an object")
            continue
        tid = tpl.get("id")
        label = "template " + (tid if isinstance(tid, str) else "?")
        problems: list[str] = []
        if not isinstance(tid, str) or not _ID_RE.match(tid) or tid in seen:
            problems.append("id missing, invalid or duplicated")
        raw = sorted(_RAW_QUERY_KEYS & set(tpl))
        if raw:
            problems.append("raw query keys not allowed (" + ", ".join(raw) + "): V3LUM builds term queries itself")
        bad_clauses = sorted(set(_walk_keys(tpl)) & ES_FORBIDDEN_CLAUSES)
        if bad_clauses:
            problems.append("forbidden query clauses (" + ", ".join(bad_clauses) + "): never query_string/Lucene syntax")
        types = tpl.get("entity_types")
        if not isinstance(types, list) or not types or not all(t in INPUT_TYPES for t in types):
            problems.append("entity_types must be a non-empty subset of " + ", ".join(INPUT_TYPES))
            types = [t for t in types if isinstance(t, str)] if isinstance(types, list) else []
        idx = tpl.get("index_patterns")
        if not isinstance(idx, list) or not idx:
            problems.append("index_patterns missing")
        else:
            for p in idx:
                if not isinstance(p, str) or not _INDEX_PATTERN_RE.match(p) or re.fullmatch(r"[*.\-_]+", p) or p == "_all":
                    problems.append(f"index pattern {_short(p, 40)!r} not allowed (specific approved patterns only, no * / _all)")
        fields = tpl.get("fields")
        if not isinstance(fields, list) or not fields or not all(isinstance(f, str) and _FIELD_RE.match(f) for f in fields):
            problems.append("fields must be explicit field names (no wildcards)")
        time_field = tpl.get("time_field")
        if not isinstance(time_field, str) or not _FIELD_RE.match(time_field):
            problems.append("time_field missing or invalid")
        for flt in tpl.get("filters") or []:
            if not (isinstance(flt, dict) and set(flt) == {"field", "value"} and isinstance(flt.get("field"), str)
                    and _FIELD_RE.match(flt["field"]) and isinstance(flt.get("value"), (str, int, bool))
                    and len(str(flt["value"])) <= 256):
                problems.append("filters must be {field, value} constant term filters")
        if not personal_ok(tpl, types):
            problems.append("covers personal identifiers (e-mail/username/user_agent) but is not flagged personal")
        if "case_insensitive" in tpl and not isinstance(tpl["case_insensitive"], bool):
            problems.append("case_insensitive must be true or false")
        if out["backend"] == "splunk":
            problems.append("Elasticsearch/OpenSearch template in a splunk template file (primary SIEM only)")
        if problems:
            errs.extend(f"{label}: {p}" for p in problems)
            continue
        seen.add(tid)
        out["templates"][tid] = {
            "id": tid, "version": out["version"], "entity_types": list(types), "index_patterns": list(idx),
            "fields": list(fields), "time_field": time_field, "personal": tpl.get("personal") is True,
            "case_insensitive": tpl.get("case_insensitive") is True,
            "filters": [dict(f) for f in tpl.get("filters") or []],
        }
    raw_saved = doc.get("splunk_saved_searches") or []
    for ss in raw_saved if isinstance(raw_saved, list) else []:
        if not isinstance(ss, dict):
            errs.append("saved search entry is not an object")
            continue
        sid = ss.get("id")
        label = "saved search " + (sid if isinstance(sid, str) else "?")
        problems = []
        if not isinstance(sid, str) or not _ID_RE.match(sid) or sid in seen:
            problems.append("id missing, invalid or duplicated")
        for k in ("name", "owner", "app"):
            if not isinstance(ss.get(k), str) or not _SPLUNK_NAME_RE.match(ss.get(k)):
                problems.append(f"{k} missing or outside [A-Za-z0-9_.-]")
        if not isinstance(ss.get("arg"), str) or not _SPLUNK_ARG_RE.match(ss.get("arg")):
            problems.append("arg missing or invalid")
        types = ss.get("entity_types")
        if not isinstance(types, list) or not types:
            problems.append("entity_types missing")
            types = []
        else:
            bad = [str(t) for t in types if t not in SPLUNK_TYPES]
            if bad:
                problems.append("types " + ", ".join(bad) + " refused for Splunk (strict charset: IP, domain, hash, e-mail)")
        if not personal_ok(ss, types):
            problems.append("covers e-mail but is not flagged personal")
        if out["backend"] in ("elasticsearch", "opensearch"):
            problems.append("Splunk saved search in an elasticsearch/opensearch template file (primary SIEM only)")
        if problems:
            errs.extend(f"{label}: {p}" for p in problems)
            continue
        seen.add(sid)
        index_label = ss.get("index_pattern")
        out["splunk"][sid] = {
            "id": sid, "version": out["version"], "name": ss["name"], "owner": ss["owner"], "app": ss["app"],
            "arg": ss["arg"], "entity_types": list(types),
            "index_pattern": _short(index_label, 120) if isinstance(index_label, str) else None,
            "personal": ss.get("personal") is True,
        }
    if out["fatal"]:
        out["templates"], out["splunk"] = {}, {}
    return out


def select_template(spec: dict[str, Any], entity_type: str) -> dict[str, Any] | None:
    """C4 one query per entity: the first approved template (file order) of the backend covering the type."""
    pool = spec.get("splunk") if spec.get("backend") == "splunk" else spec.get("templates")
    for tpl in (pool or {}).values():
        if entity_type in (tpl.get("entity_types") or []):
            return tpl
    return None


# ======================================================================================
# C2/C3/C4: request builders and the read-only allow-list
# ======================================================================================


def build_es_search(template: dict[str, Any], entity_type: str, value: Any, *, window_days: Any = None,
                    timeout_s: Any = None, max_results: Any = None) -> tuple[dict[str, Any] | None, str | None]:
    """One ``POST /<approved index patterns>/_search`` per entity. The value is only the ``value`` leaf
    of term queries (JSON string: no Lucene parsing, ``*`` is a literal); ``size: 0`` (no raw events),
    ``track_total_hits`` <= 1000, min/max aggregations on the time field for first/last seen, a
    ``now-30d`` range filter, a body timeout below the client timeout and partial results refused."""
    if not isinstance(template, dict) or not template.get("index_patterns") or not template.get("fields"):
        return None, "config: no approved template"
    if (not all(isinstance(p, str) and _INDEX_PATTERN_RE.match(p) and not re.fullmatch(r"[*.\-_]+", p) for p in template["index_patterns"])
            or not all(isinstance(f, str) and _FIELD_RE.match(f) for f in template["fields"])
            or not isinstance(template.get("time_field"), str) or not _FIELD_RE.match(template["time_field"])):
        return None, f"config: template {template.get('id')} failed validation"
    t = (entity_type or "").lower()
    if t not in (template.get("entity_types") or []):
        return None, f"not_applicable: template {template.get('id')} does not cover {t}"
    canon, why = canonical_value(t, value)
    if canon is None:
        return None, why
    timeout = effective_timeout(timeout_s)
    window = effective_window(window_days)
    cap = max(1, min(_to_int(max_results) or MAX_RESULTS, MAX_RESULTS))
    tf = template["time_field"]
    leaf: dict[str, Any] = {"value": canon}
    if template.get("case_insensitive") is True:
        leaf["case_insensitive"] = True
    terms = [{"term": {f: dict(leaf)}} for f in template["fields"]]
    match = terms[0] if len(terms) == 1 else {"bool": {"should": terms, "minimum_should_match": 1}}
    filters: list[dict[str, Any]] = [match, {"range": {tf: {"gte": f"now-{window}d", "lte": "now"}}}]
    filters += [{"term": {f["field"]: {"value": f["value"]}}} for f in template.get("filters") or []]
    body = {
        "size": 0,
        "track_total_hits": cap,
        "timeout": f"{max(1, int(timeout) - 1)}s",
        "query": {"bool": {"filter": filters}},
        "aggs": {"first_seen": {"min": {"field": tf}}, "last_seen": {"max": {"field": tf}}},
    }
    path = "/" + ",".join(quote(p, safe="*") for p in template["index_patterns"]) + "/_search"
    return {"method": "POST", "path": path, "params": dict(ES_PARAMS), "json": body, "client_timeout_s": timeout,
            "template_id": template.get("id"), "template_version": template.get("version"),
            "index_patterns": list(template["index_patterns"]), "window_days": window}, None


def build_splunk_dispatch(saved: dict[str, Any], entity_type: str, value: Any, *, window_days: Any = None,
                          timeout_s: Any = None, max_results: Any = None) -> tuple[dict[str, Any] | None, str | None]:
    """Dispatch a SOC-approved saved search with the strict-charset value as ``args.<arg>``:
    ``dispatchAs=user`` (the read-only account's rights), ``trigger_actions=0``, 30-day window,
    ``dispatch.max_count`` 1000, ``dispatch.max_time`` = the timeout, short ``dispatch.ttl``."""
    if not isinstance(saved, dict) or not saved.get("name"):
        return None, "config: no approved saved search"
    t = (entity_type or "").lower()
    canon, why = splunk_value_allowed(t, value)
    if canon is None:
        return None, why
    if t not in (saved.get("entity_types") or []):
        return None, f"not_applicable: saved search {saved.get('id')} does not cover {t}"
    for k in ("name", "owner", "app"):
        if not isinstance(saved.get(k), str) or not _SPLUNK_NAME_RE.match(saved[k]):
            return None, f"config: saved search {k} invalid"
    if not isinstance(saved.get("arg"), str) or not _SPLUNK_ARG_RE.match(saved["arg"]):
        return None, "config: saved search arg invalid"
    timeout = effective_timeout(timeout_s)
    window = effective_window(window_days)
    cap = max(1, min(_to_int(max_results) or MAX_RESULTS, MAX_RESULTS))
    path = "/servicesNS/{}/{}/saved/searches/{}/dispatch".format(
        quote(saved["owner"], safe=""), quote(saved["app"], safe=""), quote(saved["name"], safe=""))
    form = {
        f"args.{saved['arg']}": canon,
        "dispatch.earliest_time": f"-{window}d",
        "dispatch.latest_time": "now",
        "dispatch.max_count": str(cap),
        "dispatch.max_time": str(int(timeout)),
        "dispatch.ttl": "300",
        "dispatchAs": "user",
        "trigger_actions": "0",
        "output_mode": "json",
    }
    return {"method": "POST", "path": path, "form": form, "client_timeout_s": timeout,
            "template_id": saved.get("id"), "template_version": saved.get("version"),
            "index_patterns": [saved["index_pattern"]] if saved.get("index_pattern") else [], "window_days": window}, None


def splunk_sid_ok(sid: Any) -> bool:
    """The sid comes from the server: only a strict charset may enter a URL path (no '/', no '..')."""
    return isinstance(sid, str) and bool(_SID_RE.match(sid)) and ".." not in sid


def _ns(saved: dict[str, Any]) -> str:
    return "/servicesNS/{}/{}".format(quote(saved["owner"], safe=""), quote(saved["app"], safe=""))


def splunk_job_request(saved: dict[str, Any], sid: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Job status poll ``GET .../search/jobs/<sid>?output_mode=json`` (read-only)."""
    if not splunk_sid_ok(sid):
        return None, "error: invalid search id from Splunk"
    return {"method": "GET", "path": f"{_ns(saved)}/search/jobs/{sid}", "params": {"output_mode": "json"}}, None


def splunk_results_request(saved: dict[str, Any], sid: Any, max_results: Any = None, api: str = "v2") -> tuple[dict[str, Any] | None, str | None]:
    """Results ``GET .../search/v2/jobs/<sid>/results?output_mode=json&count<=1000`` (v1 path for
    Splunk < 9). Never the POST form, which accepts a post-processing ``search`` (SPL)."""
    if not splunk_sid_ok(sid):
        return None, "error: invalid search id from Splunk"
    cap = max(1, min(_to_int(max_results) or MAX_RESULTS, MAX_RESULTS))
    mid = "search/v2/jobs" if api == "v2" else "search/jobs"
    return {"method": "GET", "path": f"{_ns(saved)}/{mid}/{sid}/results", "params": {"output_mode": "json", "count": str(cap)}}, None


def splunk_definition_request(saved: dict[str, Any]) -> dict[str, Any]:
    """Saved-search definition ``GET .../saved/searches/<name>?output_mode=json`` (safety lint)."""
    return {"method": "GET", "path": f"{_ns(saved)}/saved/searches/{quote(saved['name'], safe='')}", "params": {"output_mode": "json"}}


def splunk_poll_delays(budget_s: Any = None, max_polls: int = MAX_POLLS, min_step: float = MIN_INTERVAL) -> list[float]:
    """Job-status poll schedule inside the timeout budget (min_step, then doubling up to 2 s; at most 8
    polls), so one entity costs at most 1 dispatch + 8 polls + 1 results = 10 requests."""
    budget = effective_timeout(budget_s)
    out: list[float] = []
    total, step = 0.0, max(0.5, float(min_step))
    while len(out) < max_polls and total + step <= budget:
        out.append(step)
        total += step
        step = min(step * 2, 2.0) if step < 2.0 else 2.0
    return out


_ES_BODY_ALLOW = frozenset({"size", "track_total_hits", "timeout", "query", "aggs"})
_ES_PARAM_ALLOW = frozenset({"ignore_unavailable", "allow_no_indices", "allow_partial_search_results", "rest_total_hits_as_int"})
_DISPATCH_FORM_FIXED = frozenset({"dispatch.earliest_time", "dispatch.latest_time", "dispatch.max_count", "dispatch.max_time",
                                  "dispatch.ttl", "dispatchAs", "trigger_actions", "output_mode"})
_ALLOWED_CALLS = (
    ("POST", re.compile(r"^/[a-z0-9._*,-]+/_search$"), "es_search"),
    ("GET", re.compile(r"^/$"), "es_info"),
    ("POST", re.compile(r"^/servicesNS/[^/]+/[^/]+/saved/searches/[^/]+/dispatch$"), "splunk_dispatch"),
    ("GET", re.compile(r"^/servicesNS/[^/]+/[^/]+/search/jobs/[^/]+$"), "splunk_job"),
    ("GET", re.compile(r"^/servicesNS/[^/]+/[^/]+/search/(?:v2/)?jobs/[^/]+/results$"), "splunk_results"),
    ("GET", re.compile(r"^/servicesNS/[^/]+/[^/]+/saved/searches/[^/]+$"), "splunk_saved_search_read"),
)


def request_allowed(req: Any) -> str | None:
    """A12 read-only adapter: method + path allow-list over a built request ``{method, path, params?,
    json?, form?}``. None when allowed, else 'policy: ...'. Refuses every other endpoint (DELETE jobs,
    saved-search edits, ``_bulk``, ``_delete_by_query``, ad-hoc ``search/jobs`` searches), the Lucene
    ``q`` parameter, forbidden DSL clauses anywhere in the body, ``size`` > 0, unknown dispatch form
    keys, ``trigger_actions`` other than 0, metacharacters in a dispatch argument and the results
    ``search`` post-processing parameter."""
    if not isinstance(req, dict):
        return "policy: request is not a dict"
    method = str(req.get("method") or "").upper()
    path = str(req.get("path") or "")
    if ".." in path or "//" in path or "?" in path or "#" in path:
        return f"policy: path not allowed ({_short(path, 80)})"
    kind = next((k for m, rx, k in _ALLOWED_CALLS if m == method and rx.match(path)), None)
    if kind is None:
        return f"policy: {method} {_short(path, 80)} is not an allowed read-only SIEM call"
    params = req.get("params") or {}
    if not isinstance(params, dict):
        return "policy: params must be a dict"
    if kind == "es_search":
        extra = set(params) - _ES_PARAM_ALLOW
        if extra:
            return "policy: query parameters not allowed: " + ", ".join(sorted(extra))
        body = req.get("json")
        if not isinstance(body, dict):
            return "policy: search body missing"
        bad = sorted(set(_walk_keys(body)) & ES_FORBIDDEN_CLAUSES)
        if bad:
            return "policy: forbidden query clauses: " + ", ".join(bad)
        if _to_int(body.get("size")) != 0:
            return "policy: size must be 0 (counts only, no raw events)"
        extra = set(body) - _ES_BODY_ALLOW
        if extra:
            return "policy: search body keys not allowed: " + ", ".join(sorted(extra))
        tth = _to_int(body.get("track_total_hits"))
        if tth is None or not 0 < tth <= MAX_RESULTS:
            return f"policy: track_total_hits must be an integer <= {MAX_RESULTS}"
        aggs = body.get("aggs") or {}
        if (not isinstance(aggs, dict) or set(aggs) - {"first_seen", "last_seen"}
                or any(not (isinstance(a, dict) and len(a) == 1 and next(iter(a)) in ("min", "max")) for a in aggs.values())):
            return "policy: only min/max time aggregations (first/last seen) are allowed"
    elif kind == "splunk_dispatch":
        form = req.get("form") or {}
        if not isinstance(form, dict):
            return "policy: form must be a dict"
        args = [k for k in form if str(k).startswith("args.")]
        extra = set(form) - _DISPATCH_FORM_FIXED - set(args)
        if len(args) != 1 or extra:
            return "policy: dispatch form keys not allowed: " + ", ".join(sorted(extra) or ["args"])
        if str(form.get("trigger_actions", "0")) != "0":
            return "policy: trigger_actions must be 0"
        if any(set(str(form[a])) & SPL_META for a in args):
            return "policy: argument value outside the strict Splunk charset"
    elif kind in ("splunk_results", "splunk_job", "splunk_saved_search_read", "es_info") and (
            "search" in params or req.get("form") or req.get("json")):
        return "policy: post-processing search / request body not allowed"
    return None


_SPL_SIDE_EFFECT_CMDS = frozenset({
    "delete", "outputlookup", "outputcsv", "outputtext", "collect", "mcollect", "meventcollect", "tscollect",
    "sendemail", "sendalert", "script", "run", "runshellscript", "dbxoutput", "dbxquery", "rest", "map",
    "savedsearch", "summaryindex", "sichart", "sitimechart", "sistats", "sitop", "sirare",
})


def _spl_segments(spl: str) -> list[str]:
    """Split SPL on '|' outside double quotes."""
    out, start, inq, esc = [], 0, False, False
    for i, c in enumerate(spl):
        if esc:
            esc = False
        elif c == "\\":
            esc = True
        elif c == '"':
            inq = not inq
        elif c == "|" and not inq:
            out.append(spl[start:i])
            start = i + 1
    out.append(spl[start:])
    return out


def splunk_saved_search_lint(spl: Any, arg: str = "value") -> list[str]:
    """C2/C3 defence in depth over an approved saved-search definition: the ``$args.<arg>$`` token is
    used, always inside double quotes and never in a subsearch, no side-effect or chaining command
    (delete, outputlookup, collect, sendemail, map, rest...) and the search ends in ``stats count`` so
    no raw events come back. Returns the problems ([] = clean)."""
    s = _as_text(spl, 100_000)
    token = f"$args.{arg}$"
    problems: list[str] = []
    if token not in s:
        problems.append(f"token {token} not used")
    i = s.find(token)
    while i >= 0:
        before = s[:i].replace('\\"', "")
        if before.count('"') % 2 == 0:
            problems.append(f"token {token} used outside double quotes at offset {i}")
        if before.count("[") > before.count("]"):
            problems.append(f"token {token} used inside a subsearch at offset {i}")
        i = s.find(token, i + 1)
    segs = _spl_segments(s)
    for seg in segs:
        cmd = (seg.strip().split(None, 1) or [""])[0].lower()
        if cmd in _SPL_SIDE_EFFECT_CMDS:
            problems.append(f"side-effect or chaining command not allowed: {cmd}")
    last = segs[-1].strip().lower() if len(segs) > 1 else ""
    if not re.match(r"^(stats|tstats)\b.*\bcount\b", last):
        problems.append("does not end in stats count (raw events would be returned)")
    return problems


# ======================================================================================
# C4: answers (every marker means "could not verify")
# ======================================================================================


def _es_error(doc: Any) -> tuple[str | None, str | None]:
    if not isinstance(doc, dict):
        return None, None
    err = doc.get("error")
    if isinstance(err, str):
        return None, err
    if isinstance(err, dict):
        etype = err.get("type") if isinstance(err.get("type"), str) else None
        reason = err.get("reason") if isinstance(err.get("reason"), str) else None
        rc = err.get("root_cause")
        if (not etype or not reason) and isinstance(rc, list) and rc and isinstance(rc[0], dict):
            etype = etype or (rc[0].get("type") if isinstance(rc[0].get("type"), str) else None)
            reason = reason or (rc[0].get("reason") if isinstance(rc[0].get("reason"), str) else None)
        return etype, reason
    return None, None


def es_error_marker(status: Any, body: Any, content_type: str | None = None) -> str | None:
    """Classify an OpenSearch/Elasticsearch answer. None = usable. 401 -> needs_key; 429 / rejected
    execution / circuit breaker -> rate_limited; 408/504 and ``timed_out: true`` in a 200 -> timeout;
    an HTML page (SSO or reverse proxy) -> login_wall; 403/404/400/5xx, shard failures, error objects,
    malformed JSON or a missing hit count -> error."""
    st = _to_int(status)
    if _looks_like_html(body, content_type):
        if st in (None, 200, 302, 401, 403):
            return "login_wall: HTML page instead of JSON (SSO or reverse proxy in front of the SIEM)"
        return f"error: HTML error page from the SIEM (HTTP {st})"
    doc = _as_json(body)
    etype, ereason = _es_error(doc)
    detail = _short(f"{etype + ': ' if etype else ''}{ereason or ''}", 160)
    if st == 401:
        text = _short(_as_text(body), 60) if doc is None else detail
        return "needs_key: SIEM rejected the read-only token (HTTP 401" + (f": {text}" if text else "") + ")"
    if st == 429 or etype in ("es_rejected_execution_exception", "circuit_breaking_exception", "too_many_requests"):
        return f"rate_limited: SIEM is shedding load ({detail or f'HTTP {st}'})"
    if st in (408, 504) or etype in ("timeout_exception", "search_timeout_exception"):
        return f"timeout: SIEM search timed out ({detail or f'HTTP {st}'})"
    if st == 403:
        return "error: permission denied for the read-only account (HTTP 403" + (f": {detail}" if detail else "") + ")"
    if st == 404:
        return "error: index pattern or endpoint not found (HTTP 404" + (f": {detail}" if detail else "") + ")"
    if st is not None and st >= 400:
        return f"error: HTTP {st}" + (f": {detail}" if detail else "")
    if doc is None:
        return "error: malformed JSON from the SIEM"
    if not isinstance(doc, dict):
        return "error: unexpected JSON from the SIEM"
    if doc.get("error"):
        return f"error: {detail or 'error object in a 200 answer'}"
    if doc.get("timed_out") is True:
        return "timeout: search timed out on the cluster (partial result not used)"
    shards = doc.get("_shards") if isinstance(doc.get("_shards"), dict) else {}
    failed = _to_int(shards.get("failed")) or 0
    if failed > 0:
        return f"error: {failed} of {shards.get('total', '?')} shards failed (partial result not used)"
    hits = doc.get("hits") if isinstance(doc.get("hits"), dict) else {}
    total = hits.get("total")
    if _to_int(total) is None and not (isinstance(total, dict) and _to_int(total.get("value")) is not None):
        return "error: no hit count in the answer"
    return None


def _agg_ts(aggs: Any, name: str) -> str | None:
    a = aggs.get(name) if isinstance(aggs, dict) else None
    if not isinstance(a, dict):
        return None
    if isinstance(a.get("value_as_string"), str):
        got = parse_ts(a["value_as_string"])
        if got:
            return got
    return _iso_from_epoch(a.get("value"), unit="ms") if a.get("value") is not None else None


def parse_es_search(body: Any) -> dict[str, Any]:
    """Facts of a usable ``_search`` answer -> ``{count, count_capped, first_seen, last_seen, took_ms}``.
    ``hits.total`` as an object (value/relation) or an integer; min/max with or without
    ``value_as_string``. Documents are never read (any ``hits.hits`` content is ignored: no raw events)."""
    doc = _as_json(body)
    doc = doc if isinstance(doc, dict) else {}
    hits = doc.get("hits") if isinstance(doc.get("hits"), dict) else {}
    total = hits.get("total")
    capped = False
    if isinstance(total, dict):
        count = _to_int(total.get("value"))
        capped = total.get("relation") == "gte"
    else:
        count = _to_int(total)
    if count is not None and count < 0:
        count = None
    aggs = doc.get("aggregations") if isinstance(doc.get("aggregations"), dict) else {}
    first, last = _agg_ts(aggs, "first_seen"), _agg_ts(aggs, "last_seen")
    if count == 0:
        first = last = None
    return {"count": count, "count_capped": capped, "first_seen": first, "last_seen": last, "took_ms": _to_int(doc.get("took"))}


def _splunk_messages(doc: Any) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    msgs = doc.get("messages") if isinstance(doc, dict) else None
    if isinstance(msgs, dict):  # job content keys messages by level
        for lvl, items in msgs.items():
            for item in items if isinstance(items, list) else [items]:
                out.append((str(lvl).upper(), _short(item, 300)))
    elif isinstance(msgs, list):
        for m in msgs:
            if isinstance(m, dict):
                out.append((str(m.get("type") or "").upper(), _short(m.get("text"), 300)))
            elif isinstance(m, str):
                out.append(("", _short(m, 300)))
    return out


def splunk_error_marker(status: Any, body: Any, content_type: str | None = None) -> str | None:
    """Classify a Splunk REST answer (dispatch, job, results, definition). None = usable. 401 ->
    needs_key; 429/503 with a concurrency or quota message -> rate_limited; HTML -> login_wall;
    403/404/other HTTP errors, ERROR/FATAL messages in a 2xx, non-JSON bodies (except the documented
    XML dispatch answer) -> error."""
    st = _to_int(status)
    if _looks_like_html(body, content_type):
        if st in (None, 200, 302, 401, 403):
            return "login_wall: HTML page instead of a Splunk REST answer"
        return f"error: HTML error page from Splunk (HTTP {st})"
    doc = _as_json(body)
    msgs = _splunk_messages(doc)
    first = next((t for lvl, t in msgs if lvl in ("ERROR", "FATAL")), None) or (msgs[0][1] if msgs else "")
    text_all = " ".join(t for _, t in msgs).lower()
    if st == 401:
        return "needs_key: Splunk rejected the token (HTTP 401" + (f": {_short(first, 120)}" if first else "") + ")"
    if st in (429, 503) and (st == 429 or any(k in text_all for k in ("concurren", "quota", "maximum number", "queued"))):
        return f"rate_limited: Splunk search quota reached ({_short(first, 160) or f'HTTP {st}'})"
    if st == 403:
        return "error: permission denied for the read-only account (HTTP 403" + (f": {_short(first, 160)}" if first else "") + ")"
    if st == 404:
        return "error: saved search or job not found (HTTP 404" + (f": {_short(first, 160)}" if first else "") + ")"
    if st is not None and st >= 400:
        return f"error: HTTP {st}" + (f": {_short(first, 160)}" if first else "")
    if doc is None:
        if re.search(r"<sid>[^<]{1,256}</sid>", _as_text(body, 65536)):
            return None
        return "error: malformed answer from Splunk"
    if any(lvl in ("ERROR", "FATAL") for lvl, _ in msgs):
        return f"error: {_short(first, 200)}"
    return None


def parse_splunk_dispatch(body: Any) -> str | None:
    """Search id from the dispatch answer (JSON ``{sid}`` or the documented XML ``<response><sid>``),
    only when it passes the strict sid charset (it is later used in URL paths)."""
    doc = _as_json(body)
    sid = doc.get("sid") if isinstance(doc, dict) else None
    if sid is None and doc is None:
        m = re.search(r"<sid>\s*([^<\s]{1,256})\s*</sid>", _as_text(body, 65536))
        sid = m.group(1) if m else None
    return sid if splunk_sid_ok(sid) else None


_SPLUNK_CANCEL_STATES = frozenset({"INTERNAL_CANCEL", "USER_CANCEL", "BAD_INPUT_CANCEL", "QUIT"})


def parse_splunk_job(body: Any) -> dict[str, Any]:
    """Job status (``entry[0].content``) -> ``{state, done, failed, finalized, zombie, messages}``."""
    doc = _as_json(body)
    entry = (doc.get("entry") or [None])[0] if isinstance(doc, dict) and isinstance(doc.get("entry"), list) else None
    c = entry.get("content") if isinstance(entry, dict) and isinstance(entry.get("content"), dict) else {}

    def flag(name: str) -> bool:
        v = c.get(name)
        return v is True or (isinstance(v, (int, str)) and not isinstance(v, bool) and str(v).strip().lower() in ("1", "true"))

    return {"state": c.get("dispatchState") if isinstance(c.get("dispatchState"), str) else None,
            "done": flag("isDone"), "failed": flag("isFailed"), "finalized": flag("isFinalized"),
            "zombie": flag("isZombie"), "messages": _splunk_messages(c)}


def splunk_job_marker(job: dict[str, Any], waited_s: Any = 0.0, budget_s: Any = None) -> str | None:
    """Failure markers of a polled job (None = keep polling or done). failed/zombie/cancelled -> error;
    finalized before completion (dispatch.max_time) -> timeout (partial counts are never used); still
    QUEUED when the budget is spent -> rate_limited (search quota); still running -> timeout."""
    if not isinstance(job, dict):
        return "error: no job status"
    state = (job.get("state") or "").upper()
    msgs = job.get("messages") or []
    first = next((t for lvl, t in msgs if lvl in ("ERROR", "FATAL")), None) or (msgs[0][1] if msgs else "")
    if job.get("failed") or state == "FAILED":
        return "error: Splunk search failed" + (f": {_short(first, 160)}" if first else "")
    if job.get("zombie"):
        return "error: Splunk search process died (zombie job)"
    if state in _SPLUNK_CANCEL_STATES:
        return f"error: Splunk job cancelled ({state})"
    if job.get("finalized"):
        return "timeout: Splunk search finalized before completion (time limit): partial counts not used"
    if job.get("done") and state in ("DONE", ""):
        return None
    budget = effective_timeout(budget_s)
    if (_to_float(waited_s) or 0.0) >= budget:
        if state == "QUEUED":
            return f"rate_limited: Splunk search still queued by the search quota after {int(budget)}s"
        return f"timeout: Splunk search not done within {int(budget)}s"
    return None


_RESULT_FIELDS = ("count", "first_seen", "last_seen", "index")


def parse_splunk_results(body: Any) -> dict[str, Any]:
    """Results of the saved-search contract (``| stats count min(_time) as first_seen max(_time) as
    last_seen [by index]``) -> ``{count, count_capped, first_seen, last_seen, index_patterns, rows,
    partial, dropped_fields}``. Only contract columns are read: any other column (host, user, _raw...)
    is dropped and only its NAME is reported, so internal hostnames/usernames never leave this parser."""
    doc = _as_json(body)
    doc = doc if isinstance(doc, dict) else {}
    rows = doc.get("results") if isinstance(doc.get("results"), list) else []
    total, first, last, n = 0, None, None, 0
    indexes: list[str] = []
    dropped: set[str] = set()
    have_count = False
    for r in rows:
        if not isinstance(r, dict):
            continue
        n += 1
        dropped.update(str(k)[:64] for k in r if k not in _RESULT_FIELDS)
        c = _to_int(r.get("count"))
        if c is not None and c >= 0:
            total += c
            have_count = True
        f, la = parse_ts(r.get("first_seen")), parse_ts(r.get("last_seen"))
        if f and (first is None or f < first):
            first = f
        if la and (last is None or la > last):
            last = la
        idx = r.get("index")
        if isinstance(idx, str) and idx and idx not in indexes and len(idx) <= 128 and re.fullmatch(r"[A-Za-z0-9_.:-]+", idx):
            indexes.append(idx)
    msgs = _splunk_messages(doc)
    partial = any(lvl in ("WARN", "ERROR", "FATAL") and re.search(r"incomplete|partial|ended prematurely|truncat", t, re.I) for lvl, t in msgs)
    count = total if have_count else (0 if rows == [] and "results" in doc else None)
    if count == 0:
        first = last = None
    return {"count": count, "count_capped": False, "first_seen": first, "last_seen": last, "index_patterns": indexes,
            "rows": n, "partial": partial, "dropped_fields": sorted(dropped)}


def splunk_results_marker(body: Any) -> str | None:
    """Error-in-200 markers of a results answer: ERROR/FATAL messages -> error; 'results might be
    incomplete' warnings -> error (partial: could not verify); no ``count`` column -> error."""
    doc = _as_json(body)
    if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
        return "error: malformed Splunk results"
    msgs = _splunk_messages(doc)
    bad = next((t for lvl, t in msgs if lvl in ("ERROR", "FATAL")), None)
    if bad:
        return f"error: {_short(bad, 200)}"
    parsed = parse_splunk_results(doc)
    if parsed["partial"]:
        warn = next((t for lvl, t in msgs if lvl == "WARN"), "partial results")
        return f"error: partial results ({_short(warn, 160)})"
    if parsed["count"] is None:
        return "error: saved search output has no count column (template contract)"
    return None


# ======================================================================================
# C4/C5: the internal sighting and the report line
# ======================================================================================


def make_sighting(facts: dict[str, Any], *, backend: str, template: dict[str, Any], entity_type: str, queried_at: str,
                  window_days: Any = None) -> dict[str, Any]:
    """Normalised internal sighting (A12): counts and first/last seen, index patterns, window, template id
    and version, backend. No raw events and no pivots by construction."""
    facts = facts or {}
    count = _to_int(facts.get("count"))
    idx = list(facts.get("index_patterns") or []) or list((template or {}).get("index_patterns") or [])
    if not idx and (template or {}).get("index_pattern"):
        idx = [template["index_pattern"]]
    sighting = {
        "backend": backend, "template_id": (template or {}).get("id"), "template_version": (template or {}).get("version"),
        "index_patterns": idx, "window_days": effective_window(window_days), "count": count,
        "count_capped": bool(facts.get("count_capped")), "first_seen": facts.get("first_seen"), "last_seen": facts.get("last_seen"),
        "seen": bool(count), "queried_at": queried_at, "personal": (entity_type or "").lower() in PERSONAL_TYPES,
    }
    sighting["line"] = summary_line(sighting)
    return sighting


def summary_line(sighting: dict[str, Any] | None, reason: str | None = None) -> str:
    """C4: 'seen in our logs: N events, first <date>, last <date> (last 30 days, <index patterns>)',
    'not seen in our logs (...)' or 'SIEM: could not verify (<reason>)'."""
    if reason or not sighting or sighting.get("count") is None:
        return f"SIEM: could not verify ({_short(reason or 'no count', 160)})"
    scope = f"last {sighting.get('window_days', DEFAULT_WINDOW_DAYS)} days"
    if sighting.get("index_patterns"):
        scope += ", " + ", ".join(sighting["index_patterns"])
    n = sighting["count"]
    if n == 0:
        return f"not seen in our logs ({scope})"
    capped = bool(sighting.get("count_capped"))
    events = f"{n}{'+' if capped else ''} event{'' if n == 1 and not capped else 's'}"
    first = (sighting.get("first_seen") or "?")[:10]
    last = (sighting.get("last_seen") or "?")[:10]
    return f"seen in our logs: {events}, first {first}, last {last} ({scope})"


# ======================================================================================
# C6/C7: covert flag, personal identifiers, query log
# ======================================================================================


def covert_refusal(options: Any) -> str | None:
    """C7 (P348 C8): a covert red-team case skips every internal lookup, the SIEM included (the SOC
    would see the red team's infrastructure in its query logs)."""
    if getattr(options, "covert", False) or getattr(options, "no_internal", False):
        return COVERT_REASON
    return None


def _fold(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c)).lower()


def lookup_refusal(entity_type: str, case: dict[str, Any]) -> str | None:
    """C6 (A12, AR16, LGPD): None when the lookup may run, else 'privacy: ...'. E-mail, username and
    user agent are searched only for analyst-typed seeds of a case with an id, an analyst, a recorded
    purpose and a ticket, and never for a purpose that reads as HR or performance monitoring."""
    if (entity_type or "").lower() not in PERSONAL_TYPES:
        return None
    if not case.get("is_seed"):
        return f"privacy: SIEM search of a {entity_type} runs only for an analyst-typed seed (never for a pivot)"
    need = [k for k in ("case_id", "analyst", "purpose", "ticket") if not str(case.get(k) or "").strip()]
    if need:
        return (f"privacy: SIEM search of a {entity_type} needs a case with a recorded incident purpose and ticket "
                f"(missing: {', '.join(need)}; company monitoring policy, P349 C6)")
    purpose = _fold(str(case.get("purpose")))
    if any(re.search(p, purpose) for p in HR_PURPOSE_PATTERNS):
        return "privacy: SIEM searches of people are never used for HR or performance purposes (P349 C6)"
    return None


def audit_record(*, analyst: str, case_id: str, ticket: str, backend: str, template_id: Any, template_version: Any,
                 entity_type: str, value_ref: str, outcome: str, queried_at: str) -> dict[str, Any]:
    """C6 query log entry (analyst + case id). ``value_ref`` must be the 12-hex keyed HMAC of the value
    (A4): a raw value is refused so it can never be logged by mistake."""
    if not isinstance(value_ref, str) or not re.fullmatch(r"[0-9a-f]{12}", value_ref):
        raise ValueError("value_ref must be the 12-hex HMAC of the value, never the value itself")
    return {"event": "siem_query", "analyst": analyst or "?", "case_id": case_id or "", "ticket": ticket or "",
            "backend": backend, "template_id": template_id, "template_version": template_version,
            "entity_type": entity_type, "value_ref": value_ref, "outcome": outcome, "queried_at": queried_at}


# ======================================================================================
# configuration: base URL and template file
# ======================================================================================


def base_url(value: Any) -> tuple[str | None, str]:
    """(base URL without a trailing slash, '') for a valid https URL setting; else (None, problem)."""
    raw = str(value or "").strip()
    if not raw:
        return None, f"setting {URL_SETTING} is not set: the read-only SIEM adapter is disabled (v3lum config set {URL_SETTING} https://...)"
    try:
        parts = urlsplit(raw)
        _ = parts.port
    except ValueError:
        return None, f"setting {URL_SETTING} is not a valid URL"
    if parts.scheme != "https" or not parts.hostname:
        return None, f"setting {URL_SETTING} must be an https URL (TLS verification is always on, A12)"
    if parts.username or parts.password or parts.query or parts.fragment:
        return None, f"setting {URL_SETTING} must not carry credentials, a query or a fragment"
    return raw.rstrip("/"), ""


_TEMPLATE_CACHE: OrderedDict[tuple[str, int, int], dict[str, Any]] = OrderedDict()
_TEMPLATE_LOCK = threading.Lock()


def load_templates(path_value: Any) -> tuple[dict[str, Any] | None, str]:
    """Read and validate the SOC-approved template file named by setting ``siem_search_templates``.
    Refused: missing setting, not a regular file, larger than 1 MB, group/world-writable (anyone could
    add a free-form template), invalid JSON or a fatal schema problem. Parsed once per file version."""
    raw = str(path_value or "").strip()
    if not raw:
        return None, (f"setting {TEMPLATES_SETTING} is not set: only SOC-approved, versioned templates run "
                      f"(schema {TEMPLATE_SCHEMA}; v3lum config set {TEMPLATES_SETTING} <file>)")
    path = Path(raw).expanduser()
    try:
        st = path.stat()
    except OSError:
        return None, f"template file {path.name} not found ({TEMPLATES_SETTING})"
    if not _stat.S_ISREG(st.st_mode):
        return None, f"template file {path.name} is not a regular file"
    if st.st_size > TEMPLATE_MAX_BYTES:
        return None, f"template file {path.name} is larger than 1 MB"
    if os.name == "posix" and st.st_mode & (_stat.S_IWGRP | _stat.S_IWOTH):
        return None, f"template file {path.name} is group/world-writable: make it 0600 or a team read-only file"
    key = (str(path.resolve()), int(st.st_mtime_ns), int(st.st_size))
    with _TEMPLATE_LOCK:
        hit = _TEMPLATE_CACHE.get(key)
    if hit is not None:
        return hit, ""
    try:
        with open(path, "rb") as fh:
            doc = json.loads(fh.read(TEMPLATE_MAX_BYTES + 1).decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return None, f"template file {path.name} is not valid JSON ({type(exc).__name__})"
    spec = validate_templates(doc)
    if spec["fatal"]:
        return None, f"template file {path.name} refused: " + "; ".join(spec["errors"][:3])
    with _TEMPLATE_LOCK:
        _TEMPLATE_CACHE[key] = spec
        while len(_TEMPLATE_CACHE) > 8:
            _TEMPLATE_CACHE.popitem(last=False)
    return spec, ""


# ---- C4: at most 20 queries per scan (counted per case id) ---------------------------
_RUN_BUDGET: OrderedDict[str, int] = OrderedDict()
_RUN_BUDGET_LOCK = threading.Lock()


def reserve_query(case_id: str, cap: int) -> bool:
    """Take one query from the scan's budget (``cap`` <= 20). A run without a case id (``v3lum run``)
    is a single query and is not counted."""
    if not case_id:
        return True
    with _RUN_BUDGET_LOCK:
        used = _RUN_BUDGET.get(case_id, 0)
        if used >= cap:
            return False
        _RUN_BUDGET[case_id] = used + 1
        _RUN_BUDGET.move_to_end(case_id)
        while len(_RUN_BUDGET) > 256:
            _RUN_BUDGET.popitem(last=False)
    return True


def _analyst(ctx: Any) -> str:
    name = str(ctx.setting("analyst") or "").strip()
    if name:
        return name[:80]
    try:
        return getpass.getuser()[:80]
    except Exception:  # noqa: BLE001 - no OS user name available
        return ""


class _Failed(Exception):
    """A SIEM answer that means 'could not verify' (carries the marker text)."""

    def __init__(self, marker: str) -> None:
        super().__init__(marker)
        self.marker = marker


_MARKER_STATUS = {
    "needs_key": ("needs_key", "needs_key"),
    "rate_limited": ("rate_limited", "rate_limited"),
    "timeout": ("error", "timeout"),
    "login_wall": ("blocked", "login_wall"),
    "policy": ("skipped", "policy"),
    "config": ("skipped", "config"),
    "not_applicable": ("skipped", "not_applicable"),
    "privacy": ("skipped", "privacy"),
}


def status_for_marker(marker: str) -> tuple[str, str]:
    """(status, reason_code) of a marker/refusal; anything unknown is error/error (could not verify)."""
    return _MARKER_STATUS.get(reason_code(marker) or "", ("error", "error"))


# ======================================================================================
# the module
# ======================================================================================


@register
class SiemSearch(Module):
    name = "siem_search"
    title = "Internal SIEM look-back (SOC-approved saved searches)"
    description = (
        "Did this touch us? Counts and first/last seen of an IOC (or, inside an incident case, a personal "
        "identifier) in the team's primary SIEM, through SOC-approved term queries on OpenSearch/Elasticsearch "
        "or approved Splunk saved searches; no raw events."
    )
    category = "cti_framework"
    accepts = {T.IPV4, T.IPV6, T.DOMAIN, T.URL, T.EMAIL, T.MD5, T.SHA256, T.USERNAME, T.USER_AGENT}
    produces = frozenset()
    tags = {"internal"}
    reference = "https://opensearch.org/docs/latest/api-reference/search/"
    notice = (
        "Company-operated primary SIEM only (disclosure 'internal', allowed at TLP:RED), read-only service account, "
        "SOC-approved versioned templates only. E-mail, username and user-agent searches run only for analyst-typed "
        "seeds of a case with a recorded incident purpose and ticket, under the company's monitoring policy and "
        "privacy notice; never for HR or performance purposes. Queries are logged with analyst and case id; results "
        "follow the case retention."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "internal"
    hosts = ()  # the host comes only from setting siem_url (provider hosts_from_settings)
    provider = PROVIDER
    sources = (SOURCE,)
    access_model = "internal"
    requires_keys = (KEY_NAME,)
    max_requests = 11  # Splunk: daily definition lint + dispatch + <= 8 polls + results (ES: 1)
    expected_latency = 5.0  # ES ~1.5 s, Splunk dispatch + polling ~5 s
    timeout = MAX_TIMEOUT  # never above 30 s (A12); the per-query budget is siem_search_timeout (15 s)
    min_interval = MIN_INTERVAL
    daily_quota = 500  # soft guard for the production SIEM (requests per day)
    cache_ttl = 0  # counts change; personal-identifier queries never reach http_cache.db
    max_pivots = 0  # internal hostnames and usernames are never auto-pivoted (C5)
    default_enabled = False  # P349: opt-in (A12 internal platforms disabled unless configured)
    settings = {
        URL_SETTING: SettingSpec("", "company primary SIEM base URL (https; OpenSearch/Elasticsearch REST or Splunk management port); the read-only adapter is disabled while empty"),
        TEMPLATES_SETTING: SettingSpec("", f"path of the SOC-approved, versioned template file (schema {TEMPLATE_SCHEMA}; 0600 or a team read-only path)"),
        "siem_search_auth_scheme": SettingSpec("ApiKey", "Authorization scheme for OpenSearch/Elasticsearch (Splunk always uses Bearer)", ("ApiKey", "Bearer", "Basic")),
        "siem_search_window_days": SettingSpec(DEFAULT_WINDOW_DAYS, "look-back window in days (default 30; capped at 90)"),
        "siem_search_timeout": SettingSpec(DEFAULT_TIMEOUT, "per-query timeout in seconds (default 15; never above 30)"),
        "siem_search_max_queries": SettingSpec(MAX_QUERIES_PER_SCAN, "SIEM queries per scan (at most 20)"),
        "siem_search_splunk_results_api": SettingSpec("v2", "Splunk results endpoint: v2 (Splunk >= 9) or v1", ("v2", "v1")),
        "siem_search_tlp": SettingSpec("amber+strict", "minimum TLP marking of SIEM sightings (internal telemetry stays inside the organisation)", TLP_CHOICES),
    }

    # ---- run ---------------------------------------------------------------------------
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        refusal = covert_refusal(ctx.options)
        if refusal:
            return res.mark("skipped", refusal, reason_code="policy")
        base, problem = base_url(ctx.setting(URL_SETTING))
        if base is None:
            return res.mark("skipped", problem, reason_code="config")
        key = ctx.key(KEY_NAME)
        if not key:
            return res.mark("needs_key", f"needs the SIEM key '{KEY_NAME}' of a read-only service account (v3lum keys)", reason_code="needs_key")
        spec, problem = load_templates(ctx.setting(TEMPLATES_SETTING))
        if spec is None:
            return res.mark("skipped", problem, reason_code="config")
        etype = entity.type.value
        analyst = _analyst(ctx)
        case = {"is_seed": ctx.is_seed, "case_id": ctx.case_id, "analyst": analyst, "purpose": ctx.purpose,
                "ticket": getattr(ctx.options, "ticket", "")}
        refusal = lookup_refusal(etype, case)
        if refusal:
            return res.mark("skipped", _reason_text(refusal), reason_code="privacy")
        backend = spec["backend"]
        template = select_template(spec, etype)
        if template is None:
            return res.mark("skipped", f"no SOC-approved {backend} template covers {etype} (template file v{spec['version']})", reason_code="not_applicable")
        budget = effective_timeout(ctx.setting("siem_search_timeout"))
        window = effective_window(ctx.setting("siem_search_window_days"))
        if backend == "splunk":
            req, why = build_splunk_dispatch(template, etype, entity.value, window_days=window, timeout_s=budget)
        else:
            req, why = build_es_search(template, etype, entity.value, window_days=window, timeout_s=budget)
        if req is None:
            status, code = status_for_marker(why or "error: request not built")
            return res.mark(status, _reason_text(why or "request not built"), reason_code=code)
        cap = max(1, min(_to_int(ctx.setting("siem_search_max_queries")) or MAX_QUERIES_PER_SCAN, MAX_QUERIES_PER_SCAN))
        if not reserve_query(ctx.case_id, cap):
            return res.mark("quota", f"SIEM look-back budget of {cap} queries per scan reached: not searched (could not verify)", reason_code="quota")

        queried_at = ctx.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        log_base = {"analyst": analyst, "case_id": ctx.case_id, "ticket": case["ticket"], "backend": backend,
                    "template_id": template.get("id"), "template_version": template.get("version"),
                    "entity_type": etype, "value_ref": hmacid.hmac12(entity.type, entity.value), "queried_at": queried_at}
        raw: dict[str, Any] = {"backend": backend, "template_id": template.get("id"), "template_version": template.get("version"),
                               "template_file_version": spec["version"], "approved_by": spec.get("approved_by"),
                               "index_patterns": req.get("index_patterns"), "window_days": window, "timeout_s": budget}
        res.raw = raw
        try:
            if backend == "splunk":
                facts = self._splunk(ctx, base, key, template, req, budget, raw)
            else:
                facts = self._es(ctx, base, key, req, budget, raw)
        except _Failed as failed:
            raw["query_log"] = audit_record(outcome=f"could not verify: {reason_code(failed.marker)}", **log_base)
            self._log(ctx, raw["query_log"])
            status, code = status_for_marker(failed.marker)
            line = summary_line(None, _reason_text(failed.marker))
            return res.mark(status, line, reason_code=code)
        sighting = make_sighting(facts, backend=backend, template=template, entity_type=etype, queried_at=queried_at, window_days=window)
        raw["query_log"] = audit_record(outcome="seen" if sighting["seen"] else "not seen", **log_base)
        raw["count"], raw["count_capped"] = sighting["count"], sighting["count_capped"]
        self._log(ctx, raw["query_log"])
        res.attr("siem_sighting", sighting)
        res.set_marking(str(ctx.setting("siem_search_tlp") or "amber+strict"))
        if not sighting["seen"]:
            return res.mark("empty", sighting["line"])
        res.attr("internal_sightings", [{"platform": "siem", "ref": f"SIEM {template.get('id')}", "org": None, "tlp": None,
                                         "date": (sighting["last_seen"] or "")[:10] or None, "verdict": "observed"}])
        res.finding(
            "Seen in our logs (SIEM)",
            "info",
            sighting["line"] + ". Counts from the organisation's own telemetry: a fact about our logs, not a verdict about the value.",
            confidence="confirmed",
            criterion=f"exact term match in SOC-approved template {template.get('id')} v{template.get('version')} ({backend}), last {window} days",
            data={k: sighting[k] for k in ("backend", "template_id", "template_version", "index_patterns", "window_days", "count",
                                           "count_capped", "first_seen", "last_seen", "queried_at")},
            tags=["internal_sighting", "seen_in_logs"],
            source=SOURCE,
            observed_first=sighting["first_seen"],
            observed_last=sighting["last_seen"],
            key="siem",
        )
        return res

    # ---- backends --------------------------------------------------------------------------
    def _auth(self, ctx: Any, key: str, backend: str) -> dict[str, str]:
        scheme = "Bearer" if backend == "splunk" else str(ctx.setting("siem_search_auth_scheme") or "ApiKey")
        if scheme not in ("ApiKey", "Bearer", "Basic"):
            scheme = "ApiKey"
        return {"Authorization": f"{scheme} {key}"}

    def _send(self, ctx: Any, base: str, key: str, backend: str, req: dict[str, Any], timeout: float) -> Any:
        """One request after the read-only allow-list check (a refusal is a policy stop, never sent)."""
        problem = request_allowed(req)
        if problem:
            raise PolicyError("policy", f"{self.name}: refused {req.get('method')} {req.get('path')}: {_reason_text(problem)}")
        url = base + req["path"]
        kw: dict[str, Any] = {"headers": self._auth(ctx, key, backend), "timeout": timeout, "source": SOURCE}
        if req.get("params"):
            kw["params"] = dict(req["params"])
        if req.get("min_interval"):
            kw["min_interval"] = float(req["min_interval"])
        if req["method"] == "GET":
            return ctx.http.get(url, **kw)
        if "json" in req:
            return ctx.http.post(url, json_body=req["json"], **kw)
        return ctx.http.post(url, data=dict(req.get("form") or {}), **kw)

    def _es(self, ctx: Any, base: str, key: str, req: dict[str, Any], budget: float, raw: dict[str, Any]) -> dict[str, Any]:
        resp = self._send(ctx, base, key, "elasticsearch", req, budget)
        marker = es_error_marker(resp.status, resp.content, resp.headers.get("content-type"))
        if marker:
            raise _Failed(marker)
        facts = parse_es_search(resp.content)
        raw["took_ms"] = facts.get("took_ms")
        return facts

    def _splunk(self, ctx: Any, base: str, key: str, saved: dict[str, Any], req: dict[str, Any], budget: float, raw: dict[str, Any]) -> dict[str, Any]:
        lint = self._lint(ctx, base, key, saved)
        raw["definition_lint"] = lint
        if lint.get("problems"):
            raise _Failed(f"config: saved search {saved.get('name')} failed the safety lint ({'; '.join(lint['problems'][:3])}): not dispatched")
        resp = self._send(ctx, base, key, "splunk", req, budget)
        marker = splunk_error_marker(resp.status, resp.content, resp.headers.get("content-type"))
        if marker:
            raise _Failed(marker)
        sid = parse_splunk_dispatch(resp.content)
        if sid is None:
            raise _Failed("error: no valid search id in the Splunk dispatch answer")
        waited, job = 0.0, None
        for delay in splunk_poll_delays(budget):
            jreq, why = splunk_job_request(saved, sid)
            if jreq is None:
                raise _Failed(why or "error: invalid search id")
            jreq["min_interval"] = delay
            resp = self._send(ctx, base, key, "splunk", jreq, budget)
            waited += delay
            marker = splunk_error_marker(resp.status, resp.content, resp.headers.get("content-type"))
            if marker:
                raise _Failed(marker)
            job = parse_splunk_job(resp.content)
            marker = splunk_job_marker(job, waited, budget)
            if marker:
                raise _Failed(marker)
            if job.get("done"):
                break
        else:
            marker = splunk_job_marker(job or {}, budget, budget) or f"timeout: Splunk search not done within {int(budget)}s"
            raise _Failed(marker)
        raw["polls"] = round(waited, 1)
        rreq, why = splunk_results_request(saved, sid, api=str(ctx.setting("siem_search_splunk_results_api") or "v2"))
        if rreq is None:
            raise _Failed(why or "error: invalid search id")
        resp = self._send(ctx, base, key, "splunk", rreq, budget)
        marker = splunk_error_marker(resp.status, resp.content, resp.headers.get("content-type")) or splunk_results_marker(resp.content)
        if marker:
            raise _Failed(marker)
        facts = parse_splunk_results(resp.content)
        if facts.get("dropped_fields"):
            raw["dropped_fields"] = facts["dropped_fields"]  # names only: hostnames/usernames never kept
        return facts

    def _lint(self, ctx: Any, base: str, key: str, saved: dict[str, Any]) -> dict[str, Any]:
        """At most once a day per saved search and version (ctx.state): read the definition and lint it.
        A definition that cannot be read is recorded as 'not linted' (the strict charset still holds)."""
        host = (urlsplit(base).hostname or "").lower()
        state_key = f"lint:{host}:{saved.get('id')}:{saved.get('version')}"
        now = ctx.now()
        try:
            prev = ctx.state.get(state_key)
        except Exception:  # noqa: BLE001 - state is bookkeeping
            prev = None
        if isinstance(prev, dict):
            try:
                checked = datetime.fromisoformat(str(prev.get("checked_at")).replace("Z", "+00:00"))
            except ValueError:
                checked = None
            if checked is not None and now - checked <= LINT_TTL:
                return prev
        record: dict[str, Any] = {"checked_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "linted": False, "problems": []}
        try:
            resp = self._send(ctx, base, key, "splunk", splunk_definition_request(saved), min(5.0, effective_timeout(None)))
            marker = splunk_error_marker(resp.status, resp.content, resp.headers.get("content-type"))
            if marker:
                record["note"] = f"definition not readable ({reason_code(marker)})"
            else:
                doc = _as_json(resp.content)
                entry = (doc.get("entry") or [None])[0] if isinstance(doc, dict) and isinstance(doc.get("entry"), list) else None
                content = entry.get("content") if isinstance(entry, dict) and isinstance(entry.get("content"), dict) else {}
                if isinstance(content.get("search"), str):
                    record["linted"] = True
                    record["problems"] = splunk_saved_search_lint(content["search"], saved.get("arg") or "value")
                else:
                    record["note"] = "definition without a search string"
        except (HttpError, NetworkError) as exc:
            record["note"] = f"definition not readable ({type(exc).__name__})"
        try:
            ctx.state.set(state_key, record)
        except Exception:  # noqa: BLE001 - state is bookkeeping: never fails the lookup
            pass
        if record["problems"]:
            ctx.log(f"SIEM saved search {saved.get('name')} failed the safety lint: {'; '.join(record['problems'][:3])}", level="warning")
        return record

    @staticmethod
    def _log(ctx: Any, entry: dict[str, Any]) -> None:
        ctx.log(
            f"SIEM query {entry.get('template_id')} ({entry.get('backend')}) case {entry.get('case_id') or '-'} "
            f"analyst {entry.get('analyst') or '?'} value #{entry.get('value_ref')}: {entry.get('outcome')}"
        )

    # ---- health ------------------------------------------------------------------------------
    @classmethod
    def health_check(cls) -> HealthCheck:
        """Self-test for doctor / the keys wizard: reachability and token (no investigated value);
        Splunk saved-search definitions are linted."""
        return HealthCheck(offline=False, selftest=cls._selftest)

    @classmethod
    def _selftest(cls, ctx: Any) -> HealthResult:
        adapter = cls()
        base, problem = base_url(ctx.setting(URL_SETTING))
        if base is None:
            return HealthResult("dead", problem)
        key = ctx.key(KEY_NAME)
        if not key:
            return HealthResult("needs_key", f"key '{KEY_NAME}' is not configured")
        spec, problem = load_templates(ctx.setting(TEMPLATES_SETTING))
        if spec is None:
            return HealthResult("dead", problem)
        backend = spec["backend"]
        try:
            if backend != "splunk":
                resp = adapter._send(ctx, base, key, backend, {"method": "GET", "path": "/"}, 5.0)
                marker = None
                if resp.status >= 400 or _looks_like_html(resp.content, resp.headers.get("content-type")):
                    marker = es_error_marker(resp.status, resp.content, resp.headers.get("content-type")) or f"error: HTTP {resp.status}"
                elif not isinstance(_as_json(resp.content), dict):
                    marker = "error: unexpected cluster info answer"
                return _health_from_marker(marker, f"{backend} reachable, token accepted (templates v{spec['version']})")
            problems: list[str] = []
            for saved in list(spec["splunk"].values())[:5]:
                resp = adapter._send(ctx, base, key, backend, splunk_definition_request(saved), 5.0)
                marker = splunk_error_marker(resp.status, resp.content, resp.headers.get("content-type"))
                if marker:
                    return _health_from_marker(marker, "")
                doc = _as_json(resp.content)
                entry = (doc.get("entry") or [None])[0] if isinstance(doc, dict) and isinstance(doc.get("entry"), list) else None
                content = entry.get("content") if isinstance(entry, dict) and isinstance(entry.get("content"), dict) else {}
                problems += [f"{saved['name']}: {p}" for p in splunk_saved_search_lint(content.get("search"), saved.get("arg") or "value")]
        except (HttpError, NetworkError, PolicyError) as exc:
            return HealthResult("dead", f"SIEM: {type(exc).__name__}")
        if problems:
            return HealthResult("dead", "saved searches failed the safety lint: " + "; ".join(problems[:4]))
        return HealthResult("ok", f"splunk reachable, saved searches linted (templates v{spec['version']})")


def _health_from_marker(marker: str | None, ok_detail: str) -> HealthResult:
    if marker is None:
        return HealthResult("ok", ok_detail)
    code = reason_code(marker)
    status = {"needs_key": "needs_key", "rate_limited": "quota", "login_wall": "blocked"}.get(code or "", "dead")
    return HealthResult(status, _reason_text(marker))
