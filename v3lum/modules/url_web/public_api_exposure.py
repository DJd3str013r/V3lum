"""public_api_exposure: public API exposure of the organisation (P069, batch p3-G03-1).

Two sources, one aggregator (the policy gate hands it only the sources the licence profile allows):

* ``postman.public_search`` - Postman's public workspace / collection / request search
  (``POST https://www.postman.com/_api/ws/proxy``, an undocumented website API, terms ``unknown``):
  **disabled under every licence profile until legal records its terms** (A1); its public search
  page is the manual pivot link (pack ``public_api_exposure:postman_search``).
* ``apisguru.directory`` - the APIs.guru OpenAPI directory (CC0) downloaded daily as a dataset
  (``v3lum data update public_api_exposure.apisguru_list``) and matched **locally**: the target never
  reaches APIs.guru.

Final conditions implemented (P069):

* c1 - Postman search metadata only (workspace/collection/request name, publisher, location URL,
  request hosts tied to the target) plus the APIs.guru ``list.json`` matched locally as a daily
  dataset. No collection, environment or globals download exists in this file (deep mode: backlog).
* c2 - source terms ``unknown`` in the provider registry, so POL-04 keeps Postman out of
  ``ctx.allowed_sources`` under the corporate and research profiles; APIs.guru (``open``) runs
  normally. ``Module.manual_link`` and the pivot pack give the Postman public search page.
* c3 - Postman queries only for org_profile entries: an own domain (``ctx.org.owns``) or a brand
  term (``ctx.org.brand_terms``). Hits are kept only when tied to the organisation by a request host
  under an org domain or by the publisher (handle/name equal to a brand, or a brand token of it);
  name-only hits are discarded and counted (:func:`filter_postman_hits`).
* c4 - existence and location only: request URLs are shown with every query value replaced by
  ``***``, userinfo dropped and token-like path segments masked (:func:`postman_url_info`); secret
  *types* are named (query parameter names, userinfo password, distinctive token formats through
  ``v3lum.core.sanitize.find_secrets``), never values; nothing is used or replayed. Postman answers
  are never cached (POST without ``ttl``) and never stored raw; individual publishers lose their
  display name.
* c5 - 403 or a challenge page is BLOCKED (core classification, no bypass); an unexpected shape
  (HTML instead of JSON, no ``data`` list, items without a ``document``) is ERROR 'schema changed',
  never EMPTY; one query per entity, at most :data:`POSTMAN_MAX_PAGES` pages (``body.from += 25``)
  and at most :data:`POSTMAN_MAX_QUERIES_PER_CASE` queries per case (``ctx.state``), plus the
  provider's daily budget (P334).
* c6 - ``default_enabled = False``; bbot's Postman modules (AGPL-3.0) were not copied: the request
  was rebuilt from the research record.
* c7 - tests use the recorded ``postman_public_search.json`` and ``apisguru_metrics.json`` samples
  and schema-change cases (tests/modules/test_public_api_exposure.py).
"""

from __future__ import annotations

import html as _html
import json
import re
import threading
import unicodedata
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from v3lum.core import psl
from v3lum.core.datasets import DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, DeadlineExceeded, HttpError, NetworkError, OfflineError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, Module, register
from v3lum.core.orgprofile import fold as org_fold
from v3lum.core.sanitize import find_secrets

SOURCE_POSTMAN = "postman.public_search"
SOURCE_APISGURU = "apisguru.directory"

POSTMAN_SEARCH_URL = "https://www.postman.com/_api/ws/proxy"
POSTMAN_PAGE_SIZE = 25
POSTMAN_MAX_PAGES = 2  # c5: pagination (body.from += 25) bounded to 2 pages
POSTMAN_MAX_QUERIES_PER_CASE = 6  # c5: queries capped per scan (case)
POSTMAN_QUERY_INDICES = ("collaboration.workspace", "runtime.collection", "runtime.request")
POSTMAN_KNOWN_ENTITY_TYPES = frozenset({
    "workspace", "collection", "request", "extensibleCollection", "api", "flow", "environment", "mock", "team", "user",
    "document", "specification",
})
POSTMAN_FINDING_CAP = 25
STATE_CASE_KEY = "postman_case_queries"
STATE_CASES_KEPT = 20

APISGURU_LIST = "public_api_exposure.apisguru_list"
APISGURU_METRICS = "public_api_exposure.apisguru_metrics"
APISGURU_LIST_URL = "https://api.apis.guru/v2/list.json"
APISGURU_METRICS_URL = "https://api.apis.guru/v2/metrics.json"
APISGURU_MIN_ENTRIES = 1000  # live 2026-11-26: 2,529 entries; fewer = a broken or partial download
APISGURU_MATCH_CAP = 50
APISGURU_PIVOT_CAP = 25


# =============================================================================================== helpers
def decode_body(raw: Any) -> str:
    """bytes/str -> str (UTF-8 with replacement, a leading BOM removed); anything else -> ''."""
    if isinstance(raw, (bytes, bytearray)):
        text = bytes(raw).decode("utf-8", "replace")
    elif isinstance(raw, str):
        text = raw
    else:
        return ""
    return text[1:] if text.startswith("﻿") else text


def looks_like_html(text: Any) -> bool:
    """True when a body is an HTML document (block pages, SPA shells); JSON never qualifies."""
    head = decode_body(text)[:2048].lstrip().lower()
    if not head.startswith("<"):
        return False
    return head.startswith(("<!doctype html", "<html")) or any(t in head for t in ("<head", "<body", "<title"))


def load_json(raw: Any) -> tuple[Any, str | None]:
    """``(obj, None)`` or ``(None, reason)``: HTML/XML/garbage bodies are told apart (never 'empty')."""
    if isinstance(raw, (dict, list)):
        return raw, None
    if raw is None:
        return None, "empty body"
    text = decode_body(raw)
    if not text.strip():
        return None, "empty body"
    if looks_like_html(text):
        return None, "html instead of json"
    if text.lstrip()[:5].lower() == "<?xml":
        return None, "xml instead of json"
    try:
        return json.loads(text), None
    except (ValueError, RecursionError) as exc:
        return None, f"invalid json ({str(exc)[:80]})"


def host_of(url: Any) -> str:
    """Host of a URL or bare ``host[/path]`` string: lower case, no port/userinfo/trailing dot, IDNA.

    '' for empty or unparsable values and for Postman template hosts (``{{base_url}}/x``): a templated
    host is never a tie to the target (c3).
    """
    if not isinstance(url, str) or not url.strip():
        return ""
    u = url.strip()
    if "://" not in u:
        u = "http://" + u.lstrip("/")
    try:
        netloc = urllib.parse.urlsplit(u).netloc
    except ValueError:
        return ""
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    if "{" in netloc or "}" in netloc or netloc.startswith("["):
        return ""
    host = netloc.split(":", 1)[0].strip().rstrip(".").lower()
    if not host or any(c in host for c in " \t/\\<>\"'"):
        return ""
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""


def is_under(host: str, domain: str) -> bool:
    """Label-wise membership (``host == domain`` or a subdomain of it), never a string suffix."""
    if not host or not domain:
        return False
    h = host.lower().rstrip(".")
    d = domain.lower().rstrip(".")
    return h == d or h.endswith("." + d)


def _fold(text: Any) -> str:
    if not isinstance(text, str):
        return ""
    nfkd = unicodedata.normalize("NFKD", _html.unescape(text))
    return "".join(c for c in nfkd if not unicodedata.combining(c)).casefold()


def norm_token(text: Any) -> str:
    """Folded text with everything but [a-z0-9] removed ('Itaú Unibanco' -> 'itauunibanco')."""
    return re.sub(r"[^a-z0-9]", "", _fold(text))


def tokens(text: Any) -> list[str]:
    """Folded alphanumeric tokens ('cloudflare-r2' -> ['cloudflare', 'r2'])."""
    return [t for t in re.split(r"[^a-z0-9]+", _fold(text)) if t]


def _iso_age_days(value: Any, now: datetime) -> int | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now - dt).days


# ================================================================================================ Postman
_SECRET_PARAM_RE = re.compile(
    r"(?i)^(?:.*pass(?:word|wd)?|pwd|.*secret.*|.*token.*|.*api[-_]?key.*|apikey|key|.*access[-_]?key.*|"
    r"auth|authorization|sig|signature|session(?:id)?|jwt|.*private[-_]?key.*|.*credential.*|x-api-key)$")
_PATH_TOKEN_RE = re.compile(r"(?=[A-Za-z0-9_\-.]{20,200}$)(?=.*[0-9])(?=.*[A-Za-z])[A-Za-z0-9_\-.]+")
_BOT_TOKEN_RE = re.compile(r"bot\d{5,12}:[A-Za-z0-9_-]{30,40}")
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_KNOWN_TOKEN_RE = re.compile(r"(?:ghp_|gho_|ghu_|ghs_|github_pat_|glpat-|sk_live_|sk_test_|rk_live_|xox[abprs]-|AKIA|ASIA|AIza)[A-Za-z0-9_\-]{8,}")


def postman_search_body(query: str, page: int = 0) -> dict[str, Any]:
    """JSON body of one Postman public search page (c1, c5). No Origin/Referer is needed (verified live).

    Raises ValueError outside the bounded pagination (page 0 or 1) or for an empty/oversized query.
    """
    if not isinstance(query, str) or not query.strip() or len(query) > 200:
        raise ValueError("postman query must be a non-empty string of at most 200 characters")
    if not isinstance(page, int) or page < 0 or page >= POSTMAN_MAX_PAGES:
        raise ValueError(f"postman pagination is bounded to {POSTMAN_MAX_PAGES} pages (P069 cond 5)")
    return {
        "service": "search",
        "method": "POST",
        "path": "/search-all",
        "body": {
            "queryIndices": list(POSTMAN_QUERY_INDICES),
            "queryText": query.strip(),
            "size": POSTMAN_PAGE_SIZE,
            "from": page * POSTMAN_PAGE_SIZE,
            "clientTraceId": "",
            "requestOrigin": "srp",
            "mergeEntities": "true",
            "nonNestedRequests": "true",
            "domain": "public",
        },
    }


def _path_segment_secret(seg: str) -> tuple[bool, bool]:
    """(mask, hint): mask token-like path segments in the shown URL; hint only for likely credentials."""
    if not seg or "{{" in seg:
        return False, False
    if _BOT_TOKEN_RE.fullmatch(seg) or _KNOWN_TOKEN_RE.match(seg):
        return True, True
    if _UUID_RE.fullmatch(seg) or not _PATH_TOKEN_RE.fullmatch(seg):
        return False, False
    mixed = len(seg) >= 32 and any(c.isupper() for c in seg) and any(c.islower() for c in seg) and any(c.isdigit() for c in seg)
    return True, mixed


def postman_url_info(url: Any) -> dict[str, Any]:
    """Request URL metadata without values (c4): host, redacted URL (every query value ``***``,
    userinfo dropped, token-like path segments masked), variables flag and secret *types*."""
    empty = {"host": "", "redacted_url": "", "has_variables": False, "exposed_kinds": []}
    if not isinstance(url, str) or not url.strip():
        return empty
    raw = url.strip()[:4096]
    has_vars = "{{" in raw
    u = raw if "://" in raw else "http://" + raw.lstrip("/")
    try:
        parts = urllib.parse.urlsplit(u)
    except ValueError:
        return dict(empty, has_variables=has_vars)
    kinds: set[str] = set()
    netloc = parts.netloc
    if "@" in netloc:
        userinfo, netloc = netloc.rsplit("@", 1)
        if ":" in userinfo and "{{" not in userinfo.split(":", 1)[1]:
            kinds.add("url_userinfo_password")
    names: list[str] = []
    for pair in parts.query.split("&") if parts.query else []:
        name, _, value = pair.partition("=")
        name = urllib.parse.unquote_plus(name)[:200]
        names.append(name)
        if _SECRET_PARAM_RE.match(name) and value and "{{" not in value:
            kinds.add(f"query_param:{name.lower()}")
    query = "&".join(urllib.parse.quote(n, safe="-_.{}") + "=***" for n in names)
    segments: list[str] = []
    for seg in (parts.path or "").split("/"):
        mask, hint = _path_segment_secret(seg)
        segments.append("***" if mask else seg)
        if hint:
            kinds.add("path_token")
    for hit in find_secrets(raw, distinctive_only=True):  # known token formats (AWS, GitHub, Slack...): kind only
        kinds.add(str(hit.kind))
    host = host_of(u)
    scheme = parts.scheme if "://" in raw else ""
    shown_host = host or netloc.split(":", 1)[0]  # templated hosts are shown as written
    redacted = (f"{scheme}://" if scheme else "") + shown_host + "/".join(segments) + (("?" + query) if query else "")
    return {"host": host, "redacted_url": redacted[:500], "has_variables": has_vars, "exposed_kinds": sorted(kinds)}


def postman_location(doc: Any) -> str | None:
    """Public web location of a search hit (workspace / collection / request URL) - c4."""
    if not isinstance(doc, dict):
        return None
    handle = doc.get("publisherHandle")
    et = doc.get("entityType")
    if not isinstance(handle, str) or not handle.strip():
        return None
    base = "https://www.postman.com/" + urllib.parse.quote(handle.strip(), safe="-_.")
    if et == "workspace":
        slug = doc.get("slug")
        return base + "/workspace/" + urllib.parse.quote(slug, safe="-_.") if isinstance(slug, str) and slug else None
    ws_slug = doc.get("workspaceSlug")
    if not isinstance(ws_slug, str) or not ws_slug:
        ws = doc.get("workspaces")
        if isinstance(ws, list) and ws and isinstance(ws[0], dict):
            ws_slug = ws[0].get("slug")
    if not isinstance(ws_slug, str) or not ws_slug:
        return None
    ws_url = base + "/workspace/" + urllib.parse.quote(ws_slug, safe="-_.")
    obj_id = doc.get("id")
    if not isinstance(obj_id, str) or not obj_id:
        return ws_url
    if et in ("collection", "extensibleCollection"):
        return ws_url + "/collection/" + urllib.parse.quote(obj_id, safe="-_.")
    if et == "request":
        return ws_url + "/request/" + urllib.parse.quote(obj_id, safe="-_.")
    return ws_url


def _text(value: Any, limit: int = 200) -> str | None:
    return _html.unescape(value)[:limit] if isinstance(value, str) and value.strip() else None


def normalise_postman_hit(doc: dict[str, Any]) -> dict[str, Any]:
    """One search document -> metadata (c1, c4). Individual publishers (``publisherType == 'user'``)
    keep only their handle inside the location URL: the display name is dropped (A4)."""
    et = doc.get("entityType")
    ptype = doc.get("publisherType") if isinstance(doc.get("publisherType"), str) else None
    individual = ptype == "user"
    hit: dict[str, Any] = {
        "entity_type": et,
        "id": doc.get("id") if isinstance(doc.get("id"), str) else None,
        "name": _text(doc.get("name")),
        "publisher": {
            "handle": doc.get("publisherHandle") if isinstance(doc.get("publisherHandle"), str) else None,
            "name": None if individual else _text(doc.get("publisherName")),
            "type": ptype,
            "verified": doc.get("isPublisherVerified") is True,
            "individual": individual,
        },
        "location": postman_location(doc),
        "request": None,
    }
    if et == "request":
        info = postman_url_info(doc.get("url"))
        custom = doc.get("customHostName")
        extra = [host_of(h) for h in custom if isinstance(h, str)] if isinstance(custom, list) else []
        method = doc.get("method")
        hit["request"] = {
            "method": method if isinstance(method, str) and method else None,
            "host": info["host"],
            "extra_hosts": [h for h in extra if h],
            "redacted_url": info["redacted_url"],
            "has_variables": info["has_variables"],
            "exposed_kinds": info["exposed_kinds"],
        }
    return hit


def parse_postman_search(raw: Any) -> dict[str, Any]:
    """Postman ``/search-all`` body -> ``{status, reason, hits, totals, ...}`` before the target filter.

    ``data`` list -> ``ok`` (hits) or ``empty``; an unexpected shape (no ``data`` list, items without a
    ``document`` object, HTML/XML, broken JSON) -> ``error`` 'schema changed: ...', never ``empty`` (c5);
    an ``{"error": {...}}`` envelope -> ``error`` with the provider message.
    """
    obj, why = load_json(raw)
    if obj is None:
        return {"status": "error", "reason": f"schema changed: {why}", "hits": [], "totals": {}}
    if not isinstance(obj, dict):
        return {"status": "error", "reason": f"schema changed: top level is {type(obj).__name__}", "hits": [], "totals": {}}
    if "data" not in obj and isinstance(obj.get("error"), (dict, str)):
        err = obj["error"]
        msg = (err.get("message") or err.get("name")) if isinstance(err, dict) else err
        return {"status": "error", "reason": f"postman error: {str(msg)[:200]}", "hits": [], "totals": {}}
    data = obj.get("data")
    meta = obj.get("meta") if isinstance(obj.get("meta"), dict) else {}
    if not isinstance(data, list):
        return {"status": "error", "reason": "schema changed: 'data' is not a list", "hits": [], "totals": {}}
    totals_raw = meta.get("total") if isinstance(meta.get("total"), dict) else {}
    totals = {str(k): v for k, v in totals_raw.items() if isinstance(v, int) and not isinstance(v, bool)}
    hits: list[dict[str, Any]] = []
    malformed = 0
    unknown: dict[str, int] = {}
    for item in data:
        doc = item.get("document") if isinstance(item, dict) else None
        if not isinstance(doc, dict) or not isinstance(doc.get("entityType"), str):
            malformed += 1
            continue
        if doc["entityType"] not in POSTMAN_KNOWN_ENTITY_TYPES:
            unknown[doc["entityType"][:40]] = unknown.get(doc["entityType"][:40], 0) + 1
        hits.append(normalise_postman_hit(doc))
    common = {"totals": totals, "malformed_items": malformed, "unknown_entity_types": unknown}
    if data and not hits:
        return {"status": "error", "reason": f"schema changed: {malformed} items without a document object", "hits": [], **common}
    if not hits:
        return {"status": "empty", "reason": "no public Postman hits", "hits": [], **common}
    return {"status": "ok", "reason": "", "hits": hits, **common}


def postman_next_page(totals: Any, page: int) -> int | None:
    """Next page index to fetch, or None (bounded to :data:`POSTMAN_MAX_PAGES`, c5)."""
    if not isinstance(page, int) or page + 1 >= POSTMAN_MAX_PAGES:
        return None
    seen = (page + 1) * POSTMAN_PAGE_SIZE
    if isinstance(totals, dict) and any(isinstance(v, int) and v > seen for v in totals.values()):
        return page + 1
    return None


def filter_postman_hits(hits: list[dict[str, Any]], domains: Any, brands: Any = ()) -> dict[str, Any]:
    """Keep hits tied to the organisation; discard the rest with a reason histogram (c3).

    Ties (strongest first): ``request_host`` - the request host (or a custom host) is an org domain or
    a subdomain of one (0.7); ``publisher_exact`` - the folded publisher handle or name equals a brand
    (0.6 verified publisher, else 0.5); ``publisher_token`` - a brand (>= 4 characters) is a token of
    the handle or name (0.4, the analyst checks it). A name or description mention is never a tie.
    """
    doms = [d.lower().strip(".") for d in domains or () if isinstance(d, str) and d.strip(".")]
    brand_keys = {norm_token(b) for b in brands or () if norm_token(b)}
    brand_toks = {t for b in brands or () for t in tokens(b) if len(t) >= 4}
    kept: list[dict[str, Any]] = []
    discarded: dict[str, int] = {}
    for hit in hits or []:
        tied_by: list[str] = []
        matched = None
        req = hit.get("request") or {}
        for h in [req.get("host"), *(req.get("extra_hosts") or [])]:
            matched = next((d for d in doms if h and is_under(h, d)), None)
            if matched:
                tied_by.append("request_host")
                break
        pub = hit.get("publisher") or {}
        handle, pname = pub.get("handle") or "", pub.get("name") or ""
        if brand_keys and (norm_token(handle) in brand_keys or (pname and norm_token(pname) in brand_keys)):
            tied_by.append("publisher_exact")
        elif brand_toks and (brand_toks & set(tokens(handle)) or (pname and brand_toks & set(tokens(pname)))):
            tied_by.append("publisher_token")
        if not tied_by:
            reason = "request_host_not_target" if req.get("host") else ("templated_host" if req.get("has_variables") else "no_publisher_or_host_tie")
            discarded[reason] = discarded.get(reason, 0) + 1
            continue
        if "request_host" in tied_by:
            confidence = 0.7
        elif "publisher_exact" in tied_by:
            confidence = 0.6 if pub.get("verified") else 0.5
        else:
            confidence = 0.4
        out = dict(hit)
        out.update({"tied_by": tied_by, "matched_domain": matched, "confidence": confidence,
                    "exposed_kinds": list(req.get("exposed_kinds") or [])})
        kept.append(out)
    return {"kept": kept, "discarded": sum(discarded.values()), "discarded_by_reason": discarded}


def postman_facts(hit: dict[str, Any]) -> dict[str, Any]:
    """Facts of one kept hit: existence and location only (c4) - never a body, header value or secret."""
    req = hit.get("request") or {}
    pub = hit.get("publisher") or {}
    return {
        "location": hit.get("location"),
        "entity_type": hit.get("entity_type"),
        "name": hit.get("name"),
        "publisher_handle": pub.get("handle"),
        "publisher_name": pub.get("name"),
        "publisher_verified": bool(pub.get("verified")),
        "tied_by": list(hit.get("tied_by") or []),
        "matched_domain": hit.get("matched_domain"),
        "request_host": req.get("host") or None,
        "request_url_redacted": req.get("redacted_url") or None,
        "exposed_kinds": list(hit.get("exposed_kinds") or []),
        "confidence": hit.get("confidence"),
    }


# ============================================================================================== APIs.guru
def _count_entries(obj: Any) -> int:
    return sum(1 for k, e in obj.items() if isinstance(k, str) and isinstance(e, dict) and isinstance(e.get("versions"), dict)) if isinstance(obj, dict) else 0


def validate_apisguru_list(path: Any, min_entries: int | None = None) -> bool:
    """Dataset validator of ``list.json`` (AR10 runs it before installing a download): a JSON object
    with at least ``min_entries`` provider entries that carry ``versions``. Raises ValueError otherwise."""
    raw = path.read_bytes() if isinstance(path, Path) else path
    obj, why = load_json(raw)
    if obj is None:
        raise ValueError(f"APIs.guru list.json: {why}")
    if not isinstance(obj, dict):
        raise ValueError(f"APIs.guru list.json: schema changed: top level is {type(obj).__name__}")
    good = _count_entries(obj)
    min_entries = APISGURU_MIN_ENTRIES if min_entries is None else min_entries
    if good == 0:
        raise ValueError("APIs.guru list.json: schema changed: no provider entries with versions")
    if good < min_entries:
        raise ValueError(f"APIs.guru list.json: too few entries ({good} < {min_entries}): partial download")
    return True


def validate_apisguru_metrics(path: Any) -> bool:
    """Dataset validator of ``metrics.json``: an object with an integer ``numAPIs``."""
    raw = path.read_bytes() if isinstance(path, Path) else path
    parsed = parse_apisguru_metrics(raw)
    if parsed.get("status") != "ok":
        raise ValueError(f"APIs.guru metrics.json: {parsed.get('reason')}")
    return True


def parse_apisguru_metrics(raw: Any) -> dict[str, Any]:
    """``metrics.json`` -> counts used for the entry-count cross-check of the local list copy (c1, c7)."""
    obj, why = load_json(raw)
    if not isinstance(obj, dict):
        return {"status": "error", "reason": f"schema changed: {why or 'not an object'}"}
    keys = {"numAPIs": "num_apis", "numSpecs": "num_specs", "numProviders": "num_providers", "numEndpoints": "num_endpoints"}
    out: dict[str, Any] = {v: obj[k] for k, v in keys.items() if isinstance(obj.get(k), int) and not isinstance(obj.get(k), bool)}
    if "num_apis" not in out:
        return {"status": "error", "reason": "schema changed: numAPIs missing"}
    return {"status": "ok", "reason": "", **out}


def _preferred_version(entry: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    versions = entry.get("versions")
    if not isinstance(versions, dict) or not versions:
        return None, None
    pref = entry.get("preferred")
    if isinstance(pref, str) and isinstance(versions.get(pref), dict):
        return pref, versions[pref]
    best: tuple[str, dict[str, Any]] | None = None
    for ver, v in versions.items():
        if isinstance(v, dict) and (best is None or str(v.get("updated") or "") > str(best[1].get("updated") or "")):
            best = (str(ver), v)
    return best if best else (None, None)


def _looks_like_hostname(value: Any) -> bool:
    return isinstance(value, str) and "." in value and re.fullmatch(r"[A-Za-z0-9.-]{1,253}", value) is not None \
        and not value.startswith(".") and not value.endswith(".")


class ApisGuruIndex:
    """In-memory index of the directory: registrable domain -> [(entry position, host, kind)].

    Match keys: the provider key (a domain; ``*.local`` pseudo-providers never match by name), the
    ``x-providerName``, the service name when it is a hostname (``github.com:api.github.com``) and the
    hosts of ``x-origin`` spec URLs. ``contact`` (names, e-mails, URLs) is never read.
    """

    def __init__(self, obj: dict[str, Any]) -> None:
        self.entries: list[dict[str, Any]] = []
        self.by_reg: dict[str, list[tuple[int, str, str]]] = {}
        self.newest_update: str | None = None
        for key, entry in obj.items() if isinstance(obj, dict) else ():
            if not isinstance(key, str) or not isinstance(entry, dict):
                continue
            ver, v = _preferred_version(entry)
            if v is None:
                continue
            info = v.get("info") if isinstance(v.get("info"), dict) else {}
            provider, _, service = key.partition(":")
            provider = provider.lower()
            provider_is_domain = not provider.endswith(".local") and _looks_like_hostname(provider)
            origins = [o.get("url") for o in (info.get("x-origin") or []) if isinstance(o, dict) and isinstance(o.get("url"), str)]
            updated = v.get("updated") if isinstance(v.get("updated"), str) else None
            if updated and (self.newest_update is None or updated > self.newest_update):
                self.newest_update = updated
            cats = info.get("x-apisguru-categories")
            pos = len(self.entries)
            self.entries.append({
                "key": key[:200], "provider": provider[:200], "service": service[:200] or None,
                "title": _text(info.get("title")), "version": ver, "openapi_version": v.get("openapiVer") if isinstance(v.get("openapiVer"), str) else None,
                "added": v.get("added") if isinstance(v.get("added"), str) else None, "updated": updated,
                "spec_url": v.get("swaggerUrl") if isinstance(v.get("swaggerUrl"), str) else None,
                "origin_urls": [u[:500] for u in origins[:5]],
                "categories": [c for c in cats if isinstance(c, str)][:10] if isinstance(cats, list) else [],
            })
            keys: list[tuple[str, str]] = []
            if provider_is_domain:
                keys.append((provider, "provider"))
                xprov = info.get("x-providerName")
                if isinstance(xprov, str) and _looks_like_hostname(xprov) and xprov.lower() != provider:
                    keys.append((xprov.lower(), "x-providerName"))
                if service and _looks_like_hostname(service):
                    keys.append((service.lower(), "service_host"))
            for url in origins:
                h = host_of(url)
                if h:
                    keys.append((h, "x-origin"))
            for host, kind in keys:
                reg = psl.registrable_domain(host) or host
                self.by_reg.setdefault(reg, []).append((pos, host, kind))

    def __len__(self) -> int:
        return len(self.entries)

    def match(self, domain: str, now: datetime) -> list[dict[str, Any]]:
        """Directory entries tied to ``domain`` (label-wise), each with how and the hosts under it."""
        d = (domain or "").lower().strip(".")
        if not d:
            return []
        reg = psl.registrable_domain(d) or d
        found: dict[int, dict[str, Any]] = {}
        for pos, host, kind in self.by_reg.get(reg, []):
            if not is_under(host, d):
                continue
            rec = found.setdefault(pos, {"matched_by": [], "hosts": set(), "origin_urls_on_target": []})
            if kind not in rec["matched_by"]:
                rec["matched_by"].append(kind)
            rec["hosts"].add(host)
        out: list[dict[str, Any]] = []
        for pos, rec in found.items():
            entry = self.entries[pos]
            # 'provider' and 'x-providerName' tie the same thing: report the provider key when both hold
            if "provider" in rec["matched_by"] and "x-providerName" in rec["matched_by"]:
                rec["matched_by"].remove("x-providerName")
            on_target = [u for u in entry["origin_urls"] if is_under(host_of(u), d)]
            out.append({
                **{k: entry[k] for k in ("key", "provider", "service", "title", "version", "openapi_version", "added", "updated", "spec_url", "categories")},
                "age_days": _iso_age_days(entry["updated"], now),
                "origin_urls_on_target": on_target,
                "matched_by": rec["matched_by"],
                "matched_domain": d,
                "hosts": sorted(rec["hosts"]),
                "new_hosts": sorted(h for h in rec["hosts"] if h != d),
            })
        out.sort(key=lambda m: m["key"])
        return out


_INDEX_CACHE: dict[str, ApisGuruIndex] = {}
_INDEX_LOCK = threading.Lock()


def _directory_index(path: Path, sha256: str) -> ApisGuruIndex:
    """Parsed index of the local list.json copy, cached per process by content hash (8.9 MB parse once)."""
    key = sha256 or str(path)
    with _INDEX_LOCK:
        cached = _INDEX_CACHE.get(key)
    if cached is not None:
        return cached
    obj, why = load_json(Path(path).read_bytes())
    if not isinstance(obj, dict):
        raise DatasetError(f"APIs.guru list.json copy is unusable ({why or 'not an object'}): run v3lum data update {APISGURU_LIST}", reason_code="error", name=APISGURU_LIST)
    index = ApisGuruIndex(obj)
    with _INDEX_LOCK:
        _INDEX_CACHE.clear()  # one directory copy at a time
        _INDEX_CACHE[key] = index
    return index


register_dataset(
    APISGURU_LIST,
    APISGURU_LIST_URL,
    ttl=86400,
    description="APIs.guru OpenAPI directory list.json (every provider, API version and spec URL), matched locally by public_api_exposure (P069 cond 1)",
    licence="CC0-1.0",
    terms_class="open",
    attribution="APIs.guru OpenAPI directory (CC0 1.0), https://apis.guru/",
    provider="apisguru",
    source=SOURCE_APISGURU,
    validate=validate_apisguru_list,
    min_bytes=1_000_000,
    expect="json",
    max_bytes=32 * 1024 * 1024,
    large=True,
)
register_dataset(
    APISGURU_METRICS,
    APISGURU_METRICS_URL,
    ttl=86400,
    description="APIs.guru metrics.json (numAPIs, numProviders...): entry-count cross-check of the local list.json copy (P069 cond 1, 7)",
    licence="CC0-1.0",
    terms_class="open",
    attribution="APIs.guru OpenAPI directory (CC0 1.0), https://apis.guru/",
    provider="apisguru",
    source=SOURCE_APISGURU,
    validate=validate_apisguru_metrics,
    min_bytes=50,
    expect="json",
    max_bytes=1024 * 1024,
)


# ================================================================================================= module
_FAILURE_STATUS = {
    Blocked: Status.BLOCKED,
    RateLimited: Status.RATE_LIMITED,
    QuotaExceeded: Status.QUOTA,
}


#: which failure an aggregator run reports when nothing was found (the query that could not be verified
#: wins over a missing local dataset; the order follows the engine's coverage rank)
_FAILURE_RANK = {Status.QUOTA: 8, Status.RATE_LIMITED: 7, Status.BLOCKED: 6, Status.ERROR: 5, Status.UNAVAILABLE: 3, Status.SKIPPED: 1}


def _failure(exc: Exception) -> tuple[Status, str, str]:
    """(status, reason_code, reason) of a source failure: 'could not verify', never an absence."""
    if isinstance(exc, OfflineError):
        return Status.UNAVAILABLE, "offline", f"Postman search not sent: {exc}"
    if isinstance(exc, DeadlineExceeded):
        return Status.ERROR, "timeout", f"Postman search timed out ({exc}): could not verify"
    if isinstance(exc, AuthRequired):  # keyless 401/403 without a challenge body: still a block (c5)
        return Status.BLOCKED, "challenge", f"Postman search refused the request ({exc}): could not verify, no bypass"
    for cls, status in _FAILURE_STATUS.items():
        if isinstance(exc, cls):
            code = str(getattr(exc, "reason_code", "") or "")
            default = {Status.BLOCKED: "challenge", Status.RATE_LIMITED: "rate_limited", Status.QUOTA: "quota"}[status]
            valid = {Status.BLOCKED: {"challenge", "geo_block", "login_wall", "circuit", "hostile_host"}}.get(status, {default})
            return status, code if code in valid else default, f"Postman search: {exc}: could not verify"
    return Status.ERROR, "error", f"Postman search failed ({type(exc).__name__}: {str(exc)[:200]}): could not verify"


@register
class PublicApiExposure(Module):
    name = "public_api_exposure"
    title = "Public API exposure (Postman public search, APIs.guru)"
    description = ("Public Postman workspaces, collections and requests tied to the organisation's domains and brands (metadata and "
                   "location only; source disabled until its terms are recorded) and APIs listed in the APIs.guru OpenAPI directory "
                   "(CC0, matched locally).")
    category = "url_web"
    accepts = {T.DOMAIN, T.ORG, T.KEYWORD}
    produces = {T.URL, T.DOMAIN}
    reference = "https://github.com/APIs-guru/openapi-directory"
    notice = ("Postman search is an undocumented website API with unknown terms: it stays off until legal records its terms (A1) and "
              "then searches only org_profile domains and brands. APIs.guru (CC0) needs `v3lum data update public_api_exposure.apisguru_list`.")
    terms = "unknown"  # most restrictive source class: postman.public_search (unknown); apisguru.directory is open
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # Postman receives the org domain/brand; APIs.guru never receives the value
    hosts = ("www.postman.com",)
    provider = "postman"
    sources = (SOURCE_POSTMAN, SOURCE_APISGURU)
    access_model = "free_noauth_limited"
    max_requests = POSTMAN_MAX_PAGES  # one query per entity, at most 2 pages
    expected_latency = 2.0
    timeout = 45.0
    min_interval = 2.0
    max_pivots = 60
    manual_link = "public_api_exposure:postman_search"
    default_enabled = False  # c6 (and A3: terms unknown)

    @classmethod
    def health_check(cls) -> HealthCheck:
        # example.com is not in the directory: the benign probe answers EMPTY once the dataset is installed
        return HealthCheck(T.DOMAIN, "example.com", expect="empty")

    # ------------------------------------------------------------------------------------- scope
    @staticmethod
    def _org_scope(entity: Entity, ctx: Any) -> tuple[dict[str, Any] | None, str]:
        """The Postman query for an org_profile domain or brand, with the tie domains and brands (c3)."""
        org = getattr(ctx, "org", None)
        if org is None or getattr(org, "is_empty", True):
            return None, "no org profile: Postman searches are limited to org_profile domains and brands (P069 cond 3)"
        own_domains = [str(getattr(d, "name", "") or "").lower() for d in getattr(org, "domains", []) or []]
        own_domains = [d for d in own_domains if d]
        brands = [b for b in org.brand_terms() if b]
        if entity.type is T.DOMAIN:
            owned = org.owns(entity)
            if not (getattr(owned, "own", False) and getattr(owned, "kind", "") == "domain"):
                return None, "not an org_profile domain: no Postman search about third parties (P069 cond 3)"
            query = entity.value
            if entity.value not in own_domains:
                own_domains.append(entity.value)
        else:
            if org_fold(entity.value) not in brands:
                return None, "not an org_profile brand: no Postman search about third parties (P069 cond 3)"
            query = entity.value.strip()
        if not brands:  # implicit brands: the first label (>= 4 characters) of each own domain
            brands = sorted({d.split(".")[0] for d in own_domains if len(d.split(".")[0]) >= 4})
        return {"query": query, "domains": own_domains, "brands": brands}, ""

    @staticmethod
    def _reserve_case_query(ctx: Any) -> bool:
        """Per-case query cap (c5) kept in ctx.state; a single run without a case is not capped here."""
        case_id = str(getattr(ctx, "case_id", "") or "")
        if not case_id:
            return True
        counts = ctx.state.get(STATE_CASE_KEY) or {}
        if not isinstance(counts, dict):
            counts = {}
        used = int(counts.get(case_id, 0) or 0)
        if used >= POSTMAN_MAX_QUERIES_PER_CASE:
            return False
        counts[case_id] = used + 1
        if len(counts) > STATE_CASES_KEPT:
            for old in list(counts)[: len(counts) - STATE_CASES_KEPT]:
                counts.pop(old, None)
        ctx.state.set(STATE_CASE_KEY, counts)
        return True

    # ----------------------------------------------------------------------------------- Postman
    def _postman(self, ctx: Any, scope: dict[str, Any]) -> dict[str, Any]:
        """Search one query, at most two pages. Page-1 failures propagate; page-2 failures keep page 1."""
        pages: list[dict[str, Any]] = []
        page_errors: list[str] = []
        page = 0
        while page is not None:
            try:
                resp = ctx.http.post(
                    POSTMAN_SEARCH_URL,
                    json_body=postman_search_body(scope["query"], page),
                    headers={"Accept": "application/json"},
                    source=SOURCE_POSTMAN,
                )
                ctx.http.check(resp)
            except (HttpError, NetworkError) as exc:
                if page == 0:
                    raise
                page_errors.append(_failure(exc)[2])
                break
            parsed = parse_postman_search(resp.content)
            if parsed["status"] == "error" and page > 0:
                page_errors.append(parsed["reason"])
                break
            pages.append(parsed)
            if parsed["status"] != "ok":
                break
            page = postman_next_page(parsed.get("totals"), page)
        first = pages[0]
        if first["status"] == "error":
            return {"status": "error", "reason": first["reason"]}
        hits: list[dict[str, Any]] = []
        seen: set[tuple[Any, Any]] = set()
        for parsed in pages:
            for h in parsed.get("hits") or []:
                key = (h.get("entity_type"), h.get("id") or h.get("location"))
                if key not in seen:
                    seen.add(key)
                    hits.append(h)
        filtered = filter_postman_hits(hits, scope["domains"], scope["brands"])
        summary = {
            "source": SOURCE_POSTMAN, "query": scope["query"], "pages": len(pages), "hits": len(hits),
            "kept": len(filtered["kept"]), "discarded": filtered["discarded"], "discarded_by_reason": filtered["discarded_by_reason"],
            "totals": first.get("totals") or {}, "partial": bool(page_errors), "page_errors": page_errors,
        }
        return {"status": "ok" if filtered["kept"] else "empty", "kept": filtered["kept"], "summary": summary}

    def _record_postman(self, res: ModuleResult, entity: Entity, out: dict[str, Any]) -> None:
        kept = out.get("kept") or []
        res.attr("public_api_search", out.get("summary"))
        facts = [postman_facts(h) for h in kept]
        res.attr("public_api_locations", facts)
        for fact in facts[:POSTMAN_FINDING_CAP]:
            self._postman_finding(res, entity, fact)
        for fact in facts:
            if fact["location"]:
                res.pivot(T.URL, fact["location"], "public_api_location", confidence=fact["confidence"] or 0.4, expand=False,
                          note="public Postman location tied to the organisation: existence and location only")
            host = fact.get("request_host")
            if host and fact.get("matched_domain") and host != entity.value and is_under(host, fact["matched_domain"]):
                res.pivot(T.DOMAIN, host, "subdomain", confidence=0.7)

    @staticmethod
    def _postman_finding(res: ModuleResult, entity: Entity, fact: dict[str, Any]) -> None:
        kind = str(fact.get("entity_type") or "item")
        where = fact.get("location") or "(no public URL)"
        tied = ", ".join(fact.get("tied_by") or [])
        data = {k: v for k, v in fact.items() if v not in (None, "", [])}
        if "request_host" in (fact.get("tied_by") or []) and fact.get("exposed_kinds"):
            res.finding(
                "Public Postman request with credential-type values for an organisation host",
                "high",
                f"A public Postman {kind} targets {fact.get('request_host')} (under {fact.get('matched_domain')}) and its URL carries "
                f"literal values of type {', '.join(fact['exposed_kinds'])} at {where}. Values were not stored, used or replayed: "
                "review and rotate the credentials, then ask the publisher to remove or make the item private.",
                confidence="probable",
                criterion="request host under an org_profile domain and a literal credential-type value in the request URL "
                          "(secret type from the metadata only, P069 cond 4)",
                tags=["exposure", "credential_exposure"],
                source=SOURCE_POSTMAN,
                data=data,
                references=[where] if fact.get("location") else [],
                key=str(fact.get("location") or fact.get("name") or ""),
            )
        elif "request_host" in (fact.get("tied_by") or []):
            res.finding(
                "Public Postman item references an organisation host",
                "low",
                f"A public Postman {kind} targets {fact.get('request_host')} (under {fact.get('matched_domain')}) at {where}: an API "
                "description of the organisation is published (existence and location only).",
                confidence="probable",
                criterion="request host under an org_profile domain in public Postman search metadata (P069 cond 3)",
                tags=["exposure"],
                source=SOURCE_POSTMAN,
                data=data,
                references=[where] if fact.get("location") else [],
                key=str(fact.get("location") or fact.get("name") or ""),
            )
        else:
            exact = "publisher_exact" in (fact.get("tied_by") or [])
            res.finding(
                "Public Postman workspace or collection published under an organisation brand",
                "info",
                f"Public Postman {kind} '{fact.get('name') or '?'}' by publisher '{fact.get('publisher_handle') or '?'}' ({tied}) at {where}. "
                + ("Check whether it is the organisation's official team." if exact else "Check: official team, impersonation or a fan workspace."),
                confidence=fact.get("confidence") or 0.4,
                criterion="publisher handle/name equal to (or a token equal to) an org_profile brand (P069 cond 3)",
                tags=["exposure"],
                source=SOURCE_POSTMAN,
                data=data,
                references=[where] if fact.get("location") else [],
                key=str(fact.get("location") or fact.get("name") or ""),
            )

    # --------------------------------------------------------------------------------- APIs.guru
    def _apisguru(self, ctx: Any, entity: Entity) -> dict[str, Any]:
        if not ctx.data.info(APISGURU_LIST).present:
            # 8.9 MB: installed by `v3lum data update` only, never downloaded by a lookup (A6 BR9, AR10)
            raise DatasetUnavailable(APISGURU_LIST, f"dataset {APISGURU_LIST} is not downloaded: run v3lum data update {APISGURU_LIST}")
        path = ctx.data.fetch(APISGURU_LIST)
        info = ctx.data.info(APISGURU_LIST)
        index = _directory_index(path, str(getattr(info, "sha256", "") or ""))
        metrics = None
        try:
            if ctx.data.info(APISGURU_METRICS).present:
                parsed = parse_apisguru_metrics(ctx.data.fetch_json(APISGURU_METRICS))
                metrics = parsed if parsed.get("status") == "ok" else None
        except DatasetError:
            metrics = None  # the cross-check is optional: the list itself was validated at download
        now = ctx.now()
        directory = {
            "dataset": APISGURU_LIST, "sha256": str(getattr(info, "sha256", "") or ""), "fetched_at": str(getattr(info, "fetched_at", "") or ""),
            "entries": len(index), "newest_update": index.newest_update,
            "metrics_num_apis": metrics.get("num_apis") if metrics else None,
            "complete": (len(index) >= 0.9 * metrics["num_apis"]) if metrics else None,
        }
        matches = index.match(entity.value, now)
        return {"status": "ok" if matches else "empty", "matches": matches, "directory": directory}

    def _record_apisguru(self, res: ModuleResult, entity: Entity, out: dict[str, Any]) -> None:
        matches = out["matches"]
        res.attr("public_api_directory_info", out["directory"])
        if not matches:
            return
        shown = matches[:APISGURU_MATCH_CAP]
        res.attr("public_api_directory", shown)
        newest = max((m["updated"] or "" for m in matches), default="") or None
        titles = ", ".join(sorted({m["title"] or m["key"] for m in shown})[:8])
        res.finding(
            "APIs listed in the public APIs.guru directory",
            "info",
            f"{len(matches)} API definition(s) of {entity.value} are listed in the APIs.guru OpenAPI directory ({titles}"
            f"{', ...' if len(matches) > 8 else ''}); newest update {newest or 'unknown'}. The directory has been frozen since "
            "2023-04: entries can be old.",
            confidence="confirmed",
            criterion="provider key, x-providerName, service host or x-origin spec host under the domain in the local APIs.guru copy",
            tags=["exposure"],
            source=SOURCE_APISGURU,
            data={"count": len(matches), "keys": [m["key"] for m in shown], "newest_update": newest},
            observed_last=newest,
        )
        pivots = 0
        for m in shown:
            for url in m["origin_urls_on_target"]:
                if pivots < APISGURU_PIVOT_CAP and res.pivot(T.URL, url, "api_spec_url", confidence=0.9, expand=False,
                                                            note="OpenAPI definition hosted on the domain (APIs.guru x-origin)"):
                    pivots += 1
            for host in m["new_hosts"]:
                if pivots < APISGURU_PIVOT_CAP and is_under(host, entity.value) and res.pivot(T.DOMAIN, host, "subdomain", confidence=0.7):
                    pivots += 1

    # --------------------------------------------------------------------------------------- run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        allowed = ctx.allowed_sources
        failures: list[tuple[str, Status, str, str]] = []
        answered: list[str] = []
        raw: dict[str, Any] = {}
        notes: list[str] = []

        if entity.type is T.DOMAIN and SOURCE_APISGURU in allowed:
            try:
                out = self._apisguru(ctx, entity)
            except DatasetUnavailable as exc:
                failures.append((SOURCE_APISGURU, Status.UNAVAILABLE, "dataset", f"APIs.guru directory not checked: {exc}"))
            except DatasetError as exc:
                failures.append((SOURCE_APISGURU, Status.ERROR, "error", f"APIs.guru directory copy unusable: {exc}: not checked"))
            else:
                self._record_apisguru(res, entity, out)
                answered.append(out["status"])
                raw["apisguru"] = {"matches": [m["key"] for m in out["matches"]], "directory": out["directory"]}

        scope, why = self._org_scope(entity, ctx)
        if scope is None:
            notes.append(why)
        elif SOURCE_POSTMAN not in allowed:
            notes.append("Postman search skipped by the licence gate (terms unknown, P069 cond 2): manual link public_api_exposure:postman_search")
        elif not self._reserve_case_query(ctx):
            notes.append(f"Postman query cap of this case reached ({POSTMAN_MAX_QUERIES_PER_CASE} queries, P069 cond 5)")
            failures.append((SOURCE_POSTMAN, Status.SKIPPED, "policy", f"Postman query cap of this case reached ({POSTMAN_MAX_QUERIES_PER_CASE} queries): not searched"))
        else:
            try:
                out = self._postman(ctx, scope)
            except (HttpError, NetworkError) as exc:
                status, code, reason = _failure(exc)
                failures.append((SOURCE_POSTMAN, status, code, reason))
            else:
                if out["status"] == "error":
                    failures.append((SOURCE_POSTMAN, Status.ERROR, "error", f"Postman search: {out['reason']}: could not verify"))
                else:
                    self._record_postman(res, entity, out)
                    answered.append(out["status"])
                    raw["postman"] = {"summary": out["summary"], "kept": [postman_facts(h) for h in out["kept"]]}

        if raw:
            res.raw = raw
        has_data = bool(res.findings or res.attributes or res.pivots)
        if failures and (answered or has_data):
            for source, status, code, reason in failures:
                res.source_status(source, status, reason_code=code, reason=reason)
        if has_data and any(a == "ok" for a in answered):
            return res
        if failures:
            # nothing found and a source could not answer: 'could not verify', never an absence (rule 5)
            source, status, code, reason = max(failures, key=lambda f: _FAILURE_RANK.get(f[1], 0))
            return res.mark(status, reason, reason_code=code)
        if answered:
            return res.mark(Status.EMPTY, "; ".join(notes) if notes else "")
        return res.mark(Status.SKIPPED, "; ".join(notes) or "nothing to check for this entity", reason_code="not_applicable")
