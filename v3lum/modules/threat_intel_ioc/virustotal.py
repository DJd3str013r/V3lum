"""VirusTotal API v3: multi-engine verdicts and capped relationships of IPs, domains, URLs and file hashes.

Batch p2-G07-1, proposal P158 (council final conditions):

* c1 - key ``virustotal`` (header ``x-apikey``). The public API may not be used in business
  workflows: ``terms='noncommercial'`` (registry source ``virustotal.api``), so under the corporate
  profile the policy gate skips it (reason_code ``licence``) until legal records a VirusTotal
  premium/enterprise licence in licence_allow (basis ``licence``); a public key runs only in the
  research profile. ``default_enabled`` stays the council's candidate flag: off under the corporate
  profile until licence-cleared.
* c2 - read-only by construction: GET lookups only. :func:`request_allowed` is the method/path
  allow-list every request passes (unit-tested): no POST /files or /urls, no /analyse rescan, no
  /analyses, comments, votes, downloads or upload URLs are ever built (a URL submission makes
  VirusTotal fetch and publish it: rule 7).
* c3 - budget: the public key's 4 requests/minute and 500/day are the provider's P334 token bucket and
  day window (shared seed ``virustotal``). The module's own pacer (:data:`PACER`, at the same budgeted
  rate) sends a request only when the provider's next slot is free now; otherwise the lookup ends QUOTA
  'VT: not run (quota)' and the engine defers it (one 'VirusTotal: N lookups deferred' line, ``cases
  resume``): an engine worker never sleeps for VirusTotal. A per-scan budget (setting
  ``virustotal_case_budget``, default 20 lookups) keeps the last 20% for analyst-typed seeds (seeds
  first); a ``Module.case_budget`` contract field would need an architect-approved migration (A16), so
  it is a setting. The scan never waits on VT.
* c4 - relationships (domains: resolutions, subdomains, communicating_files; IPs: resolutions,
  communicating_files; files: contacted_domains, contacted_ips, contacted_urls) are read for
  analyst-typed seeds only, one capped page each (setting ``virustotal_page_size``, default 10, max
  40), cursors reported but never followed, cached 72 h, filtered through the noise and warning lists
  and pivoted with ``expand=False`` unless the queried object itself is malicious. URL objects read no
  relationships (unverified for URL objects: backlog).
* c5 - wording 'N/M engines flagged (last analysis <date>)' with the top 3 labels; >= 5 engines (or
  one engine of the configured trusted-vendor set, setting ``virustotal_trusted_vendors``) ->
  malicious (HIGH), 3-4 -> suspicious (MEDIUM), 1-2 -> LOW 'few engines'; 0 -> no finding. URL ids are
  base64url without padding; 404 = EMPTY (unknown to VirusTotal). The EICAR test file is reported as
  an expected detection (tag ``test_file``, info).
* c6 - the VT GUI link is emitted with every answer and, as ``manual_link``
  (``threat_intel_g07_p2:vt_search``), whenever automation is skipped, key or not. Provider data is not
  redistributed (attribute ``export_restriction``: verdict, link and source name only). WHOIS,
  certificates, cookies, response headers, HTML metadata and submitted file names are never kept.
  Success fixtures are documented shapes until a licensed key exists.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import threading
from collections import Counter, OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

from v3lum.config import SettingSpec
from v3lum.core import noise
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SOURCE = "virustotal.api"
HOST = "www.virustotal.com"
BASE = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui"
KEY_NAME = "virustotal"
KEY_HEADER = "x-apikey"
ATTRIBUTION = "VirusTotal"
CASE_SETTING = "virustotal_case_budget"
TRUSTED_SETTING = "virustotal_trusted_vendors"
PAGE_SETTING = "virustotal_page_size"
CASE_DEFAULT = 20
PAGE_DEFAULT = 10
PAGE_MAX = 40
#: share of the per-scan budget kept for analyst-typed seeds (seeds first, like P334's SEED_RESERVE)
SEED_RESERVE = 0.2
RELATIONSHIP_TTL = 259200
COLLECTIONS: dict[T, str] = {
    T.IPV4: "ip_addresses", T.IPV6: "ip_addresses", T.DOMAIN: "domains", T.URL: "urls",
    T.MD5: "files", T.SHA1: "files", T.SHA256: "files",
}
#: relationships the module may read (c4); premium-only relationships are never requested
RELATIONSHIPS: dict[str, tuple[str, ...]] = {
    "domains": ("resolutions", "subdomains", "communicating_files"),
    "ip_addresses": ("resolutions", "communicating_files"),
    "files": ("contacted_domains", "contacted_ips", "contacted_urls"),
    "urls": (),
}
BAND_SEVERITY = {"malicious": "high", "suspicious": "medium", "few_engines": "low"}
COUNTED = ("malicious", "suspicious", "undetected", "harmless")
#: the EICAR anti-virus test file: detections are expected, never an incident
EICAR = frozenset({
    "44d88612fea8a8f36de82e1278abb02f", "3395856ce81f2b7382dee72602f798b642f14140",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
})
NOT_RUN = "VT: not run (quota)"
_NOISE_LABELS = frozenset({"clean", "unrated", "undetected", "harmless", "type-unsupported", "timeout", "", "none"})
_PATH_RE = re.compile(r"^/api/v3/(ip_addresses|domains|files|urls)/([^/]+)(?:/([a-z_]+))?$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")


# --------------------------------------------------------------------------------------
# pure helpers (stdlib only; ported from the batch prep parsers)
# --------------------------------------------------------------------------------------


def clean_text(value: Any, limit: int = 160) -> str | None:
    if value is None or isinstance(value, (dict, list, tuple, set, bool)):
        return None
    text = " ".join(_CTRL_RE.sub(" ", str(value)).split())
    return text[:limit] or None


def as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"\s*-?\d{1,15}\s*", value):
        return int(value)
    return None


def iso_epoch(value: Any) -> str | None:
    """VirusTotal epoch seconds -> 'YYYY-MM-DDTHH:MM:SSZ' (None for junk or dates after year 3000)."""
    seconds = as_int(value)
    if seconds is None or seconds <= 0 or seconds > 32503680000:
        return None
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_value(value: Any) -> tuple[str | None, str | None]:
    text = clean_text(value, 200)
    if not text or not _HEX_RE.match(text):
        return None, None
    kind = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(text))
    return (kind, text.lower()) if kind else (None, None)


def load_json(content: bytes | str | None) -> tuple[Any, str]:
    if content is None:
        return None, "empty answer"
    text = content.decode("utf-8", errors="replace") if isinstance(content, (bytes, bytearray)) else str(content)
    text = text.lstrip("﻿").strip()
    if not text:
        return None, "empty answer"
    if text.startswith("<"):
        return None, "HTML page instead of JSON"
    try:
        return json.loads(text), ""
    except (ValueError, RecursionError) as exc:
        return None, f"malformed JSON ({str(exc)[:60]})"


def url_id(url: str) -> str:
    """URL identifier for /urls/{id}: base64url of the URL without '=' padding (c5)."""
    return base64.urlsafe_b64encode(str(url).encode("utf-8")).decode("ascii").rstrip("=")


def object_id(entity: Entity) -> str:
    if entity.type is T.URL:
        return url_id(entity.value)
    if entity.type in (T.MD5, T.SHA1, T.SHA256, T.DOMAIN):
        return entity.value.lower()
    return entity.value


def object_url(entity: Entity) -> str | None:
    collection = COLLECTIONS.get(entity.type)
    if collection is None:
        return None
    return f"{BASE}/{collection}/{quote(object_id(entity), safe=':.-_')}"


def relationship_url(entity: Entity, relationship: str, limit: int = PAGE_DEFAULT, cursor: str = "") -> str | None:
    """ONE page of a relationship (c4): capped, a cursor only when the caller passes one (never followed by default)."""
    base = object_url(entity)
    collection = COLLECTIONS.get(entity.type, "")
    if base is None or relationship not in RELATIONSHIPS.get(collection, ()):
        return None
    params = {"limit": str(max(1, min(PAGE_MAX, int(limit))))}
    if cursor:
        params["cursor"] = cursor
    return f"{base}/{relationship}?{urlencode(params)}"


def request_allowed(method: str, url: str) -> bool:
    """Method/path allow-list (c2): GET only; /api/v3/{ip_addresses|domains|files|urls}/{id}[/{relationship}]
    with the c4 relationships and only 'limit' (<= 40) and 'cursor'. Submissions (POST /files, /urls),
    rescans (/analyse), /analyses, comments, votes, downloads, upload URLs and every other path are refused."""
    try:
        parts = urlsplit(url)
        query = parse_qs(parts.query, keep_blank_values=True)
    except ValueError:
        return False
    if (method or "").upper() != "GET" or parts.scheme != "https" or parts.hostname != HOST:
        return False
    match = _PATH_RE.match(parts.path)
    if not match:
        return False
    collection, oid, rel = match.group(1), unquote(match.group(2)), match.group(3)
    if collection == "files" and hash_value(oid)[0] is None:
        return False
    if collection == "ip_addresses":
        try:
            ipaddress.ip_address(oid)
        except ValueError:
            return False
    if collection == "domains" and not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9-]{1,63}\.)+[a-z0-9-]{1,63}", oid):
        return False
    if collection == "urls" and not re.fullmatch(r"[A-Za-z0-9_-]{4,8192}", oid):
        return False
    if rel is None:
        return not query
    if rel not in RELATIONSHIPS[collection] or not set(query) <= {"limit", "cursor"}:
        return False
    limit = as_int((query.get("limit") or ["10"])[0])
    return limit is not None and 1 <= limit <= PAGE_MAX


def gui_link(entity: Entity) -> str | None:
    """VirusTotal GUI page of the entity (c6)."""
    if entity.type in (T.IPV4, T.IPV6):
        return f"{GUI}/ip-address/{entity.value}"
    if entity.type is T.DOMAIN:
        return f"{GUI}/domain/{entity.value.lower()}"
    if entity.type in (T.MD5, T.SHA1, T.SHA256):
        return f"{GUI}/file/{entity.value.lower()}"
    if entity.type is T.URL:
        return f"{GUI}/search/{quote(entity.value, safe='')}"
    return None


def analysis(attrs: Any, top: int = 3) -> dict[str, Any]:
    """last_analysis_* -> counts, total M (malicious + suspicious + undetected + harmless; timeouts, failures and
    type-unsupported excluded), date, the top labels of flagging engines (ties alphabetical) and the
    engines that flagged it malicious."""
    attrs = attrs if isinstance(attrs, dict) else {}
    stats = attrs.get("last_analysis_stats") if isinstance(attrs.get("last_analysis_stats"), dict) else {}
    counts = {k: max(0, as_int(stats.get(k)) or 0) for k in ("malicious", "suspicious", "harmless", "undetected", "timeout")}
    total = sum(counts[k] for k in COUNTED)
    results = attrs.get("last_analysis_results") if isinstance(attrs.get("last_analysis_results"), dict) else {}
    labels: Counter[str] = Counter()
    shown: dict[str, str] = {}
    flagged: list[str] = []
    for engine, row in list(results.items())[:300]:
        if not isinstance(row, dict):
            continue
        category = (clean_text(row.get("category"), 30) or "").lower()
        if category == "malicious":
            name = clean_text(row.get("engine_name"), 80) or clean_text(engine, 80)
            if name:
                flagged.append(name)
        if category in ("malicious", "suspicious"):
            label = clean_text(row.get("result"), 120)
            if label and label.lower() not in _NOISE_LABELS:
                labels[label.lower()] += 1
                shown.setdefault(label.lower(), label)
    top_labels = [shown[k] for k, _ in sorted(labels.items(), key=lambda kv: (-kv[1], kv[0]))[:top]]
    return {**counts, "total": total, "date": iso_epoch(attrs.get("last_analysis_date")), "top_labels": top_labels,
            "flagged_by": sorted(set(flagged))}


def wording(a: dict[str, Any]) -> str:
    """'N/M engines flagged (last analysis <date>)' + suspicious count + top 3 labels (c5)."""
    text = f"{a.get('malicious') or 0}/{a.get('total') or 0} engines flagged (last analysis {(a.get('date') or 'unknown date')[:10]})"
    if a.get("suspicious"):
        text += f", {a['suspicious']} suspicious"
    if a.get("top_labels"):
        text += "; top labels: " + ", ".join(a["top_labels"])
    return text


def verdict(a: dict[str, Any], trusted_vendors: Any = ()) -> dict[str, Any]:
    """Band (c5): >= 5 malicious engines or any trusted vendor -> malicious; 3-4 suspicious; 1-2 few engines; 0 none."""
    count = a.get("malicious") or 0
    wanted = {str(v).strip().lower() for v in (trusted_vendors or ()) if str(v).strip()}
    trusted = sorted(name for name in a.get("flagged_by") or () if name.lower() in wanted)
    if count >= 5 or trusted:
        band = "malicious"
    elif count >= 3:
        band = "suspicious"
    elif count >= 1:
        band = "few_engines"
    else:
        band = "none"
    return {"band": band, "severity": BAND_SEVERITY.get(band), "trusted_vendor_hits": trusted, "wording": wording(a)}


def _str_list(value: Any, limit: int = 20, item: int = 80) -> list[str]:
    out: list[str] = []
    for raw in value if isinstance(value, list) else []:
        text = clean_text(raw, item)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _best_rank(value: Any) -> int | None:
    best = None
    for row in value.values() if isinstance(value, dict) else []:
        rank = as_int(row.get("rank")) if isinstance(row, dict) else None
        if rank is not None and rank > 0 and (best is None or rank < best):
            best = rank
    return best


def parse_object(obj: Any) -> dict[str, Any] | None:
    """GET /{collection}/{id} JSON -> normalised facts, or None. Never kept: whois, certificates, cookies,
    response headers, html_meta, trackers, comments and submitted file names (personal data or noise)."""
    data = obj.get("data") if isinstance(obj, dict) else None
    if not isinstance(data, dict) or not isinstance(data.get("attributes"), dict):
        return None
    attrs = data["attributes"]
    kind = clean_text(data.get("type"), 30)
    votes = attrs.get("total_votes") if isinstance(attrs.get("total_votes"), dict) else {}
    out: dict[str, Any] = {
        "type": kind, "analysis": analysis(attrs), "reputation": as_int(attrs.get("reputation")),
        "tags": _str_list(attrs.get("tags")), "votes": {"harmless": as_int(votes.get("harmless")), "malicious": as_int(votes.get("malicious"))},
        "last_modified": iso_epoch(attrs.get("last_modification_date")),
    }
    cats = attrs.get("categories") if isinstance(attrs.get("categories"), dict) else {}
    if kind == "ip_address":
        out.update(as_owner=clean_text(attrs.get("as_owner")), asn=as_int(attrs.get("asn")), country=clean_text(attrs.get("country"), 8),
                   network=clean_text(attrs.get("network"), 64), rir=clean_text(attrs.get("regional_internet_registry"), 20))
    elif kind == "domain":
        out.update(registrar=clean_text(attrs.get("registrar")), creation_date=iso_epoch(attrs.get("creation_date")),
                   categories=sorted(set(_str_list(list(cats.values())))), popularity_best_rank=_best_rank(attrs.get("popularity_ranks")))
    elif kind == "file":
        ptc = attrs.get("popular_threat_classification") if isinstance(attrs.get("popular_threat_classification"), dict) else {}
        sandboxes = []
        boxes = attrs.get("sandbox_verdicts") if isinstance(attrs.get("sandbox_verdicts"), dict) else {}
        for name, row in list(boxes.items())[:5]:
            if isinstance(row, dict):
                sandboxes.append({"sandbox": clean_text(row.get("sandbox_name"), 80) or clean_text(name, 80),
                                  "category": clean_text(row.get("category"), 30), "malware_names": _str_list(row.get("malware_names"), 5)})
        out.update(
            md5=hash_value(attrs.get("md5"))[1], sha1=hash_value(attrs.get("sha1"))[1], sha256=hash_value(attrs.get("sha256"))[1],
            size=as_int(attrs.get("size")), type_description=clean_text(attrs.get("type_description"), 80),
            first_submission=iso_epoch(attrs.get("first_submission_date")), last_submission=iso_epoch(attrs.get("last_submission_date")),
            times_submitted=as_int(attrs.get("times_submitted")), threat_label=clean_text(ptc.get("suggested_threat_label"), 120),
            threat_names=[n for n in (clean_text(x.get("value"), 80) for x in (ptc.get("popular_threat_name") or [])[:5] if isinstance(x, dict)) if n],
            threat_categories=[n for n in (clean_text(x.get("value"), 80) for x in (ptc.get("popular_threat_category") or [])[:5] if isinstance(x, dict)) if n],
            sandbox_verdicts=sandboxes,
        )
    elif kind == "url":
        out.update(final_url=clean_text(attrs.get("last_final_url"), 2048), title=clean_text(attrs.get("title"), 200),
                   http_code=as_int(attrs.get("last_http_response_code")), categories=sorted(set(_str_list(list(cats.values())))),
                   threat_names=_str_list(attrs.get("threat_names"), 10, 120))
    return out


def _item(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    kind = clean_text(raw.get("type"), 30)
    oid = clean_text(raw.get("id"), 2048)
    attrs = raw.get("attributes") if isinstance(raw.get("attributes"), dict) else {}
    stats = attrs.get("last_analysis_stats") if isinstance(attrs.get("last_analysis_stats"), dict) else {}
    malicious = as_int(stats.get("malicious"))
    if kind == "resolution":
        ip = clean_text(attrs.get("ip_address"), 64)
        host = clean_text(attrs.get("host_name"), 253)
        if not ip or not host:
            return None
        return {"type": "resolution", "ip": ip, "host": host.lower().rstrip("."), "date": iso_epoch(attrs.get("date"))}
    if kind == "domain" and oid:
        return {"type": "domain", "value": oid.lower().rstrip("."), "malicious": malicious}
    if kind == "ip_address" and oid:
        return {"type": "ip", "value": oid, "malicious": malicious}
    if kind == "url":
        url = clean_text(attrs.get("url"), 2048)
        return {"type": "url", "value": url, "malicious": malicious} if url else None
    if kind == "file":
        _, sha = hash_value(attrs.get("sha256") or oid)
        if sha and len(sha) == 64:
            ptc = attrs.get("popular_threat_classification") if isinstance(attrs.get("popular_threat_classification"), dict) else {}
            return {"type": "sha256", "value": sha, "malicious": malicious, "label": clean_text(ptc.get("suggested_threat_label"), 120)}
    return None


def parse_collection(obj: Any, cap: int = PAGE_DEFAULT) -> dict[str, Any] | None:
    """Relationship page -> {items, count, next_cursor, more} (c4): at most ``cap`` items; the cursor is
    reported, never followed."""
    if not isinstance(obj, dict) or not isinstance(obj.get("data"), list):
        return None
    items = [it for it in (_item(raw) for raw in obj["data"][: max(0, cap)]) if it]
    meta = obj.get("meta") if isinstance(obj.get("meta"), dict) else {}
    links = obj.get("links") if isinstance(obj.get("links"), dict) else {}
    cursor = clean_text(meta.get("cursor"), 400)
    if not cursor and clean_text(links.get("next"), 2048):
        cursor = clean_text((parse_qs(urlsplit(str(links["next"])).query).get("cursor") or [None])[0], 400)
    return {"items": items, "count": as_int(meta.get("count")), "next_cursor": cursor, "more": bool(cursor) or len(obj["data"]) > cap}


def public_ip(value: str) -> bool:
    return noise.is_public_ip(value)


def is_listed_noise(etype: T, value: str) -> bool:
    """Noise and warning lists (c4): private/reserved addresses, CDN/cloud/resolver infrastructure,
    sinkholes and warninglisted values are filtered, never pivoted."""
    probe = Entity.try_make(etype, value)
    if probe is None:
        return True
    if etype in (T.IPV4, T.IPV6) and not public_ip(value):
        return True
    return bool((noise.noise_kinds(probe) - {"private"}) or noise.warninglists(probe))


def pacing_interval() -> float:
    """Seconds between two VirusTotal requests at the provider's budgeted rate (P334: rate_per_second x
    safety_margin of the ``virustotal`` quota block; 0 when the block declares no rate, e.g. a premium
    licence's figures)."""
    try:
        from v3lum.core.providers import registry

        spec = registry().get("virustotal").quota
        rate = float(getattr(spec, "rate_per_second", 0) or 0) * float(getattr(spec, "safety_margin", 0.8) or 0.8)
    except Exception:  # noqa: BLE001 - no registry entry: no module-side pacing (the core still paces)
        return 0.0
    return 1.0 / rate if rate > 0 else 0.0


class _Pacer:
    """The module-side token bucket of c3: a request is sent only when the provider's next slot is free
    now; otherwise the lookup is deferred - an engine worker never sleeps for VirusTotal."""

    def __init__(self) -> None:
        self._next: datetime | None = None
        self._lock = threading.Lock()

    def claim(self, now: datetime, interval: float) -> bool:
        if interval <= 0:
            return True
        with self._lock:
            if self._next is not None and now < self._next:
                return False
            self._next = now + timedelta(seconds=interval)
            return True

    def reset(self) -> None:
        with self._lock:
            self._next = None


PACER = _Pacer()


class _CaseBudget:
    """Lookups per case (process memory; a case runs in one process): seeds first."""

    def __init__(self, max_cases: int = 32) -> None:
        self._cases: OrderedDict[str, int] = OrderedDict()
        self._lock = threading.Lock()
        self._max = max_cases

    def take(self, case_id: str, limit: int, *, seed: bool) -> bool:
        cap = max(0, int(limit)) if seed else int(max(0, int(limit)) * (1 - SEED_RESERVE))
        with self._lock:
            used = self._cases.get(case_id, 0)
            if used >= cap:
                return False
            self._cases[case_id] = used + 1
            self._cases.move_to_end(case_id)
            while len(self._cases) > self._max:
                self._cases.popitem(last=False)
            return True

    def used(self, case_id: str) -> int:
        with self._lock:
            return self._cases.get(case_id, 0)

    def reset(self) -> None:
        with self._lock:
            self._cases.clear()


CASE_BUDGET = _CaseBudget()


class _NotRun(Exception):
    """A lookup the budget or the pacing deferred (c3)."""


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class VirusTotal(Module):
    name = "virustotal"
    title = "VirusTotal"
    description = (
        "Multi-engine verdicts ('N/M engines flagged') and capped relationships of IPs, domains, URLs and file "
        "hashes from the VirusTotal API v3 (GET lookups only; key and a licence required for business use)."
    )
    category = "threat_intel_ioc"
    accepts = {T.IPV4, T.IPV6, T.DOMAIN, T.URL, T.MD5, T.SHA1, T.SHA256}
    produces = {T.DOMAIN, T.IPV4, T.IPV6, T.URL, T.SHA256, T.MD5, T.SHA1}
    terms = "noncommercial"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "virustotal"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,)
    absent_statuses = frozenset({404})
    error_markers = (
        {"id": "virustotal_quota_exceeded", "statuses": [429], "json_path": "error.code", "equals": "QuotaExceededError",
         "maps_to": "quota", "reason_code": "quota",
         "reason": "VirusTotal: the key's minute/daily/monthly quota is exceeded (VT: not run (quota); deferred)"},
    )
    max_requests = 4
    expected_latency = 2.0
    timeout = 30.0
    cache_ttl = 86400
    max_pivots = 60
    manual_link = "threat_intel_g07_p2:vt_search"
    default_enabled = True
    tags = {"reputation"}
    reference = "https://docs.virustotal.com/reference/overview"
    settings = {
        CASE_SETTING: SettingSpec(CASE_DEFAULT, "VirusTotal lookups per scan (the last 20% kept for analyst-typed seeds; P158 c3)"),
        TRUSTED_SETTING: SettingSpec([], "engine names whose single malicious detection makes a VirusTotal verdict malicious (P158 c5)"),
        PAGE_SETTING: SettingSpec(PAGE_DEFAULT, "items read per VirusTotal relationship page (one page, at most 40; P158 c4)"),
    }
    notice = (
        "VirusTotal's public API must not be used in business workflows: the module is off under the corporate profile "
        "until licence-cleared (a VirusTotal premium/enterprise licence recorded in licence_allow); a public key runs only "
        "in the research profile. GET lookups only: files and URLs are never submitted, rescanned, commented or voted on. "
        "Public keys: 4 lookups per minute and 500 per day, 20 per scan; the scan never waits on VT (pending lookups are "
        "deferred). VirusTotal data stays internal: exports outside the company carry the verdict, link and source name only."
    )

    # ---- budget (c3) ------------------------------------------------------------------------------
    @staticmethod
    def _spend(ctx: Any) -> None:
        case_id = str(getattr(ctx, "case_id", "") or "")
        if not case_id:
            return
        try:
            limit = int(ctx.setting(CASE_SETTING, CASE_DEFAULT))
        except (TypeError, ValueError):
            limit = CASE_DEFAULT
        if not CASE_BUDGET.take(case_id, limit, seed=bool(getattr(ctx, "is_seed", True))):
            raise _NotRun(f"{NOT_RUN}: per-scan budget of {max(0, limit)} lookups used (setting {CASE_SETTING}; seeds first); deferred")

    def _get(self, ctx: Any, url: str, key: str, *, ttl: int | None = None) -> Any:
        if not request_allowed("GET", url):  # c2: never anything but a GET lookup
            raise RuntimeError("refused a non-allow-listed VirusTotal request (module bug)")
        interval = pacing_interval()
        if not PACER.claim(ctx.now(), interval):
            raise _NotRun(f"{NOT_RUN}: public API pacing (one lookup every {interval:.0f} s); deferred, the scan does not wait")
        self._spend(ctx)
        try:
            return ctx.http.get(url, headers={KEY_HEADER: key, "Accept": "application/json"}, source=SOURCE, ttl=ttl)
        except RateLimited as exc:
            if getattr(exc, "status", 0):
                raise  # a real HTTP 429 TooManyRequests: RATE_LIMITED
            # the provider's token bucket (4/min) or a back-off: never waited for in a worker (c3)
            raise _NotRun(f"{NOT_RUN}: public API pacing (4 lookups per minute); deferred, the scan does not wait") from None

    # ---- run ------------------------------------------------------------------------------------
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = str(ctx.key(KEY_NAME) or "").strip()
        if not key:
            return res.mark(Status.NEEDS_KEY, "needs a VirusTotal key (and, for business use, a VirusTotal licence)", reason_code="needs_key")
        url = object_url(entity)
        if url is None:
            return res.mark(Status.SKIPPED, "not a VirusTotal object type", reason_code="not_applicable")
        gui = gui_link(entity)
        try:
            resp = self._get(ctx, url, key)
        except _NotRun as exc:
            return res.mark(Status.QUOTA, str(exc), reason_code="quota")
        if resp.status == 404 and resp.classification is None:
            if gui:
                res.link("VirusTotal report", gui)
            return res.mark(Status.EMPTY, "unknown to VirusTotal (404 NotFoundError)")
        ctx.http.check(resp)  # 401/403 -> NEEDS_KEY, 429 -> RATE_LIMITED (QuotaExceededError -> QUOTA), challenges, 5xx
        obj, why = load_json(resp.content)
        if why:
            return res.mark(Status.ERROR, f"unexpected VirusTotal answer ({why}): could not verify", reason_code="error")
        if isinstance(obj, dict) and isinstance(obj.get("error"), dict):
            code = clean_text(obj["error"].get("code"), 60) or "error"
            if code == "NotAvailableYet":
                return res.mark(Status.ERROR, "VirusTotal: the object is not analysed yet (NotAvailableYet): could not verify", reason_code="error")
            return res.mark(Status.ERROR, f"VirusTotal error inside an HTTP 200 answer ({code}): could not verify", reason_code="error")
        parsed = parse_object(obj)
        if parsed is None:
            return res.mark(Status.ERROR, "unexpected VirusTotal answer (no data.attributes): could not verify", reason_code="error")
        if gui:
            res.link("VirusTotal report", gui)
        v = verdict(parsed["analysis"], ctx.setting(TRUSTED_SETTING, []) or [])
        self._report(res, entity, parsed, v, gui)
        if getattr(ctx, "is_seed", True) and int(getattr(ctx, "depth", 0) or 0) == 0:
            self._relationships(res, ctx, entity, key, v["band"])
        return res

    # ---- object (c5, c6) ----------------------------------------------------------------------------
    def _report(self, res: ModuleResult, entity: Entity, p: dict[str, Any], v: dict[str, Any], gui: str | None) -> None:
        a = p["analysis"]
        eicar = entity.type in (T.MD5, T.SHA1, T.SHA256) and (entity.value.lower() in EICAR or (p.get("sha256") or "") in EICAR)
        summary = {
            "type": p["type"], "verdict": v["band"], "wording": v["wording"], "analysis": {k: a[k] for k in (*COUNTED, "timeout", "total", "date")},
            "top_labels": a["top_labels"], "reputation": p.get("reputation"), "votes": p.get("votes"), "tags": p.get("tags"),
            "categories": p.get("categories"), "threat_label": p.get("threat_label"), "link": gui,
        }
        res.raw = {"status": 200, "object": {k: val for k, val in p.items() if k not in ("analysis",)}, "analysis": a}
        res.attr("virustotal", {k: val for k, val in summary.items() if val not in (None, [], {})})
        res.attr("reputation", {"virustotal": f"{a['malicious']}/{a['total']}"})
        res.attr("data_attribution", ATTRIBUTION)
        res.attr("export_restriction", {"source": ATTRIBUTION, "redistributable": False,
                                        "external_exports": "verdict, link and source name only", "verdict": v["wording"], "link": gui or ""})
        res.attr("tags", p.get("tags"))
        if p["type"] == "ip_address":
            if p.get("asn"):
                res.attr("asn", f"AS{p['asn']}")
            res.attr("as_org", p.get("as_owner"))
            country = p.get("country")
            res.attr("country", country.upper() if country and re.fullmatch(r"[A-Za-z]{2}", country) else None)
        elif p["type"] == "domain":
            res.attr("registrar", p.get("registrar"))
            res.attr("created", p.get("creation_date"))
        elif p["type"] == "file":
            for kind in ("md5", "sha1", "sha256"):
                res.attr(kind, p.get(kind))
            res.attr("file_size", p.get("size"))
            res.attr("file_type", p.get("type_description"))
            res.attr("malware_family", p.get("threat_names") or None)
            for kind, etype in (("md5", T.MD5), ("sha1", T.SHA1), ("sha256", T.SHA256)):
                other = p.get(kind)
                if other and other != entity.value.lower():
                    res.pivot(etype, other, "same_file", confidence="confirmed", expand=False,
                              note="the same file as reported by VirusTotal (listed, not re-queried)")
        elif p["type"] == "url":
            final = p.get("final_url")
            if final and final != entity.value:
                res.pivot(T.URL, final, "redirects_to", confidence="probable", expand=False,
                          note="final URL VirusTotal reached for this URL (not fetched by V3LUM)")
        band = v["band"]
        if band == "none":
            return
        description = v["wording"] + "."
        if v["trusted_vendor_hits"]:
            description += f" Trusted vendor(s): {', '.join(v['trusted_vendor_hits'])}."
        common = {"references": [gui] if gui else [], "source": SOURCE, "observed_last": a.get("date"),
                  "data": {"band": band, "malicious": a["malicious"], "suspicious": a["suspicious"], "total": a["total"],
                           "top_labels": a["top_labels"], "last_analysis": a.get("date"), "upstream_families": ["virustotal"]}}
        if eicar:
            res.finding("EICAR test file (VirusTotal)", "info",
                        description + " This is the EICAR anti-virus test file: detections are expected and not an incident.",
                        tags=["test_file"], **common)
            return
        hostile = ["malware"] if p["type"] == "file" else []
        if any("phish" in label.lower() for label in a["top_labels"]) or any("phish" in c.lower() for c in p.get("categories") or []):
            hostile.append("phishing")
        if band == "malicious":
            res.finding("Malicious on VirusTotal", "high", description, confidence="probable",
                        criterion=f"VirusTotal: {a['malicious']} engines flagged it malicious (>= 5"
                                  + (", or a configured trusted vendor" if v["trusted_vendor_hits"] else "") + ")",
                        tags=["malicious", *hostile], **common)
        elif band == "suspicious":
            res.finding("Suspicious on VirusTotal", "medium", description, confidence="possible",
                        criterion=f"VirusTotal: {a['malicious']} engines flagged it malicious (3-4)", tags=["suspicious"], **common)
        else:
            res.finding("Few engines flag it on VirusTotal", "low", description + " Few engines: a weak signal on its own.",
                        confidence="possible", criterion=f"VirusTotal: {a['malicious']} engine(s) flagged it malicious (1-2)",
                        tags=["suspicious", "weak_signal"], **common)

    # ---- relationships (c4) ---------------------------------------------------------------------------
    def _relationships(self, res: ModuleResult, ctx: Any, entity: Entity, key: str, band: str) -> None:
        collection = COLLECTIONS.get(entity.type, "")
        try:
            size = int(ctx.setting(PAGE_SETTING, PAGE_DEFAULT))
        except (TypeError, ValueError):
            size = PAGE_DEFAULT
        size = max(1, min(PAGE_MAX, size))
        summary: dict[str, Any] = {}
        expand = band == "malicious"
        for rel in RELATIONSHIPS.get(collection, ()):
            url = relationship_url(entity, rel, size)
            if url is None:
                continue
            try:
                resp = self._get(ctx, url, key, ttl=RELATIONSHIP_TTL)
            except (_NotRun, QuotaExceeded) as exc:
                summary[rel] = {"read": False, "reason": str(exc)[:160]}
                break  # pacing/budget: the remaining pages are not read either (the object verdict stands)
            if resp.status == 404 and resp.classification is None:
                summary[rel] = {"read": True, "items": 0}
                continue
            if resp.status != 200 or resp.classification is not None:
                summary[rel] = {"read": False, "reason": f"HTTP {resp.status}: could not verify"}
                continue
            obj, why = load_json(resp.content)
            page = parse_collection(obj, size) if not why else None
            if page is None:
                summary[rel] = {"read": False, "reason": why or "unexpected page: could not verify"}
                continue
            filtered = self._pivot_page(res, entity, collection, rel, page, expand)
            summary[rel] = {"read": True, "items": len(page["items"]), "filtered": filtered, "count": page["count"], "more": page["more"]}
        if summary:
            res.attr("vt_relationships", summary)

    @staticmethod
    def _pivot_page(res: ModuleResult, entity: Entity, collection: str, rel: str, page: dict[str, Any], expand: bool) -> int:
        filtered = 0
        why = "" if expand else " (listed, not expanded: the object itself is not malicious)"
        for item in page["items"]:
            if item["type"] == "resolution":
                if collection == "domains":
                    etype = T.IPV6 if ":" in item["ip"] else T.IPV4
                    if is_listed_noise(etype, item["ip"]):
                        filtered += 1
                        continue
                    res.pivot(etype, item["ip"], "historical_a_record", confidence="probable", expand=expand,
                              note=f"resolution seen by VirusTotal on {(item['date'] or '?')[:10]}{why}")
                elif collection == "ip_addresses":
                    if is_listed_noise(T.DOMAIN, item["host"]):
                        filtered += 1
                        continue
                    res.pivot(T.DOMAIN, item["host"], "hosted_domain", confidence="probable", expand=expand,
                              note=f"resolution seen by VirusTotal on {(item['date'] or '?')[:10]}{why}")
                continue
            etype = {"domain": T.DOMAIN, "url": T.URL, "sha256": T.SHA256}.get(item["type"])
            if item["type"] == "ip":
                etype = T.IPV6 if ":" in item["value"] else T.IPV4
            if etype is None:
                continue
            if etype is not T.SHA256 and is_listed_noise(etype, item["value"]):
                filtered += 1
                continue
            if rel == "subdomains":
                relation, confidence = "subdomain", "probable"
            elif rel == "communicating_files":
                relation, confidence = "contacted_by", "possible"
            else:
                relation, confidence = "communicates_with", "possible"
            flagged = f"; {item['malicious']} engines flag it" if item.get("malicious") else ""
            res.pivot(etype, item["value"], relation, confidence=confidence, expand=expand,
                      note=f"VirusTotal {rel}{flagged}{why}")
        return filtered
