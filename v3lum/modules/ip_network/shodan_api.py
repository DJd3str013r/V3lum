"""shodan_api: host banners, DNS sub-domains and seed-only searches from the Shodan REST API (keyed) (P039).

Batch p2-G02-1, proposal P039 (approved, P2). Final conditions implemented here:

* c1 - requires key ``shodan``. Shodan accepts the key only as ``?key=`` in the URL, so every URL is
  built by :func:`shodan_url` and the core redactor (AR01) masks it in the cache url column, events and
  the live feed, logs, errors, evidence and reports (``key`` is a KEY_PARAMS name and the configured
  value is a registered secret); the module never copies a request URL into its results.
* c2 - key-terms: the policy gate runs it under the corporate profile only with ``key_plans.shodan =
  'business'``. Membership, academic and free keys are noncommercial: when ``/api-info`` reports such a
  plan code under the corporate profile the run is SKIPPED 'licence' (with a warning when the recorded
  plan says 'business'); under the research profile they follow licence_allow/research.
* c3 - ``/api-info`` is read at most once per day (``ctx.state``, per key fingerprint): plan and
  query/scan credits are kept for doctor, enforced as a credit budget (setting
  ``shodan_api_credit_reserve``) and shown in coverage with every run (per-source line).
* c4 - endpoints: ``host/{ip}?minify=true`` by default (setting ``shodan_api_minify``);
  ``dns/domain/{domain}`` for sub-domains (one page, registrable domains only, credit-gated), each
  candidate validated through the P016 DoH + wildcard pipeline before it is listed as live or pivoted;
  ``host/search`` (``http.favicon.hash:``, ``ssl.cert.fingerprint:`` or the analyst's keyword) only
  for analyst-typed seeds and only when the plan and the credits allow.
* c5 - on-demand scan endpoints (``/shodan/scan``, ``/shodan/scan/internet``) and anything outside
  :data:`ENDPOINTS` are never wired: :func:`shodan_url` refuses to build them
  (:class:`ShodanEndpointRefused`), with or without a key.
* c6 - banner timestamps become ``observed_last`` (latest banner, else ``last_update``). Banner
  vulnerabilities are version-inferred: one finding, POSSIBLE (confidence 0.5), severity from CVSS
  capped at HIGH (never CRITICAL from Shodan alone), CVE pivots at confidence 0.5.
* c7 - keyless answers (Shodan answers some demo IPs without a key) are never relied on: without the
  key the engine reports NEEDS_KEY and nothing is sent. The Cloudflare-challenged web view is a link only.

Error mapping: 401/403 'Invalid API key' -> NEEDS_KEY ('invalid key'); 401/403 'requires membership'
-> NEEDS_KEY ('the plan does not include this endpoint'); 'Insufficient query credits' -> QUOTA;
429 or the rate-limit text -> RATE_LIMITED; challenge pages -> BLOCKED; 404 'No information
available' -> EMPTY; anything else, including an error object in a 200 answer -> ERROR.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

from v3lum.config import SettingSpec
from v3lum.core import noise
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.context import StateError
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
from v3lum.core.noise import is_public_ip
from v3lum.core.psl import registrable_domain
from v3lum.modules.ip_network.shodan_internetdb import BAD_TAGS, MAX_EXPANDED_HOSTNAMES, RISKY_PORTS, SHARED_KINDS, TAG_ATTRIBUTES

try:  # P016 DoH + wildcard pipeline (c4); without it sub-domain candidates are listed, never pivoted
    from v3lum.modules.domain_dns.subdomains_passive import probe_wildcard, resolution_order, resolve_one
except Exception:  # noqa: BLE001 - an import problem of the helper module must not break this module
    probe_wildcard = resolution_order = resolve_one = None  # type: ignore[assignment]

SOURCE = "shodan.api"
KEY = "shodan"
API = "https://api.shodan.io"
WEB_HOST = "https://www.shodan.io/host/{ip}"
ATTRIBUTION = "Host and banner data: Shodan (https://www.shodan.io), used under the team's Shodan API licence"
#: endpoint -> (path template, allowed query parameters, query-credit cost per call). Nothing else is ever built (c4/c5).
ENDPOINTS: dict[str, tuple[str, frozenset[str], int]] = {
    "host": ("/shodan/host/{ip}", frozenset({"minify", "history"}), 0),
    "dns_domain": ("/dns/domain/{domain}", frozenset({"page"}), 1),
    "search": ("/shodan/host/search", frozenset({"query", "page", "minify"}), 1),
    "api_info": ("/api-info", frozenset(), 0),
}
#: /api-info plan codes of membership, academic and free keys: noncommercial under corporate (c2).
NONCOMMERCIAL_PLANS = frozenset({"oss", "dev", "edu", "free", "membership", "academic"})
#: the free plan cannot run filtered searches
NO_SEARCH_PLANS = frozenset({"oss", "free"})
API_INFO_INTERVAL = 86400.0  # c3: at most once per day
API_INFO_RETRY = 3600.0  # a failed /api-info read is retried after an hour, not on every run
DNS_VALIDATE_CAP = 50  # sub-domain candidates resolved through the P016 pipeline per run
SUBDOMAIN_PIVOT_CAP = 12  # P016 cond 8
SEARCH_PIVOT_CAP = 20
SERVICE_CAP = 50
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CVE_LABEL = "version-inferred from Shodan banner data, distro backports not considered"
SEVERITY_ORDER = ("info", "low", "medium", "high")


class ShodanEndpointRefused(ValueError):
    """An endpoint this module never wires (on-demand scans, alerts, anything outside ENDPOINTS: c5)."""


def shodan_url(endpoint: str, key: str, **params: Any) -> str:
    """The URL of one wired endpoint (c1/c4/c5). Raises ShodanEndpointRefused for scan endpoints and any
    endpoint outside :data:`ENDPOINTS`, with or without a key; ValueError for a missing key, a bad value
    or an unexpected parameter. The key travels as ``?key=`` (Shodan accepts nothing else)."""
    name = str(endpoint or "").strip()
    words = set(re.split(r"[^a-z]+", name.lower()))
    if "scan" in words or "scans" in words or name.startswith("/"):
        raise ShodanEndpointRefused(f"Shodan endpoint {name!r} is never wired: on-demand scans make Shodan probe the target outside the request ledger and publish the results to every Shodan user (P039 cond 5)")
    if name not in ENDPOINTS:
        raise ShodanEndpointRefused(f"Shodan endpoint {name!r} is not wired in this module (allowed: {', '.join(sorted(ENDPOINTS))})")
    if not isinstance(key, str) or not key.strip():
        raise ValueError("Shodan key 'shodan' is not configured: keyless answers are never relied on (P039 cond 7)")
    template, allowed, _cost = ENDPOINTS[name]
    values = dict(params)
    path = template
    if "{ip}" in template:
        ip = str(values.pop("ip", "") or "")
        if not is_public_ip(ip):
            raise ValueError("Shodan host lookups take a public IP address")
        path = template.format(ip=ip)
    elif "{domain}" in template:
        dom = str(values.pop("domain", "") or "").strip().lower().rstrip(".")
        if not dom or Entity.try_make(T.DOMAIN, dom) is None:
            raise ValueError("Shodan dns/domain takes a domain name")
        path = template.format(domain=dom)
    extra = sorted(set(values) - allowed)
    if extra:
        raise ValueError(f"parameters not allowed for Shodan {name}: {', '.join(extra)}")
    query = [("key", key.strip())] + [(k, str(v).lower() if isinstance(v, bool) else str(v)) for k, v in sorted(values.items()) if v is not None]
    return f"{API}{path}?{urlencode(query)}"


def search_query(etype: T, value: str) -> str | None:
    """Seed-only search query (c4): favicon hash, certificate fingerprint or the analyst's keyword."""
    if etype is T.FAVICON_HASH:
        try:
            n = int(str(value).strip())
        except ValueError:
            return None
        return f"http.favicon.hash:{n}" if -(2**31) <= n < 2**31 else None
    if etype is T.CERT_FP:
        hexval = re.sub(r"[^0-9a-f]", "", str(value).lower())
        return f"ssl.cert.fingerprint:{hexval}" if len(hexval) in (40, 64) else None
    if etype is T.KEYWORD:
        text = " ".join(str(value).split())
        return text[:200] if text else None
    return None


def search_cost(query: str, page: int = 1) -> int:
    """Query credits of one search page: 1 when the query has a filter or the page is past the first."""
    return 1 if (":" in query or page > 1) else 0


def vuln_severity(cvss: float | None) -> str:
    """c6 / P291: version-inferred banner vulns are capped at HIGH (CVSS >= 9 is never CRITICAL here)."""
    if cvss is None:
        return "medium"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low" if cvss > 0 else "info"


# --------------------------------------------------------------------------------------
# parsing helpers (untrusted data: every field is type-checked)
# --------------------------------------------------------------------------------------


def _json(content: bytes) -> Any:
    try:
        return json.loads(content.decode("utf-8", errors="replace"))
    except (ValueError, RecursionError):
        return None


def _text(value: Any, limit: int = 200) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?\d{1,12}", value.strip()):
        return int(value.strip())
    return None


def _float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        out = float(value)
    except ValueError:
        return None
    return out if out == out else None


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _ts(value: Any) -> str | None:
    """'2026-11-25T15:26:44.605151' -> '2026-11-25T15:26:44Z' (Shodan timestamps are UTC)."""
    m = re.match(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})", _text(value, 40))
    return f"{m.group(1)}T{m.group(2)}Z" if m else None


def _cert_date(value: Any) -> str | None:
    m = re.match(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$", _text(value, 20))
    return "{}-{}-{}T{}:{}:{}Z".format(*m.groups()) if m else None


def _domain(value: Any) -> str | None:
    text = _text(value, 253).lower().rstrip(".")
    if not text or text.startswith("*"):
        return None
    ent = Entity.try_make(T.DOMAIN, text)
    return ent.value if ent is not None else None


def parse_host(data: dict[str, Any]) -> dict[str, Any]:
    """host/{ip} answer (minified or full) -> services, vulns and pivot candidates (c4, c6)."""
    services: list[dict[str, Any]] = []
    stamps: list[str] = []
    vulns: dict[str, dict[str, Any]] = {}
    certs: dict[str, dict[str, Any]] = {}
    cpes: list[str] = []
    banners = data.get("data")
    for banner in _list(banners)[:SERVICE_CAP]:
        if not isinstance(banner, dict):
            continue
        ts = _ts(banner.get("timestamp"))
        if ts:
            stamps.append(ts)
        http = _dict(banner.get("http"))
        ssl = _dict(banner.get("ssl"))
        cert = _dict(ssl.get("cert"))
        fp = _dict(cert.get("fingerprint"))
        cpe = [c for c in (_list(banner.get("cpe23")) or _list(banner.get("cpe"))) if isinstance(c, str) and c.startswith("cpe:")][:5]
        for c in cpe:
            if c not in cpes:
                cpes.append(c)
        sha256 = _text(fp.get("sha256"), 64).lower()
        svc = {
            "port": _int(banner.get("port")),
            "transport": _text(banner.get("transport"), 8),
            "module": _text(_dict(banner.get("_shodan")).get("module"), 40),
            "product": _text(banner.get("product"), 100),
            "version": _text(banner.get("version"), 50),
            "cpe": cpe,
            "timestamp": ts,
            "http_title": _text(http.get("title"), 200),
            "http_server": _text(http.get("server"), 200),
            "favicon_hash": _int(_dict(http.get("favicon")).get("hash")),
            "cert_sha256": sha256 if SHA256_RE.match(sha256) else "",
            "cert_subject_cn": _text(_dict(cert.get("subject")).get("CN"), 255),
            "cert_issuer": _text(_dict(cert.get("issuer")).get("O"), 200) or _text(_dict(cert.get("issuer")).get("CN"), 200),
            "cert_expires": _cert_date(cert.get("expires")),
            "jarm": _text(ssl.get("jarm"), 62),
            "ja3s": _text(ssl.get("ja3s"), 32),
        }
        services.append({k: v for k, v in svc.items() if v not in (None, "", [])})
        if svc["cert_sha256"]:
            certs.setdefault(svc["cert_sha256"], svc)
        for cve, info in _dict(banner.get("vulns")).items():
            cid = str(cve).strip().upper()
            if not CVE_RE.match(cid):
                continue
            entry = vulns.setdefault(cid, {"cve": cid, "cvss": None, "verified_by_shodan": False, "ports": set(), "products": set()})
            score = _float(_dict(info).get("cvss"))
            if score is not None and (entry["cvss"] is None or score > entry["cvss"]):
                entry["cvss"] = score
            entry["verified_by_shodan"] = entry["verified_by_shodan"] or _dict(info).get("verified") is True
            if svc["port"]:
                entry["ports"].add(svc["port"])
            if svc["product"]:
                entry["products"].add(" ".join(x for x in (svc["product"], svc["version"]) if x))
    top = data.get("vulns")
    for cve in top if isinstance(top, list) else list(_dict(top)):
        cid = str(cve).strip().upper()
        if CVE_RE.match(cid):
            vulns.setdefault(cid, {"cve": cid, "cvss": None, "verified_by_shodan": False, "ports": set(), "products": set()})
    ports = sorted({p for p in (_int(x) for x in _list(data.get("ports"))) if p is not None and 0 < p < 65536})
    if not ports:
        ports = sorted({s["port"] for s in services if isinstance(s.get("port"), int) and 0 < s["port"] < 65536})
    last_update = _ts(data.get("last_update"))
    hostnames: list[str] = []
    for value in _list(data.get("hostnames")) + _list(data.get("domains")):
        dom = _domain(value)
        if dom and dom not in hostnames:
            hostnames.append(dom)
    asn = _text(data.get("asn"), 20).upper()
    return {
        "ip": _text(data.get("ip_str"), 64),
        "asn": asn if re.fullmatch(r"AS\d{1,10}", asn) else "",
        "org": _text(data.get("org")),
        "isp": _text(data.get("isp")),
        "os": _text(data.get("os"), 100),
        "country": _text(data.get("country_code"), 2).upper(),
        "city": _text(data.get("city"), 100),
        "tags": sorted({t.strip().lower() for t in _list(data.get("tags")) if isinstance(t, str) and t.strip()})[:30],
        "ports": ports,
        "hostnames": hostnames[:50],
        "services": services,
        "cpes": cpes[:50],
        "certs": certs,
        "vulns": [
            {**v, "ports": sorted(v["ports"]), "products": sorted(v["products"]), "severity": vuln_severity(v["cvss"])}
            for _cid, v in sorted(vulns.items())
        ],
        "last_update": last_update,
        "observed_last": max(stamps) if stamps else last_update,
        "minified": not isinstance(banners, list),
    }


def parse_dns_domain(data: dict[str, Any], domain: str) -> dict[str, Any]:
    """dns/domain answer -> sub-domain candidates, wildcard names and records (c4)."""
    apex = _domain(data.get("domain")) or domain
    names: list[str] = []
    wildcards: list[str] = []
    for sub in _list(data.get("subdomains")):
        label = _text(sub, 200).lower().rstrip(".")
        if not label:
            continue
        if label.startswith("*"):
            wildcards.append(f"{label}.{apex}")
            continue
        fq = _domain(f"{label}.{apex}")
        if fq and fq not in names:
            names.append(fq)
    records: list[dict[str, Any]] = []
    for rec in _list(data.get("data"))[:500]:
        if not isinstance(rec, dict):
            continue
        label = _text(rec.get("subdomain"), 200).lower()
        if label.startswith("*"):
            continue
        fq = _domain(f"{label}.{apex}") if label else apex
        records.append({"name": fq, "type": _text(rec.get("type"), 10), "value": _text(rec.get("value"), 300),
                        "last_seen": _ts(rec.get("last_seen"))})
        if fq and fq != apex and fq not in names:
            names.append(fq)
    return {"domain": apex, "names": names, "wildcards": wildcards, "records": records, "more": data.get("more") is True}


def _profile(ctx: Any) -> str:
    value = str(getattr(getattr(ctx, "options", None), "licence_profile", "") or "") or str(ctx.setting("licence_profile", "corporate") or "")
    return value.strip().lower() or "corporate"


def _age_seconds(stamp: Any, now: datetime) -> float | None:
    try:
        then = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return (now - then).total_seconds()


def _iso(now: datetime) -> str:
    return now.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _state_get(ctx: Any, key: str) -> Any:
    try:
        return ctx.state.get(key)
    except (StateError, OSError):
        return None


def _state_set(ctx: Any, key: str, value: Any) -> None:
    """Best-effort bookkeeping (the credit snapshot): a state problem never fails the lookup."""
    try:
        if value is None:
            ctx.state.delete(key)
        else:
            ctx.state.set(key, value)
    except (StateError, OSError):
        pass


class _Stop(Exception):
    """Ends a run with a status (raised inside run(), caught there)."""

    def __init__(self, status: Status, reason: str, code: str = "") -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.code = code


@register
class ShodanApi(Module):
    name = "shodan_api"
    title = "Shodan API (host, DNS, seed searches)"
    description = (
        "Host banners, ports, certificates and version-inferred CVEs for an IP, validated sub-domains for a domain and "
        "seed-only favicon/certificate/keyword searches from the Shodan REST API (team key)."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6, T.DOMAIN, T.FAVICON_HASH, T.CERT_FP, T.KEYWORD}
    produces = {T.DOMAIN, T.CVE, T.CERT_FP, T.IPV4, T.IPV6}
    tags = {"core"}
    reference = "https://developer.shodan.io/api"
    notice = (
        "Needs a company-held Shodan API subscription covering internal commercial use (key 'shodan' recorded with "
        "--plan business); membership, academic and free keys are noncommercial under the corporate profile. The key "
        "travels as ?key= and is masked everywhere by the central redactor. /api-info is read at most once a day; "
        "dns/domain pages and searches spend query credits and stop at the reserve (shodan_api_credit_reserve); searches "
        "run only for analyst-typed seeds. On-demand scans are never requested. Banner CVEs are version-inferred."
    )
    # ---- contract v2 declarations --------------------------------------------------------
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "shodan"
    sources = (SOURCE,)
    hosts = ("api.shodan.io",)
    access_model = "free_auth_limited"
    requires_keys = (KEY,)
    max_requests = 3  # /api-info (at most once a day) + host | dns/domain page | one seed search
    expected_latency = 1.5
    min_interval = 1.1  # documented limit: 1 request per second
    timeout = 60.0
    cache_ttl = 86400
    manual_link = "core_reference:shodan_host"
    default_enabled = True
    settings = {
        "shodan_api_minify": SettingSpec(True, "shodan_api: host lookups with minify=true (ports and host facts, no banners; P039 cond 4)"),
        "shodan_api_credit_reserve": SettingSpec(10, "shodan_api: query credits kept unspent; dns/domain pages and searches stop at this reserve (P039 cond 3)"),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type in (T.IPV4, T.IPV6):
            return is_public_ip(entity.value)  # private/reserved/documentation space: never sent
        if entity.type in (T.FAVICON_HASH, T.CERT_FP, T.KEYWORD):
            return bool(getattr(ctx, "is_seed", False)) and search_query(entity.type, entity.value) is not None  # c4: seeds only
        return True

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = ctx.key(KEY)
        if not key:  # the engine reports NEEDS_KEY before the run; keyless answers are never used (c7)
            return res.mark(Status.NEEDS_KEY, "Shodan key 'shodan' is not configured: keyless answers are never relied on", reason_code="needs_key")
        try:
            info, info_problem = self._api_info(ctx, key)
            self._plan_check(ctx, info)
            if entity.type in (T.IPV4, T.IPV6):
                self._host(res, ctx, key, entity.value)
            elif entity.type is T.DOMAIN:
                self._dns_domain(res, ctx, key, entity.value, info, info_problem)
            else:
                self._search(res, ctx, key, entity, info, info_problem)
        except _Stop as stop:
            res.mark(stop.status, stop.reason, reason_code=stop.code)
        self._coverage(res, ctx)
        return res

    # ------------------------------------------------------------------ requests
    def _get(self, ctx: Any, url: str, *, ttl: float | None = None, absent_marker: str = "") -> tuple[Any, bool]:
        """GET one Shodan URL -> (parsed JSON or None for the documented 404, from_cache). Raises _Stop."""
        try:
            kw: dict[str, Any] = {"source": SOURCE, "headers": {"Accept": "application/json"}}
            if ttl is not None:
                kw["ttl"] = ttl
            resp = ctx.http.get(url, **kw)
            if resp.status == 404 and absent_marker:
                body = _json(resp.content)
                if isinstance(body, dict) and absent_marker in str(body.get("error", "")).lower():
                    return None, bool(resp.from_cache)
            ctx.http.check(resp)  # 401/403/429/5xx, challenge pages and the module error markers raise
        except AuthRequired as exc:
            text = (getattr(exc, "body", "") or "").lower()
            if "credit" in text:
                raise _Stop(Status.QUOTA, "Shodan: query credits exhausted", "quota") from exc
            if "membership" in text or "upgrade" in text or "access denied" in text or "plan" in text:
                raise _Stop(Status.NEEDS_KEY, f"Shodan: the key's plan does not include this endpoint (HTTP {exc.status})", "needs_key") from exc
            raise _Stop(Status.NEEDS_KEY, f"Shodan rejected the key (HTTP {exc.status}): invalid key - check `v3lum keys`", "needs_key") from exc
        data = _json(resp.content)
        if isinstance(data, dict) and isinstance(data.get("error"), str):
            text = data["error"].lower()
            if "credit" in text:
                raise _Stop(Status.QUOTA, "Shodan: query credits exhausted", "quota")
            if "invalid api key" in text:
                raise _Stop(Status.NEEDS_KEY, "Shodan rejected the key: invalid key", "needs_key")
            raise _Stop(Status.ERROR, f"Shodan error in a 200 answer ({data['error'][:120]}): could not verify", "error")
        if data is None:
            raise _Stop(Status.ERROR, "unexpected Shodan answer (not JSON): could not verify", "error")
        return data, bool(resp.from_cache)

    def _api_info(self, ctx: Any, key: str) -> tuple[dict[str, Any] | None, _Stop | None]:
        """c3: the cached /api-info snapshot (per key fingerprint, at most one read per day)."""
        key_id = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
        now = ctx.now()
        state = _state_get(ctx, "api_info") or {}
        if isinstance(state, dict) and state.get("key_id") == key_id:
            age = _age_seconds(state.get("checked_at"), now)
            if age is not None and 0 <= age < API_INFO_INTERVAL:
                return state, None
        failed = _state_get(ctx, "api_info_failed") or {}
        if isinstance(failed, dict) and failed.get("key_id") == key_id:
            age = _age_seconds(failed.get("at"), now)
            if age is not None and 0 <= age < API_INFO_RETRY:
                return None, _Stop(Status(failed.get("status") or "error"), str(failed.get("reason") or "Shodan /api-info could not be read"),
                                   str(failed.get("code") or ""))
        try:
            data, _cached = self._get(ctx, shodan_url("api_info", key), ttl=0)
        except _Stop as stop:
            if stop.status is Status.NEEDS_KEY:
                raise  # an invalid key ends the run
            _state_set(ctx, "api_info_failed", {"key_id": key_id, "at": _iso(now), "status": stop.status.value, "code": stop.code,
                                              "reason": f"Shodan /api-info: {stop.reason}"[:300]})
            return None, _Stop(stop.status, f"Shodan /api-info: {stop.reason}", stop.code)
        except (RateLimited, QuotaExceeded, Blocked, HttpError, NetworkError) as exc:
            if isinstance(exc, (DeadlineExceeded, OfflineError)):
                raise  # the engine maps these (ERROR timeout / UNAVAILABLE offline); never recorded as an /api-info failure
            status, code = _status_of(exc)
            reason = f"Shodan /api-info could not be read ({type(exc).__name__}): credit budget unknown"
            _state_set(ctx, "api_info_failed", {"key_id": key_id, "at": _iso(now), "status": status.value, "code": code, "reason": reason})
            return None, _Stop(status, reason, code)
        if not isinstance(data, dict):
            return None, _Stop(Status.ERROR, "unexpected Shodan /api-info answer: credit budget unknown", "error")
        limits = {k: v for k, v in _dict(data.get("usage_limits")).items() if isinstance(k, str) and _int(v) is not None}
        info = {
            "key_id": key_id,
            "checked_at": _iso(now),
            "plan": _text(data.get("plan"), 40),
            "query_credits": _int(data.get("query_credits")),
            "scan_credits": _int(data.get("scan_credits")),
            "monitored_ips": _int(data.get("monitored_ips")),
            "unlocked_left": _int(data.get("unlocked_left")),
            "usage_limits": {k: _int(v) for k, v in limits.items()},
            "spent": 0,
        }
        _state_set(ctx, "api_info", info)
        _state_set(ctx, "api_info_failed", None)
        return info, None

    def _plan_check(self, ctx: Any, info: dict[str, Any] | None) -> None:
        """c2: membership/academic/free plan codes are noncommercial under the corporate profile."""
        if not info:
            return
        plan = str(info.get("plan") or "").lower()
        if plan in NONCOMMERCIAL_PLANS and _profile(ctx) == "corporate":
            warn = ""
            if ctx.key_plan(KEY) == "business":
                warn = " - key_plans.shodan is 'business' but /api-info reports a membership/academic/free plan: fix the recorded plan (doctor warning)"
            raise _Stop(Status.SKIPPED, f"skipped: Shodan plan '{plan}' is a membership/academic/free plan, noncommercial under the corporate profile (P039 cond 2){warn}", "licence")

    def _budget(self, ctx: Any, info: dict[str, Any] | None, problem: _Stop | None, cost: int) -> None:
        """c3: raise _Stop unless ``cost`` credits can be spent above the reserve."""
        if cost <= 0:
            return
        if info is None:
            stop = problem or _Stop(Status.ERROR, "Shodan /api-info could not be read: credit budget unknown", "error")
            raise _Stop(stop.status, f"{stop.reason}; credit-spending calls are not sent", stop.code)
        credits = info.get("query_credits")
        if not isinstance(credits, int):
            raise _Stop(Status.ERROR, "Shodan /api-info did not report query credits: credit budget unknown", "error")
        reserve = max(0, _int(ctx.setting("shodan_api_credit_reserve", 10)) or 0)
        left = credits - int(info.get("spent") or 0)
        if left - cost < reserve:
            raise _Stop(Status.QUOTA, f"Shodan query credit budget reached ({left} left, reserve {reserve})", "quota")

    def _spend(self, ctx: Any, info: dict[str, Any] | None, cost: int) -> None:
        if info is None or cost <= 0:
            return
        info["spent"] = int(info.get("spent") or 0) + cost
        _state_set(ctx, "api_info", info)

    # ------------------------------------------------------------------ host (c4, c6)
    def _host(self, res: ModuleResult, ctx: Any, key: str, ip: str) -> None:
        minify = bool(ctx.setting("shodan_api_minify", True))
        data, _cached = self._get(ctx, shodan_url("host", key, ip=ip, minify=minify), absent_marker="no information available")
        reference = WEB_HOST.format(ip=ip)
        if data is None:
            res.raw = {"status": 404, "detail": "No information available"}
            res.link("Shodan host page", reference)
            raise _Stop(Status.EMPTY, "Shodan has no information for this IP (not seen by its scanners; says nothing about open ports)")
        if not isinstance(data, dict):
            raise _Stop(Status.ERROR, f"unexpected Shodan host answer ({type(data).__name__}): could not verify", "error")
        host = parse_host(data)
        res.raw = {k: v for k, v in host.items() if k != "certs"}
        if not (host["ports"] or host["services"] or host["hostnames"]):
            raise _Stop(Status.EMPTY, "Shodan answered without ports, services or hostnames")
        observed = host["observed_last"]
        res.attr("open_ports", host["ports"])
        res.attr("hostnames", host["hostnames"])
        res.attr("services", host["services"])
        res.attr("cpes", host["cpes"])
        res.attr("vulns", [v["cve"] for v in host["vulns"]])
        res.attr("tags", host["tags"])
        res.attr("org", host["org"])
        res.attr("isp", host["isp"])
        res.attr("asn", host["asn"])
        res.attr("country", host["country"])
        res.attr("city", host["city"])
        res.attr("host_os", host["os"])
        res.attr("last_seen", observed)
        res.attr("data_attribution", ATTRIBUTION)
        for tag in host["tags"]:
            if tag in TAG_ATTRIBUTES:
                res.attr(TAG_ATTRIBUTES[tag], True)
        kinds = set(noise.noise_kinds(res.entity))
        shared = bool({"cdn", "cloud"} & set(host["tags"])) or bool(kinds & SHARED_KINDS) or len(host["hostnames"]) > MAX_EXPANDED_HOSTNAMES
        if shared:
            res.attr("shared_ip", True)
        for name in host["hostnames"][:25]:
            res.pivot(T.DOMAIN, name, "hosted_domain", confidence=0.5 if shared else 0.8, expand=not shared,
                      note="co-tenant of a shared/CDN IP, not the target" if shared else "Shodan hostname")
        for sha, svc in sorted(host["certs"].items())[:10]:
            res.pivot(T.CERT_FP, sha, "serves_certificate", confidence="probable", expand=False,
                      note=f"TLS certificate seen by Shodan on port {svc.get('port')}")
            cn = _domain(svc.get("cert_subject_cn"))
            if cn and cn not in host["hostnames"]:
                res.pivot(T.DOMAIN, cn, "cert_subject", confidence="possible", expand=False, note="certificate subject CN (Shodan banner)")
        when = f"last seen {observed}" if observed else "last seen unknown"
        if host["ports"]:
            res.finding(
                "Open ports observed by Shodan",
                "info",
                f"{len(host['ports'])} open port(s) ({when}): {', '.join(str(p) for p in host['ports'][:20])}.",
                data={"ports": host["ports"], "minified": host["minified"]},
                tags=["exposure"],
                references=[reference],
                source=SOURCE,
                observed_last=observed,
            )
        risky = {p: RISKY_PORTS[p] for p in host["ports"] if p in RISKY_PORTS}
        if risky:
            res.finding(
                "Sensitive services exposed to the internet",
                "medium",
                "Databases, remote desktops and admin interfaces should not be reachable from the internet: "
                + ", ".join(f"{p}/{n}" for p, n in risky.items()) + f" ({when}).",
                confidence="probable",
                criterion=f"port listed as open by Shodan scan data ({when}): confirm current exposure",
                data={"risky_ports": risky},
                tags=["exposure", "misconfiguration"],
                references=[reference],
                source=SOURCE,
                observed_last=observed,
            )
        if host["vulns"]:
            worst = max((SEVERITY_ORDER.index(v["severity"]) for v in host["vulns"]), default=2)
            cves = [v["cve"] for v in host["vulns"]]
            res.finding(
                "CVEs by version match (version-inferred)",
                SEVERITY_ORDER[worst],  # c6: capped at HIGH, never CRITICAL from Shodan alone
                f"{len(cves)} CVE(s) matched to banner versions ({CVE_LABEL}; {when}): {', '.join(cves[:20])}"
                + (" ..." if len(cves) > 20 else ""),
                confidence=0.5,
                criterion=f"{CVE_LABEL}: Shodan matched service versions/CPEs; confirm on the host",
                data={"vulns": [{k: v[k] for k in ("cve", "cvss", "severity", "ports", "products", "verified_by_shodan")} for v in host["vulns"][:100]],
                      "count": len(cves)},
                tags=["vulnerable", "version_inferred"],
                references=[reference],
                source=SOURCE,
                observed_last=observed,
            )
            for cve in cves[:50]:
                res.pivot(T.CVE, cve, "has_vuln", confidence=0.5, note=f"{CVE_LABEL}: confirm on the host")
        bad = sorted(set(host["tags"]) & BAD_TAGS)
        if bad:
            res.finding(
                "Shodan classifies the host as malicious",
                "high",
                f"Shodan tags: {', '.join(host['tags'])} ({when}).",
                confidence="probable",
                criterion=f"Shodan scanner tag(s) {', '.join(bad)} on the host",
                tags=["malicious", "c2"] if "c2" in bad else ["malicious"],
                references=[reference],
                source=SOURCE,
                observed_last=observed,
            )
        res.link("Shodan host page", reference)

    # ------------------------------------------------------------------ dns/domain (c4)
    def _dns_domain(self, res: ModuleResult, ctx: Any, key: str, domain: str, info: dict[str, Any] | None, problem: _Stop | None) -> None:
        apex = registrable_domain(domain) or domain
        if apex != domain:
            raise _Stop(Status.SKIPPED, f"Shodan dns/domain runs on registrable domains only (the sub-domains of {apex} are listed from there)", "not_applicable")
        cost = ENDPOINTS["dns_domain"][2]
        self._budget(ctx, info, problem, cost)
        data, cached = self._get(ctx, shodan_url("dns_domain", key, domain=domain, page=1), absent_marker="no information available")
        if not cached:
            self._spend(ctx, info, cost)
        if data is None:
            raise _Stop(Status.EMPTY, "Shodan has no DNS data for this domain")
        if not isinstance(data, dict):
            raise _Stop(Status.ERROR, "unexpected Shodan dns/domain answer: could not verify", "error")
        parsed = parse_dns_domain(data, domain)
        res.raw = {"domain": parsed["domain"], "names": parsed["names"][:500], "wildcards": parsed["wildcards"][:50],
                   "records": parsed["records"][:200], "more": parsed["more"]}
        res.attr("subdomain_wildcards", parsed["wildcards"][:50])
        res.attr("data_attribution", ATTRIBUTION)
        if not parsed["names"]:
            if parsed["records"]:
                return  # records of the apex only (kept in the evidence)
            raise _Stop(Status.EMPTY, "Shodan lists no sub-domains for this domain")
        self._validate(res, ctx, parsed)

    def _validate(self, res: ModuleResult, ctx: Any, parsed: dict[str, Any]) -> None:
        """c4: each candidate goes through the P016 DoH + wildcard pipeline before it is listed as live."""
        apex = parsed["domain"]
        names = parsed["names"]
        if probe_wildcard is None or resolve_one is None or resolution_order is None:
            res.attr("subdomains_unresolved", names[:500])
            res.finding("Sub-domain candidates from Shodan DNS data (not validated)", "info",
                        f"{len(names)} candidate(s); the P016 DoH validation helper is unavailable, so none is listed as live or pivoted.",
                        data={"candidates": names[:50]}, tags=["infrastructure"], source=SOURCE)
            return
        wildcard = probe_wildcard(ctx, apex)
        res.attr("dns_wildcard", {k: wildcard.get(k) for k in ("state", "answers", "nodata_quirk", "reason")})
        order, deferred = resolution_order(names, apex, cap=DNS_VALIDATE_CAP)
        provenance: dict[str, dict[str, Any]] = {}
        live: list[str] = []
        unresolved: list[str] = list(deferred)
        for name in order:
            if ctx.cancelled():
                unresolved.append(name)
                continue
            state = resolve_one(ctx, name, wildcard)
            provenance[name] = {"sources": ["shodan"], "state": state.get("state"), "addresses": state.get("addresses", [])[:4],
                                "cnames": state.get("cnames", [])[:2]}
            if state.get("state") == "live":
                live.append(name)
            elif state.get("state") == "unresolved":
                unresolved.append(name)
        res.attr("subdomains", live)
        res.attr("subdomains_unresolved", unresolved[:500])
        res.attr("subdomain_provenance", dict(list(provenance.items())[:1000]))
        for name in live[:SUBDOMAIN_PIVOT_CAP]:
            res.pivot(T.DOMAIN, name, "subdomain", confidence="probable", expand=False,
                      note="Shodan DNS data, resolves (P016 DoH + wildcard check)")
        res.finding(
            "Sub-domains from Shodan DNS data",
            "info",
            f"{len(names)} candidate(s) from Shodan DNS data: {len(live)} resolve (validated through DoH and the wildcard check), "
            f"{len(unresolved)} not verified{' (more pages exist)' if parsed['more'] else ''}.",
            data={"candidates": len(names), "live": live[:50], "unresolved": len(unresolved), "wildcard": wildcard.get("state")},
            tags=["infrastructure"],
            source=SOURCE,
        )

    # ------------------------------------------------------------------ seed-only search (c4)
    def _search(self, res: ModuleResult, ctx: Any, key: str, entity: Entity, info: dict[str, Any] | None, problem: _Stop | None) -> None:
        if not ctx.is_seed:  # pragma: no cover - applies() filters pivots
            raise _Stop(Status.SKIPPED, "Shodan search runs only for analyst-typed seeds (P039 cond 4)", "not_applicable")
        query = search_query(entity.type, entity.value)
        if not query:
            raise _Stop(Status.SKIPPED, "no Shodan search query for this value", "not_applicable")
        cost = search_cost(query)
        if info is not None and str(info.get("plan") or "").lower() in NO_SEARCH_PLANS and cost:
            raise _Stop(Status.NEEDS_KEY, f"the Shodan plan '{info.get('plan')}' cannot run filtered searches: a paid API plan is needed", "needs_key")
        self._budget(ctx, info, problem, cost)
        data, cached = self._get(ctx, shodan_url("search", key, query=query, minify=True))
        if not cached:
            self._spend(ctx, info, cost)
        if not isinstance(data, dict) or not isinstance(data.get("matches", []), list):
            raise _Stop(Status.ERROR, "unexpected Shodan search answer: could not verify", "error")
        total = _int(data.get("total")) or 0
        matches: list[dict[str, Any]] = []
        for item in _list(data.get("matches"))[:100]:
            if not isinstance(item, dict):
                continue
            ip = _text(item.get("ip_str"), 64)
            if not ip:
                continue
            matches.append({"ip": ip, "port": _int(item.get("port")), "org": _text(item.get("org")),
                            "hostnames": [h for h in (_domain(x) for x in _list(item.get("hostnames"))[:5]) if h],
                            "timestamp": _ts(item.get("timestamp"))})
        res.raw = {"query": query, "total": total, "matches": matches[:SEARCH_PIVOT_CAP * 2]}
        res.attr("scanner_search", {"query": query, "total": total, "returned": len(matches), "credits_spent": 0 if cached else cost,
                                    "matches": matches[:SEARCH_PIVOT_CAP]})
        res.attr("data_attribution", ATTRIBUTION)
        if not matches:
            raise _Stop(Status.EMPTY, f"Shodan search '{query}' matched no host")
        seen: list[str] = []
        for m in matches:
            if m["ip"] in seen:
                continue
            seen.append(m["ip"])
            etype = T.IPV6 if ":" in m["ip"] else T.IPV4
            res.pivot(etype, m["ip"], "scanner_match", confidence="possible", expand=False,
                      note=f"Shodan search match for {query[:80]} (port {m['port']}): candidate, confirm before use")
            if len(seen) >= SEARCH_PIVOT_CAP:
                break
        newest = max((m["timestamp"] for m in matches if m["timestamp"]), default=None)
        res.finding(
            "Hosts matched by a Shodan search",
            "info",
            f"Shodan search '{query}' matched {total} host banner(s); {len(seen)} listed for analyst selection.",
            data={"query": query, "total": total, "listed": seen},
            tags=["infrastructure"],
            source=SOURCE,
            observed_last=newest,
        )

    # ------------------------------------------------------------------ coverage line (c3)
    @staticmethod
    def _coverage(res: ModuleResult, ctx: Any) -> None:
        info = _state_get(ctx, "api_info") or {}
        if not isinstance(info, dict) or not info.get("checked_at"):
            return
        credits = info.get("query_credits")
        left = (credits - int(info.get("spent") or 0)) if isinstance(credits, int) else None
        line = (f"Shodan plan {info.get('plan') or '?'}: {left if left is not None else '?'} query credits left, "
                f"{info.get('scan_credits') if info.get('scan_credits') is not None else '?'} scan credits (api-info {str(info.get('checked_at'))[:10]})")
        current = res.source_statuses.get(SOURCE)
        if current is None:
            status = res.status if res.status in (Status.OK, Status.EMPTY) else Status.OK
            if res.status in (Status.OK, Status.EMPTY):
                res.source_status(SOURCE, status, reason=line)


def _status_of(exc: Exception) -> tuple[Status, str]:
    if isinstance(exc, RateLimited):
        return Status.RATE_LIMITED, "rate_limited"
    if isinstance(exc, QuotaExceeded):
        return Status.QUOTA, "quota"
    if isinstance(exc, Blocked):
        return Status.BLOCKED, getattr(exc, "reason_code", "challenge") or "challenge"
    if isinstance(exc, NetworkError):
        return Status.ERROR, "timeout" if "timeout" in str(exc).lower() or "timed out" in str(exc).lower() else "error"
    return Status.ERROR, "error"


__all__ = [
    "ENDPOINTS",
    "NONCOMMERCIAL_PLANS",
    "ShodanApi",
    "ShodanEndpointRefused",
    "parse_dns_domain",
    "parse_host",
    "search_cost",
    "search_query",
    "shodan_url",
    "vuln_severity",
]
