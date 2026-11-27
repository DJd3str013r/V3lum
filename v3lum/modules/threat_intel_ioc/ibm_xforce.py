"""ibm_xforce: IBM X-Force Exchange reputation of an IPv4, URL/domain or file hash (keyed, opt-in).

Batch p3-G07-1, proposal P155 (council final conditions):

* c1 - ``api.xforce.ibmcloud.com`` lookups only: ``GET /api/ipr/{ip}``, ``/api/url/{url}`` and
  ``/api/malware/{hash}`` (:func:`request_allowed` is the allow-list every request passes,
  unit-tested); files and collections are never submitted. ``default_enabled = False`` (opt-in).
* c2 - one key ``xforce`` holding ``key:password``; the module builds the ``Authorization: Basic``
  header itself and registers it with the central redactor (AR01); the core HTTP cache key already
  includes a hash of credential-bearing headers (P326 cond 10), so keyed answers never mix.
  ``config.KNOWN_KEYS`` is core-owned and the provider fragment ``ibm_xforce`` belongs to batch
  p2-G14-3 (a provider-ext fragment cannot declare keys): ``requires_keys`` names ``xforce`` as soon
  as the key is registered; until then the module reads ``V3LUM_KEY_XFORCE`` / the stored key itself
  and reports NEEDS_KEY without it (core request in the batch manifest).
* c3 - key-terms (registry source ``ibm_xforce.ibm_xforce_lookup``, ``free_plan_business_use``
  false): under the corporate profile only with ``key_plans.xforce = 'business'``.
* c4 - monthly quota: HTTP 402 (documented 'monthly quota of records returned exceeded') is QUOTA
  (module error marker, recorded by the quota book), never clean; a local monthly budget follows
  setting ``ibm_xforce_month_limit`` (80 %) until the provider fragment carries a P334 month block.
  401/403 = NEEDS_KEY, 404 = EMPTY 'not in X-Force', 429 = RATE_LIMITED. Score >= 7 malicious
  (MEDIUM, one vendor vote; HIGH only through the consensus), 4-6 suspicious (LOW); categories become
  tags. Malware reports carry risk high/medium/low instead of a score: high -> malicious, medium ->
  suspicious (documented gap, backlog). The success fixtures are documented shapes until the team key
  exists (backlog).

The answer is untrusted data: anything that is not the documented JSON object is 'could not verify'
(ERROR), never an absence.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import math
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, unquote, urlsplit

from v3lum.config import SettingSpec
from v3lum.core import noise
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SOURCE = "ibm_xforce.ibm_xforce_lookup"
HOST = "api.xforce.ibmcloud.com"
BASE = "https://api.xforce.ibmcloud.com/api"
WEB = "https://exchange.xforce.ibmcloud.com"
KEY_NAME = "xforce"
MONTH_SETTING = "ibm_xforce_month_limit"
SAFETY_MARGIN = 0.8
CACHE_TTL = 86400
ENDPOINTS = {T.IPV4: "ipr", T.URL: "url", T.DOMAIN: "url", T.MD5: "malware", T.SHA256: "malware"}
_PATH_RE = re.compile(r"^/api/(ipr|url|malware)/([^/]+)$")
#: c4: X-Force categories -> core vocabulary tags (others stay in the attribute only)
CATEGORY_TAGS = {
    "botnet command and control server": "c2", "malware": "malware", "spam": "spam", "scanning ips": "scanner",
    "anonymisation services": "anonymizer", "anonymization services": "anonymizer", "bots": "botnet",
    "dynamic ips": "dynamic_ip", "cryptocurrency mining": "cryptomining", "phishing urls": "phishing",
    "malware distribution": "malware", "compromised sites": "compromised", "spam urls": "spam",
}
VOTE_TAGS = frozenset({"malicious", "phishing", "malware", "c2", "botnet"})
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")


def _key_registered(name: str) -> bool:
    """True once ``name`` is a registered key (legacy KNOWN_KEYS or a provider fragment)."""
    try:
        from v3lum import config

        return name in config.key_registry()
    except Exception:  # noqa: BLE001 - registry problems keep the conservative default
        return False


# --------------------------------------------------------------------------------------
# pure helpers (stdlib only; ported from the batch prep parsers)
# --------------------------------------------------------------------------------------


def clean_text(value: Any, limit: int = 200) -> str | None:
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
    if isinstance(value, str) and re.fullmatch(r"\s*-?\d{1,18}\s*", value):
        return int(value)
    return None


def as_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    numeric = isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\s*-?\d{1,12}(\.\d{1,12})?\s*", value))
    if not numeric:
        return None
    out = float(value)
    return out if out == out and out not in (float("inf"), float("-inf")) else None


def iso(value: Any) -> str | None:
    text = clean_text(value, 64)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    parsed = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_hex(value: Any) -> tuple[str | None, str | None]:
    """Hex digest (X-Force writes '0x' prefixes) -> (md5|sha1|sha256, lower-case hex) or (None, None)."""
    text = (clean_text(value, 140) or "").strip()
    if text[:2].lower() == "0x":
        text = text[2:]
    kind = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(text))
    if kind is None or not re.fullmatch(r"[0-9A-Fa-f]+", text):
        return None, None
    return kind, text.lower()


def normalize_domain(value: Any) -> str | None:
    text = clean_text(value, 260)
    if not text:
        return None
    text = text.strip().rstrip(".").lower()
    try:
        ipaddress.ip_address(text)
        return None
    except ValueError:
        pass
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = text.split(".")
    if len(text) > 253 or len(labels) < 2 or labels[-1].isdigit():
        return None
    if not all(re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)", label) for label in labels):
        return None
    return text


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


def credential(value: Any) -> tuple[str, str]:
    """c2: the key 'xforce' = 'key:password' -> (key, password); ValueError when a part is missing."""
    text = value.strip() if isinstance(value, str) else ""
    key, sep, password = text.partition(":")
    key, password = key.strip(), password.strip()
    if not sep or not key or not password:
        raise ValueError("the X-Force key must be 'key:password' (API key and API password joined by ':')")
    return key, password


def basic_auth(value: Any) -> str:
    """c2: the Authorization header value 'Basic base64(key:password)' (registered with the redactor
    by the caller; never stored)."""
    key, password = credential(value)
    return "Basic " + base64.b64encode(f"{key}:{password}".encode()).decode("ascii")


def url_value(value: Any) -> str | None:
    """URL/domain -> the documented /url/{url} form: host + path (+ query), no scheme, userinfo or
    fragment (OpenAPI example 'www.ibm.com%2Fsmarterplanet'); None for non-URLs."""
    text = value.strip() if isinstance(value, str) else ""
    if not text or any(c.isspace() for c in text):
        return None
    if not re.match(r"^[a-z][a-z0-9+.-]*://", text, re.I):
        text = "http://" + text
    try:
        parts = urlsplit(text)
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return None
    host = parts.hostname
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not normalize_domain(host):
            return None
    out = host + port + parts.path + (f"?{parts.query}" if parts.query else "")
    return out.rstrip("/") if parts.path in ("", "/") and not parts.query else out


def lookup_url(etype: T, value: str) -> str:
    """c1: the read-only lookup URL (ValueError outside the allow-list)."""
    endpoint = ENDPOINTS.get(etype)
    if endpoint is None:
        raise ValueError(f"X-Force: unsupported type {etype}")
    if endpoint == "ipr":
        try:
            tail = str(ipaddress.ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("X-Force: not an IP address") from exc
    elif endpoint == "url":
        text = url_value(value)
        if not text:
            raise ValueError("X-Force: not a URL or domain")
        tail = quote(text, safe="")
    else:
        kind, tail = hash_hex(value)
        if kind not in ("md5", "sha256"):
            raise ValueError("X-Force: not an MD5 or SHA-256")
    return f"{BASE}/{endpoint}/{tail}"


def request_allowed(method: str, url: str) -> bool:
    """Allow-list (c1): GET https://api.xforce.ibmcloud.com/api/{ipr|url|malware}/{value}, no query
    string, fragment or userinfo; history and sub-report paths, collections, casefiles, uploads, TAXII
    and key management are refused because they are not this exact shape."""
    if (method or "").upper() != "GET" or not isinstance(url, str):
        return False
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    if parts.scheme != "https" or parts.hostname != HOST or port not in (None, 443) or parts.query or parts.fragment:
        return False
    if parts.username or parts.password:
        return False
    match = _PATH_RE.match(parts.path)
    if not match:
        return False
    endpoint, tail = match.groups()
    if endpoint == "ipr":
        try:
            ipaddress.ip_address(tail)
        except ValueError:
            return False
        return True
    if endpoint == "malware":
        return hash_hex(tail)[0] in ("md5", "sha256")
    return url_value(unquote(tail)) is not None


def verdict_from_score(score: Any) -> str | None:
    """c4: score >= 7 -> 'malicious'; 4 <= score < 7 -> 'suspicious'; lower or missing -> None (no
    finding, never clean)."""
    value = as_float(score)
    if value is None:
        return None
    if value >= 7:
        return "malicious"
    if value >= 4:
        return "suspicious"
    return None


def malware_verdict(risk: Any) -> str | None:
    """Malware reports carry risk high/medium/low (not covered by c4's numeric mapping): high ->
    malicious, medium -> suspicious, low/unknown -> None (documented gap, backlog)."""
    return {"high": "malicious", "medium": "suspicious"}.get((clean_text(risk, 20) or "").lower())


def categories(cats: Any) -> list[dict[str, Any]]:
    """X-Force cats {name: confidence | true} -> [{name, confidence}]."""
    out = []
    if isinstance(cats, dict):
        for name, value in list(cats.items())[:30]:
            text = clean_text(name, 80)
            if text:
                out.append({"name": text, "confidence": None if isinstance(value, bool) else as_int(value)})
    return out


def category_tags(cats: list[dict[str, Any]]) -> list[str]:
    """c4: categories -> core vocabulary tags (unknown categories stay in the attribute)."""
    out: list[str] = []
    for cat in cats:
        tag = CATEGORY_TAGS.get(cat["name"].lower())
        if tag and tag not in out:
            out.append(tag)
    return out


def parse_ipr(obj: Any) -> dict[str, Any] | None:
    """/ipr/{ip} -> {ip, score, verdict, categories, reason, country, subnets, first_seen, last_change}."""
    if not isinstance(obj, dict) or "error" in obj or ("score" not in obj and "cats" not in obj):
        return None
    history = [h for h in obj.get("history") if isinstance(h, dict)] if isinstance(obj.get("history"), list) else []
    created = sorted(x for x in (iso(h.get("created")) for h in history) if x)
    geo = obj.get("geo") if isinstance(obj.get("geo"), dict) else {}
    subnets = []
    for row in obj.get("subnets") if isinstance(obj.get("subnets"), list) else []:
        if not isinstance(row, dict):
            continue
        asns = row.get("asns") if isinstance(row.get("asns"), dict) else {}
        asn = next((as_int(k) for k in asns if as_int(k) is not None), None)
        company = clean_text(asns[str(asn)].get("Company"), 120) if asn is not None and isinstance(asns.get(str(asn)), dict) else None
        subnets.append({"subnet": clean_text(row.get("subnet") or row.get("ip"), 64), "score": as_float(row.get("score")),
                        "asn": asn, "company": company})
    score = as_float(obj.get("score"))
    cats = categories(obj.get("cats"))
    return {"kind": "ipr", "ip": clean_text(obj.get("ip"), 64), "score": score, "verdict": verdict_from_score(score),
            "categories": cats, "tags": category_tags(cats), "reason": clean_text(obj.get("reason"), 120),
            "country": (clean_text(geo.get("countrycode"), 5) or "").upper() or None, "subnets": subnets[:10],
            "first_seen": created[0] if created else None, "last_change": created[-1] if created else None}


def parse_url(obj: Any) -> dict[str, Any] | None:
    """/url/{url} -> {url, score, verdict, categories, associated}."""
    if not isinstance(obj, dict) or not isinstance(obj.get("result"), dict):
        return None
    result = obj["result"]
    score = as_float(result.get("score"))
    cats = categories(result.get("cats"))
    associated = []
    for row in obj.get("associated") if isinstance(obj.get("associated"), list) else []:
        if isinstance(row, dict):
            associated.append({"url": clean_text(row.get("url"), 500), "score": as_float(row.get("score")),
                               "categories": [c["name"] for c in categories(row.get("cats"))]})
    return {"kind": "url", "url": clean_text(result.get("url"), 2000), "score": score, "verdict": verdict_from_score(score),
            "categories": cats, "tags": category_tags(cats), "associated": associated[:10]}


def _servers(block: Any) -> list[dict[str, Any]]:
    rows = block.get("rows") if isinstance(block, dict) else None
    out = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        try:
            ip = str(ipaddress.ip_address(clean_text(row.get("ip"), 64) or ""))
        except ValueError:
            ip = None
        out.append({"domain": normalize_domain(row.get("domain")), "ip": ip, "first_seen": iso(row.get("firstseen")),
                    "last_seen": iso(row.get("lastseen")), "count": as_int(row.get("count"))})
    return out[:20]


def parse_malware(obj: Any) -> dict[str, Any] | None:
    """/malware/{hash} -> {hash, risk, verdict, families, external_families, detection_coverage, c2,
    download_servers, created}."""
    if not isinstance(obj, dict) or not isinstance(obj.get("malware"), dict):
        return None
    mal = obj["malware"]
    origins = mal.get("origins") if isinstance(mal.get("origins"), dict) else {}
    external = origins.get("external") if isinstance(origins.get("external"), dict) else {}
    fams: list[str] = []
    raw_fams = mal.get("family") if isinstance(mal.get("family"), list) else []
    members = mal.get("familyMembers") if isinstance(mal.get("familyMembers"), dict) else {}
    for name in [*raw_fams, *members]:
        text = clean_text(name, 60)
        if text and re.fullmatch(r"[A-Za-z][A-Za-z0-9 ._-]{1,59}", text) and text.lower() not in (f.lower() for f in fams):
            fams.append(text)
    risk = (clean_text(mal.get("risk"), 20) or "").lower() or None
    ext_fams = external.get("family") if isinstance(external.get("family"), list) else []
    return {"kind": "malware", "hash": hash_hex(mal.get("hash") or mal.get("md5"))[1], "risk": risk,
            "verdict": malware_verdict(risk), "families": fams[:10],
            "external_families": [x for x in (clean_text(f, 60) for f in ext_fams[:10]) if x],
            "detection_coverage": as_int(external.get("detectionCoverage")), "created": iso(mal.get("created")),
            "c2": _servers(origins.get("CnCServers")), "download_servers": _servers(origins.get("downloadServers"))}


def report_link(etype: T, value: str) -> str:
    """Manual pivot link (X-Force Exchange single-page app)."""
    segment = {"ipr": "ip", "url": "url", "malware": "malware"}.get(ENDPOINTS.get(etype, ""), "search")
    return f"{WEB}/{segment}/{quote(str(value), safe='')}"


def public_ip(value: str) -> bool:
    """Private, reserved and documentation addresses are never sent (patched in tests)."""
    return noise.is_public_ip(value)


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class IBMXForce(Module):
    name = "ibm_xforce"
    title = "IBM X-Force Exchange"
    description = (
        "IBM X-Force Exchange risk score, categories and malware families of an IPv4, URL/domain or MD5/SHA-256 "
        "(ipr/url/malware lookups with a company key:password; opt-in)."
    )
    category = "threat_intel_ioc"
    accepts = {T.IPV4, T.URL, T.DOMAIN, T.MD5, T.SHA256}
    produces = {T.MALWARE, T.DOMAIN, T.IPV4, T.IPV6}
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "ibm_xforce"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,) if _key_registered(KEY_NAME) else ()
    error_markers = (
        {"id": "ibm_xforce_monthly_quota", "statuses": [402], "final_url_regex": r"^https://api\.xforce\.ibmcloud\.com/",
         "maps_to": "quota", "reason_code": "quota",
         "reason": "IBM X-Force: monthly quota of records exhausted (HTTP 402): could not verify; deferred"},
        {"id": "ibm_xforce_quota_in_body", "statuses": [200, 403, 429], "json_path": "error", "regex": "(?i)quota",
         "maps_to": "quota", "reason_code": "quota", "reason": "IBM X-Force: quota exhausted: could not verify; deferred"},
        {"id": "ibm_xforce_error_in_200", "statuses": [200], "json_path": "error", "regex": r"(?i)^(?!not found)",
         "maps_to": "error", "reason_code": "error", "reason": "IBM X-Force: error inside an HTTP 200 answer: could not verify"},
    )
    max_requests = 1
    expected_latency = 1.0
    timeout = 30.0
    min_interval = 1.0
    cache_ttl = CACHE_TTL
    max_pivots = 30
    manual_link = "unverified_reputation:xforce_ip"
    default_enabled = False
    tags = {"reputation"}
    reference = "https://api.xforce.ibmcloud.com/doc/"
    settings = {
        MONTH_SETTING: SettingSpec(
            0,
            "IBM X-Force: monthly record limit of the company plan (0 = unknown: only the provider's HTTP 402 stops the "
            "module); the module spends at most 80% of it per UTC month (P155 cond 4, until a P334 month block exists)",
        ),
    }
    notice = (
        "IBM X-Force Exchange is opt-in and needs one key 'xforce' = 'key:password' from a company account; under the "
        "corporate profile it runs only with key_plans.xforce=business (IBM sells the commercial API separately). "
        "Read-only ipr/url/malware lookups: files and collections are never submitted."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.IPV4:
            return public_ip(entity.value)  # private/reserved addresses are never sent
        return True

    def _month_budget(self, ctx: Any) -> tuple[int, int, str]:
        """(budget, used, month) of the local monthly counter; budget 0 = no local cap."""
        limit = as_int(ctx.setting(MONTH_SETTING, 0)) or 0
        month = ctx.now().strftime("%Y-%m")
        record = ctx.state.get("month") or {}
        used = as_int(record.get("used")) or 0 if isinstance(record, dict) and record.get("month") == month else 0
        return (math.floor(limit * SAFETY_MARGIN) if limit > 0 else 0), used, month

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        link = report_link(entity.type, entity.value)
        raw_key = str(ctx.key(KEY_NAME) or "").strip()
        if not raw_key:
            return res.mark(Status.NEEDS_KEY, "needs the X-Force key 'xforce' = 'key:password' (v3lum keys set xforce)", reason_code="needs_key")
        try:
            header = basic_auth(raw_key)
        except ValueError as exc:
            return res.mark(Status.NEEDS_KEY, str(exc), reason_code="needs_key")
        try:
            from v3lum.core.redact import register_secret

            register_secret(header, label="api key")
            register_secret(header.split(" ", 1)[1], label="api key")
        except Exception:  # noqa: BLE001 - the Authorization header is masked as a credential header anyway
            pass
        try:
            url = lookup_url(entity.type, entity.value)
        except ValueError as exc:
            return res.mark(Status.SKIPPED, str(exc), reason_code="not_applicable")
        if not request_allowed("GET", url):  # c1: never anything but the three lookups
            return res.mark(Status.ERROR, "refused a non-allow-listed X-Force request (module bug)", reason_code="error")
        budget, used, month = self._month_budget(ctx)
        if budget and used >= budget:
            res.link("X-Force Exchange report (manual)", link)
            return res.mark(Status.QUOTA, f"X-Force monthly budget used ({used}/{budget} in {month}): could not verify; deferred", reason_code="quota")
        resp = ctx.http.get(url, headers={"Authorization": header, "Accept": "application/json"}, source=SOURCE)
        if budget and not getattr(resp, "from_cache", False):
            ctx.state.set("month", {"month": month, "used": used + 1})
        found = resp.classification
        if resp.status in (401, 403) and (found is None or found.marker_id == "keyless.403"):
            res.link("X-Force Exchange report (manual)", link)
            why = "rejected the credentials" if resp.status == 401 else "denied access for this key/plan"
            return res.mark(Status.NEEDS_KEY, f"X-Force {why} (HTTP {resp.status}): could not verify", reason_code="needs_key")
        if resp.status == 404 and found is None:
            res.raw = {"status": 404}
            return res.mark(Status.EMPTY, "not in X-Force (HTTP 404 'Not found.')")
        ctx.http.check(resp)  # 402/quota markers -> QUOTA, 429 -> RATE_LIMITED, challenges, 5xx
        obj, why = load_json(resp.content)
        if why:
            return res.mark(Status.ERROR, f"unexpected X-Force answer ({why}): could not verify", reason_code="error")
        if isinstance(obj, dict) and clean_text(obj.get("error"), 120):
            message = clean_text(obj.get("error"), 120) or ""
            if message.lower().startswith("not found"):
                return res.mark(Status.EMPTY, "not in X-Force ('Not found.')")
            return res.mark(Status.ERROR, f"X-Force error inside an HTTP 200 answer ({message}): could not verify", reason_code="error")
        parser = {"ipr": parse_ipr, "url": parse_url, "malware": parse_malware}[ENDPOINTS[entity.type]]
        parsed = parser(obj)
        if parsed is None:
            return res.mark(Status.ERROR, "unexpected X-Force answer (not the documented report object): could not verify", reason_code="error")
        return self._report(res, entity, parsed, link)

    # ---- report (c4) ---------------------------------------------------------------------
    def _report(self, res: ModuleResult, entity: Entity, p: dict[str, Any], link: str) -> ModuleResult:
        res.raw = {"status": 200, "report": p}
        res.link("X-Force Exchange report", link)
        facts = {k: v for k, v in p.items() if k != "tags"} | {"link": link}
        res.attr("xforce", facts)
        res.attr("data_attribution", "IBM X-Force Exchange")
        if p["kind"] == "malware":
            res.attr("reputation", {"ibm_xforce": p.get("risk") or "unknown"})
        elif p.get("score") is not None:
            res.attr("reputation", {"ibm_xforce": p["score"]})
        if p["kind"] == "ipr":
            res.attr("country", p["country"] if p["country"] and re.fullmatch(r"[A-Z]{2}", p["country"]) else None)
            asn = next((s["asn"] for s in p["subnets"] if s.get("asn") is not None), None)
            if asn is not None:
                res.attr("asn", f"AS{asn}")
            res.attr("first_seen", p["first_seen"])
        if p["kind"] == "malware":
            res.attr("malware_family", p["families"] or None)
            self._pivot_malware(res, p)
        verdict = p.get("verdict")
        if verdict is None:
            if p["kind"] != "malware" and (p.get("score") is None and not p.get("categories")):
                return res.mark(Status.EMPTY, "no X-Force score or categories for this value")
            return res  # below the suspicious band: facts only, never 'clean'
        cat_names = [c["name"] for c in p.get("categories", [])]
        if p["kind"] == "malware":
            basis = f"X-Force malware risk {p.get('risk')}" + (f"; families {', '.join(p['families'][:5])}" if p["families"] else "")
        else:
            basis = f"X-Force risk score {p['score']:g}" + (f"; categories {', '.join(cat_names[:5])}" if cat_names else "")
        description = basis + (f"; reason: {p['reason']}" if p.get("reason") else "") + "."
        data = {"kind": p["kind"], "score": p.get("score"), "risk": p.get("risk"), "categories": cat_names[:10],
                "families": p.get("families", [])[:10], "upstream_families": ["ibm-xforce"]}
        common = {"references": [link], "source": SOURCE, "data": data}
        if p["kind"] == "ipr" and p.get("last_change"):
            common["observed_last"] = p["last_change"]
        elif p["kind"] == "malware" and p.get("created"):
            common["observed_first"] = p["created"]
        extra = [t for t in p.get("tags", [])]
        if verdict == "malicious":
            criterion = ("X-Force malware risk high (one vendor vote; HIGH only through the consensus)" if p["kind"] == "malware"
                         else f"X-Force risk score {p['score']:g} >= 7 (one vendor vote; HIGH only through the consensus)")
            res.finding("Malicious per IBM X-Force", "medium", description, confidence="probable", criterion=criterion,
                        tags=sorted({"malicious", *extra}), **common)
        else:
            criterion = ("X-Force malware risk medium" if p["kind"] == "malware" else f"X-Force risk score {p['score']:g} (4-6: suspicious)")
            res.finding("Suspicious per IBM X-Force", "low", description, confidence="possible", criterion=criterion,
                        tags=sorted({"suspicious", *(t for t in extra if t not in VOTE_TAGS)}), **common)
        return res

    def _pivot_malware(self, res: ModuleResult, p: dict[str, Any]) -> None:
        """Families (expand=False) and the C2 servers of a malware report (expand=False: listed for the
        analyst, never investigated automatically)."""
        for fam in p.get("families", [])[:10]:
            res.pivot(T.MALWARE, fam, "family", confidence="probable", expand=False, note="IBM X-Force malware family")
        for server in p.get("c2", [])[:10]:
            if server.get("domain"):
                res.pivot(T.DOMAIN, server["domain"], "communicates_with", confidence="possible", expand=False,
                          note="C2 server named by an IBM X-Force malware report")
            if server.get("ip"):
                etype = T.IPV6 if ":" in server["ip"] else T.IPV4
                res.pivot(etype, server["ip"], "communicates_with", confidence="possible", expand=False,
                          note="C2 server named by an IBM X-Force malware report")
