"""kaspersky_opentip: Kaspersky OpenTIP zone of a file hash, IPv4, domain or URL (keyed, opt-in).

Batch p3-G07-1, proposal P162 (council final conditions):

* c1 - ``default_enabled = False`` and disabled until compliance records that the company's
  vendor/sanctions policy permits sending IOCs to Kaspersky: the module reads the provider-registry
  flag ``vendor_policy_ok`` of provider ``kaspersky`` (a ``flags.vendor_policy_ok`` field once the core
  schema has it, else the fragment field ``x_vendor_policy_ok``) and stays SKIPPED ``policy`` without
  it, before any request; legal also records the OpenTIP API terms (registry source
  ``kaspersky.kaspersky_opentip_search``: key-terms, ``free_plan_business_use`` false -> under the
  corporate profile only with ``key_plans.opentip = 'business'``).
* c2 - key ``opentip`` (``x-api-key`` header). ``config.KNOWN_KEYS`` is core-owned and the provider
  fragment ``kaspersky`` belongs to batch p2-G14-3 (a provider-ext fragment cannot declare keys):
  ``requires_keys`` names ``opentip`` as soon as the key is registered; until then the module reads
  ``V3LUM_KEY_OPENTIP`` / the stored key itself and reports NEEDS_KEY without it. Hash, IP, domain and
  URL searches only: ``GET /api/v1/search/{hash|ip|domain|url}?request=`` (:func:`request_allowed`,
  unit-tested); the file scan/upload endpoint of the official client is never built (rule 7). URLs are
  sent without query string, fragment or userinfo (:func:`clean_url`).
* c3 - 401 answers with an EMPTY body and is handled by status code: NEEDS_KEY. 403 is 'quota or
  request limit exceeded' (help pages) -> QUOTA (module marker), 404 'lookup results not found' ->
  EMPTY (never clean), 400 -> ERROR, 429 -> RATE_LIMITED. Zones: Red -> malicious (HIGH), Orange ->
  suspicious (LOW), Grey -> no finding, Green -> ``known_good`` only for file hashes; Yellow
  (adware/riskware, not covered by c3) -> info, tag ``potentially_unwanted`` (backlog: council
  confirmation). One vendor vote in consensus (``data['upstream_families'] = ['kaspersky']``).
  Budget: ``Module.daily_quota`` 1,600 (80% of the documented 2,000/day) until the provider fragment
  carries a P334 block. The success fixtures are documented shapes until the team key exists.

WHOIS blocks are never copied. The answer is untrusted data: anything that is not a zone document is
'could not verify' (ERROR), never an absence.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from v3lum.core import noise
from v3lum.core import providers as providers_mod
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

PROVIDER = "kaspersky"
SOURCE = "kaspersky.kaspersky_opentip_search"
HOST = "opentip.kaspersky.com"
SEARCH_URL = "https://opentip.kaspersky.com/api/v1/search"
WEB = "https://opentip.kaspersky.com"
KEY_NAME = "opentip"
KEY_HEADER = "x-api-key"
CACHE_TTL = 86400
DOC_DAILY_LIMIT = 2000
KINDS = {T.MD5: "hash", T.SHA256: "hash", T.IPV4: "ip", T.DOMAIN: "domain", T.URL: "url"}
_PATH_RE = re.compile(r"^/api/v1/search/(hash|ip|domain|url)$")
ZONES = ("Red", "Orange", "Yellow", "Grey", "Green")
_GENERIC_FAMILY = frozenset((
    "generic", "agent", "gen", "heur", "malware", "cryptic", "kryptik", "test", "multi", "script", "win32", "win64", "msil",
    "linux", "androidos", "html", "js", "pdf", "eicar",
))
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")


def _key_registered(name: str) -> bool:
    """True once ``name`` is a registered key (legacy KNOWN_KEYS or a provider fragment)."""
    try:
        from v3lum import config

        return name in config.key_registry()
    except Exception:  # noqa: BLE001 - registry problems keep the conservative default
        return False


def vendor_policy_ok() -> bool:
    """c1: the central registry flag set by legal/compliance (fail closed when absent)."""
    try:
        prov = providers_mod.registry().get(PROVIDER)
    except Exception:  # noqa: BLE001 - a registry problem keeps the module disabled
        return False
    if prov is None:
        return False
    if getattr(getattr(prov, "flags", None), "vendor_policy_ok", None) is True:
        return True
    extra = getattr(prov, "extra", None) or {}
    return isinstance(extra, dict) and extra.get("x_vendor_policy_ok") is True


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


def str_list(value: Any, limit: int = 20, item_limit: int = 80) -> list[str]:
    out: list[str] = []
    for item in value if isinstance(value, list) else []:
        text = clean_text(item, item_limit)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


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
    text = (clean_text(value, 140) or "").strip()
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


def clean_url(url: Any) -> str | None:
    """c2: URLs are sent without query string, fragment or userinfo -> scheme://host[:port]/path."""
    text = url.strip() if isinstance(url, str) else ""
    if not re.match(r"^https?://", text, re.I) or any(c.isspace() for c in text):
        return None
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
    return f"{parts.scheme.lower()}://{host}{port}{parts.path or '/'}"


def search_url(etype: T, value: str) -> str:
    """c2: GET /api/v1/search/{hash|ip|domain|url}?request=<value> (ValueError outside the allow-list)."""
    kind = KINDS.get(etype)
    if kind is None:
        raise ValueError(f"OpenTIP: unsupported type {etype}")
    if kind == "hash":
        hkind, text = hash_hex(value)
        if hkind not in ("md5", "sha256"):
            raise ValueError("OpenTIP: not an MD5 or SHA-256")
    elif kind == "ip":
        try:
            text = str(ipaddress.IPv4Address(value.strip()))
        except ValueError as exc:
            raise ValueError("OpenTIP: not an IPv4 address") from exc
    elif kind == "domain":
        text = normalize_domain(value) or ""
        if not text:
            raise ValueError("OpenTIP: not a domain")
    else:
        text = clean_url(value) or ""
        if not text:
            raise ValueError("OpenTIP: not an http(s) URL")
    return f"{SEARCH_URL}/{kind}?" + urlencode({"request": text})


def request_allowed(method: str, url: str) -> bool:
    """c2 allow-list (unit-tested): GET https://opentip.kaspersky.com/api/v1/search/{type}?request=<one
    value>; a URL value carries no query string, fragment or userinfo; any other path (the scan/upload
    endpoints of the official client included), POST and other hosts are refused."""
    if (method or "").upper() != "GET" or not isinstance(url, str):
        return False
    try:
        parts = urlsplit(url)
        params = parse_qs(parts.query, keep_blank_values=True)
        port = parts.port
    except ValueError:
        return False
    if parts.scheme != "https" or parts.hostname != HOST or port not in (None, 443) or parts.fragment:
        return False
    if parts.username or parts.password:
        return False
    match = _PATH_RE.match(parts.path)
    if not match or set(params) != {"request"} or len(params["request"]) != 1:
        return False
    kind, value = match.group(1), params["request"][0]
    if kind == "url":
        return clean_url(value) == value
    if kind == "hash":
        return hash_hex(value)[0] in ("md5", "sha256")
    if kind == "ip":
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            return False
        return True
    return normalize_domain(value) == value


def zone(value: Any) -> str | None:
    text = (clean_text(value, 20) or "").capitalize()
    text = "Grey" if text == "Gray" else text
    return text if text in ZONES else None


def detection_family(name: Any) -> str | None:
    """Kaspersky detection name '[Prefix:]Class.Platform.Family[.variant]' -> family
    ('Trojan-Ransom.Win32.Wanna.m' -> 'Wanna'); None for generic/heuristic names, 'not-a-virus' and the
    EICAR test file."""
    text = clean_text(name, 200)
    if not text or text.lower().startswith("not-a-virus") or "eicar" in text.lower():
        return None
    parts = text.split(":")[-1].split(".")
    if len(parts) < 3:
        return None
    fam = parts[2]
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{1,39}", fam) or fam.lower() in _GENERIC_FAMILY:
        return None
    return fam


def parse(obj: Any) -> dict[str, Any] | None:
    """OpenTIP search body -> {zone, object, file, detections, families, categories,
    categories_with_zone, ip, domain, url}; None without a Zone. WHOIS blocks are never copied."""
    if not isinstance(obj, dict):
        return None
    zn = zone(obj.get("Zone"))
    if zn is None:
        return None
    out: dict[str, Any] = {"zone": zn, "object": None, "file": None, "detections": [], "families": [], "categories": [],
                           "categories_with_zone": [], "ip": None, "domain": None, "url": None}
    info = obj.get("FileGeneralInfo")
    if isinstance(info, dict):
        out["object"] = "hash"
        out["file"] = {"status": clean_text(info.get("FileStatus"), 40), "md5": hash_hex(info.get("Md5"))[1],
                       "sha1": hash_hex(info.get("Sha1"))[1], "sha256": hash_hex(info.get("Sha256"))[1],
                       "size": as_int(info.get("Size")), "type": clean_text(info.get("Type"), 40),
                       "first_seen": iso(info.get("FirstSeen")), "last_seen": iso(info.get("LastSeen")),
                       "hits": as_int(info.get("HitsCount"))}
        rows = [*(obj.get("DetectionsInfo") if isinstance(obj.get("DetectionsInfo"), list) else []),
                *(obj.get("DynamicDetections") if isinstance(obj.get("DynamicDetections"), list) else [])]
        detections = []
        for row in rows:
            if isinstance(row, dict) and clean_text(row.get("DetectionName"), 200):
                detections.append({"name": clean_text(row.get("DetectionName"), 200), "zone": zone(row.get("Zone")),
                                   "last_detect": iso(row.get("LastDetectDate"))})
        out["detections"] = detections[:20]
        fams: list[str] = []
        for det in detections:
            fam = detection_family(det["name"])
            if fam and fam not in fams:
                fams.append(fam)
        out["families"] = fams
    for block_key, kind in (("IpGeneralInfo", "ip"), ("DomainGeneralInfo", "domain"), ("UrlGeneralInfo", "url")):
        block = obj.get(block_key)
        if not isinstance(block, dict):
            continue
        out["object"] = kind
        out["categories"] = str_list(block.get("Categories"))
        out["categories_with_zone"] = [{"name": clean_text(c.get("Name"), 80), "zone": zone(c.get("Zone"))}
                                       for c in (block.get("CategoriesWithZone") if isinstance(block.get("CategoriesWithZone"), list) else [])
                                       if isinstance(c, dict)][:20]
        if kind == "ip":
            country = (clean_text(block.get("CountryCode"), 5) or "").upper()
            out["ip"] = {"status": clean_text(block.get("Status"), 40), "country": country if re.fullmatch(r"[A-Z]{2}", country) else None,
                         "hits": as_int(block.get("HitsCount")), "first_seen": iso(block.get("FirstSeen"))}
        elif kind == "domain":
            out["domain"] = {"hits": as_int(block.get("HitsCount")), "files": as_int(block.get("FilesCount")),
                             "urls": as_int(block.get("UrlsCount")), "ipv4_count": as_int(block.get("Ipv4Count"))}
        else:
            out["url"] = {"host": normalize_domain(block.get("Host")), "files": as_int(block.get("FilesCount")),
                          "ipv4_count": as_int(block.get("Ipv4Count"))}
    return out


def verdict(p: dict[str, Any], is_hash: bool) -> dict[str, Any]:
    """c3 zone mapping: Red -> malicious (high); Orange -> suspicious (low); Grey -> no finding; Green ->
    known_good only for file hashes; Yellow -> info, potentially unwanted (not covered by c3)."""
    zn = p.get("zone")
    if zn == "Red":
        return {"band": "malicious", "severity": "high"}
    if zn == "Orange":
        return {"band": "suspicious", "severity": "low"}
    if zn == "Green" and is_hash:
        return {"band": "known_good", "severity": "info"}
    if zn == "Yellow":
        return {"band": "potentially_unwanted", "severity": "info"}
    return {"band": "none", "severity": None}


def report_link(value: str) -> str:
    return f"{WEB}/{quote(str(value), safe='')}/results?tab=lookup"


def public_ip(value: str) -> bool:
    """Private, reserved and documentation addresses are never sent (patched in tests)."""
    return noise.is_public_ip(value)


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class KasperskyOpenTIP(Module):
    name = "kaspersky_opentip"
    title = "Kaspersky OpenTIP"
    description = (
        "Kaspersky OpenTIP zone (Red/Orange/Yellow/Grey/Green), detections and categories of an MD5/SHA-256, IPv4, "
        "domain or URL (search API with a company key; opt-in, vendor-policy gated)."
    )
    category = "threat_intel_ioc"
    accepts = {T.MD5, T.SHA256, T.IPV4, T.DOMAIN, T.URL}
    produces = {T.MALWARE}
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = PROVIDER
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,) if _key_registered(KEY_NAME) else ()
    error_markers = (
        {"id": "kaspersky_opentip_quota_403", "statuses": [403], "final_url_regex": r"^https://opentip\.kaspersky\.com/api/",
         "maps_to": "quota", "reason_code": "quota",
         "reason": "Kaspersky OpenTIP: quota or request limit exceeded (HTTP 403): could not verify; deferred"},
    )
    max_requests = 1
    expected_latency = 1.5
    timeout = 30.0
    min_interval = 1.0
    daily_quota = int(DOC_DAILY_LIMIT * 0.8)
    cache_ttl = CACHE_TTL
    max_pivots = 10
    default_enabled = False
    tags = {"reputation"}
    reference = "https://opentip.kaspersky.com/Help/Doc_data/"
    notice = (
        "Kaspersky OpenTIP (foreign provider, RU) is opt-in and stays disabled until compliance records that the "
        "company's vendor/sanctions policy permits sending IOCs to Kaspersky (registry flag vendor_policy_ok) and legal "
        "records the API terms (key_plans.opentip=business under the corporate profile). Search lookups only: files "
        "are never uploaded; URLs are sent without query string or userinfo."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.IPV4:
            return public_ip(entity.value)  # private/reserved addresses are never sent
        if entity.type is T.URL:
            return clean_url(entity.value) is not None
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if not vendor_policy_ok():  # c1: before anything leaves the machine
            return res.mark(Status.SKIPPED, "Kaspersky OpenTIP disabled: compliance has not recorded vendor_policy_ok for provider "
                            "kaspersky (company vendor/sanctions policy)", reason_code="policy")
        key = str(ctx.key(KEY_NAME) or "").strip()
        if not key:
            return res.mark(Status.NEEDS_KEY, "needs the OpenTIP key (v3lum keys set opentip)", reason_code="needs_key")
        try:
            url = search_url(entity.type, entity.value)
        except ValueError as exc:
            return res.mark(Status.SKIPPED, str(exc), reason_code="not_applicable")
        if not request_allowed("GET", url):  # c2: search lookups only
            return res.mark(Status.ERROR, "refused a non-allow-listed OpenTIP request (module bug)", reason_code="error")
        resp = ctx.http.get(url, headers={KEY_HEADER: key, "Accept": "application/json"}, source=SOURCE)
        if resp.status == 401:  # c3: empty body, handled by status code
            return res.mark(Status.NEEDS_KEY, "OpenTIP rejected the key (HTTP 401, empty body): could not verify", reason_code="needs_key")
        if resp.status == 404 and resp.classification is None:
            res.raw = {"status": 404}
            return res.mark(Status.EMPTY, "not in Kaspersky OpenTIP (lookup results not found)")
        if resp.status == 400 and resp.classification is None:
            return res.mark(Status.ERROR, "OpenTIP rejected the request (HTTP 400): could not verify", reason_code="error")
        ctx.http.check(resp)  # 403 quota marker -> QUOTA, 429 -> RATE_LIMITED, challenges, 5xx
        obj, why = load_json(resp.content)
        if why:
            return res.mark(Status.ERROR, f"unexpected OpenTIP answer ({why}): could not verify", reason_code="error")
        parsed = parse(obj)
        if parsed is None:
            return res.mark(Status.ERROR, "unexpected OpenTIP answer (no Zone): could not verify", reason_code="error")
        return self._report(res, entity, parsed)

    # ---- report (c3) ----------------------------------------------------------------------
    def _report(self, res: ModuleResult, entity: Entity, p: dict[str, Any]) -> ModuleResult:
        is_hash = KINDS.get(entity.type) == "hash"
        v = verdict(p, is_hash)
        link = report_link(entity.value)
        res.raw = {"status": 200, "search": p}
        res.link("Kaspersky OpenTIP results", link)
        res.attr("opentip", {k: p[k] for k in p if p[k] not in (None, [], {})} | {"link": link})
        res.attr("reputation", {"kaspersky_opentip": p["zone"]})
        if p.get("ip"):
            res.attr("country", p["ip"].get("country"))
            res.attr("first_seen", p["ip"].get("first_seen"))
        if p.get("file"):
            res.attr("first_seen", p["file"].get("first_seen"))
            res.attr("last_seen", p["file"].get("last_seen"))
            res.attr("file_size", p["file"].get("size"))
            res.attr("file_type", p["file"].get("type"))
            res.attr("av_signatures", [d["name"] for d in p["detections"]] or None)
        if p["families"]:
            res.attr("malware_family", p["families"])
            for fam in p["families"][: self.max_pivots]:
                res.pivot(T.MALWARE, fam, "family", confidence="probable", expand=False, note="Kaspersky OpenTIP detection name")
        names = [d["name"] for d in p["detections"]][:3] or p["categories"][:3]
        criterion = f"Kaspersky OpenTIP zone {p['zone']}" + (f": {', '.join(names)}" if names else "")
        description = criterion + "." + (f" File status {p['file']['status']}." if p.get("file") and p["file"].get("status") else "")
        observed = (p.get("file") or {}).get("last_seen")
        data = {"zone": p["zone"], "detections": [d["name"] for d in p["detections"]][:10], "categories": p["categories"][:10],
                "families": p["families"][:10], "upstream_families": ["kaspersky"]}
        common = {"references": [link], "source": SOURCE, "data": data, "observed_last": observed}
        band = v["band"]
        if band == "malicious":
            res.finding("Malicious per Kaspersky OpenTIP", "high", description + " One vendor vote in the consensus.",
                        confidence="probable", criterion=criterion + " (Red -> malicious, P162 cond 3)", tags=["malicious"], **common)
        elif band == "suspicious":
            res.finding("Suspicious per Kaspersky OpenTIP", "low", description, confidence="possible",
                        criterion=criterion + " (Orange -> suspicious, P162 cond 3)", tags=["suspicious"], **common)
        elif band == "known_good":
            res.attr("known_good", True)
            res.finding("Known good file per Kaspersky OpenTIP", "info", description + " A known-good file verdict, never a 'clean' "
                        "label for other entity types.", confidence="possible", criterion=criterion + " (Green, file hashes only)",
                        tags=["known_good", "info"], **common)
        elif band == "potentially_unwanted":
            res.finding("Potentially unwanted software per Kaspersky OpenTIP", "info", description, confidence="possible",
                        criterion=criterion + " (Yellow: adware/riskware, not a malicious verdict)",
                        tags=["potentially_unwanted", "info"], **common)
        return res  # Grey (and Green for non-hashes): facts only, never 'clean'
