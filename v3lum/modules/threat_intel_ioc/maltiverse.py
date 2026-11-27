"""maltiverse: Maltiverse IoC lookup of an IPv4, domain, URL or SHA-256 (keyed only).

Batch p3-G07-1, proposal P154 (council final conditions):

* c1 - keyed only in this build: ``requires_keys = ('maltiverse',)`` (NEEDS_KEY without it). Keyless
  community lookups are never sent: their terms count as 'unknown' until legal records them.
* c2 - the key comes from a company/team account on a plan recorded by legal as
  ``key_plans.maltiverse = 'business'`` (registry source ``maltiverse.lookup``: terms key-terms,
  ``free_plan_business_use`` null, tier trusted): under the corporate profile the policy gate runs the
  module only with that plan.
* c3 - ``GET https://api.maltiverse.com/{ip|hostname|url|sample}/{value}`` only (:func:`request_allowed`
  is the allow-list every request passes, unit-tested); the ``/url/`` key is the SHA-256 of the URL
  string exactly as Maltiverse stores it (:func:`url_checksum`, :func:`url_variants`: the exact string,
  then one variant). ``{"status": "fail", "message": ...}`` bodies inside an HTTP 200 are classified by
  the module error markers (quota -> QUOTA, rate -> RATE_LIMITED, anything else -> ERROR); a 429 whose
  ``RateLimit-Reset`` is beyond one hour is QUOTA. Budget: the provider's P334 day block (the observed
  limit until the recorded plan replaces it); cache 24 h.
* c4 - aggregator semantics: every ``blacklist[]`` hit keeps its source and dates (attribute
  ``maltiverse.listings``) and the finding lists them. The finding's ``data['upstream_families']``
  names the upstream family of each recent listing (abuse.ch, Spamhaus, Blocklist.de...: the families
  the registry source ``embeds``) and ``maltiverse`` only for listings from sources V3LUM does not
  query, so CR27 (P171) never counts Maltiverse as an independent vote for listings it merely relays.
* c5 - classification whitelist/neutral dampens other votes (attribute ``allowlisted``, never a
  finding and never 'clean'); sinkhole/Tor/VPN/proxy/scanner/CDN/hosting booleans become context
  attributes, never malicious; family names in ``blacklist[].description`` (backed by a MITRE or
  Maltiverse malware reference, or family-like names) become ``malware_family`` pivots with
  ``expand=False``.

Unknown objects answer HTTP 200 with a neutral stub ``{classification, type, urlchecksum}``: that is
'not in Maltiverse' (EMPTY), never a neutral vote. The answer is untrusted data: anything that is not
a Maltiverse document is 'could not verify' (ERROR), never an absence.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from v3lum.core import noise
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SOURCE = "maltiverse.lookup"
HOST = "api.maltiverse.com"
BASE = "https://api.maltiverse.com"
WEB = "https://maltiverse.com"
KEY_NAME = "maltiverse"
CACHE_TTL = 86400
URL_MAX_VARIANTS = 2
#: V3LUM entity type -> Maltiverse object path segment
KINDS = {T.IPV4: "ip", T.DOMAIN: "hostname", T.URL: "url", T.SHA256: "sample"}
_PATH_RE = re.compile(r"^/(ip|hostname|url|sample)/([^/?#;]+)$")
CLASSIFICATIONS = ("malicious", "suspicious", "neutral", "whitelist")
#: c5: context booleans -> core vocabulary attribute (context only, never malicious)
CONTEXT_FLAGS = {
    "is_sinkhole": "is_sinkhole", "is_tor_node": "is_tor_exit", "is_vpn_node": "is_vpn", "is_open_proxy": "is_proxy",
    "is_known_scanner": "is_scanner", "is_cdn": "is_cdn", "is_hosting": "is_hosting",
}
CONTEXT_LABELS = {
    "is_sinkhole": "sinkhole", "is_tor_node": "tor", "is_vpn_node": "vpn", "is_open_proxy": "proxy",
    "is_known_scanner": "scanner", "is_cdn": "cdn", "is_hosting": "hosting", "is_mining_pool": "mining_pool",
}
#: activity booleans: reported with the verdict (the verdict itself comes from ``classification``)
THREAT_FLAGS = {
    "is_cnc": "c2", "is_distributing_malware": "malware_distribution", "is_phishing": "phishing",
    "is_storing_phishing": "phishing_hosting", "is_iot_threat": "iot_threat", "is_known_attacker": "attacker",
}
#: threat flags that are CR27 vote tags on a malicious finding
_VOTE_FLAG_TAGS = {"c2": "c2", "malware_distribution": "malware", "phishing": "phishing", "phishing_hosting": "phishing"}
#: P171 decay window (days) per Maltiverse object type; samples have none
DECAY_DAYS = {"ip": 30, "url": 30, "hostname": 90, "sample": None}
#: blacklist[].source -> registry upstream family (only families the registry source ``embeds``);
#: anything else is Maltiverse's own family (one independent family for all of them)
SOURCE_FAMILIES = (
    (r"abuse\.ch|threatfox|urlhaus|feodo|sslbl|malwarebazaar|yaraify", "abuse.ch"),
    (r"spamhaus", "spamhaus"),
    (r"stopforumspam", "stopforumspam"),
    (r"openphish", "openphish"),
    (r"phishtank", "phishtank"),
    (r"google safe ?browsing", "google_safe_browsing"),
    (r"x-force", "ibm-xforce"),
    (r"hybrid-analysis|hybrid analysis", "hybrid_analysis"),
    (r"^triage$", "triage"),
    (r"blocklist\.de", "blocklist.de"),
    (r"ciarmy|cins army|ci army", "cins"),
    (r"alienvault|\botx\b", "otx"),
    (r"internet storm center|\bsans\b|dshield", "dshield"),
    (r"cybercrime-tracker", "cybercrime-tracker"),
    (r"honeydb", "honeydb"),
    (r"emerging ?threats|proofpoint", "emergingthreats"),
    (r"greensnow", "greensnow"),
    (r"binary ?defense", "binarydefense"),
    (r"firehol", "firehol"),
    (r"tor project|torproject", "tor-project"),
    (r"myip\.ms", "myipms"),
    (r"virustotal", "virustotal"),
    (r"urlscan", "urlscan"),
)
OWN_FAMILY = "maltiverse"
_BENIGN_DESC_RE = re.compile(r"(?i)^(matched whitelist source|safe site|top popularity site|alexa top|dns server)")
_BENIGN_SOURCES = re.compile(r"(?i)cisco umbrella|tranco|alexa|public-dns\.info")
#: descriptions naming a category, not a malware family (compared lower-case)
_GENERIC_DESCRIPTIONS = frozenset((
    "phishing", "phishing site", "phishing other", "malware", "malicious url", "malicious host", "malicious hostname",
    "malicious domain", "malicious site", "malicious ip", "malware site", "malware download", "malware distribution site",
    "spam", "mail spammer", "http spammer", "scanning ips", "bots", "botnet command and control server",
    "command and control server", "anonymisation services", "social engineering", "compromised", "generic malware",
    "dns open resolver", "dns server", "hosting provider", "safe site", "top popularity site", "covid19 scam",
    "unreliable subdomains", "google dns", "google ip's", "attacker", "c2", "cryptomining", "miner", "ransomware",
    "backdoor", "exploit", "evasive", "pua", "adware", "trojan", "worm", "rat", "banker", "botnet", "infostealer",
    "stealer", "loader", "downloader", "dropper", "keylogger", "spyware", "ddos", "scam", "malicious", "suspicious",
    "unknown",
))
_FAMILY_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9 _-]{1,39}$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")
_SEVERITY = ("info", "low", "medium", "high", "critical")


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


def as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


def str_list(value: Any, limit: int = 20, item_limit: int = 200) -> list[str]:
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        value = [value]
    out: list[str] = []
    for item in value if isinstance(value, (list, tuple)) else []:
        text = clean_text(item, item_limit)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def parse_ts(value: Any) -> datetime | None:
    """'YYYY-MM-DD HH:MM:SS' (UTC), ISO-8601 or epoch seconds -> aware UTC datetime."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), timezone.utc) if 0 < value < 32503680000 else None
    text = clean_text(value, 64)
    if not text:
        return None
    if re.fullmatch(r"\d{9,11}", text):
        return parse_ts(int(text))
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def iso(value: Any) -> str | None:
    parsed = parse_ts(value)
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ") if parsed else None


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


def slug(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (clean_text(value, 80) or "").lower()).strip("_") or "unknown"


def load_json(content: bytes | str | None) -> tuple[Any, str]:
    """Body -> (parsed JSON, '') or (None, why). HTML pages and empty bodies are never JSON."""
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


def url_checksum(url: str) -> str:
    """c3: the /url/ key is the SHA-256 of the URL string exactly as Maltiverse stores it (UTF-8, no
    canonicalisation): sha256('https://alleom.com/weqmo') is the urlchecksum of the python-maltiverse
    README; live 2026-11-26 'http://example.com' had a document and 'http://example.com/' a stub."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def url_variants(url: Any) -> list[str]:
    """c3: URL strings to look up, in order, at most URL_MAX_VARIANTS: the exact (trimmed) string, then
    one variant - the trailing '/' toggled for a bare-host URL (feeds store both forms), else the
    lower-cased scheme and host when that differs. [] for anything that is not an http(s) URL."""
    if not isinstance(url, str):
        return []
    text = url.strip()
    match = re.match(r"^(https?)://([^/?#]+)(.*)$", text, re.I)
    if not match or any(c.isspace() for c in text):
        return []
    scheme, netloc, rest = match.groups()
    out = [text]
    if rest == "":
        out.append(text + "/")
    elif rest == "/":
        out.append(text[:-1])
    else:
        lowered = f"{scheme.lower()}://{netloc.lower()}{rest}"
        if lowered != text:
            out.append(lowered)
    return out[:URL_MAX_VARIANTS]


def lookup_url(etype: T, value: str) -> str:
    """c3: the read-only lookup URL for one object (ValueError outside the allow-list)."""
    kind = KINDS.get(etype)
    if kind is None:
        raise ValueError(f"maltiverse: unsupported type {etype}")
    if kind == "ip":
        try:
            tail = str(ipaddress.IPv4Address(value.strip()))
        except ValueError as exc:
            raise ValueError("maltiverse: not an IPv4 address") from exc
    elif kind == "hostname":
        tail = normalize_domain(value) or ""
        if not tail:
            raise ValueError("maltiverse: not a domain")
    elif kind == "url":
        if not url_variants(value):
            raise ValueError("maltiverse: not an http(s) URL")
        tail = url_checksum(value.strip())
    else:
        tail = value.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", tail):
            raise ValueError("maltiverse: /sample/ takes a SHA-256")
    return f"{BASE}/{kind}/{tail}"


def request_allowed(method: str, url: str) -> bool:
    """Allow-list (c3): GET https://api.maltiverse.com/{ip|hostname|url|sample}/{value} with no query
    string, fragment or userinfo; every other method, path or host is refused."""
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
    kind, tail = match.groups()
    if kind == "ip":
        try:
            ipaddress.IPv4Address(tail)
        except ValueError:
            return False
        return True
    if kind == "hostname":
        return normalize_domain(tail) == tail
    return bool(re.fullmatch(r"[0-9a-f]{64}", tail))


def is_stub(obj: Any) -> bool:
    """True for the HTTP 200 answer of an unknown object: no blacklist and nothing beyond the identity
    fields, e.g. {"classification": "neutral", "type": "url", "urlchecksum": ...} (live)."""
    if not isinstance(obj, dict) or not obj:
        return False
    identity = {"classification", "type", "urlchecksum", "ip_addr", "hostname", "sha256", "md5", "sha1", "url"}
    return not obj.get("blacklist") and set(obj) <= identity


def fail_message(obj: Any) -> str | None:
    """The documented error body {"status": "fail", "message": "..."} -> its message, else None."""
    if isinstance(obj, dict) and str(obj.get("status", "")).strip().lower() == "fail":
        return clean_text(obj.get("message"), 200) or "fail"
    return None


def source_family(source: Any) -> str:
    """c4: blacklist[].source -> registry upstream family ('ThreatFox Abuse.ch' -> 'abuse.ch'); sources
    V3LUM does not query directly are Maltiverse's own family."""
    text = (clean_text(source, 120) or "").lower()
    for pattern, family in SOURCE_FAMILIES:
        if re.search(pattern, text):
            return family
    return OWN_FAMILY


def _refs(value: Any) -> list[dict[str, Any]]:
    out = []
    for ref in value if isinstance(value, list) else []:
        if not isinstance(ref, dict):
            continue
        item = {"source_name": clean_text(ref.get("source_name"), 40), "external_id": clean_text(ref.get("external_id"), 60),
                "name": clean_text(ref.get("description"), 80)}
        if item["source_name"] or item["external_id"]:
            out.append(item)
    return out[:5]


def _is_benign(entry: dict[str, Any]) -> bool:
    if "benign" in entry["labels"] or _BENIGN_DESC_RE.match(entry["description"] or ""):
        return True
    return bool(_BENIGN_SOURCES.search(entry["source"] or "")) and not ({"malicious-activity", "malware", "botnet"} & set(entry["labels"]))


def parse_blacklist(value: Any, limit: int = 200) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """blacklist[] -> (listings, benign_listings): each {source, family, description, first_seen,
    last_seen, count, labels, refs, mitre_ids}. Provenance per hit is kept (c4); benign listings
    ('benign' label, 'Matched whitelist source', popularity lists) never count as votes."""
    hits: list[dict[str, Any]] = []
    benign: list[dict[str, Any]] = []
    for item in value if isinstance(value, list) else []:
        if not isinstance(item, dict):
            continue
        source = clean_text(item.get("source"), 120)
        entry: dict[str, Any] = {
            "source": source,
            "family": source_family(source),
            "description": clean_text(item.get("description"), 200),
            "first_seen": iso(item.get("first_seen")),
            "last_seen": iso(item.get("last_seen")) or iso(item.get("first_seen")),
            "count": as_int(item.get("count")),
            "labels": [x.lower() for x in str_list(item.get("labels"), 10, 40)],
            "refs": _refs(item.get("external_references")),
        }
        entry["mitre_ids"] = [r["external_id"] for r in entry["refs"]
                              if r["source_name"] == "mitre-attack" and re.fullmatch(r"S\d{4}", r["external_id"] or "")]
        (benign if _is_benign(entry) else hits).append(entry)
        if len(hits) + len(benign) >= limit:
            break
    return hits, benign


def _malware_ref_name(entry: dict[str, Any]) -> str | None:
    for ref in entry.get("refs", []):
        mitre = ref.get("source_name") == "mitre-attack" and re.fullmatch(r"S\d{4}", ref.get("external_id") or "")
        own = ref.get("source_name") == "maltiverse" and ref.get("external_id")
        name = (ref.get("name") or "").strip()
        if (mitre or own) and name and _FAMILY_NAME_RE.match(name) and name.lower() not in _GENERIC_DESCRIPTIONS:
            return name
    return None


def family_name(entry: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    """c5: one listing -> (family, basis 'reference' | 'name', alias). Generic categories ('Malicious
    URL', 'Generic Malware'), AV signatures without a reference ('Trojan.Agent') and tag lists without a
    reference ('banker,ramnit') give (None, None, None)."""
    desc = (entry.get("description") or "").strip()
    if not desc or desc.lower() in _GENERIC_DESCRIPTIONS or re.search(r"(?i)phishing|malicious|spam|scam|whitelist|generic", desc):
        return None, None, None
    desc_ok = "," not in desc and not re.search(r"[.:/!]", desc) and bool(_FAMILY_NAME_RE.match(desc)) and len(desc.split()) <= 3
    ref = _malware_ref_name(entry)
    if desc_ok:
        return desc, ("reference" if ref else "name"), (ref if ref and ref.lower() != desc.lower() else None)
    if ref:
        return ref, "reference", None
    return None, None, None


def families(hits: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    """c5: malware families from the listings, deduplicated case-insensitively, newest first."""
    best: dict[str, dict[str, Any]] = {}
    for hit in hits:
        name, basis, alias = family_name(hit)
        if not name:
            continue
        cur = {"name": name, "basis": basis, "alias": alias, "mitre_id": (hit.get("mitre_ids") or [None])[0],
               "source": hit.get("source"), "last_seen": hit.get("last_seen")}
        prev = best.get(name.lower())
        if prev is None:
            best[name.lower()] = cur
            continue
        merged = dict(cur if (cur["last_seen"] or "") > (prev["last_seen"] or "") else prev)
        refs = [x for x in (prev, cur) if x["basis"] == "reference"]
        if refs:
            merged.update(basis="reference", mitre_id=next((x["mitre_id"] for x in refs if x["mitre_id"]), None),
                          alias=next((x["alias"] for x in refs if x["alias"]), None))
        best[name.lower()] = merged
    return sorted(best.values(), key=lambda f: f["last_seen"] or "", reverse=True)[:limit]


def parse_document(obj: Any) -> dict[str, Any] | None:
    """One Maltiverse document (ip, hostname, url or sample) -> normalised facts; None when it is not a
    usable document (fail body, stub, unknown type). Contact mailboxes, postal addresses, registrant
    names, WHOIS, process lists and submitted file names are never copied."""
    if not isinstance(obj, dict) or fail_message(obj) is not None or is_stub(obj):
        return None
    kind = (clean_text(obj.get("type"), 20) or "").lower()
    if kind not in ("ip", "hostname", "url", "sample"):
        return None
    cls = (clean_text(obj.get("classification"), 30) or "").lower()
    cls = "whitelist" if cls == "whitelisted" else cls
    hits, benign = parse_blacklist(obj.get("blacklist"))
    asn = as_int(obj.get("as_number"))
    as_name = clean_text(obj.get("as_name"), 120)
    if asn is None and as_name:
        match = re.match(r"^AS(\d{1,10})\b", as_name)
        asn = int(match.group(1)) if match else None
    out: dict[str, Any] = {
        "type": kind,
        "value": clean_text({"ip": obj.get("ip_addr"), "hostname": obj.get("hostname"), "url": obj.get("url"),
                             "sample": obj.get("sha256")}[kind], 2000),
        "classification": cls if cls in CLASSIFICATIONS else None,
        "score": as_float(obj.get("score")),
        "listings": hits,
        "benign_listings": benign,
        "families": families(hits),
        "context": sorted({CONTEXT_LABELS[k] for k in CONTEXT_LABELS if as_bool(obj.get(k))}),
        "context_attrs": sorted({CONTEXT_FLAGS[k] for k in CONTEXT_FLAGS if as_bool(obj.get(k))}),
        "threat_flags": sorted({tag for k, tag in THREAT_FLAGS.items() if as_bool(obj.get(k))}),
        "tags": [t.lower() for t in str_list(obj.get("tag"), 30, 60) if not re.match(r"(?i)^https?://", t)],
        "asn": asn,
        "as_name": as_name,
        "cidr": str_list(obj.get("cidr") or obj.get("asn_cidr"), 5, 50),
        "country": ((clean_text(obj.get("country_code") or obj.get("asn_country_code"), 5) or "").upper() or None),
        "first_seen": iso(obj.get("creation_time")),
        "last_seen": iso(obj.get("modification_time")),
    }
    if kind == "ip":
        out["domains_resolving"] = as_int(obj.get("number_of_domains_resolving"))
        out["blacklisted_domains_resolving"] = as_int(obj.get("number_of_blacklisted_domains_resolving"))
    elif kind == "hostname":
        resolved = []
        for row in obj.get("resolved_ip") if isinstance(obj.get("resolved_ip"), list) else []:
            text = clean_text(row.get("ip_addr"), 64) if isinstance(row, dict) else None
            try:
                resolved.append(str(ipaddress.ip_address(text or "")))
            except ValueError:
                continue
        out["resolved_ips"] = resolved[:10]
        out["domain_created"] = iso(obj.get("domain_creation_time"))
    elif kind == "url":
        out["urlchecksum"] = clean_text(obj.get("urlchecksum"), 64)
        out["hostname"] = normalize_domain(obj.get("hostname"))
    else:
        signatures = []
        for row in obj.get("antivirus") if isinstance(obj.get("antivirus"), list) else []:
            name = clean_text(row.get("description"), 120) if isinstance(row, dict) else None
            if name and name not in signatures:
                signatures.append(name)
        out.update({"av_ratio": as_int(obj.get("av_ratio")), "file_type": clean_text(obj.get("filetype"), 120),
                    "size": as_int(obj.get("size")), "av_signatures": signatures[:20]})
    return out


def recent_split(parsed: dict[str, Any], now: datetime) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Listings inside / outside the P171 decay window of the object type (samples: all recent)."""
    window = DECAY_DAYS.get(parsed.get("type") or "")
    if window is None:
        return list(parsed.get("listings", [])), []
    recent, stale = [], []
    for hit in parsed.get("listings", []):
        seen = parse_ts(hit.get("last_seen"))
        age = (now - seen).total_seconds() / 86400 if seen else None
        (recent if age is not None and age <= window else stale).append(hit)
    return recent, stale


def vote_families(parsed: dict[str, Any], now: datetime) -> list[str]:
    """c4: the families a malicious/suspicious verdict stands for, for CR27 (P171): the upstream family of
    each recent listing; Maltiverse's own family only for listings from sources V3LUM does not query
    directly. Without recent listings the verdict is Maltiverse's own (dated by its last update)."""
    recent, _stale = recent_split(parsed, now)
    fams = sorted({hit["family"] for hit in recent})
    return fams or [OWN_FAMILY]


def sources_summary(hits: list[dict[str, Any]], limit: int = 5) -> str:
    """c4 wording: 'ThreatFox Abuse.ch (last 2023-09-11), Myip.ms (last 2026-10-20) +3 more', newest first."""
    seen: list[str] = []
    parts = []
    for hit in sorted(hits, key=lambda h: h.get("last_seen") or "", reverse=True):
        src = hit.get("source") or "unknown source"
        if src in seen:
            continue
        seen.append(src)
        if len(parts) < limit:
            parts.append(f"{src} (last {(hit.get('last_seen') or '?')[:10]})")
    more = len(seen) - len(parts)
    return ", ".join(parts) + (f" +{more} more" if more > 0 else "")


def web_link(etype: T, value: str, parsed: dict[str, Any] | None = None) -> str:
    kind = KINDS.get(etype, "search")
    tail = (parsed or {}).get("urlchecksum") or (url_checksum(value) if kind == "url" else value)
    return f"{WEB}/{kind}/{tail}"


def public_ip(value: str) -> bool:
    """Private, reserved and documentation addresses are never sent (patched in tests)."""
    return noise.is_public_ip(value)


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class Maltiverse(Module):
    name = "maltiverse"
    title = "Maltiverse IoC lookup"
    description = (
        "Maltiverse classification and per-source blacklist history (source, dates, count) of an IPv4, "
        "domain, URL or SHA-256 from api.maltiverse.com (key required; read-only lookups)."
    )
    category = "threat_intel_ioc"
    accepts = {T.IPV4, T.DOMAIN, T.URL, T.SHA256}
    produces = {T.MALWARE}
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "maltiverse"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,)
    error_markers = (
        {"id": "maltiverse_fail_quota", "statuses": [200, 400, 403, 429], "json_path": "message",
         "regex": "(?i)quota|daily|monthly|per day|per month", "maps_to": "quota", "reason_code": "quota",
         "reason": "Maltiverse: quota of the key's plan exhausted (could not verify; deferred)"},
        {"id": "maltiverse_fail_rate", "statuses": [200, 429], "json_path": "message",
         "regex": "(?i)rate|too many|limit", "maps_to": "rate_limited", "reason_code": "rate_limited",
         "reason": "Maltiverse: rate limited (could not verify now)"},
        {"id": "maltiverse_fail_error", "statuses": [200], "json_path": "status", "equals": "fail",
         "maps_to": "error", "reason_code": "error",
         "reason": "Maltiverse: error inside an HTTP 200 answer (status fail): could not verify"},
    )
    max_requests = URL_MAX_VARIANTS  # URL entities: the exact string plus one variant (c3)
    expected_latency = 0.5
    timeout = 30.0
    min_interval = 1.0
    cache_ttl = CACHE_TTL
    max_pivots = 20
    manual_link = "threat_intel_g07_p3:maltiverse_ip"
    default_enabled = True
    tags = {"reputation"}
    reference = "https://github.com/maltiverse/python-maltiverse"
    notice = (
        "Maltiverse is keyed only in this build (key 'maltiverse'; keyless community lookups are never sent). "
        "Under the corporate profile it runs only with a company/team plan recorded as key_plans.maltiverse=business "
        "(never an analyst's personal free account). Maltiverse aggregates other feeds: its verdict counts in the "
        "consensus only for listings from sources V3LUM does not query itself."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.IPV4:
            return public_ip(entity.value)  # private/reserved addresses are never sent
        if entity.type is T.URL:
            return bool(url_variants(entity.value))
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = str(ctx.key(KEY_NAME) or "").strip()
        if not key:
            return res.mark(Status.NEEDS_KEY, "needs the Maltiverse key (v3lum keys set maltiverse)", reason_code="needs_key")
        candidates = url_variants(entity.value) if entity.type is T.URL else [entity.value]
        stubs: list[str] = []
        parsed: dict[str, Any] | None = None
        for value in candidates:
            try:
                url = lookup_url(entity.type, value)
            except ValueError as exc:
                return res.mark(Status.SKIPPED, str(exc), reason_code="not_applicable")
            if not request_allowed("GET", url):  # c3: never anything but the four lookups
                return res.mark(Status.ERROR, "refused a non-allow-listed Maltiverse request (module bug)", reason_code="error")
            resp = ctx.http.get(url, headers={"Authorization": f"Bearer {key}", "Accept": "application/json"}, source=SOURCE)
            if resp.status == 404 and resp.classification is None:
                stubs.append(value)  # an unknown object: the same as the neutral stub
                continue
            if resp.status == 429 and resp.classification is not None and resp.classification.status == "rate_limited":
                reset = as_int((resp.headers or {}).get("ratelimit-reset"))
                if reset is not None and reset > 3600:
                    res.link("Maltiverse page (manual)", web_link(entity.type, entity.value))
                    return res.mark(Status.QUOTA, f"Maltiverse: daily quota of the key exhausted (HTTP 429, reset in {reset} s): could not verify; deferred",
                                    reason_code="quota")
            ctx.http.check(resp)  # 401/403 NEEDS_KEY, 429 RATE_LIMITED, fail markers, challenges, 5xx
            obj, why = load_json(resp.content)
            if why:
                return res.mark(Status.ERROR, f"unexpected Maltiverse answer ({why}): could not verify", reason_code="error")
            if not isinstance(obj, dict):
                return res.mark(Status.ERROR, "unexpected Maltiverse answer (not a JSON object): could not verify", reason_code="error")
            message = fail_message(obj)
            if message is not None:  # a fail body the markers did not classify
                return res.mark(Status.ERROR, f"Maltiverse error inside an HTTP 200 answer ({message}): could not verify", reason_code="error")
            if is_stub(obj):
                stubs.append(value)
                continue
            parsed = parse_document(obj)
            if parsed is None:
                return res.mark(Status.ERROR, "unexpected Maltiverse answer (not an ip/hostname/url/sample document): could not verify",
                                reason_code="error")
            break
        if parsed is None:
            res.raw = {"status": 200, "not_found": True, "looked_up": len(stubs)}
            return res.mark(Status.EMPTY, f"not in Maltiverse ({len(stubs)} lookup(s) answered an unknown-object stub)")
        return self._report(res, ctx, entity, parsed)

    # ---- report (c4, c5) -----------------------------------------------------------------
    def _report(self, res: ModuleResult, ctx: Any, entity: Entity, p: dict[str, Any]) -> ModuleResult:
        now = ctx.now()
        link = web_link(entity.type, entity.value, p)
        recent, stale = recent_split(p, now)
        recent_ids = {id(h) for h in recent}
        listings = [{k: h[k] for k in ("source", "family", "description", "first_seen", "last_seen", "count")} | {"recent": id(h) in recent_ids}
                    for h in p["listings"]]
        facts = {
            "type": p["type"], "classification": p["classification"], "score": p["score"], "listings": listings[:50],
            "benign_listings": [{k: h[k] for k in ("source", "description", "last_seen")} for h in p["benign_listings"][:20]],
            "families": [f["name"] for f in p["families"]], "context_tags": p["context"], "threat_flags": p["threat_flags"],
            "asn": p["asn"], "as_name": p["as_name"], "cidr": p["cidr"], "country": p["country"], "link": link,
        }
        for extra in ("resolved_ips", "domains_resolving", "av_ratio", "file_type", "size", "domain_created"):
            if p.get(extra) is not None:
                facts[extra] = p[extra]
        res.raw = {"status": 200, "document": {k: v for k, v in p.items() if k not in ("benign_listings",)}}
        res.link("Maltiverse page", link)
        res.attr("maltiverse", facts)
        res.attr("reputation", {"maltiverse": p["classification"] or "unknown"})
        if p["asn"] is not None:
            res.attr("asn", f"AS{p['asn']}")
        res.attr("country", p["country"] if p["country"] and re.fullmatch(r"[A-Z]{2}", p["country"]) else None)
        res.attr("first_seen", p["first_seen"])
        res.attr("last_seen", p["last_seen"])
        for attr in p["context_attrs"]:  # c5: context, never malicious
            res.attr(attr, True)
        if p["type"] == "sample":
            res.attr("file_type", p.get("file_type"))
            res.attr("file_size", p.get("size"))
            res.attr("av_signatures", p.get("av_signatures"))
        fams = p["families"]
        if fams:
            res.attr("malware_family", [f["name"] for f in fams])
        self._pivot_families(res, entity, fams)
        cls = p["classification"]
        if cls in ("whitelist", "neutral"):  # c5: dampens other votes; never a finding, never 'clean'
            reasons = [f"Maltiverse classification {cls}"]
            reasons += [f"Maltiverse listing: {h['source']} - {h['description']}" for h in p["benign_listings"][:3] if h.get("description")]
            res.attr("allowlisted", reasons)
            return res
        if cls not in ("malicious", "suspicious"):
            return res  # no usable classification: facts only (never 'clean')
        votes = vote_families(p, now)
        summary = sources_summary(p["listings"]) or "no listing source named"
        newest = max((h["last_seen"] for h in p["listings"] if h.get("last_seen")), default=None) or p["last_seen"]
        oldest = min((h["first_seen"] for h in p["listings"] if h.get("first_seen")), default=None) or p["first_seen"]
        description = (
            f"Maltiverse classification {cls}" + (f" (score {p['score']:g})" if p["score"] is not None else "")
            + f"; listed by {summary}. {len(recent)} recent and {len(stale)} older listing(s)"
            + (f"; context: {', '.join(p['context'])}" if p["context"] else "") + "."
        )
        data = {"classification": cls, "score": p["score"], "listings": listings[:20], "upstream_families": votes,
                "context_tags": p["context"], "threat_flags": p["threat_flags"], "families": [f["name"] for f in fams][:10]}
        common = {"references": [link], "source": SOURCE, "observed_first": oldest, "observed_last": newest, "data": data}
        criterion = f"Maltiverse classification {cls}; listed by {summary}"
        if cls == "malicious":
            tags = ["malicious"] + sorted({_VOTE_FLAG_TAGS[t] for t in p["threat_flags"] if t in _VOTE_FLAG_TAGS})
            res.finding("Listed as malicious by Maltiverse", "medium", description,
                        confidence="probable" if recent else "possible", criterion=criterion, tags=tags, **common)
        else:
            res.finding("Suspicious per Maltiverse", "low", description, confidence="possible", criterion=criterion,
                        tags=["suspicious"], **common)
        return res

    def _pivot_families(self, res: ModuleResult, entity: Entity, fams: list[dict[str, Any]]) -> None:
        """c5: malware_family pivots with expand=False; none for warninglisted values (sandbox noise such
        as example.com connectivity checks)."""
        try:
            listed = noise.warninglists(entity)
        except Exception:  # noqa: BLE001 - a list problem never blocks the facts
            listed = []
        if listed:
            return
        for fam in fams[: self.max_pivots]:
            note = f"Maltiverse listing by {fam['source'] or 'unknown source'}" + (f" ({fam['mitre_id']})" if fam.get("mitre_id") else "")
            res.pivot(T.MALWARE, fam["name"], "family", confidence="probable" if fam["basis"] == "reference" else "possible",
                      expand=False, note=note)
