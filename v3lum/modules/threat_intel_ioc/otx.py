"""AlienVault/LevelBlue OTX indicator lookups (P153): ``otx`` (API key) and ``otx_keyless`` (general only).

Both classes share one parser (P153 cond 1):

* ``otx`` sends the key ``otx`` (header ``X-OTX-API-KEY``) and reads the indicator sections
  ``general`` (always), ``passive_dns`` (analyst-typed seeds only) and ``url_list`` + ``malware``
  (only when the indicator is in at least one pulse, or with ``--preset deep``); NEEDS_KEY without
  the key;
* ``otx_keyless`` sends no key and reads ``general`` only; default off (keyless calls take about
  25 s and answer 429 on shared egress: A3 latency rule).

Read-only by construction (cond 2): :func:`indicator_url` builds only ``GET
/api/v1/indicators/{category}/{value}/{section}`` for the four sections above and
:func:`request_allowed` is the allow-list a test runs over every URL the modules send (no pulse
creation, no indicator submission, no pulse indicator export).

Bounds (cond 4): per-call timeout 20 s (60 s with ``--preset deep``), never past the run deadline;
5 MB per answer (a truncated answer is never parsed as complete); pulses capped at 50 by recency;
cache 24 h. 401/403 = NEEDS_KEY (key rejected; the ``general`` section ignores bad keys, keyed
sections expose them); 429 = RATE_LIMITED, never 'not listed'; an error inside a 200 body is
'could not verify'.

Verdict (cond 5): pulse membership is not a verdict. Allow-listed indicators (OTX validation /
accepted false positive) and P169 warninglist or benign-infrastructure hits give an info finding
and never a malicious one; 'malicious' needs >= 2 pulses from distinct authors modified in the last
365 days or one pulse by the AlienVault/LevelBlue labs account; otherwise 'mentioned in N community
pulses' (low). Pulses relaying abuse.ch count as ONE author (upstream family abuse.ch, P171) and a
clone of another counted pulse is ignored. CVEs are never tagged malicious.

Findings (cond 6) show the pulse count and the top 3 pulse names/authors/dates; pulse dates fill
``observed_first``/``observed_last``. Pivots (cond 7): adversary / malware families / ATT&CK ids ->
``attributed_to`` / ``family`` / ``uses_technique`` with ``expand=False`` (community labels, low
confidence), names cleaned and canonicalised by :func:`canonical_name` (the P295 alias index hook).
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from collections.abc import Callable, Iterable
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

from v3lum.core import noise, psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, HttpError, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SOURCE = "otx.indicators"
HOST = "otx.alienvault.com"
API = "https://otx.alienvault.com/api/v1/indicators"
KEY_NAME = "otx"
KEY_HEADER = "X-OTX-API-KEY"
#: cond 4: answers above this size are truncated by the core and never parsed as complete
MAX_BYTES = 5_000_000
#: cond 4: pulses kept per indicator (newest first)
MAX_PULSES = 50
#: cond 4: per-call timeout by preset (always capped by the run deadline)
TIMEOUT_S = {"quick": 20.0, "deep": 60.0}
#: url_list pages read at most (limit=100 per page), within max_requests
URL_LIST_MAX_PAGES = 3
#: cond 5: recency window of the 'two distinct authors' rule
RECENT_DAYS = 365
#: cond 5: labs account (observed 2026-11-25: labs pulses are authored by 'AlienVault', author id 2)
LABS_USERNAMES = frozenset({"alienvault", "levelblue", "levelbluelabs"})
LABS_AUTHOR_IDS = frozenset({"2"})
#: cond 6 / P171: pulses relaying abuse.ch data count as the abuse.ch upstream family
ABUSECH_HINTS = ("abuse.ch", "abuse_ch", "abusech", "urlhaus", "threatfox", "malwarebazaar", "malware bazaar", "feodotracker", "feodo tracker", "sslbl")

#: indicator sections the modules may call (cond 2) per OTX category
SECTIONS: dict[str, tuple[str, ...]] = {
    "IPv4": ("general", "passive_dns", "url_list", "malware"),
    "IPv6": ("general", "passive_dns", "url_list", "malware"),
    "domain": ("general", "passive_dns", "url_list", "malware"),
    "hostname": ("general", "passive_dns", "url_list", "malware"),
    "url": ("general", "url_list"),
    "file": ("general",),
    "cve": ("general",),
}
_TYPE_CATEGORY = {
    T.IPV4: "IPv4", T.IPV6: "IPv6", T.URL: "url", T.MD5: "file", T.SHA1: "file", T.SHA256: "file", T.CVE: "cve",
}
_TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_MITRE_SW_RE = re.compile(r"^(.*?)\s*-\s*([Ss]\d{4})$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
#: community labels that are not names of a family or an actor
JUNK_LABELS = frozenset({
    "", "unknown", "none", "null", "n/a", "na", "other", "others", "malware", "generic", "test", "mitre attack",
    "mitre att&ck", "et", "trojan", "virus", "unknown malware", "botnet", "c2", "apt", "ransomware",
})
#: canonical spellings of frequent family labels (stand-in for the P295 alias index, WP17)
FAMILY_CANON = {
    "cobaltstrike": "Cobalt Strike", "cobalt strike": "Cobalt Strike", "sliver": "Sliver", "metasploit": "Metasploit",
    "havoc": "Havoc", "brute ratel": "Brute Ratel C4", "bruteratel": "Brute Ratel C4", "mythic": "Mythic",
}


# --------------------------------------------------------------------------------------
# small defensive helpers (untrusted provider data)
# --------------------------------------------------------------------------------------


def _text(value: Any, limit: int = 300) -> str:
    """Untrusted scalar -> printable text without control characters ('' for anything else)."""
    if value is None or isinstance(value, (dict, list, bool)):
        return ""
    return _CTRL_RE.sub("", str(value)).strip()[:limit]


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_ts(value: Any) -> _dt.datetime | None:
    """Provider timestamp (ISO 8601 with or without zone/fraction, epoch seconds) -> aware UTC or None."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, _dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=_dt.timezone.utc)
    if isinstance(value, (int, float)):
        try:
            return _dt.datetime.fromtimestamp(float(value), _dt.timezone.utc) if 0 < value < 32503680000 else None
        except (OverflowError, OSError, ValueError):
            return None
    text = _text(value, 64)
    if not text:
        return None
    text = re.sub(r"\s*UTC$", "", text, flags=re.I)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = _dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=_dt.timezone.utc)


def _iso(value: _dt.datetime | None) -> str | None:
    return value.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if isinstance(value, _dt.datetime) else None


def clean_label(value: Any, max_len: int = 64) -> str | None:
    """Community actor/family label -> display name, or None for junk (hashes, 'MD5 Hash: ...',
    prose, generic words). Person names filed as 'families' cannot be recognised: their pivots are
    expand=False and low confidence (cond 7)."""
    text = _text(value, 400)
    if not text:
        return None
    text = re.sub(r"(?i)^(?:malware\s*family|family|adversary|threat\s*actor|actor|malware)\s*:\s*", "", text)
    if re.search(r"(?i)\b(?:md5|sha-?1|sha-?256|hash)\b\s*:", text) or (_HEX_RE.match(text) and len(text) >= 32):
        return None
    text = re.sub(r"\s*\(.*$", "", text)
    text = re.sub(r"\s+", " ", text).strip(" -_.,;:|")
    if not text or len(text) > max_len or text.lower() in JUNK_LABELS:
        return None
    return text


def split_mitre_software(name: str) -> tuple[str, str | None]:
    """'Cobalt Strike - S0154' -> ('Cobalt Strike', 'S0154')."""
    match = _MITRE_SW_RE.match(name.strip())
    return (match.group(1).strip(), match.group(2).upper()) if match else (name.strip(), None)


def canonical_name(kind: str, raw: Any) -> str | None:
    """Clean and canonicalise an actor/family label (kind 'malware_family' | 'threat_actor').

    Stand-in for the P295 actor/malware alias index (``v3lum/data/aliases``, read from wave 3):
    junk is dropped, MITRE software ids are split off and a few frequent spellings are unified."""
    name = clean_label(raw)
    if not name:
        return None
    name, _software_id = split_mitre_software(name)
    if not name:
        return None
    if kind == "malware_family":
        return FAMILY_CANON.get(name.lower(), name)
    return name


# --------------------------------------------------------------------------------------
# request building (cond 2: read-only by construction)
# --------------------------------------------------------------------------------------


def category(entity: Entity) -> str | None:
    """OTX indicator category of an entity: 'domain' for a PSL registrable domain, 'hostname' below it."""
    if entity.type is T.DOMAIN:
        value = entity.value.lower().rstrip(".")
        try:
            reg = psl.registrable_domain(value)
        except Exception:  # noqa: BLE001 - a PSL problem falls back to the label count
            reg = None
        if reg:
            return "domain" if reg == value else "hostname"
        return "domain" if value.count(".") <= 1 else "hostname"
    return _TYPE_CATEGORY.get(entity.type)


def indicator_url(entity: Entity, section: str = "general", *, page: int | None = None) -> str | None:
    """https://otx.alienvault.com/api/v1/indicators/{category}/{value}/{section} (cond 2); None for a
    section the modules may not call. The value is percent-encoded except ':' and '/'."""
    cat = category(entity)
    if not cat or section not in SECTIONS.get(cat, ()):
        return None
    value = entity.value.strip()
    if not value:
        return None
    if cat in ("domain", "hostname", "file"):
        value = value.lower()
    elif cat == "cve":
        value = value.upper()
    url = f"{API}/{cat}/{quote(value, safe=':/')}/{section}"
    if section == "url_list":
        url += f"?limit=100&page={int(page or 1)}"
    return url


def request_allowed(method: str, url: str) -> bool:
    """Read-only allow-list (cond 2): GET on /api/v1/indicators/{category}/{value}/{section} for the
    sections of :data:`SECTIONS` only (url_list may carry limit/page). Everything else is refused."""
    if (method or "").upper() != "GET" or not isinstance(url, str):
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme != "https" or parts.hostname != HOST or not parts.path.startswith("/api/v1/indicators/"):
        return False
    rest = parts.path[len("/api/v1/indicators/"):]
    cat, _, tail = rest.partition("/")
    section = tail.rsplit("/", 1)[-1] if "/" in tail else ""
    if cat not in SECTIONS or section not in SECTIONS[cat]:
        return False
    return not (parts.query and (section != "url_list" or set(parse_qs(parts.query)) - {"limit", "page"}))


def report_link(entity: Entity) -> str | None:
    """The OTX web page of the indicator (a single-page app; manual follow-up only)."""
    cat = category(entity)
    if not cat:
        return None
    value = entity.value.strip()
    if cat in ("domain", "hostname", "file"):
        value = value.lower()
    elif cat == "cve":
        value = value.upper()
    segment = {"IPv4": "ip", "IPv6": "ip"}.get(cat, cat)
    return f"https://otx.alienvault.com/indicator/{segment}/{quote(value, safe=':/')}"


def plan_sections(entity: Entity, pulse_count: int, *, is_seed: bool, preset: str = "quick", keyless: bool = False,
                  available: Iterable[str] | None = None) -> list[str]:
    """Sections to call in order (cond 1/2): 'general' always (otx_keyless stops there); with a key
    'passive_dns' only for analyst-typed seeds, 'url_list' and 'malware' only when the indicator is in
    at least one pulse or with ``--preset deep``. ``available`` is the 'sections' list of the general
    answer (intersected when given)."""
    cat = category(entity)
    if not cat:
        return []
    if keyless:
        return ["general"]
    allowed = set(SECTIONS[cat])
    if available:
        offered = {s for s in available if isinstance(s, str)}
        if offered:
            allowed &= offered | {"general"}
    plan = ["general"]
    if is_seed and "passive_dns" in allowed:
        plan.append("passive_dns")
    if (pulse_count or 0) > 0 or preset == "deep":
        plan += [s for s in ("url_list", "malware") if s in allowed]
    return plan


def call_timeout(preset: str, remaining: float | None) -> float:
    """cond 4: 20 s (quick) / 60 s (deep) per call, never beyond the time left in the run."""
    limit = TIMEOUT_S["deep" if preset == "deep" else "quick"]
    return max(1.0, min(limit, remaining)) if remaining is not None else limit


# --------------------------------------------------------------------------------------
# parsing (one shared parser, cond 1)
# --------------------------------------------------------------------------------------


def pulse_upstream(pulse: dict[str, Any]) -> str:
    """'abuse.ch' when the pulse relays abuse.ch data (author, name, tags, references), else 'otx' (cond 6)."""
    hay = " ".join([str(pulse.get("author") or ""), str(pulse.get("name") or "")]
                   + [str(t) for t in pulse.get("tags") or []] + [str(r) for r in pulse.get("references") or []]).lower()
    return "abuse.ch" if any(hint in hay for hint in ABUSECH_HINTS) else "otx"


def _pulse(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    author = _dict(raw.get("author"))
    families = []
    for item in _list(raw.get("malware_families")):
        name = (item.get("display_name") or item.get("id")) if isinstance(item, dict) else item
        if isinstance(name, str):
            families.append(name)
    techniques = []
    for item in _list(raw.get("attack_ids")):
        tid = item.get("id") if isinstance(item, dict) else item
        if isinstance(tid, str) and _TECH_RE.match(tid.strip().upper()):
            techniques.append(tid.strip().upper())
    created, modified = parse_ts(raw.get("created")), parse_ts(raw.get("modified"))
    pulse_id = _text(raw.get("id"), 64)
    if not re.fullmatch(r"[0-9a-fA-F]{8,64}", pulse_id):
        pulse_id = ""
    out = {
        "id": pulse_id,
        "name": _text(raw.get("name"), 200),
        "author": _text(author.get("username"), 80),
        "author_id": _text(author.get("id"), 32),
        "created": _iso(created),
        "modified": _iso(modified or created),
        "tags": [t for t in (_text(x, 80) for x in _list(raw.get("tags"))) if t][:20],
        "adversary": _text(raw.get("adversary"), 200),
        "malware_families": families[:20],
        "attack_ids": techniques[:40],
        "references": [r for r in (_text(x, 500) for x in _list(raw.get("references"))) if r][:10],
        "cloned_from": _text(raw.get("cloned_from"), 64),
    }
    out["link"] = f"https://otx.alienvault.com/pulse/{pulse_id}" if pulse_id else ""
    out["upstream"] = pulse_upstream(out)
    return out


def parse_general(obj: Any, max_pulses: int = MAX_PULSES) -> dict[str, Any] | None:
    """The 'general' section -> normalised facts; None when the answer is not a JSON object.

    Keys: pulse_count (provider total), pulses (newest first, capped by recency), pulses_capped,
    allowlisted (validation / accepted false-positive reasons), asn, country, sections, related
    {adversary, malware_families}, cve {cvss, vector, epss, seen_wild, cwe} for CVEs."""
    if not isinstance(obj, dict):
        return None
    info = _dict(obj.get("pulse_info"))
    pulses = [p for p in (_pulse(x) for x in _list(info.get("pulses"))) if p]
    pulses.sort(key=lambda p: p.get("modified") or "", reverse=True)
    count = _int(info.get("count"))
    reasons: list[str] = []
    for item in _list(obj.get("validation")):
        if isinstance(item, dict):
            reason = _text(item.get("name"), 120) or _text(item.get("message"), 120) or _text(item.get("source"), 40)
            if reason and reason not in reasons:
                reasons.append(reason)
    for item in _list(obj.get("false_positive")):
        accepted = isinstance(item, dict) and _text(item.get("assessment"), 40).lower() == "accepted"
        if accepted and not any("false positive" in r.lower() for r in reasons):
            reasons.append("Known False Positive")
    related: dict[str, list[str]] = {"adversary": [], "malware_families": []}
    for origin in ("alienvault", "other"):
        block = _dict(_dict(info.get("related")).get(origin))
        for field in related:
            for value in _list(block.get(field)):
                text = _text(value, 200)
                if text and text not in related[field]:
                    related[field].append(text)
    out: dict[str, Any] = {
        "indicator": _text(obj.get("indicator"), 2000),
        "pulse_count": max(count if count is not None else 0, len(pulses)),
        "pulses": pulses[:max_pulses],
        "pulses_capped": len(pulses) > max_pulses,
        "allowlisted": reasons,
        "asn": _text(obj.get("asn"), 120),
        "country": _text(obj.get("country_code2") or obj.get("country_code"), 4).upper(),
        "sections": [s for s in _list(obj.get("sections")) if isinstance(s, str)][:20],
        "related": related,
        "cve": None,
    }
    cvss3 = _dict(_dict(obj.get("cvssv3")).get("cvssV3"))
    if obj.get("cve") or cvss3:
        cwe = obj.get("cwe")
        out["cve"] = {
            "cvss": _float(cvss3.get("baseScore")),
            "vector": _text(cvss3.get("vectorString"), 80),
            "severity": _text(cvss3.get("baseSeverity"), 20),
            "epss": _float(obj.get("epss")),
            "seen_wild": obj.get("seen_wild") if isinstance(obj.get("seen_wild"), bool) else None,
            "cwe": [c for c in (_text(x, 30) for x in (cwe if isinstance(cwe, list) else [cwe])) if c][:5],
        }
    return out


def _is_labs(pulse: dict[str, Any]) -> bool:
    user = (pulse.get("author") or "").lower()
    return user in LABS_USERNAMES and (not pulse.get("author_id") or pulse.get("author_id") in LABS_AUTHOR_IDS)


def verdict(parsed: dict[str, Any], now: _dt.datetime, *, is_cve: bool = False, benign_reasons: Iterable[str] = (),
            window_days: int = RECENT_DAYS) -> dict[str, Any]:
    """cond 5: pulse membership is not a verdict.

    'noise' for allow-listed indicators or benign infrastructure (never malicious, whatever the
    pulses say); 'malicious' with >= 2 distinct authors of pulses modified within ``window_days`` or
    a labs pulse (abuse.ch relays count as one author, clones of a counted pulse are ignored);
    'referenced' (CVE, medium) for the same evidence on a CVE; 'mentioned' (low) otherwise; 'none'
    without pulses."""
    pulses = [p for p in parsed.get("pulses") or [] if isinstance(p, dict)]
    count = int(parsed.get("pulse_count") or len(pulses) or 0)
    families = sorted({p.get("upstream") or "otx" for p in pulses})
    out: dict[str, Any] = {"verdict": "none", "reason": "", "pulse_count": count, "recent_pulses": 0, "authors": [],
                           "labs": [], "upstream_families": families}
    reasons = list(parsed.get("allowlisted") or []) + [r for r in benign_reasons if r]
    if reasons:
        out.update(verdict="noise", reason="allow-listed / benign: " + ", ".join(dict.fromkeys(reasons)))
        return out
    if count == 0:
        out["reason"] = "no OTX pulses"
        return out

    def recent(pulse: dict[str, Any]) -> bool:
        modified = parse_ts(pulse.get("modified"))
        return modified is not None and (now - modified).total_seconds() <= window_days * 86400

    recent_pulses = [p for p in pulses if recent(p)]
    out["recent_pulses"] = len(recent_pulses)
    counted = {p.get("id") for p in recent_pulses if p.get("id")}
    authors: set[str] = set()
    for pulse in recent_pulses:
        if pulse.get("cloned_from") and pulse.get("cloned_from") in counted:
            continue  # a clone of a counted pulse is not a second opinion
        if pulse.get("upstream") == "abuse.ch":
            authors.add("upstream:abuse.ch")
        elif pulse.get("author"):
            authors.add(str(pulse["author"]))
    labs = [p for p in pulses if _is_labs(p)]
    out["authors"] = sorted(authors)
    out["labs"] = [p.get("id") or p.get("name") for p in labs]
    strong = len(authors) >= 2 or bool(labs)
    if strong:
        why = f"labs pulse by {labs[0].get('author')}" if labs else f"{len(recent_pulses)} pulses from {len(authors)} distinct authors in the last {window_days} days"
        out.update(verdict="referenced" if is_cve else "malicious", reason=why)
    else:
        out.update(verdict="mentioned", reason=f"mentioned in {count} community pulse{'s' if count != 1 else ''}")
    return out


def parse_passive_dns(obj: Any, limit: int = 200) -> list[dict[str, Any]] | None:
    """passive_dns -> [{hostname, address, address_type, record_type, first_seen, last_seen, asn}];
    None when the answer has no passive_dns list. 'NXDOMAIN'-style addresses never become IPs."""
    if not isinstance(obj, dict) or not isinstance(obj.get("passive_dns"), list):
        return None
    rows = []
    for raw in obj["passive_dns"][:limit]:
        if not isinstance(raw, dict):
            continue
        address = _text(raw.get("address"), 300)
        kind = "none"
        for etype in (T.IPV4, T.IPV6, T.DOMAIN):
            if address and Entity.try_make(etype, address) is not None:
                kind = etype.value
                break
        rows.append({
            "hostname": _text(raw.get("hostname"), 300).lower(),
            "address": address,
            "address_type": kind,
            "record_type": _text(raw.get("record_type"), 10).upper(),
            "first_seen": _iso(parse_ts(raw.get("first"))),
            "last_seen": _iso(parse_ts(raw.get("last"))),
            "asn": _text(raw.get("asn"), 120),
        })
    return rows


def parse_url_list(obj: Any, limit: int = 200) -> dict[str, Any] | None:
    """url_list -> {urls: [{url, date, http_code, ip}], has_next}; None when there is no url_list."""
    if not isinstance(obj, dict) or not isinstance(obj.get("url_list"), list):
        return None
    urls = []
    for raw in obj["url_list"][:limit]:
        if not isinstance(raw, dict):
            continue
        worker = _dict(_dict(raw.get("result")).get("urlworker"))
        url = _text(raw.get("url"), 2000)
        if url:
            urls.append({"url": url, "date": _iso(parse_ts(raw.get("date"))),
                         "http_code": _int(raw.get("httpcode")) or _int(worker.get("http_code")), "ip": _text(worker.get("ip"), 60)})
    return {"urls": urls, "has_next": raw_bool(obj.get("has_next"))}


def raw_bool(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def parse_malware(obj: Any, limit: int = 100) -> list[dict[str, Any]] | None:
    """malware section -> [{hash, type, date}] (field names unverified without a keyed capture: 'data'
    or 'malware' lists of objects with a 'hash'); None when the answer has neither list."""
    if not isinstance(obj, dict):
        return None
    items = obj.get("data") if isinstance(obj.get("data"), list) else obj.get("malware")
    if not isinstance(items, list):
        return None
    out = []
    for raw in items[:limit]:
        if not isinstance(raw, dict):
            continue
        value = _text(raw.get("hash"), 128).lower()
        etype = {32: T.MD5, 40: T.SHA1, 64: T.SHA256}.get(len(value))
        if etype is None or not _HEX_RE.match(value):
            continue
        out.append({"hash": value, "type": etype.value, "date": _iso(parse_ts(raw.get("datetime_int") or raw.get("date")))})
    return out


def pivots_from(parsed: dict[str, Any], *, include_related: bool = True) -> list[tuple[T, str, str]]:
    """(entity type, canonical name, relation) for adversaries, malware families and ATT&CK ids of the
    pulses (and of the 'related' block), de-duplicated (cond 7)."""
    found: dict[tuple[T, str], tuple[T, str, str]] = {}

    def add(etype: T, relation: str, raw: Any) -> None:
        if etype is T.MITRE:
            name = raw.strip().upper() if isinstance(raw, str) and _TECH_RE.match(raw.strip().upper()) else None
        else:
            name = canonical_name(etype.value, raw)
        if name and (etype, name.lower()) not in found:
            found[(etype, name.lower())] = (etype, name, relation)

    for pulse in parsed.get("pulses") or []:
        if pulse.get("adversary"):
            add(T.THREAT_ACTOR, "attributed_to", pulse["adversary"])
        for fam in pulse.get("malware_families") or []:
            add(T.MALWARE, "family", fam)
        for tid in pulse.get("attack_ids") or []:
            add(T.MITRE, "uses_technique", tid)
    if include_related:
        related = parsed.get("related") or {}
        for name in related.get("adversary") or []:
            add(T.THREAT_ACTOR, "attributed_to", name)
        for name in related.get("malware_families") or []:
            add(T.MALWARE, "family", name)
    return list(found.values())


def json_body(resp: Any) -> tuple[Any, str]:
    """Parse a response body defensively -> (object, '') or (None, reason)."""
    text = resp.text if hasattr(resp, "text") else str(resp or "")
    if not text.strip():
        return None, "empty answer"
    if text.lstrip()[:1] == "<":
        return None, "HTML page instead of JSON"
    try:
        return json.loads(text), ""
    except (ValueError, RecursionError) as exc:
        return None, f"malformed JSON ({str(exc)[:60]})"


def error_in_200(obj: Any) -> str:
    """OTX error bodies ({"detail": "..."} with no indicator data) -> the error text, else ''."""
    if isinstance(obj, dict) and obj.get("detail") and set(obj) <= {"detail", "status", "error"}:
        return _text(obj.get("detail"), 160) or "error"
    return ""


# --------------------------------------------------------------------------------------
# the shared run logic
# --------------------------------------------------------------------------------------


class _Unusable(Exception):
    """An OTX answer the module cannot use: (status, reason_code, text)."""

    def __init__(self, status: Status, code: str, text: str) -> None:
        super().__init__(text)
        self.status = status
        self.code = code
        self.text = text


class _OtxBase(Module):
    """Shared behaviour of otx and otx_keyless (not registered itself: it has no name)."""

    keyless_mode = False

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type in (T.IPV4, T.IPV6):
            return noise.is_public_ip(entity.value)  # private/reserved addresses are never sent
        if entity.type is T.URL:
            return entity.value.lower().startswith(("http://", "https://"))
        return category(entity) is not None

    # ---- one request -------------------------------------------------------------------
    def _get(self, ctx: Any, url: str, key: str) -> Any:
        if not request_allowed("GET", url):  # cond 2: never anything but the read-only sections
            raise _Unusable(Status.ERROR, "error", "refused a non-allow-listed OTX request (module bug)")
        preset = str(getattr(ctx.options, "preset", "quick") or "quick")
        resp = ctx.http.get(
            url,
            headers={KEY_HEADER: key} if key else None,
            timeout=call_timeout(preset, ctx.remaining()),
            max_bytes=MAX_BYTES,
            source=SOURCE,
            retries=0,  # OTX is slow: one try per call, within the 20/60 s bound (cond 4)
        )
        if resp.status == 400:
            obj, _why = json_body(resp)
            detail = error_in_200(obj) or "invalid indicator"
            raise _Unusable(Status.SKIPPED, "not_applicable", f"OTX rejected the indicator value (400 {detail})")
        ctx.http.check(resp)  # P321 classification, 401/403 AuthRequired, 429 RateLimited, other non-2xx
        if resp.truncated:
            raise _Unusable(Status.ERROR, "error", f"OTX answer larger than {MAX_BYTES // 1_000_000} MB was truncated: not parsed (could not verify)")
        obj, why = json_body(resp)
        if why:
            raise _Unusable(Status.ERROR, "error", f"unexpected OTX answer ({why}): could not verify")
        err = error_in_200(obj)
        if err:
            raise _Unusable(Status.ERROR, "error", f"OTX error inside an HTTP 200 answer ({err}): could not verify")
        if not isinstance(obj, dict):
            raise _Unusable(Status.ERROR, "error", f"unexpected OTX answer ({type(obj).__name__}, not a JSON object): could not verify")
        return obj

    # ---- run ---------------------------------------------------------------------------------
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = "" if self.keyless_mode else ctx.key(KEY_NAME)
        if not self.keyless_mode and not key:
            return res.mark(Status.NEEDS_KEY, "needs the OTX API key (free account): v3lum keys setup", reason_code="needs_key")
        url = indicator_url(entity, "general")
        if url is None:
            return res.mark(Status.SKIPPED, "not an OTX indicator type", reason_code="not_applicable")
        link = report_link(entity)
        try:
            obj = self._get(ctx, url, key)
        except _Unusable as exc:
            if link:
                res.link("OTX indicator page", link)
            return res.mark(exc.status, exc.text, reason_code=exc.code)
        parsed = parse_general(obj)
        if parsed is None:  # pragma: no cover - _get guarantees a dict
            return res.mark(Status.ERROR, "unexpected OTX answer: could not verify", reason_code="error")
        res.raw = {"general": _evidence(parsed)}
        benign = benign_reasons(entity)
        result = verdict(parsed, ctx.now(), is_cve=entity.type is T.CVE, benign_reasons=benign)
        self._record_general(res, entity, parsed, result)
        preset = str(getattr(ctx.options, "preset", "quick") or "quick")
        # allow-listed / benign indicators are not worth their URL lists (8.8.8.8 lists thousands)
        listed = 0 if result["verdict"] == "noise" else parsed["pulse_count"]
        sections = plan_sections(entity, listed, is_seed=bool(ctx.is_seed), preset=preset,
                                 keyless=self.keyless_mode, available=parsed.get("sections"))
        notes: list[str] = []
        extra = False
        for section in sections[1:]:
            try:
                if section == "passive_dns":
                    extra |= self._passive_dns(res, entity, ctx, key)
                elif section == "url_list":
                    extra |= self._url_list(res, entity, ctx, key)
                elif section == "malware":
                    extra |= self._malware(res, entity, ctx, key)
            except _Unusable as exc:
                notes.append(f"{section}: {exc.text}")
            except (RateLimited, QuotaExceeded, Blocked, AuthRequired):
                raise  # engine semantics: rate limit/quota keep the partial result, block/bad key = could not verify
            except (HttpError, NetworkError) as exc:  # one section failed: the general verdict stands
                notes.append(f"{section}: could not verify ({str(exc)[:120]})")
        if notes:
            res.error = "; ".join(notes)
        if link:
            res.link("OTX indicator page", link)
        if result["verdict"] == "none" and not extra:
            return res.mark(Status.EMPTY)  # no pulse lists it: nothing found (ASN/country stay as context)
        return res

    # ---- general ------------------------------------------------------------------------------
    def _record_general(self, res: ModuleResult, entity: Entity, parsed: dict[str, Any], result: dict[str, Any]) -> None:
        pulses = parsed["pulses"]
        top = [{"name": p.get("name"), "author": p.get("author"), "date": (p.get("modified") or "")[:10], "link": p.get("link")} for p in pulses[:3]]
        res.attr("otx_pulse_count", parsed["pulse_count"])
        res.attr("otx_pulses", top)
        res.attr("allowlisted", list(parsed.get("allowlisted") or []) or None)
        asn = re.match(r"^(AS\d+)\b", parsed.get("asn") or "", re.I)
        if asn and entity.type in (T.IPV4, T.IPV6):
            res.attr("asn", asn.group(1).upper())
        if re.fullmatch(r"[A-Z]{2}", parsed.get("country") or "") and entity.type in (T.IPV4, T.IPV6):
            res.attr("country", parsed["country"])
        created = [parse_ts(p.get("created") or p.get("modified")) for p in pulses]
        modified = [parse_ts(p.get("modified")) for p in pulses]
        first = min((c for c in created if c), default=None)
        last = max((m for m in modified if m), default=None)
        if result["verdict"] not in ("none", "noise"):
            res.attr("first_seen", _iso(first))
            res.attr("last_seen", _iso(last))
            res.attr("upstream_families", result["upstream_families"])
        cve = parsed.get("cve")
        if cve and entity.type is T.CVE:
            res.attr("cvss", cve.get("cvss"))
            res.attr("cvss_vector", cve.get("vector"))
            res.attr("epss", cve.get("epss"))
            res.attr("cwe", cve.get("cwe"))
            if cve.get("seen_wild") is not None:
                res.attr("exploited_in_wild", bool(cve["seen_wild"]))
        description = f"{parsed['pulse_count']} OTX pulse(s)" + (" (capped at the 50 newest)" if parsed.get("pulses_capped") else "")
        if top:
            description += "; newest: " + "; ".join(f"'{t['name']}' by {t['author'] or '?'} ({t['date'] or '?'})" for t in top)
        data = {"pulse_count": parsed["pulse_count"], "top_pulses": top, "verdict": result["verdict"], "reason": result["reason"],
                "distinct_recent_authors": len(result["authors"]), "labs_pulses": len(result["labs"]),
                "upstream_families": result["upstream_families"]}
        references = [t["link"] for t in top if t.get("link")]
        if result["verdict"] == "noise":
            res.attr("reputation", {"otx": "allow-listed"})
            res.finding(
                "OTX lists the indicator as allow-listed / known benign",
                "info",
                result["reason"] + (f"; {description}" if parsed["pulse_count"] else ""),
                confidence="probable",
                data=data,
                tags=["known_good", "info"],
                source=SOURCE,
            )
            return
        if result["verdict"] == "none":
            return
        labels = pivots_from(parsed)
        families = [n for (t, n, _r) in labels if t is T.MALWARE]
        actors = [n for (t, n, _r) in labels if t is T.THREAT_ACTOR]
        techniques = [n for (t, n, _r) in labels if t is T.MITRE]
        res.attr("malware_family", families[:10])
        res.attr("threat_actors", actors[:10])
        res.attr("attack_techniques", techniques[:20])
        if result["verdict"] == "malicious":
            res.attr("malicious", True)
            res.attr("reputation", {"otx": "malicious"})
            res.finding(
                "OTX pulses flag the indicator as malicious",
                "high",
                description,
                confidence="probable",
                criterion=f"OTX: {result['reason']} (pulse membership alone is not a verdict)",
                data=data,
                tags=["malicious"],
                references=references,
                source=SOURCE,
                observed_first=first,
                observed_last=last,
            )
        elif result["verdict"] == "referenced":
            res.finding(
                "CVE referenced in OTX threat pulses",
                "medium",
                description,
                confidence="probable",
                criterion=f"OTX: CVE referenced by {result['reason']}",
                data=data,
                references=references,
                source=SOURCE,
                observed_first=first,
                observed_last=last,
            )
        else:
            res.attr("reputation", {"otx": "mentioned"})
            res.finding(
                "Mentioned in OTX community pulses",
                "low",
                description,
                confidence="possible",
                criterion=f"OTX: {result['reason']} without the corroboration needed for a malicious verdict "
                          f"(>= 2 distinct authors within {RECENT_DAYS} days or a labs pulse)",
                data=data,
                tags=["weak_signal"],
                references=references,
                source=SOURCE,
                observed_first=first,
                observed_last=last,
            )
        for etype, name, relation in labels[:40]:
            res.pivot(etype, name, relation, confidence="possible", expand=False,
                      note="community OTX pulse label (low confidence)")

    # ---- keyed sections -------------------------------------------------------------------
    def _passive_dns(self, res: ModuleResult, entity: Entity, ctx: Any, key: str) -> bool:
        url = indicator_url(entity, "passive_dns")
        if url is None:
            return False
        rows = parse_passive_dns(self._get(ctx, url, key))
        if rows is None:
            raise _Unusable(Status.ERROR, "error", "unexpected passive_dns answer (no passive_dns list): could not verify")
        rows.sort(key=lambda r: r.get("last_seen") or "", reverse=True)
        res.attr("passive_dns", [{k: r[k] for k in ("hostname", "address", "record_type", "first_seen", "last_seen")} for r in rows[:50]])
        added = 0
        for row in rows:
            if added >= 25:
                break
            if entity.type is T.DOMAIN:
                if row["record_type"] in ("A", "AAAA") and row["address_type"] in ("ipv4", "ipv6"):
                    etype = T.IPV4 if row["address_type"] == "ipv4" else T.IPV6
                    if noise.is_public_ip(row["address"]) and res.pivot(etype, row["address"], "resolves_to", confidence="possible", expand=False,
                                                                       note=f"OTX passive DNS {row['first_seen'] or '?'} - {row['last_seen'] or '?'} (historical)"):
                        added += 1
                elif row["record_type"] == "CNAME" and row["address_type"] == "domain" and res.pivot(
                        T.DOMAIN, row["address"], "cname_to", confidence="possible", expand=False, note="OTX passive DNS CNAME (historical)"):
                    added += 1
            elif row["hostname"] and res.pivot(T.DOMAIN, row["hostname"], "hosted_domain", confidence="possible", expand=False,
                                               note=f"OTX passive DNS {row['first_seen'] or '?'} - {row['last_seen'] or '?'} (historical)"):
                added += 1
        return bool(rows)

    def _url_list(self, res: ModuleResult, entity: Entity, ctx: Any, key: str) -> bool:
        urls: list[dict[str, Any]] = []
        for page in range(1, URL_LIST_MAX_PAGES + 1):
            url = indicator_url(entity, "url_list", page=page)
            if url is None:
                return False
            parsed = parse_url_list(self._get(ctx, url, key))
            if parsed is None:
                raise _Unusable(Status.ERROR, "error", "unexpected url_list answer (no url_list): could not verify")
            urls += parsed["urls"]
            if not parsed["has_next"] or not parsed["urls"]:
                break
        seen: set[str] = set()
        unique = [u for u in urls if not (u["url"] in seen or seen.add(u["url"]))]
        res.attr("observed_urls", [{"url": u["url"], "date": u["date"], "http_code": u["http_code"]} for u in unique[:50]])
        added = 0
        for item in unique:
            if added >= 25:
                break
            if entity.type is T.URL:
                continue  # the url_list of a URL lists the URL itself
            if res.pivot(T.URL, item["url"], "hosts_url", confidence="possible", expand=False, note=f"OTX URL list ({item['date'] or 'undated'})"):
                added += 1
        return bool(unique)

    def _malware(self, res: ModuleResult, entity: Entity, ctx: Any, key: str) -> bool:
        url = indicator_url(entity, "malware")
        if url is None:
            return False
        samples = parse_malware(self._get(ctx, url, key))
        if samples is None:
            raise _Unusable(Status.ERROR, "error", "unexpected malware answer (no sample list): could not verify")
        res.attr("malware_samples", samples[:50])
        for sample in samples[:20]:
            res.pivot(T.parse(sample["type"]), sample["hash"], "contacted_by", confidence="possible", expand=False,
                      note="OTX malware section: sample associated with the indicator")
        return bool(samples)


def benign_reasons(entity: Entity) -> list[str]:
    """P169 warninglists and benign shared infrastructure (resolvers, CDN/cloud edges, sinkholes) of the
    indicator itself: cond 5 turns them into an info verdict, never a malicious one."""
    reasons: list[str] = []
    try:
        reasons += [f"warninglist {name}" for name in noise.warninglists(entity)]
        kind = noise.noise_kind(entity)
    except Exception:  # noqa: BLE001 - a broken list never changes a verdict by itself
        kind = None
    if kind and kind not in ("private",):
        reasons.append(f"benign infrastructure ({kind})")
    return reasons


#: OTX pulse-indicator types -> V3LUM entity types (cond 7). Pulse indicator lists come only from
#: /api/v1/pulses/{id}/indicators, which cond 2 does not allow: no current request returns them.
_PULSE_INDICATOR_TYPES = {"ipv4": T.IPV4, "ipv6": T.IPV6, "domain": T.DOMAIN, "hostname": T.DOMAIN, "url": T.URL,
                          "filehash-md5": T.MD5, "filehash-sha1": T.SHA1, "filehash-sha256": T.SHA256, "cve": T.CVE,
                          "email": T.EMAIL, "username": T.USERNAME}


def pulse_indicator_pivot(otx_type: Any, value: Any) -> tuple[T, str, bool] | None:
    """(entity type, value, expand) for a pulse indicator: e-mail and username indicators from community
    pulses are always expand=False (cond 7, A8: personal identifiers wait for the analyst)."""
    etype = _PULSE_INDICATOR_TYPES.get(_text(otx_type, 40).lower())
    text = _text(value, 2000)
    if etype is None or not text:
        return None
    return etype, text, etype not in (T.EMAIL, T.USERNAME)


def _evidence(parsed: dict[str, Any]) -> dict[str, Any]:
    """Compact evidence of the general answer (pulse names, authors and dates; no indicator lists)."""
    return {
        "pulse_count": parsed["pulse_count"],
        "pulses": [{k: p.get(k) for k in ("id", "name", "author", "created", "modified", "adversary", "malware_families", "attack_ids", "upstream", "cloned_from")}
                   for p in parsed["pulses"][:MAX_PULSES]],
        "allowlisted": parsed.get("allowlisted"),
        "asn": parsed.get("asn"),
        "country": parsed.get("country"),
        "cve": parsed.get("cve"),
    }


_COMMON = dict(
    category="threat_intel_ioc",
    accepts={T.IPV4, T.IPV6, T.DOMAIN, T.URL, T.MD5, T.SHA1, T.SHA256, T.CVE},
    produces={T.DOMAIN, T.IPV4, T.IPV6, T.URL, T.MD5, T.SHA256, T.MALWARE, T.THREAT_ACTOR, T.MITRE},
)


@register
class Otx(_OtxBase):
    name = "otx"
    title = "AlienVault OTX indicators"
    description = (
        "AlienVault/LevelBlue OTX indicator API with the OTX key: pulse count and verdict (general), passive DNS for "
        "typed seeds, URL list and malware samples for indicators listed in pulses."
    )
    category = _COMMON["category"]
    accepts = _COMMON["accepts"]
    produces = _COMMON["produces"]
    tags = {"reputation", "free"}
    reference = "https://otx.alienvault.com/api"
    notice = (
        "OTX terms are 'key-terms' (the terms page is JS-only and was not verified on 2026-11-26): under the corporate "
        "profile OTX runs only once legal records a business-compatible plan (key_plans.otx='business'). Community "
        "pulses are not verdicts; nothing is ever submitted to OTX."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "otx"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,)
    max_requests = 6  # general + passive_dns + url_list (<= 3 pages) + malware
    expected_latency = 2.0
    timeout = 120.0
    min_interval = 1.0
    daily_quota = 5000
    cache_ttl = 86400
    max_pivots = 80
    manual_link = "threat_intel_g07:otx_search"
    default_enabled = True


@register
class OtxKeyless(_OtxBase):
    name = "otx_keyless"
    title = "AlienVault OTX indicators (keyless, general only)"
    description = (
        "AlienVault/LevelBlue OTX 'general' section without a key: pulse count and verdict only. Opt-in: keyless "
        "calls are slow (about 25 s) and throttled on shared egress."
    )
    category = _COMMON["category"]
    accepts = _COMMON["accepts"]
    produces = _COMMON["produces"]
    tags = {"reputation", "free", "slow"}
    reference = "https://otx.alienvault.com/api"
    notice = (
        "Keyless OTX is opt-in (-M otx_keyless or --preset deep): about 25 s per call and HTTP 429 on shared egress. "
        "Terms 'key-terms' as for otx (corporate profile: legal must record a business-compatible plan)."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "otx"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_noauth_limited"
    max_requests = 1
    expected_latency = 25.0
    timeout = 90.0
    min_interval = 2.0
    daily_quota = 500
    cache_ttl = 86400
    max_pivots = 50
    manual_link = "threat_intel_g07:otx_search"
    default_enabled = False
    keyless_mode = True


#: names a test can check (cond 1: one parser shared by both classes)
SHARED_PARSER: tuple[Callable[..., Any], ...] = (parse_general, verdict, pivots_from)
