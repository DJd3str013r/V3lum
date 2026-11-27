"""honeypot_intel: honeypot sightings of an IP, CVE or AS (OffSeq Mirage datasets + HoneyDB) (P147).

Batch p2-G02-2, proposal P147. Final conditions implemented here (the HoneyLabs and James Brine
feeds are the separate opt-in module ``honeypot_intel_extra``, c3):

* c1 - OffSeq Mirage daily files (CC BY 4.0, TLP:CLEAR: 'open') are registered datasets refreshed
  every 6 h with the dataset manager's conditional GET (If-Modified-Since / ETag). The attackers CSV
  is parsed with the csv module under a field-size limit (every physical line is capped at
  :data:`FIELD_SIZE_LIMIT` before parsing; the process-global ``csv.field_size_limit`` is never
  changed because other modules parse CSV concurrently) into a compact local index (tags, services,
  CVEs, KEV, ATT&CK, confidence, first/last seen) memoised per dataset SHA-256. HoneyDB (key-terms,
  company key) is a separate adapter with its own per-source status.
* c2 - OffSeq's known-scanners list is the noise-provider hook :func:`noise_kind_for` (local copy
  only, like ``cloud_ranges.noise_kind_for``) and its IPs get findings tagged ``benign_scanner``,
  never malicious, plus the attribute ``scanner_classification: 'benign'`` that the P171 pack
  (CR27) reads to downgrade a consensus (SUP-benign_scanner). The import-time ``noise.register_list`` registration waits for a core change
  (a runtime list reports 'not downloaded' in ``noise.errors()``, which the contract test forbids).
* c5 - HoneyDB: two registered keys (``honeydb_api_id``, ``honeydb_api_key``) sent in the
  ``X-HoneyDb-ApiId`` / ``X-HoneyDb-ApiKey`` headers; the client follows the current API
  documentation (``GET /api/ip/{ip}``; the old /api/netinfo/lookup answers 410). 401 'Invalid API
  Credentials' gives NEEDS_KEY; its relayed third-party lists are display only, never a vote.
* c6 - sightings mean opportunistic scanning/exploitation: tag ``scanner``, at most MEDIUM alone,
  observed first/last seen on every finding and a 30-day decay (:func:`decay_weight`); IP -> CVE
  uses the relation ``attempted_exploit`` (vocabulary fragment), never ``has_vuln``.
* c7 - UDP-derived observations are excluded from verdicts (spoofable): OffSeq lists only sources
  that completed a TCP handshake; HoneyDB UDP-only (or possibly-UDP) services are context only.
* c8 - pivots: the AS, each CVE (``attempted_exploit``, joined with KEV/EPSS by their modules) and
  each ATT&CK technique (``observed_technique``); CC BY 4.0 attribution to OffSeq on every finding,
  in the dataset registration (report attributions) and in ``v3lum/data/notices/offseq_mirage.json``.

CVE and AS entities are answered from the local OffSeq index (exploitation attempts of the last
7 days; attackers of the AS): local data only, nothing is sent.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from v3lum.core import attack as _attack
from v3lum.core import http as _http
from v3lum.core import noise
from v3lum.core.datasets import DatasetError, DataStore, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status, status_for
from v3lum.core.module import Module, register

SRC_ATTACKERS = "offseq.mirage_attackers"
SRC_SCANNERS = "offseq.mirage_known_scanners"
SRC_ANONYMIZERS = "offseq.mirage_anonymizers"
SRC_HONEYDB = "honeydb.api"
OFFSEQ_ATTRIBUTION = "Mirage Feed by OffSeq Mirage (https://github.com/offseq/mirage-feed), CC BY 4.0"
OFFSEQ_REFERENCE = "https://github.com/offseq/mirage-feed"
OFFSEQ_BASE = "https://feeds.offseq.com/mirage-feed/latest/"
HONEYDB_API = "https://honeydb.io/api/ip/{ip}"
IP_CVE_RELATION = "attempted_exploit"  # c6: never has_vuln
IP_TECHNIQUE_RELATION = "observed_technique"
DECAY_DAYS = 30  # c6
FIELD_SIZE_LIMIT = 64 * 1024  # c1: longest accepted physical CSV line (a field can never be longer)
MAX_ROWS = 500_000
MAX_CVE_PIVOTS = 25
MAX_TECHNIQUE_PIVOTS = 25
OFFSEQ_COLUMNS = ("ip", "asn", "as_org", "country", "first_seen", "last_seen", "services", "tags", "cves", "kev", "attack",
                  "sensors", "networks", "hits", "confidence")
RECON_TECHNIQUES = frozenset({"T1046", "T1589", "T1590", "T1592", "T1595"})
SHARED_TAGS = frozenset({"vpn-bruteforce", "web-exploit", "web-scan"})
SHARED_TECHNIQUES = frozenset({"T1110", "T1190", "T1595"})
#: c7: services seen only over UDP (spoofable sources) and services that may run over UDP.
UDP_ONLY_SERVICES = frozenset({
    "ntp", "snmp", "tftp", "ssdp", "upnp", "mdns", "llmnr", "netbios-ns", "nbns", "coap", "ws-discovery", "wsd", "cldap",
    "rip", "ike", "isakmp", "ipmi", "stun", "quic", "radius", "l2tp", "bacnet", "wireguard",
})
MAYBE_UDP_SERVICES = frozenset({"sip", "dns", "memcached", "syslog", "chargen", "echo", "qotd", "openvpn", "kerberos", "netbios"})
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
_TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


# --------------------------------------------------------------------------------------
# shared honeypot semantics (also used by honeypot_intel_extra)
# --------------------------------------------------------------------------------------


def parse_ts(value: Any) -> datetime | None:
    """'2026-11-25T19:00:00Z', '2026-11-25 19:23:06.056000' (no zone: UTC) or '2026-11-24' -> aware UTC."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        text += "T00:00:00+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if isinstance(dt, datetime) else None


def decay_weight(last_seen: Any, now: datetime, window_days: int = DECAY_DAYS) -> float:
    """Linear 30-day decay from the observed last sighting (c6): 1.0 fresh, 0.0 = history only."""
    seen = last_seen if isinstance(last_seen, datetime) else parse_ts(last_seen)
    if seen is None:
        return 1.0  # no date published: the listing itself is current (the feeds expire entries)
    age = (now - seen).total_seconds() / 86400.0
    if age <= 0:
        return 1.0
    return round(max(0.0, 1.0 - age / float(window_days)), 3)


def observation_transport(services: Any, verified: str = "") -> str:
    """'tcp' | 'udp_only' | 'possibly_udp' | 'unknown' for one observation (c7). ``verified=
    'tcp_handshake'`` (OffSeq lists only sources that completed a TCP handshake) wins."""
    if verified == "tcp_handshake":
        return "tcp"
    names = {str(s).strip().lower() for s in (services or []) if str(s).strip()}
    if not names:
        return "unknown"
    if names - UDP_ONLY_SERVICES - MAYBE_UDP_SERVICES:
        return "tcp"
    if names <= UDP_ONLY_SERVICES:
        return "udp_only"
    return "possibly_udp"


def counts_for_verdict(transport: str) -> bool:
    """UDP-derived observations never feed verdicts (c7); 'unknown' (no service list) counts."""
    return transport in ("tcp", "unknown")


@dataclass
class Verdict:
    """Severity and tags of one honeypot sighting (c2, c6, c7; CR28 for anonymizer exits)."""

    severity: str = "low"
    tags: list[str] = field(default_factory=lambda: ["scanner"])
    counts: bool = True
    decay: float = 1.0
    why: str = ""


def honeypot_verdict(*, now: datetime, benign_scanner: bool = False, anonymizer: str = "", shared: bool = False,
                     recon_only: bool = False, transport: str = "tcp", cves: Any = (), kev: bool = False,
                     confidence: int | None = None, last_seen: Any = None) -> Verdict:
    """Tag 'scanner', at most MEDIUM alone, never 'malicious'. Known research scanners: INFO
    'benign_scanner'. UDP-derived or older than 30 days: INFO context. Anonymizer exits, shared
    addresses and reconnaissance only: LOW. CVE/KEV exploit attempts or confidence >= 70: MEDIUM."""
    weight = decay_weight(last_seen, now)
    if benign_scanner:
        return Verdict("info", ["benign_scanner"], False, weight, "known research scanner: noise, never malicious")
    if not counts_for_verdict(transport):
        return Verdict("info", ["scanner", "context_only"], False, weight, "UDP-derived sighting (spoofable source): context only")
    if weight <= 0.0:
        return Verdict("info", ["scanner", "context_only"], False, weight, f"last seen more than {DECAY_DAYS} days ago: history only")
    if anonymizer:
        extra = [anonymizer] if anonymizer in ("tor", "vpn") else []
        label = anonymizer if anonymizer in ("tor", "vpn") else "VPN/Tor"
        return Verdict("low", ["scanner", "anonymizer", *extra], True, weight, f"{label} exit: shared by many users (CR28 context)")
    if shared or recon_only:
        return Verdict("low", ["scanner"], True, weight, "shared address (CGNAT/VPN login botnet)" if shared else "reconnaissance only")
    if cves or kev or (isinstance(confidence, int) and confidence >= 70):
        return Verdict("medium", ["scanner"], True, weight, "exploit attempts" if (cves or kev) else "high honeypot confidence")
    return Verdict("low", ["scanner"], True, weight, "opportunistic scanning/brute force")


def norm_ip(value: Any) -> str | None:
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def dataset_failure(exc: BaseException) -> tuple[Status, str]:
    """Status and canonical code of a dataset that could not be used (rule 5: could not verify)."""
    if isinstance(exc, DatasetUnavailable):
        return Status.UNAVAILABLE, "dataset"
    code = str(getattr(exc, "reason_code", "") or "error")
    try:
        status = status_for(code)
    except ValueError:
        return Status.ERROR, "error"
    if status in (Status.OK, Status.EMPTY, Status.SKIPPED):
        return Status.ERROR, "error"
    return status, code


def valid_techniques(ids: Any) -> list[str]:
    """ATT&CK ids known to the bundled index (strict mode refuses unknown ids on findings); the
    pivots keep every well-formed id."""
    out: list[str] = []
    for tid in ids or ():
        try:
            if _attack.is_valid(tid):
                canon = _attack.canonical(tid)
                if canon not in out:
                    out.append(canon)
        except (ValueError, TypeError, KeyError):
            continue
    return out


def text_lines(raw: str, limit: int = FIELD_SIZE_LIMIT) -> tuple[list[str], int]:
    """Physical lines of a text, dropping those longer than ``limit`` (c1 field-size limit)."""
    kept: list[str] = []
    dropped = 0
    for line in raw.splitlines():
        if len(line) > limit:
            dropped += 1
            continue
        kept.append(line)
    return kept, dropped


def looks_like_html(text: str) -> bool:
    head = text[:1024].lstrip().lower()
    return head.startswith(("<!doctype html", "<html")) or "<head" in head[:512] or "<body" in head[:512]


def parse_ip_list(text: str) -> tuple[frozenset[str], int]:
    """One value per line (OffSeq lists, James Brine iplist.txt): (IPs, invalid line count)."""
    ips: set[str] = set()
    invalid = 0
    lines, dropped = text_lines(text)
    for line in lines:
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        ip = norm_ip(value)
        if ip is None:
            invalid += 1
        else:
            ips.add(ip)
    return frozenset(ips), invalid + dropped


# --------------------------------------------------------------------------------------
# OffSeq Mirage (c1, c2)
# --------------------------------------------------------------------------------------


def _split(value: str) -> list[str]:
    return [p.strip() for p in value.split(";") if p.strip()]


def offseq_row(row: list[str]) -> dict[str, Any] | None:
    """One attackers-7d.csv row -> a compact record (None for a malformed row)."""
    if len(row) != len(OFFSEQ_COLUMNS):
        return None
    r = dict(zip(OFFSEQ_COLUMNS, (c.strip() for c in row)))
    nums: dict[str, int] = {}
    for key in ("asn", "sensors", "networks", "hits", "confidence"):
        if not r[key].isdigit() or len(r[key]) > 10:
            return None
        nums[key] = int(r[key])
    value = r["ip"]
    if "/" in value:
        try:
            value = str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            return None
    else:
        value = norm_ip(value) or ""
        if not value:
            return None
    first, last = parse_ts(r["first_seen"]), parse_ts(r["last_seen"])
    if first is None or last is None:
        return None
    tags = _split(r["tags"])
    attack = [t for t in _split(r["attack"]) if _TECH_RE.match(t)]
    cves = sorted({c.upper() for c in _split(r["cves"]) if _CVE_RE.match(c)})
    tagset = set(tags)
    anonymizer = "tor" if "tor-exit" in tagset else ("vpn" if "vpn-exit" in tagset else "")
    shared = "cgnat" in tagset or ("vpn-bruteforce" in tagset and tagset <= SHARED_TAGS and set(attack) <= SHARED_TECHNIQUES and not cves)
    return {
        "ip": value, "asn": nums["asn"], "as_org": r["as_org"][:120], "country": r["country"][:2].upper(),
        "first_seen": iso(first), "last_seen": iso(last), "services": [s.lower() for s in _split(r["services"])][:20],
        "tags": tags[:20], "cves": cves[:50], "kev": r["kev"].lower() == "true", "attack": attack[:40],
        "sensors": nums["sensors"], "networks": nums["networks"], "hits": nums["hits"], "confidence": min(nums["confidence"], 100),
        "anonymizer": anonymizer, "shared": shared,
        "recon_only": bool(attack) and set(attack) <= RECON_TECHNIQUES and not cves, "transport": "tcp_handshake",
    }


@dataclass
class OffseqIndex:
    """Compact local index of attackers-7d.csv (c1)."""

    records: dict[str, dict[str, Any]] = field(default_factory=dict)
    networks: list[tuple[Any, dict[str, Any]]] = field(default_factory=list)
    by_cve: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    by_asn: dict[int, list[dict[str, Any]]] = field(default_factory=dict)
    rows: int = 0
    skipped: int = 0

    def lookup(self, ip: str) -> dict[str, Any] | None:
        rec = self.records.get(ip)
        if rec is not None:
            return rec
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        return next((r for net, r in self.networks if net.version == addr.version and addr in net), None)


def parse_offseq_attackers(text: str) -> OffseqIndex:
    """attackers-7d.csv -> :class:`OffseqIndex`. Raises ValueError for an HTML page or a wrong header;
    malformed rows are skipped and counted (a truncated download keeps its complete rows)."""
    if looks_like_html(text):
        raise ValueError("HTML page instead of the OffSeq attackers CSV")
    lines, dropped = text_lines(text.lstrip("﻿"))
    reader = csv.reader(io.StringIO("\n".join(lines)))
    try:
        header = [h.strip().lower() for h in next(reader)]
    except (StopIteration, csv.Error) as exc:
        raise ValueError("empty OffSeq attackers CSV") from exc
    if tuple(header) != OFFSEQ_COLUMNS:
        raise ValueError("unexpected OffSeq attackers CSV header")
    index = OffseqIndex(skipped=dropped)
    while index.rows + index.skipped < MAX_ROWS:
        try:
            row = next(reader)
        except StopIteration:
            break
        except csv.Error:
            index.skipped += 1
            continue
        if not row:
            continue
        rec = offseq_row(row)
        if rec is None:
            index.skipped += 1
            continue
        index.rows += 1
        if "/" in rec["ip"]:
            index.networks.append((ipaddress.ip_network(rec["ip"]), rec))
        else:
            index.records[rec["ip"]] = rec
        for cve in rec["cves"]:
            index.by_cve.setdefault(cve, []).append(rec)
        if rec["asn"]:
            index.by_asn.setdefault(rec["asn"], []).append(rec)
    return index


def _validate_attackers(path: Path) -> bool:
    index = parse_offseq_attackers(path.read_text(encoding="utf-8", errors="replace"))
    if index.rows and index.skipped > max(10, index.rows // 10):
        raise ValueError(f"{index.skipped} malformed rows out of {index.rows + index.skipped}")
    return True


def _validate_ip_list(path: Path) -> bool:
    text = path.read_text(encoding="utf-8", errors="replace")
    if looks_like_html(text):
        raise ValueError("HTML page instead of an IP list")
    ips, invalid = parse_ip_list(text)
    if not ips:
        raise ValueError("no IP address in the list")
    if invalid > max(5, len(ips) // 20):
        raise ValueError(f"{invalid} lines are not IP addresses")
    return True


ATTACKERS = register_dataset(
    "honeypot_intel.offseq_attackers_7d.csv",
    OFFSEQ_BASE + "attackers-7d.csv",
    ttl=21600,
    description="OffSeq Mirage attackers of the last 7 days (per IP: services, tags, CVEs, KEV, ATT&CK, sensors, hits, confidence, first/last seen)",
    licence="CC-BY-4.0",
    terms_class="open",
    attribution=OFFSEQ_ATTRIBUTION,
    provider="offseq",
    source=SRC_ATTACKERS,
    validate=_validate_attackers,
    min_bytes=100,
    expect="csv",
    max_bytes=4 * 1024 * 1024,
    large=False,
    essential=True,
)
KNOWN_SCANNERS = register_dataset(
    "honeypot_intel.offseq_known_scanners_ipv4.txt",
    OFFSEQ_BASE + "known-scanners-ipv4.txt",
    ttl=21600,
    description="OffSeq Mirage known research scanners (IPv4): benign scanners, never malicious (noise kind benign_scanner)",
    licence="CC-BY-4.0",
    terms_class="open",
    attribution=OFFSEQ_ATTRIBUTION,
    provider="offseq",
    source=SRC_SCANNERS,
    validate=_validate_ip_list,
    min_bytes=7,
    expect="lines",
    max_bytes=2 * 1024 * 1024,
    large=False,
    essential=True,
)
ANONYMIZERS = register_dataset(
    "honeypot_intel.offseq_anonymizers_7d.txt",
    OFFSEQ_BASE + "anonymizers-7d.txt",
    ttl=21600,
    description="OffSeq Mirage Tor/VPN exits seen attacking in the last 7 days (anonymizer context, CR28)",
    licence="CC-BY-4.0",
    terms_class="open",
    attribution=OFFSEQ_ATTRIBUTION,
    provider="offseq",
    source=SRC_ANONYMIZERS,
    validate=_validate_ip_list,
    min_bytes=7,
    expect="lines",
    max_bytes=1024 * 1024,
    large=False,
    essential=True,
)
_MEMO_LOCK = threading.Lock()
_MEMO: dict[str, tuple[str, Any]] = {}
_HOOK_MEMO: dict[str, Any] = {"key": None, "ips": frozenset()}


def noise_kind_for(value: Any) -> str | None:
    """The AR06 noise-provider hook of P147 c2: ``'benign_scanner'`` when the address is on the local
    copy of OffSeq's known-scanners list, else None. Local copy only: never a download, never a
    network call (the same contract as ``cloud_ranges.noise_kind_for``).

    Not registered with ``noise.register_list`` at import time: the registry contract test requires
    ``noise.errors() == []`` and a runtime list reports 'not downloaded' there in every fresh home
    (core request recorded in docs/backlog/p2-G02-2.md). The module's own findings carry the tag
    ``benign_scanner`` meanwhile."""
    ip = norm_ip(value)
    if ip is None:
        return None
    try:
        path = Path(DataStore(None).scoped().fetch(KNOWN_SCANNERS))  # no runtime bound: local copy only
        stat = path.stat()
    except (DatasetError, OSError, ValueError):
        return None
    key = (str(path), stat.st_mtime_ns, stat.st_size)
    with _MEMO_LOCK:
        if _HOOK_MEMO["key"] != key:
            _HOOK_MEMO.update(key=key, ips=parse_ip_list(path.read_text(encoding="utf-8", errors="replace"))[0])
        return "benign_scanner" if ip in _HOOK_MEMO["ips"] else None


def memo(name: str, sha256: str, build: Any) -> Any:
    """Parse a dataset once per content version (the dataset SHA-256)."""
    with _MEMO_LOCK:
        hit = _MEMO.get(name)
        if hit is not None and hit[0] == sha256 and sha256:
            return hit[1]
    value = build()
    with _MEMO_LOCK:
        _MEMO[name] = (sha256, value)
    return value


def load_attackers(ctx: Any) -> tuple[OffseqIndex, Any]:
    path = Path(ctx.data.fetch(ATTACKERS))
    info = ctx.data.info(ATTACKERS)
    return memo(ATTACKERS, str(info.sha256 or ""), lambda: parse_offseq_attackers(path.read_text(encoding="utf-8", errors="replace"))), info


def load_ip_set(ctx: Any, name: str) -> frozenset[str]:
    path = Path(ctx.data.fetch(name))
    info = ctx.data.info(name)
    return memo(name, str(info.sha256 or ""), lambda: parse_ip_list(path.read_text(encoding="utf-8", errors="replace"))[0])


# --------------------------------------------------------------------------------------
# HoneyDB (c5)
# --------------------------------------------------------------------------------------


def parse_honeydb_ip(doc: Any, now: datetime) -> dict[str, Any]:
    """HoneyDB GET /api/ip/{ip} (current API) -> sightings. ``threat_info.threat_lists`` are relays
    of other feeds (blocklist.de, CINS, ET, ThreatFox...): display only, never a HoneyDB vote (P171).
    Raises ValueError for an answer that is not the documented object."""
    if not isinstance(doc, dict) or not any(k in doc for k in ("ip_history", "network_info", "threat_info", "internet_scanner")):
        raise ValueError("unexpected HoneyDB answer (not the /api/ip object): could not verify")
    netinfo = doc.get("network_info") if isinstance(doc.get("network_info"), dict) else {}
    threat = doc.get("threat_info") if isinstance(doc.get("threat_info"), dict) else {}
    lists = threat.get("threat_lists") if isinstance(threat.get("threat_lists"), dict) else {}
    history = [h for h in (doc.get("ip_history") or []) if isinstance(h, dict)] if isinstance(doc.get("ip_history"), list) else []
    services: set[str] = set()
    dates: list[datetime] = []
    events = 0
    for item in history[:1000]:
        if isinstance(item.get("service"), str) and item["service"].strip():
            services.add(item["service"].strip().lower()[:40])
        seen = parse_ts(item.get("date"))
        if seen is not None:
            dates.append(seen)
        count = item.get("event_count")
        if isinstance(count, str) and count.isdigit():
            events += int(count)
        elif isinstance(count, int) and not isinstance(count, bool):
            events += count
    cves: list[str] = []
    for entry in doc.get("cve") or [] if isinstance(doc.get("cve"), list) else []:
        value = entry.get("cve") if isinstance(entry, dict) else entry
        if isinstance(value, str) and _CVE_RE.match(value.strip()) and value.strip().upper() not in cves:
            cves.append(value.strip().upper())
    asn = netinfo.get("asn")
    transport = observation_transport(services)
    out = {
        "listed": bool(history), "services": sorted(services), "events": events,
        "first_seen": iso(min(dates)) if dates else None, "last_seen": iso(max(dates)) if dates else None,
        "transport": transport, "counts_for_verdict": counts_for_verdict(transport),
        "internet_scanner": doc.get("internet_scanner") if isinstance(doc.get("internet_scanner"), bool) else None,
        "asn": asn if isinstance(asn, int) and not isinstance(asn, bool) and 0 < asn < 2**32 else None,
        "as_org": str(netinfo.get("organization"))[:120] if isinstance(netinfo.get("organization"), str) else None,
        "is_tor": threat.get("is_tor") if isinstance(threat.get("is_tor"), bool) else None,
        "relayed_lists": sorted(k[3:] for k, v in lists.items() if v is True and isinstance(k, str) and k.startswith("is_"))[:40],
        "cves": cves[:50],
    }
    out["verdict"] = None
    if out["listed"] or out["internet_scanner"]:
        out["verdict"] = honeypot_verdict(now=now, benign_scanner=bool(out["internet_scanner"]), transport=transport,
                                          cves=cves, last_seen=out["last_seen"])
    return out


def http_failure(exc: BaseException) -> tuple[Status, str] | None:
    """Per-source 'could not verify' of an HTTP adapter; None for what must propagate."""
    if isinstance(exc, (_http.RequestCapReached, _http.Cancelled, _http.DeadlineExceeded, _http.PolicyError, _http.ConfigError)):
        return None
    if isinstance(exc, _http.QuotaExceeded):
        return Status.QUOTA, "quota"
    if isinstance(exc, _http.RateLimited):
        return Status.RATE_LIMITED, "rate_limited"
    if isinstance(exc, _http.Blocked):
        code = str(getattr(exc, "reason_code", "") or "challenge")
        return Status.BLOCKED, code if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge"
    if isinstance(exc, _http.AuthRequired):
        return Status.NEEDS_KEY, "needs_key"
    if isinstance(exc, _http.OfflineError):
        return Status.UNAVAILABLE, "offline"
    if isinstance(exc, (_http.HttpError, _http.NetworkError, ValueError)):
        return Status.ERROR, "error"
    return None


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class HoneypotIntel(Module):
    name = "honeypot_intel"
    title = "Honeypot intelligence (OffSeq Mirage, HoneyDB)"
    description = (
        "Honeypot sightings of an IP (services, tags, CVE exploit attempts, ATT&CK techniques, first/last seen) from the "
        "OffSeq Mirage open feed matched locally, plus HoneyDB with a company key; CVE and AS activity from the local feed."
    )
    category = "threat_intel_ioc"
    accepts = {T.IPV4, T.CVE, T.ASN}
    produces = {T.CVE, T.MITRE, T.ASN}
    tags = {"reputation", "free"}
    reference = "https://github.com/offseq/mirage-feed"
    notice = (
        f"{OFFSEQ_ATTRIBUTION}; data marked TLP:CLEAR. Honeypot sightings mean opportunistic scanning/exploitation: tag "
        "scanner, at most MEDIUM alone, 30-day decay, never malicious; known research scanners are benign_scanner noise. "
        "HoneyDB needs the company API id + key (free community tier is non-commercial: business plan in key_plans)."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "offseq"
    sources = (SRC_ATTACKERS, SRC_SCANNERS, SRC_ANONYMIZERS, SRC_HONEYDB)
    hosts = ("honeydb.io",)
    access_model = "free_noauth_limited"
    optional_keys = ("honeydb_api_id", "honeydb_api_key")
    max_requests = 1
    expected_latency = 1.0
    min_interval = 1.0
    cache_ttl = 86400
    max_pivots = 60
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return entity.type is not T.IPV4 or noise.is_public_ip(entity.value)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        allowed = ctx.allowed_sources
        if entity.type is T.IPV4:
            return self._ip(res, entity, ctx, allowed)
        if SRC_HONEYDB in allowed:
            res.source_status(SRC_HONEYDB, Status.SKIPPED, reason_code="not_applicable", reason="HoneyDB is queried for IPv4 addresses only")
        if SRC_ATTACKERS not in allowed:
            return res.mark(Status.SKIPPED, "the OffSeq Mirage feed is not allowed under the licence profile", reason_code="licence")
        try:
            index, info = load_attackers(ctx)
        except (DatasetError, OSError, ValueError) as exc:
            status, code = dataset_failure(exc) if isinstance(exc, DatasetError) else (Status.ERROR, "error")
            return res.mark(status, f"OffSeq Mirage attackers feed unavailable ({str(exc)[:160]}): could not verify", reason_code=code)
        res.source_status(SRC_ATTACKERS, Status.OK)
        if entity.type is T.CVE:
            return self._cve(res, entity, index, info)
        return self._asn(res, entity, index, info)

    # ---- IPv4 ----------------------------------------------------------------------------
    def _ip(self, res: ModuleResult, entity: Entity, ctx: Any, allowed: frozenset[str]) -> ModuleResult:
        ip = norm_ip(entity.value) or entity.value
        now = ctx.now()
        answered = 0
        failures: list[tuple[Status, str, str]] = []
        record: dict[str, Any] | None = None
        info: Any = None
        benign = False
        anonymizer = False
        if SRC_ATTACKERS in allowed:
            try:
                index, info = load_attackers(ctx)
                record = index.lookup(ip)
                answered += 1
                res.source_status(SRC_ATTACKERS, Status.OK if record else Status.EMPTY)
            except (DatasetError, OSError, ValueError) as exc:
                status, code = dataset_failure(exc) if isinstance(exc, DatasetError) else (Status.ERROR, "error")
                failures.append((status, code, f"OffSeq attackers feed: {str(exc)[:160]}"))
                res.source_status(SRC_ATTACKERS, status, reason_code=code, reason=f"OffSeq attackers feed unavailable: {str(exc)[:200]}")
        for source, name, label in ((SRC_SCANNERS, KNOWN_SCANNERS, "known-scanners"), (SRC_ANONYMIZERS, ANONYMIZERS, "anonymizers")):
            if source not in allowed:
                continue
            try:
                hit = ip in load_ip_set(ctx, name)
                answered += 1
                res.source_status(source, Status.OK if hit else Status.EMPTY)
            except (DatasetError, OSError, ValueError) as exc:
                status, code = dataset_failure(exc) if isinstance(exc, DatasetError) else (Status.ERROR, "error")
                failures.append((status, code, f"OffSeq {label} list: {str(exc)[:160]}"))
                res.source_status(source, status, reason_code=code, reason=f"OffSeq {label} list unavailable: {str(exc)[:200]}")
                continue
            if source == SRC_SCANNERS:
                benign = hit
            else:
                anonymizer = hit
        honeydb = self._honeydb(res, ctx, ip, now, allowed, failures)
        if honeydb is not None:
            answered += 1
        if not answered:
            if not failures:
                return res.mark(Status.SKIPPED, "no honeypot source is allowed under the licence profile", reason_code="licence")
            status, code, _ = failures[0]
            return res.mark(status, "; ".join(t for _s, _c, t in failures)[:600] + ": could not verify", reason_code=code)
        sightings: list[dict[str, Any]] = []
        if record is not None or benign or anonymizer:
            sightings.append(self._offseq_report(res, entity, record, info, now, benign=benign, anonymizer=anonymizer))
        if honeydb is not None and (honeydb["listed"] or honeydb["internet_scanner"]):
            sightings.append(self._honeydb_report(res, entity, honeydb))
        if honeydb is not None and honeydb["relayed_lists"]:
            res.attr("honeypot_relayed_lists", honeydb["relayed_lists"])
        res.raw = {"offseq": {"record": record, "known_scanner": benign, "anonymizer_list": anonymizer,
                              "dataset": {"sha256": getattr(info, "sha256", None), "fetched_at": getattr(info, "fetched_at", None)}},
                   "honeydb": {k: v for k, v in (honeydb or {}).items() if k != "verdict"} or None}
        if not sightings:
            return res.mark("empty")
        res.attr("honeypot_sightings", sightings)
        res.attr("is_scanner", True)
        if benign or (honeydb is not None and honeydb["internet_scanner"]):
            # c2 / P171: the benign-scanner findings are context_only, so CR27 reads this attribute to
            # downgrade a consensus (SUP-benign_scanner) instead of the finding tag.
            res.attr("scanner_classification", "benign")
        return res

    def _offseq_report(self, res: ModuleResult, entity: Entity, record: dict[str, Any] | None, info: Any, now: datetime,
                       *, benign: bool, anonymizer: bool) -> dict[str, Any]:
        kind = (record or {}).get("anonymizer") or ("vpn_or_tor" if anonymizer else "")
        if record is None:
            verdict = honeypot_verdict(now=now, benign_scanner=benign, anonymizer=kind)
            sighting = {"source": "offseq_mirage", "known_scanner": benign, "anonymizer": kind or None, "decay": verdict.decay,
                        "counts_for_verdict": verdict.counts}
            if benign:
                res.finding(
                    "Known research scanner (benign)",
                    "info",
                    f"Listed by OffSeq Mirage as a known research scanner: benign internet-wide scanning, never malicious. {OFFSEQ_ATTRIBUTION}.",
                    confidence="probable",
                    tags=["benign_scanner", "context_only"],
                    references=[OFFSEQ_REFERENCE],
                    source=SRC_SCANNERS,
                )
            else:
                res.finding(
                    "Anonymizer exit seen attacking honeypots",
                    verdict.severity,
                    f"Listed in OffSeq Mirage anonymizers-7d (Tor/VPN exits seen attacking in the last 7 days): traffic from many "
                    f"users, no attribution possible. {OFFSEQ_ATTRIBUTION}.",
                    confidence="probable",
                    criterion="listed in the OffSeq Mirage anonymizers-7d file (exit addresses seen attacking its sensors)",
                    tags=[*verdict.tags, "context_only"],
                    references=[OFFSEQ_REFERENCE],
                    source=SRC_ANONYMIZERS,
                )
            return sighting
        verdict = honeypot_verdict(now=now, benign_scanner=benign, anonymizer=kind, shared=record["shared"], recon_only=record["recon_only"],
                                   transport=observation_transport(record["services"], record["transport"]), cves=record["cves"],
                                   kev=record["kev"], confidence=record["confidence"], last_seen=record["last_seen"])
        sighting = {"source": "offseq_mirage", **{k: record[k] for k in ("first_seen", "last_seen", "services", "tags", "cves", "kev",
                                                                        "attack", "sensors", "networks", "hits", "confidence")},
                    "transport": "tcp", "decay": verdict.decay, "counts_for_verdict": verdict.counts, "known_scanner": benign,
                    "anonymizer": kind or None, "why": verdict.why}
        # The services are those the address ATTACKED (kept in honeypot_sightings), never written to
        # the host attribute ``services`` (services the host offers, read by the attack-surface rules).
        res.attr("attack_techniques", record["attack"])
        res.attr("source_confidence", record["confidence"])
        if record["asn"]:
            res.attr("asn", f"AS{record['asn']}")
        res.attr("as_org", record["as_org"])
        res.attr("country", record["country"] if re.fullmatch(r"[A-Z]{2}", record["country"] or "") else None)
        title = "Known research scanner seen by honeypots (benign)" if benign else "Seen attacking honeypots (OffSeq Mirage)"
        detail = (f"{record['hits']} hits on {record['sensors']} sensors in {record['networks']} networks between "
                  f"{record['first_seen']} and {record['last_seen']}; services {', '.join(record['services']) or 'n/a'}; tags "
                  f"{', '.join(record['tags']) or 'n/a'}; CVEs {', '.join(record['cves']) or 'none'}{' (KEV)' if record['kev'] else ''}; "
                  f"OffSeq confidence {record['confidence']}. {verdict.why}. {OFFSEQ_ATTRIBUTION}.")
        res.finding(
            title,
            verdict.severity,  # c6: at most MEDIUM alone, never malicious
            detail,
            confidence="probable" if record["confidence"] >= 70 else "possible",
            criterion=(f"listed in OffSeq Mirage attackers-7d: TCP handshake plus application data seen by {record['sensors']} sensors "
                       f"in {record['networks']} networks; {verdict.why}; 30-day decay weight {verdict.decay}"),
            data={"record": {k: record[k] for k in sighting if k in record}, "decay": verdict.decay, "dataset_fetched_at": getattr(info, "fetched_at", None)},
            tags=verdict.tags,
            references=[OFFSEQ_REFERENCE],
            source=SRC_ATTACKERS,
            observed_first=record["first_seen"],
            observed_last=record["last_seen"],
            attack=valid_techniques(record["attack"]) if verdict.counts else [],
        )
        if verdict.counts:
            self._pivots(res, record["asn"], record["as_org"], record["cves"], record["attack"])
        return sighting

    def _honeydb(self, res: ModuleResult, ctx: Any, ip: str, now: datetime, allowed: frozenset[str],
                 failures: list[tuple[Status, str, str]]) -> dict[str, Any] | None:
        if SRC_HONEYDB not in allowed:
            return None
        api_id, api_key = str(ctx.key("honeydb_api_id") or "").strip(), str(ctx.key("honeydb_api_key") or "").strip()
        if not (api_id and api_key):
            why = "HoneyDB needs the honeydb_api_id and honeydb_api_key keys (company account)"
            failures.append((Status.NEEDS_KEY, "needs_key", why))
            res.source_status(SRC_HONEYDB, Status.NEEDS_KEY, reason=why)
            return None
        try:
            doc = ctx.http.get_json(HONEYDB_API.format(ip=ip), headers={"X-HoneyDb-ApiId": api_id, "X-HoneyDb-ApiKey": api_key}, source=SRC_HONEYDB)
            parsed = parse_honeydb_ip(doc, now)
        except Exception as exc:  # noqa: BLE001 - per-source rule 5, the rest propagates
            mapped = http_failure(exc)
            if mapped is None:
                raise
            reason = str(exc)[:200] or type(exc).__name__
            if getattr(exc, "status", 0) == 410:
                reason = "HoneyDB endpoint removed (410 endpoint_deprecated): the client needs the current API"
            failures.append((mapped[0], mapped[1], f"HoneyDB: {reason}"))
            res.source_status(SRC_HONEYDB, mapped[0], reason_code=mapped[1], reason=f"HoneyDB: {reason}")
            return None
        res.source_status(SRC_HONEYDB, Status.OK if (parsed["listed"] or parsed["internet_scanner"]) else Status.EMPTY)
        return parsed

    def _honeydb_report(self, res: ModuleResult, entity: Entity, hd: dict[str, Any]) -> dict[str, Any]:
        verdict: Verdict = hd["verdict"]
        sighting = {"source": "honeydb", **{k: hd[k] for k in ("first_seen", "last_seen", "services", "events", "cves", "transport",
                                                                "internet_scanner")},
                    "decay": verdict.decay, "counts_for_verdict": verdict.counts, "why": verdict.why}
        title = "Known internet scanner (HoneyDB, benign)" if hd["internet_scanner"] else "Seen by HoneyDB honeypots"
        res.finding(
            title,
            verdict.severity,
            (f"{hd['events']} events on HoneyDB honeypots between {hd['first_seen']} and {hd['last_seen']}; services "
             f"{', '.join(hd['services']) or 'n/a'}; CVEs {', '.join(hd['cves']) or 'none'}. {verdict.why}."),
            confidence="possible",
            criterion=f"HoneyDB ip_history lists the address ({hd['transport']} services); {verdict.why}; 30-day decay weight {verdict.decay}",
            data={"sighting": sighting, "relayed_lists_display_only": hd["relayed_lists"]},
            tags=verdict.tags,
            references=["https://honeydb.io/"],
            source=SRC_HONEYDB,
            observed_first=hd["first_seen"],
            observed_last=hd["last_seen"],
        )
        if verdict.counts:
            self._pivots(res, hd["asn"], hd["as_org"] or "", hd["cves"], [])
        return sighting

    @staticmethod
    def _pivots(res: ModuleResult, asn: Any, as_org: str, cves: list[str], techniques: list[str]) -> None:
        """c8: the AS, each CVE (attempted_exploit, joined with KEV/EPSS) and each ATT&CK technique."""
        if isinstance(asn, int) and asn > 0:
            res.pivot(T.ASN, f"AS{asn}", "belongs_to_asn", confidence="probable", note=as_org[:80] if as_org else "")
        for cve in cves[:MAX_CVE_PIVOTS]:
            res.pivot(T.CVE, cve, IP_CVE_RELATION, confidence="probable", note="exploit attempt seen by honeypots (not a vulnerability of this host)")
        for tid in techniques[:MAX_TECHNIQUE_PIVOTS]:
            res.pivot(T.MITRE, tid, IP_TECHNIQUE_RELATION, confidence="possible", note="technique observed in honeypot sessions")

    # ---- CVE / AS (local index) -------------------------------------------------------------------
    def _cve(self, res: ModuleResult, entity: Entity, index: OffseqIndex, info: Any) -> ModuleResult:
        rows = [r for r in index.by_cve.get(entity.value.upper(), []) if not r["shared"]]
        if not rows:
            return res.mark("empty")
        firsts = sorted(r["first_seen"] for r in rows)
        lasts = sorted(r["last_seen"] for r in rows)
        asns = sorted({(r["asn"], r["as_org"]) for r in rows if r["asn"]}, key=lambda x: -sum(1 for r in rows if r["asn"] == x[0]))
        activity = {
            "source": "offseq_mirage", "window": "7d", "source_ips": len(rows), "kev": any(r["kev"] for r in rows),
            "events": sum(r["hits"] for r in rows), "first_seen": firsts[0], "last_seen": lasts[-1],
            "top_asns": [{"asn": f"AS{a}", "org": o} for a, o in asns[:10]],
        }
        res.attr("honeypot_cve_activity", activity)
        res.attr("exploited_in_wild", True)
        res.attr("exploited", {"offseq_mirage": firsts[0]})
        res.raw = {"cve_activity": activity, "dataset": {"sha256": getattr(info, "sha256", None), "fetched_at": getattr(info, "fetched_at", None)}}
        res.finding(
            "Exploitation attempts seen by honeypots (OffSeq Mirage, 7 days)",
            "low",
            f"{len(rows)} source address(es) sent exploit payloads for {entity.value} to OffSeq Mirage sensors between {firsts[0]} and "
            f"{lasts[-1]} ({activity['events']} hits). In-the-wild exploitation attempts: prioritise patching exposed systems. "
            f"{OFFSEQ_ATTRIBUTION}.",
            confidence="probable",
            criterion="OffSeq Mirage attackers-7d rows (TCP handshake, >= 3 sensors in >= 2 networks) list this CVE among the exploit payloads",
            data=activity,
            tags=["kev"] if activity["kev"] else [],
            references=[OFFSEQ_REFERENCE],
            source=SRC_ATTACKERS,
            observed_first=firsts[0],
            observed_last=lasts[-1],
        )
        return res

    def _asn(self, res: ModuleResult, entity: Entity, index: OffseqIndex, info: Any) -> ModuleResult:
        digits = entity.value.upper().removeprefix("AS")
        rows = index.by_asn.get(int(digits), []) if digits.isdigit() else []
        if not rows:
            return res.mark("empty")
        tags: dict[str, int] = {}
        for r in rows:
            for tag in r["tags"]:
                tags[tag] = tags.get(tag, 0) + 1
        cves = sorted({c for r in rows for c in r["cves"]})
        activity = {"source": "offseq_mirage", "window": "7d", "ips": len(rows), "hits": sum(r["hits"] for r in rows),
                    "tags": [t for t, _n in sorted(tags.items(), key=lambda x: (-x[1], x[0]))[:10]], "cves": cves[:25]}
        res.attr("honeypot_asn_activity", activity)
        res.raw = {"asn_activity": activity, "dataset": {"sha256": getattr(info, "sha256", None), "fetched_at": getattr(info, "fetched_at", None)}}
        res.finding(
            "Addresses of this AS seen attacking honeypots (OffSeq Mirage, 7 days)",
            "info",  # AS-wide context: never evidence against the whole network
            f"{len(rows)} address(es) of {entity.value} attacked OffSeq Mirage sensors in the last 7 days ({activity['hits']} hits; tags "
            f"{', '.join(activity['tags']) or 'n/a'}). Context only: an AS is never judged by some of its addresses. {OFFSEQ_ATTRIBUTION}.",
            confidence="probable",
            data=activity,
            tags=["context_only"],
            references=[OFFSEQ_REFERENCE],
            source=SRC_ATTACKERS,
        )
        return res
