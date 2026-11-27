"""Offline IOC feeds matched locally (P159): ``ioc_feeds_offline`` (terms 'open', default on) and
``ioc_feeds_unreviewed`` (terms 'unknown', default off in every profile).

Both modules have disclosure 'none': the investigated value never leaves the machine and no request is
made during a scan (TLP:RED-safe). Feeds are registered datasets refreshed out of band by
``v3lum data update`` (ETag/If-Modified-Since, TTL, provenance and the last successful update are the
dataset manager's); a module only reads the local copies, serves a stale copy as it is and shows its
age in coverage (cond 8).

Feeds (terms recorded in the provider registry, cond 2/3):

* ioc_feeds_offline ('open'): TweetFeed (CC0; the week list), the CIRCL MISP OSINT feed (TLP:CLEAR,
  attribute CIRCL; ``manifest.json`` + ``hashes.csv``), Meta threat-research (MIT), Neo23x0
  signature-base hash and C2 lists (DRL 1.1, attribution; filename-iocs with untrusted regexes is never
  used) and SSLBL, read from the one SSLBL dataset shared by abusech and ip_blocklists (never downloaded
  twice);
* ioc_feeds_unreviewed ('unknown'): C2IntelFeeds (no licence), ThreatView (site terms not recorded)
  and the ViriBack C2 Tracker dump (no terms, A1 BR16). Disabled until legal records a class.

Load pipeline (cond 4): refang -> validate (bogons, non-routable and x.0.0.0 addresses, reverse-DNS
names, numeric junk, non-http(s) URLs) -> warninglists and CDN/cloud ranges (``v3lum.core.noise``)
-> index (one in-memory index per dataset version and process). A feed parsing to 0 rows is
'unhealthy' (could not verify, never 'no hits'); a feed whose newest entry is older than 3x its
expected interval is 'stale' and skipped; archive feeds (Meta) have no interval.

CIRCL (cond 5): the feed's ``hashes.csv`` maps md5(attribute value) -> event uuid for every attribute
(verified against a live event on 2026-11-26), so a lookup hashes the candidate value locally and
reads the event metadata (info, date, galaxy actors/families) from ``manifest.json``; only events
dated within the last 365 days count (setting ``ioc_feeds_offline_circl_window_days``). Both files
come from the same host; the per-event JSON files are not fetched (backlog: multi-file datasets).

Findings (cond 6/7): one grouped finding per indicator naming every feed that lists it ('seen in 3
feeds: ...') with per-feed confidence (TweetFeed and C2IntelFeeds 'Possible' labels low; CIRCL, Meta,
signature-base medium) and listing age; a single upstream family is medium at most, >= 2 independent
families raise it one level; IP/URL listings older than 90 days are low. Reposts of abuse.ch/OTX data
count as those families (P171). Matches from C2/phishing feeds carry malicious/c2/phishing/suspicious
tags and the ``blocklists`` attribute (P376 guard); panel and C2 URLs are never visited.
"""

from __future__ import annotations

import bisect
import csv
import hashlib
import io
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from v3lum.core import noise
from v3lum.core.datasets import register_dataset
from v3lum.core.entities import Entity, refang
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.threat_intel_ioc.abusech import (
    SSLBL_DATASET,
    age_days,
    iso,
    local_copy,
    memoized,
    parse_sslbl,
    read_text,
    text,
)

CONFIDENCE_ORDER = ("low", "medium", "high")
#: cond 6: IP/URL listings older than this are low
STALE_LISTING_DAYS = 90
#: cond 4: a feed whose newest entry is older than this many intervals is stale
STALE_FACTOR = 3
#: cond 5: CIRCL events dated within this window count by default
CIRCL_WINDOW_DAYS = 365
CIRCL_BASE = "https://www.circl.lu/doc/misp/feed-osint/"
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
#: TweetFeed tags that describe the activity, not the family
GENERIC_TAGS = frozenset({
    "phishing", "malware", "scam", "clickfix", "opendir", "c2", "ioc", "iocs", "spam", "ransomware", "infostealer",
    "stealer", "rat", "botnet", "apt", "cybercrime", "threatintel", "maldoc", "payload", "fakecaptcha", "socgholish",
})
FAMILY_CANON = {
    "cobaltstrike": "Cobalt Strike", "cobalt strike": "Cobalt Strike", "sliver": "Sliver", "metasploit": "Metasploit",
    "havoc": "Havoc", "brute ratel": "Brute Ratel C4", "bruteratel": "Brute Ratel C4", "mythic": "Mythic",
    "posh": "PoshC2", "covenant": "Covenant",
}
_ABUSECH_HINTS = ("abuse.ch", "abuse_ch", "abusech", "urlhaus", "threatfox", "malwarebazaar", "malware bazaar", "feodotracker", "sslbl")
#: Meta threat-research report CSVs (index.json, 11 reports, newest added 2023-05-03: an archive feed)
META_REPORTS = (
    "2023_05_malware_iocs", "2022_malicious_mobile_apps",
    "2022_09_removing_coordinated_inauthentic_behavior_from_china_and_russia", "2022_08_metas_adversarial_threat_report_q2",
    "2022_04_metas_adversarial_threat_report_q1", "2021_12_taking_action_against_surveillance_for_hire",
    "2021_11_action_against_hackers_in_pakistan_and_syria", "2021_07_taking_action_against_hackers_in_iran",
    "2021_04_taking_action_against_hackers_in_palestine", "2021_03_taking_action_against_hackers_in_china",
    "2020_12_taking_action_against_hackers_in_bangladesh_and_vietnam",
)
META_RAW = "https://raw.githubusercontent.com/facebook/threat-research/main/"
SIGBASE_RAW = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/"


# --------------------------------------------------------------------------------------
# validation and the load pipeline (cond 4)
# --------------------------------------------------------------------------------------


def normalise_ipv4(value: str) -> str:
    """Dotted quad with zero-padded decimal octets ('120.229.26.013', ThreatView) -> canonical; '' else."""
    parts = value.strip().split(".")
    if len(parts) != 4 or not all(p.isdigit() and 1 <= len(p) <= 3 for p in parts):
        return ""
    nums = [int(p, 10) for p in parts]
    return ".".join(map(str, nums)) if all(n <= 255 for n in nums) else ""


def validate(etype: T, raw: Any) -> tuple[Entity | None, str]:
    """One feed value -> (entity, '') or (None, drop reason): refang, canonical form, bogon and
    non-routable addresses, 'x.0.0.0' network addresses, reverse-DNS names, non-http(s) URLs."""
    value = refang(text(raw, 4000))
    if not value:
        return None, "empty"
    if etype in (T.IPV4, T.IPV6):
        if etype is T.IPV4:
            value = normalise_ipv4(value) or value
        ent = Entity.try_make(etype, value)
        if ent is None:
            return None, "invalid_ip"
        if not noise.is_public_ip(ent.value):
            return None, "bogon"
        if etype is T.IPV4 and ent.value.endswith(".0.0.0"):
            return None, "network_address"
        return ent, ""
    if etype is T.DOMAIN:
        low = value.lower().rstrip(".")
        if low.endswith(".arpa") or normalise_ipv4(low):
            return None, "not_a_domain"
        ent = Entity.try_make(T.DOMAIN, low)
        return (ent, "") if ent is not None else (None, "invalid_domain")
    if etype is T.URL:
        if not re.match(r"(?i)^https?://", value):
            return None, "invalid_url"
        ent = Entity.try_make(T.URL, value)
        if ent is None:
            return None, "invalid_url"
        host = (ent.value.split("://", 1)[1].split("/", 1)[0].rsplit("@", 1)[-1])
        host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host.strip("[]")
        if normalise_ipv4(host) and not noise.is_public_ip(normalise_ipv4(host)):
            return None, "url_host_bogon"
        return ent, ""
    ent = Entity.try_make(etype, value)
    return (ent, "") if ent is not None else (None, "invalid")


def is_noise(ent: Entity) -> bool:
    """Warninglists (P169) and CDN/cloud/benign infrastructure (P034): never indexed as hostile."""
    try:
        return bool(noise.warninglists(ent)) or noise.is_noise(ent)
    except Exception:  # noqa: BLE001 - a broken list never drops or keeps a row by itself
        return False


@dataclass
class Row:
    """One indexed feed listing (cond 1: value -> feed, family, first/last seen)."""

    feed: str
    key: str
    family: str = ""
    actor: str = ""
    label: str = ""
    first_seen: str | None = None
    last_seen: str | None = None
    reference: str = ""
    tags: tuple[str, ...] = ()
    role: str = ""
    upstream: str = ""
    hostile: bool = True


def canon_family(name: Any) -> str:
    label = text(name, 120)
    label = re.sub(r"(?i)^(?:malware\s*family|family)\s*:\s*", "", label)
    label = re.sub(r"\s*\(.*$", "", label).strip(" -_.,;:|#")
    if not label or len(label) > 64 or label.lower() in GENERIC_TAGS or label.lower() in ("unknown", "none", "malware"):
        return ""
    return FAMILY_CANON.get(label.lower(), label)


def upstream_hint(default: str, *texts: Any) -> str:
    """P171: rows reposting abuse.ch or OTX data count as those families, not as independent votes."""
    hay = " ".join(str(t) for t in texts if t).lower()
    if any(hint in hay for hint in _ABUSECH_HINTS):
        return "abuse.ch"
    if "alienvault otx" in hay or "otx.alienvault" in hay or "source: otx" in hay:
        return "otx"
    return default


# --------------------------------------------------------------------------------------
# feed parsers (pure: text in, raw rows out)
# --------------------------------------------------------------------------------------

RawRow = tuple[T, str, dict[str, Any]]


def parse_tweetfeed(body: str) -> list[RawRow]:
    """TweetFeed {today,week,month}.csv (no header: date,user,type,value,tags,tweet). Tags are '#x';
    non-generic tags give the family. The reporting handle is not kept."""
    out: list[RawRow] = []
    types = {"ip": T.IPV4, "domain": T.DOMAIN, "url": T.URL, "md5": T.MD5, "sha256": T.SHA256, "sha1": T.SHA1}
    for rec in csv.reader(body.splitlines()):
        if len(rec) < 4 or rec[0].startswith("#"):
            continue
        etype = types.get(rec[2].strip().lower())
        if etype is None:
            continue
        tags = [t.lstrip("#") for t in (rec[4].split() if len(rec) > 4 else []) if t.strip("#")]
        families = [canon_family(t) for t in tags if t.lower() not in GENERIC_TAGS]
        reference = text(rec[5], 300) if len(rec) > 5 else ""
        out.append((etype, rec[3], {"family": next((f for f in families if f), ""), "label": " ".join(t for t in tags if t.lower() in GENERIC_TAGS),
                                    "first_seen": iso(rec[0]), "tags": tuple(tags[:10]),
                                    "reference": reference if reference.startswith("https://") else "", "upstream": upstream_hint("tweetfeed", " ".join(tags))}))
    return out


def parse_meta_csv(body: str, report_id: str, reference: str) -> list[RawRow]:
    """Meta threat-research report CSV (indicator_type,indicator_value,comment,ds): 'APT32: Domain' comments
    give the actor, '<Name> Sample' comments the family; the reference is the report URL."""
    out: list[RawRow] = []
    types = {"url": T.URL, "domain": T.DOMAIN, "ip_address": T.IPV4, "ip": T.IPV4, "ipv4": T.IPV4, "sha256": T.SHA256, "md5": T.MD5, "sha1": T.SHA1}
    for item in csv.DictReader(io.StringIO(body)):
        etype = types.get(str(item.get("indicator_type") or "").strip().lower())
        if etype is None:
            continue
        comment = text(item.get("comment"), 200)
        actor = family = ""
        match = re.match(r"^([^:]{2,60}):", comment)
        if match:
            actor = text(match.group(1), 60)
        match = re.match(r"^(.+?)\s+Sample$", comment, re.I)
        if match:
            family = canon_family(match.group(1))
        out.append((etype, item.get("indicator_value") or "", {"family": family, "actor": actor, "label": comment, "first_seen": iso(item.get("ds")),
                                                              "reference": reference, "tags": (report_id,)}))
    return out


def parse_sigbase_hash(body: str) -> list[RawRow]:
    """signature-base iocs/hash-iocs.txt ('HASH;COMMENT', MD5/SHA1/SHA256)."""
    out: list[RawRow] = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        value, _, comment = line.partition(";")
        value = value.strip()
        etype = {32: T.MD5, 40: T.SHA1, 64: T.SHA256}.get(len(value)) if _HEX_RE.match(value) else None
        if etype is None:
            continue
        note = text(comment, 300)
        ref = re.search(r"https://\S+", note)
        out.append((etype, value, {"label": note, "reference": ref.group(0) if ref else "", "upstream": upstream_hint("signature-base", note)}))
    return out


def parse_sigbase_c2(body: str) -> list[RawRow]:
    """signature-base iocs/c2-iocs.txt: '# <report> <url>' block headers, one domain/IP per line with an
    optional ';score'. The file's own header block (before the first blank line) is skipped."""
    out: list[RawRow] = []
    report = ref = ""
    in_header = True
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            in_header = False
            continue
        if stripped.startswith("#"):
            if not in_header:
                comment = stripped.lstrip("#").strip()
                report = re.sub(r"\s*https?://\S+", "", comment).strip(" -")[:200]
                match = re.search(r"https://\S+", comment)
                ref = match.group(0) if match else ""
            continue
        in_header = False
        value = stripped.partition(";")[0].strip()
        etype = T.IPV4 if normalise_ipv4(value) else T.DOMAIN
        out.append((etype, value, {"label": report, "reference": ref, "upstream": upstream_hint("signature-base", report)}))
    return out


_C2INTEL_RE = re.compile(r"^Possible\s+(?P<fam>.+?)\s+C2\s+(?P<what>IP|Domain|Fronting Domain|Fronted Domain)\s*$", re.I)


def parse_c2intel(body: str) -> list[RawRow]:
    """C2IntelFeeds ('#ip,ioc' | '#domain,ioc' | '#domain,ioc,uri_path,ip'). 'Possible' labels are low;
    'Fronting Domain' rows name the legitimate domain used for fronting: never hostile."""
    lines = [line for line in body.splitlines() if line.strip()]
    if not lines:
        return []
    header = [c.strip().lstrip("#").strip().lower() for c in lines[0].split(",")] if lines[0].startswith("#") else ["ip", "ioc"]
    out: list[RawRow] = []
    for rec in csv.reader(line for line in lines if not line.startswith("#")):
        item = {header[i]: rec[i].strip() for i in range(min(len(header), len(rec)))}
        label = text(item.get("ioc"), 120)
        match = _C2INTEL_RE.match(label)
        family = canon_family(match.group("fam")) if match else ""
        fronting = bool(match and match.group("what").lower() == "fronting domain")
        extra = {"family": family, "label": label, "role": "fronting" if fronting else ""}
        if item.get("domain"):
            out.append((T.DOMAIN, item["domain"], dict(extra, hostile=not fronting)))
            if item.get("ip") and not fronting:
                out.append((T.IPV4, item["ip"], dict(extra)))
        elif item.get("ip"):
            out.append((T.IPV4, item["ip"], extra))
    return out


def parse_threatview_list(body: str, etype: T) -> list[RawRow]:
    """ThreatView plain lists (IP / DOMAIN / MD5); values are refanged and validated later."""
    return [(etype, line.strip(), {}) for line in body.splitlines() if line.strip() and not line.lstrip().startswith("#")]


_TV_GENERATED_RE = re.compile(r"Generated by Threatview\.io[^0-9]*?on (\d{1,2} [A-Za-z]+ \d{4})", re.I)


def parse_threatview_c2(body: str) -> tuple[list[RawRow], str | None]:
    """ThreatView Cobalt Strike C2 feed: a defanged '#' header (refanged before use, cond 8) then
    'IP,Date of Detection,Host,Protocol,Beacon Config,Comment'. Returns (rows, generated date)."""
    head = "\n".join(refang(line) for line in body.splitlines()[:5] if line.startswith("#"))
    match = _TV_GENERATED_RE.search(head)
    generated = iso(match.group(1)) if match else None
    out: list[RawRow] = []
    for rec in csv.reader(line for line in body.splitlines() if line.strip() and not line.startswith("#")):
        if len(rec) < 2 or not normalise_ipv4(rec[0]):
            continue
        seen = iso(rec[1])
        out.append((T.IPV4, rec[0], {"family": "Cobalt Strike", "label": "Cobalt Strike C2", "first_seen": seen}))
        beacon = rec[4] if len(rec) > 4 else ""
        host = beacon.split(",")[0].strip().lower()
        if host and not normalise_ipv4(host):
            out.append((T.DOMAIN, host, {"family": "Cobalt Strike", "label": "Cobalt Strike beacon host", "first_seen": seen, "role": "beacon_host"}))
    return out, generated


def parse_viriback(body: str) -> list[RawRow]:
    """ViriBack C2 Tracker dump (Family,URL,IP,FirstSeen dd-mm-yyyy): panel URLs and their IPs. Panel URLs
    are only parsed, never visited; CDN IPs are removed by the noise stage."""
    out: list[RawRow] = []
    for item in csv.DictReader(io.StringIO(body)):
        if not isinstance(item, dict):
            continue
        family = canon_family(item.get("Family"))
        seen = iso(item.get("FirstSeen"))
        if item.get("URL"):
            out.append((T.URL, item["URL"], {"family": family, "label": "C2 panel", "first_seen": seen}))
        if item.get("IP"):
            out.append((T.IPV4, item["IP"], {"family": family, "label": "C2 panel IP", "first_seen": seen}))
    return out


# --------------------------------------------------------------------------------------
# CIRCL MISP OSINT feed: manifest.json + hashes.csv (cond 5)
# --------------------------------------------------------------------------------------


def misp_galaxy(tags: Iterable[str]) -> dict[str, list[str]]:
    """MISP tag names -> {actors, families}. threat-actor/intrusion-set -> actors; malpedia, mitre
    malware/tool/software, tool, ransomware, rat, botnet, stealer, backdoor, banker -> families."""
    out: dict[str, list[str]] = {"actors": [], "families": []}
    for name in tags:
        match = re.match(r'^misp-galaxy:([a-z0-9-]+)="(.+)"$', name, re.I)
        if not match:
            continue
        galaxy, value = match.group(1).lower(), re.sub(r"\s*-\s*[ST]\d{4}(?:\.\d{3})?$", "", match.group(2)).strip()
        if galaxy in ("threat-actor", "mitre-intrusion-set", "microsoft-activity-group"):
            if value and value not in out["actors"]:
                out["actors"].append(value[:80])
        elif galaxy in ("malpedia", "mitre-malware", "mitre-tool", "tool", "ransomware", "mitre-software", "rat", "botnet", "stealer", "backdoor", "banker"):
            family = canon_family(value)
            if family and family not in out["families"]:
                out["families"].append(family)
    return out


def parse_circl_manifest(obj: Any) -> dict[str, dict[str, Any]]:
    """manifest.json (uuid -> {info, date, timestamp, Orgc, Tag}) -> {uuid: {info, date, timestamp, orgc,
    actors, families}}."""
    events: dict[str, dict[str, Any]] = {}
    for uuid, event in obj.items() if isinstance(obj, dict) else []:
        if not isinstance(event, dict) or not isinstance(uuid, str) or not _UUID_RE.match(uuid.lower()):
            continue
        tags = [text(t.get("name") if isinstance(t, dict) else t, 300) for t in event.get("Tag") or [] if t] if isinstance(event.get("Tag"), list) else []
        galaxy = misp_galaxy(t for t in tags if t)
        orgc = event.get("Orgc") if isinstance(event.get("Orgc"), dict) else {}
        events[uuid.lower()] = {"info": text(event.get("info"), 300), "date": iso(event.get("date")), "timestamp": iso(event.get("timestamp")),
                                "orgc": text(orgc.get("name"), 120), **galaxy}
    return events


class HashIndex:
    """Sorted 16-byte md5 digests of hashes.csv with the index of their event uuid (one array per dataset
    version; about 20 bytes per line instead of a dict of strings)."""

    WIDTH = 20

    def __init__(self, path: Path) -> None:
        uuids: dict[str, int] = {}
        records: list[bytes] = []
        with open(path, "rb") as fh:
            for line in fh:
                if len(line) < 70 or line[32:33] != b",":
                    continue
                try:
                    digest = bytes.fromhex(line[:32].decode("ascii"))
                except (ValueError, UnicodeDecodeError):
                    continue
                uuid = line[33:].strip().decode("ascii", "replace").lower()
                if not _UUID_RE.match(uuid):
                    continue
                records.append(digest + uuids.setdefault(uuid, len(uuids)).to_bytes(4, "big"))
        records.sort()
        self.blob = b"".join(records)
        self.uuids = list(uuids)
        self.size = len(records)

    def __len__(self) -> int:
        return self.size

    def __getitem__(self, index: int) -> bytes:  # bisect support: the digest of record ``index``
        start = index * self.WIDTH
        return self.blob[start:start + 16]

    def events(self, value: str) -> list[str]:
        """Event uuids whose attributes include ``value`` (md5 of the exact value)."""
        digest = hashlib.md5(value.encode("utf-8")).digest()  # noqa: S324 - the feed's own lookup key, not security
        pos = bisect.bisect_left(self, digest)
        out = []
        while pos < self.size and self[pos] == digest:
            start = pos * self.WIDTH
            out.append(self.uuids[int.from_bytes(self.blob[start + 16:start + 20], "big")])
            pos += 1
        return out


def circl_candidates(entity: Entity) -> list[str]:
    """Value forms MISP attributes may hold for the entity (exact md5 match)."""
    value = entity.value
    forms = [value]
    if entity.type is T.URL and value.endswith("/"):
        forms.append(value.rstrip("/"))
    if entity.type in (T.MD5, T.SHA1, T.SHA256):
        forms.append(value.upper())
    return list(dict.fromkeys(forms))


# --------------------------------------------------------------------------------------
# feeds
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Feed:
    id: str
    title: str
    module: str
    source: str
    datasets: tuple[str, ...]
    types: frozenset[T]
    interval_s: float | None
    confidence: str
    hostile: bool
    upstream: str
    grade: str
    c2: bool = False
    lazy: bool = False


_IOC = frozenset({T.IPV4, T.DOMAIN, T.URL, T.MD5, T.SHA1, T.SHA256})


def _register(name: str, url: str, *, source: str, licence: str, terms: str, attribution: str, ttl: float, description: str,
              large: bool | None = None, expect: str = "text", min_bytes: int = 10, validate: Callable[[Path], Any] | None = None) -> str:
    return register_dataset(name, url, ttl=ttl, description=description, licence=licence, terms_class=terms, attribution=attribution,
                            source=source, expect=expect, min_bytes=min_bytes, validate=validate, large=large,
                            max_bytes=None if large else 5_000_000)


def _has_rows(parser: Callable[[str], list[Any]]) -> Callable[[Path], bool]:
    """Dataset validator: a download that parses to 0 rows never replaces a good copy (cond 4)."""
    return lambda path: bool(parser(read_text(path)))


SRC_TWEETFEED = "github.ioc_feeds_offline_tweetfeed"
SRC_META = "github.ioc_feeds_offline_meta"
SRC_SIGBASE = "github.ioc_feeds_offline_sigbase"
SRC_CIRCL = "circl.misp_osint_feed"
SRC_SSLBL = "abusech.sslbl"
SRC_C2INTEL = "github.ioc_feeds_unreviewed_c2intel"
SRC_THREATVIEW = "threatview.feeds"
SRC_VIRIBACK = "viriback.c2_tracker"

DS_TWEETFEED = _register(
    "tweetfeed_week.csv", "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/week.csv", source=SRC_TWEETFEED,
    licence="CC0-1.0", terms="open", attribution="TweetFeed (https://github.com/0xDanielLopez/TweetFeed), CC0-1.0", ttl=21600,
    description="TweetFeed IOCs shared on X during the last 7 days (CSV)", validate=_has_rows(parse_tweetfeed))
DS_CIRCL_MANIFEST = _register(
    "circl_osint_manifest.json", CIRCL_BASE + "manifest.json", source=SRC_CIRCL, licence="TLP:CLEAR (CIRCL OSINT feed)", terms="open",
    attribution="CIRCL MISP OSINT feed (https://www.circl.lu/doc/misp/feed-osint/), TLP:CLEAR", ttl=86400, expect="json", min_bytes=100,
    description="CIRCL MISP OSINT feed manifest (event uuid -> info, date, galaxy tags)", large=False)
DS_CIRCL_HASHES = _register(
    "circl_osint_hashes.csv", CIRCL_BASE + "hashes.csv", source=SRC_CIRCL, licence="TLP:CLEAR (CIRCL OSINT feed)", terms="open",
    attribution="CIRCL MISP OSINT feed (https://www.circl.lu/doc/misp/feed-osint/), TLP:CLEAR", ttl=86400, min_bytes=1000, large=True,
    description="CIRCL MISP OSINT feed hashes.csv (md5 of every attribute value -> event uuid, ~42 MB: data update only)")
DS_META_INDEX = _register(
    "meta_threat_research_index.json", META_RAW + "index.json", source=SRC_META, licence="MIT", terms="open",
    attribution="Meta threat-research (https://github.com/facebook/threat-research), MIT", ttl=604800, expect="json",
    description="Meta threat-research report index")
DS_META_REPORTS = tuple(
    _register(f"meta_tr_{rid}.csv", f"{META_RAW}indicators/csv/{rid}.csv", source=SRC_META, licence="MIT", terms="open",
              attribution="Meta threat-research (https://github.com/facebook/threat-research), MIT", ttl=604800,
              description=f"Meta threat-research indicators: {rid}")
    for rid in META_REPORTS
)
DS_SIGBASE_HASH = _register(
    "sigbase_hash_iocs.txt", SIGBASE_RAW + "iocs/hash-iocs.txt", source=SRC_SIGBASE, licence="DRL-1.1", terms="open",
    attribution="signature-base by Florian Roth (https://github.com/Neo23x0/signature-base), Detection Rule License 1.1", ttl=604800,
    description="Neo23x0 signature-base hash IOCs", validate=_has_rows(parse_sigbase_hash))
DS_SIGBASE_C2 = _register(
    "sigbase_c2_iocs.txt", SIGBASE_RAW + "iocs/c2-iocs.txt", source=SRC_SIGBASE, licence="DRL-1.1", terms="open",
    attribution="signature-base by Florian Roth (https://github.com/Neo23x0/signature-base), Detection Rule License 1.1", ttl=604800,
    description="Neo23x0 signature-base C2 IOCs (domains and IPs)", validate=_has_rows(parse_sigbase_c2))
DS_C2INTEL_IP = _register(
    "c2intel_ipc2s_30day.csv", "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv", source=SRC_C2INTEL,
    licence="unknown (no licence published)", terms="unknown", attribution="C2IntelFeeds (https://github.com/drb-ra/C2IntelFeeds)", ttl=86400,
    description="C2IntelFeeds possible C2 IPs (30 days)")
DS_C2INTEL_DOMAIN = _register(
    "c2intel_domain_url_ip_30day.csv",
    "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2swithURLwithIP-30day-filter-abused.csv", source=SRC_C2INTEL,
    licence="unknown (no licence published)", terms="unknown", attribution="C2IntelFeeds (https://github.com/drb-ra/C2IntelFeeds)", ttl=86400,
    description="C2IntelFeeds possible C2 domains with URL and IP (30 days)")
DS_TV_IP = _register(
    "threatview_ip_high.txt", "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt", source=SRC_THREATVIEW,
    licence="unknown (site terms not recorded)", terms="unknown", attribution="Threatview.io", ttl=86400,
    description="ThreatView high-confidence IP feed")
DS_TV_DOMAIN = _register(
    "threatview_domain_high.txt", "https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt", source=SRC_THREATVIEW,
    licence="unknown (site terms not recorded)", terms="unknown", attribution="Threatview.io", ttl=86400, large=True,
    description="ThreatView high-confidence domain feed (~11 MB: data update only)")
DS_TV_MD5 = _register(
    "threatview_md5_all.txt", "https://threatview.io/Downloads/MD5-HASH-ALL.txt", source=SRC_THREATVIEW,
    licence="unknown (site terms not recorded)", terms="unknown", attribution="Threatview.io", ttl=86400,
    description="ThreatView MD5 hash feed")
DS_TV_COBALT = _register(
    "threatview_cobaltstrike_c2.txt", "https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt", source=SRC_THREATVIEW,
    licence="unknown (site terms not recorded)", terms="unknown", attribution="Threatview.io", ttl=86400,
    description="ThreatView high-confidence Cobalt Strike C2 feed")
DS_VIRIBACK = _register(
    "viriback_c2_dump.csv", "https://tracker.viriback.com/dump.php", source=SRC_VIRIBACK, licence="unknown (no published terms)", terms="unknown",
    attribution="ViriBack C2 Tracker (https://tracker.viriback.com/)", ttl=86400, description="ViriBack C2 Tracker dump (panels: family, URL, IP, first seen)")

OFFLINE, UNREVIEWED = "ioc_feeds_offline", "ioc_feeds_unreviewed"
DAY = 86400.0
FEEDS: tuple[Feed, ...] = (
    Feed("tweetfeed", "TweetFeed", OFFLINE, SRC_TWEETFEED, (DS_TWEETFEED,), _IOC, DAY, "low", True, "tweetfeed", "C"),
    Feed("circl_osint", "CIRCL OSINT", OFFLINE, SRC_CIRCL, (DS_CIRCL_MANIFEST, DS_CIRCL_HASHES), _IOC, DAY, "medium", True, "circl", "B"),
    Feed("meta_threat_research", "Meta threat-research", OFFLINE, SRC_META, (DS_META_INDEX, *DS_META_REPORTS), _IOC, None, "medium", True, "meta", "B"),
    Feed("sigbase_hash", "signature-base hashes", OFFLINE, SRC_SIGBASE, (DS_SIGBASE_HASH,), frozenset({T.MD5, T.SHA1, T.SHA256}), 7 * DAY,
         "medium", True, "signature-base", "B"),
    Feed("sigbase_c2", "signature-base C2", OFFLINE, SRC_SIGBASE, (DS_SIGBASE_C2,), frozenset({T.IPV4, T.DOMAIN}), 7 * DAY, "medium", True,
         "signature-base", "B", c2=True),
    Feed("sslbl", "SSLBL", OFFLINE, SRC_SSLBL, (SSLBL_DATASET,), frozenset({T.SHA1, T.CERT_FP}), DAY, "medium", True, "abuse.ch", "B", c2=True),
    Feed("c2intelfeeds", "C2IntelFeeds", UNREVIEWED, SRC_C2INTEL, (DS_C2INTEL_IP, DS_C2INTEL_DOMAIN), frozenset({T.IPV4, T.DOMAIN}), DAY, "low",
         True, "c2intelfeeds", "C", c2=True),
    Feed("threatview", "ThreatView", UNREVIEWED, SRC_THREATVIEW, (DS_TV_IP, DS_TV_DOMAIN, DS_TV_MD5), frozenset({T.IPV4, T.DOMAIN, T.MD5}), DAY,
         "low", True, "threatview", "C", lazy=True),
    Feed("threatview_cobaltstrike", "ThreatView Cobalt Strike C2", UNREVIEWED, SRC_THREATVIEW, (DS_TV_COBALT,), frozenset({T.IPV4, T.DOMAIN}), DAY,
         "low", True, "threatview", "C", c2=True),
    Feed("viriback", "ViriBack C2 Tracker", UNREVIEWED, SRC_VIRIBACK, (DS_VIRIBACK,), frozenset({T.IPV4, T.URL, T.DOMAIN}), 7 * DAY, "medium",
         True, "viriback", "C", c2=True),
)


@dataclass
class FeedIndex:
    """One feed version: rows by entity key, family counts, newest entry, row count and drop counts."""

    rows: dict[str, list[Row]]
    families: dict[str, int]
    newest: str | None
    count: int
    dropped: dict[str, int]
    lazy: frozenset[str] = frozenset()  # lazily validated keys (large lists)


def _index(feed: Feed, raw_rows: Iterable[RawRow], *, lazy: bool = False) -> FeedIndex:
    rows: dict[str, list[Row]] = {}
    families: dict[str, int] = {}
    dropped: dict[str, int] = {}
    newest: str | None = None
    count = 0
    for etype, value, extra in raw_rows:
        if lazy:  # validated and noise-checked when a lookup hits (large lists)
            key = f"{etype.value}:{refang(text(value, 300)).lower().rstrip('.')}"
        else:
            ent, why = validate(etype, value)
            if ent is None:
                dropped[why] = dropped.get(why, 0) + 1
                continue
            if ent.type in (T.IPV4, T.IPV6, T.DOMAIN, T.URL) and extra.get("role") != "fronting" and is_noise(ent):
                dropped["warninglist_or_cdn"] = dropped.get("warninglist_or_cdn", 0) + 1
                count += 1
                continue
            key = ent.key
        count += 1
        family = extra.get("family") or ""
        row = Row(feed=feed.id, key=key, family=family, actor=extra.get("actor") or "", label=extra.get("label") or "",
                  first_seen=extra.get("first_seen"), last_seen=extra.get("last_seen"), reference=extra.get("reference") or "",
                  tags=tuple(extra.get("tags") or ()), role=extra.get("role") or "", upstream=extra.get("upstream") or feed.upstream,
                  hostile=bool(extra.get("hostile", feed.hostile)))
        rows.setdefault(key, []).append(row)
        if family:
            families[family.lower()] = families.get(family.lower(), 0) + 1
        for stamp in (row.last_seen, row.first_seen):
            if stamp and (newest is None or stamp > newest):
                newest = stamp
    return FeedIndex(rows, families, newest, count, dropped, frozenset(rows) if lazy else frozenset())


# --------------------------------------------------------------------------------------
# loading a feed from its local datasets
# --------------------------------------------------------------------------------------


@dataclass
class FeedState:
    feed: Feed
    state: str  # ok | stale | unhealthy | missing
    reason: str = ""
    index: FeedIndex | None = None
    fetched_at: str = ""
    age_hours: float | None = None
    extra: dict[str, Any] | None = None


def _parse_dataset(feed: Feed, name: str, path: Path) -> list[RawRow]:
    body = read_text(path)
    if feed.id == "tweetfeed":
        return parse_tweetfeed(body)
    if feed.id == "sigbase_hash":
        return parse_sigbase_hash(body)
    if feed.id == "sigbase_c2":
        return parse_sigbase_c2(body)
    if feed.id == "c2intelfeeds":
        return parse_c2intel(body)
    if feed.id == "threatview":
        etype = {DS_TV_IP: T.IPV4, DS_TV_DOMAIN: T.DOMAIN, DS_TV_MD5: T.MD5}[name]
        return parse_threatview_list(body, etype)
    if feed.id == "threatview_cobaltstrike":
        return parse_threatview_c2(body)[0]
    if feed.id == "viriback":
        return parse_viriback(body)
    if feed.id == "sslbl":
        parsed = parse_sslbl(body)
        return [(T.SHA1, sha1, {"family": row["family"], "label": row["reason"], "first_seen": row["listed"], "upstream": "abuse.ch"})
                for sha1, row in parsed["rows"].items()]
    return []


def load_feed(ctx: Any, feed: Feed, now: Any) -> FeedState:
    """Local copies of a feed's datasets -> FeedState (never downloads; cond 4 health rules)."""
    if feed.id == "circl_osint":
        return _load_circl(ctx, feed, now)
    if feed.id == "meta_threat_research":
        return _load_meta(ctx, feed, now)
    present: list[tuple[str, Path, Any]] = []
    for name in feed.datasets:
        path, info = local_copy(ctx, name)
        if path is not None:
            present.append((name, path, info))
    if not present:
        return FeedState(feed, "missing", f"{feed.title}: not downloaded (run v3lum data update {' '.join(feed.datasets)})")
    version = "|".join(f"{n}:{i.sha256}" for n, _p, i in present)
    lazy_names = {DS_TV_DOMAIN} if feed.lazy else set()

    def build() -> FeedIndex:
        merged = FeedIndex({}, {}, None, 0, {})
        for name, path, _info in present:
            part = _index(feed, _parse_dataset(feed, name, path), lazy=name in lazy_names)
            for key, rows in part.rows.items():
                merged.rows.setdefault(key, []).extend(rows)
            for fam, n in part.families.items():
                merged.families[fam] = merged.families.get(fam, 0) + n
            merged.count += part.count
            for why, n in part.dropped.items():
                merged.dropped[why] = merged.dropped.get(why, 0) + n
            if part.newest and (merged.newest is None or part.newest > merged.newest):
                merged.newest = part.newest
            merged.lazy = merged.lazy | part.lazy
        return merged

    index = memoized(f"feed:{feed.id}", version, "index", build)
    fetched = max((str(i.fetched_at or "") for _n, _p, i in present), default="")
    ages = [i.age_hours for _n, _p, i in present if i.age_hours is not None]
    state = _health(feed, index.count, index.newest or fetched, now)
    reason = state[1]
    missing = [n for n in feed.datasets if n not in {p[0] for p in present}]
    if missing and state[0] == "ok":
        reason = f"{feed.title}: {len(missing)} list(s) not downloaded ({', '.join(missing)})"
    return FeedState(feed, state[0], reason, index, fetched, min(ages) if ages else None)


def _health(feed: Feed, count: int, newest: Any, now: Any) -> tuple[str, str]:
    """cond 4: 0 rows -> unhealthy (doctor; never 'no hits'); newest entry older than 3x the expected
    interval -> stale (skipped, age shown); archive feeds (no interval) are never stale."""
    if not count:
        return "unhealthy", f"{feed.title}: the local copy parsed to 0 rows (unhealthy): could not verify; run v3lum data update"
    if feed.interval_s is None:
        return "ok", ""
    days = age_days(newest, now)
    if days is not None and days * 86400 > STALE_FACTOR * feed.interval_s:
        return "stale", (f"{feed.title}: stale (newest entry {days:.1f} days old, more than {STALE_FACTOR}x its "
                         f"{feed.interval_s / 86400:.0f}-day interval): skipped; run v3lum data update")
    return "ok", ""


def _load_meta(ctx: Any, feed: Feed, now: Any) -> FeedState:
    idx_path, idx_info = local_copy(ctx, DS_META_INDEX)
    references: dict[str, str] = {}
    if idx_path is not None:
        try:
            for entry in json.loads(read_text(idx_path)) or []:
                if isinstance(entry, dict) and isinstance(entry.get("reference_urls"), list):
                    urls = [u for u in entry["reference_urls"] if isinstance(u, str) and u.startswith("https://")]
                    if urls:
                        references[text(entry.get("id"), 200)] = urls[0]
        except (ValueError, RecursionError, TypeError):
            references = {}
    present = []
    for rid, name in zip(META_REPORTS, DS_META_REPORTS):
        path, info = local_copy(ctx, name)
        if path is not None:
            present.append((rid, name, path, info))
    if not present:
        return FeedState(feed, "missing", f"{feed.title}: not downloaded (run v3lum data update {DS_META_INDEX} and the meta_tr_*.csv lists)")
    version = "|".join(f"{n}:{i.sha256}" for _r, n, _p, i in present) + f"|idx:{getattr(idx_info, 'sha256', '')}"

    def build() -> FeedIndex:
        raw: list[RawRow] = []
        for rid, _name, path, _info in present:
            raw += parse_meta_csv(read_text(path), rid, references.get(rid, "https://github.com/facebook/threat-research"))
        return _index(feed, raw)

    index = memoized("feed:meta", version, "index", build)
    fetched = max((str(i.fetched_at or "") for *_x, i in present), default="")
    state, reason = _health(feed, index.count, index.newest, now)
    return FeedState(feed, state, reason, index, fetched)


def _load_circl(ctx: Any, feed: Feed, now: Any) -> FeedState:
    man_path, man_info = local_copy(ctx, DS_CIRCL_MANIFEST)
    hash_path, hash_info = local_copy(ctx, DS_CIRCL_HASHES)
    if man_path is None or hash_path is None:
        missing = [n for n, p in ((DS_CIRCL_MANIFEST, man_path), (DS_CIRCL_HASHES, hash_path)) if p is None]
        return FeedState(feed, "missing", f"{feed.title}: not downloaded (run v3lum data update {' '.join(missing)})")
    try:
        events = memoized(DS_CIRCL_MANIFEST, man_info.sha256, "manifest", lambda: parse_circl_manifest(json.loads(read_text(man_path))))
        hashes = memoized(DS_CIRCL_HASHES, hash_info.sha256, "hashes", lambda: HashIndex(hash_path))
    except (ValueError, OSError, RecursionError) as exc:
        return FeedState(feed, "unhealthy", f"{feed.title}: local copy unreadable ({type(exc).__name__}): run v3lum data update")
    newest = max((e["timestamp"] or e["date"] or "" for e in events.values()), default="") or None
    count = len(hashes) if events else 0
    state, reason = _health(feed, count, newest, now)
    fetched = max(str(man_info.fetched_at or ""), str(hash_info.fetched_at or ""))
    return FeedState(feed, state, reason, None, fetched, extra={"events": events, "hashes": hashes})


# --------------------------------------------------------------------------------------
# matching and grouping (cond 6/7)
# --------------------------------------------------------------------------------------


def _lookup_keys(entity: Entity) -> list[tuple[str, str]]:
    """(index key, how) pairs for an entity: the value itself, plus the host of a URL."""
    keys = [(entity.key, "value")]
    if entity.type is T.CERT_FP:
        keys.append((f"sha1:{entity.value}", "value"))
    if entity.type is T.URL:
        host = entity.value.split("://", 1)[-1].split("/", 1)[0].rsplit("@", 1)[-1]
        host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        for etype in (T.IPV4, T.DOMAIN):
            ent = Entity.try_make(etype, host)
            if ent is not None:
                keys.append((ent.key, "url_host"))
                break
    return keys


def _lazy_ok(key: str) -> bool:
    etype, _, value = key.partition(":")
    ent, _why = validate(T.parse(etype), value)
    return ent is not None and not is_noise(ent)


def match(state: FeedState, entity: Entity, window_days: int, now: Any) -> list[tuple[Row, str]]:
    """Rows of one usable feed that list the entity, with how they matched ('value' | 'url_host')."""
    if state.feed.id == "circl_osint":
        return _match_circl(state, entity, window_days, now)
    index = state.index
    if index is None or (entity.type not in state.feed.types and entity.type is not T.URL):
        return []
    out: list[tuple[Row, str]] = []
    for key, how in _lookup_keys(entity):
        rows = index.rows.get(key) or []
        if rows and key in index.lazy and not _lazy_ok(key):
            continue
        out += [(row, how) for row in rows]
    return out


def _match_circl(state: FeedState, entity: Entity, window_days: int, now: Any) -> list[tuple[Row, str]]:
    if entity.type not in state.feed.types:
        return []
    extra = state.extra or {}
    hashes, events = extra.get("hashes"), extra.get("events") or {}
    if hashes is None:
        return []
    out: list[tuple[Row, str]] = []
    seen: set[str] = set()
    for value in circl_candidates(entity):
        for uuid in hashes.events(value):
            event = events.get(uuid)
            if uuid in seen or event is None:
                continue
            seen.add(uuid)
            days = age_days(event.get("date"), now)
            if days is None or days > window_days:
                continue
            out.append((Row(feed="circl_osint", key=entity.key, family=(event["families"] or [""])[0], actor=(event["actors"] or [""])[0],
                            label=event["info"], first_seen=event["date"], last_seen=event["timestamp"], reference=f"{CIRCL_BASE}{uuid}.json",
                            upstream=upstream_hint("circl", event["info"], event["orgc"]), hostile=True), "value"))
    return out


def group_hits(entity: Entity, hits: list[tuple[Row, str]], feeds: dict[str, Feed], now: Any) -> dict[str, Any]:
    """One grouped verdict per indicator (cond 6): per-feed confidence and age; IP/URL listings older
    than 90 days are low; one upstream family is medium at most; >= 2 independent families raise one
    level; fronting-domain rows never make the indicator hostile."""
    per_feed: dict[str, dict[str, Any]] = {}
    for row, how in hits:
        feed = feeds[row.feed]
        conf = feed.confidence
        stamp = row.last_seen or row.first_seen
        days = age_days(stamp, now)
        if entity.type in (T.IPV4, T.IPV6, T.URL) and days is not None and days > STALE_LISTING_DAYS:
            conf = "low"
        if how == "url_host":
            conf = "low"
        current = per_feed.get(row.feed)
        if current is None or CONFIDENCE_ORDER.index(conf) > CONFIDENCE_ORDER.index(current["confidence"]):
            per_feed[row.feed] = {
                "feed": feed.title, "confidence": conf, "age_days": None if days is None else round(days, 1), "family": row.family,
                "actor": row.actor, "label": row.label[:160], "reference": row.reference, "upstream": row.upstream, "match": how,
                "hostile": row.hostile and row.role != "fronting", "c2": feed.c2, "grade": feed.grade,
                "first_seen": row.first_seen, "last_seen": row.last_seen,
                "phishing": any("phish" in t.lower() for t in row.tags) or "phish" in row.label.lower(),
            }
    listed = sorted(per_feed.values(), key=lambda x: (-CONFIDENCE_ORDER.index(x["confidence"]), x["feed"]))
    families = sorted({x["upstream"] for x in listed})
    best = max((CONFIDENCE_ORDER.index(x["confidence"]) for x in listed), default=0)
    if len(families) >= 2:
        best = min(best + 1, 2)
    else:
        best = min(best, 1)
    return {"feeds": listed, "upstream_families": families, "confidence": CONFIDENCE_ORDER[best],
            "hostile": any(x["hostile"] for x in listed)}


# --------------------------------------------------------------------------------------
# the modules
# --------------------------------------------------------------------------------------

_SEVERITY = {"low": "low", "medium": "medium", "high": "high"}
_LABEL = {"low": "possible", "medium": "probable", "high": "probable"}


class _FeedMatcher(Module):
    """Shared behaviour of ioc_feeds_offline and ioc_feeds_unreviewed (not registered: no name)."""

    feed_module = ""
    finding_title = ""

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type in (T.IPV4, T.IPV6):
            return noise.is_public_ip(entity.value)
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        now = ctx.now()
        allowed = set(ctx.allowed_sources)
        feeds = {f.id: f for f in FEEDS if f.module == self.feed_module}
        window = _window(ctx)
        states: list[FeedState] = []
        wanted = {entity.type} | ({T.DOMAIN, T.IPV4} if entity.type is T.URL else set())  # a URL also matches by its host
        for feed in feeds.values():
            if feed.source not in allowed:
                continue
            if entity.type is not T.MALWARE and not (feed.types & wanted):
                continue
            states.append(load_feed(ctx, feed, now))
        usable = [s for s in states if s.state == "ok"]
        by_source: dict[str, list[FeedState]] = {}
        for state in states:
            by_source.setdefault(state.feed.source, []).append(state)
        if entity.type is T.MALWARE:
            found = self._family(res, entity, usable)
        else:
            hits: list[tuple[Row, str]] = []
            for state in usable:
                hits += match(state, entity, window, now)
            found = self._record(res, entity, hits, feeds, now, usable) if hits else False
        self._source_statuses(res, by_source, found)
        if found:
            return res
        if usable:
            return res.mark(Status.EMPTY)
        if not states:
            return res.mark(Status.SKIPPED, "no allowed offline feed covers this entity type", reason_code="not_applicable")
        unhealthy = [s for s in states if s.state == "unhealthy"]
        if unhealthy:
            return res.mark(Status.ERROR, "; ".join(s.reason for s in unhealthy)[:600], reason_code="error")
        return res.mark(Status.UNAVAILABLE, "; ".join(s.reason for s in states)[:600], reason_code="dataset")

    # ---- per-source coverage (dataset age shown, cond 8) -------------------------------------
    def _source_statuses(self, res: ModuleResult, by_source: dict[str, list[FeedState]], found: bool) -> None:
        for source, states in by_source.items():
            ok = [s for s in states if s.state == "ok"]
            notes = "; ".join(s.reason for s in states if s.reason)
            if ok:
                ages = ", ".join(f"{s.feed.title} fetched {s.fetched_at or '?'}" for s in ok)
                res.source_status(source, Status.OK if found else Status.EMPTY, reason=(ages + ("; " + notes if notes else ""))[:400])
            elif any(s.state == "unhealthy" for s in states):
                res.source_status(source, Status.ERROR, reason_code="error", reason=notes[:400])
            else:
                res.source_status(source, Status.UNAVAILABLE, reason_code="dataset", reason=notes[:400])

    # ---- indicator hits --------------------------------------------------------------------
    def _record(self, res: ModuleResult, entity: Entity, hits: list[tuple[Row, str]], feeds: dict[str, Feed], now: Any,
                usable: list[FeedState]) -> bool:
        grouped = group_hits(entity, hits, feeds, now)
        listed = grouped["feeds"]
        if not listed:
            return False
        confidence = grouped["confidence"]
        hostile = grouped["hostile"]
        names = ", ".join(x["feed"] for x in listed)
        families = sorted({x["family"] for x in listed if x["family"]})
        actors = sorted({x["actor"] for x in listed if x["actor"]})
        firsts = [x["first_seen"] for x in listed if x["first_seen"]]
        lasts = [x["last_seen"] or x["first_seen"] for x in listed if x["last_seen"] or x["first_seen"]]
        hash_like = entity.type in (T.MD5, T.SHA1, T.SHA256)
        if not hostile:
            severity, tags = "info", ["info"]
        else:
            severity = _SEVERITY[confidence]
            tags = ["malicious"] if confidence != "low" else ["suspicious"]
            if hash_like:
                tags.append("malware")
            if any(x["c2"] for x in listed if x["hostile"]):
                tags.append("c2")
            if any(x["phishing"] for x in listed):
                tags.append("phishing")
        description = f"seen in {len(listed)} feed{'s' if len(listed) != 1 else ''}: {names}. " + "; ".join(
            f"{x['feed']}: {x['confidence']} confidence, listed {x['age_days'] if x['age_days'] is not None else '?'} days ago"
            + (f", {x['family'] or x['actor'] or x['label'][:80]}" if (x["family"] or x["actor"] or x["label"]) else "")
            + (" (via the URL host)" if x["match"] == "url_host" else "")
            for x in listed)
        res.finding(
            self.finding_title,
            severity,
            description,
            confidence=_LABEL[confidence],
            criterion=(f"listed by {len(listed)} offline feed(s) from {len(grouped['upstream_families'])} upstream famil"
                       f"{'ies' if len(grouped['upstream_families']) != 1 else 'y'} ({', '.join(grouped['upstream_families'])}); "
                       "one family is medium at most, IP/URL listings older than 90 days are low"),
            data={"feeds": listed, "upstream_families": grouped["upstream_families"]},
            tags=tags,
            references=[x["reference"] for x in listed if x["reference"].startswith("https://")][:5],
            source=feeds_source(listed[0]["feed"]),
            observed_first=min(firsts) if firsts else None,
            observed_last=max(lasts) if lasts else None,
        )
        res.attr("feed_hits", [{k: x[k] for k in ("feed", "family", "actor", "label", "first_seen", "last_seen", "confidence", "age_days", "reference")}
                               for x in listed])
        res.attr("malware_family", families)
        res.attr("threat_actors", actors)
        res.attr("first_seen", min(firsts) if firsts else None)
        res.attr("last_seen", max(lasts) if lasts else None)
        res.attr("feed_status", {s.feed.title: {"state": s.state, "age_hours": s.age_hours, "fetched_at": s.fetched_at} for s in usable})
        if hostile:
            res.attr("blocklists", [x["feed"] for x in listed if x["hostile"]])
            res.attr("malicious" if confidence != "low" else "suspicious", True)
        for name in families[:10]:
            res.pivot(T.MALWARE, name, "family", confidence="possible", expand=False, note="label from an offline feed listing")
        for name in actors[:10]:
            res.pivot(T.THREAT_ACTOR, name, "attributed_to", confidence="possible", expand=False, note="label from an offline feed listing")
        return True

    # ---- malware family queries --------------------------------------------------------------
    def _family(self, res: ModuleResult, entity: Entity, usable: list[FeedState]) -> bool:
        name = canon_family(entity.value).lower() or entity.value.lower()
        counts: dict[str, int] = {}
        for state in usable:
            if state.index is not None:
                n = state.index.families.get(name, 0)
            else:  # CIRCL: events whose galaxy tags name the family
                n = sum(1 for e in ((state.extra or {}).get("events") or {}).values() if name in {f.lower() for f in e["families"]})
            if n:
                counts[state.feed.title] = n
        if not counts:
            return False
        res.attr("ioc_count", counts)
        res.finding(
            "Malware family listed in offline feeds",
            "info",
            "Indicators labelled with this family: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) + " (local feed copies).",
            confidence="probable",
            data={"counts": counts},
            source=next(feeds_source(k) for k in counts),
        )
        return True


def feeds_source(title: str) -> str:
    """Registry source id of a feed title."""
    for feed in FEEDS:
        if feed.title == title or feed.id == title:
            return feed.source
    return ""


def _window(ctx: Any) -> int:
    try:
        return max(1, int(ctx.setting("ioc_feeds_offline_circl_window_days", CIRCL_WINDOW_DAYS)))
    except (TypeError, ValueError):
        return CIRCL_WINDOW_DAYS


@register
class IocFeedsOffline(_FeedMatcher):
    name = "ioc_feeds_offline"
    title = "Offline IOC feeds (TweetFeed, CIRCL OSINT, Meta, signature-base, SSLBL)"
    description = (
        "Matches IPs, domains, URLs, hashes and certificate SHA1s against local copies of open threat feeds: TweetFeed, the "
        "CIRCL MISP OSINT feed, Meta threat-research, Neo23x0 signature-base hash/C2 lists and SSLBL. No request is sent."
    )
    category = "threat_intel_ioc"
    accepts = {T.IPV4, T.DOMAIN, T.URL, T.MD5, T.SHA1, T.SHA256, T.MALWARE, T.CERT_FP}
    produces = {T.MALWARE, T.THREAT_ACTOR}
    tags = {"offline", "reputation", "free"}
    reference = "https://www.circl.lu/doc/misp/feed-osint/"
    notice = (
        "Offline: feeds are refreshed by `v3lum data update` and matched locally (allowed at TLP:RED). Terms 'open': TweetFeed "
        "CC0, CIRCL OSINT TLP:CLEAR (attribute CIRCL), Meta MIT, signature-base DRL 1.1 (attribute Florian Roth), SSLBL CC0."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (SRC_TWEETFEED, SRC_CIRCL, SRC_META, SRC_SIGBASE, SRC_SSLBL)
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.5
    max_pivots = 30
    default_enabled = True
    settings = {"ioc_feeds_offline_circl_window_days": CIRCL_WINDOW_DAYS}
    feed_module = OFFLINE
    finding_title = "Listed in offline threat feeds"


@register
class IocFeedsUnreviewed(_FeedMatcher):
    name = "ioc_feeds_unreviewed"
    title = "Offline IOC feeds without recorded terms (C2IntelFeeds, ThreatView, ViriBack)"
    description = (
        "Matches IPs, domains, URLs and MD5s against local copies of feeds whose terms are not recorded yet: C2IntelFeeds, "
        "ThreatView and the ViriBack C2 Tracker dump. Disabled until legal records a terms class."
    )
    category = "threat_intel_ioc"
    accepts = {T.IPV4, T.DOMAIN, T.URL, T.MD5, T.MALWARE}
    produces = {T.MALWARE}
    tags = {"offline", "reputation"}
    reference = "https://github.com/drb-ra/C2IntelFeeds"
    notice = (
        "Terms 'unknown' (C2IntelFeeds: no licence; ThreatView: site terms not recorded; ViriBack: no terms, A1 BR16): disabled "
        "in every licence profile until legal records a class. Panel and C2 URLs are never visited."
    )
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (SRC_C2INTEL, SRC_THREATVIEW, SRC_VIRIBACK)
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.5
    max_pivots = 30
    default_enabled = False
    feed_module = UNREVIEWED
    finding_title = "Listed in unreviewed offline feeds"
