"""Downloadable IP/ASN/certificate blocklists matched locally (P149).

Batch p1-G02-2, proposal P149 ``ip_blocklists``. Feeds (one registry source and one dataset each):
Spamhaus DROP v4/v6 and ASN-DROP, abuse.ch Feodo Tracker and SSLBL certificates, IPsum, FireHOL
level1, blocklist.de, CINS Army, ET compromised IPs, GreenSnow, Binary Defense Artillery, DataPlane
sshclient and VoIPBL. Final conditions implemented here:

* c1/c2 - per-feed terms in the provider registry and an enable flag per feed (setting
  ``ip_blocklists_disabled_feeds``). Open feeds run under the corporate profile; blocklist.de,
  CINS, ET, GreenSnow, DataPlane, VoIPBL and the FireHOL level1 aggregate are noncommercial: the
  policy gate leaves them out of ``ctx.allowed_sources`` until licence-cleared and this module
  queries only the allowed feeds. Hits from restricted feeds carry ``restricted: true`` so exports
  drop their provenance (P303).
* c3 - the core dataset manager does the downloads (conditional GET, per-feed TTL: Feodo 15 min,
  Spamhaus DROP 1 h, others 6-24 h); each feed has a validator, so a challenge page, an empty,
  truncated or collapsed file never replaces a good copy; every hit carries provenance (feed,
  fetched_at, dataset SHA-256); a feed older than 3x its TTL is reported 'stale'.
* c4 - every IP/CIDR feed loads into the shared range index (``IntervalIndex``, P034 semantics);
  bogon/RFC 1918 and other special-purpose entries are dropped at load and never reported.
  Spamhaus NDJSON is parsed line by line (last line = metadata); SSLBL is the certificate SHA1
  CSV (the JA3 list and the SSLBL IP list are retired and not used; EDROP is merged into DROP).
* c5/c6 - feeds declare their upstream families (registry ``upstream_family``/``embeds``): an
  aggregate (FireHOL level1, IPsum) adds a vote only when none of the families it embeds already
  voted. Fidelity: Feodo, SSLBL, Spamhaus DROP = HIGH; ET compromised, CINS = MEDIUM; blocklist.de,
  GreenSnow, FireHOL L1, IPsum count < 3, Binary Defense, DataPlane, VoIPBL = LOW (IPsum >= 3 =
  MEDIUM); >= 2 independent families raise one level, capped at HIGH (CR27). Warninglists apply
  before scoring (confidence POSSIBLE).
* c7 - hits on CDN/shared-edge addresses (P034 noise kinds) are capped at LOW 'shared/reassignable
  IP'; IaaS compute keeps its severity with a verdict lifetime of 14 days.
* c8 - every hit shows the feed name and listing date / feed age; offline Feodo C2s are
  'historical'. Matching is local (disclosure 'none', allowed at TLP:RED); attribution strings are
  carried on every hit and in the notices.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core import noise
from v3lum.core import providers as _providers
from v3lum.core.datasets import DataStore, DatasetError, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.ip_network.ip_offline_db import (
    DatasetMemo,
    IntervalIndex,
    age_text,
    dataset_failure,
    ip_int,
    iso_z,
    parse_ts,
    special_purpose,
)

SEVERITIES = ("info", "low", "medium", "high")
_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SBL_RE = re.compile(r"^SBL\d+$")
SPAMHAUS_ATTR = "Spamhaus DROP lists (c) The Spamhaus Project SLU - https://www.spamhaus.org/drop/terms/"
ABUSECH_ATTR = "abuse.ch Feodo Tracker / SSL Blacklist (CC0) - https://abuse.ch/"
#: Noise kinds of shared edges (CDN, SaaS fronts, shared hosting): reputation capped at LOW (P034).
SHARED_KINDS = frozenset({"cdn", "saas", "hosting"})
#: Noise kinds of IaaS compute: severity kept, verdict lifetime 14 days (P034).
IAAS_KINDS = frozenset({"cloud"})
IAAS_VERDICT_DAYS = 14
#: A previous copy is kept when a download has fewer than this share of its entries (collapse).
SHRINK_RATIO = 0.2

# feed id -> spec. 'versions': address families a feed lists (no download for the others).
FEEDS: dict[str, dict[str, Any]] = {
    "spamhaus_drop_v4": {"name": "Spamhaus DROP (IPv4)", "source": "spamhaus.drop_v4", "url": "https://www.spamhaus.org/drop/drop_v4.json",
                         "fmt": "spamhaus_ndjson", "ttl": 3600, "fidelity": "high", "kind": "net", "versions": {4}, "min_entries": 100,
                         "expect": "lines", "attribution": SPAMHAUS_ATTR, "tags": ("malicious", "hijacked_netblock")},
    "spamhaus_drop_v6": {"name": "Spamhaus DROP (IPv6)", "source": "spamhaus.drop_v6", "url": "https://www.spamhaus.org/drop/drop_v6.json",
                         "fmt": "spamhaus_ndjson", "ttl": 3600, "fidelity": "high", "kind": "net", "versions": {6}, "min_entries": 10,
                         "expect": "lines", "attribution": SPAMHAUS_ATTR, "tags": ("malicious", "hijacked_netblock")},
    "spamhaus_asndrop": {"name": "Spamhaus ASN-DROP", "source": "spamhaus.asndrop", "url": "https://www.spamhaus.org/drop/asndrop.json",
                         "fmt": "spamhaus_asndrop", "ttl": 86400, "fidelity": "high", "kind": "asn", "versions": set(), "min_entries": 50,
                         "expect": "lines", "attribution": SPAMHAUS_ATTR, "tags": ("malicious", "hijacked_netblock")},
    "feodo": {"name": "abuse.ch Feodo Tracker (botnet C2)", "source": "abusech.feodotracker", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
              "fmt": "feodo_json", "ttl": 900, "fidelity": "high", "kind": "net", "versions": {4}, "min_entries": 0, "may_be_empty": True,
              "expect": "json", "attribution": ABUSECH_ATTR, "tags": ("malicious", "c2", "botnet")},
    "sslbl": {"name": "abuse.ch SSL Blacklist (certificates)", "source": "abusech.sslbl", "url": "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
              "fmt": "sslbl_csv", "ttl": 86400, "fidelity": "high", "kind": "sha1", "versions": set(), "min_entries": 10,
              "expect": "lines", "attribution": ABUSECH_ATTR, "tags": ("malicious", "c2")},
    "ipsum": {"name": "IPsum", "source": "github.ip_blocklists_ipsum", "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
              "fmt": "ipsum", "ttl": 86400, "fidelity": "by_count", "kind": "net", "versions": {4}, "min_entries": 1000,
              "expect": "lines", "attribution": "IPsum by Miroslav Stampar (https://github.com/stamparm/ipsum, Unlicense)", "tags": ("suspicious",)},
    "firehol_level1": {"name": "FireHOL level1", "source": "firehol.level1", "url": "https://iplists.firehol.org/files/firehol_level1.netset",
                       "fmt": "netset", "ttl": 86400, "fidelity": "low", "kind": "net", "versions": {4}, "min_entries": 1000,
                       "expect": "lines", "attribution": "FireHOL blocklist-ipsets (https://iplists.firehol.org/; each list keeps its own licence)", "tags": ("suspicious",)},
    "blocklist_de": {"name": "blocklist.de (all)", "source": "blocklist_de.all", "url": "https://lists.blocklist.de/lists/all.txt",
                     "fmt": "plain", "ttl": 21600, "fidelity": "low", "kind": "net", "versions": {4, 6}, "min_entries": 1000,
                     "expect": "lines", "attribution": "www.blocklist.de", "tags": ("scanner", "suspicious")},
    "cins": {"name": "CINS Army", "source": "cinsscore.badguys", "url": "https://cinsscore.com/list/ci-badguys.txt",
             "fmt": "plain", "ttl": 86400, "fidelity": "medium", "kind": "net", "versions": {4}, "min_entries": 1000,
             "expect": "lines", "attribution": "CINS Army list (Sentinel IPS, cinsscore.com)", "tags": ("suspicious",)},
    "et_compromised": {"name": "Emerging Threats compromised IPs", "source": "emergingthreats.compromised",
                       "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "fmt": "plain", "ttl": 86400,
                       "fidelity": "medium", "kind": "net", "versions": {4}, "min_entries": 50, "expect": "lines",
                       "attribution": "Proofpoint Emerging Threats Open (rules.emergingthreats.net)", "tags": ("suspicious",)},
    "greensnow": {"name": "GreenSnow", "source": "greensnow.list", "url": "https://blocklist.greensnow.co/greensnow.txt",
                  "fmt": "plain", "ttl": 86400, "fidelity": "low", "kind": "net", "versions": {4}, "min_entries": 100,
                  "expect": "lines", "attribution": "GreenSnow (greensnow.co)", "tags": ("scanner", "suspicious")},
    "binarydefense": {"name": "Binary Defense Artillery banlist", "source": "binarydefense.banlist", "url": "https://binarydefense.com/banlist.txt",
                      "fmt": "plain", "ttl": 86400, "fidelity": "low", "kind": "net", "versions": {4}, "min_entries": 50,
                      "expect": "lines", "attribution": "Binary Defense Systems Artillery banlist (public use only, no resale)", "tags": ("suspicious",)},
    "dataplane_sshclient": {"name": "DataPlane sshclient", "source": "dataplane.sshclient", "url": "https://dataplane.org/sshclient.txt",
                            "fmt": "dataplane", "ttl": 21600, "fidelity": "low", "kind": "net", "versions": {4}, "min_entries": 100,
                            "expect": "lines", "attribution": "Dataplane.org", "tags": ("scanner", "suspicious")},
    "voipbl": {"name": "VoIPBL", "source": "voipbl.update", "url": "https://voipbl.org/update/", "fmt": "voipbl", "ttl": 21600,
               "fidelity": "low", "kind": "net", "versions": {4}, "min_entries": 1000, "expect": "lines",
               "attribution": "VoIPBL.org", "tags": ("spam", "suspicious")},
}
SOURCES = tuple(spec["source"] for spec in FEEDS.values())
RETIRED = {
    "spamhaus_edrop": "Spamhaus EDROP was merged into DROP (edrop.txt is an empty stub)",
    "sslbl_ips": "abuse.ch SSLBL IP blacklist deprecated on 2025-01-03",
    "sslbl_ja3": "abuse.ch SSLBL JA3 list retired (JA3 obsolete)",
}


def dataset_name(feed_id: str) -> str:
    ext = {"spamhaus_ndjson": "json", "spamhaus_asndrop": "json", "feodo_json": "json", "sslbl_csv": "csv"}.get(FEEDS[feed_id]["fmt"], "txt")
    return f"ip_blocklists.{feed_id}.{ext}"


# ======================================================================================
# parsers (untrusted data: every line is checked; special-purpose entries are dropped)
# ======================================================================================


class Feed:
    """A parsed feed: range index (IP/CIDR feeds), ASN or SHA1 tables, header facts, counters."""

    def __init__(self, feed_id: str) -> None:
        self.feed_id = feed_id
        self.index = IntervalIndex()
        self.asns: dict[int, dict[str, Any]] = {}
        self.sha1: dict[str, dict[str, Any]] = {}
        self.entries = 0
        self.invalid = 0
        self.dropped_special = 0
        self.dropped_examples: list[str] = []
        self.listed_at = ""
        self.header: dict[str, Any] = {}
        self.problem = ""

    def add_net(self, value: str, payload: Any = None) -> bool:
        try:
            net = ipaddress.ip_network(str(value).strip(), strict=False)
        except ValueError:
            self.invalid += 1
            return False
        label = special_purpose(net)
        if label:
            self.dropped_special += 1
            if len(self.dropped_examples) < 10:
                self.dropped_examples.append(f"{net} ({label})")
            return False
        self.index.add_network(net, payload)
        self.entries += 1
        return True


def _text(data: bytes | str) -> str:
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    return text[1:] if text.startswith("﻿") else text


def _asn_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str):
        text = value.strip().upper().removeprefix("AS")
        return int(text) if text.isdigit() and int(text) > 0 else None
    return None


def parse_spamhaus(text: str, feed_id: str, kind: str) -> Feed:
    """Spamhaus drop_v4/drop_v6/asndrop NDJSON: one object per line, the LAST line is metadata
    {type, timestamp, size, records, copyright, terms}. A missing metadata line or a record-count
    mismatch marks a truncated download."""
    feed = Feed(feed_id)
    meta = None
    bad = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if not isinstance(obj, dict):
            bad += 1
            continue
        if obj.get("type") == "metadata":
            meta = obj
            continue
        if kind == "asn":
            asn = _asn_int(obj.get("asn"))
            if asn is None:
                bad += 1
                continue
            feed.asns[asn] = {"asn": asn, "rir": str(obj.get("rir") or "")[:16], "cc": str(obj.get("cc") or "")[:2].upper(),
                              "as_name": str(obj.get("asname") or "")[:120]}
            feed.entries += 1
        else:
            sbl = obj.get("sblid") if isinstance(obj.get("sblid"), str) and _SBL_RE.match(obj.get("sblid")) else ""
            feed.add_net(obj.get("cidr") if isinstance(obj.get("cidr"), str) else "", {"sblid": sbl})
    feed.invalid += bad
    if meta is not None:
        feed.header = {k: meta.get(k) for k in ("timestamp", "records", "size", "copyright", "terms")}
        feed.listed_at = iso_z(meta.get("timestamp")) or ""
    parsed = feed.entries + feed.dropped_special
    if meta is None:
        feed.problem = "no Spamhaus metadata line (truncated download?)"
    elif isinstance(meta.get("records"), int) and meta["records"] != parsed:
        feed.problem = f"record count mismatch (metadata {meta['records']}, parsed {parsed})"
    elif bad:
        feed.problem = f"{bad} malformed NDJSON lines"
    return feed


def parse_plain(text: str, feed_id: str) -> Feed:
    """One IP/CIDR per line; '#'/';' comment lines; inline comments; CRLF tolerated."""
    feed = Feed(feed_id)
    comments: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith(("#", ";")):
            if len(comments) < 80:
                comments.append(line)
            continue
        token = re.split(r"[\s;#,]", line, maxsplit=1)[0]
        feed.add_net(token)
    feed.header["comments"] = comments
    if feed.invalid > max(10, feed.entries // 100):
        feed.problem = f"{feed.invalid} lines are not IPs/CIDRs"
    return feed


def _header(comments: list[str], pattern: str) -> str:
    rx = re.compile(pattern, re.I)
    for comment in comments:
        m = rx.search(comment)
        if m:
            return m.group(1).strip()
    return ""


def parse_netset(text: str, feed_id: str) -> Feed:
    """FireHOL netset: header names the embedded lists and dates; bogons are dropped at load."""
    feed = parse_plain(text, feed_id)
    comments = feed.header.get("comments", [])
    joined = " ".join(c.lstrip("#").strip() for c in comments)
    m = re.search(r"\(includes:\s*([^)]*)\)", joined)
    feed.header.update({"includes": m.group(1).split() if m else [], "this_file_date": _header(comments, r"This File Date\s*:\s*(.+)$")})
    feed.listed_at = iso_z(feed.header["this_file_date"]) or ""
    return feed


def parse_ipsum(text: str, feed_id: str) -> Feed:
    """IPsum 'IP<TAB>count' (count = number of public lists); header '# Last update: <date>'."""
    feed = Feed(feed_id)
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            if line.lower().startswith("# last update:"):
                feed.listed_at = iso_z(line.split(":", 1)[1].strip()) or ""
            continue
        parts = line.split()
        count = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1
        feed.add_net(parts[0], count)
    if feed.invalid > max(10, feed.entries // 100):
        feed.problem = f"{feed.invalid} malformed IPsum lines"
    return feed


def parse_feodo(text: str, feed_id: str) -> Feed:
    """Feodo Tracker ipblocklist.json: C2 entries (ip, port, status, malware, first_seen,
    last_online...). An empty array is a valid list (it shrinks after takedowns)."""
    feed = Feed(feed_id)
    try:
        data = json.loads(text)
    except ValueError:
        feed.problem = "Feodo Tracker answer is not JSON"
        return feed
    if not isinstance(data, list):
        feed.problem = "Feodo Tracker JSON is not an array"
        return feed
    for row in data:
        if not isinstance(row, dict) or not isinstance(row.get("ip_address"), str):
            feed.invalid += 1
            continue
        port = row.get("port") if isinstance(row.get("port"), int) and not isinstance(row.get("port"), bool) else None
        payload = {
            "port": port,
            "status": str(row.get("status") or "")[:16],
            "malware": str(row.get("malware") or "")[:60],
            "first_seen": str(row.get("first_seen") or "")[:32],
            "last_online": str(row.get("last_online") or "")[:32],
            "hostname": str(row.get("hostname") or "")[:253] if isinstance(row.get("hostname"), str) else "",
        }
        feed.add_net(row["ip_address"], payload)
    return feed


def parse_sslbl(text: str, feed_id: str) -> Feed:
    """SSLBL sslblacklist.csv 'Listingdate,SHA1,Listingreason' (malware C2 certificate SHA1)."""
    feed = Feed(feed_id)
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            low = line.strip("#").strip().lower()
            if low.startswith("last updated:"):
                feed.listed_at = iso_z(line.strip("# ").split(":", 1)[1].strip()) or ""
            continue
        parts = [p.strip() for p in line.split(",", 2)]
        if len(parts) != 3 or not _SHA1_RE.match(parts[1].lower()) or parse_ts(parts[0]) is None:
            feed.invalid += 1
            continue
        reason = parts[2][:80]
        feed.sha1[parts[1].lower()] = {"listed_at": parts[0], "reason": reason, "malware": reason.removesuffix(" C&C").strip()}
        feed.entries += 1
    if feed.invalid > max(10, feed.entries // 100):
        feed.problem = f"{feed.invalid} malformed SSLBL rows"
    return feed


def parse_dataplane(text: str, feed_id: str) -> Feed:
    """DataPlane 'ASN | ASname | ipaddr | lastseen | category' with '#' comments (informational)."""
    feed = Feed(feed_id)
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            m = re.match(r"#\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2})\s*-\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2})", line)
            if m:
                feed.header["window"] = [m.group(1), m.group(2)]
                feed.listed_at = iso_z(m.group(2) + ":00") or ""
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 5:
            feed.invalid += 1
            continue
        feed.add_net(parts[2], {"last_seen": parts[3][:32], "category": parts[4][:32]})
    if feed.invalid > max(10, feed.entries // 100):
        feed.problem = f"{feed.invalid} malformed DataPlane rows"
    return feed


def parse_voipbl(text: str, feed_id: str) -> Feed:
    """VoIPBL update (served as text/html): '# TOTAL NETBLOCK: N' then CIDRs."""
    feed = parse_plain(text, feed_id)
    m = re.search(r"#\s*TOTAL NETBLOCK:\s*(\d+)", text)
    feed.header["declared_total"] = int(m.group(1)) if m else None
    declared = feed.header["declared_total"]
    if not feed.problem and declared and feed.entries + feed.dropped_special + feed.invalid < declared * 0.9:
        feed.problem = f"{feed.entries} entries but the header declares {declared} (truncated?)"
    return feed


_PARSERS = {
    "spamhaus_ndjson": lambda text, fid: parse_spamhaus(text, fid, "net"),
    "spamhaus_asndrop": lambda text, fid: parse_spamhaus(text, fid, "asn"),
    "feodo_json": parse_feodo,
    "sslbl_csv": parse_sslbl,
    "ipsum": parse_ipsum,
    "netset": parse_netset,
    "plain": parse_plain,
    "dataplane": parse_dataplane,
    "voipbl": parse_voipbl,
}


def parse_feed(feed_id: str, data: bytes | str) -> Feed:
    feed = _PARSERS[FEEDS[feed_id]["fmt"]](_text(data), feed_id)
    feed.index.freeze()
    return feed


def feed_problem(feed_id: str, feed: Feed, previous_entries: int | None = None) -> str:
    """Why a download must not replace the good copy ('' = accept): parse problem, empty or too
    few entries, or a collapse to less than SHRINK_RATIO of the previous copy."""
    spec = FEEDS[feed_id]
    if feed.problem:
        return feed.problem
    count = feed.entries
    if count == 0 and not spec.get("may_be_empty"):
        return "no entries"
    if count < spec["min_entries"] and not spec.get("may_be_empty"):
        return f"too few entries ({count} < {spec['min_entries']})"
    if previous_entries and count < previous_entries * SHRINK_RATIO:
        return f"entry count fell from {previous_entries} to {count}"
    return ""


#: Terms class per feed source when the provider registry cannot be read (the registry is authoritative).
_TERMS_FALLBACK = {
    "firehol": "noncommercial", "blocklist_de": "noncommercial", "cinsscore": "noncommercial", "emergingthreats": "noncommercial",
    "greensnow": "noncommercial", "dataplane": "noncommercial", "voipbl": "noncommercial",
}


def source_terms(source_id: str) -> str:
    """Terms class of a feed source from the provider registry (P377 per-source terms)."""
    try:
        src = _providers.registry().source(source_id)
    except Exception:  # noqa: BLE001 - a registry problem must not break registration
        src = None
    cls = getattr(getattr(src, "terms", None), "class_", None)
    return str(cls) if cls else _TERMS_FALLBACK.get(source_id.split(".", 1)[0], "open")


def _validator(feed_id: str) -> Any:
    def check(path: Path) -> bool:
        feed = parse_feed(feed_id, path.read_bytes())
        previous = None
        current = DataStore(None).path(dataset_name(feed_id))
        if current.is_file():
            try:
                previous = parse_feed(feed_id, current.read_bytes()).entries
            except (OSError, ValueError):
                previous = None
        problem = feed_problem(feed_id, feed, previous)
        if problem:
            raise ValueError(f"{FEEDS[feed_id]['name']}: {problem} (the previous copy is kept)")
        return True

    return check


for _fid, _spec in FEEDS.items():
    register_dataset(
        dataset_name(_fid),
        _spec["url"],
        ttl=_spec["ttl"],
        description=f"{_spec['name']} (ip_blocklists feed, matched locally)",
        licence={
            "spamhaus.drop_v4": "LicenseRef-Spamhaus-DROP-terms", "spamhaus.drop_v6": "LicenseRef-Spamhaus-DROP-terms",
            "spamhaus.asndrop": "LicenseRef-Spamhaus-DROP-terms", "abusech.feodotracker": "CC0-1.0", "abusech.sslbl": "CC0-1.0",
            "github.ip_blocklists_ipsum": "Unlicense", "firehol.level1": "LicenseRef-FireHOL-aggregate-NC",
            "blocklist_de.all": "LicenseRef-blocklist.de-NC", "cinsscore.badguys": "LicenseRef-CINS-Army-NC",
            "emergingthreats.compromised": "LicenseRef-ET-Open-NC", "greensnow.list": "LicenseRef-GreenSnow-NC",
            "binarydefense.banlist": "LicenseRef-BinaryDefense-public-use", "dataplane.sshclient": "LicenseRef-DataPlane-NC",
            "voipbl.update": "LicenseRef-VoIPBL-NC",
        }[_spec["source"]],
        terms_class=source_terms(_spec["source"]),
        attribution=_spec["attribution"],
        provider=_spec["source"].split(".")[0],
        source=_spec["source"],
        validate=_validator(_fid),
        min_bytes=1 if _spec.get("may_be_empty") else 16,
        expect=_spec["expect"],
        max_bytes=4 * 1024 * 1024 + 512 * 1024,
        large=False,
    )

_MEMO = DatasetMemo()


# ======================================================================================
# scoring (P149 c5-c7, P171 / CR27)
# ======================================================================================


def _source_family(source_id: str) -> tuple[str, tuple[str, ...]]:
    try:
        src = _providers.registry().source(source_id)
    except Exception:  # noqa: BLE001 - a registry problem must not break matching
        src = None
    family = str(getattr(src, "upstream_family", "") or source_id.split(".")[0])
    embeds = tuple(getattr(src, "embeds", ()) or ())
    return family, embeds


def hit_fidelity(hit: dict[str, Any]) -> str:
    fidelity = FEEDS[hit["feed"]]["fidelity"]
    if fidelity == "by_count":
        return "medium" if int(hit.get("details", {}).get("count") or 0) >= 3 else "low"
    return fidelity


def score_hits(hits: list[dict[str, Any]], *, shared: bool = False, iaas: bool = False) -> dict[str, Any]:
    """Severity of the hits on ONE entity. Families are counted, not feeds: an aggregate adds a vote
    only when none of the families it embeds voted and it does not overlap a counted aggregate;
    >= 2 independent families raise one level, capped at HIGH; shared edges are capped at LOW."""
    direct: dict[str, list[str]] = {}
    aggregates: list[tuple[str, str, tuple[str, ...]]] = []
    best = 0
    for hit in hits:
        best = max(best, SEVERITIES.index(hit_fidelity(hit)))
        family, embeds = hit["family"], tuple(hit.get("embeds") or ())
        if embeds:
            aggregates.append((hit["feed"], family, embeds))
        else:
            direct.setdefault(family, []).append(hit["feed"])
    families = sorted(direct)
    counted: list[tuple[str, ...]] = []
    deduplicated = []
    for feed_id, family, embeds in sorted(set(aggregates)):
        overlap = set(embeds) & set(direct)
        if overlap:
            deduplicated.append({"feed": feed_id, "why": f"embeds {', '.join(sorted(overlap))} (already counted)"})
            continue
        if any(set(embeds) & set(other) for other in counted):
            deduplicated.append({"feed": feed_id, "why": "overlaps another counted aggregate"})
            continue
        counted.append(embeds)
        families.append(family)
    votes = len(families)
    severity = best
    notes = []
    if votes >= 2:
        severity = min(best + 1, SEVERITIES.index("high"))
        notes.append(f"{votes} independent families: raised one level (capped at HIGH, CR27)")
    if shared:
        severity = min(severity, SEVERITIES.index("low"))
        notes.append("shared/reassignable IP (CDN or shared edge): capped at LOW")
    return {"severity": SEVERITIES[severity], "best": SEVERITIES[best], "votes": votes, "families": families,
            "deduplicated": deduplicated, "notes": notes, "verdict_lifetime_days": IAAS_VERDICT_DAYS if iaas and not shared else None}


# ======================================================================================
# the module
# ======================================================================================


@register
class IpBlocklists(Module):
    name = "ip_blocklists"
    title = "IP blocklists (local match)"
    description = (
        "Downloadable IP/ASN/certificate blocklists matched locally (Spamhaus DROP/ASN-DROP, abuse.ch Feodo and "
        "SSLBL, IPsum, FireHOL level1, blocklist.de, CINS, ET, GreenSnow, Binary Defense, DataPlane, VoIPBL); "
        "per-feed terms, provenance and family-based consensus."
    )
    category = "threat_intel_ioc"
    accepts = {T.IPV4, T.IPV6, T.CIDR, T.ASN, T.CERT_FP}
    produces = {T.CIDR, T.DOMAIN}
    terms = "noncommercial"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = SOURCES
    reference = "https://www.spamhaus.org/drop/"
    notice = (
        "Feeds are matched locally (nothing is sent). blocklist.de, CINS, ET compromised IPs, GreenSnow, DataPlane, "
        "VoIPBL and FireHOL level1 are noncommercial: off under the corporate profile until licence-cleared; their "
        "hits are never redistributed outside the team. Spamhaus DROP, abuse.ch Feodo/SSLBL, IPsum and Binary Defense "
        "run under corporate."
    )
    tags = {"offline", "free", "reputation"}
    max_pivots = 20
    timeout = 120.0
    settings = {
        "ip_blocklists_disabled_feeds": SettingSpec(
            [], "ip_blocklists feed ids to switch off (e.g. voipbl, dataplane_sshclient); see FEEDS in the module"
        ),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type in (T.IPV4, T.IPV6, T.CIDR):
            return special_purpose(entity.value) is None
        if entity.type is T.CERT_FP:
            return bool(_SHA1_RE.match(str(entity.value).lower()))
        return True

    # ------------------------------------------------------------------ feed access
    def _feeds_for(self, entity: Entity) -> list[str]:
        if entity.type is T.ASN:
            return [f for f, s in FEEDS.items() if s["kind"] == "asn"]
        if entity.type is T.CERT_FP:
            return [f for f, s in FEEDS.items() if s["kind"] == "sha1"]
        version = 6 if ":" in entity.value else 4
        return [f for f, s in FEEDS.items() if s["kind"] == "net" and version in s["versions"]]

    def _load(self, ctx: Any, feed_id: str) -> tuple[Feed, Any]:
        name = dataset_name(feed_id)
        path = Path(ctx.data.fetch(name))
        info = ctx.data.info(name)
        feed = _MEMO.get(name, info.sha256, lambda: parse_feed(feed_id, path.read_bytes()))
        return feed, info

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        disabled = {str(f).strip() for f in (ctx.setting("ip_blocklists_disabled_feeds", []) or []) if str(f).strip()}
        now = ctx.now()
        hits: list[dict[str, Any]] = []
        checked: list[str] = []
        failures: list[tuple[Status, str, str]] = []
        inside: dict[str, int] = {}
        for feed_id in self._feeds_for(entity):
            spec = FEEDS[feed_id]
            if spec["source"] not in ctx.allowed_sources:
                continue  # licence profile: the engine reports it (coverage row 'licence')
            if feed_id in disabled:
                res.source_status(spec["source"], Status.SKIPPED, reason_code="config", reason=f"{spec['name']}: disabled by setting ip_blocklists_disabled_feeds")
                continue
            try:
                feed, info = self._load(ctx, feed_id)
            except DatasetError as exc:
                status, code = dataset_failure(exc)
                reason = f"{spec['name']}: {exc} (could not verify)"
                res.source_status(spec["source"], status, reason_code=code, reason=reason)
                failures.append((status, code, reason))
                continue
            except (OSError, ValueError) as exc:
                reason = f"{spec['name']}: unreadable local copy ({type(exc).__name__}) (could not verify)"
                res.source_status(spec["source"], Status.ERROR, reason_code="error", reason=reason)
                failures.append((Status.ERROR, "error", reason))
                continue
            checked.append(feed_id)
            fetched = parse_ts(info.fetched_at)
            age = (now - fetched).total_seconds() if fetched else None
            stale = age is None or age > 3 * spec["ttl"]
            if stale:
                res.source_status(spec["source"], Status.OK, reason=f"{spec['name']}: stale copy ({age_text(age)} old, more than 3x its TTL)")
            for match in self._match(entity, feed):
                hits.append(self._hit(feed_id, feed, info, match, age, stale))
            if entity.type is T.CIDR:
                count = self._inside(entity, feed)
                if count:
                    inside[spec["name"]] = count
        if not checked:
            if failures:
                status, code, reason = failures[0]
                more = f" (+{len(failures) - 1} more feeds)" if len(failures) > 1 else ""
                return res.mark(status, f"{reason}{more}", reason_code=code)
            if disabled:
                return res.mark(Status.SKIPPED, "every applicable feed is disabled by setting ip_blocklists_disabled_feeds", reason_code="config")
            return res.mark(Status.SKIPPED, "no allowed feed applies to this entity", reason_code="not_applicable")
        res.raw = {"checked": checked, "hits": hits, "inside": inside}
        if inside:
            res.finding(
                "Listed addresses inside the range",
                "info",
                "Blocklisted entries inside this range: " + ", ".join(f"{n}: {c}" for n, c in sorted(inside.items())),
                data={"inside": inside},
                source=FEEDS[checked[0]]["source"],
            )
        if not hits:
            return res if inside else res.mark("empty")
        self._report(entity, res, hits)
        return res

    def _match(self, entity: Entity, feed: Feed) -> list[dict[str, Any]]:
        if entity.type is T.ASN:
            asn = _asn_int(entity.value)
            row = feed.asns.get(asn) if asn else None
            return [{"matched": f"AS{asn}", "details": row}] if row else []
        if entity.type is T.CERT_FP:
            row = feed.sha1.get(str(entity.value).lower().replace(":", ""))
            return [{"matched": str(entity.value).lower(), "details": row}] if row else []
        if entity.type is T.CIDR:
            net = ipaddress.ip_network(entity.value, strict=False)
            span = (int(net.network_address), int(net.broadcast_address))
            return [self._net_match(net.version, start, end, payload) for payload, start, end in self._containing(feed, net.version, span)]
        parsed = ip_int(entity.value)
        if parsed is None:
            return []
        version = parsed[0]
        return [self._net_match(version, s, e, p) for s, e, p in feed.index.lookup_spans(parsed)]

    @staticmethod
    def _containing(feed: Feed, version: int, span: tuple[int, int]) -> list[tuple[Any, int, int]]:
        found = []
        for start, end, payload in feed.index.lookup_spans((version, span[0])):
            if end >= span[1]:
                found.append((payload, start, end))
        return found

    @staticmethod
    def _inside(entity: Entity, feed: Feed) -> int:
        """Entries lying inside the CIDR (the CIDR itself, when listed, is a containing hit)."""
        net = ipaddress.ip_network(entity.value, strict=False)
        start, end = int(net.network_address), int(net.broadcast_address)
        exact = any(s == start and e == end for s, e, _p in feed.index.lookup_spans((net.version, start)))
        return len(feed.index.within(net.version, start, end)) - (1 if exact else 0)

    @staticmethod
    def _net_match(version: int, start: int, end: int, payload: Any) -> dict[str, Any]:
        cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
        nets = list(ipaddress.summarize_address_range(cls(start), cls(end)))
        matched = str(nets[0]) if len(nets) == 1 else f"{cls(start)}-{cls(end)}"
        if len(nets) == 1 and nets[0].num_addresses == 1:
            matched = str(nets[0].network_address)
        details: dict[str, Any]
        if isinstance(payload, dict):
            details = dict(payload)
        elif isinstance(payload, int):
            details = {"count": payload}
        else:
            details = {}
        return {"matched": matched, "details": details}

    def _hit(self, feed_id: str, feed: Feed, info: Any, match: dict[str, Any], age: float | None, stale: bool) -> dict[str, Any]:
        spec = FEEDS[feed_id]
        family, embeds = _source_family(spec["source"])
        details = {k: v for k, v in (match.get("details") or {}).items() if v not in (None, "")}
        listed_at = str(details.get("listed_at") or details.get("first_seen") or details.get("last_seen") or feed.listed_at or "")
        currency = "historical" if feed_id == "feodo" and str(details.get("status")).lower() == "offline" else "current"
        terms = source_terms(spec["source"])
        return {
            "feed": feed_id,
            "name": spec["name"],
            "source": spec["source"],
            "family": family,
            "embeds": list(embeds),
            "matched": match["matched"],
            "details": details,
            "listed_at": listed_at,
            "feed_age": age_text(age),
            "currency": currency,
            "stale": stale,
            "fidelity": "",
            "provenance": {"feed": feed_id, "fetched_at": info.fetched_at, "sha256": info.sha256},
            "attribution": spec["attribution"],
            "terms": terms,
            "restricted": terms != "open",
        }

    def _report(self, entity: Entity, res: ModuleResult, hits: list[dict[str, Any]]) -> None:
        kinds = set(noise.noise_kinds(entity)) if entity.type in (T.IPV4, T.IPV6) else set()
        shared = bool(kinds & SHARED_KINDS)
        iaas = bool(kinds & IAAS_KINDS)
        for hit in hits:
            hit["fidelity"] = hit_fidelity(hit)
        score = score_hits(hits, shared=shared, iaas=iaas)
        lists = noise.warninglists(entity) if entity.type in (T.IPV4, T.IPV6, T.CIDR) else []
        hits_sorted = sorted(hits, key=lambda h: -SEVERITIES.index(h["fidelity"]))
        best = hits_sorted[0]
        names = sorted({h["name"] for h in hits})
        res.attr("blocklists", names)
        res.attr("blocklist_hits", hits_sorted)
        res.attr("blocklist_families", score["families"])
        ipsum = [h for h in hits if h["feed"] == "ipsum"]
        if ipsum:
            res.attr("ipsum_count", int(ipsum[0]["details"].get("count") or 0))
        malware = sorted({str(h["details"].get("malware")) for h in hits if h["details"].get("malware")})
        res.attr("malware_family", malware)
        if shared:
            res.attr("shared_ip", True)
        if score["verdict_lifetime_days"]:
            res.attr("verdict_lifetime_days", score["verdict_lifetime_days"])
        if score["best"] == "high" and not shared:
            res.attr("malicious", True)
        elif score["best"] != "high":
            res.attr("suspicious", True)
        tags = {"blocklisted"}
        for hit in hits:
            tags.update(FEEDS[hit["feed"]]["tags"])
        if score["best"] != "high":
            tags -= {"malicious", "c2", "botnet"}
        if score["best"] == "low":
            tags.add("weak_signal")
        confidence = "probable" if score["best"] in ("high", "medium") else "possible"
        criterion = (
            f"listed by {len(names)} feed(s) from {score['votes']} independent famil{'y' if score['votes'] == 1 else 'ies'} "
            f"({', '.join(score['families'])}); best feed fidelity {score['best']}"
        )
        if lists:
            confidence = "possible"
            criterion = f"POSSIBLE - on warninglist {', '.join(lists)} | {criterion}"
        dates = [parse_ts(h["listed_at"]) for h in hits if h["listed_at"]]
        dates = [d for d in dates if d is not None]
        lines = [
            f"{h['name']}: {h['matched']} ({'listed ' + h['listed_at'] if h['listed_at'] else 'listing date not published'}; feed age "
            f"{h['feed_age']}{'; STALE copy' if h['stale'] else ''}{'; historical (offline C2)' if h['currency'] == 'historical' else ''})"
            for h in hits_sorted
        ]
        if entity.type is T.ASN:
            title = "AS listed on Spamhaus ASN-DROP"
        elif entity.type is T.CERT_FP:
            title = "Certificate on the abuse.ch SSL Blacklist"
        else:
            title = "Listed on IP blocklists"
        res.finding(
            title,
            score["severity"],
            "; ".join(lines) + (". " + " ".join(score["notes"]) if score["notes"] else ""),
            confidence=confidence,
            criterion=criterion,
            data={"hits": hits_sorted, "families": score["families"], "votes": score["votes"], "deduplicated": score["deduplicated"],
                  "notes": score["notes"], "verdict_lifetime_days": score["verdict_lifetime_days"], "warninglists": lists,
                  "restricted_sources": sorted({h["source"] for h in hits if h["restricted"]})},
            tags=sorted(tags),
            source=best["source"],
            observed_first=min(dates).isoformat() if dates else None,
            observed_last=max(dates).isoformat() if dates else None,
        )
        for hit in hits_sorted:
            sbl = hit["details"].get("sblid")
            if sbl and _SBL_RE.match(sbl):
                res.link(f"Spamhaus {sbl}", f"https://check.spamhaus.org/sbl/query/{sbl}")
            if entity.type in (T.IPV4, T.IPV6) and "/" in hit["matched"]:
                res.pivot(T.CIDR, hit["matched"], "in_network", confidence=0.9, expand=False, note=f"listed netblock ({hit['name']})")
            host = hit["details"].get("hostname")
            if host:
                res.pivot(T.DOMAIN, host, "hosted_domain", confidence=0.5, expand=False, note=f"C2 host name reported by {hit['name']}")

