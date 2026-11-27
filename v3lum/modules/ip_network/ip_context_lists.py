"""ip_context_lists: VPN / datacenter / Private Relay / DynDNS / suspicious-UA context labels (P035).

Batch p2-G02-1, proposal P035 (approved, P2). Offline matching (disclosure 'none'): the value never
leaves the machine; only the core dataset manager downloads the static lists. Final conditions:

* c1 - local matching through the shared IP-range index of P034 (``cloud_ranges.RangeIndex``: sorted
  integer intervals + bisect, IPv4 and IPv6). Every list is a registered dataset with TTL and
  provenance (licence, terms class, attribution, source): X4BNet VPN/datacenter ranges, the mthcht
  ProtonVPN/Mullvad/Surfshark server IPs, mthcht dynamic-DNS domains and suspicious user agents
  (daily), and the 12 MB Apple iCloud Private Relay egress CSV (weekly, ``large``: installed only by
  ``v3lum data update``, never downloaded during a run). A list is parsed once per downloaded
  version (cache keyed by dataset sha256), never per run.
* c2 - a missing list, or a stale copy (a refresh failed or is overdue) that does not match, is
  'not checked' (UNAVAILABLE ``dataset`` for the run and per source), never 'not a VPN/proxy/
  datacenter IP' (rule 5). A positive match on a stale copy is still reported, flagged stale. A
  failed or invalid download never replaces the last good copy: every registration carries a
  validator (HTML/error bodies, entry minimum, invalid-line ratio) on top of the manager's checks.
* c3 - per-list terms are recorded before enabling: X4BNet (README MIT notice + IPLocate CC BY-SA 4.0
  attribution: runtime download only), mthcht awesome-lists (MIT, attribution), Apple Private Relay
  ranges (published by Apple for geolocation/allow-listing: open). Notices:
  ``v3lum/data/notices/ip_context_lists_*.json`` (data/NOTICE and THIRD_PARTY_NOTICES.md, A6).
* c4 - FireHOL proxy ipsets are consumed per upstream (the ipset header names them, see
  :func:`firehol_upstream_plan`), never through the 42 MB aggregate. Each upstream inherits its own
  terms: none is recorded yet (socks_proxy_30d and sslproxies_30d: terms unrecorded; iblocklist_proxies
  and ip2proxy_px1lite: no per-upstream file), so none is wired. The registry source
  ``firehol.proxies`` is noncommercial: under the corporate profile the policy gate keeps it out and
  coverage lists it as licence-blocked; when it is licence-allowed the module reports it
  'not checked' (no upstream wired). The module's terms class is therefore 'noncommercial' (the most
  restrictive declared source) while every other list is open.
* c5 - tags are context only, never verdicts: ``vpn``, ``datacenter``, ``proxy``, ``rmm_tool``,
  ``dynamic_dns``, ``suspicious_user_agent``, ``privacy_relay`` (attribute ``context_tags``); findings
  are INFO and tagged ``context_only``.
* c6 - ``privacy_relay`` (ordinary Safari/iCloud+ users) is never scored as an anonymiser and
  suppresses the VPN/proxy labels of the same range: they move to ``context_matches`` with
  ``suppressed_by='privacy_relay'``, ``is_vpn``/``is_proxy`` stay unset and no finding carries
  ``vpn``/``proxy``/``anonymizer`` tags (CR28 never fires on a relay range).
* c7 - domain lists match on label boundaries (the domain, its PSL registrable domain or a parent
  suffix; never a substring; '*.x' rows match sub-domains only); user-agent lists match exactly
  (rows with glob characters are set aside). FireHOL proxy data, when wired, is never sole evidence
  and no IP is ever tested as an open proxy (nothing here sends traffic anywhere).

Not wired (backlog p2-G02-1): the mthcht RMM list (file path unverified: github.com listings are
refused from the build egress and guessed paths answered 404) and every FireHOL proxy upstream.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NamedTuple

from v3lum.core.datasets import DatasetError, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.core.psl import registrable_domain
from v3lum.modules.ip_network.cloud_ranges import RangeIndex, as_network, is_public_address

# ======================================================================================
# Constants, sources, terms
# ======================================================================================

CONTEXT_TAGS = ("vpn", "datacenter", "proxy", "rmm_tool", "dynamic_dns", "suspicious_user_agent", "privacy_relay")
#: c6: labels whose scoring privacy_relay suppresses for the same range (datacenter is kept: the relay
#: egress ranges sit on CDN networks and the council named VPN/proxy only).
RELAY_SUPPRESSES = frozenset({"vpn", "proxy"})
DAY = 86400
WEEK = 7 * DAY
#: fetch() TTL used for the large Apple list: serve the installed copy, never refresh it mid-run (c1).
NO_REFRESH_TTL = 10 * 365 * DAY
MIN_PREFIXLEN = {4: 8, 6: 19}
MAX_DOMAIN_LABELS = 20
MAX_UA_LEN = 1000
MAX_MATCHES = 20

SRC_X4B = "github.ip_context_lists_x4bnet"
SRC_MTHCHT_VPN = "github.ip_context_lists_mthcht_vpn"
SRC_DYNDNS = "github.ip_context_lists_mthcht_dyndns"
SRC_UA = "github.ip_context_lists_mthcht_ua"
SRC_RELAY = "icloud.private_relay"
SRC_FIREHOL = "firehol.proxies"
SOURCES = (SRC_X4B, SRC_MTHCHT_VPN, SRC_DYNDNS, SRC_UA, SRC_RELAY, SRC_FIREHOL)

X4B_BASE = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output"
MTHCHT_BASE = "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists"
RELAY_URL = "https://mask-api.icloud.com/egress-ip-ranges.csv"
FIREHOL_BASE = "https://iplists.firehol.org/files"

X4B_LICENCE = (
    "MIT (X4BNet lists_vpn README: generated lists, scripts and curated inputs); upstream IPLocate IP-to-ASN data "
    "CC BY-SA 4.0 - runtime download only, never bundled (A6)"
)
X4B_ATTRIBUTION = (
    "VPN and datacenter ranges from X4BNet lists_vpn (https://github.com/X4BNet/lists_vpn), MIT License, "
    "Copyright (c) 2026 X4B (Mathew Heard); IP address data powered by IPLocate.io (CC BY-SA 4.0)"
)
MTHCHT_LICENCE = "MIT (mthcht/awesome-lists LICENSE) - runtime download only"
MTHCHT_ATTRIBUTION = "mthcht/awesome-lists (https://github.com/mthcht/awesome-lists), MIT License, Copyright (c) 2024 @mthcht thunting.io"
RELAY_LICENCE = "published by Apple for geolocation/allow-listing (no licence text; runtime download only, never bundled)"
RELAY_ATTRIBUTION = "iCloud Private Relay egress IP ranges published by Apple Inc. (https://mask-api.icloud.com/egress-ip-ranges.csv)"

#: c4: FireHOL proxy upstreams named by the firehol_proxies header (2026-11-26) -> per-upstream file
#: (None = HTTP 404 observed on iplists.firehol.org: cannot be consumed per upstream).
FIREHOL_PROXY_UPSTREAMS: dict[str, str | None] = {
    "iblocklist_proxies": None,
    "ip2proxy_px1lite": None,
    "socks_proxy_30d": FIREHOL_BASE + "/socks_proxy_30d.ipset",
    "sslproxies_30d": FIREHOL_BASE + "/sslproxies_30d.ipset",
}
#: c4: upstream -> terms class as recorded by legal (A1). Empty on purpose: no upstream terms are
#: recorded yet, so nothing is wired (socks-proxy.net / sslproxies.org publish no terms).
FIREHOL_UPSTREAM_TERMS: dict[str, str] = {}
FIREHOL_NOT_WIRED = (
    "not checked: no FireHOL proxy upstream is wired (socks_proxy_30d, sslproxies_30d: upstream terms not recorded; "
    "iblocklist_proxies, ip2proxy_px1lite: no per-upstream file); the firehol_proxies aggregate is never consumed"
)
RMM_NOT_WIRED = "rmm_tool: not checked (the mthcht RMM list is not wired: file path unverified)"


@dataclass(frozen=True)
class ListSpec:
    """One downloaded context list (c1: a registered dataset with TTL and provenance)."""

    key: str
    url: str
    source: str
    tag: str
    fmt: str  # cidr_lines | ip_csv | relay_csv | domain_csv | ua_csv
    label: str
    ttl: int
    min_entries: int
    min_bytes: int
    expect: str
    licence: str
    attribution: str
    large: bool = False
    columns: tuple[str, ...] = ()
    max_invalid_ratio: float = 0.02

    @property
    def dataset(self) -> str:
        ext = "csv" if self.fmt.endswith("csv") else "txt"
        return f"ip_context_lists.{self.key}.{ext}"

    @property
    def group(self) -> str:
        return {"domain_csv": "domain", "ua_csv": "ua"}.get(self.fmt, "ip")


def _x4b(key: str, path: str, tag: str, label: str, min_entries: int, min_bytes: int) -> ListSpec:
    return ListSpec(key, f"{X4B_BASE}/{path}", SRC_X4B, tag, "cidr_lines", label, DAY, min_entries, min_bytes, "lines",
                    X4B_LICENCE, X4B_ATTRIBUTION)


def _mthcht_vpn(key: str, path: str, label: str, columns: tuple[str, ...], min_entries: int, min_bytes: int) -> ListSpec:
    return ListSpec(key, f"{MTHCHT_BASE}/{path}", SRC_MTHCHT_VPN, "vpn", "ip_csv", label, DAY, min_entries, min_bytes, "csv",
                    MTHCHT_LICENCE, MTHCHT_ATTRIBUTION, columns=columns, max_invalid_ratio=0.10)


#: Thresholds sit at ~25-50 % of the sizes observed on 2026-11-26 (X4BNet v4 vpn 183,651 B, v6 vpn
#: 12,664 B, v4 datacenter 719,595 B, v6 datacenter 156,705 B; ProtonVPN 356,729 B, Mullvad 65,081 B,
#: Surfshark 13,101 B; DynDNS 2,048,285 B; UA list 442,146 B; Apple 12,052,078 B), so normal churn passes
#: and truncated, HTML or error bodies are refused (the last good copy is kept, c2).
LISTS: tuple[ListSpec, ...] = (
    _x4b("x4bnet_vpn_ipv4", "vpn/ipv4.txt", "vpn", "X4BNet VPN ranges", 500, 40_000),
    _x4b("x4bnet_vpn_ipv6", "vpn/ipv6.txt", "vpn", "X4BNet VPN ranges", 50, 3_000),
    _x4b("x4bnet_datacenter_ipv4", "datacenter/ipv4.txt", "datacenter", "X4BNet datacenter ranges", 5_000, 150_000),
    _x4b("x4bnet_datacenter_ipv6", "datacenter/ipv6.txt", "datacenter", "X4BNet datacenter ranges", 500, 30_000),
    _mthcht_vpn("mthcht_vpn_protonvpn", "VPN/ProtonVPN/protonvpn_ip_list.csv", "ProtonVPN server", ("src_ip_entry", "src_ip_exit"), 500, 80_000),
    _mthcht_vpn("mthcht_vpn_mullvad", "VPN/MullVad/mullvad_relay_servers_ips_list.csv", "Mullvad VPN relay", ("dest_ip",), 100, 15_000),
    _mthcht_vpn("mthcht_vpn_surfshark", "VPN/SurfSharkVPN/surfshark_vpn_servers_domains_and_ips_list.csv", "Surfshark VPN server",
                ("dest_ip",), 20, 3_000),
    ListSpec("mthcht_dyndns", f"{MTHCHT_BASE}/DYNDNS/dyndns_list.csv", SRC_DYNDNS, "dynamic_dns", "domain_csv",
             "dynamic DNS provider domain", DAY, 1_000, 400_000, "csv", MTHCHT_LICENCE, MTHCHT_ATTRIBUTION, max_invalid_ratio=0.10),
    ListSpec("mthcht_suspicious_ua", f"{MTHCHT_BASE}/suspicious_http_user_agents_list.csv", SRC_UA, "suspicious_user_agent", "ua_csv",
             "suspicious HTTP user agent", DAY, 100, 80_000, "csv", MTHCHT_LICENCE, MTHCHT_ATTRIBUTION, max_invalid_ratio=0.10),
    ListSpec("apple_private_relay", RELAY_URL, SRC_RELAY, "privacy_relay", "relay_csv", "Apple iCloud Private Relay egress",
             WEEK, 100_000, 3_000_000, "text", RELAY_LICENCE, RELAY_ATTRIBUTION, large=True, max_invalid_ratio=0.01),
)
LIST_BY_KEY: dict[str, ListSpec] = {spec.key: spec for spec in LISTS}

# ======================================================================================
# Parsers (untrusted downloaded data: bounded, never executed)
# ======================================================================================


class Parsed(NamedTuple):
    """One parsed list: ``data`` is a RangeIndex (IP lists) or a dict (domain/UA lists)."""

    data: Any
    entries: int
    stats: dict[str, int]
    error: str = ""


class Geo(NamedTuple):
    country: str
    region: str
    city: str


_HTML_RE = re.compile(r"^\s*(?:<!doctype\s+html|<html\b|<head\b|<body\b|<\?xml\b|<title\b)", re.I)
_ERROR_BODY_RE = re.compile(r"^\d{3}:\s|^404 not found", re.I)
_UA_GLOB = re.compile(r"[*?\[]")
_CC_RE = re.compile(r"^[A-Z]{2}$")


def _text(raw: Any) -> str | None:
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8-sig", errors="replace")
    if isinstance(raw, str):
        return raw.lstrip("﻿")
    return None


def download_problem(text: str | None) -> str:
    """Why a body is not a list (empty, an HTML page, a '404: Not Found' error body), else ''."""
    if text is None:
        return "unsupported body type"
    head = text.lstrip()[:512]
    if not head:
        return "empty body"
    if _HTML_RE.match(head) or head.startswith("<"):
        return "an HTML page came back instead of the list"
    if _ERROR_BODY_RE.match(head[:32]):
        return f"an error body came back ({head[:30]!r})"
    return ""


def _network(token: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None
    return net


def parse_cidr_lines(raw: Any) -> Parsed:
    """Plain CIDR/IP list (X4BNet, FireHOL entries) -> RangeIndex of the original tokens.

    Comments ('#', ';') and blank lines are skipped; blocks broader than /8 (IPv4) or /19 (IPv6) and
    non-global space are refused."""
    stats = {"lines": 0, "valid": 0, "invalid": 0, "comments": 0, "refused": 0, "v4": 0, "v6": 0}
    text = _text(raw)
    problem = download_problem(text)
    if problem:
        return Parsed(RangeIndex(), 0, stats, problem)

    def items() -> Iterable[tuple[Any, str]]:
        for line in (text or "").splitlines():
            s = line.strip()
            if not s:
                continue
            stats["lines"] += 1
            if s[0] in "#;":
                stats["comments"] += 1
                continue
            token = s.split()[0].split("#")[0]
            net = _network(token)
            if net is None:
                stats["invalid"] += 1
                continue
            if net.prefixlen < MIN_PREFIXLEN[net.version] or not net.network_address.is_global:
                stats["refused"] += 1
                continue
            stats["valid"] += 1
            stats[f"v{net.version}"] += 1
            yield net, token

    index = RangeIndex(items())
    return Parsed(index, stats["valid"], stats, "" if stats["valid"] else "no valid entries")


def parse_ip_csv(raw: Any, columns: tuple[str, ...]) -> Parsed:
    """mthcht VPN CSV (ProtonVPN entry/exit IPs, Mullvad/Surfshark server IPs) -> RangeIndex of /32 and /128."""
    stats = {"rows": 0, "valid": 0, "invalid": 0, "refused": 0, "duplicates": 0}
    text = _text(raw)
    problem = download_problem(text)
    if problem:
        return Parsed(RangeIndex(), 0, stats, problem)
    reader = csv.reader(io.StringIO(text or ""))
    header = [h.strip() for h in next(reader, [])]
    cols = [header.index(c) for c in columns if c in header]
    if not cols:
        return Parsed(RangeIndex(), 0, stats, f"CSV header has none of the IP columns {', '.join(columns)}")
    seen: set[str] = set()

    def items() -> Iterable[tuple[Any, str]]:
        for row in reader:
            if not row or not any(c.strip() for c in row):
                continue
            stats["rows"] += 1
            for ci in cols:
                value = row[ci].strip() if ci < len(row) else ""
                if not value:
                    continue
                try:
                    ip = ipaddress.ip_address(value)
                except ValueError:
                    stats["invalid"] += 1
                    continue
                if not ip.is_global:
                    stats["refused"] += 1
                    continue
                key = str(ip)
                if key in seen:
                    stats["duplicates"] += 1
                    continue
                seen.add(key)
                stats["valid"] += 1
                yield ipaddress.ip_network(key), key

    index = RangeIndex(items())
    return Parsed(index, stats["valid"], stats, "" if stats["valid"] else "no valid entries")


def parse_relay_csv(raw: Any) -> Parsed:
    """Apple egress-ip-ranges.csv (``CIDR,CC,REGION,CITY,``) -> RangeIndex of (cidr, Geo) (c1/c6).

    Parsed once per downloaded version; a truncated first/last line counts as invalid."""
    stats = {"rows": 0, "valid": 0, "invalid": 0, "refused": 0, "v4": 0, "v6": 0}
    text = _text(raw)
    problem = download_problem(text)
    if problem:
        return Parsed(RangeIndex(), 0, stats, problem)
    geos: dict[tuple[str, str, str], Geo] = {}

    def items() -> Iterable[tuple[Any, tuple[str, Geo]]]:
        for line in (text or "").splitlines():
            if not line.strip():
                continue
            stats["rows"] += 1
            parts = line.split(",")
            token = parts[0].strip()
            net = _network(token)
            if net is None or "/" not in token:
                stats["invalid"] += 1
                continue
            if net.prefixlen < MIN_PREFIXLEN[net.version] or not net.network_address.is_global:
                stats["refused"] += 1
                continue
            cc = parts[1].strip() if len(parts) > 1 else ""
            region = parts[2].strip()[:16] if len(parts) > 2 else ""
            city = parts[3].strip()[:80] if len(parts) > 3 else ""
            geo_key = (cc if _CC_RE.match(cc) else "", region, city)
            geo = geos.get(geo_key)
            if geo is None:
                geo = geos[geo_key] = Geo(*geo_key)
            stats["valid"] += 1
            stats[f"v{net.version}"] += 1
            yield net, (token, geo)

    index = RangeIndex(items())
    return Parsed(index, stats["valid"], stats, "" if stats["valid"] else "no valid entries")


_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


def _domain(value: str) -> str | None:
    """Lower-case ASCII (punycode) host name with at least two labels, else None (cheap: lists are large)."""
    text = str(value or "").strip().lower().rstrip(".")
    if not text or len(text) > 253 or "." not in text:
        return None
    if not text.isascii():
        ent = Entity.try_make(T.DOMAIN, text)  # IDN -> punycode through the core normaliser
        if ent is None:
            return None
        text = ent.value
    labels = text.split(".")
    if len(labels) > MAX_DOMAIN_LABELS or not all(_LABEL_RE.match(label) for label in labels) or labels[-1].isdigit():
        return None
    return text


def parse_domain_csv(raw: Any) -> Parsed:
    """mthcht domain CSV (DynDNS; the RMM list uses the same layout) -> {domain: meta}.

    The domain column is the first header containing 'domain'. '*.x' rows match only sub-domains of
    x; single-label rows are refused (c7)."""
    stats = {"rows": 0, "valid": 0, "invalid": 0, "wildcard": 0, "duplicates": 0}
    text = _text(raw)
    problem = download_problem(text)
    if problem:
        return Parsed({}, 0, stats, problem)
    reader = csv.reader(io.StringIO(text or ""))
    header = [h.strip() for h in next(reader, [])]
    col = next((i for i, h in enumerate(header) if "domain" in h.lower()), None)
    if col is None:
        return Parsed({}, 0, stats, "CSV header has no domain column")
    entries: dict[str, dict[str, Any]] = {}
    for row in reader:
        if not row or not any(c.strip() for c in row):
            continue
        stats["rows"] += 1
        raw_value = row[col].strip() if col < len(row) else ""
        wildcard = raw_value.startswith("*.")
        dom = _domain(raw_value[2:] if wildcard else raw_value)
        if dom is None:
            stats["invalid"] += 1
            continue
        if dom in entries:
            stats["duplicates"] += 1
            continue
        meta: dict[str, Any] = {"subdomains_only": wildcard}
        for i, h in enumerate(header):
            if i != col and i < len(row) and row[i].strip() and h:
                name = h[9:] if h.startswith("metadata_") else h
                if name.lower() in ("retrievedat", "link", "comment", "description"):
                    continue
                meta[name.lower()[:40]] = row[i].strip()[:120]
        entries[dom] = meta
        stats["valid"] += 1
        stats["wildcard"] += int(wildcard)
    return Parsed(entries, stats["valid"], stats, "" if entries else "no valid entries")


def parse_ua_csv(raw: Any) -> Parsed:
    """mthcht suspicious_http_user_agents_list.csv -> {user agent: meta} for exact matching (c7).

    Rows with glob characters ('*', '?', '[') are set aside (counted in stats['wildcard'])."""
    stats = {"rows": 0, "exact": 0, "valid": 0, "wildcard": 0, "invalid": 0, "duplicates": 0}
    text = _text(raw)
    problem = download_problem(text)
    if problem:
        return Parsed({}, 0, stats, problem)
    reader = csv.DictReader(io.StringIO(text or ""))
    fields = [f.strip() for f in (reader.fieldnames or [])]
    if "http_user_agent" not in fields:
        return Parsed({}, 0, stats, "CSV header has no http_user_agent column")
    reader.fieldnames = fields
    exact: dict[str, dict[str, Any]] = {}
    for row in reader:
        stats["rows"] += 1
        ua = str(row.get("http_user_agent") or "").strip()
        if not ua or len(ua) > MAX_UA_LEN:
            stats["invalid"] += 1
            continue
        if _UA_GLOB.search(ua):
            stats["wildcard"] += 1
            continue
        if ua in exact:
            stats["duplicates"] += 1
            continue
        meta = {k[9:]: str(row.get(k) or "").strip()[:120] for k in ("metadata_tool", "metadata_category", "metadata_fp_risk")
                if str(row.get(k) or "").strip()}
        exact[ua] = meta
        stats["exact"] += 1
        stats["valid"] += 1
    return Parsed(exact, stats["valid"], stats, "" if exact else "no exact user-agent entries")


PARSERS: dict[str, Callable[..., Parsed]] = {
    "cidr_lines": parse_cidr_lines,
    "relay_csv": parse_relay_csv,
    "domain_csv": parse_domain_csv,
    "ua_csv": parse_ua_csv,
}


def parse_list(spec: ListSpec, raw: Any) -> Parsed:
    if spec.fmt == "ip_csv":
        return parse_ip_csv(raw, spec.columns)
    return PARSERS[spec.fmt](raw)


def domain_match(domain: str, entries: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    """c7: the domain, its registrable domain or a parent suffix equals a list entry (label boundaries,
    never a substring); '*.x' entries match sub-domains of x only."""
    dom = _domain(domain)
    if dom is None:
        return None
    labels = dom.split(".")
    for i in range(len(labels) - 1):
        cand = ".".join(labels[i:])
        meta = entries.get(cand)
        if meta is None or (meta.get("subdomains_only") and i == 0):
            continue
        return {"matched": cand, "exact": i == 0, "registrable": registrable_domain(dom) or "", "meta": meta}
    return None


def ua_match(user_agent: str, entries: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    """c7: exact match only (surrounding whitespace trimmed; no case folding, no substring)."""
    ua = str(user_agent or "").strip()
    meta = entries.get(ua) if ua else None
    return {"matched": ua, "meta": meta} if meta is not None else None


# ---- FireHOL (c4) ---------------------------------------------------------------------

_FH_KV = re.compile(r"^#\s*(Maintainer URL|Maintainer|List source URL|Source File Date|Category|Version|"
                    r"This File Date|Update Frequency|Aggregation|Entries)\s*:\s?(.*?)\s*$")
_FH_TYPE = re.compile(r"^#\s*(ipv4|ipv6)\s+(hash:\w+)\s+ipset\s*$", re.I)
_FH_KEYS = {"Maintainer": "maintainer", "Maintainer URL": "maintainer_url", "List source URL": "source_url",
            "Source File Date": "source_file_date", "Category": "category", "Version": "version",
            "This File Date": "file_date", "Update Frequency": "update_frequency", "Aggregation": "aggregation"}


def parse_firehol_header(raw: Any) -> dict[str, Any]:
    """FireHOL ipset/netset comment header -> metadata, including the upstream list names ('includes')."""
    text = _text(raw) or ""
    out: dict[str, Any] = {"name": "", "family": "", "description": "", "includes": [], "maintainer": "", "maintainer_url": "",
                           "source_url": "", "source_file_date": "", "category": "", "version": "", "file_date": "",
                           "update_frequency": "", "aggregation": "", "entries_subnets": None, "entries_unique_ips": None}
    desc: list[str] = []
    stage = "name"
    for line in text.splitlines()[:200]:
        if not line.startswith("#"):
            if line.strip():
                break
            continue
        body = line[1:].strip()
        kv = _FH_KV.match(line)
        if kv:
            key, val = kv.group(1), kv.group(2).strip()[:200]
            if key == "Entries":
                sub = re.search(r"(\d+)\s+subnets", val)
                ips = re.search(r"(\d+)\s+unique IPs", val)
                out["entries_subnets"] = int(sub.group(1)) if sub else None
                out["entries_unique_ips"] = int(ips.group(1)) if ips else None
            else:
                out[_FH_KEYS[key]] = val
            stage = "kv"
            continue
        kind = _FH_TYPE.match(line)
        if kind:
            out["family"] = kind.group(1).lower()
            stage = "desc"
            continue
        if stage == "name" and body and not out["name"]:
            out["name"] = body[:80]
        elif stage == "desc" and body:
            desc.append(body)
    joined = " ".join(desc)
    inc = re.search(r"\(includes:\s*([^)]*)\)", joined)
    if inc:
        out["includes"] = [x for x in inc.group(1).split() if re.fullmatch(r"[A-Za-z0-9_]{1,64}", x)]
        joined = (joined[: inc.start()] + joined[inc.end():]).strip()
    out["description"] = re.sub(r"\s+", " ", joined).strip()[:300]
    return out


def firehol_upstream_plan(header: dict[str, Any], upstream_terms: dict[str, str] | None = None, licence_allow: Iterable[str] = (),
                          profile: str = "corporate") -> dict[str, Any]:
    """c4: which FireHOL proxy upstreams may be wired, per upstream, under the licence profile.

    ``header``: :func:`parse_firehol_header` of the aggregate (its 'includes' names the upstreams) or
    of one list. ``upstream_terms``: {upstream: terms class} recorded by legal (missing = unrecorded =
    not wired). ``licence_allow``: upstreams with an active licence_allow entry. Returns the wired,
    licence-blocked (with coverage rows: SKIPPED 'licence'), unrecorded and unavailable upstreams; the
    aggregate itself is never consumed."""
    hdr = header if isinstance(header, dict) else {}
    upstreams = list(hdr.get("includes") or ([hdr["name"]] if hdr.get("name") else []))
    terms = dict(FIREHOL_UPSTREAM_TERMS)
    terms.update(upstream_terms or {})
    allowed = set(licence_allow or ())
    plan: dict[str, Any] = {"aggregate": hdr.get("name") or "", "consume_aggregate": False, "wired": [], "licence_blocked": [],
                            "unrecorded": [], "unavailable": [], "coverage": []}
    for name in upstreams:
        cls = terms.get(name)
        if cls is None:
            plan["unrecorded"].append(name)
            continue
        if not FIREHOL_PROXY_UPSTREAMS.get(name):
            plan["unavailable"].append(name)
            continue
        if cls == "open" or (cls in ("noncommercial", "license", "key-terms") and name in allowed):
            plan["wired"].append(name)
            continue
        reason = (f"skipped: {cls} terms (licence profile {profile})" if cls != "unknown"
                  else "skipped: unknown terms (never runs until reviewed)")
        plan["licence_blocked"].append(name)
        plan["coverage"].append({"source": f"{SRC_FIREHOL}:{name}", "status": Status.SKIPPED.value, "reason_code": "licence",
                                 "reason": reason})
    return plan


# ======================================================================================
# Dataset registrations (c1-c3)
# ======================================================================================


def _validator(spec: ListSpec) -> Callable[[Path], bool]:
    """validate(path) of the dataset manager (c2): a body that does not parse, has too few entries or
    too many invalid lines never replaces the last good copy."""

    def validate(path: Path) -> bool:
        parsed = parse_list(spec, Path(path).read_bytes())
        if parsed.error:
            raise ValueError(f"{spec.dataset}: {parsed.error}")
        if parsed.entries < spec.min_entries:
            raise ValueError(f"{spec.dataset}: only {parsed.entries} valid entries (minimum {spec.min_entries})")
        invalid = int(parsed.stats.get("invalid", 0))
        total = invalid + parsed.entries
        if total and invalid / total > spec.max_invalid_ratio:
            raise ValueError(f"{spec.dataset}: {invalid} of {total} entries invalid (truncated or wrong file?)")
        return True

    return validate


for _spec in LISTS:
    register_dataset(
        _spec.dataset, _spec.url, ttl=_spec.ttl, description=f"ip_context_lists: {_spec.label} ({_spec.tag} context list)",
        licence=_spec.licence, terms_class="open", attribution=_spec.attribution, source=_spec.source,
        validate=_validator(_spec), min_bytes=_spec.min_bytes, expect=_spec.expect,
        large=True if _spec.large else None, max_bytes=64 * 1024 * 1024 if _spec.large else None,
    )

# ======================================================================================
# Loading the local copies (parsed once per downloaded version, thread-safe)
# ======================================================================================

_LOCK = threading.Lock()
_PARSED: dict[tuple[str, str], Parsed] = {}


def _parsed(spec: ListSpec, sha: str, path: Path) -> Parsed:
    key = (spec.dataset, sha)
    with _LOCK:
        hit = _PARSED.get(key)
    if hit is not None and sha:
        return hit
    try:
        data = path.read_bytes()
    except OSError as exc:
        return Parsed(None, 0, {}, f"unreadable local copy ({type(exc).__name__})")
    parsed = parse_list(spec, data)
    if sha and not parsed.error:
        with _LOCK:
            for old in [k for k in _PARSED if k[0] == spec.dataset and k != key]:
                del _PARSED[old]
            _PARSED[key] = parsed
    return parsed


@dataclass
class _Loaded:
    parsed: dict[str, Parsed] = field(default_factory=dict)
    meta: dict[str, dict[str, Any]] = field(default_factory=dict)  # key -> {sha256, fetched_at, age_days, stale}
    missing: dict[str, str] = field(default_factory=dict)  # key -> why it could not be checked


def _load(data: Any, specs: Iterable[ListSpec]) -> _Loaded:
    """Local copies of the lists (daily lists refresh through the dataset manager; the large Apple list
    is only served when `v3lum data update` installed it). Failures are recorded per list, never raised."""
    out = _Loaded()
    for spec in specs:
        try:
            if spec.large:
                info = data.info(spec.dataset)
                if not info.present:
                    out.missing[spec.key] = (f"not downloaded: {spec.dataset} is a large list (> 5 MB) installed only by "
                                             f"`v3lum data update {spec.dataset}`, never during a run")
                    continue
                path = Path(data.fetch(spec.dataset, ttl=NO_REFRESH_TTL))
            else:
                path = Path(data.fetch(spec.dataset))
            info = data.info(spec.dataset)
        except DatasetError as exc:  # DatasetUnavailable included
            out.missing[spec.key] = (str(exc) or "download or validation failed")[:300]
            continue
        except OSError as exc:
            out.missing[spec.key] = f"local copy unreadable ({type(exc).__name__})"
            continue
        parsed = _parsed(spec, str(info.sha256 or ""), path)
        if parsed.error:
            out.missing[spec.key] = f"local copy does not parse ({parsed.error}): run v3lum data update {spec.dataset}"
            continue
        out.parsed[spec.key] = parsed
        age = None if info.age_hours is None else round(max(0.0, float(info.age_hours)) / 24.0, 2)
        out.meta[spec.key] = {"sha256": str(info.sha256 or ""), "fetched_at": str(info.fetched_at or ""), "age_days": age,
                              "stale": bool(info.stale)}
    return out


# ======================================================================================
# The module
# ======================================================================================


@register
class IpContextLists(Module):
    name = "ip_context_lists"
    title = "IP context lists (VPN, datacenter, Private Relay, DynDNS, suspicious UAs)"
    description = (
        "Context labels from downloaded lists matched offline: VPN and datacenter ranges (X4BNet, mthcht VPN server "
        "lists), Apple iCloud Private Relay egress ranges, dynamic-DNS provider domains and suspicious user agents "
        "(mthcht awesome-lists). Context only, never a verdict."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6, T.CIDR, T.DOMAIN, T.USER_AGENT}
    produces: frozenset[T] = frozenset()
    tags = {"offline", "free"}
    reference = "https://github.com/X4BNet/lists_vpn"
    notice = (
        "Offline lookup in downloaded lists (the value never leaves the machine). Labels are context only, never verdicts: "
        "Apple Private Relay users are ordinary Safari users and their range suppresses VPN/proxy labels. X4BNet lists are "
        "MIT (IP data powered by IPLocate.io, CC BY-SA 4.0), mthcht awesome-lists MIT; runtime downloads only. FireHOL "
        "proxy upstreams keep their own terms and none is wired yet; no IP is ever tested as an open proxy."
    )
    # ---- contract v2 declarations --------------------------------------------------------
    terms = "noncommercial"  # = the most restrictive declared source (firehol.proxies); every other list is open
    opsec = Opsec.PASSIVE
    disclosure = "none"  # matching is local; only the dataset manager downloads the static lists
    hosts = ()
    sources = SOURCES
    expected_latency = 0.3  # warm lookups; the first run after an update parses each list once
    timeout = 120.0  # a first run may download the daily lists (all below 5 MB) and parse the Apple CSV
    max_pivots = 0
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.CIDR:
            net = as_network(entity.value)
            return net is not None and is_public_address(net.network_address)
        if entity.type in (T.IPV4, T.IPV6):
            return is_public_address(entity.value)
        if entity.type is T.DOMAIN:
            return "." in entity.value
        return bool(str(entity.value).strip())

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        allowed = set(ctx.allowed_sources) if ctx.allowed_sources is not None else set(SOURCES)
        group = {T.DOMAIN: "domain", T.USER_AGENT: "ua"}.get(entity.type, "ip")
        specs = [s for s in LISTS if s.group == group and s.source in allowed]
        not_wired: list[str] = []
        if group == "ip":
            not_wired.append("proxy: not checked (no FireHOL proxy upstream wired)")
            if SRC_FIREHOL in allowed:
                res.source_status(SRC_FIREHOL, Status.UNAVAILABLE, reason_code="dataset", reason=FIREHOL_NOT_WIRED)
        elif group == "domain":
            not_wired.append(RMM_NOT_WIRED)
        if not specs:
            return res.mark(Status.SKIPPED, f"no {group} context list allowed in this run (licence profile)", reason_code="licence")
        loaded = _load(ctx.data, specs)
        if group == "ip":
            matches = self._ip_matches(entity, specs, loaded)
        elif group == "domain":
            matches = self._keyed_matches(entity.value, specs, loaded, domain_match)
        else:
            matches = self._keyed_matches(entity.value, specs, loaded, ua_match)
        matched_keys = {m["list"] for m in matches}
        not_checked = dict(loaded.missing)
        for key, meta in loaded.meta.items():
            if meta["stale"] and key not in matched_keys:
                not_checked[key] = (f"stale copy (age {meta['age_days']} days, refresh failed or overdue): a miss is not evidence; "
                                    f"run v3lum data update {LIST_BY_KEY[key].dataset}")
        self._report_not_checked(res, not_checked)
        res.raw = {
            "lists": {LIST_BY_KEY[k].dataset: {**loaded.meta[k], "entries": p.entries} for k, p in loaded.parsed.items()},
            "not_checked": {LIST_BY_KEY[k].dataset: why for k, why in not_checked.items()},
            "not_wired": not_wired,
        }
        if matches:
            self._record(res, entity, matches, loaded, relay_unchecked="apple_private_relay" in not_checked)
            return res
        if not_checked:
            names = ", ".join(sorted(LIST_BY_KEY[k].dataset for k in not_checked))
            return res.mark(Status.UNAVAILABLE, f"not checked: {names} missing or stale (a miss on those lists is not evidence): "
                                                "run v3lum data update", reason_code="dataset")
        res.attr("dataset_age_days", {LIST_BY_KEY[k].dataset: m["age_days"] for k, m in loaded.meta.items()})
        checked = ", ".join(sorted({LIST_BY_KEY[k].label for k in loaded.parsed}))
        extra = f"; {'; '.join(not_wired)}" if not_wired else ""
        return res.mark(Status.EMPTY, f"not on the checked lists ({checked}): absence is not a verdict{extra}")

    # ------------------------------------------------------------------ matching
    @staticmethod
    def _ip_matches(entity: Entity, specs: list[ListSpec], loaded: _Loaded) -> list[dict[str, Any]]:
        is_cidr = entity.type is T.CIDR
        out: list[dict[str, Any]] = []
        for spec in specs:
            parsed = loaded.parsed.get(spec.key)
            if parsed is None:
                continue
            index: RangeIndex = parsed.data
            hits = index.lookup_cidr(entity.value) if is_cidr else index.lookup(entity.value)
            partial = False
            if not hits and is_cidr:
                hits = index.overlapping(entity.value, limit=5)
                partial = bool(hits)
            if not hits:
                continue
            payload = hits[0]  # innermost block first
            cidr, geo = (payload if isinstance(payload, tuple) else (payload, None))
            match: dict[str, Any] = {"tag": spec.tag, "list": spec.key, "label": spec.label, "matched": str(cidr)}
            if geo is not None:
                match["geo"] = {"country": geo.country, "region": geo.region, "city": geo.city}
            if partial:
                match["partial"] = True  # the CIDR overlaps a listed block but is not inside one: no label
            out.append(match)
        return out

    @staticmethod
    def _keyed_matches(value: str, specs: list[ListSpec], loaded: _Loaded,
                       matcher: Callable[[str, dict[str, dict[str, Any]]], dict[str, Any] | None]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for spec in specs:
            parsed = loaded.parsed.get(spec.key)
            if parsed is None:
                continue
            hit = matcher(value, parsed.data)
            if hit is None:
                continue
            match: dict[str, Any] = {"tag": spec.tag, "list": spec.key, "label": spec.label, "matched": hit["matched"]}
            meta = {k: v for k, v in hit["meta"].items() if k != "subdomains_only"}
            if meta:
                match["entry"] = meta
            if hit.get("registrable"):
                match["registrable"] = hit["registrable"]
            out.append(match)
        return out

    # ------------------------------------------------------------------ reporting
    @staticmethod
    def _report_not_checked(res: ModuleResult, not_checked: dict[str, str]) -> None:
        per_source: dict[str, list[str]] = {}
        for key, why in sorted(not_checked.items()):
            per_source.setdefault(LIST_BY_KEY[key].source, []).append(f"{LIST_BY_KEY[key].dataset}: {why}"[:300])
        for source, reasons in per_source.items():
            res.source_status(source, Status.UNAVAILABLE, reason_code="dataset", reason="not checked: " + "; ".join(reasons))

    @staticmethod
    def _record(res: ModuleResult, entity: Entity, matches: list[dict[str, Any]], loaded: _Loaded, *, relay_unchecked: bool = False) -> None:
        full = [m for m in matches if not m.get("partial")]
        partial = [m for m in matches if m.get("partial")]
        tags = {m["tag"] for m in full}
        relay = next((m for m in full if m["tag"] == "privacy_relay"), None)
        suppressed = sorted(tags & RELAY_SUPPRESSES) if relay else []
        context = sorted(t for t in tags if t not in suppressed)
        rows = []
        for m in (full + partial)[:MAX_MATCHES]:
            meta = loaded.meta.get(m["list"], {})
            row = dict(m, list=LIST_BY_KEY[m["list"]].dataset, dataset_sha256=meta.get("sha256", "")[:16],
                       fetched_at=meta.get("fetched_at", ""), age_days=meta.get("age_days"), stale=bool(meta.get("stale")))
            if m["tag"] in suppressed and not m.get("partial"):
                row["suppressed_by"] = "privacy_relay"
            rows.append(row)
        res.attr("context_tags", context)
        res.attr("context_matches", rows)
        res.attr("dataset_age_days", {LIST_BY_KEY[k].dataset: m["age_days"] for k, m in loaded.meta.items()})
        used = sorted({LIST_BY_KEY[m["list"]].attribution for m in full + partial})
        res.attr("data_attribution", "; ".join(used))
        if "vpn" in context:
            res.attr("is_vpn", True)
        if "proxy" in context:
            res.attr("is_proxy", True)
        if "datacenter" in context:
            res.attr("is_hosting", True)
        stale_note = " (stale list copy)" if any(r["stale"] for r in rows) else ""
        if relay is not None:
            geo = relay.get("geo") or {}
            res.attr("privacy_relay", {"range": relay["matched"], "country": geo.get("country", ""), "region": geo.get("region", ""),
                                       "city": geo.get("city", ""), "dataset": LIST_BY_KEY[relay["list"]].dataset})
            where = ", ".join(x for x in (geo.get("city"), geo.get("region"), geo.get("country")) if x)
            res.finding(
                "Apple iCloud Private Relay egress address",
                "info",
                f"{entity.value} is in Apple's published Private Relay egress range {relay['matched']}"
                + (f" ({where})" if where else "")
                + f"{stale_note}. Ordinary Safari/iCloud+ users: never scored as an anonymiser"
                + (f"; the {', '.join(suppressed)} label(s) of this range are suppressed." if suppressed else "."),
                data={"range": relay["matched"], "geo": geo, "suppressed": suppressed},
                tags=["privacy_relay", "context_only", "info"],
                source=SRC_RELAY,
            )
        others = [t for t in context if t != "privacy_relay"]
        if others:
            labels = sorted({m["label"] for m in full if m["tag"] in others})
            title = {
                "dynamic_dns": "Dynamic DNS provider domain",
                "suspicious_user_agent": "User agent on a suspicious-user-agent list",
            }.get(others[0], "IP context labels from downloaded lists") if len(others) == 1 else "IP context labels from downloaded lists"
            relay_note = ""
            if relay_unchecked and RELAY_SUPPRESSES & set(others):
                relay_note = (" The Apple Private Relay list was not checked: an iCloud Private Relay range would suppress the "
                              "VPN/proxy label (run v3lum data update ip_context_lists.apple_private_relay.csv).")
            res.finding(
                title,
                "info",
                f"Context only, never a verdict: {', '.join(others)} ({'; '.join(labels)}){stale_note}. "
                "List membership says what kind of infrastructure or tool this is, not that it is malicious." + relay_note,
                data={"tags": others, "matches": [{k: m.get(k) for k in ("tag", "label", "matched")} for m in full if m["tag"] in others][:10],
                      "privacy_relay_checked": not relay_unchecked},
                tags=sorted(set(others) | {"context_only", "info"}),
                source=next(LIST_BY_KEY[m["list"]].source for m in full if m["tag"] in others),
            )
        if partial and not full:
            res.finding(
                "CIDR overlaps context-list ranges",
                "info",
                f"{entity.value} is not inside a listed block but overlaps {len(partial)} list(s) "
                f"({', '.join(sorted({m['label'] for m in partial}))}): no label is applied to the whole network.",
                data={"overlaps": [{k: m.get(k) for k in ("tag", "label", "matched")} for m in partial]},
                tags=["context_only", "info"],
            )


__all__ = [
    "CONTEXT_TAGS",
    "FIREHOL_PROXY_UPSTREAMS",
    "FIREHOL_UPSTREAM_TERMS",
    "LISTS",
    "LIST_BY_KEY",
    "IpContextLists",
    "domain_match",
    "download_problem",
    "firehol_upstream_plan",
    "parse_cidr_lines",
    "parse_domain_csv",
    "parse_firehol_header",
    "parse_ip_csv",
    "parse_list",
    "parse_relay_csv",
    "parse_ua_csv",
    "ua_match",
]
