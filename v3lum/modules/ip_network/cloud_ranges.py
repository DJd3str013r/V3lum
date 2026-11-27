"""cloud_ranges: cloud/CDN provider labels for an IP or CIDR from official range files (P034).

Batch p1-G02-1. Offline matching (disclosure 'none'): the address never leaves the machine. The
provider range files are registered datasets (one per file, P034 cond 2) that the core dataset
manager downloads, validates and refreshes (daily TTL); lookups only read the local copies.

* **Shared IP-range index** (P034 cond 1): :class:`RangeIndex` flattens nested CIDR blocks into
  sorted disjoint integer intervals (IPv4 and IPv6) with one bisect per lookup - no radix tree. It
  is the reference implementation of the core index (`nicbr_asn` reuses it; the core request asks
  to promote it to ``v3lum/core/ranges.py`` for ip_context_lists, ip_offline_db, ip_blocklists and
  tor_relays).
* **Datasets** (cond 2-4): AWS ip-ranges.json, Google cloud.json and goog.json, Cloudflare
  ips-v4/ips-v6, Fastly public-ip-list, Oracle OCI public_ip_ranges.json, GitHub meta and the
  cloudcheck signatures. Each download is validated (HTML/challenge pages, minimum size, parse
  success, minimum entry count) before it replaces the cached copy; a failed refresh keeps the last
  good copy with its date. cloudcheck (AGPL-3.0 repository) is runtime data only: never bundled or
  copied, attributed in ``v3lum/data/notices/cloud_ranges_cloudcheck.json``; the official files
  alone pass every test. Azure Service Tags have no stable URL and are never scraped (backlog).
* **Rule 5** (cond 4): a missing dataset gives UNAVAILABLE ('could not verify'), never 'not cloud':
  EMPTY needs every allowed dataset loaded; a dataset that could not be loaded is reported per feed
  with ``res.source_status``.
* **Labels** (cond 5-7, 9): ``is_cloud``, ``is_cdn``, ``is_hosting``, provider/region/service and a
  label such as 'Cloudflare CDN edge' or 'AWS sa-east-1 EC2'. Roles are V3LUM-authored: shared edges
  and multi-tenant front doors (cdn_edge, shared_hosting, shared_service, shared_proxy) are noise
  ('not pivoted: shared CDN/cloud IP', ``third_party_hosted``); rented compute (iaas) and whole
  provider networks are NOT noise and carry a verdict lifetime of 14 days. Official files win over
  cloudcheck; a specific record wins over a generic one (AWS 'AMAZON', goog.json); on one block a
  non-noise role wins (EC2 next to S3). The module itself creates no pivots and never suppresses
  findings about domains or URLs (cond 7).
* Helpers for the core (no network, local copies only): :func:`local_classification`,
  :func:`noise_kind_for` (the AR06 noise-provider hook, cond 1) and :func:`active_guard`
  (ACTIVE scope guard, fail closed on a missing or > 7-day-old dataset, cond 8).
"""

from __future__ import annotations

import bisect
import ipaddress
import json
import re
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NamedTuple, Union

from v3lum.core.datasets import DataStore, DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# ======================================================================================
# Shared IP-range index (P034 cond 1)
# ======================================================================================


def as_ip(value: Any) -> IPAddress | None:
    """An address from a str/ipaddress value (brackets and zone ids tolerated; IPv4-mapped IPv6 ->
    IPv4), or None."""
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        ip: Any = value
    else:
        text = str(value or "").strip().strip("[]").split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def as_network(value: Any) -> IPNetwork | None:
    """A network from a CIDR string/ipaddress value (host bits cleared), or None."""
    if isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return value
    text = str(value or "").strip()
    if not text or " " in text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def is_public_address(value: Any) -> bool:
    """True for globally routable unicast addresses (private, CGNAT, documentation, loopback,
    link-local, multicast and reserved space are not)."""
    ip = as_ip(value)
    return bool(ip is not None and ip.is_global and not ip.is_multicast)


class _Segments(NamedTuple):
    starts: list[int]
    ends: list[int]
    chains: list[tuple[tuple[int, Any], ...]]  # (prefixlen, payload), innermost first


def _flatten(blocks: dict[tuple[int, int], list[tuple[int, Any]]]) -> _Segments:
    """Sweep nested-or-disjoint CIDR blocks (sorted by start, larger first) into disjoint segments;
    every segment carries the payloads of all blocks that contain it, innermost first."""
    starts: list[int] = []
    ends: list[int] = []
    chains: list[tuple[tuple[int, Any], ...]] = []

    def emit(start: int | None, end: int, chain: tuple[tuple[int, Any], ...]) -> None:
        if start is not None and start <= end:
            starts.append(start)
            ends.append(end)
            chains.append(chain)

    stack: list[tuple[int, tuple[tuple[int, Any], ...]]] = []
    cur: int | None = None
    for start, end in sorted(blocks, key=lambda k: (k[0], -k[1])):
        while stack and stack[-1][0] < start:
            top_end, top_chain = stack.pop()
            emit(cur, top_end, top_chain)
            cur = top_end + 1
        if stack:
            emit(cur, start - 1, stack[-1][1])
        chain = tuple(blocks[(start, end)]) + (stack[-1][1] if stack else ())
        stack.append((end, chain))
        cur = start
    while stack:
        top_end, top_chain = stack.pop()
        emit(cur, top_end, top_chain)
        cur = top_end + 1
    return _Segments(starts, ends, chains)


class RangeIndex:
    """Shared IP-range index: sorted disjoint integer intervals + bisect, IPv4 and IPv6 (P034 cond 1).

    ``RangeIndex(items)`` takes ``(cidr, payload)`` pairs (CIDR strings or ipaddress networks; invalid
    ones are skipped). CIDR blocks are always nested or disjoint, so they flatten into disjoint
    segments, each holding the payloads of every block that contains it (innermost first). A lookup is
    one bisect: ``lookup(ip)`` returns the payloads of the blocks containing the address and
    ``lookup_cidr(cidr)`` those containing the whole network. Immutable after construction and safe to
    share between threads. No per-module radix trees: modules needing IP-range membership reuse this
    class (core request: promote it to ``v3lum/core/ranges.py``).
    """

    __slots__ = ("_tables", "_size")

    def __init__(self, items: Iterable[tuple[Any, Any]] = ()) -> None:
        per_version: dict[int, dict[tuple[int, int], list[tuple[int, Any]]]] = {4: {}, 6: {}}
        size = 0
        for cidr, payload in items:
            net = as_network(cidr)
            if net is None:
                continue
            key = (int(net.network_address), int(net.broadcast_address))
            per_version[net.version].setdefault(key, []).append((net.prefixlen, payload))
            size += 1
        self._tables = {version: _flatten(blocks) for version, blocks in per_version.items()}
        self._size = size

    def __len__(self) -> int:
        return self._size

    def _chain(self, ip: IPAddress) -> tuple[tuple[int, Any], ...]:
        table = self._tables[ip.version]
        n = int(ip)
        i = bisect.bisect_right(table.starts, n) - 1
        if i >= 0 and table.ends[i] >= n:
            return table.chains[i]
        return ()

    def lookup(self, value: Any) -> tuple[Any, ...]:
        """Payloads of every block containing the address, innermost first (() for none/invalid)."""
        ip = as_ip(value)
        return () if ip is None else tuple(payload for _plen, payload in self._chain(ip))

    def lookup_cidr(self, value: Any) -> tuple[Any, ...]:
        """Payloads of every block containing the whole network, innermost first."""
        net = as_network(value)
        if net is None:
            return ()
        if isinstance(net, ipaddress.IPv6Network) and net.network_address.ipv4_mapped is not None and net.prefixlen >= 96:
            net = ipaddress.ip_network(f"{net.network_address.ipv4_mapped}/{net.prefixlen - 96}", strict=False)
        return tuple(payload for plen, payload in self._chain(net.network_address) if plen <= net.prefixlen)

    def overlapping(self, value: Any, limit: int = 1000) -> tuple[Any, ...]:
        """Payloads of every block that intersects the network (inside it or containing it), at
        most ``limit``, in address order (innermost first within a segment)."""
        net = as_network(value)
        if net is None:
            return ()
        table = self._tables[net.version]
        low, high = int(net.network_address), int(net.broadcast_address)
        i = max(0, bisect.bisect_right(table.starts, low) - 1)
        out: list[Any] = []
        seen: set[int] = set()
        while i < len(table.starts) and table.starts[i] <= high and len(out) < limit:
            if table.ends[i] >= low:
                for _plen, payload in table.chains[i]:
                    if id(payload) not in seen:
                        seen.add(id(payload))
                        out.append(payload)
            i += 1
        return tuple(out[:limit])

    def contains(self, value: Any) -> bool:
        return bool(self.lookup(value))

    __contains__ = contains


# ======================================================================================
# Provider range files: records, roles, parsers
# ======================================================================================

#: role -> (is_cdn, is_hosting, noise). Noise roles are shared infrastructure: never pivoted and no
#: IP-reputation expansion to co-tenants (cond 6); iaas/provider_network stay investigable.
ROLE_FLAGS: dict[str, tuple[bool, bool, bool]] = {
    "cdn_edge": (True, False, True),
    "shared_hosting": (False, True, True),
    "shared_service": (False, False, True),
    "shared_proxy": (False, False, True),
    "iaas": (False, True, False),
    "provider_network": (False, False, False),
}
#: On one block the first role present wins: non-noise roles first, so real C2 on rented compute
#: is never hidden behind a shared label of the same block (EC2 next to S3).
ROLE_PRECEDENCE: tuple[str, ...] = ("iaas", "provider_network", "shared_hosting", "cdn_edge", "shared_service", "shared_proxy")
NOISE_ROLES = frozenset(r for r, flags in ROLE_FLAGS.items() if flags[2])
#: Cloud compute addresses are reassigned: reputation verdicts on them expire (cond 6).
VERDICT_LIFETIME_DAYS = 14
NOISE_PIVOT_NOTE = "not pivoted: shared CDN/cloud IP"
#: ACTIVE network modules refuse to run on older (or missing) range data (cond 8, fail closed).
ACTIVE_MAX_DATASET_AGE_DAYS = 7.0
#: Datasets must never hold blocks so broad that they would label the Internet (a corrupted file).
MIN_PREFIXLEN = {4: 8, 6: 19}
#: role -> noise kind of v3lum.core.noise (the AR06 hook); non-noise roles have none.
NOISE_KIND_OF_ROLE = {"cdn_edge": "cdn", "shared_hosting": "hosting", "shared_service": "saas", "shared_proxy": "cloud"}

AWS_SERVICE_ROLES: dict[str, str] = {
    "CLOUDFRONT": "cdn_edge", "CLOUDFRONT_ORIGIN_FACING": "cdn_edge", "GLOBALACCELERATOR": "cdn_edge",
    "S3": "shared_hosting",
    "API_GATEWAY": "shared_service", "DYNAMODB": "shared_service", "ROUTE53": "shared_service", "ROUTE53_HEALTHCHECKS": "shared_service",
    "ROUTE53_HEALTHCHECKS_PUBLISHING": "shared_service", "ROUTE53_RESOLVER": "shared_service", "EBS": "shared_service",
    "EFS": "shared_service", "KINESIS_VIDEO_STREAMS": "shared_service", "MEDIA_PACKAGE_V2": "shared_service",
    "IVS_REALTIME": "shared_service", "IVS_LOW_LATENCY": "shared_service", "CHIME_MEETINGS": "shared_service",
    "CHIME_VOICECONNECTOR": "shared_service", "AMAZON_CONNECT": "shared_service", "AMAZON_APPFLOW": "shared_service",
    "WORKSPACES_GATEWAYS": "shared_service", "AURORA_DSQL": "shared_service", "EC2_INSTANCE_CONNECT": "shared_service",
    "EC2": "iaas", "CLOUD9": "iaas", "CODEBUILD": "iaas",
    "AMAZON": "provider_network",
}
ORACLE_TAG_ROLES: tuple[tuple[str, str, str], ...] = (
    ("OBJECT_STORAGE", "shared_hosting", "Object Storage"), ("OSN", "shared_service", "OSN"), ("OCI", "iaas", "OCI"),
)
GITHUB_META_ROLES: dict[str, str] = {
    "pages": "shared_hosting", "web": "shared_service", "api": "shared_service", "git": "shared_service",
    "packages": "shared_service", "copilot": "shared_service", "github_enterprise_importer": "shared_service",
    "hooks": "shared_service", "importer": "shared_service", "dependabot": "shared_service",
    "actions": "iaas", "actions_macos": "iaas", "codespaces": "iaas",
}
#: V3LUM-authored roles for cloudcheck provider names (never cloudcheck code). cloudcheck tags alone
#: are not enough (Cloudflare is tagged 'waf', GitHub 'cdn'); providers whose published space mixes
#: CDN edges with rented compute (Akamai includes Linode AS63949, GitHub includes Actions/Azure runner
#: ranges, Gcore, Arvancloud) are provider_network so C2 on rented compute is never hidden.
CLOUDCHECK_ROLES: dict[str, str] = {
    # pure CDN / WAF / anti-DDoS edges (shared)
    "Cloudflare": "cdn_edge", "Cloudfront": "cdn_edge", "Fastly": "cdn_edge", "Imperva": "cdn_edge", "Sucuri": "cdn_edge",
    "Bunnycdn": "cdn_edge", "Cachefly": "cdn_edge", "Cdnetworks": "cdn_edge", "DDoSGuard": "cdn_edge", "Qrator": "cdn_edge",
    "Stormwall": "cdn_edge", "X4b": "cdn_edge", "Quiccloud": "cdn_edge", "Gocache": "cdn_edge", "Baidu": "cdn_edge",
    # multi-tenant hosting, object storage and SaaS front doors (shared)
    "Microsoft365": "shared_service", "Salesforce": "shared_hosting", "Zoho": "shared_hosting", "Heroku": "shared_hosting",
    "Backblaze": "shared_hosting", "Wasabi": "shared_hosting",
    # security-proxy egress shared by many tenants
    "Zscaler": "shared_proxy", "Iboss": "shared_proxy",
    # mixed CDN + rented compute, or whole provider space: not noise
    "Akamai": "provider_network", "GitHub": "provider_network", "Gcore": "provider_network", "Arvancloud": "provider_network",
    "Kinx": "provider_network", "Lgtelecom": "provider_network", "Skbroadband": "provider_network", "Amazon": "provider_network",
    "Google": "provider_network", "Microsoft": "provider_network", "Cisco": "provider_network", "Dell": "provider_network",
    "HPE": "provider_network",
    # rented compute
    "Oracle": "iaas", "DigitalOcean": "iaas", "Hetzner": "iaas", "OVH": "iaas", "Vultr": "iaas", "Leaseweb": "iaas",
    "Kamatera": "iaas", "Scaleway": "iaas", "Upcloud": "iaas", "Hostway": "iaas", "Rackspace": "iaas", "Alibaba": "iaas",
    "Tencent": "iaas", "Huawei": "iaas", "Yandex": "iaas", "Navercloud": "iaas", "Nhncloud": "iaas", "Ktcloud": "iaas",
    "Gabia": "iaas", "IBM": "iaas",
}
#: cloudcheck providers never labelled as cloud (government networks are not cloud infrastructure).
CLOUDCHECK_SKIP_TAGS = frozenset({"gov"})


class CloudRecord(NamedTuple):
    """One provider range with its V3LUM role (``official`` False for cloudcheck runtime data)."""

    cidr: str
    provider: str
    service: str
    region: str
    role: str
    source: str  # dataset name
    generic: bool = False  # a superset label (AWS 'AMAZON', goog.json, whole-provider cloudcheck space)
    official: bool = True


@dataclass
class ParsedRanges:
    """Parser output: records plus change-detection metadata and the entries that were dropped."""

    records: list[CloudRecord] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    skipped: int = 0  # invalid CIDRs
    too_broad: int = 0  # blocks broader than MIN_PREFIXLEN (a corrupted file never labels the Internet)


_HTML_START = re.compile(rb"^\s*(?:<!doctype\s+html|<html\b|<head\b|<body\b|<\?xml\b|<title\b)", re.I)


def _bytes(raw: Any) -> bytes | None:
    if isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
    elif isinstance(raw, str):
        data = raw.encode("utf-8")
    elif isinstance(raw, Path):
        try:
            data = raw.read_bytes()
        except OSError:
            return None
    else:
        return None
    return data[3:] if data.startswith(b"\xef\xbb\xbf") else data


def looks_like_html(raw: Any) -> bool:
    data = _bytes(raw)
    return bool(data) and bool(_HTML_START.match(data[:1024]))


def _load_json(raw: Any, label: str) -> tuple[Any, str]:
    if isinstance(raw, (dict, list)):
        return raw, ""
    data = _bytes(raw)
    if data is None:
        return None, f"{label}: unsupported body"
    if not data.strip():
        return None, f"{label}: empty body"
    if looks_like_html(data):
        return None, f"{label}: an HTML page came back instead of the dataset"
    try:
        return json.loads(data.decode("utf-8", errors="replace")), ""
    except (ValueError, RecursionError) as exc:
        return None, f"{label}: malformed JSON ({str(exc)[:80]})"


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _accept(value: Any, parsed: ParsedRanges) -> str | None:
    net = as_network(value) if isinstance(value, str) else None
    if net is None:
        parsed.skipped += 1
        return None
    if net.prefixlen < MIN_PREFIXLEN[net.version]:
        parsed.too_broad += 1
        return None
    return str(net)


def parse_aws_ip_ranges(raw: Any) -> ParsedRanges:
    """AWS ip-ranges.json: one record per (prefix, service); 'AMAZON' is the generic superset label."""
    out = ParsedRanges()
    obj, err = _load_json(raw, "aws ip-ranges.json")
    if err or not isinstance(obj, dict):
        out.error = err or "aws ip-ranges.json: not a JSON object"
        return out
    if not isinstance(obj.get("prefixes"), list):
        out.error = "aws ip-ranges.json: no 'prefixes' list"
        return out
    for key, fieldname in (("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")):
        for item in _list(obj.get(key)):
            item = _dict(item)
            cidr = _accept(item.get(fieldname), out)
            if not cidr:
                continue
            service = (_text(item.get("service")) or "AMAZON").upper()
            out.records.append(CloudRecord(cidr, "AWS", service, _text(item.get("region")), AWS_SERVICE_ROLES.get(service, "provider_network"),
                                           "cloud_ranges_aws.json", generic=service == "AMAZON"))
    out.meta = {"sync_token": _text(obj.get("syncToken")), "created": _text(obj.get("createDate"))}
    return out


def _parse_google(raw: Any, dataset: str, label: str, provider: str, role: str, generic: bool) -> ParsedRanges:
    out = ParsedRanges()
    obj, err = _load_json(raw, label)
    if err or not isinstance(obj, dict):
        out.error = err or f"{label}: not a JSON object"
        return out
    if not isinstance(obj.get("prefixes"), list):
        out.error = f"{label}: no 'prefixes' list"
        return out
    for item in obj["prefixes"]:
        item = _dict(item)
        cidr = _accept(item.get("ipv4Prefix") or item.get("ipv6Prefix"), out)
        if cidr:
            out.records.append(CloudRecord(cidr, provider, _text(item.get("service")) or provider, _text(item.get("scope")), role, dataset, generic=generic))
    out.meta = {"sync_token": _text(obj.get("syncToken")), "created": _text(obj.get("creationTime"))}
    return out


def parse_gcp_cloud(raw: Any) -> ParsedRanges:
    """Google cloud.json: customer-usable Google Cloud ranges per region -> rented compute (iaas)."""
    return _parse_google(raw, "cloud_ranges_gcp_cloud.json", "google cloud.json", "Google Cloud", "iaas", False)


def parse_google_goog(raw: Any) -> ParsedRanges:
    """Google goog.json: every Google range. Generic: an address in goog.json but in no cloud.json
    range is a Google front end / Google service (a shared edge, cond 6)."""
    return _parse_google(raw, "cloud_ranges_google_goog.json", "google goog.json", "Google", "cdn_edge", True)


def _parse_lines(raw: Any, dataset: str, label: str, provider: str, service: str, role: str) -> ParsedRanges:
    out = ParsedRanges()
    data = _bytes(raw)
    if data is None:
        out.error = f"{label}: unsupported body"
        return out
    if looks_like_html(data):
        out.error = f"{label}: an HTML page came back instead of the CIDR list"
        return out
    for line in data.decode("utf-8", errors="replace").splitlines():
        text = line.split("#", 1)[0].strip()
        if not text:
            continue
        cidr = _accept(text, out)
        if cidr:
            out.records.append(CloudRecord(cidr, provider, service, "", role, dataset))
    return out


def parse_cloudflare_v4(raw: Any) -> ParsedRanges:
    """Cloudflare ips-v4 (one CIDR per line): CDN/WAF edges."""
    return _parse_lines(raw, "cloud_ranges_cloudflare_v4.txt", "cloudflare ips-v4", "Cloudflare", "CDN edge", "cdn_edge")


def parse_cloudflare_v6(raw: Any) -> ParsedRanges:
    """Cloudflare ips-v6 (one CIDR per line): CDN/WAF edges."""
    return _parse_lines(raw, "cloud_ranges_cloudflare_v6.txt", "cloudflare ips-v6", "Cloudflare", "CDN edge", "cdn_edge")


def parse_fastly(raw: Any) -> ParsedRanges:
    """Fastly public-ip-list ({'addresses': [...], 'ipv6_addresses': [...]}): CDN edges."""
    out = ParsedRanges()
    obj, err = _load_json(raw, "fastly public-ip-list")
    if err or not isinstance(obj, dict):
        out.error = err or "fastly public-ip-list: not a JSON object"
        return out
    if not isinstance(obj.get("addresses"), list):
        out.error = "fastly public-ip-list: no 'addresses' list"
        return out
    for key in ("addresses", "ipv6_addresses"):
        for value in _list(obj.get(key)):
            cidr = _accept(value, out)
            if cidr:
                out.records.append(CloudRecord(cidr, "Fastly", "CDN edge", "", "cdn_edge", "cloud_ranges_fastly.json"))
    return out


def parse_oracle_oci(raw: Any) -> ParsedRanges:
    """Oracle OCI public_ip_ranges.json: regions[].cidrs[{cidr, tags}] (OCI iaas, OSN shared service,
    OBJECT_STORAGE shared hosting)."""
    out = ParsedRanges()
    obj, err = _load_json(raw, "oracle public_ip_ranges.json")
    if err or not isinstance(obj, dict):
        out.error = err or "oracle public_ip_ranges.json: not a JSON object"
        return out
    if not isinstance(obj.get("regions"), list):
        out.error = "oracle public_ip_ranges.json: no 'regions' list"
        return out
    for region in obj["regions"]:
        region = _dict(region)
        name = _text(region.get("region"))
        for item in _list(region.get("cidrs")):
            item = _dict(item)
            cidr = _accept(item.get("cidr"), out)
            if not cidr:
                continue
            tags = {str(t).upper() for t in _list(item.get("tags"))}
            role, service = "provider_network", "Oracle"
            for tag, trole, tservice in ORACLE_TAG_ROLES:
                if tag in tags:
                    role, service = trole, tservice
                    break
            out.records.append(CloudRecord(cidr, "Oracle", service, name, role, "cloud_ranges_oracle_oci.json"))
    out.meta = {"created": _text(obj.get("last_updated_timestamp"))}
    return out


def parse_github_meta(raw: Any) -> ParsedRanges:
    """GitHub meta: {hooks, web, api, git, packages, pages, actions, ...: [cidrs]}. Unknown keys and
    non-list values are ignored; a JSON {'message': ...} without range lists is an error answer."""
    out = ParsedRanges()
    obj, err = _load_json(raw, "github meta")
    if err or not isinstance(obj, dict):
        out.error = err or "github meta: not a JSON object"
        return out
    if not any(isinstance(obj.get(k), list) for k in GITHUB_META_ROLES):
        message = _text(obj.get("message"))
        out.error = f"github meta: no range lists{f' ({message[:120]})' if message else ''}"
        return out
    for key, role in GITHUB_META_ROLES.items():
        for value in _list(obj.get(key)):
            cidr = _accept(value, out)
            if cidr:
                out.records.append(CloudRecord(cidr, "GitHub", key, "", role, "cloud_ranges_github_meta.json"))
    return out


def parse_cloudcheck(raw: Any) -> ParsedRanges:
    """cloudcheck cloud_providers_v3.json (runtime data only, cond 3): {Provider: {cidrs, tags, ...}}.

    Only CIDRs are read (cond 5: IP/CIDR input). Roles come from the V3LUM table
    :data:`CLOUDCHECK_ROLES`; government entries are skipped; a provider missing from the table is
    labelled provider_network (not noise) until a reviewer gives it a role. Records carry
    ``official=False`` so the providers' own files always win."""
    out = ParsedRanges()
    obj, err = _load_json(raw, "cloudcheck")
    if err or not isinstance(obj, dict):
        out.error = err or "cloudcheck: not a JSON object"
        return out
    skipped: list[str] = []
    providers = 0
    for name, spec in obj.items():
        if not isinstance(spec, dict) or not isinstance(spec.get("cidrs"), list):
            continue
        providers += 1
        tags = sorted({str(t).lower() for t in _list(spec.get("tags")) if isinstance(t, str)})
        if CLOUDCHECK_SKIP_TAGS & set(tags):
            skipped.append(str(name))
            continue
        role = CLOUDCHECK_ROLES.get(str(name), "provider_network")
        display = _text(spec.get("name")) or str(name)
        service = ",".join(tags) or "cloudcheck"
        for value in spec["cidrs"]:
            cidr = _accept(value, out)
            if cidr:
                out.records.append(CloudRecord(cidr, display, service, "", role, "cloud_ranges_cloudcheck.json",
                                               generic=role == "provider_network", official=False))
    if not providers:
        out.error = "cloudcheck: no provider entries with a 'cidrs' list"
        return out
    out.meta = {"providers": providers, "skipped_providers": sorted(skipped)}
    return out


# ======================================================================================
# Dataset registrations (P034 cond 2-4)
# ======================================================================================


@dataclass(frozen=True)
class RangeDataset:
    name: str
    url: str
    source: str
    parser: Callable[[Any], ParsedRanges]
    min_bytes: int
    min_entries: int
    expect: str
    licence: str
    attribution: str
    description: str
    essential: bool = True


def _validator(spec: RangeDataset) -> Callable[[Path], bool]:
    """validate(path) of the dataset manager: parse success and entry count before the new copy
    replaces the cached one (the manager checks the size, HTML pages and the JSON/lines shape first)."""

    def validate(path: Path) -> bool:
        data = Path(path).read_bytes()
        if looks_like_html(data):
            raise ValueError(f"{spec.name}: an HTML page came back instead of the dataset")
        parsed = spec.parser(data)
        if parsed.error:
            raise ValueError(parsed.error)
        if len(parsed.records) < spec.min_entries:
            raise ValueError(f"{spec.name}: too few valid entries ({len(parsed.records)} < {spec.min_entries})")
        return True

    return validate


_PUBLIC = "public provider publication (no licence stated; runtime download, never bundled)"
#: Validation thresholds sit at ~25-50% of the sizes observed on 2026-11-26, so normal churn passes
#: and truncated, HTML or error bodies fail (the last good copy is kept).
DATASETS: tuple[RangeDataset, ...] = (
    RangeDataset("cloud_ranges_aws.json", "https://ip-ranges.amazonaws.com/ip-ranges.json", "aws.ip_ranges", parse_aws_ip_ranges,
                 500_000, 5000, "json", _PUBLIC, "AWS IP address ranges (https://ip-ranges.amazonaws.com/ip-ranges.json), Amazon Web Services",
                 "AWS published IP ranges with region and service (EC2, S3, CloudFront...)"),
    RangeDataset("cloud_ranges_gcp_cloud.json", "https://www.gstatic.com/ipranges/cloud.json", "gstatic.cloud_ip_ranges", parse_gcp_cloud,
                 20_000, 300, "json", _PUBLIC, "Google Cloud IP ranges (https://www.gstatic.com/ipranges/cloud.json), Google LLC",
                 "Google Cloud customer ranges per region"),
    RangeDataset("cloud_ranges_google_goog.json", "https://www.gstatic.com/ipranges/goog.json", "gstatic.google_ip_ranges", parse_google_goog,
                 1_000, 50, "json", _PUBLIC, "Google IP ranges (https://www.gstatic.com/ipranges/goog.json), Google LLC",
                 "every Google range (front ends = goog.json minus cloud.json)"),
    RangeDataset("cloud_ranges_cloudflare_v4.txt", "https://www.cloudflare.com/ips-v4/", "cloudflare.ips", parse_cloudflare_v4,
                 100, 10, "lines", _PUBLIC, "Cloudflare IP ranges (https://www.cloudflare.com/ips/), Cloudflare, Inc.",
                 "Cloudflare IPv4 edge ranges"),
    RangeDataset("cloud_ranges_cloudflare_v6.txt", "https://www.cloudflare.com/ips-v6/", "cloudflare.ips", parse_cloudflare_v6,
                 50, 5, "lines", _PUBLIC, "Cloudflare IP ranges (https://www.cloudflare.com/ips/), Cloudflare, Inc.",
                 "Cloudflare IPv6 edge ranges"),
    RangeDataset("cloud_ranges_fastly.json", "https://api.fastly.com/public-ip-list", "fastly.public_ip_list", parse_fastly,
                 200, 10, "json", _PUBLIC, "Fastly public IP list (https://api.fastly.com/public-ip-list), Fastly, Inc.",
                 "Fastly edge ranges"),
    RangeDataset("cloud_ranges_oracle_oci.json", "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json", "oracle.oci_public_ip_ranges",
                 parse_oracle_oci, 50_000, 300, "json", _PUBLIC,
                 "Oracle Cloud Infrastructure public IP ranges (https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json), Oracle",
                 "Oracle OCI, OSN and Object Storage ranges per region"),
    RangeDataset("cloud_ranges_github_meta.json", "https://api.github.com/meta", "github.cloud_ranges_meta", parse_github_meta,
                 2_000, 30, "json", _PUBLIC, "GitHub meta API (https://api.github.com/meta), GitHub, Inc.",
                 "GitHub service ranges (pages, web, api, actions...)", essential=False),
    RangeDataset("cloud_ranges_cloudcheck.json",
                 "https://raw.githubusercontent.com/blacklanternsecurity/cloudcheck/refs/heads/stable/cloud_providers_v3.json",
                 "github.cloud_ranges_cloudcheck", parse_cloudcheck, 500_000, 10_000, "json",
                 "AGPL-3.0 (cloudcheck repository data; runtime download only, never bundled, committed or code-copied, A6)",
                 "Cloud provider signatures from blacklanternsecurity/cloudcheck (https://github.com/blacklanternsecurity/cloudcheck), "
                 "AGPL-3.0 repository; downloaded at run time, never redistributed",
                 "cloudcheck consolidated cloud/CDN provider CIDRs (community data, official files win)", essential=False),
)
DATASET_BY_NAME: dict[str, RangeDataset] = {spec.name: spec for spec in DATASETS}

for _spec in DATASETS:
    register_dataset(
        _spec.name, _spec.url, ttl=86400, description=f"cloud_ranges: {_spec.description}", licence=_spec.licence, terms_class="open",
        attribution=_spec.attribution, source=_spec.source, validate=_validator(_spec), min_bytes=_spec.min_bytes, expect=_spec.expect,
        essential=_spec.essential,
    )


# ======================================================================================
# Classification (cond 5-7, 9)
# ======================================================================================


def _label(rec: CloudRecord, role: str) -> str:
    src, svc, region = rec.source, rec.service, rec.region
    if src == "cloud_ranges_aws.json":
        if svc in ("CLOUDFRONT", "CLOUDFRONT_ORIGIN_FACING"):
            return "AWS CloudFront CDN edge"
        if svc == "GLOBALACCELERATOR":
            return "AWS Global Accelerator anycast edge"
        if svc == "AMAZON":
            return f"AWS {region or 'GLOBAL'} (Amazon network)"
        return f"AWS {region or 'GLOBAL'} {svc}"
    if src == "cloud_ranges_gcp_cloud.json":
        return f"Google Cloud {region or 'global'}"
    if src == "cloud_ranges_google_goog.json":
        return "Google front end (Google services)"
    if src in ("cloud_ranges_cloudflare_v4.txt", "cloud_ranges_cloudflare_v6.txt"):
        return "Cloudflare CDN edge"
    if src == "cloud_ranges_fastly.json":
        return "Fastly CDN edge"
    if src == "cloud_ranges_oracle_oci.json":
        words = {"iaas": "Oracle OCI", "shared_service": "Oracle OSN (shared service)", "shared_hosting": "Oracle Object Storage"}
        return f"{words.get(role, 'Oracle')} {region}".strip()
    if src == "cloud_ranges_github_meta.json":
        if role == "shared_hosting":
            return "GitHub Pages shared hosting"
        if role == "iaas":
            return f"GitHub {svc} runner range"
        return f"GitHub {svc} service"
    words = {"cdn_edge": "CDN edge", "shared_hosting": "shared hosting", "shared_service": "shared service",
             "shared_proxy": "shared security-proxy egress", "iaas": "IaaS compute", "provider_network": "network"}
    return f"{rec.provider} {words.get(role, role)} (cloudcheck)"


def classify(chain: Iterable[CloudRecord]) -> dict[str, Any] | None:
    """Labels of one address from its index chain (innermost first); None when no record matched.

    Official provider files win over cloudcheck (A6: official files preferred); a specific record
    wins over a generic one; among the records of the innermost chosen block the first role of
    :data:`ROLE_PRECEDENCE` wins (non-noise first) and the others are listed in ``also``.
    """
    chain = [r for r in chain if isinstance(r, CloudRecord)]
    if not chain:
        return None
    official = [r for r in chain if r.official]
    specific = [r for r in official if not r.generic]
    pool = specific or official or [r for r in chain if not r.generic] or chain
    top = pool[0].cidr
    level = [r for r in pool if r.cidr == top]
    roles = {r.role for r in level}
    role = next((x for x in ROLE_PRECEDENCE if x in roles), level[0].role)
    primary = next(r for r in level if r.role == role)
    is_cdn, is_hosting, noise = ROLE_FLAGS.get(role, (False, False, False))
    label = _label(primary, role)
    also: list[str] = []
    for rec in level:
        if rec is primary:
            continue
        other = _label(rec, rec.role)
        if other != label and other not in also:
            also.append(other)
    return {
        "is_cloud": True,
        "is_cdn": is_cdn,
        "is_hosting": is_hosting,
        "noise": noise,
        "role": role,
        "provider": primary.provider,
        "service": primary.service,
        "region": primary.region,
        "label": label,
        "also": also,
        "matched_cidr": top,
        "sources": sorted({r.source for r in level}),
        "official": primary.official,
        "verdict_lifetime_days": None if noise else VERDICT_LIFETIME_DAYS,
        "pivot_note": NOISE_PIVOT_NOTE if noise else "",
        "third_party_hosted": noise,
    }


# ======================================================================================
# Loading the local copies (per-version caches, thread-safe)
# ======================================================================================

_LOCK = threading.Lock()
_PARSED: dict[tuple[str, str], list[CloudRecord]] = {}
_INDEXES: dict[tuple[tuple[str, str], ...], RangeIndex] = {}
_CACHE_LIMIT = 2


def _parsed_records(name: str, sha: str, path: Path) -> list[CloudRecord]:
    """Records of one dataset version (parsed once per sha256). Raises DatasetError when the local
    copy no longer parses (a corrupted file is never read as 'no ranges')."""
    key = (name, sha)
    with _LOCK:
        hit = _PARSED.get(key)
    if hit is not None:
        return hit
    spec = DATASET_BY_NAME[name]
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise DatasetError(f"dataset {name}: unreadable local copy ({exc})", name=name) from exc
    parsed = spec.parser(data)
    if parsed.error:
        raise DatasetError(f"dataset {name}: local copy does not parse ({parsed.error}): run v3lum data update {name}", name=name)
    with _LOCK:
        for old in [k for k in _PARSED if k[0] == name and k != key]:
            del _PARSED[old]
        _PARSED[key] = parsed.records
    return parsed.records


def _index_for(versions: dict[str, tuple[str, list[CloudRecord]]]) -> RangeIndex:
    key = tuple(sorted((name, sha) for name, (sha, _records) in versions.items()))
    with _LOCK:
        hit = _INDEXES.get(key)
        if hit is not None:
            return hit
        index = RangeIndex((rec.cidr, rec) for _name, (_sha, records) in sorted(versions.items()) for rec in records)
        while len(_INDEXES) >= _CACHE_LIMIT:
            _INDEXES.pop(next(iter(_INDEXES)))
        _INDEXES[key] = index
        return index


@dataclass
class _Loaded:
    versions: dict[str, tuple[str, list[CloudRecord]]] = field(default_factory=dict)
    ages: dict[str, float] = field(default_factory=dict)
    missing: dict[str, str] = field(default_factory=dict)  # dataset -> why it could not be loaded


def _load(data: Any, names: Iterable[str]) -> _Loaded:
    """Fetch (download/refresh through the dataset manager when a runtime is bound) and parse the
    datasets; failures are recorded per dataset, never raised."""
    out = _Loaded()
    for name in names:
        try:
            path = Path(data.fetch(name))
            info = data.info(name)
            records = _parsed_records(name, str(info.sha256 or ""), path)
        except DatasetUnavailable as exc:
            out.missing[name] = str(exc) or "not downloaded"
            continue
        except DatasetError as exc:
            out.missing[name] = str(exc) or "download or validation failed"
            continue
        out.versions[name] = (str(info.sha256 or ""), records)
        if info.age_hours is not None:
            out.ages[name] = round(float(info.age_hours) / 24.0, 2)
    return out


def local_classification(value: Any) -> dict[str, Any] | None:
    """Label of an IP/CIDR from the local dataset copies only - never a download, never a network
    call (the reference for the core noise-provider hook, AR06, and the ACTIVE scope guard).
    None when no loaded range matches or no dataset is present."""
    loaded = _load(DataStore(None).scoped(), DATASET_BY_NAME)
    if not loaded.versions:
        return None
    index = _index_for(loaded.versions)
    chain = index.lookup_cidr(value) if "/" in str(value) else index.lookup(value)
    return classify(chain)


def noise_kind_for(value: Any) -> str | None:
    """Noise kind ('cdn' | 'hosting' | 'saas' | 'cloud') of a shared CDN/cloud address from the local
    copies, or None (rented compute and unknown addresses are not noise). For the core AR06 hook."""
    cls = local_classification(value)
    return NOISE_KIND_OF_ROLE.get(cls["role"]) if cls and cls.get("noise") else None


def dataset_status(data: Any = None) -> dict[str, dict[str, Any]]:
    """{dataset: {present, age_days, stale}} of the local copies (for doctor; no download)."""
    view = data if data is not None else DataStore(None).scoped()
    out: dict[str, dict[str, Any]] = {}
    for spec in DATASETS:
        try:
            info = view.info(spec.name)
        except (ValueError, OSError):
            out[spec.name] = {"present": False, "age_days": None, "stale": True}
            continue
        age = None if info.age_hours is None else round(float(info.age_hours) / 24.0, 2)
        out[spec.name] = {"present": bool(info.present), "age_days": age, "stale": bool(info.stale)}
    return out


def active_guard(value: Any, *, scope_lists_target: bool = False, max_age_days: float = ACTIVE_MAX_DATASET_AGE_DAYS,
                 status: dict[str, dict[str, Any]] | None = None, classification: dict[str, Any] | None = None) -> str | None:
    """P034 cond 8 / A7 reference: why an ACTIVE network probe of ``value`` must be refused, else None.

    Fail closed: an essential range dataset missing or older than ``max_age_days`` refuses every
    ACTIVE network probe; an address labelled as a shared CDN/hosting front door is refused unless
    the scope file lists that IP or range (``scope_lists_target``). Local copies only."""
    status = status if status is not None else dataset_status()
    for spec in DATASETS:
        if not spec.essential:
            continue
        entry = status.get(spec.name) or {}
        age = entry.get("age_days")
        if not entry.get("present") or age is None:
            return f"refused: cloud range dataset {spec.name} missing (fail closed): run v3lum data update --essential"
        if float(age) > max_age_days:
            return f"refused: cloud range dataset {spec.name} is {float(age):.1f} days old (> {max_age_days:g}, fail closed): run v3lum data update --essential"
    cls = classification if classification is not None else local_classification(value)
    if cls and cls.get("noise") and not scope_lists_target:
        return f"refused: {value} is shared CDN/cloud infrastructure ({cls.get('label')}); list the IP or range in the scope file"
    return None


# ======================================================================================
# The module
# ======================================================================================

FINDING_TITLES: dict[str, str] = {
    "cdn_edge": "Shared CDN edge address",
    "shared_hosting": "Shared hosting address",
    "shared_service": "Shared cloud service endpoint",
    "shared_proxy": "Shared security-proxy egress address",
    "iaas": "Cloud compute (IaaS) address",
    "provider_network": "Cloud provider network address",
}


@register
class CloudRanges(Module):
    name = "cloud_ranges"
    title = "Cloud/CDN provider ranges"
    description = (
        "Labels an IP or CIDR as CDN edge, shared hosting, cloud compute... from the official AWS, Google, Cloudflare, "
        "Fastly, Oracle and GitHub range files plus cloudcheck runtime data, matched offline."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6, T.CIDR}
    produces: frozenset[T] = frozenset()
    tags = {"offline", "free"}
    reference = "https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html"
    notice = (
        "Offline lookup in downloaded provider range files (the address never leaves the machine). cloudcheck data "
        "(AGPL-3.0 repository) is downloaded at run time only and never bundled; the providers' own files win over it."
    )
    # ---- contract v2 declarations --------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # matching is local; only the dataset manager downloads the static files
    hosts = ()
    sources = tuple(dict.fromkeys(spec.source for spec in DATASETS))
    expected_latency = 0.3  # warm lookups; a first run downloads the files (~6 s live)
    timeout = 90.0  # a first run may download the files (all below 5 MB) before matching
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.CIDR:
            net = as_network(entity.value)
            return net is not None and is_public_address(net.network_address)
        return is_public_address(entity.value)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        allowed = ctx.allowed_sources
        names = [spec.name for spec in DATASETS if spec.source in allowed]
        if not names:
            return res.mark(Status.SKIPPED, "no cloud range source allowed in this run", reason_code="policy")
        loaded = _load(ctx.data, names)
        self._report_missing(res, loaded)
        if not loaded.versions:
            return res.mark(Status.UNAVAILABLE, "cloud range datasets missing: could not verify (run v3lum data update --essential)", reason_code="dataset")
        index = _index_for(loaded.versions)
        is_cidr = entity.type is T.CIDR
        chain = index.lookup_cidr(entity.value) if is_cidr else index.lookup(entity.value)
        cls = classify(chain)
        ages = {name: loaded.ages[name] for name in names if name in loaded.ages}
        if cls is None:
            if is_cidr and self._partial_overlap(res, index, entity.value, ages):
                return res
            if loaded.missing:
                missing = ", ".join(sorted(loaded.missing))
                return res.mark(
                    Status.UNAVAILABLE,
                    f"not in the loaded cloud/CDN ranges, but {missing} could not be loaded: could not verify",
                    reason_code="dataset",
                )
            res.attr("dataset_age_days", ages)
            return res.mark(Status.EMPTY)
        self._record(res, cls, ages)
        return res

    # ---- helpers --------------------------------------------------------------------------
    @staticmethod
    def _report_missing(res: ModuleResult, loaded: _Loaded) -> None:
        per_source: dict[str, list[str]] = {}
        for name, why in sorted(loaded.missing.items()):
            per_source.setdefault(DATASET_BY_NAME[name].source, []).append(f"{name}: {why}"[:300])
        for source, reasons in per_source.items():
            res.source_status(source, Status.UNAVAILABLE, reason_code="dataset", reason="; ".join(reasons))

    @staticmethod
    def _record(res: ModuleResult, cls: dict[str, Any], ages: dict[str, float]) -> None:
        res.attr("is_cloud", True)
        res.attr("is_cdn", cls["is_cdn"])
        res.attr("is_hosting", cls["is_hosting"])
        res.attr("cloud_provider", cls["provider"])
        res.attr("cloud_service", cls["service"])
        res.attr("cloud_region", cls["region"])
        res.attr("cloud_role", cls["role"])
        res.attr("cloud_label", cls["label"])
        res.attr("cloud_range", cls["matched_cidr"])
        res.attr("cloud_also", cls["also"])
        res.attr("cloud_sources", cls["sources"])
        if cls["noise"]:
            res.attr("third_party_hosted", True)
            res.attr("pivot_note", cls["pivot_note"])
        else:
            res.attr("verdict_lifetime_days", cls["verdict_lifetime_days"])
        res.attr("dataset_age_days", ages)
        role = cls["role"]
        source_word = "provider's own range file" if cls["official"] else "cloudcheck runtime data"
        if cls["noise"]:
            text = (
                f"{cls['label']} ({cls['matched_cidr']}, {source_word}). Shared infrastructure: {NOISE_PIVOT_NOTE}; "
                "no IP-reputation or co-hosting expansion to co-tenants. Findings about the domain or URL itself still apply."
            )
            tags = ["noise", "infrastructure"]
        else:
            text = (
                f"{cls['label']} ({cls['matched_cidr']}, {source_word}). Rented or provider compute: reputation applies, "
                f"but verdicts on this address expire after {VERDICT_LIFETIME_DAYS} days because cloud addresses are reassigned."
            )
            tags = ["infrastructure"]
        res.finding(
            FINDING_TITLES.get(role, "Cloud provider network address"),
            "info",
            text,
            data={"label": cls["label"], "role": role, "provider": cls["provider"], "service": cls["service"], "region": cls["region"],
                  "range": cls["matched_cidr"], "also": cls["also"], "sources": cls["sources"], "dataset_age_days": ages},
            tags=tags,
        )
        stale = sorted(name for name, age in ages.items() if age > ACTIVE_MAX_DATASET_AGE_DAYS)
        if stale:
            res.finding(
                "Cloud range data older than 7 days",
                "info",
                f"{', '.join(stale)} could not be refreshed: the last good copy is used. ACTIVE network modules refuse to run on "
                "range data older than 7 days (fail closed): run v3lum data update --essential.",
                data={"datasets": {name: ages[name] for name in stale}},
                tags=["info"],
            )

    @staticmethod
    def _partial_overlap(res: ModuleResult, index: RangeIndex, value: str, ages: dict[str, float]) -> bool:
        labels: list[str] = []
        for rec in index.overlapping(value, limit=200):
            cls = classify([rec])
            if cls and cls["label"] not in labels:
                labels.append(cls["label"])
        if not labels:
            return False
        labels = labels[:20]
        res.attr("dataset_age_days", ages)
        res.finding(
            "Network partially overlaps cloud/CDN ranges",
            "info",
            f"{value} is not inside a single provider range but overlaps: {', '.join(labels)}. Look the addresses up one by one.",
            data={"labels": labels},
            tags=["infrastructure"],
        )
        return True
