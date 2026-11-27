"""Offline IP -> ASN context from local datasets: IPtoASN (PDDL) and bgp.tools asns.csv (P047).

Batch p1-G02-2, proposal P047 ``ip_offline_db`` (DB-IP Lite mmdb lookups live in ``ip_offline_geo``
because they need the optional ``maxminddb`` package; the module-level package gate would
otherwise switch the IPtoASN lookups off too). Final conditions implemented here:

* c1/c2 - datasets only through ``v3lum data update`` (``large=True``: never downloaded by a scan or
  by this module); a missing dataset is UNAVAILABLE reason_code 'dataset' ('run v3lum data
  update ...'), never EMPTY; the dataset name and age are shown (attribute ``dataset_age``).
* c3 - lookups are local: disclosure 'none' (allowed at TLP:RED, shares_input False).
* c4 - IPtoASN loads into the shared IP-range index: :class:`IntervalIndex` below is the
  "sorted integer intervals + bisect" index of P034 (IPv4 and IPv6). The core index announced by
  P034 does not exist yet, so the batch keeps one implementation here, shared by ``ip_blocklists``
  and the Tor modules; it moves to the core when the core one lands (core request).
* c5 - bgp.tools asns.csv only, with the descriptive contact User-Agent of the provider profile
  (setting ``contact_email``, a team role mailbox, P326); without the setting the source is
  SKIPPED reason_code 'config'. It labels hosting versus eyeball networks (``network_type``).
* c7/c8 - attribution in the dataset registrations and notices; the data is ASN/country context
  only and is never used to locate a person or household.

The module never downloads: ``v3lum data update`` (the dataset manager: conditional GET, gzip
through ``safe_extract`` with size caps, validation before an atomic replace) fetches the files.
"""

from __future__ import annotations

import bisect
import csv
import io
import ipaddress
import re
import socket
import threading
from array import array
from collections.abc import Iterable
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

from v3lum.core.datasets import DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

# ======================================================================================
# shared helpers (batch p1-G02-2): special-purpose addresses, ages, timestamps
# ======================================================================================

_SPECIAL_V4 = tuple(
    (ipaddress.ip_network(net), label)
    for net, label in (
        ("0.0.0.0/8", "this_network"),
        ("10.0.0.0/8", "rfc1918"),
        ("100.64.0.0/10", "cgnat"),
        ("127.0.0.0/8", "loopback"),
        ("169.254.0.0/16", "link_local"),
        ("172.16.0.0/12", "rfc1918"),
        ("192.0.0.0/24", "ietf_protocol"),
        ("192.0.2.0/24", "documentation"),
        ("192.88.99.0/24", "6to4_relay"),
        ("192.168.0.0/16", "rfc1918"),
        ("198.18.0.0/15", "benchmarking"),
        ("198.51.100.0/24", "documentation"),
        ("203.0.113.0/24", "documentation"),
        ("224.0.0.0/4", "multicast"),
        ("240.0.0.0/4", "reserved"),
    )
)
_SPECIAL_V6 = tuple(
    (ipaddress.ip_network(net), label)
    for net, label in (
        ("::/128", "unspecified"),
        ("::1/128", "loopback"),
        ("::ffff:0:0/96", "ipv4_mapped"),
        ("64:ff9b:1::/48", "nat64_local"),
        ("100::/64", "discard"),
        ("2001:db8::/32", "documentation"),
        ("3fff::/20", "documentation"),
        ("fc00::/7", "ula"),
        ("fe80::/10", "link_local"),
        ("fec0::/10", "site_local"),
        ("ff00::/8", "multicast"),
    )
)
_GLOBAL_UNICAST_V6 = ipaddress.ip_network("2000::/3")

#: Special-purpose labels treated as public space. Empty in production; the offline tests set
#: {'documentation'} because the fixtures replace real IPs with RFC 5737/3849 documentation
#: addresses (no personal data in fixtures) - the same seam the shared core index will need.
TEST_PUBLIC_LABELS: frozenset[str] = frozenset()

_U32 = "I" if array("I").itemsize >= 4 else "L"


def special_purpose(value: Any) -> str | None:
    """Label of the special-purpose block an IP/CIDR belongs to ('rfc1918', 'cgnat',
    'documentation', 'multicast', 'special_supernet', 'unallocated'...) or None for public space.

    P149 c4: bogon/RFC 1918 entries are dropped at load and never reported; the IP modules of the
    batch never look up (or send) special-purpose addresses. A supernet fully covered by special
    blocks (224.0.0.0/3) is special too.
    """
    if isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        net = value
    elif isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        net = ipaddress.ip_network(value)
    else:
        try:
            net = ipaddress.ip_network(str(value).strip(), strict=False)
        except ValueError:
            return "invalid"
    table = _SPECIAL_V4 if net.version == 4 else _SPECIAL_V6
    covered = 0
    for special, label in table:
        if label in TEST_PUBLIC_LABELS:
            continue
        if net.subnet_of(special):  # type: ignore[arg-type]
            return label
        if special.subnet_of(net):  # type: ignore[arg-type]
            covered += special.num_addresses
    if covered and covered >= net.num_addresses:
        return "special_supernet"
    if net.version == 6 and not net.subnet_of(_GLOBAL_UNICAST_V6):  # type: ignore[arg-type]
        return "special_supernet" if _GLOBAL_UNICAST_V6.subnet_of(net) else "unallocated"  # type: ignore[arg-type]
    return None


def ip_int(value: Any) -> tuple[int, int] | None:
    """(version, integer) of an IP literal (fast C conversion; brackets, ports and zones are not
    accepted), else None."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        if ":" in text:
            return 6, int.from_bytes(socket.inet_pton(socket.AF_INET6, text), "big")
        return 4, int.from_bytes(socket.inet_pton(socket.AF_INET, text), "big")
    except (OSError, ValueError):
        return None


def age_text(seconds: float | None) -> str:
    """'42 min', '5 h 3 min', '1 day', '12 days' ('age unknown' for None)."""
    if seconds is None:
        return "age unknown"
    seconds = max(0, int(seconds))
    if seconds < 60:
        return "< 1 min"
    if seconds < 3600:
        return f"{seconds // 60} min"
    if seconds < 86400:
        hours, rest = divmod(seconds, 3600)
        return f"{hours} h {rest // 60} min" if rest >= 60 else f"{hours} h"
    if seconds < 2 * 86400:
        return "1 day"
    return f"{seconds // 86400} days"


def parse_ts(value: Any) -> datetime | None:
    """Timestamp -> aware UTC datetime: epoch numbers, ISO 8601 ('Z', offsets, 'YYYY-MM-DD HH:MM:SS
    [UTC]'), RFC 1123 HTTP dates and the FireHOL 'Wed Nov 25 04:25:16 UTC 2026' form; else None."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        dt = datetime.fromisoformat(text.replace(" UTC", "").replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in ("%a %b %d %H:%M:%S UTC %Y", "%a %b %d %H:%M:%S %Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    try:
        dt = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iso_z(value: Any) -> str | None:
    """ISO 8601 UTC 'YYYY-MM-DDTHH:MM:SSZ' of a timestamp (None when unparsable)."""
    dt = parse_ts(value)
    return None if dt is None else dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def dataset_age_line(label: str, info: Any, now: datetime) -> str:
    """Coverage line 'IPtoASN v4, fetched 2026-11-26 (0 days)' for a DatasetInfo (P047 c2)."""
    fetched = parse_ts(getattr(info, "fetched_at", "") or "")
    if fetched is None:
        return f"{label}, age unknown"
    return f"{label}, fetched {fetched.strftime('%Y-%m-%d')} ({age_text((now - fetched).total_seconds())})"


#: TTL that never expires: reading a local copy without any refresh (P047 c1: 'only via v3lum data update').
NO_REFRESH_TTL = 10.0**12


def local_dataset(ctx: Any, name: str) -> tuple[Path, Any]:
    """(path, DatasetInfo) of the local copy of a registered dataset, never downloading or
    refreshing it. Raises DatasetUnavailable ('run v3lum data update <name>') when it is absent."""
    info = ctx.data.info(name)
    if not info.present:
        raise DatasetUnavailable(name, f"dataset {name} is not downloaded: run v3lum data update {name}")
    path = ctx.data.fetch(name, ttl=NO_REFRESH_TTL)
    return Path(path), ctx.data.info(name)


#: DatasetError.reason_code -> (Status, reason_code) for per-source statuses and module results.
_DATASET_FAILURE = {
    "challenge": (Status.BLOCKED, "challenge"),
    "geo_block": (Status.BLOCKED, "geo_block"),
    "login_wall": (Status.BLOCKED, "login_wall"),
    "circuit": (Status.BLOCKED, "circuit"),
    "hostile_host": (Status.BLOCKED, "hostile_host"),
    "rate_limited": (Status.RATE_LIMITED, "rate_limited"),
    "quota": (Status.QUOTA, "quota"),
    "config": (Status.SKIPPED, "config"),
    "offline": (Status.UNAVAILABLE, "offline"),
    "dataset": (Status.UNAVAILABLE, "dataset"),
    "timeout": (Status.ERROR, "timeout"),
}


def dataset_failure(exc: BaseException) -> tuple[Status, str]:
    """Status and canonical reason code of a dataset failure: never an absence (rule 5)."""
    if isinstance(exc, DatasetUnavailable):
        code = getattr(exc, "reason_code", "dataset")
        return (Status.UNAVAILABLE, "offline") if code == "offline" else (Status.UNAVAILABLE, "dataset")
    return _DATASET_FAILURE.get(str(getattr(exc, "reason_code", "") or "error"), (Status.ERROR, "error"))


def mark_dataset_failure(res: ModuleResult, exc: BaseException, what: str) -> ModuleResult:
    """End the run 'could not verify' for a dataset problem (never EMPTY)."""
    status, code = dataset_failure(exc)
    return res.mark(status, f"{what}: {exc} (could not verify)", reason_code=code)


# ======================================================================================
# the shared IP-range index (P034 semantics: sorted integer intervals + bisect)
# ======================================================================================


class IntervalIndex:
    """Sorted integer intervals + bisect for IPv4 and IPv6 (P034). Intervals may nest (blocklist
    CIDRs inside larger ones): ``lookup`` walks back from the bisect position while the running
    maximum of the interval ends still covers the address, so nested and disjoint sets (IPtoASN)
    use one structure. Add with :meth:`add`/:meth:`add_network`, then :meth:`freeze` once."""

    MAX_WALK = 200_000

    def __init__(self) -> None:
        self._raw: dict[int, list[tuple[int, int, int]]] = {4: [], 6: []}
        self._payloads: list[Any] = []
        self._starts: dict[int, Any] = {}
        self._ends: dict[int, Any] = {}
        self._maxend: dict[int, Any] = {}
        self._refs: dict[int, Any] = {}
        self._frozen = False

    def add(self, version: int, start: int, end: int, payload: Any) -> None:
        if self._frozen:
            raise RuntimeError("IntervalIndex is frozen")
        if start > end:
            start, end = end, start
        self._payloads.append(payload)
        self._raw[4 if version == 4 else 6].append((start, end, len(self._payloads) - 1))

    def add_network(self, net: ipaddress.IPv4Network | ipaddress.IPv6Network, payload: Any) -> None:
        self.add(net.version, int(net.network_address), int(net.broadcast_address), payload)

    def freeze(self) -> IntervalIndex:
        for version in (4, 6):
            items = sorted(self._raw[version], key=lambda t: (t[0], -t[1]))
            maxend: list[int] = []
            running = -1
            for _start, end, _ref in items:
                running = max(running, end)
                maxend.append(running)
            if version == 4:
                self._starts[4] = array(_U32, (s for s, _e, _r in items))
                self._ends[4] = array(_U32, (e for _s, e, _r in items))
                self._maxend[4] = array(_U32, maxend)
            else:
                self._starts[6] = [s for s, _e, _r in items]
                self._ends[6] = [e for _s, e, _r in items]
                self._maxend[6] = maxend
            self._refs[version] = array("L", (r for _s, _e, r in items))
            self._raw[version] = []
        self._frozen = True
        return self

    def __len__(self) -> int:
        if not self._frozen:
            return len(self._raw[4]) + len(self._raw[6])
        return len(self._starts[4]) + len(self._starts[6])

    def count(self, version: int) -> int:
        return len(self._starts.get(version, ())) if self._frozen else len(self._raw[version])

    def lookup_spans(self, ip: Any) -> list[tuple[int, int, Any]]:
        """(start, end, payload) of every interval containing ``ip`` (narrowest first)."""
        parsed = ip_int(ip) if not isinstance(ip, tuple) else ip
        if parsed is None or not self._frozen:
            return []
        version, value = parsed
        return [(s, e, p) for _w, s, e, p in sorted(self._hits(version, value, value), key=lambda t: t[0])]

    def lookup(self, ip: Any) -> list[Any]:
        """Payloads of every interval containing ``ip`` (narrowest first); [] when none."""
        return [p for _s, _e, p in self.lookup_spans(ip)]

    def first(self, ip: Any) -> Any:
        hits = self.lookup(ip)
        return hits[0] if hits else None

    def containing(self, version: int, start: int, end: int) -> list[Any]:
        """Payloads of the intervals that contain the whole range [start, end] (narrowest first)."""
        if not self._frozen:
            return []
        return [p for _w, _s, _e, p in sorted(self._hits(version, start, end), key=lambda t: t[0])]

    def within(self, version: int, start: int, end: int, limit: int = 1000) -> list[Any]:
        """Payloads of the intervals lying inside [start, end] (at most ``limit``)."""
        if not self._frozen:
            return []
        starts, ends, refs = self._starts[version], self._ends[version], self._refs[version]
        out = []
        i = bisect.bisect_left(starts, start)
        while i < len(starts) and starts[i] <= end and len(out) < limit:
            if ends[i] <= end:
                out.append(self._payloads[refs[i]])
            i += 1
        return out

    def _hits(self, version: int, start: int, end: int) -> list[tuple[int, int, int, Any]]:
        starts, ends, maxend, refs = self._starts[version], self._ends[version], self._maxend[version], self._refs[version]
        i = bisect.bisect_right(starts, start) - 1
        out = []
        steps = 0
        while i >= 0 and maxend[i] >= end and steps < self.MAX_WALK:
            if ends[i] >= end:
                out.append((ends[i] - starts[i], starts[i], ends[i], self._payloads[refs[i]]))
            i -= 1
            steps += 1
        return out


class DatasetMemo:
    """Parsed dataset objects per (name, sha256): parsed once per process, replaced when the
    dataset manager installs a new copy."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, tuple[str, Any]] = {}

    def get(self, name: str, sha256: str, build: Any) -> Any:
        with self._lock:
            hit = self._items.get(name)
            if hit and hit[0] == sha256 and sha256:
                return hit[1]
        value = build()
        with self._lock:
            self._items[name] = (sha256, value)
        return value

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


# ======================================================================================
# IPtoASN and bgp.tools parsers
# ======================================================================================

#: Minimum rows a downloaded IPtoASN file must have (the real files: v4 ~540k, v6 ~179k rows).
#: Tests lower them for the minimised fixtures.
MIN_IPTOASN_ROWS = {4: 100_000, 6: 20_000}
#: Minimum ASNs in bgp.tools asns.csv (the real file lists more than 100k).
MIN_BGPTOOLS_ASNS = 50_000
BGPTOOLS_HEADER = ["asn", "name", "class", "cc"]
#: bgp.tools class -> network type (hosting versus eyeball networks, P047 c5).
BGPTOOLS_NETWORK_TYPE = {"eyeball": "eyeball", "content": "hosting", "carrier": "transit", "transit": "transit", "unknown": "unknown"}


class IpToAsn:
    """IPtoASN ranges of one address family loaded into the range index, plus an AS table."""

    def __init__(self, version: int) -> None:
        self.version = version
        self.index = IntervalIndex()
        self.asns: dict[int, list[Any]] = {}  # asn -> [country, name, ranges, addresses]
        self.rows = 0
        self.invalid = 0


def parse_iptoasn(lines: Iterable[str], version: int) -> IpToAsn:
    """IPtoASN TSV ``range_start range_end AS_number country AS_description`` -> IpToAsn.
    AS 0 rows are 'Not routed' (kept: unannounced space is a fact, not an error)."""
    out = IpToAsn(version)
    for line in lines:
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            out.invalid += 1
            continue
        a, b = ip_int(parts[0]), ip_int(parts[1])
        if a is None or b is None or a[0] != version or b[0] != version or a[1] > b[1]:
            out.invalid += 1
            continue
        asn_text = parts[2].strip()
        asn = int(asn_text) if asn_text.isdigit() else -1
        if asn < 0:
            out.invalid += 1
            continue
        country = parts[3].strip()
        country = country.upper() if re.fullmatch(r"[A-Za-z]{2}", country) else ""
        name = "\t".join(parts[4:]).strip()
        if asn == 0 or name == "Not routed":
            name = ""
        out.index.add(version, a[1], b[1], asn)
        out.rows += 1
        if asn:
            entry = out.asns.setdefault(asn, [country, name, 0, 0])
            entry[2] += 1
            entry[3] += b[1] - a[1] + 1
            if not entry[0] and country:
                entry[0] = country
            if not entry[1] and name:
                entry[1] = name
    out.index.freeze()
    return out


def _validate_iptoasn(version: int) -> Any:
    def check(path: Path) -> bool:
        rows = invalid = 0
        with open(path, encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                parts = line.rstrip("\r\n").split("\t")
                a = ip_int(parts[0]) if parts else None
                if len(parts) < 5 or a is None or a[0] != version:
                    invalid += 1
                else:
                    rows += 1
                if i < 2000 and invalid > 100:
                    raise ValueError("not an IPtoASN TSV (too many malformed lines)")
        if rows < MIN_IPTOASN_ROWS[version]:
            raise ValueError(f"too few IPtoASN rows ({rows} < {MIN_IPTOASN_ROWS[version]})")
        if invalid > max(10, rows // 100):
            raise ValueError(f"{invalid} malformed IPtoASN lines")
        return True

    return check


def parse_bgptools(text: str) -> dict[int, dict[str, str]]:
    """bgp.tools asns.csv (header 'asn,name,class,cc'; classes Eyeball/Content/Carrier/Unknown)
    -> {asn: {name, class, network_type, cc}}. Raises ValueError for another header."""
    reader = csv.reader(io.StringIO(text))
    try:
        header = [h.strip().lower() for h in next(reader)]
    except (StopIteration, csv.Error) as exc:
        raise ValueError("empty bgp.tools asns.csv") from exc
    if header != BGPTOOLS_HEADER:
        raise ValueError(f"unexpected bgp.tools header {','.join(header)[:60]!r}")
    out: dict[int, dict[str, str]] = {}
    for row in reader:
        if len(row) != 4:
            continue
        asn_text = row[0].strip().upper()
        if not asn_text.startswith("AS") or not asn_text[2:].isdigit():
            continue
        cls = row[2].strip() or "Unknown"
        cc = row[3].strip().upper()
        out[int(asn_text[2:])] = {
            "name": row[1].strip(),
            "class": cls,
            "network_type": BGPTOOLS_NETWORK_TYPE.get(cls.lower(), "unknown"),
            "cc": cc if re.fullmatch(r"[A-Z]{2}", cc) else "",
        }
    return out


def _validate_bgptools(path: Path) -> bool:
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(parse_bgptools(text)) < MIN_BGPTOOLS_ASNS:
        raise ValueError(f"too few ASNs in bgp.tools asns.csv (< {MIN_BGPTOOLS_ASNS})")
    return True


# ======================================================================================
# datasets (registered at import; fetched only by `v3lum data update`)
# ======================================================================================

IPTOASN_SOURCE = "iptoasn.ip2asn"
BGPTOOLS_SOURCE = "bgptools.asns"
IPTOASN_ATTRIBUTION = "IP to ASN mapping by IPtoASN (https://iptoasn.com), Open Data Commons Public Domain Dedication and License (PDDL)"
BGPTOOLS_ATTRIBUTION = "ASN names and network classes from bgp.tools (https://bgp.tools/asns.csv)"

IPTOASN_V4 = register_dataset(
    "ip_offline_db.iptoasn_v4.tsv",
    "https://iptoasn.com/data/ip2asn-v4.tsv.gz",
    ttl=86400,
    description="IPtoASN IPv4 ranges (range_start, range_end, AS number, country, AS description); at most daily",
    licence="PDDL-1.0",
    terms_class="open",
    attribution=IPTOASN_ATTRIBUTION,
    provider="iptoasn",
    source=IPTOASN_SOURCE,
    validate=_validate_iptoasn(4),
    min_bytes=1_000_000,
    expect="lines",
    max_bytes=96 * 1024 * 1024,
    large=True,
    archive="gz",
    member="ip2asn-v4.tsv",
    essential=True,
)
IPTOASN_V6 = register_dataset(
    "ip_offline_db.iptoasn_v6.tsv",
    "https://iptoasn.com/data/ip2asn-v6.tsv.gz",
    ttl=86400,
    description="IPtoASN IPv6 ranges (range_start, range_end, AS number, country, AS description); at most daily",
    licence="PDDL-1.0",
    terms_class="open",
    attribution=IPTOASN_ATTRIBUTION,
    provider="iptoasn",
    source=IPTOASN_SOURCE,
    validate=_validate_iptoasn(6),
    min_bytes=200_000,
    expect="lines",
    max_bytes=64 * 1024 * 1024,
    large=True,
    archive="gz",
    member="ip2asn-v6.tsv",
    essential=True,
)
# Size not published (about 5 MB): ``large`` stays unknown so a missing optional bgp.tools copy
# never blocks the IPtoASN lookups; this module never downloads it (data update only).
BGPTOOLS_ASNS = register_dataset(
    "ip_offline_db.bgptools_asns.csv",
    "https://bgp.tools/asns.csv",
    ttl=86400,
    description="bgp.tools asns.csv: AS number, name, class (Eyeball/Content/Carrier/Unknown), country; at most daily",
    licence="LicenseRef-bgp.tools-terms",
    terms_class="open",
    attribution=BGPTOOLS_ATTRIBUTION,
    provider="bgptools",
    source=BGPTOOLS_SOURCE,
    validate=_validate_bgptools,
    min_bytes=100_000,
    expect="csv",
)

_MEMO = DatasetMemo()


def load_iptoasn(ctx: Any, version: int) -> tuple[IpToAsn, Any]:
    name = IPTOASN_V4 if version == 4 else IPTOASN_V6
    path, info = local_dataset(ctx, name)

    def build() -> IpToAsn:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return parse_iptoasn(fh, version)

    return _MEMO.get(name, info.sha256, build), info


def load_bgptools(ctx: Any) -> tuple[dict[int, dict[str, str]], Any]:
    path, info = local_dataset(ctx, BGPTOOLS_ASNS)
    return _MEMO.get(BGPTOOLS_ASNS, info.sha256, lambda: parse_bgptools(path.read_text(encoding="utf-8", errors="replace"))), info


def _range_label(version: int, start: int, end: int) -> tuple[str, str]:
    """(prefix CIDR when the range is exactly one network, else '', 'first-last')."""
    cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    first, last = cls(start), cls(end)
    nets = list(ipaddress.summarize_address_range(first, last))
    return (str(nets[0]) if len(nets) == 1 else "", f"{first}-{last}")


@register
class IpOfflineDb(Module):
    name = "ip_offline_db"
    title = "Offline IP -> ASN (IPtoASN, bgp.tools)"
    description = (
        "Local IP/ASN context from the IPtoASN ranges (AS number, AS name, AS country, announced or not) and the "
        "bgp.tools AS classes (hosting versus eyeball networks); datasets fetched by `v3lum data update`, no value "
        "leaves the machine."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6, T.ASN}
    produces = {T.ASN, T.CIDR}
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (IPTOASN_SOURCE, BGPTOOLS_SOURCE)
    reference = "https://iptoasn.com/"
    notice = (
        "Offline datasets: IPtoASN (PDDL) and bgp.tools asns.csv (descriptive User-Agent with the team role contact, "
        "setting contact_email). Run `v3lum data update` to fetch them. AS/country context only: never used to locate "
        "a person or household."
    )
    tags = {"offline", "free"}
    max_pivots = 10

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type in (T.IPV4, T.IPV6):
            return special_purpose(entity.value) is None
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type is T.ASN:
            return self._asn(entity, ctx, res)
        return self._ip(entity, ctx, res)

    # ------------------------------------------------------------------ bgp.tools
    def _bgptools(self, ctx: Any, res: ModuleResult) -> tuple[dict[int, dict[str, str]] | None, Any]:
        if BGPTOOLS_SOURCE not in ctx.allowed_sources:
            return None, None
        if not str(ctx.setting("contact_email", "") or "").strip():
            res.source_status(
                BGPTOOLS_SOURCE, Status.SKIPPED, reason_code="config",
                reason="bgp.tools needs a descriptive User-Agent with the team role contact: v3lum config set contact_email <role mailbox>",
            )
            return None, None
        try:
            table, info = load_bgptools(ctx)
        except (DatasetError, OSError, ValueError) as exc:
            status, code = dataset_failure(exc) if isinstance(exc, DatasetError) else (Status.ERROR, "error")
            res.source_status(BGPTOOLS_SOURCE, status, reason_code=code, reason=f"bgp.tools asns.csv: {exc}")
            return None, None
        return table, info

    # ------------------------------------------------------------------ IP input
    def _ip(self, entity: Entity, ctx: Any, res: ModuleResult) -> ModuleResult:
        parsed = ip_int(entity.value)
        if parsed is None:
            return res.mark("error", f"not an IP address: {entity.value!r}")
        version, value = parsed
        try:
            data, info = load_iptoasn(ctx, version)
        except (DatasetError, OSError, ValueError) as exc:
            if isinstance(exc, DatasetError):
                return mark_dataset_failure(res, exc, f"IPtoASN IPv{version}")
            return res.mark("error", f"IPtoASN IPv{version}: unreadable local copy ({type(exc).__name__}): could not verify")
        now = ctx.now()
        ages = [dataset_age_line(f"IPtoASN IPv{version}", info, now)]
        spans = data.index.lookup_spans((version, value))
        raw: dict[str, Any] = {"dataset": info.name, "sha256": info.sha256, "rows": data.rows}
        if not spans:
            res.raw = raw
            return res.mark("empty")
        start, end, asn = spans[0]
        prefix, span = _range_label(version, start, end)
        raw.update({"range": span, "asn": asn})
        if not asn:
            res.attr("announced", False)
            res.attr("ip_range", span)
            res.finding(
                "Address not announced in BGP (IPtoASN)",
                "info",
                f"{entity.value} lies in {span}, which IPtoASN lists as 'Not routed' (snapshot {ages[0]}).",
                data={"range": span},
                source=IPTOASN_SOURCE,
            )
        else:
            country, as_name = data.asns.get(asn, ["", "", 0, 0])[:2]
            res.attr("announced", True)
            res.attr("asn", f"AS{asn}")
            res.attr("as_org", as_name)
            res.attr("as_country", country)
            if prefix:
                res.attr("prefix", prefix)
            res.attr("ip_range", span)
            res.pivot(T.ASN, f"AS{asn}", "belongs_to_asn", confidence=0.8)
            if prefix:
                res.pivot(T.CIDR, prefix, "in_network", confidence=0.8, expand=False, note="IPtoASN range of the address")
            table, binfo = self._bgptools(ctx, res)
            if table is not None:
                ages.append(dataset_age_line("bgp.tools asns.csv", binfo, now))
                row = table.get(asn)
                if row:
                    res.attr("network_type", row["network_type"])
                    res.attr("as_class", row["class"])
                    raw["bgptools"] = row
        res.attr("dataset_age", ages)
        res.raw = raw
        return res

    # ------------------------------------------------------------------ ASN input
    def _asn(self, entity: Entity, ctx: Any, res: ModuleResult) -> ModuleResult:
        try:
            asn = int(str(entity.value).upper().removeprefix("AS"))
        except ValueError:
            return res.mark("error", f"not an AS number: {entity.value!r}")
        now = ctx.now()
        ages: list[str] = []
        raw: dict[str, Any] = {"asn": asn}
        found = False
        failures = []
        totals = {"ranges": 0, "ipv4_addresses": 0, "ipv6_ranges": 0}
        for version in (4, 6):
            try:
                data, info = load_iptoasn(ctx, version)
            except (DatasetError, OSError, ValueError) as exc:
                failures.append((version, exc))
                continue
            ages.append(dataset_age_line(f"IPtoASN IPv{version}", info, now))
            entry = data.asns.get(asn)
            if not entry:
                continue
            found = True
            country, as_name, ranges, addresses = entry
            res.attr("as_org", as_name)
            res.attr("as_country", country)
            totals["ranges"] += ranges
            if version == 4:
                totals["ipv4_addresses"] += addresses
            else:
                totals["ipv6_ranges"] += ranges
        if len(failures) == 2:
            exc = failures[0][1]
            if isinstance(exc, DatasetError):
                return mark_dataset_failure(res, exc, "IPtoASN")
            return res.mark("error", f"IPtoASN: unreadable local copy ({type(exc).__name__}): could not verify")
        if found:
            res.attr("as_range_count", totals["ranges"])
            res.attr("as_ipv4_addresses", totals["ipv4_addresses"])
        table, binfo = self._bgptools(ctx, res)
        if table is not None:
            ages.append(dataset_age_line("bgp.tools asns.csv", binfo, now))
            row = table.get(asn)
            if row:
                found = True
                res.attr("network_type", row["network_type"])
                res.attr("as_class", row["class"])
                if row["name"]:
                    res.attr("as_org", res.attributes.get("as_org") or row["name"])
                if row["cc"]:
                    res.attr("as_country", res.attributes.get("as_country") or row["cc"])
                raw["bgptools"] = row
        raw.update(totals)
        res.raw = raw
        if not found:
            return res.mark("empty")
        res.attr("dataset_age", ages)
        return res
