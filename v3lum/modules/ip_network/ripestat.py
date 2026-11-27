"""ripestat: RIPEstat Data API - routing, registration, abuse contacts and PTR context (P031).

Batch p1-G02-1. Keyless RIPE NCC Data API (``stat.ripe.net/data/<call>/data.json``), every call with
``sourceapp=v3lum`` and the RIPE NCC attribution (cond 1); HTTP cache 24 h. Works for every RIR's
space, not only RIPE's.

* **Calls** (cond 2): IPs -> network-info, prefix-overview, rir-geo, whois, abuse-contact-finder,
  reverse-dns-ip and, when a PTR exists, dns-chain (the PTR chain); CIDRs -> prefix-overview, rir-geo,
  whois, abuse-contact-finder; ASNs -> as-overview, announced-prefixes, asn-neighbours; company names
  -> searchcomplete (ASN/prefix candidates: low confidence, expand=False).
* **Rule 5** (cond 3): the JSON envelope is checked on every answer, HTTP 200 included (status,
  status_code, messages of type error, data_call_status), through the P321 error markers of
  ``v3lum/data/providers/ripestat__p1-G02-1.json``: ERROR or RATE_LIMITED, never EMPTY. A failing data
  call never becomes an absence: it is named in ``res.error`` while the other calls stand.
* **announced-prefixes** (cond 4): ~680 KB for a big ASN. The body is capped (``max_bytes``) and
  scanned incrementally without building a second JSON tree: at most 100 cidr pivots while
  ``announced_prefix_counts`` keeps the totals.
* **LGPD** (cond 5): RIPE person objects (and every unlisted object class such as maintainers, ARIN
  technical POCs or customer records) are dropped at ingestion; role, organisation, irt and abuse-c
  objects keep allow-listed attributes only. The raw whois answer is never written to the HTTP cache
  (``cache_if``) and never kept as evidence: only the minimised objects are.
* **Shared helper** (cond 6): :func:`abuse_contact_records` (and :func:`lookup_abuse_contacts`) give
  the P345 takedown packet ranked abuse contacts with source and retrieval date. rir-geo is shown as
  registration-country context only (attribute ``registration_country``), never as a location.
"""

from __future__ import annotations

import heapq
import ipaddress
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, DeadlineExceeded, HttpError, NetworkError, OfflineError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SOURCE = "ripestat.data_api"
HOST = "stat.ripe.net"
API = "https://stat.ripe.net/data/{call}/data.json"
UI = "https://stat.ripe.net/resource/{resource}"
SOURCEAPP = "v3lum"
ATTRIBUTION = "Data: RIPEstat Data API, RIPE NCC (https://stat.ripe.net), used under the RIPEstat terms of service"
CALL_TIMEOUT = 20.0
ANNOUNCED_PREFIXES_CAP = 100  # cond 4
ANNOUNCED_MAX_BYTES = 4_000_000  # AS13335 = 679,712 bytes on 2026-11-26
NEIGHBOUR_CAP = 25
CANDIDATE_CAP = 20
CALLS = frozenset({
    "network-info", "prefix-overview", "rir-geo", "whois", "abuse-contact-finder", "reverse-dns-ip", "dns-chain",
    "as-overview", "announced-prefixes", "asn-neighbours", "searchcomplete",
})
#: P345 contact ranking: registrar RDAP abuse 1 > hosting abuse-c from the RIR 2 > Abusix 3 > CDN portal 4.
ABUSE_AUTHORITY_RANK = 2


class Unusable(Exception):
    """A RIPEstat answer that is not a usable envelope (could not verify, never an absence)."""


# ======================================================================================
# Requests
# ======================================================================================


def is_bogon_ip(value: Any) -> bool:
    """Private, shared, loopback, link-local, multicast, documentation, reserved or unparseable."""
    try:
        ip = ipaddress.ip_address(str(value).strip().strip("[]").split("%", 1)[0])
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not ip.is_global or ip.is_multicast


def asn_number(value: Any) -> int | None:
    """15169 | 'AS15169' | 'as15169' | '15169' -> 15169 (1..2^32-1), else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        n = value
    else:
        text = str(value or "").strip().upper()
        text = text[2:].strip() if text.startswith("AS") else text
        if not text.isdigit():
            return None
        n = int(text)
    return n if 0 < n < 4294967296 else None


def is_bogon_asn(value: Any) -> bool:
    """AS0, AS_TRANS (23456), documentation, private and reserved ASNs (RFC 5398/6996/7300)."""
    n = asn_number(value)
    return n is None or n == 23456 or 64496 <= n <= 131071 or n >= 4200000000


def ripestat_resource(entity: Entity) -> str | None:
    """The 'resource' parameter for an entity; None when it must not be sent (bogons, bad values)."""
    value = str(entity.value or "").strip()
    if entity.type in (T.IPV4, T.IPV6):
        if is_bogon_ip(value):
            return None
        ip = ipaddress.ip_address(value)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ip)
    if entity.type is T.CIDR:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
        return None if is_bogon_ip(net.network_address) else str(net)
    if entity.type is T.ASN:
        n = asn_number(value)
        return f"AS{n}" if n and not is_bogon_asn(n) else None
    if entity.type is T.ORG:
        text = " ".join(value.split())
        return text if 2 <= len(text) <= 100 else None
    return None


def ripestat_url(call: str, resource: str) -> str:
    """Data-call URL; ``sourceapp=v3lum`` is always present (cond 1). Raises ValueError on bad input."""
    if call not in CALLS:
        raise ValueError(f"unknown RIPEstat data call {call!r}")
    if not isinstance(resource, str) or not resource.strip():
        raise ValueError("empty RIPEstat resource")
    return API.format(call=call) + "?" + urlencode({"resource": resource.strip(), "sourceapp": SOURCEAPP})


def envelope_data(obj: Any, call: str) -> dict[str, Any]:
    """The 'data' object of a RIPEstat answer after a second envelope check (the provider markers
    are the first): raises :class:`Unusable` for anything that is not an 'ok' envelope."""
    if not isinstance(obj, dict):
        raise Unusable(f"RIPEstat {call}: answer is not a JSON object: could not verify")
    status = obj.get("status")
    if status is not None and str(status).strip().lower() != "ok":
        raise Unusable(f"RIPEstat {call}: envelope status {str(status)[:40]!r}: could not verify")
    code = obj.get("status_code")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        raise Unusable(f"RIPEstat {call}: envelope status_code {code}: could not verify")
    for message in _list(obj.get("messages")):
        if isinstance(message, list) and len(message) >= 2 and str(message[0]).strip().lower() == "error":
            raise Unusable(f"RIPEstat {call}: {str(message[1])[:160]}: could not verify")
    data = obj.get("data")
    if not isinstance(data, dict):
        raise Unusable(f"RIPEstat {call}: envelope without a data object: could not verify")
    return data


# ======================================================================================
# Pure parsers (one per data call)
# ======================================================================================


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any, limit: int = 300) -> str:
    if isinstance(value, str):
        return " ".join(value.split())[:limit]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return ""


def _cidr(value: Any) -> str:
    try:
        return str(ipaddress.ip_network(str(value).strip(), strict=False)) if isinstance(value, str) and value.strip() else ""
    except ValueError:
        return ""


def _dedupe(values: Iterable[Any]) -> list[Any]:
    out: list[Any] = []
    for value in values:
        if value and value not in out:
            out.append(value)
    return out


_EMAIL_RE = re.compile(r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


def _email(value: Any) -> str:
    text = _text(value, 254).lower()
    if text.startswith("mailto:"):
        text = text[7:]
    return text if _EMAIL_RE.match(text) else ""


def _hostname(value: Any) -> str:
    text = _text(value, 253).rstrip(".").lower()
    if not text or "." not in text:
        return ""
    try:
        ipaddress.ip_address(text)
        return ""
    except ValueError:
        pass
    return text if all(_LABEL_RE.match(label) for label in text.split(".")) else ""


def parse_network_info(data: dict[str, Any]) -> dict[str, Any]:
    """network-info: covering BGP prefix + origin ASNs ('' / [] when not announced)."""
    asns = _dedupe(asn_number(a) for a in _list(data.get("asns")))
    return {"prefix": _cidr(data.get("prefix")), "asns": [a for a in asns if a]}


def parse_prefix_overview(data: dict[str, Any]) -> dict[str, Any]:
    """prefix-overview: announced flag, origin ASNs with holder, IANA block, related prefixes.
    A 'not announced, aligned to less-specific' message stays a warning (never an error)."""
    asns = []
    for item in _list(data.get("asns")):
        n = asn_number(_dict(item).get("asn"))
        if n and all(a["asn"] != n for a in asns):
            asns.append({"asn": n, "holder": _text(_dict(item).get("holder"), 200)})
    block = _dict(data.get("block"))
    return {
        "resource": _cidr(data.get("resource")),
        "announced": data.get("announced") is True,
        "is_less_specific": data.get("is_less_specific") is True,
        "asns": asns,
        "block": {"resource": _text(block.get("resource"), 60), "desc": _text(block.get("desc"), 120)} if block else None,
        "related_prefixes": _dedupe(_cidr(p) for p in _list(data.get("related_prefixes")))[:50],
    }


def parse_rir_geo(data: dict[str, Any]) -> dict[str, Any]:
    """rir-geo: country of the RIR registration (context only, cond 6)."""
    countries = []
    for item in _list(data.get("located_resources")):
        cc = _text(_dict(item).get("location"), 8).upper()
        if re.fullmatch(r"[A-Z]{2}", cc) and cc not in countries:
            countries.append(cc)
    return {"countries": countries, "country": countries[0] if len(countries) == 1 else ""}


# ---- whois minimisation (cond 5) ---------------------------------------------------------

_NET_ATTRS = frozenset({
    "inetnum", "inet6num", "netrange", "cidr", "netname", "nethandle", "nettype", "parent", "originas", "descr", "country",
    "status", "org", "organization", "abuse-c", "mnt-irt", "created", "last-modified", "regdate", "updated", "source",
    "aut-num", "as-name", "asnumber", "asname", "ashandle", "owner",
})
_ROUTE_ATTRS = frozenset({"route", "route6", "descr", "origin", "source", "created", "last-modified"})
_ORG_ATTRS = frozenset({"organisation", "org-name", "org-type", "country", "abuse-c", "created", "last-modified", "source", "orgname", "orgid", "regdate", "updated"})
_ROLE_ATTRS = frozenset({"role", "nic-hdl", "abuse-mailbox", "country", "created", "last-modified", "source"})
_IRT_ATTRS = frozenset({"irt", "abuse-mailbox", "e-mail", "country", "created", "last-modified", "source"})
_ABUSE_POC_ATTRS = frozenset({"orgabusehandle", "orgabuseemail", "rabusehandle", "rabuseemail", "source"})
#: object class (first attribute, lower case) -> (category, allowed attributes). Every other class
#: (person, mntner, key-cert, ARIN OrgTech/OrgNOC/RTech/RNOC/OrgRouting/OrgDNS POCs, CustName customer
#: records...) is dropped: it may describe an individual (fail closed).
WHOIS_OBJECT_POLICY: dict[str, tuple[str, frozenset[str]]] = {
    "inetnum": ("network", _NET_ATTRS), "inet6num": ("network", _NET_ATTRS), "netrange": ("network", _NET_ATTRS),
    "aut-num": ("network", _NET_ATTRS), "asnumber": ("network", _NET_ATTRS),
    "route": ("route", _ROUTE_ATTRS), "route6": ("route", _ROUTE_ATTRS),
    "organisation": ("organisation", _ORG_ATTRS), "orgname": ("organisation", _ORG_ATTRS),
    "role": ("role", _ROLE_ATTRS), "irt": ("role", _IRT_ATTRS),
    "orgabusehandle": ("abuse", _ABUSE_POC_ATTRS), "rabusehandle": ("abuse", _ABUSE_POC_ATTRS),
}
#: person objects: RPSL 'person', LACNIC 'nic-hdl' and registro.br 'nic-hdl-br'
WHOIS_PERSON_CLASSES = frozenset({"person", "nic-hdl", "nic-hdl-br"})


def _cpf_shaped(value: str) -> bool:
    digits = re.sub(r"\D", "", value or "")
    return len(digits) == 11 and bool(re.fullmatch(r"[\d.\-\s/]+", value or ""))


def minimise_whois_records(records: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """(kept objects, dropped counts) for RIPEstat whois 'records' / 'irr_records' lists.

    Kept objects are ``{'class', 'category', 'attrs': [[key, value], ...]}`` with allow-listed
    attributes only; phones, street addresses, admin-c/tech-c handles, notify/changed e-mails,
    remarks, LACNIC 'responsible' and 'ownerid' never survive, and the owner name and abuse-c handle
    of a CPF-identified individual holder are dropped too."""
    kept: list[dict[str, Any]] = []
    dropped: dict[str, Any] = {"person_objects": 0, "other_objects": 0, "attributes": 0, "classes": set()}
    for record in _list(records):
        attrs: list[tuple[str, str]] = []
        for item in _list(record):
            if isinstance(item, dict):
                key, value = _text(item.get("key"), 64), _text(item.get("value"), 300)
                if key and value:
                    attrs.append((key, value))
        if not attrs:
            continue
        cls = attrs[0][0].lower()
        keys = {k.lower() for k, _v in attrs}
        if cls in WHOIS_PERSON_CLASSES or ("person" in keys and "role" not in keys and cls not in WHOIS_OBJECT_POLICY):
            dropped["person_objects"] += 1
            dropped["classes"].add(cls)
            continue
        policy = WHOIS_OBJECT_POLICY.get(cls)
        if policy is None:
            dropped["other_objects"] += 1
            dropped["classes"].add(cls)
            continue
        category, allowed = policy
        individual = any(k.lower() == "ownerid" and _cpf_shaped(v) for k, v in attrs)
        out: list[list[str]] = []
        for key, value in attrs:
            low = key.lower()
            if low not in allowed or (individual and low in ("owner", "abuse-c")):
                dropped["attributes"] += 1
                continue
            out.append([key, value])
        obj: dict[str, Any] = {"class": cls, "category": category, "attrs": out}
        if individual:
            obj["individual_holder"] = True
        kept.append(obj)
    dropped["classes"] = sorted(dropped["classes"])
    return kept, dropped


def _range_to_cidrs(value: str) -> list[str]:
    """'200.160.0.0 - 200.160.15.255' | '1.1.1.0/24' | '8.8.8.0/24, 8.8.9.0/24' -> CIDRs."""
    out: list[str] = []
    for part in (value or "").split(","):
        part = part.strip()
        if "-" in part and "/" not in part:
            low, _, high = part.partition("-")
            try:
                a, b = ipaddress.ip_address(low.strip()), ipaddress.ip_address(high.strip())
            except ValueError:
                continue
            if a.version == b.version and int(a) <= int(b):
                out.extend(str(n) for n in ipaddress.summarize_address_range(a, b))  # type: ignore[arg-type]
        elif "/" in part:
            cidr = _cidr(part)
            if cidr:
                out.append(cidr)
    return _dedupe(out)[:16]


def parse_whois(data: dict[str, Any]) -> dict[str, Any]:
    """whois: minimised registry facts (cond 5; person objects dropped here, at ingestion)."""
    kept, dropped = minimise_whois_records(data.get("records"))
    irr_kept, irr_dropped = minimise_whois_records(data.get("irr_records"))
    for key in ("person_objects", "other_objects", "attributes"):
        dropped[key] += irr_dropped[key]
    dropped["classes"] = sorted(set(dropped["classes"]) | set(irr_dropped["classes"]))
    authorities = [a.lower() for a in (_text(x, 16) for x in _list(data.get("authorities"))) if a]
    network: dict[str, Any] | None = None
    org_name = org_handle = org_country = ""
    abuse_emails: list[str] = []
    abuse_handles: list[str] = []
    for obj in kept:
        values: dict[str, list[str]] = {}
        for key, value in obj["attrs"]:
            values.setdefault(key.lower(), []).append(value)

        def first(*keys: str, _v: dict[str, list[str]] = values) -> str:
            return next((_v[k][0] for k in keys if _v.get(k)), "")

        if obj["category"] == "network" and network is None:
            block = first("inetnum", "inet6num", "netrange")
            network = {
                "range": block,
                "cidrs": _range_to_cidrs(first("cidr")) or _range_to_cidrs(block),
                "netname": first("netname"),
                "status": first("status", "nettype"),
                "country": first("country").upper()[:2],
                "created": first("created", "regdate"),
                "last_modified": first("last-modified", "updated", "changed"),
                "descr": [d[:120] for d in values.get("descr", [])[:3]],
            }
            owner = first("organization", "owner")
            if owner and not org_name:
                org_name = re.sub(r"\s*\([A-Z0-9-]+\)\s*$", "", owner)
            org_handle = org_handle or first("org")
            abuse_handles += values.get("abuse-c", [])
        elif obj["category"] == "organisation":
            org_name = org_name or first("org-name", "orgname")
            org_handle = org_handle or first("organisation", "orgid")
            org_country = org_country or first("country").upper()[:2]
            abuse_handles += values.get("abuse-c", [])
        elif obj["category"] in ("role", "abuse"):
            keys = ["abuse-mailbox", "orgabuseemail", "rabuseemail"] + (["e-mail"] if obj["class"] == "irt" else [])
            for key in keys:
                abuse_emails += [_email(v) for v in values.get(key, [])]
            abuse_handles += values.get("nic-hdl", []) + values.get("orgabusehandle", []) + values.get("rabusehandle", [])
    routes = []
    for obj in irr_kept:
        values = {}
        for key, value in obj["attrs"]:
            values.setdefault(key.lower(), []).append(value)
        route = _cidr((values.get("route") or values.get("route6") or [""])[0])
        if route:
            routes.append({"route": route, "origin": asn_number((values.get("origin") or [""])[0]), "source": (values.get("source") or [""])[0]})
    if network is not None and not network["country"] and org_country:
        network["country"] = org_country
    out = {
        "rir": authorities[0] if authorities else "",
        "network": network,
        "org_name": org_name,
        "org_handle": org_handle,
        "abuse_emails": _dedupe(abuse_emails),
        "abuse_handles": _dedupe(abuse_handles),
        "irr_routes": routes[:20],
        "objects": kept + irr_kept,
        "dropped": dropped,
        "note": "",
    }
    if not kept and routes:
        out["note"] = "no registry records returned (NIR/LACNIC space such as NIC.br): IRR routes only"
    return out


def parse_abuse_contact_finder(data: dict[str, Any]) -> dict[str, Any]:
    """abuse-contact-finder: abuse mailboxes of the authoritative RIR (role addresses)."""
    rir = _text(data.get("authoritative_rir"), 16).lower()
    return {
        "resource": _text(_dict(data.get("parameters")).get("resource"), 64),
        "contacts": _dedupe(_email(x) for x in _list(data.get("abuse_contacts")))[:10],
        "authoritative_rir": rir,
        "latest_time": _text(data.get("latest_time"), 40),
    }


def abuse_contact_records(parsed: dict[str, Any] | None, *, retrieved_at: str = "", resource: str = "") -> list[dict[str, Any]]:
    """cond 6 shared helper (P345 takedown packet): ranked abuse contacts with authority, source and
    retrieval date from a :func:`parse_abuse_contact_finder` result (authority rank 2 = hosting
    abuse-c from the RIR, after registrar RDAP abuse = 1, before Abusix = 3 and CDN portals = 4)."""
    if not isinstance(parsed, dict):
        return []
    rir = str(parsed.get("authoritative_rir") or "")
    return [
        {
            "email": email,
            "kind": "hosting_abuse_c",
            "authority_rank": ABUSE_AUTHORITY_RANK,
            "authority": f"RIR abuse-c ({rir.upper() or 'unknown RIR'})",
            "source": SOURCE,
            "resource": resource or str(parsed.get("resource") or ""),
            "retrieved_at": retrieved_at or str(parsed.get("latest_time") or ""),
            "attribution": ATTRIBUTION,
        }
        for email in parsed.get("contacts", []) or []
        if isinstance(email, str) and email
    ]


def lookup_abuse_contacts(http: Any, resource: str) -> list[dict[str, Any]]:
    """The abuse-contact lookup itself through a caller's ``ctx.http`` (which must declare
    stat.ripe.net and the source ripestat.data_api): records of :func:`abuse_contact_records`.
    Exceptions of ``ctx.http`` propagate (rule 5: a failure is never 'no contact')."""
    obj = http.get_json(ripestat_url("abuse-contact-finder", resource), timeout=CALL_TIMEOUT, source=SOURCE)
    parsed = parse_abuse_contact_finder(envelope_data(obj, "abuse-contact-finder"))
    return abuse_contact_records(parsed, retrieved_at=_text(_dict(obj).get("time"), 40), resource=resource)


def parse_reverse_dns_ip(data: dict[str, Any]) -> dict[str, Any]:
    """reverse-dns-ip: PTR names. An NXDOMAIN-like error is a meaningful 'no PTR'; any other error
    with no names is 'could not verify'."""
    names = _dedupe(_hostname(x) for x in _list(data.get("result")))[:20]
    error = _text(data.get("error"), 200)
    absent = not names and bool(re.search(r"(?i)nxdomain|no ptr|not found|does not exist|no such", error))
    return {"names": names, "error": error, "absent": absent, "unverified": bool(not names and error and not absent)}


def parse_dns_chain(data: dict[str, Any]) -> dict[str, Any]:
    """dns-chain: forward (A/AAAA) and reverse (PTR) nodes resolved by RIPEstat (the PTR chain)."""
    forward: dict[str, list[str]] = {}
    for name, ips in _dict(data.get("forward_nodes")).items():
        host = _hostname(name)
        if host:
            addrs = []
            for ip in _list(ips):
                try:
                    addrs.append(ipaddress.ip_address(str(ip).strip()).compressed)
                except ValueError:
                    continue
            forward[host] = _dedupe(addrs)
    reverse: dict[str, list[str]] = {}
    for ip, names in _dict(data.get("reverse_nodes")).items():
        try:
            key = ipaddress.ip_address(str(ip).strip()).compressed
        except ValueError:
            continue
        reverse[key] = _dedupe(_hostname(n) for n in _list(names))
    return {"forward": forward, "reverse": reverse, "ptr_names": sorted({n for v in reverse.values() for n in v})}


def parse_as_overview(data: dict[str, Any]) -> dict[str, Any]:
    block = _dict(data.get("block"))
    return {
        "asn": asn_number(data.get("resource")),
        "holder": _text(data.get("holder"), 200),
        "announced": data.get("announced") is True,
        "block": {"resource": _text(block.get("resource"), 60), "desc": _text(block.get("desc"), 120)} if block else None,
    }


class _PrefixSelector:
    """Keep the ``cap`` first prefixes (IPv4 first, then larger blocks, then address) while counting all."""

    def __init__(self, cap: int) -> None:
        self.cap = max(0, int(cap))
        self.heap: list[tuple[int, int, int, str]] = []
        self.seen: set[str] = set()
        self.total = self.v4 = self.v6 = self.invalid = 0

    def add(self, value: str) -> None:
        try:
            net = ipaddress.ip_network(value.strip(), strict=False)
        except ValueError:
            self.invalid += 1
            return
        key = str(net)
        if key in self.seen:
            return
        self.seen.add(key)
        self.total += 1
        if net.version == 4:
            self.v4 += 1
        else:
            self.v6 += 1
        item = (-net.version, -net.prefixlen, -int(net.network_address), key)
        if len(self.heap) < self.cap:
            heapq.heappush(self.heap, item)
        elif self.cap and item > self.heap[0]:
            heapq.heapreplace(self.heap, item)

    def prefixes(self) -> list[str]:
        return [item[3] for item in sorted(self.heap, reverse=True)]


_STREAM_PREFIX_RE = re.compile(rb'"prefix"\s{0,16}:\s{0,16}"([0-9A-Fa-f:./]{3,60})"')
_STREAM_TAIL_KEEP = 256
_STREAM_HEAD = 8192


def count_announced_prefixes(chunks: Iterable[bytes], cap: int = ANNOUNCED_PREFIXES_CAP) -> dict[str, Any]:
    """cond 4: incremental announced-prefixes scan over byte chunks - the envelope is read from the
    head (status comes before 'data'), prefixes are counted through a bounded regex window and at
    most ``cap`` are kept; ``complete`` is False when the body ends early (truncated stream)."""
    selector = _PrefixSelector(cap)
    head = bytearray()
    buf = b""
    tail = b""
    total_bytes = 0
    for chunk in chunks:
        if not chunk:
            continue
        total_bytes += len(chunk)
        if len(head) < _STREAM_HEAD:
            head += chunk[: _STREAM_HEAD - len(head)]
        buf += chunk
        last = 0
        for m in _STREAM_PREFIX_RE.finditer(buf):
            selector.add(m.group(1).decode("ascii", errors="replace"))
            last = m.end()
        buf = buf[max(last, len(buf) - _STREAM_TAIL_KEEP):]
        tail = (tail + chunk)[-4096:]
    head_text = bytes(head).decode("utf-8", errors="replace")
    status = re.search(r'"status"\s*:\s*"([^"]*)"', head_text)
    status_code = re.search(r'"status_code"\s*:\s*(\d+)', head_text)
    tail_text = tail.decode("utf-8", errors="replace").rstrip()
    return {
        "status": status.group(1) if status else "",
        "status_code": int(status_code.group(1)) if status_code else None,
        "json": head_text.lstrip("﻿ \t\r\n").startswith("{"),
        "complete": tail_text.endswith("}"),
        "bytes": total_bytes,
        "total": selector.total,
        "ipv4": selector.v4,
        "ipv6": selector.v6,
        "invalid": selector.invalid,
        "prefixes": selector.prefixes(),
    }


def _chunks(content: bytes, size: int = 65536) -> Iterable[bytes]:
    for i in range(0, len(content), size):
        yield content[i : i + size]


def parse_asn_neighbours(data: dict[str, Any], cap: int = NEIGHBOUR_CAP) -> dict[str, Any]:
    """asn-neighbours: left = upstream, right = downstream (sorted by power, capped per side)."""
    groups: dict[str, list[dict[str, Any]]] = {"left": [], "right": [], "uncertain": []}
    for item in _list(data.get("neighbours")):
        item = _dict(item)
        n = asn_number(item.get("asn"))
        side = str(item.get("type") or "").lower()
        if not n or side not in groups:
            continue
        power = item.get("power") if isinstance(item.get("power"), int) and not isinstance(item.get("power"), bool) else 0
        groups[side].append({"asn": n, "power": power})
    for side in groups:
        groups[side].sort(key=lambda x: (-x["power"], x["asn"]))
    counts = {k: v for k, v in _dict(data.get("neighbour_counts")).items() if isinstance(v, int) and not isinstance(v, bool)}
    return {"counts": counts, "upstreams": groups["left"][:cap], "downstreams": groups["right"][:cap], "uncertain": len(groups["uncertain"])}


def _fold(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", text or "") if not unicodedata.combining(c)).upper()


_STOPWORDS = frozenset({"LTDA", "INC", "LLC", "THE", "LTD", "CORP", "S/A", "EIRELI"})


def parse_searchcomplete(data: dict[str, Any], company: str, cap: int = CANDIDATE_CAP) -> dict[str, Any]:
    """searchcomplete: ASN/prefix candidates for a company name. ``name_match`` tells whether every
    folded token of the name appears in the candidate description (still low confidence)."""
    tokens = [t for t in re.findall(r"[A-Z0-9]{3,}", _fold(company)) if t not in _STOPWORDS]
    asns: list[dict[str, Any]] = []
    prefixes: list[dict[str, Any]] = []
    for category in _list(data.get("categories")):
        category = _dict(category)
        name = str(category.get("category") or "").lower()
        for suggestion in _list(category.get("suggestions")):
            suggestion = _dict(suggestion)
            desc = _text(suggestion.get("description"), 200)
            match = bool(tokens) and all(t in _fold(desc) for t in tokens)
            if name in ("asns", "asn"):
                n = asn_number(suggestion.get("value") or suggestion.get("label"))
                if n and not is_bogon_asn(n) and all(a["asn"] != n for a in asns):
                    asns.append({"asn": n, "description": desc, "name_match": match})
            elif "prefix" in name:
                cidr = _cidr(suggestion.get("value") or suggestion.get("label"))
                if cidr and all(p["cidr"] != cidr for p in prefixes):
                    prefixes.append({"cidr": cidr, "description": desc, "name_match": match})
    return {"term": _text(data.get("query_term"), 100), "asns": asns[:cap], "prefixes": prefixes[:cap]}


def generic_ptr(name: str, ip: str) -> bool:
    """True when a PTR name embeds the address (ISP/cloud auto-generated reverse names)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    low = name.lower()
    if addr.version == 4:
        octets = str(addr).split(".")
        forms = {"-".join(octets), ".".join(octets), "-".join(reversed(octets)), ".".join(reversed(octets)),
                 "".join(f"{int(o):03d}" for o in octets)}
        return any(form in low for form in forms)
    return addr.exploded.replace(":", "")[-8:] in low.replace("-", "").replace(".", "")


# ======================================================================================
# The module
# ======================================================================================


def _never(_resp: Any) -> bool:
    return False


@dataclass
class _Run:
    res: ModuleResult
    ctx: Any
    resource: str
    failures: dict[str, str] = field(default_factory=dict)
    offline: set[str] = field(default_factory=set)
    answered: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    retrieved_at: str = ""


@register
class RipeStat(Module):
    name = "ripestat"
    title = "RIPEstat Data API"
    description = (
        "Routing and registration context from RIPE NCC's keyless RIPEstat Data API: origin ASN, prefix, holder, "
        "RIR registration, abuse contact and PTR for an IP/CIDR; prefixes and neighbours for an ASN; ASN candidates for a company name."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6, T.CIDR, T.ASN, T.ORG}
    produces = {T.ASN, T.CIDR, T.DOMAIN, T.EMAIL}
    tags = {"free"}
    reference = "https://stat.ripe.net/docs/02.data-api/"
    notice = (
        "Data: RIPEstat Data API, RIPE NCC (sourceapp=v3lum on every call; attribution to RIPE NCC per its terms). "
        "RIPE person objects are dropped at ingestion (LGPD); rir-geo is registration-country context only."
    )
    # ---- contract v2 declarations --------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # RIPE NCC receives the IP/CIDR/ASN/company name
    provider = "ripestat"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_noauth_limited"  # keyless, fair use (no published hard limit)
    max_requests = 8  # IP: 6 calls + dns-chain when a PTR exists; ASN 3; CIDR 4; company 1
    expected_latency = 2.5  # live 2026-11-26: IP 2.2 s (7 calls), ASN 0.8 s, company name 0.2 s
    timeout = 60.0
    min_interval = 0.25  # fair use: never a burst against stat.ripe.net
    daily_quota = 2000  # self-imposed fair-use budget (RIPE NCC asks heavy users to get in touch)
    cache_ttl = 86400  # cond 1
    max_pivots = 160  # ASN: 100 prefixes + 25 upstream + 25 downstream
    manual_link = "https://stat.ripe.net/resource/{raw}"
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return ripestat_resource(entity) is not None

    # ---- orchestration ----------------------------------------------------------------------
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        resource = ripestat_resource(entity)
        if resource is None:
            return res.mark(Status.SKIPPED, "not a public IP/CIDR/ASN or a usable company name: never sent", reason_code="not_applicable")
        run = _Run(res, ctx, resource)
        if entity.type in (T.IPV4, T.IPV6):
            self._ip(run)
        elif entity.type is T.CIDR:
            self._cidr(run)
        elif entity.type is T.ASN:
            self._asn(run)
        else:
            self._company(run)
        return self._finish(run)

    def _call(self, run: _Run, call: str, *, cache: bool = True) -> dict[str, Any] | None:
        """One data call: the 'data' object, or None after recording why it could not be verified.
        Refusals that concern the whole host (rate limit, quota, block, deadline) propagate."""
        kw: dict[str, Any] = {"timeout": CALL_TIMEOUT}
        if not cache:
            kw["cache_if"] = _never
        try:
            obj = run.ctx.http.get_json(ripestat_url(call, run.resource), **kw)
            data = envelope_data(obj, call)
        except (RateLimited, QuotaExceeded, Blocked, AuthRequired, DeadlineExceeded):
            raise
        except OfflineError as exc:
            run.failures[call] = str(exc)[:200] or "offline"
            run.offline.add(call)
            return None
        except (HttpError, NetworkError, Unusable, ValueError) as exc:
            run.failures[call] = str(exc)[:200] or type(exc).__name__
            return None
        run.answered.append(call)
        run.retrieved_at = run.retrieved_at or _text(obj.get("time"), 40)
        return data

    def _finish(self, run: _Run) -> ModuleResult:
        res = run.res
        run.evidence["calls_answered"] = list(run.answered)
        if run.failures:
            run.evidence["calls_unverified"] = dict(run.failures)
        res.raw = run.evidence
        has_data = res.has_data
        if run.answered and has_data:
            res.attr("data_attribution", ATTRIBUTION)
            if res.entity.type is not T.ORG:  # a free-text company name has no RIPEstat resource page
                res.link(f"RIPEstat: {run.resource} (data: RIPE NCC)", UI.format(resource=run.resource))
        if not run.failures:
            return res  # no data at all is a genuine EMPTY: every call answered
        failed = ", ".join(f"{call} ({why})" for call, why in run.failures.items())
        if not has_data:
            # rule 5: nothing found while some calls could not be verified is never an absence
            if run.offline and set(run.failures) == run.offline:
                return res.mark(Status.UNAVAILABLE, f"offline and not cached: {failed}"[:900], reason_code="offline")
            return res.mark(Status.ERROR, f"could not verify: {failed}"[:900], reason_code="error")
        res.error = f"could not verify: {failed}"[:900]
        return res

    # ---- IP --------------------------------------------------------------------------------
    def _ip(self, run: _Run) -> None:
        res, ip = run.res, run.resource
        ni = self._call(run, "network-info")
        po = self._call(run, "prefix-overview")
        geo = self._call(run, "rir-geo")
        whois = self._call(run, "whois", cache=False)  # raw whois never reaches the HTTP cache (cond 5)
        abuse = self._call(run, "abuse-contact-finder")
        rdns = self._call(run, "reverse-dns-ip")
        routing = self._routing(run, ni, po)
        if geo is not None:
            self._geo(run, parse_rir_geo(geo))
        if whois is not None:
            self._whois(run, parse_whois(whois))
        if abuse is not None:
            self._abuse(run, parse_abuse_contact_finder(abuse))
        if rdns is not None:
            ptr = parse_reverse_dns_ip(rdns)
            run.evidence["reverse-dns-ip"] = {"names": ptr["names"], "error": ptr["error"]}
            if ptr["unverified"]:
                run.failures["reverse-dns-ip"] = f"RIPEstat reverse-dns-ip: {ptr['error'][:120]}: could not verify"
            elif ptr["names"]:
                chain = self._call(run, "dns-chain")  # cond 2: the PTR chain
                confirmed = None
                if chain is not None:
                    parsed = parse_dns_chain(chain)
                    run.evidence["dns-chain"] = {"forward": parsed["forward"], "ptr_names": parsed["ptr_names"]}
                    confirmed = all(ip in parsed["forward"].get(name, []) for name in ptr["names"])
                    res.attr("ptr_forward_confirmed", confirmed)
                res.attr("rdns", ptr["names"])
                for name in ptr["names"]:
                    generic = generic_ptr(name, ip)
                    res.pivot(T.DOMAIN, name, "reverse_dns", confidence="confirmed" if confirmed else "probable",
                              expand=not generic, note="generic reverse name embedding the address" if generic else "")
        if routing is not None and not routing["announced"] and not routing["asns"]:
            res.finding(
                "Not announced in BGP",
                "info",
                f"No BGP route covers {ip} in RIPE RIS data: traffic claiming this source address may be spoofed, "
                "or the space is unused/reserved by its holder.",
                data={"resource": ip},
                tags=["infrastructure"],
                source=SOURCE,
            )

    def _routing(self, run: _Run, ni: dict[str, Any] | None, po: dict[str, Any] | None) -> dict[str, Any] | None:
        """Origin ASNs, covering prefix, holder, IANA block (network-info + prefix-overview)."""
        if ni is None and po is None:
            return None
        res, ctx = run.res, run.ctx
        info = parse_network_info(ni) if ni is not None else {"prefix": "", "asns": []}
        overview = parse_prefix_overview(po) if po is not None else None
        asns = list(info["asns"])
        holders: dict[int, str] = {}
        if overview is not None:
            for item in overview["asns"]:
                holders[item["asn"]] = item["holder"]
                if item["asn"] not in asns:
                    asns.append(item["asn"])
        announced = overview["announced"] if overview is not None else bool(asns)
        prefix = info["prefix"] or (overview["resource"] if overview is not None and overview["announced"] else "")
        run.evidence["routing"] = {"asns": asns, "prefix": prefix, "announced": announced,
                                   "is_less_specific": bool(overview and overview["is_less_specific"])}
        res.attr("bgp_announced", announced)
        if asns:
            res.attr("asn", f"AS{asns[0]}")
            res.attr("origin_asns", [f"AS{a}" for a in asns])
            res.attr("as_org", holders.get(asns[0], ""))
        res.attr("prefix", prefix)
        if overview is not None:
            res.attr("related_prefixes", overview["related_prefixes"])
            block = overview["block"]
            if block and block.get("resource"):
                res.attr("iana_block", f"{block['resource']} {block.get('desc', '')}".strip())
        for asn in asns[:5]:
            res.pivot(T.ASN, f"AS{asn}", "belongs_to_asn", confidence="probable", expand=bool(ctx.is_seed),
                      note="" if ctx.is_seed else "listed: the address itself was reached as a pivot")
        if prefix and prefix != run.resource:
            res.pivot(T.CIDR, prefix, "in_network", confidence="probable", expand=False)
        if len(asns) > 1:
            res.finding(
                "Prefix originated by several ASNs (MOAS)",
                "info",
                f"{prefix or run.resource} is announced by {', '.join(f'AS{a}' for a in asns)}: usual for anycast and DDoS "
                "protection, but also the shape of a BGP hijack - compare with the registration holder.",
                data={"origin_asns": [f"AS{a}" for a in asns], "prefix": prefix},
                tags=["infrastructure"],
                source=SOURCE,
            )
        return {"asns": asns, "announced": announced, "prefix": prefix}

    def _geo(self, run: _Run, geo: dict[str, Any]) -> None:
        run.evidence["rir-geo"] = geo
        run.res.attr("registration_country", geo["country"])  # context only (cond 6), never 'country'

    def _whois(self, run: _Run, whois: dict[str, Any]) -> None:
        res = run.res
        run.evidence["whois"] = {"objects": whois["objects"], "dropped": whois["dropped"], "irr_routes": whois["irr_routes"], "note": whois["note"]}
        if whois["rir"]:
            res.attr("rir", whois["rir"])
        network = whois["network"]
        if network is not None:
            res.attr("rir_registration", {**network, "irr_routes": whois["irr_routes"]})
            for cidr in network["cidrs"][:4]:
                if cidr != run.resource:
                    res.pivot(T.CIDR, cidr, "in_network", confidence="confirmed", expand=False, note="RIR registration block")
        elif whois["irr_routes"]:
            res.attr("rir_registration", {"irr_routes": whois["irr_routes"], "note": whois["note"]})
        res.attr("org", whois["org_name"])
        self._contacts(run, whois["abuse_emails"], rir=whois["rir"], via="whois role/abuse object")

    def _abuse(self, run: _Run, parsed: dict[str, Any]) -> None:
        run.evidence["abuse-contact-finder"] = parsed
        if parsed["authoritative_rir"] and "rir" not in run.res.attributes:
            run.res.attr("rir", parsed["authoritative_rir"])
        records = abuse_contact_records(parsed, retrieved_at=run.retrieved_at, resource=run.resource)
        if records:
            existing = run.res.attributes.get("abuse_contacts") or []
            merged = records + [r for r in existing if r["email"] not in {x["email"] for x in records}]
            run.res.attr("abuse_contacts", merged)
            run.res.attr("abuse_contact", merged[0]["email"])
        self._contacts(run, parsed["contacts"], rir=parsed["authoritative_rir"], via="abuse-contact-finder")

    def _contacts(self, run: _Run, emails: list[str], *, rir: str, via: str) -> None:
        res = run.res
        new = [e for e in emails if e]
        if not new:
            return
        if "abuse_contacts" not in res.attributes:
            records = abuse_contact_records({"contacts": new, "authoritative_rir": rir}, retrieved_at=run.retrieved_at, resource=run.resource)
            res.attr("abuse_contacts", records)
            res.attr("abuse_contact", records[0]["email"])
        for email in new:
            res.pivot(T.EMAIL, email, "contact_email", confidence="confirmed", expand=False,
                      note=f"abuse role mailbox ({via}): takedown contact, never scored as exposure")

    # ---- CIDR ------------------------------------------------------------------------------
    def _cidr(self, run: _Run) -> None:
        po = self._call(run, "prefix-overview")
        geo = self._call(run, "rir-geo")
        whois = self._call(run, "whois", cache=False)
        abuse = self._call(run, "abuse-contact-finder")
        if po is not None:
            self._routing(run, None, po)
        if geo is not None:
            self._geo(run, parse_rir_geo(geo))
        if whois is not None:
            self._whois(run, parse_whois(whois))
        if abuse is not None:
            self._abuse(run, parse_abuse_contact_finder(abuse))

    # ---- ASN -------------------------------------------------------------------------------
    def _asn(self, run: _Run) -> None:
        res, ctx = run.res, run.ctx
        overview = self._call(run, "as-overview")
        if overview is not None:
            ov = parse_as_overview(overview)
            run.evidence["as-overview"] = ov
            res.attr("as_org", ov["holder"])
            res.attr("bgp_announced", ov["announced"])
            if ov["block"] and ov["block"].get("resource"):
                res.attr("iana_block", f"{ov['block']['resource']} {ov['block'].get('desc', '')}".strip())
        self._announced_prefixes(run)
        neighbours = self._call(run, "asn-neighbours")
        if neighbours is not None:
            nb = parse_asn_neighbours(neighbours)
            run.evidence["asn-neighbours"] = {"counts": nb["counts"], "upstreams": nb["upstreams"], "downstreams": nb["downstreams"]}
            res.attr("asn_neighbour_counts", nb["counts"])
            for item in nb["upstreams"]:
                res.pivot(T.ASN, f"AS{item['asn']}", "upstream_asn", confidence="probable", expand=False,
                          note=f"BGP neighbour (left), power {item['power']}")
            for item in nb["downstreams"]:
                res.pivot(T.ASN, f"AS{item['asn']}", "downstream_asn", confidence="probable", expand=False,
                          note=f"BGP neighbour (right), power {item['power']}")
        if overview is not None and not res.attributes.get("bgp_announced", True):
            res.finding("AS not announced in BGP", "info", f"{run.resource} originates no prefix in RIPE RIS data.",
                        data={"asn": run.resource}, tags=["infrastructure"], source=SOURCE)
        if not ctx.is_seed:
            run.evidence["note"] = "ASN reached as a pivot: announced prefixes listed without expansion"

    def _announced_prefixes(self, run: _Run) -> None:
        """cond 4: capped, incrementally scanned announced-prefixes (totals kept, <= 100 pivots)."""
        res, ctx, call = run.res, run.ctx, "announced-prefixes"
        try:
            resp = ctx.http.get(ripestat_url(call, run.resource), timeout=CALL_TIMEOUT, max_bytes=ANNOUNCED_MAX_BYTES,
                                headers={"Accept": "application/json"})
            ctx.http.check(resp)
        except (RateLimited, QuotaExceeded, Blocked, AuthRequired, DeadlineExceeded):
            raise
        except OfflineError as exc:
            run.failures[call] = str(exc)[:200] or "offline"
            run.offline.add(call)
            return
        except (HttpError, NetworkError, ValueError) as exc:
            run.failures[call] = str(exc)[:200] or type(exc).__name__
            return
        scan = count_announced_prefixes(_chunks(bytes(resp.content or b"")), ANNOUNCED_PREFIXES_CAP)
        truncated = bool(getattr(resp, "truncated", False)) or (scan["json"] and not scan["complete"])
        if not scan["json"] or (scan["status"] and scan["status"].lower() != "ok") or (scan["status_code"] or 0) >= 400:
            run.failures[call] = "RIPEstat announced-prefixes: not an 'ok' JSON envelope: could not verify"
            return
        run.answered.append(call)
        prefixes = scan["prefixes"]
        counts = {"total": scan["total"], "ipv4": scan["ipv4"], "ipv6": scan["ipv6"], "pivoted": len(prefixes),
                  "capped": scan["total"] > len(prefixes), "truncated": truncated}
        run.evidence[call] = {**counts, "bytes": scan["bytes"]}
        res.attr("announced_prefix_counts", counts)
        if truncated:
            run.failures[call] = f"answer cut at {ANNOUNCED_MAX_BYTES} bytes: counts cover the part received"
        note = "" if ctx.is_seed else "listed: ASN reached as a pivot"
        for cidr in prefixes:
            res.pivot(T.CIDR, cidr, "announces", confidence="probable", expand=bool(ctx.is_seed), note=note)

    # ---- company name -------------------------------------------------------------------------
    def _company(self, run: _Run) -> None:
        res = run.res
        data = self._call(run, "searchcomplete")
        if data is None:
            return
        found = parse_searchcomplete(data, run.resource)
        run.evidence["searchcomplete"] = found
        candidates = {"asns": [{"asn": f"AS{c['asn']}", "description": c["description"], "name_match": c["name_match"]} for c in found["asns"]],
                      "prefixes": found["prefixes"], "confidence": "low"}
        if not found["asns"] and not found["prefixes"]:
            return
        res.attr("network_candidates", candidates)
        for cand in found["asns"]:
            res.pivot(T.ASN, f"AS{cand['asn']}", "owns_network", confidence="possible", expand=False,
                      note=f"fuzzy registry name match ({cand['description'][:80]}): confirm the holder with as-overview")
        for cand in found["prefixes"]:
            res.pivot(T.CIDR, cand["cidr"], "owns_network", confidence="possible", expand=False,
                      note="fuzzy registry name match: confirm the holder")
        res.finding(
            "Candidate networks for the company name (low confidence)",
            "info",
            f"RIPEstat searchcomplete suggests {len(found['asns'])} ASN(s) and {len(found['prefixes'])} prefix(es) for "
            f"'{run.resource}' by fuzzy name match: confirm each holder before using them.",
            confidence="possible",
            data=candidates,
            tags=["infrastructure"],
            source=SOURCE,
        )
