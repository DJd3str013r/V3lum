"""team_cymru_asn: Team Cymru IP-to-ASN mapping over the core DNS-over-HTTPS resolvers (P032).

Batch p1-G02-1. DoH-only module (contract v2 s.8): every query goes through ``ctx.dns`` (core DoH,
P029) - whois.cymru.com:43 is never used (raw TCP does not pass HTTPS-only proxies), and the module
sends nothing through ``ctx.http``.

* **Queries** (cond 1): ``{reversed IPv4}.origin.asn.cymru.com``, ``{32 reversed nibbles}.origin6.asn.cymru.com``
  (full IPv6 expansion: a longer or shorter name still 'answers' for the covering block and can
  return a less specific origin), ``AS{n}.asn.cymru.com`` for AS names and ``{reversed
  IPv4}.peer.asn.cymru.com`` for upstream peers.
* **Parsing** (cond 2): ``ASN [ASN...] | prefix | CC | registry | allocated`` after the core TXT
  normalisation (Google unquoted, Cloudflare quoted or multi-string); outputs ``asn``, ``as_org``
  (from the AS name), ``country`` and a cidr pivot, plus the ASN pivot (relation ``belongs_to_asn``).
* **Rule 5** (cond 3): an NXDOMAIN origin answer means 'no announcing ASN' (documented meaningful
  absence, P328): EMPTY. SERVFAIL, REFUSED, timeouts, NODATA and unparseable TXT are 'could not
  verify' (ERROR). Private and bogon addresses and private ASNs are never queried (not_applicable).
* **Cache** (cond 4): answers are cached by the core resolver under the DoH profile TTL (1 h cap);
  the record TTL is kept in the evidence.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SOURCE = "core_doh.resolvers"
ORIGIN_ZONE = "origin.asn.cymru.com"
ORIGIN6_ZONE = "origin6.asn.cymru.com"
PEER_ZONE = "peer.asn.cymru.com"
ASN_ZONE = "asn.cymru.com"
MAX_ORIGIN_NAMES = 3  # AS-name lookups for a multi-origin (MOAS) prefix


# ======================================================================================
# Query names (cond 1)
# ======================================================================================


def _public_ip(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address (IPv4-mapped IPv6 -> IPv4) when globally routable, else None (never queried)."""
    try:
        ip = ipaddress.ip_address(str(value).strip().strip("[]").split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip if ip.is_global and not ip.is_multicast else None


def asn_number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    text = str(value or "").strip().upper()
    text = text[2:].strip() if text.startswith("AS") else text
    if not text.isdigit():
        return None
    n = int(text)
    return n if 0 < n < 4294967296 else None


def is_bogon_asn(value: Any) -> bool:
    """AS0, AS_TRANS 23456, documentation, private and reserved ASNs: never queried."""
    n = asn_number(value)
    return n is None or n == 23456 or 64496 <= n <= 131071 or n >= 4200000000


def origin_qname(value: Any) -> str | None:
    """'8.8.8.8.origin.asn.cymru.com' or the 32-nibble '... .origin6.asn.cymru.com'; None for
    private/bogon addresses."""
    ip = _public_ip(value)
    if ip is None:
        return None
    if ip.version == 4:
        return ".".join(reversed(str(ip).split("."))) + "." + ORIGIN_ZONE
    nibbles = ip.exploded.replace(":", "")  # always 32 hex digits
    return ".".join(reversed(nibbles)) + "." + ORIGIN6_ZONE


def peer_qname(value: Any) -> str | None:
    """'{reversed IPv4}.peer.asn.cymru.com' (Team Cymru publishes peers for IPv4 only)."""
    ip = _public_ip(value)
    if ip is None or ip.version != 4:
        return None
    return ".".join(reversed(str(ip).split("."))) + "." + PEER_ZONE


def asname_qname(value: Any) -> str | None:
    """'AS{n}.asn.cymru.com'; None for private/reserved ASNs."""
    n = asn_number(value)
    return None if n is None or is_bogon_asn(n) else f"AS{n}.{ASN_ZONE}"


# ======================================================================================
# TXT parsing (cond 2)
# ======================================================================================


def normalise_txt(text: Any) -> str:
    """Residual quoting after the core TXT normalisation (P029): '"a" "b"' -> 'ab', '"a"' -> 'a'."""
    if not isinstance(text, str):
        return ""
    value = text.strip()
    if value.startswith('"'):
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', value)
        value = "".join(p.replace('\\"', '"').replace("\\\\", "\\") for p in parts) if parts else value.strip('"')
    return value.strip()


def _cc(value: str) -> str:
    return value.upper() if re.fullmatch(r"[A-Za-z]{2}", value or "") else ""


def _date(value: str) -> str:
    return value if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value or "") else ""


def parse_origin(txt: Any) -> dict[str, Any] | None:
    """'ASN [ASN...] | prefix | CC | registry | allocated' -> dict, or None when unparseable."""
    parts = [p.strip() for p in normalise_txt(txt).split("|")]
    if len(parts) < 3 or "/" not in parts[1]:
        return None
    asns = [n for n in (asn_number(x) for x in parts[0].split()) if n]
    try:
        prefix = str(ipaddress.ip_network(parts[1], strict=False))
    except ValueError:
        return None
    if not asns:
        return None
    return {"asns": asns, "asn": asns[0], "prefix": prefix, "country": _cc(parts[2]),
            "registry": parts[3].lower() if len(parts) > 3 else "", "allocated": _date(parts[4]) if len(parts) > 4 else ""}


def parse_peer(txt: Any) -> dict[str, Any] | None:
    """peer.asn.cymru.com: 'PEER_ASN [PEER_ASN...] | prefix | CC | registry | allocated'."""
    rec = parse_origin(txt)
    return None if rec is None else {"peer_asns": rec["asns"], "prefix": rec["prefix"]}


def parse_asname(txt: Any) -> dict[str, Any] | None:
    """'ASN | CC | registry | allocated | AS name' -> {asn, country, registry, allocated, as_name,
    as_handle, as_org}. The trailing ', CC' of the name is removed; as_org is the part after the
    first ' - ' (the handle comes before it)."""
    parts = [p.strip() for p in normalise_txt(txt).split("|", 4)]
    if len(parts) < 5:
        return None
    asn = asn_number(parts[0])
    if not asn or not parts[4]:
        return None
    cc = _cc(parts[1])
    name = parts[4]
    if cc and name.upper().endswith(", " + cc):
        name = name[: -(len(cc) + 2)].rstrip()
    handle, _, org = name.partition(" - ")
    if not org:
        handle, org = "", name
    return {"asn": asn, "country": cc, "registry": parts[2].lower(), "allocated": _date(parts[3]), "as_name": name,
            "as_handle": handle.strip(), "as_org": org.strip()}


_PARSERS = {"origin": parse_origin, "peer": parse_peer, "asname": parse_asname}


@dataclass
class Outcome:
    """One DoH TXT lookup: status 'ok' | 'absent' (NXDOMAIN, documented) | 'unknown' (could not verify)."""

    kind: str
    qname: str
    status: str
    records: list[dict[str, Any]] = field(default_factory=list)
    ttl: int = 0
    reason: str = ""
    dns_status: str = ""
    resolver: str = ""
    raw: list[str] = field(default_factory=list)

    def evidence(self) -> dict[str, Any]:
        return {"query": self.qname, "status": self.status, "dns_status": self.dns_status, "ttl": self.ttl,
                "resolver": self.resolver, "records": self.raw, "reason": self.reason}


def interpret(kind: str, qname: str, answer: Any) -> Outcome:
    """Map one ``ctx.dns`` DnsAnswer to an :class:`Outcome` (cond 2-3)."""
    status = str(getattr(answer, "status", "") or "SERVFAIL")
    resolver = str(getattr(answer, "resolver", "") or "")
    ttl = int(getattr(answer, "ttl", 0) or 0)
    error = str(getattr(answer, "error", "") or "")
    records = [r for r in (getattr(answer, "records", None) or []) if isinstance(r, str)]
    out = Outcome(kind, qname, "unknown", ttl=ttl, dns_status=status, resolver=resolver, raw=records[:10])
    if getattr(answer, "nxdomain", False):
        out.status = "absent"
        out.reason = {"origin": "no announcing ASN (Team Cymru NXDOMAIN)", "peer": "no peer data (Team Cymru NXDOMAIN)",
                      "asname": "ASN not in the Team Cymru AS name table (NXDOMAIN)"}[kind]
        return out
    if getattr(answer, "could_not_verify", True):
        out.reason = f"could not verify: DNS {status}" + (f" ({error[:160]})" if error else "")
        return out
    if not records:
        out.reason = "could not verify: NOERROR without a TXT answer (NODATA)"
        return out
    parsed = [p for p in (_PARSERS[kind](r) for r in records) if p]
    if not parsed:
        out.reason = f"could not verify: unparseable TXT {records[0][:80]!r}"
        return out
    if kind in ("origin", "peer"):
        parsed.sort(key=lambda r: -ipaddress.ip_network(r["prefix"]).prefixlen)  # most specific first
    out.status, out.records = "ok", parsed
    return out


def lookup(ctx: Any, kind: str, qname: str) -> Outcome:
    return interpret(kind, qname, ctx.dns.query(qname, "TXT"))


# ======================================================================================
# The module
# ======================================================================================


@register
class TeamCymruAsn(Module):
    name = "team_cymru_asn"
    title = "Team Cymru IP-to-ASN (DoH)"
    description = (
        "Origin ASN, BGP prefix, registry country and AS name of an IP (or the AS name of an ASN) from Team Cymru's "
        "IP-to-ASN DNS service, queried through the core DNS-over-HTTPS resolvers."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6, T.ASN}
    produces = {T.ASN, T.CIDR}
    tags = {"free"}
    reference = "https://www.team-cymru.com/ip-asn-mapping"
    notice = "Team Cymru IP-to-ASN community service (free) through the core DoH resolvers; whois.cymru.com:43 is never used."
    # ---- contract v2 declarations (DoH-only module, contract s.8) -----------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # the DoH resolver operator sees the query name (the address reversed)
    provider = "core_doh"
    sources = (SOURCE,)
    hosts = ()
    access_model = "free_noauth_unlimited"
    max_requests = 0  # ctx.dns is not counted
    expected_latency = 1.0  # live 2026-11-26: 1.0-2.4 s cold for 3 TXT queries, cached afterwards
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.ASN:
            return asname_qname(entity.value) is not None
        return origin_qname(entity.value) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type is T.ASN:
            name_q = asname_qname(entity.value)
            if name_q is None:
                return res.mark(Status.SKIPPED, f"{entity.value} is a private or reserved ASN: never queried", reason_code="not_applicable")
            return self._asname_only(res, ctx, name_q)
        qname = origin_qname(entity.value)
        if qname is None:
            return res.mark(Status.SKIPPED, "private or bogon address: never queried", reason_code="not_applicable")
        origin = lookup(ctx, "origin", qname)
        evidence: dict[str, Any] = {"origin": origin.evidence()}
        res.raw = evidence
        if origin.status == "absent":
            return res.mark(Status.EMPTY)  # cond 3: NXDOMAIN = no announcing ASN (documented absence)
        if origin.status != "ok":
            return res.mark(Status.ERROR, origin.reason, reason_code="timeout" if origin.dns_status == "TIMEOUT" else "error")
        best = origin.records[0]
        unverified: list[str] = []
        names: dict[int, dict[str, Any]] = {}
        for asn in best["asns"][:MAX_ORIGIN_NAMES]:
            name_q = asname_qname(asn)
            if name_q is None:
                continue
            outcome = lookup(ctx, "asname", name_q)
            evidence.setdefault("asname", []).append(outcome.evidence())
            if outcome.status == "ok":
                names[asn] = outcome.records[0]
            elif outcome.status == "unknown":
                unverified.append(f"AS name of AS{asn}: {outcome.reason}")
        peers: list[int] = []
        peer_q = peer_qname(entity.value)
        if peer_q is not None:
            outcome = lookup(ctx, "peer", peer_q)
            evidence["peer"] = outcome.evidence()
            if outcome.status == "ok":
                peers = [a for a in outcome.records[0]["peer_asns"] if a not in best["asns"]]
            elif outcome.status == "unknown":
                unverified.append(f"peers: {outcome.reason}")
        primary = names.get(best["asn"], {})
        res.attr("asn", f"AS{best['asn']}")
        res.attr("origin_asns", [f"AS{a}" for a in best["asns"]])
        res.attr("as_org", primary.get("as_org", ""))
        res.attr("country", best["country"])
        res.attr("prefix", best["prefix"])
        res.attr("rir", best["registry"])
        res.attr("allocated", best["allocated"])
        res.attr("upstream_asns", [f"AS{a}" for a in peers])
        for asn in best["asns"]:
            res.pivot(T.ASN, f"AS{asn}", "belongs_to_asn", confidence="probable", expand=bool(ctx.is_seed),
                      note="" if ctx.is_seed else "listed: the address itself was reached as a pivot")
        res.pivot(T.CIDR, best["prefix"], "in_network", confidence="probable", expand=False, note="BGP prefix (Team Cymru)")
        for asn in peers[:10]:
            res.pivot(T.ASN, f"AS{asn}", "upstream_asn", confidence="probable", expand=False, note="BGP peer of the origin AS (Team Cymru)")
        if unverified:
            res.error = "; ".join(unverified)[:600]
        return res

    def _asname_only(self, res: ModuleResult, ctx: Any, qname: str) -> ModuleResult:
        outcome = lookup(ctx, "asname", qname)
        res.raw = {"asname": outcome.evidence()}
        if outcome.status == "absent":
            return res.mark(Status.EMPTY)
        if outcome.status != "ok":
            return res.mark(Status.ERROR, outcome.reason, reason_code="timeout" if outcome.dns_status == "TIMEOUT" else "error")
        rec = outcome.records[0]
        res.attr("as_org", rec["as_org"])
        res.attr("country", rec["country"])
        res.attr("rir", rec["registry"])
        res.attr("allocated", rec["allocated"])
        return res
