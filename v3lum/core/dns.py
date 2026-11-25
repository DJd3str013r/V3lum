"""DNS resolution for modules.

Default backend is DNS-over-HTTPS (Google or Cloudflare JSON API): it works through
corporate proxies and Tor, and goes through the shared HTTP cache. The ``system`` backend
uses dnspython (optional dependency) against the OS resolvers.

``ctx.dns.query("example.com", "MX")`` -> DnsAnswer(records=["10 mx.example.com"], status="NOERROR")
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from v3lum.core.http import HttpError, NetworkError

RTYPES: dict[str, int] = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28,
    "SRV": 33, "DS": 43, "DNSKEY": 48, "HTTPS": 65, "CAA": 257,
}
_CODE_TO_TYPE = {v: k for k, v in RTYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

DOH_ENDPOINTS = {
    "google": "https://dns.google/resolve",
    "cloudflare": "https://cloudflare-dns.com/dns-query",
}


@dataclass
class DnsAnswer:
    name: str
    rtype: str
    status: str = "NOERROR"
    records: list[str] = field(default_factory=list)
    ttl: int = 0
    authenticated: bool = False  # DNSSEC AD flag (validated by the resolver)
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "NOERROR" and not self.error

    @property
    def nxdomain(self) -> bool:
        return self.status == "NXDOMAIN"


def reverse_name(ip: str) -> str:
    return ipaddress.ip_address(ip).reverse_pointer


def _clean(rtype: str, data: str) -> str:
    data = data.strip()
    if rtype == "TXT":
        # '"v=spf1 " "include:x" ' -> 'v=spf1 include:x'
        parts: list[str] = []
        buf, inq, esc = [], False, False
        for ch in data:
            if esc:
                buf.append(ch)
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                if inq:
                    parts.append("".join(buf))
                    buf = []
                inq = not inq
            elif inq:
                buf.append(ch)
        if parts:
            return "".join(parts)
        return data.strip('"')
    if rtype in ("CNAME", "NS", "PTR"):
        return data.rstrip(".").lower()
    if rtype == "MX":
        bits = data.split()
        if len(bits) == 2:
            host = bits[1].rstrip(".").lower() or "."  # "0 ." is a null MX (RFC 7505)
            return f"{bits[0]} {host}"
    if rtype == "SOA":
        bits = data.split()
        return " ".join([b.rstrip(".") for b in bits[:2]] + bits[2:])
    return data


class Resolver:
    """DoH (default) or system resolver. ``http`` must provide ``get(url, params=..., headers=..., ttl=...)``."""

    def __init__(self, http: Any = None, mode: str = "doh", provider: str = "google", ttl: int = 3600) -> None:
        self.http = http
        self.mode = mode
        self.provider = provider if provider in DOH_ENDPOINTS else "google"
        self.ttl = ttl

    def query(self, name: str, rtype: str = "A") -> DnsAnswer:
        rtype = rtype.upper()
        name = name.strip().rstrip(".")
        if self.mode == "system":
            return self._system(name, rtype)
        return self._doh(name, rtype)

    def ptr(self, ip: str) -> DnsAnswer:
        return self.query(reverse_name(ip), "PTR")

    def addresses(self, name: str) -> list[str]:
        ips: list[str] = []
        for rt in ("A", "AAAA"):
            ans = self.query(name, rt)
            ips.extend(r for r in ans.records if _is_ip(r))
        return ips

    # ------------------------------------------------------------------ backends
    def _doh(self, name: str, rtype: str) -> DnsAnswer:
        if self.http is None:
            return DnsAnswer(name, rtype, status="SERVFAIL", error="no HTTP client")
        providers = [self.provider] + [p for p in DOH_ENDPOINTS if p != self.provider]
        last_err = ""
        for prov in providers:
            try:
                resp = self.http.get(
                    DOH_ENDPOINTS[prov],
                    params={"name": name, "type": rtype},
                    headers={"Accept": "application/dns-json"},
                    ttl=self.ttl,
                )
                if resp.status != 200:
                    last_err = f"{prov} HTTP {resp.status}"
                    continue
                data = resp.json()
            except (NetworkError, HttpError, ValueError) as exc:
                last_err = f"{prov}: {exc}"
                continue
            return self._parse_doh(name, rtype, data)
        return DnsAnswer(name, rtype, status="SERVFAIL", error=last_err or "DoH failed")

    @staticmethod
    def _parse_doh(name: str, rtype: str, data: dict[str, Any]) -> DnsAnswer:
        status = RCODES.get(int(data.get("Status", 2)), str(data.get("Status")))
        want = RTYPES.get(rtype)
        records, ttl = [], 0
        for ans in data.get("Answer") or []:
            if want is not None and ans.get("type") != want:
                continue
            records.append(_clean(rtype, str(ans.get("data", ""))))
            ttl = int(ans.get("TTL", ttl) or ttl)
        return DnsAnswer(name, rtype, status=status, records=records, ttl=ttl, authenticated=bool(data.get("AD")))

    def _system(self, name: str, rtype: str) -> DnsAnswer:
        try:
            import dns.exception
            import dns.flags
            import dns.resolver
        except ImportError:
            if rtype in ("A", "AAAA"):
                import socket

                fam = socket.AF_INET if rtype == "A" else socket.AF_INET6
                try:
                    infos = socket.getaddrinfo(name, None, fam)
                except OSError as exc:
                    return DnsAnswer(name, rtype, status="NXDOMAIN", error=str(exc))
                return DnsAnswer(name, rtype, records=sorted({i[4][0] for i in infos}))
            return DnsAnswer(name, rtype, status="NOTIMP", error="install dnspython for system DNS")
        try:
            res = dns.resolver.Resolver()
            ans = res.resolve(name, rtype, raise_on_no_answer=False, lifetime=8)
            records = [_clean(rtype, r.to_text()) for r in ans]
            ttl = ans.rrset.ttl if ans.rrset is not None else 0
            ad = bool(ans.response.flags & dns.flags.AD)
            return DnsAnswer(name, rtype, records=records, ttl=ttl, authenticated=ad)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer(name, rtype, status="NXDOMAIN")
        except dns.resolver.NoNameservers as exc:
            return DnsAnswer(name, rtype, status="SERVFAIL", error=str(exc))
        except dns.exception.DNSException as exc:
            return DnsAnswer(name, rtype, status="SERVFAIL", error=str(exc))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
