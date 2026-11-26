"""DNS resolution for modules: the hardened DoH resolver layer (P029, module-author contract v2 s.8).

``ctx.dns.query("example.com", "MX")`` -> ``DnsAnswer(records=["10 mx.example.com"], status="NOERROR",
resolver="google")``.

Resolvers (``DOH_PROVIDERS``; terms and tier recorded in the provider registry):

* ``google`` - Google Public DNS JSON API. Every request carries ``edns_client_subnet=0.0.0.0/0`` so
  the egress subnet never reaches the authoritative servers of the investigated name.
* ``cloudflare`` - Cloudflare 1.1.1.1 JSON API (ECS-free); first choice for names tagged hostile.
* ``quad9`` - RFC 8484 wire format on the no-ECS endpoint, only through dnspython (optional extra);
  skipped with ``'needs dnspython'`` otherwise. Never hand-parsed.
* ``internal`` - the organisation's own DoH JSON endpoint (setting ``doh_internal``, https only; an
  https URL entry of ``doh_providers`` is accepted too). Always listed first when configured.

OpenDNS/CleanBrowsing are not defaults (terms unknown). Default order: setting ``doh_providers``
(``['google', 'cloudflare']``) with ``internal`` prepended.

Semantics every module relies on (rule 5: "could not verify" is never "absent"):

* ``NXDOMAIN`` only comes from a real NXDOMAIN answer (DoH ``Status`` 3, dnspython NXDOMAIN, or the
  ``getaddrinfo`` fallback's ``EAI_NONAME``). SERVFAIL, REFUSED, ``TIMEOUT`` and transport failures
  stay distinct, carry the error text and read ``could_not_verify``.
* Failover to the next resolver happens only on transport errors (connection failures, timeouts -
  HTTP 408 included -, corrupt bodies that are not a DoH answer), HTTP 5xx and 429 (P029 cond 1). It
  never happens on a DNS answer (NOERROR, NXDOMAIN, SERVFAIL, REFUSED...), so a resolver is never
  "shopped" for a different answer, and never on a refusal: HTTP 401/403/407/451 and other 4xx, or
  an anti-bot/challenge page (P321 'blocked'), give SERVFAIL / could not verify for that query. A
  resolver host the HTTP layer short-circuited for the run (A9 circuit) is skipped like an open
  resolver circuit; offline mode skips resolvers whose answer is not cached (no circuit count).
* The failover chain of one query takes at most ``FAILOVER_BUDGET`` (5 s): each request gets
  ``min(remaining, 3 s)``. A per-Resolver (per-run) circuit breaker skips a resolver after
  ``CIRCUIT_THRESHOLD`` (3) consecutive failures.
* ``allow_public=False`` (disclosure none/internal or TLP:RED): public resolvers are never used; the
  answer is SERVFAIL ``'public DoH not allowed (TLP/disclosure)'`` unless the internal resolver
  answers. ``allow_public_fallback=False`` (TLP:AMBER and above): a query never moves from the
  internal resolver to a public one (P029 cond 7, A2).
* ``mode='system'`` (setting ``dns_mode``) uses the OS resolvers (dnspython, else ``getaddrinfo``)
  and runs only when configured explicitly - it is never a silent fallback, because the corporate
  resolver's address would reach the target's name servers.
* ``authenticated`` is the resolver's AD flag: "validated by resolver", never proof of DNSSEC.
* TXT answers are unquoted and multi-string records joined (Cloudflare quotes, Google does not);
  RFC 3597 generic data (``\\# len hex``) is decoded where possible (CAA always).
* ``wildcard(zone)`` probes a random 16-character label (A, then AAAA), cached per Resolver;
  ``confirm_nxdomain(name)`` asks a *different* resolver before an NXDOMAIN drives a takeover,
  typosquat or "domain does not exist" decision; ``dnsbl(query_name, zone)`` never goes through a
  public resolver and maps refusal codes (127.255.255.x) to blocked/rate_limited/error, never to
  "not listed".

The Resolver sends through the ``http`` object it receives: the engine hands it the per-run core
DoH scope (``Runtime.doh_scope()``: not counted in module ``max_requests`` or quotas, no module UA
or ``min_interval``; its hosts still reach the disclosure ledger).
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import secrets
import socket
import string
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit

from v3lum.core import http as _http

__all__ = [
    "CIRCUIT_THRESHOLD",
    "DEFAULT_PROVIDERS",
    "DNSBL_REFUSAL_CODES",
    "DOH_ENDPOINTS",
    "DOH_PROVIDERS",
    "ECS_ZERO",
    "FAILOVER_BUDGET",
    "PUBLIC_DOH_HOSTS",
    "PUBLIC_NOT_ALLOWED",
    "PUBLIC_FALLBACK_NOT_ALLOWED",
    "RCODES",
    "REQUEST_TIMEOUT",
    "RTYPES",
    "DnsAnswer",
    "DnsblResult",
    "Resolver",
    "WildcardInfo",
    "dnsbl_label",
    "is_public_doh_host",
    "reverse_name",
]

RTYPES: dict[str, int] = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33,
    "NAPTR": 35, "DNAME": 39, "DS": 43, "SSHFP": 44, "RRSIG": 46, "NSEC": 47, "DNSKEY": 48, "TLSA": 52,
    "CDS": 59, "CDNSKEY": 60, "OPENPGPKEY": 61, "SVCB": 64, "HTTPS": 65, "SPF": 99, "URI": 256, "CAA": 257,
}
_CODE_TO_TYPE = {v: k for k, v in RTYPES.items()}
RCODES: dict[int, str] = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN",
    7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE", 16: "BADVERS",
}

#: Resolver catalogue. ``ecs``: 'zero' sends edns_client_subnet=0.0.0.0/0, 'none' sends nothing (the
#: endpoint itself is ECS-free). ``provider_id`` is the provider-registry fragment of the resolver.
#: The internal URL comes from setting ``doh_internal`` per Resolver (empty here).
DOH_PROVIDERS: dict[str, dict[str, str]] = {
    "google": {"url": "https://dns.google/resolve", "kind": "json", "ecs": "zero", "provider_id": "google_public_dns"},
    "cloudflare": {"url": "https://cloudflare-dns.com/dns-query", "kind": "json", "ecs": "none", "provider_id": "cloudflare_dns"},
    "quad9": {"url": "https://dns.quad9.net/dns-query", "kind": "wire", "ecs": "none", "provider_id": "quad9"},
    "internal": {"url": "", "kind": "json", "ecs": "none", "provider_id": "internal_doh"},
}
#: Legacy name -> URL table of the JSON resolvers (v1 compatibility).
DOH_ENDPOINTS: dict[str, str] = {name: spec["url"] for name, spec in DOH_PROVIDERS.items() if spec["kind"] == "json" and spec["url"]}
DEFAULT_PROVIDERS: tuple[str, ...] = ("google", "cloudflare")
PUBLIC_PROVIDERS: tuple[str, ...] = ("google", "cloudflare", "quad9")
#: Hosts of public DoH services: never accepted as the organisation's "internal" resolver.
PUBLIC_DOH_HOSTS: frozenset[str] = frozenset({
    "dns.google", "dns.google.com", "8.8.8.8", "8.8.4.4", "cloudflare-dns.com", "one.one.one.one", "1.1.1.1",
    "1.0.0.1", "security.cloudflare-dns.com", "family.cloudflare-dns.com", "dns.quad9.net", "dns9.quad9.net",
    "dns10.quad9.net", "dns11.quad9.net", "9.9.9.9", "149.112.112.112", "doh.opendns.com", "dns.opendns.com",
    "doh.familyshield.opendns.com", "doh.cleanbrowsing.org", "dns.adguard-dns.com", "dns.adguard.com",
    "doh.mullvad.net", "dns.nextdns.io", "doh.dns.sb", "dns.alidns.com", "doh.pub", "dns.twnic.tw",
})
#: Public DoH operator domains: the domain itself and every subdomain (label-boundary match, e.g.
#: mozilla.cloudflare-dns.com) is public, never the organisation's internal resolver.
_PUBLIC_DOH_DOMAINS: tuple[str, ...] = (
    "dns.google", "dns.google.com", "cloudflare-dns.com", "one.one.one.one", "quad9.net", "opendns.com",
    "cleanbrowsing.org", "adguard-dns.com", "adguard.com", "mullvad.net", "nextdns.io", "dns.sb", "alidns.com",
    "doh.pub", "dns.twnic.tw", "controld.com", "dns0.eu",
)
#: Anycast networks of the public resolvers (IP-literal DoH URLs).
_PUBLIC_DOH_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "8.8.8.0/24", "8.8.4.0/24", "2001:4860:4860::/48", "1.1.1.0/24", "1.0.0.0/24", "2606:4700:4700::/48",
        "9.9.9.0/24", "149.112.112.0/24", "2620:fe::/48", "208.67.216.0/21", "2620:119:35::/48", "2620:119:53::/48",
        "94.140.14.0/24", "94.140.15.0/24", "2a10:50c0::/32", "185.228.168.0/24", "185.228.169.0/24",
    )
)

ECS_ZERO = "0.0.0.0/0"
FAILOVER_BUDGET = 5.0  # seconds across all resolvers of one query (P029 cond 1)
REQUEST_TIMEOUT = 3.0  # per DoH request (capped by the remaining budget)
CIRCUIT_THRESHOLD = 3  # consecutive failures before a resolver is skipped for this Resolver
WILDCARD_LABEL_LEN = 16
PUBLIC_NOT_ALLOWED = "public DoH not allowed (TLP/disclosure)"
PUBLIC_FALLBACK_NOT_ALLOWED = "public DoH fallback not allowed (TLP/disclosure)"

#: HTTP statuses besides 5xx after which the next resolver is tried (P029 cond 1): 429 and the
#: server's request timeout 408 (a transport timeout). Every other non-200 status - refusals
#: (401/403/407/451) and request problems (400/404/415...) - is SERVFAIL without failover.
_FAILOVER_STATUS = frozenset({408, 429})
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

#: Refusal codes of DNSBL operators (Spamhaus convention, used by others too). Never 'not listed'.
DNSBL_REFUSAL_CODES: dict[str, tuple[str, str]] = {
    "127.255.255.252": ("error", "DNSBL refused the query: typing error in the DNSBL name"),
    "127.255.255.254": ("blocked", "DNSBL refused the query: open/public resolver"),
    "127.255.255.255": ("rate_limited", "DNSBL refused the query: excessive number of queries"),
}
#: Zone-specific refusal codes (matched on the zone or any parent zone).
_ZONE_REFUSAL_CODES: dict[str, dict[str, tuple[str, str]]] = {
    "uribl.com": {"127.0.0.1": ("blocked", "URIBL refused the query (public resolver or query volume)")},
    "surbl.org": {"127.0.0.1": ("blocked", "SURBL refused the query (public resolver or query volume)")},
    "dbl.spamhaus.org": {"127.0.1.255": ("error", "Spamhaus DBL: IP queries prohibited")},
    "zen.spamhaus.org": {"127.0.1.255": ("error", "Spamhaus: IP queries prohibited for this zone")},
}
_LOOPBACK_NET = ipaddress.ip_network("127.0.0.0/8")


# --------------------------------------------------------------------------------------
# results
# --------------------------------------------------------------------------------------


@dataclass
class DnsAnswer:
    """One DNS answer as modules see it.

    ``status``: NOERROR, NXDOMAIN, SERVFAIL, REFUSED, TIMEOUT, FORMERR, NOTIMP... ``records`` holds
    normalised data of the asked type only (CNAME chain hops are in ``cnames``). ``authenticated``
    is the resolver's AD flag ("validated by resolver", never proof). ``resolver`` names the
    resolver that answered (for failures: every resolver tried, comma separated).
    """

    name: str
    rtype: str
    status: str = "NOERROR"
    records: list[str] = field(default_factory=list)
    ttl: int = 0
    authenticated: bool = False  # AD flag: validated by the resolver, never proof
    error: str = ""
    resolver: str = ""
    cnames: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """NOERROR without error (records may be empty: see ``nodata``)."""
        return self.status == "NOERROR" and not self.error

    @property
    def nxdomain(self) -> bool:
        """A real NXDOMAIN answer (never produced from SERVFAIL, timeouts or transport errors)."""
        return self.status == "NXDOMAIN" and not self.error

    @property
    def nodata(self) -> bool:
        """NOERROR without records of the asked type (the name exists, or the zone hides NXDOMAIN)."""
        return self.ok and not self.records

    @property
    def could_not_verify(self) -> bool:
        """SERVFAIL/REFUSED/TIMEOUT/transport failure/policy refusal: never read it as "absent"."""
        return self.status not in ("NOERROR", "NXDOMAIN") or bool(self.error)

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready form for evidence (resolver included, P029 cond 8)."""
        data = asdict(self)
        data["authenticated_note"] = "validated by resolver (AD flag), not proof"
        return data


@dataclass
class DnsblResult:
    """Outcome of one DNSBL lookup.

    ``listed``: True (listed, ``codes`` = return codes), False (a non-public resolver answered
    NXDOMAIN or no address) or None (could not verify: refusal, rate limit, failure, or only public
    resolvers available). ``status``: 'ok' | 'blocked' | 'rate_limited' | 'error' | 'unverified'.
    """

    listed: bool | None
    codes: list[str] = field(default_factory=list)
    status: str = "unverified"
    reason: str = ""
    query: str = ""
    resolver: str = ""


@dataclass(frozen=True)
class WildcardInfo:
    """Random-label probe of a zone. ``wildcard``: True (records came back for the random name),
    False (both probes NXDOMAIN), None (could not verify - including NODATA zones). ``nodata``: the
    zone answers NOERROR/NODATA for names that do not exist (e.g. Cloudflare-hosted zones, or a
    wildcard of another type), so neither NOERROR nor a missing NXDOMAIN proves anything there."""

    zone: str
    wildcard: bool | None
    nodata: bool = False
    records: tuple[str, ...] = ()


class _Failover(Exception):
    """No DNS answer from this resolver: try the next one (counts for the circuit breaker)."""

    def __init__(self, message: str, *, timeout: bool = False) -> None:
        super().__init__(message)
        self.timeout = timeout


class _Skip(Exception):
    """This resolver cannot be used for the query (missing extra, policy, offline, host
    short-circuited for the run): next resolver, no circuit count."""


class _Refused(Exception):
    """The resolver refused the request (HTTP 401/403/407/451, a challenge page): SERVFAIL for this
    query, no failover and no circuit count (P029 cond 1)."""


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def reverse_name(ip: str) -> str:
    """PTR name of an IP ('4.4.8.8.in-addr.arpa'). Raises ValueError for non-IPs."""
    return ipaddress.ip_address(ip).reverse_pointer


def dnsbl_label(value: str) -> str:
    """DNSBL query label: reversed octets/nibbles for an IP, the normalised name otherwise.

    ``ctx.dns.dnsbl(dnsbl_label("127.0.0.2"), "zen.spamhaus.org")`` queries ``2.0.0.127.zen.spamhaus.org``.
    """
    text = str(value).strip().rstrip(".")
    try:
        ip = ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return _qname(text)
    return ip.reverse_pointer.rsplit(".", 2)[0]


def _qname(name: Any) -> str:
    text = str(name or "").strip().rstrip(".").lower()
    if text and not text.isascii():
        try:
            text = text.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    return text


def _valid_qname(name: str) -> bool:
    if not name or len(name) > 253:
        return False
    return all(0 < len(label) <= 63 for label in name.split("."))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _short(exc: BaseException | str, limit: int = 200) -> str:
    """One-line, control-character-free, bounded text (resolver-supplied text is untrusted)."""
    text = str(exc).strip() or type(exc).__name__
    text = " ".join(_CONTROL_RE.sub(" ", text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def is_public_doh_host(host: str) -> bool:
    """True for the hosts of public DoH services (never accepted as the internal resolver)."""
    host = str(host or "").strip().lower().rstrip(".").strip("[]")
    if not host:
        return False
    if host in PUBLIC_DOH_HOSTS or any(host == d or host.endswith("." + d) for d in _PUBLIC_DOH_DOMAINS):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip.version == net.version and ip in net for net in _PUBLIC_DOH_NETS)


def _is_timeout(exc: BaseException) -> bool:
    if isinstance(exc, TimeoutError):
        return True
    text = f"{type(exc).__name__} {exc}".lower()
    return "timeout" in text or "timed out" in text


def _load_dnspython() -> Any:
    """The dnspython package (optional extra ``full``), or None when it is not installed."""
    try:
        import dns.exception
        import dns.flags
        import dns.message
        import dns.rcode
        import dns.rdata
        import dns.rdataclass
        import dns.rdatatype
        import dns.resolver
    except ImportError:
        return None
    return dns


def _comment(data: dict[str, Any]) -> str:
    """The resolver's ``Comment`` (EDE text) as one bounded, control-character-free line."""
    raw = data.get("Comment")
    text = "; ".join(str(c) for c in raw if c) if isinstance(raw, list) else str(raw or "")
    return _short(text, 300) if text.strip() else ""


def _exc_types(*names: str) -> tuple[type[BaseException], ...]:
    out = []
    for name in names:
        obj = getattr(_http, name, None)
        if isinstance(obj, type) and issubclass(obj, BaseException):
            out.append(obj)
    return tuple(out)


# Raised by the HTTP layer and never turned into a DNS answer: kill switch, run deadline, caps.
_PROPAGATE = _exc_types("Cancelled", "DeadlineExceeded", "RequestCapReached")
_POLICY = _exc_types("PolicyError", "ConfigError")
_OFFLINE = _exc_types("OfflineError")
#: Refusals (anti-bot/login wall, auth): SERVFAIL for the query, never a failover (P029 cond 1).
_REFUSED = _exc_types("Blocked", "AuthRequired")
_TRANSPORT = _exc_types("NetworkError", "HttpError")


class _SystemClock:
    @staticmethod
    def monotonic() -> float:
        return time.monotonic()


def _default_clock() -> Any:
    try:
        from v3lum.core.clock import SYSTEM_CLOCK
    except ImportError:  # wave-1 transition: clock.py arrives with WP03
        return _SystemClock()
    return SYSTEM_CLOCK


def _setting(settings: Any, name: str, default: Any = None) -> Any:
    getter = getattr(settings, "get", None)
    if callable(getter):
        try:
            return getter(name, default)
        except TypeError:  # pragma: no cover - exotic mapping
            return getter(name)
    return default


# --------------------------------------------------------------------------------------
# record normalisation
# --------------------------------------------------------------------------------------


def _txt(data: str) -> str:
    """Unquote presentation-format TXT (Cloudflare/dnspython) and join multi-string records.

    Google returns TXT unquoted and already joined: those values are kept as they are.
    """
    if not data.startswith('"'):
        return data
    out = bytearray()
    i, n, inq = 0, len(data), False
    while i < n:
        ch = data[i]
        if inq:
            if ch == "\\" and i + 1 < n:
                digits = data[i + 1 : i + 4]
                if len(digits) == 3 and digits.isdigit() and int(digits) <= 255:
                    out.append(int(digits))
                    i += 4
                    continue
                out += data[i + 1].encode("utf-8")
                i += 2
                continue
            if ch == '"':
                inq = False
            else:
                out += ch.encode("utf-8")
            i += 1
            continue
        if ch == '"':
            inq = True
        elif not ch.isspace():  # malformed text outside quotes: keep it rather than lose data
            out += ch.encode("utf-8")
        i += 1
    return out.decode("utf-8", errors="replace")


def _decode_generic(rtype: str, data: str) -> str | None:
    """RFC 3597 ``\\# <len> <hex>`` data -> presentation format (dnspython; CAA built in)."""
    parts = data.split()
    try:
        length = int(parts[1])
        raw = bytes.fromhex("".join(parts[2:]))
    except (IndexError, ValueError):
        return None
    if len(raw) != length:
        return None
    dns = _load_dnspython()
    if dns is not None and rtype in RTYPES:
        try:
            return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rtype), data).to_text()
        except Exception:  # noqa: BLE001 - dnspython raises many types for odd data
            pass
    if rtype == "CAA" and len(raw) >= 2 and len(raw) >= 2 + raw[1]:
        flags, taglen = raw[0], raw[1]
        tag = raw[2 : 2 + taglen].decode("ascii", errors="replace")
        value = raw[2 + taglen :].decode("utf-8", errors="replace").replace("\\", "\\\\").replace('"', '\\"')
        return f'{flags} {tag} "{value}"'
    return None


def _clean(rtype: str, data: str) -> str:
    data = str(data).strip()
    if data.startswith("\\#"):
        decoded = _decode_generic(rtype, data)
        if decoded is not None:
            data = decoded.strip()
    if rtype in ("TXT", "SPF"):
        # '"v=spf1 " "include:x"' -> 'v=spf1 include:x'
        return _txt(data)
    if rtype in ("CNAME", "NS", "PTR", "DNAME"):
        return data.rstrip(".").lower()
    if rtype in ("A", "AAAA"):
        try:
            return ipaddress.ip_address(data).compressed
        except ValueError:
            return data
    if rtype == "MX":
        bits = data.split()
        if len(bits) == 2:
            host = bits[1].rstrip(".").lower() or "."  # "0 ." is a null MX (RFC 7505)
            return f"{bits[0]} {host}"
    if rtype == "SRV":
        bits = data.split()
        if len(bits) == 4:
            return " ".join(bits[:3] + [bits[3].rstrip(".").lower() or "."])
    if rtype == "SOA":
        bits = data.split()
        return " ".join([b.rstrip(".") for b in bits[:2]] + bits[2:])
    return data


def _parse_doh(name: str, rtype: str, data: dict[str, Any], resolver: str) -> DnsAnswer:
    code = data.get("Status")
    status = RCODES.get(code, f"RCODE{code}") if isinstance(code, int) else "SERVFAIL"
    want = RTYPES.get(rtype)
    records: list[str] = []
    cnames: list[str] = []
    ttls: list[int] = []
    for ans in data.get("Answer") or []:
        if not isinstance(ans, dict):
            continue
        atype = ans.get("type")
        if atype == RTYPES["CNAME"] and rtype != "CNAME":
            cnames.append(_clean("CNAME", str(ans.get("data", ""))))
            continue
        if want is not None and atype != want:
            continue
        records.append(_clean(rtype, str(ans.get("data", ""))))
        try:
            ttls.append(int(ans.get("TTL") or 0))
        except (TypeError, ValueError):
            pass
    ttl = min(ttls) if ttls else 0
    if not ttls:  # negative answer: the SOA TTL of the authority section bounds negative caching
        for auth in data.get("Authority") or []:
            if isinstance(auth, dict) and auth.get("type") == RTYPES["SOA"]:
                try:
                    ttl = int(auth.get("TTL") or 0)
                except (TypeError, ValueError):
                    ttl = 0
                break
    error = ""
    if status not in ("NOERROR", "NXDOMAIN"):
        error = f"{status} from {resolver}" + (f": {_comment(data)}" if _comment(data) else "")
    return DnsAnswer(
        name, rtype, status=status, records=records, ttl=ttl, authenticated=bool(data.get("AD")), error=error,
        resolver=resolver, cnames=cnames,
    )


_INVALID = object()  # sentinel: the body is not JSON


def _doh_status(resp: Any) -> int | None:
    try:
        data = json.loads(resp.content or b"")
    except (ValueError, TypeError, AttributeError):
        return None
    return data.get("Status") if isinstance(data, dict) and isinstance(data.get("Status"), int) else None


def _cacheable_json(resp: Any) -> bool:
    """cache_if for DoH JSON: cache real answers only (NOERROR/NXDOMAIN), never SERVFAIL/REFUSED."""
    return getattr(resp, "status", 0) == 200 and _doh_status(resp) in (0, 3)


def _cacheable_wire(resp: Any) -> bool:
    if getattr(resp, "status", 0) != 200:
        return False
    dns = _load_dnspython()
    if dns is None:
        return False
    try:
        return dns.message.from_wire(resp.content).rcode() in (0, 3)
    except Exception:  # noqa: BLE001
        return False


def _classification(resp: Any) -> Any:
    """The P321 classification of a response (the client's, else ``classify(keyless=True)``)."""
    found = getattr(resp, "classification", None)
    if found is None:
        classify = getattr(_http, "classify", None)
        if callable(classify):
            try:
                found = classify(resp, keyless=True)
            except Exception:  # noqa: BLE001 - classification must never break DNS
                found = None
    return found


def _classified(resp: Any) -> str:
    """Why a response is an anti-bot/error page (P321 classification, legacy block_reason)."""
    found = _classification(resp)
    if found is not None:
        reason_code = getattr(found, "reason_code", "") or getattr(found, "status", "")
        return _short(f"{reason_code}: {getattr(found, 'reason', '')}".strip(": "))
    try:
        legacy = getattr(resp, "blocked", None)
    except Exception:  # noqa: BLE001
        legacy = None
    return _short(legacy) if legacy else ""


def _is_blocked_page(resp: Any) -> bool:
    """A challenge/login-wall/geo-block page (P321 'blocked'): a refusal, never a failover."""
    found = _classification(resp)
    if found is not None:
        return getattr(found, "status", "") == "blocked"
    try:
        return bool(getattr(resp, "blocked", None))
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------------------
# Resolver
# --------------------------------------------------------------------------------------


class Resolver:
    """DoH (default) or system resolver for one run (the circuit breaker and wildcard cache are
    per instance). ``http`` must provide ``get(url, params=, headers=, ttl=, timeout=)`` (a
    ScopedHttp) or ``request(method, url, ...)``.

    ``providers``: resolver names in order (default: setting ``doh_providers`` via ``settings``, else
    ``DEFAULT_PROVIDERS``); an https URL entry is the organisation's internal resolver.
    ``internal_url`` (or ``settings['doh_internal']``) adds the internal resolver first. ``provider``
    is the legacy preferred resolver (setting ``doh_provider``), used only when no list is given.
    ``config_errors`` lists rejected configuration entries.
    """

    def __init__(
        self,
        http: Any = None,
        mode: str = "doh",
        provider: str = "google",
        ttl: int = 3600,
        *,
        providers: Iterable[str] | str | None = None,
        allow_public: bool = True,
        allow_public_fallback: bool = True,
        clock: Any = None,
        internal_url: str | None = None,
        settings: Any = None,
    ) -> None:
        self.http = http
        self.mode = "system" if str(mode or "").strip().lower() == "system" else "doh"
        self.provider = provider if provider in DOH_PROVIDERS and provider != "internal" else "google"
        self.ttl = ttl
        self.allow_public = bool(allow_public)
        self.allow_public_fallback = bool(allow_public_fallback)
        self.clock = clock or _default_clock()
        self.config_errors: list[str] = []
        explicit = providers is not None
        if settings is not None:
            if providers is None:
                providers = _setting(settings, "doh_providers", None)
                explicit = providers is not None
            if internal_url is None:
                internal_url = _setting(settings, "doh_internal", "")
        self.internal_url = self._validate_internal(str(internal_url or ""), "doh_internal") if internal_url else ""
        self.providers: list[str] = self._build_order(providers, explicit)
        self._lock = threading.Lock()
        self._failures: dict[str, int] = {}
        self._open: set[str] = set()
        self._wildcards: dict[tuple[str, bool], WildcardInfo] = {}
        self._extras_ok = True  # does ``http`` accept retries=/cache_if= (HTTP contract v2)?

    # ---- configuration ----------------------------------------------------------------------
    def _validate_internal(self, url: str, origin: str) -> str:
        url = url.strip()
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower().rstrip(".")
        except ValueError:
            parts, host = None, ""
        if parts is None or parts.scheme != "https" or not host:
            # never echo credentials or query values of a rejected URL
            shown = f"{parts.scheme}://{host}" if parts is not None and parts.scheme and host else "the configured value"
            self.config_errors.append(f"{origin}: {_short(shown, 120)} ignored (an https:// DoH JSON endpoint is required)")
            return ""
        if parts.username or parts.password:
            self.config_errors.append(f"{origin}: credentials in the DoH URL are not allowed")
            return ""
        if is_public_doh_host(host):
            # the internal resolver is the only one allowed at TLP:RED: a public one must never pass as it
            self.config_errors.append(f"{origin}: {host} is a public resolver, not the organisation's internal DoH")
            return ""
        return url

    def _build_order(self, providers: Iterable[str] | str | None, explicit: bool) -> list[str]:
        if providers is None:
            names: list[str] = list(DEFAULT_PROVIDERS)
        elif isinstance(providers, str):
            names = [p.strip() for p in providers.split(",")]
        else:
            names = [str(p).strip() for p in providers]
        order: list[str] = []
        for raw in names:
            if not raw:
                continue
            if raw.lower().startswith(("https://", "http://")):
                url = self._validate_internal(raw, "doh_providers")
                if url and not self.internal_url:
                    self.internal_url = url
                elif url and url != self.internal_url:
                    self.config_errors.append(f"doh_providers: only one internal resolver is supported ({raw!r} ignored)")
                continue
            key = raw.lower()
            if key not in DOH_PROVIDERS:
                self.config_errors.append(
                    f"doh_providers: unknown resolver {raw!r} (google, cloudflare, quad9; set doh_internal for your own DoH)"
                )
                continue
            if key == "internal":
                continue  # placed first below when a URL is configured
            if key not in order:
                order.append(key)
        if not explicit and self.provider in order:  # legacy setting doh_provider
            order.remove(self.provider)
            order.insert(0, self.provider)
        if explicit and not order:
            self.config_errors.append("doh_providers is empty: no public DoH resolver will be used")
        if self.internal_url:
            order.insert(0, "internal")
        return order

    def _url(self, prov: str) -> str:
        return self.internal_url if prov == "internal" else DOH_PROVIDERS[prov]["url"]

    def _chain(self, hostile: bool) -> tuple[list[str], str]:
        """Resolvers to try in order, plus the note explaining excluded public resolvers."""
        internal = ["internal"] if "internal" in self.providers else []
        public = [p for p in self.providers if p != "internal"]
        if hostile and "cloudflare" in public:  # ECS-free resolver first for hostile names
            public.remove("cloudflare")
            public.insert(0, "cloudflare")
        if not self.allow_public:
            return internal, PUBLIC_NOT_ALLOWED
        if internal and not self.allow_public_fallback:
            return internal, PUBLIC_FALLBACK_NOT_ALLOWED
        return internal + public, ""

    def non_public_available(self) -> bool:
        """True when a non-public resolver exists (system mode or a configured internal DoH)."""
        return self.mode == "system" or "internal" in self.providers

    # ---- circuit breaker -----------------------------------------------------------------------
    def _is_open(self, prov: str) -> bool:
        with self._lock:
            return prov in self._open

    def _failed(self, prov: str) -> None:
        with self._lock:
            count = self._failures.get(prov, 0) + 1
            self._failures[prov] = count
            if count >= CIRCUIT_THRESHOLD:
                self._open.add(prov)

    def _succeeded(self, prov: str) -> None:
        with self._lock:
            self._failures[prov] = 0

    def circuit_open(self) -> frozenset[str]:
        """Resolvers skipped for the rest of this run (3 consecutive failures)."""
        with self._lock:
            return frozenset(self._open)

    # ---- public API --------------------------------------------------------------------------
    def query(self, name: str, rtype: str = "A", *, hostile: bool = False) -> DnsAnswer:
        """Resolve ``name``/``rtype``. ``hostile=True`` (attacker-controlled names) puts the
        ECS-free Cloudflare resolver first among the public ones (a configured internal resolver
        keeps its place)."""
        rtype = str(rtype or "A").strip().upper()
        qname = _qname(name)
        if not _valid_qname(qname):
            return DnsAnswer(qname, rtype, status="FORMERR", error=f"invalid DNS name {str(name)[:80]!r}")
        if self.mode == "system":
            return self._system(qname, rtype)
        chain, note = self._chain(hostile)
        return self._resolve(qname, rtype, chain, note)

    def ptr(self, ip: str, *, hostile: bool = False) -> DnsAnswer:
        return self.query(reverse_name(ip), "PTR", hostile=hostile)

    def addresses(self, name: str, *, hostile: bool = False) -> list[str]:
        """A + AAAA addresses of ``name`` (empty when unresolved or could not verify)."""
        ips: list[str] = []
        for rt in ("A", "AAAA"):
            ans = self.query(name, rt, hostile=hostile)
            if ans.ok:
                ips.extend(r for r in ans.records if _is_ip(r))
        return ips

    def wildcard_info(self, zone: str, *, hostile: bool = False) -> WildcardInfo:
        """Random-label A (then AAAA) probe under ``zone``; definitive results cached per Resolver."""
        zone = _qname(zone)
        key = (zone, bool(hostile))
        with self._lock:
            cached = self._wildcards.get(key)
        if cached is not None:
            return cached
        probe = f"{self._random_label()}.{zone}"
        answers = [self.query(probe, "A", hostile=hostile)]
        if not (answers[0].ok and (answers[0].records or answers[0].cnames)):
            answers.append(self.query(probe, "AAAA", hostile=hostile))
        records = tuple(r for a in answers if a.ok for r in a.records + a.cnames)
        if records:
            info = WildcardInfo(zone, True, False, records)
        elif all(a.nxdomain for a in answers):
            info = WildcardInfo(zone, False, False, ())
        elif any(a.could_not_verify for a in answers):
            info = WildcardInfo(zone, None, False, ())
        else:  # NOERROR/NODATA for a random name: existence cannot be told apart here (cond 10)
            info = WildcardInfo(zone, None, True, ())
        if info.wildcard is not None or info.nodata:  # definitive DNS answers only (never failures)
            with self._lock:
                self._wildcards[key] = info
        return info

    def wildcard(self, zone: str) -> bool | None:
        """True when random names under ``zone`` get records, False when they get NXDOMAIN, None
        when it cannot be told: the probe could not be verified, or the zone answers NOERROR/NODATA
        for names that do not exist (``wildcard_info().nodata``; NOERROR proves nothing there)."""
        return self.wildcard_info(zone).wildcard

    def confirm_nxdomain(self, name: str, rtype: str = "A", *, hostile: bool = False) -> bool | None:
        """True only when a second, different resolver also answers NXDOMAIN.

        False when the name resolves (NOERROR) on either resolver; None when the first answer could
        not be verified or no other resolver could answer (required before an NXDOMAIN drives a
        takeover, typosquat or 'domain does not exist' decision).
        """
        first = self.query(name, rtype, hostile=hostile)
        if first.could_not_verify:
            return None
        if not first.nxdomain:
            return False
        qname, rtype = _qname(name), str(rtype or "A").strip().upper()
        chain, _note = self._chain(hostile)
        if self.mode == "system":
            # the system resolver plays the internal role: moving to a public one needs both flags
            if not (self.allow_public and self.allow_public_fallback):
                chain = [p for p in chain if p == "internal"]
            exclude: tuple[str, ...] = ()
        else:
            exclude = tuple(first.resolver.split(","))
        if self.http is None or not [p for p in chain if p not in exclude]:
            return None
        second = self._resolve(qname, rtype, chain, "", exclude=exclude)
        if second.could_not_verify:
            return None
        return second.nxdomain

    def dnsbl(self, query_name: str, zone: str) -> DnsblResult:
        """Look up ``<query_name>.<zone>`` (A) through a non-public resolver only.

        ``query_name`` is the DNSBL label: reversed IPv4 octets (``dnsbl_label(ip)``) or a domain.
        With public resolvers only the result is ``listed=None``, status 'unverified'. Refusal codes
        (127.255.255.252/254/255 and zone-specific ones) give status error/blocked/rate_limited with
        ``listed=None``, never "not listed".
        """
        label = str(query_name).strip().rstrip(".").lower()
        zone_n = _qname(zone)
        qname = f"{label}.{zone_n}" if label else zone_n
        if not _valid_qname(qname):
            return DnsblResult(None, [], "error", f"invalid DNSBL query name {qname[:80]!r}", query=qname)
        if self.mode == "system":
            ans = self._system(qname, "A")
        elif "internal" in self.providers:
            ans = self._resolve(qname, "A", ["internal"], "")
        else:
            return DnsblResult(
                None, [], "unverified", "DNSBL needs a non-public resolver (dns_mode system or doh_internal)", query=qname
            )
        return _dnsbl_result(ans, zone_n, qname)

    # ---- DoH chain -----------------------------------------------------------------------------
    def _random_label(self) -> str:
        alphabet = string.ascii_lowercase + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(WILDCARD_LABEL_LEN))

    def _resolve(self, name: str, rtype: str, chain: list[str], note: str, *, exclude: tuple[str, ...] = ()) -> DnsAnswer:
        if self.http is None:
            return DnsAnswer(name, rtype, status="SERVFAIL", error="no HTTP client for DoH")
        start = self.clock.monotonic()
        errors: list[str] = []
        tried: list[str] = []
        timeouts = failures = 0
        for prov in chain:
            if prov in exclude:
                continue
            if self._is_open(prov):
                errors.append(f"{prov}: skipped (circuit open after {CIRCUIT_THRESHOLD} consecutive failures)")
                continue
            remaining = FAILOVER_BUDGET - (self.clock.monotonic() - start)
            if remaining <= 0:
                errors.append(f"failover budget of {FAILOVER_BUDGET:g} s exhausted")
                timeouts += 1
                failures += 1
                break
            timeout = min(remaining, REQUEST_TIMEOUT)
            try:
                answer, healthy = self._ask(prov, name, rtype, timeout)
            except _Skip as exc:
                errors.append(f"{prov}: {exc}")
                continue
            except _Refused as exc:  # a refusal is final for this query: no failover (P029 cond 1)
                return DnsAnswer(name, rtype, status="SERVFAIL", error=f"{prov}: {exc}", resolver=prov)
            except _Failover as exc:
                tried.append(prov)
                self._failed(prov)
                errors.append(f"{prov}: {exc}")
                failures += 1
                timeouts += int(exc.timeout)
                continue
            if healthy:
                self._succeeded(prov)
            return answer
        if note:
            errors.append(note)
        status = "TIMEOUT" if failures and timeouts == failures else "SERVFAIL"
        error = "; ".join(errors) or "no DoH resolver available"
        return DnsAnswer(name, rtype, status=status, error=error, resolver=",".join(tried))

    def _ask(self, prov: str, name: str, rtype: str, timeout: float) -> tuple[DnsAnswer, bool]:
        """One resolver, one request. Returns (answer, resolver_healthy) or raises _Failover/_Skip/_Refused."""
        if DOH_PROVIDERS[prov]["kind"] == "wire":
            return self._ask_wire(prov, name, rtype, timeout)
        params: dict[str, str] = {"name": name, "type": rtype}
        if DOH_PROVIDERS[prov]["ecs"] == "zero":
            params["edns_client_subnet"] = ECS_ZERO
        resp = self._get(self._url(prov), params, {"Accept": "application/dns-json"}, timeout, _cacheable_json)
        early = self._check_http(prov, name, rtype, resp)
        if early is not None:
            return early, False
        try:
            data: Any = json.loads(resp.content or b"")
        except (ValueError, TypeError, RecursionError):
            data = _INVALID
        code = data.get("Status") if isinstance(data, dict) else None
        if not isinstance(code, int) or isinstance(code, bool):
            self._bad_body(resp, "invalid JSON" if data is _INVALID else "no Status field")
        answer = _parse_doh(name, rtype, data, prov)
        if answer.could_not_verify:
            self._forget(resp)
        return answer, True

    def _ask_wire(self, prov: str, name: str, rtype: str, timeout: float) -> tuple[DnsAnswer, bool]:
        dns = _load_dnspython()
        if dns is None:
            raise _Skip("needs dnspython (RFC 8484 wire format; pip install 'v3lum[full]')")
        try:
            rdtype = dns.rdatatype.from_text(rtype)
            query = dns.message.make_query(name, rdtype)
        except Exception as exc:  # noqa: BLE001 - dnspython raises many types
            return DnsAnswer(name, rtype, status="FORMERR", error=f"{prov}: {_short(exc)}", resolver=prov), False
        query.id = 0  # RFC 8484 4.1: cache-friendly
        query.flags |= dns.flags.AD  # ask for the AD bit (RFC 6840 5.7)
        wire = base64.urlsafe_b64encode(query.to_wire()).rstrip(b"=").decode("ascii")
        resp = self._get(self._url(prov), {"dns": wire}, {"Accept": "application/dns-message"}, timeout, _cacheable_wire)
        early = self._check_http(prov, name, rtype, resp)
        if early is not None:
            return early, False
        msg: Any = None
        problem = ""
        try:
            msg = dns.message.from_wire(resp.content)
        except Exception as exc:  # noqa: BLE001 - dnspython raises many types for bad wire data
            problem = _short(exc)
        if msg is None:
            self._bad_body(resp, problem or "empty body", what="a DNS message")
        status = RCODES.get(msg.rcode(), dns.rcode.to_text(msg.rcode()))
        records: list[str] = []
        cnames: list[str] = []
        ttls: list[int] = []
        for rrset in msg.answer:
            if rrset.rdtype == RTYPES["CNAME"] and rtype != "CNAME":
                cnames.extend(_clean("CNAME", rd.to_text()) for rd in rrset)
            elif rrset.rdtype == rdtype:
                records.extend(_clean(rtype, rd.to_text()) for rd in rrset)
                ttls.append(int(rrset.ttl))
        error = "" if status in ("NOERROR", "NXDOMAIN") else f"{status} from {prov}"
        answer = DnsAnswer(
            name, rtype, status=status, records=records, ttl=min(ttls) if ttls else 0,
            authenticated=bool(msg.flags & dns.flags.AD), error=error, resolver=prov, cnames=cnames,
        )
        if answer.could_not_verify:
            self._forget(resp)
        return answer, True

    def _check_http(self, prov: str, name: str, rtype: str, resp: Any) -> DnsAnswer | None:
        """Failover on 5xx/429/408; SERVFAIL (could not verify, no failover) on every other non-200
        status: refusals (401/403/407/451) and request problems (P029 cond 1)."""
        try:
            status = int(getattr(resp, "status", 0) or 0)
        except (TypeError, ValueError):
            status = 0
        if status == 200:
            return None
        reason = _classified(resp)
        detail = f"HTTP {status}" + (f" ({reason})" if reason else "")
        if 500 <= status <= 599 or status in _FAILOVER_STATUS:
            raise _Failover(detail, timeout=status == 408)
        return DnsAnswer(name, rtype, status="SERVFAIL", error=f"{prov}: {detail}: could not verify", resolver=prov)

    def _bad_body(self, resp: Any, problem: str, *, what: str = "a DoH answer") -> None:
        """A 200 body that is not a DNS answer. A challenge/login/geo page is a refusal (SERVFAIL,
        no failover); anything else is a corrupt transfer (transport error: failover). Always raises."""
        self._forget(resp)  # never keep it in a cache that could not veto it
        reason = _classified(resp)
        if _is_blocked_page(resp):
            raise _Refused(f"HTTP 200 but {reason or 'an anti-bot page'} instead of {what}: could not verify")
        raise _Failover(f"not {what} ({reason or problem})")

    def _get(self, url: str, params: dict[str, str], headers: dict[str, str], timeout: float, cache_if: Callable[[Any], bool]) -> Any:
        kw: dict[str, Any] = {"params": params, "headers": headers, "ttl": self.ttl, "timeout": timeout}
        try:
            if self._extras_ok:
                try:
                    # no client retries (failover is ours, within the 5 s budget); never cache SERVFAIL
                    return self._send(url, dict(kw, retries=0, cache_if=cache_if))
                except TypeError as exc:
                    text = str(exc)
                    if "unexpected keyword" not in text or not ("retries" in text or "cache_if" in text):
                        raise
                    self._extras_ok = False  # pre-v2 HTTP client
            return self._send(url, kw)
        except _PROPAGATE:
            raise
        except _POLICY as exc:
            raise _Skip(f"refused by policy: {_short(exc)}") from exc
        except _OFFLINE as exc:  # offline and not cached: not a resolver failure
            raise _Skip(f"offline: {_short(exc)}") from exc
        except _REFUSED as exc:
            if getattr(exc, "reason_code", "") == "circuit":  # host short-circuited for this run (A9)
                raise _Skip(_short(exc)) from exc
            raise _Refused(f"{_short(exc)}: could not verify") from exc
        except _TRANSPORT as exc:  # connection errors, timeouts, rate limits/quota raised by the client
            raise _Failover(_short(exc), timeout=_is_timeout(exc)) from exc
        except (OSError, ValueError) as exc:  # raw transports outside the HTTP contract
            raise _Failover(_short(exc), timeout=_is_timeout(exc)) from exc

    def _send(self, url: str, kw: dict[str, Any]) -> Any:
        get = getattr(self.http, "get", None)
        if callable(get):
            return get(url, **kw)
        return self.http.request("GET", url, **kw)

    def _forget(self, resp: Any) -> None:
        """Drop a cached could-not-verify answer when the client could not veto caching."""
        if self._extras_ok:
            return
        evict = getattr(self.http, "evict", None)
        if callable(evict):
            try:
                evict(resp)
            except Exception:  # noqa: BLE001 - eviction is best effort
                pass

    # ---- system resolver -------------------------------------------------------------------------
    def _system(self, name: str, rtype: str) -> DnsAnswer:
        """OS resolvers: only when ``mode == 'system'`` was configured, never as a fallback."""
        dns = _load_dnspython()
        if dns is None:
            return self._getaddrinfo(name, rtype)
        try:
            res = dns.resolver.Resolver()
            ans = res.resolve(name, rtype, raise_on_no_answer=False, lifetime=8)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer(name, rtype, status="NXDOMAIN", resolver="system")
        except dns.resolver.NoNameservers as exc:
            return DnsAnswer(name, rtype, status="SERVFAIL", error=f"system: {_short(exc)}", resolver="system")
        except dns.exception.Timeout as exc:
            return DnsAnswer(name, rtype, status="TIMEOUT", error=f"system: {_short(exc)}", resolver="system")
        except (dns.exception.DNSException, OSError, ValueError) as exc:
            return DnsAnswer(name, rtype, status="SERVFAIL", error=f"system: {_short(exc)}", resolver="system")
        records, cnames = [], []
        response = getattr(ans, "response", None)
        for rrset in getattr(response, "answer", None) or []:
            if rrset.rdtype == RTYPES["CNAME"] and rtype != "CNAME":
                cnames.extend(_clean("CNAME", rd.to_text()) for rd in rrset)
        if ans.rrset is not None:
            records = [_clean(rtype, r.to_text()) for r in ans.rrset]
        ttl = ans.rrset.ttl if ans.rrset is not None else 0
        ad = bool(response is not None and response.flags & dns.flags.AD)
        return DnsAnswer(name, rtype, records=records, ttl=int(ttl), authenticated=ad, resolver="system", cnames=cnames)

    @staticmethod
    def _getaddrinfo(name: str, rtype: str) -> DnsAnswer:
        """dnspython-less fallback: only EAI_NONAME is NXDOMAIN; EAI_AGAIN, timeouts and every
        other OSError are SERVFAIL with the error text (could not verify)."""
        if rtype not in ("A", "AAAA"):
            return DnsAnswer(name, rtype, status="NOTIMP", error="install dnspython for system DNS", resolver="system")
        family = socket.AF_INET if rtype == "A" else socket.AF_INET6
        try:
            infos = socket.getaddrinfo(name, None, family, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            if exc.errno == getattr(socket, "EAI_NONAME", object()):
                return DnsAnswer(name, rtype, status="NXDOMAIN", resolver="system")
            return DnsAnswer(name, rtype, status="SERVFAIL", error=f"getaddrinfo: {_short(exc)}", resolver="system")
        except (OSError, UnicodeError) as exc:
            return DnsAnswer(name, rtype, status="SERVFAIL", error=f"getaddrinfo: {_short(exc)}", resolver="system")
        records = set()
        for info in infos:
            addr = str(info[4][0]).split("%", 1)[0]
            try:
                records.add(ipaddress.ip_address(addr).compressed)
            except ValueError:
                continue
        return DnsAnswer(name, rtype, records=sorted(records), resolver="system")


def _zone_refusals(zone: str) -> dict[str, tuple[str, str]]:
    table = dict(DNSBL_REFUSAL_CODES)
    for suffix, codes in _ZONE_REFUSAL_CODES.items():
        if zone == suffix or zone.endswith("." + suffix):
            table.update(codes)
    return table


def _dnsbl_result(ans: DnsAnswer, zone: str, qname: str) -> DnsblResult:
    if ans.could_not_verify:
        reason = f"could not verify: {ans.status}" + (f" ({ans.error})" if ans.error else "")
        return DnsblResult(None, [], "unverified", reason, query=qname, resolver=ans.resolver)
    if ans.nxdomain:
        return DnsblResult(False, [], "ok", "not listed (NXDOMAIN from a non-public resolver)", query=qname, resolver=ans.resolver)
    codes = [r for r in ans.records if _is_ip(r)]
    refusals = _zone_refusals(zone)
    for code in codes:
        if code in refusals:
            status, reason = refusals[code]
            return DnsblResult(None, codes, status, f"{reason} ({code})", query=qname, resolver=ans.resolver)
    if not codes:
        return DnsblResult(False, [], "ok", "not listed (no address record)", query=qname, resolver=ans.resolver)
    if any(ipaddress.ip_address(c) not in _LOOPBACK_NET for c in codes):
        return DnsblResult(
            None, codes, "error", "answer outside 127.0.0.0/8 (resolver rewriting NXDOMAIN?): could not verify",
            query=qname, resolver=ans.resolver,
        )
    return DnsblResult(True, codes, "ok", f"listed ({', '.join(codes)})", query=qname, resolver=ans.resolver)
