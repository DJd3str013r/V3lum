"""HTTP plumbing (module-author contract v2, section 7): one client, one classifier, one cache.

Modules never touch :class:`HttpClient`: they get ``ctx.http``, a :class:`ScopedHttp` carrying the
module's metadata (declared hosts, disclosure, opsec, request cap, deadline, absent statuses, error
markers). The client underneath:

* applies the provider ``http_profile`` of the destination host (P326): User-Agent (neutral
  ``V3LUM/<version>`` by default; the contact UA only where the profile asks and ``contact_email`` is
  set, else :class:`ConfigError`), Accept, Accept-Language (``pt-BR`` for ``.br`` hosts), timeout,
  retries, byte cap, TTL, politeness interval and concurrency;
* follows redirects in its own loop (at most 5 hops; every hop host-checked through ``hop_check``;
  credential headers stripped and credential-bearing bodies never re-sent when the origin changes;
  https->http refused); URLs whose host the transport would parse differently (backslashes, control
  characters, percent-encoded hosts) are refused;
* classifies every response **before** it is parsed or cached (P321, :func:`classify`): declared error
  markers, login walls, geo-blocks, anti-bot challenges, 429, keyless 403. Classified, truncated and
  401/403/429/5xx answers are never cached; a host that served a challenge or geo-block is
  short-circuited for the client's lifetime (``reason_code`` 'circuit', in memory only);
* never stores or replays cookies and never attaches ~/.netrc credentials (no borrowed sessions);
* retries only 502/503/504 and connection errors (bounded by ``retries`` and the run deadline) and a 429
  once when ``Retry-After`` <= 15 s - never a blocked/challenged/403 answer, never with other headers;
* reserves provider quota before sending and lets a provider's own quota signal win (P334);
* stores bodies of providers flagged ``sensitive`` only after the sanitizer hook (P145), else not at
  all;
* redacts every URL and message that leaves it - events, exceptions, cache rows (AR01).

Target contact (LIGHT/ACTIVE, wave 2, WP11: P376, A7, A13, AR02) adds, per request:

* the **egress profile** (:class:`v3lum.core.net.EgressProfiles`): passive and third-party traffic
  always takes the default route; LIGHT uses ``proxy_light`` and ACTIVE ``proxy_active`` when
  configured (own ``requests.Session`` with ``trust_env=False``, names resolved by the proxy); a
  configured profile whose proxy is down fails closed (PolicyError) and is never resent on the
  default route;
* the **SSRF/redirect guard** on every hop: private, loopback, link-local, CGNAT, ULA, multicast,
  reserved and cloud-metadata addresses, single-label names and internal suffixes are refused unless
  the run's seed is internal (``RunInfo.internal_seed``) or the scope lists them; bound requests
  (``run=``/``scope=``) resolve each hop through the profile (DoH) and pin the checked IP on the
  direct route; ACTIVE hops must match the scope, LIGHT first hops the analyst-typed seed, and
  redirect targets re-run the hostile-host guard (``contact_guard``);
* the **request rules**: GET/HEAD for LIGHT, GET/HEAD/OPTIONS for ACTIVE unless an approved
  ``v3lum/data/policy/method_allowlist/<module>.json`` lists the method; LIGHT <= 1 req/s and <= 25
  requests per target host per scan, ACTIVE <= 10 req/s, <= 2 concurrent connections per host and a
  per-case budget (``ContactCeilings``); the UA is setting ``ua_light`` (ACTIVE: the scope's ROE UA
  and header), never the V3LUM/contact UA or the organisation's identity; no credential header
  (Authorization, Cookie, X-Api-Key...) and no configured secret ever goes to a target (no login
  attempts or borrowed sessions); a bound scope's window is enforced per request (before it
  PolicyError 'scope', after it Cancelled); ACTIVE needs a scope (a context without an entity may
  reach internal hosts only, for self-tests); internal names are resolved only by the internal
  resolver. No CA/verify override exists (A12).
* the **kill switch** also shuts down a body read blocked on a slow or silent server (within
  ~100 ms; urllib3 >= 2.3).

Body fingerprints of anti-bot/WAF pages are adapted from maigret ``maigret/errors.py`` COMMON_ERRORS
(https://github.com/soxoj/maigret, commit 50e62c45e17b03fd3f059622d38a4cdb3ec2eab4, MIT, Copyright
(c) 2020-2026 Soxoj) and sherlock ``sherlock_project/sherlock.py`` WAFHitMsgs
(https://github.com/sherlock-project/sherlock, commit c588d7c8b476df9f9c84912a05d1430fb8cdcdae, MIT,
Copyright (c) 2019 Sherlock Project), transcribed 2026-11-26; notice fragment
``v3lum/data/notices/maigret_sherlock_markers.json``. Only detection strings were adapted: no bypass
helper (proxy rotation, solvers, cookie reuse) is ported and no message hints at one. The other
fingerprints (abuse.ch, DomainTools, Netcraft, Facebook, Reddit and Cloudflare custom block pages)
come from V3LUM's own research samples.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import email.utils
import hashlib
import html
import http.cookiejar
import inspect
import ipaddress
import json
import re
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

import requests

from v3lum import __version__
from v3lum.core.cache import CACHEABLE_STATUS, HttpCache
from v3lum.core.clock import SYSTEM_CLOCK, Clock, SystemClock
from v3lum.core.limiter import HostLimiter
from v3lum.core.redact import KEY_PARAMS, has_secret, is_credential_header, redact_text, redact_url

try:  # A7 hard ceilings (WP10 adds them to the limiter in wave 2; the values are fixed by A7)
    from v3lum.core.limiter import ACTIVE_MAX_CONCURRENT, ACTIVE_MAX_RPS, LIGHT_MAX_PER_HOST_PER_SCAN, LIGHT_MAX_RPS
except ImportError:  # pragma: no cover - limiter without the wave-2 constants
    LIGHT_MAX_RPS = 1.0
    LIGHT_MAX_PER_HOST_PER_SCAN = 25
    ACTIVE_MAX_RPS = 10.0
    ACTIVE_MAX_CONCURRENT = 2

__all__ = [
    "ACTIVE_MAX_CONCURRENT",
    "ACTIVE_MAX_RPS",
    "ACTIVE_METHODS",
    "CACHEABLE_STATUS",
    "DEFAULT_ACTIVE_BUDGET",
    "DEFAULT_MAX_PPS",
    "INTERNAL_SUFFIXES",
    "LIGHT_MAX_PER_HOST_PER_SCAN",
    "LIGHT_MAX_RPS",
    "LIGHT_METHODS",
    "MAX_ACTIVE_BUDGET",
    "MAX_PPS",
    "METADATA_IPS",
    "METHOD_ALLOW_SCHEMA",
    "NEVER_ALLOWED_METHODS",
    "PORT_SCAN_MAX",
    "ROE_FORBIDDEN_HEADERS",
    "WORDLIST_MAX",
    "AuthRequired",
    "Blocked",
    "Cancelled",
    "Classification",
    "ConfigError",
    "ContactCeilings",
    "DeadlineExceeded",
    "HostLimiter",
    "HttpCache",
    "HttpClient",
    "HttpError",
    "MethodAllowance",
    "NetworkError",
    "OfflineError",
    "PolicyError",
    "QuotaExceeded",
    "RateLimited",
    "RequestCapReached",
    "RequestInfo",
    "RequestsTransport",
    "Response",
    "ScopedHttp",
    "Transport",
    "active_budget",
    "allowed_methods",
    "block_reason",
    "classify",
    "contact_concurrency",
    "contact_rps",
    "entity_hosts",
    "host_problem",
    "host_within",
    "ip_problem",
    "is_metadata_ip",
    "max_pps",
    "method_allowlist",
    "method_allowlist_errors",
    "normalize_host",
    "parse_ip",
    "reload_method_allowlist",
]

RETRY_STATUS = frozenset({502, 503, 504})
REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS = 5
#: longest Retry-After (seconds) honoured with one retry; longer waits return the 429 (P326 cond 8).
RETRY_AFTER_MAX = 15.0
#: most retries of one hop whatever the caller asks (provider profiles allow 0..5).
MAX_RETRIES = 5
#: statuses that mean 'could not verify' and are never read as a declared absence (rule 5).
NEVER_ABSENT_STATUS = frozenset({401, 403, 407, 429, 430, 451, 999})
DEFAULT_MAX_BYTES = 15 * 1024 * 1024
#: TTL ceiling for providers flagged sensitive (A4: sanitized breach payloads 7 days at most).
SENSITIVE_MAX_TTL = 7 * 86400
#: Accept-Language for hosts under .br when the provider profile sets none (P326 cond 11).
BR_ACCEPT_LANGUAGE = "pt-BR,pt;q=0.9,en;q=0.5"
#: Fallback for setting ua_light (a current common desktop browser UA; LIGHT/ACTIVE requests only).
DEFAULT_UA_LIGHT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
#: Body prefix the classifier inspects (P321: regex markers run over the first 64 KB of text).
CLASSIFY_BYTES = 64 * 1024
#: Body suffix the built-in fingerprints also inspect on longer bodies (Reddit's block page puts its
#: message after ~190 KB of inline CSS).
CLASSIFY_TAIL_BYTES = 16 * 1024
_JSON_PARSE_LIMIT = 8 * 1024 * 1024

_BLOCKED_CODES = frozenset({"challenge", "geo_block", "login_wall", "circuit", "hostile_host"})
_ERROR_CODES = frozenset({"error", "timeout", "sanitizer"})
_SKIPPED_CODES = frozenset(
    {
        "not_default",
        "demoted",
        "licence",
        "tlp",
        "tier",
        "privacy",
        "own_asset",
        "opsec",
        "authorization",
        "scope",
        "egress_country",
        "deadline",
        "policy",
        "config",
        "not_applicable",
    }
)
_MARKER_CODES: dict[str, frozenset[str]] = {
    "blocked": _BLOCKED_CODES,
    "rate_limited": frozenset({"rate_limited"}),
    "quota": frozenset({"quota"}),
    "error": _ERROR_CODES,
}
_MARKER_DEFAULT_CODE = {"blocked": "challenge", "rate_limited": "rate_limited", "quota": "quota", "error": "error"}
_CIRCUIT_CODES = frozenset({"challenge", "geo_block"})
_NO_CIRCUIT_MARKERS = frozenset({"keyless.403"})


# ======================================================================================
# Exceptions (every message and URL is redacted on construction, AR01)
# ======================================================================================


def _body_text(body: Any) -> str:
    if body is None:
        return ""
    if isinstance(body, (bytes, bytearray)):
        return bytes(body[:2000]).decode("utf-8", errors="replace")
    return str(body)


class HttpError(Exception):
    """Non-success HTTP status, unusable body or classified error page for a required result.

    ``HttpError(message, status=0, url='', body='', reason_code='error')``; message, url and the first
    500 characters of the body are kept redacted. ``reason_code`` is a canonical A3 code.
    """

    default_reason_code = "error"
    allowed_reason_codes: frozenset[str] | None = None

    def __init__(self, message: Any = "", status: int = 0, url: str = "", body: Any = "", reason_code: str = "") -> None:
        msg = redact_text(message)
        super().__init__(msg)
        self.message = msg
        try:
            self.status = int(status or 0)
        except (TypeError, ValueError):
            self.status = 0
        self.url = redact_url(url) if url else ""
        self.body = redact_text(_body_text(body)[:500])
        code = str(reason_code or "") or self.default_reason_code
        if self.allowed_reason_codes is not None and code not in self.allowed_reason_codes:
            code = self.default_reason_code
        self.reason_code = code


class RateLimited(HttpError):
    """The provider throttled us (HTTP 429 or a rate-limit marker): transient, could not verify."""

    default_reason_code = "rate_limited"
    allowed_reason_codes = frozenset({"rate_limited"})


class AuthRequired(HttpError):
    """HTTP 401/403 for a keyed source (missing/invalid key). The engine maps it to NEEDS_KEY for
    modules with keys and to BLOCKED 'challenge' for keyless modules."""

    default_reason_code = "needs_key"


class Blocked(HttpError):
    """Anti-bot challenge, WAF page, geo-block, login wall, short-circuited or hostile host:
    'could not verify', never 'absent'. ``reason_code`` in challenge | geo_block | login_wall |
    circuit | hostile_host (default challenge)."""

    default_reason_code = "challenge"
    allowed_reason_codes = _BLOCKED_CODES


class QuotaExceeded(HttpError):
    """A daily/monthly budget is exhausted (provider quota marker or the quota book): Status.QUOTA."""

    default_reason_code = "quota"
    allowed_reason_codes = frozenset({"quota"})


class NetworkError(Exception):
    """Connection, DNS, TLS or transport failure (message redacted). ``retryable`` tells the client
    whether another attempt may help; ``kind`` names the underlying error class;
    ``proxy_unreachable`` is True when the configured proxy itself could not be reached (the client
    then refuses the request on a LIGHT/ACTIVE egress profile instead of retrying, A13)."""

    default_reason_code = "error"
    proxy_unreachable = False

    def __init__(
        self, message: Any = "", *, retryable: bool = True, kind: str = "", reason_code: str = "", proxy_unreachable: bool = False
    ) -> None:
        msg = redact_text(message)
        super().__init__(msg)
        self.message = msg
        self.retryable = bool(retryable)
        self.kind = kind or type(self).__name__
        self.reason_code = reason_code or self.default_reason_code
        self.proxy_unreachable = bool(proxy_unreachable)


class OfflineError(NetworkError):
    """Offline mode: the request is not in the cache (UNAVAILABLE 'offline')."""

    default_reason_code = "offline"

    def __init__(self, message: Any = "", **kw: Any) -> None:
        kw.setdefault("retryable", False)
        super().__init__(message, **kw)


class DeadlineExceeded(NetworkError):
    """The run deadline passed (before sending, while waiting or while a slow server dripped the
    body): ERROR 'timeout'."""

    default_reason_code = "timeout"

    def __init__(self, message: Any = "run deadline exceeded", **kw: Any) -> None:
        kw.setdefault("retryable", False)
        super().__init__(message, **kw)


class Cancelled(Exception):
    """The runtime cancel flag is set (Ctrl+C, scope window end, scan deadline): no new requests."""

    def __init__(self, message: Any = "cancelled: new requests are refused", stop_reason: str = "cancelled") -> None:
        msg = redact_text(message)
        super().__init__(msg)
        self.message = msg
        self.stop_reason = stop_reason or "cancelled"


class RequestCapReached(Exception):
    """The module's ``max_requests`` network sends for this entity are used (cache hits are free)."""

    stop_reason = "request_cap"

    def __init__(self, message: Any = "max_requests reached for this entity") -> None:
        msg = redact_text(message)
        super().__init__(msg)
        self.message = msg


class PolicyError(Exception):
    """A request refused by policy (SKIPPED + ``reason_code``; default 'policy', also 'scope', 'tlp',
    'egress_country' or any canonical SKIPPED code).

    Both call styles work: ``PolicyError("offline module: no network")`` and
    ``PolicyError("policy", "offline module: no network")`` (a leading canonical code is taken as
    the reason code), or ``PolicyError(message, reason_code="scope")``.
    """

    def __init__(self, *args: Any, reason_code: str = "", message: str = "") -> None:
        parts = [str(a) for a in args]
        code = reason_code
        if not code and parts and parts[0] in _SKIPPED_CODES:
            code = parts.pop(0)
        text = message or " ".join(p for p in parts if p) or f"refused by policy ({code or 'policy'})"
        msg = redact_text(text)
        super().__init__(msg)
        self.message = msg
        self.reason_code = code if code in _SKIPPED_CODES else "policy"


class ConfigError(Exception):
    """A required setting is missing (e.g. contact_email for a contact-UA provider): SKIPPED 'config'."""

    reason_code = "config"

    def __init__(self, message: Any = "") -> None:
        msg = redact_text(message)
        super().__init__(msg)
        self.message = msg


# ======================================================================================
# SSRF guard helpers (AR02): address and name classes refused for target contact
# ======================================================================================

#: Cloud metadata endpoints: AWS/GCP/Azure/OpenStack 169.254.169.254, AWS ECS 169.254.170.2, AWS
#: IPv6 fd00:ec2::254, Alibaba 100.100.100.200 and Oracle 192.0.0.192. Target contact with them
#: needs the scope to list the address itself (an internal seed alone never unlocks them).
METADATA_IPS: frozenset[str] = frozenset({"169.254.169.254", "169.254.170.2", "fd00:ec2::254", "100.100.100.200", "192.0.0.192"})
#: Name suffixes of internal namespaces refused for target contact (single-label names too).
INTERNAL_SUFFIXES: tuple[str, ...] = (".local", ".internal", ".lan", ".corp", ".home", ".intranet", ".localdomain", ".localhost", ".home.arpa")
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
_ULA_NET = ipaddress.ip_network("fc00::/7")
_NAT64_NET = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL_NET = ipaddress.ip_network("64:ff9b:1::/48")
_DOC_NETS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))
_NUMERIC_LABEL_RE = re.compile(r"^(?:0x[0-9a-f]*|[0-9]+)$")


def parse_ip(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address of an IP literal (brackets and an IPv6 zone index ignored), else None."""
    text = str(value or "").strip().strip("[]").split("%", 1)[0]
    if not text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def normalize_host(host: Any) -> str:
    """Lower-case host without brackets or trailing dot; IDN names as punycode ('' when empty)."""
    text = str(host or "").strip().strip("[]").lower().rstrip(".")
    if text and not text.isascii():
        try:
            text = text.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    return text


def _embedded_v4(addr: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    if addr.sixtofour is not None:
        return addr.sixtofour
    if addr in _NAT64_NET:
        return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return None


def ip_problem(value: Any) -> str:
    """Why an address may not be contacted by LIGHT/ACTIVE probes without an explicit allowance
    (AR02, A7): 'cloud metadata', 'loopback', 'link-local', 'CGNAT', 'unique local (ULA)',
    'multicast', 'reserved', 'private', 'documentation range' or 'not globally routable'; IPv4
    embedded in IPv6 (mapped, 6to4, NAT64) is judged by the IPv4 address. '' for a public address;
    'not an IP address' for anything unparsable."""
    addr = parse_ip(value)
    if addr is None:
        return "not an IP address"
    if addr.compressed in METADATA_IPS:
        return "cloud metadata"
    if isinstance(addr, ipaddress.IPv6Address):
        inner = _embedded_v4(addr)
        if inner is not None:
            found = ip_problem(inner)
            return f"{found} (IPv4 embedded in IPv6)" if found else ""
        if addr in _NAT64_LOCAL_NET:
            return "reserved"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT_NET:
        return "CGNAT"
    if isinstance(addr, ipaddress.IPv6Address) and addr in _ULA_NET:
        return "unique local (ULA)"
    if addr.is_multicast:
        return "multicast"
    if addr.is_unspecified or addr.is_reserved:
        return "reserved"
    if any(addr.version == net.version and addr in net for net in _DOC_NETS):
        return "documentation range"
    if addr.is_private:
        return "private"
    if not addr.is_global:
        return "not globally routable"
    return ""


def _numeric_host(host: str) -> bool:
    """An IPv4 address written in a legacy inet_aton form (2130706433, 0x7f.1, 0177.0.0.1)."""
    labels = host.split(".")
    return 1 <= len(labels) <= 4 and all(_NUMERIC_LABEL_RE.match(label) for label in labels)


def host_problem(host: Any) -> str:
    """Why a host may not be contacted by LIGHT/ACTIVE probes without an explicit allowance: the
    :func:`ip_problem` of an IP literal, 'ambiguous numeric host', 'single-label name' or
    'internal name (<suffix>)' ('' when the name itself is acceptable; its resolved addresses are
    judged separately)."""
    name = normalize_host(host)
    if not name:
        return "empty host"
    if parse_ip(name) is not None:
        return ip_problem(name)
    if _numeric_host(name):
        return "ambiguous numeric host (an IPv4 address in decimal, octal or hex form)"
    if "." not in name:
        return "single-label name"
    for suffix in INTERNAL_SUFFIXES:
        if name.endswith(suffix) or name == suffix[1:]:
            return f"internal name ({suffix})"
    return ""


def is_metadata_ip(value: Any) -> bool:
    """True for a cloud metadata endpoint (``METADATA_IPS``; IPv4-mapped forms included)."""
    addr = parse_ip(value)
    if addr is None:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        inner = _embedded_v4(addr)
        if inner is not None:
            addr = inner
    return addr.compressed in METADATA_IPS


def entity_hosts(entity: Any) -> tuple[str, ...]:
    """Host names/addresses an entity designates for target contact (a domain and its subdomains, the
    host of a URL, an IP, the domain of an e-mail, the host of a host:port service, a CIDR)."""
    if entity is None:
        return ()
    etype = getattr(entity, "type", "")
    etype = str(getattr(etype, "value", etype) or "")
    value = str(getattr(entity, "value", "") or "").strip()
    if not value:
        return ()
    if etype == "cidr":
        try:
            return (str(ipaddress.ip_network(value, strict=False)),)
        except ValueError:
            return ()
    if "://" in value:
        host = _host(value)
    elif etype == "email" or ("@" in value and etype not in ("domain", "ipv4", "ipv6")):
        host = value.rsplit("@", 1)[-1]
    elif etype == "port_service" or (value.count(":") == 1 and "." in value):
        host = value.rsplit(":", 1)[0] if not value.startswith("[") else value[1:].split("]", 1)[0]
        host = host.split("/", 1)[0]
    else:
        host = value.split("/", 1)[0]
    host = normalize_host(host)
    return (host,) if host else ()


def host_within(host: str, candidates: Iterable[str]) -> bool:
    """Does ``host`` belong to one of ``candidates`` (entity_hosts): the same host, a subdomain of
    a domain candidate (label-wise), or an address inside a CIDR candidate?"""
    name = normalize_host(host)
    if not name:
        return False
    addr = parse_ip(name)
    for cand in candidates:
        if "/" in cand:
            if addr is None:
                continue
            try:
                net = ipaddress.ip_network(cand, strict=False)
            except ValueError:
                continue
            if addr.version == net.version and addr in net:
                return True
            continue
        if name == cand:
            return True
        if addr is None and parse_ip(cand) is None and name.endswith("." + cand):
            return True
    return False


# ======================================================================================
# Method allow-list for target contact (A7: GET/HEAD for LIGHT, GET/HEAD/OPTIONS for ACTIVE)
# ======================================================================================

#: Header names a scope's ROE header may never use (credentials, hop-by-hop and identity headers):
#: an engagement token goes in its own header, e.g. X-Engagement-Token (A7 ROE).
ROE_FORBIDDEN_HEADERS: frozenset[str] = frozenset(
    {
        "authorization", "proxy-authorization", "cookie", "set-cookie", "host", "user-agent", "content-length", "content-type",
        "transfer-encoding", "connection", "upgrade", "te", "trailer", "keep-alive", "proxy-connection", "from", "referer",
        "forwarded", "x-forwarded-for", "x-real-ip", "accept-encoding",
    }
)

METHOD_ALLOW_SCHEMA = "v3lum.method_allow/1"
LIGHT_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})
ACTIVE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})
#: Methods no allow-list fragment can grant: writes, deletes, tracing and tunnelling toward targets
#: are forbidden in every mode (A7).
NEVER_ALLOWED_METHODS: frozenset[str] = frozenset(
    {"PUT", "PATCH", "DELETE", "TRACE", "TRACK", "CONNECT", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}
)
_METHOD_RE = re.compile(r"^[A-Z][A-Z_-]{1,19}$")
_ALLOW_MODULE_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_ALLOWLIST_DIR = Path(__file__).resolve().parent.parent / "data" / "policy" / "method_allowlist"


@dataclass(frozen=True)
class MethodAllowance:
    """An approved method allow-list fragment (``v3lum.method_allow/1``): extra methods one
    LIGHT/ACTIVE module may send to targets for a documented read-only reason."""

    module: str
    methods: Mapping[str, str]
    approved_by: str
    decision_ref: str
    origin: str = ""


_ALLOW_LOCK = threading.Lock()
_ALLOW_STATE: tuple[dict[str, MethodAllowance], tuple[str, ...]] | None = None
_ALLOW_EXTRA_DIRS: tuple[Path, ...] = ()


def _parse_allowance(origin: str, stem: str, data: Any) -> tuple[MethodAllowance | None, list[str]]:
    if not isinstance(data, dict):
        return None, [f"{origin}: a fragment must be a JSON object"]
    if data.get("schema") != METHOD_ALLOW_SCHEMA:
        return None, [f"{origin}: schema must be {METHOD_ALLOW_SCHEMA!r} (got {data.get('schema')!r})"]
    unknown = sorted(set(data) - {"schema", "module", "methods", "approved_by", "decision_ref", "notes"})
    if unknown:
        return None, [f"{origin}: unknown keys {unknown}"]
    module = str(data.get("module") or "")
    if not _ALLOW_MODULE_RE.match(module) or module != stem:
        return None, [f"{origin}: 'module' must be the module name and equal the file stem ({stem!r})"]
    approved_by = str(data.get("approved_by") or "").strip()
    decision_ref = str(data.get("decision_ref") or "").strip()
    if not approved_by or not decision_ref:
        return None, [f"{origin}: ignored - an allow-list entry needs approved_by and decision_ref (a recorded core policy decision)"]
    methods = data.get("methods")
    if not isinstance(methods, dict) or not methods:
        return None, [f"{origin}: 'methods' must be a non-empty object method -> justification"]
    granted: dict[str, str] = {}
    errors: list[str] = []
    for raw, why in methods.items():
        method = str(raw).strip().upper()
        if not _METHOD_RE.match(method):
            errors.append(f"{origin}: invalid method {raw!r}")
        elif method in NEVER_ALLOWED_METHODS:
            errors.append(f"{origin}: {method} can never be allow-listed (writes, deletes, tracing and tunnelling toward targets are forbidden, A7)")
        elif not isinstance(why, str) or not why.strip():
            errors.append(f"{origin}: {method} needs a written justification (the documented read-only reason)")
        else:
            granted[method] = why.strip()
    if errors:
        return None, errors
    return MethodAllowance(module, granted, approved_by, decision_ref, origin), []


def _load_allowlist() -> tuple[dict[str, MethodAllowance], tuple[str, ...]]:
    found: dict[str, MethodAllowance] = {}
    errors: list[str] = []
    for directory in (_ALLOWLIST_DIR, *_ALLOW_EXTRA_DIRS):
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.json")):
            origin = str(path)
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, ValueError) as exc:
                errors.append(f"{origin}: unreadable ({exc})")
                continue
            entry, errs = _parse_allowance(origin, path.stem, data)
            errors.extend(errs)
            if entry is None:
                continue
            if entry.module in found:
                errors.append(f"{origin}: duplicate allow-list entry for {entry.module!r} (ignored)")
                continue
            found[entry.module] = entry
    return found, tuple(errors)


def _allow_state() -> tuple[dict[str, MethodAllowance], tuple[str, ...]]:
    global _ALLOW_STATE
    with _ALLOW_LOCK:
        if _ALLOW_STATE is None:
            _ALLOW_STATE = _load_allowlist()
        return _ALLOW_STATE


def method_allowlist() -> dict[str, MethodAllowance]:
    """Approved method allow-list fragments by module (``v3lum/data/policy/method_allowlist/``;
    none ship; a fragment without ``approved_by`` and ``decision_ref`` is ignored and reported)."""
    return dict(_allow_state()[0])


def method_allowlist_errors() -> list[str]:
    """Problems of the allow-list fragments (ignored fragments included), for doctor and CI."""
    return list(_allow_state()[1])


def reload_method_allowlist(extra_dirs: Iterable[str | Path] | None = None) -> None:
    """Forget the loaded fragments; ``extra_dirs`` adds fragment directories (tests; ``()`` removes them)."""
    global _ALLOW_STATE, _ALLOW_EXTRA_DIRS
    with _ALLOW_LOCK:
        if extra_dirs is not None:
            _ALLOW_EXTRA_DIRS = tuple(Path(d) for d in extra_dirs)
        _ALLOW_STATE = None


def allowed_methods(module: str, opsec: Any) -> frozenset[str]:
    """Methods ``module`` may send to targets at ``opsec``: GET/HEAD (LIGHT) or GET/HEAD/OPTIONS
    (ACTIVE) plus the methods of its approved allow-list fragment (every method for PASSIVE)."""
    label = _opsec_label(opsec)
    if label == "passive":
        return frozenset({"*"})
    base = LIGHT_METHODS if label == "light" else ACTIVE_METHODS
    entry = method_allowlist().get(str(module or ""))
    return base | frozenset(entry.methods) if entry is not None else base


# ======================================================================================
# A7 hard ceilings shared by HttpClient, the socket connector and the external-tool runner
# ======================================================================================

#: ACTIVE budget per case (requests/probes); a scope's limits.max_requests may set it up to the max.
DEFAULT_ACTIVE_BUDGET = 10_000
MAX_ACTIVE_BUDGET = 50_000
#: packets (connection attempts) per second over all target hosts; a scope's limits.max_pps may
#: raise it up to MAX_PPS.
DEFAULT_MAX_PPS = 100
MAX_PPS = 1000
#: distinct TCP ports per target host and case (port scans; no UDP sweeps exist at all).
PORT_SCAN_MAX = 1000
#: entries of any wordlist (``Connector.cap_wordlist``; --wordlist included).
WORDLIST_MAX = 5000


def _limit(scope: Any, name: str) -> Any:
    limits = getattr(scope, "limits", None) if scope is not None else None
    if isinstance(limits, Mapping):
        return limits.get(name)
    return getattr(limits, name, None) if limits is not None else None


def _positive(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def contact_rps(opsec: Any, scope: Any = None) -> float:
    """Requests/probes per second per target host: LIGHT <= 1, ACTIVE <= 10, lower when the scope's
    limits.max_rps says so (never higher)."""
    ceiling = LIGHT_MAX_RPS if _opsec_label(opsec) == "light" else ACTIVE_MAX_RPS
    asked = _positive(_limit(scope, "max_rps"))
    return min(ceiling, asked) if asked else ceiling


def contact_concurrency(opsec: Any, scope: Any = None) -> int:
    """Concurrent connections per target host: <= 2, lower when the scope's limits.max_concurrency says so."""
    asked = _positive(_limit(scope, "max_concurrency"))
    return max(1, min(ACTIVE_MAX_CONCURRENT, int(asked))) if asked else ACTIVE_MAX_CONCURRENT


def active_budget(scope: Any = None) -> int:
    """ACTIVE requests/probes per case: 10000, or the scope's limits.max_requests (<= 50000)."""
    asked = _positive(_limit(scope, "max_requests"))
    return int(min(MAX_ACTIVE_BUDGET, asked)) if asked else DEFAULT_ACTIVE_BUDGET


def max_pps(scope: Any = None) -> int:
    """Connection attempts per second over all targets: 100, or the scope's limits.max_pps (<= 1000)."""
    asked = _positive(_limit(scope, "max_pps"))
    return int(max(1, min(MAX_PPS, asked))) if asked else DEFAULT_MAX_PPS


class ContactCeilings:
    """Counters behind the A7 per-scan and per-case ceilings of one runtime (shared by HttpClient,
    the socket connector and the external-tool runner): LIGHT <= 25 requests per target host per
    scan, the ACTIVE budget per case, <= 1000 distinct TCP ports per target host. Counters are kept
    per case id (``RunInfo.case_id``), else per scan (``reset_scan`` starts a new one; the engine
    calls it through ``HttpClient.reset_circuit`` at the start of every investigation).
    Exceeding a ceiling raises :class:`RequestCapReached` (a partial result, stop_reason request_cap)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._epoch = 0
        self._light: dict[tuple[str, str], int] = {}
        self._active: dict[str, int] = {}
        self._ports: dict[tuple[str, str], set[int]] = {}

    def _key(self, case_id: str) -> str:
        return f"case:{case_id}" if case_id else f"scan:{self._epoch}"

    def reset_scan(self) -> None:
        """Start a new scan: per-scan counters restart (per-case counters of other cases are dropped)."""
        with self._lock:
            self._epoch += 1
            self._light.clear()
            self._active.clear()
            self._ports.clear()

    def charge(self, opsec: Any, host: str, *, case_id: str = "", scope: Any = None, n: int = 1) -> None:
        """Count ``n`` requests/probes to ``host``; raise RequestCapReached when a ceiling would be passed."""
        label = _opsec_label(opsec)
        host = normalize_host(host)
        with self._lock:
            key = self._key(case_id)
            if label == "light":
                used = self._light.get((key, host), 0)
                if used + n > LIGHT_MAX_PER_HOST_PER_SCAN:
                    raise RequestCapReached(f"LIGHT ceiling reached: at most {LIGHT_MAX_PER_HOST_PER_SCAN} requests to {host} per scan (A7)")
                self._light[(key, host)] = used + n
            elif label == "active":
                budget = active_budget(scope)
                used = self._active.get(key, 0)
                if used + n > budget:
                    raise RequestCapReached(f"ACTIVE budget reached: {budget} requests/probes per case (A7; a scope's limits.max_requests sets it, at most {MAX_ACTIVE_BUDGET})")
                self._active[key] = used + n

    def port(self, host: str, port: int, *, case_id: str = "") -> None:
        """Record a TCP port probed on ``host``; more than PORT_SCAN_MAX distinct ports raise RequestCapReached."""
        host = normalize_host(host)
        with self._lock:
            ports = self._ports.setdefault((self._key(case_id), host), set())
            if int(port) not in ports and len(ports) >= PORT_SCAN_MAX:
                raise RequestCapReached(f"port-scan ceiling reached: at most {PORT_SCAN_MAX} TCP ports per target host ({host}) (A7)")
            ports.add(int(port))

    def used(self, opsec: Any, host: str = "", *, case_id: str = "") -> int:
        """Requests/probes counted so far (LIGHT: for ``host``; ACTIVE: for the case)."""
        label = _opsec_label(opsec)
        with self._lock:
            key = self._key(case_id)
            if label == "light":
                return self._light.get((key, normalize_host(host)), 0)
            return self._active.get(key, 0) if label == "active" else 0


# ======================================================================================
# Classification (P321)
# ======================================================================================


@dataclass(frozen=True)
class Classification:
    """Why a response is not usable data: ``status`` 'blocked' | 'rate_limited' | 'quota' | 'error',
    a canonical ``reason_code``, a human ``reason`` naming the provider and the ``marker_id``."""

    status: str
    reason_code: str
    reason: str
    marker_id: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"status": self.status, "reason_code": self.reason_code, "reason": self.reason, "marker_id": self.marker_id}


# (marker id, lower-case needle, vendor). STRONG markers only appear on challenge/block pages and are
# checked on any status; WEAK markers also appear on normal pages and count on error statuses only.
# Neither table is applied to JSON documents (APIs legitimately carry page titles such as
# "Just a moment..." or "Vercel Security Checkpoint" as data).
_STRONG_MARKERS: tuple[tuple[str, str, str], ...] = (
    # Cloudflare (maigret COMMON_ERRORS, sherlock WAFHitMsgs, V3LUM v1)
    ("cloudflare_challenge", "<title>just a moment", "Cloudflare"),
    ("cloudflare_challenge", "cf-chl-", "Cloudflare"),
    ("cloudflare_challenge", "/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page", "Cloudflare"),
    ("cloudflare_challenge", '<span id="challenge-error-text">', "Cloudflare"),
    ("cloudflare_challenge", "cf-browser-verification", "Cloudflare"),
    ("cloudflare_challenge", "please stand by, while we are checking your browser", "Cloudflare"),
    ("cloudflare_challenge", '<span data-translate="checking_browser">checking your browser before accessing</span>', "Cloudflare"),
    ("cloudflare_block", "attention required! | cloudflare", "Cloudflare"),
    ("cloudflare_block", "this website is using a security service to protect itself from online attacks", "Cloudflare"),
    # AWS WAF (sherlock WAFHitMsgs; challenge interstitial)
    ("aws_waf", "awswafintegration.forcerefreshtoken", "AWS WAF"),
    ("aws_waf", "aws-waf-token", "AWS WAF"),
    ("aws_waf", "window.gokuprops", "AWS WAF"),
    # PerimeterX / HUMAN (sherlock WAFHitMsgs, V3LUM v1)
    ("perimeterx", "px-captcha", "PerimeterX"),
    ("perimeterx", "_pxhd", "PerimeterX"),
    ("perimeterx", '"perimeterxidentifiers"', "PerimeterX"),
    # Imperva Incapsula (maigret COMMON_ERRORS; the block page iframe)
    ("incapsula", "incapsula incident id", "Incapsula"),
    ("incapsula", "_incapsula_resource?cwudnsai", "Incapsula"),
    # DDoS-Guard (maigret COMMON_ERRORS)
    ("ddos_guard", "<title>ddos-guard</title>", "DDoS-Guard"),
    ("ddos_guard", "check.ddos-guard.net", "DDoS-Guard"),
    # Vercel (maigret COMMON_ERRORS)
    ("vercel_checkpoint", "<title>vercel security checkpoint</title>", "Vercel"),
    # DataDome (V3LUM v1)
    ("datadome", "captcha-delivery.com", "DataDome"),
    # Google rate-limit / reCAPTCHA interstitials (maigret COMMON_ERRORS)
    ("google_captcha", "unusual traffic from your computer network", "Google"),
    ("google_captcha", "google.com/recaptcha/challengepage/", "Google reCAPTCHA"),
    ("google_captcha", 'id="gs_captcha_f"', "Google"),
    # proof-of-work and other interstitials (maigret COMMON_ERRORS)
    ("anubis", "/.within.website/x/", "Anubis"),
    ("pow_challenge", "window.pow_challenge_data", "proof-of-work challenge"),
    ("client_challenge", "<title>client challenge</title>", "anti-bot challenge"),
    ("slardar_waf", "slardarwaf", "SlardarWAF"),
    ("imunify360", "/z0f76a1d14fd21a8fb5fd0d03e0fdc3d3cedae52f", "Imunify360"),
    ("stile", "/.stile/challenge", "Stile"),
    ("blazingfast", "ddos protection by</font> blazingfast.io", "Blazingfast"),
    # V3LUM v1
    ("network_security_block", "blocked by network security", "network security block"),
    ("isc_blockme", "/blockme.html", "SANS ISC access restriction"),
    # V3LUM research samples (2026-11-25/26): interstitials served with HTTP 200 or 403
    ("netcraft_challenge", "between robotic users and genuine visitors", "Netcraft"),
    ("facebook_challenge", "/__rd_verify_", "Facebook"),
    ("cloudflare_custom_block", "your request was blocked due to our security policies", "Cloudflare WAF"),
)
#: Interstitial pages are small; phrases and titles that a normal page can also carry (a contact
#: form's 'confirm that you are not a robot', a profile named 'captcha') count only up to this size.
_INTERSTITIAL_MAX_BYTES = 32 * 1024
# phrases of the challenge pages themselves (strong, any status, small pages only)
_INTERSTITIAL_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("abusech_browser_check", "please confirm that you are not a robot", "abuse.ch browser check"),
    ("domaintools_captcha", "validate that you are indeed human", "DomainTools CAPTCHA"),
)
# <title> words of interstitial pages (strong, any status, small pages only)
_TITLE_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("title_captcha", "captcha", "CAPTCHA"),
    ("title_browser_check", "checking your browser", "browser check"),
    ("title_human_check", "human verification", "human verification"),
    ("title_bot_check", "bot verification", "bot verification"),
    ("title_robot_check", "are you a robot", "CAPTCHA"),
)
_TITLE_RE = re.compile(r"<title[^>]*>([^<]{0,300})</title>")
#: an Incapsula JS challenge is a near-empty noindex page loading only the _Incapsula_Resource script
#: (normal Incapsula-protected pages load the same script, so the script alone is a weak marker)
_INCAPSULA_CHALLENGE_MAX_BYTES = 2048
_WEAK_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("cloudflare_bot_script", "challenge-platform", "Cloudflare"),
    ("access_denied", "access denied</title>", "access-denied page"),
    ("incapsula", "request unsuccessful. incapsula", "Incapsula"),
    ("incapsula", "_incapsula_resource", "Incapsula"),
    ("akamai_bot_manager", "akamai bot manager", "Akamai Bot Manager"),
    ("sucuri", "sucuri website firewall", "Sucuri"),
    ("captcha", "verify you are human", "CAPTCHA"),
    ("captcha", "are you a robot", "CAPTCHA"),
    ("captcha", "g-recaptcha", "reCAPTCHA"),
    ("captcha", "h-captcha", "hCaptcha"),
    # the AWS WAF JS SDK and DDoS-Guard scripts are also embedded in normal pages (e.g. Portal da
    # Transparencia serves its search page with edge.sdk.awswaf.com/challenge.js and HTTP 200)
    ("aws_waf", "awswaf", "AWS WAF"),
    ("ddos_guard", "ddos-guard", "DDoS-Guard"),
)
_LOGIN_PATH_RE = re.compile(r"(?:^|/)(?:login|signin|sign-in|sign_in|servicelogin|authwall)(?:[/.;]|$)", re.IGNORECASE)
_LOGIN_HOST_PREFIXES = ("login.", "signin.")
_GOOGLE_SORRY_RE = re.compile(r"(?:^|\.)google\.[a-z.]+$")
_GEO_HINT = "needs egress_country / see v3lum doctor --egress"


def _is_weak_status(status: int) -> bool:
    """Error statuses on which weak markers count (404/410 stay meaningful absences)."""
    return status >= 400 and status not in (404, 410)


class _Body:
    """Lazy views of a response body for the classifier (text sample, lower-case sample, JSON)."""

    _UNPARSED = object()
    NOT_JSON = object()

    def __init__(self, resp: Response) -> None:
        self._resp = resp
        self._sample: str | None = None
        self._lower: str | None = None
        self._scan: str | None = None
        self._json: Any = self._UNPARSED

    @property
    def sample(self) -> str:
        if self._sample is None:
            self._sample = bytes(self._resp.content[:CLASSIFY_BYTES]).decode("utf-8", errors="replace")
        return self._sample

    @property
    def lower(self) -> str:
        if self._lower is None:
            self._lower = self.sample.lower()
        return self._lower

    @property
    def scan(self) -> str:
        """Lower-case text the built-in fingerprints search: the first 64 KB and, for longer bodies,
        the last 16 KB too."""
        if self._scan is None:
            content = self._resp.content
            text = self.lower
            if len(content) > CLASSIFY_BYTES:
                tail = bytes(content[-CLASSIFY_TAIL_BYTES:]).decode("utf-8", errors="replace").lower()
                text = f"{text}\n{tail}"
            self._scan = text
        return self._scan

    @property
    def looks_json(self) -> bool:
        ctype = str(self._resp.headers.get("content-type", "")).lower()
        if "json" in ctype:
            return True
        head = bytes(self._resp.content[:64]).lstrip(b"\xef\xbb\xbf \t\r\n")
        return head[:1] in (b"{", b"[")

    @property
    def json(self) -> Any:
        if self._json is self._UNPARSED:
            content = self._resp.content
            value: Any = self.NOT_JSON
            if content and len(content) <= _JSON_PARSE_LIMIT and self.looks_json:
                try:
                    value = json.loads(content)
                except (ValueError, UnicodeDecodeError):
                    value = self.NOT_JSON
            self._json = value
        return self._json


@dataclass(frozen=True)
class _Marker:
    id: str
    statuses: tuple[int, ...]
    json_path: str | None
    equals: Any
    has_equals: bool
    regex: re.Pattern[str] | None
    final_url_regex: re.Pattern[str] | None
    maps_to: str
    reason_code: str
    reason: str


_MARKER_CACHE: dict[int, tuple[Any, _Marker | None]] = {}
_MARKER_CACHE_LOCK = threading.Lock()


def _field(marker: Any, name: str, default: Any = None) -> Any:
    if isinstance(marker, Mapping):
        return marker.get(name, default)
    return getattr(marker, name, default)


def _compile_marker(marker: Any) -> _Marker | None:
    """Normalise a provider/module error marker (dict or ErrorMarker); None when unusable."""
    try:
        maps_to = str(_field(marker, "maps_to", "") or "")
        if maps_to not in _MARKER_CODES:
            return None
        json_path = _field(marker, "json_path")
        json_path = str(json_path) if json_path else None
        if isinstance(marker, Mapping):
            has_equals = "equals" in marker
        else:
            has_equals = _field(marker, "equals") is not None
        regex = _field(marker, "regex")
        url_regex = _field(marker, "final_url_regex")
        compiled = re.compile(str(regex)) if regex else None
        compiled_url = re.compile(str(url_regex)) if url_regex else None
        if json_path is None and compiled is None and compiled_url is None:
            return None  # a marker without a matcher would classify every response
        statuses = _field(marker, "statuses", (200,))
        statuses = (200,) if statuses is None else tuple(int(s) for s in statuses)
        code = str(_field(marker, "reason_code") or "")
        if code not in _MARKER_CODES[maps_to]:
            code = _MARKER_DEFAULT_CODE[maps_to]
        mid = str(_field(marker, "id", "") or "marker")
        return _Marker(
            id=mid,
            statuses=statuses,
            json_path=json_path,
            equals=_field(marker, "equals"),
            has_equals=has_equals,
            regex=compiled,
            final_url_regex=compiled_url,
            maps_to=maps_to,
            reason_code=code,
            reason=str(_field(marker, "reason", "") or ""),
        )
    except (TypeError, ValueError, re.error):
        return None


def _marker(marker: Any) -> _Marker | None:
    if isinstance(marker, _Marker):
        return marker
    key = id(marker)
    with _MARKER_CACHE_LOCK:
        hit = _MARKER_CACHE.get(key)
        if hit is not None and hit[0] is marker:
            return hit[1]
    compiled = _compile_marker(marker)
    with _MARKER_CACHE_LOCK:
        if len(_MARKER_CACHE) > 4096:
            _MARKER_CACHE.clear()
        _MARKER_CACHE[key] = (marker, compiled)
    return compiled


def _json_values(data: Any, path: str) -> list[Any]:
    """Values at a dotted path: 'a.b', 'list[].field', numeric list indexes and '*' for any key."""
    current = [data]
    for raw_part in path.split("."):
        many = raw_part.endswith("[]")
        part = raw_part[:-2] if many else raw_part
        nxt: list[Any] = []
        for item in current:
            if part == "":
                values = [item]
            elif part == "*":
                values = list(item.values()) if isinstance(item, dict) else list(item) if isinstance(item, list) else []
            elif isinstance(item, dict):
                values = [item[part]] if part in item else []
            elif isinstance(item, list) and part.isdigit():
                idx = int(part)
                values = [item[idx]] if idx < len(item) else []
            else:
                values = []
            for value in values:
                if many:
                    if isinstance(value, list):
                        nxt.extend(value)
                else:
                    nxt.append(value)
        current = nxt
        if not current:
            break
    return current


def _scalar_text(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip().lower()


def _equals(value: Any, expected: Any) -> bool:
    """Marker equality, tolerant of JSON scalar typing ("0" == 0, "true" == true, "ERROR" == "error")."""
    if isinstance(value, (dict, list)) or isinstance(expected, (dict, list)):
        return value == expected
    return _scalar_text(value) == _scalar_text(expected)


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip()) and value.strip().lower() not in ("false", "0", "null", "none")
    return bool(value)


def _marker_matches(m: _Marker, resp: Response, body: _Body) -> bool:
    if m.statuses and int(resp.status) not in m.statuses:
        return False
    if m.final_url_regex is not None and not m.final_url_regex.search(resp.url or ""):
        return False
    if m.json_path:
        data = body.json
        if data is _Body.NOT_JSON:
            return False
        values = _json_values(data, m.json_path)
        if not values:
            return False
        if m.has_equals:
            return any(_equals(v, m.equals) for v in values)
        if m.regex is not None:
            return any(m.regex.search(v if isinstance(v, str) else json.dumps(v)) for v in values)
        return any(_truthy(v) for v in values)
    if m.regex is not None:
        return bool(m.regex.search(body.sample))
    return m.final_url_regex is not None


def _host(url: str) -> str:
    try:
        return (urlsplit(url or "").hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _port(url: str) -> int:
    try:
        parts = urlsplit(url or "")
        return parts.port or (443 if parts.scheme == "https" else 80 if parts.scheme == "http" else 0)
    except ValueError:
        return 0


def _same_url(a: str, b: str) -> bool:
    def norm(u: str) -> tuple[str, str, int, str, str]:
        try:
            p = urlsplit(u or "")
            return (p.scheme.lower(), (p.hostname or "").lower(), _port(u), p.path or "/", p.query)
        except ValueError:
            return ("", "", 0, u, "")

    return norm(a) == norm(b)


def _named(name: str, text: str) -> str:
    return f"{name}: {text}" if name else text[:1].upper() + text[1:]


def _login_parts(url: str) -> tuple[str, bool]:
    """(host, path looks like a login page) of a URL; ('', False) when unparsable or empty."""
    if not url:
        return "", False
    try:
        parts = urlsplit(url)
    except ValueError:
        return "", False
    return (parts.hostname or "").lower(), bool(_LOGIN_PATH_RE.search(parts.path or "/"))


def _url_rule(url: str, name: str, request_url: str = "") -> Classification | None:
    """Login-wall / access-restriction rules on a final URL (or a redirect Location).

    A login path counts only when the module did not request a login URL itself, and a login host
    (login.*, signin.*) only when it differs from the requested host: a module querying an
    identity provider on purpose is not walled by that provider's own redirects.
    """
    if not url:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    path = parts.path or "/"
    lowered = path.lower()
    if lowered.endswith("/blockme.html"):
        return Classification("blocked", "challenge", _named(name, "access restricted page (blockme.html): could not verify"), "url.blockme")
    if lowered.startswith("/sorry/") and _GOOGLE_SORRY_RE.search(host):
        return Classification("blocked", "challenge", _named(name, "Google 'unusual traffic' page: could not verify"), "url.google_sorry")
    requested_host, requested_login = _login_parts(request_url)
    login_path = bool(_LOGIN_PATH_RE.search(path)) and not requested_login
    login_host = host.startswith(_LOGIN_HOST_PREFIXES) and host != requested_host
    if login_path or login_host:
        shown = redact_url(path)[:80]
        return Classification("blocked", "login_wall", _named(name, f"login wall (redirected to {host}{shown}): could not verify"), "url.login_wall")
    return None


def _header(headers: Mapping[str, Any], name: str) -> str:
    value = headers.get(name)
    if value is None:
        for key, val in headers.items():
            if str(key).lower() == name:
                return str(val)
        return ""
    return str(value)


def classify(resp: Response, *, markers: Iterable[Any] = (), keyless: bool = False, provider_name: str = "") -> Classification | None:
    """Classify a response before anything parses or caches it (P321). None = usable answer.

    Evaluated in order, first match wins:

    1. declared ``markers`` (module + provider error markers: ``json_path``/``equals``, or ``regex``
       over the first 64 KB of text; optional ``statuses`` and ``final_url_regex``) -> ``maps_to``;
    2. the final URL (when redirected) or a redirect ``Location``: login pages (/login, /accounts/login,
       /signin, /authwall, ...) -> blocked 'login_wall' (unless the module requested a login URL
       itself); /blockme.html -> blocked 'challenge';
    3. geo-blocks: CloudFront 403 'The request could not be satisfied', Akamai 'Reference #' access-denied
       pages and HTTP 451 -> blocked 'geo_block';
    4. strong anti-bot/WAF fingerprints (any status; Cloudflare, AWS WAF, PerimeterX, Incapsula, DDoS-Guard,
       Vercel, DataDome, ...; on small pages also interstitial phrases and titles such as '... Captcha'
       or 'Checking your browser'; the Incapsula JS challenge shape) and challenge headers -> blocked
       'challenge';
    5. weak fingerprints (captcha words, 'challenge-platform', 'verify you are human') and Cloudflare-served
       403/503 pages, on error statuses only -> blocked 'challenge';
    6. HTTP 429 -> rate_limited; 430 (egress IP blacklisted) and 999 (anti-bot denial) -> blocked 'challenge';
    7. ``keyless`` and HTTP 403 -> blocked 'challenge' ('HTTP 403 for a keyless source: could not verify').

    Fingerprints (3-5) search the first 64 KB and the last 16 KB of the body and are not applied to
    JSON documents. The result never means 'empty' or 'absent'.
    """
    status = int(resp.status or 0)
    name = provider_name or resp.host or _host(resp.url)
    body = _Body(resp)
    headers = resp.headers or {}

    # 1. declared error markers
    for raw in markers or ():
        m = _marker(raw)
        if m is None:
            continue
        try:
            matched = _marker_matches(m, resp, body)
        except (TypeError, ValueError, re.error, RecursionError):
            matched = False
        if matched:
            reason = m.reason or _named(name, f"{m.maps_to.replace('_', ' ')} (marker {m.id})")
            return Classification(m.maps_to, m.reason_code, reason, m.id)

    # 2. final URL / redirect target
    redirected = bool(resp.history) or not resp.request_url or not _same_url(resp.request_url, resp.url)
    requested = resp.history[0] if resp.history else resp.request_url  # the URL the module asked for
    if redirected:
        hit = _url_rule(resp.url, name, requested)
        if hit is not None:
            return hit
    if 300 <= status < 400:
        location = _header(headers, "location")
        if location:
            hit = _url_rule(urljoin(resp.url or "", location.strip()), name, requested or resp.url)
            if hit is not None:
                return hit

    if status == 451:
        return Classification("blocked", "geo_block", _named(name, f"HTTP 451 unavailable for legal reasons (geo-block) - {_GEO_HINT}"), "status.451")

    # header fingerprints (any body type)
    mitigated = _header(headers, "cf-mitigated").lower()
    if "challenge" in mitigated:
        return Classification("blocked", "challenge", _named(name, "anti-bot challenge (Cloudflare cf-mitigated header): could not verify"), "header.cf_mitigated")
    waf_action = _header(headers, "x-amzn-waf-action").lower()
    if waf_action in ("challenge", "captcha"):
        return Classification("blocked", "challenge", _named(name, f"anti-bot {waf_action} (AWS WAF): could not verify"), "header.aws_waf")

    if not body.looks_json and resp.content:
        text = body.scan
        # 3. geo-blocks
        if status == 403 and "the request could not be satisfied" in text:
            return Classification(
                "blocked", "geo_block", _named(name, f"geo-blocked from this egress (CloudFront 403 'The request could not be satisfied') - {_GEO_HINT}"), "geo.cloudfront"
            )
        if status >= 400 and "access denied" in text:
            plain = html.unescape(text) if "&" in text else text  # Akamai entity-encodes 'Reference&#32;&#35;18...'
            if "reference #" in plain or "errors.edgesuite.net" in plain:
                return Classification("blocked", "geo_block", _named(name, f"geo-blocked from this egress (Akamai access-denied page) - {_GEO_HINT}"), "geo.akamai")
        # 4. strong fingerprints: body strings, interstitial titles, the Incapsula JS challenge shape
        for mid, needle, vendor in _STRONG_MARKERS:
            if needle in text:
                return Classification("blocked", "challenge", _named(name, f"anti-bot challenge page ({vendor}): could not verify"), f"generic.{mid}")
        if len(resp.content) <= _INTERSTITIAL_MAX_BYTES:
            for mid, needle, vendor in _INTERSTITIAL_MARKERS:
                if needle in text:
                    return Classification("blocked", "challenge", _named(name, f"anti-bot challenge page ({vendor}): could not verify"), f"generic.{mid}")
            title = _TITLE_RE.search(body.lower)
            if title is not None:
                words = " ".join(title.group(1).split())
                for mid, needle, vendor in _TITLE_MARKERS:
                    if needle in words:
                        return Classification("blocked", "challenge", _named(name, f"anti-bot challenge page ({vendor}): could not verify"), f"generic.{mid}")
        if len(resp.content) <= _INCAPSULA_CHALLENGE_MAX_BYTES and "_incapsula_resource" in text and "noindex" in text:
            return Classification("blocked", "challenge", _named(name, "anti-bot challenge page (Incapsula JS challenge): could not verify"), "generic.incapsula_js_challenge")
        # 5. weak fingerprints and Cloudflare-served error pages, error statuses only
        if _is_weak_status(status):
            for mid, needle, vendor in _WEAK_MARKERS:
                if needle in text:
                    return Classification("blocked", "challenge", _named(name, f"anti-bot challenge page ({vendor}): could not verify"), f"generic.{mid}")
    # a Cloudflare-served 403 page is a block; a 503 only when Cloudflare marks it (else the origin is down)
    if (status == 403 and "cloudflare" in _header(headers, "server").lower() or status in (403, 503) and mitigated) and not body.looks_json:
        return Classification("blocked", "challenge", _named(name, f"blocked by Cloudflare (HTTP {status}): could not verify"), "header.cloudflare")

    # 6. status rules
    if status == 429:
        retry = _header(headers, "retry-after")
        extra = f", Retry-After {retry}" if retry else ""
        return Classification("rate_limited", "rate_limited", _named(name, f"rate limited (HTTP 429{extra})"), "status.429")
    if status == 430:
        return Classification("blocked", "challenge", _named(name, "provider blacklisted this egress IP (HTTP 430): could not verify"), "status.430")
    if status == 999:
        return Classification("blocked", "challenge", _named(name, "anti-bot denial (HTTP 999): could not verify"), "status.999")
    # 7. keyless 403
    if keyless and status == 403:
        return Classification("blocked", "challenge", _named(name, "HTTP 403 for a keyless source: could not verify"), "keyless.403")
    return None


def block_reason(status: int, headers: Mapping[str, str], body: bytes | str) -> str | None:
    """v1 compatibility wrapper: why a response looks like an anti-bot/WAF/geo block page, or None.

    Keeps the v1 status pre-filter (200, 202, 403, 406, 409, 429, 430, 451, 503 and 5xx) and returns
    the reason of a 'blocked' :func:`classify` result without declared markers.
    """
    if status not in (200, 202, 403, 406, 409, 429, 430, 451, 503) and status < 500:
        return None
    content = body if isinstance(body, (bytes, bytearray)) else str(body or "").encode("utf-8")
    resp = Response(int(status), "", {str(k).lower(): str(v) for k, v in (headers or {}).items()}, bytes(content))
    found = classify(resp)
    return found.reason if found is not None and found.status == "blocked" else None


def _exception_for(cls: Classification, resp: Response) -> HttpError:
    kind = {"blocked": Blocked, "rate_limited": RateLimited, "quota": QuotaExceeded}.get(cls.status, HttpError)
    return kind(cls.reason, resp.status, resp.url, resp.error_body, reason_code=cls.reason_code)


# ======================================================================================
# Response and request records
# ======================================================================================


@dataclass
class Response:
    """One HTTP answer. The v1 positional constructor is kept:
    ``Response(status, url, headers, content, elapsed=0.0, from_cache=False, truncated=False, history=[])``.

    v2 fields: ``fetched_at`` (ISO UTC; the cache row time on hits), ``request_url``, ``host`` (of the
    final URL), ``source`` (registry source id), ``classification`` (P321, None = usable). ``history``
    lists the URLs that answered with a redirect, in order. Headers are lower-case.
    """

    status: int
    url: str
    headers: dict[str, str]
    content: bytes
    elapsed: float = 0.0
    from_cache: bool = False
    truncated: bool = False
    history: list[str] = field(default_factory=list)
    fetched_at: str = ""
    request_url: str = ""
    host: str = ""
    source: str = ""
    classification: Classification | None = None
    #: cache key of the request (set when the answer was cached or served from the cache).
    cache_key: str = field(default="", init=False, repr=False, compare=False)
    _classified: bool = field(default=False, init=False, repr=False, compare=False)
    #: set by the client for providers flagged sensitive: exceptions never copy the body (A4)
    sensitive: bool = field(default=False, init=False, repr=False, compare=False)
    #: the checked address the connection was pinned to ('' = the transport resolved the name, or a
    #: proxy did; AR02)
    pinned_ip: str = field(default="", init=False, repr=False, compare=False)
    #: bytes written to the request's ``stream_to`` file (-1 = the body was not streamed; then
    #: ``content`` is the whole body, else only its first 64 KB)
    streamed_bytes: int = field(default=-1, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.headers = {str(k).lower(): ("" if v is None else str(v)) for k, v in (self.headers or {}).items()}
        if self.content is None:
            self.content = b""
        elif isinstance(self.content, str):
            self.content = self.content.encode("utf-8")
        if not self.host:
            self.host = _host(self.url)
        if self.history is None:
            self.history = []

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def error_body(self) -> bytes:
        """What an exception may quote of this body (redacted and cut by HttpError): nothing for
        providers flagged sensitive, whose raw answers never leave the client (A4)."""
        return b"" if self.sensitive else self.content

    @property
    def text(self) -> str:
        ctype = self.headers.get("content-type", "")
        charset = "utf-8"
        if "charset=" in ctype:
            charset = ctype.split("charset=", 1)[1].split(";")[0].strip().strip('"') or "utf-8"
        try:
            return self.content.decode(charset, errors="replace")
        except LookupError:
            return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        try:
            return json.loads(self.text)
        except ValueError as exc:
            raise HttpError(f"invalid JSON from {self.url}: {exc}", self.status, self.url, self.error_body) from exc

    def _ensure_classified(self) -> Classification | None:
        if self.classification is None and not self._classified:
            self.classification = classify(self)
            self._classified = True
        return self.classification

    @property
    def blocked(self) -> str | None:
        """Legacy reason string when this is a challenge/block/geo/login-wall page, else None."""
        found = self._ensure_classified()
        return found.reason if found is not None and found.status == "blocked" else None

    def raise_for_status(self) -> Response:
        """Raise by classification first (Blocked / RateLimited / QuotaExceeded / HttpError with its
        reason_code), then by status: 429/430 RateLimited, 401/403 AuthRequired, other non-2xx HttpError."""
        found = self._ensure_classified()
        if found is not None:
            raise _exception_for(found, self)
        host = self.host or _host(self.url)
        if self.status in (429, 430):
            raise RateLimited(f"rate limited by {host}", self.status, self.url, self.error_body)
        if self.status in (401, 403):
            raise AuthRequired(f"HTTP {self.status} from {host}", self.status, self.url, self.error_body)
        if not self.ok:
            raise HttpError(f"HTTP {self.status} from {host}", self.status, self.url, self.error_body)
        return self


@dataclass(frozen=True)
class RequestInfo:
    """Structured record of one network send or cache hit (event ``http_request``, request ledger).

    ``url`` and ``path`` (path + query) are redacted; ``classification`` is the P321 result of that
    answer; ``egress_profile`` names the route ('default' | 'light' | 'active') and ``resolved_ip``
    the checked (pinned) address of a bound target request. The socket connector records every
    connection with method 'CONNECT' (url ``tcp://host:port``) and the external-tool runner every
    launch with method 'EXEC' (url ``exec://<tool>/<target>``), one record per target (WP11).
    """

    ts: str
    method: str
    url: str
    host: str
    path: str
    status: int = 0
    bytes: int = 0
    elapsed: float = 0.0
    cached: bool = False
    error: str = ""
    module: str = ""
    provider: str = ""
    source: str = ""
    opsec: str = "passive"
    egress_profile: str = "default"
    resolved_ip: str = ""
    port: int = 0
    classification: Classification | None = None
    user_agent: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "status": self.status,
            "bytes": self.bytes,
            "elapsed": self.elapsed,
            "cached": self.cached,
            "error": self.error,
            "module": self.module,
            "provider": self.provider,
            "source": self.source,
            "opsec": self.opsec,
            "egress_profile": self.egress_profile,
            "resolved_ip": self.resolved_ip,
            "port": self.port,
            "classification": self.classification.to_dict() if self.classification else None,
            "user_agent": self.user_agent,
        }


def _redacted_path(redacted_url: str) -> str:
    try:
        parts = urlsplit(redacted_url)
    except ValueError:
        return ""
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


# ======================================================================================
# Transport
# ======================================================================================


@runtime_checkable
class Transport(Protocol):
    """Sends ONE hop (no redirect following) and returns its :class:`Response`.

    The body is streamed with the ``max_bytes`` cap (``truncated=True`` when cut) and ``deadline``
    (absolute, on the client clock's monotonic scale, or None) is checked between chunks: a server
    dripping its body past it raises :class:`DeadlineExceeded`. Transport failures raise
    :class:`NetworkError`.
    """

    def send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
        max_bytes: int,
        deadline: float | None,
    ) -> Response: ...


def _short(exc: BaseException) -> str:
    text = redact_text(str(exc))
    return text if len(text) < 160 else text[:157] + "..."


_NON_RETRYABLE = (
    requests.exceptions.InvalidURL,
    requests.exceptions.MissingSchema,
    requests.exceptions.InvalidSchema,
    requests.exceptions.InvalidHeader,
)


class _NoCookies(http.cookiejar.DefaultCookiePolicy):
    """Cookie policy that neither stores nor returns cookies: requests carry no session state."""

    def set_ok(self, cookie: Any, request: Any) -> bool:
        return False

    def return_ok(self, cookie: Any, request: Any) -> bool:
        return False

    def domain_return_ok(self, domain: str, request: Any) -> bool:
        return False

    def path_return_ok(self, path: str, request: Any) -> bool:
        return False


class _NoAuth(requests.auth.AuthBase):
    """Session-level auth that adds nothing: keeps requests from loading ~/.netrc credentials when
    ``trust_env`` is on (no borrowed credentials; explicit headers still work)."""

    def __call__(self, r: Any) -> Any:
        return r


_SOCKS_REPLY_RE = re.compile(r"\b0x0[1-9a-f]\b")


def _proxy_down(exc: BaseException) -> bool:
    """Did a request through a proxy fail because the proxy itself is unreachable (not the target)?

    An HTTP proxy answering CONNECT with an error ('Tunnel connection failed') and a SOCKS proxy
    returning a reply code ('0x05: Connection refused') are reachable: the target failed."""
    text = str(exc).lower()
    if "tunnel connection failed" in text or _SOCKS_REPLY_RE.search(text):
        return False
    if isinstance(exc, requests.exceptions.ProxyError):
        return True
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return True
    return isinstance(exc, requests.exceptions.ConnectionError) and "failed to establish a new connection" in text


class _PinnedAdapter(requests.adapters.HTTPAdapter):
    """Connects to one checked IP while the URL, Host header, SNI and certificate check keep the
    host name (AR02: the address the SSRF guard checked is the address contacted)."""

    def __init__(self, ip: str, **kw: Any) -> None:
        self._pin = ip
        super().__init__(**kw)

    def build_connection_pool_key_attributes(self, request: Any, verify: Any, cert: Any = None) -> tuple[dict[str, Any], dict[str, Any]]:
        host_params, pool_kwargs = super().build_connection_pool_key_attributes(request, verify, cert)
        name = str(host_params.get("host") or "")
        host_params = dict(host_params, host=self._pin)
        if str(host_params.get("scheme") or "").lower() == "https" and name:
            pool_kwargs = dict(pool_kwargs, server_hostname=name)
        return host_params, pool_kwargs


_PINNING_SUPPORTED = hasattr(requests.adapters.HTTPAdapter, "build_connection_pool_key_attributes")


class _CancelWatch:
    """One daemon thread that shuts down the in-flight response bodies of cancelled runs: a body
    read blocked on a slow or silent server stops within ~100 ms of the kill switch instead of at its
    socket timeout (A7/AR05; urllib3 >= 2.3 ``HTTPResponse.shutdown``, a no-op watch otherwise)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[int, tuple[Any, Any]] = {}
        self._thread: threading.Thread | None = None
        self._tick = threading.Event()  # never set: its wait() is the 100 ms tick

    def add(self, response: Any, event: Any) -> int | None:
        if event is None or not callable(getattr(response, "shutdown", None)):
            return None
        key = id(response)
        with self._lock:
            self._items[key] = (response, event)
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, name="v3lum-http-cancel", daemon=True)
                self._thread.start()
        return key

    def remove(self, key: int | None) -> None:
        if key is not None:
            with self._lock:
                self._items.pop(key, None)

    def _run(self) -> None:
        while True:
            self._tick.wait(0.1)
            with self._lock:
                if not self._items:
                    self._thread = None
                    return
                fired = [(k, r) for k, (r, e) in self._items.items() if e.is_set()]
                for key, _response in fired:
                    self._items.pop(key, None)
            for _key, response in fired:
                with contextlib.suppress(Exception):
                    response.shutdown()


_CANCEL_WATCH = _CancelWatch()


class RequestsTransport:
    """Default transport: one ``requests.Session`` per thread, ``allow_redirects=False``, streamed.

    TLS verification is always on: ``verify`` is the configured CA bundle or True, never False (A12).
    Cookies are never stored or replayed and ~/.netrc credentials are never attached (no session
    state or borrowed credentials between requests or modules); ``trust_env`` only brings the
    environment's proxy settings and CA bundle (egress profiles other than the default route use
    ``trust_env=False``: no environment proxies, NO_PROXY bypass or ~/.netrc).

    ``send(..., pin_ip=...)`` connects to that already checked address when the request goes out
    directly (no proxy applies to the URL): Host header, SNI and certificate verification keep the
    host name. Through a proxy the name is sent (the proxy resolves it). ``send(..., stream_to=f)``
    writes the body into the binary file ``f`` instead of memory (the returned ``content`` holds the
    first 64 KB for classification; ``Response.streamed_bytes`` counts what was written).
    """

    def __init__(self, *, proxy: str = "", trust_env: bool = True, ca_bundle: str = "", clock: Clock | None = None, pool_maxsize: int = 16) -> None:
        self.proxy = proxy or ""
        self.trust_env = bool(trust_env)
        self.verify: str | bool = str(ca_bundle) if ca_bundle else True
        self.clock: Clock = clock or SYSTEM_CLOCK
        self.pool_maxsize = int(pool_maxsize)
        self._local = threading.local()

    def _configure(self, sess: requests.Session, *, proxies: bool = True) -> requests.Session:
        sess.trust_env = self.trust_env
        if proxies and self.proxy:
            sess.proxies = {"http": self.proxy, "https": self.proxy}
        sess.cookies.set_policy(_NoCookies())  # type: ignore[arg-type]
        sess.auth = _NoAuth()  # a session auth makes requests skip the ~/.netrc lookup
        return sess

    def session(self) -> requests.Session:
        sess = getattr(self._local, "session", None)
        if sess is None:
            sess = requests.Session()
            adapter = requests.adapters.HTTPAdapter(pool_connections=16, pool_maxsize=self.pool_maxsize, max_retries=0)
            sess.mount("http://", adapter)
            sess.mount("https://", adapter)
            self._configure(sess)
            self._local.session = sess
        return sess

    def direct(self, url: str) -> bool:
        """True when ``url`` would be fetched without any proxy (explicit or from the environment)."""
        if self.proxy:
            return False
        if not self.trust_env:
            return True
        try:
            return not requests.utils.get_environ_proxies(url)
        except Exception:  # noqa: BLE001 - an unreadable environment counts as 'maybe proxied'
            return False

    def _pinned_session(self, ip: str) -> requests.Session:
        sess = requests.Session()
        adapter = _PinnedAdapter(ip, pool_connections=1, pool_maxsize=1, max_retries=0)
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
        self._configure(sess, proxies=False)
        sess.trust_env = False  # the pinned route is direct by construction
        return sess

    def send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None = None,
        timeout: float = 20.0,
        max_bytes: int = DEFAULT_MAX_BYTES,
        deadline: float | None = None,
        pin_ip: str | None = None,
        stream_to: Any = None,
        cancel_event: Any = None,
    ) -> Response:
        clock = self.clock
        host = _host(url)
        if deadline is not None and clock.monotonic() >= deadline:
            raise DeadlineExceeded(f"run deadline reached before contacting {host}")
        start = clock.monotonic()
        session = self.session()
        pinned = ""
        if pin_ip and _PINNING_SUPPORTED and parse_ip(pin_ip) is not None and parse_ip(host) is None and self.direct(url):
            pinned = str(parse_ip(pin_ip))
            session = self._pinned_session(pinned)
            headers = {k: v for k, v in headers.items() if k.lower() != "host"}
            port = urlsplit(url).port
            headers["Host"] = f"{host}:{port}" if port else host
        try:
            try:
                raw = session.request(
                    method,
                    url,
                    headers=headers,
                    data=body,
                    timeout=timeout,
                    allow_redirects=False,
                    stream=True,
                    verify=self.verify,
                )
            except requests.exceptions.RequestException as exc:
                proxied = not pinned and not self.direct(url)
                raise NetworkError(
                    f"{type(exc).__name__} contacting {host}: {_short(exc)}",
                    retryable=not isinstance(exc, _NON_RETRYABLE),
                    kind=type(exc).__name__,
                    reason_code="timeout" if isinstance(exc, requests.exceptions.Timeout) else "",
                    proxy_unreachable=proxied and _proxy_down(exc),
                ) from exc
            except (OSError, ValueError) as exc:  # e.g. an unreadable ca_bundle path: not retried
                raise NetworkError(f"{type(exc).__name__} contacting {host}: {_short(exc)}", retryable=False, kind=type(exc).__name__) from exc
            watch = _CANCEL_WATCH.add(getattr(raw, "raw", None), cancel_event)  # the kill switch also stops a blocked read
            try:
                if stream_to is not None:
                    content, truncated, written = _stream_body(raw, stream_to, max_bytes, deadline, clock, host, cancel_event=cancel_event)
                else:
                    (content, truncated), written = _read_body(raw, max_bytes, deadline, clock, host, cancel_event=cancel_event), -1
            finally:
                _CANCEL_WATCH.remove(watch)
                raw.close()
        finally:
            if pinned:
                session.close()
        resp = Response(raw.status_code, raw.url or url, {k.lower(): v for k, v in raw.headers.items()}, content, clock.monotonic() - start, False, truncated, [])
        resp.pinned_ip = pinned
        resp.streamed_bytes = written
        return resp


def _read_body(raw: requests.Response, max_bytes: int, deadline: float | None, clock: Clock, host: str, *, cancel_event: Any = None) -> tuple[bytes, bool]:
    """Read a streamed body with a size cap, checking the deadline (and the kill switch, when
    given) between received chunks."""
    import urllib3.exceptions

    chunks: list[bytes] = []
    size = 0
    stream = getattr(raw, "raw", None)
    read1 = getattr(stream, "read1", None)
    try:
        if callable(read1):
            while True:
                if deadline is not None and clock.monotonic() > deadline:
                    raise DeadlineExceeded(f"deadline exceeded while reading from {host}")
                if cancel_event is not None and cancel_event.is_set():
                    raise Cancelled(f"cancelled while reading from {host}")
                chunk = read1(65536, decode_content=True)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > max_bytes:
                    return b"".join(chunks)[:max_bytes], True
        else:  # pragma: no cover - urllib3 < 2
            for chunk in raw.iter_content(chunk_size=8192):
                if deadline is not None and clock.monotonic() > deadline:
                    raise DeadlineExceeded(f"deadline exceeded while reading from {host}")
                if not chunk:
                    continue
                chunks.append(chunk)
                size += len(chunk)
                if size > max_bytes:
                    return b"".join(chunks)[:max_bytes], True
    except (DeadlineExceeded, Cancelled):
        raise
    except (requests.exceptions.RequestException, urllib3.exceptions.HTTPError, OSError) as exc:
        if cancel_event is not None and cancel_event.is_set():  # the kill switch shut the read down
            raise Cancelled(f"cancelled while reading from {host}") from None
        timed_out = isinstance(exc, (requests.exceptions.Timeout, urllib3.exceptions.TimeoutError, TimeoutError))
        raise NetworkError(f"{type(exc).__name__} reading from {host}: {_short(exc)}", kind=type(exc).__name__, reason_code="timeout" if timed_out else "") from exc
    if cancel_event is not None and cancel_event.is_set():  # a shut-down read ends like EOF: never a whole body
        raise Cancelled(f"cancelled while reading from {host}")
    if deadline is not None and clock.monotonic() > deadline:
        raise DeadlineExceeded(f"deadline exceeded while reading from {host}")
    return b"".join(chunks), False


def _stream_body(
    raw: requests.Response, sink: Any, max_bytes: int, deadline: float | None, clock: Clock, host: str, *, cancel_event: Any = None
) -> tuple[bytes, bool, int]:
    """Write a streamed body into ``sink`` (at most ``max_bytes``), checking the deadline between
    chunks. Returns (first CLASSIFY_BYTES for classification, truncated, bytes written)."""
    import urllib3.exceptions

    head = bytearray()
    written = 0
    stream = getattr(raw, "raw", None)
    read1 = getattr(stream, "read1", None)

    def chunks() -> Iterable[bytes]:
        if callable(read1):
            while True:
                chunk = read1(65536, decode_content=True)
                if not chunk:
                    return
                yield chunk
        else:  # pragma: no cover - urllib3 < 2
            yield from raw.iter_content(chunk_size=65536)

    try:
        for chunk in chunks():
            if deadline is not None and clock.monotonic() > deadline:
                raise DeadlineExceeded(f"deadline exceeded while reading from {host}")
            if cancel_event is not None and cancel_event.is_set():
                raise Cancelled(f"cancelled while reading from {host}")
            if not chunk:
                continue
            room = max_bytes - written
            part = chunk[:room]
            if part:
                sink.write(part)
                written += len(part)
                if len(head) < CLASSIFY_BYTES:
                    head += part[: CLASSIFY_BYTES - len(head)]
            if len(chunk) > room:
                return bytes(head), True, written
    except (DeadlineExceeded, Cancelled):
        raise
    except (requests.exceptions.RequestException, urllib3.exceptions.HTTPError, OSError) as exc:
        if cancel_event is not None and cancel_event.is_set():  # the kill switch shut the read down
            raise Cancelled(f"cancelled while reading from {host}") from None
        timed_out = isinstance(exc, (requests.exceptions.Timeout, urllib3.exceptions.TimeoutError, TimeoutError))
        raise NetworkError(f"{type(exc).__name__} reading from {host}: {_short(exc)}", kind=type(exc).__name__, reason_code="timeout" if timed_out else "") from exc
    if cancel_event is not None and cancel_event.is_set():  # a shut-down read ends like EOF: never a whole body
        raise Cancelled(f"cancelled while reading from {host}")
    if deadline is not None and clock.monotonic() > deadline:
        raise DeadlineExceeded(f"deadline exceeded while reading from {host}")
    return bytes(head), False, written


def _reset_sink(sink: Any) -> None:
    """Empty a stream_to file before a new attempt or redirect hop (retries never append)."""
    try:
        sink.seek(0)
        sink.truncate()
    except (AttributeError, OSError, ValueError) as exc:
        raise ValueError(f"stream_to must be a seekable binary file opened for writing ({exc})") from None


_KW_SUPPORT: dict[tuple[type, str], bool] = {}
_KW_LOCK = threading.Lock()


def _accepts(obj: Any, name: str, method: str = "send") -> bool:
    """Does ``obj.<method>`` accept keyword ``name`` (directly or through ``**kw``)? Cached per class."""
    key = (type(obj), f"{method}.{name}")
    with _KW_LOCK:
        hit = _KW_SUPPORT.get(key)
    if hit is not None:
        return hit
    fn = getattr(obj, method, None)
    ok = False
    if callable(fn):
        try:
            params = inspect.signature(fn).parameters
        except (TypeError, ValueError):
            params = {}
        ok = name in params or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())
    with _KW_LOCK:
        _KW_SUPPORT[key] = ok
    return ok


# ======================================================================================
# Client
# ======================================================================================

RequestHook = Callable[[str, str, int, float, bool, str], None]
_UA_PLACEHOLDER_RE = re.compile(r"\{([^{}]*)\}")
_UA_SETTINGS = {"contact": "contact_email", "contact_url": "contact_url"}


def _opsec_label(value: Any) -> str:
    """'passive' | 'light' | 'active' from an Opsec enum, int or string."""
    if value is None:
        return "passive"
    label = getattr(value, "label", None)
    if isinstance(label, str):
        return label.lower()
    if isinstance(value, bool):
        return "passive"
    if isinstance(value, int):
        return {0: "passive", 1: "light"}.get(value, "active" if value > 1 else "passive")
    text = str(value).strip().lower()
    if text.startswith("opsec."):
        text = text[6:]
    return text if text in ("passive", "light", "active") else "passive"


def _with_params(url: str, params: Any) -> str:
    if not params:
        return url
    items = params.items() if isinstance(params, Mapping) else params
    clean = [(k, v) for k, v in items if v is not None]
    if not clean:
        return url
    return url + ("&" if "?" in url else "?") + urlencode(clean, doseq=True)


def _encode_body(data: Any, json_body: Any) -> tuple[bytes | None, str]:
    if json_body is not None:
        return json.dumps(json_body, sort_keys=True).encode("utf-8"), "application/json"
    if data is None:
        return None, ""
    if isinstance(data, (bytes, bytearray)):
        return bytes(data), ""
    if isinstance(data, str):
        return data.encode("utf-8"), ""
    if isinstance(data, (Mapping, list, tuple)):
        items = data.items() if isinstance(data, Mapping) else data
        return urlencode(list(items), doseq=True).encode("ascii"), "application/x-www-form-urlencoded"
    return str(data).encode("utf-8"), ""


def _credential_hash(headers: Mapping[str, str], url: str) -> str:
    """SHA-256 over credential-bearing header values and key-like params ('' when none)."""
    parts = [f"{str(k).lower()}:{v}" for k, v in headers.items() if is_credential_header(k, v)]
    try:
        query = urlsplit(url).query
    except ValueError:
        query = ""
    params = {p.lower() for p in KEY_PARAMS}
    parts += [f"param:{k.lower()}={v}" for k, v in parse_qsl(query, keep_blank_values=True) if k.lower() in params and v]
    if not parts:
        return ""
    return hashlib.sha256("\n".join(sorted(parts)).encode("utf-8")).hexdigest()


def _strip_credentials(headers: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in headers.items() if not is_credential_header(k, v)}


_KEY_PARAM_NAMES = frozenset(p.lower() for p in KEY_PARAMS)


def _json_has_key_param(data: Any, depth: int = 0) -> bool:
    if depth > 6:
        return False
    if isinstance(data, dict):
        for k, v in data.items():
            if str(k).lower() in _KEY_PARAM_NAMES and v not in (None, "", [], {}):
                return True
            if _json_has_key_param(v, depth + 1):
                return True
    elif isinstance(data, list):
        return any(_json_has_key_param(v, depth + 1) for v in data[:200])
    return False


def _body_has_credentials(body: bytes | None) -> bool:
    """Does a request body carry a registered secret or a key-like field (form or JSON)?"""
    if not body:
        return False
    text = bytes(body[:CLASSIFY_BYTES]).decode("utf-8", errors="replace")
    if has_secret(text):
        return True
    stripped = text.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            return _json_has_key_param(json.loads(text))
        except ValueError:
            return False
    try:
        pairs = parse_qsl(text, keep_blank_values=False)
    except ValueError:
        return False
    return any(k.lower() in _KEY_PARAM_NAMES and v for k, v in pairs)


def _authority_problem(url: str) -> str:
    """Why the authority of ``url`` is unsafe to send ('' when it is fine).

    Host checks parse URLs with ``urllib.parse`` while the transport (urllib3) has its own parser; a
    backslash, whitespace or control character in the authority, or a percent-encoded host, can make
    them name different hosts (``https://evil.test\\@api.example.test/`` is api.example.test to one
    and evil.test to the other). Such URLs are refused instead of guessing which host is meant.
    """
    rest = url.split("://", 1)[1] if "://" in url else ""
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if "\\" in authority or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in authority):
        return "an ambiguous URL authority (backslash, whitespace or control character)"
    try:
        from urllib3.util import parse_url

        transport_host = parse_url(url).host or ""
        checked_host = urlsplit(url).hostname or ""
    except Exception:  # noqa: BLE001 - any parser failure means the URL is not sent
        return "a URL the transport cannot parse"
    if _norm_pattern(transport_host.strip("[]")) != _norm_pattern(checked_host):
        return "an ambiguous URL host"
    return ""


def _origin(url: str) -> tuple[str, str, int]:
    try:
        parts = urlsplit(url)
    except ValueError:
        return ("", "", 0)
    return (parts.scheme.lower(), (parts.hostname or "").lower(), _port(url))


def _max_signal_seconds() -> float:
    """Longest provider signal honoured (``quota.MAX_SIGNAL_DAYS``; quota.py imports this module,
    so the constant is read lazily)."""
    try:
        from v3lum.core.quota import MAX_SIGNAL_DAYS
    except ImportError:  # pragma: no cover - quota.py ships with the core
        MAX_SIGNAL_DAYS = 32
    return float(MAX_SIGNAL_DAYS) * 86400.0


def _retry_after(value: str | None, clock: Clock) -> float | None:
    if not value:
        return None
    text = str(value).strip()
    try:
        return max(0.0, float(text))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=_dt.timezone.utc)
    return max(0.0, (when - clock.now()).total_seconds())


def _iso(when: _dt.datetime) -> str:
    return when.astimezone(_dt.timezone.utc).isoformat(timespec="milliseconds")


class _KeyedLocks:
    """One lock per cache key while someone holds or waits for it (identical in-flight requests
    collapse into one network call; unrelated keys never wait on each other)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._locks: dict[str, list[Any]] = {}

    @contextlib.contextmanager
    def hold(self, key: str) -> Any:
        with self._lock:
            entry = self._locks.get(key)
            if entry is None:
                entry = self._locks[key] = [threading.Lock(), 0]
            entry[1] += 1
        entry[0].acquire()
        try:
            yield
        finally:
            entry[0].release()
            with self._lock:
                entry[1] -= 1
                if entry[1] <= 0:
                    self._locks.pop(key, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._locks)


class _Req:
    """Per-request state shared by the client's internal steps."""

    __slots__ = (
        "method", "url", "host", "body", "headers", "user_agent", "timeout", "max_bytes", "min_interval", "retries",
        "deadline", "cancel_event", "allow_redirects", "hop_check", "source", "module", "opsec", "priority", "markers",
        "provider_markers", "keyless", "charge_quota", "network_gate", "info_sink", "cache_if", "provider", "key", "ttl",
        "use_cache", "contact", "profile", "stream_to", "ttl_from",
    )

    def __init__(self, **kw: Any) -> None:
        for name in self.__slots__:
            setattr(self, name, kw.get(name))


def _scope_call(scope: Any, name: str, *args: Any) -> bool:
    """A scope predicate (matches_url/matches_host/matches_ip); a scope without it matches nothing."""
    fn = getattr(scope, name, None)
    if not callable(fn):
        return False
    try:
        return bool(fn(*args))
    except (TypeError, ValueError):
        return False


def _scope_allows(scope: Any, host: str, ips: list[str], *, probe: str, url: str | None = None, org: Any = None) -> tuple[bool, str]:
    """``scope.allows_contact(host, ips, probe=...)`` (fail closed when the scope cannot answer)."""
    fn = getattr(scope, "allows_contact", None)
    if not callable(fn):
        return False, f"the scope cannot check contact with {host}"
    kw: dict[str, Any] = {"probe": probe}
    if url is not None and _accepts(scope, "url", "allows_contact"):
        kw["url"] = url
    if org is not None and _accepts(scope, "org", "allows_contact"):
        kw["org"] = org
    try:
        found = fn(host, list(ips), **kw)
    except (TypeError, ValueError) as exc:
        return False, f"the scope could not check contact with {host}: {exc}"
    if isinstance(found, tuple):
        return bool(found[0]), str(found[1] if len(found) > 1 else "")
    return bool(found), "" if found else f"{host} is outside the scope"


def _check_window(scope: Any, clock: Clock, label: str) -> None:
    """Target contact bound to a scope happens only inside its window (A7): before window_start ->
    PolicyError 'scope'; at or after window_end -> Cancelled (the end of the window is a kill
    switch: new target requests are refused). An unreadable window refuses (fail closed)."""
    now = clock.now()
    start = getattr(scope, "window_start", None)
    expired = getattr(scope, "window_expired", None)
    try:
        closed = bool(expired(now)) if callable(expired) else False
        early = start is not None and now < start
    except Exception:  # noqa: BLE001 - a window that cannot be compared never authorizes contact
        closed, early = True, False
    if closed:
        end = getattr(scope, "window_end", None)
        when = f" at {end.isoformat()}" if isinstance(end, _dt.datetime) else ""
        raise Cancelled(f"{label}: the scope window closed{when}: new target requests are refused (A7)")
    if early:
        raise PolicyError("scope", f"{label}: the scope window opens at {start.isoformat()}: no target contact before it (A7)")


def _scope_label(scope: Any) -> str:
    ref = str(getattr(scope, "authorization_ref", "") or "")
    digest = str(getattr(scope, "sha256", "") or "")[:12]
    return ", ".join(p for p in (f"ref {ref}" if ref else "", f"sha256 {digest}" if digest else "") if p) or "scope file"


def _pick_ip(ips: Iterable[str]) -> str:
    """The address to pin: the first IPv4, else the first address."""
    values = [str(i) for i in ips]
    for value in values:
        if ":" not in value:
            return value
    return values[0] if values else ""


def _decision_parts(decision: Any) -> tuple[bool | None, str, str, str]:
    """(allowed, status, reason_code, reason) of a policy Decision-like object, bool or mapping."""
    if decision is None or decision is True:
        return True, "", "", ""
    if decision is False:
        return False, "blocked", "hostile_host", ""
    get = decision.get if isinstance(decision, Mapping) else (lambda k, d=None: getattr(decision, k, d))
    allowed = get("allowed", None)
    status = get("status", "")
    status = str(getattr(status, "value", status) or "").lower()
    return (None if allowed is None else bool(allowed)), status, str(get("reason_code", "") or ""), str(get("reason", "") or "")


class _Contact:
    """Rules of one LIGHT/ACTIVE (target-contact) request (A7, A13, AR02).

    ``bound`` = the request carries a ``scope`` or a ``run`` with its entity (a module run through
    ctx.http): every hop is then resolved through the request's egress profile, every address
    checked and the checked address pinned on the direct route; LIGHT first hops must belong to the
    analyst-typed seed, ACTIVE hops to the scope. Unbound requests (core or test callers, contexts
    built without an entity) get the name and IP-literal checks only. The method rules and the
    ceilings apply to both.
    """

    def __init__(
        self,
        client: HttpClient,
        *,
        opsec: str,
        profile: str,
        scope: Any,
        run: Any,
        guard: Callable[[str], Any] | None,
        module: str,
        deadline: float | None,
        cancel_event: Any,
        info_sink: Callable[[RequestInfo], None] | None = None,
    ) -> None:
        self.client = client
        self.info_sink = info_sink
        self.opsec = opsec
        self.profile = profile
        self.scope = scope
        self.run = run
        self.guard = guard
        self.module = module or "module"
        self.deadline = deadline
        self.cancel_event = cancel_event
        # a run without an entity (a context built outside the engine) binds nothing but its flags
        self.bound = scope is not None or (run is not None and getattr(run, "entity", None) is not None)
        # a module context without an entity and without a scope (a self-test, never a scan run): at
        # ACTIVE it reaches only internal hosts (with internal_seed), never a public target unscoped
        self.seedless = run is not None and getattr(run, "entity", None) is None and scope is None
        self.internal_seed = bool(getattr(run, "internal_seed", False)) if run is not None else False
        self.case_id = str(getattr(run, "case_id", "") or "") if run is not None else ""
        self.seed_hosts = entity_hosts(getattr(run, "entity", None)) if run is not None else ()
        self.tor = bool(client._profile_attr(profile, "tor")) if client is not None else False
        # a SOCKS LIGHT route used for .onion is Tor whatever its port ('detected by .onion use', A13)
        scheme = str(client._profile_attr(profile, "scheme") or "") if client is not None else ""
        self.onion_route = opsec == "light" and profile == "light" and scheme.startswith("socks")

    # ------------------------------------------------------------------ request-level rules
    def request_rules(self, method: str, url: str) -> None:
        """Method allow-list, Tor read-only, ACTIVE needs a scope, then the first-hop static checks."""
        if method not in allowed_methods(self.module, self.opsec):
            extra = "/OPTIONS" if self.opsec == "active" else ""
            raise PolicyError(
                "policy",
                f"{self.module}: {method} is not allowed toward targets in {self.opsec.upper()} mode (GET/HEAD{extra}); "
                f"a state-changing method needs an approved v3lum/data/policy/method_allowlist/{self.module}.json (A7)",
            )
        host = _host(url)
        if (self.tor or host == "onion" or host.endswith(".onion")) and method not in LIGHT_METHODS:
            raise PolicyError("policy", f"{self.module}: the Tor egress profile carries LIGHT reads only (GET/HEAD, A13)")
        if self.opsec == "active" and self.scope is None and (self.bound or (self.seedless and not self.internal_seed)):
            raise PolicyError("scope", f"{self.module}: ACTIVE contact needs a scope file (--scope FILE) bound to --authorized (A7)")
        if self.scope is not None:
            _check_window(self.scope, self.client.clock if self.client is not None else SYSTEM_CLOCK, self.module)
        self.static(url, first=True)

    def credentials(self, headers: Mapping[str, str], url: str, body: bytes | None) -> None:
        """No login attempt, borrowed session or V3LUM key ever goes to a target (A7: no login
        attempts, no use of found credentials or keys): credential headers (Authorization, Cookie,
        X-Api-Key...) and registered secrets in a header, the URL or the body refuse the request.
        The scope's own ROE header (an engagement token agreed with the owner) is exempt."""
        _ua, roe_header = self.roe()
        roe_name = roe_header[0].lower() if roe_header is not None else ""
        found = sorted(k for k, v in headers.items() if k.lower() != roe_name and is_credential_header(k, v))
        if found or has_secret(url) or (body is not None and has_secret(bytes(body[:CLASSIFY_BYTES]).decode("utf-8", errors="replace"))):
            what = f"header {', '.join(found)}" if found else "a configured secret"
            raise PolicyError(
                "policy",
                f"{self.module}: {what} never goes to a target: no login attempts, borrowed sessions or V3LUM keys toward targets (A7)",
            )

    def _name_allowed(self, host: str) -> bool:
        if self.scope is not None:
            return _scope_call(self.scope, "matches_host", host)
        return self.internal_seed

    def check_ip(self, host: str, ip: str) -> None:
        """Refuse an address of a private/loopback/link-local/CGNAT/ULA/multicast/reserved/metadata
        class unless the scope lists it (or, without a scope, the seed is internal; metadata
        endpoints only when the seed is that very address)."""
        problem = ip_problem(ip)
        if not problem:
            return
        if self.scope is not None:
            if _scope_call(self.scope, "matches_ip", ip):
                return
        elif self.internal_seed and (not is_metadata_ip(ip) or host_within(ip, self.seed_hosts)):
            return
        shown = f"{host} ({ip})" if normalize_host(host) != normalize_host(ip) else ip
        raise PolicyError(
            "policy",
            f"{self.module}: refused contact with {shown}: {problem} address (SSRF guard, AR02); internal targets need an "
            "internal analyst-typed seed or a scope that lists them",
        )

    def static(self, url: str, first: bool) -> None:
        """Checks that need no DNS: onion/Tor, internal names, IP literals, scope or seed binding."""
        host = _host(url)
        where = "" if first else " (redirect target)"
        onion = host == "onion" or host.endswith(".onion")
        if onion and not (self.opsec == "light" and (self.tor or self.onion_route)):
            raise PolicyError(
                "policy",
                f"{self.module}: {host}{where}: onion services are reached only for LIGHT reads through a Tor proxy_light "
                "(v3lum config set proxy_light socks5h://127.0.0.1:9050; A13)",
            )
        if self.scope is not None and not _scope_call(self.scope, "matches_url", url):
            # the scope decides first: excluded or unlisted targets are out of scope
            raise PolicyError("scope", f"{self.module}: {host}{where} is outside the scope ({_scope_label(self.scope)}); pivots never inherit scope (A7)")
        if self.seedless and self.opsec == "active" and (onion or not host_problem(host)):
            raise PolicyError(
                "scope",
                f"{self.module}: {host}{where}: an ACTIVE context without an entity or a scope (a self-test) reaches only internal "
                "hosts with RunInfo.internal_seed; ACTIVE contact needs --scope FILE (A7)",
            )
        if not onion:
            problem = host_problem(host)
            if problem:
                if parse_ip(host) is not None:
                    self.check_ip(host, host)
                elif problem.startswith("ambiguous") or not self._name_allowed(host):
                    raise PolicyError(
                        "policy",
                        f"{self.module}: refused contact with {host}{where} ({problem}; SSRF guard, AR02); internal targets need an "
                        "internal analyst-typed seed or a scope that lists them",
                    )
        if self.scope is None and self.bound and first and self.opsec == "light":
            if not bool(getattr(self.run, "is_seed", True)):
                raise PolicyError("scope", f"{self.module}: LIGHT contact runs only on analyst-typed seeds, never on pivots (A7)")
            if self.seed_hosts and not host_within(host, self.seed_hosts):
                raise PolicyError("scope", f"{self.module}: LIGHT request to {host} is outside the seed {', '.join(self.seed_hosts)} (A7)")

    def guard_hop(self, url: str) -> None:
        """Re-run the hostile-host guard (policy.contact_guard) for a redirect target (P376 cond 6)."""
        if self.guard is None:
            return
        host = _host(url)
        try:
            decision = self.guard(url)
        except (PolicyError, Blocked, Cancelled, DeadlineExceeded):
            raise
        except Exception as exc:  # noqa: BLE001 - a broken guard refuses (fail closed)
            raise PolicyError("policy", f"{self.module}: the hostile-host guard failed for redirect target {host}: {_short(exc)} (refused)") from None
        allowed, status, code, reason = _decision_parts(decision)
        if allowed:
            return
        reason = reason or f"{self.module}: redirect target {host} refused by the hostile-host guard (needs non-corporate egress)"
        if status == "skipped" or code in _SKIPPED_CODES:
            raise PolicyError(reason, reason_code=code if code in _SKIPPED_CODES else "policy")
        raise Blocked(reason, 0, url, reason_code=code if code in _BLOCKED_CODES else "hostile_host")

    def hop(self, url: str, first: bool) -> str:
        """Every check before one hop is sent; returns the checked address to pin ('' = none)."""
        host = _host(url)
        self.static(url, first)
        if not first:
            self.guard_hop(url)
        if not self.bound or host == "onion" or host.endswith(".onion"):
            return ""
        literal = parse_ip(host)
        if literal is not None:
            ips = [str(literal)]
        else:
            ips = self.client.resolve_host(
                host, profile=self.profile, deadline=self.deadline, cancel_event=self.cancel_event,
                strict=not self.client._direct_route(self.profile, url), info_sink=self.info_sink,
            )
        if self.scope is not None:
            # the scope decides first (exclusions, targets, unlisted private and CDN addresses)
            ok, why = _scope_allows(self.scope, host, ips, probe="http", url=url)
            if not ok:
                raise PolicyError("scope", f"{self.module}: {why or host + ' is outside the scope'} (A7)")
        for ip in ips:
            self.check_ip(host, ip)
        return _pick_ip(ips)

    # ------------------------------------------------------------------ ceilings
    def charge(self, host: str) -> None:
        self.client.ceilings.charge(self.opsec, host, case_id=self.case_id, scope=self.scope)

    def interval(self) -> float:
        return 1.0 / contact_rps(self.opsec, self.scope)

    def concurrency(self) -> int:
        return contact_concurrency(self.opsec, self.scope)

    # ------------------------------------------------------------------ identity
    def roe(self) -> tuple[str, tuple[str, str] | None]:
        """(ROE User-Agent, ROE header) of the scope for ACTIVE requests ('' / None when absent)."""
        if self.opsec != "active" or self.scope is None:
            return "", None
        roe = getattr(self.scope, "roe", None)
        if roe is None:
            return "", None
        ua = str(getattr(roe, "user_agent", "") or "").strip()
        name = str(getattr(roe, "header_name", "") or "").strip()
        value = str(getattr(roe, "header_value", "") or "").strip()
        return ua, ((name, value) if name and value else None)


class HttpClient:
    """Shared HTTP client (one per Runtime). See the module docstring for the behaviour.

    v1 keyword arguments are kept (``user_agent``, ``timeout``, ``proxy``, ``cache``, ``default_ttl``,
    ``offline``, ``max_per_host``, ``retries``, ``max_bytes``, ``on_request``, ``trust_env``); v2 adds
    ``providers`` (registry; default ``providers.registry()``), ``settings`` (Config or mapping:
    user_agent, contact_email, contact_url, ua_light, ca_bundle, cache_max_age_days, retention_days),
    ``transport`` (default :class:`RequestsTransport`), ``clock`` (default ``SYSTEM_CLOCK``),
    ``limiter`` (:class:`HostLimiter`), ``quota`` (``reserve(provider_id, host, *, priority)`` raising
    QuotaExceeded and ``signal(provider_id, *, kind, until=None)``), ``sanitizer``
    (``callable(source_id, content, content_type) -> bytes | None``; default ``sanitize.sanitize_body``),
    ``on_request_info`` (``callable(RequestInfo)``) and ``cache_key_sink`` (``callable(cache_key)`` for
    every response written to or served from the cache).

    Wave 2 (WP11): ``egress`` (:class:`v3lum.core.net.EgressProfiles`; default built from
    ``settings``: proxy, proxy_light, proxy_active) and ``ceilings`` (:class:`ContactCeilings`). The
    default route keeps ``transport``; the light/active profiles use their own transports.
    :meth:`resolve_host` resolves a target host through a profile (DoH sent through that profile);
    :meth:`request` takes ``scope``, ``run``, ``contact_guard``, ``egress_profile`` (core requests
    only), ``stream_to`` and ``ttl_from``.
    """

    #: ScopedHttp passes its v2 keywords (hop checks, request cap gate, info sink) to this client.
    accepts_scope_kwargs = True

    def __init__(
        self,
        *,
        user_agent: str | None = None,
        timeout: float = 20.0,
        proxy: str = "",
        cache: HttpCache | None = None,
        default_ttl: float = 86400,
        offline: bool = False,
        max_per_host: int = 4,
        retries: int = 2,
        max_bytes: int = DEFAULT_MAX_BYTES,
        on_request: RequestHook | None = None,
        trust_env: bool = True,
        providers: Any = None,
        settings: Any = None,
        transport: Transport | None = None,
        clock: Clock | None = None,
        limiter: HostLimiter | None = None,
        quota: Any = None,
        sanitizer: Callable[[str, bytes, str], bytes | None] | None = None,
        on_request_info: Callable[[RequestInfo], None] | None = None,
        cache_key_sink: Callable[[str], None] | None = None,
        egress: Any = None,
        ceilings: ContactCeilings | None = None,
    ) -> None:
        self.user_agent = user_agent or ""
        self.timeout = float(timeout)
        self.proxy = proxy or ""
        self.cache = cache
        self.default_ttl = float(default_ttl)
        self.offline = bool(offline)
        self.max_per_host = max(1, int(max_per_host or 1))
        self.retries = max(0, int(retries))
        self.max_bytes = int(max_bytes)
        self.on_request = on_request
        self.trust_env = trust_env
        self.settings = settings
        self.clock: Clock = clock or SYSTEM_CLOCK
        self.limiter = limiter or HostLimiter(self.max_per_host, clock=self.clock)
        self.quota = quota
        self.sanitizer = sanitizer
        self.on_request_info = on_request_info
        self.cache_key_sink = cache_key_sink
        self._providers = providers
        self.transport: Transport = transport or RequestsTransport(
            proxy=self.proxy, trust_env=trust_env, ca_bundle=str(self._setting("ca_bundle", "") or ""), clock=self.clock
        )
        self._circuit: dict[str, str] = {}
        self._circuit_lock = threading.Lock()
        self._key_locks = _KeyedLocks()
        if egress is None:
            from v3lum.core.net import EgressProfiles

            egress = EgressProfiles(
                settings, default_transport=self.transport, default_proxy=self.proxy, ca_bundle=str(self._setting("ca_bundle", "") or ""), clock=self.clock
            )
        self.egress = egress
        self.ceilings = ceilings if ceilings is not None else ContactCeilings()
        self._resolvers: dict[str, Any] = {}
        self._resolver_lock = threading.Lock()

    # ------------------------------------------------------------------ settings / registry
    def _setting(self, name: str, default: Any = None) -> Any:
        settings = self.settings
        if settings is None:
            return default
        try:
            getter = getattr(settings, "get", None)
            value = getter(name, default) if callable(getter) else getattr(settings, name, default)
        except Exception:  # a broken settings object must not break requests
            return default
        return default if value is None else value

    def _number(self, name: str, default: float) -> float:
        try:
            return float(self._setting(name, default))
        except (TypeError, ValueError):
            return float(default)

    @property
    def providers(self) -> Any:
        """The provider registry in use (injected, or ``providers.registry()``)."""
        reg = self._providers
        if reg is not None:
            return reg() if callable(reg) and not hasattr(reg, "provider_for_host") else reg
        try:
            from v3lum.core import providers as providers_mod
        except ImportError:  # pragma: no cover - partial checkout
            return None
        try:
            return providers_mod.registry()
        except Exception:  # pragma: no cover - a registry bug must not break requests
            return None

    def provider_for(self, host: str, provider: str = "", source: str = "") -> Any:
        """The registry provider of a request: the owner of ``host`` (a host belongs to exactly one
        provider), else the provider of ``source`` ('pid.sid') or ``provider`` (internal platforms
        reached through hosts_from_settings). None when unknown."""
        reg = self.providers
        if reg is None:
            return None
        try:
            owner = reg.provider_for_host(host) if host else None
            if owner is not None:
                return owner
            if source:
                src = reg.source(source)
                pid = getattr(src, "provider", "") if src is not None else ""
                found = reg.get(pid) if pid else None
                if found is not None:
                    return found
            return reg.get(provider) if provider else None
        except Exception:  # pragma: no cover - registry bugs never break requests
            return None

    def neutral_user_agent(self) -> str:
        """The neutral UA: the constructor value, else setting user_agent, else 'V3LUM/<version>'."""
        return self.user_agent or str(self._setting("user_agent", "") or "") or f"V3LUM/{__version__}"

    # ------------------------------------------------------------------ circuit
    def circuit_hosts(self) -> frozenset[str]:
        """Hosts short-circuited after a challenge or geo-block (in memory, this client's lifetime)."""
        with self._circuit_lock:
            return frozenset(self._circuit)

    def reset_circuit(self) -> None:
        """Forget short-circuited hosts (the engine calls it at the start of each investigation);
        the per-scan LIGHT/ACTIVE ceiling counters start over too (``ContactCeilings.reset_scan``)."""
        with self._circuit_lock:
            self._circuit.clear()
        reset = getattr(self.ceilings, "reset_scan", None)
        if callable(reset):
            reset()

    def _trip(self, hosts: Iterable[str], reason: str) -> None:
        with self._circuit_lock:
            for host in hosts:
                if host:
                    self._circuit.setdefault(host, reason)

    def _circuit_reason(self, host: str) -> str | None:
        with self._circuit_lock:
            return self._circuit.get(host)

    # ------------------------------------------------------------------ cache helpers
    @staticmethod
    def cache_key(method: str, url: str, body: bytes | None = None, *, accept: str = "", credential_hash: str = "") -> str:
        """SHA-256 cache key of a request: method, URL, body, plus the Accept header and a hash of the
        credentials (headers and key-like params) so keyed and keyless answers never mix (P326 cond 10).
        Without accept/credentials the v1 key is unchanged."""
        h = hashlib.sha256()
        h.update(method.upper().encode())
        h.update(b" ")
        h.update(url.encode("utf-8", errors="replace"))
        if body:
            h.update(b"\n")
            h.update(body)
        if accept:
            h.update(b"\naccept:")
            h.update(accept.encode("utf-8", errors="replace"))
        if credential_hash:
            h.update(b"\ncredentials:")
            h.update(credential_hash.encode("ascii", errors="replace"))
        return h.hexdigest()

    def evict(self, resp: Response) -> bool:
        """Delete the cache row of a response (no-op when it was never cached)."""
        key = getattr(resp, "cache_key", "")
        if not key or self.cache is None:
            return False
        try:
            return bool(self.cache.delete(key))
        except Exception:  # pragma: no cover - cache I/O problems must not break modules
            return False


    def _epoch(self) -> float:
        return self.clock.now().timestamp()

    def _sink(self, key: str) -> None:
        if self.cache_key_sink is not None:
            try:
                self.cache_key_sink(key)
            except Exception:  # pragma: no cover - bookkeeping hooks never break requests
                pass

    # ------------------------------------------------------------------ profile application
    def effective_ttl(self, method: str, ttl: float | None, profile: Any = None, *, sensitive: bool = False) -> float:
        """Cache TTL of a request (P326 cond 7, A10): the requested TTL (else the profile TTL, else the
        client default; 0 for non-GET/HEAD unless requested), capped by the profile TTL (a profile
        TTL of 0 means 'never cache this provider'), cache_max_age_days, retention_days and, for
        sensitive providers, 7 days."""
        profile_ttl = getattr(profile, "ttl", None) if profile is not None else None
        if ttl is None:
            if method in ("GET", "HEAD"):
                ttl = profile_ttl if profile_ttl is not None else self.default_ttl
            else:
                ttl = 0
        try:
            value = float(ttl or 0)
        except (TypeError, ValueError):
            value = 0.0
        caps = [value]
        if profile_ttl is not None:
            try:
                caps.append(max(0.0, float(profile_ttl)))
            except (TypeError, ValueError):
                caps.append(0.0)  # an unreadable profile TTL never widens caching
        for name, default in (("cache_max_age_days", 30), ("retention_days", 180)):
            days = self._number(name, default)
            if days > 0:
                caps.append(days * 86400)
        if sensitive:
            caps.append(float(SENSITIVE_MAX_TTL))
        found = min(caps)
        return found if found > 0 else 0.0

    def _render_template(self, template: str, name: str) -> str:
        values = {
            "version": __version__,
            "app": "v3lum",
            "contact": str(self._setting("contact_email", "") or "").strip(),
            "contact_url": str(self._setting("contact_url", "") or "").strip(),
        }

        def sub(match: re.Match[str]) -> str:
            key = match.group(1)
            if key not in values:
                raise ConfigError(f"{name}: user_agent template uses unknown placeholder {{{key}}} (allowed: {{version}}, {{contact}}, {{contact_url}}, {{app}})")
            value = values[key]
            if not value:
                setting = _UA_SETTINGS.get(key, key)
                raise ConfigError(f"{name}: the provider's User-Agent needs setting {setting} (v3lum config set {setting} <value>)")
            return value

        return _UA_PLACEHOLDER_RE.sub(sub, template)

    def _carries_contact(self, ua: str) -> bool:
        """Does ``ua`` carry the organisation's contact (setting contact_email or contact_url)?"""
        lowered = ua.lower()
        for name in ("contact_email", "contact_url"):
            value = str(self._setting(name, "") or "").strip().lower()
            if value and value in lowered:
                return True
        return False

    def _identifying(self, ua: str) -> bool:
        """Does a UA (or ROE header value) name V3LUM anywhere, equal the neutral UA, or carry the
        organisation's contact? Such values never reach a target (P326 cond 5)."""
        lowered = ua.lower()
        if "v3lum" in lowered or ua == self.neutral_user_agent():
            return True
        return self._carries_contact(ua)

    def user_agent_for(self, profile: Any, provider: Any = None, *, opsec: Any = "passive", caller: str | None = None) -> str:
        """User-Agent of a request (P326 cond 3-5): LIGHT/ACTIVE -> setting ua_light (never the
        V3LUM/contact UA); passive -> the caller's UA, else the profile's ('neutral'/None ->
        neutral UA; 'contact' -> 'V3LUM/<version> (+<contact_email>)'; 'browser' -> ua_light; a
        template with {version} {contact} {contact_url} {app}). Raises ConfigError when a needed
        setting is empty. Unknown-tier and unregistered hosts never get the contact UA, not even
        from the caller."""
        light = str(self._setting("ua_light", "") or "") or DEFAULT_UA_LIGHT
        if _opsec_label(opsec) != "passive":
            if caller and not self._identifying(caller):
                return caller
            return light
        if caller:
            if self._carries_contact(caller) and (provider is None or getattr(provider, "tier", "") == "unknown"):
                return self.neutral_user_agent()
            return caller
        spec = getattr(profile, "user_agent", None) if profile is not None else None
        neutral = self.neutral_user_agent()
        if spec in (None, "", "neutral"):
            return neutral
        if spec == "browser":
            return light
        name = str(getattr(provider, "name", "") or getattr(provider, "id", "") or "provider")
        unknown_tier = getattr(provider, "tier", "") == "unknown"
        if spec == "contact":
            if unknown_tier:
                return neutral
            contact = str(self._setting("contact_email", "") or "").strip()
            if not contact:
                raise ConfigError(f"{name}: the provider asks for an identifying User-Agent but setting contact_email is empty (v3lum config set contact_email <role mailbox>)")
            return f"V3LUM/{__version__} (+{contact})"
        template = str(spec)
        if unknown_tier and set(_UA_PLACEHOLDER_RE.findall(template)) & {"contact", "contact_url"}:
            return neutral
        return self._render_template(template, name)

    def _headers(
        self,
        caller: Mapping[str, Any] | None,
        *,
        user_agent: str | None,
        profile: Any,
        provider: Any,
        host: str,
        opsec: str,
        content_type: str,
        fallback: Mapping[str, Any] | None,
        contact: _Contact | None = None,
    ) -> dict[str, str]:
        hdrs: dict[str, str] = {}
        for name, value in (caller or {}).items():
            if value is not None:
                hdrs[str(name)] = str(value)
        header_ua = None
        for name in [k for k in hdrs if k.lower() == "user-agent"]:
            header_ua = hdrs.pop(name)
        caller_ua = user_agent or header_ua
        if contact is not None:
            # LIGHT/ACTIVE never carry the organisation's identity (P326 cond 5, A7): no 'From'
            # header and no header value naming the contact mailbox/URL
            hdrs = {k: v for k, v in hdrs.items() if k.lower() != "from" and not self._carries_contact(v)}
            roe_ua, roe_header = contact.roe()
            if contact.bound:
                caller_ua = roe_ua if roe_ua and not self._identifying(roe_ua) else None
            elif roe_ua and not self._identifying(roe_ua):
                caller_ua = roe_ua
            if roe_header is not None and roe_header[0].lower() not in ROE_FORBIDDEN_HEADERS and not self._identifying(roe_header[1]):
                hdrs = {k: v for k, v in hdrs.items() if k.lower() != roe_header[0].lower()}
                hdrs[roe_header[0]] = roe_header[1]
        ua = self.user_agent_for(profile, provider, opsec=opsec, caller=caller_ua)
        out = {"User-Agent": ua}
        out.update(hdrs)
        lower = {k.lower() for k in out}
        if "accept" not in lower:
            accept = (getattr(profile, "accept", None) if profile is not None else None) or _header(fallback or {}, "accept")
            if accept:
                out["Accept"] = str(accept)
        if "accept-language" not in lower:
            lang = getattr(profile, "accept_language", None) if profile is not None else None
            if not lang and (host == "br" or host.endswith(".br")):
                lang = BR_ACCEPT_LANGUAGE
            if lang:
                out["Accept-Language"] = str(lang)
        if content_type and "content-type" not in lower:
            out["Content-Type"] = content_type
        for name, value in (fallback or {}).items():
            if value is not None and str(name).lower() not in {k.lower() for k in out}:
                out[str(name)] = str(value)
        return out

    # ------------------------------------------------------------------ request
    def request(
        self,
        method: str,
        url: str,
        *,
        params: Any = None,
        headers: Mapping[str, Any] | None = None,
        data: Any = None,
        json_body: Any = None,
        timeout: float | None = None,
        ttl: float | None = None,
        allow_redirects: bool = True,
        max_bytes: int | None = None,
        min_interval: float = 0.0,
        user_agent: str | None = None,
        source: str = "",
        provider: str = "",
        hop_check: Callable[[str], None] | None = None,
        retries: int | None = None,
        deadline: float | None = None,
        cancel_event: Any = None,
        cache_if: Callable[[Response], bool] | None = None,
        module: str = "",
        opsec: Any = "passive",
        priority: str = "seed",
        markers: Iterable[Any] = (),
        keyless: bool = False,
        charge_quota: bool = True,
        network_gate: Callable[[], None] | None = None,
        info_sink: Callable[[RequestInfo], None] | None = None,
        fallback_headers: Mapping[str, Any] | None = None,
        scope: Any = None,
        run: Any = None,
        contact_guard: Callable[[str], Any] | None = None,
        egress_profile: str | None = None,
        stream_to: Any = None,
        ttl_from: Callable[[Response], float | None] | None = None,
    ) -> Response:
        """Send a request (see the module docstring for profiles, redirects, retries, caching).

        Scope keywords (passed by :class:`ScopedHttp`): ``hop_check(url)`` before every hop (PolicyError
        stops), ``network_gate()`` once before the first network send (request caps), ``info_sink``
        (RequestInfo of every send/hit), ``markers``/``keyless`` (classification), ``charge_quota``
        (False for the core DoH scope) and ``fallback_headers`` (used only when neither the caller nor
        the profile sets the header, e.g. get_json's Accept).

        Target contact (``opsec`` LIGHT/ACTIVE, WP11): ``scope`` (a ``v3lum.core.scope.Scope``),
        ``run`` (``RunInfo``: entity, is_seed, internal_seed, case_id) and ``contact_guard``
        (``callable(url)`` returning a policy Decision for redirect targets) bind the request (see
        the module docstring). Core keywords: ``egress_profile`` ('default' | 'light' | 'active')
        sends a core request through that profile (profile resolver, ``net.public_ip``);
        ``stream_to`` (a seekable binary file) receives the body instead of memory and disables
        caching; ``ttl_from(resp) -> seconds | None`` shortens the cache lifetime of an answer from
        its content (e.g. DNS TTLs: a cached answer older than it is a miss; 0 = never stored).
        """
        method = (method or "GET").upper()
        url = _with_params(str(url), params)
        try:
            scheme = urlsplit(url).scheme.lower()
        except ValueError:
            scheme = ""
        if scheme not in ("http", "https"):
            raise PolicyError("policy", f"refused a non-HTTP(S) URL: {redact_url(url)[:120]}")
        host = _host(url)
        if not host:
            raise NetworkError(f"invalid URL (no host): {url}", retryable=False, kind="InvalidURL")
        problem = _authority_problem(url)
        if problem:
            raise PolicyError("policy", f"refused {problem}: {redact_url(url)[:120]}")
        op = _opsec_label(opsec)
        profile_name = self._profile_name(op, egress_profile)
        contact: _Contact | None = None
        if op != "passive":
            contact = _Contact(
                self, opsec=op, profile=profile_name, scope=scope, run=run, guard=contact_guard, module=module,
                deadline=deadline, cancel_event=cancel_event, info_sink=info_sink,
            )
            contact.request_rules(method, url)
        elif host == "onion" or host.endswith(".onion"):
            raise PolicyError("policy", f"refused {host}: onion services are reached only by LIGHT reads through a Tor proxy_light (A13)")
        if profile_name != "default":
            self._ensure_reachable(profile_name)  # a dead LIGHT/ACTIVE proxy refuses (fail closed, A13)
        self._check_live(cancel_event, deadline)
        if hop_check is not None:
            hop_check(url)
        body, content_type = _encode_body(data, json_body)
        prov = self.provider_for(host, provider, source)
        profile = getattr(prov, "http_profile", None) if prov is not None else None
        hdrs = self._headers(
            headers, user_agent=user_agent, profile=profile, provider=prov, host=host, opsec=op, content_type=content_type,
            fallback=fallback_headers, contact=contact,
        )
        if contact is not None:
            contact.credentials(hdrs, url, body)  # no login attempt, session or V3LUM key toward targets (A7)
        sensitive = bool(getattr(getattr(prov, "flags", None), "sensitive", False))
        eff_ttl = self.effective_ttl(method, ttl, profile, sensitive=sensitive)
        accept = _header(hdrs, "accept")
        key = self.cache_key(method, url, body, accept=accept, credential_hash=_credential_hash(hdrs, url))
        profile_timeout = getattr(profile, "timeout", None) if profile is not None else None
        profile_retries = getattr(profile, "retries", None) if profile is not None else None
        profile_max = getattr(profile, "max_bytes", None) if profile is not None else None
        req = _Req(
            method=method,
            url=url,
            host=host,
            body=body,
            headers=hdrs,
            user_agent=hdrs.get("User-Agent", ""),
            timeout=float(timeout if timeout is not None else profile_timeout if profile_timeout is not None else self.timeout),
            max_bytes=int(max_bytes if max_bytes is not None else profile_max if profile_max is not None else self.max_bytes),
            min_interval=float(min_interval or 0.0),
            retries=min(MAX_RETRIES, max(0, int(retries if retries is not None else profile_retries if profile_retries is not None else self.retries))),
            deadline=deadline,
            cancel_event=cancel_event,
            allow_redirects=bool(allow_redirects),
            hop_check=hop_check,
            source=source or "",
            module=module or "",
            opsec=op,
            priority=priority or "seed",
            markers=tuple(markers or ()) + tuple(getattr(prov, "error_markers", ()) or ()),
            provider_markers=tuple(getattr(prov, "error_markers", ()) or ()),
            keyless=bool(keyless),
            charge_quota=bool(charge_quota),
            network_gate=network_gate,
            info_sink=info_sink,
            cache_if=cache_if,
            provider=prov,
            key=key,
            ttl=eff_ttl,
            use_cache=self.cache is not None and eff_ttl > 0 and stream_to is None,
            contact=contact,
            profile=profile_name,
            stream_to=stream_to,
            ttl_from=ttl_from,
        )
        if req.use_cache:
            hit = self._cache_hit(req)
            if hit is not None:
                return hit
        if self.offline:
            raise OfflineError(f"offline mode: {url} not cached")
        if req.use_cache:
            # identical concurrent requests collapse into one network call
            with self._key_locks.hold(key):
                hit = self._cache_hit(req)
                if hit is not None:
                    return hit
                return self._fetch(req)
        return self._fetch(req)

    def _check_live(self, cancel_event: Any, deadline: float | None) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise Cancelled()
        if deadline is not None and self.clock.monotonic() >= deadline:
            raise DeadlineExceeded("run deadline reached: request not sent")

    # ------------------------------------------------------------------ egress profiles (A13)
    def _profile_name(self, opsec: str, explicit: str | None) -> str:
        """The egress profile of a request: an explicit core profile, else by opsec (passive and
        third-party traffic always 'default'; LIGHT/ACTIVE their profile when configured)."""
        egress = self.egress
        if explicit:
            name = str(explicit)
            if name not in ("default", "light", "active"):
                raise PolicyError("policy", f"unknown egress profile {name!r} (default, light or active)")
            effective = getattr(egress, "effective", None)
            return str(effective(name)) if callable(effective) else "default"
        if opsec == "passive":
            return "default"
        chooser = getattr(egress, "profile_for", None)
        return str(chooser(opsec)) if callable(chooser) else "default"

    def _profile_attr(self, name: str, attr: str) -> Any:
        getter = getattr(self.egress, "profile", None)
        if not callable(getter):
            return None
        try:
            return getattr(getter(name), attr, None)
        except (KeyError, ValueError):
            return None

    def _ensure_reachable(self, name: str) -> None:
        check = getattr(self.egress, "ensure_reachable", None)
        if callable(check):
            check(name)

    def _transport_for(self, name: str) -> Any:
        """The transport of an egress profile; a configured but unusable profile refuses (PolicyError)."""
        if name == "default":
            return self.transport
        getter = getattr(self.egress, "transport_for", None)
        if not callable(getter):
            raise PolicyError("policy", f"egress profile {name!r} is not available: request refused (A13)")
        return getter(name)

    def _direct_route(self, profile: str, url: str) -> bool:
        """Would a request on ``profile`` leave without a proxy (so the checked IP can be pinned)?"""
        if profile != "default" or self.proxy:
            return False
        direct = getattr(self.transport, "direct", None)
        if callable(direct):
            try:
                return bool(direct(url))
            except Exception:  # noqa: BLE001 - unknown means 'not pinned': resolution must then be strict
                return False
        return True

    def resolve_host(
        self, host: str, *, profile: str = "default", deadline: float | None = None, cancel_event: Any = None, strict: bool = True,
        info_sink: Callable[[RequestInfo], None] | None = None,
    ) -> list[str]:
        """A and AAAA addresses of a target host resolved through an egress profile: DoH sent through
        that profile (public resolvers only on proxied profiles; never a local getaddrinfo), or the
        ``resolver`` injected into the egress profiles. Raises NetworkError when the name does not
        resolve or the answer could not be verified (``strict``: both lookups must be verified, as on
        proxied routes where the proxy picks the address itself). ``info_sink`` receives the
        RequestInfo of every DoH lookup (the module's disclosure ledger: the resolver saw the name)."""
        name = normalize_host(host)
        literal = parse_ip(name)
        if literal is not None:
            return [str(literal)]
        # an internal name (single label, .corp, .internal...) never goes to a public resolver: it
        # would leak the internal namespace and could not resolve there anyway (A2, AR02)
        internal = bool(host_problem(name))
        if internal and profile != "default":
            raise NetworkError(f"{name} is an internal name: it is not resolved through the {profile} egress profile (request not sent)", retryable=False)
        if profile != "default":
            self._ensure_reachable(profile)  # the profile resolver goes through that proxy
        custom = getattr(self.egress, "resolver", None)
        if callable(custom):
            try:
                found = custom(name, profile)
            except Exception as exc:  # noqa: BLE001 - an injected resolver failure is 'could not verify'
                raise NetworkError(f"could not resolve {name} through the {profile} egress profile: {_short(exc)}", retryable=False) from exc
            ips = [str(parse_ip(v)) for v in (found or ()) if parse_ip(v) is not None]
            if not ips:
                raise NetworkError(f"could not resolve {name} through the {profile} egress profile: no address (request not sent)", retryable=False)
            return ips
        resolver = self._profile_resolver(profile, deadline, cancel_event, internal=internal)
        try:
            answers = [resolver.query(name, rtype) for rtype in ("A", "AAAA")]
        finally:
            if info_sink is not None:
                for info in list(getattr(resolver.http, "request_log", ()) or ()):
                    try:
                        info_sink(info)
                    except Exception:  # pragma: no cover - bookkeeping never breaks a request
                        pass
        ips = [r for a in answers if a.ok for r in a.records if parse_ip(r) is not None]
        unverified = [a for a in answers if a.could_not_verify]
        if unverified and (strict or not ips):
            detail = "; ".join(str(a.error or a.status) for a in unverified)[:200]
            raise NetworkError(f"could not resolve {name} through the {profile} egress profile ({detail}): could not verify, request not sent", retryable=False)
        if not ips:
            if all(a.nxdomain for a in answers):
                raise NetworkError(f"{name} does not resolve (NXDOMAIN through the {profile} egress profile): request not sent", retryable=False)
            raise NetworkError(f"{name} has no A/AAAA records through the {profile} egress profile: request not sent", retryable=False)
        return list(dict.fromkeys(ips))

    def _profile_resolver(self, profile: str, deadline: float | None, cancel_event: Any, *, internal: bool = False) -> Any:
        from v3lum.core.dns import DOH_PROVIDERS, Resolver

        scope = ScopedHttp(
            self, ttl=None, core=True, module="egress_resolver", disclosure="third_party", opsec="passive",
            deadline=deadline, cancel_event=cancel_event, clock=self.clock, egress_profile=profile,
        )
        if profile == "default":
            # internal names: only the organisation's own resolver (setting doh_internal), never a public one
            return Resolver(scope, mode="doh", clock=self.clock, settings=self.settings, allow_public=not internal, allow_public_fallback=not internal)
        configured = self._setting("doh_providers", None)
        names = [configured] if isinstance(configured, str) else list(configured or ())
        public = [str(p).strip().lower() for p in names if str(p).strip().lower() in DOH_PROVIDERS and str(p).strip().lower() != "internal"]
        # through a proxy only public resolvers are reachable: an internal resolver URL never leaves
        return Resolver(scope, mode="doh", providers=public or ["google", "cloudflare"], internal_url="", clock=self.clock)

    def _remaining(self, req: _Req) -> float | None:
        if req.deadline is None:
            return None
        return float(req.deadline) - self.clock.monotonic()

    def _can_wait(self, req: _Req, seconds: float) -> bool:
        if req.cancel_event is not None and req.cancel_event.is_set():
            return False
        remaining = self._remaining(req)
        return remaining is None or seconds < remaining

    def _wait(self, req: _Req, seconds: float) -> None:
        """Sleep before a retry or a politeness slot; on the real clock the run's cancel flag cuts
        the wait short (the kill switch must stop traffic within 2 s, A7/AR05)."""
        if seconds <= 0:
            return
        event = req.cancel_event
        if event is not None and isinstance(self.clock, SystemClock) and callable(getattr(event, "wait", None)):
            event.wait(seconds)
        else:
            self.clock.sleep(seconds)

    def _spend_rate_wait(self, req: _Req, prov: Any, host: str, url: str, wait: Any) -> None:
        """Spend the provider token-bucket wait returned by ``quota.reserve`` (P334 cond 3: requests at
        ``rate_per_second x safety_margin``) on the runtime clock before sending. The longest wait
        accepted is ``max(quota.RATE_WAIT_MAX, one provider interval)``: the provider's own pacing
        (one slot, e.g. 15 s for 4/min at 80%) is always spent when the run deadline allows, and
        ``RATE_WAIT_MAX`` caps only the queueing beyond it. A longer wait, or one the run has no
        time left for, is 'could not verify now' (RateLimited); the kill switch cuts the wait short
        (Cancelled)."""
        try:
            seconds = float(wait or 0.0)
        except (TypeError, ValueError):
            return  # a v1 book (or a fake) returns nothing to wait for
        if seconds != seconds or seconds <= 0:  # NaN or no wait
            return
        try:
            from v3lum.core.quota import RATE_WAIT_MAX
        except ImportError:  # pragma: no cover - quota.py ships with the core
            RATE_WAIT_MAX = 15.0
        limit = float(RATE_WAIT_MAX)
        interval_of = getattr(self.quota, "rate_interval", None)
        if callable(interval_of) and prov is not None:
            try:
                interval = float(interval_of(prov.id) or 0.0)
            except Exception:  # noqa: BLE001 - a broken book keeps the plain cap
                interval = 0.0
            if interval == interval and interval > limit:  # not NaN
                limit = interval * 1.001  # one slot (float slack: 1 / (0.0833 x 0.8) = 15.006 s)
        if seconds > limit or not self._can_wait(req, seconds):
            self._check_live(req.cancel_event, req.deadline)
            raise RateLimited(
                f"{self._name(prov, host)}: provider rate limit ({seconds:.1f} s to the next request slot); could not verify now", 0, url
            )
        self._wait(req, seconds)
        self._check_live(req.cancel_event, req.deadline)

    def _name(self, prov: Any, host: str) -> str:
        return str(getattr(prov, "name", "") or host) if prov is not None else host

    def _markers_for(self, req: _Req, prov: Any) -> tuple[Any, ...]:
        if prov is None or prov is req.provider:
            return req.markers
        return tuple(req.markers) + tuple(getattr(prov, "error_markers", ()) or ())

    def _cache_hit(self, req: _Req) -> Response | None:
        try:
            hit = self.cache.get(req.key, req.ttl, now=self._epoch())  # type: ignore[union-attr]
        except Exception:  # pragma: no cover - a corrupt cache row is a miss
            return None
        if hit is None:
            return None
        if not hit.history or hit.url == redact_url(req.url):
            hit.url = req.url  # stored redacted; without redirects the final URL is the caller's own
        hit.request_url = req.url
        hit.host = _host(hit.url) or req.host
        hit.source = req.source
        hit.sensitive = bool(getattr(getattr(req.provider, "flags", None), "sensitive", False))
        name = self._name(req.provider, req.host)
        found = classify(hit, markers=req.markers, keyless=req.keyless, provider_name=name)
        if found is not None:  # never replay a classified answer (e.g. a challenge cached by v1)
            # the row is dropped only when it is unusable for every caller (generic or provider
            # rules); a module's own markers just make this request a miss
            if req.markers == req.provider_markers or classify(hit, markers=req.provider_markers, provider_name=name) is not None:
                try:
                    self.cache.delete(req.key)  # type: ignore[union-attr]
                except Exception:  # pragma: no cover
                    pass
            return None
        if req.ttl_from is not None and self._expired_by_content(req, hit):
            try:
                self.cache.delete(req.key)  # type: ignore[union-attr]
            except Exception:  # pragma: no cover
                pass
            return None
        for hop_url in [*hit.history[1:], hit.url]:
            if req.hop_check is not None:
                req.hop_check(hop_url)
            if req.contact is not None and hop_url != req.url:
                req.contact.static(hop_url, first=False)  # a replayed redirect target is still judged
        hit.classification = None
        hit._classified = True
        hit.cache_key = req.key
        self._sink(req.key)
        self._record(req, req.method, req.url, status=hit.status, nbytes=len(hit.content), cached=True, prov=req.provider)
        return hit

    def _content_ttl(self, req: _Req, resp: Response) -> float | None:
        """``ttl_from(resp)`` as seconds (None = no opinion; a broken hook counts as 0: never cached)."""
        if req.ttl_from is None:
            return None
        try:
            value = req.ttl_from(resp)
        except Exception:  # noqa: BLE001 - fail closed: an answer whose lifetime is unknown is not kept
            return 0.0
        if value is None:
            return None
        try:
            return max(0.0, float(value))
        except (TypeError, ValueError):
            return 0.0

    def _expired_by_content(self, req: _Req, hit: Response) -> bool:
        limit = self._content_ttl(req, hit)
        if limit is None:
            return False
        try:
            fetched = _dt.datetime.fromisoformat(str(hit.fetched_at).replace("Z", "+00:00"))
        except ValueError:
            return True
        if fetched.tzinfo is None:
            fetched = fetched.replace(tzinfo=_dt.timezone.utc)
        return (self.clock.now() - fetched).total_seconds() > limit

    def _fetch(self, req: _Req) -> Response:
        method, current, body = req.method, req.url, req.body
        headers = dict(req.headers)
        history: list[str] = []
        gated = False
        while True:
            self._check_live(req.cancel_event, req.deadline)
            hop_host = _host(current)
            prov = req.provider if hop_host == req.host else (self.provider_for(hop_host) or None)
            reason = self._circuit_reason(hop_host)
            if reason is not None:
                raise Blocked(f"{self._name(prov, hop_host)}: short-circuited for this run after {reason}", 0, current, reason_code="circuit")
            # target contact: SSRF/scope/seed checks after resolution through the egress profile, the
            # hostile-host guard for redirect targets (AR02, A7, P376); the checked address is pinned
            pin = req.contact.hop(current, first=not history) if req.contact is not None else ""
            if not gated:
                gated = True
                if req.network_gate is not None:
                    req.network_gate()
            if req.charge_quota and self.quota is not None and prov is not None:
                wait = self.quota.reserve(prov.id, hop_host, priority=req.priority)
                self._spend_rate_wait(req, prov, hop_host, current, wait)
            resp, found = self._send(req, method, current, headers, body, prov, history, pin=pin)
            location = resp.headers.get("location", "").strip()
            if not (req.allow_redirects and resp.status in REDIRECT_STATUS and location and found is None):
                break
            if len(history) >= MAX_REDIRECTS:
                raise HttpError(f"too many redirects (more than {MAX_REDIRECTS}) from {req.url}", resp.status, current)
            try:
                nxt = urljoin(current, location)
                nxt_scheme = urlsplit(nxt).scheme.lower()
            except ValueError:
                raise PolicyError("policy", f"refused an unparsable redirect target from {redact_url(current)[:120]}") from None
            if nxt_scheme not in ("http", "https"):
                raise PolicyError("policy", f"refused a redirect to a non-HTTP(S) URL from {redact_url(current)[:120]}")
            if urlsplit(current).scheme.lower() == "https" and nxt_scheme == "http":
                raise PolicyError("policy", f"refused an https->http redirect downgrade to {redact_url(nxt)[:120]}")
            problem = _authority_problem(nxt)
            if problem:
                raise PolicyError("policy", f"refused a redirect to {problem}: {redact_url(nxt)[:120]}")
            if req.hop_check is not None:
                req.hop_check(nxt)
            new_method, new_body = method, body
            if (resp.status == 303 and method != "HEAD") or (resp.status in (301, 302) and method == "POST"):
                new_method, new_body = "GET", None
            if _origin(nxt) != _origin(current):
                headers = _strip_credentials(headers)
                if _body_has_credentials(new_body):  # a 307/308 would re-send it to the new origin
                    raise PolicyError("policy", f"refused to re-send a credential-bearing request body to another origin ({_host(nxt) or '?'})")
            if new_method != method:
                headers = {k: v for k, v in headers.items() if k.lower() not in ("content-type", "content-length")}
            method, body = new_method, new_body
            history.append(current)
            current = nxt
        return self._finish(req, resp, history)

    def _send(
        self, req: _Req, method: str, url: str, headers: dict[str, str], body: bytes | None, prov: Any, history: list[str], *, pin: str = ""
    ) -> tuple[Response, Classification | None]:
        """One hop with retries (5xx/connection errors with backoff, one 429 with a short Retry-After)."""
        host = _host(url)
        profile = getattr(prov, "http_profile", None) if prov is not None else None
        interval = max(req.min_interval, float(getattr(profile, "min_interval", 0.0) or 0.0))
        concurrency = int(getattr(profile, "concurrency", 0) or 0) or self.max_per_host
        contact = req.contact
        contact_slots = 0
        if contact is not None:
            interval = max(interval, contact.interval())  # LIGHT <= 1 req/s, ACTIVE <= 10 req/s (A7)
            contact_slots = contact.concurrency()
        transport = self._transport_for(req.profile or "default")
        extra: dict[str, Any] = {}
        if pin and _accepts(transport, "pin_ip") and self._direct_route(req.profile or "default", url):
            extra["pin_ip"] = pin  # the direct route connects to the checked address; a proxy gets the name
        if req.stream_to is not None and _accepts(transport, "stream_to"):
            extra["stream_to"] = req.stream_to
        if req.cancel_event is not None and _accepts(transport, "cancel_event"):
            extra["cancel_event"] = req.cancel_event  # the kill switch also stops a body being read
        markers = self._markers_for(req, prov)
        name = self._name(prov, host)
        attempt = 0
        retried_429 = False
        while True:
            self._check_live(req.cancel_event, req.deadline)
            delay = self.limiter.reserve(host, interval)
            if delay > 0:
                if not self._can_wait(req, delay):
                    self._check_live(req.cancel_event, req.deadline)
                    raise DeadlineExceeded(f"run deadline reached while waiting for {host} (politeness interval)")
                self._wait(req, delay)
                self._check_live(req.cancel_event, req.deadline)
            if contact is not None:
                contact.charge(host)  # LIGHT 25 per host per scan, the ACTIVE case budget (A7)
            if req.stream_to is not None:
                _reset_sink(req.stream_to)
            remaining = self._remaining(req)
            timeout = req.timeout if remaining is None else max(0.001, min(req.timeout, remaining))
            start = self.clock.monotonic()
            contact_slot = (
                self.limiter.acquire(f"contact:{contact_slots}:{host}", contact_slots, timeout=remaining) if contact_slots else contextlib.nullcontext()
            )
            try:
                with self.limiter.acquire(host, concurrency, timeout=remaining), contact_slot:
                    resp = transport.send(method, url, headers=dict(headers), body=body, timeout=timeout, max_bytes=req.max_bytes, deadline=req.deadline, **extra)
            except TimeoutError:
                raise DeadlineExceeded(f"run deadline reached while waiting for a connection slot to {host}") from None
            except DeadlineExceeded as exc:
                self._record(req, method, url, elapsed=self.clock.monotonic() - start, error=exc.kind, prov=prov, resolved_ip=pin)
                raise
            except Cancelled:  # the kill switch stopped a body being read: the send still reaches the ledger
                self._record(req, method, url, elapsed=self.clock.monotonic() - start, error="Cancelled", prov=prov, resolved_ip=pin)
                raise
            except NetworkError as exc:
                self._record(req, method, url, elapsed=self.clock.monotonic() - start, error=exc.kind, prov=prov, resolved_ip=pin)
                if req.profile not in (None, "", "default") and exc.proxy_unreachable:
                    # fail closed (A13): never resent on the default route, never retried
                    setting = f"proxy_{req.profile}"
                    raise PolicyError("policy", f"{setting} unreachable: request refused (never sent through the default route)") from None
                backoff = min(4.0, 0.5 * (2**attempt))
                if attempt < req.retries and exc.retryable and self._can_wait(req, backoff):
                    self._wait(req, backoff)
                    attempt += 1
                    continue
                raise
            if req.stream_to is not None and resp.streamed_bytes < 0:
                # a transport without streaming: the body goes to the file here, memory keeps the head
                req.stream_to.write(resp.content)
                resp.streamed_bytes = len(resp.content)
                resp.content = bytes(resp.content[:CLASSIFY_BYTES])
            elapsed = max(self.clock.monotonic() - start, float(resp.elapsed or 0.0))
            resp.elapsed = elapsed
            resp.request_url = url
            resp.history = list(history)
            found = classify(resp, markers=markers, keyless=req.keyless, provider_name=name)
            nbytes = resp.streamed_bytes if resp.streamed_bytes >= 0 else len(resp.content)
            self._record(req, method, url, status=resp.status, nbytes=nbytes, elapsed=elapsed, cls=found, prov=prov, resolved_ip=pin)
            if resp.status in RETRY_STATUS and found is None and attempt < req.retries:
                backoff = min(4.0, 0.5 * (2**attempt))
                if self._can_wait(req, backoff):
                    self._wait(req, backoff)
                    attempt += 1
                    continue
            if resp.status == 429 and found is not None and found.status == "rate_limited" and not retried_429 and attempt < req.retries:
                wait = _retry_after(resp.headers.get("retry-after"), self.clock)
                if wait is not None and wait <= RETRY_AFTER_MAX and self._can_wait(req, wait):
                    self._wait(req, wait)
                    attempt += 1
                    retried_429 = True
                    continue
            return resp, found

    def _finish(self, req: _Req, resp: Response, history: list[str]) -> Response:
        resp.history = list(history)
        resp.request_url = req.url
        resp.host = _host(resp.url) or req.host
        resp.source = req.source
        resp.fetched_at = _iso(self.clock.now())
        final_prov = req.provider if resp.host == req.host else (self.provider_for(resp.host) or req.provider)
        found = classify(resp, markers=self._markers_for(req, final_prov), keyless=req.keyless, provider_name=self._name(final_prov, resp.host))
        resp.classification = found
        resp._classified = True
        if found is not None:
            self._on_classified(found, resp, req, final_prov)
        no_store = False
        sensitive_owners = [p for p in (req.provider, final_prov) if p is not None and bool(getattr(getattr(p, "flags", None), "sensitive", False))]
        sensitive = bool(sensitive_owners)
        resp.sensitive = sensitive
        if sensitive:
            # only a schema of the sensitive provider's own sources may decide what of its body is kept:
            # a source of another provider (a module mistake, a redirect) means no-store (fail closed)
            owner_ids = {str(getattr(p, "id", "") or "") for p in sensitive_owners}
            own_source = str(req.source or "").split(".", 1)[0] in owner_ids
            cleaned = self._sanitize(req.source, resp) if own_source else None
            if cleaned is None:
                no_store = True  # no schema / not JSON: the module gets the raw body in memory only
            else:
                resp.content = cleaned
        content_ttl = self._content_ttl(req, resp) if req.use_cache else None
        if content_ttl is not None and content_ttl <= 0:
            no_store = True  # ttl_from: this answer must not outlive the request (e.g. DNS TTL 0)
        if req.use_cache and not no_store and found is None and not resp.truncated and resp.status in CACHEABLE_STATUS and self._cache_allowed(req, resp):
            try:
                stored = self.cache.put(req.key, resp, now=self._epoch())  # type: ignore[union-attr]
            except Exception:  # pragma: no cover - cache I/O problems must not lose the answer
                stored = False
            if stored:
                resp.cache_key = req.key
                self._sink(req.key)
        return resp

    @staticmethod
    def _cache_allowed(req: _Req, resp: Response) -> bool:
        """The module's cache_if veto; a veto that raises counts as 'do not cache' (fail closed)."""
        if req.cache_if is None:
            return True
        try:
            return bool(req.cache_if(resp))
        except Exception:  # noqa: BLE001 - a broken veto must not lose the answer or cache it
            return False

    def _on_classified(self, found: Classification, resp: Response, req: _Req, prov: Any) -> None:
        # a bare keyless 403 is 'could not verify' for that request only: it may be one endpoint
        # refusing keyless calls, so it never short-circuits the host for keyed callers
        if found.status == "blocked" and found.reason_code in _CIRCUIT_CODES and found.marker_id not in _NO_CIRCUIT_MARKERS:
            label = "a geo-block" if found.reason_code == "geo_block" else "an anti-bot challenge"
            # only the host that served the page: a redirector in front of it (URL shortener,
            # tracking link) keeps working for its other targets
            self._trip({resp.host or req.host}, label)
        if found.status in ("quota", "rate_limited") and self.quota is not None and prov is not None:
            signal = getattr(self.quota, "signal", None)
            if callable(signal):
                try:
                    until = None
                    wait = _retry_after(resp.headers.get("retry-after"), self.clock)
                    if wait is not None:
                        # a hostile or broken Retry-After ('99999999999999', 'inf') is capped like the
                        # quota book caps every signal (MAX_SIGNAL_DAYS), never an OverflowError
                        until = self.clock.now() + _dt.timedelta(seconds=min(wait, _max_signal_seconds()))
                    signal(prov.id, kind=found.status, until=until)
                except Exception:  # pragma: no cover - quota bookkeeping never breaks requests
                    pass

    def _sanitize(self, source: str, resp: Response) -> bytes | None:
        fn = self.sanitizer
        if fn is None:
            try:
                from v3lum.core import sanitize as sanitize_mod

                fn = getattr(sanitize_mod, "sanitize_body", None)
            except ImportError:
                fn = None
        if fn is None:
            return None
        try:
            out = fn(source, resp.content, resp.headers.get("content-type", ""))
        except Exception:  # fail closed: nothing raw is stored
            return None
        if isinstance(out, str):
            return out.encode("utf-8")
        return bytes(out) if isinstance(out, (bytes, bytearray)) else None

    # ------------------------------------------------------------------ events
    def _record(
        self,
        req: _Req,
        method: str,
        url: str,
        *,
        status: int = 0,
        nbytes: int = 0,
        elapsed: float = 0.0,
        cached: bool = False,
        error: str = "",
        cls: Classification | None = None,
        prov: Any = None,
        resolved_ip: str = "",
    ) -> None:
        red = redact_url(url)
        if self.on_request is not None:
            try:
                self.on_request(method, red, status, elapsed, cached, error)
            except Exception:  # pragma: no cover - UI hooks must never break requests
                pass
        if self.on_request_info is None and req.info_sink is None:
            return
        info = RequestInfo(
            ts=_iso(self.clock.now()),
            method=method,
            url=red,
            host=_host(url),
            path=_redacted_path(red),
            status=int(status or 0),
            bytes=int(nbytes or 0),
            elapsed=round(float(elapsed or 0.0), 6),
            cached=cached,
            error=error,
            module=req.module or "",
            provider=str(getattr(prov, "id", "") or ""),
            source=req.source or "",
            opsec=req.opsec or "passive",
            egress_profile=str(req.profile or "default"),
            resolved_ip=str(resolved_ip or ""),
            port=_port(url),
            classification=cls,
            user_agent=req.user_agent or "",
        )
        for fn in (self.on_request_info, req.info_sink):
            if fn is not None:
                try:
                    fn(info)
                except Exception:  # pragma: no cover - observers never break requests
                    pass


# ======================================================================================
# Scoped facade (ctx.http)
# ======================================================================================

def _norm_pattern(pattern: Any) -> str:
    text = str(pattern or "").strip().lower().rstrip(".")
    try:
        if text and not text.isascii():
            text = text.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return text


def _earliest(*deadlines: Any) -> float | None:
    """The earliest of the given deadlines (None entries ignored; None when all are None)."""
    values = []
    for value in deadlines:
        if value is None:
            continue
        try:
            values.append(float(value))
        except (TypeError, ValueError):
            continue
    return min(values) if values else None


def host_allowed(host: str, patterns: Iterable[str]) -> bool:
    """Does ``host`` match a declared pattern: exact, or '*.suffix' for strict subdomains?"""
    host = _norm_pattern(host)
    if not host:
        return False
    for pattern in patterns:
        pat = _norm_pattern(pattern)
        if not pat:
            continue
        if pat.startswith("*."):
            if host.endswith(pat[1:]) and host != pat[2:]:
                return True
        elif host == pat:
            return True
    return False


class ScopedHttp:
    """Per-module-run facade over the shared client (``ctx.http``): module defaults, host
    enforcement, request cap, deadline/cancel, classification helpers and counters.

    Works over any client exposing ``request(method, url, **kw)`` (e.g. ``ScopedHttp(FakeHttp())``);
    over :class:`HttpClient` it also passes hop checks for redirects, the request-cap gate (cache hits
    are free), error markers and the keyless flag (classification before caching) and collects the
    :class:`RequestInfo` of every send in ``request_log``.

    Enforcement (P327 cond 4-5, A8 BR9, AR05): cancel -> Cancelled; past the deadline ->
    DeadlineExceeded; more than ``max_requests`` network sends -> RequestCapReached; disclosure 'none'
    -> PolicyError (no network); disclosure 'third_party'/'internal' with ``allowed_hosts`` -> the
    URL host (and every redirect hop) must match them (exact or '*.suffix') else PolicyError;
    disclosure 'target' (LIGHT/ACTIVE) requests follow the target-contact rules of :class:`HttpClient`
    (egress profile, SSRF guard, method rules, ceilings; with ``run``/``scope`` the hop-by-hop
    resolution, pinning, seed and scope binding, and ``contact_guard`` for redirect targets).
    ``core=True`` (the core DoH scope): not counted against ``max_requests`` or quotas and no module
    UA/min_interval; only core scopes may name an ``egress_profile``. The scope's metadata wins over
    per-call keywords: opsec, module name, priority, quota charging, the cancel event and the
    run/scope/contact-guard binding are the scope's, a per-call deadline can only be earlier and a
    per-call min_interval only longer.

    Counters: ``requests`` (network request calls), ``cache_hits``, ``hosts`` (host -> network sends),
    ``bytes`` (network body bytes), ``request_log`` (RequestInfo of this scope; the socket connector
    bound to this scope adds its CONNECT and EXEC records).
    """

    def __init__(
        self,
        client: Any,
        ttl: float | None = None,
        min_interval: float = 0.0,
        user_agent: str | None = None,
        *,
        module: str = "",
        provider: str = "",
        sources: Iterable[str] = (),
        allowed_hosts: Iterable[str] | None = None,
        disclosure: str = "third_party",
        opsec: Any = "passive",
        max_requests: int | None = None,
        absent_statuses: Iterable[int] = frozenset(),
        error_markers: Iterable[Any] = (),
        keyless: bool = False,
        deadline: float | None = None,
        cancel_event: Any = None,
        clock: Clock | None = None,
        core: bool = False,
        priority: str = "seed",
        run: Any = None,
        scope: Any = None,
        contact_guard: Callable[[str], Any] | None = None,
        egress_profile: str | None = None,
    ) -> None:
        self._client = client
        self._v2 = bool(getattr(client, "accepts_scope_kwargs", False))
        self._ttl = ttl
        self._min_interval = float(min_interval or 0.0)
        self._ua = user_agent
        self.module = module or ""
        self.provider = provider or ""
        self.sources = tuple(sources or ())
        self.allowed_hosts = None if allowed_hosts is None else tuple(_norm_pattern(h) for h in allowed_hosts)
        self.disclosure = str(disclosure or "third_party")
        self.opsec = _opsec_label(opsec)
        self.max_requests = None if max_requests is None else int(max_requests)
        self.absent_statuses = frozenset(int(s) for s in (absent_statuses or ()))
        self.error_markers = tuple(error_markers or ())
        self.keyless = bool(keyless)
        self.deadline = deadline
        self.cancel_event = cancel_event
        self.clock: Clock = clock or getattr(client, "clock", None) or SYSTEM_CLOCK
        self.core = bool(core)
        self.priority = priority or "seed"
        #: the run facts (RunInfo) and the loaded scope binding LIGHT/ACTIVE requests (WP11)
        self.run = run
        self.scope = scope
        self.contact_guard = contact_guard
        self.egress_profile = str(egress_profile) if (egress_profile and self.core) else None
        self._lock = threading.Lock()
        self.requests = 0
        self.cache_hits = 0
        self.hosts: dict[str, int] = {}
        self.bytes = 0
        self.request_log: list[RequestInfo] = []

    @property
    def client(self) -> Any:
        """The underlying client."""
        return self._client

    # ------------------------------------------------------------------ enforcement
    def _label(self) -> str:
        return self.module or "module"

    def _check_live(self) -> None:
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise Cancelled()
        if self.deadline is not None and self.clock.monotonic() >= self.deadline:
            raise DeadlineExceeded(f"{self._label()}: run deadline reached: request not sent")

    def check_host(self, url: str) -> None:
        """Raise PolicyError when this scope may not contact the host of ``url`` (also used per hop)."""
        if self.disclosure == "none":
            raise PolicyError("policy", f"{self._label()}: offline module (disclosure 'none'): no network")
        if self.allowed_hosts is None or self.disclosure == "target":
            return
        host = _host(url)
        if not host_allowed(host, self.allowed_hosts):
            raise PolicyError("policy", f"{self._label()}: host {host or '?'} is not declared in Module.hosts (passive modules reach only their declared hosts)")

    def _hop_checker(self, extra: Callable[[str], None] | None) -> Callable[[str], None]:
        def check(url: str) -> None:
            self.check_host(url)
            if extra is not None:
                extra(url)

        return check

    def _gate(self) -> None:
        with self._lock:
            if self.max_requests is not None and not self.core and self.requests >= self.max_requests:
                raise RequestCapReached(f"{self._label()}: max_requests ({self.max_requests}) reached for this entity")
            self.requests += 1

    def _absorb(self, infos: Iterable[RequestInfo]) -> None:
        with self._lock:
            for info in infos:
                self.request_log.append(info)
                if not info.cached:
                    self.hosts[info.host] = self.hosts.get(info.host, 0) + 1
                    self.bytes += int(info.bytes or 0)

    def _default_source(self, url: str) -> str:
        if len(self.sources) == 1:
            return self.sources[0]
        if not self.sources or not self._v2:
            return ""
        finder = getattr(self._client, "provider_for", None)
        prov = finder(_host(url)) if callable(finder) else None
        pid = getattr(prov, "id", "") if prov is not None else ""
        candidates = [s for s in self.sources if pid and s.split(".", 1)[0] == pid]
        return candidates[0] if len(candidates) == 1 else ""

    # ------------------------------------------------------------------ requests
    def request(self, method: str, url: str, **kw: Any) -> Response:
        """Send through the client with this scope's defaults and enforcement (see the class doc)."""
        method = (method or "GET").upper()
        self._check_live()
        self.check_host(url)
        kw = dict(kw)
        # the binding is the scope's: a module never passes its own run, scope, guard or route
        for name in ("run", "scope", "contact_guard", "egress_profile"):
            kw.pop(name, None)
        if not self.core:
            kw.pop("stream_to", None)  # streaming to a file is a core facility (datasets)
        kw.setdefault("ttl", self._ttl if method in ("GET", "HEAD") else None)
        if not self.core:
            try:
                asked = float(kw.get("min_interval") or 0.0)
            except (TypeError, ValueError):
                asked = 0.0
            kw["min_interval"] = max(self._min_interval, asked)  # a call never lowers the declared politeness
            if self._ua and "user_agent" not in kw:
                kw["user_agent"] = self._ua
        if self._v2:
            return self._request_v2(method, url, kw)
        return self._request_legacy(method, url, kw)

    def _request_v2(self, method: str, url: str, kw: dict[str, Any]) -> Response:
        # The scope's metadata wins over per-call keywords: a module cannot change its opsec (UA,
        # egress), name, quota priority or charging, extend its deadline or opt out of the kill switch.
        if not kw.get("source"):
            kw["source"] = self._default_source(url)
        if not kw.get("provider"):
            kw["provider"] = self.provider
        kw["module"] = self.module or str(kw.get("module") or "")
        kw["opsec"] = self.opsec
        kw["priority"] = self.priority
        kw["deadline"] = _earliest(self.deadline, kw.get("deadline"))
        if self.cancel_event is not None:
            kw["cancel_event"] = self.cancel_event
        kw["markers"] = tuple(self.error_markers) + tuple(kw.get("markers") or ())
        kw["keyless"] = self.keyless or bool(kw.get("keyless", False))
        kw["charge_quota"] = not self.core
        kw["hop_check"] = self._hop_checker(kw.get("hop_check"))
        if self.opsec != "passive" and not self.core:
            kw["run"] = self.run
            kw["scope"] = self.scope
            kw["contact_guard"] = self.contact_guard
        if self.egress_profile:
            kw["egress_profile"] = self.egress_profile
        infos: list[RequestInfo] = []
        kw["info_sink"] = infos.append
        kw["network_gate"] = self._gate
        try:
            resp = self._client.request(method, url, **kw)
        finally:
            self._absorb(infos)
        if resp.from_cache:
            with self._lock:
                self.cache_hits += 1
        return resp

    def _legacy_contact(self) -> _Contact | None:
        if self.opsec == "passive" or self.core:
            return None
        return _Contact(
            None, opsec=self.opsec, profile="default", scope=self.scope, run=self.run, guard=None, module=self.module,  # type: ignore[arg-type]
            deadline=self.deadline, cancel_event=self.cancel_event,
        )

    def _request_legacy(self, method: str, url: str, kw: dict[str, Any]) -> Response:
        with self._lock:
            if self.max_requests is not None and not self.core and self.requests >= self.max_requests:
                raise RequestCapReached(f"{self._label()}: max_requests ({self.max_requests}) reached for this entity")
        contact = self._legacy_contact()
        if contact is not None:
            # a legacy client cannot resolve or pin: the name/literal, method, seed and scope rules
            contact.request_rules(method, url)
            contact.credentials({str(k): str(v) for k, v in (kw.get("headers") or {}).items()}, _with_params(url, kw.get("params")), None)
        start = self.clock.monotonic()
        host = _host(url)
        try:
            resp = self._client.request(method, url, **kw)
        except Exception as exc:
            info = RequestInfo(
                ts=_iso(self.clock.now()), method=method, url=redact_url(url), host=host, path=_redacted_path(redact_url(url)),
                error=getattr(exc, "kind", "") or type(exc).__name__, module=self.module, provider=self.provider, opsec=self.opsec, port=_port(url),
                elapsed=round(self.clock.monotonic() - start, 6),
            )
            with self._lock:
                self.requests += 1
            self._absorb([info])
            raise
        if not resp.request_url:
            resp.request_url = _with_params(url, kw.get("params"))
        red = redact_url(resp.url or url)
        info = RequestInfo(
            ts=_iso(self.clock.now()), method=method, url=red, host=_host(resp.url) or host, path=_redacted_path(red), status=int(resp.status),
            bytes=len(resp.content), elapsed=round(float(resp.elapsed or 0.0), 6), cached=bool(resp.from_cache), module=self.module,
            provider=self.provider, source=str(kw.get("source") or ""), opsec=self.opsec, port=_port(resp.url or url),
        )
        with self._lock:
            if resp.from_cache:
                self.cache_hits += 1
            else:
                self.requests += 1
        self._absorb([info])
        # a legacy client follows redirects itself: the module still never gets an answer from an
        # undeclared host (checked after the fact; the v2 client checks before every hop)
        for hop in [*(resp.history or [])[1:], resp.url]:
            if hop:
                self.check_host(hop)
                if contact is not None and hop != url:
                    contact.static(hop, first=False)
        return resp

    def get(self, url: str, **kw: Any) -> Response:
        """GET (``params``, ``headers``, ``timeout``, ``ttl``, ``allow_redirects``, ``max_bytes``,
        ``source``, ``cache_if``, ``retries``, ...)."""
        return self.request("GET", url, **kw)

    def head(self, url: str, **kw: Any) -> Response:
        return self.request("HEAD", url, **kw)

    def post(self, url: str, **kw: Any) -> Response:
        """POST (``data`` or ``json_body``); not cached unless ``ttl`` is given."""
        return self.request("POST", url, **kw)

    # ------------------------------------------------------------------ helpers for modules
    def _provider_of(self, resp: Response) -> Any:
        finder = getattr(self._client, "provider_for", None)
        if callable(finder):
            return finder(resp.host or _host(resp.url), self.provider, resp.source)
        try:
            from v3lum.core import providers as providers_mod

            return providers_mod.registry().provider_for_host(resp.host or _host(resp.url))
        except Exception:
            return None

    def _classify(self, resp: Response) -> Classification | None:
        if resp.classification is None:
            prov = self._provider_of(resp)
            markers = tuple(self.error_markers) + tuple(getattr(prov, "error_markers", ()) or ())
            name = str(getattr(prov, "name", "") or "") if prov is not None else ""
            resp.classification = classify(resp, markers=markers, keyless=self.keyless, provider_name=name)
        resp._classified = True
        return resp.classification

    def check(self, resp: Response) -> Response:
        """Classify ``resp`` with this scope's error markers and keyless flag, then raise_for_status().
        Call it when parsing HTML/text yourself. Returns ``resp``."""
        self._classify(resp)
        return resp.raise_for_status()

    def evict(self, resp: Response) -> bool:
        """Delete the cache row of ``resp`` (a cached answer the module judged unusable)."""
        evict = getattr(self._client, "evict", None)
        return bool(evict(resp)) if callable(evict) else False

    def _json(self, method: str, url: str, absent: Any, ok404: bool, kw: dict[str, Any]) -> Any:
        if isinstance(absent, int):
            absent = (absent,)
        absent_set = set(self.absent_statuses) | {int(s) for s in (absent or ())}
        if ok404:
            absent_set.add(404)
        if self._v2:
            fallback = dict(kw.pop("fallback_headers", None) or {})
            fallback.setdefault("Accept", "application/json")
            kw["fallback_headers"] = fallback
        else:
            headers = dict(kw.pop("headers", None) or {})
            if not any(str(k).lower() == "accept" for k in headers):
                headers["Accept"] = "application/json"
            kw["headers"] = headers
        resp = self.request(method, url, **kw)
        if self._classify(resp) is not None:
            resp.raise_for_status()
        # rule 5: 401/403/407/429/451/5xx mean 'could not verify' even when declared as absences
        if resp.status in absent_set and resp.status not in NEVER_ABSENT_STATUS and resp.status < 500:
            return None
        resp.raise_for_status()
        return resp.json()

    def get_json(self, url: str, *, absent: Iterable[int] | None = None, ok404: bool = False, **kw: Any) -> Any:
        """GET and parse JSON. None only for statuses in ``absent_statuses`` | ``absent`` (``ok404=True``
        is a deprecated alias of ``absent={404}``); classified answers raise (Blocked, RateLimited,
        QuotaExceeded, HttpError), other failures AuthRequired/HttpError. 401/403/407/429/430/451/999
        and 5xx never count as an absence, even when declared (rule 5: could not verify)."""
        return self._json("GET", url, absent, ok404, kw)

    def post_json(self, url: str, *, absent: Iterable[int] | None = None, ok404: bool = False, **kw: Any) -> Any:
        """POST and parse JSON (same rules as :meth:`get_json`)."""
        return self._json("POST", url, absent, ok404, kw)
