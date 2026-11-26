"""Scope files for ACTIVE engagements (A7 rules of engagement, AR02, A11 BR7).

ACTIVE needs ``--mode active``, ``--authorized REF`` and ``--scope FILE`` on every execution path;
the core checks the scope at connection time, after DNS resolution through the egress profile and
again on every redirect hop. Pivots never inherit scope. A scope file is TOML (``tomllib``, Python
3.11+) or JSON with the same keys; its SHA-256 is stored in the case (``ScanOptions.scope``)::

    authorization_ref = "PENTEST-2026-042"      # must equal --authorized REF
    owner = "ACME S.A. - information security"  # who authorised the engagement
    contacts = ["soc@acme.example"]             # deconfliction contacts (at least one)
    ticket = "SEC-1234"
    window_start = 2026-11-26T09:00:00Z         # UTC (TOML datetime or ISO string)
    window_end = 2026-11-27T18:00:00Z
    shared_infra_hosts = ["www.acme.example"]   # CDN-fronted names HTTP probes may contact

    [targets]
    domains = ["acme.example", "*.acme.example"]   # exact, or an explicit '*.' wildcard (strict subdomains)
    cidrs = ["198.51.100.0/24"]
    url_prefixes = ["https://portal.partner.example/acme/"]

    [exclusions]                                   # exclusions always win
    domains = ["mail.acme.example"]
    cidrs = ["198.51.100.7/32"]
    url_prefixes = []

    [limits]                                       # optional; never above the A7 ceilings
    max_rps = 5           # <= 10 requests/probes per second per target host
    max_concurrency = 1   # <= 2 concurrent connections per target host
    max_pps = 200         # <= 1000 connection attempts per second in total (default 100)
    max_requests = 20000  # <= 50000 requests/probes per case (default 10000)

    [roe]                                          # optional rules-of-engagement identity
    user_agent = "pentest-PENTEST-2026-042"        # an engagement token agreed with the owner
    header = {name = "X-Engagement-Token", value = "c0ffee42"}

The ROE user agent and header may carry an engagement token agreed with the scope owner, never the
organisation's name, team, mailbox or analyst.

``Scope.load(path)`` raises :class:`ScopeError` only when the file cannot be read or parsed; every
field problem (malformed values, limits above the ceilings, an identifying ROE) is reported by
``Scope.validate(authorization_ref, now)`` together with a REF mismatch and the window, and a scope
with problems allows no contact at all (fail closed).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from v3lum.core import psl
from v3lum.core.http import (
    ACTIVE_MAX_CONCURRENT,
    ACTIVE_MAX_RPS,
    DEFAULT_ACTIVE_BUDGET,
    DEFAULT_MAX_PPS,
    MAX_ACTIVE_BUDGET,
    MAX_PPS,
    ROE_FORBIDDEN_HEADERS,
    host_problem,
    ip_problem,
    normalize_host,
    parse_ip,
)

__all__ = [
    "AUTH_REF_RE",
    "PLACEHOLDER_REFS",
    "SCOPE_KEYS",
    "RulesOfEngagement",
    "Scope",
    "ScopeError",
    "ScopeLimits",
    "ScopeTargets",
    "authorization_ref_problem",
    "path_variants",
]

#: A7: an authorization reference (``--authorized REF`` and the scope's ``authorization_ref``).
AUTH_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{2,63}$")
#: references that only pretend to be one (compared case-insensitively).
PLACEHOLDER_REFS: frozenset[str] = frozenset({"confirmed", "yes", "ok", "none", "n/a", "test"})
#: top-level keys of a scope file.
SCOPE_KEYS: frozenset[str] = frozenset(
    {"authorization_ref", "owner", "contacts", "ticket", "window_start", "window_end", "targets", "exclusions", "shared_infra_hosts", "limits", "roe", "notes", "description"}
)
_TARGET_KEYS = frozenset({"domains", "cidrs", "url_prefixes"})
_LIMIT_KEYS = frozenset({"max_rps", "max_concurrency", "max_pps", "max_requests"})
_ROE_KEYS = frozenset({"user_agent", "header"})
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
_EMAIL_RE = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")
_MAX_FILE_BYTES = 1024 * 1024
#: narrowest prefix length a scope CIDR may have (a /7 or an IPv6 /31 is no engagement scope).
_MIN_PREFIX = {4: 8, 6: 32}
_UTC = _dt.timezone.utc


_ESCAPE_RE = re.compile(r"%([0-9A-Fa-f]{2})")
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_ENCODED_SEPARATOR_RE = re.compile(r"%2[fF]|%5[cC]|\\")
_SLASHES_RE = re.compile(r"/{2,}")


def _unquote_unreserved(path: str) -> str:
    """Decode percent-escapes of unreserved characters (what requests sends: '%61dmin' -> 'admin',
    '%2e%2e' -> '..'); other escapes stay, upper-cased."""

    def sub(match: re.Match[str]) -> str:
        char = chr(int(match.group(1), 16))
        return char if char in _UNRESERVED else match.group(0).upper()

    return _ESCAPE_RE.sub(sub, path)


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 section 5.2.4 for an absolute path ('/a/./b/../c' -> '/a/c'), as urllib3 and servers do."""
    segments = path.split("/")
    out: list[str] = []
    for segment in segments:
        if segment == "..":
            if len(out) > 1:
                out.pop()
        elif segment != ".":
            out.append(segment)
    if segments[-1] in (".", ".."):
        out.append("")
    result = "/".join(out)
    return result if result.startswith("/") else "/" + result


def path_variants(path: Any) -> tuple[str, ...]:
    """Every form a server may see for a request path (scope matching, AR02): unreserved
    percent-escapes decoded and dot segments removed (what requests/urllib3 send), plus the same
    with repeated slashes collapsed and encoded slashes/backslashes taken as separators."""
    base = _remove_dot_segments(_unquote_unreserved(str(path or "") or "/"))
    variants = {base, _SLASHES_RE.sub("/", base)}
    separated = _ENCODED_SEPARATOR_RE.sub("/", base)
    if separated != base:
        cleaned = _remove_dot_segments(separated)
        variants |= {cleaned, _SLASHES_RE.sub("/", cleaned)}
    return tuple(sorted(variants))


def _under(path: str, prefix: str, *, exclusion: bool = False) -> bool:
    if prefix in ("", "/") or path == prefix:
        return True
    if path.startswith(prefix if prefix.endswith("/") else prefix + "/"):
        return True
    # an excluded '/admin/' also covers '/admin' (the same resource on most servers)
    return exclusion and prefix.endswith("/") and path == prefix.rstrip("/")


class ScopeError(ValueError):
    """A scope file that cannot be read or parsed (``problems`` lists what is wrong)."""

    def __init__(self, message: str, problems: Iterable[str] = ()) -> None:
        super().__init__(message)
        self.problems = list(problems) or [message]


def authorization_ref_problem(ref: Any) -> str:
    """Why ``ref`` is not a usable authorization reference ('' when it is): A7 requires
    ``^[A-Za-z0-9][A-Za-z0-9._:/#-]{2,63}$`` and no placeholder (confirmed, yes, ok, none, n/a, test)."""
    text = str(ref or "").strip()
    if not text:
        return "no authorization reference"
    if text.lower() in PLACEHOLDER_REFS:
        return f"{text!r} is a placeholder, not an authorization reference"
    if not AUTH_REF_RE.match(text):
        return f"{text!r} is not a valid authorization reference (3-64 characters: letters, digits and . _ : / # -)"
    return ""


@dataclass(frozen=True)
class ScopeTargets:
    """Normalised targets (or exclusions): exact domains, '*.' wildcards (strict subdomains),
    networks and URL prefixes (scheme, host, port, path)."""

    domains: frozenset[str] = frozenset()
    wildcards: frozenset[str] = frozenset()
    cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    url_prefixes: tuple[tuple[str, str, int, str], ...] = ()

    @property
    def empty(self) -> bool:
        return not (self.domains or self.wildcards or self.cidrs or self.url_prefixes)

    def host_match(self, host: str) -> bool:
        if host in self.domains:
            return True
        return any(host.endswith("." + base) for base in self.wildcards)

    def ip_match(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return any(addr.version == net.version and addr in net for net in self.cidrs)

    def url_match(self, scheme: str, host: str, port: int, path: str, *, exclusion: bool = False) -> bool:
        """Does ``path`` fall under a URL prefix of (scheme, host, port)? The path is judged in every
        form the transport or the server may give it (:func:`path_variants`: percent-escapes of
        unreserved characters decoded, dot segments removed, repeated slashes collapsed, encoded
        slashes taken as separators): a target prefix must hold for **every** form, an exclusion
        (``exclusion=True``, compared case-insensitively; '/admin/' also covers '/admin') for
        **any** form, so ``/acme/../admin`` never passes as ``/acme/`` and ``/x/../admin/`` or
        ``/%61dmin/`` never slip past an ``/admin/`` exclusion."""
        variants = path_variants(path)
        for p_scheme, p_host, p_port, p_path in self.url_prefixes:
            if (p_scheme, p_host, p_port) != (scheme, host, port):
                continue
            if exclusion:
                if any(_under(v.lower(), p_path.lower(), exclusion=True) for v in variants):
                    return True
            elif all(_under(v, p_path) for v in variants):
                return True
        return False

    def to_dict(self) -> dict[str, list[str]]:
        urls = [f"{s}://{h}" + ("" if p == (443 if s == "https" else 80) else f":{p}") + path for s, h, p, path in self.url_prefixes]
        return {
            "domains": sorted(self.domains) + sorted(f"*.{w}" for w in self.wildcards),
            "cidrs": [str(n) for n in self.cidrs],
            "url_prefixes": urls,
        }


@dataclass(frozen=True)
class ScopeLimits:
    """Optional lower limits of a scope (``None`` = the A7 default). The effective values never
    exceed the hard ceilings: :meth:`rps` <= 10, :meth:`concurrency` <= 2, :meth:`pps` <= 1000
    (default 100), :meth:`requests` <= 50000 (default 10000)."""

    max_rps: float | None = None
    max_concurrency: int | None = None
    max_pps: int | None = None
    max_requests: int | None = None

    def rps(self) -> float:
        return min(ACTIVE_MAX_RPS, self.max_rps) if self.max_rps else ACTIVE_MAX_RPS

    def concurrency(self) -> int:
        return min(ACTIVE_MAX_CONCURRENT, self.max_concurrency) if self.max_concurrency else ACTIVE_MAX_CONCURRENT

    def pps(self) -> int:
        return min(MAX_PPS, self.max_pps) if self.max_pps else DEFAULT_MAX_PPS

    def requests(self) -> int:
        return min(MAX_ACTIVE_BUDGET, self.max_requests) if self.max_requests else DEFAULT_ACTIVE_BUDGET

    def to_dict(self) -> dict[str, Any]:
        return {"max_rps": self.max_rps, "max_concurrency": self.max_concurrency, "max_pps": self.max_pps, "max_requests": self.max_requests}


@dataclass(frozen=True)
class RulesOfEngagement:
    """The optional ROE identity of ACTIVE requests: a User-Agent and one header carrying an
    engagement token agreed with the scope owner."""

    user_agent: str = ""
    header_name: str = ""
    header_value: str = ""

    def to_dict(self) -> dict[str, Any]:
        digest = hashlib.sha256(self.header_value.encode("utf-8")).hexdigest()[:16] if self.header_value else ""
        return {"user_agent": self.user_agent, "header": self.header_name, "header_value_sha256": digest}


def _when(value: Any) -> _dt.datetime | str:
    """A UTC datetime from a TOML datetime or an ISO-8601 string, else the problem text."""
    if isinstance(value, _dt.datetime):
        moment = value
    elif isinstance(value, str) and value.strip():
        try:
            moment = _dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00").replace("z", "+00:00"))
        except ValueError:
            return f"{value!r} is not an ISO-8601 date-time"
    else:
        return "missing (UTC ISO-8601, e.g. 2026-11-26T09:00:00Z)"
    if moment.tzinfo is None or moment.utcoffset() is None:
        return f"{value!s} has no UTC offset (write it in UTC, e.g. 2026-11-26T09:00:00Z)"
    return moment.astimezone(_UTC)


def _strings(value: Any, where: str, problems: list[str]) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        problems.append(f"{where} must be a list of strings")
        return []
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            problems.append(f"{where}: {item!r} is not a non-empty string")
        else:
            out.append(item.strip())
    return out


def _valid_name(name: str) -> bool:
    return bool(name) and len(name) <= 253 and all(_LABEL_RE.match(label) for label in name.split("."))


def _parse_targets(data: Any, where: str, problems: list[str], *, exclusions: bool = False) -> ScopeTargets:
    if data is None:
        return ScopeTargets()
    if not isinstance(data, Mapping):
        problems.append(f"{where} must be a table/object with domains, cidrs and url_prefixes")
        return ScopeTargets()
    unknown = sorted(set(data) - _TARGET_KEYS)
    if unknown:
        problems.append(f"{where}: unknown keys {unknown} (domains, cidrs, url_prefixes)")
    domains: set[str] = set()
    wildcards: set[str] = set()
    for raw in _strings(data.get("domains"), f"{where}.domains", problems):
        text = raw.lower()
        wildcard = text.startswith("*.")
        name = normalize_host(text[2:] if wildcard else text)
        if "*" in name or not _valid_name(name) or parse_ip(name) is not None:
            problems.append(f"{where}.domains: {raw!r} is not a host name (exact, or '*.' + a domain; IPs go in cidrs)")
            continue
        if wildcard:
            if psl.registrable_domain(name) is None:
                problems.append(f"{where}.domains: {raw!r} is a wildcard over a public suffix or a bare label: list the organisation's domains")
                continue
            wildcards.add(name)
        else:
            if "." in name and psl.registrable_domain(name) is None and not exclusions:
                problems.append(f"{where}.domains: {raw!r} is a public suffix, not an engagement target")
                continue
            domains.add(name)
    nets: list[Any] = []
    for raw in _strings(data.get("cidrs"), f"{where}.cidrs", problems):
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            problems.append(f"{where}.cidrs: {raw!r} is not an IP network")
            continue
        if not exclusions and net.prefixlen < _MIN_PREFIX[net.version]:
            problems.append(f"{where}.cidrs: {raw!r} is too broad for an engagement scope (at most /{_MIN_PREFIX[net.version]} for IPv{net.version})")
            continue
        nets.append(net)
    prefixes: list[tuple[str, str, int, str]] = []
    for raw in _strings(data.get("url_prefixes"), f"{where}.url_prefixes", problems):
        try:
            parts = urlsplit(raw)
            port = parts.port
        except ValueError:
            problems.append(f"{where}.url_prefixes: {raw!r} is not a URL")
            continue
        scheme = parts.scheme.lower()
        host = normalize_host(parts.hostname or "")
        if scheme not in ("http", "https") or not host or parts.username or parts.password or parts.query or parts.fragment:
            problems.append(f"{where}.url_prefixes: {raw!r} must be an http(s) URL prefix without credentials, query or fragment")
            continue
        if _ENCODED_SEPARATOR_RE.search(parts.path or ""):
            problems.append(f"{where}.url_prefixes: {raw!r} has an encoded slash or a backslash in its path")
            continue
        # stored canonical: what the transport sends for that path (no dot segments, no needless escapes)
        prefixes.append((scheme, host, port or (443 if scheme == "https" else 80), _remove_dot_segments(_unquote_unreserved(parts.path or "/"))))
    return ScopeTargets(frozenset(domains), frozenset(wildcards), tuple(nets), tuple(prefixes))


def _number(value: Any, where: str, problems: list[str], *, ceiling: float, integer: bool) -> Any:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or (integer and isinstance(value, float) and not value.is_integer()):
        problems.append(f"{where} must be a {'whole' if integer else 'positive'} number")
        return None
    if value <= 0:
        problems.append(f"{where} must be greater than 0")
        return None
    if value > ceiling:
        problems.append(f"{where} {value:g} is above the A7 ceiling of {ceiling:g}: limits above the ceilings are refused")
        return None
    return int(value) if integer else float(value)


def _parse_limits(data: Any, problems: list[str]) -> ScopeLimits:
    if data is None:
        return ScopeLimits()
    if not isinstance(data, Mapping):
        problems.append("limits must be a table/object")
        return ScopeLimits()
    unknown = sorted(set(data) - _LIMIT_KEYS)
    if unknown:
        problems.append(f"limits: unknown keys {unknown} ({', '.join(sorted(_LIMIT_KEYS))})")
    return ScopeLimits(
        max_rps=_number(data.get("max_rps"), "limits.max_rps", problems, ceiling=ACTIVE_MAX_RPS, integer=False),
        max_concurrency=_number(data.get("max_concurrency"), "limits.max_concurrency", problems, ceiling=ACTIVE_MAX_CONCURRENT, integer=True),
        max_pps=_number(data.get("max_pps"), "limits.max_pps", problems, ceiling=MAX_PPS, integer=True),
        max_requests=_number(data.get("max_requests"), "limits.max_requests", problems, ceiling=MAX_ACTIVE_BUDGET, integer=True),
    )


def _identity_problem(text: str, what: str) -> str:
    lowered = text.lower()
    if "v3lum" in lowered:
        return f"{what} must not name V3LUM (the V3LUM user agent never goes to targets)"
    if _EMAIL_RE.search(text):
        return f"{what} must not carry a mailbox (the organisation's identity never goes to targets)"
    if any(ch in text for ch in "\r\n\x00"):
        return f"{what} contains a control character"
    return ""


def _parse_roe(data: Any, problems: list[str]) -> RulesOfEngagement:
    if data is None:
        return RulesOfEngagement()
    if not isinstance(data, Mapping):
        problems.append("roe must be a table/object with user_agent and header")
        return RulesOfEngagement()
    unknown = sorted(set(data) - _ROE_KEYS)
    if unknown:
        problems.append(f"roe: unknown keys {unknown} (user_agent, header)")
    ua = data.get("user_agent", "")
    if not isinstance(ua, str):
        problems.append("roe.user_agent must be a string")
        ua = ""
    ua = ua.strip()
    if ua:
        problem = _identity_problem(ua, "roe.user_agent")
        if problem:
            problems.append(problem)
            ua = ""
    name = value = ""
    header = data.get("header")
    if header is not None:
        if not isinstance(header, Mapping) or set(header) - {"name", "value"}:
            problems.append("roe.header must be {name = ..., value = ...}")
        else:
            name = str(header.get("name") or "").strip()
            value = str(header.get("value") or "").strip()
            if not _HEADER_NAME_RE.match(name) or not value:
                problems.append("roe.header needs a valid header name and a non-empty value")
                name = value = ""
            elif name.lower() in ROE_FORBIDDEN_HEADERS:
                problems.append(f"roe.header {name!r} is not allowed (credentials, identity and hop-by-hop headers; use e.g. X-Engagement-Token)")
                name = value = ""
            else:
                problem = _identity_problem(value, "roe.header value")
                if problem:
                    problems.append(problem)
                    name = value = ""
    return RulesOfEngagement(ua, name, value)


class Scope:
    """A loaded ACTIVE scope (see the module docstring for the schema).

    Attributes: ``authorization_ref``, ``owner``, ``contacts``, ``ticket``, ``window_start``,
    ``window_end`` (aware UTC datetimes or None when malformed), ``targets`` and ``exclusions``
    (:class:`ScopeTargets`), ``shared_infra_hosts``, ``limits`` (:class:`ScopeLimits`), ``roe``
    (:class:`RulesOfEngagement`), ``path``, ``sha256`` (of the file bytes, else of the canonical
    JSON) and ``problems`` (malformed fields; any problem means no contact is allowed).
    """

    def __init__(self, data: Mapping[str, Any], *, path: str = "", raw: bytes | None = None) -> None:
        if not isinstance(data, Mapping):
            raise ScopeError("a scope must be a table/object")
        problems: list[str] = []
        self.path = str(path or "")
        self.raw = dict(data)
        if raw is None:
            raw = json.dumps(self.raw, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
        self.sha256 = hashlib.sha256(raw).hexdigest()
        unknown = sorted(k for k in set(data) - SCOPE_KEYS if not str(k).startswith("x_"))
        if unknown:
            problems.append(f"unknown keys {unknown} (allowed: {', '.join(sorted(SCOPE_KEYS))})")
        self.authorization_ref = str(data.get("authorization_ref") or "").strip()
        problem = authorization_ref_problem(self.authorization_ref)
        if problem:
            problems.append(f"authorization_ref: {problem}")
        self.owner = str(data.get("owner") or "").strip()
        if not self.owner:
            problems.append("owner is required (who authorised the engagement)")
        self.contacts = tuple(_strings(data.get("contacts"), "contacts", problems))
        if not self.contacts:
            problems.append("contacts needs at least one deconfliction contact")
        self.ticket = str(data.get("ticket") or "").strip()
        if not self.ticket:
            problems.append("ticket is required")
        start = _when(data.get("window_start"))
        end = _when(data.get("window_end"))
        self.window_start: _dt.datetime | None = start if isinstance(start, _dt.datetime) else None
        self.window_end: _dt.datetime | None = end if isinstance(end, _dt.datetime) else None
        if isinstance(start, str):
            problems.append(f"window_start: {start}")
        if isinstance(end, str):
            problems.append(f"window_end: {end}")
        if self.window_start and self.window_end and self.window_end <= self.window_start:
            problems.append("window_end must be after window_start")
        self.targets = _parse_targets(data.get("targets"), "targets", problems)
        if self.targets.empty:
            problems.append("targets lists nothing (domains, cidrs or url_prefixes)")
        self.exclusions = _parse_targets(data.get("exclusions"), "exclusions", problems, exclusions=True)
        shared: set[str] = set()
        for raw_host in _strings(data.get("shared_infra_hosts"), "shared_infra_hosts", problems):
            host = normalize_host(raw_host)
            if not _valid_name(host) or parse_ip(host) is not None:
                problems.append(f"shared_infra_hosts: {raw_host!r} is not a host name")
            elif not self.targets.host_match(host):
                problems.append(f"shared_infra_hosts: {raw_host!r} is not covered by targets.domains")
            else:
                shared.add(host)
        self.shared_infra_hosts = frozenset(shared)
        self.limits = _parse_limits(data.get("limits"), problems)
        self.roe = _parse_roe(data.get("roe"), problems)
        self.problems: tuple[str, ...] = tuple(problems)

    # ------------------------------------------------------------------ loading
    @classmethod
    def load(cls, path: str | Path) -> Scope:
        """Read a scope file: ``.toml`` (tomllib), ``.json``, or either by content. Raises
        :class:`ScopeError` when the file cannot be read or parsed (field problems are reported by
        :meth:`validate`)."""
        file = Path(path).expanduser()
        try:
            raw = file.read_bytes()
        except OSError as exc:
            raise ScopeError(f"cannot read scope file {file}: {exc.strerror or exc}") from None
        if len(raw) > _MAX_FILE_BYTES:
            raise ScopeError(f"scope file {file} is larger than {_MAX_FILE_BYTES} bytes")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise ScopeError(f"scope file {file} is not UTF-8 text") from None
        suffix = file.suffix.lower()
        data = cls._parse(text, suffix, str(file))
        return cls(data, path=str(file), raw=raw)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, path: str = "") -> Scope:
        """A scope from already parsed data (tests, the shell's ``set scope``)."""
        return cls(data, path=path)

    @staticmethod
    def _parse(text: str, suffix: str, origin: str) -> dict[str, Any]:
        def as_json() -> Any:
            return json.loads(text)

        def as_toml() -> Any:
            try:
                import tomllib
            except ModuleNotFoundError:  # Python 3.10
                raise ScopeError(f"{origin}: TOML scope files need Python 3.11+ (tomllib); use the JSON form") from None
            return tomllib.loads(text)

        # the suffix decides; an unknown suffix tries JSON, then TOML
        order = (as_toml,) if suffix == ".toml" else (as_json,) if suffix == ".json" else (as_json, as_toml)
        errors: list[str] = []
        for parser in order:
            try:
                data = parser()
            except ScopeError:
                raise
            except ValueError as exc:  # json.JSONDecodeError and tomllib.TOMLDecodeError
                errors.append(str(exc))
                continue
            if not isinstance(data, dict):
                raise ScopeError(f"{origin}: a scope file must hold a table/object")
            return data
        raise ScopeError(f"{origin}: not a valid scope file ({'; '.join(errors)[:200]})")

    # ------------------------------------------------------------------ validation
    def validate(self, authorization_ref: Any, now: _dt.datetime | None = None, *, org_terms: Iterable[str] = ()) -> list[str]:
        """Every reason the scope cannot be used now: malformed fields, limits above ceilings, a
        REF that differs from ``authorization_ref`` (``--authorized``), outside the window, an ROE
        identity naming the organisation (``org_terms``: its name and brand keywords). [] = usable."""
        problems = list(self.problems)
        ref = str(authorization_ref or "").strip()
        if not ref:
            problems.append("no --authorized REF was given")
        elif ref != self.authorization_ref:
            problems.append(f"authorization_ref mismatch: the scope says {self.authorization_ref!r}, --authorized says {ref!r}")
        moment = (now or _dt.datetime.now(_UTC)).astimezone(_UTC)
        if self.window_start is not None and moment < self.window_start:
            problems.append(f"outside the window: it opens at {self.window_start.isoformat()}")
        if self.window_end is not None and moment >= self.window_end:
            problems.append(f"outside the window: it closed at {self.window_end.isoformat()}")
        for term in org_terms:
            needle = str(term or "").strip().lower()
            if len(needle) < 3:
                continue
            for what, text in (("roe.user_agent", self.roe.user_agent), ("roe.header value", self.roe.header_value)):
                if needle in text.lower():
                    problems.append(f"{what} names the organisation ({term!r}): only an engagement token agreed with the owner is allowed")
        return problems

    def window_expired(self, now: _dt.datetime | None = None) -> bool:
        """True once the window has closed (or when it is malformed: fail closed)."""
        if self.window_end is None:
            return True
        return (now or _dt.datetime.now(_UTC)).astimezone(_UTC) >= self.window_end

    def in_window(self, now: _dt.datetime | None = None) -> bool:
        """True while ``window_start <= now < window_end``."""
        if self.window_start is None or self.window_end is None:
            return False
        moment = (now or _dt.datetime.now(_UTC)).astimezone(_UTC)
        return self.window_start <= moment < self.window_end

    # ------------------------------------------------------------------ matching
    def excluded_host(self, host: Any) -> bool:
        name = normalize_host(host)
        addr = parse_ip(name)
        if addr is not None:
            return self.excluded_ip(addr)
        return bool(name) and self.exclusions.host_match(name)

    def excluded_ip(self, ip: Any) -> bool:
        addr = _addr(ip)
        return addr is not None and self.exclusions.ip_match(addr)

    def matches_host(self, host: Any) -> bool:
        """``host`` is a target (exact domain, '*.' wildcard subdomain, or an IP inside a target
        CIDR) and not excluded."""
        name = normalize_host(host)
        if not name or self.excluded_host(name):
            return False
        if parse_ip(name) is not None:
            return self.matches_ip(name)
        return self.targets.host_match(name)

    def matches_ip(self, ip: Any) -> bool:
        """``ip`` is inside a target CIDR and not excluded (IPv4-mapped IPv6 counts as IPv4)."""
        addr = _addr(ip)
        if addr is None or self.exclusions.ip_match(addr):
            return False
        return self.targets.ip_match(addr)

    def matches_url(self, url: Any) -> bool:
        """``url`` (http/https) starts with a target URL prefix, or its host is a target; excluded
        prefixes, domains and networks win."""
        try:
            parts = urlsplit(str(url or ""))
            port = parts.port
        except ValueError:
            return False
        scheme = parts.scheme.lower()
        host = normalize_host(parts.hostname or "")
        if scheme not in ("http", "https") or not host:
            return False
        port = port or (443 if scheme == "https" else 80)
        path = parts.path or "/"
        if self.exclusions.url_match(scheme, host, port, path, exclusion=True) or self.excluded_host(host):
            return False
        return self.targets.url_match(scheme, host, port, path) or self.matches_host(host)

    def allows_contact(self, host: Any, ips: Iterable[Any] = (), *, probe: str = "http", url: str | None = None, org: Any = None) -> tuple[bool, str]:
        """May an ACTIVE probe reach ``host`` resolved to ``ips``? Returns (allowed, reason).

        Exclusions win; the host must be a target (by name, by ``url`` prefix for HTTP, or every
        resolved address inside a target CIDR); private, loopback, link-local, CGNAT, ULA,
        multicast, reserved and cloud-metadata addresses only when the scope lists them;
        CDN/cloud/hosting/SaaS and warninglisted addresses (and host names under such domains) only
        when the IP/CIDR is listed (``probe='network'``) or the host is in ``shared_infra_hosts``
        (``probe='http'``); addresses of org-profile entries flagged ``third_party_hosted``
        (``org``) are excluded from network probes unless the IP/CIDR is listed (A11 BR7).
        """
        if probe not in ("http", "network"):
            raise ValueError("probe must be 'http' or 'network'")
        if self.problems:
            return False, f"the scope file has problems ({self.problems[0]}): no contact allowed"
        name = normalize_host(host)
        if not name:
            return False, "no target host"
        addrs = []
        for ip in ips or ():
            addr = _addr(ip)
            if addr is None:
                return False, f"{ip!r} is not an IP address"
            addrs.append(addr)
        if self.excluded_host(name):
            return False, f"{name} is excluded by the scope"
        for addr in addrs:
            if self.exclusions.ip_match(addr):
                return False, f"{name} resolves to {addr}, excluded by the scope"
        if url is not None and self.exclusions.url_match(*_url_key(url), exclusion=True):
            return False, f"{url} is excluded by the scope"
        by_name = self.matches_host(name) or (url is not None and self.matches_url(url))
        by_ip = bool(addrs) and all(self.targets.ip_match(a) for a in addrs)
        if not (by_name or by_ip):
            return False, f"{name} is outside the scope"
        literal = parse_ip(name) is not None
        name_kinds = set() if literal else _shared_kinds_of_name(name)
        if name_kinds:
            kind = sorted(name_kinds)[0]
            if probe == "http" and name not in self.shared_infra_hosts:
                return False, f"{name} is on shared {kind} infrastructure: list it under shared_infra_hosts for HTTP probes"
            if probe == "network" and not by_ip:
                return False, f"{name} is on shared {kind} infrastructure: network probes need its IP/CIDR listed in the scope"
        for addr in addrs:
            listed = self.targets.ip_match(addr)
            problem = ip_problem(addr)
            if problem and not listed:
                return False, f"{name} resolves to {addr} ({problem}): not listed in the scope"
            if listed:
                continue
            kinds = _shared_kinds_of_ip(addr)
            if kinds:
                kind = sorted(kinds)[0]
                if probe == "network":
                    return False, f"{name} resolves to {addr}, shared {kind} infrastructure: network probes need the IP/CIDR listed in the scope"
                if name not in self.shared_infra_hosts:
                    return False, f"{name} resolves to {addr}, shared {kind} infrastructure: list {name} under shared_infra_hosts for HTTP probes"
            if probe == "network" and org is not None and _third_party_hosted(org, addr, name):
                return False, f"{name} ({addr}) is an org asset flagged third_party_hosted: network probes need the IP/CIDR listed in the scope"
        if probe == "network" and not addrs and org is not None and not literal and _third_party_hosted(org, None, name):
            return False, f"{name} is an org asset flagged third_party_hosted: network probes need its IP/CIDR listed in the scope"
        return True, ""

    # ------------------------------------------------------------------ export
    def to_dict(self) -> dict[str, Any]:
        """Normalised view for the case audit (the ROE header value only as a SHA-256 prefix)."""
        return {
            "sha256": self.sha256,
            "path": self.path,
            "authorization_ref": self.authorization_ref,
            "owner": self.owner,
            "contacts": list(self.contacts),
            "ticket": self.ticket,
            "window_start": self.window_start.isoformat() if self.window_start else None,
            "window_end": self.window_end.isoformat() if self.window_end else None,
            "targets": self.targets.to_dict(),
            "exclusions": self.exclusions.to_dict(),
            "shared_infra_hosts": sorted(self.shared_infra_hosts),
            "limits": self.limits.to_dict(),
            "roe": self.roe.to_dict(),
            "problems": list(self.problems),
        }

    def summary(self) -> str:
        """One line for banners: REF, window and target counts."""
        t = self.targets
        window = f"{self.window_start.isoformat() if self.window_start else '?'} - {self.window_end.isoformat() if self.window_end else '?'}"
        return (
            f"scope {self.authorization_ref or '?'} ({self.sha256[:12]}): {len(t.domains) + len(t.wildcards)} domains, "
            f"{len(t.cidrs)} networks, {len(t.url_prefixes)} URL prefixes; window {window}"
        )

    def __repr__(self) -> str:
        return f"Scope({self.authorization_ref!r}, sha256={self.sha256[:12]}, problems={len(self.problems)})"


def _addr(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        addr = value
    else:
        addr = parse_ip(value)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _url_key(url: str) -> tuple[str, str, int, str]:
    try:
        parts = urlsplit(str(url or ""))
        port = parts.port
    except ValueError:
        return ("", "", 0, "")
    scheme = parts.scheme.lower()
    return (scheme, normalize_host(parts.hostname or ""), port or (443 if scheme == "https" else 80), parts.path or "/")


def _entity(etype: str, value: str) -> Any:
    from v3lum.core.entities import Entity

    return Entity.try_make(etype, value)


def _shared_kinds_of_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> set[str]:
    """Noise kinds cdn/cloud/hosting/saas of an address, plus 'warninglist <name>' hits."""
    from v3lum.core import noise

    entity = _entity("ipv4" if addr.version == 4 else "ipv6", str(addr))
    if entity is None:
        return set()
    try:
        kinds = set(noise.noise_kinds(entity)) & set(noise.CDN_KINDS)
        kinds |= {f"warninglist {name}" for name in noise.warninglists(entity)}
    except Exception:  # noqa: BLE001 - an unreadable list counts as shared infrastructure (fail closed)
        return {"unknown (noise lists unreadable)"}
    return kinds


def _shared_kinds_of_name(name: str) -> set[str]:
    """Noise kinds cdn/cloud/hosting/saas of a host name, or of its public suffix when that is a
    shared platform (tenants of github.io, pages.dev, azurewebsites.net... share its addresses)."""
    if host_problem(name):
        return set()
    from v3lum.core import noise

    candidates = [name]
    suffix = psl.public_suffix(name)
    if suffix and suffix != name and "." in suffix:
        candidates.append(suffix)
    kinds: set[str] = set()
    for candidate in candidates:
        entity = _entity("domain", candidate)
        if entity is None:
            continue
        try:
            kinds |= set(noise.noise_kinds(entity)) & set(noise.CDN_KINDS)
        except Exception:  # noqa: BLE001 - fail closed
            return {"unknown (noise lists unreadable)"}
    return kinds


def _third_party_hosted(org: Any, addr: Any, name: str) -> bool:
    owns = getattr(org, "owns", None)
    if not callable(owns):
        return False
    probes = []
    if addr is not None:
        probes.append(f"{'ipv4' if addr.version == 4 else 'ipv6'}:{addr}")
    if name and parse_ip(name) is None:
        probes.append(f"domain:{name}")
    for probe in probes:
        try:
            found = owns(probe)
        except Exception:  # noqa: BLE001 - an org profile problem never widens contact
            continue
        if bool(getattr(found, "third_party_hosted", False)):
            return True
    return False
