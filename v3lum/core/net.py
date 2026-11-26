"""Egress profiles and the core socket connector (``ctx.net``) for target contact (A7, A13, P376).

**Egress profiles** (:class:`EgressProfiles`, settings ``proxy``, ``proxy_light``, ``proxy_active``):

* ``default`` - the route of every third-party API call, DoH and PASSIVE request (setting ``proxy``,
  or direct); never ``proxy_light``/``proxy_active``, so provider terms and quotas stay global;
* ``light`` - LIGHT target contact when ``proxy_light`` is configured (else the default route, where
  the policy guard refuses hostile contact); Tor (a SOCKS proxy on port 9050/9150) is allowed here
  for reads only;
* ``active`` - ACTIVE target contact when ``proxy_active`` is configured (else the default route);
  a Tor endpoint as ``proxy_active`` is refused at load (A13).

Non-default profiles get their own ``requests.Session`` with ``trust_env=False`` (no environment
proxies, NO_PROXY bypass or ~/.netrc), explicit proxies and remote name resolution (``socks5`` is
upgraded to ``socks5h``; HTTP CONNECT proxies resolve remotely): no local ``getaddrinfo`` for a
target host. A configured profile fails closed: unusable (bad URL, PySocks missing, Tor as
proxy_active) or unreachable, its requests are refused (PolicyError 'policy', e.g. 'proxy_light
unreachable: request refused') and never resent on the default route. :func:`public_ip` asks the
benign echo service api.ipify.org through a profile, on request only (``v3lum doctor --egress``).

**Connector** (``ctx.net``, raw sockets for target modules only; the P327 lint fails direct socket
use in modules): ``connect(host, port, *, timeout=None)`` and ``wrap_tls(sock, server_hostname, *,
timeout=None)`` keep their wave-1 signatures and now apply, before a socket is opened:

* the module's egress profile (PySocks for SOCKS proxies, an HTTP CONNECT tunnel for HTTP proxies;
  the connection always goes to the checked address, through a proxy too, except onion services);
* the SSRF guard after resolution through the profile (private, loopback, link-local, CGNAT, ULA,
  multicast, reserved and cloud-metadata addresses, single-label and internal names refused unless
  the seed is internal or the scope lists them), ACTIVE scope checks (``Scope.allows_contact`` with
  ``probe='network'``: CDN/shared-hosting and third_party_hosted org addresses need the IP/CIDR
  listed) and the LIGHT seed binding;
* the A7 ceilings: <= 10 probes/s (LIGHT 1/s) and <= 2 concurrent connections per target host,
  <= 1000 TCP ports per host, <= 100 connection attempts/s in total (scope ``max_pps`` up to 1000),
  the per-case ACTIVE budget (10000, scope ``max_requests`` up to 50000) and LIGHT's 25 per host;
* the kill switch: new connections are refused once the run is cancelled or overdue (or the scope
  window has closed), a pending connect or proxy handshake is abandoned within ~100 ms, and open
  sockets are shut down within 2 s of the cancel flag;
* one ``RequestInfo`` (method 'CONNECT', url ``tcp://host:port``) per connection for the request
  ledger (``ctx.http.request_log`` and the runtime event bus when bound to ``ctx.http``).

``cap_wordlist(seq)`` caps any wordlist at 5000 entries; ``run_tool(name, args, *, targets,
timeout=None)`` is the only sanctioned way to launch an external binary (see ``v3lum.core.tools``).

    sock = ctx.net.connect("example.com", 443, timeout=5)
    tls = ctx.net.wrap_tls(sock, "example.com")
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import importlib.util
import itertools
import os
import select
import socket
import ssl
import threading
import time
import weakref
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlsplit

import requests

from v3lum.core.clock import SYSTEM_CLOCK, Clock, SystemClock
from v3lum.core.http import (
    WORDLIST_MAX,
    Cancelled,
    ContactCeilings,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    PolicyError,
    RequestInfo,
    RequestsTransport,
    _check_window,
    _opsec_label,
    _pick_ip,
    _scope_allows,
    _scope_call,
    contact_concurrency,
    contact_rps,
    entity_hosts,
    host_problem,
    host_within,
    ip_problem,
    is_metadata_ip,
    max_pps,
    normalize_host,
    parse_ip,
)
from v3lum.core.limiter import HostLimiter
from v3lum.core.models import Opsec
from v3lum.core.redact import redact_url, register_secret

__all__ = [
    "DEFAULT_CONNECT_TIMEOUT",
    "IPIFY_URL",
    "PROFILES",
    "PROFILE_SETTINGS",
    "TOR_PORTS",
    "WORDLIST_MAX",
    "Connector",
    "EgressProfile",
    "EgressProfiles",
    "ProbeSocket",
    "cap_wordlist",
    "public_ip",
]

#: connect/handshake timeout when the caller gives none (capped by the run deadline).
DEFAULT_CONNECT_TIMEOUT = 10.0
#: the egress profiles and the setting that configures each.
PROFILES: tuple[str, ...] = ("default", "light", "active")
PROFILE_SETTINGS: dict[str, str] = {"default": "proxy", "light": "proxy_light", "active": "proxy_active"}
#: SOCKS ports of a Tor client (tor 9050, Tor Browser 9150): such a proxy is the Tor network.
TOR_PORTS: frozenset[int] = frozenset({9050, 9150})
#: the benign echo service used by :func:`public_ip` (provider fragment ``ipify``).
IPIFY_URL = "https://api.ipify.org?format=json"
_PROXY_SCHEMES = ("http", "https", "socks5", "socks5h", "socks4", "socks4a")
_REMOTE_DNS = {"socks5": "socks5h", "socks4": "socks4a"}
#: how often the socket watcher checks the kill switch (open sockets close within 2 s, A7).
_WATCH_INTERVAL = 0.1
#: a LIGHT/ACTIVE proxy that accepted a TCP connection is not probed again for this long (seconds)
_REACHABLE_TTL = 30.0
_REACHABLE_TIMEOUT = 3.0


def _socks_available() -> bool:
    return importlib.util.find_spec("socks") is not None


def _proxy_port(parts: Any) -> int:
    """The port of a proxy URL; without one, the scheme's default as requests/urllib3 use it (http
    80, https 443, SOCKS 1080), so the reachability probe checks the port actually used."""
    try:
        port = parts.port
    except ValueError:
        port = None
    if port:
        return int(port)
    scheme = str(parts.scheme or "").lower()
    return 443 if scheme == "https" else 1080 if scheme.startswith("socks") else 80


def _tcp_url(host: str, port: int) -> str:
    """``tcp://host:port`` for the ledger (IPv6 literals in brackets)."""
    shown = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"tcp://{shown}:{port}"


# ======================================================================================
# Egress profiles
# ======================================================================================


@dataclass(frozen=True)
class EgressProfile:
    """One route: ``proxy`` ('' = direct), ``configured`` (its setting is set), ``tor``, ``error``
    (why it cannot be used; a configured profile with an error refuses its requests)."""

    name: str
    setting: str
    proxy: str = ""
    configured: bool = False
    tor: bool = False
    error: str = ""

    @property
    def scheme(self) -> str:
        return urlsplit(self.proxy).scheme.lower() if self.proxy else ""

    @property
    def label(self) -> str:
        """The proxy without credentials (``socks5h://127.0.0.1:9050``), or 'direct'."""
        if not self.proxy:
            return "direct"
        parts = urlsplit(self.proxy)
        host = parts.hostname or "?"
        host = f"[{host}]" if ":" in host else host
        return f"{parts.scheme}://{host}" + (f":{parts.port}" if parts.port else "")

    @property
    def usable(self) -> bool:
        return not self.error

    @property
    def remote_dns(self) -> bool:
        """True when the proxy resolves target names itself (never the local resolver)."""
        return self.scheme in ("http", "https", "socks5h", "socks4a")

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "setting": self.setting, "configured": self.configured, "proxy": self.label, "tor": self.tor, "error": self.error}


def _setting(settings: Any, name: str, default: Any = None) -> Any:
    if settings is None:
        return default
    try:
        getter = getattr(settings, "get", None)
        value = getter(name, default) if callable(getter) else getattr(settings, name, default)
    except Exception:  # noqa: BLE001 - a broken settings object configures nothing
        return default
    return default if value is None else value


def _parse_profile(name: str, value: Any) -> EgressProfile:
    setting = PROFILE_SETTINGS[name]
    text = str(value or "").strip()
    if not text:
        return EgressProfile(name, setting)
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return EgressProfile(name, setting, configured=True, error=f"{setting} is not a valid proxy URL")
    scheme = parts.scheme.lower()
    if scheme not in _PROXY_SCHEMES:
        return EgressProfile(name, setting, configured=True, error=f"{setting}: unsupported proxy scheme {scheme or '(none)'!r} (http, https, socks5h, socks4a)")
    if not parts.hostname:
        return EgressProfile(name, setting, configured=True, error=f"{setting}: the proxy URL has no host")
    if scheme.startswith("socks") and not port:
        return EgressProfile(name, setting, configured=True, error=f"{setting}: a SOCKS proxy URL needs a port (e.g. socks5h://127.0.0.1:9050)")
    for secret in (parts.username, parts.password):
        if secret:
            register_secret(unquote(secret), label=setting)
    proxy = text
    if name != "default" and scheme in _REMOTE_DNS:
        # names are always resolved by the proxy on LIGHT/ACTIVE routes (no local DNS for targets)
        proxy = _REMOTE_DNS[scheme] + text[len(scheme):]
        scheme = _REMOTE_DNS[scheme]
    tor = scheme.startswith("socks") and port in TOR_PORTS
    error = ""
    if scheme.startswith("socks") and not _socks_available():
        error = f"{setting}: SOCKS proxies need the optional package PySocks (pip install 'v3lum[full]')"
    if name == "active" and tor:
        error = f"{setting} points at a Tor SOCKS port: Tor is allowed for LIGHT reads only, never for ACTIVE (A13); ACTIVE contact is refused until it changes"
    return EgressProfile(name, setting, proxy=proxy, configured=True, tor=tor, error=error)


class EgressProfiles:
    """The three egress profiles of a runtime, built from settings (``proxy``, ``proxy_light``,
    ``proxy_active``). See the module docstring for the rules.

    ``EgressProfiles(settings=None, *, transports=None, default_transport=None, default_proxy=None,
    ca_bundle=None, clock=None, resolver=None)``: ``transports`` injects a transport per profile name
    (tests), ``default_transport`` the default route's transport; ``resolver`` (``callable(host,
    profile) -> list[str]``) replaces the DoH profile resolver (tests). ``errors`` lists the load
    problems (doctor). Selection never depends on case tags: modules never choose proxies.
    """

    def __init__(
        self,
        settings: Any = None,
        *,
        transports: Mapping[str, Any] | None = None,
        default_transport: Any = None,
        default_proxy: str | None = None,
        ca_bundle: str | None = None,
        clock: Clock | None = None,
        resolver: Any = None,
    ) -> None:
        self.settings = settings
        self.clock: Clock = clock or SYSTEM_CLOCK
        self.ca_bundle = str(ca_bundle if ca_bundle is not None else _setting(settings, "ca_bundle", "") or "")
        self.resolver = resolver
        values = {
            "default": default_proxy if default_proxy is not None else _setting(settings, "proxy", ""),
            "light": _setting(settings, "proxy_light", ""),
            "active": _setting(settings, "proxy_active", ""),
        }
        self._profiles = {name: _parse_profile(name, values[name]) for name in PROFILES}
        self._transports: dict[str, Any] = dict(transports or {})
        if default_transport is not None:
            self._transports["default"] = default_transport
        self._lock = threading.Lock()
        self._reachable: dict[str, float] = {}
        self.last_error = ""

    # ------------------------------------------------------------------ inspection
    @property
    def errors(self) -> list[str]:
        """Problems of configured profiles (each refuses its requests until fixed)."""
        return [p.error for p in self._profiles.values() if p.error]

    def profile(self, name: str) -> EgressProfile:
        """The profile called ``name`` ('default' | 'light' | 'active'); KeyError otherwise."""
        return self._profiles[name]

    def configured(self, name: str) -> bool:
        return self._profiles[name].configured

    def describe(self) -> list[dict[str, Any]]:
        """One row per profile for doctor (proxy shown without credentials)."""
        return [self._profiles[name].to_dict() for name in PROFILES]

    # ------------------------------------------------------------------ selection
    def profile_for(self, opsec: Any, *, tags: Iterable[str] = ()) -> str:
        """The profile of a request: PASSIVE (every third-party API call and DoH) -> 'default';
        LIGHT -> 'light' when proxy_light is configured, else 'default'; ACTIVE -> 'active' when
        proxy_active is configured, else 'default'. ``tags`` (case tags of the entity) never move
        traffic: a configured but broken profile stays selected and fails closed."""
        del tags  # recorded by callers; never a reason to change the route
        label = _opsec_label(opsec)
        if label == "light" and self._profiles["light"].configured:
            return "light"
        if label == "active" and self._profiles["active"].configured:
            return "active"
        return "default"

    def effective(self, name: str) -> str:
        """``name`` when it is 'default' or configured, else 'default' (an unconfigured LIGHT/ACTIVE
        profile means the default route)."""
        if name not in self._profiles:
            raise KeyError(name)
        return name if name == "default" or self._profiles[name].configured else "default"

    def check(self, name: str) -> None:
        """Raise PolicyError when profile ``name`` is configured but unusable (fail closed)."""
        prof = self._profiles[name]
        if prof.configured and prof.error:
            raise PolicyError("policy", f"{prof.error}: request refused (fail closed, A13)")

    def ensure_reachable(self, name: str) -> None:
        """Raise PolicyError ('<setting> unreachable: request refused') when the proxy of a configured
        LIGHT/ACTIVE profile does not accept a TCP connection (checked at most every 30 s; an
        injected test transport is trusted). Nothing is ever resent on the default route."""
        if name == "default":
            return
        prof = self._profiles.get(name)
        if prof is None or not prof.configured:
            return
        self.check(name)
        if name in self._transports and not isinstance(self._transports[name], RequestsTransport):
            return  # an injected transport (tests) stands for the proxy
        now = time.monotonic()
        with self._lock:
            last = self._reachable.get(name)
        if last is not None and now - last < _REACHABLE_TTL:
            return
        parts = urlsplit(prof.proxy)
        port = _proxy_port(parts)
        try:
            with socket.create_connection((parts.hostname, port), timeout=_REACHABLE_TIMEOUT):
                pass
        except (OSError, RuntimeError):  # RuntimeError: the test network guard
            raise PolicyError("policy", f"{prof.setting} unreachable: request refused (never sent through the default route, A13)") from None
        with self._lock:
            self._reachable[name] = now

    # ------------------------------------------------------------------ transports and sessions
    def _default_transport(self) -> Any:
        with self._lock:
            transport = self._transports.get("default")
            if transport is None:
                transport = RequestsTransport(proxy=self._profiles["default"].proxy, trust_env=True, ca_bundle=self.ca_bundle, clock=self.clock)
                self._transports["default"] = transport
            return transport

    def transport_for(self, name: str) -> Any:
        """The transport of profile ``name``: the default route's, or the profile's own (built with
        ``trust_env=False`` and explicit proxies). Raises PolicyError for an unusable or
        unconfigured LIGHT/ACTIVE profile (a request never silently moves to the default route)."""
        if name == "default":
            return self._default_transport()
        prof = self._profiles.get(name)
        if prof is None:
            raise PolicyError("policy", f"unknown egress profile {name!r}")
        if not prof.configured:
            raise PolicyError("policy", f"{prof.setting} is not configured: the {name} egress profile is unavailable")
        self.check(name)
        with self._lock:
            transport = self._transports.get(name)
            if transport is None:
                transport = RequestsTransport(proxy=prof.proxy, trust_env=False, ca_bundle=self.ca_bundle, clock=self.clock)
                self._transports[name] = transport
            return transport

    def session_for(self, opsec: Any, *, tags: Iterable[str] = ()) -> tuple[str, requests.Session]:
        """(profile name, requests.Session) of a request at ``opsec``: the default route's session,
        or the profile's own session (``trust_env=False``, explicit proxies, no netrc, no cookies).
        Raises PolicyError when the selected profile is configured but unusable."""
        name = self.profile_for(opsec, tags=tags)
        self.check(name)
        transport = self.transport_for(name)
        session = getattr(transport, "session", None)
        if not callable(session):  # an injected test transport: build the real session for the profile
            prof = self._profiles[name]
            session = RequestsTransport(proxy=prof.proxy, trust_env=name == "default", ca_bundle=self.ca_bundle, clock=self.clock).session
        return name, session()

    # ------------------------------------------------------------------ public IP
    def public_ip(self, name: str = "default", *, client: Any = None, timeout: float = 10.0) -> str | None:
        """Public IP of profile ``name`` through the echo service (see :func:`public_ip`)."""
        return public_ip(name, client=client, egress=self, settings=self.settings, timeout=timeout)


def public_ip(profile: str = "default", *, client: Any = None, egress: EgressProfiles | None = None, settings: Any = None, timeout: float = 10.0) -> str | None:
    """The public IP address a route exits from, asked of the benign echo service
    https://api.ipify.org?format=json through ``profile`` (an unconfigured LIGHT/ACTIVE profile
    means the default route). On request only (``v3lum doctor --egress``); never during scans and
    never cached. None when the service could not be asked (the reason is in
    ``egress.last_error``)."""
    if client is None:
        from v3lum.core.http import HttpClient

        if settings is None and egress is not None:
            settings = egress.settings
        client = HttpClient(settings=settings, egress=egress, timeout=timeout, clock=getattr(egress, "clock", None))
    holder = egress if egress is not None else getattr(client, "egress", None)
    try:
        resp = client.request(
            "GET", IPIFY_URL, egress_profile=profile, ttl=0, timeout=timeout, retries=0, module="egress_check", source="ipify.echo",
            charge_quota=False, fallback_headers={"Accept": "application/json"},
        )
        data = resp.raise_for_status().json()
    except (HttpError, NetworkError, PolicyError, Cancelled, ValueError) as exc:
        if holder is not None:
            holder.last_error = str(exc)
        return None
    found = parse_ip(data.get("ip") if isinstance(data, dict) else None)
    if found is None:
        if holder is not None:
            holder.last_error = "the echo service answered without an IP address"
        return None
    return str(found)


def cap_wordlist(seq: Iterable[Any]) -> list[Any]:
    """The first WORDLIST_MAX (5000) entries of any wordlist (A7 hard ceiling; --wordlist included)."""
    return list(itertools.islice(iter(seq or ()), WORDLIST_MAX))


# ======================================================================================
# Probe sockets (a closed socket frees its per-host connection slot)
# ======================================================================================


class _Slot:
    """One held per-host connection slot, released exactly once."""

    def __init__(self, sem: Any) -> None:
        self._sem = sem
        self._lock = threading.Lock()
        self._done = False

    def release(self) -> None:
        with self._lock:
            if self._done:
                return
            self._done = True
        try:
            self._sem.release()
        except ValueError:  # pragma: no cover - a bounded semaphore released twice elsewhere
            pass


class ProbeSocket(socket.socket):
    """A connected target socket handed out by ``ctx.net.connect``: a plain ``socket.socket`` whose
    ``close()`` also frees its per-host connection slot (A7: <= 2 concurrent per target host)."""

    _v3lum_slot: _Slot | None = None
    _v3lum_finalizer: Any = None

    def _v3lum_take_slot(self) -> _Slot | None:
        """Hand the slot over (to the TLS socket wrapping this one): this socket no longer frees it."""
        slot, self._v3lum_slot = self._v3lum_slot, None
        finalizer, self._v3lum_finalizer = self._v3lum_finalizer, None
        if finalizer is not None:
            finalizer.detach()
        return slot

    def close(self) -> None:
        slot, self._v3lum_slot = self._v3lum_slot, None
        try:
            super().close()
        finally:
            if slot is not None:
                slot.release()


class _ProbeSSLSocket(ssl.SSLSocket):
    """The TLS socket of ``ctx.net.wrap_tls``; ``close()`` frees the per-host slot."""

    _v3lum_slot: _Slot | None = None

    def close(self) -> None:
        slot, self._v3lum_slot = self._v3lum_slot, None
        try:
            super().close()
        finally:
            if slot is not None:
                slot.release()


def _adopt(raw: socket.socket, slot: _Slot | None) -> ProbeSocket:
    timeout = raw.gettimeout()
    sock = ProbeSocket(fileno=raw.detach())
    sock.settimeout(timeout)
    sock._v3lum_slot = slot
    if slot is not None:
        # a socket the module forgot to close still frees its slot when it is collected
        sock._v3lum_finalizer = weakref.finalize(sock, slot.release)
    return sock


# ======================================================================================
# Connector
# ======================================================================================


class Connector:
    """Raw TCP/TLS sockets (and external tools) for one target-module run (``ctx.net``).

    ``Connector(*, module='', disclosure='target', opsec=Opsec.LIGHT, deadline=None,
    cancel_event=None, clock=None, http=None, run=None, scope=None, org=None, egress=None,
    limiter=None, ceilings=None, on_request_info=None, config=None)``. ``deadline`` is absolute on
    ``clock.monotonic()``'s scale. ``http`` binds the connector to the module's ``ctx.http``
    (ScopedHttp): egress profiles, limiter, ceilings, profile resolver, ``run``/``scope`` and the
    request ledger come from it. Without it the connector reads the egress settings from the
    configuration and keeps its own counters.

    Modules whose disclosure is not 'target' (or whose opsec is PASSIVE) get :class:`PolicyError`;
    a set cancel flag gives :class:`Cancelled` and a passed deadline :class:`DeadlineExceeded`;
    refused targets PolicyError ('policy' for the SSRF guard, 'scope' for scope and seed binding);
    ceilings RequestCapReached. Socket errors (refused, timeout, unreachable) propagate as
    ``OSError`` so probes can tell them apart.
    """

    def __init__(
        self,
        *,
        module: str = "",
        disclosure: str = "target",
        opsec: Any = Opsec.LIGHT,
        deadline: float | None = None,
        cancel_event: Any = None,
        clock: Clock | None = None,
        http: Any = None,
        run: Any = None,
        scope: Any = None,
        org: Any = None,
        egress: EgressProfiles | None = None,
        limiter: HostLimiter | None = None,
        ceilings: ContactCeilings | None = None,
        on_request_info: Any = None,
        config: Any = None,
    ) -> None:
        self.module = module or ""
        self.disclosure = str(disclosure or "")
        self.opsec = _opsec_label(opsec)
        self.deadline = deadline
        self.cancel_event = cancel_event
        self.clock: Clock = clock or SYSTEM_CLOCK
        self.http = http
        client = getattr(http, "client", None) if http is not None else None
        self._client = client if getattr(client, "accepts_scope_kwargs", False) else None
        self.run = run if run is not None else getattr(http, "run", None)
        self.scope = scope if scope is not None else getattr(http, "scope", None)
        self.org = org
        self._egress = egress
        self._limiter = limiter
        self._ceilings = ceilings
        self.on_request_info = on_request_info
        self._config = config
        self.connections = 0
        #: RequestInfo of every connection and tool launch of this connector (CONNECT / EXEC)
        self.request_log: list[RequestInfo] = []
        self._lock = threading.Lock()
        self._open: dict[int, weakref.ref[Any]] = {}
        self._watcher: threading.Thread | None = None
        self._own_client: Any = None

    # ------------------------------------------------------------------ plumbing
    def _label(self) -> str:
        return self.module or "module"

    def _settings(self) -> Any:
        if self._config is None:
            from v3lum.config import Config

            self._config = Config.load()
        return self._config

    @property
    def egress(self) -> EgressProfiles:
        """The egress profiles in use (the bound client's, an injected set, or from the settings)."""
        if self._egress is None:
            found = getattr(self._client, "egress", None)
            self._egress = found if found is not None else EgressProfiles(self._settings(), clock=self.clock)
        return self._egress

    @property
    def limiter(self) -> HostLimiter:
        if self._limiter is None:
            found = getattr(self._client, "limiter", None)
            self._limiter = found if found is not None else HostLimiter(clock=self.clock)
        return self._limiter

    @property
    def ceilings(self) -> ContactCeilings:
        if self._ceilings is None:
            found = getattr(self._client, "ceilings", None)
            self._ceilings = found if found is not None else ContactCeilings()
        return self._ceilings

    @property
    def case_id(self) -> str:
        return str(getattr(self.run, "case_id", "") or "") if self.run is not None else ""

    @property
    def bound(self) -> bool:
        """True with a scope or a run that carries its entity (seed binding applies)."""
        return self.scope is not None or (self.run is not None and getattr(self.run, "entity", None) is not None)

    @property
    def internal_seed(self) -> bool:
        return bool(getattr(self.run, "internal_seed", False)) if self.run is not None else False

    def _resolution_client(self) -> Any:
        if self._client is not None:
            return self._client
        if self._own_client is None:
            from v3lum.core.http import HttpClient

            self._own_client = HttpClient(settings=self._settings(), egress=self.egress, clock=self.clock, ceilings=self.ceilings, limiter=self.limiter)
        return self._own_client

    def _check(self) -> None:
        if self.disclosure != "target":
            raise PolicyError("policy", f"{self._label()}: raw sockets are only for target-contact (LIGHT/ACTIVE) modules (disclosure {self.disclosure!r})")
        if self.opsec == "passive":
            raise PolicyError("policy", f"{self._label()}: a PASSIVE module may not open sockets to a target")
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise Cancelled()
        if self.deadline is not None and self.clock.monotonic() >= self.deadline:
            raise DeadlineExceeded(f"{self._label()}: run deadline reached: connection not opened")

    def _timeout(self, timeout: float | None) -> float:
        value = DEFAULT_CONNECT_TIMEOUT if timeout is None else max(0.001, float(timeout))
        if self.deadline is not None:
            remaining = self.deadline - self.clock.monotonic()
            if remaining <= 0:
                raise DeadlineExceeded(f"{self._label()}: run deadline reached: connection not opened")
            value = min(value, remaining)
        return value

    def _interrupt(self, what: str) -> None:
        """Raise Cancelled / DeadlineExceeded once the kill switch fired or the run deadline passed
        (checked every 100 ms while a connection or a proxy handshake is pending)."""
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise Cancelled(f"{self._label()}: cancelled while {what}")
        if self.deadline is not None and self.clock.monotonic() >= self.deadline:
            raise DeadlineExceeded(f"{self._label()}: run deadline reached while {what}")

    def _seedless(self) -> bool:
        """A module context without an entity and without a scope (a self-test, not a scan run)."""
        return self.run is not None and getattr(self.run, "entity", None) is None and self.scope is None

    def _wait(self, seconds: float) -> None:
        """Wait for a pacing slot, bounded by the deadline and cut short by the kill switch."""
        if seconds <= 0:
            return
        if self.deadline is not None and self.clock.monotonic() + seconds >= self.deadline:
            raise DeadlineExceeded(f"{self._label()}: run deadline reached while waiting for a probe slot")
        event = self.cancel_event
        if event is not None and isinstance(self.clock, SystemClock) and callable(getattr(event, "wait", None)):
            event.wait(seconds)
        else:
            self.clock.sleep(seconds)
        if event is not None and event.is_set():
            raise Cancelled()

    # ------------------------------------------------------------------ target checks
    def _name_allowed(self, host: str) -> bool:
        if self.scope is not None:
            return _scope_call(self.scope, "matches_host", host)
        return self.internal_seed

    def _check_ip(self, host: str, ip: str) -> None:
        problem = ip_problem(ip)
        if not problem:
            return
        if self.scope is not None:
            if _scope_call(self.scope, "matches_ip", ip):
                return
        elif self.internal_seed and (not is_metadata_ip(ip) or host_within(ip, self._seed_hosts())):
            return
        shown = f"{host} ({ip})" if normalize_host(host) != normalize_host(ip) else ip
        raise PolicyError(
            "policy",
            f"{self._label()}: refused a connection to {shown}: {problem} address (SSRF guard, AR02); internal targets need an "
            "internal analyst-typed seed or a scope that lists them",
        )

    def _seed_hosts(self) -> tuple[str, ...]:
        return entity_hosts(getattr(self.run, "entity", None)) if self.run is not None else ()

    def _authorize(self, host: str, *, what: str = "connection", probe: str = "network", url: str | None = None) -> tuple[str, list[str], str]:
        """Every check before contact with ``host``: (normalized host, checked addresses, profile).
        ``probe``/``url`` select the scope rule ('network': CDN and third_party_hosted addresses need
        their IP/CIDR listed; 'http' with the target URL: shared_infra_hosts and URL prefixes)."""
        name = normalize_host(host)
        if not name:
            raise ValueError("a target host name or IP address is required")
        profile = self.egress.profile_for(self.opsec)
        self.egress.check(profile)
        self.egress.ensure_reachable(profile)
        prof = self.egress.profile(profile)
        onion = name == "onion" or name.endswith(".onion")
        literal = parse_ip(name)
        if onion:
            # a SOCKS LIGHT route used for .onion is Tor whatever its port ('detected by .onion use')
            if self.opsec != "light" or not (prof.tor or (profile == "light" and prof.scheme.startswith("socks"))):
                raise PolicyError(
                    "policy",
                    f"{self._label()}: {name}: onion services are reached only for LIGHT reads through a Tor proxy_light "
                    "(v3lum config set proxy_light socks5h://127.0.0.1:9050; A13)",
                )
        else:
            problem = host_problem(name)
            if problem and literal is None and (problem.startswith("ambiguous") or not self._name_allowed(name)):
                raise PolicyError(
                    "policy",
                    f"{self._label()}: refused a {what} to {name} ({problem}; SSRF guard, AR02); internal targets need an internal "
                    "analyst-typed seed or a scope that lists them",
                )
        seedless = self._seedless()
        if self.opsec == "active" and self.scope is None and not (seedless and self.internal_seed):
            raise PolicyError("scope", f"{self._label()}: ACTIVE contact needs a scope file (--scope FILE) bound to --authorized (A7)")
        if self.scope is not None:
            _check_window(self.scope, self.clock, self._label())
        if seedless and self.opsec == "active" and (onion or (literal is not None and not ip_problem(literal)) or (literal is None and not host_problem(name))):
            raise PolicyError(
                "scope",
                f"{self._label()}: {name}: an ACTIVE context without an entity or a scope (a self-test) reaches only internal hosts with "
                "RunInfo.internal_seed; ACTIVE contact needs --scope FILE (A7)",
            )
        if self.scope is None and self.bound and self.opsec == "light":
            if not bool(getattr(self.run, "is_seed", True)):
                raise PolicyError("scope", f"{self._label()}: LIGHT contact runs only on analyst-typed seeds, never on pivots (A7)")
            seeds = self._seed_hosts()
            if seeds and not host_within(name, seeds):
                raise PolicyError("scope", f"{self._label()}: LIGHT {what} to {name} is outside the seed {', '.join(seeds)} (A7)")
        if self.scope is not None and url is not None and not _scope_call(self.scope, "matches_url", url):
            raise PolicyError("scope", f"{self._label()}: {url} is outside the scope (A7)")
        ips: list[str] = []
        if not onion:
            if literal is not None:
                ips = [str(literal)]
            else:
                ips = self._resolution_client().resolve_host(
                    name, profile=profile, deadline=self.deadline, cancel_event=self.cancel_event, strict=False, info_sink=self._dns_sink,
                )
        if self.scope is not None:
            # the scope decides first (exclusions, targets, unlisted private/CDN/third_party_hosted)
            ok, why = _scope_allows(self.scope, name, ips, probe=probe, url=url, org=self.org if probe == "network" else None)
            if not ok:
                raise PolicyError("scope", f"{self._label()}: {why or name + ' is outside the scope'} (A7)")
        for ip in ips:
            self._check_ip(name, ip)
        return name, ips, profile

    # ------------------------------------------------------------------ pacing and slots
    def _pace(self, host: str) -> None:
        """<= 10 probes/s per host (LIGHT 1/s; lower with the scope's max_rps) and the global
        connection-attempt rate (100/s; scope max_pps up to 1000)."""
        delay = self.limiter.reserve(host, 1.0 / contact_rps(self.opsec, self.scope))
        pps = max_pps(self.scope)
        delay = max(delay, self.limiter.reserve(f"__pps__:{pps}", 1.0 / pps))
        self._wait(delay)

    def _acquire_slot(self, host: str) -> _Slot:
        slots = contact_concurrency(self.opsec, self.scope)
        sem = self.limiter.slot(f"contact:{slots}:{host}", slots)
        while True:
            if self.cancel_event is not None and self.cancel_event.is_set():
                raise Cancelled()
            if self.deadline is not None and self.clock.monotonic() >= self.deadline:
                raise DeadlineExceeded(f"{self._label()}: run deadline reached while waiting for a connection slot to {host}")
            if sem.acquire(timeout=_WATCH_INTERVAL):
                return _Slot(sem)

    # ------------------------------------------------------------------ ledger
    def _dns_sink(self, info: RequestInfo) -> None:
        """DoH lookups of target names reach the module's disclosure ledger (``ctx.http``)."""
        absorb = getattr(self.http, "_absorb", None)
        if callable(absorb):
            absorb([info])

    def record(self, method: str, host: str, port: int = 0, *, url: str = "", path: str = "", ip: str = "", profile: str = "default",
               status: int = 0, nbytes: int = 0, elapsed: float = 0.0, error: str = "") -> RequestInfo:
        """Add one CONNECT/EXEC record to the request ledger (this connector's ``request_log``, the
        bound ``ctx.http.request_log`` and the runtime event bus)."""
        info = RequestInfo(
            ts=self.clock.now().astimezone(_dt.timezone.utc).isoformat(timespec="milliseconds"),
            method=method, url=redact_url(url or _tcp_url(host, port)), host=host, path=path, status=int(status or 0), bytes=int(nbytes or 0),
            elapsed=round(float(elapsed or 0.0), 6), cached=False, error=error, module=self.module, opsec=self.opsec,
            egress_profile=profile, resolved_ip=ip, port=int(port or 0),
        )
        with self._lock:
            self.request_log.append(info)
        absorb = getattr(self.http, "_absorb", None)
        sinks = [getattr(self._client, "on_request_info", None), self.on_request_info]
        if callable(absorb):
            try:
                absorb([info])
            except Exception:  # pragma: no cover - bookkeeping never breaks a probe
                pass
        for fn in sinks:
            if callable(fn):
                try:
                    fn(info)
                except Exception:  # pragma: no cover - observers never break a probe
                    pass
        return info

    # ------------------------------------------------------------------ sockets
    def connect(self, host: str, port: int, *, timeout: float | None = None) -> socket.socket:
        """Open a TCP connection to ``host``:``port`` through the module's egress profile after the
        SSRF, scope/seed and ceiling checks (see the module docstring); the timeout is capped by the
        run deadline. Returns a :class:`ProbeSocket` (close it to free the per-host slot)."""
        self._check()
        if not host or not isinstance(host, str):
            raise ValueError("connect() needs a host name or IP address")
        port = int(port)
        if not 0 < port < 65536:
            raise ValueError(f"invalid port {port}")
        name, ips, profile = self._authorize(host)
        ip = _pick_ip(ips) if ips else ""
        self.ceilings.port(name, port, case_id=self.case_id)  # <= 1000 TCP ports per host
        self.ceilings.charge(self.opsec, name, case_id=self.case_id, scope=self.scope)
        self._pace(name)
        self._check()
        slot = self._acquire_slot(name)
        start = self.clock.monotonic()
        try:
            raw = self._open_socket(name, ip, port, profile, self._timeout(timeout))
        except BaseException as exc:
            slot.release()
            self.record("CONNECT", name, port, ip=ip, profile=profile, elapsed=self.clock.monotonic() - start, error=type(exc).__name__)
            raise
        self.record("CONNECT", name, port, ip=ip, profile=profile, elapsed=self.clock.monotonic() - start)
        sock = _adopt(raw, slot)
        self._track(sock)
        with self._lock:
            self.connections += 1
        return sock

    def _open_socket(self, name: str, ip: str, port: int, profile: str, timeout: float) -> socket.socket:
        prof = self.egress.profile(profile)
        dest = ip or name  # the checked address on every route; an onion name only through Tor
        if not prof.proxy:
            if parse_ip(dest) is None:  # never a local getaddrinfo for a target name
                raise PolicyError("policy", f"{self._label()}: {dest} was not resolved through the egress profile: connection refused")
            return self._tcp(dest, port, timeout, what=f"connecting to {_tcp_url(dest, port)}")
        parts = urlsplit(prof.proxy)
        if prof.scheme.startswith("socks"):
            return self._socks_connect(prof, parts, dest, port, timeout)
        if prof.scheme == "http":
            return self._http_connect(prof, parts, dest, port, timeout)
        raise PolicyError("policy", f"{prof.setting}: raw sockets cannot use an {prof.scheme}:// proxy (use http:// or socks5h://): connection refused")

    def _tcp(self, addr: str, port: int, timeout: float, *, what: str) -> socket.socket:
        """A TCP connection to an IP address that the kill switch and the run deadline interrupt
        within 100 ms (non-blocking connect polled with select: a pending SYN to a silent host never
        outlives the cancel flag, A7). Returns a blocking socket with ``timeout``."""
        family = socket.AF_INET6 if ":" in addr else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.setblocking(False)
            with contextlib.suppress(BlockingIOError, InterruptedError):
                sock.connect((addr, port))  # EINPROGRESS: completion is polled below
            end = time.monotonic() + timeout
            while True:
                self._interrupt(what)
                left = end - time.monotonic()
                if left <= 0:
                    raise TimeoutError(f"timed out {what}")
                _readable, writable, failed = select.select([], [sock], [sock], min(_WATCH_INTERVAL, left))
                if writable or failed:
                    error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if error:
                        raise OSError(error, os.strerror(error))
                    break
            sock.settimeout(timeout)  # back to blocking mode, with the probe's timeout
            return sock
        except BaseException:
            sock.close()
            raise

    def _proxy_tcp(self, prof: EgressProfile, parts: Any, timeout: float) -> socket.socket:
        """The (cancellable) TCP connection to an HTTP proxy; PolicyError when it is unreachable."""
        host, port = str(parts.hostname or ""), _proxy_port(parts)
        what = f"connecting to {prof.label}"
        try:
            literal = parse_ip(host)
            addr = str(literal) if literal is not None else str(socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)[0][4][0])
            return self._tcp(addr, port, timeout, what=what)
        except (Cancelled, DeadlineExceeded):
            raise
        except (OSError, IndexError, RuntimeError):  # RuntimeError: the test network guard
            raise PolicyError("policy", f"{prof.setting} unreachable: connection refused (never opened through the default route)") from None

    def _socks_connect(self, prof: EgressProfile, parts: Any, dest: str, port: int, timeout: float) -> socket.socket:
        try:
            import socks  # PySocks (optional extra)
        except ImportError:
            raise PolicyError("policy", f"{prof.setting}: SOCKS proxies need the optional package PySocks: connection refused") from None
        kind = socks.SOCKS5 if prof.scheme.startswith("socks5") else socks.SOCKS4
        host = str(parts.hostname or "")
        literal = parse_ip(host)
        try:
            family = (socket.AF_INET6 if literal.version == 6 else socket.AF_INET) if literal is not None else socket.getaddrinfo(host, None, 0, socket.SOCK_STREAM)[0][0]
        except (OSError, IndexError, RuntimeError):
            raise PolicyError("policy", f"{prof.setting} unreachable: connection refused (never opened through the default route)") from None
        sock = socks.socksocket(family, socket.SOCK_STREAM)
        sock.set_proxy(
            kind, host, _proxy_port(parts), True,
            unquote(parts.username) if parts.username else None, unquote(parts.password) if parts.password else None,
        )
        sock.settimeout(timeout)
        outcome: dict[str, BaseException] = {}
        done, abandoned = threading.Event(), threading.Event()

        def handshake() -> None:
            try:
                sock.connect((dest, port))  # TCP to the proxy, then the SOCKS CONNECT (remote DNS)
            except BaseException as exc:  # noqa: BLE001 - handed to the caller below
                outcome["error"] = exc
            finally:
                if abandoned.is_set() and "error" not in outcome:
                    with contextlib.suppress(OSError):
                        sock.close()  # the run was cancelled meanwhile: never hand the tunnel out
                done.set()

        worker = threading.Thread(target=handshake, name=f"v3lum-socks-{self._label()}", daemon=True)
        worker.start()
        try:
            while not done.wait(_WATCH_INTERVAL):
                self._interrupt(f"connecting through {prof.label}")
        except BaseException:
            # the kill switch fired mid-handshake: shut the half-open tunnel down (the proxy drops its
            # own connection to the target) and never hand it out
            abandoned.set()
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            if done.wait(5 * _WATCH_INTERVAL):
                with contextlib.suppress(OSError):
                    sock.close()
            raise
        error = outcome.get("error")
        if error is None:
            return sock
        with contextlib.suppress(OSError):
            sock.close()
        if isinstance(error, socks.ProxyConnectionError):
            raise PolicyError("policy", f"{prof.setting} unreachable: connection refused (never opened through the default route)") from None
        if isinstance(error, socks.ProxyError):  # the proxy answered: the target refused or is unreachable
            raise OSError(f"{prof.label} could not reach {dest}:{port}: {error}") from None
        raise error

    def _http_connect(self, prof: EgressProfile, parts: Any, dest: str, port: int, timeout: float) -> socket.socket:
        sock = self._proxy_tcp(prof, parts, timeout)
        target = f"[{dest}]:{port}" if ":" in dest else f"{dest}:{port}"
        lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
        if parts.username:
            import base64

            token = base64.b64encode(f"{unquote(parts.username)}:{unquote(parts.password or '')}".encode()).decode("ascii")
            lines.append(f"Proxy-Authorization: Basic {token}")
        what = f"opening a tunnel through {prof.label}"
        try:
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
            reply = b""
            end = time.monotonic() + timeout
            sock.settimeout(_WATCH_INTERVAL)  # short reads: the kill switch is checked between them
            # one byte at a time: whatever the target sends right after the proxy's header is the
            # module's data and stays in the socket
            while not reply.endswith(b"\r\n\r\n") and len(reply) < 8192:
                self._interrupt(what)
                if time.monotonic() >= end:
                    raise TimeoutError(f"timed out {what}")
                try:
                    chunk = sock.recv(1)
                except TimeoutError:
                    continue
                if not chunk:
                    break
                reply += chunk
            sock.settimeout(timeout)
        except BaseException:
            sock.close()
            raise
        status = reply.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        fields = status.split()
        if len(fields) < 2 or fields[1] != "200":
            sock.close()
            raise OSError(f"{prof.label} could not open a tunnel to {target}: {status[:80] or 'no answer'}")
        return sock

    def wrap_tls(self, sock: socket.socket, server_hostname: str, *, timeout: float | None = None) -> ssl.SSLSocket:
        """TLS handshake over ``sock`` with the default verifying context (verification is never
        disabled; certificate problems raise ``ssl.SSLCertVerificationError``)."""
        try:
            self._check()
            sock.settimeout(self._timeout(timeout))
        except BaseException:
            sock.close()
            raise
        context = ssl.create_default_context()
        slot = None
        if isinstance(sock, ProbeSocket):
            slot = sock._v3lum_take_slot()  # the TLS socket takes over the per-host slot
            context.sslsocket_class = _ProbeSSLSocket  # type: ignore[assignment]
        try:
            tls = context.wrap_socket(sock, server_hostname=server_hostname)
        except BaseException:
            if slot is not None:
                slot.release()
            sock.close()
            raise
        if slot is not None:
            tls._v3lum_slot = slot  # type: ignore[attr-defined]
            weakref.finalize(tls, slot.release)
        self._track(tls)
        return tls

    # ------------------------------------------------------------------ kill switch
    def _track(self, sock: Any) -> None:
        if self.cancel_event is None and self.deadline is None:
            return
        with self._lock:
            self._open[id(sock)] = weakref.ref(sock)
            if self._watcher is None or not self._watcher.is_alive():
                self._watcher = threading.Thread(target=self._watch, name=f"v3lum-net-{self._label()}", daemon=True)
                self._watcher.start()

    def _live(self) -> list[Any]:
        with self._lock:
            live = []
            for key, ref in list(self._open.items()):
                sock = ref()
                if sock is None or sock.fileno() == -1:
                    self._open.pop(key, None)
                else:
                    live.append(sock)
            return live

    def _watch(self) -> None:
        """Shut every open socket of this run down once the kill switch or the deadline fires."""
        while True:
            live = self._live()
            if not live:
                return
            stop = (self.cancel_event is not None and self.cancel_event.is_set()) or (
                self.deadline is not None and self.clock.monotonic() >= self.deadline
            )
            if stop:
                self.close()
                return
            event = self.cancel_event
            if event is not None and callable(getattr(event, "wait", None)):
                event.wait(_WATCH_INTERVAL)
            else:
                time.sleep(_WATCH_INTERVAL)

    def close(self) -> None:
        """Shut down and close every socket this connector opened that is still open."""
        for sock in self._live():
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:  # pragma: no cover
                pass

    # ------------------------------------------------------------------ wordlists and tools
    @staticmethod
    def cap_wordlist(seq: Iterable[Any]) -> list[Any]:
        """The first 5000 entries of a wordlist (A7 ceiling for every wordlist, --wordlist included)."""
        return cap_wordlist(seq)

    def run_tool(self, name: str, args: Iterable[str], *, targets: Iterable[str], timeout: float | None = None) -> Any:
        """Run the registered external tool ``name`` against ``targets`` (``v3lum.core.tools.run``):
        the only sanctioned subprocess path for modules. Returns a ``ToolResult``."""
        from v3lum.core import tools

        return tools.run(self, name, args, targets=targets, timeout=timeout)
