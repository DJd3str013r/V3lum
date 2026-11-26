"""Shared pytest setup (module-author contract v2, section 21).

Every test runs with:

* an isolated ``V3LUM_HOME`` (tmp dir) and ``V3LUM_STRICT=1`` (strict contract mode);
* an environment scrubbed of API keys: ``config.key_env_names()`` (every key alias of the key
  registry, provider fragments included), any variable ending in ``_API_KEY``, ``_TOKEN``,
  ``_AUTH_KEY`` (and ``_APIKEY``, ``_KEY``, ``_SECRET``, ``_PASSWORD``) and every ``V3LUM_*``
  variable except ``V3LUM_HOME``/``V3LUM_LIVE``;
* a network guard: ``socket.socket.connect``/``connect_ex``, ``socket.create_connection`` and
  ``socket.getaddrinfo`` refuse anything but loopback (127.0.0.0/8, ::1, 'localhost') with
  ``RuntimeError('network disabled in tests')``; so do the connectionless sends
  ``socket.socket.sendto``/``sendmsg`` (UDP DNS, e.g. dnspython) and the legacy resolver calls
  ``socket.gethostbyname``/``gethostbyname_ex``/``gethostbyaddr``/``getnameinfo``. Proxy
  variables are removed so a local proxy cannot tunnel out. Only tests marked
  ``@pytest.mark.live`` run without the guard, and only when ``V3LUM_LIVE=1``.

Fixtures: ``isolated_home`` (autouse), ``network_guard`` (autouse), ``clean_registry``,
``fake_clock``, ``fake_http``. Markers: live, safety, acceptance, slow.
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
import socket
from collections.abc import Iterator
from typing import Any

import pytest

#: key-like variable suffixes always scrubbed (the contract's _API_KEY/_TOKEN/_AUTH_KEY plus other
#: common credential spellings: a developer's secrets never reach a test).
KEY_SUFFIXES = ("_API_KEY", "_TOKEN", "_AUTH_KEY", "_APIKEY", "_KEY", "_SECRET", "_PASSWORD")
KEEP_V3LUM = frozenset({"V3LUM_HOME", "V3LUM_LIVE"})
PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
NETWORK_DISABLED = "network disabled in tests"
MARKERS = {
    "live": "talks to real public services; runs only with V3LUM_LIVE=1 (benign values only)",
    "safety": "AR20 safety suite (gates every LIGHT/ACTIVE merge)",
    "acceptance": "AR21 golden-path acceptance harness (time budget)",
    "slow": "slow test (excluded from the quick loop with -m 'not slow')",
}


# --------------------------------------------------------------------------------------
# environment scrub
# --------------------------------------------------------------------------------------


def key_env_names() -> set[str]:
    """Every environment variable that can carry an API key (from the key registry)."""
    from v3lum import config

    names = set(config.key_env_names())
    for key, (_desc, _url, aliases) in config.KNOWN_KEYS.items():  # legacy table, always covered
        names.add(f"V3LUM_KEY_{key.upper()}")
        names |= set(aliases)
    return names


def scrub_names(environ: dict[str, str] | os._Environ[str]) -> list[str]:
    """Names of ``environ`` the scrub removes (keys, key-like variables, V3LUM_* settings)."""
    keyed = key_env_names()
    out = []
    for name in environ:
        if name in KEEP_V3LUM:
            continue
        if name in keyed or name.endswith(KEY_SUFFIXES) or name.startswith("V3LUM_"):
            out.append(name)
    return sorted(out)


def scrub_env(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Remove every key-carrying variable from the environment for the current test."""
    names = scrub_names(os.environ)
    for name in names:
        monkeypatch.delenv(name, raising=False)
    return names


def _reset_redactor() -> None:
    from v3lum.core import redact

    redact.clear()


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Isolated V3LUM_HOME, no developer keys, strict contract mode, fresh redactor."""
    home = tmp_path / "v3lum_home"
    home.mkdir()
    scrub_env(monkeypatch)
    monkeypatch.setenv("V3LUM_HOME", str(home))
    monkeypatch.setenv("V3LUM_STRICT", "1")
    monkeypatch.setenv("NO_COLOR", "1")
    _reset_redactor()
    yield home
    _reset_redactor()


# --------------------------------------------------------------------------------------
# network guard
# --------------------------------------------------------------------------------------


def is_loopback(host: Any) -> bool:
    """True for loopback destinations: 127.0.0.0/8, ::1 (also IPv4-mapped) and 'localhost'."""
    if host is None:
        return True
    if isinstance(host, bytes):
        host = host.decode("ascii", errors="replace")
    text = str(host).strip().rstrip(".").lower()
    if text in ("", "localhost"):
        return True
    text = text.strip("[]")
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped.is_loopback
    return addr.is_loopback


def _check_address(address: Any, family: int | None = None) -> None:
    if family is not None and family == getattr(socket, "AF_UNIX", object()):
        return
    if isinstance(address, (str, bytes)):  # AF_UNIX path
        return
    host = address[0] if isinstance(address, (tuple, list)) and address else address
    if not is_loopback(host):
        raise RuntimeError(f"{NETWORK_DISABLED}: {host!r}")


def _check_host(host: Any) -> None:
    if not is_loopback(host):
        raise RuntimeError(f"{NETWORK_DISABLED}: {host!r}")


def install_network_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch the socket layer so only loopback destinations can be reached (TCP connects, UDP
    sends and every name/address lookup)."""
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_sendto = socket.socket.sendto
    real_sendmsg = getattr(socket.socket, "sendmsg", None)
    real_create_connection = socket.create_connection
    real_getaddrinfo = socket.getaddrinfo
    lookups = {name: getattr(socket, name) for name in ("gethostbyname", "gethostbyname_ex", "gethostbyaddr") if hasattr(socket, name)}
    real_getnameinfo = socket.getnameinfo

    def connect(self, address):  # noqa: ANN001 - socket signature
        _check_address(address, self.family)
        return real_connect(self, address)

    def connect_ex(self, address):  # noqa: ANN001
        _check_address(address, self.family)
        return real_connect_ex(self, address)

    def sendto(self, data, *args):  # noqa: ANN001 - sendto(data, address) / sendto(data, flags, address)
        if args:
            _check_address(args[-1], self.family)
        return real_sendto(self, data, *args)

    def sendmsg(self, buffers, ancdata=(), flags=0, address=None):  # noqa: ANN001
        if address is not None:
            _check_address(address, self.family)
            return real_sendmsg(self, buffers, ancdata, flags, address)
        return real_sendmsg(self, buffers, ancdata, flags)

    def create_connection(address, *args, **kwargs):  # noqa: ANN001
        _check_address(address)
        return real_create_connection(address, *args, **kwargs)

    def getaddrinfo(host, *args, **kwargs):  # noqa: ANN001
        _check_host(host)
        return real_getaddrinfo(host, *args, **kwargs)

    def guarded_lookup(real):  # noqa: ANN001, ANN202
        def lookup(host, *args, **kwargs):  # noqa: ANN001
            _check_host(host)
            return real(host, *args, **kwargs)

        return lookup

    def getnameinfo(sockaddr, flags):  # noqa: ANN001
        _check_address(sockaddr)
        return real_getnameinfo(sockaddr, flags)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", sendto)
    if real_sendmsg is not None:
        monkeypatch.setattr(socket.socket, "sendmsg", sendmsg)
    monkeypatch.setattr(socket, "create_connection", create_connection)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    for name, real in lookups.items():
        monkeypatch.setattr(socket, name, guarded_lookup(real))
    monkeypatch.setattr(socket, "getnameinfo", getnameinfo)
    for name in PROXY_VARS:  # a loopback proxy must not tunnel tests out
        monkeypatch.delenv(name, raising=False)


def live_allowed(item: Any) -> bool:
    return item.get_closest_marker("live") is not None and os.environ.get("V3LUM_LIVE") == "1"


@pytest.fixture(autouse=True)
def network_guard(request, monkeypatch):
    """Autouse: no network beyond loopback, except @pytest.mark.live tests with V3LUM_LIVE=1."""
    if live_allowed(request.node):
        yield False
        return
    install_network_guard(monkeypatch)
    yield True


# --------------------------------------------------------------------------------------
# registry isolation and fakes
# --------------------------------------------------------------------------------------


def _provider_snapshot() -> Any:
    from v3lum.core import providers

    return providers.snapshot()


def _provider_restore(state: Any) -> None:
    from v3lum.core import providers

    providers.restore(state)


def _settings_snapshot() -> dict[str, Any]:
    from v3lum import config

    return dict(config.SETTINGS_META)


def _restore_settings(snapshot: dict[str, Any]) -> None:
    from v3lum import config

    config.SETTINGS_META.clear()
    config.SETTINGS_META.update(snapshot)


def _reload_caches() -> None:
    from v3lum.core import links, vocab

    vocab.reload()
    links.reload()


def _import_time_tables() -> list[dict[str, Any]]:
    """Registries that module files fill at import time (sanitizer schemas, datasets, runtime noise
    lists) and the module load errors: a synthetic module registering into them must not leak into
    later tests (the registry contract test reads them)."""
    from v3lum.core import datasets, noise, sanitize
    from v3lum.core import module as modreg

    tables = [getattr(sanitize, "_SCHEMAS", None), getattr(datasets, "DATASETS", None), getattr(noise, "_RUNTIME", None), getattr(modreg, "_LOAD_ERRORS", None)]
    return [t for t in tables if isinstance(t, dict)]


@contextlib.contextmanager
def registry_snapshot() -> Iterator[Any]:
    """Snapshot/restore the module REGISTRY, the correlation tables (RULES, RULE_ERRORS,
    RULE_REPLACED and the data-rule compilers), programmatic provider registrations, registered
    module settings, the import-time registries (sanitizer schemas, datasets, runtime noise lists,
    module load errors) and the vocab/link caches (the body of the ``clean_registry`` fixture;
    yields the module REGISTRY)."""
    from v3lum.core import correlate
    from v3lum.core import module as modreg

    modreg.load_modules()
    correlate.load_rules()  # snapshot the loaded rules, never an empty pre-load table
    saved_modules = dict(modreg.REGISTRY)
    saved_rules = correlate.RULES.copy()
    saved_rule_errors = dict(correlate.RULE_ERRORS)
    saved_replaced = dict(correlate.RULE_REPLACED)
    saved_compilers = dict(correlate._COMPILERS)
    saved_providers = _provider_snapshot()
    saved_settings = _settings_snapshot()
    saved_tables = [(table, dict(table)) for table in _import_time_tables()]
    try:
        yield modreg.REGISTRY
    finally:
        for name in [n for n in modreg.REGISTRY if saved_modules.get(n) is not modreg.REGISTRY[n]]:
            modreg.unregister(name)  # also releases the module's registered settings
        modreg.REGISTRY.clear()
        modreg.REGISTRY.update(saved_modules)
        correlate.RULES.clear()
        correlate.RULES.update(saved_rules)
        correlate.RULE_ERRORS.clear()
        correlate.RULE_ERRORS.update(saved_rule_errors)
        correlate.RULE_REPLACED.clear()
        correlate.RULE_REPLACED.update(saved_replaced)
        correlate._COMPILERS.clear()
        correlate._COMPILERS.update(saved_compilers)
        _provider_restore(saved_providers)
        _restore_settings(saved_settings)
        for table, saved in saved_tables:
            table.clear()
            table.update(saved)
        _reload_caches()


@pytest.fixture()
def clean_registry() -> Iterator[Any]:
    """Isolate a test that registers modules, rules, providers, settings, sanitizer schemas,
    datasets or noise lists: everything is restored afterwards (see ``registry_snapshot``)."""
    with registry_snapshot() as registry:
        yield registry


@pytest.fixture()
def fake_clock():
    from tests.fakes import FakeClock

    return FakeClock()


@pytest.fixture()
def fake_http(fake_clock):
    from tests.fakes import FakeHttp

    return FakeHttp(clock=fake_clock)


# --------------------------------------------------------------------------------------
# markers
# --------------------------------------------------------------------------------------


def pytest_configure(config):
    for name, text in MARKERS.items():
        config.addinivalue_line("markers", f"{name}: {text}")


def pytest_collection_modifyitems(config, items):
    if os.environ.get("V3LUM_LIVE") == "1":
        return
    skip = pytest.mark.skip(reason="live API test: set V3LUM_LIVE=1 to run")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip)
