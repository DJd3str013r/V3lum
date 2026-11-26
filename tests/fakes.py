"""Module-author test kit (contract v2, section 21): offline HTTP, fake clock, runtime factories.

Typical module test::

    from tests.fakes import FakeHttp, module_fixture, run_module

    def test_parses_response():
        http = FakeHttp().add("GET", "https://api.example.test/v1/ip/203.0.113.7",
                              json=module_fixture("example_source", "ok.json"))
        res = run_module(ExampleSource, "ipv4:203.0.113.7", http)   # engine path: status mapping,
        assert res.status.value == "ok"                             # sanitizer, caps, host checks
        http.assert_hosts_within(ExampleSource)

``FakeHttp`` is both a *Transport* (``send()``: one hop, used behind the real ``HttpClient`` built by
``make_runtime`` so classification, redirects, host checks, provider profiles and redaction run over
the fake) and a legacy client (``request()``). Routes match on method + URL: exact URLs compare
normalised (lower-case scheme/host, query parameters order-insensitive), a URL ending with ``*`` is
a prefix and a compiled regex is searched. Unmatched requests raise :class:`UnexpectedRequest` (an
``AssertionError``) listing the known routes and are recorded in ``FakeHttp.unexpected``;
``run_module`` fails the test when one happened even if the engine turned it into an ERROR result,
so tests never pass on a missing route or reach the network by accident (the conftest network
guard is the second line of defence).
"""

from __future__ import annotations

import base64
import contextlib
import json as _json
import re
import threading
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, quote_plus, unquote, urlencode, urljoin, urlsplit

from v3lum.config import Config
from v3lum.core import providers as providers_mod
from v3lum.core.context import RunInfo, Runtime, ScanOptions, doh_hosts, settings_hosts
from v3lum.core.dns import DOH_PROVIDERS
from v3lum.core.entities import Entity, EntityType
from v3lum.core.http import DeadlineExceeded, NetworkError, Response, host_allowed
from v3lum.core.models import Opsec

FIXTURES = Path(__file__).parent / "fixtures"

#: Hosts of the core public DoH resolvers (always allowed by ``assert_hosts_within``); derived from
#: ``v3lum.core.dns.DOH_PROVIDERS`` so the kit never drifts from the resolver catalogue.
DOH_HOSTS: frozenset[str] = frozenset(
    (urlsplit(spec["url"]).hostname or "").lower() for spec in DOH_PROVIDERS.values() if spec.get("url")
)

_GOOGLE_DOH = DOH_PROVIDERS["google"]["url"]
_CLOUDFLARE_DOH = DOH_PROVIDERS["cloudflare"]["url"]
_DEFAULT_PORTS = {"http": 80, "https": 443}


# --------------------------------------------------------------------------------------
# fixtures on disk
# --------------------------------------------------------------------------------------


def fixture(name: str) -> Any:
    """Load ``tests/fixtures/<name>`` (JSON parsed when the name ends with .json, else text)."""
    path = FIXTURES / name
    text = path.read_text(encoding="utf-8")
    return _json.loads(text) if name.endswith(".json") else text


def module_fixture(module: Any, name: str) -> Any:
    """Load ``tests/fixtures/<module>/<name>`` (module = class or name; JSON parsed for .json)."""
    mod_name = module if isinstance(module, str) else getattr(module, "name", "")
    if not mod_name:
        raise ValueError(f"module_fixture needs a module name or class, got {module!r}")
    return fixture(f"{mod_name}/{name}")


# --------------------------------------------------------------------------------------
# clock
# --------------------------------------------------------------------------------------


class FakeClock:
    """Deterministic clock (``now``, ``monotonic``, ``sleep``, ``advance``); sleep never blocks."""

    DEFAULT_START = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)

    def __init__(self, start: datetime | str | None = None, *, monotonic: float = 1000.0) -> None:
        if isinstance(start, str):
            start = datetime.fromisoformat(start.replace("Z", "+00:00"))
        if start is not None and start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        self._start = start or self.DEFAULT_START
        self._mono0 = float(monotonic)
        self._offset = 0.0
        self._lock = threading.Lock()
        self.sleeps: list[float] = []

    def now(self) -> datetime:
        with self._lock:
            return self._start + timedelta(seconds=self._offset)

    def monotonic(self) -> float:
        with self._lock:
            return self._mono0 + self._offset

    def sleep(self, seconds: float) -> None:
        seconds = max(0.0, float(seconds))
        with self._lock:
            self.sleeps.append(seconds)
            self._offset += seconds

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._offset += max(0.0, float(seconds))


# --------------------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------------------


@dataclass
class _Route:
    method: str
    pattern: Any
    status: int
    content: bytes
    headers: dict[str, str]
    error: Exception | None = None
    final_url: str | None = None
    match_headers: dict[str, Any] = field(default_factory=dict)
    redirect_to: str | None = None
    remaining: int | None = None  # None = unlimited
    latency: float = 0.0
    used: int = 0

    def describe(self) -> str:
        pattern = self.pattern.pattern if isinstance(self.pattern, re.Pattern) else self.pattern
        extra = []
        if self.match_headers:
            extra.append(f"headers={sorted(self.match_headers)}")
        if self.remaining is not None:
            extra.append(f"remaining={self.remaining}")
        return f"{self.method} {pattern}" + (f" ({', '.join(extra)})" if extra else "")


def _normalise(url: str) -> tuple[str, str, str, tuple[tuple[str, str], ...]]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = host if port in (None, _DEFAULT_PORTS.get(scheme)) else f"{host}:{port}"
    path = unquote(parts.path or "/")
    query = tuple(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return scheme, netloc, path, query


def _lower_origin(url: str) -> str:
    parts = urlsplit(url)
    if not parts.scheme:
        return url
    return url.replace(f"{parts.scheme}://{parts.netloc}", f"{parts.scheme.lower()}://{parts.netloc.lower()}", 1)


class UnexpectedRequest(AssertionError):
    """A request no FakeHttp route answers (the test is missing a route or the module misbehaves)."""


class FakeHttp:
    """Offline HTTP double: a Transport (``send``) and a legacy client (``request``)."""

    def __init__(self, *, clock: Any = None) -> None:
        self.routes: list[_Route] = []
        self.calls: list[dict[str, Any]] = []
        #: 'METHOD url' of every request no route answered (run_module fails the test on them).
        self.unexpected: list[str] = []
        #: clock advanced by route latency (make_runtime binds its FakeClock).
        self.clock = clock
        #: config bound by make_runtime (resolves hosts_from_settings in assert_hosts_within).
        self.bound_config: Any = None
        self._lock = threading.RLock()

    # ---- routes --------------------------------------------------------------------------
    def add(
        self,
        method: str,
        url: str | re.Pattern[str],
        *,
        status: int = 200,
        json: Any = None,
        text: str | None = None,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        error: Exception | None = None,
        final_url: str | None = None,
        match_headers: dict[str, Any] | None = None,
        redirect_to: str | None = None,
        times: int | None = None,
        latency: float = 0.0,
    ) -> FakeHttp:
        """Add a canned route; returns self so calls can be chained.

        ``times`` limits reuse (several routes for one URL give a response sequence);
        ``match_headers`` requires request headers (exact value or compiled regex);
        ``redirect_to`` answers a 302 with that Location; ``final_url`` sets ``Response.url``
        (legacy); ``latency`` advances the bound clock (and DeadlineExceeded past the deadline).
        """
        if json is not None:
            content = _json.dumps(json).encode()
            hdrs = {"content-type": "application/json"}
        elif text is not None:
            content = text.encode()
            hdrs = {"content-type": "text/html; charset=utf-8"}
        else:
            content = body or b""
            hdrs = {}
        hdrs.update({k.lower(): v for k, v in (headers or {}).items()})
        if redirect_to is not None:
            status = status if 300 <= status < 400 else 302
            hdrs["location"] = redirect_to
        route = _Route(
            method=method.upper(),
            pattern=url,
            status=status,
            content=content,
            headers=hdrs,
            error=error,
            final_url=final_url,
            match_headers={k.lower(): v for k, v in (match_headers or {}).items()},
            redirect_to=redirect_to,
            remaining=None if times is None else int(times),
            latency=float(latency or 0.0),
        )
        with self._lock:
            self.routes.append(route)
        return self

    def _url_matches(self, pattern: Any, url: str) -> bool:
        if isinstance(pattern, re.Pattern):
            return bool(pattern.search(url))
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            return url.startswith(prefix) or _lower_origin(url).startswith(_lower_origin(prefix))
        return pattern == url or _normalise(pattern) == _normalise(url)

    @staticmethod
    def _headers_match(route: _Route, headers: dict[str, str]) -> bool:
        if not route.match_headers:
            return True
        lower = {k.lower(): str(v) for k, v in (headers or {}).items()}
        for name, expected in route.match_headers.items():
            got = lower.get(name)
            if got is None:
                return False
            if isinstance(expected, re.Pattern):
                if not expected.search(got):
                    return False
            elif got != str(expected):
                return False
        return True

    def _take(self, method: str, url: str, headers: dict[str, str]) -> _Route:
        with self._lock:
            for route in self.routes:
                if route.method not in (method, "*"):
                    continue
                if route.remaining is not None and route.remaining <= 0:
                    continue
                if not self._url_matches(route.pattern, url) or not self._headers_match(route, headers):
                    continue
                if route.remaining is not None:
                    route.remaining -= 1
                route.used += 1
                return route
            known = "\n  ".join(r.describe() for r in self.routes) or "(none)"
            self.unexpected.append(f"{method} {url}")
        raise UnexpectedRequest(f"unexpected HTTP request: {method} {url}\nknown routes:\n  {known}")

    # ---- Transport protocol (one hop) -------------------------------------------------------
    def send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        timeout: float | None = None,
        max_bytes: int | None = None,
        deadline: float | None = None,
        **kw: Any,
    ) -> Response:
        """Answer ONE hop (no redirect following) like the core Transport protocol."""
        method = method.upper()
        headers = dict(headers or {})
        with self._lock:
            self.calls.append({"method": method, "url": url, "headers": headers, "body": body, "timeout": timeout, "max_bytes": max_bytes, **kw})
        route = self._take(method, url, headers)
        self._spend(route, deadline, url)
        if route.error is not None:
            raise route.error
        content, truncated = route.content, False
        if max_bytes is not None and len(content) > max_bytes:
            content, truncated = content[:max_bytes], True
        return Response(route.status, route.final_url or url, dict(route.headers), content, route.latency, False, truncated, [])

    def _spend(self, route: _Route, deadline: float | None, url: str) -> None:
        if route.latency and self.clock is not None:
            advance = getattr(self.clock, "advance", None) or self.clock.sleep
            advance(route.latency)
        if deadline is not None and self.clock is not None and self.clock.monotonic() > deadline:
            raise DeadlineExceeded(f"deadline exceeded while reading {urlsplit(url).hostname}")

    # ---- legacy client -----------------------------------------------------------------------
    def request(self, method: str, url: str, *, params: dict[str, Any] | None = None, **kw: Any) -> Response:
        """Legacy client entry point (``ScopedHttp(FakeHttp())``): params merged, redirects followed."""
        method = method.upper()
        if params:
            clean = {k: v for k, v in params.items() if v is not None}
            url = url + ("&" if "?" in url else "?") + urlencode(clean, doseq=True)
        headers = dict(kw.get("headers") or {})
        with self._lock:
            self.calls.append({"method": method, "url": url, **kw})
        history: list[str] = []
        current = url
        for _hop in range(6):
            route = self._take(method, current, headers)
            self._spend(route, kw.get("deadline"), current)
            if route.error is not None:
                raise route.error
            if route.redirect_to is not None and kw.get("allow_redirects", True):
                history.append(current)
                current = urljoin(current, route.redirect_to)
                if method not in ("GET", "HEAD") and route.status == 303:
                    method = "GET"
                with self._lock:
                    self.calls.append({"method": method, "url": current, "headers": headers, "redirected_from": history[-1]})
                continue
            return Response(route.status, route.final_url or current, dict(route.headers), route.content, route.latency, False, False, history)
        raise NetworkError(f"too many redirects from {url}")

    # ---- inspection --------------------------------------------------------------------------
    def urls(self) -> list[str]:
        """Every requested URL, in order."""
        return [c["url"] for c in self.calls]

    def hosts(self) -> set[str]:
        """Every requested host (lower case)."""
        return {(urlsplit(c["url"]).hostname or "").lower() for c in self.calls}

    def assert_hosts_within(self, module_cls: Any, *, extra: Iterable[str] = ()) -> None:
        """Assert every requested host is declared by ``module_cls`` (P327 cond 11).

        Allowed: ``module_cls.hosts`` ('*.suffix' wildcards honoured), the hosts_from_settings
        hosts of its providers (the same rule as ``ctx.http``), the core DoH hosts (``DOH_HOSTS`` +
        a configured internal DoH, as ``ctx.doh``) and ``extra``.
        """
        config = self.bound_config or Config()
        allowed = {str(h).lower() for h in (getattr(module_cls, "hosts", ()) or ())}
        allowed |= set(DOH_HOSTS) | set(doh_hosts(config)) | {str(h).lower() for h in extra}
        allowed |= settings_hosts(module_cls, config)
        bad = sorted(h for h in self.hosts() if not host_allowed(h, allowed))
        assert not bad, f"{getattr(module_cls, 'name', module_cls)} requested undeclared hosts {bad}; allowed: {sorted(allowed)}"


class DeadHttp(FakeHttp):
    """Every request fails like a dead network (NetworkError); calls are still recorded."""

    def send(self, method: str, url: str, **kw: Any) -> Response:
        with self._lock:
            self.calls.append({"method": method.upper(), "url": url, **kw})
        raise NetworkError(f"ConnectionError contacting {urlsplit(url).hostname}")

    def request(self, method: str, url: str, **kw: Any) -> Response:
        with self._lock:
            self.calls.append({"method": method.upper(), "url": url, **kw})
        raise NetworkError(f"ConnectionError contacting {url}")


# --------------------------------------------------------------------------------------
# DNS over HTTPS answers (the exact URLs the core resolver sends, P029)
# --------------------------------------------------------------------------------------


def doh_url(name: str, rtype: str, *, provider: str = "google") -> str:
    """URL the core resolver requests for (name, rtype): Google carries edns_client_subnet=0.0.0.0/0."""
    rtype = rtype.upper()
    if provider == "google":
        return f"{_GOOGLE_DOH}?" + urlencode({"name": name, "type": rtype, "edns_client_subnet": "0.0.0.0/0"})
    if provider == "cloudflare":
        return f"{_CLOUDFLARE_DOH}?" + urlencode({"name": name, "type": rtype})
    if provider.startswith("https://"):
        return f"{provider}?" + urlencode({"name": name, "type": rtype})
    raise ValueError(f"unknown DoH provider {provider!r} (google, cloudflare or an https:// JSON endpoint)")


def _providers_arg(provider: str) -> tuple[str, ...]:
    return ("google", "cloudflare") if provider == "all" else (provider,)


def doh(name: str, rtype: str, records: list[str], *, status: int = 0, ad: bool = False) -> dict[str, Any]:
    """Build a DoH JSON answer (Google/Cloudflare format)."""
    from v3lum.core.dns import RTYPES

    return {
        "Status": status,
        "AD": ad,
        "Answer": [{"name": name + ".", "type": RTYPES[rtype.upper()], "TTL": 300, "data": r} for r in records],
    }


def add_dns(http: FakeHttp, name: str, rtype: str, records: list[str], *, status: int = 0, ad: bool = False, provider: str = "google") -> None:
    """Answer one DoH query (provider 'google', 'cloudflare', 'all' or an https:// JSON endpoint)."""
    for prov in _providers_arg(provider):
        http.add("GET", doh_url(name, rtype, provider=prov), json=doh(name, rtype, records, status=status, ad=ad))


_CHALLENGE_PAGE = (
    "<!DOCTYPE html><html><head><title>Just a moment...</title></head>"
    "<body><div id=\"cf-chl-widget\">Checking your browser</div></body></html>"
)


def add_dns_failure(http: FakeHttp, name: str, rtype: str, *, kind: str = "servfail", provider: str = "google") -> None:
    """Make one DoH query fail.

    kind: 'servfail' (Status 2), 'refused' (Status 5), 'http500', 'http429', 'challenge'
    (anti-bot page) or 'timeout' (NetworkError). provider: 'google', 'cloudflare' or 'all'.
    """
    for prov in _providers_arg(provider):
        url = doh_url(name, rtype, provider=prov)
        if kind == "servfail":
            http.add("GET", url, json={"Status": 2, "Answer": [], "Comment": "SERVFAIL (test)"})
        elif kind == "refused":
            http.add("GET", url, json={"Status": 5, "Answer": [], "Comment": "REFUSED (test)"})
        elif kind == "http500":
            http.add("GET", url, status=500, text="internal error")
        elif kind == "http429":
            http.add("GET", url, status=429, text="too many requests")
        elif kind == "challenge":
            http.add("GET", url, status=403, text=_CHALLENGE_PAGE)
        elif kind == "timeout":
            http.add("GET", url, error=NetworkError(f"ReadTimeout contacting {urlsplit(url).hostname}: timed out"))
        else:
            raise ValueError(f"unknown DNS failure kind {kind!r}")


def add_nxdomain_everything(http: FakeHttp) -> None:
    """Any DoH query (Google or Cloudflare) not answered by a more specific route is NXDOMAIN."""
    http.add("GET", re.compile(r"^https://(dns\.google/resolve|cloudflare-dns\.com/dns-query)\?"), json={"Status": 3, "Answer": []})


# --------------------------------------------------------------------------------------
# runtime / context / engine factories
# --------------------------------------------------------------------------------------


def make_runtime(
    http: Any = None,
    *,
    keys: dict[str, str] | None = None,
    settings: dict[str, Any] | None = None,
    clock: Any = None,
    org_profile: Any = None,
    cache: bool = False,
    offline: bool = False,
) -> Runtime:
    """A Runtime over the fake transport: the real HttpClient (classification, redirects, host
    checks, profiles, redaction) runs over ``http`` (default ``FakeHttp()``)."""
    cfg = Config()
    cfg.file_keys.update(keys or {})
    cfg.settings.update(settings or {})
    http = FakeHttp() if http is None else http
    clock = clock or getattr(http, "clock", None) or FakeClock()
    if isinstance(http, FakeHttp):
        if http.clock is None:
            http.clock = clock
        http.bound_config = cfg
    if hasattr(http, "send"):
        return Runtime(cfg, transport=http, clock=clock, org=org_profile, no_cache=not cache, offline=offline)
    return Runtime(cfg, http_client=http, clock=clock, org=org_profile, no_cache=not cache, offline=offline)


def _as_entity(entity: Any) -> Entity:
    if isinstance(entity, Entity):
        return entity
    text = str(entity)
    etype, sep, value = text.partition(":")
    if not sep:
        raise ValueError(f"entity must be an Entity or 'type:value', got {entity!r}")
    return Entity.make(EntityType.parse(etype), value)


def _run_info(
    entity: Entity | None,
    *,
    is_seed: bool = True,
    depth: int = 0,
    provenance: Iterable[Any] = (),
    allowed_sources: Iterable[str] | None = None,
    tlp: str | None = None,
    case_id: str = "",
    priority: str = "seed",
    deadline: float | None = None,
    internal_seed: bool = False,
) -> RunInfo:
    return RunInfo(
        entity=entity,
        is_seed=is_seed,
        depth=depth,
        provenance=tuple(tuple(p) for p in provenance),
        allowed_sources=None if allowed_sources is None else frozenset(allowed_sources),
        tlp=tlp or "",
        deadline=deadline,
        case_id=case_id,
        priority=priority,
        internal_seed=internal_seed,
    )


def make_ctx(
    module_cls: Any,
    http: Any = None,
    *,
    keys: dict[str, str] | None = None,
    options: ScanOptions | None = None,
    settings: dict[str, Any] | None = None,
    entity: Any = None,
    is_seed: bool = True,
    depth: int = 0,
    provenance: Iterable[Any] = (),
    allowed_sources: Iterable[str] | None = None,
    tlp: str | None = None,
    org_profile: Any = None,
    clock: Any = None,
    runtime: Runtime | None = None,
    **run_kw: Any,
) -> Any:
    """A Context for direct ``Module().run(entity, ctx)`` calls (tlp None = options.tlp, amber)."""
    rt = runtime or make_runtime(http, keys=keys, settings=settings, clock=clock, org_profile=org_profile)
    ent = None if entity is None else _as_entity(entity)
    run = _run_info(ent, is_seed=is_seed, depth=depth, provenance=provenance, allowed_sources=allowed_sources, tlp=tlp, **run_kw)
    return rt.context(module_cls, options or ScanOptions(), run=run)


def run_module(module_cls: Any, entity: Any, http: Any = None, **kw: Any) -> Any:
    """Run one module through ``Engine.run_module`` (status mapping, sanitizer, caps): the
    recommended way to test a module. ``entity`` is an Entity or 'type:value'; ``kw`` takes the
    make_ctx keywords (keys, settings, options, is_seed, depth, provenance, allowed_sources, tlp,
    org_profile, clock, runtime, case_id, priority, deadline, internal_seed).

    A request that no FakeHttp route answers fails the test with :class:`UnexpectedRequest`, even
    though the engine maps the module's exception to an ERROR result (a missing route must never
    look like a dead source)."""
    from v3lum.core.engine import Engine

    ent = _as_entity(entity)
    options = kw.pop("options", None) or ScanOptions()
    runtime = kw.pop("runtime", None)
    keys, settings, clock, org = (kw.pop(k, None) for k in ("keys", "settings", "clock", "org_profile"))
    rt = runtime or make_runtime(http, keys=keys, settings=settings, clock=clock, org_profile=org)
    fakes = [f for f in {id(f): f for f in (http, getattr(rt.http, "transport", None), rt.http)}.values() if isinstance(f, FakeHttp)]
    seen = [len(f.unexpected) for f in fakes]
    run = _run_info(ent, **kw)
    res = Engine(rt, options).run_module(module_cls, ent, run=run)
    missed = [u for f, n in zip(fakes, seen) for u in f.unexpected[n:]]
    if missed:
        raise UnexpectedRequest(f"{getattr(module_cls, 'name', module_cls)} made requests no FakeHttp route answers: {missed} (result: {res.status.value} {res.error[:160]!r})")
    return res


# --------------------------------------------------------------------------------------
# synthetic modules, providers and vocabulary
# --------------------------------------------------------------------------------------


def define_module(name: str, accepts: Iterable[EntityType | str], run: Callable[..., Any], **attrs: Any) -> Any:
    """Declare and register a synthetic module (use with the ``clean_registry`` fixture).

    Defaults: terms 'open', disclosure 'none', hosts (), opsec PASSIVE, category 'utility'.
    LIGHT/ACTIVE without an explicit disclosure become disclosure 'target' with
    default_enabled False; networked modules default max_requests 10 and expected_latency 1.0
    (pass ``provider``/``sources``/``hosts`` from ``test_provider()``).
    """
    from v3lum.core.module import Module, register

    opsec = Opsec.parse(attrs.pop("opsec", Opsec.PASSIVE))
    body: dict[str, Any] = {
        "name": name,
        "title": attrs.pop("title", name),
        "description": attrs.pop("description", f"synthetic test module {name}"),
        "category": attrs.pop("category", "utility"),
        "accepts": {EntityType.parse(t) if isinstance(t, str) else t for t in accepts},
        "run": run,
        "terms": attrs.pop("terms", "open"),
        "opsec": opsec,
        "hosts": tuple(attrs.pop("hosts", ())),
    }
    if "disclosure" not in attrs:
        if opsec >= Opsec.LIGHT:
            attrs["disclosure"] = "target"
            attrs.setdefault("default_enabled", False)
        else:
            attrs["disclosure"] = "none"
    if attrs["disclosure"] != "none":
        attrs.setdefault("max_requests", 10)
        attrs.setdefault("expected_latency", 1.0)
    body.update(attrs)
    cls = type(name, (Module,), body)
    return register(cls)


def _keys_block(keys: Any) -> dict[str, Any]:
    if not keys:
        return {}
    items = keys.items() if isinstance(keys, dict) else ((k, None) for k in keys)
    block: dict[str, Any] = {}
    for name, spec in items:
        entry = {
            "description": f"test key {name}",
            "signup_url": "https://keys.example.test/signup",
            "env": [],
            "multi_key": False,
            "plan_hint": "",
        }
        if isinstance(spec, str):
            entry["description"] = spec
        elif isinstance(spec, dict):
            entry.update(spec)
        block[str(name)] = entry
    return block


def provider_fragment(
    provider_id: str = "test_provider",
    *,
    hosts: Iterable[str] = ("api.example.test",),
    tier: str = "trusted",
    terms: str = "open",
    sensitive: bool = False,
    sources: Any = ("default",),
    keys: Any = None,
    **extra: Any,
) -> dict[str, Any]:
    """The 'v3lum.provider/1' fragment ``test_provider`` registers (``extra`` overrides fields;
    ``publishes_queries``/``reuses_queries``/``fetches_target`` go into flags; ``sanitizer``
    applies to every source)."""
    flags = {"publishes_queries": False, "reuses_queries": False, "fetches_target": False, "sensitive": bool(sensitive)}
    for flag in ("publishes_queries", "reuses_queries", "fetches_target"):
        if flag in extra:
            flags[flag] = bool(extra.pop(flag))
    sanitizer = extra.pop("sanitizer", None)
    src_items = sources.items() if isinstance(sources, dict) else ((s, {}) for s in sources)
    src_block: dict[str, Any] = {}
    for sid, spec in src_items:
        entry: dict[str, Any] = {
            "title": f"{provider_id} {sid}",
            "terms": {
                "class": terms,
                "evidence_url": "https://terms.example.test/",
                "quote": "synthetic provider used by the V3LUM test suite",
                "checked_at": "2026-11-26",
                "reviewer": "tests",
                "free_plan_business_use": None,
            },
            "upstream_family": provider_id,
            "sanitizer": sanitizer,
            "dataset": None,
            "notes": "",
        }
        entry.update(dict(spec or {}))
        src_block[str(sid)] = entry
    fragment: dict[str, Any] = {
        "schema": "v3lum.provider/1",
        "id": provider_id,
        "name": f"Test provider {provider_id}",
        "operator": "V3LUM test suite",
        "hosts": list(hosts),
        "hosts_from_settings": [],
        "internal": False,
        "tier": tier,
        "tier_rationale": "synthetic provider for offline tests",
        "tier_reviewer": "tests",
        "tier_date": "2026-11-26",
        "flags": flags,
        "personal_data_review": None,
        "reliability": {"grade": "B", "justification": "synthetic provider for offline tests"},
        "http_profile": {},
        "quota": None,
        "error_markers": [],
        "keys": _keys_block(keys),
        "sources": src_block,
    }
    fragment.update(extra)
    return fragment


@contextlib.contextmanager
def test_provider(
    provider_id: str = "test_provider",
    *,
    hosts: Iterable[str] = ("api.example.test",),
    tier: str = "trusted",
    terms: str = "open",
    sensitive: bool = False,
    sources: Any = ("default",),
    keys: Any = None,
    **extra: Any,
) -> Iterator[Any]:
    """Register a synthetic provider fragment for the duration of the ``with`` block.

    Yields the registered Provider (``.id``, ``.hosts``, ``.sources`` keyed by 'pid.sid').
    """
    fragment = provider_fragment(provider_id, hosts=hosts, tier=tier, terms=terms, sensitive=sensitive, sources=sources, keys=keys, **extra)
    prov = providers_mod.register(fragment, origin="tests")
    try:
        yield prov
    finally:
        providers_mod.unregister(provider_id)


test_provider.__test__ = False  # type: ignore[attr-defined] - not a pytest test


def source_ids(provider: Any) -> tuple[str, ...]:
    """Fully qualified source ids ('pid.sid') of a registered provider (for Module.sources)."""
    return tuple(sorted(src.id for src in (getattr(provider, "sources", {}) or {}).values()))


@contextlib.contextmanager
def allow_vocab(attributes: Iterable[str] | dict[str, str] = (), tags: Iterable[str] | dict[str, str] = (), relations: Iterable[str] | dict[str, str] = ()) -> Iterator[None]:
    """Temporarily extend the merged vocabulary (strict mode accepts these names inside the block)."""
    from v3lum.core import vocab

    # vocab.is_known_*() consult the core tables live, so extending them is enough (no reload).
    tables = ((vocab.ATTRIBUTES, attributes), (vocab.TAGS, tags), (vocab.RELATIONS, relations))
    added: list[tuple[dict[str, str], str]] = []
    for table, names in tables:
        items = names.items() if isinstance(names, dict) else ((n, "test-only name (allow_vocab)") for n in names)
        for name, desc in items:
            if name not in table:
                table[name] = desc
                added.append((table, name))
    try:
        yield
    finally:
        for table, name in added:
            table.pop(name, None)


# --------------------------------------------------------------------------------------
# rule fixtures and secret scanning
# --------------------------------------------------------------------------------------


def graph_fixture(path: str | Path) -> tuple[Any, Any, Any]:
    """Load a 'v3lum.graph_fixture/1' file -> (Graph, results, RuleContext) (wraps
    ``correlate.load_graph_fixture``; relative paths resolve under tests/fixtures/)."""
    from v3lum.core import correlate

    p = Path(path)
    if not p.is_absolute() and not p.exists():
        p = FIXTURES / p
    gf = correlate.load_graph_fixture(p)
    return gf.graph, gf.results, gf.rctx


def _secret_variants(secret: str) -> list[bytes]:
    forms = {secret, quote(secret, safe=""), quote_plus(secret), base64.b64encode(secret.encode()).decode()}
    return sorted({f.encode("utf-8") for f in forms if f}, key=len)


#: SQLite side files that may hold rows not yet checkpointed into the main database file.
_SQLITE_SIDECARS = ("-wal", "-journal", "-shm")


def _iter_blobs(item: Any, label: str) -> Iterator[tuple[str, bytes]]:
    if isinstance(item, Path):
        if item.is_dir():
            for sub in sorted(item.rglob("*")):
                if sub.is_file():
                    yield str(sub), sub.read_bytes()
        elif item.exists():
            yield str(item), item.read_bytes()
            for suffix in _SQLITE_SIDECARS:  # a database path also covers its WAL/journal
                side = item.with_name(item.name + suffix)
                if side.is_file():
                    yield str(side), side.read_bytes()
        return
    if isinstance(item, bytes):
        yield label, item
    elif isinstance(item, str):
        yield label, item.encode("utf-8", errors="replace")
    elif isinstance(item, (dict, list, tuple, set, frozenset)):
        payload = sorted(item, key=repr) if isinstance(item, (set, frozenset)) else item
        yield label, _json.dumps(payload, default=_default_repr, ensure_ascii=False).encode("utf-8")
    elif hasattr(item, "to_dict"):
        yield label, _json.dumps(item.to_dict(), default=_default_repr, ensure_ascii=False).encode("utf-8")
    else:
        yield label, repr(item).encode("utf-8", errors="replace")


def _default_repr(obj: Any) -> Any:
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    return repr(obj)


def assert_no_secret(secret: str, *items: Any) -> None:
    """Assert ``secret`` (raw, URL-encoded or base64) appears in none of ``items``.

    Items may be str, bytes, dict/list (JSON-dumped), objects with ``to_dict()`` and Paths
    (directories scanned recursively; SQLite and every other file read as bytes).
    """
    if not secret:
        raise ValueError("assert_no_secret needs a non-empty secret")
    variants = _secret_variants(secret)
    masked = f"{secret[:2]}…({len(secret)} chars)"
    for index, item in enumerate(items):
        for where, blob in _iter_blobs(item, f"item #{index}"):
            for variant in variants:
                if variant in blob:
                    raise AssertionError(f"secret {masked} found in {where}")
