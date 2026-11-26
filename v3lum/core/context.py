"""Runtime (shared plumbing for a session) and Context (what one module run receives).

Module-author contract v2, section 6 (frozen in docs/MODULE_GUIDE.md):

* ``ScanOptions`` - what the analyst asked for (mode, TLP, scope, purpose, presets...).
* ``RunInfo`` - facts about ONE (module, entity) run decided by the engine: seed or pivot, depth,
  provenance, the sources the module may query, the entity TLP, the run deadline.
* ``Runtime`` - long-lived plumbing shared by every run of a session: config, the HTTP client
  (provider profiles, classification, redaction, cache), datasets, org profile, provider registry,
  clock, cancel flag and event bus.
* ``Context`` - the ``ctx`` a module receives: ``ctx.http`` (ScopedHttp carrying the module's
  metadata: host allow-list, request cap, deadline, error markers), ``ctx.dns`` (Resolver over a
  per-run core DoH scope), ``ctx.net`` (core socket connector, target modules only), ``ctx.data``,
  ``ctx.org``, ``ctx.state`` and the properties of the run.

Modules never choose proxies, user agents or resolvers: everything network-related comes from here.
"""

from __future__ import annotations

import copy
import datetime as _dt
import hashlib
import json
import logging
import os
import re
import secrets as _secrets
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from v3lum import paths
from v3lum.config import Config, SettingSpec
from v3lum.core import entities as _entities
from v3lum.core import module as _module_registry
from v3lum.core import orgprofile as _orgprofile
from v3lum.core import providers as _providers
from v3lum.core import redact as _redact
from v3lum.core.clock import SYSTEM_CLOCK
from v3lum.core.dns import DOH_PROVIDERS, Resolver, is_public_doh_host
from v3lum.core.http import HttpCache, HttpClient, ScopedHttp
from v3lum.core.models import Opsec
from v3lum.core.net import Connector
from v3lum.core.tlp import TLP
from v3lum.core.tlp import parse as _parse_tlp
from v3lum.core.validators import cpf_valid as _cpf_valid

log = logging.getLogger("v3lum.context")

EventListener = Callable[[str, dict[str, Any]], None]

#: Disclosure classes of contract v2 (the module registry's table; module.py never imports this file).
_DISCLOSURES = _module_registry.DISCLOSURES


# --------------------------------------------------------------------------------------
# Options and per-run facts
# --------------------------------------------------------------------------------------


@dataclass
class ScanOptions:
    """What the analyst asked for. One instance is shared by every run of a scan."""

    mode: Opsec = Opsec.PASSIVE
    #: ACTIVE authorization flag; callers set it from ``authorization_ref`` (A7).
    authorized: bool = False
    depth: int = 1
    max_entities: int = 150
    threads: int = 12
    include: set[str] = field(default_factory=set)  # only these modules (by name)
    exclude: set[str] = field(default_factory=set)
    categories: set[str] = field(default_factory=set)  # only modules in these categories
    include_disabled: bool = False  # also run modules with default_enabled=False
    offline: bool = False
    no_cache: bool = False
    timeout_total: float = 0.0  # 0 = no global timeout
    save_evidence: bool = True
    authorization_note: str = ""  # legacy free-text authorization note
    #: TLP of the inputs (FIRST TLP 2.0: clear | green | amber | amber+strict | red); A2 default amber.
    tlp: str = "amber"
    # ---- contract v2 -------------------------------------------------------------------
    authorization_ref: str = ""  # --authorized REF (A7)
    scope_path: str = ""  # --scope FILE (A7)
    scope: Any = None  # loaded scope object (wave 2); to_dict() records its sha256
    preset: str = "quick"  # quick | deep (A3)
    purpose: str = ""  # --purpose (AR16, LGPD)
    ticket: str = ""  # --ticket (AR16)
    legal_basis: str = ""  # legal basis code (docs/LEGAL.md, AR16)
    breach_scope: str = "own"  # own | all (A4)
    expand_personal: bool = False  # --expand-personal (AR07)
    allow_unknown: bool = False  # --allow-unknown (A8, CLEAR/GREEN only)
    egress_override: str = ""  # recorded --egress-override (A2/A9)
    licence_profile: str = ""  # '' = setting licence_profile (A1)
    show_personal: bool = False  # show personal identifiers unmasked in the terminal
    no_defang: bool = False  # terminal shows IOCs refanged
    seed_tlp: dict[str, str] = field(default_factory=dict)  # entity key -> TLP of that seed
    unconfirmed_seeds: set[str] = field(default_factory=set)  # entity keys the analyst did not confirm
    #: (module, entity_key) -> recorded {is_seed, depth, provenance, tlp} of a stored case
    #: (``cases resume``); the engine schedules only these pairs and never promotes them to seeds.
    only_pairs: dict[tuple[str, str], dict[str, Any]] | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe view stored in the case (the scope object is recorded by its SHA-256)."""
        return {
            "tlp": self.tlp,
            "mode": self.mode.label,
            "authorized": self.authorized,
            "depth": self.depth,
            "max_entities": self.max_entities,
            "threads": self.threads,
            "include": sorted(self.include),
            "exclude": sorted(self.exclude),
            "categories": sorted(self.categories),
            "include_disabled": self.include_disabled,
            "offline": self.offline,
            "no_cache": self.no_cache,
            "authorization_note": self.authorization_note,
            "authorization_ref": self.authorization_ref,
            "scope_path": self.scope_path,
            "scope": _scope_digest(self.scope),
            "preset": self.preset,
            "purpose": self.purpose,
            "ticket": self.ticket,
            "legal_basis": self.legal_basis,
            "breach_scope": self.breach_scope,
            "expand_personal": self.expand_personal,
            "allow_unknown": self.allow_unknown,
            "egress_override": self.egress_override,
            "licence_profile": self.licence_profile,
            "show_personal": self.show_personal,
            "no_defang": self.no_defang,
            "seed_tlp": dict(sorted(self.seed_tlp.items())),
            "unconfirmed_seeds": sorted(self.unconfirmed_seeds),
            "only_pairs": None
            if self.only_pairs is None
            else [
                {"module": module, "entity": key, **dict(info or {})}
                for (module, key), info in sorted(self.only_pairs.items(), key=lambda kv: kv[0])
            ],
        }


def _scope_digest(scope: Any) -> str | None:
    """SHA-256 of a loaded scope (attribute/key ``sha256``), or None when no scope is loaded."""
    if scope is None:
        return None
    digest = scope.get("sha256") if isinstance(scope, dict) else getattr(scope, "sha256", None)
    if digest:
        return str(digest)
    try:
        blob = json.dumps(scope, sort_keys=True, default=str).encode("utf-8")
    except (TypeError, ValueError):
        blob = repr(scope).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


@dataclass(frozen=True)
class RunInfo:
    """Facts about one (module, entity) run, decided by the engine (AR07, AR05, A2).

    ``provenance`` is the parent path as a tuple of ``(parent_key, relation, module)``;
    ``allowed_sources`` None means every declared source; ``tlp`` '' means ``options.tlp``;
    ``deadline`` is a monotonic timestamp (None = start + module timeout).
    """

    entity: Any = None
    is_seed: bool = True
    depth: int = 0
    provenance: tuple[tuple[str, str, str], ...] = ()
    allowed_sources: frozenset[str] | None = None
    tlp: str = ""
    deadline: float | None = None
    case_id: str = ""
    priority: str = "seed"
    internal_seed: bool = False


# --------------------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------------------


class EventBus:
    """Synchronous fan-out of engine/HTTP events to UI listeners (must be thread-safe).

    Event kinds: ``scan_start``, ``investigate``, ``module_start``, ``module_done``, ``entity``,
    ``finding``, ``correlation``, ``scan_done``, ``log``, ``http`` (method, url, status, elapsed,
    cached, error; URL redacted) and ``http_request`` (``info=RequestInfo``, contract v2).
    """

    def __init__(self, listener: EventListener | None = None) -> None:
        self._listeners: list[EventListener] = [listener] if listener else []
        self._lock = threading.Lock()

    def subscribe(self, listener: EventListener) -> None:
        with self._lock:
            self._listeners.append(listener)

    def unsubscribe(self, listener: EventListener) -> None:
        with self._lock:
            if listener in self._listeners:
                self._listeners.remove(listener)

    def emit(self, kind: str, **payload: Any) -> None:
        for listener in list(self._listeners):
            try:
                listener(kind, payload)
            except Exception:  # pragma: no cover - UI must never break the engine
                pass

    def http(self, method: str, url: str, status: int, elapsed: float, cached: bool, error: str) -> None:
        self.emit("http", method=method, url=url, status=status, elapsed=elapsed, cached=cached, error=error)

    def http_request(self, info: Any) -> None:
        """Forward one structured request record (``RequestInfo``) as event ``http_request``."""
        self.emit("http_request", info=info)


# --------------------------------------------------------------------------------------
# Runtime
# --------------------------------------------------------------------------------------


class Runtime:
    """Shared, long-lived plumbing: config, HTTP client + cache, datasets, org, events, clock."""

    def __init__(
        self,
        config: Config | None = None,
        *,
        http_client: Any = None,
        transport: Any = None,
        offline: bool = False,
        no_cache: bool = False,
        listener: EventListener | None = None,
        now: Callable[[], _dt.datetime] | None = None,
        proxy: str | None = None,
        clock: Any = None,
        providers: Any = None,
        org: Any = None,
    ) -> None:
        from v3lum.core.datasets import DataStore

        self.config = config or Config.load()
        self.events = EventBus(listener)
        self.cancel_event = threading.Event()
        self.cancel_reason = ""
        self._now = now  # legacy override of now(); the clock is the v2 way
        self.clock = clock or SYSTEM_CLOCK
        self._providers = providers
        self._org = org
        self._org_lock = threading.Lock()
        self._quota_lock = threading.Lock()
        #: run-level facts collected by the engine (licence profile, egress, deadlines...).
        self.meta: dict[str, Any] = {}
        #: True while Engine.investigate runs (datasets are not downloaded then, AR10).
        self.in_scan = False
        #: objects with on_case_start/on_case_end hooks (wave 2+).
        self.case_hooks: list[Any] = []
        self.offline = offline
        self._register_key_secrets()
        if http_client is None:
            cache = None if no_cache else HttpCache(str(paths.cache_file()))
            http_client = HttpClient(
                user_agent=str(self.config.get("user_agent")),
                timeout=float(self.config.get("timeout")),
                proxy=proxy if proxy is not None else str(self.config.get("proxy") or ""),
                cache=cache,
                default_ttl=float(self.config.get("cache_ttl")),
                offline=offline,
                transport=transport,
                providers=self._live_providers,  # callable: registry snapshots stay current
                settings=self.config,
                clock=self.clock,
                on_request=self.events.http,
                on_request_info=self.events.http_request,
            )
        self.http = http_client
        self.data = DataStore(self)
        self._quota: Any = None

    # ---- registries -----------------------------------------------------------------
    @property
    def providers(self) -> Any:
        """The provider registry (``providers.registry()`` unless one was injected)."""
        if self._providers is not None:
            return self._providers
        return _providers.registry()

    @providers.setter
    def providers(self, value: Any) -> None:
        self._providers = value

    def _live_providers(self) -> Any:
        return self.providers

    @property
    def org(self) -> Any:
        """The organisation profile (lazy ``orgprofile.load_default(config)`` unless injected)."""
        with self._org_lock:
            if isinstance(self._org, dict):
                self._org = _orgprofile.OrgProfile.from_dict(self._org)
            elif self._org is None:
                self._org = _orgprofile.load_default(self.config)
            return self._org

    @org.setter
    def org(self, value: Any) -> None:
        with self._org_lock:
            self._org = value

    @property
    def quota(self) -> Any:
        """Daily quota book (created lazily in the V3LUM home; one instance even when module
        threads ask for it concurrently)."""
        if self._quota is None:
            with self._quota_lock:
                if self._quota is None:
                    from v3lum.core.quota import QuotaBook

                    self._quota = QuotaBook(paths.home() / "quota.db")
        return self._quota

    def _register_key_secrets(self) -> None:
        try:
            keys = self.config.keys()
        except Exception:  # pragma: no cover - a broken key store must not stop the runtime
            return
        for name, value in keys.items():
            if value:
                _redact.register_secret(value, label=name)

    # ---- time and cancellation ---------------------------------------------------------
    def now(self) -> _dt.datetime:
        """Timezone-aware UTC now (the injected clock; frozen in tests)."""
        if self._now is not None:
            return self._now()
        return self.clock.now()

    def cancel(self, reason: str = "cancelled") -> None:
        """Kill switch: every ScopedHttp/Connector refuses new requests (AR05)."""
        self.cancel_reason = reason or "cancelled"
        self.cancel_event.set()

    # ---- scopes ----------------------------------------------------------------------
    def context(self, module_cls: Any, options: ScanOptions | None = None, case_dir: Path | None = None, *, run: RunInfo | None = None) -> Context:
        """Build the ``ctx`` for one run of ``module_cls``."""
        return Context(self, module_cls, options or ScanOptions(), case_dir, run=run)

    def doh_scope(self, *, module: str = "", deadline: float | None = None, priority: str = "seed", public: bool = True) -> Any:
        """A new core DoH scope for one run (P029 cond 11).

        Core scope: not counted for ``max_requests`` or quotas, no module UA or min_interval,
        restricted to the DoH resolver hosts (only the internal resolver when ``public`` is False:
        offline/internal modules and TLP:RED, A2); its hosts still reach the disclosure ledger.
        """
        return ScopedHttp(
            self.http,
            ttl=None,
            min_interval=0.0,
            core=True,
            module=module,
            allowed_hosts=doh_hosts(self.config, public=public),
            disclosure="third_party",
            opsec=Opsec.PASSIVE,
            deadline=deadline,
            cancel_event=self.cancel_event,
            clock=self.clock,
            priority=priority,
        )


# --------------------------------------------------------------------------------------
# Context
# --------------------------------------------------------------------------------------


class Context:
    """What ``Module.run(entity, ctx)`` receives (module-author contract v2, section 6)."""

    def __init__(self, runtime: Runtime, module_cls: Any, options: ScanOptions, case_dir: Path | None, *, run: RunInfo | None = None) -> None:
        self.runtime = runtime
        self.module = module_cls
        self.options = options
        self.case_dir = case_dir
        self.config = runtime.config
        self.run = run or RunInfo()
        clock = runtime.clock
        name = str(getattr(module_cls, "name", "") or "")
        # A Module subclass (or any class carrying module metadata) is enforced by its declared
        # disclosure; a Module subclass without a valid one (unregistered, @register bypassed) fails
        # closed to 'none': no network and no public resolver (P327 cond 3-5). Only plain core
        # helper classes without module metadata (e.g. doctor probes) skip the module host list.
        declared, is_module = _disclosure_of(module_cls)
        disclosure = declared or "third_party"
        opsec = _opsec(getattr(module_cls, "opsec", Opsec.PASSIVE))
        timeout = getattr(module_cls, "timeout", 60.0)
        if self.run.deadline is not None:
            self.deadline: float | None = float(self.run.deadline)
        elif timeout:
            self.deadline = clock.monotonic() + float(timeout)
        else:
            self.deadline = None
        key_names = tuple(getattr(module_cls, "requires_keys", ()) or ()) + tuple(getattr(module_cls, "optional_keys", ()) or ())
        self.http = ScopedHttp(
            runtime.http,
            ttl=getattr(module_cls, "cache_ttl", None),
            min_interval=float(getattr(module_cls, "min_interval", 0.0) or 0.0),
            module=name,
            provider=str(getattr(module_cls, "provider", "") or ""),
            sources=tuple(getattr(module_cls, "sources", ()) or ()),
            allowed_hosts=self._allowed_hosts(module_cls, declared) if is_module else None,
            disclosure=disclosure,
            opsec=opsec,
            max_requests=getattr(module_cls, "max_requests", None) if is_module else None,
            absent_statuses=frozenset(getattr(module_cls, "absent_statuses", ()) or ()),
            error_markers=_markers(getattr(module_cls, "error_markers", ()) or ()),
            keyless=not any(self.config.key(k) for k in key_names),
            deadline=self.deadline,
            cancel_event=runtime.cancel_event,
            clock=clock,
            priority=self.run.priority,
        )
        tlp = _tlp(self.tlp)
        offline_class = disclosure in ("none", "internal")
        # A2 / P029 cond 7: no public DoH for offline/internal modules or at RED; no move from an
        # internal resolver to a public one at AMBER and above. Resolver order comes from the
        # settings doh_providers / doh_internal (P029 cond 5).
        allow_public = not (offline_class or tlp >= TLP.RED)
        self.doh = runtime.doh_scope(module=name, deadline=self.deadline, priority=self.run.priority, public=allow_public)
        self.dns = Resolver(
            self.doh,
            mode=str(self.config.get("dns_mode") or "doh"),
            provider=str(self.config.get("doh_provider") or "google"),
            allow_public=allow_public,
            allow_public_fallback=not (offline_class or tlp >= TLP.AMBER),
            clock=clock,
            settings=self.config,
        )
        self.net = Connector(module=name, disclosure=disclosure, opsec=opsec, deadline=self.deadline, cancel_event=runtime.cancel_event, clock=clock)
        self.data = runtime.data.scoped()
        self._state: ModuleState | None = None

    # ---- construction helpers ----------------------------------------------------------
    def _allowed_hosts(self, module_cls: Any, declared: str) -> tuple[str, ...] | None:
        """Declared hosts + hosts_from_settings of the module's providers (None = no host check).

        Static provider hosts the module does not declare stay refused (P327 cond 4). Settings
        hosts come from ``ProviderRegistry.hosts_for`` (one rule for the whole core): only https
        URLs count and a configured host that another provider owns is ignored, so e.g. a
        ``misp_url`` pointing at a third-party API never becomes an 'internal' host (A12, fail
        closed). Target modules get None (scope checks arrive in wave 2).
        """
        if declared == "target":
            return None
        hosts = {str(h).lower() for h in (getattr(module_cls, "hosts", ()) or ())}
        if declared == "none":
            return tuple(sorted(hosts))
        hosts |= settings_hosts(module_cls, self.config, self.runtime.providers)
        return tuple(sorted(hosts))

    # ---- facts about the run -----------------------------------------------------------
    @property
    def mode(self) -> Opsec:
        return self.options.mode

    @property
    def authorized(self) -> bool:
        return self.options.authorized

    @property
    def entity(self) -> Any:
        """The entity of this run (``RunInfo.entity``)."""
        return self.run.entity

    @property
    def is_seed(self) -> bool:
        """True when the analyst typed the entity (not discovered as a pivot)."""
        return self.run.is_seed

    @property
    def depth(self) -> int:
        return self.run.depth

    @property
    def provenance(self) -> tuple[tuple[str, str, str], ...]:
        """Parent path: tuple of ``(parent_key, relation, module)`` from the seed to this entity."""
        return tuple(self.run.provenance)

    @property
    def allowed_sources(self) -> frozenset[str]:
        """Source ids the module may query in this run (aggregators MUST query only these)."""
        if self.run.allowed_sources is None:
            return frozenset(getattr(self.module, "sources", ()) or ())
        return frozenset(self.run.allowed_sources)

    @property
    def allowed_opsec(self) -> Opsec:
        """min(scan mode, module opsec)."""
        return Opsec(min(int(self.options.mode), int(_opsec(getattr(self.module, "opsec", Opsec.PASSIVE)))))

    @property
    def tlp(self) -> str:
        """Entity TLP value: 'clear' | 'green' | 'amber' | 'amber+strict' | 'red'."""
        return _tlp(self.run.tlp or self.options.tlp or "amber").value_str

    @property
    def purpose(self) -> str:
        return self.options.purpose

    @property
    def case_id(self) -> str:
        return self.run.case_id

    @property
    def org(self) -> Any:
        """The organisation profile (OrgProfile; empty when none is configured)."""
        return self.runtime.org

    @property
    def state(self) -> ModuleState:
        """Persistent per-module key/value store (the only persistence a module may use)."""
        if self._state is None:
            self._state = ModuleState(str(getattr(self.module, "name", "") or ""), entity=self.run.entity)
        return self._state

    # ---- keys and settings ---------------------------------------------------------------
    def key(self, name: str) -> str:
        return self.config.key(name)

    def has_key(self, name: str) -> bool:
        return bool(self.config.key(name))

    def key_plan(self, name: str) -> str:
        """Recorded plan of a key: 'business' | 'free' | ''."""
        return self.config.key_plan(name)

    def setting(self, name: str, default: Any = None) -> Any:
        """Core or module setting (configured value, else the registered default, else ``default``)."""
        missing = _MISSING
        value = self.config.get(name, missing)
        if value is not missing:
            return value
        declared = getattr(self.module, "settings", None) or {}
        if isinstance(declared, dict) and name in declared:
            value = declared[name]
            return value.default if isinstance(value, SettingSpec) else value  # settings may declare SettingSpec(default, ...)
        return default

    # ---- utilities -----------------------------------------------------------------------
    def log(self, message: str, level: str = "info") -> None:
        """A line in the live feed. Configured key values and key-like URL parameters are masked
        before the event leaves the context (AR01)."""
        self.runtime.events.emit("log", module=getattr(self.module, "name", "?"), message=_redact.redact_text(message), level=level)

    def cancelled(self) -> bool:
        return self.runtime.cancel_event.is_set()

    def now(self) -> _dt.datetime:
        """Timezone-aware UTC now (frozen in tests)."""
        return self.runtime.now()

    def remaining(self) -> float | None:
        """Seconds left until the run deadline (never negative), or None without a deadline."""
        if self.deadline is None:
            return None
        return max(0.0, self.deadline - self.runtime.clock.monotonic())

    def quota_remaining(self) -> int | None:
        """Remaining daily budget of the module's provider (or of ``daily_quota``), None if unknown.

        Thin wave-1 version: the provider registry quota block gives the budget (day limit times
        its safety margin, P334 cond 3) and the per-provider counter of ``runtime.quota``; a module
        without a provider quota falls back to ``Module.daily_quota`` and its per-module counter.
        """
        pid = str(getattr(self.module, "provider", "") or "")
        spec = getattr(self.runtime.providers.get(pid), "quota", None) if pid else None
        budget = spec.budget("day") if spec is not None else None
        try:
            if budget is not None:
                return max(0, int(budget) - int(self.runtime.quota.used(pid)))
            limit = getattr(self.module, "daily_quota", None)
            if limit:
                return max(0, int(limit) - int(self.runtime.quota.used(str(getattr(self.module, "name", "")))))
        except Exception:  # pragma: no cover - quota bookkeeping must never break a module
            return None
        return None


# --------------------------------------------------------------------------------------
# Persistent module state (ctx.state)
# --------------------------------------------------------------------------------------

#: Maximum size of one module's state file (serialised JSON).
STATE_MAX_BYTES = 1_048_576
_STATE_NAME = re.compile(r"^[a-z0-9][a-z0-9_]{0,63}$")
_STATE_LOCKS: dict[str, threading.Lock] = {}
_STATE_LOCKS_GUARD = threading.Lock()
_EMAIL_LIKE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}")  # bounded: linear time
_CPF_LIKE = re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b")
#: 11 digits not part of a longer digit run: checked with the offline CPF validator (team rule 4).
_CPF_DIGITS = re.compile(r"(?<!\d)\d{11}(?!\d)")


class StateError(ValueError):
    """A value ctx.state refuses to keep (not JSON, too large, personal identifier or secret)."""


class ModuleState:
    """Persistent per-module JSON store at ``~/.v3lum/state/<module>.json`` (0600, 1 MB cap).

    The only persistence a module may use (e.g. auto-disable flags of a site pack, the rotating
    doctor sample position). Values must be JSON-serialisable; personal identifiers (the run's
    PERSONAL_TYPES entity value, e-mail addresses, CPFs - formatted or as 11 valid digits) and
    registered secrets are refused. The file is written through ``os.open(..., 0o600)`` and an
    atomic ``os.replace`` inside a 0700 ``state`` directory.
    """

    def __init__(self, module: str, *, entity: Any = None) -> None:
        name = str(module or "").strip().lower()
        if not _STATE_NAME.match(name):
            raise StateError(f"ctx.state needs a module name matching {_STATE_NAME.pattern!r}, got {module!r}")
        self.module = name
        self._guarded = _guarded_values(entity)

    @property
    def path(self) -> Path:
        directory = paths.sub("state")
        try:
            if directory.stat().st_mode & 0o077:
                os.chmod(directory, 0o700)  # state may hold module bookkeeping: owner only (A10)
        except OSError:  # pragma: no cover - a foreign-owned directory: the 0600 files still protect values
            pass
        return directory / f"{self.module}.json"

    # ---- API ---------------------------------------------------------------------------
    def get(self, key: str, default: Any = None) -> Any:
        """Stored value of ``key`` (a copy), or ``default``."""
        _check_key(key)
        with _state_lock(self.module):
            data = self._read()
        return copy.deepcopy(data[key]) if key in data else default

    def set(self, key: str, value: Any) -> None:
        """Store a JSON-serialisable ``value`` under ``key`` (persisted immediately)."""
        _check_key(key)
        try:
            size = len(json.dumps(value, allow_nan=False).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise StateError(f"ctx.state values must be JSON-serialisable ({exc})") from exc
        if size > STATE_MAX_BYTES:
            raise StateError(f"state of module {self.module} would exceed {STATE_MAX_BYTES} bytes")
        self._check_content(key, value)
        with _state_lock(self.module):
            data = self._read()
            data[key] = copy.deepcopy(value)
            self._write(data)

    def delete(self, key: str) -> bool:
        """Remove ``key``; True when it existed."""
        _check_key(key)
        with _state_lock(self.module):
            data = self._read()
            if key not in data:
                return False
            del data[key]
            self._write(data)
            return True

    def all(self) -> dict[str, Any]:
        """A copy of every stored key/value."""
        with _state_lock(self.module):
            return copy.deepcopy(self._read())

    # ---- storage -----------------------------------------------------------------------
    def _read(self) -> dict[str, Any]:
        path = self.path
        if not path.exists():
            return {}
        try:
            if path.stat().st_size > STATE_MAX_BYTES:  # bounded read: never load an oversized file
                log.warning("ignoring state file %s larger than %d bytes", path, STATE_MAX_BYTES)
                return {}
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            log.warning("ignoring unreadable state file %s: %s", path, exc)
            return {}
        return data if isinstance(data, dict) else {}

    def _write(self, data: dict[str, Any]) -> None:
        blob = json.dumps(data, ensure_ascii=False, sort_keys=True, allow_nan=False).encode("utf-8")
        if len(blob) > STATE_MAX_BYTES:
            raise StateError(f"state of module {self.module} would exceed {STATE_MAX_BYTES} bytes")
        path = self.path
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{_secrets.token_hex(4)}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(blob)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise

    def _check_content(self, key: str, value: Any) -> None:
        for text in _strings(key, value):
            low = text.lower()
            if any(g in low for g in self._guarded):
                raise StateError("ctx.state never stores the investigated personal identifier or secret")
            if ("@" in text and _EMAIL_LIKE.search(text)) or ("-" in text and _CPF_LIKE.search(text)):
                raise StateError("ctx.state never stores personal identifiers (e-mail address / CPF)")
            if any(_cpf_valid(m.group(0)) for m in _CPF_DIGITS.finditer(text)):
                raise StateError("ctx.state never stores personal identifiers (CPF)")
            if _redact.has_secret(text):
                raise StateError("ctx.state never stores secrets (a registered key value was found)")


def _check_key(key: Any) -> None:
    if not isinstance(key, str) or not key or len(key) > 200:
        raise StateError("ctx.state keys are non-empty strings of at most 200 characters")


def _state_lock(module: str) -> threading.Lock:
    with _STATE_LOCKS_GUARD:
        lock = _STATE_LOCKS.get(module)
        if lock is None:
            lock = _STATE_LOCKS[module] = threading.Lock()
        return lock


def _guarded_values(entity: Any) -> tuple[str, ...]:
    """Lower-cased values ctx.state must never hold: the run entity when personal or secret (plus
    its digits-only form for numeric identifiers such as phones and CPFs)."""
    if entity is None:
        return ()
    etype = getattr(entity, "type", None)
    if etype is None or (etype not in _entities.PERSONAL_TYPES and etype not in _entities.SECRET_TYPES):
        return ()
    value = str(getattr(entity, "value", "") or "").strip().lower()
    if len(value) < 3:
        return ()
    digits = re.sub(r"\D", "", value)
    return (value, digits) if len(digits) >= 8 and digits != value else (value,)


def _strings(*items: Any) -> Iterable[str]:
    for item in items:
        if isinstance(item, str):
            yield item
        elif isinstance(item, bool):
            continue
        elif isinstance(item, int):
            yield str(item)  # numeric identifiers (CPF, phone digits) are checked like text
        elif isinstance(item, dict):
            for k, v in item.items():
                yield from _strings(k, v)
        elif isinstance(item, (list, tuple)):
            for v in item:
                yield from _strings(v)


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------

_MISSING = object()


def doh_hosts(config: Any, *, public: bool = True) -> tuple[str, ...]:
    """Hosts of the core DoH resolvers: the public providers (when ``public``) plus the configured
    internal resolver (setting doh_internal, or an https URL in doh_providers).

    An "internal" entry counts only when it is an https URL without credentials whose host is not a
    known public resolver - the same rule the Resolver applies - so a misconfigured public resolver
    can never reach a scope that must stay internal (offline/internal modules, TLP:RED; A2).
    """
    hosts: set[str] = set()
    for spec in DOH_PROVIDERS.values() if public else ():
        host = urlsplit(str(spec.get("url") or "")).hostname
        if host:
            hosts.add(host.lower())
    candidates = [config.get("doh_internal")] + list(_list_setting(config.get("doh_providers")))
    for value in candidates:
        host = _internal_doh_host(value)
        if host:
            hosts.add(host)
    return tuple(sorted(hosts))


def _internal_doh_host(value: Any) -> str:
    """Host of a valid internal DoH URL (https, no credentials, not a public resolver), else ''.

    'Public resolver' is :func:`v3lum.core.dns.is_public_doh_host` - the Resolver's own rule
    (public DoH domains and their subdomains, IP literals of the public anycast networks)."""
    text = str(value or "").strip()
    if not text.lower().startswith("https://"):
        return ""
    try:
        parts = urlsplit(text)
        host = (parts.hostname or "").lower().rstrip(".")
        has_credentials = bool(parts.username or parts.password)
    except ValueError:
        return ""
    if not host or has_credentials or is_public_doh_host(host):
        return ""
    return host


def settings_hosts(module_cls: Any, config: Any, registry: Any = None) -> set[str]:
    """Hosts the module's providers get from their ``hosts_from_settings`` URL settings.

    Delegates to ``ProviderRegistry.hosts_for`` (https URLs only; a host owned by another provider
    is ignored) and drops the providers' static hosts: those count only when the module declares
    them in ``Module.hosts`` (P327 cond 4). Used by ``ctx.http`` and by the test kit
    (``FakeHttp.assert_hosts_within``)."""
    reg = registry if registry is not None else _providers.registry()
    hosts: set[str] = set()
    for pid in _module_providers(module_cls):
        prov = reg.get(pid)
        if prov is None:
            continue
        static = {str(h).lower() for h in (getattr(prov, "hosts", ()) or ())}
        hosts_for = getattr(reg, "hosts_for", None)
        found = hosts_for(pid, config) if callable(hosts_for) else ()
        hosts |= {str(h).lower() for h in found if str(h).lower() not in static}
    return hosts


def _disclosure_of(module_cls: Any) -> tuple[str, bool]:
    """(disclosure the context enforces, whether module host rules apply).

    Module subclasses always get module enforcement: a missing or invalid disclosure fails closed
    to 'none'. Other classes declaring a valid disclosure are treated like modules; plain core
    helpers without any (doctor probes) return ('', False).
    """
    declared = getattr(module_cls, "disclosure", None)
    text = declared if isinstance(declared, str) else ""
    if _is_module_class(module_cls):
        return (text if text in _DISCLOSURES else "none"), True
    if text in _DISCLOSURES:
        return text, True
    return "", False


def _is_module_class(module_cls: Any) -> bool:
    from v3lum.core.module import Module  # lazy: module.py must stay importable without context.py

    return isinstance(module_cls, type) and issubclass(module_cls, Module)


def _module_providers(module_cls: Any) -> list[str]:
    pids: list[str] = []
    derived = getattr(module_cls, "providers", None)
    if isinstance(derived, (set, frozenset, list, tuple)):
        pids.extend(str(p) for p in derived)
    primary = str(getattr(module_cls, "provider", "") or "")
    if primary:
        pids.append(primary)
    for sid in getattr(module_cls, "sources", ()) or ():
        if "." in str(sid):
            pids.append(str(sid).split(".", 1)[0])
    return sorted(set(pids))


def _markers(markers: Iterable[Any]) -> tuple[Any, ...]:
    """Module error markers as parsed objects (dicts parsed with providers.parse_marker)."""
    out: list[Any] = []
    for marker in markers:
        if isinstance(marker, dict):
            try:
                out.append(_providers.parse_marker(marker))
            except ValueError as exc:  # registration rejects these; never crash a run
                log.warning("ignoring invalid error marker %r: %s", marker, exc)
        else:
            out.append(marker)
    return tuple(out)


def _opsec(value: Any) -> Opsec:
    try:
        return Opsec.parse(value)
    except (KeyError, ValueError):
        return Opsec.PASSIVE


def _tlp(value: str) -> TLP:
    """Parse a TLP value; an unparseable one fails closed to RED (no public resolver, A2)."""
    try:
        return _parse_tlp(value)
    except ValueError:
        log.warning("invalid TLP %r: treated as TLP:RED", value)
        return TLP.RED


def _list_setting(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return [str(v) for v in value]
