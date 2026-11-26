"""Module (collector) API v2, the registration lint and the module registry.

Module-author contract v2, sections 1-2 (docs/MODULE_GUIDE.md). Writing a module::

    from v3lum.core.entities import EntityType as T
    from v3lum.core.models import Opsec
    from v3lum.core.module import Module, register

    @register
    class ShodanInternetDB(Module):
        name = "shodan_internetdb"
        title = "Shodan InternetDB"
        description = "Open ports, hostnames, CPEs and version-inferred CVEs for an IP."
        category = "ip_network"
        accepts = {T.IPV4, T.IPV6}
        produces = {T.DOMAIN, T.CVE}
        terms = "noncommercial"             # == most restrictive class of the sources (registry)
        opsec = Opsec.PASSIVE
        disclosure = "third_party"          # none | internal | third_party | target
        provider = "shodan"                 # v3lum/data/providers/shodan.json
        sources = ("shodan.internetdb",)
        hosts = ("internetdb.shodan.io",)   # owned by a provider of the sources
        access_model = "free_noauth_limited"
        max_requests = 1                    # HTTP requests per entity per run (DoH not counted)
        expected_latency = 1.0              # declared p50 seconds
        absent_statuses = frozenset({404})  # documented meaningful absence

        def run(self, entity, ctx):
            res = self.result(entity)
            data = ctx.http.get_json(f"https://internetdb.shodan.io/{entity.value}", source="shodan.internetdb")
            if data is None:
                return res.mark("empty")
            ...
            return res

``terms``, ``opsec``, ``disclosure`` and ``hosts`` MUST be declared in the class body (or in a base
class other than Module: mixins and compiled specs count); networked modules (disclosure != 'none')
also declare ``max_requests`` and ``expected_latency``. ``@register`` refuses, with a fix hint, every
module that breaks a rule of the contract (RegistrationError); ``load_modules()`` records such
failures in ``load_errors()`` and never crashes the tool. Derived attributes (trust tier, providers,
upstream families, reliability, sensitive, publishes/reuses/fetches_target, shares_input, max_tlp,
access_label, terms_sources) are computed from the provider registry and never declared.

Modules are discovered automatically from the ``v3lum.modules`` package (and from
``~/.v3lum/plugins/*.py``). They must be side-effect free at import time (registering datasets and
sanitizer schemas at the top level of the file is the only allowed import-time work).
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import logging
import math
import os
import pkgutil
import re
import sys
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from v3lum import config as _config
from v3lum.core import providers as _providers
from v3lum.core import tlp as _tlp
from v3lum.core.entities import Entity, EntityType
from v3lum.core.http import NEVER_ABSENT_STATUS
from v3lum.core.models import ModuleResult, Opsec, Status

if TYPE_CHECKING:  # pragma: no cover
    from v3lum.core.context import Context

log = logging.getLogger("v3lum.modules")

CONTRACT_VERSION = "v2"

CATEGORIES: dict[str, str] = {
    "domain_dns": "Domains & DNS",
    "ip_network": "IP & network",
    "url_web": "URLs & websites",
    "email": "Email",
    "username_social": "Usernames & social media",
    "phone": "Phone numbers",
    "breach_leak": "Breaches & leaks (metadata only)",
    "threat_intel_ioc": "Threat intel & reputation",
    "malware_hash": "Malware & file hashes",
    "vulnerability_cve": "Vulnerabilities (CVE)",
    "darkweb_ransomware": "Dark web & ransomware",
    "crypto": "Crypto assets",
    "company_org": "Companies & organizations",
    "brazil_public_data": "Brazil public data",
    "person_name": "People (names)",
    "geo_image_meta": "Geo, images & metadata",
    "file_analysis": "File analysis",
    "pentest_recon": "Pentest & recon",
    "cti_framework": "CTI frameworks (ATT&CK, actors)",
    "search_dorks": "Search & dorks",
    "utility": "Utilities",
}

#: Terms classes (A1), least to most restrictive (same order as providers.TERMS_ORDER).
TERMS: tuple[str, ...] = ("open", "key-terms", "license", "noncommercial", "unknown")
#: Where the investigated value goes (A8): nowhere, company platforms, an external provider, the target.
DISCLOSURES: tuple[str, ...] = ("none", "internal", "third_party", "target")
#: Which entities a module may run on (A4/A5/A11): any, analyst-typed seeds, own assets (per-person
#: breach checks), verified own assets only (txt_verified/attested org entries).
RUN_ON: tuple[str, ...] = ("any", "seeds", "own_assets", "own_assets_only")
#: Data-source access models (P332 cond 6, SpiderFoot taxonomy) and their plain-words labels.
ACCESS_MODELS: tuple[str, ...] = (
    "free_noauth_unlimited",
    "free_noauth_limited",
    "free_auth_limited",
    "free_auth_unlimited",
    "commercial_only",
    "internal",
    "offline",
)
ACCESS_LABELS: dict[str, str] = {
    "free_noauth_unlimited": "free, no key, unlimited",
    "free_noauth_limited": "free, no key, limited",
    "free_auth_limited": "free key, limited",
    "free_auth_unlimited": "free key, unlimited",
    "commercial_only": "paid only",
    "internal": "internal platform",
    "offline": "offline",
}
#: access_model used when a module does not declare one (required for disclosure 'third_party').
DEFAULT_ACCESS_MODEL: dict[str, str] = {"none": "offline", "internal": "internal", "target": "free_noauth_unlimited"}

#: Reserved module tags -> meaning (other tags are free-form).
RESERVED_TAGS: dict[str, str] = {
    "core": "maintained with the core framework (reference/template modules)",
    "offline": "works without network: local data or computation only",
    "slow": "slow source (declared p50 above 10 s): never in the default set",
    "noisy": "produces many low-value findings or pivots",
    "brazil": "Brazil-specific source or data",
    "free": "usable without a paid plan",
    "curated_pack": "curated site pack with its own request cap and deadline (A5): may declare max_requests > 10 and stay default",
    "cached_only": "queries a fetches_target provider only in cached/no-publication mode, so it may be default (A3)",
    "high_fp": "known high false-positive rate: never default (A3)",
    "bulk_download": "downloads bulk data: never default (A3)",
    "people_sweep": "person-profiling sweep: never default (A3)",
    "sensitive_sites": "covers sensitive site categories (NSFW, dating, religion, health, politics): never default (A3/A5)",
    "fresh_assessment": "makes a fetches_target provider assess the target afresh: never default (A3)",
    "cert_derived": "data derived from TLS certificates or Certificate Transparency",
    "pack": "pivot-link or site pack module",
    "reputation": (
        "returns a malicious/suspicious/benign verdict for its accepted IOC types: only such modules count for the "
        "'inconclusive' threshold (P302 cond 6), the A3 minimum answer set and the doctor warning"
    ),
    "watch_source": "polling source invoked by each `v3lum watch` cycle on org-profile rule entities; reports new names in attribute watch_hits",
    "watch_only": "never selected outside `v3lum watch`",
}
#: Tags that force default_enabled False (A3).
NEVER_DEFAULT_TAGS: tuple[str, ...] = ("high_fp", "bulk_download", "people_sweep", "sensitive_sites", "fresh_assessment")

#: Must be declared in the class body of every module.
MUST_DECLARE: tuple[str, ...] = ("terms", "opsec", "disclosure", "hosts")
#: Must also be declared when disclosure != 'none'.
MUST_DECLARE_NETWORKED: tuple[str, ...] = ("max_requests", "expected_latency")
#: Set by @register from the provider registry; declaring any of them fails registration.
DERIVED: tuple[str, ...] = (
    "trust_tier",
    "providers",
    "upstream_families",
    "reliability",
    "sensitive",
    "publishes_queries",
    "reuses_queries",
    "fetches_target",
    "shares_input",
    "max_tlp",
    "access_label",
    "terms_sources",
)
#: v1 names removed in v2 (declaring them fails registration).
REMOVED: tuple[str, ...] = ("user_agent", "shares_input")
#: Why each removed name went away (the fix hint of the registration error).
REMOVED_REASONS: dict[str, str] = {
    "user_agent": "the provider http_profile chooses the User-Agent (P326)",
    "shares_input": "it is derived from disclosure (shares_input = disclosure in {'third_party', 'target'})",
}

#: Hard request-rate ceilings per target host (A7): modules and profiles cannot raise them.
CEILINGS: dict[str, float] = {"light_max_rps": 1.0, "active_max_rps": 10.0}

#: Benign values for default health checks, in preference order (doctor, keys wizard; P332 cond 9).
BENIGN_VALUES: dict[EntityType, str] = {
    EntityType.DOMAIN: "example.com",
    EntityType.URL: "https://example.com/",
    EntityType.EMAIL: "someone@example.com",
    EntityType.IPV4: "8.8.8.8",
    EntityType.IPV6: "2001:4860:4860::8888",
    EntityType.CIDR: "8.8.8.0/24",
    EntityType.ASN: "AS15169",
    EntityType.MD5: "44d88612fea8a8f36de82e1278abb02f",  # EICAR test file
    EntityType.SHA1: "3395856ce81f2b7382dee72602f798b642f14140",  # EICAR test file
    EntityType.SHA256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR test file
    EntityType.CVE: "CVE-2021-44228",
    EntityType.USERNAME: "octocat",
}

#: Core optional packages: import name -> pyproject extra. Fragments add more (see OPTIONAL_PACKAGES).
CORE_OPTIONAL_PACKAGES: dict[str, str] = {
    "phonenumbers": "full",
    "dns": "full",
    "PIL": "full",
    "pypdf": "full",
    "socks": "full",
    "websocket": "watch",
    "yaml": "yaml",
}
EXTRAS_DIR = Path(__file__).resolve().parent.parent / "data" / "extras"
EXTRA_SCHEMA = "v3lum.extra/1"

#: Module names @register refuses: 'core' is the owner of the built-in settings (config.CORE_OWNER).
RESERVED_NAMES: frozenset[str] = frozenset({_config.CORE_OWNER})

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_SETTING_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_SOURCE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}\.[a-z][a-z0-9_]{0,63}$")
_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
_PACKAGE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
_EXTRA_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
#: Attribute names @register wrote on a class (derived values and filled defaults), not declared by its author.
_MARK = "__v3lum_set_by_register__"


class RegistrationError(ValueError):
    """A module breaks the module contract: '<module>: <problem> - <how to fix>'."""


HEALTH_STATUSES: tuple[str, ...] = ("ok", "blocked", "quota", "needs_key", "dead")


@dataclass(frozen=True)
class HealthResult:
    """Outcome of a module self-test: status 'ok' | 'blocked' | 'quota' | 'needs_key' | 'dead'."""

    status: str
    detail: str = ""

    def __post_init__(self) -> None:
        if self.status not in HEALTH_STATUSES:
            raise ValueError(f"health status must be one of {', '.join(HEALTH_STATUSES)} (got {self.status!r})")

    @property
    def ok(self) -> bool:
        return self.status == "ok"


@dataclass(frozen=True)
class HealthCheck:
    """How doctor (P337) and the keys wizard (P379) check a module; the calls count against quotas.

    * benign probe: ``HealthCheck(etype, value, expect='ok')`` runs the module on a benign value;
    * self-test: ``HealthCheck(offline=True, selftest=fn)`` with ``fn(ctx) -> HealthResult``. With
      ``offline=True`` the ctx has no network beyond loopback (mandatory for LIGHT/ACTIVE modules);
      with ``offline=False`` it is a normal passive ctx (e.g. packs sampling claimed/unclaimed handles).
    """

    etype: EntityType | None = None
    value: str = ""
    expect: str = "ok"
    offline: bool = False
    selftest: Callable[[Any], HealthResult] | None = None

    @property
    def entity(self) -> Entity | None:
        """The benign entity probed (None for pure self-tests)."""
        if self.etype is None or not self.value:
            return None
        return Entity.try_make(self.etype, self.value)


@dataclass(frozen=True)
class Readiness:
    """Static readiness of a module: ``ready`` plus the Status and canonical reason code when not ready."""

    ready: bool
    status: Status
    reason_code: str
    reason: str

    def __iter__(self):  # legacy unpacking: ready, reason = readiness(...)
        return iter((self.ready, self.reason))


@dataclass(frozen=True)
class ExtraSpec:
    """An optional dependency fragment ``v3lum/data/extras/<package>.json`` (schema 'v3lum.extra/1')."""

    package: str
    pip: str
    extra: str
    licence: str
    justification: str
    origin: str = ""


# ---------------------------------------------------------------------------------- optional packages

#: Every optional package a module may require: CORE_OPTIONAL_PACKAGES merged with the extras fragments.
OPTIONAL_PACKAGES: dict[str, str] = dict(CORE_OPTIONAL_PACKAGES)
#: Extras fragments by import name (details for doctor and the notices registry).
EXTRAS: dict[str, ExtraSpec] = {}
_EXTRAS_ERRORS: list[str] = []


def reload_extras(directory: str | Path | None = None) -> dict[str, str]:
    """(Re)load the extras fragments into OPTIONAL_PACKAGES/EXTRAS in place. Never raises.

    Fragment: ``{"schema": "v3lum.extra/1", "package" (import name = file stem), "pip" (requirement
    spec), "extra" (pyproject extra), "licence", "justification"}``. GPL/AGPL packages are refused (A6:
    only as external processes); problems are listed by ``extras_errors()`` and in ``load_errors()``.
    """
    base = Path(directory) if directory is not None else EXTRAS_DIR
    merged = dict(CORE_OPTIONAL_PACKAGES)
    extras: dict[str, ExtraSpec] = {}
    errors: list[str] = []
    files = sorted(base.glob("*.json")) if base.is_dir() else []
    for path in files:
        where = path.name
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            errors.append(f"{where}: invalid JSON ({exc})")
            continue
        problems: list[str] = []
        if not isinstance(data, dict):
            errors.append(f"{where}: an extras fragment must be a JSON object")
            continue
        if data.get("schema") != EXTRA_SCHEMA:
            problems.append(f"schema must be {EXTRA_SCHEMA!r}")
        unknown = sorted(set(data) - {"schema", "package", "pip", "extra", "licence", "justification", "notes"})
        if unknown:
            problems.append(f"unknown field(s) {', '.join(unknown)}")
        package = data.get("package")
        if not isinstance(package, str) or not _PACKAGE_RE.match(package):
            problems.append("package must be the import name (e.g. 'websocket')")
        elif path.stem != package:
            problems.append(f"file name must be '{package}.json'")
        for name in ("pip", "licence", "justification"):
            if not isinstance(data.get(name), str) or not data[name].strip():
                problems.append(f"{name} is required")
        extra = data.get("extra")
        if not isinstance(extra, str) or not _EXTRA_NAME_RE.match(extra):
            problems.append("extra must be a pyproject extra name (e.g. 'full', 'watch')")
        licence = str(data.get("licence") or "").upper()
        if "AGPL" in licence or ("GPL" in licence and "LGPL" not in licence):
            problems.append("GPL/AGPL packages are never dependencies (A6: run them as external processes)")
        if not problems and package in merged and merged[package] != extra:
            problems.append(f"package {package!r} already belongs to extra {merged[package]!r}")
        if not problems and package in extras:
            problems.append(f"package {package!r} is declared twice")
        if problems:
            errors.append(f"{where}: " + "; ".join(problems))
            continue
        extras[package] = ExtraSpec(package, data["pip"], extra, data["licence"], data["justification"], origin=where)
        merged[package] = extra
    OPTIONAL_PACKAGES.clear()
    OPTIONAL_PACKAGES.update(merged)
    EXTRAS.clear()
    EXTRAS.update(extras)
    _EXTRAS_ERRORS[:] = errors
    return OPTIONAL_PACKAGES


def extras_errors() -> list[str]:
    """Problems found in the extras fragments (the registry contract test requires none)."""
    return list(_EXTRAS_ERRORS)


reload_extras()


# ---------------------------------------------------------------------------------- the base class


class Module:
    """Base class of every collector/analyzer (module-author contract v2).

    Class attributes are grouped as in the contract: identity, inputs/outputs, MUST-declare,
    other ClassVars (with their defaults) and the derived attributes set by @register.
    """

    # -- identity ---------------------------------------------------------------------------------
    #: unique id ^[a-z][a-z0-9_]{2,63}$ (CLI: ``v3lum run <name> <input>``).
    name: ClassVar[str] = ""
    #: human friendly title shown in tables.
    title: ClassVar[str] = ""
    #: one/two sentence description (what it does, what source it uses).
    description: ClassVar[str] = ""
    #: one of CATEGORIES.
    category: ClassVar[str] = "utility"
    #: documentation / terms URL of the source.
    reference: ClassVar[str] = ""
    #: free-form tags; RESERVED_TAGS have a defined meaning.
    tags: ClassVar[frozenset[str] | set[str]] = frozenset()
    #: legal/ethical note shown by ``v3lum info``.
    notice: ClassVar[str] = ""

    # -- inputs / outputs -------------------------------------------------------------------------
    #: entity types this module investigates (non-empty).
    accepts: ClassVar[set[EntityType] | frozenset[EntityType]] = frozenset()
    #: entity types it may discover (documentation / planning).
    produces: ClassVar[set[EntityType] | frozenset[EntityType]] = frozenset()
    #: 'any' | 'seeds' | 'own_assets' | 'own_assets_only' (see RUN_ON).
    run_on: ClassVar[str] = "any"

    # -- MUST be declared in the class body -------------------------------------------------------
    #: provider terms class (A1): 'open' | 'key-terms' | 'license' | 'noncommercial' | 'unknown'.
    terms: ClassVar[str] = "unknown"
    #: how much the module touches the target.
    opsec: ClassVar[Opsec] = Opsec.PASSIVE
    #: 'none' | 'internal' | 'third_party' | 'target' - no default: '' means undeclared.
    disclosure: ClassVar[str] = ""
    #: hosts contacted: exact names or '*.suffix' wildcards; () for none/target/DoH-only modules.
    hosts: ClassVar[tuple[str, ...]] = ()

    # -- other ClassVars ---------------------------------------------------------------------------
    #: primary provider id (v3lum/data/providers); required for third_party/internal.
    provider: ClassVar[str] = ""
    #: registry source ids 'provider.source'; required for third_party/internal (dataset users list theirs).
    sources: ClassVar[tuple[str, ...]] = ()
    #: one of ACCESS_MODELS; '' = per disclosure (none: offline, internal: internal, target:
    #: free_noauth_unlimited); required for third_party.
    access_model: ClassVar[str] = ""
    #: registered key names that MUST be configured (NEEDS_KEY otherwise).
    requires_keys: ClassVar[tuple[str, ...]] = ()
    #: registered key names that unlock more data/quota.
    optional_keys: ClassVar[tuple[str, ...]] = ()
    #: import names of optional packages (must be in OPTIONAL_PACKAGES; UNAVAILABLE 'package' when missing).
    requires_packages: ClassVar[tuple[str, ...]] = ()
    #: HTTP requests through ctx.http per entity per run (0..100000; DoH not counted).
    max_requests: ClassVar[int] = 10
    #: declared p50 latency in seconds.
    expected_latency: ClassVar[float] = 5.0
    #: run deadline in seconds (0 = no per-run deadline: only the scan deadline applies).
    timeout: ClassVar[float] = 60.0
    #: minimum seconds between requests to this module's hosts (politeness = max(module, profile)).
    min_interval: ClassVar[float] = 0.0
    #: LIGHT/ACTIVE request rate per target host in req/s (LIGHT <= 1.0, ACTIVE <= 10.0); None = ceiling.
    max_rate: ClassVar[float | None] = None
    #: fallback daily budget when the provider has no registry quota block.
    daily_quota: ClassVar[int | None] = None
    #: HTTP cache TTL in seconds for this module's requests; None = provider profile / global default.
    cache_ttl: ClassVar[int | None] = None
    #: max pivots the engine keeps from one run.
    max_pivots: ClassVar[int] = 100
    #: ISO 3166 alpha-2 egress countries the source needs (e.g. frozenset({'BR'})).
    requires_egress: ClassVar[frozenset[str]] = frozenset()
    #: HTTP statuses that are documented meaningful absences (e.g. frozenset({404})).
    absent_statuses: ClassVar[frozenset[int]] = frozenset()
    #: module error-in-200 markers (provider error-marker schema; ErrorMarker after registration).
    error_markers: ClassVar[tuple[Any, ...]] = ()
    #: '<pack>:<link_id>' or an inline https template; emitted when automation is skipped/blocked.
    manual_link: ClassVar[str] = ""
    #: candidate flag for the default set (can lower, never force it; A3 rules apply).
    default_enabled: ClassVar[bool] = True
    #: module-scoped settings name -> default (ctx.setting / ``v3lum config set``; names unique).
    settings: ClassVar[dict[str, Any]] = {}

    # -- derived by @register from the provider registry (never declared) -------------------------
    #: 'trusted' | 'community' | 'unknown' (lowest tier of the module's providers); 'n/a' for none/internal/target.
    trust_tier: ClassVar[str] = "unknown"
    #: {provider} | providers of the sources.
    providers: ClassVar[frozenset[str]] = frozenset()
    #: upstream families of the sources (including the families they embed).
    upstream_families: ClassVar[frozenset[str]] = frozenset()
    #: Admiralty grade A-F of the primary provider ('' without provider).
    reliability: ClassVar[str] = ""
    #: category breach_leak or any sensitive provider (A4).
    sensitive: ClassVar[bool] = False
    #: any value-receiving provider publishes submitted values (rule 7).
    publishes_queries: ClassVar[bool] = False
    #: any value-receiving provider may reuse submitted values.
    reuses_queries: ClassVar[bool] = False
    #: any value-receiving provider fetches the target live.
    fetches_target: ClassVar[bool] = False
    #: disclosure in {'third_party', 'target'} (v1 alias).
    shares_input: ClassVar[bool] = True
    #: highest TLP the module may receive (tlp.TLP, None = never; tlp.max_tlp).
    max_tlp: ClassVar[Any] = None
    #: plain-words label of access_model.
    access_label: ClassVar[str] = ""
    #: source id -> terms class.
    terms_sources: ClassVar[dict[str, str]] = {}

    # ---------------------------------------------------------------------------------------------

    def applies(self, entity: Entity, ctx: Context) -> bool:  # noqa: ARG002 - hook
        """Extra applicability filter beyond ``accepts`` (e.g. only public IPs); False -> SKIPPED 'not_applicable'."""
        return True

    def run(self, entity: Entity, ctx: Context) -> ModuleResult:  # pragma: no cover - abstract
        raise NotImplementedError

    def result(self, entity: Entity) -> ModuleResult:
        """A new ModuleResult for this module and entity (use its builder helpers)."""
        return ModuleResult(module=self.name, entity=entity)

    # ---------------------------------------------------------------------------------------------

    @classmethod
    def health_check(cls) -> HealthCheck | None:
        """Default health check: a benign value of the first accepted type in BENIGN_VALUES.

        None for disclosure 'none' (nothing remote to check) and for target-contact modules: LIGHT/
        ACTIVE modules MUST override it with ``HealthCheck(offline=True, selftest=fn)`` (loopback-only
        self-test; the registry contract test enforces it), so doctor never probes a real target.
        """
        if cls.disclosure in ("none", "target", ""):
            return None
        for etype, value in BENIGN_VALUES.items():
            if etype in cls.accepts:
                return HealthCheck(etype=etype, value=value)
        return None

    @classmethod
    def describe(cls) -> dict[str, Any]:
        """Every metadata field (v1 keys kept, v2 fields added; JSON-serialisable)."""
        max_tlp = cls.max_tlp
        return {
            # v1 keys
            "name": cls.name,
            "title": cls.title or cls.name,
            "description": cls.description,
            "category": cls.category,
            "accepts": sorted(t.value for t in cls.accepts),
            "produces": sorted(t.value for t in cls.produces),
            "opsec": cls.opsec.label,
            "requires_keys": list(cls.requires_keys),
            "optional_keys": list(cls.optional_keys),
            "requires_packages": list(cls.requires_packages),
            "hosts": list(cls.hosts),
            "reference": cls.reference,
            "tags": sorted(cls.tags),
            "default_enabled": cls.default_enabled,
            "notice": cls.notice,
            "shares_input": cls.shares_input,
            "terms": cls.terms,
            "daily_quota": cls.daily_quota,
            # v2 fields
            "disclosure": cls.disclosure,
            "provider": cls.provider,
            "sources": list(cls.sources),
            "access_model": cls.access_model,
            "access_label": cls.access_label,
            "run_on": cls.run_on,
            "max_requests": cls.max_requests,
            "expected_latency": cls.expected_latency,
            "timeout": cls.timeout,
            "min_interval": cls.min_interval,
            "cache_ttl": cls.cache_ttl,
            "max_pivots": cls.max_pivots,
            "requires_egress": sorted(cls.requires_egress),
            "max_rate": cls.max_rate,
            "absent_statuses": sorted(cls.absent_statuses),
            "error_markers": [m.to_dict() if hasattr(m, "to_dict") else dict(m) for m in cls.error_markers],
            "manual_link": cls.manual_link,
            "settings": dict(cls.settings),
            "trust_tier": cls.trust_tier,
            "providers": sorted(cls.providers),
            "upstream_families": sorted(cls.upstream_families),
            "reliability": cls.reliability,
            "sensitive": cls.sensitive,
            "publishes_queries": cls.publishes_queries,
            "reuses_queries": cls.reuses_queries,
            "fetches_target": cls.fetches_target,
            "max_tlp": max_tlp.value_str if max_tlp is not None and hasattr(max_tlp, "value_str") else None,
            "terms_sources": dict(cls.terms_sources),
            "contract": CONTRACT_VERSION,
        }


REGISTRY: dict[str, type[Module]] = {}
_LOAD_ERRORS: dict[str, str] = {}
_LOADED = False
_REGISTER_LOCK = threading.RLock()
#: modules whose settings were registered through @register (stale owners are released on re-use)
_SETTINGS_OWNERS: set[str] = set()


# ---------------------------------------------------------------------------------- registration lint


def _declared(cls: type, attr: str) -> bool:
    """Present in the class's own __dict__ or a base other than Module (values @register wrote do not count)."""
    for klass in cls.__mro__:
        if klass is Module or klass is object:
            continue
        own = klass.__dict__
        if attr in own and attr not in own.get(_MARK, ()):
            return True
    return False


def _fail(cls: type, problem: str, fix: str) -> RegistrationError:
    name = getattr(cls, "name", "") or getattr(cls, "__name__", "?")
    return RegistrationError(f"{name}: {problem} - {fix}")


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _str_tuple(cls: type, attr: str, value: Any) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable) or not all(isinstance(v, str) for v in value):
        raise _fail(cls, f"{attr} must be a tuple of strings (got {value!r})", f"write {attr} = ('a', 'b') - a bare string is not a tuple")
    return tuple(value)


def _entity_types(cls: type, attr: str, value: Any) -> frozenset[EntityType]:
    if isinstance(value, (str, EntityType)) or not isinstance(value, Iterable):
        raise _fail(cls, f"{attr} must be a set of EntityType (got {value!r})", f"write {attr} = {{EntityType.DOMAIN, ...}}")
    out: set[EntityType] = set()
    for item in value:
        try:
            out.add(item if isinstance(item, EntityType) else EntityType.parse(str(item)))
        except ValueError:
            raise _fail(cls, f"{attr} has an unknown entity type {item!r}", "use members of v3lum.core.entities.EntityType")
    return frozenset(out)


def _validate_manual_link(value: str) -> list[str]:
    from v3lum.core import links  # lazy: links may import the provider registry

    return list(links.validate_manual_link(value))


def _schema_for(source_id: str) -> Any:
    from v3lum.core import sanitize  # lazy: sanitize imports the provider registry

    return sanitize.schema_for(source_id)


def _release_stale_settings() -> None:
    for owner in [o for o in _SETTINGS_OWNERS if o not in REGISTRY]:
        _config.unregister_settings(owner)
        _SETTINGS_OWNERS.discard(owner)


def _check(cls: type[Module]) -> dict[str, Any]:
    """Run every registration rule in contract order; return the normalised and derived values."""
    out: dict[str, Any] = {}
    # 1. identity / enums ---------------------------------------------------------------------------
    name = cls.__dict__.get("name", getattr(cls, "name", ""))
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise _fail(cls, f"invalid module name {name!r}", "name must match ^[a-z][a-z0-9_]{2,63}$ (unique snake_case id)")
    if name in RESERVED_NAMES:
        raise _fail(cls, f"module name {name!r} is reserved", "choose another name ('core' owns the built-in settings)")
    existing = REGISTRY.get(name)
    same_class = existing is None or existing is cls or f"{existing.__module__}.{existing.__qualname__}" == f"{cls.__module__}.{cls.__qualname__}"
    if not same_class:
        raise _fail(cls, f"duplicate module name {name!r} ({existing.__module__} vs {cls.__module__})", "choose a unique name")
    for attr in ("title", "description", "notice", "reference", "manual_link", "provider"):
        if not isinstance(getattr(cls, attr), str):
            raise _fail(cls, f"{attr} must be a string", f"declare {attr} = '...'")
    if cls.reference and not re.match(r"^https?://\S+$", cls.reference):
        raise _fail(cls, f"reference {cls.reference!r} is not an http(s) URL", "point reference to the source's documentation or terms page")
    if not isinstance(cls.category, str) or cls.category not in CATEGORIES:
        raise _fail(cls, f"unknown category {cls.category!r}", f"use one of {', '.join(CATEGORIES)}")
    out["accepts"] = _entity_types(cls, "accepts", cls.accepts)
    if not out["accepts"]:
        raise _fail(cls, "accepts is empty", "declare the entity types the module investigates")
    out["produces"] = _entity_types(cls, "produces", cls.produces)
    tags = cls.tags
    if isinstance(tags, str) or not isinstance(tags, Iterable) or not all(isinstance(t, str) and _TAG_RE.match(t) for t in tags):
        raise _fail(cls, f"tags must be a set of lower-case strings (got {tags!r})", "write tags = {'free', 'core'}")
    out["tags"] = frozenset(tags)
    # 2. MUST-declare -------------------------------------------------------------------------------
    missing = [a for a in MUST_DECLARE if not _declared(cls, a)]
    if missing:
        raise _fail(
            cls,
            f"{', '.join(missing)} not declared in the class body",
            "declare terms ('open'|'key-terms'|'license'|'noncommercial'|'unknown'), opsec (Opsec.PASSIVE|LIGHT|ACTIVE), "
            "disclosure ('none'|'internal'|'third_party'|'target') and hosts (a tuple, () for none/target/DoH-only) explicitly",
        )
    for attr in REMOVED:
        if _declared(cls, attr):
            raise _fail(cls, f"declares {attr!r}, removed in contract v2", f"delete it: {REMOVED_REASONS[attr]}")
    for attr in DERIVED:
        if attr not in REMOVED and _declared(cls, attr):
            raise _fail(cls, f"declares the derived attribute {attr!r}", "delete it: @register derives it from the provider registry")
    if cls.terms not in TERMS:
        raise _fail(cls, f"unknown terms class {cls.terms!r}", f"use one of {', '.join(TERMS)}")
    try:
        if isinstance(cls.opsec, bool):  # True would silently read as LIGHT (bool is an int)
            raise ValueError("boolean opsec")
        opsec = Opsec.parse(cls.opsec)
    except (KeyError, ValueError):
        raise _fail(cls, f"invalid opsec {cls.opsec!r}", "use Opsec.PASSIVE, Opsec.LIGHT or Opsec.ACTIVE")
    out["opsec"] = opsec
    disclosure = cls.disclosure
    if disclosure not in DISCLOSURES:
        raise _fail(cls, f"unknown disclosure {disclosure!r}", f"use one of {', '.join(DISCLOSURES)}")
    if disclosure != "none":
        missing = [a for a in MUST_DECLARE_NETWORKED if not _declared(cls, a)]
        if missing:
            raise _fail(cls, f"{', '.join(missing)} not declared (disclosure {disclosure!r})", "networked modules declare max_requests (per entity per run) and expected_latency (p50 seconds)")
    if cls.run_on not in RUN_ON:
        raise _fail(cls, f"unknown run_on {cls.run_on!r}", f"use one of {', '.join(RUN_ON)}")
    # only a declared access_model counts: a default filled in for a base class must not leak into subclasses
    access_model = cls.access_model if _declared(cls, "access_model") else ""
    if access_model and access_model not in ACCESS_MODELS:
        raise _fail(cls, f"unknown access_model {access_model!r}", f"use one of {', '.join(ACCESS_MODELS)}")
    if not access_model:
        if disclosure == "third_party":
            raise _fail(cls, "access_model not declared", f"third_party modules declare one of {', '.join(ACCESS_MODELS)}")
        access_model = DEFAULT_ACCESS_MODEL[disclosure]
        out["_default_access_model"] = access_model
    out["access_model"] = access_model
    hosts = _str_tuple(cls, "hosts", cls.hosts)
    bad = [h for h in hosts if not _providers.valid_host_pattern(h)]
    if bad:
        raise _fail(cls, f"invalid host {bad[0]!r}", "hosts are lower-case exact names or '*.suffix' wildcards (no scheme, port or path)")
    out["hosts"] = hosts
    sources = _str_tuple(cls, "sources", cls.sources)
    bad = [s for s in sources if not _SOURCE_ID_RE.match(s)]
    if bad:
        raise _fail(cls, f"invalid source id {bad[0]!r}", "sources are qualified registry ids 'provider.source'")
    out["sources"] = sources
    for attr in ("requires_keys", "optional_keys", "requires_packages"):
        out[attr] = _str_tuple(cls, attr, getattr(cls, attr))
    if not isinstance(cls.default_enabled, bool):
        raise _fail(cls, "default_enabled must be a boolean", "write default_enabled = True or False")
    max_requests = cls.max_requests
    if not isinstance(max_requests, int) or isinstance(max_requests, bool) or not 0 <= max_requests <= 100000:
        raise _fail(cls, f"max_requests {max_requests!r} out of range", "declare an integer 0..100000 (HTTP requests per entity per run)")
    for attr in ("expected_latency", "timeout", "min_interval"):
        value = getattr(cls, attr)
        if not _is_number(value) or value < 0:
            raise _fail(cls, f"{attr} {value!r} is not a valid number of seconds", f"declare {attr} as a non-negative number")
    if cls.daily_quota is not None and (not isinstance(cls.daily_quota, int) or isinstance(cls.daily_quota, bool) or cls.daily_quota < 1):
        raise _fail(cls, f"daily_quota {cls.daily_quota!r} is invalid", "use None or a positive integer (requests per day)")
    if cls.cache_ttl is not None and (not isinstance(cls.cache_ttl, int) or isinstance(cls.cache_ttl, bool) or cls.cache_ttl < 0):
        raise _fail(cls, f"cache_ttl {cls.cache_ttl!r} is invalid", "use None or a non-negative integer (seconds)")
    if not isinstance(cls.max_pivots, int) or isinstance(cls.max_pivots, bool) or cls.max_pivots < 0:
        raise _fail(cls, f"max_pivots {cls.max_pivots!r} is invalid", "use a non-negative integer")
    if not isinstance(cls.settings, Mapping):
        raise _fail(cls, "settings must be a dict name -> default", "write settings = {'mymodule_limit': 10}")

    reg = _providers.registry()
    provider = cls.provider

    def resolve_provider() -> Any:
        found = reg.get(provider) if provider else None
        if provider and found is None:
            raise _fail(cls, f"provider {provider!r} is not registered", "add a v3lum/data/providers/<id>.json fragment (see the README there)")
        return found

    def resolve_sources() -> list[Any]:
        found = []
        for sid in sources:
            src = reg.source(sid)
            if src is None:
                raise _fail(cls, f"source {sid!r} is not in the provider registry", f"add it to v3lum/data/providers/{sid.split('.', 1)[0]}.json (or an extension fragment)")
            found.append(src)
        return found

    # 3. opsec LIGHT/ACTIVE <=> disclosure 'target' --------------------------------------------------
    if opsec >= Opsec.LIGHT and disclosure != "target":
        raise _fail(cls, f"{opsec.label} module with disclosure {disclosure!r}", "LIGHT/ACTIVE modules contact the target: declare disclosure = 'target'")
    if disclosure == "target" and opsec is Opsec.PASSIVE:
        raise _fail(cls, "disclosure 'target' on a PASSIVE module", "PASSIVE modules never contact the target: use 'third_party' (or opsec LIGHT/ACTIVE)")
    # 4. disclosure 'none' => no hosts, no provider ---------------------------------------------------
    if disclosure == "none" and (hosts or provider):
        raise _fail(cls, "offline module (disclosure 'none') declares hosts or a provider", "remove hosts/provider: 'none' modules get no network (dataset users list only their dataset sources)")
    # 5./6. 'internal' and 'third_party' need a registered provider and registered sources -------------
    if disclosure == "internal" and (not provider or not sources):
        raise _fail(cls, "internal module without provider or sources", "declare provider (an internal=true provider) and its sources")
    if disclosure == "third_party" and (not provider or not sources):
        raise _fail(cls, "third_party module without a registered provider and sources", "declare provider='<id>' and sources=('<id>.<source>',) from v3lum/data/providers")
    primary = resolve_provider()
    resolved = resolve_sources()  # none/target modules: their (dataset) sources must be registered too (rule 7)
    src_providers = {s.provider for s in resolved}
    all_pids = ({provider} if provider else set()) | src_providers
    all_providers = [reg.get(pid) for pid in sorted(all_pids)]
    # 5. 'internal' => internal providers only -------------------------------------------------------
    if disclosure == "internal":
        external = [p.id for p in all_providers if p is not None and not p.internal]
        if external:
            raise _fail(cls, f"disclosure 'internal' but provider(s) {', '.join(external)} are not internal", "use 'third_party', or providers marked internal: true (company-operated or contracted, A12)")
    # 6. 'third_party' (and 'internal'): the primary provider has sources and owns, with them, every host.
    #    Target-contact modules reach target-derived hosts; any host they declare besides is a provider
    #    host and needs a registry entry too (AR11: an entry for every host a module declares).
    if disclosure in ("third_party", "internal") and provider not in src_providers:
        raise _fail(cls, f"primary provider {provider!r} has none of the module's sources", f"list the {provider} sources the module queries in sources")
    if disclosure in ("third_party", "internal", "target"):
        for host in hosts:
            owner = reg.provider_for_host(host)
            if owner is None:
                raise _fail(cls, f"host {host!r} is not in the provider registry", "add it to the hosts of the provider fragment that owns it (or an extension fragment)")
            if owner.id not in src_providers:
                raise _fail(cls, f"host {host!r} belongs to provider {owner.id!r}, which has none of the module's sources", f"list the {owner.id} sources the module uses, or drop the host")
    # 7. terms == most restrictive source class ------------------------------------------------------
    if sources:
        expected = _providers.most_restrictive(s.terms.class_ for s in resolved)
        if cls.terms != expected:
            worst = ", ".join(f"{s.id}={s.terms.class_}" for s in resolved)
            raise _fail(cls, f"terms {cls.terms!r} but the most restrictive source class is {expected!r} ({worst})", f"declare terms = {expected!r}")
    else:
        if disclosure not in ("none", "target"):
            raise _fail(cls, f"disclosure {disclosure!r} without registry sources", "list the registry sources the module queries")
        if cls.terms != "open":
            raise _fail(cls, f"terms {cls.terms!r} without registry sources", "modules without sources (offline/target) declare terms = 'open'; dataset users list their dataset sources")
    # 8. max_rate ceilings ------------------------------------------------------------------------------
    if cls.max_rate is not None:
        if not _is_number(cls.max_rate) or cls.max_rate <= 0:
            raise _fail(cls, f"max_rate {cls.max_rate!r} is invalid", "use None or a positive number of requests per second")
        if opsec is Opsec.PASSIVE:
            raise _fail(cls, "max_rate on a PASSIVE module", "max_rate is the LIGHT/ACTIVE rate per target host; use min_interval for provider politeness")
        ceiling = CEILINGS["light_max_rps"] if opsec is Opsec.LIGHT else CEILINGS["active_max_rps"]
        if cls.max_rate > ceiling:
            raise _fail(cls, f"max_rate {cls.max_rate} above the {opsec.label} ceiling {ceiling} req/s", f"declare max_rate <= {ceiling} (A7 hard ceiling)")
    # 9. requires_egress codes ----------------------------------------------------------------------
    egress = cls.requires_egress
    if isinstance(egress, str) or not isinstance(egress, Iterable) or not all(isinstance(c, str) and _COUNTRY_RE.match(c) for c in egress):
        raise _fail(cls, f"requires_egress {egress!r} is invalid", "use a frozenset of ISO 3166 alpha-2 codes, e.g. frozenset({'BR'})")
    out["requires_egress"] = frozenset(egress)
    # 10. absent_statuses 100-599, never a refusal or a failure (rule 5) ---------------------------------
    absent = cls.absent_statuses
    if isinstance(absent, (str, int)) or not isinstance(absent, Iterable) or not all(isinstance(s, int) and not isinstance(s, bool) and 100 <= s <= 599 for s in absent):
        raise _fail(cls, f"absent_statuses {absent!r} is invalid", "use a frozenset of HTTP status codes 100-599, e.g. frozenset({404})")
    refusals = sorted(s for s in absent if s in NEVER_ABSENT_STATUS or s >= 500)
    if refusals:
        raise _fail(
            cls,
            f"absent_statuses {refusals} mean 'could not verify', never an absence (rule 5)",
            "declare only documented meaningful absences such as 404/410: 401/403/407/429/430/451 and 5xx are refusals or failures",
        )
    out["absent_statuses"] = frozenset(absent)
    # 11. error_markers schema --------------------------------------------------------------------------
    markers_in = cls.error_markers
    if isinstance(markers_in, (str, Mapping)) or not isinstance(markers_in, Iterable):
        raise _fail(cls, "error_markers must be a tuple of marker dicts", "write error_markers = ({'id': ..., 'maps_to': ..., 'reason': ...},)")
    markers = []
    seen_ids: set[str] = set()
    for item in markers_in:
        try:
            marker = _providers.parse_marker(item)
        except ValueError as exc:
            raise _fail(cls, f"invalid error marker ({exc})", "follow the error-marker schema of v3lum/data/providers/README.md")
        if marker.id in seen_ids:
            raise _fail(cls, f"duplicate error marker id {marker.id!r}", "give every marker a unique id")
        seen_ids.add(marker.id)
        markers.append(marker)
    out["error_markers"] = tuple(markers)
    # 12. manual_link resolvable ------------------------------------------------------------------------
    if cls.manual_link:
        problems = _validate_manual_link(cls.manual_link)
        if problems:
            raise _fail(cls, f"manual_link {cls.manual_link!r} does not resolve ({'; '.join(problems)})", "use '<pack>:<link_id>' of a v3lum/data/pivot_links pack or an https template with link placeholders")
    # 13. settings collisions (dry run; registered once every rule passed) -----------------------------
    _release_stale_settings()
    settings = dict(cls.settings)
    # settings inherited (not re-declared) from a registered base module stay that module's settings
    own_body = "settings" in cls.__dict__ and "settings" not in cls.__dict__.get(_MARK, ())
    ancestors = set() if own_body else {
        str(k.__dict__.get("name", "")) for k in cls.__mro__[1:]
        if isinstance(k, type) and issubclass(k, Module) and k is not Module and REGISTRY.get(str(k.__dict__.get("name", ""))) is k
    }
    inherited: set[str] = set()
    for key, default in settings.items():
        if not isinstance(key, str) or not _SETTING_NAME_RE.match(key):
            raise _fail(cls, f"setting name {key!r} is invalid", "setting names match ^[a-z][a-z0-9_]{1,63}$ (prefix them with the module name)")
        spec = _config.SETTINGS_META.get(key)
        if spec is not None and spec.owner != name:
            if spec.owner in ancestors:
                inherited.add(key)
                continue
            where = "a core setting" if spec.owner == _config.CORE_OWNER else f"a setting of {spec.owner}"
            raise _fail(cls, f"setting {key!r} collides with {where}", f"rename it (e.g. {name}_{key})")
        try:
            json.dumps(default.default if isinstance(default, _config.SettingSpec) else default)
        except (TypeError, ValueError):
            raise _fail(cls, f"setting {key!r} has a default that is not JSON-serialisable", "use str, int, float, bool, list or dict defaults (they are stored in config.json)")
    out["settings"] = settings
    out["_own_settings"] = {k: v for k, v in settings.items() if k not in inherited}
    # derived values needed by the remaining rules -------------------------------------------------
    receivers = all_providers if disclosure != "none" else []
    known = [p for p in all_providers if p is not None]
    out["providers"] = frozenset(p.id for p in known)
    out["trust_tier"] = _providers.lowest_tier(p.tier for p in known) if disclosure == "third_party" else "n/a"
    out["upstream_families"] = frozenset(f for s in resolved for f in s.families)
    out["reliability"] = primary.reliability.grade if primary is not None else ""
    out["sensitive"] = cls.category == "breach_leak" or any(p.flags.sensitive for p in known)
    out["publishes_queries"] = any(p.flags.publishes_queries for p in receivers if p is not None)
    out["reuses_queries"] = any(p.flags.reuses_queries for p in receivers if p is not None)
    out["fetches_target"] = any(p.flags.fetches_target for p in receivers if p is not None)
    out["shares_input"] = disclosure in ("third_party", "target")
    out["max_tlp"] = _tlp.max_tlp(disclosure, out["trust_tier"], publishes_queries=out["publishes_queries"], reuses_queries=out["reuses_queries"])
    out["access_label"] = ACCESS_LABELS[access_model]
    out["terms_sources"] = {s.id: s.terms.class_ for s in resolved}
    # 14. A3 default rule ---------------------------------------------------------------------------
    if cls.default_enabled:
        reasons = []
        if opsec >= Opsec.LIGHT:
            reasons.append(f"opsec {opsec.label}")
        if cls.terms == "unknown":
            reasons.append("terms 'unknown'")
        if known and _providers.lowest_tier(p.tier for p in known) == "unknown":
            reasons.append("a provider of tier 'unknown'")
        if max_requests > 10 and "curated_pack" not in out["tags"]:
            reasons.append(f"max_requests {max_requests} > 10 (curated packs tag curated_pack)")
        if cls.expected_latency > 10:
            reasons.append(f"expected_latency {cls.expected_latency} s > 10 s")
        if cls.category == "person_name" and disclosure == "third_party":
            reasons.append("a person_name source module")
        reasons += [f"tag {t!r}" for t in NEVER_DEFAULT_TAGS if t in out["tags"]]
        if out["fetches_target"] and "cached_only" not in out["tags"]:
            reasons.append("a fetches_target provider without tag cached_only")
        if reasons:
            raise _fail(cls, f"default_enabled True with {', '.join(reasons)}", "declare default_enabled = False (A3 default rules)")
    # 15. sensitive modules need a sanitizer schema for every source -----------------------------------
    if out["sensitive"]:
        if not resolved:
            raise _fail(
                cls,
                "sensitive module (category breach_leak or a sensitive provider) without registry sources",
                "list the registry sources it reads and give each a P145 sanitizer schema (sanitize.register_schema or a fragment 'sanitizer' block)",
            )
        for src in resolved:
            if _schema_for(src.id) is None:
                raise _fail(
                    cls,
                    f"sensitive module without a sanitizer schema for source {src.id!r}",
                    f"call sanitize.register_schema({src.id!r}, keep=[...]) at the top of the module file or add a 'sanitizer' block to the source (P145)",
                )
    # 16. keys registered ------------------------------------------------------------------------------
    known_keys = _config.key_registry()
    for key in (*out["requires_keys"], *out["optional_keys"]):
        if key not in known_keys:
            raise _fail(cls, f"key {key!r} is not registered", "declare it in the 'keys' block of the provider fragment")
    # 17. packages known ------------------------------------------------------------------------------
    for pkg in out["requires_packages"]:
        if pkg not in OPTIONAL_PACKAGES:
            raise _fail(cls, f"package {pkg!r} is not a known optional dependency", f"add v3lum/data/extras/{pkg}.json (schema {EXTRA_SCHEMA!r}); never edit pyproject.toml")
    return out


_NORMALISED = (
    "accepts", "produces", "tags", "opsec", "hosts", "sources", "requires_keys", "optional_keys", "requires_packages",
    "requires_egress", "absent_statuses", "error_markers", "settings",
)


def register(cls: type[Module]) -> type[Module]:
    """Class decorator: lint the module against contract v2, derive its registry attributes, register it.

    Raises RegistrationError('<module>: <problem> - <how to fix>') on the first broken rule.
    """
    if not isinstance(cls, type) or not issubclass(cls, Module):
        raise RegistrationError(f"{getattr(cls, '__name__', cls)!r}: @register decorates Module subclasses - inherit from v3lum.core.module.Module")
    with _REGISTER_LOCK:
        values = _check(cls)
        try:
            _config.register_settings(cls.name, values["_own_settings"])
        except ValueError as exc:
            raise _fail(cls, f"settings rejected ({exc})", "fix the module settings (unique valid names, JSON defaults within their choices)")
        if values["_own_settings"]:
            _SETTINGS_OWNERS.add(cls.name)
        set_by_register: set[str] = set(cls.__dict__.get(_MARK, ()))
        for attr in _NORMALISED:
            if _declared(cls, attr):
                # a value inherited from a base (mixin, compiled spec, registered module) is written on
                # the class normalised but stays the base's declaration (e.g. inherited settings keep
                # their owner when the class is registered again or checked by the contract test)
                inherited = attr not in cls.__dict__ or attr in set_by_register
                setattr(cls, attr, values[attr])
                if inherited:
                    set_by_register.add(attr)
        if "_default_access_model" in values:
            cls.access_model = values["_default_access_model"]
            set_by_register.add("access_model")
        for attr in DERIVED:
            setattr(cls, attr, values[attr])
            set_by_register.add(attr)
        setattr(cls, _MARK, frozenset(set_by_register))
        REGISTRY[cls.name] = cls
    return cls


def unregister(name: str) -> bool:
    """Remove a module (and its settings) from the registry. True when it was registered (tests, plugins)."""
    with _REGISTER_LOCK:
        cls = REGISTRY.pop(name, None)
        if cls is None:
            return False
        _config.unregister_settings(name)
        _SETTINGS_OWNERS.discard(name)
        return True


# ---------------------------------------------------------------------------------- discovery


def load_modules(extra_dirs: list[str] | None = None, *, force: bool = False) -> dict[str, type[Module]]:
    """Import every module under ``v3lum.modules`` (+ plugin dirs). Errors are recorded, never raised."""
    global _LOADED
    if _LOADED and not force:
        return REGISTRY
    import v3lum.modules as pkg

    for key in [k for k in _LOAD_ERRORS if k.startswith("extras:")]:
        del _LOAD_ERRORS[key]  # extras fragments are re-read by reload_extras(): report the current state
    for problem in extras_errors():
        file_name, _, message = problem.partition(": ")
        _LOAD_ERRORS[f"extras:{file_name}"] = message or problem
    for info in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + "."):
        if info.name.rsplit(".", 1)[-1].startswith("_"):
            continue
        try:
            importlib.import_module(info.name)
        except Exception as exc:  # a broken module must never kill the tool
            _LOAD_ERRORS[info.name] = f"{type(exc).__name__}: {exc}"
            log.warning("failed to load %s: %s", info.name, exc)
        else:
            _LOAD_ERRORS.pop(info.name, None)  # a module that loads now has no stale error
    for directory in extra_dirs or []:
        if not os.path.isdir(directory):
            continue
        for fname in sorted(os.listdir(directory)):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue
            path = os.path.join(directory, fname)
            mod_name = f"v3lum_plugin_{fname[:-3]}"
            try:
                spec = importlib.util.spec_from_file_location(mod_name, path)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[mod_name] = module
                    spec.loader.exec_module(module)
            except Exception as exc:
                sys.modules.pop(mod_name, None)  # a failed plugin leaves no half-initialised module behind
                _LOAD_ERRORS[path] = f"{type(exc).__name__}: {exc}"
            else:
                _LOAD_ERRORS.pop(path, None)
    _LOADED = True
    return REGISTRY


def load_errors() -> dict[str, str]:
    """Import/registration errors by module path (and 'extras:<file>' fragment errors)."""
    return dict(_LOAD_ERRORS)


def get_module(name: str) -> type[Module]:
    """A registered module by name or unique prefix (KeyError with suggestions otherwise)."""
    load_modules()
    if name in REGISTRY:
        return REGISTRY[name]
    matches = [n for n in REGISTRY if n.startswith(name)]
    if len(matches) == 1:
        return REGISTRY[matches[0]]
    raise KeyError(f"unknown module {name!r}" + (f" (did you mean: {', '.join(matches[:5])}?)" if matches else ""))


def modules_for(etype: EntityType) -> list[type[Module]]:
    """Registered modules accepting ``etype``, sorted by category and name."""
    load_modules()
    return sorted((m for m in REGISTRY.values() if etype in m.accepts), key=lambda m: (m.category, m.name))


def package_available(name: str) -> bool:
    """Is an optional package importable?"""
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


# ---------------------------------------------------------------------------------- readiness


def _has_key(keys: Any, name: str) -> bool:
    if isinstance(keys, Mapping):
        return bool(keys.get(name))
    return name in (keys or ())


def readiness_check(cls: type[Module], keys: Mapping[str, str] | Iterable[str], mode: Opsec, authorized: bool = False) -> Readiness:
    """Static readiness (packages, keys, opsec, authorization) with Status and canonical reason code.

    ``keys`` is a mapping name -> value (Config.keys()) or a set of configured key names. Order:
    missing package -> UNAVAILABLE 'package'; missing requires_keys -> NEEDS_KEY 'needs_key';
    opsec above the mode -> SKIPPED 'opsec'; ACTIVE without authorization -> SKIPPED 'authorization'.
    The policy gate (core/policy.py) adds licence, TLP, tier, privacy, scope, egress and quota.
    """
    missing_pkgs = [p for p in cls.requires_packages if not package_available(p)]
    if missing_pkgs:
        extras = sorted({OPTIONAL_PACKAGES.get(p, "full") for p in missing_pkgs})
        hint = " (pip install 'v3lum[" + ",".join(extras) + "]')"
        return Readiness(False, Status.UNAVAILABLE, "package", f"needs python package: {', '.join(missing_pkgs)}{hint}")
    missing = [k for k in cls.requires_keys if not _has_key(keys, k)]
    if missing:
        return Readiness(False, Status.NEEDS_KEY, "needs_key", f"needs API key: {', '.join(missing)}")
    mode = Opsec.parse(mode)
    opsec = Opsec.parse(cls.opsec)
    if opsec > mode:
        return Readiness(False, Status.SKIPPED, "opsec", f"{opsec.label} module (current mode: {mode.label})")
    if opsec is Opsec.ACTIVE and not authorized:
        return Readiness(False, Status.SKIPPED, "authorization", "active module: requires --authorized")
    return Readiness(True, Status.OK, "", "ready")


def readiness(cls: type[Module], keys: Mapping[str, str] | Iterable[str], mode: Opsec, authorized: bool = False) -> tuple[bool, str]:
    """Legacy wrapper of readiness_check: (ready, reason)."""
    r = readiness_check(cls, keys, mode, authorized)
    return r.ready, r.reason
