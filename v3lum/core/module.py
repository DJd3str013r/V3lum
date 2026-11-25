"""Module (collector) plugin API and registry.

Writing a module::

    from v3lum.core.module import Module, register
    from v3lum.core.entities import EntityType as T
    from v3lum.core.models import Opsec, Severity

    @register
    class InternetDB(Module):
        name = "shodan_internetdb"
        title = "Shodan InternetDB"
        description = "Open ports, hostnames, CPEs and CVEs for an IP (free, no key)."
        category = "ip_network"
        accepts = {T.IPV4}
        produces = {T.DOMAIN, T.CVE}
        hosts = ("internetdb.shodan.io",)
        reference = "https://internetdb.shodan.io/docs"

        def run(self, entity, ctx):
            res = self.result(entity)
            r = ctx.http.get(f"https://internetdb.shodan.io/{entity.value}")
            if r.status == 404:
                return res.mark("empty")
            data = r.json()
            res.raw = data
            res.attr("open_ports", data.get("ports"))
            for cve in data.get("vulns", []):
                res.pivot(T.CVE, cve, "affects")
            return res

Modules are discovered automatically from the ``v3lum.modules`` package (and from
``~/.v3lum/plugins/*.py``). They must be side-effect free at import time.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import os
import pkgutil
import sys
from typing import TYPE_CHECKING, Any, ClassVar

from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import ModuleResult, Opsec

if TYPE_CHECKING:  # pragma: no cover
    from v3lum.core.context import Context

log = logging.getLogger("v3lum.modules")

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


class Module:
    """Base class for every collector/analyzer."""

    #: unique id (snake_case). Used on the command line: ``v3lum run <name> <input>``.
    name: ClassVar[str] = ""
    #: human friendly title shown in tables.
    title: ClassVar[str] = ""
    #: one/two sentence description (what it does, what source it uses).
    description: ClassVar[str] = ""
    #: one of CATEGORIES.
    category: ClassVar[str] = "utility"
    #: entity types this module can investigate.
    accepts: ClassVar[set[EntityType] | frozenset[EntityType]] = frozenset()
    #: entity types this module may discover (documentation / planning).
    produces: ClassVar[set[EntityType] | frozenset[EntityType]] = frozenset()
    #: how much the module touches the target (see Opsec).
    opsec: ClassVar[Opsec] = Opsec.PASSIVE
    #: config keys that MUST be configured (e.g. ("shodan",)); module is skipped otherwise.
    requires_keys: ClassVar[tuple[str, ...]] = ()
    #: config keys that unlock extra data/quota when present.
    optional_keys: ClassVar[tuple[str, ...]] = ()
    #: python packages needed (import names); module reports UNAVAILABLE if missing.
    requires_packages: ClassVar[tuple[str, ...]] = ()
    #: hosts contacted (documentation, `v3lum doctor`, proxy allow-lists).
    hosts: ClassVar[tuple[str, ...]] = ()
    #: link to the source's documentation / terms.
    reference: ClassVar[str] = ""
    #: free-form tags (e.g. "free", "brazil", "slow", "noisy").
    tags: ClassVar[frozenset[str] | set[str]] = frozenset()
    #: run automatically during `scan`? (False = only when selected explicitly).
    default_enabled: ClassVar[bool] = True
    #: HTTP cache TTL (seconds) for this module's requests; None = global default.
    cache_ttl: ClassVar[int | None] = None
    #: minimum seconds between requests to this module's hosts (politeness / ToS).
    min_interval: ClassVar[float] = 0.0
    #: max pivots the engine keeps from one run (protects against explosions).
    max_pivots: ClassVar[int] = 100
    #: hard timeout for one run (seconds).
    timeout: ClassVar[float] = 60.0
    #: legal/ethical note shown in `v3lum info` (e.g. LGPD reminders).
    notice: ClassVar[str] = ""

    # ------------------------------------------------------------------------------------

    def applies(self, entity: Entity, ctx: Context) -> bool:  # noqa: ARG002 - hook
        """Extra applicability filter beyond ``accepts`` (e.g. only public IPs)."""
        return True

    def run(self, entity: Entity, ctx: Context) -> ModuleResult:  # pragma: no cover - abstract
        raise NotImplementedError

    def result(self, entity: Entity) -> ModuleResult:
        return ModuleResult(module=self.name, entity=entity)

    # ------------------------------------------------------------------------------------

    @classmethod
    def describe(cls) -> dict[str, Any]:
        return {
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
        }


REGISTRY: dict[str, type[Module]] = {}
_LOAD_ERRORS: dict[str, str] = {}
_LOADED = False


def register(cls: type[Module]) -> type[Module]:
    """Class decorator adding a module to the registry."""
    if not cls.name:
        raise ValueError(f"{cls.__name__}: module needs a name")
    if cls.category not in CATEGORIES:
        raise ValueError(f"{cls.name}: unknown category {cls.category!r}")
    if not cls.accepts:
        raise ValueError(f"{cls.name}: module must accept at least one entity type")
    if cls.name in REGISTRY and REGISTRY[cls.name] is not cls:
        existing = REGISTRY[cls.name]
        if f"{existing.__module__}.{existing.__qualname__}" != f"{cls.__module__}.{cls.__qualname__}":
            raise ValueError(f"duplicate module name {cls.name!r} ({existing.__module__} vs {cls.__module__})")
    cls.accepts = frozenset(cls.accepts)
    cls.produces = frozenset(cls.produces)
    cls.tags = frozenset(cls.tags)
    REGISTRY[cls.name] = cls
    return cls


def load_modules(extra_dirs: list[str] | None = None, *, force: bool = False) -> dict[str, type[Module]]:
    """Import every module under ``v3lum.modules`` (+ plugin dirs). Errors are recorded, not raised."""
    global _LOADED
    if _LOADED and not force:
        return REGISTRY
    import v3lum.modules as pkg

    for info in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + "."):
        if info.name.rsplit(".", 1)[-1].startswith("_"):
            continue
        try:
            importlib.import_module(info.name)
        except Exception as exc:  # a broken module must never kill the tool
            _LOAD_ERRORS[info.name] = f"{type(exc).__name__}: {exc}"
            log.warning("failed to load %s: %s", info.name, exc)
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
                _LOAD_ERRORS[path] = f"{type(exc).__name__}: {exc}"
    _LOADED = True
    return REGISTRY


def load_errors() -> dict[str, str]:
    return dict(_LOAD_ERRORS)


def get_module(name: str) -> type[Module]:
    load_modules()
    if name in REGISTRY:
        return REGISTRY[name]
    matches = [n for n in REGISTRY if n.startswith(name)]
    if len(matches) == 1:
        return REGISTRY[matches[0]]
    raise KeyError(f"unknown module {name!r}" + (f" (did you mean: {', '.join(matches[:5])}?)" if matches else ""))


def modules_for(etype: EntityType) -> list[type[Module]]:
    load_modules()
    return sorted((m for m in REGISTRY.values() if etype in m.accepts), key=lambda m: (m.category, m.name))


def package_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def readiness(cls: type[Module], keys: dict[str, str], mode: Opsec, authorized: bool = False) -> tuple[bool, str]:
    """Can this module run under the given configuration? Returns (ready, reason)."""
    missing_pkgs = [p for p in cls.requires_packages if not package_available(p)]
    if missing_pkgs:
        return False, f"needs python package: {', '.join(missing_pkgs)}"
    missing = [k for k in cls.requires_keys if not keys.get(k)]
    if missing:
        return False, f"needs API key: {', '.join(missing)}"
    if cls.opsec > mode:
        return False, f"{cls.opsec.label} module (current mode: {mode.label})"
    if cls.opsec is Opsec.ACTIVE and not authorized:
        return False, "active module: requires --authorized"
    return True, "ready"
