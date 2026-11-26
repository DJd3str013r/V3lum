"""Configuration, the settings registry and API-key management.

Precedence (highest first): command-line flags > environment variables > config file > defaults.

Settings: every core setting is described in :data:`SETTINGS_META` (``SettingSpec(default,
description, owner='core', choices)``); :data:`DEFAULT_SETTINGS` holds the core defaults. Modules
declare module-scoped settings in ``Module.settings`` and ``@register`` adds them to SETTINGS_META via
:func:`register_settings` (owner = module name; names are unique across core and modules). Both kinds
are read with ``Config.get`` (``ctx.setting`` in modules) and changed with ``Config.set`` /
``v3lum config set``. Environment overrides: ``V3LUM_<SETTING>`` (upper case).

API keys: ``V3LUM_KEY_<NAME>`` env vars (e.g. ``V3LUM_KEY_SHODAN``), the conventional aliases of the key
registry (:func:`key_registry`: the legacy :data:`KNOWN_KEYS` table merged with the ``keys`` blocks of
the provider fragments, e.g. ``SHODAN_API_KEY``, ``GITHUB_TOKEN``/``GH_TOKEN``), or
``v3lum keys set <name> <value>``, which writes ``~/.v3lum/config.json`` created 0600 (AR03). Every key
value that is loaded or set is registered with the central redactor (AR01) and keys are never printed
in full. The plan of a key ('business' | 'free', A1/A15) is recorded in the setting ``key_plans``.
"""

from __future__ import annotations

import copy
import json
import math
import os
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from v3lum import __version__, paths
from v3lum.core.providers import KeySpec

__all__ = [
    "CORE_OWNER",
    "Config",
    "DEFAULT_SETTINGS",
    "KEY_PLANS",
    "KNOWN_KEYS",
    "SETTINGS_META",
    "SettingSpec",
    "key_env_names",
    "key_registry",
    "mask",
    "register_settings",
    "settings_for",
    "unregister_settings",
]

#: Allowed values of ``key_plans.<key>`` (A1: key-terms sources run under corporate with 'business').
KEY_PLANS: tuple[str, ...] = ("business", "free")
#: Owner of the built-in settings (reserved: modules and packages register under their own names).
CORE_OWNER = "core"

_SETTING_NAME = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_TLP_VALUES = ("clear", "green", "amber", "amber+strict", "red")


@dataclass(frozen=True)
class SettingSpec:
    """One setting: default value (its type drives coercion), description, owner and allowed values.

    ``choices`` restricts the value (for list settings: every item). ``owner`` is 'core' or the name
    of the module (or core package) that registered the setting.
    """

    default: Any
    description: str = ""
    owner: str = "core"
    choices: tuple[Any, ...] | None = None


def _spec(default: Any, description: str, choices: tuple[Any, ...] | None = None) -> SettingSpec:
    return SettingSpec(default=default, description=description, owner="core", choices=choices)


_CORE_SETTINGS: dict[str, SettingSpec] = {
    # -- scan behaviour ------------------------------------------------------------------------
    "mode": _spec("passive", "default opsec mode (LIGHT/ACTIVE need explicit flags on every path, A7)", ("passive", "light", "active")),
    "depth": _spec(1, "pivot depth (0 = only the input)"),
    "threads": _spec(12, "worker threads per scan"),
    "timeout": _spec(20.0, "per-request HTTP timeout (seconds)"),
    "max_entities": _spec(150, "budget of investigated entities per scan"),
    "cache_ttl": _spec(86400, "default HTTP cache TTL in seconds (capped by cache_max_age_days and retention_days)"),
    "dns_mode": _spec("doh", "DNS transport: doh (default) or system (dnspython/UDP 53, explicit only: the corporate resolver's IP reaches the target's nameservers; doctor warns)", ("doh", "system")),
    "doh_provider": _spec("google", "legacy single DoH provider (superseded by doh_providers)", ("google", "cloudflare", "quad9")),
    "proxy": _spec("", "default route proxy for third-party APIs and DoH (e.g. http://proxy:3128); never used for LIGHT/ACTIVE target contact"),
    "user_agent": _spec(f"V3LUM/{__version__}", "neutral default User-Agent: identifies neither the organisation, the team nor the analyst (P326 veto_lift)"),
    "default_region": _spec("BR", "phone-number parsing region (ISO 3166 alpha-2)"),
    "report_dir": _spec("", "report output directory ('' = ~/.v3lum/cases/<case>/)"),
    "report_formats": _spec(["html", "md", "json"], "report formats written after a scan"),
    "feedback": _spec(True, "ask 'did this make sense?' after interactive scans"),
    "fx": _spec(True, "banner/boot animation"),
    "nsfw_sites": _spec(False, "include adult sites in username packs (off by default, A5)"),
    # -- policy, licence, TLP ------------------------------------------------------------------
    "tlp": _spec("amber", "default TLP of scans (FIRST TLP 2.0; A2)", _TLP_VALUES),
    "licence_profile": _spec("corporate", "licence profile (A1): corporate (default) or research (needs a recorded legal basis in licence_allow.json)", ("corporate", "research")),
    "licence_allow_path": _spec("", "licence allow-list file ('' = ~/.v3lum/licence_allow.json, 0600; may point to a team-shared read-only file)"),
    "key_plans": _spec({}, "plan per key name: 'business' | 'free' (recorded by `v3lum keys set <name> --plan ...` or the keys wizard)"),
    "scan_deadline": _spec(90.0, "scan deadline in seconds (0 = unlimited; --timeout overrides); pending sources end SKIPPED 'deadline'"),
    "preset": _spec("quick", "module preset: quick (the effective default set) or deep (every ready module that passes the gates)", ("quick", "deep")),
    "min_expand_confidence": _spec(0.5, "pivots below this path confidence are not auto-expanded (AR07)"),
    "skip_keyed_when_answered": _spec(False, "skip quota-limited keyed sources for an entity once enough keyless sources answered"),
    "light_for_own_assets": _spec(False, "let LIGHT modules run without --mode light on analyst-typed seeds that are verified own assets (A7)"),
    "sightings_personal": _spec(False, "show cross-case sightings for personal identifiers (off by default, A4/A8)"),
    "sensitive_sites": _spec(False, "include sensitive site categories (dating, religion, health, politics) in username packs (A5)"),
    "defang": _spec(True, "defang malicious/suspicious entities in terminal, Markdown and HTML output (AR13)"),
    # -- retention and storage -----------------------------------------------------------------
    "retention_days": _spec(180, "case retention in days (A10): cases, evidence, reports, sightings and the case's cache rows are purged after it"),
    "cache_max_age_days": _spec(30, "HTTP cache rows older than this are deleted (A10)"),
    "audit_retention_days": _spec(0, "retention of the minimal LIGHT/ACTIVE engagement audit (0 = retention_days; longer only with a written legal decision)"),
    "quota_db_path": _spec("", "provider quota DB ('' = ~/.v3lum/quota.db; a team-shared path serves analysts behind one NAT, P334)"),
    "evidence_max_file_bytes": _spec(5_000_000, "maximum size of one evidence file (bytes)"),
    "evidence_max_case_bytes": _spec(200_000_000, "maximum evidence size per case (bytes)"),
    # -- organisation, engagement and case metadata ----------------------------------------
    "org_profile_path": _spec("", "organisation profile ('' = ~/.v3lum/org_profile.toml, then .json; 0600, never exported, A11)"),
    "analyst": _spec("", "analyst name recorded in cases and in the audit trail"),
    "default_purpose": _spec("", "default --purpose for IOC-only scans (personal identifiers always need an explicit purpose, AR16)"),
    "default_ticket": _spec("", "default --ticket for IOC-only scans"),
    "default_legal_basis": _spec("", "default legal basis code (docs/LEGAL.md) for IOC-only scans"),
    "attack_surface_min_assets": _spec(20, "minimum number of own assets before the attack-surface pack reports coverage ratios"),
    # -- egress, identity and TLS -------------------------------------------------------------
    "egress_country": _spec("", "ISO 3166 alpha-2 code of the real passive egress (e.g. BR; '' = unknown); never satisfied by a proxy/VPN/Tor exit (A9)"),
    "proxy_light": _spec("", "egress profile for LIGHT target contact (contracted research proxy or socks5h; fails closed, A13)"),
    "proxy_active": _spec("", "egress profile for ACTIVE target contact (fails closed; never Tor, A13)"),
    "ua_light": _spec(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
        "User-Agent of LIGHT/ACTIVE target contact and of 'browser' provider profiles (a common desktop browser UA; never the V3LUM or contact UA)",
    ),
    "contact_email": _spec("", "role mailbox for providers whose terms ask for an identifying UA (SEC, Wikimedia, Nominatim, bgp.tools); never a personal address; empty = those providers are SKIPPED 'config'"),
    "contact_url": _spec("", "URL used by provider UA templates that need {contact_url} (e.g. KeyCDN); empty = those providers are SKIPPED 'config'"),
    "ca_bundle": _spec("", "CA bundle for internal TLS endpoints (verification is always on, A12)"),
    "doh_providers": _spec(["google", "cloudflare"], "DoH resolver chain in failover order; 'internal' is prepended when doh_internal is set (P029)", ("google", "cloudflare", "quad9", "internal")),
    "doh_internal": _spec("", "company internal DoH URL (https), used first when set; the only resolver allowed under TLP:RED"),
    # -- internal platforms (A12) -----------------------------------------------------------
    "misp_url": _spec("", "company MISP base URL (https); the read-only adapter is disabled while empty"),
    "opencti_url": _spec("", "company OpenCTI base URL (https); the read-only adapter is disabled while empty"),
    # -- plugins (AR12) -------------------------------------------------------------------------
    "plugins_enabled": _spec(False, "load ~/.v3lum/plugins/*.py (owner-only, not group/world-writable)"),
    "plugin_allow": _spec([], "SHA-256 allow-list of LIGHT/ACTIVE plugins"),
    # -- watch mode (A14) ---------------------------------------------------------------------
    "certstream_url": _spec("", "CertStream-compatible WebSocket URL for `v3lum watch` (extra v3lum[watch]; a self-hosted server is preferred)"),
    "watch_interval": _spec(3600, "seconds between `v3lum watch` polling cycles"),
    "watch_max_runtime": _spec(28800, "maximum runtime of `v3lum watch` in seconds (default 8 h)"),
    "watch_max_alerts": _spec(0, "stop `v3lum watch` after this many alerts (0 = unlimited)"),
    "watch_enrich_per_hour": _spec(30, "capped passive enrichments per hour triggered by watch hits"),
}

#: Core defaults (name -> default). Module settings are not listed here (see SETTINGS_META).
DEFAULT_SETTINGS: dict[str, Any] = {name: spec.default for name, spec in _CORE_SETTINGS.items()}

#: Every known setting: the core ones plus the module settings registered by ``register_settings``.
SETTINGS_META: dict[str, SettingSpec] = dict(_CORE_SETTINGS)

_SETTINGS_LOCK = threading.RLock()
#: serialises Config mutations with the snapshot taken by save() (module-level: Config stays copyable)
_SAVE_LOCK = threading.RLock()


def register_settings(owner: str, mapping: Mapping[str, Any] | None) -> None:
    """Register the settings of ``owner`` (a module name or core package): name -> default (or SettingSpec).

    Names match ``^[a-z][a-z0-9_]{1,63}$`` and are unique across core and modules; defaults must be
    JSON-serialisable and within their ``choices``. Re-registering the same owner replaces its
    previous settings; the owner 'core' (:data:`CORE_OWNER`) is reserved for the built-in settings.
    Raises ValueError (the base of module.RegistrationError) on a collision or an invalid entry.
    """
    if not isinstance(owner, str) or not owner:
        raise ValueError("settings owner must be a non-empty name")
    if owner == CORE_OWNER:
        # 'core' owns the built-in settings: registering under it would replace (and drop) them
        raise ValueError(f"settings owner {CORE_OWNER!r} is reserved for the built-in settings - use the module or package name")
    items = dict(mapping or {})
    with _SETTINGS_LOCK:
        problems: list[str] = []
        specs: dict[str, SettingSpec] = {}
        for name, value in items.items():
            if not isinstance(name, str) or not _SETTING_NAME.match(name):
                problems.append(f"setting name {name!r} must match ^[a-z][a-z0-9_]{{1,63}}$")
                continue
            existing = SETTINGS_META.get(name)
            if existing is not None and existing.owner != owner:
                where = "a core setting" if existing.owner == CORE_OWNER else f"already registered by {existing.owner}"
                problems.append(f"setting {name!r} collides with {where} - rename it (e.g. {owner}_{name})")
                continue
            if isinstance(value, SettingSpec):
                choices = tuple(value.choices) if value.choices is not None else None
                spec = SettingSpec(default=value.default, description=value.description or f"setting of {owner}", owner=owner, choices=choices)
            else:
                spec = SettingSpec(default=value, description=f"setting of {owner}", owner=owner)
            try:
                json.dumps(spec.default)
            except (TypeError, ValueError):
                problems.append(f"setting {name!r}: default {spec.default!r} is not JSON-serialisable")
                continue
            if spec.choices is not None:
                try:
                    _check_choices(name, spec.default, spec)
                except ValueError as exc:
                    problems.append(f"setting {name!r}: the default is not one of its choices ({exc})")
                    continue
            specs[name] = spec
        if problems:
            raise ValueError(f"{owner}: " + "; ".join(problems))
        for stale in [n for n, s in SETTINGS_META.items() if s.owner == owner and n not in specs]:
            del SETTINGS_META[stale]
        SETTINGS_META.update(specs)


def unregister_settings(owner: str) -> list[str]:
    """Remove every setting registered by ``owner`` (core settings cannot be removed). Returns the names."""
    if owner == CORE_OWNER:
        return []
    with _SETTINGS_LOCK:
        names = [n for n, s in SETTINGS_META.items() if s.owner == owner]
        for name in names:
            del SETTINGS_META[name]
        return names


def settings_for(owner: str) -> dict[str, SettingSpec]:
    """The settings registered by ``owner`` (name -> SettingSpec)."""
    return {n: s for n, s in SETTINGS_META.items() if s.owner == owner}


# ---------------------------------------------------------------------------------- keys

#: Legacy key table: name -> (description, where to get it, env aliases). Kept unchanged; provider
#: fragments add keys and aliases through ``key_registry()``.
KNOWN_KEYS: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "shodan": ("Shodan API (host details, search)", "https://account.shodan.io", ("SHODAN_API_KEY",)),
    "virustotal": ("VirusTotal v3 (files, URLs, domains, IPs)", "https://www.virustotal.com/gui/my-apikey", ("VT_API_KEY", "VIRUSTOTAL_API_KEY")),
    "abuseipdb": ("AbuseIPDB (IP abuse reports)", "https://www.abuseipdb.com/account/api", ("ABUSEIPDB_API_KEY",)),
    "greynoise": ("GreyNoise (community works without key)", "https://viz.greynoise.io/account/api-key", ("GREYNOISE_API_KEY",)),
    "otx": ("AlienVault OTX", "https://otx.alienvault.com/api", ("OTX_API_KEY",)),
    "abusech": ("abuse.ch Auth-Key (URLhaus, ThreatFox, MalwareBazaar, YARAify)", "https://auth.abuse.ch/", ("ABUSECH_AUTH_KEY",)),
    "urlscan": ("urlscan.io (higher search quota)", "https://urlscan.io/user/profile/", ("URLSCAN_API_KEY",)),
    "github": ("GitHub token (raises API limit 60 -> 5000/h, no scopes needed)", "https://github.com/settings/tokens", ("GITHUB_TOKEN", "GH_TOKEN")),
    "securitytrails": ("SecurityTrails (DNS history, subdomains)", "https://securitytrails.com/app/account/credentials", ("SECURITYTRAILS_API_KEY",)),
    "censys": ("Censys Platform API token", "https://platform.censys.io/account/api", ("CENSYS_API_KEY",)),
    "hibp": ("Have I Been Pwned (paid: email breach search)", "https://haveibeenpwned.com/API/Key", ("HIBP_API_KEY",)),
    "hunter": ("Hunter.io (emails of a domain)", "https://hunter.io/api-keys", ("HUNTER_API_KEY",)),
    "ipinfo": ("ipinfo.io token (more fields/quota)", "https://ipinfo.io/account/token", ("IPINFO_TOKEN",)),
    "etherscan": ("Etherscan API (EVM chains)", "https://etherscan.io/myapikey", ("ETHERSCAN_API_KEY",)),
    "opensanctions": ("OpenSanctions API (sanctions/PEP screening)", "https://www.opensanctions.org/api/", ("OPENSANCTIONS_API_KEY",)),
    "transparencia": ("Portal da Transparencia (CGU) API key", "https://portaldatransparencia.gov.br/api-de-dados/cadastrar-email", ("PORTAL_TRANSPARENCIA_KEY",)),
    "numverify": ("numverify (phone carrier/line type)", "https://numverify.com/product", ("NUMVERIFY_API_KEY",)),
    "pulsedive": ("Pulsedive", "https://pulsedive.com/api/", ("PULSEDIVE_API_KEY",)),
    "hybridanalysis": ("Hybrid Analysis", "https://www.hybrid-analysis.com/my-account?tab=%23api-key-tab", ("HYBRID_ANALYSIS_API_KEY",)),
    "leakix": ("LeakIX", "https://leakix.net/settings/api", ("LEAKIX_API_KEY",)),
    "netlas": ("Netlas.io", "https://app.netlas.io/profile/", ("NETLAS_API_KEY",)),
    "criminalip": ("Criminal IP", "https://www.criminalip.io/mypage/information", ("CRIMINALIP_API_KEY",)),
    "fullhunt": ("FullHunt", "https://fullhunt.io/user/settings/", ("FULLHUNT_API_KEY",)),
    "intelx": ("Intelligence X (metadata search only)", "https://intelx.io/account?tab=developer", ("INTELX_API_KEY",)),
    "google_safebrowsing": ("Google Safe Browsing v4", "https://developers.google.com/safe-browsing/v4/get-started", ("GOOGLE_SAFEBROWSING_KEY",)),
    "ipqs": ("IPQualityScore", "https://www.ipqualityscore.com/create-account", ("IPQS_API_KEY",)),
    "chainabuse": ("Chainabuse (crypto scam reports)", "https://www.chainabuse.com/api", ("CHAINABUSE_API_KEY",)),
    "builtwith": ("BuiltWith", "https://api.builtwith.com/", ("BUILTWITH_API_KEY",)),
}


def key_registry() -> dict[str, KeySpec]:
    """Every known key: legacy KNOWN_KEYS merged with the provider fragments' ``keys`` blocks.

    Env aliases are unioned (legacy first); a fragment's description/signup_url win when set, and its
    provider id and plan hint are kept.
    """
    out: dict[str, KeySpec] = {
        name: KeySpec(name=name, provider="", description=desc, signup_url=url, env=tuple(aliases))
        for name, (desc, url, aliases) in KNOWN_KEYS.items()
    }
    from v3lum.core import providers

    for name, spec in providers.registry().keys().items():
        base = out.get(name)
        if base is None:
            out[name] = spec
            continue
        out[name] = KeySpec(
            name=name,
            provider=spec.provider,
            description=spec.description or base.description,
            signup_url=spec.signup_url or base.signup_url,
            env=tuple(dict.fromkeys([*base.env, *spec.env])),
            multi_key=spec.multi_key,
            plan_hint=spec.plan_hint or base.plan_hint,
        )
    return out


def key_env_names() -> set[str]:
    """Every environment variable that can carry a key: ``V3LUM_KEY_<NAME>`` plus every alias."""
    names: set[str] = set()
    for name, spec in key_registry().items():
        names.add(f"V3LUM_KEY_{name.upper()}")
        names.update(spec.env)
    return names


def _env_key(name: str, registry: Mapping[str, KeySpec] | None = None) -> str:
    val = os.environ.get(f"V3LUM_KEY_{name.upper()}")
    if val and val.strip():
        return val.strip()
    spec = (registry if registry is not None else key_registry()).get(name)
    for alias in spec.env if spec else ():
        val = os.environ.get(alias)
        if val and val.strip():
            return val.strip()
    return ""


def _register_secret(value: str) -> None:
    """Hand a key value to the central redactor (AR01) so it is masked everywhere it could leak."""
    if not value:
        return
    try:
        from v3lum.core.redact import register_secret
    except ImportError:  # pragma: no cover - partial checkout without the redactor
        return
    register_secret(value, label="api key")


def mask(secret: str) -> str:
    """Masked display form of a secret (first 3 + last 3 characters for long values)."""
    if not secret:
        return ""
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:3]}{'*' * (len(secret) - 6)}{secret[-3:]}"


_MISSING = object()


def _default_of(name: str) -> Any:
    spec = SETTINGS_META.get(name)
    return _MISSING if spec is None else spec.default


@dataclass
class Config:
    """Settings + API keys of one V3LUM home. ``Config.load()`` reads ``config.json`` and the environment.

    ``problems`` lists the stored or environment values that ``load()`` ignored because they are
    invalid (the default or file value stays; doctor can show them). Key values never appear in
    ``repr()``.
    """

    settings: dict[str, Any] = field(default_factory=lambda: copy.deepcopy(DEFAULT_SETTINGS))
    file_keys: dict[str, str] = field(default_factory=dict, repr=False)
    problems: list[str] = field(default_factory=list, init=False, repr=False, compare=False)
    #: settings read from config.json before their module registered them (an env override still wins)
    _file_only: set[str] = field(default_factory=set, init=False, repr=False, compare=False)

    # ---------------------------------------------------------------- persistence
    @classmethod
    def load(cls) -> Config:
        """Defaults < config file < ``V3LUM_<SETTING>`` env overrides; key values go to the redactor.

        Invalid stored or environment values never break start-up: they are ignored (the default or
        file value stays) and listed in ``problems``.
        """
        cfg = cls()
        path = paths.config_file()
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = {}
                cfg.problems.append(f"{path.name}: unreadable or invalid JSON (defaults used)")
            if not isinstance(data, dict):
                data = {}
            stored = data.get("settings") or {}
            if isinstance(stored, dict):
                for name, value in stored.items():
                    if not isinstance(name, str):
                        continue
                    spec = SETTINGS_META.get(name)
                    if spec is None:
                        if _SETTING_NAME.match(name):  # a module setting registered after the config is loaded
                            cfg.settings[name] = value
                            cfg._file_only.add(name)
                        continue
                    try:
                        cfg.settings[name] = _normalise(name, value, spec)
                    except ValueError as exc:
                        cfg.problems.append(f"{path.name}: setting {name} ignored ({exc})")
            keys = data.get("keys") or {}
            if isinstance(keys, dict):
                cfg.file_keys.update({str(k).strip().lower(): str(v) for k, v in keys.items() if v})
        for name, spec in list(SETTINGS_META.items()):
            env_name = f"V3LUM_{name.upper()}"
            if env_name.startswith("V3LUM_KEY_"):  # reserved for API keys
                continue
            env = os.environ.get(env_name)
            if env is not None and env != "":
                try:
                    cfg.settings[name] = _normalise(name, _coerce(env, spec.default), spec)
                except ValueError as exc:  # a malformed override never breaks start-up
                    cfg.problems.append(f"{env_name} ignored ({exc})")
        cfg.register_secrets()
        return cfg

    def save(self) -> None:
        """Write config.json atomically, created 0600 through os.open (no chmod-after-write window, AR03)."""
        path = paths.config_file()
        # one lock for the snapshot and the write: concurrent changes never produce a torn or stale file
        with _SAVE_LOCK:
            payload = {
                "settings": {k: v for k, v in self.settings.items() if _default_of(k) != v},
                "keys": dict(self.file_keys),
            }
            data = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
            tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
            try:
                os.unlink(tmp)
            except OSError:
                pass
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, path)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise

    def register_secrets(self) -> int:
        """Register every configured key value (file and environment) with the redactor. Returns the count."""
        registry = key_registry()
        values = {v for v in self.file_keys.values() if v}
        values |= {v for v in (_env_key(n, registry) for n in registry) if v}
        for value in values:
            _register_secret(value)
        return len(values)

    # ---------------------------------------------------------------- keys
    def key(self, name: str) -> str:
        """Key value: ``V3LUM_KEY_<NAME>``, then the registry aliases, then config.json ('' when unset)."""
        name = (name or "").strip().lower()
        if not name:
            return ""
        value = _env_key(name) or self.file_keys.get(name, "")
        if value:
            _register_secret(value)
        return value

    def keys(self) -> dict[str, str]:
        """Every configured key (name -> value) among the registry keys and the stored ones."""
        registry = key_registry()
        out: dict[str, str] = {}
        for name in set(registry) | set(self.file_keys):
            value = _env_key(name, registry) or self.file_keys.get(name, "")
            if value:
                _register_secret(value)
                out[name] = value
        return out

    def key_source(self, name: str) -> str:
        """Where a key comes from: 'env', 'config' or ''."""
        name = (name or "").strip().lower()
        if not name:
            return ""
        if _env_key(name):
            return "env"
        if self.file_keys.get(name):
            return "config"
        return ""

    def key_plan(self, name: str) -> str:
        """Recorded plan of a key: 'business' | 'free' | '' (unknown: key-terms sources stay blocked under corporate)."""
        plans = self.get("key_plans") or {}
        value = plans.get((name or "").strip().lower(), "") if isinstance(plans, dict) else ""
        return value if value in KEY_PLANS else ""

    def set_key(self, name: str, value: str, *, plan: str | None = None) -> None:
        """Store a key in config.json (0600), optionally recording its plan ('business' | 'free')."""
        name = name.strip().lower()
        value = value.strip()
        if not name:
            raise ValueError("key name is empty")
        if _CONTROL_CHARS.search(value) or _CONTROL_CHARS.search(name):
            # never echo the value: it is a secret
            raise ValueError("key name/value contains control characters (a paste error?); keys travel in HTTP headers and URLs")
        if plan is not None and plan not in KEY_PLANS:
            raise ValueError(f"unknown key plan {plan!r} (expected one of {', '.join(KEY_PLANS)})")
        _register_secret(value)  # before it is stored anywhere
        with _SAVE_LOCK:
            self.file_keys[name] = value
            if plan is not None:
                plans = dict(self.get("key_plans") or {})
                plans[name] = plan
                self.settings["key_plans"] = plans
            self.save()

    def unset_key(self, name: str) -> bool:
        """Remove a stored key (and its recorded plan). True when it was stored in config.json."""
        name = name.strip().lower()
        with _SAVE_LOCK:
            existed = self.file_keys.pop(name, None) is not None
            if existed:
                plans = dict(self.get("key_plans") or {})
                if plans.pop(name, None) is not None:
                    self.settings["key_plans"] = plans
            self.save()
        return existed

    # ---------------------------------------------------------------- settings
    def get(self, name: str, default: Any = None) -> Any:
        """Value of a core or module setting (``default`` only for names nobody registered).

        Module settings registered after ``load()`` still honour the documented precedence: a valid
        ``V3LUM_<SETTING>`` override beats the config.json value, and invalid stored values fall back
        to the module's default.
        """
        spec = SETTINGS_META.get(name)
        if spec is not None and spec.owner != CORE_OWNER and (name not in self.settings or name in self._file_only):
            env_name = f"V3LUM_{name.upper()}"
            env = os.environ.get(env_name) if not env_name.startswith("V3LUM_KEY_") else None
            if env:
                try:
                    return _normalise(name, _coerce(env, spec.default), spec)
                except ValueError:
                    pass
            if name in self.settings:
                try:
                    return _normalise(name, self.settings[name], spec)
                except ValueError:
                    return copy.deepcopy(spec.default)
        if name in self.settings:
            return self.settings[name]
        if spec is not None:
            return copy.deepcopy(spec.default) if isinstance(spec.default, (list, dict)) else spec.default
        return default

    def set(self, name: str, value: Any) -> None:
        """Change a core or registered module setting and save. KeyError (unknown) / ValueError (invalid).

        Text values are parsed into the setting's type first (lists: JSON or comma-separated; dicts:
        JSON); the result is validated and stored in canonical form (e.g. tlp 'TLP:RED' -> 'red').
        """
        spec = SETTINGS_META.get(name)
        if spec is None:
            raise KeyError(f"unknown setting {name!r}")
        if isinstance(value, str):
            value = _coerce(value, spec.default)
        value = _normalise(name, value, spec)
        with _SAVE_LOCK:
            self.settings[name] = value
            self._file_only.discard(name)
            self.save()


#: URL settings of company platforms: '' or an https URL with a host and no embedded credentials (A12).
_HTTPS_URL_SETTINGS: frozenset[str] = frozenset({"doh_internal", "misp_url", "opencti_url"})
#: Settings that go into HTTP headers (User-Agent): no control characters (no header injection).
_HEADER_SETTINGS: frozenset[str] = frozenset({"user_agent", "ua_light", "contact_email", "contact_url"})
#: List settings whose items may also be https URLs (validated like _HTTPS_URL_SETTINGS; P029 cond 5).
_URL_ITEM_SETTINGS: frozenset[str] = frozenset({"doh_providers"})
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_COUNTRY_CODE = re.compile(r"^[A-Za-z]{2}$")


def _url_problem(value: str, schemes: tuple[str, ...]) -> str:
    """'' when ``value`` is a URL with one of ``schemes``, a host and no userinfo; else the problem."""
    try:
        parts = urlsplit(value.strip())
        host = parts.hostname
    except ValueError:
        return "is not a valid URL"
    if parts.scheme not in schemes or not host:
        return "must be an " + " or ".join(f"{s}://" for s in schemes) + " URL with a host"
    if parts.username or parts.password:
        return "must not embed credentials (store keys with `v3lum keys set`)"
    return ""


def _type_matches(value: Any, default: Any) -> bool:
    if default is None:
        return True
    if isinstance(default, bool):
        return isinstance(value, bool)
    if isinstance(default, int):
        return isinstance(value, int) and not isinstance(value, bool)
    if isinstance(default, float):
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if isinstance(default, str):
        return isinstance(value, str)
    if isinstance(default, list):
        return isinstance(value, list)
    if isinstance(default, dict):
        return isinstance(value, dict)
    return True


def _normalise_core(name: str, value: Any) -> Any:
    """Per-setting rules of the built-in settings (canonical form, or ValueError)."""
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value < 0:
        raise ValueError(f"invalid value {value!r} for {name} (must be >= 0)")
    if name == "tlp":
        from v3lum.core import tlp as _tlp  # lazy: core.tlp is a sibling package

        return _tlp.parse(value).value_str  # 'TLP:RED', 'Amber+Strict', 'white' -> canonical TLP 2.0 value
    if name in _HEADER_SETTINGS and _CONTROL_CHARS.search(value):
        raise ValueError(f"{name} must not contain control characters (it is sent in HTTP headers)")
    if name in _HTTPS_URL_SETTINGS and value.strip():
        problem = _url_problem(value, ("https",))
        if problem:
            raise ValueError(f"{name} {problem} (TLS verification is always on, A12)")
        return value.strip()
    if name == "contact_url" and value.strip():
        problem = _url_problem(value, ("https", "http"))
        if problem:
            raise ValueError(f"contact_url {problem}")
        return value.strip()
    if name == "contact_email" and value.strip():
        text = value.strip()
        if text.count("@") != 1 or any(ch.isspace() for ch in text) or text.startswith("@") or text.endswith("@"):
            raise ValueError("contact_email must be one role mailbox address (e.g. cti@company.example)")
        return text
    if name == "egress_country" and value.strip():
        if not _COUNTRY_CODE.match(value.strip()):
            raise ValueError("egress_country must be an ISO 3166 alpha-2 code (e.g. BR) or empty")
        return value.strip().upper()
    if name == "key_plans":
        bad = [k for k, v in value.items() if not isinstance(k, str) or v not in KEY_PLANS]
        if bad:
            raise ValueError(f"key_plans values must be one of {', '.join(KEY_PLANS)} (bad entry {bad[0]!r})")
    if name in _URL_ITEM_SETTINGS:
        out = []
        for item in value:
            if isinstance(item, str) and item.strip().lower().startswith(("https://", "http://")):
                problem = _url_problem(item, ("https",))
                if problem:
                    raise ValueError(f"{name} entry {item!r} {problem}")
                out.append(item.strip())
            else:
                out.append(item)
        return out
    return value


def _canonical_choices(name: str, value: Any, spec: SettingSpec) -> Any:
    """``value`` with every item matched to its choice (case-insensitive for text); ValueError otherwise."""
    choices = spec.choices or ()

    def canon(item: Any) -> Any:
        if item in choices:
            return item
        if isinstance(item, str):
            low = item.strip().lower()
            for choice in choices:
                if isinstance(choice, str) and choice.lower() == low:
                    return choice
            if name in _URL_ITEM_SETTINGS and low.startswith("https://"):
                return item  # validated by _normalise_core
        raise ValueError(f"invalid value {item!r} for {name} (choices: {', '.join(map(str, choices))})")

    if isinstance(value, list):
        return [canon(v) for v in value]
    return canon(value)


def _check_choices(name: str, value: Any, spec: SettingSpec) -> None:
    if spec.choices is not None:
        _canonical_choices(name, value, spec)


def _normalise(name: str, value: Any, spec: SettingSpec) -> Any:
    """Validate a setting value against its spec and return the canonical form. Raises ValueError.

    Types follow the default (an int is accepted for a float), numbers are finite, built-in settings
    apply their own rules (canonical TLP, https-only platform URLs without credentials, ISO country
    code, header-safe strings, key_plans values) and ``choices`` restrict the value or every item.
    """
    default = spec.default
    if not _type_matches(value, default):
        raise ValueError(f"invalid value {value!r} for {name} (expected {type(default).__name__})")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"invalid value {value!r} for {name} (must be a finite number)")
    if isinstance(default, float) and isinstance(value, int):
        value = float(value)
    if spec.owner == CORE_OWNER:
        value = _normalise_core(name, value)
    if spec.choices is not None:
        value = _canonical_choices(name, value, spec)
    return value


def _coerce(value: str, default: Any) -> Any:
    """Parse a text value (CLI/env) into the type of ``default``. Raises ValueError when it cannot."""
    text = str(value).strip()
    if isinstance(default, bool):
        low = text.lower()
        if low in ("1", "true", "yes", "on"):
            return True
        if low in ("0", "false", "no", "off", ""):
            return False
        raise ValueError(f"expected a boolean (true/false), got {value!r}")
    if isinstance(default, int):
        return int(text)
    if isinstance(default, float):
        return float(text)
    if isinstance(default, list):
        if text.startswith("["):
            parsed = json.loads(text)
            if not isinstance(parsed, list):
                raise ValueError(f"expected a list, got {value!r}")
            return parsed
        return [v.strip() for v in text.split(",") if v.strip()]
    if isinstance(default, dict):
        parsed = json.loads(text) if text else {}
        if not isinstance(parsed, dict):
            raise ValueError(f"expected a JSON object, got {value!r}")
        return parsed
    if isinstance(default, str):
        return text
    return value
