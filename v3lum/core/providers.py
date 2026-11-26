"""Single provider registry (AR11): who runs each host, under which terms, and how V3LUM talks to it.

Fragments live in ``v3lum/data/providers/`` (the README there documents every field) and are merged at
load time, in sorted file-name order:

* ``<provider_id>.json`` - schema ``v3lum.provider/1``: one provider (hosts, tier, flags, reliability,
  HTTP profile, quota block, error markers, keys and sources with per-source terms evidence).
* ``<provider_id>__<suffix>.json`` - schema ``v3lum.provider-ext/1``: adds hosts, sources and error
  markers to a provider owned by another package. Extensions only add; a duplicate host, source or
  marker id is an error.
* ``_set_<name>.json`` - schema ``v3lum.provider-set/1``: several providers in one data-driven file
  owned by one package (e.g. a site list).

Every problem is recorded in ``registry().errors`` and never raised at load time. The offending
provider (or extension) is left out of the registry, so its hosts stay unregistered and the modules
that need it cannot register: the registry fails closed. ``register()`` applies the same validation
to programmatic fragments (tests, plugins) and raises ``ValueError`` instead.

Consumers: ``@register`` in core/module.py (derived module attributes, host ownership, terms), the
HTTP client (profiles, markers, sensitive no-store), the quota book, core/policy.py, scoring
(``ADMIRALTY``), the keys wizard (``KeySpec``) and doctor.

Example::

    from v3lum.core import providers

    reg = providers.registry()
    reg.provider_for_host("internetdb.shodan.io").tier      # 'trusted'
    reg.source("shodan.internetdb").terms.class_            # 'noncommercial'
    providers.most_restrictive(["open", "license"])         # 'license'
"""

from __future__ import annotations

import copy
import datetime as _dt
import functools
import ipaddress
import json
import math
import re
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

__all__ = [
    "ADMIRALTY",
    "DATA_DIR",
    "ErrorMarker",
    "HttpProfile",
    "KeySpec",
    "MARKER_MAPS",
    "PROFILE_REQUIREMENTS",
    "Provider",
    "ProviderFlags",
    "ProviderRegistry",
    "QuotaSpec",
    "Reliability",
    "Review",
    "SCHEMA_EXTENSION",
    "SCHEMA_PROVIDER",
    "SCHEMA_SET",
    "Source",
    "TERMS_ORDER",
    "TIERS",
    "TTL_CLASSES",
    "Terms",
    "UA_KEYWORDS",
    "UA_PLACEHOLDERS",
    "host_matches",
    "load_dir",
    "lowest_tier",
    "most_restrictive",
    "parse_marker",
    "profile_violations",
    "register",
    "registry",
    "reload",
    "restore",
    "snapshot",
    "unregister",
    "valid_host_pattern",
]

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "providers"

SCHEMA_PROVIDER = "v3lum.provider/1"
SCHEMA_EXTENSION = "v3lum.provider-ext/1"
SCHEMA_SET = "v3lum.provider-set/1"

#: Terms classes from least to most restrictive (A1). ``most_restrictive`` follows this order.
TERMS_ORDER: tuple[str, ...] = ("open", "key-terms", "license", "noncommercial", "unknown")
#: Provider trust tiers from most to least trusted (A8). ``lowest_tier`` follows this order.
TIERS: tuple[str, ...] = ("trusted", "community", "unknown")
#: Admiralty source-reliability grades -> scoring weight (P302 prior; F = cannot be judged).
ADMIRALTY: dict[str, float] = {"A": 1.0, "B": 0.85, "C": 0.7, "D": 0.5, "E": 0.3, "F": 0.5}
#: Documented guidance for ``http_profile.ttl`` per data class, in seconds (P326 cond 7).
TTL_CLASSES: dict[str, int] = {
    "dns": 3600,
    "rdap": 86400,
    "cnpj": 259200,
    "sanitized_breach": 604800,
    "crypto": 3600,
    "sanctions": 86400,
}
#: ``http_profile.user_agent`` keywords; anything else is a template (placeholders below only).
UA_KEYWORDS: tuple[str, ...] = ("neutral", "contact", "browser")
#: Placeholders a user_agent template may use: {version} (V3LUM version), {contact} (setting
#: contact_email), {contact_url} (setting contact_url) and {app} ('v3lum').
UA_PLACEHOLDERS: tuple[str, ...] = ("version", "contact", "contact_url", "app")
#: What an error marker may classify a response as (P321).
MARKER_MAPS: tuple[str, ...] = ("blocked", "rate_limited", "quota", "error")
QUOTA_SCOPES: tuple[str, ...] = ("egress_ip", "key")

#: Host pattern -> http_profile values (plus ``flags.sensitive``) binding on whichever fragment owns
#: a matching host (P326 cond 3, 4, 7, 11). Values must match exactly, except ``ttl``, which is a
#: maximum (the profile must set a ttl no larger than it). A contradicting fragment is a registry
#: error and is left out of the registry.
PROFILE_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "rdap.registro.br": {"user_agent": "neutral", "accept": "application/rdap+json", "accept_language": "pt-BR", "ttl": 86400},
    "registro.br": {"user_agent": "neutral", "accept": "application/rdap+json", "accept_language": "pt-BR", "ttl": 86400},
    "www.sec.gov": {"user_agent": "contact"},
    "data.sec.gov": {"user_agent": "contact"},
    "efts.sec.gov": {"user_agent": "contact"},
    "*.wikipedia.org": {"user_agent": "V3LUM/{version} (+{contact}) python-requests"},
    "*.wikimedia.org": {"user_agent": "V3LUM/{version} (+{contact}) python-requests"},
    "www.wikidata.org": {"user_agent": "V3LUM/{version} (+{contact}) python-requests"},
    "query.wikidata.org": {"user_agent": "V3LUM/{version} (+{contact}) python-requests"},
    "nominatim.openstreetmap.org": {"user_agent": "contact"},
    "bgp.tools": {"user_agent": "contact"},
    "haveibeenpwned.com": {"user_agent": "neutral", "flags.sensitive": True, "ttl": 604800},
    "api.pwnedpasswords.com": {"user_agent": "neutral", "flags.sensitive": True, "ttl": 604800},
    "isc.sans.edu": {"accept": "application/json"},
    "tools.keycdn.com": {"user_agent": "keycdn-tools:{contact_url}"},
    "checkurl.phishtank.com": {"user_agent": "phishtank/{app}"},
    "data.phishtank.com": {"user_agent": "phishtank/{app}"},
    "dns.google": {"ttl": 3600},
    "cloudflare-dns.com": {"ttl": 3600},
    "dns.quad9.net": {"ttl": 3600},
}

_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_SID_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_KEY_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_SETTING_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
_FAMILY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_DATASET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MARKER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_PLACEHOLDER_RE = re.compile(r"\{([^{}]*)\}")

_PROVIDER_FIELDS = frozenset({
    "schema", "id", "name", "operator", "hosts", "hosts_from_settings", "internal", "tier", "tier_rationale",
    "tier_reviewer", "tier_date", "flags", "personal_data_review", "reliability", "http_profile", "quota",
    "error_markers", "keys", "sources", "notes",
})
_EXTENSION_FIELDS = frozenset({"schema", "extends", "hosts", "sources", "error_markers", "notes"})
_SOURCE_FIELDS = frozenset({
    "title", "terms", "upstream_family", "sanitizer", "dataset", "notes", "embeds", "licensed_alternative",
})
_TERMS_FIELDS = frozenset({"class", "evidence_url", "quote", "checked_at", "reviewer", "free_plan_business_use"})
_SANITIZER_FIELDS = frozenset({"keep", "notes"})
#: One segment of a sanitizer keep path (same grammar as core/sanitize.py: a key, '*', each optionally
#: followed by '[]', or a bare '[]').
_KEEP_SEGMENT_RE = re.compile(r"^(?:\*|[^.\[\]]+)?(?:\[\])?$")
_FLAG_FIELDS = ("publishes_queries", "reuses_queries", "fetches_target", "sensitive")
_PROFILE_FIELDS = frozenset({
    "user_agent", "accept", "accept_language", "timeout", "retries", "max_bytes", "ttl", "min_interval", "concurrency",
})
_QUOTA_FIELDS = frozenset({
    "scope", "hour", "day", "month", "rate_per_second", "burst", "published", "evidence_url", "safety_margin",
})
_KEY_FIELDS = frozenset({"description", "signup_url", "env", "multi_key", "plan_hint"})
_MARKER_FIELDS = frozenset({
    "id", "statuses", "json_path", "equals", "regex", "final_url_regex", "maps_to", "reason_code", "reason",
})
#: Canonical reason codes an error marker may name, per ``maps_to`` (A3; mirrors models.REASON_CODES).
_MARKER_CODES: dict[str, frozenset[str]] = {
    "blocked": frozenset({"hostile_host", "circuit", "challenge", "geo_block", "login_wall"}),
    "rate_limited": frozenset({"rate_limited"}),
    "quota": frozenset({"quota"}),
    "error": frozenset({"timeout", "sanitizer", "error"}),
}


# ---------------------------------------------------------------------------------- data model


@dataclass(frozen=True)
class ProviderFlags:
    """Data-handling flags of a provider (A8; all four are required in a fragment)."""

    #: rule 7: the provider publishes submitted values (recent lookups, public scan feeds) - never send values.
    publishes_queries: bool = False
    #: the terms allow reusing, selling or redistributing submitted values (excluded at TLP:AMBER and above).
    reuses_queries: bool = False
    #: the provider fetches the target live (only cached/no-publish modes may be default, A3).
    fetches_target: bool = False
    #: breach, infostealer or people-data provider (A4: sanitizer schema mandatory, cache sanitized or no-store).
    sensitive: bool = False


@dataclass(frozen=True)
class Review:
    """A recorded personal-data review (A3/A8: needed before PERSONAL_TYPES reach the default set)."""

    basis: str
    reviewer: str
    date: str


@dataclass(frozen=True)
class Reliability:
    """Admiralty source-reliability grade of a provider with its justification."""

    grade: str = "F"
    justification: str = ""

    @property
    def weight(self) -> float:
        """Scoring prior for the grade (``ADMIRALTY``)."""
        return ADMIRALTY.get(self.grade, ADMIRALTY["F"])


@dataclass(frozen=True)
class HttpProfile:
    """Per-provider HTTP profile applied by the HTTP client to every host of the provider (P326).

    ``user_agent``: None or 'neutral' (setting user_agent, 'V3LUM/<version>'), 'contact' (identifying UA
    with setting contact_email), 'browser' (setting ua_light; only where a public page needs it, never
    to pass a bot wall) or a template using only {version}, {contact}, {contact_url} and {app}.
    """

    user_agent: str | None = None
    accept: str | None = None
    accept_language: str | None = None
    timeout: float | None = None
    retries: int = 1
    max_bytes: int | None = None
    ttl: int | None = None
    min_interval: float = 0.0
    concurrency: int = 4

    @property
    def ua_kind(self) -> str:
        """'neutral' (None or 'neutral'), 'contact', 'browser' or 'template'."""
        if self.user_agent is None or self.user_agent == "neutral":
            return "neutral"
        if self.user_agent in UA_KEYWORDS:
            return self.user_agent
        return "template"

    @property
    def ua_placeholders(self) -> frozenset[str]:
        """Placeholders used by a user_agent template ({contact} also for the 'contact' keyword)."""
        if self.user_agent == "contact":
            return frozenset({"contact"})
        if self.ua_kind != "template":
            return frozenset()
        return frozenset(_PLACEHOLDER_RE.findall(self.user_agent or ""))


@dataclass(frozen=True)
class QuotaSpec:
    """Provider quota block (P334): published limits; budgets apply ``safety_margin`` (default 80%).

    ``scope`` 'egress_ip' (keyless: one budget per installation and egress, never multiplied) or 'key'
    (counted per configured key). ``published`` is True when the numbers are the provider's published
    limits (``evidence_url`` points to them) and False when they were observed/estimated.
    """

    scope: str
    hour: int | None = None
    day: int | None = None
    month: int | None = None
    rate_per_second: float | None = None
    burst: int = 1
    published: bool = True
    evidence_url: str = ""
    safety_margin: float = 0.8

    def limit(self, window: str) -> int | None:
        """The published limit of a window ('hour' | 'day' | 'month') or None."""
        return {"hour": self.hour, "day": self.day, "month": self.month}.get(window)

    def budget(self, window: str) -> int | None:
        """Usable budget of a window: floor(limit x safety_margin), at least 1; None when unlimited."""
        limit = self.limit(window)
        if limit is None:
            return None
        return max(1, math.floor(limit * self.safety_margin))


@dataclass(frozen=True)
class ErrorMarker:
    """Declared error-in-200 rule (P321), shared by provider fragments, modules and P331 specs.

    A marker matches when the response status is in ``statuses`` and every given matcher matches:
    ``json_path`` (dotted path into the JSON body) + ``equals`` (or ``regex`` over that value), ``regex``
    alone (over the first 64 KB of the body text) and/or ``final_url_regex`` (over the final URL).
    ``maps_to`` is the outcome ('blocked' | 'rate_limited' | 'quota' | 'error'), ``reason_code`` an
    optional canonical code for it and ``reason`` the human text naming the provider.
    """

    id: str
    statuses: tuple[int, ...] = (200,)
    json_path: str | None = None
    equals: Any = None
    regex: str | None = None
    final_url_regex: str | None = None
    maps_to: str = "error"
    reason_code: str | None = None
    reason: str = ""

    def __hash__(self) -> int:  # ``equals`` may hold a list/dict
        return hash((self.id, self.statuses, self.json_path, self.regex, self.final_url_regex, self.maps_to, self.reason_code, self.reason))

    def to_dict(self) -> dict[str, Any]:
        """The fragment form of the marker (JSON-serialisable)."""
        out: dict[str, Any] = {"id": self.id, "statuses": list(self.statuses)}
        if self.json_path is not None:
            out["json_path"] = self.json_path
        if self.equals is not None:
            out["equals"] = self.equals
        if self.regex is not None:
            out["regex"] = self.regex
        if self.final_url_regex is not None:
            out["final_url_regex"] = self.final_url_regex
        out["maps_to"] = self.maps_to
        if self.reason_code:
            out["reason_code"] = self.reason_code
        out["reason"] = self.reason
        return out


@dataclass(frozen=True)
class KeySpec:
    """An API key declared by a provider fragment (or the legacy config.KNOWN_KEYS table).

    ``env`` lists conventional environment aliases (``V3LUM_KEY_<NAME>`` always works).
    ``multi_key`` must stay False in this build: one key per provider (P332 veto_lift).
    """

    name: str
    provider: str = ""
    description: str = ""
    signup_url: str = ""
    env: tuple[str, ...] = ()
    multi_key: bool = False
    plan_hint: str = ""


@dataclass(frozen=True)
class Terms:
    """Per-source terms evidence (A1/P377). ``class_`` is one of TERMS_ORDER."""

    class_: str
    evidence_url: str = ""
    quote: str = ""
    checked_at: str = ""
    reviewer: str = ""
    #: True/False when the free plan's business use is settled, None when it depends on the key plan.
    free_plan_business_use: bool | None = None


@dataclass(frozen=True)
class Source:
    """One data source (endpoint family or feed) of a provider; ``id`` is 'provider.source'."""

    id: str
    provider: str
    title: str
    terms: Terms
    upstream_family: str
    sanitizer: dict[str, Any] | None = None
    dataset: str | None = None
    notes: str = ""
    #: upstream families an aggregator re-serves (P171 cond 3: FireHOL/IPsum, OTX pulses relaying abuse.ch).
    embeds: tuple[str, ...] = ()
    #: the licensed source that restores the coverage when this one is licence-blocked (doctor --licences).
    licensed_alternative: str = ""

    def __hash__(self) -> int:
        return hash(self.id)

    @property
    def sid(self) -> str:
        """The short source id (the key inside the provider fragment)."""
        return self.id.split(".", 1)[1]

    @property
    def terms_class(self) -> str:
        return self.terms.class_

    @property
    def families(self) -> frozenset[str]:
        """The source's upstream family plus the families it embeds."""
        return frozenset({self.upstream_family, *self.embeds}) - {""}


@dataclass(frozen=True)
class Provider:
    """A registered provider. ``sources`` maps the short source id to its Source (Source.id is qualified)."""

    id: str
    name: str
    operator: str
    hosts: tuple[str, ...] = ()
    hosts_from_settings: tuple[str, ...] = ()
    internal: bool = False
    tier: str = "unknown"
    tier_rationale: str = ""
    tier_reviewer: str = ""
    tier_date: str = ""
    flags: ProviderFlags = field(default_factory=ProviderFlags)
    personal_data_review: Review | None = None
    reliability: Reliability = field(default_factory=Reliability)
    http_profile: HttpProfile = field(default_factory=HttpProfile)
    quota: QuotaSpec | None = None
    error_markers: tuple[ErrorMarker, ...] = ()
    keys: dict[str, KeySpec] = field(default_factory=dict)
    sources: dict[str, Source] = field(default_factory=dict)
    origin: str = ""
    notes: str = ""
    #: free-form ``x_*`` fields of the fragment (extension point for later packages).
    extra: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.id)

    def source(self, sid: str) -> Source | None:
        """A source of this provider by short ('internetdb') or qualified ('shodan.internetdb') id."""
        if "." in sid:
            pid, _, sid = sid.partition(".")
            if pid != self.id:
                return None
        return self.sources.get(sid)


# ---------------------------------------------------------------------------------- helpers


def most_restrictive(classes: Iterable[str]) -> str:
    """The most restrictive terms class (open < key-terms < license < noncommercial < unknown).

    An empty iterable gives 'open' (nothing restricts the module); an unknown class counts as 'unknown'.
    """
    worst = 0
    for cls in classes:
        idx = TERMS_ORDER.index(cls) if cls in TERMS_ORDER else len(TERMS_ORDER) - 1
        worst = max(worst, idx)
    return TERMS_ORDER[worst]


def lowest_tier(tiers: Iterable[str]) -> str:
    """The least trusted tier (trusted > community > unknown). Empty or unknown values give 'unknown'."""
    seen = list(tiers)
    if not seen:
        return "unknown"
    worst = 0
    for tier in seen:
        idx = TIERS.index(tier) if tier in TIERS else len(TIERS) - 1
        worst = max(worst, idx)
    return TIERS[worst]


def valid_host_pattern(pattern: str) -> bool:
    """True for a lower-case exact host name, an IP literal or a '*.suffix' wildcard (suffix >= 2 labels)."""
    if not isinstance(pattern, str) or not pattern or pattern != pattern.strip().lower():
        return False
    wildcard = pattern.startswith("*.")
    name = pattern[2:] if wildcard else pattern
    if not wildcard:
        try:
            ipaddress.ip_address(name)
            return True
        except ValueError:
            pass
    labels = name.split(".")
    if len(labels) < 2 or len(name) > 253:
        return False
    return all(_LABEL_RE.match(label) for label in labels)


def host_matches(host: str, pattern: str) -> bool:
    """Does ``host`` match a declared host pattern? Exact match, or '*.suffix' for strict subdomains.

    A wildcard pattern also matches the identical wildcard (a module declaring '*.example.com' against
    a provider owning '*.example.com') and narrower wildcards ('*.a.example.com').
    """
    host = (host or "").strip().lower().rstrip(".")
    pattern = (pattern or "").strip().lower().rstrip(".")
    if not host or not pattern:
        return False
    if host == pattern:
        return True
    if not pattern.startswith("*."):
        return False
    suffix = pattern[2:]
    if host.startswith("*."):
        inner = host[2:]
        return inner == suffix or inner.endswith("." + suffix)
    return host.endswith("." + suffix)


def _overlap(a: str, b: str) -> bool:
    """Can one concrete host match both patterns?"""
    return host_matches(a, b) or host_matches(b, a)


def profile_violations(provider: Provider) -> list[str]:
    """PROFILE_REQUIREMENTS violations of a provider (empty when compliant)."""
    out: list[str] = []
    for host in provider.hosts:
        for pattern, req in PROFILE_REQUIREMENTS.items():
            if not _overlap(host, pattern):
                continue
            for name, expected in req.items():
                if name == "flags.sensitive":
                    if provider.flags.sensitive is not bool(expected):
                        out.append(f"host {host} requires flags.sensitive={str(bool(expected)).lower()} (PROFILE_REQUIREMENTS {pattern})")
                    continue
                actual = getattr(provider.http_profile, name)
                if name == "ttl":
                    if actual is None or actual > expected:
                        out.append(f"host {host} requires http_profile.ttl <= {expected} (got {actual!r}; PROFILE_REQUIREMENTS {pattern})")
                elif actual != expected:
                    out.append(f"host {host} requires http_profile.{name} = {expected!r} (got {actual!r}; PROFILE_REQUIREMENTS {pattern})")
    return out


def _valid_url(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _valid_date(value: Any) -> bool:
    if not isinstance(value, str) or not _DATE_RE.match(value):
        return False
    try:
        _dt.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _valid_keep_path(path: str) -> bool:
    """A P145 keep path ('breaches[].Name', 'stealers[].date_compromised', '*.count')."""
    path = path.strip()
    return bool(path) and all(seg and _KEEP_SEGMENT_RE.match(seg) for seg in path.split("."))


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_num(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _unknown_fields(data: Mapping[str, Any], allowed: frozenset[str]) -> list[str]:
    return sorted(k for k in data if k not in allowed and not str(k).startswith("x_"))


def _str_list(value: Any, what: str, errs: list[str]) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        errs.append(f"{what} must be a list of strings")
        return ()
    return tuple(value)


def parse_marker(data: Mapping[str, Any] | ErrorMarker) -> ErrorMarker:
    """Validate an error-marker dict (P321 schema) and return an ErrorMarker. Raises ValueError.

    Schema: {"id", "statuses": [200], "json_path": "a.b" | null, "equals": any, "regex": str | null,
    "final_url_regex": str | null, "maps_to": "blocked"|"rate_limited"|"quota"|"error",
    "reason_code": optional canonical code, "reason": "human text naming the provider"}.
    """
    if isinstance(data, ErrorMarker):
        data = data.to_dict()
    if not isinstance(data, Mapping):
        raise ValueError("error marker must be an object")
    problems: list[str] = []
    bad = _unknown_fields(data, _MARKER_FIELDS)
    if bad:
        problems.append(f"unknown field(s) {', '.join(bad)}")
    mid = data.get("id")
    if not isinstance(mid, str) or not _MARKER_ID_RE.match(mid):
        problems.append("id must match ^[a-z0-9][a-z0-9_.-]{0,63}$")
        mid = str(mid or "?")
    statuses = data.get("statuses", [200])
    if not isinstance(statuses, list) or not statuses or not all(_is_int(s) and 100 <= s <= 599 for s in statuses):
        problems.append("statuses must be a non-empty list of HTTP status codes (100-599)")
        statuses = [200]
    json_path = data.get("json_path")
    if json_path is not None and (not isinstance(json_path, str) or not json_path or any(not part for part in json_path.split("."))):
        problems.append("json_path must be a dotted path such as 'error.code'")
    equals = data.get("equals")
    regex = data.get("regex")
    final_url_regex = data.get("final_url_regex")
    for name, value in (("regex", regex), ("final_url_regex", final_url_regex)):
        if value is None:
            continue
        if not isinstance(value, str) or not value or len(value) > 500:
            problems.append(f"{name} must be a non-empty string of at most 500 characters")
            continue
        try:
            re.compile(value)
        except re.error as exc:
            problems.append(f"{name} does not compile ({exc})")
    if json_path is not None and equals is None and regex is None:
        problems.append("json_path needs 'equals' (a non-null JSON value) or 'regex'")
    if json_path is None and regex is None and final_url_regex is None:
        problems.append("needs at least one matcher: json_path + equals, regex or final_url_regex")
    maps_to = data.get("maps_to")
    if maps_to not in MARKER_MAPS:
        problems.append(f"maps_to must be one of {', '.join(MARKER_MAPS)}")
    reason_code = data.get("reason_code")
    if reason_code is not None and (not isinstance(reason_code, str) or reason_code not in _MARKER_CODES.get(str(maps_to), frozenset())):
        allowed = ", ".join(sorted(_MARKER_CODES.get(str(maps_to), frozenset()))) or "-"
        problems.append(f"reason_code {reason_code!r} is not a canonical code for maps_to {maps_to!r} (allowed: {allowed})")
    reason = data.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        problems.append("reason must be a human-readable text naming the provider")
    if problems:
        raise ValueError(f"error marker {mid}: " + "; ".join(problems))
    return ErrorMarker(
        id=str(mid),
        statuses=tuple(int(s) for s in statuses),
        json_path=json_path,
        equals=equals,
        regex=regex,
        final_url_regex=final_url_regex,
        maps_to=str(maps_to),
        reason_code=reason_code or None,
        reason=str(reason),
    )


# ---------------------------------------------------------------------------------- fragment parsing


def _parse_terms(raw: Any, where: str, errs: list[str]) -> Terms | None:
    if not isinstance(raw, Mapping):
        errs.append(f"{where}: terms must be an object")
        return None
    bad = _unknown_fields(raw, _TERMS_FIELDS)
    if bad:
        errs.append(f"{where}: unknown terms field(s) {', '.join(bad)}")
    cls = raw.get("class")
    if cls not in TERMS_ORDER:
        errs.append(f"{where}: terms.class must be one of {', '.join(TERMS_ORDER)} (got {cls!r})")
        return None
    evidence_url = raw.get("evidence_url", "")
    quote = raw.get("quote", "")
    if cls != "unknown":
        if not _valid_url(evidence_url):
            errs.append(f"{where}: terms.evidence_url must be an http(s) URL for class {cls!r}")
        if not isinstance(quote, str) or not quote.strip():
            errs.append(f"{where}: terms.quote is required for class {cls!r} (quote the terms or the binding A1 text)")
    elif evidence_url not in ("", None) and not _valid_url(evidence_url):
        errs.append(f"{where}: terms.evidence_url must be an http(s) URL")
    checked_at = raw.get("checked_at")
    if not _valid_date(checked_at):
        errs.append(f"{where}: terms.checked_at must be a YYYY-MM-DD date")
    reviewer = raw.get("reviewer")
    if not isinstance(reviewer, str) or not reviewer.strip():
        errs.append(f"{where}: terms.reviewer is required")
    fpbu = raw.get("free_plan_business_use")
    if fpbu is not None and not isinstance(fpbu, bool):
        errs.append(f"{where}: terms.free_plan_business_use must be true, false or null")
        fpbu = None
    # A1 definitions: 'open' includes internal business use; 'license'/'noncommercial' exclude it
    if cls == "open" and fpbu is False:
        errs.append(f"{where}: terms.free_plan_business_use false contradicts class 'open' (free use, business use included) - use 'key-terms', 'license' or 'noncommercial'")
    if cls in ("license", "noncommercial") and fpbu is True:
        errs.append(f"{where}: terms.free_plan_business_use true contradicts class {cls!r} (business use is excluded or needs a licence) - fix the class or the flag")
    return Terms(
        class_=str(cls),
        evidence_url=str(evidence_url or ""),
        quote=str(quote or ""),
        checked_at=str(checked_at or ""),
        reviewer=str(reviewer or ""),
        free_plan_business_use=fpbu,
    )


def _parse_source(pid: str, sid: Any, raw: Any, where: str, errs: list[str]) -> Source | None:
    here = f"{where}: source {sid!r}"
    if not isinstance(sid, str) or not _SID_RE.match(sid):
        errs.append(f"{here}: source ids must match ^[a-z][a-z0-9_]{{0,63}}$")
        return None
    if not isinstance(raw, Mapping):
        errs.append(f"{here}: must be an object")
        return None
    before = len(errs)
    bad = _unknown_fields(raw, _SOURCE_FIELDS)
    if bad:
        errs.append(f"{here}: unknown field(s) {', '.join(bad)}")
    title = raw.get("title")
    if not isinstance(title, str) or not title.strip():
        errs.append(f"{here}: title is required")
    terms = _parse_terms(raw.get("terms"), here, errs)
    family = raw.get("upstream_family")
    if not isinstance(family, str) or not _FAMILY_RE.match(family):
        errs.append(f"{here}: upstream_family is required (e.g. 'abuse.ch', 'dns'; ^[a-z0-9][a-z0-9._-]{{0,63}}$)")
    sanitizer = raw.get("sanitizer")
    if sanitizer is not None:
        keep = sanitizer.get("keep") if isinstance(sanitizer, Mapping) else None
        if not isinstance(keep, list) or not keep or not all(isinstance(k, str) and k.strip() for k in keep):
            errs.append(f"{here}: sanitizer must be null or {{\"keep\": [non-empty paths]}}")
        else:
            bad_paths = [k for k in keep if not _valid_keep_path(k)]
            if bad_paths:
                errs.append(f"{here}: sanitizer keep path {bad_paths[0]!r} is invalid (dotted keys, '[]' for list elements, '*' for any key)")
            bad = _unknown_fields(sanitizer, _SANITIZER_FIELDS)
            if bad:
                errs.append(f"{here}: unknown sanitizer field(s) {', '.join(bad)}")
            if not isinstance(sanitizer.get("notes", ""), str):
                errs.append(f"{here}: sanitizer.notes must be a string")
    dataset = raw.get("dataset")
    if dataset is not None and (not isinstance(dataset, str) or not _DATASET_RE.match(dataset)):
        errs.append(f"{here}: dataset must be null or a dataset name (^[A-Za-z0-9][A-Za-z0-9._-]{{0,127}}$)")
    notes = raw.get("notes", "")
    if not isinstance(notes, str):
        errs.append(f"{here}: notes must be a string")
    embeds = _str_list(raw.get("embeds"), f"{here}: embeds", errs)
    for fam in embeds:
        if not _FAMILY_RE.match(fam):
            errs.append(f"{here}: embeds entry {fam!r} is not an upstream family name")
    alt = raw.get("licensed_alternative", "")
    if not isinstance(alt, str):
        errs.append(f"{here}: licensed_alternative must be a string")
    if len(errs) > before or terms is None:
        return None
    return Source(
        id=f"{pid}.{sid}",
        provider=pid,
        title=str(title),
        terms=terms,
        upstream_family=str(family),
        sanitizer=dict(sanitizer) if isinstance(sanitizer, Mapping) else None,
        dataset=dataset,
        notes=str(notes),
        embeds=embeds,
        licensed_alternative=str(alt),
    )


def _parse_sources(pid: str, raw: Any, where: str, errs: list[str]) -> dict[str, Source]:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        errs.append(f"{where}: sources must be an object (source id -> source)")
        return {}
    out: dict[str, Source] = {}
    for sid, body in raw.items():
        src = _parse_source(pid, sid, body, where, errs)
        if src is not None:
            out[sid] = src
    return out


@functools.lru_cache(maxsize=1)
def _psl_namespaces() -> frozenset[str]:
    """Every name under which the bundled Public Suffix List delegates registrations to others.

    That is each rule ('co.uk', 'github.io', 's3.amazonaws.com', '*.ck' -> 'ck') plus every parent
    domain of a rule ('amazonaws.com' for 's3.amazonaws.com'). Empty when the list is missing.
    """
    try:
        text = (DATA_DIR.parent / "public_suffix_list.dat").read_text(encoding="utf-8")
    except OSError:  # pragma: no cover - the PSL is bundled (P330)
        return frozenset()
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        labels = line.split()[0].lstrip("!").lower().split(".")
        if labels and labels[0] == "*":
            labels = labels[1:]
        for i in range(len(labels)):
            out.add(".".join(labels[i:]))
    return frozenset(out)


def _wildcard_over_registrants(pattern: str) -> bool:
    """'*.suffix' covering hosts registered by unrelated parties ('*.co.uk', '*.github.io', '*.amazonaws.com')."""
    return pattern.startswith("*.") and pattern[2:] in _psl_namespaces()


def _non_global_ip(pattern: str) -> bool:
    try:
        return not ipaddress.ip_address(pattern).is_global
    except ValueError:
        return False


def _parse_hosts(raw: Any, where: str, errs: list[str]) -> tuple[str, ...]:
    hosts = _str_list(raw, f"{where}: hosts", errs)
    seen: set[str] = set()
    out: list[str] = []
    for host in hosts:
        if not valid_host_pattern(host):
            errs.append(f"{where}: invalid host {host!r} (lower-case host name, IP literal or '*.suffix' with >= 2 labels)")
            continue
        if _wildcard_over_registrants(host):
            errs.append(
                f"{where}: host {host!r} is a wildcard over a public-suffix namespace (hosts there belong to unrelated "
                "registrants, so it would let PASSIVE modules reach arbitrary sites) - list the exact hosts instead"
            )
            continue
        if _non_global_ip(host):
            errs.append(
                f"{where}: host {host!r} is a private, loopback, link-local or reserved address - internal platforms "
                "are configured through hosts_from_settings (https URL settings), never as static hosts"
            )
            continue
        if host in seen:
            errs.append(f"{where}: host {host!r} listed twice")
            continue
        seen.add(host)
        out.append(host)
    return tuple(out)


def _parse_markers(raw: Any, where: str, errs: list[str]) -> tuple[ErrorMarker, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        errs.append(f"{where}: error_markers must be a list")
        return ()
    out: list[ErrorMarker] = []
    ids: set[str] = set()
    for item in raw:
        try:
            marker = parse_marker(item)
        except ValueError as exc:
            errs.append(f"{where}: {exc}")
            continue
        if marker.id in ids:
            errs.append(f"{where}: duplicate error marker id {marker.id!r}")
            continue
        ids.add(marker.id)
        out.append(marker)
    return tuple(out)


def _parse_profile(raw: Any, where: str, errs: list[str]) -> HttpProfile:
    if raw is None:
        return HttpProfile()
    if not isinstance(raw, Mapping):
        errs.append(f"{where}: http_profile must be an object")
        return HttpProfile()
    bad = _unknown_fields(raw, _PROFILE_FIELDS)
    if bad:
        errs.append(f"{where}: unknown http_profile field(s) {', '.join(bad)}")
    ua = raw.get("user_agent")
    if ua is not None:
        if not isinstance(ua, str) or not ua.strip():
            errs.append(f"{where}: http_profile.user_agent must be null, 'neutral', 'contact', 'browser' or a template")
            ua = None
        elif ua not in UA_KEYWORDS:
            if "mozilla/" in ua.lower():
                errs.append(f"{where}: http_profile.user_agent template looks like a browser UA - use 'browser' (setting ua_light) where a public page needs one")
            names = _PLACEHOLDER_RE.findall(ua)
            unknown = [n for n in names if n not in UA_PLACEHOLDERS]
            if unknown:
                errs.append(f"{where}: http_profile.user_agent template uses unknown placeholder(s) {', '.join(unknown)} (allowed: {', '.join(UA_PLACEHOLDERS)})")
            if _PLACEHOLDER_RE.sub("", ua).count("{") or _PLACEHOLDER_RE.sub("", ua).count("}"):
                errs.append(f"{where}: http_profile.user_agent template has unbalanced braces")
    values: dict[str, Any] = {"user_agent": ua}
    for name in ("accept", "accept_language"):
        value = raw.get(name)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            errs.append(f"{where}: http_profile.{name} must be null or a non-empty string")
            value = None
        values[name] = value
    timeout = raw.get("timeout")
    if timeout is not None and (not _is_num(timeout) or timeout <= 0):
        errs.append(f"{where}: http_profile.timeout must be null or a positive number of seconds")
        timeout = None
    values["timeout"] = float(timeout) if timeout is not None else None
    retries = raw.get("retries", 1)
    if not _is_int(retries) or not 0 <= retries <= 5:
        errs.append(f"{where}: http_profile.retries must be an integer 0..5")
        retries = 1
    values["retries"] = retries
    for name in ("max_bytes", "ttl"):
        value = raw.get(name)
        if value is not None and (not _is_int(value) or value < (1 if name == "max_bytes" else 0)):
            errs.append(f"{where}: http_profile.{name} must be null or a {'positive' if name == 'max_bytes' else 'non-negative'} integer")
            value = None
        values[name] = value
    min_interval = raw.get("min_interval", 0.0)
    if not _is_num(min_interval) or min_interval < 0:
        errs.append(f"{where}: http_profile.min_interval must be a number >= 0")
        min_interval = 0.0
    values["min_interval"] = float(min_interval)
    concurrency = raw.get("concurrency", 4)
    if not _is_int(concurrency) or concurrency < 1:
        errs.append(f"{where}: http_profile.concurrency must be an integer >= 1")
        concurrency = 4
    values["concurrency"] = concurrency
    return HttpProfile(**values)


def _parse_quota(raw: Any, where: str, errs: list[str]) -> QuotaSpec | None:
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        errs.append(f"{where}: quota must be null or an object")
        return None
    before = len(errs)
    bad = _unknown_fields(raw, _QUOTA_FIELDS)
    if bad:
        errs.append(f"{where}: unknown quota field(s) {', '.join(bad)}")
    scope = raw.get("scope")
    if scope not in QUOTA_SCOPES:
        errs.append(f"{where}: quota.scope must be 'egress_ip' or 'key'")
    limits: dict[str, Any] = {}
    for name in ("hour", "day", "month"):
        value = raw.get(name)
        if value is not None and (not _is_int(value) or value < 1):
            errs.append(f"{where}: quota.{name} must be null or a positive integer")
        limits[name] = value
    rate = raw.get("rate_per_second")
    if rate is not None and (not _is_num(rate) or rate <= 0):
        errs.append(f"{where}: quota.rate_per_second must be null or a positive number")
    if all(limits[n] is None for n in limits) and rate is None:
        errs.append(f"{where}: quota needs at least one of hour, day, month or rate_per_second")
    burst = raw.get("burst", 1)
    if not _is_int(burst) or burst < 1:
        errs.append(f"{where}: quota.burst must be an integer >= 1")
    published = raw.get("published")
    if not isinstance(published, bool):
        errs.append(f"{where}: quota.published must be true (provider's published limits) or false (observed)")
    evidence_url = raw.get("evidence_url", "")
    if published is True and not _valid_url(evidence_url):
        errs.append(f"{where}: quota.evidence_url must point to the published limits")
    elif evidence_url not in ("", None) and not _valid_url(evidence_url):
        errs.append(f"{where}: quota.evidence_url must be an http(s) URL")
    margin = raw.get("safety_margin", 0.8)
    if not _is_num(margin) or not 0 < margin <= 0.8:
        errs.append(f"{where}: quota.safety_margin must be in (0, 0.8] (budgets stay at <= 80% of the published limit)")
    if len(errs) > before:
        return None
    return QuotaSpec(
        scope=str(scope),
        hour=limits["hour"],
        day=limits["day"],
        month=limits["month"],
        rate_per_second=float(rate) if rate is not None else None,
        burst=int(burst),
        published=bool(published),
        evidence_url=str(evidence_url or ""),
        safety_margin=float(margin),
    )


def _parse_keys(pid: str, raw: Any, where: str, errs: list[str]) -> dict[str, KeySpec]:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        errs.append(f"{where}: keys must be an object (key name -> key)")
        return {}
    out: dict[str, KeySpec] = {}
    for name, body in raw.items():
        here = f"{where}: key {name!r}"
        if not isinstance(name, str) or not _KEY_NAME_RE.match(name):
            errs.append(f"{here}: key names must match ^[a-z][a-z0-9_]{{1,63}}$")
            continue
        if not isinstance(body, Mapping):
            errs.append(f"{here}: must be an object")
            continue
        before = len(errs)
        bad = _unknown_fields(body, _KEY_FIELDS)
        if bad:
            errs.append(f"{here}: unknown field(s) {', '.join(bad)}")
        desc = body.get("description")
        if not isinstance(desc, str) or not desc.strip():
            errs.append(f"{here}: description is required")
        signup = body.get("signup_url", "")
        if signup not in ("", None) and not _valid_url(signup):
            errs.append(f"{here}: signup_url must be an http(s) URL")
        env = _str_list(body.get("env"), f"{here}: env", errs)
        for alias in env:
            if not _ENV_RE.match(alias):
                errs.append(f"{here}: env alias {alias!r} must be an upper-case environment variable name")
        multi = body.get("multi_key", False)
        if not isinstance(multi, bool):
            errs.append(f"{here}: multi_key must be a boolean")
        elif multi:
            errs.append(f"{here}: multi_key true is not supported - one key per provider (P332 veto_lift; multi-seat selection is in the backlog)")
        plan_hint = body.get("plan_hint", "")
        if not isinstance(plan_hint, str):
            errs.append(f"{here}: plan_hint must be a string")
        if len(errs) > before:
            continue
        out[name] = KeySpec(
            name=name,
            provider=pid,
            description=str(desc),
            signup_url=str(signup or ""),
            env=env,
            multi_key=False,
            plan_hint=str(plan_hint or ""),
        )
    return out


def _parse_provider(data: Any, origin: str, *, stem: str | None = None, require_schema: bool = False) -> tuple[Provider | None, list[str]]:
    """Validate one provider object. Returns (provider or None, errors); any error drops the provider.

    ``require_schema``: a ``<id>.json`` file must carry ``"schema"`` (members of a provider set and
    programmatic fragments may omit it).
    """
    errs: list[str] = []
    if not isinstance(data, Mapping):
        return None, [f"{origin}: a provider must be a JSON object"]
    pid = data.get("id")
    where = f"{origin}: provider {pid!r}" if isinstance(pid, str) else f"{origin}: provider"
    if require_schema and "schema" not in data:
        errs.append(f"{where}: schema is required ({SCHEMA_PROVIDER!r})")
    schema = data.get("schema", SCHEMA_PROVIDER)
    if schema != SCHEMA_PROVIDER:
        errs.append(f"{where}: schema must be {SCHEMA_PROVIDER!r} (got {schema!r})")
    bad = _unknown_fields(data, _PROVIDER_FIELDS)
    if bad:
        errs.append(f"{where}: unknown field(s) {', '.join(bad)} (custom fields must start with 'x_')")
    if not isinstance(pid, str) or not _ID_RE.match(pid):
        errs.append(f"{where}: id must match ^[a-z][a-z0-9_]{{1,63}}$")
        return None, errs
    if stem is not None and stem != pid:
        errs.append(f"{where}: id must equal the file name stem {stem!r}")
    for name in ("name", "operator", "tier_rationale", "tier_reviewer"):
        value = data.get(name)
        if not isinstance(value, str) or not value.strip():
            errs.append(f"{where}: {name} is required")
    hosts = _parse_hosts(data.get("hosts", []), where, errs)
    hosts_from_settings = _str_list(data.get("hosts_from_settings"), f"{where}: hosts_from_settings", errs)
    for name in hosts_from_settings:
        if not _SETTING_RE.match(name):
            errs.append(f"{where}: hosts_from_settings entry {name!r} is not a setting name")
    internal = data.get("internal", False)
    if not isinstance(internal, bool):
        errs.append(f"{where}: internal must be a boolean")
        internal = False
    tier = data.get("tier")
    if tier not in TIERS:
        errs.append(f"{where}: tier must be one of {', '.join(TIERS)} (got {tier!r})")
    if not _valid_date(data.get("tier_date")):
        errs.append(f"{where}: tier_date must be a YYYY-MM-DD date")
    flags_raw = data.get("flags")
    flags = ProviderFlags()
    if not isinstance(flags_raw, Mapping):
        errs.append(f"{where}: flags must be an object with the four booleans {', '.join(_FLAG_FIELDS)}")
    else:
        bad = _unknown_fields(flags_raw, frozenset(_FLAG_FIELDS))
        if bad:
            errs.append(f"{where}: unknown flag(s) {', '.join(bad)}")
        missing = [f for f in _FLAG_FIELDS if not isinstance(flags_raw.get(f), bool)]
        if missing:
            errs.append(f"{where}: flags.{', flags.'.join(missing)} must be declared as booleans")
        else:
            flags = ProviderFlags(**{f: flags_raw[f] for f in _FLAG_FIELDS})
    review = None
    pdr = data.get("personal_data_review")
    if pdr is not None:
        if not isinstance(pdr, Mapping) or not all(isinstance(pdr.get(k), str) and pdr.get(k, "").strip() for k in ("basis", "reviewer")) or not _valid_date(pdr.get("date")):
            errs.append(f"{where}: personal_data_review must be null or {{basis, reviewer, date (YYYY-MM-DD)}}")
        else:
            review = Review(basis=pdr["basis"], reviewer=pdr["reviewer"], date=pdr["date"])
    rel_raw = data.get("reliability")
    reliability = Reliability()
    grade = rel_raw.get("grade") if isinstance(rel_raw, Mapping) else None
    justification = rel_raw.get("justification") if isinstance(rel_raw, Mapping) else None
    # isinstance first: an unhashable grade (list/dict) must be an error entry, never a TypeError
    if not isinstance(grade, str) or grade not in ADMIRALTY or not isinstance(justification, str) or not justification.strip():
        errs.append(f"{where}: reliability must be {{grade: A..F, justification}}")
    else:
        reliability = Reliability(grade=grade, justification=justification)
    profile = _parse_profile(data.get("http_profile"), where, errs)
    if tier == "unknown" and profile.ua_placeholders & {"contact", "contact_url"}:
        errs.append(
            f"{where}: http_profile.user_agent {profile.user_agent!r} identifies the organisation to an unknown-tier "
            "provider - the contact UA never goes to unknown-tier providers (P326 cond 5); use 'neutral'"
        )
    quota = _parse_quota(data.get("quota"), where, errs)
    markers = _parse_markers(data.get("error_markers"), where, errs)
    keys = _parse_keys(pid, data.get("keys"), where, errs)
    sources = _parse_sources(pid, data.get("sources"), where, errs)
    notes = data.get("notes", "")
    if not isinstance(notes, str):
        errs.append(f"{where}: notes must be a string")
        notes = ""
    if errs:
        return None, errs
    provider = Provider(
        id=pid,
        name=str(data["name"]),
        operator=str(data["operator"]),
        hosts=hosts,
        hosts_from_settings=hosts_from_settings,
        internal=internal,
        tier=str(tier),
        tier_rationale=str(data["tier_rationale"]),
        tier_reviewer=str(data["tier_reviewer"]),
        tier_date=str(data["tier_date"]),
        flags=flags,
        personal_data_review=review,
        reliability=reliability,
        http_profile=profile,
        quota=quota,
        error_markers=markers,
        keys=keys,
        sources=sources,
        origin=origin,
        notes=notes,
        extra={k: v for k, v in data.items() if str(k).startswith("x_")},
    )
    violations = profile_violations(provider)
    if violations:
        return None, [f"{where}: {v}" for v in violations]
    return provider, []


# ---------------------------------------------------------------------------------- registry


class ProviderRegistry:
    """Merged view of every provider fragment. Treat instances as immutable snapshots.

    Lookups: ``get(pid)``, ``source('pid.sid')``, ``provider_for_host(host)`` (exact host first, then the
    longest '*.suffix' wildcard matching a strict subdomain), ``providers()``, ``sources()``, ``keys()``
    and ``hosts_for(pid, settings)``. ``errors`` lists every problem found while loading.
    """

    def __init__(self, providers: Iterable[Provider] = (), errors: Iterable[str] = ()) -> None:
        self._providers: dict[str, Provider] = {}
        self._exact: dict[str, str] = {}
        self._wild: dict[str, str] = {}
        self._sources: dict[str, Source] = {}
        self._keys: dict[str, KeySpec] = {}
        self.errors: list[str] = list(errors)
        for provider in providers:
            self._index(provider)

    # -- construction (builders mutate a private instance; published instances are never mutated) --
    def _index(self, provider: Provider) -> None:
        self._providers[provider.id] = provider
        for host in provider.hosts:
            self._exact.setdefault(host, provider.id)
            if host.startswith("*."):
                self._wild.setdefault(host[2:], provider.id)
        for src in provider.sources.values():
            self._sources[src.id] = src
        for name, spec in provider.keys.items():
            self._keys.setdefault(name, spec)

    def _unindex(self, pid: str) -> None:
        provider = self._providers.pop(pid, None)
        if provider is None:
            return
        for host in provider.hosts:
            if self._exact.get(host) == pid:
                del self._exact[host]
            if host.startswith("*.") and self._wild.get(host[2:]) == pid:
                del self._wild[host[2:]]
        for src in provider.sources.values():
            if self._sources.get(src.id) is src:
                del self._sources[src.id]
        for name, spec in provider.keys.items():
            if self._keys.get(name) is spec:
                del self._keys[name]

    def _copy(self) -> ProviderRegistry:
        clone = ProviderRegistry((), self.errors)
        clone._providers = dict(self._providers)
        clone._exact = dict(self._exact)
        clone._wild = dict(self._wild)
        clone._sources = dict(self._sources)
        clone._keys = dict(self._keys)
        return clone

    def conflicts(self, provider: Provider, *, replacing: str | None = None) -> list[str]:
        """Cross-provider problems adding ``provider`` would create (duplicate id, host or key name)."""
        out: list[str] = []
        if provider.id in self._providers and provider.id != replacing:
            out.append(f"duplicate provider id {provider.id!r} (already defined in {self._providers[provider.id].origin})")
        for host in provider.hosts:
            owner = self._exact.get(host)
            if owner is not None and owner != provider.id and owner != replacing:
                out.append(f"host {host!r} is already owned by provider {owner!r} (a host belongs to exactly one provider; extend that provider instead)")
        for name in provider.keys:
            owner_spec = self._keys.get(name)
            if owner_spec is not None and owner_spec.provider not in (provider.id, replacing):
                out.append(f"key {name!r} is already declared by provider {owner_spec.provider!r}")
        return out

    def with_provider(self, provider: Provider, *, replacing: str | None = None) -> ProviderRegistry:
        """A new registry with ``provider`` added (or replacing the provider of id ``replacing``)."""
        clone = self._copy()
        clone._unindex(replacing or provider.id)
        clone._index(provider)
        return clone

    def without(self, pid: str) -> ProviderRegistry:
        """A new registry without provider ``pid``."""
        clone = self._copy()
        clone._unindex(pid)
        return clone

    # -- lookups ------------------------------------------------------------------------------------
    def __contains__(self, pid: object) -> bool:
        return pid in self._providers

    def __len__(self) -> int:
        return len(self._providers)

    def get(self, pid: str) -> Provider | None:
        """Provider by id (None when unregistered)."""
        return self._providers.get(pid)

    def source(self, sid: str) -> Source | None:
        """Source by qualified id 'provider.source' (None when unregistered)."""
        return self._sources.get(sid)

    def provider_for_host(self, host: str) -> Provider | None:
        """Owner of a host: exact match first, then the longest '*.suffix' wildcard (strict subdomains)."""
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return None
        pid = self._exact.get(host)
        if pid is not None:
            return self._providers.get(pid)
        labels = host.split(".")
        for i in range(1, len(labels)):
            pid = self._wild.get(".".join(labels[i:]))
            if pid is not None:
                return self._providers.get(pid)
        return None

    def providers(self) -> list[Provider]:
        """Every provider, sorted by id."""
        return [self._providers[k] for k in sorted(self._providers)]

    def sources(self) -> list[Source]:
        """Every source, sorted by qualified id."""
        return [self._sources[k] for k in sorted(self._sources)]

    def keys(self) -> dict[str, KeySpec]:
        """Every key declared by a provider fragment (name -> KeySpec)."""
        return dict(self._keys)

    def hosts_for(self, pid: str, settings: Any = None) -> tuple[str, ...]:
        """Static hosts of a provider plus the hosts of its ``hosts_from_settings`` URL settings.

        ``settings`` is a Config or a mapping; empty settings and non-https URLs contribute nothing
        (internal platforms are reached over verified TLS only, A12). A configured host that the
        registry assigns to another provider is ignored as well (a host belongs to exactly one
        provider): e.g. ``misp_url`` pointing at a community/third-party instance never turns that
        host into an 'internal' host allowed at TLP:RED (A12) - the module then has no such host
        and its requests are refused (fail closed).
        """
        provider = self._providers.get(pid)
        if provider is None:
            return ()
        hosts = list(provider.hosts)
        getter = getattr(settings, "get", None)
        for name in provider.hosts_from_settings:
            value = getter(name) if callable(getter) else None
            for url in value if isinstance(value, (list, tuple)) else [value]:
                host = _https_host(url)
                if not host or host in hosts:
                    continue
                owner = self.provider_for_host(host)
                if owner is not None and owner.id != pid:
                    continue
                hosts.append(host)
        return tuple(hosts)


def _https_host(url: Any) -> str:
    if not isinstance(url, str) or not url.strip():
        return ""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return ""
    if parts.scheme != "https" or not parts.hostname:
        return ""
    return parts.hostname.lower().rstrip(".")


class _Builder:
    """Accumulates providers with cross-checks, then applies extension fragments."""

    def __init__(self, base: ProviderRegistry | None = None) -> None:
        # a private working copy, mutated in place (linear in the number of fragments)
        self.reg = base._copy() if base is not None else ProviderRegistry()
        self.reg.errors = []
        self.errors: list[str] = []

    def add_provider(self, data: Any, origin: str, *, stem: str | None = None, require_schema: bool = False) -> tuple[Provider | None, list[str]]:
        try:
            provider, errs = _parse_provider(data, origin, stem=stem, require_schema=require_schema)
        except Exception as exc:  # never raised at load time: a malformed fragment is an error entry
            return None, [f"{origin}: provider fragment could not be validated ({type(exc).__name__}: {exc})"]
        if provider is None:
            return None, errs
        errs = [f"{origin}: provider {provider.id!r}: {c}" for c in self.reg.conflicts(provider)]
        if errs:
            return None, errs
        self.reg._index(provider)
        return provider, []

    def apply_extension(self, data: Any, origin: str, *, stem: str | None = None) -> tuple[Provider | None, list[str]]:
        try:
            return self._apply_extension(data, origin, stem=stem)
        except Exception as exc:  # never raised at load time: a malformed fragment is an error entry
            return None, [f"{origin}: extension fragment could not be validated ({type(exc).__name__}: {exc})"]

    def _apply_extension(self, data: Any, origin: str, *, stem: str | None = None) -> tuple[Provider | None, list[str]]:
        if not isinstance(data, Mapping):
            return None, [f"{origin}: an extension must be a JSON object"]
        errs: list[str] = []
        target = data.get("extends")
        where = f"{origin}: extension of {target!r}"
        if data.get("schema") != SCHEMA_EXTENSION:
            errs.append(f"{where}: schema must be {SCHEMA_EXTENSION!r}")
        bad = _unknown_fields(data, _EXTENSION_FIELDS)
        if bad:
            errs.append(f"{where}: extension fragments add only hosts, sources and error_markers (unknown field(s) {', '.join(bad)})")
        if stem is not None and (not isinstance(target, str) or stem.split("__", 1)[0] != target):
            errs.append(f"{where}: file name must be '<extends>__<suffix>.json'")
        base = self.reg.get(target) if isinstance(target, str) else None
        if base is None:
            errs.append(f"{where}: provider {target!r} is not registered")
            return None, errs
        hosts = _parse_hosts(data.get("hosts", []), where, errs)
        for host in hosts:
            if host in base.hosts:
                errs.append(f"{where}: host {host!r} is already listed by {target!r}")
        sources = _parse_sources(base.id, data.get("sources"), where, errs)
        for sid in sources:
            if sid in base.sources:
                errs.append(f"{where}: source {base.id}.{sid} already exists (extensions only add)")
        markers = _parse_markers(data.get("error_markers"), where, errs)
        known_ids = {m.id for m in base.error_markers}
        for marker in markers:
            if marker.id in known_ids:
                errs.append(f"{where}: error marker {marker.id!r} already exists (extensions only add)")
        if errs:
            return None, errs
        merged = replace(
            base,
            hosts=base.hosts + hosts,
            sources={**base.sources, **sources},
            error_markers=base.error_markers + markers,
        )
        errs = [f"{where}: {c}" for c in self.reg.conflicts(merged, replacing=base.id)]
        errs += [f"{where}: {v}" for v in profile_violations(merged)]
        if errs:
            return None, errs
        self.reg._unindex(base.id)
        self.reg._index(merged)
        return merged, []

    def build(self, extra_errors: Iterable[str] = ()) -> ProviderRegistry:
        built = self.reg._copy()
        built.errors = [*extra_errors, *self.errors]
        return built


def _read_json(path: Path) -> tuple[Any, str]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), ""
    except (OSError, ValueError) as exc:
        return None, f"{path.name}: invalid JSON ({exc})"


def load_dir(directory: str | Path | None = None) -> ProviderRegistry:
    """Build a registry from the fragments of ``directory`` (default: the bundled data dir).

    Does not install it: ``registry()`` keeps serving the bundled fragments. Never raises; problems
    are listed in the returned registry's ``errors``.
    """
    base = Path(directory) if directory is not None else DATA_DIR
    builder = _Builder()
    files = sorted(p for p in base.glob("*.json") if not p.name.startswith(".")) if base.is_dir() else []
    providers_files: list[Path] = []
    extension_files: list[Path] = []
    for path in files:
        if "__" in path.stem and not path.stem.startswith("_set_"):
            extension_files.append(path)
        else:
            providers_files.append(path)
    for path in providers_files:
        data, problem = _read_json(path)
        if problem:
            builder.errors.append(problem)
            continue
        if path.stem.startswith("_set_"):
            if not isinstance(data, Mapping) or data.get("schema") != SCHEMA_SET or not isinstance(data.get("providers"), list):
                builder.errors.append(f"{path.name}: a provider set needs schema {SCHEMA_SET!r} and a 'providers' list")
                continue
            bad = _unknown_fields(data, frozenset({"schema", "providers", "notes"}))
            if bad:
                builder.errors.append(f"{path.name}: unknown field(s) {', '.join(bad)}")
            for idx, item in enumerate(data["providers"]):
                _, errs = builder.add_provider(item, f"{path.name}[{idx}]")
                builder.errors.extend(errs)
            continue
        if isinstance(data, Mapping) and data.get("schema") == SCHEMA_EXTENSION:
            builder.errors.append(f"{path.name}: extension fragments must be named '<provider_id>__<suffix>.json'")
            continue
        _, errs = builder.add_provider(data, path.name, stem=path.stem, require_schema=True)
        builder.errors.extend(errs)
    for path in extension_files:
        data, problem = _read_json(path)
        if problem:
            builder.errors.append(problem)
            continue
        _, errs = builder.apply_extension(data, path.name, stem=path.stem)
        builder.errors.extend(errs)
    return builder.build()


_LOCK = threading.RLock()
_REGISTRY: ProviderRegistry | None = None
#: programmatic fragments (tests, plugins), re-applied by reload(): (fragment, origin)
_PROGRAMMATIC: list[tuple[dict[str, Any], str]] = []


def registry() -> ProviderRegistry:
    """The process-wide registry (bundled fragments + programmatic registrations), loaded lazily."""
    global _REGISTRY
    reg = _REGISTRY
    if reg is not None:
        return reg
    with _LOCK:
        if _REGISTRY is None:
            _REGISTRY = _with_programmatic(load_dir())
        return _REGISTRY


def _with_programmatic(base: ProviderRegistry) -> ProviderRegistry:
    builder = _Builder(base)
    for fragment, origin in _PROGRAMMATIC:
        _, errs = _apply_fragment(builder, fragment, origin)
        builder.errors.extend(errs)
    return builder.build(base.errors)


def _apply_fragment(builder: _Builder, fragment: Mapping[str, Any], origin: str) -> tuple[Provider | None, list[str]]:
    schema = fragment.get("schema", SCHEMA_PROVIDER) if isinstance(fragment, Mapping) else None
    if schema == SCHEMA_EXTENSION:
        return builder.apply_extension(fragment, origin)
    if schema == SCHEMA_PROVIDER:
        return builder.add_provider(fragment, origin)
    return None, [f"{origin}: register() takes a {SCHEMA_PROVIDER!r} or {SCHEMA_EXTENSION!r} fragment (got {schema!r})"]


def reload() -> ProviderRegistry:
    """Re-read the bundled fragments and re-apply programmatic registrations."""
    global _REGISTRY
    with _LOCK:
        _REGISTRY = _with_programmatic(load_dir())
        return _REGISTRY


def register(fragment: Mapping[str, Any], *, origin: str = "programmatic") -> Provider:
    """Validate and add a provider (or provider-ext) fragment at runtime. Raises ValueError when invalid.

    The ``schema`` key may be omitted for a provider fragment. Registrations survive ``reload()`` until
    ``unregister()``.
    """
    global _REGISTRY
    with _LOCK:
        current = registry()
        builder = _Builder(current)
        provider, errs = _apply_fragment(builder, fragment, origin)
        if errs or provider is None:
            raise ValueError("; ".join(errs) or f"{origin}: invalid provider fragment")
        # a private deep copy: later changes to the caller's dict never alter what reload() re-applies
        _PROGRAMMATIC.append((copy.deepcopy(dict(fragment)), origin))
        _REGISTRY = builder.build(current.errors)
        return provider


def unregister(pid: str) -> bool:
    """Remove a provider (and the programmatic fragments that define or extend it). True if it existed.

    A bundled provider removed this way comes back with ``reload()``.
    """
    global _REGISTRY
    with _LOCK:
        current = registry()
        _PROGRAMMATIC[:] = [(f, o) for f, o in _PROGRAMMATIC if f.get("id") != pid and f.get("extends") != pid]
        existed = pid in current
        if existed:
            _REGISTRY = current.without(pid)
        return existed


def snapshot() -> tuple[ProviderRegistry | None, list[tuple[dict[str, Any], str]]]:
    """Opaque state of the process-wide registry (for test fixtures such as ``clean_registry``)."""
    with _LOCK:
        return _REGISTRY, list(_PROGRAMMATIC)


def restore(state: tuple[ProviderRegistry | None, list[tuple[dict[str, Any], str]]]) -> None:
    """Restore a state taken with ``snapshot()`` (drops later programmatic registrations)."""
    global _REGISTRY
    with _LOCK:
        _REGISTRY, programmatic = state
        _PROGRAMMATIC[:] = programmatic
