"""Policy as code: the single gate that decides whether a module may run on an entity (P327).

Every execution path - ``Engine.select`` (scan, shell, extract --scan, batch -i, watch), ``App``'s
single runs (``v3lum run``) and doctor health checks - builds ONE :class:`PolicyContext` with
:func:`make_context` and asks :func:`decide` for every (module, entity) candidate. No other code
makes licence, TLP, tier, privacy, own-asset, opsec, scope or egress decisions. LIGHT/ACTIVE
contact passes a second gate, :func:`contact_guard`, evaluated by the engine after the entity's
passive results are absorbed (P376 two-phase scheduling).

``decide()`` evaluates the rules in this order; the first failure wins and its rule id is quoted in
the readable reason (``... [POL-04]``):

=========  =================================================================================
POL-01     selection (A3): accepted type, watch_only outside ``v3lum watch``, preset quick and
           default_enabled, demotion (explicit ``-M`` still runs demoted/opt-in modules)
POL-02     metadata validity: a registered contract-v2 module without a load error
POL-03     offline: network modules are UNAVAILABLE 'offline' with ``--offline``
POL-04     licence (A1/P377): per source under the licence profile; aggregators get the passing
           sources in ``Decision.allowed_sources``; none passing -> SKIPPED 'licence' + manual link
POL-05     TLP (A2): publishes_queries never (rule 7); AMBER drops unknown tier and query-reusing
           providers; AMBER+STRICT trusted only; RED none/internal only (+ target contact with
           verified own assets through a non-corporate egress or a recorded override)
POL-06     tier (A8): unknown tier needs ``--allow-unknown`` and receives IOC values only
POL-07     privacy (A4/A5/A7/A8/AR16): secret values never leave the machine, run_on seeds, purpose
           for personal identifiers, providers without a personal-data review, per-person breach
           checks (run_on own_assets)
POL-08     own assets (A11): run_on own_assets_only needs a txt_verified/attested org entry
POL-09     opsec: never above the scan mode (no escalation)
POL-10     rules of engagement (A7): ACTIVE needs a real authorization reference and a matching
           scope file; LIGHT only on analyst-typed seeds; pivots never inherit scope
POL-11     egress country (A9): requires_egress vs setting egress_country + manual link
POL-12     keys and configuration: missing requires_keys -> NEEDS_KEY + manual link
POL-13     packages -> UNAVAILABLE 'package'
POL-14     datasets: a large dataset missing during a scan (or any missing one offline)
POL-15     quota (P334): exhausted provider budget or legacy daily_quota -> QUOTA + manual link
POL-16     circuit: a module host short-circuited in this run -> BLOCKED 'circuit'
GUARD-02   recipient tokens (A7 BR15): never fetched unless the exact URL was confirmed
GUARD-01   hostile host (A13/P376): LIGHT/ACTIVE contact with flagged or hostile-shaped hosts
           only through proxy_light/proxy_active or a recorded ``--egress-override``
=========  =================================================================================

:data:`RULES` is the machine-readable table (source of docs/RULES.md, AR22); every decision uses
only the canonical A3 reason codes of ``v3lum.core.models.REASON_CODES``.
"""

from __future__ import annotations

import base64
import binascii
import copy
import dataclasses
import datetime as _dt
import functools
import inspect
import ipaddress
import json
import logging
import re
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, unquote, urlsplit

from v3lum.core import entities as _entities
from v3lum.core import licence as _licence
from v3lum.core import providers as _providers
from v3lum.core import tlp as _tlp
from v3lum.core.entities import IOC_TYPES, PERSONAL_TYPES, SECRET_TYPES, Entity, EntityType
from v3lum.core.health import HealthState
from v3lum.core.licence import LicenceError, LicenceState
from v3lum.core.models import Opsec, Status, valid_reason

if TYPE_CHECKING:  # pragma: no cover
    from v3lum.core.context import RunInfo

log = logging.getLogger("v3lum.policy")

__all__ = [
    "AUTH_REF_PLACEHOLDERS",
    "AUTH_REF_RE",
    "Decision",
    "HOSTILE_ATTRIBUTES",
    "HOSTILE_TAGS",
    "LISTING_TAGS",
    "PATHS",
    "SHAPE_TAGS",
    "POLICY_VERSION",
    "PolicyContext",
    "PolicyRule",
    "RULES",
    "authorization_problem",
    "contact_guard",
    "decide",
    "describe_policy",
    "effective_default_set",
    "entity_tlp",
    "hostile_reasons",
    "lure_words",
    "make_context",
    "recipient_token",
    "rule",
    "rules_markdown",
    "shared_health",
    "valid_authorization_ref",
]

#: Version of the rule set: council decision ids and date.
POLICY_VERSION = "council-1/2026-11-26"

#: Execution paths that build a PolicyContext (AR15).
PATHS: tuple[str, ...] = ("scan", "run", "shell", "extract", "batch", "watch", "doctor")
#: Paths that run Engine.investigate (large datasets are never downloaded there, AR10).
SCAN_PATHS: frozenset[str] = frozenset({"scan", "shell", "extract", "batch", "watch"})

#: A7: --authorized REF syntax and the placeholders it may not be.
AUTH_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{2,63}$")
AUTH_REF_PLACEHOLDERS: frozenset[str] = frozenset({
    "confirmed", "yes", "ok", "none", "n/a", "test", "tbd", "todo", "xxx", "null", "true", "authorized",
})

#: GUARD-01: tags that make an entity hostile (on the node or on one of its findings); the boolean
#: attributes ``malicious``/``suspicious`` count the same way.
HOSTILE_TAGS: frozenset[str] = frozenset({
    "malicious", "phishing", "c2", "suspicious", "phishing_kit_exfil", "crypto_scam", "fraud", "hijacked_netblock",
})
#: GUARD-01: tags of reputation findings that mean 'listed by a consensus source' (a finding that is
#: only an ad/tracking listing - tag ``ads_tracking`` - does not count).
LISTING_TAGS: frozenset[str] = frozenset({"malware", "botnet", "spam", "scanner", "blocklisted"})
#: GUARD-01: tags that make an entity hostile-shaped (typosquat and brand-abuse modules).
SHAPE_TAGS: frozenset[str] = frozenset({"typosquat", "brand_abuse"})
#: GUARD-01: boolean attributes that flag an entity hostile.
HOSTILE_ATTRIBUTES: tuple[str, ...] = ("malicious", "suspicious")
#: listings that are no threat signal (ad/tracking blocklists: vocab 'ads_tracking').
_WEAK_LISTING_TAGS: frozenset[str] = frozenset({"ads_tracking"})
_WEAK_LISTING_CATEGORIES: frozenset[str] = frozenset({"ads_tracking"})
#: URLs on a big legitimate platform do not make the platform host hostile.
_LEGIT_PLATFORM_TAGS: frozenset[str] = frozenset({"hosted_on_legit_platform", "abused_legit_service"})
#: GUARD-01: case-DB sighting verdicts that count as hostile.
HOSTILE_VERDICTS: frozenset[str] = frozenset({"malicious", "phishing", "c2", "suspicious", "compromised", "positive", "true_positive"})
#: GUARD-01: consensus correlation rules (CR27 'multi_source_malicious').
CONSENSUS_RULES: frozenset[str] = frozenset({"multi_source_malicious", "cr27"})
#: GUARD-01: inputs whose extracted URLs/domains are hostile-shaped.
TEXT_TYPES: frozenset[EntityType] = frozenset({EntityType.TEXT, EntityType.FILE, EntityType.EMAIL_HEADERS})
#: GUARD-01: domains registered at most this many days ago are hostile-shaped.
YOUNG_DOMAIN_DAYS = 30
#: GUARD-02: an opaque path/query token of at least this many characters marks a recipient URL.
RECIPIENT_TOKEN_MIN = 16
#: Graph relations followed from an entity to the hosts a contact actually reaches.
_CONTACT_RELATIONS = ("redirects_to", "url_host", "cname_to", "resolves_to")
#: Providers that only ever receive DNS names (never a personal identifier itself).
DNS_ONLY_PROVIDERS: frozenset[str] = frozenset({"core_doh"})
#: Lure-word lists (P376 cond 7): ``v3lum/data/brand_lures*.json`` when present.
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
LURE_GLOB = "brand_lures*.json"

_TLP_NAMES = {t: t.label for t in _tlp.TLP}


# --------------------------------------------------------------------------------------
# Decision, rules, context
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    """The verdict of :func:`decide` / :func:`contact_guard` for one (module, entity).

    ``status``/``reason_code`` are canonical A3 values (OK and '' when allowed); ``reason`` is the
    readable text with the rule id (e.g. 'skipped: noncommercial terms (licence profile corporate)
    [POL-04]'); ``rule_id`` the failing rule ('' when allowed; 'GUARD-01' on a guard that yielded to
    an egress profile or override). ``allowed_sources``: the registry sources the module may query
    (None = no restriction: the module declares no source, or the licence step was not reached);
    ``blocked_sources``: source id -> why it is blocked (coverage rows with reason_code 'licence').
    ``emit_manual_link``: the engine emits the module's manual pivot link ('automation skipped:
    <reason_code>'). ``licence_basis``: source id -> 'open' | 'business_plan:<key>' |
    'allow:<legal_ref>' | 'research:<legal_ref>' for the sources the run may use (case
    'licence_used', report licence banner).
    """

    allowed: bool
    status: Status = Status.OK
    reason_code: str = ""
    reason: str = ""
    rule_id: str = ""
    allowed_sources: frozenset[str] | None = None
    emit_manual_link: bool = False
    licence_basis: dict[str, str] = field(default_factory=dict, hash=False)
    blocked_sources: dict[str, str] = field(default_factory=dict, hash=False)

    def __post_init__(self) -> None:
        status = Status(self.status)
        object.__setattr__(self, "status", status)
        if self.allowed:
            if status is not Status.OK or self.reason_code:
                raise ValueError("an allowed Decision has status OK and no reason_code")
        elif status in (Status.OK, Status.EMPTY) or not valid_reason(status, self.reason_code):
            raise ValueError(f"{self.reason_code!r} is not a canonical A3 reason code for status {status.value!r}")
        if self.allowed_sources is not None and not isinstance(self.allowed_sources, frozenset):
            object.__setattr__(self, "allowed_sources", frozenset(self.allowed_sources))
        object.__setattr__(self, "licence_basis", dict(self.licence_basis or {}))
        object.__setattr__(self, "blocked_sources", dict(self.blocked_sources or {}))

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe view (coverage rows, ``v3lum modules --json``)."""
        return {
            "allowed": self.allowed,
            "status": self.status.value,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "allowed_sources": None if self.allowed_sources is None else sorted(self.allowed_sources),
            "blocked_sources": dict(sorted(self.blocked_sources.items())),
            "emit_manual_link": self.emit_manual_link,
            "licence_basis": dict(sorted(self.licence_basis.items())),
        }


@dataclass(frozen=True)
class PolicyRule:
    """One row of the policy table: id, text, council decisions and the enforcing test node id."""

    id: str
    text: str
    decisions: tuple[str, ...]
    test: str


RULES: tuple[PolicyRule, ...] = (
    PolicyRule("POL-01", "Selection (A3): a module runs only on the entity types it accepts; modules tagged watch_only run only inside `v3lum watch` (not_applicable); with the preset quick only default_enabled modules run unless selected with -M (not_default); a module demoted by measured health leaves the default set but still runs with -M (demoted).", ("A3", "P327"), "tests/test_policy.py::test_pol01_selection"),
    PolicyRule("POL-02", "Metadata validity: only registered contract-v2 modules whose file loaded without errors run (policy).", ("P327", "P332"), "tests/test_policy.py::test_pol02_metadata_validity"),
    PolicyRule("POL-03", "Offline: with --offline, modules whose disclosure is third_party, internal or target are unavailable (offline).", ("P327",), "tests/test_policy.py::test_pol03_offline"),
    PolicyRule("POL-04", "Licence profile (A1): corporate runs open sources, key-terms sources with a business plan (free_plan_business_use or key_plans), noncommercial/license sources only with an active licence_allow entry; research additionally covers the noncommercial/license sources named by a recorded research basis; unknown terms never run. Aggregators query only the passing sources; a module without one is skipped (licence) with its manual link and is never replaced by a LIGHT/ACTIVE alternative.", ("A1", "P377"), "tests/test_policy.py::test_pol04_licence"),
    PolicyRule("POL-05", "TLP (A2): providers that publish lookups never receive values (policy, rule 7); CLEAR/GREEN allow every disclosure class; AMBER excludes unknown-tier and query-reusing providers; AMBER+STRICT allows trusted providers only; RED allows disclosure none/internal only, plus target contact with verified own assets that are not third-party hosted through proxy_light/proxy_active or a recorded --egress-override (tlp).", ("A2", "P332"), "tests/test_policy.py::test_pol05_tlp"),
    PolicyRule("POL-06", "Tier (A8): unknown-tier providers need the per-run --allow-unknown flag and receive IOC_TYPES values only - never personal identifiers, a CNPJ or other non-IOC values (tier).", ("A8",), "tests/test_policy.py::test_pol06_tier"),
    PolicyRule("POL-07", "Privacy (A4/A5/A7/A8/AR16): secret values (JWTs, tokens, keys, card numbers) never reach a provider, an internal platform or the target - found credentials are never used (policy); run_on seeds runs only on confirmed analyst-typed seeds; personal identifiers need a recorded --purpose; a provider without a personal-data review receives them only when the module is selected explicitly; per-person breach checks (run_on own_assets) run on verified org-domain addresses, or on typed seeds with --breach-scope all and a purpose, never on pivots or text-extracted addresses (privacy).", ("A4", "A5", "A7", "A8", "AR16"), "tests/test_policy.py::test_pol07_privacy"),
    PolicyRule("POL-08", "Own assets (A11): run_on own_assets_only modules need a txt_verified or attested org-profile entry (own_asset).", ("A11", "P378"), "tests/test_policy.py::test_pol08_own_asset"),
    PolicyRule("POL-09", "Opsec: a module never runs above the scan mode; there is no escalation (opsec).", ("A7", "AR15"), "tests/test_policy.py::test_pol09_opsec"),
    PolicyRule("POL-10", "Rules of engagement (A7): ACTIVE needs a real --authorized REF (authorization) and a scope file bound to it, inside its window, that contains the target (scope); LIGHT runs only on analyst-typed seeds, and without --mode light only on verified own seeds when light_for_own_assets is set; pivots never inherit scope (scope).", ("A7",), "tests/test_policy.py::test_pol10_rules_of_engagement"),
    PolicyRule("POL-11", "Egress country (A9): sources that need a national egress run only when setting egress_country declares it; otherwise their manual link is emitted (egress_country).", ("A9",), "tests/test_policy.py::test_pol11_egress_country"),
    PolicyRule("POL-12", "Keys and configuration: missing required keys give needs_key with the manual link; an internal platform without its URL setting and a provider that asks for an identifying contact without one are skipped (config).", ("A3", "A12", "P327"), "tests/test_policy.py::test_pol12_keys"),
    PolicyRule("POL-13", "Packages: a missing optional package makes the module unavailable (package).", ("P327",), "tests/test_policy.py::test_pol13_packages"),
    PolicyRule("POL-14", "Datasets (A6/AR10): a large dataset that was never downloaded is unavailable during a scan, and any missing dataset is unavailable offline (dataset).", ("A6", "AR10"), "tests/test_policy.py::test_pol14_datasets"),
    PolicyRule("POL-15", "Quota (P334): an exhausted provider budget, or the legacy module daily_quota for providers without a quota block, gives quota with the manual link; never another key, account or egress.", ("P334", "A3"), "tests/test_policy.py::test_pol15_quota"),
    PolicyRule("POL-16", "Circuit (A9): a module whose host was short-circuited in this run after a challenge or geo-block is blocked (circuit) with its manual link.", ("A9",), "tests/test_policy.py::test_pol16_circuit"),
    PolicyRule("GUARD-01", "Hostile-host guard (A13/P376): LIGHT/ACTIVE contact with an entity (or its host, redirect target or resolved address) tagged or flagged malicious/phishing/c2/suspicious (or phishing-kit exfiltration, crypto scam, fraud, hijacked netblock), hosting a URL so tagged, seen with such a verdict in case-DB sightings, listed by a consensus source (blocklists other than ad/tracking lists), or hostile-shaped (org-brand lookalike or typosquat/brand-abuse tag, domain <= 30 days old, lure-word domain, extracted from text/file/e-mail input) is blocked (hostile_host: needs non-corporate egress) unless a usable proxy_light/proxy_active is configured for its opsec or --egress-override is recorded; the refusal names passive alternatives and becomes a manual pivot.", ("A13", "P376"), "tests/test_policy_guard.py::test_guard01_hostile_host"),
    PolicyRule("GUARD-02", "Recipient tokens (A7 BR15/P376 cond 10): URLs carrying an e-mail address (plain, URL-encoded or base64) or an opaque token of >= 16 characters in path/query, or tagged recipient_token in the case, are never fetched unless the exact URL is confirmed with --confirm-url; an egress profile or override does not lift it, and a confirmed URL still passes GUARD-01; decide() applies the same refusal to PASSIVE modules whose provider fetches the target (unless tagged cached_only) (policy).", ("A7", "P376"), "tests/test_policy_guard.py::test_guard02_recipient_token"),
)
_RULES_BY_ID = {r.id: r for r in RULES}


def rule(rule_id: str) -> PolicyRule:
    """The PolicyRule with this id (KeyError otherwise)."""
    return _RULES_BY_ID[rule_id]


def rules_markdown() -> str:
    """docs/RULES.md body generated from :data:`RULES` (AR22): id, rule, council decisions, test."""
    lines = [
        f"<!-- generated from v3lum.core.policy.RULES ({POLICY_VERSION}); do not edit by hand -->",
        "",
        "| id | rule | decisions | enforcing test |",
        "|---|---|---|---|",
    ]
    for r in RULES:
        text = r.text.replace("|", "\\|")
        lines.append(f"| {r.id} | {text} | {', '.join(r.decisions)} | `{r.test}` |")
    return "\n".join(lines) + "\n"


class _LiveHosts(AbstractSet):
    """A live read-only set over a ``() -> iterable of hosts`` callable (the HTTP client's circuit)."""

    def __init__(self, source: Callable[[], Iterable[str]]) -> None:
        self._source = source

    def _current(self) -> frozenset[str]:
        try:
            return frozenset(str(h).lower() for h in self._source() or ())
        except Exception:  # noqa: BLE001 - a broken probe never blocks or unblocks anything
            return frozenset()

    def __contains__(self, host: object) -> bool:
        return isinstance(host, str) and host.lower() in self._current()

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self._current()))

    def __len__(self) -> int:
        return len(self._current())

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"_LiveHosts({sorted(self._current())!r})"


def _default_options() -> Any:
    from v3lum.core.context import ScanOptions  # lazy: context imports the HTTP stack

    return ScanOptions()


@dataclass
class PolicyContext:
    """Everything :func:`decide` needs, built once per run by :func:`make_context`.

    ``options`` (ScanOptions), ``config`` (Config), ``providers`` (ProviderRegistry), ``org``
    (OrgProfile), ``licence`` (LicenceState), ``keys`` (configured key names), ``now`` (aware UTC),
    ``quota`` (QuotaBook or None), ``health`` (HealthState or None), ``offline``, ``explicit``
    (module names selected with -M), ``circuit`` (hosts short-circuited in this run; live view of
    the HTTP client), ``graph`` (the case graph, for the guard), ``sightings`` (callable(entity) ->
    SightingsSummary | None, from ``runtime.meta['sightings_lookup']``), ``path`` (one of
    :data:`PATHS`), ``licence_profile`` (resolved: 'corporate' | 'research'), ``clock`` (live time
    for scope windows; None = ``now``) and ``notes`` (load problems worth one line each).
    """

    options: Any = None
    config: Any = None
    providers: Any = None
    org: Any = None
    licence: LicenceState = field(default_factory=LicenceState.empty)
    keys: frozenset[str] = frozenset()
    now: _dt.datetime = field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc))
    quota: Any = None
    health: HealthState | None = None
    offline: bool = False
    explicit: frozenset[str] = frozenset()
    circuit: AbstractSet[str] = frozenset()
    graph: Any = None
    sightings: Callable[..., Any] | None = None
    path: str = "scan"
    licence_profile: str = "corporate"
    clock: Callable[[], _dt.datetime] | None = None
    notes: list[str] = field(default_factory=list)
    _cache: dict[Any, Any] = field(default_factory=dict, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.options is None:
            self.options = _default_options()
        if self.path not in PATHS:
            raise ValueError(f"unknown policy path {self.path!r} (expected one of {', '.join(PATHS)})")
        self.keys = frozenset(self.keys or ())
        self.explicit = frozenset(self.explicit or ())
        if self.licence is None:
            self.licence = LicenceState.empty()
        if self.now.tzinfo is None:
            self.now = self.now.replace(tzinfo=_dt.timezone.utc)

    # ---- accessors --------------------------------------------------------------------------
    @property
    def registry(self) -> Any:
        """The provider registry (the injected one, else the process-wide registry)."""
        return self.providers if self.providers is not None else _providers.registry()

    def setting(self, name: str, default: Any = None) -> Any:
        """A core/module setting from ``config`` (``default`` without config or value)."""
        getter = getattr(self.config, "get", None)
        if not callable(getter):
            return default
        try:
            value = getter(name, default)
        except Exception:  # noqa: BLE001 - a broken config never unlocks anything
            return default
        return default if value is None else value

    def time(self) -> _dt.datetime:
        """Current time for windows (the live clock when given, else ``now``)."""
        if self.clock is not None:
            try:
                value = self.clock()
                if isinstance(value, _dt.datetime):
                    return value if value.tzinfo else value.replace(tzinfo=_dt.timezone.utc)
            except Exception:  # noqa: BLE001
                pass
        return self.now

    def option(self, name: str, default: Any = None) -> Any:
        value = getattr(self.options, name, default)
        return default if value is None else value


_HEALTH_STATES: dict[str, HealthState] = {}
_HEALTH_LOCK = threading.Lock()


def shared_health() -> HealthState:
    """The process-wide HealthState of the current V3LUM home (``~/.v3lum/health.json``): ONE
    instance per state file for the whole process, shared by the engine's run records (worker
    threads), the policy gate and doctor. When another writer (another process, or another
    instance on the same file) changed the file, the shared instance re-reads it in place
    (``HealthState.refresh``), so no thread is left writing a stale copy over newer records."""
    path = HealthState(autosave=True).path
    key = str(path)
    with _HEALTH_LOCK:
        state = _HEALTH_STATES.get(key)
        if state is None:
            state = HealthState.load(path)
            _HEALTH_STATES[key] = state
            return state
    state.refresh()
    return state


_shared_health = shared_health  # backwards-compatible private alias


def _runtime_health(runtime: Any) -> HealthState | None:
    """The runtime's health state when it offers one (``Runtime.health``), else the shared one."""
    try:
        health = getattr(runtime, "health", None)
    except Exception:  # noqa: BLE001 - a broken accessor never blocks a scan
        health = None
    if health is not None and callable(getattr(health, "demotion_reasons", None)):
        return health
    try:
        return shared_health()
    except Exception as exc:  # noqa: BLE001
        log.warning("module health state unavailable: %s", type(exc).__name__)
        return None


def make_context(runtime: Any, options: Any = None, *, explicit: Iterable[str] = (), graph: Any = None, path: str = "scan") -> PolicyContext:
    """Build the PolicyContext of one run - the ONLY way callers build it (AR15).

    ``explicit``: module names selected explicitly (``-M``; ``options.include`` is added); ``graph``:
    the case graph for :func:`contact_guard`; ``path``: 'scan' | 'run' | 'shell' | 'extract' |
    'batch' | 'watch' | 'doctor'. A research profile without a recorded basis falls back to the
    corporate profile here (fail closed; the CLI refuses it first) with a note.
    """
    if path not in PATHS:
        raise ValueError(f"unknown policy path {path!r} (expected one of {', '.join(PATHS)})")
    options = options if options is not None else _default_options()
    config = getattr(runtime, "config", None)
    now_fn = getattr(runtime, "now", None)
    now = now_fn() if callable(now_fn) else _dt.datetime.now(_dt.timezone.utc)
    notes: list[str] = []
    licence = LicenceState.load(config=config)
    notes += [f"licence_allow: {w}" for w in licence.warnings]
    notes += [f"licence_allow: {e}" for e in licence.errors]
    try:
        profile = _licence.resolve_profile(config, options, state=licence, now=now)
    except LicenceError as exc:
        profile = "corporate"
        notes.append(f"{exc}: running under the corporate licence profile")
    keys: frozenset[str] = frozenset()
    keys_fn = getattr(config, "keys", None)
    if callable(keys_fn):
        try:
            keys = frozenset(name for name, value in (keys_fn() or {}).items() if value)
        except Exception:  # noqa: BLE001 - a broken key store: no keys
            keys = frozenset()
    try:
        quota = getattr(runtime, "quota", None)
    except Exception:  # noqa: BLE001 - quota DB unavailable: the runtime still enforces budgets
        quota = None
    health = _runtime_health(runtime)
    notes += [f"health: {e}" for e in (getattr(health, "errors", None) or ())]
    http = getattr(runtime, "http", None)
    circuit_fn = getattr(http, "circuit_hosts", None)
    circuit: AbstractSet[str] = _LiveHosts(circuit_fn) if callable(circuit_fn) else frozenset()
    meta = getattr(runtime, "meta", None)
    lookup = meta.get("sightings_lookup") if isinstance(meta, Mapping) else None
    explicit_all = frozenset(explicit or ()) | frozenset(getattr(options, "include", None) or ())
    # an injected registry is kept; otherwise the context reads the live process-wide registry
    injected = getattr(runtime, "_providers", None) if hasattr(runtime, "_providers") else getattr(runtime, "providers", None)
    return PolicyContext(
        options=options,
        config=config,
        providers=injected,
        org=getattr(runtime, "org", None),
        licence=licence,
        keys=keys,
        now=now,
        quota=quota,
        health=health,
        offline=bool(getattr(options, "offline", False) or getattr(runtime, "offline", False)),
        explicit=explicit_all,
        circuit=circuit,
        graph=graph,
        sightings=lookup if callable(lookup) else None,
        path=path,
        licence_profile=profile,
        clock=now_fn if callable(now_fn) else None,
        notes=notes,
    )


# --------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------


def _deny(rule_id: str, status: Status, code: str, text: str, **kw: Any) -> Decision:
    return Decision(False, status, code, f"{text} [{rule_id}]", rule_id, **kw)


def _skip(rule_id: str, code: str, text: str, **kw: Any) -> Decision:
    return _deny(rule_id, Status.SKIPPED, code, text, **kw)


def _name(cls: Any) -> str:
    return str(getattr(cls, "name", "") or getattr(cls, "__name__", "?"))


def _opsec(cls: Any) -> Opsec:
    try:
        return Opsec.parse(getattr(cls, "opsec", Opsec.PASSIVE))
    except (KeyError, ValueError):
        return Opsec.ACTIVE  # unreadable: the most restricted


def _mode(pctx: PolicyContext) -> Opsec:
    try:
        return Opsec.parse(pctx.option("mode", Opsec.PASSIVE))
    except (KeyError, ValueError):
        return Opsec.PASSIVE


def _run_attr(run: Any, name: str, default: Any = None) -> Any:
    if run is None:
        return default
    if isinstance(run, Mapping):
        return run.get(name, default)
    return getattr(run, name, default)


def _parent_type(key: Any) -> EntityType | None:
    text = str(key or "")
    etype, sep, _ = text.partition(":")
    if not sep:
        return None
    try:
        return EntityType.parse(etype)
    except ValueError:
        return None


def _text_derived(run: Any) -> bool:
    """Does the run's provenance pass through a text/file/e-mail input?"""
    for step in _run_attr(run, "provenance", ()) or ():
        parent = step[0] if isinstance(step, (list, tuple)) and step else step
        if _parent_type(parent) in TEXT_TYPES:
            return True
    return False


def _typed_seed(entity: Entity, pctx: PolicyContext, run: Any) -> bool:
    """An analyst-typed, confirmed seed (never a pivot, a text-extracted or an unconfirmed value)."""
    if not _run_attr(run, "is_seed", False) or _text_derived(run):
        return False
    unconfirmed = pctx.option("unconfirmed_seeds", ()) or ()
    return entity.key not in unconfirmed


def entity_tlp(entity: Entity, pctx: PolicyContext, run: Any = None) -> _tlp.TLP:
    """TLP of the entity in this run: run.tlp, else the per-seed TLP, else options.tlp (default
    AMBER); an unreadable value counts as RED (fail closed). In a LIGHT/ACTIVE case (``--mode light``
    or ``active``) it is at least AMBER (A2: engagement cases are never below TLP:AMBER, whoever
    built the RunInfo)."""
    raw = _run_attr(run, "tlp", "") or ""
    if not raw:
        seed_tlp = pctx.option("seed_tlp", {}) or {}
        raw = seed_tlp.get(entity.key, "") if isinstance(seed_tlp, Mapping) else ""
    if not raw:
        raw = pctx.option("tlp", "") or pctx.setting("tlp", "amber") or "amber"
    try:
        level = _tlp.parse(raw)
    except ValueError:
        return _tlp.TLP.RED
    if level < _tlp.TLP.AMBER and _mode(pctx) >= Opsec.LIGHT:
        return _tlp.TLP.AMBER
    return level


def _org(pctx: PolicyContext) -> Any:
    return pctx.org


def _owns(pctx: PolicyContext, entity: Any) -> Any:
    org = _org(pctx)
    owns = getattr(org, "owns", None)
    if not callable(owns):
        return None
    try:
        return owns(entity)
    except Exception:  # noqa: BLE001 - membership errors never make an asset "own"
        return None


def _org_empty(pctx: PolicyContext) -> bool:
    org = _org(pctx)
    return org is None or bool(getattr(org, "is_empty", True))


def _verified_own(pctx: PolicyContext, entity: Entity) -> tuple[bool, bool]:
    """(verified own asset, third_party_hosted) for target-contact and own-asset rules."""
    own = _owns(pctx, entity)
    return bool(own is not None and getattr(own, "verified", False)), bool(getattr(own, "third_party_hosted", False))


def _host_of(entity: Entity) -> str:
    """Host name / address a contact with the entity reaches ('' for non-network types)."""
    if entity.type is EntityType.URL:
        return _entities.url_host(entity.value) or ""
    if entity.type in (EntityType.DOMAIN, EntityType.ONION, EntityType.IPV4, EntityType.IPV6):
        return entity.value
    if entity.type is EntityType.EMAIL:
        return entity.value.rsplit("@", 1)[-1]
    if entity.type is EntityType.PORT_SERVICE:
        host = entity.value.rsplit(":", 1)[0] if ":" in entity.value else entity.value
        return host.strip("[]")
    return ""


def _benign(entity: Entity) -> bool:
    from v3lum.core.module import BENIGN_VALUES

    return BENIGN_VALUES.get(entity.type) == entity.value


def _receivers(cls: Any, reg: Any) -> list[Any]:
    """Providers that receive the investigated value: the primary provider and the providers of the
    module's non-dataset sources."""
    pids: list[str] = []
    primary = str(getattr(cls, "provider", "") or "")
    if primary:
        pids.append(primary)
    for sid in getattr(cls, "sources", ()) or ():
        src = reg.source(sid) if reg is not None else None
        if src is not None and not getattr(src, "dataset", None) and src.provider not in pids:
            pids.append(src.provider)
    out = []
    for pid in pids:
        prov = reg.get(pid) if reg is not None else None
        if prov is not None:
            out.append(prov)
    return out


def _module_keys(cls: Any) -> tuple[str, ...]:
    return tuple(getattr(cls, "requires_keys", ()) or ()) + tuple(getattr(cls, "optional_keys", ()) or ())


def _plan_keys(cls: Any, pctx: PolicyContext) -> tuple[str, ...]:
    """Keys whose recorded plan may license the module's requests (key-terms, POL-04): its required
    keys (POL-12 refuses the run without them) and the optional keys that are configured - an
    optional key that is not set means keyless requests, which only free_plan_business_use allows."""
    required = tuple(getattr(cls, "requires_keys", ()) or ())
    optional = tuple(k for k in (getattr(cls, "optional_keys", ()) or ()) if k in pctx.keys)
    return required + optional


# --------------------------------------------------------------------------------------
# the rules
# --------------------------------------------------------------------------------------


def _pol01_selection(cls: Any, entity: Entity, pctx: PolicyContext) -> Decision | None:
    name = _name(cls)
    if entity.type not in (getattr(cls, "accepts", ()) or ()):
        return _skip("POL-01", "not_applicable", f"{name} does not accept {entity.type.value} values")
    if "watch_only" in (getattr(cls, "tags", ()) or ()) and pctx.path != "watch":
        return _skip("POL-01", "not_applicable", "runs only inside v3lum watch")
    explicit = name in pctx.explicit
    preset = str(pctx.option("preset", "quick") or "quick").strip().lower()
    deep = preset == "deep" or bool(pctx.option("include_disabled", False))
    if not deep and not getattr(cls, "default_enabled", False) and not explicit:
        return _skip("POL-01", "not_default", f"opt-in source, not in the default set: use --preset deep or -M {name}")
    if pctx.health is not None and not explicit:
        try:
            reasons = pctx.health.demotion_reasons(name)
        except Exception:  # noqa: BLE001 - a broken health file never removes a module
            reasons = []
        if reasons:
            return _skip("POL-01", "demoted", f"demoted from the default set ({'; '.join(reasons)}): run it with -M {name}")
    return None


def _pol02_metadata(cls: Any) -> Decision | None:
    from v3lum.core import module as _module

    name = _name(cls)
    if not (isinstance(cls, type) and issubclass(cls, _module.Module)):
        return _skip("POL-02", "policy", f"{name!r} is not a Module subclass")
    if _module.REGISTRY.get(name) is not cls:
        return _skip("POL-02", "policy", f"{name} is not a registered contract-v2 module (@register)")
    if getattr(cls, "disclosure", "") != "none" and getattr(_module, "_MARK", "__v3lum_set_by_register__") not in cls.__dict__:
        # a network module placed in the registry without @register has no registration lint and no
        # derived provider flags (publishes/reuses_queries, trust tier): evaluating it would fail open
        return _skip("POL-02", "policy", f"{name} bypassed @register (no registration lint, no derived provider attributes)")
    if getattr(cls, "disclosure", "") not in _module.DISCLOSURES or getattr(cls, "terms", "") not in _module.TERMS:
        return _skip("POL-02", "policy", f"{name} has invalid metadata (disclosure/terms)")
    errors = _module.load_errors()
    origin = str(getattr(cls, "__module__", "") or "")
    if origin in errors or f"spec:{name}" in errors:
        return _skip("POL-02", "policy", f"{name}: its module file has a load error")
    return None


def _pol03_offline(cls: Any, pctx: PolicyContext) -> Decision | None:
    if pctx.offline and getattr(cls, "disclosure", "") in ("third_party", "internal", "target"):
        return _deny("POL-03", Status.UNAVAILABLE, "offline", "offline mode: this source needs the network")
    return None


def _licence_eval(cls: Any, pctx: PolicyContext) -> tuple[frozenset[str] | None, dict[str, str], dict[str, str], list[Any]]:
    """(allowed sources | None, basis, blocked reasons, blocked verdicts) - cached per module/profile."""
    sources = tuple(getattr(cls, "sources", ()) or ())
    if not sources:
        return None, {}, {}, []
    key = ("licence", _name(cls), id(cls), pctx.licence_profile)
    cached = pctx._cache.get(key)
    if cached is not None:
        return cached
    reg = pctx.registry
    plan = _licence.key_plan_lookup(pctx.config) if pctx.config is not None else None
    plan_keys = _plan_keys(cls, pctx)
    allowed: set[str] = set()
    basis: dict[str, str] = {}
    blocked: dict[str, str] = {}
    verdicts: list[Any] = []
    for sid in sources:
        src = reg.source(sid) if reg is not None else None
        prov = reg.get(src.provider) if src is not None and reg is not None else None
        verdict = _licence.evaluate_source(
            src, prov, profile=pctx.licence_profile, now=pctx.now, state=pctx.licence, key_plan=plan, keys=plan_keys, source_id=sid,
            module_keys_only=True,
        )
        if verdict.allowed:
            allowed.add(sid)
            basis[sid] = verdict.basis
        else:
            blocked[sid] = verdict.reason
            verdicts.append(verdict)
    result = (frozenset(allowed), basis, blocked, verdicts)
    pctx._cache[key] = result
    return result


def _pol04_licence(cls: Any, pctx: PolicyContext, state: dict[str, Any]) -> Decision | None:
    allowed, basis, blocked, verdicts = _licence_eval(cls, pctx)
    state.update(allowed_sources=allowed, licence_basis=basis, blocked_sources=blocked)
    if allowed is None or allowed:
        return None
    worst = _providers.most_restrictive(v.terms_class for v in verdicts)
    text = next((v.reason for v in verdicts if v.terms_class == worst and v.reason), f"skipped: {worst} terms (licence profile {pctx.licence_profile})")
    return _skip("POL-04", "licence", text, allowed_sources=frozenset(), emit_manual_link=True, blocked_sources=blocked)


def _external_receivers(cls: Any, pctx: PolicyContext) -> list[Any]:
    """Providers outside the organisation that receive the investigated value: for 'third_party'
    modules and for 'target' modules that also query a provider API (the primary provider and the
    providers of the non-dataset sources)."""
    if getattr(cls, "disclosure", "") not in ("third_party", "target"):
        return []
    return [p for p in _receivers(cls, pctx.registry) if not getattr(p, "internal", False)]


def _exposure(cls: Any, pctx: PolicyContext) -> tuple[str, bool, bool, bool]:
    """(tier, reuses_queries, publishes_queries, external) of the providers that receive the value.

    The class's derived attributes (@register) are combined with the live provider registry and the
    stricter value wins: a fragment changed after registration never loosens a gate. ``external``
    is False for none/internal modules and for target modules that query no provider.
    """
    key = ("exposure", _name(cls), id(cls))
    cached = pctx._cache.get(key)
    if cached is not None:
        return cached
    disclosure = getattr(cls, "disclosure", "")
    receivers = _external_receivers(cls, pctx)
    tiers = [str(getattr(p, "tier", "unknown") or "unknown") for p in receivers]
    if disclosure == "third_party":
        tiers.append(str(getattr(cls, "trust_tier", "unknown") or "unknown"))
    flags = [getattr(p, "flags", None) for p in receivers]
    reuses = bool(getattr(cls, "reuses_queries", False)) or any(bool(getattr(f, "reuses_queries", False)) for f in flags)
    publishes = bool(getattr(cls, "publishes_queries", False)) or any(bool(getattr(f, "publishes_queries", False)) for f in flags)
    external = disclosure == "third_party" or bool(receivers)
    result = ((_providers.lowest_tier(tiers) if tiers else "n/a"), reuses, publishes, external)
    pctx._cache[key] = result
    return result


def _module_ceiling(cls: Any, entity: Entity, pctx: PolicyContext) -> tuple[_tlp.TLP | None, str]:
    """(highest TLP the module may receive for this entity, why) - A2/P332 cond 7."""
    disclosure = getattr(cls, "disclosure", "")
    if disclosure in ("none", "internal"):
        return _tlp.TLP.RED, f"disclosure {disclosure}"
    tier, reuses, _publishes, external = _exposure(cls, pctx)
    third: _tlp.TLP | None = None
    third_why = "the provider may reuse submitted values" if reuses else f"{tier}-tier provider"
    if external:
        third = _tlp.max_tlp("third_party", tier, publishes_queries=False, reuses_queries=reuses)
    if disclosure == "target":
        verified, hosted = _verified_own(pctx, entity)
        ceiling = _tlp.max_tlp_for_target(verified, hosted)
        why = "target contact with a verified own asset" if ceiling is _tlp.TLP.RED else (
            "target contact with a third-party-hosted own asset" if verified else "target contact with an asset that is not a verified own asset"
        )
        if third is not None and third < ceiling:
            return third, f"{third_why} (also queried by this target-contact module)"
        return ceiling, why
    return third, third_why


#: proxy URL schemes an egress profile accepts (v3lum.core.net).
_PROXY_SCHEMES = ("http", "https", "socks5", "socks5h", "socks4", "socks4a")


def _tor_ports() -> frozenset[int]:
    try:
        from v3lum.core.net import TOR_PORTS
    except Exception:  # noqa: BLE001 - the connector module unavailable: the usual Tor client ports
        return frozenset({9050, 9150})
    return frozenset(TOR_PORTS)


def _egress_problem(setting: str, value: str) -> str:
    """Why a configured proxy_light/proxy_active value cannot carry contact ('' = usable as far as
    its configuration goes; reachability is checked by the HTTP client, which fails closed)."""
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return f"{setting} is not a valid proxy URL"
    scheme = parts.scheme.lower()
    if scheme not in _PROXY_SCHEMES:
        return f"{setting}: unsupported proxy scheme {scheme or '(none)'!r}"
    if not parts.hostname:
        return f"{setting}: the proxy URL has no host"
    if scheme.startswith("socks") and not port:
        return f"{setting}: a SOCKS proxy URL needs a port"
    if setting == "proxy_active" and scheme.startswith("socks") and port in _tor_ports():
        return f"{setting} points at a Tor SOCKS port: Tor is never an ACTIVE route (A13)"
    return ""


def _egress_state(opsec: Opsec, pctx: PolicyContext) -> tuple[str, str]:
    """(usable egress-profile setting for the opsec or '', why the configured one is unusable or '')."""
    name = "proxy_active" if opsec is Opsec.ACTIVE else "proxy_light"
    value = str(pctx.setting(name, "") or "").strip()
    if not value:
        return "", ""
    problem = _egress_problem(name, value)
    return ("", problem) if problem else (name, "")


def _egress_profile(opsec: Opsec, pctx: PolicyContext) -> str:
    """The configured, usable non-corporate egress profile for the opsec ('' when none)."""
    return _egress_state(opsec, pctx)[0]


def _pol05_tlp(cls: Any, entity: Entity, pctx: PolicyContext, run: Any) -> Decision | None:
    if _exposure(cls, pctx)[2]:
        return _skip("POL-05", "policy", "the provider publishes submitted lookups: it never receives investigated values (rule 7)")
    level = entity_tlp(entity, pctx, run)
    if level <= _tlp.TLP.GREEN:
        return None  # unknown tier is POL-06's (--allow-unknown)
    ceiling, why = _module_ceiling(cls, entity, pctx)
    if ceiling is None or level > ceiling:
        allowed = ceiling.label if ceiling is not None else "no TLP"
        return _skip("POL-05", "tlp", f"{level.label}: {why} receives at most {allowed}")
    if getattr(cls, "disclosure", "") == "target" and level is _tlp.TLP.RED:
        opsec = _opsec(cls)
        profile, problem = _egress_state(opsec, pctx)
        if not profile and not str(pctx.option("egress_override", "") or "").strip():
            setting = "proxy_active" if opsec is Opsec.ACTIVE else "proxy_light"
            tail = f" ({problem})" if problem else ""
            return _skip("POL-05", "tlp", f"TLP:RED target contact needs a non-corporate egress profile ({setting}) or a recorded --egress-override{tail}")
    return None


def _pol06_tier(cls: Any, entity: Entity, pctx: PolicyContext) -> Decision | None:
    if getattr(cls, "disclosure", "") not in ("third_party", "target") or _exposure(cls, pctx)[0] != "unknown":
        return None
    if not pctx.option("allow_unknown", False):
        return _skip("POL-06", "tier", "unknown-tier provider: needs the per-run --allow-unknown flag (TLP:CLEAR/GREEN only)")
    if entity.type not in IOC_TYPES:
        return _skip("POL-06", "tier", f"unknown-tier provider: never receives {entity.type.value} values (IOC types only, A8)")
    return None


def _pol07_privacy(cls: Any, entity: Entity, pctx: PolicyContext, run: Any) -> Decision | None:
    run_on = str(getattr(cls, "run_on", "any") or "any")
    name = _name(cls)
    if entity.type in SECRET_TYPES and getattr(cls, "disclosure", "") != "none":
        # A8: secrets are detect-only; A7: found credentials and keys are never used or validated
        return _skip(
            "POL-07", "policy",
            f"secret value ({entity.type.value}): never sent to a provider, an internal platform or the target - found credentials and keys are never used",
        )
    benign_probe = pctx.path == "doctor" and _benign(entity)
    if run_on == "seeds" and not benign_probe and not _typed_seed(entity, pctx, run):
        return _skip("POL-07", "privacy", "runs only on confirmed analyst-typed seeds (never on pivots or values found in text)")
    if benign_probe:
        return None  # doctor health checks probe reserved example values, not personal data
    if (
        entity.type is EntityType.URL
        and _fetches_target(cls, pctx)
        and "cached_only" not in (getattr(cls, "tags", ()) or ())
        and _token_url(entity, pctx)
        and not _confirmed(entity.value, pctx)
    ):
        # a provider that fetches the target would open the recipient's link for us (P376 cond 10)
        return _skip("GUARD-02", "policy", "URL carries a per-recipient token and the provider fetches the target: re-run with --confirm-url <url>")
    personal = entity.type in PERSONAL_TYPES
    purpose = str(pctx.option("purpose", "") or "").strip()
    if personal and not purpose:
        return _skip("POL-07", "privacy", f"personal identifier ({entity.type.value}): needs a recorded --purpose (LGPD, AR16)")
    disclosure = getattr(cls, "disclosure", "")
    if personal and disclosure in ("third_party", "internal", "target"):
        # a target-contact module that also queries a provider API hands it the value as well
        receivers = _external_receivers(cls, pctx) if disclosure == "target" else _receivers(cls, pctx.registry)
        unreviewed = [p.id for p in receivers if p.id not in DNS_ONLY_PROVIDERS and getattr(p, "personal_data_review", None) is None]
        if unreviewed and name not in pctx.explicit:
            return _skip("POL-07", "privacy", f"provider {', '.join(unreviewed)} has no personal-data review: select the module explicitly (-M {name}) with --purpose")
    if run_on == "own_assets":
        own = _owns(pctx, entity)
        if own is not None and getattr(own, "verified", False):
            return None
        breach_all = str(pctx.option("breach_scope", "own") or "own").strip().lower() == "all"
        if breach_all and purpose and _typed_seed(entity, pctx, run):
            return None
        return _skip("POL-07", "privacy", "breach check skipped: not an org domain")
    return None


def _fetches_target(cls: Any, pctx: PolicyContext) -> bool:
    """Does a provider of the module fetch the target live? (derived flag or live registry)"""
    if getattr(cls, "fetches_target", False):
        return True
    if getattr(cls, "disclosure", "") not in ("third_party", "internal", "target"):
        return False
    return any(bool(getattr(getattr(p, "flags", None), "fetches_target", False)) for p in _receivers(cls, pctx.registry))


def _pol08_own_asset(cls: Any, entity: Entity, pctx: PolicyContext) -> Decision | None:
    if str(getattr(cls, "run_on", "any") or "any") != "own_assets_only":
        return None
    if _org_empty(pctx):
        return _skip("POL-08", "own_asset", "no org profile (v3lum org)")
    own = _owns(pctx, entity)
    if own is not None and getattr(own, "verified", False):
        return None
    return _skip("POL-08", "own_asset", "own-asset-only source: needs a txt_verified or attested org-profile entry (v3lum org verify)")


def _light_own_exception(cls: Any, pctx: PolicyContext) -> bool:
    """light_for_own_assets: LIGHT may pass the opsec gate in PASSIVE mode (POL-10 then checks the seed)."""
    return _opsec(cls) is Opsec.LIGHT and _mode(pctx) is Opsec.PASSIVE and pctx.setting("light_for_own_assets", False) is True


def _pol09_opsec(cls: Any, pctx: PolicyContext) -> Decision | None:
    opsec, mode = _opsec(cls), _mode(pctx)
    if opsec <= mode or _light_own_exception(cls, pctx):
        return None
    hint = "needs --mode light: contacts the target" if opsec is Opsec.LIGHT else "needs --mode active with --authorized REF and --scope FILE"
    return _skip("POL-09", "opsec", f"{opsec.label} module (current mode: {mode.label}): {hint}")


def authorization_problem(ref: Any) -> str:
    """Why ``ref`` is not a valid --authorized reference ('' when it is): A7 syntax, no placeholder."""
    text = str(ref or "").strip()
    if not text:
        return "ACTIVE needs --authorized REF (a real authorization reference, e.g. a ticket id)"
    try:
        from v3lum.core.scope import PLACEHOLDER_REFS as _scope_placeholders
    except ImportError:  # pragma: no cover - the scope module is a sibling package
        _scope_placeholders = frozenset()
    if text.lower() in AUTH_REF_PLACEHOLDERS | frozenset(_scope_placeholders):
        return f"--authorized {text!r} is a placeholder, not an authorization reference"
    if not AUTH_REF_RE.match(text):
        return "--authorized REF must match ^[A-Za-z0-9][A-Za-z0-9._:/#-]{2,63}$"
    return ""


def valid_authorization_ref(ref: Any) -> bool:
    """True for a real --authorized reference (A7 syntax and not a placeholder)."""
    return not authorization_problem(ref)


def _org_terms(pctx: PolicyContext) -> list[str]:
    """The organisation's name and brand keywords (an ROE identity must never name them, A7)."""
    org = _org(pctx)
    terms = [str(getattr(org, "name", "") or "")]
    brand_terms = getattr(org, "brand_terms", None)
    if callable(brand_terms):
        try:
            terms += list(brand_terms())
        except Exception:  # noqa: BLE001
            pass
    return [t for t in terms if t]


def _scope_problems(scope: Any, ref: str, now: _dt.datetime, org_terms: Iterable[str] = ()) -> list[str]:
    validate = getattr(scope, "validate", None)
    if callable(validate):
        try:
            try:
                return [str(p) for p in validate(ref, now, org_terms=tuple(org_terms)) or ()]
            except TypeError:  # a scope object without the org_terms keyword
                return [str(p) for p in validate(ref, now) or ()]
        except Exception as exc:  # noqa: BLE001 - an unreadable scope never authorizes anything
            return [f"scope file could not be validated ({type(exc).__name__})"]
    problems: list[str] = []
    bound = scope.get("authorization_ref") if isinstance(scope, Mapping) else getattr(scope, "authorization_ref", None)
    if str(bound or "") != ref:
        problems.append("the scope file's authorization_ref does not match --authorized")
    expired = getattr(scope, "window_expired", None)
    if callable(expired):
        try:
            if expired(now):
                problems.append("outside the scope window")
        except Exception:  # noqa: BLE001
            problems.append("the scope window could not be checked")
    return problems


def _in_scope(scope: Any, entity: Entity) -> bool:
    """Does the scope contain the target? (fail closed when the scope cannot answer)."""

    def ask(method: str, value: Any) -> bool:
        fn = getattr(scope, method, None)
        if not callable(fn):
            return False
        try:
            return bool(fn(value))
        except Exception:  # noqa: BLE001
            return False

    etype, value = entity.type, entity.value
    if etype is EntityType.URL:
        return ask("matches_url", value)
    if etype in (EntityType.DOMAIN, EntityType.ONION):
        return ask("matches_host", value)
    if etype in (EntityType.IPV4, EntityType.IPV6):
        return ask("matches_ip", value)
    if etype is EntityType.CIDR:
        if callable(getattr(scope, "matches_cidr", None)):
            return ask("matches_cidr", value)
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
        targets = getattr(getattr(scope, "targets", None), "cidrs", None)
        if targets is not None:  # the WP11 Scope: the whole network inside one target, no exclusion in it
            excluded = getattr(getattr(scope, "exclusions", None), "cidrs", None) or ()
            inside = any(t.version == net.version and net.subnet_of(t) for t in targets)
            return inside and not any(x.version == net.version and net.overlaps(x) for x in excluded)
        return ask("matches_ip", str(net.network_address)) and ask("matches_ip", str(net.broadcast_address))
    host = _host_of(entity)
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return ask("matches_host", host)
    return ask("matches_ip", host)


def _pol10_engagement(cls: Any, entity: Entity, pctx: PolicyContext, run: Any) -> Decision | None:
    opsec = _opsec(cls)
    if opsec is Opsec.ACTIVE:
        ref = str(pctx.option("authorization_ref", "") or "").strip()
        problem = authorization_problem(ref)
        if problem:
            return _skip("POL-10", "authorization", problem)
        scope = pctx.option("scope", None)
        if scope is None:
            return _skip("POL-10", "scope", "ACTIVE needs --scope FILE bound to the authorization reference")
        problems = _scope_problems(scope, ref, pctx.time(), _org_terms(pctx))
        if problems:
            return _skip("POL-10", "scope", "scope file refused: " + "; ".join(problems[:3]))
        if not _in_scope(scope, entity):
            return _skip("POL-10", "scope", "target outside the scope file (pivots never inherit scope)")
        return None
    if opsec is Opsec.LIGHT:
        if not _typed_seed(entity, pctx, run):
            return _skip("POL-10", "scope", "LIGHT runs only on analyst-typed seeds (pivots never inherit scope)")
        if _mode(pctx) is Opsec.PASSIVE:
            verified, _hosted = _verified_own(pctx, entity)
            if not verified:
                return _skip("POL-10", "scope", "without --mode light, LIGHT runs only on verified own seeds (light_for_own_assets)")
    return None


def _pol11_egress(cls: Any, pctx: PolicyContext) -> Decision | None:
    required = frozenset(str(c).upper() for c in (getattr(cls, "requires_egress", ()) or ()))
    if not required:
        return None
    current = str(pctx.setting("egress_country", "") or "").strip().upper()
    if current in required:
        return None
    codes = "/".join(sorted(required))
    return _skip("POL-11", "egress_country", f"needs {codes} egress (setting egress_country is {current or 'unset'})", emit_manual_link=True)


def _pol12_keys(cls: Any, pctx: PolicyContext) -> Decision | None:
    missing = [k for k in (getattr(cls, "requires_keys", ()) or ()) if k not in pctx.keys]
    if missing:
        return _deny("POL-12", Status.NEEDS_KEY, "needs_key", f"needs API key: {', '.join(missing)} (v3lum keys set {missing[0]})", emit_manual_link=True)
    reg = pctx.registry
    disclosure = getattr(cls, "disclosure", "")
    if disclosure == "internal" and not (getattr(cls, "hosts", ()) or ()):
        internal = [p for p in _receivers(cls, reg) if getattr(p, "internal", False)]
        if internal and not any(reg.hosts_for(p.id, pctx.config) for p in internal):
            settings = sorted({s for p in internal for s in p.hosts_from_settings})
            return _skip("POL-12", "config", f"internal platform not configured: set {' or '.join(settings) or 'its URL setting'} (https)")
    if disclosure in ("third_party", "internal"):
        for prov in _receivers(cls, reg):
            needed = prov.http_profile.ua_placeholders & {"contact", "contact_url"}
            for placeholder in sorted(needed):
                setting = "contact_email" if placeholder == "contact" else "contact_url"
                if not str(pctx.setting(setting, "") or "").strip():
                    return _skip("POL-12", "config", f"{prov.name} asks for an identifying contact: set {setting} (a role mailbox/URL, never a personal one)")
    return None


def _pol13_packages(cls: Any) -> Decision | None:
    from v3lum.core import module as _module

    missing = [p for p in (getattr(cls, "requires_packages", ()) or ()) if not _module.package_available(p)]
    if not missing:
        return None
    extras = sorted({_module.OPTIONAL_PACKAGES.get(p, "full") for p in missing})
    return _deny("POL-13", Status.UNAVAILABLE, "package", f"needs python package: {', '.join(missing)} (pip install 'v3lum[{','.join(extras)}]')")


def _module_datasets(cls: Any, pctx: PolicyContext) -> list[str]:
    """Registered datasets that belong to the module's sources (cached per context and module)."""
    from v3lum.core import datasets as _datasets

    sources = set(getattr(cls, "sources", ()) or ())
    if not sources:
        return []
    key = ("datasets", _name(cls), id(cls), len(_datasets.DATASETS))
    cached = pctx._cache.get(key)
    if cached is not None:
        return list(cached)
    names: set[str] = set()
    reg = pctx.registry
    for sid in sources:
        src = reg.source(sid) if reg is not None else None
        if src is not None and getattr(src, "dataset", None):
            names.add(str(src.dataset))
    for name, entry in list(_datasets.DATASETS.items()):
        if entry.get("source") in sources:
            names.add(name)
    result = tuple(sorted(names))
    pctx._cache[key] = result
    return list(result)


def _dataset_large(name: str) -> bool:
    from v3lum.core import datasets as _datasets

    reg = _datasets.DATASETS.get(name)
    if reg is None:
        return False
    if reg.get("large") is True:
        return True
    if reg.get("large") is False:
        return False
    return bool(reg.get("max_bytes_declared")) and int(reg.get("max_bytes") or 0) > _datasets.LARGE_BYTES


def _pol14_datasets(cls: Any, pctx: PolicyContext) -> Decision | None:
    scan = pctx.path in SCAN_PATHS
    if not scan and not pctx.offline:
        return None
    from v3lum.core import datasets as _datasets

    store = _datasets.DataStore(None)
    for name in _module_datasets(cls, pctx):
        try:
            present = store.info(name).present
        except (ValueError, OSError):
            present = False
        if present:
            continue
        if pctx.offline or _dataset_large(name):
            why = "offline mode" if pctx.offline else "large datasets are never downloaded during a scan"
            return _deny("POL-14", Status.UNAVAILABLE, "dataset", f"dataset {name} is not downloaded ({why}): run v3lum data update {name}")
    return None


def _pol15_quota(cls: Any, pctx: PolicyContext, run: Any = None) -> Decision | None:
    quota = pctx.quota
    if quota is None or pctx.offline:
        return None
    reg = pctx.registry
    exhausted = getattr(quota, "exhausted_provider", None)
    priority = str(_run_attr(run, "priority", "") or "seed")
    receivers = _receivers(cls, reg)
    for prov in receivers:
        if prov.quota is None or not callable(exhausted):
            continue
        try:
            try:
                used_up = bool(exhausted(prov.id, priority=priority))  # seeds may use the 20% seed reserve (P334)
            except TypeError:
                used_up = bool(exhausted(prov.id))
        except Exception:  # noqa: BLE001 - the HTTP client still enforces budgets at request time
            used_up = False
        if used_up:
            return _deny("POL-15", Status.QUOTA, "quota", f"{prov.name}: budget used up for the current window (P334): deferred - wait for the window or add a key", emit_manual_link=True)
    primary = reg.get(getattr(cls, "provider", "")) if getattr(cls, "provider", "") and reg is not None else None
    daily = getattr(cls, "daily_quota", None)
    if daily and (primary is None or primary.quota is None):
        legacy = getattr(quota, "exhausted", None)
        try:
            used_up = bool(legacy(_name(cls), daily)) if callable(legacy) else False
        except Exception:  # noqa: BLE001
            used_up = False
        if used_up:
            return _deny("POL-15", Status.QUOTA, "quota", f"daily free quota used ({daily}/day per egress IP): add an API key or wait", emit_manual_link=True)
    return None


def _module_hosts(cls: Any, entity: Entity, pctx: PolicyContext) -> list[str]:
    hosts = [str(h).lower() for h in (getattr(cls, "hosts", ()) or ())]
    reg = pctx.registry
    for prov in _receivers(cls, reg):
        if prov.hosts_from_settings:
            hosts += [h for h in reg.hosts_for(prov.id, pctx.config) if h not in hosts]
    if getattr(cls, "disclosure", "") == "target":
        host = _host_of(entity).lower()
        if host:
            hosts.append(host)
    return hosts


def _pol16_circuit(cls: Any, entity: Entity, pctx: PolicyContext) -> Decision | None:
    try:
        circuit = [str(h).lower() for h in pctx.circuit]
    except Exception:  # noqa: BLE001
        return None
    if not circuit:
        return None
    patterns = _module_hosts(cls, entity, pctx)
    for host in circuit:
        if any(host == p or _providers.host_matches(host, p) for p in patterns):
            return _deny("POL-16", Status.BLOCKED, "circuit", f"{host} was short-circuited in this run after a challenge or geo-block (A9)", emit_manual_link=True)
    return None


def decide(module_cls: Any, entity: Entity, pctx: PolicyContext, *, run: RunInfo | Any) -> Decision:
    """The policy decision for one (module, entity): rules POL-01..POL-16 in order, first failure wins.

    ``run`` is the RunInfo of the candidate run (is_seed, depth, provenance, tlp, case_id). An
    unexpected error fails closed (SKIPPED 'policy'); in strict contract mode (tests) it is raised.
    """
    try:
        return _decide(module_cls, entity, pctx, run)
    except Exception as exc:
        from v3lum.core import vocab as _vocab

        if _vocab.strict_enabled():
            raise
        log.warning("policy evaluation failed for %s: %s", _name(module_cls), exc)
        return _skip("POL-02", "policy", f"policy evaluation failed ({type(exc).__name__}): fail closed")


def _decide(cls: Any, entity: Entity, pctx: PolicyContext, run: Any) -> Decision:
    state: dict[str, Any] = {"allowed_sources": None, "licence_basis": {}, "blocked_sources": {}}
    found = _pol01_selection(cls, entity, pctx) or _pol02_metadata(cls) or _pol03_offline(cls, pctx) or _pol04_licence(cls, pctx, state)
    if found is not None:
        return found

    def carry(decision: Decision | None) -> Decision | None:
        if decision is None:
            return None
        return dataclasses.replace(
            decision,
            allowed_sources=state["allowed_sources"] if decision.allowed_sources is None else decision.allowed_sources,
            blocked_sources=decision.blocked_sources or state["blocked_sources"],
        )

    for check in (
        lambda: _pol05_tlp(cls, entity, pctx, run),
        lambda: _pol06_tier(cls, entity, pctx),
        lambda: _pol07_privacy(cls, entity, pctx, run),
        lambda: _pol08_own_asset(cls, entity, pctx),
        lambda: _pol09_opsec(cls, pctx),
        lambda: _pol10_engagement(cls, entity, pctx, run),
        lambda: _pol11_egress(cls, pctx),
        lambda: _pol12_keys(cls, pctx),
        lambda: _pol13_packages(cls),
        lambda: _pol14_datasets(cls, pctx),
        lambda: _pol15_quota(cls, pctx, run),
        lambda: _pol16_circuit(cls, entity, pctx),
    ):
        found = carry(check())
        if found is not None:
            return found
    allowed = state["allowed_sources"]
    blocked = state["blocked_sources"]
    reason = "allowed"
    if blocked:
        reason = f"allowed ({len(allowed or ())}/{len(allowed or ()) + len(blocked)} sources; skipped by licence profile {pctx.licence_profile}: {', '.join(sorted(blocked))})"
    return Decision(True, Status.OK, "", reason, "", allowed_sources=allowed, licence_basis=state["licence_basis"], blocked_sources=blocked)


# --------------------------------------------------------------------------------------
# GUARD-02: recipient tokens
# --------------------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,8}(?:[A-Za-z]{2,24}|xn--[A-Za-z0-9-]{1,59})")
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")
_TOKEN_RUN_RE = re.compile(r"[A-Za-z0-9+/=_-]+")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
#: a word with a short version number ('windows11', 'ios17', 'top10', '4k'): slug words, not token material.
_VERSIONED_WORD_RE = re.compile(r"^(?:[A-Za-z]{3,}\d{1,4}|\d{1,4}[A-Za-z]{3,})$")


def _unquoted(text: str) -> str:
    out = text
    for _ in range(3):  # double/triple encoding
        new = unquote(out)
        if new == out:
            break
        out = new
    return out


def _decode_b64(token: str) -> str:
    core = token.rstrip("=")
    if len(core) < 8:
        return ""
    for alt in (None, b"-_"):
        try:
            raw = base64.b64decode(core + "=" * (-len(core) % 4), altchars=alt, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if text and all(ch.isprintable() or ch in "\r\n\t" for ch in text):
            return text
    return ""


def _emails_in(text: str) -> list[str]:
    found = list(_EMAIL_RE.findall(text))
    for run in _B64_RUN_RE.findall(text):
        decoded = _decode_b64(run)
        if "@" in decoded:
            found += _EMAIL_RE.findall(_unquoted(decoded))
    return found


def _case_transitions(token: str) -> int:
    letters = [c for c in token if c.isalpha()]
    return sum(1 for a, b in zip(letters, letters[1:]) if a.islower() != b.islower())


def _opaque(token: str) -> bool:
    """Random-looking id of >= 16 characters (UUID, hex digest, long number, mixed base64)."""
    core = token.strip("=")
    if len(core) < RECIPIENT_TOKEN_MIN:
        return False
    if _UUID_RE.search(core):
        return True
    pieces = [p for p in re.split(r"[-_+/=.]", core) if p]
    mixed = sum(
        len(p) for p in pieces
        if any(c.isalpha() for c in p) and any(c.isdigit() for c in p) and not _VERSIONED_WORD_RE.match(p)
    )
    if mixed >= 8:
        return True
    for piece in pieces:
        if len(piece) < RECIPIENT_TOKEN_MIN:
            continue
        if piece.isdigit() or (_HEX_RE.match(piece) and any(c.isdigit() for c in piece)) or _case_transitions(piece) >= 4:
            return True
    return False


def recipient_token(url: Any, org: Any = None) -> bool:
    """Does the URL probably carry a per-recipient token? (A7 BR15, P376 cond 10)

    True when the path, query or fragment holds an e-mail address in plain, URL-encoded or base64
    form - an org-profile address (``org``) above all, and any other address as well (it also
    identifies a recipient) - or when the path/query holds an opaque token of >= 16 characters
    (UUID, hex digest, long number, mixed-case/alphanumeric base64). Such URLs are never fetched
    automatically (GUARD-02).
    """
    text = str(getattr(url, "value", url) or "")
    try:
        parts = urlsplit(text)
    except ValueError:
        return False
    rest = parts.path + (f"?{parts.query}" if parts.query else "") + (f"#{parts.fragment}" if parts.fragment else "")
    if not parts.netloc:
        rest = text
    decoded = _unquoted(rest)
    userinfo = parts.netloc.rpartition("@")[0] if "@" in parts.netloc else ""  # 'https://ana%40corp.com@host/'
    emails = _emails_in(decoded) or (_emails_in(_unquoted(userinfo)) if userinfo else [])
    if emails:
        return True  # org-profile addresses and any other address identify the recipient
    # opaque tokens in path segments and query values (not the fragment, which never reaches the server)
    components: list[str] = [_unquoted(seg) for seg in parts.path.split("/") if seg]
    try:
        pairs = parse_qsl(parts.query, keep_blank_values=True)
    except ValueError:
        pairs = []
    components += [_unquoted(v) for _k, v in pairs if v] + [_unquoted(k) for k, v in pairs if k and not v]
    if any(_opaque(run) for component in components for run in _TOKEN_RUN_RE.findall(component)):
        return True
    return bool(org is not None and _org_domain_in(decoded, org))


def _org_domain_in(text: str, org: Any) -> bool:
    """An org-profile domain base64-encoded in the URL (a per-organisation token)."""
    domains = [getattr(d, "name", "") for d in getattr(org, "domains", ()) or ()]
    if not domains:
        return False
    for run in _B64_RUN_RE.findall(text):
        decoded = _decode_b64(run).lower()
        if decoded and any(d and d in decoded for d in domains):
            return True
    return False


def _token_url(entity: Entity, pctx: PolicyContext) -> bool:
    """A URL entity with a probable per-recipient token: :func:`recipient_token`, or tagged
    ``recipient_token`` in the case graph (e.g. by the IOC extraction engine)."""
    if entity.type is not EntityType.URL:
        return False
    if recipient_token(entity.value, _org(pctx)):
        return True
    node = _node(pctx, entity.key)
    return node is not None and "recipient_token" in _node_tags(node)


def _confirmed(url: str, pctx: PolicyContext) -> bool:
    confirmed = pctx.option("confirmed_urls", ()) or ()
    if not confirmed:
        return False
    wanted = {url}
    try:
        wanted.add(_entities.normalize_url(url))
    except ValueError:
        pass
    for item in confirmed:
        candidate = str(item or "").strip()
        if not candidate:
            continue
        if candidate in wanted:
            return True
        try:
            if _entities.normalize_url(candidate) in wanted:
                return True
        except ValueError:
            continue
    return False


# --------------------------------------------------------------------------------------
# GUARD-01: hostile hosts
# --------------------------------------------------------------------------------------

#: Confusable characters folded before brand/lure matching (Cyrillic, Greek and look-alike digits).
_CONFUSABLES = str.maketrans({
    "0": "o", "1": "l", "i": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s", "@": "a",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "l", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "ο": "o", "α": "a", "ν": "v", "ι": "l", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ε": "e",
    "ɑ": "a", "ɡ": "g", "ı": "l", "ł": "l", "ø": "o", "đ": "d", "ħ": "h", "ŀ": "l", "ß": "ss", "æ": "ae", "œ": "oe",
})
_SEQUENCES = (("rn", "m"), ("vv", "w"), ("cl", "d"))


def _skeleton(text: str) -> str:
    """Accent-folded, lower-case, homoglyph-folded form used for brand and lure matching."""
    from v3lum.core.orgprofile import fold

    out = fold(text).translate(_CONFUSABLES)
    for seq, repl in _SEQUENCES:
        out = out.replace(seq, repl)
    return out


def _unicode_label(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            return label
    return label


def _name_labels(host: str) -> list[str]:
    """The labels an owner chose (subdomains + registrable label; the public suffix removed), Unicode."""
    from v3lum.core import psl

    host = host.strip().lower().rstrip(".")
    if not host:
        return []
    labels = host.split(".")
    reg = None
    try:
        reg = psl.registrable_domain(host)
    except Exception:  # noqa: BLE001
        reg = None
    if reg:
        suffix_len = reg.count(".")  # labels of the public suffix
        labels = labels[: len(labels) - suffix_len] if suffix_len else labels
    return [_unicode_label(lb) for lb in labels if lb]


def _distance_le1(a: str, b: str) -> bool:
    """Damerau-Levenshtein distance <= 1 (one insertion, deletion, substitution or swap)."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diff = [i for i in range(la) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    if la > lb:
        a, b = b, a
    return any(b[:i] + b[i + 1:] == a for i in range(len(b)))


def _brand_lookalike(host: str, pctx: PolicyContext) -> str:
    """The org brand the host imitates ('' when none)."""
    org = _org(pctx)
    terms_fn = getattr(org, "brand_terms", None)
    if not callable(terms_fn):
        return ""
    try:
        terms = [t for t in terms_fn() if t]
    except Exception:  # noqa: BLE001
        return ""
    if not terms:
        return ""
    labels = _name_labels(host)
    skeletons = [_skeleton(lb) for lb in labels]
    compact = [s.replace("-", "") for s in skeletons]
    for term in terms:
        key = _skeleton(term).replace(" ", "").replace("-", "")
        if len(key) < 3:
            continue
        for full, flat in zip(skeletons, compact):
            tokens = re.split(r"[-_]", full)
            if key in tokens or (len(key) >= 4 and key in flat):
                return term
            if len(key) >= 5 and any(_distance_le1(tok, key) for tok in tokens + [flat]):
                return term
    return ""


@functools.lru_cache(maxsize=8)
def _lure_words_cached(stamp: tuple[tuple[str, int, int], ...]) -> frozenset[str]:
    from v3lum.core.orgprofile import fold

    words: set[str] = set()

    def collect(value: Any) -> None:
        if isinstance(value, str):
            word = fold(value).strip()
            if len(word) >= 3:
                words.add(word)
        elif isinstance(value, (list, tuple)):
            for item in value:
                collect(item)
        elif isinstance(value, Mapping):
            for key, item in value.items():
                if key not in ("schema", "source", "licence", "notes", "description", "reviewer", "date"):
                    collect(item)

    for name, _mtime, _size in stamp:
        try:
            collect(json.loads(Path(name).read_text(encoding="utf-8")))
        except (OSError, ValueError):
            log.warning("unreadable lure-word list %s", name)
    return frozenset(words)


def lure_words() -> frozenset[str]:
    """Accent-folded lure words from ``v3lum/data/brand_lures*.json`` (empty when no file is present)."""
    stamp: list[tuple[str, int, int]] = []
    try:
        for path in sorted(DATA_DIR.glob(LURE_GLOB)):
            st = path.stat()
            stamp.append((str(path), st.st_mtime_ns, st.st_size))  # the full path: a new data dir never hits a stale entry
    except OSError:
        return frozenset()
    return _lure_words_cached(tuple(stamp)) if stamp else frozenset()


def _lure_word(host: str) -> str:
    words = lure_words()
    if not words:
        return ""
    for label in _name_labels(host):
        skel = _skeleton(label)
        tokens = set(re.split(r"[-_]", skel))
        flat = skel.replace("-", "")
        for word in words:
            key = _skeleton(word).replace(" ", "").replace("-", "")
            if key in tokens or (len(key) >= 5 and key in flat):
                return word
    return ""


def _node(pctx: PolicyContext, key: str) -> Any:
    graph = pctx.graph
    getter = getattr(graph, "get", None)
    if not callable(getter):
        return None
    try:
        return getter(key)
    except Exception:  # noqa: BLE001
        return None


def _snapshot(items: Any) -> tuple:
    """A C-level copy of a live graph collection: the guard runs in module worker threads (redirect
    hops) while the engine thread mutates the case graph, and iterating a set/list that grows
    meanwhile would raise (a spurious fail-closed refusal)."""
    if not items:
        return ()
    for _attempt in range(3):
        try:
            return tuple(items)
        except RuntimeError:  # changed size during the copy: retry
            continue
    return ()


def _node_tags(node: Any) -> set[str]:
    tags = {str(t) for t in _snapshot(getattr(node, "tags", None))}
    for finding in _snapshot(getattr(node, "findings", None)):
        tags.update(str(t) for t in _snapshot(getattr(finding, "tags", None)))
    return tags


def _attr_list(node: Any, name: str) -> list[Any]:
    """``node.attr_values(name)`` (every value any module recorded), [] when unavailable."""
    attr_values = getattr(node, "attr_values", None)
    if not callable(attr_values):
        return []
    try:
        return list(attr_values(name) or [])
    except Exception:  # noqa: BLE001
        return []


def _hostile_marks(node: Any) -> list[str]:
    """Hostile tags of the node or its findings, and the boolean attributes malicious/suspicious."""
    marks = set(HOSTILE_TAGS & _node_tags(node))
    for name in HOSTILE_ATTRIBUTES:
        if any(v is True or (isinstance(v, str) and v.strip().lower() == "true") for v in _attr_list(node, name)):
            marks.add(name)
    return sorted(marks)


def _as_date(value: Any) -> _dt.date | None:
    if isinstance(value, _dt.datetime):
        return value.astimezone(_dt.timezone.utc).date() if value.tzinfo else value.date()
    if isinstance(value, _dt.date):
        return value
    text = str(value or "").strip()
    if len(text) >= 10 and re.match(r"^\d{4}-\d{2}-\d{2}$", text[:10]):
        try:
            return _dt.date.fromisoformat(text[:10])
        except ValueError:
            return None
    return None


def _direct_entities(entity: Entity) -> list[Entity]:
    """The entity, the host it reaches and that host's registrable domain."""
    out: list[Entity] = [entity]
    host = _host_of(entity)
    if host and entity.type in (EntityType.URL, EntityType.EMAIL, EntityType.PORT_SERVICE):
        for etype in (EntityType.IPV4, EntityType.IPV6, EntityType.DOMAIN):
            ent = Entity.try_make(etype, host)
            if ent is not None:
                out.append(ent)
                break
    for ent in list(out):
        if ent.type is EntityType.DOMAIN:
            from v3lum.core import psl

            try:
                reg = psl.registrable_domain(ent.value)
            except Exception:  # noqa: BLE001
                reg = None
            if reg and reg != ent.value:
                parent = Entity.try_make(EntityType.DOMAIN, reg)
                if parent is not None and parent not in out:
                    out.append(parent)
    return out


def _related_entities(entity: Entity, pctx: PolicyContext) -> list[Entity]:
    """:func:`_direct_entities` plus, from the case graph, redirect targets, CNAMEs and non-noise
    resolved addresses (up to three hops)."""
    out = _direct_entities(entity)
    graph = pctx.graph
    out_edges = getattr(graph, "out_edges", None)
    if callable(out_edges):
        frontier = [e.key for e in out]
        seen = {e.key for e in out}
        for _hop in range(3):
            nxt: list[str] = []
            for key in frontier:
                try:
                    edges = out_edges(key)
                except Exception:  # noqa: BLE001
                    edges = []
                for edge in edges:
                    if getattr(edge, "relation", "") not in _CONTACT_RELATIONS or edge.dst in seen:
                        continue
                    node = _node(pctx, edge.dst)
                    if node is None:
                        continue
                    if edge.relation == "resolves_to" and getattr(node, "noise", False):
                        continue  # shared CDN/hosting addresses do not taint the names on them
                    seen.add(edge.dst)
                    out.append(node.entity)
                    nxt.append(edge.dst)
            frontier = nxt
            if not frontier:
                break
    return out


def _call_sightings(lookup: Callable[..., Any], entity: Entity, run: Any, level: _tlp.TLP) -> Any:
    kwargs: dict[str, Any] = {}
    try:
        params = inspect.signature(lookup).parameters
    except (TypeError, ValueError):
        params = {}
    if "case_id" in params:
        kwargs["case_id"] = _run_attr(run, "case_id", "") or ""
    if "case_tlp" in params:
        kwargs["case_tlp"] = level.value_str
    try:
        return lookup(entity, **kwargs)
    except Exception:  # noqa: BLE001 - the case DB being unavailable never unblocks or blocks by itself
        return None


def _hostile_sighting(summary: Any) -> str:
    if summary is None:
        return ""
    rows = summary.get("visible") if isinstance(summary, Mapping) else getattr(summary, "visible", None)
    for row in rows or ():
        verdict = row.get("verdict") if isinstance(row, Mapping) else getattr(row, "verdict", "")
        if str(verdict or "").strip().lower() in HOSTILE_VERDICTS:
            return str(verdict).strip().lower()
    tags = summary.get("tags") if isinstance(summary, Mapping) else getattr(summary, "tags", None)
    hit = sorted(HOSTILE_TAGS.intersection(str(t) for t in (tags or ())))
    return hit[0] if hit else ""


def _consensus(node: Any, pctx: PolicyContext) -> str:
    """'listed ...' when a reputation source lists the node (ad/tracking-only listings excluded)."""
    for finding in _snapshot(getattr(node, "findings", None)):  # live graph: copied first (redirect hops run in workers)
        ftags = {str(t) for t in _snapshot(getattr(finding, "tags", None))}
        listed = sorted(LISTING_TAGS & ftags)
        if listed and not ftags & _WEAK_LISTING_TAGS:
            return f"listed as {listed[0]}"
    listed = sorted(LISTING_TAGS & {str(t) for t in _snapshot(getattr(node, "tags", None))})
    if listed:
        return f"listed as {listed[0]}"
    hits = [h for h in _attr_list(node, "blocklist_hits") if h]
    strong = [h for h in hits if not (isinstance(h, Mapping) and str(h.get("category") or "") in _WEAK_LISTING_CATEGORIES)]
    if strong:
        first = strong[0]
        name = (first.get("list") or first.get("name") or first.get("feed") or "a blocklist") if isinstance(first, Mapping) else first
        return f"listed by {name}"
    if not hits:  # list names count unless the per-hit detail shows ad/tracking lists only
        for attr in ("blocklists", "blocklist_families"):
            values = [v for v in _attr_list(node, attr) if v]
            if values:
                return f"listed by {values[0]}"
    for corr in _snapshot(getattr(pctx.graph, "correlations", None)):
        rule_name = str(getattr(corr, "rule", "") or "").lower()
        keys_fn = getattr(corr, "entity_keys", None)
        keys = keys_fn() if callable(keys_fn) else []
        if rule_name in CONSENSUS_RULES and node.entity.key in keys:
            return "multi-source malicious consensus (CR27)"
    return ""


def _young(node: Any, today: _dt.date | None = None) -> str:
    """Young-domain signal: attribute domain_age_days <= 30, a domain node whose registration date
    (attribute ``created``) is at most 30 days before ``today``, or tag newly_registered."""
    if node is None:
        return ""
    for age in _attr_list(node, "domain_age_days"):
        if isinstance(age, (int, float)) and not isinstance(age, bool) and 0 <= age <= YOUNG_DOMAIN_DAYS:
            return f"domain registered {int(age)} days ago"
    entity = getattr(node, "entity", None)
    if today is not None and getattr(entity, "type", None) is EntityType.DOMAIN:
        for created in _attr_list(node, "created"):
            day = _as_date(created)
            if day is not None and 0 <= (today - day).days <= YOUNG_DOMAIN_DAYS:
                return f"domain registered {(today - day).days} days ago"
    if "newly_registered" in _node_tags(node):
        return "newly registered domain"
    return ""


def _hosts_hostile_url(host_entity: Entity, pctx: PolicyContext) -> str:
    """'hosts a URL tagged <tag>' when a URL of the case on exactly this host is tagged hostile (the
    host serves it); shared platforms (noise nodes, URLs tagged hosted_on_legit_platform or
    abused_legit_service) are not tainted by one hosted URL."""
    graph = pctx.graph
    node = _node(pctx, host_entity.key)
    if node is None or getattr(node, "noise", False):
        return ""
    keys: list[str] = []
    for method, relation, end in (("out_edges", "hosts_url", "dst"), ("in_edges", "url_host", "src")):
        fn = getattr(graph, method, None)
        if not callable(fn):
            continue
        try:
            keys += [getattr(e, end) for e in fn(host_entity.key) if getattr(e, "relation", "") == relation]
        except Exception:  # noqa: BLE001
            continue
    host = host_entity.value.lower()
    for key in dict.fromkeys(keys):
        unode = _node(pctx, key)
        ent = getattr(unode, "entity", None)
        if ent is None or ent.type is not EntityType.URL or (_entities.url_host(ent.value) or "").lower() != host:
            continue
        if _node_tags(unode) & _LEGIT_PLATFORM_TAGS:
            continue
        marks = _hostile_marks(unode)
        if marks:
            return f"hosts a URL tagged {marks[0]}"
    return ""


def _own_exempt(pctx: PolicyContext, entity: Entity) -> bool:
    """Own assets (any verification but 'seeded') and supplier domains are not hostile-shaped."""
    own = _owns(pctx, entity)
    if own is None:
        return False
    if getattr(own, "kind", "") == "supplier":
        return True
    if not getattr(own, "own", False):
        return False
    entry = getattr(own, "entry", None)
    return getattr(entry, "verification", "") != "seeded"


def hostile_reasons(entity: Entity, pctx: PolicyContext, *, run: Any = None) -> list[str]:
    """Why the entity is hostile or hostile-shaped for target contact (empty when it is not).

    Checked for the entity, the host it reaches, its registrable domain and the graph's redirect
    targets/CNAMEs/resolved addresses: hostile tags or attributes (case graph, :data:`HOSTILE_TAGS`,
    :data:`HOSTILE_ATTRIBUTES`), hostile case-DB sighting verdicts and consensus listings (listing
    tags, blocklist attributes; ad/tracking-only listings excluded); a host serving a URL tagged
    hostile; hostile-shaped (entity and its host only): org-brand lookalike, :data:`SHAPE_TAGS`,
    young domain (domain_age_days or the ``created`` date), lure word, extracted from
    text/file/e-mail input. Used by :func:`contact_guard` and by ``links --open`` warnings.
    """
    reasons: list[str] = []
    level = entity_tlp(entity, pctx, run)
    related = _related_entities(entity, pctx)
    for ent in related:
        node = _node(pctx, ent.key)
        label = "" if ent == entity else f" ({ent.type.value} {ent.display})"
        if node is not None:
            hits = _hostile_marks(node)
            if hits:
                reasons.append(f"tagged {hits[0]}{label}")
            listing = _consensus(node, pctx)
            if listing:
                reasons.append(f"{listing}{label}")
        if pctx.sightings is not None:
            verdict = _hostile_sighting(_call_sightings(pctx.sightings, ent, run, level))
            if verdict:
                reasons.append(f"case-DB sighting with verdict {verdict}{label}")
    direct = _direct_entities(entity)
    for ent in direct:
        if ent.type in (EntityType.DOMAIN, EntityType.IPV4, EntityType.IPV6):
            hosted = _hosts_hostile_url(ent, pctx)
            if hosted:
                reasons.append(hosted + ("" if ent == entity else f" ({ent.type.value} {ent.display})"))
    shape_targets = [e for e in direct if e.type in (EntityType.DOMAIN, EntityType.URL, EntityType.ONION, EntityType.IPV4, EntityType.IPV6)]
    exempt = _own_exempt(pctx, entity)
    if not exempt:
        today = pctx.time().astimezone(_dt.timezone.utc).date()
        for ent in shape_targets:
            host = _host_of(ent)
            if ent.type in (EntityType.DOMAIN, EntityType.URL) and host:
                brand = _brand_lookalike(host, pctx)
                if brand:
                    reasons.append(f"lookalike of the org brand {brand!r}")
                lure = _lure_word(host)
                if lure:
                    reasons.append(f"lure-word domain ({lure!r})")
            ent_node = _node(pctx, ent.key)
            shaped = sorted(SHAPE_TAGS & _node_tags(ent_node)) if ent_node is not None else []
            if shaped:
                reasons.append(f"tagged {shaped[0]}")
            young = _young(ent_node, today)
            if young:
                reasons.append(young)
        node = _node(pctx, entity.key)
        from_text = _text_derived(run)
        if not from_text and not _run_attr(run, "is_seed", False) and node is not None and callable(getattr(pctx.graph, "in_edges", None)):
            try:
                from_text = any(_parent_type(edge.src) in TEXT_TYPES for edge in pctx.graph.in_edges(entity.key))
            except Exception:  # noqa: BLE001
                from_text = False
        if from_text:
            reasons.append("extracted from text/file/e-mail input")
    seen: set[str] = set()
    return [r for r in reasons if not (r in seen or seen.add(r))]


def contact_guard(module_cls: Any, entity: Entity, pctx: PolicyContext, *, run: RunInfo | Any) -> Decision:
    """Second gate for LIGHT/ACTIVE contact, evaluated after the entity's passive results (A13).

    GUARD-02 first: a URL with a probable per-recipient token is SKIPPED 'policy' unless the exact
    URL is in ``options.confirmed_urls`` (an egress profile or override does not lift it). GUARD-01:
    hostile or hostile-shaped targets (see :func:`hostile_reasons`) give BLOCKED 'hostile_host'
    ('needs non-corporate egress') with the manual link, unless proxy_light (LIGHT) / proxy_active
    (ACTIVE) is configured or ``--egress-override`` is recorded - then the decision is allowed with
    rule_id 'GUARD-01' and the reason says which egress lifted it. PASSIVE modules always pass.
    """
    opsec = _opsec(module_cls)
    if opsec is Opsec.PASSIVE:
        return Decision(True, Status.OK, "", "no target contact")
    if _token_url(entity, pctx) and not _confirmed(entity.value, pctx):
        return _skip("GUARD-02", "policy", "URL carries a per-recipient token: re-run with --confirm-url <url>")
    reasons = hostile_reasons(entity, pctx, run=run)
    if not reasons:
        return Decision(True, Status.OK, "", "contact allowed: no hostile signal")
    summary = "; ".join(reasons[:4])
    egress, problem = _egress_state(opsec, pctx)
    if egress:
        return Decision(True, Status.OK, "", f"hostile host ({summary}): contact through egress profile {egress} [GUARD-01]", "GUARD-01")
    override = str(pctx.option("egress_override", "") or "").strip()
    if override:
        return Decision(True, Status.OK, "", f"hostile host ({summary}): contact allowed by the recorded --egress-override [GUARD-01]", "GUARD-01")
    setting = "proxy_active" if opsec is Opsec.ACTIVE else "proxy_light"
    example = "http://research-proxy.example:3128" if opsec is Opsec.ACTIVE else "socks5h://..."
    unusable = f" (the configured {setting} cannot be used: {problem})" if problem else ""
    text = (
        f"needs non-corporate egress: {summary}. Passive alternatives: urlscan search results, archived copies, sandbox reports; "
        f"configure an egress profile with `v3lum config set {setting} {example}`{unusable} or pass --egress-override \"<reason>\""
    )
    return _deny("GUARD-01", Status.BLOCKED, "hostile_host", text, emit_manual_link=True)


# --------------------------------------------------------------------------------------
# default set and explanations
# --------------------------------------------------------------------------------------

_SAMPLE_VALUES: dict[EntityType, str] = {
    EntityType.CNPJ: "00000000000191",
    EntityType.PHONE: "+5511912345678",
    EntityType.SHA512: "a" * 128,
    EntityType.MITRE: "T1566",
    EntityType.ONION: "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
    EntityType.BTC: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    EntityType.KEYWORD: "example",
    EntityType.ORG: "Example Org",
    EntityType.PERSON: "Example Person",
}


def _sample_entity(etype: EntityType) -> Entity:
    from v3lum.core.module import BENIGN_VALUES

    for value in (BENIGN_VALUES.get(etype), _SAMPLE_VALUES.get(etype)):
        if value:
            ent = Entity.try_make(etype, value)
            if ent is not None:
                return ent
    return Entity(etype, "sample")


def _default_set_context(pctx: PolicyContext) -> PolicyContext:
    options = copy.copy(pctx.options)
    for name, value in (("preset", "quick"), ("include_disabled", False), ("include", set())):
        try:
            setattr(options, name, value)
        except AttributeError:  # pragma: no cover - exotic option objects
            pass
    if not str(getattr(options, "purpose", "") or "").strip():
        try:
            options.purpose = "(default-set evaluation)"  # a plain scan of a personal seed records one (AR16)
        except AttributeError:  # pragma: no cover
            pass
    ctx = dataclasses.replace(pctx, options=options, explicit=frozenset(), graph=None, sightings=None)
    ctx._cache = pctx._cache  # licence results do not depend on these options
    return ctx


def effective_default_set(etype: EntityType | str, pctx: PolicyContext, *, include_blocked: bool = False) -> list[tuple[Any, Decision]]:
    """Modules that a plain ``v3lum scan`` of an analyst-typed ``etype`` seed runs (A3): default_enabled
    modules accepting the type that pass every gate under ``pctx`` (preset quick, no -M; a purpose is
    assumed because personal seeds always record one). ``include_blocked`` also lists the rest with
    their Decision. Sorted by category and name.
    """
    from v3lum.core.context import RunInfo
    from v3lum.core.module import modules_for

    etype = etype if isinstance(etype, EntityType) else EntityType.parse(str(etype))
    entity = _sample_entity(etype)
    ctx = _default_set_context(pctx)
    run = RunInfo(entity=entity, is_seed=True, depth=0)
    out: list[tuple[Any, Decision]] = []
    for cls in modules_for(etype):
        decision = decide(cls, entity, ctx, run=run)
        if decision.allowed or include_blocked:
            out.append((cls, decision))
    return out


def describe_policy(module_cls: Any, pctx: PolicyContext) -> list[str]:
    """Readable lines explaining which policy applies to the module and why (``v3lum info``, A3/P327 cond 14)."""
    cls = module_cls
    name = _name(cls)
    lines: list[str] = []
    accepts = sorted(getattr(cls, "accepts", ()) or (), key=lambda t: t.value)
    ctx = _default_set_context(pctx)
    in_default: list[str] = []
    out_default: list[str] = []
    if accepts:
        from v3lum.core.context import RunInfo

        for etype in accepts:
            entity = _sample_entity(etype)
            decision = decide(cls, entity, ctx, run=RunInfo(entity=entity, is_seed=True, depth=0))
            if decision.allowed:
                in_default.append(etype.value)
            else:
                out_default.append(f"{etype.value}: {decision.reason_code} - {decision.reason}")
    if in_default:
        lines.append(f"POL-01 default set: runs by default on {', '.join(in_default)} seeds")
    for row in out_default[:3]:
        lines.append(f"POL-01 default set: not run by default ({row})")
    if not getattr(cls, "default_enabled", True):
        lines.append(f"POL-01 selection: opt-in module (default_enabled False): --preset deep or -M {name}")
    if pctx.health is not None:
        reasons = pctx.health.demotion_reasons(name)
        if reasons:
            lines.append(f"POL-01 demotion: demoted ({'; '.join(reasons)}): -M {name} still runs it")
    if "watch_only" in (getattr(cls, "tags", ()) or ()):
        lines.append("POL-01 selection: watch_only - runs only inside v3lum watch")
    # licence
    allowed, basis, blocked, verdicts = _licence_eval(cls, pctx)
    if allowed is None:
        lines.append("POL-04 licence: no registry source (offline or target contact): nothing licence-restricted")
    else:
        for sid in sorted(set(basis) | set(blocked)):
            if sid in basis:
                lines.append(f"POL-04 licence ({pctx.licence_profile}): {sid} allowed ({basis[sid]})")
            else:
                verdict = next((v for v in verdicts if v.source_id == sid), None)
                remedy = f"; to clear it: {verdict.remedy}" if verdict is not None and verdict.remedy else ""
                lines.append(f"POL-04 licence ({pctx.licence_profile}): {sid} {blocked[sid]}{remedy}")
        for sid in sorted(getattr(cls, "sources", ()) or ()):
            entry = pctx.licence.entry_for(sid, pctx.now)
            if entry is not None:
                lines.append(f"POL-04 licence_allow: {sid} by {entry.legal_ref} ({entry.basis}, {entry.scope}), approved by {entry.approver}, review by {entry.review_by}")
    # TLP and tier
    tier, reuses, publishes, external = _exposure(cls, pctx)
    if publishes:
        lines.append("POL-05 TLP: the provider publishes lookups - never receives investigated values (rule 7)")
    else:
        disclosure = getattr(cls, "disclosure", "")
        third = _tlp.max_tlp("third_party", tier, publishes_queries=False, reuses_queries=reuses) if external else None
        why = "reuses submitted values" if reuses else f"{tier}-tier provider"
        if disclosure in ("none", "internal"):
            lines.append(f"POL-05 TLP: disclosure {disclosure} - allowed up to TLP:RED")
        elif disclosure == "target":
            extra = f"; it also queries a third-party provider ({why}): at most {third.label}" if third is not None else ""
            lines.append(f"POL-05 TLP: target contact - up to TLP:AMBER (TLP:RED only for verified own assets through a non-corporate egress or a recorded override){extra}")
        elif disclosure == "third_party":
            lines.append(f"POL-05 TLP: third-party provider ({why}) - receives at most {third.label if third else 'nothing'}")
    if getattr(cls, "disclosure", "") in ("third_party", "target") and tier == "unknown":
        lines.append("POL-06 tier: unknown-tier provider - needs --allow-unknown at TLP:CLEAR/GREEN and receives IOC values only")
    secrets = sorted(t.value for t in accepts if t in SECRET_TYPES)
    if secrets and getattr(cls, "disclosure", "") != "none":
        lines.append(f"POL-07 privacy: secret values ({', '.join(secrets)}) are never sent to it (found credentials are never used)")
    # privacy and own assets
    run_on = str(getattr(cls, "run_on", "any") or "any")
    if run_on == "seeds":
        lines.append("POL-07 privacy: run_on seeds - only confirmed analyst-typed seeds")
    elif run_on == "own_assets":
        lines.append("POL-07 privacy: per-person breach check - verified org-domain addresses, or typed seeds with --breach-scope all and --purpose")
    elif run_on == "own_assets_only":
        lines.append("POL-08 own assets: needs a txt_verified or attested org-profile entry" + (" (no org profile: v3lum org)" if _org_empty(pctx) else ""))
    personal = sorted(t.value for t in accepts if t in PERSONAL_TYPES)
    if personal:
        unreviewed = [p.id for p in _receivers(cls, pctx.registry) if p.id not in DNS_ONLY_PROVIDERS and getattr(p, "personal_data_review", None) is None]
        tail = f"; provider {', '.join(unreviewed)} has no personal-data review: explicit -M only" if unreviewed and getattr(cls, "disclosure", "") in ("third_party", "internal") else ""
        lines.append(f"POL-07 privacy: personal identifiers ({', '.join(personal)}) need a recorded --purpose{tail}")
    # opsec / engagement / guard
    opsec = _opsec(cls)
    if opsec is Opsec.LIGHT:
        lines.append("POL-09/POL-10 opsec LIGHT: --mode light, analyst-typed seeds only (light_for_own_assets: verified own seeds without --mode light)")
    elif opsec is Opsec.ACTIVE:
        lines.append("POL-09/POL-10 opsec ACTIVE: --mode active, --authorized REF and a matching --scope FILE; pivots never inherit scope")
    if opsec is not Opsec.PASSIVE:
        lines.append("GUARD-01/GUARD-02: contact is checked after the passive results (hostile hosts need a non-corporate egress; recipient-token URLs need --confirm-url)")
    required = sorted(getattr(cls, "requires_egress", ()) or ())
    if required:
        lines.append(f"POL-11 egress: needs {'/'.join(required)} egress (egress_country is {str(pctx.setting('egress_country', '') or 'unset')})")
    keys = list(getattr(cls, "requires_keys", ()) or ())
    if keys:
        state = ", ".join(f"{k} ({'configured' if k in pctx.keys else 'missing'})" for k in keys)
        lines.append(f"POL-12 keys: requires {state}")
    optional = list(getattr(cls, "optional_keys", ()) or ())
    if optional:
        lines.append("POL-12 keys: optional " + ", ".join(f"{k} ({'configured' if k in pctx.keys else 'missing'})" for k in optional))
    datasets = _module_datasets(cls, pctx)
    if datasets:
        lines.append(f"POL-14 datasets: {', '.join(datasets)} (large ones are fetched by v3lum data update, never during a scan)")
    providers_with_quota = [p for p in _receivers(cls, pctx.registry) if p.quota is not None]
    if providers_with_quota:
        lines.append("POL-15 quota: provider budget " + ", ".join(p.id for p in providers_with_quota) + " (P334)")
    elif getattr(cls, "daily_quota", None):
        lines.append(f"POL-15 quota: {cls.daily_quota} requests/day per egress IP")
    lines.append(f"policy {POLICY_VERSION}; licence profile {pctx.licence_profile}")
    return lines
