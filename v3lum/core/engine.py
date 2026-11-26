"""Investigation engine v2: policy-gated selection, pipelined BFS, deadlines, coverage, correlation.

One investigation (``Engine.investigate``) runs a pipelined BFS: as soon as a module returns new
entities they are scheduled. What decides, what runs and what is recorded:

* **Selection through the policy gate** (P327, A3): ``Engine.select(entity, *, run)`` asks
  ``v3lum.core.policy.decide`` for every candidate module (the accepts filter and ``-M``/``-x``/
  ``-c`` choose the candidates; ``--preset deep``/``--all-modules`` make every ready module a
  candidate; nothing bypasses a gate). One ``PolicyContext`` is built per investigation
  (``policy.make_context``). ``Engine.decide_single`` is the same gate for ``v3lum run``.
* **Runs** (``Engine.run_module``): every run executes inside ``models.collect_results``;
  exceptions map to a status + canonical reason code (module contract section 3); partial runs keep
  their data; the disclosure ledger (``res.hosts``) and dataset citations are filled; finding ids are
  deterministic; every result passes the fail-closed sanitizer stage (P145) and the AR01 redaction
  pass; a run that overruns ``Module.timeout`` (+1 s grace) ends ERROR ``timeout`` with its findings,
  pivots and evidence dropped (AR05); health and the legacy per-module daily quota are recorded.
* **Two-phase scheduling per entity** (P376 cond 5, A13): PASSIVE modules are submitted first
  (case-DB sightings, then internal platforms, A12 order); LIGHT/ACTIVE modules wait until every
  passive run of that entity is absorbed, then ``policy.contact_guard`` decides (BLOCKED
  ``hostile_host`` -> coverage + manual link).
* **Deadlines and the kill switch** (AR05, A7): scan deadline = ``options.timeout_total`` when > 0,
  else setting ``scan_deadline`` (90 s; 0 = unlimited). On expiry, Ctrl+C or the end of the scope
  window the runtime cancel flag is set (the HTTP client and the socket connector refuse new
  requests), scheduling stops, every unfinished (module, entity) is recorded SKIPPED ``deadline``
  (``scope`` for the window) and ``case.partial[<reason>] = True`` with a note; results arriving
  later are dropped (no merge, no evidence).
* **Expansion rules** (AR07): ``Node.path_confidence`` below setting ``min_expand_confidence``,
  POSSIBLE identity pivots, ``similar_to``, noise, warninglisted values and SECRET_TYPES never
  auto-expand; from text/file/e-mail-header parents only IOC_TYPES do (INPUT_LIST_CAP), and
  PERSONAL_TYPES become ``expand=False`` entries of ``case.pending_personal`` unless
  ``options.expand_personal`` and ``options.purpose``.
* **TLP** (A2/AR17): seed TLP = ``options.seed_tlp.get(key, options.tlp)``; pivots and extracted
  entities inherit the highest TLP of their parents; ``ModuleResult.tlp`` markings raise the entity
  and case TLP; LIGHT/ACTIVE cases are at least AMBER.
* **Ownership** (A11/P378): with an org profile every asset node is ``own_asset``/``third_party``
  (tag, criticality) and findings copy their node's ownership.
* **Coverage v2** (P328): ``case.coverage[module]`` (summary status ranked by
  :data:`COVERAGE_RANK`, per-entity rows, per-source rows), ``case.execution``, ``case.answered``,
  ``case.skips``, ``case.deferred``, ``case.licence_used`` and the manual-link fallback (P311 cond 9).
* **Suppression stage** at the start of ``_finish`` (P322): SUP-warninglist, SUP-sinkhole and
  SUP-generic_address downgrade findings through ``Finding.downgrade`` (never deleting, never
  crossing an analyst override); then correlation rules, scoring and the pack links.
* **Case hooks**: ``runtime.case_hooks`` objects with ``on_case_start(case)``,
  ``on_before_finish(case)`` (after the BFS, before suppression/correlation/scoring) and
  ``on_case_end(case)``.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import ipaddress
import json
import logging
import re
import secrets
import threading
import time
import traceback
from collections import Counter
from collections.abc import Iterable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from v3lum import __version__, paths
from v3lum.core import correlate, sanitize, scoring, vocab
from v3lum.core import entities as _entities
from v3lum.core import links as linklib
from v3lum.core import tlp as _tlp
from v3lum.core.context import RunInfo, Runtime, ScanOptions
from v3lum.core.detect import Detection
from v3lum.core.entities import IOC_TYPES, PERSONAL_TYPES, SECRET_TYPES, Entity, EntityType
from v3lum.core.evidence import EvidenceStore
from v3lum.core.graph import Graph, Node, redact_secret_values, secret_value_map
from v3lum.core.models import (
    DEFAULT_REASON,
    OWNERSHIP_VALUES,
    STOP_REASONS,
    Confidence,
    ContractViolation,
    Correlation,
    Finding,
    ModuleResult,
    Opsec,
    Pivot,
    Status,
    collect_results,
    status_for,
    valid_reason,
)
from v3lum.core.module import REGISTRY, Module, load_modules, modules_for

log = logging.getLogger("v3lum.engine")

# Entity types never investigated automatically (analyst decides): privacy and blast radius.
# The canonical set lives in v3lum.core.entities (A8/AR24); this name is kept as an alias.
NO_AUTO_EXPAND = _entities.NO_AUTO_EXPAND

# Max children of one type expanded from a single parent entity.
EXPAND_CAP: dict[EntityType, int] = {
    EntityType.DOMAIN: 12, EntityType.IPV4: 10, EntityType.IPV6: 4, EntityType.URL: 5, EntityType.EMAIL: 10,
    EntityType.USERNAME: 5, EntityType.CVE: 30, EntityType.MD5: 5, EntityType.SHA1: 5, EntityType.SHA256: 10,
    EntityType.ASN: 3, EntityType.CIDR: 2, EntityType.ORG: 3, EntityType.CNPJ: 5, EntityType.PHONE: 5,
    EntityType.BTC: 5, EntityType.ETH: 5, EntityType.THREAT_ACTOR: 3, EntityType.MALWARE: 5, EntityType.MITRE: 15,
}
DEFAULT_CAP = 5
#: Cap per (parent, type) for IOCs extracted from text/file inputs (the analyst pasted them: all wanted).
INPUT_LIST_CAP = 200

#: Parents whose pivots are values extracted from analyst inputs (AR07): only IOC_TYPES auto-expand.
TEXT_PARENTS = frozenset({EntityType.TEXT, EntityType.FILE, EntityType.EMAIL_HEADERS})
#: Identity relations whose POSSIBLE pivots never auto-expand (AR07).
IDENTITY_RELATIONS = frozenset({"same_person", "uses_username", "uses_email", "has_account", "commit_email"})
#: Relations that never auto-expand (P333 cond 10).
NEVER_EXPAND_RELATIONS = frozenset({"similar_to"})
#: Entity types the org profile can own (ownership tags, A11).
ASSET_TYPES = frozenset({
    EntityType.DOMAIN, EntityType.URL, EntityType.EMAIL, EntityType.IPV4, EntityType.IPV6, EntityType.CIDR,
    EntityType.ASN, EntityType.CNPJ, EntityType.FAVICON_HASH, EntityType.CARD_BIN, EntityType.PAYMENT_CARD,
})

#: A run may overrun ``Module.timeout`` by this much before it ends ERROR 'timeout' (AR05).
RUN_GRACE = 1.0
#: Seconds between two checks of the scan loop (deadlines, overdue runs, scope window).
TICK = 0.05
#: Default of setting scan_deadline (seconds; 0 = unlimited).
DEFAULT_SCAN_DEADLINE = 90.0
#: Default of setting min_expand_confidence (AR07).
DEFAULT_MIN_EXPAND_CONFIDENCE = 0.5

#: Providers that publish submitted lookups never receive an investigated value, at any TLP (rule 7, A2).
PUBLISHES_REASON = "the provider publishes submitted lookups: it never receives an investigated value (rule 7)"

#: Coverage summary rank (P328 cond 3/7): could-not-verify statuses rank above empty, so 'blocked on
#: the seed, empty on a pivot' summarises as blocked; ok wins (the module answered somewhere).
COVERAGE_RANK: dict[str, int] = {
    "ok": 9, "quota": 8, "rate_limited": 7, "blocked": 6, "error": 5, "needs_key": 4,
    "unavailable": 3, "empty": 2, "skipped": 1, "not_run": 0,
}
_STATUS_RANK = COVERAGE_RANK  # v1 name

#: Run outcomes that emit the module's manual pivot link (P311 cond 9; refusals of the gate emit it
#: through ``Decision.emit_manual_link``): the source could not be queried automatically.
MANUAL_LINK_STATUSES = frozenset({Status.BLOCKED, Status.QUOTA, Status.NEEDS_KEY})

#: Execution-report outcome per status (P328 cond 2; partial runs are 'partial').
OUTCOMES: dict[Status, str] = {
    Status.OK: "completed", Status.EMPTY: "completed", Status.RATE_LIMITED: "rate_limited", Status.QUOTA: "quota",
    Status.ERROR: "failed", Status.BLOCKED: "failed", Status.NEEDS_KEY: "failed", Status.UNAVAILABLE: "failed",
    Status.SKIPPED: "skipped",
}

#: Finding tags a warninglist or a sinkhole downgrades (SUP-warninglist / SUP-sinkhole).
SUPPRESSED_TAGS = ("malicious", "suspicious", "phishing", "c2", "spam", "scanner")
#: Finding tags capped on generic/role/test addresses (SUP-generic_address, A4).
BREACH_TAGS = ("breach", "infostealer", "credential_exposure")
CONTEXT_ONLY = "context_only"
#: Names of the core suppression rules (P322 cond 4/8, P302 cond 7, A4 BR6).
SUPPRESSION_RULES = ("SUP-warninglist", "SUP-sinkhole", "SUP-generic_address")

#: Module name of the case-DB sightings lookup (P375): always first among passive runs (A12).
CASE_SIGHTINGS_MODULE = "case_sightings"
#: Internal-platform query order (A12): case DB, MISP/OpenCTI, TheHive, SIEM.
_INTERNAL_ORDER = (("misp", "opencti"), ("thehive",), ("siem", "splunk", "elastic", "sentinel", "qradar"))

#: Host suffixes that can only name internal infrastructure (typed internal seeds, AR02).
_INTERNAL_SUFFIXES = (".local", ".internal", ".lan", ".corp", ".home", ".intranet", ".localdomain")


@dataclass
class CaseResult:
    """Everything one investigation produced (``to_dict()`` is the stored case, schema 'v3lum.case/2')."""

    case_id: str
    created: str
    seeds: list[Entity]
    options: ScanOptions
    graph: Graph
    results: list[ModuleResult] = field(default_factory=list)
    correlations: list[Correlation] = field(default_factory=list)
    risk: dict[str, Any] = field(default_factory=dict)
    coverage: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: entity key -> [{'label', 'url', ...}] (pack links; manual-link fallbacks add 'manual': True)
    links: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    detections: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    duration: float = 0.0
    case_dir: str = ""
    interrupted: bool = False
    # ---- v2 (WP08) ---------------------------------------------------------------------------
    tlp: str = ""  # case TLP value (highest of the seeds and of the raised markings)
    partial: dict[str, bool] = field(default_factory=dict)  # why the case is partial: deadline | cancelled | window
    execution: list[dict[str, Any]] = field(default_factory=list)  # per (module, entity) execution report
    answered: dict[str, dict[str, Any]] = field(default_factory=dict)  # seed key -> answered/could-not-verify line
    skips: dict[str, list[str]] = field(default_factory=dict)  # reason code -> sorted module names
    pending_personal: list[dict[str, str]] = field(default_factory=list)  # personal values awaiting analyst selection
    meta: dict[str, Any] = field(default_factory=dict)  # run-level facts (runtime.meta at the end)
    org_profile_sha256: str = ""
    licence_profile: str = ""
    deferred: list[dict[str, str]] = field(default_factory=list)  # quota-deferred (module, entity) pairs
    licence_used: dict[str, dict[str, str]] = field(default_factory=dict)  # source id -> {class, basis}
    #: cache keys written/served during the case (HttpClient cache_key_sink); not serialised
    cache_keys: set[str] = field(default_factory=set)

    @property
    def findings(self) -> list[Finding]:
        return self.graph.findings()

    def timeline(self) -> list[dict[str, Any]]:
        return build_timeline(self.graph)

    def to_dict(self) -> dict[str, Any]:
        """The stored case (schema 'v3lum.case/2'; SECRET_TYPES values written redacted)."""
        findings = sorted(self.findings, key=lambda f: (-int(f.severity), -f.confidence))
        req = sum(r.requests for r in self.results)
        hits = sum(r.cache_hits for r in self.results)
        status_counts = Counter(r.status.value for r in self.results)
        data = {
            "schema": "v3lum.case/2",
            "tool": {"name": "V3LUM", "version": __version__},
            "case_id": self.case_id,
            "created": self.created,
            "tlp": self.tlp or case_tlp(self.options, self.seeds),
            "partial": dict(self.partial),
            "inputs": self.detections,
            "seeds": [s.key for s in self.seeds],
            "options": self.options.to_dict(),
            "summary": {
                "risk_score": self.risk.get("score", 0.0),
                "risk_level": self.risk.get("level", "clean"),
                "entities": len(self.graph.nodes),
                "investigated": sum(1 for n in self.graph.nodes.values() if n.investigated),
                "relations": len(self.graph.edges),
                "findings": len(findings),
                "findings_by_severity": dict(Counter(f.severity.label for f in findings)),
                "correlations": len(self.correlations),
                "module_runs": len(self.results),
                "module_status": dict(status_counts),
                "duration": round(self.duration, 2),
                "requests": req,
                "cache_hits": hits,
                "interrupted": self.interrupted,
                "partial": bool(self.partial),
            },
            "risk": self.risk,
            "entities": [n.to_dict() for n in self.graph.nodes.values()],
            "edges": [e.to_dict() for e in self.graph.edges],
            "findings": [f.to_dict() for f in findings],
            "correlations": [c.to_dict() for c in self.correlations],
            "modules": [r.to_dict() for r in self.results],
            "coverage": self.coverage,
            "execution": self.execution,
            "answered": self.answered,
            "skips": self.skips,
            "pending_personal": self.pending_personal,
            "deferred": self.deferred,
            "licence_used": self.licence_used,
            "licence_profile": self.licence_profile,
            "links": {k: [dict(item) for item in v] for k, v in self.links.items()},
            "timeline": self.timeline(),
            "notes": self.notes,
            "meta": self.meta,
            "org_profile_sha256": self.org_profile_sha256,
            "case_dir": self.case_dir,
        }
        return redact_secret_values(data, self._secret_values())

    def _secret_values(self) -> dict[str, str]:
        """Raw SECRET_TYPES values seen in the case -> their persisted (redacted) form (item 12)."""

        def entities() -> Iterable[Any]:
            yield from (node.entity for node in self.graph.nodes.values())
            for res in self.results:
                yield res.entity
                yield from (pv.entity for pv in res.pivots)
            yield from self.seeds

        return secret_value_map(entities())


def case_tlp(options: ScanOptions, seeds: list[Entity]) -> str:
    """Highest TLP of the seeds (per-seed ``options.seed_tlp`` when given, else ``options.tlp``)."""
    default = getattr(options, "tlp", "") or "amber"
    per_seed = getattr(options, "seed_tlp", None) or {}
    values = [per_seed.get(s.key, default) for s in seeds] or [default]
    return _tlp_value(*values)


def _tlp_value(*values: Any) -> str:
    """The most restrictive of ``values`` as a TLP value string; unreadable -> 'red' (fail closed)."""
    try:
        return _tlp.highest(*values).value_str
    except ValueError:
        return _tlp.TLP.RED.value_str


#: Case ids name a directory under paths.cases_dir(): no separators, no '..'.
_CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


def new_case_id(now: _dt.datetime | None = None) -> str:
    now = now or _dt.datetime.now(_dt.timezone.utc)
    return now.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)


#: Core timeline attributes (alias of vocab.CORE_TIMELINE); fragments add more via vocab.
_DATE_ATTRS = vocab.CORE_TIMELINE


def build_timeline(graph: Graph) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for node in graph.nodes.values():
        for attr, label in vocab.timeline_attributes().items():
            for value, src in node.attributes.get(attr, []):
                date = _iso_date(value)
                if date:
                    events.append({"date": date, "entity": node.key, "event": label, "source": src})
        for f in node.findings:
            date = _iso_date(f.data.get("date")) if isinstance(f.data, dict) else None
            if date:
                events.append({"date": date, "entity": node.key, "event": f.title, "source": f.module})
    uniq = {(e["date"], e["entity"], e["event"]): e for e in events}
    return sorted(uniq.values(), key=lambda e: e["date"])


def _iso_date(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (int, float)) and value > 10**8:  # epoch seconds
        try:
            return _dt.datetime.fromtimestamp(float(value), _dt.timezone.utc).date().isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", str(value))
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    m = re.match(r"^(\d{2})/(\d{2})/(\d{4})", str(value))
    if m:
        return f"{m.group(3)}-{m.group(2)}-{m.group(1)}"
    return None


# ----------------------------------------------------------------------------------------
# Decisions made by the engine itself (fail-closed policy errors, stopped scans)
# ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class EngineDecision:
    """A refusal the engine records itself, with the attribute names of ``policy.Decision``:
    the policy gate could not be evaluated (fail closed) or the scan stopped before the run."""

    allowed: bool
    status: Status
    reason_code: str
    reason: str
    rule_id: str = ""
    allowed_sources: frozenset[str] | None = None
    emit_manual_link: bool = False
    licence_basis: dict[str, str] = field(default_factory=dict)


def _policy() -> Any:
    """The policy module (imported lazily: a sibling mid-edit never breaks importing the engine)."""
    try:
        from v3lum.core import policy
    except Exception as exc:  # noqa: BLE001 - fail closed: nothing runs without the gate
        log.error("policy gate unavailable: %s: %s", type(exc).__name__, exc)
        return None
    return policy


def _refusal(reason: str, code: str = "policy", status: Status = Status.SKIPPED, rule_id: str = "") -> EngineDecision:
    return EngineDecision(False, status, code, _redact(reason), rule_id)


def _status_of(decision: Any) -> Status:
    try:
        return Status(getattr(decision, "status", Status.SKIPPED))
    except ValueError:
        return Status.SKIPPED


def _code_of(decision: Any, status: Status) -> str:
    code = str(getattr(decision, "reason_code", "") or "")
    return code if valid_reason(status, code) else DEFAULT_REASON.get(status, "")


# ----------------------------------------------------------------------------------------
# Exception -> outcome mapping (module_author_contract section 3)
# ----------------------------------------------------------------------------------------


def _exc_class(module_name: str, name: str) -> type[BaseException] | None:
    """Look an exception class up at call time (siblings may add it after this file was imported)."""
    import importlib

    try:
        mod = importlib.import_module(module_name)
    except ImportError:  # pragma: no cover - defensive
        return None
    cls = getattr(mod, name, None)
    return cls if isinstance(cls, type) and issubclass(cls, BaseException) else None


def _isinstance(exc: BaseException, module_name: str, name: str) -> bool:
    cls = _exc_class(module_name, name)
    return cls is not None and isinstance(exc, cls)


def _redact(text: str) -> str:
    """Pass a message through the central redactor (AR01) when it is available."""
    if not text:
        return text
    try:
        from v3lum.core import redact
    except ImportError:  # pragma: no cover - redactor not installed yet
        return text
    try:
        return str(redact.redact_text(text))
    except Exception:  # pragma: no cover - the redactor must never break a run
        return text


def _code(exc: BaseException, status: Status, default: str) -> str:
    code = str(getattr(exc, "reason_code", "") or "")
    return code if valid_reason(status, code) else default


def _pick_result(built: list[ModuleResult], name: str, entity: Entity) -> ModuleResult | None:
    """The result the module was building for ``entity`` (never one built for another entity:
    its facts would be attributed to the wrong subject)."""
    for res in built:
        if res.module == name and res.entity == entity:
            return res
    for res in built:
        if res.entity == entity:
            return res
    return None


def _is_contact(cls: type[Module]) -> bool:
    """LIGHT/ACTIVE modules contact the target (two-phase scheduling, contact guard)."""
    try:
        return Opsec.parse(getattr(cls, "opsec", Opsec.PASSIVE)) >= Opsec.LIGHT
    except (KeyError, ValueError):
        return False


def _passive_rank(cls: type[Module]) -> int:
    """Order of passive submissions (A12): case-DB sightings, internal platforms (MISP/OpenCTI,
    TheHive, SIEM, others), then every other source."""
    if cls.name == CASE_SIGHTINGS_MODULE:
        return 0
    if getattr(cls, "disclosure", "") != "internal":
        return 9
    ident = f"{cls.name} {getattr(cls, 'provider', '')}".lower()
    for rank, names in enumerate(_INTERNAL_ORDER, start=1):
        if any(n in ident for n in names):
            return rank
    return len(_INTERNAL_ORDER) + 1


@dataclass
class _Job:
    """One (module, entity) run scheduled by an investigation."""

    cls: type[Module]
    entity: Entity
    run: Any
    decision: Any
    depth: int
    contact: bool

    @property
    def pair(self) -> tuple[str, str]:
        return (self.cls.name, self.entity.key)

    @property
    def timeout(self) -> float:
        try:
            return max(0.0, float(getattr(self.cls, "timeout", 60.0) or 0.0))
        except (TypeError, ValueError):
            return 60.0


class Engine:
    """Runs modules on entities through the policy gate and investigates seeds (see the module doc)."""

    def __init__(self, runtime: Runtime, options: ScanOptions | None = None, *, reliability: dict[str, float] | None = None) -> None:
        self.runtime = runtime
        self.options = options or ScanOptions()
        if self.options.include_disabled and self.options.preset != "deep":
            self.options.preset = "deep"  # --all-modules is an alias of --preset deep (A3)
        self.reliability = reliability or {}
        self._pctx: Any = None  # the PolicyContext of the running investigation
        self._pctx_error = ""
        load_modules(extra_dirs=[str(paths.plugins_dir())])
        correlate.load_rules()

    # ------------------------------------------------------------------ policy
    def policy_context(self, *, graph: Graph | None = None, path: str = "scan", explicit: Iterable[str] | None = None) -> Any:
        """A new ``policy.PolicyContext`` for this engine's runtime and options (None when the
        policy module or the context cannot be built: every decision then fails closed)."""
        pol = _policy()
        if pol is None:
            self._pctx_error = "policy gate unavailable (v3lum.core.policy failed to load)"
            return None
        names = set(self.options.include) if explicit is None else set(explicit)
        try:
            pctx = pol.make_context(self.runtime, self.options, explicit=names, graph=graph, path=path)
        except Exception as exc:  # noqa: BLE001 - e.g. a research profile without a legal basis
            self._pctx_error = _redact(f"policy context unavailable: {type(exc).__name__}: {exc}")
            return None
        self._pctx_error = ""
        return pctx

    def _context_for_select(self) -> Any:
        """The running investigation's context, else a fresh one: outside a scan every listing
        decides with the current keys, licence allow-list, org profile, health and time (a context
        cached for the engine's lifetime would keep e.g. a key the analyst has since configured
        reading needs_key)."""
        if self._pctx is not None:
            return self._pctx
        return self.policy_context()

    def _decide(self, cls: type[Module], entity: Entity, pctx: Any, run: Any) -> Any:
        """``policy.decide`` with fail-closed error handling (a policy bug never runs a module)."""
        pol = _policy()
        if pol is None or pctx is None:
            return _refusal(f"skipped: {self._pctx_error or 'policy gate unavailable'} (fail closed)")
        try:
            return pol.decide(cls, entity, pctx, run=run)
        except Exception as exc:  # noqa: BLE001
            if vocab.strict_enabled():  # tests surface policy bugs; analysts get a fail-closed skip
                raise
            log.error("policy.decide failed for %s: %s", cls.name, exc)
            return _refusal(f"skipped: policy error ({type(exc).__name__}) - fail closed")

    def _guard(self, cls: type[Module], entity: Entity, pctx: Any, run: Any) -> Any:
        """``policy.contact_guard`` for LIGHT/ACTIVE runs (fail closed on errors)."""
        pol = _policy()
        if pol is None or pctx is None:
            return _refusal(f"blocked: {self._pctx_error or 'policy gate unavailable'} (fail closed)", "hostile_host", Status.BLOCKED, "GUARD-01")
        try:
            return pol.contact_guard(cls, entity, pctx, run=run)
        except Exception as exc:  # noqa: BLE001
            if vocab.strict_enabled():
                raise
            log.error("policy.contact_guard failed for %s: %s", cls.name, exc)
            return _refusal(f"blocked: contact guard error ({type(exc).__name__}) - fail closed", "hostile_host", Status.BLOCKED, "GUARD-01")

    # ------------------------------------------------------------------ planning
    def candidates(self, entity: Entity) -> list[type[Module]]:
        """Modules accepting ``entity`` after the selection filters (-M include, -x exclude,
        -c categories); every one of them still goes through the policy gate."""
        opts = self.options
        out: list[type[Module]] = []
        for cls in modules_for(entity.type):
            explicit = cls.name in opts.include
            if opts.include and not explicit:
                continue
            if cls.name in opts.exclude:
                continue
            if opts.categories and cls.category not in opts.categories and not explicit:
                continue
            out.append(cls)
        return out

    def select(self, entity: Entity, *, run: Any = None) -> tuple[list[tuple[type[Module], Any]], list[tuple[type[Module], Any]]]:
        """``(runnable, blocked)`` for ``entity``: lists of ``(module class, Decision)``.

        Every candidate goes through ``policy.decide`` with ``run`` (a RunInfo; default: an
        analyst-typed seed at depth 0). Nothing bypasses a gate (P327 cond 1, A3).
        """
        run = run if run is not None else self._run_info(entity, is_seed=True, depth=0, provenance=(), case_id="", tlp=self._seed_tlp(entity))
        pctx = self._context_for_select()
        runnable: list[tuple[type[Module], Any]] = []
        blocked: list[tuple[type[Module], Any]] = []
        for cls in self.candidates(entity):
            decision = self._decide(cls, entity, pctx, run)
            (runnable if getattr(decision, "allowed", False) else blocked).append((cls, decision))
        return runnable, blocked

    def decide_single(self, cls: type[Module], entity: Entity, *, path: str = "run") -> Any:
        """The policy decision for one analyst-requested run (``v3lum run``): ``policy.decide`` with
        the module explicit and the entity an analyst-typed seed, then - for LIGHT/ACTIVE modules -
        ``policy.contact_guard`` (on by default on every path, A13). Returns the first refusal or the
        allowing Decision."""
        pctx = self.policy_context(path=path, explicit=set(self.options.include) | {cls.name})
        run = self._run_info(entity, is_seed=True, depth=0, provenance=(), case_id="", tlp=self._seed_tlp(entity))
        decision = self._decide(cls, entity, pctx, run)
        if getattr(decision, "allowed", False) and _is_contact(cls):
            guard = self._guard(cls, entity, pctx, run)
            if not getattr(guard, "allowed", False):
                return guard
        return decision

    def plan(self, entity: Entity) -> list[dict[str, Any]]:
        """Rows for ``v3lum plan``-style listings: every candidate with its decision."""
        runnable, blocked = self.select(entity)
        rows = [
            {"module": c.name, "title": c.title, "category": c.category, "ready": True, "reason": "ready", "status": "", "reason_code": "", "rule_id": ""}
            for c, _d in runnable
        ]
        for c, d in blocked:
            status = _status_of(d)
            rows.append({
                "module": c.name, "title": c.title, "category": c.category, "ready": False, "reason": str(getattr(d, "reason", "") or ""),
                "status": status.value, "reason_code": _code_of(d, status), "rule_id": str(getattr(d, "rule_id", "") or ""),
            })
        return rows

    # ------------------------------------------------------------------ execution
    def run_module(self, cls: type[Module], entity: Entity, case_dir: Path | None = None, *, run: Any = None, decision: Any = None) -> ModuleResult:
        """Run one module on one entity and map its outcome (never raises, except strict contract violations).

        No policy decision is taken here (callers decide through ``select``/``decide_single``);
        team rule 7 is enforced again as a last line of defence. ``decision`` (optional, e.g. the
        result of :meth:`decide_single` for ``v3lum run``) is applied, never re-taken: a refusal
        returns its status/reason_code/reason without running anything, and an allowing decision
        hands its ``allowed_sources`` to the run (``ctx.allowed_sources``: aggregators never query a
        licence-blocked feed on the single-run path either).
        """
        rt = self.runtime
        fallback = ModuleResult(module=cls.name, entity=entity)  # created outside the collector
        res = fallback
        ctx: Any = None
        start = time.monotonic()
        if getattr(cls, "publishes_queries", False) is True:  # rule 7 on every path (scan, `v3lum run`, tests)
            return self._finalize(fallback.mark(Status.SKIPPED, PUBLISHES_REASON, reason_code="policy"), cls, entity, None, start)
        if decision is not None and not getattr(decision, "allowed", False):
            status = _status_of(decision)
            if status in (Status.OK, Status.EMPTY):
                status = Status.SKIPPED
            reason = _redact(str(getattr(decision, "reason", "") or "")) or DEFAULT_REASON.get(status, "")
            return self._finalize(fallback.mark(status, reason, reason_code=_code_of(decision, status)), cls, entity, None, start)
        if run is None:
            # a single run (`v3lum run`, direct callers) is an analyst-typed seed: ctx.entity, ctx.is_seed
            # and the ctx.state guard on the investigated value need the entity
            allowed = getattr(decision, "allowed_sources", None) if decision is not None else None
            run = self._run_info(
                entity, is_seed=True, depth=0, provenance=(), case_id="", tlp=self._seed_tlp(entity),
                allowed_sources=frozenset(allowed) if allowed is not None else None,
            )
        elif decision is not None and getattr(decision, "allowed_sources", None) is not None and getattr(run, "allowed_sources", None) is None:
            run = dataclasses.replace(run, allowed_sources=frozenset(decision.allowed_sources))
        rt.events.emit("module_start", module=cls.name, entity=entity)
        with collect_results() as built:
            try:
                # the context is built inside the guard: a refusal while scoping the run (policy,
                # configuration) maps to a status like any other, it never escapes run_module
                ctx = rt.context(cls, self.options, case_dir, run=run)
                mod = cls()
                if not mod.applies(entity, ctx):
                    res.mark(Status.SKIPPED, "not applicable", reason_code="not_applicable")
                else:
                    out = mod.run(entity, ctx)
                    if isinstance(out, ModuleResult):
                        res = out
                    else:
                        # a run() that returns no result is a module bug: whatever the source answered,
                        # it must never read as 'nothing found' (rule 5)
                        res.mark(Status.ERROR, f"run() returned {type(out).__name__}, not a ModuleResult (module bug): could not verify", reason_code="error")
                    if res.status is Status.OK and not res.has_data:
                        res.status = Status.EMPTY
            except ContractViolation as exc:
                if vocab.strict_enabled():
                    raise
                res = self._error(fallback, "error", _redact(f"contract violation: {exc}"))
            except Exception as exc:
                res = self._outcome(exc, cls, entity, built, fallback)
        res = self._finalize(res, cls, entity, ctx, start)
        self._record_health(cls, res)
        return res

    def _error(self, res: ModuleResult, code: str, message: str = "") -> ModuleResult:
        res.mark(Status.ERROR, message or "error", reason_code=code)
        return res

    def _outcome(self, exc: Exception, cls: type[Module], entity: Entity, built: list[ModuleResult], fallback: ModuleResult) -> ModuleResult:
        """Map an exception raised by Module.run to (status, reason_code, partial, stop_reason)."""
        message = _redact(str(exc)) or type(exc).__name__
        H, D = "v3lum.core.http", "v3lum.core.datasets"

        def recovered(stop_reason: str, note: str) -> ModuleResult:
            res = _pick_result(built, cls.name, entity) or fallback
            res.stop(stop_reason)
            if res.status not in (Status.OK, Status.EMPTY):
                # the module already recorded an outcome (blocked, rate limited...) before it was
                # stopped: keep it, a stop must never turn 'could not verify' into ok/empty (rule 5)
                if not valid_reason(res.status, res.reason_code):
                    res.reason_code = DEFAULT_REASON[res.status]
            else:
                res.status = Status.OK if res.has_data else Status.EMPTY
                res.reason_code = ""
            res.error = (res.error + "; " if res.error else "") + note
            return res

        if _isinstance(exc, H, "Cancelled"):
            candidates = (getattr(self.runtime, "cancel_reason", ""), getattr(exc, "stop_reason", ""))
            reason = next((str(c) for c in candidates if c and str(c) in STOP_REASONS), "cancelled")
            return recovered(reason, f"stopped: {reason} (partial results)")
        if _isinstance(exc, H, "RequestCapReached"):
            return recovered("request_cap", f"request cap reached ({getattr(cls, 'max_requests', '?')} per entity): partial results")
        if _isinstance(exc, H, "QuotaExceeded"):
            res = _pick_result(built, cls.name, entity)
            if res is not None and res.has_data:
                return recovered("quota", f"quota exhausted mid-run: {message}")
            return fallback.mark(Status.QUOTA, message, reason_code=_code(exc, Status.QUOTA, "quota"))
        if _isinstance(exc, H, "RateLimited"):
            res = _pick_result(built, cls.name, entity)
            if res is not None and res.has_data:
                return recovered("rate_limited", f"rate limited mid-run: {message}")
            return fallback.mark(Status.RATE_LIMITED, message, reason_code="rate_limited")
        if _isinstance(exc, H, "Blocked"):
            return fallback.mark(Status.BLOCKED, message, reason_code=_code(exc, Status.BLOCKED, "challenge"))
        if _isinstance(exc, H, "AuthRequired"):
            if cls.requires_keys or cls.optional_keys:
                return fallback.mark(Status.NEEDS_KEY, message, reason_code="needs_key")
            return fallback.mark(Status.BLOCKED, message or "keyless source refused the request: could not verify", reason_code="challenge")
        if _isinstance(exc, H, "PolicyError"):
            return fallback.mark(Status.SKIPPED, message, reason_code=_code(exc, Status.SKIPPED, "policy"))
        if _isinstance(exc, H, "ConfigError"):
            return fallback.mark(Status.SKIPPED, message, reason_code="config")
        if _isinstance(exc, H, "DeadlineExceeded"):
            return fallback.mark(Status.ERROR, message, reason_code="timeout")
        if _isinstance(exc, D, "DatasetUnavailable"):
            return fallback.mark(Status.UNAVAILABLE, message, reason_code="dataset")
        if _isinstance(exc, D, "DatasetError"):
            # a dataset fetch that failed for a canonical reason (challenge page, quota, rate limit...)
            # keeps that outcome: could not verify, never a module bug (rule 5)
            code = str(getattr(exc, "reason_code", "") or "error")
            try:
                status = status_for(code)
            except ValueError:
                status, code = Status.ERROR, "error"
            if status in (Status.OK, Status.EMPTY):
                status, code = Status.ERROR, "error"
            return fallback.mark(status, message, reason_code=code)
        if _isinstance(exc, "v3lum.core.tools", "ToolUnavailable"):  # external binary missing (WP11)
            return fallback.mark(Status.UNAVAILABLE, message, reason_code="package")
        if _isinstance(exc, H, "OfflineError"):
            return fallback.mark(Status.UNAVAILABLE, message, reason_code="offline")
        if _isinstance(exc, H, "NetworkError") or _isinstance(exc, H, "HttpError"):
            return fallback.mark(Status.ERROR, message, reason_code=_code(exc, Status.ERROR, "error"))
        # module bug: keep going, keep the (redacted) trace for --debug
        fallback.mark(Status.ERROR, f"{type(exc).__name__}: {message}", reason_code="error")
        fallback.raw = {"traceback": _redact(traceback.format_exc(limit=6))}
        return fallback

    def _finalize(self, res: ModuleResult, cls: type[Module], entity: Entity, ctx: Any, start: float) -> ModuleResult:
        res.module = cls.name
        res.entity = entity
        res.duration = time.monotonic() - start
        http = getattr(ctx, "http", None)
        res.requests = int(getattr(http, "requests", 0) or 0)
        res.cache_hits = int(getattr(http, "cache_hits", 0) or 0)
        res.hosts = _merge_hosts(getattr(http, "hosts", None), getattr(getattr(ctx, "doh", None), "hosts", None))
        res.datasets = [dict(d) for d in (getattr(getattr(ctx, "data", None), "used", None) or []) if isinstance(d, dict)]
        log_entries = getattr(http, "request_log", None)
        res._request_log = list(log_entries) if isinstance(log_entries, list) else []  # evidence context (not serialised)
        if cls.daily_quota and res.requests:
            try:
                self.runtime.quota.add(cls.name, res.requests)
            except Exception:  # pragma: no cover - quota bookkeeping must never fail a run
                pass
        deadline = getattr(ctx, "deadline", None)
        if deadline is not None and self.runtime.clock.monotonic() > float(deadline) + RUN_GRACE:
            # AR05: the run overran its deadline - whatever it built arrives too late to be trusted
            _drop_data(res)
            res.mark(Status.ERROR, f"run exceeded its {getattr(cls, 'timeout', 0):.0f}s deadline: results dropped (could not verify)", reason_code="timeout")
        if len(res.pivots) > cls.max_pivots:
            dropped = len(res.pivots) - cls.max_pivots
            res.pivots = res.pivots[: cls.max_pivots]
            res.error = (res.error + "; " if res.error else "") + f"{dropped} extra pivots dropped (cap {cls.max_pivots})"
        if res.status in (Status.OK, Status.EMPTY):
            res.reason_code = ""  # ok/empty carry no reason code (partial runs use stop_reason)
        elif not valid_reason(res.status, res.reason_code):
            res.reason_code = DEFAULT_REASON[res.status]
        for f in res.findings:
            f.module = cls.name
            if f.entity is None:
                f.entity = entity
        res.error = _redact(res.error)
        try:
            out = sanitize.sanitize_result(res, cls)
            res = out if isinstance(out, ModuleResult) else res
            _redact_result(res)  # AR01: no key value reaches the graph, events, case JSON or reports
        except Exception as exc:  # fail closed (P145 cond 2): drop everything the module produced
            _drop_data(res)
            res.redacted_fields = ["raw", "result"]
            res.mark(Status.ERROR, _redact(f"sanitizer failed, result dropped: {type(exc).__name__}"), reason_code="sanitizer")
        _unique_finding_ids(res)
        return res

    def _health_state(self) -> Any:
        health = getattr(self._pctx, "health", None) if self._pctx is not None else None
        if health is None:
            health = getattr(self.runtime, "health", None)
        return health

    def _record_health(self, cls: type[Module], res: ModuleResult) -> None:
        """health.record_run for every run (A3 demotion data); saved at once outside a scan."""
        health = self._health_state()
        fn = getattr(health, "record_run", None)
        if not callable(fn):
            return
        try:
            fn(cls.name, float(res.duration), res.status.value)
            if not getattr(health, "autosave", True) and not getattr(self.runtime, "in_scan", False):
                save = getattr(health, "save", None)
                if callable(save):
                    save()
        except Exception as exc:  # noqa: BLE001 - health bookkeeping never fails a run
            log.warning("health record failed for %s: %s", cls.name, type(exc).__name__)

    def _seed_tlp(self, entity: Entity) -> str:
        opts = self.options
        value = _tlp_value((opts.seed_tlp or {}).get(entity.key, opts.tlp or "amber"))
        if _contact_mode(opts):
            value = _tlp_value(value, "amber")
        return value

    def _run_info(
        self,
        entity: Entity,
        *,
        is_seed: bool,
        depth: int,
        provenance: tuple[tuple[str, str, str], ...],
        case_id: str,
        tlp: str = "",
        allowed_sources: frozenset[str] | None = None,
        internal_seed: bool | None = None,
    ) -> RunInfo:
        return RunInfo(
            entity=entity,
            is_seed=is_seed,
            depth=depth,
            provenance=provenance,
            allowed_sources=allowed_sources,
            tlp=tlp,
            case_id=case_id,
            priority=_priority(depth),
            internal_seed=bool(is_seed and _internal_target(entity)) if internal_seed is None else bool(internal_seed),
        )

    # ------------------------------------------------------------------ investigation
    def investigate(
        self,
        seeds: list[Entity],
        *,
        detections: list[Detection] | None = None,
        case_id: str | None = None,
        only_pairs: dict[tuple[str, str], dict[str, Any]] | None = None,
    ) -> CaseResult:
        """Investigate the seeds (pipelined BFS through the policy gate), then correlate and score.

        ``only_pairs`` (default ``options.only_pairs``) restricts scheduling to the given
        ``(module, entity_key)`` pairs, each run with its recorded ``{is_seed, depth, provenance,
        tlp}`` (``cases resume``): those entities are never promoted to typed seeds and their pivots
        are recorded, not expanded.
        """
        rt = self.runtime
        previous = bool(getattr(rt, "in_scan", False))
        rt.in_scan = True  # AR10: large datasets are never downloaded while a scan runs
        try:
            pairs = only_pairs if only_pairs is not None else getattr(self.options, "only_pairs", None)
            return _Scan(self, seeds, detections=detections, case_id=case_id, only_pairs=pairs).execute()
        finally:
            rt.in_scan = previous
            health = self._health_state()
            self._pctx = None
            rt.cache_key_collector = None
            rt.policy_context = None
            save = getattr(health, "save", None)
            if callable(save) and not getattr(health, "autosave", True):
                try:
                    save()
                except Exception as exc:  # noqa: BLE001
                    log.warning("health state not saved: %s", type(exc).__name__)

    def rule_context(self) -> correlate.RuleContext:
        """The RuleContext handed to correlation rules after the BFS."""
        rt = self.runtime
        try:
            org = getattr(rt, "org", None)
        except Exception:  # org profile problems never break a scan
            org = None
        return correlate.RuleContext(
            now=rt.now(),
            org=org,
            options=self.options,
            providers=getattr(rt, "providers", None),
            settings=rt.config,
            meta=dict(getattr(rt, "meta", None) or {}),
        )

    def _finish(self, case: CaseResult) -> None:
        """Suppression stage, correlation rules, scoring and the manual pivot links."""
        graph = case.graph
        suppress(case)
        _inconclusive_note(case)
        case.correlations = correlate.run_rules(graph, case.results, rctx=self.rule_context())
        for corr in case.correlations:
            self.runtime.events.emit("correlation", correlation=corr)
        case.risk = scoring.score(graph, case.correlations, self.reliability)
        # Manual pivot links for the most relevant entities, with the metadata the renderers need
        # (P311 cond 5-8: host, touches_target, privacy, badge...). privacy=true links only for
        # analyst-typed seeds of a case that opted in (P311 cond 6), never for discovered entities.
        relevant = [n for n in graph.nodes.values() if not n.noise and (n.seed or n.depth <= 1)]
        relevant.sort(key=lambda n: (not n.seed, n.depth))
        unconfirmed = set(self.options.unconfirmed_seeds or ())
        opted_in = bool(self.options.show_personal and self.options.purpose)
        for node in relevant[:40]:
            typed = bool(node.seed and node.key not in unconfirmed)
            try:
                rendered = linklib.pivot_links_for(node.entity, include_privacy=typed and opted_in)
            except Exception:  # noqa: BLE001 - pack problems are reported by links.errors()
                rendered = []
            for item in rendered:
                _add_link(case, node.key, _link_item(item))


# ----------------------------------------------------------------------------------------
# One investigation
# ----------------------------------------------------------------------------------------


class _Scan:
    """State of one ``Engine.investigate`` call (the engine thread owns every mutation)."""

    def __init__(self, engine: Engine, seeds: list[Entity], *, detections: list[Detection] | None, case_id: str | None, only_pairs: Any) -> None:
        self.engine = engine
        self.rt = rt = engine.runtime
        self.opts = opts = engine.options
        case_id = case_id or new_case_id(rt.now())
        if not _CASE_ID_RE.match(case_id):  # it names a directory: never a path
            raise ValueError(f"invalid case id {case_id!r}")
        self.case_dir = paths.cases_dir() / case_id
        self.evidence = EvidenceStore(self.case_dir, now=rt.now) if opts.save_evidence else None
        self.graph = Graph()
        self.case = CaseResult(
            case_id=case_id,
            created=rt.now().isoformat(timespec="seconds"),
            seeds=list(dict.fromkeys(seeds)),
            options=opts,
            graph=self.graph,
            case_dir=str(self.case_dir),
            detections=[
                {"type": d.type.value, "value": d.value, "confidence": d.confidence, "reason": d.reason} for d in (detections or [])
            ],
        )
        self.resume: dict[tuple[str, str], dict[str, Any]] | None = dict(only_pairs) if only_pairs is not None else None
        self.pool: ThreadPoolExecutor | None = None
        self.futures: dict[Future[ModuleResult], _Job] = {}
        self.started: dict[tuple[str, str], float] = {}
        self.pairs: set[tuple[str, str]] = set()
        self.done: set[tuple[str, str]] = set()
        self.passive_left: Counter[str] = Counter()
        self.held: dict[str, list[_Job]] = {}
        self.expanded: Counter[tuple[str, EntityType]] = Counter()
        self.provenance: dict[str, tuple[tuple[str, str, str], ...]] = {}
        self.seed_of: dict[str, str] = {}
        self.budget_note = False
        self.stop = ""  # '' | 'deadline' | 'cancelled' | 'window'
        self.scan_end: float | None = None
        self.deadline_s = 0.0
        self.org: Any = None
        self.min_expand = DEFAULT_MIN_EXPAND_CONFIDENCE
        self.personal_ok = bool(opts.expand_personal and opts.purpose)
        self.seen_personal: set[tuple[str, str]] = set()

    # ------------------------------------------------------------------ driver
    def execute(self) -> CaseResult:
        eng, rt, opts, case = self.engine, self.rt, self.opts, self.case
        # a fresh kill switch per scan: runs abandoned by an earlier scan of this runtime keep the
        # old (set) flag and send nothing more
        rt.cancel_event = threading.Event()
        rt.cancel_reason = ""  # a previous scan's stop reason must not label this one
        reset_circuit = getattr(rt.http, "reset_circuit", None)
        if callable(reset_circuit):  # hosts short-circuited by a challenge in an earlier scan get a new chance
            reset_circuit()
        self._reset_quota_run()
        if self.evidence is not None:
            self.evidence.ensure_dirs()
        rt.cache_key_collector = case.cache_keys
        self._load_settings()
        self._load_org()
        eng._pctx = eng.policy_context(graph=self.graph, path="scan", explicit=self._explicit())
        rt.policy_context = eng._pctx  # redirect hops of LIGHT/ACTIVE requests re-run the guard with it
        case.licence_profile = _licence_profile(rt, opts, eng._pctx)  # the profile the gate enforces
        if eng._pctx is None and eng._pctx_error:
            case.notes.append(f"{eng._pctx_error}: every module was skipped (fail closed)")
        for note in getattr(eng._pctx, "notes", None) or ():
            if note not in case.notes:
                case.notes.append(_redact(str(note)))
        # the case TLP as far as it is known before any module runs (on_case_start hooks such as the
        # audit record, the live feed); _summaries recomputes it with the markings at the end
        case.tlp = _tlp_value(*[self.engine._seed_tlp(s) for s in case.seeds] or [case_tlp(opts, case.seeds)])
        self._hooks("on_case_start")
        begin = time.monotonic()
        rt.events.emit("scan_start", case_id=case.case_id, seeds=case.seeds, options=opts)
        self.pool = ThreadPoolExecutor(max_workers=max(1, int(opts.threads or 1)), thread_name_prefix="v3lum")
        try:
            self._seed()
            self._loop()
        except KeyboardInterrupt:
            self._halt("cancelled")
        finally:
            self._close()
        self._hooks("on_before_finish")
        self._summaries()
        eng._finish(case)
        self._final_meta()
        case.duration = time.monotonic() - begin
        self._hooks("on_case_end")
        rt.events.emit("scan_done", case=case)
        return case

    def _reset_quota_run(self) -> None:
        """A new run for the quota book (P334): in-memory backoffs ('for the rest of this run'),
        token buckets, this run's provider signals and per-run deferral counts start over, so one
        scan's state never leaks into the next scan of the same runtime (shell) or into its
        ``quota_lines``; persisted counters and recorded signals stay."""
        try:
            book = self.rt.quota
        except Exception as exc:  # noqa: BLE001 - an unavailable quota DB is reported by the HTTP client
            log.warning("quota book unavailable: %s", type(exc).__name__)
            return
        reset = getattr(book, "reset_run", None)
        if callable(reset):
            try:
                reset()
            except Exception as exc:  # noqa: BLE001
                log.warning("quota run reset failed: %s", type(exc).__name__)

    def _explicit(self) -> set[str]:
        names = set(self.opts.include)
        if self.resume is not None:
            names |= {module for module, _key in self.resume}  # the analyst asked for these pairs
        return names

    def _load_settings(self) -> None:
        cfg, opts = self.rt.config, self.opts
        try:
            total = float(opts.timeout_total or 0.0)
        except (TypeError, ValueError):
            total = 0.0
        if total <= 0:
            try:
                total = float(cfg.get("scan_deadline", DEFAULT_SCAN_DEADLINE) or 0.0)
            except (TypeError, ValueError):
                total = DEFAULT_SCAN_DEADLINE
        self.deadline_s = max(0.0, total)
        self.scan_end = self.rt.clock.monotonic() + self.deadline_s if self.deadline_s > 0 else None
        try:
            self.min_expand = float(cfg.get("min_expand_confidence", DEFAULT_MIN_EXPAND_CONFIDENCE))
        except (TypeError, ValueError):
            self.min_expand = DEFAULT_MIN_EXPAND_CONFIDENCE

    def _load_org(self) -> None:
        try:
            org = self.rt.org
        except Exception as exc:  # noqa: BLE001 - org profile problems never break a scan
            log.warning("org profile unavailable: %s", type(exc).__name__)
            org = None
        self.org = org if org is not None and not getattr(org, "is_empty", True) else None
        self.case.org_profile_sha256 = str(getattr(org, "sha256", "") or "") if org is not None else ""

    def _hooks(self, name: str) -> None:
        """Call ``name(case)`` on every runtime case hook. on_case_start errors abort the scan (fail
        closed: e.g. an audit record that cannot be written); later hooks only leave a note."""
        for hook in list(getattr(self.rt, "case_hooks", None) or ()):
            fn = getattr(hook, name, None)
            if not callable(fn):
                continue
            if name == "on_case_start":
                fn(self.case)
                continue
            try:
                fn(self.case)
            except Exception as exc:  # noqa: BLE001
                self.case.notes.append(_redact(f"case hook {type(hook).__name__}.{name} failed: {type(exc).__name__}: {exc}"))

    # ------------------------------------------------------------------ seeds
    def _seed(self) -> None:
        raised = False
        for seed in self.case.seeds:
            node, _ = self.graph.add_node(seed, 0, seed=True)
            value = _tlp_value((self.opts.seed_tlp or {}).get(seed.key, self.opts.tlp or "amber"))
            if _contact_mode(self.opts) and _tlp.parse(value) < _tlp.TLP.AMBER:
                value, raised = "amber", True
            node.tlp = _tlp_value(node.tlp, value) if node.tlp else value
            self._annotate(node)
            self.seed_of[seed.key] = seed.key
        if raised:
            self.case.notes.append("TLP raised to AMBER: LIGHT/ACTIVE cases are at least TLP:AMBER (A2)")
        if self.resume is not None:
            self._seed_resume()
            return
        for seed in self.case.seeds:
            self._schedule(seed, 0)

    def _seed_resume(self) -> None:
        """``cases resume``: schedule only the recorded (module, entity) pairs with their RunInfo."""
        by_entity: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        for (module, key), info in (self.resume or {}).items():
            by_entity.setdefault(str(key), []).append((str(module), dict(info or {})))
        for key, items in by_entity.items():
            entity = _entity_from_key(key)
            if entity is None:
                self.case.notes.append("resume: an entity key of the stored case could not be parsed (skipped)")
                continue
            info = items[0][1]
            depth = int(info.get("depth", 0) or 0)
            is_seed = bool(info.get("is_seed", False))
            provenance = tuple(tuple(str(x) for x in p) for p in info.get("provenance") or () if isinstance(p, (list, tuple)) and len(p) == 3)
            node, created = self.graph.add_node(entity, depth)
            if created:
                node.path_confidence = 1.0  # the stored case already decided to investigate it
            recorded = str(info.get("tlp") or "") or self.opts.tlp or "amber"
            node.tlp = _tlp_value(node.tlp, recorded) if node.tlp else _tlp_value(recorded)
            self._annotate(node)
            node.investigated = True
            self.provenance[key] = provenance
            self.seed_of[key] = provenance[0][0] if provenance else key
            run = self.engine._run_info(
                entity, is_seed=is_seed, depth=depth, provenance=provenance, case_id=self.case.case_id, tlp=node.tlp,
            )
            wanted = {module for module, _info in items}
            candidates = [cls for cls in modules_for(entity.type) if cls.name in wanted]
            missing = sorted(wanted - {cls.name for cls in candidates})
            for name in missing:
                self._record(name, entity, status=Status.SKIPPED, code="not_applicable", reason="resume: module not registered or does not accept this entity type")
            self._dispatch(entity, depth, run, candidates)

    # ------------------------------------------------------------------ scheduling
    def _schedule(self, entity: Entity, depth: int, via: tuple[str, str, str] | None = None) -> None:
        node = self.graph.get(entity)
        if node is None or node.investigated:
            return
        if sum(1 for n in self.graph.nodes.values() if n.investigated) >= self.opts.max_entities:
            if not self.budget_note:
                self.case.notes.append(f"entity budget reached ({self.opts.max_entities}); raise --max-entities to go further")
                self.budget_note = True
            return
        node.investigated = True
        if via is not None and entity.key not in self.provenance:
            self.provenance[entity.key] = self.provenance.get(via[0], ()) + (via,)
            self.seed_of[entity.key] = self.seed_of.get(via[0], via[0])
        provenance = self.provenance.get(entity.key, ())
        is_seed = bool(node.seed and entity.key not in (self.opts.unconfirmed_seeds or set()))
        run = self.engine._run_info(entity, is_seed=is_seed, depth=depth, provenance=provenance, case_id=self.case.case_id, tlp=node.tlp)
        self._dispatch(entity, depth, run, self.engine.candidates(entity))

    def _dispatch(self, entity: Entity, depth: int, run: Any, candidates: list[type[Module]]) -> None:
        """Decide every candidate through the gate; submit passive runs first, hold contact runs."""
        eng = self.engine
        runnable: list[tuple[type[Module], Any]] = []
        for cls in candidates:
            decision = eng._decide(cls, entity, eng._pctx, run)
            if getattr(decision, "allowed", False):
                runnable.append((cls, decision))
            else:
                self._blocked(cls, entity, decision, run)
        self.rt.events.emit("investigate", entity=entity, depth=depth, modules=[c.name for c, _d in runnable])
        passive: list[_Job] = []
        contact: list[_Job] = []
        for cls, decision in runnable:
            allowed = getattr(decision, "allowed_sources", None)
            job_run = dataclasses.replace(run, allowed_sources=frozenset(allowed) if allowed is not None else None)
            job = _Job(cls, entity, job_run, decision, depth, _is_contact(cls))
            (contact if job.contact else passive).append(job)
        passive.sort(key=lambda j: _passive_rank(j.cls))  # stable: modules_for order within a rank
        if contact:
            self.held.setdefault(entity.key, []).extend(contact)
        for job in passive:
            self._submit(job)
        if self.passive_left[entity.key] == 0:
            self._release(entity.key)

    def _submit(self, job: _Job) -> None:
        if job.pair in self.pairs:
            return
        self.pairs.add(job.pair)
        if self._expired():  # scheduling stops at the deadline / cancel / end of the window
            self._pending(job)
            return
        if not job.contact:
            self.passive_left[job.entity.key] += 1
        assert self.pool is not None
        fut = self.pool.submit(self._work, job)
        self.futures[fut] = job

    def _work(self, job: _Job) -> ModuleResult:
        """Worker thread: the run deadline starts when the run starts (AR05)."""
        begin = self.rt.clock.monotonic()
        self.started[job.pair] = begin
        run = job.run
        if run is not None and job.timeout:
            run = dataclasses.replace(run, deadline=begin + job.timeout)
        return self.engine.run_module(job.cls, job.entity, self.case_dir if self.opts.save_evidence else None, run=run)

    def _release(self, entity_key: str) -> None:
        """Every passive run of the entity is absorbed: the contact guard decides each held
        LIGHT/ACTIVE run (P376 cond 5-6)."""
        jobs = self.held.pop(entity_key, [])
        for job in jobs:
            if self._expired():
                self.pairs.add(job.pair)
                self._pending(job)
                continue
            guard = self.engine._guard(job.cls, job.entity, self.engine._pctx, job.run)
            if not getattr(guard, "allowed", False):
                self.pairs.add(job.pair)
                self._blocked(job.cls, job.entity, guard, job.run)
                continue
            if getattr(guard, "rule_id", "") and getattr(guard, "reason", ""):
                # the guard yielded (egress profile or recorded --egress-override): keep it visible
                note = _redact(f"{job.cls.name} on {_persisted_key(job.entity)}: {guard.reason}")
                if note not in self.case.notes:
                    self.case.notes.append(note)
            self._submit(job)

    # ------------------------------------------------------------------ loop
    def _loop(self) -> None:
        while True:
            if self._expired():
                return
            self._overdue()
            if not self.futures:
                if self.held:  # defensive: contact runs whose passive phase is over
                    for key in list(self.held):
                        if self.passive_left[key] <= 0:
                            self._release(key)
                    if self.futures:
                        continue
                return
            done, _pending = wait(list(self.futures), timeout=TICK, return_when=FIRST_COMPLETED)
            for fut in done:
                job = self.futures.pop(fut, None)
                if job is None:
                    continue
                try:
                    res = fut.result()
                except Exception as exc:  # strict contract violations surface here as errors
                    res = ModuleResult(job.cls.name, job.entity, status=Status.ERROR, error=_redact(f"{type(exc).__name__}: {exc}"), reason_code="error")
                self._absorb(job, res)
                if self._expired():
                    return

    def _expired(self) -> bool:
        """Deadline, cancel flag (Ctrl+C or another component) or end of the scope window?"""
        if self.stop:
            return True
        rt = self.rt
        reason = ""
        if rt.cancel_event.is_set():
            text = str(rt.cancel_reason or "cancelled")
            reason = "deadline" if text == "deadline" else "window" if "window" in text else "cancelled"
        elif self.scan_end is not None and rt.clock.monotonic() >= self.scan_end:
            reason = "deadline"
        elif self._window_over():
            reason = "window"
        if reason:
            self._halt(reason)
            return True
        return False

    def _window_over(self) -> bool:
        scope = getattr(self.opts, "scope", None)
        fn = getattr(scope, "window_expired", None)
        if not callable(fn):
            return False
        try:
            return bool(fn(self.rt.now()))
        except Exception:  # noqa: BLE001 - an unreadable window ends the engagement (fail closed)
            return True

    def _halt(self, reason: str) -> None:
        """Stop the scan: kill switch, no more scheduling; unfinished pairs are recorded at close."""
        if self.stop:
            return
        self.stop = reason
        if not self.rt.cancel_event.is_set():
            self.rt.cancel(reason)

    def _overdue(self) -> None:
        """Runs past ``Module.timeout`` + grace end ERROR 'timeout'; their late results are dropped."""
        now = self.rt.clock.monotonic()
        for fut, job in list(self.futures.items()):
            begin = self.started.get(job.pair)
            if begin is None or not job.timeout or now <= begin + job.timeout + RUN_GRACE:
                continue
            self.futures.pop(fut, None)
            res = ModuleResult(job.cls.name, job.entity)
            res.mark(Status.ERROR, f"run exceeded its {job.timeout:.0f}s deadline (+{RUN_GRACE:.0f}s grace): results dropped (could not verify)", reason_code="timeout")
            res.duration = max(0.0, now - begin)  # the execution report shows how long it was waited for
            self.done.add(job.pair)
            self.case.results.append(res)
            self._record(job.cls, job.entity, status=Status.ERROR, code="timeout", reason=res.error, res=res)
            self._passive_done(job)

    def _close(self) -> None:
        """End of the BFS: merge results that were already back, record every unfinished pair as
        not run, release the pool without waiting (late results are never read)."""
        if self.stop:
            code, reason, note = _stop_texts(self.stop, self.deadline_s)
            for fut, job in list(self.futures.items()):
                if fut.done() and not fut.cancelled():  # back before the stop: merged like any result
                    self.futures.pop(fut, None)
                    try:
                        res = fut.result()
                    except Exception as exc:  # noqa: BLE001
                        res = ModuleResult(job.cls.name, job.entity, status=Status.ERROR, error=_redact(f"{type(exc).__name__}: {exc}"), reason_code="error")
                    self._absorb(job, res)
            unfinished = list(self.futures.values())
            self.futures.clear()
            for entity_jobs in self.held.values():
                unfinished.extend(entity_jobs)
            self.held.clear()
            for job in unfinished:
                if job.pair not in self.done:
                    # a run that had started may already have sent the value: say so (rule 5), the
                    # status stays SKIPPED with the stop's reason code and its results are dropped
                    running = job.pair in self.started
                    why = _stop_texts(self.stop, self.deadline_s, running=True)[1] if running else reason
                    self._record(job.cls, job.entity, status=Status.SKIPPED, code=code, reason=why)
                    self.done.add(job.pair)
            self.case.partial[self.stop] = True
            self.case.interrupted = True
            pending = sum(1 for row in self.case.execution if row.get("reason_code") == code and row.get("status") == Status.SKIPPED.value)
            self.case.notes.append(note.format(pending=pending))
        if self.pool is not None:
            self.pool.shutdown(wait=False, cancel_futures=True)

    def _pending(self, job: _Job) -> None:
        """A pair the stopped scan will never run (recorded at once: SKIPPED deadline/scope)."""
        code, reason, _note = _stop_texts(self.stop or "deadline", self.deadline_s)
        if job.pair not in self.done:
            self._record(job.cls, job.entity, status=Status.SKIPPED, code=code, reason=reason)
            self.done.add(job.pair)

    # ------------------------------------------------------------------ merging
    def _absorb(self, job: _Job, res: ModuleResult) -> None:
        if job.pair in self.done:  # timed out or recorded already: a late result is dropped
            return
        self.done.add(job.pair)
        case, graph, rt = self.case, self.graph, self.rt
        case.results.append(res)
        self._record(job.cls, job.entity, status=res.status, code=res.reason_code, reason=res.error, res=res, decision=job.decision)
        if res.raw is not None and self.evidence is not None:
            try:
                res.evidence, res.evidence_sha256 = self.evidence.save(res, requests=getattr(res, "_request_log", ()) or ())
            except (OSError, TypeError, ValueError) as exc:  # evidence failure must not lose the result
                res.error = (res.error + "; " if res.error else "") + f"evidence not saved: {exc}"
        node, _ = graph.add_node(res.entity, job.depth, source=res.module)
        if res.tlp:  # platform markings raise the entity TLP (A12); its pivots inherit it
            node.tlp = _tlp_value(node.tlp or self.opts.tlp, res.tlp)
        if res.attributes:
            graph.add_attributes(res.entity, res.attributes, res.module)
        for f in res.findings:
            if f.entity is not None and graph.get(f.entity) is None:
                self._side_node(f.entity, node, job.depth, res.module)  # a finding about another entity
            graph.add_finding(f)
            owner = graph.get(f.entity) if f.entity is not None else node
            if owner is not None and owner.ownership in OWNERSHIP_VALUES and not f.ownership:
                f.ownership = owner.ownership
            rt.events.emit("finding", finding=f)
        for label, url in res.links:
            _add_link(case, res.entity.key, {"label": label, "url": url})
        for pv in res.pivots:
            self._pivot(res, node, pv, job.depth)
        if res.status is Status.QUOTA or (res.partial and res.stop_reason == "quota"):
            self._defer(job.cls.name, res.entity, res.error or "quota exhausted")
        if res.status in MANUAL_LINK_STATUSES:  # automation could not answer: the analyst can look by hand (P311 cond 9)
            self._manual_link(job.cls, res.entity, res.reason_code or res.status.value, job.run)
        self._sources(job.cls, job.decision, res)
        if res.status not in (Status.SKIPPED,):
            self._licence_used(job.decision)
        rt.events.emit("module_done", result=res)
        self._passive_done(job)

    def _passive_done(self, job: _Job) -> None:
        if job.contact:
            return
        key = job.entity.key
        self.passive_left[key] -= 1
        if self.passive_left[key] <= 0:
            self.passive_left[key] = 0
            self._release(key)

    def _side_node(self, entity: Entity, parent: Node, depth: int, module: str) -> Node:
        """A node a module's result created without a pivot (a finding about another entity): one
        level below the run's entity, with its TLP inherited from that entity and its ownership
        annotated like any pivot (never investigated automatically)."""
        child, created = self.graph.add_node(entity, depth + 1, source=module)
        inherited = parent.tlp or self.opts.tlp or "amber"
        child.tlp = _tlp_value(child.tlp, inherited) if child.tlp else _tlp_value(inherited)
        if created:
            self._annotate(child)
        return child

    def _pivot(self, res: ModuleResult, parent: Node, pv: Pivot, depth: int) -> None:
        graph, rt = self.graph, self.rt
        from_text = res.entity.type in TEXT_PARENTS
        if from_text and pv.entity.type in PERSONAL_TYPES and not self.personal_ok:
            pv.expand = False  # listed for the analyst's selection, never auto-investigated (AR07)
            self._pending_personal(pv, res.entity)
        child, created = graph.add_node(pv.entity, depth + 1, source=res.module)
        inherited = parent.tlp or self.opts.tlp or "amber"
        child.tlp = _tlp_value(child.tlp, inherited) if child.tlp else _tlp_value(inherited)
        if created:
            self._annotate(child)
        graph.add_edge(res.entity, pv.entity, pv.relation, res.module, pv.confidence, expand=pv.expand)
        if created:
            rt.events.emit("entity", entity=pv.entity, parent=res.entity, relation=pv.relation, module=res.module, depth=depth + 1)
        if self.resume is None and self._should_expand(pv, child, res.entity, depth + 1):
            self._schedule(pv.entity, depth + 1, (res.entity.key, pv.relation, res.module))

    def _should_expand(self, pv: Pivot, child: Node, parent: Entity, depth: int) -> bool:
        """AR07 expansion rules (see the module docstring)."""
        etype = pv.entity.type
        if etype in SECRET_TYPES:
            return False
        if depth > self.opts.depth or not pv.expand or child.investigated:
            return False
        if etype in NO_AUTO_EXPAND:
            return False
        from_text = parent.type in TEXT_PARENTS
        if from_text and etype not in IOC_TYPES and not (etype in PERSONAL_TYPES and self.personal_ok):
            return False
        if pv.relation in NEVER_EXPAND_RELATIONS:
            return False
        if pv.relation in IDENTITY_RELATIONS and pv.confidence_label is Confidence.POSSIBLE:
            return False
        if child.noise:
            return False
        if _warninglists(child.entity):
            return False  # warninglisted values are listed, never auto-pivoted (contract s.18)
        if child.path_confidence + 1e-9 < self.min_expand:
            return False
        k = (parent.key, etype)
        cap = INPUT_LIST_CAP if from_text else EXPAND_CAP.get(etype, DEFAULT_CAP)
        if self.expanded[k] >= cap:
            return False
        self.expanded[k] += 1
        return True

    def _pending_personal(self, pv: Pivot, parent: Entity) -> None:
        key = (pv.entity.key, parent.key)
        if key in self.seen_personal:
            return
        self.seen_personal.add(key)
        self.case.pending_personal.append({"entity": pv.entity.key, "parent": parent.key, "relation": pv.relation})

    def _annotate(self, node: Node) -> None:
        """Ownership tags for a new node when an org profile is loaded (A11/P378 cond 10)."""
        org = self.org
        if org is None or node.entity.type not in ASSET_TYPES:
            return
        try:
            own = org.owns(node.entity)
        except Exception:  # noqa: BLE001 - a profile problem never breaks a scan
            return
        tag = "own_asset" if getattr(own, "own", False) else "third_party"
        node.ownership = tag
        node.criticality = str(getattr(own, "criticality", "") or "") if tag == "own_asset" else ""
        node.add_tag(tag)

    # ------------------------------------------------------------------ recording
    def _blocked(self, cls: type[Module], entity: Entity, decision: Any, run: Any) -> None:
        """A (module, entity) the gate (or the contact guard) refused."""
        status = _status_of(decision)
        if status in (Status.OK, Status.EMPTY):
            status = Status.SKIPPED
        code = _code_of(decision, status)
        reason = str(getattr(decision, "reason", "") or "") or DEFAULT_REASON.get(status, "")
        self._record(cls, entity, status=status, code=code, reason=reason, decision=decision)
        if getattr(decision, "emit_manual_link", False):
            self._manual_link(cls, entity, code, run)
        if status is Status.QUOTA:
            self._defer(cls.name, entity, reason)
        self._sources(cls, decision, None)

    def _record(
        self,
        cls: Any,
        entity: Entity,
        *,
        status: Status,
        code: str,
        reason: str,
        res: ModuleResult | None = None,
        decision: Any = None,
    ) -> None:
        """One (module, entity) outcome into coverage v2, the execution report and the skip lines."""
        name = cls if isinstance(cls, str) else cls.name
        status = Status(status)
        if status in (Status.OK, Status.EMPTY):
            code = ""
        elif not valid_reason(status, code):
            code = DEFAULT_REASON.get(status, "")
        reason = _redact(str(reason or ""))[:300]
        partial = bool(res is not None and res.partial)
        stop_reason = res.stop_reason if res is not None else ""
        seed = self.seed_of.get(entity.key, entity.key)
        cov = self.case.coverage.setdefault(name, _cov_for(cls if not isinstance(cls, str) else REGISTRY.get(name), name))
        key = _persisted_key(entity)
        cov["entities"][key] = {"status": status.value, "reason_code": code, "reason": reason, "partial": partial, "stop_reason": stop_reason, "seed": _persisted_key_str(seed)}
        cov["counts"][status.value] = cov["counts"].get(status.value, 0) + 1
        cov[status.value] = cov["counts"][status.value]  # v1 per-status counters
        if res is not None:
            cov["runs"] += 1
            if partial:
                cov["partial"] = cov.get("partial", 0) + 1
                cov["stop_reason"] = stop_reason
        _summarise(cov)
        outcome = "partial" if partial and status in (Status.OK, Status.EMPTY) else OUTCOMES.get(status, "failed")
        if res is None and status is not Status.QUOTA:
            outcome = "skipped" if status is not Status.ERROR else "failed"
        self.case.execution.append({
            "module": name,
            "entity": key,
            "seed": _persisted_key_str(seed),
            "status": status.value,
            "reason_code": code,
            "outcome": outcome,
            "partial": partial,
            "stop_reason": stop_reason,
            "requests": int(res.requests) if res is not None else 0,
            "cache_hits": int(res.cache_hits) if res is not None else 0,
            "duration": round(float(res.duration), 3) if res is not None else 0.0,
        })
        if res is None or status is Status.SKIPPED:
            names = self.case.skips.setdefault(code or status.value, [])
            if name not in names:
                names.append(name)
                names.sort()

    def _sources(self, cls: type[Module], decision: Any, res: ModuleResult | None) -> None:
        """coverage[module]['sources']: automatic 'licence' rows for declared sources outside the
        decision's allowed_sources (A1 BR10) merged with the module's own res.source_statuses."""
        cov = self.case.coverage.get(cls.name)
        if cov is None:
            return
        rows: dict[str, dict[str, str]] = cov.setdefault("sources", {})
        allowed = getattr(decision, "allowed_sources", None) if decision is not None else None
        blocked = getattr(decision, "blocked_sources", None) if decision is not None else None
        blocked = blocked if isinstance(blocked, dict) else {}
        for sid, why in blocked.items():
            _merge_source(rows, str(sid), {"status": Status.SKIPPED.value, "reason_code": "licence", "reason": _redact(str(why or ""))[:300]})
        if allowed is not None:
            profile = self.case.licence_profile or _licence_profile(self.rt, self.opts, self.engine._pctx)
            for sid in getattr(cls, "sources", ()) or ():
                if sid in allowed or sid in blocked:
                    continue
                klass = _terms_class(self.rt, sid)
                _merge_source(rows, sid, {"status": Status.SKIPPED.value, "reason_code": "licence", "reason": f"skipped: {klass} terms (licence profile {profile})"})
        if res is not None:
            for sid, row in (res.source_statuses or {}).items():
                if isinstance(row, dict):
                    _merge_source(rows, str(sid), {"status": str(row.get("status") or ""), "reason_code": str(row.get("reason_code") or ""), "reason": _redact(str(row.get("reason") or ""))[:300]})

    def _licence_used(self, decision: Any) -> None:
        basis = getattr(decision, "licence_basis", None) if decision is not None else None
        if not isinstance(basis, dict):
            return
        for sid, value in basis.items():
            self.case.licence_used[str(sid)] = {"class": _terms_class(self.rt, str(sid)), "basis": str(value)}

    def _defer(self, module: str, entity: Entity, reason: str) -> None:
        """P334 cond 6-7: quota-skipped pairs are deferred for `cases resume`."""
        key = _persisted_key(entity)
        if any(d["module"] == module and d["entity"] == key for d in self.case.deferred):
            return
        text = _redact(str(reason or "quota"))[:200]
        self.case.deferred.append({"module": module, "entity": key, "reason": text})
        book = None
        try:
            book = self.rt.quota
        except Exception:  # noqa: BLE001
            book = None
        fn = getattr(book, "defer", None)
        if callable(fn):
            try:
                fn(self.case.case_id, module, entity.key, text)
            except Exception as exc:  # noqa: BLE001 - bookkeeping never fails a scan
                log.warning("quota defer failed: %s", type(exc).__name__)

    def _manual_link(self, cls: type[Module], entity: Entity, code: str, run: Any) -> None:
        """P311 cond 9: the module's manual link when automation was skipped or blocked."""
        template = str(getattr(cls, "manual_link", "") or "")
        if not template:
            return
        is_seed = bool(getattr(run, "is_seed", False))
        include_privacy = bool(is_seed and self.opts.show_personal and self.opts.purpose)  # opted-in typed seeds only
        try:
            rendered = linklib.render_manual(template, entity, include_privacy=include_privacy)
        except Exception:  # noqa: BLE001 - a broken template never breaks a scan (links.errors() reports it)
            rendered = None
        if rendered is None:
            return
        _add_link(self.case, entity.key, _link_item(rendered, note=f"automation skipped: {code}", manual=True, module=cls.name))

    # ------------------------------------------------------------------ summaries
    def _summaries(self) -> None:
        """case.tlp, case.answered, licence profile (after the BFS, before the finish stage)."""
        case, opts = self.case, self.opts
        values = [n.tlp for n in self.graph.nodes.values() if n.seed and n.tlp] or [case_tlp(opts, case.seeds)]
        values += [r.tlp for r in case.results if r.tlp]
        tlp = _tlp_value(*values)
        contact_ran = any(_is_contact(REGISTRY.get(r.module) or Module) and r.status is not Status.SKIPPED for r in case.results)
        if (contact_ran or _contact_mode(opts)) and _tlp.parse(tlp) < _tlp.TLP.AMBER:
            tlp = "amber"
            note = "TLP raised to AMBER: LIGHT/ACTIVE cases are at least TLP:AMBER (A2)"
            if note not in case.notes:
                case.notes.append(note)
        case.tlp = tlp
        case.licence_profile = _licence_profile(self.rt, opts, self.engine._pctx)
        for seed in case.seeds:
            case.answered[_persisted_key(seed)] = _answered(seed, case.results)

    def _final_meta(self) -> None:
        rt, case = self.rt, self.case
        book = None
        try:
            book = rt.quota
        except Exception:  # noqa: BLE001
            book = None
        fn = getattr(book, "quota_lines", None)
        if callable(fn):
            try:
                rt.meta["quota_lines"] = [str(line) for line in fn()]
            except Exception as exc:  # noqa: BLE001
                log.warning("quota lines unavailable: %s", type(exc).__name__)
        case.meta = _json_meta(getattr(rt, "meta", None) or {})


# ----------------------------------------------------------------------------------------
# Suppression stage (P322 cond 4/8, P302 cond 7, A4 BR6)
# ----------------------------------------------------------------------------------------


def suppress(case: CaseResult) -> int:
    """The core suppression stage (start of ``_finish``); returns the number of findings touched.

    * SUP-warninglist: entity on a warninglist -> findings tagged malicious/suspicious/phishing/c2/
      spam/scanner downgraded to POSSIBLE ('POSSIBLE - on warninglist <name>');
    * SUP-sinkhole: sinkholed entity -> those findings downgraded to POSSIBLE ('POSSIBLE - sinkhole')
      and tagged ``context_only``;
    * SUP-generic_address: generic/role/test e-mail address (attribute ``generic_address`` or
      ``entities.generic_address_kind``) -> breach/infostealer findings capped at POSSIBLE and tagged
      ``context_only``.

    Suppression only downgrades (never deletes), records the named rule through
    ``Finding.downgrade`` and never crosses an analyst override (the override keeps its values and
    the attempt is recorded as blocked). Each rule applies once per finding.
    """
    touched = 0
    for node in case.graph.nodes.values():
        if not node.findings:
            continue
        lists = _warninglists(node.entity)
        if lists:
            reason = f"on warninglist {', '.join(lists)}"
            for f in node.findings:
                if _has_any(f, SUPPRESSED_TAGS) and _apply(f, "SUP-warninglist", reason, context_only=False):
                    touched += 1
        if "sinkhole" in node.tags or _is_sinkhole(node.entity):
            for f in node.findings:
                if _has_any(f, SUPPRESSED_TAGS) and _apply(f, "SUP-sinkhole", "sinkhole", context_only=True):
                    touched += 1
        kind = _generic_kind(node)
        if kind:
            for f in node.findings:
                if _has_any(f, BREACH_TAGS) and _apply(f, "SUP-generic_address", f"generic address ({kind})", context_only=True):
                    touched += 1
    return touched


def _apply(f: Finding, rule: str, reason: str, *, context_only: bool) -> bool:
    if any(s.get("rule") == rule for s in f.suppressed_by):
        return False  # once per finding
    f.downgrade(rule, reason, to=Confidence.POSSIBLE)
    if context_only and not f.override and CONTEXT_ONLY not in f.tags:
        f.tags.append(CONTEXT_ONLY)
    return True


def _has_any(f: Finding, tags: Iterable[str]) -> bool:
    return any(t in f.tags for t in tags)


def _warninglists(entity: Entity) -> list[str]:
    try:
        from v3lum.core import noise

        return list(noise.warninglists(entity))
    except Exception:  # noqa: BLE001 - list problems are reported by noise.errors()
        return []


def _is_sinkhole(entity: Entity) -> bool:
    try:
        from v3lum.core import noise

        return bool(noise.is_sinkhole(entity))
    except Exception:  # noqa: BLE001
        return False


def _generic_kind(node: Node) -> str:
    flagged = node.attr("generic_address")
    if node.entity.type is EntityType.EMAIL:
        try:
            kind = _entities.generic_address_kind(node.entity)
        except Exception:  # noqa: BLE001
            kind = None
        if kind:
            return str(kind)
    if flagged:
        return str(flagged) if isinstance(flagged, str) else "role"
    return ""


# ----------------------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------------------


def _inconclusive_note(case: CaseResult) -> None:
    """Rule 5 on the first screen: when no module answered (none ran, or every run could not
    verify), say so; the risk level of such a case is not a verdict ('inconclusive' replaces 'clean'
    in the renderers from wave 3/4)."""
    if any(r.status in (Status.OK, Status.EMPTY) for r in case.results):
        return
    opt_in = len(case.skips.get("not_default", []))
    unverified = sum(1 for r in case.results if r.status.could_not_verify)
    why = []
    if opt_in:
        why.append(f"{opt_in} opt-in source module(s) not run: use --preset deep or -M <name>")
    if unverified:
        why.append(f"{unverified} run(s) could not verify")
    case.notes.append("inconclusive: no source answered" + (f" ({'; '.join(why)})" if why else "") + " - a 'clean' risk level is not a verdict")


def _answered(seed: Entity, results: list[ModuleResult]) -> dict[str, Any]:
    """'N of M applicable sources answered; K could not verify' for one seed (P328 cond 7): over the
    modules that ran on the seed itself. A run reporting per-feed outcomes (``source_statuses``)
    counts each reported feed; a run that itself could not verify counts once."""
    applicable = answered = cnv = rep_app = rep_ans = 0
    sources: list[dict[str, str]] = []
    for res in results:
        if res.entity.key != seed.key or res.status is Status.SKIPPED:
            continue
        cls = REGISTRY.get(res.module)
        if cls is not None and "reputation" in (getattr(cls, "tags", ()) or ()):
            rep_app += 1
            if res.status in (Status.OK, Status.EMPTY):
                rep_ans += 1
        units: list[tuple[str, str, str]] = []
        if res.status.could_not_verify or not res.source_statuses:
            units.append(("", res.status.value, res.reason_code))
        else:
            for sid, row in sorted(res.source_statuses.items()):
                st = str((row or {}).get("status") or "")
                if st == Status.SKIPPED.value:
                    continue  # e.g. a licence-blocked feed: not applicable
                units.append((sid, st, str((row or {}).get("reason_code") or "")))
        for sid, st, code in units:
            applicable += 1
            if st in (Status.OK.value, Status.EMPTY.value):
                answered += 1
            elif _could_not_verify(st):
                cnv += 1
            sources.append({"module": res.module, "source": sid, "status": st, "reason_code": code})
    return {
        "applicable": applicable,
        "answered": answered,
        "could_not_verify": cnv,
        "sources": sources,
        "reputation_applicable": rep_app,
        "reputation_answered": rep_ans,
    }


def _json_meta(meta: Any) -> dict[str, Any]:
    """``runtime.meta`` as stored in the case: JSON values only (strings through the redactor).

    The runtime also carries live objects there (e.g. the ``sightings_lookup`` callable the policy
    gate reads): they are run plumbing, not case facts, and would make the case dict unserialisable
    (or put an object repr with a memory address into stored cases and reports)."""
    out: dict[str, Any] = {}
    for key, value in dict(meta).items():
        if not isinstance(key, str) or callable(value):
            continue
        try:
            json.dumps(value, allow_nan=False)
        except (TypeError, ValueError):
            log.debug("runtime.meta[%r] is not JSON data: not stored in the case", key)
            continue
        out[key] = _redact_strings(value)
    return out


def _redact_strings(value: Any) -> Any:
    if isinstance(value, str):
        return _redact(value)
    if isinstance(value, dict):
        return {k: _redact_strings(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_strings(v) for v in value]
    return value


def _could_not_verify(status: str) -> bool:
    try:
        return Status(status).could_not_verify
    except ValueError:
        return True  # an unreadable feed status never reads as an answer (rule 5)


def _summarise(cov: dict[str, Any]) -> None:
    """Module summary from its per-entity rows: the highest COVERAGE_RANK status wins; reason and
    reason code come from that row ('' for ok/empty)."""
    best: dict[str, Any] | None = None
    for row in cov["entities"].values():
        if best is None or COVERAGE_RANK.get(row["status"], 0) > COVERAGE_RANK.get(best["status"], 0):
            best = row
    if best is None:
        return
    cov["status"] = best["status"]
    if best["status"] in (Status.OK.value, Status.EMPTY.value):
        cov["reason_code"] = ""
        cov["reason"] = ""
    else:
        cov["reason_code"] = best["reason_code"]
        cov["reason"] = best["reason"]
    _consistent_reason_code(cov)


def _merge_source(rows: dict[str, dict[str, str]], sid: str, row: dict[str, str]) -> None:
    current = rows.get(sid)
    if current is None or COVERAGE_RANK.get(row.get("status", ""), 0) > COVERAGE_RANK.get(current.get("status", ""), 0):
        rows[sid] = row


def _link_item(rendered: Any, **extra: Any) -> dict[str, Any]:
    """A ``case.links`` item from a ``links.RenderedLink``: label and url plus what the renderers
    need to apply P311/A2 (host receiving the value, touches_target, privacy, unverified/unknown
    operator badge...); ``extra`` adds the manual-link keys (note, manual, module)."""
    item: dict[str, Any] = {
        "label": str(getattr(rendered, "label", "") or ""),
        "url": str(getattr(rendered, "url", "") or ""),
        "host": str(getattr(rendered, "host", "") or ""),
        "category": str(getattr(rendered, "category", "") or ""),
        "verified": bool(getattr(rendered, "verified", False)),
        "touches_target": bool(getattr(rendered, "touches_target", False)),
        "privacy": bool(getattr(rendered, "privacy", False)),
        "antibot": bool(getattr(rendered, "antibot", False)),
        "badge": str(getattr(rendered, "badge", "") or ""),
        "ref": str(getattr(rendered, "ref", "") or ""),
    }
    item.update(extra)
    return item


def _add_link(case: CaseResult, key: str, item: dict[str, Any]) -> None:
    """Append a link to ``case.links[key]`` once per (url, label, note)."""
    bucket = case.links.setdefault(key, [])
    ident = (item.get("url"), item.get("label"), item.get("note", ""))
    if any((existing.get("url"), existing.get("label"), existing.get("note", "")) == ident for existing in bucket):
        return
    bucket.append(item)


def _stop_texts(stop: str, deadline_s: float, *, running: bool = False) -> tuple[str, str, str]:
    """(reason code, reason, note template) for unfinished pairs of a stopped scan; ``running``: the
    run had started (its value may have been sent) and its results are dropped."""
    when = "while it ran: results dropped (could not verify)" if running else "before it ran: not run"
    if stop == "window":
        return ("scope", f"engagement window ended {when}", "engagement window ended: target contact stopped, partial results ({pending} pending source run(s) SKIPPED 'scope')")
    if stop == "cancelled":
        return ("deadline", f"scan cancelled {when}", "interrupted by the analyst (Ctrl+C): partial results ({pending} pending source run(s) SKIPPED 'deadline')")
    secs = f"{deadline_s:.0f}s" if deadline_s >= 1 else f"{deadline_s:g}s"
    return ("deadline", f"scan deadline reached ({secs}) {when}", f"scan deadline (global timeout {secs}) reached: partial results ({{pending}} pending source run(s) SKIPPED 'deadline')")


def _contact_mode(opts: ScanOptions) -> bool:
    try:
        return Opsec.parse(opts.mode) >= Opsec.LIGHT
    except (KeyError, ValueError):
        return False


def _priority(depth: int) -> str:
    return "seed" if depth <= 0 else "pivot" if depth == 1 else "pivot2"


def _internal_target(entity: Entity) -> bool:
    """Does the typed value name private space (private/loopback/link-local/CGNAT/ULA addresses,
    single-label or internal-suffix host names)? Used for RunInfo.internal_seed (AR02)."""
    etype, value = entity.type, str(entity.value)
    try:
        if etype in (EntityType.IPV4, EntityType.IPV6):
            return not ipaddress.ip_address(value).is_global
        if etype is EntityType.CIDR:
            return not ipaddress.ip_network(value, strict=False).is_global
    except ValueError:
        return False
    if etype is EntityType.DOMAIN:
        host = value
    elif etype is EntityType.URL:
        host = _entities.url_host(value)
    else:
        return False
    host = str(host or "").strip().lower().rstrip(".").strip("[]")
    if not host:
        return False
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        pass
    return "." not in host or host.endswith(_INTERNAL_SUFFIXES)


def _licence_profile(rt: Runtime, opts: ScanOptions, pctx: Any = None) -> str:
    """The licence profile the gate enforces: the policy context's, else the resolved one. A profile
    that cannot be resolved (research without a recorded legal basis, an unknown name) runs - and
    is recorded - as corporate, like ``policy.make_context`` (fail closed: never a research banner
    on a case the corporate profile actually gated)."""
    enforced = str(getattr(pctx, "licence_profile", "") or "") if pctx is not None else ""
    if enforced:
        return enforced
    try:
        from v3lum.core import licence

        return str(licence.resolve_profile(rt.config, opts))
    except Exception:  # noqa: BLE001 - LicenceError: research without basis / unknown profile
        return "corporate"


def _terms_class(rt: Runtime, sid: str) -> str:
    try:
        src = rt.providers.source(sid)
    except Exception:  # noqa: BLE001
        src = None
    terms = getattr(src, "terms", None)
    return str(getattr(terms, "class_", "") or "unknown")


def _persisted_key(entity: Entity) -> str:
    """Entity key as written to the case: SECRET_TYPES values redacted (item 12)."""
    if entity.type in SECRET_TYPES:
        try:
            return f"{entity.type.value}:{_entities.redacted_value(entity.type, entity.value)}"
        except Exception:  # noqa: BLE001
            return f"{entity.type.value}:[redacted]"
    return entity.key


def _persisted_key_str(key: str) -> str:
    entity = _entity_from_key(key)
    return _persisted_key(entity) if entity is not None else key


def _entity_from_key(key: str) -> Entity | None:
    if not isinstance(key, str) or ":" not in key:
        return None
    etype, value = key.split(":", 1)
    try:
        return Entity(EntityType(etype), value)
    except ValueError:
        try:
            return Entity.make(EntityType.parse(etype), value)
        except ValueError:
            return None


def _drop_data(res: ModuleResult) -> None:
    """Drop everything a run produced (timeout overrun, sanitizer failure): could not verify."""
    res.raw = None
    res.findings, res.pivots, res.attributes, res.links = [], [], {}, []
    res.source_statuses = {}
    res.partial, res.stop_reason = False, ""


def _redact_result(res: ModuleResult) -> None:
    """AR01: mask configured key values and key-like URL parameters in everything a module produced.

    Modules may echo a request URL or an upstream message (a key in a query string or in a path) into
    a finding, an attribute, a link, a pivot, a per-feed reason or the raw payload; the result then
    reaches the graph, the live events, the case JSON, evidence and reports. This pass runs right
    after the sanitizer (and fails closed with it). Pivot values are indicators: they are rewritten
    only when they carry a configured key value (rebuilt from the masked value, or dropped when
    nothing valid is left); a key-like parameter of an investigated URL stays part of the IOC.
    """
    from v3lum.core import redact

    def clean(value: Any) -> Any:
        if isinstance(value, str):
            return redact.redact_text(value)
        if isinstance(value, dict):
            return {(clean(k) if isinstance(k, str) else k): clean(v) for k, v in value.items()}
        if isinstance(value, list):
            return [clean(v) for v in value]
        if isinstance(value, tuple):
            return tuple(clean(v) for v in value)
        return value

    for f in res.findings:
        f.title = clean(f.title)
        f.description = clean(f.description)
        f.criterion = clean(f.criterion)
        f.key = clean(f.key)
        f.references = [clean(r) for r in f.references]
        f.data = clean(f.data)
    res.attributes = clean(res.attributes)
    res.links = [(clean(label), clean(url)) for label, url in res.links]
    kept: list[Pivot] = []
    for p in res.pivots:
        p.note = clean(p.note)
        value = p.entity.value
        if redact.has_secret(value):
            rebuilt = Entity.try_make(p.entity.type, redact.redact_text(value))
            if rebuilt is None:
                continue
            p.entity = rebuilt
        kept.append(p)
    res.pivots = kept
    res.source_statuses = clean(res.source_statuses)
    res.error = clean(res.error)
    res.raw = clean(res.raw)


def _unique_finding_ids(res: ModuleResult) -> None:
    """Fill every finding id (AR09) and keep them unique within the run.

    Findings appended directly to ``res.findings`` skip the duplicate check of
    ``ModuleResult.finding``: same-title duplicates get a deterministic ``key`` ('#2', '#3'...) so
    feedback, overrides and sightings keyed by finding id never collide.
    """
    seen: set[str] = set()
    for f in res.findings:
        f.ensure_id()
        if f.id in seen and f.id == getattr(f, "_derived_id", None):  # explicit (stored) ids are kept
            base, n = f.key, 2
            while f.id in seen:
                f.key = f"{base}#{n}"
                f.ensure_id()
                n += 1
        seen.add(f.id)


def _merge_hosts(*counters: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for counter in counters:
        if not counter:
            continue
        try:
            items = counter.items()
        except AttributeError:
            continue
        for host, count in items:
            try:
                out[str(host)] = out.get(str(host), 0) + int(count)
            except (TypeError, ValueError):
                continue
    return out


def _cov_for(cls: Any, name: str) -> dict[str, Any]:
    return {
        "title": (getattr(cls, "title", "") or name) if cls is not None else name,
        "category": getattr(cls, "category", "?") if cls is not None else "?",
        "status": "not_run",
        "reason_code": "",
        "reason": "",
        "runs": 0,
        "counts": {},
        "entities": {},
        "sources": {},
    }


def _consistent_reason_code(cov: dict[str, Any]) -> None:
    """Keep a coverage entry's reason_code valid for its (merged) status: '' for ok/empty, the
    status default when the recorded code belongs to another status."""
    try:
        status = Status(cov.get("status"))
    except ValueError:  # 'not_run'
        return
    code = str(cov.get("reason_code") or "")
    if not valid_reason(status, code):
        cov["reason_code"] = "" if status in (Status.OK, Status.EMPTY) else DEFAULT_REASON.get(status, "")
