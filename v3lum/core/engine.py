"""Investigation engine: run modules, pivot on discoveries, correlate, score.

Pipelined BFS: as soon as a module returns new entities they are scheduled (no barrier
between depths). Guard rails keep investigations bounded: max depth, entity budget,
per-parent caps per entity type, noise suppression and per-module pivot caps.

Contract v2 (wave 1, thin integration; the policy gate and the deep scheduling changes arrive
with WP08): every run executes inside :func:`models.collect_results`, exceptions map to a status
plus a canonical reason code (module_author_contract section 3), partial runs keep their data,
the disclosure ledger (``res.hosts``) and dataset citations are filled, finding ids are
deterministic and every result passes the fail-closed sanitizer stage (P145).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
import secrets
import time
import traceback
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from v3lum import __version__, paths
from v3lum.core import correlate, entities as _entities, noise, sanitize, scoring, vocab
from v3lum.core import links as linklib
from v3lum.core import module as _module
from v3lum.core import tlp as _tlp
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.detect import Detection
from v3lum.core.entities import Entity, EntityType
from v3lum.core.graph import Graph
from v3lum.core.models import (
    DEFAULT_REASON,
    STOP_REASONS,
    ContractViolation,
    Correlation,
    Finding,
    ModuleResult,
    Pivot,
    Status,
    collect_results,
    valid_reason,
)
from v3lum.core.module import Module, load_modules, modules_for, readiness

# Entity types never investigated automatically (analyst decides): privacy and blast radius.
# The canonical set lives in v3lum.core.entities (A8/AR24); this name is kept as an alias.
NO_AUTO_EXPAND = getattr(_entities, "NO_AUTO_EXPAND", None) or frozenset({
    EntityType.TEXT, EntityType.FILE, EntityType.KEYWORD, EntityType.PERSON, EntityType.USER_AGENT,
    EntityType.JWT, EntityType.CPF, EntityType.COORDINATES, EntityType.CARD_BIN, EntityType.IMEI,
})

# Max children of one type expanded from a single parent entity.
EXPAND_CAP: dict[EntityType, int] = {
    EntityType.DOMAIN: 12, EntityType.IPV4: 10, EntityType.IPV6: 4, EntityType.URL: 5, EntityType.EMAIL: 10,
    EntityType.USERNAME: 5, EntityType.CVE: 30, EntityType.MD5: 5, EntityType.SHA1: 5, EntityType.SHA256: 10,
    EntityType.ASN: 3, EntityType.CIDR: 2, EntityType.ORG: 3, EntityType.CNPJ: 5, EntityType.PHONE: 5,
    EntityType.BTC: 5, EntityType.ETH: 5, EntityType.THREAT_ACTOR: 3, EntityType.MALWARE: 5, EntityType.MITRE: 15,
}
DEFAULT_CAP = 5
INPUT_LIST_CAP = 200

#: Disclosure classes of source modules: opt-in until the policy gate lands (interim A16 BR5 guard).
SOURCE_DISCLOSURES = frozenset({"third_party", "internal", "target"})
NOT_DEFAULT_REASON = "source modules are opt-in until the policy gate lands (A16)"
#: Providers that publish submitted lookups never receive an investigated value, at any TLP (rule 7, A2).
PUBLISHES_REASON = "the provider publishes submitted lookups: it never receives an investigated value (rule 7)"


@dataclass
class CaseResult:
    case_id: str
    created: str
    seeds: list[Entity]
    options: ScanOptions
    graph: Graph
    results: list[ModuleResult] = field(default_factory=list)
    correlations: list[Correlation] = field(default_factory=list)
    risk: dict[str, Any] = field(default_factory=dict)
    coverage: dict[str, dict[str, Any]] = field(default_factory=dict)
    links: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    detections: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    duration: float = 0.0
    case_dir: str = ""
    interrupted: bool = False

    @property
    def findings(self) -> list[Finding]:
        return self.graph.findings()

    @property
    def tlp(self) -> str:
        """Case TLP: the highest of the seed TLPs (ScanOptions.seed_tlp, else options.tlp)."""
        return case_tlp(self.options, self.seeds)

    def timeline(self) -> list[dict[str, Any]]:
        return build_timeline(self.graph)

    def to_dict(self) -> dict[str, Any]:
        findings = sorted(self.findings, key=lambda f: (-int(f.severity), -f.confidence))
        req = sum(r.requests for r in self.results)
        hits = sum(r.cache_hits for r in self.results)
        status_counts = Counter(r.status.value for r in self.results)
        return {
            "schema": "v3lum.case/1",
            "tool": {"name": "V3LUM", "version": __version__},
            "case_id": self.case_id,
            "created": self.created,
            "tlp": self.tlp,
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
            },
            "risk": self.risk,
            "entities": [n.to_dict() for n in self.graph.nodes.values()],
            "edges": [e.to_dict() for e in self.graph.edges],
            "findings": [f.to_dict() for f in findings],
            "correlations": [c.to_dict() for c in self.correlations],
            "modules": [r.to_dict() for r in self.results],
            "coverage": self.coverage,
            "links": {k: [{"label": lbl, "url": url} for lbl, url in v] for k, v in self.links.items()},
            "timeline": self.timeline(),
            "notes": self.notes,
            "case_dir": self.case_dir,
        }


def case_tlp(options: ScanOptions, seeds: list[Entity]) -> str:
    """Highest TLP of the seeds (per-seed ``options.seed_tlp`` when given, else ``options.tlp``)."""
    default = getattr(options, "tlp", "") or "amber"
    per_seed = getattr(options, "seed_tlp", None) or {}
    values = [per_seed.get(s.key, default) for s in seeds] or [default]
    try:
        return _tlp.highest(*values).value_str
    except ValueError:
        return _tlp.TLP.RED.value_str  # unreadable marking: fail closed


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


class Engine:
    def __init__(self, runtime: Runtime, options: ScanOptions | None = None, *, reliability: dict[str, float] | None = None) -> None:
        self.runtime = runtime
        self.options = options or ScanOptions()
        self.reliability = reliability or {}
        load_modules(extra_dirs=[str(paths.plugins_dir())])
        correlate.load_rules()

    # ------------------------------------------------------------------ planning
    def select(self, entity: Entity) -> tuple[list[type[Module]], list[tuple[type[Module], Status, str, str]]]:
        """Modules to run for ``entity`` and the ones held back: (cls, status, reason, reason_code)."""
        keys = self.runtime.config.keys()
        opts = self.options
        runnable: list[type[Module]] = []
        blocked: list[tuple[type[Module], Status, str, str]] = []
        red = self._tlp_red()
        for cls in modules_for(entity.type):
            explicit = cls.name in opts.include
            if opts.include and not explicit:
                continue
            if cls.name in opts.exclude:
                continue
            if opts.categories and cls.category not in opts.categories and not explicit:
                continue
            if not cls.default_enabled and not opts.include_disabled and not explicit:
                continue
            if getattr(cls, "publishes_queries", False) is True:  # team rule 7: no -M or preset bypasses it
                blocked.append((cls, Status.SKIPPED, PUBLISHES_REASON, "policy"))
                continue
            disclosure = getattr(cls, "disclosure", None)
            if disclosure in SOURCE_DISCLOSURES and not explicit and not opts.include_disabled:
                blocked.append((cls, Status.SKIPPED, NOT_DEFAULT_REASON, "not_default"))
                continue
            if red and _shares_input(cls):
                blocked.append((cls, Status.SKIPPED, "TLP:RED - would share the value with a third party", "tlp"))
                continue
            if cls.daily_quota and not opts.offline and self.runtime.quota.exhausted(cls.name, cls.daily_quota):
                blocked.append((cls, Status.QUOTA, f"daily free quota used ({cls.daily_quota}/day per egress IP); add an API key or wait", "quota"))
                continue
            ready, status, code, reason = _readiness(cls, keys, opts)
            if not ready:
                blocked.append((cls, status, reason, code))
                continue
            runnable.append(cls)
        return runnable, blocked

    def _tlp_red(self) -> bool:
        """TLP:RED scan? Until per-entity inheritance lands (WP08), one RED seed makes every entity RED."""
        values = [self.options.tlp, *(getattr(self.options, "seed_tlp", None) or {}).values()]
        try:
            return _tlp.highest(*values) is _tlp.TLP.RED
        except ValueError:
            return True  # unreadable TLP: fail closed

    def plan(self, entity: Entity) -> list[dict[str, Any]]:
        runnable, blocked = self.select(entity)
        rows = [
            {"module": c.name, "title": c.title, "category": c.category, "ready": True, "reason": "ready", "status": "", "reason_code": ""}
            for c in runnable
        ]
        rows += [
            {"module": c.name, "title": c.title, "category": c.category, "ready": False, "reason": r, "status": s.value, "reason_code": code}
            for c, s, r, code in blocked
        ]
        return rows

    # ------------------------------------------------------------------ execution
    def run_module(self, cls: type[Module], entity: Entity, case_dir: Path | None = None, *, run: Any = None) -> ModuleResult:
        """Run one module on one entity and map its outcome (never raises, except strict contract violations)."""
        rt = self.runtime
        fallback = ModuleResult(module=cls.name, entity=entity)  # created outside the collector
        res = fallback
        ctx: Any = None
        start = time.monotonic()
        if getattr(cls, "publishes_queries", False) is True:  # rule 7 on every path (scan, `v3lum run`, tests)
            return self._finalize(fallback.mark(Status.SKIPPED, PUBLISHES_REASON, reason_code="policy"), cls, entity, None, start)
        if run is None:
            # a single run (`v3lum run`, direct callers) is an analyst-typed seed: ctx.entity, ctx.is_seed
            # and the ctx.state guard on the investigated value need the entity
            run = self._run_info(entity, is_seed=True, depth=0, provenance=(), case_id="")
        rt.events.emit("module_start", module=cls.name, entity=entity)
        with collect_results() as built:
            try:
                # the context is built inside the guard: a refusal while scoping the run (policy,
                # configuration) maps to a status like any other, it never escapes run_module
                ctx = rt.context(cls, self.options, case_dir, run=run) if run is not None else rt.context(cls, self.options, case_dir)
                mod = cls()
                if not mod.applies(entity, ctx):
                    res.mark(Status.SKIPPED, "not applicable", reason_code="not_applicable")
                else:
                    out = mod.run(entity, ctx)
                    if isinstance(out, ModuleResult):
                        res = out
                    if res.status is Status.OK and not res.has_data:
                        res.status = Status.EMPTY
            except ContractViolation as exc:
                if vocab.strict_enabled():
                    raise
                res = self._error(fallback, "error", _redact(f"contract violation: {exc}"))
            except Exception as exc:
                res = self._outcome(exc, cls, entity, built, fallback)
        return self._finalize(res, cls, entity, ctx, start)

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
        if cls.daily_quota and res.requests:
            try:
                self.runtime.quota.add(cls.name, res.requests)
            except Exception:  # pragma: no cover - quota bookkeeping must never fail a run
                pass
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
        except Exception as exc:  # fail closed (P145 cond 2): drop everything the module produced
            res.raw = None
            res.findings, res.pivots, res.attributes, res.links = [], [], {}, []
            res.source_statuses = {}
            res.partial, res.stop_reason = False, ""
            res.redacted_fields = ["raw", "result"]
            res.mark(Status.ERROR, _redact(f"sanitizer failed, result dropped: {type(exc).__name__}"), reason_code="sanitizer")
        _unique_finding_ids(res)
        return res

    def _run_info(self, entity: Entity, *, is_seed: bool, depth: int, provenance: tuple[tuple[str, str, str], ...], case_id: str) -> Any:
        try:
            from v3lum.core.context import RunInfo
        except ImportError:  # pragma: no cover - context v1
            return None
        try:
            return RunInfo(entity=entity, is_seed=is_seed, depth=depth, provenance=provenance, case_id=case_id)
        except TypeError:  # pragma: no cover - different RunInfo signature
            return None

    def investigate(self, seeds: list[Entity], *, detections: list[Detection] | None = None, case_id: str | None = None) -> CaseResult:
        """Investigate the seeds (pipelined BFS), then correlate and score."""
        rt = self.runtime
        previous = bool(getattr(rt, "in_scan", False))
        rt.in_scan = True  # AR10: large datasets are never downloaded while a scan runs
        try:
            return self._investigate(seeds, detections=detections, case_id=case_id)
        finally:
            rt.in_scan = previous

    def _investigate(self, seeds: list[Entity], *, detections: list[Detection] | None, case_id: str | None) -> CaseResult:
        rt, opts = self.runtime, self.options
        case_id = case_id or new_case_id(rt.now())
        if not _CASE_ID_RE.match(case_id):  # it names a directory: never a path
            raise ValueError(f"invalid case id {case_id!r}")
        rt.cancel_event.clear()
        rt.cancel_reason = ""  # a previous scan's stop reason must not label this one
        reset_circuit = getattr(rt.http, "reset_circuit", None)
        if callable(reset_circuit):  # hosts short-circuited by a challenge in an earlier scan get a new chance
            reset_circuit()
        case_dir = paths.cases_dir() / case_id
        if opts.save_evidence:
            (case_dir / "evidence").mkdir(parents=True, exist_ok=True)
        graph = Graph()
        case = CaseResult(
            case_id=case_id,
            created=rt.now().isoformat(timespec="seconds"),
            seeds=list(dict.fromkeys(seeds)),
            options=opts,
            graph=graph,
            case_dir=str(case_dir),
            detections=[
                {"type": d.type.value, "value": d.value, "confidence": d.confidence, "reason": d.reason} for d in (detections or [])
            ],
        )
        expanded: Counter[tuple[str, EntityType]] = Counter()
        scheduled_pairs: set[tuple[str, str]] = set()
        provenance: dict[str, tuple[tuple[str, str, str], ...]] = {}
        futures: dict[Future[ModuleResult], tuple[type[Module], Entity, int]] = {}
        budget_note = False
        start = time.monotonic()
        rt.events.emit("scan_start", case_id=case_id, seeds=case.seeds, options=opts)
        pool = ThreadPoolExecutor(max_workers=max(1, opts.threads), thread_name_prefix="v3lum")

        def schedule(entity: Entity, depth: int, via: tuple[str, str, str] | None = None) -> None:
            nonlocal budget_note
            node = graph.get(entity)
            if node is None or node.investigated:
                return
            if sum(1 for n in graph.nodes.values() if n.investigated) >= opts.max_entities:
                if not budget_note:
                    case.notes.append(f"entity budget reached ({opts.max_entities}); raise --max-entities to go further")
                    budget_note = True
                return
            node.investigated = True
            if via is not None and entity.key not in provenance:
                provenance[entity.key] = provenance.get(via[0], ()) + (via,)
            runnable, blocked = self.select(entity)
            for cls, status, reason, code in blocked:
                cov = case.coverage.setdefault(cls.name, _cov(cls))
                cov["blocked"] = cov.get("blocked", 0) + 1
                cov["status"] = cov["status"] if cov.get("runs") else status.value
                cov["reason"] = reason
                cov["reason_code"] = cov.get("reason_code") if cov.get("runs") else code
            rt.events.emit("investigate", entity=entity, depth=depth, modules=[c.name for c in runnable])
            run = self._run_info(entity, is_seed=node.seed, depth=depth, provenance=provenance.get(entity.key, ()), case_id=case_id)
            for cls in runnable:
                pair = (cls.name, entity.key)
                if pair in scheduled_pairs:
                    continue
                scheduled_pairs.add(pair)
                fut = pool.submit(self.run_module, cls, entity, case_dir if opts.save_evidence else None, run=run)
                futures[fut] = (cls, entity, depth)

        for seed in case.seeds:
            graph.add_node(seed, 0, seed=True)
        for seed in case.seeds:
            schedule(seed, 0)

        try:
            while futures:
                if rt.cancel_event.is_set():
                    case.interrupted = True
                    case.notes.append("scan cancelled: partial results")
                    break
                if opts.timeout_total and time.monotonic() - start > opts.timeout_total:
                    rt.cancel("deadline")  # kill switch: runs still in flight send no new requests
                    case.interrupted = True
                    case.notes.append(f"global timeout ({opts.timeout_total:.0f}s) reached: partial results")
                    break
                done, _pending = wait(list(futures), timeout=0.25, return_when=FIRST_COMPLETED)
                for fut in done:
                    cls, entity, depth = futures.pop(fut)
                    try:
                        res = fut.result()
                    except Exception as exc:  # strict contract violations surface here as errors
                        res = ModuleResult(cls.name, entity, status=Status.ERROR, error=_redact(f"{type(exc).__name__}: {exc}"), reason_code="error")
                    self._absorb(case, res, depth, expanded, schedule)
        except KeyboardInterrupt:
            rt.cancel()
            case.interrupted = True
            case.notes.append("interrupted by the analyst (Ctrl+C): partial results")
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        self._finish(case)
        case.duration = time.monotonic() - start
        rt.events.emit("scan_done", case=case)
        return case

    # ------------------------------------------------------------------ merging
    def _absorb(self, case: CaseResult, res: ModuleResult, depth: int, expanded: Counter, schedule: Any) -> None:
        graph, opts, rt = case.graph, self.options, self.runtime
        case.results.append(res)
        cov = case.coverage.setdefault(res.module, _cov_name(res.module))
        cov["runs"] = cov.get("runs", 0) + 1
        cov[res.status.value] = cov.get(res.status.value, 0) + 1
        cov["status"] = _merge_status(cov.get("status"), res.status.value)
        if res.partial:
            cov["partial"] = cov.get("partial", 0) + 1
            cov["stop_reason"] = res.stop_reason
        if res.status in (Status.ERROR, Status.RATE_LIMITED, Status.NEEDS_KEY, Status.UNAVAILABLE, Status.BLOCKED, Status.QUOTA):
            if res.error:
                cov["reason"] = res.error[:200]
            if res.reason_code:
                cov["reason_code"] = res.reason_code
        if res.raw is not None and opts.save_evidence and case.case_dir:
            self._save_evidence(Path(case.case_dir), res)
        node, _ = graph.add_node(res.entity, depth, source=res.module)
        if res.attributes:
            graph.add_attributes(res.entity, res.attributes, res.module)
        for f in res.findings:
            graph.add_finding(f)
            rt.events.emit("finding", finding=f)
        if res.links:
            bucket = case.links.setdefault(res.entity.key, [])
            for item in res.links:
                if item not in bucket:
                    bucket.append(item)
        for pv in res.pivots:
            child, created = graph.add_node(pv.entity, depth + 1, source=res.module)
            graph.add_edge(res.entity, pv.entity, pv.relation, res.module, pv.confidence)
            if created:
                rt.events.emit("entity", entity=pv.entity, parent=res.entity, relation=pv.relation, module=res.module, depth=depth + 1)
            if self._should_expand(pv, child, res.entity, depth + 1, expanded):
                schedule(pv.entity, depth + 1, (res.entity.key, pv.relation, res.module))
        rt.events.emit("module_done", result=res)

    def _should_expand(self, pv: Pivot, child: Any, parent: Entity, depth: int, expanded: Counter) -> bool:
        if depth > self.options.depth or not pv.expand or child.investigated:
            return False
        if pv.entity.type in NO_AUTO_EXPAND:
            return False
        if noise.is_noise(pv.entity):
            child.noise = True
            return False
        k = (parent.key, pv.entity.type)
        # IOCs pasted by the analyst (text/file inputs) are all wanted: only the entity budget limits them.
        cap = INPUT_LIST_CAP if parent.type in (EntityType.TEXT, EntityType.FILE) else EXPAND_CAP.get(pv.entity.type, DEFAULT_CAP)
        if expanded[k] >= cap:
            return False
        expanded[k] += 1
        return True

    @staticmethod
    def _save_evidence(case_dir: Path, res: ModuleResult) -> None:
        try:
            payload = {
                "module": res.module,
                "entity": res.entity.key,
                "collected_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
                "redacted_fields": list(res.redacted_fields),
                "data": res.raw,
            }
            # AR01: configured key values and key-like URL parameters never reach an evidence file
            blob = _redact(json.dumps(payload, ensure_ascii=False, indent=1, default=str)).encode("utf-8")
            digest = hashlib.sha256(blob).hexdigest()
            # A4/AR24: no raw value (e-mail, CPF, phone...) in a path; WP15 moves this to the keyed
            # HMAC of the installation secret (<module>__<type>__<hmac12>__<sha10>.json)
            slug = hashlib.sha256(res.entity.key.encode("utf-8")).hexdigest()[:12]
            module = re.sub(r"[^A-Za-z0-9._-]+", "_", res.module)[:64] or "module"
            path = case_dir / "evidence" / f"{module}__{res.entity.type.value}__{slug}__{digest[:10]}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(blob)
            res.evidence, res.evidence_sha256 = str(path), digest
        except (OSError, TypeError, ValueError) as exc:  # evidence failure must not lose the result
            res.error = (res.error + "; " if res.error else "") + f"evidence not saved: {exc}"

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
        graph = case.graph
        case.correlations = correlate.run_rules(graph, case.results, rctx=self.rule_context())
        for corr in case.correlations:
            self.runtime.events.emit("correlation", correlation=corr)
        case.risk = scoring.score(graph, case.correlations, self.reliability)
        # Manual pivot links for the most relevant entities.
        relevant = [n for n in graph.nodes.values() if not n.noise and (n.seed or n.depth <= 1)]
        relevant.sort(key=lambda n: (not n.seed, n.depth))
        for node in relevant[:40]:
            extra = linklib.links_for(node.entity)
            if extra:
                bucket = case.links.setdefault(node.key, [])
                for item in extra:
                    if item not in bucket:
                        bucket.append(item)


def _shares_input(cls: type[Module]) -> bool:
    """Does the module send the investigated value out? (v2: derived from the declared disclosure)."""
    disclosure = getattr(cls, "disclosure", None)
    if disclosure:
        return disclosure in ("third_party", "target")
    return bool(getattr(cls, "shares_input", True))


def _readiness(cls: type[Module], keys: dict[str, str], opts: ScanOptions) -> tuple[bool, Status, str, str]:
    """(ready, status, reason_code, reason) via module.readiness_check (v2) or the v1 readiness()."""
    check = getattr(_module, "readiness_check", None)
    if callable(check):
        r = check(cls, keys, opts.mode, opts.authorized)
        if r.ready:
            return True, Status.OK, "", "ready"
        status = Status(r.status)
        code = r.reason_code if valid_reason(status, r.reason_code) else DEFAULT_REASON.get(status, "")
        return False, status, code, r.reason
    ready, reason = readiness(cls, keys, opts.mode, opts.authorized)
    if ready:
        return True, Status.OK, "", reason
    text = reason.lower()
    if "package" in text:
        return False, Status.UNAVAILABLE, "package", reason
    if "key" in text:
        return False, Status.NEEDS_KEY, "needs_key", reason
    if "authorized" in text:
        return False, Status.SKIPPED, "authorization", reason
    return False, Status.SKIPPED, "opsec", reason


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


def _cov(cls: type[Module]) -> dict[str, Any]:
    return {"title": cls.title or cls.name, "category": cls.category, "status": "not_run", "runs": 0}


def _cov_name(name: str) -> dict[str, Any]:
    from v3lum.core.module import REGISTRY

    cls = REGISTRY.get(name)
    return _cov(cls) if cls else {"title": name, "category": "?", "status": "not_run", "runs": 0}


_STATUS_RANK = {
    "ok": 7, "empty": 6, "rate_limited": 5, "quota": 5, "blocked": 4, "error": 3,
    "needs_key": 2, "unavailable": 2, "skipped": 1, "not_run": 0,
}


def _merge_status(current: str | None, new: str) -> str:
    if current is None or _STATUS_RANK.get(new, 0) > _STATUS_RANK.get(current, 0):
        return new
    return current
