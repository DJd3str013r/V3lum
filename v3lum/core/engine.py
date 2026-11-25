"""Investigation engine: run modules, pivot on discoveries, correlate, score.

Pipelined BFS: as soon as a module returns new entities they are scheduled (no barrier
between depths). Guard rails keep investigations bounded: max depth, entity budget,
per-parent caps per entity type, noise suppression and per-module pivot caps.
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
from v3lum.core import correlate, links as linklib, noise, scoring
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.detect import Detection
from v3lum.core.entities import Entity, EntityType
from v3lum.core.graph import Graph
from v3lum.core.http import AuthRequired, HttpError, NetworkError, OfflineError, RateLimited
from v3lum.core.models import Correlation, Finding, ModuleResult, Pivot, Status
from v3lum.core.module import Module, load_modules, modules_for, readiness

# Entity types never investigated automatically (analyst decides): privacy and blast radius.
NO_AUTO_EXPAND = frozenset({
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


def new_case_id(now: _dt.datetime | None = None) -> str:
    now = now or _dt.datetime.now(_dt.timezone.utc)
    return now.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)


_DATE_ATTRS = {
    "created": "registered/created",
    "updated": "updated",
    "expires": "expires",
    "first_seen": "first seen",
    "last_seen": "last seen",
    "opened": "company opened",
    "archive_first": "first web archive snapshot",
    "cert_not_after": "certificate expires",
}


def build_timeline(graph: Graph) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for node in graph.nodes.values():
        for attr, label in _DATE_ATTRS.items():
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


class Engine:
    def __init__(self, runtime: Runtime, options: ScanOptions | None = None, *, reliability: dict[str, float] | None = None) -> None:
        self.runtime = runtime
        self.options = options or ScanOptions()
        self.reliability = reliability or {}
        load_modules(extra_dirs=[str(paths.plugins_dir())])
        correlate.load_rules()

    # ------------------------------------------------------------------ planning
    def select(self, entity: Entity) -> tuple[list[type[Module]], list[tuple[type[Module], Status, str]]]:
        keys = self.runtime.config.keys()
        opts = self.options
        runnable: list[type[Module]] = []
        blocked: list[tuple[type[Module], Status, str]] = []
        for cls in modules_for(entity.type):
            if opts.include and cls.name not in opts.include:
                continue
            if cls.name in opts.exclude:
                continue
            if opts.categories and cls.category not in opts.categories and cls.name not in opts.include:
                continue
            if not cls.default_enabled and not opts.include_disabled and cls.name not in opts.include:
                continue
            ready, reason = readiness(cls, keys, opts.mode, opts.authorized)
            if not ready:
                status = Status.NEEDS_KEY if "key" in reason else Status.UNAVAILABLE if "package" in reason else Status.SKIPPED
                blocked.append((cls, status, reason))
                continue
            runnable.append(cls)
        return runnable, blocked

    def plan(self, entity: Entity) -> list[dict[str, Any]]:
        runnable, blocked = self.select(entity)
        rows = [{"module": c.name, "title": c.title, "category": c.category, "ready": True, "reason": "ready"} for c in runnable]
        rows += [{"module": c.name, "title": c.title, "category": c.category, "ready": False, "reason": r} for c, _s, r in blocked]
        return rows

    # ------------------------------------------------------------------ execution
    def run_module(self, cls: type[Module], entity: Entity, case_dir: Path | None = None) -> ModuleResult:
        ctx = self.runtime.context(cls, self.options, case_dir)
        mod = cls()
        res = ModuleResult(module=cls.name, entity=entity)
        start = time.monotonic()
        self.runtime.events.emit("module_start", module=cls.name, entity=entity)
        try:
            if not mod.applies(entity, ctx):
                res.status = Status.SKIPPED
                res.error = "not applicable"
            else:
                out = mod.run(entity, ctx)
                if isinstance(out, ModuleResult):
                    res = out
                if res.status is Status.OK and not res.has_data:
                    res.status = Status.EMPTY
        except RateLimited as exc:
            res.status, res.error = Status.RATE_LIMITED, str(exc)
        except AuthRequired as exc:
            needs_key = bool(cls.requires_keys or cls.optional_keys)
            res.status = Status.NEEDS_KEY if needs_key else Status.ERROR
            res.error = str(exc)
        except OfflineError as exc:
            res.status, res.error = Status.UNAVAILABLE, str(exc)
        except (NetworkError, HttpError) as exc:
            res.status, res.error = Status.ERROR, str(exc)
        except Exception as exc:  # module bug: keep going, keep the trace for --debug
            res.status = Status.ERROR
            res.error = f"{type(exc).__name__}: {exc}"
            res.raw = {"traceback": traceback.format_exc(limit=6)}
        res.module = cls.name
        res.entity = entity
        res.duration = time.monotonic() - start
        res.requests = ctx.http.requests
        res.cache_hits = ctx.http.cache_hits
        if len(res.pivots) > cls.max_pivots:
            dropped = len(res.pivots) - cls.max_pivots
            res.pivots = res.pivots[: cls.max_pivots]
            res.error = (res.error + "; " if res.error else "") + f"{dropped} extra pivots dropped (cap {cls.max_pivots})"
        for f in res.findings:
            f.module = cls.name
            if f.entity is None:
                f.entity = entity
        return res

    def investigate(self, seeds: list[Entity], *, detections: list[Detection] | None = None, case_id: str | None = None) -> CaseResult:
        rt, opts = self.runtime, self.options
        rt.cancel_event.clear()
        case_id = case_id or new_case_id(rt.now())
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
        futures: dict[Future[ModuleResult], tuple[type[Module], Entity, int]] = {}
        budget_note = False
        start = time.monotonic()
        rt.events.emit("scan_start", case_id=case_id, seeds=case.seeds, options=opts)
        pool = ThreadPoolExecutor(max_workers=max(1, opts.threads), thread_name_prefix="v3lum")

        def schedule(entity: Entity, depth: int) -> None:
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
            runnable, blocked = self.select(entity)
            for cls, status, reason in blocked:
                cov = case.coverage.setdefault(cls.name, _cov(cls))
                cov["blocked"] = cov.get("blocked", 0) + 1
                cov["status"] = cov["status"] if cov.get("runs") else status.value
                cov["reason"] = reason
            rt.events.emit("investigate", entity=entity, depth=depth, modules=[c.name for c in runnable])
            for cls in runnable:
                pair = (cls.name, entity.key)
                if pair in scheduled_pairs:
                    continue
                scheduled_pairs.add(pair)
                futures[pool.submit(self.run_module, cls, entity, case_dir if opts.save_evidence else None)] = (cls, entity, depth)

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
                    case.interrupted = True
                    case.notes.append(f"global timeout ({opts.timeout_total:.0f}s) reached: partial results")
                    break
                done, _pending = wait(list(futures), timeout=0.25, return_when=FIRST_COMPLETED)
                for fut in done:
                    cls, entity, depth = futures.pop(fut)
                    try:
                        res = fut.result()
                    except Exception as exc:  # pragma: no cover - run_module never raises
                        res = ModuleResult(cls.name, entity, status=Status.ERROR, error=str(exc))
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
        if res.error and res.status in (Status.ERROR, Status.RATE_LIMITED, Status.NEEDS_KEY, Status.UNAVAILABLE):
            cov["reason"] = res.error[:200]
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
                schedule(pv.entity, depth + 1)
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
        if expanded[k] >= EXPAND_CAP.get(pv.entity.type, DEFAULT_CAP):
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
                "data": res.raw,
            }
            blob = json.dumps(payload, ensure_ascii=False, indent=1, default=str).encode("utf-8")
            digest = hashlib.sha256(blob).hexdigest()
            slug = re.sub(r"[^A-Za-z0-9._-]+", "_", res.entity.value)[:60]
            path = case_dir / "evidence" / f"{res.module}__{res.entity.type.value}__{slug}__{digest[:10]}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(blob)
            res.evidence, res.evidence_sha256 = str(path), digest
        except (OSError, TypeError, ValueError) as exc:  # evidence failure must not lose the result
            res.error = (res.error + "; " if res.error else "") + f"evidence not saved: {exc}"

    def _finish(self, case: CaseResult) -> None:
        graph = case.graph
        case.correlations = correlate.run_rules(graph, case.results)
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


def _cov(cls: type[Module]) -> dict[str, Any]:
    return {"title": cls.title or cls.name, "category": cls.category, "status": "not_run", "runs": 0}


def _cov_name(name: str) -> dict[str, Any]:
    from v3lum.core.module import REGISTRY

    cls = REGISTRY.get(name)
    return _cov(cls) if cls else {"title": name, "category": "?", "status": "not_run", "runs": 0}


_STATUS_RANK = {"ok": 6, "empty": 5, "rate_limited": 4, "error": 3, "needs_key": 2, "unavailable": 2, "skipped": 1, "not_run": 0}


def _merge_status(current: str | None, new: str) -> str:
    if current is None or _STATUS_RANK.get(new, 0) > _STATUS_RANK.get(current, 0):
        return new
    return current
