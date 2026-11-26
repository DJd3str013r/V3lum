"""Cross-referencing engine: correlation rules run once over the finished investigation graph.

A rule is a function registered with ``@rule`` in a ``v3lum/correlations/<pack>.py`` file
(auto-discovered, like modules)::

    @rule("young_domain", "Recently registered domain", version="1", code="CR04", severity="medium",
          criterion="registration date within 30 days (RDAP)", attack=("T1566",))
    def young_domain(graph, results):            # v1 two-argument form keeps working
        ...

    @rule("exposed_admin", "Exposed remote admin")
    def exposed_admin(graph, results, rctx):      # three positional parameters -> RuleContext
        if rctx.org and ...

Rules only read the graph and emit :class:`~v3lum.core.models.Correlation` objects; they never
schedule modules or pivots, change the opsec mode or widen the scope. Python rules and data
rules (``v3lum/data/rules/*.json|*.toml``, compiled by a registered compiler - P301, wave 4)
share one registry (:data:`RULES`), one metadata model (:class:`RuleInfo`) and one listing
(:func:`rules_listing`, ``v3lum rules``). Every non-legacy rule ships positive and negative graph
fixtures in ``tests/fixtures/rules/<rule_id>/`` (:func:`load_graph_fixture`).
"""

from __future__ import annotations

import datetime as _dt
import importlib
import inspect
import json
import logging
import pkgutil
import re
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from v3lum.core import attack as attack_index
from v3lum.core.graph import GRAPH_FIXTURE_SCHEMA, Graph
from v3lum.core.models import Correlation, Finding, ModuleResult, Opsec, Severity

if TYPE_CHECKING:  # pragma: no cover
    from v3lum.config import Config
    from v3lum.core.context import ScanOptions

log = logging.getLogger("v3lum.correlate")

RuleFn = Callable[..., Iterable[Correlation]]
Compiler = Callable[..., Any]

#: The eight v1 rules of v3lum/correlations/generic.py: exempt from the fixture requirement until
#: a pack rule replaces them (a non-legacy rule with the same id supersedes the legacy one).
LEGACY_RULES: frozenset[str] = frozenset({
    "multi_source_malicious", "shared_infrastructure", "seeds_linked", "username_reuse",
    "breach_and_infostealer", "young_domain", "exploitable_exposure", "high_signal_tags",
})
#: Modules whose rules with a LEGACY_RULES id are the legacy versions.
LEGACY_MODULES: frozenset[str] = frozenset({"v3lum.correlations.generic"})
#: Directory of data rules (P301); only kinds with a registered compiler are loaded.
RULES_DATA_DIR: Path = Path(__file__).resolve().parent.parent / "data" / "rules"
RULE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_KIND_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


@dataclass
class RuleInfo:
    """Metadata of one correlation rule (Python or data rule)."""

    id: str
    title: str
    description: str
    fn: RuleFn
    version: str = "1"
    code: str = ""  # e.g. 'CR27'
    severity: str = "info"
    criterion: str = ""
    references: tuple[str, ...] = ()
    attack: tuple[str, ...] = ()
    false_positives: str = ""
    fixtures: tuple[str, ...] = ()
    kind: str = "python"
    legacy: bool = False
    takes_context: bool = False
    origin: str = ""  # python module or data file that registered it


@dataclass
class RuleContext:
    """Run-level context handed to rules declaring a third positional parameter."""

    now: _dt.datetime
    org: Any = None  # v3lum.core.orgprofile.OrgProfile | None
    options: ScanOptions | None = None
    providers: Any = None  # v3lum.core.providers.ProviderRegistry | None
    settings: Config | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    def setting(self, name: str, default: Any = None) -> Any:
        """A config setting (default when no settings are attached)."""
        if self.settings is None:
            return default
        try:
            return self.settings.get(name, default)
        except Exception:  # pragma: no cover - defensive
            return default


RULES: dict[str, RuleInfo] = {}
#: Registration/import/runtime problems: rule id (or python module / data file) -> message.
RULE_ERRORS: dict[str, str] = {}
#: Legacy rules dropped because a non-legacy rule registered the same id.
RULE_REPLACED: dict[str, RuleInfo] = {}
_COMPILERS: dict[str, Compiler] = {}
_LOADED = False
_LOCK = threading.RLock()


def _add_error(key: str, message: str) -> None:
    """Record a problem under ``key`` without losing an earlier one (messages joined with '; ')."""
    with _LOCK:
        previous = RULE_ERRORS.get(key)
        if not previous:
            RULE_ERRORS[key] = message
        elif message not in previous.split("; "):
            RULE_ERRORS[key] = f"{previous}; {message}"


def _positional_count(fn: Callable[..., Any]) -> int:
    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):  # pragma: no cover - builtins
        return 2
    count = 0
    for p in params:
        if p.kind is inspect.Parameter.VAR_POSITIONAL:
            return 3
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD):
            count += 1
    return count


def _origin(fn: Callable[..., Any]) -> str:
    return f"{getattr(fn, '__module__', '?')}.{getattr(fn, '__qualname__', getattr(fn, '__name__', '?'))}"


def register_rule(info: RuleInfo) -> RuleInfo:
    """Add a RuleInfo to the registry (used by @rule and by data-rule compilers).

    ATT&CK ids are validated (problems go to RULE_ERRORS) and canonicalised. Duplicate ids: a
    non-legacy rule supersedes a legacy one whatever the import order (the legacy rule goes to
    RULE_REPLACED); any other duplicate is a RULE_ERRORS entry and the first rule is kept.
    """
    with _LOCK:
        problems = attack_index.validate(info.attack) if info.attack else []
        info.attack = tuple(dict.fromkeys(attack_index.canonical(t) for t in info.attack))
        if info.legacy and info.id not in LEGACY_RULES:
            # only the eight v1 rules are exempt from the fixture gate: a rule cannot opt out by itself
            info.legacy = False
            _add_error(info.id, f"legacy is reserved for correlate.LEGACY_RULES (the eight v1 rules): {info.id!r} ships positive and negative fixtures")
        existing = RULES.get(info.id)
        if existing is not None and existing.origin != info.origin:
            if existing.legacy and not info.legacy:
                RULE_REPLACED[info.id] = existing
            elif info.legacy and not existing.legacy:
                RULE_REPLACED[info.id] = info
                return info
            else:
                _add_error(info.id, f"duplicate rule id {info.id!r}: {existing.origin} and {info.origin} (first kept)")
                return existing
        RULES[info.id] = info
        if problems:
            _add_error(info.id, "invalid ATT&CK ids: " + ", ".join(problems))
        return info


def rule(
    rule_id: str,
    title: str,
    description: str = "",
    *,
    version: str = "1",
    code: str = "",
    severity: str = "info",
    criterion: str = "",
    references: Iterable[str] = (),
    attack: Iterable[str] = (),
    false_positives: str = "",
    fixtures: Iterable[str] = (),
    legacy: bool | None = None,
) -> Callable[[RuleFn], RuleFn]:
    """Register a correlation rule. ``fn(graph, results)`` or ``fn(graph, results, rctx)``.

    ``legacy`` defaults to: the id is in LEGACY_RULES and the function lives in a legacy module. It is
    never True for another id (an explicit ``legacy=True`` there is a RULE_ERRORS entry): new rules
    always ship graph fixtures.
    """

    def deco(fn: RuleFn) -> RuleFn:
        try:
            sev = Severity.parse(severity).label
        except (KeyError, ValueError):
            _add_error(rule_id, f"invalid severity {severity!r}")
            sev = "info"
        is_legacy = legacy if legacy is not None else (rule_id in LEGACY_RULES and getattr(fn, "__module__", "") in LEGACY_MODULES)
        info = RuleInfo(
            id=rule_id,
            title=title,
            description=description or (fn.__doc__ or "").strip(),
            fn=fn,
            version=str(version),
            code=code,
            severity=sev,
            criterion=criterion,
            references=tuple(references),
            attack=tuple(attack),
            false_positives=false_positives,
            fixtures=tuple(fixtures),
            kind="python",
            legacy=bool(is_legacy),
            takes_context=_positional_count(fn) >= 3,
            origin=_origin(fn),
        )
        if not RULE_ID_RE.match(rule_id):
            _add_error(rule_id, f"invalid rule id {rule_id!r} (expected ^[a-z][a-z0-9_]{{1,63}}$)")
        register_rule(info)
        return fn

    return deco


def register_compiler(kind: str, fn: Compiler) -> None:
    """Register a data-rule compiler: ``fn(doc: dict, *, path: Path) -> RuleInfo | Iterable[RuleInfo]``.

    :func:`load_rules` compiles ``v3lum/data/rules/*.json|*.toml`` documents whose ``kind``
    (default 'data') has a compiler; files of other kinds are ignored.
    """
    if not _KIND_RE.match(kind or ""):
        raise ValueError(f"invalid rule kind {kind!r}")
    _COMPILERS[kind] = fn


def load_rules(force: bool = False) -> dict[str, RuleInfo]:
    """Import every ``v3lum.correlations`` module, then compile data rules. Errors never raise."""
    global _LOADED
    if _LOADED and not force:
        return RULES
    with _LOCK:
        if _LOADED and not force:
            return RULES
        import v3lum.correlations as pkg

        for info in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + "."):
            if info.name.rsplit(".", 1)[-1].startswith("_"):
                continue
            try:
                importlib.import_module(info.name)
            except Exception as exc:  # pragma: no cover - defensive
                RULE_ERRORS[info.name] = f"{type(exc).__name__}: {exc}"
                log.warning("failed to load rules %s: %s", info.name, exc)
        _load_data_rules()
        _LOADED = True
    return RULES


def _load_data_rules() -> None:
    if not _COMPILERS:
        return
    directory = Path(RULES_DATA_DIR)
    if not directory.is_dir():
        return
    for path in sorted(list(directory.glob("*.json")) + list(directory.glob("*.toml"))):
        try:
            if path.suffix == ".toml":
                try:
                    import tomllib  # Python >= 3.11
                except ImportError:
                    RULE_ERRORS[path.name] = "TOML rules need Python >= 3.11 (use JSON on 3.10)"
                    continue
                doc = tomllib.loads(path.read_text(encoding="utf-8"))
            else:
                doc = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            RULE_ERRORS[path.name] = f"unreadable rule file: {type(exc).__name__}: {exc}"
            continue
        if not isinstance(doc, dict):
            RULE_ERRORS[path.name] = "rule file must hold an object"
            continue
        compiler = _COMPILERS.get(str(doc.get("kind") or "data"))
        if compiler is None:
            continue
        try:
            compiled = compiler(doc, path=path)
        except Exception as exc:
            RULE_ERRORS[path.name] = f"{type(exc).__name__}: {exc}"
            continue
        items = [compiled] if isinstance(compiled, RuleInfo) else list(compiled or ())
        for info in items:
            if not isinstance(info, RuleInfo):
                RULE_ERRORS[path.name] = "compiler must return RuleInfo objects"
                continue
            if not info.origin:
                info.origin = str(path)
            register_rule(info)


def _default_context() -> RuleContext:
    return RuleContext(now=_dt.datetime.now(_dt.timezone.utc))


def _stamp(corr: Correlation, rid: str, info: RuleInfo) -> None:
    if not corr.rule:
        corr.rule = rid
    corr.version = info.version
    if not corr.criterion and info.criterion:
        corr.criterion = info.criterion
    if not corr.references and info.references:
        corr.references = list(info.references)
    if corr.attack:  # ids set by the rule at run time are validated like registration ids (P301 cond 6)
        problems = attack_index.validate(corr.attack)
        if problems:
            _add_error(rid, "invalid ATT&CK ids on a correlation: " + ", ".join(problems))
    ids = list(corr.attack) or list(info.attack)
    corr.attack = list(dict.fromkeys(attack_index.canonical(t) for t in ids))
    corr.ensure_id()


def run_rules(
    graph: Graph,
    results: list[ModuleResult],
    only: set[str] | None = None,
    *,
    rctx: RuleContext | None = None,
) -> list[Correlation]:
    """Run the registered rules once; dedupe by (rule, entities, title); sort by severity/confidence.

    Each correlation gets the rule version, the rule's criterion/references/ATT&CK ids when it
    sets none (ids canonicalised, e.g. T1656 -> T1684.001) and a deterministic id.
    """
    load_rules()
    out: list[Correlation] = []
    seen: set[tuple[str, tuple[str, ...], str]] = set()
    ids: set[str] = set()
    context = rctx
    for rid, info in list(RULES.items()):
        if only and rid not in only:
            continue
        try:
            if info.takes_context:
                if context is None:
                    context = _default_context()
                produced = info.fn(graph, results, context)
            else:
                produced = info.fn(graph, results)
            for corr in produced or []:
                _stamp(corr, rid, info)
                sig = (corr.rule, tuple(sorted(corr.entity_keys())), corr.title)
                if sig in seen:
                    continue
                seen.add(sig)
                if corr.id in ids:  # same rule + entities + key, different title: disambiguate deterministically
                    corr.key = corr.key or corr.title
                    corr.ensure_id()
                    n = 2
                    base = corr.key
                    while corr.id in ids:
                        corr.key = f"{base}#{n}"
                        corr.ensure_id()
                        n += 1
                ids.add(corr.id)
                out.append(corr)
        except Exception as exc:  # a broken rule must not break the report
            _add_error(rid, f"{type(exc).__name__}: {exc}")
            log.warning("rule %s failed: %s", rid, exc)
    out.sort(key=lambda c: (-int(c.severity), -c.confidence))
    return out


def rules_listing() -> list[dict[str, Any]]:
    """One row per registered rule for ``v3lum rules`` (sorted by id)."""
    load_rules()
    rows = []
    for rid in sorted(RULES):
        info = RULES[rid]
        rows.append({
            "id": info.id,
            "code": info.code,
            "version": info.version,
            "title": info.title,
            "severity": info.severity,
            "criterion": info.criterion,
            "attack": list(info.attack),
            "legacy": info.legacy,
            "kind": info.kind,
            "fixtures": list(info.fixtures),
            "description": info.description,
            "references": list(info.references),
            "false_positives": info.false_positives,
            "takes_context": info.takes_context,
            "error": RULE_ERRORS.get(rid, ""),
        })
    return rows


# ----------------------------------------------------------------------------------------
# Graph fixtures (contract section 16): tests/fixtures/rules/<rule_id>/{positive,negative}_*.json
# ----------------------------------------------------------------------------------------


@dataclass
class GraphFixture:
    """A loaded ``v3lum.graph_fixture/1`` document."""

    graph: Graph
    results: list[ModuleResult]
    rctx: RuleContext
    expect: dict[str, dict[str, Any]]
    path: str = ""


def _parse_now(value: Any) -> _dt.datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("graph fixture needs 'now' (ISO-8601 timestamp, e.g. '2026-11-26T12:00:00Z')")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    now = _dt.datetime.fromisoformat(text)
    if now.tzinfo is None:
        now = now.replace(tzinfo=_dt.timezone.utc)
    return now


def _fixture_options(raw: Any) -> Any:
    from v3lum.core.context import ScanOptions  # lazy: context imports the HTTP stack

    opts = ScanOptions()
    if not isinstance(raw, dict):
        return opts
    for name, value in raw.items():
        if not hasattr(opts, name):
            continue
        current = getattr(opts, name)
        if name == "mode":
            value = Opsec.parse(value)
        elif isinstance(current, set):
            value = set(value or ())
        setattr(opts, name, value)
    return opts


def _fixture_org(raw: Any) -> Any:
    if not raw:
        return None
    from v3lum.core import orgprofile  # lazy (WP04); a fixture with an org profile needs it

    return orgprofile.OrgProfile.from_dict(raw)


def _fixture_providers() -> Any:
    try:
        from v3lum.core import providers
    except ImportError:  # pragma: no cover - providers registry not installed
        return None
    try:
        return providers.registry()
    except Exception:  # pragma: no cover - defensive
        return None


def _fixture_settings(raw: Any) -> Any:
    from v3lum.config import Config

    cfg = Config()
    if isinstance(raw, dict):
        cfg.settings.update(raw)
    return cfg


def load_graph_fixture(path: str | Path) -> GraphFixture:
    """Load a rule fixture: graph (Graph.from_dict), results, a RuleContext and the expectations.

    The RuleContext's ``now`` is the fixture's ``now`` and its ``org`` is
    ``OrgProfile.from_dict(fixture['org_profile'])``; ``options`` become ScanOptions fields and an
    optional ``settings`` object overrides config settings.
    """
    p = Path(path)
    doc = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or doc.get("schema") != GRAPH_FIXTURE_SCHEMA:
        raise ValueError(f"{p}: schema must be {GRAPH_FIXTURE_SCHEMA!r}")
    graph = Graph.from_dict(doc)
    by_id: dict[str, Finding] = {f.id: f for f in graph.findings()}
    results = [ModuleResult.from_dict(r, findings=by_id) for r in doc.get("results") or ()]
    rctx = RuleContext(
        now=_parse_now(doc.get("now")),
        org=_fixture_org(doc.get("org_profile")),
        options=_fixture_options(doc.get("options")),
        providers=_fixture_providers(),
        settings=_fixture_settings(doc.get("settings")),
        meta=dict(doc.get("meta") or {}),
    )
    expect = doc.get("expect") or {}
    if not isinstance(expect, dict):
        raise ValueError(f"{p}: 'expect' must be an object of rule_id -> {{min, max, severity, confidence_label}}")
    return GraphFixture(graph=graph, results=results, rctx=rctx, expect=expect, path=str(p))


def check_fixture(rule_id: str, path: str | Path) -> list[str]:
    """Run ``rule_id`` over one fixture; return the list of failed expectations (empty = pass).

    ``positive_*`` fixtures need at least ``expect.min`` (default 1) and at most ``expect.max``
    (when given) correlations of the rule, each matching ``expect.severity`` /
    ``expect.confidence_label`` when given; ``negative_*`` fixtures need none.
    """
    p = Path(path)
    load_rules()
    if rule_id not in RULES:
        return [f"no rule registered with id {rule_id!r}"]
    fx = load_graph_fixture(p)
    # isolate this run's errors: an identical failure recorded by an earlier fixture must not hide this one
    with _LOCK:
        previous = RULE_ERRORS.pop(rule_id, None)
    try:
        corrs = run_rules(fx.graph, fx.results, only={rule_id}, rctx=fx.rctx)
    finally:
        with _LOCK:
            raised = RULE_ERRORS.pop(rule_id, None)
            if previous:
                RULE_ERRORS[rule_id] = previous
            if raised:
                _add_error(rule_id, raised)
    problems: list[str] = []
    if raised:
        problems.append(f"rule raised or emitted invalid data: {raised}")
    if p.name.startswith("negative_"):
        if corrs:
            problems.append(f"negative fixture produced {len(corrs)} correlation(s): {[c.title for c in corrs]}")
        return problems
    if not p.name.startswith("positive_"):
        return [f"fixture file names start with positive_ or negative_ (got {p.name})"]
    exp = fx.expect.get(rule_id) or {}
    low = int(exp.get("min", 1))
    high = exp.get("max")
    if len(corrs) < low:
        problems.append(f"expected at least {low} correlation(s), got {len(corrs)}")
    if high is not None and len(corrs) > int(high):
        problems.append(f"expected at most {high} correlation(s), got {len(corrs)}")
    if exp.get("severity"):
        want = Severity.parse(exp["severity"]).label
        bad = [c.severity.label for c in corrs if c.severity.label != want]
        if bad:
            problems.append(f"expected severity {want}, got {bad}")
    if exp.get("confidence_label"):
        want_label = str(exp["confidence_label"]).lower()
        bad = [c.label.value for c in corrs if c.label.value != want_label]
        if bad:
            problems.append(f"expected confidence_label {want_label}, got {bad}")
    return problems
