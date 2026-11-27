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

Run-time guarantees of :func:`run_rules` for both kinds of rule (P301, WP22):

* per-rule precision (P325 feedback, ``Store.rule_precision()``): a rule whose precision is below
  :data:`PRECISION_THRESHOLD` (0.3) after at least :data:`PRECISION_MIN_VOTES` (10) votes emits its
  correlations one severity level lower, labelled ``P301-precision`` in ``suppressed_by`` and tagged
  ``precision_demoted``; it is never disabled, and :func:`rules_listing` flags it for doctor;
* natural persons (P258 cond 3): a correlation over a ``person_name``/``cpf`` entity, tagged
  ``natural_person`` or produced by a rule declared ``person`` is capped at PROBABLE unless an
  analyst confirmed it (label ``P258-person-cap``);
* every correlation carries a one-line ``why`` (the rule's criterion when the rule sets none) and
  ATT&CK ids validated against the bundled index and canonicalised (T1656 -> T1684.001);
* read only (P301 cond 5): rules taking a context get copies of the scan options and of ``meta``
  (a rule can never change the opsec mode, the scope or the module selection); a rule that changes
  them or adds nodes, edges or findings to the graph gets a :data:`RULE_ERRORS` entry.

Data rules are compiled by :mod:`v3lum.core.rules_engine` (schema ``v3lum.rule/1``). User rules in
``~/.v3lum/rules`` load only from an owner-only directory (``paths.insecure_reasons() == []``, AR12),
pass the P327 data lint (``lint.lint_data_file``), never take an id already registered and are
reported by :func:`user_rules_report` (doctor).
"""

from __future__ import annotations

import copy
import datetime as _dt
import importlib
import inspect
import json
import logging
import pkgutil
import re
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from v3lum.core import attack as attack_index
from v3lum.core.graph import GRAPH_FIXTURE_SCHEMA, Graph
from v3lum.core.models import Confidence, Correlation, Finding, ModuleResult, Opsec, Severity

if TYPE_CHECKING:  # pragma: no cover
    from v3lum.config import Config
    from v3lum.core.context import ScanOptions

log = logging.getLogger("v3lum.correlate")

RuleFn = Callable[..., Iterable[Correlation]]
Compiler = Callable[..., Any]

#: The v1 rules still defined in v3lum/correlations/generic.py: exempt from the fixture requirement
#: until a pack rule replaces them (a non-legacy rule with the same id supersedes the legacy one).
#: WP22 removed the replaced ones from generic.py: multi_source_malicious (CR27, WP23),
#: exploitable_exposure (P291 alias, WP23) and breach_and_infostealer (CR09-CR12, WP24).
LEGACY_RULES: frozenset[str] = frozenset({
    "shared_infrastructure", "seeds_linked", "username_reuse", "young_domain", "high_signal_tags",
})
#: Legacy ids removed from generic.py by WP22 (kept for listings and migration notes).
RETIRED_LEGACY_RULES: frozenset[str] = frozenset({"multi_source_malicious", "breach_and_infostealer", "exploitable_exposure"})
#: Modules whose rules with a LEGACY_RULES id are the legacy versions.
LEGACY_MODULES: frozenset[str] = frozenset({"v3lum.correlations.generic"})
#: Directory of data rules (P301); only kinds with a registered compiler are loaded.
RULES_DATA_DIR: Path = Path(__file__).resolve().parent.parent / "data" / "rules"
RULE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_KIND_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
#: P301 cond 8: a rule below this precision after PRECISION_MIN_VOTES votes is demoted one level.
PRECISION_THRESHOLD = 0.3
PRECISION_MIN_VOTES = 10
#: Labels recorded in Correlation.suppressed_by by run_rules (never deletions).
PRECISION_LABEL = "P301-precision"
PERSON_CAP_LABEL = "P258-person-cap"
#: Tag on a correlation demoted for low precision / marking a natural-person link / analyst-confirmed.
PRECISION_TAG = "precision_demoted"
PERSON_TAG = "natural_person"
ANALYST_CONFIRMED_TAG = "analyst_confirmed"
#: Entity types that are natural persons (P258 cond 3: links capped at PROBABLE without analyst confirmation).
NATURAL_PERSON_TYPE_VALUES: frozenset[str] = frozenset({"person_name", "cpf"})
#: Sub-directory of the V3LUM home holding user data rules (AR12 ownership checks).
USER_RULES_DIRNAME = "rules"
_FALSE_POSITIVE_VERDICTS = frozenset({"false_positive", "false positive", "fp", "benign", "wrong", "negative", "not_malicious"})


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
    person: bool = False  # touches natural persons: P258 caps (and, for data rules, the purpose gate)
    user: bool = False  # loaded from the user rule directory (~/.v3lum/rules)


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
#: The last user-directory load: [{path, status ('loaded'|'refused'|'error'), reason, rules}] (doctor).
_USER_REPORT: list[dict[str, Any]] = []
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
            # only the remaining v1 rules are exempt from the fixture gate: a rule cannot opt out by itself
            info.legacy = False
            _add_error(info.id, f"legacy is reserved for correlate.LEGACY_RULES (the remaining v1 rules of generic.py): {info.id!r} ships positive and negative fixtures")
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
    person: bool = False,
) -> Callable[[RuleFn], RuleFn]:
    """Register a correlation rule. ``fn(graph, results)`` or ``fn(graph, results, rctx)``.

    ``legacy`` defaults to: the id is in LEGACY_RULES and the function lives in a legacy module. It is
    never True for another id (an explicit ``legacy=True`` there is a RULE_ERRORS entry): new rules
    always ship graph fixtures. ``person=True`` declares a rule about natural persons: run_rules caps
    its correlations at PROBABLE unless an analyst confirmed them (P258 cond 3, WP22).
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
            person=bool(person),
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


def load_rules(force: bool = False, *, user_dir: str | Path | None = None, include_user: bool = True) -> dict[str, RuleInfo]:
    """Import every ``v3lum.correlations`` module, compile the bundled data rules
    (``v3lum/data/rules``), then the user rules (``~/.v3lum/rules`` or ``user_dir``) unless
    ``include_user`` is False. Errors never raise (they go to :data:`RULE_ERRORS`; user-directory
    problems also to :func:`user_rules_report`)."""
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
        _register_data_compiler()
        _load_data_rules()
        if include_user:
            load_user_rules(user_dir)
        _LOADED = True
    return RULES


def _register_data_compiler() -> None:
    """Import :mod:`v3lum.core.rules_engine` (it registers the ``'data'`` compiler, P301)."""
    try:
        from v3lum.core import rules_engine

        rules_engine.ensure_registered()
    except Exception as exc:  # noqa: BLE001 - a broken engine never breaks the Python rules
        RULE_ERRORS["v3lum.core.rules_engine"] = f"{type(exc).__name__}: {exc}"
        log.warning("data-rule engine unavailable: %s", exc)


def _home_path() -> Path:
    """The V3LUM home (``$V3LUM_HOME`` or ``~/.v3lum``) without creating it."""
    import os

    return Path(os.environ.get("V3LUM_HOME") or Path.home() / ".v3lum")


def user_rules_dir() -> Path:
    """``~/.v3lum/rules`` (``$V3LUM_HOME/rules``); never created by V3LUM."""
    return _home_path() / USER_RULES_DIRNAME


def _insecure(path: Path) -> list[str]:
    from v3lum import paths

    return list(paths.insecure_reasons(path))


def _lint_blocking(path: Path, doc: Any = None) -> list[str]:
    """Blocking P327 data-lint issues of one rule file (``lint.lint_data_file``). ``doc`` is the
    parsed document: the lint then reads it, so TOML and YAML rules are linted like JSON ones."""
    try:
        from v3lum.core import lint
    except ImportError:  # pragma: no cover - defensive
        return ["the P327 data lint is unavailable"]
    try:
        issues = lint.lint_data_file(path) if doc is None else lint.lint_data_file(path, data=doc)
    except Exception as exc:  # noqa: BLE001 - a lint crash refuses the file, it never passes it
        return [f"lint failed ({type(exc).__name__})"]
    out = []
    for issue in issues or ():
        if getattr(issue, "allowed", False):
            continue
        rule_id = getattr(issue, "rule_id", "")
        message = getattr(issue, "message", "") or str(issue)
        out.append(f"{rule_id}: {message}" if rule_id else message)
    return out


def load_user_rules(directory: str | Path | None = None) -> list[RuleInfo]:
    """Load the analyst's data rules from ``directory`` (default :func:`user_rules_dir`).

    AR12: nothing loads unless the directory and every file in it pass ``paths.insecure_reasons``
    (owned by the current user, not group/world-writable). Each file must pass the P327 data lint
    (``lint.lint_data_file``) and the ``v3lum.rule/1`` schema (JSON, TOML, or YAML with the optional
    'yaml' extra); an id that is already registered (bundled, pack or legacy rule) is refused, so a
    user rule never replaces a reviewed one. Every outcome is recorded for :func:`user_rules_report`
    and problems also go to :data:`RULE_ERRORS` (key ``user:<file>``). Returns the registered rules.
    """
    d = Path(directory) if directory is not None else user_rules_dir()
    with _LOCK:
        _USER_REPORT.clear()
        for rid in [rid for rid, info in RULES.items() if info.user]:  # a reload starts from scratch
            del RULES[rid]
        for key in [k for k in RULE_ERRORS if k.startswith("user:")]:
            del RULE_ERRORS[key]
        if not d.is_dir():
            return []
        try:
            from v3lum.core import rules_engine
        except Exception as exc:  # noqa: BLE001
            _USER_REPORT.append({"path": str(d), "status": "error", "reason": f"data-rule engine unavailable ({type(exc).__name__})", "rules": []})
            return []
        files = rules_engine.rule_files(d, allow_yaml=True)
        refused = _insecure(d)
        for path in files:
            refused += _insecure(path)
        if refused:
            reason = "user rule directory refused (AR12): " + "; ".join(refused) + " - chmod 700/600 and own it"
            _USER_REPORT.append({"path": str(d), "status": "refused", "reason": reason, "rules": []})
            _add_error(f"user:{d.name}", reason)
            return []
        loaded: list[RuleInfo] = []
        for path in files:
            key = f"user:{path.name}"
            try:
                doc = rules_engine.read_rule_file(path, allow_yaml=True)
            except ValueError as exc:
                _USER_REPORT.append({"path": str(path), "status": "error", "reason": str(exc), "rules": []})
                _add_error(key, str(exc))
                continue
            problems = _lint_blocking(path, doc)
            if problems:
                reason = "P327 data lint: " + "; ".join(problems)
                _USER_REPORT.append({"path": str(path), "status": "refused", "reason": reason, "rules": []})
                _add_error(key, reason)
                continue
            try:
                info = rules_engine.compile_rule(doc, path=path, origin=f"user:{path}")
            except ValueError as exc:
                _USER_REPORT.append({"path": str(path), "status": "error", "reason": str(exc), "rules": []})
                _add_error(key, str(exc))
                continue
            if info.id in RULES or info.id in RULE_REPLACED:
                reason = f"rule id {info.id!r} is already registered ({(RULES.get(info.id) or RULE_REPLACED[info.id]).origin}): user rules never replace reviewed rules"
                _USER_REPORT.append({"path": str(path), "status": "refused", "reason": reason, "rules": [info.id]})
                _add_error(key, reason)
                continue
            info.user = True
            register_rule(info)
            loaded.append(info)
            _USER_REPORT.append({"path": str(path), "status": "loaded", "reason": "", "rules": [info.id]})
        return loaded


def user_rules_report() -> list[dict[str, Any]]:
    """The last user-rule load for doctor: ``[{path, status ('loaded'|'refused'|'error'), reason,
    rules}]`` ([] when ``~/.v3lum/rules`` does not exist)."""
    with _LOCK:
        return [dict(row, rules=list(row.get("rules") or ())) for row in _USER_REPORT]


def _load_data_rules() -> None:
    if not _COMPILERS:
        return
    directory = Path(RULES_DATA_DIR)
    if not directory.is_dir():
        return
    for path in sorted(list(directory.glob("*.yaml")) + list(directory.glob("*.yml"))):
        RULE_ERRORS[path.name] = "bundled rules are JSON or TOML (YAML is accepted only in ~/.v3lum/rules with the optional 'yaml' extra)"
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
    # wave-1 behaviour (tests/test_rule_api.py): unknown ids stay on the correlation, canonicalised and
    # flagged in RULE_ERRORS (which fails the rule's fixtures and the contract test in CI)
    corr.attack = list(dict.fromkeys(attack_index.canonical(t) for t in ids))
    if not str(corr.why or "").strip():  # P301 cond 6: a one-line 'why' on every correlation
        corr.why = _one_line(corr.criterion or info.criterion or info.title)
    corr.ensure_id()


def _one_line(text: Any, limit: int = 240) -> str:
    line = " ".join(str(text or "").split())
    return line if len(line) <= limit else line[: limit - 3] + "..."


# ----------------------------------------------------------------------------------------
# Per-rule precision (P301 cond 8 / P325) and the natural-person caps (P258 cond 3)
# ----------------------------------------------------------------------------------------

PrecisionTable = dict[str, tuple[float, int]]


def _coerce_precision(raw: Any) -> PrecisionTable:
    out: PrecisionTable = {}
    if not isinstance(raw, Mapping):
        return out
    for rid, value in raw.items():
        try:
            if isinstance(value, Mapping):
                precision, votes = float(value.get("precision")), int(value.get("votes") or 0)
            else:
                precision, votes = float(value[0]), int(value[1])
        except (TypeError, ValueError, IndexError, KeyError):
            continue
        out[str(rid)] = (precision, votes)
    return out


def precision_table(rctx: RuleContext | None = None, precision: Any = None, *, store: Any = None) -> PrecisionTable:
    """``{rule_id: (precision, votes)}`` for the run (``Store.rule_precision()``, P325).

    Sources, first found wins: ``precision`` (a mapping or a callable returning one), ``store``,
    ``rctx.meta['rule_precision']`` (mapping or callable), ``rctx.meta['store']`` and the store behind
    ``rctx.meta['sightings_lookup']`` (the App installs ``Store.sightings_for`` there). Never raises:
    no table means no demotion.
    """
    candidates: list[Any] = [precision]
    if store is not None:
        candidates.append(getattr(store, "rule_precision", None))
    meta = getattr(rctx, "meta", None) if rctx is not None else None
    if isinstance(meta, Mapping):
        candidates.append(meta.get("rule_precision"))
        candidates.append(getattr(meta.get("store"), "rule_precision", None))
        bound = getattr(meta.get("sightings_lookup"), "__self__", None)
        candidates.append(getattr(bound, "rule_precision", None))
    for candidate in candidates:
        if candidate is None:
            continue
        try:
            raw = candidate() if callable(candidate) else candidate
        except Exception as exc:  # noqa: BLE001 - a broken case DB never breaks the rules
            log.warning("rule precision unavailable: %s", type(exc).__name__)
            continue
        if isinstance(raw, Mapping):
            return _coerce_precision(raw)
    return {}


def demoted(precision: float | None, votes: int | None) -> bool:
    """P301 cond 8: precision below PRECISION_THRESHOLD after at least PRECISION_MIN_VOTES votes."""
    if precision is None or votes is None:
        return False
    return int(votes) >= PRECISION_MIN_VOTES and float(precision) < PRECISION_THRESHOLD


def _apply_precision(corr: Correlation, rid: str, table: PrecisionTable) -> None:
    entry = table.get(corr.rule) or table.get(rid)
    if entry is None or not demoted(*entry):
        return
    precision, votes = entry
    before = corr.severity
    after = Severity(max(int(Severity.INFO), int(before) - 1))
    corr.severity = after
    reason = (
        f"rule precision {precision:.2f} over {votes} analyst votes (< {PRECISION_THRESHOLD} after >= {PRECISION_MIN_VOTES}): "
        + (f"severity lowered {before.label} -> {after.label}" if after != before else "already at the lowest severity")
    )
    corr.suppressed_by.append({"rule": PRECISION_LABEL, "reason": reason, "from": before.label, "to": after.label})
    if PRECISION_TAG not in corr.tags:
        corr.tags.append(PRECISION_TAG)


def _entity_type_value(entity: Any) -> str:
    etype = getattr(entity, "type", None)
    return str(getattr(etype, "value", "") or "") if etype is not None else str(entity).split(":", 1)[0]


def touches_natural_person(corr: Correlation, info: RuleInfo | None = None) -> bool:
    """Does the correlation concern natural persons (P258 cond 3)? A rule declared ``person``, a
    ``natural_person`` tag, or a person_name/cpf entity."""
    if info is not None and info.person:
        return True
    if PERSON_TAG in corr.tags:
        return True
    return any(_entity_type_value(e) in NATURAL_PERSON_TYPE_VALUES for e in corr.entities)


def _analyst_confirmed(corr: Correlation, rctx: RuleContext | None, findings: dict[str, Finding] | None) -> bool:
    """An analyst decision backs the correlation: the ``analyst_confirmed`` tag, its id listed in
    ``rctx.meta['analyst_confirmed']``, or an evidence finding with an analyst override labelled
    confirmed (and not a false-positive verdict)."""
    if ANALYST_CONFIRMED_TAG in corr.tags:
        return True
    meta = getattr(rctx, "meta", None) if rctx is not None else None
    listed = meta.get("analyst_confirmed") if isinstance(meta, Mapping) else None
    if isinstance(listed, (list, tuple, set, frozenset)) and corr.id in {str(x) for x in listed}:
        return True
    if findings:
        for ref in corr.evidence:
            f = findings.get(str(ref))
            override = getattr(f, "override", None) if f is not None else None
            if not isinstance(override, Mapping):
                continue
            verdict = str(override.get("verdict") or "").strip().lower()
            label = str(override.get("label") or override.get("confidence_label") or "").strip().lower()
            if label == Confidence.CONFIRMED.value and verdict not in _FALSE_POSITIVE_VERDICTS:
                return True
    return False


def _apply_person_cap(corr: Correlation, info: RuleInfo, rctx: RuleContext | None, findings: dict[str, Finding] | None) -> None:
    if corr.label is not Confidence.CONFIRMED or not touches_natural_person(corr, info):
        return
    if _analyst_confirmed(corr, rctx, findings):
        return
    corr.downgrade(PERSON_CAP_LABEL, "link between natural persons: at most probable without analyst confirmation (P258)", to=Confidence.PROBABLE)


def _graph_shape(graph: Any) -> tuple[int, int, int]:
    """Node, edge and finding counts (a rule that changes them wrote to the graph)."""
    try:
        nodes = getattr(graph, "nodes", None) or {}
        return (len(nodes), len(getattr(graph, "edges", None) or ()), sum(len(getattr(n, "findings", ()) or ()) for n in nodes.values()))
    except Exception:  # noqa: BLE001 - a graph stand-in without these collections is not checked
        return (0, 0, 0)


def _options_state(options: Any) -> Any:
    """A comparable snapshot of the scan options (``ScanOptions.to_dict()`` when available)."""
    if options is None:
        return None
    try:
        to_dict = getattr(options, "to_dict", None)
        return json.dumps(to_dict() if callable(to_dict) else vars(options), sort_keys=True, default=str)
    except Exception:  # noqa: BLE001 - an options stand-in that cannot be snapshotted is not checked
        return None


def _guarded_context(context: RuleContext) -> tuple[RuleContext, Any]:
    """The RuleContext handed to rules: same org/providers/settings, a copy of ``meta`` and a copy of
    the scan options (containers copied too), so a rule can never change the scan's opsec mode,
    scope or depth; returns it with the snapshot :func:`run_rules` compares against."""
    options = context.options
    if options is not None:
        try:
            clone = copy.copy(options)
            for name, value in list(vars(clone).items()):
                if isinstance(value, (set, dict, list)):
                    setattr(clone, name, copy.copy(value))
            options = clone
        except Exception:  # noqa: BLE001 - uncopyable options stand-in: handed as is, still compared
            options = context.options
    guarded = RuleContext(now=context.now, org=context.org, options=options, providers=context.providers,
                          settings=context.settings, meta=dict(context.meta or {}))
    return guarded, _options_state(context.options)


def run_rules(
    graph: Graph,
    results: list[ModuleResult],
    only: set[str] | None = None,
    *,
    rctx: RuleContext | None = None,
    precision: Any = None,
) -> list[Correlation]:
    """Run the registered rules once; dedupe by (rule, entities, title); sort by severity/confidence.

    Each correlation gets the rule version, the rule's criterion/references/ATT&CK ids when it
    sets none (ids canonicalised, e.g. T1656 -> T1684.001), a one-line ``why`` and a deterministic
    id. Then, for Python and data rules alike: the precision demotion (``precision`` or
    :func:`precision_table`; < 0.3 after >= 10 votes -> one severity level lower, labelled) and the
    natural-person cap (PROBABLE at most without analyst confirmation, labelled). Rules only read the
    graph; a rule that raises is isolated (RULE_ERRORS) and the others still run.
    """
    load_rules()
    out: list[Correlation] = []
    seen: set[tuple[str, tuple[str, ...], str]] = set()
    ids: set[str] = set()
    context = rctx
    table = precision_table(rctx, precision)
    findings_by_id: dict[str, Finding] | None = None
    guarded: RuleContext | None = None  # the read-only view of the context handed to rules
    reference: dict[str, Any] | None = None
    for rid, info in list(RULES.items()):
        if only and rid not in only:
            continue
        shape = _graph_shape(graph)
        try:
            if info.takes_context:
                if context is None:
                    context = _default_context()
                if guarded is None:
                    guarded, reference = _guarded_context(context)
                produced = info.fn(graph, results, guarded)
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
                if table:
                    _apply_precision(corr, rid, table)
                if corr.label is Confidence.CONFIRMED and touches_natural_person(corr, info):
                    if findings_by_id is None:
                        findings_by_id = {f.id: f for f in graph.findings() if f.id}
                    _apply_person_cap(corr, info, context, findings_by_id)
                out.append(corr)
        except Exception as exc:  # a broken rule must not break the report
            _add_error(rid, f"{type(exc).__name__}: {exc}")
            log.warning("rule %s failed: %s", rid, exc)
        # P301 cond 5: rules only read the graph and emit correlations - they never add to the graph
        # and never change the opsec mode, the scope or another scan option (they get a copy of the
        # options; a change is recorded and the next rule gets a fresh copy)
        if _graph_shape(graph) != shape:
            _add_error(rid, "rule added nodes, edges or findings to the graph (rules only read it, P301)")
        if guarded is not None and reference is not None and _options_state(guarded.options) != reference:
            _add_error(rid, "rule changed the scan options (rules never change the opsec mode or the scope, P301)")
            guarded, reference = _guarded_context(context)
    out.sort(key=lambda c: (-int(c.severity), -c.confidence))
    return out


_FIXTURES_ROOT = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures" / "rules"


def _fixture_files(info: RuleInfo) -> list[str]:
    """The rule's declared fixtures, else the graph fixtures found in a source checkout."""
    if info.fixtures:
        return list(info.fixtures)
    folder = _FIXTURES_ROOT / info.id
    if not folder.is_dir():
        return []
    return [f"tests/fixtures/rules/{info.id}/{p.name}" for p in sorted(folder.glob("*.json")) if p.name.startswith(("positive_", "negative_"))]


def rules_listing(*, precision: Any = None, store: Any = None) -> list[dict[str, Any]]:
    """One row per registered rule for ``v3lum rules`` and doctor (sorted by id).

    Rows: id, code, version, title, severity, criterion, attack, legacy, kind, fixtures,
    description, references, false_positives, takes_context, person, user, origin, error, and the
    per-rule ``precision``/``votes`` (None/0 without a precision table: pass ``precision`` or a
    ``store`` with ``rule_precision()``) with ``demoted`` (P301 cond 8: flagged for doctor, never
    disabled).
    """
    load_rules()
    table = precision_table(None, precision, store=store)
    rows = []
    for rid in sorted(RULES):
        info = RULES[rid]
        prec, votes = table.get(rid, (None, 0))
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
            "fixtures": _fixture_files(info),
            "description": info.description,
            "references": list(info.references),
            "false_positives": info.false_positives,
            "takes_context": info.takes_context,
            "person": info.person,
            "user": info.user,
            "origin": info.origin,
            "precision": prec,
            "votes": votes,
            "demoted": demoted(prec, votes),
            "error": RULE_ERRORS.get(rid, ""),
        })
    return rows


def demoted_rules(*, precision: Any = None, store: Any = None) -> list[dict[str, Any]]:
    """The rules :func:`run_rules` currently demotes for low precision (doctor's flag list):
    ``[{id, precision, votes, registered}]``. Votes are recorded under the correlation's ``rule``
    name, which can differ from the registered id (``high_signal_tags`` emits ``tag_sanctions``...):
    such names are listed too, with ``registered`` False, because run_rules demotes them as well."""
    table = precision_table(None, precision, store=store)
    load_rules()
    out = [{"id": rid, "precision": prec, "votes": votes, "registered": rid in RULES}
           for rid, (prec, votes) in sorted(table.items()) if demoted(prec, votes)]
    return out


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
