"""Data correlation rules (P301): ``v3lum.rule/1`` documents compiled into ``correlate.RuleInfo``.

Python ``@rule`` functions stay first-class; data rules are optional documents compiled into the
same :class:`~v3lum.core.correlate.RuleInfo` objects (``kind='data'``), registered in the same
registry, run by the same :func:`~v3lum.core.correlate.run_rules` and listed by ``v3lum rules``.

Model (ported from the SpiderFoot correlation engine, MIT - see the notice below)::

    collections (entity types + exact/regex filters over vocab-keyed graph facts)
        -> aggregation (bucket the matching entities by one field)
        -> analysis   (threshold | outlier | first_collection_only |
                       match_all_to_first_collection | both_collections)
        -> headline   (whitelisted placeholders only)

One correlation per surviving bucket, with the evidence used (finding ids + facts), a one-line
``why``, the rule's recommendation and its ATT&CK ids (validated and canonicalised by correlate).

Document (``"schema": "v3lum.rule/1"``; JSON or TOML in ``v3lum/data/rules/``, and also YAML through
the optional ``yaml`` extra - ``yaml.safe_load`` only - in the user directory ``~/.v3lum/rules``)::

    {"schema": "v3lum.rule/1", "id": "rare_registrar", "version": "1", "code": "",
     "title": "Rare registrar among the investigated domains", "severity": "low",
     "criterion": "registrar used by <= 10% of the domains (>= 10 domains)",
     "references": ["https://..."], "attack": ["T1583.001"], "false_positives": "...",
     "collections": [{"name": "domains", "entity_types": ["domain"],
                      "filters": [{"field": "attr:registrar", "op": "exists"}]}],
     "aggregation": {"field": "attr:registrar"},
     "analysis": {"method": "outlier", "minimum": 10, "percentile": 10},
     "headline": "{count} domain(s) use the rare registrar {value}",
     "recommendation": "Check who registered these domains.",
     "suppress": [{"name": "parked", "when": [{"field": "tag:parked", "op": "exists"}],
                   "to": "possible", "reason": "parked domains say little about ownership"}]}

Fields: ``attr:<name>`` (a vocab attribute), ``tag:<name>`` (a vocab tag on the entity or on one of
its evidence findings), ``relation:<name>`` (a vocab relation, either direction), ``type``,
``value`` (the entity value), ``finding.source`` (a finding's registry source or module) and
``finding.severity``; aggregation also takes ``entity`` (the default). Operators: ``eq``, ``in``,
``regex`` (<= 200 characters, no nested quantifiers, no backreferences, no repeated alternation,
no adjacent unbounded repeats over overlapping characters: the ReDoS guard of
:func:`regex_problems`; subjects truncated to 1024 characters), ``gte``, ``lte``
and ``exists``; ``"negate": true`` inverts a filter. Finding filters of one collection must hold
on the same evidence finding (never a ``context_only`` or ``SUP-*``-suppressed one). Noise nodes
are skipped unless a collection sets ``"include_noise": true``.

Guarantees: rules only read the graph and emit correlations - they never schedule modules or
pivots, never change the opsec mode or the scope; suppression rules only downgrade (confidence,
optionally severity) with a visible label; rules over natural persons (person_name or cpf
collections, or ``"natural_person": true``) run only in cases with a recorded purpose and inherit
the P258 caps applied by ``correlate.run_rules`` (PROBABLE at most without analyst confirmation).
Schema errors raise :class:`RuleSchemaError` (``correlate`` records them in ``RULE_ERRORS``, which
fails the registry contract test in CI).

Adapted from SpiderFoot (https://github.com/smicallef/spiderfoot, commit
0f815a203afebf05c98b605dba5cf0475a0ee5fd, spiderfoot/correlation.py and correlations/*.yaml):
the collection/aggregation/analysis/headline model and the outlier 'noisy data' guard are
re-implemented here; Copyright Steve Micallef, MIT licence (notice fragment
``v3lum/data/notices/spiderfoot_correlations.json``).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from v3lum.core import attack as attack_index
from v3lum.core import correlate
from v3lum.core.correlate import RULE_ID_RE, RuleInfo
from v3lum.core.entities import EntityType
from v3lum.core.models import Confidence, Correlation, Finding, Severity

log = logging.getLogger("v3lum.rules_engine")

__all__ = [
    "ANALYSIS_METHODS",
    "DATA_KIND",
    "FILTER_OPS",
    "HEADLINE_PLACEHOLDERS",
    "NATURAL_PERSON_TYPES",
    "RESERVED_TAGS",
    "RULE_SCHEMA",
    "RuleSchemaError",
    "compile_document",
    "compile_rule",
    "load_data_rules",
    "read_rule_file",
    "regex_problems",
    "validate_rule",
]

#: Schema id of data-rule documents.
RULE_SCHEMA = "v3lum.rule/1"
#: The correlate compiler kind of data rules (``RuleInfo.kind``).
DATA_KIND = "data"
#: Analysis methods (SpiderFoot model).
ANALYSIS_METHODS = ("threshold", "outlier", "first_collection_only", "match_all_to_first_collection", "both_collections")
#: Filter operators.
FILTER_OPS = ("eq", "in", "regex", "gte", "lte", "exists")
#: ``match_all_to_first_collection`` match methods.
MATCH_METHODS = ("exact", "contains", "subnet")
#: Placeholders a headline may use (anything else is a schema error).
HEADLINE_PLACEHOLDERS = frozenset({"value", "count", "total", "percent", "field", "collection", "entities", "rule", "severity"})
#: Entity types that are natural persons (P258 cond 3 caps and the AR16 purpose gate).
NATURAL_PERSON_TYPES = frozenset({EntityType.PERSON, EntityType.CPF})
#: Longest accepted regex (ReDoS guard).
MAX_REGEX_LEN = 200
#: Regex subjects are truncated to this many characters (graph values are untrusted: even the
#: quadratic scan of an accepted pattern stays in the millisecond range at this length).
MAX_REGEX_INPUT = 1024
#: Largest rule file accepted.
MAX_RULE_BYTES = 256 * 1024
#: Structural limits of one document.
MAX_COLLECTIONS = 8
MAX_FILTERS = 16
MAX_IN_VALUES = 500
MAX_SUPPRESS = 8
#: At most this many correlations per data rule and run (the strongest buckets first).
MAX_CORRELATIONS = 100
#: At most this many entities / evidence items per correlation.
MAX_ENTITIES = 25
MAX_EVIDENCE = 50
#: Default analysis parameters.
DEFAULT_OUTLIER_PERCENT = 10.0
DEFAULT_NOISY_PERCENT = 10.0
DEFAULT_OUTLIER_MINIMUM = 10
#: Default confidence of a data-rule correlation (a rule may declare probable/confirmed).
DEFAULT_CONFIDENCE = Confidence.POSSIBLE
#: Tags a data rule may never set: they record run-time decisions (precision demotion, analyst
#: confirmation that lifts the P258 cap), so a rule setting them would forge one.
RESERVED_TAGS = frozenset({correlate.PRECISION_TAG, correlate.ANALYST_CONFIRMED_TAG})
#: Rule file suffixes: bundled rules are JSON/TOML; YAML is user-only and needs PyYAML (extra 'yaml').
BUNDLED_SUFFIXES = (".json", ".toml")
YAML_SUFFIXES = (".yaml", ".yml")

_TOP_REQUIRED = ("schema", "id", "version", "title", "severity", "criterion", "collections", "analysis", "headline", "recommendation")
_TOP_OPTIONAL = (
    "kind", "code", "description", "references", "attack", "false_positives", "aggregation", "confidence", "tags",
    "suppress", "fixtures", "natural_person", "$comment", "notes",
)
_CODE_RE = re.compile(r"^[A-Z][A-Z0-9-]{1,15}$")
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_PLACEHOLDER_RE = re.compile(r"\{([^{}]*)\}")
_FIELD_SIMPLE = ("type", "value", "entity", "finding.source", "finding.severity")
_FIELD_PREFIXES = ("attr", "tag", "relation")
_FINDING_FIELDS = ("finding.source", "finding.severity")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_FALSE_POSITIVE_VERDICTS = frozenset({"false_positive", "false positive", "fp", "benign", "wrong", "negative", "not_malicious"})


class RuleSchemaError(ValueError):
    """A data-rule document that does not satisfy ``v3lum.rule/1`` (``problems`` lists every issue)."""

    def __init__(self, problems: list[str], *, rule_id: str = "") -> None:
        self.problems = list(problems)
        self.rule_id = rule_id
        head = f"data rule {rule_id!r}" if rule_id else "data rule"
        super().__init__(f"{head}: " + "; ".join(self.problems))


# ----------------------------------------------------------------------------------------
# ReDoS guard
# ----------------------------------------------------------------------------------------


def _sre() -> Any:
    try:
        import re._parser as parser  # Python >= 3.11

        return parser
    except ImportError:  # pragma: no cover - Python 3.10
        import sre_parse as parser  # type: ignore[import-not-found, no-redef]

        return parser


def _sre_const() -> Any:
    try:
        import re._constants as consts  # Python >= 3.11

        return consts
    except ImportError:  # pragma: no cover - Python 3.10
        import sre_constants as consts  # type: ignore[import-not-found, no-redef]

        return consts


def regex_problems(pattern: Any) -> list[str]:
    """Why ``pattern`` is not an acceptable rule regex ([] = acceptable).

    Refused: non-strings, empty patterns, more than :data:`MAX_REGEX_LEN` characters, invalid
    syntax, backreferences, a repeated sub-pattern inside another unbounded repeat (``(a+)+``,
    ``(\\w*)*``) and an alternation inside an unbounded repeat whose branches do not all start with
    distinct literal characters (``(a|aa)+``, ``(\\d|x)*``): the classic catastrophic-backtracking
    shapes. Also refused: two unbounded repeats of one sequence over overlapping characters with
    nothing mandatory between them that the first cannot consume (``\\w*\\w*x``, ``.*a.*=``): their
    backtracking is polynomial (cubic and worse) in the subject length. Subjects are also truncated
    to :data:`MAX_REGEX_INPUT` characters at run time.
    """
    if not isinstance(pattern, str) or not pattern:
        return ["regex must be a non-empty string"]
    if len(pattern) > MAX_REGEX_LEN:
        return [f"regex longer than {MAX_REGEX_LEN} characters ({len(pattern)})"]
    try:
        re.compile(pattern)
    except re.error as exc:
        return [f"invalid regex: {exc}"]
    try:
        parsed = _sre().parse(pattern)
    except Exception as exc:  # noqa: BLE001 - an unparseable pattern is refused, never trusted
        return [f"regex could not be analysed ({type(exc).__name__})"]
    problems: list[str] = []
    _walk_regex(list(parsed), problems, in_repeat=False)
    state = getattr(parsed, "state", None)
    ignorecase = bool(getattr(state, "flags", 0) & re.IGNORECASE)
    try:
        _walk_sequences(list(parsed), problems, state, ignorecase)
    except Exception as exc:  # noqa: BLE001 - an unanalysable pattern is refused, never trusted
        problems.append(f"regex could not be analysed ({type(exc).__name__})")
    return sorted(set(problems))


#: Characters probed by the overlap test of adjacent repeats (ASCII plus a few non-ASCII samples).
_PROBE_CHARS: frozenset[int] = frozenset(range(128)) | frozenset({0xA0, 0xE9, 0xC9, 0x3B1, 0x416, 0x4E2D, 0x660, 0x2028})
_ADJACENT_PROBLEM = (
    "adjacent unbounded repeats over overlapping characters (e.g. '\\w*\\w*x', '.*.*=', 'a+a+b') backtrack "
    "polynomially: separate them with a character the first one cannot match or bound them ({0,64})"
)


def _category_chars(cat: Any) -> frozenset[int]:
    name = str(getattr(cat, "name", cat)).upper()
    negated = "NOT_" in name
    if "DIGIT" in name:
        hit = {c for c in _PROBE_CHARS if chr(c).isdecimal()}
    elif "SPACE" in name:
        hit = {c for c in _PROBE_CHARS if chr(c).isspace()}
    elif "WORD" in name:
        hit = {c for c in _PROBE_CHARS if chr(c).isalnum() or chr(c) == "_"}
    elif "LINEBREAK" in name:
        hit = {0x0A}
    else:  # unknown category: assume it matches everything (conservative)
        return _PROBE_CHARS
    return frozenset(_PROBE_CHARS - hit) if negated else frozenset(hit)


def _in_chars(items: list[Any]) -> frozenset[int]:
    c = _sre_const()
    negate = False
    chars: set[int] = set()
    for op, av in items:
        if op is c.NEGATE:
            negate = True
        elif op is c.LITERAL:
            chars.add(av)
        elif op is c.RANGE:
            lo, hi = av
            chars.update(x for x in _PROBE_CHARS if lo <= x <= hi)
        elif op is c.CATEGORY:
            chars.update(_category_chars(av))
        else:  # RANGE_UNI_IGNORE and friends: conservative
            return _PROBE_CHARS
    return frozenset(_PROBE_CHARS - chars) if negate else frozenset(chars)


def _fold(chars: frozenset[int]) -> frozenset[int]:
    out = set(chars)
    for x in chars:
        for variant in (chr(x).lower(), chr(x).upper()):
            if len(variant) == 1:
                out.add(ord(variant))
    return frozenset(out)


def _item_chars(op: Any, av: Any, ignorecase: bool) -> frozenset[int]:
    """The probe characters one parsed item can consume (zero-width items consume none)."""
    c = _sre_const()
    repeats = {c.MAX_REPEAT, c.MIN_REPEAT} | ({c.POSSESSIVE_REPEAT} if getattr(c, "POSSESSIVE_REPEAT", None) is not None else set())
    if op is c.LITERAL:
        out = frozenset({av})
    elif op is c.NOT_LITERAL:
        out = frozenset(_PROBE_CHARS - {av})
    elif op is c.ANY:
        out = _PROBE_CHARS
    elif op is c.IN:
        out = _in_chars(list(av))
    elif op in repeats:
        out = frozenset().union(*(_item_chars(o, a, ignorecase) for o, a in av[2])) if list(av[2]) else frozenset()
    elif op is c.SUBPATTERN:
        add_flags = av[1] if len(av) > 3 else 0
        inner_ic = ignorecase or bool((add_flags or 0) & re.IGNORECASE)
        out = frozenset().union(*(_item_chars(o, a, inner_ic) for o, a in av[-1])) if list(av[-1]) else frozenset()
    elif op is c.BRANCH:
        out = frozenset().union(*(_item_chars(o, a, ignorecase) for branch in av[1] for o, a in branch))
    elif getattr(c, "ATOMIC_GROUP", None) is not None and op is c.ATOMIC_GROUP:
        out = frozenset().union(*(_item_chars(o, a, ignorecase) for o, a in av)) if list(av) else frozenset()
    else:  # AT (anchors), ASSERT/ASSERT_NOT (lookarounds), GROUPREF...: zero width
        return frozenset()
    return _fold(out) if ignorecase else out


def _has_unbounded(op: Any, av: Any) -> bool:
    c = _sre_const()
    repeats = {c.MAX_REPEAT, c.MIN_REPEAT} | ({c.POSSESSIVE_REPEAT} if getattr(c, "POSSESSIVE_REPEAT", None) is not None else set())
    if op in repeats:
        return _is_unbounded(av[1]) or any(_has_unbounded(o, a) for o, a in av[2])
    if op is c.SUBPATTERN:
        return any(_has_unbounded(o, a) for o, a in av[-1])
    if op is c.BRANCH:
        return any(_has_unbounded(o, a) for branch in av[1] for o, a in branch)
    if getattr(c, "ATOMIC_GROUP", None) is not None and op is c.ATOMIC_GROUP:
        return any(_has_unbounded(o, a) for o, a in av)
    return False


def _can_be_empty(item: Any, state: Any) -> bool:
    try:
        return int(_sre().SubPattern(state, [item]).getwidth()[0]) == 0
    except Exception:  # noqa: BLE001 - unknown width: assume it may be empty (conservative)
        return True


def _adjacent_overlap(items: list[Any], state: Any, ignorecase: bool) -> bool:
    """Two unbounded repeats of one sequence whose characters overlap, with nothing mandatory
    between them that the first repeat cannot consume (``\\w*\\w*x``, ``.*a.*=``): polynomial
    backtracking that the 'nested quantifier' test does not see."""
    summary = [(_can_be_empty(item, state), _has_unbounded(*item), _item_chars(item[0], item[1], ignorecase)) for item in items]
    for i, (_empty, unbounded, chars) in enumerate(summary):
        if not unbounded or not chars:
            continue
        for empty_j, unbounded_j, chars_j in summary[i + 1:]:
            if unbounded_j and chars & chars_j:
                return True
            if not empty_j and not chars & chars_j:
                break  # a mandatory item the first repeat cannot consume ends its reach
    return False


def _walk_sequences(items: list[Any], problems: list[str], state: Any, ignorecase: bool) -> None:
    """Apply :func:`_adjacent_overlap` to every sequence of the pattern (top level and groups)."""
    c = _sre_const()
    repeats = {c.MAX_REPEAT, c.MIN_REPEAT} | ({c.POSSESSIVE_REPEAT} if getattr(c, "POSSESSIVE_REPEAT", None) is not None else set())
    if _adjacent_overlap(items, state, ignorecase):
        problems.append(_ADJACENT_PROBLEM)
    for op, av in items:
        if op in repeats:
            _walk_sequences(list(av[2]), problems, state, ignorecase)
        elif op is c.SUBPATTERN:
            add_flags = av[1] if len(av) > 3 else 0
            _walk_sequences(list(av[-1]), problems, state, ignorecase or bool((add_flags or 0) & re.IGNORECASE))
        elif op is c.BRANCH:
            for branch in av[1]:
                _walk_sequences(list(branch), problems, state, ignorecase)
        elif op in (c.ASSERT, c.ASSERT_NOT):
            _walk_sequences(list(av[1]), problems, state, ignorecase)
        elif getattr(c, "ATOMIC_GROUP", None) is not None and op is c.ATOMIC_GROUP:
            _walk_sequences(list(av), problems, state, ignorecase)


def _is_unbounded(hi: Any) -> bool:
    c = _sre_const()
    return hi is c.MAXREPEAT or (isinstance(hi, int) and hi > 64)


def _walk_regex(items: list[Any], problems: list[str], *, in_repeat: bool) -> None:
    c = _sre_const()
    repeats = {c.MAX_REPEAT, c.MIN_REPEAT}
    possessive = getattr(c, "POSSESSIVE_REPEAT", None)
    if possessive is not None:
        repeats.add(possessive)
    for op, av in items:
        if op in repeats:
            _lo, hi, sub = av
            unbounded = _is_unbounded(hi)
            body = list(sub)
            if unbounded and in_repeat:
                problems.append("nested quantifier (an unbounded repeat inside another repeat) can backtrack catastrophically")
            if unbounded and _has_overlapping_branch(body):
                problems.append("alternation inside a repeated group must start each branch with a distinct literal character")
            _walk_regex(body, problems, in_repeat=in_repeat or unbounded)
        elif op is c.SUBPATTERN:
            _walk_regex(list(av[-1]), problems, in_repeat=in_repeat)
        elif op is c.BRANCH:
            for branch in av[1]:
                _walk_regex(list(branch), problems, in_repeat=in_repeat)
        elif op in (c.ASSERT, c.ASSERT_NOT):
            _walk_regex(list(av[1]), problems, in_repeat=in_repeat)
        elif op in (c.GROUPREF, c.GROUPREF_EXISTS):
            problems.append("backreferences are not allowed")
        elif getattr(c, "ATOMIC_GROUP", None) is not None and op is c.ATOMIC_GROUP:
            _walk_regex(list(av), problems, in_repeat=in_repeat)


def _has_overlapping_branch(items: list[Any]) -> bool:
    """A BRANCH (top level of the repeated body or inside its groups) whose branches do not all
    start with distinct literal characters."""
    c = _sre_const()
    for op, av in items:
        if op is c.BRANCH:
            firsts: list[Any] = []
            for branch in av[1]:
                first = _first_literal(list(branch))
                if first is None or first in firsts:
                    return True
                firsts.append(first)
        elif op is c.SUBPATTERN and _has_overlapping_branch(list(av[-1])):
            return True
    return False


def _first_literal(items: list[Any]) -> Any:
    c = _sre_const()
    if not items:
        return None
    op, av = items[0]
    if op is c.LITERAL:
        return av
    if op is c.SUBPATTERN:
        return _first_literal(list(av[-1]))
    return None


# ----------------------------------------------------------------------------------------
# Compiled structures
# ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldRef:
    """A parsed field: ``kind`` in attr/tag/relation/type/value/entity/finding.source/finding.severity."""

    kind: str
    name: str = ""

    @property
    def text(self) -> str:
        return f"{self.kind}:{self.name}" if self.name else self.kind

    @property
    def finding_level(self) -> bool:
        return self.kind in _FINDING_FIELDS


@dataclass(frozen=True)
class Filter:
    """One compiled filter."""

    field: FieldRef
    op: str
    value: Any = None
    negate: bool = False
    regex: Any = None  # compiled pattern for op 'regex'


@dataclass(frozen=True)
class CollectionSpec:
    """One compiled collection."""

    name: str
    entity_types: frozenset[EntityType]
    node_filters: tuple[Filter, ...]
    finding_filters: tuple[Filter, ...]
    include_noise: bool = False


@dataclass(frozen=True)
class Suppression:
    """A named suppression rule: only downgrades (label, optionally severity), never deletes."""

    name: str
    when: tuple[Filter, ...]
    reason: str
    to: Confidence | None = None
    severity: Severity | None = None


@dataclass
class DataRule:
    """A compiled ``v3lum.rule/1`` document (the RuleInfo's ``fn`` evaluates it)."""

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    criterion: str
    recommendation: str
    description: str
    headline: str
    collections: tuple[CollectionSpec, ...]
    aggregation: FieldRef
    method: str
    minimum: int | None = None
    maximum: int | None = None
    percentile: float = DEFAULT_OUTLIER_PERCENT
    noisy_percent: float = DEFAULT_NOISY_PERCENT
    match: str = "exact"
    tags: tuple[str, ...] = ()
    suppress: tuple[Suppression, ...] = ()
    natural_person: bool = False
    origin: str = ""
    version: str = "1"
    code: str = ""
    references: tuple[str, ...] = ()
    attack: tuple[str, ...] = ()
    false_positives: str = ""
    fixtures: tuple[str, ...] = ()

    def __call__(self, graph: Any, results: Any, rctx: Any = None) -> list[Correlation]:
        return evaluate(self, graph, rctx)


# ----------------------------------------------------------------------------------------
# Validation and compilation
# ----------------------------------------------------------------------------------------


def _forbidden_reference(url: str) -> str:
    """Why a reference link is refused ('' = fine): references end up as links in reports, so they
    never point at people-search, submission or account-enumeration services (team rules, P327)."""
    try:
        from v3lum.core import lint
    except ImportError:  # pragma: no cover - defensive
        return ""
    try:
        rule_id = lint.forbidden_probe(url)
    except Exception:  # noqa: BLE001 - an unreadable URL is refused, never trusted
        return f"{url[:80]!r} could not be checked"
    return f"{url[:80]!r} points at a forbidden service ({rule_id})" if rule_id else ""


def _vocab_known(kind: str, name: str) -> bool:
    try:
        from v3lum.core import vocab
    except ImportError:  # pragma: no cover - defensive
        return True
    fn = {"attr": vocab.is_known_attribute, "tag": vocab.is_known_tag, "relation": vocab.is_known_relation}[kind]
    try:
        return bool(fn(name))
    except Exception:  # noqa: BLE001 - a broken vocabulary never accepts unknown names silently
        return False


def _parse_field(raw: Any, where: str, problems: list[str], *, aggregation: bool = False) -> FieldRef | None:
    if not isinstance(raw, str) or not raw.strip():
        problems.append(f"{where}: field must be a non-empty string")
        return None
    text = raw.strip()
    if text in _FIELD_SIMPLE:
        if text == "entity" and not aggregation:
            problems.append(f"{where}: field 'entity' is for aggregation only (filters use 'value' or 'type')")
            return None
        return FieldRef(text)
    prefix, sep, name = text.partition(":")
    if not sep or prefix not in _FIELD_PREFIXES:
        problems.append(
            f"{where}: unknown field {text!r} (attr:<name>, tag:<name>, relation:<name>, type, value, finding.source, finding.severity"
            + (", entity" if aggregation else "") + ")"
        )
        return None
    if not re.match(r"^[a-z][a-z0-9_]{0,63}$", name):
        problems.append(f"{where}: invalid {prefix} name {name!r}")
        return None
    vocab_kind = {"attr": "attr", "tag": "tag", "relation": "relation"}[prefix]
    if not _vocab_known(vocab_kind, name):
        label = {"attr": "attribute", "tag": "tag", "relation": "relation"}[prefix]
        problems.append(f"{where}: {label} {name!r} is not in the vocabulary (core table or a v3lum/data/vocab fragment)")
        return None
    return FieldRef(prefix, name)


def _scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) and not (isinstance(value, float) and value != value)


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value == value


def _parse_filter(raw: Any, where: str, problems: list[str]) -> Filter | None:
    if not isinstance(raw, Mapping):
        problems.append(f"{where}: a filter is an object {{field, op, value}}")
        return None
    unknown = sorted(set(raw) - {"field", "op", "value", "negate"})
    if unknown:
        problems.append(f"{where}: unknown filter keys {unknown}")
    ref = _parse_field(raw.get("field"), where, problems)
    op = raw.get("op")
    if op not in FILTER_OPS:
        problems.append(f"{where}: op must be one of {', '.join(FILTER_OPS)} (got {op!r})")
        return None
    negate = raw.get("negate", False)
    if not isinstance(negate, bool):
        problems.append(f"{where}: negate must be true or false")
        negate = False
    if ref is None:
        return None
    value = raw.get("value")
    compiled = None
    before = len(problems)
    if op == "exists":
        if value is not None and not isinstance(value, bool):
            problems.append(f"{where}: 'exists' takes no value or a boolean")
        if value is False:
            negate, value = not negate, True
    elif op == "eq":
        if not _scalar(value):
            problems.append(f"{where}: 'eq' needs a string, number or boolean value")
    elif op == "in":
        if not isinstance(value, list) or not value or len(value) > MAX_IN_VALUES or not all(_scalar(v) for v in value):
            problems.append(f"{where}: 'in' needs a non-empty list of at most {MAX_IN_VALUES} scalar values")
    elif op == "regex":
        issues = regex_problems(value)
        if issues:
            problems.extend(f"{where}: {issue}" for issue in issues)
        else:
            compiled = re.compile(value)
    elif op in ("gte", "lte"):
        if ref.kind == "finding.severity":
            try:
                value = int(Severity.parse(value))
            except (KeyError, ValueError, TypeError):
                problems.append(f"{where}: {op} on finding.severity needs a severity (info..critical)")
        elif not _number(value):
            problems.append(f"{where}: {op} needs a number")
    # field/op compatibility
    if ref.kind == "tag" and op != "exists":
        problems.append(f"{where}: tag fields take op 'exists' only")
    if ref.kind == "type":
        if op not in ("eq", "in"):
            problems.append(f"{where}: type takes op 'eq' or 'in'")
        else:
            for v in value if isinstance(value, list) else [value]:
                try:
                    EntityType.parse(str(v))
                except ValueError:
                    problems.append(f"{where}: unknown entity type {v!r}")
    if ref.kind == "finding.severity" and op in ("eq", "in"):
        for v in value if isinstance(value, list) else [value]:
            try:
                Severity.parse(v)
            except (KeyError, ValueError, TypeError):
                problems.append(f"{where}: unknown severity {v!r}")
    if ref.kind == "finding.source" and op in ("gte", "lte"):
        problems.append(f"{where}: finding.source takes eq, in, regex or exists")
    if ref.kind == "value" and op in ("gte", "lte"):
        problems.append(f"{where}: value takes eq, in, regex or exists")
    if len(problems) != before:
        return None
    if ref.kind == "type":
        value = [EntityType.parse(str(v)).value for v in (value if isinstance(value, list) else [value])]
    elif ref.kind == "finding.severity" and op in ("eq", "in"):
        value = [int(Severity.parse(v)) for v in (value if isinstance(value, list) else [value])]
    return Filter(ref, op, value, bool(negate), compiled)


def _parse_collections(raw: Any, problems: list[str]) -> tuple[CollectionSpec, ...]:
    if not isinstance(raw, list) or not raw:
        problems.append("collections must be a non-empty list")
        return ()
    if len(raw) > MAX_COLLECTIONS:
        problems.append(f"at most {MAX_COLLECTIONS} collections")
    out: list[CollectionSpec] = []
    names: set[str] = set()
    for i, item in enumerate(raw[:MAX_COLLECTIONS]):
        where = f"collections[{i}]"
        if not isinstance(item, Mapping):
            problems.append(f"{where}: must be an object {{name, entity_types, filters}}")
            continue
        unknown = sorted(set(item) - {"name", "entity_types", "filters", "include_noise"})
        if unknown:
            problems.append(f"{where}: unknown keys {unknown}")
        name = item.get("name")
        if not isinstance(name, str) or not _NAME_RE.match(name):
            problems.append(f"{where}: name must match ^[a-z][a-z0-9_]{{0,31}}$")
            name = f"c{i}"
        elif name in names:
            problems.append(f"{where}: duplicate collection name {name!r}")
        names.add(name)
        types_raw = item.get("entity_types")
        types: set[EntityType] = set()
        if not isinstance(types_raw, list) or not types_raw:
            problems.append(f"{where}: entity_types must be a non-empty list of entity types")
        else:
            for t in types_raw:
                try:
                    types.add(EntityType.parse(str(t)))
                except ValueError:
                    problems.append(f"{where}: unknown entity type {t!r}")
        filters_raw = item.get("filters", [])
        if not isinstance(filters_raw, list):
            problems.append(f"{where}: filters must be a list")
            filters_raw = []
        if len(filters_raw) > MAX_FILTERS:
            problems.append(f"{where}: at most {MAX_FILTERS} filters")
        node_filters: list[Filter] = []
        finding_filters: list[Filter] = []
        for j, f in enumerate(filters_raw[:MAX_FILTERS]):
            parsed = _parse_filter(f, f"{where}.filters[{j}]", problems)
            if parsed is None:
                continue
            (finding_filters if parsed.field.finding_level else node_filters).append(parsed)
        include_noise = item.get("include_noise", False)
        if not isinstance(include_noise, bool):
            problems.append(f"{where}: include_noise must be true or false")
            include_noise = False
        out.append(CollectionSpec(name, frozenset(types), tuple(node_filters), tuple(finding_filters), include_noise))
    return tuple(out)


def _parse_headline(raw: Any, problems: list[str]) -> str:
    if not isinstance(raw, str) or not raw.strip():
        problems.append("headline must be a non-empty string")
        return ""
    if len(raw) > 200:
        problems.append("headline longer than 200 characters")
    for name in _PLACEHOLDER_RE.findall(raw):
        if name not in HEADLINE_PLACEHOLDERS:
            problems.append(
                f"headline placeholder {{{name}}} is not allowed (whitelist: {', '.join('{' + p + '}' for p in sorted(HEADLINE_PLACEHOLDERS))})"
            )
    if "{" in _PLACEHOLDER_RE.sub("", raw) or "}" in _PLACEHOLDER_RE.sub("", raw):
        problems.append("headline has an unbalanced brace (literal braces are not allowed)")
    return raw.strip()


def _text(doc: Mapping[str, Any], key: str, problems: list[str], *, required: bool, limit: int) -> str:
    value = doc.get(key, "")
    if value is None:
        value = ""
    if not isinstance(value, str):
        problems.append(f"{key} must be a string")
        return ""
    value = value.strip()
    if required and not value:
        problems.append(f"{key} is required (non-empty)")
    if len(value) > limit:
        problems.append(f"{key} longer than {limit} characters")
    if _CTRL_RE.search(value.replace("\n", " ")):
        problems.append(f"{key} contains control characters")
    return value


def _parse_suppress(raw: Any, severity: Severity, problems: list[str]) -> tuple[Suppression, ...]:
    if raw in (None, []):
        return ()
    if not isinstance(raw, list):
        problems.append("suppress must be a list of {name, when, reason, to?, severity?}")
        return ()
    if len(raw) > MAX_SUPPRESS:
        problems.append(f"at most {MAX_SUPPRESS} suppression rules")
    out: list[Suppression] = []
    for i, item in enumerate(raw[:MAX_SUPPRESS]):
        where = f"suppress[{i}]"
        if not isinstance(item, Mapping):
            problems.append(f"{where}: must be an object")
            continue
        unknown = sorted(set(item) - {"name", "when", "reason", "to", "severity"})
        if unknown:
            problems.append(f"{where}: unknown keys {unknown} (suppression only downgrades: 'to' a lower label and/or a lower 'severity')")
        name = item.get("name")
        if not isinstance(name, str) or not re.match(r"^[a-z][a-z0-9_]{1,63}$", name):
            problems.append(f"{where}: name must match ^[a-z][a-z0-9_]{{1,63}}$")
            name = f"suppress_{i}"
        when_raw = item.get("when")
        if isinstance(when_raw, Mapping):
            when_raw = [when_raw]
        if not isinstance(when_raw, list) or not when_raw:
            problems.append(f"{where}: when must be a filter or a non-empty list of filters")
            when_raw = []
        when = [w for j, f in enumerate(when_raw[:MAX_FILTERS]) if (w := _parse_filter(f, f"{where}.when[{j}]", problems)) is not None]
        reason = item.get("reason")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 300:
            problems.append(f"{where}: reason is required (the visible label, <= 300 characters)")
            reason = ""
        to = None
        if item.get("to") is not None:
            try:
                to = Confidence.from_value(item["to"])
            except (ValueError, TypeError):
                problems.append(f"{where}: to must be possible, probable or confirmed")
        sev = None
        if item.get("severity") is not None:
            try:
                sev = Severity.parse(item["severity"])
            except (KeyError, ValueError, TypeError):
                problems.append(f"{where}: unknown severity {item.get('severity')!r}")
            else:
                if sev > severity:
                    problems.append(f"{where}: severity {sev.label} is above the rule's {severity.label} (suppression only downgrades)")
        out.append(Suppression(str(name), tuple(when), str(reason).strip(), to, sev))
    return tuple(out)


def _int_or_none(value: Any, key: str, problems: list[str]) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        problems.append(f"analysis.{key} must be a non-negative integer")
        return None
    return value


def validate_rule(doc: Any) -> list[str]:
    """Every problem of a ``v3lum.rule/1`` document ([] = valid)."""
    try:
        _compile(doc, origin="")
    except RuleSchemaError as exc:
        return list(exc.problems)
    return []


def _compile(doc: Any, *, origin: str) -> DataRule:  # noqa: C901 - one linear schema walk
    problems: list[str] = []
    if not isinstance(doc, Mapping):
        raise RuleSchemaError(["a data rule is an object"])
    rid = doc.get("id") if isinstance(doc.get("id"), str) else ""
    if doc.get("schema") != RULE_SCHEMA:
        problems.append(f"schema must be {RULE_SCHEMA!r}")
    if str(doc.get("kind") or DATA_KIND) != DATA_KIND:
        problems.append(f"kind must be {DATA_KIND!r}")
    for key in _TOP_REQUIRED:
        if key not in doc:
            problems.append(f"missing required key {key!r}")
    unknown = sorted(set(doc) - set(_TOP_REQUIRED) - set(_TOP_OPTIONAL))
    if unknown:
        problems.append(f"unknown keys {unknown}")
    if not isinstance(rid, str) or not RULE_ID_RE.match(rid):
        problems.append("id must match ^[a-z][a-z0-9_]{1,63}$")
    version = doc.get("version")
    if isinstance(version, int) and not isinstance(version, bool):
        version = str(version)
    if not isinstance(version, str) or not version.strip() or len(version) > 16:
        problems.append("version must be a non-empty string (<= 16 characters)")
        version = "1"
    code = doc.get("code", "") or ""
    if code and (not isinstance(code, str) or not _CODE_RE.match(code)):
        problems.append("code must look like 'CR40' (^[A-Z][A-Z0-9-]{1,15}$) or be empty")
        code = ""
    title = _text(doc, "title", problems, required=True, limit=120)
    criterion = _text(doc, "criterion", problems, required=True, limit=300)
    recommendation = _text(doc, "recommendation", problems, required=True, limit=500)
    description = _text(doc, "description", problems, required=False, limit=1000)
    false_positives = _text(doc, "false_positives", problems, required=False, limit=1000)
    try:
        severity = Severity.parse(doc.get("severity", ""))
    except (KeyError, ValueError, TypeError):
        problems.append("severity must be info, low, medium, high or critical")
        severity = Severity.INFO
    try:
        confidence = Confidence.from_value(doc["confidence"]) if doc.get("confidence") is not None else DEFAULT_CONFIDENCE
        if isinstance(doc.get("confidence"), (int, float)) and not isinstance(doc.get("confidence"), bool):
            problems.append("confidence must be a label: possible, probable or confirmed")
    except (ValueError, TypeError):
        problems.append("confidence must be possible, probable or confirmed")
        confidence = DEFAULT_CONFIDENCE
    references = doc.get("references", []) or []
    if not isinstance(references, list) or not all(isinstance(r, str) and r.startswith("https://") and len(r) <= 500 for r in references):
        problems.append("references must be a list of https:// URLs")
        references = []
    else:
        problems.extend(f"references: {issue}" for r in references if (issue := _forbidden_reference(r)))
    attack = doc.get("attack", []) or []
    if not isinstance(attack, list) or not all(isinstance(a, str) for a in attack):
        problems.append("attack must be a list of ATT&CK technique ids")
        attack = []
    else:
        problems.extend(f"attack: {p}" for p in attack_index.validate(attack))
    tags = doc.get("tags", []) or []
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        problems.append("tags must be a list of vocab tags")
        tags = []
    else:
        for t in tags:
            if t in RESERVED_TAGS:
                problems.append(f"tags: {t!r} is reserved for run_rules and analyst decisions (a rule never sets it)")
            elif not _vocab_known("tag", t):
                problems.append(f"tags: {t!r} is not in the vocabulary")
    fixtures = doc.get("fixtures", []) or []
    if not isinstance(fixtures, list) or not all(isinstance(f, str) for f in fixtures):
        problems.append("fixtures must be a list of paths")
        fixtures = []
    natural = doc.get("natural_person", False)
    if not isinstance(natural, bool):
        problems.append("natural_person must be true or false")
        natural = False
    collections = _parse_collections(doc.get("collections"), problems)
    agg_raw = doc.get("aggregation") or {"field": "entity"}
    aggregation = FieldRef("entity")
    if not isinstance(agg_raw, Mapping) or set(agg_raw) - {"field"}:
        problems.append("aggregation must be an object {field}")
    else:
        parsed = _parse_field(agg_raw.get("field", "entity"), "aggregation", problems, aggregation=True)
        if parsed is not None:
            aggregation = parsed
    analysis = doc.get("analysis")
    method, minimum, maximum = "threshold", None, None
    percentile, noisy, match = DEFAULT_OUTLIER_PERCENT, DEFAULT_NOISY_PERCENT, "exact"
    if not isinstance(analysis, Mapping):
        problems.append("analysis must be an object {method, minimum?, maximum?, percentile?}")
    else:
        unknown = sorted(set(analysis) - {"method", "minimum", "maximum", "percentile", "noisy_percent", "match"})
        if unknown:
            problems.append(f"analysis: unknown keys {unknown}")
        method = analysis.get("method")
        if method not in ANALYSIS_METHODS:
            problems.append(f"analysis.method must be one of {', '.join(ANALYSIS_METHODS)} (got {method!r})")
            method = "threshold"
        minimum = _int_or_none(analysis.get("minimum"), "minimum", problems)
        maximum = _int_or_none(analysis.get("maximum"), "maximum", problems)
        if minimum is not None and maximum is not None and maximum < minimum:
            problems.append("analysis.maximum is below analysis.minimum")
        for key in ("percentile", "noisy_percent"):
            raw = analysis.get(key)
            if raw is not None and (not _number(raw) or not 0 < float(raw) <= 100):
                problems.append(f"analysis.{key} must be a number in (0, 100]")
        if _number(analysis.get("percentile")):
            percentile = float(analysis["percentile"])
        if _number(analysis.get("noisy_percent")):
            noisy = float(analysis["noisy_percent"])
        match = analysis.get("match", "exact")
        if match not in MATCH_METHODS:
            problems.append(f"analysis.match must be one of {', '.join(MATCH_METHODS)}")
            match = "exact"
        elif match != "exact" and method != "match_all_to_first_collection":
            problems.append("analysis.match applies to match_all_to_first_collection only")
        if method in ("first_collection_only", "match_all_to_first_collection", "both_collections") and len(collections) < 2:
            problems.append(f"analysis.method {method} needs at least two collections")
        if method == "outlier" and maximum is not None:
            problems.append("analysis.maximum does not apply to outlier (use percentile)")
    headline = _parse_headline(doc.get("headline"), problems)
    suppress = _parse_suppress(doc.get("suppress"), severity, problems)
    person = bool(natural) or any(c.entity_types & NATURAL_PERSON_TYPES for c in collections)
    if problems:
        raise RuleSchemaError(problems, rule_id=rid if isinstance(rid, str) else "")
    rule = DataRule(
        id=rid, title=title, severity=severity, confidence=confidence, criterion=criterion, recommendation=recommendation,
        description=description, headline=headline, collections=collections, aggregation=aggregation, method=str(method),
        minimum=minimum, maximum=maximum, percentile=percentile, noisy_percent=noisy, match=str(match), tags=tuple(tags),
        suppress=suppress, natural_person=person, origin=origin, version=str(version).strip(), code=str(code),
        references=tuple(references), attack=tuple(attack), false_positives=false_positives, fixtures=tuple(fixtures),
    )
    return rule


def compile_rule(doc: Any, *, path: str | Path | None = None, origin: str = "") -> RuleInfo:
    """Compile one ``v3lum.rule/1`` document into a :class:`~v3lum.core.correlate.RuleInfo`
    (``kind='data'``, ``takes_context=True``), not registered. Raises :class:`RuleSchemaError`
    listing every schema problem."""
    where = origin or (str(path) if path is not None else "")
    rule = _compile(doc, origin=where)

    def data_rule(graph: Any, results: Any, rctx: Any = None) -> list[Correlation]:
        return evaluate(rule, graph, rctx)

    data_rule.__module__ = __name__
    data_rule.__qualname__ = data_rule.__name__ = f"data_rule_{rule.id}"
    data_rule.__doc__ = rule.description or rule.title
    data_rule.data_rule = rule  # type: ignore[attr-defined]
    info = RuleInfo(
        id=rule.id,
        title=rule.title,
        description=rule.description or rule.title,
        fn=data_rule,
        version=rule.version,
        code=rule.code,
        severity=rule.severity.label,
        criterion=rule.criterion,
        references=rule.references,
        attack=rule.attack,
        false_positives=rule.false_positives,
        fixtures=rule.fixtures,
        kind=DATA_KIND,
        legacy=False,
        takes_context=True,
        origin=where or f"data:{rule.id}",
        person=rule.natural_person,
    )
    return info


def compile_document(doc: Any, *, path: Path | None = None) -> RuleInfo:
    """The correlate compiler of kind ``'data'`` (``correlate.register_compiler``)."""
    return compile_rule(doc, path=path)


# ----------------------------------------------------------------------------------------
# Loading files
# ----------------------------------------------------------------------------------------


def read_rule_file(path: str | Path, *, allow_yaml: bool = False) -> Any:
    """Parse one rule file with a safe parser: JSON, TOML (tomllib) or - when ``allow_yaml`` and the
    optional extra 'yaml' (PyYAML) is installed - YAML through ``yaml.safe_load`` (no object tags).
    Raises ValueError on an unreadable, oversized or unparseable file."""
    p = Path(path)
    suffix = p.suffix.lower()
    if suffix not in BUNDLED_SUFFIXES + YAML_SUFFIXES:
        raise ValueError(f"{p.name}: rule files are .json or .toml (.yaml/.yml in the user directory with the 'yaml' extra)")
    try:
        size = p.stat().st_size
    except OSError as exc:
        raise ValueError(f"{p.name}: unreadable ({exc.strerror or exc})") from None
    if size > MAX_RULE_BYTES:
        raise ValueError(f"{p.name}: larger than {MAX_RULE_BYTES // 1024} KB")
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"{p.name}: unreadable ({type(exc).__name__})") from None
    if suffix == ".json":
        try:
            return json.loads(text)
        except (ValueError, RecursionError) as exc:
            raise ValueError(f"{p.name}: invalid JSON ({exc})") from None
    if suffix == ".toml":
        try:
            import tomllib
        except ImportError:  # pragma: no cover - Python 3.10
            raise ValueError(f"{p.name}: TOML rules need Python >= 3.11 (use JSON)") from None
        try:
            return tomllib.loads(text)
        except (ValueError, RecursionError) as exc:
            raise ValueError(f"{p.name}: invalid TOML ({exc})") from None
    if not allow_yaml:
        raise ValueError(f"{p.name}: bundled rules are JSON or TOML (YAML only in the user directory ~/.v3lum/rules)")
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        raise ValueError(f"{p.name}: YAML rules need the optional extra 'yaml' (pip install 'v3lum[yaml]'); use JSON or TOML") from None
    try:
        return yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001 - yaml.YAMLError and friends: never trusted
        raise ValueError(f"{p.name}: invalid YAML ({type(exc).__name__})") from None


def rule_files(directory: str | Path, *, allow_yaml: bool = False) -> list[Path]:
    """The rule files of ``directory`` in name order (README and dot files ignored)."""
    d = Path(directory)
    if not d.is_dir():
        return []
    suffixes = BUNDLED_SUFFIXES + (YAML_SUFFIXES if allow_yaml else ())
    return sorted(p for p in d.iterdir() if p.is_file() and p.suffix.lower() in suffixes and not p.name.startswith((".", "_")))


def load_data_rules(
    directory: str | Path | None = None,
    *,
    register: bool = True,
    allow_yaml: bool = False,
    origin_prefix: str = "",
    errors: dict[str, str] | None = None,
) -> list[RuleInfo]:
    """Compile every rule file of ``directory`` (default: ``v3lum/data/rules``).

    Each problem (unreadable file, schema error) is recorded in ``errors`` (default:
    ``correlate.RULE_ERRORS``, keyed by file name) and never raised; one broken file never stops the
    others. With ``register`` the compiled rules go through ``correlate.register_rule`` (duplicate ids
    are RULE_ERRORS entries, the first rule is kept). Returns the compiled RuleInfo objects.
    """
    target = correlate.RULE_ERRORS if errors is None else errors
    d = Path(directory) if directory is not None else Path(correlate.RULES_DATA_DIR)
    out: list[RuleInfo] = []
    for path in rule_files(d, allow_yaml=allow_yaml):
        key = f"{origin_prefix}{path.name}"
        try:
            doc = read_rule_file(path, allow_yaml=allow_yaml)
            info = compile_rule(doc, path=path, origin=f"{origin_prefix}{path}")
        except (ValueError, RuleSchemaError) as exc:
            _record(target, key, str(exc))
            continue
        if register:
            correlate.register_rule(info)
        out.append(info)
    return out


def _record(target: dict[str, str], key: str, message: str) -> None:
    if target is correlate.RULE_ERRORS:
        correlate._add_error(key, message)
    else:
        target[key] = message


# ----------------------------------------------------------------------------------------
# Evaluation (read-only over the graph)
# ----------------------------------------------------------------------------------------


def _evidence_ok(f: Finding) -> bool:
    """Same semantics as ``correlations.generic.evidence_finding``: context-only and SUP-* suppressed
    findings are never evidence; an analyst override keeps a finding unless it says false positive."""
    override = getattr(f, "override", None)
    if override:
        verdict = str(override.get("verdict") or "").strip().lower() if isinstance(override, dict) else ""
        return verdict not in _FALSE_POSITIVE_VERDICTS
    if "context_only" in f.tags:
        return False
    return not any(
        str(s.get("rule", "")).startswith("SUP-") and not s.get("blocked_by") for s in (f.suppressed_by or ()) if isinstance(s, dict)
    )


def _norm(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip().lower()


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _match_values(values: list[Any], flt: Filter) -> bool:
    """Does any of ``values`` satisfy ``flt`` (op eq/in/regex/gte/lte)? (exists handled by callers)"""
    op = flt.op
    if op == "eq":
        want = _norm(flt.value)
        return any(_norm(v) == want for v in values)
    if op == "in":
        wanted = {_norm(v) for v in flt.value}
        return any(_norm(v) in wanted for v in values)
    if op == "regex":
        return any(flt.regex.search(str(v)[:MAX_REGEX_INPUT]) is not None for v in values)
    if op in ("gte", "lte"):
        limit = float(flt.value)
        for v in values:
            num = _as_number(v)
            if num is not None and (num >= limit if op == "gte" else num <= limit):
                return True
        return False
    return False


class _View:
    """Read-only helpers over one graph for one rule run (adjacency built once)."""

    def __init__(self, graph: Any) -> None:
        self.graph = graph
        self._adj: dict[str, list[tuple[str, str]]] | None = None
        self._evidence: dict[str, list[Finding]] = {}
        #: relation neighbours that are noise (CDN, resolvers, webmail...) never link entities (AR06)
        #: unless the collection being evaluated sets include_noise
        self.include_noise = False

    def adjacency(self) -> dict[str, list[tuple[str, str]]]:
        if self._adj is None:
            adj: dict[str, list[tuple[str, str]]] = {}
            for e in self.graph.edges:
                adj.setdefault(e.src, []).append((e.relation, e.dst))
                adj.setdefault(e.dst, []).append((e.relation, e.src))
            self._adj = adj
        return self._adj

    def evidence(self, node: Any) -> list[Finding]:
        cached = self._evidence.get(node.key)
        if cached is None:
            cached = [f for f in node.findings if _evidence_ok(f)]
            self._evidence[node.key] = cached
        return cached

    def neighbours(self, node: Any, relation: str) -> list[str]:
        seen: list[str] = []
        for rel, other in self.adjacency().get(node.key, ()):
            target = self.graph.nodes.get(other)
            if rel != relation or other in seen or target is None:
                continue
            if target.noise and not self.include_noise:
                continue
            seen.append(other)
        return seen

    def node_values(self, node: Any, ref: FieldRef) -> list[Any]:
        """Values of a node-level field (attr values, neighbour values, type, value)."""
        if ref.kind == "attr":
            return [v for v in node.attr_values(ref.name) if v not in (None, "", [], {})]
        if ref.kind == "relation":
            return [self.graph.nodes[k].entity.value for k in self.neighbours(node, ref.name)]
        if ref.kind == "type":
            return [node.entity.type.value]
        if ref.kind == "value":
            return [node.entity.value]
        return []

    def node_filter(self, node: Any, flt: Filter) -> bool:
        ref = flt.field
        if ref.kind == "type":
            hit = node.entity.type.value in flt.value
        elif ref.kind == "tag":
            hit = ref.name in node.tags or any(ref.name in f.tags for f in self.evidence(node))
        elif flt.op == "exists":
            hit = bool(self.node_values(node, ref))
        elif ref.kind == "relation" and flt.op in ("gte", "lte"):
            count = len(self.neighbours(node, ref.name))
            hit = count >= float(flt.value) if flt.op == "gte" else count <= float(flt.value)
        else:
            hit = _match_values(self.node_values(node, ref), flt)
        return hit != flt.negate

    @staticmethod
    def finding_filter(f: Finding, flt: Filter) -> bool:
        ref = flt.field
        if ref.kind == "finding.source":
            values = [v for v in (f.source, f.module) if v]
            hit = bool(values) if flt.op == "exists" else _match_values(values, flt)
        else:  # finding.severity
            sev = int(f.severity)
            if flt.op == "exists":
                hit = True
            elif flt.op in ("eq", "in"):
                hit = sev in flt.value
            else:
                hit = sev >= int(flt.value) if flt.op == "gte" else sev <= int(flt.value)
        return hit != flt.negate

    def matching_findings(self, node: Any, filters: tuple[Filter, ...]) -> list[Finding]:
        return [f for f in self.evidence(node) if all(self.finding_filter(f, flt) for flt in filters)]

    def bucket_keys(self, node: Any, ref: FieldRef, findings: list[Finding]) -> list[tuple[str, str]]:
        """(bucket id, display value) pairs of a node for the aggregation field."""
        if ref.kind == "entity":
            return [(node.key, node.entity.value)]
        if ref.kind == "tag":
            return [(ref.name, ref.name)] if (ref.name in node.tags or any(ref.name in f.tags for f in self.evidence(node))) else []
        if ref.kind == "relation":
            return [(k, self.graph.nodes[k].entity.value) for k in self.neighbours(node, ref.name)]
        if ref.kind == "finding.source":
            pool = findings or self.evidence(node)
            vals = list(dict.fromkeys(f.source or f.module for f in pool if (f.source or f.module)))
            return [(_norm(v), str(v)) for v in vals]
        if ref.kind == "finding.severity":
            pool = findings or self.evidence(node)
            vals = list(dict.fromkeys(f.severity.label for f in pool))
            return [(v, v) for v in vals]
        out: list[tuple[str, str]] = []
        for v in self.node_values(node, ref):
            if isinstance(v, (dict, list, tuple, set)):
                continue
            key = _norm(v)
            if key and all(key != k for k, _ in out):
                out.append((key, str(v)))
        return out


@dataclass
class _Bucket:
    key: str
    display: str
    nodes: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    collections: set[int] = field(default_factory=set)

    def add(self, node_key: str, finding_ids: Iterable[str], index: int) -> None:
        if node_key not in self.nodes:
            self.nodes.append(node_key)
        for fid in finding_ids:
            if fid and fid not in self.findings:
                self.findings.append(fid)
        self.collections.add(index)


def _collect(rule: DataRule, view: _View) -> list[dict[str, _Bucket]]:
    """Buckets per collection: collection index -> {bucket id: _Bucket}."""
    per: list[dict[str, _Bucket]] = []
    nodes = list(view.graph.nodes.values())
    for index, coll in enumerate(rule.collections):
        buckets: dict[str, _Bucket] = {}
        view.include_noise = coll.include_noise
        for node in nodes:
            if node.entity.type not in coll.entity_types:
                continue
            if node.noise and not coll.include_noise:
                continue
            if not all(view.node_filter(node, flt) for flt in coll.node_filters):
                continue
            findings: list[Finding] = []
            if coll.finding_filters:
                findings = view.matching_findings(node, coll.finding_filters)
                if not findings:
                    continue
            # evidence: the findings the filters used, plus the evidence findings that carry a
            # filtered (or aggregated) tag - P301 cond 6: finding ids + facts used
            used = list(findings)
            tag_names = [f.field.name for f in coll.node_filters if f.field.kind == "tag" and not f.negate]
            if rule.aggregation.kind == "tag":
                tag_names.append(rule.aggregation.name)
            for name in tag_names:
                used += [f for f in view.evidence(node) if name in f.tags and all(f is not u for u in used)]
            for key, display in view.bucket_keys(node, rule.aggregation, findings):
                bucket = buckets.get(key)
                if bucket is None:
                    bucket = buckets[key] = _Bucket(key, display)
                bucket.add(node.key, (f.id for f in used), index)
        per.append(buckets)
    return per


def _merge(parts: Iterable[dict[str, _Bucket]]) -> dict[str, _Bucket]:
    merged: dict[str, _Bucket] = {}
    for buckets in parts:
        for key, b in buckets.items():
            target = merged.get(key)
            if target is None:
                target = merged[key] = _Bucket(key, b.display)
            target.collections.update(b.collections)
            for n in b.nodes:
                if n not in target.nodes:
                    target.nodes.append(n)
            for fid in b.findings:
                if fid not in target.findings:
                    target.findings.append(fid)
    return merged


def _in_range(count: int, rule: DataRule) -> bool:
    low = 1 if rule.minimum is None else rule.minimum
    high = rule.maximum
    return count >= low and (high is None or count <= high)


def _subnet_match(first: str, other: str) -> bool:
    try:
        net = ipaddress.ip_network(first, strict=False)
        addr = ipaddress.ip_address(other)
    except ValueError:
        try:
            inner = ipaddress.ip_network(other, strict=False)
            outer = ipaddress.ip_network(first, strict=False)
        except ValueError:
            return False
        return inner.version == outer.version and inner.subnet_of(outer)  # type: ignore[arg-type]
    return addr.version == net.version and addr in net


@dataclass
class _Result:
    bucket: _Bucket
    facts: list[str]
    why: str
    total: int = 0
    percent: float | None = None


def _analyse(rule: DataRule, per: list[dict[str, _Bucket]]) -> list[_Result]:  # noqa: C901 - one branch per method
    method = rule.method
    field_text = rule.aggregation.text
    out: list[_Result] = []
    if method == "threshold":
        merged = _merge(per)
        total = len({n for b in merged.values() for n in b.nodes})
        for b in merged.values():
            count = len(b.nodes)
            if _in_range(count, rule):
                bounds = f">= {1 if rule.minimum is None else rule.minimum}" + (f" and <= {rule.maximum}" if rule.maximum is not None else "")
                out.append(_Result(b, [f"{field_text}={b.display}", f"count={count}"],
                                   f"threshold: {field_text} {b.display!r} holds {count} entit{'y' if count == 1 else 'ies'} ({bounds})", total))
        return out
    if method == "outlier":
        merged = _merge(per)
        counts = {k: len(b.nodes) for k, b in merged.items()}
        total = sum(counts.values())
        minimum = DEFAULT_OUTLIER_MINIMUM if rule.minimum is None else rule.minimum
        if not counts or total < max(1, minimum):
            return []
        average_share = 100.0 / len(counts)
        if average_share < rule.noisy_percent:  # SpiderFoot 'noisy_percent': data too flat to call outliers
            return []
        for k, b in merged.items():
            pct = 100.0 * counts[k] / total
            if pct <= rule.percentile:
                out.append(_Result(b, [f"{field_text}={b.display}", f"count={counts[k]}", f"total={total}", f"share={pct:.1f}%"],
                                   f"outlier: {field_text} {b.display!r} holds {counts[k]} of {total} ({pct:.1f}% <= {rule.percentile:g}%)",
                                   total, pct))
        return out
    first, others = per[0], per[1:]
    if method == "first_collection_only":
        seen_elsewhere = {k for buckets in others for k in buckets}
        total = len(first)
        for k, b in first.items():
            if k not in seen_elsewhere and _in_range(len(b.nodes), rule):
                out.append(_Result(b, [f"{field_text}={b.display}", f"only_in={rule.collections[0].name}"],
                                   f"first_collection_only: {field_text} {b.display!r} appears only in {rule.collections[0].name!r}", total))
        return out
    if method == "both_collections":
        total = len(first)
        for k, b in first.items():
            if all(k in buckets for buckets in others):
                merged = _merge([{k: b}] + [{k: buckets[k]} for buckets in others])[k]
                if _in_range(len(merged.nodes), rule):
                    names = ", ".join(c.name for c in rule.collections)
                    out.append(_Result(merged, [f"{field_text}={b.display}", f"in={names}"],
                                       f"both_collections: {field_text} {b.display!r} appears in every collection ({names})", total))
        return out
    # match_all_to_first_collection
    total = len(first)
    for k, b in first.items():
        matched: list[_Bucket] = []
        for buckets in others:
            for ok, ob in buckets.items():
                if rule.match == "exact":
                    hit = ok == k
                elif rule.match == "contains":
                    hit = bool(k) and k in ok
                else:
                    hit = _subnet_match(b.display, ob.display)
                if hit:
                    matched.append(ob)
        if not matched:
            continue
        merged = _merge([{k: b}] + [{f"{i}": m} for i, m in enumerate(matched)])
        bucket = _Bucket(k, b.display)
        for part in merged.values():
            for n in part.nodes:
                if n not in bucket.nodes:
                    bucket.nodes.append(n)
            for fid in part.findings:
                if fid not in bucket.findings:
                    bucket.findings.append(fid)
        if _in_range(len(bucket.nodes), rule):
            shown = ", ".join(sorted({m.display for m in matched})[:5])
            out.append(_Result(bucket, [f"{field_text}={b.display}", f"matched={shown}", f"match={rule.match}"],
                               f"match_all_to_first_collection ({rule.match}): {len(matched)} value(s) match {b.display!r} of {rule.collections[0].name!r}",
                               total))
    return out


def _clean(value: Any, limit: int = 80) -> str:
    text = _CTRL_RE.sub(" ", str(value)).strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _headline(rule: DataRule, res: _Result, graph: Any) -> str:
    displays = [graph.nodes[k].entity.display for k in res.bucket.nodes if k in graph.nodes]
    values = {
        "value": _clean(res.bucket.display),
        "count": str(len(res.bucket.nodes)),
        "total": str(res.total),
        "percent": f"{res.percent:.1f}" if res.percent is not None else "",
        "field": rule.aggregation.text,
        "collection": rule.collections[0].name if rule.collections else "",
        "entities": _clean(", ".join(displays[:3]) + (f" (+{len(displays) - 3})" if len(displays) > 3 else ""), 160),
        "rule": rule.id,
        "severity": rule.severity.label,
    }
    text = _PLACEHOLDER_RE.sub(lambda m: values.get(m.group(1), ""), rule.headline)
    return _clean(text, 200)


def _suppression_applies(sup: Suppression, view: _View, node_keys: list[str]) -> bool:
    view.include_noise = True  # a suppression condition may name noise neighbours: it only downgrades
    node_filters = tuple(f for f in sup.when if not f.field.finding_level)
    finding_filters = tuple(f for f in sup.when if f.field.finding_level)
    for key in node_keys:
        node = view.graph.nodes.get(key)
        if node is None:
            continue
        if not all(view.node_filter(node, flt) for flt in node_filters):
            continue
        if finding_filters and not view.matching_findings(node, finding_filters):
            continue
        return True
    return False


def _purpose(rctx: Any) -> str:
    options = getattr(rctx, "options", None)
    return str(getattr(options, "purpose", "") or "").strip()


def evaluate(rule: DataRule, graph: Any, rctx: Any = None) -> list[Correlation]:
    """Run one compiled data rule over ``graph`` (read only) and return its correlations.

    Rules over natural persons return nothing unless the case has a recorded purpose (AR16, P258
    cond 11); their confidence cap is applied by ``correlate.run_rules``.
    """
    if rule.natural_person and not _purpose(rctx):
        return []
    view = _View(graph)
    per = _collect(rule, view)
    results = _analyse(rule, per)
    results.sort(key=lambda r: (-len(r.bucket.nodes), r.bucket.key))
    out: list[Correlation] = []
    for res in results[:MAX_CORRELATIONS]:
        node_keys = res.bucket.nodes
        entities = [graph.nodes[k].entity for k in node_keys if k in graph.nodes]
        if rule.aggregation.kind == "relation" and res.bucket.key in graph.nodes and res.bucket.key not in node_keys:
            entities.insert(0, graph.nodes[res.bucket.key].entity)  # the shared neighbour first
        evidence = list(res.bucket.findings[:MAX_EVIDENCE]) + res.facts
        corr = Correlation(
            rule=rule.id,
            title=_headline(rule, res, graph),
            severity=rule.severity,
            description=rule.description or rule.title,
            entities=entities[:MAX_ENTITIES],
            confidence=rule.confidence,
            evidence=evidence[: MAX_EVIDENCE + len(res.facts)],
            recommendation=rule.recommendation,
            tags=list(rule.tags),
            criterion=rule.criterion,
            why=_clean(res.why, 240),
            key=f"{rule.method}:{res.bucket.key}"[:200],
        )
        for sup in rule.suppress:
            if _suppression_applies(sup, view, node_keys):
                corr.downgrade(f"{rule.id}:{sup.name}", sup.reason, to=sup.to)
                if sup.severity is not None and sup.severity < corr.severity:
                    # visible label: the severity change is recorded next to the label change
                    corr.suppressed_by[-1].update({"from": corr.severity.label, "to": sup.severity.label})
                    corr.severity = sup.severity
        out.append(corr)
    return out


# Register the data-rule compiler with correlate (load_rules imports this module).
correlate.register_compiler(DATA_KIND, compile_document)


def ensure_registered() -> None:
    """(Re-)register the ``'data'`` compiler (a test may have cleared ``correlate._COMPILERS``)."""
    if correlate._COMPILERS.get(DATA_KIND) is not compile_document:
        correlate.register_compiler(DATA_KIND, compile_document)
