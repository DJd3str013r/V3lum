"""Result data model shared by modules, the engine, correlation and reports (module contract v2).

* :class:`Status` + the canonical A3 reason codes (:data:`REASON_CODES`) and partial-run stop
  reasons (:data:`STOP_REASONS`): rule 5 - 403/429/challenges/timeouts mean "could not verify".
* :class:`Confidence` labels (P322) with the single scoring/STIX mapping (:data:`CONFIDENCE_TABLE`).
* Deterministic ids (AR09): :func:`finding_id` and :func:`correlation_id`.
* :class:`Finding`, :class:`Pivot`, :class:`ModuleResult`, :class:`Correlation`: what modules and
  rules produce. Stored v1 case dicts keep loading through ``from_dict``.
* Strict contract mode (``V3LUM_STRICT=1``, on in tests): missing criteria, unknown vocabulary,
  non-http(s) links/references and 'absent' without evidence raise :class:`ContractViolation`.
  Outside strict mode nothing raises: gaps are repaired ('unspecified' criterion, unsafe URLs
  dropped) and logged once per (module, name) on logger ``v3lum.contract``.
"""

from __future__ import annotations

import contextlib
import contextvars
import datetime as _dt
import enum
import hashlib
import logging
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from v3lum.core import attack as _attack
from v3lum.core import tlp as _tlp
from v3lum.core import vocab as _vocab
from v3lum.core.entities import Entity, EntityType
from v3lum.core.vocab import ContractViolation, UnknownVocab

log = logging.getLogger("v3lum.contract")

__all__ = [
    "CONFIDENCE_TABLE",
    "DEFAULT_REASON",
    "OWNERSHIP_VALUES",
    "PRESENCE_STATES",
    "REASON_CODES",
    "STOP_REASONS",
    "Confidence",
    "ContractViolation",
    "Correlation",
    "Finding",
    "ModuleResult",
    "Opsec",
    "Pivot",
    "Severity",
    "Status",
    "UnknownVocab",
    "collect_results",
    "correlation_id",
    "finding_id",
    "status_for",
    "valid_reason",
]


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]


class Opsec(enum.IntEnum):
    """How much a module touches the target.

    PASSIVE: only third-party sources (APIs, caches, resolvers); the target never sees us.
    LIGHT:   benign, normal-visitor contact with the target (homepage, robots.txt, TLS handshake).
    ACTIVE:  intrusive probing (port scans, path discovery, AXFR, bucket brute force).
             Requires --authorized: only against assets you are allowed to test.
    """

    PASSIVE = 0
    LIGHT = 1
    ACTIVE = 2

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str | int | Opsec) -> Opsec:
        if isinstance(value, Opsec):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]


class Status(str, enum.Enum):
    """Outcome of one module run (the 8 v1 values are unchanged; QUOTA is new in v2)."""

    OK = "ok"  # ran and returned data
    EMPTY = "empty"  # ran fine, nothing found
    ERROR = "error"  # failed (network, parsing, bug, timeout, sanitizer)
    SKIPPED = "skipped"  # not run: not applicable / not default / a policy gate said no
    NEEDS_KEY = "needs_key"  # API key missing
    RATE_LIMITED = "rate_limited"  # transient throttling (HTTP 429): could not verify
    BLOCKED = "blocked"  # anti-bot wall, geo/datacenter block, login wall: could not verify (never "absent")
    UNAVAILABLE = "unavailable"  # provider down / dependency or dataset missing / offline mode
    QUOTA = "quota"  # budget, daily or monthly limit used up (distinct from transient rate_limited)

    @property
    def could_not_verify(self) -> bool:
        """True for outcomes that must read 'could not verify', never 'absent' (rule 5)."""
        return self in _COULD_NOT_VERIFY


_COULD_NOT_VERIFY = frozenset({Status.QUOTA, Status.RATE_LIMITED, Status.BLOCKED, Status.ERROR, Status.NEEDS_KEY, Status.UNAVAILABLE})

#: Canonical A3 reason codes -> the status they belong to (the only codes V3LUM uses).
REASON_CODES: dict[str, Status] = {
    # SKIPPED
    "not_default": Status.SKIPPED,
    "demoted": Status.SKIPPED,
    "licence": Status.SKIPPED,
    "tlp": Status.SKIPPED,
    "tier": Status.SKIPPED,
    "privacy": Status.SKIPPED,
    "own_asset": Status.SKIPPED,
    "opsec": Status.SKIPPED,
    "authorization": Status.SKIPPED,
    "scope": Status.SKIPPED,
    "egress_country": Status.SKIPPED,
    "deadline": Status.SKIPPED,
    "policy": Status.SKIPPED,
    "config": Status.SKIPPED,
    "not_applicable": Status.SKIPPED,
    # NEEDS_KEY
    "needs_key": Status.NEEDS_KEY,
    # UNAVAILABLE
    "package": Status.UNAVAILABLE,
    "dataset": Status.UNAVAILABLE,
    "offline": Status.UNAVAILABLE,
    # QUOTA
    "quota": Status.QUOTA,
    # RATE_LIMITED
    "rate_limited": Status.RATE_LIMITED,
    # BLOCKED
    "hostile_host": Status.BLOCKED,
    "circuit": Status.BLOCKED,
    "challenge": Status.BLOCKED,
    "geo_block": Status.BLOCKED,
    "login_wall": Status.BLOCKED,
    # ERROR
    "timeout": Status.ERROR,
    "sanitizer": Status.ERROR,
    "error": Status.ERROR,
}

#: Why a partial run (status ok/empty, partial=True) stopped early.
STOP_REASONS: frozenset[str] = frozenset({"request_cap", "deadline", "quota", "rate_limited", "cancelled"})

#: Reason code used when a non-ok/empty status is set without one.
DEFAULT_REASON: dict[Status, str] = {
    Status.SKIPPED: "not_applicable",
    Status.NEEDS_KEY: "needs_key",
    Status.UNAVAILABLE: "offline",
    Status.QUOTA: "quota",
    Status.RATE_LIMITED: "rate_limited",
    Status.BLOCKED: "challenge",
    Status.ERROR: "error",
}

#: Tri-state existence (P328 cond 4).
PRESENCE_STATES: tuple[str, ...] = ("found", "absent", "unknown")
#: Finding.ownership values ('' = not evaluated).
OWNERSHIP_VALUES: tuple[str, ...] = ("", "own_asset", "third_party")


def status_for(code: str) -> Status:
    """The status a canonical reason code belongs to. ValueError for unknown codes."""
    try:
        return REASON_CODES[code]
    except (KeyError, TypeError):
        raise ValueError(f"unknown reason code {code!r} (A3 canonical codes: {', '.join(REASON_CODES)})") from None


def valid_reason(status: Status | str, code: str) -> bool:
    """Is ``code`` a valid reason code for ``status``? ok/empty take no code; others need their own."""
    try:
        st = Status(status)
    except ValueError:
        return False
    if st in (Status.OK, Status.EMPTY):
        return not code
    return REASON_CODES.get(code) is st


# ----------------------------------------------------------------------------------------
# Confidence (P322)
# ----------------------------------------------------------------------------------------


class Confidence(str, enum.Enum):
    """Qualitative confidence label of a finding, pivot edge or correlation.

    Floats map as ``>= 0.85`` confirmed, ``>= 0.55`` probable, else possible. Note that
    :meth:`lower` / :meth:`higher` move one level down/up (they are not ``str.lower``).
    """

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"

    def __str__(self) -> str:
        return self.value

    def __format__(self, spec: str) -> str:
        return format(self.value, spec)

    @property
    def weight(self) -> float:
        """Scoring weight (P302): 1.0 / 0.7 / 0.4."""
        return float(CONFIDENCE_TABLE[self]["weight"])

    @property
    def stix(self) -> int:
        """STIX 2.1 confidence (P303): 90 / 70 / 40."""
        return int(CONFIDENCE_TABLE[self]["stix"])

    @property
    def rank(self) -> int:
        """Order: confirmed 2 > probable 1 > possible 0."""
        return int(CONFIDENCE_TABLE[self]["rank"])

    @property
    def threshold(self) -> float:
        """Lowest float that maps to this label (0.85 / 0.55 / 0.0)."""
        return float(CONFIDENCE_TABLE[self]["min_value"])

    def lower(self) -> Confidence:  # type: ignore[override]
        """One level down (floor: possible)."""
        return _BY_RANK[max(0, self.rank - 1)]

    def higher(self) -> Confidence:
        """One level up (ceiling: confirmed)."""
        return _BY_RANK[min(2, self.rank + 1)]

    @classmethod
    def from_value(cls, value: float | int | str | Confidence) -> Confidence:
        """Label for a float (0-1) or a label string (by value or name, any case)."""
        if isinstance(value, Confidence):
            return value
        if isinstance(value, bool):
            raise ValueError(f"invalid confidence: {value!r}")
        if isinstance(value, (int, float)):
            num = float(value)
            if num != num:  # NaN
                raise ValueError("invalid confidence: NaN")
            if num >= CONFIDENCE_TABLE[cls.CONFIRMED]["min_value"]:
                return cls.CONFIRMED
            if num >= CONFIDENCE_TABLE[cls.PROBABLE]["min_value"]:
                return cls.PROBABLE
            return cls.POSSIBLE
        if isinstance(value, str):
            text = value.strip().lower()
            for member in cls:
                if text in (member.value, member.name.lower()):
                    return member
            try:
                return cls.from_value(float(text))
            except ValueError:
                pass
        raise ValueError(f"invalid confidence {value!r} (use a float 0-1 or confirmed/probable/possible)")


#: The one documented label table (P322 cond 1): used by scoring (P302) and STIX export (P303).
CONFIDENCE_TABLE: dict[Confidence, dict[str, Any]] = {
    Confidence.CONFIRMED: {
        "label": "confirmed", "weight": 1.0, "stix": 90, "rank": 2, "min_value": 0.85,
        "meaning": "direct, documented evidence from a reliable source (or analyst confirmation)",
    },
    Confidence.PROBABLE: {
        "label": "probable", "weight": 0.7, "stix": 70, "rank": 1, "min_value": 0.55,
        "meaning": "consistent indirect evidence; a plausible alternative explanation remains",
    },
    Confidence.POSSIBLE: {
        "label": "possible", "weight": 0.4, "stix": 40, "rank": 0, "min_value": 0.0,
        "meaning": "weak or single-signal evidence, suppressed by a named rule, or version-inferred",
    },
}
_BY_RANK = {0: Confidence.POSSIBLE, 1: Confidence.PROBABLE, 2: Confidence.CONFIRMED}


# ----------------------------------------------------------------------------------------
# Deterministic ids (AR09)
# ----------------------------------------------------------------------------------------


def finding_id(module: str, entity_key: str, title: str, key: str = "") -> str:
    """sha256('module|entity_key|title|key')[:16]: the same finding gets the same id on every run."""
    return hashlib.sha256("|".join([module, entity_key, title, key]).encode("utf-8")).hexdigest()[:16]


def correlation_id(rule: str, entity_keys: Iterable[str], key: str = "") -> str:
    """sha256('rule|<rule>|<sorted entity keys>|<key>')[:16]."""
    joined = ",".join(sorted(entity_keys))
    return hashlib.sha256(("rule|" + rule + "|" + joined + "|" + key).encode("utf-8")).hexdigest()[:16]


def _new_id() -> str:  # pragma: no cover - kept for plugins that imported it (v1)
    return uuid.uuid4().hex[:12]


# ----------------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------------


def _strict() -> bool:
    return _vocab.strict_enabled()


def _violation(module: str, name: str, message: str) -> None:
    """Strict mode: raise. Otherwise: log once per (module, name). Messages pass the redactor (AR01)."""
    text = _redact(f"{module or '?'}: {message}")
    if _strict():
        raise ContractViolation(text)
    _vocab.warn_once(module, name, text)


def _redact(text: str) -> str:
    """Mask configured key values and key-like URL parameters (messages quote module-supplied URLs)."""
    try:
        from v3lum.core import redact
    except ImportError:  # pragma: no cover - redactor not installed
        return text
    try:
        return str(redact.redact_text(text))
    except Exception:  # pragma: no cover - the redactor must never break a module
        return text


def _http_url(url: Any) -> str | None:
    """The URL stripped of surrounding blanks when it is a plain http(s) URL with a host, else None."""
    if not isinstance(url, str):
        return None
    text = url.strip()
    if not text or any(ch.isspace() or ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in text):
        return None
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host:
        return None
    return text


def _iso(value: Any) -> str | None:
    """Timestamps as ISO-8601 text (datetime/date objects and epoch seconds converted)."""
    if value is None or value == "":
        return None
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    if isinstance(value, _dt.date):
        return value.isoformat()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = float(value)
        if seconds > 1e11:  # epoch milliseconds (common in provider APIs)
            seconds /= 1000.0
        try:
            return _dt.datetime.fromtimestamp(seconds, _dt.timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    return str(value).strip() or None


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _clamp(value: Any) -> float:
    try:
        num = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"invalid confidence: {value!r}") from None
    if num != num:
        raise ValueError("invalid confidence: NaN")
    return max(0.0, min(1.0, num))


def _confidence_float(value: Any) -> float:
    """Float confidence for a float or a label (labels are stored as their weight)."""
    if isinstance(value, (str, Confidence)):
        return Confidence.from_value(value).weight
    return _clamp(value)


def _entity_from_key(key: Any) -> Entity | None:
    if isinstance(key, Entity):
        return key
    if not isinstance(key, str) or ":" not in key:
        return None
    etype, value = key.split(":", 1)
    try:
        return Entity(EntityType(etype), value)
    except ValueError:
        try:
            return Entity(EntityType.parse(etype), value)
        except ValueError:
            return None


def _declared_sources(module_name: str) -> tuple[str, ...] | None:
    """Registry sources of a registered module (None when the module is unknown)."""
    if not module_name:
        return None
    try:
        from v3lum.core.module import REGISTRY  # lazy: module.py imports this file
    except ImportError:  # pragma: no cover - defensive
        return None
    cls = REGISTRY.get(module_name)
    if cls is None:
        return None
    return tuple(getattr(cls, "sources", ()) or ())


def _label_text(label: Confidence) -> str:
    return label.name  # 'POSSIBLE'


def _chain_criterion(new: str, previous: str) -> str:
    return f"{new} | {previous}" if previous else new


# ----------------------------------------------------------------------------------------
# Finding
# ----------------------------------------------------------------------------------------


@dataclass
class Finding:
    """A fact or judgement about an entity, produced by a module (or a correlation rule).

    v1 fields keep their order; v2 adds the confidence label + criterion (P322), the registry
    source and provider timestamps (AR09), ATT&CK ids, the id key, suppression records,
    ownership and the analyst override.
    """

    title: str
    severity: Severity = Severity.INFO
    description: str = ""
    confidence: float = 0.8
    data: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    entity: Entity | None = None
    module: str = ""
    id: str = ""
    confidence_label: Confidence | None = None
    criterion: str = ""
    source: str = ""
    observed_first: str | None = None
    observed_last: str | None = None
    attack: list[str] = field(default_factory=list)
    key: str = ""
    suppressed_by: list[dict[str, Any]] = field(default_factory=list)
    ownership: str = ""
    override: dict[str, Any] | None = None
    #: automatic upgrades ({rule, reason, from, to}); at most one, kept through to_dict/from_dict (P322 cond 5)
    upgraded_by: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)
        if isinstance(self.confidence, (str, Confidence)):
            label = Confidence.from_value(self.confidence)
            self.confidence = label.weight
            if self.confidence_label is None:
                self.confidence_label = label
        else:
            self.confidence = _clamp(self.confidence)
        if self.confidence_label is None:
            self.confidence_label = Confidence.from_value(self.confidence)
        else:
            self.confidence_label = Confidence.from_value(self.confidence_label)
        if self.ownership not in OWNERSHIP_VALUES:
            raise ValueError(f"ownership must be one of {OWNERSHIP_VALUES} (got {self.ownership!r})")
        self._derived_id = ""

    # ---- identity ---------------------------------------------------------------------
    @property
    def label(self) -> Confidence:
        """Effective confidence label (never None)."""
        return self.confidence_label or Confidence.from_value(self.confidence)

    def ensure_id(self) -> str:
        """Fill ``id`` with :func:`finding_id` (recomputed while it is derived; explicit ids are kept)."""
        if self.id and self.id != self._derived_id:
            return self.id
        new = finding_id(self.module, self.entity.key if self.entity is not None else "", self.title, self.key)
        self.id = new
        self._derived_id = new
        return new

    # ---- automatic confidence changes (P322 cond 4-5) --------------------------------
    def downgrade(self, rule: str, reason: str, *, to: Confidence | str | None = None) -> Finding:
        """Lower the label one level (or straight to ``to``) through a named suppression rule.

        The criterion becomes '<LABEL> - <reason>' (e.g. 'POSSIBLE - on warninglist <name>') with
        the previous criterion kept after ' | '. Never crosses an analyst override: an overridden
        finding only records {'rule', 'reason', 'blocked_by': 'analyst'} in ``suppressed_by``.
        """
        if self.override:
            self.suppressed_by.append({"rule": rule, "reason": reason, "blocked_by": "analyst"})
            return self
        current = self.label
        new = current.lower()
        if to is not None:
            target = Confidence.from_value(to)
            new = target if target.rank < current.rank else current
        if new.rank < current.rank:
            self.confidence = min(float(self.confidence), new.weight)
        self.confidence_label = new
        self.criterion = _chain_criterion(f"{_label_text(new)} - {reason}", self.criterion)
        self.suppressed_by.append({"rule": rule, "reason": reason})
        return self

    def upgrade(self, independent_families: int | Iterable[str], rule: str, reason: str) -> Finding:
        """Raise the label one level, only with >= 2 independent upstream families, at most once.

        The upgrade is recorded in ``upgraded_by`` (kept by to_dict/from_dict, so a stored and
        reloaded finding is never raised a second time). Never crosses an analyst override
        (records the blocked attempt in ``suppressed_by``).
        """
        if self.override:
            self.suppressed_by.append({"rule": rule, "reason": reason, "blocked_by": "analyst"})
            return self
        if isinstance(independent_families, int) and not isinstance(independent_families, bool):
            families = independent_families
        else:
            families = len({str(x) for x in independent_families or ()})
        if families < 2 or self.upgraded_by:
            return self
        current = self.label
        new = current.higher()
        if new is current:
            return self
        self.confidence_label = new
        self.confidence = max(float(self.confidence), new.threshold)
        self.criterion = _chain_criterion(f"{_label_text(new)} - {reason}", self.criterion)
        self.upgraded_by.append({"rule": rule, "reason": reason, "from": current.value, "to": new.value})
        return self

    # ---- analyst override (P322 cond 3) -------------------------------------------------
    def apply_override(
        self,
        *,
        label: Confidence | str | None = None,
        severity: Severity | str | int | None = None,
        verdict: str | None = None,
        analyst: str = "",
        note: str = "",
        at: str = "",
    ) -> Finding:
        """Apply an analyst decision. It always wins; the automatic values stay under override['auto']."""
        previous = self.override or {}
        auto = previous.get("auto") if isinstance(previous.get("auto"), dict) else None
        if auto is None:
            auto = {"label": self.label.value, "severity": self.severity.label, "criterion": self.criterion}
        new_label = Confidence.from_value(label) if label is not None else None
        new_sev = Severity.parse(severity) if severity is not None else None
        if new_label is not None:
            self.confidence_label = new_label
            self.confidence = new_label.weight
        if new_sev is not None:
            self.severity = new_sev
        self.override = {
            "analyst": analyst or previous.get("analyst", ""),
            "label": new_label.value if new_label is not None else previous.get("label"),
            "severity": new_sev.label if new_sev is not None else previous.get("severity"),
            "verdict": verdict if verdict is not None else previous.get("verdict"),
            "note": note or previous.get("note", ""),
            "at": at or previous.get("at") or _now_iso(),
            "auto": dict(auto),
        }
        return self

    # ---- serialisation ----------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        if not self.id:
            self.ensure_id()
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.label,
            "description": self.description,
            "confidence": round(float(self.confidence), 3),
            "data": self.data,
            "tags": list(self.tags),
            "references": list(self.references),
            "entity": self.entity.key if self.entity else None,
            "module": self.module,
            "confidence_label": self.label.value,
            "criterion": self.criterion,
            "source": self.source,
            "observed_first": self.observed_first,
            "observed_last": self.observed_last,
            "attack": list(self.attack),
            "key": self.key,
            "suppressed_by": [dict(s) for s in self.suppressed_by],
            "ownership": self.ownership,
            "override": _copy_override(self.override),
            "upgraded_by": [dict(u) for u in self.upgraded_by],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any], *, entity: Entity | None = None) -> Finding:
        """Rebuild a finding from ``to_dict`` output, including stored v1 dicts (12-char ids kept)."""
        if not isinstance(d, dict):
            raise ValueError("finding must be a dict")
        ent = entity if entity is not None else _entity_from_key(d.get("entity"))
        try:
            severity = Severity.parse(d.get("severity", "info") or "info")
        except (KeyError, ValueError):
            severity = Severity.INFO
        confidence = d.get("confidence", 0.8)
        if confidence is None:
            confidence = 0.8
        label = d.get("confidence_label") or None
        ownership = d.get("ownership") or ""
        f = cls(
            title=str(d.get("title", "")),
            severity=severity,
            description=str(d.get("description") or ""),
            confidence=confidence,
            data=dict(d.get("data") or {}) if isinstance(d.get("data"), dict) else {},
            tags=[str(t) for t in d.get("tags") or ()],
            references=[str(r) for r in d.get("references") or ()],
            entity=ent,
            module=str(d.get("module") or ""),
            id=str(d.get("id") or ""),
            confidence_label=label,
            criterion=str(d.get("criterion") or ""),
            source=str(d.get("source") or ""),
            observed_first=d.get("observed_first") or None,
            observed_last=d.get("observed_last") or None,
            attack=[str(a) for a in d.get("attack") or ()],
            key=str(d.get("key") or ""),
            suppressed_by=[dict(s) for s in d.get("suppressed_by") or () if isinstance(s, dict)],
            ownership=ownership if ownership in OWNERSHIP_VALUES else "",
            override=_copy_override(d.get("override")) if isinstance(d.get("override"), dict) else None,
            upgraded_by=[dict(u) for u in d.get("upgraded_by") or () if isinstance(u, dict)],
        )
        if not f.id:
            f.ensure_id()
        return f


def _copy_override(override: Any) -> dict[str, Any] | None:
    if not isinstance(override, dict):
        return None
    out = dict(override)
    if isinstance(out.get("auto"), dict):
        out["auto"] = dict(out["auto"])
    return out


# ----------------------------------------------------------------------------------------
# Pivot
# ----------------------------------------------------------------------------------------


@dataclass
class Pivot:
    """A new entity discovered from the subject entity. ``confidence`` accepts a float or a label."""

    entity: Entity
    relation: str
    confidence: float = 0.9
    expand: bool = True  # may the engine investigate it further?
    note: str = ""

    def __post_init__(self) -> None:
        self.confidence = _confidence_float(self.confidence)

    @property
    def confidence_label(self) -> Confidence:
        return Confidence.from_value(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity.key,
            "relation": self.relation,
            "confidence": self.confidence,
            "expand": self.expand,
            "note": self.note,
            "confidence_label": self.confidence_label.value,
        }


# ----------------------------------------------------------------------------------------
# ModuleResult
# ----------------------------------------------------------------------------------------

_COLLECTOR: contextvars.ContextVar[list[ModuleResult] | None] = contextvars.ContextVar("v3lum_collect_results", default=None)


@contextlib.contextmanager
def collect_results() -> Iterator[list[ModuleResult]]:
    """Collect every :class:`ModuleResult` created inside the block (this thread/context only).

    The engine runs each module inside it to recover the result a module was building when
    ctx.http raised RequestCapReached / Cancelled / QuotaExceeded / RateLimited mid-run.
    """
    bucket: list[ModuleResult] = []
    token = _COLLECTOR.set(bucket)
    try:
        yield bucket
    finally:
        _COLLECTOR.reset(token)


@dataclass
class ModuleResult:
    """Everything a single module run produced for one entity."""

    module: str
    entity: Entity
    status: Status = Status.OK
    findings: list[Finding] = field(default_factory=list)
    pivots: list[Pivot] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    links: list[tuple[str, str]] = field(default_factory=list)
    raw: Any = None
    error: str = ""
    duration: float = 0.0
    requests: int = 0
    cache_hits: int = 0
    evidence: str = ""  # path of saved evidence
    evidence_sha256: str = ""
    reason_code: str = ""  # canonical A3 code ('' for ok/empty)
    partial: bool = False  # stopped early, kept what it had (see stop_reason)
    stop_reason: str = ""  # one of STOP_REASONS when partial
    tlp: str = ""  # platform marking carried by the result (set_marking), '' = none
    hosts: dict[str, int] = field(default_factory=dict)  # filled by the engine: host -> requests (DoH included)
    datasets: list[dict[str, Any]] = field(default_factory=list)  # filled by the engine: dataset citations
    redacted_fields: list[str] = field(default_factory=list)  # filled by the sanitizer
    source_statuses: dict[str, dict[str, str]] = field(default_factory=dict)  # aggregators: per-feed outcome

    def __post_init__(self) -> None:
        self.status = Status(self.status)
        bucket = _COLLECTOR.get()
        if bucket is not None:
            bucket.append(self)

    # ---- builder helpers used by modules -------------------------------------------------

    def finding(
        self,
        title: str,
        severity: Severity | str = Severity.INFO,
        description: str = "",
        *,
        confidence: float | str | Confidence = 0.8,
        criterion: str = "",
        data: dict[str, Any] | None = None,
        tags: Iterable[str] = (),
        references: Iterable[str] = (),
        source: str = "",
        observed_first: Any = None,
        observed_last: Any = None,
        attack: Iterable[str] = (),
        key: str = "",
    ) -> Finding:
        """Add a finding. ``criterion`` (why it is believed) is mandatory for severity >= low."""
        sev = Severity.parse(severity)
        crit = (criterion or "").strip()
        if sev >= Severity.LOW and not crit:
            _violation(self.module, "criterion", f"finding {title!r} (severity {sev.label}) needs criterion= explaining why it is believed (P322)")
            crit = "unspecified"
        refs: list[str] = []
        for ref in references or ():
            safe = _http_url(ref)
            if safe is None:
                _violation(self.module, f"reference:{ref}", f"reference {ref!r} is not an http(s) URL (dropped)")
                continue
            if safe not in refs:
                refs.append(safe)
        tag_list: list[str] = []
        for tag in tags or ():
            _vocab.check("tag", tag, module=self.module)
            if tag not in tag_list:
                tag_list.append(tag)
        f = Finding(
            title=title,
            severity=sev,
            description=description,
            confidence=confidence,
            data=dict(data or {}),
            tags=tag_list,
            references=refs,
            entity=self.entity,
            module=self.module,
            criterion=crit,
            source=source or "",
            observed_first=_iso(observed_first),
            observed_last=_iso(observed_last),
            attack=self._attack_ids(attack),
            key=key or "",
        )
        f.ensure_id()
        if any(other.id == f.id for other in self.findings):
            _violation(self.module, f"duplicate:{title}", f"two findings share the id of {title!r}: pass key= to separate same-title findings")
            n = sum(1 for other in self.findings if other.title == title) + 1
            f.key = f"{f.key}#{n}"
            f.ensure_id()
        self.findings.append(f)
        return f

    def _attack_ids(self, ids: Iterable[str]) -> list[str]:
        out: list[str] = []
        if isinstance(ids, str):
            ids = [ids]
        for raw in ids or ():
            problems = _attack.validate([raw])
            if problems:
                _violation(self.module, f"attack:{raw}", "; ".join(problems))
            tid = _attack.canonical(raw)
            if tid not in out:
                out.append(tid)
        return out

    def pivot(
        self,
        etype: EntityType | str,
        value: str,
        relation: str,
        *,
        confidence: float | str | Confidence = 0.9,
        expand: bool = True,
        note: str = "",
    ) -> Entity | None:
        """Add a discovered entity. Invalid values are ignored (returns None)."""
        _vocab.check("relation", relation, module=self.module)
        ent = Entity.try_make(etype, value)
        if ent is None or ent == self.entity:
            return None
        if any(p.entity == ent and p.relation == relation for p in self.pivots):
            return ent
        self.pivots.append(Pivot(ent, relation, _confidence_float(confidence), expand, note))
        return ent

    def attr(self, key: str, value: Any) -> None:
        """Record a fact about the subject entity (names from the merged vocabulary only)."""
        _vocab.check("attribute", key, module=self.module)
        if value is None or value == "" or value == [] or value == {}:
            return
        self.attributes[key] = value

    def link(self, label: str, url: str) -> None:
        """Add a manual follow-up link. Only plain http(s) URLs are kept (AR13)."""
        if not url:
            return
        safe = _http_url(url)
        if safe is None:
            _violation(self.module, f"link:{url}", f"link {url!r} is not an http(s) URL (dropped)")
            return
        if (label, safe) not in self.links:
            self.links.append((label, safe))

    def mark(self, status: Status | str, error: str = "", *, reason_code: str = "") -> ModuleResult:
        """Set the outcome. A non-ok/empty status without a code gets DEFAULT_REASON; invalid codes raise."""
        st = Status(status)
        code = reason_code or ("" if st in (Status.OK, Status.EMPTY) else DEFAULT_REASON[st])
        if not valid_reason(st, code):
            raise ValueError(f"reason_code {code!r} is not valid for status {st.value!r} (A3 canonical codes)")
        self.status = st
        self.reason_code = code
        if error:
            self.error = error
        return self

    def stop(self, stop_reason: str) -> ModuleResult:
        """Mark a partial run: the module stopped early and keeps what it collected."""
        if stop_reason not in STOP_REASONS:
            raise ValueError(f"stop_reason must be one of {sorted(STOP_REASONS)} (got {stop_reason!r})")
        self.partial = True
        self.stop_reason = stop_reason
        return self

    def presence(
        self,
        state: str,
        *,
        marker: str = "",
        url: str = "",
        checked_at: Any = None,
        source: str = "",
    ) -> ModuleResult:
        """Tri-state existence result (attribute 'presence'). 'absent' needs a marker or URL as evidence."""
        st = str(state or "").strip().lower()
        if st not in PRESENCE_STATES:
            raise ValueError(f"presence state must be one of {PRESENCE_STATES} (got {state!r})")
        safe_url = ""
        if url:
            safe_url = _http_url(url) or ""
            if not safe_url:
                _violation(self.module, f"presence_url:{url}", f"presence url {url!r} is not an http(s) URL (dropped)")
        if st == "absent" and not (marker or safe_url):
            _violation(self.module, "presence_absent", "presence 'absent' needs positive evidence (marker= or url=); recorded as 'unknown' (rule 5)")
            st = "unknown"
        self.attr(
            "presence",
            {"state": st, "marker": marker or "", "url": safe_url, "checked_at": _iso(checked_at) or _now_iso(), "source": source or ""},
        )
        return self

    def set_marking(self, tlp: Any) -> ModuleResult:
        """Record a platform marking (e.g. a MISP tlp tag); the highest TLP seen is kept (A12)."""
        value = _tlp.parse(tlp)
        if not self.tlp or value > _tlp.parse(self.tlp):
            self.tlp = value.value_str
        return self

    def source_status(self, source_id: str, status: Status | str, *, reason_code: str = "", reason: str = "") -> ModuleResult:
        """Per-feed outcome for aggregators (a feed blocked or rate limited while others answered)."""
        st = Status(status)
        code = reason_code or ("" if st in (Status.OK, Status.EMPTY) else DEFAULT_REASON[st])
        if not valid_reason(st, code):
            raise ValueError(f"reason_code {code!r} is not valid for status {st.value!r} (A3 canonical codes)")
        declared = _declared_sources(self.module)
        if declared is not None and source_id not in declared:
            _violation(self.module, f"source:{source_id}", f"source_status for {source_id!r}, which is not one of the module's sources {list(declared)}")
        self.source_statuses[str(source_id)] = {"status": st.value, "reason_code": code, "reason": reason or ""}
        return self

    @property
    def has_data(self) -> bool:
        return bool(self.findings or self.pivots or self.attributes or self.links)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "entity": self.entity.key,
            "status": self.status.value,
            "findings": [f.id for f in self.findings],
            "pivots": [p.to_dict() for p in self.pivots],
            "attributes": self.attributes,
            "links": [{"label": lbl, "url": url} for lbl, url in self.links],
            "error": self.error,
            "duration": round(self.duration, 3),
            "requests": self.requests,
            "cache_hits": self.cache_hits,
            "evidence": self.evidence,
            "evidence_sha256": self.evidence_sha256,
            "reason_code": self.reason_code,
            "partial": self.partial,
            "stop_reason": self.stop_reason,
            "tlp": self.tlp,
            "hosts": dict(self.hosts),
            "datasets": [dict(d) for d in self.datasets],
            "redacted_fields": list(self.redacted_fields),
            "source_statuses": {k: dict(v) for k, v in self.source_statuses.items()},
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any], *, findings: dict[str, Finding] | None = None) -> ModuleResult:
        """Rebuild a result from ``to_dict`` output or a graph-fixture entry.

        ``findings`` entries may be ids (resolved through ``findings``) or full finding dicts.
        """
        entity = _entity_from_key(d.get("entity"))
        if entity is None:
            raise ValueError(f"module result needs an entity key 'type:value' (got {d.get('entity')!r})")
        res = cls(module=str(d.get("module") or ""), entity=entity, status=Status(d.get("status") or "ok"))
        for item in d.get("findings") or ():
            if isinstance(item, dict):
                f = Finding.from_dict(item, entity=_entity_from_key(item.get("entity")) or entity)
                if not f.module:
                    f.module = res.module
                    f.ensure_id()
                res.findings.append(f)
            elif findings and item in findings:
                res.findings.append(findings[item])
        for p in d.get("pivots") or ():
            ent = _entity_from_key(p.get("entity")) if isinstance(p, dict) else None
            if ent is None:
                continue
            conf = p.get("confidence")
            res.pivots.append(Pivot(ent, str(p.get("relation") or "related"), 0.9 if conf is None else conf, bool(p.get("expand", True)), str(p.get("note") or "")))
        attrs = d.get("attributes")
        res.attributes = dict(attrs) if isinstance(attrs, dict) else {}
        for link in d.get("links") or ():
            if isinstance(link, dict) and link.get("url"):
                res.links.append((str(link.get("label") or ""), str(link["url"])))
            elif isinstance(link, (list, tuple)) and len(link) == 2:
                res.links.append((str(link[0]), str(link[1])))
        res.raw = d.get("raw")
        res.error = str(d.get("error") or "")
        res.duration = float(d.get("duration") or 0.0)
        res.requests = int(d.get("requests") or 0)
        res.cache_hits = int(d.get("cache_hits") or 0)
        res.evidence = str(d.get("evidence") or "")
        res.evidence_sha256 = str(d.get("evidence_sha256") or "")
        res.reason_code = str(d.get("reason_code") or "")
        res.partial = bool(d.get("partial", False))
        res.stop_reason = str(d.get("stop_reason") or "")
        res.tlp = str(d.get("tlp") or "")
        res.hosts = {str(k): int(v) for k, v in (d.get("hosts") or {}).items()}
        res.datasets = [dict(x) for x in d.get("datasets") or () if isinstance(x, dict)]
        res.redacted_fields = [str(x) for x in d.get("redacted_fields") or ()]
        res.source_statuses = {str(k): dict(v) for k, v in (d.get("source_statuses") or {}).items() if isinstance(v, dict)}
        return res


# ----------------------------------------------------------------------------------------
# Correlation
# ----------------------------------------------------------------------------------------


@dataclass
class Correlation:
    """A cross-referenced conclusion spanning one or more entities (output of a rule)."""

    rule: str
    title: str
    severity: Severity
    description: str
    entities: list[Entity] = field(default_factory=list)
    confidence: float = 0.7
    evidence: list[str] = field(default_factory=list)  # finding ids or short facts
    recommendation: str = ""
    tags: list[str] = field(default_factory=list)
    id: str = ""
    criterion: str = ""
    confidence_label: Confidence | None = None
    attack: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    version: str = "1"
    why: str = ""
    key: str = ""
    suppressed_by: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)
        if isinstance(self.confidence, (str, Confidence)):
            label = Confidence.from_value(self.confidence)
            self.confidence = label.weight
            if self.confidence_label is None:
                self.confidence_label = label
        else:
            self.confidence = _clamp(self.confidence)
        if self.confidence_label is None:
            self.confidence_label = Confidence.from_value(self.confidence)
        else:
            self.confidence_label = Confidence.from_value(self.confidence_label)
        self._derived_id = ""
        self.ensure_id()

    @property
    def label(self) -> Confidence:
        return self.confidence_label or Confidence.from_value(self.confidence)

    def entity_keys(self) -> list[str]:
        return [e.key if isinstance(e, Entity) else str(e) for e in self.entities]

    def ensure_id(self) -> str:
        """Fill ``id`` with :func:`correlation_id` (recomputed while derived; explicit ids are kept)."""
        if self.id and self.id != self._derived_id:
            return self.id
        new = correlation_id(self.rule, self.entity_keys(), self.key)
        self.id = new
        self._derived_id = new
        return new

    def downgrade(self, rule: str, reason: str, *, to: Confidence | str | None = None) -> Correlation:
        """Suppression lowers the label (never deletes): same semantics as :meth:`Finding.downgrade`."""
        current = self.label
        new = current.lower()
        if to is not None:
            target = Confidence.from_value(to)
            new = target if target.rank < current.rank else current
        if new.rank < current.rank:
            self.confidence = min(float(self.confidence), new.weight)
        self.confidence_label = new
        self.criterion = _chain_criterion(f"{_label_text(new)} - {reason}", self.criterion)
        self.suppressed_by.append({"rule": rule, "reason": reason})
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id or self.ensure_id(),
            "rule": self.rule,
            "title": self.title,
            "severity": self.severity.label,
            "description": self.description,
            "entities": self.entity_keys(),
            "confidence": round(float(self.confidence), 3),
            "evidence": list(self.evidence),
            "recommendation": self.recommendation,
            "tags": list(self.tags),
            "criterion": self.criterion,
            "confidence_label": self.label.value,
            "attack": list(self.attack),
            "references": list(self.references),
            "version": self.version,
            "why": self.why,
            "key": self.key,
            "suppressed_by": [dict(s) for s in self.suppressed_by],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Correlation:
        """Rebuild a correlation from ``to_dict`` output (stored v1 dicts included)."""
        try:
            severity = Severity.parse(d.get("severity", "info") or "info")
        except (KeyError, ValueError):
            severity = Severity.INFO
        ents = [e for e in (_entity_from_key(k) for k in d.get("entities") or ()) if e is not None]
        return cls(
            rule=str(d.get("rule") or ""),
            title=str(d.get("title") or ""),
            severity=severity,
            description=str(d.get("description") or ""),
            entities=ents,
            confidence=d.get("confidence", 0.7) if d.get("confidence") is not None else 0.7,
            evidence=[str(x) for x in d.get("evidence") or ()],
            recommendation=str(d.get("recommendation") or ""),
            tags=[str(t) for t in d.get("tags") or ()],
            id=str(d.get("id") or ""),
            criterion=str(d.get("criterion") or ""),
            confidence_label=d.get("confidence_label") or None,
            attack=[str(a) for a in d.get("attack") or ()],
            references=[str(r) for r in d.get("references") or ()],
            version=str(d.get("version") or "1"),
            why=str(d.get("why") or ""),
            key=str(d.get("key") or ""),
            suppressed_by=[dict(s) for s in d.get("suppressed_by") or () if isinstance(s, dict)],
        )
