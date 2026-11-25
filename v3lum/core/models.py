"""Result data model shared by modules, the engine, correlation and reports."""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from typing import Any

from v3lum.core.entities import Entity, EntityType


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
    OK = "ok"  # ran and returned data
    EMPTY = "empty"  # ran fine, nothing found
    ERROR = "error"  # failed (network, parsing, bug)
    SKIPPED = "skipped"  # not applicable (applies() said no)
    NEEDS_KEY = "needs_key"  # API key missing
    RATE_LIMITED = "rate_limited"  # provider throttled us / daily quota used up
    BLOCKED = "blocked"  # anti-bot wall, geo/datacenter block: could not verify (never "absent")
    UNAVAILABLE = "unavailable"  # provider down / dependency missing / offline mode


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


@dataclass
class Finding:
    """A fact or judgement about an entity, produced by a module (or a correlation rule)."""

    title: str
    severity: Severity = Severity.INFO
    description: str = ""
    confidence: float = 0.8
    data: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    entity: Entity | None = None
    module: str = ""
    id: str = field(default_factory=_new_id)

    def to_dict(self) -> dict[str, Any]:
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
        }


@dataclass
class Pivot:
    """A new entity discovered from the subject entity."""

    entity: Entity
    relation: str
    confidence: float = 0.9
    expand: bool = True  # may the engine investigate it further?
    note: str = ""


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

    # ---- builder helpers used by modules -------------------------------------------------

    def finding(
        self,
        title: str,
        severity: Severity | str = Severity.INFO,
        description: str = "",
        *,
        confidence: float = 0.8,
        data: dict[str, Any] | None = None,
        tags: list[str] | tuple[str, ...] = (),
        references: list[str] | tuple[str, ...] = (),
    ) -> Finding:
        f = Finding(
            title=title,
            severity=Severity.parse(severity),
            description=description,
            confidence=max(0.0, min(1.0, float(confidence))),
            data=dict(data or {}),
            tags=list(tags),
            references=list(references),
            entity=self.entity,
            module=self.module,
        )
        self.findings.append(f)
        return f

    def pivot(
        self,
        etype: EntityType | str,
        value: str,
        relation: str,
        *,
        confidence: float = 0.9,
        expand: bool = True,
        note: str = "",
    ) -> Entity | None:
        """Add a discovered entity. Invalid values are ignored (returns None)."""
        ent = Entity.try_make(etype, value)
        if ent is None or ent == self.entity:
            return None
        if any(p.entity == ent and p.relation == relation for p in self.pivots):
            return ent
        self.pivots.append(Pivot(ent, relation, max(0.0, min(1.0, confidence)), expand, note))
        return ent

    def attr(self, key: str, value: Any) -> None:
        """Record a fact about the subject entity (see v3lum.core.vocab.ATTRIBUTES)."""
        if value is None or value == "" or value == [] or value == {}:
            return
        self.attributes[key] = value

    def link(self, label: str, url: str) -> None:
        if url and (label, url) not in self.links:
            self.links.append((label, url))

    def mark(self, status: Status | str, error: str = "") -> ModuleResult:
        self.status = Status(status)
        if error:
            self.error = error
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
            "pivots": [
                {"entity": p.entity.key, "relation": p.relation, "confidence": p.confidence, "expand": p.expand, "note": p.note}
                for p in self.pivots
            ],
            "attributes": self.attributes,
            "links": [{"label": lbl, "url": url} for lbl, url in self.links],
            "error": self.error,
            "duration": round(self.duration, 3),
            "requests": self.requests,
            "cache_hits": self.cache_hits,
            "evidence": self.evidence,
            "evidence_sha256": self.evidence_sha256,
        }


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
    id: str = field(default_factory=_new_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule": self.rule,
            "title": self.title,
            "severity": self.severity.label,
            "description": self.description,
            "entities": [e.key for e in self.entities],
            "confidence": round(float(self.confidence), 3),
            "evidence": list(self.evidence),
            "recommendation": self.recommendation,
            "tags": list(self.tags),
        }
