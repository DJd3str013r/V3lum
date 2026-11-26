"""Bundled MITRE ATT&CK technique index (ids, names, STIX ids, revocations).

The index is assembled from fragments ``v3lum/data/attack/*.json`` (schema
``v3lum.attack_index/1``), read once in file-name order; the first declaration of a technique
wins. ``core_min.json`` ships the techniques the core needs; correlation packs and the P292
batch add their own fragment files (nobody edits ``core_min.json``)::

    {"schema": "v3lum.attack_index/1", "version": "enterprise-attack 20.1",
     "techniques": {"T1566": {"name": "Phishing", "stix_id": "attack-pattern--...",
                              "revoked": false, "deprecated": false, "replaced_by": null}}}

Rules and findings reference technique ids; :func:`canonical` maps revoked ids to their
replacements (T1656 -> T1684.001) and :func:`validate` reports unknown ids and revoked or
deprecated ids without a replacement. ATT&CK is (c) The MITRE Corporation, reproduced under
the ATT&CK terms of use (attribution in each fragment).
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Schema id of ATT&CK index fragments.
FRAGMENT_SCHEMA = "v3lum.attack_index/1"
#: Directory scanned for fragments (tests monkeypatch it, then call :func:`reload`).
FRAGMENT_DIR: Path = Path(__file__).resolve().parent.parent / "data" / "attack"
#: Technique / sub-technique id format.
ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_STIX_RE = re.compile(r"^attack-pattern--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_META_KEYS = frozenset({"schema", "version", "techniques", "source", "licence", "license", "attribution", "notes", "pack", "$comment"})


@dataclass(frozen=True)
class Technique:
    """One ATT&CK technique or sub-technique as bundled by V3LUM."""

    id: str
    name: str
    stix_id: str = ""
    revoked: bool = False
    deprecated: bool = False
    replaced_by: str | None = None
    origin: str = ""

    @property
    def usable(self) -> bool:
        """Known, not revoked and not deprecated."""
        return not (self.revoked or self.deprecated)


class _Index:
    def __init__(self) -> None:
        self.loaded = False
        self.techniques: dict[str, Technique] = {}
        self.errors: list[str] = []
        self.duplicates: list[tuple[str, str]] = []
        self.versions: dict[str, str] = {}


_INDEX = _Index()
_LOCK = threading.RLock()


def normalize(tid: Any) -> str:
    """'t1566.001 ' -> 'T1566.001' (no validation)."""
    return str(tid or "").strip().upper()


def _load() -> _Index:
    idx = _Index()
    directory = Path(FRAGMENT_DIR)
    files = sorted(directory.glob("*.json")) if directory.is_dir() else []
    for path in files:
        fname = path.name
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            idx.errors.append(f"attack fragment {fname}: unreadable or invalid JSON ({type(exc).__name__}: {exc})")
            continue
        if not isinstance(doc, dict) or doc.get("schema") != FRAGMENT_SCHEMA:
            idx.errors.append(f"attack fragment {fname}: schema must be {FRAGMENT_SCHEMA!r}")
            continue
        for key in doc:
            if key not in _META_KEYS:
                idx.errors.append(f"attack fragment {fname}: unknown top-level key {key!r}")
        if doc.get("version") is not None and not isinstance(doc.get("version"), str):
            idx.errors.append(f"attack fragment {fname}: 'version' must be a string")
        idx.versions[fname] = str(doc.get("version") or "")
        techniques = doc.get("techniques")
        if not isinstance(techniques, dict):
            idx.errors.append(f"attack fragment {fname}: 'techniques' must be an object of id -> entry")
            continue
        for raw_id, entry in techniques.items():
            tech, problem = _parse_entry(raw_id, entry, fname)
            if problem:
                idx.errors.append(f"attack fragment {fname}: {raw_id!r}: {problem}")
                continue
            assert tech is not None
            existing = idx.techniques.get(tech.id)
            if existing is not None:
                same = (existing.name, existing.stix_id, existing.revoked, existing.deprecated, existing.replaced_by) == (
                    tech.name, tech.stix_id, tech.revoked, tech.deprecated, tech.replaced_by
                )
                if not same:
                    idx.duplicates.append((tech.id, fname))
                continue
            idx.techniques[tech.id] = tech
    for tech in idx.techniques.values():
        if tech.replaced_by and tech.replaced_by not in idx.techniques:
            idx.errors.append(f"attack index: {tech.id} is replaced by unknown technique {tech.replaced_by} ({tech.origin})")
    idx.loaded = True
    return idx


def _parse_entry(raw_id: Any, entry: Any, fname: str) -> tuple[Technique | None, str]:
    tid = normalize(raw_id)
    if not ID_RE.match(tid) or tid != raw_id:
        return None, "technique ids look like 'T1566' or 'T1566.001'"
    if not isinstance(entry, dict):
        return None, "entry must be an object {name, stix_id, revoked, deprecated, replaced_by}"
    name = entry.get("name")
    if not isinstance(name, str) or not name.strip():
        return None, "needs a non-empty name"
    stix_id = entry.get("stix_id") or ""
    if stix_id and (not isinstance(stix_id, str) or not _STIX_RE.match(stix_id)):
        return None, "stix_id must look like 'attack-pattern--<uuid>'"
    revoked, deprecated = entry.get("revoked", False), entry.get("deprecated", False)
    if not isinstance(revoked, bool) or not isinstance(deprecated, bool):
        return None, "revoked/deprecated must be booleans"
    replaced_by = entry.get("replaced_by")
    if replaced_by is not None:
        if not isinstance(replaced_by, str) or not ID_RE.match(replaced_by):
            return None, "replaced_by must be a technique id or null"
        if replaced_by == tid:
            return None, "replaced_by points to itself"
    return Technique(tid, name.strip(), stix_id, revoked, deprecated, replaced_by, fname), ""


def _index() -> _Index:
    global _INDEX
    if not _INDEX.loaded:
        with _LOCK:
            if not _INDEX.loaded:
                _INDEX = _load()
    return _INDEX


def reload() -> None:
    """Re-read the fragments (tests, plugins)."""
    global _INDEX
    with _LOCK:
        _INDEX = _load()


# ----------------------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------------------


def lookup(tid: str) -> Technique | None:
    """The bundled technique for ``tid`` (as declared; revoked entries included) or None."""
    return _index().techniques.get(normalize(tid))


def is_valid(tid: str) -> bool:
    """Known and neither revoked nor deprecated."""
    tech = lookup(tid)
    return tech is not None and tech.usable


def canonical(tid: str) -> str:
    """Follow ``replaced_by`` chains (T1656 -> T1684.001). Unknown ids come back normalized."""
    current = normalize(tid)
    seen: set[str] = set()
    techniques = _index().techniques
    while current not in seen:
        seen.add(current)
        tech = techniques.get(current)
        if tech is None or not tech.replaced_by:
            return current
        current = tech.replaced_by
    return normalize(tid)  # cycle: keep what the caller gave


def validate(ids: Iterable[str]) -> list[str]:
    """Problems with ``ids``: unknown ids, and revoked/deprecated ids that have no usable replacement."""
    problems: list[str] = []
    if isinstance(ids, str):
        ids = [ids]
    for raw in ids or ():
        tid = normalize(raw)
        if not ID_RE.match(tid):
            problems.append(f"{raw!r} is not an ATT&CK technique id")
            continue
        tech = lookup(tid)
        if tech is None:
            problems.append(f"{tid} is not in the bundled ATT&CK index (add it to a v3lum/data/attack/<pack>.json fragment)")
            continue
        final = lookup(canonical(tid))
        if final is None or not final.usable:
            state = "revoked" if tech.revoked else "deprecated" if tech.deprecated else "not usable"
            problems.append(f"{tid} is {state} and has no usable replacement")
    return problems


def stix_id(tid: str) -> str | None:
    """STIX id of the canonical technique for ``tid`` (revoked ids resolve to their replacement)."""
    tech = lookup(canonical(tid))
    return (tech.stix_id or None) if tech else None


def name(tid: str) -> str:
    """Display name of the canonical technique, '' when unknown."""
    tech = lookup(canonical(tid))
    return tech.name if tech else ""


def techniques() -> dict[str, Technique]:
    """Every bundled technique (merged index)."""
    return dict(_index().techniques)


def errors() -> list[str]:
    """Problems in the fragments (malformed files/entries, dangling replacements)."""
    return list(_index().errors)


def duplicates() -> list[tuple[str, str]]:
    """Techniques declared again with different content by a later fragment: (id, file). First wins."""
    return list(_index().duplicates)
