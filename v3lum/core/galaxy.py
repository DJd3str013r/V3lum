"""Stable ids for threat actors and malware families: MISP galaxy clusters (P303).

STIX ``threat-actor`` / ``malware`` objects and MISP galaxy tags of a V3LUM export must carry the
same id in every case and every run, so a TIP merges them with what it already holds. The id is the
**MISP galaxy cluster uuid** when a galaxy fragment ships the cluster, else a ``uuid5`` of the
canonical name (:data:`DERIVED_NS`), never a case-scoped id.

* :func:`lookup(kind, name) <lookup>` returns the :class:`Cluster` of a ``threat_actor`` or
  ``malware_family`` name: a fragment cluster matched by name or synonym (case-insensitive,
  whitespace collapsed), else - after resolving the name through the actor/malware alias index
  (``v3lum.core.ioc.alias_lookup``, P295) - the cluster of its canonical name, else a *derived*
  cluster (``source == 'derived'``) whose uuid is ``uuid5(DERIVED_NS, '<kind>|<canonical name
  casefolded>')``. ``None`` only for an empty name or an unknown kind.
* Fragments live in ``v3lum/data/galaxy/<name>.json`` (schema ``'v3lum.galaxy/1'``, one kind per
  file; nothing is bundled by the core)::

      {"schema": "v3lum.galaxy/1", "kind": "threat_actor", "galaxy": "threat-actor",
       "galaxy_uuid": "698774c7-8022-42c4-917f-8d6e4f06ada3",
       "source": "MISP galaxy commit <sha>, built <date>", "licence": "CC0-1.0 OR BSD-2-Clause",
       "notice": "misp_galaxy",
       "clusters": {"APT28": {"uuid": "5b4ee3ea-eee3-4c8e-8323-85ae32658754",
                              "synonyms": ["Sofacy", "Fancy Bear"]}}}

  MISP galaxy data is used under its licence: a fragment must name its notice fragment
  (``v3lum/data/notices/<notice>.json``, A6); a fragment without one, with a malformed uuid, an
  unknown kind or a name claimed by two clusters is reported by :func:`errors` and the offending
  entries are skipped (first declaration wins).

Module authors do not call this module; exporters (``v3lum.report.stix``, ``v3lum.report.misp``)
do. Tests point :data:`FRAGMENT_DIR` elsewhere or pass ``extra_dirs`` to :func:`reload`.
"""

from __future__ import annotations

import json
import re
import threading
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "Cluster",
    "DERIVED_NS",
    "FRAGMENT_DIR",
    "FRAGMENT_SCHEMA",
    "KINDS",
    "clusters",
    "errors",
    "lookup",
    "reload",
]

#: Schema id of galaxy fragments.
FRAGMENT_SCHEMA = "v3lum.galaxy/1"
#: Directory scanned for fragments (tests monkeypatch it or pass ``extra_dirs`` to :func:`reload`).
FRAGMENT_DIR: Path = Path(__file__).resolve().parent.parent / "data" / "galaxy"
#: Notice fragments (A6): a galaxy fragment must name one that exists here.
NOTICE_DIR: Path = Path(__file__).resolve().parent.parent / "data" / "notices"
#: Namespace of derived (non-galaxy) cluster uuids: uuid5(DERIVED_NS, '<kind>|<canonical casefolded>').
DERIVED_NS = uuid.UUID("3d8e2b6a-6c1f-5d0e-9a0b-7f3c2e1d4b5a")
#: Entity kind -> (default MISP galaxy type, STIX SDO type).
KINDS: dict[str, tuple[str, str]] = {
    "threat_actor": ("threat-actor", "threat-actor"),
    "malware_family": ("malpedia", "malware"),
}

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_GALAXY_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_NOTICE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_META_KEYS = frozenset({"schema", "kind", "galaxy", "galaxy_uuid", "source", "licence", "license", "notice", "notes", "clusters", "$comment"})


@dataclass(frozen=True)
class Cluster:
    """One threat actor / malware family with its stable id.

    ``kind`` 'threat_actor' | 'malware_family'; ``name`` the canonical value (the galaxy cluster
    value, or the alias index's canonical name); ``uuid`` the MISP galaxy cluster uuid (``source ==
    'galaxy'``) or the derived uuid5 (``source == 'derived'``); ``galaxy`` the MISP galaxy type
    (``threat-actor``, ``malpedia``...), ``galaxy_uuid`` that galaxy's uuid when a fragment names
    it ('' otherwise); ``synonyms`` from the fragment; ``origin`` the fragment file ('' derived).
    """

    kind: str
    name: str
    uuid: str
    galaxy: str
    galaxy_uuid: str = ""
    source: str = "derived"
    synonyms: tuple[str, ...] = ()
    origin: str = ""

    @property
    def stix_type(self) -> str:
        """'threat-actor' or 'malware'."""
        return KINDS[self.kind][1]

    @property
    def stix_id(self) -> str:
        """``<stix type>--<uuid>``: the same object id in every case and run."""
        return f"{self.stix_type}--{self.uuid}"

    @property
    def tag(self) -> str:
        """The MISP galaxy tag, e.g. ``misp-galaxy:threat-actor="APT28"`` (quotes in the name escaped)."""
        value = self.name.replace("\\", "\\\\").replace('"', '\\"')
        return f'misp-galaxy:{self.galaxy}="{value}"'


class _Index:
    def __init__(self) -> None:
        self.loaded = False
        self.by_name: dict[tuple[str, str], Cluster] = {}
        self.clusters: dict[tuple[str, str], Cluster] = {}
        self.errors: list[str] = []


_INDEX = _Index()
_LOCK = threading.RLock()
_EXTRA: tuple[Path, ...] = ()


def _norm(name: Any) -> str:
    return " ".join(str(name or "").split()).casefold()


def _load_file(idx: _Index, path: Path) -> None:
    origin = path.name
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        idx.errors.append(f"{origin}: unreadable galaxy fragment ({type(exc).__name__})")
        return
    if not isinstance(data, dict) or data.get("schema") != FRAGMENT_SCHEMA:
        idx.errors.append(f"{origin}: not a {FRAGMENT_SCHEMA} fragment")
        return
    unknown = sorted(set(data) - _META_KEYS)
    if unknown:
        idx.errors.append(f"{origin}: unknown field(s) {', '.join(unknown)}")
    kind = str(data.get("kind") or "")
    if kind not in KINDS:
        idx.errors.append(f"{origin}: kind must be one of {', '.join(sorted(KINDS))}")
        return
    galaxy = str(data.get("galaxy") or KINDS[kind][0])
    if not _GALAXY_RE.match(galaxy):
        idx.errors.append(f"{origin}: invalid galaxy type {galaxy!r}")
        return
    galaxy_uuid = str(data.get("galaxy_uuid") or "").lower()
    if galaxy_uuid and not _UUID_RE.match(galaxy_uuid):
        idx.errors.append(f"{origin}: galaxy_uuid is not a uuid")
        galaxy_uuid = ""
    if not str(data.get("licence") or data.get("license") or "").strip():
        idx.errors.append(f"{origin}: 'licence' is required (MISP galaxy data is used under its licence, A6)")
        return
    notice = str(data.get("notice") or "")
    if not _NOTICE_RE.match(notice) or not (NOTICE_DIR / f"{notice}.json").is_file():
        idx.errors.append(f"{origin}: 'notice' must name a notice fragment in v3lum/data/notices/ (A6)")
        return
    raw = data.get("clusters")
    if not isinstance(raw, dict):
        idx.errors.append(f"{origin}: 'clusters' must be an object (name -> {{uuid, synonyms}})")
        return
    for name, entry in raw.items():
        name = " ".join(str(name or "").split())
        if not name or not isinstance(entry, dict):
            idx.errors.append(f"{origin}: malformed cluster {name!r}")
            continue
        cid = str(entry.get("uuid") or "").lower()
        if not _UUID_RE.match(cid):
            idx.errors.append(f"{origin}: cluster {name!r} has no valid uuid")
            continue
        synonyms = tuple(" ".join(str(s).split()) for s in entry.get("synonyms") or () if str(s).strip())
        cluster = Cluster(kind, name, cid, galaxy, galaxy_uuid, "galaxy", synonyms, origin)
        key = (kind, _norm(name))
        if key in idx.clusters:
            idx.errors.append(f"{origin}: cluster {name!r} declared again (first declaration wins)")
            continue
        idx.clusters[key] = cluster
        for alias in (name, *synonyms):
            akey = (kind, _norm(alias))
            other = idx.by_name.get(akey)
            if other is not None and other.uuid != cid:
                idx.errors.append(f"{origin}: name {alias!r} names two clusters ({other.name}, {name}); kept {other.name}")
                continue
            idx.by_name.setdefault(akey, cluster)


def _index() -> _Index:
    with _LOCK:
        if _INDEX.loaded:
            return _INDEX
        fresh = _Index()
        dirs = [FRAGMENT_DIR, *_EXTRA]
        for directory in dirs:
            try:
                files = sorted(p for p in Path(directory).glob("*.json") if p.is_file())
            except OSError:
                files = []
            for path in files:
                _load_file(fresh, path)
        fresh.loaded = True
        _INDEX.__dict__.update(fresh.__dict__)
        return _INDEX


def reload(extra_dirs: Iterable[str | Path] = ()) -> None:
    """Re-read the fragments (plus ``extra_dirs``, e.g. a test's tmp directory); ``reload()``
    restores the bundled set."""
    global _EXTRA
    with _LOCK:
        _EXTRA = tuple(Path(d) for d in extra_dirs)
        _INDEX.loaded = False
        _index()


def errors() -> list[str]:
    """Problems found in the fragments (empty for a clean tree)."""
    return list(_index().errors)


def clusters() -> dict[tuple[str, str], Cluster]:
    """Every fragment cluster keyed by ``(kind, normalised name)``."""
    return dict(_index().clusters)


def _canonical(kind: str, name: str) -> str:
    """The alias index's canonical name for ``name`` of that kind (``name`` itself otherwise)."""
    try:
        from v3lum.core.ioc import alias_lookup  # lazy: ioc is large and optional here
    except Exception:  # noqa: BLE001 - no alias index: the name is its own canonical form
        return name
    try:
        hits = alias_lookup(name)
    except Exception:  # noqa: BLE001 - a broken alias fragment never breaks an export
        return name
    for etype, canonical in hits:
        if getattr(etype, "value", str(etype)) == kind and str(canonical).strip():
            return " ".join(str(canonical).split())
    return name


def lookup(kind: Any, name: Any) -> Cluster | None:
    """The :class:`Cluster` of a ``threat_actor`` / ``malware_family`` name (EntityType or its
    value accepted for ``kind``); see the module docstring for the resolution order. Returns
    ``None`` for an empty name or a kind other than those two."""
    kind_s = str(getattr(kind, "value", kind) or "").strip().lower()
    if kind_s not in KINDS:
        return None
    text = " ".join(str(name or "").split())
    if not text:
        return None
    idx = _index()
    found = idx.by_name.get((kind_s, _norm(text)))
    if found is not None:
        return found
    canonical = _canonical(kind_s, text)
    found = idx.by_name.get((kind_s, _norm(canonical)))
    if found is not None:
        return found
    derived = uuid.uuid5(DERIVED_NS, f"{kind_s}|{_norm(canonical)}")
    return Cluster(kind_s, canonical, str(derived), KINDS[kind_s][0], "", "derived", (), "")
