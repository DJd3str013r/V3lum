"""attack_index: MITRE ATT&CK compact offline index - technique, group and software cards (P292).

Batch p1-G11-1. Offline lookup (disclosure 'none'): the typed id or name never leaves the machine. Final
conditions (FC) of P292 and where they are met:

* **FC1 compact index.** Enterprise + Mobile + ICS ATT&CK (CAPEC 2.1 optional) reduced to a compact index:
  live techniques/tactics/groups/software/campaigns/mitigations/detection strategies and their edges, the
  ATT&CK version per domain, the build date and the MITRE notice (attribute ``data_notices`` on every card;
  ``v3lum/data/notices/mitre_attack.json`` for data/NOTICE and report footers). Lookups are offline; the
  stored index loads in well under 100 ms (gzip JSON parts, merged once per process).
* **FC2 shipping.** The prebuilt index is NOT bundled: the ATT&CK/CAPEC Terms of Use are not on the A6
  bundling list until legal records them. ``v3lum data update attack`` (and ``attack.mobile``,
  ``attack.ics``; all three are 'essential', so the first-run hint lists them) builds it.
* **FC3 rebuild.** The STIX bundles (raw.githubusercontent.com mitre-attack/attack-stix-data; ``index.json``
  for versions) are fetched by the dataset manager (large: never during a scan) and parsed object by object
  by :func:`iter_bundle_objects` (no ``json.load`` of a bundle; memory stays around one object plus a read
  chunk - tested on a synthetic 50 MB bundle). The compact part of each bundle is built in the dataset's
  ``validate`` hook, i.e. at update time, and kept in this module's state (``ctx.state``: the only
  persistence a module may use) keyed by the bundle's SHA-256; a scan never parses a bundle. TAXII 2.1
  (attack-taxii.mitre.org) only detects a newer version (:func:`parse_taxii_discovery`,
  :func:`newer_attack_version`): the dataset manager cannot send the TAXII Accept header yet (core request),
  so ``index.json`` (dataset ``attack.versions``) provides the version check meanwhile.
* **FC4 revoked/deprecated.** Revoked and deprecated objects are dropped; a revoked-by map follows chains
  (T1656 -> T1684.001; T1073 -> T1574.002 -> T1574.001). A typed revoked id answers 'revoked -> replaced by
  X' and pivots to X - never a silent rewrite. Tactic names and order come from the data per domain
  (x-mitre-tactic / x-mitre-matrix: v18+ 'Stealth' and 'Defense Impairment'); none are hard-coded.
* **FC5 ids and detections.** 'T1059/001', 't1059.001', 'T1059-001' -> 'T1059.001'
  (:func:`normalise_attack_id`; the core entity normaliser still refuses the slash form: core request);
  text_blob inputs are the P172 extractor's job. Detections come from x-mitre-detection-strategy 'detects'
  edges (DET ids).
* **FC6 exports.** Cards carry the official STIX id (``stix_id``) and the MISP galaxy tag
  (``misp-galaxy:mitre-attack-pattern="PowerShell - T1059.001"``); the ATT&CK version is on every card
  (``attack_version``) for the case record and report footers (core: P303/P336).
* **FC7 cards.** Name, tactics from the data, at most 10 related groups/software and the attack.mitre.org
  link. Group/software 'uses' edges are context, never attribution evidence: their pivots are
  ``expand=False`` and POSSIBLE. CWE -> CAPEC -> ATT&CK links (:func:`cwe_attack_candidates`) always carry
  low confidence.
* **FC8 provider.** MITRE (trusted); downloads only, no value is ever sent. Fixtures: trimmed real
  Enterprise/Mobile/ICS bundle slices with a revoked technique, the TAXII captures and a CAPEC slice.
"""

from __future__ import annotations

import base64
import codecs
import gzip
import hashlib
import json
import re
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

from v3lum.core.context import ModuleState, StateError
from v3lum.core.datasets import DATASETS, DatasetError, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

# ======================================================================================
# Sources and constants
# ======================================================================================

MODULE_NAME = "attack_index"
SOURCE = "github.attack_index_stix"
SOURCE_CAPEC = "github.attack_index_capec"
STIX_REPO = "https://github.com/mitre-attack/attack-stix-data"
BUNDLE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json"
INDEX_JSON_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
CAPEC_URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
TAXII_ROOT = "https://attack-taxii.mitre.org"
TAXII_ACCEPT = "application/taxii+json;version=2.1"
DOMAINS = ("enterprise-attack", "mobile-attack", "ics-attack")
#: dataset name -> domain ('attack' is the Enterprise bundle: `v3lum data update attack`, FC2).
DATASET_DOMAINS = {"attack": "enterprise-attack", "attack.mobile": "mobile-attack", "attack.ics": "ics-attack"}
CAPEC_DATASET = "attack.capec"
VERSIONS_DATASET = "attack.versions"
REFRESH_TTL = 7 * 86400
ATTACK_SOURCE_NAMES = ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack")
KILL_CHAIN_DOMAIN = {"mitre-attack": "enterprise-attack", "mitre-mobile-attack": "mobile-attack", "mitre-ics-attack": "ics-attack"}
COLLECTION_DOMAIN = {"enterprise att&ck": "enterprise-attack", "mobile att&ck": "mobile-attack", "ics att&ck": "ics-attack"}
TAXII_COLLECTIONS = {
    "enterprise-attack": "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019",
    "mobile-attack": "x-mitre-collection--dac0d2d7-8653-445c-9bff-82f934c1e858",
    "ics-attack": "x-mitre-collection--90c00720-636b-4485-b342-8751d232bf09",
}
MITRE_LICENCE = (
    "The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK(R) for research, "
    "development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce "
    "MITRE's copyright designation and this license in any such copy."
)
ATTRIBUTION_NOTE = "Group/software 'uses' edges are context, never attribution evidence."
MAX_RELATED = 10  # FC7
STATE_PREFIX = "part."
STATE_FORMAT = "gzip+base64/json"
#: largest single STIX object accepted by the stream parser (the Enterprise x-mitre-collection is ~3.4 MB).
MAX_OBJECT_BYTES = 64 << 20


def mitre_notice(year: Any = None) -> str:
    """The copyright designation every ATT&CK copy reproduces (attack-stix-data LICENSE.txt)."""
    y = int(year) if isinstance(year, (int, str)) and str(year).isdigit() else 2026
    return f"© {y} The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."


# ======================================================================================
# Streaming STIX bundle reader (FC3)
# ======================================================================================


class StixStreamError(ValueError):
    """Truncated, malformed or oversized STIX bundle."""


class _Stream:
    def __init__(self, fp: Any, chunk: int) -> None:
        self.fp = fp
        self.chunk = max(1024, int(chunk))
        self.buf = ""
        self.pos = 0
        self.offset = 0
        self.eof = False
        self.dec = codecs.getincrementaldecoder("utf-8-sig")("strict")
        self.read_size = self.chunk

    def more(self, grow: bool = False) -> bool:
        if self.eof:
            return False
        self.read_size = min(self.read_size * 2, 1 << 26) if grow else self.chunk
        data = self.fp.read(self.read_size)
        if isinstance(data, (bytes, bytearray)):
            try:
                text = self.dec.decode(bytes(data), final=not data)
            except UnicodeDecodeError as exc:
                raise StixStreamError(f"invalid UTF-8 near byte {self.offset} ({exc.reason})") from exc
        else:
            text = data or ""
            if text and not self.buf and self.offset == 0 and text.startswith("﻿"):
                text = text[1:]
        if not data:
            self.eof = True
        if self.pos > self.chunk:
            self.offset += self.pos
            self.buf = self.buf[self.pos:]
            self.pos = 0
        self.buf += text
        return bool(text)

    def peek(self) -> str:
        while True:
            while self.pos < len(self.buf) and self.buf[self.pos] in " \t\r\n":
                self.pos += 1
            if self.pos < len(self.buf):
                return self.buf[self.pos]
            if not self.more():
                return ""

    def expect(self, chars: str) -> str:
        c = self.peek()
        if c == "" or c not in chars:
            raise StixStreamError(f"expected {chars!r} at offset {self.offset + self.pos}, found {c or 'EOF'!r}")
        self.pos += 1
        return c


def iter_bundle_objects(fp: Any, *, key: str = "objects", chunk_size: int = 1 << 16, max_object_bytes: int = MAX_OBJECT_BYTES,
                        meta: dict[str, Any] | None = None) -> Iterator[Any]:
    """Yield the elements of a STIX bundle's top-level ``objects`` array one by one (FC3).

    ``fp`` is a binary or text file object (a ``gzip.open()`` stream works). Memory stays bounded by roughly
    the largest single object plus a read chunk: the bundle is never ``json.load``-ed. Scalar top-level
    keys (type, id, spec_version) go into ``meta``. Raises StixStreamError on truncated or malformed input
    and on an object larger than ``max_object_bytes``."""
    dec = json.JSONDecoder()
    st = _Stream(fp, chunk_size)

    def value() -> Any:
        grow = False
        while True:
            try:
                val, end = dec.raw_decode(st.buf, st.pos)
                if end >= len(st.buf) and not st.eof and not isinstance(val, (dict, list, str)):
                    st.more(grow=True)  # a bare number may continue in the next chunk
                    continue
                st.pos = end
                return val
            except ValueError:
                if st.eof:
                    raise StixStreamError(f"truncated or malformed JSON near offset {st.offset + st.pos}") from None
                if len(st.buf) - st.pos > max_object_bytes:
                    raise StixStreamError(f"object larger than {max_object_bytes} bytes or malformed near offset {st.offset + st.pos}") from None
                st.more(grow=grow)
                grow = True

    first = st.peek()
    if first != "{":
        raise StixStreamError(f"not a JSON object (starts with {first or 'EOF'!r})")
    st.pos += 1
    found = False
    while True:
        c = st.peek()
        if c == "}":
            st.pos += 1
            break
        if c != '"':
            raise StixStreamError(f"expected a key at offset {st.offset + st.pos}")
        k = value()
        st.expect(":")
        if k == key:
            found = True
            st.expect("[")
            if st.peek() == "]":
                st.pos += 1
            else:
                while True:
                    st.peek()
                    yield value()
                    if st.expect(",]") == "]":
                        break
        else:
            st.peek()
            v = value()
            if isinstance(meta, dict) and not isinstance(v, (dict, list)):
                meta[k] = v
        if st.expect(",}") == "}":
            break
    if isinstance(meta, dict):
        meta["_objects_found"] = found


# ======================================================================================
# Ids (FC5) and links
# ======================================================================================

_ID_RE = re.compile(r"^\s*(TA|DET|AN|DS|DC|[TGSCM])\s*-?\s*(\d{4})(?:\s*[./\-_ ]\s*(\d{3}))?\s*$", re.I)


def normalise_attack_id(text: Any) -> str | None:
    """'T1059/001', 't1059.001', 'T1059-001', 'g0007', 'ta0002' -> canonical id ('T1059.001'), else None.
    Sub-technique suffixes exist for techniques only; v20 'S9xxx' software ids are valid."""
    if not isinstance(text, str):
        return None
    m = _ID_RE.match(text)
    if not m:
        return None
    prefix, num, sub = m.group(1).upper(), m.group(2), m.group(3)
    if sub and prefix != "T":
        return None
    return f"{prefix}{num}.{sub}" if sub else f"{prefix}{num}"


def stix_external_id(obj: Any) -> tuple[str | None, str | None]:
    """(external_id, url) from the object's ATT&CK reference (any of the three source names)."""
    refs = obj.get("external_references") if isinstance(obj, dict) else None
    if not isinstance(refs, list):
        return None, None
    for want in ATTACK_SOURCE_NAMES:
        for r in refs:
            if isinstance(r, dict) and r.get("source_name") == want and isinstance(r.get("external_id"), str):
                return r["external_id"], r.get("url") if isinstance(r.get("url"), str) else None
    return None, None


def attack_url(eid: Any) -> str | None:
    """attack.mitre.org page of an id (T1059.001 -> /techniques/T1059/001/)."""
    n = normalise_attack_id(eid)
    if not n:
        return None
    if n.startswith("TA"):
        return f"https://attack.mitre.org/tactics/{n}/"
    if n.startswith("DET"):
        return f"https://attack.mitre.org/detectionstrategies/{n}/"
    if n[:2] in ("AN", "DS", "DC"):
        return None
    base = {"T": "techniques", "G": "groups", "S": "software", "C": "campaigns", "M": "mitigations"}.get(n[0])
    return f"https://attack.mitre.org/{base}/{n.replace('.', '/')}/" if base else None


def attack_section(eid: Any) -> str | None:
    n = normalise_attack_id(eid)
    if not n:
        return None
    if n.startswith("TA"):
        return "tactics"
    if n.startswith("DET"):
        return "detections"
    if n[:2] in ("AN", "DS", "DC"):
        return None
    return {"T": "techniques", "G": "groups", "S": "software", "C": "campaigns", "M": "mitigations"}.get(n[0])


def _version_key(v: Any) -> tuple[int, ...]:
    parts = re.findall(r"\d+", str(v))
    return tuple(int(p) for p in parts) if parts else (0,)


def newer_attack_version(local: Any, remote: Any) -> bool:
    """True when ``remote`` is a newer ATT&CK release than ``local`` (FC3 update check)."""
    if not remote:
        return False
    if not local:
        return True
    return _version_key(remote) > _version_key(local)


# ======================================================================================
# Compact index builder (FC1, FC4-FC7)
# ======================================================================================

_INDEXED = {"attack-pattern": "techniques", "intrusion-set": "groups", "malware": "software", "tool": "software", "campaign": "campaigns",
            "course-of-action": "mitigations", "x-mitre-detection-strategy": "detections", "x-mitre-analytic": "analytics"}
SECTIONS = ("techniques", "groups", "software", "campaigns", "mitigations", "detections")
_LIST_FIELDS = ("groups", "software", "mitigations", "detections", "campaigns", "techniques", "analytics")


def _domains_of(o: Mapping[str, Any]) -> list[str]:
    d = o.get("x_mitre_domains")
    return [x for x in d if isinstance(x, str)] if isinstance(d, list) else []


def _strs(value: Any) -> list[str]:
    return [x for x in value if isinstance(x, str)] if isinstance(value, list) else []


def build_attack_index(objects: Iterable[Any], *, built: str | None = None) -> dict[str, Any]:
    """Compact index from STIX objects (any iterable: e.g. :func:`iter_bundle_objects`). Never raises on odd
    objects (they are skipped). Ids are keyed per object type, so the deprecated course-of-action 'T1078'
    never shadows technique T1078; techniques resolve tactics through their kill_chain_name per domain."""
    recs: dict[str, dict[str, Any]] = {}
    rels: list[tuple[str, str, str, bool]] = []
    tactics: dict[str, dict[str, Any]] = {}
    matrices: list[dict[str, Any]] = []
    collections: dict[str, dict[str, Any]] = {}
    notice = None
    spec = None
    for o in objects:
        if not isinstance(o, dict):
            continue
        t, sid = o.get("type"), o.get("id")
        if not isinstance(t, str) or not isinstance(sid, str):
            continue
        if t == "relationship":
            rt, s, d = o.get("relationship_type"), o.get("source_ref"), o.get("target_ref")
            if isinstance(rt, str) and isinstance(s, str) and isinstance(d, str):
                rels.append((rt, s, d, bool(o.get("revoked") or o.get("x_mitre_deprecated"))))
            continue
        if t == "x-mitre-collection":
            dom = COLLECTION_DOMAIN.get(str(o.get("name", "")).lower()) or str(o.get("name") or "")
            if dom:
                collections[dom] = {"name": o.get("name"), "version": o.get("x_mitre_version"), "modified": o.get("modified"), "id": sid}
            spec = o.get("x_mitre_attack_spec_version") or spec
            continue
        if t == "marking-definition":
            definition = o.get("definition")
            stmt = definition.get("statement") if isinstance(definition, dict) else None
            if isinstance(stmt, str):
                notice = stmt
            continue
        if t == "x-mitre-matrix":
            matrices.append({"domains": _domains_of(o), "tactic_refs": _strs(o.get("tactic_refs")), "live": not (o.get("revoked") or o.get("x_mitre_deprecated"))})
            continue
        eid, _url = stix_external_id(o)
        if t == "x-mitre-tactic":
            tactics[sid] = {"id": eid, "shortname": o.get("x_mitre_shortname"), "name": o.get("name"), "domains": _domains_of(o), "stix_id": sid,
                            "live": not (o.get("revoked") or o.get("x_mitre_deprecated"))}
            continue
        if t not in _INDEXED:
            continue
        r = recs.get(sid)
        if r is None:
            r = {"type": t, "eid": eid, "name": o.get("name") if isinstance(o.get("name"), str) else eid, "stix_id": sid, "domains": set(),
                 "revoked": bool(o.get("revoked")), "deprecated": bool(o.get("x_mitre_deprecated"))}
            if t == "attack-pattern":
                r["phases"] = [(p.get("kill_chain_name"), p.get("phase_name")) for p in o.get("kill_chain_phases") or [] if isinstance(p, dict)]
                r["platforms"] = _strs(o.get("x_mitre_platforms"))
                r["is_sub"] = bool(o.get("x_mitre_is_subtechnique"))
            elif t in ("intrusion-set", "campaign"):
                r["aliases"] = _strs(o.get("aliases"))
                if t == "campaign":
                    r["first_seen"], r["last_seen"] = o.get("first_seen"), o.get("last_seen")
            elif t in ("malware", "tool"):
                r["aliases"] = _strs(o.get("x_mitre_aliases"))
                r["platforms"] = _strs(o.get("x_mitre_platforms"))
            elif t == "x-mitre-detection-strategy":
                r["analytic_refs"] = _strs(o.get("x_mitre_analytic_refs"))
            recs[sid] = r
        r["domains"].update(_domains_of(o))
    # tactic order per domain, from the matrices (FC4: names and order come from the data)
    order: dict[str, list[dict[str, Any]]] = {}
    for m in matrices:
        if not m["live"]:
            continue
        for tr in m["tactic_refs"]:
            ta = tactics.get(tr)
            if not ta or not ta["live"] or not ta["id"]:
                continue
            for dom in m["domains"] or ta["domains"]:
                lst = order.setdefault(dom, [])
                if ta["id"] not in [x["id"] for x in lst]:
                    lst.append({"id": ta["id"], "shortname": ta["shortname"], "name": ta["name"], "stix_id": ta["stix_id"]})
    by_short = {(dom, ta["shortname"]): ta for dom, lst in order.items() for ta in lst}
    live = {sid: r for sid, r in recs.items() if r["eid"] and not r["revoked"] and not r["deprecated"]}
    sid2eid = {sid: r["eid"] for sid, r in recs.items() if r["eid"]}
    nxt = {s: d for rt, s, d, _dead in rels if rt == "revoked-by" and s in recs and d in recs}
    revoked_by: dict[str, str] = {}
    for s in nxt:
        cur, seen = s, set()
        while cur in nxt and cur not in seen:
            seen.add(cur)
            cur = nxt[cur]
        if cur in live and recs[s]["eid"] and recs[s]["eid"] != live[cur]["eid"]:
            revoked_by[recs[s]["eid"]] = live[cur]["eid"]
    live_eids = {x["eid"] for x in live.values()}
    deprecated = sorted({r["eid"] for r in recs.values() if r["eid"] and r["deprecated"] and not r["revoked"] and r["eid"] not in live_eids})
    idx: dict[str, dict[str, dict[str, Any]]] = {s: {} for s in SECTIONS}
    for sid, r in live.items():
        sect = _INDEXED[r["type"]]
        if sect == "analytics":
            continue
        e: dict[str, Any] = {"name": r["name"], "stix_id": sid, "domains": sorted(r["domains"])}
        if sect == "techniques":
            names: list[str] = []
            shorts: list[str] = []
            for kc, ph in r.get("phases", []):
                ta = by_short.get((KILL_CHAIN_DOMAIN.get(kc), ph))
                if ta and ta["shortname"] not in shorts:
                    shorts.append(ta["shortname"])
                    names.append(ta["name"])
            e.update({"tactics": shorts, "tactic_names": names, "platforms": r.get("platforms", []), "is_subtechnique": r.get("is_sub", False),
                      "parent": None, "groups": [], "software": [], "mitigations": [], "detections": [], "campaigns": []})
        elif sect == "groups":
            e.update({"aliases": r.get("aliases", []), "techniques": [], "software": [], "campaigns": []})
        elif sect == "software":
            e.update({"kind": r["type"], "aliases": r.get("aliases", []), "platforms": r.get("platforms", []), "techniques": [], "groups": []})
        elif sect == "campaigns":
            e.update({"aliases": r.get("aliases", []), "first_seen": r.get("first_seen"), "last_seen": r.get("last_seen"), "groups": [], "techniques": [], "software": []})
        elif sect == "detections":
            e.update({"techniques": [], "analytics": sorted({sid2eid[a] for a in r.get("analytic_refs", []) if a in sid2eid})})
        idx[sect][r["eid"]] = e

    def link(sect: str, key: str, fld: str, val: str) -> None:
        ent = idx[sect].get(key)
        if ent is not None and val not in ent[fld]:
            ent[fld].append(val)

    for rt, s, d, dead in rels:
        if dead or s not in live or d not in live:
            continue
        a, b = live[s], live[d]
        sa, sb = _INDEXED[a["type"]], _INDEXED[b["type"]]
        ea, eb = a["eid"], b["eid"]
        if rt == "uses":
            if sa == "groups" and sb == "techniques":
                link("groups", ea, "techniques", eb)
                link("techniques", eb, "groups", ea)
            elif sa == "groups" and sb == "software":
                link("groups", ea, "software", eb)
                link("software", eb, "groups", ea)
            elif sa == "software" and sb == "techniques":
                link("software", ea, "techniques", eb)
                link("techniques", eb, "software", ea)
            elif sa == "campaigns" and sb in ("techniques", "software"):
                link("campaigns", ea, sb, eb)
                if sb == "techniques":
                    link("techniques", eb, "campaigns", ea)
        elif rt == "attributed-to" and sa == "campaigns" and sb == "groups":
            link("campaigns", ea, "groups", eb)
            link("groups", eb, "campaigns", ea)
        elif rt == "mitigates" and sa == "mitigations" and sb == "techniques":
            link("techniques", eb, "mitigations", ea)
        elif rt == "subtechnique-of" and sa == "techniques" and sb == "techniques":
            if ea in idx["techniques"]:
                idx["techniques"][ea]["parent"] = eb
        elif rt == "detects" and sa == "detections" and sb == "techniques":
            link("techniques", eb, "detections", ea)
            link("detections", ea, "techniques", eb)
    for sect in idx.values():
        for e in sect.values():
            for fld in _LIST_FIELDS:
                if isinstance(e.get(fld), list):
                    e[fld].sort()
    versions = {k: v.get("version") for k, v in collections.items() if k}
    year = None
    if isinstance(notice, str):
        years = re.findall(r"(?:19|20)\d{2}", notice)
        year = max(int(y) for y in years) if years else None
    if year is None and isinstance(built, str) and built[:4].isdigit():
        year = int(built[:4])
    meta = {
        "attack_versions": versions,
        "attack_version": max((v for v in versions.values() if v), key=_version_key, default=None),
        "attack_spec_version": spec, "collections": collections, "built": built, "notice": mitre_notice(year or 2026),
        "marking_statement": notice, "licence": MITRE_LICENCE, "source": STIX_REPO,
    }
    return {"_meta": meta, "tactics": order, "revoked_by": dict(sorted(revoked_by.items())), "deprecated": deprecated,
            "counts": {k: len(v) for k, v in idx.items()}, **idx}


def merge_indexes(parts: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Merge per-domain compact parts (software shared by several domains keeps one entry with the
    union of its edges and domains)."""
    out: dict[str, Any] = {"_meta": {"attack_versions": {}, "collections": {}, "built": None, "parts": []}, "tactics": {}, "revoked_by": {}, "deprecated": [],
                           **{s: {} for s in SECTIONS}}
    notice = None
    for part in parts:
        meta = part.get("_meta") or {}
        out["_meta"]["attack_versions"].update(meta.get("attack_versions") or {})
        out["_meta"]["collections"].update(meta.get("collections") or {})
        out["_meta"]["parts"].append({"versions": meta.get("attack_versions"), "built": meta.get("built")})
        built = meta.get("built")
        if built and (out["_meta"]["built"] is None or str(built) > str(out["_meta"]["built"])):
            out["_meta"]["built"] = built
        notice = notice or meta.get("notice")
        out["_meta"].setdefault("attack_spec_version", meta.get("attack_spec_version"))
        out["_meta"].setdefault("licence", meta.get("licence"))
        out["_meta"].setdefault("source", meta.get("source"))
        for dom, lst in (part.get("tactics") or {}).items():
            out["tactics"].setdefault(dom, lst)
        out["revoked_by"].update(part.get("revoked_by") or {})
        out["deprecated"] = sorted(set(out["deprecated"]) | set(part.get("deprecated") or []))
        for sect in SECTIONS:
            for eid, entry in (part.get(sect) or {}).items():
                cur = out[sect].get(eid)
                if cur is None:
                    out[sect][eid] = {k: (list(v) if isinstance(v, list) else v) for k, v in entry.items()}  # entries hold scalars and lists of str
                    continue
                cur["domains"] = sorted(set(cur.get("domains") or []) | set(entry.get("domains") or []))
                for fld in (*_LIST_FIELDS, "aliases", "platforms", "tactics", "tactic_names"):
                    if isinstance(entry.get(fld), list):
                        merged = list(cur.get(fld) or [])
                        merged += [v for v in entry[fld] if v not in merged]
                        cur[fld] = merged if fld in ("tactics", "tactic_names") else sorted(merged)
    live = {eid for sect in SECTIONS for eid in out[sect]}
    out["revoked_by"] = {k: v for k, v in sorted(out["revoked_by"].items()) if k not in live}
    out["deprecated"] = [d for d in out["deprecated"] if d not in live]
    versions = out["_meta"]["attack_versions"]
    out["_meta"]["attack_version"] = max((v for v in versions.values() if v), key=_version_key, default=None)
    out["_meta"]["notice"] = notice or mitre_notice()
    out["counts"] = {s: len(out[s]) for s in SECTIONS}
    return out


# ======================================================================================
# Cards and resolution (FC4, FC6, FC7)
# ======================================================================================

_MISP_GALAXY = {"techniques": "mitre-attack-pattern", "groups": "mitre-intrusion-set", "mitigations": "mitre-course-of-action", "campaigns": "mitre-campaign"}


def attack_card(index: Mapping[str, Any], eid: Any, max_related: int = MAX_RELATED) -> dict[str, Any] | None:
    """Card of a live ATT&CK object: name, tactics from the data, at most ``max_related`` related ids per
    kind (with totals), the attack.mitre.org link, the STIX id, the MISP galaxy tag and the notice."""
    n = normalise_attack_id(eid)
    sect = attack_section(n) if n else None
    meta = index.get("_meta") or {}
    if sect == "tactics":
        for dom, lst in sorted((index.get("tactics") or {}).items()):
            for pos, ta in enumerate(lst):
                if ta.get("id") == n:
                    return {"id": n, "kind": "tactic", "name": ta.get("name"), "shortname": ta.get("shortname"), "domains": [dom], "order": pos + 1,
                            "url": attack_url(n), "stix_id": ta.get("stix_id"), "notice": meta.get("notice"), "attack_version": meta.get("attack_version")}
        return None
    ent = (index.get(sect) or {}).get(n) if sect else None
    if not ent:
        return None
    kind = sect[:-1] if sect != "software" else str(ent.get("kind") or "software")
    card: dict[str, Any] = {"id": n, "kind": kind, "name": ent.get("name"), "url": attack_url(n), "stix_id": ent.get("stix_id"), "domains": ent.get("domains", [])}
    for fld in ("tactics", "tactic_names", "platforms", "is_subtechnique", "parent", "aliases", "first_seen", "last_seen"):
        if fld in ent:
            card[fld] = ent[fld]
    for fld in ("groups", "software", "mitigations", "detections", "campaigns", "techniques"):
        if fld in ent:
            vals = ent[fld]
            card[fld] = vals[:max_related]
            card[fld + "_total"] = len(vals)
    card["misp_galaxy_tag"] = misp_galaxy_tag_for(sect, card)
    card["attribution_note"] = ATTRIBUTION_NOTE
    card["notice"] = meta.get("notice")
    card["attack_version"] = meta.get("attack_version")
    return card


def misp_galaxy_tag_for(sect: str | None, card: Mapping[str, Any]) -> str | None:
    """FC6: misp-galaxy:mitre-attack-pattern="PowerShell - T1059.001" (malware -> mitre-malware, tool -> mitre-tool)."""
    galaxy = _MISP_GALAXY.get(sect or "")
    if sect == "software":
        galaxy = "mitre-malware" if card.get("kind") == "malware" else "mitre-tool"
    if not galaxy or not card.get("name"):
        return None
    return f'misp-galaxy:{galaxy}="{card["name"]} - {card["id"]}"'


def stix_attack_reference(index: Mapping[str, Any], eid: Any) -> dict[str, Any] | None:
    """STIX 2.1 reference with the official ATT&CK STIX id (FC6: no regenerated ids)."""
    card = attack_card(index, eid)
    if not card or not isinstance(card.get("stix_id"), str):
        return None
    return {"type": card["stix_id"].split("--", 1)[0], "id": card["stix_id"], "name": card["name"],
            "external_references": [{"source_name": "mitre-attack", "external_id": card["id"], "url": card["url"]}]}


def resolve_attack_id(index: Mapping[str, Any], text: Any) -> dict[str, Any]:
    """Analyst-typed id -> {'query', 'id', 'status' ok|revoked|deprecated|unknown|invalid, 'replaced_by', 'display',
    'card', 'replacement'}. A revoked id is never silently rewritten: 'T1656 revoked -> replaced by T1684.001'."""
    n = normalise_attack_id(text)
    out: dict[str, Any] = {"query": text, "id": n, "status": "invalid", "replaced_by": None, "display": None, "card": None, "replacement": None}
    if not n:
        out["display"] = "not an ATT&CK id"
        return out
    card = attack_card(index, n)
    if card:
        out.update(status="ok", card=card, display=f"{n} {card['name']}")
        return out
    rb = (index.get("revoked_by") or {}).get(n)
    if rb:
        out.update(status="revoked", replaced_by=rb, display=f"{n} revoked -> replaced by {rb}", replacement=attack_card(index, rb))
        return out
    if n in set(index.get("deprecated") or []):
        out.update(status="deprecated", display=f"{n} deprecated in ATT&CK (no replacement)")
        return out
    out.update(status="unknown", display=f"{n} not in ATT&CK {(index.get('_meta') or {}).get('attack_version')}")
    return out


def attack_footer(index: Mapping[str, Any]) -> str:
    """Report footer / case record line: version per domain, build date and the MITRE notice (FC1, FC6)."""
    meta = index.get("_meta") or {}
    label = {"enterprise-attack": "Enterprise", "mobile-attack": "Mobile", "ics-attack": "ICS"}
    dom = ", ".join(f"{label.get(k, k)} {v}" for k, v in sorted((meta.get("attack_versions") or {}).items()) if v)
    return f"MITRE ATT&CK v{meta.get('attack_version')} ({dom}), index built {meta.get('built')}. {meta.get('notice')}"


_NAME_NORM = re.compile(r"[\s\-_‐-―]+")


def _norm_name(text: Any) -> str:
    return _NAME_NORM.sub("", str(text or "")).casefold()


def name_index(index: Mapping[str, Any]) -> dict[str, list[tuple[str, str]]]:
    """Normalised group/software/campaign names and aliases -> [(section, id)]."""
    out: dict[str, list[tuple[str, str]]] = {}
    for sect in ("groups", "software", "campaigns"):
        for eid, ent in (index.get(sect) or {}).items():
            for name in [ent.get("name"), *(ent.get("aliases") or [])]:
                key = _norm_name(name)
                if len(key) >= 3 and (sect, eid) not in out.get(key, []):
                    out.setdefault(key, []).append((sect, eid))
    return out


# ======================================================================================
# CAPEC (optional, FC1/FC7: low confidence)
# ======================================================================================


def parse_capec_objects(objects: Iterable[Any]) -> dict[str, Any]:
    """CAPEC STIX objects -> {'patterns': {'CAPEC-98': {...}}, 'notice', 'version'}: name, status, CWE ids, ATT&CK
    technique ids (source_name 'ATTACK'), likelihood, severity; deprecated/obsolete patterns kept but flagged."""
    patterns: dict[str, dict[str, Any]] = {}
    notice = None
    version = None
    for o in objects or []:
        if not isinstance(o, dict):
            continue
        if o.get("type") == "marking-definition":
            d = o.get("definition")
            if isinstance(d, dict) and isinstance(d.get("statement"), str):
                notice = d["statement"]
            continue
        if o.get("type") != "attack-pattern":
            continue
        cid = None
        cwe: list[str] = []
        att: list[str] = []
        for r in o.get("external_references") or []:
            if not isinstance(r, dict) or not isinstance(r.get("external_id"), str):
                continue
            sn = r.get("source_name")
            if sn == "capec":
                cid = r["external_id"]
            elif sn == "cwe":
                cwe.append(r["external_id"].upper())
            elif sn == "ATTACK":
                tid = normalise_attack_id(r["external_id"])
                if tid and tid.startswith("T") and not tid.startswith("TA"):
                    att.append(tid)
        if not cid:
            continue
        status = o.get("x_capec_status")
        version = o.get("x_capec_version") or version
        patterns[cid] = {"name": o.get("name"), "status": status, "deprecated": status in ("Deprecated", "Obsolete"), "cwe": sorted(set(cwe)),
                         "attack": sorted(set(att)), "likelihood": o.get("x_capec_likelihood_of_attack"), "severity": o.get("x_capec_typical_severity")}
    return {"patterns": patterns, "notice": notice, "version": version}


def capec_for_technique(capec: Mapping[str, Any] | None, index: Mapping[str, Any], tid: str) -> list[dict[str, Any]]:
    """CAPEC patterns citing ``tid`` (directly or through a revoked id that now maps to it): low confidence."""
    out = []
    rb = index.get("revoked_by") or {}
    for cid, p in sorted(((capec or {}).get("patterns") or {}).items()):
        if p.get("deprecated"):
            continue
        hits = [t for t in p.get("attack") or [] if t == tid or rb.get(t) == tid]
        if hits:
            out.append({"capec": cid, "name": p.get("name"), "cwe": p.get("cwe", [])[:10], "via": hits, "confidence": "low"})
    return out


def cwe_attack_candidates(capec: Mapping[str, Any] | None, index: Mapping[str, Any], cwe: Any) -> list[dict[str, Any]]:
    """CWE -> CAPEC -> ATT&CK candidate techniques, always confidence 'low' (FC7). Revoked targets are shown
    with their replacement, unknown ids are kept as 'unknown' (CAPEC 3.9 cites ids revoked in ATT&CK v20.1)."""
    want = str(cwe or "").strip().upper()
    if not re.fullmatch(r"CWE-\d+", want):
        m = re.fullmatch(r"(\d+)", want)
        want = f"CWE-{m.group(1)}" if m else want
    out = []
    for cid, p in sorted(((capec or {}).get("patterns") or {}).items()):
        if want not in (p.get("cwe") or []) or p.get("deprecated"):
            continue
        for tid in p.get("attack") or []:
            r = resolve_attack_id(index, tid)
            out.append({"technique": tid, "via": cid, "capec_name": p.get("name"), "confidence": "low", "status": r["status"],
                        "replaced_by": r.get("replaced_by"), "display": r["display"], "note": "CWE -> CAPEC -> ATT&CK link: low confidence, context only"})
    return out


# ======================================================================================
# Version check: attack-stix-data index.json and TAXII discovery (FC3)
# ======================================================================================


def _json_body(raw: Any) -> tuple[Any, str | None]:
    if isinstance(raw, (dict, list)):
        return raw, None
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("utf-8", errors="replace")
    if not isinstance(raw, str) or not raw.strip():
        return None, "error: empty body"
    if raw.lstrip()[:1] == "<":
        return None, "error: HTML instead of JSON"
    try:
        return json.loads(raw), None
    except (ValueError, RecursionError) as exc:
        return None, f"error: malformed JSON ({str(exc)[:80]})"


def parse_stix_index_json(raw: Any) -> dict[str, Any]:
    """attack-stix-data index.json -> {'collections': [{'name', 'id', 'domain', 'latest', 'versions'}], 'marker'}."""
    obj, marker = _json_body(raw)
    out: dict[str, Any] = {"collections": [], "marker": marker}
    if marker:
        return out
    cols = obj.get("collections") if isinstance(obj, dict) else None
    if not isinstance(cols, list):
        out["marker"] = "error: index.json without 'collections'"
        return out
    for c in cols:
        if not isinstance(c, dict):
            continue
        vers = [v for v in c.get("versions") or [] if isinstance(v, dict) and v.get("version")]
        vers.sort(key=lambda v: _version_key(v.get("version")), reverse=True)
        name = c.get("name")
        out["collections"].append({"name": name, "id": c.get("id"), "domain": COLLECTION_DOMAIN.get(str(name).lower()),
                                   "latest": {k: vers[0].get(k) for k in ("version", "url", "modified")} if vers else None,
                                   "versions": [v.get("version") for v in vers]})
    return out


def taxii_error_marker(status: Any, obj: Any) -> str | None:
    """TAXII 2.1 error message -> marker. Seen live: 400 'Unsupported Media SubType' when Accept is not
    application/taxii+json;version=2.1 (also for */*), 404 'Collection Not Found'."""
    if isinstance(obj, dict) and "title" in obj and ("http_status" in obj or "error_id" in obj):
        code = obj.get("http_status") or status
        try:
            code = int(code)
        except (TypeError, ValueError):
            code = status
        title = str(obj.get("title"))[:80]
        if code == 404:
            return f"unavailable: TAXII 404 {title}"
        if code == 429:
            return f"rate_limited: TAXII 429 {title}"
        if code in (401, 403):
            return f"blocked: TAXII {code} {title}"
        hint = f" (send Accept: {TAXII_ACCEPT})" if "media" in title.lower() else ""
        return f"error: TAXII {code} {title}{hint}"
    if isinstance(status, int) and status >= 400:
        return f"error: TAXII HTTP {status}"
    return None


def parse_taxii_discovery(raw: Any, status: int | None = None) -> dict[str, Any]:
    """TAXII discovery (/taxii2/) -> {'title', 'default', 'api_roots', 'versions', 'latest', 'marker'}: one API root per
    ATT&CK release ('/api/v21/attack-20.1'), so the latest release is known without the 55 MB bundle."""
    obj, marker = _json_body(raw)
    out: dict[str, Any] = {"title": None, "default": None, "api_roots": [], "versions": [], "latest": None, "marker": marker}
    if marker:
        return out
    err = taxii_error_marker(status, obj)
    if err or not isinstance(obj, dict):
        out["marker"] = err or "error: discovery document is not an object"
        return out
    roots = [r for r in obj.get("api_roots") or [] if isinstance(r, str)]
    vers = sorted({m.group(1) for r in roots if (m := re.search(r"attack-(\d+(?:\.\d+)*)$", r))}, key=_version_key)
    out.update(title=obj.get("title"), default=obj.get("default"), api_roots=roots, versions=vers, latest=vers[-1] if vers else None)
    return out


def parse_taxii_collections(raw: Any, status: int | None = None) -> dict[str, Any]:
    """/api/v21/collections/ -> {'collections': [{'id', 'title', 'domain', 'can_read'}], 'marker'}."""
    obj, marker = _json_body(raw)
    out: dict[str, Any] = {"collections": [], "marker": marker}
    if marker:
        return out
    err = taxii_error_marker(status, obj)
    if err:
        out["marker"] = err
        return out
    for c in (obj.get("collections") if isinstance(obj, dict) else None) or []:
        if isinstance(c, dict) and isinstance(c.get("id"), str):
            out["collections"].append({"id": c["id"], "title": c.get("title"), "domain": COLLECTION_DOMAIN.get(str(c.get("title")).lower()), "can_read": bool(c.get("can_read"))})
    return out


def parse_taxii_envelope(raw: Any, status: int | None = None) -> dict[str, Any]:
    """TAXII envelope -> {'objects', 'more', 'next', 'collection_version', 'marker'} (paginate with more/next)."""
    obj, marker = _json_body(raw)
    out: dict[str, Any] = {"objects": [], "more": False, "next": None, "collection_version": None, "marker": marker}
    if marker:
        return out
    err = taxii_error_marker(status, obj)
    if err:
        out["marker"] = err
        return out
    objs = obj.get("objects") if isinstance(obj, dict) else None
    out["objects"] = [o for o in objs if isinstance(o, dict)] if isinstance(objs, list) else []
    out["more"] = bool(obj.get("more")) if isinstance(obj, dict) else False
    out["next"] = obj.get("next") if isinstance(obj, dict) and isinstance(obj.get("next"), str) else None
    for o in out["objects"]:
        if o.get("type") == "x-mitre-collection":
            out["collection_version"] = {"name": o.get("name"), "version": o.get("x_mitre_version"), "modified": o.get("modified"), "id": o.get("id")}
    return out


def taxii_version_check(get_json: Callable[[str, dict[str, str]], Any], local_version: Any) -> dict[str, Any]:
    """FC3 update check for a core caller (doctor / `v3lum data update`): ``get_json(url, headers)`` fetches the
    TAXII discovery document with the TAXII Accept header. Returns {'latest', 'newer', 'marker'}."""
    try:
        doc = get_json(f"{TAXII_ROOT}/taxii2/", {"Accept": TAXII_ACCEPT})
    except Exception as exc:  # noqa: BLE001 - the caller's transport errors are 'could not verify'
        return {"latest": None, "newer": False, "marker": f"error: {type(exc).__name__}: could not verify"}
    parsed = parse_taxii_discovery(doc)
    return {"latest": parsed["latest"], "newer": newer_attack_version(local_version, parsed["latest"]), "marker": parsed["marker"]}


# ======================================================================================
# Index persistence: compact parts built at update time (validate hooks), kept in ctx.state
# ======================================================================================


def _encode_part(part: Mapping[str, Any]) -> str:
    raw = json.dumps(part, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
    return base64.b64encode(gzip.compress(raw, compresslevel=9, mtime=0)).decode("ascii")


def _decode_part(blob: str) -> dict[str, Any]:
    return json.loads(gzip.decompress(base64.b64decode(blob.encode("ascii"))).decode("utf-8"))


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_part_from_file(path: Path, *, built: str | None = None) -> dict[str, Any]:
    """Stream one downloaded STIX bundle into its compact part (bounded memory). Raises StixStreamError."""
    meta: dict[str, Any] = {}
    with Path(path).open("rb") as fh:
        index = build_attack_index(iter_bundle_objects(fh, meta=meta), built=built or time.strftime("%Y-%m-%d", time.gmtime()))
    if meta.get("type") not in (None, "bundle") or not meta.get("_objects_found"):
        raise StixStreamError("not a STIX bundle (no 'objects' array)")
    if not any(index["counts"].values()):
        raise StixStreamError("no ATT&CK objects in the bundle")
    return index


def _state() -> ModuleState:
    return ModuleState(MODULE_NAME)


def store_part(name: str, part: Mapping[str, Any], sha256: str, *, state: ModuleState | None = None) -> None:
    (state or _state()).set(f"{STATE_PREFIX}{name}", {"sha256": sha256, "format": STATE_FORMAT, "built": (part.get("_meta") or {}).get("built"), "data": _encode_part(part)})


def _bundle_validator(name: str, domain: str):
    def validate(path: Path) -> bool:
        """Dataset hook (runs at update time, never during a scan): stream-parse the downloaded bundle and keep
        its compact part, keyed by the file's SHA-256, in this module's state."""
        part = build_part_from_file(path)
        if domain not in (part["_meta"].get("attack_versions") or {}):
            raise StixStreamError(f"bundle has no {domain} x-mitre-collection (got {sorted(part['_meta'].get('attack_versions') or {})})")
        store_part(name, part, _sha256_file(path))
        return True

    validate.__name__ = f"build_attack_part_{name.replace('.', '_')}"
    return validate


def _capec_validator(path: Path) -> bool:
    with Path(path).open("rb") as fh:
        capec = parse_capec_objects(iter_bundle_objects(fh))
    if len(capec["patterns"]) < 50:
        raise StixStreamError(f"only {len(capec['patterns'])} CAPEC patterns")
    store_part(CAPEC_DATASET, capec, _sha256_file(path))
    return True


def _versions_validator(path: Path) -> bool:
    parsed = parse_stix_index_json(Path(path).read_bytes())
    if parsed["marker"] or not parsed["collections"]:
        raise ValueError(parsed["marker"] or "index.json lists no collection")
    return True


def register_datasets() -> list[str]:
    names = []
    for name, domain in DATASET_DOMAINS.items():
        if name not in DATASETS:
            register_dataset(
                name, BUNDLE_URL.format(domain=domain), ttl=REFRESH_TTL,
                description=f"MITRE ATT&CK {domain} STIX 2.1 bundle (compact index built at update time)",
                licence="MITRE ATT&CK Terms of Use (royalty-free, notice and licence reproduced)", terms_class="open",
                attribution=mitre_notice(), provider="github", source=SOURCE, validate=_bundle_validator(name, domain),
                min_bytes=100_000, expect="bytes", large=True, essential=True,
            )
        names.append(name)
    if CAPEC_DATASET not in DATASETS:
        register_dataset(
            CAPEC_DATASET, CAPEC_URL, ttl=30 * 86400, description="MITRE CAPEC 2.1 STIX bundle (optional CWE -> CAPEC -> ATT&CK links, low confidence)",
            licence="CAPEC Terms of Use (royalty-free, notice and licence reproduced)", terms_class="open",
            attribution="CAPEC: Copyright The MITRE Corporation.", provider="github", source=SOURCE_CAPEC, validate=_capec_validator,
            min_bytes=100_000, expect="bytes", large=True,
        )
    names.append(CAPEC_DATASET)
    if VERSIONS_DATASET not in DATASETS:
        register_dataset(
            VERSIONS_DATASET, INDEX_JSON_URL, ttl=REFRESH_TTL, description="attack-stix-data index.json (ATT&CK release versions)",
            licence="MITRE ATT&CK Terms of Use (royalty-free, notice and licence reproduced)", terms_class="open", attribution=mitre_notice(),
            provider="github", source=SOURCE, validate=_versions_validator, min_bytes=200, expect="json", max_bytes=2_000_000,
        )
    names.append(VERSIONS_DATASET)
    return names


DATASET_NAMES = register_datasets()

_LOCK = threading.Lock()
_CACHE: dict[str, Any] = {"key": None, "index": None, "names": None, "capec": None}
#: (dataset, sha256) of local copies whose rebuild failed in this process (not retried on every lookup).
_FAILED_REBUILDS: set[tuple[str, str]] = set()


def _part_entries(state: Any) -> dict[str, dict[str, Any]]:
    out = {}
    try:
        values = state.all()
    except Exception:  # noqa: BLE001 - an unreadable state is 'not built'
        return {}
    for key, value in values.items():
        if key.startswith(STATE_PREFIX) and isinstance(value, dict) and value.get("format") == STATE_FORMAT and isinstance(value.get("data"), str):
            out[key[len(STATE_PREFIX):]] = value
    return out


def load_index(state: Any, installed: Mapping[str, str]) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, str]]:
    """(merged index or None, capec or None, problems {dataset: why}) from the stored parts whose SHA-256 still
    matches the installed dataset (``installed`` = {dataset: sha256}). Cached per process."""
    parts = _part_entries(state)
    problems: dict[str, str] = {}
    usable: dict[str, dict[str, Any]] = {}
    for name in DATASET_DOMAINS:
        sha = installed.get(name)
        entry = parts.get(name)
        if not sha:
            problems[name] = "not downloaded"
        elif not entry:
            problems[name] = "downloaded but no index built"
        elif entry.get("sha256") != sha:
            problems[name] = "index built for another copy"
        else:
            usable[name] = entry
    capec_entry = parts.get(CAPEC_DATASET)
    capec_ok = bool(capec_entry and installed.get(CAPEC_DATASET) and capec_entry.get("sha256") == installed.get(CAPEC_DATASET))
    key = (tuple(sorted((n, e["sha256"]) for n, e in usable.items())), capec_entry["sha256"] if capec_ok and capec_entry else "")
    with _LOCK:
        if _CACHE["key"] == key and _CACHE["index"] is not None:
            return _CACHE["index"], _CACHE["capec"], problems
    if not usable:
        return None, None, problems
    decoded = []
    for name, entry in sorted(usable.items()):
        try:
            decoded.append(_decode_part(entry["data"]))
        except (ValueError, OSError, EOFError) as exc:
            problems[name] = f"stored index unreadable ({type(exc).__name__})"
    if not decoded:
        return None, None, problems
    index = merge_indexes(decoded)
    capec = None
    if capec_ok and capec_entry:
        try:
            capec = _decode_part(capec_entry["data"])
        except (ValueError, OSError, EOFError):
            capec = None
    with _LOCK:
        _CACHE.update(key=key, index=index, names=name_index(index), capec=capec)
    return index, capec, problems


def names_for(index: Mapping[str, Any]) -> dict[str, list[tuple[str, str]]]:
    with _LOCK:
        if _CACHE["index"] is index and _CACHE["names"] is not None:
            return _CACHE["names"]
    return name_index(index)


def _drop_index() -> None:
    with _LOCK:
        _CACHE.update(key=None, index=None, names=None, capec=None)


def reset_cache() -> None:
    """Drop the process-wide index and the failed-rebuild memo (tests; a new local copy is picked up by its hash)."""
    _drop_index()
    with _LOCK:
        _FAILED_REBUILDS.clear()


# ======================================================================================
# The module
# ======================================================================================

CARD_TITLES = {
    "technique": "MITRE ATT&CK technique card", "tactic": "MITRE ATT&CK tactic card", "group": "MITRE ATT&CK group card",
    "malware": "MITRE ATT&CK software card", "tool": "MITRE ATT&CK software card", "campaign": "MITRE ATT&CK campaign card",
    "mitigation": "MITRE ATT&CK mitigation card", "detection": "MITRE ATT&CK detection strategy card",
}


@register
class AttackIndex(Module):
    name = MODULE_NAME
    title = "MITRE ATT&CK index (techniques, groups, software)"
    description = (
        "Offline MITRE ATT&CK cards (Enterprise, Mobile, ICS) for a technique id or a group/software name: tactics from "
        "the data, related groups and software, mitigations, detection strategies, official STIX id and MISP galaxy tag."
    )
    category = "cti_framework"
    accepts = {T.MITRE, T.THREAT_ACTOR, T.MALWARE}
    produces = {T.MITRE, T.THREAT_ACTOR, T.MALWARE}
    tags = {"offline", "free"}
    reference = "https://attack.mitre.org/"
    notice = (
        "MITRE ATT&CK(R) and CAPEC(TM) data under the MITRE Terms of Use: " + mitre_notice() + " The index is built by "
        "`v3lum data update attack` (it is not bundled); 'uses' edges are context, never attribution evidence."
    )
    # ---- contract v2 declarations ---------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # offline: the dataset manager alone downloads the bundles (`v3lum data update`)
    hosts = ()
    sources = (SOURCE, SOURCE_CAPEC)
    expected_latency = 0.1  # lookups take microseconds; loading the stored index takes tens of ms
    max_pivots = 40
    default_enabled = True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        installed: dict[str, str] = {}
        for name in (*DATASET_DOMAINS, CAPEC_DATASET):
            try:
                info = ctx.data.info(name)
            except (DatasetError, OSError, ValueError):
                continue
            if info.present and info.sha256:
                installed[name] = info.sha256
        index, capec, problems = load_index(ctx.state, installed)
        stale = [n for n in problems if n in installed]
        if CAPEC_DATASET in installed and capec is None:
            stale.append(CAPEC_DATASET)
        stale = [n for n in stale if (n, installed[n]) not in _FAILED_REBUILDS]
        if stale and not _in_scan(ctx):
            index, capec, problems = self._rebuild(ctx, installed, stale)  # outside a scan only (FC3)
        if index is None:
            why = "; ".join(f"{n}: {p}" for n, p in sorted(problems.items()))
            return res.mark(Status.UNAVAILABLE, f"ATT&CK index not built ({why}): run v3lum data update attack attack.mobile attack.ics (or --essential)",
                            reason_code="dataset")
        self._cite(ctx, installed)
        missing = sorted(DATASET_DOMAINS[n] for n in problems)
        if entity.type is T.MITRE:
            return self._technique(res, entity, index, capec, missing)
        return self._named(res, entity, index, missing)

    # ---- helpers --------------------------------------------------------------------------
    @staticmethod
    def _cite(ctx: Any, installed: Mapping[str, str]) -> None:
        for name in installed:
            try:
                ctx.data.fetch(name, ttl=10**12)  # present copies: a citation, never a download
            except (DatasetError, OSError, ValueError):
                continue

    @staticmethod
    def _rebuild(ctx: Any, installed: Mapping[str, str], names: Iterable[str]) -> tuple[Any, Any, dict[str, str]]:
        """Rebuild missing or stale parts from the local copies (`v3lum run`, never during a scan): the update
        hook did not run (a 304 answer, a lost state file). A copy that fails is not retried in this process."""
        for name in names:
            try:
                path = Path(ctx.data.fetch(name, ttl=10**12))
                if name == CAPEC_DATASET:
                    with path.open("rb") as fh:
                        part = parse_capec_objects(iter_bundle_objects(fh))
                else:
                    part = build_part_from_file(path)
                store_part(name, part, _sha256_file(path), state=ctx.state)
            except (StixStreamError, DatasetError, OSError, StateError, ValueError):
                with _LOCK:
                    _FAILED_REBUILDS.add((name, installed.get(name, "")))
                continue
        _drop_index()
        return load_index(ctx.state, installed)

    def _common(self, res: ModuleResult, index: Mapping[str, Any], missing: list[str]) -> None:
        meta = index.get("_meta") or {}
        res.attr("attack_version", meta.get("attack_version"))
        res.attr("attack_index_built", {"built": meta.get("built"), "versions": meta.get("attack_versions"), "missing_domains": missing})
        res.attr("data_notices", [meta.get("notice") or mitre_notice(), MITRE_LICENCE])

    def _technique(self, res: ModuleResult, entity: Entity, index: Mapping[str, Any], capec: Mapping[str, Any] | None, missing: list[str]) -> ModuleResult:
        out = resolve_attack_id(index, entity.value)
        status = out["status"]
        if status in ("invalid", "unknown"):
            if missing:
                return res.mark(Status.UNAVAILABLE, f"{out['display']}; the {', '.join(missing)} index is not built: could not verify", reason_code="dataset")
            res.error = str(out["display"])
            return res.mark(Status.EMPTY)
        self._common(res, index, missing)
        res.attr("attack_status", status)
        if status == "revoked":
            rb = out["replaced_by"]
            res.attr("attack_replaced_by", rb)
            res.finding(
                "ATT&CK id revoked",
                "info",
                f"{out['display']}: the id is kept as typed (never rewritten silently); the replacement card follows.",
                confidence="confirmed",
                data={"id": out["id"], "replaced_by": rb},
                tags=["info"],
                source=SOURCE,
            )
            res.pivot(T.MITRE, rb, "replaced_by", confidence="confirmed", expand=True)
            if out["replacement"]:
                res.link(f"ATT&CK {rb}", out["replacement"]["url"])
            return res
        if status == "deprecated":
            res.finding("ATT&CK id deprecated", "info", str(out["display"]), confidence="confirmed", data={"id": out["id"]}, tags=["info"], source=SOURCE)
            return res
        self._card(res, out["card"], index)
        if out["card"]["kind"] == "technique" and capec:
            related = capec_for_technique(capec, index, out["card"]["id"])
            if related:
                res.attr("capec_patterns", related[:MAX_RELATED])
        return res

    def _named(self, res: ModuleResult, entity: Entity, index: Mapping[str, Any], missing: list[str]) -> ModuleResult:
        want = "groups" if entity.type is T.THREAT_ACTOR else "software"
        ids: list[str] = []
        direct = normalise_attack_id(entity.value)
        if direct and attack_section(direct) in (want, "campaigns"):
            ids = [direct]
        if not ids:
            names = names_for(index)
            ids = sorted({eid for sect, eid in names.get(_norm_name(entity.value), []) if sect in (want, "campaigns" if want == "groups" else want)})
        how = "ATT&CK names and aliases"
        if not ids:
            from v3lum.modules.cti_framework import actor_alias_index  # the P295 hand-off (offline)

            ns = "actor" if want == "groups" else "malware"
            ids = [i for i in actor_alias_index.mitre_ids_for(entity.value, ns) if attack_section(i) in (want, "campaigns")]
            how = "the actor/malware alias index (P295)"
        cards = [c for c in (attack_card(index, i) for i in ids[:3]) if c]
        if not cards:
            revoked = [i for i in ids if (index.get("revoked_by") or {}).get(i)]
            if revoked:
                ids = [index["revoked_by"][revoked[0]]]
                cards = [c for c in (attack_card(index, i) for i in ids) if c]
        if not cards:
            if missing:
                return res.mark(Status.UNAVAILABLE, f"no ATT&CK {want[:-1] if want == 'groups' else want} named '{entity.value}' in the loaded domains; the "
                                f"{', '.join(missing)} index is not built: could not verify", reason_code="dataset")
            return res.mark(Status.EMPTY)
        self._common(res, index, missing)
        res.attr("attack_status", "ok")
        if len(cards) > 1:
            res.attr("attack_alternatives", [f"{c['id']} {c['name']}" for c in cards])
        for card in cards:
            self._card(res, card, index, matched_by=how)
        return res

    def _card(self, res: ModuleResult, card: Mapping[str, Any], index: Mapping[str, Any], *, matched_by: str = "") -> None:
        kind = card["kind"]
        res.attr("attack_id", card["id"])
        res.attr("attack_name", card["name"])
        res.attr("attack_kind", kind)
        res.attr("attack_url", card.get("url"))
        res.attr("stix_id", card.get("stix_id"))
        res.attr("misp_galaxy_tag", card.get("misp_galaxy_tag"))
        res.attr("attack_domains", card.get("domains"))
        if card.get("tactics") is not None and kind == "technique":
            res.attr("attack_tactics", [{"shortname": s, "name": n} for s, n in zip(card.get("tactics") or [], card.get("tactic_names") or [])])
        res.attr("attack_platforms", card.get("platforms"))
        res.attr("attack_aliases", card.get("aliases"))
        if card.get("parent"):
            res.attr("attack_parent", card["parent"])
        totals = {f: card[f + "_total"] for f in ("groups", "software", "mitigations", "detections", "campaigns", "techniques") if f + "_total" in card}
        if totals:
            res.attr("attack_related_totals", totals)

        def named(sect: str, ids: Iterable[str]) -> list[dict[str, str]]:
            table = index.get(sect) or {}
            return [{"id": i, "name": str((table.get(i) or {}).get("name") or i)} for i in ids]

        groups = named("groups", card.get("groups") or [])
        software = named("software", card.get("software") or [])
        res.attr("attack_groups", groups)
        res.attr("attack_software", software)
        res.attr("attack_mitigations", named("mitigations", card.get("mitigations") or []))
        res.attr("attack_detections", named("detections", card.get("detections") or []))
        res.attr("attack_campaigns", named("campaigns", card.get("campaigns") or []))
        if kind in ("group", "malware", "tool", "campaign"):
            res.attr("attack_techniques", list(card.get("techniques") or []))
        if card.get("url"):
            res.link(f"ATT&CK {card['id']}", card["url"])
        tactics = ", ".join(card.get("tactic_names") or []) or "-"
        parts = [f"{card['id']} {card['name']}"]
        if kind == "technique":
            parts.append(f"tactics (from ATT&CK {card.get('attack_version')}): {tactics}")
        for label, fld in (("groups", "groups"), ("software", "software"), ("techniques", "techniques"), ("mitigations", "mitigations")):
            if fld + "_total" in card:
                parts.append(f"{card[fld + '_total']} {label}")
        desc = "; ".join(parts) + f". {ATTRIBUTION_NOTE}" + (f" Matched through {matched_by}." if matched_by else "") + f" {card.get('notice') or ''}"
        res.finding(
            CARD_TITLES.get(kind, "MITRE ATT&CK card"),
            "info",
            desc.strip(),
            confidence="confirmed" if not matched_by or matched_by.startswith("ATT&CK") else "probable",
            data={"id": card["id"], "stix_id": card.get("stix_id"), "misp_galaxy_tag": card.get("misp_galaxy_tag"), "attack_version": card.get("attack_version")},
            tags=["info"],
            source=SOURCE,
            key=card["id"],
        )
        # 'uses' edges are context, never attribution (FC7): listed, never expanded automatically
        if kind == "technique":
            for g in groups:
                res.pivot(T.THREAT_ACTOR, g["name"], "used_by", confidence="possible", expand=False, note=f"ATT&CK {g['id']} (context, not attribution)")
            for s in software:
                res.pivot(T.MALWARE, s["name"], "used_by", confidence="possible", expand=False, note=f"ATT&CK {s['id']} (context, not attribution)")
        elif kind in ("group", "malware", "tool", "campaign"):
            for tid in (card.get("techniques") or [])[:MAX_RELATED]:
                res.pivot(T.MITRE, tid, "uses_technique", confidence="possible", expand=False, note="ATT&CK 'uses' edge (context)")
            if kind in ("group", "campaign"):
                for s in software:
                    res.pivot(T.MALWARE, s["name"], "uses_software", confidence="possible", expand=False, note=f"ATT&CK {s['id']} (context, not attribution)")
            else:
                for g in groups:
                    res.pivot(T.THREAT_ACTOR, g["name"], "used_by", confidence="possible", expand=False, note=f"ATT&CK {g['id']} (context, not attribution)")


def _in_scan(ctx: Any) -> bool:
    runtime = getattr(getattr(ctx, "data", None), "runtime", None)
    return bool(getattr(runtime, "in_scan", False))


def index_from_bundles(paths_: Iterable[Path], *, built: str | None = None) -> dict[str, Any]:
    """Build the merged index straight from local bundle files (tools, tests, the slow memory test)."""
    return merge_indexes(build_part_from_file(Path(p), built=built) for p in paths_)


__all__ = [
    "AttackIndex", "StixStreamError", "attack_card", "attack_footer", "attack_url", "build_attack_index", "capec_for_technique",
    "cwe_attack_candidates", "iter_bundle_objects", "merge_indexes", "misp_galaxy_tag_for", "newer_attack_version", "normalise_attack_id",
    "parse_capec_objects", "parse_stix_index_json", "parse_taxii_collections", "parse_taxii_discovery", "parse_taxii_envelope",
    "resolve_attack_id", "stix_attack_reference", "taxii_version_check",
]
