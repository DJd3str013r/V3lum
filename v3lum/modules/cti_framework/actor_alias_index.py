"""actor_alias_index: threat-actor / malware alias index with provenance per edge (P295).

Batch p1-G11-1. Offline lookup (disclosure 'none'): the typed name never leaves the machine. Final
conditions (FC) of P295 and where they are met:

* **FC1 sources (legal floor).** Bundled: the MISP galaxy clusters (dual CC0-1.0 / BSD-2-Clause, notices
  kept; MITRE-derived clusters keep the ATT&CK notice) and the Microsoft threat actor naming map (CC BY 4.0,
  attributed 'Microsoft Threat Intelligence'), as a trimmed build in
  ``v3lum/data/actor_alias_index/alias_sources.json.gz`` made by the builder of this file (``python -m
  v3lum.modules.cti_framework.actor_alias_index build``; cluster ``authors`` are never kept). ETDA/ThaiCERT
  Threat Group Cards have no licence: never bundled or redistributed.
* **FC2 ETDA.** Its terms class is 'unknown' (provider ``etda``) until legal records it: no dataset is
  registered, nothing is fetched and the source is not declared, so ``terms`` stays 'open'. The parser
  (:func:`parse_etda_export`) is ready and tested on a synthetic fixture with the real export structure;
  card links use ``?u={uuid}`` (FC7).
* **FC3 optional sources.** APTmap (CC BY 4.0, GitHub Pages; the raw 'main' path is 404) is outside the
  default update set (not registered: the dataset manager has no optional flag yet) and CyCat stays
  excluded (keyword sent to a third party: chair decision); both parsers are tested. Malpedia family ids
  come only from the bundled galaxy 'malpedia' cluster, so joins never depend on the non-commercial
  Malpedia API. Source versions (galaxy commit and cluster versions, MSTIC row count) are recorded.
* **FC4 provenance per edge.** Every alias keeps its source and kind (primary or synonym), every related
  edge its kind (synonym / overlaps / associated / uses / revoked_by), likelihood and confidence. An exact
  synonym resolves to its cluster; overlapping clusters are listed as ``overlaps_with``, never merged.
  Clusters merge only through the same MITRE G/S/C id (after revoked-by normalisation), the same Malpedia
  id, or an explicit synonym assertion that passes the guards - never on normalised-name equality alone.
* **FC5 over-merge guards.** A stop-list of generic aliases (:data:`STOP_ALIASES`), short tokens (< 3
  characters) and bare ids never bridge; no merge puts two MITRE ids of one kind or two Malpedia ids in one
  cluster; no merge through an alias that several sources hold without a shared id; a synonym held by two
  entries of one source is ambiguous and never bridges; umbrella names never bridge. A cluster-size alarm
  and the build-time collision report (:func:`collision_report_fingerprint`) fail CI unless the reviewed
  fingerprint is updated (``collision_report.reviewed.json``).
* **FC6 ambiguity.** Umbrella names (Lazarus, Winnti/APT41, TA505, FIN7/Carbanak...) are flagged and answer
  with candidates and a disambiguation note; a name hitting several clusters returns the alternatives
  ('Winnti: APT41 [...] (misp-galaxy/threat-actor) / ...'). Actor and malware namespaces stay separate, so
  an ambiguous name returns both cards.
* **FC7 cards.** Normalisation lowercases and strips spaces, dashes and underscores ('APT 28' -> 'apt28');
  a card shows the canonical name, up to 10 aliases each with its asserting sources ('X = Y according to
  <source>') and the wording 'vendor assessment, not identity'.
* **FC8 refresh and use.** Offline lookup; the bundled sources are refreshed weekly as the datasets
  ``actor_alias_index.galaxy.<cluster>`` and ``actor_alias_index.mstic`` (never during a scan). Other
  modules call :func:`resolve` (P203, P219, P254, P372, the console: AR18); detection (WP17) and yaraify read
  the generated fragments ``v3lum/data/aliases/misp_galaxy_{threat_actor,malware_family}.json``.
* **FC9 regressions** live in tests/modules/test_actor_alias_index.py (APT28 vs APT29, Lazarus vs Kimsuky,
  Conti vs Black Basta, Brazilian bankers through galaxy/Malpedia ids, known conflicting aliases).
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import sys
import threading
import time
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from v3lum import paths
from v3lum.core.datasets import DATASETS, DatasetError, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

# ======================================================================================
# Sources
# ======================================================================================

GALAXY_REPO = "https://github.com/MISP/misp-galaxy"
GALAXY_RAW_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/{cluster}.json"
MSTIC_URL = "https://raw.githubusercontent.com/microsoft/mstic/master/PublicFeeds/ThreatActorNaming/MicrosoftMapping.json"
ETDA_EXPORT_URL = "https://apt.etda.or.th/cgi-bin/getmisp.cgi?o={o}"  # o=g groups, o=t tools (not fetched: FC2)
ETDA_CARD_URL = "https://apt.etda.or.th/cgi-bin/showcard.cgi?u={uuid}"  # FC7
APTMAP_URL = "https://andreacristaldi.github.io/APTmap/{file}"  # optional (FC3); raw 'main' path is 404
SOURCE_GALAXY = "github.actor_alias_index_galaxy"
SOURCE_MSTIC = "github.actor_alias_index_mstic"
BUNDLE_FILE = "actor_alias_index/alias_sources.json.gz"
REVIEWED_FILE = "actor_alias_index/collision_report.reviewed.json"
BUNDLE_SCHEMA = "v3lum.actor_alias_sources/1"
DATASET_PREFIX = "actor_alias_index."
REFRESH_TTL = 7 * 86400  # FC8 weekly
DATASET_MAX_BYTES = 16 * 1024 * 1024  # declared above 5 MB: never downloaded during a scan
GALAXY_LICENCE = "CC0-1.0 OR BSD-2-Clause"
MSTIC_LICENCE = "CC-BY-4.0"
GALAXY_ATTRIBUTION = "MISP galaxy (https://github.com/MISP/misp-galaxy), dual-licensed CC0 1.0 / BSD-2-Clause; MITRE-derived clusters reproduce the MITRE ATT&CK notice."
MSTIC_ATTRIBUTION = "Microsoft Threat Intelligence - threat actor naming map (https://github.com/microsoft/mstic), CC BY 4.0."
RECHECK_SECONDS = 60.0

ACTOR_CLUSTERS = frozenset({
    "threat-actor", "mitre-intrusion-set", "microsoft-activity-group", "360net", "tidal-groups",
    "mitre-enterprise-attack-intrusion-set", "mitre-mobile-attack-intrusion-set", "mitre-ics-groups", "mitre-campaign",
})
MALWARE_CLUSTERS = frozenset({
    "ransomware", "malpedia", "mitre-malware", "mitre-tool", "tool", "botnet", "rat", "backdoor", "stealer", "banker",
    "exploit-kit", "android", "rmm-tool", "mitre-software", "tidal-software",
})
#: The 16 bundled clusters (FC1; the research prototype's 19 minus the tidal/campaign ones).
DEFAULT_GALAXY_CLUSTERS = (
    "threat-actor", "ransomware", "malpedia", "mitre-intrusion-set", "mitre-malware", "mitre-tool", "tool", "botnet",
    "rat", "backdoor", "stealer", "banker", "exploit-kit", "microsoft-activity-group", "360net", "android",
)

# ======================================================================================
# Normalisation and guards (FC5, FC7)
# ======================================================================================

MIN_ALIAS_LEN = 3
#: FC5 stop-list of generic aliases (normalised); short tokens are refused separately.
STOP_ALIASES = frozenset({
    "unknown", "unk", "apt", "group", "team", "gang", "crew", "hackers", "hacker", "hackergroup", "actor",
    "threatactor", "unattributed", "unnamed", "none", "n/a", "na", "other", "others", "misc", "generic",
    "malware", "ransomware", "trojan", "rat", "bot", "botnet", "loader", "stealer", "backdoor", "dropper",
    "downloader", "banker", "spyware", "adware", "worm", "virus", "wiper", "miner", "exploit", "exploitkit",
    "tool", "tools", "agent", "test", "sample", "china", "russia", "iran", "northkorea", "india", "pakistan",
    "vietnam", "israel", "ukraine", "nigeria", "brazil", "statesponsored", "cybercriminals", "cybercrime",
})
#: FC6 umbrella names (normalised): flagged, answered with candidates, never a bridge.
UMBRELLA_NAMES = frozenset({
    "lazarus", "lazarusgroup", "hiddencobra", "labyrinthchollima", "winnti", "winntigroup", "winntiumbrella",
    "apt41", "ta505", "fin7", "carbanak", "carbanakgroup", "anunak", "cobaltgroup", "grizzlysteppe",
})
CLUSTER_ALARM_SIZE = 12  # FC5
MAX_ALIASES = 10  # FC7
MAX_CARDS = 5  # cards shown per namespace
VENDOR_WORDING = "vendor assessment, not identity"
_DASHES = "-_‐‑‒–—―−﹘﹣－"


def normalise_alias(text: Any) -> str:
    """FC7: NFKC + casefold, whitespace, dashes and underscores removed ('APT 28' -> 'apt28')."""
    if not isinstance(text, str):
        return ""
    s = unicodedata.normalize("NFKC", text).casefold()
    return "".join(ch for ch in s if not ch.isspace() and ch not in _DASHES)


def is_stop_alias(norm: str) -> bool:
    """Stop-listed, too short or a bare MITRE id (ids are handled as ids, never as names) (FC5)."""
    return not norm or len(norm) < MIN_ALIAS_LEN or norm in STOP_ALIASES or bool(re.fullmatch(r"[gsct]\d{4}(\.\d{3})?", norm))


# ======================================================================================
# Parsers (never raise: odd input gives a marker)
# ======================================================================================

_HTML_START = re.compile(r"^\s*(?:<!doctype\s+html|<html\b|<head\b|<body\b|<\?xml\b|<title\b)", re.I)
_CHALLENGE = ("just a moment...", "cf-chl-", "challenge-platform", "attention required! | cloudflare", "_incapsula_resource", "ddos-guard", "captcha")


def parse_json_body(raw: Any) -> tuple[Any, str | None]:
    """(obj, marker): HTML pages ('blocked: challenge' for anti-bot walls), empty, '404: Not Found' and
    truncated bodies give a marker, never an empty result."""
    if isinstance(raw, (dict, list)):
        return raw, None
    if isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
        if data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]
        text = data.decode("utf-8", errors="replace")
    elif isinstance(raw, str):
        text = raw[1:] if raw.startswith("﻿") else raw
    else:
        return None, "error: no body"
    if not text.strip():
        return None, "error: empty body"
    if _HTML_START.match(text[:2048]):
        low = text[:20000].lower()
        if any(m in low for m in _CHALLENGE):
            return None, "blocked: challenge page (never bypassed, A9)"
        return None, "error: HTML instead of JSON"
    if text.strip() in ("404: Not Found", "400: Invalid request"):
        return None, f"unavailable: {text.strip()}"
    try:
        return json.loads(text), None
    except (ValueError, RecursionError) as exc:
        return None, f"error: malformed JSON ({str(exc)[:80]})"


_MITRE_REF = re.compile(r"attack\.mitre\.org/(groups|software|campaigns)/([GSC]\d{4})", re.I)
_MALPEDIA_REF = re.compile(r"malpedia\.caad\.fkie\.fraunhofer\.de/(details|actor)/([A-Za-z0-9_.\-]+)")
_VALUE_ID = re.compile(r"^(.*?)\s+-\s+([GSC]\d{4})\s*$")
_BARE_ID = re.compile(r"\s*[GSC]\d{4}\s*")
_OWN_ID_KINDS = {"actor": "GC", "malware": "S"}


def _ids_from(value: str, meta: Mapping[str, Any], namespace: str) -> tuple[set[str], set[str]]:
    """(own MITRE ids, own Malpedia ids). Identity follows the namespace: actor entries own G/C ids and
    Malpedia '/actor/' ids, malware entries own S ids and Malpedia '/details/' family ids; the ids an entry
    only cites (a family citing the group using it) are context, never identity."""
    own = _OWN_ID_KINDS.get(namespace, "GSC")
    mitre: set[str] = set()
    malp: set[str] = set()

    def add(mid: str) -> None:
        mid = mid.strip().upper()
        if mid[:1] in own:
            mitre.add(mid)

    m = _VALUE_ID.match(value or "")
    if m:
        add(m.group(2))
    ext = meta.get("external_id")
    if isinstance(ext, str) and re.fullmatch(r"[GSC]\d{4}", ext.strip().upper()):
        add(ext)
    for syn in meta.get("synonyms") or []:
        if isinstance(syn, str) and _BARE_ID.fullmatch(syn):
            add(syn)
    for ref in meta.get("refs") or []:
        if not isinstance(ref, str):
            continue
        for _kind, mid in _MITRE_REF.findall(ref):
            add(mid)
        mm = _MALPEDIA_REF.search(ref)
        if mm:
            mid = mm.group(2).lower().rstrip("/")
            if mm.group(1) == "actor" and namespace == "actor":
                malp.add("actor:" + mid)
            elif mm.group(1) == "details" and namespace == "malware":
                malp.add(mid)
    return mitre, malp


_REL_KIND = {"same-as": "synonym", "synonym": "synonym", "synonym-of": "synonym", "revoked-by": "revoked_by",
             "uses": "uses", "used-by": "uses", "user-of": "uses"}
_OVERLAP_TYPES = frozenset({"similar", "overlaps", "related-to", "linked-to", "subgroup", "subgroup-of", "affiliated-with",
                            "business-relations", "parent-of", "successor-of", "predecessor-of", "variant-of"})


def _rel_kind(rtype: Any) -> str:
    return _REL_KIND.get(str(rtype), "overlaps" if rtype in _OVERLAP_TYPES else "associated")


def _likelihood(tags: Any) -> str | None:
    for tag in tags or []:
        m = re.search(r'likelihood-probability="([^"]+)"', str(tag))
        if m:
            return m.group(1)
    return None


def _confidence(kind: str, likelihood: str | None = None) -> str:
    if kind == "synonym":
        return "probable"
    if likelihood in ("almost-certain", "very-likely"):
        return "probable"
    return "possible"


def _entry(source: str, uuid: Any, display: str, names: list[tuple[str, str]], namespace: str, mitre: set[str], malp: set[str],
           meta: Mapping[str, Any], related: list[dict[str, Any]], extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    uid = uuid if isinstance(uuid, str) and uuid else None
    e: dict[str, Any] = {
        "key": f"{source}:{uid or normalise_alias(display)}", "source": source, "uuid": uid, "display": display,
        "namespace": namespace, "names": [], "mitre_ids": sorted(mitre), "malpedia_ids": sorted(malp),
        "country": meta.get("country") if isinstance(meta.get("country"), str) else None, "related": related,
    }
    seen: set[str] = set()
    for alias, how in names:
        norm = normalise_alias(alias)
        if norm and norm not in seen:
            seen.add(norm)
            e["names"].append({"alias": alias, "norm": norm, "how": how})
    if extra:
        e.update({k: v for k, v in extra.items() if v not in (None, "", [], {})})
    return e


def _related(raw: Any) -> list[dict[str, Any]]:
    out = []
    for r in raw or []:
        if isinstance(r, dict) and isinstance(r.get("dest-uuid"), str):
            kind = _rel_kind(r.get("type"))
            lk = _likelihood(r.get("tags"))
            out.append({"uuid": r["dest-uuid"], "type": r.get("type"), "kind": kind, "likelihood": lk, "confidence": _confidence(kind, lk)})
    return out


def parse_galaxy_cluster(raw: Any, cluster: str | None = None) -> dict[str, Any]:
    """MISP galaxy cluster JSON -> {'cluster', 'name', 'version', 'entries', 'marker', 'empty'} (FC1, FC4).

    MITRE ids come from ' - G0007' suffixes, meta.external_id, bare-id synonyms and attack.mitre.org refs;
    Malpedia ids from malpedia refs (never the Malpedia API, FC3). 'authors' is ignored (real names)."""
    obj, marker = parse_json_body(raw)
    out: dict[str, Any] = {"cluster": cluster, "name": None, "version": None, "entries": [], "marker": marker, "empty": False}
    if marker:
        return out
    if not isinstance(obj, dict) or not isinstance(obj.get("values"), list):
        out["marker"] = "error: galaxy cluster without 'values'"
        return out
    cl = cluster or (obj.get("type") if isinstance(obj.get("type"), str) else None) or "unknown"
    out.update(cluster=cl, name=obj.get("name"), version=obj.get("version"))
    if cl in ACTOR_CLUSTERS:
        ns = "actor"
    elif cl in MALWARE_CLUSTERS:
        ns = "malware"
    else:
        ns = "actor" if obj.get("category") == "actor" else "malware"
    for v in obj["values"]:
        if not isinstance(v, dict) or not isinstance(v.get("value"), str) or not v["value"].strip():
            continue
        meta = v.get("meta") if isinstance(v.get("meta"), dict) else {}
        value = v["value"].strip()
        m = _VALUE_ID.match(value)
        display = m.group(1).strip() if m else value
        mitre, malp = _ids_from(value, meta, ns)
        names = [(display, "primary")]
        for syn in meta.get("synonyms") or []:
            if isinstance(syn, str) and syn.strip() and not _BARE_ID.fullmatch(syn):
                names.append((syn.strip(), "synonym"))
        out["entries"].append(_entry(f"misp-galaxy/{cl}", v.get("uuid"), display, names, ns, mitre, malp, meta, _related(v.get("related"))))
    out["empty"] = not out["entries"]
    return out


def parse_mstic_mapping(raw: Any) -> dict[str, Any]:
    """Microsoft threat actor naming map (CC BY 4.0) -> {'entries', 'marker', 'empty'} (FC1; 'Other names'
    is a comma list, empty on 41 of 184 rows on 2026-11-26). The rows are explicit MSTIC mappings (FC4)."""
    obj, marker = parse_json_body(raw)
    out: dict[str, Any] = {"entries": [], "marker": marker, "empty": False}
    if marker:
        return out
    if not isinstance(obj, list):
        out["marker"] = "error: MSTIC map is not a JSON array"
        return out
    for row in obj:
        if not isinstance(row, dict):
            continue
        name = row.get("Threat actor name")
        if not isinstance(name, str) or not name.strip():
            continue
        other = row.get("Other names") if isinstance(row.get("Other names"), str) else ""
        names = [(name.strip(), "primary")] + [(x.strip(), "synonym") for x in re.split(r"[,;]", other) if x.strip()]
        mitre = {x.strip().upper() for x, _h in names if _BARE_ID.fullmatch(x)}
        names = [(x, h) for x, h in names if not _BARE_ID.fullmatch(x)]
        origin = row.get("Origin/Threat") if isinstance(row.get("Origin/Threat"), str) else None
        out["entries"].append(_entry("mstic", None, name.strip(), names, "actor", mitre, set(), {}, [], {"origin": origin}))
    out["empty"] = not out["entries"]
    return out


def parse_etda_export(raw: Any) -> dict[str, Any]:
    """ETDA/ThaiCERT getmisp.cgi export -> {'entries', 'version', 'marker', 'empty'} (FC1, FC2, FC7).

    Primary values are comma-joined synonyms ('Sofacy, APT 28, Fancy Bear, Sednit'); 'same-as' related edges
    are explicit synonym assertions; ``card_url`` uses ?u={uuid}. Never called on live data until legal
    records the source's terms class (FC2)."""
    obj, marker = parse_json_body(raw)
    out: dict[str, Any] = {"entries": [], "version": None, "marker": marker, "empty": False}
    if marker:
        return out
    if not isinstance(obj, dict) or not isinstance(obj.get("values"), list):
        out["marker"] = "error: ETDA export without 'values'"
        return out
    out["version"] = obj.get("version")
    ns = "malware" if obj.get("category") == "tool" or obj.get("type") == "tgc-tools" else "actor"
    for v in obj["values"]:
        if not isinstance(v, dict) or not isinstance(v.get("value"), str):
            continue
        meta = v.get("meta") if isinstance(v.get("meta"), dict) else {}
        segs = [s.strip() for s in v["value"].split(",") if s.strip()]
        if not segs:
            continue
        mitre, _m = _ids_from("", {"synonyms": meta.get("synonyms") or []}, ns)
        names = [(segs[0], "primary")] + [(s, "synonym") for s in segs[1:]]
        names += [(s.strip(), "synonym") for s in meta.get("synonyms") or [] if isinstance(s, str) and s.strip() and not _BARE_ID.fullmatch(s)]
        uid = v.get("uuid") if isinstance(v.get("uuid"), str) else None
        out["entries"].append(_entry("etda", uid, segs[0], names, ns, mitre, set(), meta, _related(v.get("related")),
                                     {"card_url": ETDA_CARD_URL.format(uuid=uid) if uid else None}))
    out["empty"] = not out["entries"]
    return out


def parse_aptmap(raw: Any) -> dict[str, Any]:
    """APTmap apt.json (GeoJSON, CC BY 4.0, optional, FC3) -> {'entries', 'marker', 'empty'}. Feature uuids are
    MISP galaxy threat-actor uuids (816/816 at ef61dcbc): APTmap adds coordinates; otx_* fields are ignored."""
    obj, marker = parse_json_body(raw)
    out: dict[str, Any] = {"entries": [], "marker": marker, "empty": False}
    if marker:
        return out
    feats = obj.get("features") if isinstance(obj, dict) else None
    if not isinstance(feats, list):
        out["marker"] = "error: APTmap file is not a FeatureCollection"
        return out
    for f in feats:
        p = f.get("properties") if isinstance(f, dict) else None
        if not isinstance(p, dict) or not isinstance(p.get("name"), str) or not p["name"].strip():
            continue
        geom = f.get("geometry") if isinstance(f.get("geometry"), dict) else None
        coords = geom.get("coordinates") if geom and geom.get("type") == "Point" else None
        others = [x for x in p.get("other-names") or [] if isinstance(x, str) and x.strip()]
        names = [(p["name"].strip(), "primary")] + [(x.strip(), "synonym") for x in others if not _BARE_ID.fullmatch(x)]
        mitre = {x.strip().upper() for x in others if _BARE_ID.fullmatch(x)}
        out["entries"].append(_entry("aptmap", p.get("uuid"), p["name"].strip(), names, "actor", mitre, set(),
                                     {"country": p.get("country")}, _related(p.get("related")),
                                     {"coordinates": coords if isinstance(coords, list) and len(coords) == 2 else None, "first_seen": p.get("first-seen")}))
    out["empty"] = not out["entries"]
    return out


def parse_cycat_search(raw: Any) -> dict[str, Any]:
    """api.cycat.org/search/<q> -> {'uuids', 'empty', 'marker'} (excluded source, FC3)."""
    obj, marker = parse_json_body(raw)
    out: dict[str, Any] = {"uuids": [], "empty": False, "marker": marker}
    if marker:
        return out
    if not isinstance(obj, list):
        out["marker"] = "error: CyCat search did not return a list"
        return out
    out["uuids"] = [u for u in obj if isinstance(u, str) and re.fullmatch(r"[0-9a-f-]{36}", u)]
    out["empty"] = not out["uuids"]
    return out


def parse_cycat_lookup(raw: Any) -> dict[str, Any]:
    """api.cycat.org/lookup/<uuid> -> {'uuid', 'type', 'title', 'link', 'feed', 'marker'}."""
    obj, marker = parse_json_body(raw)
    out: dict[str, Any] = {"uuid": None, "type": None, "title": None, "link": None, "feed": None, "marker": marker}
    if marker:
        return out
    if not isinstance(obj, dict):
        out["marker"] = "error: CyCat lookup is not an object"
        return out
    out["uuid"] = obj.get("cycat-oid") or obj.get("uuid")
    out["type"] = obj.get("_cycat_type")
    out["title"] = obj.get("github:name") or obj.get("description") or obj.get("title")
    out["link"] = obj.get("github:html_url") or obj.get("link")
    out["feed"] = obj.get("misp:feed")
    return out


def join_cycat_with_galaxy(uuids: Iterable[str], galaxy_uuids: Iterable[str]) -> dict[str, list[str]]:
    """Split CyCat search uuids into galaxy entries already bundled and external items (OSINT events)."""
    g = set(galaxy_uuids or ())
    uu = list(uuids or ())
    return {"in_galaxy": [u for u in uu if u in g], "external": [u for u in uu if u not in g]}


# ======================================================================================
# Guarded index (FC4-FC6)
# ======================================================================================


def _id_conflict(mitre_ids: Iterable[str], malpedia_ids: Iterable[str]) -> bool:
    """True when ids disagree: two MITRE ids of one kind (G, S or C) or two Malpedia ids (FC5)."""
    by_kind: dict[str, set[str]] = {}
    for mid in mitre_ids or ():
        by_kind.setdefault(mid[:1], set()).add(mid)
    return any(len(v) > 1 for v in by_kind.values()) or len(set(malpedia_ids or ())) > 1


class _UnionFind:
    def __init__(self, keys: Iterable[str]) -> None:
        self.parent = {k: k for k in keys}

    def find(self, k: str) -> str:
        while self.parent[k] != k:
            self.parent[k] = self.parent[self.parent[k]]
            k = self.parent[k]
        return k

    def union(self, a: str, b: str) -> str:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            if rb < ra:
                ra, rb = rb, ra
            self.parent[rb] = ra
        return ra


_CANON_PRIORITY = ("misp-galaxy/mitre-intrusion-set", "misp-galaxy/mitre-malware", "misp-galaxy/mitre-tool",
                   "misp-galaxy/threat-actor", "misp-galaxy/ransomware", "misp-galaxy/malpedia", "misp-galaxy/tool",
                   "misp-galaxy/banker", "etda", "mstic", "misp-galaxy/microsoft-activity-group", "aptmap")


def _canonical(ents: Mapping[str, dict[str, Any]], members: list[str]) -> str:
    def rank(k: str) -> tuple[int, str]:
        s = ents[k]["source"]
        return (_CANON_PRIORITY.index(s) if s in _CANON_PRIORITY else len(_CANON_PRIORITY), k)

    return str(ents[sorted(members, key=rank)[0]]["display"])


def collision_report_fingerprint(lines: Iterable[str]) -> str:
    """sha256 of the sorted collision report: CI fails unless it equals the reviewed fingerprint (FC5)."""
    return hashlib.sha256("\n".join(sorted(lines or [])).encode("utf-8")).hexdigest()


@dataclass
class AliasIndex:
    entries: dict[str, dict[str, Any]]
    clusters: dict[str, dict[str, Any]]
    entry_cluster: dict[str, str]
    alias: dict[str, list[dict[str, Any]]]
    overlaps: dict[str, dict[str, dict[str, Any]]]
    revoked_map: dict[str, str]
    report: list[str]
    report_fingerprint: str
    source_dates: dict[str, Any] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)
    downloaded: list[str] = field(default_factory=list)
    build_seconds: float = 0.0


def build_alias_index(entries: Iterable[dict[str, Any]], revoked_map: Mapping[str, str] | None = None,
                      cluster_alarm_size: int = CLUSTER_ALARM_SIZE, source_dates: Mapping[str, Any] | None = None) -> AliasIndex:
    """Guarded alias index (FC4-FC6) over parsed entries of any parser.

    Hard merges (confirmed): the same MITRE id of the entry's own kind (after revoked-by normalisation, e.g.
    G0086 -> G0094 from the galaxy's own 'revoked-by' edge), the same Malpedia id, the same uuid. A name bridge
    through alias Y (probable) only when: B1 Y is not stop-listed, short or an umbrella name; B2 some entry
    holds Y as an explicit synonym (never primary-name equality alone, FC4); B3 no source holds Y as a synonym
    of two entries; B4 when Y spans several sources their id-bearing entries agree on one id per kind and at
    least one id exists; B5 the merge never joins two MITRE ids of a kind or two Malpedia ids. Entries with two
    ids of one kind are umbrella entries: never merged, listed as overlaps. related[] overlaps are kept as
    overlaps_with, never merged. Alarms: clusters above ``cluster_alarm_size`` or holding two entries of one
    source. Refused or skipped bridges and alarms make the collision report."""
    started = time.monotonic()
    ents: dict[str, dict[str, Any]] = {}
    for e in entries or []:
        if isinstance(e, dict) and e.get("key") and e["key"] not in ents:
            ents[e["key"]] = e
    by_uuid: dict[str, list[str]] = {}
    for k, e in ents.items():
        if e.get("uuid"):
            by_uuid.setdefault(e["uuid"], []).append(k)
    rmap = dict(revoked_map or {})
    for e in ents.values():  # galaxy 'revoked-by' edges between MITRE entries
        for r in e.get("related", []):
            if r.get("kind") == "revoked_by" and e["mitre_ids"]:
                for tk in by_uuid.get(r["uuid"], []):
                    tgt = ents[tk]["mitre_ids"]
                    if len(tgt) == 1:
                        for mid in e["mitre_ids"]:
                            if mid != tgt[0]:
                                rmap.setdefault(mid, tgt[0])
    norm_ids: dict[str, list[str]] = {}
    umbrella_entry: dict[str, bool] = {}
    for k, e in ents.items():
        norm_ids[k] = sorted({rmap.get(m, m) for m in e["mitre_ids"]})
        umbrella_entry[k] = _id_conflict(norm_ids[k], e["malpedia_ids"])
    report: list[str] = []
    alarms: list[str] = []
    uf = _UnionFind(ents)
    cl_ids: dict[str, dict[str, set[str]]] = {k: {"mitre": set(norm_ids[k]), "malpedia": set(ents[k]["malpedia_ids"])} for k in ents}

    def try_union(keys: list[str], why: str) -> bool:
        roots = sorted({uf.find(k) for k in keys})
        if len(roots) < 2:
            return True
        mit = set().union(*(cl_ids[r]["mitre"] for r in roots))
        mal = set().union(*(cl_ids[r]["malpedia"] for r in roots))
        if _id_conflict(mit, mal):
            report.append(f"REFUSED {why}: would join ids {', '.join(sorted(mit | mal))}")
            return False
        base = roots[0]
        for r in roots[1:]:
            base = uf.union(base, r)
            cl_ids[base] = {"mitre": mit, "malpedia": mal}
        return True

    for _u, keys in sorted(by_uuid.items()):  # same-uuid twins (APTmap -> galaxy)
        if len(keys) > 1:
            roots = sorted({uf.find(k) for k in keys})
            merged = {"mitre": set().union(*(cl_ids[x]["mitre"] for x in roots)), "malpedia": set().union(*(cl_ids[x]["malpedia"] for x in roots))}
            base = roots[0]
            for r in roots[1:]:
                base = uf.union(base, r)
            cl_ids[base] = merged
    twins = {k for keys in by_uuid.values() if len(keys) > 1 for k in keys}
    umbrella = {k for k, flag in umbrella_entry.items() if flag}
    umbrella |= {k for k in twins if any(uf.find(k) == uf.find(u) for u in umbrella)}
    for k in sorted(umbrella):
        if umbrella_entry[k]:
            report.append(f"UMBRELLA entry {ents[k]['source']} '{ents[k]['display']}' carries {', '.join(norm_ids[k] + ents[k]['malpedia_ids'])}")
    id_groups: dict[tuple[str, str, str], list[str]] = {}
    for k, e in ents.items():
        if k in umbrella:
            continue
        for mid in norm_ids[k]:
            id_groups.setdefault((e["namespace"], "mitre", mid), []).append(k)
        for mp in e["malpedia_ids"]:
            id_groups.setdefault((e["namespace"], "malpedia", mp), []).append(k)
    for gk in sorted(id_groups):
        if len(id_groups[gk]) > 1:
            try_union(id_groups[gk], f"same id {gk[2]}")
    alias: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    for k, e in ents.items():
        for n in e["names"]:
            alias.setdefault((e["namespace"], n["norm"]), []).append((k, n["how"], n["alias"]))
    for ns, norm in sorted(alias):
        holders = alias[(ns, norm)]
        keys = sorted({k for k, _h, _a in holders})
        if len(keys) < 2 or is_stop_alias(norm) or norm in UMBRELLA_NAMES:
            continue  # B1
        if not any(how == "synonym" for _k, how, _a in holders):
            continue  # B2
        syn_by_src: dict[str, set[str]] = {}
        for k, how, _a in holders:
            if how == "synonym":
                syn_by_src.setdefault(ents[k]["source"], set()).add(k)
        amb = sorted(s for s, ks in syn_by_src.items() if len(ks) > 1)
        if amb:
            report.append(f"AMBIGUOUS alias '{norm}' ({ns}): synonym of several entries in {', '.join(amb)}")
            continue  # B3
        cand = [k for k in keys if k not in umbrella]
        if len(cand) < 2:
            continue
        sources = {ents[k]["source"] for k in cand}
        if len(sources) > 1:
            mit = set().union(*(cl_ids[uf.find(k)]["mitre"] for k in cand))
            mal = set().union(*(cl_ids[uf.find(k)]["malpedia"] for k in cand))
            if not mit and not mal:
                if len({uf.find(k) for k in cand}) > 1:
                    report.append(f"UNANCHORED alias '{norm}' ({ns}) in {len(sources)} sources without a shared id")
                continue  # B4
            if _id_conflict(mit, mal):
                report.append(f"CONFLICT alias '{norm}' ({ns}) maps to {', '.join(sorted(mit | mal))}")
                continue  # B4
        try_union(cand, f"alias '{norm}'")  # B5 inside
    clusters_raw: dict[str, list[str]] = {}
    for k in ents:
        clusters_raw.setdefault(uf.find(k), []).append(k)
    clusters: dict[str, dict[str, Any]] = {}
    entry_cluster: dict[str, str] = {}
    for root, members in clusters_raw.items():
        members.sort()
        cid = "C-" + hashlib.sha256("|".join(members).encode()).hexdigest()[:12]
        canon = _canonical(ents, members)
        clusters[cid] = {
            "members": members, "mitre_ids": sorted(cl_ids[root]["mitre"]), "malpedia_ids": sorted(cl_ids[root]["malpedia"]),
            "namespace": ents[members[0]]["namespace"], "canonical": canon,
            "umbrella": any(m in umbrella for m in members) or normalise_alias(canon) in UMBRELLA_NAMES,
            "sources": sorted({ents[m]["source"] for m in members}),
        }
        for m in members:
            entry_cluster[m] = cid
        if len(members) > cluster_alarm_size:
            alarms.append(f"ALARM cluster '{canon}' has {len(members)} entries")
        per_src: dict[str, list[str]] = {}
        for m in members:
            per_src.setdefault(ents[m]["source"], []).append(ents[m]["display"])
        for s, names in sorted(per_src.items()):
            if len(names) > 1:
                alarms.append(f"ALARM cluster '{canon}' holds {len(names)} entries of {s}: {', '.join(sorted(names))}")
    overlaps: dict[str, dict[str, dict[str, Any]]] = {}
    for k, e in ents.items():
        for r in e.get("related", []):
            if r.get("kind") in ("overlaps", "associated", "synonym"):
                for tk in by_uuid.get(r["uuid"], []):
                    a, b = entry_cluster[k], entry_cluster[tk]
                    if a != b:
                        overlaps.setdefault(a, {})[b] = {"kind": r["kind"], "type": r.get("type"), "source": e["source"], "confidence": r.get("confidence")}
    for k in umbrella:
        if not umbrella_entry[k]:
            continue
        a = entry_cluster[k]
        for (ns, kind, val), keys in id_groups.items():
            if kind == "mitre" and val in norm_ids[k] and ns == ents[k]["namespace"]:
                for tk in keys:
                    b = entry_cluster[tk]
                    if a != b:
                        info = {"kind": "umbrella_overlap", "type": f"shares id {val}", "source": ents[k]["source"], "confidence": "possible"}
                        overlaps.setdefault(a, {})[b] = info
                        overlaps.setdefault(b, {})[a] = info
    alias_out: dict[str, list[dict[str, Any]]] = {}
    for (ns, norm), holders in alias.items():
        if is_stop_alias(norm):
            continue
        bucket = alias_out.setdefault(norm, [])
        for k, how, a in holders:
            bucket.append({"key": k, "how": how, "alias": a, "namespace": ns})
    lines = sorted(set(report)) + sorted(set(alarms))
    return AliasIndex(
        entries=ents, clusters=clusters, entry_cluster=entry_cluster, alias=alias_out,
        overlaps={a: dict(sorted(b.items())) for a, b in overlaps.items()}, revoked_map=rmap, report=lines,
        report_fingerprint=collision_report_fingerprint(lines), source_dates=dict(source_dates or {}),
        build_seconds=round(time.monotonic() - started, 3),
    )


# ======================================================================================
# Cards and resolution (FC6, FC7)
# ======================================================================================


def alias_card(index: AliasIndex, cid: str, max_aliases: int = MAX_ALIASES) -> dict[str, Any] | None:
    """Card: canonical name, ids, up to ``max_aliases`` aliases each with its asserting sources
    ('Fancy Bear = APT28 according to misp-galaxy/threat-actor'), the wording 'vendor assessment, not
    identity', overlaps_with, ETDA ?u= card links, countries, sources and their dates."""
    c = index.clusters.get(cid)
    if not c:
        return None
    ents = index.entries
    canon = c["canonical"]
    cn = normalise_alias(canon)
    per: dict[str, dict[str, Any]] = {}
    for k in c["members"]:
        e = ents[k]
        for n in e["names"]:
            if n["norm"] == cn or is_stop_alias(n["norm"]):
                continue
            slot = per.setdefault(n["norm"], {"alias": n["alias"], "sources": set()})
            slot["sources"].add(e["source"])
    ranked = sorted(per.values(), key=lambda s: (-len(s["sources"]), s["alias"].casefold()))
    aliases = [
        {"alias": s["alias"], "sources": sorted(s["sources"]), "statement": f"{s['alias']} = {canon} according to {', '.join(sorted(s['sources']))}"}
        for s in ranked[:max_aliases]
    ]
    over = []
    for oc, info in sorted(index.overlaps.get(cid, {}).items()):
        other = index.clusters.get(oc)
        if other:
            over.append({"cluster": oc, "name": other["canonical"], **info})
    etda = sorted(ents[k]["card_url"] for k in c["members"] if ents[k]["source"] == "etda" and ents[k].get("card_url"))
    return {
        "cluster": cid, "canonical": canon, "namespace": c["namespace"], "mitre_ids": c["mitre_ids"], "malpedia_ids": c["malpedia_ids"],
        "aliases": aliases, "aliases_total": len(per), "wording": VENDOR_WORDING, "overlaps_with": over[:20], "overlaps_total": len(over),
        "etda_card_urls": etda, "sources": c["sources"], "umbrella": c["umbrella"],
        "countries": sorted({ents[k]["country"] for k in c["members"] if ents[k].get("country")}),
        "source_dates": {s: index.source_dates.get(s) for s in c["sources"] if index.source_dates.get(s)},
    }


def _card_label(card: Mapping[str, Any]) -> str:
    ids = list(card["mitre_ids"]) + list(card["malpedia_ids"])
    if card["umbrella"] and len(ids) > 1:
        tag = f" [umbrella {'+'.join(ids)}]"
    elif ids:
        tag = f" [{', '.join(ids)}]"
    else:
        tag = ""
    return f"{card['canonical']}{tag} ({', '.join(card.get('matched_in', []))})"


def _ids_compatible(cards: list[dict[str, Any]]) -> bool:
    mit = {i for c in cards for i in c["mitre_ids"]}
    mal = {i for c in cards for i in c["malpedia_ids"]}
    return len(mit) <= 1 and len(mal) <= 1 and not any(c["umbrella"] for c in cards)


def resolve_alias(index: AliasIndex, query: Any) -> dict[str, Any]:
    """Offline lookup (FC6-FC8): {'query', 'normalised', 'status' ok|ambiguous|not_found|stop_listed|invalid,
    'actors': [cards], 'malware': [cards], 'same_name': {ns: [cards]}, 'umbrella', 'note', 'alternatives'}.

    Actor and malware namespaces stay separate ('Carbanak' or 'Winnti' answer in both). Several clusters in
    one namespace give 'ambiguous' with an alternatives line, except when they only share the exact primary
    name and their ids agree (Malpedia win.grandoreiro and MITRE S0531 'Grandoreiro'): the first card answers
    and the others are listed under same_name, still unmerged (FC4)."""
    norm = normalise_alias(query)
    out: dict[str, Any] = {"query": query, "normalised": norm, "status": "not_found", "actors": [], "malware": [], "same_name": {},
                           "umbrella": False, "note": None, "alternatives": {}}
    if not norm:
        out["status"] = "invalid"
        return out
    if is_stop_alias(norm):
        out["status"] = "stop_listed"
        out["note"] = "generic or too short alias: not resolved (FC5)"
        return out
    hits = index.alias.get(norm, [])
    if not hits:
        return out
    ambiguous = False
    notes: list[str] = []
    for ns, fname in (("actor", "actors"), ("malware", "malware")):
        cids: dict[str, set[str]] = {}
        primary_hit: dict[str, bool] = {}
        for h in hits:
            if h["namespace"] != ns:
                continue
            cid = index.entry_cluster[h["key"]]
            cids.setdefault(cid, set()).add(index.entries[h["key"]]["source"])
            if h["how"] == "primary":
                primary_hit[cid] = True
        cards = []
        for cid in cids:
            card = alias_card(index, cid)
            if card:
                card["matched_in"] = sorted(cids[cid])
                cards.append(card)
        if ns == "malware":
            cards.sort(key=lambda c: (c["umbrella"], not c["malpedia_ids"], not c["mitre_ids"], c["canonical"], c["cluster"]))
        else:
            cards.sort(key=lambda c: (c["umbrella"], not c["mitre_ids"], c["canonical"], c["cluster"]))
        if len(cards) > 1 and _ids_compatible(cards) and all(primary_hit.get(c["cluster"]) for c in cards):
            out[fname] = cards[:1]
            out["same_name"][ns] = cards[1:]
            notes.append(f"same name in {len(cards)} unmerged {ns} clusters (FC4: no merge on name equality alone)")
            continue
        out[fname] = cards
        if len(cards) > 1:
            ambiguous = True
            out["alternatives"][ns] = f"{query}: " + " / ".join(_card_label(c) for c in cards)
    umb = norm in UMBRELLA_NAMES or any(c["umbrella"] for c in out["actors"] + out["malware"])
    out["umbrella"] = umb
    if umb:
        notes.insert(0, f"umbrella name: vendors use it for several groups; candidates listed - verify identifiers ({VENDOR_WORDING})")
    out["note"] = "; ".join(notes) or None
    out["status"] = "ambiguous" if ambiguous else "ok"
    return out


# ======================================================================================
# Bundled sources, refresh datasets and the process-wide index
# ======================================================================================

#: Entry fields kept in the bundle (no free text, no authors, no refs).
_KEEP = ("key", "source", "uuid", "display", "namespace", "names", "mitre_ids", "malpedia_ids", "country", "related", "origin", "card_url")


def trim_entries(entries: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for e in entries:
        t = {k: e[k] for k in _KEEP if k in e and e[k] not in (None, "", [], {})}
        t["names"] = [{"alias": n["alias"], "norm": n["norm"], "how": n["how"]} for n in e.get("names", [])]
        t.setdefault("mitre_ids", [])
        t.setdefault("malpedia_ids", [])
        t.setdefault("related", [])
        out.append(t)
    return out


def _dataset_name(kind: str) -> str:
    return f"{DATASET_PREFIX}{kind}"


GALAXY_DATASETS = {cluster: _dataset_name(f"galaxy.{cluster}") for cluster in DEFAULT_GALAXY_CLUSTERS}
MSTIC_DATASET = _dataset_name("mstic")


def _validate_galaxy(cluster: str):
    def validate(path: Path) -> bool:
        parsed = parse_galaxy_cluster(Path(path).read_bytes(), cluster)
        if parsed["marker"]:
            raise ValueError(f"{cluster}: {parsed['marker']}")
        if parsed["empty"]:
            raise ValueError(f"{cluster}: no values")
        return True

    validate.__name__ = f"validate_galaxy_{cluster.replace('-', '_')}"
    return validate


def _validate_mstic(path: Path) -> bool:
    parsed = parse_mstic_mapping(Path(path).read_bytes())
    if parsed["marker"]:
        raise ValueError(parsed["marker"])
    if len(parsed["entries"]) < 50:
        raise ValueError(f"only {len(parsed['entries'])} MSTIC rows")
    return True


def register_datasets() -> list[str]:
    names = []
    for cluster, name in GALAXY_DATASETS.items():
        if name not in DATASETS:
            register_dataset(
                name, GALAXY_RAW_URL.format(cluster=cluster), ttl=REFRESH_TTL,
                description=f"MISP galaxy cluster {cluster} (actor/malware alias index refresh)",
                licence=GALAXY_LICENCE, terms_class="open", attribution=GALAXY_ATTRIBUTION, provider="github",
                source=SOURCE_GALAXY, validate=_validate_galaxy(cluster), min_bytes=200, expect="json",
                max_bytes=DATASET_MAX_BYTES, large=True,
            )
        names.append(name)
    if MSTIC_DATASET not in DATASETS:
        register_dataset(
            MSTIC_DATASET, MSTIC_URL, ttl=REFRESH_TTL, description="Microsoft threat actor naming map (MSTIC)",
            licence=MSTIC_LICENCE, terms_class="open", attribution=MSTIC_ATTRIBUTION, provider="github",
            source=SOURCE_MSTIC, validate=_validate_mstic, min_bytes=1000, expect="json", max_bytes=DATASET_MAX_BYTES, large=True,
        )
    names.append(MSTIC_DATASET)
    return names


DATASET_NAMES = register_datasets()


def bundle_path() -> Path:
    return Path(str(resources.files("v3lum.data").joinpath(BUNDLE_FILE)))


def load_bundle() -> tuple[dict[str, Any], str]:
    """(bundle, sha256) of the bundled sources. Raises DatasetError when missing or unusable."""
    try:
        blob = bundle_path().read_bytes()
        data = json.loads(gzip.decompress(blob).decode("utf-8"))
    except (OSError, EOFError, ValueError) as exc:
        raise DatasetError(f"bundled {BUNDLE_FILE} unusable ({type(exc).__name__}: {exc})", name=BUNDLE_FILE) from exc
    if not isinstance(data, dict) or (data.get("_meta") or {}).get("schema") != BUNDLE_SCHEMA or not isinstance(data.get("sources"), dict):
        raise DatasetError(f"bundled {BUNDLE_FILE} is not a {BUNDLE_SCHEMA} document", name=BUNDLE_FILE)
    return data, hashlib.sha256(blob).hexdigest()


def reviewed_report() -> dict[str, Any]:
    """The reviewed collision report record (fingerprint, line count, reviewer, date) or {}."""
    try:
        doc = json.loads(resources.files("v3lum.data").joinpath(REVIEWED_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


_LOCK = threading.Lock()
_STATE: dict[str, Any] = {"key": None, "index": None, "checked": 0.0, "home": ""}


def _download_stamps() -> tuple[tuple[str, int, int], ...]:
    directory = paths.datasets_dir()
    out = []
    for name in (*GALAXY_DATASETS.values(), MSTIC_DATASET):
        try:
            st = (directory / name).stat()
        except OSError:
            continue
        out.append((name, st.st_size, st.st_mtime_ns))
    return tuple(out)


def _bundle_stamp() -> tuple[str, int, int]:
    p = bundle_path()
    try:
        st = p.stat()
    except OSError as exc:
        raise DatasetError(f"bundled {BUNDLE_FILE} missing ({exc})", name=BUNDLE_FILE) from exc
    return str(p), st.st_size, st.st_mtime_ns


def get_index(*, force: bool = False) -> AliasIndex:
    """The process-wide index: bundled sources, each replaced by its downloaded refresh when that copy
    parses (local copies only, never a download); rebuilt when a copy changes (checked at most every
    :data:`RECHECK_SECONDS`). Raises DatasetError when the bundle is unusable."""
    now = time.monotonic()
    home = str(paths.datasets_dir())
    with _LOCK:
        cached = _STATE["index"]
        if cached is not None and not force and _STATE["home"] == home and now - _STATE["checked"] < RECHECK_SECONDS:
            return cached
        stamps = _download_stamps()
        key = (_bundle_stamp(), home if stamps else "", stamps)  # without local copies every home shares the bundled index
        if cached is not None and not force and _STATE["key"] == key:
            _STATE.update(checked=now, home=home)
            return cached
        bundle, sha = load_bundle()
        sources: dict[str, Any] = dict(bundle["sources"])
        dates: dict[str, Any] = {s: (v or {}).get("version") for s, v in sources.items()}
        downloaded: list[str] = []
        directory = paths.datasets_dir()
        for name, _size, mtime_ns in stamps:
            try:
                raw = (directory / name).read_bytes()
            except OSError:
                continue
            if name == MSTIC_DATASET:
                parsed, src = parse_mstic_mapping(raw), "mstic"
                version = f"{len(parsed['entries'])} rows"
            else:
                cluster = name[len(_dataset_name("galaxy.")):]
                parsed, src = parse_galaxy_cluster(raw, cluster), f"misp-galaxy/{cluster}"
                version = parsed.get("version")
            if parsed["marker"] or parsed["empty"]:
                continue  # an unusable copy never replaces the bundled source
            fetched = time.strftime("%Y-%m-%d", time.gmtime(mtime_ns / 1e9))
            sources[src] = {"version": f"{version} (downloaded {fetched})", "entries": trim_entries(parsed["entries"])}
            dates[src] = sources[src]["version"]
            downloaded.append(src)
        entries = [e for s in sorted(sources) for e in (sources[s] or {}).get("entries", [])]
        index = build_alias_index(entries, source_dates=dates)
        index.meta = {**(bundle.get("_meta") or {}), "bundle_sha256": sha}
        index.downloaded = downloaded
        _STATE.update(key=key, index=index, checked=now, home=home)
        return index


def reset_cache() -> None:
    with _LOCK:
        _STATE.update(key=None, index=None, checked=0.0, home="")


def resolve(query: Any) -> dict[str, Any] | None:
    """Shared offline API (P203, P219, P254, P372, the console - AR18): resolution of an actor or malware
    name, or None when the bundled index is unusable. Never touches the network."""
    try:
        return resolve_alias(get_index(), query)
    except DatasetError:
        return None


def namespace_cards(res: Mapping[str, Any], namespace: str) -> list[dict[str, Any]]:
    """The cards of one namespace ('actor' or 'malware') when that namespace is unambiguous, else [] (an
    ambiguity in the other namespace does not hide the answer: 'Sofacy' is one actor and several malware)."""
    if res.get("status") not in ("ok", "ambiguous") or namespace in (res.get("alternatives") or {}):
        return []
    return list(res.get("actors" if namespace == "actor" else "malware") or [])


def mitre_ids_for(query: Any, namespace: str | None = None) -> list[str]:
    """MITRE G/S/C ids of the unambiguous, non-umbrella clusters a name resolves to (P292 hand-off); [] otherwise."""
    res = resolve(query)
    if not res:
        return []
    cards = [c for ns in ("actor", "malware") if namespace in (None, ns) for c in namespace_cards(res, ns)]
    return sorted({mid for c in cards if not c["umbrella"] for mid in c["mitre_ids"]})


def alias_fragments(index: AliasIndex, *, source_note: str) -> dict[str, dict[str, Any]]:
    """`v3lum.aliases/1` fragments for detection (WP17, AR18) and yaraify: {alias: canonical} of every
    alias that resolves unambiguously in its namespace (no stop-listed, umbrella or ambiguous names)."""
    out: dict[str, dict[str, Any]] = {}
    for ns, kind in (("actor", "threat_actor"), ("malware", "malware_family")):
        names: dict[str, str] = {}
        for norm in sorted(index.alias):
            if norm in UMBRELLA_NAMES:
                continue
            cards = namespace_cards(resolve_alias(index, norm), ns)
            if len(cards) != 1 or cards[0]["umbrella"]:
                continue
            holders = [h for h in index.alias[norm] if h["namespace"] == ns]
            if not holders:
                continue
            alias = sorted({h["alias"] for h in holders}, key=lambda a: (a.casefold(), a))[0]
            names[alias] = cards[0]["canonical"]
        out[kind] = {
            "schema": "v3lum.aliases/1",
            "kind": kind,
            "source": source_note,
            "licence": f"{GALAXY_LICENCE} (MISP galaxy); {MSTIC_LICENCE} (Microsoft Threat Intelligence naming map)",
            "notes": "Generated by v3lum/modules/cti_framework/actor_alias_index.py (batch p1-G11-1, P295): only aliases that resolve "
                     "to exactly one non-umbrella cluster; equivalences are vendor assessments, not identities. Do not edit by hand.",
            "names": dict(sorted(names.items(), key=lambda kv: kv[0].casefold())),
        }
    return out


# ======================================================================================
# The module
# ======================================================================================


@register
class ActorAliasIndex(Module):
    name = "actor_alias_index"
    title = "Threat actor / malware alias index"
    description = (
        "Offline resolution of a threat-actor or malware name to its alias cluster (MISP galaxy + Microsoft naming map): "
        "canonical name, MITRE/Malpedia ids, aliases with the source asserting each, overlaps and ambiguity notes."
    )
    category = "cti_framework"
    accepts = {T.THREAT_ACTOR, T.MALWARE, T.KEYWORD}
    produces = {T.THREAT_ACTOR, T.MALWARE}
    tags = {"offline", "free"}
    reference = GALAXY_REPO
    notice = (
        "MISP galaxy (CC0-1.0 / BSD-2-Clause) and Microsoft threat actor naming map (CC BY 4.0, Microsoft Threat Intelligence). "
        "Alias equivalences are vendor assessments, not identities. ETDA Threat Group Cards are not used until legal records "
        "their terms."
    )
    # ---- contract v2 declarations ---------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # offline: the dataset manager alone refreshes the sources
    hosts = ()
    sources = (SOURCE_GALAXY, SOURCE_MSTIC)
    expected_latency = 0.2  # resolve ~0.1 ms; the first use builds the index (< 1 s)
    max_pivots = 20
    default_enabled = True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        try:
            index = get_index()
        except DatasetError as exc:
            return res.mark(Status.UNAVAILABLE, f"alias index unusable ({exc}): could not verify", reason_code="dataset")
        try:
            ctx.data.bundled_path(BUNDLE_FILE)  # citation of the bundled sources
        except (OSError, ValueError):  # pragma: no cover
            pass
        out = resolve_alias(index, entity.value)
        status = out["status"]
        if status in ("invalid", "not_found", "stop_listed"):
            if out["note"]:
                res.error = out["note"]
            return res.mark(Status.EMPTY)
        # a keyword resolves only through an exact alias; the namespaces stay separate (FC6)
        cards = [("actor", c) for c in out["actors"][:MAX_CARDS]] + [("malware", c) for c in out["malware"][:MAX_CARDS]]
        res.attr("alias_status", status)
        res.attr("alias_cards", [_card_attr(c) for _ns, c in cards])
        if out["alternatives"]:
            res.attr("alias_alternatives", out["alternatives"])
        if out["same_name"]:
            res.attr("alias_same_name", {ns: [c["canonical"] + (f" [{', '.join(c['mitre_ids'] + c['malpedia_ids'])}]" if c["mitre_ids"] or c["malpedia_ids"] else "") for c in cs]
                                         for ns, cs in out["same_name"].items()})
        if out["note"]:
            res.attr("alias_note", out["note"])
        res.attr("alias_index_build", {
            "galaxy_commit": index.meta.get("galaxy_commit"), "built": index.meta.get("built"), "downloaded": index.downloaded,
            "report_fingerprint": index.report_fingerprint,
        })
        single = status == "ok" and len(cards) == 1 and not out["umbrella"]
        actor_names = sorted({c["canonical"] for ns, c in cards if ns == "actor"})
        malware_names = sorted({c["canonical"] for ns, c in cards if ns == "malware"})
        if actor_names:
            res.attr("threat_actors", actor_names)
        if malware_names:
            res.attr("malware_family", malware_names)
        for ns, card in cards:
            etype = T.THREAT_ACTOR if ns == "actor" else T.MALWARE
            ids = card["mitre_ids"] + card["malpedia_ids"]
            stmts = "; ".join(a["statement"] for a in card["aliases"][:MAX_ALIASES])
            desc = (
                f"'{entity.value}' resolves to {card['canonical']}" + (f" [{', '.join(ids)}]" if ids else "")
                + f" ({VENDOR_WORDING}). Aliases: {stmts or 'none besides the canonical name'}."
                + (f" Overlaps with: {', '.join(o['name'] for o in card['overlaps_with'][:5])} (listed, never merged)." if card["overlaps_with"] else "")
            )
            res.finding(
                "Threat actor alias card" if ns == "actor" else "Malware family alias card",
                "info",
                desc,
                confidence="probable" if single else "possible",
                data={"cluster": card["cluster"], "canonical": card["canonical"], "mitre_ids": card["mitre_ids"], "malpedia_ids": card["malpedia_ids"],
                      "sources": card["sources"], "umbrella": card["umbrella"]},
                tags=["info", "umbrella_name"] if card["umbrella"] else ["info"],
                source=SOURCE_GALAXY if any(s.startswith("misp-galaxy/") for s in card["sources"]) else SOURCE_MSTIC,
                key=card["cluster"],
            )
            # the canonical name is a vendor assessment: expanded only for one unambiguous card (FC6)
            res.pivot(etype, card["canonical"], "alias_of", confidence="probable" if single else "possible", expand=single,
                      note="" if single else "ambiguous or umbrella name: analyst selection required")
        if status == "ambiguous" or out["umbrella"]:
            alt = " | ".join(out["alternatives"].values()) or ", ".join(c["canonical"] for _ns, c in cards)
            res.finding(
                "Ambiguous or umbrella actor/malware name",
                "info",
                f"{out['note'] or 'several clusters match'}. Candidates: {alt}. Verify identifiers before attributing anything.",
                confidence="possible",
                data={"alternatives": out["alternatives"], "umbrella": out["umbrella"]},
                tags=["info", "umbrella_name"] if out["umbrella"] else ["info"],
            )
        return res


def _card_attr(card: Mapping[str, Any]) -> dict[str, Any]:
    return {k: card.get(k) for k in ("cluster", "canonical", "namespace", "mitre_ids", "malpedia_ids", "aliases", "aliases_total", "wording",
                                     "overlaps_with", "overlaps_total", "countries", "sources", "source_dates", "umbrella", "matched_in", "etda_card_urls")}


# ======================================================================================
# Dev script: python -m v3lum.modules.cti_framework.actor_alias_index build --galaxy <clone> --mstic <file>
# ======================================================================================


def build_sources(galaxy_dir: Path, mstic_raw: bytes, *, galaxy_commit: str, built: str) -> dict[str, Any]:
    sources: dict[str, Any] = {}
    for cluster in DEFAULT_GALAXY_CLUSTERS:
        parsed = parse_galaxy_cluster((Path(galaxy_dir) / "clusters" / f"{cluster}.json").read_bytes(), cluster)
        if parsed["marker"]:
            raise ValueError(f"{cluster}: {parsed['marker']}")
        sources[f"misp-galaxy/{cluster}"] = {"version": f"cluster v{parsed['version']} (galaxy {galaxy_commit[:8]})", "entries": trim_entries(parsed["entries"])}
    parsed = parse_mstic_mapping(mstic_raw)
    if parsed["marker"]:
        raise ValueError(f"mstic: {parsed['marker']}")
    sources["mstic"] = {"version": f"{len(parsed['entries'])} rows ({built})", "entries": trim_entries(parsed["entries"])}
    return {
        "_meta": {"schema": BUNDLE_SCHEMA, "galaxy_source": GALAXY_REPO, "galaxy_commit": galaxy_commit, "mstic_source": MSTIC_URL, "built": built,
                  "licence": f"{GALAXY_LICENCE} (MISP galaxy); {MSTIC_LICENCE} (Microsoft)", "clusters": list(DEFAULT_GALAXY_CLUSTERS)},
        "sources": sources,
    }


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - developer tool
    parser = argparse.ArgumentParser(prog="python -m v3lum.modules.cti_framework.actor_alias_index", description="Build the bundled alias sources (P295 FC1).")
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--galaxy", required=True, type=Path, help="local clone of github.com/MISP/misp-galaxy")
    b.add_argument("--galaxy-commit", required=True)
    b.add_argument("--mstic", required=True, type=Path, help="downloaded MicrosoftMapping.json")
    b.add_argument("--built", required=True)
    b.add_argument("--out-dir", type=Path, default=Path("v3lum/data/actor_alias_index"))
    b.add_argument("--aliases-dir", type=Path, default=Path("v3lum/data/aliases"))
    b.add_argument("--reviewer", default="")
    args = parser.parse_args(argv)
    bundle = build_sources(args.galaxy, args.mstic.read_bytes(), galaxy_commit=args.galaxy_commit, built=args.built)
    raw = json.dumps(bundle, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode("utf-8")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / Path(BUNDLE_FILE).name).write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
    entries = [e for s in sorted(bundle["sources"]) for e in bundle["sources"][s]["entries"]]
    index = build_alias_index(entries, source_dates={s: v["version"] for s, v in bundle["sources"].items()})
    (args.out_dir / "collision_report.txt").write_text("\n".join(index.report) + "\n", encoding="utf-8")
    reviewed = {"schema": "v3lum.alias_collision_review/1", "fingerprint": index.report_fingerprint, "lines": len(index.report),
                "galaxy_commit": args.galaxy_commit, "built": args.built, "reviewed_by": args.reviewer, "report": "v3lum/data/actor_alias_index/collision_report.txt"}
    (args.out_dir / Path(REVIEWED_FILE).name).write_text(json.dumps(reviewed, indent=1) + "\n", encoding="utf-8")
    note = f"MISP galaxy commit {args.galaxy_commit} ({len(DEFAULT_GALAXY_CLUSTERS)} clusters) + Microsoft naming map, built {args.built}"
    args.aliases_dir.mkdir(parents=True, exist_ok=True)
    for kind, doc in alias_fragments(index, source_note=note).items():
        (args.aliases_dir / f"misp_galaxy_{kind}.json").write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    sys.stdout.write(json.dumps({"entries": len(index.entries), "clusters": len(index.clusters), "aliases": len(index.alias), "report_lines": len(index.report),
                                 "fingerprint": index.report_fingerprint, "bundle_bytes": (args.out_dir / Path(BUNDLE_FILE).name).stat().st_size,
                                 "build_seconds": index.build_seconds}, indent=1) + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
