"""Pure parsers and helpers for batch p3-G11-1 (group G11 cti_framework).

Modules served:
  * P294 ``d3fend``   - MITRE D3FEND: ATT&CK technique -> recommended defensive controls.
  * P296 ``malpedia`` - Malpedia (Fraunhofer FKIE): families, actors, reference URLs.

Rules for this file: standard library only, no V3LUM imports, no network, no file I/O except
where a caller passes text/bytes in. Every function accepts untrusted input (bytes, str or an
already-parsed JSON object) and must never raise on bad data; validators that guard URLs raise
ValueError on purpose (that is the "by construction" refusal of P296 FC2).

Marker convention (same as the sibling G11 prep batches): helpers return None or a short string
'<kind>: <reason>' where kind is one of error | rate_limited | quota | blocked | unavailable.
A marker is never EMPTY; "no mapping"/"not found" is reported through the result's ``empty`` flag.
"""

from __future__ import annotations

import csv
import io
import json
import re
import unicodedata
from urllib.parse import quote, unquote, urlsplit

__all__ = [
    # shared
    "marker_kind", "looks_like_html", "load_json",
    # D3FEND (P294)
    "D3FEND_HOST", "D3FEND_PINNED_VERSION", "D3FEND_MAX_CONTROLS", "D3FEND_TACTIC_ORDER",
    "D3FEND_MAX_PER_TACTIC", "D3FEND_CACHE_TTL", "D3FEND_DATASET_TTL", "D3FEND_DATASET_MIN_BYTES",
    "D3FEND_DATASET_MAX_BYTES", "D3FEND_PINNED_SHA256", "D3FEND_HEALTH_TECHNIQUE", "d3fend_health_marker",
    "D3FEND_REQUIRED_COLUMNS", "D3FEND_COPYRIGHT", "D3FEND_LICENCE_TEXT", "D3FEND_TRADEMARK",
    "D3FEND_ATTACK_NOTICE", "D3FEND_TOU_URL",
    "normalize_attack_id", "attack_parent_id", "d3fend_dataset_url", "d3fend_api_url",
    "d3fend_technique_link", "d3fend_countermeasure_link", "d3fend_notice",
    "validate_d3fend_mappings_csv", "iter_d3fend_mapping_rows", "build_d3fend_index",
    "rank_controls", "d3fend_recommendations", "d3fend_api_marker", "parse_d3fend_api",
    "parse_d3fend_version",
    # Malpedia (P296)
    "MALPEDIA_HOST", "MALPEDIA_ENDPOINTS", "MALPEDIA_CACHE_TTL", "MALPEDIA_LICENCE",
    "MALPEDIA_LICENCE_URL", "MALPEDIA_ATTRIBUTION", "MALPEDIA_TOS_LICENCE_QUOTE",
    "MALPEDIA_TOS_AMBER_QUOTE", "MALPEDIA_LICENCE_BANNER", "MALPEDIA_MIN_INTERVAL",
    "MALPEDIA_EXPECTED_LATENCY", "malpedia_licence_banner",
    "is_malpedia_family_id", "is_malpedia_actor_id", "malpedia_actor_slug",
    "build_malpedia_url", "malpedia_url_allowed", "malpedia_auth_headers", "malpedia_marker",
    "malpedia_family_link", "malpedia_actor_link", "extract_mitre_group_ids",
    "rank_reference_urls", "parse_malpedia_families_list", "parse_malpedia_find_actor",
    "parse_malpedia_actor", "parse_malpedia_family", "parse_galaxy_malpedia_cluster",
    "resolve_malpedia_family_ids", "malpedia_source_tlp", "split_token_tier_urls",
]

# ---------------------------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------------------------

_MARKER_KINDS = ("error", "rate_limited", "quota", "blocked", "unavailable")


def marker_kind(marker):
    """Return the kind part of a marker ('error', 'rate_limited', ...) or None."""
    if not isinstance(marker, str) or ":" not in marker:
        return None
    kind = marker.split(":", 1)[0].strip()
    return kind if kind in _MARKER_KINDS else None


def _as_text(raw):
    """bytes/str/None -> str (UTF-8, BOM removed, undecodable bytes replaced)."""
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("utf-8", errors="replace")
    if not isinstance(raw, str):
        return ""
    return raw[1:] if raw.startswith("\ufeff") else raw


_HTML_HINTS = ("<!doctype html", "<html", "<head", "<body", "<title", "<meta ")


def looks_like_html(raw):
    """True when the payload starts like an HTML page (block page, 404 page, captive portal).

    Only bodies whose first non-blank character is '<' qualify, so JSON or CSV that merely
    mentions a tag inside a string is never misread as HTML.
    """
    head = _as_text(raw)[:2048].lstrip().lower()
    if not head.startswith("<"):
        return False
    return any(h in head for h in _HTML_HINTS)


def load_json(raw):
    """Parse untrusted JSON. Returns (obj, marker). obj is None whenever marker is set.

    Accepts an already-parsed object (dict/list) unchanged.
    """
    if isinstance(raw, (dict, list)):
        return raw, None
    text = _as_text(raw)
    if not text.strip():
        return None, "error: empty body"
    if looks_like_html(text):
        return None, "error: HTML instead of JSON"
    try:
        return json.loads(text), None
    except ValueError as exc:
        return None, "error: malformed JSON (%s)" % str(exc)[:80]


def _retry_after(headers):
    if not isinstance(headers, dict):
        return None
    for k, v in headers.items():
        if isinstance(k, str) and k.lower() == "retry-after":
            v = str(v).strip()
            return v[:40] if v else None
    return None


def _clean_str(value, limit=None):
    """Trimmed str with C0/C1 controls removed, or '' for non-strings."""
    if not isinstance(value, str):
        return ""
    s = "".join(ch for ch in value if ch in "\n\t" or not (ord(ch) < 0x20 or 0x7F <= ord(ch) < 0xA0))
    s = s.strip()
    if limit is not None and len(s) > limit:
        s = s[: limit - 1].rstrip() + "\u2026"
    return s


def _str_list(value, limit=None):
    """List of clean, de-duplicated (order kept) strings from an untrusted list."""
    out, seen = [], set()
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return out
    for item in value:
        s = _clean_str(item)
        if s and s not in seen:
            seen.add(s)
            out.append(s)
            if limit is not None and len(out) >= limit:
                break
    return out


def _first_sentence(text, limit=300):
    s = _clean_str(text)
    if not s:
        return ""
    m = re.search(r"(?<=[.!?])\s", s)
    if m and m.start() <= limit:
        s = s[: m.start()]
    return _clean_str(s, limit)


# ---------------------------------------------------------------------------------------------
# P294 d3fend
# ---------------------------------------------------------------------------------------------

D3FEND_HOST = "d3fend.mitre.org"
D3F_NS = "http://d3fend.mitre.org/ontologies/d3fend.owl#"
#: Release used for the fixtures (version.json on 2026-11-26: ontology 1.6.0, 2026-08-31).
D3FEND_PINNED_VERSION = "1.6.0"
#: Versioned bulk export (live 200 on 2026-11-26, 14,751,588 B raw / 591,115 B gzip).
D3FEND_DATASET_URL_TEMPLATE = "https://d3fend.mitre.org/ontologies/d3fend/{version}/d3fend-full-mappings.csv"
#: The unversioned "latest" data-file link on /resources/ontology/ answered 404 (GitHub Pages)
#: on 2026-11-26: do NOT register it as the dataset URL.
D3FEND_LATEST_URL_BROKEN = "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.csv"
D3FEND_API_TEMPLATE = "https://d3fend.mitre.org/api/offensive-technique/attack/{tid}.json"
D3FEND_VERSION_URL = "https://d3fend.mitre.org/api/version.json"
D3FEND_TECHNIQUE_PAGE = "https://d3fend.mitre.org/offensive-technique/attack/{tid}/"
D3FEND_COUNTERMEASURE_PAGE = "https://d3fend.mitre.org/technique/d3f:{name}/"
D3FEND_TOU_URL = "https://d3fend.mitre.org/tou/"

#: FC2: API answers (200 and 404 alike) are cached 30 days; the bulk export is refreshed on the
#: same cadence by ``v3lum data update`` (conditional GET: the host sends weak ETags).
D3FEND_CACHE_TTL = 30 * 86400
D3FEND_DATASET_TTL = 30 * 86400
#: Size guards for the dataset manager (1.6.0 export: 14,751,588 B decompressed, 16,249 rows).
D3FEND_DATASET_MIN_BYTES = 5_000_000
D3FEND_DATASET_MAX_BYTES = 64_000_000
#: sha256 of the decompressed 1.6.0 export fetched 2026-11-26 (pinned_sha256 for the pinned release).
D3FEND_PINNED_SHA256 = "2b86a5a19de143560b75fb2b443a7ac60335d60dfb6b08a7a6e9a53a052ad79f"
#: Known-mapped technique used by the health check: a 404 here means the API moved, not "no mapping".
D3FEND_HEALTH_TECHNIQUE = "T1059"

#: FC3: at most 5 countermeasures per technique.
D3FEND_MAX_CONTROLS = 5
#: Preference order used to keep the 5 shown controls diverse (V3LUM heuristic, not D3FEND's).
D3FEND_TACTIC_ORDER = ("Harden", "Detect", "Isolate", "Evict", "Restore", "Deceive", "Model")
#: At most this many of the shown controls share one D3FEND tactic (measured on 1.6.0: keeps the
#: most specific controls and still shows a second tactic for T1003/T1055/T1021).
D3FEND_MAX_PER_TACTIC = 3

#: Columns of the SPARQL 1.1 CSV export the parser relies on (header check = drift detector).
D3FEND_REQUIRED_COLUMNS = (
    "off_tech_id", "off_tech_label", "framework_root_iri", "def_tech", "def_tech_label",
    "def_tactic_label", "def_artifact", "def_artifact_label", "def_artifact_rel_label",
    "off_artifact", "off_artifact_label", "off_artifact_rel_label",
)

# FC4 legal floor - text as published on https://d3fend.mitre.org/tou/ (legal_dpo capture,
# checked 2026-11-26). The page footer renders the trademark line as "MITRE D3FEND; and the ..."
# (a stray ';' where the title shows the TM sign); legal should confirm the wording below.
D3FEND_COPYRIGHT = "\u00a9 2025 The MITRE Corporation."
D3FEND_LICENCE_TEXT = (
    "The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use "
    "D3FEND for research, development, and commercial purposes. Any copy you make for such purposes "
    "is authorized provided that you reproduce MITRE's copyright designation and this license in any "
    "such copy."
)
D3FEND_TRADEMARK = "MITRE D3FEND\u2122 and the MITRE D3FEND logo are trademarks of The MITRE Corporation."
D3FEND_ATTACK_NOTICE = (
    "MITRE ATT&CK\u00ae and ATT&CK\u00ae are registered trademarks of The MITRE Corporation. "
    "MITRE ATT&CK content is subject to the MITRE ATT&CK terms of use."
)

_ATTACK_ID_RE = re.compile(r"^T(\d{4})(?:[./](\d{3}))?$")
_ATTACK_URL_RE = re.compile(r"/techniques/(T\d{4})(?:/(\d{3}))?/?$", re.I)
_D3F_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_\-]{0,120}$")


def normalize_attack_id(value):
    """FC1/FC2 input guard: 'T1059', 't1059.001', 'T1059/001', ATT&CK URLs -> 'T1059[.001]'.

    Returns None for anything else (SPARTA ids such as 'DE-0003.08', free text, URLs of other
    sites). The result is the only value the API fallback may send (FC2: only the technique id).
    """
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s or len(s) > 200:
        return None
    m = _ATTACK_URL_RE.search(s)
    if m and ("attack.mitre.org" in s.lower() or s.lower().startswith("/techniques/")):
        return m.group(1).upper() + ("." + m.group(2) if m.group(2) else "")
    s = s.upper()
    m = _ATTACK_ID_RE.match(s)
    if not m:
        return None
    return "T" + m.group(1) + ("." + m.group(2) if m.group(2) else "")


def attack_parent_id(tid):
    """'T1003.001' -> 'T1003'; top-level ids -> None."""
    tid = normalize_attack_id(tid)
    if not tid or "." not in tid:
        return None
    return tid.split(".", 1)[0]


def d3fend_dataset_url(version=D3FEND_PINNED_VERSION):
    """FC1: URL of the pinned bulk mapping export for a D3FEND release ('1.6.0')."""
    if not isinstance(version, str) or not re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}", version):
        raise ValueError("D3FEND version must look like 1.6.0")
    return D3FEND_DATASET_URL_TEMPLATE.format(version=version)


def d3fend_api_url(technique):
    """FC2: fallback URL; refuses anything that is not a bare ATT&CK technique id (ValueError)."""
    tid = normalize_attack_id(technique)
    if not tid:
        raise ValueError("not an ATT&CK technique id")
    return D3FEND_API_TEMPLATE.format(tid=tid)


def d3fend_technique_link(technique):
    """FC3: report link d3fend.mitre.org/offensive-technique/attack/{id}/ (None if invalid)."""
    tid = normalize_attack_id(technique)
    return D3FEND_TECHNIQUE_PAGE.format(tid=tid) if tid else None


def _d3f_fragment(iri):
    if not isinstance(iri, str):
        return ""
    s = iri.strip()
    if s.startswith(D3F_NS):
        s = s[len(D3F_NS):]
    elif s.startswith("d3f:"):
        s = s[4:]
    elif "#" in s:
        s = s.rsplit("#", 1)[1]
    return s


def d3fend_countermeasure_link(iri_or_name):
    """Link to a defensive technique page (pattern from /api/technique/d3f:X.json; not live-checked)."""
    name = _d3f_fragment(iri_or_name)
    return D3FEND_COUNTERMEASURE_PAGE.format(name=name) if _D3F_NAME_RE.match(name or "") else None


def d3fend_notice():
    """FC4: notice block for data/NOTICE, THIRD_PARTY_NOTICES and every report with D3FEND content."""
    return "\n".join([
        "MITRE D3FEND\u2122 - " + D3FEND_COPYRIGHT,
        "LICENSE: " + D3FEND_LICENCE_TEXT,
        D3FEND_TRADEMARK,
        D3FEND_ATTACK_NOTICE,
        "Terms of Use: " + D3FEND_TOU_URL,
    ])


def _framework_of(root_iri):
    frag = _d3f_fragment(root_iri)
    if frag == "ATTACKEnterpriseTechnique":
        return "enterprise"
    if frag == "ATTACKICSTechnique":
        return "ics"
    if frag == "ATTACKMobileTechnique":
        return "mobile"
    if frag.startswith("SPARTA"):
        return "sparta"
    if frag.startswith("ATLAS"):
        return "atlas"
    return frag.lower() or "unknown"


def validate_d3fend_mappings_csv(raw, min_rows=1):
    """FC1 dataset validator (AR10 ``validate=`` hook). Returns None or a marker.

    Rejects HTML (the 404 page of the unversioned link, captive portals), a changed header,
    and exports without any ATT&CK row. ``raw`` may be the whole text or its first chunk.
    """
    text = _as_text(raw)
    if not text.strip():
        return "error: empty dataset"
    if looks_like_html(text):
        return "error: HTML instead of CSV"
    first = text.split("\n", 1)[0].rstrip("\r")
    try:
        header = next(csv.reader([first]))
    except (csv.Error, StopIteration):
        return "error: unreadable CSV header"
    missing = [c for c in D3FEND_REQUIRED_COLUMNS if c not in header]
    if missing:
        return "error: D3FEND export format changed (missing %s)" % ", ".join(missing[:4])
    rows = 0
    for row in iter_d3fend_mapping_rows(text):
        if row["framework"] in ("enterprise", "ics", "mobile"):
            rows += 1
            if rows >= min_rows:
                return None
    return "error: no ATT&CK rows in D3FEND export (%d < %d)" % (rows, min_rows)


def _row_value(row, key):
    v = row.get(key) if isinstance(row, dict) else None
    if isinstance(v, dict):  # SPARQL JSON binding {"type":..,"value":..}
        v = v.get("value")
    return v.strip() if isinstance(v, str) else ""


def _normalise_mapping(row, source="dataset"):
    """One SPARQL row (CSV dict or JSON binding) -> normalised dict, or None when unusable."""
    framework = _framework_of(_row_value(row, "framework_root_iri"))
    off_id_raw = _row_value(row, "off_tech_id")
    def_iri = _row_value(row, "def_tech")
    d3f = _d3f_fragment(def_iri)
    if not off_id_raw or not d3f or not _D3F_NAME_RE.match(d3f):
        return None  # e.g. API bindings that carry only the offensive side (no countermeasure)
    tid = normalize_attack_id(off_id_raw) if framework in ("enterprise", "ics", "mobile", "unknown") else None
    parent_iri = _row_value(row, "off_tech_parent")
    parent = normalize_attack_id(_d3f_fragment(parent_iri)) if parent_iri else None
    if tid and parent is None:
        parent = attack_parent_id(tid)
    return {
        "technique_id": tid,
        "raw_offensive_id": off_id_raw,
        "technique_label": _row_value(row, "off_tech_label"),
        "parent_id": parent if (tid and "." in tid) else None,
        "parent_label": _row_value(row, "off_tech_parent_label") if (tid and "." in tid) else "",
        "framework": framework,
        "offensive_tactic": _row_value(row, "off_tactic_label"),
        "offensive_artifact": _row_value(row, "off_artifact_label"),
        "offensive_relation": _row_value(row, "off_artifact_rel_label"),
        "d3f": d3f,
        "d3fend_id": _row_value(row, "def_tech_id") or None,  # API answers only; CSV has none
        "label": _row_value(row, "def_tech_label") or d3f,
        "tactic": _row_value(row, "def_tactic_label"),
        "artifact": _row_value(row, "def_artifact_label"),
        "relation": _row_value(row, "def_artifact_rel_label"),
        "direct": bool(_row_value(row, "def_artifact")) and _row_value(row, "def_artifact") == _row_value(row, "off_artifact"),
        "source": source,
    }


def iter_d3fend_mapping_rows(raw):
    """FC1: stream the bulk CSV export (text, bytes or an iterable of lines) as normalised rows.

    Rows without a defensive technique or offensive id are skipped. Non-ATT&CK frameworks
    (SPARTA) are yielded with technique_id None so callers can count but never match them.
    """
    if isinstance(raw, (str, bytes, bytearray)):
        stream = io.StringIO(_as_text(raw), newline="")
    else:
        stream = raw
    try:
        reader = csv.DictReader(stream)
        for row in reader:
            if not isinstance(row, dict):
                continue
            norm = _normalise_mapping(row)
            if norm is not None:
                yield norm
    except csv.Error:
        return


def _control_key(c):
    return c.get("d3f") or c.get("label") or ""


def rank_controls(controls, limit=None):
    """FC3 ranking (deterministic V3LUM heuristic, documented in notes.md).

    Order: direct artifact match first; then specificity (fewer ATT&CK techniques mapped to the
    countermeasure across the whole export = more specific); then more artifact paths. Inside each
    equal-score group the tactics are interleaved in D3FEND_TACTIC_ORDER so the shown five are not
    all 'Isolate'; label is the final tie-break.
    """
    items = [c for c in (controls or []) if isinstance(c, dict) and _control_key(c)]
    tactic_rank = {t: i for i, t in enumerate(D3FEND_TACTIC_ORDER)}

    def group_key(c):
        spec = c.get("specificity")
        spec = spec if isinstance(spec, int) and spec > 0 else 10 ** 6
        paths = c.get("paths") if isinstance(c.get("paths"), int) else 1
        return (0 if c.get("direct") else 1, spec, -paths)

    groups = {}
    for c in items:
        groups.setdefault(group_key(c), []).append(c)
    ranked = []
    for key in sorted(groups):
        bucket = sorted(groups[key], key=lambda c: (tactic_rank.get(c.get("tactic"), 99), c.get("label") or "", _control_key(c)))
        by_tactic = {}
        order = []
        for c in bucket:
            t = c.get("tactic") or ""
            if t not in by_tactic:
                by_tactic[t] = []
                order.append(t)
            by_tactic[t].append(c)
        while any(by_tactic.values()):
            for t in order:
                if by_tactic[t]:
                    ranked.append(by_tactic[t].pop(0))
    return ranked[:limit] if limit is not None else ranked


def build_d3fend_index(rows, version=None, source_sha256=None):
    """FC1: build the offline index (JSON-serialisable) from normalised rows.

    Returns {'version', 'source_sha256', 'rows', 'frameworks', 'techniques': {tid: {...,
    'controls': ranked list}}, 'children': {parent: [sub-ids]}, 'labels': {id: label}}.
    Each control: d3f, label, tactic, artifact, relation, offensive_artifact,
    offensive_relation, direct, paths, specificity, d3fend_id (None from the CSV).
    """
    frameworks = {}
    per = {}
    meta = {}
    spec = {}
    labels = {}
    children = {}
    nrows = 0
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        nrows += 1
        fw = r.get("framework") or "unknown"
        frameworks[fw] = frameworks.get(fw, 0) + 1
        tid = r.get("technique_id")
        if not tid:
            continue
        spec.setdefault(r["d3f"], set()).add(tid)
        if r.get("technique_label"):
            labels.setdefault(tid, r["technique_label"])
        if r.get("parent_id"):
            children.setdefault(r["parent_id"], set()).add(tid)
            if r.get("parent_label"):
                labels.setdefault(r["parent_id"], r["parent_label"])
        m = meta.setdefault(tid, {"label": r.get("technique_label") or "", "framework": fw,
                                  "parent": r.get("parent_id"), "offensive_tactics": set()})
        if r.get("offensive_tactic"):
            m["offensive_tactics"].add(r["offensive_tactic"])
        ctl = per.setdefault(tid, {}).setdefault(r["d3f"], {
            "d3f": r["d3f"], "label": r.get("label") or r["d3f"], "tactic": r.get("tactic") or "",
            "artifact": r.get("artifact") or "", "relation": r.get("relation") or "",
            "offensive_artifact": r.get("offensive_artifact") or "",
            "offensive_relation": r.get("offensive_relation") or "",
            "direct": False, "_paths": set(), "d3fend_id": r.get("d3fend_id"),
        })
        if r.get("direct") and not ctl["direct"]:
            ctl.update(direct=True, artifact=r.get("artifact") or ctl["artifact"],
                       offensive_artifact=r.get("offensive_artifact") or ctl["offensive_artifact"],
                       relation=r.get("relation") or ctl["relation"],
                       offensive_relation=r.get("offensive_relation") or ctl["offensive_relation"])
        ctl["_paths"].add((r.get("offensive_artifact"), r.get("artifact"), r.get("relation")))
    techniques = {}
    for tid, ctls in per.items():
        out = []
        for c in ctls.values():
            c = dict(c)
            c["paths"] = len(c.pop("_paths"))
            c["specificity"] = len(spec.get(c["d3f"], ()))
            out.append(c)
        m = meta[tid]
        techniques[tid] = {
            "label": m["label"], "framework": m["framework"], "parent": m["parent"],
            "offensive_tactics": sorted(m["offensive_tactics"]),
            "total": len(out), "controls": rank_controls(out),
        }
    return {
        "version": version, "source_sha256": source_sha256, "rows": nrows,
        "frameworks": dict(sorted(frameworks.items())),
        "techniques": dict(sorted(techniques.items())),
        "children": {k: sorted(v) for k, v in sorted(children.items())},
        "labels": dict(sorted(labels.items())),
    }


def _merge_controls(lists):
    merged = {}
    for lst in lists:
        for c in lst or []:
            k = _control_key(c)
            if not k:
                continue
            cur = merged.get(k)
            if cur is None:
                merged[k] = dict(c)
            else:
                if c.get("direct") and not cur.get("direct"):
                    cur.update({x: c.get(x) for x in ("direct", "artifact", "offensive_artifact", "relation", "offensive_relation")})
                cur["paths"] = max(cur.get("paths") or 1, c.get("paths") or 1)
    return list(merged.values())


def _select_diverse(ranked, n, cap=D3FEND_MAX_PER_TACTIC):
    """Take the first n ranked controls with at most ``cap`` per tactic; fill up if short."""
    out, count = [], {}
    for c in ranked:
        t = c.get("tactic") or ""
        if count.get(t, 0) >= cap:
            continue
        out.append(c)
        count[t] = count.get(t, 0) + 1
        if len(out) >= n:
            return out
    for c in ranked:
        if len(out) >= n:
            break
        if c not in out:
            out.append(c)
    return out


def d3fend_recommendations(index, technique, limit=D3FEND_MAX_CONTROLS, rollup=True):
    """FC3: 'recommended controls' block for one ATT&CK technique (INFO / recommendation only).

    Lookup order: the technique itself (basis 'exact'); for an unmapped sub-technique its parent
    (basis 'parent'); for an unmapped parent the union of its mapped sub-techniques (basis
    'subtechniques'). Nothing found -> empty=True, reason 'no mapping' (never an error).
    """
    limit = D3FEND_MAX_CONTROLS if not isinstance(limit, int) or limit <= 0 else min(limit, D3FEND_MAX_CONTROLS)
    tid = normalize_attack_id(technique) if isinstance(technique, str) else None
    result = {
        "technique_id": tid, "technique_label": "", "framework": None, "basis": None,
        "basis_ids": [], "total": 0, "shown": 0, "controls": [],
        "link": d3fend_technique_link(tid) if tid else None,
        "section": "recommended controls", "severity": "info",
        "empty": True, "reason": None, "notice": d3fend_notice(),
        "dataset_version": (index or {}).get("version") if isinstance(index, dict) else None,
    }
    if not tid:
        result["reason"] = "not an ATT&CK technique id"
        return result
    techs = (index or {}).get("techniques") if isinstance(index, dict) else None
    techs = techs if isinstance(techs, dict) else {}
    labels = (index or {}).get("labels") or {}
    children = (index or {}).get("children") or {}
    controls, basis, basis_ids = None, None, []
    entry = techs.get(tid)
    if entry:
        controls, basis, basis_ids = entry.get("controls") or [], "exact", [tid]
        result["technique_label"] = entry.get("label") or labels.get(tid, "")
        result["framework"] = entry.get("framework")
    elif rollup and "." in tid and techs.get(tid.split(".")[0]):
        parent = tid.split(".")[0]
        pe = techs[parent]
        controls, basis, basis_ids = pe.get("controls") or [], "parent", [parent]
        result["technique_label"] = labels.get(tid, "")
        result["framework"] = pe.get("framework")
    elif rollup and "." not in tid and children.get(tid):
        subs = [s for s in children[tid] if techs.get(s)]
        if subs:
            controls = rank_controls(_merge_controls([techs[s].get("controls") for s in subs]))
            basis, basis_ids = "subtechniques", subs
            result["technique_label"] = labels.get(tid, "")
            result["framework"] = techs[subs[0]].get("framework")
    if not controls:
        result["reason"] = "no mapping"
        return result
    shown = []
    for c in _select_diverse(controls, limit):
        shown.append({
            "d3f": c.get("d3f"), "label": c.get("label"), "tactic": c.get("tactic"),
            "d3fend_id": c.get("d3fend_id"),
            "why": "%s %s; technique %s %s" % (c.get("relation") or "acts on", c.get("artifact") or "?",
                                             c.get("offensive_relation") or "uses", c.get("offensive_artifact") or "?"),
            "link": d3fend_countermeasure_link(c.get("d3f")),
        })
    result.update(basis=basis, basis_ids=basis_ids, total=len(controls), shown=len(shown),
                  controls=shown, empty=False, reason=None)
    return result


def d3fend_api_marker(status, body=None, content_type=None, headers=None):
    """FC2 marker for the per-technique API fallback. 404 is NOT a marker ('no mapping')."""
    if not isinstance(status, int):
        return "error: no HTTP status"
    if status == 404:
        return None
    if status == 429:
        ra = _retry_after(headers)
        return "rate_limited: HTTP 429" + (" (Retry-After %s)" % ra if ra else "")
    if status in (401, 403, 451):
        return "blocked: HTTP %d" % status
    if status >= 500:
        return "error: HTTP %d" % status
    if status != 200:
        return "error: HTTP %d" % status
    if looks_like_html(body) or (isinstance(content_type, str) and "html" in content_type.lower()):
        return "error: HTML instead of JSON"
    return None


def parse_d3fend_api(raw, status=200, technique=None, content_type=None, headers=None, specificity=None):
    """FC2/FC5: parse one /api/offensive-technique/attack/{T}.json answer.

    404 -> empty/no_mapping (never an error). Bindings without a defensive technique are
    skipped. ``specificity`` (d3f -> int, from a loaded index) improves the ranking when present.
    """
    tid = normalize_attack_id(technique) if isinstance(technique, str) else None
    out = {"technique_id": tid, "technique_label": "", "framework": None, "controls": [],
           "total": 0, "subtechniques": [], "description": "", "empty": True,
           "no_mapping": False, "marker": None, "link": d3fend_technique_link(tid) if tid else None}
    if status == 404:
        out.update(no_mapping=True)
        return out
    marker = d3fend_api_marker(status, raw if not isinstance(raw, (dict, list)) else None, content_type, headers)
    if marker:
        out["marker"] = marker
        return out
    obj, marker = load_json(raw)
    if marker:
        out["marker"] = marker
        return out
    if not isinstance(obj, dict):
        out["marker"] = "error: unexpected JSON shape (%s)" % type(obj).__name__
        return out
    otd = obj.get("off_to_def")
    bindings = []
    if isinstance(otd, dict) and isinstance(otd.get("results"), dict):
        b = otd["results"].get("bindings")
        bindings = b if isinstance(b, list) else []
    elif otd is not None:
        out["marker"] = "error: unexpected off_to_def shape"
        return out
    fw = obj.get("framework") if isinstance(obj.get("framework"), dict) else {}
    out["framework"] = _clean_str(fw.get("framework_key")) or None
    rows = []
    for b in bindings:
        if not isinstance(b, dict):
            continue
        n = _normalise_mapping(b, source="api")
        if n is None:
            continue
        if tid is None and n.get("technique_id"):
            tid = n["technique_id"]
        if n.get("technique_label") and not out["technique_label"]:
            out["technique_label"] = n["technique_label"]
        rows.append(n)
    out["technique_id"] = tid
    out["link"] = d3fend_technique_link(tid) if tid else None
    idx = build_d3fend_index(rows)
    entry = idx["techniques"].get(tid) if tid else None
    if entry is None and idx["techniques"]:
        entry = next(iter(idx["techniques"].values()))
    controls = [dict(c) for c in (entry or {}).get("controls", [])]
    if isinstance(specificity, dict):
        for c in controls:
            if isinstance(specificity.get(c["d3f"]), int):
                c["specificity"] = specificity[c["d3f"]]
        controls = rank_controls(controls)
    out["controls"] = controls
    out["total"] = len(controls)
    out["empty"] = not controls
    out["no_mapping"] = not controls
    desc = obj.get("description")
    graph = desc.get("@graph") if isinstance(desc, dict) else None
    if isinstance(graph, list):
        for node in graph:
            if isinstance(node, dict):
                out["description"] = _first_sentence(node.get("d3f:definition"))
                if not out["technique_label"]:
                    out["technique_label"] = _clean_str(node.get("rdfs:label"))
                break
    sub = obj.get("subtechniques")
    sgraph = sub.get("@graph") if isinstance(sub, dict) else None
    subs = []
    if isinstance(sgraph, list):
        for node in sgraph:
            if not isinstance(node, dict):
                continue
            ids = node.get("d3f:attack-id")
            ids = ids if isinstance(ids, list) else [ids]
            for i in ids:
                n = normalize_attack_id(i) if isinstance(i, str) else None
                if n and n != tid and n not in subs:
                    subs.append(n)
    out["subtechniques"] = sorted(subs)
    return out


def d3fend_health_marker(status, body=None, content_type=None):
    """Health check for the API fallback: GET the known-mapped D3FEND_HEALTH_TECHNIQUE.

    Unlike a lookup, a 404 here is a marker (the API path moved), so a silent site change can
    never turn every technique into 'no mapping'. Returns None when healthy.
    """
    if status == 404:
        return "unavailable: D3FEND API answered 404 for %s (API moved?)" % D3FEND_HEALTH_TECHNIQUE
    m = d3fend_api_marker(status, body, content_type)
    if m:
        return m
    res = parse_d3fend_api(body, status=status, technique=D3FEND_HEALTH_TECHNIQUE, content_type=content_type)
    if res["marker"]:
        return res["marker"]
    if res["empty"]:
        return "error: D3FEND API returned no countermeasures for %s (format changed?)" % D3FEND_HEALTH_TECHNIQUE
    return None


def parse_d3fend_version(raw):
    """FC1 'version recorded': parse /api/version.json -> {'version', 'ontology_version', ...}."""
    obj, marker = load_json(raw)
    if marker:
        return {"marker": marker}
    if not isinstance(obj, dict):
        return {"marker": "error: unexpected JSON shape"}
    out = {k: _clean_str(obj.get(k)) or None for k in (
        "version", "ontology_version", "release_date", "ontology_hash_sha256",
        "frontend_version", "ui_build_date", "ui_commit")}
    if not out["ontology_version"] or not re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}", out["ontology_version"]):
        return {"marker": "error: version.json without a usable ontology_version"}
    h = out.get("ontology_hash_sha256")
    if h and not re.fullmatch(r"[0-9a-f]{64}", h):
        out["ontology_hash_sha256"] = None
    out["marker"] = None
    out["dataset_url"] = d3fend_dataset_url(out["ontology_version"])
    return out


# ---------------------------------------------------------------------------------------------
# P296 malpedia
# ---------------------------------------------------------------------------------------------

MALPEDIA_HOST = "malpedia.caad.fkie.fraunhofer.de"
_MALPEDIA_BASE = "https://" + MALPEDIA_HOST

#: FC2 endpoint allow-list (the ONLY paths the module may build).
MALPEDIA_ENDPOINTS = {
    "list_families": "/api/list/families",
    "find_actor": "/api/find/actor/{value}",
    "get_actor": "/api/get/actor/{value}",
    "get_family": "/api/get/family/{value}",
}
#: FC5: list/families 7 days (binding); the others are this prep's recommendation.
MALPEDIA_CACHE_TTL = {
    "list_families": 7 * 86400,
    "find_actor": 7 * 86400,
    "get_actor": 7 * 86400,
    "get_family": 7 * 86400,
}
MALPEDIA_LICENCE = "CC BY-NC-SA 3.0"
MALPEDIA_LICENCE_URL = "http://creativecommons.org/licenses/by-nc-sa/3.0/"
MALPEDIA_ATTRIBUTION = ("Malpedia (Fraunhofer FKIE), https://malpedia.caad.fkie.fraunhofer.de/ - "
                        "content licensed under CC BY-NC-SA 3.0")
# Quotes from https://malpedia.caad.fkie.fraunhofer.de/usage/tos (legal_dpo capture, 2026-11-26).
MALPEDIA_TOS_LICENCE_QUOTE = ("The whole content of the website is released under Creative Common's "
                              "CC BY-NC-SA 3.0 license.")
MALPEDIA_TOS_AMBER_QUOTE = ("The general guideline regarding redistribution of the material that is not "
                            "publicly accessible is to treat it TLP:AMBER (unless designated or agreed "
                            "upon otherwise).")
#: FC1: banner text for research-profile runs (legal_ref filled from licence_allow.research_basis).
MALPEDIA_LICENCE_BANNER = ("Licence: Malpedia content (Fraunhofer FKIE) is CC BY-NC-SA 3.0 - non-commercial; "
                           "used under research basis {legal_ref}. Attribution: Malpedia (Fraunhofer FKIE).")

#: Observed latency from the datacenter egress on 2026-11-26: 0.77-1.24 s; server sends
#: Cache-Control max-age=7200 and no rate-limit headers (limit unpublished: be polite).
MALPEDIA_MIN_INTERVAL = 2.0
MALPEDIA_EXPECTED_LATENCY = 1.5


def malpedia_licence_banner(legal_ref):
    """FC1: banner for research-profile runs. ``legal_ref`` comes from licence_allow.research_basis."""
    ref = re.sub(r"\s+", " ", _clean_str(legal_ref, 80)) if isinstance(legal_ref, str) else ""
    return MALPEDIA_LICENCE_BANNER.format(legal_ref=ref or "(missing legal_ref)")


_FAMILY_ID_RE = re.compile(r"^[a-z0-9]{1,12}\.[a-z0-9][a-z0-9_\-]{0,79}$")
_ACTOR_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-]{0,79}$")
_NEEDLE_FORBIDDEN = re.compile(r"[/\\%?#\x00-\x1f\x7f]")
_ALLOWED_PATHS = (
    ("list_families", re.compile(r"^/api/list/families$")),
    ("find_actor", re.compile(r"^/api/find/actor/(?P<v>[^/]{1,200})$")),
    ("get_actor", re.compile(r"^/api/get/actor/(?P<v>[a-z0-9][a-z0-9_.\-]{0,79})$")),
    ("get_family", re.compile(r"^/api/get/family/(?P<v>[a-z0-9]{1,12}\.[a-z0-9][a-z0-9_\-]{0,79})$")),
)
_GROUP_ID_RE = re.compile(r"^G\d{4}$")
_GROUP_URL_RE = re.compile(r"attack\.mitre\.org/groups/(G\d{4})(?:/|$)", re.I)
_DETAILS_RE = re.compile(r"^https?://malpedia\.caad\.fkie\.fraunhofer\.de/details/([a-z0-9]{1,12}\.[a-z0-9][a-z0-9_\-]{0,79})/?$")
_YEAR_RE = re.compile(r"(?<![0-9])(20[0-3][0-9])(?:[/\-_]|[01][0-9][0-3][0-9])")


def is_malpedia_family_id(value):
    """FC5: family ids are '<platform>.<name>' (live list 2026-11-26: 3,846 ids, one dot each)."""
    return isinstance(value, str) and bool(_FAMILY_ID_RE.match(value))


def is_malpedia_actor_id(value):
    """FC5: actor ids are lowercase slugs (apt28, lazarus_group); '..' never allowed."""
    return isinstance(value, str) and bool(_ACTOR_ID_RE.match(value)) and ".." not in value


def malpedia_actor_slug(name):
    """Best-effort actor slug from a common name ('Lazarus Group' -> 'lazarus_group').

    Verified only on simple names (apt28, lazarus_group). Names with punctuation or non-ASCII
    letters must be resolved through find/actor (its 'name' field is the real id).
    """
    if not isinstance(name, str):
        return None
    s = unicodedata.normalize("NFKC", name).strip().lower()
    if not s or not s.isascii():
        return None
    s = re.sub(r"[^a-z0-9]+", "_", s).strip("_")
    return s if is_malpedia_actor_id(s) else None


def _check_needle(needle):
    if not isinstance(needle, str):
        raise ValueError("needle must be text")
    n = unicodedata.normalize("NFC", needle).strip()
    if not (1 <= len(n) <= 64):
        raise ValueError("needle length must be 1-64")
    if _NEEDLE_FORBIDDEN.search(n) or ".." in n or not n.strip("."):
        raise ValueError("needle contains a forbidden character")
    return n


def build_malpedia_url(endpoint, value=None):
    """FC2: the only URL builder. Raises ValueError for any endpoint outside the allow-list
    (samples, YARA, bib, misp, scan, get/families, find/family ...) and for unsafe values.
    """
    if endpoint not in MALPEDIA_ENDPOINTS:
        raise ValueError("endpoint not allowed: %r" % (endpoint,))
    template = MALPEDIA_ENDPOINTS[endpoint]
    if endpoint == "list_families":
        if value is not None:
            raise ValueError("list_families takes no value")
        url = _MALPEDIA_BASE + template
    elif endpoint == "find_actor":
        url = _MALPEDIA_BASE + template.format(value=quote(_check_needle(value), safe=""))
    elif endpoint == "get_actor":
        if not is_malpedia_actor_id(value):
            raise ValueError("not a Malpedia actor id")
        url = _MALPEDIA_BASE + template.format(value=value)
    else:
        if not is_malpedia_family_id(value):
            raise ValueError("not a Malpedia family id")
        url = _MALPEDIA_BASE + template.format(value=value)
    if not malpedia_url_allowed(url):  # belt and braces: the builder and the checker must agree
        raise ValueError("built URL failed the allow-list check")
    return url


def malpedia_url_allowed(url):
    """FC2 / P327 lint: True only for https URLs of the four allow-listed endpoints.

    Used by the unit test over the module's URL set: every sample/YARA/download/scan path,
    query strings, fragments, encoded slashes, dot segments and other hosts are refused.
    """
    if not isinstance(url, str) or len(url) > 400:
        return False
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError:
        return False
    if p.scheme != "https" or (p.hostname or "") != MALPEDIA_HOST or port not in (None, 443):
        return False
    if p.username or p.password or p.query or p.fragment or ";" in p.path:
        return False
    path = p.path
    if "//" in path or "\\" in path:
        return False
    for _name, rx in _ALLOWED_PATHS:
        m = rx.match(path)
        if not m:
            continue
        v = m.groupdict().get("v")
        if v is not None:
            dec = unquote(v)
            if "/" in dec or "\\" in dec or "%" in dec or ".." in dec or dec.strip() != dec or not dec.strip("."):
                return False
            if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in dec):
                return False
        return True
    return False


def malpedia_auth_headers(token):
    """FC3: optional team-account token, Authorization header only ('apitoken <TOKEN>')."""
    if token is None or token == "":
        return {}
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_\-.:+=/]{8,256}", token):
        raise ValueError("token has an unexpected format")
    return {"Authorization": "apitoken " + token}


_NOT_FOUND_DETAIL = re.compile(r"^No \w+ matches the given query\.?$")


def malpedia_marker(status, body=None, headers=None):
    """P321-style marker for Malpedia answers. 404 'No X matches the given query.' is NOT a
    marker (not found -> EMPTY). DRF throttling (429) and auth errors map to markers.
    """
    if not isinstance(status, int):
        return "error: no HTTP status"
    text = _as_text(body) if not isinstance(body, (dict, list)) else ""
    detail = None
    if isinstance(body, dict):
        detail = _clean_str(body.get("detail"), 160) or None
    elif text.strip().startswith("{"):
        obj, m = load_json(text)
        if not m and isinstance(obj, dict):
            detail = _clean_str(obj.get("detail"), 160) or None
    if status == 404:
        if detail and _NOT_FOUND_DETAIL.match(detail):
            return None
        if looks_like_html(text):
            return "error: HTTP 404 HTML page (endpoint moved?)"
        return None if detail is None else "error: HTTP 404 (%s)" % detail
    if status == 429:
        ra = _retry_after(headers)
        return "rate_limited: HTTP 429" + (" (Retry-After %s)" % ra if ra else "") + (" - %s" % detail if detail else "")
    if status in (401, 403):
        if detail and re.search(r"token|credential|authenticat", detail, re.I):
            return "error: authentication failed (%s)" % detail
        return "blocked: HTTP %d" % status + (" (%s)" % detail if detail else "")
    if status >= 500:
        return "error: HTTP %d" % status
    if status != 200:
        return "error: HTTP %d" % status + (" (%s)" % detail if detail else "")
    if looks_like_html(text):
        return "error: HTML instead of JSON"
    if detail and not _NOT_FOUND_DETAIL.match(detail):
        return "error: API message in 200 (%s)" % detail
    return None


def malpedia_family_link(family_id):
    """Manual page (P300 pivot): /details/<family_id>."""
    return "%s/details/%s" % (_MALPEDIA_BASE, family_id) if is_malpedia_family_id(family_id) else None


def malpedia_actor_link(actor_id):
    """Manual page (P300 pivot): /actor/<actor_id>."""
    return "%s/actor/%s" % (_MALPEDIA_BASE, actor_id) if is_malpedia_actor_id(actor_id) else None


def extract_mitre_group_ids(*values):
    """ATT&CK group ids (G0007) from synonym lists and attack.mitre.org/groups/ URLs."""
    found = []
    for v in values:
        items = v if isinstance(v, list) else [v]
        for item in items:
            if not isinstance(item, str):
                continue
            s = item.strip()
            gid = s.upper() if _GROUP_ID_RE.match(s.upper()) else None
            if gid is None:
                m = _GROUP_URL_RE.search(s)
                gid = m.group(1).upper() if m else None
            if gid and gid not in found:
                found.append(gid)
    return found


def _is_http_url(u):
    if not isinstance(u, str):
        return False
    s = u.strip()
    if len(s) > 2048 or any(ord(ch) < 0x21 for ch in s):
        return False
    try:
        p = urlsplit(s)
    except ValueError:
        return False
    return p.scheme in ("http", "https") and bool(p.hostname)


def rank_reference_urls(urls, limit=None):
    """Report links: http(s) only, de-duplicated, newest year in the path first (heuristic),
    then alphabetical. Malpedia returns them alphabetically with no dates."""
    seen, clean = set(), []
    for u in urls if isinstance(urls, list) else []:
        if _is_http_url(u):
            s = u.strip()
            if s not in seen:
                seen.add(s)
                clean.append(s)

    def key(u):
        years = [int(y) for y in _YEAR_RE.findall(urlsplit(u).path)]
        return (-(max(years) if years else 0), u)

    clean.sort(key=key)
    return clean[:limit] if limit is not None else clean


def parse_malpedia_families_list(raw):
    """FC5: /api/list/families -> {'ids': [...], 'count', 'platforms', 'invalid', 'marker'}."""
    obj, marker = load_json(raw)
    out = {"ids": [], "count": 0, "platforms": {}, "invalid": [], "marker": marker}
    if marker:
        return out
    if not isinstance(obj, list):
        out["marker"] = "error: unexpected JSON shape (%s)" % type(obj).__name__
        return out
    ids, seen = [], set()
    for item in obj:
        if is_malpedia_family_id(item):
            if item not in seen:
                seen.add(item)
                ids.append(item)
        else:
            out["invalid"].append(_clean_str(str(item), 80))
    platforms = {}
    for i in ids:
        p = i.split(".", 1)[0]
        platforms[p] = platforms.get(p, 0) + 1
    out.update(ids=ids, count=len(ids), platforms=dict(sorted(platforms.items())))
    return out


def parse_malpedia_find_actor(raw, status=200, headers=None, max_synonyms=50):
    """FC2 find/actor: -> {'actors': [{actor_id, common_name, synonyms, mitre_group_ids, link}],
    'empty', 'marker'}. Defensive about the documented future change (synonyms may gain the
    name-creator)."""
    out = {"actors": [], "empty": True, "marker": None}
    marker = malpedia_marker(status, raw, headers) if status != 200 or not isinstance(raw, (list, dict)) else None
    if status == 404 and marker is None:
        return out
    if marker:
        out["marker"] = marker
        return out
    obj, marker = load_json(raw)
    if marker:
        out["marker"] = marker
        return out
    if not isinstance(obj, list):
        out["marker"] = "error: unexpected JSON shape (%s)" % type(obj).__name__
        return out
    for a in obj:
        if not isinstance(a, dict):
            continue
        aid = _clean_str(a.get("name"))
        if not is_malpedia_actor_id(aid):
            continue
        syn = a.get("synonyms")
        if isinstance(syn, dict):  # possible future shape {"creator": "name"}
            syn = [v for v in syn.values() if isinstance(v, str)]
        synonyms = _str_list(syn, limit=max_synonyms)
        out["actors"].append({
            "actor_id": aid,
            "common_name": _clean_str(a.get("common_name"), 120) or aid,
            "synonyms": synonyms,
            "mitre_group_ids": extract_mitre_group_ids(synonyms),
            "link": malpedia_actor_link(aid),
        })
    out["empty"] = not out["actors"]
    return out


def parse_malpedia_actor(raw, actor_id=None, status=200, headers=None, max_refs=10, max_families=None):
    """FC2/FC4 get/actor/<id> -> actor card (live detail) with family pivots.

    Returns {'actor_id', 'name', 'uuid', 'description', 'country', 'synonyms',
    'mitre_group_ids', 'refs', 'ref_count', 'families': [...], 'related': [...], 'cfr': {...},
    'attribution_confidence', 'link', 'pivots', 'empty', 'not_found', 'marker'}.
    """
    out = {"actor_id": actor_id if is_malpedia_actor_id(actor_id) else None, "name": "", "uuid": None,
           "description": "", "country": None, "synonyms": [], "mitre_group_ids": [], "refs": [],
           "ref_count": 0, "families": [], "related": [], "cfr": {}, "attribution_confidence": None,
           "link": malpedia_actor_link(actor_id), "pivots": [], "empty": True, "not_found": False,
           "marker": None}
    marker = malpedia_marker(status, raw, headers) if not isinstance(raw, (dict, list)) or status != 200 else None
    if status == 404 and marker is None:
        out["not_found"] = True
        return out
    if marker:
        out["marker"] = marker
        return out
    obj, marker = load_json(raw)
    if marker:
        out["marker"] = marker
        return out
    if not isinstance(obj, dict):
        out["marker"] = "error: unexpected JSON shape (%s)" % type(obj).__name__
        return out
    if "detail" in obj and len(obj) == 1:
        m = malpedia_marker(200, obj)
        if m:
            out["marker"] = m
        else:
            out["not_found"] = True
        return out
    meta = obj.get("meta") if isinstance(obj.get("meta"), dict) else {}
    out["name"] = _clean_str(obj.get("value"), 120)
    uid = _clean_str(obj.get("uuid"))
    out["uuid"] = uid if re.fullmatch(r"[0-9a-f\-]{36}", uid or "") else None
    out["description"] = _clean_str(obj.get("description"), 600)
    country = _clean_str(meta.get("country"))
    out["country"] = country.upper() if re.fullmatch(r"[A-Za-z]{2}", country or "") else None
    out["synonyms"] = _str_list(meta.get("synonyms"), limit=60)
    refs = rank_reference_urls(meta.get("refs") if isinstance(meta.get("refs"), list) else [])
    out["ref_count"] = len(refs)
    out["refs"] = refs[:max_refs] if max_refs is not None else refs
    out["mitre_group_ids"] = extract_mitre_group_ids(out["synonyms"], meta.get("refs") if isinstance(meta.get("refs"), list) else [])
    conf = _clean_str(meta.get("attribution-confidence"))
    out["attribution_confidence"] = int(conf) if conf.isdigit() and int(conf) <= 100 else None
    cfr = {}
    for k in ("cfr-suspected-state-sponsor", "cfr-type-of-incident"):
        v = _clean_str(meta.get(k), 120)
        if v:
            cfr[k[4:]] = v
    for k in ("cfr-suspected-victims", "cfr-target-category"):
        v = _str_list(meta.get(k), limit=30)
        if v:
            cfr[k[4:]] = v
    out["cfr"] = cfr
    rel = []
    for r in obj.get("related") if isinstance(obj.get("related"), list) else []:
        if not isinstance(r, dict):
            continue
        dest = _clean_str(r.get("dest-uuid"))
        if not re.fullmatch(r"[0-9a-f\-]{36}", dest or ""):
            continue
        likelihood = None
        for t in r.get("tags") if isinstance(r.get("tags"), list) else []:
            m = re.search(r'likelihood-probability="([a-z\- ]+)"', t) if isinstance(t, str) else None
            if m:
                likelihood = m.group(1)
        rel.append({"uuid": dest, "type": _clean_str(r.get("type"), 40) or "related", "likelihood": likelihood})
    out["related"] = rel
    fams = obj.get("families") if isinstance(obj.get("families"), dict) else {}
    cards = []
    for fid in sorted(fams):
        f = fams[fid]
        if not is_malpedia_family_id(fid) or not isinstance(f, dict):
            continue
        urls = f.get("urls") if isinstance(f.get("urls"), list) else []
        cards.append({
            "family_id": fid,
            "common_name": _clean_str(f.get("common_name"), 120) or fid,
            "alt_names": _str_list(f.get("alt_names"), limit=20),
            "attribution": _str_list(f.get("attribution"), limit=20),
            "updated": _clean_str(f.get("updated"))[:10] or None,
            "url_count": sum(1 for u in urls if _is_http_url(u)),
            "link": malpedia_family_link(fid),
        })
    cards.sort(key=lambda c: (c["updated"] or "", c["family_id"]), reverse=True)
    out["families"] = cards[:max_families] if max_families is not None else cards
    out["pivots"] = [("malware_family", c["family_id"]) for c in out["families"]]
    out["empty"] = not (out["name"] or out["families"])
    return out


def parse_malpedia_family(raw, family_id=None, status=200, headers=None, max_urls=10):
    """FC2/FC4 get/family/<id> -> family card (the response body carries no id: pass it in).

    Returns {'family_id', 'platform', 'common_name', 'alt_names', 'attribution',
    'description', 'updated', 'uuid', 'urls' (ranked, capped), 'url_count', 'link', 'pivots',
    'empty', 'not_found', 'marker'}. Attribution entries are actor NAMES (e.g. 'MUMMY SPIDER'),
    so the threat_actor pivots carry names; P295 resolves them to ids.
    """
    fid = family_id if is_malpedia_family_id(family_id) else None
    out = {"family_id": fid, "platform": fid.split(".", 1)[0] if fid else None, "common_name": "",
           "alt_names": [], "attribution": [], "description": "", "updated": None, "uuid": None,
           "urls": [], "url_count": 0, "link": malpedia_family_link(fid), "pivots": [],
           "empty": True, "not_found": False, "marker": None}
    marker = malpedia_marker(status, raw, headers) if not isinstance(raw, (dict, list)) or status != 200 else None
    if status == 404 and marker is None:
        out["not_found"] = True
        return out
    if marker:
        out["marker"] = marker
        return out
    obj, marker = load_json(raw)
    if marker:
        out["marker"] = marker
        return out
    if not isinstance(obj, dict):
        out["marker"] = "error: unexpected JSON shape (%s)" % type(obj).__name__
        return out
    if "detail" in obj and len(obj) == 1:
        m = malpedia_marker(200, obj)
        if m:
            out["marker"] = m
        else:
            out["not_found"] = True
        return out
    urls = rank_reference_urls(obj.get("urls") if isinstance(obj.get("urls"), list) else [])
    uid = _clean_str(obj.get("uuid"))
    out.update(
        common_name=_clean_str(obj.get("common_name"), 120) or (fid or ""),
        alt_names=_str_list(obj.get("alt_names"), limit=30),
        attribution=_str_list(obj.get("attribution"), limit=30),
        description=_clean_str(obj.get("description"), 600),
        updated=_clean_str(obj.get("updated"))[:10] or None,
        uuid=uid if re.fullmatch(r"[0-9a-f\-]{36}", uid or "") else None,
        url_count=len(urls),
        urls=urls[:max_urls] if max_urls is not None else urls,
    )
    out["pivots"] = [("threat_actor", a) for a in out["attribution"]]
    out["empty"] = not (out["common_name"] or out["urls"])
    return out


def _name_key(s):
    s = unicodedata.normalize("NFKC", s or "").casefold()
    return re.sub(r"[\W_]+", "", s)


def parse_galaxy_malpedia_cluster(raw):
    """FC4 corporate path: MISP galaxy 'malpedia' cluster (CC0/BSD, bundled by P295) ->
    {'version', 'count', 'families': {family_id: {value, uuid, synonyms, refs, details_url}},
    'by_name': {name_key: [family_ids]}, 'marker'}. Reference URLs = refs minus Malpedia links.
    """
    obj, marker = load_json(raw)
    out = {"version": None, "count": 0, "families": {}, "by_name": {}, "marker": marker}
    if marker:
        return out
    if not isinstance(obj, dict) or not isinstance(obj.get("values"), list):
        out["marker"] = "error: not a MISP galaxy cluster"
        return out
    if obj.get("type") not in (None, "malpedia"):
        out["marker"] = "error: galaxy cluster type is %r, expected 'malpedia'" % (obj.get("type"),)
        return out
    out["version"] = obj.get("version") if isinstance(obj.get("version"), int) else None
    fams, by_name = {}, {}
    for v in obj["values"]:
        if not isinstance(v, dict):
            continue
        meta = v.get("meta") if isinstance(v.get("meta"), dict) else {}
        refs = meta.get("refs") if isinstance(meta.get("refs"), list) else []
        ids, others = [], []
        for r in refs:
            m = _DETAILS_RE.match(r.strip()) if isinstance(r, str) else None
            if m:
                if m.group(1) not in ids:
                    ids.append(m.group(1))
            elif _is_http_url(r):
                others.append(r.strip())
        if not ids:
            continue
        value = _clean_str(v.get("value"), 120)
        synonyms = _str_list(meta.get("synonyms"), limit=40)
        for fid in ids:
            fams[fid] = {"value": value, "uuid": _clean_str(v.get("uuid")) or None, "synonyms": synonyms,
                         "refs": rank_reference_urls(others), "details_url": malpedia_family_link(fid)}
            for name in [value] + synonyms:
                k = _name_key(name)
                if k:
                    lst = by_name.setdefault(k, [])
                    if fid not in lst:
                        lst.append(fid)
    out.update(count=len(fams), families=dict(sorted(fams.items())),
               by_name={k: sorted(v) for k, v in sorted(by_name.items())})
    return out


def resolve_malpedia_family_ids(name, family_ids=None, galaxy=None, limit=5):
    """Map a malware_family/keyword input to Malpedia family ids WITHOUT find/family (not in the
    FC2 allow-list): explicit id, then the galaxy cluster (FC4), then the cached list/families
    by name part. Returns [{'family_id', 'how'}] (how: id | galaxy | list-name).
    """
    if not isinstance(name, str) or not name.strip():
        return []
    s = unicodedata.normalize("NFKC", name).strip()
    known = set(family_ids) if isinstance(family_ids, (list, set, tuple)) else None
    out = []

    def add(fid, how):
        if fid not in [o["family_id"] for o in out]:
            out.append({"family_id": fid, "how": how})

    low = s.lower()
    if is_malpedia_family_id(low):
        add(low, "id" if known is None or low in known else "id (not in list/families)")
        return out[:limit]
    if isinstance(galaxy, dict) and isinstance(galaxy.get("by_name"), dict):
        for fid in galaxy["by_name"].get(_name_key(s), []):
            add(fid, "galaxy")
    if known:
        key = _name_key(s)
        for fid in sorted(known):
            if _name_key(fid.split(".", 1)[1]) == key:
                add(fid, "list-name")
    return out[:limit]


def malpedia_source_tlp(used_token, item_id=None, public_ids=None):
    """FC3: source TLP of a Malpedia item. Keyless answers are public ('clear'); anything fetched
    with the team token is 'amber' unless the same id is also in the keyless public set."""
    if not used_token:
        return "clear"
    if item_id is not None and isinstance(public_ids, (set, list, tuple)) and item_id in public_ids:
        return "clear"
    return "amber"


def split_token_tier_urls(public_urls, token_urls):
    """FC3 refinement when both answers exist: URLs only visible with the token are AMBER.
    Returns {'clear': [...], 'amber': [...]} (http(s) only, order kept)."""
    pub = set(u.strip() for u in public_urls or [] if _is_http_url(u))
    clear, amber = [], []
    for u in token_urls or []:
        if not _is_http_url(u):
            continue
        u = u.strip()
        (clear if u in pub else amber).append(u)
    return {"clear": clear, "amber": amber}
