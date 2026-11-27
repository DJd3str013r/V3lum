"""Internal TIP sightings (P348): read-only lookups in the company's MISP, OpenCTI and TheHive.

Three adapters share this file (one source family): ``misp_sightings`` (MISP 2.5 restSearch),
``opencti_sightings`` (OpenCTI 7.x GraphQL) and ``thehive_sightings`` (TheHive 6 query API, the P2
adapter of A12). Final conditions of P348 implemented here:

* FC1 plain HTTP clients through ``ctx.http`` (no PyMISP/pycti), each enabled only when its URL
  setting (``misp_url``, ``opencti_url``, ``thehive_sightings_url``) and its key (``misp``,
  ``opencti``, ``thehive``; ``v3lum keys``) are configured: no URL -> SKIPPED ``config``, no key ->
  NEEDS_KEY. Synthetic fixtures exist for the documented versions (MISP 2.5, OpenCTI 7.x,
  TheHive 6.0), so all three land.
* FC2 disclosure ``internal`` (allowed at TLP:RED) through ``internal: true`` providers whose host
  comes only from the URL setting; a URL whose host another (third-party) provider owns is never an
  internal host (core ``hosts_for``), so community/ISAC instances must be registered as third-party
  providers. Hits that came through a MISP sharing group are marked as such.
* FC3 TLS verification is always on (core client, setting ``ca_bundle``; nothing here can turn it
  off). Read-only in code: :func:`misp_request_allowed`, :func:`opencti_query_allowed` and
  :func:`thehive_request_allowed` are checked before every request (add/edit/publish, mutations and
  write paths are refused, unit-tested). At most once a day per instance a startup check reads the
  key's own permissions and warns (live feed, evidence, ``health_check`` self-test) when the key can
  write.
* FC4 values travel only in JSON bodies or GraphQL variables, never in a URL; <= 50 results per
  value; <= 2 requests/s per platform (``min_interval`` 0.5 s); 5 s per lookup (run deadline and
  request timeout); any failure is 'could not verify', never 'not known'.
* FC5 MISP: ``to_ids=false`` attributes are context only (no malicious tag); decayed/deleted
  attributes and expiration sightings are historical; false-positive sightings and warninglist hits
  are honoured. OpenCTI: ``x_opencti_score``, ``revoked`` and ``valid_until`` (expired ->
  historical, low).
* FC6 every hit carries its event/case id, org, TLP/marking and date (finding data); the highest
  marking is kept on the result (``res.set_marking``, never downgraded) and :func:`finding_tlp` /
  :func:`visible_in_report` give the per-finding rule for renderers (``Finding.tlp`` is requested
  from the core).
* FC7 galaxy/actor tags and OpenCTI relations become ``attributed_to`` (actors, malware, tools) or
  ``uses_technique`` pivots with ``expand=False``, names unchanged. No write-back, sightings or
  sharing from V3LUM.
* FC8 a covert exercise (``ScanOptions.covert`` / ``no_internal``, requested from the core CLI as
  ``--covert``/``--no-internal``) skips every internal lookup (SKIPPED ``policy``).
* FC9 :func:`internal_sightings_line` builds 'known internally: MISP event #N, TheHive case #M' in
  the query order case DB -> MISP/OpenCTI -> TheHive (TLP-filtered) for the report header; the
  findings carry the tag ``internal_sighting`` so renderers can list them first.

Personal data minimisation: creator/updater logins, assignees, the service account's e-mail and
free-text comments are never copied into results.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import HttpError, NetworkError, PolicyError
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, HealthResult, Module, register

TIMEOUT = 5.0  # FC4 / A12: TIP lookups time out after 5 s
MIN_INTERVAL = 0.5  # FC4: <= 2 requests/s per platform
MAX_RESULTS = 50  # FC4: <= 50 results per value
KEY_CHECK_TTL = timedelta(days=1)
#: the daily key check never eats the 5 s lookup budget
KEY_CHECK_TIMEOUT = 2.0
TLP_ORDER = ("clear", "green", "amber", "amber+strict", "red")
#: FC9 query/report order of internal sources
INTERNAL_QUERY_ORDER = ("case_db", "misp", "opencti", "thehive")
COVERT_REASON = "covert exercise (--covert / --no-internal): internal TIP lookups skipped"
IDENTIFICATION_KEYS = ("platform", "ref", "org", "tlp", "date", "verdict")

MISP_SOURCE = "internal_misp.events"
OPENCTI_SOURCE = "internal_opencti.graphql"
THEHIVE_SOURCE = "internal_thehive.query"

_TID = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")


# ======================================================================================
# shared helpers (TLP, covert flag, untrusted values)
# ======================================================================================


def normalize_tlp(label: Any) -> str | None:
    """'tlp:amber' / 'TLP:AMBER+STRICT' / 'Amber' / 'WHITE' -> TLP 2.0 value (white -> clear)."""
    if not isinstance(label, str):
        return None
    t = re.sub(r"^tlp\s*[:\-_ ]?\s*", "", label.strip().lower())
    t = t.replace(" ", "").replace("_", "+").replace("-", "+")
    if t in ("white", "clear"):
        return "clear"
    if t in ("amber+strict", "amberstrict"):
        return "amber+strict"
    return t if t in TLP_ORDER else None


def tlp_max(*labels: Any) -> str | None:
    """The most restrictive TLP among ``labels`` (unparseable values ignored)."""
    best: str | None = None
    for label in labels:
        t = normalize_tlp(label)
        if t and (best is None or TLP_ORDER.index(t) > TLP_ORDER.index(best)):
            best = t
    return best


def finding_tlp(source_tlp: Any, case_tlp: Any) -> str | None:
    """FC6: the higher of platform/source and case TLP applies; markings are never downgraded."""
    return tlp_max(source_tlp, case_tlp)


def visible_in_report(item_tlp: Any, report_tlp: Any) -> bool:
    """FC6: a renderer omits a hit whose marking is above the report TLP."""
    item = normalize_tlp(item_tlp)
    if item is None:
        return True
    report = normalize_tlp(report_tlp) or "clear"
    return TLP_ORDER.index(item) <= TLP_ORDER.index(report)


_VERDICT_NOTE = {"false_positive": "false positive", "warninglist": "warninglist", "historical": "historical", "context": "context only", "observed": "context only"}


def internal_sightings_line(hits_by_platform: dict[str, list[dict[str, Any]]], report_tlp: Any = None) -> str | None:
    """FC9: 'known internally: MISP event #N, TheHive case #M' in the order case DB -> MISP/OpenCTI ->
    TheHive; hits above ``report_tlp`` are left out (FC6). For the report header (core renderer)."""
    parts: list[str] = []
    for platform in INTERNAL_QUERY_ORDER:
        for hit in (hits_by_platform or {}).get(platform) or []:
            if not isinstance(hit, dict):
                continue
            if report_tlp is not None and not visible_in_report(hit.get("tlp"), report_tlp):
                continue
            ref = hit.get("ref")
            note = _VERDICT_NOTE.get(str(hit.get("verdict") or ""))
            if ref and note:
                ref = f"{ref} ({note})"
            if ref and ref not in parts:
                parts.append(ref)
    return "known internally: " + ", ".join(parts) if parts else None


def covert_refusal(options: Any) -> str | None:
    """FC8: a covert red-team case skips every internal lookup (TIP query logs would show the SOC
    the red team's own infrastructure)."""
    if getattr(options, "covert", False) or getattr(options, "no_internal", False):
        return COVERT_REASON
    return None


def base_url(value: Any, setting: str) -> tuple[str | None, str]:
    """(base URL without a trailing slash, '') for a valid https URL setting; else (None, problem)."""
    raw = str(value or "").strip()
    if not raw:
        return None, f"setting {setting} is not set: the read-only adapter is disabled (v3lum config set {setting} https://...)"
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None, f"setting {setting} is not a valid URL"
    if parts.scheme != "https" or not parts.hostname:
        return None, f"setting {setting} must be an https URL (TLS verification is always on, A12)"
    if parts.username or parts.password or parts.query or parts.fragment:
        return None, f"setting {setting} must not carry credentials, a query or a fragment"
    return raw.rstrip("/"), ""


def _path_only(path: Any) -> str:
    p = str(path or "")
    if re.match(r"^https?://", p):
        p = re.sub(r"^https?://[^/]+", "", p)
    return p


def _text(value: Any, limit: int = 300) -> str | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str):
        return None
    v = value.strip()
    return v[:limit] if v else None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def _boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y", "on")
    return False


def _epoch_iso(value: Any, *, millis: bool = False) -> str | None:
    if isinstance(value, bool):
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    if millis:
        seconds /= 1000.0
    if seconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        m = re.match(r"^(\d{4}-\d{2}-\d{2})", text)
        if not m:
            return None
        try:
            dt = datetime.fromisoformat(m.group(1))
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _iso(value: Any) -> str | None:
    dt = _parse_iso(value)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def _same_value(stored: Any, value: str, *, composite: bool = False) -> bool:
    """Exact (case-insensitive) match; URLs ignore a trailing slash; MISP composite values (a|b)
    match on any part. Platform value filters accept wildcards: results are post-filtered."""
    if not isinstance(stored, str):
        return False
    want = value.strip().casefold()
    parts = stored.split("|") if composite else [stored]
    for part in parts:
        got = part.strip().casefold()
        if got == want or (got.rstrip("/") == want.rstrip("/") and "://" in want):
            return True
    return False


# ======================================================================================
# MISP 2.5 (restSearch)
# ======================================================================================

_MISP_ALLOWED = (
    ("POST", re.compile(r"/attributes/restSearch")),
    ("POST", re.compile(r"/events/restSearch")),
    ("POST", re.compile(r"/sightings/restSearch/attribute")),
    ("GET", re.compile(r"/sightings/index/\d{1,10}")),
    ("GET", re.compile(r"/users/view/me")),
    ("GET", re.compile(r"/servers/getVersion")),
)
_MISP_WRITE_PERMS = (
    "perm_add", "perm_modify", "perm_modify_org", "perm_publish", "perm_delegate", "perm_sync", "perm_admin",
    "perm_site_admin", "perm_regexp_access", "perm_tagger", "perm_template", "perm_sharing_group", "perm_tag_editor",
    "perm_sighting", "perm_object_template", "perm_publish_zmq", "perm_publish_kafka", "perm_decaying",
    "perm_galaxy_editor", "perm_warninglist", "perm_analyst_data", "perm_server_sign",
)
_GALAXY = re.compile(r'^misp-galaxy:([a-z0-9\-]+)="(.+)"$', re.I)
_ACTOR_GALAXIES = frozenset({"threat-actor", "mitre-intrusion-set", "microsoft-activity-group", "mitre-enterprise-attack-intrusion-set", "tidal-groups"})
_MALWARE_GALAXIES = frozenset({
    "malpedia", "mitre-malware", "ransomware", "banker", "rat", "stealer", "botnet", "backdoor", "android",
    "mitre-enterprise-attack-malware", "tidal-software", "exploit-kit",
})
_TOOL_GALAXIES = frozenset({"tool", "mitre-tool", "mitre-enterprise-attack-tool"})
_TECHNIQUE_GALAXIES = frozenset({"mitre-attack-pattern", "mitre-enterprise-attack-attack-pattern", "mitre-mobile-attack-attack-pattern", "mitre-ics-techniques"})
_MISP_THREAT_LEVEL = {"1": "high", "2": "medium", "3": "low", "4": "medium"}


def misp_request_allowed(method: str, path: str, body: Any = None) -> str | None:
    """FC3/FC4: the read-only MISP allow-list (restSearch, sightings reads, users/view/me,
    getVersion). Values never travel in the path or the query string."""
    m = (method or "").upper()
    p = _path_only(path)
    if "?" in p or "#" in p:
        return "MISP values travel only in JSON bodies (query string refused)"
    p = p.rstrip("/") or "/"
    for allowed_method, rx in _MISP_ALLOWED:
        if m == allowed_method and rx.fullmatch(p):
            return None
    return f"MISP {m} {p} is not on the read-only allow-list"


def misp_attribute_search_body(value: str, limit: int = MAX_RESULTS, page: int = 1) -> dict[str, Any]:
    """FC4/FC5: POST /attributes/restSearch body (the value only here; limit 1..50, never 0 = 'all')."""
    try:
        n = int(limit)
    except (TypeError, ValueError):
        n = MAX_RESULTS
    n = MAX_RESULTS if n <= 0 else min(n, MAX_RESULTS)
    return {
        "value": value, "limit": n, "page": max(1, int(page or 1)), "includeEventTags": 1, "includeSightings": 1,
        "includeDecayScore": 1, "includeWarninglistHits": 1, "returnFormat": "json",
    }


def misp_event_metadata_body(event_ids: list[Any]) -> dict[str, Any]:
    """FC6: creator org (Orgc), date, threat level and tags of the hit events (metadata only)."""
    ids: list[str] = []
    for e in event_ids or []:
        s = str(e)
        if s.isdigit() and s not in ids:
            ids.append(s)
    return {"eventid": ids[:MAX_RESULTS], "metadata": 1, "limit": MAX_RESULTS, "returnFormat": "json"}


def misp_galaxy_pivots(tags: list[Any]) -> list[dict[str, Any]]:
    """FC7: galaxy tags -> attributed_to pivots (actors, malware, tools) and uses_technique pivots
    (ATT&CK patterns); cluster names are kept unchanged for STIX/MISP round-trips."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for tag in tags or []:
        name = tag.get("name") if isinstance(tag, dict) else tag
        m = _GALAXY.match(name) if isinstance(name, str) else None
        if not m:
            continue
        galaxy, cluster = m.group(1).lower(), m.group(2)
        if galaxy in _ACTOR_GALAXIES:
            piv = {"type": "threat_actor", "value": cluster, "relation": "attributed_to"}
        elif galaxy in _MALWARE_GALAXIES or galaxy in _TOOL_GALAXIES:
            piv = {"type": "malware_family", "value": cluster, "relation": "attributed_to"}
        elif galaxy in _TECHNIQUE_GALAXIES:
            tid = _TID.search(cluster)
            if not tid:
                continue
            piv = {"type": "mitre_technique", "value": tid.group(1), "relation": "uses_technique"}
        else:
            continue
        key = (piv["type"], piv["value"])
        if key not in seen:
            seen.add(key)
            out.append({**piv, "galaxy": galaxy})
    return out


def misp_sightings_summary(sightings: Any) -> dict[str, Any]:
    """FC5: sighting type '0' sighting, '1' false positive, '2' expiration -> counts and last dates."""
    out: dict[str, Any] = {"sightings": 0, "false_positives": 0, "expirations": 0, "last_sighting": None, "last_false_positive": None, "last_expiration": None}
    names = {"0": ("sightings", "last_sighting"), "1": ("false_positives", "last_false_positive"), "2": ("expirations", "last_expiration")}
    for s in sightings if isinstance(sightings, list) else []:
        if not isinstance(s, dict):
            continue
        key = names.get(str(s.get("type", "0")))
        if not key:
            continue
        out[key[0]] += 1
        when = _epoch_iso(s.get("date_sighting"))
        if when and (out[key[1]] is None or when > out[key[1]]):
            out[key[1]] = when
    return out


def misp_decay_summary(scores: Any) -> dict[str, Any] | None:
    """FC5: decay_score list -> {'score', 'decayed', 'models'}; decayed only when every model decayed."""
    items = [s for s in scores if isinstance(s, dict)] if isinstance(scores, list) else []
    values: list[tuple[float, bool]] = []
    for s in items:
        try:
            values.append((float(s.get("score")), _boolish(s.get("decayed"))))
        except (TypeError, ValueError):
            continue
    if not values:
        return None
    live = [v for v, decayed in values if not decayed]
    models = [str(s["DecayingModel"].get("name")) for s in items if isinstance(s.get("DecayingModel"), dict) and s["DecayingModel"].get("name")]
    return {"score": round(max(live or [v for v, _ in values]), 2), "decayed": all(decayed for _, decayed in values), "models": models}


def _misp_verdict(to_ids: bool, deleted: bool, decay: dict[str, Any] | None, sight: dict[str, Any], warnings: list[str]) -> tuple[str, list[str]]:
    flags = []
    if deleted:
        flags.append("deleted")
    if warnings:
        flags.append("warninglist")
    decayed = bool(decay and decay.get("decayed"))
    if decayed:
        flags.append("decayed")
    if sight["false_positives"]:
        flags.append("false_positive_reported")
    if sight["expirations"]:
        flags.append("expiration_sighting")
    if not to_ids:
        flags.append("to_ids_false")
    fp_newest = bool(sight["false_positives"]) and (not sight["sightings"] or (sight["last_false_positive"] or "") >= (sight["last_sighting"] or ""))
    if fp_newest:
        return "false_positive", flags
    if warnings:
        return "warninglist", flags
    if deleted or decayed or sight["expirations"]:
        return "historical", flags
    if not to_ids:
        return "context", flags
    return "listed", flags


def parse_misp_attributes(body: Any, value: str) -> dict[str, Any] | None:
    """FC5-FC7: /attributes/restSearch answer -> hits (<= 50), exact value matches only; None when
    the answer is not a restSearch answer (could not verify)."""
    if not isinstance(body, dict):
        return None
    resp = body.get("response")
    if isinstance(resp, dict):
        attrs = resp.get("Attribute")
    elif isinstance(resp, list) and not resp:
        attrs = []
    else:
        attrs = None
    if not isinstance(attrs, list):
        return None
    hits = []
    for a in attrs[:MAX_RESULTS]:
        if not isinstance(a, dict) or not _same_value(a.get("value"), value, composite="|" in str(a.get("type") or "")):
            continue
        tags = [t.get("name") for t in a.get("Tag") or [] if isinstance(t, dict) and isinstance(t.get("name"), str)]
        event = a.get("Event") if isinstance(a.get("Event"), dict) else {}
        sight = misp_sightings_summary(a.get("Sighting"))
        decay = misp_decay_summary(a.get("decay_score"))
        warn_src = a.get("warnings") or a.get("Warninglist") or []
        warnings: list[str] = []
        for w in warn_src if isinstance(warn_src, list) else []:
            name = _text(w.get("warninglist_name") or w.get("name"), 200) if isinstance(w, dict) else None
            if name and name not in warnings:
                warnings.append(name)
        to_ids = _boolish(a.get("to_ids"))
        verdict, flags = _misp_verdict(to_ids, _boolish(a.get("deleted")), decay, sight, warnings)
        event_id = _text(a.get("event_id") or event.get("id"), 20)
        ts = _epoch_iso(a.get("timestamp"))
        hits.append({
            "platform": "misp",
            "attribute_id": _text(a.get("id"), 20),
            "attribute_uuid": _text(a.get("uuid"), 40),
            "type": _text(a.get("type"), 60),
            "category": _text(a.get("category"), 80),
            "to_ids": to_ids,
            "event_id": event_id,
            "event_uuid": _text(event.get("uuid"), 40),
            "event_info": _text(event.get("info"), 200),
            "tlp": tlp_max(*[t for t in tags if t.lower().startswith("tlp:")]),
            "tags": [t for t in tags if not t.lower().startswith(("tlp:", "misp-galaxy:"))][:20],
            "sightings": sight,
            "decay": decay,
            "warninglists": warnings,
            "verdict": verdict,
            "flags": flags,
            "pivots": misp_galaxy_pivots(tags),
            "ref": f"MISP event #{event_id}" if event_id else "MISP attribute",
            "date": ts[:10] if ts else None,
            "timestamp": ts,
            "org": None,
            "threat_level": None,
            "sharing_group": None,
        })
    return {"hits": hits, "truncated": len(attrs) > MAX_RESULTS}


def misp_apply_event_metadata(hits: list[dict[str, Any]], events_body: Any) -> list[dict[str, Any]]:
    """FC6: org (Orgc), event date, threat level, sharing group and event TLP tags (which can only
    raise a hit's TLP, never lower it)."""
    events: dict[str, dict[str, Any]] = {}
    resp = events_body.get("response") if isinstance(events_body, dict) else None
    for item in resp if isinstance(resp, list) else []:
        e = item.get("Event") if isinstance(item, dict) else None
        if isinstance(e, dict) and e.get("id") is not None:
            events[str(e["id"])] = e
    out = []
    for hit in hits:
        h = dict(hit)
        e = events.get(str(h.get("event_id")))
        if e:
            orgc = e.get("Orgc") if isinstance(e.get("Orgc"), dict) else {}
            h["org"] = _text(orgc.get("name"), 120)
            h["date"] = _text(e.get("date"), 10) or h.get("date")
            h["threat_level"] = _MISP_THREAT_LEVEL.get(str(e.get("threat_level_id") or ""))
            etags = [t.get("name") for t in e.get("Tag") or [] if isinstance(t, dict) and isinstance(t.get("name"), str)]
            h["tlp"] = tlp_max(h.get("tlp"), *[t for t in etags if t.lower().startswith("tlp:")])
            if str(e.get("distribution")) == "4" or str(e.get("sharing_group_id") or "0") not in ("0", ""):
                h["sharing_group"] = _text(e.get("sharing_group_id"), 20) or "yes"
            for piv in misp_galaxy_pivots(etags):
                if piv not in h["pivots"]:
                    h["pivots"] = [*h["pivots"], piv]
        out.append(h)
    return out


def misp_key_write_perms(view_me: Any) -> list[str] | None:
    """FC3 startup check: write-capable permissions of the key (GET /users/view/me); None = unknown."""
    role = view_me.get("Role") if isinstance(view_me, dict) else None
    if not isinstance(role, dict):
        return None
    out = [p for p in _MISP_WRITE_PERMS if _boolish(role.get(p))]
    perm = str(role.get("permission") if role.get("permission") is not None else "")
    if perm and perm != "0":
        out.append(f"permission={perm}")
    return out


def misp_errors(body: Any) -> tuple[str, str] | None:
    """Errors inside a 200 MISP answer -> (status, reason)."""
    if isinstance(body, dict) and body.get("errors") and not body.get("response"):
        text = str(body.get("errors"))[:160]
        if any(w in text.lower() for w in ("authenticat", "api key", "authorization")):
            return "needs_key", f"MISP rejected the API key ({text})"
        return "error", f"MISP error: {text}: could not verify"
    return None


# ======================================================================================
# OpenCTI 7.x (GraphQL)
# ======================================================================================

OPENCTI_OBSERVABLE_QUERY = """query V3lumObservableSightings($filters: FilterGroup, $first: Int) {
  stixCyberObservables(filters: $filters, first: $first) {
    edges {
      node {
        id standard_id entity_type observable_value x_opencti_score created_at updated_at
        createdBy { id name entity_type }
        objectMarking { id definition_type definition x_opencti_order }
        objectLabel { id value }
        reports(first: 5) { edges { node { id name published objectMarking { definition_type definition x_opencti_order } } } }
        indicators(first: 10) { edges { node { id name pattern_type pattern valid_from valid_until revoked
          x_opencti_score x_opencti_detection confidence objectMarking { definition_type definition x_opencti_order } } } }
        stixCoreRelationships(first: 20) { edges { node { id relationship_type to {
          ... on BasicObject { id entity_type }
          ... on IntrusionSet { name } ... on ThreatActor { name } ... on Malware { name }
          ... on Tool { name } ... on AttackPattern { name x_mitre_id } } } } }
      }
    }
    pageInfo { globalCount hasNextPage endCursor }
  }
}"""
OPENCTI_ME_QUERY = "query V3lumMe { me { id capabilities { name } } }"
_OPENCTI_READ_CAPS = frozenset({"KNOWLEDGE", "EXPLORE", "KNOWLEDGE_KNGETEXPORT", "TAXIIAPI", "APIACCESS", "APIACCESS_USETOKEN"})
_OPENCTI_ACTORS = frozenset({"Intrusion-Set", "Threat-Actor-Group", "Threat-Actor-Individual", "Threat-Actor"})
_OPENCTI_MALWARE = frozenset({"Malware", "Tool"})


def _strip_graphql(doc: str) -> str:
    out = re.sub(r'"""[\s\S]*?"""', '""', doc)
    out = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', out)
    return re.sub(r"#[^\n]*", "", out)


def opencti_query_allowed(document: Any, path: str = "/graphql") -> str | None:
    """FC3: OpenCTI queries without mutations: POST /graphql only; a top-level 'mutation' or
    'subscription' operation is refused (comments and string literals are ignored)."""
    if _path_only(path).rstrip("/") != "/graphql":
        return "OpenCTI is queried only through POST /graphql"
    if not isinstance(document, str) or not document.strip():
        return "empty GraphQL document"
    depth, top = 0, []
    for m in re.finditer(r"\{|\}|[A-Za-z_][A-Za-z0-9_]*", _strip_graphql(document)):
        token = m.group(0)
        if token == "{":
            depth += 1
        elif token == "}":
            depth = max(0, depth - 1)
        elif depth == 0:
            top.append(token)
    bad = [t for t in top if t in ("mutation", "subscription")]
    if bad:
        return f"OpenCTI {bad[0]} operations are refused (read-only adapter)"
    return None


def opencti_observable_request(value: str, first: int = 20) -> dict[str, Any]:
    """FC4: the value travels only in the GraphQL variables (exact 'value' filter)."""
    n = max(1, min(int(first or 20), MAX_RESULTS))
    return {
        "query": OPENCTI_OBSERVABLE_QUERY,
        "variables": {"filters": {"mode": "and", "filters": [{"key": ["value"], "values": [value], "operator": "eq", "mode": "or"}], "filterGroups": []}, "first": n},
    }


def opencti_errors(body: Any) -> tuple[str, str] | None:
    """GraphQL errors arrive with HTTP 200 (error in 200): AUTH_REQUIRED / FORBIDDEN -> needs_key."""
    errors = body.get("errors") if isinstance(body, dict) else None
    if not isinstance(errors, list) or not errors:
        return None
    first = errors[0] if isinstance(errors[0], dict) else {}
    msg = _text(first.get("message"), 160) or "GraphQL error"
    ext = first.get("extensions") if isinstance(first.get("extensions"), dict) else {}
    code = str(ext.get("code") or "")
    if code in ("AUTH_REQUIRED", "UNAUTHENTICATED") or "logged in" in msg.lower():
        return "needs_key", f"OpenCTI rejected the token ({msg})"
    if code in ("FORBIDDEN_ACCESS", "FORBIDDEN") or "not allowed" in msg.lower():
        return "needs_key", f"the OpenCTI token lacks a capability ({msg})"
    return "error", f"OpenCTI GraphQL error ({code or 'no code'}: {msg}): could not verify"


def _markings(markings: Any) -> tuple[str | None, str | None]:
    tlp, pap = [], []
    for mk in markings if isinstance(markings, list) else []:
        if not isinstance(mk, dict):
            continue
        kind = str(mk.get("definition_type") or "").upper()
        definition = str(mk.get("definition") or "")
        if kind == "TLP" or definition.upper().startswith("TLP:"):
            tlp.append(definition)
        elif kind == "PAP" or definition.upper().startswith("PAP:"):
            pap.append(definition.split(":", 1)[-1].lower())
    return tlp_max(*tlp), (pap[0] if pap else None)


def _edges(conn: Any) -> list[dict[str, Any]]:
    if isinstance(conn, dict) and isinstance(conn.get("edges"), list):
        return [e["node"] for e in conn["edges"] if isinstance(e, dict) and isinstance(e.get("node"), dict)]
    return []


def parse_opencti_observables(body: Any, value: str, now: datetime) -> dict[str, Any] | None:
    """FC5-FC7: stixCyberObservables answer -> hits with score, TLP/PAP (highest of observable,
    indicator and report markings), indicator states (revoked / expired by valid_until ->
    historical) and pivots; None when the answer is not an observables answer."""
    data = body.get("data") if isinstance(body, dict) else None
    conn = data.get("stixCyberObservables") if isinstance(data, dict) else None
    if not isinstance(conn, dict) or not isinstance(conn.get("edges"), list):
        return None
    hits = []
    for node in _edges(conn)[:MAX_RESULTS]:
        if not _same_value(node.get("observable_value"), value):
            continue
        obs_tlp, pap = _markings(node.get("objectMarking"))
        indicators = []
        for ind in _edges(node.get("indicators")):
            itlp, _ = _markings(ind.get("objectMarking"))
            until = _parse_iso(ind.get("valid_until"))
            state = "revoked" if _boolish(ind.get("revoked")) else ("expired" if until is not None and until < now else "active")
            indicators.append({
                "id": _text(ind.get("id"), 80), "name": _text(ind.get("name"), 200), "valid_until": _iso(ind.get("valid_until")),
                "score": _int(ind.get("x_opencti_score")), "detection": _boolish(ind.get("x_opencti_detection")), "tlp": itlp, "state": state,
            })
        reports = []
        for rep in _edges(node.get("reports")):
            rtlp, _ = _markings(rep.get("objectMarking"))
            reports.append({"id": _text(rep.get("id"), 80), "name": _text(rep.get("name"), 200), "published": _iso(rep.get("published")), "tlp": rtlp})
        pivots: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for rel in _edges(node.get("stixCoreRelationships")):
            to = rel.get("to") if isinstance(rel.get("to"), dict) else {}
            kind = str(to.get("entity_type") or "")
            name = _text(to.get("name"), 200)
            if kind in _OPENCTI_ACTORS and name:
                piv = {"type": "threat_actor", "value": name, "relation": "attributed_to", "individual": kind == "Threat-Actor-Individual"}
            elif kind in _OPENCTI_MALWARE and name:
                piv = {"type": "malware_family", "value": name, "relation": "attributed_to"}
            elif kind == "Attack-Pattern" and _text(to.get("x_mitre_id"), 20):
                piv = {"type": "mitre_technique", "value": str(to["x_mitre_id"]).strip(), "relation": "uses_technique"}
            else:
                continue
            key = (piv["type"], piv["value"])
            if key not in seen:
                seen.add(key)
                pivots.append(piv)
        states = {i["state"] for i in indicators}
        status = "active" if "active" in states else ("historical" if indicators else "observed")
        created_by = node.get("createdBy") if isinstance(node.get("createdBy"), dict) else {}
        updated = _iso(node.get("updated_at")) or _iso(node.get("created_at"))
        if reports and reports[0].get("name"):
            ref = f"OpenCTI report '{reports[0]['name']}'"
        else:
            ref = f"OpenCTI {node.get('entity_type') or 'observable'} {node.get('standard_id') or node.get('id')}"
        hits.append({
            "platform": "opencti",
            "id": _text(node.get("id"), 80),
            "standard_id": _text(node.get("standard_id"), 120),
            "entity_type": _text(node.get("entity_type"), 60),
            "score": _int(node.get("x_opencti_score")),
            "labels": [lb.get("value") for lb in node.get("objectLabel") or [] if isinstance(lb, dict) and isinstance(lb.get("value"), str)][:20],
            "org": _text(created_by.get("name"), 120),
            "created_at": _iso(node.get("created_at")),
            "updated_at": updated,
            "tlp": tlp_max(obs_tlp, *[i["tlp"] for i in indicators], *[r["tlp"] for r in reports]),
            "pap": pap,
            "indicators": indicators,
            "reports": reports,
            "verdict": {"active": "listed", "historical": "historical", "observed": "observed"}[status],
            "pivots": pivots,
            "ref": ref,
            "date": updated[:10] if updated else None,
        })
    return {"hits": hits}


def opencti_write_capabilities(me_body: Any) -> list[str] | None:
    """FC3 startup check: capabilities beyond read (KNUPDATE, KNDELETE, SETTINGS..., BYPASS)."""
    data = me_body.get("data") if isinstance(me_body, dict) else None
    me = data.get("me") if isinstance(data, dict) else None
    if not isinstance(me, dict):
        return None
    caps = [c.get("name") for c in me.get("capabilities") or [] if isinstance(c, dict)]
    return sorted({c for c in caps if isinstance(c, str) and c not in _OPENCTI_READ_CAPS})


# ======================================================================================
# TheHive 6 (query API)
# ======================================================================================

_THEHIVE_ALLOWED = {("POST", "/api/v1/query"), ("GET", "/api/v1/user/current")}
THEHIVE_READ_OPS = frozenset({"listObservable", "listCase", "listAlert", "getObservable", "getCase", "getAlert", "filter", "page", "sort", "count", "case", "alert"})
_THEHIVE_EXCLUDE = ["description", "summary", "customFields"]
_THEHIVE_TLP = {0: "clear", 1: "green", 2: "amber", 3: "amber+strict", 4: "red"}
#: without a known major version, numeric 3 reads as red (older versions and the 6.0 docs' own example)
_THEHIVE_TLP_CONSERVATIVE = {0: "clear", 1: "green", 2: "amber", 3: "red", 4: "red"}
_PAP = {0: "clear", 1: "green", 2: "amber", 3: "red"}
_THEHIVE_SEVERITY = {1: "low", 2: "medium", 3: "high", 4: "high"}


def thehive_request_allowed(method: str, path: str, body: Any = None) -> str | None:
    """FC3: TheHive search only: POST /api/v1/query with read operations, GET /api/v1/user/current."""
    m = (method or "").upper()
    p = _path_only(path)
    if "?" in p:
        return "TheHive values travel only in JSON bodies (query string refused)"
    p = p.rstrip("/")
    if (m, p) not in _THEHIVE_ALLOWED:
        return f"TheHive {m} {p} is not on the read-only allow-list"
    if p == "/api/v1/query":
        query = body.get("query") if isinstance(body, dict) else None
        if not isinstance(query, list) or not query:
            return "a TheHive query body is {'query': [operations]}"
        extra = sorted(set(body) - {"query", "excludeFields"})
        if extra:
            return f"unexpected TheHive query fields {extra}"
        for op in query:
            name = op.get("_name") if isinstance(op, dict) else None
            if name not in THEHIVE_READ_OPS:
                return f"TheHive operation {name!r} is not allowed (read-only adapter)"
    return None


def thehive_observable_query(value: str, limit: int = 20) -> dict[str, Any]:
    """FC4: observable search; the value travels only in the JSON body (_eq filter on data)."""
    n = max(1, min(int(limit or 20), MAX_RESULTS))
    return {"query": [{"_name": "listObservable"}, {"_name": "filter", "_eq": {"_field": "data", "_value": value}}, {"_name": "page", "from": 0, "to": n}]}


def thehive_case_query(value: str, limit: int = 20) -> dict[str, Any]:
    """FC6/FC9: the cases holding the observable (listObservable -> filter -> case)."""
    n = max(1, min(int(limit or 20), MAX_RESULTS))
    return {
        "query": [{"_name": "listObservable"}, {"_name": "filter", "_eq": {"_field": "data", "_value": value}}, {"_name": "case"}, {"_name": "page", "from": 0, "to": n}],
        "excludeFields": list(_THEHIVE_EXCLUDE),
    }


def thehive_tlp(num: Any, label: Any = None, major: int | None = None) -> str | None:
    """FC6 never-downgrade TLP: the label and the number disagreeing -> the stricter one."""
    n = _int(num)
    by_num = None
    if n is not None:
        table = _THEHIVE_TLP if isinstance(major, int) and major >= 6 else _THEHIVE_TLP_CONSERVATIVE
        by_num = table.get(n)
    return tlp_max(normalize_tlp(label), by_num)


def thehive_pap(num: Any, label: Any = None) -> str | None:
    text = label.strip().lower() if isinstance(label, str) else ""
    if text in ("clear", "white", "green", "amber", "red"):
        return "clear" if text == "white" else text
    n = _int(num)
    return _PAP.get(n) if n is not None else None


def thehive_errors(body: Any) -> tuple[str, str] | None:
    """TheHive errors {type, message} inside a 200 answer -> (status, reason)."""
    if isinstance(body, dict) and body.get("type") and body.get("message"):
        text = f"{_text(body.get('type'), 60)}: {_text(body.get('message'), 160)}"
        if "authenticat" in text.lower() or "authoriz" in text.lower():
            return "needs_key", f"TheHive rejected the API key ({text})"
        return "error", f"TheHive error ({text}): could not verify"
    return None


def parse_thehive_observables(body: Any, value: str) -> dict[str, Any] | None:
    """FC5/FC6: observables -> hits (ioc, sighted, TLP/PAP, tags, reused Cortex taxonomies);
    creator/updater logins and assignees are never copied. None for a non-list answer."""
    if not isinstance(body, list):
        return None
    hits = []
    for obs in body[:MAX_RESULTS]:
        if not isinstance(obs, dict) or not _same_value(obs.get("data"), value):
            continue
        cortex = []
        reports = obs.get("reports") if isinstance(obs.get("reports"), dict) else {}
        for analyzer, report in reports.items():
            for tax in (report.get("taxonomies") if isinstance(report, dict) else None) or []:
                if isinstance(tax, dict):
                    cortex.append({
                        "analyzer": _text(analyzer, 80), "level": _text(tax.get("level"), 20), "namespace": _text(tax.get("namespace"), 60),
                        "predicate": _text(tax.get("predicate"), 60), "value": _text(tax.get("value"), 120),
                    })
        created = _epoch_iso(obs.get("_createdAt"), millis=True)
        ioc = _boolish(obs.get("ioc"))
        hits.append({
            "platform": "thehive",
            "id": _text(obs.get("_id"), 40),
            "data_type": _text(obs.get("dataType"), 40),
            "ioc": ioc,
            "sighted": _boolish(obs.get("sighted")),
            "sighted_at": _epoch_iso(obs.get("sightedAt"), millis=True),
            "tlp": thehive_tlp(obs.get("tlp"), obs.get("tlpLabel")),
            "pap": thehive_pap(obs.get("pap"), obs.get("papLabel")),
            "tags": [t for t in obs.get("tags") or [] if isinstance(t, str)][:20],
            "cortex": cortex[:20],
            "verdict": "listed" if ioc else "context",
            "date": created[:10] if created else None,
        })
    return {"hits": hits}


def parse_thehive_cases(body: Any, org: str | None = None) -> list[dict[str, Any]] | None:
    """FC6/FC9: cases holding the observable -> 'TheHive case #N' references; None for a non-list."""
    if not isinstance(body, list):
        return None
    cases: list[dict[str, Any]] = []
    seen: set[Any] = set()
    for case in body[:MAX_RESULTS]:
        if not isinstance(case, dict):
            continue
        number = _int(case.get("number"))
        key = number if number is not None else case.get("_id")
        if key in seen:
            continue
        seen.add(key)
        start = _epoch_iso(case.get("startDate"), millis=True)
        severity = _int(case.get("severity"))
        cases.append({
            "platform": "thehive",
            "case_number": number,
            "case_id": _text(case.get("_id"), 40),
            "title": _text(case.get("title"), 200),
            "status": _text(case.get("status"), 40),
            "stage": _text(case.get("stage"), 40),
            "severity": _THEHIVE_SEVERITY.get(severity or 0),
            "severity_label": _text(case.get("severityLabel"), 20),
            "tlp": thehive_tlp(case.get("tlp"), case.get("tlpLabel")),
            "pap": thehive_pap(case.get("pap"), case.get("papLabel")),
            "start_date": start,
            "end_date": _epoch_iso(case.get("endDate"), millis=True),
            "tags": [t for t in case.get("tags") or [] if isinstance(t, str)][:20],
            "org": org,
            "ref": f"TheHive case #{number}" if number is not None else "TheHive case",
            "date": start[:10] if start else None,
        })
    return cases


def thehive_write_permissions(user: Any) -> list[str] | None:
    """FC3 startup check: manage* permissions of the key (GET /api/v1/user/current)."""
    perms = user.get("permissions") if isinstance(user, dict) else None
    if not isinstance(perms, list):
        return None
    return sorted({p for p in perms if isinstance(p, str) and p.startswith("manage") and "/read" not in p})


# ======================================================================================
# the adapters
# ======================================================================================


class _InternalTip(Module):
    """Shared behaviour of the three read-only adapters (not registered itself)."""

    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "internal"
    hosts = ()  # the host comes only from the URL setting (provider hosts_from_settings)
    access_model = "internal"
    expected_latency = 0.5
    timeout = TIMEOUT
    min_interval = MIN_INTERVAL
    cache_ttl = 0  # live markings and verdicts that analysts change: never cached
    max_pivots = 60
    category = "cti_framework"
    produces = {T.THREAT_ACTOR, T.MALWARE, T.MITRE}
    tags = {"internal"}

    #: platform id (INTERNAL_QUERY_ORDER), display name, URL setting, key name, registry source
    platform = ""
    platform_name = ""
    url_setting = ""
    key_name = ""
    source_id = ""

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        refusal = covert_refusal(ctx.options)
        if refusal:
            return res.mark("skipped", refusal, reason_code="policy")
        base, problem = base_url(ctx.setting(self.url_setting), self.url_setting)
        if base is None:
            return res.mark("skipped", problem, reason_code="config")
        key = ctx.key(self.key_name)
        if not key:
            return res.mark("needs_key", f"needs the {self.platform_name} key '{self.key_name}' of a read-only service account (v3lum keys)", reason_code="needs_key")
        account = self.key_check(ctx, base, key)
        hits = self.lookup(entity, ctx, res, base, key, account)
        if isinstance(res.raw, dict):
            res.raw["key_check"] = {"checked_at": account.get("checked_at"), "write_permissions": account.get("write")}
        if res.status.value not in ("ok", "empty"):
            return res
        if not hits:
            res.mark("empty", f"not known internally ({self.platform_name})")
        return res

    # ---- platform hooks ----------------------------------------------------------------
    def lookup(self, entity: Entity, ctx: Any, res: ModuleResult, base: str, key: str, account: dict[str, Any]) -> list[dict[str, Any]]:  # pragma: no cover - abstract
        raise NotImplementedError

    def request_allowed(self, method: str, path: str, body: Any = None) -> str | None:  # pragma: no cover - abstract
        raise NotImplementedError

    def auth_headers(self, key: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {key}"}

    def whoami(self, ctx: Any, base: str, key: str) -> Any:  # pragma: no cover - abstract
        raise NotImplementedError

    def account(self, body: Any) -> dict[str, Any]:  # pragma: no cover - abstract
        """{'write': write-capable permissions (None = unknown), 'org': owning organisation or None}."""
        raise NotImplementedError

    # ---- requests (read-only allow-list first, values in bodies only) ---------------------------
    def send(self, ctx: Any, method: str, base: str, path: str, key: str, body: Any = None, *, timeout: float = TIMEOUT) -> Any:
        """One request after the read-only allow-list check; the value only ever travels in ``body``."""
        problem = self.request_allowed(method, path, body)
        if problem:
            raise PolicyError("policy", f"{self.name}: refused {method} {path}: {problem}")
        url = base + path
        headers = self.auth_headers(key)
        if method == "GET":
            return ctx.http.get_json(url, headers=headers, timeout=timeout, source=self.source_id)
        return ctx.http.post_json(url, json_body=body, headers=headers, timeout=timeout, source=self.source_id)

    # ---- FC3 startup check: warn when the key can write -------------------------------------
    def key_check(self, ctx: Any, base: str, key: str) -> dict[str, Any]:
        """At most once a day per instance (ctx.state): read the key's own account and warn (live
        feed) when it can write. Best effort: a failure never changes the lookup result."""
        host = (urlsplit(base).hostname or "").lower()
        state_key = f"key_check:{host}"
        now = ctx.now()
        try:
            prev = ctx.state.get(state_key)
        except Exception:
            prev = None
        record = prev if isinstance(prev, dict) else {}
        checked = _parse_iso(record.get("checked_at"))
        if checked is not None and now - checked <= KEY_CHECK_TTL:
            return record
        try:
            facts = self.account(self.whoami(ctx, base, key))
            note = ""
        except (HttpError, NetworkError, PolicyError) as exc:
            facts, note = {"write": None, "org": None}, f"key check could not run ({type(exc).__name__})"
        record = {"checked_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "write": facts.get("write"), "org": facts.get("org"), "note": note}
        try:
            ctx.state.set(state_key, record)
        except Exception:  # state is bookkeeping: never fails the lookup
            pass
        if record["write"]:
            ctx.log(
                f"{self.platform_name} key '{self.key_name}' has write permissions ({', '.join(record['write'][:8])}): "
                "use a read-only least-privilege service account (A12)",
                level="warning",
            )
        return record

    @classmethod
    def health_check(cls) -> HealthCheck:
        """Self-test for doctor/keys wizard: the key's own permissions (no investigated value)."""
        return HealthCheck(offline=False, selftest=cls._selftest)

    @classmethod
    def _selftest(cls, ctx: Any) -> HealthResult:
        adapter = cls()
        base, problem = base_url(ctx.setting(cls.url_setting), cls.url_setting)
        if base is None:
            return HealthResult("dead", problem)
        key = ctx.key(cls.key_name)
        if not key:
            return HealthResult("needs_key", f"key '{cls.key_name}' is not configured")
        try:
            perms = adapter.account(adapter.whoami(ctx, base, key)).get("write")
        except HttpError as exc:
            status = getattr(exc, "status", 0)
            return HealthResult("needs_key" if status in (401, 403) else "dead", f"{cls.platform_name}: {exc}")
        except (NetworkError, PolicyError) as exc:
            return HealthResult("dead", f"{cls.platform_name}: {exc}")
        if perms is None:
            return HealthResult("ok", "reachable; key permissions could not be read")
        if perms:
            return HealthResult("ok", f"WARNING: the key has write permissions ({', '.join(perms[:8])}): use a read-only service account")
        return HealthResult("ok", "read-only key")

    # ---- shared result building ---------------------------------------------------------
    def report_pivots(self, res: ModuleResult, pivots: list[dict[str, Any]], ref: str) -> None:
        etypes = {"threat_actor": T.THREAT_ACTOR, "malware_family": T.MALWARE, "mitre_technique": T.MITRE}
        for piv in pivots:
            etype = etypes.get(piv.get("type", ""))
            if etype is None:
                continue
            note = f"{self.platform_name}: {ref}"
            if piv.get("individual"):
                note += " (individual threat actor: personal data, analyst selection only)"
            res.pivot(etype, str(piv.get("value") or ""), piv.get("relation") or "attributed_to", confidence="probable", expand=False, note=note[:300])

    def summary(self, res: ModuleResult, hits: list[dict[str, Any]]) -> None:
        res.attr("internal_sightings", [{k: h.get(k) for k in IDENTIFICATION_KEYS} | {"platform": self.platform} for h in hits[:MAX_RESULTS]])
        for h in hits:
            tlp = normalize_tlp(h.get("tlp"))
            if tlp:
                res.set_marking(tlp)  # FC6: the highest marking is kept, never downgraded
        actors = sorted({str(p["value"]) for h in hits for p in h.get("pivots") or [] if p.get("type") == "threat_actor"})
        techniques = sorted({str(p["value"]) for h in hits for p in h.get("pivots") or [] if p.get("type") == "mitre_technique"})
        res.attr("threat_actors", actors)
        res.attr("attack_techniques", techniques)


def _verdict_finding(verdict: str, severity_listed: str) -> tuple[str, str, list[str]]:
    """(severity, confidence, tags) of one internal hit by verdict (FC5)."""
    if verdict == "listed":
        return severity_listed, "probable", ["internal_sighting", "malicious"]
    if verdict == "historical":
        return "low", "possible", ["internal_sighting", "historical"]
    if verdict == "warninglist":
        return "info", "possible", ["internal_sighting", "warninglist", "context_only"]
    if verdict == "false_positive":
        return "info", "possible", ["internal_sighting", "false_positive", "context_only"]
    return "info", "possible", ["internal_sighting", "context_only"]


@register
class MispSightings(_InternalTip):
    name = "misp_sightings"
    title = "MISP sightings (company instance, read-only)"
    description = (
        "Known internally? Exact-value restSearch in the company MISP (read-only key): events, org, TLP, "
        "sightings, decay and warninglist hits; galaxy tags become attributed_to pivots."
    )
    accepts = {T.IPV4, T.IPV6, T.DOMAIN, T.URL, T.EMAIL, T.MD5, T.SHA1, T.SHA256, T.BTC, T.CVE, T.KEYWORD}
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "internal"
    hosts = ()
    provider = "internal_misp"
    sources = (MISP_SOURCE,)
    requires_keys = ("misp",)
    max_requests = 3  # restSearch + event metadata + the daily key check
    expected_latency = 0.5
    reference = "https://www.misp-project.org/openapi/"
    notice = (
        "Company-operated MISP only (disclosure 'internal', allowed at TLP:RED); community or shared instances "
        "are third-party providers. Read-only key, no write-back; results keep the event TLP."
    )
    platform = "misp"
    platform_name = "MISP"
    url_setting = "misp_url"
    key_name = "misp"
    source_id = MISP_SOURCE

    def request_allowed(self, method: str, path: str, body: Any = None) -> str | None:
        return misp_request_allowed(method, path, body)

    def auth_headers(self, key: str) -> dict[str, str]:
        return {"Authorization": key}  # MISP: the bare key, no 'Bearer'

    def whoami(self, ctx: Any, base: str, key: str) -> Any:
        return self.send(ctx, "GET", base, "/users/view/me", key, timeout=KEY_CHECK_TIMEOUT)

    def account(self, body: Any) -> dict[str, Any]:
        return {"write": misp_key_write_perms(body), "org": None}

    def lookup(self, entity: Entity, ctx: Any, res: ModuleResult, base: str, key: str, account: dict[str, Any]) -> list[dict[str, Any]]:
        data = self.send(ctx, "POST", base, "/attributes/restSearch", key, misp_attribute_search_body(entity.value))
        error = misp_errors(data)
        if error:
            res.mark(error[0], error[1], reason_code="needs_key" if error[0] == "needs_key" else "error")
            return []
        parsed = parse_misp_attributes(data, entity.value)
        if parsed is None:
            res.mark("error", "unexpected MISP answer (no response.Attribute list): could not verify")
            return []
        hits = parsed["hits"]
        res.raw = {"hits": len(hits), "truncated": parsed["truncated"]}
        if not hits:
            return []
        metadata_note = ""
        try:
            events = self.send(ctx, "POST", base, "/events/restSearch", key, misp_event_metadata_body([h["event_id"] for h in hits]))
        except (HttpError, NetworkError) as exc:  # the hits stand; org/date enrichment could not be read
            metadata_note = f"event metadata could not be read ({type(exc).__name__}): org unknown"
        else:
            hits = misp_apply_event_metadata(hits, events)
        self.summary(res, hits)
        res.attr("allowlisted", sorted({f"MISP warninglist: {w}" for h in hits for w in h["warninglists"]} | {"MISP false-positive sighting" for h in hits if h["verdict"] == "false_positive"}))
        scores = [h["decay"]["score"] for h in hits if h["verdict"] == "listed" and h.get("decay") and h["decay"].get("score") is not None]
        res.attr("tip_score", max(scores) if scores else None)
        for h in hits:
            self._finding(res, h, metadata_note)
            if h["verdict"] in ("listed", "historical", "context"):
                self.report_pivots(res, h["pivots"], h["ref"])
        return hits

    def _finding(self, res: ModuleResult, h: dict[str, Any], metadata_note: str) -> None:
        severity, confidence, tags = _verdict_finding(h["verdict"], h.get("threat_level") or "medium")
        s = h["sightings"]
        verdicts = {
            "listed": "listed (to_ids)",
            "context": "context only (to_ids=false)",
            "historical": "historical (" + ", ".join(f for f in h["flags"] if f in ("deleted", "decayed", "expiration_sighting")) + ")",
            "warninglist": f"on warninglist {', '.join(h['warninglists'])}",
            "false_positive": "newest sighting is a false positive",
        }
        description = (
            f"{h['ref']} '{h.get('event_info') or 'untitled'}' ({h.get('org') or 'org unknown'}, {h.get('date') or 'date unknown'}, "
            f"TLP:{(h.get('tlp') or 'unmarked').upper()}): {verdicts[h['verdict']]}; {s['sightings']} sighting(s), "
            f"{s['false_positives']} false positive(s)"
        )
        if h.get("sharing_group"):
            description += "; shared through a sharing group (third-party origin)"
        if metadata_note:
            description += f"; {metadata_note}"
        criteria = {
            "listed": f"MISP attribute to_ids=true in {h['ref']} (not decayed, no newer false-positive sighting, not warninglisted)",
            "historical": f"MISP attribute in {h['ref']} is decayed, deleted or has an expiration sighting",
        }
        res.finding(
            "Known internally (MISP)",
            severity,
            description + ".",
            confidence=confidence,
            criterion=criteria.get(h["verdict"], ""),
            data={k: h.get(k) for k in (
                "platform", "ref", "event_id", "event_uuid", "attribute_id", "attribute_uuid", "type", "category", "org", "tlp", "date",
                "verdict", "flags", "sightings", "decay", "warninglists", "sharing_group", "threat_level", "event_info",
            )},
            tags=tags,
            source=self.source_id,
            observed_first=h.get("timestamp"),
            observed_last=s.get("last_sighting") or h.get("timestamp"),
            key=f"misp:{h.get('attribute_id') or h.get('event_id')}",
        )


@register
class OpenCtiSightings(_InternalTip):
    name = "opencti_sightings"
    title = "OpenCTI sightings (company instance, read-only)"
    description = (
        "Known internally? Exact-value observable query on the company OpenCTI (read-only token): score, "
        "indicators (revoked/expired), reports, markings; actor/malware/technique relations become pivots."
    )
    accepts = {T.IPV4, T.IPV6, T.DOMAIN, T.URL, T.EMAIL, T.MD5, T.SHA1, T.SHA256, T.KEYWORD}
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "internal"
    hosts = ()
    provider = "internal_opencti"
    sources = (OPENCTI_SOURCE,)
    requires_keys = ("opencti",)
    max_requests = 2  # the observables query + the daily key check
    expected_latency = 0.5
    reference = "https://docs.opencti.io/latest/reference/api/"
    notice = (
        "Company-operated OpenCTI only (disclosure 'internal', allowed at TLP:RED). GraphQL queries only, "
        "never mutations; results keep the object markings."
    )
    platform = "opencti"
    platform_name = "OpenCTI"
    url_setting = "opencti_url"
    key_name = "opencti"
    source_id = OPENCTI_SOURCE

    def request_allowed(self, method: str, path: str, body: Any = None) -> str | None:
        if (method or "").upper() != "POST":
            return "OpenCTI answers GraphQL over POST only"
        if not isinstance(body, dict) or set(body) - {"query", "variables"}:
            return "a GraphQL body is {'query', 'variables'}"
        return opencti_query_allowed(body.get("query"), path)

    def whoami(self, ctx: Any, base: str, key: str) -> Any:
        return self.send(ctx, "POST", base, "/graphql", key, {"query": OPENCTI_ME_QUERY, "variables": {}}, timeout=KEY_CHECK_TIMEOUT)

    def account(self, body: Any) -> dict[str, Any]:
        return {"write": opencti_write_capabilities(body), "org": None}

    def lookup(self, entity: Entity, ctx: Any, res: ModuleResult, base: str, key: str, account: dict[str, Any]) -> list[dict[str, Any]]:
        data = self.send(ctx, "POST", base, "/graphql", key, opencti_observable_request(entity.value))
        error = opencti_errors(data)
        if error:
            res.mark(error[0], error[1], reason_code="needs_key" if error[0] == "needs_key" else "error")
            return []
        parsed = parse_opencti_observables(data, entity.value, ctx.now())
        if parsed is None:
            res.mark("error", "unexpected OpenCTI answer (no stixCyberObservables.edges): could not verify")
            return []
        hits = parsed["hits"]
        res.raw = {"hits": len(hits)}
        if not hits:
            return []
        self.summary(res, hits)
        scores = [h["score"] for h in hits if h.get("score") is not None]
        res.attr("tip_score", max(scores) if scores else None)
        for h in hits:
            self._finding(res, h)
            self.report_pivots(res, h["pivots"], h["ref"])
        return hits

    def _finding(self, res: ModuleResult, h: dict[str, Any]) -> None:
        score = h.get("score")
        listed = "high" if score is not None and score >= 80 else "medium" if score is None or score >= 50 else "low"
        severity, confidence, tags = _verdict_finding(h["verdict"], listed)
        states = ", ".join(f"{i['name'] or i['id']}: {i['state']}" for i in h["indicators"][:5]) or "no indicator"
        description = (
            f"{h['ref']} ({h.get('org') or 'org unknown'}, {h.get('date') or 'date unknown'}, TLP:{(h.get('tlp') or 'unmarked').upper()}, "
            f"PAP:{(h.get('pap') or 'unmarked').upper()}): score {score if score is not None else 'unset'}; indicators: {states}"
        )
        criteria = {
            "listed": f"active OpenCTI indicator (not revoked, valid_until not passed) for the observable, x_opencti_score {score}",
            "historical": "every OpenCTI indicator of the observable is revoked or expired (valid_until passed): historical",
        }
        res.finding(
            "Known internally (OpenCTI)",
            severity,
            description + ".",
            confidence=confidence,
            criterion=criteria.get(h["verdict"], ""),
            data={k: h.get(k) for k in ("platform", "ref", "id", "standard_id", "entity_type", "score", "labels", "org", "tlp", "pap", "date", "verdict", "indicators", "reports")},
            tags=tags,
            source=self.source_id,
            observed_first=h.get("created_at"),
            observed_last=h.get("updated_at"),
            key=f"opencti:{h.get('id')}",
        )


@register
class TheHiveSightings(_InternalTip):
    name = "thehive_sightings"
    title = "TheHive sightings (company instance, read-only)"
    description = (
        "Known internally? Observable search on the company TheHive (read-only key): the cases holding the value "
        "(case number, status, TLP/PAP, dates) and reused Cortex analyzer taxonomies."
    )
    accepts = {T.IPV4, T.IPV6, T.DOMAIN, T.URL, T.EMAIL, T.MD5, T.SHA1, T.SHA256, T.KEYWORD}
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "internal"
    hosts = ()
    provider = "internal_thehive"
    sources = (THEHIVE_SOURCE,)
    requires_keys = ("thehive",)
    max_requests = 3  # observables + their cases + the daily key check
    expected_latency = 0.5
    reference = "https://docs.strangebee.com/thehive/api-docs/"
    notice = (
        "Company-operated TheHive only (disclosure 'internal', allowed at TLP:RED). Read-only search; cases, "
        "alerts and observables are never created or updated. Results keep the case TLP/PAP."
    )
    settings = {
        "thehive_sightings_url": SettingSpec("", "company TheHive base URL (https); the read-only adapter is disabled while empty"),
    }
    platform = "thehive"
    platform_name = "TheHive"
    url_setting = "thehive_sightings_url"
    key_name = "thehive"
    source_id = THEHIVE_SOURCE

    def request_allowed(self, method: str, path: str, body: Any = None) -> str | None:
        return thehive_request_allowed(method, path, body)

    def whoami(self, ctx: Any, base: str, key: str) -> Any:
        return self.send(ctx, "GET", base, "/api/v1/user/current", key, timeout=KEY_CHECK_TIMEOUT)

    def account(self, body: Any) -> dict[str, Any]:
        return {"write": thehive_write_permissions(body), "org": _text(body.get("organisation"), 120) if isinstance(body, dict) else None}

    def lookup(self, entity: Entity, ctx: Any, res: ModuleResult, base: str, key: str, account: dict[str, Any]) -> list[dict[str, Any]]:
        data = self.send(ctx, "POST", base, "/api/v1/query", key, thehive_observable_query(entity.value))
        error = thehive_errors(data)
        if error:
            res.mark(error[0], error[1], reason_code="needs_key" if error[0] == "needs_key" else "error")
            return []
        parsed = parse_thehive_observables(data, entity.value)
        if parsed is None:
            res.mark("error", "unexpected TheHive answer (not a list of observables): could not verify")
            return []
        observables = parsed["hits"]
        res.raw = {"observables": len(observables)}
        if not observables:
            return []
        org = account.get("org")
        cases_note = ""
        try:
            cases = parse_thehive_cases(self.send(ctx, "POST", base, "/api/v1/query", key, thehive_case_query(entity.value)), org)
        except (HttpError, NetworkError) as exc:  # the observables stand; case references could not be read
            cases, cases_note = [], f"case references could not be read ({type(exc).__name__})"
        if cases is None:
            cases, cases_note = [], "unexpected case answer: case references not verified"
        ioc = any(o["ioc"] for o in observables)
        hits = [{**c, "verdict": "listed" if ioc else "context", "pivots": []} for c in cases]
        if not hits:  # observables outside any readable case (alerts): one hit for them
            tlp = tlp_max(*[o["tlp"] for o in observables])
            hits = [{"platform": "thehive", "ref": "TheHive observable", "org": org, "tlp": tlp, "date": observables[0]["date"], "verdict": "listed" if ioc else "context", "pivots": []}]
        hits = [h | {"tlp": tlp_max(h.get("tlp"), *[o["tlp"] for o in observables])} for h in hits]
        self.summary(res, hits)
        for h in hits:
            self._finding(res, h, observables, cases_note)
        return hits

    def _finding(self, res: ModuleResult, h: dict[str, Any], observables: list[dict[str, Any]], cases_note: str) -> None:
        listed = h.get("severity") or "medium"
        severity, confidence, tags = _verdict_finding(h["verdict"], listed)
        sighted = sum(1 for o in observables if o["sighted"])
        cortex = [c for o in observables for c in o["cortex"]][:10]
        if h.get("case_number") is not None:
            description = (
                f"{h['ref']} '{h.get('title') or 'untitled'}' ({h.get('status') or '?'}/{h.get('stage') or '?'}, severity "
                f"{h.get('severity_label') or h.get('severity') or '?'}, TLP:{(h.get('tlp') or 'unmarked').upper()}, "
                f"PAP:{(h.get('pap') or 'unmarked').upper()}, opened {h.get('date') or 'date unknown'})"
            )
        else:
            description = f"{len(observables)} observable(s) outside a readable case (TLP:{(h.get('tlp') or 'unmarked').upper()})"
        description += f": observable flagged as IOC: {'yes' if h['verdict'] == 'listed' else 'no'}; {sighted} sighted"
        if cases_note:
            description += f"; {cases_note}"
        res.finding(
            "Known internally (TheHive)",
            severity,
            description + ".",
            confidence=confidence,
            criterion=f"observable flagged as IOC in {h['ref']} of the company TheHive" if h["verdict"] == "listed" else "",
            data={
                **{k: h.get(k) for k in ("platform", "ref", "case_number", "case_id", "title", "status", "stage", "severity", "tlp", "pap", "date", "end_date", "org", "verdict", "tags")},
                "observables": [{k: o[k] for k in ("id", "data_type", "ioc", "sighted", "sighted_at", "tlp", "pap", "tags", "date")} for o in observables[:10]],
                "cortex": cortex,
            },
            tags=tags,
            source=self.source_id,
            observed_first=h.get("start_date"),
            observed_last=max((o["sighted_at"] for o in observables if o.get("sighted_at")), default=None),
            key=f"thehive:{h.get('case_number') if h.get('case_number') is not None else 'observables'}",
        )
