"""MISP event JSON export (P303; A2, A12). Hand-rolled: no PyMISP runtime dependency (PyMISP is only
an optional dev test oracle).

``event(case, *, include_personal=False, include_weak=False)`` returns ``{"Event": {...}}`` in the
MISP core format (the body of ``POST /events/add`` and of MISP's JSON import), built from the same
filtered view as the STIX bundle (``v3lum.report.stix.prepare``), so both exports carry the same
data:

* one attribute per exportable entity (:data:`ATTRIBUTE_TYPES`; deterministic uuids per case and
  value), ``to_ids`` true only for the indicator gating of P303 cond 5 (a CR27 consensus or an
  analyst-confirmed hostile finding; POSSIBLE and warninglisted values only with ``include_weak``,
  ``context_only`` never); attribute distribution 5 (inherit the event);
* event tags: the ``tlp:*`` tag of the case TLP (TLP 2.0 taxonomy, ``tlp:amber+strict`` included)
  and ``workflow:state="draft"``; galaxy tags ``misp-galaxy:<galaxy>="<name>"`` for threat actors,
  malware families (``v3lum.core.galaxy.lookup``) and ATT&CK techniques, with a ``Galaxy`` block
  carrying the MISP galaxy cluster uuids of the clusters a galaxy fragment ships;
* ``distribution`` "0" (your organisation only) at every TLP - stricter than A2's AMBER/AMBER+STRICT/
  RED floor -, ``published`` false, no sharing group;
* the same personal-data stripping as STIX: PERSONAL_TYPES values only with ``include_personal``
  (person names as ``full-name``, phone numbers as ``phone-number``), CPF never (masked in every
  comment), only exported IOC seeds in the event info, ``threat_level_id`` from the case score
  without personal-data entities (``stix.export_risk``; 4 'undefined' for a personal subject), no
  analyst note, no local path; cross-case references omitted at CLEAR/GREEN and reduced to the
  visible count at AMBER+;
* research-profile cases carry the licence banner as a ``comment`` attribute.

:func:`counts` gives the dry-run summary numbers ('1 event, 23 attributes, 4 to_ids').
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

from v3lum.report.stix import V3LUM_NS, ExportView, _node_parts, _stamp, export_risk, prepare

__all__ = ["ATTRIBUTE_TYPES", "DISTRIBUTION_ORG_ONLY", "counts", "event", "tlp_tag"]

#: MISP distribution 0: "Your organisation only" (every V3LUM event, every TLP).
DISTRIBUTION_ORG_ONLY = "0"
#: Attribute distribution 5: "Inherit event".
_INHERIT = "5"
#: Entity type -> (MISP attribute type, category). Types missing here are not exported as attributes
#: (actors, malware and ATT&CK become galaxy tags; local files, text blobs and secrets never leave).
ATTRIBUTE_TYPES: dict[str, tuple[str, str]] = {
    "domain": ("domain", "Network activity"),
    "onion": ("domain", "Network activity"),
    "url": ("url", "Network activity"),
    "ipv4": ("ip-dst", "Network activity"),
    "ipv6": ("ip-dst", "Network activity"),
    "cidr": ("ip-dst", "Network activity"),
    "asn": ("AS", "Network activity"),
    "mac_address": ("mac-address", "Network activity"),
    "md5": ("md5", "Payload delivery"),
    "sha1": ("sha1", "Payload delivery"),
    "sha256": ("sha256", "Payload delivery"),
    "sha512": ("sha512", "Payload delivery"),
    "ssdeep": ("ssdeep", "Payload delivery"),
    "imphash": ("imphash", "Payload delivery"),
    "tlsh": ("tlsh", "Payload delivery"),
    "cve": ("vulnerability", "External analysis"),
    "btc_address": ("btc", "Financial fraud"),
    "xmr_address": ("xmr", "Financial fraud"),
    "user_agent": ("user-agent", "Network activity"),
    # personal types: exported only with include_personal
    "email": ("email", "Network activity"),
    "phone": ("phone-number", "Person"),
    "person_name": ("full-name", "Person"),
    "username": ("text", "Social network"),
    "social_account": ("text", "Social network"),
    "telegram_handle": ("text", "Social network"),
    "fediverse_handle": ("text", "Social network"),
    "bsky_handle": ("text", "Social network"),
}
_FINGERPRINTS = {32: "x509-fingerprint-md5", 40: "x509-fingerprint-sha1", 64: "x509-fingerprint-sha256"}
_THREAT_LEVEL = {"critical": "1", "high": "1", "medium": "2", "low": "3"}


def tlp_tag(tlp: Any) -> str:
    """The MISP TLP 2.0 taxonomy tag of a TLP value: 'tlp:clear' ... 'tlp:amber+strict', 'tlp:red'."""
    from v3lum.core import tlp as _tlp

    return "tlp:" + _tlp.parse(tlp).value_str


def _uuid(case_id: str, *parts: str) -> str:
    return str(uuid.uuid5(V3LUM_NS, "misp|" + case_id + "|" + "|".join(parts)))


def _attribute_for(view: ExportView, key: str, node: Mapping[str, Any]) -> dict[str, Any] | None:
    _k, etype, value = _node_parts(node)
    if etype in ("cert_fingerprint", "code_signing_cert"):
        hexval = "".join(ch for ch in value.lower() if ch in "0123456789abcdef")
        mtype = _FINGERPRINTS.get(len(hexval))
        if not mtype:
            return None
        category, value = "Network activity", hexval
    elif etype in ATTRIBUTE_TYPES:
        mtype, category = ATTRIBUTE_TYPES[etype]
    else:
        return None
    if etype == "social_account" and ":" in value:
        platform, handle = value.split(":", 1)
        value = handle
        comment = f"{platform} account"
    elif mtype == "text":
        comment = etype.replace("_", " ")
    else:
        comment = ""
    to_ids = view.is_indicator(key)
    ind = view.indicators.get(key)
    if to_ids and ind is not None:
        reason = "analyst-confirmed" if ind.basis == "confirmed" else "independent-source consensus (CR27)"
        comment = (comment + "; " if comment else "") + view.scrub(f"{reason}: {ind.criterion}" if ind.criterion else reason)
    elif ind is not None and ind.weak:
        comment = (comment + "; " if comment else "") + f"observable only ({ind.weak})"
    attr: dict[str, Any] = {
        "uuid": _uuid(view.case_id, "attribute", mtype, value),
        "type": mtype,
        "category": category,
        "value": value,
        "to_ids": bool(to_ids),
        "distribution": _INHERIT,
        "disable_correlation": False,
        "comment": comment[:1000],
    }
    if to_ids and ind is not None and ind.observed_last is not None:
        attr["last_seen"] = _stamp(ind.observed_last)
    return attr


def _galaxy_tags(view: ExportView) -> tuple[list[str], list[dict[str, Any]]]:
    from v3lum.core import attack, galaxy

    tags: list[str] = []
    blocks: dict[str, dict[str, Any]] = {}
    techniques: set[str] = set()
    for node in view.nodes.values():
        _k, etype, value = _node_parts(node)
        if etype in ("threat_actor", "malware_family"):
            cluster = galaxy.lookup(etype, value)
            if cluster is None:
                continue
            tags.append(cluster.tag)
            if cluster.source == "galaxy":
                block = blocks.setdefault(cluster.galaxy, {"type": cluster.galaxy, "GalaxyCluster": []})
                if cluster.galaxy_uuid:
                    block["uuid"] = cluster.galaxy_uuid
                block["GalaxyCluster"].append({"uuid": cluster.uuid, "value": cluster.name, "type": cluster.galaxy, "tag_name": cluster.tag})
        elif etype == "mitre_technique":
            techniques.add(value)
    for item in [*view.findings, *view.correlations]:
        techniques.update(str(t) for t in item.get("attack") or () if t)
    for canonical in sorted({attack.canonical(t) for t in techniques}):
        if not attack.is_valid(canonical):  # canonical first: a revoked id counts as its replacement
            continue
        name = attack.name(canonical)
        if name:
            tags.append(f'misp-galaxy:mitre-attack-pattern="{name} - {canonical}"')
    galaxies = [dict(b, GalaxyCluster=sorted(b["GalaxyCluster"], key=lambda c: c["uuid"])) for _g, b in sorted(blocks.items())]
    return sorted(dict.fromkeys(tags)), galaxies


def event(case: Mapping[str, Any], *, include_personal: bool = False, include_weak: bool = False) -> dict[str, Any]:
    """The MISP event of a case (see the module docstring): ``{"Event": {...}}``."""
    view = prepare(case, include_personal=include_personal, include_weak=include_weak)
    return _event(view)


def _event(view: ExportView) -> dict[str, Any]:
    attributes: dict[str, dict[str, Any]] = {}
    for key, node in view.nodes.items():
        attr = _attribute_for(view, key, node)
        if attr is not None:
            prev = attributes.get(attr["uuid"])
            if prev is None or (attr["to_ids"] and not prev["to_ids"]):
                attributes[attr["uuid"]] = attr
    if view.banner:
        attributes["banner"] = {
            "uuid": _uuid(view.case_id, "attribute", "comment", "licence-banner"),
            "type": "comment",
            "category": "Other",
            "value": view.banner,
            "to_ids": False,
            "distribution": _INHERIT,
            "disable_correlation": True,
            "comment": "licence banner (A1)",
        }
    risk = export_risk(view)  # never a score about a person (P302 cond 10)
    threat = "4" if risk is None else _THREAT_LEVEL.get(str(risk[1]).lower(), "4")
    info = f"V3LUM case {view.case_id}"
    if view.seeds:
        shown = ", ".join(view.seeds[:3]) + (f" (+{len(view.seeds) - 3})" if len(view.seeds) > 3 else "")
        info += f": {shown}"
    galaxy_tags, galaxies = _galaxy_tags(view)
    tags = [tlp_tag(view.tlp), 'workflow:state="draft"', *galaxy_tags]
    ev: dict[str, Any] = {
        "uuid": _uuid(view.case_id, "event"),
        "info": view.scrub(info)[:500],
        "date": view.created.date().isoformat(),
        "threat_level_id": threat,
        "analysis": "0",
        "distribution": DISTRIBUTION_ORG_ONLY,
        "published": False,
        "Tag": [{"name": t} for t in tags],
        "Attribute": sorted(attributes.values(), key=lambda a: (a["type"], a["value"])),
    }
    if galaxies:
        ev["Galaxy"] = galaxies
    return {"Event": ev}


def counts(ev: Mapping[str, Any]) -> dict[str, int]:
    """``{events, attributes, to_ids}`` of an :func:`event` result (the push dry-run summary)."""
    body = ev.get("Event") if isinstance(ev.get("Event"), Mapping) else ev
    attrs = [a for a in body.get("Attribute") or () if isinstance(a, Mapping)]
    return {"events": 1, "attributes": len(attrs), "to_ids": sum(1 for a in attrs if a.get("to_ids"))}
