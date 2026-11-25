"""STIX 2.1 bundle export (for MISP, OpenCTI, TIPs).

* Observables become SCOs with deterministic ids (UUIDv5, STIX namespace, id-contributing props).
* CVEs -> vulnerability, threat actors -> threat-actor, malware -> malware, ATT&CK -> attack-pattern.
* Entities flagged malicious get an indicator (STIX pattern) ``based-on`` their observable.
* Graph edges -> relationship SROs; correlations -> notes; everything wrapped in a report.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

STIX_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
V3LUM_NS = uuid.UUID("6f3f8a2e-2d1e-4b8b-9f3c-5a1d0c3e7b21")

HASH_KEYS = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512"}
BAD_TAGS = {"malicious", "phishing", "malware", "c2", "botnet"}


def _sco_id(kind: str, props: dict[str, Any]) -> str:
    canon = json.dumps(props, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"{kind}--{uuid.uuid5(STIX_NS, canon)}"


def _sdo_id(kind: str, case_id: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(V3LUM_NS, f'{case_id}|{kind}|{key}')}"


def _ts(case: dict[str, Any]) -> str:
    created = str(case.get("created") or "1970-01-01T00:00:00+00:00")
    created = created.replace("+00:00", "")
    if not created.endswith("Z"):
        created += "Z"
    if "." not in created:
        created = created[:-1] + ".000Z"
    return created


def _object_for(node: dict[str, Any], case: dict[str, Any], ts: str) -> tuple[dict[str, Any] | None, str | None]:
    t, v = node["type"], node["value"]
    common = {"spec_version": "2.1"}
    if t == "domain":
        return {"type": "domain-name", "id": _sco_id("domain-name", {"value": v}), "value": v, **common}, f"[domain-name:value = '{v}']"
    if t == "ipv4":
        return {"type": "ipv4-addr", "id": _sco_id("ipv4-addr", {"value": v}), "value": v, **common}, f"[ipv4-addr:value = '{v}']"
    if t == "ipv6":
        return {"type": "ipv6-addr", "id": _sco_id("ipv6-addr", {"value": v}), "value": v, **common}, f"[ipv6-addr:value = '{v}']"
    if t == "cidr":
        kind = "ipv6-addr" if ":" in v else "ipv4-addr"
        return {"type": kind, "id": _sco_id(kind, {"value": v}), "value": v, **common}, f"[{kind}:value = '{v}']"
    if t == "email":
        return {"type": "email-addr", "id": _sco_id("email-addr", {"value": v}), "value": v, **common}, f"[email-addr:value = '{v}']"
    if t == "url":
        esc = v.replace("\\", "\\\\").replace("'", "\\'")
        return {"type": "url", "id": _sco_id("url", {"value": v}), "value": v, **common}, f"[url:value = '{esc}']"
    if t in HASH_KEYS:
        algo = HASH_KEYS[t]
        return (
            {"type": "file", "id": _sco_id("file", {"hashes": {algo: v}}), "hashes": {algo: v}, **common},
            f"[file:hashes.'{algo}' = '{v}']",
        )
    if t == "asn":
        num = int(v[2:])
        return {"type": "autonomous-system", "id": _sco_id("autonomous-system", {"number": num}), "number": num, **common}, None
    if t == "mac_address":
        mac = v.lower()
        return {"type": "mac-addr", "id": _sco_id("mac-addr", {"value": mac}), "value": mac, **common}, None
    sdo_common = {"spec_version": "2.1", "created": ts, "modified": ts}
    if t == "cve":
        return (
            {
                "type": "vulnerability",
                "id": _sdo_id("vulnerability", case["case_id"], v),
                "name": v,
                "external_references": [{"source_name": "cve", "external_id": v}],
                **sdo_common,
            },
            None,
        )
    if t == "threat_actor":
        return {"type": "threat-actor", "id": _sdo_id("threat-actor", case["case_id"], v), "name": v, **sdo_common}, None
    if t == "malware_family":
        return {"type": "malware", "id": _sdo_id("malware", case["case_id"], v), "name": v, "is_family": True, **sdo_common}, None
    if t == "mitre_technique":
        return (
            {
                "type": "attack-pattern",
                "id": _sdo_id("attack-pattern", case["case_id"], v),
                "name": v,
                "external_references": [{"source_name": "mitre-attack", "external_id": v, "url": f"https://attack.mitre.org/techniques/{v.replace('.', '/')}/"}],
                **sdo_common,
            },
            None,
        )
    return None, None


def bundle(case: dict[str, Any]) -> dict[str, Any]:
    ts = _ts(case)
    cid = case["case_id"]
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": f"identity--{uuid.uuid5(V3LUM_NS, 'v3lum-tool')}",
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "name": "V3LUM",
        "identity_class": "system",
    }
    objects: list[dict[str, Any]] = [identity]
    ids: dict[str, str] = {}
    findings_by_entity: dict[str, list[dict[str, Any]]] = {}
    for f in case.get("findings", []):
        if f.get("entity"):
            findings_by_entity.setdefault(f["entity"], []).append(f)

    for node in case.get("entities", []):
        obj, pattern = _object_for(node, case, ts)
        if obj is None:
            continue
        if obj["id"] not in {o["id"] for o in objects}:
            objects.append(obj)
        ids[node["key"]] = obj["id"]
        tags = {t for f in findings_by_entity.get(node["key"], []) for t in f.get("tags", [])}
        if pattern and tags & BAD_TAGS:
            ind = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": _sdo_id("indicator", cid, node["key"]),
                "created": ts,
                "modified": ts,
                "created_by_ref": identity["id"],
                "name": f"{node['type']}: {node['value']}",
                "indicator_types": ["malicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": ts,
                "labels": sorted(tags & BAD_TAGS),
            }
            objects.append(ind)
            objects.append(_rel(cid, ts, identity, ind["id"], obj["id"], "based-on"))

    for edge in case.get("edges", []):
        src, dst = ids.get(edge["src"]), ids.get(edge["dst"])
        if src and dst and src != dst:
            objects.append(_rel(cid, ts, identity, src, dst, edge["relation"].replace("_", "-"), f"via {edge['module']}"))

    for corr in case.get("correlations", []):
        refs = [ids[k] for k in corr.get("entities", []) if k in ids]
        if not refs:
            continue
        objects.append(
            {
                "type": "note",
                "spec_version": "2.1",
                "id": _sdo_id("note", cid, corr["id"]),
                "created": ts,
                "modified": ts,
                "created_by_ref": identity["id"],
                "abstract": f"[{corr['severity'].upper()}] {corr['title']}",
                "content": (corr.get("description", "") + ("\nRecommendation: " + corr["recommendation"] if corr.get("recommendation") else "")).strip(),
                "object_refs": refs,
            }
        )

    report_refs = [o["id"] for o in objects if o["type"] != "identity"]
    if not report_refs:
        report_refs = [identity["id"]]
    objects.append(
        {
            "type": "report",
            "spec_version": "2.1",
            "id": _sdo_id("report", cid, "report"),
            "created": ts,
            "modified": ts,
            "created_by_ref": identity["id"],
            "name": f"V3LUM case {cid}",
            "description": f"Risk {case.get('summary', {}).get('risk_level', 'clean')} ({case.get('summary', {}).get('risk_score', 0)}/100). Seeds: {', '.join(case.get('seeds', []))}",
            "published": ts,
            "report_types": ["threat-report"],
            "object_refs": report_refs,
        }
    )
    return {"type": "bundle", "id": f"bundle--{uuid.uuid5(V3LUM_NS, 'bundle|' + cid)}", "objects": objects}


def _rel(cid: str, ts: str, identity: dict[str, Any], src: str, dst: str, rtype: str, desc: str = "") -> dict[str, Any]:
    rel = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": _sdo_id("relationship", cid, f"{src}|{rtype}|{dst}"),
        "created": ts,
        "modified": ts,
        "created_by_ref": identity["id"],
        "relationship_type": rtype,
        "source_ref": src,
        "target_ref": dst,
    }
    if desc:
        rel["description"] = desc
    return rel
