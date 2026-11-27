"""The consolidated CVE card (P183 cond 5/6, batch p1-G08-1): one card and one priority line per CVE.

Every CVE module (cisa_kev, cve_record, epss, epss_api and the later P181/P185/P352 modules) adds facts
to the CVE node with provenance (each attribute value keeps the module that reported it) instead of
separate findings. Rule ``g08_cve_card`` reads them after the scan and emits ONE informational
correlation per investigated CVE node:

* the card: CVSS with source/version, EPSS + percentile with the model date, KEV (dateAdded, ransomware
  use, due date), exploitation evidence by source, curated exploit links (count + links), vendor fix
  (advisories, fixed versions) and affected products - each line names the module it came from;
* ``kev`` stays CISA-only (P182 cond 4): a 'kev' fact from a module that does not relay CISA data
  (cisa_kev, cve_record's CISA ADP/NVD relay, cve_offline_mirror) is moved to exploitation evidence;
* one plain-words priority line (e.g. 'KEV + EPSS 0.97: patch now') as the title; the card is always
  INFO: a bare CVE lookup shows the patch-priority label and never raises the case risk level. Asset
  severity is decided only by CR15 (P291); the card names the own assets linked through has_vuln;
* notices of the data shown (NVD API notice, FIRST/CISA attribution, MITRE CVE/CWE designations).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Correlation, ModuleResult, Severity
from v3lum.modules.vulnerability_cve.cve_record import (
    CISA_KEV_ATTRIBUTION,
    CVE_TERMS_POINTER,
    CWE_COPYRIGHT,
    FIRST_EPSS_ATTRIBUTION,
    KEV_RELAY_MODULES,
    epss_percentile_words,
    format_epss,
    merge_cvss,
    patch_priority,
)

RULE_ID = "g08_cve_card"
#: facts that make a CVE node card-worthy (a CVE nobody looked up gets no card)
CARD_FACTS = ("kev", "kev_status", "epss", "epss_text", "cvss", "cvss_scores", "cve_state", "exploited", "exploit_refs", "cve_description")
_RECOMMENDATION = {
    "patch now": "Patch or mitigate now: CISA has confirmed exploitation in the wild. Check exposure of every asset running the product.",
    "patch urgently": "Patch urgently: exploitation in the next 30 days is likely (EPSS).",
    "patch soon": "Patch in the next cycle and check exposure: high impact or an elevated exploitation probability.",
    "normal cycle": "Normal patch cycle; re-check when KEV or EPSS change.",
    "no action": "No action: the CVE record is not published (rejected or reserved).",
}


def _values(node: Node, key: str) -> list[tuple[Any, str]]:
    return [(value, str(module)) for value, module in node.attributes.get(key, [])]


def _first(node: Node, key: str, modules: Iterable[str] | None = None) -> tuple[Any, str] | None:
    wanted = set(modules) if modules is not None else None
    for value, module in _values(node, key):
        if value not in (None, "", [], {}) and (wanted is None or module in wanted):
            return value, module
    return None


def _value_of(node: Node, key: str, module: str) -> Any:
    for value, mod in _values(node, key):
        if mod == module:
            return value
    return None


def _items(node: Node, key: str) -> list[tuple[Any, str]]:
    """Flattened (item, module) pairs of a list-valued attribute."""
    out: list[tuple[Any, str]] = []
    for value, module in _values(node, key):
        for item in value if isinstance(value, (list, tuple)) else [value]:
            if item not in (None, "") and not any(item == i for i, _m in out):
                out.append((item, module))
    return out


def _float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def build_card(node: Node, graph: Graph | None = None) -> dict[str, Any] | None:
    """The consolidated card of one CVE node (None when no CVE module reported anything about it)."""
    if not any(node.attributes.get(k) for k in CARD_FACTS):
        return None
    card: dict[str, Any] = {"cve": node.entity.value, "modules": sorted({m for vals in node.attributes.values() for _v, m in vals})}
    states = [str(v).upper() for v, _m in _values(node, "cve_state") if v]
    card["state"] = next((s for s in states if s in ("REJECTED", "RESERVED")), states[0] if states else None)
    card["scorable"] = card["state"] not in ("REJECTED", "RESERVED")

    # KEV: CISA-only; other 'kev' claims are exploitation evidence (P182 cond 4)
    exploited: dict[str, Any] = {}
    kev_modules = []
    for value, module in _values(node, "kev"):
        if value is not True:
            continue
        if module in KEV_RELAY_MODULES:
            kev_modules.append(module)
        else:
            exploited.setdefault(f"{module} (not CISA KEV)", _value_of(node, "kev_date_added", module))
    kev: dict[str, Any] = {"listed": bool(kev_modules), "providers": sorted(set(kev_modules))}
    if kev_modules:
        order = sorted(set(kev_modules), key=lambda m: (m != "cisa_kev", m))
        for field, attr in (("date_added", "kev_date_added"), ("due_date", "kev_due_date"), ("ransomware_use", "kev_ransomware_use")):
            for module in order:
                value = _value_of(node, attr, module)
                if value:
                    kev[field] = value
                    break
        kev["ransomware_known"] = any(v is True for v, _m in _values(node, "kev_ransomware_known"))
        absent = _first(node, "kev_status", ["cisa_kev"])
        if "cisa_kev" not in kev_modules and absent is not None:
            kev["note"] = f"listed by {', '.join(kev['providers'])} but not in the local CISA KEV copy (stale copy?)"
    else:
        status = _first(node, "kev_status", ["cisa_kev"])
        if status is not None:
            kev["text"] = str(status[0])
    card["kev"] = kev

    # EPSS: the newest model date wins; every score keeps its module
    epss_rows = []
    for value, module in _values(node, "epss"):
        score = _float(value)
        if score is None:
            continue
        epss_rows.append({
            "score": score,
            "percentile": _float(_value_of(node, "epss_percentile", module)),
            "date": _value_of(node, "epss_date", module),
            "model_version": _value_of(node, "epss_model_version", module),
            "module": module,
        })
    epss_rows.sort(key=lambda r: (str(r.get("date") or ""), r["module"] == "epss"), reverse=True)
    card["epss"] = epss_rows[0] if epss_rows else None
    card["epss_all"] = epss_rows

    # CVSS with source/version (all modules), best first
    cvss = []
    for item, module in _items(node, "cvss_scores"):
        if isinstance(item, dict) and _float(item.get("score")) is not None:
            cvss.append(dict(item, module=module))
    cvss = merge_cvss(cvss)
    if not cvss:
        plain = _first(node, "cvss")
        if plain is not None and _float(plain[0]) is not None:
            cvss = [{"score": _float(plain[0]), "source": plain[1], "module": plain[1]}]
    card["cvss"] = cvss

    # exploitation evidence by source (never 'kev'), exploits, vendor fix, affected products, CWE
    for value, module in _values(node, "exploited"):
        if isinstance(value, dict):
            for source, date in value.items():
                key = f"{source} [{module}]"
                if key not in exploited or (date and (not exploited[key] or str(date) < str(exploited[key]))):
                    exploited[key] = date
    card["exploited"] = exploited
    links = [u for u, _m in _items(node, "exploit_refs") if isinstance(u, str)]
    card["exploits"] = {"count": len(links), "links": links[:20]}
    fixed = [f for f, _m in _items(node, "fixed_versions") if isinstance(f, dict) and f.get("fixed")]
    advisories = [u for u, _m in _items(node, "vendor_advisories") if isinstance(u, str)]
    card["vendor_fix"] = {"fixed_versions": fixed[:20], "advisories": advisories[:20]}
    affected = []
    for item, module in _items(node, "affected"):
        if isinstance(item, dict):
            label = " ".join(x for x in (item.get("vendor"), item.get("product")) if x)
            if label and label not in [a["product"] for a in affected]:
                affected.append({"product": label, "module": module})
    kev_product = " ".join(str(v) for v in (_value_of(node, "kev_vendor", "cisa_kev"), _value_of(node, "kev_product", "cisa_kev")) if v)
    if kev_product and not any(kev_product.casefold() in a["product"].casefold() for a in affected):
        affected.append({"product": kev_product, "module": "cisa_kev"})
    card["affected"] = affected[:20]
    card["cwe"] = [c for c, _m in _items(node, "cwe")]
    card["cwe_names"] = [c for c, _m in _items(node, "cwe_names")]
    card["description"] = (_first(node, "cve_description") or _first(node, "kev_description") or (None, ""))[0]
    card["own_assets"] = []
    if graph is not None:
        for edge in graph.in_edges(node.key, "has_vuln"):
            src = graph.get(edge.src)
            if src is not None and src.ownership == "own_asset":
                card["own_assets"].append(src.key)
    best = card["cvss"][0] if card["cvss"] else {}
    card["priority"] = patch_priority({
        "scorable": card["scorable"],
        "state": card["state"],
        "kev": kev,
        "epss": card["epss"] or {},
        "cvss": best.get("score"),
    })
    card["notices"] = card_notices(node, card)
    return card


def card_notices(node: Node, card: dict[str, Any]) -> list[str]:
    """Notices required by the data on the card (P183 cond 7, P184 cond 3)."""
    notices = [n for n, _m in _items(node, "data_notices") if isinstance(n, str)]
    if card.get("epss"):
        notices.append(FIRST_EPSS_ATTRIBUTION)
    if card["kev"].get("listed") or card["kev"].get("text"):
        notices.append(CISA_KEV_ATTRIBUTION)
    if card.get("state") or card.get("description"):
        notices.append(CVE_TERMS_POINTER)
    if card.get("cwe_names"):
        notices.append(CWE_COPYRIGHT)
    return list(dict.fromkeys(notices))


def card_lines(card: dict[str, Any]) -> list[str]:
    """The card as short evidence lines, each naming the module(s) it came from."""
    lines: list[str] = []
    kev = card["kev"]
    if kev.get("listed"):
        parts = [f"since {kev.get('date_added') or '?'}"]
        if kev.get("due_date"):
            parts.append(f"due {kev['due_date']}")
        parts.append(f"ransomware use: {kev.get('ransomware_use') or ('Known' if kev.get('ransomware_known') else '?')}")
        lines.append(f"KEV: listed {', '.join(parts)} [{', '.join(kev['providers'])}]")
        if kev.get("ransomware_known"):
            lines.append("KEV flag: known ransomware campaign use [cisa_kev]")
        if kev.get("note"):
            lines.append(f"KEV note: {kev['note']}")
    elif kev.get("text"):
        lines.append(f"KEV: {kev['text']} [cisa_kev]")
    for row in card["epss_all"][:3]:
        tier = epss_percentile_words(row.get("percentile"))
        pct = f", percentile {row['percentile'] * 100:.2f}%" if isinstance(row.get("percentile"), float) else ""
        tier_txt = f" ({tier})" if tier else ""
        model = f" (model {row['model_version']})" if row.get("model_version") else ""
        lines.append(f"EPSS {format_epss(row['score'])}{pct}{tier_txt} on {row.get('date') or '?'}{model} [{row['module']}]")
    for entry in card["cvss"][:4]:
        severity = f" {entry['severity']}" if entry.get("severity") else ""
        version = f" v{entry['version']}" if entry.get("version") else ""
        lines.append(f"CVSS {entry['score']:.1f}{severity}{version} ({entry.get('source') or '?'}) [{entry.get('module') or '?'}]")
    for source, date in list(card["exploited"].items())[:6]:
        lines.append(f"exploitation evidence: {source}{f' since {date}' if date else ''}")
    if card["exploits"]["count"]:
        lines.append(f"exploits: {card['exploits']['count']} curated exploit/PoC reference(s) (links only)")
    fixes = card["vendor_fix"]["fixed_versions"]
    if fixes:
        shown = "; ".join(f"{f.get('product') or '?'} {f['fixed']}" for f in fixes[:5])
        lines.append(f"fixed versions: {shown}")
    if card["vendor_fix"]["advisories"]:
        lines.append(f"vendor advisories: {len(card['vendor_fix']['advisories'])}")
    if card["affected"]:
        lines.append("affected: " + "; ".join(a["product"] for a in card["affected"][:5]))
    if card["cwe"]:
        lines.append("weakness: " + "; ".join(card["cwe_names"][:4] or card["cwe"][:4]))
    if card["own_assets"]:
        lines.append(f"linked to own asset(s): {', '.join(card['own_assets'][:5])} - asset severity is decided by CR15 (P291)")
    return lines


@rule(
    RULE_ID,
    "CVE card: consolidated facts and patch priority",
    "One informational card per CVE built from the facts of every CVE module (provenance per line), with one "
    "plain-words patch-priority line (P183 cond 5/6). Never raises the case risk level: asset severity is CR15's (P291).",
    version="1",
    severity="info",
    criterion="facts reported by the CVE modules on the CVE node (KEV, EPSS, CVSS, exploitation evidence, fix); priority from KEV, EPSS and CVSS",
    references=("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "https://www.first.org/epss/"),
    false_positives="EPSS is a probability, not an observation; a CVE missing from KEV may still be exploited.",
    fixtures=("tests/fixtures/rules/g08_cve_card/",),
)
def g08_cve_card(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.of_type(EntityType.CVE):
        card = build_card(node, graph)
        if card is None:
            continue
        priority = card["priority"]
        lines = card_lines(card)
        description = (card.get("description") or "").strip()
        summary = f"Patch priority: {priority['line']}." + (f" {description[:600]}" if description else "")
        if card["notices"]:
            summary += " Notices: " + " ".join(card["notices"])
        tags = []
        if card["kev"].get("listed"):
            tags.append("kev")
        if card["exploits"]["count"]:
            tags.append("exploit_available")
        yield Correlation(
            rule=RULE_ID,
            title=f"{card['cve']}: {priority['line']}",
            severity=Severity.INFO,
            description=summary,
            entities=[node.entity],
            confidence=0.9,
            evidence=lines,
            recommendation=_RECOMMENDATION.get(priority["label"], priority["line"]),
            tags=tags,
            criterion=f"consolidated CVE card from {', '.join(card['modules'])}; priority label '{priority['label']}' (informational, never scored)",
            why=priority["label"],
        )
