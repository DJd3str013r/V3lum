"""Correlation rules of batch p2-G03-1 (P061 analytics ids, P345 takedown packet).

* ``g03_same_analytics`` (P061 cond 5, 7, 8): domains of the case that carry the same analytics id
  (grouped by UA account / AdSense publisher) are linked ``same_analytics`` - PROBABLE at most (0.7), never
  sufficient alone for CONFIRMED ownership (P013), at most 10 links per id. Archived sightings carry their
  snapshot dates and a link needs overlapping dates (each window widened by 90 days); every link names the
  id and where each side was seen (live page, archive snapshot, GTM container, text input). Shared ids
  (template/placeholder ids, known agency/CMS ids, reverse lookups with more than 50 domains) give no
  same-owner correlation.
* ``g03_analytics_clone`` (P061 cond 6): a non-own site carrying an id used by an org-profile own site is
  'possible clone of <brand> (copied tracking ID)': a phishing indicator, never a same-owner link.
* ``g03_takedown_packet_ready`` (P345 cond 2): a hostile URL/host with a finding >= HIGH backed by
  consensus (>= 2 independent upstream families, P171) or an analyst confirmation announces its takedown
  packet (ranked contacts, CERT.br guidance, manual links); a single-source hit never does.

Rules only read the graph: they never schedule modules, change findings or contact anything.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from v3lum.core import psl
from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Correlation, ModuleResult, Severity
from v3lum.modules.url_web.analytics_ids import (
    REVERSE_PIVOT_CAP,
    SAME_ANALYTICS_MAX_CONFIDENCE,
    SHARED_FANOUT_THRESHOLD,
    analytics_key,
    is_template_id,
    normalise_analytics_id,
    parse_iso,
    shared_id_decision,
    sighting_label,
    windows_overlap,
)
from v3lum.modules.url_web.takedown_packet import (
    build_packet,
    hostile_targets,
    view_from_graph,
)

RULE_SAME = "g03_same_analytics"
RULE_CLONE = "g03_analytics_clone"
RULE_TAKEDOWN = "g03_takedown_packet_ready"
SIGHTING_RELATIONS = frozenset({"same_analytics", "mentions", "historical_analytics_id", "copied_tracking_id"})
ARCHIVE_RELATIONS = frozenset({"historical_analytics_id"})
UTC = timezone.utc


def _host(node: Node) -> str | None:
    if node.entity.type is EntityType.DOMAIN:
        return str(node.entity.value).lower()
    if node.entity.type is EntityType.URL:
        from urllib.parse import urlsplit

        try:
            return (urlsplit(str(node.entity.value)).hostname or "").lower() or None
        except ValueError:
            return None
    return None


def _archive_dates(node: Node, analytics_id: str) -> list[datetime]:
    """Snapshot dates of an id on a domain node (archive_mining 'archived_analytics_ids', web_archives
    'homepage_indicators')."""
    dates: list[datetime] = []
    for item in node.attr_values("archived_analytics_ids"):
        if isinstance(item, dict) and normalise_analytics_id(item.get("id")) == analytics_id:
            for k in ("first_seen", "last_seen"):
                dt = parse_iso(item.get(k))
                if dt:
                    dates.append(dt)
            snaps = item.get("snapshots")
            for snap in snaps if isinstance(snaps, list) else []:
                dt = parse_iso(snap if isinstance(snap, str) else (snap or {}).get("timestamp") if isinstance(snap, dict) else None)
                if dt:
                    dates.append(dt)
    for item in node.attr_values("homepage_indicators"):
        if isinstance(item, dict) and analytics_id in [normalise_analytics_id(x) for x in item.get("analytics_ids") or []]:
            dt = parse_iso(item.get("captured_at") or item.get("snapshot"))
            if dt:
                dates.append(dt)
    return dates


def _own(node: Node, rctx: Any) -> bool:
    if node.ownership == "own_asset" or "own_asset" in node.tags:
        return True
    org = getattr(rctx, "org", None)
    try:
        return bool(org is not None and org.owns(node.entity).own)
    except Exception:  # noqa: BLE001
        return False


def _brand(rctx: Any) -> str:
    org = getattr(rctx, "org", None)
    for brand in getattr(org, "brands", None) or []:
        name = getattr(brand, "name", "")
        if name:
            return str(name)
    return str(getattr(org, "name", "") or "")


def _sightings(graph: Graph, now: datetime) -> dict[str, dict[str, Any]]:
    """key -> {"ids", "domains": {domain: {"node", "where": [...], "first", "last", "dated"}}, "shared_hints", "reverse_total"}"""
    groups: dict[str, dict[str, Any]] = {}

    def add(key: str, aid: str, dom_node: Node, where: str, *, dates: list[datetime] | None, container: str | None = None) -> None:
        host = _host(dom_node)
        if not host:
            return
        g = groups.setdefault(key, {"ids": set(), "domains": {}, "shared_hints": [], "reverse_total": None})
        g["ids"].add(aid)
        rec = g["domains"].setdefault(host, {"node": dom_node, "where": [], "first": None, "last": None})
        if where == "archive" and not dates:
            rec["where"].append("archive snapshot (undated)")
            return
        points = dates or [now]
        rec["first"] = min([d for d in [rec["first"], *points] if d])
        rec["last"] = max([d for d in [rec["last"], *points] if d])
        if where == "archive":
            rec["where"].append(sighting_label("archive", snapshot=min(points).strftime("%Y%m%d")))
        elif where == "gtm":
            rec["where"].append(sighting_label("gtm", container=container, seen_at=now.isoformat()))
        else:
            rec["where"].append(sighting_label("live", seen_at=now.isoformat()))

    for node in graph.of_type(EntityType.ANALYTICS_ID):
        aid = normalise_analytics_id(str(node.entity.value)) or str(node.entity.value)
        key = analytics_key(aid) or aid
        for edge in graph.in_edges(node.key):
            if edge.relation not in SIGHTING_RELATIONS:
                continue
            src = graph.get(edge.src)
            if src is None or src.entity.type not in (EntityType.DOMAIN, EntityType.URL):
                continue
            dates = _archive_dates(src, aid)
            archive = edge.relation in ARCHIVE_RELATIONS or (bool(dates) and edge.module in ("archive_mining", "web_archives", "web_archives_deep"))
            add(key, aid, src, "archive" if archive else "live", dates=dates if archive else None)
        for edge in graph.out_edges(node.key, "same_analytics"):
            dst = graph.get(edge.dst)
            if dst is not None and dst.entity.type is EntityType.DOMAIN:
                add(key, aid, dst, "live", dates=None)
        for edge in graph.in_edges(node.key, "gtm_loads"):
            container = graph.get(edge.src)
            if container is None:
                continue
            for e2 in graph.in_edges(container.key):
                src = graph.get(e2.src)
                if e2.relation in SIGHTING_RELATIONS and src is not None and src.entity.type in (EntityType.DOMAIN, EntityType.URL):
                    add(key, aid, src, "gtm", dates=None, container=str(container.entity.value))
        g = groups.get(key)
        if g is None:
            continue
        for item in node.attr_values("analytics_shared_id"):
            if isinstance(item, dict) and item.get("shared"):
                g["shared_hints"].append(str(item.get("reason") or "reverse lookup: shared"))
            if isinstance(item, dict) and isinstance(item.get("domains"), int):
                g["reverse_total"] = max(g["reverse_total"] or 0, item["domains"])
        if node.tagged("shared_tracking_id"):
            g["shared_hints"].append("flagged shared by a reverse-lookup module")
    for node in graph.of_type(EntityType.DOMAIN):
        for value in node.attr_values("shared_tracking_ids"):
            aid = normalise_analytics_id(str(value)) if isinstance(value, str) else None
            key = analytics_key(aid) if aid else None
            if key and key in groups:
                groups[key]["shared_hints"].append(f"seen on more than {SHARED_FANOUT_THRESHOLD} domains (reverse lookup counts)")
    return groups


def _shared(key: str, group: dict[str, Any]) -> str | None:
    sample = sorted(group["ids"])[0] if group["ids"] else key
    if is_template_id(sample) or is_template_id(key):
        return "template/placeholder id"
    total = group["reverse_total"]
    if total is None and len(group["domains"]) > SHARED_FANOUT_THRESHOLD:
        total = len(group["domains"])
    decision = shared_id_decision(sample, total)
    if decision["shared"]:
        return str(decision["reason"])
    if group["shared_hints"]:
        return group["shared_hints"][0]
    return None


def _registrable(host: str) -> str:
    return psl.registrable_domain(host) or host


@rule(
    RULE_SAME,
    "Domains share an analytics id",
    "Sites of the case carry the same Google Analytics / Tag Manager / AdSense id (same UA account or AdSense publisher): "
    "a PROBABLE same-owner link at most, never sufficient alone for CONFIRMED ownership; archived sightings need overlapping "
    "dates; shared agency/CMS/template ids are never linked (P061 cond 5, 7, 8).",
    version="1",
    severity="info",
    criterion="the same analytics id (or UA account / AdSense publisher) on at least two registrable domains with overlapping sighting dates",
    false_positives="Agency or CMS ids reused across clients, templates left in themes, ids copied by clones, a former owner's archived pages.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_SAME}/positive_two_sites_one_ga4_id.json",
        f"tests/fixtures/rules/{RULE_SAME}/positive_archive_dates_overlap.json",
        f"tests/fixtures/rules/{RULE_SAME}/negative_template_and_high_fanout.json",
        f"tests/fixtures/rules/{RULE_SAME}/negative_archive_eras_do_not_overlap.json",
    ),
)
def same_analytics(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    now = getattr(rctx, "now", None) or datetime.now(UTC)
    for key, group in sorted(_sightings(graph, now).items()):
        if _shared(key, group):
            continue
        others = {d: rec for d, rec in group["domains"].items() if not _own(rec["node"], rctx)}
        by_reg: dict[str, str] = {}
        for d in sorted(others):
            by_reg.setdefault(_registrable(d), d)
        cand = [others[d] for d in by_reg.values()]
        links: list[str] = []
        ents = []
        for i in range(len(cand)):
            for j in range(i + 1, len(cand)):
                a, b = cand[i], cand[j]
                if not windows_overlap((a["first"], a["last"]), (b["first"], b["last"])):
                    continue
                if len(links) >= REVERSE_PIVOT_CAP:
                    break
                da, db = _host(a["node"]), _host(b["node"])
                links.append(f"{da} ({'; '.join(sorted(set(a['where'])))}) <-> {db} ({'; '.join(sorted(set(b['where'])))})")
                for n in (a["node"], b["node"]):
                    if n.entity not in ents:
                        ents.append(n.entity)
        if not links:
            continue
        ids = ", ".join(sorted(group["ids"]))
        yield Correlation(
            rule=RULE_SAME,
            title=f"Domains share analytics id {key}",
            severity=Severity.INFO,
            description=(f"{len(ents)} domains carry analytics id {ids}: {len(links)} same_analytics link(s). A shared tracking id is a "
                         "PROBABLE same-owner link at most and never sufficient alone for CONFIRMED ownership (agencies and CMS reuse ids)."),
            entities=ents[: REVERSE_PIVOT_CAP + 1],
            confidence=SAME_ANALYTICS_MAX_CONFIDENCE,
            evidence=[f"id {key}: {line}" for line in links],
            recommendation="Corroborate ownership with an independent signal (RDAP registrant org, M365 tenant, certificates) before treating the sites as one organisation.",
            tags=["infrastructure"],
            criterion=f"same analytics id {key} on {len(ents)} registrable domains with overlapping sighting dates; never sufficient alone for CONFIRMED ownership",
            key=key,
        )


@rule(
    RULE_CLONE,
    "Possible clone of an organisation site (copied tracking ID)",
    "A site outside the organisation carries an analytics / tag-manager / AdSense id used by an org-profile own site: "
    "'possible clone of <brand> (copied tracking ID)', a phishing indicator - never a same-owner link (P061 cond 6).",
    version="1",
    severity="medium",
    criterion="an analytics id of an org-profile own domain found on a non-own registrable domain with an overlapping sighting date",
    false_positives="A supplier, agency or subsidiary site not yet in the org profile; shared template ids (excluded).",
    fixtures=(
        f"tests/fixtures/rules/{RULE_CLONE}/positive_brand_id_on_lookalike.json",
        f"tests/fixtures/rules/{RULE_CLONE}/negative_own_sites_and_template_id.json",
    ),
)
def analytics_clone(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    now = getattr(rctx, "now", None) or datetime.now(UTC)
    brand = _brand(rctx)
    for key, group in sorted(_sightings(graph, now).items()):
        if _shared(key, group):
            continue
        own = {d: rec for d, rec in group["domains"].items() if _own(rec["node"], rctx)}
        if not own:
            continue
        own_regs = {_registrable(d) for d in own}
        own_rec = own[sorted(own)[0]]
        for host, rec in sorted(group["domains"].items()):
            if host in own or _registrable(host) in own_regs:
                continue
            try:
                supplier = rctx.org is not None and _registrable(host) in {_registrable(s) for s in rctx.org.supplier_domains()}
            except Exception:  # noqa: BLE001
                supplier = False
            if supplier:
                continue
            if not windows_overlap((own_rec["first"], own_rec["last"]), (rec["first"], rec["last"])):
                continue
            label = brand or _host(own_rec["node"]) or "the organisation"
            yield Correlation(
                rule=RULE_CLONE,
                title=f"Possible clone of {label} (copied tracking ID)",
                severity=Severity.MEDIUM,
                description=(f"{host} carries {', '.join(sorted(group['ids']))}, the tracking id of own site {_host(own_rec['node'])}: a phishing "
                             "indicator (pages copied with their tracking code), never a same-owner link."),
                entities=[rec["node"].entity, own_rec["node"].entity],
                confidence="possible",
                evidence=[f"id {key}: {host} ({'; '.join(sorted(set(rec['where'])))})",
                          f"own site {_host(own_rec['node'])} ({'; '.join(sorted(set(own_rec['where'])))})"],
                recommendation="Review the site for brand abuse (screenshot through urlscan, passive checks only) and consider a takedown packet if it is hostile.",
                tags=["brand_abuse", "possible_clone", "suspicious"],
                criterion=f"tracking id {key} of an org-profile own domain on non-own {host} (overlapping sightings); never a same-owner link",
                key=f"{key}|{host}",
            )


@rule(
    RULE_TAKEDOWN,
    "Takedown packet ready",
    "A hostile URL or host has a finding >= HIGH backed by consensus (two or more independent upstream families) or an analyst "
    "confirmation: its takedown packet (ranked abuse contacts, CERT.br guidance, manual report links, evidence hashes) can be "
    "exported. Never from a single-source hit; V3LUM never sends or submits anything (P345 cond 2, 5).",
    version="1",
    severity="info",
    criterion="hostile finding >= HIGH on the entity backed by >= 2 independent upstream families or an analyst confirmation",
    false_positives="Consensus between feeds that copy each other without declaring it (embeds); a compromised legitimate site (owner contact first).",
    fixtures=(
        f"tests/fixtures/rules/{RULE_TAKEDOWN}/positive_consensus_registrar_rir_abusix.json",
        f"tests/fixtures/rules/{RULE_TAKEDOWN}/positive_br_analyst_confirmed.json",
        f"tests/fixtures/rules/{RULE_TAKEDOWN}/negative_single_source_hit.json",
    ),
)
def takedown_packet_ready(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    now = getattr(rctx, "now", None) or datetime.now(UTC)
    options = getattr(rctx, "options", None)
    tlp = str(getattr(options, "tlp", "") or "amber")
    view = view_from_graph(graph, results, now=now, tlp=tlp)
    seen_hosts: set[str] = set()
    for target, _findings in hostile_targets(view):
        packet = build_packet(view, now=now, target_key=target.key)
        if not packet.get("generated") or not packet["gate"].get("automatic"):
            continue
        host = packet["target"].get("host") or target.value
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        node = graph.get(target.key)
        contacts = [f"contact {c['order']}: {c.get('email') or c.get('url')} - {c['reason']}" for c in packet["contacts"][:5]]
        evidence = [f"why: {packet['gate']['reason']}"] + contacts
        if packet.get("cert_br"):
            evidence.append(f"CERT.br: {packet['cert_br']['guidance_en']}")
        evidence += [f"manual link: {lk['name']}" for lk in packet["manual_links"]]
        yield Correlation(
            rule=RULE_TAKEDOWN,
            title=f"Takedown packet ready: {packet['target'].get('host_defanged') or target.key}",
            severity=Severity.INFO,
            description=(f"{len(packet['contacts'])} ranked abuse contact(s), {len(packet['evidence'])} evidence hash(es)"
                         + (", CERT.br in Cc" if packet.get("cert_br") else "") + f". {packet['disclosure_note']}"),
            entities=[node.entity] if node is not None else [],
            confidence="probable",
            evidence=evidence,
            recommendation=("Export the takedown packet (takedown_packet.build_takedown_packet over the stored case) and send it yourself; "
                            "record the disclosure decision in the case audit."),
            tags=["takedown_ready"],
            criterion=f"P345 cond 2 gate: {packet['gate']['reason']}",
            key=target.key,
        )
