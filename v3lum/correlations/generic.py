"""Generic cross-source correlation rules (work with any module that follows v3lum.core.vocab).

Noise semantics (AR06): ``seeds_linked`` and ``shared_infrastructure`` never link entities through
noise nodes (shared resolvers, webmail, CDN/cloud/hosting/SaaS front doors such as
``aspmx.l.google.com``) nor through weak relations (:func:`weak_edge`): mail exchangers, name
servers and certificate SANs say nothing about common ownership, an ``expand=False``
``hosted_domain`` or any edge below :data:`MIN_LINK_CONFIDENCE` is too weak, and the address of a
site hosted on a legitimate platform (``hosted_on_legit_platform``) is the platform's.

Suppression semantics (P322 cond 4, P171 cond 5, A4 BR6): the engine's suppression stage runs
before these rules. A finding tagged ``context_only`` (sinkholes, generic/role/test addresses,
third-party breach context) or downgraded by a core suppression rule (``SUP-*``: warninglist,
sinkhole, generic address) is never evidence for a correlation (:func:`evidence_finding`); an
analyst override keeps it as evidence unless its verdict is a false positive. ``breach_and_infostealer``
never fires for generic/role/test addresses and stays MEDIUM context for anything that is not a
verified own asset (A4 BR9-BR10: third-party addresses are at most MEDIUM, never scored as exposure).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from v3lum.core import entities as _entities
from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import LEGIT_PLATFORM_TAG, Edge, Graph, Node
from v3lum.core.models import Correlation, Finding, ModuleResult, Severity

BAD_TAGS = ("malicious", "phishing", "malware", "c2", "botnet")
#: Tag of findings shown as context only: never evidence for a correlation (vocab, A4 BR6).
CONTEXT_ONLY = "context_only"
#: Prefix of the engine's named suppression rules (SUP-warninglist, SUP-sinkhole, SUP-generic_address).
SUPPRESSION_PREFIX = "SUP-"
#: Analyst override verdicts that take a finding out of the evidence.
FALSE_POSITIVE_VERDICTS = frozenset({"false_positive", "false positive", "fp", "benign", "wrong", "negative", "not_malicious"})

#: Relations that never link two entities in ``seeds_linked``/``shared_infrastructure`` (AR06).
WEAK_RELATIONS = frozenset({"mx_host", "nameserver", "cert_san"})
#: Edges below this confidence never link two entities (AR06).
MIN_LINK_CONFIDENCE = 0.6
#: Relations through a platform's shared address (a tenant site's IP is the platform's).
_PLATFORM_RELATIONS = frozenset({"resolves_to", "hosted_domain"})


def weak_edge(graph: Graph, edge: Edge) -> bool:
    """True for relations too weak to link entities: mx_host, nameserver, cert_san; hosted_domain
    pivoted with expand=False; any edge with confidence < 0.6; resolves_to/hosted_domain touching a
    site hosted on a legitimate platform (AR06)."""
    if edge.relation in WEAK_RELATIONS:
        return True
    if edge.relation == "hosted_domain" and not getattr(edge, "expand", True):
        return True
    try:
        if float(edge.confidence) < MIN_LINK_CONFIDENCE:
            return True
    except (TypeError, ValueError):
        return True
    if edge.relation in _PLATFORM_RELATIONS:
        for key in (edge.src, edge.dst):
            node = graph.nodes.get(key)
            if node is not None and LEGIT_PLATFORM_TAG in node.tags:
                return True
    return False


def evidence_finding(f: Finding) -> bool:
    """May ``f`` support a correlation? Not when it is ``context_only`` or was downgraded by a core
    suppression rule (``SUP-*``): suppression runs before the rules and only downgrades, and a
    correlation built on the suppressed findings would undo it. An analyst override keeps the
    finding as evidence unless its verdict says false positive (analyst decisions always win)."""
    override = getattr(f, "override", None)
    if override:
        verdict = str(override.get("verdict") or "").strip().lower() if isinstance(override, dict) else ""
        return verdict not in FALSE_POSITIVE_VERDICTS
    if CONTEXT_ONLY in f.tags:
        return False
    return not any(
        str(s.get("rule", "")).startswith(SUPPRESSION_PREFIX) and not s.get("blocked_by") for s in (f.suppressed_by or ()) if isinstance(s, dict)
    )


def _evidence(node: Node) -> list[Finding]:
    return [f for f in node.findings if evidence_finding(f)]


def _has_evidence_tag(node: Node, tag: str) -> bool:
    return any(tag in f.tags for f in _evidence(node))


def _modules_with_tags(node: Node, tags: Iterable[str]) -> set[str]:
    return {f.module for f in _evidence(node) if any(t in f.tags for t in tags)}


def _suppressed_entity(node: Node) -> bool:
    """Sinkholed (entity tag) or on a warninglist (``noise.warninglists``)."""
    if "sinkhole" in node.tags:
        return True
    try:
        from v3lum.core import noise

        return bool(noise.warninglists(node.entity))
    except Exception:  # noqa: BLE001 - list problems are reported by noise.errors()
        return False


def generic_address(node: Node) -> bool:
    """A generic, role or test address (attribute ``generic_address`` or the bundled list, A4 BR6)."""
    if node.attr("generic_address"):
        return True
    if node.entity.type is EntityType.EMAIL:
        try:
            return bool(_entities.generic_address_kind(node.entity))
        except Exception:  # noqa: BLE001 - an unreadable list never flags an address
            return False
    return False


def _verified_own(node: Node, rctx: Any) -> bool:
    """A verified own asset (txt_verified/attested org-profile domain, A4 BR9/A11 BR4)."""
    if node.ownership != "own_asset":
        return False
    org = getattr(rctx, "org", None)
    owns = getattr(org, "owns", None)
    if not callable(owns):
        return False
    try:
        own = owns(node.entity)
    except Exception:  # noqa: BLE001 - a profile problem never makes an asset verified
        return False
    return bool(getattr(own, "own", False) and getattr(own, "verified", False))


@rule("multi_source_malicious", "Independent sources agree the entity is malicious")
def multi_source_malicious(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.nodes.values():
        mods = _modules_with_tags(node, BAD_TAGS)
        # on a sinkholed or warninglisted entity the 'malicious' flags are suppressed like the
        # findings (P171 cond 5: suppression runs before consensus)
        flagged_attr = [] if _suppressed_entity(node) else [src for v, src in node.attributes.get("malicious", []) if v]
        sources = mods | set(flagged_attr)
        if len(sources) >= 2:
            yield Correlation(
                rule="multi_source_malicious",
                title=f"{node.entity.display} flagged malicious by {len(sources)} independent sources",
                severity=Severity.CRITICAL,
                description="Multiple unrelated threat-intel sources classify this indicator as malicious, which makes a false positive unlikely.",
                entities=[node.entity],
                confidence=min(0.99, 0.75 + 0.08 * len(sources)),
                evidence=sorted(sources),
                recommendation="Block the indicator at the perimeter/EDR and hunt for it in logs (proxy, DNS, mail).",
                tags=["malicious"],
            )


@rule("shared_infrastructure", "Several investigated domains share the same IP")
def shared_infrastructure(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    by_ip: dict[str, set[str]] = defaultdict(set)
    for e in graph.edges:
        if e.relation != "resolves_to" or weak_edge(graph, e):
            continue
        src = graph.nodes.get(e.src)
        if src is None or src.noise:  # noise domains never 'share infrastructure' (AR06)
            continue
        by_ip[e.dst].add(e.src)
    for ip_key, domains in by_ip.items():
        ip_node = graph.nodes.get(ip_key)
        if ip_node is None or ip_node.noise or len(domains) < 2:
            continue
        dom_nodes = [graph.nodes[d] for d in domains if d in graph.nodes]
        bad = [n for n in dom_nodes if _modules_with_tags(n, BAD_TAGS)]
        cdn = bool(ip_node.attr("is_cdn")) or bool(ip_node.attr("is_hosting"))
        sev = Severity.HIGH if bad else Severity.LOW if cdn else Severity.MEDIUM
        yield Correlation(
            rule="shared_infrastructure",
            title=f"{len(dom_nodes)} domains resolve to {ip_node.entity.display}",
            severity=sev,
            description=(
                "Domains in this investigation share hosting. "
                + ("At least one of them is flagged malicious, so the others deserve scrutiny. " if bad else "")
                + ("The IP belongs to a CDN/hosting provider: co-hosting may be coincidental." if cdn else "")
            ).strip(),
            entities=[ip_node.entity] + [n.entity for n in dom_nodes],
            confidence=0.55 if cdn else 0.75,
            evidence=sorted(domains),
            recommendation="Review the co-hosted domains; on dedicated hosting they often belong to the same operator.",
            tags=["infrastructure"],
        )


@rule("seeds_linked", "Two of the analyst's inputs are connected")
def seeds_linked(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    seeds = graph.seeds()
    if len(seeds) < 2:
        return
    adj: dict[str, set[str]] = defaultdict(set)
    for e in graph.edges:
        if weak_edge(graph, e):  # mx_host / nameserver / cert_san / weak or platform edges (AR06)
            continue
        adj[e.src].add(e.dst)
        adj[e.dst].add(e.src)
    seed_keys = {s.key for s in seeds}
    for s in seeds:
        # BFS up to 3 hops, never walking through noise nodes.
        frontier, seen, parent = [s.key], {s.key}, {s.key: ""}
        for _ in range(3):
            nxt = []
            for k in frontier:
                for m in adj.get(k, ()):
                    node = graph.nodes.get(m)
                    if m in seen or node is None or (node.noise and m not in seed_keys):
                        continue
                    seen.add(m)
                    parent[m] = k
                    nxt.append(m)
            frontier = nxt
        for other in seed_keys:
            if other <= s.key or other not in seen:
                continue
            path, cur = [], other
            while cur:
                path.append(cur)
                cur = parent.get(cur, "")
            path.reverse()
            yield Correlation(
                rule="seeds_linked",
                title=f"Inputs {graph.nodes[s.key].entity.display} and {graph.nodes[other].entity.display} are linked",
                severity=Severity.MEDIUM,
                description="The investigation found a chain of relations connecting two inputs: " + " -> ".join(path),
                entities=[graph.nodes[k].entity for k in path if k in graph.nodes],
                confidence=0.8 if len(path) <= 3 else 0.6,
                evidence=path,
                recommendation="Confirm the link: shared infrastructure or identity between inputs is often the key finding.",
                tags=["identity", "infrastructure"],
            )


@rule("username_reuse", "Same handle on many platforms")
def username_reuse(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.of_type(EntityType.USERNAME):
        accounts = [e for e in graph.out_edges(node.key, "has_account")]
        profiles = node.attr_values("profiles")
        count = max(len(accounts), len(profiles))
        if count >= 3:
            yield Correlation(
                rule="username_reuse",
                title=f"Handle '{node.entity.value}' found on {count} platforms",
                severity=Severity.LOW,
                description="The same username is registered on several services. It may be the same person, but common handles collide: confirm with profile photo, bio, links and dates.",
                entities=[node.entity],
                confidence=0.6,
                evidence=[e.dst for e in accounts][:20],
                recommendation="Pivot on the profiles' declared links, avatars and creation dates to confirm the identity.",
                tags=["identity", "account"],
            )


@rule("breach_and_infostealer", "Credential exposure from breaches and infostealer logs")
def breach_and_infostealer(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    for node in graph.of_type(EntityType.EMAIL, EntityType.USERNAME, EntityType.DOMAIN):
        if generic_address(node):
            continue  # generic/role/test addresses are context only, never scored as exposure (A4 BR6)
        breach = _has_evidence_tag(node, "breach") or bool(node.attr("breach_count"))
        stealer = _has_evidence_tag(node, "infostealer") or bool(node.attr("infostealer"))
        if breach and stealer:
            own = _verified_own(node, rctx)
            yield Correlation(
                rule="breach_and_infostealer",
                title=f"{node.entity.display}: in data breaches AND in infostealer logs",
                # A4 BR9-BR10: only a verified own asset is exposure; anything else is MEDIUM context
                severity=Severity.HIGH if own else Severity.MEDIUM,
                description="Infostealer logs contain live session cookies and saved passwords taken from an infected device; combined with breach exposure this indicates an active account-takeover risk."
                + ("" if own else " Not a verified own asset: context only, not scored as exposure."),
                entities=[node.entity],
                confidence=0.85,
                recommendation="Force password reset and session revocation, enforce MFA, check the device for malware.",
                tags=["credential_exposure", "infostealer", "breach"] + ([] if own else [CONTEXT_ONLY]),
            )


@rule("young_domain", "Recently registered domain")
def young_domain(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.of_type(EntityType.DOMAIN):
        age = node.attr("domain_age_days")
        if age is None:
            continue
        try:
            age = int(age)
        except (TypeError, ValueError):
            continue
        if age <= 30 and not node.noise:
            lookalike = node.has_tag("typosquat") or bool(graph.in_edges(node.key, "lookalike"))
            yield Correlation(
                rule="young_domain",
                title=f"{node.entity.display} was registered {age} day(s) ago" + (" and imitates a known brand" if lookalike else ""),
                severity=Severity.HIGH if lookalike else Severity.MEDIUM,
                description="Most phishing and malware domains are used within days of registration.",
                entities=[node.entity],
                confidence=0.8 if lookalike else 0.6,
                recommendation="Treat as suspicious until proven otherwise; monitor DNS/MX and consider pre-emptive blocking.",
                tags=["newly_registered"] + (["typosquat"] if lookalike else []),
            )


@rule("exploitable_exposure", "Exposed host with exploited vulnerabilities")
def exploitable_exposure(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.of_type(EntityType.IPV4, EntityType.IPV6, EntityType.DOMAIN):
        cves = [n for n in graph.neighbors(node.key, "has_vuln")]
        kev = [c for c in cves if c.attr("kev")]
        hot = [c for c in cves if (c.attr("epss") or 0) >= 0.5]
        if kev or hot:
            worst = kev or hot
            yield Correlation(
                rule="exploitable_exposure",
                title=f"{node.entity.display} exposes {len(worst)} vulnerabilit{'y' if len(worst) == 1 else 'ies'} with known/likely exploitation",
                severity=Severity.CRITICAL if kev else Severity.HIGH,
                description="Vulnerabilities on this host are in CISA KEV and/or have a high EPSS exploitation probability.",
                entities=[node.entity] + [c.entity for c in worst[:10]],
                confidence=0.7,
                evidence=[c.entity.value for c in worst[:20]],
                recommendation="Patch or isolate the exposed service; version-based CVE matches must be confirmed on the host.",
                tags=["vulnerable", "kev" if kev else "exploit_available"],
            )


@rule("high_signal_tags", "Critical intelligence tags")
def high_signal_tags(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    specs = [
        ("ransomware", Severity.CRITICAL, "listed in ransomware / extortion data", "Engage incident response; validate the leak claim and notify stakeholders."),
        ("sanctions", Severity.CRITICAL, "appears on a sanctions list", "Stop transactions and escalate to compliance/legal."),
        ("takeover", Severity.HIGH, "may be vulnerable to subdomain takeover", "Remove the dangling DNS record or reclaim the resource."),
        ("credential_exposure", Severity.HIGH, "has exposed credentials/secrets", "Rotate the exposed secrets and review access logs."),
    ]
    for node in graph.nodes.values():
        evidence = _evidence(node)
        for tag, sev, text, rec in specs:
            mods = sorted({f.module for f in evidence if tag in f.tags})
            if mods:
                yield Correlation(
                    rule=f"tag_{tag}",
                    title=f"{node.entity.display} {text}",
                    severity=sev,
                    description=f"Reported by: {', '.join(mods)}.",
                    entities=[node.entity],
                    confidence=0.8,
                    evidence=mods,
                    recommendation=rec,
                    tags=[tag],
                )
