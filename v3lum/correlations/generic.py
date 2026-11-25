"""Generic cross-source correlation rules (work with any module that follows v3lum.core.vocab)."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Correlation, ModuleResult, Severity

BAD_TAGS = ("malicious", "phishing", "malware", "c2", "botnet")


def _modules_with_tags(node: Node, tags: Iterable[str]) -> set[str]:
    return {f.module for f in node.findings if any(t in f.tags for t in tags)}


@rule("multi_source_malicious", "Independent sources agree the entity is malicious")
def multi_source_malicious(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.nodes.values():
        mods = _modules_with_tags(node, BAD_TAGS)
        flagged_attr = [src for v, src in node.attributes.get("malicious", []) if v]
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
        if e.relation == "resolves_to":
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
def breach_and_infostealer(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.of_type(EntityType.EMAIL, EntityType.USERNAME, EntityType.DOMAIN):
        breach = node.has_tag("breach") or bool(node.attr("breach_count"))
        stealer = node.has_tag("infostealer") or bool(node.attr("infostealer"))
        if breach and stealer:
            yield Correlation(
                rule="breach_and_infostealer",
                title=f"{node.entity.display}: in data breaches AND in infostealer logs",
                severity=Severity.HIGH,
                description="Infostealer logs contain live session cookies and saved passwords taken from an infected device; combined with breach exposure this indicates an active account-takeover risk.",
                entities=[node.entity],
                confidence=0.85,
                recommendation="Force password reset and session revocation, enforce MFA, check the device for malware.",
                tags=["credential_exposure", "infostealer", "breach"],
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
        for tag, sev, text, rec in specs:
            mods = sorted({f.module for f in node.findings if tag in f.tags})
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
