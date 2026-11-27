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
analyst override keeps it as evidence unless its verdict is a false positive.

Legacy rules (WP22): ``multi_source_malicious``, ``breach_and_infostealer`` and
``exploitable_exposure`` were removed from this file. Their replacements live in the packs:
``threat_intel.multi_source_malicious`` (CR27) and ``attack_surface.exploitable_exposure`` keep the
ids; CR09-CR12 of ``breach.py`` replace ``breach_and_infostealer``. ``seeds_linked``,
``shared_infrastructure``, ``username_reuse``, ``young_domain`` and ``high_signal_tags`` stay here.

``high_signal_tags`` is homonym-safe (AR08): a 'ransomware' or 'sanctions' tag is CRITICAL only
with an exact identifier match (CNPJ, LEI, wallet, domain, URL) or with >= 2 independent upstream
families; a name-only match is MEDIUM/POSSIBLE 'possible match - verify identifiers', states the
match type and carries the underlying confidence.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from v3lum.core import entities as _entities
from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import LEGIT_PLATFORM_TAG, Edge, Graph, Node
from v3lum.core.models import Confidence, Correlation, Finding, ModuleResult, Severity

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


@rule("shared_infrastructure", "Several investigated domains share the same IP", severity="high",
      criterion="two or more investigated domains resolve to the same non-noise IP (weak relations excluded, AR06)")
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


@rule("seeds_linked", "Two of the analyst's inputs are connected", severity="medium",
      criterion="a chain of at most 3 non-weak relations, never through noise nodes, connects two seeds (AR06)")
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


@rule("username_reuse", "Same handle on many platforms", severity="low",
      criterion="the same handle has accounts/profiles on >= 3 platforms (same handle does not prove identity)")
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


@rule("young_domain", "Recently registered domain", severity="high",
      criterion="domain_age_days <= 30 on a non-noise domain (HIGH when it also imitates a known brand)")
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




# ----------------------------------------------------------------------------------------
# AR08: homonym-safe high-signal tags
# ----------------------------------------------------------------------------------------

#: Tags that may yield CRITICAL - only with an exact identifier match or >= 2 upstream families (AR08).
CRITICAL_TAGS: dict[str, tuple[str, str]] = {
    "ransomware": ("listed in ransomware / extortion data", "Engage incident response; validate the leak claim and notify stakeholders."),
    "sanctions": ("appears on a sanctions list", "Stop transactions and escalate to compliance/legal."),
}
#: Other high-signal tags: HIGH at most, with the underlying confidence.
HIGH_TAGS: dict[str, tuple[str, str]] = {
    "takeover": ("may be vulnerable to subdomain takeover", "Remove the dangling DNS record or reclaim the resource."),
    "credential_exposure": ("has exposed credentials/secrets", "Rotate the exposed secrets and review access logs."),
}
#: Independent upstream families needed for CRITICAL without an exact identifier match (AR08).
MIN_INDEPENDENT_FAMILIES = 2
#: Identifier kinds that count as an exact match (AR08: CNPJ, LEI, wallet, domain, URL).
EXACT_IDENTIFIER_KINDS = frozenset({"cnpj", "lei", "wallet", "domain", "url"})
#: Entity types whose own tag is an exact identifier match (the finding is about that very value).
IDENTIFIER_TYPES: dict[EntityType, str] = {
    EntityType.CNPJ: "cnpj", EntityType.DOMAIN: "domain", EntityType.ONION: "domain", EntityType.URL: "url",
    EntityType.BTC: "wallet", EntityType.ETH: "wallet", EntityType.XMR: "wallet", EntityType.CRYPTO: "wallet",
}
#: Entity types whose tag can only come from a name comparison (homonym-prone).
NAME_TYPES = frozenset({EntityType.PERSON, EntityType.ORG, EntityType.THREAT_ACTOR, EntityType.KEYWORD, EntityType.USERNAME})
#: ``Finding.data['match_type']`` values that mean a name-only comparison.
NAME_MATCH_TYPES = frozenset({"name", "name_only", "fuzzy", "fuzzy_name", "alias", "similar_name", "partial_name"})
#: Words of a match type that mean a name comparison ('exact_name', 'normalised_name', 'alias_fuzzy'...).
_NAME_WORDS = frozenset({"name", "names", "alias", "aliases", "fuzzy", "similar", "partial", "nickname", "akas", "aka"})
#: Identifier kinds that are not exact matches but are no name comparison either (the first word of
#: the match type, e.g. 'cnpj_root', 'cpf_masked', 'imo_number'): 'unspecified', never 'name'.
IDENTIFIER_KIND_WORDS = frozenset({
    "cnpj", "lei", "wallet", "domain", "url", "cpf", "imo", "iban", "bic", "swift", "isin", "tax", "vat", "registration",
    "passport", "document", "email", "phone", "ip", "ipv4", "ipv6", "hash", "sha256", "md5", "account", "id",
})
#: Tag a module sets on a name-only match (sanctions_lists, ransomware trackers).
NAME_ONLY_TAG = "name_only_match"
#: Correlation label of a name-only match (AR08 wording).
NAME_ONLY_TITLE = "possible match - verify identifiers"
#: Unattributed findings (no registry source) all count as one family.
UNATTRIBUTED_FAMILY = "unattributed"


def _registry(rctx: Any) -> Any:
    reg = getattr(rctx, "providers", None) if rctx is not None else None
    if reg is not None and callable(getattr(reg, "source", None)):
        return reg
    try:
        from v3lum.core import providers

        return providers.registry()
    except Exception:  # noqa: BLE001 - registry problems leave findings unattributed
        return None


def _module_sources(module: str) -> tuple[str, ...]:
    if not module:
        return ()
    try:
        from v3lum.core.module import REGISTRY
    except ImportError:  # pragma: no cover - defensive
        return ()
    cls = REGISTRY.get(module)
    return tuple(getattr(cls, "sources", ()) or ()) if cls is not None else ()


def upstream_families(f: Finding, reg: Any) -> frozenset[str]:
    """The independent upstream families behind one finding (AR08): the registry ``upstream_family``
    of ``Finding.source`` (else of the module's single declared source), narrowed to the families
    ``data['upstream_families']`` states when the source embeds several; findings without a
    registered source share one 'unattributed' family (two unknown feeds never make a consensus)."""
    src = _source_of(f, reg)
    if src is None or not src.upstream_family:
        return frozenset({UNATTRIBUTED_FAMILY})
    stated = _stated_families(f, src)
    return stated or frozenset({src.upstream_family})


def _source_of(f: Finding, reg: Any) -> Any:
    """The registry source behind a finding: ``Finding.source``, else the module's single declared
    source family (None when unknown or ambiguous)."""
    src = reg.source(f.source) if (reg is not None and f.source) else None
    if src is None and reg is not None:
        declared = [x for x in (reg.source(s) for s in _module_sources(f.module)) if x is not None]
        if len({x.upstream_family for x in declared}) == 1:
            src = declared[0]
    return src


def _stated_families(f: Finding, src: Any) -> frozenset[str]:
    """``data['upstream_families']`` narrowed to the families the source may serve ([] = not stated)."""
    data = f.data if isinstance(f.data, dict) else {}
    stated = data.get("upstream_families")
    if isinstance(stated, (list, tuple, set, frozenset)) and stated:
        return frozenset({str(x) for x in stated if str(x)} & set(getattr(src, "families", ()) or ()))
    return frozenset()


def independent_families(findings: Iterable[Finding], reg: Any) -> list[str]:
    """The independent upstream families behind ``findings`` (AR08, same counting as CR27/P171):

    * a direct source counts its ``upstream_family`` once (a mirror of the same family adds nothing);
    * a finding stating ``data['upstream_families']`` counts those families (within the source's);
    * an aggregator (``Source.embeds``) without such a statement counts its own label only when none
      of the families it embeds is already counted and no counted aggregator overlaps it (it may
      merely re-serve one of them);
    * findings without a registry source name no family: together they count as one 'unattributed'
      family only when two different modules (not already counted through a registered source)
      report them - one unknown feed never corroborates anything.
    """
    direct: set[str] = set()
    aggregates: list[Any] = []
    unattributed: set[str] = set()
    attributed_modules: set[str] = set()
    for f in findings:
        src = _source_of(f, reg)
        if src is None or not getattr(src, "upstream_family", ""):
            unattributed.add(f.module or f.source or "?")
            continue
        attributed_modules.add(f.module or "")
        stated = _stated_families(f, src)
        if stated:
            direct |= stated
        elif getattr(src, "embeds", ()):
            aggregates.append(src)
        else:
            direct.add(src.upstream_family)
    counted = set(direct)
    covered: set[str] = set(direct)
    for src in sorted(aggregates, key=lambda x: str(getattr(x, "id", ""))):
        fams = set(getattr(src, "families", ()) or ()) - {src.upstream_family}
        if fams & covered or src.upstream_family in counted:
            continue
        counted.add(src.upstream_family)
        covered |= fams | {src.upstream_family}
    out = sorted(counted)
    if len(unattributed - attributed_modules) >= MIN_INDEPENDENT_FAMILIES:
        out.append(UNATTRIBUTED_FAMILY)
    return out


def match_kind(f: Finding, node: Node) -> tuple[str, str]:
    """``(class, kind)`` of one tagged finding: class 'exact' (kind cnpj/lei/wallet/domain/url),
    'name' (a name-only comparison: homonym risk), 'former' (formerly listed) or 'unspecified'.

    From ``Finding.data['match_type']`` (``exact_cnpj``, ``cnpj``, ``name``, ``formerly_name``...),
    the ``name_only_match`` tag, else from the node's entity type (a tag on a CNPJ, wallet, domain or
    URL is about that very identifier; a tag on a person, company or actor name is a name match). On
    a name entity (person, company, actor, keyword, username) a match type that names no identifier
    (``exact``, ``normalised``, ``full``...) is a name match too; identifier kinds that are not exact
    (``cnpj_root``, ``cpf``, ``imo``...) are 'unspecified'."""
    data = f.data if isinstance(f.data, dict) else {}
    raw = str(data.get("match_type") or "").strip().lower()
    if raw.startswith("formerly_"):
        return "former", raw[len("formerly_"):]
    if NAME_ONLY_TAG in f.tags:
        return "name", raw or "name"
    if raw:
        kind = raw[len("exact_"):] if raw.startswith("exact_") else raw
        if kind in NAME_MATCH_TYPES or _NAME_WORDS & set(re.split(r"[^a-z0-9]+", kind)):
            return "name", kind
        if kind in EXACT_IDENTIFIER_KINDS:
            return "exact", kind
        if node.entity.type in NAME_TYPES and not _identifier_kind(kind):
            # a name entity matched by anything but an identifier ('exact', 'normalised', 'full'...)
            # is still a name comparison: homonym risk (AR08)
            return "name", kind
        return "unspecified", kind
    etype = node.entity.type
    if etype in IDENTIFIER_TYPES:
        return "exact", IDENTIFIER_TYPES[etype]
    if etype in NAME_TYPES:
        return "name", "name"
    return "unspecified", ""


def _identifier_kind(kind: str) -> bool:
    words = [w for w in re.split(r"[^a-z0-9]+", kind) if w]
    return bool(words) and words[0] in IDENTIFIER_KIND_WORDS


def _best(findings: list[Finding]) -> Finding:
    return max(findings, key=lambda f: (f.label.rank, float(f.confidence), f.id))


def _confidence_text(f: Finding) -> str:
    return f"{f.label.value} ({float(f.confidence):.2f}, {f.module or f.source or 'unknown module'})"


def _evidence_ids(findings: list[Finding], facts: list[str]) -> list[str]:
    return [f.id for f in findings if f.id][:20] + facts


@rule("high_signal_tags", "Critical intelligence tags (homonym-safe)", severity="critical",
      criterion="ransomware/sanctions CRITICAL only on an exact identifier match (CNPJ, LEI, wallet, domain, URL) or >= 2 "
                "independent upstream families; name-only matches MEDIUM/POSSIBLE 'possible match - verify identifiers' (AR08)")
def high_signal_tags(graph: Graph, results: list[ModuleResult], rctx: Any = None) -> Iterable[Correlation]:
    """AR08: a single module's 'ransomware' or 'sanctions' tag no longer yields a fixed CRITICAL.

    * exact identifier match (CNPJ, LEI, wallet, domain, URL) -> CRITICAL;
    * no exact match but >= 2 independent upstream families (name-only findings never count) -> CRITICAL;
    * one family, match type not stated -> HIGH ('reported by one source - verify');
    * name-only (or formerly-listed) matches -> MEDIUM, POSSIBLE, 'possible match - verify identifiers'.

    Every correlation states the match type and propagates the underlying confidence (the best
    evidence finding's label, capped at POSSIBLE for name-only matches); 'takeover' and
    'credential_exposure' stay HIGH with the underlying confidence. Context-only and SUP-* suppressed
    findings are never evidence (:func:`evidence_finding`).
    """
    reg: Any = None
    for node in graph.nodes.values():
        evidence = _evidence(node)
        if not evidence:
            continue
        for tag, (text, rec) in CRITICAL_TAGS.items():
            tagged = [f for f in evidence if tag in f.tags]
            if not tagged:
                continue
            if reg is None:
                reg = _registry(rctx)
            yield _critical_tag(node, tag, text, rec, tagged, reg)
        for tag, (text, rec) in HIGH_TAGS.items():
            tagged = [f for f in evidence if tag in f.tags]
            if not tagged:
                continue
            best = _best(tagged)
            mods = sorted({f.module for f in tagged if f.module})
            yield Correlation(
                rule=f"tag_{tag}",
                title=f"{node.entity.display} {text}",
                severity=Severity.HIGH,
                description=f"Reported by: {', '.join(mods) or 'unknown module'}. Underlying confidence: {_confidence_text(best)}.",
                entities=[node.entity],
                confidence=best.label,
                evidence=_evidence_ids(tagged, [f"tag:{tag}"]),
                recommendation=rec,
                tags=[tag],
                criterion=f"evidence finding tagged '{tag}'",
                why=f"{len(tagged)} finding(s) tagged '{tag}' on {node.entity.display}",
            )


def _critical_tag(node: Node, tag: str, text: str, rec: str, tagged: list[Finding], reg: Any) -> Correlation:
    classes: dict[str, list[tuple[Finding, str]]] = defaultdict(list)
    for f in tagged:
        cls, kind = match_kind(f, node)
        classes[cls].append((f, kind))
    exact = [f for f, _k in classes.get("exact", [])]
    other = [f for f, _k in classes.get("unspecified", [])]
    families = independent_families(other, reg)
    mods = sorted({f.module for f in tagged if f.module})
    display = node.entity.display
    if exact:
        kinds = sorted({k for _f, k in classes["exact"]})
        best = _best(exact)
        return Correlation(
            rule=f"tag_{tag}",
            title=f"{display} {text} (exact {'/'.join(k.upper() if k in ('cnpj', 'lei', 'url') else k for k in kinds)} match)",
            severity=Severity.CRITICAL,
            description=f"Match type: exact identifier ({', '.join(kinds)}). Reported by: {', '.join(mods) or 'unknown module'}. "
            f"Underlying confidence: {_confidence_text(best)}.",
            entities=[node.entity],
            confidence=best.label,
            evidence=_evidence_ids(exact, [f"tag:{tag}", "match:exact_" + "+".join(kinds)]),
            recommendation=rec,
            tags=[tag],
            criterion=f"'{tag}' finding with an exact {'/'.join(kinds)} identifier match (AR08)",
            why=f"exact {'/'.join(kinds)} identifier match in '{tag}' data",
            key="exact",
        )
    counted = len(families)
    if other and counted >= MIN_INDEPENDENT_FAMILIES:
        best = _best(other)
        shown = ", ".join(families)
        return Correlation(
            rule=f"tag_{tag}",
            title=f"{display} {text} ({counted} independent sources)",
            severity=Severity.CRITICAL,
            description=f"Match type: not an identifier match, corroborated by {counted} independent upstream families ({shown}). "
            f"Reported by: {', '.join(mods)}. Underlying confidence: {_confidence_text(best)}.",
            entities=[node.entity],
            confidence=best.label,
            evidence=_evidence_ids(other, [f"tag:{tag}", f"families:{shown}"]),
            recommendation=rec,
            tags=[tag],
            criterion=f"'{tag}' reported by >= {MIN_INDEPENDENT_FAMILIES} independent upstream families (AR08)",
            why=f"{counted} independent upstream families report '{tag}'",
            key="families",
        )
    if other:
        best = _best(other)
        return Correlation(
            rule=f"tag_{tag}",
            title=f"{display} {text} (one source - verify)",
            severity=Severity.HIGH,
            description=f"Match type: {', '.join(sorted({k for _f, k in classes['unspecified'] if k})) or 'not stated'}; reported by "
            f"{'one upstream family only (' + ', '.join(families) + ')' if families else 'sources without registry provenance'}, so it is "
            f"not CRITICAL. Reported by: {', '.join(mods) or 'unknown module'}. Underlying confidence: {_confidence_text(best)}.",
            entities=[node.entity],
            confidence=best.label,
            evidence=_evidence_ids(other, [f"tag:{tag}", f"families:{','.join(families) or UNATTRIBUTED_FAMILY}"]),
            recommendation=f"Confirm with a second independent source or an exact identifier. {rec}",
            tags=[tag],
            criterion=f"'{tag}' from a single upstream family without an identifier match: HIGH at most (AR08)",
            why=f"one upstream family reports '{tag}' without an identifier match",
            key="single",
        )
    # name-only (and formerly-listed) matches: homonym risk
    weak = [f for f, _k in classes.get("name", [])] + [f for f, _k in classes.get("former", [])]
    best = _best(weak)
    former = bool(classes.get("former")) and not classes.get("name")
    match_text = "formerly listed (not on the current list)" if former else "name only (no identifier matched)"
    label = Confidence.POSSIBLE
    return Correlation(
        rule=f"tag_{tag}",
        title=f"{display}: {NAME_ONLY_TITLE} ({tag})",
        severity=Severity.MEDIUM,
        description=f"Match type: {match_text}. A name match alone does not establish identity (homonyms): confirm with a second "
        f"identifier (CNPJ/LEI, document, date of birth, wallet, domain). Reported by: {', '.join(mods) or 'unknown module'}. "
        f"Underlying confidence: {_confidence_text(best)}.",
        entities=[node.entity],
        confidence=min(float(best.confidence), Confidence.PROBABLE.threshold - 0.05),
        confidence_label=label,
        evidence=_evidence_ids(weak, [f"tag:{tag}", "match:former" if former else "match:name_only"]),
        recommendation=f"Verify identifiers before acting: {rec}",
        tags=[tag, NAME_ONLY_TAG],
        criterion=f"'{tag}' finding on a {'former listing' if former else 'name-only match'}: MEDIUM/POSSIBLE (AR08)",
        why=f"{NAME_ONLY_TITLE}: '{tag}' {match_text}",
        key="name_only",
    )
