"""Correlation pack: threat-intel consensus (P171, CR27-CR30).

Rules (all ``fn(graph, results, rctx)``, offline: they only read the graph, never the network):

* **CR27** ``multi_source_malicious`` - replaces the legacy rule of the same id (CRITICAL at two
  module names). Consensus counts *upstream families*, never modules (P171 cond 2-4, 10):
  ``Finding.source`` (a registry source id) maps to its registry ``upstream_family``; the abuse.ch
  feeds are one family, Spamhaus another. An aggregate source (``Source.embeds``: FireHOL, IPsum,
  OTX relays...) counts as the families it embeds: a listing it reports names one of them, so it
  adds a vote only when none of those families already voted (ambiguous, counted once). A finding
  may state which families answered (``data['upstream_families']``, e.g. OTX pulses relaying
  abuse.ch count as abuse.ch) or carry one hit per feed (``data['hits'] = [{source, listed_at|
  last_seen, currency}]``); both are honoured within the source's declared families. HIGH with
  >= :data:`CONSENSUS_FAMILIES` families listing the entity inside the type's decay window
  (:data:`DECAY_DAYS`: ip/url 30 days, domain 90 days), MEDIUM with one. Older hits are history:
  listed in the evidence, never counted. A verdict without registry provenance names no family:
  such verdicts count (together, as one 'unattributed' family) only when two modules agree.
* Suppression runs before CR27 and only downgrades (cond 5): findings the engine's suppression
  stage downgraded (``SUP-*``) or tagged ``context_only`` are no votes (they stay in the case,
  downgraded, and are listed in the evidence); on sinkholes and warninglisted values no listing is a
  vote (engine parity, tests/test_engine_suppression.py). An analyst override restores a listing
  unless its verdict is a false positive. Known benign scanners (noise kind/tag ``benign_scanner``,
  attribute ``scanner_classification`` = 'benign', e.g. GreyNoise), allow-listed values
  (``known_good``), shared CDN/SaaS/hosting addresses, other noise ranges (resolvers, webmail,
  private) and anonymity infrastructure (Tor exit/VPN/proxy facts, cond 7: never above LOW, never
  tagged malicious) keep their consensus correlation, downgraded to POSSIBLE and capped by
  :data:`SUPPRESSION_CAPS` with the reason - never deleted.
* Shared addresses never give consensus to the domains behind them (cond 6): votes are always
  about the entity itself, and a domain vote derived from a listing of a shared address it resolves
  to (finding data ``ip``/``address``/``resolved_ip``/``via_ip``) is not counted. Feeds disabled by
  the licence profile (P377) are not counted: sources reported ``licence`` in a result's
  ``source_statuses`` or listed in ``rctx.meta['licence_blocked_sources']``, and registry sources
  whose terms class is 'unknown' (disabled in every profile, A1).
* **CR28** ``anonymized_infrastructure`` - Tor exit / VPN / anonymizing proxy membership is context
  only: at most LOW, tagged ``context_only`` and never ``malicious`` (lawful privacy tools).
* **CR29** ``favicon_clone_cluster`` - sites sharing a favicon hash (attribute ``favicon_mmh3``,
  ``favicon`` edges to favicon_hash nodes, ``similar_to`` links between favicon nodes) need at
  least one extra non-similarity signal (young domain, typosquat/lookalike, phishing tag). An
  org-profile brand favicon served by a non-owned host plus one signal is HIGH 'brand favicon
  clone'. Indexed hashes only: the rule never fetches a favicon.
* **CR30** ``jarm_matches_known_c2`` - indexed JARM values (attribute ``jarm``) equal to the JARM of
  a C2-tagged host of the case or named by a source (``jarm_c2_matches``); MEDIUM with at least one
  extra signal, LOW and POSSIBLE otherwise. Live JARM probes are out of the pack's reach.

Thresholds are the named constants below. The helpers in the first section (:func:`evidence_ok`,
:func:`parse_when`, :func:`setting`, :func:`owned`, :func:`in_scope`...) are shared with the
attack-surface and e-mail spoofing packs of the same package.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import threading
import weakref
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.entities import Entity, EntityType
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Confidence, Correlation, Finding, ModuleResult, Severity

# ----------------------------------------------------------------------------------------
# Thresholds and vocabularies (P171) - one block, named constants only
# ----------------------------------------------------------------------------------------

#: CR27: independent upstream families for HIGH (one family = MEDIUM).
CONSENSUS_FAMILIES = 2
#: CR27: families at which the consensus confidence becomes 'confirmed'.
CONFIRMED_FAMILIES = 3
#: CR27 decay windows in days (cond 4); other types never decay (file hashes stay malicious).
DECAY_DAYS: dict[EntityType, int] = {
    EntityType.IPV4: 30,
    EntityType.IPV6: 30,
    EntityType.CIDR: 30,
    EntityType.URL: 30,
    EntityType.DOMAIN: 90,
}
#: CR27: decay window of an IaaS (noise kind 'cloud') address: reassigned quickly (P149 c7).
IAAS_DECAY_DAYS = 14
#: Finding tags that make a finding a CR27 vote ('this source lists the entity as malicious').
VOTE_TAGS = frozenset({"malicious", "phishing", "malware", "c2", "botnet"})
#: Noise kinds of shared addresses (many unrelated tenants): consensus downgraded, never inherited.
SHARED_KINDS = frozenset({"cdn", "saas", "hosting"})
#: IaaS compute ranges: severity kept, shorter decay window.
IAAS_KINDS = frozenset({"cloud"})
#: Finding data keys naming the address a domain-level listing was derived from (cond 6).
VIA_IP_KEYS = ("ip", "address", "resolved_ip", "via_ip", "listed_ip")
#: Family label of verdicts without registry provenance (counted only when two modules agree).
UNATTRIBUTED = "unattributed (no registry source)"
#: Minimum number of modules before provenance-less verdicts form their single family.
UNATTRIBUTED_MIN_MODULES = 2
#: Hits read from one finding's data['hits'] (aggregated blocklist findings).
MAX_HITS = 50
#: Severity cap of a consensus downgraded by a CR27 suppression rule (benign scanner, shared address).
SUPPRESSED_CAP = Severity.LOW
#: CR27 downgrade rules (P171 cond 5-7): each keeps the consensus but downgrades it (POSSIBLE) and caps
#: its severity - never deletes it. Unknown rules cap at SUPPRESSED_CAP.
SUPPRESSION_CAPS: dict[str, Severity] = {
    "SUP-benign_scanner": Severity.LOW,
    "SUP-allowlist": Severity.LOW,
    "SUP-shared_address": Severity.LOW,
    "SUP-noise": Severity.LOW,
    "SUP-anonymizer": Severity.LOW,
}
#: Downgrades whose consensus is context only (tagged context_only): anonymity infrastructure is a
#: lawful privacy tool, never scored malicious (P171 cond 7).
CONTEXT_SUPPRESSIONS = frozenset({"SUP-anonymizer"})
#: Noise kinds that leave a CR27 consensus to their own handling: IaaS 'cloud' (shorter decay window),
#: 'parked' (often hostile) and the kinds with a named suppression rule of their own.
NOISE_KEEP_KINDS = frozenset({"cloud", "parked", "sinkhole", "warninglist", "benign_scanner"})

#: CR28: current anonymizer facts (attribute -> label) and the finding/entity tags that say the same.
ANONYMIZER_ATTRIBUTES: dict[str, str] = {"is_tor_exit": "Tor exit node", "is_proxy": "anonymizing proxy", "is_vpn": "VPN endpoint"}
ANONYMIZER_TAGS: dict[str, str] = {"tor": "Tor exit node", "proxy": "anonymizing proxy", "vpn": "VPN endpoint", "anonymizer": "anonymity infrastructure"}
#: CR28: facts that only show past or non-exit membership (INFO).
ANONYMIZER_HISTORY_ATTRIBUTES: dict[str, str] = {"tor_exit_history": "past Tor exit", "is_tor_relay": "Tor relay (not an exit)"}
#: CR28 severities: never above LOW (P171 cond 7).
ANONYMIZER_SEVERITY = Severity.LOW
ANONYMIZER_HISTORY_SEVERITY = Severity.INFO

#: CR29/CR30: a domain registered at most this many days ago is 'young'.
YOUNG_DOMAIN_DAYS = 30
#: CR29: sites sharing one favicon before it is a cluster (a brand favicon needs one non-owned site).
FAVICON_CLUSTER_MIN_SITES = 2
#: CR29: other cluster members listed in one correlation.
MAX_CLUSTER_MEMBERS = 10
#: CR29 severities.
BRAND_CLONE_SEVERITY = Severity.HIGH
CLUSTER_SEVERITY = Severity.MEDIUM
#: CR30: JARM fingerprint format and the 'no TLS answer' value (never a match).
JARM_RE = re.compile(r"^[0-9a-f]{62}$")
JARM_EMPTY = "0" * 62
#: CR30 severities: with / without an extra signal.
JARM_SEVERITY = Severity.MEDIUM
JARM_WEAK_SEVERITY = Severity.LOW

#: Hostile tags (P291 cond 5, P027 cond 7) and the tags of a site's phishing signal (CR29).
HOSTILE_TAGS = frozenset({"malicious", "phishing", "c2"})
LOOKALIKE_TAGS = frozenset({"typosquat", "lookalike_brand", "brand_abuse"})
#: Tag of findings shown as context only; prefix of the engine's suppression rules (WP08).
CONTEXT_ONLY = "context_only"
SUPPRESSION_PREFIX = "SUP-"
#: Analyst override verdicts that take a finding out of the evidence.
FALSE_POSITIVE_VERDICTS = frozenset({"false_positive", "false positive", "fp", "benign", "wrong", "negative", "not_malicious"})

CR27 = "multi_source_malicious"
CR28 = "anonymized_infrastructure"
CR29 = "favicon_clone_cluster"
CR30 = "jarm_matches_known_c2"

_REFS_CONSENSUS = (
    "https://www.misp-project.org/2019/09/12/Decaying-Of-Indicators.html",
    "https://github.com/MISP/misp-warninglists",
)
_REFS_TOR = ("https://metrics.torproject.org/exonerator.html",)
_REFS_FAVICON = ("https://www.shodan.io/search/filters",)
_REFS_JARM = ("https://github.com/salesforce/jarm",)


def _fixtures(rule_id: str, *names: str) -> tuple[str, ...]:
    """Graph-fixture paths of a rule (tests/fixtures/rules/<rule_id>/<name>.json)."""
    return tuple(f"tests/fixtures/rules/{rule_id}/{name}.json" for name in names)


# ----------------------------------------------------------------------------------------
# Shared pack helpers (also used by attack_surface.py and email_spoofing.py)
# ----------------------------------------------------------------------------------------


def evidence_ok(f: Finding) -> bool:
    """May ``f`` support a correlation? Not when tagged ``context_only`` or downgraded by a core
    suppression rule (``SUP-*``): suppression runs before the rules and only downgrades, so a
    correlation built on suppressed findings would undo it. An analyst override keeps the finding
    as evidence unless its verdict is a false positive (analyst decisions always win)."""
    override = getattr(f, "override", None)
    if override:
        verdict = str(override.get("verdict") or "").strip().lower() if isinstance(override, dict) else ""
        return verdict not in FALSE_POSITIVE_VERDICTS
    if CONTEXT_ONLY in (f.tags or ()):
        return False
    return not any(
        isinstance(s, dict) and str(s.get("rule", "")).startswith(SUPPRESSION_PREFIX) and not s.get("blocked_by")
        for s in (f.suppressed_by or ())
    )


def evidence_findings(node: Node) -> list[Finding]:
    """The node's findings that may support a correlation (:func:`evidence_ok`)."""
    return [f for f in node.findings if evidence_ok(f)]


def evidence_tagged(node: Node, tags: Iterable[str]) -> list[Finding]:
    """Evidence findings carrying any of ``tags``."""
    wanted = set(tags)
    return [f for f in evidence_findings(node) if wanted.intersection(f.tags or ())]


def hostile(node: Node, tags: Iterable[str] = HOSTILE_TAGS) -> bool:
    """Entity tagged hostile: an entity tag, or an evidence finding with one of ``tags``."""
    wanted = set(tags)
    return bool(wanted & set(node.tags)) or bool(evidence_tagged(node, wanted))


def parse_when(value: Any) -> _dt.datetime | None:
    """ISO-8601 text (date or date-time, 'Z' allowed), a date/datetime or epoch seconds/ms -> aware
    UTC datetime; anything else -> None."""
    if value is None or value == "" or isinstance(value, bool):
        return None
    if isinstance(value, _dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=_dt.timezone.utc)
    if isinstance(value, _dt.date):
        return _dt.datetime(value.year, value.month, value.day, tzinfo=_dt.timezone.utc)
    if isinstance(value, (int, float)):
        seconds = float(value) / 1000.0 if float(value) > 1e11 else float(value)
        try:
            return _dt.datetime.fromtimestamp(seconds, _dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    if " " in text and "T" not in text:
        text = text.replace(" ", "T", 1)
    try:
        when = _dt.datetime.fromisoformat(text)
    except ValueError:
        try:
            when = _dt.datetime.fromisoformat(text[:10])
        except ValueError:
            return None
    return when if when.tzinfo else when.replace(tzinfo=_dt.timezone.utc)


def age_days(when: _dt.datetime | None, now: _dt.datetime) -> float | None:
    """Days between ``when`` and ``now`` (a future date counts as 0), None when unknown."""
    if when is None:
        return None
    return max(0.0, (now - when).total_seconds() / 86400.0)


def day(when: _dt.datetime | None) -> str:
    """'YYYY-MM-DD' or 'unknown'."""
    return when.date().isoformat() if when is not None else "unknown"


def now_of(rctx: Any) -> _dt.datetime:
    """The rule clock (``rctx.now``; aware UTC)."""
    now = getattr(rctx, "now", None)
    if isinstance(now, _dt.datetime):
        return now if now.tzinfo else now.replace(tzinfo=_dt.timezone.utc)
    return _dt.datetime.now(_dt.timezone.utc)


def setting(rctx: Any, name: str, default: Any = None) -> Any:
    """A config setting through ``rctx.setting`` (the default without settings)."""
    getter = getattr(rctx, "setting", None)
    if callable(getter):
        try:
            value = getter(name, default)
        except Exception:  # noqa: BLE001 - a settings problem never breaks a rule
            return default
        return default if value is None else value
    return default


def org_of(rctx: Any) -> Any:
    """The org profile of the run, or None (an empty profile counts as none)."""
    org = getattr(rctx, "org", None)
    if org is None or getattr(org, "is_empty", False):
        return None
    return org


def owned(entity: Entity, rctx: Any) -> Any:
    """``OrgProfile.owns(entity)`` or None (no profile, or a profile problem)."""
    org = org_of(rctx)
    owns = getattr(org, "owns", None)
    if not callable(owns):
        return None
    try:
        return owns(entity)
    except Exception:  # noqa: BLE001 - a profile problem never makes an asset owned
        return None


def own_asset(node: Node, rctx: Any) -> bool:
    """Own asset of the org profile: the engine's ownership tag, or ``OrgProfile.owns`` (stored
    cases and fixtures)."""
    if node.ownership == "own_asset" or "own_asset" in node.tags:
        return True
    own = owned(node.entity, rctx)
    return bool(getattr(own, "own", False))


def verified_own(node: Node, rctx: Any) -> bool:
    """A txt_verified/attested org-profile domain entry covers the entity (A4 BR9 / A11 BR4)."""
    own = owned(node.entity, rctx)
    return bool(getattr(own, "own", False) and getattr(own, "verified", False))


_SCOPE_CACHE: dict[str, Any] = {}
_SCOPE_LOCK = threading.Lock()  # rules of concurrent scans share the one-entry cache


def _scope(rctx: Any) -> Any:
    """The ACTIVE scope of the run (a ``core.scope.Scope``; a mapping is loaded once), or None."""
    options = getattr(rctx, "options", None)
    raw = getattr(options, "scope", None)
    if raw is None:
        return None
    if callable(getattr(raw, "matches_host", None)):
        return raw
    if not isinstance(raw, Mapping):
        return None
    try:
        key = json.dumps(raw, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return None
    with _SCOPE_LOCK:
        if key in _SCOPE_CACHE:
            return _SCOPE_CACHE[key]
    try:
        from v3lum.core.scope import Scope

        loaded = Scope.from_dict(raw)
    except Exception:  # noqa: BLE001 - an unreadable scope puts nothing in scope
        loaded = None
    with _SCOPE_LOCK:
        _SCOPE_CACHE.clear()
        _SCOPE_CACHE[key] = loaded
    return loaded


def in_scope(node: Node, rctx: Any) -> bool:
    """The entity matches the ACTIVE scope of the run (entity tag ``in_scope`` or the scope file's
    targets: domains, CIDRs, URL prefixes). Pivots never inherit scope (A7): only the entity itself
    is matched."""
    if "in_scope" in node.tags:
        return True
    scope = _scope(rctx)
    if scope is None:
        return False
    etype, value = node.entity.type, str(node.entity.value)
    try:
        if etype in (EntityType.IPV4, EntityType.IPV6):
            return bool(scope.matches_ip(value))
        if etype is EntityType.DOMAIN:
            return bool(scope.matches_host(value))
        if etype is EntityType.URL:
            return bool(scope.matches_url(value))
    except Exception:  # noqa: BLE001 - a scope problem never puts an entity in scope
        return False
    return False


def registry_of(rctx: Any) -> Any:
    """The provider registry of the run (``rctx.providers``) or the loaded one; None on failure."""
    reg = getattr(rctx, "providers", None)
    if reg is not None and callable(getattr(reg, "source", None)):
        return reg
    try:
        from v3lum.core import providers

        return providers.registry()
    except Exception:  # noqa: BLE001 - registry problems leave votes unattributed
        return None


def module_sources(module: str) -> tuple[str, ...]:
    """Registry sources declared by a registered module ('' -> ())."""
    if not module:
        return ()
    try:
        from v3lum.core.module import REGISTRY
    except ImportError:  # pragma: no cover - defensive
        return ()
    cls = REGISTRY.get(module)
    return tuple(getattr(cls, "sources", ()) or ()) if cls is not None else ()


def young_domain(node: Node, now: _dt.datetime) -> str:
    """'registered N days ago' for a domain registered <= YOUNG_DOMAIN_DAYS ago, else ''."""
    for age in node.attr_values("domain_age_days"):
        if isinstance(age, (int, float)) and not isinstance(age, bool) and 0 <= age <= YOUNG_DOMAIN_DAYS:
            return f"registered {int(age)} day(s) ago"
    if node.entity.type is EntityType.DOMAIN:
        for created in node.attr_values("created"):
            days = age_days(parse_when(created), now)
            if days is not None and days <= YOUNG_DOMAIN_DAYS:
                return f"registered {int(days)} day(s) ago"
    if "newly_registered" in node.tags or evidence_tagged(node, {"newly_registered"}):
        return "newly registered"
    return ""


def shared_kind(node: Node) -> str:
    """The shared-infrastructure kind of an address ('cdn' | 'saas' | 'hosting' | 'shared'), or ''."""
    if node.noise_kind in SHARED_KINDS:
        return node.noise_kind
    kinds = SHARED_KINDS & set(node.tags)
    if kinds:
        return sorted(kinds)[0]
    if any(v is True for v in node.attr_values("shared_ip")) or any(v is True for v in node.attr_values("is_cdn")):
        return "shared"
    role = " ".join(str(v) for v in node.attr_values("cloud_role")).lower()
    if "shared" in role or "cdn" in role:
        return "shared"
    return ""


def _flag(node: Node, name: str) -> bool:
    return any(v is True for v in node.attr_values(name))


class _EdgeIndex:
    """Edges of a finished graph by (endpoint, relation): ``Graph.out_edges``/``in_edges`` scan every
    edge per call, which makes per-node rules quadratic on large cases (P301 cond 5: < 2 s)."""

    def __init__(self, graph: Graph) -> None:
        self.size = len(graph.edges)
        self.out: dict[tuple[str, str | None], list[Any]] = {}
        self.inn: dict[tuple[str, str | None], list[Any]] = {}
        for edge in graph.edges:
            for rel in (edge.relation, None):
                self.out.setdefault((edge.src, rel), []).append(edge)
                self.inn.setdefault((edge.dst, rel), []).append(edge)


_EDGE_INDEXES: weakref.WeakKeyDictionary[Graph, _EdgeIndex] = weakref.WeakKeyDictionary()
_EDGE_LOCK = threading.Lock()


def _edge_index(graph: Graph) -> _EdgeIndex:
    with _EDGE_LOCK:
        index = _EDGE_INDEXES.get(graph)
    if index is None or index.size != len(graph.edges):  # rebuilt when edges were added since
        index = _EdgeIndex(graph)
        with _EDGE_LOCK:
            _EDGE_INDEXES[graph] = index
    return index


def edges_out(graph: Graph, key: str, relation: str | None = None) -> list[Any]:
    """``graph.out_edges(key, relation)`` through a per-graph index (same edges, same order)."""
    return list(_edge_index(graph).out.get((key, relation), ()))


def edges_in(graph: Graph, key: str, relation: str | None = None) -> list[Any]:
    """``graph.in_edges(key, relation)`` through a per-graph index (same edges, same order)."""
    return list(_edge_index(graph).inn.get((key, relation), ()))


def adjacent(graph: Graph, key: str, relation: str | None = None, direction: str = "out") -> list[Node]:
    """``graph.neighbors(key, relation, direction)`` through the per-graph index."""
    keys: list[str] = []
    if direction in ("out", "both"):
        keys += [e.dst for e in edges_out(graph, key, relation)]
    if direction in ("in", "both"):
        keys += [e.src for e in edges_in(graph, key, relation)]
    out: list[Node] = []
    seen: set[str] = set()
    for k in keys:
        if k not in seen and k in graph.nodes:
            seen.add(k)
            out.append(graph.nodes[k])
    return out


# ----------------------------------------------------------------------------------------
# CR27 multi_source_malicious
# ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Vote:
    """One listing of the entity by one source (P171): the families it may come from."""

    source: str  # registry source id ('' when unknown)
    module: str
    families: tuple[str, ...]  # candidate upstream families (sorted)
    aggregate: bool  # an aggregate listing: it names one of ``families``, we do not know which
    label: str  # the family shown when the vote counts
    when: _dt.datetime | None  # last_seen of the listing (provider timestamp)
    historical: bool  # the source says the listing is history (used when no date is known)
    terms: str  # terms class of the source ('' without a registry source)
    finding: str  # finding id ('' for attribute votes)

    def describe(self) -> str:
        who = self.source or f"module {self.module}"
        fam = f"aggregate of {', '.join(self.families)}" if self.aggregate else self.label
        terms = self.terms or "n/a"
        return f"{who} (family {fam}; last seen {day(self.when)}; terms {terms})"


@dataclass
class Consensus:
    """Outcome of CR27 counting for one entity."""

    families: list[str]
    counted: list[Vote]
    deduplicated: list[str]
    history: list[str]
    excluded: list[str]


def licence_blocked_sources(results: Iterable[ModuleResult], rctx: Any) -> frozenset[str]:
    """Sources disabled by the licence profile in this run: rows with reason_code 'licence' in any
    result's ``source_statuses`` plus ``rctx.meta['licence_blocked_sources']`` (ids or a mapping)."""
    blocked: set[str] = set()
    for res in results or ():
        for sid, row in (getattr(res, "source_statuses", None) or {}).items():
            if isinstance(row, Mapping) and str(row.get("reason_code") or "") == "licence":
                blocked.add(str(sid))
    meta = getattr(rctx, "meta", None)
    extra = meta.get("licence_blocked_sources") if isinstance(meta, Mapping) else None
    if isinstance(extra, (Mapping, list, tuple, set, frozenset)):
        blocked.update(str(k) for k in extra)
    return frozenset(blocked)


def _source_votes(
    sid: str, module: str, reg: Any, *, explicit: Any, when: _dt.datetime | None, historical: bool, finding: str
) -> list[Vote]:
    """Votes of one listing by registry source ``sid`` (or the module's declared sources)."""
    src = reg.source(sid) if (reg is not None and sid) else None
    if src is None:
        declared = [s for s in (reg.source(x) for x in module_sources(module)) if s is not None] if reg is not None else []
        if len(declared) == 1:
            src = declared[0]
        elif declared:
            fams = sorted({f for s in declared for f in s.families})
            terms = _most_restrictive([s.terms_class for s in declared])
            if len(fams) == 1:
                return [Vote("", module, (fams[0],), False, fams[0], when, historical, terms, finding)]
            return [Vote("", module, tuple(fams), True, f"module {module}", when, historical, terms, finding)]
        else:
            return [Vote(sid, module, (UNATTRIBUTED,), False, UNATTRIBUTED, when, historical, "", finding)]
    families = set(src.families)
    terms = src.terms_class
    if isinstance(explicit, (list, tuple, set, frozenset)):
        stated = sorted({str(x) for x in explicit} & families)
        if stated:
            return [Vote(src.id, module, (fam,), False, fam, when, historical, terms, finding) for fam in stated]
    if src.embeds:
        return [Vote(src.id, module, tuple(sorted(families)), True, src.upstream_family, when, historical, terms, finding)]
    return [Vote(src.id, module, (src.upstream_family,), False, src.upstream_family, when, historical, terms, finding)]


def _most_restrictive(classes: Iterable[str]) -> str:
    try:
        from v3lum.core.providers import most_restrictive

        return most_restrictive(list(classes))
    except Exception:  # noqa: BLE001 - defensive
        return "unknown"


def _derived_from_shared_ip(graph: Graph, node: Node, f: Finding) -> str:
    """For a domain/URL vote: the shared address the listing was derived from ('' when none)."""
    if node.entity.type not in (EntityType.DOMAIN, EntityType.URL) or not isinstance(f.data, Mapping):
        return ""
    for key in VIA_IP_KEYS:
        value = f.data.get(key)
        for item in value if isinstance(value, (list, tuple)) else [value]:
            if not isinstance(item, str) or not item.strip():
                continue
            for etype in (EntityType.IPV4, EntityType.IPV6):
                ent = Entity.try_make(etype, item.strip())
                if ent is None:
                    continue
                ip_node = graph.nodes.get(ent.key)
                if ip_node is not None and (shared_kind(ip_node) or ip_node.noise):
                    return ent.value
    return ""


def _false_positive(f: Finding) -> str:
    """The analyst's false-positive verdict on ``f`` ('' when none): such a listing is no vote at all."""
    override = getattr(f, "override", None)
    if not isinstance(override, Mapping):
        return ""
    verdict = str(override.get("verdict") or "").strip().lower()
    return verdict if verdict in FALSE_POSITIVE_VERDICTS else ""


def finding_suppressions(f: Finding) -> list[tuple[str, str]]:
    """(rule, reason) pairs of the suppression that downgraded ``f``: the core ``SUP-*`` records no
    analyst blocked, else ``SUP-context_only`` for a listing its source marks context only."""
    pairs = [
        (str(s.get("rule")), str(s.get("reason") or s.get("rule")))
        for s in (f.suppressed_by or ())
        if isinstance(s, Mapping) and str(s.get("rule", "")).startswith(SUPPRESSION_PREFIX) and not s.get("blocked_by")
    ]
    if not pairs and CONTEXT_ONLY in (f.tags or ()):
        pairs.append(("SUP-context_only", "context only (the source marks the listing as context)"))
    return list(dict.fromkeys(pairs))


def entity_suppressions(node: Node) -> list[tuple[str, str]]:
    """(rule, reason) pairs of the entity-level suppression of ``node``: sinkhole, warninglists."""
    pairs: list[tuple[str, str]] = []
    if "sinkhole" in node.tags or node.noise_kind == "sinkhole" or _flag(node, "is_sinkhole"):
        pairs.append(("SUP-sinkhole", "sinkhole"))
    lists = _warninglists(node)
    if lists:
        pairs.append(("SUP-warninglist", f"on warninglist {', '.join(lists)}"))
    return pairs


def collect_votes(graph: Graph, node: Node, rctx: Any) -> tuple[list[Vote], list[str]]:
    """CR27 votes on ``node`` and the reasons of listings that are no votes (suppression stage).

    Suppression runs first (cond 5, integrated with the engine stage of WP08): listings downgraded by
    a ``SUP-*`` rule, marked ``context_only`` or on a sinkholed/warninglisted entity stay in the case
    (downgraded) but are no votes; an analyst override restores a listing unless its verdict is a
    false positive. A module whose listing is no vote never votes again through its ``malicious``
    attribute."""
    reg = registry_of(rctx)
    votes: list[Vote] = []
    excluded: list[str] = []
    entity_held = entity_suppressions(node)
    voted_modules: set[str] = set()
    for f in sorted(node.findings, key=lambda x: (x.module, x.id)):
        if not VOTE_TAGS.intersection(f.tags or ()):
            continue
        voted_modules.add(f.module)  # the module's 'malicious' attribute says the same as this finding
        verdict = _false_positive(f)
        if verdict:
            excluded.append(f"excluded: finding {f.id} by {f.module} (analyst verdict {verdict})")
            continue
        held = finding_suppressions(f) if not evidence_ok(f) else []
        if not f.override:  # an analyst decision on the finding wins over entity-level suppression
            held = list(dict.fromkeys(held + entity_held))
        if held:
            excluded.append(f"suppressed ({'; '.join(reason for _rule, reason in held)}): finding {f.id} by {f.module}")
            continue
        via = _derived_from_shared_ip(graph, node, f)
        if via:
            excluded.append(f"not counted: finding {f.id} by {f.module} derives from shared address {via} (never consensus for the domains behind it)")
            continue
        votes.extend(_finding_votes(f, reg))
    if not entity_held:
        flagged = sorted({src for value, src in node.attributes.get("malicious", []) if value is True or value == "true"})
        for module in flagged:
            if module in voted_modules:
                continue  # the module's finding already voted (or was excluded)
            votes.extend(_source_votes("", module, reg, explicit=None, when=None, historical=False, finding=""))
    return votes, excluded


def _finding_votes(f: Finding, reg: Any) -> list[Vote]:
    data = f.data if isinstance(f.data, Mapping) else {}
    when = parse_when(f.observed_last) or parse_when(f.observed_first)
    historical = "historical" in (f.tags or ())
    hits = data.get("hits")
    out: list[Vote] = []
    if isinstance(hits, list):
        for hit in hits[:MAX_HITS]:
            if not isinstance(hit, Mapping) or not isinstance(hit.get("source"), str) or not hit.get("source"):
                continue
            hit_when = parse_when(hit.get("last_seen")) or parse_when(hit.get("last_online")) or parse_when(hit.get("listed_at"))
            hit_hist = str(hit.get("currency") or "") == "historical" or hit.get("historical") is True
            out.extend(_source_votes(str(hit["source"]), f.module, reg, explicit=None, when=hit_when, historical=hit_hist, finding=f.id))
    if out:
        return out
    return _source_votes(f.source, f.module, reg, explicit=data.get("upstream_families"), when=when, historical=historical, finding=f.id)


def _warninglists(node: Node) -> list[str]:
    names = [str(v) for v in node.attr_values("warninglists") if isinstance(v, str)]
    if node.noise_kind == "warninglist":
        names.append("noise list")
    try:
        from v3lum.core import noise

        names.extend(noise.warninglists(node.entity))
    except Exception:  # noqa: BLE001 - list problems are reported by noise.errors()
        pass
    return sorted(set(names))


def count_families(node: Node, votes: list[Vote], now: _dt.datetime, *, blocked: frozenset[str] = frozenset()) -> Consensus:
    """Count independent upstream families among ``votes`` (P171 cond 2-4, 6).

    Direct votes count their family once (later votes of the same family are 'deduplicated');
    an aggregate vote counts its own label only when none of the families it embeds voted directly
    and it overlaps no aggregate already counted. Votes outside the decay window are history.
    """
    window = DECAY_DAYS.get(node.entity.type)
    if window is not None and (node.noise_kind in IAAS_KINDS or IAAS_KINDS & set(node.tags)):
        window = min(window, IAAS_DECAY_DAYS)
    current: list[Vote] = []
    history: list[str] = []
    excluded: list[str] = []
    for vote in votes:
        if vote.source and vote.source in blocked:
            excluded.append(f"not counted: {vote.source} (disabled by the licence profile)")
            continue
        if vote.terms == "unknown" and vote.source:
            excluded.append(f"not counted: {vote.source} (unknown terms: disabled in every licence profile)")
            continue
        age = age_days(vote.when, now)
        if window is not None and age is not None and age > window:
            history.append(f"history (not counted): {vote.describe()} - older than {window} days")
            continue
        if vote.when is None and vote.historical:
            history.append(f"history (not counted): {vote.describe()} - the source marks the listing historical")
            continue
        current.append(vote)
    unattributed = [v for v in current if v.families == (UNATTRIBUTED,)]
    if unattributed and len({v.module for v in unattributed}) < UNATTRIBUTED_MIN_MODULES:
        for v in unattributed:
            excluded.append(f"not counted: verdict of {v.module} without registry provenance and without a second module")
        current = [v for v in current if v.families != (UNATTRIBUTED,)]
    families: list[str] = []
    counted: list[Vote] = []
    dedup: list[str] = []
    order = sorted(current, key=lambda v: (v.aggregate, v.label, v.source, v.module, v.finding))
    direct = {v.families[0] for v in order if not v.aggregate}
    seen_aggregates: list[set[str]] = []
    for vote in order:
        if not vote.aggregate:
            fam = vote.families[0]
            if fam in families:
                dedup.append(f"deduplicated: {vote.describe()} - family {fam} already counted")
                continue
            families.append(fam)
            counted.append(vote)
            continue
        cands = set(vote.families)
        overlap = cands & direct
        if overlap:
            dedup.append(f"deduplicated: {vote.describe()} - embeds {', '.join(sorted(overlap))} (already counted)")
            continue
        if any(cands & other for other in seen_aggregates):
            dedup.append(f"deduplicated: {vote.describe()} - overlaps another counted aggregate")
            continue
        seen_aggregates.append(cands)
        families.append(vote.label)
        counted.append(vote)
    return Consensus(families=families, counted=counted, deduplicated=dedup, history=history, excluded=excluded)


def cr27_downgrades(node: Node) -> list[tuple[str, str]]:
    """(suppression rule, reason) pairs that keep a consensus on ``node`` but downgrade it (P171 cond
    5-7): benign scanners, allow-listed values, shared CDN/SaaS/hosting addresses, other noise ranges
    (resolvers, webmail, private) and anonymity infrastructure (never scored malicious)."""
    out: list[tuple[str, str]] = []
    classes = {str(v).strip().lower() for v in node.attr_values("scanner_classification")}
    if node.noise_kind == "benign_scanner" or "benign_scanner" in node.tags:
        out.append(("SUP-benign_scanner", "known benign internet scanner (research/search-engine scanner list)"))
    elif "benign" in classes:
        out.append(("SUP-benign_scanner", "classified benign by a scanner-intelligence source (e.g. GreyNoise 'benign')"))
    elif evidence_tagged(node, {"benign_scanner"}):
        out.append(("SUP-benign_scanner", "known benign internet scanner"))
    if evidence_tagged(node, {"known_good"}) or node.attr_values("allowlisted"):
        out.append(("SUP-allowlist", "allow-listed / known benign by a source"))
    kind = shared_kind(node)
    if kind:
        out.append(("SUP-shared_address", f"shared {kind} address: the listing may concern another tenant of the address"))
    elif node.noise and node.noise_kind not in NOISE_KEEP_KINDS:
        out.append(("SUP-noise", f"noise/shared infrastructure ({node.noise_kind or 'noise list'}): many unrelated users behind the value"))
    current, _past = _anonymizer_facts(node)
    if current:
        out.append((
            "SUP-anonymizer",
            f"anonymity infrastructure ({', '.join(sorted(current))}): a lawful privacy tool relaying many users' traffic, never scored malicious",
        ))
    return out


def _cr27_downgrade(node: Node) -> tuple[str, str]:
    """The first (suppression rule, reason) of :func:`cr27_downgrades`, or ('', '')."""
    found = cr27_downgrades(node)
    return found[0] if found else ("", "")


@rule(
    CR27,
    "Independent upstream families list the entity as malicious (consensus)",
    "CR27 (P171): HIGH when >= 2 independent upstream families list the entity inside the decay window "
    "(ip/url 30 days, domain 90 days), MEDIUM with one. Families, not modules: feeds relaying one "
    "upstream count once and aggregates count as the families they embed. Suppression runs first and "
    "only downgrades; licence-disabled feeds are not counted.",
    version="2",
    code="CR27",
    severity="high",
    criterion="distinct registry upstream families (Finding.source -> upstream_family / embeds) listing the entity "
    "inside the type's decay window, after warninglist/sinkhole/benign-scanner/shared-address suppression",
    references=_REFS_CONSENSUS,
    attack=("T1583", "T1584"),
    false_positives="Shared hosting/CDN addresses (another tenant listed), benign research scanners, sinkholes, "
    "allow-listed infrastructure and stale listings: suppressed or downgraded with the reason, never deleted.",
    fixtures=_fixtures(
        CR27, "positive_two_families_high", "positive_two_modules_one_upstream_count_once", "positive_stale_hit_not_counted",
        "positive_cdn_ip_downgraded_cohosted_domains_untainted", "positive_benign_scanner_downgraded",
        "positive_tor_exit_capped_low", "negative_stale_hits_only", "negative_suppressed_findings",
        "negative_cdn_ip_listing_does_not_taint_domains", "negative_sinkhole", "negative_analyst_false_positive",
    ),
)
def multi_source_malicious(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    now = now_of(rctx)
    blocked = licence_blocked_sources(results, rctx)
    for key in sorted(graph.nodes):
        node = graph.nodes[key]
        votes, excluded = collect_votes(graph, node, rctx)
        if not votes:
            continue
        cons = count_families(node, votes, now, blocked=blocked)
        n = len(cons.families)
        if n == 0:
            continue
        severity = Severity.HIGH if n >= CONSENSUS_FAMILIES else Severity.MEDIUM
        confidence = 0.9 if n >= CONFIRMED_FAMILIES else 0.8 if n >= CONSENSUS_FAMILIES else 0.6
        fam_text = ", ".join(cons.families)
        evidence = [f"counted: {v.describe()}" for v in cons.counted]
        evidence += [f"finding:{v.finding}" for v in cons.counted if v.finding]
        evidence += cons.deduplicated + cons.history + excluded + cons.excluded
        corr = Correlation(
            rule=CR27,
            title=f"{node.entity.display} listed as malicious by {n} independent upstream famil{'y' if n == 1 else 'ies'}",
            severity=severity,
            description=(
                f"Upstream families listing the entity inside the decay window: {fam_text}. "
                + ("Independent sources agree, which makes a false positive unlikely." if n >= CONSENSUS_FAMILIES
                   else "A single upstream family lists it: corroborate before blocking.")
                + (f" {len(cons.deduplicated)} listing(s) relay an upstream already counted." if cons.deduplicated else "")
                + (f" {len(cons.history)} older listing(s) are history and not counted." if cons.history else "")
            ),
            entities=[node.entity],
            confidence=confidence,
            evidence=evidence,
            recommendation=(
                "Block the indicator at the perimeter/EDR and hunt for it in proxy, DNS and mail logs."
                if n >= CONSENSUS_FAMILIES else
                "Corroborate with a second independent source or your own telemetry before blocking."
            ),
            tags=["malicious"] if n >= CONSENSUS_FAMILIES else ["suspicious"],
            criterion=f"{n} independent upstream famil{'y' if n == 1 else 'ies'} ({fam_text}) inside the decay window",
            why=f"families counted: {fam_text}",
        )
        downgrades = cr27_downgrades(node)
        if downgrades:
            rules = list(dict.fromkeys(rule_name for rule_name, _r in downgrades))
            corr.severity = min([corr.severity] + [SUPPRESSION_CAPS.get(r, SUPPRESSED_CAP) for r in rules])
            for sup_rule, reason in downgrades:
                corr.downgrade(sup_rule, reason, to=Confidence.POSSIBLE)
            context = bool(CONTEXT_SUPPRESSIONS.intersection(rules))
            corr.tags = ["suspicious", "weak_signal"] + ([CONTEXT_ONLY] if context else [])
            shown = ", ".join(r[len(SUPPRESSION_PREFIX):] if r.startswith(SUPPRESSION_PREFIX) else r for r in rules)
            corr.title += f" (downgraded: {shown})"
            reasons = "; ".join(reason for _rule, reason in downgrades)
            corr.description += f" Suppressed (downgraded, never deleted): {reasons}."
            corr.recommendation = f"Context: {reasons}. Do not block the value on this consensus alone."
        yield corr


# ----------------------------------------------------------------------------------------
# CR28 anonymized_infrastructure
# ----------------------------------------------------------------------------------------


def _anonymizer_facts(node: Node) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """(current facts, history facts): label -> sources/finding ids."""
    current: dict[str, list[str]] = {}
    past: dict[str, list[str]] = {}
    for attr, label in ANONYMIZER_ATTRIBUTES.items():
        for value, src in node.attributes.get(attr, []):
            if value is True:
                current.setdefault(label, []).append(src or "?")
    for attr, label in ANONYMIZER_HISTORY_ATTRIBUTES.items():
        for value, src in node.attributes.get(attr, []):
            if value and value is not False:
                past.setdefault(label, []).append(src or "?")
    for f in evidence_findings(node):
        for tag, label in ANONYMIZER_TAGS.items():
            if tag in (f.tags or ()):
                current.setdefault(label, []).append(f"finding:{f.id}")
    for tag, label in ANONYMIZER_TAGS.items():
        if tag in node.tags:
            current.setdefault(label, []).append("entity tag")
    return current, past


@rule(
    CR28,
    "Anonymity infrastructure (Tor exit, VPN, proxy): context only",
    "CR28 (P171 cond 7): Tor exit / VPN / anonymizing-proxy membership is context, never a verdict: at most LOW, "
    "tagged context_only and never malicious (lawful privacy tools; traffic from many users, no attribution).",
    version="1",
    code="CR28",
    severity="low",
    criterion="a source reports the address as a Tor exit, VPN endpoint or anonymizing proxy (context only)",
    references=_REFS_TOR,
    attack=("T1090", "T1090.003"),
    false_positives="Shared VPN/proxy exits carry traffic of many unrelated users; Tor exits relay others' traffic.",
    fixtures=_fixtures(CR28, "positive_tor_exit_context", "positive_past_exit_is_info", "negative_no_anonymizer_facts"),
)
def anonymized_infrastructure(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    for key in sorted(graph.nodes):
        node = graph.nodes[key]
        if node.entity.type not in (EntityType.IPV4, EntityType.IPV6, EntityType.CIDR):
            continue
        current, past = _anonymizer_facts(node)
        if not current and not past:
            continue
        labels = sorted(current) or sorted(past)
        sources = sorted({s for group in (current or past).values() for s in group})
        severity = ANONYMIZER_SEVERITY if current else ANONYMIZER_HISTORY_SEVERITY
        tor = any("Tor" in label for label in labels)
        yield Correlation(
            rule=CR28,
            title=f"{node.entity.display} is anonymity infrastructure ({', '.join(labels)}): context only",
            severity=severity,
            description=(
                f"{', '.join(labels)} reported by {len(sources)} source(s). Anonymity networks and VPNs are lawful privacy "
                "tools carrying traffic of many users: this is context for the analyst, never evidence of malice and "
                "never attribution." + ("" if current else " Only past or non-exit membership is known.")
            ),
            entities=[node.entity],
            confidence=0.9 if len(sources) >= 2 else 0.7,
            evidence=[f"{label}: {', '.join(sorted(set(srcs)))}" for label, srcs in sorted((current or past).items())],
            recommendation="Treat activity from this address as unattributable; correlate with your own logs instead of blocking on membership alone.",
            tags=["anonymizer", CONTEXT_ONLY] + (["tor"] if tor else []),
            criterion=f"source facts: {', '.join(labels)} (context only, never scored as malicious)",
            attack=["T1090.003"] if tor else ["T1090"],
        )


# ----------------------------------------------------------------------------------------
# CR29 favicon_clone_cluster
# ----------------------------------------------------------------------------------------

_SITE_TYPES = (EntityType.DOMAIN, EntityType.URL, EntityType.IPV4, EntityType.IPV6)


def _favicon_value(value: Any) -> str:
    """Normalised Shodan-style mmh3 favicon hash ('-1234'); '' when not an integer."""
    try:
        return str(int(str(value).strip()))
    except (TypeError, ValueError):
        return ""


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def favicon_clusters(graph: Graph) -> dict[str, dict[str, Any]]:
    """Clusters of sites sharing a favicon: cluster id -> {'hashes': set, 'sites': set of site keys}.

    Hashes come from the site attribute ``favicon_mmh3`` and from ``favicon`` edges between a site
    and a favicon_hash node; ``similar_to`` edges between favicon/icon nodes merge clusters."""
    uf = _UnionFind()
    site_hashes: dict[str, set[str]] = {}
    for key, node in graph.nodes.items():
        if node.entity.type in _SITE_TYPES:
            for value in node.attr_values("favicon_mmh3"):
                fav = _favicon_value(value)
                if fav:
                    site_hashes.setdefault(key, set()).add(f"favicon_hash:{fav}")
    for edge in graph.edges:
        src, dst = graph.nodes.get(edge.src), graph.nodes.get(edge.dst)
        if src is None or dst is None:
            continue
        if edge.relation == "favicon":
            pair = (src, dst) if dst.entity.type is EntityType.FAVICON_HASH else (dst, src)
            site, fav = pair
            if fav.entity.type is EntityType.FAVICON_HASH and site.entity.type in _SITE_TYPES:
                site_hashes.setdefault(site.key, set()).add(f"favicon_hash:{_favicon_value(fav.entity.value) or fav.entity.value}")
        elif edge.relation == "similar_to" and {src.entity.type, dst.entity.type} <= {EntityType.FAVICON_HASH, EntityType.ICON_DHASH}:
            uf.union(_fav_key(src), _fav_key(dst))
    clusters: dict[str, dict[str, Any]] = {}
    for site, hashes in site_hashes.items():
        for h in hashes:
            entry = clusters.setdefault(uf.find(h), {"hashes": set(), "sites": set()})
            entry["sites"].add(site)
            entry["hashes"].add(h)
    for h in list(uf.parent):  # similar_to-linked hashes no site of the case serves
        root = uf.find(h)
        if root in clusters:
            clusters[root]["hashes"].add(h)
    return clusters


def _fav_key(node: Node) -> str:
    if node.entity.type is EntityType.FAVICON_HASH:
        return f"favicon_hash:{_favicon_value(node.entity.value) or node.entity.value}"
    return node.key


def _site_domains(graph: Graph, site: Node) -> list[Node]:
    """The site and the domains it is served from (URL -> url_host; IP -> nothing extra)."""
    out = [site]
    if site.entity.type is EntityType.URL:
        out += [n for n in adjacent(graph, site.key, "url_host") if n.entity.type is EntityType.DOMAIN]
    return out


def lookalike(graph: Graph, node: Node) -> bool:
    """A typosquat/lookalike candidate: tag (entity or evidence finding), or the candidate end of a
    ``lookalike`` (brand -> candidate) or ``lookalike_of`` (candidate -> brand) edge."""
    if LOOKALIKE_TAGS & set(node.tags) or evidence_tagged(node, LOOKALIKE_TAGS):
        return True
    return bool(edges_in(graph, node.key, "lookalike") or edges_out(graph, node.key, "lookalike_of"))


def phishing_signals(graph: Graph, site: Node, now: _dt.datetime) -> list[str]:
    """Non-similarity signals of a site (CR29/CR30): young domain, typosquat/lookalike, phishing tag."""
    signals: list[str] = []
    for node in _site_domains(graph, site):
        young = young_domain(node, now)
        if young:
            signals.append(f"young domain {node.entity.display}: {young}")
        if lookalike(graph, node):
            signals.append(f"typosquat/lookalike: {node.entity.display}")
        if "phishing" in node.tags or evidence_tagged(node, {"phishing"}):
            signals.append(f"phishing tag on {node.entity.display}")
    return list(dict.fromkeys(signals))


@rule(
    CR29,
    "Favicon shared with a cluster of sites plus a phishing signal",
    "CR29 (P171 cond 8): sites sharing a favicon hash (indexed hashes first) need at least one extra non-similarity "
    "signal (young domain, typosquat, phishing tag). An org-profile brand favicon on a non-owned host plus one signal "
    "is HIGH 'brand favicon clone'.",
    version="1",
    code="CR29",
    severity="high",
    criterion="identical (or similar_to-linked) favicon hash on a non-owned site plus >= 1 non-similarity signal",
    references=_REFS_FAVICON,
    attack=("T1583.001", "T1608.005", "T1684.001"),
    false_positives="Default favicons of frameworks and hosting platforms, resellers and partners embedding the brand "
    "icon: the extra signal requirement filters most of them.",
    fixtures=_fixtures(
        CR29, "positive_brand_favicon_clone", "positive_cluster_with_typosquat", "negative_cluster_without_signal",
        "negative_brand_favicon_on_own_host",
    ),
)
def favicon_clone_cluster(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    now = now_of(rctx)
    org = org_of(rctx)
    brand = {f"favicon_hash:{_favicon_value(h)}" for h in (getattr(org, "favicon_hashes", None) or ()) if _favicon_value(h)}
    for _root, cluster in sorted(favicon_clusters(graph).items()):
        sites = sorted(cluster["sites"])
        brand_hashes = sorted(cluster["hashes"] & brand)
        if len(sites) < FAVICON_CLUSTER_MIN_SITES and not brand_hashes:
            continue
        for key in sites:
            site = graph.nodes[key]
            if site.noise or own_asset(site, rctx) or any(own_asset(d, rctx) for d in _site_domains(graph, site)[1:]):
                continue
            signals = phishing_signals(graph, site, now)
            if not signals:
                continue
            others = [k for k in sites if k != key]
            if brand_hashes:
                severity, label = BRAND_CLONE_SEVERITY, "brand favicon clone"
                confidence = 0.8
                why = f"serves the organisation's brand favicon {', '.join(h.split(':', 1)[1] for h in brand_hashes)} from a non-owned host"
            else:
                severity, label = CLUSTER_SEVERITY, "favicon shared with a cluster of sites"
                confidence = 0.7 if len(signals) >= 2 else 0.5
                why = f"shares favicon {', '.join(sorted(h.split(':', 1)[1] for h in cluster['hashes']))} with {len(others)} other site(s)"
            fav_entities = [Entity.try_make(EntityType.FAVICON_HASH, h.split(":", 1)[1]) for h in sorted(cluster["hashes"]) if h.startswith("favicon_hash:")]
            yield Correlation(
                rule=CR29,
                title=f"{site.entity.display}: {label}",
                severity=severity,
                description=f"{site.entity.display} {why}. Extra signal(s): {'; '.join(signals)}.",
                entities=[site.entity] + [e for e in fav_entities if e is not None][:3] + [graph.nodes[k].entity for k in others[:MAX_CLUSTER_MEMBERS]],
                confidence=confidence,
                evidence=[f"favicon {h.split(':', 1)[1]}" for h in sorted(cluster["hashes"])] + signals + [f"cluster member: {k}" for k in others[:MAX_CLUSTER_MEMBERS]],
                recommendation="Review the site for brand impersonation (archived copies, urlscan results) and start takedown if it imitates the organisation; never fetch it from the corporate egress.",
                tags=["phishing", "typosquat"] if brand_hashes else ["suspicious"],
                criterion=f"{label}: identical favicon hash + {len(signals)} non-similarity signal(s)",
                key=key,
            )


# ----------------------------------------------------------------------------------------
# CR30 jarm_matches_known_c2
# ----------------------------------------------------------------------------------------


def _jarms(node: Node) -> list[str]:
    """Normalised JARM values of a host (attribute ``jarm``: a string, a list, or {port, jarm} items)."""
    out: list[str] = []
    for value in node.attr_values("jarm"):
        raw = value.get("jarm") if isinstance(value, Mapping) else value
        text = str(raw or "").strip().lower()
        if JARM_RE.match(text) and text != JARM_EMPTY and text not in out:
            out.append(text)
    return out


def _known_c2_jarms(graph: Graph) -> dict[str, list[str]]:
    """JARM -> descriptions of the known C2 servers carrying it (C2-tagged hosts of the case)."""
    known: dict[str, list[str]] = {}
    for key in sorted(graph.nodes):
        node = graph.nodes[key]
        if node.noise or shared_kind(node):
            continue
        c2 = evidence_tagged(node, {"c2", "botnet"})
        if not c2 and "c2" not in node.tags:
            continue
        for jarm in _jarms(node):
            known.setdefault(jarm, []).append(key)
    return known


def _listed_matches(node: Node) -> list[tuple[str, str]]:
    """(jarm, description) pairs a source reports for the host (attribute ``jarm_c2_matches``)."""
    out: list[tuple[str, str]] = []
    for value, src in node.attributes.get("jarm_c2_matches", []):
        for item in value if isinstance(value, list) else [value]:
            if not isinstance(item, Mapping):
                continue
            jarm = str(item.get("jarm") or "").strip().lower()
            if not JARM_RE.match(jarm) or jarm == JARM_EMPTY:
                continue
            fam = str(item.get("family") or item.get("list") or "known C2")
            out.append((jarm, f"{fam} (listed by {item.get('source') or src or '?'})"))
    return out


def _jarm_extra_signals(graph: Graph, node: Node, matches: list[str], now: _dt.datetime) -> list[str]:
    signals: list[str] = []
    if evidence_tagged(node, VOTE_TAGS | {"suspicious", "blocklisted"}):
        signals.append("the host itself is listed or flagged by a source")
    if _flag(node, "tls_self_signed"):
        signals.append("self-signed TLS certificate")
    for dom in sorted(adjacent(graph, node.key, "resolves_to", direction="in"), key=lambda n: n.key):
        young = young_domain(dom, now)
        if young:
            signals.append(f"young domain {dom.entity.display} resolves to it ({young})")
        if lookalike(graph, dom):
            signals.append(f"lookalike domain {dom.entity.display} resolves to it")
    my_asn = {str(v).upper() for v in node.attr_values("asn")}
    my_certs = {str(v).lower() for v in node.attr_values("cert_sha256")}
    for other_key in matches:
        other = graph.nodes.get(other_key)
        if other is None:
            continue
        if my_asn & {str(v).upper() for v in other.attr_values("asn")}:
            signals.append(f"same AS as the known C2 {other.entity.display}")
        if my_certs & {str(v).lower() for v in other.attr_values("cert_sha256")}:
            signals.append(f"same TLS certificate as the known C2 {other.entity.display}")
    return list(dict.fromkeys(signals))


@rule(
    CR30,
    "Indexed JARM fingerprint matches a known C2 server",
    "CR30 (P171 cond 9): passive JARM values from indexed scan data equal to the JARM of a C2 server known in the case "
    "or listed by a source. MEDIUM with >= 1 extra signal, LOW/POSSIBLE otherwise. Live JARM probes are ACTIVE and run "
    "only on in-scope authorized targets: never from this rule.",
    version="1",
    code="CR30",
    severity="medium",
    criterion="identical indexed JARM fingerprint (62 hex) on a non-shared host plus >= 1 extra signal",
    references=_REFS_JARM,
    attack=("T1071",),
    false_positives="JARM identifies a TLS server stack: default configurations (Java, Go, some load balancers) share "
    "fingerprints with C2 frameworks. Hence the extra-signal requirement and low confidence without one.",
    fixtures=_fixtures(CR30, "positive_match_with_extra_signal", "positive_match_without_signal_is_low", "negative_no_match"),
)
def jarm_matches_known_c2(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    now = now_of(rctx)
    known = _known_c2_jarms(graph)
    known_hosts = {k for keys in known.values() for k in keys}
    for key in sorted(graph.nodes):
        node = graph.nodes[key]
        if node.entity.type not in (EntityType.IPV4, EntityType.IPV6, EntityType.DOMAIN) or node.noise or shared_kind(node):
            continue
        listed = _listed_matches(node)
        for jarm in _jarms(node):
            # a host already known as C2 learns nothing from another C2's JARM: only a source's list counts
            others = [] if key in known_hosts else [k for k in known.get(jarm, []) if k != key]
            via_list = [desc for j, desc in listed if j == jarm]
            if not others and not via_list:
                continue
            signals = _jarm_extra_signals(graph, node, others, now)
            strong = bool(signals)
            matched = [f"known C2 {graph.nodes[k].entity.display}" for k in others[:5]] + via_list[:5]
            corr = Correlation(
                rule=CR30,
                title=f"{node.entity.display}: JARM matches a known C2 server",
                severity=JARM_SEVERITY if strong else JARM_WEAK_SEVERITY,
                description=(
                    f"Indexed JARM {jarm} of {node.entity.display} equals the JARM of: {'; '.join(matched)}. "
                    + (f"Extra signal(s): {'; '.join(signals)}." if strong else
                       "No extra signal: JARM alone identifies a TLS stack, not an operator (low confidence).")
                ),
                entities=[node.entity] + [graph.nodes[k].entity for k in others[:5]],
                confidence=0.7 if strong else 0.4,
                evidence=[f"jarm {jarm}"] + matched + signals,
                recommendation="Hunt for connections to the host in proxy/firewall logs; confirm with certificate, ASN and passive DNS before blocking.",
                tags=["c2", "suspicious"] if strong else ["weak_signal"],
                criterion=f"identical JARM {jarm[:12]}... with {len(signals)} extra signal(s)",
                key=jarm,
            )
            yield corr
