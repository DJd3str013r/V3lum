"""Risk model v2 (P302): severity x confidence x Admiralty reliability x MISP decay x asset criticality.

A **triage aid, not a conclusion** (:data:`SCORE_LABEL`): :func:`score` is a pure function of the
case graph, the correlations and the explicit inputs below (it reads the provider registry and the
module registry, never the network or the case DB) and every constant is documented here.

Per finding (the weight of one fact, 0..1)::

    weight = W_SEV[severity] / 10  x  C_conf  x  R_src  x  decay  x  A_crit

* ``W_SEV`` (:data:`W_SEV`): CRITICAL 10, HIGH 7, MEDIUM 4, LOW 2, INFO 0 (INFO never scores).
* ``C_conf`` (:data:`C_CONF`): the P322 label weight ``Confidence.weight`` - CONFIRMED 1.0, PROBABLE
  0.7, POSSIBLE 0.4. A warninglisted finding (the engine's ``SUP-warninglist`` suppression record)
  counts as POSSIBLE with the label 'on warninglist'. An analyst override always wins (its label and
  severity are the finding's); an override verdict that rejects the finding (``false_positive``,
  ``benign``, ``wrong``... :data:`REJECT_VERDICTS`) takes it out of the score.
* ``R_src``: the Admiralty prior of the finding's source provider (``providers.ADMIRALTY``: A 1.0,
  B 0.85, C 0.7, D 0.5, E 0.3, F 0.5), replaced by the analyst-feedback weight of that source when
  ``source_reliability`` (``Store.source_reliability()``: Beta-updated by explicit votes, moving off
  the prior only after 5 votes, floor 0.3 - P325) has it. The source is ``Finding.source``
  ('provider.source', or a short id of the module's provider); a finding without one (or with a
  source the registry does not know) uses its module's declared ``Module.sources`` (several: the
  least reliable; an unregistered provider: F 0.5); a finding of a module without registry sources (offline analysis) uses
  :data:`LOCAL_RELIABILITY` (1.0) times the v1 per-module weight (``reliability``, ``Store.reliability()``).
  When ``source_reliability`` is not given at all (a v1 caller), the v1 per-module weight also
  multiplies sourced findings, as in model v1.
* ``decay``: the MISP polynomial ``base x (1 - (t / tau) ** (1 / delta))`` (:func:`decay`) with
  ``t`` = days since ``Finding.observed_last`` and ``tau`` = :data:`TAU_DAYS` of the finding's class
  (:func:`decay_class`: the tags infostealer / breach / typosquat first, then the entity type - ip,
  url, domain, hash), ``delta`` = :data:`DELTA` (1.0). Hashes never decay; a finding without a
  provider timestamp gets no decay and the label 'age unknown'.
* ``A_crit`` (:data:`A_CRIT`): org-profile criticality of the entity (``Node.criticality``):
  critical 1.0, high 0.95, medium 0.85, low 0.6; entities without one 1.0.

Never scored: findings tagged ``context_only`` (A4 BR6/BR9: generic/role/test addresses, third-party
breach context, sinkholes...) or ``known_good``, findings of sources disabled by the licence profile
(``coverage``: a source row or the entity row of the module with reason_code 'licence'), findings on
noise nodes (unless an analyst decided on them), INFO findings, and correlations tagged
``context_only``. :data:`TAG_FAMILIES` / :func:`tag_family` and :func:`upstream_families` name what
is deduplicated.

Per entity: the findings are grouped by **tag family** (:func:`tag_family`); within a family,
findings whose upstream families overlap (``Source.families``: the upstream family plus the families
an aggregator embeds) are one contribution (the strongest is kept: deduplication per (entity, tag
family, upstream family)). A family reported by >= 2 *independent* upstream families counts once at
'+1 confidence level' (POSSIBLE -> PROBABLE -> CONFIRMED; never for warninglisted, overridden or
already upgraded findings) - corroboration never adds a second noisy-OR term. Only groups backed by a
registry upstream family count as independent: findings of modules without registry sources (offline
analysis of collected facts, family ``module:<name>``, :data:`LOCAL_FAMILY_PREFIX`) are derived facts. The family
contributions combine by **noisy-OR** (``1 - prod(1 - w)``, each w <= 0.99) x 100, capped at 100.
**Severity ceiling**: the entity score never exceeds the band of the highest severity among its
contributing findings and correlations (:data:`SEVERITY_CAP`; LOW findings stay 'low' however many).

Correlations take the **max/uplift**, never a second noisy-OR term: a correlation weighs
``W_SEV/10 x C_conf``; an entity it names takes ``max(entity, correlation)`` and its ceiling rises to
the correlation's severity (weak signals escalate only through an explicit correlation rule). Own
assets and known-good/verified entities (:data:`PROTECTED_TAGS`, :data:`PROTECTED_ATTRIBUTES`,
gov.br domains) never inherit risk from neighbours: a correlation uplifts them only when it cites one
of their own findings.

Per case: ``seeds + correlations + the top-5 pivots`` (:data:`TOP_PIVOTS`): the noisy-OR of the seed
entity scores and of the 5 strongest pivot entities weighted by ``Node.path_confidence`` (AR07); a
pivot reached from the seeds only through shared infrastructure (:data:`SHARED_RELATIONS`: co-hosted,
same ASN / network, same NS/MX, or through a noise node such as a CDN) transfers at most a LOW
contribution (:data:`SHARED_TRANSFER_CAP`) and at most LOW severity to the ceiling; then
``max(that, strongest correlation)``, capped by the case ceiling. Levels keep the thresholds
80/55/30/8 (:data:`LEVELS`); the lowest level reads 'no findings'. A seed for which fewer than 2
reputation-capable sources answered ok/empty (``coverage['answered'][seed]['reputation_answered']``)
is listed in ``inconclusive``: its reading is 'inconclusive', never 'no findings'.

Output (:func:`score`): the v1 keys ``score``, ``level``, ``entities`` ({key: {score, level, ...}}) and
``top`` stay, so stored v1 cases still render; v2 adds ``contributors`` (the top-3 of the case:
finding_id, entity, path, confidence_label, weight, words), ``label`` ('triage aid, not a
conclusion'), ``inconclusive`` (seed keys), ``no_export`` (PERSONAL_TYPES entity keys: their scores
are never exported to STIX/MISP as a score about a person and never drive an automated action, LGPD
art. 20), ``automation`` (``{score, level, basis}``: the case score without PERSONAL_TYPES entities
and the correlations naming one - the only score an automated action such as ``--fail-on`` may use,
P302 cond 10), ``reading`` (the level, or 'inconclusive' at the lowest level when a seed is listed
in ``inconclusive``), ``ceiling``, ``excluded`` (counts per reason) and ``model`` ('v3lum.risk/2').
Malformed reliability values (NaN, text) are ignored: the prior applies, never the floor.

Feedback (P325): the analyst votes on findings with ``Store.vote`` (``v3lum cases feedback``); the
per-source Beta weights come back through ``Store.source_reliability()`` and the analyst decisions on
single findings through ``Store.overrides_for`` (applied by the engine before suppression,
correlations and scoring, so they survive re-runs). ``Store.reliability()`` is the v1 module view.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import heapq
import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from v3lum.core import entities as _entities
from v3lum.core import providers as _providers
from v3lum.core.entities import PERSONAL_TYPES, SECRET_TYPES, Entity, EntityType
from v3lum.core.graph import Edge, Graph, Node
from v3lum.core.models import Confidence, Correlation, Finding, Severity

__all__ = [
    "AUTOMATION_BASIS",
    "A_CRIT",
    "A_CRIT_DEFAULT",
    "C_CONF",
    "DELTA",
    "INCONCLUSIVE",
    "LEVELS",
    "LOCAL_FAMILY_PREFIX",
    "LOCAL_RELIABILITY",
    "MODEL",
    "NO_FINDINGS",
    "PROTECTED_ATTRIBUTES",
    "PROTECTED_TAGS",
    "REJECT_VERDICTS",
    "SCORE_LABEL",
    "SEVERITY_CAP",
    "SHARED_RELATIONS",
    "SHARED_TRANSFER_CAP",
    "TAG_FAMILIES",
    "TAU_DAYS",
    "TOP_CONTRIBUTORS",
    "TOP_PIVOTS",
    "W_SEV",
    "WEIGHTS",
    "age_days",
    "decay",
    "decay_class",
    "level",
    "score",
    "tag_family",
    "upstream_families",
]

#: Schema id of the risk dict (``risk['model']``).
MODEL = "v3lum.risk/2"
#: Every score carries this label (P302 cond 9).
SCORE_LABEL = "triage aid, not a conclusion"
#: The lowest level (renamed from v1 'clean', P302 cond 6).
NO_FINDINGS = "no findings"
#: The case reading at the lowest level when a seed lacks 2 reputation-capable answers (P302 cond 6).
INCONCLUSIVE = "inconclusive"
#: What ``risk['automation']`` leaves out (P302 cond 10, LGPD art. 20).
AUTOMATION_BASIS = "case score without personal-data entities and the correlations naming them (LGPD art. 20)"

#: Severity weight W_sev (P302 cond 1); a finding weighs W_SEV / 10.
W_SEV: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.0,
}
#: v1 name kept for old callers: the per-severity weight (W_SEV / 10).
WEIGHTS: dict[Severity, float] = {sev: w / 10.0 for sev, w in W_SEV.items()}
#: Confidence weight C_conf = ``Confidence.weight`` (P322): confirmed 1.0, probable 0.7, possible 0.4.
C_CONF: dict[Confidence, float] = {label: label.weight for label in Confidence}
#: R_src of findings whose module has no registry source (offline analysis of collected facts).
LOCAL_RELIABILITY = 1.0
#: Upstream-family prefix of findings whose module has no registry source (offline analysis): such a
#: family deduplicates the module's own findings but never counts as an independent source.
LOCAL_FAMILY_PREFIX = "module:"
#: R_src of a source the registry does not know (Admiralty F: reliability cannot be judged).
UNKNOWN_SOURCE_RELIABILITY = _providers.ADMIRALTY["F"]
#: Floor of an analyst-feedback source weight (P302 cond 7, P325).
RELIABILITY_FLOOR = 0.3

#: MISP decay tau per class, in days (P302 cond 2); None = never decays.
TAU_DAYS: dict[str, float | None] = {
    "ip": 30,
    "url": 30,
    "domain": 90,
    "typosquat": 180,
    "breach": 1095,
    "infostealer": 365,
    "hash": None,
}
#: MISP decay delta (1.0 = linear).
DELTA = 1.0
#: Asset criticality A_crit from the org profile (P302 cond 8).
A_CRIT: dict[str, float] = {"critical": 1.0, "high": 0.95, "medium": 0.85, "low": 0.6}
#: A_crit of entities without a profile criticality.
A_CRIT_DEFAULT = 1.0

#: (threshold, level) from the highest; the thresholds 80/55/30/8 are unchanged from v1.
LEVELS: list[tuple[float, str]] = [(80, "critical"), (55, "high"), (30, "medium"), (8, "low"), (0, NO_FINDINGS)]
#: Highest score a severity ceiling allows (the top of its level band).
SEVERITY_CAP: dict[Severity, float] = {
    Severity.CRITICAL: 100.0,
    Severity.HIGH: 79.9,
    Severity.MEDIUM: 54.9,
    Severity.LOW: 29.9,
    Severity.INFO: 7.9,
}
#: Pivot entities that count towards the case score (P302 cond 5).
TOP_PIVOTS = 5
#: Contributors listed with the score (P302 cond 9).
TOP_CONTRIBUTORS = 3
#: A seed needs this many reputation-capable answers (ok/empty) not to read 'inconclusive'.
MIN_REPUTATION_ANSWERS = 2
#: No single weight reaches 1.0 in the noisy-OR (v1 rule: one fact never makes a certainty).
MAX_WEIGHT = 0.99

#: Relations through shared infrastructure (co-hosted, same ASN / network, same NS/MX): what is
#: reached only through them transfers at most a LOW contribution to the case (P302 cond 5).
SHARED_RELATIONS: frozenset[str] = frozenset({
    "hosted_domain", "belongs_to_asn", "in_network", "announces", "nameserver", "mx_host",
    "upstream_asn", "downstream_asn", "network_provider",
})
#: The largest contribution a shared-infrastructure pivot transfers (a CONFIRMED LOW from an A source).
SHARED_TRANSFER_CAP = W_SEV[Severity.LOW] / 10.0

#: Entity/finding tags of entities that never inherit risk from neighbours (P302 cond 5).
PROTECTED_TAGS: frozenset[str] = frozenset({"own_asset", "known_good", "verified_fi"})
#: Entity attributes with the same effect (truthy value): allow-listed values, official gov.br and
#: BCB-verified financial-institution domains.
PROTECTED_ATTRIBUTES: frozenset[str] = frozenset({"known_good", "official_gov_br", "bcb_verified_domain"})
#: Override verdicts that take a finding out of the score (the analyst rejected it).
REJECT_VERDICTS: frozenset[str] = frozenset({"false_positive", "false positive", "fp", "benign", "wrong", "negative", "not_malicious"})

#: Finding tags never scored as exposure (A4 BR6) / allow-listed facts.
CONTEXT_ONLY = "context_only"
KNOWN_GOOD = "known_good"
#: The engine's warninglist suppression rule (P302 cond 7).
WARNINGLIST_RULE = "SUP-warninglist"

#: Tag families (ordered: the first family whose tags a finding carries is its family). Findings of
#: one family on one entity state the same kind of fact; they are deduplicated per upstream family.
TAG_FAMILIES: tuple[tuple[str, frozenset[str]], ...] = (
    ("infostealer", frozenset({"infostealer"})),
    ("breach", frozenset({"breach"})),
    ("credential_exposure", frozenset({"credential_exposure"})),
    ("ransomware", frozenset({"ransomware"})),
    ("malicious", frozenset({"malicious", "malware", "c2", "botnet"})),
    ("phishing", frozenset({"phishing"})),
    ("fraud", frozenset({"fraud"})),
    ("suspicious", frozenset({"suspicious"})),
    ("abuse", frozenset({"spam", "scanner"})),
    ("anonymizer", frozenset({"tor", "proxy"})),
    ("vulnerability", frozenset({"vulnerable", "kev", "exploit_available"})),
    ("takeover", frozenset({"takeover"})),
    ("exposure", frozenset({"exposure", "misconfiguration"})),
    ("email_security", frozenset({"weak_email_security"})),
    ("typosquat", frozenset({"typosquat"})),
    ("newly_registered", frozenset({"newly_registered"})),
    ("darkweb", frozenset({"darkweb"})),
    ("sanctions", frozenset({"sanctions", "pep"})),
    ("identity", frozenset({"identity", "account"})),
)
#: Tags that never name a family on their own (context, handling and ownership labels).
NEUTRAL_TAGS: frozenset[str] = frozenset({
    "info", "privacy", "own_asset", "third_party", "weak_signal", "version_inferred", "high_collision",
    "unknown_operator", "hosted_on_legit_platform", "noise", "recipient_token", "infrastructure",
    "sinkhole", "parked", "benign_scanner", CONTEXT_ONLY, KNOWN_GOOD, "verified_fi",
})

_HASH_TYPES = frozenset(EntityType(v) for v in (
    "md5", "sha1", "sha256", "sha512", "ssdeep", "imphash", "tlsh", "telfhash", "gimphash", "authentihash", "icon_dhash",
))
_IP_TYPES = frozenset({EntityType.IPV4, EntityType.IPV6, EntityType.CIDR})
_DOMAIN_TYPES = frozenset({EntityType.DOMAIN, EntityType.ONION})
_DEFANG_TYPES = frozenset({EntityType.DOMAIN, EntityType.URL, EntityType.IPV4, EntityType.IPV6, EntityType.ONION})
_IDENTITY_RULES = frozenset({"identity_link_strength", "cr34"})
_EPS = 1e-12


# ----------------------------------------------------------------------------------------
# small public helpers
# ----------------------------------------------------------------------------------------


def level(score: float) -> str:
    """The level of a 0-100 score: critical >= 80, high >= 55, medium >= 30, low >= 8, else 'no findings'."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return NO_FINDINGS
    for threshold, name in LEVELS:
        if value >= threshold:
            return name
    return NO_FINDINGS


def decay(age: float | None, tau_days: float | None, *, base: float = 1.0, delta: float = DELTA) -> float:
    """MISP polynomial decay ``base x (1 - (age / tau) ** (1 / delta))`` (P302 cond 2).

    ``age`` in days (negative ages - timestamps in the future - count as 0); ``tau_days`` None (a
    class that never decays, e.g. hashes) or ``age`` None (no provider timestamp: 'age unknown')
    return ``base`` unchanged; at or beyond ``tau`` the result is 0.0. Example: ``decay(15, 30)`` =
    0.5; ``decay(1, 30, base=80, delta=2)`` = 65.4 (the MISP reference curve)."""
    if age is None or tau_days is None:
        return float(base)
    try:
        tau = float(tau_days)
        t = max(0.0, float(age))
        d = float(delta)
    except (TypeError, ValueError):
        return float(base)
    if tau <= 0 or d <= 0:
        return float(base)
    if t >= tau:
        return 0.0
    return float(base) * (1.0 - (t / tau) ** (1.0 / d))


def decay_class(finding: Finding | Mapping[str, Any], entity_type: EntityType | str | None = None) -> str | None:
    """The :data:`TAU_DAYS` class of a finding (``Finding`` or its dict): the tags infostealer, then
    breach / credential_exposure, then typosquat; else the entity type - hash types 'hash', IPs and
    CIDRs 'ip', URLs 'url', domains and onions 'domain'; None for any other type (no decay)."""
    tags = set(_tags_of(finding))
    if "infostealer" in tags:
        return "infostealer"
    if "breach" in tags or "credential_exposure" in tags:
        return "breach"
    if "typosquat" in tags:
        return "typosquat"
    etype = _etype(entity_type) if entity_type is not None else _finding_etype(finding)
    if etype is None:
        return None
    if etype in _HASH_TYPES:
        return "hash"
    if etype in _IP_TYPES:
        return "ip"
    if etype is EntityType.URL:
        return "url"
    if etype in _DOMAIN_TYPES:
        return "domain"
    return None


def age_days(observed: Any, now: _dt.datetime | None = None) -> float | None:
    """Days between ``observed`` (an ISO date/datetime string or a datetime) and ``now`` (UTC now when
    None); None when ``observed`` is empty or unreadable. 'YYYY-MM' and 'YYYY' read as the first day."""
    when = _parse_time(observed)
    if when is None:
        return None
    ref = _aware(now) if now is not None else _dt.datetime.now(_dt.timezone.utc)
    return (ref - when).total_seconds() / 86400.0


def tag_family(finding: Finding | Mapping[str, Any]) -> str:
    """The tag family of a finding (:data:`TAG_FAMILIES`); else 'tag:<first non-neutral tag>'; else
    'title:<lower-cased title>' (a finding without a family tag is its own kind of fact)."""
    tags = [str(t) for t in _tags_of(finding)]
    present = set(tags)
    for family, members in TAG_FAMILIES:
        if members & present:
            return family
    for tag in tags:
        if tag and tag not in NEUTRAL_TAGS:
            return f"tag:{tag}"
    title = finding.get("title") if isinstance(finding, Mapping) else getattr(finding, "title", "")
    return "title:" + re.sub(r"\s+", " ", str(title or "")).strip().lower()


def upstream_families(source_ids: Iterable[str], registry: Any = None) -> frozenset[str]:
    """Upstream families of registry sources ('provider.source'): ``Source.families`` (the source's
    upstream family plus the families it embeds); an unregistered id counts as 'source:<id>'."""
    reg = registry if registry is not None else _registry()
    out: set[str] = set()
    for sid in source_ids:
        src = _lookup_source(reg, str(sid))
        fams = set(getattr(src, "families", ()) or ()) if src is not None else set()
        if not fams and src is not None and getattr(src, "upstream_family", ""):
            fams = {src.upstream_family}
        out |= fams or {f"source:{sid}"}
    return frozenset(out)


# ----------------------------------------------------------------------------------------
# the model
# ----------------------------------------------------------------------------------------


@dataclass
class _Part:
    """One scored finding (or the corroborated best of a tag family)."""

    finding: Finding
    node: Node
    weight: float
    severity: Severity
    label: Confidence
    reliability: float
    decay: float
    age: str
    crit: float
    family: str
    upstreams: frozenset[str]
    source: str
    notes: list[str] = field(default_factory=list)
    corroboration: int = 1
    warninglisted: bool = False

    def rank(self) -> tuple[float, int, int, str]:
        return (round(self.weight, 12), int(self.severity), self.label.rank, self.finding.id or "")


@dataclass
class _Row:
    """An entity's scoring state."""

    node: Node
    parts: list[_Part]
    base: float  # 0..1, findings only (what the case aggregates)
    ceiling: Severity
    uplift: float = 0.0  # 0..1, the strongest correlation naming the entity (display row only)
    uplift_ceiling: Severity = Severity.INFO
    uplift_by: Correlation | None = None


class _Inputs:
    """The explicit inputs of one :func:`score` call, resolved once."""

    def __init__(self, reliability: Mapping[str, float] | None, source_reliability: Mapping[str, float] | None,
                 now: _dt.datetime | None, coverage: Any, registry: Any) -> None:
        self.reliability = dict(reliability or {})
        self.source_reliability = dict(source_reliability) if source_reliability is not None else None
        self.now = _aware(now) if now is not None else _dt.datetime.now(_dt.timezone.utc)
        self.coverage, self.answered = _coverage_parts(coverage)
        self.registry = registry if registry is not None else _registry()
        self.modules = _module_registry()
        self.excluded: Counter[str] = Counter()

    def module_sources(self, module: str) -> tuple[str, ...]:
        cls = self.modules.get(module) if module else None
        try:
            return tuple(str(s) for s in (getattr(cls, "sources", ()) or ()) if s)
        except TypeError:
            return ()

    def module_provider(self, module: str) -> str:
        cls = self.modules.get(module) if module else None
        return str(getattr(cls, "provider", "") or "")


def score(
    graph: Graph,
    correlations: list[Correlation],
    reliability: dict[str, float] | None = None,
    *,
    source_reliability: Mapping[str, float] | None = None,
    now: _dt.datetime | None = None,
    coverage: Mapping[str, Any] | None = None,
    registry: Any = None,
) -> dict[str, Any]:
    """Risk of a case graph (model 'v3lum.risk/2'; see the module docstring for every rule).

    ``reliability``: v1 ``{module: weight}`` (``Store.reliability()``); ``source_reliability``:
    ``{source_id: weight}`` (``Store.source_reliability()``, replaces the Admiralty prior of those
    sources); ``now``: the reference time of the decay (UTC now when None; the engine passes
    ``runtime.now()``); ``coverage``: ``{'coverage': case.coverage, 'answered': case.answered}`` (a
    case dict works too) - licence-disabled sources and the ``inconclusive`` seeds come from it;
    without it nothing is inconclusive. ``registry``: a ``providers.ProviderRegistry`` (default: the
    loaded registry).

    Returns ``{score, level, entities, top, contributors, label, inconclusive, reading, no_export,
    automation, ceiling, excluded, model}``; ``entities[key]`` = ``{score, level, ceiling,
    contributors[, uplifted_by][, personal]}`` for every entity with a score above 0.
    """
    ctx = _Inputs(reliability, source_reliability, now, coverage, registry)
    corr_parts = _correlation_weights(correlations or [], ctx)
    rows: dict[str, _Row] = {}
    for key, node in graph.nodes.items():
        row = _entity_row(node, ctx)
        if row is not None:
            rows[key] = row
    _uplift(graph, rows, corr_parts)

    entities: dict[str, dict[str, Any]] = {}
    paths = _best_paths(graph)
    for key, row in rows.items():
        value = _row_score(row)
        if value <= 0:
            continue
        entry: dict[str, Any] = {
            "score": value,
            "level": level(value),
            "ceiling": _max_sev(row.ceiling, row.uplift_ceiling if row.uplift > 0 else Severity.INFO).label,
            "contributors": _row_contributors(row, paths),
        }
        if row.uplift_by is not None and row.uplift * 100 > row.base * 100 + _EPS:
            entry["uplifted_by"] = row.uplift_by.id
        if row.node.entity.type in PERSONAL_TYPES:
            entry["personal"] = True
        entities[key] = entry

    case_value, case_ceiling, contributors = _case(graph, rows, corr_parts, paths)
    auto_value, _auto_ceiling, _ = _case(graph, rows, corr_parts, paths, personal=False)
    top = sorted(entities.items(), key=lambda kv: (-kv[1]["score"], kv[0]))[:10]
    inconclusive = _inconclusive(graph, ctx)
    case_level = level(case_value)
    return {
        "score": case_value,
        "level": case_level,
        "entities": entities,
        "top": [{"entity": k, "score": v["score"], "level": v["level"], **({"personal": True} if v.get("personal") else {})} for k, v in top],
        "contributors": contributors,
        "label": SCORE_LABEL,
        "inconclusive": inconclusive,
        "reading": _reading(case_level, inconclusive),
        "no_export": sorted(k for k in entities if graph.nodes[k].entity.type in PERSONAL_TYPES),
        "automation": {"score": auto_value, "level": level(auto_value), "basis": AUTOMATION_BASIS},
        "ceiling": case_ceiling.label if case_value > 0 else Severity.INFO.label,
        "excluded": dict(sorted(ctx.excluded.items())),
        "model": MODEL,
    }


def _reading(case_level: str, inconclusive: list[str]) -> str:
    """The case reading: the level; at the lowest level 'inconclusive' when a seed is (P302 cond 6)."""
    return INCONCLUSIVE if case_level == NO_FINDINGS and inconclusive else case_level


# ---------------------------------------------------------------------------- per finding


def _entity_row(node: Node, ctx: _Inputs) -> _Row | None:
    parts: list[_Part] = []
    seen: set[str] = set()
    for f in node.findings:
        fid = f.id or f.ensure_id()
        if fid in seen:
            continue
        seen.add(fid)
        part = _finding_part(f, node, ctx)
        if part is not None and part.weight > 0:
            parts.append(part)
    if not parts:
        return None
    bests = _family_bests(parts, ctx)
    ceiling = max((p.severity for p in bests), default=Severity.INFO, key=int)
    base = _noisy_or(p.weight for p in bests)
    base = min(base, SEVERITY_CAP[ceiling] / 100.0)
    return _Row(node=node, parts=bests, base=base, ceiling=ceiling)


def _finding_part(f: Finding, node: Node, ctx: _Inputs) -> _Part | None:
    tags = set(f.tags or ())
    override = f.override if isinstance(f.override, dict) else None
    if override and str(override.get("verdict") or "").strip().lower() in REJECT_VERDICTS:
        ctx.excluded["analyst_rejected"] += 1
        return None
    if CONTEXT_ONLY in tags:
        ctx.excluded["context_only"] += 1
        return None
    if KNOWN_GOOD in tags:
        ctx.excluded["known_good"] += 1
        return None
    if node.noise and not override:
        ctx.excluded["noise"] += 1
        return None
    severity = f.severity
    if W_SEV.get(severity, 0.0) <= 0:
        return None
    sids, rel, families, source = _source_of(f, ctx)
    if _licence_blocked(f, node, sids, ctx):
        ctx.excluded["licence"] += 1
        return None
    label = f.label
    notes: list[str] = []
    warninglisted = any(s.get("rule") == WARNINGLIST_RULE and not s.get("blocked_by") for s in f.suppressed_by if isinstance(s, dict))
    if warninglisted and not override and label.rank > Confidence.POSSIBLE.rank:
        label = Confidence.POSSIBLE
    if warninglisted and not override:
        notes.append("on warninglist")
    klass = decay_class(f, node.entity.type)
    age = age_days(f.observed_last, ctx.now)
    tau = TAU_DAYS.get(klass) if klass else None
    factor = decay(age, tau) if klass else 1.0
    if age is None:
        age_label = "age unknown"
    elif klass is None or tau is None:
        age_label = f"{_days(age)}, no decay"
    else:
        age_label = f"{_days(age)}, decay {factor:.2f}"
    crit = A_CRIT.get(str(node.criticality or "").strip().lower(), A_CRIT_DEFAULT)
    weight = W_SEV[severity] / 10.0 * label.weight * rel * factor * crit
    return _Part(
        finding=f, node=node, weight=max(0.0, weight), severity=severity, label=label, reliability=rel, decay=factor,
        age=age_label, crit=crit, family=tag_family(f), upstreams=families, source=source, notes=notes,
        warninglisted=warninglisted and not override,
    )


def _source_of(f: Finding, ctx: _Inputs) -> tuple[tuple[str, ...], float, frozenset[str], str]:
    """(registry source ids, R_src, upstream families, label) of a finding."""
    reg = ctx.registry
    raw = str(f.source or "").strip()
    sids: tuple[str, ...] = ()
    if raw:
        src = _lookup_source(reg, raw)
        if src is None and "." not in raw:
            provider = ctx.module_provider(f.module)
            if provider:
                src = _lookup_source(reg, f"{provider}.{raw}")
        if src is not None:
            sids = (src.id,)
        elif "." in raw and reg is not None and reg.get(raw.split(".", 1)[0]) is not None:
            sids = (raw,)  # a source of a registered provider the registry does not list: the provider's grade
    if not sids:
        sids = ctx.module_sources(f.module)  # free-text or missing source: the module's declared sources
    if not sids:
        rel = LOCAL_RELIABILITY * _v1_module_weight(f.module, ctx)
        return (), rel, frozenset({f"{LOCAL_FAMILY_PREFIX}{f.module or '?'}"}), f.module
    weights = []
    for sid in sids:
        provider = reg.get(sid.split(".", 1)[0]) if reg is not None else None
        prior = float(provider.reliability.weight) if provider is not None else UNKNOWN_SOURCE_RELIABILITY
        voted = _number(ctx.source_reliability.get(sid)) if ctx.source_reliability is not None else None
        # the feedback weight replaces the prior; an unreadable one (NaN, text) is ignored, never a penalty
        weights.append(_clamp(voted, RELIABILITY_FLOOR, 1.0) if voted is not None else prior)
    rel = min(weights)
    if ctx.source_reliability is None:
        rel *= _v1_module_weight(f.module, ctx)  # a v1 caller: the module view weighs every finding
    label = sids[0] if len(sids) == 1 else (f.module or sids[0])
    return sids, rel, upstream_families(sids, reg), label


def _v1_module_weight(module: str, ctx: _Inputs) -> float:
    """The v1 per-module weight (floor 0.3); 1.0 when absent or unreadable (NaN, text)."""
    value = _number(ctx.reliability.get(module)) if module in ctx.reliability else None
    return _clamp(value, RELIABILITY_FLOOR, 1.0) if value is not None else 1.0


def _licence_blocked(f: Finding, node: Node, sids: tuple[str, ...], ctx: _Inputs) -> bool:
    """Was the finding's source (or the module run on this entity) skipped by the licence profile?"""
    row = ctx.coverage.get(f.module) if f.module else None
    if not isinstance(row, Mapping):
        return False
    ents = row.get("entities")
    if isinstance(ents, Mapping):
        for key in _keys_of(node.entity):
            ent = ents.get(key)
            if isinstance(ent, Mapping) and str(ent.get("reason_code") or "") == "licence":
                return True
    rows = row.get("sources")
    if not isinstance(rows, Mapping) or not sids:
        return False

    def blocked(sid: str) -> bool:
        for key in {sid, sid.split(".", 1)[-1]}:
            r = rows.get(key)
            if isinstance(r, Mapping) and str(r.get("reason_code") or "") == "licence":
                return True
        return False

    return all(blocked(s) for s in sids)


# ---------------------------------------------------------------------------- per entity


def _family_bests(parts: list[_Part], ctx: _Inputs) -> list[_Part]:
    """One contribution per tag family: the strongest of each group of overlapping upstream
    families, raised one confidence level when >= 2 independent groups report the family."""
    by_family: dict[str, list[_Part]] = {}
    for p in parts:
        by_family.setdefault(p.family, []).append(p)
    out: list[_Part] = []
    for family in sorted(by_family):
        groups = _independent_groups(by_family[family])
        bests = [max(g, key=_Part.rank) for g in groups]
        best = max(bests, key=_Part.rank)
        # only groups backed by a registry upstream family are independent sources: offline analyses
        # of facts already collected (modules without registry sources, family 'module:<name>') are
        # derived, never a second source (P171)
        independent = sum(1 for g in groups if any(not fam.startswith(LOCAL_FAMILY_PREFIX) for p in g for fam in p.upstreams))
        if independent >= 2:
            best = _corroborate(best, independent)
        out.append(best)
    return out


def _independent_groups(parts: list[_Part]) -> list[list[_Part]]:
    """Union-find over the parts: two parts are dependent when their upstream families overlap."""
    parent = list(range(len(parts)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}
    for i, p in enumerate(parts):
        for fam in sorted(p.upstreams):
            if fam in owner:
                a, b = find(i), find(owner[fam])
                if a != b:
                    parent[max(a, b)] = min(a, b)
            else:
                owner[fam] = i
    groups: dict[int, list[_Part]] = {}
    for i, p in enumerate(parts):
        groups.setdefault(find(i), []).append(p)
    return [groups[k] for k in sorted(groups)]


def _corroborate(best: _Part, independent: int) -> _Part:
    """'+1 confidence level' for a family seen by >= 2 independent upstream families (P302 cond 4,
    P171): never for an analyst decision, an already upgraded finding or a warninglisted one."""
    f = best.finding
    note = f"seen by {independent} independent sources"
    if f.override or f.upgraded_by or best.warninglisted or best.label is Confidence.CONFIRMED:
        return dataclasses.replace(best, corroboration=independent, notes=[*best.notes, note])
    new = best.label.higher()
    weight = best.weight / best.label.weight * new.weight if best.label.weight > 0 else best.weight
    return dataclasses.replace(best, label=new, weight=weight, corroboration=independent, notes=[*best.notes, note + " (+1 confidence level)"])


def _correlation_weights(correlations: Iterable[Correlation], ctx: _Inputs) -> list[tuple[Correlation, float]]:
    out: list[tuple[Correlation, float]] = []
    for c in correlations:
        if not isinstance(c, Correlation):
            continue
        if CONTEXT_ONLY in (c.tags or ()):
            ctx.excluded["context_only"] += 1
            continue
        w = W_SEV.get(c.severity, 0.0) / 10.0 * c.label.weight
        if w > 0:
            out.append((c, min(MAX_WEIGHT, w)))
    return out


def _uplift(graph: Graph, rows: dict[str, _Row], corr_parts: list[tuple[Correlation, float]]) -> None:
    """Correlations uplift the entities they name (max, never a noisy-OR term); protected entities
    only when the correlation cites one of their own findings."""
    for corr, w in corr_parts:
        cited = {str(e) for e in corr.evidence or ()}
        for key in dict.fromkeys(corr.entity_keys()):
            node = graph.nodes.get(key)
            if node is None or node.noise:
                continue
            own_ids = {f.id for f in node.findings if f.id}
            if _protected(node) and not (cited & own_ids):
                continue
            row = rows.get(key)
            if row is None:
                row = rows[key] = _Row(node=node, parts=[], base=0.0, ceiling=Severity.INFO)
            if w > row.uplift + _EPS or (abs(w - row.uplift) <= _EPS and int(corr.severity) > int(row.uplift_ceiling)):
                row.uplift = w
                row.uplift_by = corr
            row.uplift_ceiling = _max_sev(row.uplift_ceiling, corr.severity)


def _row_score(row: _Row) -> float:
    ceiling = _max_sev(row.ceiling, row.uplift_ceiling if row.uplift > 0 else Severity.INFO)
    value = max(row.base, row.uplift)
    return round(min(value * 100.0, SEVERITY_CAP[ceiling], 100.0), 1)


def _protected(node: Node) -> bool:
    """Own assets and known-good/verified entities (P302 cond 5)."""
    if node.ownership == "own_asset" or (node.tags & PROTECTED_TAGS):
        return True
    if any(PROTECTED_TAGS.intersection(f.tags or ()) for f in node.findings):
        return True
    for name in PROTECTED_ATTRIBUTES:
        try:
            if node.attr(name):
                return True
        except Exception:  # noqa: BLE001 - odd attribute shapes never break scoring
            continue
    if node.entity.type is EntityType.DOMAIN:
        value = str(node.entity.value or "").lower().rstrip(".")
        if value == "gov.br" or value.endswith(".gov.br"):
            return True
    return False


# ---------------------------------------------------------------------------- per case


def _case(graph: Graph, rows: dict[str, _Row], corr_parts: list[tuple[Correlation, float]],
          paths: dict[str, list[dict[str, str]]], *, personal: bool = True) -> tuple[float, Severity, list[dict[str, Any]]]:
    """(case score, case ceiling, top-3 contributors). ``personal=False`` is the automation view
    (P302 cond 10): PERSONAL_TYPES entities and correlations naming one are left out."""
    direct = _direct_nodes(graph)
    terms: list[float] = []
    ceiling = Severity.INFO
    candidates: list[tuple[float, int, str, dict[str, Any]]] = []
    pivots: list[tuple[float, str, _Row, bool, float]] = []
    if not personal:
        rows = {k: r for k, r in rows.items() if r.node.entity.type not in PERSONAL_TYPES}
        corr_parts = [(c, w) for c, w in corr_parts if not _names_personal(graph, c)]
    for key, row in rows.items():
        if row.base <= 0:
            continue
        if row.node.seed:
            terms.append(row.base)
            ceiling = _max_sev(ceiling, row.ceiling)
            for p in row.parts:
                candidates.append(_candidate(p, p.weight, paths))
            continue
        factor = _clamp(row.node.path_confidence, 0.0, 1.0)
        shared = key not in direct
        transferred = row.base * factor
        if shared:
            transferred = min(transferred, SHARED_TRANSFER_CAP)
        if transferred > 0:
            pivots.append((transferred, key, row, shared, factor))
    pivots.sort(key=lambda t: (-t[0], t[1]))
    for transferred, _key, row, shared, factor in pivots[:TOP_PIVOTS]:
        terms.append(transferred)
        ceiling = _max_sev(ceiling, Severity.LOW if shared and int(row.ceiling) > int(Severity.LOW) else row.ceiling)
        for p in row.parts:
            w = p.weight * factor
            if shared:
                w = min(w, SHARED_TRANSFER_CAP)
            candidates.append(_candidate(p, w, paths, shared=shared))
    value = _noisy_or(terms)
    for corr, w in corr_parts:
        value = max(value, w)
        ceiling = _max_sev(ceiling, corr.severity)
        if not _is_identity_link(corr.tags, corr.label, corr.rule):
            candidates.append((w, int(corr.severity), "~" + corr.id, _corr_contributor(corr, w)))
    case_value = round(min(value * 100.0, SEVERITY_CAP[ceiling], 100.0), 1) if value > 0 else 0.0
    candidates = [c for c in candidates if c[3]]
    candidates.sort(key=lambda c: (-c[0], -c[1], c[2]))
    return case_value, ceiling, [c[3] for c in candidates[:TOP_CONTRIBUTORS]]


def _names_personal(graph: Graph, corr: Correlation) -> bool:
    """Does the correlation name a PERSONAL_TYPES entity (its severity rests partly on a person)?"""
    for key in corr.entity_keys():
        node = graph.nodes.get(key)
        etype = node.entity.type if node is not None else _etype(str(key).split(":", 1)[0])
        if etype is None or etype in PERSONAL_TYPES:  # an unreadable key is treated as personal (fail closed)
            return True
    return False


def _candidate(p: _Part, w: float, paths: dict[str, list[dict[str, str]]], *, shared: bool = False) -> tuple[float, int, str, dict[str, Any]]:
    if _is_identity_link(p.finding.tags, p.label, ""):
        return (-1.0, 0, p.finding.id, {})  # POSSIBLE identity links never reach the first screen (P258 cond 12)
    return (w, int(p.severity), p.finding.id, _contributor(p, w, paths, shared=shared))


def _contributor(p: _Part, w: float, paths: dict[str, list[dict[str, str]]], *, shared: bool = False) -> dict[str, Any]:
    f = p.finding
    notes = list(p.notes)
    if shared:
        notes.append("shared infrastructure: capped at low")
    if p.crit != A_CRIT_DEFAULT:
        notes.append(f"asset criticality {p.node.criticality}")
    extra = "".join(f", {n}" for n in notes)
    words = f"{_who(p.node.entity)}: {_clip(f.title, 100)} ({p.severity.label}, {p.age}{extra})"
    return {
        "finding_id": f.id,
        "entity": p.node.key,
        "path": list(paths.get(p.node.key, [])),
        "confidence_label": p.label.value,
        "weight": round(w, 4),
        "words": words,
        "severity": p.severity.label,
        "source": p.source,
        "age": p.age,
    }


def _corr_contributor(corr: Correlation, w: float) -> dict[str, Any]:
    keys = corr.entity_keys()
    return {
        "finding_id": "",
        "correlation_id": corr.id,
        "rule": corr.rule,
        "entity": keys[0] if keys else "",
        "path": [],
        "confidence_label": corr.label.value,
        "weight": round(w, 4),
        "words": f"correlation {corr.rule}: {_clip(corr.title, 100)} ({corr.severity.label})",
        "severity": corr.severity.label,
    }


def _row_contributors(row: _Row, paths: dict[str, list[dict[str, str]]]) -> list[dict[str, Any]]:
    cands = [_candidate(p, p.weight, paths) for p in row.parts]
    if row.uplift_by is not None and row.uplift > 0 and not _is_identity_link(row.uplift_by.tags, row.uplift_by.label, row.uplift_by.rule):
        cands.append((row.uplift, int(row.uplift_by.severity), "~" + row.uplift_by.id, _corr_contributor(row.uplift_by, row.uplift)))
    cands = [c for c in cands if c[3]]
    cands.sort(key=lambda c: (-c[0], -c[1], c[2]))
    return [c[3] for c in cands[:TOP_CONTRIBUTORS]]


def _inconclusive(graph: Graph, ctx: _Inputs) -> list[str]:
    """Seeds with fewer than 2 reputation-capable answers (P302 cond 6); [] without coverage."""
    if not ctx.answered:
        return []
    out: list[str] = []
    for node in graph.seeds():
        row = None
        for key in _keys_of(node.entity):
            candidate = ctx.answered.get(key)
            if isinstance(candidate, Mapping):
                row = candidate
                break
        try:
            answered = int((row or {}).get("reputation_answered") or 0)
        except (TypeError, ValueError):
            answered = 0
        if answered < MIN_REPUTATION_ANSWERS:
            out.append(node.key)
    return sorted(out)


# ---------------------------------------------------------------------------- graph walks


def _adjacency(graph: Graph) -> dict[str, list[Edge]]:
    adj: dict[str, list[Edge]] = {}
    for e in graph.edges:
        adj.setdefault(e.src, []).append(e)
    return adj


def _direct_nodes(graph: Graph) -> set[str]:
    """Nodes reachable from a seed without a shared-infrastructure relation or a noise node."""
    adj = _adjacency(graph)
    seeds = [n.key for n in graph.seeds()]
    direct = set(seeds)
    work = list(seeds)
    while work:
        key = work.pop()
        node = graph.nodes.get(key)
        if node is None or (node.noise and not node.seed):
            continue
        for e in adj.get(key, ()):
            if e.relation in SHARED_RELATIONS or e.dst in direct:
                continue
            target = graph.nodes.get(e.dst)
            if target is None:
                continue
            direct.add(e.dst)
            if not target.noise:
                work.append(e.dst)
    return direct


def _best_paths(graph: Graph) -> dict[str, list[dict[str, str]]]:
    """Per node, the hops of its most confident path from a seed ({from, relation, to}); [] for seeds."""
    adj = _adjacency(graph)
    best: dict[str, float] = {}
    parent: dict[str, Edge] = {}
    heap: list[tuple[float, str]] = []
    for node in graph.seeds():
        best[node.key] = 1.0
        heap.append((-1.0, node.key))
    heapq.heapify(heap)
    while heap:
        negc, key = heapq.heappop(heap)
        conf = -negc
        if conf + _EPS < best.get(key, 0.0):
            continue
        for e in adj.get(key, ()):
            dst = e.dst
            if dst not in graph.nodes or graph.nodes[dst].seed:
                continue
            cand = conf * _clamp(e.confidence, 0.0, 1.0)
            if cand > best.get(dst, 0.0) + _EPS:
                best[dst] = cand
                parent[dst] = e
                heapq.heappush(heap, (-cand, dst))
    out: dict[str, list[dict[str, str]]] = {}
    for key in graph.nodes:
        hops: list[dict[str, str]] = []
        current, seen = key, {key}
        while current in parent and len(hops) < 64:
            e = parent[current]
            hops.append({"from": e.src, "relation": e.relation, "to": e.dst})
            current = e.src
            if current in seen:
                break
            seen.add(current)
        out[key] = list(reversed(hops))
    return out


# ---------------------------------------------------------------------------- helpers


def _noisy_or(weights: Iterable[float]) -> float:
    """``1 - prod(1 - w)`` with each w clamped to [0, 0.99] (0..1)."""
    acc = 1.0
    for w in weights:
        acc *= 1.0 - _clamp(w, 0.0, MAX_WEIGHT)
    return 1.0 - acc


def _max_sev(a: Severity, b: Severity) -> Severity:
    return a if int(a) >= int(b) else b


def _number(value: Any) -> float | None:
    """A finite float, or None (None, booleans, text, NaN, infinities)."""
    if value is None or isinstance(value, bool):
        return None
    try:
        num = float(value)
    except (TypeError, ValueError):
        return None
    return num if num == num and num not in (float("inf"), float("-inf")) else None


def _clamp(value: Any, lo: float, hi: float) -> float:
    try:
        num = float(value)
    except (TypeError, ValueError):
        return lo
    if num != num:  # NaN
        return lo
    return max(lo, min(hi, num))


def _days(age: float) -> str:
    days = int(max(0.0, age))
    return "observed today" if days == 0 else f"{days} day{'s' if days != 1 else ''} old"


def _clip(text: Any, limit: int) -> str:
    value = re.sub(r"\s+", " ", str(text or "")).strip()
    return value if len(value) <= limit else value[: max(0, limit - 3)].rstrip() + "..."


def _who(entity: Entity) -> str:
    """The entity in contributor words: masked (CPF, VIN, secrets) and defanged for hosts and URLs."""
    if entity.type in SECRET_TYPES:
        return f"{entity.type.value} (secret)"
    try:
        shown = entity.display
    except Exception:  # noqa: BLE001
        shown = entity.type.value
    if entity.type in _DEFANG_TYPES:
        try:
            shown = _entities.defang(shown)
        except Exception:  # noqa: BLE001
            pass
    return _clip(shown, 60)


def _is_identity_link(tags: Iterable[str], label: Confidence, rule: str) -> bool:
    identity = "identity" in set(tags or ()) or str(rule or "").strip().lower() in _IDENTITY_RULES
    return identity and label is Confidence.POSSIBLE


def _keys_of(entity: Entity) -> tuple[str, ...]:
    """The entity key and its persisted form (SECRET_TYPES values are redacted in stored cases)."""
    keys = [entity.key]
    if entity.type in SECRET_TYPES:
        try:
            keys.append(f"{entity.type.value}:{_entities.redacted_value(entity.type, entity.value)}")
        except Exception:  # noqa: BLE001
            pass
    return tuple(dict.fromkeys(keys))


def _coverage_parts(coverage: Any) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    """(coverage per module, answered per seed) from the ``coverage`` argument."""
    if not isinstance(coverage, Mapping):
        return {}, {}
    cov, ans = coverage.get("coverage"), coverage.get("answered")
    if cov is None and ans is None:
        values = [v for v in coverage.values() if isinstance(v, Mapping)]
        if values and all(("reputation_answered" in v or "applicable" in v) for v in values):
            return {}, coverage  # a bare answered map
        return coverage, {}  # a bare coverage map
    return (cov if isinstance(cov, Mapping) else {}), (ans if isinstance(ans, Mapping) else {})


def _tags_of(finding: Any) -> list[str]:
    raw = finding.get("tags") if isinstance(finding, Mapping) else getattr(finding, "tags", None)
    return [str(t) for t in raw or () if t]


def _etype(value: Any) -> EntityType | None:
    if isinstance(value, EntityType):
        return value
    try:
        return EntityType.parse(str(value))
    except (ValueError, AttributeError):
        return None


def _finding_etype(finding: Any) -> EntityType | None:
    if isinstance(finding, Mapping):
        key = str(finding.get("entity") or "")
        return _etype(key.split(":", 1)[0]) if ":" in key else None
    entity = getattr(finding, "entity", None)
    return entity.type if isinstance(entity, Entity) else None


def _aware(value: _dt.datetime) -> _dt.datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=_dt.timezone.utc)


def _parse_time(value: Any) -> _dt.datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, _dt.datetime):
        return _aware(value)
    if isinstance(value, _dt.date):
        return _dt.datetime(value.year, value.month, value.day, tzinfo=_dt.timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d{4}", text):
        text += "-01-01"
    elif re.fullmatch(r"\d{4}-\d{2}", text):
        text += "-01"
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            day = _dt.date.fromisoformat(text)
            return _dt.datetime(day.year, day.month, day.day, tzinfo=_dt.timezone.utc)
        return _aware(_dt.datetime.fromisoformat(text))
    except ValueError:
        return None


def _registry() -> Any:
    try:
        return _providers.registry()
    except Exception:  # noqa: BLE001 - a broken registry never breaks scoring (sources read as unknown)
        return None


def _lookup_source(reg: Any, sid: str) -> Any:
    if reg is None or not sid:
        return None
    try:
        return reg.source(sid)
    except Exception:  # noqa: BLE001
        return None


def _module_registry() -> Mapping[str, Any]:
    try:
        from v3lum.core.module import REGISTRY  # lazy: module.py imports the engine-side packages

        return REGISTRY
    except Exception:  # noqa: BLE001
        return {}
