"""First-screen honesty (AR14): pure functions over a stored case dict, shared by every renderer.

The terminal (``ui/render.py``) uses them now; the HTML and Markdown writers use the same functions
from wave 4 (WP20), so every medium says the same thing. Each function reads a case dict - the v2
shape written by ``CaseResult.to_dict()`` (schema ``'v3lum.case/2'``) or a stored v1 case (no
``answered``/``skips``/``tlp``/``hosts``) - and never mutates it. Returned strings are plain text with
control characters removed (``ui.safe.clean_text``) and **no** markup escaping: each medium escapes
for itself (``ui.safe.safe_text`` for rich markup, HTML/Markdown escaping in the writers).

* :func:`header_lines` / :func:`header_items` - the header: TLP label, mode and egress, the
  engagement banner of LIGHT/ACTIVE cases, partial-result notes (deadline, entity budget,
  cancellation, end of the scope window), per seed 'N of M applicable sources answered; K could not
  verify' with the could-not-verify list and the seed reading (P328 cond 7), 'value disclosed to N
  third-party providers' (A8), the licence banner (research profile, or noncommercial/license
  sources used under an allow-list entry: A1, P377 cond 4), purpose/ticket/legal basis (AR16) and
  every string of ``case['meta']['header_notes']`` (extension point for later waves).
* :func:`bottom_line` - three lines (AR14): what the input is (type plus 2-3 key facts), why the
  reading (``risk['contributors']`` when the risk model v2 recorded them, else the top risky
  entities, with confidence labels; scores are a 'triage aid, not a conclusion', P302 cond 9) and
  what to do next (the highest recommendation).
* :func:`skip_lines` - one line per reason code of ``case['skips']`` ('N sources skipped: licence
  profile corporate - v3lum doctor --licences', 'N opt-in sources not run (use --preset deep)',
  ...), then ``case['meta']['quota_lines']`` (P334 cond 7).
* :func:`seed_level` / :func:`case_level` - the reading: 'inconclusive' when fewer than
  :data:`MIN_REPUTATION_ANSWERS` reputation sources (modules tagged ``reputation``) answered ok/empty
  for a seed (P302 cond 6, P328 cond 7), else the risk level with 'no findings' replacing 'clean'.
  No function of this module ever returns the word 'clean'.
* :func:`disclosure_summary` / :func:`disclosure_by_entity` - the disclosure ledger from the hosts the
  runs actually contacted (``case['modules'][*]['hosts']``, cached responses excluded, DoH resolvers
  included) and the provider registry (A8).
* :func:`licence_lines` - coverage lost under the licence profile, per entity type (A1, P377 cond 8).
* :func:`followup_lines`, :func:`note_lines`, :func:`partial_notes`, :func:`level_label`,
  :func:`tlp_value`, :func:`tlp_label` - small helpers the renderers share.

Reports v2 (WP20) add, for the HTML, Markdown and pivot-page writers and the terminal:
:func:`tlp_description` (TLP 2.0 banner text), :func:`shareable_view` (cross-case and internal
references omitted at TLP:CLEAR/GREEN, A2), :func:`report_notices` (personal data under LGPD,
unmasked view, the P146 LGPD art. 20 breach notice), :func:`tls_interception_line` (P329),
:func:`sighting_lines` (internal sightings, case DB first: P375 cond 6, A12), :func:`contributor_lines`
and :func:`score_text` (P302 cond 9/10), :func:`finding_rows` (P335 grouped rows), :func:`is_own_asset`
(A11), :func:`breach_facts` / :func:`password_words` (P145 cond 9), :func:`engagement_block` /
:func:`engagement_banner` (A7), :func:`pivot_plan` / :func:`reference_view` (P311, P336 cond 2-3),
:func:`appendix_licence`, :func:`appendix_disclosure` and :func:`attributions` (A1, A8, P336 cond 6)
and the content hash note (P336 cond 4). The header gains the kinds ``tls``, ``sightings`` and
``since`` (the since-last-run line when the audit hook did not add it as a header note).
"""

from __future__ import annotations

import functools
import hashlib
import inspect
import json
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from v3lum.core import tlp as _tlp
from v3lum.core.entities import EntityType
from v3lum.ui.safe import DEFANG_TAGS, clean_text, display_text, entity_display

__all__ = [
    "ATTACK_ATTRIBUTION",
    "BREACH_NOTICE",
    "BREACH_RULES",
    "BREACH_TAGS",
    "CONFIDENCE_LABELS",
    "CONTENT_END_MARKER",
    "CaseIndex",
    "FindingRow",
    "HEADER_LABELS",
    "INCONCLUSIVE",
    "LEVEL_ORDER",
    "MIN_REPUTATION_ANSWERS",
    "NO_FINDINGS",
    "PERSONAL_DATA_NOTICE",
    "PROVIDER_ATTRIBUTIONS",
    "PivotEntity",
    "PivotItem",
    "PivotPlan",
    "REFERENCE_HOSTS",
    "SCORE_LABEL",
    "SHOW_PERSONAL_NOTICE",
    "TLP_DESCRIPTIONS",
    "appendix_disclosure",
    "appendix_licence",
    "attention",
    "attributions",
    "bottom_line",
    "case_values",
    "breach_facts",
    "breach_rules_fired",
    "case_level",
    "confidence_label",
    "contains_personal_data",
    "content_hash",
    "content_hash_note",
    "contributor_lines",
    "defang_urls_in_text",
    "disclosure_by_entity",
    "disclosure_summary",
    "engagement_banner",
    "engagement_block",
    "engagement_details",
    "entity_host",
    "finding_rows",
    "followup_lines",
    "header_items",
    "header_lines",
    "is_identity_link",
    "is_own_asset",
    "is_partial_note",
    "level_label",
    "licence_lines",
    "link_host",
    "merged_links",
    "note_lines",
    "override_text",
    "partial_notes",
    "password_words",
    "pivot_plan",
    "reference_view",
    "report_notices",
    "score_text",
    "seed_inconclusive",
    "seed_level",
    "shareable_view",
    "sighting_lines",
    "skip_lines",
    "target_hosts",
    "tls_interception_line",
    "tlp_color",
    "tlp_description",
    "tlp_label",
    "tlp_value",
]

#: The lowest risk level, renamed from 'clean' (P302 cond 6, AR14).
NO_FINDINGS = "no findings"
#: The reading of a seed (or of a case at the lowest level) with too little reputation coverage.
INCONCLUSIVE = "inconclusive"
#: Reputation-capable sources that must answer ok/empty before a seed reads anything but inconclusive.
MIN_REPUTATION_ANSWERS = 2
#: Label of every score (P302 cond 9).
SCORE_LABEL = "triage aid, not a conclusion"
#: Risk levels from the lowest; v1 cases call the lowest 'clean'.
LEVEL_ORDER: tuple[str, ...] = (NO_FINDINGS, "low", "medium", "high", "critical")
#: Confidence labels (P322) from the strongest.
CONFIDENCE_LABELS: tuple[str, ...] = ("confirmed", "probable", "possible")

_LOWEST = frozenset({"", "clean", "none", "no findings", "no_findings"})
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_CONF_RANK = {"confirmed": 2, "probable": 1, "possible": 0}
_TERMS_LICENSED = ("noncommercial", "license")
#: Statuses that mean 'could not verify' (rule 5), never 'absent'.
_CNV_STATUSES = frozenset({"quota", "rate_limited", "blocked", "error", "needs_key", "unavailable"})
#: Correlation rules that link identities (P258 CR34): POSSIBLE ones stay out of the first screen.
_IDENTITY_RULES = frozenset({"identity_link_strength", "cr34"})
#: Notes about a partial result (they go to the header, not to the closing notes; AR14).
_PARTIAL_MARKERS = ("partial result", "entity budget reached", "interrupted")
#: The wave-2 engine note ends with a clause naming the v1 level; the first screen never prints it.
_CLEAN_CLAUSE = re.compile(r"\s*-\s*a 'clean' risk level is not a verdict\s*$", re.I)

#: Key facts of the 'what it is' line, per entity type (first ones win; personal facts excluded).
_HASH_TYPES = (EntityType.MD5, EntityType.SHA1, EntityType.SHA256, EntityType.SHA512, EntityType.SSDEEP, EntityType.IMPHASH, EntityType.TLSH)
_FACTS: dict[EntityType, tuple[str, ...]] = {
    EntityType.DOMAIN: ("registrar", "created", "domain_age_days", "a_records", "mx", "nameservers", "dmarc_policy", "is_parked", "is_sinkhole"),
    EntityType.URL: ("http_status", "title", "server", "technologies", "waf"),
    EntityType.IPV4: ("asn", "as_org", "country", "isp", "rdns", "open_ports", "is_tor_exit", "is_hosting", "is_cdn"),
    EntityType.IPV6: ("asn", "as_org", "country", "isp", "rdns", "open_ports", "is_hosting", "is_cdn"),
    EntityType.CIDR: ("asn", "as_org", "country", "prefix"),
    EntityType.ASN: ("as_org", "country", "prefix"),
    EntityType.EMAIL: ("generic_address", "mx_valid", "disposable", "free_provider", "breach_count"),
    EntityType.CVE: ("cvss", "epss", "kev", "exploit_available"),
    EntityType.CNPJ: ("legal_name", "status", "opened", "cnae"),
    EntityType.PHONE: ("carrier", "line_type", "country"),
    EntityType.BTC: ("balance", "tx_count", "sanctioned"),
    EntityType.ETH: ("balance", "tx_count", "sanctioned"),
    EntityType.XMR: ("sanctioned",),
    EntityType.CRYPTO: ("balance", "tx_count", "sanctioned"),
    **{t: ("malware_family", "file_type", "known_good", "first_seen") for t in _HASH_TYPES},
}
_DEFAULT_FACTS = ("country", "org", "first_seen", "last_seen", "created", "malicious", "suspicious", "status")
_EXTRACT_TYPES = frozenset({EntityType.TEXT, EntityType.FILE, EntityType.EMAIL_HEADERS})

#: skip_lines order (most actionable first) and wording per canonical reason code.
_SKIP_ORDER = (
    "licence", "not_default", "needs_key", "own_asset", "privacy", "tlp", "tier", "quota", "rate_limited", "deadline",
    "opsec", "authorization", "scope", "egress_country", "hostile_host", "circuit", "challenge", "geo_block", "login_wall",
    "policy", "config", "demoted", "package", "dataset", "offline", "timeout", "sanitizer", "error", "not_applicable",
)


# ======================================================================================
# small helpers
# ======================================================================================


def _d(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


def _plural(n: int, word: str, plural: str | None = None) -> str:
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def _verb(n: int, plural_form: str) -> str:
    """'need' -> 'needs' for one subject ('1 source needs ...', '2 sources need ...')."""
    return plural_form + "s" if n == 1 else plural_form


def _num(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: max(0, limit - 3)].rstrip() + "..."


def level_label(level: Any) -> str:
    """The display name of a risk level: 'clean' (v1) and empty become 'no findings' (P302 cond 6);
    other levels are lower-cased with control characters removed (a stored case is untrusted).
    Never returns 'clean'."""
    text = clean_text(level if level is not None else "").strip().lower()
    return NO_FINDINGS if text in _LOWEST else _clip(text, 40)


def confidence_label(item: Mapping[str, Any]) -> str:
    """The P322 label of a finding/correlation dict ('confirmed' | 'probable' | 'possible'); stored v1
    dicts without a label map their float (>= 0.85 confirmed, >= 0.55 probable, else possible)."""
    label = str(item.get("confidence_label") or "").strip().lower()
    if label in _CONF_RANK:
        return label
    try:
        value = float(item.get("confidence", 0.8) if item.get("confidence") is not None else 0.8)
    except (TypeError, ValueError):
        value = 0.0
    return "confirmed" if value >= 0.85 else "probable" if value >= 0.55 else "possible"


def is_identity_link(item: Mapping[str, Any]) -> bool:
    """Is this finding/correlation dict a POSSIBLE identity link (P258 cond 12: shown only in the
    entity map and the HTML details, never in the terminal top findings)? Identity links carry the
    tag ``identity`` or come from the CR34 identity_link_strength rule."""
    tags = {str(t) for t in _l(item.get("tags"))}
    rule = str(item.get("rule") or "").strip().lower()
    identity = "identity" in tags or rule in _IDENTITY_RULES
    return identity and confidence_label(item) == "possible"


def tlp_value(case: Mapping[str, Any]) -> str:
    """The case TLP value ('clear' | 'green' | 'amber' | 'amber+strict' | 'red'): ``case['tlp']``, else
    the stored options' tlp, else the A2 default 'amber'; an unreadable value reads 'red' (fail closed)."""
    raw = case.get("tlp") or _d(case.get("options")).get("tlp") or ""
    if not raw:
        return "amber"
    try:
        return _tlp.parse(raw).value_str
    except ValueError:
        return "red"


def tlp_label(case: Mapping[str, Any]) -> str:
    """The marking text of the case TLP, e.g. 'TLP:AMBER+STRICT' (generated, never typed: A2)."""
    return "TLP:" + tlp_value(case).upper()


def is_partial_note(note: Any) -> bool:
    """Does a case note describe a partial result (deadline, cancellation, scope window, entity budget)?"""
    low = str(note or "").lower()
    return any(marker in low for marker in _PARTIAL_MARKERS)


class CaseIndex:
    """Read-only lookups over one case dict, shared by the summary functions and the renderers:
    ``nodes`` (entity key -> entity dict), ``findings``, ``by_id``, ``by_entity``; :meth:`tags` (node
    and finding tags plus the malicious/suspicious attributes), :meth:`hostile`, :meth:`type_value`,
    :meth:`display` (masked, defanged when hostile and for URLs, see ``ui.safe.entity_display``),
    :meth:`labelled` ('<type> <display>'), :meth:`text` (module free text, CPFs masked) and
    :meth:`attr_values`. Built per call: nothing is cached
    across cases and the case is never modified."""

    def __init__(self, case: Mapping[str, Any], *, show_personal: bool = False, no_defang: bool = False) -> None:
        self.case = case
        self.show_personal = show_personal
        self.no_defang = no_defang
        self.nodes: dict[str, dict[str, Any]] = {}
        for node in _l(case.get("entities")):
            if isinstance(node, dict) and node.get("key"):
                self.nodes[str(node["key"])] = node
        self.findings: list[dict[str, Any]] = [f for f in _l(case.get("findings")) if isinstance(f, dict)]
        self.by_id: dict[str, dict[str, Any]] = {str(f.get("id")): f for f in self.findings if f.get("id")}
        self.by_entity: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for f in self.findings:
            if f.get("entity"):
                self.by_entity[str(f["entity"])].append(f)

    def tags(self, key: str) -> set[str]:
        """Node tags plus the tags of its findings (and the malicious/suspicious attributes)."""
        node = self.nodes.get(key) or {}
        tags = {str(t) for t in _l(node.get("tags"))}
        for f in self.by_entity.get(key, ()):
            tags.update(str(t) for t in _l(f.get("tags")))
        attrs = _d(node.get("attributes"))
        for name in ("malicious", "suspicious"):
            for item in _l(attrs.get(name)):
                value = item.get("value") if isinstance(item, dict) else item
                if value is True or (isinstance(value, str) and value.strip().lower() == "true"):
                    tags.add(name)
        return tags

    def hostile(self, key: str) -> bool:
        return bool(self.tags(key) & DEFANG_TAGS)

    def type_value(self, key: str) -> tuple[str, str]:
        etype, _, value = str(key).partition(":")
        node = self.nodes.get(key)
        if node:
            etype = str(node.get("type") or etype)
            value = str(node.get("value") if node.get("value") is not None else value)
        return etype, value

    def display(self, key: str) -> str:
        etype, value = self.type_value(key)
        return entity_display(etype, value, show_personal=self.show_personal, tags=self.tags(key), no_defang=self.no_defang)

    def labelled(self, key: str) -> str:
        etype, _ = self.type_value(key)
        return f"{clean_text(etype)} {self.display(key)}"

    def text(self, value: Any) -> str:
        """Module-derived free text of this view: control characters removed and valid CPFs masked
        unless ``show_personal`` (``ui.safe.display_text``)."""
        return display_text(value, show_personal=self.show_personal)

    def attr_values(self, key: str, name: str) -> list[Any]:
        node = self.nodes.get(key) or {}
        out = []
        for item in _l(_d(node.get("attributes")).get(name)):
            out.append(item.get("value") if isinstance(item, dict) else item)
        return out


def _seeds(case: Mapping[str, Any]) -> list[str]:
    seeds = [str(s) for s in _l(case.get("seeds")) if s]
    if seeds:
        return seeds
    out = []
    for inp in _l(case.get("inputs")):
        if isinstance(inp, dict) and inp.get("type") and inp.get("value") is not None:
            out.append(f"{inp['type']}:{inp['value']}")
    return out


# ======================================================================================
# readings (P302 cond 6, P328 cond 7)
# ======================================================================================


def _answered_row(case: Mapping[str, Any], seed_key: str) -> dict[str, Any] | None:
    """``case['answered'][seed]`` (v2), else a row derived from the stored module results (v1)."""
    answered = case.get("answered")
    if isinstance(answered, dict) and isinstance(answered.get(seed_key), dict):
        return answered[seed_key]
    if isinstance(answered, dict) and answered:
        return None  # a v2 case without a row for this seed
    runs = [m for m in _l(case.get("modules")) if isinstance(m, dict) and m.get("entity") == seed_key and m.get("status") != "skipped"]
    if not runs:
        return None
    sources = [{"module": str(m.get("module") or ""), "source": "", "status": str(m.get("status") or ""), "reason_code": str(m.get("reason_code") or "")} for m in runs]
    return {
        "applicable": len(runs),
        "answered": sum(1 for s in sources if s["status"] in ("ok", "empty")),
        "could_not_verify": sum(1 for s in sources if s["status"] in _CNV_STATUSES),
        "sources": sources,
        "derived": True,
    }


def _reputation_answered(row: Mapping[str, Any] | None) -> int:
    if not row:
        return 0
    try:
        return int(row.get("reputation_answered") or 0)
    except (TypeError, ValueError):
        return 0


def seed_inconclusive(case: Mapping[str, Any], seed_key: str) -> bool:
    """True when fewer than :data:`MIN_REPUTATION_ANSWERS` reputation-capable sources answered
    ok/empty for the seed (``case['answered'][seed]['reputation_answered']``; a seed without that
    record - a stored v1 case - counts as 0), or when the risk model listed it as inconclusive."""
    if seed_key in {str(k) for k in _l(_d(case.get("risk")).get("inconclusive"))}:
        return True
    return _reputation_answered(_answered_row(case, seed_key)) < MIN_REPUTATION_ANSWERS


def _entity_level(case: Mapping[str, Any], key: str) -> str:
    row = _d(_d(_d(case.get("risk")).get("entities")).get(key))
    return level_label(row.get("level"))


def seed_level(case: Mapping[str, Any], seed_key: str) -> str:
    """'inconclusive' when :func:`seed_inconclusive`, else the seed's risk level with 'no findings'
    replacing 'clean' (a seed without a scored finding reads 'no findings'). Never 'clean'."""
    if seed_inconclusive(case, seed_key):
        return INCONCLUSIVE
    return _entity_level(case, seed_key)


def case_level(case: Mapping[str, Any]) -> str:
    """The case reading: the case risk level ('low'...'critical'); at the lowest level 'inconclusive'
    when any seed is inconclusive (or no seed is known), else 'no findings'. Never 'clean'."""
    raw = _d(case.get("risk")).get("level") or _d(case.get("summary")).get("risk_level") or ""
    if str(raw).strip().lower() == INCONCLUSIVE:
        return INCONCLUSIVE
    level = level_label(raw)
    if level != NO_FINDINGS:
        return level
    seeds = _seeds(case)
    if not seeds or any(seed_inconclusive(case, s) for s in seeds):
        return INCONCLUSIVE
    return NO_FINDINGS


def _score(case: Mapping[str, Any]) -> float:
    raw = _d(case.get("risk")).get("score")
    if raw is None:
        raw = _d(case.get("summary")).get("risk_score")
    try:
        return float(raw or 0.0)
    except (TypeError, ValueError):
        return 0.0


# ======================================================================================
# header (AR14, P328 cond 7, A1, A2, A8, AR16)
# ======================================================================================


def _options(case: Mapping[str, Any]) -> dict[str, Any]:
    return _d(case.get("options"))


def _licence_profile(case: Mapping[str, Any]) -> str:
    return clean_text(case.get("licence_profile") or _options(case).get("licence_profile") or "corporate")


def _engagement(case: Mapping[str, Any]) -> dict[str, Any]:
    """The LIGHT/ACTIVE engagement summary (``case['engagement']``, else ``case['meta']['engagement']``
    where the audit hook also records it, WP15); {} for a passive case."""
    return _d(case.get("engagement")) or _d(_d(case.get("meta")).get("engagement"))


def _egress_text(case: Mapping[str, Any], mode: str) -> str:
    engagement = _engagement(case)
    meta = _d(case.get("meta"))
    value = engagement.get("egress") or meta.get("egress") or meta.get("egress_profile")
    if isinstance(value, dict):
        name = value.get("profile") or value.get("name") or ""
        route = value.get("proxy") or value.get("label") or ""
        ip = value.get("ip") or value.get("public_ip") or ""
        parts = [str(p) for p in (name, route, f"public IP {ip}" if ip else "") if p]
        if parts:
            return clean_text(" ".join(parts))
    elif value:
        return clean_text(value)
    if mode in ("light", "active"):
        return "not recorded"
    return "default route"  # third-party API calls and DoH always leave through the default route


def _mode_line(case: Mapping[str, Any]) -> str:
    opts = _options(case)
    mode = clean_text(opts.get("mode") or "passive").lower()
    parts = [f"mode {mode}", f"egress {_egress_text(case, mode)}"]
    if opts.get("preset"):
        parts.append(f"preset {clean_text(opts['preset'])}")
    if opts.get("depth") is not None:
        parts.append(f"depth {clean_text(opts['depth'])}")
    override = opts.get("egress_override") or _engagement(case).get("egress_override")
    if override:
        parts.append(f"egress override {clean_text(override)}")
    if opts.get("offline"):
        parts.append("offline (no network)")
    if opts.get("allow_unknown"):
        parts.append("unknown-tier providers allowed (--allow-unknown)")
    if mode in ("light", "active"):
        ref = opts.get("authorization_ref") or opts.get("authorization_note") or ""
        parts.append(f"authorization {clean_text(ref)}" if ref else "authorization not recorded")
    return " · ".join(parts)


def _window_text(window: Any) -> str:
    if isinstance(window, dict):
        start = window.get("start") or window.get("window_start") or "?"
        end = window.get("end") or window.get("window_end") or "?"
        return f"{start} - {end}"
    if isinstance(window, (list, tuple)) and len(window) == 2:
        return f"{window[0]} - {window[1]}"
    return str(window or "")


def _target_text(idx: CaseIndex | None, target: Any) -> str:
    """A refused target: an entity key is shown like every entity display (masked, defanged when
    hostile); anything else as plain text."""
    text = str(target or "?")
    etype, sep, _ = text.partition(":")
    if idx is not None and sep:
        try:
            EntityType(etype)
        except ValueError:
            return text
        return idx.display(text)
    return text


def _refusal_line(idx: CaseIndex | None, r: Mapping[str, Any]) -> str:
    line = f"refused: {_target_text(idx, r.get('target'))} ({r.get('module', '?')}: {r.get('reason_code', '?')}) {r.get('reason', '')}".rstrip()
    return idx.text(line) if idx is not None else display_text(line)


def engagement_details(case: Mapping[str, Any], *, show_personal: bool = False, no_defang: bool = False) -> dict[str, Any]:
    """The full LIGHT/ACTIVE engagement record for the report body (A7: 'out-of-scope refusals list
    each target and the reason'; the header shows the first ten): ``{touched: [(target display,
    request count)], refusals: [line, ...], omitted: N}`` - every target touched with its request
    count, every recorded refusal, and the refusals the engine did not keep. Targets are displayed
    like every entity (masked, defanged when hostile). Empty lists for a passive case."""
    eng = _engagement(case)
    idx = CaseIndex(case, show_personal=show_personal, no_defang=no_defang)
    touched: list[tuple[str, int]] = []
    for target, count in sorted(_d(eng.get("targets_touched")).items(), key=lambda kv: str(kv[0])):
        touched.append((_target_text(idx, target), int(_num(count))))
    refusals = [_refusal_line(idx, r) for r in _l(eng.get("refusals")) if isinstance(r, dict)]
    try:
        omitted = max(0, int(eng.get("refusals_omitted") or 0))
    except (TypeError, ValueError):
        omitted = 0
    return {"touched": touched, "refusals": refusals, "omitted": omitted}


def _engagement_lines(case: Mapping[str, Any], idx: CaseIndex | None = None) -> list[str]:
    eng = _engagement(case)
    if not eng:
        return []
    parts = []
    if eng.get("authorization_ref"):
        parts.append(f"authorization {eng['authorization_ref']}")
    if eng.get("scope_sha256"):
        parts.append(f"scope sha256 {str(eng['scope_sha256'])[:16]}")
    if eng.get("window"):
        parts.append(f"window {_window_text(eng['window'])}")
    touched = _d(eng.get("targets_touched"))
    if touched:
        parts.append(f"targets touched {len(touched)}")
    if eng.get("request_count") is not None:
        parts.append(f"{eng['request_count']} target requests")
    lines = ["engagement: " + " · ".join(display_text(p) for p in parts)] if parts else []
    refusals = [r for r in _l(eng.get("refusals")) if isinstance(r, dict)]
    for r in refusals[:10]:
        lines.append(_refusal_line(idx, r))
    omitted = len(refusals) - 10 if len(refusals) > 10 else 0
    try:
        omitted += int(eng.get("refusals_omitted") or 0)
    except (TypeError, ValueError):
        pass
    if omitted > 0:
        lines.append(f"refused: +{omitted} more targets (see the report)")
    return lines


def partial_notes(case: Mapping[str, Any], *, show_personal: bool = False) -> list[str]:
    """The partial-result notes of a case (deadline, Ctrl+C, end of the scope window, entity budget):
    the engine's notes, plus a synthesised one for a ``case['partial']`` reason without a note (and
    for a v1 case flagged interrupted). Valid CPFs quoted in a note are masked unless
    ``show_personal``."""
    notes = [display_text(n, show_personal=show_personal) for n in _l(case.get("notes")) if is_partial_note(n)]
    joined = " ".join(notes).lower()
    partial = case.get("partial")
    reasons = [str(k) for k, v in partial.items() if v] if isinstance(partial, dict) else []
    synth = {
        "deadline": ("deadline", "scan deadline reached: partial results"),
        "cancelled": ("interrupted", "interrupted by the analyst: partial results"),
        "window": ("window", "engagement window ended: partial results"),
    }
    for reason in reasons:
        marker, text = synth.get(reason, (reason, f"{reason}: partial results"))
        if marker not in joined:
            notes.append(clean_text(text))
    if not notes and (partial is True or _d(case.get("summary")).get("interrupted")):
        notes.append("scan interrupted: partial results")
    return notes


def _cnv_label(row: Mapping[str, Any]) -> str:
    name = str(row.get("module") or "?")
    if row.get("source"):
        name += f"/{row['source']}"
    code = row.get("reason_code") or row.get("status") or "?"
    return clean_text(f"{name}: {code}")


def _answered_line(case: Mapping[str, Any], idx: CaseIndex, seed_key: str) -> str:
    who = idx.display(seed_key)
    row = _answered_row(case, seed_key)
    reading = seed_level(case, seed_key)
    if row is None:
        text = f"{who}: answered sources not recorded"
    else:
        try:
            applicable = int(row.get("applicable") or 0)
            answered = int(row.get("answered") or 0)
            cnv = int(row.get("could_not_verify") or 0)
        except (TypeError, ValueError):
            applicable = answered = cnv = 0
        if applicable <= 0:
            text = f"{who}: no applicable source answered (none ran)"
        else:
            text = f"{who}: {answered} of {applicable} applicable sources answered; {cnv} could not verify"
        failing = [s for s in _l(row.get("sources")) if isinstance(s, dict) and str(s.get("status") or "") in _CNV_STATUSES]
        if failing:
            shown = ", ".join(_cnv_label(s) for s in failing[:6])
            more = f", +{len(failing) - 6} more" if len(failing) > 6 else ""
            text += f" ({shown}{more})"
    text += f" · reading: {reading}"
    if reading == INCONCLUSIVE:
        text += f" (reputation sources answered: {_reputation_answered(row)}; at least {MIN_REPUTATION_ANSWERS} needed)"
        level = _entity_level(case, seed_key)
        if level != NO_FINDINGS:
            text += f" · highest scored level {level}"  # inconclusive never hides a scored risk
    return text


def _disclosure_line(case: Mapping[str, Any]) -> str:
    runs = [m for m in _l(case.get("modules")) if isinstance(m, dict)]
    if runs and not any("hosts" in m for m in runs):
        return "value disclosure not recorded (stored v1 case)"
    summary = disclosure_summary(case)
    providers: dict[str, str] = {}
    for host, row in summary.items():
        if row.get("third_party"):
            providers[str(row.get("provider") or host)] = str(row.get("name") or row.get("provider") or host)
    n = len(providers)
    text = f"value disclosed to {n} third-party {'provider' if n == 1 else 'providers'}"
    if providers:
        names = sorted({x.split(" (", 1)[0].strip() or x for x in providers.values()}, key=str.lower)
        shown = ", ".join(_clip(clean_text(x), 40) for x in names[:5])
        text += f": {shown}" + (f", +{len(names) - 5} more" if len(names) > 5 else "")
    return text


def _licence_banner(case: Mapping[str, Any]) -> str:
    profile = _licence_profile(case)
    used = {
        str(sid): _d(info)
        for sid, info in _d(case.get("licence_used")).items()
        if str(_d(info).get("class") or "") in _TERMS_LICENSED
    }
    if profile != "research" and not used:
        return ""
    head = "LICENCE: research profile (recorded legal basis)" if profile == "research" else f"LICENCE: licence profile {profile}"
    if used:
        items = [f"{sid} ({info.get('class')}, {info.get('basis') or 'basis not recorded'})" for sid, info in sorted(used.items())]
        return clean_text(head + " - noncommercial/license sources used: " + ", ".join(items))
    return clean_text(head + " - no noncommercial/license source was used in this run")


def _purpose_line(case: Mapping[str, Any]) -> str:
    opts = _options(case)
    parts = []
    for key, label in (("purpose", "purpose"), ("ticket", "ticket"), ("legal_basis", "legal basis")):
        value = opts.get(key)
        if value:
            parts.append(f"{label}: {clean_text(value)}")
    return " · ".join(parts)


def _answered_rest(case: Mapping[str, Any], seeds: list[str]) -> str:
    """One line for the seeds left out of a capped header: summed counts and inconclusive seeds."""
    answered = applicable = cnv = 0
    for seed in seeds:
        row = _answered_row(case, seed) or {}
        try:
            answered += int(row.get("answered") or 0)
            applicable += int(row.get("applicable") or 0)
            cnv += int(row.get("could_not_verify") or 0)
        except (TypeError, ValueError):
            continue
    inconclusive = sum(1 for seed in seeds if seed_inconclusive(case, seed))
    return (
        f"+{_plural(len(seeds), 'more input')}: {answered} of {applicable} applicable sources answered; {cnv} could not verify"
        f" · {inconclusive} inconclusive (the report lists every input)"
    )


def header_items(
    case: Mapping[str, Any], *, show_personal: bool = False, no_defang: bool = False, max_seeds: int | None = None,
) -> list[tuple[str, str]]:
    """The header as ``(kind, text)`` pairs, in order. Kinds: ``tlp``, ``mode``, ``engagement``,
    ``partial``, ``answered``, ``disclosure``, ``licence``, ``purpose``, ``note`` (renderers style by
    kind; :func:`header_lines` returns the texts). ``max_seeds`` caps the per-seed answered lines (a
    batch of inputs on the terminal): the other seeds are summed in one more ``answered`` line."""
    idx = CaseIndex(case, show_personal=show_personal, no_defang=no_defang)
    items: list[tuple[str, str]] = [("tlp", tlp_label(case)), ("mode", _mode_line(case))]
    tls = tls_interception_line(case)
    if tls:
        items.append(("tls", tls))  # P329 cond 4: one header line, not one per finding
    items += [("engagement", line) for line in _engagement_lines(case, idx)]
    items += [("partial", f"PARTIAL RESULT: {note}") for note in partial_notes(case, show_personal=show_personal)]
    seeds = _seeds(case)
    shown = seeds if max_seeds is None or max_seeds < 0 else seeds[:max_seeds]
    items += [("answered", _answered_line(case, idx, seed)) for seed in shown]
    if len(shown) < len(seeds):
        items.append(("answered", _answered_rest(case, seeds[len(shown):])))
    for seed in shown:  # P375 cond 6, A12: internal sightings in the summary, case DB first
        lines = sighting_lines(case, seed, idx=idx)
        if lines:
            items.append(("sightings", f"{idx.display(seed)}: " + "; ".join(lines)))
    items.append(("disclosure", _disclosure_line(case)))
    banner = _licence_banner(case)
    if banner:
        items.append(("licence", banner))
    purpose = idx.text(_purpose_line(case))  # analyst-typed, but a CPF in it stays masked too
    if purpose:
        items.append(("purpose", purpose))
    notes = [idx.text(note).strip() for note in _l(_d(case.get("meta")).get("header_notes"))]
    since = _since_line(case)
    if since and not any(n.lower().startswith("since last run") for n in notes):
        items.append(("since", since))  # P324 cond 8 (the audit hook normally adds it as a header note)
    for text in notes:
        if text:
            items.append(("note", text))
    return items


def _since_line(case: Mapping[str, Any]) -> str:
    """'since last run (case <id>): N new findings, M resolved' from ``case['since_last_run']`` (or
    its ``meta`` copy, WP15); '' for a first collection."""
    since = case.get("since_last_run") if isinstance(case.get("since_last_run"), dict) else _d(case.get("meta")).get("since_last_run")
    if not isinstance(since, dict):
        return ""
    try:
        from v3lum.core.audit import since_last_run_line
    except Exception:  # noqa: BLE001
        return ""
    try:
        return clean_text(since_last_run_line(since))
    except Exception:  # noqa: BLE001
        return ""


def header_lines(
    case: Mapping[str, Any], *, show_personal: bool = False, no_defang: bool = False, max_seeds: int | None = None,
) -> list[str]:
    """The header lines (AR14): TLP label, mode and egress, the LIGHT/ACTIVE engagement banner,
    partial-result notes, per seed 'N of M applicable sources answered; K could not verify' with the
    reading, 'value disclosed to N third-party providers', the licence banner, purpose/ticket/legal
    basis and ``case['meta']['header_notes']`` (``max_seeds``: see :func:`header_items`)."""
    return [text for _kind, text in header_items(case, show_personal=show_personal, no_defang=no_defang, max_seeds=max_seeds)]


# ======================================================================================
# bottom line (AR14)
# ======================================================================================


def _fact(name: str, value: Any) -> str:
    label = name.replace("_", " ")
    if isinstance(value, bool):
        return f"{label}: {'yes' if value else 'no'}"
    if isinstance(value, (list, tuple, set)):
        items = [clean_text(v.get("value") or v.get("name") or v) if isinstance(v, dict) else clean_text(v) for v in value]
        items = [i for i in items if i]
        if not items:
            return ""
        shown = ", ".join(_clip(i, 40) for i in items[:2])
        return f"{label} {shown}" + (f" (+{len(items) - 2})" if len(items) > 2 else "")
    if isinstance(value, dict):
        pairs = [f"{clean_text(k)}={clean_text(v)}" for k, v in list(value.items())[:2]]
        return f"{label} {', '.join(pairs)}" if pairs else ""
    text = clean_text(value).strip()
    return f"{label} {_clip(text, 60)}" if text else ""


def _facts(idx: CaseIndex, key: str, limit: int = 3) -> list[str]:
    etype, _ = idx.type_value(key)
    try:
        et: EntityType | None = EntityType(etype)
    except ValueError:
        et = None
    if et in _EXTRACT_TYPES:
        n = sum(1 for e in _l(idx.case.get("edges")) if isinstance(e, dict) and e.get("src") == key)
        return [f"{n} values extracted"] if n else []
    out: list[str] = []
    for name in (_FACTS.get(et, ()) if et is not None else ()) + _DEFAULT_FACTS:
        if len(out) >= limit:
            break
        values = idx.attr_values(key, name)
        if not values:
            continue
        text = idx.text(_fact(name, values[0]))
        if text and text not in out:
            out.append(text)
    return out


def _what_line(case: Mapping[str, Any], idx: CaseIndex) -> str:
    seeds = _seeds(case)
    if not seeds:
        return "What it is: no input recorded"
    if len(seeds) == 1:
        facts = _facts(idx, seeds[0])
        return f"What it is: {idx.labelled(seeds[0])}" + (" - " + "; ".join(facts) if facts else " - no facts collected")
    parts = []
    for seed in seeds[:3]:
        facts = _facts(idx, seed, limit=2)
        parts.append(idx.labelled(seed) + (f" ({'; '.join(facts)})" if facts else ""))
    more = f"; +{len(seeds) - 3} more" if len(seeds) > 3 else ""
    return f"What it is: {len(seeds)} inputs - " + "; ".join(parts) + more


def _sev_word(item: Mapping[str, Any]) -> str:
    """The severity of a finding/correlation dict as one of the five known words ('info' else)."""
    sev = str(item.get("severity") or "").strip().lower()
    return sev if sev in _SEV_RANK else "info"


def _rank(item: Mapping[str, Any]) -> tuple[int, int, float]:
    try:
        conf = float(item.get("confidence") or 0.0)
    except (TypeError, ValueError):
        conf = 0.0
    return (_SEV_RANK.get(str(item.get("severity") or "info"), 0), _CONF_RANK.get(confidence_label(item), 0), conf)


def _contributors(case: Mapping[str, Any], idx: CaseIndex) -> list[str]:
    risk = _d(case.get("risk"))
    out: list[str] = []
    for c in _l(risk.get("contributors"))[:5]:
        if not isinstance(c, dict):
            continue
        finding = idx.by_id.get(str(c.get("finding_id") or ""))
        if finding is not None and is_identity_link(finding):
            continue
        words = idx.text(c.get("words") or "").strip()
        if not words and finding is not None:
            who = idx.display(str(finding.get("entity"))) if finding.get("entity") else ""
            words = f"{who}: {idx.text(finding.get('title'))}" if who else idx.text(finding.get("title"))
        if not words:
            continue
        label = str(c.get("confidence_label") or "").strip().lower()
        if label not in _CONF_RANK:  # only the three P322 labels are ever printed
            label = confidence_label(finding) if finding is not None else ""
        out.append(_clip(words, 140) + (f" [{label.upper()}]" if label else ""))
        if len(out) >= 3:
            break
    if out:
        return out
    # v1 / no contributors: the strongest correlation, then the top risky entities with their finding
    corrs = sorted((c for c in _l(case.get("correlations")) if isinstance(c, dict) and not is_identity_link(c)), key=_rank, reverse=True)
    if corrs and _SEV_RANK.get(str(corrs[0].get("severity")), 0) >= _SEV_RANK["medium"]:
        c = corrs[0]
        out.append(f"{_clip(idx.text(c.get('title')), 120)} ({_sev_word(c)} correlation) [{confidence_label(c).upper()}]")
    top = [t for t in _l(risk.get("top")) if isinstance(t, dict) and t.get("entity")]
    if not top:
        ents = _d(risk.get("entities"))
        top = [{"entity": k, **_d(v)} for k, v in sorted(ents.items(), key=lambda kv: -_num(_d(kv[1]).get("score")))]
    for t in top:
        if len(out) >= 3:
            break
        key = str(t["entity"])
        cands = [f for f in idx.by_entity.get(key, ()) if _sev_word(f) != "info" and not is_identity_link(f)]
        if not cands:
            continue
        best = max(cands, key=_rank)
        out.append(f"{idx.display(key)}: {_clip(idx.text(best.get('title')), 110)} ({_sev_word(best)}) [{confidence_label(best).upper()}]")
    if not out:
        cands = [f for f in idx.findings if _sev_word(f) != "info" and not is_identity_link(f)]
        for f in sorted(cands, key=_rank, reverse=True):
            who = idx.display(str(f.get("entity"))) if f.get("entity") else "case"
            text = f"{who}: {_clip(idx.text(f.get('title')), 110)} ({_sev_word(f)}) [{confidence_label(f).upper()}]"
            if text not in out:  # the same fact from several sources is one contributor (P335)
                out.append(text)
            if len(out) >= 3:
                break
    return list(dict.fromkeys(out))[:3]


def _why_line(case: Mapping[str, Any], idx: CaseIndex) -> str:
    reading = case_level(case)
    if reading == INCONCLUSIVE:
        seeds = [s for s in _seeds(case) if seed_inconclusive(case, s)]
        parts = []
        for seed in seeds[:3]:
            row = _d(_answered_row(case, seed))
            rep_app = int(_num(row.get("reputation_applicable")))
            cnv = int(_num(row.get("could_not_verify")))
            text = f"{idx.display(seed)}: {_reputation_answered(row)}" + (f" of {rep_app}" if rep_app else "") + " answered"
            parts.append(text + (f"; {_plural(cnv, 'source')} could not verify" if cnv else ""))
        if len(seeds) > 3:
            parts.append(f"+{len(seeds) - 3} more inputs")
        detail = ", ".join(parts) if parts else "no source answered"
        return f"Why: inconclusive - fewer than {MIN_REPUTATION_ANSWERS} reputation sources answered ({detail}); not a verdict either way"
    if reading == NO_FINDINGS:
        answered = applicable = 0
        for seed in _seeds(case):
            row = _answered_row(case, seed) or {}
            try:
                answered += int(row.get("answered") or 0)
                applicable += int(row.get("applicable") or 0)
            except (TypeError, ValueError):
                continue
        return f"Why: no findings - {answered} of {applicable} applicable sources answered and none reported a risk signal ({SCORE_LABEL})"
    label = clean_text(_d(case.get("risk")).get("label") or SCORE_LABEL)
    head = f"Why: {reading.upper()} {_score(case):.0f}/100 ({label})"
    contributors = _contributors(case, idx)
    return head + (" - " + "; ".join(contributors) if contributors else "")


def _next_line(case: Mapping[str, Any], idx: CaseIndex) -> str:
    corrs = [c for c in _l(case.get("correlations")) if isinstance(c, dict) and str(c.get("recommendation") or "").strip() and not is_identity_link(c)]
    if corrs:
        best = max(corrs, key=_rank)
        return "Next step: " + _clip(idx.text(best["recommendation"]).strip(), 240)
    reading = case_level(case)
    skips = _d(case.get("skips"))
    if reading == INCONCLUSIVE:
        steps = []
        if skips.get("needs_key"):
            steps.append("configure the missing API keys (v3lum keys)")
        if skips.get("not_default"):
            steps.append("run the opt-in sources (--preset deep)")
        cnv = any(_num(_d(_answered_row(case, s)).get("could_not_verify")) > 0 for s in _seeds(case))
        if case.get("deferred") or cnv:
            steps.append(f"retry the sources that could not verify (v3lum cases resume {clean_text(case.get('case_id') or '<case>')})")
        if skips.get("licence"):
            steps.append("review the coverage lost to the licence profile (v3lum doctor --licences)")
        if not steps:
            steps.append("use the manual pivots: no automated reputation source covered this input")
        return "Next step: add coverage before concluding - " + "; ".join(steps)
    if reading == NO_FINDINGS:
        return "Next step: no action suggested by the automated sources; use the manual pivots for what they cannot see"
    cands = [f for f in idx.findings if _sev_word(f) != "info" and not is_identity_link(f)]
    if cands:
        best = max(cands, key=_rank)
        who = idx.display(str(best.get("entity"))) if best.get("entity") else "the case"
        return f"Next step: confirm the {_sev_word(best)} finding '{_clip(idx.text(best.get('title')), 100)}' on {who} with its evidence before acting"
    return "Next step: review the findings below with their evidence before acting"


def bottom_line(case: Mapping[str, Any], *, show_personal: bool = False, no_defang: bool = False) -> list[str]:
    """Three lines (AR14): 'What it is: <type> <value> - <2-3 key facts>', 'Why: <reading> ...'
    (contributors with confidence labels; 'inconclusive'/'no findings' explained) and 'Next step:
    <the highest recommendation>'. Entity values are masked/defanged like every display."""
    idx = CaseIndex(case, show_personal=show_personal, no_defang=no_defang)
    return [_what_line(case, idx), _why_line(case, idx), _next_line(case, idx)]


# ======================================================================================
# skip lines (A1, A3, P334 cond 7)
# ======================================================================================


def _licence_feed_ids(case: Mapping[str, Any], skipped: Iterable[str]) -> set[str]:
    skipped = set(skipped)
    out: set[str] = set()
    for name, cov in _d(case.get("coverage")).items():
        if name in skipped:
            continue
        for sid, row in _d(_d(cov).get("sources")).items():
            if str(_d(row).get("reason_code") or "") == "licence":
                out.add(str(sid))
    return out


def _skip_text(code: str, n: int, case: Mapping[str, Any]) -> str:
    src = _plural(n, "source")
    need = _verb(n, "need")
    case_id = clean_text(case.get("case_id") or "<case>")
    texts = {
        "licence": f"{src} skipped: licence profile {_licence_profile(case)} - v3lum doctor --licences",
        "not_default": f"{_plural(n, 'opt-in source')} not run (use --preset deep)",
        "needs_key": f"{src} {need} an API key: v3lum keys",
        "own_asset": f"{_plural(n, 'own-asset module')} {need} a verified org profile: v3lum org",
        "privacy": f"{src} skipped for privacy: personal values need a recorded purpose (--purpose) and a reviewed provider",
        "tlp": f"{src} skipped at {tlp_label(case)}: the value may not leave for them at this TLP",
        "tier": f"{src} skipped: unknown-tier providers (only with --allow-unknown at TLP:CLEAR/GREEN)",
        "quota": f"{src} not run: provider quota used up - could not verify (v3lum cases resume {case_id})",
        "rate_limited": f"{src} rate limited - could not verify",
        "deadline": f"{src} not run: scan deadline reached (raise --timeout or setting scan_deadline)",
        "opsec": f"{src} {_verb(n, 'contact')} the target: --mode light or --mode active needed",
        "authorization": f"{src} {need} --authorized REF and --scope FILE (ACTIVE)",
        "scope": f"{src} skipped: target outside the engagement scope",
        "egress_country": f"{src} {need} another egress country (setting egress_country)",
        "hostile_host": f"{src} refused contact with a hostile host (needs a non-corporate egress profile)",
        "circuit": f"{src} not run after a provider block earlier in the scan - could not verify",
        "challenge": f"{src} blocked by an anti-bot challenge - could not verify",
        "geo_block": f"{src} geo-blocked - could not verify",
        "login_wall": f"{src} behind a login wall - could not verify",
        "policy": f"{src} refused by policy (rule 7 or undeclared hosts) - v3lum info <module>",
        "config": f"{src} skipped: configuration missing (v3lum config)",
        "demoted": f"{_plural(n, 'demoted source')} not run (health or precision) - v3lum doctor --sources",
        "package": f"{src} {need} an optional package: pip install 'v3lum[full]'",
        "dataset": f"{src} {need} a dataset: v3lum data update",
        "offline": f"{src} unavailable in offline mode",
        "timeout": f"{src} timed out - could not verify",
        "sanitizer": f"{src} dropped by the sanitizer - could not verify",
        "error": f"{src} failed - could not verify",
        "not_applicable": f"{src} not applicable to these inputs",
    }
    return texts.get(code, f"{src} skipped ({clean_text(code)})")


def skip_lines(case: Mapping[str, Any]) -> list[str]:
    """One line per reason code of ``case['skips']`` (``{reason_code: [module names]}``), most
    actionable first ('N sources skipped: licence profile corporate - v3lum doctor --licences', 'N
    opt-in sources not run (use --preset deep)', 'N own-asset modules need a verified org profile:
    v3lum org', ...), followed by every line of ``case['meta']['quota_lines']`` (P334 cond 7). The
    licence line also counts the feeds of aggregators that ran with licence-blocked sources."""
    skips = {str(k): [str(m) for m in _l(v)] for k, v in _d(case.get("skips")).items()}
    counts: dict[str, int] = {code: len(set(names)) for code, names in skips.items() if names}
    feeds = _licence_feed_ids(case, skips.get("licence", ()))
    if feeds:
        counts["licence"] = counts.get("licence", 0) + len(feeds)
    order = {code: i for i, code in enumerate(_SKIP_ORDER)}
    lines = [_skip_text(code, counts[code], case) for code in sorted(counts, key=lambda c: (order.get(c, len(order)), c))]
    for line in _l(_d(case.get("meta")).get("quota_lines")):
        text = clean_text(line).strip()
        if text:
            lines.append(text)
    return lines


def followup_lines(case: Mapping[str, Any]) -> list[str]:
    """Follow-ups of an unfinished case: quota-deferred lookups (``case['deferred']``: resume hint)
    and personal values found in text inputs that were not investigated (``case['pending_personal']``,
    AR07) - counts and types only, never the values."""
    lines = []
    deferred = [d for d in _l(case.get("deferred")) if isinstance(d, dict)]
    if deferred:
        lines.append(f"{_plural(len(deferred), 'lookup')} deferred by provider quota: v3lum cases resume {clean_text(case.get('case_id') or '<case>')}")
    pending = [p for p in _l(case.get("pending_personal")) if isinstance(p, dict)]
    if pending:
        types: dict[str, int] = defaultdict(int)
        for p in pending:
            types[str(p.get("entity") or "").partition(":")[0] or "?"] += 1
        kinds = ", ".join(f"{n} {clean_text(t)}" for t, n in sorted(types.items()))
        lines.append(
            f"{_plural(len(pending), 'personal value')} found in the input not investigated automatically ({kinds}): "
            "pick them interactively, or re-run with --expand-personal and --purpose"
        )
    return lines


def note_lines(case: Mapping[str, Any], *, show_personal: bool = False) -> list[str]:
    """The case notes for the closing section: partial-result notes are left out (the header shows
    them), the wave-2 'inconclusive' note loses its clause naming the v1 level and valid CPFs quoted
    in a note (engine notes name entity keys) are masked unless ``show_personal``."""
    out = []
    for note in _l(case.get("notes")):
        if is_partial_note(note):
            continue
        text = _CLEAN_CLAUSE.sub(" - the risk level is not a verdict", display_text(note, show_personal=show_personal)).strip()
        if text and text not in out:
            out.append(text)
    return out


# ======================================================================================
# disclosure ledger (A8)
# ======================================================================================


def _registry() -> Any:
    try:
        from v3lum.core import providers

        return providers.registry()
    except Exception:  # noqa: BLE001 - a broken registry must not break a report
        return None


def _module_disclosure(name: str) -> str:
    try:
        from v3lum.core.module import REGISTRY
    except Exception:  # noqa: BLE001
        return ""
    cls = REGISTRY.get(name)
    return str(getattr(cls, "disclosure", "") or "") if cls is not None else ""


def entity_host(key: str) -> str:
    """The host an entity key names (lower case, no trailing dot): a domain/IP/onion itself, the host
    of a URL, the domain of an e-mail address; '' for other types. Opening a link to that host (or a
    subdomain of it) contacts the investigated target (P311 cond 8)."""
    etype, _, value = str(key or "").partition(":")
    value = value.strip().lower()
    host = ""
    if etype == "url":
        try:
            from v3lum.core.entities import url_host

            host = url_host(value) or ""
        except Exception:  # noqa: BLE001
            host = ""
    elif etype == "email":
        host = value.rpartition("@")[2]
    elif etype in ("domain", "ipv4", "ipv6", "onion"):
        host = value
    return host.strip("[]").rstrip(".")


_entity_host = entity_host


def _is_target(host: str, entity: str, module: str) -> bool:
    if _module_disclosure(module) == "target":
        return True
    target = _entity_host(entity)
    host = host.strip().lower().rstrip(".")
    return bool(target) and (host == target or host.endswith("." + target))


def _host_row(reg: Any, host: str, entity: str, module: str) -> dict[str, Any]:
    provider = None
    if reg is not None:
        try:
            provider = reg.provider_for_host(host)
        except Exception:  # noqa: BLE001
            provider = None
    row: dict[str, Any] = {"provider": "", "name": host, "tier": "unknown", "terms": "unknown", "internal": False, "target": False, "third_party": True, "requests": 0, "entities": []}
    if provider is not None:
        classes = [getattr(src.terms, "class_", "unknown") for src in getattr(provider, "sources", {}).values()]
        try:
            from v3lum.core.providers import most_restrictive

            terms = most_restrictive(classes) if classes else "unknown"
        except Exception:  # noqa: BLE001
            terms = "unknown"
        internal = bool(getattr(provider, "internal", False))
        row.update(provider=str(provider.id), name=str(getattr(provider, "name", "") or provider.id), tier=str(getattr(provider, "tier", "unknown")), terms=terms, internal=internal, third_party=not internal)
    elif _is_target(host, entity, module):
        row.update(name="investigated target", tier="n/a", terms="n/a", target=True, third_party=False)
    return row


def disclosure_summary(case: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """The disclosure ledger (A8) keyed by contacted host: ``{host: {provider, name, tier, terms,
    internal, target, third_party, requests, entities}}`` from the hosts the runs actually contacted
    (``case['modules'][*]['hosts']``; cached responses are not counted, DoH resolvers are) and the
    provider registry: ``terms`` is the most restrictive class of the provider's sources, a host of no
    registered provider is 'unknown' tier and third-party unless it is the investigated target itself.
    ``entities`` lists the entity keys whose runs contacted the host (see :func:`disclosure_by_entity`)."""
    reg = _registry()
    out: dict[str, dict[str, Any]] = {}
    for res in _l(case.get("modules")):
        if not isinstance(res, dict):
            continue
        entity = str(res.get("entity") or "")
        module = str(res.get("module") or "")
        for host, count in _d(res.get("hosts")).items():
            host = clean_text(host).strip().lower()
            if not host:
                continue
            row = out.get(host)
            if row is None:
                row = out[host] = _host_row(reg, host, entity, module)
            try:
                row["requests"] += int(count)
            except (TypeError, ValueError):
                pass
            if entity and entity not in row["entities"]:
                row["entities"].append(entity)
    return dict(sorted(out.items()))


def disclosure_by_entity(case: Mapping[str, Any]) -> dict[str, list[str]]:
    """Per entity key, the third-party providers (names) that received its value in this run (A8)."""
    out: dict[str, set[str]] = defaultdict(set)
    for host, row in disclosure_summary(case).items():
        if not row.get("third_party"):
            continue
        for key in row.get("entities") or ():
            out[str(key)].add(str(row.get("name") or row.get("provider") or host))
    return {k: sorted(v, key=str.lower) for k, v in sorted(out.items())}


# ======================================================================================
# coverage lost under the licence profile (A1, P377 cond 8)
# ======================================================================================

_TERMS_IN_REASON = re.compile(r"(open|key-terms|license|noncommercial|unknown) terms")


def _terms_of(reg: Any, sid: str, reason: str) -> str:
    match = _TERMS_IN_REASON.search(reason or "")
    if match:
        return match.group(1)
    if reg is not None and "." in sid:
        try:
            src = reg.source(sid)
        except Exception:  # noqa: BLE001
            src = None
        klass = getattr(getattr(src, "terms", None), "class_", "") if src is not None else ""
        if klass:
            return str(klass)
    return "terms"


def licence_lines(case: Mapping[str, Any]) -> list[str]:
    """Coverage lost under the licence profile, one line per entity type:
    ``'ipv4: abusech.urlhaus (license), shodan.internetdb (noncommercial)'`` - from the coverage rows
    with reason_code 'licence' (whole modules and the blocked feeds of aggregators). Empty when the
    profile cost nothing."""
    reg = _registry()
    lost: dict[str, dict[str, str]] = defaultdict(dict)
    skipped = set(_l(_d(case.get("skips")).get("licence")))
    for name, cov in _d(case.get("coverage")).items():
        cov = _d(cov)
        rows = {str(k): _d(r) for k, r in _d(cov.get("entities")).items()}
        licence_keys = [k for k, r in rows.items() if str(r.get("reason_code") or "") == "licence"]
        ran_keys = [k for k, r in rows.items() if str(r.get("status") or "") not in ("skipped", "not_run")]
        feeds = {str(sid): _d(row) for sid, row in _d(cov.get("sources")).items() if str(_d(row).get("reason_code") or "") == "licence"}
        whole = bool(licence_keys) or (name in skipped) or (str(cov.get("reason_code") or "") == "licence" and str(cov.get("status")) == "skipped")
        if not feeds and not whole:
            continue
        # entity types that lost the coverage: where the module was licence-skipped, plus (for blocked
        # feeds of an aggregator that ran) where it ran; a v1 entry without rows counts as 'any'
        keys = licence_keys + (ran_keys if feeds else [])
        types = sorted({k.partition(":")[0] for k in keys} or {k.partition(":")[0] for k in rows} or {"any"})
        if feeds:
            labels = {clean_text(sid): _terms_of(reg, sid, str(row.get("reason") or "")) for sid, row in feeds.items()}
        else:
            reason = str(rows[licence_keys[0]].get("reason") if licence_keys else cov.get("reason") or "")
            labels = {clean_text(name): _terms_of(reg, "", reason)}
        for etype in types:
            lost[etype].update(labels)
    return [f"{clean_text(etype)}: " + ", ".join(f"{label} ({klass})" for label, klass in sorted(items.items())) for etype, items in sorted(lost.items())]


# ======================================================================================
# reports v2 (WP20): TLP texts, notices, sightings, contributors, grouped rows, breach facts,
# manual pivots, appendices and attributions - shared by the HTML, Markdown, pivot-page and
# terminal renderers (pure: they read the case dict and the registries, never the network)
# ======================================================================================

#: FIRST TLP 2.0 definitions: the banner under every marking (A2).
TLP_DESCRIPTIONS: dict[str, str] = {
    "clear": "TLP:CLEAR - recipients can spread this to the world; there is no limit on disclosure.",
    "green": "TLP:GREEN - limited disclosure: recipients can spread this within their community.",
    "amber": "TLP:AMBER - limited disclosure: recipients can only spread this on a need-to-know basis within their organisation and its clients.",
    "amber+strict": "TLP:AMBER+STRICT - limited disclosure: recipients can only spread this within their own organisation.",
    "red": "TLP:RED - for the eyes and ears of individual recipients only; no further disclosure.",
}
#: Display label of each header kind (:func:`header_items`) in the HTML/Markdown reports.
HEADER_LABELS: dict[str, str] = {
    "tlp": "TLP", "mode": "run", "tls": "TLS", "engagement": "engagement", "partial": "warning", "answered": "answered",
    "sightings": "seen before", "disclosure": "disclosure", "licence": "licence", "purpose": "recorded", "since": "re-collection",
    "note": "note",
}
#: 'contains personal data (LGPD)' notice (P336 cond 7): shown when PERSONAL_TYPES entities are present.
PERSONAL_DATA_NOTICE = (
    "contains personal data (LGPD): use it only for the recorded purpose and legal basis; CPF values are masked "
    "unless the analyst unmasked this view (recorded in the case audit)"
)
#: The view was rendered with --show-personal (AR24: recorded in the case audit).
SHOW_PERSONAL_NOTICE = "personal data is shown unmasked in this report (--show-personal, recorded in the case audit): do not share it beyond the case purpose"
#: P146 cond 11: shown when the breach/infostealer rules fired.
BREACH_NOTICE = (
    "infostealer findings about employees go to incident response and are not a basis for disciplinary decisions "
    "without human review (LGPD art. 20)"
)
#: Correlation rules of the breach pack (P146 CR09-CR12) and the legacy rule they replace.
BREACH_RULES: frozenset[str] = frozenset({
    "corporate_credentials_in_infostealer", "email_in_multiple_password_breaches", "generic_or_shared_email_suppression",
    "breach_predates_domain", "breach_and_infostealer",
})
#: Documentation hosts whose references stay clickable in HTML/Markdown (P336 cond 3): only exact hosts.
REFERENCE_HOSTS: frozenset[str] = frozenset({
    "attack.mitre.org", "capec.mitre.org", "cve.mitre.org", "cwe.mitre.org", "www.cve.org", "nvd.nist.gov", "www.cisa.gov",
    "www.first.org", "first.org", "haveibeenpwned.com", "owasp.org", "cheatsheetseries.owasp.org", "www.rfc-editor.org",
    "datatracker.ietf.org", "www.iana.org", "learn.microsoft.com", "msrc.microsoft.com", "osv.dev", "endoflife.date",
    "www.cert.br", "www.gov.br", "www.misp-project.org", "www.circl.lu",
})
#: Tags that make a finding a breach/infostealer finding (its data classes and password form are shown).
BREACH_TAGS: frozenset[str] = frozenset({"breach", "infostealer", "credential_exposure", "stealer_log"})
#: Internal sighting platforms in the A12 query order (case DB first).
_INTERNAL_PLATFORMS = ("case_db", "misp", "opencti", "thehive", "siem")
#: Entity attributes that carry internal-platform references (left out at TLP:CLEAR/GREEN, A2).
_INTERNAL_ATTRIBUTES = ("internal_sightings", "siem_sighting")
_INTERNAL_NOTES = {"false_positive": "false positive", "warninglist": "warninglist", "historical": "historical", "context": "context only", "observed": "context only"}
_CASE_SIGHTINGS_MODULE = "case_sightings"
_URL_IN_TEXT = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`]+")
_VALUEISH = re.compile(r"[@$]|[0-9A-Fa-f]{16}")


def tlp_description(case: Mapping[str, Any]) -> str:
    """The FIRST TLP 2.0 definition of the case TLP (the banner text of every report)."""
    return TLP_DESCRIPTIONS.get(tlp_value(case), TLP_DESCRIPTIONS["red"])


def tlp_color(case: Mapping[str, Any]) -> str:
    """The TLP 2.0 colour of the case marking (hex, for a black background)."""
    return _tlp.parse(tlp_value(case)).color


def defang_urls_in_text(text: Any) -> str:
    """Free text with every http(s)/www URL defanged (``hxxps://evil[.]com/x``): module text never
    carries a URL a Markdown renderer would autolink or a reader could open by accident."""
    from v3lum.core.entities import defang

    return _URL_IN_TEXT.sub(lambda m: defang(m.group(0)), "" if text is None else str(text))


def shareable_view(case: Mapping[str, Any]) -> dict[str, Any]:
    """The case as a shareable report may show it (A2, P375 cond 3). At TLP:CLEAR/GREEN (and for an
    unreadable TLP: fail closed) a copy without cross-case references (``store.omit_cross_case``)
    and without internal-platform references (attributes ``internal_sightings`` / ``siem_sighting``
    removed; findings tagged ``internal_sighting`` keep their title and severity but lose their
    data, description, criterion, references and evidence - which name the platform's event, case
    or template ids; the since-last-run line keeps its counts without the earlier case id); at AMBER
    and above a shallow copy of the case. The case itself is never changed."""
    from v3lum.core import store as _store

    if _store.cross_case_allowed(tlp_value(case)):
        return dict(case)
    # a damaged stored case (a scalar where a list is expected) must not break a CLEAR/GREEN report
    clean = {k: (v if isinstance(v, (list, tuple)) or k not in _LIST_FIELDS else []) for k, v in case.items()}
    view = _store.omit_cross_case(clean)
    for node in _l(view.get("entities")):
        attrs = node.get("attributes") if isinstance(node, dict) else None
        if isinstance(attrs, dict):
            for name in _INTERNAL_ATTRIBUTES:
                attrs.pop(name, None)
    label = tlp_label(case)
    omitted = f"reference omitted at {label}: cross-case references are not shared at this TLP"
    for f in _l(view.get("findings")):
        if isinstance(f, dict) and "internal_sighting" in {str(t) for t in _l(f.get("tags"))}:
            f["data"] = {}
            f["description"] = f"Known in an internal platform ({omitted})."
            f["criterion"] = f"internal platform match ({omitted})"
            f["references"] = []
            f.pop("evidence", None)
            f.pop("key", None)
    # the re-collection line keeps its counts but not the earlier case's id (a cross-case reference)
    for holder in (view, _d(view.get("meta"))):
        since = holder.get("since_last_run")
        if isinstance(since, dict):
            holder["since_last_run"] = {k: v for k, v in since.items() if k not in ("previous_case", "previous_created")}
    meta = view.get("meta")
    if isinstance(meta, dict) and isinstance(meta.get("header_notes"), list):
        meta["header_notes"] = [_SINCE_CASE_RE.sub("since last run", n) if isinstance(n, str) else n for n in meta["header_notes"]]
    return view


#: Case fields that are lists (anything else in a stored case is replaced by [] before filtering).
_LIST_FIELDS = frozenset({"entities", "findings", "correlations", "edges", "timeline", "modules", "seeds", "inputs", "notes"})
#: 'since last run (case <id>)' - the earlier case id is dropped from CLEAR/GREEN reports.
_SINCE_CASE_RE = re.compile(r"since last run \(case [^)]*\)", re.I)


def contains_personal_data(case: Mapping[str, Any]) -> bool:
    """True when the case holds an entity (or seed) of a PERSONAL_TYPES type (P336 cond 7)."""
    from v3lum.core.entities import PERSONAL_TYPES

    keys = [str(n.get("type") or str(n.get("key") or "").partition(":")[0]) for n in _l(case.get("entities")) if isinstance(n, dict)]
    keys += [s.partition(":")[0] for s in _seeds(case)]
    for etype in keys:
        try:
            if EntityType(etype) in PERSONAL_TYPES:
                return True
        except ValueError:
            continue
    return False


def breach_rules_fired(case: Mapping[str, Any]) -> bool:
    """True when a P146 breach/infostealer rule produced a correlation, or an infostealer finding is
    present (the LGPD art. 20 notice applies, P146 cond 11)."""
    for c in _l(case.get("correlations")):
        if isinstance(c, dict) and str(c.get("rule") or "") in BREACH_RULES:
            return True
    return any(isinstance(f, dict) and "infostealer" in {str(t) for t in _l(f.get("tags"))} for f in _l(case.get("findings")))


def report_notices(case: Mapping[str, Any], *, show_personal: bool = False) -> list[tuple[str, str]]:
    """Report notices as ``(kind, text)``: ``personal`` (:data:`PERSONAL_DATA_NOTICE`, P336 cond 7),
    ``show_personal`` (:data:`SHOW_PERSONAL_NOTICE`, the view is unmasked) and ``breach``
    (:data:`BREACH_NOTICE`, P146 cond 11)."""
    out: list[tuple[str, str]] = []
    if contains_personal_data(case):
        out.append(("personal", PERSONAL_DATA_NOTICE))
        if show_personal:
            out.append(("show_personal", SHOW_PERSONAL_NOTICE))
    if breach_rules_fired(case):
        out.append(("breach", BREACH_NOTICE))
    return out


def tls_interception_line(case: Mapping[str, Any]) -> str:
    """The one header line of P329 cond 4 from ``case['meta']['tls_interception']`` (a dict
    ``{intercepted, issuer, profile, checked_at, host}``, a list of them, or a text); '' when no
    interception was recorded."""
    info = _d(case.get("meta")).get("tls_interception")
    items = info if isinstance(info, (list, tuple)) else [info]
    parts: list[str] = []
    for item in items:
        if isinstance(item, str) and item.strip():
            parts.append(clean_text(item).strip())
            continue
        if not isinstance(item, Mapping) and item is not None and not isinstance(item, str):
            item = {k: getattr(item, k, None) for k in ("intercepted", "issuer", "profile", "checked_at", "host")}
        if not isinstance(item, Mapping) or item.get("intercepted") is False or not (item.get("intercepted") or item.get("issuer")):
            continue
        issuer = clean_text(item.get("issuer") or "an unknown issuer")
        profile = clean_text(item.get("profile") or "default")
        parts.append(f"TLS-intercepted by {issuer} (egress profile {profile})")
    if not parts:
        return ""
    return _clip("; ".join(parts), 300) + ": certificate-derived findings are inconclusive for this run"


# ---------------------------------------------------------------------------------- sightings


def _hit_visible(hit_tlp: Any, case_tlp: str) -> bool:
    if hit_tlp in (None, ""):
        return True
    try:
        return _tlp.parse(hit_tlp) <= _tlp.parse(case_tlp)
    except ValueError:
        return _tlp.parse(case_tlp) >= _tlp.TLP.RED  # unreadable marking: RED cases only


def _sightings_headline(value: Any) -> str:
    if not isinstance(value, Mapping):
        return ""
    try:
        count, restricted = int(value.get("count") or 0), int(value.get("restricted") or 0)
    except (TypeError, ValueError):
        return ""
    if count > 0:
        last = clean_text(value.get("last") or "") or "unknown"
        verdict = clean_text(value.get("verdict") or "") or "none"
        text = f"seen in {_plural(count, 'previous case')}, last {last}, verdict: {verdict}"
        if restricted > 0:
            text += f"; also in {_plural(restricted, 'restricted case')} (higher TLP)"
        return text
    if restricted > 0:
        return f"seen in {_plural(restricted, 'restricted case')}"
    return ""


def _internal_ref(hit: Mapping[str, Any]) -> str:
    ref = clean_text(hit.get("ref") or "").strip()
    if not ref:
        return ""
    note = _INTERNAL_NOTES.get(str(hit.get("verdict") or ""))
    return _clip(f"{ref} ({note})" if note else ref, 80)


def sighting_lines(case: Mapping[str, Any], key: str, *, idx: CaseIndex | None = None) -> list[str]:
    """The internal sightings of one entity, case DB first (P375 cond 6, A12): the ``case_sightings``
    finding title ('seen in N previous cases, last <date>, verdict: <v>'; else the same text built
    from attribute ``sightings``), then 'known internally: MISP event #N, TheHive case #M' from
    attribute ``internal_sightings`` (hits marked above the case TLP left out). Internal-platform
    references are never listed at TLP:CLEAR/GREEN (A2: cross-case references). ``idx``: a
    :class:`CaseIndex` of the case the caller already built."""
    from v3lum.core import store as _store

    idx = idx if idx is not None else CaseIndex(case)
    attrs = _d((idx.nodes.get(str(key)) or {}).get("attributes"))
    out: list[str] = []
    titles = [
        display_text(f.get("title")).strip()
        for f in idx.by_entity.get(str(key), ())
        if str(f.get("module") or "") == _CASE_SIGHTINGS_MODULE
    ]
    titles = [t for t in titles if t]
    if titles:
        out.append(_clip(titles[0], 160))
    else:
        for item in _l(attrs.get("sightings")):
            text = _sightings_headline(item.get("value") if isinstance(item, Mapping) and "value" in item else item)
            if text:
                out.append(text)
                break
    case_tlp = tlp_value(case)
    if not _store.cross_case_allowed(case_tlp):
        return out
    hits: list[Mapping[str, Any]] = []
    for item in _l(attrs.get("internal_sightings")):
        value = item.get("value") if isinstance(item, Mapping) and "value" in item else item
        for hit in value if isinstance(value, (list, tuple)) else [value]:
            if isinstance(hit, Mapping) and _hit_visible(hit.get("tlp"), case_tlp):
                hits.append(hit)
    order = {p: i for i, p in enumerate(_INTERNAL_PLATFORMS)}
    refs: list[str] = []
    for hit in sorted(hits, key=lambda h: order.get(str(h.get("platform") or ""), len(order))):
        ref = _internal_ref(hit)
        if ref and ref not in refs:
            refs.append(ref)
    if refs:
        out.append("known internally: " + ", ".join(refs[:6]) + (f", +{len(refs) - 6} more" if len(refs) > 6 else ""))
    return out


# ---------------------------------------------------------------------------------- contributors and scores


def _path_text(idx: CaseIndex, path: Any) -> str:
    if isinstance(path, (list, tuple)):
        steps = [str(p) for p in path if p]
    elif isinstance(path, str) and path.strip():
        steps = [p.strip() for p in re.split(r"\s*(?:->|→|>)\s*", path) if p.strip()]
    else:
        return ""
    shown = []
    for step in steps[:6]:
        etype, sep, _ = step.partition(":")
        try:
            EntityType(etype)
            known = bool(sep)
        except ValueError:
            known = False
        shown.append(idx.display(step) if known else idx.text(step))
    return " -> ".join(shown) + (" -> ..." if len(steps) > 6 else "")


def contributor_lines(case: Mapping[str, Any], *, show_personal: bool = False, no_defang: bool = False, limit: int = 3) -> list[str]:
    """The top contributors of the score in plain words (P302 cond 9), numbered: ``'1. <words>
    [PROBABLE] (finding <id>, path <a> -> <b>)'`` from ``risk['contributors']`` (risk model v2:
    finding_id, entity, path, confidence_label, words); POSSIBLE identity links are never listed;
    stored v1 cases fall back to the strongest correlation and findings. Entities in the words and
    paths are masked/defanged like every display."""
    idx = CaseIndex(case, show_personal=show_personal, no_defang=no_defang)
    out: list[str] = []
    for c in _l(_d(case.get("risk")).get("contributors")):
        if not isinstance(c, dict):
            continue
        finding = idx.by_id.get(str(c.get("finding_id") or ""))
        if finding is not None and is_identity_link(finding):
            continue
        words = idx.text(c.get("words") or "").strip()
        if not words and finding is not None:
            who = idx.display(str(finding.get("entity"))) if finding.get("entity") else ""
            words = f"{who}: {idx.text(finding.get('title'))}" if who else idx.text(finding.get("title"))
        if not words and c.get("entity"):
            words = idx.display(str(c["entity"]))
        if not words:
            continue
        label = str(c.get("confidence_label") or "").strip().lower()
        if label not in _CONF_RANK:
            label = confidence_label(finding) if finding is not None else ""
        meta = []
        fid = clean_text(c.get("finding_id") or "").strip()
        if fid:
            meta.append(f"finding {_clip(fid, 24)}")
        path = _path_text(idx, c.get("path"))
        if path:
            meta.append(f"path {path}")
        line = _clip(words, 160) + (f" [{label.upper()}]" if label else "") + (f" ({'; '.join(meta)})" if meta else "")
        out.append(f"{len(out) + 1}. {line}")
        if len(out) >= limit:
            return out
    if out:
        return out
    return [f"{i}. {text}" for i, text in enumerate(_contributors(case, idx)[:limit], 1)]


def score_text(case: Mapping[str, Any], key: str, *, show_personal: bool = False, no_defang: bool = False, idx: CaseIndex | None = None) -> str:
    """The risk reading of one entity for entity maps and tables: '' without a scored level;
    ``'<level> <score>'``; for PERSONAL_TYPES entities the level only together with its top
    contributor (``'<level>: <top finding>'``, P302 cond 10: never a bare score about a person).
    ``idx``: a :class:`CaseIndex` of the same case and view the caller already built."""
    from v3lum.core.entities import PERSONAL_TYPES

    row = _d(_d(_d(case.get("risk")).get("entities")).get(key))
    level = level_label(row.get("level"))
    if level == NO_FINDINGS:
        return ""
    idx = idx if idx is not None else CaseIndex(case, show_personal=show_personal, no_defang=no_defang)
    etype, _ = idx.type_value(key)
    try:
        personal = EntityType(etype) in PERSONAL_TYPES
    except ValueError:
        personal = False
    if personal:
        cands = [f for f in idx.by_entity.get(key, ()) if _sev_word(f) != "info" and not is_identity_link(f)]
        why = _clip(idx.text(max(cands, key=_rank).get("title")), 80) if cands else "see the findings"
        return f"{level}: {why}"
    return f"{level} {_num(row.get('score')):.0f}"


# ---------------------------------------------------------------------------------- findings: grouping, ownership, breach facts


@dataclass
class FindingRow:
    """One displayed finding row (P335: presentation-only grouping; every member keeps its id,
    evidence and feedback). ``lead`` is the member with the highest severity and confidence."""

    key: str
    lead: dict[str, Any]
    members: list[dict[str, Any]]
    severity: str
    confidence_label: str
    criterion: str
    sources: list[str] = field(default_factory=list)
    families: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.members)

    @property
    def grouped(self) -> bool:
        return len(self.members) > 1

    @property
    def member_ids(self) -> list[str]:
        return [str(m.get("id") or "") for m in self.members if m.get("id")]

    def sources_text(self) -> str:
        """'seen by 3 sources: XON, HIBP, LeakCheck' (P335 cond 3); '' for a single source."""
        names = [clean_text(s) for s in self.sources if s]
        if len(names) < 2:
            return ""
        text = f"seen by {len(names)} sources: " + ", ".join(names[:8]) + (f", +{len(names) - 8} more" if len(names) > 8 else "")
        fams = [clean_text(f) for f in self.families if f]
        if fams and len(fams) != len(names):
            text += f" ({_plural(len(fams), 'upstream family', 'upstream families')})"
        return text


def _field(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _source_name(f: Mapping[str, Any]) -> str:
    return clean_text(f.get("source") or f.get("module") or "")


def _row_of(key: str, members: list[dict[str, Any]], group: Any = None) -> FindingRow:
    principal = str(_field(group, "principal_id", "") or "") if group is not None else ""
    lead = next((m for m in members if principal and str(m.get("id") or "") == principal), None) or max(members, key=_rank)
    sev = str(_field(group, "severity", "") or "").strip().lower() if group is not None else ""
    if sev not in _SEV_RANK:
        sev = _sev_word(max(members, key=lambda f: _SEV_RANK.get(_sev_word(f), 0)))
    label = str(_field(group, "confidence_label", "") or "").strip().lower() if group is not None else ""
    if label not in _CONF_RANK:
        label = max((confidence_label(m) for m in members), key=lambda x: _CONF_RANK.get(x, 0))
    criterion = clean_text(_field(group, "criterion", "") or "") if group is not None else ""
    if not criterion:
        best = [m for m in members if confidence_label(m) == label] or members
        criterion = clean_text(max(best, key=_rank).get("criterion") or "")
    sources = [clean_text(s) for s in _l(_field(group, "sources", None))] if group is not None else []
    if not sources:
        sources = list(dict.fromkeys(s for s in (_source_name(m) for m in members) if s))
    families = [clean_text(f) for f in _l(_field(group, "upstream_families", None))] if group is not None else []
    return FindingRow(key=key, lead=lead, members=members, severity=sev, confidence_label=label, criterion=criterion, sources=sources, families=families)


def finding_rows(findings: Iterable[Mapping[str, Any]]) -> list[FindingRow]:
    """Display rows of findings (P335): ``grouping.group_findings`` (WP19; the same breach across
    sources, URL variants of one resource, the same CVE from several sources - identity entities are
    never merged) turned into :class:`FindingRow` objects in the order of the strongest member.
    Every finding appears in exactly one row; without the grouping module (or if it fails) each
    finding is its own row. Case JSON and exports are never grouped."""
    items = [dict(f) for f in findings if isinstance(f, Mapping)]
    by_id = {str(f.get("id")): f for f in items if f.get("id")}
    rows: list[FindingRow] = []
    placed: set[int] = set()
    groups: Any = None
    try:
        from v3lum.core import grouping  # WP19 (same wave)

        groups = grouping.group_findings(items)
    except Exception:  # noqa: BLE001 - not there yet, or failed: one row per finding
        groups = None
    for group in groups or ():
        ids = [str(i) for i in _l(_field(group, "member_ids", None))]
        members = []
        for fid in ids:
            f = by_id.get(fid)
            if f is not None and id(f) not in placed:
                members.append(f)
                placed.add(id(f))
        if members:
            rows.append(_row_of(clean_text(_field(group, "key", "") or members[0].get("id") or ""), members, group))
    for f in items:
        if id(f) not in placed:
            placed.add(id(f))
            rows.append(_row_of(str(f.get("id") or ""), [f]))
    rows.sort(key=lambda r: (_SEV_RANK.get(r.severity, 0), _CONF_RANK.get(r.confidence_label, 0), _rank(r.lead)[2]), reverse=True)
    return rows


def is_own_asset(item: Mapping[str, Any]) -> bool:
    """Is this finding/correlation about one of the organisation's assets (A11: 'your assets' first)?"""
    return str(item.get("ownership") or "") == "own_asset" or "own_asset" in {str(t) for t in _l(item.get("tags"))}


def override_text(item: Mapping[str, Any], *, show_personal: bool = False) -> str:
    """'analyst: <label> / <severity> / <verdict> (<note>)' for a finding with an analyst override
    (P322 cond 3); '' otherwise."""
    ov = _d(item.get("override"))
    if not ov:
        return ""
    parts = [clean_text(ov.get(k)) for k in ("label", "severity", "verdict") if ov.get(k)]
    note = display_text(ov.get("note"), show_personal=show_personal).strip()
    return f"analyst: {' / '.join(parts) or 'reviewed'}" + (f" ({_clip(note, 200)})" if note else "")


def password_words(form: Any) -> str:
    """The password form of a breach in plain words (P145 cond 9): ``'passwords: plaintext'``,
    ``'passwords: hashed (bcrypt)'``, ``'passwords: hashed'``, ``'passwords: storage form unknown'``;
    several forms are joined. Only recognised forms are ever printed (``sanitize.normalize_password_form``
    / ``is_password_form``): anything else - a value, a hash, a hint - gives ''."""
    from v3lum.core import sanitize as _sanitize

    forms = form if isinstance(form, (list, tuple, set)) else [form]
    words: list[str] = []
    for item in forms:
        if not isinstance(item, str):
            continue
        canon = _sanitize.normalize_password_form(item)
        if not canon or not _sanitize.is_password_form(canon):
            continue
        head, sep, algorithm = canon.partition(":")
        if head.strip() == "hashed" and sep and algorithm.strip():
            word = f"hashed ({algorithm.strip()})"
        elif head.strip() == "unknown":
            word = "storage form unknown"
        else:
            word = head.strip()
        if word not in words:
            words.append(word)
    return "passwords: " + ", ".join(words) if words else ""


def breach_facts(item: Mapping[str, Any], *, show_personal: bool = False) -> list[str]:
    """For a breach/infostealer finding (tags :data:`BREACH_TAGS`): its data classes and password form
    in plain words from the kept fields (``data_classes``, ``password_form``, also per record under
    ``breaches`` / ``records`` / ``breach_records``): ``['data classes: Email addresses, Passwords',
    'passwords: hashed (bcrypt)']``. Never any value (P145 cond 9); [] for other findings."""
    if not ({str(t) for t in _l(item.get("tags"))} & BREACH_TAGS):
        return []
    data = _d(item.get("data"))
    records = [data] + [r for k in ("breaches", "records", "breach_records") for r in _l(data.get(k)) if isinstance(r, dict)]
    classes: list[str] = []
    forms: list[Any] = []
    for rec in records:
        for raw in _l(rec.get("data_classes")) + _l(rec.get("dataclasses")):
            text = display_text(raw, show_personal=show_personal).strip()
            if text and not _VALUEISH.search(text) and text not in classes:
                classes.append(_clip(text, 40))
        value = rec.get("password_form")
        if value:
            forms.extend(value if isinstance(value, (list, tuple)) else [value])
    out = []
    if classes:
        out.append("data classes: " + ", ".join(classes[:12]) + (f" (+{len(classes) - 12})" if len(classes) > 12 else ""))
    words = password_words(forms)
    if words:
        out.append(words)
    return out


def attention(case: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    """``(attention points, limitations)`` from ``core.attention`` (WP16); if it fails, the
    limitations fall back to the could-not-verify coverage groups (rule 5 stays visible)."""
    points: list[str] = []
    limits: list[str] | None = None
    try:
        from v3lum.core import attention as _att
    except Exception:  # noqa: BLE001
        _att = None
    if _att is not None:
        try:
            points = [str(p) for p in _att.attention_points(case) or ()]
        except Exception:  # noqa: BLE001
            points = []
        try:
            limits = [str(x) for x in _att.limitations(case) or ()]
        except Exception:  # noqa: BLE001
            limits = None
    if limits is None:
        groups: dict[str, list[str]] = defaultdict(list)
        for name, info in sorted(_d(case.get("coverage")).items()):
            info = _d(info)
            st = str(info.get("status") or "")
            if st in _CNV_STATUSES:
                groups[str(info.get("reason_code") or st)].append(clean_text(name))
        limits = []
        for code, names in sorted(groups.items()):
            shown = ", ".join(names[:8]) + (f", +{len(names) - 8} more" if len(names) > 8 else "")
            limits.append(f"could not verify: {shown} ({clean_text(code)}) - not a finding of absence")
    return points, limits


# ---------------------------------------------------------------------------------- engagement banner (A7)


def engagement_block(case: Mapping[str, Any], *, show_personal: bool = False, no_defang: bool = False) -> list[str]:
    """The LIGHT/ACTIVE engagement block (A7): first line ``'<MODE> engagement · authorization <ref> ·
    scope sha256 <..> · window <..> · egress <profile/IP> · targets touched N · M target requests'``
    (:func:`engagement_banner`), then one line per out-of-scope refusal (target and reason). [] for
    a passive case without an engagement record."""
    banner = engagement_banner(case)
    if not banner:
        return []
    idx = CaseIndex(case, show_personal=show_personal, no_defang=no_defang)
    return [banner] + [line for line in _engagement_lines(case, idx) if not line.startswith("engagement:")]


def engagement_banner(case: Mapping[str, Any]) -> str:
    """The one-line engagement banner repeated at the top of every report section of a LIGHT/ACTIVE
    case (A7, P336 cond 8); '' for a passive case without an engagement record."""
    eng = _engagement(case)
    mode = clean_text(_options(case).get("mode") or eng.get("mode") or "passive").lower()
    if not eng and mode not in ("light", "active"):
        return ""
    parts = [f"{mode.upper()} engagement"]
    ref = eng.get("authorization_ref") or _options(case).get("authorization_ref") or ""
    parts.append(f"authorization {display_text(ref)}" if ref else "authorization not recorded")
    parts.append(f"scope sha256 {clean_text(eng.get('scope_sha256'))[:16]}" if eng.get("scope_sha256") else "scope sha256 not recorded")
    parts.append(f"window {display_text(_window_text(eng.get('window')))}" if eng.get("window") else "window not recorded")
    parts.append(f"egress {_egress_text(case, mode)}")
    parts.append(f"targets touched {len(_d(eng.get('targets_touched')))}")
    count = eng.get("request_count")
    parts.append(f"{clean_text(count)} target requests" if count is not None else "target requests not recorded")
    return " · ".join(parts)


# ---------------------------------------------------------------------------------- manual pivots and references (P311, P336, A2)


@dataclass
class PivotItem:
    """One manual pivot as a report shows it: ``href`` is the clickable URL (None = plain text),
    ``text`` the defanged non-clickable form, ``warning`` the disclosure / target warning."""

    label: str
    url: str
    host: str
    category: str
    href: str | None
    text: str
    warning: str = ""
    badge: str = ""
    note: str = ""
    verified: bool = False
    manual: bool = False
    template: bool = False
    #: a target-contact link of a hostile entity: shown only when the analyst expands it (P311 cond 8)
    collapsed: bool = False


@dataclass
class PivotEntity:
    key: str
    display: str
    seed: bool
    groups: list[tuple[str, list[PivotItem]]] = field(default_factory=list)

    @property
    def count(self) -> int:
        return sum(len(items) for _cat, items in self.groups)


@dataclass
class PivotPlan:
    """The manual pivots of a case under the TLP and touches_target rules (see :func:`pivot_plan`)."""

    tlp: str
    clickable: bool
    entities: list[PivotEntity] = field(default_factory=list)
    hidden_red: int = 0
    hidden_privacy: int = 0
    hidden_hostile: int = 0
    dropped: int = 0

    @property
    def count(self) -> int:
        return sum(e.count for e in self.entities)


def merged_links(items: Iterable[Any]) -> list[dict[str, Any]]:
    """The link items of one entity with duplicates of the same URL merged (the P311 manual-link
    fallback and the pack link of the same URL become one item: pack fields kept, ``manual`` and the
    'automation skipped' note added). Order is kept."""
    out: list[dict[str, Any]] = []
    by_url: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, Mapping) or not item.get("url"):
            continue
        url = str(item["url"]).strip()
        current = by_url.get(url)
        if current is None:
            merged = dict(item)
            by_url[url] = merged
            out.append(merged)
            continue
        for k, v in item.items():
            if k in ("manual", "verified", "privacy", "touches_target", "antibot"):
                current[k] = bool(current.get(k)) or bool(v)
            elif k == "note":
                notes = [n for n in (str(current.get("note") or ""), str(v or "")) if n]
                current["note"] = "; ".join(dict.fromkeys(notes))
            elif not current.get(k) and v:
                current[k] = v
    return out


def _declared_host(item: Mapping[str, Any]) -> str:
    return str(item.get("host") or "").strip().lower().rstrip(".")


def link_host(item: Mapping[str, Any]) -> str:
    """The host a link sends the value to: the URL's own host (what a browser contacts), else the
    declared ``host`` of a pivot pack (packs validate both are equal at load; a stored case is
    untrusted, so a declared host never hides where the URL really goes)."""
    try:
        from urllib.parse import urlsplit

        host = (urlsplit(str(item.get("url") or "").strip()).hostname or "").lower()
    except ValueError:
        host = ""
    return host.rstrip(".") or _declared_host(item)


def _host_in(host: str, targets: Iterable[str]) -> bool:
    return bool(host) and any(t and (host == t or host.endswith("." + t)) for t in targets)


def target_hosts(case: Mapping[str, Any], key: str = "", *, idx: CaseIndex | None = None) -> set[str]:
    """Hosts whose links contact a target rather than a third party: the host of ``key`` and of every
    hostile entity of the case (P311 cond 8)."""
    idx = idx if idx is not None else CaseIndex(case)
    hosts = {entity_host(key)} if key else set()
    hosts.update(entity_host(k) for k in idx.nodes if idx.hostile(k))
    return {h for h in hosts if h}


def _internal_host(host: str) -> bool:
    reg = _registry()
    if reg is None or not host:
        return False
    try:
        prov = reg.provider_for_host(host)
    except Exception:  # noqa: BLE001
        return False
    return bool(getattr(prov, "internal", False)) if prov is not None else False


def case_values(case: Mapping[str, Any]) -> frozenset[str]:
    """The lower-cased entity and seed values of a case (4+ characters) - what a URL must not carry
    to stay clickable above TLP:GREEN (:func:`reference_view`)."""
    values = {str(n.get("value") or "").strip().lower() for n in _l(case.get("entities")) if isinstance(n, dict)}
    values |= {s.partition(":")[2].strip().lower() for s in _seeds(case)}
    return frozenset(v for v in values if len(v) >= 4)


@functools.lru_cache(maxsize=16)
def _values_pattern(values: frozenset[str]) -> re.Pattern[str] | None:
    if not values:
        return None
    return re.compile("|".join(re.escape(v) for v in sorted(values, key=len, reverse=True)))


def _carries_value(case: Mapping[str, Any], url: str, values: frozenset[str] | None = None) -> bool:
    pattern = _values_pattern(values if values is not None else case_values(case))
    return bool(pattern is not None and pattern.search(url.lower()))


def reference_view(
    case: Mapping[str, Any], url: Any, *, no_defang: bool = False, targets: set[str] | None = None, values: frozenset[str] | None = None,
) -> tuple[str | None, str]:
    """``(href, text)`` of a finding reference or a module link (P336 cond 2-3): clickable (``href``)
    only for an http(s) URL (``ui.safe.safe_href``) whose host is an allow-listed documentation host
    (:data:`REFERENCE_HOSTS`), is not an investigated or hostile host, and - above TLP:GREEN - does
    not carry a case value. Otherwise ``href`` is None and ``text`` is the defanged URL. ``targets``:
    :func:`target_hosts` of the case and ``values`` its :func:`case_values` when the caller already
    computed them (renderers of large cases)."""
    from v3lum.core.entities import defang
    from v3lum.ui.safe import safe_href

    raw = clean_text(url).strip()
    href = safe_href(raw)
    text = defang(raw)
    if href is None:
        return None, text
    host = link_host({"url": href})
    if host not in REFERENCE_HOSTS:
        return None, text
    targets = targets if targets is not None else target_hosts(case)
    if _host_in(host, targets) or _host_in(host, {entity_host(s) for s in _seeds(case)} - {""}):
        return None, text
    if _tlp.parse(tlp_value(case)) > _tlp.TLP.GREEN and _carries_value(case, href, values):
        return None, text
    return href, (raw if no_defang else href)


def pivot_plan(
    case: Mapping[str, Any],
    *,
    show_personal: bool = False,
    no_defang: bool = False,
    full: bool = True,
    keys: Iterable[str] | None = None,
) -> PivotPlan:
    """The manual pivots of a case as reports show them (P311 cond 5/8/10, A2, P336 cond 3):

    * grouped per entity (seeds first) and per analyst question (``links.LINK_CATEGORIES`` order),
      manual fallbacks and verified links first, badges kept; duplicates of one URL merged;
    * clickable (``href``) only for pivot-pack templates (``ref``) at TLP:CLEAR/GREEN that do not touch
      the target; module links (no template) are clickable only to an allow-listed reference host
      (:func:`reference_view`); every other link is defanged plain text with ``'opening sends <value>
      to <host>'``;
    * touches_target links (declared, or to the investigated host or a hostile entity's host) are
      defanged and never clickable; for hostile entities they are hidden (counted in
      ``hidden_hostile``) unless ``full``, and with ``full`` marked ``collapsed`` (shown only when the
      analyst expands them);
    * at TLP:RED third-party links are hidden (``hidden_red``; only ``v3lum links`` shows them);
    * personal-data (privacy) links only for analyst-typed seeds and with ``show_personal``
      (P311 cond 6); non-http(s) URLs dropped;
    * a pack template whose URL host differs from its declared host is treated as a plain module
      link (never clickable as a template)."""
    from v3lum.core.entities import defang
    from v3lum.ui.safe import safe_href

    idx = CaseIndex(case, show_personal=show_personal, no_defang=no_defang)
    tlp = _tlp.parse(tlp_value(case))
    plan = PivotPlan(tlp=tlp_value(case), clickable=tlp <= _tlp.TLP.GREEN)
    links = _d(case.get("links"))
    seeds = _seeds(case)
    seed_set = set(seeds)
    wanted = [str(k) for k in keys] if keys is not None else seeds + sorted(k for k in links if k not in seed_set)
    try:
        from v3lum.core.links import LINK_CATEGORIES as cats
    except Exception:  # noqa: BLE001
        cats = ("other",)
    order = {c: i for i, c in enumerate(cats)}
    hostile_hosts = target_hosts(case, idx=idx)
    values = case_values(case)
    for key in wanted:
        candidates = merged_links(_l(links.get(key)))
        if not candidates:
            continue
        hostile = idx.hostile(key)
        own_host = entity_host(key)
        targets = hostile_hosts | ({own_host} if own_host else set())
        value = idx.display(key)
        items: list[PivotItem] = []
        for item in candidates:
            url = str(item.get("url") or "").strip()
            href = safe_href(url)
            if href is None:
                plan.dropped += 1
                continue
            host = link_host(item)
            declared = _declared_host(item)
            touches = bool(item.get("touches_target")) or _host_in(host, targets)
            if tlp >= _tlp.TLP.RED and not _internal_host(host):
                plan.hidden_red += 1
                continue
            if item.get("privacy") and not (show_personal and key in seed_set):
                plan.hidden_privacy += 1  # P311 cond 6: analyst-typed seeds of an opted-in view only
                continue
            collapsed = bool(touches and (hostile or _host_in(host, hostile_hosts - {own_host})))
            if collapsed and not full:
                plan.hidden_hostile += 1
                continue
            # a pack template is clickable only when its URL goes to the host the pack declares
            template = bool(item.get("ref")) and (not declared or declared == host)
            shown_host = clean_text(host) or "its host"
            clickable: str | None = None
            warning = ""
            if touches:
                warning = "opens the target (or makes a third party fetch it live): not clickable"
            elif template and plan.clickable:
                clickable = href
            elif template:
                warning = f"opening sends {value} to {shown_host}"
            else:
                ref_href, _ = reference_view(case, href, targets=hostile_hosts, values=values)
                clickable = ref_href
                if clickable is None:
                    warning = f"not a pivot template: opening sends {value} to {shown_host}"
            cat = str(item.get("category") or "other")
            items.append(PivotItem(
                label=clean_text(item.get("label") or host or "link"), url=href, host=clean_text(host), category=cat if cat in order else "other",
                href=clickable, text=href if clickable else defang(href), warning=warning, badge=clean_text(item.get("badge") or ""),
                note=clean_text(item.get("note") or ""), verified=bool(item.get("verified")), manual=bool(item.get("manual")), template=template,
                collapsed=collapsed,
            ))
        if not items:
            continue
        items.sort(key=lambda i: (not i.manual, not i.verified, order.get(i.category, len(order))))
        groups: dict[str, list[PivotItem]] = defaultdict(list)
        for it in items:
            groups[it.category].append(it)
        plan.entities.append(PivotEntity(
            key=key, display=value, seed=key in set(seeds),
            groups=[(c, groups[c]) for c in sorted(groups, key=lambda c: order.get(c, len(order)))],
        ))
    return plan


# ---------------------------------------------------------------------------------- appendices (A1, A8, P334, P377)


def appendix_licence(case: Mapping[str, Any]) -> dict[str, Any]:
    """The licence part of the coverage appendix (A1 BR6/BR21, P377 cond 4/5/8, P336 cond 6, P334
    cond 7): ``{profile, banner, skipped_line, lost, used, allow_entries, deferred}`` -
    ``banner`` the licence banner ('' when no noncommercial/license source ran in a corporate case),
    ``lost`` the 'Coverage lost under licence profile' lines per entity type (:func:`licence_lines`),
    ``used`` every noncommercial/license source used with its class and basis, ``allow_entries`` the
    licence_allow entries the run relied on (basis 'allow:<legal_ref>'), ``deferred`` one line per
    source (module) with lookups deferred by provider quota."""
    used = []
    allow = []
    for sid, info in sorted(_d(case.get("licence_used")).items()):
        info = _d(info)
        klass = clean_text(info.get("class") or "")
        basis = clean_text(info.get("basis") or "")
        if klass in _TERMS_LICENSED:
            used.append({"source": clean_text(sid), "class": klass, "basis": basis or "basis not recorded"})
        if basis.startswith("allow:"):
            allow.append({"source": clean_text(sid), "class": klass or "unknown", "legal_ref": basis.partition(":")[2] or "not recorded"})
    skips = {str(k): v for k, v in _d(case.get("skips")).items()}
    skipped_line = ""
    if skips.get("licence") or _licence_feed_ids(case, skips.get("licence", ())):
        skipped_line = next((line for line in skip_lines(case) if "licence profile" in line), "")
    deferred: dict[str, list[str]] = defaultdict(list)
    for d in _l(case.get("deferred")):
        if isinstance(d, dict):
            deferred[clean_text(d.get("module") or "?")].append(str(d.get("entity") or "").partition(":")[0] or "?")
    case_id = clean_text(case.get("case_id") or "<case>")
    deferred_lines = []
    for module, types in sorted(deferred.items()):
        counts = ", ".join(f"{n} {t}" for t, n in sorted({t: types.count(t) for t in types}.items()))
        deferred_lines.append(f"{module}: {_plural(len(types), 'lookup')} deferred by provider quota ({counts}) - v3lum cases resume {case_id}")
    return {
        "profile": _licence_profile(case),
        "banner": _licence_banner(case),
        "skipped_line": skipped_line,
        "lost": licence_lines(case),
        "used": used,
        "allow_entries": allow,
        "deferred": deferred_lines,
    }


def appendix_disclosure(case: Mapping[str, Any], *, show_personal: bool = False, no_defang: bool = False) -> dict[str, Any]:
    """The 'Disclosure ledger' appendix (A8): ``{line, recorded, hosts, by_entity}`` - ``line`` the
    header line 'value disclosed to N third-party providers', ``recorded`` False for a stored v1
    case, ``hosts`` one row per contacted host ``{host, provider, name, tier, terms, requests, role}``
    (role third party | internal | investigated target) from the runs' recorded host counts
    (runtime HTTP events, cached answers excluded), ``by_entity`` ``[(entity display, [providers])]``
    - which third-party providers received each value (displays masked/defanged)."""
    idx = CaseIndex(case, show_personal=show_personal, no_defang=no_defang)
    runs = [m for m in _l(case.get("modules")) if isinstance(m, dict)]
    recorded = not (runs and not any("hosts" in m for m in runs))
    hosts = []
    for host, row in disclosure_summary(case).items():
        role = "investigated target" if row.get("target") else "internal" if row.get("internal") else "third party"
        hosts.append({
            "host": clean_text(host), "provider": clean_text(row.get("provider") or ""), "name": clean_text(row.get("name") or ""),
            "tier": clean_text(row.get("tier") or "unknown"), "terms": clean_text(row.get("terms") or "unknown"),
            "requests": int(_num(row.get("requests"))), "role": role,
        })
    by_entity = [(idx.labelled(key), [clean_text(n) for n in names]) for key, names in disclosure_by_entity(case).items()]
    return {"line": _disclosure_line(case), "recorded": recorded, "hosts": hosts, "by_entity": by_entity}


# ---------------------------------------------------------------------------------- attributions (P336 cond 6)

#: Attributions for providers whose data licence requires one when no notice fragment covers them.
PROVIDER_ATTRIBUTIONS: dict[str, dict[str, str]] = {
    "hibp": {"name": "Have I Been Pwned", "licence": "CC-BY-4.0", "source_url": "https://haveibeenpwned.com/",
             "text": "Breach data from Have I Been Pwned (https://haveibeenpwned.com/), licensed under Creative Commons Attribution 4.0 International (CC BY 4.0)."},
    "openstreetmap": {"name": "OpenStreetMap", "licence": "ODbL-1.0", "source_url": "https://www.openstreetmap.org/copyright",
                      "text": "Map data © OpenStreetMap contributors, available under the Open Database License (ODbL)."},
    "dbip": {"name": "DB-IP", "licence": "CC-BY-4.0", "source_url": "https://db-ip.com",
             "text": "IP Geolocation by DB-IP (https://db-ip.com), licensed under Creative Commons Attribution 4.0 International (CC BY 4.0)."},
}
#: MITRE ATT&CK attribution used when ATT&CK ids appear and no notice fragment is installed.
ATTACK_ATTRIBUTION: dict[str, str] = {
    "name": "mitre_attack", "licence": "MITRE ATT&CK Terms of Use", "source_url": "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/",
    "text": "© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation (MITRE ATT&CK®).",
}
_NOTICES_DIR = Path(__file__).resolve().parent.parent / "data" / "notices"
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_NOTICE_CACHE: dict[str, Any] = {}


def _notices() -> list[dict[str, Any]]:
    """Every ``v3lum/data/notices/*.json`` fragment (cached per directory listing and mtimes)."""
    try:
        files = sorted(_NOTICES_DIR.glob("*.json"))
        stamp = tuple((f.name, f.stat().st_mtime_ns) for f in files)
    except OSError:
        return []
    if _NOTICE_CACHE.get("stamp") == stamp:
        return list(_NOTICE_CACHE.get("items") or [])
    items = []
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and data.get("name"):
            items.append(data)
    _NOTICE_CACHE.update(stamp=stamp, items=items)
    return list(items)


def _module_files(name: str) -> set[str]:
    """Repository-relative source files of a registered module (its class file, its spec file)."""
    try:
        from v3lum.core.module import REGISTRY
    except Exception:  # noqa: BLE001
        return set()
    cls = REGISTRY.get(name)
    if cls is None:
        return set()
    out: set[str] = set()
    try:
        src = inspect.getsourcefile(cls)
    except (TypeError, OSError):
        src = None
    for candidate in (src, getattr(cls, "spec_origin", None)):
        if not candidate:
            continue
        try:
            out.add(Path(str(candidate)).resolve().relative_to(_REPO_ROOT).as_posix())
        except (ValueError, OSError):
            continue
    return out


def _module_provider(name: str) -> str:
    try:
        from v3lum.core.module import REGISTRY
    except Exception:  # noqa: BLE001
        return ""
    cls = REGISTRY.get(name)
    return str(getattr(cls, "provider", "") or "") if cls is not None else ""


def _used_runs(case: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [m for m in _l(case.get("modules")) if isinstance(m, dict) and str(m.get("status") or "") in ("ok", "empty")]


def attributions(case: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Required attributions for the sources and datasets this case actually used (P336 cond 6),
    generated from metadata, never typed by hand: notice fragments (``v3lum/data/notices``) whose
    ``files`` name a module that answered (ok/empty) or whose name is a dataset the runs cited,
    the dataset registry's ``attribution`` of every cited dataset, :data:`PROVIDER_ATTRIBUTIONS` for
    providers whose answers were used, and MITRE ATT&CK whenever an ATT&CK id appears. Each item:
    ``{name, licence, text, source_url, used_by}`` (sorted by name, one per name)."""
    runs = _used_runs(case)
    modules = sorted({str(m.get("module") or "") for m in runs} - {""})
    datasets_used: dict[str, set[str]] = defaultdict(set)
    for m in runs:
        for d in _l(m.get("datasets")):
            if isinstance(d, dict) and d.get("name"):
                datasets_used[str(d["name"])].add(str(m.get("module") or ""))
    files: dict[str, set[str]] = defaultdict(set)
    for name in modules:
        for path in _module_files(name):
            files[path].add(name)
    out: dict[str, dict[str, Any]] = {}

    def add(name: str, licence: str, text: str, url: str, used_by: Iterable[str]) -> None:
        text = clean_text(text).strip()
        if not text:
            return
        key = clean_text(name) or text[:40]
        row = out.setdefault(key, {"name": key, "licence": clean_text(licence), "text": _clip(text, 1200), "source_url": clean_text(url), "used_by": set()})
        row["used_by"].update(u for u in used_by if u)

    for notice in _notices():
        name = str(notice.get("name") or "")
        users: set[str] = set()
        for path in _l(notice.get("files")):
            users |= files.get(str(path), set())
        users |= datasets_used.get(name, set())
        if users:
            add(name, str(notice.get("licence") or ""), str(notice.get("attribution") or ""), str(notice.get("source_url") or ""), users)
    try:
        from v3lum.core.datasets import DATASETS
    except Exception:  # noqa: BLE001
        DATASETS = {}  # noqa: N806
    for ds, users in sorted(datasets_used.items()):
        reg = DATASETS.get(ds) or {}
        if reg.get("attribution") and not any(row["text"] == clean_text(reg["attribution"]).strip() for row in out.values()):
            add(f"dataset {ds}", str(reg.get("licence") or ""), str(reg["attribution"]), "", users)
    providers: dict[str, set[str]] = defaultdict(set)
    for name in modules:
        pid = _module_provider(name)
        if pid:
            providers[pid].add(name)
    reg = _registry()
    for m in runs:
        for host in _d(m.get("hosts")):
            try:
                prov = reg.provider_for_host(str(host)) if reg is not None else None
            except Exception:  # noqa: BLE001
                prov = None
            if prov is not None:
                providers[str(prov.id)].add(str(m.get("module") or ""))
    for pid, users in sorted(providers.items()):
        info = PROVIDER_ATTRIBUTIONS.get(pid)
        if info and not any(info["name"].lower() in row["text"].lower() for row in out.values()):
            add(info["name"], info["licence"], info["text"], info["source_url"], users)
    attack_users = sorted({
        str(item.get("module") or item.get("rule") or "")
        for item in _l(case.get("findings")) + _l(case.get("correlations"))
        if isinstance(item, dict) and _l(item.get("attack"))
    } - {""})
    if attack_users and not any(row["name"] == "mitre_attack" for row in out.values()):
        notice = next((n for n in _notices() if n.get("name") == "mitre_attack"), None)
        if notice:
            add("mitre_attack", str(notice.get("licence") or ""), str(notice.get("attribution") or ""), str(notice.get("source_url") or ""), attack_users)
        else:
            add(ATTACK_ATTRIBUTION["name"], ATTACK_ATTRIBUTION["licence"], ATTACK_ATTRIBUTION["text"], ATTACK_ATTRIBUTION["source_url"], attack_users)
    elif attack_users:
        out["mitre_attack"]["used_by"].update(attack_users)
    return [{**row, "used_by": sorted(row["used_by"])} for _k, row in sorted(out.items(), key=lambda kv: kv[0].lower())]


# ---------------------------------------------------------------------------------- content hash note (P336 cond 4)

#: Marker that ends the hashed content of an HTML/Markdown report (the footer note follows it).
CONTENT_END_MARKER = "<!--v3lum:content-end-->"


def content_hash(text: str) -> str:
    """SHA-256 (hex) of the report content above :data:`CONTENT_END_MARKER` (UTF-8 bytes)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def content_hash_note(digest: str) -> str:
    """The footer hash note: it states that it covers the content above it (a file cannot contain its
    own hash; the whole file's SHA-256 is in the ``<report>.sha256`` sidecar and the case DB)."""
    return (
        f"SHA-256 of the report content above this note (every byte before the marker '{CONTENT_END_MARKER}'): {digest}. "
        "The SHA-256 of the whole file is in its .sha256 sidecar and in the case DB (v3lum cases verify)."
    )
