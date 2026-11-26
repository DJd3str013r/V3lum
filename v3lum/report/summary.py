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
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from v3lum.core import tlp as _tlp
from v3lum.core.entities import EntityType
from v3lum.ui.safe import DEFANG_TAGS, clean_text, display_text, entity_display

__all__ = [
    "CONFIDENCE_LABELS",
    "CaseIndex",
    "INCONCLUSIVE",
    "LEVEL_ORDER",
    "MIN_REPUTATION_ANSWERS",
    "NO_FINDINGS",
    "SCORE_LABEL",
    "bottom_line",
    "case_level",
    "confidence_label",
    "disclosure_by_entity",
    "disclosure_summary",
    "entity_host",
    "followup_lines",
    "header_items",
    "header_lines",
    "is_identity_link",
    "is_partial_note",
    "level_label",
    "licence_lines",
    "note_lines",
    "partial_notes",
    "seed_inconclusive",
    "seed_level",
    "skip_lines",
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
        line = f"refused: {_target_text(idx, r.get('target'))} ({r.get('module', '?')}: {r.get('reason_code', '?')}) {r.get('reason', '')}".rstrip()
        lines.append(idx.text(line) if idx is not None else display_text(line))
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
    items += [("engagement", line) for line in _engagement_lines(case, idx)]
    items += [("partial", f"PARTIAL RESULT: {note}") for note in partial_notes(case, show_personal=show_personal)]
    seeds = _seeds(case)
    shown = seeds if max_seeds is None or max_seeds < 0 else seeds[:max_seeds]
    items += [("answered", _answered_line(case, idx, seed)) for seed in shown]
    if len(shown) < len(seeds):
        items.append(("answered", _answered_rest(case, seeds[len(shown):])))
    items.append(("disclosure", _disclosure_line(case)))
    banner = _licence_banner(case)
    if banner:
        items.append(("licence", banner))
    purpose = idx.text(_purpose_line(case))  # analyst-typed, but a CPF in it stays masked too
    if purpose:
        items.append(("purpose", purpose))
    for note in _l(_d(case.get("meta")).get("header_notes")):
        text = idx.text(note).strip()
        if text:
            items.append(("note", text))
    return items


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
        for f in sorted(cands, key=_rank, reverse=True)[:3]:
            who = idx.display(str(f.get("entity"))) if f.get("entity") else "case"
            out.append(f"{who}: {_clip(idx.text(f.get('title')), 110)} ({_sev_word(f)}) [{confidence_label(f).upper()}]")
    return out[:3]


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
