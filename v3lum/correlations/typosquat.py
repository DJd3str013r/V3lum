"""Correlation pack: typosquat and brand abuse (P028: CR04, CR05, CR06, CR35).

The pack only correlates facts other modules already recorded; it never contacts a candidate
domain, never schedules modules or pivots and never sends anything anywhere (P028 cond 3, 11):

* **CR04** ``typosquat_phishing_capable`` - HIGH: a registered lookalike with a mail exchanger,
  registered at most :data:`PHISHING_CAPABLE_MAX_AGE_DAYS` days ago (RDAP), whose registrant, NS and
  MX are not the brand's. POSSIBLE while RDAP is redacted or unavailable (P028 cond 1, 5).
* **CR05** ``typosquat_with_fresh_certificate`` - HIGH: the FIRST certificate ever logged for the
  name (earliest ``first_cert_seen`` not_before, Certificate Transparency) is at most
  :data:`FRESH_CERT_MAX_AGE_DAYS` days old; the latest auto-renewal never counts (P028 cond 1).
* **CR06** ``typosquat_on_malicious_infra`` - CRITICAL only when >= :data:`CONSENSUS_MIN_FAMILIES`
  independent upstream families (P171 definition: registry ``upstream_family`` plus ``embeds``,
  after warninglist/sinkhole/benign-scanner suppression and inside the P171 decay window) list an
  address the lookalike resolves to, and that address is neither a CDN nor a hosting edge
  (``is_cdn``/``is_hosting`` false) nor a sinkhole and carries fewer than
  :data:`SHARED_HOSTING_MIN_NAMES` co-hosted names. Otherwise HIGH. Shared-hosting listings never
  count unless the domain itself is flagged (P028 cond 6).
* **CR35** ``new_brand_keyword_domain`` - MEDIUM: a domain at most
  :data:`NEW_DOMAIN_MAX_AGE_DAYS` days old whose name combines an org brand keyword with a lure word
  of ``v3lum/data/brand_lures_pt.json``, matched after IDNA->Unicode, accent and homoglyph folding
  (:func:`fold_text`; P028 cond 2, 8).

Protected brands, domains and name servers come only from the organisation profile
(``rctx.org``, its suppliers included): nothing is hard-coded and without a profile no rule fires
(P028 cond 4). Own assets are never flagged (P028 cond 5, :func:`suppression_reason`): profile
domains, domains whose RDAP registrant CNPJ root (registro.br publicIds) or NS/MX hosts match the
profile, BCB DominiosVerificados domains (P360, ``verified_fi``) and own/defensive registrations the
P012 typosquat module already established. Parked lookalikes are capped at MEDIUM with a 'parked'
label (cond 7). Wording is 'lookalike / phishing-capable indicator', never 'malicious' unless the
CR06 consensus holds (cond 9); takedown and abuse reports stay manual, separately approved actions.
A registrant CNPJ is noted for the analyst's company due diligence; CPF registrants and
legalRepresentative names never appear (cond 10). Values are shown defanged with a one-line
evidence chain (cond 11).
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import threading
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from v3lum.core import entities as _entities
from v3lum.core import noise, psl
from v3lum.core.correlate import rule
from v3lum.core.entities import Entity, EntityType
from v3lum.core.graph import Edge, Graph, Node
from v3lum.core.models import Confidence, Correlation, Finding, ModuleResult, Severity
from v3lum.core.orgprofile import fold as _accent_fold

__all__ = [
    "Brand",
    "ListingVote",
    "LookalikeFacts",
    "RULE_BRAND_KEYWORD",
    "RULE_FRESH_CERT",
    "RULE_MALICIOUS_INFRA",
    "RULE_PHISHING_CAPABLE",
    "brand_matches",
    "fold_text",
    "independent_families",
    "lookalike_candidates",
    "lure_matches",
    "lure_words",
    "module_vote",
    "protected_brands",
    "provider_registry",
    "source_vote",
    "suppression_reason",
]

# ----------------------------------------------------------------------------------------
# Rule ids and named constants (one place, P028 cond 1-8)
# ----------------------------------------------------------------------------------------

RULE_PHISHING_CAPABLE = "typosquat_phishing_capable"  # CR04
RULE_FRESH_CERT = "typosquat_with_fresh_certificate"  # CR05
RULE_MALICIOUS_INFRA = "typosquat_on_malicious_infra"  # CR06
RULE_BRAND_KEYWORD = "new_brand_keyword_domain"  # CR35

#: CR04: a lookalike registered at most this many days ago (RDAP) with MX is phishing-capable.
PHISHING_CAPABLE_MAX_AGE_DAYS = 90
#: CR05: the FIRST certificate ever logged for the name is at most this many days old.
FRESH_CERT_MAX_AGE_DAYS = 30
#: CR35: a domain at most this many days old combining a brand keyword with a lure word.
NEW_DOMAIN_MAX_AGE_DAYS = 30
#: CR06: CRITICAL needs at least this many independent upstream families listing the address.
CONSENSUS_MIN_FAMILIES = 2
#: CR06: an address with this many co-hosted names or more is shared hosting.
SHARED_HOSTING_MIN_NAMES = 50
#: P171 cond 4 decay windows: older listings are history and are not counted (days).
IP_LISTING_WINDOW_DAYS = 30
DOMAIN_LISTING_WINDOW_DAYS = 90
#: P028 cond 7: parked (and sinkholed) lookalikes never exceed this severity.
PARKED_CAP = Severity.MEDIUM
#: Brand keywords shorter than this match only as a whole hyphen/underscore token.
BRAND_SUBSTRING_MIN = 4
#: Brand keywords at least this long also match one edit away (a typo of the brand).
BRAND_TYPO_MIN = 5
#: Lure words shorter than this match only as a whole token (the P376 guard uses the same rule).
LURE_SUBSTRING_MIN = 5
#: Folded brand keys shorter than this are ignored (too ambiguous to protect).
BRAND_MIN_LENGTH = 3
#: Finding tags that list an entity as hostile (TI verdicts read by CR06).
LISTING_TAGS = frozenset({"malicious", "phishing", "malware", "c2", "botnet"})
#: Entity tags that take an address out of the consensus (suppression runs before CR06, P171 cond 5).
NON_COUNTING_TAGS = frozenset({"sinkhole", "benign_scanner", "warninglist", "known_good"})
#: cloud_role values of shared front doors (p1-G02-1 cloud_ranges): never consensus for the names behind them.
SHARED_CLOUD_ROLES = frozenset({"cdn_edge", "shared_hosting", "shared_service", "shared_proxy"})
#: Noise kinds of shared infrastructure (noise.CDN_KINDS).
SHARED_NOISE_KINDS = frozenset({"cdn", "cloud", "hosting", "saas"})
#: Analyst override verdicts that take a finding out of the evidence.
FALSE_POSITIVE_VERDICTS = frozenset({"false_positive", "false positive", "fp", "benign", "wrong", "negative", "not_malicious"})
#: The shared lure list (P028 cond 8).
LURES_PATH: Path = Path(__file__).resolve().parent.parent / "data" / "brand_lures_pt.json"
#: Mandatory wording (P028 cond 9).
WORDING = "lookalike / phishing-capable indicator"
NOT_A_VERDICT = "This is not a verdict of maliciousness and the registrant (possibly a natural person) is not judged."
NO_TAKEDOWN = ("No automated takedown or abuse report: notifying the registrar or hosting provider is a manual, "
               "separately approved action.")

_REFERENCES = (
    "https://attack.mitre.org/techniques/T1583/001/",
    "https://github.com/elceef/dnstwist",
)
_UTC = _dt.timezone.utc

# ----------------------------------------------------------------------------------------
# Folding: IDNA -> Unicode, accents, homoglyphs (P028 cond 8; same table as the P376 guard)
# ----------------------------------------------------------------------------------------

_CONFUSABLES = str.maketrans({
    "0": "o", "1": "l", "i": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s", "@": "a",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "l", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "ο": "o", "α": "a", "ν": "v", "ι": "l", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ε": "e",
    "ɑ": "a", "ɡ": "g", "ı": "l", "ł": "l", "ø": "o", "đ": "d", "ħ": "h", "ŀ": "l", "ß": "ss", "æ": "ae", "œ": "oe",
})
_SEQUENCES = (("rn", "m"), ("vv", "w"), ("cl", "d"))
_SPLIT = re.compile(r"[-_]")


def _unicode_label(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            return label
    return label


def fold_text(text: Any) -> str:
    """The comparison form of a name or word: IDNA labels decoded to Unicode, accents removed,
    lower-case, homoglyphs folded (Cyrillic/Greek look-alikes, 0->o, 1/i->l, 3->e, 4->a, rn->m...).

    Brand keywords, lure words and candidate domains are folded the same way, so 'аcmе-рix' (Cyrillic),
    'acrne-pix' and 'acmé-pix' all read 'acme-plx' (P028 cond 8)."""
    labels = [_unicode_label(lb) for lb in str(text or "").strip().lower().split(".")]
    out = _accent_fold(".".join(labels)).translate(_CONFUSABLES)
    for seq, repl in _SEQUENCES:
        out = out.replace(seq, repl)
    return out


def _key(text: Any) -> str:
    """Folded form without spaces, hyphens and underscores (brand and lure keys)."""
    return re.sub(r"[\s_-]+", "", fold_text(text))


def owner_labels(domain: str) -> list[str]:
    """The labels a registrant chose (subdomains + registrable label, public suffix removed), folded."""
    host = str(domain or "").strip().lower().rstrip(".")
    if not host:
        return []
    labels = host.split(".")
    try:
        reg = psl.registrable_domain(host)
    except Exception:  # noqa: BLE001 - an odd name keeps all its labels
        reg = None
    if reg:
        suffix_labels = reg.count(".")
        labels = labels[: len(labels) - suffix_labels] if suffix_labels else labels
    return [fold_text(lb) for lb in labels if lb]


def _distance_le1(a: str, b: str) -> bool:
    """Damerau-Levenshtein distance <= 1 (one insertion, deletion, substitution or swap)."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diff = [i for i in range(la) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    if la > lb:
        a, b = b, a
    return any(b[:i] + b[i + 1:] == a for i in range(len(b)))


# ----------------------------------------------------------------------------------------
# Lure words (v3lum/data/brand_lures_pt.json)
# ----------------------------------------------------------------------------------------

_LURE_LOCK = threading.Lock()
_LURE_CACHE: dict[tuple[str, int, int], tuple[str, ...]] = {}


def lure_words(path: str | Path | None = None) -> tuple[str, ...]:
    """The lure words of ``v3lum/data/brand_lures_pt.json`` ('pt', 'en' and 'words' lists, order kept,
    de-duplicated); ``()`` when the file is missing or unreadable (CR35 then never fires)."""
    p = Path(path) if path is not None else Path(LURES_PATH)
    try:
        st = p.stat()
    except OSError:
        return ()
    stamp = (str(p), st.st_mtime_ns, st.st_size)
    with _LURE_LOCK:
        cached = _LURE_CACHE.get(stamp)
    if cached is not None:
        return cached
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return ()
    words: list[str] = []
    lists = [doc] if isinstance(doc, list) else [doc.get(k) for k in ("pt", "en", "words")] if isinstance(doc, Mapping) else []
    for values in lists:
        for word in values if isinstance(values, list) else ():
            text = str(word or "").strip().lower()
            if text and text not in words:
                words.append(text)
    result = tuple(words)
    with _LURE_LOCK:
        _LURE_CACHE.clear()
        _LURE_CACHE[stamp] = result
    return result


# ----------------------------------------------------------------------------------------
# Protected brands (org profile only, suppliers included; P028 cond 4)
# ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Brand:
    """A protected keyword: ``term`` as written in the profile, ``key`` its folded comparison form,
    ``origin`` 'brand' | 'variant' | 'supplier brand' | 'domain' | 'supplier domain'."""

    term: str
    key: str
    origin: str


def _has_profile(org: Any) -> bool:
    if org is None or getattr(org, "is_empty", True):
        return False
    return bool(getattr(org, "domains", None) or getattr(org, "brands", None) or getattr(org, "suppliers", None))


def _registrable_label(domain: str) -> str:
    reg = psl.registrable_domain(domain) or domain
    return reg.split(".", 1)[0]


def protected_brands(org: Any) -> list[Brand]:
    """Brand keywords protected by the organisation profile: its brands and their variants, the
    suppliers' brands and the registrable labels of its own and its suppliers' domains. Empty without
    a profile (no hard-coded brand ever, P028 cond 4)."""
    if not _has_profile(org):
        return []
    out: list[Brand] = []
    seen: set[str] = set()

    def add(term: Any, origin: str) -> None:
        key = _key(term)
        if len(key) >= BRAND_MIN_LENGTH and key not in seen:
            seen.add(key)
            out.append(Brand(str(term), key, origin))

    for brand in getattr(org, "brands", ()) or ():
        add(brand.keyword, "brand")
        for variant in brand.variants:
            add(variant, "variant")
    for supplier in getattr(org, "suppliers", ()) or ():
        for term in supplier.brands:
            add(term, "supplier brand")
    for entry in getattr(org, "domains", ()) or ():
        add(_registrable_label(entry.name), "domain")
    for supplier in getattr(org, "suppliers", ()) or ():
        for dom in supplier.domains:
            add(_registrable_label(dom), "supplier domain")
    return out


def brand_matches(domain: str, brands: Iterable[Brand]) -> list[tuple[Brand, str]]:
    """Protected brands the domain's owner labels carry: ``(brand, technique)`` with technique
    'brand-label' (a whole hyphen token), 'brand-in-label' (inside a label, keys of 4+ characters) or
    'typo' (one edit away, keys of 5+ characters); all after :func:`fold_text`."""
    labels = owner_labels(domain)
    hits: list[tuple[Brand, str]] = []
    for brand in brands:
        technique = ""
        for label in labels:
            tokens = [t for t in _SPLIT.split(label) if t]
            flat = "".join(tokens)
            if brand.key in tokens or brand.key == flat:
                technique = "brand-label"
            elif len(brand.key) >= BRAND_SUBSTRING_MIN and brand.key in flat:
                technique = "brand-in-label"
            elif len(brand.key) >= BRAND_TYPO_MIN and any(_distance_le1(t, brand.key) for t in [*tokens, flat]):
                technique = "typo"
            if technique:
                break
        if technique:
            hits.append((brand, technique))
    return hits


def lure_matches(domain: str, brand_key: str, words: Iterable[str]) -> list[str]:
    """Lure words in the domain's owner labels once the brand occurrence is removed (the brand never
    counts as its own lure): whole tokens, or inside a label for words of 5+ characters."""
    rest: list[str] = []
    removed = False
    for label in owner_labels(domain):
        for token in (t for t in _SPLIT.split(label) if t):
            if not removed and brand_key and brand_key in token:
                before, _, after = token.partition(brand_key)
                rest.extend(x for x in (before, after) if x)
                removed = True
            else:
                rest.append(token)
    joined = "".join(rest)
    hits: list[str] = []
    for word in words:
        key = _key(word)
        if not key or word in hits:
            continue
        if key in rest or (len(key) >= LURE_SUBSTRING_MIN and (key in joined or any(key in t for t in rest))):
            hits.append(word)
    return hits


# ----------------------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------------------


def _date(value: Any) -> _dt.datetime | None:
    """An aware UTC datetime for ISO dates/datetimes ('2026-11-14', '2026-11-14T10:00:00Z')."""
    if isinstance(value, _dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=_UTC)
    if isinstance(value, _dt.date):
        return _dt.datetime(value.year, value.month, value.day, tzinfo=_UTC)
    text = str(value or "").strip()
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", text)
    if not m:
        return None
    if len(text) > 10:
        try:
            parsed = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=_UTC)
        except ValueError:
            pass
    try:
        return _dt.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=_UTC)
    except ValueError:
        return None


def _days(then: _dt.datetime | None, now: _dt.datetime) -> int | None:
    if then is None:
        return None
    return max(0, (now - then).days)


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _now(rctx: Any) -> _dt.datetime:
    now = getattr(rctx, "now", None)
    if isinstance(now, _dt.datetime):
        return now if now.tzinfo else now.replace(tzinfo=_UTC)
    return _dt.datetime.now(_UTC)


def _host(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _real_mx(value: Any) -> str:
    """The MX host of an attribute value ('10 mx.example' or 'mx.example'); '' for a null MX ('.')."""
    text = str(value.get("host") or value.get("exchange") or "") if isinstance(value, Mapping) else str(value or "")
    host = _host(text.split()[-1] if text.split() else "")
    return "" if host in ("", ".") else host


def _domain_entity(host: str) -> Entity | None:
    return Entity.try_make(EntityType.DOMAIN, host) if host else None


def _display(domain: str) -> str:
    """Defanged domain, with its Unicode form when it is an IDN (P028 cond 11)."""
    shown = _entities.defang(domain)
    unicode = ".".join(_unicode_label(lb) for lb in domain.split("."))
    return f"{shown} ({_entities.defang(unicode)})" if unicode != domain else shown


def _evidence_finding(f: Finding) -> bool:
    """May ``f`` count as a listing? Not when it is context only or was downgraded by a core
    suppression rule (SUP-*); an analyst override keeps it unless its verdict is a false positive."""
    override = f.override if isinstance(f.override, dict) else None
    if override:
        return str(override.get("verdict") or "").strip().lower() not in FALSE_POSITIVE_VERDICTS
    if "context_only" in f.tags:
        return False
    return not any(
        str(s.get("rule", "")).startswith("SUP-") and not s.get("blocked_by") for s in f.suppressed_by or () if isinstance(s, dict)
    )


class _Edges:
    """Edges indexed once per rule run (graph.out_edges/in_edges scan every edge each call)."""

    def __init__(self, graph: Graph) -> None:
        self.out: dict[str, list[Edge]] = {}
        self.into: dict[str, list[Edge]] = {}
        for edge in graph.edges:
            self.out.setdefault(edge.src, []).append(edge)
            self.into.setdefault(edge.dst, []).append(edge)

    def targets(self, key: str, relation: str) -> list[str]:
        return [e.dst for e in self.out.get(key, ()) if e.relation == relation]

    def sources(self, key: str, relation: str) -> list[str]:
        return [e.src for e in self.into.get(key, ()) if e.relation == relation]


# ----------------------------------------------------------------------------------------
# Threat-intel families (P171 definition) for CR06
# ----------------------------------------------------------------------------------------


def provider_registry(rctx: Any) -> Any:
    """The provider registry of the rule context (``rctx.providers``), else the loaded registry; None
    when neither is available (source ids then stand for their own family)."""
    reg = getattr(rctx, "providers", None)
    if reg is not None:
        return reg
    try:
        from v3lum.core import providers

        return providers.registry()
    except Exception:  # noqa: BLE001 - without a registry source ids stand for themselves
        return None


@dataclass(frozen=True)
class ListingVote:
    """One current listing: ``families`` = the source's upstream family plus the families it embeds
    (an aggregate names one of them, we do not know which); ``primary`` = its own upstream family."""

    label: str
    families: frozenset[str]
    primary: str


def source_vote(source_id: str, registry: Any) -> ListingVote | None:
    """The vote of a registry source id ('<provider>.<source>'): its upstream family plus the families
    it embeds; an unregistered id stands for its provider prefix. None for an empty id."""
    sid = str(source_id or "").strip()
    if not sid:
        return None
    src = None
    if registry is not None:
        try:
            src = registry.source(sid)
        except Exception:  # noqa: BLE001
            src = None
    if src is not None and getattr(src, "upstream_family", ""):
        fams = frozenset(getattr(src, "families", ()) or ()) or frozenset({src.upstream_family})
        return ListingVote(sid, fams, src.upstream_family)
    fam = sid.split(".", 1)[0]
    return ListingVote(sid, frozenset({fam}), fam)


def module_vote(module: str, registry: Any) -> ListingVote | None:
    """The vote of a module whose finding or attribute names no source: the union of its declared
    sources' families (an unregistered module stands for itself, 'module:<name>')."""
    if not module:
        return None
    try:
        from v3lum.core.module import REGISTRY  # lazy: module.py imports models

        cls = REGISTRY.get(module)
    except Exception:  # noqa: BLE001
        cls = None
    votes = [v for v in (source_vote(sid, registry) for sid in getattr(cls, "sources", ()) or ()) if v is not None]
    if not votes:
        return ListingVote(module, frozenset({f"module:{module}"}), f"module:{module}")
    fams = frozenset(f for v in votes for f in v.families)
    primary = votes[0].primary if len({v.primary for v in votes}) == 1 else "+".join(sorted({v.primary for v in votes}))
    return ListingVote(module, fams, primary)


def independent_families(votes: Iterable[ListingVote]) -> list[str]:
    """Independent upstream families among listings (P171 cond 2-3): direct sources first, then an
    aggregate (FireHOL, IPsum, OTX relays...) only when it shares no family with a vote already
    counted, so two modules re-serving one upstream count once."""
    counted: list[str] = []
    taken: set[str] = set()
    for vote in sorted(votes, key=lambda v: (len(v.families), v.label)):
        if vote.families & taken:
            continue
        taken |= vote.families
        if vote.primary not in counted:
            counted.append(vote.primary)
    return counted


def _listing_votes(node: Node, now: _dt.datetime, window_days: int, registry: Any) -> list[ListingVote]:
    """The CURRENT listings of a node: evidence findings tagged as listings inside the decay window
    (never 'historical'), ``malicious`` attributes and ``blocklist_families`` (already families)."""
    votes: list[ListingVote] = []
    for f in node.findings:
        if not (set(f.tags) & LISTING_TAGS) or "historical" in f.tags or not _evidence_finding(f):
            continue
        seen = _date(f.observed_last) or _date(f.observed_first)
        if seen is not None and (now - seen).days > window_days:
            continue  # older listings are history, not counted (P171 cond 4)
        vote = source_vote(f.source, registry) if f.source else module_vote(f.module, registry)
        if vote is not None:
            votes.append(vote)
    for value, src in node.attributes.get("malicious", []):
        if value is True:
            vote = module_vote(src, registry)
            if vote is not None:
                votes.append(vote)
    for fam in node.attr_values("blocklist_families"):
        if isinstance(fam, str) and fam.strip():
            votes.append(ListingVote(f"blocklist_families:{fam.strip()}", frozenset({fam.strip()}), fam.strip()))
    return votes


def _warninglisted(entity: Entity) -> bool:
    try:
        return bool(noise.warninglists(entity))
    except Exception:  # noqa: BLE001 - list problems are reported by noise.errors()
        return False


@dataclass
class _Address:
    value: str
    votes: list[ListingVote] = field(default_factory=list)
    shared: bool = False
    cdn: bool = False
    hosting: bool = False
    sinkhole: bool = False
    parked: bool = False
    suppressed: str = ""
    cohosted: int = 0

    @property
    def families(self) -> list[str]:
        """Independent upstream families listing the address."""
        return independent_families(self.votes)

    @property
    def dedicated(self) -> bool:
        return not (self.cdn or self.hosting or self.shared or self.sinkhole) and self.cohosted < SHARED_HOSTING_MIN_NAMES


def _address(graph: Graph, edges: _Edges, value: str, now: _dt.datetime, registry: Any) -> _Address:
    etype = EntityType.IPV6 if ":" in value else EntityType.IPV4
    ent = Entity.try_make(etype, value)
    addr = _Address(value)
    node = graph.get(ent) if ent is not None else None
    kinds: set[str] = set()
    if ent is not None:
        try:
            kinds = set(noise.noise_kinds(ent))
        except Exception:  # noqa: BLE001
            kinds = set()
    if node is not None:
        kinds.add(node.noise_kind)
        bools = {name: any(v is True for v in node.attr_values(name)) for name in ("is_cdn", "is_hosting", "shared_ip", "is_sinkhole", "is_parked")}
        addr.cdn = bools["is_cdn"]
        addr.hosting = bools["is_hosting"]
        addr.shared = bools["shared_ip"] or bool(set(map(str, node.attr_values("cloud_role"))) & SHARED_CLOUD_ROLES)
        addr.sinkhole = bools["is_sinkhole"] or "sinkhole" in node.tags
        addr.parked = bools["is_parked"] or "parked" in node.tags
        counts = [len(node.attr_values("hostnames")), len(edges.targets(node.key, "hosted_domain"))]
        counts += [n for n in (_int(v) for v in node.attr_values("cohosted_count")) if n is not None]
        addr.cohosted = max(counts)
        if node.tags & NON_COUNTING_TAGS:
            addr.suppressed = "tagged " + ", ".join(sorted(node.tags & NON_COUNTING_TAGS))
    addr.cdn = addr.cdn or "cdn" in kinds
    addr.shared = addr.shared or bool(kinds & SHARED_NOISE_KINDS)
    addr.sinkhole = addr.sinkhole or "sinkhole" in kinds
    addr.parked = addr.parked or "parked" in kinds
    if ent is not None and _warninglisted(ent):
        addr.suppressed = addr.suppressed or "on a warninglist"
    if node is not None and not addr.suppressed and not addr.sinkhole:
        addr.votes = _listing_votes(node, now, IP_LISTING_WINDOW_DAYS, registry)
    return addr


# ----------------------------------------------------------------------------------------
# Lookalike candidates and their facts
# ----------------------------------------------------------------------------------------


@dataclass
class LookalikeFacts:
    """What the graph says about one lookalike candidate (nothing is ever fetched)."""

    node: Node
    domain: str
    targets: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    brands: list[tuple[Brand, str]] = field(default_factory=list)
    registered: bool | None = None
    rdap: str = "unavailable"  # ok | redacted | unavailable
    registrant_kind: str = ""
    registrant_roots: list[str] = field(default_factory=list)
    registrant_cnpjs: list[str] = field(default_factory=list)
    created: _dt.datetime | None = None
    age_days: int | None = None
    newly_registered: bool = False
    mx: list[str] = field(default_factory=list)
    mx_unnamed: bool = False
    ns: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    first_cert: _dt.datetime | None = None
    fresh_cert_signal: bool = False
    parked: bool = False
    sinkhole: bool = False
    row: dict[str, Any] = field(default_factory=dict)
    supporting: list[str] = field(default_factory=list)

    @property
    def has_mx(self) -> bool:
        return bool(self.mx) or self.mx_unnamed


#: P012 ownership verdicts that make a candidate an own or defensive registration (never flagged).
OWN_ROW_VERDICTS = frozenset({"own_asset", "defensive_probable"})


def _rows_index(graph: Graph) -> dict[str, dict[str, Any]]:
    """Forward-scan rows of the P012 typosquat module (``typosquat_lookalikes`` tables and the data of
    its 'Registered lookalike domain' findings) by candidate domain: facts for candidates the scan only
    listed (expand=False pivots are never investigated by other modules).

    The module lists own and defensive registrations apart (``typosquat_own_registrations``
    ``{domain, ownership, evidence}``, never in the lookalike table and never pivoted): their verdict
    is merged first and always wins, so the same name reaching the graph through another module (an
    NRD feed, CT, a reverse match) stays suppressed (P028 cond 5, 12)."""
    rows: dict[str, dict[str, Any]] = {}
    for node in graph.nodes.values():
        for own in node.attr_values("typosquat_own_registrations"):
            if not isinstance(own, Mapping):
                continue
            dom = _host(own.get("domain"))
            verdict = str(own.get("ownership") or "own_asset")
            if not dom or verdict not in OWN_ROW_VERDICTS:
                continue
            merged = rows.setdefault(dom, {})
            merged["ownership"] = verdict
            merged["ownership_evidence"] = _str_list(own.get("evidence") or own.get("ownership_evidence")) or [
                "P012 own or defensive registration"]
    for node in graph.nodes.values():
        items = list(node.attr_values("typosquat_lookalikes"))
        items += [f.data for f in node.findings if isinstance(f.data, dict) and f.data.get("domain") and "typosquat" in f.tags]
        for row in items:
            if not isinstance(row, Mapping):
                continue
            dom = _host(row.get("domain"))
            if not dom:
                continue
            merged = rows.setdefault(dom, {})
            for k, v in row.items():
                if v not in (None, "", [], {}) and k not in merged:
                    merged[k] = v
    return rows


def _str_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)] if value not in (None, "", False, True) else []


def _cnpj_root(value: Any) -> str:
    text = re.sub(r"[^0-9A-Za-z]", "", str(value or "")).upper()
    return text[:8] if len(text) in (8, 14) else ""


def _facts(graph: Graph, edges: _Edges, node: Node, rows: Mapping[str, dict[str, Any]], now: _dt.datetime) -> LookalikeFacts:
    domain = node.entity.value
    facts = LookalikeFacts(node=node, domain=domain, row=dict(rows.get(domain) or {}))
    row = facts.row
    reg_name = psl.registrable_domain(domain) or domain
    reg_node = graph.get(f"domain:{reg_name}") if reg_name != domain else None
    sources = [node] + ([reg_node] if reg_node is not None else [])

    mx = [_real_mx(v) for v in node.attr_values("mx")] + edges.targets(node.key, "mx_host") + _str_list(row.get("mx"))
    facts.mx = sorted({_host(h.split(":", 1)[-1]) for h in mx if _host(h.split(":", 1)[-1]) not in ("", ".")})
    facts.mx_unnamed = not facts.mx and row.get("mx_present") is True
    ns = node.attr_values("nameservers") + [k.split(":", 1)[-1] for k in edges.targets(node.key, "nameserver")] + _str_list(row.get("ns"))
    facts.ns = sorted({_host(h) for h in ns if _host(h)})
    ips = node.attr_values("a_records") + node.attr_values("aaaa_records") + _str_list(row.get("a"))
    ips += [k.split(":", 1)[-1] for k in edges.targets(node.key, "resolves_to") if k.startswith(("ipv4:", "ipv6:"))]
    facts.ips = sorted({str(ip).strip() for ip in ips if str(ip).strip()})

    flags = [v for v in node.attr_values("registered") if isinstance(v, bool)]
    if True in flags:
        facts.registered = True
    elif flags:
        facts.registered = False  # the authoritative registry's 404 (rdap module): not registered
    elif facts.ns or facts.ips or facts.has_mx or str(row.get("state") or "") == "registered":
        facts.registered = True

    created = [d for d in (_date(v) for n in sources for v in n.attr_values("created")) if d] + ([_date(row["created"])] if _date(row.get("created")) else [])
    if created:
        facts.created = min(created)
        facts.age_days = _days(facts.created, now)
    else:
        ages = [a for a in (_int(v) for n in sources for v in n.attr_values("domain_age_days")) if a is not None and a >= 0]
        row_age = _int(row.get("age_days"))
        if row_age is not None and row_age >= 0:
            ages.append(row_age)
        facts.age_days = min(ages) if ages else None
    facts.newly_registered = any(n.tagged("newly_registered") for n in sources)

    kinds = [str(v) for n in sources for v in n.attr_values("registrant_kind")] + _str_list(row.get("registrant_kind"))
    privacy = any(v is True for n in sources for v in n.attr_values("privacy_proxy"))
    facts.registrant_kind = kinds[0] if kinds else ""
    if "redacted" in kinds or privacy:
        facts.rdap = "redacted"
    elif kinds or flags or created:
        facts.rdap = "ok"
    roots = [_cnpj_root(v) for n in sources for v in n.attr_values("cnpj_roots")] + [_cnpj_root(v) for v in _str_list(row.get("cnpj_roots"))]
    facts.registrant_roots = sorted({r for r in roots if r})
    cnpjs = [k.split(":", 1)[-1] for n in sources for k in edges.targets(n.key, "registrant") if k.startswith("cnpj:")]
    cnpjs += [re.sub(r"[^0-9A-Za-z]", "", str(v)).upper() for n in sources for v in n.attr_values("registrant_doc")]
    facts.registrant_cnpjs = sorted({c for c in cnpjs if len(c) == 14})  # never an 11-digit CPF (P028 cond 10)

    certs = [d for d in (_date(v) for n in sources for v in n.attr_values("first_cert_seen")) if d]
    certs += [d for d in (_date(v.get("first_cert_seen")) for n in sources for v in n.attr_values("ct_summary") if isinstance(v, Mapping)) if d]
    facts.first_cert = min(certs) if certs else None
    facts.fresh_cert_signal = "ct_cert<=30d" in _str_list(row.get("signals"))

    parked = any(n.tagged("parked") or n.noise_kind == "parked" or any(v is True for v in n.attr_values("is_parked")) for n in sources)
    sinkhole = any(n.tagged("sinkhole") or n.noise_kind == "sinkhole" or any(v is True for v in n.attr_values("is_sinkhole")) for n in sources)
    parked = parked or row.get("parked") is True or any(_parked_name(graph, h) for h in facts.ns)
    sinkhole = sinkhole or row.get("sinkhole") is True
    for ip in facts.ips:
        ip_node = graph.get(f"{'ipv6' if ':' in ip else 'ipv4'}:{ip}")
        if ip_node is not None and (ip_node.noise_kind == "parked" or "parked" in ip_node.tags):
            parked = True
        if ip_node is not None and (ip_node.noise_kind == "sinkhole" or "sinkhole" in ip_node.tags):
            sinkhole = True
    facts.parked, facts.sinkhole = parked, sinkhole
    facts.supporting = [f.id for f in node.findings if f.id and ("typosquat" in f.tags or "newly_registered" in f.tags)]
    return facts


def _parked_name(graph: Graph, host: str) -> bool:
    ns_node = graph.get(f"domain:{host}")
    if ns_node is not None and (ns_node.noise_kind == "parked" or "parked" in ns_node.tags):
        return True
    ent = _domain_entity(host)
    try:
        return bool(ent is not None and noise.is_parked(ent))
    except Exception:  # noqa: BLE001
        return False


def _protected_node(org: Any, node: Node | None, brand_keys: Mapping[str, Brand]) -> str:
    """The protected name a lookalike edge points at ('' when it is not protected by the profile)."""
    if node is None:
        return ""
    if node.entity.type is EntityType.DOMAIN:
        try:
            own = org.owns(node.entity)
        except Exception:  # noqa: BLE001
            return ""
        return node.entity.value if (own.own or own.kind == "supplier") else ""
    if node.entity.type is EntityType.KEYWORD:
        return node.entity.value if _key(node.entity.value) in brand_keys else ""
    return ""


def _targets(graph: Graph, edges: _Edges, node: Node, org: Any, brands: list[Brand]) -> tuple[list[str], list[str], list[tuple[Brand, str]]]:
    keys = {b.key: b for b in brands}
    targets: list[str] = []
    techniques: list[str] = []

    def add(target: str, technique: str) -> None:
        if target and target not in targets:
            targets.append(target)
        if technique and technique not in techniques:
            techniques.append(technique)

    for src in edges.sources(node.key, "lookalike"):  # forward scan: protected domain/brand -> candidate
        add(_protected_node(org, graph.get(src), keys), "permutation")
    for dst in edges.targets(node.key, "lookalike_of"):  # reverse match: candidate -> protected domain/brand
        add(_protected_node(org, graph.get(dst), keys), "reverse match")
    for match in node.attr_values("lookalike_matches"):
        if not isinstance(match, Mapping):
            continue
        protected = _host(match.get("protected"))
        if not protected:
            continue
        if "." in protected:
            ent = _domain_entity(protected)
            try:
                own = org.owns(ent) if ent is not None else None
            except Exception:  # noqa: BLE001
                own = None
            if own is not None and (own.own or own.kind == "supplier"):
                add(protected, str(match.get("technique") or "reverse match"))
        elif _key(protected) in keys:
            add(protected, str(match.get("technique") or "reverse match"))
    hits = brand_matches(node.entity.value, brands)
    for brand, technique in hits:
        add(brand.term, technique)
    return targets, techniques, hits


def suppression_reason(graph: Graph, node: Node, facts: LookalikeFacts, org: Any) -> tuple[str, str] | None:
    """``(kind, reason)`` when a lookalike candidate is never flagged (P028 cond 5), else None.

    kind 'own_asset': an org-profile domain, a registrant CNPJ root in the profile's cnpj_roots
    (registro.br publicIds), NS/MX hosts under an org-profile domain, or an own/defensive registration
    the P012 module established; 'supplier': a supplier's domain or NS/MX under it; 'verified_fi': a
    BCB DominiosVerificados domain (P360). Such names belong to the own-asset section (tags own_asset /
    verified_fi), never to typosquat findings."""
    ent = node.entity
    try:
        own = org.owns(ent)
    except Exception:  # noqa: BLE001 - a profile problem never flags anything
        own = None
    if own is not None and own.own:
        return "own_asset", "organisation domain (org profile)"
    if own is not None and own.kind == "supplier":
        return "supplier", "supplier domain (org profile suppliers)"
    if node.ownership == "own_asset" or "own_asset" in node.tags:
        return "own_asset", "own asset (org profile ownership tag)"
    roots = set(getattr(org, "cnpj_roots", ()) or ())
    # the cnpj_roots attribute, or the roots of a registrant CNPJ edge / registrant_doc (sources that only pivot it)
    shared = sorted((set(facts.registrant_roots) | {c[:8] for c in facts.registrant_cnpjs}) & roots)
    if shared:
        return "own_asset", f"registrant CNPJ root {shared[0]} is the organisation's (registro.br publicIds)"
    for kind, hosts in (("NS", facts.ns), ("MX", facts.mx)):
        for host in hosts:
            host_ent = _domain_entity(host)
            try:
                host_own = org.owns(host_ent) if host_ent is not None else None
            except Exception:  # noqa: BLE001
                host_own = None
            if host_own is not None and host_own.own:
                return "own_asset", f"{kind} {host} is under an organisation domain"
            if host_own is not None and host_own.kind == "supplier":
                return "supplier", f"{kind} {host} is under a supplier domain"
    if node.attr_values("bcb_verified_domain") or "verified_fi" in node.tags:
        return "verified_fi", "BCB DominiosVerificados domain (P360)"
    if str(facts.row.get("ownership") or "") in ("own_asset", "defensive_probable"):
        evidence = "; ".join(_str_list(facts.row.get("ownership_evidence"))) or str(facts.row.get("ownership"))
        return "own_asset", f"own or defensive registration ({evidence})"
    return None


def lookalike_candidates(graph: Graph, rctx: Any) -> list[LookalikeFacts]:
    """Every domain of the graph that imitates a profile-protected domain or brand and is not an own,
    supplier or verified asset, with its facts. Empty without an organisation profile (P028 cond 4)."""
    org = getattr(rctx, "org", None)
    if not _has_profile(org):
        return []
    brands = protected_brands(org)
    edges = _Edges(graph)
    rows = _rows_index(graph)
    now = _now(rctx)
    out: list[LookalikeFacts] = []
    for node in list(graph.nodes.values()):
        if node.entity.type is not EntityType.DOMAIN:
            continue
        if node.noise and node.noise_kind not in ("parked", "sinkhole"):
            continue  # platform infrastructure (CDN, webmail, resolvers...) is never a lookalike
        targets, techniques, hits = _targets(graph, edges, node, org, brands)
        if not targets:
            continue
        facts = _facts(graph, edges, node, rows, now)
        facts.targets, facts.techniques, facts.brands = targets, techniques, hits
        if suppression_reason(graph, node, facts, org) is not None:
            continue
        out.append(facts)
    return out


# ----------------------------------------------------------------------------------------
# Output helpers
# ----------------------------------------------------------------------------------------


def _chain(facts: LookalikeFacts, now: _dt.datetime, ti: str = "none") -> str:
    """The one-line evidence chain (P028 cond 11)."""
    if facts.age_days is not None:
        when = f" ({facts.created.date().isoformat()})" if facts.created else ""
        registered = f"registered {facts.age_days} day(s) ago{when}"
    elif facts.registered:
        registered = "registered (date unknown: RDAP unavailable)"
    else:
        registered = "registration unknown"
    mx = "MX yes (" + ", ".join(_entities.defang(h) for h in facts.mx[:3]) + ")" if facts.mx else ("MX yes" if facts.mx_unnamed else "MX no")
    if facts.first_cert is not None:
        cert = f"first certificate {facts.first_cert.date().isoformat()}"
    elif facts.fresh_cert_signal:
        cert = "first certificate <= 30 days (CT signal)"
    else:
        cert = "first certificate unknown"
    return f"{registered}; {mx}; {cert}; TI sources: {ti}"


def _registrant_note(facts: LookalikeFacts) -> str:
    if facts.registrant_cnpjs:
        shown = ", ".join(_entities.display_value(EntityType.CNPJ, c) for c in facts.registrant_cnpjs[:3])
        return f"registrant CNPJ {shown} (registry publicIds): pivot for company due diligence (analyst action)"
    if facts.registrant_roots:
        return f"registrant CNPJ root {', '.join(facts.registrant_roots[:3])} (registry publicIds): pivot for company due diligence (analyst action)"
    if facts.registrant_kind == "individual":
        return "registrant: natural person (identity withheld; never pivoted)"
    if facts.rdap == "redacted":
        return "registrant: redacted (privacy)"
    if facts.rdap == "unavailable":
        return "registrant: RDAP unavailable"
    return "registrant: not the organisation"


def _cap(facts: LookalikeFacts, severity: Severity) -> tuple[Severity, str]:
    """Parked or sinkholed lookalikes are capped at MEDIUM with a label (P028 cond 7)."""
    if facts.parked or facts.sinkhole:
        label = "parked" if facts.parked else "sinkholed"
        if severity > PARKED_CAP:
            return PARKED_CAP, label
        return severity, label
    return severity, ""


def _targets_text(facts: LookalikeFacts) -> str:
    shown = [_entities.defang(t) if "." in t else t for t in facts.targets[:4]]  # protected names too (cond 11)
    return ", ".join(shown) + (f" ({', '.join(facts.techniques[:3])})" if facts.techniques else "")


def _correlation(
    rule_id: str,
    facts: LookalikeFacts,
    *,
    title: str,
    severity: Severity,
    confidence: Confidence,
    summary: str,
    criterion: str,
    chain: str,
    recommendation: str,
    tags: list[str],
    extra_evidence: Iterable[str] = (),
) -> Correlation:
    severity, cap = _cap(facts, severity)
    if cap:
        title = f"{title} ({cap})"
        criterion += f"; {cap} (parking/sinkhole NS or address): capped at MEDIUM until its MX, A record or certificate changes (P028 cond 7)"
        tags = [*tags, "parked" if facts.parked else "sinkhole"]
    description = (
        f"{_display(facts.domain)} imitates {_targets_text(facts)}: {summary} "
        f"Evidence chain: {chain}. {_registrant_note(facts)}. {NOT_A_VERDICT}"
    )
    evidence = [chain, _registrant_note(facts), *extra_evidence, *facts.supporting]
    return Correlation(
        rule=rule_id,
        title=title,
        severity=severity,
        description=description,
        entities=[facts.node.entity],
        confidence=confidence,
        evidence=list(dict.fromkeys(e for e in evidence if e)),
        recommendation=recommendation,
        tags=list(dict.fromkeys(tags)),
        criterion=criterion,
        why=chain,
    )


_RECOMMEND = ("Monitor the lookalike (v3lum watch) and consider blocking it at the mail gateway, DNS filter and web proxy; "
              "do not visit it from the corporate network. " + NO_TAKEDOWN)


# ----------------------------------------------------------------------------------------
# CR04 typosquat_phishing_capable
# ----------------------------------------------------------------------------------------


@rule(
    RULE_PHISHING_CAPABLE,
    "Phishing-capable lookalike of an organisation domain or brand",
    "A lookalike of an org-profile domain or brand (P012 permutation, reverse match, CT/NRD name carrying the "
    "brand) that is registered, has a mail exchanger and was registered at most 90 days ago, with a registrant, "
    "NS and MX that are not the brand's: it can send and receive phishing mail now (P028 cond 1). POSSIBLE "
    "while RDAP is redacted or unavailable; parked names are capped at MEDIUM.",
    version="1",
    code="CR04",
    severity="high",
    criterion="registered + MX + RDAP registration <= 90 days + registrant/NS/MX not the brand's (org profile, "
    "registro.br CNPJ roots, BCB verified domains) (P028 cond 1, 5)",
    references=_REFERENCES,
    attack=("T1583.001", "T1566"),
    false_positives="A brand subsidiary, agency or reseller registered under a CNPJ root the org profile does not list; "
    "a partner brand not yet in the profile's suppliers; a parked domain that later changes hands.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_PHISHING_CAPABLE}/positive_fresh_mx_lookalike_high.json",
        f"tests/fixtures/rules/{RULE_PHISHING_CAPABLE}/positive_parked_lookalike_medium.json",
        f"tests/fixtures/rules/{RULE_PHISHING_CAPABLE}/positive_rdap_unavailable_possible.json",
        f"tests/fixtures/rules/{RULE_PHISHING_CAPABLE}/negative_own_defensive_registration.json",
        f"tests/fixtures/rules/{RULE_PHISHING_CAPABLE}/negative_brand_subsidiary.json",
        f"tests/fixtures/rules/{RULE_PHISHING_CAPABLE}/negative_no_org_profile.json",
        f"tests/fixtures/rules/{RULE_PHISHING_CAPABLE}/negative_old_or_no_mx.json",
    ),
)
def typosquat_phishing_capable(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterator[Correlation]:
    now = _now(rctx)
    for facts in lookalike_candidates(graph, rctx):
        if not facts.registered or not facts.has_mx:
            continue
        if facts.age_days is not None and facts.age_days > PHISHING_CAPABLE_MAX_AGE_DAYS:
            continue
        rdap_ok = facts.rdap == "ok" and facts.age_days is not None
        label = Confidence.PROBABLE if rdap_ok else Confidence.POSSIBLE
        criterion = (
            "CR04: registered, MX present, "
            + (f"RDAP registration {facts.age_days} day(s) ago (<= {PHISHING_CAPABLE_MAX_AGE_DAYS})" if facts.age_days is not None
               else "registration date unknown")
            + ", registrant/NS/MX not the brand's (org profile)"
        )
        if not rdap_ok:
            criterion = f"POSSIBLE - RDAP {'redacted' if facts.rdap == 'redacted' else 'unavailable'}: registration age or registrant unverified | {criterion}"
        yield _correlation(
            RULE_PHISHING_CAPABLE,
            facts,
            title=f"Phishing-capable lookalike: {_entities.defang(facts.domain)}",
            severity=Severity.HIGH,
            confidence=label,
            summary=f"a {WORDING}: registered with a mail exchanger, so it can send and receive mail in the brand's name.",
            criterion=criterion,
            chain=_chain(facts, now),
            recommendation=_RECOMMEND,
            tags=["typosquat", "phishing_capable"],
        )


# ----------------------------------------------------------------------------------------
# CR05 typosquat_with_fresh_certificate
# ----------------------------------------------------------------------------------------


@rule(
    RULE_FRESH_CERT,
    "Lookalike with a freshly issued first certificate",
    "A lookalike of an org-profile domain or brand whose FIRST certificate ever logged in Certificate Transparency "
    "(earliest not_before) is at most 30 days old: a site is being prepared now. The latest auto-renewal never "
    "counts (P028 cond 1).",
    version="1",
    code="CR05",
    severity="high",
    criterion="earliest CT not_before (first_cert_seen) <= 30 days, never the latest renewal; not an own/verified asset",
    references=(*_REFERENCES, "https://certificate.transparency.dev/"),
    attack=("T1583.001", "T1588.004", "T1608.003"),
    false_positives="A new legitimate brand campaign site registered by an agency outside the org profile; a CT log "
    "backfill that surfaces an old name late.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_FRESH_CERT}/positive_first_certificate_12_days.json",
        f"tests/fixtures/rules/{RULE_FRESH_CERT}/negative_old_first_certificate_recent_renewal.json",
        f"tests/fixtures/rules/{RULE_FRESH_CERT}/negative_own_domain_certificate.json",
    ),
)
def typosquat_with_fresh_certificate(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterator[Correlation]:
    now = _now(rctx)
    for facts in lookalike_candidates(graph, rctx):
        cert_age = _days(facts.first_cert, now)
        if cert_age is not None:
            if cert_age > FRESH_CERT_MAX_AGE_DAYS:
                continue  # the first certificate is old: a renewal is not a new site
            detail = f"first certificate ever logged {cert_age} day(s) ago ({facts.first_cert.date().isoformat()})"  # type: ignore[union-attr]
        elif facts.fresh_cert_signal:
            detail = "first certificate ever logged <= 30 days ago (P012 CT signal)"
        else:
            continue
        yield _correlation(
            RULE_FRESH_CERT,
            facts,
            title=f"Lookalike with a fresh first certificate: {_entities.defang(facts.domain)}",
            severity=Severity.HIGH,
            confidence=Confidence.PROBABLE,
            summary=f"a {WORDING}: its {detail}, so a web site under the name is being prepared.",
            criterion=f"CR05: earliest CT not_before {detail}; never the latest auto-renewal (P028 cond 1)",
            chain=_chain(facts, now),
            recommendation=_RECOMMEND,
            tags=["typosquat", "phishing_capable"],
        )


# ----------------------------------------------------------------------------------------
# CR06 typosquat_on_malicious_infra
# ----------------------------------------------------------------------------------------


@rule(
    RULE_MALICIOUS_INFRA,
    "Lookalike hosted on infrastructure listed by threat intelligence",
    "A lookalike of an org-profile domain or brand that resolves to an address threat-intelligence sources list, "
    "or that is listed itself. CRITICAL only when >= 2 independent upstream families (P171) list a dedicated "
    "address (not CDN/hosting, not a sinkhole, < 50 co-hosted names) after warninglist suppression; otherwise "
    "HIGH. Shared-hosting listings never count unless the domain itself is flagged (P028 cond 6).",
    version="1",
    code="CR06",
    severity="critical",
    criterion=">= 2 independent upstream families list a dedicated address of the lookalike (CRITICAL); one family, "
    "a hosting address or the domain's own listing (HIGH); after warninglist/sinkhole suppression (P028 cond 6, P171)",
    references=(*_REFERENCES, "https://www.misp-project.org/warninglists/"),
    attack=("T1583.001", "T1583", "T1566"),
    false_positives="A recycled dedicated address that a feed still lists after the previous tenant left; a lookalike "
    "parked by a registrar whose parking addresses are listed for malvertising.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_MALICIOUS_INFRA}/positive_two_families_dedicated_critical.json",
        f"tests/fixtures/rules/{RULE_MALICIOUS_INFRA}/positive_one_family_high.json",
        f"tests/fixtures/rules/{RULE_MALICIOUS_INFRA}/negative_shared_hosting_listing.json",
        f"tests/fixtures/rules/{RULE_MALICIOUS_INFRA}/negative_suppressed_or_stale_listings.json",
    ),
)
def typosquat_on_malicious_infra(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterator[Correlation]:
    now = _now(rctx)
    registry = provider_registry(rctx)
    edges = _Edges(graph)
    for facts in lookalike_candidates(graph, rctx):
        domain_votes = _listing_votes(facts.node, now, DOMAIN_LISTING_WINDOW_DAYS, registry)
        for key in edges.sources(facts.node.key, "url_host") + edges.targets(facts.node.key, "hosts_url"):
            url_node = graph.get(key)
            if url_node is not None and url_node.entity.type is EntityType.URL:
                domain_votes += _listing_votes(url_node, now, DOMAIN_LISTING_WINDOW_DAYS, registry)
        domain_families = independent_families(domain_votes)
        addresses = [_address(graph, edges, ip, now, registry) for ip in facts.ips]
        counted = [a for a in addresses if a.votes and not a.shared and not a.cdn and not a.sinkhole and not a.suppressed
                   and a.cohosted < SHARED_HOSTING_MIN_NAMES]
        consensus = [a for a in counted if a.dedicated and len(a.families) >= CONSENSUS_MIN_FAMILIES]
        if not counted and not domain_families:
            continue  # shared-hosting or suppressed listings only: never a lookalike's taint
        ip_families = independent_families([v for a in counted for v in a.votes])
        all_families = independent_families([v for a in counted for v in a.votes] + domain_votes)
        ti = ", ".join(all_families) or "none"
        chain = _chain(facts, now, ti)
        if consensus:
            best = max(consensus, key=lambda a: len(a.families))
            fams = sorted(best.families)
            severity = Severity.CRITICAL
            label = Confidence.PROBABLE
            title = f"Lookalike on malicious infrastructure: {_entities.defang(facts.domain)}"
            summary = (f"a {WORDING} resolving to {_entities.defang(best.value)}, which {len(fams)} independent upstream families "
                       f"list as malicious ({', '.join(fams)}): dedicated address, not CDN/hosting, not a sinkhole.")
            criterion = (f"CR06 consensus: {len(fams)} independent upstream families ({', '.join(fams)}) list the dedicated "
                         f"address {_entities.defang(best.value)} (< {SHARED_HOSTING_MIN_NAMES} co-hosted names) after warninglist suppression")
            tags = ["typosquat", "phishing_capable", "malicious"]
        else:
            severity = Severity.HIGH
            parts = []
            if counted:
                parts.append("address " + ", ".join(f"{_entities.defang(a.value)} ({', '.join(a.families)})" for a in counted[:3]))
            if domain_families:
                parts.append("the domain itself (" + ", ".join(domain_families) + ")")
            many = len(all_families) >= CONSENSUS_MIN_FAMILIES or bool(domain_families) or len(ip_families) >= CONSENSUS_MIN_FAMILIES
            label = Confidence.PROBABLE if many else Confidence.POSSIBLE
            title = f"Lookalike on listed infrastructure: {_entities.defang(facts.domain)}"
            summary = (f"a {WORDING} with threat-intelligence listings on " + " and ".join(parts) + "; no consensus of independent "
                       "families on a dedicated address, so it is not called malicious.")
            criterion = ("CR06 without consensus: listings on " + "; ".join(parts) + f" (CRITICAL needs >= {CONSENSUS_MIN_FAMILIES} "
                         "independent families on a dedicated, non-CDN, non-hosting, non-sinkhole address)")
            tags = ["typosquat", "phishing_capable", "suspicious"]
        shared = [_entities.defang(a.value) for a in addresses if a.votes and (a.shared or a.cdn or a.cohosted >= SHARED_HOSTING_MIN_NAMES)]
        extra = [f"shared-hosting listings not counted: {', '.join(shared[:5])}"] if shared else []
        suppressed = [f"{_entities.defang(a.value)} ({a.suppressed or 'sinkhole'})" for a in addresses if a.suppressed or a.sinkhole]
        extra += [f"suppressed addresses: {', '.join(suppressed[:5])}"] if suppressed else []
        yield _correlation(
            RULE_MALICIOUS_INFRA,
            facts,
            title=title,
            severity=severity,
            confidence=label,
            summary=summary,
            criterion=criterion,
            chain=chain,
            recommendation="Block the lookalike and the listed address at the perimeter and hunt for contact in proxy, DNS and "
            "mail logs. " + NO_TAKEDOWN,
            tags=tags,
            extra_evidence=extra,
        )


# ----------------------------------------------------------------------------------------
# CR35 new_brand_keyword_domain
# ----------------------------------------------------------------------------------------


@rule(
    RULE_BRAND_KEYWORD,
    "New domain combining a brand keyword with a lure word",
    "A domain registered at most 30 days ago whose name combines an org-profile brand keyword (suppliers' brands "
    "included) with a lure word of v3lum/data/brand_lures_pt.json (conta, pix, boleto, 2via, login, token...), "
    "matched after IDNA->Unicode, accent and homoglyph folding (P028 cond 2, 8).",
    version="1",
    code="CR35",
    severity="medium",
    criterion="registration <= 30 days (RDAP, or an NRD feed's newly_registered tag) + org brand keyword + lure word in "
    "the owner labels, after folding; not an own/verified asset",
    references=(*_REFERENCES, "https://www.cert.br/"),
    attack=("T1583.001", "T1684.001", "T1566.002"),
    false_positives="A new legitimate campaign or partner domain (e.g. a promotion site of the brand's agency) not yet in "
    "the org profile; a reseller combining the brand with a service word.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_BRAND_KEYWORD}/positive_brand_pix_12_days.json",
        f"tests/fixtures/rules/{RULE_BRAND_KEYWORD}/positive_homoglyph_brand_with_lure.json",
        f"tests/fixtures/rules/{RULE_BRAND_KEYWORD}/negative_no_lure_or_old.json",
        f"tests/fixtures/rules/{RULE_BRAND_KEYWORD}/negative_no_org_profile.json",
    ),
)
def new_brand_keyword_domain(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterator[Correlation]:
    now = _now(rctx)
    words = lure_words()
    if not words:
        return
    for facts in lookalike_candidates(graph, rctx):
        brands = [(b, t) for b, t in facts.brands if t in ("brand-label", "brand-in-label")]
        if not brands:
            continue
        if facts.age_days is not None:
            if facts.age_days > NEW_DOMAIN_MAX_AGE_DAYS:
                continue
            age_text = f"registered {facts.age_days} day(s) ago"
        elif facts.newly_registered:
            age_text = "newly registered (NRD feed)"
        else:
            continue
        for brand, _technique in brands:
            lures = lure_matches(facts.domain, brand.key, words)
            if not lures:
                continue
            yield _correlation(
                RULE_BRAND_KEYWORD,
                facts,
                title=f"New brand-keyword domain: {_entities.defang(facts.domain)}",
                severity=Severity.MEDIUM,
                confidence=Confidence.PROBABLE,
                summary=(f"a {WORDING}: {age_text}, its name combines the brand keyword '{brand.term}' ({brand.origin}) "
                         f"with the lure word(s) {', '.join(repr(w) for w in lures[:3])}."),
                criterion=(f"CR35: {age_text} (<= {NEW_DOMAIN_MAX_AGE_DAYS} days), brand keyword '{brand.term}' + lure word "
                           f"{lures[0]!r} after IDNA/accent/homoglyph folding (P028 cond 2, 8)"),
                chain=_chain(facts, now),
                recommendation=_RECOMMEND,
                tags=["typosquat", "newly_registered"],
            )
            break
