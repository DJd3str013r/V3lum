"""Correlation pack: breach and infostealer validation (P146: CR09-CR12 and the Céos heuristics).

The rules read only P145-sanitized metadata other modules recorded - breach names, dates, data
classes, the password FORM, counts, stealer family and service counts - and they replace the legacy
``breach_and_infostealer`` rule of ``generic.py`` (removed there by WP22). Credentials are never
tested, validated or used in any mode (A4 BR12); nothing is fetched.

* **Suppression first, downgrade only** (P146 cond 2, A4 BR6): an identity on the generic/role/test
  list (``data/generic_addresses.json``), flagged ``generic_address``/``role_account`` by a module,
  with >= :data:`LEAKCHECK_SHARED_FOUND` breach-corpus hits (LeakCheck 'found', attribute
  ``breach_hit_count``) or >= :data:`SHARED_STEALER_COMPUTERS` infected computers (Hudson Rock) keeps
  every correlation, capped at POSSIBLE and MEDIUM and tagged ``context_only`` (never scored), with the
  visible label 'POSSIBLE - generic or shared address' (:func:`generic_reason`). **CR11**
  ``generic_or_shared_email_suppression`` states the cap as its own INFO correlation.
* **CR09** ``corporate_credentials_in_infostealer`` (cond 5): CRITICAL only for an address on a
  verified org-profile domain (txt_verified/attested) with a stealer log at most
  :data:`STEALER_RECENT_DAYS` days old; older own-domain logs with corporate services > 0 are HIGH,
  other older ones MEDIUM (decay tau :data:`STEALER_DECAY_TAU_DAYS` days, shown as the P302 weight).
  Verified own domains with employee stealer counts (counts only, no dates) are HIGH.
* **CR10** ``email_in_multiple_password_breaches`` (cond 6): >= :data:`MIN_VERIFIED_BREACHES` verified
  password breaches, or >= :data:`MIN_BREACHES_CONFIRMED` password breaches confirmed by
  >= :data:`MIN_CONFIRMING_FAMILIES` independent upstream families, with at least one within
  :data:`RECENT_BREACH_DAYS` days: HIGH for own-domain addresses. Breaches re-served by aggregators
  count once (per normalised name and independent family, cond 8); fabricated and spam-list breaches
  never count.
* **CR12** ``breach_predates_domain`` (cond 4): the earliest breach listing (``first_seen_breach`` or a
  breach record) predates the RDAP creation date of the address's domain - silent when that date is
  unknown; the listing is a probable false positive (or a re-registered domain) and CR09/CR10
  correlations of the address are downgraded with that criterion.
* Third-party addresses (anything but a verified own domain, A4 BR9-BR10) are evaluated only under the
  A4 breach scope - ``--breach-scope all`` with a recorded ``--purpose``, analyst-typed seeds only -
  and are context only: at most MEDIUM, ``context_only``, no exposure score (cond 5-7).
* The Céos verdict heuristics (cond 9) are named functions, each returning a :class:`Signal` with a
  P322 criterion: :func:`is_fabricated_against`, :func:`spam_list_alert`, :func:`compilation_doubt`,
  :func:`sources_agree`, :func:`profile_plausible`, plus :func:`verified_listing`,
  :func:`stealer_alert`, :func:`domain_after_breach_against`, :func:`generic_alert` and
  :func:`ownership_signal`; :func:`suggest_verdict` turns them into the suggested verdict (positive /
  false positive / inconclusive) with the 2-3 criteria that drove it.

Wording is a suggestion: infostealer findings about employees go to incident response and are not a
basis for disciplinary decisions without human review (LGPD art. 20, :data:`LGPD_NOTICE`). Every
output string passes ``sanitize.scrub_text`` (P146 cond 1) and every correlation about an address is
tagged ``privacy`` (personal data: excluded from STIX/MISP exports unless the analyst includes it).
"""

from __future__ import annotations

import calendar
import datetime as _dt
import math
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from v3lum.core import entities as _entities
from v3lum.core import psl
from v3lum.core import sanitize as _sanitize
from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Confidence, Correlation, Finding, ModuleResult, Severity
from v3lum.correlations.typosquat import ListingVote, independent_families, module_vote, provider_registry, source_vote

__all__ = [
    "AGAINST",
    "ALERT",
    "DOUBT",
    "LGPD_NOTICE",
    "OK",
    "RULE_GENERIC",
    "RULE_INFOSTEALER",
    "RULE_MULTI_BREACH",
    "RULE_PREDATES",
    "BreachRecord",
    "MergedBreach",
    "Signal",
    "StealerLog",
    "Verdict",
    "breach_key",
    "breach_records",
    "compilation_doubt",
    "domain_after_breach_against",
    "earliest_breach",
    "generic_alert",
    "generic_reason",
    "in_breach_scope",
    "is_fabricated_against",
    "merge_breaches",
    "ownership_signal",
    "profile_plausible",
    "sources_agree",
    "spam_list_alert",
    "stealer_alert",
    "stealer_logs",
    "suggest_verdict",
    "verified_listing",
]

# ----------------------------------------------------------------------------------------
# Rule ids and named constants (one place, P146 cond 2-6)
# ----------------------------------------------------------------------------------------

RULE_INFOSTEALER = "corporate_credentials_in_infostealer"  # CR09
RULE_MULTI_BREACH = "email_in_multiple_password_breaches"  # CR10
RULE_GENERIC = "generic_or_shared_email_suppression"  # CR11
RULE_PREDATES = "breach_predates_domain"  # CR12

#: CR09: a stealer log at most this many days old on a verified own domain is CRITICAL.
STEALER_RECENT_DAYS = 365
#: CR09: decay time constant of stealer logs (P302 weight e^-age/tau, shown in the evidence).
STEALER_DECAY_TAU_DAYS = 365
#: CR10: verified password breaches needed on their own.
MIN_VERIFIED_BREACHES = 3
#: CR10: independent upstream families that confirm the listings.
MIN_CONFIRMING_FAMILIES = 2
#: CR10: password breaches needed when the confirmation comes from >= 2 families ('multiple').
MIN_BREACHES_CONFIRMED = 2
#: CR10: at least one counted breach within this many days.
RECENT_BREACH_DAYS = 3 * 365
#: CR11: LeakCheck 'found' at or above this marks a generic/shared address (Céos MUITOS_VAZAMENTOS).
LEAKCHECK_SHARED_FOUND = 100
#: CR11: infected computers (Hudson Rock) at or above this mark a generic/shared identity.
SHARED_STEALER_COMPUTERS = 5
#: Third-party (non verified own) addresses never exceed this severity (A4 BR9-BR10).
THIRD_PARTY_MAX = Severity.MEDIUM
#: Generic/shared identities never exceed this severity, at POSSIBLE (CR11).
GENERIC_MAX = Severity.MEDIUM
#: Breach names of compilations and combo lists: re-served data of unknown origin ('doubt').
COMPILATION_RE = re.compile(
    r"collection|combo|compilation|anti-?public|exploit\.?in|breach ?compilation|cit0day|naz\.?api|txtbase|"
    r"combolist|\bulp\b|url:?log:?pass",
    re.I,
)
#: Data-class names that mean passwords were exposed (names only, never values).
_PASSWORD_CLASS = re.compile(r"passwords?|senhas?|credentials?|password hashes|hashed passwords|plaintext", re.I)
_HINT_CLASS = re.compile(r"hint|dica", re.I)
#: Verdict signal levels (Céos: ok / alert / doubt / against).
OK, ALERT, DOUBT, AGAINST = "ok", "alert", "doubt", "against"
#: Named suppression labels recorded in Correlation.suppressed_by.
SUPPRESSION_GENERIC = "CR11 generic_or_shared_email_suppression"
SUPPRESSION_PREDATES = "CR12 breach_predates_domain"
#: LGPD art. 20 wording (P146 cond 11).
LGPD_NOTICE = (
    "Infostealer and breach findings about employees go to incident response; they are suggestions, not a basis for "
    "disciplinary decisions without human review (LGPD art. 20)."
)
NEVER_TESTED = "Leaked credentials are never tested, validated or used in any mode."
#: Analyst override verdicts that take a finding out of the evidence.
FALSE_POSITIVE_VERDICTS = frozenset({"false_positive", "false positive", "fp", "benign", "wrong", "negative", "not_malicious"})
_IDENTITY_TYPES = (EntityType.EMAIL, EntityType.USERNAME)
_REFERENCES = (
    "https://haveibeenpwned.com/FAQs",
    "https://attack.mitre.org/techniques/T1589/001/",
)
_UTC = _dt.timezone.utc


# ----------------------------------------------------------------------------------------
# Dates
# ----------------------------------------------------------------------------------------


def _bounds(value: Any) -> tuple[_dt.datetime | None, _dt.datetime | None]:
    """(earliest, latest) instant a reported date can mean: '2019' -> 2019-01-01 .. 2019-12-31,
    '2019-07' -> 2019-07-01 .. 2019-07-31, '2019-07-12[T...]' -> that day."""
    if isinstance(value, _dt.datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=_UTC)
        return moment, moment
    if isinstance(value, _dt.date):
        moment = _dt.datetime(value.year, value.month, value.day, tzinfo=_UTC)
        return moment, moment
    text = str(value or "").strip()
    m = re.match(r"^(\d{4})(?:-(\d{2})(?:-(\d{2}))?)?", text)
    if not m:
        return None, None
    year = int(m.group(1))
    try:
        if m.group(3):
            day = _dt.datetime(year, int(m.group(2)), int(m.group(3)), tzinfo=_UTC)
            return day, day
        if m.group(2):
            month = int(m.group(2))
            last = calendar.monthrange(year, month)[1]
            return _dt.datetime(year, month, 1, tzinfo=_UTC), _dt.datetime(year, month, last, tzinfo=_UTC)
        return _dt.datetime(year, 1, 1, tzinfo=_UTC), _dt.datetime(year, 12, 31, tzinfo=_UTC)
    except ValueError:
        return None, None


def _now(rctx: Any) -> _dt.datetime:
    now = getattr(rctx, "now", None)
    if isinstance(now, _dt.datetime):
        return now if now.tzinfo else now.replace(tzinfo=_UTC)
    return _dt.datetime.now(_UTC)


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _flag(value: Any) -> bool | None:
    """Provider booleans: True/False, 1/0, 'yes'/'no' (None when unknown)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value or "").strip().lower()
    if text in ("yes", "y", "true", "1", "sim"):
        return True
    if text in ("no", "n", "false", "0", "nao", "não"):
        return False
    return None


def _evidence_finding(f: Finding) -> bool:
    """A fact the rules may read: everything except findings an analyst marked false positive."""
    override = f.override if isinstance(f.override, dict) else None
    return not (override and str(override.get("verdict") or "").strip().lower() in FALSE_POSITIVE_VERDICTS)


# ----------------------------------------------------------------------------------------
# Breach records (sanitized metadata only)
# ----------------------------------------------------------------------------------------


def breach_key(name: Any) -> str:
    """Normalised breach name for cross-source merging (P146 cond 8): 'SynthForum.example',
    'SynthForum' and 'synth forum' -> 'synthforum'; 'Collection #1' and 'Collection-1' -> 'collection1'."""
    text = str(name or "").strip().lower()
    if "." in text and " " not in text:
        try:
            reg = psl.registrable_domain(text)
        except Exception:  # noqa: BLE001
            reg = None
        if reg:
            text = reg.split(".", 1)[0]
    return re.sub(r"[^0-9a-z]+", "", text)


@dataclass(frozen=True)
class BreachRecord:
    """One sanitized breach listing of an identity by one source (never a value of the leak)."""

    name: str
    key: str
    date: str = ""
    data_classes: tuple[str, ...] = ()
    password_form: str = ""
    verified: bool | None = None
    fabricated: bool | None = None
    spam_list: bool | None = None
    stealer_log: bool | None = None
    sensitive: bool | None = None
    compilation: bool | None = None
    domain: str = ""
    source: str = ""
    module: str = ""

    @property
    def password(self) -> bool:
        """The listing exposed passwords (a password data class or a password FORM), not hints only."""
        if self.password_form:
            return True
        return any(_PASSWORD_CLASS.search(c) and not _HINT_CLASS.search(c) for c in self.data_classes)

    @property
    def shown_name(self) -> str:
        """Display name: sensitive breaches are never named (LGPD art. 11)."""
        return "sensitive breach (name withheld)" if self.sensitive else self.name


_NAME_KEYS = ("name", "Name", "breach", "Breach", "title", "Title")
_DATE_KEYS = ("date", "breach_date", "BreachDate", "breachDate", "xposed_date", "date_breached")
_CLASS_KEYS = ("data_classes", "DataClasses", "dataclasses", "xposed_data", "fields", "data")


def _classes(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        parts = re.split(r"[;,|]", value)
    elif isinstance(value, (list, tuple, set)):
        parts = [str(v) for v in value]
    else:
        parts = []
    return tuple(dict.fromkeys(p.strip() for p in parts if p and p.strip()))


def _pick(data: Mapping[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        value = data.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _record(data: Mapping[str, Any], *, source: str, module: str) -> BreachRecord | None:
    nested = data.get("source") if isinstance(data.get("source"), Mapping) else {}
    name = _pick(data, _NAME_KEYS) or _pick(nested, _NAME_KEYS)
    if isinstance(name, Mapping) or not str(name or "").strip():
        return None
    name = str(name).strip()
    unverified = _flag(data.get("unverified", nested.get("unverified")))
    verified = _flag(_pick(data, ("verified", "IsVerified", "is_verified")))
    if verified is None and unverified is not None:
        verified = not unverified
    compilation = _flag(data.get("compilation", nested.get("compilation")))
    if COMPILATION_RE.search(name):
        compilation = True
    date = _pick(data, _DATE_KEYS) or _pick(nested, _DATE_KEYS) or ""
    src = str(data.get("source") or "") if isinstance(data.get("source"), str) else ""
    return BreachRecord(
        name=name,
        key=breach_key(name),
        date=str(date).strip(),
        data_classes=_classes(_pick(data, _CLASS_KEYS)),
        password_form=str(data.get("password_form") or "").strip(),
        verified=verified,
        fabricated=_flag(_pick(data, ("fabricated", "IsFabricated", "is_fabricated"))),
        spam_list=_flag(_pick(data, ("spam_list", "IsSpamList", "is_spam_list"))),
        stealer_log=_flag(_pick(data, ("stealer_log", "IsStealerLog", "IsMalware", "is_stealer_log"))),
        sensitive=_flag(_pick(data, ("sensitive", "IsSensitive", "is_sensitive"))),
        compilation=compilation,
        domain=str(_pick(data, ("domain", "Domain")) or "").strip().lower(),
        source=src or source,
        module=module,
    )


def _catalogue(graph: Graph) -> dict[str, BreachRecord]:
    """Breach catalogue facts recorded anywhere in the graph (``breach_metadata``, ``service_breaches``)
    by normalised name: they enrich listings that carry only a name (P132 catalogue helper)."""
    out: dict[str, BreachRecord] = {}
    for node in graph.nodes.values():
        for value in node.attr_values("breach_metadata") + node.attr_values("service_breaches"):
            if isinstance(value, Mapping):
                rec = _record(value, source="", module="catalogue")
                if rec is not None and rec.key and rec.key not in out:
                    out[rec.key] = rec
    return out


def _enrich(rec: BreachRecord, cat: Mapping[str, BreachRecord]) -> BreachRecord:
    ref = cat.get(rec.key)
    if ref is None:
        return rec
    merged = dict(rec.__dict__)
    for name in ("date", "data_classes", "password_form", "verified", "fabricated", "spam_list", "stealer_log", "sensitive", "domain"):
        if merged[name] in (None, "", ()):
            merged[name] = getattr(ref, name)
    return BreachRecord(**merged)


def breach_records(graph: Graph, node: Node) -> list[BreachRecord]:
    """Every sanitized breach listing of an identity: ``breach_records`` attributes, findings tagged
    ``breach`` (their ``data``), and ``breaches`` name lists, enriched with catalogue facts of the
    graph. Findings an analyst marked false positive are left out."""
    out: list[BreachRecord] = []
    for value, src in node.attributes.get("breach_records", []):
        for item in value if isinstance(value, (list, tuple)) else [value]:
            if isinstance(item, Mapping):
                rec = _record(item, source=str(item.get("source") or "") if isinstance(item.get("source"), str) else "", module=src)
                if rec is not None:
                    out.append(rec)
    for f in node.findings:
        if "breach" not in f.tags or not _evidence_finding(f) or not isinstance(f.data, Mapping):
            continue
        rec = _record(f.data, source=f.source, module=f.module)
        if rec is not None:
            if not rec.date and f.observed_first:
                rec = BreachRecord(**{**rec.__dict__, "date": str(f.observed_first)})
            out.append(rec)
    for value, src in node.attributes.get("breaches", []):
        for name in value if isinstance(value, (list, tuple)) else [value]:
            if isinstance(name, str) and name.strip():
                out.append(BreachRecord(name=name.strip(), key=breach_key(name), module=src))
    cat = _catalogue(graph)
    return [_enrich(r, cat) for r in out if r.key]


@dataclass
class MergedBreach:
    """One breach merged across sources by normalised name (counted once, P146 cond 8)."""

    key: str
    records: list[BreachRecord] = field(default_factory=list)
    votes: list[ListingVote] = field(default_factory=list)

    def _any(self, name: str) -> bool:
        return any(getattr(r, name) is True for r in self.records)

    @property
    def name(self) -> str:
        return next((r.shown_name for r in self.records if r.sensitive), self.records[0].name if self.records else self.key)

    @property
    def verified(self) -> bool:
        return self._any("verified")

    @property
    def fabricated(self) -> bool:
        return self._any("fabricated")

    @property
    def spam_list(self) -> bool:
        return self._any("spam_list")

    @property
    def stealer_log(self) -> bool:
        return self._any("stealer_log")

    @property
    def compilation(self) -> bool:
        return self._any("compilation")

    @property
    def sensitive(self) -> bool:
        """A sensitive breach (HIBP IsSensitive): its name and service domain are never shown (LGPD art. 11)."""
        return self._any("sensitive")

    @property
    def password(self) -> bool:
        return any(r.password for r in self.records)

    @property
    def domain(self) -> str:
        return next((r.domain for r in self.records if r.domain), "")

    @property
    def date(self) -> str:
        """The most precise reported date (YYYY-MM-DD over YYYY-MM over YYYY)."""
        dates = sorted((r.date for r in self.records if r.date), key=lambda d: (-len(d[:10]), d))
        return dates[0][:10] if dates else ""

    @property
    def bounds(self) -> tuple[_dt.datetime | None, _dt.datetime | None]:
        return _bounds(self.date)

    @property
    def families(self) -> list[str]:
        return independent_families(self.votes)

    @property
    def counted(self) -> bool:
        """A password breach that counts for CR10: never fabricated, never a spam list."""
        return self.password and not self.fabricated and not self.spam_list

    def describe(self) -> str:
        bits = [self.date or "date unknown"]
        if self.verified:
            bits.append("verified")
        if self.families:
            bits.append("sources: " + ", ".join(self.families))
        return f"{self.name} ({'; '.join(bits)})"


def merge_breaches(records: Iterable[BreachRecord], registry: Any = None) -> list[MergedBreach]:
    """Listings merged per normalised breach name; each listing votes with its source's upstream
    family (aggregators re-serving HIBP-type data count once, P146 cond 8)."""
    merged: dict[str, MergedBreach] = {}
    for rec in records:
        item = merged.setdefault(rec.key, MergedBreach(rec.key))
        item.records.append(rec)
        vote = source_vote(rec.source, registry) if rec.source else module_vote(rec.module, registry)
        if vote is not None:
            item.votes.append(vote)
    return sorted(merged.values(), key=lambda m: (m.date or "9999", m.key))


def earliest_breach(node: Node, breaches: Iterable[MergedBreach]) -> tuple[_dt.datetime | None, _dt.datetime | None, str]:
    """(earliest instant, latest instant of that listing, label) of the oldest breach that lists the
    identity: ``first_seen_breach`` attributes (emitted by the breach modules) and dated breaches."""
    best: tuple[_dt.datetime | None, _dt.datetime | None, str] = (None, None, "")
    for value in node.attr_values("first_seen_breach"):
        low, high = _bounds(value)
        if low is not None and (best[0] is None or low < best[0]):
            best = (low, high, f"first_seen_breach {str(value)[:10]}")
    for item in breaches:
        low, high = item.bounds
        if low is not None and (best[0] is None or low < best[0]):
            best = (low, high, f"{item.name} {item.date}")
    return best


# ----------------------------------------------------------------------------------------
# Stealer logs
# ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class StealerLog:
    """One sanitized infostealer record: compromise date, family and service counts only."""

    date_text: str
    date: _dt.datetime | None
    family: str = ""
    corporate: int | None = None
    user: int | None = None
    source: str = ""


def _log(data: Mapping[str, Any], source: str) -> StealerLog | None:
    date = str(data.get("date_compromised") or data.get("date") or "").strip()
    family = str(data.get("stealer_family") or data.get("family") or "").strip()
    corp = _int(data.get("total_corporate_services"))
    user = _int(data.get("total_user_services"))
    if not (date or family or corp is not None or user is not None):
        return None
    return StealerLog(date, _bounds(date)[0], family, corp, user, source)


def stealer_logs(node: Node) -> list[StealerLog]:
    """Distinct stealer records of an identity (``stealer_logs`` attributes and the data of findings
    tagged ``infostealer``); one record is one infected computer."""
    out: list[StealerLog] = []
    seen: set[tuple[str, str, int | None, int | None]] = set()

    def add(log: StealerLog | None) -> None:
        if log is None:
            return
        key = (log.date_text[:10], log.family.lower(), log.corporate, log.user)
        if key not in seen:
            seen.add(key)
            out.append(log)

    for value, src in node.attributes.get("stealer_logs", []):
        for item in value if isinstance(value, (list, tuple)) else [value]:
            if isinstance(item, Mapping):
                add(_log(item, src))
    for f in node.findings:
        if "infostealer" in f.tags and _evidence_finding(f) and isinstance(f.data, Mapping) and f.data.get("date_compromised"):
            add(_log(f.data, f.source or f.module))
    return out


# ----------------------------------------------------------------------------------------
# Scope, ownership and the generic suppression
# ----------------------------------------------------------------------------------------


def _email_domain(node: Node) -> str:
    return node.entity.value.rsplit("@", 1)[-1] if node.entity.type is EntityType.EMAIL else ""


def _own_verified(node: Node, org: Any) -> bool:
    """An address on a verified (txt_verified/attested) org-profile domain (A4 BR9, A11 BR4)."""
    if org is None or node.entity.type is not EntityType.EMAIL:
        return False
    try:
        return bool(org.is_verified_domain(_email_domain(node)))
    except Exception:  # noqa: BLE001 - a profile problem never makes an address own
        return False


def in_breach_scope(node: Node, rctx: Any) -> tuple[bool, bool]:
    """``(evaluate, own_verified)``: verified own addresses always; any other identity only under the A4
    breach scope - ``breach_scope == 'all'``, a recorded purpose and an analyst-typed (confirmed) seed."""
    own = _own_verified(node, getattr(rctx, "org", None))
    if own:
        return True, True
    opts = getattr(rctx, "options", None)
    scope = str(getattr(opts, "breach_scope", "own") or "own").strip().lower()
    purpose = str(getattr(opts, "purpose", "") or "").strip()
    unconfirmed = set(getattr(opts, "unconfirmed_seeds", ()) or ())
    typed = bool(node.seed) and node.key not in unconfirmed
    return (scope == "all" and bool(purpose) and typed), False


def generic_reason(node: Node, logs: Iterable[StealerLog] | None = None) -> str:
    """Why an identity is generic or shared (CR11, A4 BR6), '' when it is not: the bundled
    generic/role/test list, a module's ``generic_address``/``role_account`` flag, LeakCheck found
    >= 100 (``breach_hit_count``) or Hudson Rock >= 5 infected computers."""
    reasons: list[str] = []
    if node.entity.type is EntityType.EMAIL:
        kind = _entities.generic_address_kind(node.entity)
        if kind:
            reasons.append({"role": "role mailbox", "test": "test address", "example_domain": "IANA example/test domain"}.get(kind, kind)
                           + " (data/generic_addresses.json)")
    for value in node.attr_values("generic_address"):
        if value and str(value) not in ("True", "true"):
            reasons.append(f"flagged generic: {value}")
        elif value:
            reasons.append("flagged generic by a source module")
    if any(v is True for v in node.attr_values("role_account")):
        reasons.append("role mailbox (role_account)")
    hits = [n for n in (_int(v) for v in node.attr_values("breach_hit_count")) if n is not None]
    if hits and max(hits) >= LEAKCHECK_SHARED_FOUND:
        reasons.append(f"{max(hits)} breach-corpus hits (LeakCheck found >= {LEAKCHECK_SHARED_FOUND})")
    computers = len(list(logs if logs is not None else stealer_logs(node)))
    if computers >= SHARED_STEALER_COMPUTERS:
        reasons.append(f"{computers} infected computers (Hudson Rock >= {SHARED_STEALER_COMPUTERS})")
    return "; ".join(dict.fromkeys(reasons))


def _domain_created(graph: Graph, node: Node, now: _dt.datetime) -> tuple[_dt.datetime | None, str]:
    """RDAP creation date of the address's domain (its registrable domain as fallback), or None."""
    domain = _email_domain(node)
    if not domain:
        return None, ""
    names = [domain]
    reg = psl.registrable_domain(domain)
    if reg and reg != domain:
        names.append(reg)
    for name in names:
        dom = graph.get(f"domain:{name}")
        if dom is None:
            continue
        dates = [d for d in (_bounds(v)[0] for v in dom.attr_values("created")) if d]
        if dates:
            return min(dates), name
        ages = [a for a in (_int(v) for v in dom.attr_values("domain_age_days")) if a is not None and a >= 0]
        if ages:
            return now - _dt.timedelta(days=max(ages)), name
    return None, domain


# ----------------------------------------------------------------------------------------
# Céos verdict heuristics (P146 cond 9): named functions, one P322 criterion each
# ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Signal:
    """One heuristic result: ``level`` ok | alert | doubt | against and the P322 ``criterion``."""

    name: str
    level: str
    criterion: str


@dataclass(frozen=True)
class Verdict:
    """The suggested verdict ('positive' | 'false_positive' | 'inconclusive') and the 2-3 criteria
    that drove it. A suggestion for the analyst, never a decision about a person (LGPD art. 20)."""

    verdict: str
    drivers: tuple[str, ...]

    @property
    def label(self) -> str:
        return self.verdict.replace("_", " ")

    def text(self) -> str:
        return f"suggested verdict: {self.label} (" + "; ".join(self.drivers) + ")"


def is_fabricated_against(breaches: Iterable[MergedBreach]) -> Signal | None:
    """HIBP IsFabricated: the listing is fabricated (against)."""
    names = [b.name for b in breaches if b.fabricated]
    if not names:
        return None
    return Signal("is_fabricated_against", AGAINST, f"breach flagged fabricated by HIBP (IsFabricated): {', '.join(names[:3])}")


def spam_list_alert(breaches: Iterable[MergedBreach]) -> Signal | None:
    """A spam list: the address circulated, an account at the service is not implied (alert)."""
    names = [b.name for b in breaches if b.spam_list]
    if not names:
        return None
    return Signal("spam_list_alert", ALERT, f"listed in a spam list ({', '.join(names[:3])}): the address circulated, no account is implied")


def compilation_doubt(breaches: Iterable[MergedBreach]) -> Signal | None:
    """A compilation or combo list (Collection, AntiPublic, Exploit.in...): re-served data of unknown origin (doubt)."""
    names = [b.name for b in breaches if b.compilation]
    if not names:
        return None
    return Signal("compilation_doubt", DOUBT, f"compilation/combo list ({', '.join(names[:3])}): re-served data, the original breach is unknown")


def sources_agree(breaches: Iterable[MergedBreach], min_families: int = MIN_CONFIRMING_FAMILIES) -> Signal | None:
    """>= 2 independent upstream families report the identity's (non-fabricated) breaches (ok)."""
    items = [b for b in breaches if not b.fabricated]
    families = independent_families([v for b in items for v in b.votes])
    if len(families) < min_families:
        return None
    return Signal("sources_agree", OK, f"confirmed by {len(families)} independent sources ({', '.join(families[:4])})")


def verified_listing(breaches: Iterable[MergedBreach]) -> Signal | None:
    """A verified breach listing (ok); only unverified listings (alert)."""
    items = [b for b in breaches if not b.fabricated]
    if not items:
        return None
    verified = [b.name for b in items if b.verified]
    if verified:
        return Signal("verified_listing", OK, f"verified breach listing ({', '.join(verified[:3])})")
    return Signal("verified_listing", ALERT, "only unverified breach listings")


def profile_plausible(graph: Graph, node: Node, breaches: Iterable[MergedBreach]) -> Signal | None:
    """The subject has a public profile/account on a breached service's domain: the exposure is plausible (ok)."""
    domains = {b.domain: b for b in breaches if b.domain and not b.fabricated}
    if not domains:
        return None
    hosts: set[str] = set()
    for edge in graph.edges:
        if edge.src == node.key and edge.relation == "has_account":
            value = edge.dst.split(":", 1)[-1]
            host = _entities.url_host(value) if "://" in value else value.split(":", 1)[0]
            hosts.add(host)
    for prof in node.attr_values("profiles"):
        if isinstance(prof, Mapping):
            hosts.add(_entities.url_host(str(prof.get("url") or "")))
            hosts.add(str(prof.get("platform") or "").lower())
    regs = {psl.registrable_domain(h) or h for h in hosts if h}
    for domain, item in domains.items():
        if domain in regs or (psl.registrable_domain(domain) or domain) in regs or breach_key(domain) in {breach_key(h) for h in regs}:
            if item.sensitive:  # the service domain would name the sensitive breach (LGPD art. 11)
                return Signal("profile_plausible", OK, "the subject has a public profile on the breached service (sensitive breach, "
                              "name withheld): plausible")
            return Signal("profile_plausible", OK, f"the subject has a public profile on {domain}, the breached service ({item.name}): plausible")
    return None


def stealer_alert(logs: Iterable[StealerLog]) -> Signal | None:
    """Seen in infostealer logs: malware on a device that used the identity (alert)."""
    items = list(logs)
    if not items:
        return None
    families = sorted({lg.family for lg in items if lg.family})
    return Signal("stealer_alert", ALERT, f"seen in {len(items)} infostealer log(s)" + (f" ({', '.join(families[:3])})" if families else ""))


def domain_after_breach_against(created: _dt.datetime | None, earliest_high: _dt.datetime | None, label: str = "", domain: str = "") -> Signal | None:
    """The address's domain was registered (RDAP) after the breach: the address could not exist then (against)."""
    if created is None or earliest_high is None or earliest_high >= created:
        return None
    return Signal(
        "domain_after_breach_against", AGAINST,
        f"breach listing {label or earliest_high.date().isoformat()} predates the RDAP creation of {domain or 'the domain'} "
        f"({created.date().isoformat()})",
    )


def generic_alert(reason: str) -> Signal | None:
    """Generic, role, test or shared identity (too many hits): never scored as exposure (alert)."""
    return Signal("generic_alert", ALERT, f"generic or shared address: {reason}") if reason else None


def ownership_signal(own_verified: bool, typed_seed: bool) -> Signal:
    """Supplied by the analyst or on a verified org domain (ok); found elsewhere (alert)."""
    if own_verified:
        return Signal("ownership", OK, "address on a verified org-profile domain")
    if typed_seed:
        return Signal("ownership", OK, "address supplied by the analyst (typed seed)")
    return Signal("ownership", ALERT, "address found elsewhere (not supplied by the analyst)")


def suggest_verdict(signals: Iterable[Signal | None]) -> Verdict:
    """Céos rule: fabricated or domain-after-breach -> false positive; (verified or >= 2 sources) and
    not spam/compilation and (strong ownership or a plausible service) and not generic -> positive;
    otherwise inconclusive. The 2-3 driving criteria come with it."""
    items = [s for s in signals if s is not None]
    against = [s for s in items if s.level == AGAINST]
    if against:
        return Verdict("false_positive", tuple(s.criterion for s in against[:3]))
    confirmed = [s for s in items if s.name in ("verified_listing", "sources_agree") and s.level == OK]
    anchored = [s for s in items if s.name in ("ownership", "profile_plausible") and s.level == OK]
    blockers = [s for s in items if s.name in ("spam_list_alert", "compilation_doubt", "generic_alert")]
    if confirmed and anchored and not blockers:
        drivers = [confirmed[0], anchored[0], *confirmed[1:2]]
        return Verdict("positive", tuple(s.criterion for s in drivers[:3]))
    drivers = blockers or [s for s in items if s.level in (ALERT, DOUBT)]
    if not drivers:
        drivers = [Signal("missing", DOUBT, "no verified listing and no second independent source" if not confirmed else
                          "the address is neither on a verified org domain nor supplied by the analyst")]
    return Verdict("inconclusive", tuple(s.criterion for s in drivers[:3]))


# ----------------------------------------------------------------------------------------
# Output helpers
# ----------------------------------------------------------------------------------------


def _sentence(text: str) -> str:
    """First letter upper-case, the rest untouched (str.capitalize would lower-case names)."""
    return text[:1].upper() + text[1:]


def _scrub(text: str) -> str:
    """Every output string passes the P145 text scrubber (combos, hashes, hints and secrets dropped)."""
    try:
        return _sanitize.scrub_text(text)
    except Exception:  # noqa: BLE001 - fail closed: never emit a string that could not be scrubbed
        return "[removed by the sanitizer]"


def _finish(corr: Correlation) -> Correlation:
    corr.title = _scrub(corr.title)
    corr.description = _scrub(corr.description)
    corr.recommendation = _scrub(corr.recommendation)
    corr.criterion = _scrub(corr.criterion)
    corr.why = _scrub(corr.why)
    corr.evidence = [_scrub(e) for e in corr.evidence]
    corr.ensure_id()
    return corr


def _ownership_tags(own: bool) -> list[str]:
    return ["own_asset"] if own else ["third_party", "context_only"]


def _cap(severity: Severity, ceiling: Severity) -> Severity:
    return min(severity, ceiling)


def _apply_suppressions(corr: Correlation, generic: str, predates: Signal | None) -> Correlation:
    """Suppression only downgrades, with a visible label (P146 cond 2, 4)."""
    if generic:
        corr.severity = _cap(corr.severity, GENERIC_MAX)
        corr.downgrade(SUPPRESSION_GENERIC, f"generic or shared address ({generic})", to=Confidence.POSSIBLE)
        if "context_only" not in corr.tags:
            corr.tags.append("context_only")
    if predates is not None:
        corr.downgrade(SUPPRESSION_PREDATES, predates.criterion)
    return corr


def _decay(age_days: int | None) -> str:
    if age_days is None:
        return "log date unknown"
    weight = math.exp(-age_days / STEALER_DECAY_TAU_DAYS)
    return f"log age {age_days} day(s); decay weight e^(-age/{STEALER_DECAY_TAU_DAYS}d) = {weight:.2f} (P302)"


def _identities(graph: Graph) -> list[Node]:
    return [n for n in graph.nodes.values() if n.entity.type in _IDENTITY_TYPES]


# ----------------------------------------------------------------------------------------
# CR09 corporate_credentials_in_infostealer
# ----------------------------------------------------------------------------------------


@rule(
    RULE_INFOSTEALER,
    "Corporate credentials in infostealer logs",
    "An identity in infostealer logs (metadata only: compromise date, stealer family, service counts). CRITICAL only for an "
    "address on a verified org-profile domain with a log at most 12 months old; older own-domain logs with corporate "
    "services > 0 are HIGH, other older ones MEDIUM (decay tau 1 year). Third-party identities are context only (at most "
    "MEDIUM, no exposure score) and evaluated only under the A4 breach scope; generic/shared identities are capped at "
    "POSSIBLE (P146 cond 2, 5, 7).",
    version="1",
    code="CR09",
    severity="critical",
    criterion="stealer log <= 12 months on a verified own domain (CRITICAL); older with corporate services > 0 (HIGH); "
    "other older (MEDIUM); third-party context <= MEDIUM",
    references=(*_REFERENCES, "https://www.hudsonrock.com/free-tools"),
    attack=("T1555.003", "T1539", "T1078"),
    false_positives="A shared or role mailbox typed on many machines; an old log of a credential already rotated; an "
    "employee's personal device (still an incident-response matter, never a disciplinary one).",
    fixtures=(
        f"tests/fixtures/rules/{RULE_INFOSTEALER}/positive_recent_own_domain_log_critical.json",
        f"tests/fixtures/rules/{RULE_INFOSTEALER}/positive_two_year_old_log_high.json",
        f"tests/fixtures/rules/{RULE_INFOSTEALER}/positive_generic_test_address_capped_possible.json",
        f"tests/fixtures/rules/{RULE_INFOSTEALER}/negative_third_party_outside_breach_scope.json",
    ),
)
def corporate_credentials_in_infostealer(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterator[Correlation]:
    now = _now(rctx)
    org = getattr(rctx, "org", None)
    for node in _identities(graph):
        logs = stealer_logs(node)
        flagged = any(v is True for v in node.attr_values("infostealer"))
        if not logs and not flagged:
            continue
        evaluate, own = in_breach_scope(node, rctx)
        if not evaluate:
            continue  # A4 BR9-BR10: third parties only as typed seeds under --breach-scope all + purpose
        dated = [lg for lg in logs if lg.date is not None]
        newest = max(dated, key=lambda lg: lg.date) if dated else None  # type: ignore[arg-type, return-value]
        age = max(0, (now - newest.date).days) if newest is not None and newest.date is not None else None
        corporate = [lg for lg in logs if (lg.corporate or 0) > 0]
        if age is not None and age <= STEALER_RECENT_DAYS:
            severity, why_sev = Severity.CRITICAL, f"log {age} day(s) old (<= {STEALER_RECENT_DAYS})"
        elif corporate:
            severity, why_sev = Severity.HIGH, f"log older than {STEALER_RECENT_DAYS} days or undated, corporate services > 0"
        else:
            severity, why_sev = Severity.MEDIUM, f"log older than {STEALER_RECENT_DAYS} days or undated, no corporate services"
        if not own:
            severity = _cap(severity, THIRD_PARTY_MAX)
        logs_text = "; ".join(
            f"{lg.date_text[:10] or 'undated'}" + (f" {lg.family}" if lg.family else "")
            + (f", corporate services {lg.corporate}" if lg.corporate is not None else "")
            + (f", user services {lg.user}" if lg.user is not None else "")
            for lg in sorted(logs, key=lambda lg: lg.date_text, reverse=True)[:5]
        ) or "flagged by a source (no record kept)"
        scope = "verified org-profile domain" if own else "third-party identity under the A4 breach scope: context only, no exposure score"
        criterion = (f"CR09: {len(logs) or 'an'} infostealer record(s) ({logs_text}); {why_sev}; {scope}")
        generic = generic_reason(node, logs)
        created, domain = _domain_created(graph, node, now)
        predates = None
        if created is not None and dated and all(lg.date is not None and lg.date < created for lg in dated):
            newest_date = max(lg.date for lg in dated if lg.date is not None)
            predates = domain_after_breach_against(created, newest_date, "stealer log", domain)
        title = (f"Corporate credentials in infostealer logs: {node.entity.display}" if own
                 else f"Identity in infostealer logs (context): {node.entity.display}")
        corr = Correlation(
            rule=RULE_INFOSTEALER,
            title=title,
            severity=severity,
            description=(
                f"{node.entity.display} appears in infostealer logs: {logs_text}. "
                + ("Malware on a device that used this corporate identity captured its saved credentials and session data. "
                   if own else "Not a verified own asset: shown as context, never scored as exposure. ")
                + LGPD_NOTICE
            ),
            entities=[node.entity],
            confidence=Confidence.PROBABLE if logs else Confidence.POSSIBLE,
            evidence=[logs_text, _decay(age), *([f"newest log family {newest.family}"] if newest is not None and newest.family else [])],
            recommendation=(
                "Route to incident response: reset the password, revoke sessions and tokens, enforce MFA and check the device for "
                "malware. " if own else "Context for the investigation: notify the identity's owner only through an approved process. "
            ) + NEVER_TESTED + " " + LGPD_NOTICE,
            tags=["infostealer", "privacy", *(["credential_exposure"] if own and not generic else []), *_ownership_tags(own)],
            criterion=criterion,
            why=f"{logs_text}; {_decay(age)}",
        )
        yield _finish(_apply_suppressions(corr, generic, predates))
    # verified own domains: employee counts only (hudson_rock_domain, no dates)
    for node in graph.of_type(EntityType.DOMAIN):
        try:
            verified = bool(org is not None and org.is_verified_domain(node.entity.value))
        except Exception:  # noqa: BLE001
            verified = False
        if not verified:
            continue
        employees = 0
        families: list[str] = []
        for value in node.attr_values("stealer_exposure"):
            if isinstance(value, Mapping):
                employees = max(employees, _int(value.get("employees")) or 0)
                fams = value.get("stealer_families")
                if isinstance(fams, (Mapping, list)):
                    families += [str(k) for k in fams]
        if employees <= 0:
            continue
        counts = f"{employees} employee identit{'y' if employees == 1 else 'ies'} in infostealer logs (counts only)"
        corr = Correlation(
            rule=RULE_INFOSTEALER,
            title=f"Corporate credentials in infostealer logs: {node.entity.display} (domain counts)",
            severity=Severity.HIGH,
            description=(f"{counts} for the verified org domain {node.entity.display}"
                         + (f"; stealer families {', '.join(sorted(set(families))[:5])}" if families else "")
                         + ". No dates are available at domain level, so this is not CRITICAL; per-identity checks date the logs. "
                         + LGPD_NOTICE),
            entities=[node.entity],
            confidence=Confidence.PROBABLE,
            evidence=[counts],
            recommendation="Route to incident response: identify the affected accounts through the own-domain identity checks, "
            "reset credentials and sessions, enforce MFA. " + NEVER_TESTED + " " + LGPD_NOTICE,
            tags=["infostealer", "credential_exposure", "own_asset"],
            criterion=f"CR09: verified org domain with {counts}; undated (CRITICAL needs a dated log <= {STEALER_RECENT_DAYS} days)",
            why=counts,
        )
        yield _finish(corr)


# ----------------------------------------------------------------------------------------
# CR10 email_in_multiple_password_breaches
# ----------------------------------------------------------------------------------------


@rule(
    RULE_MULTI_BREACH,
    "Address in several password breaches",
    "An e-mail address listed in >= 3 verified password breaches, or in >= 2 password breaches confirmed by 2 independent "
    "sources, at least one within the last 3 years: HIGH for verified own-domain addresses, context (at most MEDIUM) for "
    "third parties under the A4 breach scope. The same breach re-served by aggregators counts once; fabricated and "
    "spam-list breaches never count; the suggested verdict comes with its criteria (P146 cond 6, 8, 9).",
    version="1",
    code="CR10",
    severity="high",
    criterion=">= 3 verified password breaches, or >= 2 confirmed by 2 independent sources, one within 3 years; HIGH for "
    "own-domain addresses, <= MEDIUM context for third parties",
    references=_REFERENCES,
    attack=("T1589.001", "T1110.004", "T1078"),
    false_positives="Breaches of a previous owner of a recycled address or domain; compilation lists that re-serve old "
    "data; an address used only for newsletters.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_MULTI_BREACH}/positive_three_verified_own_high.json",
        f"tests/fixtures/rules/{RULE_MULTI_BREACH}/positive_two_sources_third_party_context.json",
        f"tests/fixtures/rules/{RULE_MULTI_BREACH}/negative_same_upstream_counted_once.json",
        f"tests/fixtures/rules/{RULE_MULTI_BREACH}/negative_old_or_fabricated_breaches.json",
    ),
)
def email_in_multiple_password_breaches(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterator[Correlation]:
    now = _now(rctx)
    registry = provider_registry(rctx)
    for node in graph.of_type(EntityType.EMAIL):
        records = breach_records(graph, node)
        if not records:
            continue
        evaluate, own = in_breach_scope(node, rctx)
        if not evaluate:
            continue
        merged = merge_breaches(records, registry)
        counted = [b for b in merged if b.counted]
        if not counted:
            continue
        verified = [b for b in counted if b.verified]
        families = independent_families([v for b in counted for v in b.votes])
        recent_limit = now - _dt.timedelta(days=RECENT_BREACH_DAYS)
        recent = [b for b in counted if b.bounds[1] is not None and b.bounds[1] >= recent_limit]
        by_verified = len(verified) >= MIN_VERIFIED_BREACHES
        by_sources = len(counted) >= MIN_BREACHES_CONFIRMED and len(families) >= MIN_CONFIRMING_FAMILIES
        if not (by_verified or by_sources) or not recent:
            continue
        generic = generic_reason(node)
        created, domain = _domain_created(graph, node, now)
        low, high, label = earliest_breach(node, counted)
        predates = domain_after_breach_against(created, high, label, domain)
        # the verdict is about the breaches that counted: fabricated listings are already left out (and
        # named under 'Not counted'), so they never turn a correlation built on other breaches into a
        # 'false positive'; spam-list and compilation listings of the identity still weigh as alert/doubt
        signals = [
            is_fabricated_against(counted), spam_list_alert(merged), compilation_doubt(merged), sources_agree(counted),
            verified_listing(counted), profile_plausible(graph, node, counted), generic_alert(generic), predates,
            ownership_signal(own, node.seed and node.key not in set(getattr(getattr(rctx, "options", None), "unconfirmed_seeds", ()) or ())),
        ]
        verdict = suggest_verdict(signals)
        listed = "; ".join(b.describe() for b in counted[:6])
        how = (f"{len(verified)} verified password breaches (>= {MIN_VERIFIED_BREACHES})" if by_verified
               else f"{len(counted)} password breaches confirmed by {len(families)} independent sources ({', '.join(families)})")
        excluded = [b.name for b in merged if b.fabricated or b.spam_list]
        severity = Severity.HIGH if own else THIRD_PARTY_MAX
        corr = Correlation(
            rule=RULE_MULTI_BREACH,
            title=(f"Address in several password breaches: {node.entity.display}" if own
                   else f"Address in several password breaches (context): {node.entity.display}"),
            severity=severity,
            description=(
                f"{node.entity.display} is listed in password breaches: {listed}. Exposure is breach METADATA only (names, dates, "
                f"data classes, password form). {_sentence(verdict.text())}; a suggestion, the analyst decides."
                + ("" if own else " Not a verified own asset: context only, never scored as exposure.")
                + (f" Not counted: {', '.join(excluded[:4])} (fabricated or spam list)." if excluded else "")
            ),
            entities=[node.entity],
            confidence=Confidence.PROBABLE,
            evidence=[listed, verdict.text(), *([f"earliest listing {label}"] if label else [])],
            recommendation=("Make sure the password was changed after the newest breach and is not reused, enforce MFA and watch "
                            "for credential stuffing against corporate services. " if own else
                            "Context for the investigation only: notify the owner through an approved process. ")
            + NEVER_TESTED + " " + LGPD_NOTICE,
            tags=["breach", "privacy", *(["credential_exposure"] if own and not generic else []), *_ownership_tags(own)],
            criterion=f"CR10: {how}; newest within {RECENT_BREACH_DAYS // 365} years ({recent[-1].describe()})",
            why=verdict.text(),
        )
        yield _finish(_apply_suppressions(corr, generic, predates))


# ----------------------------------------------------------------------------------------
# CR11 generic_or_shared_email_suppression
# ----------------------------------------------------------------------------------------


@rule(
    RULE_GENERIC,
    "Generic or shared address: breach and stealer hits capped at POSSIBLE",
    "A generic, role or test address (data/generic_addresses.json, a module's generic flag), or an identity with >= 100 "
    "breach-corpus hits (LeakCheck found) or >= 5 infected computers (Hudson Rock), that carries breach or stealer facts: "
    "every correlation about it is capped at POSSIBLE and never scored as exposure. Suppression only downgrades, with this "
    "visible label; it never deletes (P146 cond 2-3, A4 BR6).",
    version="1",
    code="CR11",
    severity="info",
    criterion="generic/role/test list, a module's generic flag, LeakCheck found >= 100 or Hudson Rock >= 5 computers, plus "
    "breach or stealer facts",
    references=_REFERENCES,
    attack=("T1589.002",),
    false_positives="A personal address whose local part happens to be on the role list (e.g. a person named 'rh'); a "
    "shared mailbox whose exposure the organisation still wants to rotate.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_GENERIC}/positive_test_example_five_stealers.json",
        f"tests/fixtures/rules/{RULE_GENERIC}/positive_leakcheck_found_over_100.json",
        f"tests/fixtures/rules/{RULE_GENERIC}/negative_personal_address.json",
    ),
)
def generic_or_shared_email_suppression(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterator[Correlation]:
    for node in _identities(graph):
        logs = stealer_logs(node)
        records = breach_records(graph, node)
        counts = [n for n in (_int(v) for v in node.attr_values("breach_count") + node.attr_values("breach_hit_count")) if n]
        flagged = any(v is True for v in node.attr_values("infostealer"))
        if not (logs or records or counts or flagged):
            continue
        evaluate, own = in_breach_scope(node, rctx)
        if not evaluate:
            continue
        generic = generic_reason(node, logs)
        if not generic:
            continue
        verdict = suggest_verdict([generic_alert(generic), stealer_alert(logs)])
        facts = []
        if records:
            facts.append(f"{len({r.key for r in records})} breach listing(s)")
        if logs:
            facts.append(f"{len(logs)} infostealer record(s)")
        if counts:
            facts.append(f"breach counts up to {max(counts)}")
        corr = Correlation(
            rule=RULE_GENERIC,
            title=f"Generic or shared address: hits capped at POSSIBLE ({node.entity.display})",
            severity=Severity.INFO,
            description=(
                f"{node.entity.display} is a generic or shared identity ({generic}); its {', '.join(facts) or 'breach facts'} are "
                f"capped at POSSIBLE and never scored as exposure. {_sentence(verdict.text())}."
            ),
            entities=[node.entity],
            confidence=Confidence.POSSIBLE,
            evidence=[generic, *facts],
            recommendation="No exposure score: review only if the shared mailbox's credentials are in use. " + NEVER_TESTED,
            tags=["breach", "privacy", "context_only", *(["infostealer"] if logs else []), *(["own_asset"] if own else ["third_party"])],
            criterion=f"POSSIBLE - generic or shared address ({generic}) (CR11, A4 BR6)",
            why=verdict.text(),
        )
        yield _finish(corr)


# ----------------------------------------------------------------------------------------
# CR12 breach_predates_domain
# ----------------------------------------------------------------------------------------


@rule(
    RULE_PREDATES,
    "Breach listing predates the address's domain",
    "The earliest breach listing of an e-mail address (first_seen_breach or a dated breach record) is older than the RDAP "
    "creation date of the address's domain: the address could not exist then, so the listing is a probable false positive "
    "or belongs to a previous owner of a re-registered domain. Silent when the creation date is unknown; CR09/CR10 "
    "correlations of the address are downgraded with this criterion (P146 cond 4).",
    version="1",
    code="CR12",
    severity="info",
    criterion="earliest breach date (latest possible day of its period) < RDAP creation date of the address's domain",
    references=(*_REFERENCES, "https://about.rdap.org/"),
    attack=("T1589.001",),
    false_positives="A domain dropped and re-registered by the same organisation (RDAP shows the new creation date); a "
    "breach date that the source reports approximately.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_PREDATES}/positive_breach_before_registration.json",
        f"tests/fixtures/rules/{RULE_PREDATES}/negative_no_creation_date.json",
        f"tests/fixtures/rules/{RULE_PREDATES}/negative_breach_after_registration.json",
    ),
)
def breach_predates_domain(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterator[Correlation]:
    now = _now(rctx)
    registry = provider_registry(rctx)
    for node in graph.of_type(EntityType.EMAIL):
        records = breach_records(graph, node)
        if not records and not node.attr_values("first_seen_breach"):
            continue
        evaluate, own = in_breach_scope(node, rctx)
        if not evaluate:
            continue
        created, domain = _domain_created(graph, node, now)
        if created is None:
            continue  # cond 4: silent without the RDAP creation date
        merged = merge_breaches(records, registry)
        low, high, label = earliest_breach(node, merged)
        against = domain_after_breach_against(created, high, label, domain)
        if against is None:
            continue
        verdict = suggest_verdict([against, is_fabricated_against(merged)])
        corr = Correlation(
            rule=RULE_PREDATES,
            title=f"Breach listing predates the address's domain: {node.entity.display}",
            severity=Severity.INFO,
            description=(
                f"The earliest breach listing of {node.entity.display} ({label}) is older than the RDAP creation of {domain} "
                f"({created.date().isoformat()}): the address could not exist then. A probable false positive, or the breach of "
                f"a previous owner of a re-registered domain. {_sentence(verdict.text())}."
            ),
            entities=[node.entity],
            confidence=Confidence.PROBABLE,
            evidence=[against.criterion, verdict.text()],
            recommendation="Treat the listing as unconfirmed for this address; check whether the domain was re-registered. "
            + NEVER_TESTED,
            tags=["breach", "privacy", "context_only", *(["own_asset"] if own else ["third_party"])],
            criterion=f"CR12: {against.criterion} (confidence of the breach correlations downgraded)",
            why=verdict.text(),
        )
        yield _finish(corr)
