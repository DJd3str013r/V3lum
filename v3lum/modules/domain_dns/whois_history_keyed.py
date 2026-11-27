"""WHOIS history and reverse WHOIS through paid APIs (P022 whois_history_keyed): WhoisXML API, Whoxy, WhoisFreaks.

A domain seed gets its historical WHOIS records (registrar, dates, nameservers, status and the registrant values
an analyst may select); an e-mail, organisation or person-name seed gets the domains whose (historical) WHOIS
record shows the same registrant value (reverse WHOIS). Results are candidates, never scope.

Final conditions (council #1, P022) and where they live:

1. One adapter per provider (:class:`WhoisXmlAdapter`, :class:`WhoxyAdapter`, :class:`WhoisFreaksAdapter`), each
   with its own key (provider fragments ``whoisxmlapi`` / ``whoxy_api`` / ``whoisfreaks``: keys ``whoisxml``,
   ``whoxy``, ``whoisfreaks``, env ``V3LUM_WHOISXML_KEY`` / ``V3LUM_WHOXY_KEY`` / ``V3LUM_WHOISFREAKS_KEY``), its
   own per-source status (``res.source_status``) and its own credit budget: the provider quota block (P334
   monthly window, request counts) plus a credit-weighted monthly budget kept in ``ctx.state``
   (:class:`CreditBook`, setting ``whois_history_keyed_monthly_credits``: a WhoisXML history purchase costs 50
   DRS credits). Terms 'license' per source: under corporate the licence gate runs an adapter only with a
   licence_allow entry recording the company purchase (the module queries ``ctx.allowed_sources`` only).
   WhoisXML gets its key in the X-Authentication-Token header; Whoxy (``?key=``) and WhoisFreaks (``?apiKey=``)
   take it in the URL, passed only as ``params`` to ``ctx.http`` so the central redactor masks it (AR01).
2. ``default_enabled = False`` and ``run_on = 'seeds'``: never on auto-pivoted entities. Every pivot is
   ``expand=False``: candidates, never scope.
3. Reverse WHOIS by registrant e-mail or person name only when (a) the value is an analyst-typed, confirmed seed,
   (b) the case has a recorded purpose and (c) the value is already in a WHOIS/RDAP record of the case: an
   in-edge ``registrant`` / ``registrant_email`` from a registration module, or a ``registrant_selectors`` /
   ``registrant_email`` attribute of one, in the live case graph (:func:`registration_provenance`). No
   free-text person search (rule 4); a refusal is SKIPPED ``privacy`` with the reason.
4. Privacy/proxy and redacted values (the P003 list ``v3lum/data/rdap/privacy_proxy.json`` + :data:`EXTRA_PRIVACY_PATTERNS`,
   placeholder e-mails with privacy/proxy/redacted/whoisguard words, contact-form texts, generic placeholders
   and role names) are never selectors (:meth:`Privacy.marker`), never reverse-WHOIS inputs and never CR32 keys.
5. Minimisation at ingestion (:func:`minimise_contact`): only e-mail/organisation/name/country of the registrant
   contact are read; street, city, postal code, phones, faxes, raw text and admin/tech/billing contacts are
   never kept. History records keep domain, registrar, dates, nameservers, status, registrant kind and the
   organisation of organisation registrants; natural-person values survive only as ``registrant_selectors`` /
   ``email`` pivots (privacy tag on the finding, case retention). Reverse items keep domain, registrar, dates,
   the record date and the matched field. ``res.raw`` holds only the minimised structures.
6. Every record carries its record date (WhoisXML ``audit.updatedDate``, Whoxy/WhoisFreaks ``query_time``) and
   records last seen before 2018-05-25 are labelled 'historical (pre-GDPR)'. CR32 confidence follows the match
   field: e-mail 0.7 > organisation 0.6 > name 0.4 (POSSIBLE when the record shows another value in that field).
7. ``cache_ttl`` 30 days (<= cache_max_age_days); reverse queries run inside a case, so their cache rows are
   recorded per case and removed by the case purge. Error bodies: Whoxy ``{status:0,'Invalid API Key'}`` and
   WhoisFreaks 400 'Please provide apikey' -> NEEDS_KEY; credit/balance answers -> QUOTA (provider markers);
   429 -> RATE_LIMITED; HTML or malformed answers -> ERROR 'could not verify', never EMPTY.
8. Fixtures: the real error bodies of all three providers are in tests; trimmed real success answers captured
   with the team keys are still owed (docs/backlog/p3-G01-2.md).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core import psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    Cancelled,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    OfflineError,
    QuotaExceeded,
    RateLimited,
    RequestCapReached,
)
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.domain_dns.rdap import PrivacyList, load_privacy_list

MODULE = "whois_history_keyed"
SRC_WHOISXML = "whoisxmlapi.drs"
SRC_WHOXY = "whoxy_api.api"
SRC_WHOISFREAKS = "whoisfreaks.api"
WHOISXML_HISTORY_URL = "https://whois-history.whoisxmlapi.com/api/v1"
WHOISXML_REVERSE_URL = "https://reverse-whois.whoisxmlapi.com/api/v2"
WHOXY_URL = "https://api.whoxy.com/"
WHOISFREAKS_URL = "https://api.whoisfreaks.com/v1.0/whois"

#: P022 cond 7: 30 days (the default cache_max_age_days cap, A10).
CACHE_TTL = 30 * 86400
#: P022 cond 6: records last observed before the GDPR application date are 'historical (pre-GDPR)'.
GDPR_CUTOFF = date(2018, 5, 25)
HISTORICAL_LABEL = "historical (pre-GDPR)"
#: a reverse selector matching more domains is a reseller/registrar/privacy value: no CR32 cluster, no pivots.
REVERSE_GENERIC_THRESHOLD = 500
MAX_REVERSE_KEEP = 500
MAX_REVERSE_PIVOTS = 100
MAX_HISTORY_RECORDS = 100
MAX_SELECTORS = 20
MAX_REVERSE_PAGES = 3
#: CR32 confidence per match field (P022 cond 6; P258: links between natural persons stay <= PROBABLE).
CR32_MATCH_CONFIDENCE: dict[str, tuple[str, float]] = {
    "email": ("probable", 0.7),
    "organization": ("probable", 0.6),
    "name": ("possible", 0.4),
}
FIELD_LABELS = {"email": "registrant e-mail", "organization": "registrant organisation", "name": "registrant name"}
SELECTOR_KIND = {"email": "email", "organization": "company_name", "name": "person_name"}
#: credits per request (documented 2026-11-26): WhoisXML DRS pool, Whoxy prepaid queries, WhoisFreaks credit ledger.
CREDIT_COST: dict[tuple[str, str, str], int] = {
    ("whoisxml", "history", "preview"): 1,
    ("whoisxml", "history", "purchase"): 50,
    ("whoisxml", "reverse", "preview"): 0,
    ("whoisxml", "reverse", "purchase"): 1,
    ("whoxy", "history", ""): 1,
    ("whoxy", "reverse", ""): 1,
    ("whoisfreaks", "history", ""): 2,
    ("whoisfreaks", "reverse", ""): 5,
}
DEFAULT_MONTHLY_CREDITS = {"whoisxml": 400, "whoxy": 400, "whoisfreaks": 400}
#: Whoxy stays off by default: whoxy.com shows a public 'recent WHOIS lookups' list and it is not yet verified
#: that API lookups never feed it (rule 7). Add 'whoxy' to the setting once the team-key check is recorded.
DEFAULT_PROVIDERS = ["whoisxml", "whoisfreaks"]
#: modules whose registrant edges/attributes count as 'a WHOIS/RDAP record of the case' (P022 cond 3).
REGISTRATION_MODULES = frozenset({"rdap", "whois_fallback", "whois_fallback_public", MODULE})
REGISTRANT_RELATIONS = frozenset({"registrant", "registrant_email"})
REGISTRANT_ATTRIBUTES = frozenset({"registrant_selectors", "registrant_email", "registrant"})
#: failure rank when no adapter answered (the most specific 'could not verify' wins).
_FAILURE_RANK = {Status.RATE_LIMITED: 6, Status.QUOTA: 5, Status.BLOCKED: 4, Status.ERROR: 3, Status.NEEDS_KEY: 2, Status.SKIPPED: 1}
STOP_EXCEPTIONS = (Cancelled, DeadlineExceeded, RequestCapReached, OfflineError)

# ======================================================================================
# Privacy/proxy, placeholder and role values (P022 cond 4)
# ======================================================================================

#: additions to the P003 list for registrant e-mail/organisation placeholders seen in WHOIS-history data.
EXTRA_PRIVACY_PATTERNS = (
    "privacy-link", "identity-protect", "gdpr-masked", "protecteddomainservices", "domainprotect", "private by design",
    "privacydotlink", "whoisprotection", "proxy.dreamhost", "hidden by", "redacted by", "on behalf of", "dnstinations",
    "redacted_person", "data protected", "not disclosed",
)
PLACEHOLDER_EMAIL_WORDS = ("privacy", "proxy", "redacted", "whoisguard", "masked", "anonymi", "protect")
_CONTACT_FORM_RE = re.compile(r"https?://|www\.|contact[ -]?form|web ?form|request email form|\bform\b", re.I)
GENERIC_PLACEHOLDERS = frozenset({
    "n/a", "na", "none", "null", "nil", "-", "--", "?", "private", "personal", "individual", "unknown", "withheld",
    "undisclosed", "not available", "not applicable", "see whois", "no data", "no name", "no organization",
    "no organisation", "non-public", "domain owner", "private person", "private individual", "not provided",
    "none provided", "pessoa fisica", "pessoa física", "particular",
})
ROLE_NAMES = frozenset({
    "domain administrator", "domain admin", "domains admin", "dns admin", "dns administrator", "hostmaster",
    "webmaster", "administrator", "admin", "technical contact", "tech contact", "technical department",
    "it department", "domain manager", "domain management", "registrant", "owner", "billing", "legal department",
})
_ROLE_LOCALS_TEXT = (
    """abuse noc hostmaster postmaster security soc cert csirt dns dns-admin dnsadmin domains domain domainadmin
    domain-admin admin administrator support suporte contato contact info network netops ipadmin registry legal
    juridico privacy dpo webmaster tech technical ti helpdesk servicedesk billing financeiro registrar marketing
    compliance trademarks brand"""
)
_ROLE_LOCALS = frozenset(_ROLE_LOCALS_TEXT.split())
_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_DATE_RE = re.compile(r"(\d{4})-(\d{1,2})-(\d{1,2})")
_IANA_RE = re.compile(r"^\d{1,6}$")
_STATUS_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z_-]{0,63}$")
_LABEL_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


def _text(value: Any, limit: int = 300) -> str:
    """A provider string, control characters removed, whitespace collapsed, capped; '' for other types."""
    if not isinstance(value, str):
        return ""
    return " ".join(_CTRL_RE.sub("", value).split())[:limit]


def is_valid_email(value: Any) -> bool:
    return isinstance(value, str) and len(value) <= 254 and bool(_EMAIL_RE.match(value.strip()))


def is_role_mailbox(email: Any) -> bool:
    """Role mailbox (hostmaster@, dns-admin@, abuse@...) as opposed to an address that may belong to a person."""
    if not is_valid_email(email):
        return False
    local = email.strip().split("@", 1)[0].lower().split("+", 1)[0]
    return local in _ROLE_LOCALS or local.startswith(("abuse", "noc", "hostmaster", "dns-", "domains"))


@dataclass(frozen=True)
class Privacy:
    """The P003 privacy/proxy list plus the P022 placeholder rules (cond 4)."""

    p003: PrivacyList

    def marker(self, value: Any, kind: str) -> str | None:
        """Why a registrant value can never be a selector or a CR32 key, or None when it is usable.

        ``kind``: 'email' | 'organization' | 'name'. Markers: 'empty', 'placeholder', 'privacy_proxy',
        'placeholder_email', 'contact_form', 'role_name'."""
        v = _text(value, 300)
        if not v:
            return "empty"
        low = v.lower()
        if not any(ch.isalnum() for ch in v):
            return "placeholder"
        if self.p003.matches(v) or any(p in low for p in EXTRA_PRIVACY_PATTERNS):
            return "privacy_proxy"
        if kind == "email":
            if not is_valid_email(v):
                return "contact_form" if _CONTACT_FORM_RE.search(v) else "placeholder_email"
            if any(w in low for w in PLACEHOLDER_EMAIL_WORDS):
                return "placeholder_email"
            return None
        if _CONTACT_FORM_RE.search(v) and "@" not in v:
            return "contact_form"
        if low.strip(" .") in GENERIC_PLACEHOLDERS:
            return "placeholder"
        if low in ROLE_NAMES:
            return "role_name"
        return None


def load_privacy(ctx: Any = None) -> Privacy:
    return Privacy(load_privacy_list(ctx))


# ======================================================================================
# Records: minimisation at ingestion (P022 cond 5, 6)
# ======================================================================================

_CONTACT_KEYS: dict[str, dict[str, tuple[str, ...]]] = {
    "whoisxml": {"email": ("email",), "organization": ("organization",), "name": ("name",), "country": ("countryCode", "country")},
    "whoxy": {"email": ("email_address", "email"), "organization": ("company_name", "company"), "name": ("full_name", "name"),
              "country": ("country_code", "country_name")},
    "whoisfreaks": {"email": ("email_address", "email"), "organization": ("company", "company_name"), "name": ("name", "full_name"),
                    "country": ("country_code", "country_name")},
}


def parse_day(value: Any) -> date | None:
    """First YYYY-MM-DD in a provider date string ('2018-06-17 11:23:51.000 UTC', '2026-04-14T10:30:00Z')."""
    m = _DATE_RE.search(value) if isinstance(value, str) else None
    if not m:
        return None
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def iso_day(value: Any) -> str | None:
    d = parse_day(value)
    return d.isoformat() if d else None


def is_pre_gdpr(record_date: Any) -> bool:
    d = parse_day(record_date)
    return bool(d and d < GDPR_CUTOFF)


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _first(contact: Any, keys: Iterable[str]) -> str:
    if not isinstance(contact, Mapping):
        return ""
    for k in keys:
        v = _text(contact.get(k), 300)
        if v:
            return v
    return ""


def normalise_domain(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    d = value.strip().lower().rstrip(".")
    try:
        d = d.encode("idna").decode("ascii") if any(ord(c) > 127 for c in d) else d
    except UnicodeError:
        return None
    return d if _LABEL_RE.match(d) else None


def classify_value(kind: str, value: str, privacy: Privacy, *, registrant_name: str = "") -> dict[str, Any]:
    """{kind, value, usable, marker, natural_person} of one registrant field (P022 cond 4, 5)."""
    marker = privacy.marker(value, kind)
    out: dict[str, Any] = {"kind": kind, "value": value or None, "usable": marker is None, "marker": marker, "natural_person": False}
    if marker:
        return out
    if kind == "email":
        out["value"] = value.lower()
        out["natural_person"] = not is_role_mailbox(value)
    elif kind == "name":
        out["natural_person"] = True
    elif kind == "organization" and registrant_name and registrant_name.lower() == value.lower():
        out["natural_person"] = True  # an organisation equal to the person name is a person value
    return out


def minimise_contact(provider: str, contact: Any, privacy: Privacy) -> dict[str, Any]:
    """Only e-mail, organisation, name and country of the registrant contact are read (P022 cond 5); every
    other contact field and every other contact role is never looked at, let alone kept."""
    keys = _CONTACT_KEYS.get(provider, _CONTACT_KEYS["whoxy"])
    name = _first(contact, keys["name"])
    reg = {
        "email": classify_value("email", _first(contact, keys["email"]), privacy),
        "organization": classify_value("organization", _first(contact, keys["organization"]), privacy, registrant_name=name),
        "name": classify_value("name", name, privacy),
        "country": None,
    }
    country = _first(contact, keys["country"])
    if registrant_kind(reg) == "org" and country:
        reg["country"] = country.upper() if len(country) == 2 else country.title()[:60]
    return reg


def registrant_kind(reg: Mapping[str, Any]) -> str:
    """'org' | 'individual' | 'redacted' | 'unknown' (the P003 vocabulary)."""
    org, name, email = reg.get("organization") or {}, reg.get("name") or {}, reg.get("email") or {}
    if org.get("usable") and not org.get("natural_person"):
        return "org"
    if name.get("usable") or org.get("usable"):
        return "individual"
    if any(x.get("marker") and x.get("marker") != "empty" for x in (org, name, email)):
        return "redacted"
    return "unknown"


def _registrar(name: Any, iana: Any) -> dict[str, Any] | None:
    nm = _text(name, 120) or None
    iana_s = str(iana).strip() if isinstance(iana, (int, str)) and not isinstance(iana, bool) else ""
    out = {"name": nm, "iana_id": iana_s if _IANA_RE.match(iana_s) else None}
    return out if nm or out["iana_id"] else None


def _nameservers(value: Any) -> list[str]:
    out: list[str] = []
    for v in value if isinstance(value, list) else []:
        d = normalise_domain(v) if isinstance(v, str) else None
        if d and d not in out:
            out.append(d)
    return out[:13]


def _status_tokens(value: Any) -> list[str]:
    """EPP status tokens ('clientTransferProhibited (https://icann.org/epp#...)' -> 'clientTransferProhibited')."""
    out: list[str] = []
    for v in [value] if isinstance(value, str) else value if isinstance(value, list) else []:
        for tok in v.split() if isinstance(v, str) else []:
            if _STATUS_TOKEN_RE.match(tok) and tok not in out:
                out.append(tok)
    return out[:20]


def _record(provider: str, domain: Any, *, record_date: Any, date_source: str, first_seen: Any, created: Any, updated: Any,
            expires: Any, registrar: dict[str, Any] | None, contact: Any, nameservers: Any, status: Any,
            privacy: Privacy) -> dict[str, Any] | None:
    dom = normalise_domain(domain)
    if dom is None:
        return None
    reg = minimise_contact(provider, contact, privacy)
    kind = registrant_kind(reg)
    rd = iso_day(record_date)
    org = reg["organization"]
    return {
        "provider": provider,
        "domain": dom,
        "record_date": rd,
        "record_date_source": date_source if rd else None,
        "first_seen": iso_day(first_seen),
        "historical": is_pre_gdpr(rd),
        "label": HISTORICAL_LABEL if is_pre_gdpr(rd) else None,
        "created": iso_day(created),
        "updated": iso_day(updated),
        "expires": iso_day(expires),
        "registrar": registrar,
        "nameservers": _nameservers(nameservers),
        "status": _status_tokens(status),
        "registrant_kind": kind,
        "privacy_proxy": any((reg[f].get("marker") or "") in ("privacy_proxy", "contact_form", "placeholder_email") for f in ("email", "organization", "name")),
        "registrant_organization": org["value"] if kind == "org" else None,
        "registrant_country": reg["country"],
        "_registrant": reg,  # in-memory only: selectors are derived from it, then it is dropped
    }


def _whoxy_like_record(provider: str, r: Mapping[str, Any], privacy: Privacy) -> dict[str, Any] | None:
    reg = r.get("domain_registrar") if isinstance(r.get("domain_registrar"), Mapping) else {}
    contact = r.get("registrant_contact") if isinstance(r.get("registrant_contact"), Mapping) else _flat_contact(r)
    return _record(provider, r.get("domain_name"), record_date=r.get("query_time"), date_source="query_time", first_seen=None,
                   created=r.get("create_date"), updated=r.get("update_date"), expires=r.get("expiry_date"),
                   registrar=_registrar(reg.get("registrar_name"), reg.get("iana_id")), contact=contact,
                   nameservers=r.get("name_servers"), status=r.get("domain_status"), privacy=privacy)


def _flat_contact(r: Mapping[str, Any]) -> dict[str, Any]:
    """WhoisFreaks mini mode may flatten registrant fields (registrant_name / registrant_email / registrant_company)."""
    flat = {k[len("registrant_"):]: v for k, v in r.items() if isinstance(k, str) and k.startswith("registrant_")}
    if "email" in flat and "email_address" not in flat:
        flat["email_address"] = flat["email"]
    return flat


def _whoisxml_record(r: Mapping[str, Any], privacy: Privacy) -> dict[str, Any] | None:
    audit = r.get("audit") if isinstance(r.get("audit"), Mapping) else {}
    last, src = audit.get("updatedDate"), "audit.updatedDate"
    if not parse_day(last):
        last, src = audit.get("createdDate"), "audit.createdDate"
    if not parse_day(last):
        last, src = r.get("updatedDateISO8601") or r.get("updatedDate"), "updatedDate"
    return _record("whoisxml", r.get("domainName"), record_date=last, date_source=src, first_seen=audit.get("createdDate"),
                   created=r.get("createdDateISO8601") or r.get("createdDate"), updated=r.get("updatedDateISO8601") or r.get("updatedDate"),
                   expires=r.get("expiresDateISO8601") or r.get("expiresDate"),
                   registrar=_registrar(r.get("registrarName"), r.get("registrarIANAID")), contact=r.get("registrantContact"),
                   nameservers=r.get("nameServers"), status=r.get("status"), privacy=privacy)


def parse_whoisxml_history(doc: Any, privacy: Privacy) -> dict[str, Any] | None:
    """WhoisXML WHOIS History API v1 -> {records_count, preview, records} or None (not a history answer)."""
    if not isinstance(doc, Mapping) or ("recordsCount" not in doc and "records" not in doc):
        return None
    recs = doc.get("records")
    preview = not isinstance(recs, list)
    items = [_whoisxml_record(r, privacy) for r in recs if isinstance(r, Mapping)] if isinstance(recs, list) else []
    count = _int(doc.get("recordsCount"))
    return {"records_count": count if count is not None else len(items), "preview": preview, "records": [x for x in items if x]}


def parse_whoxy_history(doc: Any, privacy: Privacy) -> dict[str, Any] | None:
    """Whoxy ?history= answer (status 1) -> {records_count, preview, records} or None."""
    if not isinstance(doc, Mapping) or doc.get("status") not in (1, "1", True):
        return None
    recs = doc.get("whois_records")
    if recs is not None and not isinstance(recs, list):
        return None
    items = [_whoxy_like_record("whoxy", r, privacy) for r in recs or [] if isinstance(r, Mapping)]
    count = _int(doc.get("total_records_found"))
    return {"records_count": count if count is not None else len(items), "preview": False, "records": [x for x in items if x]}


def parse_whoisfreaks_history(doc: Any, privacy: Privacy) -> dict[str, Any] | None:
    """WhoisFreaks historical answer -> {records_count, preview, records} or None."""
    if not isinstance(doc, Mapping):
        return None
    recs = doc.get("whois_domains_historical")
    if not isinstance(recs, list):
        return None
    items = [_whoxy_like_record("whoisfreaks", r, privacy) for r in recs if isinstance(r, Mapping)]
    count = _int(doc.get("total_records"))
    return {"records_count": count if count is not None else len(items), "preview": False, "records": [x for x in items if x]}


def registrant_selectors(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Usable registrant values of one record, for analyst selection (P022 cond 3-5): privacy/proxy,
    placeholder and role values never appear."""
    reg = record.get("_registrant") if isinstance(record.get("_registrant"), Mapping) else {}
    out: list[dict[str, Any]] = []
    for fld in ("email", "organization", "name"):
        c = reg.get(fld) or {}
        if not c.get("usable") or not c.get("value"):
            continue
        out.append({"kind": SELECTOR_KIND[fld], "value": c["value"], "match_field": fld, "natural_person": bool(c.get("natural_person")),
                    "record_date": record.get("record_date"), "historical": bool(record.get("historical")), "provider": record.get("provider")})
    return out


def public_record(record: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in record.items() if not k.startswith("_")}


# ---- reverse WHOIS --------------------------------------------------------------------


def cr32_confidence(match_field: str, match_confirmed: bool | None = None) -> tuple[str, float]:
    """CR32 confidence by match field (P022 cond 6): e-mail > organisation > name; a record showing another
    value in that field lowers the link to POSSIBLE."""
    label, value = CR32_MATCH_CONFIDENCE.get(match_field, ("possible", 0.4))
    if match_confirmed is False:
        return "possible", min(value, 0.4)
    return label, value


def _same(a: str, b: str) -> bool:
    return " ".join(a.lower().split()) == " ".join(b.lower().split())


def _reverse_item(provider: str, r: Any, match_field: str, selector: str) -> dict[str, Any] | None:
    """One reverse-WHOIS domain, minimised: domain, registrar, dates, record date and the matched field."""
    if isinstance(r, str):
        dom = normalise_domain(r)
        return {"domain": dom, "created": None, "updated": None, "expires": None, "registrar": None, "record_date": None,
                "historical": False, "label": None, "match_confirmed": None} if dom else None
    if not isinstance(r, Mapping):
        return None
    if provider == "whoisxml":
        audit = r.get("audit") if isinstance(r.get("audit"), Mapping) else {}
        dom = normalise_domain(r.get("domainName"))
        rd = iso_day(audit.get("updatedDate"))
        return {"domain": dom, "created": None, "updated": None, "expires": None, "registrar": None, "record_date": rd,
                "historical": is_pre_gdpr(rd), "label": HISTORICAL_LABEL if is_pre_gdpr(rd) else None, "match_confirmed": None} if dom else None
    reg = r.get("domain_registrar") if isinstance(r.get("domain_registrar"), Mapping) else {}
    dom = normalise_domain(r.get("domain_name"))
    if dom is None:
        return None
    rd = iso_day(r.get("query_time"))
    contact = r.get("registrant_contact") if isinstance(r.get("registrant_contact"), Mapping) else _flat_contact(r)
    shown = _first(contact, _CONTACT_KEYS.get(provider, _CONTACT_KEYS["whoxy"])[match_field])
    return {"domain": dom, "created": iso_day(r.get("create_date")), "updated": iso_day(r.get("update_date")),
            "expires": iso_day(r.get("expiry_date")), "registrar": _registrar(reg.get("registrar_name"), reg.get("iana_id")),
            "record_date": rd, "historical": is_pre_gdpr(rd), "label": HISTORICAL_LABEL if is_pre_gdpr(rd) else None,
            "match_confirmed": None if not shown else _same(shown, selector)}


def _reverse_page(provider: str, items: Iterable[Any], match_field: str, selector: str) -> list[dict[str, Any]]:
    return [x for x in (_reverse_item(provider, r, match_field, selector) for r in items) if x]


# ======================================================================================
# Credit budget (P022 cond 1, P334 monthly window)
# ======================================================================================


class CreditBook:
    """Monthly credit budget per adapter in ``ctx.state`` (counts only, never values). Budget from setting
    ``whois_history_keyed_monthly_credits`` ({adapter: credits}); 0 disables the adapter, a missing entry means
    'provider quota block only'. Cache hits are free and never charged."""

    def __init__(self, ctx: Any, budgets: Mapping[str, Any]) -> None:
        self.ctx = ctx
        self.budgets = dict(budgets)
        self.month = ctx.now().strftime("%Y-%m")

    def _key(self, adapter: str) -> str:
        return f"credits:{adapter}:{self.month}"

    def budget(self, adapter: str) -> int | None:
        value = self.budgets.get(adapter)
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None

    def spent(self, adapter: str) -> int:
        try:
            value = self.ctx.state.get(self._key(adapter), 0)
        except Exception:  # noqa: BLE001 - unreadable state: count from zero (the provider quota block still applies)
            return 0
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0

    def remaining(self, adapter: str) -> int | None:
        budget = self.budget(adapter)
        return None if budget is None else max(0, budget - self.spent(adapter))

    def can_spend(self, adapter: str, credits: int) -> bool:
        left = self.remaining(adapter)
        return left is None or (left > 0 and left >= credits)

    def spend(self, adapter: str, credits: int) -> None:
        if credits <= 0:
            return
        try:
            state = self.ctx.state
            state.set(self._key(adapter), self.spent(adapter) + credits)
            for key in list(state.all()):  # keep the current month only
                if key.startswith(f"credits:{adapter}:") and key != self._key(adapter):
                    state.delete(key)
        except Exception:  # noqa: BLE001 - bookkeeping never fails a lookup that already answered
            self.ctx.log(f"{MODULE}: credit ledger not updated for {adapter}", "warning")


# ======================================================================================
# Adapters (P022 cond 1): one per provider
# ======================================================================================


class _Unusable(Exception):
    """An answer that is not the documented format: could not verify."""


class _NeedsKey(Exception):
    """A provider error body that means 'missing or invalid key' (P022 cond 7)."""


class _Absent(Exception):
    """A documented 'no record' answer."""


@dataclass
class Outcome:
    """What one adapter produced: OK/EMPTY with data, or a 'could not verify' status."""

    adapter: str
    source: str
    status: Status
    reason_code: str = ""
    reason: str = ""
    data: dict[str, Any] | None = None
    credits: int = 0
    stop: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def answered(self) -> bool:
        return self.status in (Status.OK, Status.EMPTY)


def _json(resp: Any, label: str) -> Any:
    if getattr(resp, "truncated", False):
        raise _Unusable(f"{label} answer truncated at the size cap: could not verify")
    try:
        return resp.json()
    except (ValueError, HttpError):
        raise _Unusable(f"{label} answer is not JSON (HTML or text): could not verify") from None


def _body_json(resp: Any) -> Any:
    try:
        return resp.json()
    except (ValueError, HttpError):
        return None


class _Adapter:
    name = ""
    source = ""
    key_name = ""
    label = ""

    def history(self, ctx: Any, domain: str, key: str, credits: CreditBook, privacy: Privacy, opts: Mapping[str, Any]) -> Outcome:
        raise NotImplementedError

    def reverse(self, ctx: Any, match_field: str, value: str, key: str, credits: CreditBook, opts: Mapping[str, Any]) -> Outcome:
        raise NotImplementedError

    # ---- shared helpers ------------------------------------------------------------------
    def outcome(self, status: Status, reason: str = "", *, reason_code: str = "", data: dict[str, Any] | None = None, credits: int = 0) -> Outcome:
        return Outcome(self.name, self.source, status, reason_code=reason_code, reason=reason, data=data, credits=credits)

    def cost(self, endpoint: str, mode: str = "") -> int:
        return CREDIT_COST.get((self.name, endpoint, mode), CREDIT_COST.get((self.name, endpoint, ""), 1))

    def send(self, ctx: Any, method: str, url: str, *, cache_if: Callable[[Any], bool], **kw: Any) -> Any:
        return ctx.http.request(method, url, source=self.source, ttl=CACHE_TTL, allow_redirects=False, cache_if=cache_if, **kw)

    def charge(self, credits: CreditBook, resp: Any, amount: int) -> int:
        """Charge a network answer (cache hits are free)."""
        if getattr(resp, "from_cache", False):
            return 0
        credits.spend(self.name, amount)
        return amount

    def guarded(self, fn: Callable[[], Outcome]) -> Outcome:
        """Run one adapter call; provider failures become this adapter's status (rule 5: could not verify)."""
        try:
            return fn()
        except STOP_EXCEPTIONS:
            raise
        except _NeedsKey as exc:
            return self.outcome(Status.NEEDS_KEY, f"{self.label}: {exc} (key {self.key_name})", reason_code="needs_key")
        except _Absent as exc:
            return self.outcome(Status.EMPTY, f"{self.label}: {exc}", data={})
        except _Unusable as exc:
            return self.outcome(Status.ERROR, str(exc)[:200], reason_code="error")
        except AuthRequired as exc:
            return self.outcome(Status.NEEDS_KEY, f"{self.label} refused the API key (HTTP {getattr(exc, 'status', '?')}; key {self.key_name})",
                                reason_code="needs_key")
        except QuotaExceeded as exc:
            return self.outcome(Status.QUOTA, f"{self.label}: {str(exc)[:160]}", reason_code="quota")
        except RateLimited as exc:
            return self.outcome(Status.RATE_LIMITED, f"{self.label}: {str(exc)[:160]}", reason_code="rate_limited")
        except Blocked as exc:
            code = getattr(exc, "reason_code", "") or "challenge"
            return self.outcome(Status.BLOCKED, f"{self.label}: {str(exc)[:160]}", reason_code=code if code in _BLOCKED_CODES else "challenge")
        except HttpError as exc:
            status = getattr(exc, "status", 0)
            code = "timeout" if status in (408, 499, 504) or getattr(exc, "reason_code", "") == "timeout" else "error"
            return self.outcome(Status.ERROR, f"{self.label}: {str(exc)[:160]} (could not verify)", reason_code=code)
        except NetworkError as exc:
            code = "timeout" if "timeout" in str(exc).lower() or "timed out" in str(exc).lower() else "error"
            return self.outcome(Status.ERROR, f"{self.label}: {str(exc)[:160]} (could not verify)", reason_code=code)


_BLOCKED_CODES = frozenset({"hostile_host", "circuit", "challenge", "geo_block", "login_wall"})
_WHOISXML_FIELDS = {"email": "RegistrantContact.Email", "organization": "RegistrantContact.Organization", "name": "RegistrantContact.Name"}
_WHOXY_FIELDS = {"email": "email", "organization": "company", "name": "name"}
_WHOISFREAKS_FIELDS = {"email": "email", "organization": "company", "name": "owner"}


def _whoisxml_ok(resp: Any) -> bool:
    doc = _body_json(resp)
    return isinstance(doc, Mapping) and ("recordsCount" in doc or "domainsCount" in doc) and "ErrorMessage" not in doc


class WhoisXmlAdapter(_Adapter):
    """WhoisXML API (trusted): WHOIS History API v1 and Reverse WHOIS API v2, one DRS credit pool. The key goes
    in the X-Authentication-Token header, never in the URL."""

    name = "whoisxml"
    source = SRC_WHOISXML
    key_name = "whoisxml"
    label = "WhoisXML API"

    def _post(self, ctx: Any, url: str, key: str, body: dict[str, Any]) -> Any:
        resp = self.send(ctx, "POST", url, json_body=body, headers={"X-Authentication-Token": key}, cache_if=_whoisxml_ok)
        ctx.http.check(resp)  # provider markers (credits 403 -> QUOTA), 401 -> AuthRequired, 429, non-2xx
        doc = _json(resp, self.label)
        if not isinstance(doc, Mapping):
            raise _Unusable(f"{self.label} answer is not a JSON object: could not verify")
        if isinstance(doc.get("ErrorMessage"), Mapping) or _int(doc.get("code")) and (_int(doc.get("code")) or 0) >= 400:
            msg = _text(str(doc.get("ErrorMessage") or doc.get("messages") or ""), 160)
            if "authenticat" in msg.lower() or "api key" in msg.lower():
                raise _NeedsKey(msg or "API key refused")
            raise _Unusable(f"{self.label} error in a 200 answer ({msg}): could not verify")
        return resp, doc

    def history(self, ctx: Any, domain: str, key: str, credits: CreditBook, privacy: Privacy, opts: Mapping[str, Any]) -> Outcome:
        def run() -> Outcome:
            spent = 0
            if not credits.can_spend(self.name, self.cost("history", "preview")):
                return self.outcome(Status.QUOTA, f"{self.label}: monthly credit budget exhausted (setting whois_history_keyed_monthly_credits)",
                                    reason_code="quota")
            resp, doc = self._post(ctx, WHOISXML_HISTORY_URL, key, {"domainName": domain, "mode": "preview", "outputFormat": "JSON"})
            spent += self.charge(credits, resp, self.cost("history", "preview"))
            preview = parse_whoisxml_history(doc, privacy)
            if preview is None:
                raise _Unusable(f"{self.label} history preview without recordsCount: could not verify")
            if not preview["records_count"]:
                return self.outcome(Status.EMPTY, f"{self.label}: no historical WHOIS records", data=preview, credits=spent)
            if opts.get("whoisxml_mode") != "purchase":
                out = self.outcome(Status.OK, "count only (preview mode)", data=preview, credits=spent)
                out.notes.append("WhoisXML history in preview mode (setting whois_history_keyed_whoisxml_mode): record count only")
                return out
            purchase = self.cost("history", "purchase")
            if not credits.can_spend(self.name, purchase):
                out = self.outcome(Status.OK, "count only: purchase skipped (monthly credit budget)", data=preview, credits=spent)
                out.stop = "quota"
                out.notes.append(f"WhoisXML history purchase ({purchase} credits) skipped: monthly credit budget too low")
                return out
            resp, doc = self._post(ctx, WHOISXML_HISTORY_URL, key, {"domainName": domain, "mode": "purchase", "outputFormat": "JSON"})
            spent += self.charge(credits, resp, purchase)
            parsed = parse_whoisxml_history(doc, privacy)
            if parsed is None or parsed["preview"]:
                raise _Unusable(f"{self.label} history purchase without records: could not verify")
            return self.outcome(Status.OK if parsed["records"] else Status.EMPTY, data=parsed, credits=spent)

        return self.guarded(run)

    def reverse(self, ctx: Any, match_field: str, value: str, key: str, credits: CreditBook, opts: Mapping[str, Any]) -> Outcome:
        def body(mode: str) -> dict[str, Any]:
            return {"searchType": "historic", "mode": mode, "punycode": True, "includeAuditDates": True,
                    "advancedSearchTerms": [{"field": _WHOISXML_FIELDS[match_field], "term": value, "exactMatch": True}]}

        def run() -> Outcome:
            resp, doc = self._post(ctx, WHOISXML_REVERSE_URL, key, body("preview"))  # free (0 credits)
            total = _int(doc.get("domainsCount"))
            if total is None:
                raise _Unusable(f"{self.label} reverse preview without domainsCount: could not verify")
            data: dict[str, Any] = {"total": total, "domains": [], "pages": 0}
            if total == 0:
                return self.outcome(Status.EMPTY, f"{self.label}: no domain with this {FIELD_LABELS[match_field]}", data=data)
            if total > REVERSE_GENERIC_THRESHOLD:
                data["too_broad"] = True
                return self.outcome(Status.OK, "selector too broad: not purchased", data=data)
            cost = self.cost("reverse", "purchase")
            if not credits.can_spend(self.name, cost):
                out = self.outcome(Status.OK, "count only: purchase skipped (monthly credit budget)", data=data)
                out.stop = "quota"
                return out
            resp, doc = self._post(ctx, WHOISXML_REVERSE_URL, key, body("purchase"))
            spent = self.charge(credits, resp, cost)
            lst = doc.get("domainsList")
            if not isinstance(lst, list):
                raise _Unusable(f"{self.label} reverse purchase without domainsList: could not verify")
            data.update(domains=_reverse_page(self.name, lst, match_field, value), pages=1,
                        total=_int(doc.get("domainsCount")) or total)
            return self.outcome(Status.OK if data["domains"] else Status.EMPTY, data=data, credits=spent)

        return self.guarded(run)


def _whoxy_ok(resp: Any) -> bool:
    doc = _body_json(resp)
    return isinstance(doc, Mapping) and doc.get("status") in (1, "1", True)


_WHOXY_NOT_FOUND = re.compile(r"(?i)not found|no record|no whois|no result|no domain")


def _whoxy_doc(ctx: Any, resp: Any, label: str) -> Mapping[str, Any]:
    if resp.classification is None and resp.status == 200:
        doc = _body_json(resp)
        if isinstance(doc, Mapping) and doc.get("status") not in (1, "1", True):
            reason = _text(doc.get("status_reason"), 160)
            low = reason.lower()
            if "api key" in low or "apikey" in low or ("key" in low and ("invalid" in low or "missing" in low)):
                raise _NeedsKey(reason)  # verified: {"status":0,"status_reason":"Invalid API Key"} (HTTP 200)
    ctx.http.check(resp)  # balance/rate markers in the 200 body, 429, non-2xx
    doc = _json(resp, label)
    if not isinstance(doc, Mapping):
        raise _Unusable(f"{label} answer is not a JSON object: could not verify")
    if doc.get("status") in (1, "1", True):
        return doc
    reason = _text(doc.get("status_reason"), 160)
    if doc.get("status") is None:
        raise _Unusable(f"{label} answer without a status field: could not verify")
    if _WHOXY_NOT_FOUND.search(reason):
        raise _Absent(reason or "no record")
    raise _Unusable(f"{label} error ({reason or 'status 0'}): could not verify")


class WhoxyAdapter(_Adapter):
    """Whoxy (community): ?history= and ?reverse=whois. The key travels as ?key= through ``params`` only, so the
    central redactor masks it in every log, event, error and cache row (AR01)."""

    name = "whoxy"
    source = SRC_WHOXY
    key_name = "whoxy"
    label = "Whoxy API"

    def _get(self, ctx: Any, key: str, params: dict[str, str]) -> tuple[Any, Mapping[str, Any]]:
        resp = self.send(ctx, "GET", WHOXY_URL, params={"key": key, **params}, cache_if=_whoxy_ok)
        return resp, _whoxy_doc(ctx, resp, self.label)

    def history(self, ctx: Any, domain: str, key: str, credits: CreditBook, privacy: Privacy, opts: Mapping[str, Any]) -> Outcome:
        def run() -> Outcome:
            cost = self.cost("history")
            if not credits.can_spend(self.name, cost):
                return self.outcome(Status.QUOTA, f"{self.label}: monthly credit budget exhausted (setting whois_history_keyed_monthly_credits)",
                                    reason_code="quota")
            resp, doc = self._get(ctx, key, {"history": domain})
            spent = self.charge(credits, resp, cost)
            parsed = parse_whoxy_history(doc, privacy)
            if parsed is None:
                raise _Unusable(f"{self.label} history answer without whois_records: could not verify")
            return self.outcome(Status.OK if parsed["records"] else Status.EMPTY, data=parsed, credits=spent)

        return self.guarded(run)

    def reverse(self, ctx: Any, match_field: str, value: str, key: str, credits: CreditBook, opts: Mapping[str, Any]) -> Outcome:
        def run() -> Outcome:
            data: dict[str, Any] = {"total": None, "domains": [], "pages": 0}
            spent = 0
            page, pages = 1, 1
            max_pages = int(opts.get("reverse_pages") or 1)
            while page <= min(pages, max_pages):
                cost = self.cost("reverse")
                if not credits.can_spend(self.name, cost):
                    if page == 1:
                        return self.outcome(Status.QUOTA, f"{self.label}: monthly credit budget exhausted", reason_code="quota")
                    out = self.outcome(Status.OK, "more pages skipped (monthly credit budget)", data=data, credits=spent)
                    out.stop = "quota"
                    return out
                try:
                    resp, doc = self._get(ctx, key, {"reverse": "whois", _WHOXY_FIELDS[match_field]: value, "page": str(page)})
                except _Absent:
                    if page == 1:
                        raise
                    break
                spent += self.charge(credits, resp, cost)
                lst = doc.get("search_result") if isinstance(doc.get("search_result"), list) else doc.get("search_results")
                if not isinstance(lst, list):
                    raise _Unusable(f"{self.label} reverse answer without search_result: could not verify")
                data["domains"].extend(_reverse_page(self.name, lst, match_field, value))
                data["pages"] = page
                total = _int(doc.get("total_results"))
                data["total"] = total if total is not None else len(data["domains"])
                pages = _int(doc.get("total_pages")) or 1
                if (data["total"] or 0) > REVERSE_GENERIC_THRESHOLD:
                    data["too_broad"] = True
                    break
                page += 1
            return self.outcome(Status.OK if data["domains"] or data.get("too_broad") else Status.EMPTY, data=data, credits=spent)

        return self.guarded(run)


def _whoisfreaks_ok(resp: Any) -> bool:
    doc = _body_json(resp)
    return isinstance(doc, Mapping) and (isinstance(doc.get("whois_domains_historical"), list) or isinstance(doc.get("whois_domains"), list))


def _whoisfreaks_doc(ctx: Any, resp: Any, label: str) -> Mapping[str, Any]:
    if resp.classification is None:
        doc = _body_json(resp)
        message = _text(doc.get("message"), 160) if isinstance(doc, Mapping) else ""
        if resp.status == 400 and re.search(r"(?i)api ?key", message):
            raise _NeedsKey(message)  # verified keyless answer: 400 'Please provide apikey'
        if resp.status == 404:
            raise _Absent(message or "No Record Found")  # documented: 404 'No Record Found'
    ctx.http.check(resp)  # credits/suspicious/TLD markers, 401 -> AuthRequired, 429, 408/5xx
    doc = _json(resp, label)
    if not isinstance(doc, Mapping):
        raise _Unusable(f"{label} answer is not a JSON object: could not verify")
    status = _int(doc.get("status")) if not isinstance(doc.get("status"), bool) else None
    if status is not None and status >= 400:
        raise _Unusable(f"{label} error in a 2xx answer ({_text(doc.get('message'), 120)}): could not verify")
    return doc


class WhoisFreaksAdapter(_Adapter):
    """WhoisFreaks (community): v1.0 historical and reverse WHOIS. The key travels as ?apiKey= through
    ``params`` only (central redactor, AR01)."""

    name = "whoisfreaks"
    source = SRC_WHOISFREAKS
    key_name = "whoisfreaks"
    label = "WhoisFreaks"

    def _get(self, ctx: Any, key: str, params: dict[str, str]) -> tuple[Any, Mapping[str, Any]]:
        resp = self.send(ctx, "GET", WHOISFREAKS_URL, params={**params, "apiKey": key}, cache_if=_whoisfreaks_ok)
        return resp, _whoisfreaks_doc(ctx, resp, self.label)

    def history(self, ctx: Any, domain: str, key: str, credits: CreditBook, privacy: Privacy, opts: Mapping[str, Any]) -> Outcome:
        def run() -> Outcome:
            cost = self.cost("history")
            if not credits.can_spend(self.name, cost):
                return self.outcome(Status.QUOTA, f"{self.label}: monthly credit budget exhausted (setting whois_history_keyed_monthly_credits)",
                                    reason_code="quota")
            resp, doc = self._get(ctx, key, {"whois": "historical", "domainName": domain})
            spent = self.charge(credits, resp, cost)
            parsed = parse_whoisfreaks_history(doc, privacy)
            if parsed is None:
                raise _Unusable(f"{self.label} history answer without whois_domains_historical: could not verify")
            return self.outcome(Status.OK if parsed["records"] else Status.EMPTY, data=parsed, credits=spent)

        return self.guarded(run)

    def reverse(self, ctx: Any, match_field: str, value: str, key: str, credits: CreditBook, opts: Mapping[str, Any]) -> Outcome:
        def run() -> Outcome:
            data: dict[str, Any] = {"total": None, "domains": [], "pages": 0}
            spent = 0
            page, pages = 1, 1
            max_pages = int(opts.get("reverse_pages") or 1)
            while page <= min(pages, max_pages):
                cost = self.cost("reverse")
                if not credits.can_spend(self.name, cost):
                    if page == 1:
                        return self.outcome(Status.QUOTA, f"{self.label}: monthly credit budget exhausted", reason_code="quota")
                    out = self.outcome(Status.OK, "more pages skipped (monthly credit budget)", data=data, credits=spent)
                    out.stop = "quota"
                    return out
                params = {"whois": "reverse", _WHOISFREAKS_FIELDS[match_field]: value, "exact": "true", "mode": "mini", "page": str(page)}
                try:
                    resp, doc = self._get(ctx, key, params)
                except _Absent:
                    if page == 1:
                        raise
                    break
                spent += self.charge(credits, resp, cost)
                lst = doc.get("whois_domains_historical") if isinstance(doc.get("whois_domains_historical"), list) else doc.get("whois_domains")
                if not isinstance(lst, list):
                    raise _Unusable(f"{self.label} reverse answer without a domain list: could not verify")
                data["domains"].extend(_reverse_page(self.name, lst, match_field, value))
                data["pages"] = page
                total = _int(doc.get("total_Result"))
                data["total"] = total if total is not None else len(data["domains"])
                pages = _int(doc.get("total_Pages")) or 1
                if (data["total"] or 0) > REVERSE_GENERIC_THRESHOLD:
                    data["too_broad"] = True
                    break
                page += 1
            return self.outcome(Status.OK if data["domains"] or data.get("too_broad") else Status.EMPTY, data=data, credits=spent)

        return self.guarded(run)


ADAPTERS: dict[str, _Adapter] = {a.name: a for a in (WhoisXmlAdapter(), WhoxyAdapter(), WhoisFreaksAdapter())}


# ======================================================================================
# P022 cond 3: is the registrant value already in a WHOIS/RDAP record of the case?
# ======================================================================================


def _case_graph(ctx: Any) -> Any:
    runtime = getattr(ctx, "runtime", None)
    pctx = getattr(runtime, "policy_context", None)
    return getattr(pctx, "graph", None)


def _snapshot(items: Any) -> list[Any]:
    for _ in range(3):  # the engine thread may grow the live graph while this worker reads it
        try:
            return list(items or ())
        except RuntimeError:
            continue
    return []


def _attr_matches(value: Any, wanted: str, kind: str) -> bool:
    if isinstance(value, str):
        return _same(value, wanted)
    if isinstance(value, Mapping):
        v = value.get("value")
        k = value.get("kind")
        return isinstance(v, str) and _same(v, wanted) and (k is None or k == kind)
    if isinstance(value, list):
        return any(_attr_matches(v, wanted, kind) for v in value[:200])
    return False


def registration_provenance(ctx: Any, entity: Entity) -> str | None:
    """How the value reached the case from a WHOIS/RDAP record, or None (P022 cond 3).

    Reads the live case graph of the running investigation: an in-edge ``registrant`` / ``registrant_email``
    emitted by a registration module, or a ``registrant_selectors`` / ``registrant_email`` / ``registrant``
    attribute of a node, recorded by a registration module, holding the same value. Outside a scan (no case
    graph) there is no case, so the answer is None."""
    graph = _case_graph(ctx)
    if graph is None:
        return None
    key = entity.key
    for edge in _snapshot(getattr(graph, "edges", None)):
        if getattr(edge, "dst", None) == key and getattr(edge, "relation", "") in REGISTRANT_RELATIONS and getattr(edge, "module", "") in REGISTRATION_MODULES:
            return f"{edge.relation} of {edge.src} ({edge.module})"
    kind = entity.type.value
    nodes = getattr(graph, "nodes", None)
    for node in _snapshot(nodes.values() if isinstance(nodes, Mapping) else ()):
        attrs = getattr(node, "attributes", None)
        if not isinstance(attrs, Mapping):
            continue
        for name in REGISTRANT_ATTRIBUTES:
            for pair in _snapshot(attrs.get(name)):
                if not (isinstance(pair, tuple) and len(pair) == 2) or pair[1] not in REGISTRATION_MODULES:
                    continue
                if _attr_matches(pair[0], str(entity.value), kind):
                    return f"{name} of {getattr(node, 'key', '?')} ({pair[1]})"
    return None


# ======================================================================================
# Module
# ======================================================================================


@register
class WhoisHistoryKeyed(Module):
    name = MODULE
    title = "WHOIS history and reverse WHOIS (WhoisXML, Whoxy, WhoisFreaks)"
    description = (
        "Paid WHOIS-history APIs: historical registration records of a seed domain (registrar, dates, nameservers, "
        "usable registrant values) and reverse WHOIS by a registrant e-mail, organisation or name already found in "
        "a WHOIS/RDAP record of the case. Results are candidates, never scope."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN, T.EMAIL, T.ORG, T.PERSON}
    produces = {T.DOMAIN, T.EMAIL, T.ORG}
    run_on = "seeds"
    reference = "https://whois-history.whoisxmlapi.com/api/documentation/making-requests"
    notice = (
        "Paid WHOIS-history / reverse-WHOIS APIs (terms 'license'): company-paid keys only, each recorded with its "
        "licence/purchase in licence_allow before it runs under the corporate profile. Off by default and analyst-typed "
        "seeds only. Reverse WHOIS by e-mail or person name runs only for a registrant value already found in a "
        "WHOIS/RDAP record of this case, selected by the analyst, in a case with a recorded purpose (no people search). "
        "Privacy/proxy values are never selectors. Results are candidates, never scope. The Whoxy adapter stays off "
        "until its public recent-lookups list is ruled out (rule 7)."
    )
    terms = "license"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "whoisxmlapi"
    sources = (SRC_WHOISXML, SRC_WHOXY, SRC_WHOISFREAKS)
    hosts = ("whois-history.whoisxmlapi.com", "reverse-whois.whoisxmlapi.com", "api.whoxy.com", "api.whoisfreaks.com")
    access_model = "commercial_only"
    optional_keys = ("whoisxml", "whoxy", "whoisfreaks")
    max_requests = 6  # history: preview + purchase (+1 per fallback adapter); reverse: preview + pages
    expected_latency = 2.0
    timeout = 60.0
    min_interval = 1.0
    daily_quota = 20
    cache_ttl = CACHE_TTL
    max_pivots = MAX_REVERSE_PIVOTS
    default_enabled = False
    settings = {
        "whois_history_keyed_providers": SettingSpec(
            list(DEFAULT_PROVIDERS),
            "whois_history_keyed: adapters in query order (whoisxml, whoxy, whoisfreaks); whoxy is off until the rule-7 "
            "check of its public recent-lookups list is recorded",
            ("whoisxml", "whoxy", "whoisfreaks"),
        ),
        "whois_history_keyed_all_providers": SettingSpec(False, "whois_history_keyed: query every configured adapter instead of stopping at the first that answers"),
        "whois_history_keyed_monthly_credits": SettingSpec(
            dict(DEFAULT_MONTHLY_CREDITS),
            "whois_history_keyed: monthly credit budget per adapter (set it to 80% of the purchased plan; 0 disables the adapter)",
        ),
        "whois_history_keyed_whoisxml_mode": SettingSpec(
            "purchase", "whois_history_keyed: WhoisXML history mode (preview = record count only, 1 credit; purchase = all records, 50 credits)",
            ("preview", "purchase"),
        ),
        "whois_history_keyed_reverse_pages": SettingSpec(2, "whois_history_keyed: reverse-WHOIS pages per adapter (1-3)"),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.DOMAIN:
            return psl.registrable_domain(str(entity.value)) is not None
        return True

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        privacy = load_privacy(ctx)
        opts = self._options(ctx)
        if entity.type is not T.DOMAIN:
            field_name = {T.EMAIL: "email", T.ORG: "organization", T.PERSON: "name"}[entity.type]
            refusal = self._reverse_refusal(entity, ctx, field_name, privacy)
            if refusal:
                return res.mark("skipped", refusal, reason_code="privacy")
        adapters, why = self._usable_adapters(ctx, res, opts)
        if not adapters:
            status, code, reason = why
            return res.mark(status, reason, reason_code=code)
        credits = CreditBook(ctx, opts["monthly_credits"])
        if entity.type is T.DOMAIN:
            return self._history(entity, ctx, res, adapters, credits, privacy, opts)
        return self._reverse(entity, ctx, res, adapters, credits, field_name, opts)

    @staticmethod
    def _options(ctx: Any) -> dict[str, Any]:
        order = ctx.setting("whois_history_keyed_providers", DEFAULT_PROVIDERS)
        order = [str(x).strip().lower() for x in (order if isinstance(order, list) else []) if str(x).strip().lower() in ADAPTERS]
        budgets = ctx.setting("whois_history_keyed_monthly_credits", DEFAULT_MONTHLY_CREDITS)
        budgets = {str(k): v for k, v in budgets.items()} if isinstance(budgets, Mapping) else dict(DEFAULT_MONTHLY_CREDITS)
        try:
            pages = int(ctx.setting("whois_history_keyed_reverse_pages", 2))
        except (TypeError, ValueError):
            pages = 2
        return {
            "order": list(dict.fromkeys(order)),
            "all": bool(ctx.setting("whois_history_keyed_all_providers", False) is True),
            "monthly_credits": budgets,
            "whoisxml_mode": "preview" if ctx.setting("whois_history_keyed_whoisxml_mode", "purchase") == "preview" else "purchase",
            "reverse_pages": max(1, min(MAX_REVERSE_PAGES, pages)),
        }

    def _usable_adapters(self, ctx: Any, res: ModuleResult, opts: Mapping[str, Any]) -> tuple[list[tuple[_Adapter, str]], tuple[str, str, str]]:
        """Adapters with a configured key, an allowed (licence-cleared) source, enabled by setting and with a
        credit budget left; the reason when there is none."""
        allowed = set(ctx.allowed_sources)
        keyed = [a for a in ADAPTERS.values() if ctx.key(a.key_name)]
        if not keyed:
            return [], ("needs_key", "needs_key", "needs a company-paid WHOIS-history key: whoisxml, whoxy or whoisfreaks (v3lum keys setup)")
        usable: list[tuple[_Adapter, str]] = []
        disabled: list[str] = []
        exhausted: list[str] = []
        budgets = CreditBook(ctx, opts["monthly_credits"])
        for adapter in keyed:
            if adapter.source not in allowed:
                continue  # the policy gate reports licence-blocked sources itself (coverage 'licence')
            if adapter.name not in opts["order"]:
                disabled.append(adapter.name)
                reason = "adapter off (setting whois_history_keyed_providers)"
                if adapter.name == "whoxy":
                    reason += ": rule-7 check of the public recent-lookups list pending"
                res.source_status(adapter.source, Status.SKIPPED, reason_code="config", reason=reason)
                continue
            if budgets.remaining(adapter.name) == 0:
                exhausted.append(adapter.name)
                res.source_status(adapter.source, Status.QUOTA, reason_code="quota",
                                  reason=f"{adapter.label}: monthly credit budget exhausted (setting whois_history_keyed_monthly_credits)")
                continue
            usable.append((adapter, ctx.key(adapter.key_name)))
        usable.sort(key=lambda pair: opts["order"].index(pair[0].name))
        if usable:
            return usable, ("", "", "")
        if exhausted:
            return [], ("quota", "quota", "monthly credit budget exhausted for " + ", ".join(exhausted) + ": could not verify")
        if disabled:
            return [], ("skipped", "config", "the configured adapters are off (setting whois_history_keyed_providers): " + ", ".join(disabled))
        return [], ("skipped", "licence", "no WHOIS-history source with a configured key is licence-cleared (licence_allow entry needed)")

    def _reverse_refusal(self, entity: Entity, ctx: Any, field_name: str, privacy: Privacy) -> str:
        """'' when the reverse lookup may be sent, else the refusal (P022 cond 3-4, rule 4)."""
        value = str(entity.value)
        marker = privacy.marker(value, field_name)
        if marker:
            return f"{FIELD_LABELS[field_name]} is a privacy/proxy, placeholder or role value ({marker}): never a reverse-WHOIS selector (P022 cond 4)"
        if field_name == "organization":
            return ""
        if not ctx.is_seed or ctx.depth != 0 or entity.key in (getattr(ctx.options, "unconfirmed_seeds", None) or set()):
            return "reverse WHOIS by e-mail or person name needs an analyst-selected, confirmed seed (P022 cond 3)"
        if not str(ctx.purpose or "").strip():
            return "reverse WHOIS by e-mail or person name needs a case with a recorded purpose (--purpose: fraud / actor infrastructure; P022 cond 3)"
        if registration_provenance(ctx, entity) is None:
            return ("reverse WHOIS by e-mail or person name only for a registrant value already found in a WHOIS/RDAP record of this case "
                    "(run whois_history_keyed or rdap on the domain in the same case first): no free-text person search (P022 cond 3, rule 4)")
        return ""

    # ------------------------------------------------------------------ adapters
    @staticmethod
    def _collect(res: ModuleResult, outcomes: list[Outcome]) -> None:
        for out in outcomes:
            if out.answered:
                res.source_status(out.source, out.status, reason=out.reason[:200])
            else:
                res.source_status(out.source, out.status, reason_code=out.reason_code, reason=out.reason[:200])

    @staticmethod
    def _failed(res: ModuleResult, outcomes: list[Outcome], what: str) -> ModuleResult:
        worst = max(outcomes, key=lambda o: _FAILURE_RANK.get(o.status, 0))
        detail = "; ".join((o.reason or f"{ADAPTERS[o.adapter].label}: {o.status.value}")[:160] for o in outcomes)
        return res.mark(worst.status, f"no WHOIS-history provider answered the {what} ({detail}): could not verify", reason_code=worst.reason_code)

    def _run_adapters(self, ctx: Any, adapters: list[tuple[_Adapter, str]], opts: Mapping[str, Any], call: Callable[[_Adapter, str], Outcome]) -> list[Outcome]:
        outcomes: list[Outcome] = []
        for adapter, key in adapters:
            if ctx.cancelled():
                break
            out = call(adapter, key)
            outcomes.append(out)
            if out.answered and not opts["all"]:
                break  # stop at the first provider that answered (credits); --all via setting
        return outcomes

    # ------------------------------------------------------------------ history (domain)
    def _history(self, entity: Entity, ctx: Any, res: ModuleResult, adapters: list[tuple[_Adapter, str]], credits: CreditBook,
                 privacy: Privacy, opts: Mapping[str, Any]) -> ModuleResult:
        domain = psl.registrable_domain(str(entity.value)) or str(entity.value)
        outcomes = self._run_adapters(ctx, adapters, opts, lambda a, k: a.history(ctx, domain, k, credits, privacy, opts))
        self._collect(res, outcomes)
        answered = [o for o in outcomes if o.answered]
        res.raw = {"mode": "history", "queried": domain, "adapters": [self._raw_outcome(o) for o in outcomes]}
        if not answered:
            return self._failed(res, outcomes, "WHOIS-history lookup")
        records: list[dict[str, Any]] = []
        count = 0
        preview = False
        for out in answered:
            data = out.data or {}
            records.extend(data.get("records") or [])
            count += data.get("records_count") or 0
            preview = preview or bool(data.get("preview"))
        records.sort(key=lambda r: r.get("record_date") or "", reverse=True)
        records = records[:MAX_HISTORY_RECORDS]
        notes = [n for o in answered for n in o.notes]
        if domain != entity.value:
            notes.append(f"queried the registrable domain {domain}")
        stop = next((o.stop for o in answered if o.stop), "")
        if not records and not count:
            res.raw["notes"] = notes
            return res.mark("empty", f"no historical WHOIS records of {domain} ({', '.join(ADAPTERS[o.adapter].label for o in answered)})")
        self._report_history(entity, res, domain, records, count, preview, answered, notes, privacy)
        if stop:
            res.stop(stop)
        return res

    @staticmethod
    def _raw_outcome(out: Outcome) -> dict[str, Any]:
        return {"adapter": out.adapter, "status": out.status.value, "reason": out.reason[:200], "credits": out.credits}

    def _report_history(self, entity: Entity, res: ModuleResult, domain: str, records: list[dict[str, Any]], count: int, preview: bool,
                        answered: list[Outcome], notes: list[str], privacy: Privacy) -> None:
        selectors: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for rec in records:
            for sel in registrant_selectors(rec):
                k = (sel["kind"], sel["value"].lower())
                if k not in seen and len(selectors) < MAX_SELECTORS:
                    seen.add(k)
                    selectors.append(sel)
        public = [public_record(r) for r in records]
        dates = sorted(r["record_date"] for r in public if r.get("record_date"))
        registrars = list(dict.fromkeys(r["registrar"]["name"] for r in public if r.get("registrar") and r["registrar"].get("name")))
        orgs = list(dict.fromkeys(r["registrant_organization"] for r in public if r.get("registrant_organization")))
        providers = list(dict.fromkeys(ADAPTERS[o.adapter].label for o in answered))
        summary = {
            "providers": providers,
            "records_count": count,
            "records_kept": len(public),
            "historical_count": sum(1 for r in public if r["historical"]),
            "preview": preview,
            "earliest_record": dates[0] if dates else None,
            "latest_record": dates[-1] if dates else None,
            "registrars": registrars[:10],
            "registrant_organizations": orgs[:10],
            "privacy_proxy_records": sum(1 for r in public if r["privacy_proxy"]),
        }
        res.attr("whois_history", public)
        res.attr("whois_history_summary", summary)
        res.attr("registrant_selectors", selectors)
        natural = any(s["natural_person"] for s in selectors)
        for sel in selectors:
            when = f"WHOIS record dated {sel['record_date'] or '?'}" + (f" ({HISTORICAL_LABEL})" if sel["historical"] else "")
            if sel["kind"] == "email":
                privacy_note = "personal e-mail (privacy)" if sel["natural_person"] else "role mailbox"
                res.pivot(T.EMAIL, sel["value"], "registrant_email", confidence="probable", expand=False,
                          note=f"registrant e-mail in a {when}; {privacy_note}: reverse-WHOIS candidate, analyst selection and purpose required")
            elif sel["kind"] == "company_name" and not sel["natural_person"]:
                res.pivot(T.ORG, sel["value"], "registrant", confidence="probable", expand=False,
                          note=f"registrant organisation in a {when}: candidate, never scope")
        source = answered[0].source
        period = f" between {summary['earliest_record']} and {summary['latest_record']}" if dates else ""
        parts = [f"{len(public) or count} historical WHOIS record(s) of {domain} from {', '.join(providers)}{period}"]
        if preview:
            parts.append(f"record count only ({count}): the records were not purchased")
        if summary["historical_count"]:
            parts.append(f"{summary['historical_count']} last seen before 2018-05-25 ({HISTORICAL_LABEL})")
        if registrars:
            parts.append("registrars: " + ", ".join(registrars[:5]))
        if summary["privacy_proxy_records"]:
            parts.append(f"{summary['privacy_proxy_records']} record(s) with privacy/proxy registrant data (redacted (privacy))")
        if selectors:
            parts.append(f"{len(selectors)} registrant value(s) usable as reverse-WHOIS seeds (analyst selection, a case purpose and this case required)")
        parts.extend(notes)
        tags = ["historical"] + (["privacy"] if natural else [])
        res.finding(
            "WHOIS history: past registration records",
            "info",
            "; ".join(parts) + ". Historical records describe past registrations, not the current one.",
            confidence="probable",
            criterion="records returned by a paid WHOIS-history API, each dated by the provider's record date (P022 cond 6)",
            data=summary,
            tags=tags,
            source=source,
            observed_first=dates[0] if dates else None,
            observed_last=dates[-1] if dates else None,
        )

    # ------------------------------------------------------------------ reverse (e-mail / organisation / name)
    def _reverse(self, entity: Entity, ctx: Any, res: ModuleResult, adapters: list[tuple[_Adapter, str]], credits: CreditBook,
                 field_name: str, opts: Mapping[str, Any]) -> ModuleResult:
        value = str(entity.value).strip()
        if field_name == "email":
            value = value.lower()
        outcomes = self._run_adapters(ctx, adapters, opts, lambda a, k: a.reverse(ctx, field_name, value, k, credits, opts))
        self._collect(res, outcomes)
        answered = [o for o in outcomes if o.answered]
        res.raw = {"mode": "reverse", "match_field": field_name, "adapters": [self._raw_outcome(o) for o in outcomes]}
        if not answered:
            return self._failed(res, outcomes, "reverse-WHOIS lookup")
        domains: dict[str, dict[str, Any]] = {}
        total = 0
        too_broad = False
        for out in answered:
            data = out.data or {}
            too_broad = too_broad or bool(data.get("too_broad"))
            total = max(total, data.get("total") or 0)
            for item in data.get("domains") or []:
                prev = domains.get(item["domain"])
                if prev is None or (item.get("match_confirmed") is True and prev.get("match_confirmed") is not True):
                    domains[item["domain"]] = item
        items = sorted(domains.values(), key=lambda d: d.get("record_date") or "", reverse=True)[:MAX_REVERSE_KEEP]
        stop = next((o.stop for o in answered if o.stop), "")
        if not items and not too_broad:
            return res.mark("empty", f"no domain shows this {FIELD_LABELS[field_name]} ({', '.join(ADAPTERS[o.adapter].label for o in answered)})")
        self._report_reverse(entity, res, field_name, items, max(total, len(items)), too_broad, answered)
        if stop:
            res.stop(stop)
        return res

    def _report_reverse(self, entity: Entity, res: ModuleResult, field_name: str, items: list[dict[str, Any]], total: int, too_broad: bool,
                        answered: list[Outcome]) -> None:
        providers = list(dict.fromkeys(ADAPTERS[o.adapter].label for o in answered))
        source = answered[0].source
        label = FIELD_LABELS[field_name]
        historical = sum(1 for d in items if d.get("historical"))
        natural = field_name == "name" or (field_name == "email" and not is_role_mailbox(str(entity.value)))
        attribute = {
            "providers": providers,
            "match_field": field_name,
            "total": total,
            "kept": len(items),
            "truncated": total > len(items),
            "too_broad": too_broad,
            "historical_count": historical,
            "domains": items,
        }
        res.attr("reverse_whois", attribute)
        if too_broad:
            res.finding(
                "Reverse WHOIS selector too broad",
                "info",
                f"{total} domains show this {label} per {', '.join(providers)}: a reseller, registrar, privacy or shared corporate "
                "value. No pivots and no shared-registrant cluster (P022 cond 4, CR32).",
                confidence="possible",
                criterion=f"more than {REVERSE_GENERIC_THRESHOLD} domains share the selector",
                data={"total": total, "match_field": field_name, "providers": providers},
                tags=["weak_signal"] + (["privacy"] if natural else []),
                source=source,
            )
            return
        pivoted = 0
        for item in items:
            if pivoted >= MAX_REVERSE_PIVOTS:
                break
            conf_label, conf = cr32_confidence(field_name, item.get("match_confirmed"))
            when = f"WHOIS record dated {item.get('record_date') or '?'}" + (f" ({HISTORICAL_LABEL})" if item.get("historical") else "")
            if res.pivot(T.DOMAIN, item["domain"], "shared_registrant", confidence=conf, expand=False,
                         note=f"reverse WHOIS candidate: same {label} in a {when}; never scope"):
                pivoted += 1
        conf_label, conf = cr32_confidence(field_name)
        names = sorted({d["domain"] for d in items})
        cluster = None
        if len(names) >= 2:
            cluster = {
                "rule": "CR32",
                "title": "shared_registrant_cluster",
                "match_field": field_name,
                "domains": names[:50],
                "confidence": conf,
                "confidence_label": conf_label,
                "candidates_only": True,
                "expand": False,
                "natural_person": natural,
            }
        parts = [f"{len(items)} domain(s) show this {label} per {', '.join(providers)} (reverse WHOIS, {total} reported)"]
        if historical:
            parts.append(f"{historical} from records last seen before 2018-05-25 ({HISTORICAL_LABEL})")
        unconfirmed = sum(1 for d in items if d.get("match_confirmed") is False)
        if unconfirmed:
            parts.append(f"{unconfirmed} record(s) show another value in that field (POSSIBLE)")
        parts.append("candidates sharing the registrant, never scope: confirm before acting")
        res.finding(
            f"Domains sharing the {label}",
            "info",
            "; ".join(parts) + ".",
            confidence=conf_label,
            criterion=f"reverse WHOIS by {label} ({', '.join(providers)}); CR32 confidence follows the match field: e-mail > organisation > name (P022 cond 6)",
            data={"total": total, "kept": len(items), "match_field": field_name, "cr32_candidate": cluster},
            tags=(["privacy"] if natural else []) + (["historical"] if historical else []),
            source=source,
            key=field_name,
            observed_last=max((d["record_date"] for d in items if d.get("record_date")), default=None),
        )
