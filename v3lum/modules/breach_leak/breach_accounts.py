"""Shared per-account breach helpers of batch p2-G04-1 (P133 hibp_account, P135 leakcheck_public,
P137 xposedornot). No module lives here: the helpers are pure (no network) and are imported by the
three per-account breach modules so that one breach is described, scoped and scored the same way
whichever source reported it.

* **Scope (A4 BR9-BR10, P133 cond 3, P135 cond 8, P137 cond 3)**: :func:`breach_scope` is the
  in-module defence in depth next to the policy gate (``run_on='own_assets'``): an address on a
  verified (txt_verified/attested) org-profile domain is an own asset; anything else runs only as an
  analyst-typed seed with ``--breach-scope all`` and a recorded ``--purpose`` and is context only
  (severity at most MEDIUM, tags ``context_only`` + ``third_party``, no exposure score). Otherwise
  the run ends SKIPPED ``privacy`` ('breach check skipped: not an org domain').
* **Generic addresses (A4 BR6)**: role/test/example addresses (:func:`generic_kind`) and LeakCheck
  ``found >= 100`` are flagged, capped at POSSIBLE and never scored (INFO + ``context_only``).
* **One breach, one key (P133 cond 7, P135 cond 7, P137 cond 7)**: :func:`breach_key` normalises a
  name (accents and case folded, domain suffix stripped, a year qualifier kept: 'Zacks.com (2024)'
  -> 'zacks2024'); :func:`resolve` maps any source's name onto the shared HIBP catalogue entry of the
  P132 helper (``hibp_catalog.breach_catalog``: exact name, then the stripped key, then domain + year
  within one year), so HIBP, XposedOrNot and LeakCheck listings of the same breach carry the same
  ``breach_key`` in their finding data. The correlation rule ``p2g04_breach_merge``
  (``v3lum/correlations/p2_g04_1.py``) then keeps ONE finding per breach listing every source and
  turns the others into INFO context, so the noisy-OR never counts one breach 3-4 times.
* **Sensitive breaches (P133 cond 6, LGPD art. 11)**: IsSensitive or a sensitive service category
  (catalogue) read 'sensitive breach (name withheld)'; their domain and special-category data classes
  are dropped and nothing is inferred about the person; severity never uses the category.
* **Never counted**: IsSpamList / IsFabricated listings are INFO ``context_only``.
* **Severity (P133 cond 6)**: own addresses - stealer-log listing HIGH, passwords MEDIUM, other data
  LOW; a breach older than 3 years is lowered one level unless passwords are involved (no rotation
  is ever known to V3LUM); third parties are capped at MEDIUM. Confidence: verified breach PROBABLE,
  otherwise POSSIBLE (a listing is never CONFIRMED).
* Every finding states its data classes and a next step (:func:`next_step`: 'password exposed in a
  2019 breach: confirm it was changed and not reused'). Metadata only: names, dates, data classes,
  counts and the password FORM (A4 BR4); never passwords, hashes or hints.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from typing import Any

from v3lum.core import sanitize
from v3lum.core.entities import Entity, generic_address_kind
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult

__all__ = [
    "GENERIC_FOUND",
    "LGPD_NOTE",
    "MERGE_MODULES",
    "NEVER_TESTED",
    "SENSITIVE_LABEL",
    "SPECIAL_CATEGORY_CLASSES",
    "Listing",
    "breach_domain",
    "breach_key",
    "breach_scope",
    "emit_listings",
    "generic_kind",
    "masked_key",
    "next_step",
    "norm_date",
    "normalise_data_classes",
    "normalise_email",
    "resolve",
    "safe_form",
    "severity_for",
]

SENSITIVE_LABEL = "sensitive breach (name withheld)"
#: A4 BR6 / P135 cond 5: an aggregator total at or above this marks a generic or shared value
GENERIC_FOUND = 100
#: modules whose per-breach findings the p2g04_breach_merge rule merges (order = finding of record)
MERGE_MODULES = ("hibp_account", "xposedornot", "leakcheck_public")
NEVER_TESTED = "Leaked credentials are never tested, validated or used."
LGPD_NOTE = "Personal data (LGPD): case use only, security purpose recorded; breach metadata only."
OLD_YEARS = 3
SEVERITIES = ("info", "low", "medium", "high", "critical")
SCOPE_SKIP = (
    "breach check skipped: not an org domain (third-party addresses need an analyst-typed seed, "
    "--breach-scope all and --purpose)"
)
#: LGPD art. 11 special categories: never shown for a masked (sensitive) breach
SPECIAL_CATEGORY_CLASSES = frozenset({
    "sexual orientations", "sexual fetishes", "religions", "ethnicities", "political views", "political donations",
    "health insurance information", "personal health data", "medical conditions", "hiv statuses", "races", "castes",
    "drug habits", "disabilities", "biometric data", "fitness levels",
})

_KNOWN_GTLDS = frozenset({
    "com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "io", "app", "dev", "xyz", "online", "site",
    "store", "shop", "club", "top", "live", "film", "games", "game", "pro", "name", "mobi", "asia", "tech", "cloud",
    "space", "website", "fun", "life", "world", "today", "news", "blog", "media", "music", "porn", "sex", "xxx",
    "adult", "dating", "social", "network", "email", "link", "page", "one", "vip", "win", "bet", "casino", "poker",
    "travel", "agency", "digital", "studio", "academy", "center", "zone", "systems", "solutions", "software",
    "group", "global", "health", "care", "church", "school", "market", "money", "finance", "bank", "art", "design",
    "photo", "photography", "tv", "fm", "am", "cat", "coop", "aero", "museum", "jobs", "tel",
})
_SLD_LABELS = frozenset({"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "mil", "nic", "ltd", "plc"})
_DOMAINISH = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$")
_YEAR_QUALIFIER = re.compile(r"\(\s*((?:19|20)\d{2})\s*\)\s*$")
_ANY_QUALIFIER = re.compile(r"\([^)]*\)")
_COMPILATION = re.compile(r"collection|combo|compilation|antipublic|exploit\.?in|naz\.?api", re.I)
_STEALER = re.compile(r"stealer", re.I)
_DATA_CLASS_MAP = {
    "password": "Passwords", "passwords": "Passwords", "pass": "Passwords", "pwd": "Passwords",
    "email": "Email addresses", "emails": "Email addresses", "email addresses": "Email addresses", "e-mail": "Email addresses",
    "username": "Usernames", "usernames": "Usernames", "login": "Usernames", "profile_name": "Usernames",
    "ip": "IP addresses", "ip1": "IP addresses", "ip2": "IP addresses", "ip addresses": "IP addresses",
    "dob": "Dates of birth", "dates of birth": "Dates of birth", "birthdate": "Dates of birth",
    "phone": "Phone numbers", "phone numbers": "Phone numbers", "mobile": "Phone numbers",
    "address": "Physical addresses", "physical addresses": "Physical addresses",
    "city": "Geographic locations", "state": "Geographic locations", "country": "Geographic locations",
    "zip": "Geographic locations", "geographic locations": "Geographic locations",
    "name": "Names", "names": "Names", "first_name": "Names", "last_name": "Names", "middle_name": "Names", "full_name": "Names",
    "gender": "Genders", "genders": "Genders",
    "ssn": "Social security numbers", "social security numbers": "Social security numbers",
    "company_name": "Employers", "employers": "Employers", "job titles": "Job titles",
}
_NOT_DATA_CLASSES = frozenset({"id", "origin"})
_CLASS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ,'()/&.+-]{0,79}$")


# --------------------------------------------------------------------------------------
# small parsers (untrusted data: wrong types never raise)
# --------------------------------------------------------------------------------------


def _str(value: Any, cap: int = 300) -> str | None:
    if isinstance(value, str):
        s = " ".join(value.split())[:cap]
        return s or None
    return None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value == value:
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"\s*-?\d{1,15}\s*", value):
        return int(value)
    return None


def _flag(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false", "yes", "no", "1", "0"):
        return value.strip().lower() in ("true", "yes", "1")
    if isinstance(value, int):
        return bool(value)
    return None


def normalise_email(value: Any) -> str | None:
    """Trimmed lower-case address with exactly one '@' and a dotted domain, else None."""
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    if v.count("@") != 1 or any(c.isspace() for c in v) or len(v) > 254:
        return None
    local, domain = v.split("@")
    if not local or not domain or "." not in domain.strip("."):
        return None
    return v


def norm_date(value: Any) -> str | None:
    """'YYYY-MM-DD', 'YYYY-MM' or 'YYYY' from an ISO date/date-time or a year, else None."""
    text = _str(value, 40) if not isinstance(value, int) or isinstance(value, bool) else str(value)
    if not text:
        return None
    m = re.match(r"^((?:19|20)\d{2})(?:-(\d{2})(?:-(\d{2}))?)?", text)
    if not m:
        return None
    year, month, day = m.groups()
    if month and not 1 <= int(month) <= 12:
        return year
    if day and not 1 <= int(day) <= 31:
        return f"{year}-{month}"
    return "-".join(p for p in (year, month, day) if p)


def _year(value: Any) -> int | None:
    d = norm_date(value)
    return int(d[:4]) if d else None


def _fold(text: str) -> str:
    text = unicodedata.normalize("NFKD", text)
    return "".join(c for c in text if not unicodedata.combining(c)).lower()


def _is_tld(label: str) -> bool:
    return (len(label) == 2 and label.isalpha()) or label in _KNOWN_GTLDS or label.startswith("xn--")


def breach_domain(name: Any) -> str | None:
    """The service domain when a breach/source name is domain-shaped ('Zomato.com'), else None."""
    if not isinstance(name, str):
        return None
    text = _ANY_QUALIFIER.sub(" ", _fold(name)).strip()
    if text.startswith("www."):
        text = text[4:]
    if not _DOMAINISH.match(text) or not _is_tld(text.rsplit(".", 1)[-1]):
        return None
    return text


def _key_parts(name: Any) -> tuple[str, str | None, str | None, str | None]:
    if not isinstance(name, str):
        return "", None, None, None
    text = _fold(name).strip()
    year = None
    m = _YEAR_QUALIFIER.search(text)
    if m:
        year = m.group(1)
        text = text[: m.start()].strip()
    qualifiers = [q.strip("() ").strip() for q in _ANY_QUALIFIER.findall(text)]
    qualifier = "; ".join(q for q in qualifiers if q) or None
    text = _ANY_QUALIFIER.sub(" ", text).strip()
    domain = breach_domain(text)
    if domain:
        labels = domain.split(".")[:-1]
        if len(labels) > 1 and labels[-1] in _SLD_LABELS:
            labels = labels[:-1]
        text = "".join(labels)
    return re.sub(r"[^a-z0-9]", "", text), year, qualifier, domain


def breach_key(name: Any) -> str:
    """Normalised breach name (P133/P135/P137 cond 7): 'Zacks.com (2024)' and 'Zacks-2024' ->
    'zacks2024'; '8Tracks.com' -> '8tracks'; 'Ticketek.com.au' -> 'ticketek'."""
    base, year, _q, _d = _key_parts(name)
    return base + (year or "") if base else ""


def masked_key(key: str) -> str:
    """Stable, non-reversible merge key of a sensitive breach (its name is never shown)."""
    return "sensitive:" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


def normalise_data_classes(values: Any) -> list[str]:
    """Sorted unique HIBP-style data classes from a list or a ';'-joined string (field NAMES only)."""
    if isinstance(values, str):
        values = values.split(";")
    if not isinstance(values, (list, tuple)):
        return []
    out: set[str] = set()
    for v in values:
        text = _str(v, 80)
        if not text:
            continue
        low = text.lower()
        if low in _NOT_DATA_CLASSES:
            continue
        label = _DATA_CLASS_MAP.get(low) or (text[0].upper() + text[1:])
        if _CLASS_RE.match(label):
            out.add(label)
    return sorted(out)


def safe_form(value: Any) -> str | None:
    """A password FORM the sanitizer accepts ('plaintext', 'hashed[: algorithm]', 'unknown'), or None."""
    if not isinstance(value, str) or not value.strip():
        return None
    form = sanitize.normalize_password_form(value) or value.strip()
    if sanitize.is_password_form(form):
        return form
    return "hashed" if form.lower().startswith("hashed") else "unknown"


def _has_passwords(classes: Iterable[str], form: str | None) -> bool:
    return bool(form) or any(c.lower() in ("passwords", "historical passwords") for c in classes)


# --------------------------------------------------------------------------------------
# one listing of an identity by one source
# --------------------------------------------------------------------------------------


@dataclass
class Listing:
    """One breach that lists the investigated identity, as one source reported it (metadata only)."""

    name: str
    source: str  # registry source id, e.g. 'hibp.account'
    date: str | None = None
    domain: str | None = None
    data_classes: list[str] = field(default_factory=list)
    password_form: str | None = None
    verified: bool | None = None
    fabricated: bool | None = None
    spam_list: bool | None = None
    stealer_log: bool | None = None
    sensitive: bool | None = None
    compilation: bool | None = None
    records: int | None = None
    catalogue: str = ""  # how the shared catalogue matched: '' | 'name' | 'key' | 'domain'
    canonical: str = ""  # catalogue name used for the merge key

    @property
    def key(self) -> str:
        """The merge key: the catalogue's canonical name when one matched, else the source name."""
        return breach_key(self.canonical or self.name) or re.sub(r"[^a-z0-9]", "", _fold(self.name))

    @property
    def counted(self) -> bool:
        """IsSpamList / IsFabricated listings never count as exposure (P133 cond 6)."""
        return not (self.spam_list or self.fabricated)

    @property
    def passwords(self) -> bool:
        return _has_passwords(self.data_classes, self.password_form)

    def shown_name(self) -> str:
        return SENSITIVE_LABEL if self.sensitive else self.name

    def shown_key(self) -> str:
        return masked_key(self.key) if self.sensitive else self.key

    def shown_classes(self) -> list[str]:
        if not self.sensitive:
            return list(self.data_classes)
        return [c for c in self.data_classes if c.lower() not in SPECIAL_CATEGORY_CLASSES]

    def record(self) -> dict[str, Any]:
        """The ``breach_records`` / finding-data shape the P146 pack reads (sensitive names withheld)."""
        return {
            "name": self.shown_name(),
            "breach_key": self.shown_key(),
            "date": self.date,
            "data_classes": self.shown_classes(),
            "password_form": self.password_form,
            "verified": self.verified,
            "fabricated": self.fabricated,
            "spam_list": self.spam_list,
            "stealer_log": self.stealer_log,
            "sensitive": bool(self.sensitive),
            "compilation": self.compilation,
            "domain": None if self.sensitive else self.domain,
            "records": self.records,
            "source": self.source,
        }


# --------------------------------------------------------------------------------------
# the shared catalogue join (P132 helper of hibp_catalog)
# --------------------------------------------------------------------------------------


def resolve(catalog: Any, name: str, *, date: str | None = None, domain: str | None = None) -> tuple[dict[str, Any] | None, str]:
    """Catalogue facts of a breach name reported by any source: (normalised HIBP breach | None, how).

    Order: the catalogue's own normalised key ('name'); the domain-stripped key ('key'); then the
    service domain (given, or a domain-shaped name) with a breach year within one year of ``date``
    ('domain'; a unique closest match only). A name with a non-year qualifier ('Twitter.com (scraping
    data)') tries the domain + year join first. Never raises: an unusable catalogue gives (None, '').
    """
    if catalog is None or not isinstance(name, str) or not name.strip():
        return None, ""
    try:
        by_key = getattr(catalog, "by_key", {}) or {}
        base, qyear, qualifier, ndomain = _key_parts(name)
        year = _year(date) or (int(qyear) if qyear else None)
        dom = (domain or "").strip().lower().rstrip(".") or ndomain
        if dom and dom.startswith("www."):
            dom = dom[4:]

        def by_name() -> tuple[dict[str, Any] | None, str]:
            hit = catalog.lookup(name)
            if hit is not None:
                return hit, "name"
            key = base + (qyear or "") if base else ""
            hit = by_key.get(key) if key else None
            return (hit, "key") if hit is not None else (None, "")

        def by_domain() -> tuple[dict[str, Any] | None, str]:
            if not dom:
                return None, ""
            cands = list(catalog.for_domain(dom))
            if year is not None:
                scored = sorted(
                    (abs(_year(c.get("breach_date")) - year), i, c)  # type: ignore[operator]
                    for i, c in enumerate(cands)
                    if _year(c.get("breach_date")) is not None and abs(_year(c.get("breach_date")) - year) <= 1  # type: ignore[operator]
                )
                if not scored or (len(scored) > 1 and scored[0][0] == scored[1][0]):
                    return None, ""
                return scored[0][2], "domain"
            return (cands[0], "domain") if len(cands) == 1 else (None, "")

        steps = [by_name, by_domain]
        if qualifier and year is not None:
            steps.reverse()
        for step in steps:
            hit, how = step()
            if hit is not None:
                return hit, how
    except Exception:  # noqa: BLE001 - a broken catalogue only means 'no enrichment'
        return None, ""
    return None, ""


def enrich(listing: Listing, catalog: Any) -> Listing:
    """Fill what a source left out (date, domain, data classes, password FORM, flags) from the shared
    HIBP catalogue; sensitive/spam/fabricated/stealer flags are OR-ed (a flag any source sets wins)."""
    hit, how = resolve(catalog, listing.name, date=listing.date, domain=listing.domain)
    if hit is None:
        return listing
    classes = list(listing.data_classes) or [c for c in hit.get("data_classes") or [] if isinstance(c, str)]

    def either(mine: bool | None, theirs: Any) -> bool | None:
        if mine is True or theirs is True:
            return True
        return mine if mine is not None else (bool(theirs) if isinstance(theirs, bool) else None)

    return replace(
        listing,
        date=_precise(listing.date, norm_date(hit.get("breach_date"))),
        domain=listing.domain or hit.get("domain"),
        data_classes=normalise_data_classes(classes),
        password_form=listing.password_form or safe_form(hit.get("password_form")),
        verified=either(listing.verified, hit.get("is_verified")),
        fabricated=either(listing.fabricated, hit.get("is_fabricated")),
        spam_list=either(listing.spam_list, hit.get("is_spam_list")),
        stealer_log=either(listing.stealer_log, hit.get("is_stealer_log")),
        sensitive=either(listing.sensitive, hit.get("sensitive")),
        catalogue=how,
        canonical=str(hit.get("name") or ""),
    )


def _precise(a: str | None, b: str | None) -> str | None:
    """The more precise of two dates of the same breach (YYYY-MM-DD over YYYY-MM over YYYY) when they agree
    on their common prefix; otherwise the source's own date wins."""
    if not a or not b:
        return a or b
    if len(b) > len(a) and b.startswith(a):
        return b
    return a


def flags_from_name(name: str) -> dict[str, bool]:
    """Compilation / stealer-log hints from a bare source name (LeakCheck, unknown XON ids)."""
    return {"compilation": bool(_COMPILATION.search(name)), "stealer_log": bool(_STEALER.search(name))}


# --------------------------------------------------------------------------------------
# scope, generic addresses, severity, next steps
# --------------------------------------------------------------------------------------


def generic_kind(entity: Entity) -> str | None:
    """A4 BR6: 'role' | 'test' | 'example_domain' for generic addresses (data/generic_addresses.json)."""
    if entity.type is not T.EMAIL:
        return None
    try:
        return generic_address_kind(entity.value) or None
    except Exception:  # noqa: BLE001
        return None


def breach_scope(entity: Entity, ctx: Any) -> tuple[bool, str]:
    """(own verified identity?, skip reason). Defence in depth next to the policy gate (A4, A11 BR4):
    addresses on txt_verified/attested org-profile domains are own assets; anything else runs only as
    an analyst-typed seed with --breach-scope all and a recorded purpose (third party, context only)."""
    org = getattr(ctx, "org", None)
    if entity.type is T.EMAIL and org is not None:
        try:
            if org.is_verified_domain(entity.value.rsplit("@", 1)[-1]):
                return True, ""
        except Exception:  # noqa: BLE001 - an unreadable profile owns nothing
            pass
    options = getattr(ctx, "options", None)
    scope_all = str(getattr(options, "breach_scope", "own") or "own").strip().lower() == "all"
    purpose = str(getattr(options, "purpose", "") or "").strip()
    if scope_all and purpose and bool(getattr(ctx, "is_seed", False)):
        return False, ""
    return False, SCOPE_SKIP


def _age_years(date: str | None, today: _dt.date) -> int | None:
    d = norm_date(date)
    if not d:
        return None
    year = int(d[:4])
    month = int(d[5:7]) if len(d) >= 7 else 1
    day = int(d[8:10]) if len(d) >= 10 else 1
    return max(0, today.year - year - ((today.month, today.day) < (month, day)))


def severity_for(listing: Listing, *, own: bool, generic: str | None, today: _dt.date) -> tuple[str, str, str]:
    """(severity, confidence label, criterion) of one listing (P133 cond 3/6/8, A4 BR6/BR10)."""
    if not listing.counted:
        what = "spam list" if listing.spam_list else "fabricated breach"
        return "info", "possible", f"{what}: never counted as exposure (P133 cond 6)"
    if generic:
        return "info", "possible", f"POSSIBLE - generic address ({generic}): flagged, never scored (A4 BR6)"
    passwords = listing.passwords
    if listing.stealer_log and own:
        sev, why = "high", "infostealer-log listing of an own address"
    elif passwords:
        sev, why = "medium", "passwords in the data classes"
    else:
        sev, why = "low", "no passwords in the data classes"
    age = _age_years(listing.date, today)
    if age is not None and age > OLD_YEARS and not passwords:
        sev = SEVERITIES[max(0, SEVERITIES.index(sev) - 1)]
        why += f"; breach older than {OLD_YEARS} years"
    elif age is not None and age > OLD_YEARS:
        why += f"; older than {OLD_YEARS} years but passwords are involved and no rotation is known"
    conf = "probable" if listing.verified else "possible"
    if not own:
        if SEVERITIES.index(sev) > SEVERITIES.index("medium"):
            sev = "medium"
        conf = "possible"
        why += "; third-party address (analyst-typed seed, --breach-scope all): context only, at most MEDIUM, no exposure score"
    else:
        why += "; address on a verified org-profile domain"
    if listing.sensitive:
        why += "; sensitive breach: name withheld, never scored on its category"
    return sev, conf, why


def next_step(listing: Listing) -> str:
    """The next step of a finding (P133 cond 7)."""
    year = _year(listing.date)
    when = f"a {year} breach" if year else "an undated breach"
    if listing.fabricated:
        return "fabricated breach: not counted; no action"
    if listing.spam_list:
        return "spam list only (no account at the service implied): not counted; expect spam"
    if listing.stealer_log:
        return f"address listed in infostealer logs ({when}): route to incident response and reset the credentials used on that device"
    if listing.passwords:
        extra = " (the service stored them in clear)" if listing.password_form == "plaintext" else ""
        return f"password exposed in {when}{extra}: confirm it was changed and not reused"
    classes = [c.lower() for c in listing.shown_classes()][:3]
    what = ", ".join(classes) if classes else "account data"
    return f"{what} exposed in {when}: no password involved; expect targeted phishing"


# --------------------------------------------------------------------------------------
# result building shared by the three modules
# --------------------------------------------------------------------------------------


def emit_listings(
    res: ModuleResult,
    listings: list[Listing],
    *,
    provider_label: str,
    own: bool,
    generic: str | None,
    today: _dt.date,
    references: Iterable[str] = (),
    max_findings: int = 200,
    summary_extra: str = "",
) -> None:
    """Attributes (``breach_records``, ``breaches``, ``breach_count``, ``breach_data_classes``,
    ``first_seen_breach``) and one finding per breach (tag ``breach``; data carries ``breach_key`` so
    ``p2g04_breach_merge`` can merge the sources). Listings with the same key are merged first.
    A generic/role/test/shared identity gets ONE INFO ``context_only`` summary finding instead
    (A4 BR6: flagged, capped at POSSIBLE, never scored; test@example.com lists 200+ breaches)."""
    merged: dict[str, Listing] = {}
    for item in listings:
        key = item.key
        if not key:
            continue
        prev = merged.get(key)
        merged[key] = item if prev is None else _merge_same(prev, item)
    items = sorted(merged.values(), key=lambda li: (li.date or "0000", li.key), reverse=True)
    records = [li.record() for li in items]
    res.attr("breach_records", records)
    res.attr("breaches", sorted({li.shown_name() for li in items}))
    counted = [li for li in items if li.counted]
    res.attr("breach_count", len(counted))
    res.attr("breach_data_classes", sorted({c for li in counted for c in li.shown_classes()}))
    dates = sorted(li.date for li in counted if li.date)
    if dates:
        res.attr("first_seen_breach", dates[0])
    refs = [r for r in references if isinstance(r, str)]
    if generic:
        res.attr("generic_address", generic)
        names = [li.shown_name() for li in counted][:10]
        res.finding(
            "Generic or shared identity listed in breaches",
            "info",
            f"{len(items)} breach listing(s) from {provider_label} for a generic, role, test or shared identity ({generic})"
            + (f": {', '.join(names)}" + (" ..." if len(counted) > len(names) else "") if names else "")
            + f". {summary_extra + ' ' if summary_extra else ''}Context only, never scored as exposure. {NEVER_TESTED}",
            confidence="possible",
            criterion=f"POSSIBLE - generic or shared identity ({generic}): flagged, never scored (A4 BR6, P146 CR11)",
            data={"listings": len(items), "counted": len(counted), "generic": generic,
                  "data_classes": sorted({c for li in counted for c in li.shown_classes()})[:40]},
            tags=["breach", "privacy", "context_only", *([] if own else ["third_party"])],
            references=refs,
            source=items[0].source if items else "",
        )
        return
    for li in items[:max_findings]:
        sev, conf, why = severity_for(li, own=own, generic=generic, today=today)
        step = next_step(li)
        classes = li.shown_classes()
        tags = ["breach", "privacy"]
        if not li.counted or generic or not own:
            tags.append("context_only")
        if not own:
            tags.append("third_party")
        if own and li.counted and not generic and li.passwords:
            tags.append("credential_exposure")
        details = [f"{li.shown_name()} ({li.date or 'date unknown'})"]
        details.append("data classes: " + (", ".join(classes[:20]) if classes else "not stated by the source"))
        if li.password_form:
            details.append(f"password form {li.password_form}")
        if li.records is not None:
            details.append(f"{li.records:,} accounts in the breach")
        if not li.counted:
            details.append("IsSpamList/IsFabricated: never counted as exposure")
        details.append("next step: " + step)
        data = li.record()
        data.update({"sources": [li.source], "next_step": step, "counted": li.counted, "own_verified": own})
        res.finding(
            f"Listed in breach: {li.shown_name()}",
            sev,
            "; ".join(details) + f". Source: {provider_label} (metadata only). {NEVER_TESTED}",
            confidence=conf,
            criterion=f"{provider_label}: the address is listed in this breach - {why}",
            data=data,
            tags=tags,
            references=refs,
            source=li.source,
            observed_first=li.date if li.date and len(li.date) == 10 else None,
            key=li.shown_key(),
        )


def _merge_same(a: Listing, b: Listing) -> Listing:
    """Two listings of the same breach from one source (e.g. check-email + analytics)."""

    def pick(x: Any, y: Any) -> Any:
        return x if x not in (None, "", []) else y

    def either(x: bool | None, y: bool | None) -> bool | None:
        if x is True or y is True:
            return True
        return x if x is not None else y

    date = a.date if a.date and (not b.date or len(a.date) >= len(b.date)) else b.date
    return replace(
        a,
        date=date,
        domain=pick(a.domain, b.domain),
        data_classes=sorted(set(a.data_classes) | set(b.data_classes)),
        password_form=pick(a.password_form, b.password_form),
        verified=either(a.verified, b.verified),
        fabricated=either(a.fabricated, b.fabricated),
        spam_list=either(a.spam_list, b.spam_list),
        stealer_log=either(a.stealer_log, b.stealer_log),
        sensitive=either(a.sensitive, b.sensitive),
        compilation=either(a.compilation, b.compilation),
        records=pick(a.records, b.records),
        catalogue=a.catalogue or b.catalogue,
        canonical=a.canonical or b.canonical,
    )


def today_of(ctx: Any) -> _dt.date:
    now = ctx.now() if callable(getattr(ctx, "now", None)) else _dt.datetime.now(_dt.timezone.utc)
    return now.date()


def bool_or_none(value: Any) -> bool | None:
    return _flag(value)


def int_or_none(value: Any) -> int | None:
    return _int(value)


def str_or_none(value: Any, cap: int = 300) -> str | None:
    return _str(value, cap)
