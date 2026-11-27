"""Have I Been Pwned breach catalogue (P132) and the shared breach-catalogue helper (P132 C3).

Keyless catalogue endpoints only (C1): ``/api/v3/breaches`` (a registered 24 h dataset, stale copy
kept on failure, C2), ``/breach/{name}``, ``/latestbreach`` and ``/dataclasses`` (a registered
dataset). HIBP's terms allow them "for any lawful purpose, including within commercial products";
the data is CC BY 4.0: attribution "Have I Been Pwned" with a link wherever results are shown (C7).
The provider's neutral ``V3LUM/<version>`` user agent is always sent (HIBP rejects requests without
one, P326).

* Domain input: answered LOCALLY from the catalogue dataset (C2: it discloses nothing; HIBP's
  ``?domain=`` endpoint is never called). The wording is fixed (C6): breaches of the service at the
  domain - "this service was breached", never "accounts at my domain".
* Keyword input (a breach name): the local catalogue first, ``/breach/{name}`` only for a name the
  local copy does not know (404 = no such breach in HIBP).
* ``/latestbreach`` is the cheap "catalogue changed?" probe (1.3 KB) made before re-downloading the
  1.1 MB catalogue when the local copy is older than 24 h: HIBP sends no ETag, so a conditional GET
  cannot help.

The shared helper :func:`breach_catalog` (lookup by normalised name and by domain) is THE catalogue
of every breach module (P133, P134, P135, P137, P140; no module keeps its own copy): it adds breach
dates, data classes, the IsVerified/IsFabricated/IsSpamList/IsStealerLog/IsSensitive flags, the
sensitive service category and the password FORM to breach names reported by other sources. Flags
propagate (C4): IsSensitive and sensitive-category breaches (adult, dating, health, religion,
sexual orientation, politics) display as 'sensitive breach (name withheld)' by default, and
IsSpamList/IsFabricated breaches never count as exposure. The password FORM ('plaintext' or
'hashed: <algorithm>', a port of Céos ``forma_senha``) is the only password-related fact kept
(C5, A4). A module using the helper declares ``hibp.catalog`` among its sources (the sanitizer
schema of that source is registered here)::

    from v3lum.modules.breach_leak.hibp_catalog import SRC_CATALOG, breach_catalog
    catalog = breach_catalog(ctx)            # local dataset copy (refreshed when older than 24 h)
    facts = catalog.enrich(["Adobe", "LinkedIn"])
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import html as _html
import json
import re
import threading
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

from v3lum.core import http as _http
from v3lum.core import psl, sanitize
from v3lum.core.datasets import DatasetError, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

__all__ = [
    "ATTRIBUTION_TEXT",
    "ATTRIBUTION_URL",
    "BreachCatalog",
    "CATALOG_DATASET",
    "DATACLASSES_DATASET",
    "DOMAIN_WORDING",
    "SENSITIVE_BREACH_LABEL",
    "SENSITIVE_CATEGORIES",
    "SRC_CATALOG",
    "breach_catalog",
    "breach_category",
    "normalise_breach",
    "normalise_breach_name",
    "password_form",
]

SRC_CATALOG = "hibp.catalog"
SRC_DATACLASSES = "hibp.hibp_catalog_dataclasses"
API = "https://haveibeenpwned.com/api/v3"
CATALOG_URL = f"{API}/breaches"
BREACH_URL = API + "/breach/{name}"
LATEST_URL = f"{API}/latestbreach"
DATACLASSES_URL = f"{API}/dataclasses"
BREACH_PAGE = "https://haveibeenpwned.com/Breach/{name}"
ATTRIBUTION_TEXT = "Have I Been Pwned (CC BY 4.0)"
ATTRIBUTION_URL = "https://haveibeenpwned.com/"
#: C6 wording, visible in reports.
DOMAIN_WORDING = "breaches of the service at {domain} (this service was breached) - not accounts at this domain"
SENSITIVE_BREACH_LABEL = "sensitive breach (name withheld)"
SENSITIVE_CATEGORIES = ("adult", "dating", "health", "religion", "sexual_orientation", "politics")
DAY = 86400
MIN_BREACHES = 500
MAX_LISTED = 200

#: Fields kept from HIBP breach objects (list form for /breaches, object form for /breach/{name} and
#: /latestbreach). LogoPath (external images are never loaded), Attribution (it can hold a
#: person's handle) and DisclosureUrl are dropped before the cache, the dataset copy and evidence.
BREACH_FIELDS = (
    "Name", "Title", "Domain", "BreachDate", "AddedDate", "ModifiedDate", "PwnCount", "Description", "DataClasses",
    "IsVerified", "IsFabricated", "IsSensitive", "IsRetired", "IsSpamList", "IsMalware", "IsSubscriptionFree", "IsStealerLog",
)
sanitize.register_schema(
    SRC_CATALOG,
    keep=[f"[].{f}" for f in BREACH_FIELDS] + list(BREACH_FIELDS),
    notes="P132/A4: HIBP catalogue breach objects keep only breach metadata (names, dates, counts, data classes, "
    "description, flags); LogoPath, Attribution and DisclosureUrl are dropped. Registered by hibp_catalog for every "
    "module that reads the shared catalogue.",
)

_FLAG_FIELDS = (
    ("is_verified", "IsVerified"), ("is_fabricated", "IsFabricated"), ("is_sensitive", "IsSensitive"),
    ("is_retired", "IsRetired"), ("is_spam_list", "IsSpamList"), ("is_malware", "IsMalware"),
    ("is_stealer_log", "IsStealerLog"), ("is_subscription_free", "IsSubscriptionFree"),
)
_PASSWORD_CLASSES = {"passwords", "historical passwords"}
#: data classes that reveal the NATURE of the service (membership itself is sensitive)
_CATEGORY_CLASSES = {"Sexual fetishes": "adult", "Sexual orientations": "sexual_orientation", "HIV statuses": "health"}
#: LGPD art. 5 II sensitive data classes: informational (what leaked), they do not mask the name
SENSITIVE_DATA_CLASSES = (
    "Religions", "Political views", "Political donations", "Sexual orientations", "Sexual fetishes", "HIV statuses",
    "Health insurance information", "Personal health data", "Disabilities", "Ethnicities", "Races", "Castes",
    "Biometric data", "Drug habits",
)
# service-type keywords, matched only on Title/Name/Domain + the FIRST sentence of the description
_CATEGORY_WORDS = (
    ("adult", r"\b(?:adult|porn\w*|xxx|escorts?|erotic\w*|fetish\w*|sex|sexual|nsfw|camgirls?|webcam\w*|hentai)\b"),
    ("dating", r"\bdating\b(?! back)|\bhook-?ups?\b|\binfidelity\b|\bmatchmaking\b|\bmatrimonial\b|\bswingers?\b|\bsugar (?:daddy|baby|dating)\b"),
    ("sexual_orientation", r"\b(?:gay|lesbian|lgbt\w*|bisexual|queer|transgender)\b"),
    ("religion", r"\b(?:christian\w*|muslims?|islamic|church\w*|religious|bible|jewish|catholic\w*|mosques?|evangelical)\b"),
    ("health", r"\b(?:health ?care|medical|clinics?|hospitals?|pharmac\w*|hiv|mental health|patients?|telehealth|dental|therap\w*)\b"),
    ("politics", r"\b(?:political|politics|elections?|electoral|voters?|parliament\w*)\b"),
)
_SENTENCE_END_RE = re.compile(r"(?<!\b[A-Z])[.!?](?:\s|$)")
_TAG_STRIP_RE = re.compile(r"<[^>]+>")
_HINT_RE = re.compile(r"password hints?[^.;]*", re.I)  # Céos _DICA
# 'quickly resolved/cracked back to plain text' describes cracking, not plaintext storage (Adobe)
_CRACKED_RE = re.compile(r"\b(?:resolved|cracked|converted|reversed|recovered)\b[^.;]*?(?:plain ?text|clear ?text)", re.I)
_PLAIN_RE = re.compile(r"plain ?text|plaintext|unhashed|in the clear|cleartext|clear text|unencrypted passwords?|unsalted and unhashed", re.I)
_HASH_WORD_RE = re.compile(r"hash|bcrypt|md5|sha-?1|sha-?256|sha-?512|salted|pbkdf2|argon|scrypt|crypt|encrypt", re.I)
_ALGOS = (
    ("bcrypt", r"bcrypt"), ("argon2", r"argon2?"), ("scrypt", r"scrypt"), ("pbkdf2", r"pbkdf2"), ("sha512", r"sha-?512"),
    ("sha256", r"sha-?256"), ("sha1", r"sha-?1\b"), ("md5", r"\bmd5"), ("des-crypt", r"\bdes\b|des-based|\bcrypt\("),
    ("phpass", r"phpass|wordpress (?:hash|style)"), ("encrypted", r"encrypt"),
)


# --------------------------------------------------------------------------------------
# pure helpers (ported from the prep parsers; defensive, never raise on odd input)
# --------------------------------------------------------------------------------------


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    return None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _iso(value: Any) -> str | None:
    """ISO date/time -> 'YYYY-MM-DD' (dates) or 'YYYY-MM-DDTHH:MM:SSZ' (UTC); None when unreadable."""
    if not isinstance(value, str) or not value.strip():
        return None
    v = value.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
        try:
            _dt.date.fromisoformat(v)
        except ValueError:
            return None
        return v
    try:
        d = _dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=_dt.timezone.utc)
    return d.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean(value: Any, limit: int) -> str:
    text = value if isinstance(value, str) else ""
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", text).strip()[:limit]


def strip_html(text: Any) -> str:
    """Breach Description HTML -> plain text (tags removed, entities unescaped, whitespace collapsed)."""
    s = _TAG_STRIP_RE.sub(" ", text[:200_000] if isinstance(text, str) else "")
    return " ".join(_html.unescape(s).split())


def password_form(description: Any, data_classes: Iterable[str] | None = None) -> str | None:
    """Password FORM from the breach description (Céos forma_senha port, C5 / A4 BR4): None (no
    password data class), 'plaintext' (worst case wins), 'hashed: <algorithm[/algorithm]>' or
    'unknown'. Password-hint phrases and 'cracked/resolved back to plain text' phrases are removed
    first. The only password-related fact kept."""
    classes = {str(c).strip().lower() for c in (data_classes or []) if isinstance(c, str)}
    if data_classes is not None and not classes & _PASSWORD_CLASSES:
        return None
    desc = _CRACKED_RE.sub(" ", _HINT_RE.sub(" ", strip_html(description)))
    if _PLAIN_RE.search(desc):
        return "plaintext"
    if _HASH_WORD_RE.search(desc):
        algos = [name for name, pat in _ALGOS if re.search(pat, desc, re.I)]
        if len(algos) > 1 and "encrypted" in algos:
            algos.remove("encrypted")
        return "hashed: " + ("/".join(algos) if algos else "unknown")
    return "unknown"


def first_sentence(text: Any) -> str:
    t = strip_html(text)
    m = _SENTENCE_END_RE.search(t)
    return (t[: m.start()] if m else t)[:400]


def breach_category(breach: Any) -> str | None:
    """Sensitive SERVICE category from service-revealing data classes, then keywords on
    Title/Name/Domain and the first sentence of the description; None otherwise (C3/C4)."""
    if not isinstance(breach, dict):
        return None
    classes = breach.get("DataClasses") if isinstance(breach.get("DataClasses"), list) else []
    for c in classes:
        if isinstance(c, str) and c in _CATEGORY_CLASSES:
            return _CATEGORY_CLASSES[c]
    text = " ".join(str(breach.get(k) or "") for k in ("Title", "Name", "Domain"))
    text += " " + first_sentence(breach.get("Description"))
    for category, pattern in _CATEGORY_WORDS:
        if re.search(pattern, text, re.I):
            return category
    return None


def normalise_breach_name(name: Any) -> str:
    """Lower-case alphanumerics only: the cross-source key of a breach name (C3)."""
    s = unicodedata.normalize("NFKD", str(name or ""))
    s = "".join(c for c in s if not unicodedata.combining(c)).lower()
    return re.sub(r"[^a-z0-9]", "", s)


def normalise_breach(b: Any) -> dict[str, Any] | None:
    """One HIBP breach object -> the kept metadata with propagated flags (C4)."""
    if not isinstance(b, dict) or not isinstance(b.get("Name"), str) or not b["Name"].strip():
        return None
    classes = [c for c in b.get("DataClasses") if isinstance(c, str)] if isinstance(b.get("DataClasses"), list) else []
    flags = {key: bool(_bool(b.get(src))) for key, src in _FLAG_FIELDS}
    category = breach_category(b)
    domain = b.get("Domain") if isinstance(b.get("Domain"), str) else ""
    return {
        "name": _clean(b["Name"], 200),
        "title": _clean(b.get("Title") or b["Name"], 200),
        "key": normalise_breach_name(b["Name"]),
        "domain": domain.strip().rstrip(".").lower() or None,
        "breach_date": _iso(b.get("BreachDate")),
        "added_date": _iso(b.get("AddedDate")),
        "modified_date": _iso(b.get("ModifiedDate")),
        "pwn_count": _int(b.get("PwnCount")),
        "data_classes": classes,
        "sensitive_data_classes": [c for c in classes if c in SENSITIVE_DATA_CLASSES],
        "password_form": password_form(b.get("Description"), classes),
        "category": category,
        "sensitive": flags["is_sensitive"] or category in SENSITIVE_CATEGORIES,
        "counts_as_exposure": not (flags["is_spam_list"] or flags["is_fabricated"]),
        **flags,
    }


def display_breach_name(breach: dict[str, Any], show_sensitive: bool = False) -> str:
    """Name shown downstream: sensitive breaches are masked by default (C4)."""
    if breach.get("sensitive") and not show_sensitive:
        return SENSITIVE_BREACH_LABEL
    return str(breach.get("title") or breach.get("name") or "")


def public_view(breach: dict[str, Any], show_sensitive: bool = False) -> dict[str, Any]:
    """The facts shown in attributes, findings and reports (sensitive names withheld by default)."""
    masked = bool(breach.get("sensitive")) and not show_sensitive
    out = {
        "name": SENSITIVE_BREACH_LABEL if masked else breach.get("name"),
        "title": display_breach_name(breach, show_sensitive),
        "breach_date": breach.get("breach_date"),
        "added_date": breach.get("added_date"),
        "pwn_count": breach.get("pwn_count"),
        "data_classes": list(breach.get("data_classes") or []),
        "password_form": breach.get("password_form"),
        "category": breach.get("category"),
        "sensitive": bool(breach.get("sensitive")),
        "counts_as_exposure": bool(breach.get("counts_as_exposure")),
        **{key: bool(breach.get(key)) for key, _src in _FLAG_FIELDS},
    }
    return out


# --------------------------------------------------------------------------------------
# datasets (C2) and the shared catalogue helper (C3)
# --------------------------------------------------------------------------------------


def _validate_catalog(path: Path) -> bool:
    """AR10 ``validate=``: a challenge page, an error body or a truncated list never replaces the copy."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (ValueError, OSError) as exc:
        raise DatasetError(f"HIBP catalogue is not valid JSON ({type(exc).__name__})")
    if not isinstance(data, list):
        raise DatasetError("HIBP catalogue is not a JSON list")
    count = sum(1 for b in data if isinstance(b, dict) and isinstance(b.get("Name"), str))
    if count < MIN_BREACHES:
        raise DatasetError(f"only {count} breaches (expected >= {MIN_BREACHES})")
    return True


def _validate_dataclasses(path: Path) -> bool:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (ValueError, OSError) as exc:
        raise DatasetError(f"HIBP data classes are not valid JSON ({type(exc).__name__})")
    if not isinstance(data, list) or sum(1 for x in data if isinstance(x, str) and x.strip()) < 50:
        raise DatasetError("HIBP data classes: expected a list of at least 50 names")
    return True


CATALOG_DATASET = register_dataset(
    "hibp_breaches.json",
    CATALOG_URL,
    ttl=DAY,
    description="Have I Been Pwned breach catalogue (/api/v3/breaches, sanitized: breach metadata only)",
    licence="CC-BY-4.0",
    terms_class="open",
    attribution="Have I Been Pwned (https://haveibeenpwned.com/), CC BY 4.0",
    provider="hibp",
    source=SRC_CATALOG,
    validate=_validate_catalog,
    min_bytes=50_000,
    expect="json",
    max_bytes=5_000_000,
    essential=True,
)
DATACLASSES_DATASET = register_dataset(
    "hibp_dataclasses.json",
    DATACLASSES_URL,
    ttl=DAY,
    description="Have I Been Pwned data-class names (/api/v3/dataclasses)",
    licence="CC-BY-4.0",
    terms_class="open",
    attribution="Have I Been Pwned (https://haveibeenpwned.com/), CC BY 4.0",
    provider="hibp",
    source=SRC_DATACLASSES,
    validate=_validate_dataclasses,
    min_bytes=200,
    expect="json",
    max_bytes=200_000,
)


@dataclass
class BreachCatalog:
    """Index of the HIBP catalogue by normalised Name/Title and by Domain (C3)."""

    breaches: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, dict[str, Any]] = field(default_factory=dict)  # key -> sanitized HIBP object (evidence)
    by_key: dict[str, dict[str, Any]] = field(default_factory=dict)
    by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    origin: str = ""  # 'dataset' | 'dataset (stale)' | 'dataset (latestbreach: unchanged)'
    fetched_at: str = ""

    @classmethod
    def build(cls, data: Any, *, origin: str = "", fetched_at: str = "") -> BreachCatalog:
        cat = cls(origin=origin, fetched_at=fetched_at)
        for item in data if isinstance(data, list) else []:
            b = normalise_breach(item)
            if b is None:
                continue
            cat.breaches.append(b)
            cat.raw.setdefault(b["key"], {k: item[k] for k in BREACH_FIELDS if k in item})
            for key in (b["key"], normalise_breach_name(b["title"])):
                if key and key not in cat.by_key:
                    cat.by_key[key] = b
            if b["domain"]:
                cat.by_domain.setdefault(b["domain"], []).append(b)
        for items in cat.by_domain.values():
            items.sort(key=lambda x: (x.get("breach_date") or "", x["name"]))
        return cat

    def __len__(self) -> int:
        return len(self.breaches)

    def lookup(self, name: Any) -> dict[str, Any] | None:
        """A breach name reported by any source -> its catalogue facts (exact normalised key)."""
        return self.by_key.get(normalise_breach_name(name))

    def for_domain(self, domain: Any) -> list[dict[str, Any]]:
        """Breaches OF the service at this domain (C2/C6: 'this service was breached')."""
        d = str(domain or "").strip().rstrip(".").lower()
        d = d[4:] if d.startswith("www.") else d
        return list(self.by_domain.get(d, []))

    def newest_added(self) -> str:
        return max((b.get("added_date") or "" for b in self.breaches), default="")

    def enrich(self, names: Iterable[Any], *, show_sensitive: bool = False) -> list[dict[str, Any]]:
        """Breach names from another source -> catalogue facts with flags and display names;
        unknown names come back with known=False (never dropped)."""
        out = []
        for name in names or ():
            b = self.lookup(name)
            if b is None:
                out.append({"source_name": _clean(str(name), 200), "known": False})
                continue
            out.append({"source_name": _clean(str(name), 200), "known": True, **public_view(b, show_sensitive)})
        return out


_INDEX: dict[str, BreachCatalog] = {}
_INDEX_LOCK = threading.Lock()


def _catalog_from(data: Any, sha: str, origin: str, fetched_at: str) -> BreachCatalog:
    with _INDEX_LOCK:
        hit = _INDEX.get(sha)
    if hit is not None:
        return BreachCatalog(hit.breaches, hit.raw, hit.by_key, hit.by_domain, origin, fetched_at)
    cat = BreachCatalog.build(data, origin=origin, fetched_at=fetched_at)
    with _INDEX_LOCK:
        if len(_INDEX) > 4:
            _INDEX.clear()
        _INDEX[sha] = cat
    return cat


def _probe_unchanged(ctx: Any, local: BreachCatalog) -> bool:
    """/latestbreach probe (module runs only): True when the newest HIBP breach is already in the
    local copy, so the 1.1 MB catalogue is not downloaded again. Remembered for 24 h in ctx.state."""
    state = getattr(ctx, "state", None)
    now = ctx.now() if callable(getattr(ctx, "now", None)) else _dt.datetime.now(_dt.timezone.utc)
    newest = local.newest_added()
    try:
        last = state.get("latestbreach_probe") if state is not None else None
    except Exception:  # noqa: BLE001 - state is a convenience, never a failure
        last = None
    if isinstance(last, dict) and last.get("newest_added") == newest:
        try:
            when = _dt.datetime.fromisoformat(str(last.get("checked_at")).replace("Z", "+00:00"))
            if (now - when).total_seconds() < DAY:
                return True
        except (TypeError, ValueError):
            pass
    data = ctx.http.get_json(LATEST_URL, source=SRC_CATALOG)
    latest = normalise_breach(data)
    if latest is None:
        return False
    unchanged = local.lookup(latest["name"]) is not None and (latest.get("added_date") or "") <= newest
    if unchanged and state is not None:
        try:
            state.set("latestbreach_probe", {"checked_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "newest_added": newest})
        except Exception:  # noqa: BLE001 - never fail a run for the probe memo
            pass
    return unchanged


#: probe failures that only mean "could not tell": the normal refresh decides (never the kill switch,
#: the request cap or a policy refusal, which propagate)
_PROBE_FAILURES: tuple[type[BaseException], ...] = tuple(
    getattr(_http, n) for n in ("NetworkError", "HttpError", "Blocked", "RateLimited", "QuotaExceeded", "AuthRequired") if hasattr(_http, n)
)


def breach_catalog(ctx: Any, *, probe: bool = False) -> BreachCatalog:
    """THE shared HIBP catalogue (C3). Reads the dataset ``hibp_breaches.json`` through ``ctx.data``:
    a fresh local copy is used as is; an older one is refreshed (24 h TTL) and kept when the refresh
    fails (C2); with ``probe=True`` (the hibp_catalog module) a stale copy is first checked with the
    cheap ``/latestbreach`` probe. Raises DatasetError/DatasetUnavailable when no copy exists and
    none can be downloaded (the engine maps it to ERROR / UNAVAILABLE)."""
    data_view = ctx.data
    info = data_view.info(CATALOG_DATASET)
    origin = "dataset"
    if info.present and info.stale and probe:
        local_data = data_view.fetch_json(CATALOG_DATASET, ttl=10.0**12)
        local_info = data_view.info(CATALOG_DATASET)
        local = _catalog_from(local_data, local_info.sha256, "dataset (stale)", local_info.fetched_at)
        try:
            unchanged = len(local) >= MIN_BREACHES and _probe_unchanged(ctx, local)
        except _PROBE_FAILURES:
            unchanged = False  # the probe could not answer: fall back to the normal refresh (stale copy kept on failure)
        if unchanged:
            local.origin = "dataset (latestbreach: unchanged)"
            return local
    data = data_view.fetch_json(CATALOG_DATASET)
    info = data_view.info(CATALOG_DATASET)
    if info.stale:
        origin = "dataset (stale)"
    return _catalog_from(data, info.sha256 or hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest(), origin, info.fetched_at)


def data_classes(ctx: Any) -> list[str]:
    """HIBP data-class names (dataset ``hibp_dataclasses.json``); [] when unavailable."""
    try:
        data = ctx.data.fetch_json(DATACLASSES_DATASET)
    except DatasetError:
        return []
    return [_clean(x, 120) for x in data if isinstance(x, str) and x.strip()] if isinstance(data, list) else []


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class HibpCatalog(Module):
    name = "hibp_catalog"
    title = "Have I Been Pwned breach catalogue"
    description = (
        "Breaches of the service at a domain (answered locally from the HIBP catalogue dataset: this service was "
        "breached, not accounts at it) and the catalogue facts of a breach name; data CC BY 4.0, Have I Been Pwned."
    )
    category = "breach_leak"
    accepts = {T.DOMAIN, T.KEYWORD}
    tags = {"free"}
    reference = "https://haveibeenpwned.com/API/v3"
    notice = (
        "Data: Have I Been Pwned (https://haveibeenpwned.com/), CC BY 4.0. A domain result means the service at that "
        "domain was breached - never that accounts at the domain were. Sensitive breaches show as 'sensitive breach "
        "(name withheld)' by default (setting hibp_catalog_show_sensitive)."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # breach names unknown to the local copy go to /breach/{name}
    provider = "hibp"
    sources = (SRC_CATALOG, SRC_DATACLASSES)
    hosts = ("haveibeenpwned.com",)
    access_model = "free_noauth_unlimited"
    absent_statuses = frozenset({404})  # /breach/{name}: 'Not found' = no breach of that name in HIBP
    max_requests = 2  # /latestbreach probe + /breach/{name}; the catalogue itself is a dataset
    expected_latency = 1.0
    timeout = 120.0  # a cold catalogue download (1.1 MB) is sanitized before it is stored
    min_interval = 1.0
    cache_ttl = DAY
    default_enabled = True
    max_pivots = 0
    settings = {"hibp_catalog_show_sensitive": False}

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        show = bool(ctx.setting("hibp_catalog_show_sensitive", False))
        if entity.type is T.KEYWORD:
            return self._breach_name(res, entity.value, ctx, show)
        return self._domain(res, entity.value, ctx, show)

    # ------------------------------------------------------------------ domain: local lookup (C2, C6)
    def _domain(self, res: ModuleResult, value: str, ctx: Any, show: bool) -> ModuleResult:
        catalog = breach_catalog(ctx, probe=True)
        if len(catalog) < MIN_BREACHES:
            return res.mark("error", f"HIBP catalogue copy has only {len(catalog)} breaches: could not verify")
        domain = value.lower()
        matched_domain = domain
        breaches = catalog.for_domain(domain)
        reg = psl.registrable_domain(domain)
        if not breaches and reg and reg != domain:
            breaches, matched_domain = catalog.for_domain(reg), reg
        wording = DOMAIN_WORDING.format(domain=matched_domain)
        res.raw = {SRC_CATALOG: [catalog.raw[b["key"]] for b in breaches if b["key"] in catalog.raw][:MAX_LISTED]}
        if not breaches:
            return res  # the full catalogue was searched: no breach of this service (EMPTY)
        views = [public_view(b, show) for b in breaches[:MAX_LISTED]]
        res.link("Have I Been Pwned (CC BY 4.0)", ATTRIBUTION_URL)  # C7: attribution wherever results are shown
        res.attr("service_breaches", [{"wording": wording, **v} for v in views])
        counted = [b for b in breaches if b["counts_as_exposure"]]
        res.attr("breach_count", len(counted))
        res.attr("breach_data_classes", sorted({c for b in counted for c in b["data_classes"]}))
        for b, view in zip(breaches[:MAX_LISTED], views):
            self._breach_finding(res, b, view, matched_domain, catalog, show)
        return res

    def _breach_finding(self, res: ModuleResult, b: dict[str, Any], view: dict[str, Any], domain: str, catalog: BreachCatalog, show: bool) -> None:
        verified = b["is_verified"]
        excluded = not b["counts_as_exposure"]
        title = "HIBP: this service was breached" if not excluded else "HIBP: spam list or fabricated breach (not exposure)"
        details = [
            f"{view['title']} ({b.get('breach_date') or 'date unknown'})",
            DOMAIN_WORDING.format(domain=domain),
        ]
        if b.get("pwn_count") is not None:
            details.append(f"{b['pwn_count']:,} accounts in the breach")
        if b["data_classes"]:
            details.append("data classes: " + ", ".join(b["data_classes"][:20]))
        if b.get("password_form"):
            details.append(f"password form: {b['password_form']}")
        if excluded:
            details.append("IsSpamList/IsFabricated: never counts as exposure")
        tags = ["breach", "context_only"] if excluded else ["breach"]
        references = [ATTRIBUTION_URL]
        if not view["sensitive"] or show:
            references.append(BREACH_PAGE.format(name=quote(b["name"], safe="")))
        res.finding(
            title,
            "info" if excluded or not verified else "low",
            ". ".join(details) + ". Source: Have I Been Pwned (CC BY 4.0).",
            confidence="possible" if excluded else ("confirmed" if verified else "possible"),
            criterion=f"HIBP catalogue entry whose Domain is {domain} ({'verified' if verified else 'unverified'} breach): this service was breached, not accounts at this domain",
            data={k: view[k] for k in ("title", "breach_date", "pwn_count", "data_classes", "password_form", "category", "sensitive", "is_verified", "is_spam_list", "is_fabricated", "is_stealer_log")},
            tags=tags,
            references=references,
            source=SRC_CATALOG,
            observed_first=b.get("breach_date"),
            key=b["key"],
        )

    # ------------------------------------------------------------------ keyword: a breach name
    def _breach_name(self, res: ModuleResult, name: str, ctx: Any, show: bool) -> ModuleResult:
        key = normalise_breach_name(name)
        if not key or len(name) > 120:
            return res.mark("skipped", "not a breach name", reason_code="not_applicable")
        catalog = breach_catalog(ctx, probe=True)
        breach = catalog.lookup(name)
        obj = catalog.raw.get(breach["key"]) if breach else None
        if breach is None:
            data = ctx.http.get_json(BREACH_URL.format(name=quote(name.strip(), safe="")), source=SRC_CATALOG)
            if data is None:  # 404: HIBP has no breach of that name (documented absence)
                return res
            breach = normalise_breach(data)
            if breach is None:
                return res.mark("error", "unexpected HIBP answer (no breach Name): could not verify")
            obj = {k: data[k] for k in BREACH_FIELDS if k in data}
        view = public_view(breach, show)
        res.raw = {SRC_CATALOG: obj or {}}
        res.link("Have I Been Pwned (CC BY 4.0)", ATTRIBUTION_URL)  # C7
        res.attr("breach_metadata", view)
        res.attr("breach_data_classes", list(breach["data_classes"]))
        flags = [label for key_, label in (("is_verified", "verified"), ("is_fabricated", "fabricated"), ("is_spam_list", "spam list"), ("is_stealer_log", "stealer log"), ("is_sensitive", "sensitive")) if breach.get(key_)]
        references = [ATTRIBUTION_URL]
        if not view["sensitive"] or show:
            references.append(BREACH_PAGE.format(name=quote(breach["name"], safe="")))
        res.finding(
            "HIBP breach catalogue entry",
            "info",
            f"{view['title']}: breach date {breach.get('breach_date') or 'unknown'}, added {breach.get('added_date') or 'unknown'}"
            + (f", {breach['pwn_count']:,} accounts" if breach.get("pwn_count") is not None else "")
            + (f", password form {breach['password_form']}" if breach.get("password_form") else "")
            + (f", flags: {', '.join(flags)}" if flags else "")
            + ". Source: Have I Been Pwned (CC BY 4.0).",
            confidence="confirmed" if breach["is_verified"] else "possible",
            criterion="HIBP breach catalogue (keyless /breaches dataset or /breach/{name})",
            data={k: view[k] for k in ("breach_date", "pwn_count", "data_classes", "password_form", "category", "sensitive", "counts_as_exposure")},
            tags=["breach"] if breach["counts_as_exposure"] else ["breach", "context_only"],
            references=references,
            source=SRC_CATALOG,
            observed_first=breach.get("breach_date"),
        )
        return res
