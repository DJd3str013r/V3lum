"""Leak-Lookup PUBLIC-key search: breach NAMES listing an e-mail address, username or own domain (P140).

**Only** ``POST https://leak-lookup.com/api/search`` with the company-registered PUBLIC key in the form
body (cond 1): :func:`leaklookup_request` is the single request builder and :func:`leaklookup_form_allowed`
the type allow-list the module checks before every request. The private/records tier is never subscribed
to or wired: no builder exists for it, a record-bearing answer is refused (fail closed) and the P145
schema of ``leaklookup.search`` empties record lists before the module ever sees them.

* Key (cond 1): one canonical key ``leaklookup`` (env aliases ``V3LUM_LEAKLOOKUP_KEY`` and
  ``V3LUM_LEAKLOOKUP_PUBLIC_KEY``, provider fragment ``leaklookup.json``), sent in the POST body only;
  without it the run is NEEDS_KEY before any request. Key-terms: legal records the plan before it runs
  under the corporate profile (``key_plans.leaklookup``).
* Types (cond 2): ``email_address``, ``domain`` and ``username`` only - ``password``, ``hash``,
  ``ipaddress``, ``phone`` and ``fullname`` can never be built. Only breach names are kept; names of
  sensitive services (HIBP IsSensitive, or a sensitive-category word for names the catalogue does not
  know) read 'sensitive breach (name withheld)'.
* Error-in-200 (cond 3): ``{'error':'true','message':...}`` bodies are classified by the provider error
  markers BEFORE parsing - 'REQUEST LIMIT REACHED' -> QUOTA (the provider is stopped for the UTC day),
  'RATE LIMIT REACHED' -> RATE_LIMITED, API-key refusals and any other error -> ERROR; an error body
  that reached the module anyway is ERROR too. Never EMPTY. The public plan's 10 daily searches and
  5 per minute are the P334 quota block of the provider (80% budget).
* Catalogue and merge (cond 4): names go through the shared HIBP catalogue helper (P132,
  ``hibp_catalog.breach_catalog``) for dates, data classes and flags, and every per-breach finding
  carries ``data['breach_key']``; the correlation rule ``p3g042_leaklookup_breach_merge``
  (``v3lum/correlations/p3_g04_2.py``) folds it into the HIBP/XposedOrNot/LeakCheck finding of the same
  breach (one breach, one scored finding).
* Scope (cond 5, A4): ``run_on='own_assets'``: addresses on verified org-profile domains, or
  analyst-typed seeds with ``--breach-scope all`` and ``--purpose`` (context only, at most MEDIUM);
  usernames only as such seeds; domain queries only for verified own domains (Leak-Lookup's terms
  forbid 'Mass-Domain queries of unauthorized domains'). Generic, role and test addresses are flagged,
  capped at POSSIBLE and never scored.
* cond 6: ``default_enabled=False``; the success fixtures follow the documented public answer
  (``{"error": "false", "message": {"<breach>": []}}``, leak-lookup.com/docs/search) until a trimmed
  real answer is captured with the company public key (backlog p3-G04-2).
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from v3lum.core.datasets import DatasetError, DatasetUnavailable
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.breach_leak.breach_accounts import (
    LGPD_NOTE,
    NEVER_TESTED,
    Listing,
    breach_domain,
    breach_scope,
    emit_listings,
    enrich,
    flags_from_name,
    generic_kind,
    today_of,
)
from v3lum.modules.breach_leak.hibp_catalog import SRC_CATALOG, breach_catalog, breach_category

__all__ = [
    "FORBIDDEN_TYPES",
    "KEY_NAME",
    "SEARCH_URL",
    "SRC_SEARCH",
    "TYPES",
    "LeakLookupPublic",
    "leaklookup_form_allowed",
    "leaklookup_request",
    "parse_leaklookup",
    "sensitive_breach_name",
]

SRC_SEARCH = "leaklookup.search"
KEY_NAME = "leaklookup"
HOST = "leak-lookup.com"
SEARCH_URL = "https://leak-lookup.com/api/search"
#: cond 2: entity type -> Leak-Lookup search type (the allow-list)
TYPES = {T.EMAIL: "email_address", T.DOMAIN: "domain", T.USERNAME: "username"}
#: documented search types V3LUM never builds (cond 2)
FORBIDDEN_TYPES = frozenset({"password", "hash", "ipaddress", "ipadress", "phone", "fullname"})
ATTRIBUTION_URL = "https://leak-lookup.com/"
ABSENT_TEXT = "not found in Leak-Lookup (public key: breach names)"
MAX_NAMES = 300
_USERNAME = re.compile(r"^[^\s@:/\\]{1,64}$")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_NAME_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,200}$")

# Sensitive-category fallback for names the HIBP catalogue does not know (P132 cond 4 categories:
# adult, dating, health, religion, sexual orientation, politics). Distinctive stems match anywhere
# ('adultfriendfinder'); short words only at the start of a token or as a whole token, so 'essex'
# and 'archive' stay readable. It masks more, never less.
_SENSITIVE_STEMS = (
    "adult", "porn", "escort", "fetish", "hentai", "camgirl", "onlyfans",
    "dating", "hookup", "swinger", "matchmak", "lesbian", "lgbt", "grindr", "queer", "transgender",
    "health", "medic", "clinic", "hospital", "pharma", "therapy", "dentist",
    "church", "bible", "relig", "islam", "muslim", "christian", "jewish", "catholic", "gospel",
    "politic", "election", "partido",
)
_SENSITIVE_TOKEN_PREFIXES = ("sex", "xxx", "gay", "nude")
_SENSITIVE_TOKENS = frozenset({"trans", "hiv", "aids", "dental", "fling", "affair"})


def _fold(text: str) -> str:
    text = unicodedata.normalize("NFKD", text)
    return "".join(c for c in text if not unicodedata.combining(c)).lower()


def sensitive_breach_name(name: Any) -> bool:
    """True when a breach (or bucket) name reveals a sensitive service category (LGPD art. 11):
    the shared HIBP keyword table (``hibp_catalog.breach_category``) or the stem fallback above."""
    if not isinstance(name, str) or not name.strip():
        return False
    try:
        if breach_category({"Name": name, "Title": name}):
            return True
    except Exception:  # noqa: BLE001 - the fallback below still decides
        pass
    low = _fold(name)
    if any(stem in low for stem in _SENSITIVE_STEMS):
        return True
    tokens = [t for t in re.split(r"[^a-z0-9]+", low) if t]
    return any(t.startswith(_SENSITIVE_TOKEN_PREFIXES) or t in _SENSITIVE_TOKENS for t in tokens)


def _domain(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().lower().rstrip(".")
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = text.split(".")
    if len(text) > 253 or len(labels) < 2 or not all(_LABEL.match(x) for x in labels) or labels[-1].isdigit():
        return None
    return text


def _email(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    if v.count("@") != 1 or any(c.isspace() for c in v):
        return None
    local, dom = v.split("@")
    dom_ok = _domain(dom)
    if not local or len(local) > 64 or dom_ok is None:
        return None
    return f"{local}@{dom_ok}"


def leaklookup_request(etype: Any, value: Any, key: Any) -> dict[str, Any]:
    """{'url', 'form'} of the ONE request V3LUM sends (cond 1-2); ValueError outside the allow-list.

    The key travels only in the form body (never in the URL); the type comes from :data:`TYPES`."""
    api_type = TYPES.get(etype) if isinstance(etype, T) else None
    if api_type is None or api_type in FORBIDDEN_TYPES:
        raise ValueError(f"Leak-Lookup type not allow-listed: {etype!r} (P140 cond 2)")
    key = key.strip() if isinstance(key, str) else ""
    if not key or any(c in key for c in "\r\n\t &="):
        raise ValueError("Leak-Lookup public key missing or malformed")
    if etype is T.EMAIL:
        query = _email(value)
    elif etype is T.DOMAIN:
        query = _domain(value)
    else:
        query = value.strip() if isinstance(value, str) and _USERNAME.match(value.strip()) else None
    if not query:
        raise ValueError(f"unusable Leak-Lookup query for type {api_type}")
    return {"url": SEARCH_URL, "form": {"key": key, "type": api_type, "query": query}}


def leaklookup_form_allowed(form: Any) -> bool:
    """Type allow-list checked before every request (cond 2): exactly key/type/query, type allowed."""
    if not isinstance(form, dict) or set(form) != {"key", "type", "query"}:
        return False
    return form.get("type") in set(TYPES.values()) and form.get("type") not in FORBIDDEN_TYPES


def _flag(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


def parse_leaklookup(data: Any) -> dict[str, Any]:
    """Sanitized public answer -> {state ok|absent|error|private, names, error} (cond 2-3).

    ``message`` is a dict of breach names (values: empty lists in the public tier) or a list of names.
    A non-empty value under a name is a private-tier record list (refused: fail closed, cond 1)."""
    out: dict[str, Any] = {"state": "error", "names": [], "error": ""}
    if not isinstance(data, dict):
        out["error"] = "answer is not a JSON object"
        return out
    err = _flag(data.get("error"))
    if err is None:
        out["error"] = "answer without an error flag"
        return out
    if err:
        out["error"] = "error 'true'"
        return out
    msg = data.get("message")
    names: list[str] = []
    if isinstance(msg, dict):
        for name, value in msg.items():
            if isinstance(value, list) and value:
                out["state"] = "private"
                out["error"] = "the answer carries record lists (private tier): V3LUM uses the public key only"
                return out
            if not isinstance(value, list):
                out["error"] = "unexpected message shape"
                return out
            names.append(name)
    elif isinstance(msg, list):
        for name in msg:
            if not isinstance(name, str):
                out["state"] = "private"
                out["error"] = "the answer carries records instead of breach names: refused"
                return out
            names.append(name)
    elif msg in (None, "", {}):
        names = []
    else:
        out["error"] = "unexpected message shape"
        return out
    clean = []
    seen: set[str] = set()
    for name in names:
        text = " ".join(str(name).split())
        if not text or not _NAME_RE.match(text) or text.lower() in seen:
            continue
        seen.add(text.lower())
        clean.append(text)
        if len(clean) >= MAX_NAMES:
            break
    out["names"] = sorted(clean, key=lambda n: (n.lower(), n))
    out["state"] = "ok" if clean else "absent"
    return out


@register
class LeakLookupPublic(Module):
    name = "leak_lookup_public"
    title = "Leak-Lookup public key (breach names)"
    description = (
        "Breach NAMES that list an e-mail address, username or verified own domain, from Leak-Lookup's search API "
        "with the company's PUBLIC key (the records tier is never used); joined to the shared HIBP catalogue."
    )
    category = "breach_leak"
    accepts = {T.EMAIL, T.DOMAIN, T.USERNAME}
    run_on = "own_assets"
    tags = {"breach"}
    reference = "https://leak-lookup.com/docs/search"
    notice = (
        "Key-terms: legal records the company public-key plan before it runs under the corporate profile (default off). "
        "Public key only: breach names, never records or passwords; type 'password' is never used. Leak-Lookup's terms "
        "allow searches only for the organisation's own data or written-authorised subjects. " + LGPD_NOTE
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # Leak-Lookup receives the address, handle or domain
    provider = "leaklookup"
    sources = (SRC_SEARCH, SRC_CATALOG)
    hosts = (HOST,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,)
    max_requests = 1
    expected_latency = 2.0
    timeout = 40.0  # one paced slot of the provider bucket (5/min at 80% = 15 s) must fit
    min_interval = 12.0  # documented 5 requests per minute
    cache_ttl = 0  # no-store: the key travels in the POST body
    max_pivots = 0
    default_enabled = False  # cond 6 (P3, key-terms)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        allowed = getattr(ctx, "allowed_sources", None)
        if allowed is not None and SRC_SEARCH not in allowed:
            return res.mark("skipped", "Leak-Lookup terms not cleared under this licence profile", reason_code="licence")
        if entity.type is T.DOMAIN:
            # Leak-Lookup's terms forbid 'Mass-Domain queries of unauthorized domains' (own domains only)
            if not _verified_domain(ctx, entity.value):
                return res.mark("skipped", "Leak-Lookup domain search: own verified domains only (v3lum org verify)", reason_code="own_asset")
            own = True
        else:
            own, why = breach_scope(entity, ctx)
            if why:
                return res.mark("skipped", why, reason_code="privacy")
        try:
            req = leaklookup_request(entity.type, entity.value, ctx.key(KEY_NAME))
        except ValueError as exc:
            if "key" in str(exc):
                return res.mark("needs_key", "Leak-Lookup public key missing or malformed (v3lum keys set leaklookup)")
            return res.mark("skipped", f"value not usable for a Leak-Lookup {TYPES.get(entity.type, '?')} search", reason_code="not_applicable")
        if not leaklookup_form_allowed(req["form"]):  # cond 2: checked before every request
            return res.mark("skipped", "Leak-Lookup search type outside the allow-list", reason_code="policy")
        try:
            data = ctx.http.post_json(req["url"], data=req["form"], source=SRC_SEARCH, allow_redirects=False)
        except ValueError:
            return res.mark("error", "Leak-Lookup answered something that is not JSON: could not verify")
        parsed = parse_leaklookup(data)
        if parsed["state"] in ("error", "private"):
            return res.mark("error", f"Leak-Lookup: {parsed['error']}: could not verify")
        res.raw = {SRC_SEARCH: {"error": "false", "message": []}}
        if parsed["state"] == "absent":
            res.presence("absent", marker=f"error 'false' with no breach names: {ABSENT_TEXT}", checked_at=ctx.now(), source=SRC_SEARCH)
            res.error = ABSENT_TEXT
            return res.mark("empty")
        res.link("Leak-Lookup (public API, breach names only)", ATTRIBUTION_URL)
        catalog = self._catalogue(res, ctx)
        listings = [self._listing(name, catalog) for name in parsed["names"]]
        # evidence keeps the names as shown: sensitive-category names stay masked there too (cond 2)
        res.raw = {SRC_SEARCH: {"error": "false", "message": sorted({li.shown_name() for li in listings})}}
        if entity.type is T.DOMAIN:
            self._emit_domain(res, listings, today_of(ctx))
            return res
        generic = generic_kind(entity)
        emit_listings(res, listings, provider_label="Leak-Lookup", own=own, generic=generic, today=today_of(ctx),
                      references=[ATTRIBUTION_URL],
                      summary_extra="Leak-Lookup public key: breach names only (no dates or data classes from the provider).")
        return res

    @staticmethod
    def _listing(name: str, catalog: Any) -> Listing:
        hints = flags_from_name(name)
        li = Listing(name=name, source=SRC_SEARCH, domain=breach_domain(name),
                     compilation=hints["compilation"] or None, stealer_log=hints["stealer_log"] or None)
        li = enrich(li, catalog)
        if not li.catalogue and sensitive_breach_name(name):
            li.sensitive = True  # cond 2: a sensitive-category name the catalogue does not know stays masked
        return li

    @staticmethod
    def _emit_domain(res: ModuleResult, listings: list[Listing], today: Any) -> None:
        """Own-domain mode: breaches that list addresses AT the domain (names only, one summary finding)."""
        merged: dict[str, Listing] = {}
        for li in listings:
            if li.key and li.key not in merged:
                merged[li.key] = li
        items = sorted(merged.values(), key=lambda li: (li.date or "0000", li.key), reverse=True)
        counted = [li for li in items if li.counted]
        res.attr("breach_records", [li.record() for li in items])
        res.attr("breaches", sorted({li.shown_name() for li in items}))
        res.attr("breach_count", len(counted))
        res.attr("breach_data_classes", sorted({c for li in counted for c in li.shown_classes()}))
        dates = sorted(li.date for li in counted if li.date)
        if dates:
            res.attr("first_seen_breach", dates[0])
        passwords = [li for li in counted if li.passwords]
        severity = "medium" if passwords else ("low" if counted else "info")
        names = [li.shown_name() for li in counted][:15]
        res.finding(
            "Addresses at the own domain listed in breaches (Leak-Lookup)",
            severity,
            f"Leak-Lookup lists addresses at this verified own domain in {len(counted)} breach(es)"
            + (f": {', '.join(names)}" + (" ..." if len(counted) > len(names) else "") if names else "")
            + (f"; {len(passwords)} with passwords in the data classes (HIBP catalogue)" if passwords else "")
            + ". Names only: which addresses are affected is not disclosed by the public key; check each address with "
            "the per-address breach modules. " + NEVER_TESTED,
            confidence="possible",
            criterion="Leak-Lookup public-key domain search on a verified own domain: breach names only, "
            + ("passwords among the catalogue data classes" if passwords else "no password data class known"),
            data={"breaches": [li.record() for li in items][:100], "counted": len(counted), "high_risk_breaches": len(passwords),
                  "breach_keys": [li.shown_key() for li in items][:100]},
            tags=["breach", "privacy", "own_asset"],
            references=[ATTRIBUTION_URL],
            source=SRC_SEARCH,
            observed_first=dates[0] if dates and len(dates[0]) == 10 else None,
        )

    @staticmethod
    def _catalogue(res: ModuleResult, ctx: Any) -> Any:
        allowed = getattr(ctx, "allowed_sources", None)
        if allowed is not None and SRC_CATALOG not in allowed:
            return None
        try:
            return breach_catalog(ctx)
        except (DatasetError, DatasetUnavailable) as exc:
            code = "dataset" if isinstance(exc, DatasetUnavailable) else "error"
            status = "unavailable" if code == "dataset" else "error"
            res.source_status(SRC_CATALOG, status, reason_code=code, reason="HIBP catalogue unavailable: Leak-Lookup names not enriched")
            return None


def _verified_domain(ctx: Any, domain: str) -> bool:
    org = getattr(ctx, "org", None)
    if org is None:
        return False
    try:
        return bool(org.is_verified_domain(domain))
    except Exception:  # noqa: BLE001 - an unreadable profile owns nothing
        return False

