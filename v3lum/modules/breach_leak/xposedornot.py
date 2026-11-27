"""XposedOrNot: breach names per e-mail, breach analytics, the breach catalogue and own-domain
breaches (P137). Three modules share this file (one source family):

* ``xposedornot`` (e-mail, ``run_on='own_assets'``): keyless ``GET /v1/check-email/{email}`` (the
  lower-cased, URL-encoded address), then ``GET /v1/breach-analytics?email=`` only when it is listed.
  A never-seen address answers HTTP 200 ``{'Error': 'Not found'}`` (live 2026-11-26) or a 404 (research
  2026-11-25): both are the declared absence 'not found in XposedOrNot'. Breach ids are joined offline
  with the daily catalogue dataset ``xposedornot_breaches.json`` (sensitive flag, type, dates) and the
  shared HIBP catalogue of the P132 helper (canonical names, flags), then merged with HIBP/LeakCheck per
  normalised name through ``p2g04_breach_merge`` (cond 7).
* ``xposedornot_domain`` (domain, offline): the catalogue dataset answers 'was this SERVICE breached'
  for a domain (cond 2: never 'accounts at this domain'); the domain is never sent anywhere.
* ``xposedornot_domain_breaches`` (domain, ``run_on='own_assets_only'``, key ``xon``): ``POST
  /v1/domain-breaches/`` with ``x-api-key`` for txt_verified/attested own domains only (cond 2, A11
  BR4), because it returns employees' addresses (access restricted to the case; they are listed as
  analyst-selected pivots only, ``expand=False``).

Terms (cond 1, A1 BR15): keyless XposedOrNot is ``noncommercial`` ('Commercial use of our data requires
a proper licensing agreement', verified 2026-11-26): off under the corporate profile until
licence-cleared, keyless use only through licence_allow or the research profile (coverage then reads
'licence', never empty). Own-domain monitoring is xonEnterprise+ (``key-terms``, key_plans.xon =
'business'). Limits (cond 4): 2 req/s, 25/hour, 100/day per egress IP - the provider quota block
(P334 windows) and ``min_interval`` 0.5 s; exhaustion is RATE_LIMITED/QUOTA with the key hint.
Metadata only (cond 5): the P145 schemas of the provider fragment apply before the HTTP cache and the
dataset copy; sensitive breaches are masked; logos (external images) are never loaded. Generic
addresses (test@example.com lists 216 breaches) follow the A4 generic rule (one INFO summary).
401 ``{'detail': 'Invalid or missing API key'}`` is NEEDS_KEY (cond 8).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from v3lum.core import psl
from v3lum.core.datasets import DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.breach_leak.breach_accounts import (
    LGPD_NOTE,
    SENSITIVE_LABEL,
    SPECIAL_CATEGORY_CLASSES,
    Listing,
    bool_or_none,
    breach_key,
    breach_scope,
    emit_listings,
    enrich,
    flags_from_name,
    generic_kind,
    int_or_none,
    masked_key,
    norm_date,
    normalise_data_classes,
    normalise_email,
    safe_form,
    str_or_none,
    today_of,
)
from v3lum.modules.breach_leak.hibp_catalog import SRC_CATALOG, breach_catalog

PROVIDER = "xposedornot"
SRC_API = "xposedornot.api"
SRC_CATALOGUE = "xposedornot.catalogue"
SRC_DOMAIN_BREACHES = "xposedornot.domain_breaches"
HOST = "api.xposedornot.com"
API = f"https://{HOST}/v1"
CHECK_URL = API + "/check-email/{email}"  # v3lum-lint: allow LINT-03 -- XposedOrNot breach-name lookup (breach metadata of an address), not account enumeration, sign-up/reset or mailbox verification
ANALYTICS_URL = API + "/breach-analytics"
CATALOGUE_URL = API + "/breaches"
DOMAIN_BREACHES_URL = API + "/domain-breaches/"
ATTRIBUTION = "XposedOrNot"
ATTRIBUTION_URL = "https://xposedornot.com/"
ABSENT_TEXT = "not found in XposedOrNot"
SERVICE_WORDING = "breaches of the service at {domain} (this service was breached) - not accounts at this domain"
KEY_HINT = "XposedOrNot keyless limit (2/s, 25/h, 100/day per IP): a xonAPI+ licence lifts it"
MIN_CATALOGUE = 300
MAX_DOMAIN_PIVOTS = 100
CATALOGUE_DATASET = "xposedornot_breaches.json"


def _validate_catalogue(path: Path) -> bool:
    """AR10 ``validate=``: an error body or a truncated list never replaces the local copy."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (ValueError, OSError) as exc:
        raise DatasetError(f"XposedOrNot catalogue is not valid JSON ({type(exc).__name__})")
    items = data.get("exposedBreaches") if isinstance(data, dict) else data
    count = sum(1 for b in items if isinstance(b, dict) and isinstance(b.get("breachID"), str)) if isinstance(items, list) else 0
    if count < MIN_CATALOGUE:
        raise DatasetError(f"XposedOrNot catalogue has only {count} breaches (expected >= {MIN_CATALOGUE})")
    return True


register_dataset(
    CATALOGUE_DATASET,
    CATALOGUE_URL,
    ttl=86400,
    description="XposedOrNot breach catalogue (/v1/breaches, ~645 KB, sanitized: metadata only, logos dropped)",
    licence="XposedOrNot terms: free API for personal and low-volume use; commercial use requires a licensing agreement",
    terms_class="noncommercial",
    attribution="XposedOrNot (https://xposedornot.com)",
    provider=PROVIDER,
    source=SRC_CATALOGUE,
    validate=_validate_catalogue,
    min_bytes=2_000,
    expect="json",
    max_bytes=5_000_000,
)


# --------------------------------------------------------------------------------------
# parsers (untrusted data: wrong types never raise)
# --------------------------------------------------------------------------------------


def _risk_form(item: dict[str, Any], *keys: str) -> str | None:
    """Password FORM from XposedOrNot's password risk (the core sanitizer may already have renamed the
    field to ``password_form``): 'plaintext' means the service stored passwords in clear."""
    for key in ("password_form", *keys):
        form = safe_form(item.get(key))
        if form:
            return form
    return None


def parse_check_email(data: Any) -> dict[str, Any]:
    """check-email -> {ok, found, breaches (flattened ids)}; {'Error': 'Not found'} -> found False."""
    out: dict[str, Any] = {"ok": isinstance(data, dict), "found": False, "breaches": []}
    if not isinstance(data, dict):
        return out
    seen: list[str] = []

    def walk(value: Any, depth: int = 0) -> None:
        if depth > 3:
            return
        if isinstance(value, str) and value.strip():
            name = value.strip()[:200]
            if name not in seen:
                seen.append(name)
        elif isinstance(value, list):
            for v in value[:2000]:
                walk(v, depth + 1)

    walk(data.get("breaches"))
    out["breaches"] = seen
    out["found"] = bool(seen)
    return out


def parse_analytics(data: Any) -> dict[str, Any]:
    """breach-analytics -> per-breach metadata, risk {label, score}, paste count (logos, descriptions
    and reference links are ignored). ExposedBreaches null = nothing more than check-email."""
    out: dict[str, Any] = {"ok": isinstance(data, dict), "breaches": [], "risk": None, "pastes": 0}
    if not isinstance(data, dict):
        return out
    exposed = data.get("ExposedBreaches") if isinstance(data.get("ExposedBreaches"), dict) else {}
    details = exposed.get("breaches_details") if isinstance(exposed.get("breaches_details"), list) else []
    for item in details[:2000]:
        if not isinstance(item, dict):
            continue
        name = str_or_none(item.get("breach"), 200)
        if not name:
            continue
        out["breaches"].append({
            "name": name,
            "domain": (str_or_none(item.get("domain"), 253) or "").lower() or None,
            "year": norm_date(item.get("xposed_date")),
            "records": int_or_none(item.get("xposed_records")),
            "data_classes": normalise_data_classes(item.get("xposed_data")),
            "password_form": _risk_form(item, "password_risk"),
            "verified": bool_or_none(item.get("verified")),
        })
    metrics = data.get("BreachMetrics") if isinstance(data.get("BreachMetrics"), dict) else {}
    risk = metrics.get("risk")
    risk = risk[0] if isinstance(risk, list) and risk and isinstance(risk[0], dict) else risk
    if isinstance(risk, dict) and (risk.get("risk_label") or risk.get("risk_score") is not None):
        out["risk"] = {"label": str_or_none(risk.get("risk_label"), 40), "score": int_or_none(risk.get("risk_score"))}
    pastes = data.get("PastesSummary") if isinstance(data.get("PastesSummary"), dict) else {}
    out["pastes"] = int_or_none(pastes.get("cnt")) or 0
    return out


def parse_catalogue(data: Any) -> list[dict[str, Any]]:
    """The /v1/breaches catalogue (full answer or a bare list) -> metadata records (logos dropped)."""
    items = data.get("exposedBreaches") if isinstance(data, dict) else data
    out: list[dict[str, Any]] = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        bid = str_or_none(item.get("breachID"), 200)
        if not bid:
            continue
        btype = str_or_none(item.get("breachType"), 40) or ""
        out.append({
            "id": bid,
            "key": breach_key(bid),
            "date": (norm_date(item.get("breachedDate")) or "")[:7] or None,  # month precision upstream (day always 01)
            "added": norm_date(item.get("addedDate")),
            "domain": (str_or_none(item.get("domain"), 253) or "").lower().rstrip(".") or None,
            "industry": str_or_none(item.get("industry"), 80),
            "data_classes": normalise_data_classes(item.get("exposedData")),
            "records": int_or_none(item.get("exposedRecords")),
            "password_form": _risk_form(item, "passwordRisk"),
            "sensitive": bool_or_none(item.get("sensitive")),
            "verified": bool_or_none(item.get("verified")),
            "stealer_log": btype.lower() == "stealerlogs" or None,
            "compilation": btype.lower() == "combolist" or None,
        })
    return out


class XonCatalogue:
    """Index of the XposedOrNot catalogue by breach id, normalised key and service domain."""

    def __init__(self, records: list[dict[str, Any]]) -> None:
        self.records = records
        self.by_id = {r["id"].lower(): r for r in records}
        self.by_key: dict[str, dict[str, Any]] = {}
        self.by_domain: dict[str, list[dict[str, Any]]] = {}
        for r in records:
            if r["key"]:
                self.by_key.setdefault(r["key"], r)
            if r["domain"]:
                self.by_domain.setdefault(r["domain"], []).append(r)

    def __len__(self) -> int:
        return len(self.records)

    def lookup(self, name: str) -> dict[str, Any] | None:
        return self.by_id.get(name.lower()) or self.by_key.get(breach_key(name))

    def for_domain(self, domain: str) -> list[dict[str, Any]]:
        d = domain.lower().rstrip(".")
        d = d[4:] if d.startswith("www.") else d
        return sorted(self.by_domain.get(d, []), key=lambda r: (r.get("date") or "", r["id"]))


def load_xon_catalogue(ctx: Any) -> XonCatalogue:
    """The daily catalogue dataset (raises DatasetError/DatasetUnavailable when no copy exists)."""
    return XonCatalogue(parse_catalogue(ctx.data.fetch_json(CATALOGUE_DATASET)))


def _listing(name: str, *, xon: dict[str, Any] | None, detail: dict[str, Any] | None) -> Listing:
    xon = xon or {}
    detail = detail or {}
    hints = flags_from_name(name)
    classes = detail.get("data_classes") or xon.get("data_classes") or []
    return Listing(
        name=name,
        source=SRC_API,
        date=xon.get("date") or detail.get("year"),
        domain=detail.get("domain") or xon.get("domain"),
        data_classes=list(classes),
        password_form=detail.get("password_form") or xon.get("password_form"),
        verified=detail.get("verified") if detail.get("verified") is not None else xon.get("verified"),
        stealer_log=xon.get("stealer_log") or hints["stealer_log"] or None,
        compilation=xon.get("compilation") or hints["compilation"] or None,
        sensitive=xon.get("sensitive"),
        records=detail.get("records") or xon.get("records"),
    )


def _catalogue_status(res: ModuleResult, source: str, exc: Exception) -> None:
    unavailable = isinstance(exc, DatasetUnavailable)
    res.source_status(source, "unavailable" if unavailable else "error", reason_code="dataset" if unavailable else "error",
                      reason=f"{source} catalogue unavailable: names not enriched ({type(exc).__name__})")


# --------------------------------------------------------------------------------------
# xposedornot: breach names per e-mail
# --------------------------------------------------------------------------------------


@register
class XposedOrNot(Module):
    name = "xposedornot"
    title = "XposedOrNot breaches of an e-mail address"
    description = (
        "Breach names listing an e-mail address (check-email, breach-analytics), joined offline with the XposedOrNot "
        "and HIBP catalogues: dates, data classes and the password form only; sensitive breaches masked."
    )
    category = "breach_leak"
    accepts = {T.EMAIL}
    run_on = "own_assets"
    tags = {"breach", "free"}
    reference = "https://xposedornot.com/api_doc"
    notice = (
        "XposedOrNot keyless data is noncommercial: off under the corporate profile until licence-cleared (licence_allow or "
        "the research profile); a xonAPI+ plan is needed for business use. Own-domain addresses by default; third parties "
        "only as typed seeds with --breach-scope all and --purpose. Attribution: XposedOrNot. " + LGPD_NOTE
    )
    terms = "noncommercial"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # XposedOrNot receives the address
    provider = PROVIDER
    sources = (SRC_API, SRC_CATALOGUE, SRC_CATALOG)
    hosts = (HOST,)
    access_model = "free_noauth_limited"
    absent_statuses = frozenset({404})  # research 2026-11-25: 404 = address not in XposedOrNot
    max_requests = 2  # check-email, then breach-analytics only when listed
    expected_latency = 1.0
    min_interval = 0.5  # 2 req/s (cond 4); hourly/daily windows in the provider quota block
    cache_ttl = 604800  # sanitized body, at most 7 days (A4)
    max_pivots = 0
    default_enabled = True  # licence-gated default candidate (A3 BR4)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        own, why = breach_scope(entity, ctx)
        if why:
            return res.mark("skipped", why, reason_code="privacy")
        email = normalise_email(entity.value)
        if email is None:
            return res.mark("skipped", "not a usable e-mail address", reason_code="not_applicable")
        allowed = getattr(ctx, "allowed_sources", None)
        if allowed is not None and SRC_API not in allowed:
            return res.mark("skipped", "XposedOrNot keyless terms are noncommercial: licence_allow entry needed", reason_code="licence")
        data = ctx.http.get_json(CHECK_URL.format(email=quote(email, safe="")), source=SRC_API)
        if data is not None and not isinstance(data, dict):
            return res.mark("error", "unexpected XposedOrNot answer (not a JSON object): could not verify")
        check = parse_check_email(data or {})
        raw: dict[str, Any] = {SRC_API: data or {}}
        res.raw = raw
        if not check["found"]:
            err = str((data or {}).get("Error") or "") if isinstance(data, dict) else ""
            if data is not None and "not found" not in err.lower():
                return res.mark("error", "XposedOrNot answer without breaches or a 'Not found' marker: could not verify")
            res.presence("absent", marker=f"{'HTTP 404' if data is None else 'Error: Not found'}: {ABSENT_TEXT}",
                         checked_at=ctx.now(), source=SRC_API)
            res.error = ABSENT_TEXT
            return res.mark("empty")
        analytics = parse_analytics(ctx.http.get_json(ANALYTICS_URL, params={"email": email}, source=SRC_API))
        details = {d["name"].lower(): d for d in analytics["breaches"]}
        xon = self._xon_catalogue(res, ctx)
        hibp = self._hibp_catalogue(res, ctx)
        names = list(check["breaches"])
        for d in analytics["breaches"]:
            if d["name"] not in names:
                names.append(d["name"])
        listings = [enrich(_listing(n, xon=xon.lookup(n) if xon else None, detail=details.get(n.lower())), hibp) for n in names]
        res.link(ATTRIBUTION, ATTRIBUTION_URL)
        generic = generic_kind(entity)
        emit_listings(res, listings, provider_label="XposedOrNot", own=own, generic=generic, today=today_of(ctx),
                      references=[ATTRIBUTION_URL])
        if analytics["risk"]:
            res.attr("breach_risk", {**analytics["risk"], "provider": "XposedOrNot",
                                     "note": "provider risk summary: context only" + ("" if own else "; third-party address: no exposure score")})
        if analytics["pastes"]:
            res.attr("paste_count", analytics["pastes"])
        return res

    @staticmethod
    def _xon_catalogue(res: ModuleResult, ctx: Any) -> XonCatalogue | None:
        allowed = getattr(ctx, "allowed_sources", None)
        if allowed is not None and SRC_CATALOGUE not in allowed:
            return None
        try:
            return load_xon_catalogue(ctx)
        except (DatasetError, DatasetUnavailable) as exc:
            _catalogue_status(res, SRC_CATALOGUE, exc)
            return None

    @staticmethod
    def _hibp_catalogue(res: ModuleResult, ctx: Any) -> Any:
        allowed = getattr(ctx, "allowed_sources", None)
        if allowed is not None and SRC_CATALOG not in allowed:
            return None
        try:
            return breach_catalog(ctx)
        except (DatasetError, DatasetUnavailable) as exc:
            _catalogue_status(res, SRC_CATALOG, exc)
            return None


# --------------------------------------------------------------------------------------
# xposedornot_domain: 'was this SERVICE breached' answered from the catalogue (offline)
# --------------------------------------------------------------------------------------


@register
class XposedOrNotDomain(Module):
    name = "xposedornot_domain"
    title = "XposedOrNot breaches of a service (catalogue)"
    description = (
        "Breaches OF the service at a domain from the XposedOrNot catalogue dataset, answered locally (the domain is never "
        "sent): this service was breached - never accounts at the domain."
    )
    category = "breach_leak"
    accepts = {T.DOMAIN}
    tags = {"breach"}
    reference = "https://xposedornot.com/api_doc"
    notice = (
        "Answered locally from the daily XposedOrNot catalogue (noncommercial terms: off under the corporate profile until "
        "licence-cleared). A result means the service at the domain was breached, not accounts at it."
    )
    terms = "noncommercial"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # the catalogue is a dataset: the domain never leaves the machine
    hosts = ()
    sources = (SRC_CATALOGUE,)
    access_model = "offline"
    default_enabled = True
    max_pivots = 0

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        catalogue = load_xon_catalogue(ctx)
        if len(catalogue) < 1:
            return res.mark("error", "XposedOrNot catalogue copy is empty: could not verify")
        domain = entity.value.lower().rstrip(".")
        matched = domain
        found = catalogue.for_domain(domain)
        reg = psl.registrable_domain(domain)
        if not found and reg and reg != domain:
            found, matched = catalogue.for_domain(reg), reg
        res.raw = {SRC_CATALOGUE: {"exposedBreaches": [
            {"breachID": r["id"], "breachedDate": r.get("date"), "domain": r.get("domain")} for r in found[:100] if not r.get("sensitive")
        ]}}
        if not found:
            return res  # the whole catalogue was searched: no breach of this service (EMPTY)
        wording = SERVICE_WORDING.format(domain=matched)
        views = []
        for r in found[:100]:
            masked = bool(r.get("sensitive"))
            classes = [c for c in r["data_classes"] if not (masked and c.lower() in SPECIAL_CATEGORY_CLASSES)]
            views.append({
                "name": SENSITIVE_LABEL if masked else r["id"],
                "breach_date": r.get("date"),
                "data_classes": classes,
                "records": r.get("records"),
                "password_form": r.get("password_form"),
                "sensitive": masked,
                "verified": r.get("verified"),
                "wording": wording,
            })
        res.attr("service_breach_records", views)
        res.link(ATTRIBUTION, ATTRIBUTION_URL)
        for r, v in zip(found[:100], views):
            verified = bool(r.get("verified"))
            details = [f"{v['name']} ({v['breach_date'] or 'date unknown'})", wording]
            if v["records"] is not None:
                details.append(f"{v['records']:,} records")
            if v["data_classes"]:
                details.append("data classes: " + ", ".join(v["data_classes"][:20]))
            if v["password_form"]:
                details.append(f"password form {v['password_form']}")
            res.finding(
                "XposedOrNot: this service was breached",
                "low" if verified else "info",
                ". ".join(details) + ". Source: XposedOrNot catalogue (metadata only).",
                confidence="probable" if verified else "possible",
                criterion=f"XposedOrNot catalogue entry whose domain is {matched} ({'verified' if verified else 'unverified'} breach): "
                "this service was breached, not accounts at this domain",
                data={k: v[k] for k in ("name", "breach_date", "data_classes", "records", "password_form", "sensitive", "verified")},
                tags=["breach"],
                references=[ATTRIBUTION_URL],
                source=SRC_CATALOGUE,
                key=masked_key(r["key"]) if v["sensitive"] else r["key"],
            )
        return res


# --------------------------------------------------------------------------------------
# xposedornot_domain_breaches: breached addresses of a verified own domain (keyed)
# --------------------------------------------------------------------------------------


def parse_domain_breaches(data: Any, domain: str) -> dict[str, Any] | None:
    """POST /v1/domain-breaches/ answer -> {addresses: {email: [breach, ...]}, breaches: {name: count},
    years} for ``domain`` (and its subdomains); None when the body has no ``metrics`` object."""
    if not isinstance(data, dict) or not isinstance(data.get("metrics"), dict):
        return None
    metrics = data["metrics"]
    details = metrics.get("Breaches_Details") if isinstance(metrics.get("Breaches_Details"), list) else []
    want = domain.lower().rstrip(".")
    addresses: dict[str, list[str]] = {}
    for item in details[:20000]:
        if not isinstance(item, dict):
            continue
        email = normalise_email(item.get("email"))
        breach = str_or_none(item.get("breach"), 200)
        dom = (str_or_none(item.get("domain"), 253) or (email.rsplit("@", 1)[-1] if email else "")).lower()
        if not email or not breach or not (dom == want or dom.endswith("." + want)):
            continue
        if not (email.endswith("@" + want) or email.endswith("." + want)):
            continue
        names = addresses.setdefault(email, [])
        if breach not in names:
            names.append(breach)
    breaches: dict[str, int] = {}
    for names in addresses.values():
        for n in names:
            breaches[n] = breaches.get(n, 0) + 1
    yearly = metrics.get("Yearly_Metrics") if isinstance(metrics.get("Yearly_Metrics"), dict) else {}
    years = {str(k): int_or_none(v) for k, v in yearly.items() if str(k).isdigit() and int_or_none(v) is not None}
    return {"addresses": addresses, "breaches": breaches, "years": years}


@register
class XposedOrNotDomainBreaches(Module):
    name = "xposedornot_domain_breaches"
    title = "XposedOrNot breached addresses of an own domain (key)"
    description = (
        "Breached addresses of a txt_verified/attested own domain from XposedOrNot domain-breaches (key 'xon', domain "
        "verified in the XposedOrNot account): breach names and counts; addresses listed for analyst selection only."
    )
    category = "breach_leak"
    accepts = {T.DOMAIN}
    produces = {T.EMAIL}
    run_on = "own_assets_only"
    tags = {"breach"}
    reference = "https://xposedornot.com/api_doc"
    notice = (
        "Own verified domains only (A11 BR4): it returns employees' addresses - case access only, never auto-expanded. "
        "Business use needs xonEnterprise+ recorded as key_plans.xon = 'business'. " + LGPD_NOTE
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # the key identifies the account whose verified domains XposedOrNot returns
    provider = PROVIDER
    sources = (SRC_DOMAIN_BREACHES,)
    hosts = (HOST,)
    access_model = "free_auth_limited"
    requires_keys = ("xon",)
    max_requests = 1
    expected_latency = 2.0
    min_interval = 0.5
    cache_ttl = 86400
    max_pivots = MAX_DOMAIN_PIVOTS
    default_enabled = True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        domain = entity.value.lower().rstrip(".")
        org = getattr(ctx, "org", None)
        try:
            verified = bool(org is not None and org.is_verified_domain(domain))
        except Exception:  # noqa: BLE001 - an unreadable profile verifies nothing
            verified = False
        if not verified:
            return res.mark("skipped", "domain-breaches only for txt_verified/attested own domains (A11 BR4)", reason_code="own_asset")
        key = ctx.key("xon")
        if not key:
            return res.mark("needs_key", "XposedOrNot domain-breaches needs the key 'xon' (account with the domain verified)")
        data = ctx.http.post_json(DOMAIN_BREACHES_URL, headers={"x-api-key": key}, source=SRC_DOMAIN_BREACHES, ttl=86400)
        parsed = parse_domain_breaches(data, domain)
        if parsed is None:
            return res.mark("error", "unexpected XposedOrNot domain-breaches answer (no metrics): could not verify")
        res.raw = {SRC_DOMAIN_BREACHES: data}
        addresses = parsed["addresses"]
        if not addresses:
            return res  # the account's verified domains list no breached address of this domain (EMPTY)
        breaches = sorted(parsed["breaches"].items(), key=lambda kv: (-kv[1], kv[0]))
        res.attr("own_domain_breaches", {
            "addresses": len(addresses),
            "breaches": [{"name": n, "addresses": c} for n, c in breaches[:200]],
            "years": parsed["years"],
            "provider": "XposedOrNot",
        })
        res.link(ATTRIBUTION, ATTRIBUTION_URL)
        for email in sorted(addresses)[:MAX_DOMAIN_PIVOTS]:
            res.pivot(T.EMAIL, email, "domain_breach_address", confidence="probable", expand=False,
                      note="own-domain address listed by XposedOrNot domain-breaches: analyst selection required")
        top = ", ".join(f"{n} ({c})" for n, c in breaches[:8])
        res.finding(
            "Own-domain addresses in breaches",
            "medium",
            f"{len(addresses)} address(es) of {domain} appear in {len(breaches)} breach(es): {top}. Next step: confirm the "
            "affected users changed their passwords and are not reusing them; enforce MFA. Breach metadata only; addresses are "
            "listed for analyst selection and never checked automatically.",
            confidence="probable",
            criterion="XposedOrNot domain-breaches for a txt_verified/attested own domain (key 'xon')",
            data={"addresses": len(addresses), "breaches": {n: c for n, c in breaches[:50]}},
            tags=["breach", "privacy", "own_asset"],
            references=[ATTRIBUTION_URL],
            source=SRC_DOMAIN_BREACHES,
        )
        return res
