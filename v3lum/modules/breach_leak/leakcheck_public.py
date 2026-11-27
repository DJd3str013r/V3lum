"""LeakCheck public API: breach source names and field NAMES for an e-mail or username (P135).

**Only** ``GET https://leakcheck.io/api/public?check=<value>`` (cond 3): :func:`leakcheck_public_url` is
the single URL builder and :func:`leakcheck_url_allowed` the allow-list the module checks before every
request. The authenticated v2 'lookup' API (raw records with passwords) is never implemented or
subscribed to: no builder or constant for it exists and a test asserts it cannot be built.

* Terms 'unknown' (cond 1, A1 BR16): ``default_enabled = False`` and every licence profile skips it
  until legal records LeakCheck's terms. osint_investigator's evidence (the LeakCheck API docs say the
  Public API is 'Free, including commercial use' with a 'Powered by LeakCheck' link) is queued for that
  review (cond 2); if cleared, the attribution :data:`ATTRIBUTION` goes into the report footer and
  ``v3lum info`` (it is already in the notice and emitted as a link).
* Stored (cond 4): the found count (``breach_hit_count``), source names with their month dates and the
  field NAMES as breach data classes - never values (the public API has none). Sensitive provider: the
  P145 schema of ``leakcheck.public`` (provider fragment) applies before the HTTP cache.
* ``found >= 100`` flags a generic/shared value (cond 5, A4: test@example.com returns 1715): info
  only, never scored.
* 429 and 'limit' answers are QUOTA with the provider marked exhausted for the UTC day (provider
  markers ``leakcheck_throttled`` / ``leakcheck_limit_body``; the quota book shows it once per scan);
  ``min_interval`` 1 s (documented 1 RPS) (cond 6). ``{'success': false, 'error': 'Not found'}`` is
  the declared absence 'not found in LeakCheck'; any other error text is ERROR ('could not verify').
* Source names are normalised (domain suffix stripped) and joined to the shared HIBP catalogue (P132
  helper) for dates, data classes and the sensitive flag; sensitive names read 'sensitive breach'
  (cond 7). Each per-breach finding carries ``data['breach_key']`` so ``p2g04_breach_merge`` folds it
  into the HIBP/XposedOrNot finding of the same breach: LeakCheck alone never adds a second scored
  finding for a breach already reported.
* Scope (cond 8, A4): ``run_on='own_assets'``; third-party addresses and usernames only as
  analyst-typed seeds with ``--breach-scope all`` and ``--purpose``, as context, not score.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from v3lum.core.datasets import DatasetError, DatasetUnavailable
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.breach_leak.breach_accounts import (
    GENERIC_FOUND,
    LGPD_NOTE,
    Listing,
    breach_domain,
    breach_scope,
    emit_listings,
    enrich,
    flags_from_name,
    generic_kind,
    int_or_none,
    norm_date,
    normalise_data_classes,
    str_or_none,
    today_of,
)
from v3lum.modules.breach_leak.hibp_catalog import SRC_CATALOG, breach_catalog

SRC_PUBLIC = "leakcheck.public"
PUBLIC_API = "https://leakcheck.io/api/public"
ATTRIBUTION = "Powered by LeakCheck"
ATTRIBUTION_URL = "https://leakcheck.io/"
ABSENT_TEXT = "not found in LeakCheck"
MAX_SOURCES = 200
MIN_CHARS = 3


def leakcheck_public_url(value: Any) -> str:
    """The ONLY LeakCheck URL V3LUM builds (cond 3): GET /api/public?check=<value>."""
    if not isinstance(value, str):
        raise ValueError("value must be a string")
    text = value.strip()
    if len(text) < MIN_CHARS or len(text) > 254 or any(ord(c) < 32 for c in text):
        raise ValueError("invalid LeakCheck value")
    return PUBLIC_API + "?" + urlencode({"check": text})


def leakcheck_url_allowed(url: Any) -> bool:
    """URL allow-list (cond 3): https://leakcheck.io/api/public with exactly one non-empty ``check``."""
    if not isinstance(url, str):
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme != "https" or parts.netloc.lower() != "leakcheck.io" or parts.path != "/api/public" or parts.fragment:
        return False
    params = parse_qs(parts.query, keep_blank_values=True)
    return set(params) == {"check"} and len(params["check"]) == 1 and bool(params["check"][0].strip())


def parse_public(data: Any) -> dict[str, Any]:
    """Public answer -> {state ok|absent|error, found, fields, data_classes, sources, error} (cond 4-6)."""
    out: dict[str, Any] = {"state": "error", "found": None, "fields": [], "data_classes": [], "sources": [], "error": ""}
    if not isinstance(data, dict):
        out["error"] = "answer is not a JSON object"
        return out
    success = data.get("success")
    err = str_or_none(data.get("error"), 120) or ""
    if success is not True:
        if "not found" in err.lower():
            out["state"] = "absent"
        else:
            out["error"] = err or "success flag missing"
        return out
    out["state"] = "ok"
    out["found"] = int_or_none(data.get("found"))
    fields = data.get("fields") if isinstance(data.get("fields"), list) else []
    out["fields"] = sorted({f.strip()[:60] for f in fields if isinstance(f, str) and f.strip()})
    out["data_classes"] = normalise_data_classes(out["fields"])
    for src in data.get("sources") or []:
        if not isinstance(src, dict):
            continue
        name = str_or_none(src.get("name"), 200)
        if not name:
            continue
        out["sources"].append({"name": name, "date": norm_date(src.get("date"))})
        if len(out["sources"]) >= MAX_SOURCES:
            break
    return out


@register
class LeakcheckPublic(Module):
    name = "leakcheck_public"
    title = "LeakCheck public API (breach sources)"
    description = (
        "Breach source names, month dates and exposed field NAMES (never values) listing an e-mail address or username, "
        "from LeakCheck's public endpoint only; found >= 100 marks a generic or shared value."
    )
    category = "breach_leak"
    accepts = {T.EMAIL, T.USERNAME}
    run_on = "own_assets"
    tags = {"breach"}
    reference = "https://wiki.leakcheck.io/en/api/public"
    notice = (
        "Terms unknown: disabled in every licence profile until legal records LeakCheck's terms (default off). "
        f"Attribution when cleared: '{ATTRIBUTION}' ({ATTRIBUTION_URL}). Public endpoint only; the authenticated "
        "lookup API (raw records) is never used. " + LGPD_NOTE
    )
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # LeakCheck receives the address or handle
    provider = "leakcheck"
    sources = (SRC_PUBLIC, SRC_CATALOG)
    hosts = ("leakcheck.io",)
    access_model = "free_noauth_limited"
    max_requests = 1
    expected_latency = 1.0
    min_interval = 1.0  # documented 1 request/s (cond 6)
    cache_ttl = 604800  # sanitized body, at most 7 days (A4)
    max_pivots = 0
    default_enabled = False  # terms unknown (cond 1, A3 BR2)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        own, why = breach_scope(entity, ctx)
        if why:
            return res.mark("skipped", why, reason_code="privacy")
        allowed = getattr(ctx, "allowed_sources", None)
        if allowed is not None and SRC_PUBLIC not in allowed:
            return res.mark("skipped", "LeakCheck terms not cleared under this licence profile", reason_code="licence")
        try:
            url = leakcheck_public_url(entity.value)
        except ValueError:
            return res.mark("skipped", f"value too short for LeakCheck (at least {MIN_CHARS} characters)", reason_code="not_applicable")
        if not leakcheck_url_allowed(url):  # cond 3: the allow-list is checked before every request
            return res.mark("skipped", "URL outside the LeakCheck allow-list", reason_code="policy")
        data = ctx.http.get_json(url, source=SRC_PUBLIC)
        parsed = parse_public(data)
        res.raw = {SRC_PUBLIC: data if isinstance(data, dict) else {}}
        if parsed["state"] == "absent":
            res.presence("absent", marker=f"success=false 'Not found': {ABSENT_TEXT}", checked_at=ctx.now(), source=SRC_PUBLIC)
            res.error = ABSENT_TEXT
            return res.mark("empty")
        if parsed["state"] != "ok":
            return res.mark("error", f"LeakCheck rejected the query ({parsed['error']}): could not verify")
        found = parsed["found"]
        if not found and not parsed["sources"]:
            return res.mark("empty")
        res.link(ATTRIBUTION, ATTRIBUTION_URL)
        res.attr("breach_hit_count", found)
        generic = generic_kind(entity)
        if found is not None and found >= GENERIC_FOUND:
            generic = generic or f"shared (LeakCheck found {found})"
        catalog = self._catalogue(res, ctx)
        listings = []
        for src in parsed["sources"]:
            hints = flags_from_name(src["name"])
            li = Listing(name=src["name"], source=SRC_PUBLIC, date=src["date"], domain=breach_domain(src["name"]),
                         compilation=hints["compilation"] or None, stealer_log=hints["stealer_log"] or None)
            listings.append(enrich(li, catalog))
        extra = f"LeakCheck reports {found} record(s) for this value." if found is not None else ""
        emit_listings(res, listings, provider_label="LeakCheck", own=own, generic=generic, today=today_of(ctx),
                      references=[ATTRIBUTION_URL], summary_extra=extra)
        if parsed["data_classes"]:
            # LeakCheck's fields are a union over all its sources (never per breach): kept as data-class names
            res.attr("breach_data_classes", sorted(set(res.attributes.get("breach_data_classes") or []) | set(parsed["data_classes"])))
        return res

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
            res.source_status(SRC_CATALOG, status, reason_code=code, reason="HIBP catalogue unavailable: LeakCheck names not enriched")
            return None
