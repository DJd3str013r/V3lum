"""Have I Been Pwned per-account breaches and paste metadata (P133), company-paid key only.

``GET /api/v3/breachedaccount/{account}?truncateResponse=false`` and ``GET /api/v3/pasteaccount/{account}``
with the key ``hibp`` in the ``hibp-api-key`` header (P133 cond 1: a company-paid subscription recorded in
licence_allow; the source class is ``license``, so the corporate profile skips the module with reason
``licence`` until that entry exists). HIBP's Permitted Purpose is on-demand queries within the plan's
rate limit: ``min_interval`` comes from the tier setting ``hibp_account_rpm`` (default 10 RPM = 6 s,
Core 1); the provider quota block paces the key and the core honours Retry-After on 429 (cond 2).

* A 404 is a declared, meaningful absence worded **'not found in HIBP'** - never 'never breached'
  (cond 2). 401 = NEEDS_KEY; 429 = RATE_LIMITED ('could not verify').
* Breach scope (cond 3, A4): ``run_on='own_assets'`` - addresses on txt_verified/attested org-profile
  domains; third-party addresses only as analyst-typed seeds with ``--breach-scope all`` and
  ``--purpose``, as context (earliest breach date, data classes; at most MEDIUM, no exposure score).
  Never pivots or addresses from text (the policy gate and :func:`breach_accounts.breach_scope`).
* Domain search and stealer logs (cond 4) are not called here: they are own-assets-only endpoints of a
  plan that must be recorded first (see docs/backlog/p2-G04-1.md).
* Pastes (cond 5): metadata only (source, id, date, e-mail count); the paste content is never fetched -
  a manual Pastebin link at most.
* Breach objects pass the P132 helper's normaliser (``hibp_catalog.normalise_breach``): sensitive
  breaches (IsSensitive or a sensitive service category) read 'sensitive breach (name withheld)', spam
  lists and fabricated breaches never count, and only the password FORM survives (cond 6). One finding
  per breach carries ``data['breach_key']``; the rule ``p2g04_breach_merge`` merges it with the
  XposedOrNot and LeakCheck findings of the same breach (cond 7).
* Sensitive provider (cond 8): the P145 schemas of ``hibp.account`` (registered below) and
  ``hibp.hibp_account_pastes`` (provider fragment) apply before the HTTP cache (TTL <= 7 days).
  Generic/role/test addresses are flagged and never scored. Attribution: Have I Been Pwned (CC BY 4.0).
* personal_data_review (cond 9): the hibp provider has none recorded yet, so the policy gate gives the
  address to HIBP only when the module is selected explicitly in a case with a recorded purpose
  (SKIPPED ``privacy`` otherwise).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from v3lum.core import sanitize
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.breach_leak.breach_accounts import (
    LGPD_NOTE,
    Listing,
    breach_scope,
    emit_listings,
    generic_kind,
    normalise_data_classes,
    normalise_email,
    norm_date,
    safe_form,
    today_of,
)
from v3lum.modules.breach_leak.hibp_catalog import ATTRIBUTION_TEXT, ATTRIBUTION_URL, BREACH_FIELDS, normalise_breach

SRC_ACCOUNT = "hibp.account"
SRC_PASTES = "hibp.hibp_account_pastes"
API = "https://haveibeenpwned.com/api/v3"
BREACHED_URL = API + "/breachedaccount/{account}"
PASTES_URL = API + "/pasteaccount/{account}"
ABSENT_TEXT = "not found in HIBP"
DEFAULT_RPM = 10
MAX_PASTES = 50
MAX_PASTE_LINKS = 5

sanitize.register_schema(
    SRC_ACCOUNT,
    keep=[f"[].{f}" for f in BREACH_FIELDS],
    notes="P133 cond 8 / P145: breachedaccount?truncateResponse=false keeps breach METADATA only (names, dates, counts, "
    "data classes, flags and the description the password FORM is derived from); LogoPath, Attribution, DisclosureUrl "
    "and any future field are dropped before the HTTP cache. Registered by hibp_account.",
)


def hibp_min_interval(rpm: Any) -> float:
    """Seconds between keyed HIBP requests for a plan's requests per minute (cond 2: 10 RPM -> 6 s)."""
    try:
        value = int(rpm)
    except (TypeError, ValueError):
        value = DEFAULT_RPM
    return round(60.0 / max(1, min(value, 1000)), 3)


def listings_from_hibp(data: Any) -> list[Listing] | None:
    """breachedaccount answer -> listings (None when the body is not a JSON list)."""
    if not isinstance(data, list):
        return None
    out: list[Listing] = []
    for obj in data:
        b = normalise_breach(obj)
        if b is None:
            continue
        name = str(b.get("name") or "")
        classes = normalise_data_classes(b.get("data_classes") or [])
        out.append(Listing(
            name=name,
            source=SRC_ACCOUNT,
            date=norm_date(b.get("breach_date")),
            domain=b.get("domain"),
            data_classes=classes,
            password_form=safe_form(b.get("password_form")),
            verified=bool(b.get("is_verified")),
            fabricated=bool(b.get("is_fabricated")),
            spam_list=bool(b.get("is_spam_list")),
            stealer_log=bool(b.get("is_stealer_log")),
            sensitive=bool(b.get("sensitive")),
            compilation=bool(re.search(r"collection|combo|compilation|antipublic", name, re.I)),
            records=b.get("pwn_count") if isinstance(b.get("pwn_count"), int) else None,
            catalogue="name",
            canonical=name,
        ))
    return out


def parse_pastes(data: Any) -> list[dict[str, Any]] | None:
    """pasteaccount answer -> paste METADATA {source, id, date, email_count} (cond 5); None if not a list."""
    if not isinstance(data, list):
        return None
    out: list[dict[str, Any]] = []
    for item in data[:MAX_PASTES]:
        if not isinstance(item, dict) or not isinstance(item.get("Source"), str) or not item["Source"].strip():
            continue
        pid = item.get("Id") if isinstance(item.get("Id"), str) else None
        count = item.get("EmailCount")
        out.append({
            "source": item["Source"].strip()[:60],
            "id": pid.strip()[:80] if pid else None,
            "date": norm_date(item.get("Date")),
            "email_count": count if isinstance(count, int) and not isinstance(count, bool) else None,
        })
    return out


def pastebin_link(paste: dict[str, Any]) -> str | None:
    """A manual link for a Pastebin paste id (never fetched automatically, cond 5)."""
    pid = paste.get("id")
    if str(paste.get("source") or "").lower() == "pastebin" and isinstance(pid, str) and re.fullmatch(r"[A-Za-z0-9]{1,32}", pid):
        return f"https://pastebin.com/{pid}"
    return None


@register
class HibpAccount(Module):
    name = "hibp_account"
    title = "Have I Been Pwned account breaches (paid key)"
    description = (
        "Breaches and paste metadata listing an e-mail address in Have I Been Pwned (company-paid key): breach names, "
        "dates, data classes and the password form only; 404 means 'not found in HIBP'."
    )
    category = "breach_leak"
    accepts = {T.EMAIL}
    run_on = "own_assets"
    tags = {"breach"}
    reference = "https://haveibeenpwned.com/API/v3"
    notice = (
        "Company-paid HIBP subscription only (licence_allow entry required under the corporate profile; never an "
        "analyst's personal key). Own-domain addresses by default; third parties only as typed seeds with --breach-scope "
        "all and --purpose, as context. Pastes: metadata only. Data: Have I Been Pwned (CC BY 4.0). " + LGPD_NOTE
    )
    terms = "license"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # HIBP receives the address
    provider = "hibp"
    sources = (SRC_ACCOUNT, SRC_PASTES)
    hosts = ("haveibeenpwned.com",)
    access_model = "commercial_only"
    requires_keys = ("hibp",)
    absent_statuses = frozenset({404})  # documented: the account is not in HIBP (cond 2 wording)
    max_requests = 2  # breachedaccount + pasteaccount
    expected_latency = 7.0  # two keyed calls 6 s apart at 10 RPM
    timeout = 60.0
    cache_ttl = 86400  # sensitive provider: sanitized body only, <= 7 days (cond 8)
    max_pivots = 0
    default_enabled = True
    settings = {"hibp_account_rpm": DEFAULT_RPM}

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        own, why = breach_scope(entity, ctx)
        if why:
            return res.mark("skipped", why, reason_code="privacy")
        account = normalise_email(entity.value)
        if account is None:
            return res.mark("skipped", "not a usable e-mail address", reason_code="not_applicable")
        allowed = getattr(ctx, "allowed_sources", None)
        if allowed is not None and SRC_ACCOUNT not in allowed:
            return res.mark("skipped", "HIBP account API not licensed under this profile (licence_allow entry needed)", reason_code="licence")
        key = ctx.key("hibp")
        if not key:
            return res.mark("needs_key", "HIBP needs the company subscription key 'hibp'")
        interval = hibp_min_interval(ctx.setting("hibp_account_rpm", DEFAULT_RPM))
        headers = {"hibp-api-key": key}
        quoted = quote(account, safe="")
        data = ctx.http.get_json(
            BREACHED_URL.format(account=quoted), params={"truncateResponse": "false"}, headers=headers,
            source=SRC_ACCOUNT, min_interval=interval,
        )
        listings: list[Listing] = []
        if data is not None:
            parsed = listings_from_hibp(data)
            if parsed is None:
                return res.mark("error", "unexpected HIBP answer (not a list of breaches): could not verify")
            listings = parsed
        pastes: list[dict[str, Any]] | None = None
        if allowed is None or SRC_PASTES in allowed:
            pdata = ctx.http.get_json(PASTES_URL.format(account=quoted), headers=headers, source=SRC_PASTES, min_interval=interval)
            if pdata is not None:
                pastes = parse_pastes(pdata)
                if pastes is None:
                    res.source_status(SRC_PASTES, "error", reason="unexpected HIBP paste answer: could not verify")
        # evidence keeps the breach metadata; the free-text Description (read only for the password FORM) is left out
        raw: dict[str, Any] = {SRC_ACCOUNT: [
            {k: v for k, v in b.items() if k != "Description"} for b in (data if isinstance(data, list) else []) if isinstance(b, dict)
        ]}
        if pastes is not None:
            raw[SRC_PASTES] = [{"Source": p["source"], "Id": p["id"], "Date": p["date"], "EmailCount": p["email_count"]} for p in pastes]
        res.raw = raw
        generic = generic_kind(entity)
        if not listings and not pastes:
            res.presence("absent", marker=f"HTTP 404: {ABSENT_TEXT}", url=ATTRIBUTION_URL, checked_at=ctx.now(), source=SRC_ACCOUNT)
            res.error = f"{ABSENT_TEXT} (the address may still be in breaches HIBP has not loaded)"
            return res.mark("empty")
        res.link(ATTRIBUTION_TEXT, ATTRIBUTION_URL)  # CC BY 4.0 attribution wherever results are shown
        if listings:
            emit_listings(res, listings, provider_label="Have I Been Pwned", own=own, generic=generic, today=today_of(ctx),
                          references=[ATTRIBUTION_URL])
        elif generic:
            res.attr("generic_address", generic)
        if pastes:
            self._pastes(res, pastes, own=own, generic=generic)
        return res

    @staticmethod
    def _pastes(res: ModuleResult, pastes: list[dict[str, Any]], *, own: bool, generic: str | None) -> None:
        res.attr("pastes", pastes)
        res.attr("paste_count", len(pastes))
        for p in pastes[:MAX_PASTE_LINKS]:
            link = pastebin_link(p)
            if link:
                res.link(f"Pastebin paste {p['id']} (manual check; content never fetched)", link)
        dates = sorted(p["date"] for p in pastes if p.get("date"))
        context = generic is not None or not own
        tags = ["breach", "privacy"] + (["context_only"] if context else []) + ([] if own else ["third_party"])
        res.finding(
            "Address listed in public pastes",
            "info" if context else "low",
            f"{len(pastes)} paste(s) list the address" + (f" (newest {dates[-1]})" if dates else "")
            + ": " + ", ".join(sorted({p['source'] for p in pastes})) + ". Paste METADATA only: the paste content is never "
            "fetched (a manual link at most). Next step: review the pastes manually and rotate any credential they expose.",
            confidence="possible",
            criterion="HIBP pasteaccount lists the address (paste metadata)"
            + ("; generic address: never scored" if generic else "")
            + ("" if own else "; third-party address: context only"),
            data={"pastes": len(pastes), "sources": sorted({p["source"] for p in pastes}), "newest": dates[-1] if dates else None},
            tags=tags,
            source=SRC_PASTES,
        )
