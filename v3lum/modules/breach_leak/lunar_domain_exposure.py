"""Lunar (Webz.io) domain exposure API: a 12-month aggregate 'domain exposure card' (P136).

``GET https://api.lunarcyber.com/domain-exposure?domain=<domain>`` (keyless). Aggregate counts only
(cond 3): events in 12 months (infostealer vs data breach, employee vs client, first/last seen), top
stealer families, operating systems, antivirus products, months and the breach-source split - never
records. Lunar is a sensitive provider: the P145 schema of ``lunarcyber.domain_exposure`` (provider
fragment) keeps only those aggregate fields before the HTTP cache.

* Terms 'unknown' (cond 1): the only Webz.io terms found cover its News API Lite (non-commercial
  derivatives), none the Lunar endpoint: ``default_enabled = False`` and every licence profile skips it
  until Webz.io confirms in writing or legal records the terms.
* Runs only for analyst-typed seed domains (org-profile own domains, suppliers inside a case with a
  recorded purpose; ``run_on='seeds'``), never for pivoted domains, webmail/free-provider domains or
  noise-list domains (gmail.com counts are meaningless) (cond 2).
* An info/low card (cond 4): context, never the compromise of a specific account. Implausible volumes
  (> 100,000 events) and test domains (example.com) carry an 'unreliable/generic' caveat.
* Confidential case data (cond 5): the result is marked TLP:AMBER (``res.set_marking('amber')``) and
  tagged ``confidential`` (AMBER-marked report sections, excluded from CLEAR/GREEN exports).
* Cache 24 h (cond 6). A domain asked for the first time answers ``GENERATING_REPORT`` with
  ``report: null`` (live 2026-11-26; ready a few seconds later): the module polls at most twice more,
  3 s apart, never caches a generating answer and ends ERROR 'timeout' ('could not verify') when the
  report is still not ready - never EMPTY. Error bodies map to ERROR / RATE_LIMITED (provider markers);
  400 'Invalid domain.' is ERROR.
* The top login URLs of the Lunar report are not kept: their key carries the second-net token 'login'
  (dropped by the core sanitizer before the cache) and their paths can hold masked user names; see
  docs/backlog/p2-G04-1.md.
"""

from __future__ import annotations

from typing import Any

from v3lum.core import noise
from v3lum.core.entities import Entity, generic_address_kind
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.breach_leak.breach_accounts import int_or_none, norm_date, str_or_none

SOURCE = "lunarcyber.domain_exposure"
HOST = "api.lunarcyber.com"
API = f"https://{HOST}/domain-exposure"
IMPLAUSIBLE_EVENTS = 100_000
MAX_POLLS = 2  # extra requests while the report is GENERATING_REPORT
POLL_INTERVAL = 3.0
TOP = 10
REFERENCE = "https://docs.webz.io/markdown/webz/dea-api-reference"


def parse_exposure(data: Any) -> dict[str, Any]:
    """Lunar answer -> {state ready|generating|unknown, domain, period, card...} (aggregates only)."""
    out: dict[str, Any] = {"state": "unknown", "domain": None, "period": None, "status": None}
    if not isinstance(data, dict):
        return out
    status = (str_or_none(data.get("status"), 40) or "").upper()
    out["status"] = status or None
    out["domain"] = (str_or_none(data.get("domain"), 253) or "").lower() or None
    pf, pt = norm_date(data.get("periodFrom")), norm_date(data.get("periodTo"))
    out["period"] = {"from": pf, "to": pt} if pf or pt else None
    report = data.get("report") if isinstance(data.get("report"), dict) else None
    if status == "GENERATING_REPORT":
        out["state"] = "generating"
        return out
    if report is None or (status and status != "REPORT_READY"):
        return out
    out["state"] = "ready"
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    out["totals"] = {k: int_or_none(summary.get(k)) for k in (
        "total_events", "infostealer_events", "data_breach_events", "employee_events", "client_events")}
    out["totals"]["first_seen"] = norm_date(summary.get("first_seen"))
    out["totals"]["last_seen"] = norm_date(summary.get("last_seen"))
    out["stealer_families"] = _counts(report.get("malware_family_breakdown"), "family", "events")
    out["operating_systems"] = _counts(report.get("os_breakdown"), "os_family", "infostealer_events")
    out["antivirus"] = _counts(report.get("antivirus_breakdown"), "antivirus", "events")
    months = []
    for row in report.get("monthly_timeline") or []:
        if isinstance(row, dict) and norm_date(row.get("month")):
            months.append({"month": (norm_date(row.get("month")) or "")[:7],
                           "events": int_or_none(row.get("total_events")),
                           "infostealer": int_or_none(row.get("infostealer_events")),
                           "data_breach": int_or_none(row.get("data_breach_events"))})
    out["months"] = months[:24]
    dbs = report.get("data_breach_summary") if isinstance(report.get("data_breach_summary"), dict) else {}
    out["breach_sources"] = {
        "known_sources": int_or_none(dbs.get("known_breach_sources_count")),
        "events_from_known_sources": int_or_none(dbs.get("events_from_known_breach_sources")),
        "events_from_combolists": int_or_none(dbs.get("events_from_combolist_sources")),
    }
    out["generated_at"] = norm_date(report.get("generated_at"))
    return out


def _counts(rows: Any, label_key: str, count_key: str) -> list[dict[str, Any]]:
    out = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        label = str_or_none(row.get(label_key), 80)
        count = int_or_none(row.get(count_key))
        if label and count is not None:
            out.append({"name": label, "events": count})
    return sorted(out, key=lambda r: (-r["events"], r["name"]))[:TOP]


def caveats(parsed: dict[str, Any], domain: str) -> list[str]:
    """cond 4: 'unreliable/generic' for implausible volumes and IANA example/test domains."""
    out = []
    total = (parsed.get("totals") or {}).get("total_events")
    if isinstance(total, int) and total > IMPLAUSIBLE_EVENTS:
        out.append(f"unreliable/generic: implausible volume ({total:,} events in 12 months)")
    try:
        kind = generic_address_kind("x@" + domain)
    except Exception:  # noqa: BLE001
        kind = None
    if kind in ("test", "example_domain") or domain.rsplit(".", 1)[-1] in ("test", "example", "invalid", "localhost"):
        out.append("unreliable/generic: IANA example/test domain")
    return out


def _ready(resp: Any) -> bool:
    """cache_if veto: only a ready report is cached (a GENERATING answer must be asked again)."""
    try:
        return parse_exposure(resp.json())["state"] == "ready"
    except Exception:  # noqa: BLE001 - unreadable: never cached
        return False


def refusal(entity: Entity, ctx: Any) -> str | None:
    """cond 2: webmail/free-provider and noise-list domains give meaningless counts and are never sent."""
    domain = entity.value.lower().rstrip(".")
    try:
        from v3lum.modules.email.email_hygiene import is_free_provider

        if is_free_provider(domain, ctx):
            return "webmail/free-provider domain: Lunar counts are meaningless"
    except Exception:  # noqa: BLE001 - the list is a convenience; noise lists still apply
        pass
    try:
        kind = noise.noise_kind(entity)
    except Exception:  # noqa: BLE001
        kind = None
    if kind:
        return f"noise-list domain ({kind}): Lunar counts are meaningless"
    return None


@register
class LunarDomainExposure(Module):
    name = "lunar_domain_exposure"
    title = "Lunar domain exposure card (aggregate)"
    description = (
        "12-month aggregate exposure counts of a domain from Lunar (Webz.io): infostealer vs breach events, stealer "
        "families, OS, antivirus and months - counts only, never records; confidential (TLP:AMBER)."
    )
    category = "breach_leak"
    accepts = {T.DOMAIN}
    run_on = "seeds"
    tags = {"breach"}
    reference = REFERENCE
    notice = (
        "Terms unknown (Webz.io has not confirmed terms for the Lunar endpoint): disabled until legal records them. Own "
        "and analyst-typed supplier domains only; aggregate counts are confidential case data (TLP:AMBER minimum) and "
        "an exposure context, never the compromise of a specific account."
    )
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # Lunar receives the domain
    provider = "lunarcyber"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_noauth_limited"
    max_requests = 1 + MAX_POLLS
    expected_latency = 2.0
    timeout = 60.0
    min_interval = POLL_INTERVAL
    daily_quota = 50  # politeness budget: Lunar publishes no limit
    cache_ttl = 86400  # cond 6
    max_pivots = 0
    default_enabled = False  # terms unknown (cond 1, A3 BR2)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return refusal(entity, ctx) is None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        why = refusal(entity, ctx)
        if why:
            return res.mark("skipped", why, reason_code="not_applicable")
        domain = entity.value.lower().rstrip(".")
        parsed: dict[str, Any] = {"state": "unknown"}
        data: Any = None
        for _attempt in range(1 + MAX_POLLS):
            if ctx.cancelled():
                break
            data = ctx.http.get_json(API, params={"domain": domain}, source=SOURCE, cache_if=_ready)
            parsed = parse_exposure(data)
            if parsed["state"] != "generating":
                break
        res.raw = {SOURCE: data if isinstance(data, dict) else {}}
        if parsed["state"] == "generating":
            return res.mark("error", "Lunar report still being generated (GENERATING_REPORT after the poll budget): could not verify",
                            reason_code="timeout")
        if parsed["state"] != "ready":
            return res.mark("error", f"unexpected Lunar answer (status {parsed.get('status') or 'missing'}, no report): could not verify")
        totals = parsed["totals"]
        notes = caveats(parsed, domain)
        card = {
            "period": parsed["period"],
            "totals": totals,
            "stealer_families": parsed["stealer_families"],
            "operating_systems": parsed["operating_systems"],
            "antivirus": parsed["antivirus"],
            "months": parsed["months"],
            "breach_sources": parsed["breach_sources"],
            "caveats": notes,
            "provider": "Lunar (Webz.io)",
        }
        res.set_marking("amber")  # cond 5: confidential case data, minimum TLP:AMBER
        res.attr("domain_exposure", card)
        families = [f["name"] for f in parsed["stealer_families"]]
        if families:
            res.attr("malware_family", families)
        total = totals.get("total_events") or 0
        stealer = totals.get("infostealer_events") or 0
        if not total and not stealer and not (totals.get("data_breach_events") or 0):
            return res.mark("empty")
        severity = "low" if stealer and not notes else "info"
        top = ", ".join(f"{f['name']} ({f['events']})" for f in parsed["stealer_families"][:5])
        res.finding(
            "Domain exposure card (12-month aggregate)",
            severity,
            f"{total:,} exposure events in 12 months for {domain}: {stealer:,} infostealer, "
            f"{(totals.get('data_breach_events') or 0):,} data breach; employees {(totals.get('employee_events') or 0):,}, "
            f"clients {(totals.get('client_events') or 0):,}"
            + (f"; first seen {totals['first_seen']}, last seen {totals['last_seen']}" if totals.get("first_seen") else "")
            + (f". Top stealer families: {top}" if top else "")
            + ". Aggregate counts only: an exposure context, not the compromise of a specific account."
            + (" Caveat: " + "; ".join(notes) + "." if notes else "")
            + " Next step: review SSO/VPN exposure, enforce MFA and password resets for the affected population.",
            confidence="possible",
            criterion="Lunar 12-month aggregate counts for the domain (context only; confidential, TLP:AMBER)"
            + (" - " + "; ".join(notes) if notes else ""),
            data={"total_events": total, "infostealer_events": stealer, "data_breach_events": totals.get("data_breach_events"),
                  "caveats": notes},
            tags=["confidential", "exposure", *(["context_only"] if notes else [])],
            references=[REFERENCE],
            source=SOURCE,
        )
        return res
