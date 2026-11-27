"""DomainsDB keyword search (P005 cond 3-4): registered domains containing an org-profile brand (keyed, opt-in).

The keyword search discloses the brand to DomainsDB, so it is a separate module from the local NRD
matching of ``nrd_feeds``:

* cond 3: terms 'key-terms' (key ``domainsdb``, ``Authorization: Bearer``), ``default_enabled=False``,
  keywords only from org_profile brands (:meth:`DomainsdbSearch.applies`).
* cond 4: the provider is unknown tier until reviewed, and an unknown-tier provider may receive only
  IOC_TYPES values (A8 BR4): the policy gate refuses a brand keyword, and :meth:`DomainsdbSearch.run`
  fails closed on its own as well (SKIPPED ``tier``) while the registry tier is 'unknown'. After a
  recorded promotion the source stays flagged ``reuses_queries`` (provider fragment) so it is excluded at
  TLP:AMBER and above.

Statuses: 401/403 NEEDS_KEY (the real anonymous answer is 401 'API key required'), 429 RATE_LIMITED, quota
words QUOTA (P321 marker), the documented 404 'Domains not found' is the only absence. Hits are
candidates (DomainsDB dates and DNS records of unknown freshness): pivots ``expand=False``, no
``newly_registered`` tag (that tag needs a DoH confirmation, P005 cond 9).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.domain_dns import typosquat_permutations as perm

SOURCE = "domainsdb.search"
PROVIDER = "domainsdb"
HOST = "api.domainsdb.info"
API = "https://api.domainsdb.info/v1/domains/search"
KEY_NAME = "domainsdb"
RECENT_DAYS = 30
MAX_DOMAINS = 200
MAX_PIVOTS = 50
MAX_RECENT_FINDINGS = 20
NOT_FOUND_RE = re.compile(r"(?i)domains? not found|no domains")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


class _Unusable(Exception):
    """An answer that is not the documented format: could not verify."""


def _text(value: Any, limit: int = 200) -> str:
    if value is None or isinstance(value, (dict, list, bool)):
        return ""
    return re.sub(r"\s+", " ", _CTRL_RE.sub("", str(value))).strip()[:limit]


def _date(value: Any) -> str | None:
    m = re.match(r"^(\d{4}-\d{2}-\d{2})", _text(value, 40))
    return m.group(1) if m else None


def _ipv4(value: Any) -> str | None:
    try:
        return str(ipaddress.IPv4Address(_text(value, 64)))
    except ValueError:
        return None


def search_url(keyword: str) -> str:
    return f"{API}?domain={quote(keyword, safe='')}"


def parse_search(doc: Any) -> list[dict[str, Any]] | None:
    """/v1/domains/search -> [{domain, created, updated, is_dead, a, mx}] or None when not that answer."""
    if not isinstance(doc, Mapping) or not isinstance(doc.get("domains"), list):
        return None
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in doc["domains"][:1000]:
        if not isinstance(row, Mapping):
            continue
        ent = Entity.try_make(T.DOMAIN, _text(row.get("domain"), 253).rstrip("."))
        if ent is None or ent.value in seen or "." not in ent.value:
            continue
        seen.add(ent.value)
        mx = [_text(m.get("exchange"), 253).rstrip(".").lower() for m in row.get("MX") or [] if isinstance(m, Mapping) and _text(m.get("exchange"))] \
            if isinstance(row.get("MX"), list) else []
        a = [ip for ip in (_ipv4(v) for v in row.get("A") or []) if ip] if isinstance(row.get("A"), list) else []
        out.append({
            "domain": ent.value, "created": _date(row.get("create_date")), "updated": _date(row.get("update_date")),
            "is_dead": str(row.get("isDead")).strip().lower() == "true", "a": a[:10], "mx": [m for m in mx if m][:10],
        })
    return out


def _provider_tier() -> str:
    try:
        from v3lum.core import providers

        prov = providers.registry().get(PROVIDER)
        return str(getattr(prov, "tier", "unknown") or "unknown")
    except Exception:  # noqa: BLE001 - fail closed
        return "unknown"


def _fold(text: str) -> str:
    return perm.fold(re.sub(r"[\s_.'\"/\\]+", "", text or ""))


@register
class DomainsdbSearch(Module):
    name = "domainsdb_search"
    title = "DomainsDB keyword search (org brands, opt-in)"
    description = (
        "Registered domains whose name contains an org-profile brand keyword, from the DomainsDB API (keyed). Opt-in: "
        "the search discloses the brand to DomainsDB, an unknown-tier provider until a recorded promotion."
    )
    category = "domain_dns"
    accepts = {T.KEYWORD}
    produces = {T.DOMAIN}
    run_on = "seeds"
    tags = {"free"}
    reference = "https://api.domainsdb.info/v1/"
    notice = (
        "Discloses the brand keyword to DomainsDB: opt-in, org-profile brands only, and only after a reviewer records the "
        "provider's promotion from unknown tier (P005 cond 3-4); excluded at TLP:AMBER and above (reuses_queries)."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = PROVIDER
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,)
    max_requests = 2
    expected_latency = 1.5
    timeout = 30.0
    min_interval = 1.0
    cache_ttl = 86400
    max_pivots = MAX_PIVOTS
    default_enabled = False
    error_markers = (
        {"id": "domainsdb_quota", "statuses": [200, 402, 403, 429], "json_path": "message",
         "regex": r"(?i)quota|limit (?:reached|exceeded)|daily limit|exceeded",
         "maps_to": "quota", "reason_code": "quota", "reason": "DomainsDB: request quota exhausted (could not verify)"},
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        """cond 3: keywords only from org_profile brands."""
        org = getattr(ctx, "org", None)
        try:
            terms = {_fold(t) for t in (org.brand_terms() if org is not None else [])}
        except Exception:  # noqa: BLE001
            return False
        return bool(_fold(entity.value)) and _fold(entity.value) in terms

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if _provider_tier() == "unknown":
            return res.mark("skipped", "DomainsDB is unknown tier until a reviewer records its promotion: a brand keyword is not an IOC "
                            "value (A8 BR4, P005 cond 4)", reason_code="tier")
        key = ctx.key(KEY_NAME)
        if not key:
            return res.mark("needs_key", "needs the DomainsDB API key (company/team account): v3lum keys setup", reason_code="needs_key")
        keyword = _fold(entity.value)
        resp = ctx.http.get(search_url(keyword), headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
                            allow_redirects=False, source=SOURCE)
        try:
            doc = resp.json()
        except ValueError:
            doc = None
        message = " - ".join(t for t in (_text(doc.get("error"), 80), _text(doc.get("message"), 200)) if t) if isinstance(doc, Mapping) else ""
        if resp.classification is None and resp.status == 404 and NOT_FOUND_RE.search(message):
            return res.mark("empty", f"DomainsDB lists no registered domain containing the keyword ({message})")
        try:
            ctx.http.check(resp)
        except AuthRequired:
            return res.mark("needs_key", f"DomainsDB refused the API key ({message or 'HTTP ' + str(resp.status)})", reason_code="needs_key")
        rows = parse_search(doc)
        if rows is None:
            return res.mark("error", "unexpected DomainsDB answer (no domains list): could not verify")
        if not rows:
            return res.mark("empty", "DomainsDB lists no registered domain containing the keyword")
        res.raw = {"total": doc.get("total") if isinstance(doc.get("total"), int) else None, "domains": rows[:MAX_DOMAINS]}
        res.attr("keyword_domains", [{k: r[k] for k in ("domain", "created", "updated", "is_dead")} for r in rows[:MAX_DOMAINS]])
        cutoff = (ctx.now() - timedelta(days=RECENT_DAYS)).date().isoformat() if isinstance(ctx.now(), datetime) else \
            (datetime.now(timezone.utc) - timedelta(days=RECENT_DAYS)).date().isoformat()
        recent = [r for r in rows if r["created"] and r["created"] >= cutoff]
        res.finding(
            "Registered domains containing the brand keyword (DomainsDB)",
            "info",
            f"{len(rows)} registered domain(s) contain the keyword ({len(recent)} created in the last {RECENT_DAYS} days): candidates to "
            "verify (DomainsDB dates and DNS records may be stale).",
            confidence="possible",
            data={"count": len(rows), "recent": len(recent)},
            source=SOURCE,
        )
        for row in rows[:MAX_PIVOTS]:
            res.pivot(T.DOMAIN, row["domain"], "brand_match", confidence="possible", expand=False,
                      note=f"DomainsDB keyword search (created {row['created'] or '?'}{', marked dead' if row['is_dead'] else ''})")
        for row in recent[:MAX_RECENT_FINDINGS]:
            ent = Entity.try_make(T.DOMAIN, row["domain"])
            if ent is None:
                continue
            finding = res.finding(
                "Recently created domain containing the brand keyword",
                "low",
                f"{row['domain']} was created on {row['created']} according to DomainsDB and contains the brand keyword; registration "
                "and activity are not confirmed here (no DoH check: no newly_registered tag).",
                confidence="possible",
                criterion=f"DomainsDB create_date {row['created']} within {RECENT_DAYS} days and the brand keyword in the name",
                data={k: row[k] for k in ("created", "updated", "is_dead", "mx")},
                source=SOURCE,
                observed_first=row["created"],
                key=row["domain"],
            )
            finding.entity = ent
            finding.ensure_id()
        return res
