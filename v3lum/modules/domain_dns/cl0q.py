"""cl0q open-web index (P018): favicon reverse pivots and ASN browse, as hypotheses (unknown tier, keyed, opt-in).

Final conditions (council #1, P018) and where they live:

1. Unknown tier until a promotion is recorded (provider fragment ``cl0q``): ``default_enabled=False``; the
   policy gate excludes it at TLP:AMBER, AMBER+STRICT and RED and asks ``--allow-unknown`` at CLEAR/GREEN.
   It receives IOC_TYPES values only: ``accepts`` is {domain, asn} (keywords and every personal type are
   refused; the proposal's 'keyword' input is not accepted).
2. Key ``cl0q`` (provider fragment; ``V3LUM_KEY_CL0Q`` and the ``V3LUM_CL0Q_KEY`` alias) in
   ``requires_keys``: NEEDS_KEY without it. The key travels only in the ``X-API-Key`` header, never as
   ``?key=`` (the cache stores URLs). Key-terms: ``free_plan_business_use`` null, so under the corporate
   profile it runs only once legal records the plan (``key_plans.cl0q='business'``).
3. Favicon pivots: cl0q content-addresses favicons by the **SHA-256 of the icon bytes**, not mmh3 (docs read
   2026-11-26; an mmh3 value is a 400 'malformed hash'). The module therefore asks cl0q for the domain's
   own favicon record (``/api/favicon?domain=``: the hash, how many sites share it and a sample), then
   reverses the SHA-256 (``/api/favicon?hash=``) when more sites share it: no icon bytes ever leave the
   machine and no local hash is needed. ``favicon_hash`` entities (mmh3 by the core normaliser) are not
   accepted: see docs/backlog/p3-G01-1.md.
4. Every result is a hypothesis: domains pivot with relation ``related``, ``expand=False`` and confidence
   POSSIBLE (<= 0.5); a favicon shared by more than :data:`COMMON_ICON` sites is a framework/hosting default
   and gives no pivot at all.
5. 30 requests/min and 1,000/day go into the provider quota block (P334, 80% margin). 401/403 ('missing API
   key', 'signin_required') -> NEEDS_KEY, throttling -> RATE_LIMITED, daily exhaustion -> QUOTA, never EMPTY.
6. Merge gate: a trimmed real success fixture captured with the team key is still owed (only the 401 body
   is real) - docs/backlog/p3-G01-1.md.

Never called: ``POST /api/signup`` (automated sign-up), ``POST /api/watch`` (stores the query),
``/api/feedback``, ``/api/report``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import HttpError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.domain_dns.subdomains_keyed import auth_headers, check_error_body, keyed_get
from v3lum.modules.domain_dns.subdomains_passive import UnexpectedAnswer

__all__ = ["COMMON_ICON", "Cl0q", "parse_domain_list", "parse_sha256"]

SOURCE = "cl0q.api"
FAVICON_URL = "https://cl0q.com/api/favicon"
BROWSE_ASN_URL = "https://cl0q.com/api/browse/asn/{asn}"
CACHE_TTL = 86400
LIMIT = 100
PIVOT_CAP = 50
ASN_PIVOT_CAP = 25
COMMON_ICON = 100  # more sites than this share the icon: a framework/hosting default, never a pivot
CONFIDENCE = "possible"  # P018 cond 4: at most POSSIBLE
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DATA_KEYS = ("hash", "sha256", "favicon_sha256", "domains", "sample", "samples", "items", "results", "matches", "sites", "count", "total")


def parse_sha256(value: Any) -> str | None:
    """A lower-case 64-hex SHA-256 (optional 'sha256:' prefix), else None."""
    if not isinstance(value, str):
        return None
    s = value.strip().lower().removeprefix("sha256:")
    return s if _HEX64.match(s) else None


def _count(obj: Mapping[str, Any]) -> int | None:
    for key in ("count", "total", "shared"):
        v = obj.get(key)
        if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
            return v
    return None


def parse_domain_list(obj: Any, exclude: str = "") -> dict[str, Any]:
    """Domains of a cl0q favicon (forward/reverse) or browse answer -> ``{domains, rejected, count, hash, next}``.

    Field names of the favicon answers are not documented (prose only): ``domains`` / ``sample`` / ``items``
    / ``results`` lists of strings or ``{domain|d|host|name}`` objects are read; the queried name is left out.
    Raises UnexpectedAnswer when no list (or zero count) is present."""
    if not isinstance(obj, Mapping):
        raise UnexpectedAnswer("cl0q: answer is not a JSON object")
    items = next((obj[k] for k in ("domains", "sample", "samples", "items", "results", "matches", "sites") if isinstance(obj.get(k), list)), None)
    count = _count(obj)
    if items is None:
        if count == 0:
            items = []
        else:
            raise UnexpectedAnswer("cl0q: answer without a domain list")
    out: dict[str, Any] = {"domains": [], "rejected": 0, "count": count,
                           "hash": parse_sha256(obj.get("hash") or obj.get("sha256") or obj.get("favicon_sha256") or obj.get("key")),
                           "next": bool(isinstance(obj.get("next"), str) and obj.get("next"))}
    skip = (exclude or "").strip().lower().rstrip(".")
    for item in items:
        value = item if isinstance(item, str) else (
            next((item[k] for k in ("domain", "d", "host", "name") if isinstance(item.get(k), str)), None) if isinstance(item, Mapping) else None)
        ent = Entity.try_make(T.DOMAIN, value.strip().lower().rstrip(".")) if isinstance(value, str) else None
        if ent is None:
            out["rejected"] += 1
            continue
        name = str(ent.value)
        if name != skip and name not in out["domains"]:
            out["domains"].append(name)
    return out


@register
class Cl0q(Module):
    name = "cl0q"
    title = "cl0q favicon and ASN pivots (hypotheses)"
    description = (
        "cl0q open-web index (keyed, unknown tier): sites serving the same favicon bytes as a domain (SHA-256 content "
        "address) and a sample of registrable domains hosted in an AS - listed as hypotheses, never investigated."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN, T.ASN}  # IOC_TYPES only (P018 cond 1)
    produces = {T.DOMAIN}
    tags = {"free"}
    reference = "https://cl0q.com/docs/"
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "cl0q"
    sources = (SOURCE,)
    hosts = ("cl0q.com",)
    access_model = "free_auth_limited"
    requires_keys = ("cl0q",)
    max_requests = 2  # favicon by domain + one reverse page (or one ASN browse page)
    expected_latency = 2.0
    timeout = 45.0
    min_interval = 2.0
    cache_ttl = CACHE_TTL
    max_pivots = PIVOT_CAP
    default_enabled = False  # unknown tier (P018 cond 1, A3)
    notice = (
        "Unknown-tier provider: opt-in, excluded at TLP:AMBER and above, --allow-unknown at CLEAR/GREEN; it receives only "
        "domains and ASNs. The key (a company/team account on a plan recorded by legal) travels only in the X-API-Key "
        "header. Results are hypotheses (relation 'related', never expanded): a shared favicon may be a framework default, "
        "a hosting template or a phishing kit."
    )
    settings = {
        "cl0q_reverse": SettingSpec(True, "cl0q: also reverse the favicon SHA-256 when more sites share it than the sample lists (one more request)"),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.ASN:
            return True
        return "." in str(entity.value)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = ctx.key("cl0q")
        headers = auth_headers("X-API-Key", "{key}", key)
        if not headers:
            return res.mark("needs_key", "needs the cl0q API key (company/team account): v3lum keys set cl0q", reason_code="needs_key")
        feed = SimpleNamespace(source=SOURCE, label="cl0q")
        try:
            if entity.type is T.ASN:
                return self._asn(res, ctx, feed, headers, str(entity.value))
            return self._favicon(res, ctx, feed, headers, str(entity.value).strip().lower().rstrip("."))
        except UnexpectedAnswer as exc:
            return res.mark("error", f"{exc}: could not verify", reason_code="error")

    # ---- favicon (cond 3, 4) ---------------------------------------------------------------------------
    def _favicon(self, res: ModuleResult, ctx: Any, feed: Any, headers: dict[str, str], domain: str) -> ModuleResult:
        obj, resp = keyed_get(ctx, feed, FAVICON_URL, headers=headers, deadline=ctx.deadline, params={"domain": domain, "limit": str(LIMIT)})
        try:
            check_error_body("cl0q", obj, _DATA_KEYS)
            fwd = parse_domain_list(obj, exclude=domain)
        except (UnexpectedAnswer, HttpError):
            ctx.http.evict(resp)
            raise
        sha = fwd["hash"]
        evidence: dict[str, Any] = {"forward": {"hash": sha, "count": fwd["count"], "listed": len(fwd["domains"]), "rejected": fwd["rejected"]}}
        res.raw = evidence
        if not sha:
            if fwd["domains"]:
                raise UnexpectedAnswer("cl0q: favicon answer lists sites but no SHA-256")
            return res.mark("empty")  # the index holds no favicon for this domain
        domains = list(fwd["domains"])
        # the docs: 'this domain's favicon hash, plus how many OTHER domains serve the same icon and a sample of them'
        shared = max(fwd["count"] if fwd["count"] is not None else 0, len(domains))
        truncated = shared > len(domains)
        if truncated and shared <= COMMON_ICON and bool(ctx.setting("cl0q_reverse", True)):
            try:
                robj, rresp = keyed_get(ctx, feed, FAVICON_URL, headers=headers, deadline=ctx.deadline, params={"hash": sha, "limit": str(LIMIT)})
                try:
                    check_error_body("cl0q", robj, _DATA_KEYS)
                    rev = parse_domain_list(robj, exclude=domain)
                except (UnexpectedAnswer, HttpError):
                    ctx.http.evict(rresp)
                    raise
                for d in rev["domains"]:
                    if d not in domains:
                        domains.append(d)
                truncated = shared > len(domains) or rev["next"]
                evidence["reverse"] = {"count": rev["count"], "listed": len(rev["domains"]), "rejected": rev["rejected"]}
            except RateLimited:
                res.stop("rate_limited")
            except QuotaExceeded:
                res.stop("quota")
            except (HttpError, UnexpectedAnswer) as exc:
                res.partial = True
                res.error = f"partial: cl0q reverse favicon lookup failed ({str(exc)[:160]}): sample only"
        common = shared > COMMON_ICON
        res.attr("favicon_sha256", sha)
        res.attr("favicon_shared", {"sha256": sha, "shared_count": shared, "listed": len(domains), "truncated": bool(truncated),
                                    "common": common, "source": SOURCE})
        if common:
            res.finding(
                "Favicon is a common icon",
                "info",
                f"cl0q lists {shared} other sites serving the same favicon bytes: a framework, CMS or hosting default, "
                "so the favicon is not a pivot here.",
                confidence=CONFIDENCE, data={"sha256": sha, "shared_count": shared}, tags=["info"], source=SOURCE,
            )
            return res
        for d in domains[:PIVOT_CAP]:
            res.pivot(T.DOMAIN, d, "related", confidence=CONFIDENCE, expand=False,
                      note="serves the identical favicon bytes (cl0q SHA-256): hypothesis - same operator, framework default or kit")
        if domains:
            self._shared_finding(res, ctx, domain, sha, shared, domains)
        return res

    @staticmethod
    def _shared_finding(res: ModuleResult, ctx: Any, domain: str, sha: str, shared: int, domains: list[str]) -> None:
        own = False
        try:
            own = bool(ctx.org.owns(Entity.make(T.DOMAIN, domain)).own)
        except Exception:  # noqa: BLE001 - no organisation profile: not an own asset
            own = False
        outsiders = []
        for d in domains:
            try:
                if not ctx.org.owns(Entity.make(T.DOMAIN, d)).own:
                    outsiders.append(d)
            except Exception:  # noqa: BLE001
                outsiders.append(d)
        if own and outsiders:
            res.finding(
                "Own site favicon served by other domains",
                "low",
                f"{len(outsiders)} domain(s) outside the organisation profile serve the identical favicon bytes of {domain} "
                f"(cl0q, {shared} site(s) in total): a cloned page or phishing kit is possible, as is a shared template. "
                "Hypothesis only: review the listed domains.",
                confidence=CONFIDENCE,
                criterion="identical favicon SHA-256 (cl0q content address) on domains outside the organisation profile; "
                          f"icon shared by at most {COMMON_ICON} sites",
                data={"sha256": sha, "domains": outsiders[:PIVOT_CAP], "shared_count": shared},
                tags=["possible_clone"], source=SOURCE,
            )
            return
        res.finding(
            "Favicon shared with other sites",
            "info",
            f"{shared} other site(s) serve the identical favicon bytes of {domain} (cl0q): related infrastructure, a shared "
            "template or a framework default - hypotheses, listed and not investigated.",
            confidence=CONFIDENCE, data={"sha256": sha, "shared_count": shared, "listed": domains[:PIVOT_CAP]}, tags=["info"], source=SOURCE,
        )

    # ---- ASN browse --------------------------------------------------------------------------------------
    def _asn(self, res: ModuleResult, ctx: Any, feed: Any, headers: dict[str, str], asn: str) -> ModuleResult:
        number = asn.upper().removeprefix("AS")
        if not number.isdigit():
            return res.mark("skipped", "not an AS number", reason_code="not_applicable")
        obj, resp = keyed_get(ctx, feed, BROWSE_ASN_URL.format(asn=int(number)), headers=headers, deadline=ctx.deadline,
                              params={"apex": "1", "limit": str(LIMIT)})
        try:
            check_error_body("cl0q", obj, _DATA_KEYS)
            got = parse_domain_list(obj)
        except (UnexpectedAnswer, HttpError):
            ctx.http.evict(resp)
            raise
        res.raw = {"asn": f"AS{int(number)}", "listed": len(got["domains"]), "rejected": got["rejected"], "more": got["next"]}
        if not got["domains"]:
            return res.mark("empty")
        res.attr("asn_domain_sample", {"asn": f"AS{int(number)}", "listed": len(got["domains"]), "more": got["next"],
                                       "domains": got["domains"][:LIMIT], "source": SOURCE})
        for d in got["domains"][:ASN_PIVOT_CAP]:
            res.pivot(T.DOMAIN, d, "related", confidence=CONFIDENCE, expand=False,
                      note="hosted in this AS according to cl0q's open-web index: hypothesis, never ownership")
        return res
