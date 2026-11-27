"""P224 Wikidata: organisation items, official website and corporate relations (batch p3-G10-1).

Council P224 final conditions, as implemented:

1. One Wikidata client (``company_org.wikidata_client``, shared with P361). The seed provider ``wikidata``
   binds the identifying UA ``V3LUM/<version> (+<contact_email>) python-requests`` to www.wikidata.org and
   query.wikidata.org; without setting ``contact_email`` the run is SKIPPED ``config`` 'needs contact UA'.
2. min_interval 1 s; 429 (edge or API gateway) -> RATE_LIMITED; MediaWiki errors inside HTTP 200 -> markers
   (maxlag/ratelimited RATE_LIMITED, others ERROR); a WDQS ``TimeoutException`` -> ERROR ``timeout``.
   Requests: ``wbsearchentities`` plus the fixed SPARQL claims template for P6204 (CNPJ), P856 (official
   website), P749 (parent) and P355 (subsidiary) of at most 10 candidates - free-form SPARQL is never sent;
   every template has LIMIT 20 and a 20 s timeout. (The Action API rate-limits datacenter egress quickly,
   so the claims come from one WDQS template instead of per-property wbgetclaims calls.)
3. Default scans: company_name and domain inputs, organisation items only (instance/subclass of business or
   organization), accepted only on an exact label/alias match or a P6204 CNPJ match; a P6204 match with the
   CNPJ the name came from is the only automatic company link (CONFIRMED, the website and relations may expand).
4. Person items only for public figures the analyst typed as seeds and only when the module is selected
   explicitly; never in default scans or from pivots (SKIPPED ``privacy``).
5. P856 becomes a domain pivot (``company_of``) at confidence <= 0.7 labelled 'official site per Wikidata
   (community-edited)'; it never sets known_good or own-asset status, is expanded only for a CNPJ-confirmed
   item, and is called 'official' only when RDAP or CNPJ data agree (correlation, not this module).
6. Parent/subsidiary (P749/P355) become ``company_of`` company-name pivots from depth-0 entities only (depth
   1). Coverage is small (~2,900 items carry a CNPJ): no item is no signal (EMPTY, never a finding). One-line
   output (``wikidata_summary``). CC0.
"""

from __future__ import annotations

import json
import re
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import HttpError
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.company_org import wikidata_client as wd
from v3lum.modules.company_org.registry_text import text

SOURCE_API = "wikidata.wbapi"
SOURCE_SPARQL = "wikidata.sparql"
WEBSITE_CONFIDENCE = 0.7  # cond 5 (cap)
RELATION_CONFIDENCE = 0.6  # cond 6
WEBSITE_LABEL = "official site per Wikidata (community-edited)"
UA_HINT = "needs contact UA: set contact_email to the team role mailbox (Wikimedia User-Agent policy; a UA without contact gets 429)"
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def _json_ok(resp: Any) -> bool:
    try:
        doc = json.loads(resp.content)
    except (ValueError, TypeError, UnicodeDecodeError, AttributeError):
        return False
    return isinstance(doc, dict) and wd.mediawiki_error(doc) is None


def explicitly_selected(module_name: str, ctx: Any) -> bool:
    options = getattr(ctx, "options", None)
    if module_name in set(getattr(options, "include", ()) or ()):
        return True
    return not bool(getattr(getattr(ctx, "runtime", None), "in_scan", False))


def _typed_seed(entity: Entity, ctx: Any) -> bool:
    unconfirmed = set(getattr(getattr(ctx, "options", None), "unconfirmed_seeds", None) or ())
    return bool(getattr(ctx, "is_seed", False)) and int(getattr(ctx, "depth", 0) or 0) == 0 and entity.key not in unconfirmed


def case_cnpj(ctx: Any) -> str | None:
    """The CNPJ a company name was read from (one hop: cnpj -> legal_name), for the P6204 link."""
    prov = tuple(getattr(ctx, "provenance", ()) or ())
    last = prov[-1] if prov else ()
    if len(last) >= 2 and str(last[0]).startswith("cnpj:") and str(last[1]) == "legal_name":
        digits = wd.cnpj_digits(str(last[0])[5:])
        return digits if len(digits) == 14 else None
    return None


@register
class Wikidata(Module):
    name = "wikidata"
    title = "Wikidata organisation items"
    description = (
        "Finds the Wikidata organisation item of a company name (exact label/alias or CNPJ P6204) or of a domain (P856): "
        "official website, parent and subsidiaries as community-edited hints; persons only for typed public figures on request."
    )
    category = "company_org"
    accepts = {T.ORG, T.DOMAIN, T.PERSON, T.KEYWORD}
    produces = {T.DOMAIN, T.ORG}
    tags = {"free"}
    reference = "https://www.wikidata.org/wiki/Wikidata:Data_access"
    notice = (
        "Wikimedia User-Agent policy: needs setting contact_email (a role mailbox, never a personal one). Community-edited data "
        "(CC0): the official website is a hint at confidence <= 0.7 and never marks a domain as known-good or own. About 2,900 items "
        "carry a CNPJ: no item is no signal. Persons only for analyst-typed public figures with -M wikidata."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # Wikidata receives the name or domain
    hosts = ("www.wikidata.org", "query.wikidata.org")
    provider = "wikidata"
    sources = (SOURCE_API, SOURCE_SPARQL)
    access_model = "free_noauth_limited"
    max_requests = 2  # search (or domain template) + claims template
    expected_latency = 6.0  # search ~0.2 s + 1 s spacing + claims template (P279* closure, 0.2-8 s measured)
    timeout = 60.0
    min_interval = 1.0  # cond 2
    cache_ttl = 86400
    max_pivots = 12
    default_enabled = True  # council P224: default-on for organisations
    error_markers = (
        {"id": "wikidata_mediawiki_ratelimited", "statuses": [200], "json_path": "error.code", "equals": None,
         "regex": "^(maxlag|ratelimited|too-many-requests)$", "final_url_regex": None, "maps_to": "rate_limited",
         "reason_code": "rate_limited", "reason": "Wikidata: MediaWiki maxlag/ratelimited error inside an HTTP 200 answer (could not verify)"},
        {"id": "wikidata_mediawiki_error", "statuses": [200], "json_path": None, "equals": None,
         "regex": r"\A\s*\{\s*\"error\"\s*:\s*\{", "final_url_regex": None, "maps_to": "error", "reason_code": "error",
         "reason": "Wikidata: MediaWiki API error body in an HTTP 200 answer (could not verify)"},
        {"id": "wikidata_wdqs_timeout", "statuses": [500], "json_path": None, "equals": None, "regex": "TimeoutException",
         "final_url_regex": None, "maps_to": "error", "reason_code": "timeout",
         "reason": "Wikidata Query Service: query timeout (could not verify)"},
    )

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if not _EMAIL.match(text(ctx.setting("contact_email", ""))):
            return res.mark(Status.SKIPPED, UA_HINT, reason_code="config")
        if entity.type is T.PERSON and not (_typed_seed(entity, ctx) and explicitly_selected(self.name, ctx)):
            return res.mark(Status.SKIPPED, "Wikidata person lookups only for public figures the analyst typed, with -M wikidata (P224 cond 4)",
                            reason_code="privacy")
        if entity.type is T.KEYWORD and not explicitly_selected(self.name, ctx):
            return res.mark(Status.SKIPPED, "keywords are looked up only when wikidata is selected explicitly (-M wikidata)", reason_code="not_default")
        if entity.type is T.DOMAIN:
            return self._domain(res, ctx, str(entity.value))
        return self._name(res, ctx, " ".join(text(entity.value).split()), person=entity.type is T.PERSON)

    # ------------------------------------------------------------------ requests
    @staticmethod
    def _get(ctx: Any, url: str, source: str, *, sparql: bool = False) -> Any:
        doc = ctx.http.get_json(url, source=source, cache_if=_json_ok, timeout=wd.SPARQL_TIMEOUT if sparql else None)
        err = wd.mediawiki_error(doc)
        if err:  # markers catch these first; a variant they miss is still could-not-verify
            raise HttpError(f"{err[1]}: could not verify", 200, url)
        return doc

    def _claims(self, ctx: Any, qids: list[str], *, person: bool = False) -> dict[str, dict[str, Any]]:
        query = wd.person_query(qids) if person else wd.claims_query(qids)
        try:
            items, _truncated = wd.parse_claims(self._get(ctx, wd.sparql_url(query), SOURCE_SPARQL, sparql=True))
        except ValueError as exc:
            raise HttpError(f"{exc}: could not verify", 200, wd.SPARQL_URL) from exc
        return items

    # ------------------------------------------------------------------ company / person names
    def _name(self, res: ModuleResult, ctx: Any, query: str, *, person: bool) -> ModuleResult:
        if len(query) < 2:
            return res.mark(Status.SKIPPED, "name too short", reason_code="not_applicable")
        try:
            hits = wd.parse_search(self._get(ctx, wd.wbsearchentities_url(query), SOURCE_API))
        except ValueError as exc:
            raise HttpError(f"{exc}: could not verify", 200, wd.API_URL) from exc
        cnpj = None if person else case_cnpj(ctx)
        candidates = hits if cnpj else [h for h in hits if wd.exact_match(query, h)]
        if not candidates:
            return self._nothing(res, f"no exact Wikidata label/alias match for '{query}'")
        items = self._claims(ctx, [h["qid"] for h in candidates], person=person)
        accepted = []
        for h in candidates:
            it = items.get(h["qid"])
            if not it or not (it["is_human"] if person else it["is_org"]):
                continue
            if cnpj and cnpj in {wd.cnpj_digits(c) for c in it["cnpj"]}:
                accepted.append((it, h, "cnpj", "confirmed"))
            elif wd.exact_match(query, h):
                accepted.append((it, h, "label", "possible"))
        accepted.sort(key=lambda a: (a[2] != "cnpj", a[0]["qid"]))
        if not accepted:
            what = "person" if person else "organisation"
            return self._nothing(res, f"no Wikidata {what} item matches '{query}' exactly{' or carries its CNPJ' if cnpj else ''}")
        return self._emit(res, ctx, accepted[:3], person=person)

    # ------------------------------------------------------------------ domains
    def _domain(self, res: ModuleResult, ctx: Any, domain: str) -> ModuleResult:
        try:
            found = wd.parse_domain_items(self._get(ctx, wd.sparql_url(wd.domain_query(domain)), SOURCE_SPARQL, sparql=True))
        except ValueError as exc:
            if "invalid domain" in str(exc):
                return res.mark(Status.SKIPPED, "not a host name Wikidata can hold", reason_code="not_applicable")
            raise HttpError(f"{exc}: could not verify", 200, wd.SPARQL_URL) from exc
        if not found:
            return self._nothing(res, f"no Wikidata item declares {domain} as its official website (P856)")
        items = self._claims(ctx, [f["qid"] for f in found])
        accepted = [(items[f["qid"]], {"qid": f["qid"], "label": f["label"]}, "website", "possible")
                    for f in found if f["qid"] in items and items[f["qid"]]["is_org"]]
        if not accepted:
            return self._nothing(res, f"the Wikidata items declaring {domain} are not organisations")
        return self._emit(res, ctx, accepted[:3], person=False, subject_domain=domain)

    # ------------------------------------------------------------------ output
    @staticmethod
    def _nothing(res: ModuleResult, why: str) -> ModuleResult:
        line = f"Wikidata: {why} (coverage is small: no item is no signal); CC0"
        res.attr("wikidata_summary", line)
        return res.mark(Status.EMPTY, line)

    def _emit(self, res: ModuleResult, ctx: Any, accepted: list[tuple[dict[str, Any], dict[str, Any], str, str]], *, person: bool,
              subject_domain: str | None = None) -> ModuleResult:
        depth0 = int(getattr(ctx, "depth", 0) or 0) == 0
        items = []
        for it, hit, link, confidence in accepted:
            label = it.get("label") or hit.get("label") or it["qid"]
            confirmed = link == "cnpj"
            items.append({"qid": it["qid"], "label": label, "description": hit.get("description"), "link": link, "confidence": confidence,
                          "cnpj": it["cnpj"], "websites": it["websites"][:3], "parents": it["parents"][:5], "subsidiaries": it["subsidiaries"][:5],
                          "url": wd.ENTITY_URL.format(qid=it["qid"])})
            for site in it["websites"][:3]:
                host = wd.host_of(site)
                subject = (subject_domain or "").lower()
                if host and host not in (subject, "www." + subject):
                    res.pivot(T.DOMAIN, host, "company_of", confidence=WEBSITE_CONFIDENCE, expand=confirmed,
                              note=f"{WEBSITE_LABEL}: P856 of {it['qid']} '{label}'; never known-good, 'official' only when RDAP/CNPJ agree")
            if subject_domain:
                res.pivot(T.ORG, label, "company_of", confidence=RELATION_CONFIDENCE, expand=False,
                          note=f"Wikidata item {it['qid']} declares {subject_domain} as its official website (community-edited)")
            if depth0 and not person:
                for key, what in (("parents", "parent organisation (P749)"), ("subsidiaries", "subsidiary (P355)")):
                    for rel in it[key][:5]:
                        res.pivot(T.ORG, rel["label"], "company_of", confidence=RELATION_CONFIDENCE, expand=confirmed,
                                  note=f"{what} of {it['qid']} '{label}' per Wikidata (community-edited, depth 1 only)")
            res.link(f"Wikidata {it['qid']} ({label})", wd.ENTITY_URL.format(qid=it["qid"]))
        first = items[0]
        parts = [f"Wikidata {first['qid']} '{first['label']}' ({first['link']} match, {first['confidence']})"]
        if first["websites"]:
            parts.append(f"site {first['websites'][0]} (community-edited)")
        if first["subsidiaries"]:
            parts.append("subsidiaries: " + ", ".join(s["label"] for s in first["subsidiaries"][:3]))
        if len(items) > 1:
            parts.append(f"+{len(items) - 1} more item(s)")
        res.attr("wikidata_item", first)
        res.attr("wikidata_summary", "; ".join(parts) + "; CC0")
        res.attr("data_attribution", [wd.LICENCE])
        res.raw = {"items": items}
        return res
