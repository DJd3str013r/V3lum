"""P227 UK Companies House: company profile, officers and persons with significant control (batch p3-G10-1).

Council P227 final conditions, as implemented:

1. ``requires_keys=('companies_house',)`` (provider ``companies_house_api``): the key travels only as the HTTP
   basic-auth username (``Authorization: Basic base64(key:)``), never in URLs, and is registered with the
   central redactor by the key registry. A keyless or rejected 401 ('Empty Authorization header') -> NEEDS_KEY.
2. Key-terms (A1): source ``companies_house_api.public_data_api`` has class ``key-terms`` with
   ``free_plan_business_use`` null, so under the corporate profile the policy gate runs it only when legal has
   recorded the company/team key's plan as business (``v3lum keys set companies_house --plan business``);
   the terms URL is in the provider fragment.
3. UK counterparties only (the UK register), opt-in (default_enabled=False). Company search by name (the
   exact normalised title is followed; other hits are listed as candidates) and profile by company number
   (a keyword shaped like a UK company number).
4. Officers and PSC keep name, role/kind (natures of control for PSC) and appointment/notification and
   resignation/cessation dates only; dates of birth, nationality, occupation, residence, identification and
   addresses are dropped at parse time. Current ones become person_name pivots (corporate ones company_name)
   with relation ``officer_of`` / ``psc_of`` and expand=False: never auto-pivoted into person modules.
5. Rate: the documented 600 requests per 5 minutes is the provider quota block (P334 budget: 2 req/s, 80%);
   429 -> RATE_LIMITED. OGL attribution in ``data_attribution``.
6. Merge gate: the success fixtures are documented-shape placeholders until the team key captures real ones
   (the keyless 401 is a real capture) - recorded in docs/backlog/p3-G10-1.md.
"""

from __future__ import annotations

import base64
import re
from typing import Any
from urllib.parse import quote, urlencode

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import HttpError
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.company_org.registry_text import as_dict, as_list, iso_date, norm_company_name, text

BASE = "https://api.company-information.service.gov.uk"
SOURCE = "companies_house_api.public_data_api"
PAGE_URL = "https://find-and-update.company-information.service.gov.uk/company/{number}"
ATTRIBUTION = "Contains public sector information licensed under the Open Government Licence v3.0 (Companies House)."
CACHE_TTL = 86400
MAX_LISTED = 30
MAX_PIVOTS = 15
_NUMBER = re.compile(r"^(?:\d{8}|[A-Z]{2}\d{6}|R\d{7})$")
_CORPORATE = re.compile(r"^corporate-|^legal-person|corporate-entity")
_UK_FORMS = ((re.compile(r"\bpublic limited company\b"), "plc"), (re.compile(r"\blimited\b"), "ltd"),
             (re.compile(r"\bcyfyngedig\b"), "cyf"))


def company_number(value: Any) -> str | None:
    """'1234' -> '00001234'; 'sc123456' -> 'SC123456'; anything else -> None."""
    s = re.sub(r"\s", "", text(value)).upper()
    if s.isdigit() and 1 <= len(s) <= 8:
        s = s.zfill(8)
    return s if _NUMBER.match(s) else None


def search_url(name: str, items_per_page: int = 5) -> str:
    q = re.sub(r"\s+", " ", text(name))
    if not q:
        raise ValueError("empty name")
    return f"{BASE}/search/companies?" + urlencode([("q", q), ("items_per_page", str(items_per_page))], quote_via=quote)


def company_url(number: str, sub: str | None = None) -> str:
    n = company_number(number)
    if not n:
        raise ValueError("invalid company number")
    return f"{BASE}/company/{n}" + {None: "", "officers": "/officers", "psc": "/persons-with-significant-control"}[sub]


def uk_name_key(name: Any) -> str:
    """Exact-comparison key: 'Example Trading Ltd' == 'EXAMPLE TRADING LIMITED' (UK legal-form spellings unified)."""
    s = norm_company_name(name)
    for rx, rep in _UK_FORMS:
        s = rx.sub(rep, s)
    return s


def basic_auth(key: str) -> str:
    """Cond 1: the key is the basic-auth username with an empty password (never in URLs)."""
    return "Basic " + base64.b64encode((text(key) + ":").encode("utf-8")).decode("ascii")


def parse_search(doc: Any) -> list[dict[str, Any]]:
    """Search hits -> [{company_number, title, status, type, created, ceased}] (address snippets dropped)."""
    if not isinstance(doc, dict):
        raise ValueError("Companies House search answer is not a JSON object")
    out = []
    for r in as_list(doc.get("items")):
        r = as_dict(r)
        n = company_number(r.get("company_number"))
        if n and text(r.get("title")):
            out.append({"company_number": n, "title": text(r.get("title")), "status": text(r.get("company_status")) or None,
                        "type": text(r.get("company_type")) or None, "created": iso_date(r.get("date_of_creation")),
                        "ceased": iso_date(r.get("date_of_cessation"))})
    return out


def parse_company(doc: Any) -> dict[str, Any] | None:
    """Profile -> company facts (the registered office address is not kept)."""
    o = as_dict(doc)
    n = company_number(o.get("company_number"))
    if not n:
        return None
    return {"company_number": n, "name": text(o.get("company_name")) or None, "status": text(o.get("company_status")) or None,
            "type": text(o.get("type")) or None, "jurisdiction": text(o.get("jurisdiction")) or None,
            "created": iso_date(o.get("date_of_creation")), "ceased": iso_date(o.get("date_of_cessation")),
            "sic_codes": [text(x) for x in as_list(o.get("sic_codes")) if text(x)][:10],
            "previous_names": [text(as_dict(p).get("name")) for p in as_list(o.get("previous_company_names")) if text(as_dict(p).get("name"))][:10],
            "has_insolvency_history": o.get("has_insolvency_history") is True, "has_charges": o.get("has_charges") is True,
            "accounts_overdue": as_dict(o.get("accounts")).get("overdue") is True,
            "confirmation_overdue": as_dict(o.get("confirmation_statement")).get("overdue") is True,
            "url": PAGE_URL.format(number=n)}


def parse_officers(doc: Any) -> list[dict[str, Any]]:
    """Cond 4: [{name, role, appointed_on, resigned_on, corporate}] ONLY (everything else dropped here)."""
    out = []
    for r in as_list(as_dict(doc).get("items")):
        r = as_dict(r)
        name, role = text(r.get("name")), text(r.get("officer_role"))
        if name:
            out.append({"name": name[:200], "role": role or None, "appointed_on": iso_date(r.get("appointed_on")),
                        "resigned_on": iso_date(r.get("resigned_on")), "corporate": bool(_CORPORATE.search(role))})
    return out[:MAX_LISTED]


def parse_psc(doc: Any) -> list[dict[str, Any]]:
    """Cond 4: [{name, kind, natures_of_control, notified_on, ceased_on, corporate}] ONLY."""
    out = []
    for r in as_list(as_dict(doc).get("items")):
        r = as_dict(r)
        name, kind = text(r.get("name")), text(r.get("kind"))
        if name:
            out.append({"name": name[:200], "kind": kind or None,
                        "natures_of_control": [text(x) for x in as_list(r.get("natures_of_control")) if text(x)][:10],
                        "notified_on": iso_date(r.get("notified_on")), "ceased_on": iso_date(r.get("ceased_on")),
                        "corporate": bool(_CORPORATE.search(kind))})
    return out[:MAX_LISTED]


@register
class UkCompaniesHouse(Module):
    name = "uk_companies_house"
    title = "UK Companies House (company, officers, PSC)"
    description = (
        "Looks up a UK counterparty at Companies House (search by name or profile by company number) with its officers and "
        "persons with significant control, minimised to names, roles and dates."
    )
    category = "company_org"
    accepts = {T.ORG, T.KEYWORD}
    produces = {T.PERSON, T.ORG}
    tags = frozenset()
    reference = "https://developer-specs.company-information.service.gov.uk/"
    notice = (
        "Needs the company/team Companies House key recorded with a business plan (never an analyst's personal account). "
        "Officers and PSC are personal data on a public register: name, role and dates only, never investigated automatically. "
        + ATTRIBUTION
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # Companies House receives the company name or number
    hosts = ("api.company-information.service.gov.uk",)
    provider = "companies_house_api"
    sources = (SOURCE,)
    access_model = "free_auth_limited"
    requires_keys = ("companies_house",)  # cond 1
    max_requests = 4  # search + profile + officers + PSC
    expected_latency = 2.5
    timeout = 60.0
    min_interval = 0.5
    cache_ttl = CACHE_TTL
    max_pivots = MAX_PIVOTS * 2
    default_enabled = False  # cond 3

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if not ctx.has_key("companies_house"):
            return res.mark(Status.NEEDS_KEY, "Companies House key not configured (v3lum keys set companies_house --plan business)",
                            reason_code="needs_key")
        headers = {"Authorization": basic_auth(ctx.key("companies_house"))}
        value = " ".join(text(entity.value).split())
        number = company_number(value) if entity.type is T.KEYWORD else None
        if entity.type is T.KEYWORD and not number:
            return res.mark(Status.SKIPPED, "keywords are looked up only when shaped like a UK company number", reason_code="not_applicable")
        if number is None:
            hits = parse_search(ctx.http.get_json(search_url(value), headers=headers, source=SOURCE))
            exact = [h for h in hits if uk_name_key(h["title"]) == uk_name_key(value)]
            if not exact:
                if not hits:
                    return res.mark(Status.EMPTY, f"no UK company matches '{value}' at Companies House")
                res.attr("uk_company_candidates", hits[:5])
                res.attr("data_attribution", [ATTRIBUTION])
                return res
            number = exact[0]["company_number"]
            if len(hits) > 1:
                res.attr("uk_company_candidates", [h for h in hits if h["company_number"] != number][:5])
        profile = ctx.http.get_json(company_url(number), headers=headers, source=SOURCE, absent={404})
        if profile is None:
            return res.mark(Status.EMPTY, f"no UK company with number {number} at Companies House")
        company = parse_company(profile)
        if company is None:
            raise HttpError("unexpected Companies House profile: could not verify", 200, company_url(number))
        res.attr("uk_company", company)
        res.attr("data_attribution", [ATTRIBUTION])
        res.link(f"Companies House {number}", company["url"])
        officers = parse_officers(ctx.http.get_json(company_url(number, "officers"), headers=headers, source=SOURCE, absent={404}))
        psc = parse_psc(ctx.http.get_json(company_url(number, "psc"), headers=headers, source=SOURCE, absent={404}))
        if officers:
            res.attr("uk_officers", officers)
        if psc:
            res.attr("uk_psc", psc)
        label = company.get("name") or number
        for rows, relation, end_key, role_key in ((officers, "officer_of", "resigned_on", "role"), (psc, "psc_of", "ceased_on", "kind")):
            for row in [r for r in rows if not r.get(end_key)][:MAX_PIVOTS]:
                res.pivot(T.ORG if row["corporate"] else T.PERSON, row["name"], relation, confidence="confirmed", expand=False,
                          note=f"{row.get(role_key) or relation} of UK company {number} '{label}' per Companies House (name, role and dates only; "
                               "not investigated automatically)")
        res.raw = {"company": company, "officers": officers, "psc": psc}
        return res
