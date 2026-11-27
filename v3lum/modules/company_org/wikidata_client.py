"""Wikidata client of P224 (batch p3-G10-1), the one client P224 cond 1 asks to share with P361.

Pure builders and parsers (no I/O): the calling module sends the requests through its own ``ctx.http`` over
the seed provider ``wikidata`` (identifying UA ``V3LUM/<version> (+<contact_email>) python-requests`` on
www.wikidata.org and query.wikidata.org, min_interval 1 s). P361 (``cnpj_name_resolver_wikidata``) shipped
a minimal P6204 search before this client existed; its migration to these helpers is recorded in
docs/backlog/p3-G10-1.md (another batch's file).

* Action API: :func:`wbsearchentities_url` / :func:`parse_search` (labels, aliases, match type);
  :func:`mediawiki_error` reads the error object MediaWiki returns inside HTTP 200 bodies.
* WDQS: free-form SPARQL is never sent. :data:`TEMPLATES` holds the only queries (cond 2): ``claims``
  (organisation check through ``P31/P279*`` of organization/business plus P6204 CNPJ, P856 official website,
  P749 parent and P355 subsidiary of at most 10 candidates), ``domain`` (organisation items whose P856 is a
  domain) and ``person`` (human check and P856 of analyst-typed public figures). Every template ends in
  ``LIMIT 20``; :func:`sparql_url` refuses anything else; inputs are validated (QID, host name).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from v3lum.modules.company_org.registry_text import as_dict, as_list, norm_company_name, text

API_URL = "https://www.wikidata.org/w/api.php"
SPARQL_URL = "https://query.wikidata.org/sparql"
ENTITY_URL = "https://www.wikidata.org/wiki/{qid}"
SPARQL_LIMIT = 20  # cond 2
SPARQL_TIMEOUT = 20.0  # cond 2 (client side; WDQS's own limit is 60 s)
MAX_CANDIDATES = 10
LICENCE = "Wikidata (CC0)"
_QID = re.compile(r"^Q[1-9]\d{0,9}$")
_HOST = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.(?!-)[a-z0-9-]{1,63})+$")

_CLAIMS = (
    "SELECT ?item ?itemLabel ?isOrg ?rel ?value ?valueLabel WHERE {{ VALUES ?item {{ {values} }} "
    "BIND(EXISTS {{ VALUES ?cls {{ wd:Q43229 wd:Q4830453 }} ?item wdt:P31/wdt:P279* ?cls }} AS ?isOrg) "
    '{{ ?item wdt:P6204 ?value . BIND("P6204" AS ?rel) }} UNION {{ ?item wdt:P856 ?value . BIND("P856" AS ?rel) }} '
    'UNION {{ ?item wdt:P749 ?value . BIND("P749" AS ?rel) }} UNION {{ ?item wdt:P355 ?value . BIND("P355" AS ?rel) }} '
    'UNION {{ BIND("none" AS ?rel) }} '
    'SERVICE wikibase:label {{ bd:serviceParam wikibase:language "pt,en" . }} }} LIMIT {limit}'
)
_DOMAIN = (
    "SELECT ?item ?itemLabel ?site WHERE {{ VALUES ?site {{ {sites} }} ?item wdt:P856 ?site . "
    'SERVICE wikibase:label {{ bd:serviceParam wikibase:language "pt,en" . }} }} LIMIT {limit}'
)
_PERSON = (
    "SELECT ?item ?itemLabel ?isHuman ?rel ?value WHERE {{ VALUES ?item {{ {values} }} "
    "BIND(EXISTS {{ ?item wdt:P31 wd:Q5 }} AS ?isHuman) "
    '{{ ?item wdt:P856 ?value . BIND("P856" AS ?rel) }} UNION {{ BIND("none" AS ?rel) }} '
    'SERVICE wikibase:label {{ bd:serviceParam wikibase:language "pt,en" . }} }} LIMIT {limit}'
)
TEMPLATES = {"claims": _CLAIMS, "domain": _DOMAIN, "person": _PERSON}


# --------------------------------------------------------------------------------------
# Action API
# --------------------------------------------------------------------------------------


def wbsearchentities_url(query: str, *, language: str = "pt", limit: int = MAX_CANDIDATES) -> str:
    q = re.sub(r"\s+", " ", text(query))
    if not q or len(q) > 250:
        raise ValueError("unusable search text")
    if not re.fullmatch(r"[a-z]{2,3}(?:-[a-z]{2,4})?", language):
        raise ValueError("bad language")
    params = [("action", "wbsearchentities"), ("search", q), ("language", language), ("uselang", language), ("type", "item"),
              ("limit", str(max(1, min(int(limit), MAX_CANDIDATES)))), ("format", "json")]
    return API_URL + "?" + urlencode(params, quote_via=quote)


def mediawiki_error(doc: Any) -> tuple[str, str] | None:
    """(kind 'rate_limited' | 'error', reason) for an error object inside an HTTP 200 body, else None."""
    err = as_dict(as_dict(doc).get("error"))
    if not err:
        return None
    code = text(err.get("code"))
    if code in ("maxlag", "ratelimited", "too-many-requests"):
        return "rate_limited", f"Wikidata API: {code}"
    return "error", f"Wikidata API error {code or '?'}: {text(err.get('info'))[:120]}"


def parse_search(doc: Any) -> list[dict[str, Any]]:
    """wbsearchentities -> [{qid, label, description, match_type, match_text, aliases}]. Raises ValueError
    when the body is not a search answer (could not verify)."""
    if not isinstance(doc, dict) or not isinstance(doc.get("search"), list):
        raise ValueError("Wikidata search answer without a search list")
    out = []
    for r in doc["search"]:
        r = as_dict(r)
        qid = text(r.get("id"))
        if not _QID.match(qid):
            continue
        m = as_dict(r.get("match"))
        out.append({"qid": qid, "label": text(r.get("label")) or None, "description": text(r.get("description")) or None,
                    "match_type": text(m.get("type")) or None, "match_text": text(m.get("text")) or None,
                    "aliases": [text(a) for a in as_list(r.get("aliases")) if text(a)]})
    return out[:MAX_CANDIDATES]


def exact_match(query: str, hit: dict[str, Any]) -> bool:
    """Cond 3: the normalised query equals the label, the matched text or an alias (legal forms kept)."""
    q = norm_company_name(query)
    if not q:
        return False
    names = [hit.get("label"), hit.get("match_text") if hit.get("match_type") in ("label", "alias") else None, *(hit.get("aliases") or [])]
    return any(n and norm_company_name(n) == q for n in names)


# --------------------------------------------------------------------------------------
# WDQS fixed templates
# --------------------------------------------------------------------------------------


def _qids(qids: Iterable[str]) -> list[str]:
    out = [q for q in dict.fromkeys(text(q) for q in qids) if _QID.match(q)][:MAX_CANDIDATES]
    if not out:
        raise ValueError("no valid QIDs")
    return out


def claims_query(qids: Iterable[str]) -> str:
    return _CLAIMS.format(values=" ".join("wd:" + q for q in _qids(qids)), limit=SPARQL_LIMIT)


def person_query(qids: Iterable[str]) -> str:
    return _PERSON.format(values=" ".join("wd:" + q for q in _qids(qids)), limit=SPARQL_LIMIT)


def domain_query(domain: str) -> str:
    """Organisation items whose P856 is the domain (http/https, with/without www, with/without '/')."""
    host = text(domain).lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    if not _HOST.match(host):
        raise ValueError("invalid domain")
    sites = [f"<{scheme}://{h}{slash}>" for scheme in ("https", "http") for h in (host, "www." + host) for slash in ("/", "")]
    return _DOMAIN.format(sites=" ".join(sites), limit=SPARQL_LIMIT)


def sparql_url(query: str) -> str:
    """Only the fixed templates, ending in LIMIT <= 20, are ever sent (cond 2)."""
    m = re.search(r"LIMIT (\d+)\s*$", query)
    if not m or int(m.group(1)) > SPARQL_LIMIT or not query.startswith("SELECT ?item ?itemLabel "):
        raise ValueError("only fixed templates with LIMIT <= 20 are sent (P224 cond 2)")
    return SPARQL_URL + "?" + urlencode([("format", "json"), ("query", query)], quote_via=quote)


def _qid_of(uri: Any) -> str | None:
    m = re.search(r"/entity/(Q\d+)$", text(uri))
    return m.group(1) if m else None


def _rows(doc: Any) -> list[dict[str, str]]:
    if not isinstance(doc, dict) or not isinstance(as_dict(doc.get("results")).get("bindings"), list):
        raise ValueError("WDQS answer without results.bindings")
    return [{k: text(as_dict(v).get("value")) for k, v in as_dict(b).items()} for b in doc["results"]["bindings"]]


def parse_claims(doc: Any) -> tuple[dict[str, dict[str, Any]], bool]:
    """claims / person template answers -> ({qid: {qid, label, is_org, is_human, cnpj, websites, parents,
    subsidiaries}}, truncated)."""
    rows = _rows(doc)
    items: dict[str, dict[str, Any]] = {}
    for r in rows:
        qid = _qid_of(r.get("item"))
        if not qid:
            continue
        it = items.setdefault(qid, {"qid": qid, "label": r.get("itemLabel") or None, "is_org": False, "is_human": False, "cnpj": [],
                                    "websites": [], "parents": [], "subsidiaries": []})
        it["is_org"] = it["is_org"] or r.get("isOrg") == "true"
        it["is_human"] = it["is_human"] or r.get("isHuman") == "true"
        rel, value = r.get("rel"), r.get("value")
        if not value:
            continue
        if rel == "P6204" and value not in it["cnpj"]:
            it["cnpj"].append(value)
        elif rel == "P856" and value not in it["websites"]:
            it["websites"].append(value)
        elif rel in ("P749", "P355"):
            sub = {"qid": _qid_of(value), "label": r.get("valueLabel") or None}
            if sub["qid"] and sub["label"] and not _QID.match(sub["label"]):
                it["parents" if rel == "P749" else "subsidiaries"].append(sub)
    return items, len(rows) >= SPARQL_LIMIT


def parse_domain_items(doc: Any) -> list[dict[str, Any]]:
    """domain template answer -> [{qid, label, site}]."""
    out = []
    for r in _rows(doc):
        qid = _qid_of(r.get("item"))
        if qid:
            out.append({"qid": qid, "label": r.get("itemLabel") or None, "site": r.get("site") or None})
    return out


def host_of(url: Any) -> str | None:
    try:
        host = (urlsplit(text(url)).hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    return host if _HOST.match(host) else None


def cnpj_digits(value: Any) -> str:
    return re.sub(r"\D", "", text(value))
