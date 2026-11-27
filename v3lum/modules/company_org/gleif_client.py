"""Shared GLEIF LEI API client (P220 cond 1): the one GLEIF client of V3LUM.

Used by the ``gleif`` module (P220, batch p2-G10-1) and meant for ``cnpj_name_resolver`` (P361, batch
p2-G10-3), which today still builds its own ``filter[fulltext]`` URL: moving it onto :class:`GleifClient`
and :func:`parse_lei_records` is the integration step recorded in the p2-G10-1 manifest. Nothing here is
a Module: it is a helper over ``ctx.http`` (no network of its own) plus pure, stdlib-only parsers of the
GLEIF JSON:API documents.

Rules it encodes (P220 final conditions):

* cond 1 - host ``api.gleif.org`` only, keyless, CC0 (courtesy attribution :data:`GLEIF_ATTRIBUTION`),
  documented 60 req/min: the registry provider ``gleif`` carries min_interval 1 s and the quota block.
* cond 2 - the ``filter[entity.registeredAs]`` filter always gets the FORMATTED CNPJ
  (``00.000.000/0001-91``): raw digits return 0 hits (verified live). :func:`cnpj_url` never sends digits.
* cond 3 - JSON:API page size <= 10 (:data:`PAGE_SIZE`); children are read from the first page only and
  capped at 10 (:data:`CHILDREN_CAP`).
* cond 7 - 401/403/429, timeouts, 5xx and error-in-200 bodies (a JSON:API ``errors`` member, a document
  without ``data``, HTML or truncated JSON) are "could not verify" and are never cached; a 404 is an
  absence only when it carries GLEIF's own JSON:API not-found body (a proxy or HTML 404 is an error).
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlencode

from v3lum.core.http import (
    AuthRequired,
    Blocked,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    QuotaExceeded,
    RateLimited,
)

SOURCE = "gleif.lei_api"
BASE = "https://api.gleif.org/api/v1"
HOST = "api.gleif.org"
ACCEPT = "application/vnd.api+json"
PAGE_SIZE = 10  # cond 3
CHILDREN_CAP = 10  # cond 3
MAX_REQUESTS = 4  # cond 3: record (or search), direct parent, ultimate parent, first page of children
CACHE_TTL = 86400  # LEI data moves slowly (golden copy republished several times a day)
RA_RECEITA = "RA000041"  # GLEIF registration authority code of the Receita Federal CNPJ register
GLEIF_ATTRIBUTION = "LEI data: GLEIF (CC0 1.0), attribution given as a courtesy - https://www.gleif.org"
HYPOTHESIS_CONFIDENCE = 0.5  # cond 4: name/keyword hits are hypotheses (<= 0.5)
RELATION_CONFIDENCE = 0.8
RELATIONS = ("direct-parent", "ultimate-parent", "direct-children")
EXCEPTION_RELATIONS = ("direct-parent-reporting-exception", "ultimate-parent-reporting-exception")
EXCEPTION_REASONS = {
    "NATURAL_PERSONS": "controlled by natural persons (not identified; never pursued)",
    "NON_CONSOLIDATING": "parent does not consolidate it",
    "NO_KNOWN_PERSON": "no known controlling person",
    "NON_PUBLIC": "parent information is not public",
    "BINDING_LEGAL_COMMITMENTS": "legal commitments prevent disclosure",
    "LEGAL_OBSTACLES": "legal obstacles prevent disclosure",
    "DISCLOSURE_DETRIMENTAL": "disclosure would be detrimental",
    "DETRIMENT_NOT_EXCLUDED": "detriment not excluded",
    "CONSENT_NOT_OBTAINED": "consent not obtained",
}
#: GLEIF entity category of sole proprietors: a natural person behind the record (LGPD): no address,
#: no name pivot.
NATURAL_PERSON_CATEGORIES = frozenset({"SOLE_PROPRIETOR"})

_LEI_RE = re.compile(r"^[0-9A-Z]{18}[0-9]{2}$")
_CNPJ_RE = re.compile(r"^[0-9A-Z]{12}[0-9]{2}$")


# --------------------------------------------------------------------------------------
# small coercions (untrusted JSON)
# --------------------------------------------------------------------------------------


def _s(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return ""
    return str(value).strip()


def _d(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def iso_date(value: Any) -> str | None:
    """'2026-08-07T07:20:59Z' | '2026-08-07' -> '2026-08-07'; anything else -> None."""
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", _s(value))
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else None


def fold(text: Any) -> str:
    t = unicodedata.normalize("NFKD", _s(text))
    return "".join(c for c in t if not unicodedata.combining(c)).upper()


# --------------------------------------------------------------------------------------
# identifiers
# --------------------------------------------------------------------------------------


def _cnpj_val(c: str) -> int:
    return ord(c) - 48  # '0'-'9' -> 0-9, 'A'-'Z' -> 17-42 (RFB alphanumeric CNPJ rule)


def cnpj_check_digits(base12: str) -> str:
    out = ""
    for weights in ((5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2), (6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)):
        r = sum(_cnpj_val(c) * weights[i] for i, c in enumerate(base12 + out)) % 11
        out += "0" if r < 2 else str(11 - r)
    return out


def normalize_cnpj(value: Any) -> str | None:
    """'00.000.000/0001-91' | '00000000000191' | '12.ABC.345/01DE-35' -> 14 characters when the check
    digits hold, else None."""
    c = re.sub(r"[\s./-]", "", _s(value)).upper()
    if not _CNPJ_RE.match(c) or c == c[0] * 14:
        return None
    return c if cnpj_check_digits(c[:12]) == c[12:] else None


def format_cnpj(value: Any) -> str | None:
    """14 characters -> 'NN.NNN.NNN/NNNN-NN', the only form ``registeredAs`` matches (cond 2)."""
    c = normalize_cnpj(value)
    return f"{c[:2]}.{c[2:5]}.{c[5:8]}/{c[8:12]}-{c[12:]}" if c else None


def lei_valid(lei: Any) -> bool:
    """ISO 17442 LEI: 20 alphanumerics, ISO 7064 MOD 97-10 (value mod 97 == 1)."""
    s = _s(lei).upper()
    if not _LEI_RE.match(s):
        return False
    return int("".join(str(int(c, 36)) for c in s)) % 97 == 1


# --------------------------------------------------------------------------------------
# URL builders (brackets percent-encoded; page size <= 10)
# --------------------------------------------------------------------------------------


def _query(pairs: list[tuple[str, str]]) -> str:
    return urlencode(pairs, quote_via=quote, safe="")


def cnpj_url(cnpj: Any) -> str:
    """cond 2: registeredAs always gets the FORMATTED CNPJ; raises ValueError for an invalid CNPJ."""
    formatted = format_cnpj(cnpj)
    if not formatted:
        raise ValueError("invalid CNPJ")
    return f"{BASE}/lei-records?" + _query([("filter[entity.registeredAs]", formatted), ("page[size]", str(PAGE_SIZE))])


def name_url(name: Any) -> str:
    """cond 4: exact company_name input -> filter[entity.legalName] (default scans)."""
    n = re.sub(r"\s+", " ", _s(name))
    if len(n) < 3:
        raise ValueError("company name too short")
    return f"{BASE}/lei-records?" + _query([("filter[entity.legalName]", n), ("page[size]", str(PAGE_SIZE))])


def fulltext_url(query: Any, *, country: str = "") -> str:
    """Keyword -> filter[fulltext] (same lei-records shape); optionally limited to one legal-address
    country (P361 uses 'BR'). Explicit selection only (cond 4)."""
    t = re.sub(r"\s+", " ", _s(query))
    if len(t) < 3:
        raise ValueError("search term too short")
    pairs = [("filter[fulltext]", t)]
    if country:
        pairs.append(("filter[entity.legalAddress.country]", country.upper()))
    pairs.append(("page[size]", str(PAGE_SIZE)))
    return f"{BASE}/lei-records?" + _query(pairs)


def fuzzy_url(query: Any) -> str:
    """cond 4: keyword -> fuzzycompletions on the legal name; explicit selection only."""
    t = re.sub(r"\s+", " ", _s(query))
    if len(t) < 3:
        raise ValueError("search term too short")
    return f"{BASE}/fuzzycompletions?" + _query([("field", "entity.legalName"), ("q", t)])


def record_url(lei: Any) -> str:
    if not lei_valid(lei):
        raise ValueError("invalid LEI")
    return f"{BASE}/lei-records/{_s(lei).upper()}"


def relation_url(lei: Any, relation: str) -> str:
    """cond 3: one relation request; children always with page[size]=10 (first page only)."""
    if relation not in RELATIONS + EXCEPTION_RELATIONS:
        raise ValueError("unknown relation")
    url = f"{record_url(lei)}/{relation}"
    if relation == "direct-children":
        url += "?" + _query([("page[size]", str(CHILDREN_CAP))])
    return url


# --------------------------------------------------------------------------------------
# parsers
# --------------------------------------------------------------------------------------


def relation_state(rel_obj: Any) -> str:
    """'present' when GLEIF links a related record, 'exception' when it links only a reporting
    exception, 'unknown' otherwise (verified live: a parent-less record links 'reporting-exception')."""
    links = _d(_d(rel_obj).get("links"))
    if any(k in links for k in ("lei-record", "relationship-record", "related", "relationship-records")):
        return "present"
    if "reporting-exception" in links:
        return "exception"
    return "unknown"


def _address(a: Any, *, lines: bool = True) -> dict[str, Any]:
    a = _d(a)
    out: dict[str, Any] = {
        "city": _s(a.get("city")) or None,
        "region": _s(a.get("region")) or None,
        "country": _s(a.get("country")).upper() or None,
        "postal_code": _s(a.get("postalCode")) or None,
    }
    if lines:
        out["lines"] = [x for x in (_s(v) for v in _l(a.get("addressLines"))) if x][:4]
    return out


def parse_lei_record(resource: Any) -> dict[str, Any] | None:
    """One ``lei-records`` resource -> normalised record (None when it carries no LEI)."""
    r = _d(resource)
    at = _d(r.get("attributes"))
    e = _d(at.get("entity"))
    reg = _d(at.get("registration"))
    lei = _s(at.get("lei") or r.get("id")).upper()
    if not lei:
        return None
    reg_at = _s(_d(e.get("registeredAt")).get("id")).upper() or None
    reg_as = _s(e.get("registeredAs")) or None
    jurisdiction = _s(e.get("jurisdiction")).upper() or None
    category = _s(e.get("category")).upper() or None
    cnpj = normalize_cnpj(reg_as) if reg_as and (reg_at == RA_RECEITA or jurisdiction == "BR") else None
    rel = _d(r.get("relationships"))
    natural = category in NATURAL_PERSON_CATEGORIES
    return {
        "lei": lei,
        "lei_valid": lei_valid(lei),
        "legal_name": _s(_d(e.get("legalName")).get("name")) or None,
        "other_names": [n for n in (_s(_d(x).get("name")) for x in _l(e.get("otherNames"))) if n][:5],
        "registration_status": _s(reg.get("status")).upper() or None,
        "entity_status": _s(e.get("status")).upper() or None,
        "last_update": iso_date(reg.get("lastUpdateDate")),
        "initial_registration": iso_date(reg.get("initialRegistrationDate")),
        "next_renewal": iso_date(reg.get("nextRenewalDate")),
        "corroboration": _s(reg.get("corroborationLevel")).upper() or None,
        "jurisdiction": jurisdiction,
        "registered_at": reg_at,
        "registered_as": reg_as,
        "cnpj": cnpj,
        "legal_form": _s(_d(e.get("legalForm")).get("id")) or None,
        "category": category,
        "natural_person": natural,
        # a sole proprietor is a natural person: never keep the address (LGPD); companies keep city/country
        "legal_address": None if natural else _address(e.get("legalAddress")),
        "successor_lei": _s(_d(e.get("successorEntity")).get("lei")).upper() or None,
        "bic": [b for b in (_s(x) for x in _l(at.get("bic"))) if b][:10],
        "relations": {k: relation_state(rel.get(k)) for k in RELATIONS},
    }


def error_in_body(doc: Any) -> str | None:
    """cond 7: a JSON:API ``errors`` member, a non-object or a document without ``data`` in a 2xx."""
    if not isinstance(doc, dict):
        return "response is not a JSON:API document"
    errs = _l(doc.get("errors"))
    if errs:
        e = _d(errs[0])
        detail = _s(e.get("title")) or _s(e.get("detail"))
        return f"error inside HTTP 200 ({_s(e.get('status')) or '?'} {detail})".strip()
    if "data" not in doc:
        return "JSON:API document without a data member"
    return None


def is_not_found_body(doc: Any) -> bool:
    """cond 7: GLEIF's own 404 body ``{'errors': [{'status': '404', ...}]}``."""
    return any(_s(_d(e).get("status")) == "404" for e in _l(_d(doc).get("errors")))


def parse_lei_records(doc: Any) -> dict[str, Any]:
    """A lei-records collection (or a single resource) -> {records, total, has_more, golden_copy}."""
    o = _d(doc)
    data = o.get("data")
    if isinstance(data, dict):
        data = [data]
    records = [x for x in (parse_lei_record(r) for r in _l(data)) if x]
    meta = _d(o.get("meta"))
    total = _int(_d(meta.get("pagination")).get("total"))
    return {
        "records": records,
        "total": total if total is not None else len(records),
        "has_more": bool(_d(o.get("links")).get("next")),
        "golden_copy": iso_date(_d(meta.get("goldenCopy")).get("publishDate")),
    }


def parse_reporting_exception(doc: Any) -> dict[str, Any] | None:
    """Why GLEIF has no parent (e.g. NON_CONSOLIDATING): shown on the summary line, never pursued."""
    at = _d(_d(_d(doc).get("data")).get("attributes"))
    reason = _s(at.get("reason")).upper() or None
    category = _s(at.get("category")).upper() or None
    if not (reason or category):
        return None
    return {"category": category, "reason": reason, "reason_text": EXCEPTION_REASONS.get(reason or "", reason)}


def parse_children(doc: Any, cap: int = CHILDREN_CAP) -> dict[str, Any]:
    """cond 3: first page of direct children, capped at 10."""
    parsed = parse_lei_records(doc)
    kids = parsed["records"][:cap]
    return {"children": kids, "total": parsed["total"], "truncated": parsed["has_more"] or (parsed["total"] or 0) > len(kids)}


def parse_fuzzycompletions(doc: Any, cap: int = PAGE_SIZE) -> list[dict[str, Any]]:
    """cond 4: keyword hits are hypotheses (entries without an LEI are kept as names only)."""
    out: list[dict[str, Any]] = []
    for item in _l(_d(doc).get("data")):
        it = _d(item)
        value = _s(_d(it.get("attributes")).get("value"))
        if not value:
            continue
        lei = _s(_d(_d(_d(it.get("relationships")).get("lei-records")).get("data")).get("id")).upper()
        out.append({"legal_name": value, "lei": lei if lei_valid(lei) else None})
        if len(out) >= cap:
            break
    return out


_LEGAL_SUFFIX = ((r"\bS\s*/\s*A\b", "SA"), (r"\bS\s*\.\s*A\s*\.?", "SA"), (r"\bLTDA\b\.?", "LTDA"))


def norm_company_name(name: Any) -> str:
    """Accent/punctuation-insensitive legal name ('S.A.' == 'SA') for exact-name comparison."""
    t = fold(name)
    for pat, rep in _LEGAL_SUFFIX:
        t = re.sub(pat, rep, t)
    return re.sub(r"\s+", " ", re.sub(r"[^A-Z0-9 ]", " ", t)).strip()


def classify_name_hits(query: Any, records: list[dict[str, Any]]) -> dict[str, Any]:
    """cond 4: a unique normalised-equal legal name is an 'exact_name' match; several or none equal
    are 'ambiguous' / 'none' and every candidate stays a hypothesis."""
    qn = norm_company_name(query)
    exact = [r for r in records if norm_company_name(r.get("legal_name")) == qn]
    if len(exact) == 1:
        return {"match": "exact_name", "record": exact[0], "candidates": []}
    cands = exact or list(records)
    return {"match": "ambiguous" if cands else "none", "record": None, "candidates": cands}


def cnpj_matches(records: list[dict[str, Any]], cnpj: Any) -> list[dict[str, Any]]:
    """cond 2/5: records whose registeredAs equals the queried CNPJ (the only exact CNPJ match)."""
    c = normalize_cnpj(cnpj)
    return [r for r in records if c and r.get("cnpj") == c]


def relation_plan(record: dict[str, Any], used: int = 1, max_requests: int = MAX_REQUESTS) -> list[str]:
    """cond 3: relation requests allowed after ``used`` record/search requests. A parent slot fetches the
    parent when GLEIF links one, or the reporting exception when only an exception is linked; children
    are fetched when linked. Never more than ``max_requests`` in total."""
    rel = _d(_d(record).get("relations"))
    plan: list[str] = []
    for kind in ("direct-parent", "ultimate-parent"):
        state = rel.get(kind)
        if state == "present":
            plan.append(kind)
        elif state == "exception":
            plan.append(kind + "-reporting-exception")
    if rel.get("direct-children") == "present":
        plan.append("direct-children")
    return plan[: max(0, max_requests - used)]


def entity_view(rec: dict[str, Any] | None) -> dict[str, Any] | None:
    """Compact view of a related record for attributes (no address)."""
    if not rec:
        return None
    return {k: rec.get(k) for k in ("lei", "legal_name", "jurisdiction", "registration_status", "cnpj", "category") if rec.get(k)}


def _parent_text(parent: dict[str, Any] | None, exception: dict[str, Any] | None, state: str) -> str:
    if parent:
        return f"{parent.get('legal_name') or '?'} ({parent.get('lei')})"
    if exception:
        return f"none reported ({exception.get('reason') or exception.get('category')})"
    if state == "unverified":
        return "could not verify"
    if state in ("none", "exception"):
        return "none reported"
    return "not checked"


def summary_line(record: dict[str, Any], parents: dict[str, Any]) -> str:
    """cond 6: LEI, legal name, registration status, last update, direct and ultimate parent on one line."""
    return " | ".join([
        f"LEI {record.get('lei')}",
        record.get("legal_name") or "?",
        record.get("registration_status") or "?",
        f"updated {record.get('last_update') or '?'}",
        "direct parent: " + _parent_text(parents.get("direct"), parents.get("direct_exception"), parents.get("direct_state", "")),
        "ultimate parent: " + _parent_text(parents.get("ultimate"), parents.get("ultimate_exception"), parents.get("ultimate_state", "")),
    ])


# --------------------------------------------------------------------------------------
# the client
# --------------------------------------------------------------------------------------


@dataclass
class GleifAnswer:
    """Outcome of one GLEIF request. ``state``: ok | empty | blocked | rate_limited | quota | error;
    ``reason_code`` is a canonical A3 code for the non-ok states."""

    state: str
    doc: Any = None
    reason: str = ""
    reason_code: str = ""
    status: int = 0
    url: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.state == "ok"

    @property
    def could_not_verify(self) -> bool:
        return self.state not in ("ok", "empty")


def _decode(content: Any) -> Any:
    try:
        raw = bytes(content or b"")
        if raw.lstrip()[:1] not in (b"{", b"["):
            return None
        return json.loads(raw.decode("utf-8"))
    except (ValueError, TypeError, UnicodeDecodeError):
        return None


def _cacheable(resp: Any) -> bool:
    """Only usable documents are cached: a 200 JSON:API document with ``data``, or GLEIF's own 404."""
    status = int(getattr(resp, "status", 0) or 0)
    doc = _decode(getattr(resp, "content", b""))
    if status == 200:
        return doc is not None and error_in_body(doc) is None
    if status == 404:
        return doc is not None and is_not_found_body(doc)
    return False


class GleifClient:
    """GLEIF requests through ``ctx.http`` (host allow-list, max_requests, min_interval, quota and the
    run deadline stay the core's). :meth:`fetch` never raises for an HTTP failure: it returns a
    :class:`GleifAnswer` the caller maps to a status; RequestCapReached, Cancelled and the run deadline
    propagate (the engine keeps what was built)."""

    def __init__(self, ctx: Any, *, source: str = SOURCE, ttl: int | None = CACHE_TTL) -> None:
        self.ctx = ctx
        self.source = source
        self.ttl = ttl

    def fetch(self, url: str, *, what: str = "LEI record") -> GleifAnswer:
        http = self.ctx.http
        try:
            resp = http.get(url, source=self.source, headers={"Accept": ACCEPT}, ttl=self.ttl, cache_if=_cacheable)
        except (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError, DeadlineExceeded) as exc:
            return self._failure(exc, url, what)
        try:
            http.check(resp)
        except HttpError as exc:
            if getattr(resp, "status", 0) == 404 and type(exc) is HttpError:
                doc = _decode(resp.content)
                if doc is not None and is_not_found_body(doc):
                    return GleifAnswer("empty", doc, f"GLEIF: no {what} (HTTP 404)", status=404, url=url)
                return GleifAnswer("error", None, "GLEIF: HTTP 404 without GLEIF's JSON:API not-found body: could not verify",
                                   "error", 404, url)
            return self._failure(exc, url, what)
        except (RateLimited, QuotaExceeded, Blocked, AuthRequired, NetworkError) as exc:
            return self._failure(exc, url, what)
        doc = _decode(resp.content)
        if doc is None:
            http.evict(resp)
            return GleifAnswer("error", None, "GLEIF: HTML or invalid JSON where a JSON:API document was expected: could not verify",
                               "error", int(resp.status), url)
        problem = error_in_body(doc)
        if problem:
            http.evict(resp)
            return GleifAnswer("error", None, f"GLEIF: {problem}: could not verify", "error", int(resp.status), url)
        if doc.get("data") in ([], None):
            return GleifAnswer("empty", doc, f"GLEIF: no {what}", status=int(resp.status), url=url)
        return GleifAnswer("ok", doc, status=int(resp.status), url=url)

    def _failure(self, exc: Exception, url: str, what: str) -> GleifAnswer:
        if isinstance(exc, DeadlineExceeded):
            remaining = self.ctx.remaining() if callable(getattr(self.ctx, "remaining", None)) else None
            if remaining is not None and remaining <= 0:
                raise exc  # the run deadline itself: the engine maps it (ERROR timeout)
            return GleifAnswer("error", None, f"GLEIF {what}: no answer in time ({exc}): could not verify", "timeout", url=url)
        status = int(getattr(exc, "status", 0) or 0)
        if isinstance(exc, RateLimited):
            return GleifAnswer("rate_limited", None, f"GLEIF {what}: rate limited ({exc}): could not verify", "rate_limited", status, url)
        if isinstance(exc, QuotaExceeded):
            return GleifAnswer("quota", None, f"GLEIF {what}: quota exhausted ({exc}): could not verify", "quota", status, url)
        if isinstance(exc, Blocked):
            code = str(getattr(exc, "reason_code", "") or "challenge")
            if code not in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host"):
                code = "challenge"
            return GleifAnswer("blocked", None, f"GLEIF {what}: blocked ({exc}): could not verify", code, status, url)
        if isinstance(exc, AuthRequired):
            return GleifAnswer("blocked", None, f"GLEIF {what}: HTTP {status or '401/403'} for a keyless API: could not verify",
                               "challenge", status, url)
        if isinstance(exc, NetworkError):
            kind = str(getattr(exc, "kind", "") or "").lower()
            code = "timeout" if "timeout" in kind or "timed out" in str(exc).lower() else "error"
            return GleifAnswer("error", None, f"GLEIF {what}: {exc}: could not verify", code, status, url)
        return GleifAnswer("error", None, f"GLEIF {what}: {exc}: could not verify", "error", status, url)


__all__ = [
    "ACCEPT",
    "BASE",
    "CHILDREN_CAP",
    "GLEIF_ATTRIBUTION",
    "HOST",
    "MAX_REQUESTS",
    "PAGE_SIZE",
    "SOURCE",
    "GleifAnswer",
    "GleifClient",
    "classify_name_hits",
    "cnpj_matches",
    "cnpj_url",
    "entity_view",
    "error_in_body",
    "format_cnpj",
    "fulltext_url",
    "fuzzy_url",
    "is_not_found_body",
    "lei_valid",
    "name_url",
    "normalize_cnpj",
    "parse_children",
    "parse_fuzzycompletions",
    "parse_lei_record",
    "parse_lei_records",
    "parse_reporting_exception",
    "record_url",
    "relation_plan",
    "relation_url",
    "summary_line",
]
