"""P223 SEC EDGAR: did a counterparty disclose a material cybersecurity incident? (batch p3-G10-1).

Council P223 final conditions, as implemented:

1. Identifying UA (P326): the provider ``sec`` profile is ``user_agent: contact`` on www.sec.gov,
   data.sec.gov and efts.sec.gov (the core sends ``V3LUM/<version> (+<contact_email>)`` there only).
   Without setting ``contact_email`` (a team role mailbox) the run is SKIPPED ``config`` 'needs contact UA';
   no contact is ever made up.
2. Rate <= 2 req/s: min_interval 0.5 s on every SEC host and a provider budget of 2 req/s (quota safety
   margin 0.2 of SEC's 10 req/s). SEC's 403 'Request Rate Threshold Exceeded / Automated access ... must
   comply' page is the provider marker ``sec_fair_access_block`` -> BLOCKED with the UA hint (the host is
   then short-circuited for the rest of the investigation - the backoff), never 'no filings'.
3. ``company_tickers.json`` is the daily dataset ``sec_company_tickers`` matched locally (no disclosure for
   that step); the CIK is padded to 10 digits for ``data.sec.gov/submissions``.
4. Full-text search (efts.sec.gov) only for the counterparty name, first page only, at most 10 hits per
   entity, 8-K/8-K/A filings with Item 1.05 (material cybersecurity incident) and 6-K filed by the
   counterparty itself (foreign issuers). EFTS has no grouping (parentheses become literal phrases): the
   query is ``"<name>" "Item 1.05" OR "cybersecurity incident"`` with fixed phrases only, and the item
   filter runs on the returned page.
5. Output: CIK/ticker of the registrant (``sec_company``) and cyber-incident disclosures (form, date, company,
   filing URL) as LOW (the registrant's own Item 1.05) or INFO (mentions) supplier-incident context.
   Name-to-company matches are POSSIBLE unless the input is the ticker (CONFIRMED). Filing metadata and
   links only: no filing body is fetched or stored.
6. Opt-in (default_enabled=False); company_name input, keyword only when selected explicitly. US government
   work, public domain.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from v3lum.core.datasets import DatasetError, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import Blocked, HttpError, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.company_org.registry_text import as_dict, as_int, as_list, iso_date, name_core, norm_company_name, text

TICKERS_URL = "https://www.sec.gov/files/company_tickers.json"
SUBMISSIONS_URL = "https://data.sec.gov/submissions/CIK{cik10}.json"
EFTS_URL = "https://efts.sec.gov/LATEST/search-index"
ARCHIVE_URL = "https://www.sec.gov/Archives/edgar/data/{cik}/{acc}/{doc}"
INDEX_URL = "https://www.sec.gov/Archives/edgar/data/{cik}/{acc}/{accession}-index.htm"
DATASET = "sec_company_tickers"
SOURCE_TICKERS = "sec.company_tickers"
SOURCE_SUBMISSIONS = "sec.submissions"
SOURCE_EFTS = "sec.efts"
ITEM_105_EFFECTIVE = "2023-12-18"  # Form 8-K Item 1.05 effective date
EFTS_CAP = 10  # cond 4
CYBER_PHRASES = ("Item 1.05", "cybersecurity incident")
INCIDENT_FORMS = ("8-K", "8-K/A")
FOREIGN_FORMS = ("6-K", "6-K/A")
CACHE_TTL = 86400
DAY = 86400
UA_HINT = ("needs contact UA: set contact_email to the team role mailbox (v3lum config set contact_email <role mailbox>) - SEC fair "
           "access requires an identifying User-Agent")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_TICKER = re.compile(r"^[A-Z][A-Z0-9.\-]{0,9}$")


def cik10(value: Any) -> str | None:
    """CIK -> 10-digit zero-padded string, or None."""
    s = re.sub(r"^CIK", "", text(value), flags=re.I).strip()
    if not re.fullmatch(r"\d{1,10}", s) or int(s) <= 0:
        return None
    return f"{int(s):010d}"


# --------------------------------------------------------------------------------------
# company_tickers.json (daily dataset, local matching)
# --------------------------------------------------------------------------------------


def parse_tickers(doc: Any) -> list[dict[str, Any]]:
    """{"0": {cik_str, ticker, title}, ...} -> [{cik10, ticker, title}]."""
    values = doc.values() if isinstance(doc, dict) else (doc if isinstance(doc, list) else [])
    rows = []
    for v in values:
        v = as_dict(v)
        c, t, title = cik10(v.get("cik_str")), text(v.get("ticker")).upper(), text(v.get("title"))
        if c and (t or title):
            rows.append({"cik10": c, "ticker": t or None, "title": title or None})
    return rows


def _validate_tickers(path: Path) -> bool:
    rows = parse_tickers(json.loads(Path(path).read_text(encoding="utf-8")))
    if len(rows) < 5:
        raise ValueError(f"company_tickers.json with {len(rows)} usable rows")
    return True


register_dataset(
    DATASET,
    TICKERS_URL,
    ttl=DAY,
    description="SEC company_tickers.json (CIK, ticker, title) matched locally by sec_edgar (P223 cond 3)",
    licence="U.S. Government work (public domain)",
    terms_class="open",
    attribution="U.S. Securities and Exchange Commission (EDGAR)",
    provider="sec",
    source=SOURCE_TICKERS,
    validate=_validate_tickers,
    min_bytes=200,
    expect="json",
    max_bytes=4_000_000,
    large=False,
)


def match_company(value: str, rows: list[dict[str, Any]], *, ticker: bool = False) -> list[dict[str, Any]]:
    """Cond 3/5: ticker -> CONFIRMED; exact normalised title or core name -> POSSIBLE. Deduplicated by CIK."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(cands: list[dict[str, Any]], how: str, confidence: str) -> None:
        for r in cands:
            if r["cik10"] not in seen:
                seen.add(r["cik10"])
                out.append({**r, "match": how, "confidence": confidence})

    if ticker:
        add([r for r in rows if r.get("ticker") == text(value).upper()], "ticker", "confirmed")
        return out
    exact, core = norm_company_name(value), name_core(value)
    add([r for r in rows if r.get("title") and norm_company_name(r["title"]) == exact], "name_exact", "possible")
    if core and len(core) >= 3:
        add([r for r in rows if r.get("title") and name_core(r["title"]) == core], "name_core", "possible")
    return out


# --------------------------------------------------------------------------------------
# submissions
# --------------------------------------------------------------------------------------


def filing_url(cik: Any, accession: Any, document: Any) -> str | None:
    c, acc = cik10(cik), text(accession)
    if not c or not re.fullmatch(r"\d{10}-\d{2}-\d{6}", acc) or not text(document):
        return None
    return ARCHIVE_URL.format(cik=int(c), acc=acc.replace("-", ""), doc=quote(text(document), safe="/._-"))


def filing_index_url(cik: Any, accession: Any) -> str | None:
    c, acc = cik10(cik), text(accession)
    if not c or not re.fullmatch(r"\d{10}-\d{2}-\d{6}", acc):
        return None
    return INDEX_URL.format(cik=int(c), acc=acc.replace("-", ""), accession=acc)


def _items(value: Any) -> list[str]:
    if isinstance(value, list):
        return [text(x) for x in value if text(x)]
    return [x.strip() for x in text(value).split(",") if x.strip()]


def parse_submissions(doc: Any) -> dict[str, Any] | None:
    """Submissions JSON -> company facts + recent filings metadata (addresses, phone, EIN never kept)."""
    if not isinstance(doc, dict) or not cik10(doc.get("cik")):
        return None
    c = cik10(doc.get("cik"))
    recent = as_dict(as_dict(doc.get("filings")).get("recent"))
    forms = as_list(recent.get("form"))
    filings = []
    for i, form in enumerate(forms):
        def col(key: str, i: int = i) -> Any:
            arr = as_list(recent.get(key))
            return arr[i] if i < len(arr) else None

        acc, doc_name = text(col("accessionNumber")), text(col("primaryDocument"))
        filings.append({"accession": acc or None, "form": text(form), "filing_date": iso_date(col("filingDate")), "items": _items(col("items")),
                        "url": filing_url(c, acc, doc_name), "index_url": filing_index_url(c, acc)})
    return {
        "cik": c, "name": text(doc.get("name")) or None, "tickers": [text(t).upper() for t in as_list(doc.get("tickers")) if text(t)],
        "exchanges": [text(x) for x in as_list(doc.get("exchanges")) if text(x)], "sic": text(doc.get("sic")) or None,
        "sic_description": text(doc.get("sicDescription")) or None, "state_of_incorporation": text(doc.get("stateOfIncorporation")) or None,
        "former_names": [text(as_dict(f).get("name")) for f in as_list(doc.get("formerNames")) if text(as_dict(f).get("name"))][:10],
        "filings": filings, "older_pages": len(as_list(as_dict(doc.get("filings")).get("files"))),
    }


def own_disclosures(facts: dict[str, Any], since: str = ITEM_105_EFFECTIVE) -> list[dict[str, Any]]:
    """The registrant's own 8-K/8-K/A filings carrying Item 1.05 (recent filings of the submissions file)."""
    out = []
    for f in facts.get("filings") or []:
        if f.get("form") in INCIDENT_FORMS and "1.05" in (f.get("items") or []) and (f.get("filing_date") or "") >= since:
            out.append({"adsh": f.get("accession"), "form": f.get("form"), "filing_date": f.get("filing_date"), "items": f.get("items"),
                        "company": facts.get("name"), "cik": facts.get("cik"), "relation": "own_cik", "kind": "item_1_05",
                        "url": f.get("url"), "index_url": f.get("index_url"), "origin": "submissions"})
    return out


# --------------------------------------------------------------------------------------
# EFTS full-text search
# --------------------------------------------------------------------------------------


def efts_query(name: str) -> str:
    """Cond 4: '"<name>" "Item 1.05" OR "cybersecurity incident"' - parentheses, quotes and backslashes removed
    (EFTS turns parentheses into literal phrases)."""
    n = re.sub(r"\s+", " ", re.sub(r'["()\\]', " ", text(name))).strip()
    if not n or len(n) > 150 or re.fullmatch(r"(?i)(and|or|not)", n):
        raise ValueError("unusable counterparty name for EFTS")
    return f'"{n}" "{CYBER_PHRASES[0]}" OR "{CYBER_PHRASES[1]}"'


def efts_url(name: str, enddt: str) -> str:
    """First page only (no 'from'), root forms 8-K (covers 8-K/A) and 6-K, since the Item 1.05 date."""
    params = [("q", efts_query(name)), ("forms", "8-K,6-K"), ("dateRange", "custom"), ("startdt", ITEM_105_EFFECTIVE), ("enddt", enddt)]
    return EFTS_URL + "?" + urlencode(params, quote_via=quote)


_DISPLAY = re.compile(r"^(?P<rest>.*?)\s*\(CIK\s*(?P<cik>\d{1,10})\)\s*$")
_TICKERS = re.compile(r"^(?P<name>.*?)\s+\((?P<t>[A-Z0-9.\-]+(?:,\s*[A-Z0-9.\-]+)*)\)\s*$")


def parse_display_name(value: Any) -> dict[str, Any]:
    """'NCR Voyix Corp  (VYX, NCRRP)  (CIK 0000070866)' -> {name, tickers, cik}."""
    s = text(value)
    m = _DISPLAY.match(s)
    if not m:
        return {"name": s or None, "tickers": [], "cik": None}
    rest, tickers = m.group("rest").strip(), []
    t = _TICKERS.match(rest)
    if t:
        rest, tickers = t.group("name").strip(), [x.strip() for x in t.group("t").split(",") if x.strip()]
    return {"name": rest or None, "tickers": tickers, "cik": cik10(m.group("cik"))}


def parse_efts(doc: Any) -> dict[str, Any]:
    """EFTS answer -> {total, relation, hits [...]}. Raises ValueError for an unexpected body (could not verify)."""
    if not isinstance(doc, dict) or not isinstance(as_dict(doc.get("hits")).get("hits"), list):
        raise ValueError("SEC full-text search answer without hits")
    total = as_dict(as_dict(doc.get("hits")).get("total"))
    hits = []
    for h in doc["hits"]["hits"]:
        src = as_dict(as_dict(h).get("_source"))
        hid = text(as_dict(h).get("_id"))
        adsh = text(src.get("adsh")) or hid.split(":", 1)[0]
        document = hid.split(":", 1)[1] if ":" in hid else None
        names, ciks = as_list(src.get("display_names")), as_list(src.get("ciks"))
        filers = []
        for i, dn in enumerate(names or ciks):
            p = parse_display_name(dn) if names else {"name": None, "tickers": [], "cik": None}
            if not p["cik"] and i < len(ciks):
                p["cik"] = cik10(ciks[i])
            filers.append(p)
        first = filers[0]["cik"] if filers else None
        hits.append({"adsh": adsh or None, "form": text(src.get("form")) or None, "root_forms": [text(x) for x in as_list(src.get("root_forms"))],
                     "file_date": iso_date(src.get("file_date")), "items": _items(src.get("items")), "file_type": text(src.get("file_type")) or None,
                     "filers": filers, "url": filing_url(first, adsh, document) if document else None, "index_url": filing_index_url(first, adsh)})
    return {"total": as_int(total.get("value")), "relation": text(total.get("relation")) or None, "hits": hits}


def select_hits(parsed: dict[str, Any], *, name: str, ciks: set[str], tickers: set[str]) -> list[dict[str, Any]]:
    """Cond 4/5: 8-K/8-K/A with Item 1.05 (own or mention) and 6-K only when filed by the counterparty;
    deduplicated per filing (the main document wins), at most 10."""
    cname, ccore = norm_company_name(name), name_core(name)
    out: list[dict[str, Any]] = []
    seen: dict[str, int] = {}
    for h in parsed.get("hits") or []:
        form, filers, roots = h.get("form") or "", h.get("filers") or [], h.get("root_forms") or []
        relation = "mention"
        for f in filers:
            if f.get("cik") and f["cik"] in ciks:
                relation = "own_cik"
                break
            if tickers & {t.upper() for t in f.get("tickers") or []}:
                relation = "own_ticker"
                break
            fname = f.get("name") or ""
            if cname and (norm_company_name(fname) == cname or (ccore and name_core(fname) == ccore)):
                relation = "own_name"
        if form in INCIDENT_FORMS or (form.startswith("8-K") and "8-K" in roots):
            if "1.05" not in (h.get("items") or []):
                continue
            kind = "item_1_05"
        elif form in FOREIGN_FORMS or (form.startswith("6-K") and "6-K" in roots):
            if relation == "mention":
                continue
            kind = "6k_own"
        else:
            continue
        key = h.get("adsh") or ""
        if key in seen:
            prev = out[seen[key]]
            if (h.get("file_type") or "").upper() == form.upper() and h.get("url"):
                prev["url"] = h.get("url")
            continue
        if len(out) >= EFTS_CAP:
            break
        seen[key] = len(out)
        out.append({"adsh": h.get("adsh"), "form": form, "filing_date": h.get("file_date"), "items": h.get("items"),
                    "company": filers[0].get("name") if filers else None, "cik": filers[0].get("cik") if filers else None,
                    "relation": relation, "kind": kind, "url": h.get("url"), "index_url": h.get("index_url"), "origin": "efts"})
    return out


def _json_ok(resp: Any) -> bool:
    try:
        return isinstance(json.loads(resp.content), dict)
    except (ValueError, TypeError, UnicodeDecodeError, AttributeError):
        return False


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


def explicitly_selected(module_name: str, ctx: Any) -> bool:
    options = getattr(ctx, "options", None)
    if module_name in set(getattr(options, "include", ()) or ()):
        return True
    return not bool(getattr(getattr(ctx, "runtime", None), "in_scan", False))


@register
class SecEdgar(Module):
    name = "sec_edgar"
    title = "SEC EDGAR cyber-incident disclosures"
    description = (
        "Matches a counterparty to an SEC registrant (local company_tickers dataset), reads its recent filings and the first page "
        "of EDGAR full-text search for 8-K Item 1.05 material cybersecurity incident disclosures (and 6-K of foreign issuers)."
    )
    category = "company_org"
    accepts = {T.ORG, T.KEYWORD}
    produces = frozenset()
    tags = {"free"}
    reference = "https://www.sec.gov/os/accessing-edgar-data"
    notice = (
        "SEC fair access: requests carry the identifying User-Agent with the team role mailbox (setting contact_email, never a "
        "personal address) and stay below 2 req/s. Filing metadata and links only. Opt-in (-M sec_edgar)."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # EFTS receives the company name; submissions receive the CIK
    hosts = ("www.sec.gov", "data.sec.gov", "efts.sec.gov")
    provider = "sec"
    sources = (SOURCE_TICKERS, SOURCE_SUBMISSIONS, SOURCE_EFTS)
    access_model = "free_noauth_limited"
    max_requests = 3  # submissions + one EFTS page (+1 slack)
    expected_latency = 1.5
    timeout = 60.0
    min_interval = 0.5  # cond 2: <= 2 req/s
    cache_ttl = CACHE_TTL
    max_pivots = 0
    default_enabled = False  # cond 6

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        contact = text(ctx.setting("contact_email", ""))
        if not _EMAIL.match(contact):
            return res.mark(Status.SKIPPED, UA_HINT, reason_code="config")
        value = " ".join(text(entity.value).split())
        if entity.type is T.KEYWORD and not explicitly_selected(self.name, ctx):
            return res.mark(Status.SKIPPED, "keywords are searched only when sec_edgar is selected explicitly (-M sec_edgar)", reason_code="not_default")
        if len(value) < 2:
            return res.mark(Status.SKIPPED, "name too short", reason_code="not_applicable")
        coverage: dict[str, Any] = {"first_page_only": True}
        # cond 3: local ticker/title matching (no disclosure)
        companies: list[dict[str, Any]] = []
        try:
            rows = parse_tickers(ctx.data.fetch_json(DATASET))
            as_ticker = entity.type is T.KEYWORD and bool(_TICKER.match(value))
            companies = match_company(value, rows, ticker=as_ticker) or (match_company(value, rows) if as_ticker else [])
            res.source_status(SOURCE_TICKERS, Status.OK)
        except (DatasetError, OSError, ValueError) as exc:
            res.source_status(SOURCE_TICKERS, Status.ERROR, reason=f"company_tickers dataset unavailable ({str(exc)[:120]}): could not match locally")
        disclosures: list[dict[str, Any]] = []
        best = companies[0] if companies else None
        if best:
            facts = parse_submissions(ctx.http.get_json(SUBMISSIONS_URL.format(cik10=best["cik10"]), absent={404}, source=SOURCE_SUBMISSIONS,
                                                        cache_if=_json_ok))
            if facts is not None:
                company = {k: facts.get(k) for k in ("cik", "name", "tickers", "exchanges", "sic", "sic_description",
                                                     "state_of_incorporation", "former_names")}
                company.update({"match": best["match"], "confidence": best["confidence"], "other_candidates": [c["cik10"] for c in companies[1:5]]})
                res.attr("sec_company", company)
                disclosures.extend(own_disclosures(facts))
                coverage.update({"submissions_checked": True, "older_filing_pages": facts.get("older_pages")})
            res.source_status(SOURCE_SUBMISSIONS, Status.OK)
        ciks = {c["cik10"] for c in companies}
        tickers = {t for c in companies for t in (c.get("ticker"),) if t}
        try:
            parsed = parse_efts(ctx.http.get_json(efts_url(value, ctx.now().date().isoformat()), source=SOURCE_EFTS, cache_if=_json_ok))
            coverage.update({"efts_total": parsed["total"], "efts_total_relation": parsed["relation"], "efts_returned": len(parsed["hits"])})
            known = {d["adsh"] for d in disclosures}
            for hit in select_hits(parsed, name=value, ciks=ciks, tickers=tickers):
                if hit["adsh"] not in known and len(disclosures) < EFTS_CAP:
                    disclosures.append(hit)
            res.source_status(SOURCE_EFTS, Status.OK)
        except ValueError as exc:
            if not best:
                raise HttpError(f"{exc}: could not verify", 200, EFTS_URL) from exc
            res.source_status(SOURCE_EFTS, Status.ERROR, reason=f"{exc}: could not verify")
        except (Blocked, RateLimited, QuotaExceeded, HttpError, NetworkError) as exc:
            if not res.attributes.get("sec_company"):
                raise
            status = Status.BLOCKED if isinstance(exc, Blocked) else Status.RATE_LIMITED if isinstance(exc, RateLimited) else \
                Status.QUOTA if isinstance(exc, QuotaExceeded) else Status.ERROR
            res.source_status(SOURCE_EFTS, status, reason=f"full-text search could not verify ({type(exc).__name__})")
        res.attr("sec_search_coverage", coverage)
        match_conf = best["confidence"] if best else "possible"
        for d in disclosures:
            own = d["relation"] in ("own_cik", "own_ticker")
            d["confidence"] = match_conf if own else "possible"
        res.raw = {"companies": companies[:5], "disclosures": disclosures, "coverage": coverage}
        if disclosures:
            res.attr("sec_cyber_disclosures", disclosures)
        for d in disclosures:
            self._finding(res, d, value)
        if not best and not disclosures:
            return res.mark(Status.EMPTY, f"no SEC registrant matched '{value}' and no Item 1.05 disclosure on the first page of EDGAR "
                                          f"full-text search ({coverage.get('efts_total', 0)} hit(s) in total)")
        return res

    @staticmethod
    def _finding(res: ModuleResult, d: dict[str, Any], value: str) -> None:
        own = d["relation"] != "mention"
        if d["kind"] == "6k_own":
            title, severity = "Foreign issuer report (6-K) mentioning a cybersecurity incident", "info"
        elif own:
            title, severity = "Material cybersecurity incident disclosed to the SEC (8-K Item 1.05)", "low"
        else:
            title, severity = "Another registrant's 8-K Item 1.05 disclosure mentions the counterparty", "info"
        res.finding(
            title,
            severity,
            f"{d.get('form')} filed {d.get('filing_date')} by {d.get('company')} (CIK {d.get('cik')}), items {', '.join(d.get('items') or [])}; "
            f"relation to '{value}': {d['relation']}. Supplier-incident context: filing metadata and link only.",
            confidence=d["confidence"],
            criterion="SEC EDGAR filing of the registrant carrying Form 8-K Item 1.05 (material cybersecurity incident)" if own else
                      "EDGAR full-text search: an Item 1.05 filing of another registrant mentions the name (POSSIBLE)",
            data={k: d.get(k) for k in ("adsh", "form", "filing_date", "items", "company", "cik", "relation", "kind", "url", "index_url")},
            tags=["cyber_incident_disclosure"] + ([] if own and d["kind"] == "item_1_05" else ["context_only"]),
            references=[u for u in (d.get("url"), d.get("index_url")) if u],
            source=SOURCE_SUBMISSIONS if d.get("origin") == "submissions" else SOURCE_EFTS,
            observed_first=d.get("filing_date"),
            key=str(d.get("adsh") or ""),
        )
        if d.get("index_url"):
            res.link(f"SEC filing {d.get('form')} {d.get('filing_date')} ({d.get('company')})", d["index_url"])
