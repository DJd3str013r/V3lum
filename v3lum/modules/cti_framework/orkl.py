"""orkl: public CTI reports from the ORKL library (P293, batch p2-G11-1).

Final conditions (FC) of P293 and where they are met:

* **FC1 legal floor.** ORKL publishes no terms readable from the research egress, so the source class is
  'unknown' (provider ``orkl``): ``terms = 'unknown'`` and ``default_enabled = False``; the licence gate
  keeps the module out of every profile until legal records the terms.
* **FC2 tier.** The provider tier is 'unknown' (excluded at TLP:AMBER+ and needing ``--allow-unknown`` at
  CLEAR/GREEN: core policy gate). While it is unknown only IOC_TYPES values are sent (CVE and ATT&CK
  ids); threat_actor and malware_family values are SKIPPED ``tier`` until the provider registry records a
  promotion to community (read live from the registry, :func:`provider_promoted`). Company names and free
  keywords are never accepted (they cannot be told apart from victim names).
* **FC3 queries.** ``library/search?query=&limit=`` with limit <= 10, ``min_interval`` 1 s, cache 7 days.
  The error envelope ``{"status": "error"}`` inside HTTP 200 is an error marker of the provider fragment
  (ERROR); any other non-'success' status, HTML or invalid JSON is ERROR 'could not verify'; timeouts,
  403 and 429 propagate (rule 5). The ORKL search is fuzzy (a non-existent CVE returned unrelated
  reports, live 2026-11-26), so only reports that name the queried value exactly are kept
  (:func:`orkl_relevance`); dropped fuzzy hits are counted, never shown as matches.
* **FC4 output.** Report title, publisher (ORKL ``authors``), date and the publisher URL as links: the 5
  most recent as ``res.link`` (terminal) and up to 10 in ``cti_reports`` (HTML); URL pivots have
  ``expand=False``. No report file is downloaded and the ``archive.orkl.eu`` files are never linked;
  excerpts are truncated (publishers keep copyright).
* **FC5 report IOCs (opt-in).** Off by default (setting ``orkl_report_iocs``). When on, the entry text of
  at most ``orkl_ioc_reports`` (<= 3) reports is truncated to 20,000 characters first, mined with the
  shared IOC engine (``v3lum.core.ioc.extract``), filtered through the P169 warninglists (fail closed:
  when the warninglist index is unusable nothing is emitted) and pivoted with ``expand=False``, confidence
  POSSIBLE and the note 'from report <title> (<date>)': never verdicts.
* **FC6 merge gate.** tests/modules/test_orkl.py (FakeHttp, trimmed real fixtures in tests/fixtures/orkl/).
"""

from __future__ import annotations

import email.utils
import html
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from v3lum.config import SettingSpec
from v3lum.core import providers
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, HttpError, NetworkError
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

PROVIDER = "orkl"
SOURCE = "orkl.library"
SEARCH_URL = "https://orkl.eu/api/v1/library/search"
ENTRY_URL = "https://orkl.eu/api/v1/library/entry/{id}"
MAX_LIMIT = 10  # FC3
TERMINAL_REPORTS = 5  # FC4: the terminal shows the 5 most recent
HTML_REPORTS = 10  # FC4: HTML up to 10
TEXT_CAP = 20_000  # FC5: plain_text truncated before extraction
MAX_IOC_REPORTS = 3
MAX_REPORT_IOCS = 50
EXCERPT_CHARS = 280
IOC_QUERY_TYPES = frozenset({T.CVE, T.MITRE})  # FC2: IOC_TYPES only while the tier is unknown
PROMOTION_TYPES = frozenset({T.THREAT_ACTOR, T.MALWARE})  # FC2: need a recorded promotion
PROMOTED_TIERS = frozenset({"community", "trusted"})
#: report-IOC types kept from the extraction engine (FC5); identities and secrets never.
REPORT_IOC_TYPES = frozenset({T.IPV4, T.IPV6, T.DOMAIN, T.URL, T.MD5, T.SHA1, T.SHA256, T.CVE, T.MITRE})
#: warninglist categories that drop a report IOC (benign examples): suppress outcomes always drop.
DROP_CATEGORIES = frozenset({"popular_site", "known_vendor_domain"})

_WS = re.compile(r"\s+")
_TAG = re.compile(r"<[^<>]{0,2000}>")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_ID_QUERY = re.compile(r"(?i)cve-\d{4}-\d{4,7}|t\d{4}(?:\.\d{3})?")


# ------------------------------------------------------------------------------------------ helpers


def _s(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return str(value)


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def clean_text(value: Any, max_len: int = 300) -> str:
    """Untrusted text -> one line: entities decoded, tags/control characters removed, truncated."""
    text = html.unescape(_s(value))
    text = _TAG.sub(" ", text)
    text = _CTRL.sub(" ", text)
    text = _WS.sub(" ", text).strip()
    if max_len and len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text


def fold_text(value: Any) -> str:
    text = unicodedata.normalize("NFKD", _s(value))
    return "".join(ch for ch in text if not unicodedata.combining(ch)).casefold()


def safe_http_url(value: Any) -> str | None:
    """An http(s) URL or None (spaces percent-encoded: ORKL references contain them)."""
    text = _s(value).strip().replace(" ", "%20")
    if not text or len(text) > 2048 or any(ch in text for ch in "\r\n\t\x00"):
        return None
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host:
        return None
    return text


def parse_date(value: Any) -> datetime | None:
    """RFC 2822, ISO 8601 or a leading YYYY-MM-DD -> aware UTC datetime; placeholder years (< 1971,
    ORKL's 0001-01-01 'unknown') and junk give None."""
    text = _s(value).strip()
    if not text or len(text) > 64:
        return None
    dt = None
    if re.match(r"^[A-Za-z]{3},|^\d{1,2} [A-Za-z]{3} \d{4}", text):
        try:
            dt = email.utils.parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            dt = None
    if dt is None:
        iso = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        m = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(\.\d+)?(.*)$", iso)
        if m:
            frac = (m.group(2) or "")[:7].ljust(7, "0") if m.group(2) else ""
            iso = m.group(1) + frac + m.group(3)
        try:
            dt = datetime.fromisoformat(iso)
        except ValueError:
            m = re.match(r"^(\d{4})[-/](\d{2})[-/](\d{2})", text)
            if not m:
                return None
            try:
                dt = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            except ValueError:
                return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return None if dt.year < 1971 else dt


def provider_promoted() -> bool:
    """FC2: True once the provider registry records ORKL at community (or trusted) tier."""
    try:
        prov = providers.registry().get(PROVIDER)
    except Exception:  # noqa: BLE001 - an unreadable registry never promotes
        return False
    return bool(prov is not None and str(getattr(prov, "tier", "")) in PROMOTED_TIERS)


def search_params(value: Any, limit: Any = MAX_LIMIT) -> dict[str, Any]:
    """FC3: query + limit clamped to 1..10; CVE/ATT&CK ids upper-cased (stable cache key)."""
    query = _s(value).strip()
    if _ID_QUERY.fullmatch(query):
        query = query.upper()
    try:
        n = int(limit)
    except (TypeError, ValueError):
        n = MAX_LIMIT
    return {"query": query[:200], "limit": max(1, min(n, MAX_LIMIT))}


def envelope_problem(doc: Any) -> str | None:
    """FC3: ORKL wraps every answer in {data, message, status}; anything but status 'success' is an
    error whatever the HTTP code. None for a usable envelope."""
    if not isinstance(doc, dict):
        return "ORKL answer is not a JSON object"
    status = _s(doc.get("status")).strip().lower()
    if status != "success":
        msg = clean_text(doc.get("message"), 120) or "no message"
        return f"ORKL status={status or 'missing'} ({msg})"
    data = doc.get("data")
    if data is not None and not isinstance(data, (list, dict)):
        return f"ORKL 'data' has unexpected type {type(data).__name__}"
    return None


def report_date(entry: Any) -> tuple[str | None, str | None]:
    """FC4 date: a leading date in the title (VX-Underground mirrors), the PDF creation date
    (0001-01-01 = unknown), else the date ORKL added the report ('orkl_added')."""
    if not isinstance(entry, dict):
        return None, None
    m = re.match(r"\s*(\d{4}-\d{2}-\d{2})\b", _s(entry.get("title")))
    if m:
        dt = parse_date(m.group(1))
        if dt:
            return dt.strftime("%Y-%m-%d"), "title"
    for key, label in (("file_creation_date", "file_creation_date"), ("created_at", "orkl_added")):
        dt = parse_date(entry.get(key))
        if dt:
            return dt.strftime("%Y-%m-%d"), label
    return None, None


def pick_url(references: Any) -> str | None:
    """FC4 link: the first publisher web page, else the first reference; archive.orkl.eu never."""
    urls = [u for u in (safe_http_url(r) for r in _list(references)) if u and "archive.orkl.eu" not in u.lower()]
    for url in urls:
        if not urlsplit(url).path.lower().endswith(".pdf"):
            return url
    return urls[0] if urls else None


def orkl_relevance(entry: Any, query: Any, query_type: T | None = None) -> str:
    """'exact' when the queried value appears in the title, report names or reference URLs (ids with
    digit boundaries; names accent-folded with word boundaries, or a threat_actors name/alias equal to
    it), 'fuzzy' otherwise (the ORKL search is fuzzy)."""
    q = _s(query).strip()
    if not q or not isinstance(entry, dict):
        return "fuzzy"
    parts = [_s(entry.get("title")), _s(entry.get("llm_title"))]
    parts += [_s(x) for x in _list(entry.get("report_names"))]
    parts += [_s(x) for x in _list(entry.get("references"))]
    hay = " ".join(parts)
    if query_type in IOC_QUERY_TYPES or _ID_QUERY.fullmatch(q):
        pat = re.compile(r"(?<![0-9A-Za-z])" + re.escape(q) + r"(?![0-9])", re.I)
        return "exact" if pat.search(hay) else "fuzzy"
    fq = fold_text(q)
    for actor in _list(entry.get("threat_actors")):
        if isinstance(actor, dict):
            names = [actor.get("main_name"), *_list(actor.get("aliases"))]
            if any(fold_text(n) == fq for n in names if isinstance(n, str)):
                return "exact"
    pat = re.compile(r"(?<![0-9a-z])" + re.escape(fq) + r"(?![0-9a-z])")
    return "exact" if pat.search(fold_text(hay)) else "fuzzy"


def orkl_report(entry: Any) -> dict[str, Any] | None:
    """One library entry -> FC4 fields only (None without a title). ``publisher`` is ORKL's
    ``authors`` (an organisation or researchers' names: displayed, never an entity)."""
    if not isinstance(entry, dict):
        return None
    title = clean_text(entry.get("title") or entry.get("llm_title"), 300)
    if not title:
        return None
    refs = [u for u in (safe_http_url(r) for r in _list(entry.get("references"))) if u][:10]
    date, date_source = report_date(entry)
    actors: dict[str, str] = {}
    for actor in _list(entry.get("threat_actors"))[:100]:
        if isinstance(actor, dict):
            name = clean_text(actor.get("main_name"), 120)
            if name:
                actors.setdefault(fold_text(name), name)
    sha1 = _s(entry.get("sha1_hash")).strip().lower()
    return {
        "id": _s(entry.get("id")).strip()[:64] or None,
        "title": title,
        "publisher": clean_text(entry.get("authors"), 200) or None,
        "date": date,
        "date_source": date_source,
        "url": pick_url(refs),
        "orkl_sources": [s for s in (clean_text(x, 40) for x in _list(entry.get("sources"))[:10]) if s],
        "actors": list(actors.values())[:20],
        "report_sha1": sha1 if re.fullmatch(r"[0-9a-f]{40}", sha1) else None,
    }


def recent_first(reports: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """FC4 ordering: most recent first (undated last), then title."""
    dated = sorted((r for r in reports if r.get("date")), key=lambda r: (r["date"], r["title"]), reverse=True)
    undated = sorted((r for r in reports if not r.get("date")), key=lambda r: r["title"])
    return (dated + undated)[: max(0, int(limit))]


def parse_search(doc: Any, query: Any, query_type: T | None = None) -> dict[str, Any]:
    """FC3/FC4: library/search -> {status ok|empty|error, reason, reports, fuzzy_dropped, total}."""
    problem = envelope_problem(doc)
    if problem:
        return {"status": "error", "reason": problem, "reports": [], "fuzzy_dropped": 0, "total": 0}
    data = doc.get("data")
    if isinstance(data, dict):
        data = [data]
    data = _list(data)
    reports, dropped = [], 0
    for entry in data[:50]:
        rep = orkl_report(entry)
        if rep is None:
            continue
        if orkl_relevance(entry, query, query_type) != "exact":
            dropped += 1
            continue
        reports.append(rep)
    reports = recent_first(reports, HTML_REPORTS)
    return {"status": "ok" if reports else "empty", "reason": None, "reports": reports, "fuzzy_dropped": dropped, "total": len(data)}


def excerpt(text: Any, max_chars: int = EXCERPT_CHARS) -> str:
    """FC4: excerpts are truncated (publishers keep copyright)."""
    return clean_text(text, max_chars)


def report_tag(report: dict[str, Any]) -> str:
    return f"from report {clean_text(report.get('title'), 160) or 'untitled'} ({report.get('date') or 'undated'})"


def warninglist_drop(entity: Entity) -> bool | None:
    """P169 filter for report IOCs: True = drop (suppressed or a popular/vendor site), False = keep,
    None = the warninglist index is unusable (the caller fails closed)."""
    try:
        from v3lum.modules.threat_intel_ioc.warninglists import local_classification
    except ImportError:  # pragma: no cover - P169 module always ships with this batch's tree
        return None
    try:
        cls = local_classification(entity)
    except Exception:  # noqa: BLE001 - an unusable index fails closed
        return None
    if cls is None:
        return None
    if cls.get("outcome") == "suppress" or cls.get("suppressed"):
        return True
    return bool(DROP_CATEGORIES & set(cls.get("categories") or ()))


def report_iocs(text: Any, report: dict[str, Any], *, query: Entity, limit: int = MAX_REPORT_IOCS) -> dict[str, Any]:
    """FC5: IOCs mined from a report's plain text with the shared engine, truncated first, P169
    filtered (fail closed), tagged 'from report <title> (<date>)', never verdicts."""
    from v3lum.core.ioc import extract  # shared IOC extraction engine (WP17)

    raw = _s(text)
    truncated = len(raw) > TEXT_CAP
    raw = raw[:TEXT_CAP]
    out = {"report": report.get("title"), "tag": report_tag(report), "truncated": truncated, "chars_scanned": len(raw),
           "iocs": [], "warninglisted": 0, "failed_closed": False}
    if not raw.strip():
        return out
    result = extract(raw, limit=500, source_type="text")
    for item in result.entities:
        ent = item.entity
        if ent.type not in REPORT_IOC_TYPES or ent.key == query.key:
            continue
        flags = set(item.flags)
        if flags & {"bogon", "private", "personal", "secret", "recipient_token", "unverified_attack_id"}:
            continue
        if "warninglisted" in flags:
            out["warninglisted"] += 1
            continue
        verdict = warninglist_drop(ent)
        if verdict is None:  # fail closed: an unknown warninglist state never leaks unfiltered IOCs
            out["failed_closed"] = True
            out["iocs"] = []
            return out
        if verdict:
            out["warninglisted"] += 1
            continue
        out["iocs"].append(ent)
        if len(out["iocs"]) >= limit:
            break
    return out


# ------------------------------------------------------------------------------------------ module


@register
class Orkl(Module):
    name = "orkl"
    title = "ORKL CTI report library"
    description = (
        "Public CTI reports (title, publisher, date, publisher link) that name a CVE or ATT&CK technique (actor and "
        "malware names once ORKL is promoted to community tier), from the ORKL library search. Links only."
    )
    category = "cti_framework"
    accepts = {T.CVE, T.MITRE, T.THREAT_ACTOR, T.MALWARE}
    produces = {T.URL, T.IPV4, T.IPV6, T.DOMAIN, T.MD5, T.SHA1, T.SHA256, T.CVE, T.MITRE}
    tags = {"free"}
    reference = "https://orkl.eu/"
    notice = (
        "ORKL terms are unknown (A1): off in every profile until legal records them. Unknown-tier operator: only CVE and "
        "ATT&CK ids are sent; actor/malware names wait for a recorded promotion. Reports keep their publishers' copyright: "
        "titles and links only, no report files."
    )
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    hosts = ("orkl.eu",)
    provider = PROVIDER
    sources = (SOURCE,)
    access_model = "free_noauth_limited"
    max_requests = 1 + MAX_IOC_REPORTS
    expected_latency = 0.8
    timeout = 40.0
    min_interval = 1.0
    daily_quota = 500
    cache_ttl = 7 * 86400
    max_pivots = HTML_REPORTS + MAX_REPORT_IOCS
    default_enabled = False
    settings = {
        "orkl_limit": SettingSpec(MAX_LIMIT, "ORKL search results requested per value (1..10, P293 cond 3)"),
        "orkl_report_iocs": SettingSpec(False, "opt-in: mine IOCs from the text of the matched reports (P293 cond 5; low confidence, never verdicts)"),
        "orkl_ioc_reports": SettingSpec(MAX_IOC_REPORTS, "reports whose text is mined when orkl_report_iocs is on (1..3)"),
    }

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type in PROMOTION_TYPES and not provider_promoted():
            return res.mark(
                "skipped",
                f"orkl.eu is an unknown-tier operator: {entity.type.value} values need a recorded promotion to community tier "
                "(P293 cond 2); only CVE and ATT&CK ids are sent",
                reason_code="tier",
            )
        params = search_params(entity.value, ctx.setting("orkl_limit", MAX_LIMIT))
        try:
            doc = ctx.http.get_json(SEARCH_URL, params=params, source=SOURCE)
        except ValueError as exc:  # invalid JSON / an HTML page in a 200: untrusted answer, never empty
            return res.mark("error", f"ORKL answer is not JSON ({str(exc)[:80]}): could not verify")
        parsed = parse_search(doc, params["query"], entity.type)
        if parsed["status"] == "error":
            return res.mark("error", f"{parsed['reason']}: could not verify")
        res.raw = {"query": params, "total": parsed["total"], "fuzzy_dropped": parsed["fuzzy_dropped"],
                   "reports": [{k: r[k] for k in ("id", "title", "date", "url")} for r in parsed["reports"]]}
        if parsed["fuzzy_dropped"]:
            res.attr("cti_reports_fuzzy_dropped", parsed["fuzzy_dropped"])
        reports = parsed["reports"]
        if not reports:
            why = (f"{parsed['fuzzy_dropped']} fuzzy search hit(s) do not name {params['query']} and were dropped"
                   if parsed["fuzzy_dropped"] else "ORKL returned no report")
            return res.mark("empty", f"no ORKL report names {params['query']} ({why})")
        res.attr("cti_reports", [{k: v for k, v in r.items() if v not in (None, [], "") and k != "id"} for r in reports])
        res.attr("cti_report_count", len(reports))
        for rep in reports[:TERMINAL_REPORTS]:
            if rep.get("url"):
                label = " - ".join(x for x in (rep.get("date") or "undated", rep.get("publisher"), excerpt(rep["title"], 120)) if x)
                res.link(f"ORKL report: {label}", rep["url"])
        for rep in reports:
            if rep.get("url"):
                res.pivot(T.URL, rep["url"], "reported_in", confidence="probable", expand=False,
                          note=f"public CTI report ({rep.get('date') or 'undated'}): publisher link, not investigated")
        shown = "; ".join(f"{r.get('date') or 'undated'} {excerpt(r['title'], 90)}" for r in reports[:TERMINAL_REPORTS])
        res.finding(
            "Public CTI reports name this value",
            "info",
            f"{len(reports)} ORKL report(s) name {params['query']}: {shown}",
            confidence="probable",
            tags=["info", "context_only"],
            source=SOURCE,
            data={"reports": len(reports), "fuzzy_dropped": parsed["fuzzy_dropped"]},
        )
        if ctx.setting("orkl_report_iocs", False):
            self._report_iocs(entity, ctx, res, reports)
        return res

    def _report_iocs(self, entity: Entity, ctx: Any, res: ModuleResult, reports: list[dict[str, Any]]) -> None:
        """FC5 opt-in: entry text -> truncated -> shared IOC engine -> P169 -> pivots (expand=False)."""
        try:
            wanted = max(1, min(int(ctx.setting("orkl_ioc_reports", MAX_IOC_REPORTS)), MAX_IOC_REPORTS))
        except (TypeError, ValueError):
            wanted = MAX_IOC_REPORTS
        summary: list[dict[str, Any]] = []
        emitted = 0
        for rep in [r for r in reports if r.get("id")][:wanted]:
            if not re.fullmatch(r"[0-9A-Za-z-]{1,64}", rep["id"]):
                continue
            try:
                doc = ctx.http.get_json(ENTRY_URL.format(id=rep["id"]), source=SOURCE)
            except ValueError:
                summary.append({"report": rep["title"], "error": "entry answer is not JSON"})
                continue
            except (HttpError, Blocked, AuthRequired, NetworkError) as exc:  # the search stands; this entry could not be read
                summary.append({"report": rep["title"], "error": f"entry could not be read: {str(exc)[:120]}"})
                continue
            if envelope_problem(doc) or not isinstance(doc.get("data"), dict):
                summary.append({"report": rep["title"], "error": envelope_problem(doc) or "entry without data"})
                continue
            mined = report_iocs(doc["data"].get("plain_text"), rep, query=entity, limit=MAX_REPORT_IOCS - emitted)
            row = {"report": rep["title"], "date": rep.get("date"), "iocs": len(mined["iocs"]), "warninglisted": mined["warninglisted"],
                   "truncated": mined["truncated"], "chars_scanned": mined["chars_scanned"]}
            if mined["failed_closed"]:
                row["error"] = "warninglists unavailable: report IOCs withheld (fail closed)"
            summary.append(row)
            for ioc in mined["iocs"]:
                if res.pivot(ioc.type, ioc.value, "co_mentioned_in_report", confidence="possible", expand=False,
                             note=f"{mined['tag']}: low confidence, never a verdict (reports carry example and benign IOCs)"):
                    emitted += 1
            if emitted >= MAX_REPORT_IOCS:
                break
        res.attr("report_iocs", summary)
