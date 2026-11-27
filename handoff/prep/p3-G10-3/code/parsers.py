"""Pure parsers for batch p3-G10-3 (group G10, brazil_company).

P253 adverse_media_rss  - adverse-media mentions from GDELT DOC 2.0 (Google News stays a manual link).
P254 wanted_notices     - FBI Wanted cyber list matched locally against actor aliases / typed person seeds
                          (INTERPOL is a manual link only).

Standard library only, no V3LUM imports, no network. Every function takes the raw response (bytes, str or
already-parsed JSON) and returns plain dicts/lists. Functions that cannot read a body raise ParseError (never
return an empty list for a body they could not understand: an unreadable body is never 'no news' / 'no match').
Docstrings name the final condition (FC) each function serves.
"""
from __future__ import annotations

import html
import json
import re
import unicodedata
import urllib.parse
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from xml.etree import ElementTree as ET


class ParseError(ValueError):
    """Body could not be read as the expected format. .reason is a short machine string."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# =====================================================================
# shared helpers
# =====================================================================

def to_text(raw):
    """bytes/str/None -> str (UTF-8, BOM stripped, undecodable bytes replaced)."""
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("utf-8", "replace")
    if not isinstance(raw, str):
        raw = str(raw)
    return raw.lstrip("﻿")


def fold(text):
    """Case- and accent-insensitive form: NFKD, combining marks dropped, casefolded."""
    if not isinstance(text, str):
        text = "" if text is None else str(text)
    text = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in text if not unicodedata.combining(ch)).casefold()


def words(text, split_digits=False):
    """Folded text with every non-alphanumeric run replaced by one space (no padding).

    split_digits=True also separates letter/digit boundaries ('APT41' -> 'apt 41') so that 'APT41',
    'APT 41' and 'APT-41' compare equal.
    """
    s = re.sub(r"[^0-9a-z]+", " ", fold(text))
    if split_digits:
        s = re.sub(r"(?<=[a-z])(?=[0-9])|(?<=[0-9])(?=[a-z])", " ", s)
    return " ".join(s.split())


def strip_html(value):
    """HTML fragment -> plain text (tags removed, entities unescaped, whitespace collapsed)."""
    if not isinstance(value, str):
        return ""
    s = re.sub(r"(?is)<(script|style)\b.*?</\1\s*>", " ", value)
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(s)
    return " ".join(s.split())


def load_json(raw):
    """raw -> parsed JSON. Accepts an already-parsed dict/list. Raises ParseError('html'|'empty_body'|'malformed_json')."""
    if isinstance(raw, (dict, list)):
        return raw
    text = to_text(raw).strip()
    if not text:
        raise ParseError("empty_body")
    if text[0] == "<":
        raise ParseError("html_not_json", text[:80])
    try:
        return json.loads(text)
    except ValueError as exc:
        raise ParseError("malformed_json", str(exc)[:120]) from None


def _header(headers, name):
    if not headers:
        return ""
    try:
        items = headers.items()
    except AttributeError:
        return ""
    for k, v in items:
        if str(k).lower() == name.lower():
            return str(v)
    return ""


CF_CHALLENGE_MARKERS = (
    "<title>just a moment...</title>",
    "/cdn-cgi/challenge-platform/h/",
    "cf-chl-",
    "attention required! | cloudflare",
    "enable javascript and cookies to continue",
)
AKAMAI_DENIED_MARKERS = ("<title>access denied</title>", "errors.edgesuite.net", "errors&#46;edgesuite&#46;net")


def detect_block(status, headers=None, body=None):
    """Anti-bot / block page detector -> 'challenge:cloudflare' | 'challenge:akamai' | 'rate_limited' | None.

    P254 FC3/FC6 and A9: a block is BLOCKED (reason_code 'challenge'), never EMPTY and never retried with other
    headers. Cloudflare's passive '/cdn-cgi/challenge-platform/scripts/jsd/' script is injected into normal 200
    HTML pages (api.fbi.gov/docs) and is deliberately NOT a marker.
    """
    low = to_text(body)[:20000].lower()
    if _header(headers, "cf-mitigated").lower() == "challenge":
        return "challenge:cloudflare"
    if any(m in low for m in CF_CHALLENGE_MARKERS):
        return "challenge:cloudflare"
    if any(m in low for m in AKAMAI_DENIED_MARKERS) and (status in (None, 403) or "access denied" in low):
        return "challenge:akamai"
    if status == 429:
        return "rate_limited"
    return None


# =====================================================================
# P253 adverse_media_rss - GDELT DOC 2.0
# =====================================================================

GDELT_DOC_URL = "https://api.gdeltproject.org/api/v2/doc/doc"
GDELT_CITATION = "Source: The GDELT Project (https://www.gdeltproject.org/)"
GDELT_MIN_INTERVAL_S = 5.0          # provider asks for <= 1 request / 5 s per IP (FC3: shared token bucket)
TITLE_SIMILARITY_THRESHOLD = 0.8    # FC6: Jaccard over folded title tokens (Ceos 'agrupar' rule)
MAX_HEADLINES = 10                  # FC6: at most 10 headlines (story clusters)
HOMONYM_DEFAULT_PHRASE = "name-only match: may be a homonym (verify with another identifier)"
MENTION_LABEL = "mention - not verified, not risk-scored"

RISK_TERMS_VERSION = "pt-risk-v1"
# FC4 versioned list (ships in data/; kept here so the parser and its tests are self-contained)
RISK_TERMS_PT = ("fraude", "corrupcao", "preso", "investigado", "condenado", "denuncia", "golpe", "lavagem",
                 "estelionato", "improbidade", "operacao", "desvio", "propina")
RISK_TERMS_PT_ORG = ("vazamento", "ransomware", "ataque hacker", "incidente", "dados expostos", "invasao")
RISK_TERMS_EN = ("fraud", "corruption", "arrested", "investigated", "convicted", "indicted", "scam", "laundering",
                 "embezzlement", "bribery")
RISK_TERMS_EN_ORG = ("data breach", "leak", "ransomware", "cyberattack", "hacked", "incident", "exposed data",
                     "intrusion")

# Headline matching patterns over words() text (folded, punctuation -> space). Keys are the query terms.
TERM_PATTERNS = {
    "fraude": r"fraudes?|fraudulent[oa]s?",
    "corrupcao": r"corrupc(?:ao|oes)|corrupt[oa]s?",
    "preso": r"pres[oa]s?|prisao|prisoes",
    "investigado": r"investigad[oa]s?|investigac(?:ao|oes)|investiga",
    "condenado": r"condenad[oa]s?|condenac(?:ao|oes)",
    "denuncia": r"denuncias?|denunciad[oa]s?",
    "golpe": r"golpes?|golpistas?",
    "lavagem": r"lavagem",
    "estelionato": r"estelionat(?:o|os|ario|aria|arios|arias)",
    "improbidade": r"improbidade",
    "operacao": r"operac(?:ao|oes)",
    "desvio": r"desvios?|desviad[oa]s?|desviou",
    "propina": r"propinas?",
    "vazamento": r"vazamentos?|vaz(?:a|am|ou|aram)",
    "ransomware": r"ransomware",
    "ataque hacker": r"ataques? (?:hacker|hackers|cibernetic[oa]s?)",
    "incidente": r"incidentes?",
    "dados expostos": r"dados expostos|exp(?:oe|oem|os) dados",
    "invasao": r"invas(?:ao|oes)|invadid[oa]s?",
    "fraud": r"fraud(?:s|ulent)?",
    "corruption": r"corruption",
    "arrested": r"arrest(?:ed|s)?",
    "investigated": r"investigat(?:ed|ion|ions)",
    "convicted": r"convict(?:ed|ion)",
    "indicted": r"indict(?:ed|ment)",
    "scam": r"scams?",
    "laundering": r"laundering",
    "embezzlement": r"embezzl(?:ement|ed)",
    "bribery": r"briber(?:y|ies)|bribes?",
    "data breach": r"data breach(?:es)?",
    "leak": r"leak(?:s|ed)?",
    "cyberattack": r"cyber ?attacks?",
    "hacked": r"hacked",
    "incident": r"incidents?",
    "exposed data": r"exposed data|data exposed",
    "intrusion": r"intrusions?",
}

LEGAL_SUFFIXES = ("ltda", "limitada", "sa", "s a", "eireli", "me", "epp", "mei", "ss", "sociedade anonima",
                  "cia", "companhia", "s s")
HONORIFICS = ("dr", "dra", "sr", "sra", "prof", "profa", "eng")


def risk_terms(kind="org", include_en=False):
    """FC4: the versioned risk-term list for an entity kind ('org' adds the CTI terms; persons never get them)."""
    terms = list(RISK_TERMS_PT)
    if kind == "org":
        terms += RISK_TERMS_PT_ORG
    if include_en:
        terms += [t for t in RISK_TERMS_EN if t not in terms]
        if kind == "org":
            terms += [t for t in RISK_TERMS_EN_ORG if t not in terms]
    return terms


def name_phrase(name, kind="org"):
    """FC4: distinctive name tokens for the quoted phrase (folded, punctuation dropped, legal suffixes and honorifics
    removed). 'BANCO DO BRASIL S.A.' -> 'banco do brasil'; 'Dra. Maria Exemplo' -> 'maria exemplo'."""
    toks = words(name).split()
    if kind == "org":
        changed = True
        while changed and len(toks) > 1:
            changed = False
            for suf in sorted(LEGAL_SUFFIXES, key=lambda s: -len(s.split())):
                parts = suf.split()
                if len(toks) > len(parts) and toks[-len(parts):] == parts:
                    toks = toks[: -len(parts)]
                    changed = True
                    break
    else:
        while toks and toks[0] in HONORIFICS:
            toks = toks[1:]
    return " ".join(toks)


def gdelt_query_problem(phrase):
    """Pre-flight check: GDELT rejects very short phrases with an HTTP 200 text error. Returns a reason or None."""
    if not phrase:
        return "empty name"
    if len(phrase.replace(" ", "")) < 4:
        return "name too short for a reliable news search"
    return None


def build_gdelt_query(name, kind="org", source_filter="sourcelang:portuguese", include_en=False):
    """FC3/FC4: ONE query per entity: "<distinctive name>" (term OR term ...) <sourcelang|sourcecountry filter>."""
    phrase = name_phrase(name, kind)
    terms = risk_terms(kind, include_en)
    ors = " OR ".join(f'"{t}"' if " " in t else t for t in terms)
    parts = [f'"{phrase}"', f"({ors})"]
    if source_filter:
        parts.append(source_filter)
    return " ".join(parts)


def gdelt_request_params(query, maxrecords=50, timespan="3months"):
    """FC1: JSON artlist parameters (format=json preferred; sort newest first)."""
    return {"query": query, "mode": "artlist", "format": "json", "maxrecords": str(int(maxrecords)),
            "timespan": timespan, "sort": "datedesc"}


def gdelt_request_url(query, **kw):
    return GDELT_DOC_URL + "?" + urllib.parse.urlencode(gdelt_request_params(query, **kw), quote_via=urllib.parse.quote)


GDELT_RATE_LIMIT_MARKERS = ("limit requests to one every", "please limit requests")


def gdelt_marker(status, body, headers=None):
    """FC3 marker helper -> None (readable JSON/RSS) or a short reason:

    'rate_limited'        HTTP 429 or the 'Please limit requests to one every 5 seconds' text (-> RATE_LIMITED,
                          never 'no news')
    'challenge:<vendor>'  block page (-> BLOCKED)
    'http_<code>'         other HTTP error
    'empty_body'          200 with nothing
    'error_in_200:<msg>'  200 with a plain-text GDELT error (e.g. 'The specified phrase is too short.')
    'html_not_json'       200 HTML page
    'malformed_json'      broken JSON
    """
    text = to_text(body).strip()
    low = text.lower()
    if status == 429 or any(m in low for m in GDELT_RATE_LIMIT_MARKERS):
        return "rate_limited"
    blk = detect_block(status, headers, text)
    if blk and blk != "rate_limited":
        return blk
    if status is not None and status >= 400:
        return f"http_{status}"
    if not text:
        return "empty_body"
    if text[0] in "{[":
        try:
            json.loads(text)
        except ValueError:
            return "malformed_json"
        return None
    if text.startswith("<"):
        head = low[:300]
        if head.startswith("<?xml") or "<rss" in head:
            return None
        return "html_not_json"
    first = text.splitlines()[0].strip()
    return "error_in_200:" + first[:200]


def transport_reason(error_text):
    """FC3 companion for transport failures (no HTTP answer) -> {reason_code, text, cool_down}.

    GDELT answers throttled clients with 429 and, after that, with TLS connection resets (observed 3/5 calls
    from the datacenter egress). A reset is reported as ERROR 'error' ('could not verify', never 'no news') and
    asks the shared provider bucket to cool down; a timeout is ERROR 'timeout'.
    """
    low = to_text(error_text).lower()
    if "reset" in low or "recv failure" in low or "connection aborted" in low:
        return {"reason_code": "error", "text": "connection reset by provider (throttling suspected)",
                "cool_down": True}
    if "timed out" in low or "timeout" in low:
        return {"reason_code": "timeout", "text": "provider did not answer in time", "cool_down": False}
    return {"reason_code": "error", "text": "network error", "cool_down": False}


def _gdelt_date(value):
    """'20261120T101500Z' -> '2026-11-20T10:15:00Z'; anything else -> None."""
    if not isinstance(value, str):
        return None
    m = re.fullmatch(r"(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z", value.strip())
    if not m:
        return None
    y, mo, d, h, mi, s = m.groups()
    return f"{y}-{mo}-{d}T{h}:{mi}:{s}Z"


def _host(url):
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower() or None
    except ValueError:
        return None


def parse_gdelt_artlist(raw):
    """FC1/FC6: GDELT DOC 2.0 mode=artlist JSON -> [{title, url, domain, date, language, sourcecountry}].

    Only headline-level fields are kept (no socialimage, no article text: articles are never fetched). '{}' (the
    observed no-match answer) -> []. Non-JSON bodies raise ParseError so a 429 text or an error-in-200 can never
    be read as 'no news'. Records without an http(s) URL or a title are skipped.
    """
    text = raw if isinstance(raw, (dict, list)) else to_text(raw).strip()
    if isinstance(text, str):
        marker = gdelt_marker(200, text)
        if marker:
            raise ParseError(marker.split(":", 1)[0], marker)
    obj = load_json(text)
    if not isinstance(obj, dict):
        raise ParseError("unexpected_json", type(obj).__name__)
    arts = obj.get("articles")
    if arts is None:
        return []
    if not isinstance(arts, list):
        raise ParseError("unexpected_json", "articles is not a list")
    out = []
    for a in arts:
        if not isinstance(a, dict):
            continue
        url = a.get("url")
        title = a.get("title")
        if not isinstance(url, str) or not url.lower().startswith(("http://", "https://")):
            continue
        if not isinstance(title, str) or not title.strip():
            continue
        domain = a.get("domain") if isinstance(a.get("domain"), str) and a.get("domain") else _host(url)
        out.append({
            "title": " ".join(title.split()),
            "url": url,
            "domain": (domain or "").lower() or None,
            "date": _gdelt_date(a.get("seendate")),
            "language": a.get("language") if isinstance(a.get("language"), str) else None,
            "sourcecountry": a.get("sourcecountry") if isinstance(a.get("sourcecountry"), str) else None,
        })
    return out


def safe_xml_fromstring(raw, max_bytes=5_000_000):
    """Minimal safe-XML gate (FC1 'RSS only through the safe XML helper'): refuses DOCTYPE/ENTITY declarations and
    oversize bodies before parsing. The module must use V3LUM's core safe XML helper; this mirrors its contract."""
    text = to_text(raw)
    if len(text.encode("utf-8", "replace")) > max_bytes:
        raise ParseError("too_large")
    head = text[:4096].lower()
    if "<!doctype" in head or "<!entity" in text.lower():
        raise ParseError("xml_dtd_refused")
    try:
        return ET.fromstring(text.encode("utf-8"))
    except ET.ParseError as exc:
        raise ParseError("malformed_xml", str(exc)[:120]) from None


def _rss_date(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = parsedate_to_datetime(value.strip())
    except (TypeError, ValueError, IndexError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_gdelt_rss(raw):
    """FC1 fallback: GDELT format=rss -> same records as parse_gdelt_artlist (through the safe-XML gate)."""
    root = safe_xml_fromstring(raw)
    out = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        if not title or not link.lower().startswith(("http://", "https://")):
            continue
        out.append({"title": " ".join(title.split()), "url": link, "domain": _host(link),
                    "date": _rss_date(item.findtext("pubDate")), "language": None, "sourcecountry": None})
    return out


def _term_regex(term):
    pat = TERM_PATTERNS.get(term) or re.escape(words(term))
    return re.compile(r"(?<![0-9a-z])(?:" + pat + r")(?![0-9a-z])")


def headline_match(title, phrase, terms):
    """FC6: a headline counts only if it contains the exact name phrase (word-bounded, accent/case-insensitive)
    AND at least one risk term. Returns the sorted matched terms ([] = no match)."""
    t = " " + words(title) + " "
    p = words(phrase)
    if not p or (" " + p + " ") not in t:
        return []
    return sorted({term for term in terms if _term_regex(term).search(t)})


def title_tokens(title):
    return frozenset(words(title).split())


def jaccard(a, b):
    a, b = set(a), set(b)
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


def cluster_headlines(articles, threshold=TITLE_SIMILARITY_THRESHOLD):
    """FC6: group the same story across outlets (Jaccard(title tokens) >= threshold, greedy, newest first).

    Returns [{title, url, domain, date, outlets, urls, articles}] where title/url/domain/date are the newest
    article of the cluster and outlets the sorted distinct source domains.
    """
    ordered = sorted(articles, key=lambda a: a.get("date") or "", reverse=True)
    clusters = []
    for a in ordered:
        toks = title_tokens(a.get("title"))
        for c in clusters:
            if jaccard(toks, c["_tokens"]) >= threshold:
                c["_members"].append(a)
                break
        else:
            clusters.append({"_tokens": toks, "_members": [a]})
    out = []
    for c in clusters:
        head = c["_members"][0]
        out.append({
            "title": head.get("title"),
            "url": head.get("url"),
            "domain": head.get("domain"),
            "date": head.get("date"),
            "outlets": sorted({m.get("domain") for m in c["_members"] if m.get("domain")}),
            "urls": [m.get("url") for m in c["_members"]],
            "articles": len(c["_members"]),
        })
    return out


def adverse_media_mentions(articles, name, kind="org", include_en=False, homonym_phrase=None,
                           threshold=TITLE_SIMILARITY_THRESHOLD, max_headlines=MAX_HEADLINES):
    """FC6/FC7: parsed articles -> at most `max_headlines` story clusters whose headline contains the exact name and
    a risk term. Every hit is a 'mention' (severity info, summary low), never risk-scored; person names carry the
    P252 homonym phrase (pass core namematch's phrase; a neutral default is used otherwise).
    Output per mention: title, outlet domains, date, URL(s) and matched terms only.
    """
    phrase = name_phrase(name, kind)
    terms = risk_terms(kind, include_en)
    matched = []
    for a in articles or []:
        if not isinstance(a, dict):
            continue
        hits = headline_match(a.get("title") or "", phrase, terms)
        if hits:
            b = dict(a)
            b["matched_terms"] = hits
            matched.append(b)
    clusters = cluster_headlines(matched, threshold)
    for c in clusters:
        members = [m for m in matched if m.get("url") in c["urls"]]
        c["matched_terms"] = sorted({t for m in members for t in m["matched_terms"]})
        c["label"] = MENTION_LABEL
        c["severity"] = "info"
    result = {
        "name_phrase": phrase,
        "kind": kind,
        "terms_version": RISK_TERMS_VERSION,
        "articles_total": len([a for a in (articles or []) if isinstance(a, dict)]),
        "articles_matched": len(matched),
        "clusters_total": len(clusters),
        "mentions": clusters[:max_headlines],
        "truncated": len(clusters) > max_headlines,
        "summary_severity": "low" if clusters else None,
        "risk_scored": False,
        "citation": GDELT_CITATION,
        "homonym": None,
    }
    if kind == "person":
        result["homonym"] = homonym_phrase or HOMONYM_DEFAULT_PHRASE
    return result


def url_pivots(mentions):
    """produces: url - one url pivot per mention cluster member (expand=False: articles are never fetched)."""
    seen, out = set(), []
    for m in mentions or []:
        for u in m.get("urls") or [m.get("url")]:
            if isinstance(u, str) and u not in seen:
                seen.add(u)
                out.append({"type": "url", "value": u, "expand": False})
    return out


GOOGLE_NEWS_SEARCH = "https://news.google.com/search"


def google_news_manual_link(name, kind="org"):
    """FC2: Google News is never automated; this is the manual pivot link (news.google.com/search?q=)."""
    phrase = name_phrase(name, kind)
    terms = risk_terms(kind)
    q = f'"{phrase}" (' + " OR ".join(f'"{t}"' if " " in t else t for t in terms) + ")"
    return GOOGLE_NEWS_SEARCH + "?" + urllib.parse.urlencode(
        {"q": q, "hl": "pt-BR", "gl": "BR", "ceid": "BR:pt-419"}, quote_via=urllib.parse.quote)


def adverse_media_query_allowed(kind, analyst_typed, purpose, source=None):
    """FC5 gate helper: company names by default; person names only for analyst-typed due-diligence subjects with a
    recorded purpose; never QSA partners, pivots or names from text; never employment screening.
    Returns None when allowed, else a short reason (reason_code 'privacy')."""
    if kind == "org":
        return None
    if kind != "person":
        return "unsupported kind"
    if not analyst_typed or source in ("qsa", "pivot", "text"):
        return "person names only for analyst-typed due-diligence subjects"
    if not purpose or not str(purpose).strip():
        return "person-name news search needs a recorded purpose"
    if re.search(r"\b(employment|hiring|recruit|candidate|emprego|contratacao|admissao|candidato|selecao)\b",
                 words(purpose)):
        return "employment screening is not an allowed purpose"
    return None


# =====================================================================
# P254 wanted_notices - FBI Wanted
# =====================================================================

FBI_LIST_URL = "https://api.fbi.gov/wanted/v1/list"   # alias of the documented /@wanted
FBI_PAGE_SIZE = 50          # server clamps pageSize to 50 (pageSize=100 answered 50 items)
FBI_MAX_PAGES = 25          # FC1 cap
FBI_CYBER_SUBJECT = "cyber's most wanted"
FBI_CYBER_PATH = "/wanted/cyber/"
FBI_CYBER_LIST_PAGE = "https://www.fbi.gov/wanted/cyber"
INTERPOL_RED_NOTICES_PAGE = "https://www.interpol.int/How-we-work/Notices/Red-Notices/View-Red-Notices"
POSSIBLE_MATCH_LABEL = "possible match - not identity proof"
GROUP_TITLE_WORDS = ("group", "hackers", "hacking", "workers", "actors", "conspirators", "officers", "unit")
NAME_PARTICLES = ("da", "de", "do", "das", "dos", "e", "d", "del", "van", "von", "bin", "al")
GENERIC_ALIAS_WORDS = frozenset({"group", "team", "hackers", "hacker", "apt", "unknown", "china", "chinese", "russia",
                                 "russian", "iran", "iranian", "north korea", "dprk", "korea", "gang", "crew",
                                 "actor", "actors", "ransomware", "malware", "spider", "panda", "bear", "kitten"})
_ANCHOR_RE = re.compile(r"<a\b[^>]*?href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a\s*>", re.I | re.S)


def fbi_list_params(page, page_size=FBI_PAGE_SIZE, poster_classification="default"):
    """FC1 dataset fetch parameters. The API has NO subject filter (`subjects=` is ignored: total stayed 1283), so
    the documented poster_classification filter narrows the walk (default: 730 items = 15 pages) and the cyber
    subject is selected locally. Pass poster_classification=None for the unfiltered walk (1283 items = 26 pages >
    the 25-page cap)."""
    p = {"pageSize": str(int(page_size)), "page": str(int(page))}
    if poster_classification:
        p["poster_classification"] = poster_classification
    return p


def fbi_page_meta(raw):
    """{total, page, count} of one list page (ParseError on HTML/malformed)."""
    obj = load_json(raw)
    if not isinstance(obj, dict):
        raise ParseError("unexpected_json", type(obj).__name__)
    items = obj.get("items")
    total = obj.get("total")
    page = obj.get("page")
    return {"total": total if isinstance(total, int) and total >= 0 else None,
            "page": page if isinstance(page, int) else None,
            "count": len(items) if isinstance(items, list) else 0}


def fbi_pages_needed(total, page_size=FBI_PAGE_SIZE, cap=FBI_MAX_PAGES):
    """FC1: pages to walk for `total` items, capped. {'pages', 'capped', 'missing_items'} (capped -> partial run)."""
    if not isinstance(total, int) or total <= 0:
        return {"pages": 1, "capped": False, "missing_items": 0}
    need = -(-total // page_size)
    pages = min(need, cap)
    return {"pages": pages, "capped": need > cap, "missing_items": max(0, total - pages * page_size)}


def fbi_is_cyber(item):
    """Local subject filter: "Cyber's Most Wanted" in subjects (any apostrophe) or a /wanted/cyber/ poster path."""
    if not isinstance(item, dict):
        return False
    subs = item.get("subjects")
    if isinstance(subs, list):
        for s in subs:
            if isinstance(s, str) and fold(s).replace("’", "'").strip() == FBI_CYBER_SUBJECT:
                return True
    path = item.get("path")
    if isinstance(path, str) and path.startswith(FBI_CYBER_PATH):
        return True
    url = item.get("url")
    return isinstance(url, str) and FBI_CYBER_PATH in url


def _str_list(value):
    if isinstance(value, list):
        return [" ".join(v.split()) for v in value if isinstance(v, str) and v.strip()]
    if isinstance(value, str) and value.strip():
        return [" ".join(value.split())]
    return []


def _path_of(url):
    if not isinstance(url, str):
        return None
    if url.startswith("/"):
        return url.rstrip("/")
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    if (parts.hostname or "").lower() not in ("www.fbi.gov", "fbi.gov"):
        return None
    return parts.path.rstrip("/") or None


def _fbi_links(item, own_path):
    links = {}
    for f in ("caution", "remarks", "details", "additional_information", "description"):
        v = item.get(f)
        if not isinstance(v, str):
            continue
        for href, label in _ANCHOR_RE.findall(v):
            p = _path_of(html.unescape(href))
            if p and p.startswith(FBI_CYBER_PATH) and p != own_path:
                links.setdefault(p, strip_html(label) or None)
    return links


def _fbi_match_text(item):
    parts = []
    for f in ("title", "description", "caution", "remarks", "details", "additional_information"):
        v = item.get(f)
        if isinstance(v, str):
            parts.append(strip_html(v))
    parts.extend(_str_list(item.get("aliases")))
    return " " + words(" ".join(parts), split_digits=True) + " "


def normalise_fbi_item(item):
    """FC4: one FBI poster -> {uid, title, aliases, charges, subjects, url, path, poster_urls, field_offices, status,
    publication, modified, is_group, links{path: label}, match_text}. Images, physical description, dates of birth
    and places are never kept (no biometrics, minimal personal data). match_text is the folded searchable text
    used only for local matching (never rendered)."""
    if not isinstance(item, dict):
        return None
    url = item.get("url") if isinstance(item.get("url"), str) else None
    path = item.get("path") if isinstance(item.get("path"), str) else _path_of(url)
    path = path.rstrip("/") if path else None
    title = " ".join(item.get("title").split()) if isinstance(item.get("title"), str) else None
    charges = strip_html(item.get("description")) if isinstance(item.get("description"), str) else ""
    posters = []
    for f in item.get("files") or []:
        if isinstance(f, dict) and isinstance(f.get("url"), str) and f["url"].startswith("https://"):
            posters.append(f["url"])
    links = _fbi_links(item, path)
    aliases = _str_list(item.get("aliases"))
    t = words(title or "")
    is_group = bool(re.search(r"\b(" + "|".join(GROUP_TITLE_WORDS) + r")\b", t)) or (
        not aliases and not charges and len(links) >= 2)
    return {
        "uid": item.get("uid") if isinstance(item.get("uid"), str) else None,
        "title": title,
        "aliases": aliases,
        "charges": charges or None,
        "subjects": _str_list(item.get("subjects")),
        "url": url,
        "path": path,
        "poster_urls": posters,
        "field_offices": _str_list(item.get("field_offices")),
        "status": item.get("status") if isinstance(item.get("status"), str) else None,
        "publication": item.get("publication") if isinstance(item.get("publication"), str) else None,
        "modified": item.get("modified") if isinstance(item.get("modified"), str) else None,
        "is_group": is_group,
        "links": links,
        "match_text": _fbi_match_text(item),
    }


def parse_fbi_list(raw, cyber_only=True):
    """FC1: one /wanted/v1/list page -> normalised cyber records (ParseError on HTML, challenge or malformed JSON).
    An empty 'items' list (page past the end) -> []."""
    text = raw if isinstance(raw, (dict, list)) else to_text(raw)
    if isinstance(text, str):
        blk = detect_block(None, None, text)
        if blk and blk != "rate_limited":
            raise ParseError("challenge", blk)
    obj = load_json(text)
    if not isinstance(obj, dict):
        raise ParseError("unexpected_json", type(obj).__name__)
    items = obj.get("items")
    if items is None:
        raise ParseError("unexpected_json", "no items key")
    if not isinstance(items, list):
        raise ParseError("unexpected_json", "items is not a list")
    out = []
    for it in items:
        if cyber_only and not fbi_is_cyber(it):
            continue
        rec = normalise_fbi_item(it)
        if rec and (rec["path"] or rec["uid"]):
            out.append(rec)
    return out


def merge_fbi_pages(pages):
    """Dataset assembly: concatenate page record lists, de-duplicated by path (or uid), first occurrence wins."""
    seen, out = set(), []
    for recs in pages or []:
        for r in recs or []:
            key = r.get("path") or r.get("uid")
            if key and key not in seen:
                seen.add(key)
                out.append(r)
    return out


def fbi_public_view(rec):
    """FC4 output fields only: name, aliases, charges, poster URL(s), status."""
    return {"title": rec.get("title"), "aliases": list(rec.get("aliases") or []), "charges": rec.get("charges"),
            "url": rec.get("url"), "poster_urls": list(rec.get("poster_urls") or []), "status": rec.get("status")}


def actor_alias_forms(actor, aliases=()):
    """FC1: actor name + P295 aliases -> distinct match forms (folded, letter/digit split, padded). Forms shorter
    than 4 characters or generic words are dropped to avoid false links; 'Lazarus Group' also yields 'lazarus'."""
    forms = set()
    for a in [actor, *(aliases or ())]:
        if not isinstance(a, str):
            continue
        w = words(a, split_digits=True)
        cands = {w}
        stripped = re.sub(r" (group|team|gang|crew)$", "", w)
        cands.add(stripped)
        for c in cands:
            if len(c.replace(" ", "")) < 4 or c in GENERIC_ALIAS_WORDS:
                continue
            forms.add(c)
    return sorted(forms, key=lambda s: (-len(s), s))


def match_actor(records, actor, aliases=()):
    """FC1/FC2/FC4: local match of the cached cyber list against an actor and its aliases (no name leaves the host).

    Direct hits: any alias form inside a poster's title/aliases/charges/caution/remarks/details. Group posters that
    hit pull in the members they link to and the posters that link back to them. Returns
    {actor, forms, matched[], individuals[], groups[], count, summary, label, severity, confidence}.
    """
    forms = actor_alias_forms(actor, aliases)
    by_path = {r.get("path"): r for r in records or [] if isinstance(r, dict) and r.get("path")}
    direct = []
    for r in records or []:
        if not isinstance(r, dict):
            continue
        txt = r.get("match_text") or ""
        hit = next((f for f in forms if (" " + f + " ") in txt), None)
        if hit:
            direct.append((r, hit))
    groups = [r for r, _ in direct if r.get("is_group")]
    group_paths = {g.get("path") for g in groups}
    individuals = {}

    def add(path, rec, via, label=None, alias=None):
        if not path or path in individuals or path in group_paths:
            return
        if rec is not None and rec.get("is_group"):
            return
        view = fbi_public_view(rec) if rec else {"title": label, "aliases": [], "charges": None,
                                                    "url": "https://www.fbi.gov" + path, "poster_urls": [],
                                                    "status": None}
        view.update({"path": path, "via": via, "matched_alias": alias})
        individuals[path] = view

    for r, hit in direct:
        if not r.get("is_group"):
            add(r.get("path"), r, "direct", alias=hit)
    for g in groups:
        for p, label in (g.get("links") or {}).items():
            add(p, by_path.get(p), "group_poster", label=label)
        for r in records or []:
            if isinstance(r, dict) and g.get("path") in (r.get("links") or {}):
                add(r.get("path"), r, "links_to_group")
    inds = sorted(individuals.values(), key=lambda v: (v["via"] != "direct", v.get("path") or ""))
    n = len(inds)
    return {
        "actor": actor,
        "forms": forms,
        "matched": [dict(fbi_public_view(r), path=r.get("path"), matched_alias=h, is_group=bool(r.get("is_group")))
                    for r, h in direct],
        "groups": [dict(fbi_public_view(g), path=g.get("path")) for g in groups],
        "individuals": inds,
        "count": n,
        "summary": f"{n} indicted individuals linked to {actor} - FBI" if n else None,
        "label": POSSIBLE_MATCH_LABEL,
        "severity": "info",
        "confidence": "medium",
    }


def _person_tokens(name):
    toks = [t for t in words(name).split() if t not in NAME_PARTICLES]
    while toks and toks[0] in HONORIFICS:
        toks = toks[1:]
    return toks


def match_person(records, person_name, homonym_phrase=None):
    """FC2/FC4: analyst-typed person seed matched locally against poster titles and aliases (never sent anywhere).

    match_type: 'name_exact' (same token set as the title, any order), 'alias_exact', or 'name_subset' (all seed
    tokens, >= 2, inside the title). Group posters are skipped. Each hit is a 'possible match - not identity proof'
    at INFO/MEDIUM with the homonym phrase. Seeds with fewer than 2 tokens return [] (too ambiguous).
    """
    seed = _person_tokens(person_name)
    if len(seed) < 2:
        return []
    sset = set(seed)
    out = []
    for r in records or []:
        if not isinstance(r, dict) or r.get("is_group"):
            continue
        title_set = set(_person_tokens(r.get("title") or ""))
        mtype = None
        if title_set and sset == title_set:
            mtype = "name_exact"
        elif any(sset == set(_person_tokens(a)) for a in r.get("aliases") or []):
            mtype = "alias_exact"
        elif title_set and sset <= title_set:
            mtype = "name_subset"
        if mtype:
            v = fbi_public_view(r)
            v.update({"path": r.get("path"), "match_type": mtype, "label": POSSIBLE_MATCH_LABEL,
                      "severity": "info", "confidence": "medium",
                      "homonym": homonym_phrase or HOMONYM_DEFAULT_PHRASE})
            out.append(v)
    order = {"name_exact": 0, "alias_exact": 1, "name_subset": 2}
    return sorted(out, key=lambda v: (order[v["match_type"]], v.get("path") or ""))


def fbi_marker(status, body, headers=None):
    """Marker helper for an api.fbi.gov answer -> None or 'challenge:<vendor>' | 'rate_limited' | 'http_<code>' |
    'html_not_json' | 'malformed_json' | 'empty_body' | 'unexpected_json'."""
    blk = detect_block(status, headers, body)
    if blk:
        return blk
    if status is not None and status >= 400:
        return f"http_{status}"
    try:
        obj = load_json(body)
    except ParseError as exc:
        return exc.reason
    if not isinstance(obj, dict) or not isinstance(obj.get("items"), list):
        return "unexpected_json"
    return None


def interpol_manual_link():
    """FC3: INTERPOL is never automated (unknown terms, Akamai wall). Red-notice web search as a manual link with
    no name in the URL; yellow notices (missing persons) are excluded entirely."""
    return INTERPOL_RED_NOTICES_PAGE


def fbi_manual_link():
    return FBI_CYBER_LIST_PAGE


def now_iso():  # pragma: no cover - convenience for scripts
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
