"""Brand app discovery and look-alike apps (P346): Apple iTunes Search, Digital Asset Links (P008 client),
Koodous (company token) and Google Play manual links.

Final conditions of P346 (council #1) and where they live:

1. Brand terms come only from org_profile brands, or from a company_name/keyword seed the analyst typed
   with explicit ``-M`` (``ScanOptions.include``); never from domain pivots (:func:`select_terms`,
   ``run_on='seeds'``; a domain seed runs only when it is an organisation domain and then searches the
   org brands, any other domain is SKIPPED ``not_applicable``).
2. Apple iTunes Search (``country=br``, ``entity=software``, :func:`itunes_search_url`): registry source
   ``apple.itunes_search`` has terms class ``license`` - off under the corporate profile until legal
   records a licence_allow entry with a metadata-only scope (the policy gate narrows
   ``ctx.allowed_sources``; the module queries only the allowed feeds).
3. App metadata only (:func:`parse_itunes_results` drops artwork, screenshots and previews: they are never
   downloaded, stored or displayed). <= 20 calls/min: provider ``apple`` http_profile ``min_interval`` 3 s
   plus a token bucket of 0.333/s. A bare 403 is retried ONCE with the identical request (same default
   UA, same headers) after the host's politeness interval; the retry declares :data:`ITUNES_RETRY_WAIT_S`
   as Apple's interval, so every later Apple call of the run backs off to 8 s. A second 403, or no time
   left in the run deadline, is BLOCKED 'could not verify' - never another UA (P326).
4. Android official apps are confirmed through the Digital Asset Links client of P008
   (:func:`v3lum.modules.domain_dns.digital_asset_links.fetch_statements`, package + signing-certificate
   SHA-256; no copy of the client). Analyst-provided APK files: the apk_triage certificate SHA-256 is
   compared with the official certificates by the correlation rule ``mobile_app_apk_official_cert``
   (``v3lum/correlations/p2_g03_2.py``). F-Droid is dropped from this build (backlog p2-G03-2).
5. Koodous only with the company token (key ``koodous``, ``Authorization: Token``), for APK package
   lookups of the official Android packages (:func:`koodous_search_url`; only the read endpoints,
   :func:`koodous_path_allowed`); a 401/403 is NEEDS_KEY. Google Play only as manual pivot links
   (:func:`google_play_links`), never fetched or scraped.
6. Official apps (developer id, seller name or exact bundle id of org_profile; Android: package +
   certificate in the official domain's DAL or org_profile) form the ``official_apps`` known_good list.
   Look-alike = brand term in the app name AND seller/developer not matching the organisation AND absent
   from the official domain's DAL, scored by name similarity and seller mismatch (:func:`classify_app`).
   A developer-entered seller URL or bundle prefix of the organisation never makes an app official: with
   another seller it raises the look-alike score (P346 notes W4).
7. Look-alikes are a review list at LOW ('needs analyst review'), capped at 20, pivots ``expand=False``,
   never 'malicious' (:func:`review_findings`).
8. ``.apk`` links found on scam pages or in pasted messages are recorded as url entities only and never
   downloaded (:func:`is_apk_url`, correlation rule ``mobile_app_apk_link``; this module never fetches a
   store page, an APK or an artwork URL).
9. Tests: the recorded research sample (gaps__app_store_search), real iTunes and Digital Asset Links
   captures, official app recognised, look-alike listed for review, 403 handling
   (``tests/modules/test_mobile_app_impersonation.py``).
"""

from __future__ import annotations

import difflib
import json
import re
import unicodedata
from typing import Any
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

from v3lum.core import psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    OfflineError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, HealthResult, Module, register
from v3lum.modules.domain_dns.digital_asset_links import SOURCE as SOURCE_DAL
from v3lum.modules.domain_dns.digital_asset_links import fetch_statements, normalize_cert_sha256

SOURCE_ITUNES = "apple.itunes_search"
SOURCE_KOODOUS = "koodous.apks"
KEY_KOODOUS = "koodous"

ITUNES_HOST = "itunes.apple.com"
ITUNES_SEARCH_URL = "https://itunes.apple.com/search"
ITUNES_LOOKUP_URL = "https://itunes.apple.com/lookup"
ITUNES_COUNTRY = "br"  # c2
ITUNES_ENTITY = "software"  # c2
ITUNES_LIMIT = 50
ITUNES_MIN_INTERVAL_S = 3.0  # c3: <= 20 calls/min
ITUNES_RETRY_WAIT_S = 8.0  # c3: Apple back-off interval after a 403 (live 2026-11-26: refusals lasted > 11 s)
ITUNES_MAX_TERMS = 3  # searched terms per run (max_requests budget: 3 x (1 + one retry))
ITUNES_MAX_BYTES = 2 * 1024 * 1024  # 50 results observed at 470-500 KB

KOODOUS_HOST = "developer.koodous.com"
KOODOUS_BASE = f"https://{KOODOUS_HOST}"
KOODOUS_MAX_LOOKUPS = 2
#: Koodous GET endpoints that change state or move files (docs.koodous.com/api/apks.html): never called.
KOODOUS_STATE_CHANGING = ("analyze_static", "analyze_dynamic", "analyze_yara", "download", "get_upload_url",
                          "vote_negative", "vote_positive", "comments", "votes")

DAL_MAX_DOMAINS = 2
REVIEW_CAP = 20  # c7
REVIEW_SEVERITY = "low"  # c7
REVIEW_LABEL = "needs analyst review"  # c7
MAX_LINKS = 8

#: org_profile ``[[app_ids]]`` kinds read here (free-form kinds of the P378 schema).
APP_ID_KINDS = ("apple_developer_id", "apple_seller", "apple_track_id", "bundle_id", "bundle_prefix",
                "android_package", "android_cert_sha256")
#: Apple fields that are never output, downloaded or displayed (c3).
ARTWORK_FIELDS = ("artworkUrl60", "artworkUrl100", "artworkUrl512", "screenshotUrls", "ipadScreenshotUrls",
                  "appletvScreenshotUrls", "previewUrl")

LOOKALIKE_CRITERION = ("brand term in the app name AND seller/developer not matching the organisation AND not listed in "
                       "the official domain's Digital Asset Links (P346 c6): a review candidate, never a verdict")
UNVERIFIED_CRITERION = ("official package or bundle name without a comparable signing certificate or matching seller "
                        "(P346 c6): cannot be confirmed either way")

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_PKG = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_][A-Za-z0-9_-]*)+$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CRITICALITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ======================================================================================== text helpers


def _clean(value: Any, limit: int = 300) -> str:
    """Untrusted value -> one line without control characters, capped."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", " ", _CTRL.sub("", value)).strip()[:limit]


def _loads(raw: Any) -> tuple[Any, str | None]:
    """(value, why): Apple bodies are text/javascript with leading newlines; never rely on content-type."""
    if isinstance(raw, (dict, list)):
        return raw, None
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("utf-8", errors="replace")
    text = raw if isinstance(raw, str) else ""
    if not text.strip():
        return None, "empty body"
    head = text.lstrip("﻿ \t\r\n")[:300].lower()
    if head.startswith(("<!doctype html", "<html")) or "<head" in head or "<body" in head:
        return None, "HTML instead of JSON"
    try:
        return json.loads(text), None
    except ValueError:
        return None, "malformed JSON"


_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ο": "o", "α": "a", "ν": "v", "κ": "k", "τ": "t", "ι": "i",
    "ρ": "p", "ε": "e",
})
_LEET_L = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
_LEET_I = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
_LEGAL = frozenset({"sa", "ltda", "ltd", "llc", "inc", "corp", "corporation", "co", "company", "limited", "plc", "gmbh",
                    "ag", "bv", "nv", "me", "epp", "eireli", "pte", "pty", "srl", "spa", "oy", "ab", "as", "kk", "lp",
                    "llp", "sas", "sl", "slu"})


def fold(value: Any) -> str:
    """Accent- and case-folded text: 'Itaú' -> 'itau'."""
    if not isinstance(value, str):
        return ""
    norm = unicodedata.normalize("NFKD", value)
    return "".join(ch for ch in norm if not unicodedata.combining(ch)).casefold()


def skeleton(value: Any) -> str:
    """fold() plus confusable folding (matching only, never displayed)."""
    return fold(value).translate(_CONFUSABLES)


def tokens(value: Any) -> list[str]:
    return re.findall(r"[a-z0-9]+", skeleton(value))


def seller_key(name: Any) -> str:
    """Comparable seller/developer name: 'BANCO BRADESCO S.A.' -> 'banco bradesco'; 'Google LLC' -> 'google'."""
    text = re.sub(r"\bs\s*[/.]\s*a\b\.?", " sa ", skeleton(name))
    toks = re.findall(r"[a-z0-9]+", text)
    while toks and toks[-1] in _LEGAL:
        toks.pop()
    return " ".join(toks)


def url_host(url: Any) -> str | None:
    """Lower-case host of an http(s) URL (trailing dot removed), else None. Never fetches anything."""
    if not isinstance(url, str) or not url.strip():
        return None
    try:
        parts = urlsplit(url.strip())
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host:
        return None
    return host.rstrip(".").lower() or None


def _contains_seq(toks: list[str], sub: list[str]) -> bool:
    n = len(sub)
    return any(toks[i:i + n] == sub for i in range(len(toks) - n + 1)) if n else False


def brand_hits(text: Any, terms: Any) -> list[str]:
    """Brand terms present in ``text`` (c6 'brand term in the app name').

    Whole-token phrase match on accent/confusable-folded tokens. Terms of <= 3 letters ('bb') match only as
    whole tokens (never inside 'bbc'); longer terms also match after leet folding ('g00gle') and, from 5
    letters, glued inside a token ('googleforms', 'bancodobrasil')."""
    if not isinstance(text, str) or not text.strip():
        return []
    base = skeleton(text)
    hits: list[str] = []
    for term in terms or ():
        tt = tokens(term) if isinstance(term, str) else []
        if not tt:
            continue
        joined = "".join(tt)
        variants = [base] if len(joined) <= 3 else [base, base.translate(_LEET_L), base.translate(_LEET_I)]
        for variant in variants:
            toks = re.findall(r"[a-z0-9]+", variant)
            if _contains_seq(toks, tt) or (len(joined) >= 5 and joined in "".join(toks)):
                if term not in hits:
                    hits.append(term)
                break
    return hits


def name_similarity(name: Any, terms: Any) -> float:
    """0..1 similarity of an app name to the brand terms (c6 scoring input): an exact copy scores 1.0."""
    if not isinstance(name, str) or not name.strip():
        return 0.0
    nf = " ".join(tokens(name))
    best = 0.0
    for term in terms or ():
        tf = " ".join(tokens(term)) if isinstance(term, str) else ""
        if not tf or not nf:
            continue
        ratio = difflib.SequenceMatcher(None, nf, tf).ratio()
        if brand_hits(name, [term]):
            score = max(ratio, 0.5 + 0.5 * min(1.0, len(tf) / max(len(nf), 1)))
            if nf.startswith(tf):
                score += 0.1
        else:
            score = ratio * 0.5
        best = max(best, min(1.0, score))
    return round(best, 3)


# ======================================================================================== org profile (c1, c6)


def _norm_domain(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    dom = value.strip().rstrip(".").lower()
    if dom.startswith("*."):
        dom = dom[2:]
    if not dom or "/" in dom or " " in dom or "." not in dom:
        return None
    try:
        return dom.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _reverse_prefix(domain: str) -> str | None:
    labels = [x for x in domain.split(".") if x]
    return (".".join(reversed(labels)) + ".") if len(labels) >= 2 else None


def profile_view(org: Any, *, seed_identity: str = "") -> dict[str, Any]:
    """OrgProfile (P378) -> the plain view the classifier needs (c1, c6). Never sent anywhere.

    Seller identities = the org name, explicit ``apple_seller`` app ids and brand keywords of >= 6 letters
    or >= 2 words (a short generic keyword never makes a seller official), plus ``seed_identity`` (an
    analyst-typed company name checked with -M). ``domains`` are ``(name, criticality)`` pairs."""
    name = _clean(getattr(org, "name", ""), 200) if org is not None else ""
    domains: list[tuple[str, str]] = []
    for entry in (getattr(org, "domains", None) or []) if org is not None else []:
        dom = _norm_domain(getattr(entry, "name", None))
        if dom and dom not in [d for d, _c in domains]:
            domains.append((dom, str(getattr(entry, "criticality", "") or "medium")))
    keywords: list[str] = []
    variants: list[str] = []
    for brand in (getattr(org, "brands", None) or []) if org is not None else []:
        kw = fold(getattr(brand, "keyword", "")).strip()
        if kw and kw not in keywords:
            keywords.append(kw)
        for var in getattr(brand, "variants", ()) or ():
            fv = fold(var).strip() if isinstance(var, str) else ""
            if fv and fv not in variants and fv not in keywords:
                variants.append(fv)
    ids: dict[str, set[str]] = {k: set() for k in APP_ID_KINDS}
    prefixes: list[str] = []
    for app in (getattr(org, "app_ids", None) or []) if org is not None else []:
        kind = str(getattr(app, "kind", "") or "").strip().lower()
        value = str(getattr(app, "value", "") or "").strip()
        if kind == "android_signing_cert_sha256":
            kind = "android_cert_sha256"
        if kind == "android_app":
            kind = "android_package"
        if kind not in ids or not value:
            continue
        if kind == "bundle_prefix":
            prefix = value.lower().rstrip(".") + "."
            if prefix not in prefixes:
                prefixes.append(prefix)
        elif kind == "android_cert_sha256":
            fp = normalize_cert_sha256(value)
            if fp:
                ids[kind].add(fp)
        elif kind == "apple_seller":
            ids[kind].add(seller_key(value))
        elif kind in ("bundle_id", "android_package"):
            ids[kind].add(value.lower())
        else:
            ids[kind].add(value)
    sellers = {k for k in ({seller_key(name)} | ids["apple_seller"]) if k}
    for kw in keywords:
        if len(kw.split()) >= 2 or len(kw.replace(" ", "")) >= 6:
            sellers.add(seller_key(kw))
    if seed_identity:
        sellers.add(seller_key(seed_identity))
    sellers.discard("")
    return {
        "name": name,
        "domains": domains,
        "keywords": keywords,
        "variants": variants,
        "match_terms": keywords + [v for v in variants if v not in keywords],
        "seller_keys": sellers,
        "developer_ids": ids["apple_developer_id"],
        "track_ids": ids["apple_track_id"],
        "bundle_ids": ids["bundle_id"],
        "bundle_prefixes": prefixes,
        "derived_prefixes": [p for p in (_reverse_prefix(d) for d, _c in domains) if p],
        "android_packages": ids["android_package"],
        "android_certs": ids["android_cert_sha256"],
        "owns_host": None,
    }


def _has_identity(view: dict[str, Any]) -> bool:
    return bool(view.get("seller_keys") or view.get("developer_ids") or view.get("track_ids") or view.get("bundle_ids")
                or view.get("android_packages"))


def _owned(view: dict[str, Any], host: Any) -> bool:
    """Organisation host? Through OrgProfile.owns() (PSL registrable domain + subdomain, never a suffix test)."""
    check = view.get("owns_host")
    if not host or not callable(check):
        return False
    try:
        return bool(check(host))
    except Exception:  # noqa: BLE001 - an odd host is simply not owned
        return False


def select_terms(view: dict[str, Any], etype: T, value: str, *, explicit: bool, own_domain: bool,
                 max_terms: int = ITUNES_MAX_TERMS, min_search_len: int = 4) -> dict[str, Any]:
    """Brand terms for one run (c1).

    -> {"search": [...], "match": [...], "skip": None | (status, reason_code, reason), "note": str, "own": bool,
    "term": str}. Org brands always; a company_name/keyword seed outside the profile only when typed with -M; a
    domain seed only when it is an organisation domain (never a term derived from the domain itself)."""
    match = list(view.get("match_terms") or [])
    search = [k for k in (view.get("keywords") or []) if len(k.replace(" ", "")) >= min_search_len]
    out: dict[str, Any] = {"search": [], "match": [], "skip": None, "note": "", "own": False, "term": ""}
    if etype in (T.ORG, T.KEYWORD):
        term = (seller_key(value) if etype is T.ORG else fold(value)).strip()
        term = re.sub(r"\s+", " ", term)
        out["term"] = term
        own = term in match or (etype is T.ORG and term in (view.get("seller_keys") or set()))
        out["own"] = own
        if not own:
            if not explicit:
                out["skip"] = (Status.SKIPPED, "not_applicable",
                               "brand terms come only from org_profile brands or from a company/keyword seed typed with "
                               "explicit -M (P346 c1)")
                return out
            if len(term.replace(" ", "")) < 2:
                out["skip"] = (Status.SKIPPED, "not_applicable", "seed too short to be a brand term")
                return out
            match = [term] + [m for m in match if m != term]
            if len(term.replace(" ", "")) >= min_search_len:
                search = [term] + [s for s in search if s != term]
        elif term in search or len(term.replace(" ", "")) >= min_search_len:
            search = [term] + [s for s in search if s != term]  # the typed org brand (or variant) first
    elif etype is T.DOMAIN:
        out["own"] = own_domain
        if not own_domain:
            out["skip"] = (Status.SKIPPED, "not_applicable",
                           "not an org_profile domain: brand terms are never derived from domains (P346 c1)")
            return out
    if not match:
        out["skip"] = (Status.SKIPPED, "config", "no org_profile brands to check (v3lum org): add [[brands]] to the profile")
        return out
    out["search"], out["match"] = search[:max_terms], match
    if not search:
        out["note"] = (f"no brand keyword of >= {min_search_len} letters to search; short terms are only used to match "
                       "app names (high collision)")
    elif len(search) > max_terms:
        out["note"] = f"{len(search) - max_terms} brand keyword(s) not searched this run (max {max_terms})"
    return out


# ======================================================================================== Apple iTunes (c2, c3)


def itunes_search_url(term: Any, country: str = ITUNES_COUNTRY, limit: int = ITUNES_LIMIT) -> str | None:
    """https://itunes.apple.com/search?term=..&entity=software&country=br&limit=50 (c2); None on a bad term."""
    text = _clean(term, 200) if isinstance(term, str) else ""
    if not text or len(text) > 100 or not re.fullmatch(r"[a-z]{2}", country or ""):
        return None
    lim = limit if isinstance(limit, int) and 1 <= limit <= 200 else ITUNES_LIMIT
    return f"{ITUNES_SEARCH_URL}?term={quote(text, safe='')}&entity={ITUNES_ENTITY}&country={country}&limit={lim}"


def itunes_lookup_url(track_id: Any = None, bundle_id: Any = None, country: str = ITUNES_COUNTRY) -> str | None:
    """https://itunes.apple.com/lookup?id=<trackId>|bundleId=<bundle>&country=br; None on bad input."""
    if not re.fullmatch(r"[a-z]{2}", country or ""):
        return None
    if track_id is not None and re.fullmatch(r"\d{1,12}", str(track_id)):
        return f"{ITUNES_LOOKUP_URL}?id={track_id}&country={country}"
    if isinstance(bundle_id, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.\-_]{0,154}", bundle_id):
        return f"{ITUNES_LOOKUP_URL}?bundleId={quote(bundle_id, safe='')}&country={country}"
    return None


def _date(value: Any) -> str | None:
    return value[:10] if isinstance(value, str) and re.match(r"^\d{4}-\d{2}-\d{2}", value) else None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"\d{1,15}", value.strip()):
        return int(value.strip())
    return None


def _strip_query(url: Any) -> str | None:
    """https URL without query/fragment (drops Apple's '?uo=4'); None for non-http(s)."""
    if url_host(url) is None:
        return None
    parts = urlsplit(url.strip())
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path, "", ""))


def parse_itunes_results(raw: Any) -> dict[str, Any]:
    """Search or lookup body -> {"state": ok|empty|error, "result_count", "apps", "skipped", "error"}.

    App records: {store 'apple', rank, track_id, name, bundle_id, seller, developer, developer_id, seller_url,
    seller_domain, store_url, developer_url, genre, released, updated, version, rating_count} - metadata
    only: artwork, screenshot and preview URLs never leave this function (c3). Never raises."""
    doc, why = _loads(raw)
    out: dict[str, Any] = {"state": "error", "result_count": None, "apps": [], "skipped": 0, "error": why}
    if not isinstance(doc, dict):
        out["error"] = out["error"] or "answer is not a JSON object"
        return out
    if doc.get("errorMessage") not in (None, ""):
        out["error"] = "errorMessage: " + _clean(doc.get("errorMessage"), 200)
        return out
    results = doc.get("results")
    if not isinstance(results, list):
        out["error"] = "no results list"
        return out
    out["result_count"] = _int(doc.get("resultCount"))
    seen: set[Any] = set()
    for rank, rec in enumerate(results[:200], 1):
        if not isinstance(rec, dict):
            out["skipped"] += 1
            continue
        kind = rec.get("kind") or rec.get("wrapperType")
        name = _clean(rec.get("trackName"), 200) if isinstance(rec.get("trackName"), str) else ""
        if kind not in (None, "software") or not name:
            out["skipped"] += 1
            continue
        tid = _int(rec.get("trackId"))
        key = tid if tid is not None else ("name", name, _clean(rec.get("bundleId"), 160))
        if key in seen:
            continue
        seen.add(key)
        seller_url = rec.get("sellerUrl") if url_host(rec.get("sellerUrl")) else None
        artist_id = _int(rec.get("artistId"))
        out["apps"].append({
            "store": "apple",
            "rank": rank,
            "track_id": tid,
            "name": name,
            "bundle_id": _clean(rec.get("bundleId"), 160) or None,
            "seller": _clean(rec.get("sellerName"), 200) or _clean(rec.get("artistName"), 200) or None,
            "developer": _clean(rec.get("artistName"), 200) or None,
            "developer_id": str(artist_id) if artist_id is not None else None,
            "seller_url": _clean(seller_url, 300) or None,
            "seller_domain": url_host(seller_url),
            "store_url": _strip_query(rec.get("trackViewUrl")),
            "developer_url": _strip_query(rec.get("artistViewUrl")),
            "genre": _clean(rec.get("primaryGenreName"), 60) or None,
            "released": _date(rec.get("releaseDate")),
            "updated": _date(rec.get("currentVersionReleaseDate")),
            "version": _clean(rec.get("version"), 40) or None,
            "rating_count": _int(rec.get("userRatingCount")),
        })
    out["error"] = None
    out["state"] = "ok" if out["apps"] else "empty"
    return out


def _itunes_cacheable(resp: Any) -> bool:
    """cache_if veto: only real search/lookup answers are cached (never an errorMessage body)."""
    try:
        return parse_itunes_results(resp.text)["state"] in ("ok", "empty")
    except Exception:  # noqa: BLE001 - an unreadable answer is never cached
        return False


def bare_403(resp: Any) -> bool:
    """A plain HTTP 403 (Apple's empty-body refusal), not a challenge or geo-block page: the one case c3 lets
    the module retry once with the identical request."""
    if getattr(resp, "status", None) != 403:
        return False
    found = getattr(resp, "classification", None)
    return found is None or getattr(found, "marker_id", "") == "keyless.403"


# ======================================================================================== Koodous (c5)


def koodous_search_url(package: Any = None, sha256: Any = None) -> str | None:
    """GET /apks/?search=package: <pkg> | hash: <sha256> (documented search modifiers)."""
    if isinstance(sha256, str) and _HEX64.match(sha256.strip().lower()):
        query = f"hash: {sha256.strip().lower()}"
    elif isinstance(package, str) and _PKG.match(package.strip()):
        query = f"package: {package.strip()}"
    else:
        return None
    return f"{KOODOUS_BASE}/apks/?search={quote(query, safe='')}"


def koodous_detail_url(sha256: Any) -> str | None:
    """GET /apks/<sha256>/ (detail)."""
    if isinstance(sha256, str) and _HEX64.match(sha256.strip().lower()):
        return f"{KOODOUS_BASE}/apks/{sha256.strip().lower()}/"
    return None


def koodous_path_allowed(url: Any) -> bool:
    """True only for the read endpoints (/apks/ search, /apks/<sha256>/ detail); analysis requests, votes,
    comments, downloads and upload links are refused (they change state or move files)."""
    if not isinstance(url, str):
        return False
    path = urlsplit(url).path if "://" in url else url.split("?", 1)[0]
    low = path.lower()
    if any(action in low for action in KOODOUS_STATE_CHANGING):
        return False
    return bool(re.fullmatch(r"/apks/(?:[0-9a-f]{64}/)?", low))


def parse_koodous_apk(obj: Any) -> dict[str, Any] | None:
    """One Koodous APK object -> normalised dict, or None. The icon URL is dropped (no artwork, c3)."""
    if not isinstance(obj, dict):
        return None
    sha = obj.get("sha256")
    if not isinstance(sha, str) or not _HEX64.match(sha.lower()):
        return None
    pkg = obj.get("package_name")
    tags = obj.get("tags") if isinstance(obj.get("tags"), list) else []
    created = obj.get("created_at") or obj.get("created_on")
    rating = obj.get("rating")
    return {
        "store": "android",
        "source": "koodous",
        "sha256": sha.lower(),
        "name": _clean(obj.get("app"), 200) or None,
        "package": pkg if isinstance(pkg, str) and _PKG.match(pkg) else None,
        "seller": _clean(obj.get("company"), 200) or None,
        "version": _clean(obj.get("version") or obj.get("displayed_version"), 40) or None,
        "tags": [_clean(t, 40) for t in tags if isinstance(t, str)][:20],
        "trusted": obj.get("is_trusted") if isinstance(obj.get("is_trusted"), bool) else None,
        "detected": obj.get("is_detected") if isinstance(obj.get("is_detected"), bool) else None,
        "rating": rating if isinstance(rating, int) and not isinstance(rating, bool) else None,
        "created_at": created[:25] if isinstance(created, str) and re.match(r"^\d{4}-\d{2}-\d{2}", created) else None,
    }


def parse_koodous_search(raw: Any) -> dict[str, Any]:
    """/apks/ list body ({next, previous, results} or a bare list) or a detail body -> {"state": ok|empty|error,
    "apks", "error"}."""
    doc, why = _loads(raw)
    out: dict[str, Any] = {"state": "error", "apks": [], "error": why}
    if isinstance(doc, dict) and isinstance(doc.get("results"), list):
        items = doc["results"]
    elif isinstance(doc, list):
        items = doc
    elif isinstance(doc, dict) and isinstance(doc.get("sha256"), str):
        items = [doc]
    else:
        if isinstance(doc, dict):
            out["error"] = ("detail: " + _clean(doc.get("detail"), 200)) if doc.get("detail") else "unexpected object"
        return out
    out["apks"] = [a for a in (parse_koodous_apk(x) for x in items[:100]) if a]
    out["error"] = None
    out["state"] = "ok" if out["apks"] else "empty"
    return out


def koodous_signal(apk: dict[str, Any] | None) -> dict[str, Any]:
    """Community context for one APK (never a verdict on its own, c7)."""
    a = apk or {}
    label = "detected" if a.get("detected") else ("trusted" if a.get("trusted") else "unrated")
    return {"label": label, "detected": a.get("detected"), "trusted": a.get("trusted"), "rating": a.get("rating")}


def koodous_app_record(apk: dict[str, Any]) -> dict[str, Any]:
    """Koodous APK -> generic app record for classify_app."""
    return {"store": "android", "source": "koodous", "name": apk.get("name"), "seller": apk.get("seller"),
            "developer": apk.get("seller"), "package": apk.get("package"), "bundle_id": apk.get("package"),
            "sha256": apk.get("sha256"), "cert_sha256": None, "koodous": koodous_signal(apk)}


# ======================================================================================== Digital Asset Links (c4)


def dal_view(parsed: list[dict[str, Any]]) -> dict[str, Any]:
    """P008 parses of the official domains -> {"state": ok|not_published|unknown, "apps": {pkg: [fps]}}.

    'unknown' when no domain could be verified (403/429/5xx/odd answer): look-alikes are then listed with
    'Digital Asset Links not verified'."""
    apps: dict[str, list[str]] = {}
    states = []
    for item in parsed:
        state = item.get("state") if isinstance(item, dict) else None
        states.append(state)
        if state != "ok":
            continue
        for app in item.get("apps") or []:
            pkg = app.get("package") if isinstance(app, dict) else None
            if not isinstance(pkg, str) or not _PKG.match(pkg):
                continue
            entry = apps.setdefault(pkg.lower(), [])
            for fp in app.get("sha256") or []:
                norm = normalize_cert_sha256(fp)
                if norm and norm not in entry:
                    entry.append(norm)
    if "ok" in states:
        return {"state": "ok", "apps": apps}
    if states and all(s == "not_published" for s in states):
        return {"state": "not_published", "apps": {}}
    return {"state": "unknown", "apps": {}}


def dal_check(dal: dict[str, Any] | None, package: Any, cert_sha256: Any = None) -> str:
    """'listed' | 'listed_other_cert' | 'listed_cert_unknown' | 'absent' | 'not_published' | 'unknown'."""
    if not isinstance(dal, dict) or dal.get("state") not in ("ok", "not_published"):
        return "unknown"
    if dal.get("state") == "not_published":
        return "not_published"
    if not isinstance(package, str) or not package:
        return "absent"
    certs = (dal.get("apps") or {}).get(package.lower())
    if certs is None:
        return "absent"
    fp = normalize_cert_sha256(cert_sha256) if cert_sha256 else None
    if fp is None or not certs:
        return "listed_cert_unknown"  # nothing to compare: never read as a mismatch
    return "listed" if fp in certs else "listed_other_cert"


# ======================================================================================== classification (c6, c7)


def _seller_similarity(seller: Any, view: dict[str, Any]) -> float:
    key = seller_key(seller)
    if not key:
        return 0.0
    return max((difflib.SequenceMatcher(None, key, k).ratio() for k in view.get("seller_keys") or ()), default=0.0)


_DAL_REASON = {
    "absent": "not listed in the official domain's Digital Asset Links",
    "not_published": "official domain publishes no Digital Asset Links statements",
    "unknown": "Digital Asset Links not verified (could not verify)",
    "n/a": "Digital Asset Links not applicable",
}


def classify_app(app: dict[str, Any], view: dict[str, Any], dal: dict[str, Any] | None = None, terms: Any = None) -> dict[str, Any]:
    """c6 for one store record -> {"category": official|lookalike|unverified|unrelated, "official_by",
    "signals", "brand_terms", "dal", "score", "reasons", "claims_org_identity"}.

    official   : developer id, track id, seller/developer name or exact bundle id of org_profile; Android:
                 package + signing certificate listed in the official domain's DAL (P008) or org_profile.
    lookalike  : brand term in the app name AND seller/developer not matching AND not listed in DAL. An org
                 seller URL or bundle prefix with another seller is NOT official (developer-entered on
                 Apple): the app stays a look-alike with a higher score. An official Android package signed
                 with another certificate is a look-alike (possible repackaged app).
    unverified : an official package or bundle name without a certificate to compare and without a
                 matching seller: analyst review.
    unrelated  : no brand term in the name (counted, not listed)."""
    a = app if isinstance(app, dict) else {}
    v = view or {}
    terms = list(terms) if terms else list(v.get("match_terms") or [])
    name = a.get("name") or ""
    bundle = a.get("bundle_id") or a.get("package") or ""
    bl = bundle.lower() if isinstance(bundle, str) else ""
    official_by: list[str] = []
    signals: list[str] = []
    if a.get("developer_id") and str(a["developer_id"]) in (v.get("developer_ids") or set()):
        official_by.append("developer_id")
    if a.get("track_id") is not None and str(a["track_id"]) in (v.get("track_ids") or set()):
        official_by.append("track_id")
    keys = {seller_key(a.get("seller")), seller_key(a.get("developer"))} - {""}
    if keys & set(v.get("seller_keys") or ()):
        official_by.append("seller_name")
    if bl and bl in (v.get("bundle_ids") or set()):
        official_by.append("bundle_id")
    if _owned(v, a.get("seller_domain")):
        signals.append("seller_url")
    if bl and any(bl.startswith(p) for p in (v.get("bundle_prefixes") or [])):
        signals.append("bundle_prefix")
    elif bl and any(bl.startswith(p) for p in (v.get("derived_prefixes") or [])):
        signals.append("bundle_prefix_derived")
    fp = normalize_cert_sha256(a.get("cert_sha256")) if a.get("cert_sha256") else None
    dal_state = "n/a"
    if a.get("store") == "android":
        dal_state = dal_check(dal, a.get("package"), a.get("cert_sha256"))
        if dal_state == "listed":
            official_by.append("digital_asset_links")
        elif bl and bl in (v.get("android_packages") or set()) and fp and fp in (v.get("android_certs") or set()):
            official_by.append("org_profile_android")
    elif dal is not None and bl:
        dal_state = dal_check(dal, bl)
    hits = brand_hits(name, terms)
    res: dict[str, Any] = {"category": "unrelated", "official_by": official_by, "signals": signals, "brand_terms": hits,
                           "dal": dal_state, "score": None, "reasons": [], "claims_org_identity": False}
    if official_by:
        res["category"] = "official"
        return res
    claims = bool({"seller_url", "bundle_prefix"} & set(signals))
    res["claims_org_identity"] = claims
    if a.get("store") == "android":
        in_profile = bool(bl) and bl in (v.get("android_packages") or set())
        prof_certs = v.get("android_certs") or set()
        if dal_state == "listed_other_cert" or (in_profile and fp and prof_certs and fp not in prof_certs):
            res.update(category="lookalike", score=1.0, reasons=[
                "official package name signed with a different certificate (possible repackaged app)",
                f"Digital Asset Links: {dal_state}"])
            return res
        if dal_state == "listed_cert_unknown" or (in_profile and (not fp or not prof_certs)):
            res.update(category="unverified", reasons=[
                "official package name but no signing certificate to compare: cannot confirm (obtain the APK and run "
                "apk_triage offline, or compare the certificate manually)"])
            return res
    if not hits:
        return res
    if dal_state == "listed_cert_unknown":
        res.update(category="unverified", reasons=[
            "bundle id equals a package listed in the official domain's Digital Asset Links but the seller does not "
            "match: verify manually"])
        return res
    seller = a.get("seller") or a.get("developer") or "unknown seller"
    sim = _seller_similarity(seller, v)
    imitates = sim >= 0.6 or bool(brand_hits(seller, terms))
    ns = name_similarity(name, terms)
    score = 0.6 * ns + 0.4 * (1.0 if imitates else 0.7) + (0.1 if claims else 0.0)
    reasons = [f"brand term '{hits[0]}' in the app name"]
    if _has_identity(v):
        reasons.append(f"seller '{_clean(seller, 80)}' does not match the organisation")
    else:
        reasons.append(f"seller '{_clean(seller, 80)}': no organisation identity to compare (org_profile has no name, "
                       "seller or app ids)")
    if imitates:
        reasons.append("seller name resembles the organisation")
    if "seller_url" in signals:
        reasons.append("uses an organisation domain as seller URL (developer-entered)")
    if "bundle_prefix" in signals:
        reasons.append("uses an organisation bundle prefix (developer-entered)")
    reasons.append(_DAL_REASON.get(dal_state, f"Digital Asset Links: {dal_state}"))
    res.update(category="lookalike", score=round(min(1.0, score), 3), reasons=reasons, name_similarity=ns,
               seller_similarity=round(sim, 3))
    return res


def _app_key(app: dict[str, Any]) -> tuple[Any, ...]:
    if app.get("store") == "apple" and app.get("track_id") is not None:
        return ("apple", app["track_id"])
    if app.get("sha256"):
        return ("sha256", app["sha256"])
    return (app.get("store"), (app.get("bundle_id") or app.get("package") or "").lower(), app.get("name"))


def build_review(apps: Any, view: dict[str, Any], dal: dict[str, Any] | None = None, terms: Any = None,
                 cap: int = REVIEW_CAP) -> dict[str, Any]:
    """Classify store records (several searches may repeat apps) -> {"official", "review" (look-alikes by
    score, then unverified; <= cap), "review_total", "omitted", "unrelated", "claims_org_identity"} (c6, c7)."""
    seen: set[tuple[Any, ...]] = set()
    official: list[dict[str, Any]] = []
    looks: list[dict[str, Any]] = []
    unver: list[dict[str, Any]] = []
    claims: list[dict[str, Any]] = []
    unrelated = 0
    for app in apps or ():
        if not isinstance(app, dict):
            continue
        key = _app_key(app)
        if key in seen:
            continue
        seen.add(key)
        cls = classify_app(app, view, dal, terms)
        item = {**app, "classification": cls}
        if cls["category"] == "official":
            official.append(item)
        elif cls["category"] == "lookalike":
            looks.append(item)
        elif cls["category"] == "unverified":
            unver.append(item)
        else:
            unrelated += 1
            if cls["claims_org_identity"]:
                claims.append(item)
    looks.sort(key=lambda x: (-(x["classification"]["score"] or 0), x.get("rank") or 10**6, x.get("name") or ""))
    cap = cap if isinstance(cap, int) and cap > 0 else REVIEW_CAP
    review = (looks + unver)[:cap]
    total = len(looks) + len(unver)
    return {"official": official, "review": review, "review_total": total, "omitted": max(0, total - len(review)),
            "lookalikes_total": len(looks), "unverified_total": len(unver), "unrelated": unrelated,
            "claims_org_identity": claims}


def review_item(item: dict[str, Any]) -> dict[str, Any]:
    """One review-list entry (attribute ``lookalike_apps`` and finding data): metadata only."""
    cls = item.get("classification") or {}
    return {
        "store": item.get("store"),
        "category": cls.get("category"),
        "name": item.get("name"),
        "seller": item.get("seller"),
        "bundle_id": item.get("bundle_id") or item.get("package"),
        "track_id": item.get("track_id"),
        "store_url": item.get("store_url"),
        "seller_url": item.get("seller_url"),
        "sha256": item.get("sha256"),
        "score": cls.get("score"),
        "reasons": list(cls.get("reasons") or []),
        "dal": cls.get("dal"),
        "koodous": item.get("koodous"),
    }


def official_entry(item: dict[str, Any]) -> dict[str, Any]:
    """known_good entry (attribute ``official_apps``)."""
    cls = item.get("classification") or {}
    return {"store": item.get("store"), "name": item.get("name"), "seller": item.get("seller"),
            "bundle_id": item.get("bundle_id") or item.get("package"), "track_id": item.get("track_id"),
            "store_url": item.get("store_url"), "official_by": list(cls.get("official_by") or [])}


def lookalike_pivots(item: dict[str, Any], view: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Pivots of one review item, all ``expand=False`` (c7): keyword = bundle id / package, domain = seller site
    when it is not an organisation domain, sha256 = APK sample (Koodous)."""
    out: list[dict[str, Any]] = []
    bid = item.get("bundle_id") or item.get("package")
    if isinstance(bid, str) and bid:
        out.append({"type": T.KEYWORD, "value": bid, "relation": "app_bundle_id"})
    dom = item.get("seller_domain")
    if dom and not _owned(view or {}, dom):
        out.append({"type": T.DOMAIN, "value": dom, "relation": "app_seller_site"})
    if item.get("sha256"):
        out.append({"type": T.SHA256, "value": item["sha256"], "relation": "apk_sample"})
    return out


# ======================================================================================== links (c5, c8)


def google_play_links(terms: Any = (), packages: Any = ()) -> list[tuple[str, str]]:
    """Google Play search/details links (c5): manual pivot links only, never fetched or parsed."""
    out: list[tuple[str, str]] = []
    for term in terms or ():
        text = _clean(term, 100) if isinstance(term, str) else ""
        if text:
            out.append((f"Google Play search: {text} (manual)",
                        f"https://play.google.com/store/search?q={quote(text, safe='')}&c=apps&hl=pt_BR&gl=BR"))
    for pkg in packages or ():
        if isinstance(pkg, str) and _PKG.match(pkg):
            out.append((f"Google Play app {pkg} (manual)",
                        f"https://play.google.com/store/apps/details?id={quote(pkg, safe='.')}&hl=pt_BR"))
    return out


def is_apk_url(url: Any) -> bool:
    """True for an http(s) URL whose path, or a query value, ends with '.apk' (c8)."""
    if url_host(url) is None:
        return False
    parts = urlsplit(url.strip())
    if parts.path.lower().rstrip("/").endswith(".apk"):
        return True
    return any(v.lower().endswith(".apk") for _k, v in parse_qsl(parts.query, keep_blank_values=True))


def apk_url_entities(urls: Any) -> list[dict[str, Any]]:
    """.apk links from scam pages or pasted messages -> url entities only (c8): expand/fetch/download False."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for url in urls or ():
        if not isinstance(url, str) or not is_apk_url(url):
            continue
        value = _clean(url, 2000)
        if value in seen:
            continue
        seen.add(value)
        out.append({"type": T.URL, "value": value, "expand": False, "fetch": False, "download": False,
                    "tags": ["apk_link"], "filename": _clean(urlsplit(value).path.rsplit("/", 1)[-1], 200) or None})
    return out


# ======================================================================================== failures


def failure_of(exc: BaseException, *, keyed: bool = False) -> tuple[Status, str]:
    """(status, reason_code) of a source failure (rule 5: always 'could not verify', never absent)."""
    if isinstance(exc, QuotaExceeded):
        return Status.QUOTA, "quota"
    if isinstance(exc, RateLimited):
        return Status.RATE_LIMITED, "rate_limited"
    if isinstance(exc, Blocked):
        code = getattr(exc, "reason_code", "") or "challenge"
        return Status.BLOCKED, code if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge"
    if isinstance(exc, AuthRequired):
        return (Status.NEEDS_KEY, "needs_key") if keyed else (Status.BLOCKED, "challenge")
    if isinstance(exc, OfflineError):
        return Status.UNAVAILABLE, "offline"
    if isinstance(exc, DeadlineExceeded):
        return Status.ERROR, "timeout"
    if isinstance(exc, NetworkError):
        return Status.ERROR, "timeout" if "timed out" in str(exc).lower() else "error"
    return Status.ERROR, "error"


_SOURCE_ERRORS = (QuotaExceeded, RateLimited, Blocked, AuthRequired, HttpError, NetworkError)
_FAILURE_ORDER = (Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.NEEDS_KEY, Status.UNAVAILABLE, Status.ERROR)


class _Stop(Exception):
    """A source refused us: no further calls to it in this run."""


# ======================================================================================== the module


def _selftest(ctx: Any) -> HealthResult:
    """Doctor self-test (offline=False, a normal passive ctx): the P008 client on the central benign domain
    and, when the licence profile allows Apple, one iTunes search for a benign public brand."""
    try:
        parsed = fetch_statements(ctx, "example.com")
    except _SOURCE_ERRORS as exc:
        status, _code = failure_of(exc)
        return HealthResult({Status.QUOTA: "quota", Status.NEEDS_KEY: "needs_key"}.get(status, "blocked"),
                            f"Digital Asset Links: {str(exc)[:120]}")
    if parsed.get("state") not in ("ok", "not_published"):
        return HealthResult("dead", f"Digital Asset Links: unexpected answer ({parsed.get('error') or parsed.get('state')})")
    if SOURCE_ITUNES in (getattr(ctx, "allowed_sources", None) or ()):
        try:
            resp = ctx.http.get(itunes_search_url("wikipedia"), source=SOURCE_ITUNES, cache_if=_itunes_cacheable)
            if bare_403(resp):
                return HealthResult("blocked", "Apple iTunes: HTTP 403 (could not verify)")
            ctx.http.check(resp)
        except _SOURCE_ERRORS as exc:
            status, _code = failure_of(exc)
            return HealthResult("quota" if status is Status.QUOTA else "blocked", f"Apple iTunes: {str(exc)[:120]}")
        if parse_itunes_results(resp.text)["state"] == "error":
            return HealthResult("dead", "Apple iTunes: unexpected answer")
    return HealthResult("ok", "")


@register
class MobileAppImpersonation(Module):
    name = "mobile_app_impersonation"
    title = "Brand app discovery and look-alike apps (App Store, Digital Asset Links, Koodous)"
    description = (
        "Finds the organisation's official apps and look-alike apps for its brands: Apple iTunes Search (BR store, "
        "metadata only), the official Android apps of the org domains through Digital Asset Links (P008 client) and, "
        "with the company token, Koodous APK package lookups. Look-alikes are a capped LOW review list, never a verdict; "
        "Google Play is offered as manual links only."
    )
    category = "url_web"
    accepts = {T.ORG, T.KEYWORD, T.DOMAIN}
    produces = {T.KEYWORD, T.SHA256, T.DOMAIN}
    tags = {"brazil"}
    reference = "https://performance-partners.apple.com/search-api"
    notice = (
        "Apple's Search API terms cover promotional use: the iTunes feed is 'license' and stays off under the corporate "
        "licence profile until legal records a metadata-only licence_allow entry. Brand terms come only from org_profile "
        "brands or a company/keyword seed typed with -M. Look-alike apps are review candidates (LOW, 'needs analyst "
        "review'), never 'malicious'; artwork, store pages and APK files are never downloaded."
    )
    terms = "license"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "apple"
    sources = (SOURCE_ITUNES, SOURCE_DAL, SOURCE_KOODOUS)
    hosts = (ITUNES_HOST, "digitalassetlinks.googleapis.com", KOODOUS_HOST)
    access_model = "free_noauth_limited"
    optional_keys = (KEY_KOODOUS,)
    run_on = "seeds"
    max_requests = 10  # iTunes <= 3 x (1 + one same-request retry), DAL <= 2, Koodous <= 2
    expected_latency = 6.0
    timeout = 60.0
    min_interval = 1.0
    cache_ttl = 86400
    max_pivots = 3 * REVIEW_CAP
    manual_link = "https://play.google.com/store/search?q={q}&c=apps&hl=pt_BR&gl=BR"
    default_enabled = True

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=False, selftest=_selftest)

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if not ctx.is_seed:
            return res.mark("skipped", "runs on analyst-typed seeds only: brand terms are never taken from pivots (P346 c1)",
                            reason_code="not_applicable")
        org = ctx.org
        explicit = self.name in set(getattr(ctx.options, "include", ()) or ())
        own_domain = False
        if entity.type is T.DOMAIN and org is not None:
            try:
                own_domain = bool(org.owns(entity).own)
            except Exception:  # noqa: BLE001 - an unreadable profile owns nothing
                own_domain = False
        view = profile_view(org)
        view["owns_host"] = self._owner_check(org)
        sel = select_terms(view, entity.type, str(entity.value), explicit=explicit, own_domain=own_domain)
        if sel["skip"]:
            status, code, why = sel["skip"]
            return res.mark(status, why, reason_code=code)
        if entity.type is T.ORG and not sel["own"] and sel["term"]:
            # an analyst-typed company name (-M) outside the profile is the identity being checked (c6)
            view["seller_keys"] = set(view["seller_keys"]) | {sel["term"]}
        allowed = ctx.allowed_sources
        coverage: dict[str, Any] = {"terms_searched": [], "sources": {}, "dal_domains": [], "dal_state": "not queried"}
        failures: list[tuple[str, Status, str, str]] = []
        raw: dict[str, Any] = {"itunes": [], "dal": [], "koodous": []}
        apps: list[dict[str, Any]] = []
        answered = False  # a store source (iTunes / Koodous) answered (ok or empty)

        # Digital Asset Links of the official domains (c4) - P008's client
        dal = self._dal(ctx, entity, view, allowed, coverage, failures, raw)

        # Apple iTunes Search (c2, c3)
        if SOURCE_ITUNES in allowed and sel["search"]:
            found, ok = self._itunes(ctx, sel["search"], coverage, failures, raw)
            apps.extend(found)
            answered = answered or ok
        elif SOURCE_ITUNES not in allowed:
            coverage["sources"][SOURCE_ITUNES] = "not run (licence profile: Apple Search API terms are 'license')"
        else:
            coverage["sources"][SOURCE_ITUNES] = "not run (" + (sel["note"] or "no search term") + ")"

        # Koodous APK package lookups (c5)
        packages = self._official_packages(view, dal)
        if SOURCE_KOODOUS in allowed:
            found, ok = self._koodous(ctx, res, packages, coverage, failures, raw)
            apps.extend(found)
            answered = answered or ok
        else:
            coverage["sources"][SOURCE_KOODOUS] = "not run (licence profile: Koodous is 'key-terms', record key_plans.koodous)"

        review = build_review(apps, view, dal, sel["match"])
        for item in failures:
            src, status, code, why = item
            res.source_status(src, status, reason_code=code, reason=why)
        self._emit(res, entity, view, sel, dal, review, coverage, raw)
        return self._finish(res, review, dal, answered, failures, sel, coverage)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _owner_check(org: Any) -> Any:
        if org is None or getattr(org, "is_empty", True):
            return None

        def owns(host: str) -> bool:
            ent = Entity.try_make(T.DOMAIN, host)
            return bool(ent is not None and org.owns(ent).own)

        return owns

    @staticmethod
    def _dal_domains(entity: Entity, view: dict[str, Any], own_domain_seed: bool) -> list[str]:
        """Registrable org domains to read (seed domain first, then by criticality), at most DAL_MAX_DOMAINS."""
        ordered: list[str] = []

        def add(name: str) -> None:
            try:
                reg = psl.registrable_domain(name)
            except Exception:  # noqa: BLE001 - an unknown suffix has no registrable domain
                reg = None
            if reg and reg not in ordered:
                ordered.append(reg)

        if own_domain_seed:
            add(str(entity.value))
        for name, _crit in sorted(view.get("domains") or [], key=lambda d: _CRITICALITY.get(d[1], 2)):
            add(name)
        return ordered[:DAL_MAX_DOMAINS]

    def _dal(self, ctx: Any, entity: Entity, view: dict[str, Any], allowed: frozenset[str], coverage: dict[str, Any],
             failures: list[tuple[str, Status, str, str]], raw: dict[str, Any]) -> dict[str, Any] | None:
        own_seed = entity.type is T.DOMAIN and _owned(view, entity.value)
        domains = self._dal_domains(entity, view, own_seed)
        if SOURCE_DAL not in allowed:
            coverage["sources"][SOURCE_DAL] = "not run (not allowed in this run)"
            return None
        if not domains:
            coverage["sources"][SOURCE_DAL] = "not run (no org_profile domain)"
            return None
        parsed: list[dict[str, Any]] = []
        for dom in domains:
            try:
                answer = fetch_statements(ctx, dom)
            except _SOURCE_ERRORS as exc:
                status, code = failure_of(exc)
                failures.append((SOURCE_DAL, status, code, f"Digital Asset Links ({dom}): {_clean(str(exc), 160)}"))
                parsed.append({"state": "could_not_verify"})
                raw["dal"].append({"domain": dom, "state": "could_not_verify", "error": _clean(str(exc), 160)})
                if status in (Status.RATE_LIMITED, Status.QUOTA, Status.BLOCKED):
                    break
                continue
            parsed.append(answer)
            raw["dal"].append({"domain": dom, "state": answer.get("state"), "apps": answer.get("apps"),
                               "error_codes": answer.get("error_codes"), "error": answer.get("error")})
        coverage["dal_domains"] = domains
        view_dal = dal_view(parsed)
        coverage["dal_state"] = view_dal["state"]
        coverage["sources"][SOURCE_DAL] = {"ok": "answered", "not_published": "answered (no statements published)",
                                           "unknown": "could not verify"}[view_dal["state"]]
        if view_dal["state"] == "unknown" and not any(f[0] == SOURCE_DAL for f in failures):
            failures.append((SOURCE_DAL, Status.ERROR, "error", "Digital Asset Links: unexpected answer (could not verify)"))
        return view_dal

    def _itunes(self, ctx: Any, terms: list[str], coverage: dict[str, Any], failures: list[tuple[str, Status, str, str]],
                raw: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
        apps: list[dict[str, Any]] = []
        answered = False
        per_term: dict[str, str] = {}
        stopped = ""
        for term in terms:
            url = itunes_search_url(term)
            if url is None:
                per_term[term] = "not searched (invalid term)"
                continue
            if stopped:
                per_term[term] = f"not searched ({stopped})"
                continue
            try:
                parsed = self._itunes_call(ctx, url)
            except _Stop as exc:
                why = str(exc)
                failures.append((SOURCE_ITUNES, Status.BLOCKED, "challenge", why))
                per_term[term] = why
                stopped = "Apple refused the previous search"
                continue
            except _SOURCE_ERRORS as exc:
                status, code = failure_of(exc)
                why = f"Apple iTunes: {_clean(str(exc), 160)}"
                failures.append((SOURCE_ITUNES, status, code, why))
                per_term[term] = f"could not verify ({status.value})"
                if status is not Status.ERROR:
                    stopped = f"Apple answered {status.value}"
                continue
            coverage["terms_searched"].append(term)
            raw["itunes"].append({"term": term, "state": parsed["state"], "result_count": parsed["result_count"],
                                  "apps": parsed["apps"][:ITUNES_LIMIT], "error": parsed["error"]})
            if parsed["state"] == "error":
                why = f"Apple iTunes: unexpected answer ({parsed['error']}): could not verify"
                failures.append((SOURCE_ITUNES, Status.ERROR, "error", why))
                per_term[term] = "could not verify (unexpected answer)"
                continue
            answered = True
            per_term[term] = f"{len(parsed['apps'])} app(s)" if parsed["apps"] else "App Store BR: no apps found"
            apps.extend(parsed["apps"])
        coverage["sources"][SOURCE_ITUNES] = per_term
        return apps, answered

    @staticmethod
    def _itunes_call(ctx: Any, url: str) -> dict[str, Any]:
        """One search with the c3 403 rule: a bare 403 is retried ONCE with the identical request (same URL,
        headers and UA) after the host's politeness interval, then BLOCKED 'could not verify'; challenge and
        geo-block pages raise at once. The retry raises Apple's per-host interval to ITUNES_RETRY_WAIT_S for
        the rest of the run (the core limiter keeps the largest interval declared for a host)."""
        kwargs: dict[str, Any] = {"source": SOURCE_ITUNES, "cache_if": _itunes_cacheable, "max_bytes": ITUNES_MAX_BYTES}
        resp = ctx.http.get(url, **kwargs)
        if bare_403(resp):
            remaining = ctx.remaining()
            if remaining is not None and remaining < ITUNES_RETRY_WAIT_S + 3.0:
                raise _Stop("Apple iTunes: could not verify (HTTP 403, no time left for the retry)")
            ctx.log("Apple iTunes: HTTP 403 (retrying once, same request)")
            resp = ctx.http.get(url, min_interval=ITUNES_RETRY_WAIT_S, **kwargs)
            if bare_403(resp):
                raise _Stop("Apple iTunes: could not verify (HTTP 403 after one retry)")
        ctx.http.check(resp)
        return parse_itunes_results(resp.text)

    @staticmethod
    def _official_packages(view: dict[str, Any], dal: dict[str, Any] | None) -> list[str]:
        out: list[str] = []
        for pkg in list((dal or {}).get("apps") or {}) + sorted(view.get("android_packages") or ()):
            if isinstance(pkg, str) and _PKG.match(pkg) and pkg not in out:
                out.append(pkg)
        return out

    def _koodous(self, ctx: Any, res: ModuleResult, packages: list[str], coverage: dict[str, Any],
                 failures: list[tuple[str, Status, str, str]], raw: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
        token = ctx.key(KEY_KOODOUS)
        if not token:
            coverage["sources"][SOURCE_KOODOUS] = "not run (needs the company token: key 'koodous')"
            failures.append((SOURCE_KOODOUS, Status.NEEDS_KEY, "needs_key",
                             "Koodous: needs the company token (key 'koodous', V3LUM_KOODOUS_TOKEN)"))
            return [], False
        if not packages:
            coverage["sources"][SOURCE_KOODOUS] = "not run (no official Android package to look up)"
            return [], False
        records: list[dict[str, Any]] = []
        answered = False
        per_pkg: dict[str, str] = {}
        for pkg in packages[:KOODOUS_MAX_LOOKUPS]:
            url = koodous_search_url(package=pkg)
            if url is None or not koodous_path_allowed(url):
                per_pkg[pkg] = "not looked up (invalid package)"
                continue
            try:
                resp = ctx.http.get(url, source=SOURCE_KOODOUS, headers={"Authorization": f"Token {token}"},
                                    allow_redirects=False, cache_if=lambda r: parse_koodous_search(r.text)["state"] != "error")
                ctx.http.check(resp)
            except _SOURCE_ERRORS as exc:
                status, code = failure_of(exc, keyed=True)
                why = f"Koodous: {_clean(str(exc), 160)}"
                if status is Status.NEEDS_KEY:
                    why += " - needs a valid company token (key 'koodous')"
                failures.append((SOURCE_KOODOUS, status, code, why))
                per_pkg[pkg] = f"could not verify ({status.value})"
                if status is not Status.ERROR:
                    break
                continue
            parsed = parse_koodous_search(resp.text)
            raw["koodous"].append({"package": pkg, "state": parsed["state"], "apks": parsed["apks"][:50], "error": parsed["error"]})
            if parsed["state"] == "error":
                failures.append((SOURCE_KOODOUS, Status.ERROR, "error", f"Koodous: unexpected answer ({parsed['error']}): could not verify"))
                per_pkg[pkg] = "could not verify (unexpected answer)"
                continue
            answered = True
            per_pkg[pkg] = f"{len(parsed['apks'])} APK(s)" if parsed["apks"] else "no APK known to Koodous"
            records.extend(koodous_app_record(a) for a in parsed["apks"])
        coverage["sources"][SOURCE_KOODOUS] = per_pkg
        return records, answered

    def _emit(self, res: ModuleResult, entity: Entity, view: dict[str, Any], sel: dict[str, Any], dal: dict[str, Any] | None,
              review: dict[str, Any], coverage: dict[str, Any], raw: dict[str, Any]) -> None:
        official = [official_entry(i) for i in review["official"]]
        for pkg, certs in sorted(((dal or {}).get("apps") or {}).items()):
            official.append({"store": "android", "name": None, "seller": None, "bundle_id": pkg, "track_id": None,
                             "store_url": None, "official_by": ["digital_asset_links"], "cert_sha256": list(certs)})
        items = [review_item(i) for i in review["review"]]
        coverage.update(review_total=review["review_total"], review_shown=len(items), official=len(official),
                        unrelated=review["unrelated"])
        res.attr("official_apps", official)
        res.attr("lookalike_apps", items)
        res.attr("app_store_coverage", coverage)
        res.raw = {"coverage": coverage, **raw}
        if review["official"]:
            names = ", ".join(_clean(i.get("name"), 60) for i in review["official"][:8])
            res.finding(
                "Official apps recognised (known_good)",
                "info",
                f"{len(review['official'])} store app(s) published by the organisation: {names}"
                + (" ..." if len(review["official"]) > 8 else "") + ".",
                confidence="probable",
                data={"apps": official[:40]},
                tags=["known_good"],
                source=SOURCE_ITUNES if any(i.get("store") == "apple" for i in review["official"]) else SOURCE_KOODOUS,
            )
        for item, data in zip(review["review"], items):
            cls = item.get("classification") or {}
            lookalike = cls.get("category") == "lookalike"
            kind = "look-alike" if lookalike else "unverified"
            src = SOURCE_ITUNES if item.get("store") == "apple" else SOURCE_KOODOUS
            seller = _clean(item.get("seller"), 80) or "unknown seller"
            res.finding(
                f"Possible {kind} app for review: {_clean(item.get('name'), 100) or item.get('bundle_id') or '?'}",
                REVIEW_SEVERITY,
                f"{REVIEW_LABEL.capitalize()}: '{_clean(item.get('name'), 100)}' by {seller} "
                f"({item.get('bundle_id') or item.get('package') or 'no bundle id'}) - " + "; ".join(data["reasons"][:5]) + ".",
                confidence="possible",
                criterion=LOOKALIKE_CRITERION if lookalike else UNVERIFIED_CRITERION,
                data={**data, "label": REVIEW_LABEL},
                tags=["lookalike_app"] if lookalike else ["unverified_app"],
                references=[u for u in (item.get("store_url"),) if isinstance(u, str) and u.startswith("https://")],
                source=src,
                key=str(item.get("track_id") or item.get("sha256") or item.get("bundle_id") or item.get("name") or ""),
            )
            for pv in lookalike_pivots(item, view):
                res.pivot(pv["type"], pv["value"], pv["relation"], confidence="possible", expand=False,
                          note=f"{kind} app candidate ({REVIEW_LABEL}); never fetched or downloaded")
        if review["review_total"]:
            more = f" (showing {len(items)}, {review['omitted']} more not shown)" if review["omitted"] else ""
            apple = any(i.get("store") == "apple" for i in review["review"])
            res.finding(
                "App-store review list",
                "info",
                f"{review['review_total']} app(s) for analyst review{more}: {review['lookalikes_total']} look-alike "
                f"candidate(s), {review['unverified_total']} unverified; {len(official)} official, "
                f"{review['unrelated']} unrelated result(s).",
                confidence="possible",
                data={"total": review["review_total"], "shown": len(items), "omitted": review["omitted"]},
                tags=["info"],
                source=SOURCE_ITUNES if apple else SOURCE_KOODOUS,
            )
        android = [i.get("package") for i in review["review"] if i.get("store") == "android" and i.get("package")]
        for label, url in google_play_links(sel["search"] or sel["match"][:1], android)[:MAX_LINKS]:
            res.link(label, url)

    @staticmethod
    def _finish(res: ModuleResult, review: dict[str, Any], dal: dict[str, Any] | None, answered: bool,
                failures: list[tuple[str, Status, str, str]], sel: dict[str, Any], coverage: dict[str, Any]) -> ModuleResult:
        found = bool(review["official"] or review["review"] or ((dal or {}).get("apps")))
        store_failures = [f for f in failures if f[0] in (SOURCE_ITUNES, SOURCE_KOODOUS) and f[1] is not Status.NEEDS_KEY]
        if any(f[1] is Status.RATE_LIMITED for f in failures) and (found or answered):
            res.stop("rate_limited")
        if found:
            return res.mark("ok")
        if store_failures and not answered:
            first = sorted(store_failures, key=lambda f: _FAILURE_ORDER.index(f[1]) if f[1] in _FAILURE_ORDER else 99)[0]
            detail = "; ".join(f[3] for f in store_failures[:3])
            return res.mark(first[1], f"could not verify: {detail}", reason_code=first[2])
        if answered:
            terms = ", ".join(f"'{t}'" for t in coverage.get("terms_searched") or []) or "the brand terms"
            if review["unrelated"]:
                return res.mark("empty", f"App Store BR: {review['unrelated']} app(s) found for {terms}, none published by "
                                         "the organisation or using its brand terms in the app name (no review candidate "
                                         "in these searches)")
            return res.mark("empty", f"App Store BR: no apps found for {terms} (no official app and no look-alike "
                                     "candidate in these searches)")
        dal_fail = [f for f in failures if f[0] == SOURCE_DAL]
        if dal_fail:
            first = dal_fail[0]
            return res.mark(first[1], f"could not verify: {first[3]}", reason_code=first[2])
        key_missing = [f for f in failures if f[1] is Status.NEEDS_KEY]
        why = "no app-store source ran for this entity"
        if SOURCE_ITUNES not in coverage["sources"] or isinstance(coverage["sources"].get(SOURCE_ITUNES), str):
            why += f" ({coverage['sources'].get(SOURCE_ITUNES, 'Apple iTunes not run')})"
        if key_missing:
            why += "; Koodous needs the company token"
        if (dal or {}).get("state") == "not_published":
            why += "; the official domain publishes no Digital Asset Links statements"
        return res.mark("empty", why)
