"""dork_generator: search-engine dork links, BR phone variants and the pasted-URL router (P306, batch p2-G14-3).

Links only (cond 1): the module builds Google, Bing and DuckDuckGo search URLs (``duckduckgo.com/?q=``) and makes
zero HTTP requests; search engines are never queried, scraped or rendered by V3LUM (rule 1) and Google Programmable
Search is not used (it ends on 2027-01-01). Disclosure ``none``: the analyst opens a link in a browser.

* The dork pack ``v3lum/data/dork_generator/dorks.json`` (schema ``v3lum.dork_pack/1``) is V3LUM-owned data written
  from search-operator facts (cond 2, A6): nothing copied from sitedorks/msdorkdump (AGPL), PhoneInfoga (GPL) or
  dorks_hunter / Fast-Google-Dorks-Scan (no licence). :func:`lint_dork` validates it like a pivot pack: whitelisted
  placeholders (re.sub, never str.format), <= 32 words and fewer than 30 ``site:`` operators per query, engines among
  google/bing/duckduckgo with ``ip:``/``url:`` on Bing only, no CPF ever, no person identifier combined with document,
  password or leak terms (cpf, rg, senha, password, vazamento, dump, pastebin), paste-site dorks for domains and brands
  only, privacy flags on person/phone/e-mail/username/PIX rows, LinkedIn X-ray only for the own organisation
  (cond 2, 5, 6).
* Families (cond 3, 4): exposure dorks (documents, configs, panels, errors, directory listings...) only for
  analyst-typed entities, names under a typed apex and org_profile assets, never for pivoted third-party domains;
  Bing ``ip:``/``url:``; site-category dorks over the team-curated BR-focused site lists; BR fraud families (CNPJ on
  Reclame Aqui/Jusbrasil/gov.br, golpe/fraude terms, random PIX keys, phone variants, wa.me and t.me forms). Brazilian
  phone variants come from the offline normaliser :func:`br_phone_variants` (E.164 -> '+55 11 9xxxx-xxxx',
  '(11) 9xxxx-xxxx', '119xxxxxxxx', with and without the 9).
* Gates (cond 6): person, phone, e-mail, username and PIX dorks are privacy rows: analyst-typed seeds of a case that
  opted in (show_personal + a recorded purpose) only. LinkedIn X-ray rows need the organisation name of the
  org_profile (a person at the own organisation, or the own organisation's company entity).
* Rendering (cond 7, 8): at TLP:AMBER and above every label carries 'opening sends <query> to <host>' (renderers show
  module links as plain text there); at TLP:RED nothing is emitted (``v3lum links``). At most 20 links per entity
  (curated rows first, one engine each: setting ``dork_generator_engine``); the terminal view keeps 5 curated rows; the
  rest is listed in the evidence for ``v3lum links --all``.
* :func:`route_pasted_url` is the port of the Ceos pasted-URL router ``destino()`` (cond 9): a pure function telling
  which entity and route a URL the analyst found by hand belongs to (``v3lum add-url``). It never fetches the URL.
"""

from __future__ import annotations

import json
import re
import threading
import unicodedata
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus, unquote, urlsplit

from v3lum.config import SettingSpec
from v3lum.core import tlp as _tlp
from v3lum.core.entities import Entity, platform_for_url
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.core.validators import cnpj_valid, cpf_valid

PACK_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "dork_generator" / "dorks.json"
SCHEMA = "v3lum.dork_pack/1"
ENGINES: dict[str, tuple[str, str]] = {
    "google": ("www.google.com", "https://www.google.com/search?q="),
    "bing": ("www.bing.com", "https://www.bing.com/search?q="),
    "duckduckgo": ("duckduckgo.com", "https://duckduckgo.com/?q="),
}
FAMILIES = ("exposure", "bing_operator", "site_category", "br_fraud", "person", "phone", "email", "username", "pix",
            "linkedin_xray")
SCOPES = ("typed_or_own", "seed_only", "own_org_only")
#: Whitelisted placeholders and the entity types they take.
PLACEHOLDER_TYPES: dict[str, frozenset[T]] = {
    "domain": frozenset({T.DOMAIN}),
    "company": frozenset({T.ORG}),
    "keyword": frozenset({T.KEYWORD}),
    "term": frozenset({T.ORG, T.KEYWORD}),
    "cnpj_fmt": frozenset({T.CNPJ}),
    "cnpj_digits": frozenset({T.CNPJ}),
    "ip": frozenset({T.IPV4}),
    "url": frozenset({T.URL}),
    "user": frozenset({T.USERNAME, T.TELEGRAM_HANDLE}),
    "email": frozenset({T.EMAIL}),
    "name": frozenset({T.PERSON}),
    "pix": frozenset({T.PIX}),
    "phone_variants": frozenset({T.PHONE}),
    "phone_wa": frozenset({T.PHONE}),
    "own_company": frozenset({T.PERSON, T.ORG}),
    "sites": frozenset(),  # expands the row's site_list; any type
}
PERSON_TYPES: frozenset[T] = frozenset({T.PERSON, T.EMAIL, T.PHONE, T.USERNAME, T.TELEGRAM_HANDLE, T.PIX})
BRAND_TYPES: frozenset[T] = frozenset({T.DOMAIN, T.ORG, T.KEYWORD, T.CNPJ})
#: cond 5: document, password and leak terms never combined with a person identifier.
FORBIDDEN_PERSON_TERMS = re.compile(
    r"(?i)(?<![a-z0-9])(cpf|rg|senhas?|passwords?|passwd|vazamentos?|vazad[oa]s?|vazou|dumps?|pastebin)(?![a-z0-9])")
PASTE_SITES = ("pastebin.com", "ghostbin.com", "rentry.co", "rentry.org", "paste.ee", "controlc.com", "justpaste.it",
               "pastelink.net", "hastebin.com", "dpaste.org", "dpaste.com")
_BING_ONLY = re.compile(r"(?i)(?<![a-z])(?:ip|url):\{")
_SITE_OP = re.compile(r"(?i)(?<![a-z-])site:")
_RE_PH = re.compile(r"\{([a-z0-9_]+)\}")
_RE_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩﻿]")
_RE_CPF = re.compile(r"(?<!\d)(\d{3}\.?\d{3}\.?\d{3}-?\d{2})(?!\d)")
_RE_SITE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,200}(/[A-Za-z0-9_./-]{1,100})?$")
MAX_DORK_WORDS = 32  # cond 2 (Google's query limit)
MAX_SITE_OPERATORS = 30  # cond 2: each query has fewer than 30 site: operators
TERMINAL_DORK_CAP = 5  # cond 8
REPORT_LINK_CAP = 20  # cond 8
MAX_PHRASE = 128


# --------------------------------------------------------------------------------------
# Values (validated before they enter a query)
# --------------------------------------------------------------------------------------


def dork_phrase(value: Any) -> str:
    """A value safe inside one quoted dork phrase: quotes and control characters removed, whitespace folded, at most
    128 characters ('' when nothing is left)."""
    v = _RE_CTRL.sub(" ", str(value or "")).replace('"', " ").replace("\\", " ")
    return re.sub(r"\s+", " ", v).strip()[:MAX_PHRASE].strip()


def contains_cpf(text: str) -> bool:
    """True when ``text`` carries a CPF number (11 digits with a valid check, formatted or not): rule 4."""
    return any(cpf_valid(re.sub(r"\D", "", m)) for m in _RE_CPF.findall(text or ""))


def _br_digits(phone: str) -> str | None:
    digits = re.sub(r"\D", "", phone or "")
    if not (phone or "").strip().startswith("+") or not digits.startswith("55") or len(digits) not in (12, 13):
        return None
    if digits[2] == "0" or (len(digits) == 13 and digits[4] != "9"):
        return None
    return digits


def br_phone_variants(e164: Any) -> dict[str, Any] | None:
    """cond 4 offline phone normaliser: from an E.164 Brazilian number build '+55 11 9xxxx-xxxx', '(11) 9xxxx-xxxx' and
    '119xxxxxxxx' with and without the mobile 9 (landlines have no 9 variant; a legacy 8-digit mobile gains the 9),
    plus the E.164 and wa.me forms. None for non-Brazilian or invalid input."""
    d = _br_digits(str(e164 or ""))
    if not d:
        return None
    ddd, num = d[2:4], d[4:]
    if len(num) == 9:
        kind, forms = "mobile", [num, num[1:]]
    elif num[0] in "2345":
        kind, forms = "landline", [num]
    elif num[0] in "6789":
        kind, forms = "mobile", ["9" + num, num]
    else:
        return None

    def fmt(n: str) -> dict[str, str]:
        return {"intl": f"+55 {ddd} {n[:-4]}-{n[-4:]}", "national": f"({ddd}) {n[:-4]}-{n[-4:]}", "digits": ddd + n}

    variants: list[str] = []
    for n in forms:
        f = fmt(n)
        variants += [f["intl"], f["national"], f["digits"]]
    return {"kind": kind, "e164": "+55" + ddd + forms[0], "wa": "55" + ddd + forms[0],
            "variants": list(dict.fromkeys(variants))}


def dork_values(entity: Entity, *, own_company: str = "") -> dict[str, str] | None:
    """Placeholder values for one entity (None = the entity never enters a dork: CPF, a value carrying a CPF, an
    unusable value). Text values go through :func:`dork_phrase`; identifiers through their validators."""
    t, v = entity.type, entity.value
    if t is T.CPF or contains_cpf(v):
        return None
    out: dict[str, str] = {}
    if t is T.DOMAIN:
        if not re.fullmatch(r"[a-z0-9.-]{1,253}", v):
            return None
        out["domain"] = v
    elif t in (T.ORG, T.KEYWORD):
        p = dork_phrase(v)
        if not p:
            return None
        out["term"] = p
        out["company" if t is T.ORG else "keyword"] = p
    elif t is T.CNPJ:
        digits = re.sub(r"[^0-9A-Za-z]", "", v).upper()
        if len(digits) != 14 or (digits.isdigit() and not cnpj_valid(digits)):
            return None
        out["cnpj_digits"] = digits
        out["cnpj_fmt"] = f"{digits[:2]}.{digits[2:5]}.{digits[5:8]}/{digits[8:12]}-{digits[12:]}"
    elif t is T.IPV4:
        out["ip"] = v
    elif t is T.URL:
        if '"' in v or any(c.isspace() for c in v) or _RE_CTRL.search(v):
            return None
        out["url"] = v
    elif t in (T.USERNAME, T.TELEGRAM_HANDLE):
        user = v.lstrip("@")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", user) or user in (".", ".."):
            return None
        out["user"] = user
    elif t is T.EMAIL:
        if '"' in v or any(c.isspace() for c in v):
            return None
        out["email"] = v
    elif t is T.PERSON:
        p = dork_phrase(v)
        if not p:
            return None
        out["name"] = p
    elif t is T.PIX:
        if not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", v):
            return None  # random (EVP) keys only: never a CPF key (rule 4)
        out["pix"] = v.lower()
    elif t is T.PHONE:
        pv = br_phone_variants(v)
        if pv:
            forms = [*pv["variants"], pv["e164"]]
            out["phone_wa"] = pv["wa"]
        else:
            digits = re.sub(r"\D", "", v)
            if not 8 <= len(digits) <= 15:
                return None
            forms = ["+" + digits, digits]
            out["phone_wa"] = digits
        out["phone_variants"] = " OR ".join(f'"{f}"' for f in dict.fromkeys(forms))
    else:
        return None
    company = dork_phrase(own_company)
    if company and t in (T.PERSON, T.ORG) and not contains_cpf(company):
        out["own_company"] = company
    return out


# --------------------------------------------------------------------------------------
# Pack lint (cond 2, 5, 6, 7) and loading
# --------------------------------------------------------------------------------------


def count_words(query: str) -> int:
    return len([w for w in re.split(r"\s+", (query or "").replace("(", " ").replace(")", " ")) if w])


def site_operators(query: str) -> int:
    return len(_SITE_OP.findall(query or ""))


def sites_clause(sites: list[str]) -> str:
    return " OR ".join(f"site:{s}" for s in sites)


def _types(entry: Mapping[str, Any]) -> tuple[set[T], list[str]]:
    out: set[T] = set()
    errs: list[str] = []
    raw = entry.get("entity_types")
    if not isinstance(raw, list) or not raw:
        return out, ["entity_types must be a non-empty list"]
    for item in raw:
        try:
            out.add(T(str(item)))
        except ValueError:
            errs.append(f"unknown entity type {item!r}")
    return out, errs


def lint_dork(entry: Any, site_lists: Mapping[str, Any] | None = None) -> list[str]:
    """Problems of one dork row ('DLnn: ...'; empty = clean). Placeholders count as one word."""
    if not isinstance(entry, Mapping):
        return ["DL10: a dork row is an object"]
    errs = [f"DL10: missing field {k}" for k in ("id", "family", "group", "label", "query", "entity_types", "engines",
                                                  "privacy", "scope", "curated") if k not in entry]
    if errs:
        return errs
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", str(entry["id"])):
        errs.append("DL10: invalid id")
    label = entry["label"]
    if not isinstance(label, str) or not label or len(label) > 120 or _RE_CTRL.search(label):
        errs.append("DL10: label must be a single-line string of at most 120 characters")
    if entry["family"] not in FAMILIES:
        errs.append("DL10: unknown family")
    if entry["scope"] not in SCOPES:
        errs.append(f"DL10: scope must be one of {SCOPES}")
    for flag in ("privacy", "curated"):
        if not isinstance(entry[flag], bool):
            errs.append(f"DL10: {flag} must be true or false")
    query = entry["query"]
    if not isinstance(query, str) or not query.strip() or _RE_CTRL.search(query):
        return errs + ["DL10: query must be a single-line string"]
    types, type_errs = _types(entry)
    errs += [f"DL10: {e}" for e in type_errs]
    names = _RE_PH.findall(query)
    if "{" in _RE_PH.sub("", query) or "}" in _RE_PH.sub("", query):
        errs.append("DL01: stray braces (only whitelisted {name} placeholders, never str.format)")
    if not names:
        errs.append("DL01: query has no placeholder")
    for name in names:
        allowed = PLACEHOLDER_TYPES.get(name)
        if allowed is None:
            errs.append(f"DL01: unknown placeholder {{{name}}}")
        elif allowed and not types <= allowed:
            errs.append(f"DL01: {{{name}}} does not take {sorted(t.value for t in types - allowed)}")
    site_list = entry.get("site_list")
    expanded = query
    if "sites" in names:
        sites = (site_lists or {}).get(site_list) if isinstance(site_list, str) else None
        site_values = sites.get("sites") if isinstance(sites, Mapping) else None
        if not isinstance(site_values, list) or not site_values or not all(
                isinstance(s, str) and _RE_SITE.match(s) for s in site_values):
            errs.append(f"DL01: {{sites}} needs a valid site_list (got {site_list!r})")
        else:
            expanded = query.replace("{sites}", sites_clause(site_values))
    elif site_list is not None:
        errs.append("DL01: site_list without a {sites} placeholder")
    if count_words(_RE_PH.sub("X", expanded)) > MAX_DORK_WORDS:
        errs.append(f"DL02: more than {MAX_DORK_WORDS} words")
    if site_operators(expanded) >= MAX_SITE_OPERATORS:
        errs.append(f"DL03: {MAX_SITE_OPERATORS} or more site: operators")
    if T.CPF in types or "cpf" in names or contains_cpf(expanded):
        errs.append("DL04: a template never contains a CPF (rule 4)")
    person = bool(types & PERSON_TYPES)
    if person and FORBIDDEN_PERSON_TERMS.search(_RE_PH.sub(" ", expanded)):
        errs.append("DL05: a person identifier is never combined with document, password or leak terms (cond 5)")
    if any(p in expanded.lower() for p in PASTE_SITES) and not types <= BRAND_TYPES:
        errs.append("DL06: paste-site dorks are for domains and brands only (cond 5)")
    if person and entry["privacy"] is not True:
        errs.append("DL07: person, phone, e-mail, username and PIX dorks are privacy=true (cond 6)")
    if "linkedin.com" in expanded.lower() and (entry["scope"] != "own_org_only" or entry["privacy"] is not True):
        errs.append("DL08: LinkedIn X-ray only for the own organisation, privacy=true (cond 6, A11)")
    if entry["scope"] == "own_org_only" and "own_company" not in names:
        errs.append("DL08: own_org_only rows use {own_company}")
    engines = entry["engines"]
    if not isinstance(engines, list) or not engines or not set(engines) <= set(ENGINES):
        errs.append("DL09: engines must be among google, bing, duckduckgo (cond 7)")
    elif _BING_ONLY.search(query) and set(engines) != {"bing"}:
        errs.append("DL09: ip:/url: operators are Bing-only")
    if entry["family"] == "exposure" and (not types <= BRAND_TYPES or entry["scope"] != "typed_or_own"):
        errs.append("DL11: exposure dorks only for analyst-typed entities, names under a typed apex and org assets (cond 3)")
    return errs


def lint_pack(data: Any) -> list[str]:
    """Every problem of a dork pack ('<id>: DLnn ...'); empty = clean (CI and the loader use it)."""
    if not isinstance(data, Mapping) or data.get("schema") != SCHEMA:
        return [f"pack: schema must be {SCHEMA!r}"]
    errs: list[str] = []
    engines = data.get("engines")
    if not isinstance(engines, Mapping) or any(
            (engines.get(k) or {}).get("host") != h or (engines.get(k) or {}).get("base") != b for k, (h, b) in ENGINES.items()):
        errs.append("pack: engines must be exactly the three manual search engines of cond 7")
    site_lists = data.get("site_lists") if isinstance(data.get("site_lists"), Mapping) else {}
    seen: set[str] = set()
    for row in data.get("dorks") or []:
        ident = str(row.get("id")) if isinstance(row, Mapping) else "?"
        if ident in seen:
            errs.append(f"{ident}: duplicate id")
        seen.add(ident)
        errs += [f"{ident}: {e}" for e in lint_dork(row, site_lists)]
    return errs


_LOCK = threading.Lock()
_CACHE: dict[str, Any] = {}


def load_pack(path: Path | None = None) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    """(pack data, valid rows, problems). Rows with problems are dropped (fail closed)."""
    key = str(path or PACK_PATH)
    with _LOCK:
        if key in _CACHE:
            return _CACHE[key]
        try:
            data = json.loads(Path(key).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            state: tuple[dict[str, Any], list[dict[str, Any]], list[str]] = ({}, [], [f"pack unreadable ({type(exc).__name__})"])
        else:
            if not isinstance(data, dict) or data.get("schema") != SCHEMA:
                state = ({}, [], [f"pack: schema must be {SCHEMA!r}"])
            else:
                site_lists = data.get("site_lists") if isinstance(data.get("site_lists"), Mapping) else {}
                rows = [dict(r) for r in data.get("dorks") or [] if isinstance(r, Mapping) and not lint_dork(r, site_lists)]
                state = (data, rows, lint_pack(data))
        _CACHE[key] = state
        return state


def reset_cache() -> None:
    with _LOCK:
        _CACHE.clear()


# --------------------------------------------------------------------------------------
# Building links (pure: strings only, zero HTTP, cond 1)
# --------------------------------------------------------------------------------------


def render_query(row: Mapping[str, Any], values: Mapping[str, str], site_lists: Mapping[str, Any]) -> str | None:
    """The row's query with its placeholders substituted (re.sub whitelist; a missing value renders nothing)."""
    query = str(row.get("query") or "")

    def repl(m: re.Match[str]) -> str:
        name = m.group(1)
        if name == "sites":
            sites = (site_lists.get(str(row.get("site_list"))) or {}).get("sites") or []
            if not sites:
                raise ValueError(name)
            return sites_clause([str(s) for s in sites])
        value = values.get(name)
        if name not in PLACEHOLDER_TYPES or not value:
            raise ValueError(name)
        return value

    try:
        out = _RE_PH.sub(repl, query)
    except ValueError:
        return None
    out = re.sub(r"\s+", " ", out).strip()
    if count_words(out) > MAX_DORK_WORDS or site_operators(out) >= MAX_SITE_OPERATORS or _RE_CTRL.search(out):
        return None
    return out


def dork_url(engine: str, query: str) -> str | None:
    """Search URL of one engine (links only: never fetched by V3LUM)."""
    if engine not in ENGINES or not query:
        return None
    return ENGINES[engine][1] + quote_plus(query)


def row_allowed(row: Mapping[str, Any], *, typed: bool, opted_in: bool, own_asset: bool, under_typed_apex: bool,
                own_org: bool) -> tuple[bool, str]:
    """cond 3/6 gates for one row: (allowed, reason when not)."""
    scope = row.get("scope")
    if row.get("privacy") and not (typed and opted_in):
        return False, "privacy: analyst-typed seeds of a case that opted in only (cond 6)"
    if scope == "own_org_only" and not (typed and own_org):
        return False, "own organisation only (cond 6, A11)"
    if scope == "seed_only" and not typed:
        return False, "analyst-typed seeds only"
    if scope == "typed_or_own" and not (typed or own_asset or under_typed_apex):
        return False, "exposure dorks only for typed entities, names under a typed apex and org assets (cond 3)"
    return True, ""


def build_rows(entity: Entity, *, typed: bool, opted_in: bool = False, own_asset: bool = False,
               under_typed_apex: bool = False, own_org: bool = False, own_company: str = "",
               pack: tuple[dict[str, Any], list[dict[str, Any]], list[str]] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Rows ``{id, family, group, label, query, privacy, curated, links: [{engine, host, url}]}`` for one entity and
    the rows left out with their reason. Pure: builds strings only (cond 1)."""
    data, rows, _errs = pack or load_pack()
    site_lists = data.get("site_lists") if isinstance(data.get("site_lists"), Mapping) else {}
    values = dork_values(entity, own_company=own_company if own_org else "")
    out: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    if values is None:
        return out, skipped
    for row in rows:
        if entity.type.value not in row.get("entity_types", []):
            continue
        ok, reason = row_allowed(row, typed=typed, opted_in=opted_in, own_asset=own_asset,
                                 under_typed_apex=under_typed_apex, own_org=own_org)
        if not ok:
            skipped.append({"id": str(row["id"]), "reason": reason})
            continue
        query = render_query(row, values, site_lists)
        if query is None:
            continue
        if row.get("privacy") and FORBIDDEN_PERSON_TERMS.search(_RE_PH.sub(" ", str(row.get("query")))):
            continue  # defence in depth: the lint already refuses such rows
        links = [{"engine": e, "host": ENGINES[e][0], "url": dork_url(e, query)} for e in row["engines"]]
        out.append({"id": row["id"], "family": row["family"], "group": row["group"], "label": row["label"],
                    "query": query, "privacy": row["privacy"], "curated": row["curated"], "links": links})
    return out, skipped


def cap_rows(rows: list[dict[str, Any]], *, terminal: int = TERMINAL_DORK_CAP, report: int = REPORT_LINK_CAP) -> dict[str, Any]:
    """cond 8: curated rows first; the terminal view keeps ``terminal`` curated rows, reports ``report`` links (one per
    row), the rest goes to ``v3lum links --all``."""
    ordered = [r for r in rows if r.get("curated")] + [r for r in rows if not r.get("curated")]
    shown = ordered[:report]
    groups: dict[str, list[str]] = {}
    for r in shown:
        groups.setdefault(str(r.get("group") or r.get("family")), []).append(str(r["id"]))
    return {"report": shown, "terminal": [r["id"] for r in ordered if r.get("curated")][:terminal], "groups": groups,
            "overflow": [r["id"] for r in ordered[report:]], "overflow_hint": "v3lum links --all" if len(ordered) > report else ""}


# --------------------------------------------------------------------------------------
# Pasted-URL router (cond 9): port of Ceos busca_web.destino() / variacoes.analisar_url()
# --------------------------------------------------------------------------------------

_POST_X = re.compile(r"^https?://(?:www\.|mobile\.)?(?:x|twitter)\.com/(\w{1,15})/status(?:es)?/(\d{1,25})(?:[/?#]|$)", re.I)
_X_ROUTES = frozenset({"search", "hashtag", "i", "home", "explore", "intent", "share", "login", "settings",
                       "notifications", "messages", "tos", "privacy"})
_LEAK_SITES = frozenset({"pastebin.com", "ghostbin.com", "ghostbin.co", "rentry.co", "rentry.org", "paste.ee",
                         "controlc.com", "justpaste.it", "pastelink.net", "hastebin.com", "dpaste.org", "dpaste.com"})
_PROFILE_HOSTS = {"lattes.cnpq.br": "lattes", "orcid.org": "orcid", "behance.net": "behance"}


def route_pasted_url(url: Any) -> dict[str, Any]:
    """Which entity and route a URL the analyst found manually belongs to (``v3lum add-url <url>``, cond 9).

    kind: ``post_x`` (an X/Twitter post, attached to the author's ``social_account``), ``exposure`` (paste and leak
    sites: manual triage only, never fetched - rule 3), ``profile`` (a social profile as ``social_account
    <platform>:<handle>``, a ``telegram_handle``/``telegram_invite``, or a ``url`` for Lattes/ORCID/Behance),
    ``company_page`` (LinkedIn company pages; Ceos treated them as people), ``other`` or ``invalid``. Pure: the URL is
    never requested."""
    raw = str(url or "").strip()
    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower()
    except ValueError:
        parts, host = None, ""
    if parts is None or parts.scheme.lower() not in ("http", "https") or not host or _RE_CTRL.search(raw) or " " in raw:
        return {"kind": "invalid", "entity_type": None, "value": None, "route": None, "privacy": False,
                "label": "invalid link (http/https only)"}
    bare = host[4:] if host.startswith("www.") else host
    m = _POST_X.match(raw)
    if m and m.group(1).lower() not in _X_ROUTES:
        author = m.group(1).lower()
        return {"kind": "post_x", "entity_type": "url", "value": raw, "attach_to": ("social_account", f"x:{author}"),
                "platform": "x", "handle": author, "post_id": m.group(2), "route": "social_post", "privacy": True,
                "label": f"Social - X - post by @{author}"}
    if bare in _LEAK_SITES:
        return {"kind": "exposure", "entity_type": "url", "value": raw, "route": "exposure_triage", "privacy": True,
                "label": "Exposure - possible leak (manual triage; never fetched)"}
    segments = [unquote(s) for s in parts.path.split("/") if s]
    if bare in ("t.me", "telegram.me") and segments:
        first = segments[0]
        if first.startswith("+") or first.lower() == "joinchat":
            return {"kind": "profile", "entity_type": "telegram_invite", "value": raw, "platform": "telegram",
                    "handle": None, "route": "social_profile", "privacy": True, "label": "Social - Telegram invite"}
        handle = first.lower()
        if re.fullmatch(r"[a-z][a-z0-9_]{4,31}", handle):
            return {"kind": "profile", "entity_type": "telegram_handle", "value": handle, "platform": "telegram",
                    "handle": handle, "route": "social_profile", "privacy": True, "label": "Social - Telegram - profile"}
    if bare.endswith("linkedin.com") and len(segments) > 1 and segments[0].lower() in ("company", "school", "showcase"):
        return {"kind": "company_page", "entity_type": "url", "value": raw, "platform": "linkedin",
                "handle": segments[1].lower(), "route": "company_presence", "privacy": False,
                "label": "Company - LinkedIn page"}
    for suffix, platform in _PROFILE_HOSTS.items():
        if (bare == suffix or bare.endswith("." + suffix)) and segments:
            return {"kind": "profile", "entity_type": "url", "value": raw, "platform": platform, "handle": None,
                    "id": segments[0], "route": "social_profile", "privacy": True, "label": f"Profile - {platform}"}
    found = platform_for_url(raw)
    if found:
        platform, handle = found
        if not (platform == "x" and handle.lower() in _X_ROUTES):
            account = Entity.try_make(T.SOCIAL_ACCOUNT, f"{platform}:{handle}")
            if account is not None:
                return {"kind": "profile", "entity_type": "social_account", "value": account.value, "platform": platform,
                        "handle": account.value.split(":", 1)[1], "route": "social_profile", "privacy": True,
                        "label": f"Social - {platform} - profile"}
    return {"kind": "other", "entity_type": "url", "value": raw, "route": "triage", "privacy": False,
            "label": "Triage - other"}


# --------------------------------------------------------------------------------------
# Module
# --------------------------------------------------------------------------------------


def _fold(text: str) -> str:
    norm = unicodedata.normalize("NFKD", text or "")
    return re.sub(r"\s+", " ", "".join(c for c in norm if not unicodedata.combining(c))).strip().lower()


def _company_core(text: str) -> str:
    """'ACME S.A.' / 'Acme Ltda' -> 'acme' (accent-folded, legal suffixes dropped) for own-organisation matching."""
    folded = re.sub(r"[^a-z0-9 ]+", " ", _fold(text))
    words = [w for w in folded.split() if w not in ("sa", "s", "a", "ltda", "me", "epp", "eireli", "inc", "llc", "ltd")]
    return " ".join(words)


def _tlp_level(ctx: Any) -> _tlp.TLP:
    try:
        return _tlp.parse(getattr(ctx, "tlp", "") or "amber")
    except ValueError:
        return _tlp.TLP.RED


@register
class DorkGenerator(Module):
    name = "dork_generator"
    title = "Search-engine dork links (Google, Bing, DuckDuckGo)"
    description = (
        "Pre-filled search-engine dork links (exposed documents/configs/panels, BR site categories, BR fraud families, "
        "Bing ip:/url:, privacy-gated person/phone/e-mail/username dorks, own-organisation LinkedIn X-ray) and Brazilian "
        "phone variants. Links only: V3LUM never queries a search engine."
    )
    category = "search_dorks"
    accepts = {T.DOMAIN, T.ORG, T.KEYWORD, T.USERNAME, T.TELEGRAM_HANDLE, T.EMAIL, T.PHONE, T.PERSON, T.IPV4, T.URL,
               T.CNPJ, T.PIX}
    produces = frozenset()
    reference = "https://www.google.com/advanced_search"
    tags = {"offline", "brazil"}
    notice = (
        "Links only: the analyst opens them; V3LUM never queries, scrapes or renders a search engine. Person, phone, "
        "e-mail, username and PIX dorks need an analyst-typed seed in a case that opted in; LinkedIn X-ray only for the "
        "own organisation. No dork ever carries a CPF or combines a person with document, password or leak terms."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # the module only builds URLs
    hosts = ()
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.05
    timeout = 10.0
    default_enabled = True
    settings = {
        "dork_generator_engine": SettingSpec(
            "google", "search engine of the report links (every engine's URL stays in the evidence)",
            choices=("google", "bing", "duckduckgo")),
    }

    def _context(self, entity: Entity, ctx: Any) -> dict[str, Any]:
        opts = getattr(ctx, "options", None)
        unconfirmed = set(getattr(opts, "unconfirmed_seeds", ()) or ())
        typed = bool(getattr(ctx, "is_seed", False)) and entity.key not in unconfirmed
        opted_in = bool(getattr(opts, "show_personal", False) and getattr(opts, "purpose", ""))
        org = getattr(ctx, "org", None)
        own_asset = False
        own_company = ""
        own_org = False
        try:
            own_asset = bool(org is not None and org.owns(entity).own)
        except Exception:  # noqa: BLE001 - an unusable profile never grants anything
            own_asset = False
        org_name = str(getattr(org, "name", "") or "") if org is not None else ""
        if org_name and _company_core(org_name):
            own_company = org_name
            if entity.type is T.PERSON:
                own_org = True
            elif entity.type is T.ORG:
                brands = []
                try:
                    brands = [str(b) for b in org.brand_terms()]
                except Exception:  # noqa: BLE001
                    brands = []
                core = _company_core(entity.value)
                own_org = bool(core) and (core == _company_core(org_name) or core in {_company_core(b) for b in brands})
        under_apex = False
        prov = tuple(getattr(ctx, "provenance", ()) or ())
        if entity.type is T.DOMAIN and prov:
            root = str(prov[0][0]) if prov[0] else ""
            if root.startswith("domain:"):
                apex = root.split(":", 1)[1]
                under_apex = entity.value.endswith("." + apex)
        return {"typed": typed, "opted_in": opted_in, "own_asset": own_asset, "under_typed_apex": under_apex,
                "own_org": own_org, "own_company": own_company}

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        level = _tlp_level(ctx)
        if level >= _tlp.TLP.RED:
            return res.mark(Status.SKIPPED, "TLP:RED: third-party links are hidden from reports", reason_code="tlp")
        pack = load_pack()
        if not pack[1]:
            return res.mark(Status.UNAVAILABLE, "dork pack unavailable: " + "; ".join(pack[2][:3]), reason_code="dataset")
        gates = self._context(entity, ctx)
        rows, skipped = build_rows(entity, pack=pack, **gates)
        if entity.type is T.PHONE and gates["typed"]:
            variants = br_phone_variants(entity.value)
            if variants:
                res.attr("br_phone_variants", variants["variants"])
        capped = cap_rows(rows)
        engine = str(ctx.setting("dork_generator_engine", "google") or "google")
        shown: list[dict[str, Any]] = []
        for row in capped["report"]:
            link = next((x for x in row["links"] if x["engine"] == engine), row["links"][0])
            label = f"Dork [{row['group']}] {row['label']} ({link['engine']})"
            if level >= _tlp.TLP.AMBER:
                label += f" - opening sends the query {row['query']} to {link['host']}"
            res.link(label, link["url"])
            shown.append({"id": row["id"], "engine": link["engine"], "host": link["host"], "url": link["url"]})
        res.raw = {"tlp": level.value_str, "gates": {k: v for k, v in gates.items() if k != "own_company"},
                   "rows": rows, "shown": shown, "terminal": capped["terminal"], "groups": capped["groups"],
                   "overflow": capped["overflow"], "overflow_hint": capped["overflow_hint"], "skipped": skipped}
        if not shown:
            reason = "no dork applies" + (f" ({skipped[0]['reason']})" if skipped else "")
            return res.mark(Status.EMPTY, reason)
        return res
