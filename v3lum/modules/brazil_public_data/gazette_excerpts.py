"""Shared helpers for official-gazette and court-communication excerpts (batch p2-G10-3).

No Module class lives in this file. ``querido_diario`` (P243) and the offline helpers of
``djen_court_communications`` (P362) use it; ``dou_search`` (P242) follows the same presentation rules
(count plus the five most relevant excerpts, penalty terms first, excerpts of at most 300 characters).

* **Minimisation** (P243 FC4, P362 FC5, rule 4): :func:`clean_excerpt` collapses whitespace, masks every
  CPF-shaped value (formatted CPFs and bare 11-digit runs with valid check digits) and cuts the text to
  at most :data:`EXCERPT_MAX` characters (ellipses included), centred on the queried CNPJ or name.
  Person names inside an excerpt are never extracted as entities.
* **Penalty terms** (P243 FC3): :func:`penalty_terms` finds penalidade, inidoneidade, rescisao, multa,
  sancao and suspensao as whole words, accent-insensitive; 'multa(s) de transito' (a fine-collection
  service contract, seen live in a bank's municipal contract) does not count.
* **Derived identifiers** (P243 FC5, P362 FC6): :func:`extract_cnpjs` keeps only CNPJs whose check
  digits are valid (numeric and the alphanumeric form of IN RFB 2.229/2024); cut-off or malformed values
  are ignored. :func:`extract_cnj` uses the shared CNJ parser of batch p2-G10-2
  (``cnj_process.extract_cnj_numbers``, mod-97 check and DataJud routing) and falls back to
  ``br_parsers.cnj_parse`` when that helper is not installed.
"""

from __future__ import annotations

import datetime as _dt
import re
import unicodedata
from typing import Any
from urllib.parse import urlsplit

from v3lum.core import validators
from v3lum.modules.brazil_public_data import br_parsers

try:  # shared CNJ parser and DataJud router (batch p2-G10-2, P241 cond 3-4)
    from v3lum.modules.brazil_public_data import cnj_process as _cnj
except ImportError:  # pragma: no cover - the helper of another batch is not installed
    _cnj = None

__all__ = [
    "CNJ_PIVOT_NOTE",
    "EXCERPT_MAX",
    "PENALTY_TERMS",
    "clean_excerpt",
    "cnj_pivot_args",
    "collapse_ws",
    "extract_cnj",
    "extract_cnpjs",
    "fold",
    "format_cnpj",
    "http_url",
    "iso_date",
    "mask_cpfs",
    "normalize_cnpj",
    "penalty_terms",
    "text",
    "years_back",
]

EXCERPT_MAX = 300
PENALTY_TERMS = ("penalidade", "inidoneidade", "rescisao", "multa", "sancao", "suspensao")
CNJ_PIVOT_NOTE = "CNJ process number found in an official text: run datajud on it explicitly (never automatic, P241 cond 4)"

_PENALTY_RE = re.compile(
    r"\b(penalidades?|inidoneidade|inidone[oa]s?|rescis(?:ao|oes)|multas?|sanc(?:ao|oes)|suspens(?:ao|oes))\b")
_PENALTY_CANON = (("penalidade", "penalidade"), ("inidone", "inidoneidade"), ("rescis", "rescisao"),
                  ("multa", "multa"), ("sanc", "sancao"), ("suspens", "suspensao"))
#: routine phrases that carry a penalty word but are no sanction on the company (seen live)
_ROUTINE_RE = re.compile(r"\bmultas? de transito\b")
_CPF_FMT_RE = re.compile(r"(?<![0-9])\d{3}\.\d{3}\.\d{3}-\d{2}(?![0-9])")
_DIGITS11_RE = re.compile(r"(?<![0-9])\d{11}(?![0-9])")
_CNPJ14 = re.compile(r"^[0-9A-Z]{12}[0-9]{2}$")
_CNPJ_FMT_RE = re.compile(r"(?<![0-9A-Za-z./-])([0-9A-Z]{2}\.[0-9A-Z]{3}\.[0-9A-Z]{3}/[0-9A-Z]{4}-[0-9]{2})(?![0-9/-])")
_CNPJ_BARE_RE = re.compile(r"(?<![0-9A-Za-z])([0-9]{14})(?![0-9A-Za-z])")
_WS_RE = re.compile(r"[\s   ]+")


def text(value: Any) -> str:
    """str() of strings and numbers; '' for None, booleans and containers (untrusted JSON)."""
    if isinstance(value, str):
        return value
    if isinstance(value, bool) or value is None:
        return ""
    if isinstance(value, (int, float)):
        return str(value)
    return ""


def _fold_char(c: str) -> str:
    d = "".join(x for x in unicodedata.normalize("NFKD", c) if not unicodedata.combining(x)).lower()
    return d if len(d) == 1 else c.lower()


def fold(value: Any) -> str:
    """Accent-free lower-case text with collapsed whitespace."""
    return _WS_RE.sub(" ", "".join(_fold_char(c) for c in text(value))).strip()


def _fold_aligned(value: str) -> str:
    """Accent-free lower-case text with the same length as the input (index-aligned)."""
    return "".join(_fold_char(c) for c in value)


def collapse_ws(value: Any) -> str:
    """Newlines, tabs and non-breaking spaces become single spaces."""
    return _WS_RE.sub(" ", text(value)).strip()


def iso_date(value: Any) -> str | None:
    """'2026-11-25', '2026-11-25T10:00:00Z' or '25/11/2026' -> '2026-11-25'; anything else None."""
    t = text(value).strip()
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", t)
    if m:
        y, mo, d = (int(x) for x in m.groups())
    else:
        m = re.match(r"^(\d{2})/(\d{2})/(\d{4})", t)
        if not m:
            return None
        d, mo, y = (int(x) for x in m.groups())
    try:
        return _dt.date(y, mo, d).isoformat()
    except ValueError:
        return None


def years_back(today: _dt.date, years: int) -> _dt.date:
    """``today`` minus ``years`` years (29 February becomes 28 February)."""
    try:
        return today.replace(year=today.year - years)
    except ValueError:
        return today.replace(year=today.year - years, day=28)


def http_url(value: Any) -> str | None:
    """Absolute http(s) URL (a link shown to the analyst, never fetched) or None."""
    t = text(value).strip()
    if not t or any(c in t for c in " \t\r\n\"'<>"):
        return None
    try:
        parts = urlsplit(t)
    except ValueError:
        return None
    return t if parts.scheme in ("http", "https") and parts.netloc else None


def normalize_cnpj(value: Any) -> str | None:
    """14-character CNPJ (digits or the alphanumeric form), check digits NOT verified; else None."""
    t = re.sub(r"[\s./-]", "", text(value)).upper()
    return t if _CNPJ14.match(t) else None


def format_cnpj(value: Any) -> str | None:
    """'00000000000191' -> '00.000.000/0001-91' (also the alphanumeric form); None otherwise."""
    n = normalize_cnpj(value)
    return f"{n[:2]}.{n[2:5]}.{n[5:8]}/{n[8:12]}-{n[12:]}" if n else None


def _cnpj_ok(value: str) -> bool:
    return bool(value) and validators.cnpj_valid(value)


def extract_cnpjs(value: Any, exclude: Any = ()) -> list[str]:
    """Valid CNPJs of a free text (formatted, also alphanumeric, or 14 bare digits), normalised to 14
    characters, deduplicated, in order. Cut-off values ('306.294/0001-45'), malformed ones
    ('90.400.888/00001-42') and wrong check digits are ignored (P243 FC5: hypotheses only)."""
    t = text(value)
    skip = {n for n in (normalize_cnpj(x) for x in (exclude or ())) if n}
    hits = sorted([(m.start(), m.group(1)) for m in _CNPJ_FMT_RE.finditer(t)] + [(m.start(), m.group(1)) for m in _CNPJ_BARE_RE.finditer(t)])
    out: list[str] = []
    for _pos, raw in hits:
        n = normalize_cnpj(raw)
        if n and _cnpj_ok(n) and n not in skip and n not in out:
            out.append(n)
    return out


def mask_cpfs(value: Any) -> str:
    """Rule 4 / LGPD minimisation of stored excerpts: formatted CPFs become '***.***.***-**' and bare
    11-digit runs with valid CPF check digits become eleven asterisks; 14-digit CNPJs are untouched."""
    t = _CPF_FMT_RE.sub("***.***.***-**", text(value))
    return _DIGITS11_RE.sub(lambda m: "*" * 11 if validators.cpf_valid(m.group(0)) else m.group(0), t)


def clean_excerpt(value: Any, anchors: Any = (), limit: int = EXCERPT_MAX) -> str:
    """P243 FC4 / P362 FC5: whitespace collapsed, CPFs masked, at most ``limit`` characters (ellipses
    included), centred on the first anchor (queried CNPJ or name) found in the text."""
    t = mask_cpfs(collapse_ws(value))
    if len(t) <= limit:
        return t
    ft = _fold_aligned(t)
    pos, alen = -1, 0
    for anchor in anchors or ():
        fa = fold(anchor).strip('"')
        if fa:
            i = ft.find(fa)
            if i >= 0:
                pos, alen = i, len(fa)
                break
    if pos < 0:
        return t[: limit - 1].rstrip() + "…"
    room = limit - 2  # two ellipses at most
    start = max(0, pos - max(0, (room - alen) // 2))
    end = min(len(t), start + room)
    start = max(0, end - room)
    piece = t[start:end].strip()
    if start > 0:
        piece = "…" + piece
    if end < len(t):
        piece += "…"
    return piece[:limit]


def penalty_terms(value: Any) -> list[str]:
    """P243 FC3: canonical penalty terms of an excerpt, sorted (accent-insensitive whole words;
    'multa(s) de transito' does not count)."""
    t = _ROUTINE_RE.sub(" ", fold(value))
    found: set[str] = set()
    for m in _PENALTY_RE.finditer(t):
        word = m.group(1)
        for prefix, canon in _PENALTY_CANON:
            if word.startswith(prefix):
                found.add(canon)
                break
    return sorted(found)


def _fallback_cnj(value: str) -> dict[str, Any] | None:
    info = br_parsers.cnj_parse(value)
    if not info or not info.get("check_ok"):
        return None
    return {"formatted": info["formatted"], "index": info.get("datajud_alias"), "court": None, "alias": None, "valid": True}


def extract_cnj(value: Any, limit: int = 10) -> list[dict[str, Any]]:
    """Valid CNJ process numbers of a text (formatted or 20 bare digits, mod-97 checked), in order, at
    most ``limit``: [{number, court, index}] (``index`` = DataJud index for the P241 route, or None)."""
    t = text(value)
    if _cnj is not None:
        found = _cnj.extract_cnj_numbers(t, limit=limit).get("numbers") or []
        return [{"number": p.get("formatted"), "court": p.get("court"), "index": p.get("index")} for p in found if p.get("formatted")]
    out: list[dict[str, Any]] = []
    cands = sorted(list(re.finditer(r"(?<![0-9])\d{7}-\d{2}\.\d{4}\.\d\.\d{2}\.\d{4}(?![0-9])", t))
                   + list(re.finditer(r"(?<![0-9.\-/])\d{20}(?![0-9])", t)), key=lambda m: m.start())
    for m in cands:
        p = _fallback_cnj(m.group(0))
        if p and all(o["number"] != p["formatted"] for o in out):
            out.append({"number": p["formatted"], "court": p["court"], "index": p["index"]})
            if len(out) >= limit:
                break
    return out


def cnj_pivot_args(number: str) -> dict[str, Any]:
    """``res.pivot(T.KEYWORD, **cnj_pivot_args(n))`` for a CNJ number found in an official text: never
    expanded, so DataJud (P241, under its licence gate) runs on it only when the analyst asks. A
    KEYWORD stands in until the core ``cnj_process`` entity type (P333) exists."""
    if _cnj is not None:
        args = dict(_cnj.cnj_pivot_args({"formatted": number}))
        args["expand"] = False
        return args
    return {"value": number, "relation": "mentions", "confidence": "probable", "expand": False, "note": CNJ_PIVOT_NOTE}
