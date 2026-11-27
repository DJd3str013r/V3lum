"""Small text helpers shared by the company-registry modules of batch p3-G10-1.

Pure stdlib, no I/O. Used by ``icij_offshore`` (P221), ``opensanctions`` (P222), ``sec_edgar`` (P223),
``wikidata`` (P224), ``eu_vies`` (P225) and ``uk_companies_house`` (P227):

* defensive coercion of untrusted JSON values (:func:`text`, :func:`as_dict`, :func:`as_list`,
  :func:`as_int`, :func:`as_float`);
* :func:`fold` (accents and case folded) and :func:`norm_company_name` - the *exact* comparison form of a
  company name: legal-form punctuation unified (``S.A.``/``S/A`` -> ``sa``, ``S.A R.L.`` -> ``sarl``,
  ``CO., LTD.`` -> ``co ltd``) but legal forms kept, so 'exact' never silently becomes 'similar';
* :func:`name_core` - the name without trailing legal forms, 'holding(s)' and 'group' (POSSIBLE
  comparisons only);
* :func:`iso_date` - ICIJ ``23-MAR-2006``, ISO, ``23/03/2006`` and ``Mar 23, 2006`` forms to ISO dates.

The fuzzy matcher itself is the shared P219 matcher (``company_org.namematch``).
"""

from __future__ import annotations

import re
import unicodedata
from datetime import date
from typing import Any

__all__ = ["as_dict", "as_float", "as_int", "as_list", "fold", "iso_date", "name_core", "norm_company_name", "text"]


def text(value: Any) -> str:
    """A stripped string for any scalar (None -> '', bools lower-case); containers -> ''."""
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return ""
    if isinstance(value, bool):
        return str(value).lower()
    return str(value).strip()


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def as_float(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if out == out and out not in (float("inf"), float("-inf")) else None


def fold(value: Any) -> str:
    """Accent-stripped, case-folded text."""
    return "".join(c for c in unicodedata.normalize("NFKD", text(value)) if not unicodedata.combining(c)).casefold()


_LEGAL_PUNCT = (
    (re.compile(r"\bs\s*\.?\s*a\s*\.?\s*r\s*\.?\s*l\b\.?"), "sarl"),
    (re.compile(r"\bs\s*\.\s*a\s*\.?\s*s\s*\.?\s*u\b\.?"), "sasu"),
    (re.compile(r"\bs\s*\.\s*a\s*\.?\s*s\b\.?"), "sas"),
    (re.compile(r"\bs\s*\.\s*p\s*\.?\s*a\b\.?"), "spa"),
    (re.compile(r"\bs\s*\.\s*r\s*\.?\s*l\b\.?"), "srl"),
    (re.compile(r"\bs\s*/\s*a\b"), "sa"),
    (re.compile(r"\bs\s*\.\s*a\b\.?"), "sa"),
    (re.compile(r"\bco\s*\.\s*,?\s*ltd\b\.?"), "co ltd"),
    (re.compile(r"\bltda\b\.?"), "ltda"),
    (re.compile(r"\bb\s*\.\s*v\b\.?"), "bv"),
    (re.compile(r"\bn\s*\.\s*v\b\.?"), "nv"),
    (re.compile(r"\ba\s*/\s*s\b"), "as"),
    (re.compile(r"\ba\s*\.\s*s\b\.?"), "as"),
)
_NON_WORD = re.compile(r"[^\w\s]|_")
_SPACES = re.compile(r"\s+")


def norm_company_name(name: Any) -> str:
    """Exact-comparison form of a company name (legal forms kept, punctuation unified)."""
    s = fold(name)
    for rx, rep in _LEGAL_PUNCT:
        s = rx.sub(rep, s)
    s = s.replace("&", " and ")
    s = _NON_WORD.sub(" ", s)
    return _SPACES.sub(" ", s).strip()


_CORE_SUFFIX_TEXT = (
    "inc incorporated corp corporation co company cia ltd limited llc plc lp llp sa sarl sas sasu spa srl "
    "ag gmbh kg bv nv oy oyj ab as asa aps se ltda eireli me epp holding holdings group the"
)
_CORE_SUFFIXES = frozenset(_CORE_SUFFIX_TEXT.split())


def name_core(name: Any) -> str:
    """Company name without trailing legal forms / 'holding(s)' / 'group' (POSSIBLE comparisons only)."""
    toks = norm_company_name(name).split()
    while len(toks) > 1 and toks[-1] in _CORE_SUFFIXES:
        toks.pop()
    while len(toks) > 1 and toks[0] == "the":
        toks.pop(0)
    return " ".join(toks)


_MONTHS = {m: i for i, m in enumerate(("JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"), start=1)}
_ISO = re.compile(r"^[+]?(\d{4})-(\d{2})-(\d{2})")
_DMONY = re.compile(r"^(\d{1,2})-([A-Za-z]{3})-(\d{4})$")
_DMY = re.compile(r"^(\d{1,2})[/.](\d{1,2})[/.](\d{4})$")
_MDY = re.compile(r"^([A-Za-z]{3})[a-z]*\.? (\d{1,2}),? (\d{4})$")


def iso_date(value: Any) -> str | None:
    """'23-MAR-2006' | '2006-03-23[T...]' | '23/03/2006' | '23.03.2006' | 'Mar 23, 2006' -> '2006-03-23' or None."""
    s = text(value)
    if not s:
        return None
    y = mo = d = None
    m = _ISO.match(s)
    if m:
        y, mo, d = (int(x) for x in m.groups())
    elif (m := _DMONY.match(s)) is not None:
        d, y, mo = int(m.group(1)), int(m.group(3)), _MONTHS.get(m.group(2).upper())
    elif (m := _DMY.match(s)) is not None:
        d, mo, y = (int(x) for x in m.groups())
    elif (m := _MDY.match(s)) is not None:
        mo, d, y = _MONTHS.get(m.group(1).upper()), int(m.group(2)), int(m.group(3))
    if not (y and mo and d):
        return None
    try:
        return date(y, mo, d).isoformat()
    except ValueError:
        return None
