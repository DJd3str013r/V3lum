"""CNJ unified process number parser and DataJud router (batch p2-G10-2, P241 cond 3-4; shared helper).

Offline, standard library only, own implementation of a public specification (CNJ Resolucao 65/2008):

* ``NNNNNNN-DD.AAAA.J.TR.OOOO`` - sequence, check digits, filing year, justice segment J, tribunal TR and
  origin unit; valid iff ``int(N + AAAA + J + TR + OOOO + DD) % 97 == 1`` (``DD = 98 - (N AAAA J TR OOOO * 100
  mod 97)``).
* Routing to the 91 public DataJud indices (``api_publica_<alias>``): J=8 TR in the CNJ order of the states
  (by state name: 01 AC ... 03 AP, 04 AM ... 07 DF -> tjdft ... 25 SE, 26 SP, 27 TO); J=4 -> trf1..trf6;
  J=5 -> trt1..trt24 (TR 00 = tst); J=6 -> tre-xx / tre-dft (TR 00 = tse); J=3 TR 00 -> stj; J=7 -> stm;
  J=9 -> tjmmg / tjmrs / tjmsp. STF (J=1), CNJ (J=2), CJF (4.90) and CSJT (5.90) have no public index:
  such numbers are valid but never queried ('no public DataJud index for ...').

Every other batch that finds CNJ numbers in text (DOU, Querido Diario, DJEN) uses :func:`extract_cnj_numbers`
(at most 5 per text) and :func:`cnj_pivot_args` so DataJud never runs on them automatically (expand=False).
Until the core ``cnj_process`` entity type (P333) exists, numbers are pivoted as KEYWORD entities in the
formatted form (see docs/backlog/p2-G10-2.md); the parser belongs in core validators (core request).
"""

from __future__ import annotations

import re
from typing import Any

__all__ = [
    "CNJ_FORMATTED_RE",
    "CNJ_PIVOT_NOTE",
    "CNJ_SEGMENTS",
    "CNJ_UF_ORDER",
    "DATAJUD_ALIASES",
    "MAX_PER_TEXT",
    "cnj_dv",
    "cnj_format",
    "cnj_parse",
    "cnj_pivot_args",
    "extract_cnj_numbers",
    "looks_like_cnj",
]

#: P241 cond 4: at most 5 process numbers per text input (the rest are counted, never queried).
MAX_PER_TEXT = 5
CNJ_SEGMENTS = {
    "1": "STF", "2": "CNJ", "3": "STJ", "4": "Justica Federal", "5": "Justica do Trabalho", "6": "Justica Eleitoral",
    "7": "Justica Militar da Uniao", "8": "Justica Estadual", "9": "Justica Militar Estadual",
}
#: TR order of J=8 and J=6 (Res. 65/2008 annex): states by name, so AP (03) precedes AM (04), SE (25) SP (26).
CNJ_UF_ORDER = ("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", "MT", "MS", "MG", "PA", "PB", "PR",
                "PE", "PI", "RJ", "RN", "RS", "RO", "RR", "SC", "SE", "SP", "TO")
CNJ_FORMATTED_RE = re.compile(r"(?<![0-9])(\d{7})-(\d{2})\.(\d{4})\.(\d)\.(\d{2})\.(\d{4})(?![0-9])")
_DIGITS20_RE = re.compile(r"(?<![0-9.\-/])(\d{20})(?![0-9])")
CNJ_PIVOT_NOTE = "CNJ process number found in text: run datajud on it explicitly (never automatic, P241 cond 4)"


def _digits(value: Any) -> str:
    return re.sub(r"\D", "", value if isinstance(value, str) else str(value or ""))


def _route(segment: str, tribunal: str) -> tuple[str | None, str | None]:
    """(alias, court) for J and TR; alias None when DataJud has no index for that court."""
    t = int(tribunal)
    if segment == "3":
        return ("stj", "STJ") if t == 0 else (None, None)
    if segment == "4":
        return (f"trf{t}", f"TRF{t}") if 1 <= t <= 6 else (None, "CJF" if t == 90 else None)
    if segment == "5":
        if t == 0:
            return "tst", "TST"
        return (f"trt{t}", f"TRT{t}") if 1 <= t <= 24 else (None, "CSJT" if t == 90 else None)
    if segment == "6":
        if t == 0:
            return "tse", "TSE"
        if 1 <= t <= 27:
            uf = CNJ_UF_ORDER[t - 1]
            return ("tre-dft" if uf == "DF" else f"tre-{uf.lower()}"), f"TRE-{uf}"
        return None, None
    if segment == "7":
        # TR 00 = STM; TR 01-12 = first-instance military circumscriptions, assumed to sit in the STM index.
        return ("stm", "STM" if t == 0 else f"JMU {t}a CJM") if 0 <= t <= 12 else (None, None)
    if segment == "8":
        if 1 <= t <= 27:
            uf = CNJ_UF_ORDER[t - 1]
            return ("tjdft", "TJDFT") if uf == "DF" else (f"tj{uf.lower()}", f"TJ{uf}")
        return None, None
    if segment == "9":
        return {13: ("tjmmg", "TJMMG"), 21: ("tjmrs", "TJMRS"), 26: ("tjmsp", "TJMSP")}.get(t, (None, None))
    if segment in ("1", "2"):
        return None, CNJ_SEGMENTS[segment]
    return None, None


def _all_aliases() -> frozenset[str]:
    out = set()
    for seg in "123456789":
        for t in range(100):
            alias = _route(seg, f"{t:02d}")[0]
            if alias:
                out.add(alias)
    return frozenset(out)


#: the 91 public DataJud indices (checked against the wiki endpoints page, research 2026-11-25)
DATAJUD_ALIASES = _all_aliases()


def cnj_dv(sequence: str, year: str, segment: str, tribunal: str, origin: str) -> int:
    """Check digits DD = 98 - (int(N AAAA J TR OOOO) * 100 mod 97)."""
    return 98 - (int(f"{sequence}{year}{segment}{tribunal}{origin}") * 100) % 97


def cnj_format(digits: Any) -> str | None:
    """'07000551020188010022' -> '0700055-10.2018.8.01.0022' (None unless 20 digits)."""
    d = _digits(digits)
    return f"{d[:7]}-{d[7:9]}.{d[9:13]}.{d[13]}.{d[14:16]}.{d[16:]}" if len(d) == 20 else None


def cnj_parse(value: Any) -> dict[str, Any]:
    """P241 cond 3: a CNJ unified number -> parts, validity and DataJud routing.

    ``valid``: mod-97 check digits match and the year/segment are plausible. ``index`` is
    'api_publica_<alias>' or None when DataJud has no index for that court (``reason`` says why).
    """
    d = _digits(value)
    if len(d) != 20:
        return {"valid": False, "check_ok": False, "digits": d, "formatted": None, "reason": "not a 20-digit CNJ number",
                "index": None, "alias": None, "court": None}
    n, dd, ano, seg, tr, orig = d[:7], d[7:9], d[9:13], d[13], d[14:16], d[16:]
    check_ok = int(n + ano + seg + tr + orig + dd) % 97 == 1
    alias, court = _route(seg, tr)
    valid = check_ok and seg != "0" and 1900 <= int(ano) <= 2100
    if not check_ok:
        reason: str | None = "check digits do not match"
    elif not valid:
        reason = "implausible year or segment"
    elif alias is None:
        reason = f"no public DataJud index for {court or 'J=' + seg + ' TR=' + tr}"
    else:
        reason = None
    return {
        "valid": valid, "check_ok": check_ok, "digits": d, "formatted": cnj_format(d), "sequence": n, "dv": dd,
        "year": int(ano), "segment": seg, "segment_name": CNJ_SEGMENTS.get(seg), "tribunal_code": tr, "origin": orig,
        "court": court, "alias": alias, "index": f"api_publica_{alias}" if alias and valid else None, "reason": reason,
    }


def looks_like_cnj(value: Any) -> bool:
    """True when ``value`` is one valid CNJ number (formatted or 20 bare digits) and nothing else."""
    text = str(value or "").strip()
    if not (CNJ_FORMATTED_RE.fullmatch(text) or re.fullmatch(r"\d{20}", text)):
        return False
    return bool(cnj_parse(text)["valid"])


def extract_cnj_numbers(text: Any, limit: int = MAX_PER_TEXT) -> dict[str, Any]:
    """P241 cond 4 / P242 cond 8: valid CNJ numbers of a text, in order, deduplicated, at most ``limit``.

    Accepts the formatted form and bare 20-digit runs (mod-97 filtered). Returns ``numbers`` (cnj_parse
    dicts), ``invalid`` (candidates failing the check digits) and ``over_limit`` (valid numbers beyond the
    limit: listed as a count, never queried).
    """
    text = text if isinstance(text, str) else ""
    cands = sorted([*CNJ_FORMATTED_RE.finditer(text), *_DIGITS20_RE.finditer(text)], key=lambda m: m.start())
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    invalid = over = 0
    for m in cands:
        digits = _digits(m.group(0))
        if digits in seen:
            continue
        parsed = cnj_parse(digits)
        if not parsed["valid"]:
            invalid += 1
            continue
        seen.add(digits)
        if len(found) >= limit:
            over += 1
            continue
        found.append(parsed)
    return {"numbers": found, "invalid": invalid, "over_limit": over}


def cnj_pivot_args(parsed: dict[str, Any]) -> dict[str, Any]:
    """Keyword arguments of ``res.pivot`` for a CNJ number found while pivoting (P241 cond 4): never expanded.

    ``res.pivot(T.KEYWORD, **cnj_pivot_args(p))`` until the core cnj_process type exists.
    """
    return {"value": parsed["formatted"], "relation": "mentions", "confidence": "probable", "expand": False,
            "note": CNJ_PIVOT_NOTE}
