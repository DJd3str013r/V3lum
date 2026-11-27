"""Offline Brazilian identifier, boleto and PIX BR Code parsers (batch p1-G10-1: P232, P233).

Shared helper library of the modules ``br_validators`` (P232) and ``boleto_pix`` (P233); it holds no
Module class. Standard library plus the stdlib-only core helpers (``v3lum.core.validators`` for the
CPF/CNPJ check digits and the CRC16, ``v3lum.core.entities.mask_cpf`` - the one masking function of
AR24). No network, no file or socket access: every function takes values and returns data, and parses
defensively (wrong types, HTML instead of CSV/JSON, cut downloads...).

Pending core moves (manifest core_requests): the identifier helpers belong in core/validators.py
(P232 cond 1 "pure-stdlib extension of core/validators.py") and :data:`BR_RULES` with
:func:`extract_br_entities` is the BR rule set of the shared P172 extraction engine (P232 cond 8),
which lands with WP17 (wave 3); until then the modules call it directly.

Personal data (team rule 4, AR24): a CPF is validated offline only and never returned unmasked by
the extractor, the BR Code helpers or the verdict lines; CPFs are never generated, enumerated or
completed from masked forms (a masked ``***.456.789-**`` stays a ``masked_cpf`` marker).
"""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
import re
import unicodedata
from typing import Any

from v3lum.core import validators as _val
from v3lum.core.entities import mask_cpf

__all__ = [
    "BANK_ALIASES",
    "BRCODE_MAX_BYTES",
    "BR_RULES",
    "DDD_UF",
    "FORMAT_ONLY_WORDING",
    "PIX_GUI",
    "bank_name",
    "boleto_bank_mismatch",
    "boleto_verdict_line",
    "brcode_entities",
    "brcode_verdict_line",
    "build_bank_index",
    "cep_info",
    "cnj_parse",
    "cnpj_dv",
    "cnpj_format",
    "cnpj_headquarters",
    "cnpj_info",
    "cnpj_normalize",
    "cpf_region",
    "detect_bank_mentions",
    "due_dates_from_factor",
    "extract_br_entities",
    "find_boleto_lines",
    "find_brcodes",
    "format_brl",
    "mask_cpf",
    "mask_national_id",
    "mask_pix_key",
    "parse_bcb_str_csv",
    "parse_boleto",
    "parse_brasilapi_banks",
    "parse_brasilapi_pix_participants",
    "parse_brcode",
    "parse_emv_tlv",
    "payee_brand_mismatch",
    "pix_key_type",
    "plate_info",
    "type_11_digit_candidate",
    "validate_table",
]

def _words(text: str) -> frozenset[str]:
    """A frozenset of the space-separated words of ``text`` (readable constant tables)."""
    return frozenset(text.split())


def _words_seq(text: str) -> tuple[str, ...]:
    """The space-separated words of ``text`` in order."""
    return tuple(text.split())


# =============================================================================================
# A. text helpers
# =============================================================================================


def to_text(raw: Any) -> str:
    """Decode a body to str: UTF-8 (BOM stripped), falling back to cp1252. None -> ''."""
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
        try:
            return data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            if exc.start >= len(data) - 4:  # stream cut inside a multi-byte character
                return data.decode("utf-8-sig", errors="replace")
            if data.startswith(b"\xef\xbb\xbf"):
                data = data[3:]
            return data.decode("cp1252", errors="replace")
    if isinstance(raw, str):
        return raw[1:] if raw.startswith("﻿") else raw
    return str(raw)


def has_utf8_bom(raw: Any) -> bool:
    """True when the raw body starts with a UTF-8 BOM (BCB STR and EU FSF files do)."""
    if isinstance(raw, (bytes, bytearray, memoryview)):
        return bytes(raw[:3]) == b"\xef\xbb\xbf"
    return isinstance(raw, str) and raw.startswith("﻿")


def looks_like_html(raw: Any) -> bool:
    """True when a body that should be CSV/JSON is an HTML page (error or maintenance page)."""
    head = to_text(raw[:4096] if isinstance(raw, (bytes, bytearray, str)) else raw)[:4096].lstrip().lower()
    if head.startswith(("<!doctype html", "<html", "<head", "<body")):
        return True
    return head.startswith("<!--") and "<html" in head


def only_digits(value: Any) -> str:
    return re.sub(r"\D", "", str(value if value is not None else ""))


def strip_accents(text: Any) -> str:
    """NFKD and drop combining marks."""
    return "".join(c for c in unicodedata.normalize("NFKD", str(text or "")) if not unicodedata.combining(c))


def _fold(text: Any) -> str:
    """Accent-folded, case-folded words separated by single spaces, padded with spaces."""
    return " " + re.sub(r"[\W_]+", " ", strip_accents(text).casefold()).strip() + " "


# =============================================================================================
# B. Brazilian identifiers (P232) - CNPJ (numeric and alphanumeric), CPF (offline only, masked),
#    masking of other personal ids, plates, CEP, PIX key types, CNJ process numbers
# =============================================================================================

#: P232 cond 4: a check-digit validation says nothing about existence or registration.
FORMAT_ONLY_WORDING = "check digits valid (format only)"
CEP_WORDING = "format valid (existence not checked)"

#: 9th CPF digit -> fiscal region states (Receita Federal). Region 10 is written '0'.
CPF_REGIONS: dict[str, tuple[str, ...]] = {
    "1": ("DF", "GO", "MS", "MT", "TO"), "2": ("AC", "AM", "AP", "PA", "RO", "RR"), "3": ("CE", "MA", "PI"),
    "4": ("AL", "PB", "PE", "RN"), "5": ("BA", "SE"), "6": ("MG",), "7": ("ES", "RJ"), "8": ("SP",),
    "9": ("PR", "SC"), "0": ("RS",),
}
CNPJ_RE = re.compile(r"^[0-9A-Z]{12}[0-9]{2}$")


def cpf_valid(value: Any) -> bool:
    """CPF mod 11 (weights 10..2 and 11..2), repeated digits rejected. Offline only (P232 cond 3)."""
    d = only_digits(value)
    return len(d) == 11 and _val.cpf_valid(d)


def cpf_region(value: Any) -> dict[str, Any] | None:
    """P232 cond 4: fiscal region of the 9th digit, worded as issuance, never residence (info only)."""
    d = only_digits(value)
    if len(d) != 11 or not _val.cpf_valid(d):
        return None
    ufs = CPF_REGIONS[d[8]]
    region = int(d[8]) if d[8] != "0" else 10
    return {"region": region, "ufs": list(ufs), "text": f"CPF issued in fiscal region {region} ({', '.join(ufs)})", "info_only": True}


def mask_national_id(value: Any, keep_start: int = 3, keep_end: int = 2) -> str:
    """Masking for PIS/NIS, titulo de eleitor, RENAVAM, CNS and CNH (P232 cond 6): separators kept,
    the first ``keep_start`` and last ``keep_end`` digits masked. These identifiers are never
    auto-detected entity types and never pivots; their validators ship only with official test
    vectors (docs/backlog/p1-G10-1.md)."""
    text = str(value if value is not None else "")
    positions = [i for i, c in enumerate(text) if c.isdigit()]
    if not positions:
        return text
    hide = set(positions[:keep_start]) | set(positions[-keep_end:] if keep_end else [])
    return "".join("*" if i in hide else c for i, c in enumerate(text))


def cnpj_normalize(value: Any) -> str | None:
    """Strip '.', '/', '-' and spaces and upper-case; None when the shape is not a CNPJ (the
    alphanumeric CNPJ of IN RFB 2.229/2024 included: ``^[0-9A-Z]{12}[0-9]{2}$``)."""
    c = re.sub(r"[\s./-]", "", str(value if value is not None else "")).upper()
    return c if CNPJ_RE.match(c) else None


def cnpj_dv(base12: Any) -> str:
    """Alphanumeric CNPJ check digits (P232 cond 2): value ord(c)-48, weights 5..2,9..2 then
    6..2,9..2, r = sum % 11, DV = 0 if r < 2 else 11 - r. Raises ValueError for a bad base."""
    base = str(base12 if base12 is not None else "").upper()
    if not re.match(r"^[0-9A-Z]{12}$", base):
        raise ValueError("CNPJ base must be 12 characters [0-9A-Z]")
    return _val.cnpj_check_digits(base)


def cnpj_valid(value: Any) -> bool:
    """CNPJ validity (numeric and alphanumeric); repeated characters rejected."""
    c = cnpj_normalize(value)
    return bool(c) and _val.cnpj_valid(c)


def cnpj_format(value: Any) -> str | None:
    c = cnpj_normalize(value)
    return f"{c[:2]}.{c[2:5]}.{c[5:8]}/{c[8:12]}-{c[12:]}" if c else None


def cnpj_headquarters(value: Any) -> str | None:
    """Head-office CNPJ derived from the 8-character root: root + '0001' + DV (P232 cond 2). Accepts a
    full CNPJ or the 8-character root."""
    c = cnpj_normalize(value)
    if c:
        root = c[:8]
    else:
        root = re.sub(r"[\s./-]", "", str(value if value is not None else "")).upper()
        if not re.match(r"^[0-9A-Z]{8}$", root):
            return None
    base = root + "0001"
    return base + cnpj_dv(base)


def cnpj_info(value: Any) -> dict[str, Any]:
    """{valid, normalized, formatted, root, order, is_headquarters, hq_cnpj, alphanumeric, wording}."""
    c = cnpj_normalize(value)
    valid = bool(c) and cnpj_valid(c)
    return {
        "valid": valid,
        "normalized": c,
        "formatted": cnpj_format(c) if c else None,
        "root": c[:8] if c else None,
        "order": c[8:12] if c else None,
        "is_headquarters": bool(c) and c[8:12] == "0001",
        "hq_cnpj": cnpj_headquarters(c) if c else None,
        "alphanumeric": bool(c) and not c.isdigit(),
        "wording": FORMAT_ONLY_WORDING if valid else "invalid check digits",
    }


PLATE_OLD_RE = re.compile(r"^[A-Z]{3}[0-9]{4}$")
PLATE_MERCOSUL_RE = re.compile(r"^[A-Z]{3}[0-9][A-Z][0-9]{2}$")


def plate_info(value: Any) -> dict[str, Any] | None:
    """P232 cond 9: validation and old <-> Mercosul conversion only (5th character: digit d <-> letter
    chr(65 + d); a Mercosul letter after J has no old form). Never an owner lookup."""
    p = re.sub(r"[^A-Za-z0-9]", "", str(value if value is not None else "")).upper()
    if PLATE_OLD_RE.match(p):
        mercosul = p[:4] + chr(65 + int(p[4])) + p[5:]
        return {"format": "old", "plate": p, "old": p, "mercosul": mercosul, "search_forms": [p, mercosul]}
    if PLATE_MERCOSUL_RE.match(p):
        old = p[:4] + str(ord(p[4]) - 65) + p[5:] if p[4] <= "J" else None
        return {"format": "mercosul", "plate": p, "old": old, "mercosul": p, "search_forms": [p] + ([old] if old else [])}
    return None


#: First CEP digits (5) -> UF, from the public Correios range table (approximate: a hint, never proof).
CEP_RANGES = (
    (1000, 19999, "SP"), (20000, 28999, "RJ"), (29000, 29999, "ES"), (30000, 39999, "MG"), (40000, 48999, "BA"),
    (49000, 49999, "SE"), (50000, 56999, "PE"), (57000, 57999, "AL"), (58000, 58999, "PB"), (59000, 59999, "RN"),
    (60000, 63999, "CE"), (64000, 64999, "PI"), (65000, 65999, "MA"), (66000, 68899, "PA"), (68900, 68999, "AP"),
    (69000, 69299, "AM"), (69300, 69399, "RR"), (69400, 69899, "AM"), (69900, 69999, "AC"), (70000, 72799, "DF"),
    (72800, 72999, "GO"), (73000, 73699, "DF"), (73700, 76799, "GO"), (76800, 76999, "RO"), (77000, 77999, "TO"),
    (78000, 78899, "MT"), (79000, 79999, "MS"), (80000, 87999, "PR"), (88000, 89999, "SC"), (90000, 99999, "RS"),
)


def cep_info(value: Any) -> dict[str, Any]:
    """P232 cond 9: CEP format check (8 digits) and an approximate UF hint from the public ranges."""
    d = only_digits(value)
    if len(d) != 8 or d == "00000000":
        return {"valid": False, "normalized": None, "formatted": None, "uf_hint": None, "wording": "invalid CEP format"}
    n = int(d[:5])
    uf = next((u for a, b, u in CEP_RANGES if a <= n <= b), None)
    return {"valid": True, "normalized": d, "formatted": f"{d[:5]}-{d[5:]}", "uf_hint": uf, "wording": CEP_WORDING}


#: Allocated Brazilian DDDs (Anatel numbering plan) -> UF.
DDD_UF: dict[int, str] = {
    11: "SP", 12: "SP", 13: "SP", 14: "SP", 15: "SP", 16: "SP", 17: "SP", 18: "SP", 19: "SP", 21: "RJ", 22: "RJ",
    24: "RJ", 27: "ES", 28: "ES", 31: "MG", 32: "MG", 33: "MG", 34: "MG", 35: "MG", 37: "MG", 38: "MG", 41: "PR",
    42: "PR", 43: "PR", 44: "PR", 45: "PR", 46: "PR", 47: "SC", 48: "SC", 49: "SC", 51: "RS", 53: "RS", 54: "RS",
    55: "RS", 61: "DF", 62: "GO", 64: "GO", 63: "TO", 65: "MT", 66: "MT", 67: "MS", 68: "AC", 69: "RO", 71: "BA",
    73: "BA", 74: "BA", 75: "BA", 77: "BA", 79: "SE", 81: "PE", 87: "PE", 82: "AL", 83: "PB", 84: "RN", 85: "CE",
    88: "CE", 86: "PI", 89: "PI", 91: "PA", 93: "PA", 94: "PA", 92: "AM", 97: "AM", 95: "RR", 96: "AP", 98: "MA",
    99: "MA",
}

_EVP_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_EMAIL_RE = re.compile(
    r"^[a-z0-9.!#$&'*+/=?^_`{|}~-]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


def pix_key_type(value: Any) -> str | None:
    """'cpf' | 'cnpj' | 'phone' | 'email' | 'evp' | None, offline (no DICT lookup; P232 cond 9,
    P233 cond 4). The EVP check accepts any RFC 4122 layout (the BCB manual vector is a version-1 UUID)."""
    if not isinstance(value, str):
        return None
    k = value.strip()
    if not k or len(k) > 128:
        return None
    if _EVP_RE.match(k.lower()):
        return "evp"
    if "@" in k:
        return "email" if len(k) <= 77 and _EMAIL_RE.match(k.lower()) else None
    if re.fullmatch(r"\+55[1-9]{2}9?[0-9]{8}", k):
        return "phone" if int(k[3:5]) in DDD_UF else None
    c = re.sub(r"[.\-/ ]", "", k).upper()
    if len(c) == 11 and c.isdigit() and _val.cpf_valid(c):
        return "cpf"
    if len(c) == 14 and cnpj_valid(c):
        return "cnpj"
    return None


def mask_pix_key(value: Any, key_type: str | None = None) -> str:
    """CPF keys are masked (rule 4, AR24); other key types are shown as they are."""
    kt = key_type or pix_key_type(value if isinstance(value, str) else None)
    return mask_cpf(value) if kt == "cpf" else str(value if value is not None else "")


_TR_STATE = list(_words_seq("AC AL AP AM BA CE DF ES GO MA MT MS MG PA PB PR PE PI RJ RN RS RO RR SC SE SP TO"))


def cnj_parse(value: Any) -> dict[str, Any] | None:
    """CNJ unified process number NNNNNNN-DD.AAAA.J.TR.OOOO with its mod-97 check (Res. CNJ 65/2008)."""
    d = only_digits(value)
    if len(d) != 20:
        return None
    n, dd, year, j, tr, origin = d[0:7], d[7:9], d[9:13], d[13], d[14:16], d[16:20]
    ok = int(n + year + j + tr + origin + dd) % 97 == 1
    tri = int(tr)
    alias = None
    if j == "8" and 1 <= tri <= 27:
        alias = "tjdft" if _TR_STATE[tri - 1] == "DF" else "tj" + _TR_STATE[tri - 1].lower()
    elif j == "4" and 1 <= tri <= 6:
        alias = f"trf{tri}"
    elif j == "5" and 1 <= tri <= 24:
        alias = f"trt{tri}"
    elif j == "6" and 1 <= tri <= 27:
        alias = "tre-dft" if _TR_STATE[tri - 1] == "DF" else "tre-" + _TR_STATE[tri - 1].lower()
    elif j == "5" and tri == 0:
        alias = "tst"
    elif j == "3":
        alias = "stj"
    elif j == "7":
        alias = "stm"
    elif j == "9":
        alias = {13: "tjmmg", 21: "tjmrs", 26: "tjmsp"}.get(tri)
    return {
        "check_ok": ok, "seq": n, "dv": dd, "year": year, "segment": j, "tribunal_code": tr, "origin": origin,
        "formatted": f"{n}-{dd}.{year}.{j}.{tr}.{origin}", "datajud_alias": ("api_publica_" + alias) if alias else None,
    }


# =============================================================================================
# C. 11-digit typing gate (P232 cond 7) and the BR rule set (P232 cond 8)
# =============================================================================================

_CPF_LABEL_RE = re.compile(r"(?:\bc\.?p\.?f\b\.?(?:/mf\b)?|\bcadastro de pessoa)[^0-9\n]{0,25}$", re.I)
_CPF_FORM_RE = re.compile(r"(?:name\s*=\s*[\"']?cpf|[\"']cpf[\"']\s*:|\bcpf\s*=)\s*[\"']?\s*$", re.I)
_PHONE_WORDS_RE = re.compile(
    r"(?:\b(?:tel|telefone|fone|cel|celular|whats(?:app)?|zap|wpp|ligue|liga|contato|sms)\b|wa\.me/|api\.whatsapp\.com)[^0-9\n]{0,20}$",
    re.I,
)
_CPF_MASK_RE = re.compile(r"^\d{3}\.\d{3}\.\d{3}-\d{2}$")


def type_11_digit_candidate(text: str, start: int, end: int) -> dict[str, Any]:
    """P232 cond 7 typing gate for the 11-digit candidate ``text[start:end]``.

    CPF only with valid check digits AND context (a CPF label before it, the ###.###.###-## mask or a
    cpf form/JSON field); phone context (DDD in parentheses, +55, tel/whats/zap words, wa.me) types
    it as a phone and wins over the check digits; a context-free mobile-shaped number is a weak (0.4)
    phone and never a CPF. Returns {type: 'cpf' | 'phone' | None, confidence, reason}.
    """
    s = str(text or "")
    cand = s[start:end]
    digits = only_digits(cand)
    before = s[max(0, start - 40):start]
    if len(digits) != 11:
        return {"type": None, "confidence": 0.0, "reason": "not 11 digits"}
    dv_ok = _val.cpf_valid(digits)
    if _CPF_MASK_RE.match(cand) and dv_ok:
        return {"type": "cpf", "confidence": 0.95, "reason": "CPF mask ###.###.###-## with valid check digits"}
    phone_ctx = (
        bool(_PHONE_WORDS_RE.search(before)) or bool(re.search(r"(?:\+?55\s*)$|\(\s*$", before)) or bool(re.match(r"^\(\d{2}\)", cand))
    )
    ddd_ok = int(digits[:2]) in DDD_UF and digits[2] == "9"
    if phone_ctx:
        return {
            "type": "phone" if ddd_ok else None,
            "confidence": 0.85 if ddd_ok else 0.0,
            "reason": "phone context" + ("" if ddd_ok else " but not a valid Brazilian mobile number"),
        }
    if dv_ok and (_CPF_LABEL_RE.search(before) or _CPF_FORM_RE.search(before)):
        return {"type": "cpf", "confidence": 0.9, "reason": "CPF label or field with valid check digits"}
    if ddd_ok:
        note = " (also passes the CPF check digits: never typed CPF without context)" if dv_ok else ""
        return {"type": "phone", "confidence": 0.4, "reason": "Brazilian mobile shape without context" + note}
    if dv_ok:
        return {"type": None, "confidence": 0.0, "reason": "valid CPF check digits but no CPF context"}
    return {"type": None, "confidence": 0.0, "reason": "no rule matched"}


#: The BR rule set (P232 cond 8): applied in this priority order by :func:`extract_br_entities`;
#: a higher-priority span masks lower-priority candidates inside it. Each rule: (rule id, entity type,
#: candidate pattern, checksum gate). It is meant to be registered as rules of the shared P172
#: extraction engine (WP17) - never a second extractor once that engine lands.
BR_RULES: tuple[tuple[str, str, str, str], ...] = (
    ("brcode_emv", "brcode", "'000201' + EMV TLV walk to field 63/04 (<= 512 bytes) with br.gov.bcb.pix", "CRC16/CCITT-FALSE"),
    ("boleto_bancario", "boleto", "47-digit linha digitavel (formatted or a digit run)", "field DVs mod 10 + general DV mod 11"),
    ("boleto_arrecadacao", "boleto", "48-digit line starting with 8", "block DVs mod 10 / mod 11 by the value type"),
    ("cnj_mod97", "cnj", "20-digit CNJ process number NNNNNNN-DD.AAAA.J.TR.OOOO", "mod 97"),
    ("cnpj_formatted", "cnpj", "##.###.###/####-## (alphanumeric bodies included)", "CNPJ check digits"),
    ("cnpj_digits", "cnpj", "14 digits", "CNPJ check digits"),
    ("cnpj_alnum_labelled", "cnpj", "12 alphanumeric + 2 digits after a CNPJ label", "CNPJ check digits"),
    ("pix_key_labelled", "pix_key", "value after 'chave pix'", "PIX key type (CPF/CNPJ check digits, DDD, e-mail, EVP)"),
    ("cpf_mask", "cpf", "###.###.###-##", "CPF check digits + typing gate"),
    ("cpf_labelled", "cpf", "11 digits after a CPF label or field", "CPF check digits + typing gate (never phone context)"),
    ("phone_11_digits_context", "phone", "11 digits in phone context", "allocated DDD + mobile 9"),
    ("phone_br", "phone", "+55 / (DD) / DDD-number forms", "allocated DDD"),
    ("masked_cpf_marker", "masked_cpf", "***.###.###-**", "none: never completed"),
)
BR_PRIORITY = ("brcode", "boleto", "cnj", "cnpj", "pix_key", "cpf", "phone", "masked_cpf")

_BRCODE_START = re.compile(r"000201")
_BOLETO_BANCARIO_FMT = re.compile(r"(?<![\d])\d{5}\.?\d{5}[ .]?\d{5}\.?\d{6}[ .]?\d{5}\.?\d{6}[ .]?\d[ .]?\d{14}(?![\d])")
_BOLETO_ARREC_FMT = re.compile(r"(?<![\d])8\d{10}[- ]?\d[ ]?\d{11}[- ]?\d[ ]?\d{11}[- ]?\d[ ]?\d{11}[- ]?\d(?![\d])")
_BOLETO_CAND = re.compile(r"(?<![\d])\d(?:[\d .\-]{40,80})\d(?![\d])")
_CNJ_CAND = re.compile(r"(?<![\d])\d{7}-?\d{2}\.?\d{4}\.?\d\.?\d{2}\.?\d{4}(?![\d])")
_CNPJ_FMT_CAND = re.compile(r"(?<![0-9A-Za-z])[0-9A-Z]{2}\.[0-9A-Z]{3}\.[0-9A-Z]{3}/[0-9A-Z]{4}-\d{2}(?![0-9A-Za-z])")
_CNPJ_RAW_CAND = re.compile(r"(?<![0-9A-Za-z])[0-9A-Z]{12}\d{2}(?![0-9A-Za-z])")
_CPF_FMT_CAND = re.compile(r"(?<![\d.])\d{3}\.\d{3}\.\d{3}-\d{2}(?![\d])")
_D11_CAND = re.compile(r"(?<![\d])\d{11}(?![\d])")
_PHONE_CAND = re.compile(r"(?<![\d+])(?:\+?55\s?)?\(?\s?[1-9]{2}\s?\)?\s?9?\d{4}[-\s]?\d{4}(?![\d])")
_MASKED_CPF = re.compile(r"\*{3}\.\d{3}\.\d{3}-\*{2}")
_CNPJ_LABEL_RE = re.compile(r"\bcnpj\b[^0-9A-Za-z\n]{0,20}$", re.I)
_PIX_KEY_CAND = re.compile(r"\bchave\s+pix\b\s*[:\-]?\s*(\S{1,128})", re.I)
#: Upper bound of entities one text yields (the module caps pivots separately).
MAX_TEXT_ENTITIES = 1000


def scan_brcode(text: str, start: int) -> str | None:
    """Walk the EMV TLV chain from ``start`` (a '000201' position) and return the payload that ends
    with the CRC field 63/04, or None (a '6304' inside another field never cuts the payload)."""
    s = str(text or "")
    i = start
    limit = min(len(s), start + BRCODE_MAX_BYTES)
    while i + 4 <= limit:
        tag, length = s[i:i + 2], s[i + 2:i + 4]
        if not (tag.isdigit() and length.isdigit()):
            return None
        ln = int(length)
        if tag == "63":
            if ln != 4 or i + 8 > len(s):
                return None
            crc = s[i + 4:i + 8]
            return s[start:i + 8] if re.fullmatch(r"[0-9A-Fa-f]{4}", crc) else None
        value = s[i + 4:i + 4 + ln]
        if len(value) != ln or "\n" in value or "\r" in value:
            return None
        i += 4 + ln
    return None


def find_brcodes(text: str, *, limit: int = 50) -> list[tuple[int, int, str]]:
    """(start, end, payload) of every PIX BR Code candidate in ``text`` (TLV walk, GUI present)."""
    s = str(text or "")
    out: list[tuple[int, int, str]] = []
    pos = 0
    while len(out) < limit:
        m = _BRCODE_START.search(s, pos)
        if not m:
            break
        payload = scan_brcode(s, m.start())
        if payload and PIX_GUI in payload.lower():
            out.append((m.start(), m.start() + len(payload), payload))
            pos = m.start() + len(payload)
        else:
            pos = m.start() + 1
    return out


def find_boleto_lines(text: str, *, limit: int = 50) -> list[tuple[int, int, str]]:
    """(start, end, digits) of boleto line candidates (47 bancario / 48 arrecadacao digits) in
    ``text``; formatted patterns first, then generic digit runs. Overlapping candidates are dropped."""
    s = str(text or "")
    out: list[tuple[int, int, str]] = []
    for rx in (_BOLETO_BANCARIO_FMT, _BOLETO_ARREC_FMT, _BOLETO_CAND):
        for m in rx.finditer(s):
            if len(out) >= limit:
                return out
            digits = only_digits(m.group(0))
            if len(digits) not in (47, 48) or (len(digits) == 48 and digits[0] != "8"):
                continue
            a, b = m.span()
            if any(not (b <= x or a >= y) for x, y, _d in out):
                continue
            out.append((a, b, digits))
    return out


def extract_br_entities(text: Any, *, max_entities: int = MAX_TEXT_ENTITIES) -> list[dict[str, Any]]:
    """Apply :data:`BR_RULES` to a text (P232 cond 8): regex candidates, then checksum gating, in the
    priority BR Code > boleto (47/48) > CNJ (mod 97) > CNPJ > PIX key > CPF > phone; a higher-priority
    span masks lower-priority candidates inside it.

    Each entity: {type, value, display, span, rule, confidence, checksum_ok, expand} (+ key_type for
    PIX keys). CPF values (and CPF PIX keys) are returned masked only: the raw CPF never leaves this
    function; a BR Code with a CPF key is returned with the key masked in place. Masked CPFs
    (``***.456.789-**``) become 'masked_cpf' markers and are never completed.
    """
    s = str(text or "")
    found: list[dict[str, Any]] = []
    taken: list[tuple[int, int]] = []

    def overlaps(a: int, b: int) -> bool:
        return any(not (b <= x or a >= y) for x, y in taken)

    def add(etype: str, value: str, span: tuple[int, int], rule: str, conf: float, checksum_ok: bool | None = True,
            display: str | None = None, extra: dict[str, Any] | None = None) -> None:
        if len(found) >= max_entities or overlaps(*span):
            return
        taken.append(span)
        item = {"type": etype, "value": value, "display": display if display is not None else value, "span": [span[0], span[1]],
                "rule": rule, "confidence": conf, "checksum_ok": checksum_ok, "expand": etype not in ("cpf", "phone", "pix_key", "masked_cpf")}
        if extra:
            item.update(extra)
        found.append(item)

    for start, end, payload in find_brcodes(s, limit=max_entities):
        parsed = parse_brcode(payload)
        if not parsed.get("ok"):
            continue
        shown = masked_brcode(payload, parsed)
        add("brcode", shown, (start, end), "brcode_emv", 0.99 if parsed.get("crc_ok") else 0.8, bool(parsed.get("crc_ok")),
            display=(shown[:40] + ("..." if len(shown) > 40 else "")) if parsed.get("key_type") != "cpf" else "PIX BR Code (CPF key masked)",
            extra={"key_type": parsed.get("key_type"), "crc_ok": bool(parsed.get("crc_ok"))})
    for start, end, digits in find_boleto_lines(s, limit=max_entities):
        parsed = parse_boleto(digits)
        if not parsed.get("ok"):
            continue
        add("boleto", digits, (start, end), "boleto_" + parsed["type"], 0.95 if parsed["check_digits_ok"] else 0.6, bool(parsed["check_digits_ok"]))
    for m in _CNJ_CAND.finditer(s):
        info = cnj_parse(m.group(0))
        if info and info["check_ok"]:
            add("cnj", info["formatted"], m.span(), "cnj_mod97", 0.9 if "-" in m.group(0) else 0.75)
    for m in _CNPJ_FMT_CAND.finditer(s):
        c = cnpj_normalize(m.group(0))
        if c and cnpj_valid(c):
            add("cnpj", c, m.span(), "cnpj_formatted", 0.95, display=cnpj_format(c))
    for m in _CNPJ_RAW_CAND.finditer(s):
        c = m.group(0)
        if not cnpj_valid(c):
            continue
        if c.isdigit():
            add("cnpj", c, m.span(), "cnpj_digits", 0.85, display=cnpj_format(c))
        elif _CNPJ_LABEL_RE.search(s[max(0, m.start() - 30):m.start()]):
            add("cnpj", c, m.span(), "cnpj_alnum_labelled", 0.8, display=cnpj_format(c))
    for m in _PIX_KEY_CAND.finditer(s):
        key = m.group(1).rstrip(".,;")
        kt = pix_key_type(key)
        if kt:
            shown = mask_pix_key(key, kt)
            add("pix_key", shown, (m.start(1), m.start(1) + len(key)), "pix_key_labelled", 0.9, display=shown, extra={"key_type": kt})
    for m in _CPF_FMT_CAND.finditer(s):
        gate = type_11_digit_candidate(s, m.start(), m.end())
        if gate["type"] == "cpf":
            shown = mask_cpf(m.group(0))
            add("cpf", shown, m.span(), "cpf_mask", gate["confidence"], display=shown)
    for m in _D11_CAND.finditer(s):
        gate = type_11_digit_candidate(s, m.start(), m.end())
        if gate["type"] == "cpf":
            shown = mask_cpf(m.group(0))
            add("cpf", shown, m.span(), "cpf_labelled", gate["confidence"], display=shown)
        elif gate["type"] == "phone" and gate["confidence"] >= 0.8:
            add("phone", "+55" + m.group(0), m.span(), "phone_11_digits_context", gate["confidence"])
    for m in _PHONE_CAND.finditer(s):
        digits = only_digits(m.group(0))
        if digits.startswith("55") and len(digits) in (12, 13):
            digits = digits[2:]
        if len(digits) not in (10, 11) or int(digits[:2]) not in DDD_UF:
            continue
        if len(digits) == 11 and digits[2] != "9":
            continue
        has_context = bool(re.search(r"\(|\+55|-|\s", m.group(0))) or bool(_PHONE_WORDS_RE.search(s[max(0, m.start() - 30):m.start()]))
        if not has_context:
            continue
        add("phone", "+55" + digits, m.span(), "phone_br", 0.85 if len(digits) == 11 else 0.7)
    for m in _MASKED_CPF.finditer(s):
        if len(found) < max_entities and not overlaps(*m.span()):
            found.append({"type": "masked_cpf", "value": m.group(0), "display": m.group(0), "span": [m.start(), m.end()],
                          "rule": "masked_cpf_marker", "confidence": 1.0, "checksum_ok": None, "expand": False})
    order = {t: i for i, t in enumerate(BR_PRIORITY)}
    found.sort(key=lambda e: (e["span"][0], order.get(e["type"], 99)))
    return found


# =============================================================================================
# D. Boleto (P233 cond 1, 2, 7, 8)
# =============================================================================================

FACTOR_BASE_OLD = dt.date(1997, 10, 7)  # factor 1000 = 2000-07-03, 9999 = 2025-02-21
FACTOR_RESET_DATE = dt.date(2025, 2, 22)  # new cycle: factor 1000 = 2025-02-22
#: The nearest candidate farther than this from today is flagged ambiguous (both dates shown).
DUE_AMBIGUOUS_DAYS = 1825
ARRECADACAO_SEGMENTS = {
    "1": "prefeituras", "2": "saneamento", "3": "energia eletrica e gas", "4": "telecomunicacoes", "5": "orgaos governamentais",
    "6": "carnes e assemelhados / empresas identificadas por CNPJ", "7": "multas de transito", "9": "uso exclusivo do banco",
}
WORDING_DV_MISMATCH = "CHECK DIGIT MISMATCH - invalid or altered code (typed or altered line)"
WORDING_OCR = "could not verify (OCR)"


def _as_date(value: Any) -> dt.date | None:
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return dt.date.fromisoformat(text[:10])
    except ValueError:
        return None


def mod10(number: str) -> int:
    """FEBRABAN mod 10 (weights 2,1 from the right, digit sum of the products)."""
    total, weight = 0, 2
    for ch in reversed(str(number)):
        p = int(ch) * weight
        total += p // 10 + p % 10
        weight = 1 if weight == 2 else 2
    return (10 - total % 10) % 10


def _mod11_sum(number: str) -> int:
    total, weight = 0, 2
    for ch in reversed(str(number)):
        total += int(ch) * weight
        weight = 2 if weight == 9 else weight + 1
    return total


def mod11_bancario(number: str) -> int:
    """General DV of the bancario barcode: weights 2..9, DV = 11 - r; 0/10/11 -> 1."""
    dv = 11 - _mod11_sum(number) % 11
    return 1 if dv in (0, 10, 11) else dv


def mod11_arrecadacao(number: str) -> int:
    """Arrecadacao mod 11 variant (value type 8/9): r 0/1 -> 0, r 10 -> 1, else 11 - r."""
    r = _mod11_sum(number) % 11
    return 0 if r in (0, 1) else (1 if r == 10 else 11 - r)


def due_dates_from_factor(factor: Any, today: Any = None) -> dict[str, Any]:
    """P233 cond 2: the due-date factor wrapped on 2025-02-22 (9999 = 2025-02-21, new 1000 =
    2025-02-22): both cycles computed, the nearest to today chosen, ambiguity flagged."""
    ref = _as_date(today) or dt.date.today()
    try:
        f = int(factor)
    except (TypeError, ValueError):
        return {"factor": None, "old_cycle": None, "new_cycle": None, "chosen": None, "cycle": None, "ambiguous": False}
    if f == 0:
        return {"factor": 0, "old_cycle": None, "new_cycle": None, "chosen": None, "cycle": None, "ambiguous": False, "note": "no due date (factor 0)"}
    old = FACTOR_BASE_OLD + dt.timedelta(days=f)
    new = FACTOR_RESET_DATE + dt.timedelta(days=f - 1000) if f >= 1000 else None
    candidates = [("old", old)] + ([("new", new)] if new else [])
    cycle, chosen = min(candidates, key=lambda c: (abs((c[1] - ref).days), c[0] != "new"))
    ambiguous = abs((chosen - ref).days) > DUE_AMBIGUOUS_DAYS
    return {"factor": f, "old_cycle": old.isoformat(), "new_cycle": new.isoformat() if new else None, "chosen": chosen.isoformat(),
            "cycle": cycle, "ambiguous": ambiguous}


def format_brl(cents: Any) -> str:
    """123456 -> 'R$ 1.234,56'."""
    try:
        c = int(cents)
    except (TypeError, ValueError):
        return "R$ ?"
    sign = "-" if c < 0 else ""
    c = abs(c)
    whole = f"{c // 100:,}".replace(",", ".")
    return f"{sign}R$ {whole},{c % 100:02d}"


def parse_boleto(line: Any, *, today: Any = None) -> dict[str, Any]:
    """Parse a boleto linha digitavel (47 bancario / 48 arrecadacao digits) or a 44-digit barcode
    (P233 cond 1). bancario: bank(3)+currency(1)+K+factor(4)+value(10)+free(25); field DVs mod 10,
    general DV mod 11 (2..9; 0/10/11 -> 1). arrecadacao: mod 10 when the 3rd digit is 6/7, the mod-11
    variant when 8/9; segment decoded; company id (the CNPJ root for segment 6)."""
    d = only_digits(line)
    if not d:
        return {"ok": False, "error": "not a boleto: no digits"}
    if len(d) == 44:
        return _parse_barcode(d, today)
    if len(d) == 47:
        f1, f2, f3, k, f5 = d[0:10], d[10:21], d[21:32], d[32], d[33:47]
        field_dvs = [mod10(f[:-1]) == int(f[-1]) for f in (f1, f2, f3)]
        bar = d[0:4] + k + f5 + d[4:9] + d[10:20] + d[21:31]
        res = _bancario_from_barcode(bar, today)
        res.update({"input_kind": "linha_digitavel", "field_dvs": field_dvs, "fields_dv_ok": all(field_dvs)})
        res["check_digits_ok"] = res["fields_dv_ok"] and res["general_dv_ok"]
        return res
    if len(d) == 48:
        if d[0] != "8":
            return {"ok": False, "error": "not a boleto: 48 digits must start with 8 (arrecadacao)"}
        blocks = [d[i:i + 12] for i in range(0, 48, 12)]
        bar = "".join(b[:11] for b in blocks)
        res = _arrecadacao_from_barcode(bar)
        if not res["ok"]:
            return res
        fn = mod10 if res["dv_method"] == "mod10" else mod11_arrecadacao
        block_dvs = [fn(b[:11]) == int(b[11]) for b in blocks]
        res.update({"input_kind": "linha_digitavel", "block_dvs": block_dvs, "fields_dv_ok": all(block_dvs)})
        res["check_digits_ok"] = res["fields_dv_ok"] and res["general_dv_ok"]
        return res
    return {"ok": False, "error": f"not a boleto: expected 47 (bancario) or 48 (arrecadacao) digits, got {len(d)}"}


def _parse_barcode(bar: str, today: Any) -> dict[str, Any]:
    res = _arrecadacao_from_barcode(bar) if bar[0] == "8" else _bancario_from_barcode(bar, today)
    if res.get("ok"):
        res.update({"input_kind": "barcode", "fields_dv_ok": None, "check_digits_ok": res["general_dv_ok"]})
    return res


def _bancario_from_barcode(bar: str, today: Any) -> dict[str, Any]:
    general_ok = mod11_bancario(bar[:4] + bar[5:]) == int(bar[4])
    factor = int(bar[5:9])
    cents = int(bar[9:19])
    return {"ok": True, "type": "bancario", "barcode": bar, "bank_code": bar[0:3], "currency": bar[3], "currency_ok": bar[3] == "9",
            "general_dv_ok": general_ok, "due_factor": factor, "due": due_dates_from_factor(factor, today), "amount_cents": cents,
            "amount_text": format_brl(cents) if cents else None, "free_field": bar[19:44]}


def _arrecadacao_from_barcode(bar: str) -> dict[str, Any]:
    value_type = bar[2]
    if value_type not in "6789":
        return {"ok": False, "error": f"arrecadacao value type {value_type} unknown (expected 6/7/8/9)"}
    method = "mod10" if value_type in "67" else "mod11"
    fn = mod10 if method == "mod10" else mod11_arrecadacao
    general_ok = fn(bar[:3] + bar[4:]) == int(bar[3])
    segment = bar[1]
    is_amount = value_type in "68"
    cents = int(bar[4:15]) if is_amount else None
    return {"ok": True, "type": "arrecadacao", "barcode": bar, "segment": segment, "segment_name": ARRECADACAO_SEGMENTS.get(segment),
            "value_type": value_type, "value_is_amount": is_amount, "dv_method": method, "general_dv_ok": general_ok, "amount_cents": cents,
            "amount_text": format_brl(cents) if cents else None, "company_id": bar[15:23] if segment == "6" else bar[15:19],
            "cnpj_root": bar[15:23] if segment == "6" else None}


def boleto_verdict_line(parsed: Any, *, bank_index: Any = None, origin: str = "typed") -> str:
    """P233 cond 7/8 plain-language verdict line (shown first)."""
    if not isinstance(parsed, dict) or not parsed.get("ok"):
        return "Boleto: not a boleto line (" + str((parsed or {}).get("error") if isinstance(parsed, dict) else "unreadable") + ")"
    if not parsed.get("check_digits_ok"):
        if origin in ("ocr", "qr"):
            return f"Boleto: {WORDING_OCR}"
        return f"Boleto: {WORDING_DV_MISMATCH}"
    if parsed["type"] == "arrecadacao":
        amount = parsed.get("amount_text") or "amount not encoded"
        return (f"Boleto (arrecadacao): check digits OK - segment {parsed['segment']} ({parsed.get('segment_name') or 'unknown'}), "
                f"{amount}, company id {parsed.get('company_id')}")
    code = parsed.get("bank_code")
    name = bank_name(code, bank_index) if bank_index else None
    due = parsed.get("due") or {}
    if due.get("factor") == 0:
        due_text = "no due date"
    elif due.get("ambiguous"):
        due_text = f"due date ambiguous ({due.get('new_cycle')} or {due.get('old_cycle')})"
    else:
        due_text = f"due {due.get('chosen')}"
    amount = parsed.get("amount_text") or "amount not set"
    return f"Boleto: check digits OK - bank {code} ({name or 'unknown bank'}), {due_text}, {amount}"


# =============================================================================================
# E. PIX BR Code (P233 cond 3, 4, 5, 7, 8)
# =============================================================================================

BRCODE_MAX_BYTES = 512
BRCODE_MAX_DEPTH = 2
PIX_GUI = "br.gov.bcb.pix"
_NESTED_TAGS = {f"{i:02d}" for i in range(26, 52)} | {"62", "64"} | {f"{i:02d}" for i in range(80, 100)}
WORDING_CRC_BAD = "altered or corrupted payload"


def crc16_ccitt_false(data: str | bytes) -> int:
    """CRC16/CCITT-FALSE (poly 0x1021, init 0xFFFF): the core implementation (b'123456789' -> 0x29B1)."""
    return _val.crc16_ccitt(data.encode("utf-8") if isinstance(data, str) else bytes(data))


def parse_emv_tlv(payload: str, *, depth: int = 1, max_depth: int = BRCODE_MAX_DEPTH) -> list[tuple[str, Any]]:
    """Strict EMV TLV parse (2-digit tag, 2-digit length); nested templates are parsed only down to
    ``max_depth`` (P233 cond 3 bound). Raises ValueError on malformed data."""
    if depth > max_depth:
        raise ValueError("BR Code nesting deeper than allowed")
    items: list[tuple[str, Any]] = []
    i = 0
    n = len(payload)
    while i < n:
        if i + 4 > n:
            raise ValueError(f"truncated TLV header at position {i}")
        tag, length = payload[i:i + 2], payload[i + 2:i + 4]
        if not (tag.isdigit() and length.isdigit()):
            raise ValueError(f"malformed TLV at position {i}")
        ln = int(length)
        value = payload[i + 4:i + 4 + ln]
        if len(value) != ln:
            raise ValueError(f"TLV value at position {i} shorter than its length")
        if tag in _NESTED_TAGS and depth < max_depth:
            items.append((tag, parse_emv_tlv(value, depth=depth + 1, max_depth=max_depth)))
        else:
            items.append((tag, value))
        i += 4 + ln
    return items


def defang_host(host: Any) -> str:
    return str(host or "").replace(".", "[.]")


def parse_brcode(payload: Any, *, origin: str = "typed") -> dict[str, Any]:
    """Parse a PIX BR Code (copia e cola or a decoded QR) offline (P233 cond 3): payload <= 512 bytes,
    nesting depth 2, merchant account template 26-51 with br.gov.bcb.pix, CRC16/CCITT-FALSE over the
    payload through '6304'. The dynamic location URL (sub-tag 25) is never fetched (cond 5): only its
    host is returned, with a defanged and a masked form."""
    out: dict[str, Any] = {
        "ok": False, "error": None, "crc_ok": None, "crc_found": None, "crc_computed": None, "point_of_initiation": None,
        "dynamic": False, "gui": None, "key": None, "key_type": None, "key_display": None, "description": None,
        "location_host": None, "location_host_defanged": None, "location_masked": None, "mcc": None, "currency": None,
        "amount": None, "amount_text": None, "country": None, "merchant_name": None, "merchant_city": None, "postal_code": None,
        "txid": None, "status_text": None, "origin": origin,
    }
    if not isinstance(payload, str):
        out["error"] = "not a BR Code: payload is not text"
        return out
    p = payload.strip()
    if len(p.encode("utf-8")) > BRCODE_MAX_BYTES:
        out["error"] = f"not a BR Code: payload larger than {BRCODE_MAX_BYTES} bytes"
        return out
    if not p.startswith("000201"):
        out["error"] = "not a BR Code: missing payload format indicator 000201"
        return out
    try:
        top = parse_emv_tlv(p)
    except ValueError as exc:
        out["error"] = f"malformed BR Code: {exc}"
        return out
    if not top or top[-1][0] != "63" or not isinstance(top[-1][1], str) or len(top[-1][1]) != 4:
        out["error"] = "malformed BR Code: CRC field 63 missing or not last"
        return out
    out["crc_found"] = top[-1][1].upper()
    out["crc_computed"] = format(crc16_ccitt_false(p[:-4]), "04X")
    out["crc_ok"] = out["crc_found"] == out["crc_computed"]
    fields: dict[str, Any] = {}
    for tag, value in top:
        fields.setdefault(tag, value)
    mai = None
    for tag, value in top:
        if "26" <= tag <= "51" and isinstance(value, list):
            sub = {t: v for t, v in value if isinstance(v, str)}
            if (sub.get("00") or "").lower() == PIX_GUI:
                mai = sub
                break
    if mai is None:
        out["error"] = "not a PIX BR Code: no merchant account template with br.gov.bcb.pix"
        return out

    def field(tag: str) -> str | None:
        value = fields.get(tag)
        return value if isinstance(value, str) else None

    out["gui"] = mai.get("00")
    out["point_of_initiation"] = field("01")
    key = mai.get("01")
    if key:
        out["key"] = key
        out["key_type"] = pix_key_type(key)
        out["key_display"] = mask_pix_key(key, out["key_type"])
    out["description"] = mai.get("02")
    url = mai.get("25")
    if url:
        out["dynamic"] = True
        bare = re.sub(r"^[a-z]+://", "", url.strip(), flags=re.I)
        host = bare.split("/", 1)[0].split("?", 1)[0].split(":", 1)[0].lower()
        out["location_host"] = host or None
        out["location_host_defanged"] = defang_host(host) if host else None
        out["location_masked"] = (host + "/***") if host else "***"
    out["mcc"] = field("52")
    out["currency"] = field("53")
    amount = field("54")
    if amount:
        out["amount"] = amount
        try:
            out["amount_text"] = format_brl(round(float(amount) * 100))
        except (ValueError, OverflowError):
            out["amount_text"] = None
    out["country"] = field("58")
    out["merchant_name"] = field("59")
    out["merchant_city"] = field("60")
    out["postal_code"] = field("61")
    add = fields.get("62")
    if isinstance(add, list):
        out["txid"] = {t: v for t, v in add if isinstance(v, str)}.get("05")
    out["ok"] = True
    if out["crc_ok"]:
        out["status_text"] = "CRC OK"
    elif origin in ("ocr", "qr"):
        out["status_text"] = WORDING_OCR
    else:
        out["status_text"] = WORDING_CRC_BAD
    return out


def masked_brcode(payload: str, parsed: dict[str, Any] | None = None) -> str:
    """The payload with a CPF PIX key masked in place (every copy of the digits): safe to display."""
    parsed = parsed if parsed is not None else parse_brcode(payload)
    key = parsed.get("key") if isinstance(parsed, dict) else None
    if key and parsed.get("key_type") == "cpf":
        digits = only_digits(key)
        masked = mask_cpf(digits)
        return payload.replace(key, masked).replace(digits, masked)
    return payload


def build_brcode(fields: list[tuple[str, Any]], merchant_account: list[tuple[str, str]]) -> str:
    """Assemble a BR Code from ordered (tag, value) pairs plus a merchant account template and append
    the CRC (test vectors only)."""

    def tlv(tag: str, value: str) -> str:
        return f"{tag}{len(value):02d}{value}"

    mai = "".join(tlv(t, v) for t, v in merchant_account)
    body = ""
    for tag, value in fields:
        if tag == "26":
            body += tlv("26", mai)
        elif isinstance(value, list):
            body += tlv(tag, "".join(tlv(t, v) for t, v in value))
        else:
            body += tlv(tag, value)
    body += "6304"
    return body + format(crc16_ccitt_false(body), "04X")


#: Legal-form words that make a merchant name a company (never a natural person, cond 4).
LEGAL_SUFFIXES = _words(
    "ltda ltd limitada sa eireli me epp mei ss llc inc incorporated corp corporation co company cia gmbh ag kg plc srl spa sas sarl "
    "sl bv nv ab as pte pty jsc ooo lda limited"
)


def has_legal_suffix(name: Any) -> bool:
    toks = _fold(name).split()
    return bool(toks) and (toks[-1] in LEGAL_SUFFIXES or toks[0] in {"ooo", "jsc"})


def brcode_entities(parsed: Any) -> dict[str, Any]:
    """Pivots and attributes of a parsed BR Code (P233 cond 4, 5).

    CPF keys: masked attribute only, never pivoted. E-mail and phone keys: pivots with relation
    pix_key_of and expand=False (no automatic breach, stealer, username or phone-reputation lookup).
    CNPJ keys: pivot (expand=True) to the P236 CNPJ chain. EVP: attribute. Location URL: its host only
    as a domain pivot (expand=False); the URL stays a masked attribute, never a url entity. Merchant
    names are pivoted (company_name, expand=False) only for a CNPJ key or a legal suffix.
    """
    pivots: list[dict[str, Any]] = []
    attrs: dict[str, Any] = {}
    if not isinstance(parsed, dict) or not parsed.get("ok"):
        return {"pivots": pivots, "attributes": attrs}
    kt, key = parsed.get("key_type"), parsed.get("key")
    if key:
        attrs["pix_key_type"] = kt or "unknown"
        attrs["pix_key"] = mask_pix_key(key, kt)
        if kt == "email":
            pivots.append({"type": "email", "value": key.lower(), "relation": "pix_key_of", "expand": False,
                           "note": "PIX key of the payee: no automatic lookup (analyst-initiated only)"})
        elif kt == "phone":
            pivots.append({"type": "phone", "value": key, "relation": "pix_key_of", "expand": False,
                           "note": "PIX key of the payee: no automatic lookup (analyst-initiated only)"})
        elif kt == "cnpj":
            pivots.append({"type": "cnpj", "value": cnpj_normalize(key), "relation": "pix_key_of", "expand": True,
                           "note": "who receives the money: CNPJ chain (P236)"})
    if parsed.get("location_host"):
        pivots.append({"type": "domain", "value": parsed["location_host"], "relation": "pix_location_host", "expand": False,
                       "note": f"PIX dynamic payload host {parsed.get('location_host_defanged')}: the location URL is never fetched"})
        attrs["pix_location_url"] = parsed.get("location_masked")
    merchant = parsed.get("merchant_name")
    if merchant:
        attrs["pix_merchant_name"] = merchant
        if kt == "cnpj" or has_legal_suffix(merchant):
            pivots.append({"type": "company_name", "value": merchant, "relation": "pix_merchant", "expand": False,
                           "note": "merchant name of the BR Code"})
    if parsed.get("merchant_city"):
        attrs["pix_merchant_city"] = parsed["merchant_city"]
    if parsed.get("txid"):
        attrs["pix_txid"] = parsed["txid"]
    if parsed.get("amount_text"):
        attrs["pix_amount"] = parsed["amount_text"]
    return {"pivots": pivots, "attributes": attrs}


def brcode_verdict_line(parsed: Any) -> str:
    """P233 cond 8: merchant, city, key type (masked key), txid, amount and CRC status."""
    if not isinstance(parsed, dict) or not parsed.get("ok"):
        return "PIX: not a valid BR Code (" + str((parsed or {}).get("error") if isinstance(parsed, dict) else "unreadable") + ")"
    if parsed.get("dynamic") and not parsed.get("key"):
        key_part = f"dynamic (location host {parsed.get('location_host_defanged')})"
    else:
        key_part = f"{parsed.get('key_type') or 'unknown'} ({parsed.get('key_display') or '?'})"
    crc = parsed.get("status_text")
    if parsed.get("crc_ok") is False and parsed.get("origin") not in ("ocr", "qr"):
        crc = f"CRC MISMATCH: {WORDING_CRC_BAD}"
    return (f"PIX: merchant {parsed.get('merchant_name') or '?'}, city {parsed.get('merchant_city') or '?'}, key {key_part}, "
            f"txid {parsed.get('txid') or '-'}, amount {parsed.get('amount_text') or 'not set'}, {crc}")


# =============================================================================================
# F. Bank / ISPB / PIX participant tables (P233 cond 9) and verdicts (cond 6)
# =============================================================================================

STR_MIN_ROWS = 300  # 473 participants on 2026-11-25
BRASILAPI_BANKS_MIN_ROWS = 300  # 473 on 2026-11-26
PIX_PARTICIPANTS_MIN_ROWS = 500  # 880 on 2026-11-26
_STR_COLUMNS = {"ispb": "ispb", "nome_reduzido": "short_name", "numero_codigo": "code", "participa_da_compe": "compe",
                "acesso_principal": "access", "nome_extenso": "full_name", "inicio_da_operacao": "start_date"}


def _norm_header(h: str) -> str:
    return strip_accents(h).strip().lower().replace(" ", "_")


def _bank_code(value: Any) -> str | None:
    text = str(value if value is not None else "").strip()
    if not text.isdigit() or int(text) == 0:
        return None
    return text.zfill(3)


def _dmy(value: str) -> str | None:
    m = re.match(r"^(\d{2})/(\d{2})/(\d{4})$", (value or "").strip())
    return f"{m.group(3)}-{m.group(2)}-{m.group(1)}" if m else ((value or "").strip() or None)


def parse_bcb_str_csv(raw: Any) -> dict[str, Any]:
    """BCB ParticipantesSTR.csv (UTF-8 BOM, ',' separated): {ok, bom, entries [{ispb, short_name, code,
    compe, access, full_name, start_date}], rows, bad_rows, error}. 'n/a' and '0' codes -> None."""
    out: dict[str, Any] = {"ok": False, "bom": has_utf8_bom(raw), "entries": [], "rows": 0, "bad_rows": 0, "error": None}
    text = to_text(raw)
    if not text.strip():
        out["error"] = "empty: STR participants body is empty"
        return out
    if looks_like_html(text):
        out["error"] = "error: HTML page instead of ParticipantesSTR.csv"
        return out
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except csv.Error as exc:
        out["error"] = f"malformed: STR CSV error ({exc})"
        return out
    if not rows:
        out["error"] = "malformed: STR CSV header missing"
        return out
    header = [_norm_header(h) for h in rows[0]]
    missing = [c for c in _STR_COLUMNS if c not in header]
    if missing:
        out["error"] = "malformed: STR CSV header lacks " + ", ".join(missing)
        return out
    ix = {_STR_COLUMNS[h]: i for i, h in enumerate(header) if h in _STR_COLUMNS}
    for row in rows[1:]:
        if not row or row == [""]:
            continue
        if len(row) != len(header) or not row[ix["ispb"]].strip().isdigit():
            out["bad_rows"] += 1
            continue
        out["entries"].append({
            "ispb": row[ix["ispb"]].strip().zfill(8), "short_name": row[ix["short_name"]].strip(), "code": _bank_code(row[ix["code"]]),
            "compe": strip_accents(row[ix["compe"]]).strip().lower() == "sim", "access": row[ix["access"]].strip() or None,
            "full_name": row[ix["full_name"]].strip(), "start_date": _dmy(row[ix["start_date"]]),
        })
    out["rows"] = len(out["entries"])
    out["ok"] = out["rows"] > 0
    if not out["ok"]:
        out["error"] = "malformed: no STR rows"
    return out


def _json_list(data: Any, what: str) -> tuple[list[Any] | None, str | None]:
    if isinstance(data, (bytes, bytearray, str)):
        text = to_text(data)
        if looks_like_html(text):
            return None, f"error: HTML page instead of {what} JSON"
        try:
            data = json.loads(text)
        except (ValueError, RecursionError):
            return None, f"malformed: truncated or invalid {what} JSON"
    if isinstance(data, dict):
        etype = str(data.get("type") or data.get("name") or "")
        if etype:
            return None, f"error: BrasilAPI {etype} instead of the {what} list"
        return None, f"malformed: {what} JSON is not a list"
    if not isinstance(data, list):
        return None, f"malformed: {what} JSON is not a list"
    return data, None


def parse_brasilapi_banks(data: Any) -> dict[str, Any]:
    """GET /api/banks/v1 (full list, never per value): [{ispb, name, code (int | null), fullName}]."""
    out: dict[str, Any] = {"ok": False, "entries": [], "bad_rows": 0, "error": None}
    items, err = _json_list(data, "BrasilAPI banks")
    if err:
        out["error"] = err
        return out
    for item in items or ():
        if not isinstance(item, dict) or not str(item.get("ispb") or "").strip().isdigit():
            out["bad_rows"] += 1
            continue
        out["entries"].append({"ispb": str(item["ispb"]).strip().zfill(8), "code": _bank_code(item.get("code")),
                               "name": str(item.get("name") or "").strip() or None, "full_name": str(item.get("fullName") or "").strip() or None})
    out["ok"] = bool(out["entries"])
    if not out["ok"]:
        out["error"] = "empty: BrasilAPI banks list is empty"
    return out


def parse_brasilapi_pix_participants(data: Any) -> dict[str, Any]:
    """GET /api/pix/v1/participants: [{ispb, nome, nome_reduzido, modalidade_participacao,
    tipo_participacao, inicio_operacao}]."""
    out: dict[str, Any] = {"ok": False, "entries": [], "bad_rows": 0, "error": None}
    items, err = _json_list(data, "BrasilAPI PIX participants")
    if err:
        out["error"] = err
        return out
    for item in items or ():
        if not isinstance(item, dict) or not str(item.get("ispb") or "").strip().isdigit():
            out["bad_rows"] += 1
            continue
        out["entries"].append({"ispb": str(item["ispb"]).strip().zfill(8), "name": str(item.get("nome") or "").strip() or None,
                               "short_name": str(item.get("nome_reduzido") or "").strip() or None,
                               "modality": item.get("modalidade_participacao"), "participation": item.get("tipo_participacao")})
    out["ok"] = bool(out["entries"])
    if not out["ok"]:
        out["error"] = "empty: BrasilAPI PIX participants list is empty"
    return out


def validate_table(parsed: Any, *, min_rows: int, what: str) -> str | None:
    """P233 cond 9 / AR10: None when a parsed table may replace the previous copy, else the reason."""
    if not isinstance(parsed, dict) or not parsed.get("ok"):
        return (parsed or {}).get("error") if isinstance(parsed, dict) and parsed.get("error") else f"malformed: {what} could not be parsed"
    n = len(parsed.get("entries") or [])
    if n < min_rows:
        return f"malformed: {what} has {n} rows (< {min_rows})"
    if parsed.get("bad_rows", 0) > max(5, n // 20):
        return f"malformed: {what} has {parsed['bad_rows']} rows with an unexpected shape"
    return None


def build_bank_index(str_entries: Any = (), brasilapi_entries: Any = (), pix_entries: Any = ()) -> dict[str, Any]:
    """code -> bank and ispb -> institution: BCB STR (trusted) first, BrasilAPI (community) fills gaps,
    PIX participants flag membership. The ISPB is the 8-digit CNPJ root of the institution."""
    by_code: dict[str, dict[str, Any]] = {}
    by_ispb: dict[str, dict[str, Any]] = {}
    for src, rows in (("bcb_str", str_entries), ("brasilapi_banks", brasilapi_entries)):
        for r in rows or ():
            rec = {"ispb": r.get("ispb"), "code": r.get("code"), "name": r.get("short_name") or r.get("name"),
                   "full_name": r.get("full_name"), "source": src}
            if rec["code"] and rec["code"] not in by_code:
                by_code[rec["code"]] = rec
            if rec["ispb"] and rec["ispb"] not in by_ispb:
                by_ispb[rec["ispb"]] = rec
    for r in pix_entries or ():
        ispb = r.get("ispb")
        if ispb and ispb not in by_ispb:
            by_ispb[ispb] = {"ispb": ispb, "code": None, "name": r.get("short_name") or r.get("name"), "full_name": r.get("name"),
                             "source": "brasilapi_pix"}
        if ispb in by_ispb:
            by_ispb[ispb]["pix_participant"] = True
    return {"by_code": by_code, "by_ispb": by_ispb}


def bank_name(code: Any, index: Any) -> str | None:
    c = _bank_code(code)
    rec = (index or {}).get("by_code", {}).get(c) if c else None
    return rec.get("name") if rec else None


def bank_record(code: Any, index: Any) -> dict[str, Any] | None:
    c = _bank_code(code)
    return (index or {}).get("by_code", {}).get(c) if c else None


#: Bank brand words used in documents and scam texts -> COMPE code (checked against the STR table).
BANK_ALIASES: dict[str, str] = {
    "banco do brasil": "001", "bco do brasil": "001", "santander": "033", "banrisul": "041", "banco inter": "077",
    "caixa economica": "104", "caixa economica federal": "104", "bradesco": "237", "nubank": "260", "nu pagamentos": "260",
    "pagseguro": "290", "pagbank": "290", "mercado pago": "323", "c6 bank": "336", "itau": "341", "itau unibanco": "341",
    "picpay": "380", "safra": "422", "sicredi": "748", "sicoob": "756", "btg pactual": "208",
}


def detect_bank_mentions(text: Any, *, aliases: dict[str, str] | None = None) -> list[str]:
    """COMPE codes of the banks named in a document or OCR text (accent- and case-insensitive)."""
    norm = _fold(text)
    codes: list[str] = []
    for alias, code in sorted((aliases or BANK_ALIASES).items(), key=lambda kv: -len(kv[0])):
        if f" {alias} " in norm and code not in codes:
            codes.append(code)
    return codes


def boleto_bank_mismatch(parsed: Any, claimed_text: Any, *, bank_index: Any = None, aliases: dict[str, str] | None = None) -> dict[str, Any] | None:
    """P233 cond 6: a barcode bank that differs from the bank named in the document -> HIGH 'boleto
    bank mismatch: possible tampering' (PROBABLE); never labelled malicious on its own."""
    if not isinstance(parsed, dict) or not parsed.get("ok") or parsed.get("type") != "bancario":
        return None
    claimed = detect_bank_mentions(claimed_text, aliases=aliases)
    code = parsed.get("bank_code")
    if not claimed or code in claimed:
        return None
    return {"severity": "high", "confidence": "probable", "title": "boleto bank mismatch: possible tampering", "barcode_bank": code,
            "barcode_bank_name": bank_name(code, bank_index) if bank_index else None, "claimed_banks": claimed,
            "claimed_bank_names": [bank_name(c, bank_index) for c in claimed] if bank_index else [], "malicious": False}


def payee_brand_mismatch(parsed: Any, *, claimed_brand: str, brand_keywords: Any = (), brand_cnpj_roots: Any = ()) -> dict[str, Any] | None:
    """P233 cond 6: a PIX merchant name or key CNPJ root that does not match the claimed brand ->
    MEDIUM 'payee differs from claimed brand'; never labelled malicious on its own."""
    if not isinstance(parsed, dict) or not parsed.get("ok") or not claimed_brand:
        return None
    words = [strip_accents(w).casefold().strip() for w in (brand_keywords or ()) if w and str(w).strip()]
    words = words or [strip_accents(claimed_brand).casefold().strip()]
    merchant = _fold(parsed.get("merchant_name") or "")
    name_ok = any(f" {w} " in merchant or (len(w.replace(" ", "")) >= 4 and w.replace(" ", "") in merchant.replace(" ", "")) for w in words)
    root_ok = False
    roots = {re.sub(r"[^0-9A-Za-z]", "", str(r)).upper()[:8] for r in brand_cnpj_roots or ()}
    if parsed.get("key_type") == "cnpj":
        root_ok = (cnpj_normalize(parsed.get("key")) or "")[:8] in roots
    if name_ok or root_ok:
        return None
    return {"severity": "medium", "confidence": "possible", "title": "payee differs from claimed brand", "claimed_brand": claimed_brand,
            "merchant_name": parsed.get("merchant_name"), "key_type": parsed.get("key_type"), "malicious": False}
