"""Vehicle VIN decoder: offline WMI table and check digit first, NHTSA vPIC second (P320, batch p3-G12-2).

Council P320: opt-in (default_enabled False), provider tier trusted (NHTSA, US DOT), terms open (US government
work, public domain), opsec passive, the VIN goes to vPIC (disclosure third_party). Final conditions:

* c1 the ``vin`` entity type (P333) is detected only through an explicit ``vin:`` TYPE:value prefix (core
  ``detect``) or a VIN/chassi label right before a 17-character value without I/O/Q. The core has the TYPE prefix;
  for the label this module also accepts KEYWORD inputs and runs only when :func:`detect_labelled_vins` finds a
  labelled value (VIN, V.I.N., chassi/chassis, nº/número do chassi): a bare 17-character token is never a VIN.
  Labelled VINs are decoded offline and pivoted as ``vin`` entities (analyst-typed keyword: expanded; anything
  else: expand=False with a note). The label rule for free text in core detection is a core request.
* c2 offline first: the bundled WMI table ``v3lum/data/vin_decoder/wmi_table.json`` (NHTSA vPIC registrant and
  make, public domain; curated rows for Brazilian WMIs vPIC does not list, such as 9BD and 93H) gives the
  manufacturer; the country comes from the ISO 3780 range of the first two characters (never from vPIC, whose
  Country is the registrant's: 9BW -> MEXICO). The position-9 check digit is enforced only for North American
  WMIs (first character 1-5); for other WMIs a mismatch is a note, never 'invalid'.
* c3 the online step: vPIC ``DecodeVinValues`` (one validated VIN per run; the engine runs one entity per module
  run, so the documented ``DecodeVINValuesBatch`` form of up to 50 VINs is kept in :func:`vpic_batch_forms` for
  the engine's future grouped inputs - docs/backlog/p3-G12-2.md). Every online fact carries the US-centric label
  :data:`VPIC_SCOPE_LABEL`. VIN is a PERSONAL_TYPE: until the provider records a personal-data review the policy
  gate (POL-07) runs the module only when it is selected explicitly in a case with a recorded purpose (A3/A8).
  vPIC answers HTTP 200 for everything: errors are read from ErrorCode/ErrorText (error-in-200), an unknown
  vehicle is 'no vehicle data in vPIC', and 403/429/5xx/timeouts/non-JSON answers are 'could not verify' for the
  vPIC source (``res.source_status``) while the offline facts stand.
* c4 no owner, plate or registration lookups (no such host is declared; the P327 lint refuses them). The VIN is
  masked in exports by the core (first 11 characters, serial hidden); this module never writes the full VIN
  into attributes, findings or evidence (``mask_vin``).
* c5 merge gate: offline tests over trimmed real vPIC captures and a non-North-American VIN with a failing
  check digit (tests/modules/test_vin_decoder.py), provider fragment ``nhtsa``, registry contract test, P327 lint.
"""

from __future__ import annotations

import re
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.entities import mask_vin
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    HttpError,
    NetworkError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec, Status, valid_reason
from v3lum.core.module import Module, register

SRC_VPIC = "nhtsa.vpic_decode"
SRC_WMI = "nhtsa.wmi_table"
WMI_TABLE = "vin_decoder/wmi_table.json"
VPIC_BASE = "https://vpic.nhtsa.dot.gov/api/vehicles"
VPIC_SCOPE_LABEL = "NHTSA vPIC (US-market data; vehicles sold only outside the US may be missing or partial)"
VPIC_BATCH_MAX = 50
MAX_LABELLED = 5

# ======================================================================================================
# [P320 offline decoding] (prep parsers.py, stdlib only)
# ======================================================================================================

VIN_CHARS = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"  # ISO 3779: no I, O, Q
_VIN_RE = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")
_TRANSLIT = {**{str(d): d for d in range(10)},
             **dict(zip("ABCDEFGH", range(1, 9))), **dict(zip("JKLMN", range(1, 6))), "P": 7, "R": 9,
             **dict(zip("STUVWXYZ", range(2, 10)))}
_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)
#: ISO 3780 / SAE order of the second character inside a country range: A-Z (no I, O, Q), then 1-9, then 0.
_ISO3780_ORDER = "ABCDEFGHJKLMNPRSTUVWXYZ1234567890"
#: (first char, second char from, second char to, country): the ISO 3780 / SAE WMI country ranges this table
#: is sure of (Brazil and the main producing countries). A WMI outside them gets its region only.
ISO3780_RANGES: tuple[tuple[str, str, str, str], ...] = (
    ("A", "A", "H", "South Africa"),
    ("J", "A", "0", "Japan"),
    ("K", "L", "R", "South Korea"),
    ("L", "A", "0", "China"),
    ("M", "A", "E", "India"), ("M", "F", "K", "Indonesia"), ("M", "L", "R", "Thailand"),
    ("N", "L", "R", "Turkey"),
    ("P", "A", "E", "Philippines"), ("P", "L", "R", "Malaysia"),
    ("R", "F", "K", "Taiwan"), ("R", "L", "R", "Vietnam"),
    ("S", "A", "M", "United Kingdom"), ("S", "U", "Z", "Poland"),
    ("T", "A", "H", "Switzerland"), ("T", "J", "P", "Czech Republic"), ("T", "R", "V", "Hungary"),
    ("T", "W", "1", "Portugal"),
    ("U", "U", "Z", "Romania"), ("U", "5", "7", "Slovakia"),
    ("V", "A", "E", "Austria"), ("V", "F", "R", "France"), ("V", "S", "W", "Spain"),
    ("W", "A", "0", "Germany"),
    ("X", "L", "R", "Netherlands"), ("X", "S", "W", "Russia"), ("X", "3", "0", "Russia"),
    ("Y", "A", "E", "Belgium"), ("Y", "F", "K", "Finland"), ("Y", "S", "W", "Sweden"),
    ("Z", "A", "R", "Italy"),
    ("1", "A", "0", "United States"), ("4", "A", "0", "United States"), ("5", "A", "0", "United States"),
    ("2", "A", "0", "Canada"), ("3", "A", "W", "Mexico"),
    ("6", "A", "W", "Australia"), ("7", "A", "E", "New Zealand"),
    ("8", "A", "E", "Argentina"), ("8", "F", "J", "Chile"), ("8", "L", "R", "Ecuador"), ("8", "S", "W", "Peru"),
    ("8", "X", "2", "Venezuela"),
    ("9", "A", "E", "Brazil"), ("9", "F", "J", "Colombia"), ("9", "S", "V", "Uruguay"), ("9", "3", "9", "Brazil"),
)
ISO3780_REGIONS = {**dict.fromkeys("ABCDEFGH", "Africa"), **dict.fromkeys("JKLMNPR", "Asia"),
                   **dict.fromkeys("STUVWXYZ", "Europe"), **dict.fromkeys("12345", "North America"),
                   **dict.fromkeys("67", "Oceania"), **dict.fromkeys("89", "South America")}
NORTH_AMERICA_FIRST = frozenset("12345")
_YEAR_CODES = "ABCDEFGHJKLMNPRSTVWXY123456789"  # 30-year cycle from 1980 (and 2010)


def is_vin_syntax(value: Any) -> bool:
    """17 characters of the ISO 3779 alphabet (no I/O/Q), upper case (c1)."""
    return isinstance(value, str) and bool(_VIN_RE.match(value))


def normalize_vin(value: Any) -> str | None:
    """Analyst-typed VIN (TYPE:value input): strip, upper-case, drop inner spaces/hyphens and a 'vin:'/'chassi:'
    prefix. None unless the result is a syntactically valid VIN. Never used on free text (c1)."""
    if not isinstance(value, str):
        return None
    v = re.sub(r"[\s\-]", "", value.strip()).upper()
    if v.lower().startswith(("vin:", "chassi:")):
        v = v.split(":", 1)[1]
    return v if is_vin_syntax(v) else None


def vin_check_digit(vin: str) -> str | None:
    """Expected position-9 check digit ('0'-'9' or 'X') of a syntactically valid VIN (c2)."""
    if not is_vin_syntax(vin):
        return None
    r = sum(_TRANSLIT[c] * w for c, w in zip(vin, _WEIGHTS)) % 11
    return "X" if r == 10 else str(r)


def is_north_american_wmi(vin_or_wmi: Any) -> bool:
    """WMI first character 1-5 (United States, Canada, Mexico...): the only WMIs whose check digit is
    enforced (c2)."""
    return isinstance(vin_or_wmi, str) and vin_or_wmi[:1] in NORTH_AMERICA_FIRST


def iso3780_country(vin_or_wmi: Any) -> dict[str, str | None]:
    """Country and region of a WMI from the ISO 3780 range of its first two characters (c2). Never taken from
    vPIC's WMI 'Country', which is the US registrant's (9BW -> 'MEXICO')."""
    s = vin_or_wmi.upper()[:2] if isinstance(vin_or_wmi, str) else ""
    out: dict[str, str | None] = {"country": None, "region": ISO3780_REGIONS.get(s[:1]) if s else None}
    if len(s) < 2 or s[1] not in _ISO3780_ORDER:
        return out
    pos = _ISO3780_ORDER.index(s[1])
    for first, lo, hi, country in ISO3780_RANGES:
        if s[0] == first and _ISO3780_ORDER.index(lo) <= pos <= _ISO3780_ORDER.index(hi):
            out["country"] = country
            break
    return out


def model_year_candidates(vin: str, current_year: int) -> list[int]:
    """Model years encoded at position 10 (30-year cycle), newest first, capped at current_year + 1. For North
    American WMIs position 7 (digit -> 1980-2009, letter -> 2010-2039) picks the cycle; elsewhere position 10
    is optional in ISO 3779, so the result is only a hint (c2)."""
    if not is_vin_syntax(vin) or vin[9] not in _YEAR_CODES:
        return []
    base = 1980 + _YEAR_CODES.index(vin[9])
    years = [y for y in (base, base + 30) if y <= current_year + 1]
    if is_north_american_wmi(vin) and len(years) == 2:
        years = [base] if vin[6].isdigit() else [base + 30]
    return sorted(years, reverse=True)


def wmi_row(table: Any, vin: str) -> dict[str, Any]:
    """Bundled-table row of a VIN's WMI ({} when absent or the table is unusable)."""
    rows = table.get("table") if isinstance(table, dict) else None
    row = rows.get(vin[:3]) if isinstance(rows, dict) else None
    return row if isinstance(row, dict) else {}


def vin_offline_decode(vin: str, table: Any, current_year: int) -> dict[str, Any]:
    """Offline-first decode (c2): WMI -> manufacturer/make (bundled table) and country (ISO 3780); check digit
    enforced only for North American WMIs, otherwise a mismatch is a note, never 'invalid'. The result never
    holds the full VIN (the serial, positions 12-17, identifies one vehicle)."""
    if not is_vin_syntax(vin):
        return {"validity": "not_a_vin", "notes": ["not 17 characters of the VIN alphabet (I, O and Q are not allowed)"]}
    wmi = vin[:3]
    row = wmi_row(table, vin)
    geo = iso3780_country(vin)
    expected = vin_check_digit(vin)
    enforced = is_north_american_wmi(vin)
    matches = expected == vin[8]
    notes: list[str] = []
    note = None
    if not matches and enforced:
        note = f"check digit {vin[8]!r} does not match {expected!r} (mandatory for North American VINs)"
    elif not matches:
        note = (f"check digit {vin[8]!r} does not match the North American algorithm ({expected!r}); "
                "not required for this WMI region")
    if note:
        notes.append(note)
    small = wmi[2] == "9"
    if small:
        notes.append("small-manufacturer WMI (third character 9): positions 12-14 identify the maker")
    if not row:
        notes.append("WMI not in the bundled table")
    elif row.get("source") == "curated":
        notes.append("WMI not listed by NHTSA vPIC: make from the curated Brazilian rows (unverified against NHTSA)")
    types = row.get("vehicle_types")
    return {
        "wmi": {k: v for k, v in {
            "wmi": wmi, "manufacturer": _str(row.get("manufacturer")), "make": _str(row.get("make")),
            "vehicle_types": [t for t in types if isinstance(t, str)][:6] if isinstance(types, list) else None,
            "source": _str(row.get("source")), "small_manufacturer": small or None,
        }.items() if v not in (None, [], "")},
        "country": geo["country"], "region": geo["region"],
        "model_year_candidates": model_year_candidates(vin, current_year),
        "plant_code": vin[10],
        "check_digit": {"expected": expected, "actual": vin[8], "matches": matches, "enforced": enforced, "note": note},
        "validity": "invalid" if (enforced and not matches) else "valid",
        "notes": notes,
    }


def _str(v: Any, limit: int = 200) -> str | None:
    if not isinstance(v, str):
        return None
    v = " ".join(v.split())
    return v[:limit] or None


_LABELLED_VIN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?P<label>v\.?i\.?n\.?|chass[iy]s?|n[ºo°.]?\s{0,3}(?:do|de)\s{1,3}chassi|n[uú]mero\s{1,3}(?:do|de)\s{1,3}chassi)"
    r"(?:\s{0,3}(?:n[ºo°]\.?|no\.|nr\.?|number|n[uú]mero))?"
    r"\s{0,3}[:=#\-–]?\s{0,3}"
    r"(?P<value>[A-Za-z0-9]{17})(?![A-Za-z0-9])",
    re.IGNORECASE)


def detect_labelled_vins(text: Any, limit: int = 20) -> list[dict[str, Any]]:
    """VINs in free text (c1): only a 17-character value right after a 'VIN'/'chassi' label, without I/O/Q and
    with at least one digit and one letter. A bare 17-character token is never typed as a VIN (collisions with
    other identifiers). Returns [{'vin', 'label', 'start', 'end'}] (value upper-cased), at most ``limit``."""
    if not isinstance(text, str):
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for m in _LABELLED_VIN_RE.finditer(text[:200_000]):
        v = m.group("value").upper()
        if not is_vin_syntax(v) or not re.search(r"\d", v) or not re.search(r"[A-Z]", v) or v in seen:
            continue
        seen.add(v)
        out.append({"vin": v, "label": m.group("label"), "start": m.start("value"), "end": m.end("value")})
        if len(out) >= limit:
            break
    return out


# ======================================================================================================
# [P320 vPIC] (prep parsers.py)
# ======================================================================================================

def vpic_decode_url(vin: str) -> str:
    """Single-VIN vPIC URL (DecodeVinValues, flat format, JSON) for a validated VIN (c3)."""
    if not is_vin_syntax(vin):
        raise ValueError("only a validated 17-character VIN is sent to vPIC")
    return f"{VPIC_BASE}/DecodeVinValues/{vin}?format=json"


def vpic_batch_forms(vins: Any, model_years: dict[str, int] | None = None) -> list[dict[str, str]]:
    """Form bodies for POST {VPIC_BASE}/DecodeVINValuesBatch/ in chunks of at most 50 VINs (c3; kept for the
    engine's grouped inputs): DATA='vin[,year];vin[,year]...', format='json'. Only valid VINs are sent."""
    years = model_years or {}
    ok = [v for v in dict.fromkeys(vins or []) if is_vin_syntax(v)]
    forms = []
    for i in range(0, len(ok), VPIC_BATCH_MAX):
        chunk = ok[i:i + VPIC_BATCH_MAX]
        parts = [f"{v},{int(years[v])}" if years.get(v) else v for v in chunk]
        forms.append({"DATA": ";".join(parts), "format": "json"})
    return forms


_VPIC_FIELDS = {
    "make": "Make", "model": "Model", "model_year": "ModelYear", "manufacturer": "Manufacturer",
    "vehicle_type": "VehicleType", "body_class": "BodyClass", "trim": "Trim", "series": "Series",
    "doors": "Doors", "drive_type": "DriveType", "gvwr": "GVWR", "fuel_primary": "FuelTypePrimary",
    "plant_city": "PlantCity", "plant_state": "PlantState", "plant_country": "PlantCountry",
    "plant_company": "PlantCompanyName", "vehicle_descriptor": "VehicleDescriptor",
}
_VPIC_ENGINE = {"cylinders": "EngineCylinders", "displacement_l": "DisplacementL", "hp": "EngineHP",
                "configuration": "EngineConfiguration", "model": "EngineModel"}
_EMPTY = ("", "Not Applicable", "null")
#: vPIC ErrorCode flags (seen live 2026-11-26 or in the research sample); anything else is 'code_<n>'.
VPIC_CODE_FLAGS = {0: "clean", 1: "check_digit", 6: "incomplete", 7: "not_registered_us", 8: "no_detailed_data",
                   11: "model_year_mismatch"}


def _clean(v: Any) -> str | None:
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return str(v)
    if not isinstance(v, str):
        return None
    v = " ".join(v.split())[:200]
    return None if v in _EMPTY else v


def parse_vpic_error_codes(rec: Any) -> tuple[list[int], list[dict[str, Any]]]:
    """ErrorCode '6,7,11' + ErrorText '6 - ...; 7 - ...' -> ([6, 7, 11], [{'code', 'text', 'flag'}]): vPIC's
    error-in-200 markers (c3)."""
    if not isinstance(rec, dict):
        return [], []
    codes: list[int] = []
    for part in str(rec.get("ErrorCode") or "").split(",")[:20]:
        part = part.strip()
        if part.isdigit() and len(part) <= 4:
            codes.append(int(part))
    texts: dict[int, str] = {}
    for chunk in re.split(r";\s*(?=\d{1,4}\s+-\s)", str(rec.get("ErrorText") or "")[:4000]):
        m = re.match(r"\s*(\d{1,4})\s+-\s+(.*)", chunk, re.S)
        if m:
            texts[int(m.group(1))] = " ".join(m.group(2).split())[:300]
    errors = [{"code": c, "text": texts.get(c), "flag": VPIC_CODE_FLAGS.get(c, f"code_{c}")} for c in codes]
    return codes, errors


def vpic_result(rec: Any) -> dict[str, Any] | None:
    """One vPIC DecodeVinValues/Batch record -> normalised facts labelled US-centric (c3). 'vin_query' is the VIN
    vPIC echoed (used only to match batch records; never stored unmasked)."""
    if not isinstance(rec, dict):
        return None
    out: dict[str, Any] = {k: _clean(rec.get(src)) for k, src in _VPIC_FIELDS.items()}
    out["vin_query"] = _clean(rec.get("VIN"))
    engine = {k: _clean(rec.get(src)) for k, src in _VPIC_ENGINE.items()}
    out["engine"] = {k: v for k, v in engine.items() if v is not None}
    codes, errors = parse_vpic_error_codes(rec)
    flags = {e["flag"] for e in errors}
    out.update({
        "error_codes": codes, "errors": errors, "clean": codes == [0],
        "check_digit_failed": "check_digit" in flags, "incomplete": "incomplete" in flags,
        "not_registered_us": "not_registered_us" in flags, "no_detailed_data": "no_detailed_data" in flags,
        "has_vehicle_data": bool(out["make"] or out["model"] or out["manufacturer"]),
        "scope_label": VPIC_SCOPE_LABEL,
    })
    return out


def vpic_result_reason(norm: Any) -> str | None:
    """Per-VIN error-in-200 reason (c3): 'no_vehicle_data' when vPIC returned nothing usable, else a note-level
    'not_registered_us' / 'no_detailed_data' / 'check_digit' / 'incomplete', or None for a clean decode."""
    if not isinstance(norm, dict):
        return "unexpected_shape"
    if not norm.get("has_vehicle_data"):
        return "no_vehicle_data"
    for flag in ("not_registered_us", "no_detailed_data", "check_digit_failed", "incomplete"):
        if norm.get(flag):
            return flag.replace("_failed", "")
    return None


def parse_vpic_decode(obj: Any) -> dict[str, Any]:
    """DecodeVinValues / DecodeVINValuesBatch JSON -> {'ok', 'reason', 'count', 'results'} (c3). reason: None |
    'unexpected_shape' | 'no_results'. Results keep the request order (batch)."""
    base: dict[str, Any] = {"ok": False, "reason": None, "count": 0, "results": []}
    if not isinstance(obj, dict) or not isinstance(obj.get("Results"), list):
        return {**base, "reason": "unexpected_shape"}
    raw = obj["Results"][:VPIC_BATCH_MAX]
    if raw and not any(isinstance(x, dict) and ("ErrorCode" in x or "VIN" in x) for x in raw):
        return {**base, "reason": "unexpected_shape"}
    results = [r for r in (vpic_result(x) for x in raw) if r]
    count = obj.get("Count")
    base.update({"count": count if isinstance(count, int) and not isinstance(count, bool) else len(results),
                 "results": results})
    if not results:
        return {**base, "reason": "no_results"}
    return {**base, "ok": True}


def pick_vpic_record(parsed: dict[str, Any], vin: str) -> dict[str, Any] | None:
    """The record for ``vin``: matched by the echoed VIN, else the first record (single decode)."""
    results = parsed.get("results") or []
    for r in results:
        if r.get("vin_query") == vin:
            return r
    return results[0] if len(results) == 1 else None


# Table builders (release/data-update time; see docs/backlog/p3-G12-2.md): vPIC DecodeWMI and
# GetWMIsForManufacturer answers -> bundled rows. Country is never copied from vPIC (c2).

def parse_vpic_decode_wmi(obj: Any) -> dict[str, Any] | None:
    """DecodeWMI/{wmi} -> {'manufacturer', 'make', 'vehicle_type'} (None when vPIC does not list the WMI)."""
    if not isinstance(obj, dict) or not isinstance(obj.get("Results"), list) or not obj["Results"]:
        return None
    r = obj["Results"][0] if isinstance(obj["Results"][0], dict) else {}
    out = {"manufacturer": _clean(r.get("ManufacturerName")), "make": _clean(r.get("Make")),
           "vehicle_type": _clean(r.get("VehicleType"))}
    return out if out["manufacturer"] or out["make"] else None


def parse_vpic_wmis_for_manufacturer(obj: Any) -> list[dict[str, Any]]:
    """GetWMIsForManufacturer -> [{'wmi', 'name', 'vehicle_type', 'vpic_country', 'country'}] where 'country'
    is recomputed from ISO 3780 (vPIC's Country is the registrant's, e.g. 9BW = MEXICO)."""
    if not isinstance(obj, dict) or not isinstance(obj.get("Results"), list):
        return []
    rows = []
    for r in obj["Results"]:
        if not isinstance(r, dict):
            continue
        wmi = (_clean(r.get("WMI")) or "").upper()
        if not re.fullmatch(r"[A-HJ-NPR-Z0-9]{3}", wmi):
            continue
        rows.append({"wmi": wmi, "name": _clean(r.get("Name")), "vehicle_type": _clean(r.get("VehicleType")),
                     "vpic_country": _clean(r.get("Country")), "country": iso3780_country(wmi)["country"]})
    return rows


# ======================================================================================================
# The module
# ======================================================================================================

#: per-source failures of the online step: the offline facts stand, vPIC is 'could not verify' (rule 5);
#: the run deadline, the request cap, cancellation and --offline always propagate.
_VPIC_FAILURES = (RateLimited, Blocked, QuotaExceeded, AuthRequired, HttpError, NetworkError)


def failure_status(exc: BaseException) -> tuple[Status, str]:
    """(status, canonical reason code) of a vPIC failure, reported with ``res.source_status``."""
    if isinstance(exc, RateLimited):
        return Status.RATE_LIMITED, "rate_limited"
    if isinstance(exc, QuotaExceeded):
        return Status.QUOTA, "quota"
    if isinstance(exc, AuthRequired):
        return Status.BLOCKED, "challenge"  # keyless source: a 401/403 is a refusal, never 'needs a key'
    if isinstance(exc, Blocked):
        code = str(getattr(exc, "reason_code", "") or "challenge")
        return Status.BLOCKED, code if valid_reason(Status.BLOCKED, code) else "challenge"
    code = str(getattr(exc, "reason_code", "") or "error")
    return Status.ERROR, code if code in ("timeout", "error") else "error"


@register
class VinDecoder(Module):
    name = "vin_decoder"
    title = "VIN decoder (offline WMI/check digit + NHTSA vPIC)"
    description = (
        "Decodes a vehicle identification number offline (WMI manufacturer from a bundled NHTSA table, ISO 3780 "
        "country, model-year code, check digit enforced only for North American VINs), then asks NHTSA vPIC for "
        "make, model, year, body and engine (US-market data). Never looks up owners, plates or registrations."
    )
    category = "utility"
    accepts = {T.VIN, T.KEYWORD}
    produces = {T.VIN}
    reference = "https://vpic.nhtsa.dot.gov/api/"
    notice = (
        "Opt-in (P320). The VIN is sent to NHTSA vPIC, a US-centric database: vehicles sold only outside the US "
        "(many Brazilian chassis numbers) may be missing or attributed to the US importer, and Brazilian VINs need "
        "not satisfy the North American check digit. VINs are personal data (A8): the module runs only when selected "
        "in a case with a recorded purpose, exports mask the serial, and owner, plate or registration lookups are "
        "never made."
    )
    # ---- contract v2 declarations ---------------------------------------------------------------
    terms = "open"  # US government work (public domain)
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # NHTSA receives the VIN
    provider = "nhtsa"
    sources = (SRC_VPIC, SRC_WMI)
    hosts = ("vpic.nhtsa.dot.gov",)
    access_model = "free_noauth_limited"
    max_requests = 1  # one DecodeVinValues per VIN (batching waits for grouped engine inputs, c3)
    expected_latency = 0.5
    timeout = 20.0
    min_interval = 1.0
    daily_quota = 500  # self-imposed: vPIC publishes a rate-control mechanism but no numbers
    cache_ttl = 30 * 86400  # a decode is static per VIN; the vPIC dataset changes monthly
    max_pivots = MAX_LABELLED
    default_enabled = False  # council P320: opt-in online step

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.VIN:
            return is_vin_syntax(entity.value)
        return bool(detect_labelled_vins(entity.value, limit=1))  # c1: a labelled value only, never a bare token

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        table = self._table(ctx)
        year = ctx.now().year
        if entity.type is T.KEYWORD:
            return self._run_keyword(entity, ctx, res, table, year)
        vin = entity.value
        off = vin_offline_decode(vin, table, year)
        if off.get("validity") == "not_a_vin":
            return res.mark(Status.SKIPPED, "not a 17-character VIN (I, O and Q are never used)", reason_code="not_applicable")
        self._emit_offline(res, off)
        online = self._online(vin, ctx, res)
        self._summary(res, off, online)
        res.raw = {"offline": {k: off[k] for k in ("wmi", "country", "region", "model_year_candidates", "plant_code",
                                                   "check_digit", "validity", "notes")},
                   "vpic": online.get("raw"), "vin_masked": mask_vin(vin)}
        return res

    # ---- offline ---------------------------------------------------------------------------------
    @staticmethod
    def _table(ctx: Any) -> Any:
        try:
            return ctx.data.bundled_json(WMI_TABLE)
        except (OSError, ValueError):
            return None  # the decode still gives country, region, year and check digit

    @staticmethod
    def _emit_offline(res: ModuleResult, off: dict[str, Any]) -> None:
        res.attr("vin_wmi", off["wmi"])
        res.attr("vin_country", off["country"])
        res.attr("vin_check_digit", off["check_digit"])
        res.attr("vin_validity", off["validity"])
        res.attr("vin_model_years", off["model_year_candidates"])
        cd = off["check_digit"]
        if cd["enforced"] and not cd["matches"]:
            res.finding(
                "VIN check digit mismatch (North American VIN)",
                "low",
                f"Position 9 is {cd['actual']!r} but the check-digit algorithm gives {cd['expected']!r}. Mandatory for "
                "North American WMIs: a typo, an altered or cloned VIN, or a record to verify against the vehicle.",
                confidence="possible",
                criterion="49 CFR 565 check digit (position 9) recomputed offline; enforced only for WMIs 1-5 (P320 c2)",
                tags=["vin_check_digit_mismatch"],
                source=SRC_WMI,
                data={"expected": cd["expected"], "actual": cd["actual"], "wmi": off["wmi"].get("wmi")},
            )

    # ---- online (c3) -----------------------------------------------------------------------------
    def _online(self, vin: str, ctx: Any, res: ModuleResult) -> dict[str, Any]:
        if SRC_VPIC not in ctx.allowed_sources:
            return {"state": "not_run"}
        try:
            data = ctx.http.get_json(vpic_decode_url(vin), source=SRC_VPIC)
        except ValueError:
            return self._could_not_verify(res, Status.ERROR, "error", "vPIC answer is not JSON (could not verify)")
        except _VPIC_FAILURES as exc:
            status, code = failure_status(exc)
            return self._could_not_verify(res, status, code, f"vPIC could not verify: {str(exc)[:160]}")
        parsed = parse_vpic_decode(data)
        if not parsed["ok"]:
            return self._could_not_verify(res, Status.ERROR, "error",
                                          f"unexpected vPIC answer ({parsed['reason']}): could not verify")
        rec = pick_vpic_record(parsed, vin)
        if rec is None:
            return self._could_not_verify(res, Status.ERROR, "error", "vPIC answered for another VIN: could not verify")
        reason = vpic_result_reason(rec)
        meta = {"error_codes": rec["error_codes"], "errors": rec["errors"], "reason": reason, "scope": VPIC_SCOPE_LABEL,
                "vehicle_descriptor": rec.get("vehicle_descriptor")}
        raw = {**meta, **{k: rec.get(k) for k in ("make", "model", "model_year", "manufacturer", "vehicle_type")}}
        res.attr("vpic_result", meta)
        if reason == "no_vehicle_data":
            res.source_status(SRC_VPIC, Status.EMPTY, reason="vPIC has no vehicle data for this VIN (" + _codes_text(rec) + ")")
            return {"state": "no_data", "rec": rec, "raw": raw}
        res.attr("vehicle_make", rec.get("make"))
        res.attr("vehicle_model", rec.get("model"))
        res.attr("vehicle_model_year", rec.get("model_year"))
        details = {k: rec.get(k) for k in ("manufacturer", "vehicle_type", "body_class", "trim", "series", "doors",
                                            "drive_type", "fuel_primary", "gvwr")}
        plant = {k[6:]: rec.get(k) for k in ("plant_city", "plant_state", "plant_country", "plant_company") if rec.get(k)}
        details = {k: v for k, v in {**details, "plant": plant, "engine": rec.get("engine")}.items() if v}
        res.attr("vehicle_details", details)
        return {"state": "ok", "rec": rec, "raw": raw}

    @staticmethod
    def _could_not_verify(res: ModuleResult, status: Status, code: str, reason: str) -> dict[str, Any]:
        res.source_status(SRC_VPIC, status, reason_code=code, reason=reason)
        res.error = reason  # rule 5: could not verify, never 'no vehicle data'
        return {"state": "failed", "status": status.value, "reason": reason, "raw": {"failed": reason}}

    # ---- summary ---------------------------------------------------------------------------------
    @staticmethod
    def _summary(res: ModuleResult, off: dict[str, Any], online: dict[str, Any]) -> None:
        w = off["wmi"]
        who = w.get("make") or w.get("manufacturer") or "unknown manufacturer"
        if w.get("source") == "nhtsa_vpic" and w.get("manufacturer") and w.get("make"):
            who = f"{w['make']} (NHTSA registrant {w['manufacturer']})"
        where = off["country"] or off["region"] or "unknown country"
        years = "/".join(str(y) for y in off["model_year_candidates"]) or "unknown"
        cd = off["check_digit"]
        if cd["matches"]:
            check = "check digit ok"
        elif cd["enforced"]:
            check = "check digit MISMATCH (North American VIN)"
        else:
            check = "check digit not required for this region (mismatch noted)"
        parts = [f"WMI {w.get('wmi')}: {who}, {where}", f"model year {years}", check]
        state = online.get("state")
        rec = online.get("rec") or {}
        if state == "ok":
            vehicle = " ".join(str(x) for x in (rec.get("model_year"), rec.get("make"), rec.get("model")) if x)
            extra = {"not_registered_us": "manufacturer not registered with NHTSA for the US",
                     "no_detailed_data": "no detailed data", "incomplete": "incomplete decode",
                     "check_digit": "vPIC flags the check digit"}.get(vpic_result_reason(rec) or "")
            parts.append(f"vPIC: {vehicle or 'partial decode'}" + (f" ({extra})" if extra else "") + " [US-market data]")
        elif state == "no_data":
            parts.append("vPIC: no vehicle data (US-market database)")
        elif state == "failed":
            parts.append("vPIC: could not verify")
        summary = "; ".join(parts)
        res.attr("vin_summary", summary)
        data = {"wmi": w.get("wmi"), "country": off["country"], "validity": off["validity"], "vpic": state}
        res.finding("VIN decoded", "info", summary + ". " + VPIC_SCOPE_LABEL + ".", tags=["info"], data=data,
                    source=SRC_VPIC if state == "ok" else SRC_WMI)

    # ---- keyword input with a VIN/chassi label (c1) ----------------------------------------------
    def _run_keyword(self, entity: Entity, ctx: Any, res: ModuleResult, table: Any, year: int) -> ModuleResult:
        found = detect_labelled_vins(entity.value, limit=MAX_LABELLED)
        if not found:
            return res.mark(Status.SKIPPED, "no VIN next to a VIN/chassi label (bare 17-character tokens are never VINs)",
                            reason_code="not_applicable")
        rows = []
        for f in found:
            off = vin_offline_decode(f["vin"], table, year)
            rows.append({"vin_masked": mask_vin(f["vin"]), "label": f["label"], "wmi": off["wmi"].get("wmi"),
                         "country": off["country"], "make": off["wmi"].get("make") or off["wmi"].get("manufacturer"),
                         "validity": off["validity"]})
            expand = bool(ctx.is_seed)
            note = ("VIN typed by the analyst next to a VIN/chassi label" if expand else
                    "personal identifier (VIN) found next to a label: analyst selection required")
            res.pivot(T.VIN, f["vin"], "mentions", confidence="confirmed", expand=expand, note=note)
        res.attr("vin_labelled", rows)
        res.raw = {"labelled": rows}
        return res


def _codes_text(rec: dict[str, Any]) -> str:
    errs = rec.get("errors") or []
    return "; ".join(f"{e['code']} {e.get('text') or e['flag']}"[:120] for e in errs[:4]) or "no error code"
