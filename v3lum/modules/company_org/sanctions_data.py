"""Offline parsers of the sanctions lists used by ``sanctions_lists`` (P219): OFAC SDN exports, the UN
consolidated XML and the EU Financial Sanctions Files CSV, plus the safe XML helper.

Helper library (no Module class). Standard library plus the stdlib-only core validators. No network,
no file writes: parsers take bytes/str (or a path for the 25 MB EU file, read as a stream) and return
data; every parser is defensive (HTML or storage error pages instead of the list, cut downloads,
wrong shapes) and reports problems as data.

* safe XML (P219 cond 5): :func:`safe_xml_parse` refuses DOCTYPE/ENTITY/ELEMENT/ATTLIST/NOTATION
  declarations before parsing and through expat handlers, accepts UTF-8 only and caps bytes, depth
  and element count. Stand-in for the core safe XML helper every XML parser should share (core
  request of batch p1-G10-1).
* OFAC (cond 1, 5, 7): SDN.CSV (no header, 12 columns, '-0-' = null, 0x1A trailer); remarks cut at
  1000 characters are completed from SDN_COMMENTS.CSV by direct concatenation, and the last clause of
  a still-cut remark is never indexed; 'Digital Currency Address - <CHAIN> <address>' remarks are
  indexed per chain; Brazilian 11-digit Tax IDs (CPFs) are dropped (rule 4).
* wallets (cond 7): exact matching of normalised addresses: base58 and bech32 as-is (an all-upper-case
  bech32 QR form folds to lower case, BIP-173), EVM lower-cased, TRON hex 41... -> base58check.
* UN (cond 5): CONSOLIDATED_LIST/INDIVIDUALS|ENTITIES through the safe XML helper.
* EU FSF (cond 5): ';'-separated CSV 1.1 with a UTF-8 BOM, one sub-record per row grouped by
  Entity_LogicalId, read as a stream.
"""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
import re
import xml.parsers.expat
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from v3lum.core import validators as _val

# =============================================================================================
# A. text helpers and error documents
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
            if exc.start >= len(data) - 4:  # cut inside a multi-byte character
                return data.decode("utf-8-sig", errors="replace")
            if data.startswith(b"\xef\xbb\xbf"):
                data = data[3:]
            return data.decode("cp1252", errors="replace")
    if isinstance(raw, str):
        return raw[1:] if raw.startswith("﻿") else raw
    return str(raw)


def looks_like_html(text: str) -> bool:
    head = (text or "")[:4096].lstrip().lower()
    return head.startswith(("<!doctype html", "<html", "<head", "<body")) or (head.startswith("<!--") and "<html" in head)


_XML_CODE = re.compile(r"<Code>\s*([A-Za-z0-9.]+)\s*</Code>")
_XML_MSG = re.compile(r"<Message>\s*(.*?)\s*</Message>", re.S)


def cloud_storage_error_reason(body: Any) -> str | None:
    """S3 / Azure Blob error documents (OFAC SLS redirects to pre-signed S3 URLs, the UN list to Azure
    SAS URLs, both valid about 1 h): a short reason, or None."""
    text = to_text(body)[:8192]
    if "<Error>" not in text or "<Code>" not in text:
        return None
    code_m = _XML_CODE.search(text)
    code = code_m.group(1) if code_m else "unknown"
    msg_m = _XML_MSG.search(text)
    msg = (msg_m.group(1).splitlines()[0].strip() if msg_m and msg_m.group(1).strip() else "")[:120]
    if code in ("AccessDenied", "ExpiredToken") and ("expired" in msg.lower() or code == "ExpiredToken"):
        return "download link expired (pre-signed storage URL past its validity): request the export again"
    if code in ("AuthenticationFailed", "AuthorizationFailure"):
        return "storage refused the signed download link (SAS expired or invalid): request the list again"
    if code in ("NoSuchKey", "BlobNotFound", "ResourceNotFound", "NoSuchBucket"):
        return f"published file not found in storage ({code})"
    return f"storage error {code}{': ' + msg if msg else ''}"


def _body_problem(text: str, what: str) -> str | None:
    stripped = text.strip()
    if not stripped or stripped == "\x1a":
        return f"{what} body is empty"
    if looks_like_html(text):
        return f"HTML page instead of {what}"
    storage = cloud_storage_error_reason(text)
    if storage:
        return storage
    return None


# =============================================================================================
# B. safe XML helper (P219 cond 5)
# =============================================================================================


class XMLRefused(ValueError):
    """DOCTYPE/ENTITY/DTD content or a non UTF-8 document was refused."""


class XMLLimitExceeded(ValueError):
    """Size, depth or element-count cap exceeded."""


class XMLMalformed(ValueError):
    """Not well-formed XML (cut download, garbage, HTML...)."""


XML_MAX_BYTES = 32 * 1024 * 1024
XML_MAX_DEPTH = 32
XML_MAX_ELEMENTS = 2_000_000
_DTD_RE = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY|ELEMENT|ATTLIST|NOTATION)", re.I)
_XML_DECL_ENC = re.compile(rb"^\s*<\?xml[^>]*?encoding\s*=\s*[\"']([A-Za-z0-9._-]+)[\"']", re.I)
_OK_XML_ENCODINGS = {b"utf-8", b"utf8", b"us-ascii", b"ascii"}


def safe_xml_parse(data: Any, *, max_bytes: int = XML_MAX_BYTES, max_depth: int = XML_MAX_DEPTH, max_elements: int = XML_MAX_ELEMENTS) -> ET.Element:
    """Parse UTF-8 XML into an ElementTree Element, refusing DTDs and enforcing caps (P219 cond 5).

    Raises XMLRefused, XMLLimitExceeded or XMLMalformed (ValueError subclasses). No external entity
    is ever resolved: declarations are refused before parsing and the expat DTD handlers raise.
    """
    if isinstance(data, str):
        raw = data.encode("utf-8")
    elif isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)
    else:
        raise XMLMalformed("XML input must be bytes or str")
    if len(raw) > max_bytes:
        raise XMLLimitExceeded(f"XML larger than {max_bytes} bytes")
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff") or b"\x00" in raw[:1024]:
        raise XMLRefused("only UTF-8 XML is accepted")
    enc = _XML_DECL_ENC.match(raw[:512])
    if enc and enc.group(1).lower().replace(b"_", b"-") not in _OK_XML_ENCODINGS:
        raise XMLRefused("only UTF-8 XML is accepted (declared " + enc.group(1).decode("ascii", "replace") + ")")
    if _DTD_RE.search(raw):
        raise XMLRefused("DOCTYPE/ENTITY declarations are refused")
    parser = xml.parsers.expat.ParserCreate("UTF-8")
    parser.SetParamEntityParsing(xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER)
    builder = ET.TreeBuilder()
    state = {"depth": 0, "count": 0}

    def _start(tag: str, attrs: dict[str, str]) -> None:
        state["depth"] += 1
        state["count"] += 1
        if state["depth"] > max_depth:
            raise XMLLimitExceeded(f"XML nested deeper than {max_depth}")
        if state["count"] > max_elements:
            raise XMLLimitExceeded(f"XML has more than {max_elements} elements")
        builder.start(tag, attrs)

    def _end(tag: str) -> None:
        state["depth"] -= 1
        builder.end(tag)

    def _refuse(*_args: Any) -> None:
        raise XMLRefused("DTD content refused")

    parser.StartElementHandler = _start
    parser.EndElementHandler = _end
    parser.CharacterDataHandler = builder.data
    parser.StartDoctypeDeclHandler = _refuse
    parser.EntityDeclHandler = _refuse
    parser.UnparsedEntityDeclHandler = _refuse
    parser.NotationDeclHandler = _refuse
    parser.ExternalEntityRefHandler = _refuse
    parser.buffer_text = True
    try:
        parser.Parse(raw, True)
    except xml.parsers.expat.ExpatError as exc:
        raise XMLMalformed(f"malformed XML: {exc}") from None
    return builder.close()


# =============================================================================================
# C. OFAC SDN (Sanctions List Service exports)
# =============================================================================================

OFAC_LIST = "OFAC SDN"
OFAC_REMARKS_LIMIT = 1000  # SDN.CSV cuts remarks here; the rest is in SDN_COMMENTS.CSV
OFAC_SDN_MIN_ROWS = 5000  # 19,629 rows in the list dated 2026-11-20
OFAC_ALT_MIN_ROWS = 1000
OFAC_ADD_MIN_ROWS = 1000
_TRAILER = "\x1a"


def _null(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if text in ("", "-0-") else text


def _csv_rows(text: str, delimiter: str = ",") -> list[list[str]]:
    """strict=True: an unterminated quote (download cut inside a field) raises csv.Error."""
    return list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True))


def split_ofac_programs(value: Any) -> list[str]:
    """'IRAN] [SDGT] [IRGC' -> ['IRAN', 'SDGT', 'IRGC']."""
    text = _null(value)
    if not text:
        return []
    return [p.strip(" []") for p in re.split(r"\]\s*\[", text) if p.strip(" []")]


def parse_ofac_sdn_csv(raw: Any) -> dict[str, Any]:
    """SDN.CSV -> {ok, entries, rows, bad_rows, trailer, error}; entry: {list, uid, name, kind (entity |
    individual | vessel | aircraft), programs, remarks, remarks_truncated}."""
    text = to_text(raw)
    out: dict[str, Any] = {"ok": False, "entries": [], "rows": 0, "bad_rows": 0, "trailer": False, "error": None}
    problem = _body_problem(text, "SDN.CSV")
    if problem:
        out["error"] = problem
        return out
    try:
        rows = _csv_rows(text)
    except csv.Error as exc:
        out["error"] = f"SDN.CSV is not valid CSV ({exc})"
        return out
    for row in rows:
        if not row:
            continue
        if len(row) == 1 and row[0].strip() in (_TRAILER, ""):
            out["trailer"] = out["trailer"] or row[0].strip() == _TRAILER
            continue
        if len(row) != 12 or not row[0].strip().isdigit():
            out["bad_rows"] += 1
            continue
        kind = (_null(row[2]) or "entity").lower()
        remarks = _null(row[11])
        out["entries"].append({
            "list": OFAC_LIST, "uid": int(row[0].strip()), "name": row[1].strip(), "kind": kind, "programs": split_ofac_programs(row[3]),
            "remarks": remarks, "remarks_truncated": bool(remarks) and len(row[11]) >= OFAC_REMARKS_LIMIT,
        })
    out["rows"] = len(out["entries"])
    out["ok"] = out["rows"] > 0
    if not out["ok"]:
        out["error"] = "no SDN rows found"
    return out


def parse_ofac_comments_csv(raw: Any) -> dict[str, Any]:
    """SDN_COMMENTS.CSV (ent_num, remarks spill-over) -> {ok, comments {uid: text}, rows, bad_rows, trailer, error}."""
    text = to_text(raw)
    out: dict[str, Any] = {"ok": False, "comments": {}, "rows": 0, "bad_rows": 0, "trailer": False, "error": None}
    problem = _body_problem(text, "SDN_COMMENTS.CSV")
    if problem:
        out["error"] = problem
        return out
    try:
        rows = _csv_rows(text)
    except csv.Error as exc:
        out["error"] = f"SDN_COMMENTS.CSV is not valid CSV ({exc})"
        return out
    for row in rows:
        if not row or (len(row) == 1 and row[0].strip() in (_TRAILER, "")):
            out["trailer"] = out["trailer"] or bool(row and row[0].strip() == _TRAILER)
            continue
        if len(row) != 2 or not row[0].strip().isdigit():
            out["bad_rows"] += 1
            continue
        uid = int(row[0].strip())
        out["comments"][uid] = out["comments"].get(uid, "") + row[1]
    out["rows"] = len(out["comments"])
    out["ok"] = True
    return out


def merge_ofac_remarks(entries: list[dict[str, Any]], comments: dict[int, str] | None) -> list[dict[str, Any]]:
    """Append SDN_COMMENTS continuations (direct concatenation, no separator: 'WHOIS HACKIN' + 'G TEAM')
    to cut remarks; remarks_truncated stays True only for a cut remark without continuation."""
    comments = comments or {}
    merged = []
    for entry in entries or []:
        item = dict(entry)
        extra = comments.get(item.get("uid"))
        if extra:
            item["remarks"] = (item.get("remarks") or "") + extra
            item["remarks_truncated"] = False
        merged.append(item)
    return merged


def parse_ofac_alt_csv(raw: Any) -> dict[str, Any]:
    """ALT.CSV: ent_num, alt_num, alt_type (aka/fka/nka), alt_name, alt_remarks -> {ok, aliases {uid: [..]}, rows, bad_rows, error}."""
    text = to_text(raw)
    out: dict[str, Any] = {"ok": False, "aliases": {}, "rows": 0, "bad_rows": 0, "error": None}
    problem = _body_problem(text, "ALT.CSV")
    if problem:
        out["error"] = problem
        return out
    try:
        rows = _csv_rows(text)
    except csv.Error as exc:
        out["error"] = f"ALT.CSV is not valid CSV ({exc})"
        return out
    for row in rows:
        if not row or (len(row) == 1 and row[0].strip() in (_TRAILER, "")):
            continue
        if len(row) != 5 or not row[0].strip().isdigit():
            out["bad_rows"] += 1
            continue
        name = _null(row[3])
        if not name:
            continue
        out["aliases"].setdefault(int(row[0].strip()), []).append({"type": (_null(row[2]) or "aka").lower(), "name": name})
        out["rows"] += 1
    out["ok"] = True
    return out


def parse_ofac_add_csv(raw: Any) -> dict[str, Any]:
    """ADD.CSV: ent_num, add_num, address, city/state/postal, country, remarks -> {ok, addresses {uid:
    [{city, country}]}, rows, bad_rows, error} (street lines are not kept: minimisation)."""
    text = to_text(raw)
    out: dict[str, Any] = {"ok": False, "addresses": {}, "rows": 0, "bad_rows": 0, "error": None}
    problem = _body_problem(text, "ADD.CSV")
    if problem:
        out["error"] = problem
        return out
    try:
        rows = _csv_rows(text)
    except csv.Error as exc:
        out["error"] = f"ADD.CSV is not valid CSV ({exc})"
        return out
    for row in rows:
        if not row or (len(row) == 1 and row[0].strip() in (_TRAILER, "")):
            continue
        if len(row) != 6 or not row[0].strip().isdigit():
            out["bad_rows"] += 1
            continue
        out["addresses"].setdefault(int(row[0].strip()), []).append({"city": _null(row[3]), "country": _null(row[4])})
        out["rows"] += 1
    out["ok"] = True
    return out


_REM_ALIAS = re.compile(r"^([afn])\.k\.a\.\s+'(.+)'$", re.I)
_REM_DCA = re.compile(r"^Digital Currency Address - ([A-Za-z0-9]+)\s+(\S+)$")
_REM_ID = re.compile(
    r"^(Passport|National ID No\.|Tax ID No\.|Registration Number|Company Number|Business Registration Number|"
    r"Unified Social Credit Code \(USCC\)|Registration ID|Commercial Registry Number|Business Number|Enterprise Number|"
    r"Identification Number|Cedula No\.|D\.N\.I\.|NIT #|RFC|C\.U\.R\.P\.|SSN|Personal ID Card|Residency Number)"
    r"\s+(\S+?)(?:\s+\(([^)]+)\))?(?:\s.*)?$"
)
_ID_KIND = {"passport": "passport", "national id no.": "national_id", "tax id no.": "tax_id"}
_REM_SIMPLE = (
    ("dob", re.compile(r"^DOB\s+(.+)$")),
    ("nationality", re.compile(r"^nationality\s+(.+)$", re.I)),
    ("citizen", re.compile(r"^citizen\s+(.+)$", re.I)),
    ("lei", re.compile(r"^Legal Entity Number\s+(\S+)")),
    ("imo", re.compile(r"^Vessel Registration Identification IMO\s+(\d{7})$")),
)


def parse_ofac_remarks(remarks: Any, *, truncated: bool = False) -> dict[str, Any]:
    """Split SDN remarks into facts: aliases [{type, name}], wallets [{chain, address, normalized,
    family, entity_type, valid_shape}], dob, nationality, citizen, documents (count only), tax_ids,
    registrations [{scheme, number, country}], cnpjs (valid 14-character Brazilian Tax IDs), lei, imo,
    listing_dates [{scope, date}], incomplete_tail. Brazilian 11-digit Tax IDs (CPFs) are dropped
    (rule 4). When ``truncated`` the last clause may be cut mid-value and is never indexed."""
    facts: dict[str, Any] = {"aliases": [], "wallets": [], "dob": [], "nationality": [], "citizen": [], "documents": 0, "registrations": [],
                             "cnpjs": [], "lei": [], "imo": [], "listing_dates": [], "incomplete_tail": None}
    if not remarks or not isinstance(remarks, str):
        return facts
    clauses = [c.strip() for c in remarks.split(";") if c.strip()]
    if truncated and clauses:
        facts["incomplete_tail"] = clauses.pop()
    for clause in clauses:
        c = re.sub(r"^alt\.\s+", "", clause).rstrip(".").strip()
        m = _REM_ALIAS.match(c)
        if m:
            facts["aliases"].append({"type": m.group(1).lower() + "ka", "name": m.group(2).strip()})
            continue
        m = _REM_DCA.match(c)
        if m:
            chain, addr = m.group(1).upper(), m.group(2).rstrip(".")
            facts["wallets"].append({"chain": chain, "address": addr, **normalize_wallet(addr, chain)})
            continue
        m = re.match(r"^Listing Date \(([^)]+)\):\s*(.+)$", c)
        if m:
            facts["listing_dates"].append({"scope": m.group(1), "date": m.group(2)})
            continue
        m = _REM_ID.match(c)
        if m:
            scheme, number, country = m.group(1), m.group(2).rstrip(".,"), (m.group(3) or None)
            kind = _ID_KIND.get(scheme.lower())
            if kind == "tax_id" and country and country.strip().lower() == "brazil":
                digits = re.sub(r"[^0-9A-Za-z]", "", number).upper()
                if len(digits) == 11 and digits.isdigit():
                    continue  # a CPF: never indexed or matched (rule 4)
                if _val.cnpj_valid(digits):
                    facts["cnpjs"].append(digits)
                continue
            if kind in ("passport", "national_id"):
                facts["documents"] += 1  # personal documents: counted as a second-identifier source only
            elif kind != "tax_id":
                facts["registrations"].append({"scheme": scheme, "number": number, "country": country})
            continue
        for key, rx in _REM_SIMPLE:
            m = rx.match(c)
            if m:
                facts[key].append(m.group(1).strip())
                break
    return facts


def validate_ofac_sdn(parsed: Any, *, min_rows: int | None = None) -> str | None:
    """P219 cond 3: format + minimum rows + the 0x1A trailer before the copy is replaced."""
    min_rows = OFAC_SDN_MIN_ROWS if min_rows is None else min_rows
    if not isinstance(parsed, dict) or not parsed.get("ok"):
        return (parsed or {}).get("error") if isinstance(parsed, dict) and parsed.get("error") else "SDN.CSV could not be parsed"
    if not parsed.get("trailer"):
        return "SDN.CSV lacks its end-of-file marker 0x1A (truncated download?)"
    if parsed.get("rows", 0) < min_rows:
        return f"SDN.CSV has {parsed.get('rows', 0)} rows (< {min_rows})"
    if parsed.get("bad_rows", 0) > max(5, parsed.get("rows", 0) // 1000):
        return f"SDN.CSV has {parsed['bad_rows']} rows with an unexpected shape"
    return None


def validate_ofac_side(parsed: Any, *, what: str, min_rows: int) -> str | None:
    """Validation of SDN_COMMENTS / ALT / ADD before replacement."""
    if not isinstance(parsed, dict) or not parsed.get("ok"):
        return (parsed or {}).get("error") if isinstance(parsed, dict) and parsed.get("error") else f"{what} could not be parsed"
    if parsed.get("rows", 0) < min_rows:
        return f"{what} has {parsed.get('rows', 0)} rows (< {min_rows})"
    if parsed.get("bad_rows", 0) > max(5, parsed.get("rows", 0) // 100):
        return f"{what} has {parsed['bad_rows']} rows with an unexpected shape"
    return None


# =============================================================================================
# D. crypto wallet normalisation (P219 cond 7)
# =============================================================================================

_B58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]+$")
_BECH32_RE = re.compile(r"^(bc|tb|ltc|tltc|bcrt|bnb)1[02-9ac-hj-np-z]{6,87}$")
_CASHADDR_RE = re.compile(r"^[qp][02-9ac-hj-np-z]{41}$")
_EVM_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_TRON_HEX_RE = re.compile(r"^(?:0x)?41[0-9a-fA-F]{40}$")
_EVM_CHAINS = {"ETH", "ETC", "BNB", "BSC", "ARB", "MATIC", "POL", "AVAX", "BASE", "OP", "USDT", "USDC"}


def normalize_wallet(address: Any, chain: str | None = None) -> dict[str, Any]:
    """Normalise a wallet for exact matching (P219 cond 7): EVM 0x addresses lower-cased; TRON hex
    (41...) -> base58check T-address; bech32/cashaddr all-upper folded to lower (BIP-173: the same
    address; mixed case is invalid and kept as-is so it never matches); base58 as-is (case-sensitive).
    Returns {normalized, family, entity_type, valid_shape}."""
    text = str(address if address is not None else "").strip()
    text = re.sub(r"^(?:bitcoin|ethereum|litecoin|tron|monero|bitcoincash):", "", text, flags=re.I)
    text = text.split("?")[0].strip().rstrip(".")
    ch = (chain or "").upper()
    if _EVM_RE.match(text):
        return {"normalized": text.lower(), "family": "evm", "entity_type": "eth_address", "valid_shape": True}
    if _TRON_HEX_RE.match(text):
        hexpart = text[2:] if text.lower().startswith("0x") else text
        return {"normalized": _val.base58check_encode(bytes.fromhex(hexpart)), "family": "tron", "entity_type": "other_crypto_address",
                "valid_shape": True}
    if text.startswith("T") and len(text) == 34 and _B58_RE.match(text):
        return {"normalized": text, "family": "tron", "entity_type": "other_crypto_address", "valid_shape": True}
    low = text.lower()
    if _BECH32_RE.match(low) and (text == low or text == text.upper()):
        etype = "btc_address" if low.startswith(("bc1", "tb1", "bcrt1")) else "other_crypto_address"
        return {"normalized": low, "family": "bech32", "entity_type": etype, "valid_shape": True}
    if _CASHADDR_RE.match(low) and (text == low or text == text.upper()) and ch in ("BCH", ""):
        return {"normalized": low, "family": "cashaddr", "entity_type": "other_crypto_address", "valid_shape": True}
    if _B58_RE.match(text) and 25 <= len(text) <= 110:
        if ch == "XMR" or (len(text) in (95, 106) and text[0] in "48"):
            return {"normalized": text, "family": "base58", "entity_type": "xmr_address", "valid_shape": True}
        etype = "btc_address" if ch in ("XBT", "BTC") or (not ch and text[0] in "13") else "other_crypto_address"
        return {"normalized": text, "family": "base58", "entity_type": etype, "valid_shape": True}
    etype = "eth_address" if ch in _EVM_CHAINS and text.lower().startswith("0x") else "other_crypto_address"
    return {"normalized": text, "family": "other", "entity_type": etype, "valid_shape": False}


# =============================================================================================
# E. UN consolidated list XML
# =============================================================================================

UN_LIST = "UN"
UN_MIN_ENTRIES = 300  # 1,008 entries on 2026-11-26 (733 individuals, 275 entities)
UN_XML_MAX_BYTES = 16 * 1024 * 1024


def _t(el: Any, tag: str) -> str | None:
    if el is None:
        return None
    found = el.find(tag)
    if found is None or found.text is None:
        return None
    text = found.text.strip()
    return text or None


def _values(el: Any, tag: str) -> list[str]:
    return [v.text.strip() for item in el.findall(tag) for v in item.findall("VALUE") if v.text and v.text.strip()]


def _children(el: Any, tag: str, fields: tuple[str, ...]) -> list[dict[str, Any]]:
    out = []
    for item in el.findall(tag):
        rec = {f.lower(): _t(item, f) for f in fields}
        if any(rec.values()):
            out.append(rec)
    return out


def _un_entry(el: Any, kind: str) -> dict[str, Any]:
    parts = [_t(el, t) for t in ("FIRST_NAME", "SECOND_NAME", "THIRD_NAME", "FOURTH_NAME")]
    alias_tag = "INDIVIDUAL_ALIAS" if kind == "individual" else "ENTITY_ALIAS"
    aliases = [{"name": _t(a, "ALIAS_NAME"), "quality": _t(a, "QUALITY")} for a in el.findall(alias_tag) if _t(a, "ALIAS_NAME")]
    dataid = _t(el, "DATAID")
    entry: dict[str, Any] = {
        "list": UN_LIST, "uid": "UN:" + (dataid or "?"), "dataid": dataid, "kind": kind, "name": " ".join(p for p in parts if p),
        "programs": [p for p in (_t(el, "UN_LIST_TYPE"),) if p], "reference_number": _t(el, "REFERENCE_NUMBER"), "listed_on": _t(el, "LISTED_ON"),
        "aliases": aliases,
    }
    if kind == "individual":
        entry["nationalities"] = _values(el, "NATIONALITY")
        entry["dates_of_birth"] = _children(el, "INDIVIDUAL_DATE_OF_BIRTH", ("TYPE_OF_DATE", "DATE", "YEAR", "FROM_YEAR", "TO_YEAR"))
        entry["documents"] = len(el.findall("INDIVIDUAL_DOCUMENT"))
        entry["countries"] = sorted({a["country"] for a in _children(el, "INDIVIDUAL_ADDRESS", ("CITY", "COUNTRY")) if a.get("country")})
    else:
        entry["countries"] = sorted({a["country"] for a in _children(el, "ENTITY_ADDRESS", ("CITY", "COUNTRY")) if a.get("country")})
    return entry


def parse_un_consolidated(raw: Any, *, max_bytes: int = UN_XML_MAX_BYTES) -> dict[str, Any]:
    """consolidated.xml through :func:`safe_xml_parse` -> {ok, date_generated, entries, individuals, entities, error}."""
    out: dict[str, Any] = {"ok": False, "date_generated": None, "entries": [], "individuals": 0, "entities": 0, "error": None}
    head = to_text(raw[:8192] if isinstance(raw, (bytes, bytearray, str)) else raw)
    if not head.strip():
        out["error"] = "UN list body is empty"
        return out
    if looks_like_html(head):
        out["error"] = "HTML page instead of the UN consolidated XML"
        return out
    storage = cloud_storage_error_reason(head)
    if storage:
        out["error"] = storage
        return out
    try:
        root = safe_xml_parse(raw, max_bytes=max_bytes)
    except XMLRefused as exc:
        out["error"] = f"refused: {exc}"
        return out
    except (XMLLimitExceeded, XMLMalformed) as exc:
        out["error"] = str(exc)
        return out
    if root.tag != "CONSOLIDATED_LIST":
        out["error"] = f"unexpected root element <{root.tag}>"
        return out
    out["date_generated"] = root.get("dateGenerated")
    for el in root.findall("INDIVIDUALS/INDIVIDUAL"):
        out["entries"].append(_un_entry(el, "individual"))
        out["individuals"] += 1
    for el in root.findall("ENTITIES/ENTITY"):
        out["entries"].append(_un_entry(el, "entity"))
        out["entities"] += 1
    out["ok"] = True
    return out


def validate_un(parsed: Any, *, min_entries: int | None = None) -> str | None:
    min_entries = UN_MIN_ENTRIES if min_entries is None else min_entries
    if not isinstance(parsed, dict) or not parsed.get("ok"):
        return (parsed or {}).get("error") if isinstance(parsed, dict) and parsed.get("error") else "UN list could not be parsed"
    n = len(parsed.get("entries") or [])
    if n < min_entries:
        return f"UN list has {n} entries (< {min_entries})"
    if not parsed.get("date_generated"):
        return "UN list has no dateGenerated attribute"
    return None


# =============================================================================================
# F. EU Financial Sanctions Files CSV 1.1 (';' + BOM)
# =============================================================================================

EU_LIST = "EU FSF"
#: Validation floor: calibrated at the first full download (5,000+ entities on 2026-11-26).
EU_MIN_ENTITIES = 1000
EU_FSF_REQUIRED = (
    "fileGenerationDate", "Entity_LogicalId", "Entity_EU_ReferenceNumber", "Entity_SubjectType", "Entity_Regulation_Programme",
    "Entity_DesignationDate", "Entity_Regulation_PublicationDate", "NameAlias_WholeName", "BirthDate_BirthDate", "Identification_Number",
    "Citizenship_CountryIso2Code", "Address_CountryIso2Code",
)


def _dmy(value: Any) -> str | None:
    text = str(value or "").strip()
    m = re.match(r"^(\d{2})/(\d{2})/(\d{4})$", text)
    return f"{m.group(3)}-{m.group(2)}-{m.group(1)}" if m else (text or None)


def eu_fsf_error_reason(status: Any = None, body: Any = None) -> str | None:
    """EU FSF refusals: the 403 JSON {status, error: Forbidden} without (or with a changed) public token."""
    text = to_text(body)[:4096]
    if text.lstrip().startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        if isinstance(data, dict) and (data.get("status") or data.get("error")):
            code = data.get("status") or status
            return f"EU FSF refused the download (HTTP {code} {data.get('error') or ''}".rstrip() + "): the Commission's public token may have changed"
    try:
        code = int(status) if status is not None else None
    except (TypeError, ValueError):
        code = None
    if code is not None and code >= 400:
        return f"EU FSF download failed (HTTP {code})"
    return None


def _eu_lines(source: Any) -> Iterator[str]:
    """Lines of the EU file from a path (streamed) or a body (bytes/str)."""
    if isinstance(source, Path):
        with open(source, encoding="utf-8-sig", errors="replace", newline="") as fh:
            yield from fh
        return
    yield from io.StringIO(to_text(source), newline="")


def _eu_head(source: Any) -> tuple[bool, str]:
    """(has BOM, first 4 KB as text)."""
    if isinstance(source, Path):
        with open(source, "rb") as fh:
            raw = fh.read(4096)
    elif isinstance(source, str):
        return source.startswith("﻿"), source[:4096]
    else:
        raw = bytes(source or b"")[:4096]
    return raw.startswith(b"\xef\xbb\xbf"), to_text(raw)


def parse_eu_fsf_csv(source: Any) -> dict[str, Any]:
    """EU FSF full CSV 1.1 (path or body) grouped by Entity_LogicalId into entries {list, uid,
    logical_id, eu_reference, un_id, kind (individual | entity), programs, designation_date,
    publication_date, name, aliases [{name, language}], birth_dates, citizenships, identifications
    (number, type_code, country), countries}. Returns {ok, bom, file_generation_date, entries, rows,
    bad_rows, truncated, missing_columns, error}."""
    bom, head = _eu_head(source)
    out: dict[str, Any] = {"ok": False, "bom": bom, "file_generation_date": None, "entries": [], "rows": 0, "bad_rows": 0, "truncated": False,
                           "missing_columns": [], "error": None}
    if not head.strip():
        out["error"] = "EU FSF body is empty"
        return out
    if head.lstrip()[:1] == "{":
        out["error"] = eu_fsf_error_reason(None, head) or "JSON instead of the EU FSF CSV"
        return out
    if looks_like_html(head):
        out["error"] = "HTML page instead of the EU FSF CSV"
        return out
    if ";" not in head.split("\n", 1)[0]:
        out["error"] = "not a ';'-separated EU FSF file"
        return out
    reader = csv.reader(_eu_lines(source), delimiter=";", strict=True)
    try:
        header = next(reader)
    except (StopIteration, csv.Error):
        out["error"] = "EU FSF header missing"
        return out
    header = [h.lstrip("﻿") for h in header]
    out["missing_columns"] = [c for c in EU_FSF_REQUIRED if c not in header]
    if out["missing_columns"]:
        out["error"] = "EU FSF header lacks " + ", ".join(out["missing_columns"][:5])
        return out
    ix = {name: i for i, name in enumerate(header)}
    width = len(header)
    entries: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    seen_names: dict[str, set[str]] = {}
    last_bad = False

    def g(row: list[str], col: str) -> str | None:
        i = ix.get(col)
        if i is None:
            return None
        value = row[i].strip()
        return value or None

    try:
        for row in reader:
            if not row or row == [""]:
                continue
            if len(row) != width:
                out["bad_rows"] += 1
                last_bad = True
                continue
            last_bad = False
            out["rows"] += 1
            lid = g(row, "Entity_LogicalId")
            if not lid:
                out["bad_rows"] += 1
                continue
            entry = entries.get(lid)
            if entry is None:
                if out["file_generation_date"] is None:
                    out["file_generation_date"] = _dmy(g(row, "fileGenerationDate"))
                subject = g(row, "Entity_SubjectType")
                programme = g(row, "Entity_Regulation_Programme")
                entry = {"list": EU_LIST, "uid": "EU:" + lid, "logical_id": lid, "eu_reference": g(row, "Entity_EU_ReferenceNumber"),
                         "un_id": g(row, "Entity_UnitedNationId"), "kind": "individual" if subject == "P" else "entity",
                         "programs": [programme] if programme else [], "designation_date": g(row, "Entity_DesignationDate"),
                         "publication_date": g(row, "Entity_Regulation_PublicationDate"), "names": [], "birth_dates": [],
                         "citizenships": [], "identifications": [], "countries": []}
                entries[lid] = entry
                order.append(lid)
                seen_names[lid] = set()
            whole = g(row, "NameAlias_WholeName")
            if whole:
                key = g(row, "NameAlias_LogicalId") or whole
                if key not in seen_names[lid]:
                    seen_names[lid].add(key)
                    entry["names"].append({"name": whole, "language": g(row, "NameAlias_NameLanguage")})
            bd = g(row, "BirthDate_BirthDate") or g(row, "BirthDate_Year")
            if bd:
                rec = {"date": g(row, "BirthDate_BirthDate"), "year": g(row, "BirthDate_Year"), "circa": g(row, "BirthDate_Circa")}
                if rec not in entry["birth_dates"]:
                    entry["birth_dates"].append(rec)
            num = g(row, "Identification_Number")
            if num:
                rec = {"number": num, "type_code": g(row, "Identification_TypeCode"), "country": g(row, "Identification_CountryIso2Code")}
                if rec not in entry["identifications"]:
                    entry["identifications"].append(rec)
            cit = g(row, "Citizenship_CountryIso2Code")
            if cit and cit not in entry["citizenships"]:
                entry["citizenships"].append(cit)
            country = g(row, "Address_CountryIso2Code")
            if country and country not in entry["countries"]:
                entry["countries"].append(country)
    except csv.Error as exc:
        out["error"] = f"EU FSF CSV error ({exc})"
        return out
    out["truncated"] = last_bad
    for lid in order:
        entry = entries[lid]
        names = entry.pop("names")
        primary = next((n for n in names if (n.get("language") or "EN") == "EN"), None) or (names[0] if names else None)
        entry["name"] = primary["name"] if primary else None
        entry["aliases"] = [{"name": n["name"], "language": n.get("language")} for n in names if n is not primary]
        out["entries"].append(entry)
    out["ok"] = bool(out["entries"])
    if not out["ok"]:
        out["error"] = "no EU FSF rows found"
    return out


def validate_eu_fsf(parsed: Any, *, min_entities: int | None = None) -> str | None:
    """P219 cond 3: format, BOM, complete last row, minimum entities."""
    min_entities = EU_MIN_ENTITIES if min_entities is None else min_entities
    if not isinstance(parsed, dict) or not parsed.get("ok"):
        return (parsed or {}).get("error") if isinstance(parsed, dict) and parsed.get("error") else "EU FSF could not be parsed"
    if parsed.get("truncated"):
        return "EU FSF CSV ends with an incomplete row (truncated download)"
    if not parsed.get("bom"):
        return "EU FSF CSV without the expected UTF-8 BOM"
    n = len(parsed.get("entries") or [])
    if n < min_entities:
        return f"EU FSF has {n} entities (< {min_entities})"
    return None


# =============================================================================================
# G. second identifiers, verdict wording, coverage, history
# =============================================================================================

ATTRIBUTION = {
    OFAC_LIST: "OFAC Specially Designated Nationals list, U.S. Department of the Treasury (public domain)",
    UN_LIST: "United Nations Security Council Consolidated List (UN public information)",
    EU_LIST: "EU Financial Sanctions Files, European Commission (EU open data, reuse with attribution: European Commission reuse notice)",
}
_MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), start=1)}


def normalize_dob(value: Any) -> dict[str, Any] | None:
    """OFAC '01 Jan 1970', 'Jan 1970', '1970', 'circa 1970', '1970 to 1972'; ISO '1970-01-01'; UN
    dicts {date, year, from_year, to_year}; EU dicts {date, year} -> {year_from, year_to, month, day, circa}."""
    if isinstance(value, dict):
        if value.get("date"):
            return normalize_dob(value["date"])
        if value.get("from_year") and value.get("to_year"):
            return normalize_dob(f"{value['from_year']} to {value['to_year']}")
        return normalize_dob(value.get("year"))
    text = str(value or "").strip().lower()
    if not text:
        return None
    circa = text.startswith("circa")
    text = text.replace("circa", "").strip()
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", text)
    if m:
        return {"year_from": int(m.group(1)), "year_to": int(m.group(1)), "month": int(m.group(2)), "day": int(m.group(3)), "circa": circa}
    m = re.fullmatch(r"(?:(\d{1,2}) )?([a-z]{3}) (\d{4})", text)
    if m and m.group(2) in _MONTHS:
        return {"year_from": int(m.group(3)), "year_to": int(m.group(3)), "month": _MONTHS[m.group(2)], "day": int(m.group(1)) if m.group(1) else None,
                "circa": circa}
    m = re.fullmatch(r"(\d{4})(?: to (\d{4}))?", text)
    if m:
        return {"year_from": int(m.group(1)), "year_to": int(m.group(2) or m.group(1)), "month": None, "day": None, "circa": circa}
    return None


def dob_matches(subject_dob: Any, listed_dobs: Any, *, circa_years: int = 1) -> bool:
    """True when the subject's date of birth is compatible with a listed one (P219 cond 8)."""
    subj = normalize_dob(subject_dob)
    if not subj:
        return False
    for listed in listed_dobs or ():
        cand = normalize_dob(listed)
        if not cand:
            continue
        lo = cand["year_from"] - (circa_years if cand["circa"] else 0)
        hi = cand["year_to"] + (circa_years if cand["circa"] else 0)
        if not lo <= subj["year_from"] <= hi:
            continue
        if cand["month"] and subj["month"] and cand["month"] != subj["month"]:
            continue
        if cand["day"] and subj["day"] and cand["day"] != subj["day"]:
            continue
        return True
    return False


def actor_designation_line(designations: Any) -> str | None:
    """P219 cond 11: '<lists> designated (<dates>) - payments may be prohibited, escalate to legal'."""
    items = [(str(lbl), d) for lbl, d in (designations or ()) if lbl]
    if not items:
        return None
    labels = "/".join(dict.fromkeys(lbl for lbl, _d in items))
    dates = ", ".join(dict.fromkeys(str(d) for _l, d in items if d))
    return f"{labels} designated ({dates or 'date not published'}) - payments may be prohibited, escalate to legal"


def delisted_entries(previous: Any, current: Any) -> list[dict[str, Any]]:
    """P219 cond 12: uids present in the previous list version and absent from the current one."""
    cur = {e.get("uid") for e in current or ()}
    return [{"uid": e.get("uid"), "name": e.get("name"), "list": e.get("list")} for e in previous or () if e.get("uid") not in cur]


def formerly_listed_line(previous_list_date: Any) -> str:
    """P219 cond 12 wording for a match found only in the previous list version."""
    return f"formerly listed ({previous_list_date or 'date unknown'})"


def as_date(value: Any) -> dt.date | None:
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
