"""PDF/Office document metadata and maldoc indicators (P269) - offline, disclosure 'none'.

Final conditions of P269 implemented here (see docs/backlog/p1-G12-1.md for the core pieces it waits for):

* c1 FILE input only: the module never fetches a URL. An analyst-typed URL gets SKIPPED 'opsec' with the
  manual pivot link (archived copy, ``file_triage:wayback_url``) until the shared LIGHT file fetcher
  exists (c2-c4: a core piece gated by the AR20 safety suite; backlog). URL pivots never run it.
* c5 the parsers are pure, bounded standard-library code: input cap 100 MB, every inflate capped (size,
  ratio, per-file read budget), the safe XML helper, a chain-loop-safe OLE reader, bounded regexes and
  the 1 MB evidence cap. The core sandbox (core/sandbox.py: python -I child, rlimits, wall timeout) does
  not exist yet, so pypdf and olefile - which need it (pypdf has had infinite-loop CVEs) - are not run in
  process: the PDF path is a pdfid-style raw scanner that also inflates object and metadata streams
  within caps; the OLE path is the bounded [MS-CFB] reader of file_type_sniff. Nothing is executed,
  rendered or decrypted.
* c6 formats: PDF Info dictionary (also inside object streams) and XMP, PDF dates D:YYYYMMDDHHmmSSOHH'mm'
  -> ISO; OOXML and ODF docProps through the safe ZIP reader (member/size/ratio caps) and the safe XML
  helper (DOCTYPE/ENTITY refused); OLE SummaryInformation/DocumentSummaryInformation and VBA presence;
  Outlook .msg through its __substg1.0_* streams (never the GPL extract-msg); RTF {\\info} and objects.
* c7 macros are decompressed ([MS-OVBA]) and scanned as text, never executed; oletools stays a future
  optional extra (backlog); encrypted files are reported, never decrypted with a guessed password.
* c8 external relationships (TargetMode=External, attachedTemplate, frame, oleObject, subDocument...),
  remote INCLUDE fields, UNC and WebDAV paths, mhtml/protocol-handler targets and external hyperlinks
  become url/domain/IP pivots (relations remote_template / external_hyperlink) for passive modules only;
  nothing resolves or fetches them (the module has no network: disclosure 'none').
* c9 severity table: remote template / auto-loaded external relationship = HIGH (T1221); auto-exec
  macro, XLM macro sheets and DDE fields = HIGH worded 'suspicious'; macro present = MEDIUM; PDF
  /Launch or /JavaScript run by /OpenAction or /AA = HIGH, /EmbeddedFile = MEDIUM; PDF URIs = url pivots.
* c10 author, last-modified-by and company are INFO attributes; author names become person_name pivots
  (relation document_author) and C:\\Users\\<name> paths username pivots (relation local_account),
  always expand=False with a privacy note (never auto-checked by person/username modules, A5).
* c11 :func:`redact_for_export` is the STIX/MISP view (paths, usernames and author names redacted unless
  --include-personal); one summary line per document (attribute ``document_summary``).
* c12 tests build the fixtures (tests/modules/test_document_metadata.py).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
import struct
import urllib.parse
import zlib
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.file_analysis.file_type_sniff import (
    EXECUTABLE_KINDS,
    LIMITS,
    SEVERITY_ORDER,
    ArchiveLimit,
    Budget,
    CFB,
    FileRefused,
    UnsafeXML,
    cap_json,
    clean_text,
    emit_findings,
    extension_findings,
    extract_iocs,
    fact,
    filetime_to_iso,
    guid_le,
    ip_loose,
    ole_subtype,
    read_capped,
    safe_xml_parse,
    sniff,
    sniff_path,
    u16,
    u32,
    u64,
    xml_local,
    xml_text,
    zip_read,
    zip_scan,
)

MANUAL_LINK = "file_triage:wayback_url"

# ======================================================================================== PDF

_PDF_DATE = re.compile(r"^\s{0,8}(?:D:)?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?\s{0,8}(?:([Zz+\-])\s{0,4}(\d{1,2})?'?\s{0,4}(\d{1,2})?'?)?")


def pdf_date_to_iso(value: Any) -> str | None:
    """c6: PDF date D:YYYYMMDDHHmmSSOHH'mm' (any suffix optional) -> ISO 8601; None when invalid."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    m = _PDF_DATE.match(str(value)[:64])
    if not m:
        return None
    y, mo, d, h, mi, s, sign, tzh, tzm = m.groups()
    try:
        dt = _dt.datetime(int(y), int(mo or 1), int(d or 1), int(h or 0), int(mi or 0), int(s or 0))
    except ValueError:
        return None
    if sign in ("Z", "z"):
        return dt.replace(tzinfo=_dt.timezone.utc).isoformat()
    if sign in ("+", "-"):
        try:
            off = _dt.timedelta(hours=int(tzh or 0), minutes=int(tzm or 0))
            if off >= _dt.timedelta(hours=24):
                return dt.isoformat()
            return dt.replace(tzinfo=_dt.timezone(off if sign == "+" else -off)).isoformat()
        except ValueError:
            return dt.isoformat()
    return dt.isoformat()


_PDFDOC = {0x18: "\u02d8", 0x19: "\u02c7", 0x1A: "\u02c6", 0x1B: "\u02d9", 0x1C: "\u02dd", 0x1D: "\u02db", 0x1E: "\u02da", 0x1F: "\u02dc",
           0x80: "\u2022", 0x81: "\u2020", 0x82: "\u2021", 0x83: "\u2026", 0x84: "\u2014", 0x85: "\u2013", 0x86: "\u0192", 0x87: "\u2044",
           0x88: "\u2039", 0x89: "\u203a", 0x8A: "\u2212", 0x8B: "\u2030", 0x8C: "\u201e", 0x8D: "\u201c", 0x8E: "\u201d", 0x8F: "\u2018",
           0x90: "\u2019", 0x91: "\u201a", 0x92: "\u2122", 0x93: "\ufb01", 0x94: "\ufb02", 0x95: "\u0141", 0x96: "\u0152", 0x97: "\u0160",
           0x98: "\u0178", 0x99: "\u017d", 0x9A: "\u0131", 0x9B: "\u0142", 0x9C: "\u0153", 0x9D: "\u0161", 0x9E: "\u017e", 0xA0: "\u20ac"}


def pdf_decode_text(raw: bytes) -> str:
    """PDF text string bytes -> str (UTF-16BE/UTF-8 BOM, else PDFDocEncoding)."""
    if raw[:2] == b"\xfe\xff":
        return raw[2:].decode("utf-16-be", "replace")
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", "replace")
    return "".join(_PDFDOC.get(b, chr(b)) for b in raw)


_LITERAL_ESC = {0x6E: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x66: 12, 0x28: 0x28, 0x29: 0x29, 0x5C: 0x5C}


def pdf_unescape_literal(raw: bytes) -> bytes:
    """Body of a PDF literal string (without the outer parentheses) -> bytes (escapes, octal, continuations)."""
    out = bytearray()
    i, n = 0, len(raw)
    while i < n:
        c = raw[i]
        if c != 0x5C:
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= n:
            break
        c = raw[i]
        if c in _LITERAL_ESC:
            out.append(_LITERAL_ESC[c])
            i += 1
        elif 0x30 <= c <= 0x37:
            j = i
            while j < n and j < i + 3 and 0x30 <= raw[j] <= 0x37:
                j += 1
            out.append(int(raw[i:j], 8) & 0xFF)
            i = j
        elif c == 0x0D:
            i += 2 if i + 1 < n and raw[i + 1] == 0x0A else 1
        elif c == 0x0A:
            i += 1
        else:
            out.append(c)
            i += 1
    return bytes(out)


def _pdf_literal_at(data: bytes, pos: int, limit: int = 8192) -> tuple[bytes | None, int]:
    """A balanced literal string starting at data[pos] == '(' -> (body, end) or (None, pos)."""
    if pos >= len(data) or data[pos] != 0x28:
        return None, pos
    depth, i, end = 0, pos, min(len(data), pos + limit)
    while i < end:
        c = data[i]
        if c == 0x5C:
            i += 2
            continue
        if c == 0x28:
            depth += 1
        elif c == 0x29:
            depth -= 1
            if depth == 0:
                return data[pos + 1:i], i + 1
        i += 1
    return None, pos


_WS = re.compile(rb"\s")


def pdf_string_value(data: bytes, pos: int) -> str | None:
    """Literal '(..)' or hex '<..>' string value at ``pos`` -> decoded text or None (bounded)."""
    end_ws = min(len(data), pos + 64)
    while pos < end_ws and data[pos] in b" \t\r\n\x0c\x00":
        pos += 1
    if pos < len(data) and data[pos] == 0x28:
        body, _ = _pdf_literal_at(data, pos)
        return pdf_decode_text(pdf_unescape_literal(body)) if body is not None else None
    if pos < len(data) and data[pos] == 0x3C and data[pos + 1:pos + 2] != b"<":
        end = data.find(b">", pos, pos + 16384)
        if end != -1:
            hx = _WS.sub(b"", data[pos + 1:end])
            if len(hx) % 2:
                hx += b"0"
            try:
                return pdf_decode_text(bytes.fromhex(hx.decode("ascii")))
            except ValueError:
                return None
    return None


PDF_KEYWORDS = ("/Page", "/Encrypt", "/ObjStm", "/JS", "/JavaScript", "/AA", "/OpenAction", "/AcroForm", "/JBIG2Decode", "/RichMedia",
                "/Launch", "/EmbeddedFile", "/EmbeddedFiles", "/XFA", "/URI", "/GoToR", "/GoToE", "/ImportData", "/Names", "/Sig",
                "/SubmitForm")  # v3lum-lint: allow LINT-05 -- a PDF keyword counted inside the analysed file (pdfid-style detection), never requested
_NAME_END = rb"(?=[\x00\x09\x0a\x0c\x0d\x20()<>\[\]{}/%]|$)"
_PDF_KW_RX = re.compile(rb"/(" + b"|".join(re.escape(k[1:].encode()) for k in sorted(PDF_KEYWORDS, key=len, reverse=True)) + rb")" + _NAME_END)
_PDF_HEXNAME_RX = re.compile(rb"/((?:[^\x00\x09\x0a\x0c\x0d\x20()<>\[\]{}/%#]|#[0-9A-Fa-f]{2}){1,127})" + _NAME_END)
_PDF_HEXESC = re.compile(rb"#([0-9A-Fa-f]{2})")
_PDF_TOKEN_RX = re.compile(rb"(?<![A-Za-z])(obj|endobj|stream|endstream|xref|trailer|startxref)(?![A-Za-z])")
_PDF_HEADER = re.compile(rb"%PDF-(\d\.\d)")


def pdf_keyword_counts(data: bytes) -> dict[str, Any]:
    """pdfid-style keyword counts (maldoc triage). Hex-escaped names (/J#61vaScript) are normalised and
    counted in 'obfuscated_names'. Linear regex passes at C speed."""
    counts = dict.fromkeys(PDF_KEYWORDS, 0)
    for raw in _PDF_KW_RX.findall(data):
        counts["/" + raw.decode("latin-1")] += 1
    obfuscated: dict[str, int] = {}
    if b"#" in data:
        for raw in _PDF_HEXNAME_RX.findall(data):
            if b"#" not in raw:
                continue
            name = "/" + _PDF_HEXESC.sub(lambda x: bytes([int(x.group(1), 16)]), raw).decode("latin-1")
            if name in counts:
                obfuscated[name] = obfuscated.get(name, 0) + 1
                counts[name] += 1
    tokens = dict.fromkeys(("obj", "endobj", "stream", "endstream", "xref", "trailer", "startxref"), 0)
    for tok in _PDF_TOKEN_RX.findall(data):
        tokens[tok.decode()] += 1
    m = _PDF_HEADER.search(data[:1024])
    return {"header": m.group(1).decode() if m else None, "keywords": counts, "obfuscated_names": obfuscated, "tokens": tokens,
            "eof_markers": data.count(b"%%EOF")}


def _merge_counts(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    out = json.loads(json.dumps(a))
    for k, v in b.get("keywords", {}).items():
        out["keywords"][k] = out["keywords"].get(k, 0) + v
    for k, v in b.get("obfuscated_names", {}).items():
        out["obfuscated_names"][k] = out["obfuscated_names"].get(k, 0) + v
    return out


_STREAM_KW = re.compile(rb"(?<![A-Za-z])stream(?:\r\n|\r|\n)")
_DICT_LENGTH = re.compile(rb"/Length\s{1,8}(\d{1,10})(?!\s{1,8}\d{1,10}\s{1,8}R)")
_OBJSTM_N = re.compile(rb"/N\s{1,8}(\d{1,8})")
_OBJSTM_FIRST = re.compile(rb"/First\s{1,8}(\d{1,10})")
_INTS = re.compile(rb"\d{1,10}")
PDF_STREAM_MAX = 16 * 1024 * 1024
PDF_INFLATE_TOTAL = 64 * 1024 * 1024
PDF_MAX_STREAMS = 5000


def pdf_inflate_streams(data: bytes, budget: Budget) -> dict[str, Any]:
    """Inflate the FlateDecode object streams (/Type /ObjStm) and metadata streams (/Type /Metadata) only,
    within caps (16 MB per stream, 64 MB in total, 5,000 streams, the per-file read budget). Returns
    {'objstm_text': [bytes], 'objects': {num: bytes}, 'metadata': [bytes], 'inflated': n, 'errors': n}."""
    out: dict[str, Any] = {"objstm_text": [], "objects": {}, "metadata": [], "inflated": 0, "errors": 0, "capped": False}
    total = 0
    for i, m in enumerate(_STREAM_KW.finditer(data)):
        if i >= PDF_MAX_STREAMS or total >= PDF_INFLATE_TOTAL:
            out["capped"] = True
            break
        s = m.start()
        head_at = data.rfind(b"obj", max(0, s - 8192), s)
        d = data[head_at if head_at != -1 else max(0, s - 2048):s]
        is_objstm = re.search(rb"/Type\s{0,8}/ObjStm", d) is not None
        is_meta = re.search(rb"/Type\s{0,8}/Metadata", d) is not None or re.search(rb"/Subtype\s{0,8}/XML", d) is not None
        if not (is_objstm or is_meta):
            continue
        start = m.end()
        lm = _DICT_LENGTH.search(d)
        end = start + int(lm.group(1)) if lm else data.find(b"endstream", start)
        if end < start or end == -1:
            end = len(data)
        raw = data[start:min(end, len(data))]
        if re.search(rb"/(?:FlateDecode|Fl)" + _NAME_END, d):
            if re.search(rb"/(?:ASCIIHexDecode|ASCII85Decode|LZWDecode|RunLengthDecode|AHx|A85|LZW|RL|Crypt)" + _NAME_END, d):
                out["errors"] += 1
                continue
            try:
                budget.charge(len(raw))
                z = zlib.decompressobj()
                text = z.decompress(raw, PDF_STREAM_MAX)
            except (zlib.error, ArchiveLimit):
                out["errors"] += 1
                continue
            if len(text) > 100 * max(len(raw), 1) and len(text) > LIMITS["ratio_grace"]:
                out["errors"] += 1  # an object/metadata stream is text: a ratio above 100 is a bomb shape
                continue
        elif b"/Filter" in d:
            continue
        else:
            text = raw
        total += len(text)
        out["inflated"] += 1
        try:
            budget.charge(len(text))
        except ArchiveLimit:
            out["capped"] = True
            break
        if is_objstm:
            out["objstm_text"].append(text)
            _index_objstm(d, text, out["objects"])
        else:
            out["metadata"].append(text)
    return out


def _index_objstm(d: bytes, text: bytes, objects: dict[int, bytes]) -> None:
    n_m, f_m = _OBJSTM_N.search(d), _OBJSTM_FIRST.search(d)
    if not (n_m and f_m):
        return
    n, first = min(int(n_m.group(1)), 100_000), int(f_m.group(1))
    nums = [int(x) for x in _INTS.findall(text[:first])][: 2 * n]
    pairs = list(zip(nums[0::2], nums[1::2]))
    for i, (num, off) in enumerate(pairs):
        start = first + off
        end = first + pairs[i + 1][1] if i + 1 < len(pairs) else len(text)
        if 0 <= start < end <= len(text) and num not in objects:
            objects[num] = text[start:min(end, start + 65536)]


def _pdf_object(data: bytes, objects: dict[int, bytes], num: int, gen: int = 0) -> bytes | None:
    """The body of object ``num gen`` (the newest revision in the file, else from an object stream)."""
    rx = re.compile(rb"(?<![0-9])" + str(num).encode() + rb"\s{1,8}" + str(gen).encode() + rb"\s{1,8}obj\b")
    last = None
    for i, m in enumerate(rx.finditer(data)):
        last = m
        if i > 64:
            break
    if last is not None:
        end = data.find(b"endobj", last.end(), last.end() + 65536)
        return data[last.end():end if end != -1 else last.end() + 65536]
    return objects.get(num)


_INFO_REF = re.compile(rb"/Info\s{1,8}(\d{1,10})\s{1,8}(\d{1,5})\s{1,8}R")
INFO_KEYS = ("Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate")


def _dict_strings(body: bytes, keys: tuple[str, ...]) -> dict[str, str]:
    out = {}
    for key in keys:
        m = re.search(rb"/" + key.encode() + rb"\s{0,8}(?=[(<])", body)
        if m:
            v = pdf_string_value(body, m.end())
            if v:
                out["/" + key] = v
    return out


def pdf_info(data: bytes, objects: dict[int, bytes], extra_texts: list[bytes]) -> tuple[dict[str, str], str]:
    """The Info dictionary: through the trailer's /Info reference (newest), else the first dictionary that
    looks like Info (has /Producer, /Creator or /CreationDate). Returns (info, how)."""
    refs = list(_INFO_REF.finditer(data))[-1:]
    for m in refs:
        body = _pdf_object(data, objects, int(m.group(1)), int(m.group(2)))
        if body:
            info = _dict_strings(body, INFO_KEYS)
            if info:
                return info, "trailer_info"
    for text in [data, *extra_texts]:
        for i, m in enumerate(re.finditer(rb"/(?:Producer|CreationDate|Creator)\s{0,8}(?=[(<])", text)):
            if i > 50:
                break
            start = text.rfind(b"<<", max(0, m.start() - 4096), m.start())
            end = text.find(b">>", m.end(), m.end() + 16384)
            if start != -1:
                info = _dict_strings(text[start:end if end != -1 else m.end() + 4096], INFO_KEYS)
                if info:
                    return info, "info_like_dictionary"
    return {}, "none"


_XMP_START = re.compile(rb"<x:x[ma]pmeta\b")
_XMP_END = re.compile(rb"</x:x[ma]pmeta>")


def pdf_xmp_packets(texts: list[bytes], limit: int = 5) -> list[bytes]:
    out = []
    for text in texts:
        for m in _XMP_START.finditer(text):
            e = _XMP_END.search(text, m.end(), m.end() + 1024 * 1024)
            if e:
                out.append(text[m.start():e.end()])
                if len(out) >= limit:
                    return out
    return out


def _bounded_matches(rx: re.Pattern[bytes], texts: list[bytes], cap: int = 5000):
    n = 0
    for text in texts:
        for m in rx.finditer(text):
            yield text, m
            n += 1
            if n >= cap:
                return


_URI_KEY = re.compile(rb"/URI\s{0,8}(?=[(<])")


def pdf_uris(texts: list[bytes], limit: int = 500) -> list[str]:
    """URIs of /URI actions (c9: PDF URIs = url pivots)."""
    out: list[str] = []
    for text, m in _bounded_matches(_URI_KEY, texts):
        v = clean_text(pdf_string_value(text, m.end()), 2048)
        if v and v not in out:
            out.append(v)
            if len(out) >= limit:
                break
    return out


_JS_IN = re.compile(rb"/S\s{0,8}/JavaScript\b|/JS\s{0,8}[(<\d]")
_LAUNCH_IN = re.compile(rb"/S\s{0,8}/Launch\b")
_REF = re.compile(rb"\s{0,8}(\d{1,10})\s{1,8}(\d{1,5})\s{1,8}R")
_OPEN_ACTION = re.compile(rb"/OpenAction\b")
_AA = re.compile(rb"/AA\s{0,8}<<")


def _action_kind(body: bytes | None) -> str | None:
    if not body:
        return None
    if _JS_IN.search(body):
        return "javascript"
    if _LAUNCH_IN.search(body):
        return "launch"
    return None


def pdf_auto_actions(data: bytes, objects: dict[int, bytes], texts: list[bytes]) -> dict[str, Any]:
    """/OpenAction and /AA triggers that run JavaScript or /Launch, resolved through object references."""
    open_action: dict[str, Any] = {}
    aa: list[dict[str, Any]] = []
    for text, m in _bounded_matches(_OPEN_ACTION, texts, cap=50):
        after = text[m.end():m.end() + 4096]
        ref = _REF.match(after)
        body = _pdf_object(data, objects, int(ref.group(1)), int(ref.group(2))) if ref else after
        kind = _action_kind(body)
        if kind:
            open_action = {"type": kind}
            break
        if not open_action:
            open_action = {"type": "other"}
    for text, m in _bounded_matches(_AA, texts, cap=50):
        inner = text[m.end():m.end() + 2048]
        end = inner.find(b">>")
        inner = inner[:end if end != -1 else len(inner)]
        kinds = [_action_kind(inner)]
        for i, ref in enumerate(re.finditer(rb"(\d{1,10})\s{1,8}(\d{1,5})\s{1,8}R", inner)):
            if i >= 20:
                break
            kinds.append(_action_kind(_pdf_object(data, objects, int(ref.group(1)), int(ref.group(2)))))
        for k in kinds:
            if k:
                aa.append({"type": k})
                break
    return {"open_action": open_action or None, "aa_triggers": aa}


def pdf_launch_targets(texts: list[bytes]) -> list[dict[str, str]]:
    out = []
    for text, m in _bounded_matches(_LAUNCH_IN, texts, cap=20):
        window = text[m.end():m.end() + 2048]
        entry = {}
        for key in ("F", "P"):
            km = re.search(rb"/" + key.encode() + rb"\s{0,8}(?=[(<])", window)
            if km:
                entry["file" if key == "F" else "params"] = clean_text(pdf_string_value(window, km.end()), 200) or ""
        if entry:
            out.append(entry)
    return out


def pdf_embedded_names(texts: list[bytes]) -> list[str]:
    out = []
    for text, m in _bounded_matches(re.compile(rb"/Type\s{0,8}/Filespec\b"), texts, cap=100):
        window = text[max(0, m.start() - 1024):m.end() + 2048]
        for key in (b"/UF", b"/F"):
            km = re.search(re.escape(key) + rb"\s{0,8}(?=[(<])", window)
            if km:
                name = clean_text(pdf_string_value(window, km.end()), 260)
                if name and name not in out:
                    out.append(name)
                break
    return out[:50]


XMP_NS = {"x": "adobe:ns:meta/", "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#", "dc": "http://purl.org/dc/elements/1.1/",
          "xmp": "http://ns.adobe.com/xap/1.0/", "pdf": "http://ns.adobe.com/pdf/1.3/", "xmpMM": "http://ns.adobe.com/xap/1.0/mm/",
          "photoshop": "http://ns.adobe.com/photoshop/1.0/"}


def parse_xmp(xml: bytes) -> dict[str, Any]:
    """XMP packet (safe XML) -> creators, tool, producer, dates, document/instance ids, history (c6)."""
    root = safe_xml_parse(xml)
    out: dict[str, Any] = {"creators": [], "title": None, "creator_tool": None, "producer": None, "create_date": None, "modify_date": None,
                           "metadata_date": None, "document_id": None, "instance_id": None, "original_document_id": None,
                           "derived_from": None, "history": []}

    def prop(desc: Any, ns: str, name: str) -> Any:
        v = desc.get(f"{{{XMP_NS[ns]}}}{name}")
        if v is not None:
            return clean_text(v)
        el = desc.find(f"{{{XMP_NS[ns]}}}{name}")
        if el is None:
            return None
        items = el.findall(f".//{{{XMP_NS['rdf']}}}li")
        if items:
            return [clean_text(i.text or "") for i in items if (i.text or "").strip()]
        return clean_text(el.text or "") or None

    for desc in root.iter(f"{{{XMP_NS['rdf']}}}Description"):
        c = prop(desc, "dc", "creator")
        if c:
            out["creators"] += c if isinstance(c, list) else [c]
        t = prop(desc, "dc", "title")
        out["title"] = out["title"] or (t[0] if isinstance(t, list) and t else t)
        for key, ns, name in (("creator_tool", "xmp", "CreatorTool"), ("producer", "pdf", "Producer"), ("create_date", "xmp", "CreateDate"),
                              ("modify_date", "xmp", "ModifyDate"), ("metadata_date", "xmp", "MetadataDate"),
                              ("document_id", "xmpMM", "DocumentID"), ("instance_id", "xmpMM", "InstanceID"),
                              ("original_document_id", "xmpMM", "OriginalDocumentID")):
            v = prop(desc, ns, name)
            if v and not out[key]:
                out[key] = v if not isinstance(v, list) else v[0]
        df = desc.find(f"{{{XMP_NS['xmpMM']}}}DerivedFrom")
        if df is not None:
            out["derived_from"] = {k.split("}")[-1]: clean_text(v) for k, v in df.attrib.items()} or None
        hist = desc.find(f"{{{XMP_NS['xmpMM']}}}History")
        if hist is not None:
            for li in hist.findall(f".//{{{XMP_NS['rdf']}}}li")[:100]:
                ev = {k.split("}")[-1]: clean_text(v) for k, v in li.attrib.items()}
                for child in li:
                    ev[xml_local(child.tag)] = clean_text(child.text or "")
                ev = {k: v for k, v in ev.items() if k in ("action", "softwareAgent", "when", "instanceID", "changed", "parameters")}
                if ev:
                    out["history"].append(ev)
    out["creators"] = list(dict.fromkeys(out["creators"]))
    return out


def analyse_pdf(data: bytes, budget: Budget | None = None) -> dict[str, Any]:
    """Stdlib PDF path: pdfid-style counts, the Info dictionary (also inside object streams), XMP, URIs,
    /OpenAction and /AA actions, /Launch targets and embedded file names. With /Encrypt the strings are
    ciphertext: only structure and counts are kept (nothing is decrypted)."""
    budget = budget or Budget()
    counts_raw = pdf_keyword_counts(data)
    encrypted = counts_raw["keywords"]["/Encrypt"] > 0
    streams = pdf_inflate_streams(data, budget) if not encrypted else {"objstm_text": [], "objects": {}, "metadata": [], "inflated": 0,
                                                                         "errors": 0, "capped": False}
    texts = [data, *streams["objstm_text"]]
    counts = counts_raw
    for text in streams["objstm_text"]:
        counts = _merge_counts(counts, pdf_keyword_counts(text))
    facts: dict[str, Any] = {"format": "pdf", "encrypted": encrypted, "encryption": "present" if encrypted else "none", "info": {},
                             "info_source": "none", "xmp": None, "uris": [], "embedded_files": [], "launch": [], "open_action": None,
                             "aa_triggers": [], "errors": [], "raw_counts": counts_raw, "counts": counts,
                             "streams": {k: streams[k] for k in ("inflated", "errors", "capped")}, "pages": counts["keywords"]["/Page"]}
    actions = pdf_auto_actions(data, streams["objects"], texts)
    facts.update(actions)
    facts["launch"] = pdf_launch_targets(texts)
    if not encrypted:
        info, how = pdf_info(data, streams["objects"], streams["objstm_text"])
        facts["info"], facts["info_source"] = info, how
        facts["uris"] = pdf_uris(texts)
        facts["embedded_files"] = pdf_embedded_names(texts)
        for packet in pdf_xmp_packets([data, *streams["metadata"]]):
            try:
                xmp = parse_xmp(packet)
            except (UnsafeXML, ValueError) as exc:
                facts["errors"].append(f"xmp_refused:{exc.args[0] if exc.args else exc}")
                continue
            facts["xmp"] = _merge_xmp(facts["xmp"], xmp)
    info = facts["info"]
    facts.update({"title": clean_text(info.get("/Title")), "author": clean_text(info.get("/Author")), "subject": clean_text(info.get("/Subject")),
                  "keywords": clean_text(info.get("/Keywords")), "creator_tool": clean_text(info.get("/Creator")),
                  "producer": clean_text(info.get("/Producer")), "created": pdf_date_to_iso(info.get("/CreationDate")),
                  "modified": pdf_date_to_iso(info.get("/ModDate"))})
    if counts_raw["eof_markers"] == 0:
        facts["errors"].append("no_eof_marker")
    if not counts_raw["header"]:
        facts["errors"].append("no_pdf_header_in_first_kb")
    return facts


def _merge_xmp(a: dict[str, Any] | None, b: dict[str, Any]) -> dict[str, Any]:
    if a is None:
        return b
    for k, v in b.items():
        if k == "creators":
            a["creators"] = list(dict.fromkeys(a["creators"] + v))
        elif k == "history":
            a["history"] = (a["history"] + v)[:100]
        elif not a.get(k) and v:
            a[k] = v
    return a


# ======================================================================================== OLE property sets

FMTID_SUMMARY = "f29f85e0-4ff9-1068-ab91-08002b27b3d9"
FMTID_DOCSUMMARY = "d5cdd502-2e9c-101b-9397-08002b2cf9ae"
FMTID_USERDEFINED = "d5cdd505-2e9c-101b-9397-08002b2cf9ae"
SUMMARY_PIDS = {2: "title", 3: "subject", 4: "author", 5: "keywords", 6: "comments", 7: "template", 8: "last_saved_by", 9: "revision",
                10: "edit_time_minutes", 11: "last_printed", 12: "created", 13: "last_saved", 14: "pages", 15: "words", 16: "chars",
                18: "app_name", 19: "doc_security"}
DOCSUMMARY_PIDS = {2: "category", 14: "manager", 15: "company", 23: "app_version", 26: "content_type", 27: "content_status",
                   28: "language", 29: "doc_version"}
_CODEPAGES = {1200: "utf-16-le", 65001: "utf-8", 1252: "cp1252", 10000: "mac_roman", 437: "cp437", 850: "cp850"}


def _codec(cp: int) -> str:
    if cp in _CODEPAGES:
        return _CODEPAGES[cp]
    try:
        name = f"cp{int(cp)}"
        "".encode(name)
        return name
    except (LookupError, TypeError, ValueError):
        return "cp1252"


def _ps_size(buf: bytes, p: int, vt: int) -> int:
    if vt in (0x02, 0x0B, 0x03, 0x13, 0x16, 0x17):
        return 4
    if vt in (0x05, 0x40):
        return 8
    if vt in (0x1E, 0x41):
        return 4 + ((u32(buf, p) + 3) & ~3)
    if vt == 0x1F:
        return 4 + ((u32(buf, p) * 2 + 3) & ~3)
    return 4


def _ps_value(buf: bytes, off: int, codepage: int, depth: int = 0) -> Any:
    vt = u16(buf, off)
    p = off + 4
    if vt in (0x02, 0x0B):  # I2, BOOL
        v = struct.unpack_from("<h", buf, p)[0]
        return (v != 0) if vt == 0x0B else v
    if vt in (0x03, 0x16):
        return struct.unpack_from("<i", buf, p)[0]
    if vt in (0x13, 0x17):
        return u32(buf, p)
    if vt == 0x05:
        return struct.unpack_from("<d", buf, p)[0]
    if vt == 0x1E:  # LPSTR
        raw = buf[p + 4:p + 4 + min(u32(buf, p), 1 << 20)]
        if codepage == 1200:
            return raw.decode("utf-16-le", "replace").split("\x00")[0]
        return raw.split(b"\x00")[0].decode(_codec(codepage), "replace")
    if vt == 0x1F:  # LPWSTR
        return buf[p + 4:p + 4 + min(u32(buf, p), 1 << 19) * 2].decode("utf-16-le", "replace").split("\x00")[0]
    if vt == 0x40:
        return ("filetime", u64(buf, p))
    if vt == 0x41:  # BLOB
        return buf[p + 4:p + 4 + min(u32(buf, p), 1 << 20)]
    if vt & 0x1000 and depth == 0:  # VECTOR of LPSTR/LPWSTR/VARIANT
        q = p + 4
        items = []
        base = vt & 0x0FFF
        for _ in range(min(u32(buf, p), 1000)):
            if base == 0x0C:  # VARIANT: a full typed value
                vt2 = u16(buf, q)
                items.append(_ps_value(buf, q, codepage, depth + 1))
                q += 4 + _ps_size(buf, q + 4, vt2)
            else:
                fake = struct.pack("<HH", base, 0) + buf[q:q + 4 + u32(buf, q) * (2 if base == 0x1F else 1) + 4]
                items.append(_ps_value(fake, 0, codepage, depth + 1))
                q += _ps_size(buf, q, base)
        return items
    return None


def ole_property_sets(stream: bytes) -> dict[str, dict[str, Any]]:
    """PropertySetStream -> {fmtid: {'props': {pid: value}, 'names': {pid: name}, 'codepage'}}."""
    out: dict[str, dict[str, Any]] = {}
    if len(stream) < 48 or u16(stream, 0) != 0xFFFE:
        return out
    for i in range(min(u32(stream, 24), 4)):
        fmtid = guid_le(stream[28 + i * 20:44 + i * 20])
        base = u32(stream, 44 + i * 20)
        if base + 8 > len(stream) or fmtid is None:
            continue
        nprops = min(u32(stream, base + 4), 1000)
        props: dict[int, Any] = {}
        names: dict[int, str] = {}
        codepage = 1252
        pairs = [struct.unpack_from("<II", stream, base + 8 + j * 8) for j in range(nprops) if base + 16 + j * 8 <= len(stream)]
        for pid, off in pairs:
            if pid == 1 and base + off + 6 <= len(stream):
                codepage = struct.unpack_from("<H", stream, base + off + 4)[0]
        for pid, off in pairs:
            o = base + off
            if o + 8 > len(stream):
                continue
            try:
                if pid == 0:  # dictionary of user-defined names
                    q = o + 4
                    for _ in range(min(u32(stream, o), 1000)):
                        npid, ln = struct.unpack_from("<II", stream, q)
                        q += 8
                        if codepage == 1200:
                            names[npid] = stream[q:q + ln * 2].decode("utf-16-le", "replace").rstrip("\x00")
                            q += (ln * 2 + 3) & ~3
                        else:
                            names[npid] = stream[q:q + ln].split(b"\x00")[0].decode(_codec(codepage), "replace")
                            q += ln
                    continue
                props[pid] = _ps_value(stream, o, codepage)
            except (struct.error, IndexError):
                continue
        out[fmtid] = {"props": props, "names": names, "codepage": codepage}
    return out


_HLINK_TARGET = re.compile(r"(?:https?://|\\\\|file://)[^\x00\s\"<>]{3,2048}")


def ole_summary(cfb: CFB) -> dict[str, Any]:
    """Normalised OLE metadata: SummaryInformation + DocumentSummaryInformation + user-defined hyperlinks."""
    res: dict[str, Any] = {}
    for path, table in (("\x05SummaryInformation", SUMMARY_PIDS), ("\x05DocumentSummaryInformation", DOCSUMMARY_PIDS)):
        e = cfb.find(path)
        if e is None:
            continue
        try:
            sets = ole_property_sets(cfb.read(e, max_out=4 << 20) or b"")
        except ArchiveLimit:
            continue
        for fmtid, ps in sets.items():
            if fmtid in (FMTID_SUMMARY, FMTID_DOCSUMMARY):
                for pid, key in table.items():
                    v = ps["props"].get(pid)
                    if isinstance(v, tuple) and v and v[0] == "filetime":
                        v = round(v[1] / 600_000_000, 1) if key == "edit_time_minutes" else filetime_to_iso(v[1])
                    if isinstance(v, str):
                        v = clean_text(v) or None
                    if isinstance(v, (bytes, list)):
                        continue
                    if v is not None and v != "":
                        res[key] = v
            elif fmtid == FMTID_USERDEFINED:
                custom = {}
                for pid, v in ps["props"].items():
                    if pid in (0, 1):  # dictionary / codepage are structure
                        continue
                    nm = ps["names"].get(pid, str(pid))
                    if isinstance(v, bytes):
                        if nm in ("_PID_HLINKS", "_PID_LINKBASE"):
                            res.setdefault("hyperlinks", []).extend(_HLINK_TARGET.findall(v.decode("utf-16-le", "replace"))[:100])
                        continue
                    if isinstance(v, tuple):
                        v = filetime_to_iso(v[1])
                    if isinstance(v, list):
                        v = [x for x in v if isinstance(x, (str, int, float, bool))][:20]
                    custom[clean_text(nm, 256) or str(pid)] = clean_text(v, 1024) if isinstance(v, str) else v
                if custom:
                    res["custom"] = custom
    if isinstance(res.get("app_version"), int):
        res["app_version"] = f"{res['app_version'] >> 16}.{res['app_version'] & 0xFFFF:04d}"
    if isinstance(res.get("doc_security"), int):
        res["protection_flag"] = bool(res["doc_security"] & 1)
    return res


# ======================================================================================== VBA ([MS-OVBA])


def vba_decompress(data: bytes, max_out: int = 16 << 20) -> bytes:
    """[MS-OVBA] 2.4.1 decompression (CompressedContainer -> bytes). Raises ValueError on corrupt input;
    every decompressed chunk is at most 4096 bytes (the spec limit), so the output is bounded."""
    if not data or data[0] != 0x01:
        raise ValueError("vba_bad_signature")
    out = bytearray()
    pos = 1
    while pos + 2 <= len(data):
        header = u16(data, pos)
        chunk_end = min(pos + (header & 0x0FFF) + 3, len(data))
        pos += 2
        dec_start = len(out)
        if not header & 0x8000:  # raw chunk of 4096 bytes
            out += data[pos:pos + 4096]
            pos += 4096
        else:
            while pos < chunk_end:
                flags = data[pos]
                pos += 1
                for bit in range(8):
                    if pos >= chunk_end:
                        break
                    if not (flags >> bit) & 1:
                        out.append(data[pos])
                        pos += 1
                        continue
                    if pos + 2 > len(data):
                        raise ValueError("vba_truncated_token")
                    token = u16(data, pos)
                    pos += 2
                    bits = max((len(out) - dec_start - 1).bit_length(), 4)
                    length = (token & (0xFFFF >> bits)) + 3
                    offset = (token >> (16 - bits)) + 1
                    src = len(out) - offset
                    if src < dec_start:
                        raise ValueError("vba_bad_copy_token")
                    if offset >= length:
                        out += out[src:src + length]
                    else:  # overlapping copy (run-length style)
                        for k in range(length):
                            out.append(out[src + k])
                    if len(out) - dec_start > 4096:
                        raise ValueError("vba_chunk_overflow")
        if len(out) > max_out:
            raise ValueError("vba_too_large")
    return bytes(out)


def vba_dir_modules(dir_bytes: bytes) -> dict[str, Any]:
    """Decompressed VBA 'dir' stream -> {'codepage', 'project', 'modules': [{name, stream, offset, type}]}."""
    pos, codepage, project, mods = 0, 1252, None, []
    cur: dict[str, Any] | None = None
    while pos + 6 <= len(dir_bytes) and len(mods) < 1000:
        rid, size = struct.unpack_from("<HI", dir_bytes, pos)
        pos += 6
        if rid == 0x0009:  # PROJECTVERSION: 'size' is Reserved=4 but 6 bytes follow
            pos += 6
            continue
        if size > len(dir_bytes) - pos:
            break
        body = dir_bytes[pos:pos + size]
        pos += size
        if rid == 0x0003 and size == 2:
            codepage = u16(body, 0)
        elif rid == 0x0004:
            project = body.decode(_codec(codepage), "replace")
        elif rid == 0x0019:
            cur = {"name": body.decode(_codec(codepage), "replace"), "stream": None, "offset": 0, "type": None}
            mods.append(cur)
        elif rid == 0x0047 and cur is not None:
            cur["name"] = body.decode("utf-16-le", "replace") or cur["name"]
        elif rid == 0x001A and cur is not None:
            cur["stream"] = body.decode(_codec(codepage), "replace")
        elif rid == 0x0032 and cur is not None and body:
            cur["stream"] = body.decode("utf-16-le", "replace") or cur["stream"]
        elif rid == 0x0031 and cur is not None and size == 4:
            cur["offset"] = u32(body, 0)
        elif rid in (0x0021, 0x0022) and cur is not None:
            cur["type"] = "procedural" if rid == 0x0021 else "document_or_class"
        elif rid == 0x0010:
            break
    return {"codepage": codepage, "project": project, "modules": mods}


AUTOEXEC_NAMES = ("AutoExec", "AutoOpen", "Auto_Open", "AutoClose", "Auto_Close", "AutoExit", "AutoNew", "Document_Open", "DocumentOpen",
                  "Document_Close", "DocumentBeforeClose", "Document_BeforeClose", "Document_New", "NewDocument",
                  "Document_ContentControlOnEnter", "Workbook_Open", "Workbook_Activate", "Workbook_Close", "Workbook_BeforeClose",
                  "Workbook_Deactivate", "Workbook_WindowActivate", "Auto_Activate", "App_WorkbookOpen")
_AUTOEXEC_RX = re.compile(r"\b(?:Sub|Function)\s{1,16}(" + "|".join(AUTOEXEC_NAMES) + r"|\w{1,64}_(?:Layout|Painted|Painting|GotFocus|Resize|Initialize))\b", re.I)
SUSPICIOUS_VBA = ("Shell", "WScript.Shell", "CreateObject", "GetObject", "CallByName", "PowerShell", "cmd.exe", "URLDownloadToFile",
                  "MSXML2.XMLHTTP", "MSXML2.ServerXMLHTTP", "WinHttp.WinHttpRequest", "ADODB.Stream", "SaveToFile", "Environ", "StrReverse",
                  "ExecuteExcel4Macro", "Application.Run", "CreateTextFile", "VirtualAlloc", "RtlMoveMemory", "CreateThread", "regsvr32",
                  "mshta", "rundll32", "certutil", "bitsadmin", "schtasks", "bin.base64", 'Lib "kernel32"', 'Lib "urlmon"')
_CHR_CALL = re.compile(r"\bchrw?\$?\s{0,8}\(", re.I)


def vba_scan(source: str) -> dict[str, Any]:
    """Auto-exec triggers, suspicious keywords and IOCs in VBA source text (macros are never executed, c7)."""
    autoexec = sorted({m.group(1) for m in _AUTOEXEC_RX.finditer(source)}, key=str.lower)
    low = source.lower()
    sus = [k for k in SUSPICIOUS_VBA if k.lower() in low]
    if len(_CHR_CALL.findall(source)) >= 10:
        sus.append("Chr() obfuscation")
    return {"autoexec": autoexec, "suspicious": sus, "iocs": extract_iocs(source, max_items=100)}


def vba_project_from_cfb(cfb: CFB) -> dict[str, Any]:
    """VBA projects (Word 'Macros/VBA', Excel '_VBA_PROJECT_CUR/VBA', vbaProject.bin 'VBA') ->
    {'present', 'projects': [{'root', 'modules': [{name, type, source_len, autoexec, suspicious, iocs}]}], 'errors'}."""
    res: dict[str, Any] = {"present": False, "projects": [], "errors": []}
    roots = sorted({e["path"].rsplit("/", 1)[0] for e in cfb.streams() if e["path"].lower().endswith("vba/dir")})[:10]
    for vroot in roots:
        res["present"] = True
        proj: dict[str, Any] = {"root": vroot, "modules": []}
        try:
            info = vba_dir_modules(vba_decompress(cfb.read(vroot + "/dir", max_out=8 << 20) or b""))
        except (ValueError, ArchiveLimit, TypeError) as exc:
            res["errors"].append(f"dir:{exc}")
            res["projects"].append(proj)
            continue
        for m in info["modules"][:200]:
            entry: dict[str, Any] = {"name": clean_text(m["name"], 128), "type": m["type"], "source_len": 0, "autoexec": [], "suspicious": [],
                                     "iocs": {}}
            try:
                raw = cfb.read(f"{vroot}/{m['stream']}", max_out=16 << 20) if m["stream"] else None
            except ArchiveLimit as exc:
                raw = None
                entry["error"] = exc.args[0]
            if raw is None:
                entry.setdefault("error", "module_stream_missing")
            else:
                try:
                    src = vba_decompress(raw[m["offset"]:]).decode(_codec(info["codepage"]), "replace")
                    entry["source_len"] = len(src)
                    entry.update(vba_scan(src))
                except ValueError as exc:
                    entry["error"] = str(exc)
            proj["modules"].append(entry)
        res["projects"].append(proj)
    if not roots and any(e["name"].upper() in ("_VBA_PROJECT", "PROJECT") for e in cfb.entries if e["path"]):
        res["present"] = True
        res["errors"].append("vba_dir_not_found")
    return res


def xls_biff_globals(workbook: bytes, max_records: int = 200_000) -> dict[str, Any]:
    """BOUNDSHEET8 + Lbl records of the workbook globals: XLM macro sheets, hidden state, Auto_Open names."""
    res: dict[str, Any] = {"sheets": [], "autoexec_names": [], "encrypted": False}
    pos, n = 0, 0
    while pos + 4 <= len(workbook) and n < max_records:
        rtype, rlen = struct.unpack_from("<HH", workbook, pos)
        body = workbook[pos + 4:pos + 4 + rlen]
        pos += 4 + rlen
        n += 1
        if rtype == 0x002F:
            res["encrypted"] = True
        elif rtype == 0x0085 and len(body) >= 8:
            state = {0: "visible", 1: "hidden", 2: "very_hidden"}.get(body[4] & 3, "unknown")
            stype = {0x00: "worksheet", 0x01: "xlm_macro", 0x02: "chart", 0x06: "vba_module"}.get(body[5], hex(body[5]))
            cch, high = body[6], body[7] & 1
            name = body[8:8 + cch * (2 if high else 1)].decode("utf-16-le" if high else "latin-1", "replace")
            res["sheets"].append({"name": clean_text(name, 64), "type": stype, "state": state})
        elif rtype == 0x0018 and len(body) >= 15:
            flags, cch = u16(body, 0), body[3]
            high = body[14] & 1
            raw = body[15:15 + cch * (2 if high else 1)]
            if flags & 0x20 and raw[:1] in (b"\x01", b"\x02"):
                res["autoexec_names"].append("Auto_Open" if raw[:1] == b"\x01" else "Auto_Close")
            else:
                nm = raw.decode("utf-16-le" if high else "latin-1", "replace")
                if nm.lower().startswith(("auto_open", "auto_close")):
                    res["autoexec_names"].append(nm[:64])
        elif rtype == 0x000A:  # EOF of the globals substream
            break
    return res


# ======================================================================================== Outlook .msg

MSG_PROPS = {0x0037: "subject", 0x0C1A: "sender_name", 0x0C1F: "sender_address", 0x5D01: "sender_smtp", 0x0042: "sent_representing_name",
             0x0065: "sent_representing_address", 0x0E04: "display_to", 0x0E03: "display_cc", 0x1000: "body", 0x007D: "transport_headers",
             0x1035: "internet_message_id", 0x0070: "conversation_topic", 0x1013: "body_html"}
ATTACH_PROPS = {0x3707: "long_filename", 0x3704: "filename", 0x370E: "mime_tag", 0x3712: "content_id", 0x3701: "data"}
RECIP_PROPS = {0x3001: "display_name", 0x3003: "address", 0x39FE: "smtp_address"}
_SUBSTG = re.compile(r"__substg1\.0_([0-9A-Fa-f]{4})([0-9A-Fa-f]{4})")


def _msg_value(raw: bytes, ptype: int) -> Any:
    if ptype == 0x001F:
        return raw.decode("utf-16-le", "replace").rstrip("\x00")
    if ptype == 0x001E:
        return raw.rstrip(b"\x00").decode("cp1252", "replace")
    return raw


def msg_parse(cfb: CFB, *, max_attach: int = 50) -> dict[str, Any]:
    """Outlook .msg -> subject, sender/recipients (personal data), message-id, transport-header presence
    (the headers themselves go to email_header_analyzer, P085), attachments (name, size, sha256, sniffed
    kind) and body URLs. Never the GPL extract-msg (c6)."""
    top: dict[str, Any] = {}
    recips: dict[str, dict[str, Any]] = {}
    atts: dict[str, dict[str, Any]] = {}
    for e in cfb.streams():
        parts = e["path"].split("/")
        m = _SUBSTG.fullmatch(parts[-1])
        if not m:
            continue
        pid, ptype = int(m.group(1), 16), int(m.group(2), 16)
        holder = parts[0] if len(parts) > 1 else None
        wanted = (holder is None and pid in MSG_PROPS) or (holder and holder.lower().startswith("__recip_version1.0_") and pid in RECIP_PROPS) \
            or (holder and holder.lower().startswith("__attach_version1.0_") and pid in ATTACH_PROPS)
        if not wanted:
            continue
        try:
            raw = cfb.read(e, max_out=32 << 20) or b""
        except ArchiveLimit:
            continue
        if holder is None:
            top[MSG_PROPS[pid]] = _msg_value(raw, ptype)
        elif holder.lower().startswith("__recip_version1.0_"):
            recips.setdefault(holder, {})[RECIP_PROPS[pid]] = _msg_value(raw, ptype)
        else:
            atts.setdefault(holder, {})[ATTACH_PROPS[pid]] = _msg_value(raw, ptype)
    body = top.get("body") if isinstance(top.get("body"), str) else ""
    html = top.get("body_html")
    if isinstance(html, bytes):
        html = html.decode("utf-8", "replace")
    attachments = []
    for _, a in sorted(atts.items())[:max_attach]:
        data = a.get("data") if isinstance(a.get("data"), bytes) else b""
        name = clean_text(a.get("long_filename") or a.get("filename") or "", 260) or ""
        sn = sniff(data[: LIMITS["sniff_head"]], size=len(data), name=name,
                   tail=data[-LIMITS["sniff_tail"]:] if len(data) > LIMITS["sniff_head"] else None) if data else None
        attachments.append({"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest() if data else None,
                            "mime": a.get("mime_tag") if isinstance(a.get("mime_tag"), str) else None,
                            "kind": sn["kind"] if sn else None, "findings": extension_findings(name, sn) if sn else []})
    return {"format": "msg", "subject": clean_text(top.get("subject")),
            "sender_name": clean_text(top.get("sender_name") or top.get("sent_representing_name")),
            "sender_address": clean_text(top.get("sender_smtp") or top.get("sender_address") or top.get("sent_representing_address")),
            "recipients": len(recips), "internet_message_id": clean_text(top.get("internet_message_id")),
            "transport_headers_present": bool(top.get("transport_headers")), "attachments": attachments,
            "body_iocs": extract_iocs((body or "") + "\n" + (html if isinstance(html, str) else ""), max_items=200)}


# ======================================================================================== OOXML / ODF

NS = {"cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties", "dc": "http://purl.org/dc/elements/1.1/",
      "dcterms": "http://purl.org/dc/terms/", "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
      "cust": "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties",
      "rel": "http://schemas.openxmlformats.org/package/2006/relationships", "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
      "x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main", "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
      "office": "urn:oasis:names:tc:opendocument:xmlns:office:1.0", "meta": "urn:oasis:names:tc:opendocument:xmlns:meta:1.0",
      "xlink": "http://www.w3.org/1999/xlink", "script": "urn:oasis:names:tc:opendocument:xmlns:script:1.0"}
CORE_FIELDS = {"title": ("dc", "title"), "subject": ("dc", "subject"), "author": ("dc", "creator"), "keywords": ("cp", "keywords"),
               "description": ("dc", "description"), "last_modified_by": ("cp", "lastModifiedBy"), "revision": ("cp", "revision"),
               "created": ("dcterms", "created"), "modified": ("dcterms", "modified"), "last_printed": ("cp", "lastPrinted"),
               "category": ("cp", "category"), "content_status": ("cp", "contentStatus"), "language": ("dc", "language")}
APP_FIELDS = ("Application", "AppVersion", "Company", "Manager", "Template", "TotalTime", "Pages", "Words", "DocSecurity", "HyperlinkBase",
              "SharedDoc", "LinksUpToDate")
#: relationship types loaded automatically on open (template injection family, T1221) vs click-only hyperlinks
AUTO_LOAD_REL_TYPES = frozenset({"attachedtemplate", "oleobject", "frame", "subdocument", "image", "externallink", "externallinkpath",
                                 "mailmergesource", "mailmergeheadersource", "recipientdata", "audio", "video", "media", "package", "font",
                                 "printersettings", "customxml"})


def ooxml_core(xml: bytes) -> dict[str, str]:
    root = safe_xml_parse(xml)
    out = {}
    for key, (ns, name) in CORE_FIELDS.items():
        el = root.find(f"{{{NS[ns]}}}{name}")
        if el is not None and (el.text or "").strip():
            out[key] = clean_text(el.text)
    return out


def ooxml_app(xml: bytes) -> dict[str, str]:
    root = safe_xml_parse(xml)
    out = {}
    for name in APP_FIELDS:
        el = root.find(f"{{{NS['ep']}}}{name}")
        if el is not None and (el.text or "").strip():
            out[name] = clean_text(el.text)
    return out


_TENANT = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def ooxml_custom(xml: bytes) -> tuple[dict[str, Any], list[str]]:
    """docProps/custom.xml -> ({name: value}, M365 sensitivity-label tenant ids from MSIP_Label_*_SiteId)."""
    root = safe_xml_parse(xml)
    out: dict[str, Any] = {}
    for prop in root.findall(f"{{{NS['cust']}}}property")[:500]:
        name = clean_text(prop.get("name"), 256)
        if name:
            out[name] = xml_text(prop[0]) if len(prop) else None
    tenants = sorted({v.lower() for k, v in out.items() if k.startswith("MSIP_Label_") and k.endswith("_SiteId") and isinstance(v, str)
                      and _TENANT.fullmatch(v)})
    return out, tenants


def ooxml_relationships(xml: bytes, part: str) -> list[dict[str, Any]]:
    root = safe_xml_parse(xml)
    out = []
    for r in root.findall(f"{{{NS['rel']}}}Relationship")[:2000]:
        out.append({"id": r.get("Id"), "type": (r.get("Type") or "").rsplit("/", 1)[-1], "target": r.get("Target") or "",
                    "external": (r.get("TargetMode") or "").lower() == "external", "part": part})
    return out


_PROTO_HANDLERS = ("ms-msdt:", "search-ms:", "search:", "ms-officecmd:", "ms-word:", "ms-excel:", "ms-powerpoint:", "ms-its:", "its:", "mk:",
                   "ms-appinstaller:", "ms-cxh:", "ms-settings:", "shell:", "javascript:", "vbscript:")
_URL_SCHEME = re.compile(r"^(?:https?|ftp):[\\/]{2}", re.I)
_LOCAL_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


def classify_target(target: str | None) -> dict[str, Any]:
    """External relationship / link target -> kind (url|unc|webdav|local_path|protocol_handler|mhtml|relative),
    host, ip, normalised url, path_user. Never resolved or fetched (c8)."""
    t = (target or "").strip()[:4096]
    res: dict[str, Any] = {"raw": t[:2048], "kind": "relative", "host": None, "ip": None, "url": None, "path_user": None}
    if not t:
        return res
    low = t.lower()
    for prefix in ("mhtml:", "!x-usc:"):
        if low.startswith(prefix):
            inner = classify_target(t[len(prefix):])
            inner.update(kind="mhtml", inner_kind=inner["kind"], raw=t[:2048])
            return inner
    if low.startswith(_PROTO_HANDLERS):
        res.update(kind="protocol_handler", scheme=low.split(":", 1)[0])
        return res
    if _URL_SCHEME.match(t):
        scheme, _, rest = t.partition(":")
        norm = scheme.lower() + "://" + rest.lstrip("\\/").replace("\\", "/")
        res.update(kind="url", url=norm)
        try:
            u = urllib.parse.urlsplit(norm)
            host = (u.hostname or "").rstrip(".")
            res["host"] = host or None
        except ValueError:
            pass
        if res["host"]:
            res["ip"] = ip_loose(res["host"])
        if "@ssl" in low or "/davwwwroot" in low:
            res["kind"] = "webdav"
        return res
    unc = None
    if low.startswith("file://"):
        rest = t[7:]
        if rest.startswith("/") or _LOCAL_DRIVE.match(rest):
            res.update(kind="local_path", path_user=_path_user(rest.lstrip("/")))
            return res
        unc = rest.replace("/", "\\")
    elif t.startswith(("\\\\", "//")):
        unc = t[2:].replace("/", "\\")
    if unc is not None:
        host = unc.split("\\", 1)[0]
        webdav = "@" in host or "\\davwwwroot" in unc.lower()
        host = host.split("@", 1)[0]
        res.update(kind="webdav" if webdav else "unc", host=host or None)
        res["ip"] = ip_loose(host) if host else None
        return res
    if _LOCAL_DRIVE.match(t):
        res.update(kind="local_path", path_user=_path_user(t))
    return res


_USER_PATH_RX = (re.compile(r"(?i)\b[A-Z]:[\\/]{1,4}(?:Users|Documents and Settings)[\\/]{1,4}([^\\/:*?\"<>|\r\n]{1,64})[\\/]"),
                 re.compile(r"(?i)(?<![\w.])/(?:Users|home)/([A-Za-z0-9._ -]{1,64})/"))
GENERIC_ACCOUNTS = frozenset({"public", "default", "default user", "all users", "administrator", "administrador", "admin", "user", "usuario",
                              "usuário", "owner", "guest", "convidado", "defaultapppool", "localservice", "networkservice", "systemprofile",
                              "%username%", "username", "<user>", "shared", "root", "test", "teste"})
GENERIC_AUTHORS = GENERIC_ACCOUNTS | frozenset({"", "windows user", "microsoft office user", "usuário do windows", "usuario de windows",
                                                "utilisateur", "author", "autor", "unknown", "desconhecido", "pc", "python-docx", "openpyxl",
                                                "apache poi", "microsoft corporation", "office", "home", "customer", "cliente", "win", "win10",
                                                "win11", "desktop", "hp", "dell", "lenovo"})


def _path_user(path: Any) -> str | None:
    for rx in _USER_PATH_RX:
        m = rx.search(path if isinstance(path, str) else "")
        if m:
            return m.group(1).strip()
    return None


def extract_user_paths(*texts: Any) -> list[dict[str, Any]]:
    """C:\\Users\\<name>, /Users/<name>, /home/<name> -> [{'user', 'generic', 'path'}] (c10 local_account)."""
    out, seen = [], set()
    for t in texts:
        if not isinstance(t, str):
            continue
        for rx in _USER_PATH_RX:
            for m in rx.finditer(t[:65536]):
                user = m.group(1).strip()
                if not user or user.lower() in seen:
                    continue
                seen.add(user.lower())
                out.append({"user": user, "generic": user.lower() in GENERIC_ACCOUNTS})
                if len(out) >= 20:
                    return out
    return out


_DOMAIN_USER = re.compile(r"([A-Za-z0-9._-]{1,63})\\([A-Za-z0-9._ $-]{1,64})")
_ACCOUNT = re.compile(r"[A-Za-z0-9._-]{2,32}")
_CAPWORD = re.compile(r"[A-Z][a-z]+")


def author_pivots(value: Any, field: str) -> list[dict[str, Any]]:
    """c10: an author-like field -> pivots (expand=False, privacy). DOMAIN\\user and single tokens become
    username pivots, natural names person_name pivots (relation document_author); generic values none."""
    v = clean_text(value, 256)
    if not v or v.lower() in GENERIC_AUTHORS or len(v) < 2:
        return []
    m = _DOMAIN_USER.fullmatch(v)
    if m:
        user = m.group(2).strip()
        if user.lower() in GENERIC_ACCOUNTS:
            return []
        return [{"type": T.USERNAME, "value": user, "relation": "document_author", "field": field, "windows_domain": m.group(1)}]
    if _ACCOUNT.fullmatch(v) and not _CAPWORD.fullmatch(v):
        return [{"type": T.USERNAME, "value": v, "relation": "document_author", "field": field}]
    if "@" in v:  # an e-mail as author: attribute only
        return []
    return [{"type": T.PERSON, "value": v, "relation": "document_author", "field": field}]


def _w_field_instructions(root: Any) -> list[str]:
    """Word field codes (fldChar begin/separate/end + instrText, and fldSimple) in document order."""
    w = NS["w"]
    out: list[str] = []
    stack: list[list[str] | None] = []
    for el in root.iter():
        tag = el.tag
        if tag == f"{{{w}}}fldSimple":
            out.append(el.get(f"{{{w}}}instr") or "")
        elif tag == f"{{{w}}}fldChar":
            t = el.get(f"{{{w}}}fldCharType")
            if t == "begin":
                stack.append([])
            elif t in ("separate", "end") and stack and (t == "end" or stack[-1] is not None):
                instr = "".join(stack[-1] or [])
                if instr:
                    out.append(instr)
                if t == "end":
                    stack.pop()
                else:
                    stack[-1] = None
        elif tag == f"{{{w}}}instrText" and stack and stack[-1] is not None:
            stack[-1].append(el.text or "")
        if len(out) >= 2000:
            break
    return [" ".join(i.split())[:1024] for i in out if i and i.strip()]


_DDE_FIELD = re.compile(r"^(?:DDEAUTO|DDE)\b\s{0,8}(.{0,512})$", re.I | re.S)
_INCLUDE_FIELD = re.compile(r"^(?:INCLUDETEXT|INCLUDEPICTURE|IMPORT|LINK)\b\s{0,8}\"?([^\"\s]{1,2048})", re.I)
_HYPERLINK_FIELD = re.compile(r"^HYPERLINK\s{1,8}\"([^\"]{1,2048})\"", re.I)


def classify_field(instr: str) -> tuple[str | None, str | None]:
    """Word field instruction -> ('dde' | 'remote_include' | 'hyperlink' | None, target)."""
    m = _DDE_FIELD.match(instr)
    if m:
        return "dde", m.group(1)
    m = _INCLUDE_FIELD.match(instr)
    if m:
        tgt = classify_target(m.group(1).replace("\\\\", "\\"))
        return ("remote_include", m.group(1)) if tgt["kind"] in ("url", "unc", "webdav", "mhtml", "protocol_handler") else (None, None)
    m = _HYPERLINK_FIELD.match(instr)
    if m:
        return "hyperlink", m.group(1)
    return None, None


def _read_member(data: bytes, members: dict[str, dict[str, Any]], name: str, refused: list[dict[str, str]], budget: Budget,
                 cap: int | None = None) -> bytes | None:
    e = members.get(name)
    if e is None:
        return None
    try:
        return zip_read(data, e, max_out=cap or LIMITS["xml_max_bytes"], budget=budget)
    except ArchiveLimit as exc:
        refused.append({"part": name, "reason": exc.args[0]})
        return None


def _xml_part(data: bytes, members: dict[str, dict[str, Any]], name: str, refused: list[dict[str, str]], budget: Budget, fn: Any, *args: Any) -> Any:
    raw = _read_member(data, members, name, refused, budget)
    if raw is None:
        return None
    try:
        return fn(raw, *args)
    except UnsafeXML as exc:
        refused.append({"part": name, "reason": f"unsafe_xml:{exc.args[0]}"})
    except ValueError:
        refused.append({"part": name, "reason": "malformed_xml"})
    return None


_DDE_LINK = re.compile(rb"ddeService=\"([^\"]{0,256})\"[^>]{0,2048}?ddeTopic=\"([^\"]{0,256})\"")
_COMMENT_AUTHOR = re.compile(r"w:author=\"([^\"]{1,128})\"")


def _members(z: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for e in z["entries"]:
        out.setdefault(e["name"], e)  # the first central-directory entry wins for duplicate names
    return out


def analyse_ooxml(data: bytes, budget: Budget | None = None) -> dict[str, Any]:
    """OOXML (docx/xlsx/pptx and macro variants) -> metadata, external relationships, macros, XLM, DDE (c6-c10).
    Refused parts (XXE, zip bomb...) are listed with the reason; the rest is still analysed."""
    budget = budget or Budget()
    z = zip_scan(data)
    members = _members(z)
    refused: list[dict[str, str]] = []
    res: dict[str, Any] = {"format": "ooxml", "zip_anomalies": z["anomalies"], "core": {}, "app": {}, "custom": {}, "m365_tenant_ids": [],
                           "relationships": [], "external": [], "macros": {"present": False}, "xlm_sheets": [], "xlm_autoexec": [], "dde": [],
                           "remote_fields": [], "field_hyperlinks": [], "comment_authors": [], "embedded_objects": [], "activex": False,
                           "refused_parts": refused, "content_types_macro": False}
    names = list(members)
    res["core"] = _xml_part(data, members, "docProps/core.xml", refused, budget, ooxml_core) or {}
    res["app"] = _xml_part(data, members, "docProps/app.xml", refused, budget, ooxml_app) or {}
    cust = _xml_part(data, members, "docProps/custom.xml", refused, budget, ooxml_custom)
    if cust:
        res["custom"], res["m365_tenant_ids"] = cust
    ct = _read_member(data, members, "[Content_Types].xml", refused, budget)
    if ct and b"macroEnabled" in ct:
        res["content_types_macro"] = True
    for n in [n for n in names if n.endswith(".rels")][:300]:
        for r in _xml_part(data, members, n, refused, budget, ooxml_relationships, n) or []:
            res["relationships"].append(r)
            if r["external"]:
                res["external"].append({"type": r["type"], "part": n, "target": classify_target(r["target"]),
                                        "auto_load": r["type"].lower() in AUTO_LOAD_REL_TYPES})
    res["embedded_objects"] = [n for n in names if "/embeddings/" in n.lower()][:100]
    res["activex"] = any("/activex/" in n.lower() for n in names)
    vba_names = [n for n in names if n.lower().endswith("vbaproject.bin")]
    if vba_names or res["content_types_macro"]:
        res["macros"] = {"present": bool(vba_names), "container": vba_names[:5], "projects": [], "errors": []}
        for vn in vba_names[:3]:
            raw = _read_member(data, members, vn, refused, budget, cap=32 << 20)
            if raw is None:
                continue
            try:
                proj = vba_project_from_cfb(CFB(raw, budget=budget))
                res["macros"]["projects"] += proj["projects"]
                res["macros"]["errors"] += proj["errors"]
            except (ValueError, struct.error, IndexError, ArchiveLimit) as exc:
                res["macros"]["errors"].append(f"vbaProject.bin:{exc}")
    sheet_rels = {r["id"]: r for r in res["relationships"] if r["part"] == "xl/_rels/workbook.xml.rels"}
    wb = _read_member(data, members, "xl/workbook.xml", refused, budget)
    if wb:
        try:
            root = safe_xml_parse(wb)
            for sh in root.iter(f"{{{NS['x']}}}sheet"):
                rel = sheet_rels.get(sh.get(f"{{{NS['r']}}}id"))
                if rel and rel["type"].lower() in ("xlmacrosheet", "xlintlmacrosheet"):
                    res["xlm_sheets"].append({"name": clean_text(sh.get("name"), 64), "state": sh.get("state") or "visible"})
            for dn in root.iter(f"{{{NS['x']}}}definedName"):
                nm = dn.get("name") or ""
                if nm.lower() in ("_xlnm.auto_open", "_xlnm.auto_close") or nm.lower().startswith("auto_open"):
                    res["xlm_autoexec"].append(nm[:64])
        except UnsafeXML as exc:
            refused.append({"part": "xl/workbook.xml", "reason": f"unsafe_xml:{exc.args[0]}"})
        except ValueError:
            refused.append({"part": "xl/workbook.xml", "reason": "malformed_xml"})
    if not res["xlm_sheets"]:
        res["xlm_sheets"] = [{"name": n.rsplit("/", 1)[-1], "state": "unknown"} for n in names
                             if n.lower().startswith("xl/macrosheets/") and n.lower().endswith((".xml", ".bin"))][:50]
    doc = _read_member(data, members, "word/document.xml", refused, budget)
    if doc:
        try:
            for instr in _w_field_instructions(safe_xml_parse(doc)):
                kind, tgt = classify_field(instr)
                if kind == "dde":
                    res["dde"].append(clean_text(instr, 512))
                elif kind == "remote_include":
                    res["remote_fields"].append({"instr": clean_text(instr, 512), "target": classify_target(tgt)})
                elif kind == "hyperlink":
                    res["field_hyperlinks"].append(tgt)
        except UnsafeXML as exc:
            refused.append({"part": "word/document.xml", "reason": f"unsafe_xml:{exc.args[0]}"})
        except ValueError:
            refused.append({"part": "word/document.xml", "reason": "malformed_xml"})
            if re.search(rb"DDE(?:AUTO)?\b", doc):
                res["dde"].append("DDE keyword in an unparsable document.xml")
    for n in [n for n in names if n.lower().startswith("xl/externallinks/") and n.lower().endswith(".xml")][:50]:
        raw = _read_member(data, members, n, refused, budget)
        if raw and b"ddeLink" in raw:
            m = _DDE_LINK.search(raw)
            res["dde"].append(f"ddeLink {m.group(1).decode('latin-1')} {m.group(2).decode('latin-1')}"[:512] if m else "ddeLink")
    cm = _read_member(data, members, "word/comments.xml", refused, budget)
    if cm:
        res["comment_authors"] = sorted(set(_COMMENT_AUTHOR.findall(cm.decode("utf-8", "replace"))))[:20]
    return res


_ODF_META = {"generator": ("meta", "generator"), "title": ("dc", "title"), "subject": ("dc", "subject"), "description": ("dc", "description"),
             "initial_creator": ("meta", "initial-creator"), "creator": ("dc", "creator"), "printed_by": ("meta", "printed-by"),
             "created": ("meta", "creation-date"), "modified": ("dc", "date"), "printed": ("meta", "print-date"),
             "editing_cycles": ("meta", "editing-cycles"), "editing_duration": ("meta", "editing-duration"), "language": ("dc", "language")}
_ODF_AUTO_EVENTS = ("dom:load", "office:load", "onload", "onnew", "office:new", "dom:focus")


def analyse_odf(data: bytes, budget: Budget | None = None) -> dict[str, Any]:
    """ODF (odt/ods/odp) -> meta.xml facts, remote template/auto-reload, links, DDE, macros and auto-exec events."""
    budget = budget or Budget()
    z = zip_scan(data)
    members = _members(z)
    refused: list[dict[str, str]] = []
    res: dict[str, Any] = {"format": "odf", "zip_anomalies": z["anomalies"], "meta": {}, "external": [], "links": [], "dde": [],
                           "macros": {"present": False, "containers": [], "autoexec_events": []}, "encrypted": False, "refused_parts": refused}
    meta = _read_member(data, members, "meta.xml", refused, budget)
    if meta:
        try:
            root = safe_xml_parse(meta)
            m: dict[str, Any] = {}
            for key, (ns, name) in _ODF_META.items():
                el = root.find(f".//{{{NS[ns]}}}{name}")
                if el is not None and (el.text or "").strip():
                    m[key] = clean_text(el.text)
            for tag, kind in (("template", "template"), ("auto-reload", "auto_reload")):
                el = root.find(f".//{{{NS['meta']}}}{tag}")
                href = el.get(f"{{{NS['xlink']}}}href") if el is not None else None
                if href:
                    m[kind] = clean_text(href, 2048)
                    tgt = classify_target(href)
                    if tgt["kind"] not in ("relative", "local_path"):
                        res["external"].append({"type": kind, "part": "meta.xml", "target": tgt, "auto_load": True})
            m["user_defined"] = {clean_text(u.get(f"{{{NS['meta']}}}name"), 128) or "": xml_text(u)
                                 for u in list(root.iter(f"{{{NS['meta']}}}user-defined"))[:200]}
            res["meta"] = m
        except UnsafeXML as exc:
            refused.append({"part": "meta.xml", "reason": f"unsafe_xml:{exc.args[0]}"})
        except ValueError:
            refused.append({"part": "meta.xml", "reason": "malformed_xml"})
    content = _read_member(data, members, "content.xml", refused, budget)
    if content:
        try:
            root = safe_xml_parse(content)
            for el in root.iter():
                href = el.get(f"{{{NS['xlink']}}}href")
                tag = xml_local(el.tag)
                if href and tag == "a":
                    if len(res["links"]) < 500:
                        res["links"].append(clean_text(href, 2048))
                elif href and tag in ("object", "image", "object-ole", "plugin", "applet", "section-source"):
                    tgt = classify_target(href)
                    if tgt["kind"] not in ("relative", "local_path") and len(res["external"]) < 200:
                        res["external"].append({"type": tag, "part": "content.xml", "target": tgt, "auto_load": True})
                elif tag == "event-listener" and href and "vnd.sun.star.script" in href:
                    ev = el.get(f"{{{NS['script']}}}event-name") or ""
                    if ev.lower() in _ODF_AUTO_EVENTS:
                        res["macros"]["autoexec_events"].append(f"{ev} -> {href[:200]}")
                elif tag in ("dde-source", "dde-connection-decl"):
                    res["dde"].append(" ".join(f"{xml_local(k)}={v}" for k, v in el.attrib.items())[:512])
        except UnsafeXML as exc:
            refused.append({"part": "content.xml", "reason": f"unsafe_xml:{exc.args[0]}"})
        except ValueError:
            refused.append({"part": "content.xml", "reason": "malformed_xml"})
    macro_members = [n for n in members if re.match(r"(?i)^(?:basic|scripts)/", n) and not n.endswith("/")]
    script_lc = [n for n in macro_members if n.lower().endswith(("script-lc.xml", "script-lb.xml", "dialog-lc.xml"))]
    code = [n for n in macro_members if n not in script_lc]
    res["macros"]["present"] = bool(code)
    res["macros"]["containers"] = code[:50]
    man = _read_member(data, members, "META-INF/manifest.xml", refused, budget)
    if man and b"encryption-data" in man:
        res["encrypted"] = True
    return res


def analyse_ole_document(data: bytes, budget: Budget | None = None) -> dict[str, Any]:
    """Legacy OLE document (.doc/.xls/.ppt/.msg/encrypted OOXML) -> summary metadata, VBA, XLM, .msg facts."""
    budget = budget or Budget()
    try:
        cfb = CFB(data, budget=budget)
    except (ValueError, struct.error, IndexError, ArchiveLimit) as exc:
        return {"format": "ole", "kind": "ole", "error": f"malformed_ole:{exc}", "summary": {}, "macros": {}}
    kind = ole_subtype([e["name"] for e in cfb.entries if e["type"] in (1, 2)], cfb.root_clsid)
    res: dict[str, Any] = {"format": "ole", "kind": kind, "summary": {}, "macros": {}, "xlm_sheets": [], "xlm_autoexec": [],
                           "encrypted": kind == "ole-encrypted-ooxml", "anomalies": [], "streams": len(cfb.streams()), "msg": None,
                           "embedded_ole": [e["path"] for e in cfb.entries if e["type"] == 1 and e["name"].startswith("_")][:50]}
    try:
        res["summary"] = ole_summary(cfb)
        res["macros"] = vba_project_from_cfb(cfb)
        if kind == "ole-xls":
            wb = cfb.find("Workbook") or cfb.find("Book")
            if wb is not None:
                g = xls_biff_globals(cfb.read(wb, max_out=64 << 20) or b"")
                res["xlm_sheets"] = [s for s in g["sheets"] if s["type"] == "xlm_macro"]
                res["xlm_autoexec"] = g["autoexec_names"]
                res["encrypted"] = res["encrypted"] or g["encrypted"]
                res["sheets"] = g["sheets"][:200]
        if kind == "ole-doc":
            wd = cfb.find("WordDocument")
            if wd is not None:
                fib = (cfb.read(wd, max_out=1 << 20) or b"")[:0x0C]
                if len(fib) >= 0x0C and u16(fib, 0) == 0xA5EC:
                    res["encrypted"] = bool(u16(fib, 0x0A) & 0x0100)  # FIB fEncrypted
        if kind == "ole-msg":
            res["msg"] = msg_parse(cfb)
    except ArchiveLimit as exc:
        res["error"] = f"read_limit:{exc.args[0]}"
    res["anomalies"] = sorted(set(cfb.anomalies))
    return res


_RTF_INFO_KEYS = ("title", "subject", "author", "operator", "company", "manager", "category", "keywords", "comment")
_RTF_OBJCLASS = re.compile(r"\\objclass\s{1,8}([^}\\]{1,64})")
_RTF_DDE = re.compile(r"\\fldinst\s{0,8}\{?[^{}]{0,64}?\bDDE(?:AUTO)?\b", re.I)


def rtf_info(data: bytes, max_bytes: int = 4 << 20) -> dict[str, Any]:
    """RTF {\\info} group (author, operator, company, dates) + embedded objects (\\objdata, \\objupdate) + DDE fields."""
    txt = data[:max_bytes].decode("latin-1")
    out: dict[str, Any] = {}
    for key in _RTF_INFO_KEYS:
        m = re.search(r"\{\\" + key + r"\s{1,8}([^{}]{0,512})\}", txt)
        if m:
            out[key] = clean_text(m.group(1))
    for key in ("creatim", "revtim"):
        m = re.search(r"\{\\" + key + r"\\yr(\d{1,4})\\mo(\d{1,2})\\dy(\d{1,2})(?:\\hr(\d{1,2}))?(?:\\min(\d{1,2}))?", txt)
        if m:
            try:
                out[key] = _dt.datetime(*(int(x or 0) for x in m.groups())).isoformat()
            except ValueError:
                pass
    out["objects"] = len(re.findall(r"\\object\b", txt))
    out["objdata"] = len(re.findall(r"\\objdata\b", txt))
    out["objupdate"] = re.search(r"\\objupdate\b", txt) is not None
    out["ole_classes"] = sorted({c.strip() for c in _RTF_OBJCLASS.findall(txt)})[:20]
    out["equation_editor"] = re.search(r"(?i)equation\.3|0002ce02-0000-0000-c000-000000000046", txt) is not None
    out["dde"] = [clean_text(m.group(0), 200) for m in _RTF_DDE.finditer(txt)][:10]
    return out


def analyse_rtf(data: bytes) -> dict[str, Any]:
    info = rtf_info(data)
    return {"format": "rtf", "rtf": info, "dde": info.get("dde") or []}


# ======================================================================================== severity table, pivots, export view

CRITERIA = {
    "remote_template": "external relationship loaded when the document opens (TargetMode=External attachedTemplate/frame/oleObject..., remote INCLUDE field, UNC/WebDAV/mhtml target): template injection, T1221",
    "external_hyperlinks": "TargetMode=External hyperlinks and HYPERLINK fields (click-only)",
    "macro_autoexec": "an auto-exec procedure (AutoOpen, Document_Open, Workbook_Open, ActiveX events) in the decompressed VBA source or an ODF on-load script binding",
    "macro_present": "a VBA project (vbaProject.bin / Macros/VBA) or ODF Basic/script container is present",
    "xlm_macro": "Excel 4.0 macro sheets (BOUNDSHEET type 1 / xlMacrosheet relationship) or an Auto_Open defined name",
    "dde_field": "DDE/DDEAUTO field codes, Excel ddeLink or ODF DDE connections",
    "part_refused": "the safe XML/archive helpers refused a part (DOCTYPE/ENTITY, ratio or size cap)",
    "pdf_auto_action": "/OpenAction or /AA resolved to a /JavaScript or /Launch action",
    "pdf_auto_action_raw": "/OpenAction or /AA keywords co-occur with /JavaScript or /Launch (raw keyword counts only)",
    "pdf_active_content": "/JavaScript or /Launch present without an automatic trigger",
    "pdf_embedded_file": "/EmbeddedFile streams in the PDF",
    "pdf_name_obfuscation": "PDF names written with #xx hex escapes (/J#61vaScript): a pdfid obfuscation signal",
    "rtf_object": "\\object/\\objdata groups in the RTF; \\objupdate with Equation Editor or OLE2Link auto-updates on open (T1203)",
    "executable_attachment": "an attachment sniffed as executable content (P270 table)",
    "parse_error": "the document structure could not be parsed",
    "encrypted": "an encryption dictionary, an EncryptedPackage stream or encryption flags",
}


def _target_pivots(tgt: dict[str, Any], relation: str) -> list[dict[str, Any]]:
    out = []
    if tgt.get("url"):
        out.append({"type": T.URL, "value": tgt["url"], "relation": relation, "kind": tgt["kind"]})
    if tgt.get("ip"):
        out.append({"type": T.IPV4 if "." in tgt["ip"] else T.IPV6, "value": tgt["ip"], "relation": relation, "kind": tgt["kind"]})
    elif tgt.get("host") and "." in tgt["host"]:
        out.append({"type": T.DOMAIN, "value": tgt["host"].lower(), "relation": relation, "kind": tgt["kind"]})
    return out


def _shown_target(tgt: dict[str, Any]) -> str:
    if tgt.get("url"):
        return clean_text(tgt["url"], 160) or ""
    if tgt.get("host"):
        return f"\\\\{tgt['host']}\\..."
    return clean_text(tgt.get("raw"), 120) or ""


def document_findings_and_pivots(res: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Map an analyse_* result onto the c9 severity table (findings) and the c8/c10 pivots."""
    out_f: list[dict[str, Any]] = []
    pv: list[dict[str, Any]] = []
    externals = list(res.get("external") or []) + [{"type": "field", "part": "word/document.xml", "target": f["target"], "auto_load": True}
                                                   for f in res.get("remote_fields") or []]
    hyperlinks = 0
    for ext in externals:
        tgt = ext["target"]
        dangerous = tgt["kind"] in ("unc", "webdav", "mhtml", "protocol_handler")
        auto = bool(ext.get("auto_load")) or dangerous
        pv += _target_pivots(tgt, "remote_template" if auto else "external_hyperlink")
        if auto:
            out_f.append(fact("remote_template", "high", f"Suspicious remote template / external {ext['type']} ({tgt['kind']})",
                              confidence="probable", attack="T1221", criterion=CRITERIA["remote_template"], tags=["suspicious", "remote_template", "maldoc"],
                              description=f"{_shown_target(tgt)} in {ext['part']}: loaded when the document opens. Never fetched or resolved by V3LUM.",
                              part=ext["part"], target_kind=tgt["kind"], target=tgt.get("url") or tgt.get("host")))
        else:
            hyperlinks += 1
    for link in list(res.get("links") or []) + list(res.get("field_hyperlinks") or []) + list(res.get("summary", {}).get("hyperlinks") or []):
        tgt = classify_target(link)
        if tgt["kind"] in ("unc", "webdav"):
            pv += _target_pivots(tgt, "remote_template")
            out_f.append(fact("remote_template", "high", f"Suspicious {tgt['kind'].upper()} link (credential leak on click)", confidence="probable",
                              attack="T1221", criterion=CRITERIA["remote_template"], tags=["suspicious", "remote_template", "maldoc"],
                              description=f"{_shown_target(tgt)}: Windows sends NTLM credentials to UNC/WebDAV hosts. Never contacted by V3LUM.",
                              target_kind=tgt["kind"], target=tgt.get("host")))
        elif tgt["kind"] == "url":
            hyperlinks += 1
            pv += _target_pivots(tgt, "external_hyperlink")
    if hyperlinks:
        out_f.append(fact("external_hyperlinks", "info", "External hyperlinks (url pivots, never fetched)", confidence="confirmed",
                          criterion=CRITERIA["external_hyperlinks"], description=f"{hyperlinks} click-only external hyperlink(s).", count=hyperlinks))
    macros = res.get("macros") or {}
    modules = [m for p in macros.get("projects", []) for m in p.get("modules", [])]
    auto = sorted({a for m in modules for a in m.get("autoexec", [])})
    sus = sorted({s for m in modules for s in m.get("suspicious", [])})
    odf_auto = macros.get("autoexec_events") or []
    if auto or odf_auto:
        out_f.append(fact("macro_autoexec", "high", "Suspicious auto-exec macro", confidence="probable", attack="T1059.005",
                          criterion=CRITERIA["macro_autoexec"], tags=["suspicious", "maldoc"],
                          description=f"{', '.join(auto or odf_auto)[:200]}" + (f"; keywords: {', '.join(sus)[:200]}" if sus else "")
                                      + ". Macros were decompressed and read as text, never executed.",
                          autoexec=auto or odf_auto, suspicious_keywords=sus))
    elif macros.get("present"):
        out_f.append(fact("macro_present", "medium", "Macro present (not executed)", confidence="confirmed", criterion=CRITERIA["macro_present"],
                          tags=["maldoc"], description=(f"Keywords: {', '.join(sus)[:200]}." if sus else "No auto-exec procedure found."),
                          suspicious_keywords=sus))
    for m in modules:
        for u in (m.get("iocs") or {}).get("urls", [])[:50]:
            pv.append({"type": T.URL, "value": u, "relation": "macro_string"})
    xlm = res.get("xlm_sheets") or []
    if xlm or res.get("xlm_autoexec"):
        states = sorted({s.get("state", "unknown") for s in xlm})
        out_f.append(fact("xlm_macro", "high", "Suspicious Excel 4.0 (XLM) macro sheet", confidence="probable", attack="T1059",
                          criterion=CRITERIA["xlm_macro"], tags=["suspicious", "maldoc"],
                          description=f"{len(xlm)} macro sheet(s) ({', '.join(states) or 'state unknown'}); auto-exec names: "
                                      f"{', '.join(res.get('xlm_autoexec') or []) or 'none'}.",
                          sheets=xlm[:20], autoexec=res.get("xlm_autoexec") or []))
    if res.get("dde"):
        out_f.append(fact("dde_field", "high", "Suspicious DDE field", confidence="probable", attack="T1559.002", criterion=CRITERIA["dde_field"],
                          tags=["suspicious", "maldoc"], description=clean_text(res["dde"][0], 200) or "", count=len(res["dde"])))
    for r in (res.get("refused_parts") or [])[:20]:
        bad = r["reason"].startswith(("unsafe_xml", "ratio", "size_cap", "total_cap", "read_budget"))
        out_f.append(fact("part_refused", "medium" if bad else "low", f"Part not parsed: {clean_text(r['part'], 120)} ({r['reason']})",
                          confidence="confirmed", criterion=CRITERIA["part_refused"], tags=["maldoc"] if bad else [], part=r["part"], reason=r["reason"]))
    if res.get("format") == "pdf":
        out_f += pdf_findings(res)
        for u in res.get("uris") or []:
            pv.append({"type": T.URL, "value": u, "relation": "pdf_link"})
    if res.get("encrypted"):
        out_f.append(fact("encrypted", "info", "Encrypted document (not decrypted)", confidence="confirmed", criterion=CRITERIA["encrypted"],
                          description="Analysed without decryption: passwords are never guessed (metadata strings of encrypted PDFs are ciphertext)."))
    rtf = res.get("rtf") or {}
    if rtf.get("objects") or rtf.get("objdata"):
        classes = rtf.get("ole_classes") or []
        risky = bool(rtf.get("objupdate")) and (bool(rtf.get("equation_editor")) or any("ole2link" in c.lower() for c in classes))
        out_f.append(fact("rtf_object", "high" if risky else "medium",
                          "Suspicious auto-updating embedded OLE object" if risky else "Embedded OLE object in RTF",
                          confidence="probable", attack="T1203" if risky else None, criterion=CRITERIA["rtf_object"],
                          tags=["suspicious", "maldoc"] if risky else ["maldoc"],
                          description=f"Class: {', '.join(classes) or 'unknown'}; {rtf.get('objects', 0)} object(s).", classes=classes))
    msg = res.get("msg") or {}
    for att in msg.get("attachments", []):
        for f in att.get("findings", []):
            f["detail"]["attachment"] = att["name"]
            f["title"] = f"{f['title']} (attachment {clean_text(att['name'], 80)})"
            out_f.append(f)
        if att.get("kind") in EXECUTABLE_KINDS:
            out_f.append(fact("executable_attachment", "medium", f"Executable attachment: {clean_text(att['name'], 120)}", confidence="confirmed",
                              criterion=CRITERIA["executable_attachment"], tags=["suspicious"], description=f"Sniffed as {att['kind']}.",
                              sha256=att.get("sha256"), kind=att.get("kind")))
        if att.get("sha256"):
            pv.append({"type": T.SHA256, "value": att["sha256"], "relation": "attachment", "member": att["name"]})
    for u in (msg.get("body_iocs") or {}).get("urls", [])[:100]:
        pv.append({"type": T.URL, "value": u, "relation": "link_in_message"})
    if msg.get("sender_name"):
        pv += [dict(p, relation="message_sender") for p in author_pivots(msg["sender_name"], "sender_name")]
    meta = document_metadata_fields(res)
    for field in ("author", "last_modified_by"):
        values = meta.get(field)
        for v in ([values] if isinstance(values, str) else values or []):
            pv += author_pivots(v, field)
    for v in res.get("comment_authors") or []:
        pv += [dict(p, role="commenter") for p in author_pivots(v, "comment_author")]
    for u in extract_user_paths(*_all_strings(res)):
        if not u["generic"]:
            pv.append({"type": T.USERNAME, "value": u["user"], "relation": "local_account"})
    seen: set[tuple[Any, ...]] = set()
    uniq = []
    for p in pv:
        key = (p["type"], str(p["value"]).lower(), p["relation"])
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    return out_f, uniq


def pdf_findings(facts: dict[str, Any]) -> list[dict[str, Any]]:
    """PDF rows of the severity table: (/Launch or /JavaScript) run by /OpenAction or /AA = HIGH,
    /EmbeddedFile = MEDIUM; raw keyword co-occurrence only = HIGH at POSSIBLE confidence."""
    out = []
    oa = facts.get("open_action") or {}
    aa = facts.get("aa_triggers") or []
    kw = (facts.get("counts") or {}).get("keywords") or {}
    auto_js = oa.get("type") == "javascript" or any(t.get("type") == "javascript" for t in aa)
    auto_launch = oa.get("type") == "launch" or any(t.get("type") == "launch" for t in aa)
    launch = facts.get("launch") or []
    if auto_js or auto_launch:
        what = " + ".join(x for x, f in (("/JavaScript", auto_js), ("/Launch", auto_launch)) if f)
        out.append(fact("pdf_auto_action", "high", f"Suspicious {what} run by /OpenAction or /AA", confidence="probable",
                        attack="T1059.007" if auto_js else "T1204.002", criterion=CRITERIA["pdf_auto_action"], tags=["suspicious", "maldoc"],
                        description="Runs when the document opens." + (f" Launch target: {launch[0].get('file', '')}" if launch else ""),
                        launch=launch[:5]))
    elif (kw.get("/OpenAction", 0) + kw.get("/AA", 0)) and (kw.get("/JavaScript", 0) + kw.get("/JS", 0) + kw.get("/Launch", 0)):
        out.append(fact("pdf_auto_action", "high", "Suspicious /OpenAction with /JavaScript or /Launch keywords", confidence="possible",
                        attack="T1059.007", criterion=CRITERIA["pdf_auto_action_raw"], tags=["suspicious", "maldoc"],
                        description="The action could not be resolved structurally (encrypted or obfuscated objects): keyword co-occurrence only."))
    elif kw.get("/JavaScript") or kw.get("/JS") or kw.get("/Launch") or launch:
        out.append(fact("pdf_active_content", "medium", "JavaScript or /Launch present (not auto-run)", confidence="possible",
                        criterion=CRITERIA["pdf_active_content"], tags=["maldoc"], launch=launch[:5]))
    if facts.get("embedded_files") or kw.get("/EmbeddedFile"):
        names = [n for n in facts.get("embedded_files") or [] if n][:10]
        out.append(fact("pdf_embedded_file", "medium", "Embedded file in PDF", confidence="confirmed" if names else "probable",
                        criterion=CRITERIA["pdf_embedded_file"], tags=["maldoc"], description=", ".join(names) or "embedded file present",
                        names=names))
    obf = (facts.get("counts") or {}).get("obfuscated_names") or {}
    if obf:
        out.append(fact("pdf_name_obfuscation", "medium", "Hex-obfuscated PDF names", confidence="probable", attack="T1027",
                        criterion=CRITERIA["pdf_name_obfuscation"], tags=["suspicious", "maldoc"], description=", ".join(sorted(obf)),
                        names=sorted(obf)))
    return out


def document_metadata_fields(res: dict[str, Any]) -> dict[str, Any]:
    """Uniform INFO attributes across formats: author, last_modified_by, company, application, template, dates."""
    fmt = res.get("format")
    if fmt == "pdf":
        xmp = res.get("xmp") or {}
        authors = [a for a in [res.get("author"), *list(xmp.get("creators") or [])] if a]
        return {"format": "pdf", "author": list(dict.fromkeys(authors)), "last_modified_by": None, "company": None,
                "application": res.get("creator_tool") or xmp.get("creator_tool"), "producer": res.get("producer") or xmp.get("producer"),
                "created": res.get("created") or xmp.get("create_date"), "modified": res.get("modified") or xmp.get("modify_date"),
                "title": res.get("title") or xmp.get("title"), "subject": res.get("subject"), "keywords": res.get("keywords"),
                "pages": res.get("pages"), "document_id": xmp.get("document_id"), "instance_id": xmp.get("instance_id"),
                "xmp_history": (xmp.get("history") or [])[:20] or None, "encrypted": res.get("encrypted")}
    if fmt == "ooxml":
        c, a = res.get("core", {}), res.get("app", {})
        return {"format": "ooxml", "author": c.get("author"), "last_modified_by": c.get("last_modified_by"), "company": a.get("Company"),
                "application": " ".join(x for x in (a.get("Application"), a.get("AppVersion")) if x) or None, "template": a.get("Template"),
                "created": c.get("created"), "modified": c.get("modified"), "title": c.get("title"), "subject": c.get("subject"),
                "keywords": c.get("keywords"), "revision": c.get("revision"), "last_printed": c.get("last_printed"),
                "total_edit_minutes": a.get("TotalTime"), "pages": a.get("Pages"), "manager": a.get("Manager"),
                "hyperlink_base": a.get("HyperlinkBase"), "m365_tenant_ids": res.get("m365_tenant_ids") or None,
                "custom_properties": len(res.get("custom") or {}) or None}
    if fmt == "odf":
        m = res.get("meta", {})
        return {"format": "odf", "author": m.get("initial_creator"), "last_modified_by": m.get("creator"), "company": None,
                "application": m.get("generator"), "template": m.get("template"), "created": m.get("created"), "modified": m.get("modified"),
                "title": m.get("title"), "printed_by": m.get("printed_by"), "editing_cycles": m.get("editing_cycles"),
                "encrypted": res.get("encrypted")}
    if fmt == "rtf":
        r = res.get("rtf", {})
        return {"format": "rtf", "author": r.get("author"), "last_modified_by": r.get("operator"), "company": r.get("company"),
                "application": None, "template": None, "created": r.get("creatim"), "modified": r.get("revtim"), "title": r.get("title"),
                "manager": r.get("manager")}
    if fmt == "ole" and res.get("msg"):
        m = res["msg"]
        return {"format": "msg", "title": m.get("subject"), "sender": m.get("sender_name"), "sender_address": m.get("sender_address"),
                "message_id": m.get("internet_message_id"), "recipients": m.get("recipients"), "attachments": len(m.get("attachments", [])),
                "transport_headers_present": m.get("transport_headers_present")}
    if fmt == "ole":
        s = res.get("summary", {})
        return {"format": res.get("kind") or "ole", "author": s.get("author"), "last_modified_by": s.get("last_saved_by"),
                "company": s.get("company"), "application": s.get("app_name"), "template": s.get("template"), "created": s.get("created"),
                "modified": s.get("last_saved"), "title": s.get("title"), "subject": s.get("subject"), "manager": s.get("manager"),
                "revision": s.get("revision"), "total_edit_minutes": s.get("edit_time_minutes"), "app_version": s.get("app_version"),
                "pages": s.get("pages"), "encrypted": res.get("encrypted")}
    return {}


def _all_strings(obj: Any, depth: int = 0) -> Any:
    if depth > 6:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _all_strings(v, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj[:500]:
            yield from _all_strings(v, depth + 1)


_REDACT_USER_PATH = re.compile(r"(?i)(\b[A-Z]:[\\/]{1,4}(?:Users|Documents and Settings)[\\/]{1,4})([^\\/:*?\"<>|\r\n]{1,64})")
_REDACT_UNIX_PATH = re.compile(r"(?i)((?<![\w.])/(?:Users|home)/)([A-Za-z0-9._ -]{1,64})")
PERSONAL_FIELDS = ("author", "last_modified_by", "manager", "sender", "sender_address", "printed_by")
PERSONAL_RELATIONS = frozenset({"document_author", "local_account", "message_sender"})


def redact_for_export(meta: dict[str, Any], pivots: list[dict[str, Any]], *, include_personal: bool = False) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """c11 STIX/MISP view: internal paths, usernames and author names redacted unless --include-personal
    (which the exporter records). Hostile remote-template IOCs stay."""
    if include_personal:
        return dict(meta), list(pivots)
    out: dict[str, Any] = {}
    for k, v in meta.items():
        if k in PERSONAL_FIELDS:
            out[k] = "[redacted]" if v else v
        elif isinstance(v, str):
            out[k] = _REDACT_UNIX_PATH.sub(r"\1[redacted]", _REDACT_USER_PATH.sub(r"\1[redacted]", v))
        else:
            out[k] = v
    kept = [p for p in pivots if p.get("relation") not in PERSONAL_RELATIONS and p.get("type") not in (T.USERNAME, T.PERSON)]
    return out, kept


def document_summary_line(meta: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    """c11: one line per document: format | application | author | company | top severity: codes."""
    top = max((f["severity"] for f in findings), key=lambda s: SEVERITY_ORDER.get(s, 0), default="info")
    parts = [str(meta.get("format") or "document")]
    if meta.get("application"):
        parts.append(str(meta["application"])[:40])
    authors = meta.get("author")
    if authors:
        parts.append("author: " + (authors if isinstance(authors, str) else ", ".join(authors[:2]))[:40])
    if meta.get("company"):
        parts.append("company: " + str(meta["company"])[:30])
    codes = sorted({f["code"] for f in findings if f["severity"] in ("high", "medium", "critical")})
    parts.append(f"{top.upper()}: {', '.join(codes)}" if codes else "no findings")
    return " | ".join(parts)


def analyse_document(data: bytes, kind: str) -> dict[str, Any]:
    """Dispatch on the P270 kind; one read budget per file."""
    budget = Budget()
    if kind == "pdf":
        return analyse_pdf(data, budget)
    if kind.startswith("ooxml-"):
        return analyse_ooxml(data, budget)
    if kind.startswith("odf-") or kind == "epub":
        return analyse_odf(data, budget)
    if kind.startswith("ole"):
        return analyse_ole_document(data, budget)
    if kind == "rtf":
        return analyse_rtf(data)
    return {"format": kind, "error": f"unsupported_kind:{kind}"}


# ======================================================================================== the module


def _personal_note(p: dict[str, Any]) -> str:
    if p["relation"] == "local_account":
        return "personal data (privacy): account name from a user-profile path in the document metadata - analyst selection only, never auto-checked"
    if p["relation"] == "message_sender":
        return "personal data (privacy): sender of the message file - analyst selection only, never auto-checked"
    role = " (commenter)" if p.get("role") == "commenter" else ""
    dom = f" (Windows domain {p['windows_domain']})" if p.get("windows_domain") else ""
    return f"personal data (privacy): {p.get('field', 'author')}{role} from the document metadata{dom} - analyst selection only, never auto-checked"


_PIVOT_NOTES = {
    "remote_template": "remote template / external relationship (T1221): hostile, passive modules only, never fetched or resolved by V3LUM",
    "external_hyperlink": "external hyperlink of the document: passive modules only, never fetched",
    "macro_string": "URL in macro source (macro never executed): hostile candidate, passive modules only",
    "pdf_link": "PDF URI action target: passive modules only, never fetched",
    "link_in_message": "URL in the message body: hostile candidate, passive modules only",
    "attachment": "attachment hashed locally from the .msg (never opened or executed)",
}


@register
class DocumentMetadata(Module):
    name = "document_metadata"
    title = "Document metadata and maldoc indicators (PDF/Office/RTF/.msg)"
    description = (
        "Extracts authors, software, dates, templates and internal paths from local PDF, OOXML, ODF, OLE (.doc/.xls/.ppt), "
        "RTF and Outlook .msg files and flags remote templates (T1221), auto-exec macros, XLM, DDE and auto-run PDF actions. "
        "Offline: nothing is executed, rendered, decrypted or fetched."
    )
    category = "file_analysis"
    accepts = {T.FILE, T.URL}
    produces = {T.USERNAME, T.PERSON, T.URL, T.DOMAIN, T.IPV4, T.SHA256}
    tags = {"offline"}
    reference = "https://attack.mitre.org/techniques/T1221/"
    notice = ("FILE input only: URLs are never downloaded by this module (the shared LIGHT file fetcher is not available yet). "
              "Author names and account names are personal data: pivots are analyst-selected only and redacted in external exports "
              "unless --include-personal.")
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.3
    timeout = 30.0
    max_pivots = 200
    manual_link = MANUAL_LINK
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.URL:
            return bool(ctx.is_seed)  # c1/c4: analyst-typed URLs get the manual link; URL pivots never run this module
        return entity.type is T.FILE

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type is T.URL:
            return self._url(entity, res)
        try:
            sn = sniff_path(entity.value)
        except FileRefused as exc:
            return res.mark("error" if exc.kind == "unreadable" else "skipped", exc.reason,
                            reason_code="error" if exc.kind == "unreadable" else "not_applicable")
        if self.name not in sn["routes"]:
            return res.mark("skipped", f"not a document ({sn['description']})", reason_code="not_applicable")
        try:
            data, size = read_capped(entity.value, LIMITS["max_input"])
        except FileRefused as exc:
            return res.mark("error", exc.reason)
        analysis = analyse_document(data, sn["kind"])
        findings, pivots = document_findings_and_pivots(analysis)
        meta = {k: v for k, v in document_metadata_fields(analysis).items() if v not in (None, "", [], {})}
        if size > len(data):
            findings.append(fact("parse_error", "low", "Document larger than the 100 MB input cap: only the first 100 MB were parsed",
                                 confidence="confirmed", criterion=CRITERIA["parse_error"], size=size))
        summary = document_summary_line(meta, findings)
        self._attributes(res, sn, analysis, meta, summary, pivots)
        res.finding(f"Document metadata: {meta.get('format', sn['kind'])}", "info", summary, confidence="confirmed",
                    data={"kind": sn["kind"], "metadata": meta}, tags=["info"])
        emit_findings(res, findings)
        self._pivots(res, pivots)
        res.raw = cap_json({"kind": sn["kind"], "analysis": analysis, "summary": summary})
        error = analysis.get("error")
        substantive = set(meta) - {"format", "encrypted"}
        if error and not substantive and not findings and not pivots:  # nothing read: could not verify, never 'empty'
            return res.mark("error", f"document not parsed: {error}")
        return res

    def _url(self, entity: Entity, res: ModuleResult) -> ModuleResult:
        from v3lum.core import links as _links

        rendered = _links.render_manual(self.manual_link, entity)
        if rendered is not None:
            res.link(rendered.label, rendered.url)
        return res.mark("skipped", "document URLs are never downloaded by this passive module: the shared LIGHT file fetcher "
                                   "(--mode light) is not available yet - use the archived-copy link", reason_code="opsec")

    def _attributes(self, res: ModuleResult, sn: dict[str, Any], analysis: dict[str, Any], meta: dict[str, Any], summary: str,
                    pivots: list[dict[str, Any]]) -> None:
        res.attr("file_type", sn["description"])
        res.attr("document_metadata", cap_json(meta, 64 * 1024))
        res.attr("document_summary", summary)
        authors = meta.get("author")
        res.attr("document_author", authors if isinstance(authors, list) else [authors] if authors else None)
        res.attr("document_last_modified_by", meta.get("last_modified_by"))
        res.attr("document_company", meta.get("company"))
        targets = []
        for ext in analysis.get("external") or []:
            tgt = ext["target"]
            targets.append({"type": ext["type"], "target_kind": tgt["kind"], "target": tgt.get("url") or tgt.get("host") or tgt.get("raw"),
                            "auto_load": bool(ext.get("auto_load")), "part": ext.get("part")})
        for f in analysis.get("remote_fields") or []:
            targets.append({"type": "field", "target_kind": f["target"]["kind"], "target": f["target"].get("url") or f["target"].get("raw"),
                            "auto_load": True, "part": "word/document.xml"})
        res.attr("document_external_targets", targets[:200])
        macros = analysis.get("macros") or {}
        modules = [m for p in macros.get("projects", []) for m in p.get("modules", [])]
        if macros.get("present") or analysis.get("xlm_sheets") or analysis.get("dde"):
            res.attr("document_macros", cap_json({
                "present": bool(macros.get("present")),
                "modules": [{k: m.get(k) for k in ("name", "type", "source_len", "autoexec", "suspicious", "error")} for m in modules][:100],
                "autoexec_events": macros.get("autoexec_events") or None, "xlm_sheets": analysis.get("xlm_sheets") or None,
                "xlm_autoexec": analysis.get("xlm_autoexec") or None, "dde": analysis.get("dde") or None}, 64 * 1024))
        if analysis.get("format") == "pdf":
            res.attr("pdf_structure", cap_json({k: analysis.get(k) for k in ("counts", "streams", "open_action", "aa_triggers", "launch",
                                                                             "embedded_files", "info_source", "encrypted", "errors")}, 64 * 1024))
        msg = analysis.get("msg") or {}
        if msg.get("attachments"):
            res.attr("email_attachments", [{"filename": a["name"], "declared_type": a.get("mime"), "size": a["size"], "sha256": a.get("sha256"),
                                            "kind": a.get("kind")} for a in msg["attachments"]][:50])

    def _pivots(self, res: ModuleResult, pivots: list[dict[str, Any]]) -> None:
        kept = 0
        for p in pivots:
            if kept >= self.max_pivots:
                break
            personal = p["relation"] in PERSONAL_RELATIONS
            if personal:
                ent = res.pivot(p["type"], p["value"], p["relation"], confidence="probable", expand=False, note=_personal_note(p))
            else:
                note = _PIVOT_NOTES.get(p["relation"], "found in the document")
                if p.get("member"):
                    note = f"{note}: {clean_text(p['member'], 120)}"
                ent = res.pivot(p["type"], p["value"], p["relation"], confidence="confirmed", note=note)
            if ent is not None:
                kept += 1


__all__ = [
    "DocumentMetadata",
    "analyse_document",
    "analyse_odf",
    "analyse_ole_document",
    "analyse_ooxml",
    "analyse_pdf",
    "analyse_rtf",
    "author_pivots",
    "classify_target",
    "document_findings_and_pivots",
    "document_metadata_fields",
    "document_summary_line",
    "extract_user_paths",
    "msg_parse",
    "parse_xmp",
    "pdf_date_to_iso",
    "pdf_keyword_counts",
    "redact_for_export",
    "vba_decompress",
    "xls_biff_globals",
]
