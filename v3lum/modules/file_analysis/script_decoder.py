"""Static script de-obfuscation for IOC extraction (P366, batch p2-G12-2).

c1: offline (disclosure 'none', ctx.http refuses every request, terms 'open', tier n/a, allowed at TLP:RED).
Pure-Python static decoders only: nothing here evaluates, executes, compiles or emulates the script; there is no
PowerShell/JScript/VBScript engine and no subprocess (a unit test walks this file's AST to prove it).

c2 techniques (one technique per layer, all its occurrences, in ``SD_ORDER`` priority):
UTF-16LE base64 of -EncodedCommand (every unambiguous prefix -e ... -EncodedCommand, '/' and en/em-dash
prefixes), ``FromBase64String`` (UTF-8/UTF-16LE autodetect; gzip or DeflateStream payloads inflated within the cap;
binary payloads hashed, never inlined), char-code joins (``[char]NN+...``, ``[char[]](...)``,
``String.fromCharCode``), ``unescape``/%u and ``decodeURI*``, VBS ``Chr``/``ChrW``/``ChrB``, JS escapes, hex blobs
(hash-length runs skipped unless 0x-prefixed), simple string concatenation (a linear scanner, no regex) and quoted
base64 literals that decode to clean text. cmd ``^`` carets and PowerShell backticks are normalised first.

c3 bounds: at most 5 layers, 1 MB of text per layer (the input is cut to the same cap) and a 5 s total time
budget; every regex is linear by construction and passes the ReDoS fuzz test.

c4: each layer is recorded in evidence (``res.raw['layers']``) after the central redactor (``sanitize.scrub_text``
then ``redact.redact_text``: passwords dropped, secrets fingerprinted, configured keys and key-like URL parameters
masked) and shown as defanged plain text with its technique ('layer 1: base64 UTF-16LE -EncodedCommand'),
truncated in the ``decoded_layers`` attribute and complete in evidence.

c5: each decoded layer goes to the shared P172 extractor (``v3lum.core.ioc.extract``); IOCs first seen in a
decoded layer become pivots with relation ``extracted_from``, the note naming the layer path (provenance) and
'decoded'. Schema, namespace and documentation hosts and library CDNs (``NAMESPACE_AND_CDN_HOSTS``) and values the
P169 warninglists flag are filtered first. IOCs already visible in the input are left to the generic extractor.

c6: URLs and hosts of a decoded download cradle (DownloadString, Invoke-WebRequest, certutil -urlcache, BITS,
XMLHTTP, curl/wget, mshta http...) are hostile IOCs for passive modules only: nothing in this module contacts them
and their pivot note says so (the P376 guard keeps LIGHT/ACTIVE contact away from values extracted from text).
``decode_layers`` and ``extract_decoded_iocs`` are the reusable API for P367 (LNK, MSI, OneNote), P365 and pasted
EDR command lines.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import time
import zlib
from collections.abc import Callable, Iterable
from typing import Any
from urllib.parse import urlsplit

from v3lum.core import ioc as _ioc
from v3lum.core import psl
from v3lum.core.entities import IOC_TYPES, PERSONAL_TYPES, SECRET_TYPES, Entity, defang
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.core.redact import redact_text
from v3lum.core.sanitize import scrub_text

SD_MAX_LAYERS = 5  # c3
SD_MAX_LAYER_BYTES = 1_000_000  # c3
SD_TIME_BUDGET_S = 5.0  # c3
SD_MIN_PRINTABLE = 0.85
SD_TECHNIQUE_LABELS = {  # c2/c4 (labels shown as 'layer N: <label>')
    "ps_encodedcommand": "base64 UTF-16LE -EncodedCommand",
    "frombase64string": "base64 FromBase64String",
    "char_codes": "char-code join ([char]NN, [char[]](...), String.fromCharCode)",
    "vbs_chr": "VBS Chr/ChrW concatenation",
    "unescape": "unescape %uXXXX/%XX",
    "js_escapes": "\\xNN/\\uNNNN string escapes",
    "hex_blob": "hex blob",
    "concat": "string concatenation",
    "base64_literal": "base64 string literal",
    "normalise": "normalise cmd ^ carets / PowerShell backticks",
}
SD_ORDER = ("ps_encodedcommand", "frombase64string", "char_codes", "vbs_chr", "unescape", "js_escapes", "hex_blob",
            "concat", "base64_literal")
_SD_HASH_HEX_LENS = frozenset({32, 40, 56, 64, 96, 128})
_SD_PS_ENC_RE = re.compile(
    r"(?:^|(?<=[\s\"'(]))[-/–—―](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco"
    r"|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)(?![\w-])[\s:]{0,20}[\"']?"
    r"([A-Za-z0-9+/]{8,}={0,2})", re.I)
_SD_FROMB64_RE = re.compile(
    r"(?:\[(?:System\.)?Convert\]::)?FromBase64String\(\s*(?:'([A-Za-z0-9+/=\s]{8,})'|\"([A-Za-z0-9+/=\s]{8,})\")\s*\)", re.I)
_SD_NUM = r"(?:0x[0-9a-f]{1,6}|\d{1,7})"
_SD_NUMLIST = _SD_NUM + r"(?:\s*,\s*" + _SD_NUM + r")*"
_SD_PS_CHARARRAY_RE = re.compile(r"\[char\[\]\]\s*\(\s*(" + _SD_NUMLIST + r")\s*\)", re.I)
_SD_PS_CHARCHAIN_RE = re.compile(r"\[char\]\s*" + _SD_NUM + r"(?:\s*\+\s*\[char\]\s*" + _SD_NUM + r")+", re.I)
_SD_PS_CHARITEM_RE = re.compile(r"\[char\]\s*(" + _SD_NUM + r")", re.I)
_SD_JS_FROMCHARCODE_RE = re.compile(r"String\.fromCharCode\(\s*(" + _SD_NUMLIST + r")\s*\)", re.I)
_SD_NUM_ITEM_RE = re.compile(_SD_NUM, re.I)
_SD_VBS_ARG = r"(?:&H[0-9a-f]{1,6}|\d{1,7})(?:\s*[-+*]\s*(?:&H[0-9a-f]{1,6}|\d{1,7}))?"
_SD_VBS_CHR = r"Chr[WB]?\$?\(\s*" + _SD_VBS_ARG + r"\s*\)"
_SD_VBS_CHAIN_RE = re.compile(_SD_VBS_CHR + r"(?:\s*[&+]\s*" + _SD_VBS_CHR + r")+", re.I)
_SD_VBS_ITEM_RE = re.compile(r"Chr[WB]?\$?\(\s*(" + _SD_VBS_ARG + r")\s*\)", re.I)
_SD_VBS_TERM_RE = re.compile(r"&H[0-9a-f]{1,6}|\d{1,7}|[-+*]", re.I)
_SD_UNESCAPE_RE = re.compile(r"(unescape|decodeURIComponent|decodeURI)\(\s*(?:'([^'\r\n]+)'|\"([^\"\r\n]+)\")\s*\)", re.I)
_SD_PCT_RE = re.compile(r"%u([0-9a-fA-F]{4})|%([0-9a-fA-F]{2})")
_SD_PCT_TOKEN_RE = re.compile(r"%u([0-9a-fA-F]{4})|%([0-9a-fA-F]{2})|[^%]+|%")
_SD_JS_ESC_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]{1,6}\}){4,}")
_SD_JS_ESC_ITEM_RE = re.compile(r"\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})|\\u\{([0-9a-fA-F]{1,6})\}")
_SD_HEX_RE = re.compile(r"(?<![0-9A-Za-z])(?:0x)?([0-9a-fA-F]{16,})(?![0-9A-Za-z])")
_SD_B64_LITERAL_RE = re.compile(r"'([A-Za-z0-9+/]{24,}={0,2})'|\"([A-Za-z0-9+/]{24,}={0,2})\"")
_SD_CARET_RE = re.compile(r"(?<=[A-Za-z0-9])\^+(?=[A-Za-z0-9])")
_SD_TICK_RE = re.compile(r"`(?=[A-Za-z0-9\-])(?![0abfnrtv])")
_SD_CRADLE_RE = re.compile(
    r"DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\birm\b"
    r"|Start-BitsTransfer|Net\.WebClient|bitsadmin|certutil(?:\.exe)?\s[^\r\n]{0,40}-urlcache|MSXML2\.XMLHTTP"
    r"|WinHttp\.WinHttpRequest|\bcurl(?:\.exe)?\s|\bwget\s|mshta(?:\.exe)?\s+https?:", re.I)
#: the PowerShell host token of an -EncodedCommand invocation (path characters are walked back without a regex)
_SD_PS_HOST_RE = re.compile(r"(?<![\w-])(?:powershell|pwsh)(?:\.exe)?(?![\w-])", re.I)
_SD_CMD_SEPARATORS = frozenset("&|;\r\n")
_SD_PATH_STOP = frozenset(" \t\"'&|;\r\n(=,")
#: every compiled pattern of this module (the ReDoS test runs pathological inputs against each)
PATTERNS: tuple[re.Pattern[str], ...] = (
    _SD_PS_ENC_RE, _SD_FROMB64_RE, _SD_PS_CHARARRAY_RE, _SD_PS_CHARCHAIN_RE, _SD_PS_CHARITEM_RE, _SD_JS_FROMCHARCODE_RE,
    _SD_NUM_ITEM_RE, _SD_VBS_CHAIN_RE, _SD_VBS_ITEM_RE, _SD_VBS_TERM_RE, _SD_UNESCAPE_RE, _SD_PCT_RE, _SD_PCT_TOKEN_RE,
    _SD_JS_ESC_RE, _SD_JS_ESC_ITEM_RE, _SD_HEX_RE, _SD_B64_LITERAL_RE, _SD_CARET_RE, _SD_TICK_RE, _SD_CRADLE_RE,
    _SD_PS_HOST_RE,
)  # + the defang patterns below (PATTERNS_ALL)
#: c5: schema, namespace and documentation hosts and common library CDNs (filtered before pivoting, with the
#: P169 warninglist flag of the core extractor)
NAMESPACE_AND_CDN_HOSTS = frozenset({
    "schemas.microsoft.com", "schemas.openxmlformats.org", "schemas.xmlsoap.org", "www.w3.org", "w3.org",
    "go.microsoft.com", "purl.org", "ns.adobe.com", "ajax.googleapis.com", "cdnjs.cloudflare.com", "code.jquery.com",
    "cdn.jsdelivr.net", "unpkg.com", "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com", "fonts.googleapis.com",
    "fonts.gstatic.com", "xmlns.com", "ogp.me", "schema.org",
})
SCRIPT_EXTENSIONS = frozenset({
    ".ps1", ".psm1", ".psd1", ".js", ".jse", ".vbs", ".vbe", ".hta", ".wsf", ".wsh", ".sct", ".bat", ".cmd", ".txt", ".log",
    ".html", ".htm", ".svg", ".xsl", ".iqy", ".slk", ".reg", ".url", ".py", ".sh", ".json", ".xml", ".csv", "",
})
MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_PIVOTS = 300
PREVIEW_CHARS = 160
CRADLE_NOTE = "decoded download cradle: hostile, for passive modules only, never contacted by any automatic step"


class _Budget:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.clock = clock
        self.deadline = clock() + seconds

    def over(self) -> bool:
        return self.clock() > self.deadline


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\r\n\t")
    return ok / len(s)


def _as_text(data: Any) -> str:
    if isinstance(data, (bytes, bytearray, memoryview)):
        b = bytes(data)
        if b.startswith(b"\xff\xfe") or b.startswith(b"\xfe\xff"):
            return b.decode("utf-16", errors="replace")
        if b.startswith(b"\xef\xbb\xbf"):
            b = b[3:]
        return b.decode("utf-8", errors="replace")
    return data if isinstance(data, str) else ""


_TEXT_BYTES = frozenset(range(32, 127)) | {9, 10, 12, 13, 27}


def _looks_binary(raw: bytes) -> bool:
    """A file that is not a text script: NUL bytes outside UTF-16 text, or > 30% control bytes in the head."""
    head = bytes(raw[:65536])
    if not head or head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return False
    if b"\x00" in head:
        return True
    odd = sum(1 for b in head if b < 128 and b not in _TEXT_BYTES)
    return odd > 0.3 * len(head)


def _sd_wrap(s: str, style: str = "'") -> str:
    """Decoded STRING-building results are re-quoted so the concatenation pass can fold them; text that itself
    contains quotes is code and is inlined raw."""
    if "'" in s or '"' in s:
        return s
    return style + s + style


def _sd_b64decode(blob: str) -> bytes | None:
    s = "".join(blob.split()).rstrip("=")
    if len(s) < 4 or len(s) % 4 == 1:
        return None
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _sd_inflate(data: bytes, wbits: int, cap: int) -> tuple[bytes | None, bool]:
    try:
        d = zlib.decompressobj(wbits)
        out = d.decompress(data, cap + 1)
    except zlib.error:
        return None, False
    return out[:cap], len(out) > cap


def _sd_bytes_to_text(data: bytes) -> str | None:
    if len(data) >= 4 and data[1::2].count(0) >= 0.4 * (len(data) // 2):
        try:
            txt = data.decode("utf-16-le")
        except UnicodeDecodeError:
            txt = None
        if txt is not None and _printable_ratio(txt) >= SD_MIN_PRINTABLE:
            return txt
    try:
        txt = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return txt if _printable_ratio(txt) >= SD_MIN_PRINTABLE else None


def _sd_payload(data: bytes) -> dict[str, Any]:
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - IOC hash
            "magic": data[:4].hex(), "pe": data[:2] == b"MZ"}


def _sd_pct_decode(arg: str, utf8: bool) -> str:
    """unescape(): %XX = Latin-1 code point, %uXXXX = UTF-16 unit; decodeURI*(): %XX bytes are UTF-8."""
    if not utf8:
        return _SD_PCT_RE.sub(lambda x: chr(int(x.group(1) or x.group(2), 16)), arg)
    buf = bytearray()
    for m in _SD_PCT_TOKEN_RE.finditer(arg):
        if m.group(1):
            buf += chr(int(m.group(1), 16)).encode("utf-8", "replace")
        elif m.group(2):
            buf.append(int(m.group(2), 16))
        else:
            buf += m.group(0).encode("utf-8", "replace")
    return buf.decode("utf-8", "replace")


def _sd_codes(items: Iterable[str]) -> str | None:
    chars = []
    for it in items:
        it = it.strip()
        try:
            cp = int(it, 16) if it.lower().startswith("0x") else int(it)
        except ValueError:
            return None
        if not (0 <= cp <= 0x10FFFF) or 0xD800 <= cp <= 0xDFFF:
            return None
        chars.append(chr(cp))
    s = "".join(chars)
    return s if s and _printable_ratio(s) >= SD_MIN_PRINTABLE else None


def _sd_vbs_value(arg: str) -> int | None:
    terms = _SD_VBS_TERM_RE.findall(arg)
    if not terms:
        return None

    def num(x: str) -> int:
        return int(x[2:], 16) if x.lower().startswith("&h") else int(x)

    try:
        if len(terms) == 1:
            return num(terms[0])
        if len(terms) == 3 and terms[1] in "+-*":
            a, b = num(terms[0]), num(terms[2])
            return a + b if terms[1] == "+" else a - b if terms[1] == "-" else a * b
    except ValueError:
        return None
    return None


def _ps_invocation_start(text: str, pos: int) -> int:
    """c4 readable layer: start of the ``powershell``/``pwsh`` invocation that owns the -EncodedCommand at ``pos``
    (same command: no ``& | ;`` or line break in between), so the layer shows the command PowerShell runs in place
    of the wrapper (``cmd /c powershell -w hidden -enc X`` -> ``cmd /c <decoded>``); ``pos`` when there is none."""
    lo = max(0, pos - 1024)
    window = text[lo:pos]
    hosts = list(_SD_PS_HOST_RE.finditer(window))
    if not hosts:
        return pos
    host = hosts[-1]
    between = window[host.end():].lstrip("\"' \t")
    if any(c in _SD_CMD_SEPARATORS for c in between) or (between and between[0] not in "-/"):
        return pos  # another command, or prose: only 'powershell [-flags ...] -enc' is replaced
    start = host.start()
    quote = window[host.end():host.end() + 1]
    if quote in ("\"", "'"):  # quoted path, possibly with spaces: "C:\Program Files\PowerShell\7\pwsh.exe"
        opening = window.rfind(quote, 0, start)
        if opening > max(window.rfind("\n", 0, start), window.rfind("\r", 0, start)):
            return lo + opening
    while start > 0 and window[start - 1] not in _SD_PATH_STOP:
        start -= 1
    return lo + start


def _sd_sub(text: str, rx: re.Pattern[str], fn: Callable[[re.Match[str]], str | None], budget: _Budget,
            start_of: Callable[[str, int], int] | None = None) -> tuple[str, int]:
    out, last, count = [], 0, 0
    for i, m in enumerate(rx.finditer(text)):
        if i % 64 == 0 and budget.over():
            break
        rep = fn(m)
        if rep is None:
            continue
        begin = max(last, start_of(text, m.start())) if start_of else m.start()
        out.append(text[last:begin])
        out.append(rep)
        last = m.end()
        count += 1
    if not count:
        return text, 0
    out.append(text[last:])
    return "".join(out), count


def _sd_tech(name: str, text: str, budget: _Budget, payloads: list[dict[str, Any]]) -> tuple[str, int]:
    cap = SD_MAX_LAYER_BYTES
    if name == "ps_encodedcommand":
        def f_enc(m: re.Match[str]) -> str | None:
            data = _sd_b64decode(m.group(1))
            if data is None or len(data) % 2:
                return None
            try:
                txt = data.decode("utf-16-le")
            except UnicodeDecodeError:
                return None
            return txt if _printable_ratio(txt) >= SD_MIN_PRINTABLE else None
        return _sd_sub(text, _SD_PS_ENC_RE, f_enc, budget, _ps_invocation_start)
    if name == "frombase64string":
        def f_b64(m: re.Match[str]) -> str | None:
            data = _sd_b64decode(m.group(1) or m.group(2) or "")
            if data is None:
                return None
            context = text[max(0, m.start() - 300):m.start()].lower()
            if data[:2] == b"\x1f\x8b":
                data, _ = _sd_inflate(data, 31, cap)
            elif "deflatestream" in context:
                data, _ = _sd_inflate(data, -15, cap)
            if data is None:
                return None
            txt = _sd_bytes_to_text(data)
            if txt is None:
                p = _sd_payload(data)
                payloads.append(p)
                return f"'<binary payload: {p['bytes']} bytes, sha256 {p['sha256']}>'"
            return txt  # decoded code is inlined raw (never re-quoted) so later layers keep their shape
        return _sd_sub(text, _SD_FROMB64_RE, f_b64, budget)
    if name == "char_codes":
        total = 0
        for rx, items in ((_SD_PS_CHARARRAY_RE, lambda m: _SD_NUM_ITEM_RE.findall(m.group(1))),
                          (_SD_PS_CHARCHAIN_RE, lambda m: _SD_PS_CHARITEM_RE.findall(m.group(0))),
                          (_SD_JS_FROMCHARCODE_RE, lambda m: _SD_NUM_ITEM_RE.findall(m.group(1)))):
            def f_codes(m: re.Match[str], items: Callable[[re.Match[str]], list[str]] = items) -> str | None:
                s = _sd_codes(items(m))
                return _sd_wrap(s) if s is not None else None
            text, n = _sd_sub(text, rx, f_codes, budget)
            total += n
        return text, total
    if name == "vbs_chr":
        def f_vbs(m: re.Match[str]) -> str | None:
            cps = [_sd_vbs_value(a) for a in _SD_VBS_ITEM_RE.findall(m.group(0))]
            if not cps or any(c is None or not (0 <= c <= 0x10FFFF) or 0xD800 <= c <= 0xDFFF for c in cps):
                return None
            s = "".join(chr(c) for c in cps if c is not None)
            return _sd_wrap(s, '"') if _printable_ratio(s) >= SD_MIN_PRINTABLE else None
        return _sd_sub(text, _SD_VBS_CHAIN_RE, f_vbs, budget)
    if name == "unescape":
        def f_unesc(m: re.Match[str]) -> str | None:
            arg = m.group(2) if m.group(2) is not None else m.group(3)
            if "%" not in arg:
                return None
            s = _sd_pct_decode(arg, utf8=m.group(1).lower() != "unescape")
            return _sd_wrap(s) if s and _printable_ratio(s) >= SD_MIN_PRINTABLE else None
        return _sd_sub(text, _SD_UNESCAPE_RE, f_unesc, budget)
    if name == "js_escapes":
        def f_js(m: re.Match[str]) -> str | None:
            cps = []
            for a, b, c in _SD_JS_ESC_ITEM_RE.findall(m.group(0)):
                cp = int(a or b or c, 16)
                if not (0 <= cp <= 0x10FFFF) or 0xD800 <= cp <= 0xDFFF:
                    return None
                cps.append(chr(cp))
            s = "".join(cps)
            return s if _printable_ratio(s) >= SD_MIN_PRINTABLE else None
        return _sd_sub(text, _SD_JS_ESC_RE, f_js, budget)
    if name == "hex_blob":
        def f_hex(m: re.Match[str]) -> str | None:
            h = m.group(1)
            if len(h) % 2 or (len(h) in _SD_HASH_HEX_LENS and not m.group(0).lower().startswith("0x")):
                return None
            try:
                data = bytes.fromhex(h)
            except ValueError:
                return None
            txt = _sd_bytes_to_text(data)
            return txt if txt is not None and len(txt) >= 8 and _printable_ratio(txt) >= 0.9 else None
        return _sd_sub(text, _SD_HEX_RE, f_hex, budget)
    if name == "concat":
        return _sd_fold_concat(text, budget)
    if name == "base64_literal":
        def f_lit(m: re.Match[str]) -> str | None:
            blob = m.group(1) or m.group(2)
            data = _sd_b64decode(blob)
            if data is None:
                return None
            txt = _sd_bytes_to_text(data)
            if txt is None or len(txt) < 16 or _printable_ratio(txt) < 0.95:
                return None
            return _sd_wrap(txt)
        return _sd_sub(text, _SD_B64_LITERAL_RE, f_lit, budget)
    return text, 0


def _sd_fold_concat(text: str, budget: _Budget) -> tuple[str, int]:
    """Fold 'a' + 'b' / "a" & "b" (adjacent literals on one line) with a linear scanner (no regex)."""
    pieces: list[list[str]] = []  # ['lit', quote, content] | ['raw', text]
    i, n = 0, len(text)
    nxt: dict[str, int] = {"'": -2, '"': -2, "\n": -2}

    def find_next(ch: str, frm: int) -> int:
        # amortised O(n): positions only move forward, so each character is scanned once per symbol
        p = nxt[ch]
        if p == -2 or (p != -1 and p < frm):
            p = text.find(ch, frm)
            nxt[ch] = p
        return p if p != -1 else n

    while i < n:
        c = text[i]
        if c in "'\"":
            nl = find_next("\n", i + 1)
            j = find_next(c, i + 1)
            if j < nl:
                pieces.append(["lit", c, text[i + 1:j]])
                i = j + 1
                continue
        k = min(find_next("'", i + 1), find_next('"', i + 1))
        pieces.append(["raw", text[i:k]])
        i = k
    out: list[str] = []
    folds = 0
    idx = 0
    while idx < len(pieces):
        if budget.over():
            out.extend(p[1] + p[2] + p[1] if p[0] == "lit" else p[1] for p in pieces[idx:])
            break
        p = pieces[idx]
        if p[0] != "lit":
            out.append(p[1])
            idx += 1
            continue
        quote, content = p[1], p[2]
        j = idx
        while (j + 2 < len(pieces) and pieces[j + 1][0] == "raw" and pieces[j + 1][1].strip() in ("+", "&")
               and pieces[j + 2][0] == "lit"):
            merged = content + pieces[j + 2][2]
            if quote in merged:
                alt = '"' if quote == "'" else "'"
                if alt in merged:
                    break
                quote = alt
            content = merged
            folds += 1
            j += 2
        out.append(quote + content + quote)
        idx = j + 1
    return ("".join(out), folds) if folds else (text, 0)


def _sd_normalise(text: str) -> tuple[str, bool]:
    t2 = _SD_TICK_RE.sub("", _SD_CARET_RE.sub("", text))
    return t2, t2 != text


def _truncate_utf8(s: str, cap: int) -> str:
    return s.encode("utf-8", "replace")[:cap].decode("utf-8", "ignore")


def central_redact(text: str) -> str:
    """c4 (AR01): passwords dropped and secrets fingerprinted (``sanitize.scrub_text``), then configured key values
    and key-like URL parameters masked (``redact.redact_text``)."""
    return redact_text(scrub_text(text))


def decode_layers(data: Any, *, max_layers: int = SD_MAX_LAYERS, max_layer_bytes: int = SD_MAX_LAYER_BYTES,
                  time_budget_s: float = SD_TIME_BUDGET_S, clock: Callable[[], float] = time.monotonic,
                  redact: Callable[[str], str] | None = None) -> dict[str, Any]:
    """c2-c4: static, bounded de-obfuscation (no evaluation, no engine, no emulation; reusable by P367/P365).

    Returns {'layers': [{'n', 'technique', 'label', 'count', 'normalised', 'text', 'bytes', 'truncated',
    'payloads'}], 'stop': 'no_more_encodings'|'max_layers'|'output_cap'|'time_budget'|'empty', 'input_truncated',
    'path', 'elapsed_s'}. Layer text passes through ``redact`` (the AR01 central redactor) before it is returned.
    """
    budget = _Budget(time_budget_s, clock)
    t0 = clock()
    text = _as_text(data)
    res: dict[str, Any] = {"layers": [], "stop": None, "input_truncated": False, "path": "", "elapsed_s": 0.0}
    if not text.strip():
        res["stop"] = "empty"
        return res
    if len(text.encode("utf-8", "replace")) > max_layer_bytes:
        text = _truncate_utf8(text, max_layer_bytes)
        res["input_truncated"] = True
    cur = text
    red = redact or (lambda s: s)
    for n in range(1, max_layers + 2):
        if budget.over():
            res["stop"] = "time_budget"
            break
        norm, changed = _sd_normalise(cur)
        applied, new, count, payloads = None, norm, 0, []
        for tech in SD_ORDER:
            if budget.over():
                break
            new, count = _sd_tech(tech, norm, budget, payloads)
            if count:
                applied = tech
                break
        if budget.over() and applied is None:
            res["stop"] = "time_budget"
            break
        if applied is None and not changed:
            res["stop"] = "no_more_encodings"
            break
        if n > max_layers:
            res["stop"] = "max_layers"
            break
        tech = applied or "normalise"
        size = len(new.encode("utf-8", "replace"))
        truncated = size > max_layer_bytes
        if truncated:
            new = _truncate_utf8(new, max_layer_bytes)
        label = f"layer {n}: {SD_TECHNIQUE_LABELS[tech]}" + (" (after normalising ^/` escapes)" if changed and applied else "")
        res["layers"].append({"n": n, "technique": tech, "label": label, "count": count or 1, "normalised": changed,
                              "text": red(new), "bytes": min(size, max_layer_bytes), "truncated": truncated,
                              "payloads": payloads})
        cur = new
        if truncated:
            res["stop"] = "output_cap"
            break
    res["path"] = ">".join(f"L{x['n']}:{x['technique']}" for x in res["layers"])
    res["elapsed_s"] = round(clock() - t0, 4)
    return res


def detect_cradles(text: Any) -> list[str]:
    """c6: download-cradle API names present in a decoded layer."""
    t = text if isinstance(text, str) else ""
    return sorted({m.group(0).strip().lower() for m in _SD_CRADLE_RE.finditer(t)})


def _host_of(etype: T, value: str) -> str:
    if etype is T.URL:
        try:
            return (urlsplit(value).hostname or "").lower()
        except ValueError:
            return ""
    return value.lower() if etype is T.DOMAIN else ""


def is_namespace_or_cdn(etype: T, value: str) -> bool:
    """c5: schema/namespace/documentation hosts and library CDNs are not IOCs."""
    host = _host_of(etype, value)
    return bool(host) and (host in NAMESPACE_AND_CDN_HOSTS or any(host.endswith("." + h) for h in NAMESPACE_AND_CDN_HOSTS))


def extract_decoded_iocs(result: dict[str, Any], original: Any = "") -> dict[str, Any]:
    """c5-c6: IOCs FIRST seen in a decoded layer (P172 extractor on each layer), namespace/CDN and P169-warninglisted
    values filtered first. Returns {'items': [{'entity', 'layer', 'provenance', 'cradle', 'flags', 'confidence'}],
    'filtered': n, 'withheld': {kind: count}}."""
    try:
        # literally visible in the input (the core extractor's own base64/hex decoding is flagged 'decoded' and kept here)
        base = {e.entity.key for e in _ioc.extract(_as_text(original)[:SD_MAX_LAYER_BYTES]).entities if "decoded" not in e.flags}
    except Exception:  # noqa: BLE001 - an extractor failure on the input never hides decoded IOCs
        base = set()
    seen: set[str] = set(base)
    items: list[dict[str, Any]] = []
    filtered = 0
    withheld: dict[str, int] = {}
    path: list[str] = []
    for layer in (result or {}).get("layers", []):
        path.append(f"L{layer['n']}:{layer['technique']}")
        cradles = detect_cradles(layer.get("text", ""))
        extracted = _ioc.extract(layer.get("text", ""), source_type="text")
        found = [(e.entity, set(e.flags), float(e.confidence)) for e in extracted.entities]
        for p in layer.get("payloads", []):
            for etype, value in ((T.SHA256, p["sha256"]), (T.MD5, p["md5"])):
                ent = Entity.try_make(etype, value)
                if ent is not None:
                    found.append((ent, {"decoded_payload"}, 0.9))
        for ent, flags, conf in found:
            if ent.key in seen:
                continue
            seen.add(ent.key)
            if ent.type in SECRET_TYPES or ent.type is T.CPF:
                withheld[ent.type.value] = withheld.get(ent.type.value, 0) + 1
                continue
            if is_namespace_or_cdn(ent.type, ent.value) or (ent.type is T.DOMAIN and "warninglisted" in flags):
                filtered += 1
                continue
            items.append({"entity": ent, "layer": layer["n"], "provenance": ">".join(path), "flags": sorted(flags),
                          "cradle": bool(cradles) and ent.type in (T.URL, T.DOMAIN, T.IPV4, T.IPV6), "confidence": conf})
    return {"items": items, "filtered": filtered, "withheld": withheld}


_URL_TEXT_RE = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>()\[\]{}\\^`|]{1,2048}", re.I)
_TOKEN_TEXT_RE = re.compile(r"[A-Za-z0-9.\-]{4,300}")
_IPV4_TEXT_RE = re.compile(r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}")
#: starts only at a token boundary (it is used with fullmatch; the lookbehind keeps a scan linear-fast)
_DOMAIN_TEXT_RE = re.compile(r"(?<![a-z0-9-])(?:[a-z0-9-]{1,63}\.){1,10}[a-z]{2,24}", re.I)


#: every compiled pattern of this module, the defang helpers included (ReDoS test)
PATTERNS_ALL: tuple[re.Pattern[str], ...] = (*PATTERNS, _URL_TEXT_RE, _TOKEN_TEXT_RE, _IPV4_TEXT_RE, _DOMAIN_TEXT_RE)


def defang_text(text: Any) -> str:
    """c4: defanged plain text: URLs through the core ``defang`` (hxxp://, [.] in the host), bare IPv4s and host
    names with a known TLD bracketed ('c2[.]example[.]org'); code tokens such as Net.WebClient stay readable."""
    t = _URL_TEXT_RE.sub(lambda m: defang(m.group(0)), text if isinstance(text, str) else "")

    def dot(m: re.Match[str]) -> str:
        tok = m.group(0)
        core = tok.strip(".-")
        if _IPV4_TEXT_RE.fullmatch(core) or (_DOMAIN_TEXT_RE.fullmatch(core) and psl.is_known_tld(core.rsplit(".", 1)[-1].lower())):
            return tok.replace(core, core.replace(".", "[.]"))
        return tok

    return _TOKEN_TEXT_RE.sub(dot, t)


def render_layer(layer: dict[str, Any], max_chars: int = PREVIEW_CHARS) -> str:
    """c4 terminal line: '<label>: <defanged, truncated text>'."""
    body = " ".join(defang_text(layer.get("text", "")).split())
    if len(body) > max_chars:
        body = body[:max_chars] + f"... ({layer.get('bytes', len(body))} bytes in evidence)"
    return f"{layer.get('label', 'layer ?')}: {body}"


def _technique_attack(layers: list[dict[str, Any]]) -> list[str]:
    ids = ["T1027"]
    techniques = {x["technique"] for x in layers}
    if techniques & {"ps_encodedcommand", "frombase64string"}:
        ids.append("T1059.001")
    if "vbs_chr" in techniques:
        ids.append("T1059.005")
    if techniques & {"js_escapes", "unescape"}:
        ids.append("T1059.007")
    return ids


@register
class ScriptDecoder(Module):
    name = "script_decoder"
    title = "Script de-obfuscation (EncodedCommand, FromBase64String, JS/VBS/HTA strings)"
    description = (
        "Static, bounded decoding of obfuscated scripts and command lines (base64 UTF-16LE -EncodedCommand, "
        "FromBase64String, char codes, unescape, VBS Chr, hex, concatenation) feeding the IOC extractor; nothing is "
        "executed or emulated."
    )
    category = "file_analysis"
    accepts = {T.FILE, T.TEXT}
    produces = {T.URL, T.DOMAIN, T.IPV4, T.IPV6, T.MD5, T.SHA1, T.SHA256}
    tags = {"offline", "free"}
    reference = "https://attack.mitre.org/techniques/T1027/"
    notice = (
        "Static decoding only (no execution, no emulation, no engine). URLs of decoded download cradles are hostile "
        "IOCs for passive modules only and are never contacted."
    )
    # ---- contract v2 declarations ---------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # c1
    hosts = ()
    access_model = "offline"
    expected_latency = 0.1
    max_pivots = MAX_PIVOTS
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.FILE:
            path = entity.value
            ext = os.path.splitext(path)[1].lower()
            # regular files only: a FIFO or a device would block (not applicable)
            return ext in SCRIPT_EXTENSIONS and os.path.isfile(path) and os.path.getsize(path) <= MAX_FILE_BYTES
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type is T.FILE:
            try:
                with open(entity.value, "rb") as fh:
                    raw = fh.read(SD_MAX_LAYER_BYTES + 1)
            except OSError as exc:
                return res.mark(Status.ERROR, f"cannot read the file: {exc.strerror or type(exc).__name__}")
            text = _as_text(raw)
            if _looks_binary(raw):
                return res.mark(Status.SKIPPED, "not a text script (binary content): not decoded", reason_code="not_applicable")
        else:
            text = entity.value or ""
        out = decode_layers(text, redact=central_redact)
        layers = out["layers"]
        if not layers:
            res.error = "no supported encoding found (plain script or unsupported technique): nothing decoded"
            return res.mark(Status.EMPTY)
        res.attr("decoded_layers", [{"n": x["n"], "technique": x["technique"], "label": x["label"], "count": x["count"],
                                     "bytes": x["bytes"], "truncated": x["truncated"], "preview": render_layer(x)} for x in layers])
        res.attr("decode_path", f"{out['path']} (stop: {out['stop']})")
        cradles = sorted({c for x in layers for c in detect_cradles(x["text"])})
        res.attr("download_cradles", cradles)
        iocs = extract_decoded_iocs(out, text)
        pivots = 0
        for item in iocs["items"]:
            if pivots >= self.max_pivots:
                break
            ent, prov = item["entity"], item["provenance"]
            note = f"decoded ({prov}; layer {item['layer']})"
            if item["cradle"]:
                note += f"; {CRADLE_NOTE}"
            conf = min(0.8, item["confidence"])
            if ent.type in IOC_TYPES and not (set(item["flags"]) & _ioc.NO_EXPAND_FLAGS):
                added = res.pivot(ent.type, ent.value, "extracted_from", confidence=conf, note=note)
            elif ent.type in PERSONAL_TYPES:
                added = res.pivot(ent.type, ent.value, "extracted_from", confidence=conf, expand=False,
                                  note=f"personal identifier from a decoded script: analyst selection required; {note}")
            else:
                added = res.pivot(ent.type, ent.value, "extracted_from", confidence=conf, expand=False,
                                  note=f"listed, not auto-investigated ({', '.join(item['flags']) or 'analyst selection'}); {note}")
            pivots += added is not None
        payloads = [p for x in layers for p in x["payloads"]]
        res.finding(
            "Obfuscated script decoded",
            "info",
            f"{len(layers)} layer(s): " + "; ".join(x["label"] for x in layers) + f". Stop: {out['stop']}. "
            f"{len(iocs['items'])} indicator(s) found only after decoding; {iocs['filtered']} namespace/CDN/warninglisted value(s) filtered.",
            confidence="confirmed",
            data={"path": out["path"], "stop": out["stop"], "input_truncated": out["input_truncated"], "filtered": iocs["filtered"],
                  "withheld": iocs["withheld"], "payloads": payloads},
            tags=["info", "decoded"],
            attack=_technique_attack(layers),
        )
        if cradles:
            urls = [i["entity"].value for i in iocs["items"] if i["cradle"] and i["entity"].type is T.URL]
            res.finding(
                "Download cradle in a decoded script layer",
                "medium",
                f"Decoded layer(s) use {', '.join(cradles)}"
                + (f" with {', '.join(defang(u) for u in urls[:5])}" if urls else "")
                + ". Static decoding only: the URLs are hostile IOCs for passive modules and were never contacted.",
                confidence="probable",
                criterion="static decode of an obfuscated script reveals a download-cradle API (no execution or emulation)",
                data={"cradles": cradles, "urls": urls[:20], "path": out["path"]},
                tags=["suspicious", "decoded", "download_cradle"],
                attack=_technique_attack(layers),
            )
        if payloads:
            res.finding(
                "Binary payload embedded in the script",
                "medium",
                f"{len(payloads)} base64 payload(s) decode to binary data"
                + (" (PE/MZ header)" if any(p["pe"] for p in payloads) else "")
                + ": hashed (" + ", ".join(p["sha256"][:16] + "..." for p in payloads[:3]) + "), never written or executed.",
                confidence="probable",
                criterion="FromBase64String payload decodes to non-text bytes (hashes pivoted for passive lookups)",
                data={"payloads": payloads},
                tags=["suspicious", "decoded"],
                attack=["T1027"],
            )
        res.raw = {"layers": [{k: x[k] for k in ("n", "technique", "label", "count", "normalised", "bytes", "truncated", "payloads", "text")}
                              for x in layers],
                   "stop": out["stop"], "path": out["path"], "input_truncated": out["input_truncated"], "elapsed_s": out["elapsed_s"],
                   "iocs": [{"entity": i["entity"].key, "layer": i["layer"], "provenance": i["provenance"], "cradle": i["cradle"]}
                            for i in iocs["items"][:1000]]}
        return res
