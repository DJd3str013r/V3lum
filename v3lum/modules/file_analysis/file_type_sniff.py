"""File-type detection (P270) and the shared safe readers of the file-analysis family (batch p1-G12-1).

P270 final conditions implemented here:

* c1 offline module: disclosure 'none' (ctx.http refuses every request), terms 'open', provider tier
  'n/a', allowed at TLP:RED. :func:`sniff_path` / :func:`sniff` and :func:`route` are the library
  functions every file module calls (document_metadata, apk_triage and archive_listing decide their
  applicability with them), so the routing table exists once.
* c2 an own magic table, bundled data with offsets (``v3lum/data/file_type_sniff/magic.json``, every
  row tested), no dependency. It covers PE (exe/dll/.NET/DOS), ELF, Mach-O, ZIP and its families
  (OOXML, APK/AAB, JAR, ODF, EPUB, APPX/MSIX, XPI, NuGet, IPA), OLE (doc/xls/ppt/msg/MSI/MSP/MST/
  encrypted OOXML...), PDF (also a header at an offset), RAR4/5, 7z, gzip/bzip2/xz/zstd/lz4, CAB, tar,
  ISO 9660/UDF, VHD/VHDX/VMDK, LNK, OneNote, CHM, RTF, DEX, WASM and script/text kinds by heuristics
  (HTA, WSF, SCT, JS, VBS/VBE, PS1 incl. UTF-16LE, batch, shebang, HTML, SVG, EML, .url, .reg, IQY...).
* c3 at most the first 64 KB plus the ZIP central directory (read through the safe ZIP reader below,
  never the members) and the last 64 KB for footers (EOCD, VHD) and appended archives.
* c4 licences (A6): no third-party library is imported; filetype.py (MIT) stays a possible extra,
  Magika and python-magic are not used in this build, hachoir (GPL-2.0) is never imported or bundled.
* c5 findings: executable content behind a document or image extension, or a double extension such
  as ``invoice.pdf.exe``, is HIGH; other extension/content mismatches MEDIUM; polyglots (PDF+ZIP,
  PE+ZIP/RAR/7z) MEDIUM at POSSIBLE confidence; wording 'claimed .pdf, actually PE32 executable'.

Shared safe readers (also used by document_metadata, apk_triage and archive_listing; candidates for
the core helpers named by the final conditions, see docs/backlog/p1-G12-1.md):

* the safe ZIP reader (P365 c1 'single safe archive helper', P269 c6, P364 c2): a tolerant
  central-directory scan (duplicate names, local/central mismatch, overlapping entries, bad central
  directory -> local-header scan) and a bounded inflate (size cap, ratio cap enforced while inflating
  after a 64 KB grace window, truncated streams, CRC check, ZipCrypto only with a caller-supplied
  password, never guessed);
* the safe XML helper (P269 c6): pyexpat with DOCTYPE, entity and notation declarations refused,
  external entities never resolved, element/depth/size caps;
* a bounded OLE/CFB reader ([MS-CFB]) with chain-loop detection and a per-file read budget;
* regular-file access only (FIFOs, devices and sockets are refused before anything is opened) with
  read caps.

Every function only parses bytes: nothing is executed, rendered, decrypted with a guessed password,
fetched or resolved.
"""

from __future__ import annotations

import binascii
import collections
import datetime as _dt
import functools
import ipaddress
import json
import math
import os
import re
import stat as _stat
import struct
import unicodedata
import urllib.parse
import xml.etree.ElementTree as ET
import xml.parsers.expat as _expat
import zlib
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

# ======================================================================================== limits

#: Numeric caps of the final conditions (P269 c5, P270 c3, P364 c3, P365 c2/c7) and parser bounds.
LIMITS: dict[str, int] = {
    "max_input": 100 * 1024 * 1024,  # P269/P364: input cap of a parsed file
    "max_output_json": 1024 * 1024,  # evidence (res.raw) JSON cap
    "sniff_head": 64 * 1024,  # P270 c3: at most the first 64 KB (+ the zip central directory)
    "sniff_tail": 64 * 1024 + 22,  # footers (EOCD, VHD) and appended archives
    "zip_cd_max": 32 * 1024 * 1024,  # central directory read by the sniffer
    "archive_total": 500 * 1024 * 1024,  # P365 c2: total uncompressed
    "archive_ratio": 100,  # P365 c2: compression ratio
    "archive_members": 10_000,  # P365 c2: members
    "archive_depth": 3,  # P365 c2: nesting depth
    "ratio_grace": 64 * 1024,  # ratio enforced once an entry inflates past this (POI-style grace window)
    "xml_max_bytes": 16 * 1024 * 1024,  # one XML part inflated
    "xml_max_elements": 500_000,
    "read_budget": 256 * 1024 * 1024,  # bytes inflated/read per analysed file (overlapping-entry bombs)
    "hash_member_max": 10 * 1024 * 1024,  # P365 c7 'small members' hashed in memory
    "hash_members_per_archive": 50,  # P365 c7
    "dex_max_strings": 300_000,
    "string_max_len": 4096,
    "cfb_max_sectors": 2_000_000,
    "cfb_max_entries": 50_000,
    "iso_max_entries": 10_000,
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class ArchiveLimit(Exception):
    """A safe-reader limit or refusal; ``args[0]`` is a reason code (ratio, size_cap, encrypted...)."""


class FileRefused(Exception):
    """The path is not a readable regular file. ``kind``: 'missing' | 'special' | 'unreadable'."""

    def __init__(self, kind: str, reason: str) -> None:
        super().__init__(reason)
        self.kind = kind
        self.reason = reason


class Budget:
    """Bytes a single analysis may read or inflate in total (overlapping-entry and repeated-chain bombs)."""

    def __init__(self, total: int | None = None) -> None:
        self.left = LIMITS["read_budget"] if total is None else int(total)

    def charge(self, n: int) -> None:
        self.left -= max(0, int(n))
        if self.left < 0:
            raise ArchiveLimit("read_budget")


# ======================================================================================== small helpers


def u16(b: Any, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def u32(b: Any, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def u64(b: Any, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def clean_text(s: Any, limit: int | None = None) -> str | None:
    """Drop C0/C1 controls and lone surrogates (tab/newline kept; format characters such as U+202E stay
    as evidence), strip and cap the length. AR13 escaping happens later in the renderers."""
    if s is None:
        return None
    s = "".join(ch for ch in str(s) if ch in "\t\n" or unicodedata.category(ch) not in ("Cc", "Cs")).strip()
    return s[: (limit or LIMITS["string_max_len"])]


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0..8): context only."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(data).values())


def filetime_to_iso(ft: Any) -> str | None:
    """Windows FILETIME (100 ns since 1601-01-01 UTC) -> ISO 8601; None for 0 or out-of-range values."""
    if not isinstance(ft, int) or ft <= 0:
        return None
    try:
        return (_dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc) + _dt.timedelta(microseconds=ft // 10)).isoformat()
    except OverflowError:
        return None


def dos_datetime(d: int, t: int) -> str | None:
    try:
        return _dt.datetime(((d >> 9) & 0x7F) + 1980, (d >> 5) & 0x0F, d & 0x1F, (t >> 11) & 0x1F, (t >> 5) & 0x3F, (t & 0x1F) * 2).isoformat()
    except ValueError:
        return None


def guid_le(b: bytes) -> str | None:
    """16 GUID bytes (little-endian struct layout) -> canonical lower-case text."""
    if len(b) != 16:
        return None
    d1, d2, d3 = struct.unpack_from("<IHH", b, 0)
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{b[8:10].hex()}-{b[10:16].hex()}"


def fact(code: str, severity: str, title: str, *, confidence: str = "probable", criterion: str = "", attack: Any = None,
         tags: Iterable[str] = (), description: str = "", **detail: Any) -> dict[str, Any]:
    """Plain finding dict built by the parsers and mapped onto core findings by :func:`emit_findings`."""
    out: dict[str, Any] = {"code": code, "severity": severity.lower(), "confidence": confidence.lower(), "title": title,
                           "criterion": criterion, "tags": list(tags), "description": description, "detail": detail}
    if attack:
        out["attack"] = [attack] if isinstance(attack, str) else list(attack)
    return out


def emit_findings(res: ModuleResult, items: Iterable[dict[str, Any]], *, default_criteria: dict[str, str] | None = None) -> None:
    """Map :func:`fact` dicts onto ``res.finding`` (stable titles; ``key`` separates repeated titles)."""
    seen: dict[str, int] = {}
    for item in items:
        title = clean_text(item.get("title"), 300) or item.get("code", "finding")
        n = seen.get(title, 0)
        seen[title] = n + 1
        criterion = item.get("criterion") or (default_criteria or {}).get(item.get("code", ""), "")
        detail = item.get("detail") or {}
        res.finding(
            title,
            item.get("severity", "info"),
            item.get("description") or "",
            confidence=item.get("confidence", "probable"),
            criterion=criterion,
            data=_jsonable({"code": item.get("code"), **detail}),
            tags=item.get("tags") or (),
            attack=item.get("attack") or (),
            key=f"{item.get('code')}#{n}" if n else "",
        )


def _jsonable(obj: Any, depth: int = 0) -> Any:
    """A JSON-safe copy (bytes become their length, sets become sorted lists, depth capped)."""
    if depth > 8:
        return None
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return {"bytes": len(obj)}
    if isinstance(obj, dict):
        return {str(k): _jsonable(v, depth + 1) for k, v in obj.items() if not str(k).startswith("_")}
    if isinstance(obj, (set, frozenset)):
        return sorted(_jsonable(v, depth + 1) for v in obj)
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v, depth + 1) for v in obj]
    return str(obj)


def cap_json(obj: Any, limit: int | None = None) -> Any:
    """Shrink a JSON-able evidence object until it serialises within ``limit`` bytes (1 MB): long lists
    are cut (keeping their head) and the cut is recorded under '_truncated' (never fails)."""
    limit = limit or LIMITS["max_output_json"]
    data = _jsonable(obj)
    for keep in (2000, 500, 100, 20, 5):
        if len(json.dumps(data, default=str)) <= limit:
            return data
        data = _trim_lists(data, keep)
    if len(json.dumps(data, default=str)) <= limit:
        return data
    return {"_truncated": "evidence larger than the 1 MB cap: summary only"}


def _trim_lists(obj: Any, keep: int) -> Any:
    if isinstance(obj, dict):
        return {k: _trim_lists(v, keep) for k, v in obj.items()}
    if isinstance(obj, list):
        out = [_trim_lists(v, keep) for v in obj[:keep]]
        if len(obj) > keep:
            out.append({"_truncated": len(obj) - keep})
        return out
    if isinstance(obj, str) and len(obj) > 4096:
        return obj[:4096]
    return obj


# ======================================================================================== regular files


def file_mode_refusal(st_mode: Any) -> str | None:
    """None for a regular file; else why it is refused (checked BEFORE the file is opened)."""
    if not isinstance(st_mode, int) or isinstance(st_mode, bool):
        return "no stat information"
    if _stat.S_ISREG(st_mode):
        return None
    for test, kind in ((_stat.S_ISFIFO, "FIFO"), (_stat.S_ISCHR, "character device"), (_stat.S_ISBLK, "block device"),
                       (_stat.S_ISSOCK, "socket"), (_stat.S_ISDIR, "directory"), (_stat.S_ISLNK, "symbolic link")):
        if test(st_mode):
            return f"refused {kind}: only regular files are analysed"
    return "refused special file: only regular files are analysed"


def open_regular(path: str) -> Any:
    """Open ``path`` read-only when it is a regular file (FIFOs/devices refused before opening, the
    open file re-checked with fstat so a swapped path is refused too). Raises :class:`FileRefused`."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        raise FileRefused("missing", "the file no longer exists") from None
    except OSError as exc:
        raise FileRefused("unreadable", f"cannot stat the file: {exc.strerror or type(exc).__name__}") from None
    refusal = file_mode_refusal(st.st_mode)
    if refusal:
        raise FileRefused("special", refusal)
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise FileRefused("unreadable", f"cannot open the file: {exc.strerror or type(exc).__name__}") from None
    fh = os.fdopen(fd, "rb", buffering=0)
    refusal = file_mode_refusal(os.fstat(fh.fileno()).st_mode)
    if refusal:
        fh.close()
        raise FileRefused("special", refusal)
    return fh


def read_capped(path: str, cap: int) -> tuple[bytes, int]:
    """(content of at most ``cap`` bytes, real size) of a regular file."""
    with open_regular(path) as fh:
        size = os.fstat(fh.fileno()).st_size
        chunks, got = [], 0
        while got < cap:
            block = fh.read(min(1 << 20, cap - got))
            if not block:
                break
            chunks.append(block)
            got += len(block)
        return b"".join(chunks), size


def read_head_tail(path: str) -> tuple[bytes, bytes | None, int, list[str] | None]:
    """P270 c3: (first 64 KB, last 64 KB or None when the head holds the whole file, size, ZIP
    central-directory names or None). Only the EOCD and the central directory are read for ZIPs."""
    with open_regular(path) as fh:
        size = os.fstat(fh.fileno()).st_size
        head = fh.read(LIMITS["sniff_head"])
        tail = None
        if size > len(head):
            fh.seek(max(0, size - LIMITS["sniff_tail"]))
            tail = fh.read(LIMITS["sniff_tail"])
        window = tail if tail is not None else head
        names = None
        if head[:2] == b"PK" or b"PK\x05\x06" in window:
            entries = zip_cd_entries_from_file(fh, size, window)
            names = [e["name"] for e in entries] if entries is not None else None
        return head, tail, size, names


def zip_cd_entries_from_file(fh: Any, size: int, window: bytes) -> list[dict[str, Any]] | None:
    """Central-directory entries of a ZIP read from an open file (EOCD in ``window`` = the last bytes of
    the file, then the central directory only; members are never read). None when there is none."""
    base = size - len(window)
    eocd, _ = _find_eocd(window)
    if eocd < 0:
        return None
    try:
        _, _, _, _, n_total, cd_size, cd_off, _ = struct.unpack_from("<IHHHHIIH", window, eocd)
    except struct.error:
        return None
    loc = eocd - 20
    if (0xFFFFFFFF in (cd_size, cd_off) or n_total == 0xFFFF) and loc >= 0 and window[loc:loc + 4] == b"PK\x06\x07":
        rec = u64(window, loc + 8)
        fh.seek(rec)
        z64 = fh.read(56)
        if z64[:4] == b"PK\x06\x06" and len(z64) >= 56:
            cd_size, cd_off = u64(z64, 40), u64(z64, 48)
    if cd_size <= 0 or cd_size > LIMITS["zip_cd_max"]:
        return None
    for start in (cd_off, base + eocd - cd_size):  # declared offset, then 'prefixed data' (SFX stubs)
        if start < 0 or start + cd_size > size:
            continue
        fh.seek(start)
        blob = fh.read(cd_size)
        if blob[:4] == b"PK\x01\x02":
            entries, pos = [], 0
            while pos + 46 <= len(blob) and blob[pos:pos + 4] == b"PK\x01\x02" and len(entries) < LIMITS["archive_members"]:
                try:
                    entry, pos = _entry_from_cd(blob, pos)
                except struct.error:
                    break
                entries.append(entry)
            return entries
    return None


# ======================================================================================== safe XML helper


class UnsafeXML(ValueError):
    """XML refused by the safe XML helper: ``args[0]`` is the reason ('doctype', 'entity_declaration'...)."""


def safe_xml_parse(data: bytes | str, *, max_bytes: int | None = None, max_elements: int | None = None, max_depth: int = 256) -> ET.Element:
    """Parse XML with DOCTYPE, entity and notation declarations refused (P269 c6).

    pyexpat feeds an ElementTree TreeBuilder, so the result is a normal Element with '{ns}local'
    tags. Raises :class:`UnsafeXML` (DOCTYPE, ENTITY, external entity, too many elements, too deep,
    oversize) and ValueError('xml_error: ...') for malformed XML. Nothing is ever resolved.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    max_bytes = max_bytes or LIMITS["xml_max_bytes"]
    max_elements = max_elements or LIMITS["xml_max_elements"]
    if len(data) > max_bytes:
        raise UnsafeXML("xml_too_large")
    parser = _expat.ParserCreate(namespace_separator="}")
    builder = ET.TreeBuilder()
    state = {"elements": 0, "depth": 0}

    def _name(n: str) -> str:
        return "{" + n if "}" in n else n

    def start(name: str, attrs: dict[str, str]) -> None:
        state["elements"] += 1
        state["depth"] += 1
        if state["elements"] > max_elements:
            raise UnsafeXML("too_many_elements")
        if state["depth"] > max_depth:
            raise UnsafeXML("too_deep")
        builder.start(_name(name), {_name(k): v for k, v in attrs.items()})

    def end(name: str) -> None:
        state["depth"] -= 1
        builder.end(_name(name))

    def refuse(reason: str) -> Callable[..., None]:
        def _handler(*_args: Any) -> None:
            raise UnsafeXML(reason)
        return _handler

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = builder.data
    parser.StartDoctypeDeclHandler = refuse("doctype")
    parser.EntityDeclHandler = refuse("entity_declaration")
    parser.UnparsedEntityDeclHandler = refuse("entity_declaration")
    parser.NotationDeclHandler = refuse("notation_declaration")
    parser.ExternalEntityRefHandler = refuse("external_entity")
    parser.SetParamEntityParsing(_expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.buffer_text = True
    try:
        parser.Parse(data, True)
    except _expat.ExpatError as exc:
        raise ValueError(f"xml_error: {exc}") from None
    try:
        return builder.close()
    except Exception as exc:  # noqa: BLE001 - unbalanced input expat accepted in pieces
        raise ValueError(f"xml_error: {exc}") from None


def xml_local(tag: Any) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def xml_text(el: ET.Element | None) -> str | None:
    return clean_text("".join(el.itertext())) if el is not None else None


# ======================================================================================== safe ZIP reader

_DOS_ATTR_DIR, _DOS_ATTR_HIDDEN = 0x10, 0x02


def _zip_extra(extra: bytes) -> dict[int, bytes]:
    out: dict[int, bytes] = {}
    pos = 0
    while pos + 4 <= len(extra):
        hid, ln = struct.unpack_from("<HH", extra, pos)
        out.setdefault(hid, extra[pos + 4:pos + 4 + ln])
        pos += 4 + ln
    return out


def _find_eocd(data: bytes) -> tuple[int, list[str]]:
    """(offset, anomalies) of the end-of-central-directory record; prefers the one whose comment ends at EOF."""
    start = max(0, len(data) - (22 + 65535))
    cands: list[int] = []
    i = data.rfind(b"PK\x05\x06", start)
    while i != -1 and len(cands) < 16:
        if i + 22 <= len(data):
            cands.append(i)
        i = data.rfind(b"PK\x05\x06", start, i)
    if not cands:
        return -1, []
    exact = [c for c in cands if u16(data, c + 20) == len(data) - (c + 22)]
    anomalies = ["multiple_eocd_signatures"] if len(cands) > 1 else []
    if exact:
        return exact[0], anomalies
    anomalies.append("eocd_comment_length_mismatch")
    return cands[0], anomalies


def _zip64_eocd(data: bytes, eocd: int) -> dict[str, int] | None:
    loc = eocd - 20
    if loc >= 0 and data[loc:loc + 4] == b"PK\x06\x07":
        rec = u64(data, loc + 8)
        if data[rec:rec + 4] == b"PK\x06\x06" and rec + 56 <= len(data):
            return {"entries": u64(data, rec + 32), "cd_size": u64(data, rec + 40), "cd_offset": u64(data, rec + 48)}
    return None


def _decode_zip_name(raw: bytes, flags: int, extra: dict[int, bytes]) -> tuple[str, bool]:
    up = extra.get(0x7075)
    if up and len(up) > 5:
        try:
            return up[5:].decode("utf-8"), True
        except UnicodeDecodeError:
            pass
    if flags & 0x800:
        return raw.decode("utf-8", "replace"), True
    return raw.decode("cp437"), False


def _zip_encryption(flags: int, method: int, extra: dict[int, bytes]) -> tuple[str | None, int | None]:
    if not flags & 0x1:
        return None, None
    if flags & 0x40:
        return "strong", None
    if method == 99:
        ae = extra.get(0x9901, b"")
        return "aes", {1: 128, 2: 192, 3: 256}.get(ae[4] if len(ae) > 4 else 0)
    return "zipcrypto", None


def _entry_from_cd(data: bytes, pos: int) -> tuple[dict[str, Any], int]:
    (_, made_by, _need, flags, method, mtime, mdate, crc, csize, usize, nlen, xlen, clen, disk, _iattr, eattr,
     loff) = struct.unpack_from("<IHHHHHHIIIHHHHHII", data, pos)
    raw = data[pos + 46:pos + 46 + nlen]
    extra = _zip_extra(data[pos + 46 + nlen:pos + 46 + nlen + xlen])
    z64 = extra.get(0x0001)
    if z64:  # zip64 sizes/offset in field order, only for the fields saturated in the record
        vals = list(struct.unpack_from("<" + "Q" * (len(z64) // 8), z64))
        if usize == 0xFFFFFFFF and vals:
            usize = vals.pop(0)
        if csize == 0xFFFFFFFF and vals:
            csize = vals.pop(0)
        if loff == 0xFFFFFFFF and vals:
            loff = vals.pop(0)
    name, utf8 = _decode_zip_name(raw, flags, extra)
    system = made_by >> 8
    mode = (eattr >> 16) & 0xFFFF if system == 3 else 0
    enc, aes = _zip_encryption(flags, method, extra)
    entry = {
        "name": name, "name_raw": raw, "utf8": utf8, "flags": flags, "method": method, "crc32": crc,
        "compressed_size": csize, "file_size": usize, "local_header_offset": loff, "external_attr": eattr,
        "create_system": system, "unix_mode": mode, "mtime": dos_datetime(mdate, mtime),
        "is_dir": name.endswith(("/", "\\")) or bool(eattr & _DOS_ATTR_DIR and system in (0, 11, 14)) or _stat.S_ISDIR(mode),
        "is_symlink": _stat.S_ISLNK(mode), "hidden": bool(eattr & _DOS_ATTR_HIDDEN) if system in (0, 11, 14) else False,
        "encrypted": bool(flags & 0x1), "encryption": enc, "aes_strength": aes, "extra_ids": sorted(extra),
        "comment": data[pos + 46 + nlen + xlen:pos + 46 + nlen + xlen + clen].decode("cp437", "replace"),
    }
    return entry, pos + 46 + nlen + xlen + clen


def _local_header(data: bytes, off: int) -> dict[str, Any] | None:
    if off < 0 or off + 30 > len(data) or data[off:off + 4] != b"PK\x03\x04":
        return None
    (_, _need, flags, method, _mtime, _mdate, crc, csize, usize, nlen, xlen) = struct.unpack_from("<IHHHHHIIIHH", data, off)
    if off + 30 + nlen + xlen > len(data):  # the header itself is cut: a stray signature, not a member
        return None
    return {"flags": flags, "method": method, "crc32": crc, "compressed_size": csize, "file_size": usize,
            "name_raw": data[off + 30:off + 30 + nlen], "data_offset": off + 30 + nlen + xlen}


def zip_scan(data: bytes, *, max_members: int | None = None) -> dict[str, Any]:
    """Tolerant ZIP/APK central-directory reader. Never raises on malformed input.

    Returns ``{'ok', 'entries', 'anomalies', 'cd_offset', 'cd_size', 'eocd_offset', 'prefix_bytes',
    'apk_sig_block', 'zip64', 'comment', 'from_local_scan'}``. Anomalies flag malware zip tricks:
    duplicate names, local/central name or method mismatch, overlapping entries (quoted-overlap bombs),
    bad or missing central directory (local-header scan instead), data after the EOCD, member cap.
    """
    max_members = max_members or LIMITS["archive_members"]
    res: dict[str, Any] = {"ok": False, "entries": [], "anomalies": [], "cd_offset": None, "cd_size": None,
                           "eocd_offset": None, "prefix_bytes": 0, "apk_sig_block": None, "zip64": False, "comment": "",
                           "from_local_scan": False}
    eocd, anomalies = _find_eocd(data)
    res["anomalies"] += anomalies
    if eocd < 0:
        res["anomalies"].append("eocd_missing")
        return _zip_local_scan(data, res, max_members)
    (_, disk, cd_disk, _n_disk, n_total, cd_size, cd_off, clen) = struct.unpack_from("<IHHHHIIH", data, eocd)
    res["eocd_offset"] = eocd
    res["comment"] = data[eocd + 22:eocd + 22 + clen].decode("cp437", "replace")
    if eocd + 22 + clen < len(data):
        res["anomalies"].append("data_after_eocd")
    z64 = _zip64_eocd(data, eocd) if 0xFFFFFFFF in (cd_size, cd_off) or n_total == 0xFFFF else None
    if z64:
        res["zip64"] = True
        n_total, cd_size, cd_off = z64["entries"], z64["cd_size"], z64["cd_offset"]
    if disk or cd_disk:
        res["anomalies"].append("multi_disk")
    if data[cd_off:cd_off + 4] != b"PK\x01\x02" and n_total:
        guess = eocd - cd_size
        if guess >= 0 and data[guess:guess + 4] == b"PK\x01\x02":
            res["anomalies"].append("cd_offset_mismatch")
            res["prefix_bytes"] = guess - cd_off
            cd_off = guess
        else:
            res["anomalies"].append("central_directory_unreadable")
            return _zip_local_scan(data, res, max_members)
    res["cd_offset"], res["cd_size"] = cd_off, cd_size
    if cd_off >= 24 and data[cd_off - 16:cd_off] == b"APK Sig Block 42":
        size = u64(data, cd_off - 24)
        start = cd_off - size - 8
        if start >= 0 and u64(data, start) == size:
            res["apk_sig_block"] = (start, cd_off)
    pos = cd_off
    seen: set[str] = set()
    while pos + 46 <= len(data) and data[pos:pos + 4] == b"PK\x01\x02":
        if len(res["entries"]) >= max_members:
            res["anomalies"].append("member_cap_reached")
            break
        try:
            entry, pos = _entry_from_cd(data, pos)
        except struct.error:
            res["anomalies"].append("truncated_central_directory")
            break
        res["entries"].append(entry)
        key = entry["name"].replace("\\", "/").lower()
        if key in seen:
            res["anomalies"].append("duplicate_name")
            entry["duplicate"] = True
        seen.add(key)
    if n_total != len(res["entries"]) and "member_cap_reached" not in res["anomalies"]:
        res["anomalies"].append("entry_count_mismatch")
    _zip_check_locals(data, res)
    res["ok"] = True
    res["anomalies"] = sorted(set(res["anomalies"]))
    return res


def _zip_check_locals(data: bytes, res: dict[str, Any]) -> None:
    ranges = []
    first = None
    for entry in res["entries"]:
        lh = _local_header(data, entry["local_header_offset"] + res["prefix_bytes"])
        if lh is None:
            entry["local_ok"] = False
            res["anomalies"].append("bad_local_header")
            continue
        entry["local_ok"] = True
        entry["data_offset"] = lh["data_offset"]
        if lh["name_raw"] != entry["name_raw"]:
            entry["local_name_mismatch"] = lh["name_raw"].decode("utf-8", "replace")
            res["anomalies"].append("local_name_mismatch")
        if lh["method"] != entry["method"]:
            entry["local_method"] = lh["method"]
            res["anomalies"].append("local_method_mismatch")
        if entry["compressed_size"]:
            ranges.append((lh["data_offset"], lh["data_offset"] + entry["compressed_size"]))
        first = entry["local_header_offset"] if first is None else min(first, entry["local_header_offset"])
    ranges.sort()
    for (_s1, e1), (s2, _e2) in zip(ranges, ranges[1:]):
        if s2 < e1:
            res["anomalies"].append("overlapping_entries")
            break
    if first and first > 0 and not res["prefix_bytes"]:
        res["prefix_bytes"] = first


def _zip_local_scan(data: bytes, res: dict[str, Any], max_members: int) -> dict[str, Any]:
    """Listing from local headers when the central directory is missing or broken."""
    res["from_local_scan"] = True
    pos = data.find(b"PK\x03\x04")
    if pos > 0:
        res["prefix_bytes"] = pos
    while pos != -1 and len(res["entries"]) < max_members:
        lh = _local_header(data, pos)
        if lh is None:
            break
        name, utf8 = _decode_zip_name(lh["name_raw"], lh["flags"], {})
        enc, aes = _zip_encryption(lh["flags"], lh["method"], {})
        size = lh["compressed_size"]
        if lh["flags"] & 0x8 and size == 0:  # data descriptor: size unknown, find the next signature
            nxt = data.find(b"PK\x07\x08", lh["data_offset"])
            size = (nxt - lh["data_offset"]) if nxt != -1 else 0
        res["entries"].append({
            "name": name, "name_raw": lh["name_raw"], "utf8": utf8, "flags": lh["flags"], "method": lh["method"],
            "crc32": lh["crc32"], "compressed_size": size, "file_size": lh["file_size"], "local_header_offset": pos,
            "data_offset": lh["data_offset"], "external_attr": 0, "create_system": 0, "unix_mode": 0, "mtime": None,
            "is_dir": name.endswith("/"), "is_symlink": False, "hidden": False, "encrypted": bool(lh["flags"] & 1),
            "encryption": enc, "aes_strength": aes, "extra_ids": [], "comment": "", "local_ok": True,
        })
        pos = data.find(b"PK\x03\x04", lh["data_offset"] + max(size, 0))
    res["ok"] = bool(res["entries"])
    res["anomalies"] = sorted(set(res["anomalies"]))
    return res


def _crc_table() -> list[int]:
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        table.append(c)
    return table


_CRC_TABLE = _crc_table()


#: ZipCrypto runs in pure Python (~0.3 s/MB): larger encrypted members are listed, never decrypted
ZIPCRYPTO_MAX = 8 * 1024 * 1024


def zipcrypto_decrypt(buf: bytes, password: bytes, check: int) -> bytes:
    """Traditional PKWARE decryption with an analyst-supplied password (P365 c4: never guessed). The
    12-byte header is checked before the body is decrypted (a wrong password costs 12 bytes)."""
    if len(buf) < 12:
        raise ArchiveLimit("bad_password")
    if len(buf) > ZIPCRYPTO_MAX + 12:
        raise ArchiveLimit("zipcrypto_size_cap")
    crc = _CRC_TABLE
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
    for c in password:
        k0 = (k0 >> 8) ^ crc[(k0 ^ c) & 0xFF]
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = (k2 >> 8) ^ crc[(k2 ^ (k1 >> 24)) & 0xFF]
    out = bytearray(len(buf))
    for i, c in enumerate(buf):
        t = (k2 | 2) & 0xFFFF
        p = c ^ (((t * (t ^ 1)) >> 8) & 0xFF)
        out[i] = p
        k0 = (k0 >> 8) ^ crc[(k0 ^ p) & 0xFF]
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = (k2 >> 8) ^ crc[(k2 ^ (k1 >> 24)) & 0xFF]
        if i == 11 and p != check:
            raise ArchiveLimit("bad_password")
    return bytes(out[12:])


def zip_member_chunks(data: bytes, entry: dict[str, Any], *, max_out: int | None = None, ratio: int | None = None,
                      grace: int | None = None, password: bytes | None = None, ignore_encryption_flag: bool = False,
                      budget: Budget | None = None) -> Iterator[bytes]:
    """Bounded inflate of one member, chunk by chunk (size cap, ratio cap, read budget, truncation).

    ``password``: bytes supplied by the analyst (P365 c4). ``ignore_encryption_flag`` mirrors Android,
    which ignores bit 0 (the fake-encryption anti-analysis trick of APKs, P364 c2). Raises
    :class:`ArchiveLimit` on any refusal; the caller checks the CRC through :func:`zip_read`.
    """
    max_out = LIMITS["archive_total"] if max_out is None else max_out
    ratio = ratio or LIMITS["archive_ratio"]
    grace = LIMITS["ratio_grace"] if grace is None else grace
    start = entry.get("data_offset")
    if start is None:
        lh = _local_header(data, entry["local_header_offset"])
        if lh is None:
            raise ArchiveLimit("bad_local_header")
        start = lh["data_offset"]
    csize = entry["compressed_size"]
    comp = data[start:start + csize]
    if len(comp) < csize:
        raise ArchiveLimit("truncated_member")
    if budget is not None:
        budget.charge(len(comp))
    if entry.get("encrypted") and not ignore_encryption_flag:
        if entry.get("encryption") != "zipcrypto":
            raise ArchiveLimit(f"encrypted_{entry.get('encryption')}_needs_extra")
        if not password:
            raise ArchiveLimit("encrypted_needs_password")
        if entry["flags"] & 0x8:  # data descriptor: the check byte is the high byte of the DOS time
            check = (struct.unpack_from("<H", data, entry["local_header_offset"] + 10)[0] >> 8) & 0xFF
        else:
            check = (entry["crc32"] >> 24) & 0xFF
        comp = zipcrypto_decrypt(comp, password, check)
    method = entry["method"]
    if method == 0:
        if len(comp) > max_out:
            raise ArchiveLimit("size_cap")
        if comp:
            yield comp
        return
    if method != 8:
        raise ArchiveLimit(f"unsupported_method_{method}")
    d = zlib.decompressobj(-15)
    buf = comp
    total = 0
    while not d.eof:
        try:
            chunk = d.decompress(buf, 1 << 16)  # may emit pending match output even with no input left
        except zlib.error:
            raise ArchiveLimit("corrupt_deflate") from None
        buf = d.unconsumed_tail
        if not chunk and not buf:
            break
        total += len(chunk)
        if total > max_out:
            raise ArchiveLimit("size_cap")
        consumed = len(comp) - len(buf)
        if total > grace and total > ratio * max(consumed, 1):
            raise ArchiveLimit("ratio")
        if budget is not None:
            budget.charge(len(chunk))
        if chunk:
            yield chunk
    if not d.eof:
        raise ArchiveLimit("truncated_deflate")


def zip_read(data: bytes, entry: dict[str, Any], *, max_out: int | None = None, ratio: int | None = None,
             grace: int | None = None, password: bytes | None = None, ignore_encryption_flag: bool = False,
             budget: Budget | None = None) -> bytes:
    """One member's bytes with the caps of :func:`zip_member_chunks`; a CRC mismatch is flagged on the entry."""
    out = b"".join(zip_member_chunks(data, entry, max_out=max_out, ratio=ratio, grace=grace, password=password,
                                     ignore_encryption_flag=ignore_encryption_flag, budget=budget))
    if (binascii.crc32(out) & 0xFFFFFFFF) != entry["crc32"]:
        entry["crc_mismatch"] = True
    return out


# ======================================================================================== OLE / CFB reader

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


class CFB:
    """Bounded compound-file reader ([MS-CFB]): entries with paths, types, sizes and CLSIDs; ``read``
    with size caps, chain-loop detection and a per-file read budget. Raises ValueError for non-OLE input."""

    def __init__(self, data: bytes, *, tolerant: bool = False, max_sectors: int | None = None, budget: Budget | None = None) -> None:
        if data[:8] != OLE_MAGIC:
            raise ValueError("not_ole")
        if len(data) < 512:
            raise ValueError("truncated_header")
        self.data, self.tolerant = data, tolerant
        self.anomalies: list[str] = []
        self.max_sectors = max_sectors or LIMITS["cfb_max_sectors"]
        self.budget = budget or Budget()
        _minor, major, bom, sshift, mshift = struct.unpack_from("<HHHHH", data, 24)
        if bom != 0xFFFE:
            self.anomalies.append("bad_byte_order")
        if sshift not in (9, 12):
            raise ValueError("bad_sector_shift")
        if mshift != 6:
            self.anomalies.append("nonstandard_mini_sector")
            mshift = 6
        self.major = major
        self.ss, self.mss = 1 << sshift, 1 << mshift
        (_ndir, nfat, first_dir, _ts, cutoff, first_mini, nmini, first_difat, ndifat) = struct.unpack_from("<9I", data, 40)
        if cutoff != 4096:
            self.anomalies.append("nonstandard_mini_cutoff")
        self.cutoff = 4096
        n_sectors = max(1, len(data) // self.ss)
        difat = list(struct.unpack_from("<109I", data, 76))
        sid, hops, seen_difat = first_difat, 0, set()
        while sid < 0xFFFFFFFA and hops < min(ndifat, n_sectors) + 1 and sid not in seen_difat:
            seen_difat.add(sid)
            sec = self._sector(sid)
            if sec is None:
                break
            vals = struct.unpack_from(f"<{self.ss // 4}I", sec)
            difat.extend(vals[:-1])
            sid, hops = vals[-1], hops + 1
        self.fat: list[int] = []
        fat_sids = [s for s in difat if s < 0xFFFFFFFA][: max(0, min(nfat, n_sectors)) or None]
        for s in fat_sids:
            sec = self._sector(s)
            if sec is None:
                self.anomalies.append("fat_sector_missing")
                break
            self.fat.extend(struct.unpack_from(f"<{self.ss // 4}I", sec))
        self.entries: list[dict[str, Any]] = []
        dir_bytes = self._chain_bytes(first_dir, self.fat, self.ss)
        for i in range(min(len(dir_bytes) // 128, LIMITS["cfb_max_entries"])):
            e = dir_bytes[i * 128:(i + 1) * 128]
            nlen = u16(e, 64)
            name = e[: max(0, min(nlen, 64) - 2)].decode("utf-16-le", "replace")
            left, right, child = struct.unpack_from("<III", e, 68)
            size = u32(e, 120) if major == 3 else u64(e, 120)
            self.entries.append({"id": i, "name": name, "type": e[66], "left": left, "right": right, "child": child,
                                 "clsid": guid_le(e[80:96]), "ctime": filetime_to_iso(u64(e, 100)),
                                 "mtime": filetime_to_iso(u64(e, 108)), "start": u32(e, 116), "size": size, "path": None})
        if not self.entries or self.entries[0]["type"] != 5:
            if not tolerant:
                raise ValueError("no_root_entry")
            self.anomalies.append("no_root_entry")
            self.root_clsid = None
            self.minifat: list[int] = []
            self.ministream = b""
            return
        root = self.entries[0]
        self.root_clsid = root["clsid"] if root["clsid"] != "00000000-0000-0000-0000-000000000000" else None
        mf = self._chain_bytes(first_mini, self.fat, self.ss) if nmini else b""
        self.minifat = list(struct.unpack_from(f"<{len(mf) // 4}I", mf)) if mf else []
        self.ministream = self._chain_bytes(root["start"], self.fat, self.ss)[: root["size"]] if root["size"] else b""
        self._walk()

    def _sector(self, sid: int) -> bytes | None:
        off = (sid + 1) * self.ss
        if off + self.ss > len(self.data):
            if self.tolerant and off < len(self.data):
                return self.data[off:] + b"\x00" * (self.ss - (len(self.data) - off))
            return None
        return self.data[off:off + self.ss]

    def _chain(self, start: int, fat: list[int]) -> Iterator[int]:
        seen: set[int] = set()
        sid = start
        while sid < 0xFFFFFFFA:
            if sid in seen:
                self.anomalies.append("chain_loop")
                return
            if len(seen) >= self.max_sectors:
                self.anomalies.append("sector_cap")
                return
            seen.add(sid)
            yield sid
            if sid >= len(fat):
                if not self.tolerant:
                    self.anomalies.append("chain_out_of_range")
                return
            sid = fat[sid]

    def _chain_bytes(self, start: int, fat: list[int], size_unit: int) -> bytes:
        parts = []
        for sid in self._chain(start, fat):
            if fat is self.fat:
                sec = self._sector(sid)
                if sec is None:
                    self.anomalies.append("truncated_stream")
                    break
                parts.append(sec)
            else:
                off = sid * self.mss
                parts.append(self.ministream[off:off + self.mss])
            self.budget.charge(size_unit)
        return b"".join(parts)

    def _walk(self) -> None:
        stack = [(self.entries[0]["child"], "")]
        seen = {0}
        while stack:
            sid, parent = stack.pop()
            if sid >= len(self.entries) or sid in seen:
                if sid < len(self.entries):
                    self.anomalies.append("directory_loop")
                continue
            seen.add(sid)
            e = self.entries[sid]
            e["path"] = f"{parent}/{e['name']}" if parent else e["name"]
            stack.append((e["left"], parent))
            stack.append((e["right"], parent))
            if e["type"] == 1:
                stack.append((e["child"], e["path"]))
        self.entries[0]["path"] = ""

    def streams(self) -> list[dict[str, Any]]:
        return [e for e in self.entries if e["type"] == 2 and e["path"]]

    def find(self, path: str) -> dict[str, Any] | None:
        low = path.lower()
        for e in self.entries:
            if e["path"] is not None and e["path"].lower() == low:
                return e
        return None

    def read(self, entry_or_path: str | dict[str, Any], max_out: int | None = None) -> bytes | None:
        e = self.find(entry_or_path) if isinstance(entry_or_path, str) else entry_or_path
        if e is None:
            return None
        max_out = max_out or LIMITS["max_input"]
        if e["size"] > max_out:
            raise ArchiveLimit("size_cap")
        if e["size"] < self.cutoff and e["type"] == 2:
            buf = self._chain_bytes(e["start"], self.minifat, self.mss)
        else:
            buf = self._chain_bytes(e["start"], self.fat, self.ss)
        if len(buf) < e["size"]:
            self.anomalies.append("short_stream")
        return buf[: e["size"]]


# ======================================================================================== IOC stand-in

# Stand-in for the shared P172 extractor (core v3lum.core.ioc.extract, wave 3): same output shape.
_URL_RX = re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>\\^`{|}\x00-\x1f]{3,2048}", re.I)
_IPV4_RX = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])")
_HOST_RX = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
_VERSION_BEFORE = re.compile(r"(?:version|ver|v)[\s:=]{0,3}$")
_PACKAGE_ROOTS = frozenset({"com", "org", "net", "br", "io", "android", "androidx", "java", "javax", "kotlin", "kotlinx", "dalvik",
                            "google", "okhttp3", "okio", "retrofit2", "de", "me", "dev", "app"})
#: TLDs accepted for bare host names found in strings (a bare 'a.b' token is too ambiguous otherwise)
HOST_TLDS = frozenset({"com", "net", "org", "br", "io", "info", "biz", "xyz", "top", "online", "site", "ru", "cn", "app", "dev", "me",
                       "co", "tk", "ml", "ga", "cf", "gq", "us", "uk", "de", "fr", "es", "it", "pt", "ar", "mx", "cl", "pe", "uy",
                       "py", "shop", "store", "live", "cloud", "tech", "club", "link", "click", "icu", "cc", "ws", "su", "pw",
                       "in", "tv", "eu", "one", "zip", "mov"})


def ip_loose(host: str) -> str | None:
    """IPv4/IPv6 literal, also the decimal/hex/octal IPv4 forms Windows accepts -> canonical text."""
    h = (host or "").strip("[]")
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    parts = h.split(".")
    if not 1 <= len(parts) <= 4 or len(h) > 64:
        return None
    vals = []
    for p in parts:
        try:
            vals.append(int(p, 16) if p.lower().startswith("0x") else int(p, 8) if len(p) > 1 and p.startswith("0") else int(p))
        except ValueError:
            return None
    try:
        if len(vals) == 1:
            n = vals[0]
            if not h.isdigit() and not h.lower().startswith("0x"):
                return None
        elif len(vals) == 2:
            n = (vals[0] << 24) | vals[1]
        elif len(vals) == 3:
            n = (vals[0] << 24) | (vals[1] << 16) | vals[2]
        else:
            if any(v > 255 for v in vals):
                return None
            n = (vals[0] << 24) | (vals[1] << 16) | (vals[2] << 8) | vals[3]
        if not 0 <= n < 2**32:
            return None
        return str(ipaddress.IPv4Address(n))
    except (ValueError, ipaddress.AddressValueError):
        return None


def extract_iocs(text: str, *, max_items: int = 500) -> dict[str, list[str]]:
    """URLs, IPv4 addresses and host names in free text/strings ({'urls', 'ipv4', 'hosts'})."""
    urls: list[str] = []
    ips: list[str] = []
    hosts: list[str] = []
    for m in _URL_RX.finditer(text):
        u = m.group(0).rstrip(".,;)]'\"")
        if u not in urls:
            urls.append(u)
        try:
            h = (urllib.parse.urlsplit(u).hostname or "").lower()
        except ValueError:
            h = ""
        if h and not ip_loose(h) and h not in hosts:
            hosts.append(h)
        if len(urls) >= max_items:
            break
    for m in _IPV4_RX.finditer(text):
        if _VERSION_BEFORE.search(text[max(0, m.start() - 8):m.start()].lower()):
            continue  # 1.2.3.4-style version strings
        if m.group(0) not in ips:
            ips.append(m.group(0))
            if len(ips) >= max_items:
                break
    for line in text.split("\n")[:100_000]:
        s = line.strip().lower()
        if len(s) < 4 or len(s) > 253 or not _HOST_RX.match(s):
            continue
        labels = s.split(".")
        if labels[-1] not in HOST_TLDS or (labels[0] in _PACKAGE_ROOTS and len(labels) >= 3):
            continue  # reversed Java/Android package names look like hosts
        if s not in hosts:
            hosts.append(s)
            if len(hosts) >= max_items:
                break
    return {"urls": urls[:max_items], "ipv4": ips[:max_items], "hosts": hosts[:max_items]}


_NON_ROUTABLE = [ipaddress.ip_network(n) for n in ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                                                   "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "::1/128",
                                                   "::/128", "fc00::/7", "fe80::/10", "ff00::/8")]


def non_routable(ip: str) -> bool:
    """True for internal/loopback/link-local/CGNAT/multicast addresses (never hostile pivots)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(a in n for n in _NON_ROUTABLE if n.version == a.version)


# ======================================================================================== P270: magic table

_DATA_FILE = Path(__file__).resolve().parents[2] / "data" / "file_type_sniff" / "magic.json"
MAGIC_SCHEMA = "v3lum.magic_table/1"


@functools.lru_cache(maxsize=1)
def magic_table() -> tuple[tuple[int, bytes, str, str, str], ...]:
    """The bundled magic table (offset, magic bytes, kind, category, description), first match wins."""
    doc = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    if doc.get("schema") != MAGIC_SCHEMA:
        raise ValueError(f"{_DATA_FILE.name}: schema must be {MAGIC_SCHEMA!r}")
    rows = []
    for row in doc["rows"]:
        rows.append((int(row["offset"]), bytes.fromhex(row["hex"]), str(row["kind"]), str(row["category"]), str(row["description"])))
    return tuple(rows)


RAR4_SIG, RAR5_SIG, SEVENZIP_SIG = b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00", b"7z\xbc\xaf'\x1c"
_RIFF = {b"WEBP": ("webp", "image", "WebP image"), b"WAVE": ("wav", "media", "WAV audio"), b"AVI ": ("avi", "media", "AVI video")}
_FTYP_IMAGE = (b"heic", b"heix", b"mif1", b"msf1", b"avif", b"hevc")

_EXTRA_CATEGORIES = {
    "pe-exe": "executable", "pe-dll": "executable", "dos-mz": "executable", "java-class": "executable", "apk": "mobile",
    "aab": "mobile", "jar": "executable", "ooxml-docx": "document", "ooxml-docm": "document", "ooxml-xlsx": "document",
    "ooxml-xlsm": "document", "ooxml-xlsb": "document", "ooxml-pptx": "document", "ooxml-pptm": "document",
    "ooxml-vsdx": "document", "odf-text": "document", "odf-spreadsheet": "document", "odf-presentation": "document",
    "odf-graphics": "document", "odf-other": "document", "epub": "document", "appx": "installer", "xpi": "archive",
    "nupkg": "archive", "ipa": "mobile", "ole-doc": "document", "ole-xls": "document", "ole-ppt": "document",
    "ole-msg": "document", "ole-msi": "installer", "ole-msp": "installer", "ole-mst": "installer", "ole-vsd": "document",
    "ole-pub": "document", "ole-hwp": "document", "ole-encrypted-ooxml": "document", "ole-thumbs": "other", "webp": "image",
    "wav": "media", "avi": "media", "mp4": "media", "heif": "image", "svg": "image", "hta": "script", "js": "script",
    "vbs": "script", "ps1": "script", "batch": "script", "wsf": "script", "sct": "script", "xsl-script": "script",
    "script-shebang": "script", "python": "script", "html": "document", "xml": "document", "eml": "document",
    "url-shortcut": "shortcut", "reg": "script", "iqy": "script", "slk": "document", "settingcontent-ms": "shortcut",
    "library-ms": "shortcut", "searchconnector-ms": "shortcut", "text": "other", "empty": "other", "unknown": "other",
    "iso9660+udf": "disk_image", "deb": "archive", "dmg": "disk_image",
}


def kind_category(kind: str) -> str:
    for _off, _magic, k, cat, _desc in magic_table():
        if k == kind:
            return cat
    return _EXTRA_CATEGORIES.get(kind, "other")


#: kinds treated as executable content for the c5 HIGH rule
EXECUTABLE_KINDS = frozenset({
    "pe", "pe-exe", "pe-dll", "dos-mz", "elf", "macho", "macho-fat", "java-class", "jar", "dex", "apk", "wasm", "ole-msi",
    "ole-msp", "lnk", "chm", "hta", "js", "vbs", "vbe", "ps1", "batch", "wsf", "sct", "xsl-script", "script-shebang",
    "settingcontent-ms", "reg", "appx",
})
EXECUTABLE_EXTS = frozenset({
    "exe", "dll", "scr", "com", "pif", "cpl", "msi", "msp", "msix", "msixbundle", "appx", "appxbundle", "bat", "cmd", "js",
    "jse", "vbs", "vbe", "wsf", "wsh", "wsc", "hta", "ps1", "psm1", "lnk", "jar", "sct", "chm", "reg", "inf", "application",
    "appref-ms", "gadget", "msc", "xll", "settingcontent-ms", "iqy", "slk", "url", "scf", "library-ms", "searchconnector-ms",
    "diagcab", "apk", "sys", "drv", "ocx",
})
SCRIPT_EXTS = frozenset({"js", "jse", "vbs", "vbe", "wsf", "wsh", "wsc", "hta", "ps1", "psm1", "bat", "cmd", "sct"})
DOCUMENT_EXTS = frozenset({
    "pdf", "doc", "docx", "docm", "dot", "dotx", "dotm", "xls", "xlsx", "xlsm", "xlsb", "xlt", "xltx", "xltm", "ppt", "pptx",
    "pptm", "pps", "ppsx", "ppsm", "rtf", "odt", "ods", "odp", "odg", "txt", "csv", "xml", "html", "htm", "one", "msg",
    "eml", "epub", "md", "log", "json", "xps", "oxps",
})
IMAGE_EXTS = frozenset({"jpg", "jpeg", "jpe", "jfif", "png", "gif", "bmp", "tif", "tiff", "webp", "ico", "svg", "heic", "heif",
                        "avif", "psd"})
ARCHIVE_EXTS = frozenset({"zip", "rar", "7z", "gz", "tgz", "bz2", "tbz2", "xz", "txz", "zst", "tar", "cab", "iso", "img", "vhd",
                          "vhdx", "vmdk", "arj", "lzh", "ace", "z", "lz", "lz4", "dmg", "cpio", "rpm", "deb", "jar", "apk",
                          "xapk", "apks", "aab", "ipa", "nupkg", "xpi", "crx"})
MEDIA_EXTS = frozenset({"mp4", "m4a", "mov", "mp3", "wav", "avi", "mkv", "webm", "ogg", "flac", "flv", "wma", "wmv"})

ZIP_FAMILY = frozenset({"zip", "jar", "apk", "aab", "appx", "xpi", "nupkg", "ipa", "epub", "ooxml-docx", "ooxml-docm", "ooxml-xlsx",
                        "ooxml-xlsm", "ooxml-xlsb", "ooxml-pptx", "ooxml-pptm", "ooxml-vsdx", "odf-text", "odf-spreadsheet",
                        "odf-presentation", "odf-graphics", "odf-other"})
DISK_KINDS = frozenset({"iso9660", "udf", "iso9660+udf", "fat-image", "ntfs-image"})
#: extension -> acceptable kinds (anything else is a mismatch)
EXT_KINDS: dict[str, set[str]] = {
    "exe": {"pe-exe", "pe-dll", "pe", "dos-mz"}, "dll": {"pe-dll", "pe-exe", "pe"}, "scr": {"pe-exe", "pe"},
    "cpl": {"pe-dll", "pe-exe"}, "sys": {"pe-exe", "pe-dll"}, "ocx": {"pe-dll", "pe-exe"}, "efi": {"pe-exe", "pe-dll"},
    "com": {"pe-exe", "dos-mz", "unknown"}, "pdf": {"pdf"}, "doc": {"ole-doc"}, "dot": {"ole-doc"},
    "docx": {"ooxml-docx", "ole-encrypted-ooxml"}, "dotx": {"ooxml-docx"}, "docm": {"ooxml-docm", "ooxml-docx", "ole-encrypted-ooxml"},
    "dotm": {"ooxml-docm", "ooxml-docx"}, "xls": {"ole-xls"}, "xlt": {"ole-xls"}, "xla": {"ole-xls"},
    "xlsx": {"ooxml-xlsx", "ole-encrypted-ooxml"}, "xltx": {"ooxml-xlsx"}, "xlsm": {"ooxml-xlsm", "ooxml-xlsx", "ole-encrypted-ooxml"},
    "xltm": {"ooxml-xlsm", "ooxml-xlsx"}, "xlam": {"ooxml-xlsm", "ooxml-xlsx"}, "xlsb": {"ooxml-xlsb"}, "ppt": {"ole-ppt"},
    "pps": {"ole-ppt"}, "pot": {"ole-ppt"}, "pptx": {"ooxml-pptx", "ole-encrypted-ooxml"}, "ppsx": {"ooxml-pptx"},
    "pptm": {"ooxml-pptm", "ooxml-pptx"}, "ppsm": {"ooxml-pptm", "ooxml-pptx"}, "vsdx": {"ooxml-vsdx"}, "vsd": {"ole-vsd"},
    "pub": {"ole-pub"}, "hwp": {"ole-hwp"}, "rtf": {"rtf"}, "odt": {"odf-text"}, "ods": {"odf-spreadsheet"},
    "odp": {"odf-presentation"}, "odg": {"odf-graphics"}, "epub": {"epub"}, "msg": {"ole-msg"}, "eml": {"eml", "text"},
    "one": {"onenote"}, "onetoc2": {"onenote-toc"}, "onepkg": {"cab"}, "lnk": {"lnk"}, "url": {"url-shortcut", "text"},
    "msi": {"ole-msi"}, "msp": {"ole-msp"}, "mst": {"ole-mst"}, "msix": {"appx"}, "appx": {"appx"}, "msixbundle": {"appx"},
    "appxbundle": {"appx"}, "chm": {"chm"}, "hlp": {"hlp"}, "zip": set(ZIP_FAMILY), "jar": {"jar", "zip"}, "war": {"jar", "zip"},
    "apk": {"apk"}, "xapk": set(ZIP_FAMILY), "apks": set(ZIP_FAMILY), "aab": {"aab", "zip"}, "ipa": {"ipa", "zip"},
    "xpi": {"xpi", "zip"}, "crx": {"unknown", "zip"}, "nupkg": {"nupkg", "zip"}, "rar": {"rar4", "rar5"}, "7z": {"7z"},
    "gz": {"gzip"}, "tgz": {"gzip"}, "bz2": {"bzip2"}, "tbz2": {"bzip2"}, "xz": {"xz"}, "txz": {"xz"}, "zst": {"zstd"},
    "lz4": {"lz4"}, "lz": {"lzip"}, "z": {"compress-z"}, "tar": {"tar"}, "cab": {"cab"}, "arj": {"arj"}, "lzh": {"lzh"},
    "ace": {"ace"}, "cpio": {"cpio"}, "rpm": {"rpm"}, "deb": {"ar", "deb"}, "iso": set(DISK_KINDS), "img": set(DISK_KINDS) | {"vhd"},
    "vhd": {"vhd"}, "vhdx": {"vhdx"}, "vmdk": {"vmdk"}, "qcow2": {"qcow"}, "jpg": {"jpeg"}, "jpeg": {"jpeg"}, "jpe": {"jpeg"},
    "jfif": {"jpeg"}, "png": {"png"}, "gif": {"gif"}, "bmp": {"bmp"}, "tif": {"tiff"}, "tiff": {"tiff"}, "webp": {"webp"},
    "ico": {"ico"}, "svg": {"svg", "xml"}, "heic": {"heif"}, "heif": {"heif"}, "avif": {"heif"}, "psd": {"psd"}, "mp4": {"mp4"},
    "m4a": {"mp4"}, "mov": {"mp4"}, "mp3": {"mp3"}, "wav": {"wav"}, "avi": {"avi"}, "mkv": {"mkv"}, "webm": {"mkv"},
    "ogg": {"ogg"}, "flac": {"flac"}, "flv": {"flv"}, "js": {"js", "text"}, "jse": {"vbe"}, "vbs": {"vbs", "text"},
    "vbe": {"vbe"}, "ps1": {"ps1", "text"}, "psm1": {"ps1", "text"}, "bat": {"batch", "text"}, "cmd": {"batch", "text"},
    "hta": {"hta", "html"}, "wsf": {"wsf", "xml"}, "sct": {"sct", "xml"}, "wsc": {"sct", "xml"}, "sh": {"script-shebang", "text"},
    "py": {"python", "script-shebang", "text"}, "html": {"html", "xml", "text"}, "htm": {"html", "xml", "text"},
    "xml": {"xml", "svg", "xsl-script", "wsf", "sct", "html", "settingcontent-ms", "library-ms", "searchconnector-ms", "text"},
    "txt": {"text", "empty"}, "csv": {"text", "empty"}, "log": {"text", "empty"}, "md": {"text", "empty"}, "json": {"text", "empty"},
    "ini": {"text", "empty"}, "cfg": {"text", "empty"}, "reg": {"reg", "text"}, "iqy": {"iqy", "text"}, "slk": {"slk", "text"},
    "settingcontent-ms": {"settingcontent-ms", "xml"}, "library-ms": {"library-ms", "xml"},
    "searchconnector-ms": {"searchconnector-ms", "xml"}, "class": {"java-class"}, "dex": {"dex"}, "wasm": {"wasm"},
    "so": {"elf"}, "elf": {"elf"}, "dylib": {"macho", "macho-fat"}, "sqlite": {"sqlite"}, "db": {"sqlite", "ole-thumbs"},
    "pcap": {"pcap"}, "pcapng": {"pcapng"}, "evtx": {"evtx"},
}

#: c1: every file goes to these modules, whatever its kind
ALWAYS_ROUTES = ("file_hashing", "yara_scan")
#: c1: the single routing table of the approved file parsers (module names of the approved proposals)
ROUTES: dict[str, frozenset[str]] = {
    "document_metadata": frozenset({"pdf", "rtf", "ole-doc", "ole-xls", "ole-ppt", "ole-vsd", "ole-pub", "ole-hwp", "ole-msg",
                                    "ole-encrypted-ooxml", "ole", "ooxml-docx", "ooxml-docm", "ooxml-xlsx", "ooxml-xlsm",
                                    "ooxml-xlsb", "ooxml-pptx", "ooxml-pptm", "ooxml-vsdx", "odf-text", "odf-spreadsheet",
                                    "odf-presentation", "odf-graphics", "odf-other", "epub"}),
    "email_header_analyzer": frozenset({"eml", "ole-msg"}),
    "pe_triage": frozenset({"pe", "pe-exe", "pe-dll", "dos-mz"}),
    "elf_triage": frozenset({"elf"}),
    "apk_triage": frozenset({"apk", "aab", "dex"}),
    "archive_listing": frozenset({"zip", "jar", "xpi", "nupkg", "appx", "ipa", "tar", "gzip", "bzip2", "xz", "zstd", "lz4", "lzip",
                                  "compress-z", "rar4", "rar5", "7z", "cab", "ar", "deb", "rpm", "cpio", "arj", "lzh", "ace",
                                  "iso9660", "udf", "iso9660+udf", "vhd", "vhdx", "vmdk", "qcow", "fat-image", "ntfs-image"}),
    "windows_artifact_triage": frozenset({"lnk", "ole-msi", "ole-msp", "ole-mst", "onenote", "onenote-toc"}),
    "script_decoder": frozenset({"hta", "js", "vbs", "vbe", "ps1", "batch", "wsf", "sct", "xsl-script", "script-shebang", "python",
                                 "html", "svg", "iqy", "slk", "settingcontent-ms", "url-shortcut", "reg"}),
    "image_metadata": frozenset({"jpeg", "png", "gif", "tiff", "webp", "heif", "bmp", "psd"}),
    "image_ela": frozenset({"jpeg", "png"}),
    "qr_decode": frozenset({"jpeg", "png", "gif", "bmp", "webp"}),
    "image_ocr": frozenset({"jpeg", "png", "tiff", "bmp", "pdf"}),
}


def route(kind: str) -> list[str]:
    """c1: the modules that should receive a file of this kind (ALWAYS_ROUTES first)."""
    return list(ALWAYS_ROUTES) + sorted(m for m, kinds in ROUTES.items() if kind in kinds)


# ======================================================================================== P270: header facts

_PE_MACHINES = {0x14C: "Intel 80386", 0x8664: "x86-64", 0x1C0: "ARM", 0x1C4: "ARMv7 Thumb-2", 0xAA64: "ARM64",
                0x200: "Intel Itanium", 0xEBC: "EFI byte code"}
_PE_SUBSYS = {1: "native", 2: "GUI", 3: "console", 9: "Windows CE GUI", 10: "EFI application", 11: "EFI boot driver",
              12: "EFI runtime driver", 14: "Xbox", 16: "boot application"}


def pe_info(head: bytes, size: int | None = None) -> dict[str, Any] | None:
    """PE header facts from the first bytes: bits, DLL flag, machine, subsystem, .NET, overlay, Authenticode."""
    if len(head) < 0x40 or head[:2] != b"MZ":
        return None
    e_lfanew = u32(head, 0x3C)
    info: dict[str, Any] = {"kind": "dos-mz", "description": "MS-DOS executable", "e_lfanew": e_lfanew}
    if e_lfanew + 24 > len(head) or head[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return info
    machine, nsect, ts, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", head, e_lfanew + 4)
    opt = e_lfanew + 24
    if opt + 2 > len(head):
        return info
    plus = u16(head, opt) == 0x20B
    dll = bool(chars & 0x2000)
    subsystem = u16(head, opt + 68) if opt + 70 <= len(head) else None
    dd = opt + (112 if plus else 96)
    ndd = u32(head, opt + (108 if plus else 92)) if opt + 112 <= len(head) else 0
    dotnet = ndd > 14 and dd + 15 * 8 <= len(head) and u32(head, dd + 14 * 8) != 0
    sec_dir = (u32(head, dd + 4 * 8), u32(head, dd + 4 * 8 + 4)) if ndd > 4 and dd + 5 * 8 <= len(head) else (0, 0)
    raw_end = 0
    sect = opt + opt_size
    for i in range(min(nsect, 96)):
        s = sect + 40 * i
        if s + 40 > len(head):
            break
        raw_size, raw_ptr = struct.unpack_from("<II", head, s + 16)
        raw_end = max(raw_end, raw_ptr + raw_size)
    bits = "PE32+" if plus else "PE32"
    desc = f"{bits} {'DLL' if dll else 'executable'}"
    if subsystem in _PE_SUBSYS:
        desc += f" ({_PE_SUBSYS[subsystem]})"
    desc += f" {_PE_MACHINES.get(machine, hex(machine))}"
    if dotnet:
        desc += ", .NET assembly"
    info.update({"kind": "pe-dll" if dll else "pe-exe", "description": desc, "bits": 64 if plus else 32,
                 "machine": _PE_MACHINES.get(machine, hex(machine)), "subsystem": _PE_SUBSYS.get(subsystem) if subsystem is not None else None,
                 "dll": dll, "dotnet": dotnet, "sections": nsect, "timestamp": ts, "authenticode_present": sec_dir[1] > 0})
    if size is not None and raw_end:
        sig = sec_dir[1] if sec_dir[0] >= raw_end else 0
        info["overlay_size"] = max(0, size - raw_end - sig)
        info["overlay_offset"] = raw_end if info["overlay_size"] else None
    return info


_ELF_MACH = {3: "x86", 0x3E: "x86-64", 0x28: "ARM", 0xB7: "AArch64", 8: "MIPS", 0x14: "PowerPC", 0x15: "PowerPC64", 0xF3: "RISC-V",
             0x2B: "SPARC V9", 0x16: "S/390"}


def elf_info(head: bytes) -> dict[str, Any] | None:
    if len(head) < 52 or head[:4] != b"\x7fELF":
        return None
    cls, endian = head[4], head[5]
    e = "<" if endian == 1 else ">"
    etype, mach = struct.unpack_from(e + "HH", head, 16)
    kind = {1: "relocatable", 2: "executable", 3: "shared object", 4: "core dump"}.get(etype, "unknown type")
    if etype == 3:  # a PIE executable has a PT_INTERP program header
        try:
            if cls == 2:
                (phoff,) = struct.unpack_from(e + "Q", head, 32)
                phent, phnum = struct.unpack_from(e + "HH", head, 54)
            else:
                (phoff,) = struct.unpack_from(e + "I", head, 28)
                phent, phnum = struct.unpack_from(e + "HH", head, 42)
            for i in range(min(phnum, 64)):
                p = phoff + i * phent
                if p + 4 <= len(head) and struct.unpack_from(e + "I", head, p)[0] == 3:
                    kind = "PIE executable"
                    break
        except struct.error:
            pass
    bits = 64 if cls == 2 else 32
    return {"kind": "elf", "description": f"ELF {bits}-bit {kind}, {_ELF_MACH.get(mach, hex(mach))}", "bits": bits,
            "elf_type": kind, "machine": _ELF_MACH.get(mach, hex(mach))}


_MACHO_CPU = {7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000C: "ARM64", 18: "PowerPC"}


def macho_info(head: bytes) -> dict[str, Any] | None:
    if len(head) < 8:
        return None
    m = head[:4]
    if m in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        major = struct.unpack_from(">H", head, 6)[0]
        if 45 <= major <= 100:  # a Java class file shares the magic
            return {"kind": "java-class", "description": f"Java class file (version {major})"}
        n = struct.unpack_from(">I", head, 4)[0]
        if 0 < n < 30:
            return {"kind": "macho-fat", "description": f"Mach-O universal binary with {n} architectures"}
        return None
    if m in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf") and len(head) >= 16:
        e = "<" if m[0] in (0xCE, 0xCF) else ">"
        cpu, _sub, ftype = struct.unpack_from(e + "iii", head, 4)
        ft = {1: "object", 2: "executable", 6: "dynamic library", 8: "bundle"}.get(ftype, "file")
        bits = 64 if m in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") else 32
        return {"kind": "macho", "description": f"Mach-O {bits}-bit {ft} {_MACHO_CPU.get(cpu, hex(cpu & 0xFFFFFFFF))}"}
    return None


_OLE_CLSID = {
    "000c1084-0000-0000-c000-000000000046": "ole-msi", "000c1086-0000-0000-c000-000000000046": "ole-msp",
    "000c1082-0000-0000-c000-000000000046": "ole-mst", "00020906-0000-0000-c000-000000000046": "ole-doc",
    "00020900-0000-0000-c000-000000000046": "ole-doc", "00020820-0000-0000-c000-000000000046": "ole-xls",
    "00020810-0000-0000-c000-000000000046": "ole-xls", "64818d10-4f9b-11cf-86ea-00aa00b929e8": "ole-ppt",
}
OLE_DESCRIPTIONS = {"ole-msi": "Windows Installer package (MSI)", "ole-msp": "Windows Installer patch (MSP)",
                    "ole-mst": "Windows Installer transform (MST)", "ole-doc": "Word 97-2003 document",
                    "ole-xls": "Excel 97-2003 workbook", "ole-ppt": "PowerPoint 97-2003 presentation",
                    "ole-msg": "Outlook message (.msg)", "ole-vsd": "Visio drawing", "ole-pub": "Publisher document",
                    "ole-hwp": "Hangul word processor document",
                    "ole-encrypted-ooxml": "password-protected Office document (OLE EncryptedPackage)"}


def ole_subtype(names: Iterable[str], root_clsid: str | None = None) -> str:
    """OLE kind from directory names / root CLSID (MSI vs DOC vs XLS vs MSG ...)."""
    low = {n.lower() for n in names}
    if root_clsid in _OLE_CLSID and _OLE_CLSID[root_clsid] in ("ole-msi", "ole-msp", "ole-mst"):
        return _OLE_CLSID[root_clsid]
    if "encryptedpackage" in low and "encryptioninfo" in low:
        return "ole-encrypted-ooxml"
    if "worddocument" in low:
        return "ole-doc"
    if "workbook" in low or "book" in low:
        return "ole-xls"
    if "powerpoint document" in low:
        return "ole-ppt"
    if "__properties_version1.0" in low or any(n.startswith("__substg1.0_") for n in low):
        return "ole-msg"
    if "visiodocument" in low:
        return "ole-vsd"
    if "quill" in low or ("envelope" in low and "contents" in low):
        return "ole-pub"
    if "fileheader" in low and "\x05hwpsummaryinformation" in low:
        return "ole-hwp"
    if "catalog" in low:
        return "ole-thumbs"
    if root_clsid in _OLE_CLSID:
        return _OLE_CLSID[root_clsid]
    return "ole"


_DEX_NAME = re.compile(r"classes\d{0,4}\.dex")
_IPA_APP = re.compile(r"payload/[^/]{1,255}\.app/")


def zip_family_kind(names: Iterable[str], first_name: str | None = None, first_data: bytes | None = None) -> str:
    """c3: tell OOXML, APK, JAR, ODF/EPUB, APPX ... apart from central-directory names."""
    low = {n.lower() for n in names}
    if "androidmanifest.xml" in low and any(_DEX_NAME.fullmatch(n) for n in low):
        return "apk"
    if "base/manifest/androidmanifest.xml" in low or "bundleconfig.pb" in low:
        return "aab"
    if "androidmanifest.xml" in low and "resources.arsc" in low:
        return "apk"
    if first_name == "mimetype" and first_data:
        mt = first_data.strip().decode("ascii", "replace")
        if mt == "application/epub+zip":
            return "epub"
        if mt.startswith("application/vnd.oasis.opendocument."):
            return {"text": "odf-text", "spreadsheet": "odf-spreadsheet", "presentation": "odf-presentation",
                    "graphics": "odf-graphics"}.get(mt.rsplit(".", 1)[-1], "odf-other")
    if "[content_types].xml" in low:
        if any(n.startswith("word/") for n in low):
            return "ooxml-docm" if "word/vbaproject.bin" in low else "ooxml-docx"
        if any(n.startswith("xl/") for n in low):
            if "xl/workbook.bin" in low:
                return "ooxml-xlsb"
            macro = "xl/vbaproject.bin" in low or any(n.startswith("xl/macrosheets/") for n in low)
            return "ooxml-xlsm" if macro else "ooxml-xlsx"
        if any(n.startswith("ppt/") for n in low):
            return "ooxml-pptm" if "ppt/vbaproject.bin" in low else "ooxml-pptx"
        if any(n.startswith("visio/") for n in low):
            return "ooxml-vsdx"
    if "appxmanifest.xml" in low or "appxmetadata/appxbundlemanifest.xml" in low:
        return "appx"
    if "meta-inf/manifest.mf" in low or any(n.endswith(".class") for n in low):
        return "jar"
    if "install.rdf" in low or ("manifest.json" in low and any(n.startswith("meta-inf/mozilla") for n in low)):
        return "xpi"
    if any(n.endswith(".nuspec") for n in low):
        return "nupkg"
    if any(_IPA_APP.match(n) for n in low):
        return "ipa"
    if "mimetype" in low and "meta-inf/manifest.xml" in low:
        return "odf-other"
    return "zip"


# ======================================================================================== P270: text heuristics

# c2: HTA, JS, VBS, PS1, batch... by heuristics. Every quantifier next to a character class is bounded
# (linear scans of the 64 KB head, no catastrophic backtracking).
_SCRIPT_RULES: dict[str, list[tuple[str, int]]] = {
    "hta": [(r"<hta:application\b", 6), (r"<script[^>]{0,256}language\s{0,8}=\s{0,8}[\"']?(?:vbscript|jscript)", 2),
            (r"window\.(?:resizeto|moveto)\s{0,8}\(", 1)],
    "wsf": [(r"<job\b", 4), (r"<package\b", 2), (r"<script\s{1,8}language\s{0,8}=\s{0,8}[\"']?(?:vbscript|jscript|javascript)", 2)],
    "sct": [(r"<scriptlet\b", 6), (r"<registration\b", 3), (r"\bprogid\s{0,8}=", 1)],
    "xsl-script": [(r"<msxsl:script\b", 6), (r"<xsl:stylesheet\b", 1)],
    "settingcontent-ms": [(r"<pcsettings\b", 6), (r"<deeplink\b", 2)],
    "library-ms": [(r"<librarydescription\b", 6)],
    "searchconnector-ms": [(r"<searchconnectordescription\b", 6)],
    "ps1": [(r"\$env:[a-z_]", 2), (r"\b(?:invoke-expression|iex)\b", 2), (r"new-object\s{1,8}(?:system\.)?net\.webclient", 3),
            (r"-(?:e|ec|enc|encodedcommand)\s{1,8}[a-z0-9+/=]{20,4096}", 3), (r"\[system\.convert\]::frombase64string", 3),
            (r"\bparam\s{0,8}\(", 1), (r"\bwrite-(?:host|output)\b", 2), (r"\b(?:get|set|new|start|invoke)-[a-z]{3,32}\b", 1),
            (r"\$[a-z_][a-z0-9_]{0,64}\s{0,8}=", 1), (r"\.downloadstring\s{0,8}\(", 2), (r"\bfunction\s{1,8}[a-z][\w-]{0,64}\s{0,8}\{", 1)],
    "vbs": [(r"^\s{0,32}dim\s{1,8}\w", 2), (r"\bset\s{1,8}\w{1,64}\s{0,8}=\s{0,8}(?:wscript\.)?createobject\s{0,8}\(", 3),
            (r"\bwscript\.(?:shell|echo|sleep|arguments|scriptfullname)\b", 2), (r"\bon\s{1,8}error\s{1,8}resume\s{1,8}next\b", 3),
            (r"^\s{0,32}end\s{1,8}(?:sub|function|if)\b", 2), (r"\bmsgbox\b", 1), (r"\bchrw?\s{0,8}\(\s{0,8}\d{1,6}\s{0,8}\)\s{0,8}&", 1)],
    "js": [(r"\bvar\s{1,8}\w{1,64}\s{0,8}=", 1), (r"\bfunction\s{0,8}\w{0,64}\s{0,8}\([^)]{0,256}\)\s{0,8}\{", 1),
           (r"new\s{1,8}activexobject\s{0,8}\(", 4), (r"\beval\s{0,8}\(", 1), (r"string\.fromcharcode\s{0,8}\(", 2),
           (r"\b(?:const|let)\s{1,8}\w{1,64}\s{0,8}=", 1), (r"wscript\.createobject\s{0,8}\(\s{0,8}[\"']", 1),
           (r"\brequire\s{0,8}\(\s{0,8}[\"']", 2), (r"=>", 1)],
    "batch": [(r"^\s{0,32}@?echo\s{1,8}off\b", 4), (r"%~dp0|%comspec%|%temp%|%appdata%|%userprofile%", 2),
              (r"^\s{0,32}set\s{1,8}/[ap]\s", 2), (r"^\s{0,32}(?:rem\b|::)", 1), (r"\bgoto\s{1,8}:?\w", 2),
              (r"\bcmd(?:\.exe)?\s{1,8}/[ck]\b", 2), (r"\bif\s{1,8}(?:not\s{1,8})?exist\b", 2), (r"^\s{0,32}start\s{1,8}(?:\"\"|/b|/min)", 2)],
    "python": [(r"^\s{0,32}(?:import\s{1,8}\w|from\s{1,8}[\w.]{1,128}\s{1,8}import\b)", 2), (r"^\s{0,32}def\s{1,8}\w{1,64}\s{0,8}\(", 2),
               (r"if\s{1,8}__name__\s{0,8}==\s{0,8}[\"']__main__", 3)],
    "html": [(r"<!doctype\s{1,8}html|<html\b", 3), (r"<(?:body|head|div|meta)\b", 1)],
    "svg": [(r"<svg\b", 5)],
    "eml": [(r"^(?:received|return-path|message-id|mime-version|x-mailer|dkim-signature):", 2), (r"^(?:from|to|subject|date):", 1)],
    "url-shortcut": [(r"^\s{0,32}\[internetshortcut\]", 6)],
    "reg": [(r"^\s{0,32}(?:windows registry editor version 5\.00|regedit4)", 6)],
    "iqy": [(r"^web\s{0,8}\r?\n\s{0,8}1\s{0,8}\r?\n\s{0,8}https?://", 6)],
    "slk": [(r"^id;p", 5)],
}
_SCRIPT_RX = {kind: [(re.compile(p, re.I | re.M), w) for p, w in rules] for kind, rules in _SCRIPT_RULES.items()}

SCRIPT_DESCRIPTIONS = {"js": "JavaScript/JScript script", "vbs": "VBScript script", "ps1": "PowerShell script",
                       "batch": "Windows batch script", "hta": "HTML application (HTA)", "wsf": "Windows Script File",
                       "sct": "Windows scriptlet (SCT)", "xsl-script": "XSL stylesheet with embedded script",
                       "python": "Python script", "script-shebang": "Unix script", "html": "HTML document",
                       "svg": "SVG image (can carry script)", "eml": "e-mail message", "xml": "XML document",
                       "url-shortcut": "Internet shortcut (.url)", "reg": "registry script", "text": "text",
                       "iqy": "Excel web query (IQY)", "slk": "SYLK spreadsheet", "settingcontent-ms": "Windows settings shortcut",
                       "library-ms": "Windows library description", "searchconnector-ms": "Windows search connector"}


def decode_text(head: bytes) -> tuple[str | None, str | None]:
    """(text, encoding) when the head looks like text (BOM-aware, UTF-16LE without BOM), else (None, None)."""
    if not head:
        return None, None
    for bom, enc in ((b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be")):
        if head[: len(bom)] == bom:
            return head[len(bom):].decode(enc, "replace"), enc
    if b"\x00" in head[:4096]:
        even, odd = head[0:400:2], head[1:400:2]
        printable_even = sum(1 for b in even if b in (9, 10, 13) or 32 <= b < 127)
        if odd and odd.count(0) > 0.9 * len(odd) and printable_even > 0.9 * len(even):
            return head.decode("utf-16-le", "replace"), "utf-16-le"  # UTF-16LE without BOM (Windows PS1/VBS)
        return None, None
    sample = head[:8192]
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127 or b >= 0x80)
    if printable / max(len(sample), 1) < 0.95:
        return None, None
    try:
        return head.decode("utf-8"), "utf-8"
    except UnicodeDecodeError as exc:  # the 64 KB cut may split a multi-byte character
        if exc.start > len(head) - 4:
            return head[: exc.start].decode("utf-8"), "utf-8"
        return head.decode("latin-1"), "latin-1"


def script_guess(text: str) -> tuple[str, str, dict[str, int]]:
    """Score text against the heuristics: (kind, confidence 'high'|'medium'|'low', scores)."""
    t = text[:65536]
    scores: dict[str, int] = {}
    for kind, rules in _SCRIPT_RX.items():
        s = sum(w * min(len(rx.findall(t)), 3) for rx, w in rules)
        if s:
            scores[kind] = s
    lead = t.lstrip()
    if lead.startswith("#!"):
        line = lead.split("\n", 1)[0].lower()
        return ("python" if "python" in line else "script-shebang"), "high", scores
    xml_lead = lead[:64].lower().startswith("<?xml")
    if not scores:
        return ("xml", "medium", scores) if xml_lead else ("text", "low", scores)
    best = max(scores, key=lambda k: (scores[k], k))
    s = scores[best]
    if best == "eml" and s < 4:
        return "text", "low", scores
    conf = "high" if s >= 6 else "medium" if s >= 3 else "low"
    if conf == "low" and best != "svg":
        return ("xml" if xml_lead else "text"), "low", scores
    return best, conf, scores


# ======================================================================================== P270: sniff


def _ole_head_names(head: bytes) -> tuple[list[str], str | None]:
    """Directory names + root CLSID of an OLE file from the head bytes only (bounded, tolerant)."""
    try:
        cfb = CFB(head, tolerant=True, budget=Budget(8 * LIMITS["sniff_head"]))
    except (ValueError, struct.error, IndexError, ArchiveLimit):
        return [], None
    return [e["name"] for e in cfb.entries if e["type"] in (1, 2)], cfb.root_clsid


_ZIP_DESCRIPTIONS = {"apk": "Android package (APK)", "jar": "Java archive (JAR)", "epub": "EPUB e-book", "appx": "MSIX/APPX package",
                     "ooxml-docx": "Word document (OOXML)", "ooxml-docm": "macro-enabled Word document (OOXML)",
                     "ooxml-xlsx": "Excel workbook (OOXML)", "ooxml-xlsm": "macro-enabled Excel workbook",
                     "ooxml-pptx": "PowerPoint presentation (OOXML)", "ooxml-pptm": "macro-enabled PowerPoint",
                     "ooxml-xlsb": "Excel binary workbook", "ooxml-vsdx": "Visio drawing (OOXML)", "odf-text": "OpenDocument text",
                     "odf-spreadsheet": "OpenDocument spreadsheet", "odf-presentation": "OpenDocument presentation",
                     "odf-graphics": "OpenDocument drawing", "odf-other": "OpenDocument file", "xpi": "browser extension (XPI)",
                     "nupkg": "NuGet package", "ipa": "iOS app (IPA)", "aab": "Android app bundle (AAB)"}


def sniff(head: bytes, *, size: int | None = None, name: str | None = None, tail: bytes | None = None,
          zip_names: list[str] | None = None, zip_first: tuple[str, bytes] | None = None) -> dict[str, Any]:
    """File-type detection from the first <= 64 KB (+ the tail for EOCD/VHD footers + CD names).

    ``head``: first bytes (cut to 64 KB); ``size``: real file size; ``tail``: last ~64 KB (ZIP EOCD,
    VHD/DMG footers, appended-archive polyglots); ``zip_names``: central-directory member names
    (OOXML/APK/JAR...). Returns ``{'kind', 'category', 'description', 'confidence', 'details',
    'polyglot', 'entropy', 'size', 'routes'}``.
    """
    head = bytes(head[: LIMITS["sniff_head"]])
    if tail is None and size is not None and size <= len(head):
        tail = head  # the whole file is in the head: footers and appended archives are visible
    res: dict[str, Any] = {"kind": "unknown", "category": "other", "description": "unknown data", "confidence": "low",
                           "details": {}, "polyglot": [], "entropy": round(shannon_entropy(head), 3), "size": size}
    if not head:
        res.update(kind="empty", description="empty file", confidence="high")
        res["routes"] = route("empty")
        return res
    for off, magic, kind, cat, desc in magic_table():
        if head[off:off + len(magic)] == magic:
            res.update(kind=kind, category=cat, description=desc, confidence="high")
            break
    else:
        if head[:4] == b"RIFF" and head[8:12] in _RIFF:
            k, c, d = _RIFF[head[8:12]]
            res.update(kind=k, category=c, description=d, confidence="high")
        elif head[4:8] == b"ftyp":
            if head[8:12] in _FTYP_IMAGE:
                res.update(kind="heif", category="image", description="HEIF/AVIF image", confidence="high")
            else:
                res.update(kind="mp4", category="media", description="MPEG-4/QuickTime media", confidence="high")
        else:
            pdf_at = head[:1024].find(b"%PDF-")
            if pdf_at > 0:
                res.update(kind="pdf", category="document", description=f"PDF document (header at offset {pdf_at})", confidence="medium")
                res["details"]["pdf_header_offset"] = pdf_at
            else:
                text, enc = decode_text(head)
                if text is not None:
                    kind, conf, scores = script_guess(text)
                    desc = SCRIPT_DESCRIPTIONS.get(kind, kind)
                    res.update(kind=kind, category=kind_category(kind), confidence=conf,
                               description=desc if conf == "high" or kind in ("text", "xml") else f"{desc} (heuristic)")
                    res["details"].update(encoding=enc, script_scores=scores)
    kind = res["kind"]
    if kind == "pe":
        info = pe_info(head, size)
        if info:
            res.update(kind=info["kind"], description=info["description"])
            res["details"].update({k: v for k, v in info.items() if k not in ("kind", "description")})
    elif kind == "elf":
        info = elf_info(head)
        if info:
            res["description"] = info["description"]
            res["details"].update({k: v for k, v in info.items() if k not in ("kind", "description")})
    elif kind in ("macho", "macho-fat"):
        info = macho_info(head)
        if info:
            res.update(kind=info["kind"], description=info["description"], category=kind_category(info["kind"]) or "executable")
        else:
            res.update(kind="unknown", category="other", description="unknown data (CAFEBABE)", confidence="low")
    elif kind == "ole":
        names, clsid = _ole_head_names(head)
        sub = ole_subtype(names, clsid)
        res.update(kind=sub, category=kind_category(sub) if sub != "ole" else "document",
                   description=OLE_DESCRIPTIONS.get(sub, "OLE2 compound file"))
        res["details"].update(ole_root_clsid=clsid, ole_names_seen=len(names))
    elif kind == "zip":
        names = zip_names
        if names is None:  # small files: the head holds the central directory
            z = zip_scan(tail if tail is not None else head)
            names = [e["name"] for e in z["entries"]] if z["ok"] else []
        first = zip_first
        if first is None and head[:4] == b"PK\x03\x04":
            lh = _local_header(head, 0)
            if lh and lh["method"] == 0:
                first = (lh["name_raw"].decode("utf-8", "replace"), head[lh["data_offset"]:lh["data_offset"] + min(lh["compressed_size"], 128)])
        sub = zip_family_kind(names, *(first or (None, None)))
        res.update(kind=sub, category=kind_category(sub) if sub != "zip" else "archive",
                   description=_ZIP_DESCRIPTIONS.get(sub, res["description"]))
        res["details"]["zip_members_seen"] = len(names)
    elif kind == "iso9660":
        if _iso_has_udf(head):
            res["kind"] = "iso9660+udf"
            res["description"] = "ISO 9660 + UDF image"
        vid = _iso_volume_id(head)
        if vid:
            res["details"]["volume_id"] = vid
    elif kind == "bmp":
        if len(head) >= 6 and size and u32(head, 2) not in (size, 0) and abs(u32(head, 2) - size) > 8:
            res.update(kind="unknown", category="other", description="unknown data (BM)", confidence="low")
    elif kind == "bzip2" and not (len(head) > 3 and 0x31 <= head[3] <= 0x39):
        res.update(kind="unknown", category="other", description="unknown data (BZh)", confidence="low")
    elif kind == "ar" and b"debian-binary" in head[:200]:
        res.update(kind="deb", description="Debian package")
    if tail is not None and size:
        _tail_checks(res, tail)
    _polyglot_checks(res, head, tail)
    res["routes"] = route(res["kind"])
    return res


def _iso_has_udf(head: bytes) -> bool:
    for i in range(16, 32):
        ident = head[i * 2048 + 1:i * 2048 + 6]
        if ident in (b"NSR02", b"NSR03"):
            return True
        if ident not in (b"CD001", b"BEA01", b"BOOT2", b"CDW02"):
            return False
    return False


def _iso_volume_id(head: bytes) -> str | None:
    off = 16 * 2048
    if head[off:off + 1] == b"\x01" and head[off + 1:off + 6] == b"CD001":
        return clean_text(head[off + 40:off + 72].decode("latin-1"), 32) or None
    return None


def _tail_checks(res: dict[str, Any], tail: bytes) -> None:
    t = tail[-512:]
    if res["kind"] in ("unknown", "text") and t[:8] == b"conectix":
        res.update(kind="vhd", category="disk_image", description="VHD disk image (fixed)", confidence="high")
    elif res["kind"] == "unknown" and t[:4] == b"koly":
        res.update(kind="dmg", category="disk_image", description="Apple disk image (DMG)", confidence="medium")


def _polyglot_checks(res: dict[str, Any], head: bytes, tail: bytes | None) -> None:
    """c5: polyglots such as PDF+ZIP or PE+ZIP/RAR/7z (MEDIUM, POSSIBLE)."""
    kind = res["kind"]
    pdf_at = head[:1024].find(b"%PDF-")
    if pdf_at > 0 and kind != "pdf":
        res["polyglot"].append({"with": "pdf", "offset": pdf_at})
    # containers (archives, disk images) legitimately hold a ZIP at their end: only non-containers count.
    # An OLE2 compound file legitimately holds ZIP packages inside its streams (Word 2007+ theme data in .doc,
    # embedded OOXML objects; seen on Apache POI's benign SampleDoc.doc): a CFB file is a whole number of
    # 512-byte sectors, so only bytes past that grid (data appended after the compound file) count for OLE.
    size = res.get("size")
    ole_embedded = kind.startswith("ole") and isinstance(size, int) and size > 0 and size % 512 == 0
    if res["category"] in ("document", "executable", "image", "media", "installer", "shortcut", "script") \
            and kind not in ZIP_FAMILY and tail is not None and not ole_embedded:
        z = zip_scan(tail)
        if z["ok"] and z["entries"] and not z["from_local_scan"]:
            res["polyglot"].append({"with": "zip", "members": len(z["entries"])})
    if kind in ("pe-exe", "pe-dll", "pe"):
        for sig, label in ((RAR5_SIG, "rar5"), (RAR4_SIG, "rar4"), (SEVENZIP_SIG, "7z")):
            at = head.find(sig, 64)
            if at > 0:
                res["polyglot"].append({"with": label, "offset": at})
    if kind == "pdf" and head[:4] != b"%PDF" and head[:2] in (b"MZ", b"PK"):
        res["polyglot"].append({"with": "pe" if head[:2] == b"MZ" else "zip", "offset": 0})


_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069\u200b-\u200f]")
_EXT_TOKEN = re.compile(r"[a-z0-9_\-]{1,20}")
_PADDED = re.compile(r"(?:\s{3,}|_{5,})\.[A-Za-z0-9]{2,5}$|\.\w{1,20}\s{1,64}\.\w{1,20}$")


def split_name(name: str | None) -> dict[str, Any]:
    """'invoice.pdf.exe' -> {'base': 'invoice', 'exts': ['pdf', 'exe'], 'padded', 'rtlo', 'visible'}.

    'visible' is what Explorer shows: after U+202E the run is rendered right to left."""
    n = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    rtlo = "\u202e" in n
    if rtlo:
        before, after = n.split("\u202e", 1)
        after, _, rest = after.partition("\u202c")
        visible = before + after[::-1] + rest
    else:
        visible = n
    visible = _BIDI.sub("", visible)
    parts = visible.split(".")
    exts: list[str] = []
    for p in reversed(parts[1:]):
        p2 = p.strip().lower()
        if not p2 or not _EXT_TOKEN.fullmatch(p2):
            break
        exts.insert(0, p2)
    padded = bool(_PADDED.search(visible))
    return {"base": parts[0], "exts": exts, "padded": padded, "rtlo": rtlo, "visible": visible}


def is_double_extension(exts: list[str]) -> bool:
    return len(exts) >= 2 and exts[-1] in EXECUTABLE_EXTS and exts[-2] in (DOCUMENT_EXTS | IMAGE_EXTS | MEDIA_EXTS | ARCHIVE_EXTS)


CRITERIA = {
    "filename_rtlo": "the file name contains U+202E (right-to-left override): Explorer shows a different extension than the real one",
    "double_extension": "an executable extension follows a document/image/media/archive extension in the file name",
    "extension_mismatch": "the magic bytes (bundled V3LUM table) disagree with the file name extension",
    "polyglot": "a second valid container signature (ZIP central directory, PDF header, RAR/7z stub) was found in the same file",
}


def extension_findings(name: str | None, sniffed: dict[str, Any]) -> list[dict[str, Any]]:
    """c5 findings for one claimed file name + :func:`sniff` result.

    Executable content behind a document or image extension, and double extensions = HIGH; other
    mismatches = MEDIUM; polyglots = MEDIUM/POSSIBLE. Wording: 'claimed .pdf, actually PE32 executable'.
    Generic containers whose subtype could not be read never claim a mismatch.
    """
    out: list[dict[str, Any]] = []
    kind = sniffed.get("kind", "unknown")
    desc = sniffed.get("description", kind)
    sp = split_name(name or "")
    exts = sp["exts"]
    ext = exts[-1] if exts else None
    if sp["rtlo"]:
        out.append(fact("filename_rtlo", "high", f'Suspicious file name with a right-to-left override: displays as "{clean_text(sp["visible"], 120)}"',
                        confidence="probable", attack="T1036.002", criterion=CRITERIA["filename_rtlo"], tags=["suspicious", "masquerading"],
                        description="Explorer renders the name right to left after U+202E, hiding the real extension.",
                        name=clean_text(name, 260)))
    if is_double_extension(exts):
        out.append(fact("double_extension", "high", f'Suspicious double extension ".{exts[-2]}.{exts[-1]}"', confidence="probable",
                        attack="T1036.007", criterion=CRITERIA["double_extension"], tags=["suspicious", "masquerading"],
                        description=f"{clean_text(sp['visible'], 200)}: Windows hides the last extension by default, so the file "
                                    f"looks like a .{exts[-2]}." + (" The name is padded to push the real extension out of view." if sp["padded"] else ""),
                        name=clean_text(name, 260), padded=sp["padded"]))
    if ext and kind not in ("unknown", "empty"):
        accepted = EXT_KINDS.get(ext)
        weak = sniffed.get("confidence") == "low"
        details = sniffed.get("details") or {}
        generic_parent = (kind == "ole" and bool(accepted) and all(a.startswith("ole-") for a in accepted)) or \
            (kind == "zip" and not details.get("zip_members_seen") and bool(accepted) and accepted <= ZIP_FAMILY)
        if accepted is not None and kind not in accepted and not (weak and "text" in accepted) and not generic_parent:
            exec_content = kind in EXECUTABLE_KINDS
            high = exec_content and ext in (DOCUMENT_EXTS | IMAGE_EXTS)
            out.append(fact("extension_mismatch", "high" if high else "medium", f"Extension mismatch: claimed .{ext}, actually {desc}",
                            confidence="probable" if sniffed.get("confidence") == "high" else "possible", attack="T1036.008",
                            criterion=CRITERIA["extension_mismatch"], tags=["suspicious", "masquerading"] if high else ["masquerading"],
                            description=("Executable content behind a document or image extension." if high else
                                         "The content does not match the extension (renamed or disguised file)."),
                            claimed_ext=ext, actual_kind=kind, executable_content=exec_content))
    for pg in sniffed.get("polyglot") or []:
        out.append(fact("polyglot", "medium", f"Polyglot: {desc} that is also a valid {str(pg.get('with', '')).upper()}", confidence="possible",
                        criterion=CRITERIA["polyglot"], tags=["polyglot"],
                        description="Two parsers see two different files: a common trick to slip a payload past content filters.", **pg))
    return out


def sniff_path(path: str, *, name: str | None = None) -> dict[str, Any]:
    """c1 library function: sniff a regular file (64 KB head, 64 KB tail, ZIP central-directory names).
    Raises :class:`FileRefused` for missing/special/unreadable paths."""
    head, tail, size, names = read_head_tail(path)
    return sniff(head, size=size, name=name or os.path.basename(path), tail=tail, zip_names=names)


def routes_for_path(path: str) -> list[str]:
    """The modules a file goes to (``[]`` when the path cannot be read)."""
    try:
        return sniff_path(path)["routes"]
    except (FileRefused, OSError):
        return []


def applies_to_file(module_name: str, entity: Entity) -> bool:
    """Applicability of a file module through the single routing table (c1)."""
    return entity.type is T.FILE and module_name in routes_for_path(entity.value)


# ======================================================================================== the module


@register
class FileTypeSniff(Module):
    name = "file_type_sniff"
    title = "File type detection (own magic table)"
    description = (
        "Identifies a local file's real type from its first 64 KB, the ZIP central directory and its footer with V3LUM's "
        "own bundled magic table and script heuristics; flags extension/content mismatches, double extensions, "
        "right-to-left-override names and polyglots, and routes the file to the right analysers. Offline."
    )
    category = "file_analysis"
    accepts = {T.FILE, T.TEXT}
    produces = frozenset()
    tags = {"offline"}
    reference = "https://attack.mitre.org/techniques/T1036/008/"
    notice = "Offline: the file never leaves the machine and is never executed. hachoir (GPL) is not used; Magika and libmagic are not used in this build."
    terms = "open"  # own code, no registry source
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.02
    timeout = 20.0
    max_pivots = 0
    default_enabled = True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type is T.TEXT:
            return self._text(entity, res)
        try:
            sn = sniff_path(entity.value)
        except FileRefused as exc:
            if exc.kind == "unreadable":
                return res.mark("error", exc.reason)
            return res.mark("skipped", exc.reason, reason_code="not_applicable")
        claimed = os.path.basename(entity.value)
        res.attr("file_type", sn["description"])
        res.attr("file_size", sn["size"])
        res.attr("file_sniff", _sniff_attribute(sn, claimed))
        res.finding(
            f"File type: {sn['description']}",
            "info",
            f"Identified from the magic bytes and structure ({sn['confidence']} confidence); routed to: {', '.join(sn['routes'])}.",
            confidence=_CONFIDENCE[sn["confidence"]],
            data={"kind": sn["kind"], "category": sn["category"], "routes": sn["routes"], "entropy": sn["entropy"]},
            tags=["info"],
        )
        emit_findings(res, extension_findings(claimed, sn))
        res.raw = cap_json({"sniff": sn, "claimed_name": claimed})
        return res

    def _text(self, entity: Entity, res: ModuleResult) -> ModuleResult:
        data = entity.value.encode("utf-8", "replace")[: LIMITS["sniff_head"]]
        sn = sniff(data, size=len(data))
        res.attr("file_sniff", _sniff_attribute(sn, None))
        if sn["category"] in ("script", "shortcut") or sn["kind"] in ("html", "svg", "eml", "xml"):
            res.attr("file_type", sn["description"])
            res.finding(f"Content type: {sn['description']}", "info",
                        f"Pasted text identified by heuristics ({sn['confidence']} confidence); routed to: {', '.join(sn['routes'])}.",
                        confidence=_CONFIDENCE[sn["confidence"]],
                        data={"kind": sn["kind"], "routes": sn["routes"]}, tags=["info"])
        res.raw = cap_json({"sniff": sn})
        return res


#: sniff confidence -> finding confidence label
_CONFIDENCE = {"high": "confirmed", "medium": "probable", "low": "possible"}


def _sniff_attribute(sn: dict[str, Any], claimed: str | None) -> dict[str, Any]:
    details = {k: v for k, v in (sn.get("details") or {}).items() if k != "script_scores"}
    out = {"kind": sn["kind"], "category": sn["category"], "description": sn["description"], "confidence": sn["confidence"],
           "entropy": sn["entropy"], "routes": sn["routes"], "polyglot": sn["polyglot"], "details": _jsonable(details)}
    if claimed is not None:
        sp = split_name(claimed)
        out["claimed_extension"] = sp["exts"][-1] if sp["exts"] else None
    return out
