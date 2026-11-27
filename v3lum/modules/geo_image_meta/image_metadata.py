"""Image metadata: EXIF/XMP/IPTC dates, camera make/model/serial, software and GPS (P259, batch p2-G12-1).

Offline module (disclosure 'none', terms 'open', provider tier n/a, default-on, A3). Final conditions:

* c1 FILE input only: this passive module never fetches URLs. An analyst-typed URL is downloaded only by the
  shared LIGHT file fetcher (P269; built in the LIGHT/ACTIVE phase, docs/backlog/p2-G12-1.md), which hands the
  module a file.
* c2 parsing in the shared file-analysis sandbox ``core/sandbox.py``: when the core provides it
  (:func:`core_sandbox`), Pillow (and ExifRead for HEIC/RAW) run only there through :func:`sandbox_run` (python
  -I child, wall timeout, rlimits, 100 MB input, 1 MB JSON output). This build has no core sandbox yet, so the
  module parses with :func:`scan_image_bytes`: a bounded, pure standard-library reader that decodes no pixels
  (1000 entries per IFD, 64 KB per value, IFD-loop detection, MakerNote size only, XMP 1 MB, capped PNG text
  inflate) on a regular file of at most 100 MB. Pillow, a C decoder, is never run in process here. Downloaded
  data is never executed.
* c3 decompression bombs: the declared pixel count is checked from the header against
  :data:`IMAGE_MAX_PIXELS` (Pillow's ``Image.MAX_IMAGE_PIXELS`` in the sandbox child, warning promoted to an
  error) and refused with an ERROR result and a clear reason; nothing is decoded. ExifRead (BSD-3) is the
  HEIC/RAW fallback (sandbox only); ExifTool (GPL) would only ever be an external binary (A6); pillow-heif is
  not used (GPLv2 wheels).
* c4 EXIF/XMP/IPTC dates, camera make/model/serial and software become attributes; editing software
  (Photoshop, GIMP...) an INFO finding; an EXIF thumbnail whose aspect ratio differs from the main image
  'possible crop/edit' (rotated thumbnails and, in the sandbox, letterboxed ones are notes only).
* c5 GPS becomes a ``coordinates`` pivot (relation ``photo_taken_at``, expand=False, privacy note); no
  reverse geocoding, map, Wi-Fi or other lookup ever runs; map links are privacy links of the geo_image pack
  rendered by pivots_geo_image only for coordinates the analyst confirmed (P260 cond 11).
* c6 no face detection or recognition of any kind (no biometric library is imported; tested). GPS, camera
  serials and owner fields are listed in :data:`PRIVACY_ATTRIBUTES` and stripped by :func:`export_view` from
  STIX/MISP exports unless the analyst opts in for the case (the exporter calls it; core request).
* c7 plain-language summary first ('taken 2026-03-01 14:22 (UTC-03:00) with <make/model>, GPS present'), with
  the notes that missing EXIF is normal and that EXIF can be edited; missing EXIF is never a finding.
* c8 tests build synthetic images (the research JPEG with GPS, a decompression bomb, a truncated file).
"""

from __future__ import annotations

import collections
import datetime as _dt
import importlib
import io
import math
import os
import re
import stat as _stat
import struct
import unicodedata
import warnings
import zlib
from collections.abc import Iterator
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, package_available, register

# ======================================================================================================
# Shared by the batch: input reading and the core sandbox adapter (qr_decode, pe_triage, yara_scan import it)
# ======================================================================================================

INPUT_CAP = 100 * 1024 * 1024  # c2: sandbox input cap (100 MB)
SANDBOX_MODULE = "v3lum.core.sandbox"  # the shared file-analysis sandbox (P269 c2/c5); not in this build yet
SANDBOX_DEFAULTS: dict[str, Any] = {
    "wall_timeout": 15.0, "cpu_seconds": 10, "mem_bytes": 1 << 30, "max_input": INPUT_CAP, "max_output": 1 << 20,
}
NO_SANDBOX_NOTE = ("core/sandbox.py is not in this build: third-party parsers are never run in process, so the "
                   "bounded standard-library reader was used")


class InputRefused(ValueError):
    """The input path is not a regular file the module may read. ``code`` is a reason code for res.mark()."""

    def __init__(self, message: str, code: str = "not_applicable", status: str = "skipped") -> None:
        super().__init__(message)
        self.code = code
        self.status = status


class SandboxUnavailable(RuntimeError):
    """The core file-analysis sandbox is missing (or its API differs): the library path cannot run."""


def read_regular_file(path: Any, cap: int = INPUT_CAP) -> bytes:
    """Bytes of a regular file of at most ``cap`` bytes (FIFOs, devices, sockets and directories are refused
    before anything is opened; the descriptor is re-checked with fstat so a swapped path is refused too)."""
    if not isinstance(path, str) or not path:
        raise InputRefused("no file path")
    try:
        st = os.stat(path)
    except FileNotFoundError:
        raise InputRefused("the file no longer exists") from None
    except OSError as exc:
        raise InputRefused(f"cannot stat the file: {exc.strerror or type(exc).__name__}", "error", "error") from None
    if not _stat.S_ISREG(st.st_mode):
        raise InputRefused("only regular files are analysed (FIFOs, devices, sockets and directories are refused)")
    if st.st_size > cap:
        raise InputRefused(f"file larger than the {cap // (1024 * 1024)} MB analysis cap", "error", "error")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise InputRefused(f"cannot open the file: {exc.strerror or type(exc).__name__}", "error", "error") from None
    with os.fdopen(fd, "rb", buffering=0) as fh:
        if not _stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise InputRefused("the path changed between the check and the open: not read")
        data = fh.read(cap + 1)
    if len(data) > cap:
        raise InputRefused(f"file larger than the {cap // (1024 * 1024)} MB analysis cap", "error", "error")
    return data


def read_head(path: Any, n: int = 64) -> bytes:
    """First ``n`` bytes of a regular file (b'' for anything else); used by applies()."""
    try:
        if not isinstance(path, str) or not _stat.S_ISREG(os.stat(path).st_mode):
            return b""
        with open(path, "rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def core_sandbox() -> Any | None:
    """The core file-analysis sandbox module (``v3lum.core.sandbox``) when this build has it, else None."""
    try:
        mod = importlib.import_module(SANDBOX_MODULE)
    except ImportError:
        return None
    return mod if callable(getattr(mod, "run_sandboxed", None)) else None


def sandbox_run(target: str, path: str, *, args: dict[str, Any] | None = None, **limits: Any) -> dict[str, Any]:
    """Run ``target`` ('package.module:function', called as ``function(data: bytes, **args)``) on one file inside
    the core sandbox and return its result dict ``{'ok', 'result', 'error', 'reason_code', 'elapsed_s',
    'isolation'}`` (the p1-G12-1 prototype contract). Raises :class:`SandboxUnavailable` when the core has no
    sandbox or its API is not the expected one; never runs the target in process."""
    sb = core_sandbox()
    if sb is None:
        raise SandboxUnavailable(NO_SANDBOX_NOTE)
    cfg = {**SANDBOX_DEFAULTS, **limits}
    try:
        out = sb.run_sandboxed(target, path, args=dict(args or {}), **cfg)
    except TypeError as exc:  # an API other than the one this batch asked for (core request)
        raise SandboxUnavailable(f"core/sandbox.py API mismatch ({exc})") from None
    if not isinstance(out, dict):
        return {"ok": False, "result": None, "error": "sandbox returned no result object", "reason_code": "bad_output"}
    return out


def sandbox_failure(out: dict[str, Any]) -> tuple[str, str]:
    """(reason_code, reason) of a failed sandbox run: timeouts -> 'timeout', everything else -> 'error'."""
    code = str(out.get("reason_code") or "error")
    err = str(out.get("error") or code)[:200]
    if code in ("timeout", "cpu_limit"):
        return "timeout", f"parser stopped by the sandbox ({code}): could not verify"
    return "error", f"parser failed in the sandbox ({code}: {err})"


# ======================================================================================================
# [common] (prep parsers.py, stdlib only)
# ======================================================================================================

def as_str(value: Any, limit: int = 4096) -> str | None:
    """Best-effort text from str/bytes/numbers; None for None/containers.  Strips NULs and C0/C1 controls
    except tab/newline (AR13 safe_text happens later in the renderer; this only keeps JSON clean)."""
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return None
    if isinstance(value, bytes):
        for enc in ('utf-8', 'latin-1'):
            try:
                value = value.decode(enc)
                break
            except UnicodeDecodeError:  # pragma: no cover - latin-1 never fails
                continue
    text = str(value)
    text = ''.join(ch for ch in text if ch in '\t\n' or not unicodedata.category(ch).startswith('C'))
    text = text.strip().strip('\x00').strip()
    return text[:limit] if text else None


def as_int(value: Any) -> int | None:
    """int from int/float/numeric str; None otherwise (bool is rejected)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return int(value)
    if isinstance(value, str) and re.fullmatch(r'\s*-?\d{1,20}\s*', value):
        return int(value)
    return None


def as_float(value: Any) -> float | None:
    """float from int/float/numeric str/(num, den) pair/{'num','den'} dict; None when not finite."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (list, tuple)) and len(value) == 2:
        num, den = as_float(value[0]), as_float(value[1])
        if num is None or den in (None, 0.0):
            return None
        value = num / den
    elif isinstance(value, dict) and 'num' in value and 'den' in value:
        return as_float((value.get('num'), value.get('den')))
    elif isinstance(value, str):
        try:
            value = float(value.strip())
        except ValueError:
            return None
    if isinstance(value, (int, float)):
        value = float(value)
        return value if math.isfinite(value) else None
    return None


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 for empty input)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(data).values())


def defang_url(url: str) -> str:
    """Defanged display form (P261 c5, AR13): hxxp(s)://host[.]tld/path; dots in the host only."""
    text = as_str(url, 8192) or ''
    m = re.match(r'(?i)^(https?|ftp)://([^/?#]*)(.*)$', text, re.S)
    if not m:
        return text.replace('://', '[://]').replace('.', '[.]', 1) if '://' in text else text
    scheme, host, rest = m.groups()
    scheme = {'http': 'hxxp', 'https': 'hxxps', 'ftp': 'fxp'}[scheme.lower()]
    return f'{scheme}://{host.replace(".", "[.]")}{rest}'

# ======================================================================================================
# [P259 image_metadata] (prep parsers.py, stdlib only)
# ======================================================================================================

IMAGE_MAX_PIXELS = 50_000_000            # P259 c3: Image.MAX_IMAGE_PIXELS (warning promoted to error)
IMAGE_INPUT_CAP = 100 * 1024 * 1024      # P259 c2: sandbox input cap
TIFF_MAX_ENTRIES = 1000                  # per IFD
TIFF_MAX_VALUE_BYTES = 64 * 1024         # per tag value (MakerNote is never decoded)
XMP_MAX_BYTES = 1 << 20

EXIF_NAMES = {
    'ifd0': {270: 'ImageDescription', 271: 'Make', 272: 'Model', 274: 'Orientation', 305: 'Software',
             306: 'DateTime', 315: 'Artist', 11: 'ProcessingSoftware', 33432: 'Copyright', 40093: 'XPAuthor',
             256: 'ImageWidth', 257: 'ImageLength'},
    'exif': {36867: 'DateTimeOriginal', 36868: 'DateTimeDigitized', 36880: 'OffsetTime',
             36881: 'OffsetTimeOriginal', 36882: 'OffsetTimeDigitized', 37521: 'SubsecTimeOriginal',
             40962: 'PixelXDimension', 40963: 'PixelYDimension', 42032: 'CameraOwnerName',
             42033: 'BodySerialNumber', 42034: 'LensSpecification', 42035: 'LensMake', 42036: 'LensModel',
             42037: 'LensSerialNumber', 37500: 'MakerNote', 42016: 'ImageUniqueID', 37510: 'UserComment'},
    'gps': {0: 'GPSVersionID', 1: 'GPSLatitudeRef', 2: 'GPSLatitude', 3: 'GPSLongitudeRef', 4: 'GPSLongitude',
            5: 'GPSAltitudeRef', 6: 'GPSAltitude', 7: 'GPSTimeStamp', 18: 'GPSMapDatum', 29: 'GPSDateStamp',
            16: 'GPSImgDirectionRef', 17: 'GPSImgDirection', 27: 'GPSProcessingMethod'},
    'ifd1': {259: 'Compression', 513: 'JPEGInterchangeFormat', 514: 'JPEGInterchangeFormatLength',
             256: 'ImageWidth', 257: 'ImageLength'},
}
_POINTER_TAGS = {34665, 34853, 40965}
_TIFF_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4}

# editing software -> canonical label (P259 c4: INFO tag).  Camera firmware strings are not editors.
EDITING_SOFTWARE = (
    (r'photoshop', 'Adobe Photoshop'), (r'lightroom', 'Adobe Lightroom'), (r'\bgimp\b', 'GIMP'),
    (r'paint\.net', 'Paint.NET'), (r'affinity photo', 'Affinity Photo'), (r'pixelmator', 'Pixelmator'),
    (r'photopea', 'Photopea'), (r'snapseed', 'Snapseed'), (r'picsart', 'PicsArt'), (r'\bcanva\b', 'Canva'),
    (r'\bfotor\b', 'Fotor'), (r'luminar', 'Luminar'), (r'capture one', 'Capture One'),
    (r'darktable', 'darktable'), (r'rawtherapee', 'RawTherapee'), (r'acdsee', 'ACDSee'),
    (r'paintshop', 'Corel PaintShop'), (r'imagemagick', 'ImageMagick'), (r'graphicsmagick', 'GraphicsMagick'),
    (r'picasa', 'Picasa'), (r'facetune', 'Facetune'), (r'meitu', 'Meitu'), (r'remini', 'Remini'),
    (r'microsoft photos|windows photo editor', 'Microsoft Photos'), (r'\bpaint\b', 'Microsoft Paint'),
)
MISSING_EXIF_NOTE = ('Missing EXIF is normal: WhatsApp, Telegram, social platforms and screenshots strip it. '
                     'It is never a finding.')
EDITABLE_EXIF_NOTE = 'EXIF can be edited: treat these values as claims by the file, not as proof.'
STRIP_EXPORT_FIELDS = ('gps', 'camera.serial', 'camera.lens_serial', 'owner')   # P259 c6


def jsonable_bytes(value: bytes) -> Any:
    """Shared bytes -> JSON shape used by the children and the stdlib readers: printable ASCII -> str
    (trailing NULs dropped), otherwise {'hex'}; > 256 bytes -> {'bytes_len'}."""
    if len(value) > 256:
        return {'bytes_len': len(value)}
    text = value.rstrip(b'\x00')
    if text and all(32 <= b < 127 for b in text):
        return text.decode('ascii')
    return {'hex': value.hex()}


def _b(value: Any) -> bytes | None:
    if isinstance(value, dict) and isinstance(value.get('hex'), str):
        try:
            return bytes.fromhex(value['hex'])
        except ValueError:
            return None
    if isinstance(value, str):
        return value.encode('utf-8')
    if isinstance(value, list) and all(isinstance(x, int) and 0 <= x < 256 for x in value):
        return bytes(value)
    if isinstance(value, int) and 0 <= value < 256:
        return bytes([value])
    return None


def sniff_image(data: bytes) -> str | None:
    """Container sniff for routing (P259 c3: HEIC/AVIF/RAW -> ExifRead fallback)."""
    if data[:3] == b'\xff\xd8\xff':
        return 'JPEG'
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        return 'PNG'
    if data[:4] == b'RIFF' and data[8:12] == b'WEBP':
        return 'WEBP'
    if data[:4] in (b'II*\x00', b'MM\x00*'):
        return 'TIFF'
    if data[:6] in (b'GIF87a', b'GIF89a'):
        return 'GIF'
    if data[:2] == b'BM':
        return 'BMP'
    if data[4:8] == b'ftyp':
        brand = data[8:12]
        if brand in (b'heic', b'heix', b'hevc', b'hevx', b'heim', b'heis', b'mif1', b'msf1'):
            return 'HEIC'
        if brand in (b'avif', b'avis'):
            return 'AVIF'
    return None


def _tiff_value(t: bytes, bo: str, typ: int, cnt: int, raw: bytes) -> Any:
    if typ == 2:
        s = raw.split(b'\x00', 1)[0]
        try:
            return s.decode('utf-8').strip()
        except UnicodeDecodeError:
            return s.decode('latin-1').strip()
    if typ in (1, 6, 7):
        return jsonable_bytes(raw)
    fmt = {3: 'H', 4: 'I', 8: 'h', 9: 'i', 11: 'f', 12: 'd', 13: 'I'}.get(typ)
    if fmt:
        vals = list(struct.unpack(f'{bo}{cnt}{fmt}', raw))
        return vals[0] if cnt == 1 else vals[:256]
    if typ in (5, 10):
        f = 'I' if typ == 5 else 'i'
        pairs = [list(struct.unpack_from(f'{bo}2{f}', raw, 8 * i)) for i in range(cnt)]
        return pairs[0] if cnt == 1 else pairs[:256]
    return None


def parse_tiff(t: bytes, base_name: str = 'ifd0') -> dict:
    """Bounded TIFF/EXIF IFD reader (P259 c2 defensive parsing): {'ifd0','exif','gps','interop','ifd1'} keyed
    by str(tag) like the sandbox children, plus 'anomalies' (ifd loop, out-of-range offsets, absurd counts,
    too many entries) and 'thumbnail' bytes from IFD1 when present.  Never raises on hostile input."""
    out: dict = {'ifd0': {}, 'exif': {}, 'gps': {}, 'interop': {}, 'ifd1': {}, 'anomalies': [], 'thumbnail': None}
    if len(t) < 8 or t[:4] not in (b'II*\x00', b'MM\x00*'):
        out['anomalies'].append('not a TIFF header')
        return out
    bo = '<' if t[:2] == b'II' else '>'
    visited: set[int] = set()

    def read_ifd(off: int, name: str) -> tuple[dict, int]:
        if off in visited:
            out['anomalies'].append(f'{name}: IFD loop')
            return {}, 0
        if off < 8 or off + 2 > len(t):
            out['anomalies'].append(f'{name}: offset {off} out of range')
            return {}, 0
        visited.add(off)
        n = struct.unpack_from(bo + 'H', t, off)[0]
        if n > TIFF_MAX_ENTRIES:
            out['anomalies'].append(f'{name}: {n} entries (capped)')
        n = min(n, TIFF_MAX_ENTRIES, max(0, (len(t) - off - 2) // 12))
        entries: dict = {}
        for i in range(n):
            e = off + 2 + 12 * i
            tag, typ, cnt = struct.unpack_from(bo + 'HHI', t, e)
            size = _TIFF_SIZES.get(typ)
            if not size:
                continue
            total = size * cnt
            if tag == 37500:
                entries[str(tag)] = {'bytes_len': total}
                continue
            if total > TIFF_MAX_VALUE_BYTES:
                out['anomalies'].append(f'{name}: tag {tag} count {cnt} too large')
                continue
            if total <= 4:
                raw = t[e + 8:e + 8 + total]
            else:
                voff = struct.unpack_from(bo + 'I', t, e + 8)[0]
                if voff + total > len(t):
                    out['anomalies'].append(f'{name}: tag {tag} data out of range')
                    continue
                raw = t[voff:voff + total]
            try:
                entries[str(tag)] = _tiff_value(t, bo, typ, cnt, raw)
            except struct.error:
                out['anomalies'].append(f'{name}: tag {tag} unreadable')
        end = off + 2 + 12 * n
        nxt = struct.unpack_from(bo + 'I', t, end)[0] if end + 4 <= len(t) else 0
        return entries, nxt

    ifd0, nxt = read_ifd(struct.unpack_from(bo + 'I', t, 4)[0], base_name)
    for k in list(ifd0):
        if int(k) in _POINTER_TAGS:
            continue
        out['ifd0'][k] = ifd0[k]
    for ptr_tag, name in ((34665, 'exif'), (34853, 'gps')):
        ptr = ifd0.get(str(ptr_tag))
        if isinstance(ptr, int) and ptr:
            entries, _ = read_ifd(ptr, name)
            out[name] = {k: v for k, v in entries.items() if int(k) not in _POINTER_TAGS}
            if name == 'exif' and isinstance(entries.get('40965'), int):
                out['interop'], _ = read_ifd(entries['40965'], 'interop')
    if nxt:
        out['ifd1'], _ = read_ifd(nxt, 'ifd1')
        off, ln = out['ifd1'].get('513'), out['ifd1'].get('514')
        if isinstance(off, int) and isinstance(ln, int) and 0 < off < len(t) and 0 < ln <= 65535:
            if off + ln <= len(t):
                out['thumbnail'] = t[off:off + ln]
            else:
                out['anomalies'].append('ifd1: thumbnail out of range')
    return out


def jpeg_segments(data: bytes) -> dict:
    """Walk JPEG markers up to SOS: {'segments': [(marker, payload)], 'width', 'height', 'truncated'}."""
    res: dict = {'segments': [], 'width': None, 'height': None, 'truncated': False}
    if data[:2] != b'\xff\xd8':
        res['truncated'] = True
        return res
    pos, n = 2, len(data)
    while pos + 4 <= n:
        if data[pos] != 0xFF:
            break
        marker = data[pos + 1]
        if marker == 0xFF:
            pos += 1
            continue
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker == 0xD9:
            break
        length = struct.unpack_from('>H', data, pos + 2)[0]
        if length < 2 or pos + 2 + length > n:
            res['truncated'] = True
            break
        payload = data[pos + 4:pos + 2 + length]
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF) \
                and len(payload) >= 5 and res['width'] is None:
            res['height'], res['width'] = struct.unpack_from('>HH', payload, 1)
        if marker == 0xDA:
            break
        if len(res['segments']) < 64:
            res['segments'].append((marker, payload))
        pos += 2 + length
    else:
        res['truncated'] = True
    return res


def parse_photoshop_irb(payload: bytes) -> dict:
    """APP13 'Photoshop 3.0' image resource blocks -> IPTC-NAA (resource 0x0404) in the children's shape."""
    if not payload.startswith(b'Photoshop 3.0\x00'):
        return {}
    pos, n = 14, len(payload)
    while pos + 12 <= n and payload[pos:pos + 4] == b'8BIM':
        rid = struct.unpack_from('>H', payload, pos + 4)[0]
        nlen = payload[pos + 6]
        name_total = 1 + nlen + ((1 + nlen) & 1)
        p2 = pos + 6 + name_total
        if p2 + 4 > n:
            break
        size = struct.unpack_from('>I', payload, p2)[0]
        data = payload[p2 + 4:p2 + 4 + size]
        if rid == 0x0404:
            return parse_iptc(data)
        pos = p2 + 4 + size + (size & 1)
    return {}


def parse_iptc(data: bytes) -> dict:
    """IPTC-NAA records -> {'r:d': [value, ...]} (values via jsonable_bytes)."""
    out: dict = {}
    pos, n = 0, len(data)
    while pos + 5 <= n and data[pos] == 0x1C:
        rec, ds = data[pos + 1], data[pos + 2]
        size = struct.unpack_from('>H', data, pos + 3)[0]
        hdr = 5
        if size & 0x8000:
            ln = size & 0x7FFF
            if ln > 4 or pos + 5 + ln > n:
                break
            size = int.from_bytes(data[pos + 5:pos + 5 + ln], 'big')
            hdr += ln
        val = data[pos + hdr:pos + hdr + size]
        lst = out.setdefault(f'{rec}:{ds}', [])
        if len(lst) < 64:
            lst.append(jsonable_bytes(val))
        pos += hdr + size
    return out


def _png_chunks(data: bytes) -> Iterator[tuple[bytes, bytes, bool]]:
    pos, n = 8, len(data)
    count = 0
    while pos + 12 <= n and count < 4096:
        ln = struct.unpack_from('>I', data, pos)[0]
        ctype = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + ln]
        if pos + 12 + ln > n:
            yield ctype, body, False
            return
        crc_ok = struct.unpack_from('>I', data, pos + 8 + ln)[0] == (zlib.crc32(ctype + body) & 0xFFFFFFFF)
        yield ctype, body, crc_ok
        if ctype == b'IEND':
            return
        pos += 12 + ln
        count += 1


def _bounded_inflate(blob: bytes, cap: int = 1 << 20) -> bytes | None:
    d = zlib.decompressobj()
    try:
        out = d.decompress(blob, cap)
    except zlib.error:
        return None
    return out if not d.unconsumed_tail else None


def scan_image_bytes(data: bytes) -> dict:
    """Stdlib reader producing the same raw shape as pillow_image_child (source 'stdlib'): format, width,
    height, exif{ifd0,exif,gps,ifd1}, xmp, iptc, png_text, thumbnail{width,height,bytes}, anomalies.
    Used as the offline oracle in tests and as a no-Pillow fallback for metadata only (P259 c2, c3)."""
    out: dict = {'source': 'stdlib', 'errors': [], 'format': sniff_image(data), 'width': None, 'height': None,
                 'exif': {'ifd0': {}, 'exif': {}, 'gps': {}, 'ifd1': {}}, 'xmp': None, 'iptc': {},
                 'png_text': {}, 'thumbnail': None, 'anomalies': []}
    fmt = out['format']
    tiff = None
    if fmt == 'JPEG':
        js = jpeg_segments(data)
        out['width'], out['height'] = js['width'], js['height']
        if js['truncated']:
            out['errors'].append('truncated')
        for marker, payload in js['segments']:
            if marker == 0xE1 and payload.startswith(b'Exif\x00\x00') and tiff is None:
                tiff = payload[6:]
            elif marker == 0xE1 and payload.startswith(b'http://ns.adobe.com/xap/1.0/\x00') and out['xmp'] is None:
                out['xmp'] = payload[29:].decode('utf-8', 'replace')
            elif marker == 0xED and not out['iptc']:
                out['iptc'] = parse_photoshop_irb(payload)
    elif fmt == 'PNG':
        for ctype, body, crc_ok in _png_chunks(data):
            if not crc_ok:
                out['anomalies'].append(f'png chunk {ctype.decode("latin-1")} crc/length bad')
            if ctype == b'IHDR' and len(body) >= 8:
                out['width'], out['height'] = struct.unpack_from('>II', body, 0)
            elif ctype == b'eXIf':
                tiff = body[6:] if body.startswith(b'Exif\x00\x00') else body
            elif ctype in (b'tEXt', b'zTXt', b'iTXt'):
                key, _, rest = body.partition(b'\x00')
                k = key.decode('latin-1')[:79]
                if ctype == b'tEXt':
                    val = rest.decode('latin-1')
                elif ctype == b'zTXt':
                    val = (_bounded_inflate(rest[1:]) or b'').decode('latin-1')
                else:
                    flag = rest[0:1]
                    parts = rest[2:].split(b'\x00', 2)
                    txt = parts[2] if len(parts) == 3 else b''
                    if flag == b'\x01':
                        txt = _bounded_inflate(txt) or b''
                    val = txt.decode('utf-8', 'replace')
                if k == 'XML:com.adobe.xmp':
                    out['xmp'] = val
                elif k.lower() == 'raw profile type exif' and tiff is None:
                    hexdata = ''.join(val.split('\n')[3:]) if '\n' in val else ''
                    try:
                        blob = bytes.fromhex(re.sub(r'\s+', '', hexdata))
                        tiff = blob[6:] if blob.startswith(b'Exif\x00\x00') else blob
                    except ValueError:
                        out['anomalies'].append('raw profile exif not hex')
                elif len(out['png_text']) < 64:
                    out['png_text'][k] = val[:512]
    elif fmt == 'WEBP':
        pos = 12
        while pos + 8 <= len(data):
            ctype = data[pos:pos + 4]
            ln = struct.unpack_from('<I', data, pos + 4)[0]
            body = data[pos + 8:pos + 8 + ln]
            if ctype == b'VP8X' and len(body) >= 10:
                out['width'] = 1 + int.from_bytes(body[4:7], 'little')
                out['height'] = 1 + int.from_bytes(body[7:10], 'little')
            elif ctype == b'VP8 ' and len(body) >= 10 and out['width'] is None:
                out['width'] = struct.unpack_from('<H', body, 6)[0] & 0x3FFF
                out['height'] = struct.unpack_from('<H', body, 8)[0] & 0x3FFF
            elif ctype == b'VP8L' and len(body) >= 5 and out['width'] is None:
                bits = int.from_bytes(body[1:5], 'little')
                out['width'], out['height'] = (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
            elif ctype == b'EXIF':
                tiff = body[6:] if body.startswith(b'Exif\x00\x00') else body
            elif ctype == b'XMP ':
                out['xmp'] = body.decode('utf-8', 'replace')
            pos += 8 + ln + (ln & 1)
    elif fmt == 'TIFF':
        tiff = data
    elif fmt in ('HEIC', 'AVIF'):
        out['errors'].append(f'{fmt}: needs the ExifRead fallback (no decoder offline)')
    elif fmt is None:
        out['errors'].append('not a recognised image format')
    if fmt == 'JPEG' and 'truncated' in out['errors']:
        return {'source': 'stdlib', 'error': 'OSError', 'message': 'Truncated File Read (segment runs past the end)'}
    if fmt in ('HEIC', 'AVIF'):
        return {'source': 'stdlib', 'error': 'UnidentifiedImageError', 'message': f'{fmt} container', 'fallback': 'exifread'}
    if fmt is None:
        return {'source': 'stdlib', 'error': 'UnidentifiedImageError', 'message': 'not a recognised image format'}
    w, h = as_int(out['width']), as_int(out['height'])
    if w and h and w * h > IMAGE_MAX_PIXELS:
        return {'source': 'stdlib', 'error': 'DecompressionBombError',
                'message': f'Image size ({w * h} pixels) exceeds limit of {IMAGE_MAX_PIXELS} pixels'}
    if tiff is not None:
        parsed = parse_tiff(tiff)
        out['exif'] = {k: parsed[k] for k in ('ifd0', 'exif', 'gps', 'ifd1')}
        out['anomalies'].extend(parsed['anomalies'])
        if fmt == 'TIFF' and out['width'] is None:
            out['width'], out['height'] = parsed['ifd0'].get('256'), parsed['ifd0'].get('257')
        th = parsed.get('thumbnail')
        if th:
            tj = jpeg_segments(th)
            out['thumbnail'] = {'width': tj['width'], 'height': tj['height'], 'bytes': len(th),
                                'readable': tj['width'] is not None, 'bbox': None}
    return out


_XMP_NS = {
    'http://ns.adobe.com/xap/1.0/': 'xmp', 'http://ns.adobe.com/xap/1.0/mm/': 'xmpMM',
    'http://ns.adobe.com/xap/1.0/sType/ResourceEvent#': 'stEvt', 'http://ns.adobe.com/photoshop/1.0/': 'photoshop',
    'http://purl.org/dc/elements/1.1/': 'dc', 'http://ns.adobe.com/exif/1.0/': 'exif',
    'http://cipa.jp/exif/1.0/': 'exifEX', 'http://ns.adobe.com/tiff/1.0/': 'tiff',
    'http://ns.adobe.com/exif/1.0/aux/': 'aux', 'http://ns.adobe.com/lightroom/1.0/': 'lr',
    'http://ns.adobe.com/camera-raw-settings/1.0/': 'crs', 'http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/': 'Iptc4xmpCore',
    'http://www.w3.org/1999/02/22-rdf-syntax-ns#': 'rdf', 'http://ns.google.com/photos/1.0/camera/': 'GCamera',
    'http://www.w3.org/XML/1998/namespace': 'xml',
}


def _xmp_qname(tag: str) -> str:
    if tag.startswith('{'):
        ns, local = tag[1:].split('}', 1)
        return f'{_XMP_NS.get(ns, ns)}:{local}'
    return tag


def parse_xmp(xmp: str | bytes | None) -> dict:
    """Safe XMP reader (P259 c2/c4): refuses DOCTYPE/ENTITY (no entity expansion, no external fetch), caps
    size, returns {'props': {prefix:name: value|list}, 'history': [{action, softwareAgent, when}], 'error'}."""
    if xmp is None:
        return {'props': {}, 'history': [], 'error': None}
    text = xmp.decode('utf-8', 'replace') if isinstance(xmp, bytes) else str(xmp)
    if len(text) > XMP_MAX_BYTES:
        return {'props': {}, 'history': [], 'error': 'XMP larger than 1 MB (not parsed)'}
    if re.search(r'<!\s*(DOCTYPE|ENTITY)', text, re.I):
        return {'props': {}, 'history': [], 'error': 'unsafe XMP refused (DOCTYPE/ENTITY declarations)'}
    import xml.etree.ElementTree as ET
    text = text.lstrip('﻿')
    try:
        root = ET.fromstring(text.encode('utf-8'))
    except ET.ParseError as e:
        return {'props': {}, 'history': [], 'error': f'malformed XMP ({str(e)[:80]})'}
    props: dict = {}
    history: list = []
    rdf_desc = '{http://www.w3.org/1999/02/22-rdf-syntax-ns#}Description'
    rdf_li = '{http://www.w3.org/1999/02/22-rdf-syntax-ns#}li'
    count = 0
    for desc in root.iter(rdf_desc):
        for k, v in desc.attrib.items():
            q = _xmp_qname(k)
            if not q.startswith('rdf:') and len(props) < 512:
                props.setdefault(q, as_str(v, 1024))
        for child in desc:
            count += 1
            if count > 2048:
                break
            q = _xmp_qname(child.tag)
            lis = list(child.iter(rdf_li))
            if q == 'xmpMM:History':
                for li in lis[:200]:
                    ev = {_xmp_qname(k).split(':', 1)[1]: as_str(v, 300) for k, v in li.attrib.items()}
                    for sub in li:
                        ev[_xmp_qname(sub.tag).split(':', 1)[-1]] = as_str(sub.text, 300)
                    history.append({k: ev.get(k) for k in ('action', 'softwareAgent', 'when', 'changed') if ev.get(k)})
            elif lis:
                props.setdefault(q, [x for x in (as_str(li.text, 1024) for li in lis[:64]) if x])
            elif child.text and child.text.strip():
                props.setdefault(q, as_str(child.text, 1024))
    return {'props': props, 'history': history, 'error': None}


def gps_decimal(dms: Any, ref: Any, kind: str) -> tuple[float | None, list[str]]:
    """EXIF GPS rationals ([[d,1],[m,1],[s,1]], floats or a single number) + ref -> signed decimal degrees,
    rounded to 6 places; warnings for bad refs/ranges.  kind 'lat' or 'lon'.  P259 c5."""
    warn: list[str] = []
    if isinstance(dms, list) and len(dms) == 2 and all(isinstance(x, int) and not isinstance(x, bool) for x in dms):
        parts = [dms]          # one rational [num, den] (non-standard count 1)
    else:
        parts = dms if isinstance(dms, list) else [dms]
    vals = [as_float(p) for p in parts[:3]]
    if not vals or any(v is None for v in vals):
        return None, ['unreadable GPS value']
    d = vals[0]
    m = vals[1] if len(vals) > 1 else 0.0
    s = vals[2] if len(vals) > 2 else 0.0
    if m < 0 or m >= 60 or s < 0 or s >= 60 or d < 0:
        return None, ['GPS minutes/seconds out of range']
    dec = d + m / 60 + s / 3600
    r = (as_str(ref) or '').upper()[:1]
    allowed = ('N', 'S') if kind == 'lat' else ('E', 'W')
    if r not in allowed:
        warn.append(f'GPS {kind} reference missing or invalid ({ref!r}); sign assumed positive')
    if r in ('S', 'W'):
        dec = -dec
    limit = 90 if kind == 'lat' else 180
    if abs(dec) > limit:
        return None, [f'GPS {kind} out of range']
    return round(dec, 6), warn


def parse_xmp_gps(value: Any, kind: str) -> float | None:
    """XMP GPS 'DDD,MM.mmmmK' or 'DDD,MM,SSK' (K in NSEW) -> signed decimal (6 places)."""
    v = as_str(value, 64)
    m = re.fullmatch(r'\s*(\d{1,3}),(\d{1,2}(?:\.\d+)?)(?:,(\d{1,2}(?:\.\d+)?))?\s*([NSEWnsew])\s*', v or '')
    if not m:
        return None
    d, mi, se, ref = m.groups()
    dec, _ = gps_decimal([float(d), float(mi), float(se or 0)], ref, kind)
    return dec


def exif_datetime(value: Any, offset: Any = None) -> str | None:
    """'2026:03:01 14:22:00' (+ OffsetTime '-03:00') -> '2026-03-01T14:22:00-03:00'; placeholders such as
    '0000:00:00 00:00:00' and impossible dates -> None.  Also accepts ISO strings (XMP)."""
    v = as_str(value, 64)
    if not v:
        return None
    m = re.fullmatch(r'(\d{4})[:\-](\d{2})[:\-](\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?\s*'
                     r'(Z|[+\-]\d{2}:?\d{2})?', v)
    if not m:
        m2 = re.fullmatch(r'(\d{4})[:\-](\d{2})[:\-](\d{2})', v)
        if not m2:
            return None
        try:
            return _dt.date(*map(int, m2.groups())).isoformat()
        except ValueError:
            return None
    y, mo, d, h, mi, s, tz = m.groups()
    try:
        stamp = _dt.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s or 0))
    except ValueError:
        return None
    if stamp.year < 1990:
        return None
    off = as_str(offset, 8) or tz
    if off and re.fullmatch(r'Z|[+\-]\d{2}:?\d{2}', off):
        if off != 'Z' and ':' not in off:
            off = off[:3] + ':' + off[3:]
        return stamp.isoformat() + ('Z' if off == 'Z' else off)
    return stamp.isoformat()


def editing_software(*names: Any) -> str | None:
    """First editor recognised in Software/CreatorTool/history agents/PNG Software (P259 c4 INFO tag)."""
    for name in names:
        n = (as_str(name, 300) or '').lower()
        if not n:
            continue
        for pat, label in EDITING_SOFTWARE:
            if re.search(pat, n):
                return label
    return None


def thumbnail_check(main_w: Any, main_h: Any, th_w: Any, th_h: Any, bbox: Any = None,
                    tolerance: float = 0.03) -> dict:
    """EXIF thumbnail vs main image aspect ratio (P259 c4: differs -> 'possible crop/edit').
    A letterboxed thumbnail (non-black bbox matching the main aspect) and a rotated thumbnail are reported
    as notes, not as possible crop/edit.  Returns {'status': 'match'|'mismatch'|'rotated'|'letterboxed'|
    'unknown', 'main_aspect', 'thumb_aspect', 'tag'}."""
    mw, mh, tw, th = (as_int(x) for x in (main_w, main_h, th_w, th_h))
    if not all(x and x > 0 for x in (mw, mh, tw, th)):
        return {'status': 'unknown', 'main_aspect': None, 'thumb_aspect': None, 'tag': None}
    ma, ta = mw / mh, tw / th
    res = {'main_aspect': round(ma, 4), 'thumb_aspect': round(ta, 4), 'tag': None}
    if abs(ma - ta) / ma <= tolerance:
        return {**res, 'status': 'match'}
    if abs(mh / mw - ta) / (mh / mw) <= tolerance:
        return {**res, 'status': 'rotated', 'tag': 'thumbnail rotated relative to the main image'}
    if isinstance(bbox, (list, tuple)) and len(bbox) == 4:
        bw, bh = bbox[2] - bbox[0], bbox[3] - bbox[1]
        if bw > 0 and bh > 0 and abs(ma - bw / bh) / ma <= max(tolerance, 2 / min(bw, bh)):
            return {**res, 'status': 'letterboxed', 'tag': None}
    return {**res, 'status': 'mismatch',
            'tag': 'possible crop/edit: EXIF thumbnail aspect ratio differs from the main image'}


def _iptc_text(values: Any, utf8: bool) -> list[str]:
    out = []
    for v in values if isinstance(values, list) else [values]:
        if isinstance(v, str):
            out.append(v)
        else:
            b = _b(v)
            if b is not None:
                try:
                    out.append(b.decode('utf-8') if utf8 else b.decode('latin-1'))
                except UnicodeDecodeError:
                    out.append(b.decode('latin-1'))
    return [x.strip() for x in out if x and x.strip()]


def image_error_reason(dump: Any) -> dict | None:
    """Map a child error to the module result (P259 c3): bomb/truncated/corrupt -> ERROR with a clear reason;
    unrecognised format -> ERROR 'not a supported image' (HEIC/RAW: try the ExifRead fallback).  None if ok."""
    if not isinstance(dump, dict):
        return {'status': 'error', 'reason_code': 'error', 'reason': 'sandbox output is not an object'}
    err = as_str(dump.get('error'), 64)
    if not err:
        return None
    msg = as_str(dump.get('message'), 300) or ''
    if err == 'DecompressionBombError':
        m = re.search(r'\((\d+) pixels\)', msg)
        px = f'{int(m.group(1)):,} pixels' if m else 'too many pixels'
        return {'status': 'error', 'reason_code': 'error',
                'reason': f'decompression bomb refused: the image declares {px}, over the '
                          f'{IMAGE_MAX_PIXELS:,}-pixel cap; nothing was decoded'}
    if err == 'UnidentifiedImageError':
        return {'status': 'error', 'reason_code': 'error',
                'reason': 'not a supported image format (HEIC/RAW: use the ExifRead fallback)', 'fallback': 'exifread'}
    if 'truncat' in msg.lower() or err == 'EOFError':
        return {'status': 'error', 'reason_code': 'error', 'reason': 'truncated or corrupt image file'}
    if err in ('timeout', 'memory_limit', 'cpu_limit'):
        return {'status': 'error', 'reason_code': 'timeout' if err == 'timeout' else 'error',
                'reason': f'image parser stopped by the sandbox ({err})'}
    return {'status': 'error', 'reason_code': 'error', 'reason': f'image could not be parsed ({err}: {msg[:120]})'}


def normalize_image_meta(raw: Any) -> dict:
    """Normalise pillow_image_child / exifread_child / scan_image_bytes output (P259 c4-c7).

    Returns summary (plain language, first), notes (missing EXIF is normal; EXIF can be edited), dates,
    taken_at, camera {make, model, serial, lens_model, lens_serial}, software, editing_software, owner
    {artist, copyright, camera_owner, xmp_creator, xmp_rights, iptc_byline, iptc_copyright}, gps
    {lat, lon, alt, timestamp, datum, warnings}, thumbnail check, tags (INFO), pivots (coordinates with the
    privacy tag, expand False, relation photo_taken_at), attributes, has_metadata, status."""
    err = image_error_reason(raw)
    if err:
        return {**err, 'summary': err['reason'], 'notes': [], 'pivots': [], 'tags': [], 'attributes': {}}
    exif = raw.get('exif') if isinstance(raw.get('exif'), dict) else {}
    ifd0 = exif.get('ifd0') if isinstance(exif.get('ifd0'), dict) else {}
    ex = exif.get('exif') if isinstance(exif.get('exif'), dict) else {}
    gps = exif.get('gps') if isinstance(exif.get('gps'), dict) else {}
    xmp = parse_xmp(raw.get('xmp'))
    xp = xmp['props']
    iptc = raw.get('iptc') if isinstance(raw.get('iptc'), dict) else {}
    utf8 = (_b((iptc.get('1:90') or [None])[0]) or b'') in (b'\x1b%G', b'\x1b%/I')
    png_text = raw.get('png_text') if isinstance(raw.get('png_text'), dict) else {}

    def g(d: dict, tag: int) -> Any:
        v = d.get(str(tag))
        return None if v in ('', None) else v

    def text(v: Any, limit: int = 300) -> str | None:
        if isinstance(v, dict):
            b = _b(v)
            if b is None:
                return None
            if b[:8] in (b'ASCII\x00\x00\x00', b'UNICODE\x00'):
                b = b[8:].decode('utf-16-le' if b[:7] == b'UNICODE' else 'ascii', 'replace').encode('utf-8')
            v = b.decode('utf-8', 'replace')
        return as_str(v, limit)

    xp_author = g(ifd0, 40093)
    if isinstance(xp_author, (dict, list)):
        b = _b(xp_author)
        xp_author = b.decode('utf-16-le', 'replace').rstrip('\x00') if b else None

    # dates (EXIF > XMP > IPTC)
    dates = []
    for label, val, off in (
            ('EXIF DateTimeOriginal', g(ex, 36867), g(ex, 36881) or g(ex, 36880)),
            ('EXIF DateTimeDigitized', g(ex, 36868), g(ex, 36882) or g(ex, 36880)),
            ('EXIF DateTime (last change)', g(ifd0, 306), g(ex, 36880)),
            ('XMP DateTimeOriginal', xp.get('exif:DateTimeOriginal'), None),
            ('XMP CreateDate', xp.get('xmp:CreateDate'), None),
            ('XMP photoshop:DateCreated', xp.get('photoshop:DateCreated'), None),
            ('XMP ModifyDate', xp.get('xmp:ModifyDate'), None)):
        iso = exif_datetime(val, off)
        if iso:
            dates.append({'field': label, 'value': iso, 'raw': as_str(val, 64)})
    d55 = _iptc_text(iptc.get('2:55'), utf8)
    if d55 and re.fullmatch(r'\d{8}', d55[0]):
        t60 = _iptc_text(iptc.get('2:60'), utf8)
        tm = re.fullmatch(r'(\d{2})(\d{2})(\d{2})([+\-]\d{4})?', t60[0]) if t60 else None
        stamp = f'{d55[0][:4]}:{d55[0][4:6]}:{d55[0][6:]}' + (f' {tm.group(1)}:{tm.group(2)}:{tm.group(3)}' if tm else '')
        iso = exif_datetime(stamp, (tm.group(4)[:3] + ':' + tm.group(4)[3:]) if tm and tm.group(4) else None)
        if iso:
            dates.append({'field': 'IPTC DateCreated', 'value': iso, 'raw': d55[0]})
    taken = next((d for d in dates if 'DateTimeOriginal' in d['field'] or 'CreateDate' in d['field']
                  or 'DateCreated' in d['field']), None)
    last_change = next((d['value'] for d in dates if d['field'].startswith('EXIF DateTime (')), None)

    camera = {
        'make': text(g(ifd0, 271), 100) or as_str(xp.get('tiff:Make'), 100),
        'model': text(g(ifd0, 272), 100) or as_str(xp.get('tiff:Model'), 100),
        'serial': text(g(ex, 42033), 100) or as_str(xp.get('aux:SerialNumber') or xp.get('exifEX:BodySerialNumber'), 100),
        'lens_model': text(g(ex, 42036), 100) or as_str(xp.get('exifEX:LensModel') or xp.get('aux:Lens'), 100),
        'lens_serial': text(g(ex, 42037), 100) or as_str(xp.get('aux:LensSerialNumber'), 100),
    }
    software = [s for s in (text(g(ifd0, 305)), text(g(ifd0, 11)), as_str(xp.get('xmp:CreatorTool')),
                            as_str(png_text.get('Software'))) if s]
    agents = [h.get('softwareAgent') for h in xmp['history'] if h.get('softwareAgent')]
    editor = editing_software(*software, *agents)
    owner = {
        'artist': text(g(ifd0, 315)) or as_str(xp_author), 'copyright': text(g(ifd0, 33432)),
        'camera_owner': text(g(ex, 42032)),
        'xmp_creator': ', '.join(xp['dc:creator']) if isinstance(xp.get('dc:creator'), list) else as_str(xp.get('dc:creator')),
        'xmp_rights': ', '.join(xp['dc:rights']) if isinstance(xp.get('dc:rights'), list) else as_str(xp.get('dc:rights')),
        'iptc_byline': ', '.join(_iptc_text(iptc.get('2:80'), utf8)) or None,
        'iptc_copyright': ', '.join(_iptc_text(iptc.get('2:116'), utf8)) or None,
        'png_author': as_str(png_text.get('Author')),
    }
    owner = {k: v for k, v in owner.items() if v}
    iptc_place = {k: ', '.join(_iptc_text(iptc.get(code), utf8)) or None
                  for k, code in (('city', '2:90'), ('sublocation', '2:92'), ('state', '2:95'), ('country', '2:101'))}
    iptc_place = {k: v for k, v in iptc_place.items() if v}

    # GPS (EXIF first, XMP second)
    gps_out = None
    gps_warn: list[str] = []
    if g(gps, 2) is not None and g(gps, 4) is not None:
        lat, w1 = gps_decimal(g(gps, 2), g(gps, 1), 'lat')
        lon, w2 = gps_decimal(g(gps, 4), g(gps, 3), 'lon')
        gps_warn = w1 + w2
        if lat is not None and lon is not None:
            alt = as_float(g(gps, 6))
            ref = g(gps, 5)
            refb = _b(ref) if not isinstance(ref, int) else bytes([ref])
            if alt is not None and refb and refb[:1] == b'\x01':
                alt = -alt
            ts = None
            t7, d29 = g(gps, 7), as_str(g(gps, 29))
            if isinstance(t7, list) and len(t7) == 3 and d29:
                hms = [as_float(x) for x in t7]
                if all(x is not None for x in hms):
                    ts = exif_datetime(f'{d29} {int(hms[0]):02d}:{int(hms[1]):02d}:{int(hms[2]):02d}', 'Z')
            gps_out = {'lat': lat, 'lon': lon, 'alt': round(alt, 1) if alt is not None else None,
                       'timestamp': ts, 'datum': as_str(g(gps, 18), 32), 'source': 'EXIF'}
    elif xp.get('exif:GPSLatitude') and xp.get('exif:GPSLongitude'):
        lat, lon = parse_xmp_gps(xp['exif:GPSLatitude'], 'lat'), parse_xmp_gps(xp['exif:GPSLongitude'], 'lon')
        if lat is not None and lon is not None:
            gps_out = {'lat': lat, 'lon': lon, 'alt': None, 'timestamp': None, 'datum': None, 'source': 'XMP'}
        else:
            gps_warn.append('unreadable XMP GPS')
    if gps_out and gps_out['lat'] == 0 and gps_out['lon'] == 0:
        gps_warn.append('GPS 0,0 (no satellite fix): not used as a location')
        gps_out = None

    # thumbnail
    th = raw.get('thumbnail') if isinstance(raw.get('thumbnail'), dict) else None
    tcheck = thumbnail_check(raw.get('width'), raw.get('height'), (th or {}).get('width'), (th or {}).get('height'),
                             (th or {}).get('bbox')) if th else {'status': 'none', 'tag': None}

    tags = []
    if editor:
        tags.append({'level': 'INFO', 'tag': f'editing software: {editor}'})
    if tcheck.get('tag'):
        tags.append({'level': 'INFO', 'tag': tcheck['tag']})
    if taken and last_change and _iso_gap_seconds(taken['value'], last_change) > 60:
        tags.append({'level': 'INFO', 'tag': 'file changed after capture (EXIF DateTime later than DateTimeOriginal)'})

    has_meta = bool(ifd0 or ex or gps or xp or iptc or any(v for v in camera.values()))
    pivots = []
    if gps_out:
        pivots.append({'type': 'coordinates', 'value': f"{gps_out['lat']:.6f},{gps_out['lon']:.6f}",
                       'relation': 'photo_taken_at', 'tags': ['privacy'], 'expand': False,
                       'auto_lookups': False, 'map_links': 'manual, privacy=true, after analyst confirmation'})
    attributes = {k: v for k, v in {
        'camera_make': camera['make'], 'camera_model': camera['model'], 'camera_serial': camera['serial'],
        'lens_model': camera['lens_model'], 'lens_serial': camera['lens_serial'],
        'software': software[0] if software else None, 'taken_at': taken['value'] if taken else None,
        'last_changed_at': last_change, 'gps_altitude_m': gps_out['alt'] if gps_out else None,
        'gps_timestamp': gps_out['timestamp'] if gps_out else None,
        'xmp_document_id': as_str(xp.get('xmpMM:DocumentID'), 200),
        'xmp_original_document_id': as_str(xp.get('xmpMM:OriginalDocumentID'), 200),
    }.items() if v not in (None, '')}
    privacy_attrs = sorted({'camera_serial', 'lens_serial'} & set(attributes)) + sorted(f'owner.{k}' for k in owner)

    # plain-language summary first (P259 c7)
    when = taken['value'] if taken else None
    if has_meta:
        parts = []
        if when:
            off = re.search(r'([+\-]\d{2}:\d{2}|Z)$', when)
            parts.append('taken ' + when[:16].replace('T', ' ') + (f' (UTC{off.group(1)})' if off and off.group(1) != 'Z' else ''))
        dev = ' '.join(x for x in (camera['make'], camera['model']) if x)
        if dev:
            parts.append(f'with {dev}' if parts else f'camera {dev}')
        summary = ' '.join(parts) if parts else 'metadata present'
        summary += ', GPS present' if gps_out else ', no GPS'
        notes = [EDITABLE_EXIF_NOTE]
    else:
        summary = 'no EXIF metadata'
        notes = [MISSING_EXIF_NOTE]
    if gps_warn:
        notes.extend(gps_warn)
    anomalies = list(raw.get('anomalies') or []) + list(raw.get('warnings') or [])
    if xmp['error']:
        anomalies.append(xmp['error'])
    return {
        'status': 'ok' if has_meta else 'empty', 'reason_code': None, 'summary': summary, 'notes': notes,
        'format': as_str(raw.get('format'), 16), 'width': as_int(raw.get('width')), 'height': as_int(raw.get('height')),
        'has_metadata': has_meta, 'dates': dates, 'taken_at': when, 'camera': camera, 'software': software,
        'editing_software': editor, 'xmp_history': xmp['history'], 'owner': owner, 'iptc_place': iptc_place,
        'gps': gps_out, 'thumbnail': tcheck, 'tags': tags, 'pivots': pivots, 'attributes': attributes,
        'privacy_attributes': privacy_attrs, 'anomalies': anomalies[:40], 'source': as_str(raw.get('source'), 16),
        'findings': [],
    }


def _iso_gap_seconds(first: str, later: str) -> float:
    """Seconds from first to later (offsets ignored when either lacks one); 0 when unparsable."""
    try:
        a = _dt.datetime.fromisoformat(first[:19])
        b = _dt.datetime.fromisoformat(later[:19])
    except ValueError:
        return 0.0
    return (b - a).total_seconds()


def image_meta_export_view(norm: dict, case_opt_in: bool = False) -> dict:
    """STIX/MISP export view (P259 c6): GPS, camera/lens serials and owner fields are stripped unless the
    analyst opted in for the case; GPS is otherwise shown only inside the case report."""
    if case_opt_in:
        return dict(norm)
    out = {k: v for k, v in norm.items() if k not in ('gps', 'owner', 'pivots', 'privacy_attributes', 'iptc_place')}
    out['camera'] = {k: v for k, v in (norm.get('camera') or {}).items() if k not in ('serial', 'lens_serial')}
    out['attributes'] = {k: v for k, v in (norm.get('attributes') or {}).items()
                         if k not in ('camera_serial', 'lens_serial', 'gps_altitude_m', 'gps_timestamp')}
    out['stripped_for_export'] = list(STRIP_EXPORT_FIELDS)
    return out


# ======================================================================================================
# Sandbox children (run ONLY inside core/sandbox.py; libraries imported inside the functions)
# ======================================================================================================

PRIVACY_ATTRIBUTES = ("camera_serial", "lens_serial", "image_owner", "gps_altitude_m", "gps_timestamp")  # c6
FACE_LIBRARIES = ("face_recognition", "dlib", "cv2", "mediapipe", "deepface", "insightface")  # c6: never imported


def _j(value: Any) -> Any:
    """JSON-safe conversion for Pillow / ExifRead values (child side)."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    num, den = getattr(value, "numerator", None), getattr(value, "denominator", None)
    if num is not None and den is not None:
        return [int(num), int(den)]
    if isinstance(value, bytes):
        return jsonable_bytes(value)
    if isinstance(value, (list, tuple)):
        return [_j(v) for v in value[:64]]
    if isinstance(value, dict):
        return {str(k): _j(v) for k, v in list(value.items())[:256]}
    return str(value)[:512]


def _ifd(d: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in list(d.items())[:512]:
        if k == 0x927C:  # MakerNote: size only (vendor binary, never parsed)
            out[str(k)] = {"bytes_len": len(v) if isinstance(v, (bytes, bytearray)) else None}
        elif k not in (0x8769, 0x8825, 0xA005):
            out[str(k)] = _j(v)
    return out


def pillow_image_child(data: bytes, max_pixels: int = IMAGE_MAX_PIXELS) -> dict[str, Any]:
    """c2/c3 sandbox child: EXIF (IFD0/Exif/GPS/IFD1), XMP, IPTC, PNG text and the EXIF thumbnail without
    decoding the main image; DecompressionBombWarning is promoted to an error (a hard pixel cap)."""
    from PIL import ExifTags, Image, IptcImagePlugin, UnidentifiedImageError

    Image.MAX_IMAGE_PIXELS = max_pixels
    out: dict[str, Any] = {"source": "pillow", "errors": []}
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            with Image.open(io.BytesIO(data)) as im:
                out.update({"format": im.format, "width": im.size[0], "height": im.size[1]})
                exif = im.getexif()
                out["exif"] = {"ifd0": _ifd(exif), "exif": _ifd(exif.get_ifd(ExifTags.IFD.Exif)),
                               "gps": _ifd(exif.get_ifd(ExifTags.IFD.GPSInfo)), "ifd1": _ifd(exif.get_ifd(ExifTags.IFD.IFD1))}
                xmp = im.info.get("xmp") or im.info.get("XML:com.adobe.xmp")
                out["xmp"] = xmp.decode("utf-8", "replace") if isinstance(xmp, bytes) else xmp
                try:
                    iptc = IptcImagePlugin.getiptcinfo(im) or {}
                except Exception as exc:  # noqa: BLE001 - the library raises many types on bad IPTC
                    iptc = {}
                    out["errors"].append(f"iptc: {type(exc).__name__}")
                out["iptc"] = {f"{k[0]}:{k[1]}": [_j(x) for x in (v if isinstance(v, list) else [v])] for k, v in iptc.items()}
                text = getattr(im, "text", None)
                out["png_text"] = {str(k): str(v)[:512] for k, v in (text or {}).items()}
                out["thumbnail"] = _pillow_thumbnail(im, exif)
        except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
            return {"source": "pillow", "error": "DecompressionBombError", "message": str(exc)[:300]}
        except UnidentifiedImageError:
            return {"source": "pillow", "error": "UnidentifiedImageError", "message": "not a recognised image format"}
        except (OSError, SyntaxError, ValueError, struct.error) as exc:
            return {"source": "pillow", "error": type(exc).__name__, "message": str(exc)[:300]}
    out["warnings"] = [f"{w.category.__name__}: {str(w.message)[:160]}" for w in caught][:20]
    return out


def _pillow_thumbnail(im: Any, exif: Any) -> dict[str, Any] | None:
    from PIL import ExifTags, Image

    ifd1 = exif.get_ifd(ExifTags.IFD.IFD1)
    off, ln = ifd1.get(0x0201), ifd1.get(0x0202)
    if not off or not ln:
        return None
    raw = None
    for marker, payload in getattr(im, "applist", []):
        if marker == "APP1" and payload.startswith(b"Exif\x00\x00"):
            tiff = payload[6:]
            if 0 < off < len(tiff) and ln <= 65535:
                raw = tiff[off:off + ln]
            break
    if raw is None:
        return {"declared_length": ln, "readable": False}
    try:
        with Image.open(io.BytesIO(raw)) as th:
            if th.size[0] * th.size[1] > 1_000_000:
                return {"declared_length": ln, "readable": False}
            th.load()
            bbox = th.convert("L").point(lambda p: 255 if p > 16 else 0).getbbox()
            return {"width": th.size[0], "height": th.size[1], "bbox": list(bbox) if bbox else None, "bytes": len(raw), "readable": True}
    except Exception as exc:  # noqa: BLE001 - a broken thumbnail never breaks the metadata
        return {"declared_length": ln, "readable": False, "error": type(exc).__name__}


def exifread_child(data: bytes) -> dict[str, Any]:
    """c3 sandbox child (HEIC/RAW fallback): ExifRead reads tags without decoding pixels; same raw shape."""
    import exifread

    prefix = {"Image": "ifd0", "EXIF": "exif", "GPS": "gps", "Thumbnail": "ifd1", "Interoperability": "interop"}
    out: dict[str, Any] = {"source": "exifread", "errors": [], "format": sniff_image(data), "exif": {"ifd0": {}, "exif": {}, "gps": {}, "ifd1": {}}}
    try:
        tags = exifread.process_file(io.BytesIO(data), details=False, extract_thumbnail=False)
    except Exception as exc:  # noqa: BLE001 - ExifRead raises many types on hostile input
        return {"source": "exifread", "error": type(exc).__name__, "message": str(exc)[:300]}
    for key, tag in list(tags.items())[:1024]:
        ifd = prefix.get(key.split(" ", 1)[0])
        if ifd is None or not hasattr(tag, "tag"):
            continue
        vals = getattr(tag, "values", None)
        if isinstance(vals, (list, tuple)) and len(vals) == 1:
            vals = vals[0]
        out["exif"].setdefault(ifd, {})[str(tag.tag)] = _j(vals)
    return out


def export_view(attributes: dict[str, Any], case_opt_in: bool = False) -> dict[str, Any]:
    """c6: the attributes a STIX/MISP export may carry: GPS, camera/lens serials and owner fields are stripped
    unless the analyst opted in for the case (GPS is otherwise shown only inside the case report)."""
    if case_opt_in:
        return dict(attributes)
    return {k: v for k, v in attributes.items() if k not in PRIVACY_ATTRIBUTES}


# ======================================================================================================
# The module
# ======================================================================================================

PARSER_LIMITS = {"wall_timeout": 15.0, "cpu_seconds": 10}
_INFO = ["info"]
_EDIT = ["info", "edited_image", "context_only"]


def _parse(data: bytes, path: str, fmt: str | None) -> tuple[dict[str, Any], str]:
    """(raw dump, parser note). The sandbox path when the core has it; else the stdlib reader in process."""
    want_exifread = fmt in ("HEIC", "AVIF")
    if core_sandbox() is not None:
        target, ok = (("exifread_child", package_available("exifread")) if want_exifread else ("pillow_image_child", package_available("PIL")))
        if ok:
            args = {} if want_exifread else {"max_pixels": IMAGE_MAX_PIXELS}
            out = sandbox_run(f"{__name__}:{target}", path, args=args, **PARSER_LIMITS)
            if not out.get("ok"):
                code, reason = sandbox_failure(out)
                return {"source": "sandbox", "error": code if code == "timeout" else "sandbox", "message": reason}, ""
            raw = out.get("result")
            return (raw if isinstance(raw, dict) else {"error": "sandbox", "message": "no result object"}), f"sandbox ({out.get('isolation') or 'isolated'})"
    if want_exifread:
        raise SandboxUnavailable(f"{fmt} metadata needs the ExifRead extra run inside core/sandbox.py")
    return scan_image_bytes(data), NO_SANDBOX_NOTE


@register
class ImageMetadata(Module):
    name = "image_metadata"
    title = "Image metadata (EXIF/XMP/IPTC, camera, GPS)"
    description = (
        "Reads EXIF/XMP/IPTC metadata of a local image offline: capture dates, camera make/model/serial, software "
        "and editing tools, thumbnail consistency and GPS (a coordinates pivot, never auto-expanded or geocoded)."
    )
    category = "geo_image_meta"
    accepts = {T.FILE}
    produces = {T.COORDINATES}
    reference = "https://pillow.readthedocs.io/en/stable/reference/ExifTags.html"
    tags = {"offline"}
    notice = (
        "Missing EXIF is normal (WhatsApp, Telegram, social platforms and screenshots strip it) and EXIF can be edited. "
        "No face detection or recognition of any kind; GPS, serials and owner fields are personal data kept out of "
        "exports unless the analyst opts in; no automatic geocoding or map lookup."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # the file never leaves the machine
    hosts = ()
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.1
    timeout = 60.0
    max_pivots = 1
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return sniff_image(read_head(entity.value, 64)) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        try:
            data = read_regular_file(entity.value)
        except InputRefused as exc:
            return res.mark(exc.status, str(exc), reason_code=exc.code)
        fmt = sniff_image(data)
        if fmt is None:
            return res.mark("skipped", "not an image file", reason_code="not_applicable")
        try:
            raw, parser = _parse(data, entity.value, fmt)
        except SandboxUnavailable as exc:
            return res.mark("unavailable", str(exc), reason_code="package")
        if isinstance(raw, dict) and raw.get("error") in ("timeout", "sandbox"):
            return res.mark("error", str(raw.get("message")), reason_code="timeout" if raw.get("error") == "timeout" else "error")
        norm = normalize_image_meta(raw)
        if norm.get("status") == "error":
            res.raw = {"format": fmt, "parser": parser, "error": norm.get("reason")}
            return res.mark("error", str(norm.get("reason")), reason_code=str(norm.get("reason_code") or "error"))
        self._emit(res, norm, parser)
        return res

    def _emit(self, res: ModuleResult, norm: dict[str, Any], parser: str) -> None:
        summary = norm["summary"]
        notes = list(norm.get("notes") or [])
        res.attr("image_summary", summary)  # c7: the plain-language line comes first
        attrs = norm.get("attributes") or {}
        mapping = {"camera_make": "camera_make", "camera_model": "camera_model", "camera_serial": "camera_serial",
                   "lens_model": "lens_model", "lens_serial": "lens_serial", "software": "image_software",
                   "taken_at": "taken_at", "last_changed_at": "last_changed_at", "gps_altitude_m": "gps_altitude_m",
                   "gps_timestamp": "gps_timestamp", "xmp_document_id": "xmp_document_id",
                   "xmp_original_document_id": "xmp_original_document_id"}
        for key, name in mapping.items():
            res.attr(name, attrs.get(key))
        res.attr("image_owner", norm.get("owner") or None)
        facts = {
            "format": norm.get("format"), "width": norm.get("width"), "height": norm.get("height"),
            "has_metadata": norm.get("has_metadata"), "dates": norm.get("dates"), "software": norm.get("software"),
            "editing_software": norm.get("editing_software"), "xmp_history": (norm.get("xmp_history") or [])[:20],
            "iptc_place": norm.get("iptc_place"), "thumbnail": norm.get("thumbnail"), "anomalies": norm.get("anomalies"),
            "notes": notes, "parser": parser,
        }
        res.attr("image_metadata", {k: v for k, v in facts.items() if v not in (None, "", [], {})})
        res.finding("Image metadata", "info", " ".join([summary + "."] + notes), tags=_INFO, data={"summary": summary, "notes": notes})
        for tag in norm.get("tags") or []:
            text = str(tag.get("tag") or "")
            if text.startswith("editing software"):
                res.finding("Editing software named in the image metadata", "info",
                            f"{text}. Context, not proof: metadata can be edited, and editors also rewrite it on export.",
                            tags=_EDIT, data={"editing_software": norm.get("editing_software")})
            elif text.startswith("possible crop/edit"):
                res.finding("Possible crop/edit: EXIF thumbnail aspect ratio differs from the main image", "info",
                            f"{text} (main {norm['thumbnail'].get('main_aspect')}, thumbnail {norm['thumbnail'].get('thumb_aspect')}).",
                            tags=_EDIT, data={"thumbnail": norm.get("thumbnail")})
            elif text.startswith("file changed after capture"):
                res.finding("Image changed after capture", "info", f"{text}.", tags=_EDIT,
                            data={"taken_at": attrs.get("taken_at"), "last_changed_at": attrs.get("last_changed_at")})
        for p in norm.get("pivots") or []:
            res.pivot(T.COORDINATES, p["value"], "photo_taken_at", confidence="probable", expand=False,
                      note="GPS from the image metadata (privacy): never auto-expanded, no automatic geocoding or map "
                           "lookup; map links only after the analyst confirms for this image")
        if norm.get("gps"):
            res.finding("GPS location recorded in the image", "info",
                        "The metadata carries a GPS position (a claim by the file; EXIF can be edited). It is personal data: "
                        "shown only inside the case report, stripped from STIX/MISP exports unless the analyst opts in, and "
                        "never geocoded or looked up automatically.", tags=["info", "privacy"],
                        data={"source": norm["gps"].get("source"), "datum": norm["gps"].get("datum")})
        res.raw = {"summary": summary, "format": norm.get("format"), "width": norm.get("width"), "height": norm.get("height"),
                   "dates": norm.get("dates"), "camera": norm.get("camera"), "gps": norm.get("gps"),
                   "thumbnail": norm.get("thumbnail"), "anomalies": norm.get("anomalies"), "parser": parser}
