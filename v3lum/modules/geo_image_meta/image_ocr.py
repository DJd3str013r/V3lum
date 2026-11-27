"""Offline OCR of screenshots and scans: Tesseract por+eng, PDF text layer first (P363, batch p2-G12-2).

c1: offline (disclosure 'none', TLP:RED-safe, terms 'open'). The tesseract binary is optional, found through the
setting ``image_ocr_tesseract_path`` or PATH and never installed by V3LUM; pytesseract (Apache-2.0, extra 'ocr')
is the wrapper; rapidocr-onnxruntime is not used. A missing binary gives UNAVAILABLE 'package' with the exact
install command for the platform. The binary is also registered as a ``v3lum.core.tools.ToolSpec`` so doctor
reports its version.

c2: models por and eng from tesseract-ocr/tessdata_fast (Apache-2.0) at a pinned commit, through the dataset
manager with SHA-256 pinning (``tessdata_fast_por.traineddata``, ``tessdata_fast_eng.traineddata``; tesseract
loads them as the languages ``tessdata_fast_por+tessdata_fast_eng``).

c3: parsing runs only inside the shared file-analysis sandbox (``v3lum.core.sandbox`` through
``image_metadata.sandbox_run``: python -I child, wall timeout, rlimits - memory <= 1 GiB, CPU, no file writes -
100 MB input, 1 MB JSON output). :func:`ocr_child` is the sandbox target; it is never called in the V3LUM process.
Before anything is decoded the image header is read without decoding and checked against the pixel cap (Pillow's
cap is lowered to the same value inside the child, its bomb warning promoted to an error), because Leptonica parses
hostile images. This build has no core sandbox yet: the module then reports UNAVAILABLE 'package' (could not
verify), never 'no text'.

c4: pypdf text layer first; OCR only for image-only pages (their embedded images), at most 10 pages per document;
pages without a text layer or an image are reported as a coverage gap.

c5: OCR text is never auto-expanded, so this module runs the shared P172 extractor (``v3lum.core.ioc.extract``),
the P232 BR rules (``br_parsers.extract_br_entities``), the P233 boleto/PIX parsers (``parse_boleto``,
``parse_brcode`` with origin 'ocr', wrapped PIX lines joined first) and the P261 QR helpers (``qr_decode``, same
sandbox) itself and emits their results as pivots with relation ``extracted_from`` - not as a text_blob.

c6: OCR-derived entities carry provenance 'ocr', confidence <= 0.6 and expand=False until the analyst confirms them
(0/O, l/1, rn/m misreads are flagged in the note); the module never raises lookalike/typosquat findings from OCR
text, and boleto/PIX check-digit failures on OCR text read 'could not verify (OCR): likely misread, not tampering'.

c7: the report shows the OCR snippet around each indicator (``ocr_snippets``; CPFs masked); the full OCR text is
kept only in case evidence (``res.raw``, CPFs masked as well); CPFs are counted, masked and never pivoted.
"""

from __future__ import annotations

import io
import json
import os
import platform
import re
import shutil
import struct
import warnings
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core import ioc as _ioc
from v3lum.core.datasets import DATASETS, register_dataset
from v3lum.core.entities import IOC_TYPES, SECRET_TYPES, Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, package_available, register
from v3lum.core.tools import ToolSpec, get_tool, register_tool
from v3lum.modules.geo_image_meta.image_metadata import (
    IMAGE_MAX_PIXELS,
    InputRefused,
    SandboxUnavailable,
    read_head,
    read_regular_file,
    sandbox_failure,
    sandbox_run,
)

try:  # P232/P233 shared parsers (batch p1-G10-1)
    from v3lum.modules.brazil_public_data import br_parsers as _br
except ImportError:  # pragma: no cover - ships with the Brazil batch
    _br = None

OCR_MAX_CONFIDENCE = 0.6  # c6
OCR_MAX_PDF_PAGES = 10  # c4
PDF_MAX_SCAN_PAGES = 200  # text-layer pass bound (pages beyond it are reported, not read)
OCR_INPUT_CAP = 100 * 1024 * 1024  # c3
OCR_JSON_CAP = 1_000_000  # c3
MAX_TEXT_CHARS = 200_000  # per page, inside the child
MAX_SNIPPETS = 100
MAX_PIVOTS = 100
SOURCE = "github.image_ocr_tessdata_fast"
TESSDATA_FAST_COMMIT = "87416418657359cb625c412a48b6e1d6d41c29bd"  # tessdata_fast main on 2026-11-26
OCR_MODELS = {  # c2 (measured 2026-11-26)
    "tessdata_fast_por.traineddata": {
        "url": f"https://raw.githubusercontent.com/tesseract-ocr/tessdata_fast/{TESSDATA_FAST_COMMIT}/por.traineddata",
        "sha256": "c4932b937207a9514b7514d518b931a99938c02a28a5a5a553f8599ed58b7deb", "bytes": 1982756, "lang": "Portuguese"},
    "tessdata_fast_eng.traineddata": {
        "url": f"https://raw.githubusercontent.com/tesseract-ocr/tessdata_fast/{TESSDATA_FAST_COMMIT}/eng.traineddata",
        "sha256": "7d4322bd2a7749724879683fc3912cb542f19906c83bcc1a52132556427170b2", "bytes": 4113088, "lang": "English"},
}
LANGS = "tessdata_fast_por+tessdata_fast_eng"
TESSERACT_INSTALL = {  # c1: exact install commands (the Debian one was executed in prep: tesseract 5.3.4)
    "Linux": "sudo apt-get install -y tesseract-ocr (Debian/Ubuntu) or sudo dnf install -y tesseract (Fedora/RHEL)",
    "Darwin": "brew install tesseract",
    "Windows": "winget install --id UB-Mannheim.TesseractOCR -e",
}
PYTESSERACT_INSTALL = "pip install pytesseract"
OCR_LIMITS = {"wall_timeout": 180.0, "cpu_seconds": 150, "mem_bytes": 1 << 30, "max_input": OCR_INPUT_CAP, "max_output": OCR_JSON_CAP}
OCR_NOTE = ("OCR-derived (unconfirmed, provenance ocr): confirm before use; never used for lookalike/typosquat or "
            "tampering findings without a non-OCR confirmation")
_TSV_COLUMNS = ("level", "page_num", "block_num", "par_num", "line_num", "word_num", "left", "top", "width", "height", "conf", "text")
_HTML_HEAD_RE = re.compile(r"\s{0,200}(?:<!doctype\s{1,20}html|<html|<head|<body|<title|<meta\s)", re.I)


# ---------------------------------------------------------------------------------- registrations
def register_datasets() -> list[str]:
    names = []
    for name, spec in OCR_MODELS.items():
        if name not in DATASETS:
            register_dataset(
                name, spec["url"], ttl=365 * 86400,
                description=f"tessdata_fast {spec['lang']} model (tesseract-ocr project, commit {TESSDATA_FAST_COMMIT[:12]}, SHA-256 pinned)",
                licence="Apache-2.0", terms_class="open", attribution="Tesseract OCR tessdata_fast models, Apache-2.0 (tesseract-ocr project)",
                provider="github", source=SOURCE, min_bytes=1_000_000, expect="bytes", pinned_sha256=spec["sha256"],
                max_bytes=5_000_000, essential=True,
            )
        names.append(name)
    return names


DATASET_NAMES = register_datasets()
TOOL = ToolSpec(
    name="tesseract", binary="tesseract", version_args=("--version",), version_regex=r"tesseract\s+v?(\d+\.\d+(?:\.\d+)?)",
    min_version="4.1", licence="Apache-2.0",
    notes="P363 image_ocr: run only inside the core file-analysis sandbox through pytesseract; never downloaded or updated by V3LUM",
)
if get_tool(TOOL.name) is None:
    register_tool(TOOL)


# ---------------------------------------------------------------------------------- pure helpers
def image_header_info(head: Any) -> dict[str, Any] | None:
    """c3: dimensions from the first bytes WITHOUT decoding (PNG, GIF, BMP, JPEG, WEBP); None when unknown."""
    b = bytes(head[:1 << 20]) if isinstance(head, (bytes, bytearray, memoryview)) else None
    if not b or len(b) < 10:
        return None
    try:
        if b[:8] == b"\x89PNG\r\n\x1a\n" and b[12:16] == b"IHDR":
            w, h = struct.unpack(">II", b[16:24])
            return {"format": "png", "width": w, "height": h}
        if b[:6] in (b"GIF87a", b"GIF89a"):
            w, h = struct.unpack("<HH", b[6:10])
            return {"format": "gif", "width": w, "height": h}
        if b[:2] == b"BM" and len(b) >= 26:
            w, h = struct.unpack("<ii", b[18:26])
            return {"format": "bmp", "width": abs(w), "height": abs(h)}
        if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
            chunk = b[12:16]
            if chunk == b"VP8X" and len(b) >= 30:
                return {"format": "webp", "width": 1 + int.from_bytes(b[24:27], "little"), "height": 1 + int.from_bytes(b[27:30], "little")}
            if chunk == b"VP8L" and len(b) >= 25:
                bits = int.from_bytes(b[21:25], "little")
                return {"format": "webp", "width": (bits & 0x3FFF) + 1, "height": ((bits >> 14) & 0x3FFF) + 1}
            if chunk == b"VP8 " and len(b) >= 30:
                w, h = struct.unpack("<HH", b[26:30])
                return {"format": "webp", "width": w & 0x3FFF, "height": h & 0x3FFF}
            return None
        if b[:2] == b"\xff\xd8":
            i, steps = 2, 0
            while i + 9 < len(b) and steps < 512:
                steps += 1
                if b[i] != 0xFF:
                    return None
                marker = b[i + 1]
                if marker == 0xFF:
                    i += 1
                    continue
                if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                    i += 2
                    continue
                seg_len = struct.unpack(">H", b[i + 2:i + 4])[0]
                if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                    h, w = struct.unpack(">HH", b[i + 5:i + 9])
                    return {"format": "jpeg", "width": w, "height": h}
                if seg_len < 2:
                    return None
                i += 2 + seg_len
            return None
    except struct.error:
        return None
    return None


def pixel_cap_check(info: dict[str, Any] | None, max_pixels: int = IMAGE_MAX_PIXELS) -> str | None:
    """c3: 'too_many_pixels WxH' when the declared size exceeds the cap, 'zero_size', else None."""
    if not isinstance(info, dict):
        return None
    w, h = info.get("width"), info.get("height")
    if not isinstance(w, int) or not isinstance(h, int):
        return None
    if w <= 0 or h <= 0:
        return "zero_size"
    if w * h > max_pixels:
        return f"too_many_pixels {w}x{h}"
    return None


def file_kind(head: bytes) -> str | None:
    """'image' (PNG, JPEG, GIF, BMP, TIFF, WEBP), 'pdf' or None."""
    if head[:5] == b"%PDF-":
        return "pdf"
    if (head[:8] == b"\x89PNG\r\n\x1a\n" or head[:3] == b"\xff\xd8\xff" or head[:6] in (b"GIF87a", b"GIF89a") or head[:2] == b"BM"
            or head[:4] in (b"II*\x00", b"MM\x00*") or (head[:4] == b"RIFF" and head[8:12] == b"WEBP")):
        return "image"
    return None


def _word(rec: dict[str, Any]) -> dict[str, Any] | None:
    try:
        level = int(rec.get("level", 0))
        conf = float(rec.get("conf", -1))
        text = str(rec.get("text") or "")
        box = tuple(int(rec.get(k, 0)) for k in ("left", "top", "width", "height"))
        key = tuple(int(rec.get(k, 0)) for k in ("page_num", "block_num", "par_num", "line_num", "word_num"))
    except (TypeError, ValueError):
        return None
    if level != 5 or not text.strip() or conf < 0:
        return None
    return {"page": key[0], "block": key[1], "par": key[2], "line": key[3], "word": key[4], "left": box[0], "top": box[1],
            "width": box[2], "height": box[3], "conf": max(0.0, min(100.0, conf)), "text": text.strip()}


def parse_tesseract_tsv(raw: Any) -> dict[str, Any]:
    """tesseract TSV (``-c tessedit_create_tsv=1`` or ``pytesseract.image_to_data``) -> {'words', 'error'}; layout rows
    (conf -1) and empty texts are dropped."""
    t = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw if isinstance(raw, str) else None
    if t is None or not t.strip():
        return {"words": [], "error": "empty"}
    if _HTML_HEAD_RE.match(t[:4096]):
        return {"words": [], "error": "html"}
    lines = t.splitlines()
    head = [h.strip() for h in lines[0].split("\t")]
    if tuple(head[:12]) != _TSV_COLUMNS:
        return {"words": [], "error": "bad_header"}
    words = []
    for line in lines[1:]:
        cols = line.split("\t")
        if len(cols) < 12:
            continue
        w = _word(dict(zip(_TSV_COLUMNS, [*cols[:11], "\t".join(cols[11:])], strict=True)))
        if w:
            words.append(w)
    return {"words": words, "error": None}


def ocr_text_and_spans(words: Iterable[dict[str, Any]]) -> tuple[str, list[tuple[int, int, float]]]:
    """OCR text (lines joined by newline) plus character spans with each word's confidence."""
    parts: list[str] = []
    spans: list[tuple[int, int, float]] = []
    pos = 0
    by_line: dict[tuple, list[dict[str, Any]]] = {}
    for w in words or ():
        by_line.setdefault((w["page"], w["block"], w["par"], w["line"]), []).append(w)
    for n, key in enumerate(sorted(by_line)):
        if n:
            parts.append("\n")
            pos += 1
        for j, w in enumerate(sorted(by_line[key], key=lambda x: x["word"])):
            if j:
                parts.append(" ")
                pos += 1
            spans.append((pos, pos + len(w["text"]), w["conf"]))
            parts.append(w["text"])
            pos += len(w["text"])
    return "".join(parts), spans


def span_confidence(spans: Sequence[tuple[int, int, float]], start: int, end: int) -> float | None:
    """Mean tesseract confidence (0-100) of the words overlapping [start, end)."""
    vals = [c for (s, e, c) in spans if s < end and e > start]
    return round(sum(vals) / len(vals), 2) if vals else None


def ocr_confidence(mean_conf_pct: Any) -> float:
    """c6: entity confidence from OCR word confidence, capped at 0.6."""
    try:
        c = float(mean_conf_pct)
    except (TypeError, ValueError):
        return 0.0
    return round(max(0.0, min(OCR_MAX_CONFIDENCE, c / 100.0)), 2)


_MISREAD_CHECKS = (
    ("rn~m", re.compile(r"rn", re.I)), ("vv~w", re.compile(r"vv", re.I)), ("cl~d", re.compile(r"cl", re.I)),
    ("0~o", re.compile(r"(?<=[a-z])0|0(?=[a-z])|(?<=\d)o|o(?=\d)", re.I)),
    ("1~l~i", re.compile(r"(?<=[a-z])1|1(?=[a-z])|(?<=\d)[li]|[li](?=\d)", re.I)),
    ("5~s", re.compile(r"(?<=[a-z])5|5(?=[a-z])", re.I)), ("8~b", re.compile(r"(?<=[a-z])8|8(?=[a-z])", re.I)),
)


def misread_risk(value: Any) -> list[str]:
    """c6: OCR-confusable glyph groups present in a value (0/O, l/1, rn/m, vv/w, cl/d, 5/S, 8/B)."""
    if not isinstance(value, str) or not value:
        return []
    return [name for name, rx in _MISREAD_CHECKS if rx.search(value)]


_CPF_TEXT_RE = re.compile(
    r"(?<![0-9A-Za-z])([0-9OoIlSB]{3})\.([0-9OoIlSB]{3})\.([0-9OoIlSB]{3})\s?[-–]\s?([0-9OoIlSB]{2})(?![0-9A-Za-z])"
    r"|(?<!\d)(\d{3})(\d{3})(\d{3})(\d{2})(?!\d)")


def cpf_valid(value: Any) -> bool:
    """CPF check digits (decides masking of unformatted runs only; CPFs are never pivoted)."""
    d = re.sub(r"\D", "", value) if isinstance(value, str) else ""
    if len(d) != 11 or d == d[0] * 11:
        return False
    for n in (9, 10):
        s = sum(int(d[i]) * (n + 1 - i) for i in range(n))
        if (s * 10) % 11 % 10 != int(d[n]):
            return False
    return True


def mask_cpfs(text: Any) -> tuple[str, int]:
    """c7: every CPF-shaped value of OCR text masked ('***.456.789-**'): formatted ones even with OCR confusables
    (O/0, l/1...), 11-digit runs only with valid check digits (phone numbers stay readable)."""
    t = text if isinstance(text, str) else ""
    count = 0

    def repl(m: re.Match[str]) -> str:
        nonlocal count
        if m.group(1):
            count += 1
            mid = (m.group(2) + m.group(3)).translate(str.maketrans("OoIlSB", "001158"))
            return f"***.{mid[:3]}.{mid[3:]}-**"
        digits = "".join(m.group(i) for i in range(5, 9))
        if cpf_valid(digits):
            count += 1
            return f"***.{digits[3:6]}.{digits[6:9]}-**"
        return m.group(0)

    return _CPF_TEXT_RE.sub(repl, t), count


def ocr_snippet(text: str, start: int, end: int, width: int = 40) -> str:
    """c7: report snippet around one indicator (CPFs masked, newlines flattened, ellipses on cuts)."""
    start, end = max(0, int(start)), min(len(text), int(end))
    a, b = max(0, start - width), min(len(text), end + width)
    snip, _ = mask_cpfs(text[a:b])
    snip = " ".join(snip.split())
    return ("..." if a > 0 else "") + snip + ("..." if b < len(text) else "")


def brcode_candidates(text: str, max_lines: int = 4) -> list[str]:
    """c5: OCR wraps long PIX 'copia e cola' payloads over several lines: candidates starting at '000201' joined
    with up to ``max_lines`` following lines (whitespace removed), cut after '6304' + 4 characters."""
    lines = (text or "").splitlines()
    out: list[str] = []
    for i, line in enumerate(lines):
        if "000201" not in line:
            continue
        joined = "".join("".join(lines[j].split()) for j in range(i, min(len(lines), i + max_lines)))
        start = joined.find("000201")
        end = joined.find("6304", start)
        cand = joined[start:end + 8] if end >= 0 and len(joined) >= end + 8 else joined[start:start + 512]
        if cand and cand not in out:
            out.append(cand)
    return out


def plan_pdf_pages(page_texts: Sequence[Any], *, max_ocr_pages: int = OCR_MAX_PDF_PAGES, min_text_chars: int = 20) -> dict[str, Any]:
    """c4: text layer first; OCR only for image-only pages, at most 10 per document (0-based indexes)."""
    text_pages, need = [], []
    for i, t in enumerate(page_texts or ()):
        s = t if isinstance(t, str) else ""
        (text_pages if len("".join(s.split())) >= min_text_chars else need).append(i)
    return {"text_pages": text_pages, "ocr_pages": need[:max_ocr_pages], "skipped_pages": need[max_ocr_pages:],
            "truncated": len(need) > max_ocr_pages}


def cap_ocr_output(result: dict[str, Any], cap_bytes: int = OCR_JSON_CAP) -> dict[str, Any]:
    """c3: keep the child's JSON result within 1 MB (per-word data dropped first, then page texts halved)."""
    def size(o: Any) -> int:
        return len(json.dumps(o, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    if size(result) <= cap_bytes:
        return result
    r = json.loads(json.dumps(result))
    for page in r.get("pages", []):
        if isinstance(page, dict):
            page.pop("words", None)
    r["truncated"] = True
    while size(r) > cap_bytes:
        pages = [p for p in r.get("pages", []) if isinstance(p, dict) and p.get("text")]
        if not pages:
            return {"truncated": True, "error": "output_cap"}
        biggest = max(pages, key=lambda p: len(p["text"]))
        biggest["text"] = biggest["text"][: len(biggest["text"]) // 2]
    return r


def tesseract_stderr_marker(stderr: Any) -> str | None:
    """Short reason of a failed tesseract run from its stderr: 'lang_missing' (-> UNAVAILABLE dataset),
    'config_missing', 'bad_image' or None."""
    err = stderr if isinstance(stderr, str) else ""
    if "Failed loading language" in err or "couldn't load any languages" in err:
        return "lang_missing"
    if "read_params_file: Can't open" in err:
        return "config_missing"
    if "Error in pixRead" in err or "Error during processing" in err or "libpng error" in err:
        return "bad_image"
    return None


# ---------------------------------------------------------------------------------- sandbox child (c3)
def _open_image(data: bytes, max_pixels: int) -> Any:
    from PIL import Image

    Image.MAX_IMAGE_PIXELS = max_pixels
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        im = Image.open(io.BytesIO(data))
        im.load()
    return im


def _tesseract_tsv(image: Any, *, tessdata_dir: str, langs: str, tesseract_cmd: str, timeout: float) -> str:
    """One OCR call through pytesseract (the c1 wrapper). Runs only inside the sandbox child."""
    import pytesseract

    # OpenMP busy-waits on multi-core hosts and can stall tesseract for minutes (measured 2026-11-26: > 60 s vs 1.2 s
    # with one thread); this runs in the sandbox child only, whose environment the tesseract process inherits.
    os.environ["OMP_THREAD_LIMIT"] = "1"
    pytesseract.pytesseract.tesseract_cmd = tesseract_cmd
    return pytesseract.image_to_data(image, lang=langs, config=f'--tessdata-dir "{tessdata_dir}" --psm 3',
                                     output_type=pytesseract.Output.STRING, timeout=timeout)


def _ocr_image_bytes(data: bytes, *, page: int, max_pixels: int, **ocr: Any) -> dict[str, Any]:
    refused = pixel_cap_check(image_header_info(data), max_pixels)
    if refused:
        return {"page": page, "source": "ocr", "error": refused}
    try:
        image = _open_image(data, max_pixels)
    except Exception as exc:  # noqa: BLE001 - hostile/corrupt image: reported, never raised
        return {"page": page, "source": "ocr", "error": type(exc).__name__, "message": str(exc)[:200]}
    try:
        tsv = _tesseract_tsv(image, **ocr)
    except Exception as exc:  # noqa: BLE001 - tesseract failure (stderr marker) or timeout
        marker = tesseract_stderr_marker(str(exc))
        return {"page": page, "source": "ocr", "error": marker or type(exc).__name__, "message": str(exc)[:300]}
    parsed = parse_tesseract_tsv(tsv)
    words = [{**w, "page": page} for w in parsed["words"]]
    text, _spans = ocr_text_and_spans(words)
    mean = round(sum(w["conf"] for w in words) / len(words), 2) if words else None
    return {"page": page, "source": "ocr", "words": words, "text": text[:MAX_TEXT_CHARS], "mean_conf": mean,
            "error": parsed["error"] if parsed["error"] not in (None, "empty") else None}


def ocr_child(data: bytes, *, kind: str, tessdata_dir: str, langs: str = LANGS, tesseract_cmd: str = "tesseract",
              max_pages: int = OCR_MAX_PDF_PAGES, max_pixels: int = IMAGE_MAX_PIXELS, timeout: float = 30.0) -> dict[str, Any]:
    """c3-c4 sandbox target (``image_metadata.sandbox_run``; never called in the V3LUM process): OCR of one image,
    or the text layer of a PDF plus OCR of at most ``max_pages`` image-only pages. Result capped at 1 MB."""
    ocr = {"tessdata_dir": tessdata_dir, "langs": langs, "tesseract_cmd": tesseract_cmd, "timeout": timeout}
    if kind == "image":
        return cap_ocr_output({"kind": "image", "pages": [_ocr_image_bytes(data, page=1, max_pixels=max_pixels, **ocr)]})
    from pypdf import PdfReader

    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        total = len(reader.pages)
    except Exception as exc:  # noqa: BLE001 - corrupt PDF: reported, never raised
        return {"kind": "pdf", "pages": [], "error": "pdf_unreadable", "message": f"{type(exc).__name__}: {str(exc)[:200]}"}
    scan = min(total, PDF_MAX_SCAN_PAGES)
    texts: list[str] = []
    for i in range(scan):
        try:
            texts.append((reader.pages[i].extract_text() or "")[:MAX_TEXT_CHARS])
        except Exception:  # noqa: BLE001 - one broken page never ends the document
            texts.append("")
    plan = plan_pdf_pages(texts, max_ocr_pages=max_pages)
    pages: list[dict[str, Any]] = [{"page": i + 1, "source": "text_layer", "text": texts[i]} for i in plan["text_pages"]]
    gaps: list[int] = []
    for i in plan["ocr_pages"]:
        try:
            images = list(reader.pages[i].images)
        except Exception:  # noqa: BLE001
            images = []
        best = max(images, key=lambda im: len(getattr(im, "data", b"") or b""), default=None)
        if best is None:
            gaps.append(i + 1)  # vector-only page: no text layer, no image (coverage gap)
            continue
        pages.append(_ocr_image_bytes(bytes(best.data), page=i + 1, max_pixels=max_pixels, **ocr))
    plan_out = {"total_pages": total, "scanned_pages": scan, "text_pages": [i + 1 for i in plan["text_pages"]],
                "ocr_pages": [i + 1 for i in plan["ocr_pages"]], "skipped_pages": [i + 1 for i in plan["skipped_pages"]],
                "coverage_gaps": gaps, "truncated": plan["truncated"] or total > scan}
    return cap_ocr_output({"kind": "pdf", "pages": sorted(pages, key=lambda p: p["page"]), "plan": plan_out})


# ---------------------------------------------------------------------------------- module
def _install_hint() -> str:
    return TESSERACT_INSTALL.get(platform.system(), TESSERACT_INSTALL["Linux"])


@register
class ImageOcr(Module):
    name = "image_ocr"
    title = "Offline OCR of screenshots and scans (Tesseract por+eng)"
    description = (
        "Offline OCR of images and image-only PDF pages (PDF text layer first) with Tesseract por+eng in the file-analysis "
        "sandbox; indicators, boleto/PIX codes and QR codes found are listed as unconfirmed pivots, CPFs masked."
    )
    category = "geo_image_meta"
    accepts = {T.FILE}
    produces = {T.URL, T.DOMAIN, T.IPV4, T.EMAIL, T.PHONE, T.BOLETO, T.PIX_BRCODE, T.CNPJ}
    tags = {"offline", "free"}
    reference = "https://github.com/tesseract-ocr/tessdata_fast"
    notice = (
        "Tesseract and the tessdata_fast models are Apache-2.0; the binary is installed by the analyst (never by V3LUM). "
        "OCR text may hold personal data: it stays in the case evidence; OCR-derived values are unconfirmed (confidence <= 0.6)."
    )
    # ---- contract v2 declarations ---------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # c1: the dataset manager alone downloads the models
    hosts = ()
    sources = (SOURCE,)
    access_model = "offline"
    requires_packages = ("pytesseract", "PIL")
    expected_latency = 2.0
    timeout = 240.0
    max_pivots = MAX_PIVOTS
    default_enabled = True
    settings = {
        "image_ocr_tesseract_path": SettingSpec("", "absolute path of the tesseract binary for image_ocr (empty: found on PATH)"),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return file_kind(read_head(entity.value, 64)) is not None

    # ---- readiness ---------------------------------------------------------------------------
    @staticmethod
    def tesseract_path(ctx: Any) -> str | None:
        """c1: the configured path (an existing file named tesseract*) or the binary on PATH; None when missing."""
        configured = str(ctx.setting("image_ocr_tesseract_path", "") or "").strip()
        if configured:
            p = Path(configured)
            ok = p.is_absolute() and p.is_file() and p.name.lower().startswith("tesseract")
            return str(p) if ok else None
        return shutil.which("tesseract")

    @staticmethod
    def tessdata_dir(ctx: Any) -> str:
        """c2: both pinned models through the dataset manager (DatasetUnavailable -> UNAVAILABLE 'dataset')."""
        paths = [Path(ctx.data.fetch(name)) for name in OCR_MODELS]
        return str(paths[0].parent)

    # ---- run -----------------------------------------------------------------------------------
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        try:
            data = read_regular_file(entity.value, OCR_INPUT_CAP)
        except InputRefused as exc:
            return res.mark(exc.status, str(exc), reason_code=exc.code)
        kind = file_kind(data[:64])
        if kind is None:
            return res.mark(Status.SKIPPED, "not an image or PDF: not analysed", reason_code="not_applicable")
        if kind == "image":
            refused = pixel_cap_check(image_header_info(data), IMAGE_MAX_PIXELS)
            if refused:
                return res.mark(Status.ERROR, f"image refused before decoding ({refused}; cap {IMAGE_MAX_PIXELS:,} pixels): nothing was OCRed")
        cmd = self.tesseract_path(ctx)
        if cmd is None:
            return res.mark(Status.UNAVAILABLE, f"tesseract binary not found (setting image_ocr_tesseract_path or PATH); install: {_install_hint()}",
                            reason_code="package")
        for package, hint in (("pytesseract", PYTESSERACT_INSTALL), ("PIL", "pip install Pillow")):
            if not package_available(package):
                return res.mark(Status.UNAVAILABLE, f"{package} not installed; install: {hint}", reason_code="package")
        tessdata = self.tessdata_dir(ctx)
        args = {"kind": kind, "tessdata_dir": tessdata, "langs": LANGS, "tesseract_cmd": cmd, "max_pages": OCR_MAX_PDF_PAGES,
                "max_pixels": IMAGE_MAX_PIXELS, "timeout": 30.0}
        try:
            out = sandbox_run(f"{__name__}:ocr_child", entity.value, args=args, **OCR_LIMITS)
        except SandboxUnavailable as exc:
            return res.mark(Status.UNAVAILABLE, f"OCR runs tesseract only inside the file-analysis sandbox (P363 c3): {exc}; could not verify",
                            reason_code="package")
        if not out.get("ok"):
            code, reason = sandbox_failure(out)
            return res.mark(Status.ERROR, reason, reason_code=code)
        result = out.get("result") if isinstance(out.get("result"), dict) else {}
        errors = [p.get("error") for p in result.get("pages", []) if isinstance(p, dict) and p.get("error")]
        if "lang_missing" in errors:
            return res.mark(Status.UNAVAILABLE, "tesseract could not load the tessdata_fast models: run v3lum data update "
                            + " ".join(OCR_MODELS), reason_code="dataset")
        if result.get("error"):
            return res.mark(Status.ERROR, f"document could not be read ({result.get('error')}): could not verify")
        qr = self._qr(entity.value) if kind == "image" else None
        return self.emit(res, result, ctx, qr=qr, isolation=str(out.get("isolation") or ""))

    @staticmethod
    def _qr(path: str) -> dict[str, Any] | None:
        """c5: the P261 QR helpers on the same image, in the same sandbox (None when they cannot run)."""
        try:
            from v3lum.modules.geo_image_meta import qr_decode as _qr
        except ImportError:
            return None
        try:
            out = sandbox_run(f"{_qr.__name__}:zxing_child", path, args={"max_pixels": IMAGE_MAX_PIXELS, "payload_cap": _qr.QR_PAYLOAD_CAP},
                              **_qr.DECODER_LIMITS)
        except SandboxUnavailable:
            return None
        if not out.get("ok"):
            return None
        norm = _qr.normalize_zxing_results(out.get("result"))
        return norm if norm.get("status") == "ok" else None

    # ---- emission (pure: tests feed recorded tesseract output) ------------------------------------
    def emit(self, res: ModuleResult, result: dict[str, Any], ctx: Any, *, qr: dict[str, Any] | None = None,
             isolation: str = "") -> ModuleResult:
        pages = [p for p in result.get("pages", []) if isinstance(p, dict)]
        snippets: list[dict[str, Any]] = []
        withheld: dict[str, int] = {}
        payments: list[dict[str, Any]] = []
        seen: set[str] = set()
        cpf_total = 0
        evidence_pages = []
        for page in pages:
            source = "ocr" if page.get("source") == "ocr" else "text_layer"
            words = page.get("words") if isinstance(page.get("words"), list) else []
            if source == "ocr" and words:
                text, spans = ocr_text_and_spans(words)
            else:
                text, spans = str(page.get("text") or ""), []
            masked, cpfs = mask_cpfs(text)
            cpf_total += cpfs
            evidence_pages.append({"page": page.get("page"), "source": source, "mean_conf": page.get("mean_conf"),
                                   "error": page.get("error"), "text": masked})
            if text.strip():
                self._extract(res, text, spans, page, source, seen, snippets, withheld, payments)
        words_n = sum(len(p.get("words") or []) for p in pages if isinstance(p.get("words"), list))
        confs = [p["mean_conf"] for p in pages if isinstance(p.get("mean_conf"), (int, float))]
        plan = result.get("plan") if isinstance(result.get("plan"), dict) else {}
        summary = {
            "engine": "tesseract (pytesseract)", "langs": "por+eng (tessdata_fast)", "isolation": isolation or "sandbox",
            "pages": len(pages), "text_layer_pages": plan.get("text_pages", []), "ocr_pages": [p.get("page") for p in pages if p.get("source") == "ocr"],
            "skipped_pages": plan.get("skipped_pages", []), "coverage_gaps": plan.get("coverage_gaps", []), "words": words_n,
            "mean_confidence": round(sum(confs) / len(confs), 2) if confs else None, "truncated": bool(result.get("truncated") or plan.get("truncated")),
        }
        res.attr("ocr_summary", {k: v for k, v in summary.items() if v not in (None, [], "")})
        res.attr("ocr_snippets", snippets[:MAX_SNIPPETS])
        if qr:
            self._emit_qr(res, qr)
        has_text = any(p["text"].strip() for p in evidence_pages)
        if has_text:
            res.finding(
                "Text recognised in the file (OCR)",
                "info",
                f"{len(pages)} page(s) read ({len(summary['ocr_pages'])} by OCR, {len(summary['text_layer_pages'])} from the PDF text layer); "
                f"{len(snippets)} indicator(s) listed as unconfirmed pivots. The full text stays in the case evidence only.",
                data={"summary": summary},
                tags=["info", "ocr"],
            )
        if cpf_total or withheld.get("cpf"):
            res.finding(
                "CPF in the recognised text (masked, not pivoted)",
                "info",
                f"{max(cpf_total, withheld.get('cpf', 0))} CPF-shaped value(s) masked in snippets and evidence; CPFs are never "
                "looked up or pivoted (team rule 4).",
                data={"count": max(cpf_total, withheld.get("cpf", 0))},
                tags=["info", "privacy"],
            )
        for n, pay in enumerate(payments):
            if pay["checksum_ok"] is False:
                res.finding(
                    "Payment code in OCR text could not be verified (OCR)",
                    "info",
                    f"{pay['kind']} {pay['display']}: check digits fail on OCR text - could not verify (OCR): likely a misread, "
                    "not tampering. Confirm against the original document before drawing conclusions.",
                    data={"kind": pay["kind"], "rule": pay["rule"]},
                    tags=["info", "ocr", "unconfirmed"],
                    key=str(n),
                )
        if pages and len(summary["coverage_gaps"]) and not has_text:
            res.error = "PDF pages without a text layer or an embedded image cannot be OCRed without a rasteriser"
        res.raw = {"summary": summary, "pages": evidence_pages, "withheld": withheld,
                   "payments": [{k: p[k] for k in ("kind", "display", "checksum_ok", "page")} for p in payments]}
        if not has_text:
            res.error = res.error or "no text recognised in the file (blank or unreadable image)"
            return res.mark(Status.EMPTY)
        return res

    def _extract(self, res: ModuleResult, text: str, spans: list[tuple[int, int, float]], page: dict[str, Any], source: str,
                 seen: set[str], snippets: list[dict[str, Any]], withheld: dict[str, int], payments: list[dict[str, Any]]) -> None:
        """c5-c7: P172 extractor + P232/P233 parsers over one page's text."""
        ocr = source == "ocr"
        page_conf = page.get("mean_conf") if isinstance(page.get("mean_conf"), (int, float)) else None

        def conf_at(start: int, end: int, value: str) -> float | None:
            c = span_confidence(spans, start, end) if spans else None
            if c is None and spans:
                pos = text.lower().find(value.lower()[:40])
                c = span_confidence(spans, pos, pos + len(value)) if pos >= 0 else None
            return c if c is not None else page_conf

        def emit(ent: Entity, start: int, end: int, *, extra: str = "", checksum_ok: bool | None = None) -> None:
            if ent.key in seen:
                return
            seen.add(ent.key)
            c = conf_at(start, end, ent.value)
            risks = misread_risk(ent.value) if ocr else []
            snippet = ocr_snippet(text, start, end)
            if ocr:
                note = f"{OCR_NOTE}; page {page.get('page')}" + (f"; confusable glyphs {', '.join(risks)}" if risks else "") + extra
                confidence = ocr_confidence(c if c is not None else 0)
                res.pivot(ent.type, ent.value, "extracted_from", confidence=confidence, expand=False, note=note)
            else:
                note = f"PDF text layer, page {page.get('page')}" + extra
                expand = ent.type in IOC_TYPES
                confidence = 0.7
                res.pivot(ent.type, ent.value, "extracted_from", confidence=confidence, expand=expand, note=note)
            snippets.append({"type": ent.type.value, "display": ent.display, "snippet": snippet, "page": page.get("page"),
                             "source": source, "confidence": confidence, "misread_risk": risks, "checksum_ok": checksum_ok})

        scrubbed = _ioc.scrub(text)
        same = scrubbed == text
        try:
            extracted = _ioc.extract(text, source_type="text").entities
        except Exception:  # noqa: BLE001 - one bad page never ends the run
            extracted = []
        for item in extracted:
            ent = item.entity
            if ent.type in SECRET_TYPES or ent.type is T.CPF:
                withheld[ent.type.value] = withheld.get(ent.type.value, 0) + 1
                continue
            start, end = item.span if same else (max(0, text.find(ent.value)), max(0, text.find(ent.value)) + len(ent.value))
            emit(ent, start, end)
        if _br is None:
            return
        for item in _br.extract_br_entities(text):
            kind, value = item.get("type"), item.get("value")
            if kind in ("cpf", "masked_cpf"):
                withheld["cpf"] = withheld.get("cpf", 0) + (1 if kind == "cpf" else 0)
                continue
            if kind == "boleto":
                parsed = _br.parse_boleto(value)
                ok = bool(parsed.get("check_digits_ok")) if parsed.get("ok") else False
                payments.append({"kind": "boleto", "display": f"{value[:5]}...{value[-6:]}", "checksum_ok": ok, "page": page.get("page"),
                                 "rule": item.get("rule")})
                ent = Entity.try_make(T.BOLETO, value)
                if ent is not None:
                    emit(ent, *item["span"], extra="; boleto check digits " + ("valid" if ok else "fail on OCR text (could not verify, OCR)"),
                         checksum_ok=ok)
        for cand in brcode_candidates(text):
            parsed = _br.parse_brcode(cand, origin="ocr" if ocr else "typed")
            if not parsed.get("ok"):
                if "br.gov.bcb.pix" in cand.lower():  # a PIX payload the OCR garbled: could not verify, never 'tampered'
                    payments.append({"kind": "PIX", "display": "BR Code not readable on OCR text", "checksum_ok": False,
                                     "page": page.get("page"), "rule": "brcode_emv"})
                continue
            ok = bool(parsed.get("crc_ok"))
            payments.append({"kind": "PIX", "display": (parsed.get("key_display") or "BR Code")[:60], "checksum_ok": ok,
                             "page": page.get("page"), "rule": "brcode_emv"})
            ent = Entity.try_make(T.PIX_BRCODE, cand)
            if ent is not None:
                pos = text.find(cand[:20])
                emit(ent, max(0, pos), max(0, pos) + len(cand), extra="; PIX CRC " + ("valid" if ok else "fails on OCR text (could not verify, OCR)"),
                     checksum_ok=ok)

    @staticmethod
    def _emit_qr(res: ModuleResult, norm: dict[str, Any]) -> None:
        """c5: QR codes decoded from the same image by the P261 helpers (exact decodes, listed for the analyst)."""
        for code in norm.get("codes", [])[:20]:
            item = code.get("item") or {}
            value = item.get("value")
            if code.get("kind") == "url" and value:
                res.pivot(T.URL, value, "extracted_from", confidence="probable", expand=False,
                          note="decoded from a QR code in the image (P261 helpers): never fetched or opened")
            elif code.get("kind") == "boleto" and value:
                res.pivot(T.BOLETO, value, "extracted_from", confidence="probable", expand=False, note="boleto barcode decoded from the image (P261)")
            elif code.get("kind") == "pix" and value:
                res.pivot(T.PIX_BRCODE, value, "extracted_from", confidence="probable", expand=False, note="PIX QR decoded from the image (P261)")
        if norm.get("summary"):
            res.finding("QR codes in the image", "info", str(norm["summary"]), data={"count": len(norm.get("codes", []))},
                        tags=["info", "qr_code"])
