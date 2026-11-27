"""Error Level Analysis (ELA) of JPEG images: an offline tamper heuristic, never proof (P264, batch p3-G12-1).

Final conditions, as implemented here:

1. Offline module: disclosure ``none`` (no network at all: ScopedHttp refuses any request), terms ``open``, provider
   tier n/a, allowed at TLP:RED. Opt-in (``default_enabled=False``). Pillow is an optional package (core extra
   'full', ``requires_packages=('PIL',)``): without it the run is UNAVAILABLE ``package``.
2. Parsing runs only in the shared file-analysis sandbox ``core/sandbox.py`` through
   ``image_metadata.sandbox_run`` (python -I child, wall timeout, rlimits - memory <= 1 GiB, CPU, no file writes -
   100 MB input cap, 1 MB JSON output cap). :func:`ela_child` is the sandbox target and is never called in the
   V3LUM process; its JSON is validated by :func:`normalize_ela_child_output` (never trusted). This build has no
   core sandbox yet: the run is then UNAVAILABLE ``package`` ('runs only inside the file-analysis sandbox'),
   never a result computed in process. Downloaded data is never executed.
3. JPEG only: the magic bytes are sniffed without decoding; PNG and other lossless images (most PIX-receipt
   screenshots) are SKIPPED ``not_applicable`` with 'ELA not meaningful for lossless images'; other formats are
   SKIPPED too. Images above 40 MP are refused before any decoding.
4. Method: the child re-saves the decoded JPEG at a fixed quality (q90) in memory, takes
   ``ImageChops.difference`` and the per-pixel maximum over R, G, B, and returns aggregates only (256-bin
   histogram, 8x8 tile means, size, the estimated source quality from the quantisation table) plus a
   contrast-stretched ELA PNG. The module records the numeric metrics (mean/max/std/p99 error level, share of
   pixels >= 16, region statistics and the three hottest regions) in attribute ``ela_metrics``; the ELA PNG goes
   to the case evidence (``res.raw['ela_map_png']``) as a data: URI for the HTML report only (core request: the
   HTML renderer embeds it, the case directory keeps it).
5. Wording: one INFO finding 'Error level analysis: heuristic, not proof of tampering' (tags ``heuristic``,
   ``context_only``: never scored and never raising severity); attribute ``ela_summary`` is the only terminal
   line - 'ELA map in the HTML report (heuristic, not proof)' - and no value anywhere is named a 'tamper' number.
6. Tests generate the synthetic fixtures themselves: an original and an edited JPEG and a PNG that is skipped.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import statistics
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.geo_image_meta.image_metadata import (
    InputRefused,
    SandboxUnavailable,
    read_head,
    sandbox_failure,
    sandbox_run,
)

ELA_RESAVE_QUALITY = 90
ELA_WORDING = "Error level analysis: heuristic, not proof of tampering"
ELA_TERMINAL_LINE = "ELA map in the HTML report (heuristic, not proof)"
ELA_LOSSLESS_REASON = "ELA not meaningful for lossless images"
ELA_MAX_INPUT_BYTES = 100 * 1024 * 1024
ELA_MAX_PIXELS = 40_000_000
ELA_MAX_PNG_BYTES = 700_000
GRID = 8
PNG_MAX_WIDTH = 1024
SANDBOX_LIMITS = {"wall_timeout": 30.0, "cpu_seconds": 20, "mem_bytes": 1 << 30, "max_input": ELA_MAX_INPUT_BYTES,
                  "max_output": 1 << 20}

# IJG / Annex K standard luminance table (natural order) and the zig-zag order used by the DQT segment
_STD_LUMA = [16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55,
             14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51, 87, 80, 62,
             18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92,
             49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99]
_ZIGZAG = [0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34,
           27, 20, 13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37,
           44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63]
_STD_LUMA_ZZ = [_STD_LUMA[i] for i in _ZIGZAG]


# ======================================================================================================
# pure helpers (stdlib only; used by the parent and by the sandbox child)
# ======================================================================================================

def sniff_image_format(head: Any) -> str | None:
    """jpeg, png, gif, bmp, tiff, webp_lossy, webp_lossless, webp_extended, heic, avif or None (magic bytes)."""
    if not isinstance(head, (bytes, bytearray)):
        return None
    h = bytes(head[:64])
    if h[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if h[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if h[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if h[:2] == b"BM" and len(h) >= 14:
        return "bmp"
    if h[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if h[:4] == b"RIFF" and h[8:12] == b"WEBP":
        return {b"VP8 ": "webp_lossy", b"VP8L": "webp_lossless", b"VP8X": "webp_extended"}.get(h[12:16], "webp_extended")
    if h[4:8] == b"ftyp":
        brand = h[8:12]
        if brand in (b"avif", b"avis"):
            return "avif"
        if brand in (b"heic", b"heix", b"hevc", b"heim", b"heis", b"mif1", b"msf1"):
            return "heic"
    return None


def ela_applicability(fmt: str | None) -> str | None:
    """None for JPEG, else the reason the image is not analysed (FC3)."""
    if fmt == "jpeg":
        return None
    if fmt in ("png", "gif", "bmp", "tiff", "webp_lossless"):
        return ELA_LOSSLESS_REASON
    if fmt in ("webp_lossy", "webp_extended", "heic", "avif"):
        return "ELA is implemented for JPEG only"
    return "not a recognised image"


def jpeg_info(data: Any, max_segments: int = 512) -> dict[str, Any] | None:
    """Walk the JPEG marker segments up to SOS: {width, height, components, progressive, dqt, errors}."""
    if not isinstance(data, (bytes, bytearray)) or bytes(data[:3]) != b"\xff\xd8\xff":
        return None
    info: dict[str, Any] = {"width": None, "height": None, "components": None, "progressive": None, "dqt": {},
                            "errors": []}
    i, n, count = 2, len(data), 0
    while i + 4 <= n and count < max_segments:
        if data[i] != 0xFF:
            info["errors"].append(f"bad marker at {i}")
            break
        marker = data[i + 1]
        if marker == 0xFF:
            i += 1
            continue
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if marker == 0xD9:
            break
        seglen = int.from_bytes(data[i + 2:i + 4], "big")
        if seglen < 2 or i + 2 + seglen > n:
            info["errors"].append(f"truncated segment 0x{marker:02X} at {i}")
            break
        seg = bytes(data[i + 4:i + 2 + seglen])
        if marker == 0xDB:
            j = 0
            while j < len(seg):
                pq, tq = seg[j] >> 4, seg[j] & 0x0F
                size = 128 if pq else 64
                vals = seg[j + 1:j + 1 + size]
                if len(vals) < size or tq > 3:
                    info["errors"].append("bad DQT")
                    break
                info["dqt"][tq] = list(vals) if pq == 0 else [int.from_bytes(vals[k:k + 2], "big") for k in range(0, 128, 2)]
                j += 1 + size
        elif 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            if len(seg) >= 6:
                info["height"] = int.from_bytes(seg[1:3], "big")
                info["width"] = int.from_bytes(seg[3:5], "big")
                info["components"] = seg[5]
                info["progressive"] = marker in (0xC2, 0xC6, 0xCA, 0xCE)
        elif marker == 0xDA:
            break
        i += 2 + seglen
        count += 1
    return info


def _ijg_table(quality: int) -> list[int]:
    q = max(1, min(100, int(quality)))
    scale = 5000 // q if q < 50 else 200 - 2 * q
    return [max(1, min(255, (v * scale + 50) // 100)) for v in _STD_LUMA_ZZ]


def jpeg_estimate_quality(dqt: Any) -> int | None:
    """Estimated IJG quality (1..100) of the source from its luminance table, or None."""
    if not isinstance(dqt, dict):
        return None
    table = dqt.get(0)
    if not (isinstance(table, list) and len(table) == 64 and all(isinstance(v, int) for v in table)):
        return None
    best: tuple[int, int] | None = None
    for q in range(1, 101):
        err = sum(abs(a - b) for a, b in zip(table, _ijg_table(q), strict=True))
        if best is None or err < best[1]:
            best = (q, err)
    return best[0] if best else None


def ela_summary(agg: Any) -> dict[str, Any] | None:
    """Numeric metrics from the child's aggregates: mean/max/std/p50/p95/p99 error level, share >= 16 / >= 32, tile
    max/median, region_ratio (hottest tile / median tile) and the three hottest regions (image fractions)."""
    if not isinstance(agg, dict):
        return None
    hist, tiles = agg.get("histogram"), agg.get("tile_means")
    w, h, grid = agg.get("width"), agg.get("height"), agg.get("grid")
    if not (isinstance(hist, list) and len(hist) == 256 and all(isinstance(c, int) and not isinstance(c, bool) and c >= 0 for c in hist)):
        return None
    if not all(isinstance(v, int) and not isinstance(v, bool) and v > 0 for v in (w, h, grid)):
        return None
    if not (isinstance(tiles, list) and len(tiles) == grid and all(
            isinstance(r, list) and len(r) == grid and all(isinstance(x, (int, float)) and not isinstance(x, bool)
                                                           and math.isfinite(x) and 0 <= x <= 255 for x in r)
            for r in tiles)):
        return None
    n = sum(hist)
    if n <= 0:
        return None
    mean = sum(i * c for i, c in enumerate(hist)) / n
    var = sum(c * (i - mean) ** 2 for i, c in enumerate(hist)) / n
    mx = max(i for i, c in enumerate(hist) if c)

    def pct(p: float) -> int:
        target, cum = p * n, 0
        for i, c in enumerate(hist):
            cum += c
            if cum >= target:
                return i
        return 255

    flat = [(float(tiles[r][c]), r, c) for r in range(grid) for c in range(grid)]
    vals = [v for v, _, _ in flat]
    tmax, tmed = max(vals), statistics.median(vals)
    hot = sorted(flat, key=lambda t: (-t[0], t[1], t[2]))[:3]
    regions = [{"row": r, "col": c, "mean": round(v, 3),
                "box": [round(c / grid, 3), round(r / grid, 3), round((c + 1) / grid, 3), round((r + 1) / grid, 3)]}
               for v, r, c in hot]
    return {
        "mean": round(mean, 3), "max": mx, "std": round(math.sqrt(var), 3), "p50": pct(0.50), "p95": pct(0.95),
        "p99": pct(0.99), "frac_ge_16": round(sum(hist[16:]) / n, 5), "frac_ge_32": round(sum(hist[32:]) / n, 5),
        "tile_max": round(tmax, 3), "tile_median": round(tmed, 3), "region_ratio": round(tmax / max(tmed, 0.5), 3),
        "hot_regions": regions, "grid": grid, "width": w, "height": h,
    }


def png_data_uri(png: Any, max_bytes: int = ELA_MAX_PNG_BYTES) -> str | None:
    """'data:image/png;base64,...' for the HTML report, or None (not a PNG, or over the size cap)."""
    if isinstance(png, str):
        try:
            png = base64.b64decode(png, validate=True)
        except (binascii.Error, ValueError):
            return None
    if not isinstance(png, (bytes, bytearray)) or bytes(png[:8]) != b"\x89PNG\r\n\x1a\n" or len(png) > max_bytes:
        return None
    return "data:image/png;base64," + base64.b64encode(bytes(png)).decode("ascii")


def normalize_ela_child_output(obj: Any) -> dict[str, Any]:
    """Validate the child's JSON (never trusted): {'ok', 'errors', 'skip', 'metrics', 'png_data_uri'}."""
    res: dict[str, Any] = {"ok": False, "errors": [], "skip": None, "metrics": {}, "png_data_uri": None}
    if isinstance(obj, (str, bytes)):
        try:
            obj = json.loads(obj)
        except ValueError:
            obj = None
    if not isinstance(obj, dict):
        res["errors"].append("child output is not a JSON object")
        return res
    if obj.get("skipped"):
        fmt = obj.get("format_sniffed") if isinstance(obj.get("format_sniffed"), str) else None
        res["skip"] = ela_applicability(fmt) if fmt and fmt != "jpeg" else str(obj.get("skipped"))[:160]
        return res
    if obj.get("error"):
        res["errors"].append(f"child error: {str(obj.get('error'))[:200]}")
        return res
    summary = ela_summary(obj)
    if summary is None:
        res["errors"].append("aggregates missing or malformed")
        return res
    q = obj.get("jpeg_quality_estimate")
    resave = obj.get("quality_resave")
    res["metrics"] = {
        "heuristic": "not proof of tampering",
        "mean": summary["mean"], "max": summary["max"], "std": summary["std"], "p99": summary["p99"],
        "frac_ge_16": summary["frac_ge_16"], "region_ratio": summary["region_ratio"],
        "hot_regions": summary["hot_regions"], "width": summary["width"], "height": summary["height"],
        "resave_quality": resave if isinstance(resave, int) and not isinstance(resave, bool) else ELA_RESAVE_QUALITY,
        "jpeg_quality_estimate": q if isinstance(q, int) and not isinstance(q, bool) and 1 <= q <= 100 else None,
    }
    if obj.get("ela_png_b64"):
        res["png_data_uri"] = png_data_uri(obj.get("ela_png_b64"))
        if res["png_data_uri"] is None:
            res["errors"].append("ELA PNG missing, invalid or over the size cap (not embedded)")
    res["ok"] = True
    return res


# ======================================================================================================
# sandbox child (runs ONLY inside core/sandbox.py; Pillow imported inside the function)
# ======================================================================================================

def ela_child(data: bytes, quality: int = ELA_RESAVE_QUALITY, grid: int = GRID, png_max_width: int = PNG_MAX_WIDTH) -> dict[str, Any]:
    """FC2-FC4 sandbox child: JPEG only, <= 40 MP checked before decoding, in-memory re-save at q90, difference
    map, aggregates and a contrast-stretched PNG. Never writes files; never decides 'tampered'."""
    import io

    fmt = sniff_image_format(data[:64])
    if fmt != "jpeg":
        return {"skipped": "not_jpeg", "format_sniffed": fmt}
    if len(data) > ELA_MAX_INPUT_BYTES:
        return {"skipped": "input over the 100 MB cap", "format_sniffed": fmt}
    info = jpeg_info(data) or {}
    w0, h0 = info.get("width"), info.get("height")
    if isinstance(w0, int) and isinstance(h0, int) and w0 * h0 > ELA_MAX_PIXELS:
        return {"skipped": f"image larger than {ELA_MAX_PIXELS // 1_000_000} MP: not decoded", "format_sniffed": fmt}
    try:
        import warnings

        from PIL import Image, ImageChops, ImageStat
    except ImportError:
        return {"error": "Pillow not installed"}
    Image.MAX_IMAGE_PIXELS = ELA_MAX_PIXELS
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            im = Image.open(io.BytesIO(data))
            im = im.convert("RGB")
        buf = io.BytesIO()
        im.save(buf, "JPEG", quality=int(quality))
        resaved = Image.open(io.BytesIO(buf.getvalue())).convert("RGB")
        diff = ImageChops.difference(im, resaved)
        r, g, b = diff.split()
        err = ImageChops.lighter(ImageChops.lighter(r, g), b)
        w, h = err.size
        grid = max(1, min(int(grid), w, h))
        xs = [w * k // grid for k in range(grid + 1)]
        ys = [h * k // grid for k in range(grid + 1)]
        tiles = [[round(ImageStat.Stat(err.crop((xs[c], ys[r_], xs[c + 1], ys[r_ + 1]))).mean[0], 4)
                  for c in range(grid)] for r_ in range(grid)]
        hist = err.histogram()
        mx = max((i for i, c in enumerate(hist) if c), default=0)
        scale = 255.0 / max(1, mx)
        vis = err.point(lambda v: min(255, int(v * scale)))
        if vis.size[0] > png_max_width:
            vis = vis.resize((png_max_width, max(1, vis.size[1] * png_max_width // vis.size[0])))
        pbuf = io.BytesIO()
        vis.save(pbuf, "PNG", optimize=True)
    except Exception as exc:  # noqa: BLE001 - a hostile or truncated image ends as a child error, never a crash
        return {"error": f"{type(exc).__name__}: {str(exc)[:160]}"}
    return {"format_sniffed": fmt, "quality_resave": int(quality), "width": w, "height": h, "grid": grid,
            "histogram": hist, "tile_means": tiles, "jpeg_quality_estimate": jpeg_estimate_quality(info.get("dqt") or {}),
            "ela_png_b64": base64.b64encode(pbuf.getvalue()).decode("ascii")}


# ======================================================================================================
# the module
# ======================================================================================================

@register
class ImageEla(Module):
    name = "image_ela"
    title = "Error level analysis (JPEG, heuristic)"
    description = ("Offline error level analysis of a JPEG (re-save at q90, difference map) in the file-analysis "
                   "sandbox: numeric error-level metrics and an ELA map for the HTML report; a heuristic, never proof.")
    category = "geo_image_meta"
    accepts = {T.FILE}
    produces = frozenset()
    tags = {"offline"}
    reference = "https://fotoforensics.com/tutorial-ela.php"
    notice = ("ELA is a heuristic, not proof of tampering: recompressed images (messaging apps, screenshots) mislead it. "
              "JPEG only; lossless images are skipped.")
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    access_model = "offline"
    requires_packages = ("PIL",)
    max_pivots = 0
    timeout = 60.0
    default_enabled = False

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return bool(read_head(entity.value, 16))

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        fmt = sniff_image_format(read_head(entity.value, 64))
        reason = ela_applicability(fmt)
        if reason is not None:  # FC3: decided from the magic bytes, nothing is decoded
            return res.mark(Status.SKIPPED, reason, reason_code="not_applicable")
        try:
            out = sandbox_run(f"{__name__}:ela_child", entity.value, args={"quality": ELA_RESAVE_QUALITY}, **SANDBOX_LIMITS)
        except SandboxUnavailable as exc:
            return res.mark(Status.UNAVAILABLE, f"ELA decodes images only inside the file-analysis sandbox (P264 cond 2): "
                            f"{exc}; could not verify", reason_code="package")
        except InputRefused as exc:
            return res.mark(exc.status, str(exc), reason_code=exc.code)
        if not out.get("ok"):
            code, why = sandbox_failure(out)
            return res.mark(Status.ERROR, why, reason_code=code)
        norm = normalize_ela_child_output(out.get("result"))
        if norm["skip"]:
            return res.mark(Status.SKIPPED, norm["skip"], reason_code="not_applicable")
        if not norm["ok"]:
            return res.mark(Status.ERROR, f"ELA output unusable ({'; '.join(norm['errors'])[:200]}): could not verify")
        m = norm["metrics"]
        res.attr("ela_summary", ELA_TERMINAL_LINE)
        res.attr("ela_metrics", m)
        res.raw = {"metrics": m, "ela_map_png": norm["png_data_uri"], "isolation": out.get("isolation"),
                   "warnings": norm["errors"]}
        q = m.get("jpeg_quality_estimate")
        caveat = (f" The source was saved at about quality {q}: far from {ELA_RESAVE_QUALITY}, or recompressed by a "
                  "messaging app, the map is weak evidence." if q else "")
        res.finding(
            ELA_WORDING, "info",
            f"{ELA_TERMINAL_LINE}. Re-saved at q{m['resave_quality']}; the hottest regions are listed with the metrics. "
            "Bright regions only show areas that recompress differently - edits, text, sharp edges and noise all do."
            + caveat,
            confidence="possible",
            criterion="error level analysis (JPEG re-save at fixed quality and difference map): heuristic, not proof",
            tags=["info", "heuristic", "context_only"],
        )
        return res
