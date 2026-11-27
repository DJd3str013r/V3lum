"""Reference ELA child for P264 image_ela (Pillow; port into the core/sandbox.py child).

usage: python3 -I ela_child_reference.py <image path>   -> one JSON object on stdout

What the V3LUM sandbox child must do (P264-FC2..FC4), shown with Pillow:
- read at most 100 MB (larger -> refuse), sniff the magic bytes; anything but JPEG -> {"skipped":
  ..., "format_sniffed": fmt} (PNG etc.: 'ELA not meaningful for lossless images', FC3);
- refuse images above 40 MP before decoding pixels (Image.MAX_IMAGE_PIXELS + size check);
- re-save at fixed quality 90 into memory (no file writes), ImageChops.difference, per-pixel
  error = max over R, G, B;
- emit aggregates only: 256-bin histogram, 8x8 tile means, size, the estimated source quality,
  and a contrast-stretched ELA PNG (<= 1024 px wide, <= 700 KB) as base64 for the HTML report.
The parent validates this JSON with parsers.normalize_ela_child_output (never trusts it) and
keeps the JSON under the 1 MB output cap. Nothing here decides 'tampered' (FC5).
"""
import base64
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # our own code dir only
import parsers as p  # noqa: E402

try:
    from PIL import Image, ImageChops, ImageStat
except ImportError:  # the V3LUM module reports UNAVAILABLE reason 'package' (optional extra)
    Image = None

GRID = 8
PNG_MAX_WIDTH = 1024


def ela(data, quality=p.ELA_RESAVE_QUALITY, grid=GRID, png_max_width=PNG_MAX_WIDTH):
    fmt = p.sniff_image_format(data[:64])
    if fmt != "jpeg":
        return {"skipped": "not_jpeg", "format_sniffed": fmt}
    if Image is None:
        return {"error": "Pillow not installed"}
    Image.MAX_IMAGE_PIXELS = p.ELA_MAX_PIXELS
    info = p.jpeg_info(data) or {}
    gate = p.ela_input_check(len(data), info.get("width"), info.get("height"))
    if gate:
        return {"skipped": gate, "format_sniffed": fmt}
    im = Image.open(io.BytesIO(data))
    im = im.convert("RGB")
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=quality)
    resaved = Image.open(io.BytesIO(buf.getvalue())).convert("RGB")
    diff = ImageChops.difference(im, resaved)
    r, g, b = diff.split()
    err = ImageChops.lighter(ImageChops.lighter(r, g), b)
    w, h = err.size
    grid = max(1, min(grid, w, h))
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
    q = p.jpeg_estimate_quality(info.get("dqt") or {})
    return {"format_sniffed": fmt, "quality_resave": quality, "width": w, "height": h, "grid": grid,
            "histogram": hist, "tile_means": tiles,
            "jpeg_quality_estimate": q["quality"] if q else None,
            "ela_png_b64": base64.b64encode(pbuf.getvalue()).decode("ascii")}


def main():
    path = Path(sys.argv[1])
    size = path.stat().st_size
    if size > p.ELA_MAX_INPUT_BYTES:
        print(json.dumps({"skipped": "input over 100 MB", "format_sniffed": None}))
        return
    print(json.dumps(ela(path.read_bytes()), separators=(",", ":")))


if __name__ == "__main__":
    main()
