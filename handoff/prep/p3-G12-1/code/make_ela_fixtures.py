"""Generate the synthetic image_ela fixtures (P264-FC6) with Pillow (run with python3 -I).

usage: cd code && python3 -I make_ela_fixtures.py   (then python3 -I build_fixtures.py keeps them)

Writes to ../fixtures:
- image_ela__original_q90.jpg   synthetic scene (gradient + shapes), saved once at q90, then
                                re-saved at q90 (a twice-compressed 'camera original')
- image_ela__edited_q90.jpg     the same twice-compressed image with a freshly drawn block pasted
                                in the box EDIT_BOX, saved once more at q90
- image_ela__lossless.png       small PNG that must be SKIPPED (not_applicable)
- image_ela__truncated.jpg      first 200 bytes of the original (jpeg_info must not crash)
- image_ela__child_original.json / _edited.json / _png_skipped.json   outputs of
  ela_child_reference.py on those files (ELA PNG thumbnail kept small)
- image_ela__child_malformed.json, image_ela__child_error.json   hand-written bad child outputs
and adds their entries to fixtures/MANIFEST.json. No real photo or person is involved.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # our own code dir only
import ela_child_reference as child  # noqa: E402
from PIL import Image, ImageDraw  # noqa: E402

FIX = Path(__file__).resolve().parent.parent / "fixtures"
W, H = 256, 192
SRC_Q = 90  # 'camera' quality; ELA re-saves at q90 (P264-FC4), so a twice-saved background converges
EDIT_BOX = (160, 32, 224, 96)  # x0, y0, x1, y1 -> grid tiles rows 1-3, cols 5-6 (8x8 grid of 32x24 px)


def scene():
    im = Image.new("RGB", (W, H))
    px = im.load()
    for y in range(H):
        for x in range(W):
            px[x, y] = (40 + x * 160 // W, 60 + y * 120 // H, 120 + ((x + y) % 64))
    d = ImageDraw.Draw(im)
    d.ellipse((20, 30, 110, 120), fill=(200, 180, 60), outline=(20, 20, 20), width=3)
    d.rectangle((120, 120, 230, 175), fill=(30, 90, 160), outline=(250, 250, 250), width=2)
    for i in range(0, W, 16):
        d.line((i, 0, i, 12), fill=(255, 255, 255), width=1)
    return im


def jpeg_bytes(im, q):
    import io
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=q)
    return buf.getvalue()


def main():
    import io
    base = Image.open(io.BytesIO(jpeg_bytes(scene(), SRC_Q))).convert("RGB")
    original = jpeg_bytes(base, SRC_Q)
    edited_im = Image.open(io.BytesIO(original)).convert("RGB")
    d = ImageDraw.Draw(edited_im)
    x0, y0, x1, y1 = EDIT_BOX
    d.rectangle(EDIT_BOX, fill=(245, 245, 245))
    for yy in range(y0 + 2, y1 - 2, 4):  # sharp, high-frequency pasted content (typed digits, ruling)
        d.line((x0 + 2, yy, x1 - 2, yy), fill=(180, 190, 200), width=1)
    d.text((x0 + 4, y0 + 6), "R$ 9.999,00", fill=(10, 10, 10))
    d.text((x0 + 4, y0 + 30), "12/2026 OK", fill=(10, 10, 10))
    d.line((x0 + 4, y1 - 10, x1 - 4, y1 - 10), fill=(200, 0, 0), width=2)
    edited = jpeg_bytes(edited_im, SRC_Q)
    png_buf = io.BytesIO()
    scene().resize((64, 48)).save(png_buf, "PNG", optimize=True)
    png = png_buf.getvalue()

    files = {
        "image_ela__original_q90.jpg": (original, "original", "twice-compressed synthetic scene at q90"),
        "image_ela__edited_q90.jpg": (edited, "edited", "block pasted at box %r, saved once more at q90" % (EDIT_BOX,)),
        "image_ela__lossless.png": (png, "png_skip", "lossless PNG -> SKIPPED not_applicable"),
        "image_ela__truncated.jpg": (original[:200], "malformed", "first 200 bytes of the original JPEG"),
    }
    outputs = {
        "image_ela__child_original.json": (child.ela(original, png_max_width=64), "child_ok",
                                           "ela_child_reference.py on the original (64 px ELA PNG)"),
        "image_ela__child_edited.json": (child.ela(edited, png_max_width=64), "child_ok_edited",
                                         "ela_child_reference.py on the edited JPEG (64 px ELA PNG)"),
        "image_ela__child_png_skipped.json": (child.ela(png), "child_skipped", "ela_child_reference.py on the PNG"),
        "image_ela__child_malformed.json": ({"_synthetic": "histogram with 255 bins and no tile means",
                                             "format_sniffed": "jpeg", "width": 4, "height": 4, "grid": 2,
                                             "histogram": [16] + [0] * 254, "tile_means": None},
                                            "child_malformed", "hand-written invalid child output"),
        "image_ela__child_error.json": ({"_synthetic": "child failure report",
                                         "error": "cannot identify image file"},
                                        "child_error", "hand-written child error output"),
    }
    entries = []
    for name, (data, case, note) in files.items():
        (FIX / name).write_bytes(data)
        entries.append({"file": name, "module": "image_ela", "case": case, "provenance": "synthetic",
                        "source": "code/make_ela_fixtures.py (Pillow %s)" % Image.__version__ if hasattr(Image, "__version__")
                        else "code/make_ela_fixtures.py", "note": note, "bytes": len(data)})
    for name, (obj, case, note) in outputs.items():
        text = json.dumps(obj, indent=1) + "\n"
        (FIX / name).write_text(text)
        entries.append({"file": name, "module": "image_ela", "case": case, "provenance": "synthetic",
                        "source": "code/make_ela_fixtures.py", "note": note, "bytes": len(text.encode())})
    man_path = FIX / "MANIFEST.json"
    man = json.loads(man_path.read_text()) if man_path.exists() else {"fixtures": []}
    man["fixtures"] = sorted([e for e in man.get("fixtures", []) if e.get("module") != "image_ela"] + entries,
                             key=lambda e: e["file"])
    man_path.write_text(json.dumps(man, indent=1, ensure_ascii=False) + "\n")
    eo, ee = outputs["image_ela__child_original.json"][0], outputs["image_ela__child_edited.json"][0]
    import parsers as p
    so, se = p.ela_summary(eo), p.ela_summary(ee)
    print("original", {k: so[k] for k in ("mean", "max", "region_ratio", "tile_max")}, so["hot_regions"][0])
    print("edited  ", {k: se[k] for k in ("mean", "max", "region_ratio", "tile_max")}, se["hot_regions"][0])
    print("quality estimate", eo["jpeg_quality_estimate"], ee["jpeg_quality_estimate"])


if __name__ == "__main__":
    main()
