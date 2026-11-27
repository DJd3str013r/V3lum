"""image_ela (P264, batch p3-G12-1): error level analysis of JPEGs in the file-analysis sandbox.

The synthetic images are generated here (FC6): a twice-compressed 'camera original', the same image with a freshly
pasted block, and a lossless PNG that is skipped. The sandbox is simulated by running the child function in the test
process (the core sandbox does not exist in this build; the module itself never runs Pillow in process).
"""

from __future__ import annotations

import io
import json

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.core.models import Status
from v3lum.modules.geo_image_meta import image_ela as IE
from v3lum.modules.geo_image_meta.image_ela import ImageEla

PIL = pytest.importorskip("PIL")
from PIL import Image, ImageDraw  # noqa: E402

W, H = 256, 192
EDIT_BOX = (160, 32, 224, 96)


def _jpeg(im: Image.Image, q: int = 90) -> bytes:
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=q)
    return buf.getvalue()


def _scene() -> Image.Image:
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


@pytest.fixture()
def images(tmp_path):
    base = Image.open(io.BytesIO(_jpeg(_scene()))).convert("RGB")
    original = _jpeg(base)  # saved twice at q90: converged background
    edited = Image.open(io.BytesIO(original)).convert("RGB")
    d = ImageDraw.Draw(edited)
    x0, y0, x1, y1 = EDIT_BOX
    d.rectangle(EDIT_BOX, fill=(245, 245, 245))
    for yy in range(y0 + 2, y1 - 2, 4):  # sharp, high-frequency pasted content (typed digits, ruling)
        d.line((x0 + 2, yy, x1 - 2, yy), fill=(180, 190, 200), width=1)
    d.text((x0 + 4, y0 + 6), "R$ 9.999,00", fill=(10, 10, 10))
    d.text((x0 + 4, y0 + 30), "12/2026 OK", fill=(10, 10, 10))
    d.line((x0 + 4, y1 - 10, x1 - 4, y1 - 10), fill=(200, 0, 0), width=2)
    paths = {"original": tmp_path / "original.jpg", "edited": tmp_path / "edited.jpg", "png": tmp_path / "receipt.png",
             "truncated": tmp_path / "truncated.jpg"}
    paths["original"].write_bytes(original)
    paths["edited"].write_bytes(_jpeg(edited))
    buf = io.BytesIO()
    _scene().save(buf, "PNG")
    paths["png"].write_bytes(buf.getvalue())
    paths["truncated"].write_bytes(original[:200])
    return paths


@pytest.fixture()
def sandbox(monkeypatch):
    """Simulated core sandbox: runs the named child on the file bytes and returns the p1-G12-1 contract dict."""
    calls = []

    def fake_sandbox_run(target, path, *, args=None, **limits):
        calls.append({"target": target, "limits": limits})
        module, _, func = target.partition(":")
        assert module == IE.__name__ and func == "ela_child"
        data = open(path, "rb").read()
        result = IE.ela_child(data, **(args or {}))
        json.dumps(result)  # the child's output must be plain JSON (1 MB cap in the real sandbox)
        return {"ok": True, "result": result, "error": None, "reason_code": None, "elapsed_s": 0.01, "isolation": "test"}

    monkeypatch.setattr(IE, "sandbox_run", fake_sandbox_run)
    return calls


def run(path):
    return run_module(ImageEla, f"file:{path}", FakeHttp())


def test_original_and_edited_jpeg_give_heuristic_metrics(images, sandbox):
    orig = run(images["original"])
    edit = run(images["edited"])
    assert orig.status is Status.OK and edit.status is Status.OK
    mo, me = orig.attributes["ela_metrics"], edit.attributes["ela_metrics"]
    assert mo["heuristic"] == "not proof of tampering" and mo["resave_quality"] == 90
    assert mo["width"] == W and mo["height"] == H and mo["jpeg_quality_estimate"] == 90
    # the pasted block recompresses differently: higher max error and region ratio, hottest tile inside the box
    assert me["max"] > mo["max"] and me["region_ratio"] > mo["region_ratio"]
    box = me["hot_regions"][0]["box"]
    assert 160 / W - 0.13 <= box[0] <= 224 / W and 32 / H - 0.13 <= box[1] <= 96 / H
    # FC5: one INFO finding, heuristic wording, never scored; the terminal line is the only summary
    f = edit.findings[0]
    assert f.title == "Error level analysis: heuristic, not proof of tampering"
    assert f.severity.name == "INFO" and {"heuristic", "context_only"} <= set(f.tags)
    assert edit.attributes["ela_summary"] == "ELA map in the HTML report (heuristic, not proof)"
    assert "tamper" not in json.dumps(list(edit.attributes)).lower()
    assert edit.raw["ela_map_png"].startswith("data:image/png;base64,")
    assert "ela_map_png" not in edit.attributes  # the map never reaches the terminal
    assert sandbox[0]["limits"]["mem_bytes"] == 1 << 30 and sandbox[0]["limits"]["max_input"] == 100 * 1024 * 1024


def test_png_is_skipped_as_lossless_before_any_decoding(images, sandbox):
    res = run(images["png"])
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert res.error == "ELA not meaningful for lossless images"
    assert sandbox == []  # nothing reached the sandbox


def test_no_core_sandbox_is_unavailable_never_computed_in_process(images, monkeypatch):
    def boom(*a, **k):  # pragma: no cover - must never run in process
        raise AssertionError("Pillow must never run in the V3LUM process")

    monkeypatch.setattr(IE, "ela_child", boom)
    res = run(images["original"])  # the real sandbox_run: this build has no core/sandbox.py
    assert res.status is Status.UNAVAILABLE and res.reason_code == "package"
    assert "sandbox" in res.error


def test_truncated_jpeg_is_a_child_error_never_empty(images, sandbox):
    res = run(images["truncated"])
    assert res.status is Status.ERROR


def test_sandbox_timeout_and_malformed_output_are_errors(images, monkeypatch):
    monkeypatch.setattr(IE, "sandbox_run", lambda *a, **k: {"ok": False, "reason_code": "timeout", "error": "wall timeout"})
    res = run(images["original"])
    assert res.status is Status.ERROR and res.reason_code == "timeout"
    monkeypatch.setattr(IE, "sandbox_run", lambda *a, **k: {"ok": True, "result": {"histogram": [1, 2], "tile_means": "x"}})
    res2 = run(images["original"])
    assert res2.status is Status.ERROR and "could not verify" in res2.error
    monkeypatch.setattr(IE, "sandbox_run", lambda *a, **k: {"ok": True, "result": {"skipped": "not_jpeg", "format_sniffed": "png"}})
    res3 = run(images["original"])
    assert res3.status is Status.SKIPPED and res3.error == IE.ELA_LOSSLESS_REASON


def test_oversized_image_is_refused_before_decoding():
    # a JPEG header claiming 10000 x 5000 pixels (50 MP): refused from the SOF segment, nothing decoded
    sof = b"\xff\xc0\x00\x11\x08" + (5000).to_bytes(2, "big") + (10000).to_bytes(2, "big") + b"\x03" + b"\x01\x11\x00\x02\x11\x01\x03\x11\x01"
    data = b"\xff\xd8" + sof + b"\xff\xd9"
    out = IE.ela_child(data)
    assert "skipped" in out and "40 MP" in out["skipped"]


def test_pure_helpers():
    assert IE.sniff_image_format(b"\x89PNG\r\n\x1a\n" + b"0" * 8) == "png"
    assert IE.ela_applicability("gif") == IE.ELA_LOSSLESS_REASON
    assert IE.ela_applicability("heic") == "ELA is implemented for JPEG only"
    assert IE.png_data_uri(b"not a png") is None
    assert IE.normalize_ela_child_output("not json")["errors"]


def test_metadata_matches_the_council_decision():
    assert ImageEla.disclosure == "none" and ImageEla.terms == "open" and ImageEla.hosts == ()
    assert ImageEla.default_enabled is False and ImageEla.requires_packages == ("PIL",)
    assert ImageEla.trust_tier == "n/a" and ImageEla.max_tlp.name == "RED"
