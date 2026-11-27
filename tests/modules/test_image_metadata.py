"""image_metadata (P259): EXIF/XMP/IPTC/GPS offline, stdlib reader until core/sandbox.py exists.

c8: the research JPEG prototype with GPS (S 23 33 1 / W 46 38 2 -> -23.550278,-46.633889), a decompression-bomb
PNG and a truncated file are generated here; tests/fixtures/image_metadata/ holds the prep's synthetic images
(Pillow/stdlib builders, documentation values only) and recorded Pillow sandbox-child dumps. Offline module: the
networked failure cases map to refused, malformed, oversized and unreadable inputs; no request is ever made.
"""

from __future__ import annotations

import json
import os
import struct
import sys
import zlib
from pathlib import Path


from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.geo_image_meta import image_metadata as im
from v3lum.modules.geo_image_meta.image_metadata import ImageMetadata

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "image_metadata"


# ---- synthetic builders (c8) -------------------------------------------------------------------


def _ifd(entries: list[tuple[int, int, int, bytes]], base: int, nxt: int = 0) -> tuple[bytes, bytes]:
    """Little-endian IFD at offset ``base``: (ifd bytes, value area appended right after it)."""
    head = struct.pack("<H", len(entries))
    area = b""
    data_off = base + 2 + 12 * len(entries) + 4
    body = b""
    for tag, typ, count, raw in entries:
        if len(raw) <= 4:
            body += struct.pack("<HHI", tag, typ, count) + raw.ljust(4, b"\x00")
        else:
            body += struct.pack("<HHII", tag, typ, count, data_off + len(area))
            area += raw + (b"\x00" if len(raw) % 2 else b"")
    return head + body + struct.pack("<I", nxt), area


def _ascii(s: str) -> bytes:
    return s.encode() + b"\x00"


def _rat(*pairs: tuple[int, int]) -> bytes:
    return b"".join(struct.pack("<II", n, d) for n, d in pairs)


def gps_jpeg(width: int = 640, height: int = 480) -> bytes:
    """The research prototype: Make/Model, DateTimeOriginal with offset, GPS S 23 33 1 / W 46 38 2."""
    ifd0_off = 8
    ifd0_entries = 4
    ifd0_len = 2 + 12 * ifd0_entries + 4
    make, model = _ascii("V3LUMCam"), _ascii("Model-X")
    exif_off = ifd0_off + ifd0_len + len(make) + len(make) % 2 + len(model) + len(model) % 2
    exif_entries = [(36867, 2, 20, _ascii("2026:03:01 14:22:00")), (36881, 2, 7, _ascii("-03:00"))]
    exif_len = 2 + 12 * len(exif_entries) + 4 + 20 + 8
    gps_off = exif_off + exif_len
    ifd0, area0 = _ifd([(271, 2, len(make), make), (272, 2, len(model), model), (34665, 4, 1, struct.pack("<I", exif_off)),
                        (34853, 4, 1, struct.pack("<I", gps_off))], ifd0_off)
    exif, area1 = _ifd(exif_entries, exif_off)
    gps, area2 = _ifd([(1, 2, 2, b"S\x00"), (2, 5, 3, _rat((23, 1), (33, 1), (1, 1))), (3, 2, 2, b"W\x00"),
                       (4, 5, 3, _rat((46, 1), (38, 1), (2, 1)))], gps_off)
    tiff = b"II*\x00" + struct.pack("<I", ifd0_off) + ifd0 + area0 + exif + area1 + gps + area2
    app1 = b"Exif\x00\x00" + tiff
    sof = b"\x08" + struct.pack(">HH", height, width) + b"\x01\x01\x11\x00"
    return (b"\xff\xd8" + b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1
            + b"\xff\xc0" + struct.pack(">H", len(sof) + 2) + sof
            + b"\xff\xda" + struct.pack(">H", 8) + b"\x01\x01\x00\x00\x3f\x00" + b"\x00" * 16 + b"\xff\xd9")


def png_header(width: int, height: int) -> bytes:
    """A PNG that only declares its size (the decompression-bomb case: nothing to decode)."""
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)

    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)

    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IEND", b"")


def run(path: Path, **kw):
    http = FakeHttp()
    res = run_module(ImageMetadata, Entity.make(T.FILE, str(path)), http, **kw)
    assert http.calls == [] and res.requests == 0  # c1/c2: offline, never fetches anything
    return res


def write(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


# ---- c4/c5/c7: the research prototype ------------------------------------------------------------


def test_research_prototype_gps_and_camera(tmp_path):
    res = run(write(tmp_path, "proto.jpg", gps_jpeg()))
    assert res.status is Status.OK
    assert res.attributes["image_summary"] == "taken 2026-03-01 14:22 (UTC-03:00) with V3LUMCam Model-X, GPS present"
    assert res.attributes["camera_make"] == "V3LUMCam" and res.attributes["camera_model"] == "Model-X"
    assert res.attributes["taken_at"] == "2026-03-01T14:22:00-03:00"
    [pivot] = res.pivots
    assert pivot.entity.type is T.COORDINATES and pivot.entity.value == "-23.550278,-46.633889"
    assert pivot.relation == "photo_taken_at" and pivot.expand is False  # c5: never auto-expanded
    assert "no automatic geocoding" in pivot.note
    titles = [f.title for f in res.findings]
    assert titles[0] == "Image metadata" and "GPS location recorded in the image" in titles
    gps = next(f for f in res.findings if f.title.startswith("GPS"))
    assert "privacy" in gps.tags and "-23.55" not in gps.description  # coordinates stay in the pivot/case only
    assert all(f.severity.label == "info" for f in res.findings)
    assert "EXIF can be edited" in res.findings[0].description  # c7


def test_prep_fixture_images(tmp_path):
    res = run(FIX / "ok_gps_motorola.jpg")  # big-endian TIFF
    assert [p.entity.value for p in res.pivots] == ["-23.550278,-46.633889"]
    for name in ("png_exif.png", "webp_exif.webp", "xmp_iptc.jpg"):
        r = run(FIX / name)
        assert r.status is Status.OK and r.pivots and r.attributes["camera_make"] == "V3LUMCam", name


def test_editing_software_thumbnail_and_change_after_capture():
    res = run(FIX / "edited_thumb_mismatch.jpg")
    titles = {f.title for f in res.findings}
    assert {"Editing software named in the image metadata", "Possible crop/edit: EXIF thumbnail aspect ratio differs from the main image",
            "Image changed after capture"} <= titles
    for f in res.findings:
        if f.title != "Image metadata" and not f.title.startswith("GPS"):
            assert f.severity.label == "info" and "edited_image" in f.tags  # c4: INFO context, not a verdict
    assert res.attributes["image_metadata"]["editing_software"] == "Adobe Photoshop"


def test_missing_exif_is_normal_and_never_a_finding():
    for name in ("no_exif.png", "stripped.jpg"):
        res = run(FIX / name)
        assert res.attributes["image_summary"] == "no EXIF metadata"
        assert [f.title for f in res.findings] == ["Image metadata"]
        assert "Missing EXIF is normal" in res.findings[0].description and not res.pivots


# ---- c3: bombs, truncated and malformed files -------------------------------------------------------


def test_decompression_bomb_is_an_error_with_a_clear_reason(tmp_path):
    res = run(write(tmp_path, "bomb.png", png_header(30000, 30000)))
    assert res.status is Status.ERROR and res.reason_code == "error"
    assert "decompression bomb refused" in res.error and "900,000,000 pixels" in res.error
    assert run(FIX / "bomb.png").status is Status.ERROR


def test_truncated_file_is_an_error(tmp_path):
    data = gps_jpeg()
    res = run(write(tmp_path, "trunc.jpg", data[: len(data) // 2]))
    assert res.status is Status.ERROR and "truncated" in res.error
    assert run(FIX / "truncated.jpg").status is Status.ERROR


def test_malformed_exif_and_unsafe_xmp_are_anomalies_not_crashes():
    res = run(FIX / "malformed_exif.jpg")
    assert res.status is Status.OK and res.attributes["image_metadata"]["anomalies"]
    res = run(FIX / "xmp_doctype.jpg")
    assert any("unsafe XMP refused" in a for a in res.attributes["image_metadata"]["anomalies"])


def test_heic_needs_the_exifread_extra_in_the_sandbox():
    res = run(FIX / "heic_ftyp_only.heic")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "package" and "ExifRead" in res.error


def test_not_an_image_and_special_files_are_not_applicable(tmp_path):
    res = run(write(tmp_path, "notes.txt", b"hello"))
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    fifo = tmp_path / "pipe.jpg"
    os.mkfifo(fifo)
    http = FakeHttp()
    assert run_module(ImageMetadata, Entity(T.FILE, str(fifo)), http).status is Status.SKIPPED and http.calls == []


# ---- c2: the sandbox path (fake core sandbox returning a recorded Pillow child dump) ------------------


class FakeSandbox:
    def __init__(self, result=None, ok=True, reason_code=None):
        self.calls = []
        self.out = {"ok": ok, "result": result, "error": None if ok else "boom", "reason_code": reason_code, "isolation": "test"}

    def run_sandboxed(self, target, path, *, args=None, **limits):
        self.calls.append((target, path, args, limits))
        return self.out


def test_pillow_runs_only_in_the_sandbox(monkeypatch):
    sb = FakeSandbox(module_fixture("image_metadata", "pillow_ok_gps.json"))
    monkeypatch.setattr(im, "core_sandbox", lambda: sb)
    res = run(FIX / "ok_gps.jpg")
    assert res.status is Status.OK and res.pivots and sb.calls
    target, _path, args, limits = sb.calls[0]
    assert target == "v3lum.modules.geo_image_meta.image_metadata:pillow_image_child"
    assert args == {"max_pixels": im.IMAGE_MAX_PIXELS} and limits["mem_bytes"] == 1 << 30 and limits["max_output"] == 1 << 20
    assert res.raw["parser"].startswith("sandbox")
    bomb = FakeSandbox(module_fixture("image_metadata", "pillow_bomb.json"))
    monkeypatch.setattr(im, "core_sandbox", lambda: bomb)
    assert "decompression bomb refused" in run(FIX / "bomb.png").error
    dead = FakeSandbox(ok=False, reason_code="timeout")
    monkeypatch.setattr(im, "core_sandbox", lambda: dead)
    res = run(FIX / "ok_gps.jpg")
    assert res.status is Status.ERROR and res.reason_code == "timeout"


def test_letterboxed_thumbnail_from_the_sandbox_is_a_note():
    raw = module_fixture("image_metadata", "pillow_edited_thumb_mismatch.json")
    norm = im.normalize_image_meta(raw)
    assert norm["thumbnail"]["status"] in ("mismatch", "letterboxed", "rotated")
    assert im.thumbnail_check(3000, 2000, 160, 120, bbox=[0, 7, 160, 113])["status"] == "letterboxed"
    assert im.thumbnail_check(3000, 2000, 120, 160)["status"] == "mismatch"
    assert im.thumbnail_check(3000, 2000, 120, 180)["status"] == "rotated"


# ---- helpers -------------------------------------------------------------------------------------


def test_gps_decimal_and_no_fix():
    assert im.gps_decimal([[23, 1], [33, 1], [1, 1]], "S", "lat") == (-23.550278, [])
    assert im.gps_decimal([[46, 1], [38, 1], [2, 1]], "W", "lon")[0] == -46.633889
    assert im.gps_decimal([[91, 1], [0, 1], [0, 1]], "N", "lat")[0] is None
    raw = {"exif": {"gps": {"1": "N", "2": [[0, 1], [0, 1], [0, 1]], "3": "E", "4": [[0, 1], [0, 1], [0, 1]]}, "ifd0": {"271": "X"}}}
    norm = im.normalize_image_meta(raw)
    assert norm["gps"] is None and not norm["pivots"] and any("0,0" in n for n in norm["notes"])


def test_export_view_strips_gps_serials_and_owner_unless_opted_in():
    attrs = {"camera_make": "V3LUMCam", "camera_serial": "SN-0000-EXAMPLE", "image_owner": {"artist": "Fulano de Tal"},
             "gps_altitude_m": 760.0, "taken_at": "2026-03-01T14:22:00-03:00"}
    view = im.export_view(attrs)
    assert set(view) == {"camera_make", "taken_at"}
    assert im.export_view(attrs, case_opt_in=True) == attrs


def test_no_face_processing_library_is_imported():
    source = Path(im.__file__).read_text(encoding="utf-8")
    for lib in im.FACE_LIBRARIES:
        assert f"import {lib}" not in source and lib not in sys.modules or lib == "cv2"
    assert "import cv2" not in source and "face_recognition" not in json.dumps(sorted(sys.modules))


def test_contract_metadata():
    assert ImageMetadata.disclosure == "none" and ImageMetadata.terms == "open" and ImageMetadata.default_enabled is True
    assert ImageMetadata.hosts == () and ImageMetadata.max_tlp.value_str == "red"
