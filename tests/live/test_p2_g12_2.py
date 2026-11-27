"""Live checks of batch p2-G12-2 (id_timestamp_decoders, mac_oui, mac_oui_online, jwt_analysis, image_ocr,
script_decoder); run with V3LUM_LIVE=1.

Four modules are offline algorithms with no source at all (id_timestamp_decoders, jwt_analysis, script_decoder) or
whose only network traffic is the dataset manager (mac_oui: the IEEE listings; image_ocr: the pinned tessdata_fast
models). mac_oui_online is the opt-in prefix relay: it is checked with the unassigned MA-L prefix 004A00 (never a
full MAC). A 403/429/challenge from this datacenter egress is an acceptable outcome when it is reported as could
not verify (BLOCKED/RATE_LIMITED/ERROR/UNAVAILABLE, never EMPTY): those checks skip with the reason.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from tests.fakes import make_ctx, run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.datasets import DatasetError
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.geo_image_meta import image_ocr as OCR
from v3lum.modules.geo_image_meta.image_ocr import ImageOcr
from v3lum.modules.utility import mac_oui as M
from v3lum.modules.utility.id_timestamp_decoders import IdTimestampDecoders
from v3lum.modules.utility.mac_oui import MacOui
from v3lum.modules.utility.mac_oui_online import MacOuiOnline

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = (Status.BLOCKED, Status.RATE_LIMITED, Status.ERROR, Status.UNAVAILABLE, Status.QUOTA)


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def test_mac_oui_with_the_live_ieee_listings():
    M._CACHE.update(key=None, index=None)
    res = run_module(MacOui, "mac_address:FC:FB:FB:01:FA:21", runtime=live_runtime())
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"could not verify from this egress: {res.status.value} {res.error[:120]}")
    assert res.status is Status.OK and res.attributes["mac_vendor"].startswith("Cisco")
    assert res.attributes["mac_oui"]["registry"] == "MA-L"
    ra = run_module(MacOui, "mac_address:70:B3:D5:0A:C1:23", runtime=live_runtime())
    assert ra.attributes["mac_oui"]["registry"] == "MA-S" and ra.attributes["mac_oui"]["bits"] == 36
    assert {d["name"] for d in res.datasets} >= set(M.LOOKUP_DATASETS)


def test_mac_oui_online_sends_only_the_prefix_of_an_unassigned_block():
    M._CACHE.update(key=None, index=None)
    rt = live_runtime()
    res = run_module(MacOuiOnline, "mac_address:00:4A:00:12:34:56", runtime=rt)
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"could not verify from this egress: {res.status.value} {res.error[:160]}")
    assert res.status in (Status.EMPTY, Status.OK)  # 004A00 is unassigned: macvendors 404 / maclookup found=false
    if res.status is Status.EMPTY:
        assert "unknown to" in res.error


def test_tessdata_models_download_pinned_and_module_reports_the_sandbox_gap(tmp_path):
    rt = live_runtime()
    ctx = make_ctx(ImageOcr, runtime=rt)
    try:
        folder = Path(ImageOcr.tessdata_dir(ctx))
    except DatasetError as exc:
        pytest.skip(f"could not verify from this egress: {exc}")
    for name, spec in OCR.OCR_MODELS.items():
        assert hashlib.sha256((folder / name).read_bytes()).hexdigest() == spec["sha256"]
    from PIL import Image, ImageDraw

    img = Image.new("L", (900, 80), 255)
    ImageDraw.Draw(img).text((10, 30), "https://atualiza-cadastro.example.com/login", fill=0)
    path = tmp_path / "shot.png"
    img.save(path)
    res = run_module(ImageOcr, Entity.make(T.FILE, str(path)), runtime=rt)
    # this build: no pytesseract in the venv and no core sandbox -> UNAVAILABLE 'package' (could not verify)
    assert res.status in (Status.UNAVAILABLE, Status.OK) and (res.status is Status.OK or res.reason_code == "package")


def test_offline_modules_need_no_network():
    res = run_module(IdTimestampDecoders, "url:https://x.com/example/status/1536682540265873408", runtime=live_runtime())
    assert res.attributes["created"] == "2022-06-14T12:10:42.437Z" and not res.hosts
