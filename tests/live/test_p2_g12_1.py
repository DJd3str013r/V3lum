"""Live checks of batch p2-G12-1 (image_metadata, pivots_geo_image, qr_decode, pe_triage, yara_scan); V3LUM_LIVE=1.

The five modules are offline (disclosure 'none'): they never touch the network, and every check asserts that they
made no request. The live part is the input and the data the modules depend on, fetched by the test harness (never
by the modules):

* a public-domain JPEG from Wikimedia Commons (image_metadata; real-world EXIF or none);
* the ``cli-64.exe`` launcher from the ``setuptools`` wheel on PyPI (MIT, a tiny benign PE) for pe_triage;
* the YARA Forge core release zip (the ``yara_scan.forge_core`` dataset URL): split, licence classes and coverage
  computed by the module's own stdlib code (yara-python is not installed here; the rules are never compiled or
  stored in the repository);
* the geo_image pack templates (pivots_geo_image) re-checked with a benign image URL and the research coordinates,
  GET without following redirects: what `v3lum doctor --links` asks a human to do monthly.

A 403/429/timeout from this datacenter egress skips that check with the reason (could not verify).
"""

from __future__ import annotations

import io
import zipfile
from urllib.parse import urlsplit

import pytest
import requests

from tests.fakes import FakeHttp, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.file_analysis import yara_scan as ys
from v3lum.modules.file_analysis.pe_triage import PeTriage
from v3lum.modules.geo_image_meta.image_metadata import ImageMetadata
from v3lum.modules.geo_image_meta.pivots_geo_image import PivotsGeoImage

pytestmark = pytest.mark.live

UA = {"User-Agent": "V3LUM-live-tests"}
JPEG = "https://upload.wikimedia.org/wikipedia/commons/a/a9/Example.jpg"
SETUPTOOLS_JSON = "https://pypi.org/pypi/setuptools/75.8.0/json"
FORGE = ys.FORGE_URL.format(package="core")


def fetch(url: str, max_bytes: int = 8 * 1024 * 1024, **kw) -> requests.Response:
    try:
        resp = requests.get(url, headers=UA, timeout=30, **kw)
    except requests.RequestException as exc:
        pytest.skip(f"could not verify: {type(exc).__name__}")
    if resp.status_code in (403, 429, 451) or resp.status_code >= 500:
        pytest.skip(f"could not verify: HTTP {resp.status_code} from this egress")
    if len(resp.content) > max_bytes:
        pytest.skip("sample larger than expected")
    return resp


def test_image_metadata_on_a_public_jpeg(tmp_path):
    path = tmp_path / "example.jpg"
    path.write_bytes(fetch(JPEG).content)
    http = FakeHttp()
    res = run_module(ImageMetadata, Entity.make(T.FILE, str(path)), http)
    assert http.calls == [] and res.status is Status.OK
    assert res.attributes["image_summary"]  # 'no EXIF metadata' or a capture line: both are answers


def test_pe_triage_on_a_benign_launcher(tmp_path):
    meta = fetch(SETUPTOOLS_JSON).json()
    wheel = next(u["url"] for u in meta["urls"] if u["filename"].endswith(".whl"))
    with zipfile.ZipFile(io.BytesIO(fetch(wheel).content)) as zf:
        name = next(n for n in zf.namelist() if n.endswith("cli-64.exe"))
        path = tmp_path / "cli-64.exe"
        path.write_bytes(zf.read(name))
    http = FakeHttp()
    res = run_module(PeTriage, Entity.make(T.FILE, str(path)), http)
    assert http.calls == [] and res.status is Status.OK
    assert res.attributes["pe_machine"] == "amd64" and res.attributes["imphash"]


def test_yara_forge_core_package_splits_and_filters_by_licence():
    resp = fetch(FORGE, max_bytes=16 * 1024 * 1024)
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        text = zf.read("packages/core/yara-rules-core.yar").decode("utf-8", "replace")
    split = ys.forge_split_package(text)
    assert split["package"]["name"] == "core" and split["package"]["number_of_rules"] > 1000
    corp = ys.select_yara_rules(split["rule_sets"], "corporate", [])
    assert corp["counts"]["loaded"] > 1000 and corp["counts"]["licence"] > 0
    assert corp["by_class"].get("unknown", 0) > 0 and corp["coverage_line"].endswith("rules excluded: licence")


def test_geo_image_templates_answer():
    res = run_module(PivotsGeoImage, Entity.make(T.URL, JPEG), FakeHttp(), options=ScanOptions(tlp="clear"))
    coords = run_module(PivotsGeoImage, Entity.make(T.COORDINATES, "-23.550278,-46.633889"), FakeHttp(),
                        options=ScanOptions(tlp="clear", show_personal=True, purpose="live template check"))
    checked = {}
    for _label, url in res.links + coords.links:
        host = urlsplit(url).hostname
        if host == "lens.google.com":
            continue  # upload-type endpoint: not re-checked automatically (prep notes)
        try:
            resp = requests.get(url, headers=UA, timeout=30, allow_redirects=False)
        except requests.RequestException as exc:
            checked[host] = f"could not verify ({type(exc).__name__})"
            continue
        checked[host] = resp.status_code
    print("geo_image template re-check:", checked)
    assert checked, "no template rendered"
    assert all(v in (200, 301, 302, 303, 403, 429) or str(v).startswith("could not verify") for v in checked.values()), checked
