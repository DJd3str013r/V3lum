"""qr_decode (P261): zxing-cpp in the file-analysis sandbox; URL/PIX/boleto/text routing. Offline.

c6 fixtures (tests/fixtures/qr_decode/): QR PNGs made once with segno 1.6.6 (dev-only) and an ITF boleto PNG from
an own stdlib encoder (benign URL, the BCB example PIX BR Code with CRC 1D3D, a tampered and a dynamic PIX, a
synthetic Banco do Brasil barcode, IOC text, Wi-Fi), a multi-code image, a blank image and an oversized header;
zxing_*.json are the decoder child's recorded output (zxing-cpp 3.2.0) for each. Without the core sandbox the
module reports UNAVAILABLE 'package'; a fake sandbox returns the recorded dumps for the module tests.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import v3lum.core.module as core_module
from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Status
from v3lum.modules.geo_image_meta import image_metadata as im
from v3lum.modules.geo_image_meta import qr_decode as q
from v3lum.modules.geo_image_meta.qr_decode import QrDecode

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "qr_decode"


class FakeSandbox:
    def __init__(self, result, ok=True, reason_code=None):
        self.calls = []
        self.out = {"ok": ok, "result": result, "error": None if ok else "killed", "reason_code": reason_code, "isolation": "test"}

    def run_sandboxed(self, target, path, *, args=None, **limits):
        self.calls.append((target, path, args, limits))
        return self.out


@pytest.fixture
def extras(monkeypatch):
    real = core_module.package_available
    monkeypatch.setattr(core_module, "package_available", lambda name: name in ("zxingcpp", "PIL") or real(name))


def run(name, dump=None, monkeypatch=None, **kw):
    if dump is not None:
        sb = dump if isinstance(dump, FakeSandbox) else FakeSandbox(module_fixture("qr_decode", dump))
        monkeypatch.setattr(im, "core_sandbox", lambda: sb)
    http = FakeHttp()
    res = run_module(QrDecode, Entity.make(T.FILE, str(FIX / name)), http, **kw)
    assert http.calls == [] and res.requests == 0  # c1: no network at all
    return res


def pivots(res):
    return {(p.entity.type.value, p.entity.value): p for p in res.pivots}


# ---- c2/c3: extra and sandbox -----------------------------------------------------------------------


def test_missing_extra_is_unavailable_package():
    res = run("url.png")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "package"


def test_without_the_core_sandbox_nothing_is_decoded_in_process(extras):
    res = run("url.png")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "package" and "sandbox" in res.error


def test_sandbox_call_and_caps(extras, monkeypatch):
    sb = FakeSandbox(module_fixture("qr_decode", "zxing_url.json"))
    res = run("url.png", sb, monkeypatch)
    assert res.status is Status.OK
    target, _path, args, limits = sb.calls[0]
    assert target == "v3lum.modules.geo_image_meta.qr_decode:zxing_child"
    assert args == {"max_pixels": im.IMAGE_MAX_PIXELS, "payload_cap": 4096} and limits["mem_bytes"] == 1 << 30


def test_sandbox_failures_are_could_not_verify(extras, monkeypatch):
    res = run("url.png", FakeSandbox(None, ok=False, reason_code="timeout"), monkeypatch)
    assert res.status is Status.ERROR and res.reason_code == "timeout"
    res = run("oversized.png", "zxing_oversized.json", monkeypatch)
    assert res.status is Status.ERROR and "decompression bomb refused" in res.error


# ---- c4/c5: routing and display -------------------------------------------------------------------


def test_url_is_a_pivot_never_fetched_and_defanged(extras, monkeypatch):
    res = run("url.png", "zxing_url.json", monkeypatch)
    p = pivots(res)[("url", "https://example.com/v3lum-qr-fixture?ref=test")]
    assert p.relation == "qr_payload" and p.expand is True and "never fetched" in p.note  # passive scan
    assert res.attributes["qr_codes"][0]["display"] == "QR -> URL hxxps://example[.]com/v3lum-qr-fixture?ref=test"
    assert "clean" not in json.dumps(res.attributes)


def test_url_is_not_expanded_in_a_light_scan(extras, monkeypatch):
    res = run("url.png", "zxing_url.json", monkeypatch, options=ScanOptions(mode=Opsec.LIGHT))
    assert pivots(res)[("url", "https://example.com/v3lum-qr-fixture?ref=test")].expand is False


def test_pix_static_and_tampered(extras, monkeypatch):
    ok = run("pix_static.png", "zxing_pix_static.json", monkeypatch)
    assert ok.status is Status.OK and ok.attributes["pix_key_type"] == "evp"
    assert "CRC ok" in ok.attributes["qr_codes"][0]["display"]
    assert not [f for f in ok.findings if f.severity.label != "info"]
    bad = run("pix_bad_crc.png", "zxing_pix_bad_crc.json", monkeypatch)
    finding = next(f for f in bad.findings if f.title.startswith("PIX QR payload altered"))
    assert finding.severity.label == "medium" and "tampering_suspected" in finding.tags and finding.criterion


def test_pix_dynamic_location_host_is_never_fetched(extras, monkeypatch):
    res = run("pix_dynamic.png", "zxing_pix_dynamic.json", monkeypatch)
    p = pivots(res)[("domain", "pix.example.com")]
    assert p.expand is False and "never fetched" in p.note


def test_boleto_itf_goes_to_the_p233_parser(extras, monkeypatch):
    res = run("boleto_itf.png", "zxing_boleto_itf.json", monkeypatch)
    display = res.attributes["qr_codes"][0]["display"]
    assert display.startswith("ITF -> Boleto: check digits OK") and "2026-12-15" in display
    assert ("boleto", "00194166100000123450000001234567000000000117") in pivots(res)


def test_text_goes_to_the_ioc_extractor_personal_values_not_expanded(extras, monkeypatch):
    res = run("text_ioc.png", "zxing_text_ioc.json", monkeypatch)
    p = pivots(res)
    assert p[("email", "suporte@example.com")].expand is False
    assert any(t == "url" or t == "domain" for t, _v in p)


def test_multi_code_image_reports_every_code(extras, monkeypatch):
    res = run("multi.png", "zxing_multi.json", monkeypatch)
    assert [c["kind"] for c in res.attributes["qr_codes"]] == ["url", "text", "boleto"]
    assert res.attributes["qr_summary"] == "3 code(s) decoded: boleto, text, url"


def test_wifi_password_is_never_kept(extras, monkeypatch):
    res = run("wifi.png", "zxing_wifi.json", monkeypatch)
    blob = json.dumps([res.attributes, res.raw, [f.description for f in res.findings]])
    assert "not-a-real-secret-123" not in blob and "password present, not kept" in blob


def test_no_code_is_never_clean(extras, monkeypatch):
    res = run("no_code.png", "zxing_no_code.json", monkeypatch)
    assert res.status is Status.EMPTY and res.error == "no QR/barcode found"


def test_not_an_image_is_not_applicable(extras):
    assert run("not_image.txt").status is Status.SKIPPED


def test_normalizer_on_every_recorded_dump():
    for path in sorted(FIX.glob("zxing_*.json")):
        norm = q.normalize_zxing_results(json.loads(path.read_text()))
        assert norm["status"] in ("ok", "empty", "error"), path.name
        assert "clean" not in json.dumps(norm, default=str).lower()
    assert q.normalize_zxing_results(["junk"])["status"] == "error"
    assert q.classify_qr_payload("otpauth://totp/x?secret=ABC")["value"] is None
    assert q.parse_wifi_qr("WIFI:S:Net;T:WPA;P:pw;;") == {"kind": "wifi", "ssid": "Net", "auth": "WPA", "hidden": False, "password_present": True}


def test_contract_metadata():
    assert QrDecode.disclosure == "none" and QrDecode.default_enabled is True
    assert QrDecode.requires_packages == ("zxingcpp", "PIL") and QrDecode.max_tlp.value_str == "red"
