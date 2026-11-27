"""apk_triage (P364): offline APK triage (AXML/ARSC/DEX/signing block on the safe ZIP reader).

Fixtures (c8): a minimal benign APK built in tests (v1 + v2 + v3 signed, tests/modules/test_p1_g12_1.py), a
banker-profile APK, malformed-zip variants (duplicate entries, bad central directory, bomb ratio, fake encryption
flag) and, in tests/fixtures/apk_triage/: two throwaway self-signed test certificates (keys discarded),
androguard's TestActivity.apk (Apache-2.0, a real debug-signed v1 APK) and assetlinks.json answers (a real
Google statement list, a malformed copy and an HTML page served with HTTP 200). Offline module: the HTTP failure
cases of networked modules map to refused, malformed and oversized inputs; the assetlinks parser (used on
archived copies, never fetched here) reports 403/404/429/redirects/HTML-in-200 as 'could not verify' markers.
"""

from __future__ import annotations

import hashlib
import json
import zlib
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from tests.modules import test_p1_g12_1 as B
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.file_analysis import apk_triage as at
from v3lum.modules.file_analysis import file_type_sniff as fts
from v3lum.modules.file_analysis.apk_triage import ApkTriage

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "apk_triage"
OFFICIAL = hashlib.sha256(B.cert("official")).hexdigest()
DEBUG = hashlib.sha256(B.cert("android_debug")).hexdigest()


def run(tmp_path, name, data, **kw):
    http = FakeHttp()
    res = run_module(ApkTriage, Entity.make(T.FILE, B.write(tmp_path, name, data)), http, **kw)
    assert http.calls == [] and res.requests == 0  # c1/c4: embedded hosts are never contacted
    return res


def titles(res):
    return {f.title: f for f in res.findings}


def pivots(res, relation=None):
    return {(p.entity.type.value, p.entity.value): p for p in res.pivots if relation is None or p.relation == relation}


def unsigned_apk(extra_files=()):
    man, arsc, dex = B.demo_parts()
    files = [("AndroidManifest.xml", man), ("resources.arsc", arsc), ("classes.dex", dex), *extra_files]
    return files, B.zip_bytes([{"name": n, "data": d} for n, d in files])


# ------------------------------------------------------------------ contract
def test_contract_metadata():
    cls = ApkTriage
    assert (cls.disclosure, cls.hosts, cls.provider, cls.terms, cls.access_model) == ("none", (), "", "open", "offline")
    assert cls.trust_tier == "n/a" and cls.max_tlp.value_str == "red" and cls.default_enabled is True
    assert cls.accepts == {T.FILE} and T.CODE_SIGNING_CERT in cls.produces and cls.requires_packages == ()


# ------------------------------------------------------------------ c2/c4: the minimal benign APK (v1 + v2 + v3)
def test_benign_apk_outputs(tmp_path):
    res = run(tmp_path, "demo.apk", B.apk_ok_v1v2v3())
    assert res.status is Status.OK, res.error
    assert {f.severity.label for f in res.findings} == {"info"}
    assert res.findings[0].title == "Android package: com.example.v3lum.demo"
    manifest = res.attributes["apk_manifest"]
    assert (manifest["package"], manifest["label"], manifest["version_code"], manifest["version_name"]) == \
        ("com.example.v3lum.demo", "V3LUM Demo", 7, "1.2.0")
    assert (manifest["min_sdk"], manifest["target_sdk"], manifest["permissions"]) == (24, 34, ["android.permission.INTERNET"])
    assert [c["name"] for c in manifest["exported_components"]] == ["com.example.v3lum.demo.MainActivity"]  # .SyncService is not exported
    signing = res.attributes["apk_signing"]
    assert signing["schemes"] == ["v1", "v2", "v3"] and signing["consistent"] is True and signing["verified"] is False
    assert {c["sha256"] for c in signing["certificates"]} == {OFFICIAL}
    assert all(c["key_matches"] in (True, None) for c in signing["certificates"])
    cert = pivots(res, "signing_certificate")[("code_signing_cert", OFFICIAL)]
    assert cert.expand is True and "not verified" in cert.note
    pkg = pivots(res, "android_package")[("keyword", "com.example.v3lum.demo")]
    assert pkg.expand is False
    assert res.attributes["android_package"] == "com.example.v3lum.demo"


def test_embedded_iocs_noise_and_non_routable(tmp_path):
    res = run(tmp_path, "demo.apk", B.apk_ok_v1v2v3())
    extracted = set(pivots(res, "extracted_from"))
    assert {("url", "https://api.example.com/v1/telemetry"), ("domain", "api.example.com"), ("domain", "cdn.example.net")} <= extracted
    values = {v for _t, v in extracted}
    assert not {"firebaseinstallations.googleapis.com", "schemas.android.com", "10.0.2.2", "v1.2.3.4"} & values  # SDK noise, private IP
    contents = res.attributes["apk_contents"]
    assert contents["noise_hosts"]["firebase"] == ["firebaseinstallations.googleapis.com"]
    assert contents["non_routable_ipv4"] == ["10.0.2.2"]
    assert all(p.expand for p in pivots(res, "extracted_from").values())  # hostile candidates for passive modules only


def test_label_resolution_prefers_default_then_portuguese():
    _man, arsc, _dex = B.demo_parts()
    table = at.arsc_strings(arsc)
    assert at.arsc_lookup(table["resolve"], 0x7F010000) == "V3LUM Demo"
    only_pt = at.arsc_strings(B.arsc_encode("com.example.x", {"pt-BR": "Aplicativo Exemplo", "en": "Example App"}))
    assert at.arsc_lookup(only_pt["resolve"], 0x7F010000) == "Aplicativo Exemplo"


@pytest.mark.parametrize("utf8", [False, True])
def test_axml_string_pools(utf8):
    tree = B.manifest_tree("com.example.pool", "Pool Ação", ["android.permission.INTERNET"], [])
    doc = at.axml_decode(B.axml_encode(tree, utf8=utf8))
    summary = at.manifest_summary(doc["elements"])
    assert summary["package"] == "com.example.pool" and summary["label"] == "Pool Ação"


def test_text_manifest_goes_through_safe_xml():
    ok = at.axml_or_text(b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.text">'
                         b'<uses-permission android:name="android.permission.INTERNET"/></manifest>')
    assert at.manifest_summary(ok["elements"])["package"] == "com.example.text"
    with pytest.raises(fts.UnsafeXML):
        at.axml_or_text(b'<!DOCTYPE m [<!ENTITY x SYSTEM "file:///dev/null">]><manifest package="&x;"/>')


def test_v1_only_and_v2_only(tmp_path):
    files, _ = unsigned_apk()
    v1 = B.zip_bytes([{"name": n, "data": d} for n, d in files + B.v1_signature(files, B.cert("official"))])
    assert run(tmp_path, "v1.apk", v1).attributes["apk_signing"]["schemes"] == ["v1"]
    _, plain = unsigned_apk()
    v2 = B.insert_sig_block(plain, B.sig_block(B.cert("official"), schemes=("v2",)))
    res = run(tmp_path, "v2.apk", v2)
    assert res.attributes["apk_signing"]["schemes"] == ["v2"] and pivots(res, "signing_certificate")[("code_signing_cert", OFFICIAL)]


def test_pkcs7_and_x509_parsers():
    certs = at.pkcs7_certificates(B.pkcs7_with_cert(B.cert("official")))
    assert certs == [B.cert("official")]
    info = at.x509_summary(B.cert("android_debug"))
    assert info["sha256"] == DEBUG and info["subject"] == "C=US, O=Android, CN=Android Debug" and info["self_signed"] is True
    assert at.x509_summary(b"\x30\x82\xff\xff" + b"\x00" * 10)["error"] == "x509_parse: truncated_content"
    assert at.x509_summary(b"\x30\x80" * 5000)["error"] == "x509_parse: too_deep"  # deep BER nesting is refused, not recursed
    with pytest.raises(at.DERError):
        at.pkcs7_certificates(b"\x30\x80" * 5000)


# ------------------------------------------------------------------ signing anomalies
def test_unsigned_apk_is_info(tmp_path):
    _, plain = unsigned_apk()
    res = run(tmp_path, "unsigned.apk", plain)
    assert titles(res)["No APK signature found (Android refuses to install it)"].severity.label == "info"
    assert res.status is Status.OK


def test_v1_and_v2_certificates_differ(tmp_path):
    files, _ = unsigned_apk()
    mixed = B.zip_bytes([{"name": n, "data": d} for n, d in files + B.v1_signature(files, B.cert("official"))])
    mixed = B.insert_sig_block(mixed, B.sig_block(B.cert("android_debug")))
    res = run(tmp_path, "mixed.apk", mixed)
    assert titles(res)["v1 and v2/v3 signing certificates differ"].severity.label == "medium"
    assert res.attributes["apk_signing"]["consistent"] is False


def test_signer_public_key_mismatch(tmp_path):
    _, plain = unsigned_apk()
    block = B.sig_block(B.cert("official"), schemes=("v2",), pubkey=B.spki_of(B.cert("android_debug")))
    res = run(tmp_path, "badkey.apk", B.insert_sig_block(plain, block))
    assert titles(res)["v2/v3 signer public key does not match its certificate"].severity.label == "medium"


# ------------------------------------------------------------------ c5: banker profile as data
def test_banker_profile_medium_in_plain_language(tmp_path):
    res = run(tmp_path, "seguranca.apk", B.apk_banker())
    f = titles(res)["Permissions consistent with Brazilian banking trojans"]
    assert f.severity.label == "medium" and f.confidence <= 0.4 and {"banker_profile", "suspicious"} <= set(f.tags)
    for plain in ("accessibility service (reads the screen and acts for the user)", "draw over other apps (overlay screens)",
                  "read/receive/send SMS messages", "device administrator (lock/wipe, resists uninstall)", "install other apps"):
        assert plain in f.description
    assert "not a malware verdict" in f.description
    assert not [x for x in res.findings if "malicious" in (x.title + x.description).lower()]
    found = titles(res)
    assert found["Debuggable build (android:debuggable=true)"].severity.label == "low"
    assert found["Signed with an Android debug certificate"].severity.label == "low"
    assert found["Packer hints"].severity.label == "info" and "Qihoo 360 Jiagu" in found["Packer hints"].description
    assert found["Code-like assets (dynamic loading candidates)"].severity.label == "low"
    extracted = set(pivots(res, "extracted_from"))
    assert {("url", "http://203.0.113.50/api/v2/register"), ("url", "wss://c2.example.org:8443/socket"), ("domain", "c2.example.org")} <= extracted
    assert ("domain", "app-measurement.com") not in extracted  # analytics SDK noise (c4)


def test_banker_profile_rules():
    full = {"traits": ["accessibility_service", "overlay", "sms", "device_admin"], "permissions": ["android.permission.QUERY_ALL_PACKAGES"]}
    assert at.banker_profile(full)["code"] == "banker_profile"
    no_install = dict(full, permissions=[])
    assert at.banker_profile(no_install)["code"] == "banker_profile_partial"
    partial = {"traits": ["accessibility_service", "overlay"], "permissions": []}
    assert at.banker_profile(partial)["severity"] == "info"
    assert at.banker_profile({"traits": ["overlay", "sms"], "permissions": []}) is None
    assert at.profiles()["banker_profile"]["all_of"] == ["accessibility_service", "overlay", "sms", "device_admin"]


# ------------------------------------------------------------------ c6/c7: impersonation
def test_protected_brand_without_reference_gives_no_verdict(tmp_path):
    res = run(tmp_path, "itau.apk", B.apk_banker(label="Itaú Segurança", package="com.itau.seguranca.update"))
    f = titles(res)["Protected brand used (Itau), official certificate unknown"]
    assert f.severity.label == "low" and "brand_abuse" in f.tags and "no impersonation verdict" in f.description
    assert not [x for x in res.findings if x.title.startswith("Impersonation:")]


def test_impersonation_with_supplied_reference(tmp_path):
    settings = {"apk_triage_reference_certs": {"Itau": [OFFICIAL.upper()]}}
    fake = run(tmp_path, "itau.apk", B.apk_banker(label="Itaú Segurança", package="com.itau.seguranca.update"), settings=settings)
    f = titles(fake)["Impersonation: Itau brand with a non-official signing certificate"]
    assert f.severity.label == "high" and {"brand_abuse", "suspicious"} <= set(f.tags) and DEBUG in f.description
    real = run(tmp_path, "itau_ok.apk", B.apk_banker(label="Itaú", package="com.itau.app", signer="official", perms=[]), settings=settings)
    assert titles(real)["Itau: signing certificate matches the official one"].severity.label == "info"
    assert not [x for x in real.findings if x.title.startswith("Impersonation:")]


def test_impersonation_with_org_profile(tmp_path):
    org = OrgProfile.from_dict({"brands": [{"keyword": "bancoexemplo"}],
                                "app_ids": [{"kind": "android_cert_sha256", "value": ":".join(OFFICIAL[i:i + 2] for i in range(0, 64, 2))}]})
    res = run(tmp_path, "seg.apk", B.apk_banker(), org_profile=org)
    f = titles(res)["Impersonation: organisation brand (org_profile) brand with a non-official signing certificate"]
    assert f.severity.label == "high" and f.data["brand"] == "organisation brand (org_profile)"


class _FakeBcbIndex:
    dominios = True
    datasets = ({"name": "bcb_dominios_verificados.json", "sha256": "ab" * 32},)


class _FakeP360:
    """Stands in for P360's local BCB copy (DominiosVerificados): documentation domains only."""

    calls = 0

    @staticmethod
    def load_bcb(data, sedes=True):
        _FakeP360.calls += 1
        assert sedes is False and data is not None  # read through ctx.data (cited), never a download
        return _FakeBcbIndex()

    @staticmethod
    def protected_brands(index):
        return [
            {"registrable_domain": "bancoexemplo.com.br", "brand_label": "bancoexemplo", "names": ["BANCO EXEMPLO S.A."]},
            {"registrable_domain": "bb.com.br", "brand_label": "bb", "names": ["BANCO DO BRASIL S.A."]},  # too short alone
            {"registrable_domain": "credito.com.br", "brand_label": "credito", "names": ["CREDITO EXEMPLO S.A."]},  # generic word
            {"registrable_domain": "santander.com.br", "brand_label": "santander", "names": ["BANCO SANTANDER S.A."]},  # curated
        ]


def test_p360_bcb_brands_from_the_local_copy(tmp_path, monkeypatch):
    monkeypatch.setattr(at, "_p360", _FakeP360)
    monkeypatch.setattr(at, "_P360_MEMO", {})
    res = run(tmp_path, "seg.apk", B.apk_banker())
    f = titles(res)["Protected brand used (BANCO EXEMPLO S.A. (bancoexemplo.com.br)), official certificate unknown"]
    assert f.severity.label == "low" and f.data["source"] == "P360 BCB DominiosVerificados" and "no impersonation verdict" in f.description
    labels = [b["label"] for b in at.p360_brands(type("Ctx", (), {"data": object()})(), {"santander"})]
    assert labels == ["bancoexemplo"]  # 'bb' too short, 'credito' generic, 'santander' already curated
    # a reference keyed by the registrable domain gives the c6 verdict
    settings = {"apk_triage_reference_certs": {"bancoexemplo.com.br": [OFFICIAL]}}
    fake = run(tmp_path, "seg2.apk", B.apk_banker(), settings=settings)
    imp = titles(fake)["Impersonation: BANCO EXEMPLO S.A. (bancoexemplo.com.br) brand with a non-official signing certificate"]
    assert imp.severity.label == "high" and DEBUG in imp.description


def test_p360_missing_or_broken_copy_adds_no_brand(tmp_path, monkeypatch):
    class Missing(_FakeP360):
        @staticmethod
        def load_bcb(data, sedes=True):
            return type("Idx", (), {"dominios": False, "datasets": ()})()

    class Broken(_FakeP360):
        @staticmethod
        def load_bcb(data, sedes=True):
            raise ValueError("the local copy does not parse")

    for stub in (Missing, Broken, None):
        monkeypatch.setattr(at, "_p360", stub)
        monkeypatch.setattr(at, "_P360_MEMO", {})
        res = run(tmp_path, f"seg_{getattr(stub, '__name__', 'none')}.apk", B.apk_banker())
        assert res.status is Status.OK
        assert not [x for x in res.findings if "official certificate" in x.title or x.title.startswith("Impersonation:")]


def test_brand_match_guards_short_keywords():
    brands = [{"name": "Banco do Brasil", "keywords": ["banco do brasil"], "exact": ["bb"], "packages": []}]
    assert at.brand_match(None, "br.com.bb.android", brands)[1] == "package"
    assert at.brand_match("BB Seguro", None, brands)[1] == "label"
    assert at.brand_match("Bbq Grill", "com.bbq.grill", brands) == (None, None, None)
    assert at.brand_match("Banco do Brasil - Atualizacao", None, brands)[0]["name"] == "Banco do Brasil"


def test_curated_reference_list_is_dated_and_pending_review():
    ref = at.curated_references()
    assert ref["schema"] == "v3lum.app_cert_references/1" and ref["checked_at"] and "pending" in ref["review_status"]
    assert all(not app["sha256"] for app in ref["apps"])  # filled only by the reviewed process, with evidence


def test_assetlinks_statements_and_markers():
    ok = at.parse_assetlinks((FIXTURES / "assetlinks_google_ok.json").read_bytes())
    assert ok["ok"] and ok["marker"] is None
    assert at.assetlinks_reference(ok, "com.google.android.calendar") == ["f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83"]
    html = at.parse_assetlinks((FIXTURES / "assetlinks_html_in_200.html").read_bytes(), content_type="text/html; charset=utf-8")
    assert not html["ok"] and html["marker"] == "html_in_200"  # an error page inside HTTP 200 is detected
    assert at.parse_assetlinks((FIXTURES / "assetlinks_malformed.json").read_bytes())["marker"] == "malformed_json"
    assert at.parse_assetlinks(b"", status=404)["marker"] == "not_found"
    assert at.parse_assetlinks(b"", status=429)["marker"] == "rate_limited"
    assert at.parse_assetlinks(b"<html>Just a moment...</html>", status=403)["marker"] == "challenge"
    assert at.parse_assetlinks(b"", status=301)["marker"] == "redirect_not_followed"
    assert at.parse_assetlinks(b"", status=200)["marker"] == "empty_body"
    assert at.parse_assetlinks(b"[]")["marker"] == "empty" and at.parse_assetlinks(b'{"a": 1}')["marker"] == "not_a_statement_list"
    assert module_fixture(ApkTriage, "assetlinks_google_ok.json")[0]["target"]["namespace"] == "android_app"


# ------------------------------------------------------------------ c8: malformed-zip variants
def test_duplicate_entries(tmp_path):
    res = run(tmp_path, "dup.apk", B.apk_dup_entries())
    f = titles(res)["Malformed-zip anti-analysis tricks"]
    assert f.severity.label == "medium" and "duplicate_name" in json.dumps(f.data)
    assert res.attributes["apk_contents"]["duplicates"] == ["AndroidManifest.xml"]


def test_bad_central_directory(tmp_path):
    res = run(tmp_path, "badcd.apk", B.apk_bad_central_directory())
    assert "central_directory_unreadable" in json.dumps(titles(res)["Malformed-zip anti-analysis tricks"].data)
    assert res.attributes["android_package"] == "com.example.v3lum.demo"  # recovered from the local headers


def test_bomb_ratio_member_is_refused(tmp_path):
    res = run(tmp_path, "bomb.apk", B.apk_bomb_ratio())
    f = titles(res)["Members not read (limits or corruption)"]
    assert f.severity.label == "medium" and "ratio" in json.dumps(f.data)
    assert res.status is Status.OK and res.attributes["android_package"] == "com.example.v3lum.demo"


def test_fake_encryption_flag(tmp_path):
    res = run(tmp_path, "fakeenc.apk", B.apk_fake_encryption())
    assert "fake_encryption_flag" in json.dumps(titles(res)["Malformed-zip anti-analysis tricks"].data)
    assert res.attributes["android_package"] == "com.example.v3lum.demo"  # Android ignores the flag, so do we


def test_corrupt_apk_is_an_error(tmp_path):
    bad = B.zip_bytes([{"name": "AndroidManifest.xml", "data": b"\x03\x00\x08\x00" + b"\xff" * 40}, {"name": "classes.dex", "data": b"dex\n035\x00"}])
    res = run(tmp_path, "broken.apk", bad)
    assert res.status is Status.ERROR and res.error.startswith("could not parse the APK")


def test_oversized_apk_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setitem(fts.LIMITS, "max_input", 1024)
    res = run(tmp_path, "big.apk", B.apk_ok_v1v2v3())
    assert res.status is Status.ERROR and "input cap" in res.error


# ------------------------------------------------------------------ real APK, applicability, limits
def test_real_androguard_test_apk(tmp_path):
    res = run_module(ApkTriage, Entity.make(T.FILE, str(FIXTURES / "androguard_testactivity_real.apk")), FakeHttp())
    assert res.status is Status.OK
    manifest = res.attributes["apk_manifest"]
    assert (manifest["package"], manifest["label"], manifest["min_sdk"]) == ("tests.androguard", "TestsAndroguardApplication", 9)
    sha = "6f5c31608f1f9e285eb6343c7c8af07de81c1fb2148b5349bec906444144576d"
    assert res.attributes["apk_signing"]["schemes"] == ["v1"] and pivots(res, "signing_certificate")[("code_signing_cert", sha)]
    assert titles(res)["Signed with an Android debug certificate"].severity.label == "low"


def test_non_apk_inputs_are_not_applicable(tmp_path):
    assert run(tmp_path, "a.docx", B.docx_rich_ok()).reason_code == "not_applicable"
    man, _arsc, dex = B.demo_parts()
    aab = B.zip_bytes([{"name": "BundleConfig.pb", "data": b"\x0a\x00"}, {"name": "base/manifest/AndroidManifest.xml", "data": man},
                       {"name": "base/dex/classes.dex", "data": dex}])
    res = run(tmp_path, "app.aab", aab)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and "backlog" in res.error
    res = run(tmp_path, "classes.dex", dex)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_dex_string_limits():
    dex = B.dex_encode([f"https://h{i}.example.com/x" for i in range(50)])
    assert len(at.dex_strings(dex)) == 50 and len(at.dex_strings(dex, max_strings=5)) == 5
    assert at.dex_strings(b"dex\n035\x00" + b"\xff" * 200) == []
    assert zlib.adler32(dex[12:]) & 0xFFFFFFFF == int.from_bytes(dex[8:12], "little")  # the builder writes valid headers
