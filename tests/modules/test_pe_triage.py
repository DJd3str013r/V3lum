"""pe_triage (P271): static PE triage offline (bounded stdlib reader; pefile only in the core sandbox).

c8 fixtures (tests/fixtures/pe_triage/): small benign PE files built for the tests by the prep's own PE builder
(code bytes push/mov/ret + int3: nothing runnable; Rich header with the real checksum, imports by name and ordinal,
exports, RSDS/REPRO debug, a resource tree, an Authenticode signature made with a throwaway 'V3LUM Test Root CA
(DO NOT TRUST)' chain whose keys were deleted), a truncated and two malformed PEs and a DOS-only stub;
pefile_*.json are pefile 2024.8.26's output (fast_load + the four directories) for each, the oracle of the stdlib
reader. No malware is in the repository. Offline module: no request is ever made.
"""

from __future__ import annotations

import datetime as dt
import os
from pathlib import Path

import pytest

import v3lum.core.module as core_module
from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.file_analysis import pe_triage as pt
from v3lum.modules.file_analysis.pe_triage import PeTriage
from v3lum.modules.geo_image_meta import image_metadata as im

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "pe_triage"
NAMES = ("unsigned_ok.exe", "signed_ok.exe", "dll_zero_ts.dll", "delphi_ts.exe", "packed_future_ts.exe", "pe64_repro.exe",
         "truncated.exe", "truncated_sections.exe", "malformed_headers.exe")


def run(name, **kw):
    http = FakeHttp()
    res = run_module(PeTriage, Entity.make(T.FILE, str(FIX / name)), http, **kw)
    assert http.calls == [] and res.requests == 0  # c1: offline, never executed
    return res


def pivots(res):
    return {(p.entity.type.value, p.relation): p for p in res.pivots}


@pytest.mark.parametrize("name", NAMES)
def test_stdlib_reader_matches_pefile(name):  # c2/c3: same shape and values as pefile
    stem = name.rsplit(".", 1)[0]
    ref = module_fixture("pe_triage", f"pefile_{stem}.json")
    raw = pt.parse_pe((FIX / name).read_bytes())
    for key in ("machine", "timestamp", "magic", "subsystem", "entry_point", "md5", "sha256"):
        assert raw.get(key) == ref.get(key), key
    ref_names = [s["name"] for s in ref["sections"]]
    assert [s["name"] for s in raw["sections"]][: len(ref_names)] == ref_names  # malformed: the stdlib also lists empty rows
    if ref.get("imphash"):
        assert raw["imphash"] == ref["imphash"]
    if ref.get("rich"):
        assert raw["rich"]["clear_md5"] == ref["rich"]["clear_md5"]


def test_unsigned_executable():
    res = run("unsigned_ok.exe")
    assert res.status is Status.OK and res.attributes["pe_summary"].startswith("PE32 executable (i386, windows_gui), compile time 2026-11-01")
    p = pivots(res)
    assert p[("md5", "has_hash")].expand and p[("sha256", "has_hash")].entity.value == res.attributes["sha256"]
    assert p[("imphash", "has_imphash")].expand is False  # c5
    assert res.attributes["rich_header_hash"] and res.attributes["rich_checksum_valid"] is True
    assert ("keyword", "has_imphash") not in p and not [x for x in res.pivots if x.entity.type is T.KEYWORD]


def test_signed_not_verified_with_signer_pivot():
    res = run("signed_ok.exe")
    sig = res.attributes["pe_signature"]
    assert sig["status"] == "signed, not verified" and sig["signers"][0]["serial"] == "1234ABCD5678"
    assert "Example Org Ltda Code Signing (TEST)" in sig["signers"][0]["subject"]
    cert = pivots(res)[("code_signing_cert", "signing_certificate")]
    assert cert.expand is False and len(cert.entity.value) == 64 and "not verified" in cert.note
    f = next(f for f in res.findings if f.title.startswith("Authenticode"))
    assert "no claim about validity" in f.description and "valid" not in f.title.lower().replace("not verified", "")


@pytest.mark.parametrize("name,flag", [("dll_zero_ts.dll", "zero"), ("delphi_ts.exe", "delphi_1992"), ("packed_future_ts.exe", "future")])
def test_unreliable_compile_timestamps(name, flag):  # c4
    res = run(name)
    assert flag in res.attributes["compile_time_flags"]
    assert any(f.title == "Compile timestamp unreliable/forged" and "unreliable_timestamp" in f.tags for f in res.findings)


def test_reproducible_build_timestamp_is_not_a_date():
    res = run("pe64_repro.exe")
    assert "reproducible_build" in res.attributes["compile_time_flags"] and "compile_time" not in res.attributes
    assert res.attributes["pe_machine"] == "amd64"


def test_packer_hints_are_low_context_never_verdicts():  # c7
    res = run("packed_future_ts.exe")
    f = next(f for f in res.findings if f.title == "Packer or obfuscation hints")
    assert f.severity.label == "low" and {"context_only", "packer_hint"} <= set(f.tags) and "malicious" not in f.tags
    hints = pt.pe_packer_hints(pt.parse_pe((FIX / "packed_future_ts.exe").read_bytes()))
    down, note = pt.downgrade_pe_hints(hints, [{"source": "circl_hashlookup", "known_malicious": []}])
    assert all(h["severity"] == "info" for h in down) and "not proof of good" in note
    kept, note2 = pt.downgrade_pe_hints(hints, [{"source": "circl_hashlookup"}, {"source": "x", "known_malicious": ["malshare"]}])
    assert kept == hints and "KnownMalicious" in note2


def test_pdb_user_and_machine_are_privacy_attributes_never_usernames():  # c6
    info = pt.pdb_info(r"C:\Users\analyst01\source\repos\demo\Release\demo.pdb")
    assert info["username"] == "analyst01" and info["tags"] == ["privacy"]
    assert pt.pdb_info(r"\\BUILD-PC01\share\demo.pdb")["machine"] == "BUILD-PC01"
    for name in NAMES:
        res = run(name)
        assert not [p for p in res.pivots if p.entity.type in (T.USERNAME, T.PERSON)]
        if res.attributes.get("pdb_path"):
            assert "pdb_username" in res.attributes or "pdb_path" in res.attributes


def test_truncated_and_malformed_files():  # c8
    for name in ("truncated.exe", "truncated_sections.exe", "malformed_headers.exe"):
        res = run(name)
        assert res.status is Status.OK and res.attributes["pe_summary"].startswith("truncated")
        assert any(f.title == "Malformed or truncated PE structures" for f in res.findings)
    for name in ("dos_only.exe", "malformed_lfanew.exe"):
        res = run(name)
        assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and "not a PE file" in res.error


def test_garbage_and_special_files(tmp_path):
    junk = tmp_path / "junk.exe"
    junk.write_bytes(b"MZ" + b"\xff" * 10)
    assert run_module(PeTriage, Entity.make(T.FILE, str(junk)), FakeHttp()).status in (Status.SKIPPED, Status.ERROR)
    fifo = tmp_path / "pipe.exe"
    os.mkfifo(fifo)
    assert run_module(PeTriage, Entity(T.FILE, str(fifo)), FakeHttp()).status is Status.SKIPPED
    assert pt.normalize_pe(["not", "a", "dict"])["status"] == "error"


def test_pefile_runs_only_in_the_sandbox(monkeypatch):
    calls = []

    class FakeSandbox:
        def run_sandboxed(self, target, path, *, args=None, **limits):
            calls.append(target)
            return {"ok": True, "result": module_fixture("pe_triage", "pefile_signed_ok.json"), "isolation": "test"}

    real = core_module.package_available
    monkeypatch.setattr(core_module, "package_available", lambda name: name == "pefile" or real(name))
    monkeypatch.setattr(pt, "package_available", lambda name: name == "pefile" or real(name))
    monkeypatch.setattr(pt, "core_sandbox", lambda: FakeSandbox())
    monkeypatch.setattr(im, "core_sandbox", lambda: FakeSandbox())
    res = run("signed_ok.exe")
    assert calls == ["v3lum.modules.file_analysis.pe_triage:pefile_child"] and res.raw["parser"].startswith("pefile in the sandbox")
    assert res.attributes["pe_signature"]["status"] == "signed, not verified"


def test_compile_time_flags_helper():
    now = dt.datetime(2026, 11, 26, tzinfo=dt.timezone.utc)
    assert pt.compile_time_flags(0x2A425E19, now)["flags"] == ["delphi_1992"]
    assert pt.compile_time_flags(915148800 - 86400, now)["flags"] == ["pre_2000"]
    assert pt.compile_time_flags(1700000000, now)["reliable"] is True


def test_contract_metadata():
    assert PeTriage.disclosure == "none" and PeTriage.default_enabled is True and PeTriage.max_tlp.value_str == "red"
