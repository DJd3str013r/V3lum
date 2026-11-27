"""file_type_sniff (P270): own bundled magic table, 64 KB read limit, extension findings, one routing table.

Fixtures are tiny synthetic files built in tests (P270 c6) by the builders in tests/modules/test_p1_g12_1.py, plus
the research prototype expectations in tests/fixtures/file_type_sniff/research_proto_expected.json (the prototype
files live in tests/fixtures/document_metadata/). The module is offline (disclosure 'none'): the HTTP failure
cases of networked modules (401/403/429/5xx/error-in-200) do not exist here; their offline counterparts are the
refused/unreadable/empty/malformed inputs and the evidence cap below.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, make_ctx, module_fixture, run_module
from tests.modules import test_p1_g12_1 as B
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.file_analysis import apk_triage, archive_listing, document_metadata
from v3lum.modules.file_analysis import file_type_sniff as fts
from v3lum.modules.file_analysis.file_type_sniff import FileTypeSniff

DOC_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "document_metadata"


def run(tmp_path, name, data, **kw):
    return run_module(FileTypeSniff, Entity.make(T.FILE, B.write(tmp_path, name, data)), FakeHttp(), **kw)


def by_title(res):
    return {f.title: f for f in res.findings}


# ------------------------------------------------------------------ c1: offline module, library function
def test_contract_metadata():
    cls = FileTypeSniff
    assert (cls.disclosure, cls.hosts, cls.provider, cls.terms, cls.access_model) == ("none", (), "", "open", "offline")
    assert cls.trust_tier == "n/a" and cls.max_tlp.value_str == "red" and cls.default_enabled is True
    assert cls.max_requests == 0 and cls.requires_packages == ()


def test_routing_function_is_shared_by_every_file_module():
    """c1: the file modules call the same library function (no duplicated routing logic)."""
    assert document_metadata.sniff_path is fts.sniff_path
    assert apk_triage.sniff_path is fts.sniff_path
    assert archive_listing.sniff_path is fts.sniff_path


def test_routes_for_path_and_applies_to_file(tmp_path):
    docx = B.write(tmp_path, "a.docx", B.docx_rich_ok())
    assert fts.routes_for_path(docx) == ["file_hashing", "yara_scan", "document_metadata"]
    assert fts.applies_to_file("document_metadata", Entity.make(T.FILE, docx))
    assert not fts.applies_to_file("apk_triage", Entity.make(T.FILE, docx))
    assert fts.routes_for_path(str(tmp_path / "missing.bin")) == []


# ------------------------------------------------------------------ c2: own magic table, tested per type
_REFINED = {"pe": "dos-mz"}  # the 'MZ' row is refined from the header: a bare MZ stub is a DOS executable
_SUFFIX = {"macho-fat": b"\x00\x00\x00\x02\x01\x00\x00\x07", "bzip2": b"91AY&SY"}  # plausibility checks need these bytes


@pytest.mark.parametrize("row", fts.magic_table(), ids=lambda r: f"{r[2]}@{r[0]}:{r[1].hex()[:16]}")
def test_every_magic_row_is_detected(row):
    offset, magic, kind, category, _description = row
    data = b"\x00" * offset + magic + _SUFFIX.get(kind, b"") + b"\x00" * 600
    sn = fts.sniff(data, size=len(data))
    assert sn["kind"] == _REFINED.get(kind, kind)
    assert sn["category"] in (category, fts.kind_category(sn["kind"]))


def test_magic_table_is_own_dated_data():
    doc = json.loads((Path(fts.__file__).resolve().parents[2] / "data" / "file_type_sniff" / "magic.json").read_text(encoding="utf-8"))
    assert doc["schema"] == "v3lum.magic_table/1" and doc["licence"] == "own work (V3LUM)" and doc["checked_at"]
    assert len(doc["rows"]) == len(fts.magic_table()) >= 70


COVERAGE = [  # c2: at least PE, ELF, Mach-O, ZIP, OOXML, OLE, PDF, RAR, 7z, ISO, LNK, MSI, OneNote, APK/JAR and scripts
    ("pe32.exe", B.pe32_exe, "pe-exe", "pe_triage"),
    ("pe64.dll", B.pe64_dll, "pe-dll", "pe_triage"),
    ("tool.elf", lambda: B.elf64(interp=True), "elf", "elf_triage"),
    ("tool.macho", B.macho64, "macho", None),
    ("tool.fat", B.macho_fat, "macho-fat", None),
    ("Main.class", B.java_class, "java-class", None),
    ("ok.zip", B.zip_ok, "zip", "archive_listing"),
    ("a.docx", B.docx_rich_ok, "ooxml-docx", "document_metadata"),
    ("a.docm", B.docm_macro, "ooxml-docm", "document_metadata"),
    ("a.xlsm", B.xlsm_xlm_macrosheet, "ooxml-xlsm", "document_metadata"),
    ("a.odt", B.odt_ok, "odf-text", "document_metadata"),
    ("a.doc", B.doc_no_macro, "ole-doc", "document_metadata"),
    ("a.xls", B.xls_xlm_auto_open, "ole-xls", "document_metadata"),
    ("a.msg", B.msg_ok, "ole-msg", "email_header_analyzer"),
    ("a.msi", B.msi_installer, "ole-msi", "windows_artifact_triage"),
    ("a.pdf", B.pdf_no_metadata, "pdf", "document_metadata"),
    ("a.rtf", lambda: B.RTF_OK, "rtf", "document_metadata"),
    ("a.rar", lambda: B.rar5_bytes([("a.txt", b"x")]), "rar5", "archive_listing"),
    ("a.7z", B.sevenzip_bytes, "7z", "archive_listing"),
    ("a.iso", B.iso_ok, "iso9660", "archive_listing"),
    ("b.iso", lambda: B.iso_bytes([("A.TXT", b"x", False)], udf_bridge=True), "iso9660+udf", "archive_listing"),
    ("a.cab", lambda: B.cab_bytes([("a.txt", b"x")]), "cab", "archive_listing"),
    ("a.vhd", B.vhd_fixed, "vhd", "archive_listing"),
    ("a.vhdx", B.vhdx_header, "vhdx", "archive_listing"),
    ("a.tar", lambda: B.tar_bytes(B.TAR_MEMBERS), "tar", "archive_listing"),
    ("a.gz", lambda: B.gzip_named(b"x", "a"), "gzip", "archive_listing"),
    ("a.lnk", B.lnk_bytes, "lnk", "windows_artifact_triage"),
    ("a.one", lambda: bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3") + b"\x00" * 200, "onenote", "windows_artifact_triage"),
    ("a.apk", B.apk_ok_v1v2v3, "apk", "apk_triage"),
    ("a.jar", lambda: B.zip_bytes([{"name": "META-INF/MANIFEST.MF", "data": b"Manifest-Version: 1.0\r\n"},
                                   {"name": "a/Main.class", "data": B.java_class()}]), "jar", "archive_listing"),
    ("a.hta", lambda: b'<html><head><HTA:APPLICATION ID="app" WINDOWSTATE="minimize"></head><script language="VBScript">'
                      b'Set o = CreateObject("WScript.Shell")</script></html>', "hta", "script_decoder"),
    ("a.js", lambda: B.JS, "js", "script_decoder"),
    ("a.vbs", lambda: B.VBS, "vbs", "script_decoder"),
    ("a.ps1", lambda: b'$wc = New-Object System.Net.WebClient\n$d = [System.Convert]::FromBase64String("AAAA")\n'
                      b'Invoke-Expression $s\nWrite-Host "fixture"\n', "ps1", "script_decoder"),
    ("a.bat", lambda: b"@echo off\r\nsetlocal\r\nset X=1\r\nif exist %TEMP%\\a.txt goto end\r\n:end\r\nexit /b 0\r\n", "batch", "script_decoder"),
    ("a.png", B.png_bytes, "png", "image_metadata"),
]


@pytest.mark.parametrize("name,builder,kind,routed", COVERAGE, ids=[c[0] for c in COVERAGE])
def test_coverage_list_through_the_module(tmp_path, name, builder, kind, routed):
    """Every approved file parser is reachable: each kind is identified and routed (file_hashing/yara_scan always)."""
    http = FakeHttp()
    res = run_module(FileTypeSniff, Entity.make(T.FILE, B.write(tmp_path, name, builder())), http)
    assert res.status is Status.OK, res.error
    sniffed = res.attributes["file_sniff"]
    assert sniffed["kind"] == kind
    assert sniffed["routes"][:2] == ["file_hashing", "yara_scan"]
    if routed:
        assert routed in sniffed["routes"]
    assert [f.severity.label for f in res.findings] == ["info"]  # matching names: no extension finding
    assert res.findings[0].title == f"File type: {sniffed['description']}"
    assert res.attributes["file_type"] == sniffed["description"] and res.attributes["file_size"] > 0
    assert http.calls == [] and res.requests == 0 and res.pivots == []


def test_research_prototypes_and_a_system_binary():
    expected = module_fixture(FileTypeSniff, "research_proto_expected.json")
    for proto, fixture in (("fixture_docprops.docx", "research_proto_ok.docx"), ("fixture_meta.pdf", "research_proto_ok.pdf")):
        assert fts.sniff_path(str(DOC_FIXTURES / fixture))["kind"] == expected[proto]
    if os.path.isfile("/bin/ls"):
        assert fts.sniff_path("/bin/ls")["kind"] == expected["/bin/ls"]


# ------------------------------------------------------------------ c5: findings and wording
def test_double_extension_pe_is_high(tmp_path):
    res = run(tmp_path, "invoice.pdf.exe", B.pe32_exe())
    f = by_title(res)['Suspicious double extension ".pdf.exe"']
    assert f.severity.label == "high" and "T1036.007" in f.attack and {"suspicious", "masquerading"} <= set(f.tags)
    assert f.criterion and "looks like a .pdf" in f.description
    assert not [x for x in res.findings if x.title.startswith("Extension mismatch")]  # .exe holding a PE is no mismatch


def test_padded_double_extension_is_described(tmp_path):
    res = run(tmp_path, "boleto.pdf" + " " * 40 + ".exe", B.pe32_exe())
    f = by_title(res)['Suspicious double extension ".pdf.exe"']
    assert f.data["padded"] is True and "padded" in f.description


@pytest.mark.parametrize("name,builder,actual", [
    ("fatura.pdf", B.pe32_exe, "PE32 executable (GUI) Intel 80386"),
    ("foto.jpg", lambda: B.JS, "JavaScript/JScript script"),
    ("nota.docx", B.pe64_dll, "PE32+ DLL (console) x86-64"),
])
def test_executable_content_behind_document_or_image_extension_is_high(tmp_path, name, builder, actual):
    res = run(tmp_path, name, builder())
    ext = name.rsplit(".", 1)[1]
    f = by_title(res)[f"Extension mismatch: claimed .{ext}, actually {actual}"]
    assert f.severity.label == "high" and "T1036.008" in f.attack and "suspicious" in f.tags
    assert f.data["executable_content"] is True and f.data["claimed_ext"] == ext


@pytest.mark.parametrize("name,builder,actual", [
    ("imagem.jpg", B.png_bytes, "PNG image"),
    ("carta.doc", lambda: B.RTF_OK, "RTF document"),
    ("planilha.xlsx", B.pdf_no_metadata, "PDF document"),
])
def test_other_mismatches_are_medium(tmp_path, name, builder, actual):
    res = run(tmp_path, name, builder())
    ext = name.rsplit(".", 1)[1]
    f = by_title(res)[f"Extension mismatch: claimed .{ext}, actually {actual}"]
    assert f.severity.label == "medium" and "suspicious" not in f.tags and f.data["executable_content"] is False


def test_pdf_zip_polyglot_is_medium_possible(tmp_path):
    poly = B.pdf_no_metadata() + B.zip_bytes([{"name": "payload/run.js", "data": B.JS}])
    res = run(tmp_path, "boleto.pdf", poly)
    f = by_title(res)["Polyglot: PDF document that is also a valid ZIP"]
    assert f.severity.label == "medium" and f.confidence <= 0.4 and "polyglot" in f.tags
    assert res.attributes["file_sniff"]["kind"] == "pdf" and res.attributes["file_sniff"]["polyglot"]


def test_zip_package_inside_an_ole_stream_is_not_a_polyglot(tmp_path):
    """Word 2007+ keeps the theme as a small OOXML package inside .doc streams (live check: Apache POI's
    SampleDoc.doc): a ZIP inside the CFB sector grid is embedded content, not a polyglot."""
    theme = B.zip_bytes([{"name": "theme/theme/theme1.xml", "data": b"<a:theme/>" * 20, "method": 0},
                         {"name": "[Content_Types].xml", "data": b"<Types/>", "method": 0}])
    doc = B.cfb_bytes([("WordDocument", B.word_fib()), ("1Table", b"\x00" * 600), ("Data", theme)] + B.summary_streams())
    assert len(doc) % 512 == 0 and b"PK\x05\x06" in doc
    res = run(tmp_path, "relatorio.doc", doc)
    assert res.attributes["file_sniff"]["kind"] == "ole-doc" and res.attributes["file_sniff"]["polyglot"] == []
    assert not [f for f in res.findings if f.title.startswith("Polyglot")]
    # the same ZIP appended after the compound file (off the 512-byte grid) is a polyglot
    appended = run(tmp_path, "relatorio2.doc", doc + theme)
    assert any(f.title.startswith("Polyglot: Word 97-2003 document") and f.severity.label == "medium" for f in appended.findings)


def test_pe_with_zip_overlay_is_polyglot(tmp_path):
    res = run(tmp_path, "setup.exe", B.pe32_exe() + B.zip_bytes([{"name": "data.txt", "data": b"x" * 100}]))
    assert any(f.title.startswith("Polyglot: PE32 executable") and f.severity.label == "medium" for f in res.findings)


def test_rtlo_file_name_is_high(tmp_path):
    name = "Fatura_\u202efdp.exe"
    res = run(tmp_path, name, B.pe32_exe())
    f = by_title(res)['Suspicious file name with a right-to-left override: displays as "Fatura_exe.pdf"']
    assert f.severity.label == "high" and "T1036.002" in f.attack


def test_split_name_and_double_extension_helpers():
    assert fts.split_name("C:\\Users\\x\\invoice.PDF.exe")["exts"] == ["pdf", "exe"]
    assert fts.split_name("a\u202ecod.scr")["visible"] == "arcs.doc"
    assert fts.is_double_extension(["pdf", "exe"]) and fts.is_double_extension(["jpg", "scr"])
    assert not fts.is_double_extension(["tar", "gz"]) and not fts.is_double_extension(["exe"])


def test_matching_names_only_info(tmp_path):
    res = run(tmp_path, "relatorio.pdf", B.pdf_xmp_ok())
    assert res.status is Status.OK and [f.severity.label for f in res.findings] == ["info"]
    f = res.findings[0]
    assert f.title == "File type: PDF document" and f.confidence == 1.0 and "document_metadata" in f.data["routes"]
    assert res.attributes["file_sniff"]["claimed_extension"] == "pdf"


# ------------------------------------------------------------------ c3: 64 KB head + ZIP central directory only
class _Counting:
    def __init__(self, fh, counter):
        self._fh, self._counter = fh, counter

    def read(self, n=-1):
        data = self._fh.read(n)
        self._counter.append(len(data))
        return data

    def __getattr__(self, name):
        return getattr(self._fh, name)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._fh.close()


def _counting_open(monkeypatch):
    counter: list[int] = []
    real = fts.open_regular
    monkeypatch.setattr(fts, "open_regular", lambda path: _Counting(real(path), counter))
    return counter


def test_reads_head_and_tail_only(tmp_path, monkeypatch):
    big = B.pdf_no_metadata() + os.urandom(3 << 20)
    path = B.write(tmp_path, "big.pdf", big)
    counter = _counting_open(monkeypatch)
    sn = fts.sniff_path(path)
    assert sn["kind"] == "pdf" and sn["size"] == len(big)
    assert sum(counter) <= fts.LIMITS["sniff_head"] + fts.LIMITS["sniff_tail"]


def test_zip_family_told_apart_from_the_central_directory(tmp_path, monkeypatch):
    """A 3 MB stored member pushes [Content_Types].xml out of the head: the central directory still tells OOXML apart."""
    filler = {"name": "word/media/image1.bin", "data": os.urandom(3 << 20), "method": 0}
    parts = [filler] + [{"name": n, "data": d.encode()} for n, d in (("[Content_Types].xml", B.CT_DOCX.format(extra="")),
                                                                     ("_rels/.rels", B.ROOT_RELS), ("word/document.xml", B.doc_xml("<w:p/>")))]
    path = B.write(tmp_path, "big.docx", B.zip_bytes(parts))
    counter = _counting_open(monkeypatch)
    sn = fts.sniff_path(path)
    assert sn["kind"] == "ooxml-docx"
    assert sum(counter) <= fts.LIMITS["sniff_head"] + fts.LIMITS["sniff_tail"] + 4096


# ------------------------------------------------------------------ pasted text, refused / unreadable / empty / malformed inputs
def test_text_entity_script_heuristics():
    res = run_module(FileTypeSniff, Entity.make(T.TEXT, "$c = New-Object System.Net.WebClient; Invoke-Expression $c.DownloadString($u)"),
                     FakeHttp())
    assert res.status is Status.OK
    assert [f.title for f in res.findings] == ["Content type: PowerShell script"]
    plain = run_module(FileTypeSniff, Entity.make(T.TEXT, "Bom dia, segue o relatorio mensal."), FakeHttp())
    assert plain.status is Status.OK and plain.findings == [] and plain.attributes["file_sniff"]["kind"] == "text"


def test_fifo_and_directory_are_refused_before_opening(tmp_path):
    fifo = tmp_path / "pipe.pdf"
    os.mkfifo(fifo)  # opening a FIFO would block: it must be refused from stat() alone
    res = run_module(FileTypeSniff, Entity(T.FILE, str(fifo)), FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and "FIFO" in res.error
    res = run_module(FileTypeSniff, Entity(T.FILE, str(tmp_path)), FakeHttp())
    assert res.status is Status.SKIPPED and "directory" in res.error
    res = run_module(FileTypeSniff, Entity(T.FILE, str(tmp_path / "gone.bin")), FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_unreadable_file_is_an_error_not_empty(tmp_path, monkeypatch):
    path = B.write(tmp_path, "locked.pdf", B.pdf_no_metadata())
    real_open = os.open

    def deny(p, *a, **k):
        if str(p) == path:
            raise PermissionError(13, "Permission denied")
        return real_open(p, *a, **k)

    monkeypatch.setattr(fts.os, "open", deny)
    with pytest.raises(fts.FileRefused) as info:
        fts.open_regular(path)
    assert info.value.kind == "unreadable"
    entity = Entity.make(T.FILE, path)
    res = FileTypeSniff().run(entity, make_ctx(FileTypeSniff, entity=entity))
    assert res.status is Status.ERROR and "Permission denied" in res.error


def test_empty_file(tmp_path):
    res = run(tmp_path, "vazio.pdf", b"")
    assert res.status is Status.OK and res.attributes["file_sniff"]["kind"] == "empty"
    assert [f.severity.label for f in res.findings] == ["info"]  # an empty file never claims a mismatch


@pytest.mark.parametrize("data", [
    b"MZ" + b"\xff" * 30,
    B.OLE_MAGIC + b"\xff" * 100,
    b"PK\x03\x04" + b"\xff" * 64,
    b"PK\x05\x06" + b"\x00" * 18,
    b"%PDF-" + b"\x00" * 10,
    b"Rar!\x1a\x07\x01\x00" + b"\xff" * 20,
    b"\x7fELF\x02\x01\x01" + b"\xff" * 20,
    bytes(range(256)) * 300,
], ids=["mz", "ole", "zip-local", "zip-eocd", "pdf", "rar5", "elf", "binary"])
def test_malformed_headers_never_crash(tmp_path, data):
    res = run(tmp_path, "x.bin", data)
    assert res.status is Status.OK and res.attributes["file_sniff"]["kind"]


@pytest.mark.parametrize("text", [
    "<" * 70_000, "a" * 70_000, "$" * 70_000, "%" * 70_000, "=" * 70_000, "var " * 20_000, "Sub " * 20_000,
    "Set " * 20_000, "@echo " * 12_000, "\\x41" * 20_000, "(" * 70_000 + ")" * 70_000, "Chr(" * 20_000,
])
def test_heuristics_are_bounded(text):
    """ReDoS guard: the script heuristics stay fast on pathological input (64 KB window, bounded patterns)."""
    started = time.perf_counter()
    fts.sniff(text.encode()[: fts.LIMITS["sniff_head"]], size=len(text))
    fts.script_guess(text)
    assert time.perf_counter() - started < 2.0


def test_evidence_is_capped(tmp_path):
    names = [{"name": f"dir{i:05d}/" + "n" * 200 + ".txt", "data": b"", "method": 0} for i in range(3000)]
    res = run(tmp_path, "many.zip", B.zip_bytes(names))
    assert res.status is Status.OK
    assert len(json.dumps(res.raw, default=str)) <= fts.LIMITS["max_output_json"]
    capped = fts.cap_json({"blob": "x" * (3 << 20)})
    assert len(json.dumps(capped)) <= fts.LIMITS["max_output_json"]
