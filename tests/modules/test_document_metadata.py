"""document_metadata (P269): PDF/OOXML/ODF/OLE/RTF/.msg metadata and maldoc indicators, offline.

Synthetic fixtures are built in tests (c12) by tests/modules/test_p1_g12_1.py: the research PDF/DOCX prototypes
(tests/fixtures/document_metadata/research_proto_ok.*, expected values in research_proto_expected.json), a docx with
a remote template, an XXE docx, a billion-laughs docx, a zip-bomb docx, macro-bearing OLE/OOXML/ODF files, XLM and
DDE documents and PDFs with /OpenAction. libreoffice_real.* are tiny documents saved by LibreOffice 24.2 with
placeholder metadata ('Fulano de Tal', 'analyst01'); ovba_compression_vectors.json holds the [MS-OVBA] examples.
Offline module: the networked failure cases (401/403/429/5xx/error-in-200) map to refused, malformed, encrypted
and oversized inputs here; no test ever sees a request.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from tests.modules import test_p1_g12_1 as B
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.file_analysis import document_metadata as dm
from v3lum.modules.file_analysis import file_type_sniff as fts
from v3lum.modules.file_analysis.document_metadata import DocumentMetadata

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "document_metadata"


def run(tmp_path, name, data, http=None, **kw):
    http = http if http is not None else FakeHttp()
    res = run_module(DocumentMetadata, Entity.make(T.FILE, B.write(tmp_path, name, data)), http, **kw)
    assert http.calls == [] and res.requests == 0  # c1/c8: nothing is ever fetched or resolved
    return res


def titles(res):
    return {f.title: f for f in res.findings}


def pivots(res, relation=None):
    return {(p.entity.type.value, p.entity.value): p for p in res.pivots if relation is None or p.relation == relation}


def docm_with(modules):
    vba_bin = B.cfb_bytes(B.vba_streams("", modules))
    ct = B.CT_DOCX.format(extra="").replace("document.main+xml", "document.macroEnabled.main+xml").replace(
        "</Types>", '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>')
    return B.ooxml([("[Content_Types].xml", ct), ("_rels/.rels", B.ROOT_RELS), ("word/document.xml", B.doc_xml("<w:p/>")),
                    ("word/_rels/document.xml.rels", B.rels(("rId1", "http://schemas.microsoft.com/office/2006/relationships/vbaProject",
                                                             "vbaProject.bin", False))),
                    ("word/vbaProject.bin", vba_bin), ("docProps/core.xml", B.core_xml("Fulano de Tal", "analyst01")),
                    ("docProps/app.xml", B.app_xml())])


# ------------------------------------------------------------------ contract, c1 (FILE only; URLs get the manual link)
def test_contract_metadata():
    cls = DocumentMetadata
    assert (cls.disclosure, cls.hosts, cls.provider, cls.terms, cls.access_model) == ("none", (), "", "open", "offline")
    assert cls.trust_tier == "n/a" and cls.max_tlp.value_str == "red" and cls.default_enabled is True
    assert cls.manual_link == "file_triage:wayback_url" and cls.requires_packages == ()


def test_seed_url_is_never_downloaded_and_gets_the_archived_copy_link():
    http = FakeHttp()
    res = run_module(DocumentMetadata, "url:https://www.example.com/docs/fatura.pdf", http)
    assert res.status is Status.SKIPPED and res.reason_code == "opsec" and "LIGHT file fetcher" in res.error
    assert res.links == [("Wayback Machine captures of the document URL (archived copy, no contact with the target)",
                          "https://web.archive.org/web/*/https://www.example.com/docs/fatura.pdf")]
    assert http.calls == []
    pivot = run_module(DocumentMetadata, "url:https://www.example.com/docs/fatura.pdf", FakeHttp(), is_seed=False)
    assert pivot.status is Status.SKIPPED and pivot.reason_code == "not_applicable" and pivot.links == []  # never for URL pivots


def test_non_documents_and_empty_files_are_not_applicable(tmp_path):
    res = run(tmp_path, "setup.exe", B.pe32_exe())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and "not a document" in res.error
    assert run(tmp_path, "vazio.docx", b"").status is Status.SKIPPED
    assert run(tmp_path, "setup.msi", B.msi_installer()).reason_code == "not_applicable"  # MSI goes to windows_artifact_triage


# ------------------------------------------------------------------ c12: research prototypes
def test_research_docx_prototype():
    expected = module_fixture(DocumentMetadata, "research_proto_expected.json")["fixture_docprops.docx"]
    data = (FIXTURES / "research_proto_ok.docx").read_bytes()
    assert hashlib.sha256(data).hexdigest() == expected["sha256"]
    res = run_module(DocumentMetadata, Entity.make(T.FILE, str(FIXTURES / "research_proto_ok.docx")), FakeHttp())
    meta = res.attributes["document_metadata"]
    exp = expected["meta"]
    assert meta["author"] == exp["creator"] and meta["last_modified_by"] == exp["lastModifiedBy"]
    assert meta["company"] == exp["Company"] and meta["template"] == exp["Template"] and meta["created"] == exp["created"]
    assert meta["revision"] == exp["revision"] and meta["application"] == f"{exp['Application']} {exp['AppVersion']}"
    assert not res.attributes.get("document_external_targets") and "document_macros" not in res.attributes
    assert res.attributes["document_company"] == "ACME Ltda" and res.attributes["document_author"] == ["jdoe"]
    assert res.attributes["document_summary"] == "ooxml | Microsoft Office Word 16.0000 | author: jdoe | company: ACME Ltda | no findings"


def test_research_pdf_prototype():
    expected = module_fixture(DocumentMetadata, "research_proto_expected.json")["fixture_meta.pdf"]
    assert hashlib.sha256((FIXTURES / "research_proto_ok.pdf").read_bytes()).hexdigest() == expected["sha256"]
    res = run_module(DocumentMetadata, Entity.make(T.FILE, str(FIXTURES / "research_proto_ok.pdf")), FakeHttp())
    meta = res.attributes["document_metadata"]
    info = expected["meta"]["info"]
    assert meta["author"] == [info["/Author"]] and meta["producer"] == info["/Producer"] and meta["application"] == info["/Creator"]
    assert meta["created"] == dm.pdf_date_to_iso(info["/CreationDate"]) == "2026-11-25T12:00:00-03:00"
    assert meta["title"] == info["/Title"] and meta["pages"] == expected["meta"]["pages"] and meta["encrypted"] is False
    assert pivots(res)[("person_name", "V3LUM Test Author")].relation == "document_author"


@pytest.mark.parametrize("name", ["libreoffice_real.doc", "libreoffice_real.docx", "libreoffice_real.pdf", "libreoffice_real.rtf",
                                  "libreoffice_real.xls"])
def test_real_libreoffice_documents(name):
    res = run_module(DocumentMetadata, Entity.make(T.FILE, str(FIXTURES / name)), FakeHttp())
    assert res.status is Status.OK, res.error
    meta = res.attributes["document_metadata"]
    assert meta["title"] == "Relatorio"
    assert meta["author"] in ("Fulano de Tal", ["Fulano de Tal"])
    assert [f.severity.label for f in res.findings] in (["info"], ["info", "info"])  # benign: nothing above INFO


# ------------------------------------------------------------------ c9: severity table
SEVERITY_TABLE = [
    ("rt.docx", B.docx_remote_template, "Suspicious remote template / external attachedTemplate (url)", "high", "T1221"),
    ("odt_rt.odt", B.odt_macro_remote_template, "Suspicious remote template / external template (url)", "high", "T1221"),
    ("macro.docm", B.docm_macro, "Suspicious auto-exec macro", "high", "T1059.005"),
    ("macro.doc", B.doc_macro_autoopen, "Suspicious auto-exec macro", "high", "T1059.005"),
    ("odt_macro.odt", B.odt_macro_remote_template, "Suspicious auto-exec macro", "high", "T1059.005"),
    ("xlm.xls", B.xls_xlm_auto_open, "Suspicious Excel 4.0 (XLM) macro sheet", "high", "T1059"),
    ("xlm.xlsm", B.xlsm_xlm_macrosheet, "Suspicious Excel 4.0 (XLM) macro sheet", "high", "T1059"),
    ("dde.docx", B.docx_dde, "Suspicious DDE field", "high", "T1559.002"),
    ("benign_macro.docm", lambda: docm_with([("Module1", "std", B.VBA_BENIGN)]), "Macro present (not executed)", "medium", None),
    ("js.pdf", B.pdf_openaction_js, "Suspicious /JavaScript run by /OpenAction or /AA", "high", "T1059.007"),
    ("launch.pdf", B.pdf_launch, "Suspicious /Launch run by /OpenAction or /AA", "high", "T1204.002"),
    ("emb.pdf", B.pdf_embedded_uri, "Embedded file in PDF", "medium", None),
    ("obf.pdf", B.pdf_obfuscated_names, "Hex-obfuscated PDF names", "medium", "T1027"),
    ("obj.rtf", lambda: B.RTF_OBJUPDATE, "Suspicious auto-updating embedded OLE object", "high", "T1203"),
]


@pytest.mark.parametrize("name,builder,title,severity,attack", SEVERITY_TABLE, ids=[s[0] for s in SEVERITY_TABLE])
def test_severity_table(tmp_path, name, builder, title, severity, attack):
    res = run(tmp_path, name, builder())
    assert res.status is Status.OK, res.error
    f = titles(res)[title]
    assert f.severity.label == severity and f.criterion
    if attack:
        assert attack in f.attack
    if severity == "high":
        assert f.title.startswith("Suspicious") and "suspicious" in f.tags  # worded 'suspicious', never 'malicious'
        assert f.confidence < 1.0
    assert res.findings[0].title.startswith("Document metadata: ")  # one INFO summary per document (c11)


def test_obfuscated_auto_action_is_only_possible(tmp_path):
    f = titles(run(tmp_path, "obf.pdf", B.pdf_obfuscated_names()))["Suspicious /OpenAction with /JavaScript or /Launch keywords"]
    assert f.severity.label == "high" and f.confidence <= 0.4


def test_benign_documents_have_no_alerts(tmp_path):
    for name, builder in (("a.pdf", B.pdf_xmp_ok), ("a.docx", B.docx_rich_ok), ("a.odt", B.odt_ok), ("a.doc", B.doc_no_macro),
                          ("a.rtf", lambda: B.RTF_OK), ("n.pdf", B.pdf_no_metadata)):
        res = run(tmp_path, name, builder())
        assert res.status is Status.OK and {f.severity.label for f in res.findings} == {"info"}, name
        assert "no findings" in res.attributes["document_summary"]


# ------------------------------------------------------------------ c8: external relationships = hostile pivots, never fetched
def test_remote_template_targets_become_hostile_pivots(tmp_path):
    res = run(tmp_path, "fatura.docx", B.docx_remote_template())
    rt = pivots(res, "remote_template")
    assert ("url", "http://203.0.113.10/templates/fatura.dotm") in rt
    assert {("ipv4", "203.0.113.10"), ("ipv4", "198.51.100.20"), ("ipv4", "198.51.100.7")} <= set(rt)  # URL, WebDAV, UNC hosts
    assert all(p.expand for p in rt.values())  # hostile IOCs: passive modules may look them up (never fetched here)
    kinds = {f.title for f in res.findings if f.severity.label == "high"}
    assert kinds == {"Suspicious remote template / external attachedTemplate (url)", "Suspicious remote template / external frame (webdav)",
                     "Suspicious remote template / external image (unc)", "Suspicious remote template / external oleObject (mhtml)"}
    assert all({"remote_template", "maldoc"} <= set(f.tags) for f in res.findings if f.severity.label == "high")
    targets = {t["type"]: t for t in res.attributes["document_external_targets"]}
    assert targets["attachedTemplate"]["auto_load"] is True and targets["attachedTemplate"]["target_kind"] == "url"
    assert targets["frame"]["target_kind"] == "webdav" and targets["image"]["target_kind"] == "unc"
    assert targets["hyperlink"]["auto_load"] is False
    assert pivots(res, "external_hyperlink")[("url", "https://www.example.com/ajuda")]
    assert "HIGH: remote_template" in res.attributes["document_summary"]


def test_dde_and_includepicture_field(tmp_path):
    res = run(tmp_path, "dde.docx", B.docx_dde())
    assert pivots(res, "remote_template")[("url", "http://198.51.100.40/t.png")]
    macros = res.attributes["document_macros"]
    assert macros["dde"] and "cmd.exe" in json.dumps(macros["dde"]).lower()


def test_macro_strings_and_modules(tmp_path):
    res = run(tmp_path, "m.doc", B.doc_macro_autoopen())
    assert pivots(res, "macro_string")[("url", "http://203.0.113.5/p.ps1")].expand is True
    macros = res.attributes["document_macros"]
    mods = {m["name"]: m for m in macros["modules"]}
    assert set(mods) == {"ThisDocument", "Module1"} and mods["ThisDocument"]["autoexec"] == ["AutoOpen"]
    assert mods["ThisDocument"]["suspicious"] == ["Shell"] and mods["Module1"]["autoexec"] == []


def test_classify_target_never_resolves():
    assert dm.classify_target("\\\\198.51.100.7\\share\\x.png")["kind"] == "unc"
    assert dm.classify_target("file://198.51.100.20@SSL/DavWWWRoot/a.html")["kind"] == "webdav"
    assert dm.classify_target("http://203.0.113.10/t.dotm")["ip"] == "203.0.113.10"
    assert dm.classify_target("media/image1.png")["kind"] == "relative"


# ------------------------------------------------------------------ c10/c11: personal data
def test_personal_data_pivots_are_analyst_selected_only(tmp_path):
    res = run(tmp_path, "rich.docx", B.docx_rich_ok())
    found = pivots(res)
    author = found[("person_name", "Fulano de Tal")]
    assert author.relation == "document_author" and author.expand is False and author.confidence == pytest.approx(0.7)
    assert "privacy" in author.note
    assert found[("person_name", "Beltrano Exemplo")].relation == "document_author"  # commenter
    account = found[("username", "jdoe")]  # C:\Users\jdoe\... in the template path
    assert account.relation == "local_account" and account.expand is False and "never auto-checked" in account.note
    assert found[("username", "analyst01")].expand is False  # CORP\analyst01 (lastModifiedBy)
    assert res.attributes["document_author"] == ["Fulano de Tal"]
    assert res.attributes["document_last_modified_by"] == "CORP\\analyst01"
    assert res.attributes["document_company"] == "Example Org Ltda"
    assert all(f.severity.label == "info" for f in res.findings)  # personal fields are INFO attributes only


def test_export_redaction_unless_include_personal(tmp_path):
    analysis = dm.analyse_document(B.docx_rich_ok(), "ooxml-docx")
    meta = dm.document_metadata_fields(analysis)
    _findings, piv = dm.document_findings_and_pivots(analysis)
    red_meta, red_piv = dm.redact_for_export(meta, piv)
    assert red_meta["author"] == "[redacted]" and red_meta["last_modified_by"] == "[redacted]"
    assert "jdoe" not in json.dumps(red_meta)
    assert not [p for p in red_piv if p["relation"] in dm.PERSONAL_RELATIONS]
    assert [p for p in red_piv if p["relation"] == "external_hyperlink"]  # hostile/IOC pivots stay
    full_meta, full_piv = dm.redact_for_export(meta, piv, include_personal=True)
    assert full_meta == meta and full_piv == piv


def test_one_summary_line(tmp_path):
    res = run(tmp_path, "m.docm", B.docm_macro())
    line = res.attributes["document_summary"]
    assert "\n" not in line and line.startswith("ooxml | ") and line.endswith("HIGH: macro_autoexec")
    assert dm.document_summary_line({"format": "pdf"}, []) == "pdf | no findings"


# ------------------------------------------------------------------ safe parsing: XXE, entity expansion, zip bomb
def test_xxe_docx_is_refused_without_expansion(tmp_path):
    res = run(tmp_path, "xxe.docx", B.docx_xxe())
    f = titles(res)["Part not parsed: docProps/core.xml (unsafe_xml:doctype)"]
    assert f.severity.label == "medium"
    assert "document_author" not in res.attributes and "&xxe;" not in json.dumps(res.raw)
    assert res.attributes["document_company"] == "Example Org Ltda"  # the other parts are still read


def test_billion_laughs_docx_is_refused(tmp_path):
    res = run(tmp_path, "lol.docx", B.docx_billion_laughs())
    assert titles(res)["Part not parsed: docProps/app.xml (unsafe_xml:doctype)"].severity.label == "medium"
    assert "aaaaaaaaaa" not in json.dumps(res.raw) and "document_company" not in res.attributes


def test_zip_bomb_docx_part_is_refused(tmp_path):
    res = run(tmp_path, "bomb.docx", B.docx_zip_bomb())
    assert titles(res)["Part not parsed: docProps/core.xml (ratio)"].severity.label == "medium"
    assert res.status is Status.OK


def test_safe_xml_rejects_doctype_and_entities():
    with pytest.raises(fts.UnsafeXML):
        fts.safe_xml_parse(b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY e "x">]><a>&e;</a>')
    with pytest.raises(fts.UnsafeXML):
        fts.safe_xml_parse(b"<a>" + b"<b>" * 300 + b"</b>" * 300 + b"</a>")  # depth cap
    assert fts.safe_xml_parse(b"<a><b>ok</b></a>").find("b").text == "ok"


# ------------------------------------------------------------------ PDF details
@pytest.mark.parametrize("raw,iso", [
    ("D:20261120091500-03'00'", "2026-11-20T09:15:00-03:00"),
    ("D:20261121100000Z", "2026-11-21T10:00:00+00:00"),
    (b"D:20261120091500+05'30'", "2026-11-20T09:15:00+05:30"),
    ("D:20261125120000-03'00", "2026-11-25T12:00:00-03:00"),
    ("D:2026", "2026-01-01T00:00:00"),
    ("D:20261340990000", None),
    ("garbage", None),
    (None, None),
])
def test_pdf_dates(raw, iso):
    assert dm.pdf_date_to_iso(raw) == iso


def test_pdf_info_and_xmp(tmp_path):
    res = run(tmp_path, "fatura.pdf", B.pdf_xmp_ok())
    meta = res.attributes["document_metadata"]
    assert meta["author"] == ["Fulano de Tal"] and meta["application"] == "Microsoft Word 2016"
    assert meta["producer"] == "Microsoft: Print To PDF" and meta["created"] == "2026-11-20T09:15:00-03:00"
    xmp = dm.parse_xmp(B.XMP)
    assert xmp["creators"] == ["Fulano de Tal"] and xmp["document_id"] == "uuid:00000000-0000-4000-8000-000000000101"
    assert [h["action"] for h in xmp["history"]] == ["created", "saved"]
    assert pivots(res)[("username", "jdoe")].relation == "local_account"  # C:\Users\jdoe in the XMP title


def test_pdf_object_stream_info_and_links(tmp_path):
    res = run(tmp_path, "objstm.pdf", B.pdf_objstm_info())
    assert res.attributes["document_metadata"]["author"] == ["Beltrano Exemplo"]
    assert pivots(res, "pdf_link")[("url", "https://www.example.com/objstm")]


def test_pdf_uris_are_url_pivots(tmp_path):
    res = run(tmp_path, "emb.pdf", B.pdf_embedded_uri())
    links = pivots(res, "pdf_link")
    assert set(links) == {("url", "https://203.0.113.10/login"), ("url", "http://www.example.com/report")}  # literal + hex string
    structure = res.attributes["pdf_structure"]
    assert structure["embedded_files"] and structure["counts"]["keywords"]["/EmbeddedFile"] >= 1


def test_encrypted_pdf_is_not_decrypted(tmp_path):
    res = run(tmp_path, "enc.pdf", B.pdf_encrypted())
    assert titles(res)["Encrypted document (not decrypted)"].severity.label == "info"
    assert res.attributes["pdf_structure"]["encrypted"] is True
    assert "document_author" not in res.attributes  # encrypted strings are never shown as metadata


def test_pdf_keyword_counts_normalise_hex_names():
    counts = dm.pdf_keyword_counts(B.pdf_obfuscated_names())
    assert counts["keywords"]["/OpenAction"] == 1 and counts["keywords"]["/JavaScript"] == 1
    assert counts["obfuscated_names"] == {"/OpenAction": 1, "/JavaScript": 1, "/JS": 1}


# ------------------------------------------------------------------ OLE / VBA / XLS / MSG / RTF / ODF
def test_ole_summary_information(tmp_path):
    res = run(tmp_path, "a.doc", B.doc_no_macro())
    meta = res.attributes["document_metadata"]
    assert meta["author"] == "Beltrano Exemplo" and meta["last_modified_by"] == "jdoe" and meta["company"] == "Example Org Ltda"
    assert meta["created"] == "2026-11-20T09:15:00+00:00" and meta["template"] == "Normal.dotm"
    assert res.attributes["document_author"] == ["Beltrano Exemplo"]


def test_ovba_reference_vectors_and_round_trip():
    vectors = module_fixture(DocumentMetadata, "ovba_compression_vectors.json")["vectors"]
    for v in vectors:
        assert dm.vba_decompress(bytes.fromhex(v["compressed_hex"])) == v["text"].encode()
    for text in (B.VBA_SOURCE, B.VBA_BENIGN * 200):
        assert dm.vba_decompress(B.ovba_compress(text.encode("cp1252"))) == text.encode("cp1252")


@pytest.mark.parametrize("bad", [b"", b"\x02abc", b"\x01\xff\xbf" + b"\xff" * 10, b"\x01\x00\xb0\x01\x00\xff\xff"])
def test_vba_decompress_rejects_corrupt_input(bad):
    try:
        out = dm.vba_decompress(bad)
    except ValueError:
        return
    assert len(out) <= 4096  # a corrupt chunk never yields more than one chunk of output


def test_xls_biff_globals():
    info = dm.xls_biff_globals(B.xls_workbook([("Planilha1", 0, 0), ("Macro1", 1, 2)], autoopen=True))
    sheets = {s["name"]: s for s in info["sheets"]}
    assert sheets["Macro1"]["type"] == "xlm_macro" and sheets["Macro1"]["state"] == "very_hidden"
    assert info["autoexec_names"]


def test_encrypted_ooxml_container(tmp_path):
    res = run(tmp_path, "protegido.docx", B.ole_encrypted_ooxml())
    assert titles(res)["Encrypted document (not decrypted)"].severity.label == "info" and res.status is Status.OK


def test_outlook_msg(tmp_path):
    res = run(tmp_path, "fatura.msg", B.msg_ok())
    found = titles(res)
    assert found['Suspicious double extension ".pdf.exe" (attachment boleto.pdf.exe)'].severity.label == "high"
    assert found["Executable attachment: boleto.pdf.exe"].severity.label == "medium"
    att = pivots(res, "attachment")[("sha256", hashlib.sha256(B.pe32_exe()).hexdigest())]
    assert att.expand is True
    assert set(pivots(res, "link_in_message")) == {("url", "https://www.example.com/fatura"), ("url", "http://203.0.113.77/boleto.zip")}
    sender = pivots(res, "message_sender")[("person_name", "Remetente Exemplo")]
    assert sender.expand is False and "privacy" in sender.note
    assert res.attributes["email_attachments"][0]["filename"] == "boleto.pdf.exe"
    dumped = json.dumps([res.raw, res.attributes], default=str)
    assert "destinatario" not in dumped.lower()  # recipients are counted, never stored


def test_rtf_info_group(tmp_path):
    res = run(tmp_path, "carta.rtf", B.RTF_OK)
    meta = res.attributes["document_metadata"]
    assert meta["author"] == "Fulano de Tal" and meta["last_modified_by"] == "analyst01" and meta["company"] == "Example Org Ltda"
    assert meta["created"] == "2026-11-20T09:15:00"


def test_odf_template_path_and_generator(tmp_path):
    res = run(tmp_path, "relatorio.odt", B.odt_ok())
    meta = res.attributes["document_metadata"]
    assert meta["author"] == "Fulano de Tal" and meta["last_modified_by"] == "analyst01"
    assert meta["application"].startswith("LibreOffice/24.2")
    assert pivots(res, "local_account")[("username", "jdoe")].expand is False


# ------------------------------------------------------------------ malformed input, input cap, pivot cap
def test_truncated_ole_document_is_an_error(tmp_path):
    res = run(tmp_path, "quebrado.doc", B.doc_no_macro()[:1536])
    assert res.status is Status.ERROR and res.error.startswith("document not parsed")


def test_input_cap_is_reported(tmp_path, monkeypatch):
    monkeypatch.setitem(fts.LIMITS, "max_input", 2048)
    res = run(tmp_path, "grande.pdf", B.pdf_xmp_ok() + b"%" + b"x" * 8192 + b"\n")
    f = titles(res)["Document larger than the 100 MB input cap: only the first 100 MB were parsed"]
    assert f.severity.label == "low"


def test_pivot_cap(tmp_path):
    links = [(f"rId{i}", B.R + "hyperlink", f"https://www.example.com/p/{i}", True) for i in range(10, 400)]
    data = B.ooxml([("[Content_Types].xml", B.CT_DOCX.format(extra="")), ("_rels/.rels", B.ROOT_RELS),
                    ("word/document.xml", B.doc_xml("<w:p/>")), ("word/_rels/document.xml.rels", B.rels(*links)),
                    ("docProps/core.xml", B.core_xml("Fulano de Tal", "analyst01")), ("docProps/app.xml", B.app_xml())])
    res = run(tmp_path, "links.docx", data)
    assert res.status is Status.OK and 0 < len(res.pivots) <= DocumentMetadata.max_pivots
    assert len(json.dumps(res.raw, default=str)) <= fts.LIMITS["max_output_json"]
