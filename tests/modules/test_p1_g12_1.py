"""Batch p1-G12-1 (P269 document_metadata, P270 file_type_sniff, P364 apk_triage, P365 archive_listing).

This file hosts the synthetic fixture builders the final conditions ask for ("fixtures built in tests":
P269 c12, P270 c6, P364 c8, P365 c8) - pure functions returning bytes, shared by
tests/modules/test_{file_type_sniff,document_metadata,apk_triage,archive_listing}.py - plus batch-level
tests (routing table, stdlib-only parsers, every module offline through the engine).

Every value is a documentation value: example.com / example.org / example.net, 192.0.2.x, 198.51.100.x,
203.0.113.x, 'Fulano de Tal' / 'Beltrano Exemplo' (Brazilian placeholder names), 'jdoe' / 'analyst01'
placeholder accounts. Payload-like strings are inert text and nothing is ever executed. The two X.509
certificates in tests/fixtures/apk_triage/ are self-signed throwaway test certificates (public data only,
their keys were discarded); v1 APK signatures here are certificate-only PKCS#7 containers (the parser reads
certificates, never verifies signatures).
"""

from __future__ import annotations

import ast
import binascii
import bz2
import datetime as dt
import gzip
import hashlib
import io
import lzma
import os
import random
import struct
import sys
import tarfile
import uuid
import zlib
from pathlib import Path

import pytest

from tests.fakes import make_ctx, run_module
from v3lum.core.http import PolicyError
from v3lum.core.models import Status

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
RNG = random.Random(20261126)
FIXED_DT = (2026, 11, 25, 12, 0, 0)
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def write(tmp_path: Path, name: str, data: bytes) -> str:
    """Write a fixture under pytest's tmp_path and return its path (FILE entities need a real file)."""
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return str(p)


# ============================================================================================= ZIP writer


def _dos(dtt=FIXED_DT):
    y, mo, d, h, mi, s = dtt
    return ((y - 1980) << 9) | (mo << 5) | d, (h << 11) | (mi << 5) | (s // 2)


def zip_bytes(entries, comment=b""):
    """entries: dicts name, data, method (0/8), flags, extra, external_attr, create_system, crc/size
    overrides, raw_name (bytes), local_name, comp (pre-compressed), declared_size, force_offset."""
    out = bytearray()
    cd = bytearray()
    ddate, dtime = _dos()
    for e in entries:
        raw_name = e.get("raw_name") or e["name"].encode("utf-8")
        data = e.get("data", b"")
        method = e.get("method", 8)
        if "comp" in e:
            comp = e["comp"]
        elif method == 8:
            c = zlib.compressobj(9, zlib.DEFLATED, -15)
            comp = c.compress(data) + c.flush()
        else:
            comp = data
        crc = e.get("crc", binascii.crc32(data) & 0xFFFFFFFF)
        usize = e.get("declared_size", len(data))
        flags = e.get("flags", 0x800 if any(b > 0x7F for b in raw_name) else 0)
        extra = e.get("extra", b"")
        local_name = e.get("local_name", raw_name)
        off = e.get("force_offset", len(out))
        if "force_offset" not in e:
            out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, e.get("local_method", method), dtime, ddate, crc, len(comp), usize,
                               len(local_name), len(extra)) + local_name + extra + comp
        made_by = (e.get("create_system", 0) << 8) | 20
        cd += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, made_by, 20, flags, method, dtime, ddate, crc, len(comp), usize, len(raw_name),
                          len(extra), 0, 0, 0, e.get("external_attr", 0), off)
        cd += raw_name + extra
    cd_off = len(out)
    out += cd
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(cd), cd_off, len(comment))
    out += comment
    return bytes(out)


def _crc_table():
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        table.append(c)
    return table


_CRC = _crc_table()


def _zc_update(keys, c):
    k0 = (keys[0] >> 8) ^ _CRC[(keys[0] ^ c) & 0xFF]
    k1 = ((keys[1] + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
    k2 = (keys[2] >> 8) ^ _CRC[(keys[2] ^ (k1 >> 24)) & 0xFF]
    keys[0], keys[1], keys[2] = k0, k1, k2


def zipcrypto_encrypt(plain, password, check):
    keys = [0x12345678, 0x23456789, 0x34567890]
    for c in password:
        _zc_update(keys, c)
    header = bytes(RNG.getrandbits(8) for _ in range(11)) + bytes([check])
    out = bytearray()
    for c in header + plain:
        t = (keys[2] | 2) & 0xFFFF
        out.append(c ^ (((t * (t ^ 1)) >> 8) & 0xFF))
        _zc_update(keys, c)
    return bytes(out)


# ============================================================================================= PDF writer


def pdf_bytes(objs, *, root=1, info=None, header=b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n", trailer_extra=b""):
    out = bytearray(header)
    offs = {}
    for num in sorted(objs):
        offs[num] = len(out)
        out += b"%d 0 obj\n" % num + objs[num] + b"\nendobj\n"
    xref = len(out)
    n = max(objs) + 1
    out += b"xref\n0 %d\n0000000000 65535 f \n" % n
    for i in range(1, n):
        out += (b"%010d 00000 n \n" % offs[i]) if i in offs else b"0000000000 65535 f \n"
    out += b"trailer\n<< /Size %d /Root %d 0 R" % (n, root)
    if info:
        out += b" /Info %d 0 R" % info
    out += trailer_extra + b" >>\nstartxref\n%d\n" % xref + b"%%EOF\n"
    return bytes(out)


def pdf_stream(data, extra=b""):
    return b"<< /Length %d%s >>\nstream\n" % (len(data), extra) + data + b"\nendstream"


XMP = ('<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?>'
       '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
       '<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmp="http://ns.adobe.com/xap/1.0/"'
       ' xmlns:pdf="http://ns.adobe.com/pdf/1.3/" xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/"'
       ' xmlns:stEvt="http://ns.adobe.com/xap/1.0/sType/ResourceEvent#" xmp:CreatorTool="Microsoft Word 2016"'
       ' xmp:CreateDate="2026-11-20T09:15:00-03:00" pdf:Producer="Microsoft: Print To PDF"'
       ' xmpMM:DocumentID="uuid:00000000-0000-4000-8000-000000000101"'
       ' xmpMM:InstanceID="uuid:00000000-0000-4000-8000-000000000102">'
       "<dc:creator><rdf:Seq><rdf:li>Fulano de Tal</rdf:li></rdf:Seq></dc:creator>"
       '<dc:title><rdf:Alt><rdf:li xml:lang="x-default">C:\\Users\\jdoe\\Desktop\\fatura_novembro.docx</rdf:li></rdf:Alt></dc:title>'
       '<xmpMM:History><rdf:Seq><rdf:li stEvt:action="created" stEvt:softwareAgent="Microsoft Word 2016"'
       ' stEvt:when="2026-11-20T09:15:00-03:00"/><rdf:li stEvt:action="saved" stEvt:softwareAgent="Adobe Acrobat 23.0"'
       ' stEvt:when="2026-11-21T10:00:00-03:00" stEvt:instanceID="xmp.iid:0000000000000103"/></rdf:Seq></xmpMM:History>'
       '</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>').encode("utf-8")
PDF_PAGE = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] >>"
PDF_PAGES = b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"


def pdf_xmp_ok():
    return pdf_bytes({1: b"<< /Type /Catalog /Pages 2 0 R /Metadata 5 0 R >>", 2: PDF_PAGES, 3: PDF_PAGE,
                      4: b"<< /Title (fatura_novembro) /Author (Fulano de Tal) /Creator (Microsoft Word 2016) "
                         b"/Producer (Microsoft: Print To PDF) /CreationDate (D:20261120091500-03'00') /ModDate (D:20261121100000Z) >>",
                      5: pdf_stream(XMP, b" /Type /Metadata /Subtype /XML")}, info=4)


def pdf_openaction_js():
    return pdf_bytes({1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>", 2: PDF_PAGES, 3: PDF_PAGE,
                      5: b"<< /Type /Action /S /JavaScript /JS (app.alert\\('V3LUM fixture'\\);) >>"})


def pdf_launch():
    return pdf_bytes({1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /Launch /Win << /F (cmd.exe) /P (/c echo v3lum-fixture) >> >> >>",
                      2: PDF_PAGES, 3: PDF_PAGE})


def pdf_embedded_uri():
    emb = b"synthetic embedded attachment for the V3LUM fixture\n"
    return pdf_bytes({
        1: b"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(boleto.txt) 6 0 R] >> >> >>", 2: PDF_PAGES,
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] /Annots [4 0 R 8 0 R] >>",
        4: b"<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /A << /S /URI /URI (https://203.0.113.10/login) >> >>",
        6: b"<< /Type /Filespec /F (boleto.txt) /UF (boleto.txt) /EF << /F 7 0 R >> >>",
        7: pdf_stream(emb, b" /Type /EmbeddedFile /Params << /Size %d >>" % len(emb)),
        8: b"<< /Type /Annot /Subtype /Link /Rect [10 10 20 20] /A << /S /URI /URI <687474703a2f2f7777772e6578616d706c652e636f6d2f7265706f7274> >> >>"})


def pdf_obfuscated_names():
    return pdf_bytes({1: b"<< /Type /Catalog /Pages 2 0 R /Open#41ction 5 0 R >>", 2: PDF_PAGES, 3: PDF_PAGE,
                      5: b"<< /S /J#61vaScript /J#53 (app.alert\\(1\\);) >>"})


def pdf_no_metadata():
    return pdf_bytes({1: b"<< /Type /Catalog /Pages 2 0 R >>", 2: PDF_PAGES, 3: PDF_PAGE})


def pdf_objstm_info():
    """PDF 1.5 shape: the Info dictionary and a /URI annotation live inside a Flate object stream."""
    objs_text = (b"4 0 9 120 << /Title (Relatorio) /Author (Beltrano Exemplo) /Producer (Example PDF Library 3.1) "
                 b"/CreationDate (D:20261120091500Z) >>"
                 b" << /Type /Annot /Subtype /Link /A << /S /URI /URI (https://www.example.com/objstm) >> >>")
    first = objs_text.index(b"<<")
    header = objs_text[:first]
    comp = zlib.compress(objs_text)
    objstm = b"<< /Type /ObjStm /N 2 /First %d /Filter /FlateDecode /Length %d >>\nstream\n" % (len(header), len(comp)) + comp + b"\nendstream"
    return pdf_bytes({1: b"<< /Type /Catalog /Pages 2 0 R >>", 2: PDF_PAGES, 3: PDF_PAGE, 10: objstm}, info=4)


def pdf_encrypted():
    return pdf_bytes({1: b"<< /Type /Catalog /Pages 2 0 R >>", 2: PDF_PAGES, 3: PDF_PAGE,
                      4: b"<< /Author <9f3c27aa41> /Producer <77ee01> >>",
                      6: b"<< /Filter /Standard /V 2 /R 3 /Length 128 /P -4 /O <00> /U <00> >>"},
                     info=4, trailer_extra=b" /Encrypt 6 0 R /ID [<00112233><00112233>]")


# ============================================================================================= OOXML / ODF

CT_DOCX = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
           '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
           '<Default Extension="xml" ContentType="application/xml"/>'
           '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.'
           'wordprocessingml.document.main+xml"/>{extra}</Types>')
ROOT_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
             '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
             '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
             '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
             "</Relationships>")
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
W_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'


def core_xml(creator, last, created="2026-11-20T09:15:00Z", title="Fatura novembro", doctype=""):
    return (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>{doctype}'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"'
            ' xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"'
            ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f"<dc:title>{title}</dc:title><dc:creator>{creator}</dc:creator><cp:lastModifiedBy>{last}</cp:lastModifiedBy>"
            f'<cp:revision>4</cp:revision><dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>'
            '<dcterms:modified xsi:type="dcterms:W3CDTF">2026-11-21T10:00:00Z</dcterms:modified></cp:coreProperties>')


def app_xml(company="Example Org Ltda", template="Normal.dotm", app="Microsoft Office Word", extra=""):
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
            f"<Template>{template}</Template><TotalTime>12</TotalTime><Application>{app}</Application>"
            f"<DocSecurity>0</DocSecurity><Company>{company}</Company><AppVersion>16.0000</AppVersion>{extra}</Properties>")


def rels(*items):
    body = ""
    for rid, rtype, target, external in items:
        mode = ' TargetMode="External"' if external else ""
        body += f'<Relationship Id="{rid}" Type="{rtype}" Target="{target}"{mode}/>'
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{body}</Relationships>')


def doc_xml(body):
    return f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document {W_NS}><w:body>{body}</w:body></w:document>'


def ooxml(parts, method=8):
    return zip_bytes([{"name": n, "data": d.encode("utf-8") if isinstance(d, str) else d, "method": method} for n, d in parts])


def docx_rich_ok():
    custom = ('<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" '
              'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><property '
              'fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="MSIP_Label_00000000-0000-4000-8000-0000000000aa_SiteId">'
              '<vt:lpwstr>00000000-0000-4000-8000-0000000000bb</vt:lpwstr></property><property fmtid='
              '"{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="3" name="Projeto"><vt:lpwstr>Cobranca</vt:lpwstr></property></Properties>')
    return ooxml([
        ("[Content_Types].xml", CT_DOCX.format(extra='<Override PartName="/docProps/custom.xml" ContentType="application/'
                                                     'vnd.openxmlformats-officedocument.custom-properties+xml"/>')),
        ("_rels/.rels", ROOT_RELS),
        ("word/document.xml", doc_xml('<w:p><w:hyperlink r:id="rId5"><w:r><w:t>site</w:t></w:r></w:hyperlink></w:p>')),
        ("word/_rels/document.xml.rels", rels(("rId5", R + "hyperlink", "https://www.example.com/contato", True),
                                              ("rId6", R + "comments", "comments.xml", False))),
        ("word/comments.xml", f'<?xml version="1.0"?><w:comments {W_NS}><w:comment w:id="0" w:author="Beltrano Exemplo" '
                              'w:initials="BE"><w:p/></w:comment></w:comments>'),
        ("docProps/core.xml", core_xml("Fulano de Tal", "CORP\\analyst01")),
        ("docProps/app.xml", app_xml(template="C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Templates\\Normal.dotm")),
        ("docProps/custom.xml", custom)])


def docx_remote_template():
    return ooxml([
        ("[Content_Types].xml", CT_DOCX.format(extra="")), ("_rels/.rels", ROOT_RELS),
        ("word/document.xml", doc_xml("<w:p><w:r><w:t>Fatura</w:t></w:r></w:p>")),
        ("word/settings.xml", f'<?xml version="1.0"?><w:settings {W_NS}><w:attachedTemplate r:id="rId1"/></w:settings>'),
        ("word/_rels/settings.xml.rels", rels(("rId1", R + "attachedTemplate", "http://203.0.113.10/templates/fatura.dotm", True))),
        ("word/webSettings.xml", f'<?xml version="1.0"?><w:webSettings {W_NS}/>'),
        ("word/_rels/webSettings.xml.rels", rels(("rId1", R + "frame", "file://198.51.100.20@SSL/DavWWWRoot/frame.html", True))),
        ("word/_rels/document.xml.rels", rels(("rId7", R + "image", "\\\\198.51.100.7\\share\\pixel.png", True),
                                              ("rId8", R + "hyperlink", "https://www.example.com/ajuda", True),
                                              ("rId9", R + "oleObject", "mhtml:http://3405803786/obj.html!x-usc:http://3405803786/obj.html", True))),
        ("docProps/core.xml", core_xml("Fulano de Tal", "analyst01")), ("docProps/app.xml", app_xml())])


def docx_xxe():
    decl = "<!DOCTYPE cp:coreProperties [<!ENTITY xxe SYSTEM " + '"file:///dev/null">]>'
    return ooxml([("[Content_Types].xml", CT_DOCX.format(extra="")), ("_rels/.rels", ROOT_RELS), ("word/document.xml", doc_xml("<w:p/>")),
                  ("docProps/core.xml", core_xml("&xxe;", "analyst01", doctype=decl)), ("docProps/app.xml", app_xml())])


def docx_billion_laughs():
    lol = ('<!DOCTYPE Properties [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
           '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>')
    app = app_xml().replace('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>', '<?xml version="1.0"?>' + lol).replace("Example Org Ltda", "&c;")
    return ooxml([("[Content_Types].xml", CT_DOCX.format(extra="")), ("_rels/.rels", ROOT_RELS), ("word/document.xml", doc_xml("<w:p/>")),
                  ("docProps/core.xml", core_xml("Fulano de Tal", "analyst01")), ("docProps/app.xml", app)])


def docx_zip_bomb():
    bomb_core = core_xml("Fulano de Tal", "analyst01").replace("</cp:coreProperties>", "<!--" + " " * (8 << 20) + "--></cp:coreProperties>")
    return ooxml([("[Content_Types].xml", CT_DOCX.format(extra="")), ("_rels/.rels", ROOT_RELS), ("word/document.xml", doc_xml("<w:p/>")),
                  ("docProps/core.xml", bomb_core), ("docProps/app.xml", app_xml())])


def docx_dde():
    body = ('<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> DD</w:instrText>'
            '</w:r><w:r><w:instrText xml:space="preserve">EAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k echo v3lum-fixture"'
            '</w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>x</w:t></w:r><w:r>'
            '<w:fldChar w:fldCharType="end"/></w:r></w:p><w:p><w:fldSimple w:instr=\' INCLUDEPICTURE "http://198.51.100.40/'
            "t.png\" \\d '><w:r><w:t>i</w:t></w:r></w:fldSimple></w:p>")
    return ooxml([("[Content_Types].xml", CT_DOCX.format(extra="")), ("_rels/.rels", ROOT_RELS), ("word/document.xml", doc_xml(body)),
                  ("docProps/core.xml", core_xml("Fulano de Tal", "analyst01")), ("docProps/app.xml", app_xml())])


def xlsm_xlm_macrosheet():
    xl = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    return ooxml([
        ("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                                '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/></Types>'),
        ("_rels/.rels", ROOT_RELS.replace("word/document.xml", "xl/workbook.xml")),
        ("xl/workbook.xml", f'<?xml version="1.0"?><workbook xmlns="{xl}" xmlns:r="{R[:-1]}"><sheets>'
                            '<sheet name="Planilha1" sheetId="1" r:id="rId1"/><sheet name="Macro1" sheetId="2" state="veryHidden" r:id="rId2"/>'
                            '</sheets><definedNames><definedName name="_xlnm.Auto_Open">Macro1!$A$1</definedName></definedNames></workbook>'),
        ("xl/_rels/workbook.xml.rels", rels(("rId1", R + "worksheet", "worksheets/sheet1.xml", False),
                                            ("rId2", "http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet",
                                             "macrosheets/sheet1.xml", False))),
        ("xl/worksheets/sheet1.xml", f'<?xml version="1.0"?><worksheet xmlns="{xl}"/>'),
        ("xl/macrosheets/sheet1.xml", '<?xml version="1.0"?><xm:macrosheet xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main">'
                                      "<sheetData/></xm:macrosheet>"),
        ("docProps/core.xml", core_xml("Fulano de Tal", "analyst01")), ("docProps/app.xml", app_xml(app="Microsoft Excel"))])


def docm_macro():
    vba_bin = cfb_bytes(vba_streams("", [("ThisDocument", "doc", VBA_SOURCE)]))
    ct = CT_DOCX.format(extra="").replace("document.main+xml", "document.macroEnabled.main+xml").replace(
        "</Types>", '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>')
    return ooxml([("[Content_Types].xml", ct), ("_rels/.rels", ROOT_RELS), ("word/document.xml", doc_xml("<w:p/>")),
                  ("word/_rels/document.xml.rels", rels(("rId1", "http://schemas.microsoft.com/office/2006/relationships/vbaProject",
                                                         "vbaProject.bin", False))),
                  ("word/vbaProject.bin", vba_bin), ("docProps/core.xml", core_xml("Fulano de Tal", "analyst01")), ("docProps/app.xml", app_xml())])


ODF_META = ('<?xml version="1.0" encoding="UTF-8"?><office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:'
            'xmlns:office:1.0" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:dc="http://purl.org/dc/'
            'elements/1.1/" xmlns:xlink="http://www.w3.org/1999/xlink" office:version="1.3"><office:meta>'
            "<meta:generator>LibreOffice/24.2.7.2$Linux_X86_64</meta:generator><dc:title>Relatorio</dc:title>"
            "<meta:initial-creator>Fulano de Tal</meta:initial-creator><dc:creator>analyst01</dc:creator>"
            "<meta:creation-date>2026-11-20T09:15:00</meta:creation-date><dc:date>2026-11-21T10:00:00</dc:date>"
            "<meta:editing-cycles>3</meta:editing-cycles>{tpl}</office:meta></office:document-meta>")
ODF_CONTENT = ('<?xml version="1.0" encoding="UTF-8"?><office:document-content xmlns:office="urn:oasis:names:tc:'
               'opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
               'xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:script="urn:oasis:names:tc:opendocument:xmlns:'
               'script:1.0" office:version="1.3">{scripts}<office:body><office:text><text:p><text:a xlink:type="simple" '
               'xlink:href="https://www.example.com/relatorio">link</text:a></text:p></office:text></office:body>'
               "</office:document-content>")


def odf(meta, content, extra=(), media="application/vnd.oasis.opendocument.text"):
    entries = [("/", media), ("content.xml", "text/xml"), ("meta.xml", "text/xml")] + [(n, "text/xml") for n, _ in extra]
    manifest = ('<?xml version="1.0" encoding="UTF-8"?><manifest:manifest xmlns:manifest="urn:oasis:names:tc:'
                'opendocument:xmlns:manifest:1.0" manifest:version="1.3">'
                + "".join(f'<manifest:file-entry manifest:full-path="{p}" manifest:media-type="{t}"/>' for p, t in entries)
                + "</manifest:manifest>")
    parts = [{"name": "mimetype", "data": media.encode(), "method": 0}, {"name": "meta.xml", "data": meta.encode()},
             {"name": "content.xml", "data": content.encode()}, {"name": "META-INF/manifest.xml", "data": manifest.encode()}]
    parts += [{"name": n, "data": d.encode()} for n, d in extra]
    return zip_bytes(parts)


def odt_ok():
    tpl = '<meta:template xlink:type="simple" xlink:href="file:///C:/Users/jdoe/Documents/modelo.ott" xlink:title="modelo"/>'
    return odf(ODF_META.format(tpl=tpl), ODF_CONTENT.format(scripts=""))


def odt_macro_remote_template():
    ev = ('<office:scripts><office:event-listeners><script:event-listener script:language="ooo:script" '
          'script:event-name="dom:load" xlink:href="vnd.sun.star.script:Standard.Module1.Main?language=Basic&amp;'
          'location=document" xlink:type="simple"/></office:event-listeners></office:scripts>')
    return odf(ODF_META.format(tpl='<meta:template xlink:type="simple" xlink:href="http://203.0.113.30/modelos/relatorio.ott"/>'),
               ODF_CONTENT.format(scripts=ev),
               extra=[("Basic/script-lc.xml", '<?xml version="1.0"?><library:libraries xmlns:library="http://openoffice.org/2000/library"/>'),
                      ("Basic/Standard/Module1.xml", '<?xml version="1.0"?><script:module xmlns:script="http://openoffice.org/2000/script" '
                                                     'script:name="Module1" script:language="StarBasic">Sub Main\n  MsgBox "fixture"\n'
                                                     "End Sub</script:module>")])


# ============================================================================================= VBA / CFB / OLE


def ovba_compress(data):
    """[MS-OVBA] 2.4.1 compression with copy tokens (greedy longest match per 4096-byte chunk)."""
    out = bytearray(b"\x01")
    for cstart in range(0, len(data), 4096):
        chunk = data[cstart:cstart + 4096]
        body = bytearray()
        pos = 0
        while pos < len(chunk):
            flag_at = len(body)
            body.append(0)
            flags = 0
            for bit in range(8):
                if pos >= len(chunk):
                    break
                bits = max((pos - 1).bit_length(), 4)
                max_len = (0xFFFF >> bits) + 3
                max_off = 1 << bits
                best_len, best_off = 0, 0
                for cand in range(max(0, pos - max_off), pos):
                    ln = 0
                    while ln < max_len and pos + ln < len(chunk) and chunk[cand + ln] == chunk[pos + ln]:
                        ln += 1
                    if ln > best_len:
                        best_len, best_off = ln, pos - cand
                if best_len >= 3:
                    body += struct.pack("<H", ((best_off - 1) << (16 - bits)) | (best_len - 3))
                    flags |= 1 << bit
                    pos += best_len
                else:
                    body.append(chunk[pos])
                    pos += 1
            body[flag_at] = flags
        out += struct.pack("<H", 0xB000 | ((len(body) + 2 - 3) & 0x0FFF)) + body
    return bytes(out)


def _rec(rid, body):
    return struct.pack("<HI", rid, len(body)) + body


def vba_dir_stream(modules, codepage=1252):
    d = bytearray()
    d += _rec(0x0001, struct.pack("<I", 1)) + _rec(0x0002, struct.pack("<I", 0x409))
    d += _rec(0x0014, struct.pack("<I", 0x409)) + _rec(0x0003, struct.pack("<H", codepage))
    d += _rec(0x0004, b"Project") + _rec(0x0005, b"") + _rec(0x0040, b"") + _rec(0x0006, b"") + _rec(0x003D, b"")
    d += _rec(0x0007, struct.pack("<I", 0)) + _rec(0x0008, struct.pack("<I", 0))
    d += struct.pack("<HIIH", 0x0009, 4, 0x5BC5D1E2, 6)  # PROJECTVERSION: Reserved=4 + 4 + 2 bytes
    d += _rec(0x000C, b"") + _rec(0x003C, b"")
    d += _rec(0x000F, struct.pack("<H", len(modules))) + _rec(0x0013, struct.pack("<H", 0xFFFF))
    for name, mtype in modules:
        n = name.encode("cp1252")
        d += _rec(0x0019, n) + _rec(0x0047, name.encode("utf-16-le"))
        d += _rec(0x001A, n) + _rec(0x0032, name.encode("utf-16-le"))
        d += _rec(0x001C, b"") + _rec(0x0048, b"")
        d += _rec(0x0031, struct.pack("<I", 0)) + _rec(0x001E, struct.pack("<I", 0))
        d += _rec(0x002C, struct.pack("<H", 0xFFFF)) + _rec(0x0021 if mtype == "std" else 0x0022, b"")
        d += _rec(0x002B, b"")
    d += _rec(0x0010, b"")
    return ovba_compress(bytes(d))


VBA_SOURCE = ('Attribute VB_Name = "ThisDocument"\r\nSub AutoOpen()\r\n    Dim u As String\r\n    u = "http://203.0.113.5/p.ps1"\r\n'
              "    ' V3LUM fixture: inert text, never executed\r\n    Shell \"cmd /c echo \" & u, vbHide\r\nEnd Sub\r\n")
VBA_BENIGN = 'Attribute VB_Name = "Module1"\r\nSub Totals()\r\n    MsgBox "fixture"\r\nEnd Sub\r\n'


def vba_streams(prefix, modules):
    """modules: [(name, 'doc'|'std', source)] -> [(path, bytes)] for a compound file."""
    project = ('ID="{00000000-0000-0000-0000-000000000000}"\r\n'
               + "".join(f"Document={m[0]}/&H00000000\r\n" if m[1] == "doc" else f"Module={m[0]}\r\n" for m in modules)
               + 'Name="Project"\r\n').encode("cp1252")
    out = [(f"{prefix}PROJECT", project),
           (f"{prefix}PROJECTwm", b"".join(m[0].encode() + b"\x00" + m[0].encode("utf-16-le") + b"\x00\x00" for m in modules) + b"\x00\x00"),
           (f"{prefix}VBA/_VBA_PROJECT", b"\x61\xcc\xff\xff\x00\x00\x00"),
           (f"{prefix}VBA/dir", vba_dir_stream([(m[0], m[1]) for m in modules]))]
    for name, _t, src in modules:
        out.append((f"{prefix}VBA/{name}", ovba_compress(src.encode("cp1252"))))
    return out


def cfb_bytes(streams, root_clsid=b"\x00" * 16):
    """streams: [(path, bytes)] with '/'-separated storages -> a v3 compound file (512-byte sectors, mini stream)."""
    ss, mss, cut = 512, 64, 4096
    nodes = {"": {"name": "Root Entry", "type": 5, "children": [], "data": b"", "clsid": root_clsid}}
    for path, data in streams:
        parts = path.split("/")
        for i in range(1, len(parts)):
            sp = "/".join(parts[:i])
            if sp not in nodes:
                nodes[sp] = {"name": parts[i - 1], "type": 1, "children": [], "data": b"", "clsid": b"\x00" * 16}
                nodes["/".join(parts[:i - 1])]["children"].append(sp)
        nodes[path] = {"name": parts[-1], "type": 2, "children": [], "data": data, "clsid": b"\x00" * 16}
        nodes["/".join(parts[:-1])]["children"].append(path)
    order = [""] + [p for p in nodes if p]
    sid = {p: i for i, p in enumerate(order)}

    def key(p):
        n = nodes[p]["name"]
        return (len(n), n.upper())

    def tree(children):
        children = sorted(children, key=key)
        if not children:
            return 0xFFFFFFFF, {}
        mid = len(children) // 2
        lroot, links = tree(children[:mid])
        rroot, links2 = tree(children[mid + 1:])
        links.update(links2)
        links[children[mid]] = (lroot, rroot)
        return sid[children[mid]], links

    lr, child = {}, {}
    for p, n in nodes.items():
        root, links = tree(n["children"])
        child[p] = root
        lr.update(links)
    mini, minifat, starts, big = bytearray(), [], {}, []
    for p in order[1:]:
        n = nodes[p]
        if n["type"] != 2:
            continue
        if len(n["data"]) < cut:
            if not n["data"]:
                starts[p] = 0xFFFFFFFE
                continue
            first = len(mini) // mss
            cnt = -(-len(n["data"]) // mss)
            mini += n["data"] + b"\x00" * (cnt * mss - len(n["data"]))
            minifat += [first + k + 1 for k in range(cnt - 1)] + [0xFFFFFFFE]
            starts[p] = first
        else:
            big.append(p)
    sectors = []

    def alloc(data):
        cnt = -(-len(data) // ss) if data else 0
        first = len(sectors)
        for k in range(cnt):
            sectors.append(data[k * ss:(k + 1) * ss].ljust(ss, b"\x00"))
        return first, cnt

    chains = []
    for p in big:
        first, cnt = alloc(nodes[p]["data"])
        starts[p] = first
        chains.append((first, cnt))
    ms_first, ms_cnt = alloc(bytes(mini)) if mini else (0xFFFFFFFE, 0)
    if ms_cnt:
        chains.append((ms_first, ms_cnt))
    mf = b"".join(struct.pack("<I", v) for v in minifat)
    mf_first, mf_cnt = alloc(mf) if mf else (0xFFFFFFFE, 0)
    if mf_cnt:
        chains.append((mf_first, mf_cnt))
    entries = bytearray()
    for p in order:
        n = nodes[p]
        name = n["name"].encode("utf-16-le") + b"\x00\x00"
        left, right = lr.get(p, (0xFFFFFFFF, 0xFFFFFFFF))
        if p == "":
            start, size = (ms_first if ms_cnt else 0xFFFFFFFE), len(mini)
        elif n["type"] == 2:
            start, size = starts[p], len(n["data"])
        else:
            start, size = 0, 0
        ft = 0x01DD7F0E8F1A4000 if n["type"] != 2 else 0
        entries += name.ljust(64, b"\x00") + struct.pack("<HBBIII", len(name), n["type"], 1, left, right, child[p]) + n["clsid"] \
            + struct.pack("<IQQIQ", 0, ft, ft, start, size)
    while len(entries) % ss:
        entries += b"\x00" * 64 + struct.pack("<HBBIII", 0, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF) + b"\x00" * 16 + struct.pack("<IQQIQ", 0, 0, 0, 0, 0)
    dir_first, dir_cnt = alloc(bytes(entries))
    chains.append((dir_first, dir_cnt))
    nfat = 1
    while nfat * (ss // 4) < len(sectors) + nfat:
        nfat += 1
    fat_first = len(sectors)
    fat = [0xFFFFFFFF] * (nfat * ss // 4)
    for first, cnt in chains:
        for k in range(cnt):
            fat[first + k] = first + k + 1 if k < cnt - 1 else 0xFFFFFFFE
    for k in range(nfat):
        fat[fat_first + k] = 0xFFFFFFFD
    fatb = b"".join(struct.pack("<I", v) for v in fat)
    for k in range(nfat):
        sectors.append(fatb[k * ss:(k + 1) * ss])
    difat = [fat_first + k for k in range(nfat)] + [0xFFFFFFFF] * (109 - nfat)
    header = (OLE_MAGIC + b"\x00" * 16 + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + b"\x00" * 6
              + struct.pack("<IIIIIIIII", 0, nfat, dir_first, 0, cut, mf_first if mf_cnt else 0xFFFFFFFE, mf_cnt, 0xFFFFFFFE, 0)
              + struct.pack("<109I", *difat))
    return header + b"".join(sectors)


def _ft(y, mo, d, h=12, mi=0, s=0):
    delta = dt.datetime(y, mo, d, h, mi, s) - dt.datetime(1601, 1, 1)
    return (delta.days * 86400 + delta.seconds) * 10_000_000


def propset_stream(sections):
    """sections: [(fmtid_bytes, {pid: (vt, value)})] -> PropertySetStream bytes (codepage 1252)."""
    blobs = []
    for fmtid, props in sections:
        props = dict(props)
        props.setdefault(1, (0x02, 1252))
        vals, offs = bytearray(), []
        base = 8 + 8 * len(props)
        for pid, (vt, v) in sorted(props.items()):
            offs.append((pid, base + len(vals)))
            if vt == 0x02:
                vals += struct.pack("<HHhH", vt, 0, v, 0)
            elif vt == 0x03:
                vals += struct.pack("<HHi", vt, 0, v)
            elif vt == 0x1E:
                b = v.encode("cp1252") + b"\x00"
                b += b"\x00" * (-len(b) % 4)
                vals += struct.pack("<HHI", vt, 0, len(v) + 1) + b
            elif vt == 0x40:
                vals += struct.pack("<HHQ", vt, 0, v)
        body = struct.pack("<II", 8 + 8 * len(props) + len(vals), len(props))
        body += b"".join(struct.pack("<II", pid, off) for pid, off in offs) + vals
        blobs.append((fmtid, body))
    head = struct.pack("<HHI", 0xFFFE, 0, 0x00020006) + b"\x00" * 16 + struct.pack("<I", len(blobs))
    off = len(head) + 20 * len(blobs)
    out = bytearray(head)
    for fmtid, body in blobs:
        out += fmtid + struct.pack("<I", off)
        off += len(body)
    for _, body in blobs:
        out += body
    return bytes(out)


SUMMARY = uuid.UUID("f29f85e0-4ff9-1068-ab91-08002b27b3d9").bytes_le
DOCSUMMARY = uuid.UUID("d5cdd502-2e9c-101b-9397-08002b2cf9ae").bytes_le


def summary_streams(author="Fulano de Tal", last="analyst01", template="Normal.dotm", app="Microsoft Office Word", company="Example Org Ltda"):
    si = propset_stream([(SUMMARY, {2: (0x1E, "Fatura novembro"), 4: (0x1E, author), 7: (0x1E, template), 8: (0x1E, last), 9: (0x1E, "3"),
                                    10: (0x40, 7_200_000_000), 12: (0x40, _ft(2026, 11, 20, 9, 15)), 13: (0x40, _ft(2026, 11, 21, 10, 0)),
                                    14: (0x03, 1), 18: (0x1E, app), 19: (0x03, 0)})])
    dsi = propset_stream([(DOCSUMMARY, {14: (0x1E, "Gerente Exemplo"), 15: (0x1E, company), 23: (0x03, (16 << 16) | 0)})])
    return [("\x05SummaryInformation", si), ("\x05DocumentSummaryInformation", dsi)]


def word_fib():
    fib = bytearray(1024)
    struct.pack_into("<HH", fib, 0, 0xA5EC, 0x00C1)
    struct.pack_into("<H", fib, 0x0A, 0x0200)
    return bytes(fib)


def biff_record(rtype, body):
    return struct.pack("<HH", rtype, len(body)) + body


def xls_workbook(sheets, autoopen=False):
    """BIFF8 globals: BOF, BOUNDSHEET8 records, an optional built-in Auto_Open Lbl, EOF."""
    out = bytearray(biff_record(0x0809, struct.pack("<HHHHII", 0x0600, 0x0005, 0x0DBB, 0x07CC, 0, 0)))
    for name, dtype, state in sheets:
        n = name.encode("latin-1")
        out += biff_record(0x0085, struct.pack("<IBB", 0, state, dtype) + bytes([len(n), 0]) + n)
    if autoopen:
        body = struct.pack("<HBBHHH", 0x0020, 0, 1, 11, 0, 0) + b"\x00" * 4 + b"\x00\x01"
        body += bytes([0x3A, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # inert rgce bytes
        out += biff_record(0x0018, body)
    out += biff_record(0x000A, b"")
    return bytes(out)


def doc_macro_autoopen():
    return cfb_bytes([("WordDocument", word_fib()), ("1Table", b"\x00" * 600)] + summary_streams()
                     + vba_streams("Macros/", [("ThisDocument", "doc", VBA_SOURCE), ("Module1", "std", VBA_BENIGN)]))


def doc_no_macro():
    return cfb_bytes([("WordDocument", word_fib()), ("1Table", b"\x00" * 600)] + summary_streams(author="Beltrano Exemplo", last="jdoe"))


def xls_xlm_auto_open():
    return cfb_bytes([("Workbook", xls_workbook([("Planilha1", 0, 0), ("Macro1", 1, 2)], autoopen=True))] + summary_streams(app="Microsoft Excel"))


def ole_encrypted_ooxml():
    return cfb_bytes([("EncryptionInfo", b"\x04\x00\x04\x00\x40\x00\x00\x00" + b'<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption"/>'),
                      ("EncryptedPackage", struct.pack("<Q", 4096) + bytes(RNG.getrandbits(8) for _ in range(4096)))])


def msi_installer():
    return cfb_bytes([("\u4840\u3f3f\u4577\u446c\u3b6a\u45e4\u4824", b"\x00" * 64),
                      ("\x05SummaryInformation", propset_stream([(SUMMARY, {2: (0x1E, "Installation Database"), 4: (0x1E, "Example Org"),
                                                                            18: (0x1E, "Windows Installer XML")})]))],
                     root_clsid=uuid.UUID("000c1084-0000-0000-c000-000000000046").bytes_le)


def msg_ok():
    def s(pid, text):
        return (f"__substg1.0_{pid:04X}001F", text.encode("utf-16-le"))

    streams = [("__properties_version1.0", struct.pack("<8xIIII8x", 1, 1, 1, 1)), s(0x0037, "Fatura pendente - exemplo"),
               s(0x0C1A, "Remetente Exemplo"), s(0x0C1F, "remetente@example.com"), s(0x5D01, "remetente@example.com"),
               s(0x0E04, "Destinatario Exemplo"),
               s(0x1000, "Prezado cliente, segue o boleto: https://www.example.com/fatura\r\nOu baixe em http://203.0.113.77/boleto.zip\r\n"),
               s(0x007D, "Received: from mail.example.com (mail.example.com [198.51.100.25])\r\nMessage-ID: <fixture-0001@example.com>\r\n"),
               s(0x1035, "<fixture-0001@example.com>"),
               ("__recip_version1.0_#00000000/__properties_version1.0", struct.pack("<8x")),
               ("__recip_version1.0_#00000000/" + s(0x3001, "x")[0], "Destinatario Exemplo".encode("utf-16-le")),
               ("__recip_version1.0_#00000000/" + s(0x39FE, "x")[0], "destinatario@example.com".encode("utf-16-le")),
               ("__attach_version1.0_#00000000/__properties_version1.0", struct.pack("<8x")),
               ("__attach_version1.0_#00000000/" + s(0x3707, "x")[0], "boleto.pdf.exe".encode("utf-16-le")),
               ("__attach_version1.0_#00000000/__substg1.0_37010102", pe32_exe()),
               ("__attach_version1.0_#00000000/" + s(0x370E, "x")[0], "application/octet-stream".encode("utf-16-le"))]
    return cfb_bytes(streams, root_clsid=uuid.UUID("00020d0b-0000-0000-c000-000000000046").bytes_le)


RTF_OK = (b"{\\rtf1\\ansi\\deff0{\\info{\\title Fatura}{\\author Fulano de Tal}{\\operator analyst01}"
          b"{\\company Example Org Ltda}{\\creatim\\yr2026\\mo11\\dy20\\hr9\\min15}}\\pard Fixture\\par}")
RTF_OBJUPDATE = (b"{\\rtf1{\\object\\objemb\\objupdate{\\*\\objclass Equation.3}\\objw380\\objh260{\\*\\objdata "
                 b"01050000020000000b0000004571756174696f6e2e33000000000000000000000c0000d0cf11e0a1b11ae1}}}")


# ============================================================================================= executables


def pe32_exe():
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<4sHHIIIHH", b"PE\x00\x00", 0x14C, 1, 0x67890ABC, 0, 0, 0xE0, 0x0102)
    opt = bytearray(0xE0)
    struct.pack_into("<HBBIIIIIII", opt, 0, 0x10B, 14, 0, 0x200, 0, 0, 0x1000, 0x1000, 0x1000, 0x400000)
    struct.pack_into("<IIHHHHHHIIII", opt, 32, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0)
    struct.pack_into("<HH", opt, 68, 2, 0x8140)  # GUI subsystem
    struct.pack_into("<IIIIII", opt, 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    sect = struct.pack("<8sIIIIIIHHI", b".text", 0x10, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    hdr = bytes(dos) + coff + bytes(opt) + sect
    return hdr.ljust(0x200, b"\x00") + b"\xc3".ljust(0x200, b"\x00")


def pe64_dll(dotnet=False):
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<4sHHIIIHH", b"PE\x00\x00", 0x8664, 1, 0x67890ABC, 0, 0, 0xF0, 0x2022)
    opt = bytearray(0xF0)
    struct.pack_into("<HBBIIIII", opt, 0, 0x20B, 14, 0, 0x200, 0, 0, 0x1000, 0x1000)
    struct.pack_into("<Q", opt, 24, 0x180000000)
    struct.pack_into("<IIHHHHHHIIII", opt, 32, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0)
    struct.pack_into("<HH", opt, 68, 3, 0x8160)
    struct.pack_into("<QQQQII", opt, 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    if dotnet:
        struct.pack_into("<II", opt, 112 + 14 * 8, 0x1008, 0x48)
    sect = struct.pack("<8sIIIIIIHHI", b".text", 0x10, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    hdr = bytes(dos) + coff + bytes(opt) + sect
    return hdr.ljust(0x200, b"\x00") + b"\xc3".ljust(0x200, b"\x00")


def dos_mz():
    d = bytearray(128)
    d[0:2] = b"MZ"
    struct.pack_into("<I", d, 0x3C, 0x60)
    return bytes(d)


def elf64(etype=2, interp=False):
    phnum = 2 if interp else 1
    eh = struct.pack("<4sBBBBB7sHHIQQQIHHHHHH", b"\x7fELF", 2, 1, 1, 0, 0, b"\x00" * 7, etype, 0x3E, 1, 0x400078, 64, 0, 0, 64, 56, phnum, 64, 0, 0)
    ph = struct.pack("<IIQQQQQQ", 3, 4, 0xB0, 0, 0, 28, 28, 1) if interp else b""
    ph += struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0x100, 0x100, 0x1000)
    body = (eh + ph).ljust(0xB0, b"\x00")
    if interp:
        body += b"/lib64/ld-linux-x86-64.so.2\x00"
    return body.ljust(0x100, b"\x00")


def macho64():
    return struct.pack("<IiiIIII", 0xFEEDFACF, 0x01000007, 3, 2, 0, 0, 0) + b"\x00" * 4


def macho_fat():
    return struct.pack(">II", 0xCAFEBABE, 2) + struct.pack(">iiIII", 0x01000007, 3, 4096, 32, 12) + struct.pack(">iiIII", 0x0100000C, 0, 8192, 32, 14) + b"\x00" * 32


def java_class():
    return struct.pack(">IHH", 0xCAFEBABE, 0, 52) + struct.pack(">H", 1) + b"\x00" * 16


def lnk_bytes(args="/c echo v3lum-fixture"):
    hdr = struct.pack("<I16sIIQQQIIIHHII", 0x4C, bytes.fromhex("0114020000000000c000000000000046"), 0x20 | 0x80, 0x20, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0)
    a = args.encode("utf-16-le")
    return hdr + struct.pack("<H", len(args)) + a


def png_bytes():
    png = b"\x89PNG\r\n\x1a\n"
    for typ, body in ((b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)), (b"IDAT", zlib.compress(b"\x00\x00")), (b"IEND", b"")):
        png += struct.pack(">I", len(body)) + typ + body + struct.pack(">I", binascii.crc32(typ + body) & 0xFFFFFFFF)
    return png


# ============================================================================================= APK


def _pool(strings, utf8=False):
    offs, data = [], bytearray()
    for s in strings:
        offs.append(len(data))
        if utf8:
            b = s.encode("utf-8")
            u16 = len(s.encode("utf-16-le")) // 2
            data += bytes([u16]) if u16 < 0x80 else struct.pack(">H", u16 | 0x8000)
            data += bytes([len(b)]) if len(b) < 0x80 else struct.pack(">H", len(b) | 0x8000)
            data += b + b"\x00"
        else:
            u = s.encode("utf-16-le")
            data += struct.pack("<H", len(u) // 2) + u + b"\x00\x00"
    data += b"\x00" * (-len(data) % 4)
    hsize = 28
    body = struct.pack("<IIIII", len(strings), 0, 0x100 if utf8 else 0, hsize + 4 * len(strings), 0) + b"".join(struct.pack("<I", o) for o in offs) + bytes(data)
    return struct.pack("<HHI", 0x0001, hsize, 8 + len(body)) + body


def _attr_res():
    from v3lum.modules.file_analysis.apk_triage import ANDROID_ATTR_IDS

    return {v: k for k, v in ANDROID_ATTR_IDS.items()}


ANDROID_URI = "http://schemas.android.com/apk/res/android"


def axml_encode(root, utf8=False):
    """root = (tag, [(name, value, is_android)], [children]) -> binary AndroidManifest.xml."""
    attr_res = _attr_res()
    attr_names = []

    def collect(n):
        for name, _v, is_android in n[1]:
            if is_android and name in attr_res and name not in attr_names:
                attr_names.append(name)
        for c in n[2]:
            collect(c)

    collect(root)
    strings = list(attr_names)

    def idx(s):
        if s not in strings:
            strings.append(s)
        return strings.index(s)

    for s in ("android", ANDROID_URI):
        idx(s)
    chunks = []

    def walk(n):
        tag, attrs, kids = n
        ab = b""
        for name, v, is_android in attrs:
            ns = idx(ANDROID_URI) if is_android else 0xFFFFFFFF
            nm = idx(name)
            if isinstance(v, bool):
                raw, dtype, data = 0xFFFFFFFF, 0x12, 0xFFFFFFFF if v else 0
            elif isinstance(v, int):
                raw, dtype, data = 0xFFFFFFFF, 0x10, v & 0xFFFFFFFF
            elif isinstance(v, tuple):
                raw, dtype, data = 0xFFFFFFFF, 0x01, v[1]
            else:
                raw = idx(v)
                dtype, data = 0x03, raw
            ab += struct.pack("<IIIHBBI", ns, nm, raw, 8, 0, dtype, data)
        t = idx(tag)
        body = struct.pack("<IIIIHHHHHH", 1, 0xFFFFFFFF, 0xFFFFFFFF, t, 20, 20, len(attrs), 0, 0, 0) + ab
        chunks.append(struct.pack("<HHI", 0x0102, 16, 8 + len(body)) + body)
        for c in kids:
            walk(c)
        chunks.append(struct.pack("<HHIIIII", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, t))

    walk(root)
    ns_start = struct.pack("<HHIIIII", 0x0100, 16, 24, 1, 0xFFFFFFFF, idx("android"), idx(ANDROID_URI))
    ns_end = struct.pack("<HHIIIII", 0x0101, 16, 24, 1, 0xFFFFFFFF, idx("android"), idx(ANDROID_URI))
    pool = _pool(strings, utf8)
    resmap = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(attr_names)) + b"".join(struct.pack("<I", attr_res[n]) for n in attr_names)
    body = pool + resmap + ns_start + b"".join(chunks) + ns_end
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def arsc_encode(package, values):
    """values: {locale: app_name} -> resources.arsc with one string resource 0x7f010000 (string/app_name)."""
    locales = list(values)
    gpool = _pool([values[loc] for loc in locales], utf8=True)
    tpool = _pool(["string"])
    kpool = _pool(["app_name"])
    spec = struct.pack("<HHIBBHI", 0x0202, 16, 20, 1, 0, 0, 1) + struct.pack("<I", 0)
    types = b""
    for i, loc in enumerate(locales):
        cfg = bytearray(64)
        struct.pack_into("<I", cfg, 0, 64)
        if loc:
            lang, _, country = loc.partition("-")
            cfg[8:10] = lang.encode()[:2]
            if country:
                cfg[10:12] = country.encode()[:2]
        hsize = 20 + 64
        entries = struct.pack("<HHI", 8, 0, 0) + struct.pack("<HBBI", 8, 0, 0x03, i)
        body = struct.pack("<BBHII", 1, 0, 0, 1, hsize + 4) + bytes(cfg) + struct.pack("<I", 0) + entries
        types += struct.pack("<HHI", 0x0201, hsize, 8 + len(body)) + body
    name = package.encode("utf-16-le")[:254].ljust(256, b"\x00")
    pkg_hsize = 288
    pkg_body = struct.pack("<I", 0x7F) + name + struct.pack("<IIIII", pkg_hsize, 0, pkg_hsize + len(tpool), 0, 0)
    pkg = struct.pack("<HHI", 0x0200, pkg_hsize, pkg_hsize + len(tpool) + len(kpool) + len(spec) + len(types)) + pkg_body + tpool + kpool + spec + types
    body = struct.pack("<I", 1) + gpool + pkg
    return struct.pack("<HHI", 0x0002, 12, 8 + len(body)) + body


def dex_encode(strings):
    strings = sorted(set(strings), key=lambda s: s.encode("utf-16-be"))
    data = bytearray()
    offs = []
    base = 0x70 + 4 * len(strings)
    for s in strings:
        offs.append(base + len(data))
        v = len(s.encode("utf-16-le")) // 2
        b = bytearray()
        while True:
            byte = v & 0x7F
            v >>= 7
            b.append(byte | (0x80 if v else 0))
            if not v:
                break
        data += bytes(b) + s.encode("utf-8").replace(b"\x00", b"\xc0\x80") + b"\x00"
    data += b"\x00" * (-len(data) % 4)
    map_off = base + len(data)
    maplist = struct.pack("<I", 4) + struct.pack("<HHII", 0x0000, 0, 1, 0) + struct.pack("<HHII", 0x0001, 0, len(strings), 0x70) \
        + struct.pack("<HHII", 0x2002, 0, len(strings), base) + struct.pack("<HHII", 0x1000, 0, 1, map_off)
    body = b"".join(struct.pack("<I", o) for o in offs) + bytes(data) + maplist
    size = 0x70 + len(body)
    hdr = bytearray(0x70)
    hdr[0:8] = b"dex\n035\x00"
    struct.pack_into("<IIIIIIII", hdr, 0x20, size, 0x70, 0x12345678, 0, 0, map_off, len(strings), 0x70)
    struct.pack_into("<II", hdr, 0x68, size - base, base)
    full = bytearray(bytes(hdr) + body)
    full[12:32] = hashlib.sha1(bytes(full[32:])).digest()
    struct.pack_into("<I", full, 8, zlib.adler32(bytes(full[12:])) & 0xFFFFFFFF)
    return bytes(full)


def manifest_tree(package, label, perms, components, version=(7, "1.2.0"), sdk=(24, 34), debuggable=None):
    app_attrs = [("label", label, True)]
    if debuggable is not None:
        app_attrs.append(("debuggable", debuggable, True))
    return ("manifest", [("versionCode", version[0], True), ("versionName", version[1], True), ("package", package, False)],
            [("uses-sdk", [("minSdkVersion", sdk[0], True), ("targetSdkVersion", sdk[1], True)], [])]
            + [("uses-permission", [("name", p, True)], []) for p in perms] + [("application", app_attrs, components)])


def cert(name):
    """The stored throwaway self-signed test certificates ('official' / 'android_debug')."""
    return (FIXTURES / "apk_triage" / f"cert_{name}.der").read_bytes()


def _tlv(tag, content):
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = b"\x81" + bytes([n])
    elif n < 0x10000:
        ln = b"\x82" + struct.pack(">H", n)
    else:
        ln = b"\x83" + n.to_bytes(3, "big")
    return bytes([tag]) + ln + content


OID_SIGNED_DATA = bytes.fromhex("06092a864886f70d010702")
OID_DATA = bytes.fromhex("06092a864886f70d010701")


def pkcs7_with_cert(cert_der):
    """A certificate-only CMS SignedData (APK v1 META-INF/CERT.RSA shape; no signer info, nothing to verify)."""
    signed = _tlv(0x30, _tlv(0x02, b"\x01") + _tlv(0x31, b"") + _tlv(0x30, OID_DATA) + _tlv(0xA0, cert_der) + _tlv(0x31, b""))
    return _tlv(0x30, OID_SIGNED_DATA + _tlv(0xA0, signed))


def v1_signature(files, cert_der):
    mf = b"Manifest-Version: 1.0\r\nCreated-By: v3lum-fixture\r\n\r\n"
    import base64

    for n, d in files:
        mf += b"Name: %s\r\nSHA-256-Digest: %s\r\n\r\n" % (n.encode(), base64.b64encode(hashlib.sha256(d).digest()))
    sf = b"Signature-Version: 1.0\r\nCreated-By: v3lum-fixture\r\nSHA-256-Digest-Manifest: %s\r\n\r\n" % base64.b64encode(hashlib.sha256(mf).digest())
    return [("META-INF/MANIFEST.MF", mf), ("META-INF/CERT.SF", sf), ("META-INF/CERT.RSA", pkcs7_with_cert(cert_der))]


def _lp(b):
    return struct.pack("<I", len(b)) + b


def spki_of(cert_der):
    from v3lum.modules.file_analysis.apk_triage import x509_summary

    return x509_summary(cert_der)["spki_der"]


def sig_block(cert_der, schemes=("v2", "v3"), pubkey=None):
    pubkey = spki_of(cert_der) if pubkey is None else pubkey
    pairs = []
    for scheme in schemes:
        digests = _lp(_lp(struct.pack("<I", 0x0103) + _lp(b"\x00" * 32)))
        certs = _lp(_lp(cert_der))
        sigs = _lp(_lp(struct.pack("<I", 0x0103) + _lp(b"\x00" * 256)))  # placeholder: not a real signature
        if scheme == "v2":
            signer = _lp(digests + certs + _lp(b"")) + sigs + _lp(pubkey)
            pid = 0x7109871A
        else:
            signer = _lp(digests + certs + struct.pack("<II", 24, 0x7FFFFFFF) + _lp(b"")) + struct.pack("<II", 24, 0x7FFFFFFF) + sigs + _lp(pubkey)
            pid = 0xF05368C0
        pairs.append((pid, _lp(_lp(signer))))
    pairs.append((0x42726577, b"\x00" * 12))
    body = b"".join(struct.pack("<QI", len(v) + 4, i) + v for i, v in pairs)
    size = len(body) + 8 + 16
    return struct.pack("<Q", size) + body + struct.pack("<Q", size) + b"APK Sig Block 42"


def insert_sig_block(zipdata, block):
    eocd = zipdata.rfind(b"PK\x05\x06")
    cd_off = struct.unpack_from("<I", zipdata, eocd + 16)[0]
    new = zipdata[:cd_off] + block + zipdata[cd_off:]
    eocd += len(block)
    return new[:eocd + 16] + struct.pack("<I", cd_off + len(block)) + new[eocd + 20:]


DEMO_DEX_STRINGS = ["https://api.example.com/v1/telemetry", "http://198.51.100.23:8080/gate.php", "https://firebaseinstallations.googleapis.com/v1/projects",
                    "http://schemas.android.com/apk/res/android", "com.example.v3lum.demo.MainActivity", "cdn.example.net", "10.0.2.2", "v1.2.3.4",
                    "Lcom/example/v3lum/demo/MainActivity;", "com.google.android.gms.common", "nul\x00byte"]


def demo_parts():
    man = axml_encode(manifest_tree("com.example.v3lum.demo", ("ref", 0x7F010000), ["android.permission.INTERNET"], [
        ("activity", [("name", "com.example.v3lum.demo.MainActivity", True), ("exported", True, True)], [
            ("intent-filter", [], [("action", [("name", "android.intent.action.MAIN", True)], []),
                                   ("category", [("name", "android.intent.category.LAUNCHER", True)], [])])]),
        ("service", [("name", ".SyncService", True), ("exported", False, True)], [])]))
    arsc = arsc_encode("com.example.v3lum.demo", {"": "V3LUM Demo", "pt-BR": "V3LUM Demonstração"})
    return man, arsc, dex_encode(DEMO_DEX_STRINGS)


def apk_ok_v1v2v3():
    man, arsc, dex = demo_parts()
    files = [("AndroidManifest.xml", man), ("resources.arsc", arsc), ("classes.dex", dex), ("res/values/x.txt", b"fixture")]
    official = cert("official")
    z = zip_bytes([{"name": n, "data": d, "method": 0 if n == "resources.arsc" else 8} for n, d in files + v1_signature(files, official)])
    return insert_sig_block(z, sig_block(official))


BANKER_PERMS = ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.RECEIVE_SMS", "android.permission.READ_SMS",
                "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.QUERY_ALL_PACKAGES", "android.permission.RECEIVE_BOOT_COMPLETED"]


def apk_banker(label="Banco Exemplo Segurança", package="br.com.bancoexemplo.seguranca", signer="android_debug", perms=None):
    man = axml_encode(manifest_tree(package, label, BANKER_PERMS if perms is None else perms, [
        ("service", [("name", ".AccService", True), ("permission", "android.permission.BIND_ACCESSIBILITY_SERVICE", True), ("exported", False, True)],
         [("intent-filter", [], [("action", [("name", "android.accessibilityservice.AccessibilityService", True)], [])])]),
        ("receiver", [("name", ".AdminReceiver", True), ("permission", "android.permission.BIND_DEVICE_ADMIN", True)],
         [("intent-filter", [], [("action", [("name", "android.app.action.DEVICE_ADMIN_ENABLED", True)], [])])]),
        ("receiver", [("name", ".SmsReceiver", True)],
         [("intent-filter", [], [("action", [("name", "android.provider.Telephony.SMS_RECEIVED", True)], [])])])],
        version=(1, "1.0"), sdk=(23, 30), debuggable=True), utf8=True)
    dex = dex_encode(["http://203.0.113.50/api/v2/register", "wss://c2.example.org:8443/socket", "198.51.100.77", "https://app-measurement.com/a",
                      "com.bancoexemplo.Overlay"])
    files = [("AndroidManifest.xml", man), ("classes.dex", dex), ("lib/arm64-v8a/libjiagu.so", b"\x7fELF" + b"\x00" * 60),
             ("assets/update.dex", b"dex\n035\x00")]
    return insert_sig_block(zip_bytes([{"name": n, "data": d} for n, d in files]), sig_block(cert(signer), schemes=("v2",)))


def apk_dup_entries():
    man, _arsc, dex = demo_parts()
    other = axml_encode(manifest_tree("com.example.other", "Other", [], []))
    return zip_bytes([{"name": "AndroidManifest.xml", "data": man}, {"name": "classes.dex", "data": dex}, {"name": "AndroidManifest.xml", "data": other}])


def apk_bad_central_directory():
    man, arsc, dex = demo_parts()
    good = zip_bytes([{"name": n, "data": d} for n, d in (("AndroidManifest.xml", man), ("resources.arsc", arsc), ("classes.dex", dex))])
    first_cd = good.find(b"PK\x01\x02")
    bad = bytearray(good)
    bad[first_cd:first_cd + 4] = b"PK\x01\x00"
    return bytes(bad)


def apk_bomb_ratio():
    man, _arsc, _dex = demo_parts()
    return zip_bytes([{"name": "AndroidManifest.xml", "data": man}, {"name": "classes.dex", "data": b"dex\n035\x00" + b"\x00" * (4 << 20)}])


def apk_fake_encryption():
    man, _arsc, dex = demo_parts()
    return zip_bytes([{"name": "AndroidManifest.xml", "data": man, "flags": 0x1}, {"name": "classes.dex", "data": dex}])


# ============================================================================================= archives


def iso_bytes(files, volume="V3LUM_FIXTURE", udf_bridge=False):
    """files: [(path, data, hidden)] (one directory level at most) -> an ISO 9660 + Joliet image."""
    sec = 2048
    date7 = struct.pack("<BBBBBBb", 126, 11, 25, 12, 0, 0, -12)
    date17 = b"2026112512000000" + bytes([0xF4])

    def both32(v):
        return struct.pack("<I", v) + struct.pack(">I", v)

    def both16(v):
        return struct.pack("<H", v) + struct.pack(">H", v)

    def rec(name, lba, size, is_dir, hidden=False):
        n = len(name)
        body = bytes([0]) + both32(lba) + both32(size) + date7 + bytes([(0x02 if is_dir else 0) | (0x01 if hidden else 0), 0, 0]) + both16(1) + bytes([n]) + name
        if n % 2 == 0:
            body += b"\x00"
        return bytes([len(body) + 1]) + body

    dirs = sorted({os.path.dirname(p) for p, _, _ in files if os.path.dirname(p)})
    lba = 16 + 3 + (2 if udf_bridge else 0) + 4
    dir_lba = {}
    for view in ("pvd", "svd"):
        for d in [""] + dirs:
            dir_lba[(view, d)] = lba
            lba += 1
    file_lba = {}
    for p, data, _ in files:
        file_lba[p] = lba
        lba += max(1, -(-len(data) // sec))
    total = lba

    def iso_name(p, is_dir, view):
        base = os.path.basename(p)
        if view == "svd":
            return base.encode("utf-16-be")
        stem, _, ext = base.upper().rpartition(".") if "." in base else (base.upper(), "", "")

        def clean(s):
            return "".join(c if c.isalnum() else "_" for c in s)

        return (clean(stem)[:8] + ("." + clean(ext)[:3] if ext else "")).encode() + (b"" if is_dir else b";1")

    def dir_extent(view, d):
        me = dir_lba[(view, d)]
        parent = dir_lba[(view, os.path.dirname(d))] if d else dir_lba[(view, "")]
        out = rec(b"\x00", me, sec, True) + rec(b"\x01", parent, sec, True)
        for sub in [x for x in dirs if os.path.dirname(x) == d]:
            out += rec(iso_name(sub, True, view), dir_lba[(view, sub)], sec, True)
        for p, data, hidden in files:
            if os.path.dirname(p) == d:
                out += rec(iso_name(p, False, view), file_lba[p], len(data), False, hidden)
        return out.ljust(sec, b"\x00")

    def ptable(view, big):
        out = b""
        for d in [""] + dirs:
            ident = b"\x00" if not d else iso_name(d, True, view)
            out += bytes([len(ident), 0]) + struct.pack((">" if big else "<") + "IH", dir_lba[(view, d)], 1) + ident
            if len(ident) % 2:
                out += b"\x00"
        return out

    def vd(vtype, view):
        b = bytearray(sec)
        b[0] = vtype
        b[1:6] = b"CD001"
        b[6] = 1

        def enc(s, n):
            return s.encode("utf-16-be")[:n].ljust(n, b"\x00") if view == "svd" else s.encode()[:n].ljust(n, b" ")

        b[8:40] = enc("LINUX", 32)
        b[40:72] = enc(volume, 32)
        b[80:88] = both32(total)
        if view == "svd":
            b[88:91] = b"%/E"
        b[120:124] = both16(1)
        b[124:128] = both16(1)
        b[128:132] = both16(sec)
        b[132:140] = both32(len(ptable(view, False)))
        base = 19 + (2 if udf_bridge else 0)
        lpt, mpt = (base, base + 1) if view == "pvd" else (base + 2, base + 3)
        b[140:144] = struct.pack("<I", lpt)
        b[148:152] = struct.pack(">I", mpt)
        root = rec(b"\x00", dir_lba[(view, "")], sec, True)
        b[156:156 + len(root)] = root
        b[574:606] = enc("V3LUM FIXTURE BUILDER", 32)
        b[813:830] = date17
        b[830:847] = date17
        b[881] = 1
        return bytes(b)

    img = bytearray(sec * 16)
    img += vd(1, "pvd") + vd(2, "svd")
    term = bytearray(sec)
    term[0], term[1:6], term[6] = 255, b"CD001", 1
    img += term
    if udf_bridge:
        for ident in (b"BEA01", b"NSR02"):
            s = bytearray(sec)
            s[1:6], s[6] = ident, 1
            img += s
    for view in ("pvd", "svd"):
        img += ptable(view, False).ljust(sec, b"\x00") + ptable(view, True).ljust(sec, b"\x00")
    for view in ("pvd", "svd"):
        for d in [""] + dirs:
            img += dir_extent(view, d)
    for _p, data, _ in files:
        img += data.ljust(max(1, -(-len(data) // sec)) * sec, b"\x00")
    return bytes(img)


def udf_only():
    img = bytearray(2048 * 16)
    for ident in (b"BEA01", b"NSR02", b"TEA01"):
        s = bytearray(2048)
        s[1:6], s[6] = ident, 1
        img += s
    return bytes(img)


def rar5_bytes(files):
    """Minimal RAR 5 (store method) per the RARLAB technote."""
    def vint(v):
        out = bytearray()
        while True:
            b = v & 0x7F
            v >>= 7
            out.append(b | (0x80 if v else 0))
            if not v:
                return bytes(out)

    def block(htype, hflags, fields, data=b"", extra=b""):
        if extra:
            hflags |= 0x0001
        if data:
            hflags |= 0x0002
        body = vint(htype) + vint(hflags) + (vint(len(extra)) if extra else b"") + (vint(len(data)) if data else b"") + fields + extra
        size = vint(len(body))
        return struct.pack("<I", binascii.crc32(size + body) & 0xFFFFFFFF) + size + body + data

    out = b"Rar!\x1a\x07\x01\x00" + block(1, 0, vint(0))
    for name, data in files:
        nb = name.encode("utf-8")
        fields = vint(0x0004) + vint(len(data)) + vint(0x20) + struct.pack("<I", binascii.crc32(data) & 0xFFFFFFFF) + vint(0) + vint(0) + vint(len(nb)) + nb
        out += block(2, 0, fields, data)
    return out + block(5, 0, vint(0))


def cab_bytes(files):
    names = [n.encode("cp437") + b"\x00" for n, _ in files]
    data = b"".join(d for _, d in files)
    coff_files = 36 + 8
    cff = b""
    off = 0
    ddate, dtime = _dos()
    for (_n, d), nb in zip(files, names):
        cff += struct.pack("<IIHHHH", len(d), off, 0, ddate, dtime, 0x20) + nb
        off += len(d)
    cfdata_off = coff_files + len(cff)
    cfdata = struct.pack("<IHH", 0, len(data), len(data)) + data
    total = cfdata_off + len(cfdata)
    hdr = struct.pack("<4sIIIIIBBHHHHH", b"MSCF", 0, total, 0, coff_files, 0, 3, 1, 1, len(files), 0, 0x1234, 0)
    return hdr + struct.pack("<IHH", cfdata_off, 1, 0) + cff + cfdata


def sevenzip_bytes():
    nh = b"\x01\x00"
    tail = struct.pack("<QQI", 0, len(nh), binascii.crc32(nh) & 0xFFFFFFFF)
    return b"7z\xbc\xaf'\x1c\x00\x04" + struct.pack("<I", binascii.crc32(tail) & 0xFFFFFFFF) + tail + nh


def vhd_fixed(size=4096, creator=b"qemu"):
    footer = bytearray(512)
    footer[0:8] = b"conectix"
    struct.pack_into(">IIQI", footer, 8, 2, 0x00010000, 0xFFFFFFFFFFFFFFFF, 0x30D40000)
    footer[28:32] = creator
    struct.pack_into(">I", footer, 32, 0x00050003)
    footer[36:40] = b"Wi2k"
    struct.pack_into(">QQIi", footer, 40, size, size, 0x00010110, 2)
    footer[68:84] = bytes(range(16))
    struct.pack_into(">I", footer, 64, (~sum(footer)) & 0xFFFFFFFF)
    return b"\x00" * size + bytes(footer)


def vhdx_header():
    return (b"vhdxfile" + "V3LUM fixture builder".encode("utf-16-le")).ljust(4096, b"\x00")


def tar_bytes(members, mode="w"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode, format=tarfile.GNU_FORMAT) as tf:
        for m in members:
            ti = tarfile.TarInfo(m["name"])
            ti.mtime = 1764072000
            ti.uname, ti.gname = "builder", "builder"
            ti.mode = m.get("mode", 0o644)
            ti.type = m.get("type", tarfile.REGTYPE)
            ti.linkname = m.get("link", "")
            data = m.get("data", b"")
            ti.size = len(data) if ti.type == tarfile.REGTYPE else 0
            if ti.type in (tarfile.CHRTYPE, tarfile.BLKTYPE):
                ti.devmajor, ti.devminor = 8, 0
            tf.addfile(ti, io.BytesIO(data) if ti.type == tarfile.REGTYPE else None)
    return buf.getvalue()


def gzip_named(data, name):
    buf = io.BytesIO()
    with gzip.GzipFile(filename=name, mode="wb", fileobj=buf, mtime=0) as g:
        g.write(data)
    return buf.getvalue()


TINY_PDF = pdf_bytes({1: b"<< /Type /Catalog /Pages 2 0 R >>", 2: b"<< /Type /Pages /Kids [] /Count 0 >>"})
JS = b'var sh = new ActiveXObject("WScript.Shell");\nvar u = "http://203.0.113.80/p";\nfunction f(a){ return String.fromCharCode(a); }\n'
VBS = b'On Error Resume Next\r\nDim o\r\nSet o = CreateObject("WScript.Shell")\r\nWScript.Echo "fixture"\r\n'
TAR_MEMBERS = [{"name": "leia-me.txt", "data": b"tar fixture\n"}, {"name": "bin/tool.sh", "data": b"#!/bin/sh\necho x\n", "mode": 0o755},
               {"name": "data/payload.bin", "data": bytes(range(256))}]


def zip_ok():
    inner = zip_bytes([{"name": "inner/hello.txt", "data": b"hello from the inner archive\n"}])
    return zip_bytes([{"name": "leia-me.txt", "data": b"Conteudo de exemplo.\n"}, {"name": "docs/", "data": b"", "method": 0, "external_attr": 0x10},
                      {"name": "docs/relatorio.pdf", "data": TINY_PDF}, {"name": "nested.zip", "data": inner, "method": 0}])


def zip_traversal():
    up = "../" * 2
    return zip_bytes([{"name": up + "etc/cron.d/evil", "data": b"* * * * * root echo fixture\n"}, {"name": "/abs/path.txt", "data": b"x"},
                      {"name": "C:\\Windows\\Temp\\x.dll", "data": b"x"}, {"name": "ok.txt", "data": b"ok"}])


def zip_symlink():
    return zip_bytes([{"name": "link_to_hosts", "data": b"/etc/hosts", "method": 0, "create_system": 3, "external_attr": (0o120777 << 16)},
                      {"name": "readme.txt", "data": b"x", "create_system": 3, "external_attr": (0o100644 << 16)}])


def zip_bomb_ratio():
    return zip_bytes([{"name": "zeros.bin", "data": b"\x00" * (2 << 20)}])


def zip_declared_oversize():
    return zip_bytes([{"name": "huge.iso", "data": b"small", "declared_size": 600 << 20, "method": 0}])


def zip_overlap():
    return zip_bytes([{"name": "a.txt", "data": b"A" * 2048}, {"name": "b.txt", "data": b"A" * 2048, "force_offset": 0}])


def zip_encrypted_zipcrypto(password=b"infected"):
    plain = pe32_exe()
    crc = binascii.crc32(plain) & 0xFFFFFFFF
    enc = zipcrypto_encrypt(plain, password, (crc >> 24) & 0xFF)
    return zip_bytes([{"name": "amostra.exe", "data": plain, "comp": enc, "method": 0, "flags": 0x1, "crc": crc},
                      {"name": "LEIA.txt", "data": b"the archive password is in the e-mail (fixture)\n"}])


def zip_aes_flag():
    aes_extra = struct.pack("<HHH2sBH", 0x9901, 7, 2, b"AE", 3, 8)
    return zip_bytes([{"name": "secret.docx", "data": b"", "comp": bytes(RNG.getrandbits(8) for _ in range(64)), "method": 99, "flags": 0x1,
                       "extra": aes_extra, "crc": 0, "declared_size": 1000}])


def zip_nested_depth(levels=4):
    deep = zip_bytes([{"name": "deep.txt", "data": b"deepest level\n"}])
    for i in range(levels):
        deep = zip_bytes([{"name": f"level{levels - i}.zip", "data": deep, "method": 0}])
    return deep


STEALER_ROOT = "BR[203.0.113.9][DESKTOP-AB12CD3]_2026_11_20/"


def zip_stealer_bundle():
    root = STEALER_ROOT
    return zip_bytes([{"name": root + "Passwords.txt", "data": b"SYNTHETIC PLACEHOLDER - no credentials\n"},
                      {"name": root + "Cookies/Chrome_Default.txt", "data": b"SYNTHETIC PLACEHOLDER\n"},
                      {"name": root + "Autofill/Chrome_Default.txt", "data": b"SYNTHETIC PLACEHOLDER\n"},
                      {"name": root + "System Info.txt", "data": b"SYNTHETIC PLACEHOLDER\n"},
                      {"name": root + "Wallets/Exodus/exodus.wallet", "data": b"SYNTHETIC PLACEHOLDER\n"},
                      {"name": root + "user@example.com/Screenshot.jpg", "data": b"\xff\xd8\xff"}])


def zip_lure_br():
    pe = pe32_exe()
    return zip_bytes([{"name": "Fatura_Novembro_2026.pdf.exe", "data": pe}, {"name": "boleto.js", "data": JS}, {"name": "comprovante.vbs", "data": VBS},
                      {"name": "leia-me.txt", "data": b"Abra a fatura.\n"}, {"name": "nota.pdf", "data": pe}])


def zip_winrar_trap():
    return zip_bytes([{"name": "documento.pdf ", "data": b"%PDF-1.4 fixture"}, {"name": "documento.pdf /", "data": b"", "method": 0},
                      {"name": "documento.pdf /documento.pdf .cmd", "data": b"@echo off\r\necho fixture\r\n"}])


def iso_lnk_motw():
    return iso_bytes([("Fatura 2026.pdf.lnk", lnk_bytes(), False), ("payload.dll", pe64_dll(), True), ("LEIA.txt", b"Abra o atalho.\n", False)])


def iso_ok():
    return iso_bytes([("README.TXT", b"benign iso fixture\n", False), ("docs/manual.pdf", TINY_PDF, False)], volume="DOCS_2026")


# ============================================================================================= batch-level tests

MODULE_FILES = ("file_type_sniff", "document_metadata", "apk_triage", "archive_listing")


def test_parsers_import_only_stdlib_and_core():
    """c5/P270 c4: no network client, process or third-party import in the four module files (hachoir,
    magika, libmagic, pypdf, olefile... are never imported; py7zr only dynamically through importlib)."""
    root = Path(__file__).resolve().parents[2] / "v3lum" / "modules" / "file_analysis"
    forbidden = {"socket", "ssl", "http", "urllib.request", "ftplib", "smtplib", "subprocess", "ctypes", "requests", "asyncio", "hachoir",
                 "magic", "magika", "pypdf", "olefile", "oletools", "androguard", "rarfile", "py7zr", "pycdlib", "filetype"}
    for name in MODULE_FILES:
        tree = ast.parse((root / f"{name}.py").read_text(encoding="utf-8"))
        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods |= {a.name for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods.add(node.module)
        assert not {m.split(".")[0] for m in mods} & forbidden, (name, mods)
        third_party = {m for m in mods if m.split(".")[0] not in sys.stdlib_module_names and not m.startswith("v3lum")}
        assert not third_party, (name, third_party)


def test_routing_table_reaches_every_file_module():
    """P270 c1/c2: one routing table; every approved file parser is reachable from some kind."""
    from v3lum.modules.file_analysis.file_type_sniff import ALWAYS_ROUTES, ROUTES, route

    assert set(ALWAYS_ROUTES) == {"file_hashing", "yara_scan"}
    reachable = set(ALWAYS_ROUTES) | set(ROUTES)
    for name in ("document_metadata", "apk_triage", "archive_listing", "pe_triage", "elf_triage", "windows_artifact_triage", "script_decoder",
                 "image_metadata", "qr_decode", "image_ocr", "email_header_analyzer"):
        assert name in reachable
    assert route("ooxml-docx")[:2] == ["file_hashing", "yara_scan"] and "document_metadata" in route("ooxml-docx")
    assert "apk_triage" in route("apk") and "archive_listing" in route("iso9660") and "windows_artifact_triage" in route("lnk")


@pytest.mark.parametrize("builder,module,filename", [
    (docx_remote_template, "document_metadata", "fatura.docx"),
    (apk_ok_v1v2v3, "apk_triage", "app.apk"),
    (zip_lure_br, "archive_listing", "fatura.zip"),
    (pe32_exe, "file_type_sniff", "tool.exe"),
])
def test_each_module_runs_offline_and_others_skip(tmp_path, builder, module, filename):
    """Each file goes to its analyser through the routing function; the other analysers skip it as not
    applicable, and no module sends a single request (disclosure 'none')."""
    from tests.fakes import FakeHttp
    from v3lum.core.module import REGISTRY, load_modules

    load_modules()
    path = write(tmp_path, filename, builder())
    for name in MODULE_FILES:
        http = FakeHttp()
        res = run_module(REGISTRY[name], f"file:{path}", http)
        assert http.calls == [] and res.requests == 0
        if name in (module, "file_type_sniff"):
            assert res.status is Status.OK, (name, res.status, res.error)
        else:
            assert res.status is Status.SKIPPED and res.reason_code == "not_applicable", (name, res.status, res.error)


def test_disclosure_none_modules_have_no_network():
    from v3lum.core.module import REGISTRY, load_modules

    load_modules()
    for name in MODULE_FILES:
        cls = REGISTRY[name]
        assert cls.disclosure == "none" and cls.hosts == () and cls.terms == "open" and cls.default_enabled is True
        assert cls.trust_tier == "n/a" and cls.max_requests == 0
        ctx = make_ctx(cls)
        with pytest.raises(PolicyError):
            ctx.http.get("https://example.com/")


def test_builders_are_deterministic_where_it_matters():
    assert hashlib.sha256(docx_remote_template()).hexdigest() == hashlib.sha256(docx_remote_template()).hexdigest()
    assert zip_ok()[:4] == b"PK\x03\x04" and cfb_bytes([("x", b"1")])[:8] == OLE_MAGIC
    assert gzip.decompress(gzip_named(b"abc", "a.txt")) == b"abc" and lzma.decompress(lzma.compress(b"x")) == b"x"
    assert bz2.decompress(bz2.compress(b"x")) == b"x"
