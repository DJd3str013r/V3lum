"""Windows artefact triage (P367): LNK shortcuts, MSI installers and OneNote files - offline, disclosure 'none'.

LNK droppers, MSI CustomActions and OneNote-embedded scripts are the usual first stages of the
Grandoreiro / Mekotio / Casbaneiro chains seen in Brazil. This module reads such a file as data, never runs
it, and turns what it finds into facts, findings and pivots. Final conditions of P367:

* c1 offline: disclosure 'none' (ctx.http refuses everything), terms 'open', provider tier 'n/a', allowed at
  TLP:RED, FILE input only. Applicability comes from the shared routing table of file_type_sniff (P270);
  a file whose magic is damaged but whose name says .lnk/.one/.onetoc2/.msi/.msm/.msp/.mst stays in
  scope, so a broken artefact ends ERROR instead of being skipped (c5).
* c2 the parsing entry points (:func:`lnk_report`, :func:`onenote_report`, :func:`msi_report`, dispatched by
  :func:`child_entry`) are pure ``bytes -> JSON`` functions written for the shared file-analysis sandbox
  ``core/sandbox.py`` (python -I child, wall timeout, rlimits, 100 MB in / 1 MB JSON out:
  :func:`fit_report`). That core piece does not exist yet and module files may not start processes
  (P327 LINT-01), so until it lands they run in process on input capped at 100 MB, with bounded loops
  and the run deadline (core request and backlog). Downloaded data is never executed.
* c3 LNK through LnkParse3 (MIT, optional extra ``lnk``; it pulls PyYAML, which only that extra brings
  and V3LUM never imports): target, arguments, working dir, icon location, timestamps, machine id,
  droid MAC and volume serial. Without the extra (or when it fails) the built-in [MS-SHLLINK] reader
  :func:`lnk_read_builtin` gives the same report shape. The five StringData strings are always re-read
  exactly per [MS-SHLLINK] (:func:`lnk_string_data`), because LnkParse3 1.6.0 caps three of them at 260
  characters and then mis-aligns the rest - a crafted description would hide the real arguments.
  Arguments go to the P366 script decoder (:func:`decode_for_triage`).
* c4 OneNote: own scan for the FileDataStoreObject GUID header (:func:`scan_onenote`; pyOneNote is not
  used). MSI: streams through olefile (optional, BSD) or the bounded built-in compound-file reader, and the
  CustomAction / Binary / Property tables only through the optional pre-release pymsi (MIT, extra
  ``msi``); otherwise the result says 'MSI tables not parsed (...)' - never empty.
* c5 scripts (HTA, JS, VBS, PowerShell in CustomActions, OneNote objects and LNK appended data) go to
  P366; embedded files are hashed in memory and become sha256 pivots (relation ``contains``), never
  written to disk or made executable. A parser failure is ERROR, never EMPTY.
* c6 UNC and WebDAV targets (``\\\\host@SSL\\DavWWWRoot\\...``), URLs and IPs in shortcut fields become
  hostile pivots (relations ``lnk_target``, ``lnk_icon``, ``lnk_reference``, ``msi_reference``): nothing
  resolves them or opens SMB/WebDAV/HTTP (as P269). Entities extracted from a FILE are hostile-shaped for
  the P376 contact guard, which refuses LIGHT/ACTIVE contact with them.
* c7 machine id, droid MAC and volume serial are clustering attributes (``lnk_machine_id``,
  ``lnk_droid_mac``, ``lnk_volume_serial``) plus namespaced keyword pivots with expand=False (relation
  ``lnk_metadata``): never sent to any lookup. Indexing them in the P375 sightings needs a core change
  (keywords are not IOC_TYPES): core request.
* c8 synthetic LNK, OneNote and MSI samples, with a malformed one of each, are built by the tests.

Severities (the final conditions fix none) follow P269 c9's wording: 'suspicious', never 'malicious'.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import hashlib
import importlib
import importlib.metadata
import io
import ipaddress
import json
import re
import struct
import threading
import uuid
import warnings
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core import ioc as _ioc
from v3lum.core.entities import IOC_TYPES, Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.core.redact import redact_text
from v3lum.modules.file_analysis.document_metadata import ole_summary
from v3lum.modules.file_analysis.file_type_sniff import (
    CFB,
    ArchiveLimit,
    Budget,
    FileRefused,
    cap_json,
    emit_findings,
    fact,
    filetime_to_iso,
    read_capped,
    sniff_path,
    split_name,
)

UTC = _dt.timezone.utc

LIMITS: dict[str, int] = {
    "input_max": 100 * 1024 * 1024,  # c2 sandbox input cap
    "report_max_bytes": 900 * 1024,  # c2: child JSON budget (< the 1 MB sandbox output cap)
    "text_max": 256 * 1024,  # script text per item handed to P366
    "text_total_max": 640 * 1024,  # all script text of one report
    "onenote_max_objects": 256,
    "onenote_names_max": 64,
    "msi_max_streams": 1000,
    "msi_max_rows": 2000,
    "msi_stream_read_max": 64 * 1024 * 1024,
    "lnk_max_warnings": 50,
    "lnk_string_chars": 32768,  # per StringData field kept (CountCharacters is a u16)
    "lnk_ui_field_chars": 260,  # LnkParse3 1.6.0 caps description / relative path / working dir here
    "lnk_max_items": 64,  # shell items in a LinkTargetIDList
    "lnk_max_blocks": 64,  # ExtraData blocks
    "arg_padding_min": 32,  # leading whitespace run that hides arguments (ZDI-CAN-25373 style)
    "arg_ui_chars": 260,  # Explorer shows only the first 260 characters of the target field
    "refs_max": 200,
    "format_passes": 2,
    "decode_matches": 10,  # stand-in decoder: encoded blocks per input
    "decode_rounds": 3,  # stand-in decoder: nested -EncodedCommand layers
    "extract_text_max": 256 * 1024,  # text given to the P172 extractor per decoder input
}

# ---------------------------------------------------------------------------------------- format identifiers

LNK_CLSID = uuid.UUID("00021401-0000-0000-C000-000000000046").bytes_le
ONE_GUID = uuid.UUID("7B5C52E4-D88C-4DA7-AEB1-5378D02996D3").bytes_le
ONETOC2_GUID = uuid.UUID("43FF2FA1-EFD9-4C76-9EE2-10EA5722765F").bytes_le
ONE_FILE_FORMAT_GUID = uuid.UUID("109ADD3F-911B-49F5-A5D0-1791EDC8AED8").bytes_le
FDSO_HEADER = uuid.UUID("BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC").bytes_le  # FileDataStoreObject guidHeader
FDSO_FOOTER = uuid.UUID("71FBA722-0F79-4A0B-BB13-899256426B24").bytes_le  # FileDataStoreObject guidFooter
OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
INSTALLER_CLSIDS = {"000c1084-0000-0000-c000-000000000046": "msi",  # MSI / MSM
                    "000c1086-0000-0000-c000-000000000046": "msp",  # patch
                    "000c1082-0000-0000-c000-000000000046": "mst"}  # transform
#: file extensions that keep a damaged artefact in scope (c5: ERROR, never skipped)
EXTENSIONS = {"lnk": "lnk", "one": "onenote", "onetoc2": "onetoc2", "msi": "msi", "msm": "msi", "msp": "msp", "mst": "mst"}
#: file_type_sniff kinds routed to this module -> artefact format
SNIFF_FORMATS = {"lnk": "lnk", "onenote": "onenote", "onenote-toc": "onetoc2", "ole-msi": "msi", "ole-msp": "msp",
                 "ole-mst": "mst"}
MSI_FORMATS = ("msi", "msp", "mst")
ONENOTE_FORMATS = ("onenote", "onetoc2")
MSI_NOT_PARSED = "MSI tables not parsed"
FORMAT_LABELS = {"lnk": "Windows shortcut (LNK)", "onenote": "OneNote section", "onetoc2": "OneNote table of contents",
                 "msi": "Windows Installer package (MSI)", "msp": "Windows Installer patch (MSP)",
                 "mst": "Windows Installer transform (MST)"}

#: enterprise-internal address space (RFC 1918, loopback, link-local, ULA): SMB shares there drop to MEDIUM
INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                                         "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"))
#: schema, namespace and documentation hosts and common library CDNs: never pivoted from script text
#: (P366 c5 asks for the P169 warninglist filter first; this stand-in covers the hosts it names)
NAMESPACE_AND_CDN_HOSTS = frozenset({
    "schemas.microsoft.com", "schemas.openxmlformats.org", "schemas.xmlsoap.org", "www.w3.org", "w3.org",
    "go.microsoft.com", "purl.org", "ns.adobe.com", "ajax.googleapis.com", "cdnjs.cloudflare.com", "code.jquery.com",
    "cdn.jsdelivr.net", "unpkg.com", "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com", "fonts.googleapis.com",
    "fonts.gstatic.com"})
#: P366 script decoder (batch p2-G12-2): used through ``decode_layers`` when that module is installed
SCRIPT_DECODER_MODULE = "v3lum.modules.file_analysis.script_decoder"

LOLBINS = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    "rundll32.exe", "regsvr32.exe", "msiexec.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "conhost.exe",
    "forfiles.exe", "schtasks.exe", "wmic.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "odbcconf.exe", "hh.exe", "cmstp.exe", "finger.exe", "ftp.exe", "tar.exe", "expand.exe", "extrac32.exe",
    "esentutl.exe", "msdt.exe", "pcalua.exe", "scriptrunner.exe", "explorer.exe", "msxsl.exe", "bash.exe",
    "wsl.exe", "control.exe", "presentationhost.exe", "syncappvpublishingserver.vbs", "pubprn.vbs", "mavinject.exe"})
LOLBIN_ATTACK = {"powershell.exe": "T1059.001", "pwsh.exe": "T1059.001", "powershell_ise.exe": "T1059.001",
                 "cmd.exe": "T1059.003", "mshta.exe": "T1218.005", "msiexec.exe": "T1218.007", "wscript.exe": "T1059.005",
                 "cscript.exe": "T1059.005"}
SCRIPT_KINDS = frozenset({"hta", "js", "vbs", "wsf", "bat", "ps1", "html"})
ACTIVE_KINDS = SCRIPT_KINDS | {"pe", "mz", "lnk", "chm", "msi", "elf"}
CONTAINER_KINDS = frozenset({"zip", "cab", "rar", "7z", "ole", "pdf", "onenote", "rtf", "iso"})
KIND_EXTENSIONS = {"hta": (".hta",), "js": (".js", ".jse"), "vbs": (".vbs", ".vbe"), "wsf": (".wsf", ".wsh"),
                   "bat": (".bat", ".cmd"), "ps1": (".ps1",), "pe": (".exe", ".dll", ".scr", ".cpl"),
                   "lnk": (".lnk",), "chm": (".chm",), "zip": (".zip",), "png": (".png",), "jpeg": (".jpg", ".jpeg"),
                   "gif": (".gif",), "pdf": (".pdf",), "html": (".html", ".htm"), "iso": (".iso", ".img"),
                   "msi": (".msi",), "onenote": (".one",)}
#: local, offline OUI hints for virtualisation vendors (no lookup service is ever called, c7)
VM_OUIS = {"00:05:69": "VMware", "00:0c:29": "VMware", "00:1c:14": "VMware", "00:50:56": "VMware",
           "08:00:27": "VirtualBox", "0a:00:27": "VirtualBox", "00:15:5d": "Hyper-V", "00:03:ff": "Virtual PC",
           "00:1c:42": "Parallels", "52:54:00": "QEMU/KVM", "00:16:3e": "Xen"}

# ---------------------------------------------------------------------------------------- severity table

#: code -> (severity, ATT&CK ids, tags). A proposal: P367's final conditions fix none (P269 c9 wording).
SEVERITY: dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {
    "lnk_remote_target": ("high", ("T1204.002",), ("suspicious",)),
    "lnk_remote_icon": ("high", ("T1187",), ("suspicious",)),
    "lnk_remote_reference": ("medium", ("T1204.002",), ("suspicious",)),
    "lnk_lolbin_target": ("high", ("T1204.002",), ("suspicious",)),
    "lnk_whitespace_padding": ("high", ("T1027",), ("suspicious",)),
    "lnk_encoded_arguments": ("medium", ("T1027",), ("suspicious",)),
    "lnk_hidden_window": ("medium", ("T1564.003",), ("suspicious",)),
    "lnk_icon_masquerade": ("medium", ("T1036",), ("suspicious", "masquerading")),
    "lnk_appended_data": ("medium", ("T1027.009",), ("suspicious",)),
    "lnk_target_mismatch": ("medium", ("T1036",), ("suspicious",)),
    "lnk_long_string_field": ("medium", ("T1027",), ("suspicious",)),
    "onenote_embedded_active": ("high", ("T1204.002",), ("suspicious",)),
    "onenote_embedded_container": ("medium", ("T1204.002",), ("suspicious",)),
    "onenote_embedded_file": ("info", (), ("info",)),
    "msi_script_custom_action": ("high", ("T1218.007",), ("suspicious",)),
    "msi_lolbin_custom_action": ("high", ("T1218.007",), ("suspicious",)),
    "msi_binary_custom_action": ("low", ("T1218.007",), ()),
    "msi_elevated_custom_action": ("medium", ("T1218.007",), ("suspicious",)),
    "msi_nested_install": ("low", ("T1218.007",), ()),
    "msi_tables_not_parsed": ("info", (), ("info",)),
    "parser_anomaly": ("low", (), ()),
}
CRITERIA: dict[str, str] = {
    "lnk_remote_target": "the shortcut target is a UNC/WebDAV share, URL or IP: opening it runs remote content "
                         "(classified from the LNK structures, never contacted)",
    "lnk_remote_icon": "the icon location is a UNC/WebDAV path: Explorer fetches it when the folder is viewed and "
                       "leaks NTLM credentials (classified, never contacted)",
    "lnk_remote_reference": "a UNC/WebDAV path, URL or IP appears in the arguments, working directory or description",
    "lnk_lolbin_target": "the shortcut launches a script interpreter or a system binary used for proxy execution",
    "lnk_whitespace_padding": "the arguments start with a long whitespace run that pushes the command past the "
                              "260 characters the properties dialog shows",
    "lnk_encoded_arguments": "the arguments carry an encoded or obfuscated command (-EncodedCommand, char codes, "
                             "carets); decoded statically, never run",
    "lnk_hidden_window": "ShowCommand SW_SHOWMINNOACTIVE: the target window opens minimised without focus",
    "lnk_icon_masquerade": "the icon is taken from another program than the target (e.g. a browser or PDF icon on "
                           "a script interpreter)",
    "lnk_appended_data": "bytes follow the LNK terminal block: a payload carried inside the shortcut",
    "lnk_target_mismatch": "the LNK structures name different target files (ID list, LinkInfo, environment block)",
    "lnk_long_string_field": "a StringData field is longer than 260 characters: parsers and the properties dialog "
                             "that stop there miss the rest (the full [MS-SHLLINK] count is used)",
    "onenote_embedded_active": "a FileDataStoreObject of the OneNote file holds a script, executable, shortcut "
                               "or help file (sniffed from its bytes)",
    "onenote_embedded_container": "a FileDataStoreObject holds an archive, compound file or document",
    "msi_script_custom_action": "a CustomAction runs VBScript/JScript (inline, from a property or from the Binary "
                                "table) during installation",
    "msi_lolbin_custom_action": "a CustomAction command line starts a script interpreter or a system binary used "
                                "for proxy execution",
    "msi_binary_custom_action": "a CustomAction runs a DLL/EXE from the Binary table or the installed files "
                                "(common in legitimate WiX installers too)",
    "msi_elevated_custom_action": "a deferred CustomAction without impersonation runs as LocalSystem",
    "msi_nested_install": "a CustomAction installs another product",
    "parser_anomaly": "a structure of the file is inconsistent with its specification (damaged or crafted)",
}
FINDING_TITLES: dict[str, str] = {
    "lnk_remote_target": "Suspicious LNK: target on a remote share or URL (never contacted)",
    "lnk_remote_icon": "Suspicious LNK: icon loaded from a remote share (forced authentication)",
    "lnk_remote_reference": "Suspicious LNK: remote reference in arguments, working directory or description",
    "lnk_lolbin_target": "Suspicious LNK: launches a script interpreter or system binary",
    "lnk_whitespace_padding": "Suspicious LNK: arguments hidden behind whitespace padding",
    "lnk_encoded_arguments": "Suspicious LNK: encoded or obfuscated arguments",
    "lnk_hidden_window": "Suspicious LNK: runs minimised without activation",
    "lnk_icon_masquerade": "Suspicious LNK: icon borrowed from another program",
    "lnk_appended_data": "Suspicious LNK: data appended after the terminal block",
    "lnk_target_mismatch": "Suspicious LNK: target differs between LNK structures",
    "lnk_long_string_field": "Suspicious LNK: string field longer than 260 characters",
    "onenote_embedded_active": "Suspicious OneNote: embedded script or executable",
    "onenote_embedded_container": "OneNote embeds an archive or document",
    "onenote_embedded_file": "OneNote embeds a file",
    "msi_script_custom_action": "Suspicious MSI: script custom action",
    "msi_lolbin_custom_action": "Suspicious MSI: custom action runs a script interpreter or system binary",
    "msi_binary_custom_action": "MSI custom action runs a DLL or EXE",
    "msi_elevated_custom_action": "MSI custom action runs as LocalSystem (deferred, no impersonation)",
    "msi_nested_install": "MSI custom action installs another package",
    "msi_tables_not_parsed": "MSI tables not parsed",
    "parser_anomaly": "Artefact structure anomaly",
}

# ======================================================================================== small helpers


def hashes(blob: bytes) -> dict[str, str]:
    """c5: in-memory hashes of an embedded file (never written to disk)."""
    return {"md5": hashlib.md5(blob).hexdigest(), "sha1": hashlib.sha1(blob).hexdigest(),
            "sha256": hashlib.sha256(blob).hexdigest()}


_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def clean_text(value: Any, limit: int | None = None) -> str | None:
    """Drop C0/C1 controls (tab/CR/LF kept) and cap the length; non-str -> None."""
    if not isinstance(value, str):
        return None
    out = _CTRL.sub("", value)
    return out[:limit] if limit else out


def iso_z(value: Any) -> str | None:
    """ISO text or datetime -> '2026-11-19T12:00:00Z'; anything unparseable -> None."""
    if value is None:
        return None
    if isinstance(value, _dt.datetime):
        d = value if value.tzinfo else value.replace(tzinfo=UTC)
    elif isinstance(value, str):
        try:
            d = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if d.tzinfo is None:
            d = d.replace(tzinfo=UTC)
    else:
        return None
    return d.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def bytes_to_text(blob: Any) -> tuple[str | None, str | None]:
    """Bytes -> (text, encoding): BOMs, UTF-16LE by NUL pattern, then UTF-8, then cp1252 (pt-BR Windows ANSI)."""
    if not isinstance(blob, (bytes, bytearray)):
        return None, None
    b = bytes(blob)
    for bom, enc in ((b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be")):
        if b.startswith(bom):
            return b[len(bom):].decode(enc, "replace"), enc
    sample = b[:4096]
    half = len(sample) // 2
    if len(sample) >= 4 and sample[1::2].count(0) >= 0.4 * half and sample[0::2].count(0) < 0.1 * half:
        return b.decode("utf-16-le", "replace"), "utf-16-le"
    try:
        return b.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return b.decode("cp1252", "replace"), "cp1252"


def looks_text(text: str | None, threshold: float = 0.92) -> bool:
    if not text:
        return False
    sample = text[:8192]
    ok = sum(1 for c in sample if c.isprintable() or c in "\r\n\t")
    return ok / len(sample) >= threshold


_RX_HTA = re.compile(r"(?i)<hta:application")
_RX_WSF = re.compile(r"(?i)<(?:job|package)\b[^>]{0,200}>")
_RX_SCRIPT_TAG = re.compile(r"(?i)<script\b")
_RX_HTML = re.compile(r"(?i)<html\b")
_RX_PS = re.compile(r"(?i)(?:\binvoke-(?:expression|webrequest|restmethod)\b|\biex\b|\bnew-object\b|"
                    r"\bdownloadstring\b|frombase64string|\$env:|\bwrite-output\b|-encodedcommand\b|\bstart-process\b)")
_RX_JS = re.compile(r"(?i)(?:activexobject|string\.fromcharcode|wscript\.createobject|\bvar\s{1,8}\w{1,64}\s{0,8}=|"
                    r"\bfunction\s{1,8}\w{1,64}\s{0,8}\([^)]{0,200}\)\s{0,8}\{)")
_RX_VBS = re.compile(r"(?im)(?:^\s{0,16}(?:dim|set|sub|private sub|on error resume next)\b|createobject\(|"
                     r"\bchrw?\(\s{0,4}\d{1,6}\s{0,4}\)|^\s{0,16}'|wscript\.)")
_RX_BAT = re.compile(r"(?im)(?:^\s{0,16}@?echo\s{1,8}off\b|%~dp0|^\s{0,16}(?:start|call|goto)\s|\bcmd(?:\.exe)?\s{1,8}/[ck]\b)")


def sniff_blob(blob: Any) -> str:
    """Magic + script heuristics for an embedded blob (OneNote object, MSI stream, LNK appended data)."""
    if not isinstance(blob, (bytes, bytearray)) or not blob:
        return "empty"
    b = bytes(blob[:4096])
    if b[:2] == b"MZ":
        if len(blob) >= 0x40:
            off = struct.unpack_from("<I", blob, 0x3C)[0]
            if 0 < off <= len(blob) - 4 and blob[off:off + 4] == b"PE\x00\x00":
                return "pe"
        return "mz"
    table = ((b"PK\x03\x04", "zip"), (b"MSCF", "cab"), (b"Rar!\x1a\x07", "rar"), (b"7z\xbc\xaf\x27\x1c", "7z"),
             (OLE_MAGIC, "ole"), (b"%PDF-", "pdf"), (b"\x7fELF", "elf"), (b"\x89PNG\r\n\x1a\n", "png"),
             (b"\xff\xd8\xff", "jpeg"), (b"GIF87a", "gif"), (b"GIF89a", "gif"), (b"ITSF", "chm"),
             (b"{\\rtf", "rtf"), (b"\x00\x00\x01\x00", "ico"))
    for magic, kind in table:
        if b.startswith(magic):
            return kind
    if b[:4] == b"L\x00\x00\x00" and b[4:20] == LNK_CLSID:
        return "lnk"
    if b[:16] in (ONE_GUID, ONETOC2_GUID):
        return "onenote"
    if len(blob) > 0x8006 and blob[0x8001:0x8006] == b"CD001":
        return "iso"
    text, _ = bytes_to_text(b)
    if text is None or not looks_text(text):
        return "binary"
    if _RX_HTA.search(text):
        return "hta"
    if _RX_WSF.search(text) and _RX_SCRIPT_TAG.search(text):
        return "wsf"
    if _RX_SCRIPT_TAG.search(text) or _RX_HTML.search(text):
        return "html"
    for rx, kind in ((_RX_PS, "ps1"), (_RX_JS, "js"), (_RX_VBS, "vbs"), (_RX_BAT, "bat")):
        if rx.search(text):
            return kind
    return "text"


def blob_record(blob: Any, *, offset: int | None = None, want_text: bool | None = None) -> dict[str, Any]:
    """c5: an embedded blob for the report: size, md5/sha1/sha256 (in memory), sniffed kind, first bytes and -
    for script-like or text content - the decoded text (<= LIMITS['text_max']) for P366."""
    blob = bytes(blob or b"")
    rec: dict[str, Any] = {"size": len(blob), **hashes(blob), "kind": sniff_blob(blob), "head_hex": blob[:16].hex(),
                           "text": None, "text_truncated": False, "encoding": None}
    if offset is not None:
        rec["offset"] = offset
    if want_text is None:
        want_text = rec["kind"] in SCRIPT_KINDS or rec["kind"] == "text"
    if want_text and blob:
        text, enc = bytes_to_text(blob[:LIMITS["text_max"] * 2])
        if text is not None and looks_text(text):
            rec["text"] = text[:LIMITS["text_max"]]
            rec["text_truncated"] = len(blob) > LIMITS["text_max"] * 2 or len(text) > LIMITS["text_max"]
            rec["encoding"] = enc
    return rec


def _jsonable(obj: Any, depth: int = 0) -> Any:
    """Library output -> JSON-safe (datetimes as ISO, bytes as hex, unknown objects as a short repr)."""
    if depth > 12:
        return None
    if isinstance(obj, dict):
        return {str(k): _jsonable(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v, depth + 1) for v in obj]
    if isinstance(obj, _dt.datetime):
        return obj.isoformat()
    if isinstance(obj, (bytes, bytearray)):
        return "<binary>" if len(obj) > 64 else bytes(obj).hex()
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return repr(obj)[:200]


def fit_report(rep: dict[str, Any], max_bytes: int | None = None) -> dict[str, Any]:
    """c2: keep the child's JSON under the sandbox output cap: shrink the largest 'text' fields first (marking
    text_truncated), then drop list tails, and record what was cut in rep['trimmed']."""
    max_bytes = max_bytes or LIMITS["report_max_bytes"]
    size = len(json.dumps(rep, default=str))
    if size <= max_bytes:
        return rep
    holders: list[dict[str, Any]] = []
    stack: list[Any] = [rep]
    while stack:
        o = stack.pop()
        if isinstance(o, dict):
            if isinstance(o.get("text"), str):
                holders.append(o)
            stack.extend(o.values())
        elif isinstance(o, list):
            stack.extend(o)
    trimmed = []
    for h in sorted(holders, key=lambda x: -len(x["text"])):
        if size <= max_bytes:
            break
        before = len(h["text"])
        h["text"] = h["text"][:4096]
        h["text_truncated"] = True
        size -= before - len(h["text"])
        trimmed.append("text")
    for key in ("streams", "objects", "warnings"):
        lst = rep.get(key)
        while isinstance(lst, list) and lst and len(json.dumps(rep, default=str)) > max_bytes:
            lst.pop()
            trimmed.append(key)
    rep["trimmed"] = sorted(set(trimmed))
    return rep


def _version(dist: str) -> str:
    try:
        return importlib.metadata.version(dist)
    except importlib.metadata.PackageNotFoundError:
        return "?"


# ======================================================================================== format sniffing (c1, c5)


def cfb_root_clsid(data: bytes) -> str | None:
    """Root-entry CLSID of a compound file (MSI/MSP/MST identification) or None. Bounded: one directory read."""
    if len(data) < 512 or data[:8] != OLE_MAGIC:
        return None
    shift = struct.unpack_from("<H", data, 0x1E)[0]
    if shift not in (9, 12):
        return None
    first_dir = struct.unpack_from("<I", data, 0x30)[0]
    off = (first_dir + 1) * (1 << shift) + 0x50
    if first_dir >= 0xFFFFFFFA or off + 16 > len(data):
        return None
    return str(uuid.UUID(bytes_le=bytes(data[off:off + 16])))


def sniff_kind(data: Any, name: str | None = None) -> dict[str, Any]:
    """c1/c5: which artefact a FILE is: {'kind': lnk|onenote|onetoc2|msi|msp|mst|unknown, 'by': magic|extension|
    none, 'magic_ok', 'extension'}. Extension-only matches (a .lnk whose header is broken) stay in scope so a
    damaged artefact ends ERROR instead of being skipped. Works on a prefix of the file too."""
    data = bytes(data[:1 << 20]) if isinstance(data, (bytes, bytearray)) else b""
    ext = ""
    if isinstance(name, str) and "." in name:
        ext = name.rsplit(".", 1)[1].lower()
    kind = None
    if data[:4] == b"L\x00\x00\x00" and (data[4:20] == LNK_CLSID or (len(data) < 20 and LNK_CLSID.startswith(data[4:20]))):
        kind = "lnk"
    elif data[:16] == ONE_GUID:
        kind = "onenote"
    elif data[:16] == ONETOC2_GUID:
        kind = "onetoc2"
    elif data[:8] == OLE_MAGIC:
        kind = INSTALLER_CLSIDS.get(cfb_root_clsid(data) or "")
    by = "magic" if kind else None
    if not kind and ext in EXTENSIONS:
        kind, by = EXTENSIONS[ext], "extension"
    return {"kind": kind or "unknown", "by": by or "none", "magic_ok": by == "magic", "extension": ext or None}


def artefact_format(path: str, name: str | None = None) -> tuple[str | None, dict[str, Any], str]:
    """(format or None, file_type_sniff result, 'magic'|'extension'|'none') for a FILE path. The shared routing
    table decides first (c1); a damaged file keeps its extension's format when the sniffer cannot name it
    (unknown data, or a generic compound file named .msi). Raises FileRefused for missing/special paths."""
    sn = sniff_path(path, name=name)
    fmt = SNIFF_FORMATS.get(sn.get("kind") or "")
    if fmt and WindowsArtifactTriage.name in (sn.get("routes") or []):
        return fmt, sn, "magic"
    ext = (split_name(name or path).get("exts") or [""])[-1].lower()
    by_ext = EXTENSIONS.get(ext)
    if by_ext and (sn.get("kind") in ("unknown", "data") or (by_ext in MSI_FORMATS and sn.get("kind") == "ole")):
        return by_ext, sn, "extension"
    return None, sn, "none"


# ======================================================================================== remote targets (c6)

_PROTO_HANDLERS = ("search-ms:", "search:", "ms-search:", "ms-msdt:", "ms-officecmd:", "ms-word:", "ms-excel:",
                   "ms-powerpoint:", "ms-appinstaller:", "ms-cxh:", "ms-settings:", "shell:", "javascript:",
                   "vbscript:", "mhtml:", "ms-its:", "its:", "mk:", "res:")
_RX_URL_SCHEME = re.compile(r"(?i)^(https?|ftp|davs?)://")
_RX_HOSTPORT = re.compile(r"^[a-z]{2,8}://(?:[^/@?#]{0,256}@)?(\[[0-9a-fA-F:.]{2,64}\]|[^/:?#]{1,255})(?::(\d{1,5}))?")
_RX_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


def _host_ip(host: str | None) -> str | None:
    """IP literal (plain, [v6] or the UNC '.ipv6-literal.net' form) -> normalised address or None."""
    h = (host or "").strip("[]").rstrip(".")
    low = h.lower()
    if low.endswith(".ipv6-literal.net"):
        h = low[: -len(".ipv6-literal.net")].replace("-", ":").split("s", 1)[0]
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        return None


def classify_target(target: Any) -> dict[str, Any]:
    """c6 (as P269 c8): a shortcut target / icon / working dir / reference -> {'raw', 'kind', 'host', 'ip',
    'port', 'ssl', 'share', 'url', 'path'}; kind url|webdav|unc|local_path|env_path|protocol_handler|relative|
    empty. WebDAV UNC syntax \\\\host[@SSL][@port]\\DavWWWRoot\\... is recognised. Values are classified, NEVER
    resolved, fetched or opened over HTTP/SMB/WebDAV."""
    t = (target if isinstance(target, str) else "").strip().strip('"').strip()[:4096]
    res: dict[str, Any] = {"raw": t[:2048], "kind": "empty" if not t else "relative", "host": None, "ip": None,
                           "port": None, "ssl": None, "share": None, "url": None, "path": None}
    if not t:
        return res
    low = t.lower()
    if low.startswith(_PROTO_HANDLERS):
        res["kind"] = "protocol_handler"
        res["scheme"] = low.split(":", 1)[0]
        inner = [r for r in extract_net_refs(t[len(res["scheme"]) + 1:]) if r["kind"] in ("url", "unc", "webdav")]
        if inner:
            for k in ("host", "ip", "port", "ssl", "share", "url"):
                res[k] = inner[0][k]
            res["inner_kind"] = inner[0]["kind"]
        return res
    m = _RX_URL_SCHEME.match(t)
    if m:
        norm = m.group(1).lower() + "://" + t[m.end():].replace("\\", "/")
        host, port = None, None
        hp = _RX_HOSTPORT.match(norm)
        if hp:
            host = hp.group(1).strip("[]").rstrip(".").lower() or None
            port = int(hp.group(2)) if hp.group(2) else None
        res.update(kind="url", url=norm, host=host, port=port, ssl=norm.startswith(("https", "davs")))
        res["ip"] = _host_ip(host) if host else None
        if "/davwwwroot" in norm.lower() or norm.startswith("dav"):
            res["kind"] = "webdav"
        return res
    unc = None
    if low.startswith("file:"):
        rest = re.sub(r"^file:/*", "", t, flags=re.I)
        if _RX_DRIVE.match(rest):
            res.update(kind="local_path", path=rest)
            return res
        unc = rest.replace("/", "\\")
    elif t.startswith(("\\\\", "//")):
        unc = t[2:].replace("/", "\\")
    if unc is not None:
        if unc.startswith(("?\\", ".\\")):
            if unc[2:6].upper() == "UNC\\":
                unc = unc[6:]
            else:
                res.update(kind="local_path", path=t)
                return res
        parts = unc.split("\\")
        pieces = parts[0].split("@")
        host = pieces[0].rstrip(".") or None
        ssl, port = None, None
        for p in pieces[1:]:
            if p.upper() == "SSL":
                ssl = True
            elif p.isdigit() and len(p) <= 5:
                port = int(p)
        webdav = len(pieces) > 1 or any(x.lower() == "davwwwroot" for x in parts[1:2])
        if webdav and ssl and port is None:
            port = 443
        res.update(kind="webdav" if webdav else "unc", host=host.lower() if host else None, ssl=ssl, port=port,
                   share=parts[1] if len(parts) > 1 and parts[1] else None, path="\\".join(parts[2:]) or None)
        res["ip"] = _host_ip(host) if host else None
        return res
    if _RX_DRIVE.match(t):
        res.update(kind="local_path", path=t)
    elif t.startswith("%") and "%" in t[1:]:
        res.update(kind="env_path", path=t)
    return res


_RX_URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"'<>|^`]{3,2048}")
_RX_UNC = re.compile(r"(?<![\\\w])\\\\[^\\\s\"'<>|]{1,255}(?:\\[^\\\s\"'<>|]{1,255}){0,16}")
_RX_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def extract_net_refs(text: Any, limit: int | None = None) -> list[dict[str, Any]]:
    """URLs, UNC/WebDAV paths and bare IPv4s in clear text (LNK fields, MSI properties and CustomAction
    targets) -> classify_target() dicts with 'match' and 'offset'. Linear-time patterns with bounded runs;
    obfuscated text is decoded by P366 first."""
    if not isinstance(text, str) or not text:
        return []
    limit = limit or LIMITS["refs_max"]
    out: list[dict[str, Any]] = []
    spans: list[tuple[int, int]] = []
    for rx in (_RX_URL, _RX_UNC):
        for m in rx.finditer(text):
            if len(out) >= limit:
                break
            raw = m.group(0).rstrip(".,;:)]}'\"")
            ref = classify_target(raw)
            ref.update(match=raw, offset=m.start())
            out.append(ref)
            spans.append(m.span())
    for m in _RX_IPV4.finditer(text):
        if len(out) >= limit:
            break
        if any(a <= m.start() < b for a, b in spans):
            continue
        ip = _host_ip(m.group(0))
        if ip:
            out.append({"raw": m.group(0), "kind": "bare_ip", "host": ip, "ip": ip, "port": None, "ssl": None,
                        "share": None, "url": None, "path": None, "match": m.group(0), "offset": m.start()})
    return sorted(out, key=lambda r: r["offset"])[:limit]


def is_remote(ref: dict[str, Any]) -> bool:
    return ref.get("kind") in ("url", "webdav", "unc", "bare_ip") or (
        ref.get("kind") == "protocol_handler" and bool(ref.get("host")))


def internal_share(ref: dict[str, Any]) -> bool:
    """A plain SMB (not WebDAV) reference to a private/loopback/link-local address or a single-label NetBIOS name:
    typical of enterprise file servers, so remote-target findings drop to MEDIUM. Never resolved."""
    if ref.get("kind") != "unc":
        return False
    ip = ref.get("ip")
    if ip:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in net for net in INTERNAL_NETS if a.version == net.version)
    host = str(ref.get("host") or "")
    return bool(host) and "." not in host


def webdav_url(ref: dict[str, Any]) -> str | None:
    """c6: the HTTP(S) URL Windows' WebDAV redirector would request for a WebDAV UNC reference
    (\\\\host@SSL[@port]\\DavWWWRoot\\path -> https://host[:port]/path). Derived for passive lookups only."""
    if ref.get("kind") != "webdav" or ref.get("url") or not ref.get("host"):
        return None
    host = str(ref["host"])
    if ":" in host:
        host = f"[{host}]"
    scheme = "https" if ref.get("ssl") else "http"
    port = ref.get("port")
    netloc = host + (f":{port}" if port and port != (443 if ref.get("ssl") else 80) else "")
    parts = [p for p in ((ref.get("share") or ""), (ref.get("path") or "")) if p]
    if parts and parts[0].lower() == "davwwwroot":
        parts = parts[1:]
    path = "/".join(p.replace("\\", "/").strip("/") for p in parts if p.strip("\\/"))
    return f"{scheme}://{netloc}/{path}"


def ref_text(ref: dict[str, Any]) -> str:
    """The remote reference as the analyst should read it (URL, or \\\\host[@SSL]\\share)."""
    if ref.get("url"):
        return str(ref["url"])[:300]
    if ref.get("host"):
        return f"\\\\{ref['host']}{'@SSL' if ref.get('ssl') else ''}\\{ref.get('share') or ''}"
    return str(ref.get("raw") or "")[:300]


# ======================================================================================== LNK (c3, c5, c6, c7)

LNK_FLAG_NAMES = ("HasTargetIDList", "HasLinkInfo", "HasName", "HasRelativePath", "HasWorkingDir", "HasArguments",
                  "HasIconLocation", "IsUnicode", "ForceNoLinkInfo", "HasExpString", "RunInSeparateProcess", "Unused1",
                  "HasDarwinID", "RunAsUser", "HasExpIcon", "NoPidlAlias", "Unused2", "RunWithShimLayer",
                  "ForceNoLinkTrack", "EnableTargetMetadata", "DisableLinkPathTracking", "DisableKnownFolderTracking",
                  "DisableKnownFolderAlias", "AllowLinkToLink", "UnaliasOnSave", "PreferEnvironmentPath",
                  "KeepLocalIDListForUNCTarget")
FILE_ATTRIBUTE_NAMES = ((0x1, "FILE_ATTRIBUTE_READONLY"), (0x2, "FILE_ATTRIBUTE_HIDDEN"), (0x4, "FILE_ATTRIBUTE_SYSTEM"),
                        (0x10, "FILE_ATTRIBUTE_DIRECTORY"), (0x20, "FILE_ATTRIBUTE_ARCHIVE"), (0x80, "FILE_ATTRIBUTE_NORMAL"),
                        (0x100, "FILE_ATTRIBUTE_TEMPORARY"), (0x200, "FILE_ATTRIBUTE_SPARSE_FILE"),
                        (0x400, "FILE_ATTRIBUTE_REPARSE_POINT"), (0x800, "FILE_ATTRIBUTE_COMPRESSED"),
                        (0x1000, "FILE_ATTRIBUTE_OFFLINE"), (0x2000, "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED"),
                        (0x4000, "FILE_ATTRIBUTE_ENCRYPTED"))
SHOW_COMMANDS = {1: "SW_SHOWNORMAL", 3: "SW_SHOWMAXIMIZED", 7: "SW_SHOWMINNOACTIVE"}
DRIVE_TYPES = {0: "DRIVE_UNKNOWN", 1: "DRIVE_NO_ROOT_DIR", 2: "DRIVE_REMOVABLE", 3: "DRIVE_FIXED", 4: "DRIVE_REMOTE",
               5: "DRIVE_CDROM", 6: "DRIVE_RAMDISK"}
EXTRA_BLOCKS = {0xA0000001: "ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK", 0xA0000002: "CONSOLE_PROPERTIES_BLOCK",
                0xA0000003: "DISTRIBUTED_LINK_TRACKER_BLOCK", 0xA0000004: "CONSOLE_CODEPAGE_BLOCK",
                0xA0000005: "SPECIAL_FOLDER_LOCATION_BLOCK", 0xA0000006: "DARWIN_BLOCK", 0xA0000007: "ICON_LOCATION_BLOCK",
                0xA0000008: "SHIM_LAYER_BLOCK", 0xA0000009: "METADATA_PROPERTIES_BLOCK",
                0xA000000B: "KNOWN_FOLDER_LOCATION_BLOCK", 0xA000000C: "SHELL_ITEM_IDENTIFIER_BLOCK"}
LNK_STRING_FIELDS = ((0x4, "description"), (0x8, "relative_path"), (0x10, "working_directory"),
                     (0x20, "command_line_arguments"), (0x40, "icon_location"))
#: serialises LnkParse3's warnings capture (warnings.catch_warnings is process-global; see lnk_report)
_WARNINGS_LOCK = threading.Lock()


def lnk_precheck(data: Any) -> str | None:
    """c3/c5: structural check BEFORE any LNK parser (LnkParse3 only warns on a bad HeaderSize/CLSID and then
    parses garbage). Returns a short reason (-> ERROR) or None."""
    if not isinstance(data, (bytes, bytearray)):
        return "no data"
    n = len(data)
    if n < 0x4C:
        return f"truncated ShellLinkHeader ({n} of 76 bytes)"
    hsize = struct.unpack_from("<I", data, 0)[0]
    if hsize != 0x4C:
        return f"HeaderSize 0x{hsize:x} != 0x4c"
    if bytes(data[4:20]) != LNK_CLSID:
        return f"LinkCLSID {uuid.UUID(bytes_le=bytes(data[4:20]))} != 00021401-0000-0000-c000-000000000046"
    flags = struct.unpack_from("<I", data, 20)[0]
    off = 0x4C
    if flags & 0x1:
        if off + 2 > n:
            return "IDList size field past end of file"
        size = struct.unpack_from("<H", data, off)[0]
        if off + 2 + size > n:
            return f"LinkTargetIDList ({size} bytes) runs past end of file"
        off += 2 + size
    if flags & 0x2 and not flags & 0x100:
        if off + 8 > n:
            return "LinkInfo header past end of file"
        li_size, li_hsize = struct.unpack_from("<II", data, off)
        if li_hsize < 0x1C or li_size < li_hsize or off + li_size > n:
            return f"LinkInfo size {li_size}/header {li_hsize} inconsistent with file size"
    return None


def _lnk_string_start(data: bytes) -> int:
    flags = struct.unpack_from("<I", data, 20)[0]
    off = 0x4C
    if flags & 0x1:
        off += 2 + struct.unpack_from("<H", data, off)[0]
    if flags & 0x2 and not flags & 0x100:
        off += struct.unpack_from("<I", data, off)[0]
    return off


def lnk_string_data(data: Any) -> dict[str, Any] | None:
    """c3: the five StringData fields read exactly as [MS-SHLLINK] defines them (full CountCharacters) ->
    {'fields': {name: {'count', 'text', 'nul'}}, 'end', 'error'}; None when the header is broken. Text is cut at
    the first NUL (what CreateProcess sees) and capped at LIMITS['lnk_string_chars']."""
    if lnk_precheck(data):
        return None
    data = bytes(data)
    n = len(data)
    flags = struct.unpack_from("<I", data, 20)[0]
    off = _lnk_string_start(data)
    wide = bool(flags & 0x80)
    out: dict[str, Any] = {"fields": {}, "end": None, "error": None}
    for bit, name in LNK_STRING_FIELDS:
        if not flags & bit:
            continue
        if off + 2 > n:
            out["error"] = f"{name}: CountCharacters past end of file"
            return out
        count = struct.unpack_from("<H", data, off)[0]
        size = count * (2 if wide else 1)
        if off + 2 + size > n:
            out["error"] = f"{name}: {count} chars run past end of file"
            return out
        raw = data[off + 2:off + 2 + size]
        text = raw.decode("utf-16-le", "replace") if wide else raw.decode("cp1252", "replace")
        out["fields"][name] = {"count": count, "text": text.split("\x00", 1)[0][:LIMITS["lnk_string_chars"]],
                               "nul": "\x00" in text}
        off += 2 + size
    out["end"] = off
    return out


def _cstr(blob: bytes, off: int, *, wide: bool = False, cp: str = "cp1252", limit: int = 4096) -> str | None:
    """NUL-terminated string at ``off`` (bounded by the blob and ``limit`` characters)."""
    if not 0 <= off < len(blob):
        return None
    if wide:
        end = off
        stop = min(len(blob) - 1, off + limit * 2)
        while end < stop and blob[end:end + 2] != b"\x00\x00":
            end += 2
        return blob[off:end].decode("utf-16-le", "replace")
    end = blob.find(b"\x00", off, off + limit)
    return blob[off:end if end >= 0 else min(len(blob), off + limit)].decode(cp, "replace")


def _guid_upper(b: bytes) -> str | None:
    if len(b) != 16:
        return None
    return str(uuid.UUID(bytes_le=bytes(b))).upper()


def _fat_dt(d: int, t: int) -> str | None:
    try:
        return _dt.datetime(((d >> 9) & 0x7F) + 1980, (d >> 5) & 0x0F, d & 0x1F, (t >> 11) & 0x1F, (t >> 5) & 0x3F,
                            (t & 0x1F) * 2, tzinfo=UTC).isoformat()
    except ValueError:
        return None


def _beef0004_long_name(item: bytes, start: int) -> str | None:
    """Long (Unicode) file name of a BEEF0004 extension block inside a file-entry shell item."""
    sig = item.find(b"\x04\x00\xef\xbe", start)
    if sig < 4:
        return None
    ext = sig - 4
    size, version = struct.unpack_from("<HH", item, ext)
    if size < 22 or ext + size > len(item):
        return None
    off = 18
    if version >= 7:
        off += 18
    if version >= 3:
        off += 2
    if version >= 9:
        off += 4
    if version >= 8:
        off += 4
    name = _cstr(item[ext:ext + size], off, wide=True, limit=520)
    return name or None


_RX_VOLUME = re.compile(r"[A-Za-z]:\\?")


def _shell_item(item: bytes) -> dict[str, Any]:
    """One [MS-SHLLINK] / shell-item record (without its size field) -> LnkParse3-like dict."""
    t = item[0]
    if t == 0x1F and len(item) >= 18:
        return {"class": "Root Folder", "guid": _guid_upper(item[2:18]), "sort_index_value": item[1]}
    group = t & 0x70
    if group == 0x20:
        name = _cstr(item, 1, cp="ascii", limit=64) or ""
        return {"class": "Volume Item", "flags": hex(t & 0x0F),
                "volume_name": name if _RX_VOLUME.fullmatch(name) else None}
    if group == 0x30 and len(item) >= 12:
        size, fdate, ftime, attrs = struct.unpack_from("<IHHH", item, 2)
        wide = bool(t & 0x04)
        primary = _cstr(item, 12, wide=wide, limit=260) or ""
        name_end = 12 + (len(primary) * 2 + 2 if wide else len(primary.encode("cp1252", "replace")) + 1)
        long_name = _beef0004_long_name(item, name_end)
        out = {"class": "File entry", "flags": "Is directory" if t & 0x01 else "Is file", "file_size": size,
               "file_attribute_flags": attrs, "modification_time": _fat_dt(fdate, ftime),
               "primary_name": long_name or primary}
        if long_name and long_name != primary:
            out["short_name"] = primary
        return out
    if group == 0x40 and len(item) >= 3:
        return {"class": "Network Location", "flags": hex(item[2]), "location": _cstr(item, 3, limit=512)}
    return {"class": "Unknown", "type": hex(t)}


def _lnk_idlist(data: bytes, off: int, warnings_: list[str]) -> tuple[dict[str, Any], int]:
    size = struct.unpack_from("<H", data, off)[0]
    blob = data[off + 2:off + 2 + size]
    items: list[dict[str, Any]] = []
    pos = 0
    while pos + 2 <= len(blob) and len(items) < LIMITS["lnk_max_items"]:
        isize = struct.unpack_from("<H", blob, pos)[0]
        if isize == 0:
            break
        if isize < 3 or pos + isize > len(blob):
            warnings_.append(f"shell item at +{pos} declares {isize} bytes past the ID list")
            break
        try:
            items.append(_shell_item(blob[pos + 2:pos + isize]))
        except (struct.error, IndexError, ValueError):
            items.append({"class": "Unknown", "type": "unparsed"})
        pos += isize
    return {"size": size, "items": items}, off + 2 + size


def _lnk_linkinfo(data: bytes, off: int, warnings_: list[str]) -> tuple[dict[str, Any], int]:
    size, hsize, flags, vol_off, base_off, cnrl_off, sfx_off = struct.unpack_from("<7I", data, off)
    blob = data[off:off + size]
    info: dict[str, Any] = {"link_info_flags": flags, "link_info_size": size, "link_info_header_size": hsize}
    base_u = sfx_u = 0
    if hsize >= 0x24 and len(blob) >= 0x24:
        base_u, sfx_u = struct.unpack_from("<II", blob, 28)
    loc: dict[str, Any] = {}
    if flags & 0x1:
        info["location"] = "Local"
        if vol_off + 16 <= len(blob):
            vsize, dtype, serial, label_off = struct.unpack_from("<4I", blob, vol_off)
            vol = blob[vol_off:vol_off + vsize]
            loc.update(drive_type=DRIVE_TYPES.get(dtype, f"0x{dtype:x}"), r_drive_type=dtype,
                       drive_serial_number=f"0x{serial:x}")
            if label_off == 0x14 and len(vol) >= 0x14:
                loc["volume_label_unicode"] = _cstr(vol, struct.unpack_from("<I", vol, 16)[0], wide=True, limit=64)
            else:
                loc["volume_label"] = _cstr(vol, label_off, limit=64)
        else:
            warnings_.append("VolumeID past the LinkInfo structure")
        info["local_base_path"] = _cstr(blob, base_off)
        if base_u:
            info["local_base_path_unicode"] = _cstr(blob, base_u, wide=True)
    if flags & 0x2:
        info.setdefault("location", "Network")
        if cnrl_off + 20 <= len(blob):
            csize, cflags, net_off, dev_off, provider = struct.unpack_from("<5I", blob, cnrl_off)
            cnrl = blob[cnrl_off:cnrl_off + csize]
            loc.update(common_network_relative_link_flags=cflags, net_name=_cstr(cnrl, net_off, limit=1024))
            if cflags & 0x1:
                loc["device_name"] = _cstr(cnrl, dev_off, limit=64)
            if cflags & 0x2:
                loc["r_network_provider_type"] = hex(provider)
            if net_off > 0x14 and len(cnrl) >= 0x1C:
                net_u, dev_u = struct.unpack_from("<II", cnrl, 20)
                loc["net_name_unicode"] = _cstr(cnrl, net_u, wide=True, limit=1024)
                if cflags & 0x1:
                    loc["device_name_unicode"] = _cstr(cnrl, dev_u, wide=True, limit=64)
        else:
            warnings_.append("CommonNetworkRelativeLink past the LinkInfo structure")
    info["location_info"] = loc
    info["common_path_suffix"] = _cstr(blob, sfx_off) if sfx_off else ""
    if sfx_u:
        info["common_path_suffix_unicode"] = _cstr(blob, sfx_u, wide=True)
    return info, off + size


def _lnk_extra(data: bytes, off: int, warnings_: list[str]) -> tuple[dict[str, Any], int, bytes]:
    """ExtraData blocks until the TerminalBlock -> (blocks, end offset, appended bytes)."""
    extra: dict[str, Any] = {}
    n = len(data)
    count = 0
    while True:
        if off + 4 > n:
            warnings_.append("ExtraData ends without a TerminalBlock")
            return extra, n, b""
        size = struct.unpack_from("<I", data, off)[0]
        if size < 4:
            appended = data[off + 4:]
            if appended:
                extra["TERMINAL_BLOCK"] = {"size": 4 + len(appended),
                                           "appended_data_sha256": hashlib.sha256(appended).hexdigest()}
            return extra, off + 4, appended
        count += 1
        if count > LIMITS["lnk_max_blocks"] or size < 8 or off + size > n:
            warnings_.append(f"ExtraData block at {off} declares {size} bytes (file has {n})")
            return extra, n, b""
        blob = data[off:off + size]
        sig = struct.unpack_from("<I", blob, 4)[0]
        name = EXTRA_BLOCKS.get(sig, "UNKNOWN_BLOCK")
        block: dict[str, Any] = {"size": size}
        if sig in (0xA0000001, 0xA0000006, 0xA0000007) and size >= 0x314:
            block.update(target_ansi=_cstr(blob, 8, limit=260), target_unicode=_cstr(blob[268:788], 0, wide=True, limit=260))
        elif sig == 0xA0000003 and size >= 0x60:
            block.update(length=struct.unpack_from("<I", blob, 8)[0], version=struct.unpack_from("<I", blob, 12)[0],
                         machine_identifier=_cstr(blob[16:32], 0, cp="cp1252", limit=16),
                         droid_volume_identifier=_guid_upper(blob[32:48]), droid_file_identifier=_guid_upper(blob[48:64]),
                         birth_droid_volume_identifier=_guid_upper(blob[64:80]),
                         birth_droid_file_identifier=_guid_upper(blob[80:96]))
        elif sig == 0xA0000005 and size >= 16:
            block.update(special_folder_id=struct.unpack_from("<I", blob, 8)[0], offset=struct.unpack_from("<I", blob, 12)[0])
        elif sig == 0xA000000B and size >= 28:
            block.update(known_folder_id=_guid_upper(blob[8:24]), offset=struct.unpack_from("<I", blob, 24)[0])
        elif sig == 0xA0000008:
            block["layer_name"] = _cstr(blob, 8, wide=True, limit=260)
        elif name == "UNKNOWN_BLOCK":
            block["signature"] = hex(sig)
        if name not in extra:
            extra[name] = block
        elif name != "UNKNOWN_BLOCK":
            warnings_.append(f"duplicate {name}")
        off += size


def _lnk_time(ft: int) -> str | None:
    iso = filetime_to_iso(ft)
    return iso_z(iso).replace("Z", "+00:00") if iso and iso_z(iso) else None  # second precision, like LnkParse3


def lnk_read_builtin(data: bytes) -> dict[str, Any]:
    """Built-in [MS-SHLLINK] reader (stdlib, bounded) -> the subset of LnkParse3's ``get_json()`` shape this
    module reads: header, target.items, link_info, data, extra, size, warnings. Raises ValueError/struct.error
    on a structure it cannot read (the caller turns that into ERROR)."""
    warnings_: list[str] = []
    flags, attrs, ctime, atime, mtime, fsize, icon_index, show, hotkey = struct.unpack_from("<IIQQQIiIH", data, 20)
    header = {
        "guid": _guid_upper(data[4:20]), "r_link_flags": flags,
        "link_flags": [name for i, name in enumerate(LNK_FLAG_NAMES) if flags & (1 << i)],
        "r_file_flags": attrs, "file_flags": [name for bit, name in FILE_ATTRIBUTE_NAMES if attrs & bit],
        "creation_time": _lnk_time(ctime), "accessed_time": _lnk_time(atime),
        "modified_time": _lnk_time(mtime), "file_size": fsize, "icon_index": icon_index,
        "windowstyle": SHOW_COMMANDS.get(show, "SW_SHOWNORMAL"), "r_windowstyle": show,
        "r_hotkey": hotkey, "hotkey": f"0x{hotkey:04x}" if hotkey else None,
    }
    out: dict[str, Any] = {"header": header}
    off = 0x4C
    if flags & 0x1:
        out["target"], off = _lnk_idlist(data, off, warnings_)
    if flags & 0x2 and not flags & 0x100:
        out["link_info"], off = _lnk_linkinfo(data, off, warnings_)
    sd = lnk_string_data(data)
    if sd is None:
        raise ValueError("LNK header could not be read")
    if sd.get("error"):
        warnings_.append(f"StringData: {sd['error']}")
        out["data"] = {k: v["text"] for k, v in sd["fields"].items()}
        out["warnings"] = warnings_
        out["size"] = len(data)
        return out
    out["data"] = {k: v["text"] for k, v in sd["fields"].items()}
    out["extra"], end, appended = _lnk_extra(data, sd["end"], warnings_)
    out["size"] = end + len(appended)  # like LnkParse3: the structures plus appended data
    out["warnings"] = warnings_
    return out


def lnk_report(data: Any, *, use_extras: bool = True) -> dict[str, Any]:
    """c2/c3 sandbox entry: LNK bytes -> report {'kind': 'lnk', 'size', 'precheck', 'parser', 'unavailable',
    'error', 'lnk' (LnkParse3 get_json() shape), 'warnings', 'appended' (blob_record), 'string_data'}.
    LnkParse3 is used when installed and allowed; its structural complaints (warnings.warn) are recorded. The
    built-in reader is the fallback when the extra is missing or fails."""
    data = bytes(data or b"")
    rep: dict[str, Any] = {"kind": "lnk", "size": len(data), "precheck": lnk_precheck(data), "parser": None,
                           "unavailable": None, "error": None, "lnk": None, "warnings": [], "appended": None,
                           "string_data": None}
    if rep["precheck"]:
        return rep
    rep["string_data"] = lnk_string_data(data)
    lib = None
    if use_extras:
        try:
            import LnkParse3 as lib  # MIT, optional extra 'lnk' (pulls PyYAML, never imported by V3LUM)
        except ImportError:
            lib = None
            rep["unavailable"] = "LnkParse3 not installed (optional extra 'lnk'): built-in [MS-SHLLINK] reader used"
    else:
        rep["unavailable"] = "optional parsers disabled (setting windows_artifact_triage_use_extras): built-in reader used"
    if lib is not None:
        rep["parser"] = f"LnkParse3 {_version('LnkParse3')}"
        with _WARNINGS_LOCK, warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            try:
                rep["lnk"] = _jsonable(lib.lnk_file(indata=data, cp="cp1252").get_json())
            except Exception as exc:  # noqa: BLE001 - LnkParse3 raises struct.error/IndexError/... on damaged files
                rep["warnings"].append(f"LnkParse3 failed ({type(exc).__name__}: {str(exc)[:200]}): built-in reader used")
                rep["lnk"] = None
        rep["warnings"].extend(str(w.message)[:200] for w in caught)
    if rep["lnk"] is None:
        try:
            rep["lnk"] = lnk_read_builtin(data)
            rep["parser"] = "builtin MS-SHLLINK reader" + (" (LnkParse3 failed)" if lib is not None else "")
        except (ValueError, struct.error, IndexError) as exc:
            rep["error"] = f"{type(exc).__name__}: {exc}"[:300]
            return rep
        rep["warnings"].extend(rep["lnk"].pop("warnings", []))
    rep["warnings"] = rep["warnings"][:LIMITS["lnk_max_warnings"]]
    term = ((rep["lnk"] or {}).get("extra") or {}).get("TERMINAL_BLOCK")
    if isinstance(term, dict) and isinstance(term.get("size"), int):
        n = term["size"] - 4
        if 0 < n <= len(data):
            rep["appended"] = blob_record(data[len(data) - n:], offset=len(data) - n)
    return rep


def normalise_mac(node: Any) -> str | None:
    """48-bit int or 'aa-bb-..'/'aabb..' -> 'aa:bb:cc:dd:ee:ff' (lower case) or None."""
    if isinstance(node, int) and not isinstance(node, bool):
        if not 0 <= node < 1 << 48:
            return None
        h = f"{node:012x}"
    elif isinstance(node, str):
        h = re.sub(r"[^0-9a-fA-F]", "", node).lower()
        if len(h) != 12:
            return None
    else:
        return None
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def mac_vm_vendor(mac: str | None) -> str | None:
    """Local, offline OUI check for virtualisation vendors (no lookup service is ever called, c7)."""
    return VM_OUIS.get((mac or "")[:8])


def droid_info(value: Any) -> dict[str, Any] | None:
    """c7: droid object id -> {'uuid', 'version', 'mac', 'mac_random', 'time', 'clock_seq'}. Version-1 ids carry
    the creating machine's MAC (node) and a 100 ns timestamp; a node with the multicast bit set is a random node
    (RFC 4122 4.5), not a MAC."""
    try:
        u = uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None
    out: dict[str, Any] = {"uuid": str(u), "version": u.version, "mac": None, "mac_random": None, "time": None,
                           "clock_seq": None}
    if u.int == 0:
        out["version"] = None
        return out
    if u.version == 1 and u.variant == uuid.RFC_4122:
        out["mac_random"] = bool((u.node >> 40) & 0x01)
        out["mac"] = None if out["mac_random"] else normalise_mac(u.node)
        try:
            when = _dt.datetime(1582, 10, 15, tzinfo=UTC) + _dt.timedelta(microseconds=u.time // 10)
            out["time"] = iso_z(when) if 1990 <= when.year <= 2100 else None
        except OverflowError:
            out["time"] = None
        out["clock_seq"] = u.clock_seq
    return out


def volume_serial(value: Any) -> str | None:
    """c7: DriveSerialNumber ('0x5e005301', int or 'XXXX-XXXX') -> 'XXXX-XXXX'; 0/garbage -> None."""
    if isinstance(value, str):
        v = value.strip()
        try:
            num = int(v.replace("-", ""), 16) if re.fullmatch(r"[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{4}", v) else int(v, 0)
        except ValueError:
            return None
    elif isinstance(value, int) and not isinstance(value, bool):
        num = value
    else:
        return None
    if not 0 < num <= 0xFFFFFFFF:
        return None
    return f"{num >> 16:04X}-{num & 0xFFFF:04X}"


def machine_id(value: Any) -> str | None:
    """c7: TrackerDataBlock MachineID (NetBIOS name, <= 15 chars) -> lower-case key or None."""
    v = (clean_text(value, 16) or "").strip().strip("\x00").strip()
    if not v or not re.fullmatch(r"[\w.\- $]{1,16}", v):
        return None
    return v.lower()


def _basename(path: Any) -> str | None:
    if not isinstance(path, str) or not path:
        return None
    return re.split(r"[\\/]", path.strip().strip('"'))[-1].lower() or None


_SHORT_NAME = re.compile(r"~\d")


def _idlist_path(items: Any) -> str | None:
    """Rebuild a path from target items (Volume Item + File entry / Network Location)."""
    parts: list[str] = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        cls = it.get("class")
        if cls == "Volume Item" and isinstance(it.get("volume_name"), str):
            parts = [it["volume_name"].rstrip("\\")]
        elif cls == "Network Location" and isinstance(it.get("location"), str):
            parts = [it["location"].rstrip("\\")]
        elif cls == "File entry" and isinstance(it.get("primary_name"), str) and it["primary_name"]:
            parts.append(it["primary_name"])
        elif cls == "Users property view" and isinstance((it.get("file_entry") or {}).get("primary_name"), str):
            parts.append(it["file_entry"]["primary_name"])
    return "\\".join(parts) if parts else None


_RX_ENC_ARG = re.compile(r"(?i)(?:^|\s)[-/–—]e[a-z]{0,13}\s{1,16}[A-Za-z0-9+/]{20,}={0,2}(?=\s|$|['\"])")
_RX_OBFUSC = re.compile(r"(?i)frombase64string|\[char\]\s{0,4}\d|string\.fromcharcode|\bchrw?\(\s{0,4}\d|-join\b|\^.\^.\^")


def argument_markers(args: Any) -> dict[str, Any]:
    """c3: markers of an LNK/CustomAction command line: whitespace padding (arguments hidden past the 260-char
    properties field, ZDI-CAN-25373 style) and encoded/obfuscated arguments (routing hint for P366)."""
    out: dict[str, Any] = {}
    if not isinstance(args, str) or not args:
        return out
    lead = len(args) - len(args.lstrip(" \t\r\n\x0b\x0c"))
    longest = max((len(m.group(0)) for m in re.finditer(r"[ \t\r\n\x0b\x0c]{8,}", args)), default=0)
    if lead >= LIMITS["arg_padding_min"] or longest >= 64:
        out["whitespace_padding"] = {"leading": lead, "longest_run": longest, "hidden_tail": clean_text(args.strip(), 512)}
    if len(args) > LIMITS["arg_ui_chars"]:
        out["arguments_exceed_ui"] = len(args)
    if _RX_ENC_ARG.search(args):
        out["encoded_arguments"] = True
    if _RX_OBFUSC.search(args) or args.count("^") >= 5:
        out["obfuscated_arguments"] = True
    return out


def _empty_result(fmt: str, status: str, reason: str, *, code: str = "error", rep: dict[str, Any] | None = None,
                  **extra: Any) -> dict[str, Any]:
    out = {"format": fmt, "status": status, "reason_code": code, "reason": reason, "partial": False,
           "facts": {"size": (rep or {}).get("size")}, "clustering": {}, "remote_targets": [], "embedded": [],
           "decoder_inputs": [], "markers": [], "warnings": list((rep or {}).get("warnings") or [])[:10]}
    out.update(extra)
    return out


def analyse_lnk_report(rep: Any) -> dict[str, Any]:
    """c3/c5/c6/c7: lnk_report() -> normalised result. Precheck or parse failure -> 'error' (never 'empty')."""
    if not isinstance(rep, dict):
        return _empty_result("lnk", "error", "malformed LNK report (not a JSON object)")
    if rep.get("precheck"):
        return _empty_result("lnk", "error", f"malformed LNK: {rep['precheck']}", rep=rep)
    if rep.get("error"):
        return _empty_result("lnk", "error", f"malformed LNK: {rep['error']}", rep=rep)
    j = rep.get("lnk")
    if not isinstance(j, dict) or not isinstance(j.get("header"), dict):
        return _empty_result("lnk", "error", "the LNK parser returned no header", rep=rep)
    hdr = j["header"]
    data = j.get("data") if isinstance(j.get("data"), dict) else {}
    # c3: the exact StringData walk wins over LnkParse3's 260-character reading
    sd = rep.get("string_data") if isinstance(rep.get("string_data"), dict) else {}
    sd_fields = {k: v for k, v in (sd.get("fields") or {}).items() if isinstance(v, dict) and isinstance(v.get("text"), str)}
    string_markers, string_source = [], "parser"
    if sd_fields:
        long_fields = [k for k in ("description", "relative_path", "working_directory")
                       if isinstance(sd_fields.get(k, {}).get("count"), int) and sd_fields[k]["count"] > LIMITS["lnk_ui_field_chars"]]
        differs = [k for k, v in sd_fields.items() if data.get(k) != v["text"]]
        if long_fields:
            string_markers.append("long_string_field")
        if differs:
            string_markers.append("string_data_mismatch")
        if long_fields or differs:
            data, string_source = {k: v["text"] for k, v in sd_fields.items()}, "exact StringData walk"
        if any(v.get("nul") for v in sd_fields.values()):
            string_markers.append("embedded_nul")
    if sd.get("error"):
        string_markers.append("string_data_truncated")
    info = j.get("link_info") if isinstance(j.get("link_info"), dict) else {}
    loc = info.get("location_info") if isinstance(info.get("location_info"), dict) else {}
    extra = j.get("extra") if isinstance(j.get("extra"), dict) else {}
    env = extra.get("ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK") if isinstance(extra.get("ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK"), dict) else {}
    icon_env = extra.get("ICON_LOCATION_BLOCK") if isinstance(extra.get("ICON_LOCATION_BLOCK"), dict) else {}
    tracker = extra.get("DISTRIBUTED_LINK_TRACKER_BLOCK") if isinstance(extra.get("DISTRIBUTED_LINK_TRACKER_BLOCK"), dict) else {}
    term = extra.get("TERMINAL_BLOCK") if isinstance(extra.get("TERMINAL_BLOCK"), dict) else {}

    sources: dict[str, str | None] = {}
    sources["env_block"] = clean_text(env.get("target_unicode") or env.get("target_ansi"), 1024) or None
    sfx = info.get("common_path_suffix_unicode") or info.get("common_path_suffix") or ""
    sfx = sfx if isinstance(sfx, str) else ""
    base = info.get("local_base_path_unicode") or info.get("local_base_path")
    if isinstance(base, str) and base:
        sources["link_info"] = clean_text(base + sfx, 1024) or None
    net = loc.get("net_name_unicode") or loc.get("net_name")
    if isinstance(net, str) and net:
        sources["link_info_network"] = clean_text(net.rstrip("\\") + ("\\" + sfx if sfx else ""), 1024)
    target_items = (j.get("target") or {}).get("items") if isinstance(j.get("target"), dict) else None
    sources["idlist"] = _idlist_path(target_items)
    sources["relative_path"] = clean_text(data.get("relative_path"), 1024) or None
    srcs = {k: v for k, v in sources.items() if v}
    target = next((srcs[k] for k in ("env_block", "link_info_network", "link_info", "idlist", "relative_path") if k in srcs), None)

    args = data.get("command_line_arguments") if isinstance(data.get("command_line_arguments"), str) else None
    icon = clean_text(data.get("icon_location"), 1024) or None
    if not icon:
        icon = clean_text(icon_env.get("target_unicode") or icon_env.get("target_ansi"), 1024) or None
    workdir = clean_text(data.get("working_directory"), 1024) or None
    desc = clean_text(data.get("description"), 1024) or None
    times = {k: iso_z(hdr.get(f"{k}_time")) for k in ("creation", "accessed", "modified")}
    facts: dict[str, Any] = {
        "target": target, "target_sources": srcs, "arguments": clean_text(args, 8192) if args else None,
        "arguments_length": len(args) if args else 0, "working_dir": workdir, "icon_location": icon,
        "icon_index": hdr.get("icon_index"), "description": desc, "show_command": hdr.get("windowstyle"),
        "link_flags": [f for f in hdr.get("link_flags") or [] if isinstance(f, str)],
        "file_attributes": [f for f in hdr.get("file_flags") or [] if isinstance(f, str)],
        "target_times": times, "target_size": hdr.get("file_size"), "hotkey": hdr.get("hotkey"),
        "drive_type": loc.get("drive_type"), "volume_label": loc.get("volume_label_unicode") or loc.get("volume_label") or None,
        "network_share": net if isinstance(net, str) and net else None,
        "network_provider": loc.get("r_network_provider_type") if net else None,
        "extra_blocks": sorted(k for k in extra if k != "TERMINAL_BLOCK"),
        "lnk_size": j.get("size"), "size": rep.get("size"), "parser": rep.get("parser"), "string_data_source": string_source,
        "parser_note": clean_text(rep.get("unavailable"), 200),
    }
    darwin = extra.get("DARWIN_BLOCK") if isinstance(extra.get("DARWIN_BLOCK"), dict) else {}
    if darwin:
        facts["darwin_id"] = clean_text(darwin.get("target_unicode") or darwin.get("target_ansi"), 260)
    markers, remote = list(string_markers), []
    clustering: dict[str, str] = {}
    if tracker:
        mid = machine_id(tracker.get("machine_identifier"))
        d_file = droid_info(tracker.get("droid_file_identifier"))
        d_birth = droid_info(tracker.get("birth_droid_file_identifier"))
        facts["droid"] = {"volume": tracker.get("droid_volume_identifier"), "file": tracker.get("droid_file_identifier"),
                          "birth_volume": tracker.get("birth_droid_volume_identifier"),
                          "birth_file": tracker.get("birth_droid_file_identifier"),
                          "file_time": (d_file or {}).get("time"), "birth_file_time": (d_birth or {}).get("time")}
        if mid:
            clustering["machine_id"] = mid
        if d_file and d_file.get("mac"):
            clustering["droid_mac"] = d_file["mac"]
        if d_birth and d_birth.get("mac") and d_birth["mac"] != clustering.get("droid_mac"):
            clustering["birth_droid_mac"] = d_birth["mac"]
        vm = mac_vm_vendor(clustering.get("droid_mac") or clustering.get("birth_droid_mac"))
        if vm:
            facts["droid_mac_vm_vendor"] = vm
    serial = volume_serial(loc.get("drive_serial_number")) if info.get("location") == "Local" or loc.get("drive_type") else None
    if serial:
        clustering["volume_serial"] = serial

    seen: set[tuple[str, Any]] = set()

    def add_remote(field: str, ref: dict[str, Any]) -> None:
        key = (field, ref.get("raw"))
        if key not in seen and len(remote) < LIMITS["refs_max"]:
            seen.add(key)
            remote.append(dict(ref, field=field))

    for name, value in srcs.items():
        ref = classify_target(value)
        if is_remote(ref):
            add_remote(f"target.{name}", ref)
    for field, value in (("icon_location", icon), ("working_dir", workdir)):
        ref = classify_target(value)
        if is_remote(ref):
            add_remote(field, ref)
    for field, value in (("arguments", args), ("description", desc)):
        for ref in extract_net_refs(value):
            if is_remote(ref):
                add_remote(field, ref)

    tb = _basename(target)
    lolbin = tb if tb in LOLBINS else None
    if lolbin:
        markers.append(f"lolbin_target:{lolbin}")
    if facts["show_command"] == "SW_SHOWMINNOACTIVE":
        markers.append("hidden_window")
    am = argument_markers(args)
    for k in ("whitespace_padding", "arguments_exceed_ui", "encoded_arguments", "obfuscated_arguments"):
        if k in am:
            markers.append(k)
    if am.get("whitespace_padding"):
        facts["hidden_arguments"] = am["whitespace_padding"]["hidden_tail"]
    ib = _basename(re.sub(r",\s*-?\d+\s*$", "", icon or ""))
    if lolbin and ib and ib != tb:
        markers.append("icon_masquerade")
    names = {_basename(v) for v in srcs.values() if _basename(v) and not _SHORT_NAME.search(_basename(v) or "")}
    if len(names) > 1:
        markers.append("target_mismatch")
    if target and not any(times.values()):
        markers.append("zeroed_timestamps")
    if any(r["field"].startswith("target.") for r in remote):
        markers.append("remote_target")
    if any(r["field"] == "icon_location" for r in remote):
        markers.append("remote_icon")
    if any(r["field"] in ("arguments", "description", "working_dir") for r in remote):
        markers.append("remote_reference")
    warnings_ = [w for w in (clean_text(x, 200) for x in rep.get("warnings") or []) if w]
    if warnings_:
        markers.append("parser_warnings")

    embedded: list[dict[str, Any]] = []
    app = rep.get("appended") if isinstance(rep.get("appended"), dict) else None
    if term.get("appended_data_sha256"):
        markers.append("appended_data")
        e: dict[str, Any] = {"origin": "lnk:appended_data", "name": None, "sha256": term["appended_data_sha256"],
                             "size": (term.get("size") or 4) - 4}
        if app and app.get("sha256") == term["appended_data_sha256"]:
            e.update({k: app.get(k) for k in ("md5", "sha1", "kind", "offset", "text", "text_truncated")})
        embedded.append(e)

    decoder_inputs: list[dict[str, Any]] = []
    if args and args.strip():
        cmd = (f'"{target}" ' if target and " " in target else (f"{target} " if target else "")) + args.strip()
        decoder_inputs.append({"origin": "lnk:command_line", "kind": "command_line", "text": cmd[:LIMITS["text_max"]]})
    for e in embedded:
        if e.get("text") and e.get("kind") in SCRIPT_KINDS | {"text"}:
            decoder_inputs.append({"origin": e["origin"], "kind": e["kind"], "text": e["text"]})
    status = "ok" if (target or args or remote or embedded) else "empty"
    return {"format": "lnk", "status": status, "reason_code": None,
            "reason": None if status == "ok" else "LNK has no target, arguments or references",
            "partial": False, "facts": facts, "clustering": clustering, "remote_targets": remote,
            "embedded": embedded, "decoder_inputs": decoder_inputs, "markers": markers,
            "warnings": warnings_[:LIMITS["lnk_max_warnings"]]}


# ======================================================================================== OneNote (c4, c5)

NAME_EXTENSIONS = ("hta", "js", "jse", "vbs", "vbe", "wsf", "wsh", "bat", "cmd", "ps1", "exe", "dll", "scr", "cpl",
                   "lnk", "chm", "zip", "rar", "7z", "iso", "img", "vhd", "vhdx", "msi", "one", "doc", "docm", "docx",
                   "xls", "xlsm", "xlsx", "ppt", "pptm", "pdf", "png", "jpg", "jpeg", "gif", "bmp", "txt", "htm",
                   "html", "url")
# UTF-16LE '.ext' anchors (EmbeddedFileName-like values); the stem is found by walking back from the dot
# (<= 120 chars), so the scan is linear and the number of anchors examined is capped.
_RX_UTF16_EXT = re.compile(
    rb"\.\x00(?:" + b"|".join(b"".join(re.escape(bytes([c])) + rb"\x00" for c in ext.encode())
                             for ext in sorted(NAME_EXTENSIONS, key=len, reverse=True))
    + rb")(?![\x20-\x7e]\x00)", re.I)
UTF16_NAME_MAX_CHARS = 120
UTF16_ANCHORS_MAX = 4096


def _utf16_names(data: bytes, skip: list[tuple[int, int]]) -> list[str]:
    out: list[str] = []
    for i, m in enumerate(_RX_UTF16_EXT.finditer(data)):
        if i >= UTF16_ANCHORS_MAX or len(out) >= LIMITS["onenote_names_max"]:
            break
        dot = m.start()
        if any(a <= dot < b for a, b in skip):
            continue
        start = dot
        while (dot - start) // 2 < UTF16_NAME_MAX_CHARS and start >= 2 and data[start - 1] == 0 and 0x20 <= data[start - 2] <= 0x7E:
            start -= 2
        if start == dot:
            continue
        name = data[start:m.end()].decode("utf-16-le", "replace").strip()
        name = re.split(r"[\\/]", name)[-1]
        if name and name not in out:
            out.append(name)
    return out


def scan_onenote(data: Any) -> dict[str, Any]:
    """c4 sandbox entry: OWN scan of a OneNote file for FileDataStoreObject structures (guidHeader
    {BDE316E7-...}, cbLength u64, unused u32, reserved u64, FileData, padding to 8 bytes, guidFooter
    {71FBA722-...}); pyOneNote is not used. Every embedded file is hashed in memory (c5) and script-like ones
    carry their decoded text for P366."""
    data = bytes(data or b"")
    n = len(data)
    rep: dict[str, Any] = {"kind": "onenote", "size": n, "header": None, "objects": [], "names": [], "markers": [],
                           "error": None, "objects_capped": False, "parser": "builtin FileDataStoreObject scan"}
    if n < 1024:
        rep["error"] = f"truncated OneNote header ({n} of 1024 bytes)"
        return rep
    ftype = data[:16]
    if ftype not in (ONE_GUID, ONETOC2_GUID):
        rep["error"] = f"not a OneNote revision store (guidFileType {uuid.UUID(bytes_le=ftype)})"
        return rep
    rep["kind"] = "onenote" if ftype == ONE_GUID else "onetoc2"
    expected = struct.unpack_from("<Q", data, 196)[0]
    rep["header"] = {"file_type": "one" if ftype == ONE_GUID else "onetoc2", "guid_file": str(uuid.UUID(bytes_le=data[16:32])),
                     "file_format_ok": data[48:64] == ONE_FILE_FORMAT_GUID,
                     "ffv_last_writer": struct.unpack_from("<I", data, 64)[0], "expected_length": expected}
    if not rep["header"]["file_format_ok"]:
        rep["markers"].append("unexpected_file_format_guid")
    if expected and expected != n:
        rep["markers"].append("length_mismatch")
    pos, skip, text_budget = 1024, [], LIMITS["text_total_max"]
    while True:
        off = data.find(FDSO_HEADER, pos)
        if off < 0:
            break
        if len(rep["objects"]) >= LIMITS["onenote_max_objects"]:
            rep["objects_capped"] = True
            rep["markers"].append("objects_capped")
            break
        idx = len(rep["objects"]) + 1
        if off + 36 > n:
            rep["objects"].append({"index": idx, "offset": off, "declared_size": None, "truncated": True, "footer_ok": False})
            rep["markers"].append("object_header_truncated")
            break
        cb = struct.unpack_from("<Q", data, off + 16)[0]
        avail = n - (off + 36)
        obj: dict[str, Any] = {"index": idx, "offset": off, "declared_size": cb, "truncated": cb > avail, "footer_ok": False}
        if data[off + 24:off + 36] != b"\x00" * 12:
            obj["reserved_nonzero"] = True
            rep["markers"].append("reserved_nonzero")
        if cb > avail:
            obj["available"] = avail
            rep["objects"].append(obj)
            rep["markers"].append("object_truncated")
            pos = off + 16
            continue
        blob = data[off + 36:off + 36 + cb]
        foot = off + 36 + cb + (-(36 + cb) % 8)
        obj["footer_ok"] = data[foot:foot + 16] == FDSO_FOOTER
        rec = blob_record(blob)
        if rec.get("text"):
            if text_budget <= 0:
                rec.update(text=None, text_truncated=True)
            else:
                rec["text"] = rec["text"][:text_budget]
                text_budget -= len(rec["text"])
        obj.update(rec)
        rep["objects"].append(obj)
        if obj["footer_ok"]:
            skip.append((off, foot + 16))
            pos = foot + 16
        else:
            rep["markers"].append("footer_missing")
            skip.append((off, off + 36 + cb))
            pos = off + 16
    rep["names"] = _utf16_names(data, skip)
    good = [o for o in rep["objects"] if not o.get("truncated")]
    bad = [o for o in rep["objects"] if o.get("truncated")]
    if bad and not good:
        o = bad[0]
        rep["error"] = (f"embedded object #{o['index']} at 0x{o['offset']:x} declares {o.get('declared_size')} bytes, "
                        f"only {o.get('available', 0)} remain")
    rep["markers"] = sorted(set(rep["markers"]))
    return rep


onenote_report = scan_onenote


def _bind_name(kind: Any, names: list[str], used: set[str]) -> str | None:
    exts = KIND_EXTENSIONS.get(kind or "", ())
    cands = [nm for nm in names if nm.lower().endswith(exts) and nm not in used] if exts else []
    return cands[0] if len(cands) == 1 else None


def analyse_onenote_report(rep: Any) -> dict[str, Any]:
    """c4/c5: scan_onenote() -> normalised result. Embedded files become hash entries with a name bound
    heuristically when exactly one EmbeddedFileName-like string matches the sniffed kind; scripts go to P366.
    Malformed -> 'error' (never 'empty'); a valid file without embedded objects -> 'empty'."""
    if not isinstance(rep, dict):
        return _empty_result("onenote", "error", "malformed OneNote report")
    fmt = rep.get("kind") if rep.get("kind") in ONENOTE_FORMATS else "onenote"
    if rep.get("error"):
        return _empty_result(fmt, "error", f"malformed OneNote: {rep['error']}", rep=rep,
                             facts={"size": rep.get("size"), "header": rep.get("header")}, markers=list(rep.get("markers") or []))
    names = [nm for nm in rep.get("names") or [] if isinstance(nm, str)]
    embedded: list[dict[str, Any]] = []
    decoder_inputs: list[dict[str, Any]] = []
    used: set[str] = set()
    for o in rep.get("objects") or []:
        if not isinstance(o, dict) or o.get("truncated") or not o.get("sha256"):
            continue
        name = _bind_name(o.get("kind"), names, used)
        if name:
            used.add(name)
        origin = f"onenote:object#{o.get('index')}"
        embedded.append({"origin": origin, "name": name, "name_source": "heuristic" if name else None, "size": o.get("size"),
                         "md5": o.get("md5"), "sha1": o.get("sha1"), "sha256": o["sha256"], "kind": o.get("kind"),
                         "offset": o.get("offset"), "footer_ok": o.get("footer_ok")})
        if o.get("text") and o.get("kind") in SCRIPT_KINDS | {"text"}:
            decoder_inputs.append({"origin": origin, "kind": o.get("kind"), "text": o["text"], "name": name})
    markers = list(rep.get("markers") or [])
    facts = {"size": rep.get("size"), "header": rep.get("header"), "embedded_count": len(embedded), "embedded_names": names,
             "kinds": sorted({e["kind"] for e in embedded if e.get("kind")}), "parser": rep.get("parser")}
    status = "ok" if embedded else "empty"
    return {"format": fmt, "status": status, "reason_code": None,
            "reason": None if embedded else "no embedded files (no FileDataStoreObject found)",
            "partial": bool(rep.get("objects_capped")), "facts": facts, "clustering": {}, "remote_targets": [],
            "embedded": embedded, "decoder_inputs": decoder_inputs, "markers": markers, "warnings": []}


# ======================================================================================== MSI (c4, c5)

MSI_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"
MSI_TABLES = ("Property", "CustomAction", "Binary", "InstallExecuteSequence", "InstallUISequence")


def decode_msi_stream_name(name: Any) -> tuple[str | None, bool]:
    """c4: Windows Installer stream-name decompression -> (decoded, is_table). U+3800..U+47FF carry two
    alphabet characters, U+4800..U+483F one, a leading U+4840 marks a table stream."""
    if not isinstance(name, str):
        return None, False
    out, is_table = [], False
    for i, ch in enumerate(name):
        v = ord(ch)
        if i == 0 and v == 0x4840:
            is_table = True
            continue
        if 0x3800 <= v < 0x4800:
            v -= 0x3800
            out.append(MSI_ALPHABET[v & 0x3F])
            out.append(MSI_ALPHABET[(v >> 6) & 0x3F])
        elif 0x4800 <= v < 0x4840:
            out.append(MSI_ALPHABET[v - 0x4800])
        else:
            out.append(ch)
    return "".join(out), is_table


def classify_msi_stream(decoded: str, is_table: bool) -> str:
    if is_table:
        return "table"
    if decoded == "\x05SummaryInformation":
        return "summary"
    if decoded in ("\x05DigitalSignature", "\x05MsiDigitalSignatureEx"):
        return "signature"
    if decoded.startswith("Binary."):
        return "binary"
    if decoded.startswith("Icon."):
        return "icon"
    if decoded.lower().endswith(".cab"):
        return "cabinet"
    return "other"


CA_BASE = {  # Type & 0x3F -> (action, source, description) ("Custom Action Types", Windows Installer)
    1: ("dll", "binary", "DLL from Binary table"), 2: ("exe", "binary", "EXE from Binary table"),
    5: ("jscript", "binary", "JScript from Binary table"), 6: ("vbscript", "binary", "VBScript from Binary table"),
    7: ("install", "substorage", "Concurrent install from substorage"),
    17: ("dll", "file", "DLL installed with the product"), 18: ("exe", "file", "EXE installed with the product"),
    19: ("error", "none", "Error message, install fails"), 21: ("jscript", "file", "JScript file installed"),
    22: ("vbscript", "file", "VBScript file installed"), 23: ("install", "source_tree", "Concurrent install of a product source tree"),
    34: ("exe", "directory", "EXE with working directory, full command line in Target"),
    35: ("set_directory", "directory", "Directory set from formatted Target"),
    37: ("jscript", "inline", "JScript text in Target"), 38: ("vbscript", "inline", "VBScript text in Target"),
    39: ("install", "advertised", "Concurrent install of an advertised product"),
    50: ("exe", "property", "EXE path in Property, arguments in Target"),
    51: ("set_property", "property", "Property set from formatted Target"),
    53: ("jscript", "property", "JScript text in Property"), 54: ("vbscript", "property", "VBScript text in Property"),
}


def decode_ca_type(value: Any) -> dict[str, Any] | None:
    """c4: CustomAction.Type bit field -> base action, source kind and option flags (in-script = deferred,
    no-impersonate = runs as LocalSystem when deferred)."""
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    t = value & 0xFFFF
    base = t & 0x3F
    action, source, desc = CA_BASE.get(base, ("unknown", "unknown", f"unknown base type {base}"))
    in_script = bool(t & 0x400)
    sched = t & 0x300
    return {"type": t, "base": base, "action": action, "source_kind": source, "description": desc,
            "script_language": action if action in ("jscript", "vbscript") else None,
            "executes": action in ("dll", "exe", "jscript", "vbscript", "install"),
            "continue_on_error": bool(t & 0x40), "async": bool(t & 0x80), "deferred": in_script,
            "rollback": in_script and sched == 0x100, "commit": in_script and sched == 0x200,
            "no_impersonate": bool(t & 0x800), "elevated": in_script and bool(t & 0x800),
            "x64_script": bool(t & 0x1000), "hide_target": bool(t & 0x2000), "ts_aware": bool(t & 0x4000)}


_RX_PROP_REF = re.compile(r"\[([A-Za-z_][A-Za-z0-9_.]{0,71})\]")


def resolve_formatted(text: Any, props: dict[str, Any]) -> str | None:
    """[Property] references of a formatted string resolved from the Property table (2 bounded passes;
    directory and file references such as [SystemFolder] / [#File] stay as written)."""
    if not isinstance(text, str):
        return None
    out = text
    for _ in range(LIMITS["format_passes"]):
        new = _RX_PROP_REF.sub(lambda m: props[m.group(1)] if isinstance(props.get(m.group(1)), str) else m.group(0), out)
        if new == out:
            break
        out = new[:LIMITS["text_max"]]
    return out


def _stream_record(decoded: str, is_table: bool, size: int, read: Any, budget: list[int]) -> dict[str, Any]:
    rec: dict[str, Any] = {"name": decoded, "table": is_table, "size": size}
    if classify_msi_stream(decoded, is_table) in ("table", "summary", "signature"):
        return rec
    if size > LIMITS["msi_stream_read_max"]:
        rec["read_error"] = "stream larger than the read cap: not hashed"
        return rec
    try:
        blob = read()
    except (ArchiveLimit, OSError, ValueError, struct.error, IndexError) as exc:
        rec["read_error"] = f"{type(exc).__name__}: {exc}"[:200]
        return rec
    rec.update(blob_record(blob, want_text=True))
    if rec.get("text"):
        if budget[0] <= 0:
            rec.update(text=None, text_truncated=True)
        else:
            rec["text"] = rec["text"][:budget[0]]
            budget[0] -= len(rec["text"])
    return rec


def _msi_streams_olefile(olefile: Any, data: bytes, rep: dict[str, Any]) -> None:
    """Streams, storages, signature and SummaryInformation through olefile (optional, BSD)."""
    ole = olefile.OleFileIO(io.BytesIO(data))
    try:
        rep["clsid"] = (ole.root.clsid or "").lower() or None
        paths = ole.listdir(streams=True, storages=False)
        if len(paths) > LIMITS["msi_max_streams"]:
            rep["streams_capped"] = True
            paths = paths[:LIMITS["msi_max_streams"]]
        budget = [LIMITS["text_total_max"]]
        for path in paths:
            decoded = "/".join(decode_msi_stream_name(p)[0] or "" for p in path)
            is_table = len(path) == 1 and decode_msi_stream_name(path[0])[1]

            def read(path: Any = path) -> bytes:
                with ole.openstream(path) as fh:
                    return fh.read()
            rep["streams"].append(_stream_record(decoded, is_table, ole.get_size(path), read, budget))
        rep["storages"] = ["/".join(decode_msi_stream_name(p)[0] or "" for p in s) for s in ole.listdir(streams=False, storages=True)]
        rep["signed"] = bool(ole.exists("\x05DigitalSignature") or ole.exists("\x05MsiDigitalSignatureEx"))
        if ole.exists("\x05SummaryInformation"):
            meta = ole.get_metadata()
            summ = {}
            for attr in ("title", "subject", "author", "keywords", "comments", "template", "revision_number",
                         "creating_application", "create_time", "last_saved_time", "num_pages", "num_words", "security", "codepage"):
                v = getattr(meta, attr, None)
                summ[attr] = v.decode("cp1252", "replace") if isinstance(v, bytes) else v
            rep["summary"] = _jsonable(summ)
    finally:
        ole.close()


def _msi_streams_builtin(data: bytes, rep: dict[str, Any]) -> None:
    """Streams, storages, signature and SummaryInformation through the bounded built-in [MS-CFB] reader."""
    cfb = CFB(data, budget=Budget())
    rep["clsid"] = cfb.root_clsid
    streams = cfb.streams()
    if len(streams) > LIMITS["msi_max_streams"]:
        rep["streams_capped"] = True
        streams = streams[:LIMITS["msi_max_streams"]]
    budget = [LIMITS["text_total_max"]]
    for e in streams:
        parts = e["path"].split("/")
        decoded = "/".join(decode_msi_stream_name(p)[0] or "" for p in parts)
        is_table = len(parts) == 1 and decode_msi_stream_name(parts[0])[1]
        rep["streams"].append(_stream_record(decoded, is_table, e["size"],
                                             lambda e=e: cfb.read(e, max_out=LIMITS["msi_stream_read_max"]) or b"", budget))
    rep["storages"] = ["/".join(decode_msi_stream_name(p)[0] or "" for p in e["path"].split("/"))
                       for e in cfb.entries if e.get("type") == 1 and e.get("path")]
    rep["signed"] = bool(cfb.find("\x05DigitalSignature") or cfb.find("\x05MsiDigitalSignatureEx"))
    if cfb.find("\x05SummaryInformation"):
        s = ole_summary(cfb)
        rep["summary"] = {"title": s.get("title"), "subject": s.get("subject"), "author": s.get("author"),
                          "keywords": s.get("keywords"), "comments": s.get("comments"), "template": s.get("template"),
                          "revision_number": s.get("revision"), "creating_application": s.get("app_name"),
                          "create_time": s.get("created"), "last_saved_time": s.get("last_saved"),
                          "num_pages": s.get("pages"), "num_words": s.get("words"), "security": s.get("doc_security")}
    rep["cfb_anomalies"] = sorted(set(cfb.anomalies))[:20]


def _msi_tables_pymsi(pymsi: Any, data: bytes, rep: dict[str, Any]) -> None:
    """CustomAction / Binary / Property (+ sequence) tables through the optional pre-release pymsi (MIT).
    strict=False: strict validation prints to stdout, which a shared process must not capture."""
    rep["tables_parser"] = f"pymsi {_version('pymsi')}"
    try:
        pkg = pymsi.Package(io.BytesIO(data), strict=False)
        try:
            tables = {}
            for name in MSI_TABLES:
                tbl = pkg.get(name)
                if tbl is not None:
                    rows = []
                    for i, r in enumerate(tbl):
                        if i >= LIMITS["msi_max_rows"]:
                            break
                        rows.append(dict(r))
                    tables[name] = rows
            rep["table_names"] = sorted(str(t) for t in pkg.tables)[:500]
        finally:
            pkg.close()
        rep["tables"] = _jsonable(tables)
        rep["tables_status"] = "parsed"
    except Exception as exc:  # noqa: BLE001 - pre-release parser: every failure is a status, never a crash (c4)
        rep["tables_status"] = f"error: {type(exc).__name__}: {exc}"[:200]


def msi_report(data: Any, kind: str = "msi", *, use_extras: bool = True) -> dict[str, Any]:
    """c2/c4 sandbox entry: MSI/MSP/MST bytes -> {'kind', 'size', 'parser', 'error', 'clsid', 'summary', 'signed',
    'streams' [{name, table, size, md5, sha1, sha256, kind, text...}], 'storages', 'tables_parser',
    'tables_status' ('parsed' | 'not_installed' | 'disabled' | 'error: ...'), 'tables', 'table_names'}."""
    data = bytes(data or b"")
    rep: dict[str, Any] = {"kind": kind if kind in MSI_FORMATS else "msi", "size": len(data), "parser": None,
                           "unavailable": None, "error": None, "clsid": None, "summary": None, "signed": False,
                           "streams": [], "streams_capped": False, "storages": [], "tables_parser": None,
                           "tables_status": None, "tables": None, "table_names": None}
    olefile = None
    if use_extras:
        try:
            import olefile  # BSD, optional extra 'full'
        except ImportError:
            olefile = None
    try:
        if olefile is not None:
            rep["parser"] = f"olefile {_version('olefile')}"
            _msi_streams_olefile(olefile, data, rep)
        else:
            rep["parser"] = "builtin MS-CFB reader"
            _msi_streams_builtin(data, rep)
    except Exception as exc:  # noqa: BLE001 - damaged compound files raise OSError/ValueError/struct.error/...
        rep["error"] = f"{type(exc).__name__}: {exc}"[:300]
        return rep
    if not use_extras:
        rep["tables_status"] = "disabled"
        return rep
    try:
        import pymsi  # MIT, pre-release, optional extra 'msi'
    except ImportError:
        rep["tables_status"] = "not_installed"
        return rep
    _msi_tables_pymsi(pymsi, data, rep)
    return rep


def _rows(tables: Any, name: str) -> list[dict[str, Any]]:
    rows = (tables or {}).get(name) if isinstance(tables, dict) else None
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


def analyse_msi_report(rep: Any) -> dict[str, Any]:
    """c4/c5: msi_report() -> normalised result. A compound-file failure -> 'error' (never 'empty'). Without
    pymsi (or when it fails) the result is still 'ok' with reason 'MSI tables not parsed (...)': streams are
    hashed and script streams go to P366 anyway."""
    if not isinstance(rep, dict):
        rep = {"error": "malformed MSI report"}
    fmt = rep.get("kind") if rep.get("kind") in MSI_FORMATS else "msi"
    if rep.get("error"):
        return _empty_result(fmt, "error", f"malformed {fmt.upper()}: {rep['error']}", rep=rep)
    streams = [s for s in rep.get("streams") or [] if isinstance(s, dict)]
    by_name = {s.get("name"): s for s in streams}
    tables = rep.get("tables") if isinstance(rep.get("tables"), dict) else None
    tstatus = rep.get("tables_status") or "not_installed"
    reason = None
    if tables is None or tstatus != "parsed":
        why = {"not_installed": "optional pymsi not installed",
               "disabled": "optional parsers disabled by setting windows_artifact_triage_use_extras"}.get(tstatus, f"pymsi {tstatus}")
        reason = f"{MSI_NOT_PARSED} ({why})"
    props: dict[str, Any] = {}
    for r in _rows(tables, "Property"):
        if isinstance(r.get("Property"), str):
            props[r["Property"]] = r.get("Value") if isinstance(r.get("Value"), str) else None
    seq: dict[str, list[dict[str, Any]]] = {}
    for tname in ("InstallExecuteSequence", "InstallUISequence"):
        for r in _rows(tables, tname):
            if isinstance(r.get("Action"), str):
                seq.setdefault(r["Action"], []).append({"table": tname, "sequence": r.get("Sequence"), "condition": r.get("Condition")})
    summ = rep.get("summary") if isinstance(rep.get("summary"), dict) else {}
    tmpl = summ.get("template") if isinstance(summ.get("template"), str) else ""
    facts: dict[str, Any] = {
        "size": rep.get("size"), "clsid": rep.get("clsid"), "signed": bool(rep.get("signed")), "parser": rep.get("parser"),
        "product": {k: props.get(k) for k in ("ProductName", "Manufacturer", "ProductVersion", "ProductCode", "UpgradeCode",
                                              "ProductLanguage") if props.get(k)},
        "summary": {k: v for k, v in {
            "title": clean_text(summ.get("title"), 256), "subject": clean_text(summ.get("subject"), 256),
            "author": clean_text(summ.get("author"), 256), "platform": (tmpl.split(";")[0] or None) if tmpl else None,
            "languages": tmpl.split(";")[1] if ";" in tmpl else None, "package_code": clean_text(summ.get("revision_number"), 64),
            "creating_application": clean_text(summ.get("creating_application"), 256),
            "created": iso_z(summ.get("create_time")), "last_saved": iso_z(summ.get("last_saved_time")),
            "schema": summ.get("num_pages"), "security": summ.get("security")}.items() if v not in (None, "")},
        "tables_parser": rep.get("tables_parser"), "tables_status": tstatus, "table_names": rep.get("table_names"),
        "stream_count": len(streams), "storages": rep.get("storages") or [], "custom_actions": [], "property_count": len(props),
        "cfb_anomalies": rep.get("cfb_anomalies") or [],
    }
    embedded, decoder_inputs, remote, markers = [], [], [], []
    for s in streams:
        cls = classify_msi_stream(s.get("name") or "", bool(s.get("table")))
        if cls in ("table", "summary", "signature") or not s.get("sha256"):
            continue
        key = s["name"].split(".", 1)[1] if cls in ("binary", "icon") and "." in s["name"] else s["name"]
        embedded.append({"origin": f"msi:stream:{s['name']}", "name": key, "stream_class": cls, "size": s.get("size"),
                         "md5": s.get("md5"), "sha1": s.get("sha1"), "sha256": s["sha256"], "kind": s.get("kind")})
    script_streams: set[str] = set()
    for r in _rows(tables, "CustomAction"):
        ca = decode_ca_type(r.get("Type"))
        if ca is None:
            continue
        name, source, target = r.get("Action"), r.get("Source"), r.get("Target")
        entry = dict(ca, name=clean_text(name, 72), source=clean_text(source, 72),
                     target=clean_text(target, 2048) if isinstance(target, str) else None, scheduled=seq.get(name, []))
        origin = f"msi:custom_action:{clean_text(name, 72)}"
        text, cmd = None, None
        if ca["base"] in (37, 38) and isinstance(target, str):
            text = target
        elif ca["base"] in (53, 54) and isinstance(props.get(source), str):
            text = props[source]
        elif ca["base"] in (5, 6) and isinstance(source, str):
            st = by_name.get(f"Binary.{source}")
            script_streams.add(f"Binary.{source}")
            if st and st.get("text"):
                text = st["text"]
            entry["payload_sha256"] = (st or {}).get("sha256")
        elif ca["base"] in (1, 2) and isinstance(source, str):
            entry["payload_sha256"] = (by_name.get(f"Binary.{source}") or {}).get("sha256")
        if ca["base"] == 34 and isinstance(target, str):
            cmd = resolve_formatted(target, props)
        elif ca["base"] == 50 and isinstance(source, str):
            exe = resolve_formatted(props.get(source) or f"[{source}]", props)
            cmd = f"{exe} {resolve_formatted(target, props) or ''}".strip()
        elif ca["base"] in (2, 18) and isinstance(source, str):
            cmd = f"{'Binary' if ca['base'] == 2 else 'File'}:{source} {resolve_formatted(target, props) or ''}".strip()
        if text:
            decoder_inputs.append({"origin": origin, "kind": ca["script_language"], "text": text[:LIMITS["text_max"]]})
            markers.append("script_custom_action")
        if cmd:
            entry["command_line"] = cmd[:2048]
            decoder_inputs.append({"origin": origin, "kind": "command_line", "text": cmd[:LIMITS["text_max"]]})
            exe_name = (_basename(re.split(r"\s+", cmd.strip().strip('"'), maxsplit=1)[0]) or "").split("]")[-1]
            if exe_name in LOLBINS or exe_name + ".exe" in LOLBINS or re.search(r"(?i)\b(?:powershell|pwsh|mshta|wscript|cscript)\b", cmd):
                markers.append("lolbin_custom_action")
                entry["lolbin"] = True
            entry.update({k: True for k in argument_markers(cmd) if k in ("encoded_arguments", "obfuscated_arguments")})
        if ca["base"] in (1, 2, 17, 18):
            markers.append("binary_custom_action")
        if ca["elevated"] and ca["executes"]:
            markers.append("elevated_custom_action")
        if ca["action"] == "install":
            markers.append("nested_install")
        for value in ((None if ca["script_language"] else target), cmd):
            for ref in extract_net_refs(value if isinstance(value, str) else None):
                if is_remote(ref):
                    remote.append(dict(ref, field=origin))
        facts["custom_actions"].append(entry)
    for s in streams:  # script streams not referenced by a parsed CustomAction (tables not parsed, or unused)
        if s.get("text") and s.get("name") not in script_streams and s.get("kind") in SCRIPT_KINDS and \
                classify_msi_stream(s.get("name") or "", bool(s.get("table"))) in ("binary", "other"):
            decoder_inputs.append({"origin": f"msi:stream:{s['name']}", "kind": s.get("kind"), "text": s["text"]})
    for key, value in props.items():
        for ref in extract_net_refs(value):
            if is_remote(ref):
                remote.append(dict(ref, field=f"msi:property:{key}"))
    dedup, seen = [], set()
    for r in remote:
        k = (r["field"], r.get("raw"))
        if k not in seen and len(dedup) < LIMITS["refs_max"]:
            seen.add(k)
            dedup.append(r)
    if reason:
        markers.append("tables_not_parsed")
    if facts["cfb_anomalies"]:
        markers.append("cfb_anomalies")
    return {"format": fmt, "status": "ok", "reason_code": None, "reason": reason, "partial": bool(rep.get("streams_capped")),
            "facts": facts, "clustering": {}, "remote_targets": dedup, "embedded": embedded, "decoder_inputs": decoder_inputs,
            "markers": sorted(set(markers)), "warnings": []}


# ======================================================================================== dispatch (c2)


def child_entry(fmt: str, data: Any, *, use_extras: bool = True) -> dict[str, Any]:
    """c2: the trusted entry point core/sandbox.py will run on the file bytes; the parent chose ``fmt`` from the
    magic or the original file name (a damaged artefact stays in scope). Output fits the 1 MB JSON cap."""
    if fmt == "lnk":
        rep = lnk_report(data, use_extras=use_extras)
    elif fmt in ONENOTE_FORMATS:
        rep = scan_onenote(data)
    elif fmt in MSI_FORMATS:
        rep = msi_report(data, fmt, use_extras=use_extras)
    else:
        rep = {"kind": "unknown", "size": len(data or b"")}
    return fit_report(rep)


def analyse(rep: Any) -> dict[str, Any]:
    """Child report -> normalised result by kind; unknown kinds are not_applicable (SKIPPED, c1)."""
    kind = rep.get("kind") if isinstance(rep, dict) else None
    if kind == "lnk":
        return analyse_lnk_report(rep)
    if kind in ONENOTE_FORMATS:
        return analyse_onenote_report(rep)
    if kind in MSI_FORMATS:
        return analyse_msi_report(rep)
    return _empty_result(kind or "unknown", "not_applicable", "not an LNK, OneNote or Windows Installer file", code="not_applicable")


# ======================================================================================== P366 hand-off (c3, c5)

_RX_PS_ENC = re.compile(r"(?i)(?:^|[\s\"'(])[-/–—]e(?:c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|"
                        r"ncodedcomm|ncodedcomma|ncodedcomman|ncodedcommand)?\s{1,16}[\"']?([A-Za-z0-9+/]{16,}={0,2})")
_RX_FROMB64 = re.compile(r"(?i)frombase64string\(\s{0,8}[\"']([A-Za-z0-9+/]{16,}={0,2})[\"']")


def _b64_text(blob: str, utf16: bool) -> str | None:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    if utf16:
        if len(raw) % 2:
            return None
        text = raw.decode("utf-16-le", "replace")
    else:
        text, _ = bytes_to_text(raw)
    return text if text and looks_text(text, 0.9) else None


def standin_decode(text: str) -> dict[str, Any]:
    """Stand-in for the P366 decoder while it is not installed: static decoding of PowerShell
    -EncodedCommand (UTF-16LE base64) and FromBase64String literals only, <= 3 nested rounds, bounded matches
    and output (no eval, no engine, nothing is run)."""
    layers: list[dict[str, Any]] = []
    current = text[:LIMITS["text_max"]]
    for n in range(1, LIMITS["decode_rounds"] + 1):
        found: list[str] = []
        for rx, utf16, label in ((_RX_PS_ENC, True, "base64 UTF-16LE -EncodedCommand"), (_RX_FROMB64, False, "FromBase64String")):
            for i, m in enumerate(rx.finditer(current)):
                if i >= LIMITS["decode_matches"]:
                    break
                dec = _b64_text(m.group(1), utf16)
                if dec:
                    found.append(dec[:LIMITS["text_max"]])
                    layers.append({"n": n, "technique": label, "label": f"layer {n}: {label}", "text": dec[:LIMITS["text_max"]]})
        if not found:
            break
        current = "\n".join(found)[:LIMITS["text_max"]]
    return {"decoder": "stand-in", "layers": layers, "path": ">".join(f"L{x['n']}:{x['technique']}" for x in layers)}


def script_decoder() -> Any:
    """``decode_layers`` of the P366 module when it is installed, else None (the stand-in is used)."""
    try:
        mod = importlib.import_module(SCRIPT_DECODER_MODULE)
    except Exception:  # noqa: BLE001 - P366 not in this build: the stand-in decodes
        return None
    fn = getattr(mod, "decode_layers", None)
    return fn if callable(fn) else None


def decode_for_triage(text: str, decoder: Any = None) -> dict[str, Any]:
    """c3/c5: hand one script/command line to P366 (``decode_layers(text, redact=...)``: static, <= 5 layers,
    1 MB per layer, 5 s); any failure or unexpected answer falls back to :func:`standin_decode`."""
    if decoder is not None:
        try:
            out = decoder(text, redact=redact_text)
            raw_layers = out.get("layers") if isinstance(out, dict) else None
            if isinstance(raw_layers, list):
                layers = [{"n": x.get("n"), "technique": str(x.get("technique") or ""), "label": str(x.get("label") or ""),
                           "text": x["text"][:LIMITS["text_max"]]}
                          for x in raw_layers if isinstance(x, dict) and isinstance(x.get("text"), str)]
                return {"decoder": "script_decoder", "layers": layers, "path": str(out.get("path") or ""),
                        "stop": out.get("stop")}
        except Exception as exc:  # noqa: BLE001 - a P366 failure never ends the triage: the stand-in decodes
            res = standin_decode(text)
            res["decoder_error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
            return res
    return standin_decode(text)


# ======================================================================================== module


def namespace_or_cdn(etype: T, value: str) -> bool:
    """P366 c5: schema/namespace/documentation URLs and library CDNs found in script text are not IOCs."""
    if etype is T.URL:
        host = (_RX_HOSTPORT.match(value.lower()) or [None, ""])[1] or ""
    elif etype is T.DOMAIN:
        host = value.lower()
    else:
        return False
    host = host.strip("[]").rstrip(".")
    return any(host == h or host.endswith("." + h) for h in NAMESPACE_AND_CDN_HOSTS)


def _pivot_note(relation: str, field: str, hostile: bool = True) -> str:
    base = {"lnk_target": "shortcut target", "lnk_icon": "shortcut icon location (fetched by Explorer on folder view)",
            "lnk_reference": "reference in the shortcut", "msi_reference": "reference in the MSI"}.get(relation, "reference")
    if not hostile:
        return f"{base} ({field}): vendor metadata (ARP property), passive modules only, never fetched"
    return f"{base} ({field}): hostile, passive modules only, never resolved or contacted over HTTP, SMB or WebDAV"


def _ip_expandable(value: str | None) -> bool:
    try:
        return bool(value) and ipaddress.ip_address(value).is_global  # type: ignore[arg-type]
    except ValueError:
        return False


@register
class WindowsArtifactTriage(Module):
    name = "windows_artifact_triage"
    title = "Windows artefact triage (LNK, MSI, OneNote)"
    description = (
        "Parses local Windows shortcuts (LNK), Windows Installer packages (MSI/MSP/MST) and OneNote files offline: "
        "shortcut targets, arguments, icons and tracker ids, MSI CustomActions and streams, OneNote embedded files. "
        "Scripts are decoded statically, embedded files hashed in memory, remote shares listed as hostile pivots; "
        "nothing is executed, written or contacted."
    )
    category = "file_analysis"
    accepts = {T.FILE}
    produces = {T.URL, T.DOMAIN, T.IPV4, T.IPV6, T.KEYWORD, T.SHA256, T.MD5, T.SHA1}
    tags = {"offline"}
    reference = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943"
    notice = ("FILE input only and fully offline: shortcut targets, UNC/WebDAV shares and URLs are listed as hostile "
              "pivots and never contacted. Machine ids, droid MACs and volume serials are clustering attributes only "
              "(never looked up). Optional parsers (LnkParse3, olefile, pymsi) run in process until the shared "
              "file-analysis sandbox exists; setting windows_artifact_triage_use_extras=false keeps to the built-in readers.")
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.2
    timeout = 30.0
    max_pivots = 200
    default_enabled = True
    settings = {
        "windows_artifact_triage_use_extras": SettingSpec(
            True, "windows_artifact_triage: use the optional LnkParse3/olefile/pymsi parsers when installed (P367 c3/c4); "
                  "false keeps to the built-in readers (they run in process until core/sandbox.py exists)"),
    }

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        try:
            fmt, sn, how = artefact_format(entity.value)
        except FileRefused as exc:
            return res.mark("error" if exc.kind == "unreadable" else "skipped", exc.reason,
                            reason_code="error" if exc.kind == "unreadable" else "not_applicable")
        if fmt is None:
            return res.mark("skipped", f"not an LNK, OneNote or Windows Installer file ({sn.get('description') or sn.get('kind')})",
                            reason_code="not_applicable")
        try:
            data, size = read_capped(entity.value, LIMITS["input_max"])
        except FileRefused as exc:
            return res.mark("error", exc.reason)
        if not data:
            return res.mark("skipped", "empty file", reason_code="not_applicable")
        use_extras = bool(ctx.setting("windows_artifact_triage_use_extras", True))
        report = child_entry(fmt, data, use_extras=use_extras)
        result = analyse(report)
        result.setdefault("facts", {})["detected_by"] = how
        if size > len(data):
            result["partial"] = True
            result.setdefault("markers", []).append("input_capped")
        status = result.get("status")
        summary = summary_line(result)
        res.attr("file_type", FORMAT_LABELS.get(result.get("format") or "", sn.get("description")))
        res.attr("windows_artifact_summary", summary)
        if status in ("error", "unavailable", "not_applicable"):
            res.raw = cap_json({"format": fmt, "detected_by": how, "report": report, "result": result})
            if status == "not_applicable":
                return res.mark("skipped", result.get("reason") or "not applicable", reason_code="not_applicable")
            if status == "unavailable":
                return res.mark("unavailable", result.get("reason") or "optional parser missing", reason_code="package")
            return res.mark("error", f"could not parse the {FORMAT_LABELS.get(fmt, fmt)}: {result.get('reason')}")
        decoded = self._emit(res, result, ctx)
        res.raw = cap_json({"format": fmt, "detected_by": how, "summary": summary, "report": report, "result": result,
                            "script_decoder": decoded})
        if status == "empty":
            return res.mark("empty")
        return res

    # ------------------------------------------------------------------------------------ output mapping

    def _emit(self, res: ModuleResult, result: dict[str, Any], ctx: Any) -> list[dict[str, Any]]:
        fmt = result.get("format")
        facts = result.get("facts") or {}
        markers = list(result.get("markers") or [])
        self._attributes(res, result)
        items = artefact_findings(result)
        if result.get("partial") and "input_capped" in markers:
            items.append(fact("parser_anomaly", "low", "Artefact larger than the 100 MB input cap: only the first 100 MB were parsed",
                              confidence="confirmed", criterion="input cap of the file-analysis sandbox (P367 c2)", marker="input_capped"))
        emit_findings(res, items)
        pivoted: set[tuple[str, str]] = set()
        kept = [0]

        def pivot(etype: T, value: str, relation: str, *, expand: bool = True, note: str = "", confidence: str = "confirmed") -> None:
            canon = Entity.try_make(etype, value)
            if canon is None or kept[0] >= self.max_pivots:
                return
            if relation == "extracted_from" and (canon.type.value, canon.value) in pivoted:
                return  # already pivoted from a structured field (target, icon, property...)
            ent = res.pivot(etype, value, relation, confidence=confidence, expand=expand, note=note)
            if ent is not None:
                kept[0] += 1
                pivoted.add((ent.type.value, ent.value))

        # c6: remote targets in any representation become hostile pivots (never contacted)
        for ref in result.get("remote_targets") or []:
            field = str(ref.get("field") or "")
            hostile = True
            if fmt == "lnk":
                relation = "lnk_icon" if field == "icon_location" else "lnk_target" if field.startswith("target.") else "lnk_reference"
            else:
                relation = "msi_reference"
                if field.startswith("msi:property:ARP"):
                    hostile = False
            note = _pivot_note(relation, field, hostile)
            if ref.get("url") and ref.get("kind") in ("url", "webdav"):
                pivot(T.URL, ref["url"], relation, note=note)
            elif webdav_url(ref):
                pivot(T.URL, webdav_url(ref) or "", relation, note=note + " (URL derived from the WebDAV UNC path)")
            if ref.get("ip"):
                pivot(T.IPV6 if ":" in ref["ip"] else T.IPV4, ref["ip"], relation, expand=_ip_expandable(ref["ip"]), note=note)
            elif ref.get("host") and "." in ref["host"]:
                pivot(T.DOMAIN, ref["host"], relation, note=note)
        # c5: embedded files hashed in memory -> sha256 pivots
        for e in result.get("embedded") or []:
            if e.get("sha256"):
                label = " ".join(x for x in (e.get("kind") or "file", repr(e["name"]) if e.get("name") else "") if x)
                pivot(T.SHA256, e["sha256"], "contains",
                      note=f"embedded {label} from {e.get('origin')}: hashed in memory, never written to disk or executed")
        # c7: clustering identifiers, never looked up
        for key, ns in (("machine_id", "lnk_machine_id"), ("droid_mac", "lnk_droid_mac"), ("birth_droid_mac", "lnk_droid_mac"),
                        ("volume_serial", "lnk_volume_serial")):
            v = (result.get("clustering") or {}).get(key)
            if v:
                pivot(T.KEYWORD, f"{ns}:{v}", "lnk_metadata", expand=False,
                      note="LNK clustering identifier: links artefacts across cases, never sent to any lookup")
        # c3/c5: scripts and command lines go to P366, the decoded text to the P172 extractor
        decoded: list[dict[str, Any]] = []
        decoder = script_decoder()
        budget = LIMITS["text_total_max"]
        for item in result.get("decoder_inputs") or []:
            text = item.get("text") if isinstance(item.get("text"), str) else ""
            if not text.strip() or budget <= 0:
                continue
            text = text[:min(LIMITS["extract_text_max"], budget)]
            budget -= len(text)
            out = decode_for_triage(text, decoder)
            iocs = self._extract(text, item.get("origin"), out, pivot, ctx)
            decoded.append({"origin": item.get("origin"), "kind": item.get("kind"), "chars": len(text),
                            "sha256": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(), "decoder": out.get("decoder"),
                            "layers": [x.get("label") for x in out.get("layers") or []], "iocs": iocs,
                            "decoder_error": out.get("decoder_error"), "layers_text": [x.get("text") for x in out.get("layers") or []]})
        res.attr("script_decoder_inputs", [{k: v for k, v in d.items() if v not in (None, [], "") and k != "layers_text"}
                                           for d in decoded][:100])
        if facts.get("arguments") is not None and any(d["origin"] == "lnk:command_line" and d["layers"] for d in decoded):
            first = next(d for d in decoded if d["origin"] == "lnk:command_line" and d["layers"])
            res.attr("lnk_decoded_command", clean_text("\n".join(t for t in first["layers_text"] if t), 4096))
        return decoded

    def _extract(self, text: str, origin: Any, decoded: dict[str, Any], pivot: Any, ctx: Any) -> int:
        """IOCs of a decoder input and of its decoded layers (core P172 extractor) -> 'extracted_from' pivots.
        Namespace/CDN/warninglisted values are dropped (P366 c5); hostile candidates are never contacted."""
        count = 0
        blocks = [(text, "found in")] + [(x["text"], "decoded from") for x in decoded.get("layers") or [] if isinstance(x.get("text"), str)]
        for block, how in blocks:
            try:
                found = _ioc.extract(block, source_type="file", org=getattr(ctx, "org", None))
            except Exception:  # noqa: BLE001 - the extractor never raises by contract; stay safe on odd input
                continue
            for item in found:
                ent = item.entity
                if ent.type not in IOC_TYPES or ent.type in (T.CVE, T.MITRE) or item.noise or "warninglisted" in item.flags:
                    continue
                if namespace_or_cdn(ent.type, ent.value):
                    continue
                note = f"{how} {origin} (static decoding, nothing run): hostile candidate, passive modules only, never contacted"
                pivot(ent.type, ent.value, "extracted_from", expand=item.expand, note=note,
                      confidence="probable" if how == "decoded from" else "confirmed")
                count += 1
        return count

    def _attributes(self, res: ModuleResult, result: dict[str, Any]) -> None:
        fmt = result.get("format")
        facts = result.get("facts") or {}
        res.attr("windows_artifact", cap_json({"format": fmt, "status": result.get("status"), "reason": result.get("reason"),
                                               "parser": facts.get("parser"), "detected_by": facts.get("detected_by"),
                                               "markers": result.get("markers") or [], "warnings": result.get("warnings") or [],
                                               "partial": bool(result.get("partial"))}, 64 * 1024))
        clustering = result.get("clustering") or {}
        res.attr("lnk_machine_id", clustering.get("machine_id"))
        res.attr("lnk_droid_mac", clustering.get("droid_mac"))
        res.attr("lnk_birth_droid_mac", clustering.get("birth_droid_mac"))
        res.attr("lnk_volume_serial", clustering.get("volume_serial"))
        if fmt == "lnk":
            res.attr("lnk_shortcut", cap_json({k: v for k, v in facts.items() if v not in (None, "", [], {}, 0)
                                               and k not in ("detected_by",)}, 64 * 1024))
        elif fmt in MSI_FORMATS:
            res.attr("msi_package", cap_json({k: facts.get(k) for k in ("product", "summary", "signed", "clsid", "parser", "tables_parser",
                                                                        "table_names", "stream_count", "storages", "property_count",
                                                                        "cfb_anomalies") if facts.get(k) not in (None, "", [], {})},
                                             64 * 1024))
            res.attr("msi_tables_status", result.get("reason") or "parsed")
            res.attr("msi_custom_actions", cap_json([{k: v for k, v in ca.items() if v not in (None, "", [], False)}
                                                     for ca in facts.get("custom_actions") or []][:200], 64 * 1024))
        elif fmt in ONENOTE_FORMATS:
            res.attr("onenote_file", cap_json({k: facts.get(k) for k in ("header", "embedded_count", "embedded_names", "kinds", "parser")
                                               if facts.get(k) not in (None, "", [], {})}, 64 * 1024))
        res.attr("embedded_files", [{k: e.get(k) for k in ("origin", "name", "kind", "size", "md5", "sha1", "sha256", "stream_class")
                                     if e.get(k) not in (None, "")} for e in result.get("embedded") or []][:200])


def _f(code: str, description: str = "", *, confidence: str = "probable", attack: tuple[str, ...] = (), **detail: Any) -> dict[str, Any]:
    severity, base_attack, tags = SEVERITY[code]
    return fact(code, severity, FINDING_TITLES[code], confidence=confidence, criterion=CRITERIA.get(code, ""),
                attack=list(dict.fromkeys(base_attack + tuple(attack))) or None, tags=tags, description=description, **detail)


def artefact_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalised result -> finding dicts (one per code; the values in the description and data)."""
    out: list[dict[str, Any]] = []
    fmt, facts, markers = result.get("format"), result.get("facts") or {}, result.get("markers") or []
    remote = result.get("remote_targets") or []
    if fmt == "lnk":
        tgt = facts.get("target") or "?"
        groups = {"lnk_remote_target": [r for r in remote if str(r.get("field", "")).startswith("target.")],
                  "lnk_remote_icon": [r for r in remote if r.get("field") == "icon_location"],
                  "lnk_remote_reference": [r for r in remote if r.get("field") in ("arguments", "description", "working_dir")]}
        for code, refs in groups.items():
            if refs:
                shown = "; ".join(f"{r['field']}: {ref_text(r)} ({r['kind']})" for r in refs[:10])
                item = _f(code, f"{shown}. Never resolved or contacted by V3LUM.",
                          refs=[{"field": r["field"], "kind": r["kind"], "value": ref_text(r)} for r in refs[:20]])
                if code != "lnk_remote_reference" and all(internal_share(r) for r in refs):
                    item["severity"] = "medium"  # SMB share on a private address or NetBIOS name: common in enterprises
                    item["description"] += " Internal file-share host (private address or NetBIOS name): MEDIUM."
                out.append(item)
        lol = [m.split(":", 1)[1] for m in markers if m.startswith("lolbin_target:")]
        if lol:
            out.append(_f("lnk_lolbin_target", f"target {tgt}", attack=(LOLBIN_ATTACK.get(lol[0], "T1218"),), binary=lol[0]))
        simple = {"whitespace_padding": ("lnk_whitespace_padding", f"hidden command: {facts.get('hidden_arguments') or ''}"[:600]),
                  "encoded_arguments": ("lnk_encoded_arguments", "the decoded text goes to the script decoder (static, never run)"),
                  "hidden_window": ("lnk_hidden_window", f"ShowCommand {facts.get('show_command')}"),
                  "icon_masquerade": ("lnk_icon_masquerade", f"icon {facts.get('icon_location')} on target {tgt}"),
                  "appended_data": ("lnk_appended_data", "appended bytes are hashed in memory (sha256 pivot)"),
                  "target_mismatch": ("lnk_target_mismatch", json.dumps(facts.get("target_sources") or {}, ensure_ascii=False)[:600]),
                  "long_string_field": ("lnk_long_string_field", "the strings were re-read with the full [MS-SHLLINK] counts")}
        if "obfuscated_arguments" in markers and "encoded_arguments" not in markers:
            out.append(_f("lnk_encoded_arguments", "obfuscated arguments (char codes, carets, joins)"))
        for marker, (code, text) in simple.items():
            if marker in markers:
                out.append(_f(code, text, target=tgt))
    elif fmt in ONENOTE_FORMATS:
        by_code: dict[str, list[dict[str, Any]]] = {}
        for e in result.get("embedded") or []:
            k = e.get("kind")
            code = ("onenote_embedded_active" if k in ACTIVE_KINDS else "onenote_embedded_container" if k in CONTAINER_KINDS
                    else "onenote_embedded_file")
            by_code.setdefault(code, []).append(e)
        for code, items in by_code.items():
            shown = ", ".join(" ".join(x for x in (str(e.get("kind") or "file"), e.get("name") or "", f"({e.get('size')} bytes)") if x)
                              for e in items[:10])
            out.append(_f(code, f"{len(items)} embedded file(s): {shown}", confidence="confirmed" if code == "onenote_embedded_file" else "probable",
                          files=[{"kind": e.get("kind"), "name": e.get("name"), "size": e.get("size"), "sha256": e.get("sha256")} for e in items[:20]]))
    elif fmt in MSI_FORMATS:
        cas = facts.get("custom_actions") or []
        script = [ca for ca in cas if ca.get("script_language") and ca.get("executes")]
        if script:
            langs = sorted({ca["script_language"] for ca in script})
            attack = tuple("T1059.005" if lang == "vbscript" else "T1059.007" for lang in langs)
            out.append(_f("msi_script_custom_action", "; ".join(f"{ca.get('name')} ({ca['description']})" for ca in script[:10]),
                          attack=attack, actions=[ca.get("name") for ca in script[:20]]))
        groups2 = {"msi_lolbin_custom_action": [ca for ca in cas if ca.get("lolbin")],
                   "msi_binary_custom_action": [ca for ca in cas if ca.get("base") in (1, 2, 17, 18)],
                   "msi_elevated_custom_action": [ca for ca in cas if ca.get("elevated") and ca.get("executes")],
                   "msi_nested_install": [ca for ca in cas if ca.get("action") == "install"]}
        for code, items in groups2.items():
            if items:
                shown = "; ".join(f"{ca.get('name')}: {(ca.get('command_line') or ca['description'])[:160]}" for ca in items[:10])
                out.append(_f(code, shown, actions=[ca.get("name") for ca in items[:20]]))
        if str(result.get("reason") or "").startswith(MSI_NOT_PARSED):
            out.append(_f("msi_tables_not_parsed", f"{result['reason']}: CustomAction, Binary and Property tables were not read; "
                                                    "streams were hashed and script streams decoded", confidence="confirmed"))
    for marker in ("parser_warnings", "reserved_nonzero", "footer_missing", "length_mismatch", "object_truncated", "cfb_anomalies",
                   "string_data_truncated", "embedded_nul", "string_data_mismatch"):
        if marker == "string_data_mismatch" and "long_string_field" in markers:
            continue  # the 260-character quirk already has its own finding
        if marker in markers:
            detail = {"parser_warnings": result.get("warnings"), "cfb_anomalies": facts.get("cfb_anomalies")}.get(marker) or []
            text = f"{fmt} structure anomaly: {marker}" + (f" ({'; '.join(map(str, detail[:3]))})" if detail else "")
            out.append(_f("parser_anomaly", text, confidence="confirmed", marker=marker))
    return out


def summary_line(result: dict[str, Any]) -> str:
    """One terminal line per artefact (analyst_ux style used across G12)."""
    fmt, facts, st = result.get("format"), result.get("facts") or {}, result.get("status")
    if st in ("error", "unavailable", "not_applicable"):
        return f"{fmt}: {st} - {result.get('reason')}"
    remote = len(result.get("remote_targets") or [])
    emb = len(result.get("embedded") or [])
    if fmt == "lnk":
        args = (facts.get("arguments") or "").strip()
        bits = [f"LNK -> {facts.get('target') or '?'}" + (f" {args[:60]}..." if len(args) > 60 else (f" {args}" if args else ""))]
        bits += [m for m in result.get("markers") or [] if not m.startswith("lolbin_target")][:4]
        if remote:
            bits.append(f"{remote} remote ref(s), never contacted")
        if (result.get("clustering") or {}).get("machine_id"):
            bits.append(f"machine {result['clustering']['machine_id']}")
        return clean_text("; ".join(bits), 400) or "LNK"
    if fmt in ONENOTE_FORMATS:
        kinds = ", ".join(str(e.get("kind") or "?") for e in result.get("embedded") or [])
        return f"OneNote: {emb} embedded file(s)" + (f" ({kinds})" if kinds else "")
    if fmt in MSI_FORMATS:
        p = facts.get("product") or {}
        cas = facts.get("custom_actions") or []
        head = f"{fmt.upper()} '{p.get('ProductName') or (facts.get('summary') or {}).get('subject') or '?'}'"
        if p.get("ProductVersion"):
            head += f" {p['ProductVersion']}"
        if p.get("Manufacturer"):
            head += f" by {p['Manufacturer']}"
        tail = (f"{len(cas)} custom action(s), {len(result.get('decoder_inputs') or [])} item(s) for the script decoder"
                if result.get("reason") is None else str(result["reason"]))
        return clean_text(f"{head}: {tail}; {emb} embedded stream(s)", 400) or fmt
    return f"{fmt}: {st}"


__all__ = [
    "WindowsArtifactTriage",
    "analyse",
    "analyse_lnk_report",
    "analyse_msi_report",
    "analyse_onenote_report",
    "argument_markers",
    "artefact_findings",
    "artefact_format",
    "blob_record",
    "child_entry",
    "classify_target",
    "decode_ca_type",
    "decode_for_triage",
    "decode_msi_stream_name",
    "droid_info",
    "extract_net_refs",
    "fit_report",
    "lnk_precheck",
    "lnk_read_builtin",
    "lnk_report",
    "lnk_string_data",
    "msi_report",
    "scan_onenote",
    "sniff_blob",
    "sniff_kind",
    "standin_decode",
    "summary_line",
    "volume_serial",
]
