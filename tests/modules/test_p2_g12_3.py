"""Batch p2-G12-3 (windows_artifact_triage, P367): synthetic artefact builders (c8) and library cross-checks.

Final condition 8: synthetic LNK, OneNote and MSI samples built in tests, including a malformed one of each.
Every builder below is a pure ``bytes`` function (ported from the batch prep, no file is read). Payloads are
INERT (Write-Output / echo / string assignments only); network values are documentation values (203.0.113.x,
198.51.100.x, example.com); MACs are the RFC 7042 documentation range 00:00:5e:00:53:xx plus one VMware-OUI
value with a documentation-style suffix; machine ids, products and companies are invented.

Formats: [MS-SHLLINK] (LNK), [MS-ONESTORE] (the header and FileDataStoreObject structures the module scans),
[MS-CFB] v3 + the Windows Installer database layout (string pool, _Tables, _Columns, column-major tables,
stream-name compression) + [MS-OLEPS] SummaryInformation.

tests/fixtures/windows_artifact_triage/*.child.json are what the REAL LnkParse3 1.6.0 / olefile 0.47 /
pymsi 0.0.0rc1 produced on these exact bytes (prep capture, 2026-11-26; _provenance.json pins the sha256 of
every input). The tests at the end of this file re-run the libraries when they are installed (they skip
otherwise) and check that the module's built-in readers agree with them.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import importlib.util
import json
import re
import struct
import uuid
import zlib
from pathlib import Path

import pytest

from tests.fakes import module_fixture
from v3lum.modules.file_analysis import windows_artifact_triage as W

UTC = dt.timezone.utc
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "windows_artifact_triage"

# ---- shared helpers ------------------------------------------------------------------------------------------


def filetime(when):
    """datetime (UTC) -> Windows FILETIME (100 ns since 1601-01-01)."""
    delta = when - dt.datetime(1601, 1, 1, tzinfo=UTC)
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def fat_datetime(when):
    """datetime -> (FAT date, FAT time) as used by shell items."""
    date = ((when.year - 1980) << 9) | (when.month << 5) | when.day
    time = (when.hour << 11) | (when.minute << 5) | (when.second // 2)
    return date, time


def uuid_v1(when, node, clock_seq=0x1234):
    """Deterministic RFC 4122 version-1 UUID (droid object ids are v1: timestamp + clock seq + MAC node)."""
    ts = int((when - dt.datetime(1582, 10, 15, tzinfo=UTC)).total_seconds() * 10_000_000)
    return uuid.UUID(fields=(ts & 0xFFFFFFFF, (ts >> 32) & 0xFFFF, ((ts >> 48) & 0x0FFF) | 0x1000,
                             ((clock_seq >> 8) & 0x3F) | 0x80, clock_seq & 0xFF, node))


def ps_enc(script):
    """PowerShell -EncodedCommand form (base64 of UTF-16LE)."""
    return base64.b64encode(script.encode('utf-16-le')).decode('ascii')


def png_1x1():
    def chunk(kind, body):
        return struct.pack('>I', len(body)) + kind + body + struct.pack('>I', zlib.crc32(kind + body) & 0xFFFFFFFF)
    ihdr = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b'\x00\xff\xff\xff')
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', ihdr) + chunk(b'IDAT', idat) + chunk(b'IEND', b'')


def mz_stub(tag=b'fixture'):
    """A DOS-header-shaped stub: sniffs as 'pe' (MZ + e_lfanew -> 'PE\\0\\0') but has no sections or code."""
    head = bytearray(b'MZ' + b'\x90\x00' + b'\x00' * 60)
    struct.pack_into('<I', head, 0x3C, 0x80)
    body = bytes(head) + b'This program cannot be run in DOS mode.\r\r\n$' + b'\x00' * (0x80 - 64 - 43)
    return body + b'PE\x00\x00' + b'\x4c\x01' + b'\x00' * 18 + b'v3-stub:' + tag


# ---- LNK (MS-SHLLINK) ------------------------------------------------------------------------------------------

LNK_CLSID = uuid.UUID('00021401-0000-0000-C000-000000000046').bytes_le
CLSID_MY_COMPUTER = uuid.UUID('20D04FE0-3AEA-1069-A2D8-08002B30309D').bytes_le
F_IDLIST, F_LINKINFO, F_NAME, F_RELPATH, F_WORKDIR, F_ARGS, F_ICON, F_UNICODE = (
    0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80)
F_EXPSTRING = 0x200
SW_NORMAL, SW_MINNOACTIVE = 1, 7


def lnk_header(flags, *, attrs=0x20, times=(None, None, None), size=0, icon_index=0, show=SW_NORMAL,
               header_size=0x4C, clsid=LNK_CLSID):
    ft = [filetime(t) if t else 0 for t in times]
    return struct.pack('<I16sIIQQQIiIHHII', header_size, clsid, flags, attrs, ft[0], ft[1], ft[2], size,
                       icon_index, show, 0, 0, 0, 0)


def lnk_idlist(path, *, file_size=0, when=dt.datetime(2026, 11, 19, 12, 0, 0, tzinfo=UTC)):
    """My Computer -> volume -> file entries (ANSI primary names, no extension blocks)."""
    items = [struct.pack('<H', 20) + b'\x1f\x50' + CLSID_MY_COMPUTER]
    drive, rest = path[:3], path[3:]
    vol = b'\x2f' + drive.encode('ascii').ljust(20, b'\x00') + b'\x00\x00'
    items.append(struct.pack('<H', 2 + len(vol)) + vol)
    parts = [p for p in rest.split('\\') if p]
    fdate, ftime = fat_datetime(when)
    for i, name in enumerate(parts):
        last = i == len(parts) - 1
        nm = name.encode('cp1252') + b'\x00'
        nm += b'\x00' * (len(nm) % 2)
        body = bytes([0x32 if last else 0x31, 0]) + struct.pack('<IHHH', file_size if last else 0, fdate, ftime,
                                                                0x20 if last else 0x10) + nm
        items.append(struct.pack('<H', 2 + len(body)) + body)
    data = b''.join(items) + b'\x00\x00'
    return struct.pack('<H', len(data)) + data


def lnk_linkinfo_local(path, serial, label=b''):
    volid = struct.pack('<IIII', 16 + len(label) + 1, 3, serial, 0x10) + label + b'\x00'
    base = path.encode('cp1252') + b'\x00'
    hs = 0x1C
    vo = hs
    bo = vo + len(volid)
    so = bo + len(base)
    total = so + 1
    return struct.pack('<IIIIIII', total, hs, 0x1, vo, bo, 0, so) + volid + base + b'\x00'


def lnk_linkinfo_network(net_name, suffix, provider=0x002E0000):
    nn = net_name.encode('cp1252') + b'\x00'
    cnrl = struct.pack('<IIIII', 0x14 + len(nn), 0x2, 0x14, 0, provider) + nn
    sfx = suffix.encode('cp1252') + b'\x00'
    hs = 0x1C
    co = hs
    so = co + len(cnrl)
    total = so + len(sfx)
    return struct.pack('<IIIIIII', total, hs, 0x2, 0, 0, co, so) + cnrl + sfx


def lnk_string(text):
    return struct.pack('<H', len(text)) + text.encode('utf-16-le')


def lnk_env_block(target, sig=0xA0000001):
    return (struct.pack('<II', 0x314, sig) + target.encode('cp1252').ljust(260, b'\x00')
            + target.encode('utf-16-le').ljust(520, b'\x00'))


def lnk_tracker_block(machine_id, droid_volume, droid_file, birth_volume=None, birth_file=None):
    return (struct.pack('<IIII', 0x60, 0xA0000003, 0x58, 0) + machine_id.encode('ascii').ljust(16, b'\x00')
            + droid_volume.bytes_le + droid_file.bytes_le + (birth_volume or droid_volume).bytes_le
            + (birth_file or droid_file).bytes_le)


def lnk_bytes(*, flags, idlist=b'', linkinfo=b'', strings=(), extras=(), appended=b'', **hdr):
    out = lnk_header(flags, **hdr) + idlist + linkinfo + b''.join(lnk_string(s) for s in strings)
    out += b''.join(extras) + struct.pack('<I', 0)
    return out + appended


PS_TARGET = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
CMD_TARGET = 'C:\\Windows\\System32\\cmd.exe'
DOC_MAC = 0x00005E005301          # RFC 7042 documentation MAC 00:00:5e:00:53:01
VMWARE_DOC_MAC = 0x000C29005302   # VMware OUI 00:0c:29 + documentation-style suffix (synthetic)
T_DROID = dt.datetime(2026, 11, 20, 10, 0, 0, tzinfo=UTC)
PS_LNK_SCRIPT = "Write-Output 'fixture'; $u = 'https://203.0.113.10/boleto/nfe.ps1'"
PS_LNK_ARGS = '-NoP -NonI -w hidden -enc ' + ps_enc(PS_LNK_SCRIPT)
PADDED_ARGS = '\t' + ' ' * 256 + '\r\n' + '/c echo start /min mshta https://203.0.113.11/nfe.hta'
APPENDED_VBS = (b"' appended stage (fixture, strings only)\r\n"
                b'Dim u : u = "https://203.0.113.12/a.vbs"\r\n')


def build_lnk_ok():
    """PowerShell -enc dropper shape: hidden window, PDF-like icon (msedge.exe,11), env block, tracker block."""
    flags = F_IDLIST | F_LINKINFO | F_NAME | F_RELPATH | F_WORKDIR | F_ARGS | F_ICON | F_UNICODE | F_EXPSTRING
    t = dt.datetime(2026, 11, 19, 12, 0, 0, tzinfo=UTC)
    droid_vol = uuid.UUID('6f1d2a3b-4c5d-4e6f-8a9b-0c1d2e3f5301')
    return lnk_bytes(
        flags=flags, times=(t, t, t), size=450560, icon_index=11, show=SW_MINNOACTIVE,
        idlist=lnk_idlist(PS_TARGET, file_size=450560), linkinfo=lnk_linkinfo_local(PS_TARGET, 0x5E005301),
        strings=('Fatura NF-e 2026-11 (PDF)', '..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                 'C:\\Windows\\System32', PS_LNK_ARGS,
                 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'),
        extras=(lnk_env_block('%windir%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'),
                lnk_tracker_block('desktop-exmpl01', droid_vol, uuid_v1(T_DROID, DOC_MAC))))


def build_lnk_webdav():
    """Target on a WebDAV share (\\\\host@SSL\\DavWWWRoot) + UNC icon (forced-authentication shape), zeroed times."""
    flags = F_LINKINFO | F_NAME | F_ICON | F_UNICODE
    droid_vol = uuid.UUID('6f1d2a3b-4c5d-4e6f-8a9b-0c1d2e3f5302')
    return lnk_bytes(
        flags=flags, linkinfo=lnk_linkinfo_network('\\\\203.0.113.7@SSL\\DavWWWRoot', 'nfe\\documento.vbs'),
        strings=('Documento NF-e', '\\\\198.51.100.9\\icons\\pdf.ico'),
        extras=(lnk_tracker_block('win-exmpl02', droid_vol, uuid_v1(T_DROID, VMWARE_DOC_MAC, 0x0042)),))


def build_lnk_padded_overlay():
    """cmd.exe with whitespace-padded arguments (hidden past the 260-char UI field) and data appended after the
    terminal block (LnkParse3 reports it as TERMINAL_BLOCK.appended_data_sha256)."""
    flags = F_IDLIST | F_LINKINFO | F_RELPATH | F_ARGS | F_ICON | F_UNICODE
    t = dt.datetime(2026, 11, 18, 8, 30, 0, tzinfo=UTC)
    droid_vol = uuid.UUID('6f1d2a3b-4c5d-4e6f-8a9b-0c1d2e3f5303')
    return lnk_bytes(
        flags=flags, times=(t, t, t), size=289792, show=SW_MINNOACTIVE,
        idlist=lnk_idlist(CMD_TARGET, file_size=289792), linkinfo=lnk_linkinfo_local(CMD_TARGET, 0x5E005303),
        strings=('..\\..\\..\\Windows\\System32\\cmd.exe', PADDED_ARGS, '%SystemRoot%\\System32\\imageres.dll'),
        extras=(lnk_tracker_block('desktop-exmpl01', droid_vol, uuid_v1(T_DROID, DOC_MAC, 0x1235)),),
        appended=APPENDED_VBS)


LONG_DESCRIPTION = 'Fatura NF-e 2026-11 ' + '.' * 280          # 300 chars: > the 260-char UI field
LONG_DESC_ARGS = '/c echo https://203.0.113.60/x'


def build_lnk_long_description():
    """Description longer than 260 chars: Windows reads all CountCharacters, LnkParse3 1.6.0 reads 260 and then
    mis-aligns every later string (arguments come back as garbage, silently) - a parser-evasion shape."""
    flags = F_IDLIST | F_NAME | F_WORKDIR | F_ARGS | F_UNICODE
    return lnk_bytes(flags=flags, idlist=lnk_idlist(CMD_TARGET), strings=(LONG_DESCRIPTION, 'C:\\Windows',
                                                                         LONG_DESC_ARGS))


def build_lnk_malformed():
    """Truncated inside the 76-byte ShellLinkHeader (LnkParse3 raises struct.error)."""
    return build_lnk_ok()[:60]


def build_lnk_bad_clsid():
    """Full-length file whose HeaderSize/LinkCLSID are wrong: LnkParse3 only *warns* and keeps parsing garbage,
    so the stdlib pre-check must turn it into ERROR (c5)."""
    data = bytearray(build_lnk_ok())
    struct.pack_into('<I', data, 0, 0x4B)
    data[4:20] = uuid.UUID('00021401-0000-0000-C000-000000000047').bytes_le
    return bytes(data)


# ---- OneNote (MS-ONESTORE header + FileDataStoreObject) --------------------------------------------------------

ONE_GUID = uuid.UUID('7B5C52E4-D88C-4DA7-AEB1-5378D02996D3').bytes_le
FILE_FORMAT_GUID = uuid.UUID('109ADD3F-911B-49F5-A5D0-1791EDC8AED8').bytes_le
FDSO_HEADER = uuid.UUID('BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC').bytes_le
FDSO_FOOTER = uuid.UUID('71FBA722-0F79-4A0B-BB13-899256426B24').bytes_le

HTA_LURE = (b'<html><head><title>NF-e</title>\r\n'
            b'<HTA:APPLICATION ID="nfe" WINDOWSTATE="minimize" SHOWINTASKBAR="no"/>\r\n'
            b'<script language="VBScript">\r\n'
            b"' fixture only: string assignments, nothing is executed\r\n"
            b'Dim u : u = "https://203.0.113.13/nfe/stage2.txt"\r\n'
            b'Dim c : c = Chr(104) & Chr(116) & Chr(116) & Chr(112)\r\n'
            b'</script></head><body></body></html>\r\n')


ONE_FILE_ID = uuid.UUID('0e9a3c55-5301-4e6f-8a9b-0c1d2e3f0001')


def onenote_header(total_len, file_guid=ONE_FILE_ID):
    h = bytearray(1024)
    h[0:16] = ONE_GUID
    h[16:32] = file_guid.bytes_le
    h[48:64] = FILE_FORMAT_GUID
    struct.pack_into('<IIII', h, 64, 0x2A, 0x2A, 0x2A, 0x2A)
    struct.pack_into('<Q', h, 196, total_len)
    return bytes(h)


def fdso(data, declared=None):
    body = FDSO_HEADER + struct.pack('<Q', len(data) if declared is None else declared) + b'\x00' * 12 + data
    return body + b'\x00' * (-len(body) % 8) + FDSO_FOOTER


def property_area(*names):
    """Stand-in for the revision-store property data where OneNote keeps EmbeddedFileName (UTF-16LE)."""
    out = b'\x00' * 32
    for n in names:
        out += struct.pack('<I', len(n) * 2) + n.encode('utf-16-le') + b'\x00' * 12
    return out + b'\x00' * (-len(out) % 8)


def onenote_bytes(objects, names=(), declared=None):
    body = property_area(*names) + b''.join(fdso(o, declared) for o in objects)
    head = onenote_header(1024 + len(body))
    return head + body


def build_onenote_ok():
    return onenote_bytes([png_1x1(), HTA_LURE], names=('imagem.png', 'Fatura_2026-11.hta'))


def build_onenote_empty():
    return onenote_bytes([], names=('Nota.txt',))


def build_onenote_malformed():
    """Declares a 2 GiB embedded object in a 1.1 KB file and claims a wrong expected length."""
    data = bytearray(onenote_bytes([b'MZ' + b'\x00' * 30], declared=0x7FFFFFFF))
    return bytes(data[:len(data) - 24])


# ---- CFB writer (adapted from prep/p1-G12-1) + property sets -------------------------------------------------

OLE_MAGIC = bytes.fromhex('d0cf11e0a1b11ae1')
MSI_CLSID = uuid.UUID('000C1084-0000-0000-C000-000000000046').bytes_le


def cfb_bytes(streams, root_clsid=b'\x00' * 16):
    """streams: [(name, bytes)] (flat; MSI databases keep everything in the root storage). Returns CFB v3."""
    SS, MSS, CUT = 512, 64, 4096
    nodes = {'': {'name': 'Root Entry', 'type': 5, 'children': [], 'data': b'', 'clsid': root_clsid}}
    for name, data in streams:
        nodes[name] = {'name': name, 'type': 2, 'children': [], 'data': data, 'clsid': b'\x00' * 16}
        nodes['']['children'].append(name)
    order = list(nodes)
    sid = {p: i for i, p in enumerate(order)}

    def key(p):
        n = nodes[p]['name']
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

    root_child, lr = tree(nodes['']['children'])
    mini, minifat, starts, big = bytearray(), [], {}, []
    for p in order[1:]:
        data = nodes[p]['data']
        if len(data) < CUT:
            if not data:
                starts[p] = 0xFFFFFFFE
                continue
            first = len(mini) // MSS
            cnt = -(-len(data) // MSS)
            mini += data + b'\x00' * (cnt * MSS - len(data))
            minifat += [first + k + 1 for k in range(cnt - 1)] + [0xFFFFFFFE]
            starts[p] = first
        else:
            big.append(p)
    sectors, chains = [], []

    def alloc(data):
        cnt = -(-len(data) // SS) if data else 0
        first = len(sectors)
        for k in range(cnt):
            sectors.append(data[k * SS:(k + 1) * SS].ljust(SS, b'\x00'))
        return first, cnt

    for p in big:
        first, cnt = alloc(nodes[p]['data'])
        starts[p] = first
        chains.append((first, cnt))
    ms_first, ms_cnt = alloc(bytes(mini)) if mini else (0xFFFFFFFE, 0)
    if ms_cnt:
        chains.append((ms_first, ms_cnt))
    mf = b''.join(struct.pack('<I', v) for v in minifat)
    mf_first, mf_cnt = alloc(mf) if mf else (0xFFFFFFFE, 0)
    if mf_cnt:
        chains.append((mf_first, mf_cnt))
    entries = bytearray()
    for p in order:
        n = nodes[p]
        name = n['name'].encode('utf-16-le') + b'\x00\x00'
        left, right = lr.get(p, (0xFFFFFFFF, 0xFFFFFFFF))
        child = root_child if p == '' else 0xFFFFFFFF
        if p == '':
            start, size = (ms_first if ms_cnt else 0xFFFFFFFE), len(mini)
        else:
            start, size = starts[p], len(n['data'])
        entries += name.ljust(64, b'\x00') + struct.pack('<HBBIII', len(name), n['type'], 1, left, right, child)
        entries += n['clsid'] + struct.pack('<IQQIQ', 0, 0, 0, start, size)
    while len(entries) % SS:
        entries += (b'\x00' * 64 + struct.pack('<HBBIII', 0, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
                    + b'\x00' * 16 + struct.pack('<IQQIQ', 0, 0, 0, 0, 0))
    dir_first, dir_cnt = alloc(bytes(entries))
    chains.append((dir_first, dir_cnt))
    nfat = 1
    while nfat * (SS // 4) < len(sectors) + nfat:
        nfat += 1
    fat_first = len(sectors)
    fat = [0xFFFFFFFF] * (nfat * SS // 4)
    for first, cnt in chains:
        for k in range(cnt):
            fat[first + k] = first + k + 1 if k < cnt - 1 else 0xFFFFFFFE
    for k in range(nfat):
        fat[fat_first + k] = 0xFFFFFFFD
    fatb = b''.join(struct.pack('<I', v) for v in fat)
    for k in range(nfat):
        sectors.append(fatb[k * SS:(k + 1) * SS])
    difat = [fat_first + k for k in range(nfat)] + [0xFFFFFFFF] * (109 - nfat)
    header = (OLE_MAGIC + b'\x00' * 16 + struct.pack('<HHHHH', 0x3E, 3, 0xFFFE, 9, 6) + b'\x00' * 6
              + struct.pack('<IIIIIIIII', 0, nfat, dir_first, 0, CUT, mf_first if mf_cnt else 0xFFFFFFFE, mf_cnt,
                            0xFFFFFFFE, 0) + struct.pack('<109I', *difat))
    return header + b''.join(sectors)


FMTID_SUMMARY = uuid.UUID('F29F85E0-4FF9-1068-AB91-08002B27B3D9').bytes_le


def propset_stream(fmtid, props):
    """props: {pid: (vt, value)} -> single-section PropertySetStream (codepage 1252)."""
    props = dict(props)
    props.setdefault(1, (0x02, 1252))
    vals, offs = bytearray(), []
    base = 8 + 8 * len(props)
    for pid, (vt, v) in sorted(props.items()):
        offs.append((pid, base + len(vals)))
        if vt == 0x02:
            vals += struct.pack('<HHhH', vt, 0, v, 0)
        elif vt == 0x03:
            vals += struct.pack('<HHi', vt, 0, v)
        elif vt == 0x1E:
            b = v.encode('cp1252') + b'\x00'
            b += b'\x00' * (-len(b) % 4)
            vals += struct.pack('<HHI', vt, 0, len(v) + 1) + b
        elif vt == 0x40:
            vals += struct.pack('<HHQ', vt, 0, v)
    body = struct.pack('<II', 8 + 8 * len(props) + len(vals), len(props))
    body += b''.join(struct.pack('<II', pid, off) for pid, off in offs) + vals
    head = struct.pack('<HHI', 0xFFFE, 0, 0x00020006) + b'\x00' * 16 + struct.pack('<I', 1)
    return head + fmtid + struct.pack('<I', len(head) + 20) + body


# ---- MSI database ------------------------------------------------------------------------------------------------

MSI_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._'


def msi_stream_name(name, table=False):
    """Windows Installer stream-name compression (pairs of [0-9A-Za-z._] -> U+3800..U+47FF, single -> U+4800+,
    table streams prefixed with U+4840)."""
    out = ['\u4840'] if table else []
    i = 0
    while i < len(name):
        a = MSI_ALPHABET.find(name[i])
        if a >= 0:
            b = MSI_ALPHABET.find(name[i + 1]) if i + 1 < len(name) else -1
            if b >= 0:
                out.append(chr(0x3800 + a + (b << 6)))
                i += 2
                continue
            out.append(chr(0x4800 + a))
        else:
            out.append(name[i])
        i += 1
    return ''.join(out)


# column type bits (Wine msipriv.h / rust-msi): VALID 0x100, LOCALIZABLE 0x200, NONBINARY 0x400, STRING 0x800,
# NULLABLE 0x1000, KEY 0x2000; low byte = width. Binary (OBJECT) = STRING|VALID without NONBINARY and width 0.
def col_s(width, key=False, null=False, loc=False):
    return 0x0D00 | width | (0x2000 if key else 0) | (0x1000 if null else 0) | (0x200 if loc else 0)


def col_i(width, key=False, null=False):
    return 0x0100 | width | (0x2000 if key else 0) | (0x1000 if null else 0)


COL_BINARY = 0x0900


def msi_database(tables, summary, binaries, *, codepage=1252, corrupt_columns=False):
    """tables: {name: ([(col_name, type_bits)], [row tuples])}; binaries: {'Binary.Key': bytes}."""
    order, refs = [], {}

    def sid(s):
        if s is None:
            return 0
        if s not in refs:
            order.append(s)
            refs[s] = 0
        refs[s] += 1
        return order.index(s) + 1

    names = sorted(tables)
    streams = []
    streams.append((msi_stream_name('_Tables', True), b''.join(struct.pack('<H', sid(n)) for n in names)))
    crow = [(t, i + 1, c, ty) for t in names for i, (c, ty) in enumerate(tables[t][0])]
    cols = (b''.join(struct.pack('<H', sid(r[0])) for r in crow)
            + b''.join(struct.pack('<H', (r[1] + 0x8000) & 0xFFFF) for r in crow)
            + b''.join(struct.pack('<H', sid(r[2])) for r in crow)
            + b''.join(struct.pack('<H', (r[3] + 0x8000) & 0xFFFF) for r in crow))
    if corrupt_columns:
        cols = cols[:-1]
    streams.append((msi_stream_name('_Columns', True), cols))
    for t in names:
        columns, rows = tables[t]
        out = bytearray()
        for ci, (_, ty) in enumerate(columns):
            for row in rows:
                v = row[ci]
                if ty & 0x0800 and not (ty & 0x0400) and (ty & 0xFF) == 0:
                    out += struct.pack('<H', 1)                     # binary cell marker
                elif ty & 0x0800:
                    out += struct.pack('<H', sid(v))
                elif (ty & 0xFF) == 4:
                    out += struct.pack('<I', 0 if v is None else (v + 0x80000000) & 0xFFFFFFFF)
                else:
                    out += struct.pack('<H', 0 if v is None else (v + 0x8000) & 0xFFFF)
        streams.append((msi_stream_name(t, True), bytes(out)))
    pool = struct.pack('<I', codepage)
    data = b''
    for s in order:
        b = s.encode('cp1252')
        pool += struct.pack('<HH', len(b), refs[s])
        data += b
    streams.append((msi_stream_name('_StringPool', True), pool))
    streams.append((msi_stream_name('_StringData', True), data))
    for k, v in binaries.items():
        streams.append((msi_stream_name(k), v))
    streams.append(('\x05SummaryInformation', propset_stream(FMTID_SUMMARY, summary)))
    return cfb_bytes(streams, MSI_CLSID)


PRODUCT_CODE = '{0E9A3C55-5301-4E6F-8A9B-0C1D2E3F4A01}'
UPGRADE_CODE = '{0E9A3C55-5301-4E6F-8A9B-0C1D2E3F4A02}'
PACKAGE_CODE = '{0E9A3C55-5301-4E6F-8A9B-0C1D2E3F4A03}'
VBS_CA = ("' fixture: string assignments only\r\n"
          'Dim u : u = "http://198.51.100.20/stage2.txt"\r\n'
          'Dim s : s = Chr(87) & Chr(83)\r\n')
JS_BINARY = (b'function Main() {\r\n'
             b'  // fixture: string building only, nothing is fetched or run\r\n'
             b"  var u = String.fromCharCode(104,116,116,112,115) + '://203.0.113.22/js.txt';\r\n"
             b'  return 1;\r\n}\r\n')
PS_MSI_SCRIPT = "Write-Output 'fixture'; $u = 'https://203.0.113.23/nfe.ps1'"
PS_MSI_CMD = 'powershell.exe -NoP -NonI -w hidden -enc ' + ps_enc(PS_MSI_SCRIPT)

PROPERTY_COLS = [('Property', col_s(72, key=True)), ('Value', col_s(0, loc=True))]
CA_COLS = [('Action', col_s(72, key=True)), ('Type', col_i(2)), ('Source', col_s(72, null=True)),
           ('Target', col_s(0, null=True)), ('ExtendedType', col_i(4, null=True))]
BINARY_COLS = [('Name', col_s(72, key=True)), ('Data', COL_BINARY)]
SEQ_COLS = [('Action', col_s(72, key=True)), ('Condition', col_s(255, null=True)), ('Sequence', col_i(2, null=True))]


def msi_summary(subject):
    t = filetime(dt.datetime(2026, 11, 20, 9, 0, 0, tzinfo=UTC))
    return {2: (0x1E, 'Installation Database'), 3: (0x1E, subject), 4: (0x1E, 'Example Org Ltda'),
            5: (0x1E, 'Installer'), 6: (0x1E, 'This installer database contains the logic and data required '
                                             'to install ' + subject + '.'),
            7: (0x1E, 'Intel;1046'), 9: (0x1E, PACKAGE_CODE), 12: (0x40, t), 13: (0x40, t), 14: (0x03, 200),
            15: (0x03, 2), 18: (0x1E, 'Windows Installer XML Toolset (3.11.2.4516)'), 19: (0x03, 2)}


def msi_ok_tables():
    props = [('ProductName', 'Leitor NF-e'), ('Manufacturer', 'Example Org Ltda'), ('ProductVersion', '1.0.0'),
             ('ProductCode', PRODUCT_CODE), ('UpgradeCode', UPGRADE_CODE), ('ProductLanguage', '1046'),
             ('ALLUSERS', '1'), ('DLURL', 'https://203.0.113.21/nfe/pkg.txt'), ('CMDEXE', '[SystemFolder]cmd.exe'),
             ('ARPHELPLINK', 'https://www.example.com/suporte')]
    cas = [('SetDlUrl', 51, 'DLURL', 'https://203.0.113.21/nfe/pkg.txt', None),
           ('RunVbs', 38, None, VBS_CA, None),
           ('RunJsBin', 5, 'JsPayload', 'Main', None),
           ('RunDllBin', 1 | 0x400 | 0x800, 'CADll', 'DllEntry', None),
           ('RunPs', 34 | 0x400 | 0x800, 'SystemFolder', PS_MSI_CMD, None),
           ('RunCmdProp', 50 | 0x40, 'CMDEXE', '/c echo https://203.0.113.24/x.bat', None)]
    seq = [('CostInitialize', None, 800), ('SetDlUrl', None, 1100), ('RunVbs', 'NOT Installed', 1500),
           ('RunJsBin', 'NOT Installed', 1510), ('RunDllBin', 'NOT Installed', 6590),
           ('RunPs', 'NOT Installed', 6595), ('RunCmdProp', 'NOT Installed', 6596), ('InstallFinalize', None, 6600)]
    return {'Property': (PROPERTY_COLS, props), 'CustomAction': (CA_COLS, cas),
            'Binary': (BINARY_COLS, [('CADll', None), ('JsPayload', None)]),
            'InstallExecuteSequence': (SEQ_COLS, seq)}


MSI_BINARIES = {'Binary.JsPayload': JS_BINARY, 'Binary.CADll': mz_stub(b'CADll')}


def build_msi_ok():
    return msi_database(msi_ok_tables(), msi_summary('Leitor NF-e'), MSI_BINARIES)


def build_msi_benign():
    props = [('ProductName', 'Planilha Exemplo'), ('Manufacturer', 'Example Org Ltda'), ('ProductVersion', '2.4.1'),
             ('ProductCode', '{0E9A3C55-5301-4E6F-8A9B-0C1D2E3F4B01}'), ('ProductLanguage', '1046'),
             ('ARPURLINFOABOUT', 'https://www.example.com/')]
    seq = [('CostInitialize', None, 800), ('InstallFiles', None, 4000), ('InstallFinalize', None, 6600)]
    return msi_database({'Property': (PROPERTY_COLS, props), 'InstallExecuteSequence': (SEQ_COLS, seq)},
                        msi_summary('Planilha Exemplo'), {})


def build_msi_bad_tables():
    """Valid CFB + SummaryInformation + Binary streams, but _Columns is one byte short: pymsi raises, olefile
    streams still work -> 'MSI tables not parsed (pymsi error ...)', never EMPTY (c4)."""
    return msi_database(msi_ok_tables(), msi_summary('Leitor NF-e'), MSI_BINARIES, corrupt_columns=True)


def build_msi_malformed():
    """CFB header intact, file cut after 3 sectors: olefile cannot read the directory/FAT -> ERROR (c5)."""
    return build_msi_ok()[:512 * 3]


NOT_ARTIFACT = b'Relatorio de teste - arquivo de texto comum, sem estrutura LNK/OneNote/MSI.\n'

BUILDERS = {
    'lnk_ok.lnk': build_lnk_ok,
    'lnk_webdav.lnk': build_lnk_webdav,
    'lnk_padded_overlay.lnk': build_lnk_padded_overlay,
    'lnk_long_description.lnk': build_lnk_long_description,
    'lnk_malformed.lnk': build_lnk_malformed,
    'lnk_bad_clsid.lnk': build_lnk_bad_clsid,
    'onenote_ok.one': build_onenote_ok,
    'onenote_empty.one': build_onenote_empty,
    'onenote_malformed.one': build_onenote_malformed,
    'msi_ok.msi': build_msi_ok,
    'msi_benign.msi': build_msi_benign,
    'msi_bad_tables.msi': build_msi_bad_tables,
    'msi_malformed.msi': build_msi_malformed,
    'not_artifact.txt': lambda: NOT_ARTIFACT,
}


# ======================================================================================== fixture hygiene (c8)

PROVENANCE = module_fixture("windows_artifact_triage", "_provenance.json")["files"]


@pytest.mark.parametrize("case", sorted(BUILDERS))
def test_builders_reproduce_the_captured_inputs(case):
    """The library reports in tests/fixtures/windows_artifact_triage/ were captured on exactly these bytes."""
    data = BUILDERS[case]()
    assert PROVENANCE[case]["sha256"] == hashlib.sha256(data).hexdigest() and PROVENANCE[case]["bytes"] == len(data)
    assert PROVENANCE[case]["origin"] == "synthetic"


def test_malformed_variant_exists_for_each_format():
    assert {"lnk_malformed.lnk", "lnk_bad_clsid.lnk", "onenote_malformed.one", "msi_malformed.msi", "msi_bad_tables.msi"} <= set(BUILDERS)


DOC_NETS = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")


def _doc_ip(ip):
    import ipaddress
    a = ipaddress.ip_address(ip)
    return any(a in ipaddress.ip_network(n) for n in DOC_NETS)


def _texts(data):
    yield data.decode("latin-1")
    for start in (0, 1):
        yield data[start:].decode("utf-16-le", "ignore")


def _all_fixture_bytes():
    for case, builder in BUILDERS.items():
        yield case, builder()
    for p in FIXTURES.iterdir():
        yield p.name, p.read_bytes()


def test_fixtures_carry_no_personal_data_keys_or_real_infrastructure():
    email = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
    cpf = re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b")
    phone = re.compile(r"\+?55\s?\(?\d{2}\)?\s?9?\d{4}-?\d{4}")
    ipv4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
    for name, data in _all_fixture_bytes():
        for text in _texts(data):
            assert not cpf.search(text) and not phone.search(text), name
            for m in email.finditer(text):  # WebDAV '\\host@SSL\\' is not an e-mail
                assert m.group(0).lower().endswith("example.com") or "@ssl" in m.group(0).lower(), (name, m.group(0))
            for m in ipv4.finditer(text):
                parts = m.group(0).split(".")
                if all(0 <= int(x) <= 255 for x in parts) and len(set(parts)) > 1 and int(parts[0]) > 9:
                    assert _doc_ip(m.group(0)), (name, m.group(0))
        for key_word in (b"api_key", b"apikey", b"authorization:", b"cookie:", b"password="):
            assert key_word not in data.lower(), name


def test_encoded_payloads_are_inert():
    """The only -enc payloads (LNK arguments, MSI CustomAction) decode to Write-Output + a string assignment;
    no download cradle exists in any fixture."""
    known = {PS_LNK_ARGS.rsplit(" ", 1)[1]: PS_LNK_SCRIPT, PS_MSI_CMD.rsplit(" ", 1)[1]: PS_MSI_SCRIPT}
    for b64, script in known.items():
        assert base64.b64decode(b64).decode("utf-16-le") == script
        assert script.startswith("Write-Output 'fixture'; $u = '")
    for name, data in _all_fixture_bytes():
        for text in _texts(data):
            assert not re.search(r"(?i)downloadstring|invoke-webrequest|net\.webclient|start-process|\biex\b", text), name


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.child.json")), ids=lambda p: p.name)
def test_every_captured_report_fits_the_sandbox_output_cap(path):
    rep = json.loads(path.read_text(encoding="utf-8"))
    assert len(json.dumps(W.fit_report(rep))) <= 1024 * 1024


# ======================================================================================== built-in readers vs the libraries


@pytest.mark.parametrize("case", ["lnk_ok", "lnk_webdav", "lnk_padded_overlay"])
def test_builtin_lnk_reader_agrees_with_captured_lnkparse3_output(case):
    """c3: the built-in [MS-SHLLINK] reader gives the facts LnkParse3 1.6.0 gave on the same bytes."""
    ours = W.lnk_read_builtin(BUILDERS[f"{case}.lnk"]())
    theirs = module_fixture("windows_artifact_triage", f"{case}.child.json")["lnk"]
    for k in ("link_flags", "file_flags", "creation_time", "accessed_time", "modified_time", "file_size", "icon_index", "windowstyle"):
        assert ours["header"][k] == theirs["header"][k], k
    assert ours["data"] == theirs["data"]
    for k in ("location", "local_base_path", "common_path_suffix"):
        assert (ours.get("link_info") or {}).get(k) == (theirs.get("link_info") or {}).get(k), k
    for k in ("drive_serial_number", "drive_type", "net_name", "r_network_provider_type"):
        assert (ours.get("link_info") or {}).get("location_info", {}).get(k) == (theirs.get("link_info") or {}).get("location_info", {}).get(k), k
    for blk, b in theirs.get("extra", {}).items():
        for k, v in b.items():
            assert ours["extra"][blk][k] == v, (blk, k)
    names = [(i["class"], i.get("volume_name") or i.get("primary_name")) for i in theirs.get("target", {}).get("items", [])]
    assert [(i["class"], i.get("volume_name") or i.get("primary_name")) for i in ours.get("target", {}).get("items", [])] == names
    assert ours["size"] == theirs["size"]


def test_lnkparse3_device_name_quirk_is_not_reproduced():
    """LnkParse3 reads a bogus device name ('1') when ValidDevice is unset; the built-in reader leaves it out."""
    theirs = module_fixture("windows_artifact_triage", "lnk_webdav.child.json")["lnk"]["link_info"]["location_info"]
    ours = W.lnk_read_builtin(build_lnk_webdav())["link_info"]["location_info"]
    assert theirs["device_name"] == "1" and "device_name" not in ours


def _has(name):
    return importlib.util.find_spec(name) is not None


@pytest.mark.skipif(not _has("LnkParse3"), reason="optional extra 'lnk' (LnkParse3) not installed")
@pytest.mark.parametrize("case", ["lnk_ok", "lnk_webdav", "lnk_padded_overlay", "lnk_long_description"])
def test_installed_lnkparse3_matches_the_captured_reports(case):
    rep = W.lnk_report(BUILDERS[f"{case}.lnk"]())
    captured = module_fixture("windows_artifact_triage", f"{case}.child.json")
    assert rep["parser"].startswith("LnkParse3") and rep["lnk"] == captured["lnk"]
    assert rep["string_data"] == captured["string_data"] and rep["appended"] == captured["appended"]


@pytest.mark.skipif(not _has("LnkParse3"), reason="optional extra 'lnk' (LnkParse3) not installed")
def test_lnkparse3_failure_falls_back_to_the_builtin_reader(monkeypatch):
    import LnkParse3

    def boom(**_kw):
        raise struct.error("unpack requires a buffer of 2 bytes")
    monkeypatch.setattr(LnkParse3, "lnk_file", boom)
    rep = W.lnk_report(build_lnk_ok())
    assert rep["parser"] == "builtin MS-SHLLINK reader (LnkParse3 failed)" and rep["error"] is None
    assert any("LnkParse3 failed (error" in w for w in rep["warnings"])
    assert W.analyse(rep)["facts"]["target"].endswith("powershell.exe")


@pytest.mark.skipif(not (_has("olefile") and _has("pymsi")), reason="optional extras olefile/pymsi not installed")
@pytest.mark.parametrize("case", ["msi_ok", "msi_bad_tables", "msi_benign"])
def test_installed_olefile_and_pymsi_match_the_captured_reports(case):
    rep = W.msi_report(BUILDERS[f"{case}.msi"]())
    captured = module_fixture("windows_artifact_triage", f"{case}.child.json")
    assert rep["parser"].startswith("olefile") and rep["tables_status"] == captured["tables_status"]
    assert rep["tables"] == captured["tables"] and rep["summary"] == captured["summary"]
    assert [s["sha256"] for s in rep["streams"] if s.get("sha256")] == [s["sha256"] for s in captured["streams"] if s.get("sha256")]


@pytest.mark.parametrize("case", ["msi_ok", "msi_bad_tables", "msi_benign"])
def test_builtin_cfb_reader_agrees_with_captured_olefile_streams(case):
    """c4: without olefile the bounded built-in compound-file reader lists, hashes and decodes the same streams."""
    rep = W.msi_report(BUILDERS[f"{case}.msi"](), use_extras=False)
    captured = module_fixture("windows_artifact_triage", f"{case}.child.json")
    assert rep["parser"] == "builtin MS-CFB reader" and rep["tables_status"] == "disabled"
    assert rep["clsid"] == captured["clsid"] and rep["signed"] is captured["signed"]

    def key(streams):
        return sorted((s["name"], s["size"], s.get("sha256"), s.get("kind"), s.get("text")) for s in streams)
    assert key(rep["streams"]) == key(captured["streams"])
    for k in ("subject", "author", "template", "revision_number", "creating_application", "num_pages", "security"):
        assert rep["summary"][k] == captured["summary"][k], k
    assert W.iso_z(rep["summary"]["create_time"]) == W.iso_z(captured["summary"]["create_time"])
