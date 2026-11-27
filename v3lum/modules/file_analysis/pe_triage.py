"""PE header, imports, imphash, Rich header and Authenticode triage (P271, batch p2-G12-1).

Offline module (disclosure 'none': no network at all; terms 'open'; provider tier n/a; allowed at TLP:RED;
default-on). The sample is never executed. Final conditions:

* c1 FILE input only (regular files of at most 100 MB); nothing is executed, loaded or emulated.
* c2 parsing in the shared file-analysis sandbox ``core/sandbox.py``: with the core sandbox and the pefile extra,
  :func:`pefile_child` runs there (python -I child, wall timeout, rlimits, 100 MB input, 1 MB JSON output). This
  build has no core sandbox yet, so the module parses with :func:`parse_pe`, a bounded pure standard-library PE
  reader with the same output shape (verified equal to pefile 2024.8.26 on every fixture during the prep); pefile
  is never run in process.
* c3 only the headers and the IMPORT, EXPORT, RESOURCE and DEBUG directories (plus the security directory for
  the signer) are parsed, with caps on sections, DLLs, import/export symbols, resource entries/depth and debug
  entries (:data:`PE_CAPS`; pefile's MAX_* globals in the child).
* c4 outputs: compile timestamp (zero, future, pre-2000 and the Delphi 1992 stamp flagged 'unreliable/forged';
  a REPRO debug entry = a build hash, not a date), imphash, Rich header hash, sections with entropy, imports,
  packer hints, Authenticode presence with signer subject/issuer/serial recorded as 'signed, not verified' (no
  claim of validity), PDB path.
* c5 pivots: md5/sha256 of the file (has_hash); imphash (``imphash`` entity, expand=False) and the signer
  certificate (``code_signing_cert`` SHA-256 thumbprint, expand=False) now that the P333 types exist; the Rich
  hash stays an attribute; nothing becomes a free-text keyword.
* c6 PDB paths and the user/machine names inside them are privacy attributes, never username entities.
* c7 packer hints and high entropy are context (low, ``context_only``), never verdicts; the correlation rule
  ``p2g12_pe_hints_known_good`` (v3lum/correlations/p2_g12_1.py) reports them downgraded when a known-good source
  in the case marks the hash (CIRCL hashlookup without KnownMalicious, P169 known-good lists): a hashlookup hit
  alone is not proof of good. :func:`downgrade_pe_hints` is the shared rule.
* c8 fixtures are small benign PE files built for the tests (no malware; EICAR only in the YARA fixtures, as
  halves), plus a truncated and a malformed PE.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import re
import struct
from collections.abc import Iterable
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, package_available, register
from v3lum.modules.geo_image_meta.image_metadata import (
    InputRefused,
    SandboxUnavailable,
    as_float,
    as_int,
    as_str,
    core_sandbox,
    read_head,
    read_regular_file,
    sandbox_failure,
    sandbox_run,
    shannon_entropy,
)

# ======================================================================================================
# [P271 pe_triage] (prep parsers.py, stdlib only)
# ======================================================================================================

PE_CAPS = {'sections': 96, 'dlls': 256, 'import_symbols': 4096, 'export_symbols': 8192, 'resource_entries': 4096,
           'resource_depth': 3, 'debug_entries': 16, 'cert_entries': 8, 'string': 512}
DELPHI_TIMESTAMP = 0x2A425E19            # 1992-06-19 22:22:17 UTC, Borland/Delphi linker constant (P271 c4)
PE_MACHINES = {0x14C: 'i386', 0x8664: 'amd64', 0xAA64: 'arm64', 0x1C0: 'arm', 0x1C4: 'armnt', 0x200: 'ia64',
               0xEBC: 'efi_bytecode', 0x0: 'unknown'}
PE_SUBSYSTEMS = {1: 'native', 2: 'windows_gui', 3: 'windows_cui', 5: 'os2_cui', 7: 'posix_cui', 9: 'windows_ce_gui',
                 10: 'efi_application', 11: 'efi_boot_driver', 12: 'efi_runtime_driver', 13: 'efi_rom', 14: 'xbox',
                 16: 'windows_boot_application'}
DEBUG_TYPES = {1: 'COFF', 2: 'CODEVIEW', 4: 'MISC', 9: 'BORLAND', 12: 'VC_FEATURE', 13: 'POGO', 14: 'ILTCG',
               16: 'REPRO', 20: 'EX_DLLCHARACTERISTICS'}
PACKER_SECTIONS = {
    'upx0': 'UPX', 'upx1': 'UPX', 'upx2': 'UPX', '.upx0': 'UPX', '.upx1': 'UPX', '.aspack': 'ASPack',
    '.adata': 'ASPack', 'aspack': 'ASPack', '.nsp0': 'NsPack', '.nsp1': 'NsPack', '.nsp2': 'NsPack',
    '.mpress1': 'MPRESS', '.mpress2': 'MPRESS', '.petite': 'Petite', 'pec2': 'PECompact', 'pecompact2': 'PECompact',
    '.themida': 'Themida', '.winlice': 'WinLicense', '.vmp0': 'VMProtect', '.vmp1': 'VMProtect', '.vmp2': 'VMProtect',
    '.enigma1': 'Enigma', '.enigma2': 'Enigma', '.perplex': 'Perplex', '.yp': 'Y0da', '.y0da': 'Y0da',
    '.packed': 'generic', '.rlpack': 'RLPack', '.upack': 'Upack', '.bydwing': 'Upack', 'mew': 'MEW',
    'kkrunchy': 'kkrunchy', '.spack': 'SimplePack', '.svkp': 'SVKP', 'pelocknt': 'PELock', '.neolit': 'NeoLite',
    '.boom': 'Boomerang', '.taz': 'PESpin', '.ccg': 'CCG', '.sforce3': 'StarForce', '.ndata': 'NSIS installer',
}
WINSOCK_ORDINALS = {  # well-known ws2_32.dll export ordinals (wsock32.dll differs at 10-12, below)
    1: 'accept', 2: 'bind', 3: 'closesocket', 4: 'connect', 5: 'getpeername', 6: 'getsockname', 7: 'getsockopt',
    8: 'htonl', 9: 'htons', 10: 'ioctlsocket', 11: 'inet_addr', 12: 'inet_ntoa', 13: 'listen', 14: 'ntohl',
    15: 'ntohs', 16: 'recv', 17: 'recvfrom', 18: 'select', 19: 'send', 20: 'sendto', 21: 'setsockopt',
    22: 'shutdown', 23: 'socket', 51: 'gethostbyaddr', 52: 'gethostbyname', 53: 'getprotobyname',
    54: 'getprotobynumber', 55: 'getservbyname', 56: 'getservbyport', 57: 'gethostname', 111: 'WSAGetLastError',
    112: 'WSASetLastError', 115: 'WSAStartup', 116: 'WSACleanup', 151: '__WSAFDIsSet',
}
WSOCK32_ORDINALS = {**WINSOCK_ORDINALS, 10: 'inet_addr', 11: 'inet_ntoa', 12: 'ioctlsocket'}  # WinSock 1.1 order
ORDINAL_NAMES = {'ws2_32.dll': WINSOCK_ORDINALS, 'wsock32.dll': WSOCK32_ORDINALS,
                 'oleaut32.dll': {2: 'SysAllocString', 6: 'SysFreeString', 7: 'SysStringLen', 8: 'VariantInit',
                                  9: 'VariantClear'}}
_OID_NAMES = {
    '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
    '2.5.4.5': 'serialNumber', '1.2.840.113549.1.9.1': 'emailAddress', '2.5.4.97': 'organizationIdentifier',
    '1.3.6.1.4.1.311.60.2.1.3': 'jurisdictionC', '2.5.4.15': 'businessCategory',
    '1.2.840.113549.1.7.2': 'signedData', '1.3.6.1.4.1.311.2.1.4': 'SpcIndirectDataContent',
    '2.16.840.1.101.3.4.2.1': 'sha256', '1.3.14.3.2.26': 'sha1', '1.2.840.113549.2.5': 'md5',
    '2.16.840.1.101.3.4.2.2': 'sha384', '2.16.840.1.101.3.4.2.3': 'sha512',
}


class DerError(ValueError):
    pass


def _der(data: bytes, pos: int, end: int) -> tuple[int, int, int]:
    """One DER TLV: (tag, content_start, content_end); definite lengths only, bounds-checked."""
    if pos + 2 > end:
        raise DerError('truncated TLV')
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise DerError('multi-byte tag')
    first = data[pos + 1]
    if first < 0x80:
        length, hdr = first, 2
    elif first == 0x80:
        raise DerError('indefinite length (BER)')
    else:
        n = first & 0x7F
        if n > 4 or pos + 2 + n > end:
            raise DerError('bad length')
        length, hdr = int.from_bytes(data[pos + 2:pos + 2 + n], 'big'), 2 + n
    cs, ce = pos + hdr, pos + hdr + length
    if ce > end:
        raise DerError('content past end')
    return tag, cs, ce


def _der_children(data: bytes, cs: int, ce: int, limit: int = 4096) -> list[tuple[int, int, int]]:
    out, pos = [], cs
    while pos < ce and len(out) < limit:
        tag, s, e = _der(data, pos, ce)
        out.append((tag, s, e))
        pos = e
    return out


def _oid_str(b: bytes) -> str:
    if not b:
        return ''
    parts = [b[0] // 40, b[0] % 40]
    val = 0
    for x in b[1:]:
        val = (val << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(val)
            val = 0
    return '.'.join(map(str, parts))


def _der_string(tag: int, raw: bytes) -> str:
    if tag == 0x1E:
        return raw.decode('utf-16-be', 'replace')
    if tag == 0x1C:
        return raw.decode('utf-32-be', 'replace')
    if tag == 0x14:
        return raw.decode('latin-1')
    return raw.decode('utf-8', 'replace')


def _der_name(data: bytes, cs: int, ce: int) -> str:
    parts = []
    for _t, s, e in _der_children(data, cs, ce, 64):          # RDN SETs
        for _t2, s2, e2 in _der_children(data, s, e, 16):     # AttributeTypeAndValue
            kids = _der_children(data, s2, e2, 4)
            if len(kids) >= 2 and kids[0][0] == 0x06:
                oid = _oid_str(data[kids[0][1]:kids[0][2]])
                val = _der_string(kids[1][0], data[kids[1][1]:kids[1][2]])
                parts.append(f'{_OID_NAMES.get(oid, oid)}={as_str(val, 256)}')
    return ', '.join(parts)


def _der_time(tag: int, raw: bytes) -> str | None:
    t = raw.decode('ascii', 'replace')
    m = re.fullmatch(r'(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z', t)
    if not m:
        return None
    y = int(m.group(1))
    if tag == 0x17:
        y += 1900 if y >= 50 else 2000
    try:
        return _dt.datetime(y, int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)),
                            int(m.group(6) or 0), tzinfo=_dt.timezone.utc).isoformat().replace('+00:00', 'Z')
    except ValueError:
        return None


def _der_int_hex(raw: bytes) -> str:
    raw = raw.lstrip(b'\x00') or b'\x00'
    return raw.hex().upper()


def _x509_summary(data: bytes, cs: int, ce: int) -> dict:
    tbs = _der_children(data, cs, ce, 3)[0]
    f = _der_children(data, tbs[1], tbs[2], 16)
    i = 1 if f and f[0][0] == 0xA0 else 0
    serial = _der_int_hex(data[f[i][1]:f[i][2]])
    issuer = _der_name(data, f[i + 2][1], f[i + 2][2])
    validity = _der_children(data, f[i + 3][1], f[i + 3][2], 2)
    subject = _der_name(data, f[i + 4][1], f[i + 4][2])
    nb = _der_time(validity[0][0], data[validity[0][1]:validity[0][2]]) if validity else None
    na = _der_time(validity[1][0], data[validity[1][1]:validity[1][2]]) if len(validity) > 1 else None
    return {'subject': subject, 'issuer': issuer, 'serial': serial, 'not_before': nb, 'not_after': na}


def pkcs7_signed_data_info(der: bytes, depth: int = 0) -> dict:
    """Authenticode PKCS#7/CMS SignedData -> signer subject/issuer/serial, embedded digest algorithm,
    certificates, timestamps and nested signatures.  No verification of any kind (P271 c4)."""
    info: dict = {'status': 'signed, not verified', 'signers': [], 'certificates': [], 'content_type': None,
                  'digest_algorithm': None, 'program_name': None, 'more_info_url': None, 'timestamped': False,
                  'nested_signatures': 0, 'anomalies': []}
    try:
        _t, cs, ce = _der(der, 0, len(der))
        ci = _der_children(der, cs, ce, 3)
        if len(ci) < 2 or _oid_str(der[ci[0][1]:ci[0][2]]) != '1.2.840.113549.1.7.2':
            info['anomalies'].append('not a PKCS#7 SignedData')
            return info
        _t, sds, sde = _der(der, ci[1][1], ci[1][2])
        sd = _der_children(der, sds, sde, 8)
        pos = 2                                   # version, digestAlgorithms
        enc = _der_children(der, sd[pos][1], sd[pos][2], 2)
        info['content_type'] = _OID_NAMES.get(_oid_str(der[enc[0][1]:enc[0][2]]), _oid_str(der[enc[0][1]:enc[0][2]]))
        if len(enc) > 1:
            _t, ecs, ece = _der(der, enc[1][1], enc[1][2])
            if _t == 0x04:                        # CMS: eContent wrapped in an OCTET STRING
                _t, ecs, ece = _der(der, ecs, ece)
            try:
                spc = _der_children(der, ecs, ece, 2)
                dig = _der_children(der, spc[1][1], spc[1][2], 2)
                alg = _der_children(der, dig[0][1], dig[0][2], 2)
                oid = _oid_str(der[alg[0][1]:alg[0][2]])
                info['digest_algorithm'] = _OID_NAMES.get(oid, oid)
                info['program_digest'] = der[dig[1][1]:dig[1][2]].hex()
            except (DerError, IndexError):
                info['anomalies'].append('unreadable SpcIndirectDataContent')
        pos += 1
        certs_by_key = {}
        while pos < len(sd) and sd[pos][0] in (0xA0, 0xA1):
            if sd[pos][0] == 0xA0:
                for _t2, s, e in _der_children(der, sd[pos][1], sd[pos][2], 64):
                    try:
                        c = _x509_summary(der, s, e)
                    except (DerError, IndexError):
                        info['anomalies'].append('unreadable certificate')
                        continue
                    c['sha256'] = hashlib.sha256(der[s - _hdr_len(der, s, e):e]).hexdigest()
                    info['certificates'].append(c)
                    certs_by_key[(c['issuer'], c['serial'])] = c
            pos += 1
        if pos < len(sd):
            for _t3, s, e in _der_children(der, sd[pos][1], sd[pos][2], 8):
                si = _der_children(der, s, e, 8)
                sid = si[1]
                signer = {'subject': None, 'issuer': None, 'serial': None}
                if sid[0] == 0x30:
                    ias = _der_children(der, sid[1], sid[2], 2)
                    signer['issuer'] = _der_name(der, ias[0][1], ias[0][2])
                    signer['serial'] = _der_int_hex(der[ias[1][1]:ias[1][2]])
                    cert = certs_by_key.get((signer['issuer'], signer['serial']))
                    if cert:
                        signer.update({'subject': cert['subject'], 'not_before': cert['not_before'],
                                       'not_after': cert['not_after'], 'sha256': cert.get('sha256')})
                for tag, a, b in si[3:]:
                    if tag == 0xA0:              # signed attributes
                        for _t4, s4, e4 in _der_children(der, a, b, 32):
                            kids = _der_children(der, s4, e4, 2)
                            oid = _oid_str(der[kids[0][1]:kids[0][2]])
                            if oid == '1.3.6.1.4.1.311.2.1.12':      # SpcSpOpusInfo
                                _opus(der, kids[1], info)
                    elif tag == 0xA1:            # unsigned attributes
                        for _t4, s4, e4 in _der_children(der, a, b, 32):
                            kids = _der_children(der, s4, e4, 2)
                            oid = _oid_str(der[kids[0][1]:kids[0][2]])
                            if oid in ('1.2.840.113549.1.9.6', '1.3.6.1.4.1.311.3.3.1'):
                                info['timestamped'] = True
                            elif oid == '1.3.6.1.4.1.311.2.4.1':
                                vals = _der_children(der, kids[1][1], kids[1][2], 8)
                                info['nested_signatures'] += len(vals)
                                if depth < 1:
                                    for _t5, s5, e5 in vals:
                                        nested = pkcs7_signed_data_info(der[s5 - _hdr_len(der, s5, e5):e5], depth + 1)
                                        info['signers'].extend(nested['signers'])
                info['signers'].append(signer)
    except (DerError, IndexError, ValueError) as e:
        info['anomalies'].append(f'unreadable signature structure ({e})')
    return info


def _hdr_len(der: bytes, cs: int, ce: int) -> int:
    """Length of the TLV header that precedes content [cs, ce) (used to re-slice nested ContentInfo)."""
    for h in range(2, 7):
        if cs - h >= 0:
            try:
                _t, s, e = _der(der, cs - h, ce)
                if s == cs and e == ce:
                    return h
            except DerError:
                continue
    return 0


def _opus(der: bytes, value_set: tuple, info: dict) -> None:
    try:
        seq = _der_children(der, value_set[1], value_set[2], 1)[0]
        for tag, s, e in _der_children(der, seq[1], seq[2], 4):
            inner = _der_children(der, s, e, 1)
            if not inner:
                continue
            itag, i_s, i_e = inner[0]
            raw = der[i_s:i_e]
            if tag == 0xA0:
                info['program_name'] = as_str(raw.decode('utf-16-be', 'replace') if itag == 0x80 else raw.decode('latin-1'), 200)
            elif tag == 0xA1 and itag == 0x80:
                info['more_info_url'] = as_str(raw.decode('latin-1'), 500)
    except (DerError, IndexError):
        info['anomalies'].append('unreadable SpcSpOpusInfo')


def authenticode_info(table: bytes) -> dict:
    """WIN_CERTIFICATE table (security directory bytes) -> {'present', 'status': 'signed, not verified',
    'entries': [...pkcs7_signed_data_info], 'signers', 'anomalies'} (P271 c4: presence and signer only)."""
    out: dict = {'present': False, 'status': 'unsigned', 'entries': [], 'signers': [], 'anomalies': []}
    pos = 0
    while pos + 8 <= len(table) and len(out['entries']) < PE_CAPS['cert_entries']:
        length, rev, ctype = struct.unpack_from('<IHH', table, pos)
        if length < 8 or pos + length > len(table):
            out['anomalies'].append('certificate entry length out of range')
            break
        body = table[pos + 8:pos + length]
        if ctype == 0x0002:
            info = pkcs7_signed_data_info(body)
            out['entries'].append(info)
            out['signers'].extend(info['signers'])
        else:
            out['entries'].append({'status': f'certificate type 0x{ctype:04X} (not PKCS#7)'})
        pos += (length + 7) & ~7
    if out['entries']:
        out['present'] = True
        out['status'] = 'signed, not verified'
    return out


def compile_time_flags(ts: Any, now: _dt.datetime | None = None, debug_types: Iterable[int] = ()) -> dict:
    """P271 c4: zero, future, pre-2000 and the Delphi 1992 stamp are 'unreliable/forged'; a REPRO debug entry
    means the field is a build hash, not a date."""
    t = as_int(ts)
    now = now or _dt.datetime.now(_dt.timezone.utc)
    if t is None:
        return {'raw': None, 'value': None, 'flags': ['missing'], 'reliable': False, 'label': 'unreliable/forged'}
    value = _dt.datetime.fromtimestamp(t, _dt.timezone.utc).isoformat().replace('+00:00', 'Z')
    flags = []
    if 16 in set(debug_types or ()):
        return {'raw': t, 'value': None, 'flags': ['reproducible_build'], 'reliable': False,
                'label': 'not a date (reproducible build: the field holds a build hash)'}
    if t == 0:
        flags.append('zero')
    elif t == DELPHI_TIMESTAMP:
        flags.append('delphi_1992')
    elif _dt.datetime.fromtimestamp(t, _dt.timezone.utc) > now + _dt.timedelta(days=1):
        flags.append('future')
    elif _dt.datetime.fromtimestamp(t, _dt.timezone.utc) < _dt.datetime(2000, 1, 1, tzinfo=_dt.timezone.utc):
        flags.append('pre_2000')
    return {'raw': t, 'value': None if t == 0 else value, 'flags': flags, 'reliable': not flags,
            'label': 'unreliable/forged' if flags else None}


def pe_imphash(imports: Any, ordinal_names: dict | None = None) -> tuple[str | None, bool]:
    """pefile-compatible imphash from [{'dll', 'functions': [{'name', 'ordinal'}]}] -> (md5, exact).
    exact=False when an ordinal of ws2_32/wsock32/oleaut32 is missing from the local table (pefile resolves
    those through its ordlookup tables, so the stdlib value may differ)."""
    names = ordinal_names or ORDINAL_NAMES
    parts, exact = [], True
    for entry in imports if isinstance(imports, list) else []:
        dll = (as_str((entry or {}).get('dll'), 512) or '')
        lib = dll.lower()
        base, _, ext = lib.rpartition('.')
        if base and ext in ('ocx', 'sys', 'dll'):
            lib = base
        for fn in (entry or {}).get('functions') or []:
            name = as_str((fn or {}).get('name'), 512)
            if not name:
                ordv = as_int((fn or {}).get('ordinal'))
                if ordv is None:
                    continue
                table = names.get(dll.lower())
                if table is not None and ordv not in table:
                    exact = False
                name = (table or {}).get(ordv) or f'ord{ordv}'
            parts.append(f'{lib}.{name.lower()}')
    if not parts:
        return None, True
    return hashlib.md5(','.join(parts).encode()).hexdigest(), exact


def pdb_info(path: Any) -> dict | None:
    """PDB path -> {'path', 'username', 'machine', 'tags': ['privacy']} (P271 c6): user and machine names are
    attributes with the privacy tag, never username entities."""
    p = as_str(path, 1024)
    if not p:
        return None
    user = None
    m = re.search(r'(?i)[\\/](?:users|documents and settings|home)[\\/]([^\\/]{1,64})[\\/]', p)
    if m and m.group(1).lower() not in ('public', 'default', 'all users', 'shared'):
        user = m.group(1)
    machine = None
    mu = re.match(r'^\\\\([^\\/]{1,64})[\\/]', p)
    if mu:
        machine = mu.group(1)
    return {'path': p, 'file': re.split(r'[\\/]', p)[-1], 'username': user, 'machine': machine, 'tags': ['privacy']}


def _rich_parse(data: bytes, e_lfanew: int) -> dict | None:
    end = min(e_lfanew, len(data), 0x1000)
    idx = data.find(b'Rich', 0x80, end)
    if idx < 0 or idx + 8 > len(data):
        return None
    key = data[idx + 4:idx + 8]
    k = int.from_bytes(key, 'little')
    raw = data[0x80:idx]
    raw = raw[:4 * (len(raw) // 4)]
    clear = bytes(b ^ key[i % 4] for i, b in enumerate(raw))
    dwords = [int.from_bytes(clear[i:i + 4], 'little') for i in range(0, len(clear), 4)]
    if not dwords or dwords[0] != 0x536E6144:
        return {'present': True, 'valid_layout': False, 'clear_md5': hashlib.md5(clear).hexdigest(), 'entries': [],
                'checksum_valid': False, 'key_hex': key.hex()}
    entries = [[dwords[i], dwords[i + 1]] for i in range(4, len(dwords) - 1, 2)][:128]
    csum = 0x80
    for i, b in enumerate(data[:0x80]):
        if 0x3C <= i < 0x40:
            continue
        n = i % 32
        csum = (csum + (((b << n) | (b >> (32 - n))) & 0xFFFFFFFF if n else b)) & 0xFFFFFFFF
    for compid, count in entries:
        n = count % 32
        csum = (csum + ((((compid << n) | (compid >> (32 - n))) & 0xFFFFFFFF) if n else compid)) & 0xFFFFFFFF
    return {'present': True, 'valid_layout': True, 'clear_md5': hashlib.md5(clear).hexdigest(), 'entries': entries,
            'checksum_valid': csum == k, 'key_hex': key.hex()}


def parse_pe(data: bytes, caps: dict | None = None) -> dict:
    """Stdlib PE reader with the pefile_child output shape (offline oracle and no-pefile fallback; P271 c3:
    only headers, IMPORT, EXPORT, RESOURCE, DEBUG and the security directory; caps on every list)."""
    c = {**PE_CAPS, **(caps or {})}
    warnings_: list[str] = []
    if len(data) < 0x40 or data[:2] != b'MZ':
        return {'source': 'stdlib', 'error': 'PEFormatError', 'message': 'DOS Header magic not found.'}
    e = struct.unpack_from('<I', data, 0x3C)[0]
    if e + 24 > len(data):
        return {'source': 'stdlib', 'error': 'PEFormatError', 'message': 'Invalid e_lfanew value, probably not a PE file'}
    if data[e:e + 4] != b'PE\x00\x00':
        return {'source': 'stdlib', 'error': 'PEFormatError', 'message': 'NT Headers not found.'}
    machine, nsec, ts, _ps, _ns, opt_size, chars = struct.unpack_from('<HHIIIHH', data, e + 4)
    opt = e + 24
    if opt + 2 > len(data):
        return {'source': 'stdlib', 'error': 'PEFormatError', 'message': 'optional header truncated'}
    magic = struct.unpack_from('<H', data, opt)[0]
    is64 = magic == 0x20B
    need = opt + (112 if is64 else 96)
    if magic not in (0x10B, 0x20B) or need > len(data):
        return {'source': 'stdlib', 'error': 'PEFormatError', 'message': f'bad optional header (magic 0x{magic:x})'}
    entry = struct.unpack_from('<I', data, opt + 16)[0]
    image_base = struct.unpack_from('<Q', data, opt + 24)[0] if is64 else struct.unpack_from('<I', data, opt + 28)[0]
    size_image, size_headers, checksum, subsystem, dllch = struct.unpack_from('<IIIHH', data, opt + 56)
    nrva = struct.unpack_from('<I', data, opt + (108 if is64 else 92))[0]
    dd_off = opt + (112 if is64 else 96)
    dirs = []
    for i in range(min(nrva, 16)):
        if dd_off + 8 * i + 8 <= len(data):
            dirs.append(struct.unpack_from('<II', data, dd_off + 8 * i))
        else:
            dirs.append((0, 0))
    dirs += [(0, 0)] * (16 - len(dirs))
    sec_off = opt + opt_size
    if nsec > c['sections']:
        warnings_.append(f'NumberOfSections {nsec} above cap {c["sections"]}')
    sections = []
    for i in range(min(nsec, c['sections'])):
        so = sec_off + 40 * i
        if so + 40 > len(data):
            warnings_.append('section table truncated')
            break
        name, vsize, va, rsize, rptr, _a, _b, _c, _d, sch = struct.unpack_from('<8sIIIIIIHHI', data, so)
        raw = data[rptr:rptr + rsize] if rptr < len(data) else b''
        if rptr + rsize > len(data):
            warnings_.append(f'section {i} raw data beyond end of file')
        sections.append({'name': name.rstrip(b'\x00').decode('latin-1'), 'virtual_address': va,
                         'virtual_size': vsize, 'raw_size': rsize, 'raw_offset': rptr, 'characteristics': sch,
                         'entropy': round(shannon_entropy(raw), 4)})

    def off(rva: int) -> int | None:
        if rva < size_headers and rva < len(data):
            return rva
        for s in sections:
            if not s['raw_size']:
                continue                       # no file data (e.g. UPX0): nothing to read
            span = max(s['virtual_size'], s['raw_size'])
            if s['virtual_address'] <= rva < s['virtual_address'] + span:
                o = s['raw_offset'] + (rva - s['virtual_address'])
                return o if o < len(data) else None
        return None

    def cstr(rva: int, limit: int = c['string']) -> str | None:
        o = off(rva)
        if o is None:
            return None
        end = data.find(b'\x00', o, o + limit)
        raw = data[o:end if end >= 0 else o + limit]
        return raw.decode('latin-1') if raw else None

    out: dict = {'source': 'stdlib', 'size': len(data), 'parse_error': None, 'machine': machine,
                 'number_of_sections': nsec, 'timestamp': ts, 'characteristics': chars, 'magic': magic,
                 'subsystem': subsystem, 'dll_characteristics': dllch, 'entry_point': entry, 'image_base': image_base,
                 'checksum': checksum, 'size_of_image': size_image, 'size_of_headers': size_headers,
                 'sections': sections, 'imports': [], 'exports': [], 'debug': [], 'resources': [],
                 'warnings': warnings_}
    # imports
    irva, isize = dirs[1]
    if irva:
        io = off(irva)
        if io is None:
            warnings_.append('import directory outside the image')
        total = 0
        seen_desc = 0
        while io is not None and io + 20 <= len(data) and seen_desc < c['dlls']:
            oft, _t, _f, name_rva, ft = struct.unpack_from('<IIIII', data, io)
            if not (oft or name_rva or ft):
                break
            seen_desc += 1
            dll = cstr(name_rva) or None
            funcs = []
            to = off(oft or ft)
            step = 8 if is64 else 4
            flag = 1 << (63 if is64 else 31)
            while to is not None and to + step <= len(data) and total < c['import_symbols']:
                val = struct.unpack_from('<Q' if is64 else '<I', data, to)[0]
                if val == 0:
                    break
                if val & flag:
                    funcs.append({'name': None, 'ordinal': val & 0xFFFF})
                else:
                    nm = cstr((val & 0x7FFFFFFF) + 2)
                    funcs.append({'name': nm, 'ordinal': None})
                total += 1
                to += step
            if total >= c['import_symbols']:
                warnings_.append('import symbol cap reached')
            if funcs and dll:
                out['imports'].append({'dll': dll, 'functions': funcs})
            else:
                warnings_.append('import descriptor without a readable name or thunks skipped')
            io += 20
    out['imphash'], out['imphash_exact'] = pe_imphash(out['imports'])
    # exports
    erva, esize = dirs[0]
    eo = off(erva) if erva else None
    if eo is not None and eo + 40 <= len(data):
        _ch, _ts, _mj, _mn, name_rva, base, nfun, nnames, aof, aon, aoo = struct.unpack_from('<IIHHIIIIIII', data, eo)
        out['export_dll_name'] = cstr(name_rva)
        fo, no, oo = off(aof), off(aon), off(aoo)
        for i in range(min(nnames, c['export_symbols'])):
            if no is None or oo is None or no + 4 * i + 4 > len(data) or oo + 2 * i + 2 > len(data):
                break
            nrva_ = struct.unpack_from('<I', data, no + 4 * i)[0]
            idx = struct.unpack_from('<H', data, oo + 2 * i)[0]
            frva = struct.unpack_from('<I', data, fo + 4 * idx)[0] if fo is not None and fo + 4 * idx + 4 <= len(data) else 0
            fwd = cstr(frva) if erva <= frva < erva + esize else None
            out['exports'].append({'name': cstr(nrva_), 'ordinal': base + idx, 'forwarder': fwd})
    # debug
    drva, dsize = dirs[6]
    do = off(drva) if drva else None
    if do is not None:
        for i in range(min(dsize // 28, c['debug_entries'])):
            if do + 28 * i + 28 > len(data):
                break
            _ch, dts, _mj, _mn, typ, sz, arva, praw = struct.unpack_from('<IIHHIIII', data, do + 28 * i)
            item = {'type': typ, 'timestamp': dts, 'size': sz}
            if typ == 2:
                po = praw if praw and praw < len(data) else off(arva)
                blob = data[po:po + min(sz, 4096)] if po is not None else b''
                if blob[:4] == b'RSDS' and len(blob) >= 24:
                    g = blob[4:20]
                    d1, d2, d3 = struct.unpack_from('<IHH', g)
                    item['guid'] = f'{d1:08X}-{d2:04X}-{d3:04X}-{g[8:10].hex().upper()}-{g[10:16].hex().upper()}'
                    item['age'] = struct.unpack_from('<I', blob, 20)[0]
                    item['cv_signature'] = 'RSDS'
                    item['pdb'] = blob[24:].split(b'\x00', 1)[0].decode('utf-8', 'replace')[:1024]
                elif blob[:4] == b'NB10' and len(blob) >= 16:
                    item['cv_signature'] = 'NB10'
                    item['age'] = struct.unpack_from('<I', blob, 12)[0]
                    item['pdb'] = blob[16:].split(b'\x00', 1)[0].decode('latin-1')[:1024]
            out['debug'].append(item)
    # resources (type/name/lang, loop-safe)
    rrva, _rs = dirs[2]
    ro = off(rrva) if rrva else None
    if ro is not None:
        seen: set[int] = set()

        def walk(dir_off: int, depth: int, path: list) -> None:
            if depth >= c['resource_depth'] or dir_off in seen or len(out['resources']) >= 256:
                return
            seen.add(dir_off)
            base_o = ro + dir_off
            if base_o + 16 > len(data):
                return
            n_named, n_id = struct.unpack_from('<HH', data, base_o + 12)
            for k in range(min(n_named + n_id, c['resource_entries'])):
                eo2 = base_o + 16 + 8 * k
                if eo2 + 8 > len(data):
                    return
                name_id, target = struct.unpack_from('<II', data, eo2)
                ident = name_id & 0xFFFF if not name_id & 0x80000000 else f'name@{name_id & 0x7FFFFFFF:x}'
                if target & 0x80000000:
                    walk(target & 0x7FFFFFFF, depth + 1, path + [ident])
                else:
                    deo = ro + target
                    if deo + 16 > len(data):
                        continue
                    drva2, dsz = struct.unpack_from('<II', data, deo)
                    po = off(drva2)
                    blob = data[po:po + min(dsz, 1 << 20)] if po is not None else b''
                    p = path + [ident]
                    out['resources'].append({'type': p[0] if p else None, 'name': p[1] if len(p) > 1 else None,
                                             'lang': p[2] if len(p) > 2 else None, 'size': dsz,
                                             'entropy': round(shannon_entropy(blob), 4)})
        walk(0, 0, [])
    # rich header, security directory, overlay, hashes
    rich = _rich_parse(data, e)
    if rich:
        out['rich'] = rich
    srva, ssize = dirs[4]
    out['security_dir'] = {'offset': srva, 'size': ssize}
    if srva and ssize:
        if srva + ssize <= len(data):
            out['authenticode'] = authenticode_info(data[srva:srva + ssize])
        else:
            warnings_.append('certificate table beyond end of file')
    ends = [s['raw_offset'] + s['raw_size'] for s in sections if s['raw_size']] + [size_headers]
    ov = max(ends) if ends else None
    out['overlay'] = {'offset': ov, 'size': len(data) - ov} if ov is not None and ov < len(data) else None
    out['md5'] = hashlib.md5(data).hexdigest()
    out['sha256'] = hashlib.sha256(data).hexdigest()
    return out


def pe_packer_hints(raw: dict) -> list[dict]:
    """Context hints (P271 c4, c7: never verdicts): packer section names, high entropy, empty raw sections
    with virtual size, W+X, entry point outside the first section / in a writable one, loader-only imports,
    overlay beyond the certificate table, high-entropy resources."""
    hints = []
    secs = raw.get('sections') or []
    for s in secs:
        nm = (s.get('name') or '').lower()
        if nm in PACKER_SECTIONS:
            hints.append({'hint': f'section name {s.get("name")} ({PACKER_SECTIONS[nm]})', 'kind': 'packer_name'})
        ent = as_float(s.get('entropy')) or 0.0
        ch = as_int(s.get('characteristics')) or 0
        if ent >= 7.2 and (as_int(s.get('raw_size')) or 0) >= 1024:
            hints.append({'hint': f'high entropy {ent:.2f} in section {s.get("name")}', 'kind': 'entropy'})
        if ch & 0x20000000 and ch & 0x80000000:
            hints.append({'hint': f'section {s.get("name")} is writable and executable', 'kind': 'wx'})
        if (as_int(s.get('raw_size')) or 0) == 0 and (as_int(s.get('virtual_size')) or 0) >= 0x1000 and ch & 0x20000000:
            hints.append({'hint': f'executable section {s.get("name")} has no file data (unpacked at run time)',
                          'kind': 'empty_raw'})
    ep = as_int(raw.get('entry_point')) or 0
    ep_sec = None
    for i, s in enumerate(secs):
        va, span = as_int(s.get('virtual_address')) or 0, max(as_int(s.get('virtual_size')) or 0, as_int(s.get('raw_size')) or 0)
        if va <= ep < va + span:
            ep_sec = (i, s)
            break
    if secs and ep and ep_sec is None:
        hints.append({'hint': 'entry point outside every section', 'kind': 'entry_point'})
    elif ep_sec and ((as_int(ep_sec[1].get('characteristics')) or 0) & 0x80000000 or ep_sec[0] == len(secs) - 1 and len(secs) > 1):
        hints.append({'hint': f'entry point in {"writable" if (as_int(ep_sec[1].get("characteristics")) or 0) & 0x80000000 else "last"} section {ep_sec[1].get("name")}',
                      'kind': 'entry_point'})
    funcs = [f.get('name') for imp in raw.get('imports') or [] for f in imp.get('functions') or []]
    names = {(n or '').lower() for n in funcs}
    if funcs and len(funcs) <= 10 and {'loadlibrarya', 'getprocaddress'} <= names | {n.rstrip('w') + 'a' for n in names if n}:
        hints.append({'hint': f'only {len(funcs)} imports incl. LoadLibrary/GetProcAddress (APIs resolved at run time)',
                      'kind': 'imports'})
    ov = raw.get('overlay') or {}
    sec = raw.get('security_dir') or {}
    if ov and ov.get('size'):
        cert_only = sec.get('offset') == ov.get('offset') and sec.get('size') == ov.get('size')
        if not cert_only and ov['size'] >= 4096:
            hints.append({'hint': f'{ov["size"]} bytes of overlay data after the last section', 'kind': 'overlay'})
    for r in raw.get('resources') or []:
        if (as_float(r.get('entropy')) or 0) >= 7.5 and (as_int(r.get('size')) or 0) >= 64 * 1024:
            hints.append({'hint': f'high-entropy resource type {r.get("type")} ({r.get("size")} bytes)', 'kind': 'resource'})
    for h in hints:
        h['severity'] = 'low'
        h['context_only'] = True
    return hints


def downgrade_pe_hints(hints: list[dict], known_good: Iterable[dict] = ()) -> tuple[list[dict], str | None]:
    """P271 c7: packer/entropy hints are downgraded to info when a known-good source in the case marks the hash
    (CIRCL hashlookup without KnownMalicious, P169 known-good lists).  A hashlookup hit alone is not proof of good,
    so the hints stay visible with the reason."""
    marks = [m for m in known_good or [] if isinstance(m, dict)]
    good = [m for m in marks if not m.get('known_malicious')]
    bad = [m for m in marks if m.get('known_malicious')]
    if not good or bad:
        return hints, ('not downgraded: a known-good source also reports KnownMalicious' if bad and good else None)
    src = ', '.join(sorted({str(m.get('source')) for m in good}))
    note = f'downgraded: {src} lists this hash as known software (a hashlookup hit alone is not proof of good)'
    return [{**h, 'severity': 'info', 'downgraded': True} for h in hints], note


def normalize_pe(raw: Any, now: _dt.datetime | None = None, known_good: Iterable[dict] = ()) -> dict:
    """Normalise pefile_child / parse_pe output (P271 c4-c7): summary, compile time with reliability flags,
    imphash, Rich hash (attribute), sections with entropy, imports, packer hints (context, downgradable),
    Authenticode 'signed, not verified' with signer subject/issuer/serial, PDB path as privacy attributes,
    pivots: md5/sha256 hash pivots, imphash and signer with expand=False."""
    if not isinstance(raw, dict):
        return {'status': 'error', 'reason_code': 'error', 'reason': 'sandbox output is not an object', 'pivots': []}
    if raw.get('error'):
        msg = as_str(raw.get('message'), 200) or raw['error']
        not_pe = any(k in msg for k in ('DOS Header magic not found', 'NT Headers not found', 'e_lfanew'))
        if not_pe:
            return {'status': 'not_applicable', 'reason_code': 'not_applicable',
                    'reason': f'not a PE file ({msg})', 'pivots': [], 'summary': 'not a PE file'}
        return {'status': 'error', 'reason_code': 'error', 'reason': f'malformed or truncated PE ({msg})',
                'pivots': [], 'summary': 'malformed or truncated PE'}
    debug = raw.get('debug') or []
    ct = compile_time_flags(raw.get('timestamp'), now, [as_int(d.get('type')) for d in debug if isinstance(d, dict)])
    dbg_ts = {as_int(d.get('timestamp')) for d in debug if isinstance(d, dict) and as_int(d.get('timestamp'))}
    if dbg_ts and as_int(raw.get('timestamp')) not in dbg_ts and 'reproducible_build' not in ct['flags']:
        ct['flags'].append('debug_timestamp_differs')
        ct['reliable'] = False
        ct['label'] = 'unreliable/forged'
    is_dll = bool((as_int(raw.get('characteristics')) or 0) & 0x2000)
    is64 = as_int(raw.get('magic')) == 0x20B
    machine = PE_MACHINES.get(as_int(raw.get('machine')) or 0, f'0x{(as_int(raw.get("machine")) or 0):x}')
    subsystem = PE_SUBSYSTEMS.get(as_int(raw.get('subsystem')) or 0, str(raw.get('subsystem')))
    imports = {}
    count = 0
    for imp in raw.get('imports') or []:
        dll = as_str(imp.get('dll'), 256) or '?'
        fl = []
        table = ORDINAL_NAMES.get(dll.lower(), {})
        for f in imp.get('functions') or []:
            ordv = as_int(f.get('ordinal'))
            fl.append(as_str(f.get('name'), 256) or table.get(ordv) or f'ord{ordv}')
        imports.setdefault(dll, []).extend(fl)
        count += len(fl)
    sections = [{'name': as_str(s.get('name'), 16), 'entropy': as_float(s.get('entropy')),
                 'raw_size': as_int(s.get('raw_size')), 'virtual_size': as_int(s.get('virtual_size')),
                 'characteristics': as_int(s.get('characteristics'))} for s in raw.get('sections') or []]
    hints = pe_packer_hints(raw)
    hints, downgrade_note = downgrade_pe_hints(hints, known_good)
    auth = raw.get('authenticode') or {'present': False, 'status': 'unsigned', 'signers': []}
    signers = [s for s in auth.get('signers') or [] if s.get('serial')]
    pdbs = [pdb_info(d.get('pdb')) for d in debug if isinstance(d, dict) and d.get('pdb')]
    pdbs = [p for p in pdbs if p]
    rich = raw.get('rich') or {}
    pivots = []
    for algo in ('md5', 'sha256'):
        if as_str(raw.get(algo), 64):
            pivots.append({'type': algo, 'value': raw[algo], 'relation': 'file_hash'})
    if as_str(raw.get('imphash'), 32):
        pivots.append({'type': 'imphash', 'value': raw['imphash'], 'relation': 'imphash', 'expand': False,
                       'fallback': 'attribute until the P333 type exists (never a keyword)'})
    for s in signers[:4]:
        pivots.append({'type': 'x509_signer', 'value': f"{s.get('issuer')}|{s.get('serial')}", 'subject': s.get('subject'),
                       'issuer': s.get('issuer'), 'serial': s.get('serial'), 'relation': 'signed_by',
                       'expand': False, 'status': 'signed, not verified',
                       'fallback': 'attribute until the P333 type exists (never a keyword)'})
    kind = ('PE32+' if is64 else 'PE32') + (' DLL' if is_dll else ' executable')
    size = as_int(raw.get('size')) or 0
    raw_end = max([(as_int(s.get('raw_offset')) or 0) + (as_int(s.get('raw_size')) or 0)
                   for s in raw.get('sections') or [] if as_int(s.get('raw_size'))] or [0])
    sec_dir = raw.get('security_dir') or {}
    truncated = bool(size and (raw_end > size or (sec_dir.get('offset') or 0) + (sec_dir.get('size') or 0) > size))
    too_many = (as_int(raw.get('number_of_sections')) or 0) > PE_CAPS['sections']
    if ct['raw'] == 0:
        when = '0 (unreliable/forged)'
    elif ct['value']:
        when = ct['value'][:10] + (f' ({ct["label"]})' if ct['label'] else '')
    else:
        when = ct['label'] or 'missing'
    sig_txt = (f"signed (not verified) by \"{signers[0].get('subject') or signers[0].get('issuer')}\""
               if signers else ('signature present but unreadable' if auth.get('present') else 'unsigned'))
    summary = (f'{"truncated " if truncated else ""}{kind} ({machine}, {subsystem}), compile time {when}, '
               f'{len(sections)} sections, {count} imports from {len(imports)} DLLs, {sig_txt}')
    anomalies = []
    if truncated:
        anomalies.append('truncated: section or certificate data runs past the end of the file')
    if too_many:
        anomalies.append(f'NumberOfSections {raw.get("number_of_sections")} above the cap of {PE_CAPS["sections"]}')
    attributes = {k: v for k, v in {
        'imphash': as_str(raw.get('imphash'), 32), 'rich_header_hash': rich.get('clear_md5') or None,
        'rich_checksum_valid': rich.get('checksum_valid'), 'compile_time': ct['value'],
        'compile_time_flags': ct['flags'] or None, 'machine': machine, 'subsystem': subsystem,
        'signature': auth.get('status'), 'export_dll_name': as_str(raw.get('export_dll_name'), 256),
    }.items() if v not in (None, '', [])}
    privacy_attributes = []
    for p in pdbs:
        privacy_attributes.append({'name': 'pdb_path', 'value': p['path'], 'tags': ['privacy']})
        if p['username']:
            privacy_attributes.append({'name': 'pdb_username', 'value': p['username'], 'tags': ['privacy'],
                                       'entity': None})
        if p['machine']:
            privacy_attributes.append({'name': 'pdb_machine', 'value': p['machine'], 'tags': ['privacy'], 'entity': None})
    return {
        'status': 'ok', 'reason_code': None, 'summary': summary, 'file_type': kind, 'machine': machine,
        'subsystem': subsystem, 'is_dll': is_dll, 'compile_time': ct, 'imphash': as_str(raw.get('imphash'), 32),
        'imphash_exact': raw.get('imphash_exact', True), 'rich': {'hash': rich.get('clear_md5'), 'entries': rich.get('entries'),
                                                                  'checksum_valid': rich.get('checksum_valid')} if rich else None,
        'sections': sections, 'imports': imports, 'import_count': count, 'exports': raw.get('exports') or [],
        'packer_hints': hints, 'hints_note': downgrade_note, 'signature': {
            'present': bool(auth.get('present')), 'status': auth.get('status'),
            'signers': [{k: s.get(k) for k in ('subject', 'issuer', 'serial', 'not_before', 'not_after', 'sha256')} for s in signers],
            'timestamped': any(en.get('timestamped') for en in auth.get('entries') or [] if isinstance(en, dict)),
            'anomalies': auth.get('anomalies') or []},
        'pdb': pdbs, 'overlay': raw.get('overlay'), 'pivots': pivots, 'attributes': attributes,
        'privacy_attributes': privacy_attributes, 'warnings': (raw.get('warnings') or [])[:20],
        'md5': as_str(raw.get('md5'), 32), 'sha256': as_str(raw.get('sha256'), 64),
        'anomalies': anomalies, 'partial': truncated or too_many,
        'parse_error': raw.get('parse_error'), 'verdict': None,
    }


# ======================================================================================================
# Sandbox child (runs ONLY inside core/sandbox.py; pefile imported inside the function)
# ======================================================================================================

PEFILE_CAPS = {"sections": 96, "import_symbols": 4096, "export_symbols": 8192, "resource_entries": 4096,
               "resource_depth": 8, "debug_entries": 16, "cert_table_bytes": 512 * 1024}


def pefile_child(data: bytes) -> dict[str, Any]:
    """c2-c4 sandbox child: pefile fast_load + only IMPORT/EXPORT/RESOURCE/DEBUG with caps; the Authenticode
    blob is decoded by the stdlib DER reader (:func:`authenticode_info`), never verified."""
    import pefile

    caps = PEFILE_CAPS
    pefile.MAX_SECTIONS = caps["sections"]
    pefile.MAX_IMPORT_SYMBOLS = caps["import_symbols"]
    pefile.MAX_SYMBOL_EXPORT_COUNT = caps["export_symbols"]
    pefile.MAX_RESOURCE_ENTRIES = caps["resource_entries"]
    pefile.MAX_RESOURCE_DEPTH = caps["resource_depth"]
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        return {"source": "pefile", "error": "PEFormatError", "message": str(exc)[:300]}
    d = pefile.DIRECTORY_ENTRY
    parse_error = None
    try:
        pe.parse_data_directories(directories=[d["IMAGE_DIRECTORY_ENTRY_IMPORT"], d["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                                               d["IMAGE_DIRECTORY_ENTRY_RESOURCE"], d["IMAGE_DIRECTORY_ENTRY_DEBUG"]])
    except Exception as exc:  # noqa: BLE001 - pefile raises assorted errors on hostile directories
        parse_error = f"{type(exc).__name__}: {str(exc)[:200]}"
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    out: dict[str, Any] = {
        "source": "pefile", "size": len(data), "parse_error": parse_error, "machine": fh.Machine,
        "number_of_sections": fh.NumberOfSections, "timestamp": fh.TimeDateStamp, "characteristics": fh.Characteristics,
        "magic": oh.Magic, "subsystem": oh.Subsystem, "dll_characteristics": oh.DllCharacteristics,
        "entry_point": oh.AddressOfEntryPoint, "image_base": oh.ImageBase, "checksum": oh.CheckSum,
        "size_of_image": oh.SizeOfImage, "size_of_headers": oh.SizeOfHeaders, "sections": [], "imports": [],
        "exports": [], "debug": [], "resources": [], "warnings": [w[:200] for w in pe.get_warnings()[:50]],
    }
    for s in pe.sections[:caps["sections"]]:
        out["sections"].append({"name": s.Name.rstrip(b"\x00").decode("latin-1"), "virtual_address": s.VirtualAddress,
                                "virtual_size": s.Misc_VirtualSize, "raw_size": s.SizeOfRawData, "raw_offset": s.PointerToRawData,
                                "characteristics": s.Characteristics, "entropy": round(s.get_entropy(), 4)})
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:256]:
        out["imports"].append({"dll": entry.dll.decode("latin-1") if entry.dll else None,
                               "functions": [{"name": i.name.decode("latin-1") if i.name else None,
                                              "ordinal": i.ordinal if i.import_by_ordinal else None}
                                             for i in entry.imports[:caps["import_symbols"]]]})
    try:
        out["imphash"] = pe.get_imphash() or None
    except Exception:  # noqa: BLE001
        out["imphash"] = None
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp is not None:
        out["export_dll_name"] = exp.name.decode("latin-1") if exp.name else None
        for s in exp.symbols[:caps["export_symbols"]]:
            out["exports"].append({"name": s.name.decode("latin-1") if s.name else None, "ordinal": s.ordinal,
                                   "forwarder": s.forwarder.decode("latin-1") if s.forwarder else None})
    rich = pe.parse_rich_header()
    if rich:  # with fast_load get_rich_header_hash() is '': hash parse_rich_header()['clear_data'] instead
        vals = rich.get("values", [])
        out["rich"] = {"key_hex": rich["key"].hex() if isinstance(rich.get("key"), bytes) else None,
                       "checksum": rich.get("checksum"), "clear_md5": hashlib.md5(rich.get("clear_data") or b"").hexdigest(),
                       "entries": [[vals[i], vals[i + 1]] for i in range(0, len(vals) - 1, 2)][:128]}
    for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", [])[:caps["debug_entries"]]:
        item = {"type": dbg.struct.Type, "timestamp": dbg.struct.TimeDateStamp, "size": dbg.struct.SizeOfData}
        e = getattr(dbg, "entry", None)
        if e is not None and hasattr(e, "PdbFileName"):
            item["pdb"] = e.PdbFileName.rstrip(b"\x00").decode("utf-8", "replace")[:1024]
            item["age"] = getattr(e, "Age", None)
        out["debug"].append(item)
    sec = oh.DATA_DIRECTORY[d["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    out["security_dir"] = {"offset": sec.VirtualAddress, "size": sec.Size}
    if sec.VirtualAddress and sec.Size:
        out["authenticode"] = authenticode_info(data[sec.VirtualAddress:sec.VirtualAddress + min(sec.Size, caps["cert_table_bytes"])])
    ov = pe.get_overlay_data_start_offset()
    out["overlay"] = {"offset": ov, "size": len(data) - ov} if ov is not None else None
    out["md5"] = hashlib.md5(data).hexdigest()
    out["sha256"] = hashlib.sha256(data).hexdigest()
    return out


# ======================================================================================================
# The module
# ======================================================================================================

PARSER_LIMITS = {"wall_timeout": 30.0, "cpu_seconds": 25}
_FLAG_TEXT = {"zero": "zero", "future": "in the future", "pre_2000": "before 2000", "delphi_1992": "the Delphi/Borland 1992 constant",
              "debug_timestamp_differs": "contradicted by the debug directory timestamp", "missing": "missing"}


def parse_input(data: bytes, path: str) -> tuple[dict[str, Any], str]:
    """(raw dump, parser note): pefile in the core sandbox when available, else the stdlib reader in process."""
    if core_sandbox() is not None and package_available("pefile"):
        out = sandbox_run(f"{__name__}:pefile_child", path, **PARSER_LIMITS)
        if not out.get("ok"):
            code, reason = sandbox_failure(out)
            raise RuntimeError(f"{code}|{reason}")
        raw = out.get("result")
        return (raw if isinstance(raw, dict) else {"error": "PEFormatError", "message": "no result object"}), f"pefile in the sandbox ({out.get('isolation') or 'isolated'})"
    return parse_pe(data), "bounded standard-library PE reader (core/sandbox.py is not in this build; pefile is never run in process)"


@register
class PeTriage(Module):
    name = "pe_triage"
    title = "PE triage (headers, imports, imphash, Rich, Authenticode)"
    description = (
        "Static triage of a local Windows PE file offline: compile time with reliability flags, imphash, Rich header "
        "hash, sections with entropy, imports, packer hints (context), Authenticode signer ('signed, not verified') "
        "and PDB path. The sample is never executed."
    )
    category = "file_analysis"
    accepts = {T.FILE}
    produces = {T.MD5, T.SHA256, T.IMPHASH, T.CODE_SIGNING_CERT}
    reference = "https://github.com/erocarrera/pefile"
    tags = {"offline"}
    notice = (
        "Static parsing only: the sample is never executed. Packer hints and entropy are context, not verdicts; "
        "signatures are recorded as 'signed, not verified'; PDB user and machine names are personal data (attributes only)."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # no network at all
    hosts = ()
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.1
    timeout = 90.0
    max_pivots = 10
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return read_head(entity.value, 2) == b"MZ"

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        try:
            data = read_regular_file(entity.value)
            raw, parser = parse_input(data, entity.value)
        except InputRefused as exc:
            return res.mark(exc.status, str(exc), reason_code=exc.code)
        except SandboxUnavailable as exc:
            return res.mark("unavailable", str(exc), reason_code="package")
        except RuntimeError as exc:
            code, _, reason = str(exc).partition("|")
            return res.mark("error", reason or str(exc), reason_code=code if code in ("timeout", "error") else "error")
        norm = normalize_pe(raw, now=ctx.now())
        if norm["status"] == "not_applicable":
            return res.mark("skipped", str(norm["reason"]), reason_code="not_applicable")
        if norm["status"] != "ok":
            res.raw = {"parser": parser, "error": norm.get("reason")}
            return res.mark("error", str(norm.get("reason")), reason_code="error")
        self.emit(res, norm, parser)
        return res

    def emit(self, res: ModuleResult, norm: dict[str, Any], parser: str) -> None:
        attrs = norm["attributes"]
        res.attr("pe_summary", norm["summary"])
        res.attr("file_type", norm["file_type"])
        for key, name in (("imphash", "imphash"), ("rich_header_hash", "rich_header_hash"), ("rich_checksum_valid", "rich_checksum_valid"),
                          ("compile_time", "compile_time"), ("compile_time_flags", "compile_time_flags"), ("machine", "pe_machine"),
                          ("subsystem", "pe_subsystem"), ("export_dll_name", "export_dll_name")):
            res.attr(name, attrs.get(key))
        res.attr("md5", norm.get("md5"))
        res.attr("sha256", norm.get("sha256"))
        res.attr("pe_sections", norm["sections"][:96])
        res.attr("pe_imports", {dll: fns[:512] for dll, fns in list(norm["imports"].items())[:256]})
        res.attr("pe_signature", norm["signature"])
        res.attr("pe_packer_hints", [{k: h[k] for k in ("hint", "kind", "severity")} for h in norm["packer_hints"]])
        for p in norm["privacy_attributes"]:  # c6: attributes only, never username entities
            res.attr(p["name"], p["value"])
        res.finding("PE triage", "info", norm["summary"] + ".", tags=["info"],
                    data={"file_type": norm["file_type"], "imports": norm["import_count"], "sections": len(norm["sections"]), "parser": parser})
        ct = norm["compile_time"]
        if ct.get("flags"):
            flags = [f for f in ct["flags"] if f != "reproducible_build"]
            if "reproducible_build" in ct["flags"]:
                res.finding("Compile timestamp is a build hash (reproducible build)", "info",
                            "A REPRO debug entry is present: the COFF TimeDateStamp holds a build hash, not a date.", tags=["info"])
            if flags:
                res.finding("Compile timestamp unreliable/forged", "info",
                            "The COFF compile timestamp is " + ", ".join(_FLAG_TEXT.get(f, f) for f in flags) + ": unreliable/forged, do not date the sample by it.",
                            tags=["info", "unreliable_timestamp"], data={"raw": ct.get("raw"), "flags": ct["flags"]})
        hints = norm["packer_hints"]
        if hints:
            res.finding("Packer or obfuscation hints", "low",
                        "; ".join(h["hint"] for h in hints[:12]) + ". Context, not a verdict: legitimate installers and protectors show the same traits.",
                        confidence="possible", criterion="static PE traits: packer section names, entropy >= 7.2, W+X sections, loader-only imports, overlay (P271 c4/c7)",
                        tags=["packer_hint", "context_only"], data={"hints": [h["hint"] for h in hints]})
        sig = norm["signature"]
        if sig["present"]:
            who = ", ".join(s.get("subject") or s.get("issuer") or "?" for s in sig["signers"][:3]) or "unreadable signer"
            res.finding("Authenticode signature present (signed, not verified)", "info",
                        f"Signer: {who}. Recorded as 'signed, not verified': no claim about validity, revocation or trust.",
                        tags=["info"], data={"signers": sig["signers"][:4], "timestamped": sig["timestamped"]})
        if norm["anomalies"]:
            res.finding("Malformed or truncated PE structures", "info", "; ".join(norm["anomalies"]) + ".", tags=["info"],
                        data={"anomalies": norm["anomalies"], "warnings": norm["warnings"][:10]})
        for p in norm["pivots"]:
            if p["type"] in ("md5", "sha256"):
                res.pivot(T(p["type"]), p["value"], "has_hash", confidence="confirmed", note="computed locally from the file content")
            elif p["type"] == "imphash":
                res.pivot(T.IMPHASH, p["value"], "has_imphash", confidence="confirmed", expand=False,
                          note="import-table hash: for hash-lookup modules on analyst selection (shared by unrelated builds)")
        for s in sig["signers"][:4]:
            if s.get("sha256"):
                res.pivot(T.CODE_SIGNING_CERT, s["sha256"], "signing_certificate", confidence="probable", expand=False,
                          note=f"signer certificate {s.get('subject') or ''} (serial {s.get('serial')}): signed, not verified")
        res.raw = {"summary": norm["summary"], "parser": parser, "compile_time": ct, "imphash_exact": norm.get("imphash_exact"),
                   "rich": norm.get("rich"), "overlay": norm.get("overlay"), "pdb": norm.get("pdb"), "anomalies": norm["anomalies"],
                   "parse_error": norm.get("parse_error"), "hint_kinds": sorted({h["kind"] for h in hints})}
