"""Android APK static triage (P364) - offline, disclosure 'none'.

Final conditions of P364 implemented here:

* c1 offline module (ctx.http refuses every request), terms 'open', tier 'n/a', allowed at TLP:RED;
  FILE input only. APKs are parsed, never installed, emulated or executed.
* c2 own parser on the safe ZIP reader of file_type_sniff: central-directory reading tolerant of malware
  zip tricks (duplicate entries resolve to the first, like Android; a bad central directory falls back
  to a local-header scan; the fake-encryption flag is ignored, like Android), a binary AXML manifest
  decoder (UTF-8/UTF-16 pools, resource-map attribute names so blanked names still resolve),
  resources.arsc label resolution, v1 (META-INF PKCS#7) and v2/v3/v3.1 signing-block certificate
  SHA-256, and URL/IP/domain extraction from dex strings (the P172 extractor interface; core
  ``v3lum.core.ioc`` arrives in wave 3). androguard is not needed (optional deep analysis: backlog).
* c3 bounded in-process parsing (input cap 100 MB, DEX 64 MB per file, a 256 MB read budget, entry,
  size and ratio caps). The core sandbox (core/sandbox.py) does not exist yet: see the backlog.
* c4 outputs: package and label, permissions, exported components, the signing-certificate SHA-256 as a
  code_signing_cert pivot (P333), embedded URLs/domains/IPs as hostile pivots for passive modules only
  (never contacted: no network); SDK/analytics/CDN hosts (firebase, crashlytics, google-analytics,
  app-measurement...) and warninglisted values are reported as noise, not pivoted.
* c5 the banker profile is data (``v3lum/data/apk_triage/profiles.json``): accessibility service +
  overlay + SMS + device admin, plus REQUEST_INSTALL_PACKAGES or QUERY_ALL_PACKAGES, gives a MEDIUM
  heuristic 'permissions consistent with Brazilian banking trojans' in plain language; never 'malicious'.
* c6/c7 impersonation: a label or package matching an org_profile brand or a protected Brazilian bank
  brand AND a signing certificate different from the official one = HIGH. Protected brands: org_profile
  brands, the curated dated list ``v3lum/data/apk_triage/br_bank_app_certs.json`` and P360's
  BCB-verified institution domains (:func:`p360_brands`, read from P360's local copy, never downloaded
  here). Reference certificates come from org_profile app_ids (kind ``android_cert_sha256``), the
  curated list, setting ``apk_triage_reference_certs`` (analyst-supplied, e.g. an archived
  assetlinks.json parsed with :func:`parse_assetlinks`) and, inside a case, the P008 Digital Asset Links
  results of the brand's domain (correlation rule ``g12_apk_dal_cert_mismatch``,
  ``v3lum/correlations/p1_g12_1.py``); no request is made here. Without a reference the finding reads
  'protected brand used, official certificate unknown' (no verdict). The direct LIGHT fetch of a
  brand's assetlinks.json waits for the shared LIGHT fetcher (backlog).
"""

from __future__ import annotations

import datetime as _dt
import functools
import hashlib
import json
import re
import struct
import unicodedata
import urllib.parse
from pathlib import Path
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core import noise as _noise
from v3lum.core.datasets import DatasetError
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.file_analysis.file_type_sniff import (
    LIMITS,
    ArchiveLimit,
    Budget,
    FileRefused,
    UnsafeXML,
    cap_json,
    clean_text,
    emit_findings,
    extract_iocs,
    fact,
    non_routable,
    read_capped,
    safe_xml_parse,
    sniff_path,
    u16,
    u32,
    u64,
    xml_local,
    zip_read,
    zip_scan,
)

try:  # c6 'BCB-protected brand (P360)': read from P360's local BCB copies only, never downloaded here
    from v3lum.modules.brazil_public_data import bcb_authorized_institutions as _p360
except ImportError:  # pragma: no cover - P360 ships with the package
    _p360 = None

_DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "apk_triage"
DEX_MAX_BYTES = 64 * 1024 * 1024


@functools.lru_cache(maxsize=1)
def profiles() -> dict[str, Any]:
    """The bundled banker profile, plain-language permissions, SDK noise list and packer hints (c4/c5 as data)."""
    return json.loads((_DATA_DIR / "profiles.json").read_text(encoding="utf-8"))


@functools.lru_cache(maxsize=1)
def curated_references() -> dict[str, Any]:
    """The curated, dated list of Brazilian bank brands and official app certificates (c6)."""
    return json.loads((_DATA_DIR / "br_bank_app_certs.json").read_text(encoding="utf-8"))


# ======================================================================================== DER / X.509 / PKCS#7


class DERError(ValueError):
    pass


def _der_tlv(buf: bytes, off: int, end: int, depth: int = 0) -> tuple[int, int, int, int]:
    """One BER/DER TLV -> (tag, content_start, content_end, next_offset). Definite lengths up to 4 bytes;
    the indefinite form is accepted for constructed tags (old signers emit BER)."""
    if depth > 40:
        raise DERError("too_deep")
    if off + 2 > end:
        raise DERError("truncated_header")
    tag = buf[off]
    off += 1
    if tag & 0x1F == 0x1F:  # high tag number
        for _ in range(5):
            if off >= end:
                raise DERError("truncated_tag")
            b = buf[off]
            off += 1
            if not b & 0x80:
                break
        else:
            raise DERError("tag_too_long")
    if off >= end:
        raise DERError("truncated_length")
    ln = buf[off]
    off += 1
    if ln == 0x80:
        if not tag & 0x20:
            raise DERError("indefinite_primitive")
        pos = off
        for _ in range(100_000):
            if pos + 2 > end:
                raise DERError("unterminated_indefinite")
            if buf[pos] == 0 and buf[pos + 1] == 0:
                return tag, off, pos, pos + 2
            _, _, _, pos = _der_tlv(buf, pos, end, depth + 1)
        raise DERError("too_many_children")
    if ln & 0x80:
        n = ln & 0x7F
        if n > 4 or off + n > end:
            raise DERError("bad_length")
        ln = int.from_bytes(buf[off:off + n], "big")
        off += n
    if off + ln > end:
        raise DERError("truncated_content")
    return tag, off, off + ln, off + ln


def der_children(buf: bytes, start: int, end: int, limit: int = 10_000) -> list[tuple[int, int, int, int, int]]:
    """(tag, content_start, content_end, tlv_start, tlv_end) of the TLVs between start and end."""
    out = []
    pos = start
    while pos < end and len(out) < limit:
        tag, cs, ce, nxt = _der_tlv(buf, pos, end)
        out.append((tag, cs, ce, pos, nxt))
        pos = nxt
    return out


def der_oid(content: bytes) -> str:
    if not content:
        return ""
    first = content[0]
    parts = [str(min(first // 40, 2)), str(first - 40 * min(first // 40, 2))]
    val = 0
    for b in content[1:32]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(val))
            val = 0
    return ".".join(parts)


_NAME_OIDS = {"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber",
              "1.2.840.113549.1.9.1": "emailAddress", "2.5.4.12": "title", "0.9.2342.19200300.100.1.25": "DC"}


def _der_string(tag: int, content: bytes) -> str:
    t = tag & 0x1F
    if t == 0x1E:
        return content.decode("utf-16-be", "replace")
    if t == 0x1C:
        return content.decode("utf-32-be", "replace")
    if t == 0x0C:
        return content.decode("utf-8", "replace")
    return content.decode("latin-1")


def x509_name(buf: bytes, start: int, end: int) -> list[tuple[str, str]]:
    out = []
    for _, rcs, rce, _, _ in der_children(buf, start, end, limit=64):  # RDN SET
        for _, acs, ace, _, _ in der_children(buf, rcs, rce, limit=16):  # AttributeTypeAndValue SEQUENCE
            kids = der_children(buf, acs, ace, limit=4)
            if len(kids) >= 2:
                oid = der_oid(buf[kids[0][1]:kids[0][2]])
                out.append((_NAME_OIDS.get(oid, oid), clean_text(_der_string(kids[1][0], buf[kids[1][1]:kids[1][2]]), 256) or ""))
    return out


def _der_time(tag: int, content: bytes) -> str | None:
    s = content.decode("ascii", "replace")
    try:
        if tag == 0x17:  # UTCTime YYMMDDHHMMSSZ
            s = ("19" if int(s[:2]) >= 50 else "20") + s
        return _dt.datetime.strptime(s[:14], "%Y%m%d%H%M%S").replace(tzinfo=_dt.timezone.utc).isoformat()
    except ValueError:
        return None


def x509_summary(cert_der: bytes) -> dict[str, Any]:
    """One X.509 certificate (no signature verification): SHA-256 of the DER (what apksigner prints and
    Digital Asset Links lists), subject, issuer, serial, validity and the SPKI digest."""
    buf = bytes(cert_der)
    res: dict[str, Any] = {"sha256": hashlib.sha256(buf).hexdigest(), "sha1": hashlib.sha1(buf).hexdigest(), "subject": None, "issuer": None,
                           "serial": None, "not_before": None, "not_after": None, "spki_sha256": None, "self_signed": None, "error": None}
    try:
        tag, cs, ce, _ = _der_tlv(buf, 0, len(buf))
        if tag != 0x30:
            raise DERError("not_sequence")
        top = der_children(buf, cs, ce, limit=4)
        tbs = der_children(buf, top[0][1], top[0][2], limit=16)
        i = 1 if tbs and tbs[0][0] == 0xA0 else 0  # [0] version
        res["serial"] = buf[tbs[i][1]:tbs[i][2]].hex()[:64]
        issuer = x509_name(buf, tbs[i + 2][1], tbs[i + 2][2])
        validity = der_children(buf, tbs[i + 3][1], tbs[i + 3][2], limit=2)
        subject = x509_name(buf, tbs[i + 4][1], tbs[i + 4][2])
        spki = tbs[i + 5]
        res["subject"] = ", ".join(f"{k}={v}" for k, v in subject)
        res["issuer"] = ", ".join(f"{k}={v}" for k, v in issuer)
        res["not_before"] = _der_time(validity[0][0], buf[validity[0][1]:validity[0][2]])
        res["not_after"] = _der_time(validity[1][0], buf[validity[1][1]:validity[1][2]])
        res["spki_der"] = buf[spki[3]:spki[4]]
        res["spki_sha256"] = hashlib.sha256(res["spki_der"]).hexdigest()
        res["self_signed"] = subject == issuer
    except (DERError, IndexError, struct.error) as exc:
        res["error"] = f"x509_parse: {exc}"
    return res


def pkcs7_certificates(der: bytes) -> list[bytes]:
    """Certificates (full DER) inside a PKCS#7/CMS SignedData blob (APK v1 META-INF/*.RSA|DSA|EC)."""
    buf = bytes(der)
    tag, cs, ce, _ = _der_tlv(buf, 0, len(buf))
    if tag != 0x30:
        raise DERError("not_content_info")
    kids = der_children(buf, cs, ce, limit=4)
    if len(kids) < 2 or der_oid(buf[kids[0][1]:kids[0][2]]) != "1.2.840.113549.1.7.2":
        raise DERError("not_signed_data")
    inner = der_children(buf, kids[1][1], kids[1][2], limit=4)  # [0] EXPLICIT
    if not inner or inner[0][0] != 0x30:
        raise DERError("bad_signed_data")
    certs = []
    for t, ccs, cce, _, _ in der_children(buf, inner[0][1], inner[0][2], limit=16):
        if t == 0xA0:  # [0] IMPLICIT SET OF Certificate
            for t2, _, _, s2, e2 in der_children(buf, ccs, cce, limit=64):
                if t2 == 0x30:
                    certs.append(buf[s2:e2])
    return certs


# ======================================================================================== binary AXML

ANDROID_NS = "http://schemas.android.com/apk/res/android"
#: android attribute resource ids -> names (obfuscated APKs blank the attribute-name strings)
ANDROID_ATTR_IDS = {0x01010001: "label", 0x01010002: "icon", 0x01010003: "name", 0x01010006: "permission", 0x0101000E: "enabled",
                    0x0101000F: "debuggable", 0x01010010: "exported", 0x01010024: "value", 0x01010025: "resource",
                    0x0101021B: "versionCode", 0x0101021C: "versionName", 0x0101020C: "minSdkVersion", 0x01010270: "targetSdkVersion",
                    0x01010271: "maxSdkVersion", 0x01010280: "allowBackup", 0x010104EC: "usesCleartextTraffic"}


def _string_pool(buf: bytes, off: int) -> list[str]:
    """ResStringPool chunk at ``off`` -> list of strings (UTF-8 or UTF-16)."""
    _, hsize, size = struct.unpack_from("<HHI", buf, off)
    count, _styles, flags, sstart, _ = struct.unpack_from("<IIIII", buf, off + 8)
    utf8 = bool(flags & 0x100)
    count = min(count, 500_000, max(0, (len(buf) - off - hsize) // 4))
    offs = struct.unpack_from(f"<{count}I", buf, off + hsize) if count else ()
    base, end = off + sstart, min(off + size, len(buf))
    out = []
    for o in offs:
        p = base + o
        try:
            if p >= end:
                out.append("")
                continue
            if utf8:
                p += 2 if buf[p] & 0x80 else 1  # utf16 length (skipped)
                n = buf[p]
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | buf[p + 1]
                    p += 2
                else:
                    p += 1
                out.append(buf[p:min(p + n, end, p + LIMITS["string_max_len"])].decode("utf-8", "replace"))
            else:
                n = u16(buf, p)
                p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | u16(buf, p)
                    p += 2
                out.append(buf[p:min(p + 2 * n, end, p + 2 * LIMITS["string_max_len"])].decode("utf-16-le", "replace"))
        except (IndexError, struct.error):
            out.append("")
    return out


def _res_value(dtype: int, data: int, strings: list[str]) -> Any:
    if dtype == 0x03:
        return strings[data] if data < len(strings) else ""
    if dtype == 0x12:
        return data != 0
    if dtype == 0x10:
        return struct.unpack("<i", struct.pack("<I", data))[0]
    if dtype == 0x11:
        return hex(data)
    if dtype in (0x01, 0x07):
        return {"ref": data}
    if dtype == 0x04:
        return struct.unpack("<f", struct.pack("<I", data))[0]
    return {"type": dtype, "data": data}


def axml_decode(buf: bytes) -> dict[str, Any]:
    """Binary XML -> {'elements': [{'tag', 'depth', 'attrs'}], 'anomalies'}; tolerant of lying chunk sizes
    and blanked attribute-name strings (resolved through the resource map)."""
    res: dict[str, Any] = {"elements": [], "anomalies": []}
    if len(buf) < 8:
        res["anomalies"].append("too_short")
        return res
    if buf[:4] != b"\x03\x00\x08\x00":
        res["anomalies"].append("unexpected_xml_header")
    strings: list[str] = []
    resmap: list[int] = []
    pos, depth = 8, 0
    while pos + 8 <= len(buf) and len(res["elements"]) < 50_000:
        ctype, hsize, csize = struct.unpack_from("<HHI", buf, pos)
        if csize < 8 or pos + csize > len(buf):
            res["anomalies"].append("bad_chunk_size")
            break
        try:
            if ctype == 0x0001 and not strings:
                strings = _string_pool(buf, pos)
            elif ctype == 0x0180:
                n = min((csize - hsize) // 4, 100_000)
                resmap = list(struct.unpack_from(f"<{n}I", buf, pos + hsize))
            elif ctype == 0x0102:
                _ns, name, astart, asize, acount = struct.unpack_from("<IIHHH", buf, pos + 16)
                tag = strings[name] if name < len(strings) else ""
                attrs: dict[str, Any] = {}
                a0 = pos + 16 + astart
                for i in range(min(acount, 500)):
                    a = a0 + i * (asize or 20)
                    _a_ns, a_name, a_raw, _vsize, _r0, dtype, data = struct.unpack_from("<IIIHBBI", buf, a)
                    aname = strings[a_name] if a_name < len(strings) else ""
                    rid = resmap[a_name] if a_name < len(resmap) else None
                    if rid in ANDROID_ATTR_IDS and aname != ANDROID_ATTR_IDS[rid]:
                        if aname:
                            res["anomalies"].append("attribute_name_mismatch")
                        aname = ANDROID_ATTR_IDS[rid]
                    raw_str = strings[a_raw] if a_raw != 0xFFFFFFFF and a_raw < len(strings) else None
                    val = _res_value(dtype, data, strings)
                    if dtype == 0x03 and raw_str is not None:
                        val = raw_str
                    attrs[aname or f"attr{i}"] = val
                res["elements"].append({"tag": tag, "depth": depth, "attrs": attrs})
                depth += 1
            elif ctype == 0x0103:
                depth = max(0, depth - 1)
        except (struct.error, IndexError):
            res["anomalies"].append("truncated_chunk")
            break
        pos += csize
    res["anomalies"] = sorted(set(res["anomalies"]))
    return res


def axml_or_text(buf: bytes) -> dict[str, Any]:
    """AndroidManifest.xml is binary AXML, or plain text XML in source-like packages (safe XML helper)."""
    if buf[:5] == b"<?xml" or buf.lstrip()[:1] == b"<":
        root = safe_xml_parse(buf)
        els: list[dict[str, Any]] = []
        stack = [(root, 0)]
        while stack and len(els) < 50_000:
            e, d = stack.pop()
            attrs = {(xml_local(k) if k.startswith("{" + ANDROID_NS) else k): v for k, v in e.attrib.items()}
            els.append({"tag": xml_local(e.tag), "depth": d, "attrs": attrs})
            stack.extend((c, d + 1) for c in reversed(list(e)))
        return {"elements": els, "anomalies": ["text_manifest"]}
    return axml_decode(buf)


# ======================================================================================== resources.arsc


def arsc_strings(buf: bytes, max_entries: int = 200_000) -> dict[str, Any]:
    """resources.arsc -> {'resolve': {res_id: {locale: value}}, 'global_strings': [...]} for string/reference values."""
    out: dict[int, dict[str, Any]] = {}
    gstrings: list[str] = []
    if len(buf) < 12 or u16(buf, 0) != 0x0002:
        return {"resolve": out, "global_strings": gstrings, "error": "not_arsc"}
    pos, count = u16(buf, 2), 0
    while pos + 8 <= len(buf):
        ctype, chs, csize = struct.unpack_from("<HHI", buf, pos)
        if csize < 8 or pos + csize > len(buf):
            break
        if ctype == 0x0001 and not gstrings:
            gstrings = _string_pool(buf, pos)
        elif ctype == 0x0200:
            pkg_id = u32(buf, pos + 8)
            p, end = pos + chs, pos + csize
            while p + 8 <= end:
                t, ths, tsz = struct.unpack_from("<HHI", buf, p)
                if tsz < 8 or p + tsz > end:
                    break
                if t == 0x0201 and p + 32 <= end:
                    type_id, flags = buf[p + 8], buf[p + 9]
                    n, estart = struct.unpack_from("<II", buf, p + 12)
                    cfg = p + 20
                    lang, country = buf[cfg + 8:cfg + 10], buf[cfg + 10:cfg + 12]
                    locale = "" if lang == b"\x00\x00" else lang.decode("latin-1").rstrip("\x00") + (
                        "-" + country.decode("latin-1").rstrip("\x00") if country != b"\x00\x00" else "")
                    idx = p + ths
                    entries: list[tuple[int, int]] = []
                    n = min(n, max_entries, max(0, (end - idx) // 2))
                    try:
                        if flags & 0x01:  # sparse: (index u16, offset/4 u16)
                            entries = [(lambda ei, eo: (ei, eo * 4))(*struct.unpack_from("<HH", buf, idx + 4 * k)) for k in range(n)]
                        elif flags & 0x02:  # offset16
                            entries = [(k, u16(buf, idx + 2 * k) * 4) for k in range(n) if u16(buf, idx + 2 * k) != 0xFFFF]
                        else:
                            entries = [(k, u32(buf, idx + 4 * k)) for k in range(n) if u32(buf, idx + 4 * k) != 0xFFFFFFFF]
                    except struct.error:
                        entries = []
                    for ei, eo in entries:
                        e = p + estart + eo
                        if e + 8 > end:
                            continue
                        esize, eflags = struct.unpack_from("<HH", buf, e)
                        rid = (pkg_id << 24) | (type_id << 16) | ei
                        if eflags & 0x0008:  # compact entry: data type in the high byte of flags
                            dtype, data = eflags >> 8, u32(buf, e + 4)
                        elif eflags & 0x0001:
                            continue  # complex (bag) entry: not a plain string
                        else:
                            if e + esize + 8 > end:
                                continue
                            _vs, _r0, dtype, data = struct.unpack_from("<HBBI", buf, e + esize)
                        if dtype == 0x03 and data < len(gstrings):
                            out.setdefault(rid, {})[locale] = gstrings[data]
                        elif dtype == 0x01:
                            out.setdefault(rid, {})[locale] = {"ref": data}
                        count += 1
                        if count > max_entries:
                            return {"resolve": out, "global_strings": gstrings, "error": "entry_cap"}
                p += tsz
        pos += csize
    return {"resolve": out, "global_strings": gstrings, "error": None}


def arsc_lookup(resolve: dict[int, dict[str, Any]], rid: int, prefer: tuple[str, ...] = ("", "pt-BR", "pt", "en")) -> str | None:
    """Resolve a resource id (following up to 5 references) to its preferred-locale string."""
    for _ in range(5):
        vals = resolve.get(rid)
        if not vals:
            return None
        v = next((vals[loc] for loc in prefer if loc in vals), next(iter(vals.values())))
        if isinstance(v, dict) and "ref" in v:
            rid = v["ref"]
            continue
        return v if isinstance(v, str) else None
    return None


# ======================================================================================== DEX strings


def _uleb128(b: bytes, p: int) -> tuple[int, int]:
    val = shift = 0
    for i in range(5):
        c = b[p + i]
        val |= (c & 0x7F) << shift
        shift += 7
        if not c & 0x80:
            return val, p + i + 1
    raise ValueError("bad_uleb128")


def dex_strings(buf: bytes, *, max_strings: int | None = None) -> list[str]:
    """DEX string_ids -> strings (MUTF-8 decoded, capped). Raises ValueError for non-DEX input."""
    max_strings = max_strings or LIMITS["dex_max_strings"]
    if len(buf) < 0x70 or buf[:4] != b"dex\n":
        raise ValueError("not_dex")
    n, off = struct.unpack_from("<II", buf, 0x38)
    out = []
    for i in range(min(n, max_strings)):
        p = off + 4 * i
        if p + 4 > len(buf):
            break
        sp = u32(buf, p)
        try:
            _, q = _uleb128(buf, sp)
        except (ValueError, IndexError):
            continue
        end = buf.find(b"\x00", q, q + LIMITS["string_max_len"] * 3)
        raw = buf[q:end if end != -1 else q + LIMITS["string_max_len"]]
        s = raw.replace(b"\xc0\x80", b"\x00").decode("utf-8", "surrogatepass")
        out.append(s.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace"))
    return out


# ======================================================================================== APK signing block v2/v3

APK_SIG_IDS = {0x7109871A: "v2", 0xF05368C0: "v3", 0x1B93AD61: "v3.1", 0x42726577: "verity_padding", 0x6DFF800D: "source_stamp_v2",
               0x2B09189E: "source_stamp", 0x504B4453: "dependency_info", 0x71777777: "channel_info"}


def _lp(buf: bytes, p: int) -> tuple[bytes, int]:
    n = u32(buf, p)
    if p + 4 + n > len(buf):
        raise ValueError("lp_out_of_range")
    return buf[p + 4:p + 4 + n], p + 4 + n


def _lp_seq(buf: bytes) -> list[bytes]:
    out, p = [], 0
    while p + 4 <= len(buf) and len(out) < 64:
        item, p = _lp(buf, p)
        out.append(item)
    return out


def apk_signing_block(data: bytes, block_range: tuple[int, int]) -> dict[str, Any]:
    """APK Signing Block -> {'schemes': {'v2': [signer...]}, 'other_ids', 'errors'}; each certificate has
    'public_key_matches_certificate' (a consistency check, not a signature verification: 'signed, not verified')."""
    start, end = block_range
    pairs = data[start:end][8:-24]
    res: dict[str, Any] = {"schemes": {}, "other_ids": [], "errors": []}
    p = 0
    while p + 12 <= len(pairs) and len(res["other_ids"]) < 64:
        ln = u64(pairs, p)
        if ln < 4 or p + 8 + ln > len(pairs):
            res["errors"].append("bad_pair_length")
            break
        pid = u32(pairs, p + 8)
        val = pairs[p + 12:p + 8 + ln]
        p += 8 + ln
        name = APK_SIG_IDS.get(pid)
        if name in ("v2", "v3", "v3.1"):
            try:
                signers_blob, _ = _lp(val, 0)
                signers = []
                for signer in _lp_seq(signers_blob):
                    signed, q = _lp(signer, 0)
                    if name != "v2":
                        q += 8  # minSDK, maxSDK
                    _sigs, q = _lp(signer, q)
                    pubkey, q = _lp(signer, q)
                    _digests, r = _lp(signed, 0)
                    certs_blob, r = _lp(signed, r)
                    certs = []
                    for c in _lp_seq(certs_blob):
                        s = x509_summary(c)
                        s["public_key_matches_certificate"] = s.get("spki_der") == pubkey
                        s.pop("spki_der", None)
                        certs.append(s)
                    signers.append({"certificates": certs})
                res["schemes"][name] = signers
            except (ValueError, struct.error) as exc:
                res["errors"].append(f"{name}:{exc}")
        elif name != "verity_padding":
            res["other_ids"].append(name or hex(pid))
    return res


# ======================================================================================== manifest, banker profile, impersonation


def _bool(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1")
    if isinstance(v, int):
        return v != 0
    return None


def manifest_summary(elements: list[dict[str, Any]], resolve: dict[int, dict[str, Any]] | None = None) -> dict[str, Any]:
    """axml_decode elements -> package, versions, SDKs, label, permissions, components (exported), traits."""
    res: dict[str, Any] = {"package": None, "version_code": None, "version_name": None, "min_sdk": None, "target_sdk": None, "label": None,
                           "label_ref": None, "debuggable": None, "allow_backup": None, "cleartext": None, "permissions": [],
                           "declared_permissions": [], "components": [], "traits": []}
    comp: dict[str, Any] | None = None
    for el in elements:
        tag, a = el["tag"], el["attrs"]
        if tag == "manifest":
            res["package"] = clean_text(a.get("package"), 256) if isinstance(a.get("package"), str) else res["package"]
            res["version_code"] = a.get("versionCode") if isinstance(a.get("versionCode"), (int, str)) else None
            res["version_name"] = clean_text(a.get("versionName"), 128) if isinstance(a.get("versionName"), str) else None
        elif tag == "uses-sdk":
            res["min_sdk"] = a.get("minSdkVersion") if isinstance(a.get("minSdkVersion"), int) else res["min_sdk"]
            res["target_sdk"] = a.get("targetSdkVersion") if isinstance(a.get("targetSdkVersion"), int) else res["target_sdk"]
        elif tag in ("uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"):
            if isinstance(a.get("name"), str) and a["name"] not in res["permissions"] and len(res["permissions"]) < 500:
                res["permissions"].append(clean_text(a["name"], 256))
        elif tag == "permission" and isinstance(a.get("name"), str) and len(res["declared_permissions"]) < 200:
            res["declared_permissions"].append(clean_text(a["name"], 256))
        elif tag == "application":
            lab = a.get("label")
            if isinstance(lab, dict) and "ref" in lab:
                res["label_ref"] = lab["ref"]
                res["label"] = clean_text(arsc_lookup(resolve or {}, lab["ref"]), 256)
            elif isinstance(lab, str):
                res["label"] = clean_text(lab, 256)
            res["debuggable"] = _bool(a.get("debuggable"))
            res["allow_backup"] = _bool(a.get("allowBackup"))
            res["cleartext"] = _bool(a.get("usesCleartextTraffic"))
        elif tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            if len(res["components"]) >= 2000:
                continue
            comp = {"type": tag, "name": clean_text(a.get("name"), 256) if isinstance(a.get("name"), str) else None,
                    "exported_attr": _bool(a.get("exported")), "permission": a.get("permission") if isinstance(a.get("permission"), str) else None,
                    "actions": [], "categories": []}
            res["components"].append(comp)
        elif tag == "intent-filter" and comp is not None:
            comp["has_intent_filter"] = True
        elif tag in ("action", "category") and comp is not None and isinstance(a.get("name"), str):
            target_list = comp["actions" if tag == "action" else "categories"]
            if len(target_list) < 50:
                target_list.append(a["name"])
    target = res["target_sdk"] or res["min_sdk"] or 1
    for c in res["components"]:
        if c["exported_attr"] is not None:
            c["exported"], c["exported_implicit"] = c["exported_attr"], False
        elif c["type"] == "provider":
            c["exported"], c["exported_implicit"] = target < 17, True
        else:
            c["exported"], c["exported_implicit"] = bool(c.get("has_intent_filter")), True
    perms = set(res["permissions"])
    traits = set()
    for c in res["components"]:
        if c["permission"] == "android.permission.BIND_ACCESSIBILITY_SERVICE" or "android.accessibilityservice.AccessibilityService" in c["actions"]:
            traits.add("accessibility_service")
        if c["permission"] == "android.permission.BIND_DEVICE_ADMIN" or "android.app.action.DEVICE_ADMIN_ENABLED" in c["actions"]:
            traits.add("device_admin")
        if c["permission"] == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE":
            traits.add("notification_listener")
        if "android.provider.Telephony.SMS_RECEIVED" in c["actions"]:
            traits.add("sms")
        if "android.intent.action.MAIN" in c["actions"] and "android.intent.category.LAUNCHER" in c["categories"]:
            traits.add("launcher_activity")
    if "android.permission.SYSTEM_ALERT_WINDOW" in perms:
        traits.add("overlay")
    if perms & {"android.permission.RECEIVE_SMS", "android.permission.READ_SMS", "android.permission.SEND_SMS"}:
        traits.add("sms")
    if "launcher_activity" not in traits and res["components"]:
        traits.add("no_launcher_icon")
    res["traits"] = sorted(traits)
    return res


BANKER_CRITERION = ("permission profile of P364 c5 (data: v3lum/data/apk_triage/profiles.json): accessibility service + overlay + SMS + "
                    "device admin, plus REQUEST_INSTALL_PACKAGES or QUERY_ALL_PACKAGES; heuristic, never a malware verdict")


def banker_profile(summary: dict[str, Any]) -> dict[str, Any] | None:
    """c5: MEDIUM heuristic 'consistent with Brazilian banking trojans' (never 'malicious' here)."""
    prof = profiles()
    profile, plain_perm, plain_trait = prof["banker_profile"], prof["permission_plain"], prof["trait_plain"]
    traits, perms = set(summary["traits"]), set(summary["permissions"])
    have = [t for t in profile["all_of"] if t in traits]
    extra = [p for p in profile["any_of_permissions"] if p in perms]
    plain = [plain_trait.get(t, t) for t in have] + [plain_perm.get(p, p) for p in extra]
    if len(have) == len(profile["all_of"]) and extra:
        return fact("banker_profile", "medium", f"Permissions {profile['name']}", confidence="possible", criterion=BANKER_CRITERION,
                    tags=["banker_profile", "suspicious"], description="; ".join(plain) + ". A permission heuristic, not a malware verdict.",
                    matched=have + extra, plain_language=plain)
    if "accessibility_service" in have and len(have) >= 2:
        missing = [t for t in profile["all_of"] if t not in traits]
        return fact("banker_profile_partial", "info", "Partial banking-trojan permission profile", confidence="possible",
                    criterion=BANKER_CRITERION, tags=["banker_profile"],
                    description=f"{len(have)} of {len(profile['all_of'])} traits: " + "; ".join(plain) + f". Missing: {', '.join(missing)}.",
                    matched=have + extra, missing=missing, plain_language=plain)
    return None


def fold(s: Any) -> str:
    s = unicodedata.normalize("NFKD", str(s or ""))
    s = "".join(c for c in s if not unicodedata.combining(c)).lower()
    return re.sub(r"[^a-z0-9]+", " ", s).strip()


def brand_match(label: str | None, package: str | None, brands: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, str | None, str | None]:
    """First brand whose keyword appears in the label (whole words) or package segments (c6). Package
    segments must equal the keyword; keywords of >= 6 characters may also appear inside a segment;
    'exact' keywords (short or common words) never match inside other words."""
    lab = f" {fold(label)} "
    segs = [s for s in (package or "").lower().split(".") if s]
    for b in brands:
        for kw, exact in [(k, False) for k in b.get("keywords", [])] + [(k, True) for k in b.get("exact", [])]:
            k = fold(kw)
            if not k:
                continue
            compact = k.replace(" ", "")
            if f" {k} " in lab:
                return b, "label", kw
            if compact in segs or (not exact and len(compact) >= 6 and any(compact in s for s in segs)):
                return b, "package", kw
        if package and package.lower() in (p.lower() for p in b.get("packages", [])):
            return b, "package", package
    return None, None, None


IMPERSONATION_CRITERIA = {
    "brand_impersonation": "the label or package uses a protected brand AND none of the APK signing certificates is an official one of that brand",
    "protected_brand_cert_unknown": "the label or package uses a protected brand but no official certificate is known for it (no verdict)",
    "official_certificate_matches": "the signing certificate equals an official reference certificate of the brand",
}


def impersonation_check(label: str | None, package: str | None, cert_sha256s: list[str], brands: list[dict[str, Any]],
                        references: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    """c6/c7. references: {brand_name: {'sha256': [...], 'source': ...}}. No reference -> 'protected brand
    used, official certificate unknown' (no verdict)."""
    brand, where, kw = brand_match(label, package, brands)
    if brand is None:
        return None
    ref = references.get(brand["name"]) or next((references[k] for k in brand.get("ref_keys", ()) if k in references), {})
    official = {h.lower().replace(":", "") for h in ref.get("sha256", []) if isinstance(h, str)}
    mine = {h.lower().replace(":", "") for h in cert_sha256s}
    if not official:
        return fact("protected_brand_cert_unknown", "low", f"Protected brand used ({brand['name']}), official certificate unknown",
                    confidence="possible", criterion=IMPERSONATION_CRITERIA["protected_brand_cert_unknown"], tags=["brand_abuse"],
                    description=f"Matched in the {where} ('{clean_text(kw, 64)}'); no official certificate is recorded for this brand, so no "
                                "impersonation verdict is given.", brand=brand["name"], matched_in=where, source=brand.get("source"))
    if mine & official:
        return fact("official_certificate_matches", "info", f"{brand['name']}: signing certificate matches the official one",
                    confidence="probable", criterion=IMPERSONATION_CRITERIA["official_certificate_matches"],
                    description="Certificate digest equality only: signatures are not verified.", brand=brand["name"], reference=ref.get("source"))
    return fact("brand_impersonation", "high", f"Impersonation: {brand['name']} brand with a non-official signing certificate",
                confidence="probable", criterion=IMPERSONATION_CRITERIA["brand_impersonation"], tags=["brand_abuse", "suspicious"],
                description=f"Matched in the {where} ('{clean_text(kw, 64)}'); the app is signed with {', '.join(sorted(mine)) or 'no certificate'}, "
                            f"not with an official certificate ({ref.get('source') or 'reference'}).",
                brand=brand["name"], reference=ref.get("source"), app_certificates=sorted(mine))


# ======================================================================================== assetlinks.json (references)


def assetlinks_marker(status: int, content_type: str, body: bytes | str) -> str | None:
    """Short reason when an assetlinks.json answer is not a usable statement list, else None."""
    b = body.lstrip()[:2048] if isinstance(body, (bytes, bytearray)) else (body or "").encode()[:2048]
    low = b.lower()
    if status in (301, 302, 303, 307, 308):
        return "redirect_not_followed"
    if status == 404:
        return "not_found"
    if status == 429:
        return "rate_limited"
    if status in (401, 403) and (b"cf-chl" in low or b"just a moment" in low or b"attention required" in low):
        return "challenge"
    if status and status >= 400:
        return f"http_{status}"
    if b"cf-chl" in low or b"<title>just a moment" in low:
        return "challenge"
    if low[:1] == b"<" or "html" in (content_type or "").lower():
        return "html_in_200"
    if not b:
        return "empty_body"
    return None


_FP_RX = re.compile(r"(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{64}")


def parse_assetlinks(body: bytes | str, *, status: int = 200, content_type: str = "application/json") -> dict[str, Any]:
    """assetlinks.json (archived copy or the future LIGHT fetch) -> {'ok', 'marker', 'statements':
    [{'relations', 'namespace', 'package', 'sha256', 'site'}]}; fingerprints lower-case hex without colons."""
    res: dict[str, Any] = {"ok": False, "marker": assetlinks_marker(status, content_type, body), "statements": []}
    if res["marker"]:
        return res
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        res["marker"] = "malformed_json"
        return res
    if not isinstance(data, list):
        res["marker"] = "not_a_statement_list"
        return res
    for st in data[:5000]:
        if not isinstance(st, dict):
            continue
        t = st.get("target") if isinstance(st.get("target"), dict) else {}
        fps = [f.lower().replace(":", "") for f in t.get("sha256_cert_fingerprints", []) if isinstance(f, str) and _FP_RX.fullmatch(f)]
        res["statements"].append({"relations": [r for r in st.get("relation", []) if isinstance(r, str)] if isinstance(st.get("relation"), list) else [],
                                  "namespace": t.get("namespace"), "package": t.get("package_name"), "sha256": fps, "site": t.get("site")})
    res["ok"] = True
    if not res["statements"]:
        res["marker"] = "empty"
    return res


def assetlinks_reference(parsed: dict[str, Any], package: str | None = None) -> list[str]:
    """Official certificate fingerprints for one package (or every android_app target) of a parsed file."""
    out: set[str] = set()
    for st in parsed.get("statements", []):
        if st["namespace"] == "android_app" and (package is None or st["package"] == package):
            out.update(st["sha256"])
    return sorted(out)


# ======================================================================================== the analysis driver

_HEX64 = re.compile(r"[0-9a-f]{64}")


def classify_embedded_host(host: str) -> str | None:
    """The SDK-noise class of an embedded host ('firebase', 'schema', ...) or None (= hostile pivot)."""
    h = (host or "").lower().strip(".")
    for cls, suffixes in profiles()["sdk_noise"].items():
        for s in suffixes:
            if h == s or h.endswith("." + s):
                return cls
    return None


def _core_noise(etype: T, value: str) -> str | None:
    """P169 warninglists and core noise lists (applied when present; never raised)."""
    ent = Entity.try_make(etype, value)
    if ent is None:
        return "invalid"
    try:
        lists = _noise.warninglists(ent)
        if lists:
            return f"warninglist:{lists[0]}"
        if _noise.is_noise(ent):
            return f"noise:{_noise.noise_kind(ent) or 'core'}"
    except Exception:  # noqa: BLE001 - a noise-list problem never breaks the triage
        return None
    return None


def analyse_apk(data: bytes, *, budget: Budget | None = None, check: Any = None) -> dict[str, Any]:
    """P364 driver over the safe ZIP reader: manifest, label, permissions, components, signing
    certificates (v1 PKCS#7 + v2/v3 block), embedded URLs/domains/IPs (noise-classified), native libs,
    packer hints, anomalies. Pure: never installs, emulates or executes anything (c1)."""
    budget = budget or Budget()
    z = zip_scan(data)
    res: dict[str, Any] = {"format": "apk", "zip_anomalies": list(z["anomalies"]), "manifest": None, "certificates": {},
                           "iocs": {"urls": [], "ipv4": [], "hosts": []}, "noise_hosts": {}, "native_libs": [], "packer_hints": [],
                           "dynamic_code": [], "refused": [], "signing_other_ids": [], "signing_errors": [], "entries": len(z["entries"])}
    by_name: dict[str, list[dict[str, Any]]] = {}
    for e in z["entries"]:
        by_name.setdefault(e["name"], []).append(e)
    dups = sorted(n for n, v in by_name.items() if len(v) > 1)
    if dups:
        res["duplicates"] = dups[:50]

    def read(name: str, cap: int) -> bytes | None:
        es = by_name.get(name)
        if not es:
            return None
        e = es[0]  # Android's resolver uses the first central-directory entry
        try:
            out = zip_read(data, e, max_out=cap, ignore_encryption_flag=True, budget=budget)
        except ArchiveLimit as exc:
            res["refused"].append({"member": name, "reason": exc.args[0]})
            return None
        if e["encrypted"]:
            res["zip_anomalies"].append("fake_encryption_flag")
        return out

    resolve: dict[int, dict[str, Any]] = {}
    gstrings: list[str] = []
    arsc = read("resources.arsc", 64 << 20)
    if arsc:
        a = arsc_strings(arsc)
        resolve, gstrings = a["resolve"], a["global_strings"]
    man = read("AndroidManifest.xml", 8 << 20)
    if man:
        try:
            dec = axml_or_text(man)
            res["manifest"] = manifest_summary(dec["elements"], resolve)
            res["manifest"]["anomalies"] = dec["anomalies"]
        except UnsafeXML as exc:
            res["refused"].append({"member": "AndroidManifest.xml", "reason": f"unsafe_xml:{exc.args[0]}"})
        except ValueError:
            res["refused"].append({"member": "AndroidManifest.xml", "reason": "malformed_xml"})
    for name in by_name:
        up = name.upper()
        if up.startswith("META-INF/") and up.endswith((".RSA", ".DSA", ".EC")) and len(res["certificates"].get("v1", [])) < 10:
            blob = read(name, 1 << 20)
            if blob:
                try:
                    certs = [x509_summary(c) for c in pkcs7_certificates(blob)]
                    for c in certs:
                        c.pop("spki_der", None)
                    res["certificates"].setdefault("v1", []).append({"file": name, "certificates": certs})
                except DERError as exc:
                    res["signing_errors"].append(f"v1:{clean_text(name, 64)}:{exc}")
    if z["apk_sig_block"]:
        sb = apk_signing_block(data, z["apk_sig_block"])
        for scheme, signers in sb["schemes"].items():
            res["certificates"][scheme] = signers
        res["signing_other_ids"] = sb["other_ids"]
        res["signing_errors"] += sb["errors"]
    shas = sorted({c["sha256"] for s in res["certificates"].values() for signer in s for c in signer["certificates"]})
    res["certificate_sha256"] = shas
    v1 = {c["sha256"] for s in res["certificates"].get("v1", []) for c in s["certificates"]}
    v2 = {c["sha256"] for k in ("v2", "v3", "v3.1") for s in res["certificates"].get(k, []) for c in s["certificates"]}
    res["signing_consistent"] = not (v1 and v2) or bool(v1 & v2)
    strings: list[str] = []
    dex_total = 0
    for name in sorted(n for n in by_name if re.fullmatch(r"classes\d{0,4}\.dex", n))[:64]:
        if check is not None:
            check()
        blob = read(name, DEX_MAX_BYTES)
        if not blob:
            continue
        dex_total += len(blob)
        try:
            strings += dex_strings(blob, max_strings=max(0, LIMITS["dex_max_strings"] - len(strings)))
        except ValueError as exc:
            res["refused"].append({"member": name, "reason": str(exc)})
    strings += gstrings[:100_000]
    _classify_iocs(res, extract_iocs("\n".join(strings), max_items=500))
    hints = profiles()["packer_hints"]
    for n in by_name:
        low = n.lower()
        if low.startswith("lib/") and low.endswith(".so"):
            if len(res["native_libs"]) < 200:
                res["native_libs"].append(n)
            res["packer_hints"] += [v for k, v in hints.items() if k in low.rsplit("/", 1)[-1]]
        if low.startswith("assets/") and low.endswith((".dex", ".jar", ".apk", ".zip", ".so")) and len(res["dynamic_code"]) < 100:
            res["dynamic_code"].append(n)
    res["packer_hints"] = sorted(set(res["packer_hints"]))
    res["strings_scanned"] = len(strings)
    res["dex_bytes"] = dex_total
    res["zip_anomalies"] = sorted(set(res["zip_anomalies"]))
    return res


def _classify_iocs(res: dict[str, Any], iocs: dict[str, list[str]]) -> None:
    noise: dict[str, set[str]] = {}
    for u in iocs["urls"]:
        try:
            host = (urllib.parse.urlsplit(u).hostname or "").lower()
        except ValueError:
            host = ""
        cls = classify_embedded_host(host) or (_core_noise(T.URL, u) if host else "invalid")
        if cls:
            noise.setdefault(cls, set()).add(host or u[:80])
        else:
            res["iocs"]["urls"].append(u)
    for h in iocs["hosts"]:
        cls = classify_embedded_host(h) or _core_noise(T.DOMAIN, h)
        if cls:
            noise.setdefault(cls, set()).add(h)
        else:
            res["iocs"]["hosts"].append(h)
    res["iocs"]["non_routable_ipv4"] = [ip for ip in iocs["ipv4"] if non_routable(ip)][:50]
    for ip in iocs["ipv4"]:
        if non_routable(ip):
            continue
        cls = _core_noise(T.IPV4, ip)
        if cls:
            noise.setdefault(cls, set()).add(ip)
        else:
            res["iocs"]["ipv4"].append(ip)
    res["noise_hosts"] = {k: sorted(v)[:50] for k, v in noise.items()}


CRITERIA = {
    "apk_debuggable": "android:debuggable=true in the manifest",
    "debug_certificate": "a signing certificate whose subject is 'CN=Android Debug'",
    "signing_block_inconsistent": "a v2/v3 signer public key differs from its own certificate key (consistency check, signatures not verified)",
    "signing_schemes_disagree": "the v1 and v2/v3 certificates differ",
    "zip_anti_analysis": "malformed-zip tricks seen by the safe reader (duplicates, overlaps, fake encryption, bad central directory...)",
    "member_refused": "the safe reader refused a member (limit, ratio or corruption)",
    "packer_hint": "native library names of known Android packers",
    "dynamic_code_payload": "code-like files (dex/jar/apk/so) under assets/: dynamic loading candidates",
    "unsigned_apk": "no v1, v2 or v3 signature was found",
}


def apk_findings_and_pivots(res: dict[str, Any], *, brands: list[dict[str, Any]], references: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Map analyse_apk output onto findings and pivots (certificate SHA-256 = code_signing_cert pivot, P333)."""
    out_f: list[dict[str, Any]] = []
    pv: list[dict[str, Any]] = []
    m = res.get("manifest") or {}
    if m:
        bp = banker_profile(m)
        if bp:
            out_f.append(bp)
        imp = impersonation_check(m.get("label"), m.get("package"), res.get("certificate_sha256", []), brands, references)
        if imp:
            out_f.append(imp)
        if m.get("debuggable"):
            out_f.append(fact("apk_debuggable", "low", "Debuggable build (android:debuggable=true)", confidence="confirmed",
                              criterion=CRITERIA["apk_debuggable"]))
    debug_seen = mismatch_seen = False
    for scheme in res.get("certificates", {}).values():
        for signer in scheme:
            for c in signer["certificates"]:
                if "CN=Android Debug" in (c.get("subject") or "") and not debug_seen:
                    debug_seen = True
                    out_f.append(fact("debug_certificate", "low", "Signed with an Android debug certificate", confidence="confirmed",
                                      criterion=CRITERIA["debug_certificate"]))
                if c.get("public_key_matches_certificate") is False and not mismatch_seen:
                    mismatch_seen = True
                    out_f.append(fact("signing_block_inconsistent", "medium", "v2/v3 signer public key does not match its certificate",
                                      confidence="probable", criterion=CRITERIA["signing_block_inconsistent"], tags=["suspicious"]))
    if not res.get("signing_consistent", True):
        out_f.append(fact("signing_schemes_disagree", "medium", "v1 and v2/v3 signing certificates differ", confidence="probable",
                          criterion=CRITERIA["signing_schemes_disagree"], tags=["suspicious"]))
    if not res.get("certificate_sha256"):
        out_f.append(fact("unsigned_apk", "info", "No APK signature found (Android refuses to install it)", confidence="probable",
                          criterion=CRITERIA["unsigned_apk"]))
    bad = [a for a in res.get("zip_anomalies", []) if a in ("duplicate_name", "local_name_mismatch", "overlapping_entries", "fake_encryption_flag",
                                                             "central_directory_unreadable", "cd_offset_mismatch", "local_method_mismatch")]
    if bad:
        out_f.append(fact("zip_anti_analysis", "medium", "Malformed-zip anti-analysis tricks", confidence="probable",
                          criterion=CRITERIA["zip_anti_analysis"], tags=["suspicious"], description=", ".join(bad), anomalies=bad))
    if res.get("refused"):
        out_f.append(fact("member_refused", "medium", "Members not read (limits or corruption)", confidence="confirmed",
                          criterion=CRITERIA["member_refused"],
                          description=", ".join(f"{clean_text(r['member'], 64)} ({r['reason']})" for r in res["refused"][:5]), refused=res["refused"][:20]))
    if res.get("packer_hints"):
        out_f.append(fact("packer_hint", "info", "Packer hints", confidence="possible", criterion=CRITERIA["packer_hint"],
                          description=", ".join(res["packer_hints"])))
    if res.get("dynamic_code"):
        out_f.append(fact("dynamic_code_payload", "low", "Code-like assets (dynamic loading candidates)", confidence="possible",
                          criterion=CRITERIA["dynamic_code_payload"], description=", ".join(clean_text(n, 80) or "" for n in res["dynamic_code"][:5])))
    for sha in res.get("certificate_sha256", []):
        if _HEX64.fullmatch(sha):
            pv.append({"type": T.CODE_SIGNING_CERT, "value": sha, "relation": "signing_certificate"})
    for u in res["iocs"]["urls"]:
        pv.append({"type": T.URL, "value": u, "relation": "extracted_from"})
    for h in res["iocs"]["hosts"]:
        pv.append({"type": T.DOMAIN, "value": h, "relation": "extracted_from"})
    for ip in res["iocs"]["ipv4"]:
        pv.append({"type": T.IPV4, "value": ip, "relation": "extracted_from"})
    if m.get("package"):
        pv.append({"type": T.KEYWORD, "value": m["package"], "relation": "android_package"})
    return out_f, pv


# ======================================================================================== the module


#: registrable-domain labels of BCB-verified domains that are ordinary words, not one institution's brand
#: (P360 feed): never matched on their own
P360_GENERIC_LABELS = frozenset({
    "banco", "bank", "banking", "conta", "contas", "credito", "cartao", "cartoes", "pagamento", "pagamentos", "pagar", "pague",
    "pix", "financeira", "financeiro", "financas", "investimento", "investimentos", "invest", "seguro", "seguros", "digital",
    "online", "mobile", "app", "apps", "cooperativa", "consorcio", "consorcios", "cambio", "corretora", "capital", "credit",
    "money", "cash", "pay", "wallet", "carteira", "emprestimo", "emprestimos", "fintech", "brasil", "nacional", "central",
})
P360_MIN_LABEL = 4  # 'bb', 'cef', 'c6' collide with everyday words: the curated list covers them with exact keywords
_P360_MEMO: dict[str, Any] = {}


def p360_brands(ctx: Any, known: set[str] | None = None) -> list[dict[str, Any]]:
    """c6 'BCB-protected brand (P360)': one brand per registrable domain of the BCB DominiosVerificados
    list, read from P360's local copy through ``ctx.data`` (cited in the result; never downloaded during
    a run: ``[]`` until ``v3lum data update`` installed it). Labels shorter than 4 characters, generic
    words and labels already covered by the curated list or org_profile are skipped."""
    if _p360 is None:
        return []
    try:
        index = _p360.load_bcb(ctx.data, sedes=False)
    except (DatasetError, OSError, ValueError, KeyError, TypeError, AttributeError):  # a broken copy never breaks the triage
        return []
    if not getattr(index, "dominios", False):
        return []
    signature = tuple((str(m.get("name")), str(m.get("sha256"))) for m in getattr(index, "datasets", ()) or ())
    hit = _P360_MEMO.get("brands")
    if hit is not None and hit[0] == signature and signature:
        raw = hit[1]
    else:
        raw = []
        for b in _p360.protected_brands(index):
            label = fold(b.get("brand_label")).replace(" ", "")
            if len(label) < P360_MIN_LABEL or label in P360_GENERIC_LABELS or label.isdigit():
                continue
            names = [clean_text(n, 80) for n in b.get("names") or [] if isinstance(n, str)]
            raw.append({"name": f"{names[0]} ({b['registrable_domain']})" if names else b["registrable_domain"],
                        "keywords": [label] if len(label) >= 6 else [], "exact": [label] if len(label) < 6 else [], "packages": [],
                        "source": "P360 BCB DominiosVerificados", "ref_keys": [b["registrable_domain"]], "label": label})
        _P360_MEMO["brands"] = (signature, raw)
    skip = known or set()
    return [b for b in raw if b["label"] not in skip]


def brands_and_references(ctx: Any) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Protected brands and official certificates: org_profile, the curated dated list, P360's BCB-verified
    institution domains (local copy), setting apk_triage_reference_certs (analyst-supplied, keyed by brand
    name or registrable domain). No request is ever made (c6/c7)."""
    brands: list[dict[str, Any]] = []
    refs: dict[str, dict[str, Any]] = {}
    org = getattr(ctx, "org", None)
    if org is not None and not getattr(org, "is_empty", True):
        terms = [t for t in org.brand_terms() if len(t) >= 3]
        app_ids = list(getattr(org, "app_ids", []) or [])
        packages = [a.value for a in app_ids if a.kind.lower() in ("android_package", "android_app")]
        certs = [a.value.lower().replace(":", "") for a in app_ids if a.kind.lower() in ("android_cert_sha256", "android_signing_cert_sha256")]
        if terms or packages:
            brands.append({"name": "organisation brand (org_profile)", "keywords": [t for t in terms if len(t) >= 6],
                           "exact": [t for t in terms if len(t) < 6], "packages": packages, "source": "org_profile"})
            if certs:
                refs["organisation brand (org_profile)"] = {"sha256": certs, "source": "org_profile app_ids"}
    curated = curated_references()
    for app in curated.get("apps", []):
        brands.append({"name": app["brand"], "keywords": app.get("keywords", []), "exact": app.get("exact", []),
                       "packages": app.get("packages", []), "source": f"data/apk_triage/br_bank_app_certs.json@{curated.get('checked_at')}"})
        if app.get("sha256"):
            refs[app["brand"]] = {"sha256": list(app["sha256"]), "source": f"br_bank_app_certs.json@{app.get('checked_at') or curated.get('checked_at')}"}
    known = {fold(k).replace(" ", "") for b in brands for k in [*b.get("keywords", []), *b.get("exact", [])]}
    brands += p360_brands(ctx, known)
    supplied = ctx.setting("apk_triage_reference_certs") or {}
    if isinstance(supplied, dict):
        for brand, values in supplied.items():
            vals = [str(v).lower().replace(":", "") for v in (values if isinstance(values, list) else [values]) if isinstance(v, str)]
            vals = [v for v in vals if _HEX64.fullmatch(v)]
            if vals:
                entry = refs.setdefault(str(brand), {"sha256": [], "source": "setting apk_triage_reference_certs"})
                entry["sha256"] = sorted(set(entry["sha256"]) | set(vals))
    return brands, refs


_PIVOT_NOTES = {
    "signing_certificate": "SHA-256 of the APK signing certificate (signature not verified): code-signing pivot (P333)",
    "extracted_from": "embedded in the APK code/resources: hostile candidate for passive modules only, never contacted",
    "android_package": "Android package name (analyst selection)",
}


@register
class ApkTriage(Module):
    name = "apk_triage"
    title = "Android APK static triage"
    description = (
        "Parses a local APK offline (own AXML/ARSC/DEX/signing-block parser on the safe ZIP reader): package and label, "
        "permissions, exported components, signing-certificate SHA-256, embedded URLs/domains/IPs, a Brazilian-banker "
        "permission profile and brand impersonation against official certificates. Never installed or executed."
    )
    category = "file_analysis"
    accepts = {T.FILE}
    produces = {T.CODE_SIGNING_CERT, T.DOMAIN, T.URL, T.IPV4, T.KEYWORD}
    tags = {"offline"}
    reference = "https://source.android.com/docs/security/features/apksigning"
    notice = ("Offline static parsing only: APKs are never installed, emulated or executed, embedded hosts are never contacted and "
              "signatures are not verified ('signed, not verified'). The banker profile is a heuristic, never a malware verdict.")
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.2
    timeout = 60.0
    max_pivots = 300
    default_enabled = True
    settings = {
        "apk_triage_reference_certs": SettingSpec({}, "apk_triage: analyst-supplied official app certificates {brand: [sha256, ...]} "
                                                      "(e.g. from Digital Asset Links results or an archived assetlinks.json; P364 c6)"),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return entity.type is T.FILE

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        try:
            sn = sniff_path(entity.value)
        except FileRefused as exc:
            return res.mark("error" if exc.kind == "unreadable" else "skipped", exc.reason,
                            reason_code="error" if exc.kind == "unreadable" else "not_applicable")
        if self.name not in sn["routes"]:
            return res.mark("skipped", f"not an Android package ({sn['description']})", reason_code="not_applicable")
        if sn["kind"] != "apk":
            return res.mark("skipped", f"{sn['description']}: only APK files are parsed in this build (AAB/bare DEX: backlog)",
                            reason_code="not_applicable")
        try:
            data, size = read_capped(entity.value, LIMITS["max_input"])
        except FileRefused as exc:
            return res.mark("error", exc.reason)
        if size > len(data):
            return res.mark("error", f"APK larger than the {LIMITS['max_input']} byte input cap: not parsed")
        analysis = analyse_apk(data)
        brands, refs = brands_and_references(ctx)
        findings, pivots = apk_findings_and_pivots(analysis, brands=brands, references=refs)
        self._report(res, sn, analysis, findings, pivots)
        if not (analysis["manifest"] or {}).get("package") and not analysis["certificate_sha256"]:
            return res.mark("error", "could not parse the APK (no readable manifest or signature): "
                                     + (", ".join(analysis["zip_anomalies"][:3]) or "unreadable structure"))
        return res

    def _report(self, res: ModuleResult, sn: dict[str, Any], analysis: dict[str, Any], findings: list[dict[str, Any]],
                pivots: list[dict[str, Any]]) -> None:
        m = analysis.get("manifest") or {}
        res.attr("file_type", sn["description"])
        if m:
            res.attr("android_package", m.get("package"))
            exported = [{"type": c["type"], "name": c["name"], "implicit": c["exported_implicit"], "permission": c["permission"]}
                        for c in m.get("components", []) if c.get("exported")]
            res.attr("apk_manifest", cap_json({k: m.get(k) for k in ("package", "label", "version_code", "version_name", "min_sdk", "target_sdk",
                                                                     "debuggable", "allow_backup", "cleartext", "permissions",
                                                                     "declared_permissions", "traits", "anomalies")}
                                              | {"exported_components": exported[:200], "components": len(m.get("components", []))}, 128 * 1024))
        signing = {"schemes": sorted(analysis["certificates"]), "certificates": [], "consistent": analysis["signing_consistent"],
                   "verified": False, "other_block_ids": analysis["signing_other_ids"], "errors": analysis["signing_errors"][:10]}
        for scheme, signers in analysis["certificates"].items():
            for signer in signers:
                for c in signer["certificates"]:
                    signing["certificates"].append({"scheme": scheme, "sha256": c["sha256"], "subject": c.get("subject"), "issuer": c.get("issuer"),
                                                    "not_before": c.get("not_before"), "not_after": c.get("not_after"),
                                                    "self_signed": c.get("self_signed"), "key_matches": c.get("public_key_matches_certificate")})
        res.attr("apk_signing", cap_json(signing, 64 * 1024))
        res.attr("apk_contents", cap_json({"entries": analysis["entries"], "native_libs": analysis["native_libs"][:100],
                                           "packer_hints": analysis["packer_hints"], "dynamic_code": analysis["dynamic_code"][:50],
                                           "dex_bytes": analysis["dex_bytes"], "strings_scanned": analysis["strings_scanned"],
                                           "noise_hosts": analysis["noise_hosts"], "non_routable_ipv4": analysis["iocs"].get("non_routable_ipv4"),
                                           "zip_anomalies": analysis["zip_anomalies"], "duplicates": analysis.get("duplicates")}, 128 * 1024))
        label = m.get("label") or "no label"
        res.finding(f"Android package: {m.get('package') or 'unknown'}", "info",
                    f"{label}; {len(m.get('permissions', []))} permission(s), "
                    f"{sum(1 for c in m.get('components', []) if c.get('exported'))} exported component(s); signed with "
                    f"{', '.join(signing['schemes']) or 'no scheme'} (signatures not verified); {len(analysis['iocs']['urls'])} URL(s), "
                    f"{len(analysis['iocs']['hosts'])} host(s), {len(analysis['iocs']['ipv4'])} IP(s) embedded.",
                    confidence="confirmed", data={"package": m.get("package"), "label": m.get("label"), "schemes": signing["schemes"]}, tags=["info"])
        emit_findings(res, findings)
        kept = 0
        for p in pivots:
            if kept >= self.max_pivots:
                break
            expand = p["type"] is not T.KEYWORD
            if res.pivot(p["type"], p["value"], p["relation"], confidence="confirmed", expand=expand,
                         note=_PIVOT_NOTES.get(p["relation"], "")) is not None:
                kept += 1
        res.raw = cap_json({"analysis": analysis})
