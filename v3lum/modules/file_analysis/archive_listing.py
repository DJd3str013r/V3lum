"""Archive and disk-image listing with bomb and depth limits (P365) - offline, disclosure 'none'.

Final conditions of P365 implemented here:

* c1 offline (ctx.http refuses every request), terms 'open', tier 'n/a', allowed at TLP:RED. Built on the
  single safe ZIP reader of ``file_type_sniff`` (shared with document_metadata and apk_triage) plus the
  listers below (tar through ``tarfile`` streaming over a capped decompressor, ISO 9660/Joliet, RAR4/5
  headers, CAB, 7z signature header, VHD/VHDX facts): listing by default, members are never executed.
* c2 limits: total uncompressed <= 500 MB (declared and actually inflated), ratio <= 100 (enforced while
  inflating, after a 64 KB grace window), members <= 10,000, nesting depth <= 3. Absolute paths, '..',
  drive letters, backslashes, control/RTLO characters, symlinks, hardlinks, devices/FIFOs and setuid
  bits are flagged and never extracted.
* c3 extraction only with the explicit setting ``archive_listing_extract``, into a fresh 0700 temporary
  directory (``tempfile.mkdtemp``) that is deleted when the run ends; only members of
  :func:`extraction_plan` are written (files 0600, never executable, no links, ``tarfile.data_filter``
  re-check), then hashed and sniffed from disk.
* c4 encrypted members are listed; they are decrypted only with the analyst password of setting
  ``archive_listing_password``, and the conventional sample passwords ('infected', 'malware') only with
  ``archive_listing_sample_passwords`` (one try each). Nothing is ever guessed or brute-forced.
* c5 licences (A6): rarfile is not used (own RAR header listing, no unrar, no decompression); py7zr
  (LGPL-2.1+) is an unmodified optional extra imported dynamically to list 7z members; pycdlib
  (LGPL-2.1) for UDF-only images is not wired in this build (INFO 'listing unavailable'). VHD/VHDX are
  reported, never mounted.
* c6 rule 3: stealer-log / leak bundles (>= 3 marker categories among member names: saved logins,
  browser sessions, form data, system info, wallets, messengers, cards, screenshots...) are listed only
  as masked names, sizes and counts: nothing is read, hashed, nested or extracted (infected-host IPs,
  e-mails, ids and machine names in member names are masked first, A4).
* c7 Mark-of-the-Web-defeating containers (ISO/IMG/VHD holding LNK/EXE/JS/HTA...) are suspicious;
  executables, scripts and double extensions inside are flagged; small members (<= 10 MB, at most 50
  per archive) are hashed in memory and emitted as sha256 pivots (relation 'contains'), each sniffed
  through file_type_sniff; hash lookups follow the case TLP (the core gate keeps them away at RED).
"""

from __future__ import annotations

import bz2
import datetime as _dt
import hashlib
import importlib
import io
import ipaddress
import lzma
import os
import re
import shutil
import stat
import struct
import tarfile
import tempfile
import zlib
from collections.abc import Callable
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import Cancelled, DeadlineExceeded
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, package_available, register
from v3lum.modules.file_analysis.file_type_sniff import (
    _IPV4_RX,
    ARCHIVE_EXTS,
    DOCUMENT_EXTS,
    EXECUTABLE_EXTS,
    EXECUTABLE_KINDS,
    IMAGE_EXTS,
    LIMITS,
    MEDIA_EXTS,
    RAR4_SIG,
    RAR5_SIG,
    SCRIPT_EXTS,
    SEVENZIP_SIG,
    ZIP_FAMILY,
    ArchiveLimit,
    FileRefused,
    cap_json,
    clean_text,
    dos_datetime,
    emit_findings,
    extension_findings,
    fact,
    filetime_to_iso,
    open_regular,
    read_capped,
    sniff,
    sniff_path,
    split_name,
    u32,
    zip_cd_entries_from_file,
    zip_member_chunks,
    zip_read,
    zip_scan,
)

#: in-memory read cap of an archive (larger files: ZIP central directory from the file, else the head only)
ARCHIVE_READ_CAP = 256 * 1024 * 1024
#: members listed in the archive_members attribute (the evidence keeps up to the JSON cap)
MEMBERS_SHOWN = 1000
SAMPLE_PASSWORDS = (b"infected", b"malware")

# ======================================================================================== member names

_DRIVE = re.compile(r"^[A-Za-z]:")


def member_name_flags(name: str, *, is_symlink: bool = False, is_hardlink: bool = False, is_device: bool = False,
                      link_target: str | None = None) -> list[str]:
    """Unsafe-name reasons for one member (c2): a member with any reason is never extracted."""
    reasons = []
    n = name.replace("\\", "/")
    if n.startswith("/"):
        reasons.append("absolute_path")
    if _DRIVE.match(n):
        reasons.append("drive_letter")
    if any(p == ".." for p in n.split("/")):
        reasons.append("parent_traversal")
    if "\\" in name:
        reasons.append("backslash_separator")
    if any(ord(c) < 0x20 for c in name):
        reasons.append("control_characters")
    if "\u202e" in name or "\u202d" in name:
        reasons.append("rtlo_character")
    if is_symlink:
        reasons.append("symlink")
    if is_hardlink:
        reasons.append("hardlink")
    if is_device:
        reasons.append("device_or_fifo")
    if link_target is not None:
        lt = link_target.replace("\\", "/")
        if lt.startswith("/") or _DRIVE.match(lt) or ".." in lt.split("/"):
            reasons.append("link_target_escapes")
    return reasons


# ======================================================================================== tar (streaming, capped)


class _CappedStream(io.RawIOBase):
    """File-like decompressing reader for tarfile streaming mode, with total and ratio caps."""

    def __init__(self, data: bytes, codec: str | None, cap: int, ratio: int, grace: int) -> None:
        super().__init__()
        self.src, self.pos, self.codec = data, 0, codec
        self.cap, self.ratio, self.grace = cap, ratio, grace
        self.total, self.buf, self.done = 0, b"", False
        self.d = self._new()

    def _new(self) -> Any:
        if self.codec == "gz":
            return zlib.decompressobj(31)
        if self.codec == "bz2":
            return bz2.BZ2Decompressor()
        if self.codec == "xz":
            return lzma.LZMADecompressor()
        return None

    def readable(self) -> bool:
        return True

    def _fill(self, want: int) -> None:
        if self.d is None:
            chunk = self.src[self.pos:self.pos + want]
            self.pos += len(chunk)
            self.done = not chunk
            self.buf += chunk
            return
        if self.codec == "gz":
            inp = self.d.unconsumed_tail or self.src[self.pos:self.pos + 65536]
            if not self.d.unconsumed_tail:
                self.pos += len(inp)
            chunk = self.d.decompress(inp, want)
            if self.d.eof:
                rest = self.d.unused_data
                if rest[:2] == b"\x1f\x8b":  # multi-member gzip
                    self.pos -= len(rest)
                    self.d = self._new()
                else:
                    self.done = not chunk
        else:
            if self.d.eof:
                self.done = True
                return
            if self.d.needs_input:
                inp = self.src[self.pos:self.pos + 65536]
                self.pos += len(inp)
            else:
                inp = b""
            chunk = self.d.decompress(inp, max_length=want)
        if not chunk and self.pos >= len(self.src) and (self.codec == "gz" or getattr(self.d, "needs_input", True)):
            self.done = True
        self.total += len(chunk)
        if self.total > self.cap:
            raise ArchiveLimit("total_cap")
        if self.total > self.grace and self.total > self.ratio * max(self.pos, 1):
            raise ArchiveLimit("ratio")
        self.buf += chunk

    def read(self, n: int | None = -1) -> bytes:
        n = (1 << 20) if n is None or n < 0 else n
        while len(self.buf) < n and not self.done:
            self._fill(max(n - len(self.buf), 65536))
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def readinto(self, b: Any) -> int:  # pragma: no cover - tarfile uses read()
        data = self.read(len(b))
        b[: len(data)] = data
        return len(data)


def _tar_kind(ti: tarfile.TarInfo) -> str:
    if ti.isdir():
        return "dir"
    if ti.issym():
        return "symlink"
    if ti.islnk():
        return "hardlink"
    if ti.ischr() or ti.isblk():
        return "device"
    if ti.isfifo():
        return "fifo"
    return "file" if ti.isreg() else "other"


def tar_list(data: bytes, *, codec: str | None = None, keep_small: int = 0, check: Callable[[], None] | None = None) -> dict[str, Any]:
    """List a (compressed) tar in streaming mode without extracting it.

    ``codec``: None | 'gz' | 'bz2' | 'xz'. ``keep_small=N`` keeps the bytes of up to N regular members of
    at most 10 MB in '_bytes' (memory only, for hashing). Owner names (uname/gname) are never returned.
    """
    cap, ratio, max_members = LIMITS["archive_total"], LIMITS["archive_ratio"], LIMITS["archive_members"]
    res: dict[str, Any] = {"ok": False, "entries": [], "anomalies": [], "stop": None, "declared_total": 0}
    stream = _CappedStream(data, codec, cap, ratio, LIMITS["ratio_grace"])
    try:
        tf = tarfile.open(fileobj=stream, mode="r|")  # noqa: SIM115 - a streaming reader, closed with the stream
        for ti in tf:
            if check is not None:
                check()
            if len(res["entries"]) >= max_members:
                res["stop"] = "member_cap"
                break
            kind = _tar_kind(ti)
            flags = member_name_flags(ti.name, is_symlink=ti.issym(), is_hardlink=ti.islnk(), is_device=kind in ("device", "fifo"),
                                      link_target=ti.linkname if (ti.issym() or ti.islnk()) else None)
            if ti.mode & 0o6000:
                flags.append("setuid_setgid")
            res["declared_total"] += ti.size if ti.isreg() else 0
            try:
                mtime = _dt.datetime.fromtimestamp(ti.mtime, _dt.timezone.utc).isoformat() if 0 <= ti.mtime < 2**33 else None
            except (OverflowError, OSError, ValueError):
                mtime = None
            ent = {"name": ti.name, "size": ti.size, "type": kind, "link_target": ti.linkname or None, "mode": oct(ti.mode),
                   "mtime": mtime, "flags": flags, "is_dir": ti.isdir(), "encrypted": False}
            res["entries"].append(ent)
            if keep_small and ti.isreg() and ti.size <= LIMITS["hash_member_max"] and not flags:
                fh = tf.extractfile(ti)  # in-memory read of the current stream member: nothing is written
                if fh is not None:
                    ent["_bytes"] = fh.read(LIMITS["hash_member_max"] + 1)
                    keep_small -= 1
            if res["declared_total"] > cap:
                res["stop"] = "total_cap"
                break
        res["ok"] = True
    except ArchiveLimit as exc:
        res["stop"] = exc.args[0]
        res["ok"] = bool(res["entries"])
    except (Cancelled, DeadlineExceeded):
        raise
    except Exception as exc:  # noqa: BLE001 - a malformed tar is reported, never fatal
        res["anomalies"].append(f"tar_error:{type(exc).__name__}")
        res["ok"] = bool(res["entries"])
    return res


# ======================================================================================== ISO 9660 / Joliet / UDF

ISO_SECTOR = 2048


def _iso_dirrec(data: bytes, pos: int, joliet: bool) -> tuple[dict[str, Any] | None, int]:
    ln = data[pos]
    if ln < 34 or pos + ln > len(data):
        return None, ln
    lba, size = u32(data, pos + 2), u32(data, pos + 10)
    flags = data[pos + 25]
    nlen = data[pos + 32]
    raw = data[pos + 33:pos + 33 + nlen]
    if raw in (b"\x00", b"\x01"):
        name = None
    else:
        name = raw.decode("utf-16-be", "replace") if joliet else raw.decode("latin-1")
        name = name.split(";")[0]
        if name.endswith(".") and not (flags & 0x02):
            name = name[:-1]
    y, mo, d, h, mi, s, _tz = struct.unpack_from("<BBBBBBb", data, pos + 18)
    try:
        when = _dt.datetime(1900 + y, mo, d, h, mi, s).isoformat() if mo else None
    except ValueError:
        when = None
    return {"name": name, "lba": lba, "size": size, "is_dir": bool(flags & 0x02), "hidden": bool(flags & 0x01),
            "multi_extent": bool(flags & 0x80), "mtime": when}, ln


def iso_volume_info(data: bytes) -> dict[str, Any]:
    """Volume descriptors (sector 16+): PVD, Joliet SVD, El Torito boot record, UDF recognition sequence."""
    info: dict[str, Any] = {"iso9660": False, "joliet": False, "udf": False, "el_torito": False, "volume_id": None, "pvd": None, "svd": None}
    for i in range(16, 16 + 64):
        off = i * ISO_SECTOR
        if off + ISO_SECTOR > len(data):
            break
        ident, vtype = data[off + 1:off + 6], data[off]
        if ident == b"CD001":
            if vtype == 1 and info["pvd"] is None:
                info.update(iso9660=True, pvd=off, volume_id=clean_text(data[off + 40:off + 72].decode("latin-1"), 32) or None)
            elif vtype == 2 and data[off + 88:off + 91] in (b"%/@", b"%/C", b"%/E"):
                info.update(joliet=True, svd=off)
                info["volume_id"] = clean_text(data[off + 40:off + 72].decode("utf-16-be", "replace"), 32) or info["volume_id"]
            elif vtype == 0 and data[off + 7:off + 30].startswith(b"EL TORITO SPECIFICATION"):
                info["el_torito"] = True
            continue
        if ident in (b"NSR02", b"NSR03"):
            info["udf"] = True
            continue
        if ident in (b"BEA01", b"BOOT2", b"CDW02"):
            continue
        break  # TEA01 or anything else ends the volume recognition area
    return info


def iso_list(data: bytes, *, max_depth: int = 16) -> dict[str, Any]:
    """List an ISO 9660 image (Joliet names preferred); never mounts. UDF-only images are reported as such."""
    max_entries = LIMITS["iso_max_entries"]
    vol = iso_volume_info(data)
    res: dict[str, Any] = {"ok": False, "entries": [], "anomalies": [], "volume": vol}
    if not vol["iso9660"]:
        res["anomalies"].append("udf_only_needs_extra" if vol["udf"] else "no_primary_volume_descriptor")
        return res
    if vol["udf"]:
        res["anomalies"].append("udf_bridge_view_may_differ")
    joliet = vol["joliet"]
    root, _ = _iso_dirrec(data, (vol["svd"] if joliet else vol["pvd"]) + 156, joliet)
    if root is None:
        res["anomalies"].append("bad_root_record")
        return res
    queue = [("", root["lba"], root["size"], 0)]
    seen: set[tuple[int, int]] = set()
    while queue and len(res["entries"]) < max_entries:
        path, lba, size, depth = queue.pop(0)
        if (lba, size) in seen:
            res["anomalies"].append("directory_loop")
            continue
        seen.add((lba, size))
        start, end = lba * ISO_SECTOR, lba * ISO_SECTOR + size
        if end > len(data) or size > 64 * 1024 * 1024:
            res["anomalies"].append("extent_outside_image")
            continue
        pos = start
        while pos < end and len(res["entries"]) < max_entries:
            if data[pos] == 0:  # padding to the next sector
                pos = (pos // ISO_SECTOR + 1) * ISO_SECTOR
                continue
            rec, ln = _iso_dirrec(data, pos, joliet)
            if rec is None:
                res["anomalies"].append("bad_directory_record")
                break
            pos += ln
            if rec["name"] is None:
                continue
            full = f"{path}/{rec['name']}" if path else rec["name"]
            if rec["lba"] * ISO_SECTOR + (0 if rec["is_dir"] else rec["size"]) > len(data):
                res["anomalies"].append("extent_outside_image")
            rec = dict(rec, name=full, flags=member_name_flags(rec["name"]), encrypted=False)
            res["entries"].append(rec)
            if rec["is_dir"]:
                if depth + 1 > max_depth:
                    res["anomalies"].append("depth_cap")
                else:
                    queue.append((full, rec["lba"], rec["size"], depth + 1))
    if len(res["entries"]) >= max_entries:
        res["anomalies"].append("member_cap_reached")
    res["ok"] = True
    res["anomalies"] = sorted(set(res["anomalies"]))
    return res


def iso_read(data: bytes, entry: dict[str, Any], *, max_out: int | None = None) -> bytes:
    """Bytes of one ISO file extent (in-memory hashing of small members)."""
    max_out = max_out or LIMITS["hash_member_max"]
    if entry["size"] > max_out:
        raise ArchiveLimit("size_cap")
    start = entry["lba"] * ISO_SECTOR
    out = data[start:start + entry["size"]]
    if len(out) < entry["size"]:
        raise ArchiveLimit("truncated_member")
    return out


# ======================================================================================== RAR 4/5 headers (own reader)


def _vint(b: bytes, pos: int) -> tuple[int, int]:
    val, shift = 0, 0
    for i in range(10):
        if pos + i >= len(b):
            raise ArchiveLimit("truncated_vint")
        c = b[pos + i]
        val |= (c & 0x7F) << shift
        shift += 7
        if not c & 0x80:
            return val, pos + i + 1
    raise ArchiveLimit("bad_vint")


def _rar4_unicode(std: bytes, enc: bytes) -> str:
    """Decode RAR 2.x-4.x 'encoded unicode' file names (flag 0x200)."""
    if not enc:
        return std.decode("latin-1")
    out: list[int] = []
    high = enc[0]
    pos, flagbits, flags = 1, 0, 0
    while pos < len(enc) and len(out) < 4096:
        if flagbits == 0:
            flags = enc[pos]
            pos += 1
            flagbits = 8
        flagbits -= 2
        op = (flags >> flagbits) & 3
        if pos >= len(enc):
            break
        if op == 0:
            out.append(enc[pos])
            pos += 1
        elif op == 1:
            out.append(enc[pos] | (high << 8))
            pos += 1
        elif op == 2:
            if pos + 1 >= len(enc):
                break
            out.append(enc[pos] | (enc[pos + 1] << 8))
            pos += 2
        else:
            n = enc[pos]
            pos += 1
            if n & 0x80:
                if pos >= len(enc):
                    break
                corr = enc[pos]
                pos += 1
                for _ in range((n & 0x7F) + 2):
                    i = len(out)
                    out.append(((std[i] + corr) & 0xFF) | (high << 8) if i < len(std) else 0)
            else:
                for _ in range(n + 2):
                    i = len(out)
                    out.append(std[i] if i < len(std) else 0)
    return "".join(chr(c) for c in out if c)


def rar_list(data: bytes) -> dict[str, Any]:
    """List RAR 4.x/5.x file headers without unpacking (c5: header listing only, no unrar extraction).

    With header encryption nothing beyond the flag can be listed (it needs the analyst password and an
    external tool)."""
    res: dict[str, Any] = {"ok": False, "version": None, "entries": [], "anomalies": [], "headers_encrypted": False, "solid": False,
                           "volume": False, "comment_present": False}
    try:
        if data[: len(RAR5_SIG)] == RAR5_SIG:
            res["version"] = 5
            _rar5_walk(data, res)
        elif data[: len(RAR4_SIG)] == RAR4_SIG:
            res["version"] = 4
            _rar4_walk(data, res)
        else:
            res["anomalies"].append("not_rar")
            return res
        res["ok"] = True
    except (ArchiveLimit, struct.error, IndexError, ValueError, OverflowError, OSError) as exc:
        res["anomalies"].append(f"rar_error:{exc.args[0] if exc.args else type(exc).__name__}")
        res["ok"] = bool(res["entries"]) or res["headers_encrypted"]
    return res


def _unix_time(v: int) -> str | None:
    try:
        return _dt.datetime.fromtimestamp(v, _dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _rar5_walk(data: bytes, res: dict[str, Any]) -> None:
    pos = len(RAR5_SIG)
    while pos + 7 <= len(data):
        if len(res["entries"]) >= LIMITS["archive_members"]:
            res["anomalies"].append("member_cap_reached")
            return
        crc = u32(data, pos)
        hsize, hstart = _vint(data, pos + 4)
        if hsize == 0 or hstart + hsize > len(data):
            raise ArchiveLimit("truncated_header")
        if (zlib.crc32(data[pos + 4:hstart + hsize]) & 0xFFFFFFFF) != crc:
            res["anomalies"].append("header_crc_mismatch")
        htype, p = _vint(data, hstart)
        hflags, p = _vint(data, p)
        extra_size = data_size = 0
        if hflags & 0x0001:
            extra_size, p = _vint(data, p)
        if hflags & 0x0002:
            data_size, p = _vint(data, p)
        body_end = hstart + hsize
        extra_area = data[body_end - extra_size:body_end] if extra_size else b""
        if htype == 1:  # main archive header
            aflags, p = _vint(data, p)
            res["volume"] = bool(aflags & 0x0001)
            res["solid"] = bool(aflags & 0x0004)
        elif htype == 4:  # archive encryption header: everything after it is encrypted
            res["headers_encrypted"] = True
            return
        elif htype in (2, 3):
            fflags, p = _vint(data, p)
            usize, p = _vint(data, p)
            _attrs, p = _vint(data, p)
            mtime = None
            if fflags & 0x0002:
                mtime = _unix_time(u32(data, p))
                p += 4
            if fflags & 0x0004:
                p += 4
            comp_info, p = _vint(data, p)
            host_os, p = _vint(data, p)
            nlen, p = _vint(data, p)
            name = data[p:p + nlen].decode("utf-8", "replace")
            if htype == 3:
                if name == "CMT":
                    res["comment_present"] = True
            else:
                e = {"name": name, "size": usize, "compressed_size": data_size, "is_dir": bool(fflags & 0x0001), "mtime": mtime,
                     "method": (comp_info >> 7) & 7, "solid": bool(comp_info & 0x40),
                     "host_os": {0: "windows", 1: "unix"}.get(host_os, str(host_os)), "encrypted": False, "link_type": None,
                     "link_target": None}
                _rar5_file_extra(extra_area, e)
                e["flags"] = member_name_flags(name, is_symlink=e["link_type"] in ("unix_symlink", "windows_symlink", "junction"),
                                               is_hardlink=e["link_type"] == "hardlink", link_target=e["link_target"])
                res["entries"].append(e)
        elif htype == 5:
            return
        pos = body_end + data_size


def _rar5_file_extra(extra: bytes, e: dict[str, Any]) -> None:
    pos = 0
    while pos < len(extra):
        size, p = _vint(extra, pos)
        end = p + size
        rtype, p = _vint(extra, p)
        if rtype == 0x01:
            e["encrypted"] = True
        elif rtype == 0x03 and e.get("mtime") is None:  # file time record: flags, then mtime first if 0x0002
            tflags, p = _vint(extra, p)
            if tflags & 0x0002:
                e["mtime"] = _unix_time(u32(extra, p)) if tflags & 0x0001 else filetime_to_iso(struct.unpack_from("<Q", extra, p)[0])
        elif rtype == 0x05:
            ltype, p = _vint(extra, p)
            _lflags, p = _vint(extra, p)
            nlen, p = _vint(extra, p)
            e["link_type"] = {1: "unix_symlink", 2: "windows_symlink", 3: "junction", 4: "hardlink", 5: "file_copy"}.get(ltype, str(ltype))
            e["link_target"] = extra[p:p + nlen].decode("utf-8", "replace")
        pos = max(end, pos + 1)


def _rar4_walk(data: bytes, res: dict[str, Any]) -> None:
    pos = len(RAR4_SIG)
    while pos + 7 <= len(data):
        if len(res["entries"]) >= LIMITS["archive_members"]:
            res["anomalies"].append("member_cap_reached")
            return
        hcrc, htype, hflags, hsize = struct.unpack_from("<HBHH", data, pos)
        if hsize < 7 or pos + hsize > len(data):
            raise ArchiveLimit("truncated_header")
        if (zlib.crc32(data[pos + 2:pos + hsize]) & 0xFFFF) != hcrc and htype != 0x7B:
            res["anomalies"].append("header_crc_mismatch")
        add = u32(data, pos + 7) if hflags & 0x8000 and htype != 0x74 else 0
        if htype == 0x73:
            res["headers_encrypted"] = bool(hflags & 0x0080)
            res["solid"] = bool(hflags & 0x0008)
            res["volume"] = bool(hflags & 0x0001)
            res["comment_present"] = bool(hflags & 0x0002)
            if res["headers_encrypted"]:
                return
        elif htype == 0x74:
            pack, unp, host, _fcrc, ftime, _ver, method, nsize, attr = struct.unpack_from("<IIBIIBBHI", data, pos + 7)
            p = pos + 32
            if hflags & 0x100:
                hp, hu = struct.unpack_from("<II", data, p)
                pack |= hp << 32
                unp |= hu << 32
                p += 8
            raw = data[p:p + nsize]
            if hflags & 0x200 and b"\x00" in raw:
                std, enc = raw.split(b"\x00", 1)
                name = _rar4_unicode(std, enc)
            else:  # Unix rar writes locale (UTF-8) bytes without the unicode flag; DOS/Windows use the OEM page
                try:
                    name = raw.decode("utf-8")
                except UnicodeDecodeError:
                    name = raw.decode("cp437" if host in (0, 2) else "latin-1", "replace")
            e = {"name": name, "size": unp, "compressed_size": pack, "is_dir": (hflags & 0xE0) == 0xE0,
                 "mtime": dos_datetime(ftime >> 16, ftime & 0xFFFF), "method": method - 0x30 if method >= 0x30 else method,
                 "host_os": {0: "msdos", 2: "windows", 3: "unix"}.get(host, str(host)), "encrypted": bool(hflags & 0x04),
                 "solid": bool(hflags & 0x10), "link_type": None, "link_target": None}
            if host == 3 and stat.S_ISLNK(attr):
                e["link_type"] = "unix_symlink"
            e["flags"] = member_name_flags(name, is_symlink=e["link_type"] is not None)
            res["entries"].append(e)
            add = pack
        elif htype == 0x75 or (htype == 0x7A and data[pos + 32:pos + 35] == b"CMT"):
            res["comment_present"] = True
            if htype == 0x7A:
                add = u32(data, pos + 7)
        elif htype == 0x7B:
            return
        pos += hsize + add


# ======================================================================================== CAB, 7z, VHD


def cab_list(data: bytes) -> dict[str, Any]:
    """Microsoft Cabinet CFFILE listing (names, sizes, attributes); no decompression."""
    res: dict[str, Any] = {"ok": False, "entries": [], "anomalies": []}
    if data[:4] != b"MSCF" or len(data) < 36:
        res["anomalies"].append("not_cab")
        return res
    cb, coff = u32(data, 8), u32(data, 16)
    nfolders, nfiles, _flags = struct.unpack_from("<HHH", data, 26)
    if cb != len(data):
        res["anomalies"].append("size_mismatch")
    pos = coff
    for _ in range(min(nfiles, LIMITS["archive_members"])):
        if pos + 16 > len(data):
            res["anomalies"].append("truncated")
            break
        size, _off, _folder, date, time_, attribs = struct.unpack_from("<IIHHHH", data, pos)
        end = data.find(b"\x00", pos + 16, pos + 16 + 512)
        if end == -1:
            res["anomalies"].append("bad_name")
            break
        name = data[pos + 16:end].decode("utf-8" if attribs & 0x80 else "cp437", "replace")
        res["entries"].append({"name": name, "size": size, "mtime": dos_datetime(date, time_), "is_dir": False,
                               "hidden": bool(attribs & 0x02), "encrypted": False, "flags": member_name_flags(name)})
        pos = end + 1
    res["ok"] = True
    res["folders"] = nfolders
    return res


def sevenzip_header(data: bytes) -> dict[str, Any]:
    """7z signature-header facts (member listing needs the optional py7zr extra, c5)."""
    if data[: len(SEVENZIP_SIG)] != SEVENZIP_SIG or len(data) < 32:
        return {"ok": False}
    start_crc = u32(data, 8)
    nh_off, nh_size, _nh_crc = struct.unpack_from("<QQI", data, 12)
    nh = data[32 + nh_off:32 + nh_off + 1] if 32 + nh_off < len(data) else b""
    return {"ok": True, "version": f"{data[6]}.{data[7]}", "start_header_crc_ok": (zlib.crc32(data[12:32]) & 0xFFFFFFFF) == start_crc,
            "next_header_size": nh_size, "encoded_header": nh == b"\x17"}


def vhd_info(data: bytes) -> dict[str, Any] | None:
    """VHD/VHDX facts, never mounted (c5): disk type, size, creator application/OS."""
    if data[:8] == b"vhdxfile":
        creator = data[8:520].decode("utf-16-le", "replace").split("\x00")[0]
        return {"format": "vhdx", "creator": clean_text(creator, 128) or None}
    foot = data[:512] if data[:8] == b"conectix" else data[-512:]
    if foot[:8] != b"conectix" or len(foot) < 64:
        return None
    dtype = struct.unpack_from(">I", foot, 60)[0]
    return {"format": "vhd", "disk_type": {2: "fixed", 3: "dynamic", 4: "differencing"}.get(dtype, str(dtype)),
            "original_size": struct.unpack_from(">Q", foot, 40)[0], "creator_app": clean_text(foot[28:32].decode("latin-1"), 8),
            "creator_os": clean_text(foot[36:40].decode("latin-1"), 8)}


def list_7z_py7zr(data: bytes, password: bytes | None) -> dict[str, Any]:
    """7z member listing through the optional py7zr extra (LGPL-2.1+, imported dynamically, unmodified):
    headers only, nothing is extracted. Returns {'ok', 'entries', 'anomalies', 'headers_encrypted'}."""
    res: dict[str, Any] = {"ok": False, "entries": [], "anomalies": [], "headers_encrypted": False}
    try:
        py7zr = importlib.import_module("py7zr")
    except Exception:  # noqa: BLE001 - a broken optional package never breaks the listing
        res["anomalies"].append("listing_needs_extra:py7zr")
        return res
    try:
        pw = password.decode("utf-8", "replace") if password else None
        with py7zr.SevenZipFile(io.BytesIO(data), mode="r", password=pw) as z:
            infos = list(z.list())[: LIMITS["archive_members"]]
        for info in infos:
            name = str(getattr(info, "filename", "") or "")
            created = getattr(info, "creationtime", None)
            res["entries"].append({
                "name": name, "size": int(getattr(info, "uncompressed", 0) or 0), "compressed_size": getattr(info, "compressed", None),
                "is_dir": bool(getattr(info, "is_directory", False)), "encrypted": False,
                "mtime": created.isoformat() if hasattr(created, "isoformat") else None, "flags": member_name_flags(name),
            })
        res["ok"] = True
    except Exception as exc:  # noqa: BLE001 - PasswordRequired, Bad7zFile, unsupported filters...
        kind = type(exc).__name__
        if "password" in kind.lower():
            res["headers_encrypted"] = True
        res["anomalies"].append(f"py7zr_error:{kind}")
    return res


# ======================================================================================== rule 3 and name masking

#: P365 c6: stealer-log / leak bundle markers by member name (category names avoid credential words so
#: the result sanitizer keeps the counts)
STEALER_MARKERS: dict[str, tuple[str, ...]] = {
    "saved_logins": (r"(?:^|/)(?:all ?)?passwords?\.txt$", r"(?:^|/)passwords?/"),
    "browser_sessions": (r"(?:^|/)cookies?(?:/|\.txt$)",),
    "form_data": (r"(?:^|/)(?:important)?autofills?(?:/|\.txt$)",),
    "system_info": (r"(?:^|/)(?:system ?info(?:rmation)?|information|userinformation|user ?info)\.txt$",),
    "wallets": (r"(?:^|/)(?:crypto ?)?wallets?/", r"(?:^|/)(?:exodus|electrum|metamask|atomic|coinomi)/"),
    "messengers": (r"(?:^|/)(?:telegram|tdata)/", r"(?:^|/)discord(?:/|tokens?\.txt$)", r"(?:^|/)tokens?\.txt$"),
    "payment_cards": (r"(?:^|/)(?:credit ?cards?|cc)(?:/|\.txt$)",),
    "screenshots": (r"(?:^|/)screen(?:shot)?\.(?:jpe?g|png|bmp)$",),
    "browsers": (r"(?:^|/)browsers?/",),
    "domain_detects": (r"(?:^|/)domain ?detects?\.txt$",),
}
_STEALER_RX = {cat: [re.compile(p, re.I) for p in pats] for cat, pats in STEALER_MARKERS.items()}


def stealer_bundle_check(names: list[str], threshold: int = 3) -> dict[str, Any]:
    """c6 (rule 3): recognise infostealer log / leak bundles by member names only."""
    hits: dict[str, int] = {}
    for n in names:
        nn = n.replace("\\", "/")
        for cat, rxs in _STEALER_RX.items():
            if any(rx.search(nn) for rx in rxs):
                hits[cat] = hits.get(cat, 0) + 1
    return {"is_bundle": len(hits) >= threshold, "categories": hits}


_IPV6_CAND = re.compile(r"(?<![0-9A-Za-z:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Za-z:])")
_EMAIL_IN_NAME = re.compile(r"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}")
_GUID_IN_NAME = re.compile(r"\b[0-9A-Fa-f]{8}-?[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{12}\b")
_HEXID_IN_NAME = re.compile(r"\b[0-9A-Fa-f]{16,128}\b")
_HOSTNAME_IN_NAME = re.compile(r"\b(?:DESKTOP|LAPTOP|WIN|PC)-[A-Z0-9]{4,15}\b", re.I)


def _sub_ipv6(s: str) -> str:
    def repl(m: re.Match[str]) -> str:
        try:
            ipaddress.IPv6Address(m.group(0))
        except ValueError:
            return m.group(0)
        return "[ip]"

    return _IPV6_CAND.sub(repl, s)


def redact_member_name(name: str) -> str:
    """A4 inside rule-3 listings: infected-host IPs, e-mails, HWIDs/GUIDs and machine names in member
    names are masked before anything is shown, stored or exported."""
    s = _IPV4_RX.sub("[ip]", name)
    s = _sub_ipv6(s)
    s = _EMAIL_IN_NAME.sub("[email]", s)
    s = _GUID_IN_NAME.sub("[id]", s)
    s = _HEXID_IN_NAME.sub("[id]", s)
    return _HOSTNAME_IN_NAME.sub("[host]", s)


# ======================================================================================== analysis

MOTW_CONTAINERS = frozenset({"iso9660", "udf", "iso9660+udf", "vhd", "vhdx", "fat-image", "ntfs-image", "vmdk"})
MOTW_PAYLOAD_EXTS = frozenset({"lnk", "exe", "dll", "scr", "js", "jse", "vbs", "vbe", "hta", "wsf", "bat", "cmd", "ps1", "msi",
                               "cpl", "chm", "url", "settingcontent-ms", "library-ms", "one", "xll", "msc", "com", "pif", "jar",
                               "reg", "iqy", "sct"})
#: kinds descended into (nested containers); documents, apps and JARs are other modules' business
NESTED_KINDS = (ZIP_FAMILY | {"tar", "gzip", "bzip2", "xz", "rar4", "rar5", "cab", "7z", "iso9660", "iso9660+udf", "vhd", "vhdx"}) - {
    "apk", "aab", "jar", "ooxml-docx", "ooxml-docm", "ooxml-xlsx", "ooxml-xlsm", "ooxml-xlsb", "ooxml-pptx", "ooxml-pptm",
    "ooxml-vsdx", "epub", "odf-text", "odf-spreadsheet", "odf-presentation", "odf-graphics", "odf-other", "appx", "ipa", "xpi", "nupkg"}
LISTABLE_KINDS = ZIP_FAMILY | {"tar", "gzip", "bzip2", "xz", "iso9660", "iso9660+udf", "udf", "rar4", "rar5", "cab", "7z", "vhd", "vhdx"}

CRITERIA = {
    "stealer_log_bundle": ">= 3 infostealer-log marker categories among the member names (rule 3: listed as names, sizes and counts only)",
    "archive_total_cap": "declared uncompressed size above the 500 MB cap of P365 c2",
    "archive_member_cap": "more than 10,000 members (P365 c2 cap)",
    "decompression_bomb": "compression ratio above 100 or the total/size cap of P365 c2 reached while inflating",
    "member_not_read": "the safe archive reader refused the member (limit, encryption or corruption)",
    "listing_unavailable": "the format needs an optional extra that is not installed",
    "unsafe_member_path": "absolute, '..', drive-letter, link or device member names (P365 c2): never extracted",
    "double_extension": "an executable extension follows a document/image/media/archive extension in a member name",
    "executable_inside": "member names or content sniffed as executables or scripts",
    "motw_container": "ISO/IMG/VHD containers do not propagate Mark-of-the-Web to their contents (T1553.005)",
    "encrypted_members": "encryption flags in the member headers",
    "encrypted_headers": "the archive headers are encrypted (RAR/7z header encryption)",
    "winrar_trailing_space_trap": "a file and a folder share a trailing-space name: the CVE-2023-38831 lure shape",
    "archive_anomaly": "structural anomalies of the safe ZIP reader (duplicates, overlaps, local/central mismatch, unreadable central directory)",
    "nesting_depth_cap": "nested container beyond the depth-3 cap of P365 c2",
    "listing_partial": "the file is larger than the in-memory listing cap",
}


def _list_container(data: bytes, kind: str, *, password: bytes | None, check: Callable[[], None] | None) -> tuple[list[dict[str, Any]], dict[str, Any], str | None]:
    """Dispatch to the right lister -> (entries, meta, reader or None)."""
    if kind in ZIP_FAMILY:
        z = zip_scan(data)
        ents = [{"name": e["name"], "size": e["file_size"], "compressed_size": e["compressed_size"], "is_dir": e["is_dir"],
                 "encrypted": e["encrypted"], "encryption": e["encryption"], "aes_strength": e["aes_strength"], "mtime": e["mtime"],
                 "hidden": e["hidden"], "flags": member_name_flags(e["name"], is_symlink=e["is_symlink"]), "_zip": e}
                for e in z["entries"]]
        return ents, {"anomalies": z["anomalies"], "comment": clean_text(z["comment"], 256)}, "zip"
    if kind == "tar":
        t = tar_list(data, keep_small=LIMITS["hash_members_per_archive"], check=check)
        return t["entries"], {"anomalies": t["anomalies"], "stop": t["stop"]}, None
    if kind in ("gzip", "bzip2", "xz"):
        codec = {"gzip": "gz", "bzip2": "bz2", "xz": "xz"}[kind]
        t = tar_list(data, codec=codec, keep_small=LIMITS["hash_members_per_archive"], check=check)
        if t["entries"]:
            return t["entries"], {"anomalies": t["anomalies"], "stop": t["stop"], "inner": "tar"}, None
        return _single_stream(data, kind, codec)
    if kind in ("iso9660", "iso9660+udf", "udf"):
        r = iso_list(data)
        return r["entries"], {"anomalies": r["anomalies"], "volume": {k: v for k, v in r["volume"].items() if k not in ("pvd", "svd")}}, "iso"
    if kind in ("rar4", "rar5"):
        r = rar_list(data)
        return r["entries"], {k: r[k] for k in ("anomalies", "headers_encrypted", "solid", "volume", "comment_present", "version")}, None
    if kind == "cab":
        r = cab_list(data)
        return r["entries"], {"anomalies": r["anomalies"]}, None
    if kind == "7z":
        meta: dict[str, Any] = {"anomalies": [], "sevenzip": sevenzip_header(data)}
        if package_available("py7zr"):
            r = list_7z_py7zr(data, password)
            meta["anomalies"] += r["anomalies"]
            meta["headers_encrypted"] = r["headers_encrypted"]
            meta["lister"] = "py7zr"
            return r["entries"], meta, None
        meta["anomalies"].append("listing_needs_extra:py7zr")
        return [], meta, None
    if kind in ("vhd", "vhdx"):
        return [], {"anomalies": ["disk_image_not_mounted"], "disk": vhd_info(data)}, None
    return [], {"anomalies": [f"unsupported_container:{kind}"]}, None


def _single_stream(data: bytes, kind: str, codec: str) -> tuple[list[dict[str, Any]], dict[str, Any], str | None]:
    """A compressed single file (not a tar): size counted through the capped stream, small bodies kept."""
    stream = _CappedStream(data, codec, LIMITS["archive_total"], LIMITS["archive_ratio"], LIMITS["ratio_grace"])
    stop = None
    body: bytes | None = None
    try:
        body = stream.read(LIMITS["hash_member_max"] + 1)
        while not stream.done:  # count the rest without keeping it
            if not stream.read(1 << 20):
                break
    except ArchiveLimit as exc:
        body, stop = None, exc.args[0]
    except (zlib.error, lzma.LZMAError, OSError, EOFError, ValueError):
        body, stop = None, "corrupt_stream"
    name = None
    if kind == "gzip" and len(data) > 10 and data[3] & 0x08:
        end = data.find(b"\x00", 10, 10 + 1024)
        name = clean_text(data[10:end].decode("latin-1"), 260) if end != -1 else None
    keep = body if body is not None and len(body) <= LIMITS["hash_member_max"] else None
    entry = {"name": name or "(compressed stream)", "size": stream.total, "is_dir": False, "encrypted": False,
             "flags": member_name_flags(name or ""), "_bytes": keep}
    return [entry], {"anomalies": [], "stop": stop, "single_stream": True}, None


def _is_exec_name(exts: list[str]) -> bool:
    ext = exts[-1] if exts else None
    return ext in EXECUTABLE_EXTS or ext in SCRIPT_EXTS


def archive_analyse(data: bytes, *, name: str | None = None, kind: str | None = None, depth: int = 0, budget: dict[str, int] | None = None,
                    password: bytes | None = None, allow_sample_passwords: bool = False, hash_members: bool = True,
                    listing: tuple[list[dict[str, Any]], dict[str, Any], str | None] | None = None,
                    check: Callable[[], None] | None = None) -> dict[str, Any]:
    """List (never extract) with the c2 limits; flag unsafe names, encryption, executables/scripts/double
    extensions, MotW containers and stealer bundles (metadata only); descend into nested containers up to
    depth 3; hash small members in memory (<= 50 per archive). ``listing`` injects a pre-computed
    (entries, meta, reader) - e.g. a ZIP central directory read from a file above the in-memory cap.

    Returns ``{'kind', 'name', 'depth', 'meta', 'entries', 'counts', 'findings', 'pivots', 'nested',
    'stop', 'stealer_bundle'}``.
    """
    budget = budget if budget is not None else {"total": 0, "hashed": 0}
    if kind is None:
        kind = sniff(data[: LIMITS["sniff_head"]], size=len(data), name=name,
                     tail=data[-LIMITS["sniff_tail"]:] if len(data) > LIMITS["sniff_head"] else None)["kind"]
    entries, meta, reader = listing if listing is not None else _list_container(data, kind, password=password, check=check)
    findings: list[dict[str, Any]] = []
    pivots: list[dict[str, Any]] = []
    nested: list[dict[str, Any]] = []
    res: dict[str, Any] = {"kind": kind, "name": name, "depth": depth, "meta": meta, "entries": [], "counts": {}, "findings": findings,
                           "pivots": pivots, "nested": nested, "stop": meta.get("stop"), "stealer_bundle": False}
    names = [e["name"] for e in entries]
    stealer = stealer_bundle_check(names)
    res["stealer_bundle"] = stealer["is_bundle"]
    files = [e for e in entries if not e.get("is_dir")]
    declared = sum(int(e.get("size") or 0) for e in files)
    res["counts"] = {"members": len(entries), "files": len(files), "declared_total": declared,
                     "encrypted": sum(1 for e in entries if e.get("encrypted")), "unsafe_names": sum(1 for e in entries if e.get("flags"))}
    if stealer["is_bundle"]:  # rule 3: names, sizes and counts only; nothing read, hashed, nested or extracted
        res["entries"] = [{"name": redact_member_name(e["name"]), "size": e.get("size"), "is_dir": e.get("is_dir")} for e in entries]
        res["counts"]["stealer_categories"] = dict(stealer["categories"])
        findings.append(fact("stealer_log_bundle", "medium", "Archive looks like an infostealer log bundle (metadata only)",
                             confidence="probable", criterion=CRITERIA["stealer_log_bundle"], tags=["infostealer"],
                             description="Listed as masked member names, sizes and counts only: nothing was read, hashed, "
                                         "extracted or printed beyond member names (rule 3).",
                             categories=sorted(stealer["categories"])))
        return res
    if declared > LIMITS["archive_total"]:
        findings.append(fact("archive_total_cap", "medium", "Declared uncompressed size above the 500 MB cap", confidence="confirmed",
                             criterion=CRITERIA["archive_total_cap"], tags=["archive_bomb"],
                             description=f"{declared} bytes declared: members past the cap are not read.", declared_total=declared))
    if len(entries) >= LIMITS["archive_members"] or "member_cap_reached" in meta.get("anomalies", []):
        findings.append(fact("archive_member_cap", "medium", "More than 10,000 members: listing truncated", confidence="confirmed",
                             criterion=CRITERIA["archive_member_cap"], tags=["archive_bomb"]))
    passwords = ([password] if password else []) + (list(SAMPLE_PASSWORDS) if allow_sample_passwords else [])
    exe_inside: list[str] = []
    double_ext: list[str] = []
    motw_payload: list[str] = []
    for e in entries:
        if check is not None:
            check()
        nm = e["name"]
        pub = {k: v for k, v in e.items() if not k.startswith("_")}
        res["entries"].append(pub)
        if e.get("is_dir"):
            continue
        sp = split_name(nm)
        ext = sp["exts"][-1] if sp["exts"] else None
        if len(sp["exts"]) >= 2 and ext in EXECUTABLE_EXTS and sp["exts"][-2] in (DOCUMENT_EXTS | IMAGE_EXTS | MEDIA_EXTS | ARCHIVE_EXTS):
            double_ext.append(nm)
        elif _is_exec_name(sp["exts"]):
            exe_inside.append(nm)
        if ext in MOTW_PAYLOAD_EXTS:
            motw_payload.append(nm)
        size = int(e.get("size") or 0)
        csize = e.get("compressed_size")
        ratio = size / max(int(csize or 0), 1) if csize else 0
        if ratio > LIMITS["archive_ratio"] and size > LIMITS["ratio_grace"]:
            findings.append(fact("decompression_bomb", "medium", f"Possible decompression bomb: {clean_text(nm, 120)}", confidence="probable",
                                 criterion=CRITERIA["decompression_bomb"], tags=["archive_bomb"],
                                 description=f"Declared ratio {ratio:.0f} above {LIMITS['archive_ratio']}: the member was not read.", member=nm))
            continue
        body = _member_body(data, e, reader, budget, passwords, findings, hash_members=hash_members)
        if body is None:
            continue
        budget["total"] += len(body)
        budget["hashed"] += 1
        sha = hashlib.sha256(body).hexdigest()
        sn = sniff(body[: LIMITS["sniff_head"]], size=len(body), name=nm,
                   tail=body[-LIMITS["sniff_tail"]:] if len(body) > LIMITS["sniff_head"] else None)
        pub.update(sha256=sha, kind=sn["kind"])
        pivots.append({"type": T.SHA256, "value": sha, "relation": "contains", "member": nm, "size": len(body), "kind": sn["kind"]})
        for f in extension_findings(nm, sn):
            if f["code"] == "double_extension":
                continue  # reported once below for all members
            f["detail"]["member"] = nm
            f["title"] = f"{f['title']} (member {clean_text(nm, 80)})"
            findings.append(f)
        if sn["kind"] in EXECUTABLE_KINDS and nm not in exe_inside and nm not in double_ext:
            exe_inside.append(nm)
        if sn["kind"] in NESTED_KINDS:
            if depth + 1 > LIMITS["archive_depth"]:
                findings.append(fact("nesting_depth_cap", "info", f"Nested container beyond depth {LIMITS['archive_depth']} not listed",
                                     confidence="confirmed", criterion=CRITERIA["nesting_depth_cap"], member=nm))
            else:
                sub = archive_analyse(body, name=nm, kind=sn["kind"], depth=depth + 1, budget=budget, password=password,
                                      allow_sample_passwords=allow_sample_passwords, hash_members=hash_members, check=check)
                nested.append(sub)
                for f in sub["findings"]:
                    f = dict(f, detail=dict(f["detail"], nested_in=nm))
                    f["title"] = f"{f['title']} (inside {clean_text(nm, 60)})"
                    findings.append(f)
                pivots.extend(sub["pivots"])
    _container_findings(res, kind, meta, entries, exe_inside, double_ext, motw_payload, passwords)
    return res


def _member_body(data: bytes, e: dict[str, Any], reader: str | None, budget: dict[str, int], passwords: list[bytes],
                 findings: list[dict[str, Any]], *, hash_members: bool) -> bytes | None:
    """In-memory bytes of a small member (c7), or None (too big, link, encrypted without password, limit)."""
    size = int(e.get("size") or 0)
    linkish = set(e.get("flags") or []) & {"symlink", "hardlink", "device_or_fifo"}
    if not hash_members or size > LIMITS["hash_member_max"] or linkish or budget["hashed"] >= LIMITS["hash_members_per_archive"] \
            or budget["total"] + size > LIMITS["archive_total"]:
        return None
    nm = e["name"]
    try:
        if reader == "zip":
            zent = e["_zip"]
            if zent["encrypted"]:
                if zent["encryption"] != "zipcrypto" or not passwords:
                    return None
                for pw in passwords:
                    try:
                        return zip_read(data, zent, max_out=LIMITS["hash_member_max"], password=pw)
                    except ArchiveLimit as exc:
                        if exc.args[0] != "bad_password":
                            raise
                findings.append(fact("member_not_read", "low", f"Encrypted member not decrypted: {clean_text(nm, 120)}", confidence="confirmed",
                                     criterion=CRITERIA["member_not_read"], description="The supplied password(s) did not open it.", member=nm))
                return None
            return zip_read(data, zent, max_out=LIMITS["hash_member_max"])
        if reader == "iso":
            return iso_read(data, e)
        body = e.get("_bytes")
        return body if isinstance(body, bytes) and len(body) <= LIMITS["hash_member_max"] else None
    except ArchiveLimit as exc:
        reason = exc.args[0]
        findings.append(fact("member_not_read", "low", f"Member not read: {clean_text(nm, 120)} ({reason})", confidence="confirmed",
                             criterion=CRITERIA["member_not_read"], member=nm, reason=reason))
        if reason in ("ratio", "size_cap"):
            findings.append(fact("decompression_bomb", "medium", f"Possible decompression bomb: {clean_text(nm, 120)}", confidence="probable",
                                 criterion=CRITERIA["decompression_bomb"], tags=["archive_bomb"],
                                 description=f"Inflating stopped at the {reason} limit; the member was not read.", member=nm))
        return None


def _container_findings(res: dict[str, Any], kind: str, meta: dict[str, Any], entries: list[dict[str, Any]], exe_inside: list[str],
                        double_ext: list[str], motw_payload: list[str], passwords: list[bytes]) -> None:
    findings = res["findings"]
    if meta.get("stop") in ("ratio", "total_cap", "size_cap"):
        findings.append(fact("decompression_bomb", "medium", "Possible decompression bomb: compressed stream stopped at a limit",
                             confidence="probable", criterion=CRITERIA["decompression_bomb"], tags=["archive_bomb"],
                             description=f"Inflating stopped at the {meta['stop']} limit: the listing is partial.", stop=meta["stop"]))
    anomalies = meta.get("anomalies") or []
    missing = [a for a in anomalies if a.startswith("listing_needs_extra") or a == "udf_only_needs_extra"]
    if missing:
        extra = "py7zr" if "7z" in kind else "pycdlib"
        findings.append(fact("listing_unavailable", "info", f"{kind}: member listing needs the optional {extra} extra", confidence="confirmed",
                             criterion=CRITERIA["listing_unavailable"],
                             description=f"Install the optional {extra} package (LGPL, used unmodified) to list the members.", extra=extra))
    unsafe = [e for e in res["entries"] if e.get("flags")]
    if unsafe:
        reasons = sorted({r for e in unsafe for r in e["flags"]})
        findings.append(fact("unsafe_member_path", "medium", "Members with unsafe paths (never extracted)", confidence="confirmed",
                             criterion=CRITERIA["unsafe_member_path"], tags=["unsafe_path"],
                             description=f"{len(unsafe)} member(s): {', '.join(reasons)}.", members=[e["name"] for e in unsafe][:20], reasons=reasons))
    if double_ext:
        findings.append(fact("double_extension", "high", "Suspicious double extension inside the archive", confidence="probable",
                             attack="T1036.007", criterion=CRITERIA["double_extension"], tags=["suspicious", "masquerading"],
                             description=", ".join(clean_text(n, 120) or "" for n in double_ext[:5]), members=double_ext[:50]))
    if exe_inside:
        findings.append(fact("executable_inside", "medium", "Executables or scripts inside the archive", confidence="confirmed",
                             criterion=CRITERIA["executable_inside"], description=", ".join(clean_text(n, 120) or "" for n in exe_inside[:5]),
                             members=exe_inside[:50]))
    if kind in MOTW_CONTAINERS and motw_payload:
        hidden = [e["name"] for e in res["entries"] if e.get("hidden")]
        findings.append(fact("motw_container", "high", f"Suspicious {kind} image holding executable content (Mark-of-the-Web bypass)",
                             confidence="probable", attack="T1553.005", criterion=CRITERIA["motw_container"], tags=["suspicious", "motw_bypass"],
                             description=f"{', '.join(clean_text(n, 80) or '' for n in motw_payload[:3])}"
                                         + (f"; hidden members: {', '.join(clean_text(n, 80) or '' for n in hidden[:3])}" if hidden else ""),
                             payloads=motw_payload[:50], hidden_members=hidden[:50]))
    elif kind in ("vhd", "vhdx"):
        findings.append(fact("motw_container", "medium", f"{kind.upper()} disk image (bypasses Mark-of-the-Web; never mounted)",
                             confidence="possible", attack="T1553.005", criterion=CRITERIA["motw_container"], tags=["motw_bypass"],
                             description="Disk images are never mounted, so their contents were not inspected.", disk=meta.get("disk")))
    if res["counts"].get("encrypted"):
        findings.append(fact("encrypted_members", "info", "Encrypted members listed", confidence="confirmed", criterion=CRITERIA["encrypted_members"],
                             description=f"{res['counts']['encrypted']} encrypted member(s)"
                                         + ("" if passwords else ": decryption needs the analyst's archive password setting"),
                             count=res["counts"]["encrypted"]))
    if meta.get("headers_encrypted"):
        findings.append(fact("encrypted_headers", "info", "Archive headers are encrypted: member names not listable", confidence="confirmed",
                             criterion=CRITERIA["encrypted_headers"]))
    # WinRAR CVE-2023-38831 shape: a 'name.ext ' file next to a 'name.ext /' directory
    dirs = {e["name"].replace("\\", "/").rstrip("/") for e in entries if e.get("is_dir")} | \
        {e["name"].replace("\\", "/").rsplit("/", 1)[0] for e in entries if "/" in e["name"].replace("\\", "/")}
    trap = [e["name"] for e in entries if not e.get("is_dir") and e["name"].endswith(" ") and e["name"] in dirs]
    if trap:
        findings.append(fact("winrar_trailing_space_trap", "high", "Suspicious trailing-space file and folder pair (CVE-2023-38831 pattern)",
                             confidence="probable", criterion=CRITERIA["winrar_trailing_space_trap"], tags=["suspicious"],
                             description=f"{trap[0]!r} is both a file and a folder name.", members=trap[:10]))
    structural = [a for a in anomalies if a in ("duplicate_name", "overlapping_entries", "local_name_mismatch", "central_directory_unreadable")]
    if structural:
        findings.append(fact("archive_anomaly", "medium", "Archive structure anomalies", confidence="confirmed", criterion=CRITERIA["archive_anomaly"],
                             description=", ".join(structural), anomalies=structural))


def extraction_plan(analysis: dict[str, Any]) -> dict[str, Any]:
    """c3: which members an explicit extraction may write into the fresh 0700 temp dir, and why others not."""
    if analysis.get("stealer_bundle"):
        return {"allowed": [], "refused": [{"name": "*", "reason": "stealer_bundle_rule3"}]}
    allowed: list[str] = []
    refused: list[dict[str, str]] = []
    for e in analysis.get("entries", []):
        if e.get("is_dir"):
            continue
        why = list(e.get("flags") or [])
        if e.get("encrypted") and not e.get("sha256"):
            why.append("encrypted")
        if int(e.get("size") or 0) > LIMITS["archive_total"]:
            why.append("size")
        if why:
            refused.append({"name": e["name"], "reason": ",".join(why)})
        else:
            allowed.append(e["name"])
    return {"allowed": allowed, "refused": refused}


# ======================================================================================== explicit extraction (c3)

EXTRACTABLE_KINDS = ZIP_FAMILY | {"tar", "gzip", "bzip2", "xz", "iso9660", "iso9660+udf"}


def _safe_target(root: str, member: str) -> str | None:
    """The path a member is written to inside ``root``, or None when it would escape it."""
    parts = [p for p in member.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or any(p == ".." or ":" in p or any(ord(c) < 0x20 for c in p) for p in parts):
        return None
    target = os.path.realpath(os.path.join(root, *parts))
    base = os.path.realpath(root)
    return target if target.startswith(base + os.sep) else None


def _write_member(root: str, member: str, chunks: Any, written: dict[str, int]) -> str | None:
    target = _safe_target(root, member)
    if target is None:
        return None
    os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        for chunk in chunks:
            written["total"] += len(chunk)
            if written["total"] > LIMITS["archive_total"]:
                raise ArchiveLimit("total_cap")
            fh.write(chunk)
    return target


def extract_and_sniff(data: bytes, analysis: dict[str, Any], *, password: bytes | None, allow_sample_passwords: bool,
                      check: Callable[[], None] | None = None) -> dict[str, Any]:
    """c3: write the allowed members of the top-level container into a fresh 0700 temp dir, hash and sniff
    each file from disk, then delete the directory (always, in ``finally``). Returns {'written',
    'refused', 'files': [{name, sha256, size, kind}], 'removed'}."""
    kind = analysis.get("kind")
    plan = extraction_plan(analysis)
    out: dict[str, Any] = {"written": 0, "refused": list(plan["refused"]), "files": [], "removed": False}
    if kind not in EXTRACTABLE_KINDS:
        out["refused"].append({"name": "*", "reason": f"listing_only:{kind}"})
        return out
    allowed = set(plan["allowed"])
    passwords = ([password] if password else []) + (list(SAMPLE_PASSWORDS) if allow_sample_passwords else [])
    root = tempfile.mkdtemp(prefix="v3lum-archive-")  # 0700 on POSIX
    written = {"total": 0}
    try:
        for name, chunks in _member_streams(data, kind, allowed, passwords):
            if check is not None:
                check()
            try:
                path = _write_member(root, name, chunks, written)
            except ArchiveLimit as exc:
                out["refused"].append({"name": name, "reason": exc.args[0]})
                if exc.args[0] == "total_cap":
                    break
                continue
            except OSError as exc:
                out["refused"].append({"name": name, "reason": f"write_error:{type(exc).__name__}"})
                continue
            if path is None:
                out["refused"].append({"name": name, "reason": "unsafe_target"})
                continue
            out["written"] += 1
            out["files"].append(_hash_and_sniff(path, name))
    finally:
        shutil.rmtree(root, ignore_errors=True)
        out["removed"] = not os.path.exists(root)
    return out


def _member_streams(data: bytes, kind: str, allowed: set[str], passwords: list[bytes]) -> Any:
    """(name, chunk iterator) of every allowed member, through the same bounded readers as the listing."""
    if kind in ZIP_FAMILY:
        for zent in zip_scan(data)["entries"]:
            if zent["name"] not in allowed or zent["is_dir"] or zent.get("duplicate"):
                continue
            if zent["encrypted"] and (zent["encryption"] != "zipcrypto" or not passwords):
                continue
            pw = None
            if zent["encrypted"]:
                for cand in passwords:
                    try:
                        zip_read(data, zent, max_out=0, password=cand)
                    except ArchiveLimit as exc:
                        if exc.args[0] == "bad_password":
                            continue
                    pw = cand
                    break
                if pw is None:
                    continue
            yield zent["name"], zip_member_chunks(data, zent, password=pw)
    elif kind in ("iso9660", "iso9660+udf"):
        for e in iso_list(data)["entries"]:
            if e["name"] in allowed and not e["is_dir"]:
                start = e["lba"] * ISO_SECTOR
                yield e["name"], iter([data[start:start + min(e["size"], LIMITS["archive_total"])]])
    else:
        codec = {"tar": None, "gzip": "gz", "bzip2": "bz2", "xz": "xz"}.get(kind)
        stream = _CappedStream(data, codec, LIMITS["archive_total"], LIMITS["archive_ratio"], LIMITS["ratio_grace"])
        try:
            tf = tarfile.open(fileobj=stream, mode="r|")  # noqa: SIM115 - streaming reader
        except (tarfile.TarError, ArchiveLimit, OSError, EOFError, zlib.error, lzma.LZMAError):
            return
        data_filter = getattr(tarfile, "data_filter", None)
        try:
            for ti in tf:
                if ti.name not in allowed or not ti.isreg():
                    continue
                if data_filter is not None:
                    try:
                        data_filter(ti, "/nonexistent-v3lum-root")
                    except tarfile.FilterError:
                        continue
                fh = tf.extractfile(ti)
                if fh is not None:
                    yield ti.name, iter(lambda fh=fh: fh.read(1 << 16), b"")
        except (tarfile.TarError, ArchiveLimit, OSError, EOFError, zlib.error, lzma.LZMAError):
            return


def _hash_and_sniff(path: str, name: str) -> dict[str, Any]:
    h = hashlib.sha256()
    size = 0
    with open_regular(path) as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
            size += len(block)
    try:
        kind = sniff_path(path, name=name)["kind"]
    except (FileRefused, OSError):
        kind = "unknown"
    return {"name": name, "sha256": h.hexdigest(), "size": size, "kind": kind}


# ======================================================================================== the module


def _check_live(ctx: Any) -> None:
    """Kill switch and run deadline, checked between members."""
    if ctx.cancelled():
        raise Cancelled("cancelled while listing the archive")
    remaining = ctx.remaining()
    if remaining is not None and remaining <= 0:
        raise DeadlineExceeded("run deadline reached while listing the archive")


@register
class ArchiveListing(Module):
    name = "archive_listing"
    title = "Archive and disk-image listing (bomb and depth limits)"
    description = (
        "Lists ZIP/TAR/ISO/RAR/CAB archives and reports 7z/VHD/VHDX images offline with the P365 limits (500 MB, ratio 100, "
        "10,000 members, depth 3): unsafe paths, encryption, executables, double extensions, Mark-of-the-Web-defeating "
        "containers and stealer-log bundles (names only); small members are hashed in memory as sha256 pivots."
    )
    category = "file_analysis"
    accepts = {T.FILE}
    produces = {T.SHA256, T.FILE}
    tags = {"offline"}
    reference = "https://attack.mitre.org/techniques/T1553/005/"
    notice = ("Listing only by default: members are never executed, archives never mounted, passwords never guessed. "
              "Extraction needs setting archive_listing_extract and uses a 0700 temporary directory deleted after the run. "
              "Stealer-log bundles are listed as masked names, sizes and counts only (rule 3).")
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.1
    timeout = 120.0
    max_pivots = LIMITS["hash_members_per_archive"]
    default_enabled = True
    settings = {
        "archive_listing_extract": SettingSpec(False, "archive_listing: extract the allowed members into a 0700 temp dir deleted after the run (P365 c3)"),
        "archive_listing_password": SettingSpec("", "archive_listing: analyst-supplied password for encrypted members (P365 c4; never guessed)"),
        "archive_listing_sample_passwords": SettingSpec(False, "archive_listing: also try the conventional sample passwords 'infected' and 'malware' (explicit option, P365 c4)"),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return entity.type is T.FILE

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        path = entity.value
        try:
            sn = sniff_path(path)
        except FileRefused as exc:
            return res.mark("error" if exc.kind == "unreadable" else "skipped", exc.reason,
                            reason_code="error" if exc.kind == "unreadable" else "not_applicable")
        if self.name not in sn["routes"]:
            return res.mark("skipped", f"not an archive or disk image ({sn['description']})", reason_code="not_applicable")
        password = str(ctx.setting("archive_listing_password") or "").encode("utf-8") or None
        samples = bool(ctx.setting("archive_listing_sample_passwords"))
        check = lambda: _check_live(ctx)  # noqa: E731
        try:
            data, size = read_capped(path, ARCHIVE_READ_CAP)
        except FileRefused as exc:
            return res.mark("error", exc.reason)
        partial = size > len(data)
        listing = None
        if partial and sn["kind"] in ZIP_FAMILY:
            listing = _zip_listing_from_file(path)
        analysis = archive_analyse(data if not listing else b"", name=os.path.basename(path), kind=sn["kind"], password=password,
                                   allow_sample_passwords=samples, listing=listing, check=check)
        if partial:
            analysis["findings"].append(fact("listing_partial", "info", "Archive larger than the in-memory listing cap: listing partial",
                                             confidence="confirmed", criterion=CRITERIA["listing_partial"],
                                             description=(f"{size} bytes; " + ("members listed from the ZIP central directory, not read or hashed."
                                                                               if listing else f"only the first {ARCHIVE_READ_CAP} bytes were listed.")),
                                             size=size))
        extraction = None
        if ctx.setting("archive_listing_extract") and not partial:
            extraction = extract_and_sniff(data, analysis, password=password, allow_sample_passwords=samples, check=check)
        return self._report(res, sn, analysis, extraction, size)

    def _report(self, res: ModuleResult, sn: dict[str, Any], analysis: dict[str, Any], extraction: dict[str, Any] | None, size: int) -> ModuleResult:
        counts = analysis["counts"]
        listable = analysis["kind"] in LISTABLE_KINDS
        anomalies = analysis["meta"].get("anomalies") or []
        res.attr("file_type", sn["description"])
        summary = {"kind": analysis["kind"], "counts": counts, "anomalies": anomalies, "stealer_bundle": analysis["stealer_bundle"],
                   "stop": analysis["stop"], "nested": [{"name": n["name"], "kind": n["kind"], "members": n["counts"].get("members")}
                                                        for n in analysis["nested"]][:50], "size": size}
        for key in ("volume", "disk", "sevenzip", "comment", "headers_encrypted", "solid", "version"):
            if analysis["meta"].get(key) not in (None, "", {}, []):
                summary[key] = analysis["meta"][key]
        if extraction is not None:
            summary["extraction"] = {"written": extraction["written"], "refused": len(extraction["refused"]),
                                     "temp_dir_removed": extraction["removed"]}
        res.attr("archive_summary", cap_json(summary, 64 * 1024))
        members = [{k: v for k, v in m.items() if k in ("name", "size", "compressed_size", "encrypted", "encryption", "flags", "hidden",
                                                         "sha256", "kind", "is_dir", "type", "link_target", "mtime")}
                   for m in analysis["entries"][:MEMBERS_SHOWN]]
        res.attr("archive_members", members)
        what = "stealer-log bundle (names only)" if analysis["stealer_bundle"] else sn["description"]
        res.finding(f"Archive listed: {what}", "info",
                    f"{counts.get('members', 0)} member(s), {counts.get('files', 0)} file(s), {counts.get('declared_total', 0)} bytes declared, "
                    f"{counts.get('encrypted', 0)} encrypted, {counts.get('unsafe_names', 0)} unsafe name(s); nothing was executed or mounted.",
                    confidence="confirmed", data={"kind": analysis["kind"], "counts": counts}, tags=["info"])
        emit_findings(res, analysis["findings"])
        shown = 0
        for p in analysis["pivots"]:
            if shown >= self.max_pivots:
                break
            if res.pivot(p["type"], p["value"], p["relation"], confidence="confirmed",
                         note=f"archive member {clean_text(p.get('member'), 120)} ({p.get('kind')}, {p.get('size')} bytes) hashed in memory"):
                shown += 1
        if extraction is not None:
            for f in extraction["files"]:
                if shown >= self.max_pivots:
                    break
                if res.pivot(T.SHA256, f["sha256"], "contains", confidence="confirmed",
                             note=f"archive member {clean_text(f['name'], 120)} ({f['kind']}, {f['size']} bytes) hashed after extraction"):
                    shown += 1
        res.raw = cap_json({"analysis": {k: v for k, v in analysis.items() if k not in ("findings", "pivots")}, "extraction": extraction})
        if listable and not analysis["entries"] and not analysis["stealer_bundle"] and _listing_failed(analysis):
            res.mark("error", f"could not list the {analysis['kind']} container: {', '.join(anomalies[:3]) or 'unreadable structure'}")
        return res


def _listing_failed(analysis: dict[str, Any]) -> bool:
    """True when a listable container produced no entry because its structure could not be read."""
    meta = analysis["meta"]
    anomalies = meta.get("anomalies") or []
    if meta.get("headers_encrypted") or any(a.startswith(("listing_needs_extra", "udf_only")) or a == "disk_image_not_mounted" for a in anomalies):
        return False
    bad = ("eocd_missing", "central_directory_unreadable", "no_primary_volume_descriptor", "bad_root_record", "not_rar", "not_cab")
    return any(a.startswith(("tar_error", "rar_error", "py7zr_error")) or a in bad for a in anomalies) or meta.get("stop") == "corrupt_stream"


def _zip_listing_from_file(path: str) -> tuple[list[dict[str, Any]], dict[str, Any], str | None] | None:
    """Listing of a ZIP above the in-memory cap from its central directory (members are not read)."""
    try:
        with open_regular(path) as fh:
            size = os.fstat(fh.fileno()).st_size
            fh.seek(max(0, size - LIMITS["sniff_tail"]))
            window = fh.read(LIMITS["sniff_tail"])
            entries = zip_cd_entries_from_file(fh, size, window)
    except (FileRefused, OSError):
        return None
    if entries is None:
        return None
    ents = [{"name": e["name"], "size": e["file_size"], "compressed_size": e["compressed_size"], "is_dir": e["is_dir"],
             "encrypted": e["encrypted"], "encryption": e["encryption"], "mtime": e["mtime"], "hidden": e["hidden"],
             "flags": member_name_flags(e["name"], is_symlink=e["is_symlink"])} for e in entries]
    return ents, {"anomalies": ["listed_from_central_directory"]}, None


