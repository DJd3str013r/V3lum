"""ELF basic triage: architecture, interpreter, libraries, symbols, entropy and UPX hints (P368, batch p3-G12-2).

Offline module (disclosure 'none': no network at all, ScopedHttp refuses any request; terms 'open'; provider tier
n/a; allowed at TLP:RED; default-on). Final conditions:

* c1 FILE input only (regular files of at most 100 MB); the sample is parsed, never executed, loaded or emulated.
  This module makes no network call.
* c2 parsing in the shared file-analysis sandbox ``core/sandbox.py``: with the core sandbox, :func:`elf_child`
  (pyelftools) or, without the extra, :func:`parse_elf` runs there through ``image_metadata.sandbox_run`` (python
  -I child, wall timeout, rlimits, 100 MB input, 1 MB JSON output; the output is kept under 900 KB). This build
  has no core sandbox yet and modules may not start processes (P327 LINT-01), so the module parses with
  :func:`parse_elf`, a bounded pure standard-library ELF reader with the same output shape as the pyelftools child
  (normalised facts verified equal to pyelftools 0.33 on every fixture: tests/fixtures/elf_triage/child_*.json);
  pyelftools is never run in process (the same G12 rule as pe_triage, P271). Caps: 256 sections, 64 segments,
  1,500 imports/exports listed (totals kept), 200,000 symbol entries scanned, entropy over at most 256 KiB per
  region (an evenly spaced sample above it) and 4 MiB per file.
* c3 pyelftools (pure Python, public domain) is the only third-party library, an optional extra
  (``v3lum/data/extras/elftools.json``, ``pyelftools>=0.33,<0.34``: the child uses the pinned private
  ``ELFFile._get_segment_header`` to keep partial results). Outputs: architecture, interpreter, needed libraries,
  imported and exported symbols, section entropy and UPX markers; every marker is an INFO hint, never a verdict.
* c4 the telfhash library is not used (dead dependency set): telfhash values come only from the YARAify and
  MalwareBazaar modules (``yaraify``, ``abusech``, ``structural_hash_pivots``) under the abuse.ch licence
  decision (A1: MalwareBazaar class 'license'); this module never computes or looks one up.
* c5 fixtures: small benign ELF files built at test time by a stdlib builder (in tests/modules/test_elf_triage.py,
  byte-identical to the stored fixtures) plus a gcc-built benign 'hello', a truncated copy and a cut header
  (tests/fixtures/elf_triage/); nothing is ever executed.

The GNU build-id becomes a keyword pivot with expand=False (a sample identifier: listed, never sent anywhere
automatically). Imports and libraries are attributes, not pivots.
"""

from __future__ import annotations

import collections
import hashlib
import io
import json
import math
import re
import struct
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, package_available, register
from v3lum.modules.geo_image_meta.image_metadata import (
    InputRefused,
    SandboxUnavailable,
    core_sandbox,
    read_head,
    read_regular_file,
    sandbox_failure,
    sandbox_run,
)

MAX_INPUT = 100 * 1024 * 1024  # c2 sandbox input cap
CAPS: dict[str, int] = {
    "sections": 256, "segments": 64, "imports": 1500, "exports": 1500, "needed": 128, "symtab_sample": 200,
    "comment": 8, "name_len": 160, "symbol_scan": 200_000, "dynamic_entries": 4096, "notes": 64,
    "entropy_region": 256 * 1024, "entropy_budget": 4 << 20, "output_bytes": 900 * 1024,
}
HIGH_ENTROPY = 7.2
MIN_ENTROPY_BYTES = 512
PARSER_LIMITS = {"wall_timeout": 30.0, "cpu_seconds": 25}

# ======================================================================================================
# [P368 elf_triage] names (pyelftools 0.33 spellings, so both parsers give the same output shape)
# ======================================================================================================

EM_NAMES = {2: "EM_SPARC", 3: "EM_386", 4: "EM_68K", 8: "EM_MIPS", 10: "EM_MIPS_RS3_LE", 18: "EM_SPARC32PLUS",
            20: "EM_PPC", 21: "EM_PPC64", 22: "EM_S390", 40: "EM_ARM", 42: "EM_SH", 43: "EM_SPARCV9",
            50: "EM_IA_64", 62: "EM_X86_64", 92: "EM_OPENRISC", 93: "EM_ARC_COMPACT", 94: "EM_XTENSA",
            106: "EM_BLACKFIN", 164: "EM_QDSP6", 183: "EM_AARCH64", 189: "EM_MICROBLAZE",
            195: "EM_ARC_COMPACT2", 243: "EM_RISCV", 258: "EM_LOONGARCH"}
ELF_MACHINES = {2: "SPARC", 3: "x86", 4: "m68k", 8: "MIPS", 10: "MIPS (RS3000 LE)", 18: "SPARC32+", 20: "PowerPC",
                21: "PowerPC64", 22: "s390", 40: "ARM", 42: "SuperH", 43: "SPARC V9", 50: "IA-64", 62: "x86-64",
                92: "OpenRISC", 93: "ARC", 94: "Xtensa", 106: "Blackfin", 164: "Hexagon", 183: "AArch64",
                189: "MicroBlaze", 195: "ARCv2", 243: "RISC-V", 258: "LoongArch"}
_EM_NAME_TO_NUM = {v: k for k, v in EM_NAMES.items()}
OSABI_NAMES = {0: "ELFOSABI_SYSV", 1: "ELFOSABI_HPUX", 2: "ELFOSABI_NETBSD", 3: "ELFOSABI_LINUX",
               6: "ELFOSABI_SOLARIS", 7: "ELFOSABI_AIX", 8: "ELFOSABI_IRIX", 9: "ELFOSABI_FREEBSD",
               10: "ELFOSABI_TRU64", 11: "ELFOSABI_MODESTO", 12: "ELFOSABI_OPENBSD", 13: "ELFOSABI_OPENVMS",
               14: "ELFOSABI_NSK", 15: "ELFOSABI_AROS", 64: "ELFOSABI_ARM_AEABI", 97: "ELFOSABI_ARM",
               255: "ELFOSABI_STANDALONE"}
ET_NAMES = {0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}
PT_NAMES = {0: "PT_NULL", 1: "PT_LOAD", 2: "PT_DYNAMIC", 3: "PT_INTERP", 4: "PT_NOTE", 5: "PT_SHLIB", 6: "PT_PHDR",
            7: "PT_TLS", 0x6474E550: "PT_GNU_EH_FRAME", 0x6474E551: "PT_GNU_STACK", 0x6474E552: "PT_GNU_RELRO",
            0x6474E553: "PT_GNU_PROPERTY"}
PT_MACHINE = {40: {0x70000001: "PT_ARM_EXIDX"},
              8: {0x70000000: "PT_MIPS_REGINFO", 0x70000001: "PT_MIPS_RTPROC", 0x70000002: "PT_MIPS_OPTIONS",
                  0x70000003: "PT_MIPS_ABIFLAGS"}}
SHT_NAMES = {0: "SHT_NULL", 1: "SHT_PROGBITS", 2: "SHT_SYMTAB", 3: "SHT_STRTAB", 4: "SHT_RELA", 5: "SHT_HASH",
             6: "SHT_DYNAMIC", 7: "SHT_NOTE", 8: "SHT_NOBITS", 9: "SHT_REL", 10: "SHT_SHLIB", 11: "SHT_DYNSYM",
             14: "SHT_INIT_ARRAY", 15: "SHT_FINI_ARRAY", 16: "SHT_PREINIT_ARRAY", 17: "SHT_GROUP",
             18: "SHT_SYMTAB_SHNDX", 19: "SHT_RELR", 0x6FFFFFF5: "SHT_GNU_ATTRIBUTES", 0x6FFFFFF6: "SHT_GNU_HASH",
             0x6FFFFFF7: "SHT_GNU_LIBLIST", 0x6FFFFFFD: "SHT_GNU_verdef", 0x6FFFFFFE: "SHT_GNU_verneed",
             0x6FFFFFFF: "SHT_GNU_versym"}
SHT_MACHINE = {40: {0x70000001: "SHT_ARM_EXIDX", 0x70000003: "SHT_ARM_ATTRIBUTES"},
               8: {0x70000006: "SHT_MIPS_REGINFO", 0x7000000D: "SHT_MIPS_OPTIONS", 0x7000002A: "SHT_MIPS_ABIFLAGS"},
               243: {0x70000003: "SHT_RISCV_ATTRIBUTES"}, 62: {0x70000001: "SHT_AMD64_UNWIND"}}
STB_NAMES = {0: "STB_LOCAL", 1: "STB_GLOBAL", 2: "STB_WEAK", 10: "STB_GNU_UNIQUE"}
STT_NAMES = {0: "STT_NOTYPE", 1: "STT_OBJECT", 2: "STT_FUNC", 3: "STT_SECTION", 4: "STT_FILE", 5: "STT_COMMON",
             6: "STT_TLS", 10: "STT_GNU_IFUNC"}
DT_NULL, DT_NEEDED, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SONAME, DT_RPATH, DT_RUNPATH = 0, 1, 4, 5, 6, 10, 14, 15, 29
DT_FLAGS_1, DT_GNU_HASH = 0x6FFFFFFB, 0x6FFFFEF5
SHT_SYMTAB, SHT_STRTAB, SHT_DYNAMIC, SHT_NOTE, SHT_NOBITS, SHT_DYNSYM = 2, 3, 6, 7, 8, 11
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE = 1, 2, 3, 4
STANDARD_INTERPRETER_RE = re.compile(
    r"^(?:/lib(?:32|64|x32)?/ld-linux[-\w.]*\.so\.\d+|/lib(?:32|64)?/ld\.so\.1|/lib/ld-musl-[\w.-]+\.so\.1"
    r"|/lib/ld-uClibc[\w.-]*\.so\.\d+|/lib(?:64)?/ld64\.so\.[12]|/system/bin/linker(?:64)?"
    r"|/libexec/ld-elf\.so\.1|/usr/libexec/ld\.so|/lib/ld\.so\.1)$")
#: Linker/CRT symbols present in almost every glibc binary: kept in the counts, hidden from the analyst lists.
TOOLCHAIN_SYMBOLS = frozenset({
    "_ITM_deregisterTMCloneTable", "_ITM_registerTMCloneTable", "__gmon_start__", "__libc_start_main",
    "__cxa_finalize", "_Jv_RegisterClasses", "__stack_chk_fail", "__libc_csu_init", "__libc_csu_fini",
    "_edata", "_end", "__bss_start", "_IO_stdin_used", "_start", "data_start", "__data_start", "_init", "_fini",
    "__dso_handle", "__TMC_END__", "_DYNAMIC", "_GLOBAL_OFFSET_TABLE_", "__GNU_EH_FRAME_HDR"})


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 for empty input)."""
    if not data:
        return 0.0
    n = len(data)
    return 0.0 + abs(sum(c / n * math.log2(c / n) for c in collections.Counter(data).values()))


def region_entropy(data: bytes, off: int, size: int, budget: list[int], caps: dict[str, int] = CAPS) -> float | None:
    """Entropy of data[off:off+size] clipped to the file: exact up to ``entropy_region`` bytes, else 16 evenly
    spaced chunks of that total; None when nothing is inside the file or the per-file budget is spent."""
    length = len(data)
    if off < 0 or off >= length or size <= 0:
        return None
    avail = min(size, length - off)
    cap = caps["entropy_region"]
    if avail <= cap:
        blob = data[off:off + avail]
    else:
        step, chunk = avail // 16, cap // 16
        blob = b"".join(data[off + i * step: off + i * step + chunk] for i in range(16))
    if not blob or budget[0] < len(blob):
        return None
    budget[0] -= len(blob)
    return round(shannon_entropy(blob), 4)


def elf_ident(head: bytes, file_size: int) -> dict[str, Any] | None:
    """Stdlib ELF header preflight (c1/c5): None if not ELF, else header fields plus 'problems'
    (truncated_header, bad_class, bad_data_encoding, phdrs_beyond_eof, shdrs_beyond_eof)."""
    if not isinstance(head, (bytes, bytearray)) or head[:4] != b"\x7fELF":
        return None
    out: dict[str, Any] = {"bits": None, "endian": None, "type": None, "machine": None, "problems": []}
    if len(head) < 16:
        out["problems"].append("truncated_header")
        return out
    cls, enc = head[4], head[5]
    if cls not in (1, 2):
        out["problems"].append("bad_class")
        return out
    if enc not in (1, 2):
        out["problems"].append("bad_data_encoding")
        return out
    out.update({"bits": 32 if cls == 1 else 64, "endian": "little" if enc == 1 else "big"})
    e = "<" if enc == 1 else ">"
    need = 52 if cls == 1 else 64
    if len(head) >= 20:
        et, em = struct.unpack_from(e + "HH", head, 16)
        out.update({"type": ET_NAMES.get(et, et), "machine": EM_NAMES.get(em, em)})
    if len(head) < need:
        out["problems"].append("truncated_header")
        return out
    fmt = e + ("HHIIIIIHHHHHH" if cls == 1 else "HHIQQQIHHHHHH")
    (_et, _em, _v, _entry, phoff, shoff, _fl, _eh, phes, phn, shes, shn, _shx) = struct.unpack_from(fmt, head, 16)
    if phn and phoff + phn * phes > file_size:
        out["problems"].append("phdrs_beyond_eof")
    if shn and shoff + shn * shes > file_size:
        out["problems"].append("shdrs_beyond_eof")
    return out


def elf_preflight(data: Any, max_input: int = MAX_INPUT) -> dict[str, Any]:
    """Decide before parsing (c1/c2): {'ok', 'reason', 'ident'}, reason in {None, 'empty', 'too_large', 'not_elf',
    'truncated_header', 'malformed_header'}. Section headers past EOF stay ok (partial results)."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        return {"ok": False, "reason": "empty", "ident": None}
    if len(data) > max_input:
        return {"ok": False, "reason": "too_large", "ident": None}
    ident = elf_ident(bytes(data[:64]), len(data))
    if ident is None:
        return {"ok": False, "reason": "not_elf", "ident": None}
    probs = ident["problems"]
    if "truncated_header" in probs:
        return {"ok": False, "reason": "truncated_header", "ident": ident}
    if "bad_class" in probs or "bad_data_encoding" in probs:
        return {"ok": False, "reason": "malformed_header", "ident": ident}
    return {"ok": True, "reason": None, "ident": ident}


_UPX_VER_RE = re.compile(rb"\$Id: UPX (\d{1,2}\.\d{1,3}(?:\.\d{1,3})?)")


def upx_markers(data: Any, max_hits: int = 8) -> dict[str, Any]:
    """UPX packer markers (c3, INFO hints): offsets of 'UPX!' (l_info after the program headers and the trailing
    PackHeader), the '$Info: ... UPX' banner and the '$Id: UPX x.y' version. Malware often patches 'UPX!' to break
    'upx -d'; the normaliser then falls back to a structural hint (no sections + a high-entropy segment)."""
    if not isinstance(data, (bytes, bytearray)):
        return {"magic_offsets": [], "info_banner": False, "version": None}
    b = bytes(data)
    offs, i = [], b.find(b"UPX!")
    while i != -1 and len(offs) < max_hits:
        offs.append(i)
        i = b.find(b"UPX!", i + 1)
    m = _UPX_VER_RE.search(b)
    return {"magic_offsets": offs, "info_banner": b"This file is packed with the UPX executable packer" in b,
            "version": m.group(1).decode() if m else None}


def _text(raw: bytes, limit: int = CAPS["name_len"]) -> str:
    return raw.decode("utf-8", "replace")[:limit]


def _cstr(data: bytes, off: int, limit: int = 4096) -> bytes:
    if off < 0 or off >= len(data):
        raise ValueError(f"string offset {off} past EOF {len(data)}")
    end = data.find(b"\x00", off, off + limit)
    return data[off:end if end != -1 else min(len(data), off + limit)]


# ======================================================================================================
# The bounded standard-library reader (c2 fallback; same output shape as elf_child)
# ======================================================================================================

def parse_elf(data: bytes, caps: dict[str, int] | None = None) -> dict[str, Any]:
    """Parse one ELF with the standard library only: header, program headers, sections + entropy, dynamic tags,
    imported/exported dynamic symbols (section table, else DT_SYMTAB with DT_HASH/DT_GNU_HASH), symtab presence,
    GNU build-id, .comment, Go buildinfo and UPX markers. Every step is bounded and isolated: a failure is
    recorded in 'errors' and the other steps still run (truncated files). Nothing is executed or loaded."""
    caps = {**CAPS, **(caps or {})}
    data = bytes(data)
    length = len(data)
    base = {"source": "stdlib", "version": "1", "size": length}
    if data[:4] != b"\x7fELF":
        return {**base, "error": "ELFError", "message": "Magic number does not match"}
    if length < 16 or data[4] not in (1, 2) or data[5] not in (1, 2):
        return {**base, "error": "ELFError", "message": f"truncated or malformed e_ident (found {min(length, 16)} bytes)"}
    is64 = data[4] == 2
    e = "<" if data[5] == 1 else ">"
    need = 64 if is64 else 52
    if length < need:
        return {**base, "error": "ELFError", "message": f"truncated ELF header: expected {need}, found {length}"}
    fmt = e + ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH")
    (etype, machine, _ver, entry, phoff, shoff, flags, _ehsize, phentsize, phnum, shentsize, shnum,
     shstrndx) = struct.unpack_from(fmt, data, 16)
    out: dict[str, Any] = {**base, "header": {}, "interpreter": None, "segments": [], "sections": [], "dynamic": {},
                           "imports": [], "exports": [], "imports_total": 0, "exports_total": 0,
                           "symtab": {"present": False}, "build_id": None, "comment": [], "go_buildinfo": False,
                           "upx": upx_markers(data), "errors": [], "capped": []}
    budget = [caps["entropy_budget"]]
    segs: list[dict[str, Any]] = []
    secs: list[dict[str, Any]] = []
    state: dict[str, Any] = {"phnum": phnum, "shnum": shnum, "shstrndx": shstrndx}

    def step(name: str, fn: Any) -> None:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - untrusted file: recorded, partial result kept
            out["errors"].append({"step": name, "error": f"{type(exc).__name__}: {str(exc)[:200]}"})

    def header() -> None:
        sec0 = None
        if shoff and shentsize >= (64 if is64 else 40) and shoff + shentsize <= length:
            sec0 = _section_header(data, shoff, e, is64)
        if shnum == 0 and sec0 is not None:
            state["shnum"] = sec0["sh_size"]  # e_shnum overflow: the real count lives in section 0
        if shstrndx == 0xFFFF and sec0 is not None:
            state["shstrndx"] = sec0["sh_link"]  # SHN_XINDEX
        if phnum == 0xFFFF and sec0 is not None:
            state["phnum"] = sec0["sh_info"]  # PN_XNUM
        out["header"] = {"class": "ELFCLASS64" if is64 else "ELFCLASS32",
                         "data": "ELFDATA2LSB" if e == "<" else "ELFDATA2MSB",
                         "osabi": OSABI_NAMES.get(data[7], data[7]), "abiversion": data[8],
                         "type": ET_NAMES.get(etype, etype), "machine": EM_NAMES.get(machine, machine),
                         "machine_arch": ELF_MACHINES.get(machine, f"machine_{machine}"), "entry": entry,
                         "flags": flags, "phnum": state["phnum"], "shnum": state["shnum"], "shoff": shoff,
                         "shstrndx": state["shstrndx"], "phoff": phoff, "phentsize": phentsize,
                         "shentsize": shentsize}

    def segments() -> None:
        n = int(state["phnum"])
        need_sz = 56 if is64 else 32
        failed = []
        for i in range(min(n, caps["segments"])):
            at = phoff + i * phentsize
            if phentsize < need_sz or at + need_sz > length:
                failed.append(f"{i}: program header at offset {at} past EOF {length}")
                continue
            if is64:
                ptype, pflags, poff, pvaddr, _pa, pfilesz, pmemsz, _al = struct.unpack_from(e + "IIQQQQQQ", data, at)
            else:
                ptype, poff, pvaddr, _pa, pfilesz, pmemsz, pflags, _al = struct.unpack_from(e + "IIIIIIII", data, at)
            name = PT_NAMES.get(ptype) or PT_MACHINE.get(machine, {}).get(ptype) or ptype
            seg = {"p_type": ptype, "p_offset": poff, "p_vaddr": pvaddr, "p_filesz": pfilesz}
            segs.append(seg)
            item: dict[str, Any] = {"type": name, "offset": poff, "vaddr": pvaddr, "filesz": pfilesz, "memsz": pmemsz,
                                    "flags": pflags}
            if ptype in (PT_LOAD, PT_INTERP, PT_DYNAMIC, PT_NOTE) and pfilesz:
                item["oob"] = poff + pfilesz > length
            if ptype == PT_LOAD and pfilesz:
                item["entropy"] = region_entropy(data, poff, pfilesz, budget, caps)
            out["segments"].append(item)
            if ptype == PT_INTERP and out["interpreter"] is None and pfilesz:
                out["interpreter"] = _text(_cstr(data, poff, min(pfilesz, 4096)))
        if n > caps["segments"]:
            out["capped"].append("segments")
        if failed:
            out["errors"].append({"step": "segments", "error": f"{len(failed)} of {n} segment(s) unreadable; first: {failed[0]}"})

    def sections() -> None:
        n = int(state["shnum"])
        if not n or not shoff:
            return
        need_sz = 64 if is64 else 40
        strtab = None
        sx = int(state["shstrndx"])
        if 0 < sx < n and shentsize >= need_sz and shoff + sx * shentsize + need_sz <= length:
            strtab = _section_header(data, shoff + sx * shentsize, e, is64)
        failed = []
        for i in range(min(n, caps["sections"])):
            at = shoff + i * shentsize
            if shentsize < need_sz or at + need_sz > length:
                failed.append(f"{i}: section header at offset {at} past EOF {length}")
                continue
            h = _section_header(data, at, e, is64)
            name = ""
            if h["sh_name"] and strtab is not None:
                try:
                    name = _text(_cstr(data, strtab["sh_offset"] + h["sh_name"], 256), 64)
                except ValueError as exc:
                    failed.append(f"{i}: name: {exc}")
                    continue
            h["index"], h["name"] = i, name
            secs.append(h)
            stype = h["sh_type"]
            tname = SHT_NAMES.get(stype) or SHT_MACHINE.get(machine, {}).get(stype) or stype
            size, off = h["sh_size"], h["sh_offset"]
            item: dict[str, Any] = {"name": name, "type": tname, "flags": h["sh_flags"], "addr": h["sh_addr"],
                                    "offset": off, "size": size}
            if stype != SHT_NOBITS and size:
                item["oob"] = off + size > length
                item["entropy"] = region_entropy(data, off, size, budget, caps)
            out["sections"].append(item)
            if name in (".go.buildinfo", ".note.go.buildid"):
                out["go_buildinfo"] = True
        if n > caps["sections"]:
            out["capped"].append("sections")
        if failed:
            out["errors"].append({"step": "sections", "error": f"{len(failed)} of {n} section(s) unreadable; first: {failed[0]}"})

    dyn_tags: list[tuple[int, int]] = []

    def dynamic() -> None:
        sec = next((s for s in secs if s["sh_type"] == SHT_DYNAMIC), None)
        strtab: tuple[int, int] | None = None
        if sec is not None:
            off, size = sec["sh_offset"], sec["sh_size"]
            link = _by_index(secs, sec["sh_link"])
            if link is not None and link["sh_type"] != SHT_NOBITS:
                strtab = (link["sh_offset"], link["sh_size"])
        else:
            seg = next((s for s in segs if s["p_type"] == PT_DYNAMIC), None)
            if seg is None:
                return
            off, size = seg["p_offset"], seg["p_filesz"]
        entsz = 16 if is64 else 8
        fmt_d = e + ("qQ" if is64 else "iI")
        pos, end = off, min(off + size, length)
        while pos + entsz <= end and len(dyn_tags) < caps["dynamic_entries"]:
            tag, val = struct.unpack_from(fmt_d, data, pos)
            if tag == DT_NULL:
                break
            dyn_tags.append((tag, val))
            pos += entsz
        if not dyn_tags:
            if off + size > length:
                raise ValueError(f"dynamic table at offset {off} past EOF {length}")
            return
        if strtab is None:
            vaddr = next((v for t, v in dyn_tags if t == DT_STRTAB), None)
            strsz = next((v for t, v in dyn_tags if t == DT_STRSZ), 0)
            foff = _vaddr_to_offset(segs, vaddr) if vaddr is not None else None
            strtab = (foff, min(strsz or 1 << 20, 1 << 20)) if foff is not None else None
        state["dynstr"] = strtab
        d: dict[str, Any] = {"needed": [], "soname": None, "rpath": None, "runpath": None, "flags_1": None}
        for tag, val in dyn_tags:
            if tag in (DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH):
                if strtab is None or val >= strtab[1]:
                    continue
                s = _cstr(data, strtab[0] + val, 1024)
                if tag == DT_NEEDED and len(d["needed"]) < caps["needed"]:
                    d["needed"].append(_text(s))
                elif tag == DT_SONAME:
                    d["soname"] = _text(s)
                elif tag == DT_RPATH:
                    d["rpath"] = _text(s, 512)
                elif tag == DT_RUNPATH:
                    d["runpath"] = _text(s, 512)
            elif tag == DT_FLAGS_1:
                d["flags_1"] = val
        out["dynamic"] = d

    def symbols() -> None:
        dynsym = next((s for s in secs if s["sh_type"] == SHT_DYNSYM), None)
        entries: tuple[int, int, tuple[int, int] | None] | None = None
        symsz = 24 if is64 else 16
        if dynsym is not None:
            link = _by_index(secs, dynsym["sh_link"])
            strtab = (link["sh_offset"], link["sh_size"]) if link is not None else None
            ent = dynsym["sh_entsize"] or symsz
            entries = (dynsym["sh_offset"], dynsym["sh_size"] // max(ent, 1), strtab)
        elif dyn_tags:
            symtab_va = next((v for t, v in dyn_tags if t == DT_SYMTAB), None)
            foff = _vaddr_to_offset(segs, symtab_va) if symtab_va is not None else None
            count = _dynamic_symbol_count(data, segs, dyn_tags, e, is64, caps)
            if foff is not None and count:
                entries = (foff, count, state.get("dynstr"))
        if entries is not None:
            off, count, strtab = entries
            scanned = 0
            for idx in range(count):
                if scanned >= caps["symbol_scan"]:
                    out["capped"].append("symbol_scan")
                    break
                at = off + idx * symsz
                if at + symsz > length:
                    raise ValueError(f"symbol {idx} at offset {at} past EOF {length}")
                scanned += 1
                name_off, info, other, shndx = _symbol(data, at, e, is64)
                if not name_off or strtab is None or name_off >= strtab[1]:
                    continue
                name = _text(_cstr(data, strtab[0] + name_off, 512))
                if not name:
                    continue
                item = {"name": name, "type": STT_NAMES.get(info & 0xF, info & 0xF), "bind": STB_NAMES.get(info >> 4, info >> 4)}
                if shndx == 0:
                    out["imports_total"] += 1
                    if len(out["imports"]) < caps["imports"]:
                        out["imports"].append(item)
                elif (info >> 4) in (1, 2, 10) and (other & 3) in (0, 3):
                    out["exports_total"] += 1
                    if len(out["exports"]) < caps["exports"]:
                        out["exports"].append(item)
            if out["imports_total"] > len(out["imports"]):
                out["capped"].append("imports")
            if out["exports_total"] > len(out["exports"]):
                out["capped"].append("exports")
        symtab = next((s for s in secs if s["sh_type"] == SHT_SYMTAB), None)
        if symtab is not None:
            link = _by_index(secs, symtab["sh_link"])
            ent = symtab["sh_entsize"] or symsz
            total = symtab["sh_size"] // max(ent, 1)
            inside = max(0, min(total, (length - symtab["sh_offset"]) // max(ent, 1)))
            sample: list[str] = []
            for idx in range(min(inside, caps["symbol_scan"])):
                if len(sample) >= caps["symtab_sample"]:
                    break
                name_off, info, _other, _shndx = _symbol(data, symtab["sh_offset"] + idx * ent, e, is64)
                if (info >> 4) == 1 and (info & 0xF) == 2 and name_off and link is not None and name_off < link["sh_size"]:
                    name = _text(_cstr(data, link["sh_offset"] + name_off, 512))
                    if name:
                        sample.append(name)
            out["symtab"] = {"present": True, "count": inside, "globals_sample": sample}

    def notes() -> None:
        holders = [(s["sh_offset"], s["sh_size"]) for s in secs if s["sh_type"] == SHT_NOTE]
        if not holders:
            holders = [(s["p_offset"], s["p_filesz"]) for s in segs if s["p_type"] == PT_NOTE]
        for off, size in holders:
            pos, end = off, min(off + size, length)
            for _ in range(caps["notes"]):
                if pos + 12 > end:
                    break
                namesz, descsz, ntype = struct.unpack_from(e + "III", data, pos)
                name_at = pos + 12
                desc_at = name_at + ((namesz + 3) & ~3)
                nxt = desc_at + ((descsz + 3) & ~3)
                if desc_at + descsz > end or nxt <= pos:
                    break
                if ntype == 3 and data[name_at:name_at + namesz].rstrip(b"\x00") == b"GNU" and descsz:
                    out["build_id"] = data[desc_at:desc_at + descsz].hex()[:128]
                    return
                pos = nxt

    def comment() -> None:
        sec = next((s for s in secs if s["name"] == ".comment"), None)
        if sec is None or sec["sh_type"] == SHT_NOBITS or sec["sh_offset"] >= length:
            return
        raw = data[sec["sh_offset"]:sec["sh_offset"] + min(sec["sh_size"], 4096)]
        out["comment"] = [_text(x) for x in raw.split(b"\x00") if x.strip()][:caps["comment"]]

    for name, fn in (("header", header), ("segments", segments), ("sections", sections), ("dynamic", dynamic),
                     ("symbols", symbols), ("notes", notes), ("comment", comment)):
        step(name, fn)
    return fit_output(out, caps)


def _section_header(data: bytes, at: int, e: str, is64: bool) -> dict[str, int]:
    fmt = e + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
    vals = struct.unpack_from(fmt, data, at)
    keys = ("sh_name", "sh_type", "sh_flags", "sh_addr", "sh_offset", "sh_size", "sh_link", "sh_info",
            "sh_addralign", "sh_entsize")
    return dict(zip(keys, vals))


def _symbol(data: bytes, at: int, e: str, is64: bool) -> tuple[int, int, int, int]:
    if is64:
        name, info, other, shndx, _v, _s = struct.unpack_from(e + "IBBHQQ", data, at)
    else:
        name, _v, _s, info, other, shndx = struct.unpack_from(e + "IIIBBH", data, at)
    return name, info, other, shndx


def _by_index(secs: list[dict[str, Any]], idx: int) -> dict[str, Any] | None:
    return next((s for s in secs if s.get("index") == idx), None)


def _vaddr_to_offset(segs: list[dict[str, Any]], vaddr: int | None) -> int | None:
    if vaddr is None:
        return None
    for s in segs:
        if s["p_type"] == PT_LOAD and s["p_vaddr"] <= vaddr < s["p_vaddr"] + s["p_filesz"]:
            return s["p_offset"] + (vaddr - s["p_vaddr"])
    return None


def _dynamic_symbol_count(data: bytes, segs: list[dict[str, Any]], tags: list[tuple[int, int]], e: str, is64: bool,
                          caps: dict[str, int]) -> int:
    """Number of dynamic symbols without a section table: DT_HASH nchain, else the DT_GNU_HASH chains."""
    length = len(data)
    h = _vaddr_to_offset(segs, next((v for t, v in tags if t == DT_HASH), None))
    if h is not None and h + 8 <= length:
        return min(struct.unpack_from(e + "II", data, h)[1], caps["symbol_scan"])
    g = _vaddr_to_offset(segs, next((v for t, v in tags if t == DT_GNU_HASH), None))
    if g is None or g + 16 > length:
        return 0
    nbuckets, symoffset, bloom_size, _shift = struct.unpack_from(e + "IIII", data, g)
    buckets_at = g + 16 + bloom_size * (8 if is64 else 4)
    if nbuckets > caps["symbol_scan"] or buckets_at + 4 * nbuckets > length:
        return 0
    last = max(struct.unpack_from(e + f"{nbuckets}I", data, buckets_at), default=0)
    if last < symoffset:
        return symoffset
    chain_at = buckets_at + 4 * nbuckets
    idx = last
    while idx - symoffset < caps["symbol_scan"]:
        at = chain_at + 4 * (idx - symoffset)
        if at + 4 > length:
            return 0
        if struct.unpack_from(e + "I", data, at)[0] & 1:
            return idx + 1
        idx += 1
    return caps["symbol_scan"]


def fit_output(out: dict[str, Any], caps: dict[str, int] = CAPS) -> dict[str, Any]:
    """c2: keep the parser output under the sandbox's 1 MB JSON cap (halve the longest symbol list)."""
    while len(json.dumps(out, default=repr)) > caps["output_bytes"] and (out["imports"] or out["exports"]):
        key = "exports" if len(out["exports"]) >= len(out["imports"]) else "imports"
        out[key] = out[key][: len(out[key]) // 2]
        if "output_bytes" not in out["capped"]:
            out["capped"].append("output_bytes")
    return out


# ======================================================================================================
# Sandbox child (runs ONLY inside core/sandbox.py; pyelftools imported inside the function)
# ======================================================================================================

def elf_child(data: bytes, caps: dict[str, int] | None = None) -> dict[str, Any]:
    """c2/c3 sandbox child: parse one ELF with pyelftools 0.33 (header, segments, sections + entropy, dynamic
    tags, imported/exported dynamic symbols, symtab presence, build-id, .comment, Go buildinfo, UPX markers).
    The stream is an in-memory BytesIO: no stream_loader, no DWARF or .gnu_debuglink resolution, so no other file
    is ever opened. Each step is isolated; per-index loops keep partial results on truncated files."""
    from elftools import __version__ as pyelftools_version
    from elftools.common.exceptions import ELFError
    from elftools.elf.dynamic import DynamicSection, DynamicSegment
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import NoteSection, SymbolTableSection
    from elftools.elf.segments import InterpSegment, NoteSegment, Segment

    caps = {**CAPS, **(caps or {})}
    stream = io.BytesIO(data)
    length = len(data)
    budget = [caps["entropy_budget"]]
    try:
        elf = ELFFile(stream)
    except ELFError as exc:
        return {"source": "pyelftools", "version": pyelftools_version, "size": length, "error": "ELFError",
                "message": str(exc)[:300]}
    except Exception as exc:  # noqa: BLE001 - hostile headers raise assorted struct/construct errors
        return {"source": "pyelftools", "version": pyelftools_version, "size": length, "error": type(exc).__name__,
                "message": str(exc)[:300]}
    out: dict[str, Any] = {"source": "pyelftools", "version": pyelftools_version, "size": length, "header": {},
                           "interpreter": None, "segments": [], "sections": [], "dynamic": {}, "imports": [],
                           "exports": [], "imports_total": 0, "exports_total": 0, "symtab": {"present": False},
                           "build_id": None, "comment": [], "go_buildinfo": False, "upx": upx_markers(data),
                           "errors": [], "capped": []}

    def s_(v: Any, n: int = caps["name_len"]) -> Any:
        if isinstance(v, bytes):
            v = v.decode("utf-8", "replace")
        return v[:n] if isinstance(v, str) else v

    def step(name: str, fn: Any) -> None:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - recorded, partial result kept
            out["errors"].append({"step": name, "error": f"{type(exc).__name__}: {str(exc)[:200]}"})

    def header() -> None:
        h = elf.header
        out["header"] = {"class": h["e_ident"]["EI_CLASS"], "data": h["e_ident"]["EI_DATA"],
                         "osabi": h["e_ident"]["EI_OSABI"], "abiversion": h["e_ident"]["EI_ABIVERSION"],
                         "type": h["e_type"], "machine": h["e_machine"], "machine_arch": elf.get_machine_arch(),
                         "entry": h["e_entry"], "flags": h["e_flags"], "phnum": h["e_phnum"], "shnum": h["e_shnum"],
                         "shoff": h["e_shoff"], "shstrndx": h["e_shstrndx"], "phoff": h["e_phoff"],
                         "phentsize": h["e_phentsize"], "shentsize": h["e_shentsize"]}

    segs: list[Any] = []

    def segments() -> None:
        n = elf.num_segments()
        failed = []
        for i in range(min(n, caps["segments"])):
            try:
                seg = elf.get_segment(i)
            except Exception as exc:  # noqa: BLE001 - e.g. DynamicSegment needs sections past EOF
                failed.append(f"{i}: {type(exc).__name__}: {str(exc)[:160]}")
                try:
                    seg = Segment(elf._get_segment_header(i), stream)  # plain header (pinned pyelftools 0.33)
                except Exception:  # noqa: BLE001 - header itself unreadable
                    continue
            segs.append(seg)
            item = {"type": seg["p_type"], "offset": seg["p_offset"], "vaddr": seg["p_vaddr"],
                    "filesz": seg["p_filesz"], "memsz": seg["p_memsz"], "flags": seg["p_flags"]}
            if seg["p_type"] in ("PT_LOAD", "PT_INTERP", "PT_DYNAMIC", "PT_NOTE") and seg["p_filesz"]:
                item["oob"] = seg["p_offset"] + seg["p_filesz"] > length
            if seg["p_type"] == "PT_LOAD" and seg["p_filesz"]:
                item["entropy"] = region_entropy(data, seg["p_offset"], seg["p_filesz"], budget, caps)
            out["segments"].append(item)
            if isinstance(seg, InterpSegment) and out["interpreter"] is None:
                out["interpreter"] = s_(seg.get_interp_name())
        if n > caps["segments"]:
            out["capped"].append("segments")
        if failed:
            out["errors"].append({"step": "segments", "error": f"{len(failed)} segment(s) partly parsed; first: {failed[0]}"})

    secs: list[Any] = []

    def sections() -> None:
        n = elf.num_sections()
        failed = []
        for i in range(min(n, caps["sections"])):
            try:
                sec = elf.get_section(i)
                name = s_(sec.name, 64)
            except Exception as exc:  # noqa: BLE001 - header past EOF or bad shstrndx
                failed.append(f"{i}: {type(exc).__name__}: {str(exc)[:160]}")
                continue
            secs.append(sec)
            size, off = sec["sh_size"], sec["sh_offset"]
            item = {"name": name, "type": sec["sh_type"], "flags": sec["sh_flags"], "addr": sec["sh_addr"],
                    "offset": off, "size": size}
            if sec["sh_type"] != "SHT_NOBITS" and size:
                item["oob"] = off + size > length
                item["entropy"] = region_entropy(data, off, size, budget, caps)
            out["sections"].append(item)
            if name in (".go.buildinfo", ".note.go.buildid"):
                out["go_buildinfo"] = True
        if n > caps["sections"]:
            out["capped"].append("sections")
        if failed:
            out["errors"].append({"step": "sections", "error": f"{len(failed)} of {n} section(s) unreadable; first: {failed[0]}"})

    def dynamic() -> None:
        src = next((s for s in secs if isinstance(s, DynamicSection)), None) or \
            next((s for s in segs if isinstance(s, DynamicSegment)), None)
        if src is None:
            return
        d: dict[str, Any] = {"needed": [], "soname": None, "rpath": None, "runpath": None, "flags_1": None}
        for count, tag in enumerate(src.iter_tags()):
            if count >= caps["dynamic_entries"]:
                break
            t = tag.entry.d_tag
            if t == "DT_NEEDED" and len(d["needed"]) < caps["needed"]:
                d["needed"].append(s_(tag.needed))
            elif t == "DT_SONAME":
                d["soname"] = s_(tag.soname)
            elif t == "DT_RPATH":
                d["rpath"] = s_(tag.rpath, 512)
            elif t == "DT_RUNPATH":
                d["runpath"] = s_(tag.runpath, 512)
            elif t == "DT_FLAGS_1":
                d["flags_1"] = tag.entry.d_val
        out["dynamic"] = d

    def symbols() -> None:
        dynsym = next((s for s in secs if isinstance(s, SymbolTableSection) and s["sh_type"] == "SHT_DYNSYM"), None)
        source = dynsym if dynsym is not None else next((s for s in segs if isinstance(s, DynamicSegment)), None)
        if source is not None:
            for scanned, sym in enumerate(source.iter_symbols()):
                if scanned >= caps["symbol_scan"]:
                    out["capped"].append("symbol_scan")
                    break
                name = sym.name
                if not name:
                    continue
                info = sym["st_info"]
                item = {"name": s_(name), "type": info["type"], "bind": info["bind"]}
                if sym["st_shndx"] == "SHN_UNDEF":
                    out["imports_total"] += 1
                    if len(out["imports"]) < caps["imports"]:
                        out["imports"].append(item)
                elif info["bind"] in ("STB_GLOBAL", "STB_WEAK", "STB_LOOS", "STB_GNU_UNIQUE") and \
                        sym["st_other"]["visibility"] in ("STV_DEFAULT", "STV_PROTECTED"):
                    out["exports_total"] += 1
                    if len(out["exports"]) < caps["exports"]:
                        out["exports"].append(item)
            if out["imports_total"] > len(out["imports"]):
                out["capped"].append("imports")
            if out["exports_total"] > len(out["exports"]):
                out["capped"].append("exports")
        symtab = next((s for s in secs if isinstance(s, SymbolTableSection) and s["sh_type"] == "SHT_SYMTAB"), None)
        if symtab is not None:
            sample: list[str] = []
            count = 0
            for sym in symtab.iter_symbols():
                if count >= caps["symbol_scan"]:
                    break
                count += 1
                if sym.name and sym["st_info"]["bind"] == "STB_GLOBAL" and sym["st_info"]["type"] == "STT_FUNC" \
                        and len(sample) < caps["symtab_sample"]:
                    sample.append(s_(sym.name))
            out["symtab"] = {"present": True, "count": count, "globals_sample": sample}

    def notes() -> None:
        holders = [s for s in secs if isinstance(s, NoteSection)] or [s for s in segs if isinstance(s, NoteSegment)]
        for h in holders:
            for count, note in enumerate(h.iter_notes()):
                if count >= caps["notes"]:
                    break
                if note["n_type"] == "NT_GNU_BUILD_ID" and isinstance(note["n_desc"], str):
                    out["build_id"] = note["n_desc"][:128]
                    return

    def comment() -> None:
        sec = next((s for s in secs if s.name == ".comment"), None)
        if sec is None or sec["sh_type"] == "SHT_NOBITS":
            return
        raw = data[sec["sh_offset"]:sec["sh_offset"] + min(sec["sh_size"], 4096)]
        out["comment"] = [s_(x) for x in raw.split(b"\x00") if x.strip()][:caps["comment"]]

    for name, fn in (("header", header), ("segments", segments), ("sections", sections), ("dynamic", dynamic),
                     ("symbols", symbols), ("notes", notes), ("comment", comment)):
        step(name, fn)
    return fit_output(out, caps)


# ======================================================================================================
# Normalisation (prep parsers.normalize_elf_child)
# ======================================================================================================

def arch_label(machine: Any, bits: Any, endian: Any) -> str | None:
    """'x86-64 (64-bit LE)', 'MIPS (32-bit BE)'... from e_machine (number or pyelftools 'EM_*' name)."""
    num = machine if isinstance(machine, int) else _EM_NAME_TO_NUM.get(machine) if isinstance(machine, str) else None
    name = ELF_MACHINES.get(num) if num is not None else (machine if isinstance(machine, str) else None)
    if not name:
        return f"machine {num}" if isinstance(num, int) else None
    parts = [f"{bits}-bit" if bits in (32, 64) else None, {"little": "LE", "big": "BE"}.get(endian)]
    parts = [p for p in parts if p]
    return f"{name} ({' '.join(parts)})" if parts else name


def interpreter_kind(path: Any) -> str | None:
    """'standard' for the usual glibc/musl/uClibc/bionic/BSD loaders, 'nonstandard' otherwise, None if absent."""
    if not isinstance(path, str) or not path:
        return None
    return "standard" if STANDARD_INTERPRETER_RE.match(path) else "nonstandard"


def _names(items: Any, cap: int, drop: frozenset[str] = frozenset()) -> list[str]:
    out: list[str] = []
    for it in items if isinstance(items, list) else []:
        n = it.get("name") if isinstance(it, dict) else it if isinstance(it, str) else None
        if isinstance(n, str) and n and n not in out and n not in drop:
            out.append(n[:200])
        if len(out) >= cap:
            break
    return out


def elf_child_error_reason(raw: Any) -> str | None:
    """Map a parser result to a short reason (c2/c5): None when parsed, else 'not_elf', 'truncated', 'malformed'
    or 'unexpected_shape'."""
    if not isinstance(raw, dict):
        return "unexpected_shape"
    err = raw.get("error")
    if not err:
        return None
    msg = f"{err} {raw.get('message') or ''}".lower()
    if "magic number does not match" in msg or "not an elf" in msg:
        return "not_elf"
    if any(k in msg for k in ("truncated", "end of stream", "unpack requires", "expected", "stream")):
        return "truncated"
    return "malformed"


def _int(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def normalize_elf_child(raw: Any, max_symbols: int = 500) -> dict[str, Any]:
    """Parser JSON (pyelftools child or the stdlib reader) -> {'facts', 'markers', 'pivots', 'partial', 'reason'}.

    c3: architecture, interpreter, needed libraries, imported/exported symbols, section entropy, UPX markers as
    INFO hints; c5: truncated input gives partial facts plus a 'truncated' marker, never an exception. Pivots: the
    GNU build-id as a keyword with expand=False. No telfhash here (c4)."""
    reason = elf_child_error_reason(raw)
    if reason:
        return {"facts": {}, "markers": [{"id": "parse_failed", "severity": "info", "detail": reason}],
                "pivots": [], "partial": False, "reason": reason}
    h = raw.get("header") if isinstance(raw.get("header"), dict) else {}
    bits = {"ELFCLASS32": 32, "ELFCLASS64": 64}.get(h.get("class"))
    endian = {"ELFDATA2LSB": "little", "ELFDATA2MSB": "big"}.get(h.get("data"))
    etype = str(h.get("type") or "").replace("ET_", "") or None
    dyn = raw.get("dynamic") if isinstance(raw.get("dynamic"), dict) else {}
    flags_1 = _int(dyn.get("flags_1")) or 0
    interp = raw.get("interpreter") if isinstance(raw.get("interpreter"), str) else None
    sections = [s for s in raw.get("sections") or [] if isinstance(s, dict)]
    segments = [s for s in raw.get("segments") or [] if isinstance(s, dict)]
    symtab = raw.get("symtab") if isinstance(raw.get("symtab"), dict) else {}
    has_dynamic_seg = any(s.get("type") == "PT_DYNAMIC" for s in segments)
    linkage = "dynamic" if (interp or dyn.get("needed") or has_dynamic_seg) else "static"
    pie = None
    if etype == "DYN":
        pie = bool(interp) or bool(flags_1 & 0x08000000)
    elif etype == "EXEC":
        pie = False
    kind = {"EXEC": "executable", "REL": "relocatable object", "CORE": "core dump"}.get(etype or "")
    if etype == "DYN":
        kind = "pie executable" if pie else "shared object"
    imports_raw = raw.get("imports") if isinstance(raw.get("imports"), list) else []
    exports_raw = raw.get("exports") if isinstance(raw.get("exports"), list) else []
    facts = {
        "format": "ELF", "bits": bits, "endian": endian, "machine": h.get("machine"),
        "arch": arch_label(h.get("machine"), bits, endian), "elf_type": etype, "kind": kind, "pie": pie,
        "osabi": str(h.get("osabi") or "").replace("ELFOSABI_", "") or None, "entry": _int(h.get("entry")),
        "interpreter": interp, "interpreter_kind": interpreter_kind(interp), "linkage": linkage,
        "needed": _names(dyn.get("needed"), CAPS["needed"]), "soname": dyn.get("soname") if isinstance(dyn.get("soname"), str) else None,
        "rpath": dyn.get("rpath") if isinstance(dyn.get("rpath"), str) else None,
        "runpath": dyn.get("runpath") if isinstance(dyn.get("runpath"), str) else None,
        "imports": _names(imports_raw, max_symbols, TOOLCHAIN_SYMBOLS),
        "exports": _names(exports_raw, max_symbols, TOOLCHAIN_SYMBOLS),
        "imports_count": _int(raw.get("imports_total")) if _int(raw.get("imports_total")) is not None else len(imports_raw),
        "exports_count": _int(raw.get("exports_total")) if _int(raw.get("exports_total")) is not None else len(exports_raw),
        "stripped": not bool(symtab.get("present")), "symtab_globals": _names(symtab.get("globals_sample"), 100),
        "section_count": len(sections), "segment_count": len(segments),
        "sections": [{"name": s.get("name"), "type": s.get("type"), "size": s.get("size"), "entropy": s.get("entropy")}
                     for s in sections],
        "build_id": raw.get("build_id") if isinstance(raw.get("build_id"), str) else None,
        "compiler_comment": [c for c in raw.get("comment") or [] if isinstance(c, str)][:5],
        "go_buildinfo": bool(raw.get("go_buildinfo")),
        "size": _int(raw.get("size")),
    }
    markers: list[dict[str, Any]] = []
    for s in sections:
        ent, size = s.get("entropy"), s.get("size")
        if isinstance(ent, (int, float)) and isinstance(size, int) and size >= MIN_ENTROPY_BYTES and ent >= HIGH_ENTROPY:
            markers.append({"id": "high_entropy_section", "severity": "info",
                            "detail": f"{s.get('name')}: {ent:.2f} bits/byte over {size} B"})
    if not sections and h.get("shnum") == 0:
        markers.append({"id": "no_section_headers", "severity": "info",
                        "detail": "no section header table (typical of packed or hand-crafted binaries)"})
        for s in segments:
            ent, size = s.get("entropy"), s.get("filesz")
            if isinstance(ent, (int, float)) and isinstance(size, int) and size >= MIN_ENTROPY_BYTES and ent >= HIGH_ENTROPY:
                markers.append({"id": "high_entropy_segment", "severity": "info",
                                "detail": f"{s.get('type')} @0x{_int(s.get('offset')) or 0:x}: {ent:.2f} bits/byte"})
    upx = raw.get("upx") if isinstance(raw.get("upx"), dict) else {}
    if upx.get("magic_offsets") or upx.get("info_banner"):
        ver = f" {upx['version']}" if isinstance(upx.get("version"), str) else ""
        markers.append({"id": "upx_packed", "severity": "info",
                        "detail": f"UPX{ver} markers: {len(upx.get('magic_offsets') or [])} x 'UPX!'"
                                  + (", '$Info' banner" if upx.get("info_banner") else "")})
    elif any(m["id"] == "high_entropy_segment" for m in markers):
        markers.append({"id": "packed_unknown", "severity": "info",
                        "detail": "no sections + high-entropy segment without UPX markers (patched or other packer)"})
    if facts["interpreter_kind"] == "nonstandard":
        markers.append({"id": "nonstandard_interpreter", "severity": "info", "detail": interp})
    errors = [e for e in raw.get("errors") or [] if isinstance(e, dict)]
    size = facts["size"]
    tables_past_eof = False
    if size is not None:
        for off_k, num_k, ent_k in (("shoff", "shnum", "shentsize"), ("phoff", "phnum", "phentsize")):
            o, n, en = _int(h.get(off_k)), _int(h.get(num_k)), _int(h.get(ent_k))
            if o is not None and n and en is not None and o + n * en > size:
                tables_past_eof = True
    eof_text = any(k in str(e.get("error", "")).lower() for e in errors
                   for k in ("past eof", "end of stream", "unpack requires", "truncated"))
    oob = [s.get("name") for s in sections if s.get("oob")] + [s.get("type") for s in segments if s.get("oob")]
    truncated = tables_past_eof or eof_text
    if truncated:
        markers.append({"id": "truncated", "severity": "info",
                        "detail": "file shorter than its headers claim (section/program header table or data past "
                                  "EOF): partial results"})
    elif oob:
        markers.append({"id": "out_of_bounds", "severity": "info",
                        "detail": "header points past EOF: " + ", ".join(map(str, oob[:5]))})
    for e in errors[:10]:
        markers.append({"id": "parse_error", "severity": "info", "detail": f"{e.get('step')}: {str(e.get('error'))[:160]}"})
    capped = [str(c) for c in raw.get("capped") or []]
    if capped:
        markers.append({"id": "output_capped", "severity": "info", "detail": ", ".join(capped)})
    pivots = []
    if facts["build_id"] and re.fullmatch(r"[0-9a-f]{16,128}", facts["build_id"]):
        pivots.append({"type": "keyword", "value": facts["build_id"], "relation": "has_build_id", "expand": False})
    return {"facts": facts, "markers": markers, "pivots": pivots, "partial": bool(errors or truncated), "reason": None}


def elf_summary(facts: dict[str, Any], markers: list[dict[str, Any]]) -> str:
    """One plain-language line (attribute elf_summary)."""
    parts = [f"{'truncated ' if any(m['id'] == 'truncated' for m in markers) else ''}ELF{facts.get('bits') or ''} "
             f"{facts.get('kind') or facts.get('elf_type') or 'file'}", facts.get("arch") or "unknown architecture"]
    if facts.get("linkage") == "dynamic":
        interp = facts.get("interpreter")
        parts.append("dynamically linked" + (f" (interpreter {interp})" if interp else ""))
    else:
        parts.append("statically linked")
    parts.append(f"{len(facts.get('needed') or [])} needed librar{'y' if len(facts.get('needed') or []) == 1 else 'ies'}, "
                 f"{facts.get('imports_count') or 0} imports, {facts.get('exports_count') or 0} exports")
    parts.append("stripped" if facts.get("stripped") else "not stripped")
    hints = sorted({m["id"] for m in markers if m["id"] in ("upx_packed", "packed_unknown", "high_entropy_section",
                                                             "high_entropy_segment", "no_section_headers",
                                                             "nonstandard_interpreter")})
    if hints:
        parts.append("hints: " + ", ".join(h.replace("_", " ") for h in hints))
    return ", ".join(parts)


# ======================================================================================================
# The module
# ======================================================================================================

STDLIB_NOTE = ("bounded standard-library ELF reader in process (core/sandbox.py is not in this build; pyelftools "
               "is never run in process)")


def parse_input(data: bytes, path: str) -> tuple[dict[str, Any], str]:
    """(raw dump, parser note): pyelftools (or the stdlib reader) in the core sandbox when it exists (c2), else the
    bounded stdlib reader in process. Raises RuntimeError('<code>|<reason>') when the sandbox run failed."""
    if core_sandbox() is not None:
        target = "elf_child" if package_available("elftools") else "parse_elf"
        try:
            out = sandbox_run(f"{__name__}:{target}", path, **PARSER_LIMITS)
        except SandboxUnavailable:
            return parse_elf(data), STDLIB_NOTE
        if not out.get("ok"):
            code, reason = sandbox_failure(out)
            raise RuntimeError(f"{code}|{reason}")
        raw = out.get("result")
        lib = "pyelftools" if target == "elf_child" else "bounded standard-library ELF reader"
        return (raw if isinstance(raw, dict) else {"error": "ELFError", "message": "no result object"}), \
            f"{lib} in the sandbox ({out.get('isolation') or 'isolated'})"
    return parse_elf(data), STDLIB_NOTE


_MARKER_FINDINGS: dict[str, tuple[str, str]] = {
    "upx_packed": ("UPX packer markers", "UPX markers ('UPX!' magic and/or the $Info/$Id banner)"),
    "packed_unknown": ("Packed ELF hint (unknown packer)", "no section headers and a high-entropy segment without UPX markers"),
    "high_entropy_section": ("High-entropy ELF sections or segments", "entropy >= 7.2 bits/byte over >= 512 bytes"),
    "high_entropy_segment": ("High-entropy ELF sections or segments", "entropy >= 7.2 bits/byte over >= 512 bytes"),
    "no_section_headers": ("ELF without section headers", "e_shnum = 0"),
    "nonstandard_interpreter": ("Non-standard ELF interpreter", "PT_INTERP outside the usual glibc/musl/uClibc/bionic/BSD loaders"),
    "truncated": ("Malformed or truncated ELF structures", "header tables or data past EOF"),
    "out_of_bounds": ("Malformed or truncated ELF structures", "a header points past EOF"),
    "parse_error": ("Malformed or truncated ELF structures", "a parsing step failed"),
}


@register
class ElfTriage(Module):
    name = "elf_triage"
    title = "ELF triage (architecture, interpreter, libraries, symbols, entropy, UPX hints)"
    description = (
        "Static triage of a local Linux/IoT ELF file offline: architecture, kind, interpreter, needed libraries, "
        "imported and exported symbols, section entropy, GNU build-id and UPX/packer hints (INFO). The sample is "
        "parsed, never executed."
    )
    category = "file_analysis"
    accepts = {T.FILE}
    produces = {T.KEYWORD}
    reference = "https://github.com/eliben/pyelftools"
    tags = {"offline"}
    notice = (
        "Static parsing only: the sample is never executed. Packer and entropy markers are INFO hints, never "
        "verdicts. telfhash is not computed here: it comes from the YARAify/MalwareBazaar modules under their "
        "licence decision."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # c1: no network at all
    hosts = ()
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.5
    timeout = 60.0
    max_pivots = 5
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return read_head(entity.value, 4) == b"\x7fELF"

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        try:
            data = read_regular_file(entity.value, MAX_INPUT)
        except InputRefused as exc:
            return res.mark(exc.status, str(exc), reason_code=exc.code)
        pre = elf_preflight(data)
        if pre["reason"] == "not_elf":
            return res.mark(Status.SKIPPED, "not an ELF file", reason_code="not_applicable")
        if not pre["ok"]:
            res.raw = {"preflight": pre}
            return res.mark(Status.ERROR, f"malformed or truncated ELF ({pre['reason'].replace('_', ' ')}): could not parse",
                            reason_code="error")
        try:
            raw, parser = parse_input(data, entity.value)
        except RuntimeError as exc:
            code, _, reason = str(exc).partition("|")
            return res.mark(Status.ERROR, reason or str(exc), reason_code=code if code in ("timeout", "error") else "error")
        norm = normalize_elf_child(raw)
        if norm["reason"] == "not_elf":
            return res.mark(Status.SKIPPED, "not an ELF file", reason_code="not_applicable")
        if norm["reason"]:
            res.raw = {"parser": parser, "error": raw.get("message") if isinstance(raw, dict) else None}
            return res.mark(Status.ERROR, f"malformed or truncated ELF ({norm['reason']}): could not parse", reason_code="error")
        self.emit(res, norm, raw, parser, hashlib.sha256(data).hexdigest())
        return res

    def emit(self, res: ModuleResult, norm: dict[str, Any], raw: dict[str, Any], parser: str, sha256: str) -> None:
        f, markers = norm["facts"], norm["markers"]
        summary = elf_summary(f, markers)
        res.attr("elf_summary", summary)
        res.attr("file_type", f"ELF{f.get('bits') or ''} {f.get('kind') or f.get('elf_type') or 'file'}")
        res.attr("sha256", sha256)
        res.attr("elf_arch", f.get("arch"))
        res.attr("elf_kind", f.get("kind"))
        res.attr("elf_interpreter", f.get("interpreter"))
        res.attr("elf_linkage", f.get("linkage"))
        res.attr("elf_needed", f.get("needed"))
        res.attr("elf_dynamic", {k: v for k, v in {"soname": f.get("soname"), "rpath": f.get("rpath"),
                                                    "runpath": f.get("runpath"), "pie": f.get("pie")}.items() if v is not None})
        res.attr("elf_imports", f.get("imports"))
        res.attr("elf_exports", f.get("exports"))
        res.attr("elf_symbols", {"imports_count": f.get("imports_count"), "exports_count": f.get("exports_count"),
                                 "stripped": f.get("stripped"), "symtab_globals": f.get("symtab_globals") or None})
        res.attr("elf_sections", f.get("sections")[:96])
        res.attr("elf_build_id", f.get("build_id"))
        res.attr("elf_compiler", f.get("compiler_comment"))
        res.attr("elf_markers", [{"id": m["id"], "detail": m["detail"]} for m in markers])
        res.finding("ELF triage", "info", summary + ".", tags=["info"],
                    data={"kind": f.get("kind"), "arch": f.get("arch"), "linkage": f.get("linkage"),
                          "imports": f.get("imports_count"), "exports": f.get("exports_count"),
                          "sections": f.get("section_count"), "parser": parser, "partial": norm["partial"]})
        grouped: dict[str, list[str]] = {}
        crit: dict[str, str] = {}
        for m in markers:
            spec = _MARKER_FINDINGS.get(m["id"])
            if spec is None:
                continue
            grouped.setdefault(spec[0], []).append(str(m["detail"]))
            crit.setdefault(spec[0], spec[1])
        for title, details in grouped.items():
            packer = title in ("UPX packer markers", "Packed ELF hint (unknown packer)", "High-entropy ELF sections or segments")
            tags = ["info", "elf_hint"] + (["packer_hint", "context_only"] if packer else [])
            res.finding(title, "info", "; ".join(details[:8]) + ". Context, not a verdict (" + crit[title] + ").",
                        tags=tags, data={"details": details[:20]})
        for p in norm["pivots"]:
            res.pivot(T.KEYWORD, p["value"], "has_build_id", confidence="confirmed", expand=False,
                      note="GNU build-id of the sample: a sample identifier, listed, never sent anywhere automatically")
        res.raw = {"parser": parser, "summary": summary, "header": raw.get("header"),
                   "segments": (raw.get("segments") or [])[:64], "errors": raw.get("errors"), "capped": raw.get("capped"),
                   "upx": raw.get("upx"), "imports_total": raw.get("imports_total"), "exports_total": raw.get("exports_total"),
                   "symtab_count": (raw.get("symtab") or {}).get("count")}
