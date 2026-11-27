"""elf_triage (P368): ELF triage offline (bounded stdlib reader; pyelftools only in the core sandbox).

c5 fixtures (tests/fixtures/elf_triage/): small benign ELF files built by the stdlib builder below (filler bytes, no
real instructions: nothing runnable; the test checks the stored files are byte-identical to fresh builds), a
gcc-built benign 'hello' (stripped, never executed), its first 1024 bytes (truncated) and first 40 bytes (cut
header), a hostile section header pointing past EOF, a synthetic UPX-like layout and a copy with the markers
patched out, and a shell script. child_*.json are pyelftools 0.33's output (prep, sandbox-like rlimits) for each:
the oracle of the stdlib reader. Offline module: no request is ever made.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.file_analysis import elf_triage as et
from v3lum.modules.file_analysis.elf_triage import ElfTriage
from v3lum.modules.geo_image_meta import image_metadata as im

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "elf_triage"
ELF_FIXTURES = ("ok_x86_64_pie_gcc.elf", "ok_built_x86_64_dyn.elf", "ok_mips_be_static.elf", "ok_aarch64_static_symtab.elf",
                "malformed_oob_section.elf", "upx_like_arm.elf", "packed_patched_magic_arm.elf", "truncated.elf",
                "truncated_header.elf", "not_elf.txt")

# ======================================================================================================
# Stdlib builder of benign, never-executed ELF images (prep code/elfbuild.py; condition 5)
# ======================================================================================================

EM = {"386": 3, "MIPS": 8, "ARM": 40, "X86_64": 62, "AARCH64": 183}
ET_EXEC, ET_DYN = 2, 3
SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_DYNAMIC, SHT_NOTE, SHT_NOBITS, SHT_DYNSYM = 1, 2, 3, 6, 7, 8, 11
SHF_WRITE, SHF_ALLOC, SHF_EXEC = 1, 2, 4
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE, PT_PHDR, PT_GNU_STACK = 1, 2, 3, 4, 6, 0x6474E551
DT_NULL, DT_NEEDED, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT, DT_SONAME, DT_FLAGS_1 = 0, 1, 5, 6, 10, 11, 14, 0x6FFFFFFB
STB_LOCAL, STB_GLOBAL, STT_OBJECT, STT_FUNC = 0, 1, 1, 2


def prng_bytes(n: int, seed: bytes = b"v3lum-fixture") -> bytes:
    """Deterministic high-entropy filler (SHA-256 counter mode)."""
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(seed + i.to_bytes(8, "little")).digest()
        i += 1
    return bytes(out[:n])


class _Strtab:
    def __init__(self) -> None:
        self.data = bytearray(b"\x00")
        self.index: dict[str, int] = {"": 0}

    def add(self, s: str) -> int:
        if s not in self.index:
            self.index[s] = len(self.data)
            self.data += s.encode() + b"\x00"
        return self.index[s]


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def build_elf(*, bits=64, little=True, machine=EM["X86_64"], etype=ET_EXEC, e_flags=0, osabi=0, interp=None, needed=(),
              soname=None, imports=(), exports=(), pie=False, text=b"\x00" * 64, rodata=b"", data=b"", bss_size=0,
              build_id=None, comment=None, symtab=(), extra_sections=(), base=None) -> bytes:
    e = "<" if little else ">"
    is64 = bits == 64
    ehsize, phentsize, shentsize = (64, 56, 64) if is64 else (52, 32, 40)
    symsize, dynsize = (24, 16) if is64 else (16, 8)
    if base is None:
        base = 0 if etype == ET_DYN else (0x400000 if is64 else 0x10000)
    dynamic = bool(needed or soname or imports or exports or interp)
    secs: list[dict] = []

    def add(name, stype, flags, payload, align=1, entsize=0, link=None, info=0, fake_size=None):
        secs.append({"name": name, "type": stype, "flags": flags, "data": payload, "align": align, "entsize": entsize,
                     "link": link, "info": info, "fake_size": fake_size})

    if interp:
        add(".interp", SHT_PROGBITS, SHF_ALLOC, interp.encode() + b"\x00")
    if build_id is not None:
        add(".note.gnu.build-id", SHT_NOTE, SHF_ALLOC, struct.pack(e + "III", 4, len(build_id), 3) + b"GNU\x00" + build_id, align=4)
    dynstr = _Strtab()
    if dynamic:
        for lib in needed:
            dynstr.add(lib)
        if soname:
            dynstr.add(soname)
        for n in list(imports) + list(exports):
            dynstr.add(n)
        add(".dynsym", SHT_DYNSYM, SHF_ALLOC, b"", align=8 if is64 else 4, entsize=symsize, link=".dynstr", info=1)
        add(".dynstr", SHT_STRTAB, SHF_ALLOC, bytes(dynstr.data))
    add(".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXEC, text, align=16)
    if rodata:
        add(".rodata", SHT_PROGBITS, SHF_ALLOC, rodata, align=8)
    if dynamic:
        add(".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, b"", align=8 if is64 else 4, entsize=dynsize, link=".dynstr")
    if data:
        add(".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, data, align=8)
    if bss_size:
        add(".bss", SHT_NOBITS, SHF_ALLOC | SHF_WRITE, b"", align=8, fake_size=bss_size)
    for name, stype, flags, payload, fake in extra_sections:
        add(name, stype, flags, payload, align=4, fake_size=fake)
    if comment:
        add(".comment", SHT_PROGBITS, 0, comment.encode() + b"\x00", entsize=1)
    strtab = _Strtab()
    if symtab:
        for n, _t, _b in symtab:
            strtab.add(n)
        add(".symtab", SHT_SYMTAB, 0, b"", align=8 if is64 else 4, entsize=symsize, link=".strtab",
            info=1 + sum(1 for s in symtab if s[2] == "LOCAL"))
        add(".strtab", SHT_STRTAB, 0, bytes(strtab.data))
    shstr = _Strtab()
    for s in secs:
        shstr.add(s["name"])
    shstr.add(".shstrtab")
    add(".shstrtab", SHT_STRTAB, 0, bytes(shstr.data))

    kinds = (["PHDR"] if dynamic and interp else []) + (["INTERP"] if interp else []) + ["LOAD_RX", "LOAD_RW"]
    kinds += (["DYNAMIC"] if dynamic else []) + (["NOTE"] if build_id is not None else []) + ["GNU_STACK"]
    phoff = ehsize
    off = phoff + phentsize * len(kinds)
    n_dynsym = 1 + len(imports) + len(exports) if dynamic else 0
    dyn_entries = len(needed) + (1 if soname else 0) + 4 + (1 if pie else 0) + 1 if dynamic else 0
    for s in secs:
        if s["name"] == ".dynsym":
            s["data"] = b"\x00" * (symsize * n_dynsym)
        elif s["name"] == ".dynamic":
            s["data"] = b"\x00" * (dynsize * dyn_entries)
        elif s["name"] == ".symtab":
            s["data"] = b"\x00" * (symsize * (1 + len(symtab)))
    rw_started = False
    for s in secs:
        if s["flags"] & SHF_WRITE and not rw_started:
            off = _align(off, 0x10)
            rw_started = True
        off = _align(off, s["align"])
        s["offset"] = off
        s["addr"] = base + off if s["flags"] & SHF_ALLOC else 0
        if s["type"] != SHT_NOBITS:
            off += len(s["data"])
    idx = {s["name"]: i + 1 for i, s in enumerate(secs)}
    addr = {s["name"]: s["addr"] for s in secs}

    def sym(name_off, value, size, bind, typ, shndx):
        if is64:
            return struct.pack(e + "IBBHQQ", name_off, (bind << 4) | typ, 0, shndx, value, size)
        return struct.pack(e + "IIIBBH", name_off, value, size, (bind << 4) | typ, 0, shndx)

    for s in secs:
        if s["name"] == ".dynsym":
            out = sym(0, 0, 0, 0, 0, 0)
            for n in imports:
                out += sym(dynstr.index[n], 0, 0, STB_GLOBAL, STT_FUNC, 0)
            for i, n in enumerate(exports):
                out += sym(dynstr.index[n], addr[".text"] + 16 * i, 16, STB_GLOBAL, STT_FUNC, idx[".text"])
            s["data"] = out
        elif s["name"] == ".dynamic":
            ents = [(DT_NEEDED, dynstr.index[lib]) for lib in needed] + ([(DT_SONAME, dynstr.index[soname])] if soname else [])
            ents += [(DT_STRTAB, addr[".dynstr"]), (DT_SYMTAB, addr[".dynsym"]), (DT_STRSZ, len(dynstr.data)), (DT_SYMENT, symsize)]
            ents += ([(DT_FLAGS_1, 0x08000000)] if pie else []) + [(DT_NULL, 0)]
            s["data"] = b"".join(struct.pack(e + ("qQ" if is64 else "iI"), t, v) for t, v in ents)
        elif s["name"] == ".symtab":
            out = sym(0, 0, 0, 0, 0, 0)
            ordered = [x for x in symtab if x[2] == "LOCAL"] + [x for x in symtab if x[2] != "LOCAL"]
            for i, (n, t, b) in enumerate(ordered):
                shndx = idx[".text"] if t == "FUNC" else idx.get(".data", idx[".text"])
                out += sym(strtab.index[n], addr[".text"] + 8 * i, 8, STB_LOCAL if b == "LOCAL" else STB_GLOBAL,
                           STT_FUNC if t == "FUNC" else STT_OBJECT, shndx)
            s["data"] = out

    shoff = _align(off, 8)
    rx_end = max((s["offset"] + len(s["data"]) for s in secs if s["flags"] & SHF_ALLOC and not s["flags"] & SHF_WRITE), default=off)
    rw = [s for s in secs if s["flags"] & SHF_WRITE]
    rw_off = min((s["offset"] for s in rw), default=rx_end)
    rw_fend = max((s["offset"] + len(s["data"]) for s in rw if s["type"] != SHT_NOBITS), default=rw_off)
    rw_mend = max((s["offset"] + (s["fake_size"] or len(s["data"])) for s in rw), default=rw_off)

    def ph(ptype, flags, p_off, filesz, memsz, align):
        vaddr = base + p_off
        if is64:
            return struct.pack(e + "IIQQQQQQ", ptype, flags, p_off, vaddr, vaddr, filesz, memsz, align)
        return struct.pack(e + "IIIIIIII", ptype, p_off, vaddr, vaddr, filesz, memsz, flags, align)

    phbytes = b""
    for kind in kinds:
        if kind == "PHDR":
            phbytes += ph(PT_PHDR, 4, phoff, phentsize * len(kinds), phentsize * len(kinds), 8)
        elif kind == "INTERP":
            s = secs[idx[".interp"] - 1]
            phbytes += ph(PT_INTERP, 4, s["offset"], len(s["data"]), len(s["data"]), 1)
        elif kind == "LOAD_RX":
            phbytes += ph(PT_LOAD, 5, 0, rx_end, rx_end, 0x1000)
        elif kind == "LOAD_RW":
            phbytes += ph(PT_LOAD, 6, rw_off, rw_fend - rw_off, rw_mend - rw_off, 0x1000)
        elif kind == "DYNAMIC":
            s = secs[idx[".dynamic"] - 1]
            phbytes += ph(PT_DYNAMIC, 6, s["offset"], len(s["data"]), len(s["data"]), 8)
        elif kind == "NOTE":
            s = secs[idx[".note.gnu.build-id"] - 1]
            phbytes += ph(PT_NOTE, 4, s["offset"], len(s["data"]), len(s["data"]), 4)
        else:
            phbytes += ph(PT_GNU_STACK, 6, 0, 0, 0, 16)

    def sh(name_off, stype, flags, s_addr, s_off, size, link, info, align, entsize):
        return struct.pack(e + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII"), name_off, stype, flags, s_addr, s_off, size, link,
                           info, align, entsize)

    shbytes = sh(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    for s in secs:
        size = s["fake_size"] if s["fake_size"] is not None else len(s["data"])
        shbytes += sh(shstr.index[s["name"]], s["type"], s["flags"], s["addr"], s["offset"], size,
                      idx[s["link"]] if s["link"] else 0, s["info"], s["align"], s["entsize"])
    ident = b"\x7fELF" + bytes([2 if is64 else 1, 1 if little else 2, 1, osabi, 0]) + b"\x00" * 7
    fmt = e + ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH")
    ehdr = ident + struct.pack(fmt, etype, machine, 1, addr[".text"], phoff, shoff, e_flags, ehsize, phentsize, len(kinds),
                               shentsize, len(secs) + 1, idx[".shstrtab"])
    img = bytearray(shoff + len(shbytes))
    img[0:len(ehdr)] = ehdr
    img[phoff:phoff + len(phbytes)] = phbytes
    for s in secs:
        if s["type"] != SHT_NOBITS:
            img[s["offset"]:s["offset"] + len(s["data"])] = s["data"]
    img[shoff:shoff + len(shbytes)] = shbytes
    return bytes(img)


def build_upx_like(*, machine=EM["ARM"], little=True, e_flags=0x05000200, payload_size=6000, version="4.22") -> bytes:
    """ELF32 laid out like a UPX 4.x packed executable (synthetic markers; never produced by UPX)."""
    e = "<" if little else ">"
    ehsize, phentsize, phnum, base = 52, 32, 2, 0x8000
    l_info = struct.pack(e + "I", 0) + b"UPX!" + struct.pack(e + "HBB", 0x0E1C, 14, 23)
    p_info = struct.pack(e + "III", 0, payload_size * 3, payload_size * 3)
    banner = (b"\x00$Info: This file is packed with the UPX executable packer http://upx.sf.net $\n\x00"
              b"$Id: UPX " + version.encode() + b" Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $\n\x00")
    pack_header = b"UPX!" + bytes([14, 23, 14, 9]) + prng_bytes(24, b"v3lum-upx-ph") + struct.pack(e + "I", 0)
    body = l_info + p_info + prng_bytes(payload_size, b"v3lum-upx-like") + prng_bytes(512, b"v3lum-upx-stub") + banner
    total = ehsize + phentsize * phnum + len(body) + len(pack_header)

    def ph(ptype, flags, p_off, vaddr, filesz, memsz, align):
        return struct.pack(e + "IIIIIIII", ptype, p_off, vaddr, vaddr, filesz, memsz, flags, align)

    phbytes = ph(PT_LOAD, 5, 0, base, total, total, 0x10000) + ph(PT_LOAD, 6, 0, base + 0x100000, 0, payload_size * 4, 0x10000)
    ident = b"\x7fELF" + bytes([1, 1 if little else 2, 1, 3, 0]) + b"\x00" * 7
    ehdr = ident + struct.pack(e + "HHIIIIIHHHHHH", ET_EXEC, machine, 1, base + ehsize + phentsize * phnum + 64, ehsize, 0,
                               e_flags, ehsize, phentsize, phnum, 40, 0, 0)
    return ehdr + phbytes + body + pack_header


def built_dyn() -> bytes:
    """The 'small benign ELF built in tests' (c5): PIE, interpreter, DT_NEEDED, 3 imports, 1 export, build-id."""
    return build_elf(etype=ET_DYN, interp="/lib64/ld-linux-x86-64.so.2", needed=("libc.so.6",), pie=True,
                     imports=("puts", "getenv", "strlen"), exports=("v3lum_fixture_export",), build_id=bytes(range(20)),
                     comment="GCC: (V3LUM fixture builder) 0.1", rodata=b"v3lum benign ELF fixture\x00",
                     data=b"\x01\x02\x03\x04" * 4)


BUILDS = {
    "ok_built_x86_64_dyn.elf": built_dyn,
    "ok_mips_be_static.elf": lambda: build_elf(bits=32, little=False, machine=EM["MIPS"], e_flags=0x1007, text=b"\x00" * 256,
                                               rodata=b"v3lum benign fixture\x00/proc/self\x00",
                                               data=prng_bytes(4096, b"v3lum-mips-table"), bss_size=512),
    "ok_aarch64_static_symtab.elf": lambda: build_elf(machine=EM["AARCH64"], text=b"\x1f\x20\x03\xd5" * 32,
                                                      symtab=(("helper_local", "FUNC", "LOCAL"), ("main", "FUNC", "GLOBAL"),
                                                              ("v3lum_fixture_init", "FUNC", "GLOBAL"),
                                                              ("v3lum_fixture_loop", "FUNC", "GLOBAL"))),
    "malformed_oob_section.elf": lambda: build_elf(extra_sections=((".v3lum_oob", 1, 2, b"\xcc" * 16, 0x7FFFFFFF),)),
    "upx_like_arm.elf": build_upx_like,
}

# ======================================================================================================
# Tests
# ======================================================================================================


def run(path, **kw):
    http = FakeHttp()
    res = run_module(ElfTriage, Entity.make(T.FILE, str(path)), http, **kw)
    assert http.calls == [] and res.requests == 0  # c1: offline, never executed
    return res


def write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return p


@pytest.mark.parametrize("name", sorted(BUILDS))
def test_builder_reproduces_the_stored_fixtures(name):  # c5: CI needs no compiler
    assert BUILDS[name]() == (FIX / name).read_bytes()


def test_patched_fixture_is_the_upx_layout_without_markers():
    import re

    patched = build_upx_like().replace(b"UPX!", b"\x00" * 4).replace(b"$Info: This file is packed with the UPX",
                                                                     b"$Info: " + b"." * 32)
    patched = re.sub(rb"\$Id: UPX [0-9.]+", b"$Id: ........", patched)
    assert patched == (FIX / "packed_patched_magic_arm.elf").read_bytes()


@pytest.mark.parametrize("name", ELF_FIXTURES)
def test_stdlib_reader_matches_pyelftools(name):  # c2/c3: same normalised facts as pyelftools 0.33
    stem = name.rsplit(".", 1)[0]
    ref = et.normalize_elf_child(module_fixture("elf_triage", f"child_{stem}.json"))
    mine = et.normalize_elf_child(et.parse_elf((FIX / name).read_bytes()))
    assert mine["facts"] == ref["facts"]
    assert {m["id"] for m in mine["markers"]} == {m["id"] for m in ref["markers"]}
    assert mine["pivots"] == ref["pivots"] and mine["reason"] == ref["reason"]


def test_gcc_pie_executable():
    res = run(FIX / "ok_x86_64_pie_gcc.elf")
    a = res.attributes
    assert res.status is Status.OK
    assert a["elf_arch"] == "x86-64 (64-bit LE)" and a["elf_kind"] == "pie executable" and a["elf_linkage"] == "dynamic"
    assert a["elf_interpreter"] == "/lib64/ld-linux-x86-64.so.2" and a["elf_needed"] == ["libc.so.6"]
    assert "getenv" in a["elf_imports"] and "__libc_start_main" not in a["elf_imports"]  # CRT noise hidden, counted
    assert a["elf_symbols"]["stripped"] is True and a["elf_symbols"]["imports_count"] >= len(a["elf_imports"])
    assert a["sha256"] == hashlib.sha256((FIX / "ok_x86_64_pie_gcc.elf").read_bytes()).hexdigest()
    assert a["elf_summary"].startswith("ELF64 pie executable, x86-64 (64-bit LE), dynamically linked")
    assert any(s["name"] == ".text" and isinstance(s["entropy"], float) for s in a["elf_sections"])
    piv = res.pivots[0]
    assert (piv.entity.type, piv.relation, piv.expand) == (T.KEYWORD, "has_build_id", False)
    assert piv.entity.value == a["elf_build_id"] and len(piv.entity.value) == 40
    assert [f.title for f in res.findings] == ["ELF triage"]
    assert all(f.severity.name == "INFO" for f in res.findings)


def test_small_benign_elf_built_in_the_test(tmp_path):  # c5
    res = run(write(tmp_path, "built.elf", built_dyn()))
    a = res.attributes
    assert a["elf_imports"] == ["puts", "getenv", "strlen"] and a["elf_exports"] == ["v3lum_fixture_export"]
    assert a["elf_dynamic"]["pie"] is True and a["elf_compiler"] == ["GCC: (V3LUM fixture builder) 0.1"]
    assert res.pivots[0].entity.value == bytes(range(20)).hex()


def test_iot_style_mips_static_with_high_entropy_data():
    res = run(FIX / "ok_mips_be_static.elf")
    a = res.attributes
    assert a["elf_arch"] == "MIPS (32-bit BE)" and a["elf_linkage"] == "static" and a["elf_kind"] == "executable"
    assert "high_entropy_section" in {m["id"] for m in a["elf_markers"]}
    f = next(f for f in res.findings if f.title == "High-entropy ELF sections or segments")
    assert f.severity.name == "INFO" and {"packer_hint", "context_only"} <= set(f.tags)  # c3: hints, never verdicts


def test_unstripped_aarch64_lists_symtab_globals():
    a = run(FIX / "ok_aarch64_static_symtab.elf").attributes
    assert a["elf_symbols"]["stripped"] is False
    assert a["elf_symbols"]["symtab_globals"] == ["main", "v3lum_fixture_init", "v3lum_fixture_loop"]


def test_upx_markers_are_info_hints():
    res = run(FIX / "upx_like_arm.elf")
    ids = {m["id"] for m in res.attributes["elf_markers"]}
    assert {"upx_packed", "no_section_headers", "high_entropy_segment"} <= ids and "packed_unknown" not in ids
    f = next(f for f in res.findings if f.title == "UPX packer markers")
    assert f.severity.name == "INFO" and "UPX 4.22" in f.description and "not a verdict" in f.description
    assert res.attributes["elf_arch"] == "ARM (32-bit LE)"


def test_patched_upx_gives_the_structural_hint_only():
    ids = {m["id"] for m in run(FIX / "packed_patched_magic_arm.elf").attributes["elf_markers"]}
    assert "upx_packed" not in ids and {"packed_unknown", "high_entropy_segment"} <= ids


def test_truncated_file_keeps_partial_results():  # c5: a truncated ELF
    res = run(FIX / "truncated.elf")
    a = res.attributes
    assert res.status is Status.OK and a["elf_interpreter"] == "/lib64/ld-linux-x86-64.so.2"
    assert a["elf_build_id"] == "7c33fea49cce50359ffbfa6aed1ad1a90b5467ac"  # from PT_NOTE although sections are gone
    assert "truncated" in {m["id"] for m in a["elf_markers"]} and a["elf_summary"].startswith("truncated ELF64")
    assert any(f.title == "Malformed or truncated ELF structures" for f in res.findings)


def test_hostile_section_size_is_out_of_bounds_not_a_crash():
    res = run(FIX / "malformed_oob_section.elf")
    ids = {m["id"] for m in res.attributes["elf_markers"]}
    assert res.status is Status.OK and "out_of_bounds" in ids
    oob = next(s for s in res.attributes["elf_sections"] if s["name"] == ".v3lum_oob")
    assert oob["size"] == 0x7FFFFFFF and oob["entropy"] is not None


def test_cut_header_is_an_error_never_empty():
    res = run(FIX / "truncated_header.elf")
    assert res.status is Status.ERROR and "truncated header" in res.error and not res.attributes


@pytest.mark.parametrize("data,why", [(b"\x7fELF\x03\x01\x01" + b"\x00" * 60, "malformed header"), (b"\x7fELF", "truncated header")])
def test_malformed_headers(tmp_path, data, why):
    res = run(write(tmp_path, "bad.elf", data))
    assert res.status is Status.ERROR and why in res.error


def test_non_elf_and_special_files_are_not_applicable(tmp_path):
    assert run(FIX / "not_elf.txt").status is Status.SKIPPED
    gone = write(tmp_path, "gone.elf", built_dyn())
    entity = Entity.make(T.FILE, str(gone))
    gone.unlink()  # vanished between detection and the run: not applicable, never a crash
    res = run_module(ElfTriage, entity, FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_input_cap_is_enforced(tmp_path, monkeypatch):
    monkeypatch.setattr(et, "MAX_INPUT", 64)
    p = write(tmp_path, "big.elf", built_dyn())
    res = run(p)
    assert res.status is Status.ERROR and "analysis cap" in res.error


def test_symbol_and_section_caps(tmp_path):
    imports = tuple(f"imp_{i}" for i in range(40))
    data = build_elf(etype=ET_DYN, interp="/lib/ld-musl-x86_64.so.1", imports=imports, exports=("a", "b"))
    raw = et.parse_elf(data, caps={"imports": 10, "sections": 4})
    assert raw["imports_total"] == 40 and len(raw["imports"]) == 10 and {"imports", "sections"} <= set(raw["capped"])
    norm = et.normalize_elf_child(raw)
    assert "output_capped" in {m["id"] for m in norm["markers"]} and norm["facts"]["interpreter_kind"] == "standard"
    small = et.fit_output({**raw, "imports": raw["imports"] * 1000}, {**et.CAPS, "output_bytes": 4096})
    assert len(json.dumps(small)) <= 4096 + 512 and "output_bytes" in small["capped"]


def test_dynamic_symbols_without_section_headers(tmp_path):
    """sstrip-style binaries: no section table, symbols found through PT_DYNAMIC + DT_HASH."""
    data = bytearray(build_elf(etype=ET_DYN, interp="/lib64/ld-linux-x86-64.so.2", needed=("libc.so.6",),
                               imports=("connect", "send"), exports=("entry",)))
    # add a DT_HASH table (nbucket=1, nchain=4) and drop the section headers (e_shoff=e_shnum=0)
    raw = et.parse_elf(bytes(data))
    dyn_off = next(s["offset"] for s in raw["sections"] if s["name"] == ".dynamic")
    text = next(s for s in raw["sections"] if s["name"] == ".text")
    hash_off = text["offset"] + 32
    struct.pack_into("<IIIIIIII", data, hash_off, 1, 4, 0, 0, 0, 0, 0, 0)
    tags = []
    for i in range(8):
        tag = struct.unpack_from("<qQ", data, dyn_off + 16 * i)
        if tag[0] == 0:
            break
        tags.append(tag)
    tags[-1] = (4, text["addr"] + 32)  # replace DT_SYMENT by DT_HASH (the table keeps its size)
    for i, (t, v) in enumerate(tags):
        struct.pack_into("<qQ", data, dyn_off + 16 * i, t, v)
    struct.pack_into("<Q", data, 40, 0)  # e_shoff = 0
    struct.pack_into("<HH", data, 60, 0, 0)  # e_shnum = e_shstrndx = 0
    out = et.parse_elf(bytes(data))
    assert out["sections"] == [] and [i["name"] for i in out["imports"]] == ["connect", "send"]
    assert [i["name"] for i in out["exports"]] == ["entry"] and out["dynamic"]["needed"] == ["libc.so.6"]


def test_nonstandard_interpreter_marker(tmp_path):
    res = run(write(tmp_path, "odd.elf", build_elf(etype=ET_DYN, interp="/tmp/.x/ld.so", imports=("puts",))))
    assert "nonstandard_interpreter" in {m["id"] for m in res.attributes["elf_markers"]}
    assert any(f.title == "Non-standard ELF interpreter" for f in res.findings)


def test_parser_choice_without_and_with_the_core_sandbox(monkeypatch):
    data = built_dyn()
    raw, note = et.parse_input(data, "/nonexistent")
    assert raw["source"] == "stdlib" and "pyelftools is never run in process" in note
    calls = []

    class FakeSandbox:
        @staticmethod
        def run_sandboxed(target, path, *, args, **limits):
            calls.append((target, limits))
            return {"ok": True, "result": et.parse_elf(data), "isolation": "rlimits"}

    monkeypatch.setattr(im, "core_sandbox", lambda: FakeSandbox)
    monkeypatch.setattr(et, "core_sandbox", lambda: FakeSandbox)
    raw2, note2 = et.parse_input(data, "/x.elf")
    expect = "elf_child" if et.package_available("elftools") else "parse_elf"
    assert calls[0][0] == f"v3lum.modules.file_analysis.elf_triage:{expect}" and "in the sandbox (rlimits)" in note2
    assert calls[0][1]["wall_timeout"] == 30.0 and raw2["header"]["machine"] == "EM_X86_64"

    class FailingSandbox:
        @staticmethod
        def run_sandboxed(target, path, *, args, **limits):
            return {"ok": False, "reason_code": "timeout", "error": "wall timeout"}

    monkeypatch.setattr(im, "core_sandbox", lambda: FailingSandbox)
    monkeypatch.setattr(et, "core_sandbox", lambda: FailingSandbox)
    with pytest.raises(RuntimeError, match="timeout"):
        et.parse_input(data, "/x.elf")


def test_sandbox_timeout_is_an_error(tmp_path, monkeypatch):
    class FailingSandbox:
        @staticmethod
        def run_sandboxed(target, path, *, args, **limits):
            return {"ok": False, "reason_code": "timeout", "error": "wall timeout"}

    monkeypatch.setattr(im, "core_sandbox", lambda: FailingSandbox)
    monkeypatch.setattr(et, "core_sandbox", lambda: FailingSandbox)
    res = run(write(tmp_path, "b.elf", built_dyn()))
    assert res.status is Status.ERROR and res.reason_code == "timeout"


def test_metadata_matches_the_council():
    cls = ElfTriage
    assert cls.disclosure == "none" and cls.hosts == () and cls.terms == "open" and cls.default_enabled is True
    assert cls.trust_tier == "n/a" and str(cls.max_tlp) == "red" and cls.accepts == frozenset({T.FILE})
    assert cls.requires_packages == ()  # the stdlib reader works without the extra; pyelftools only in the sandbox
    from v3lum.core.module import OPTIONAL_PACKAGES

    assert "elftools" in OPTIONAL_PACKAGES


def test_no_telfhash_library_and_no_network_code():
    src = Path(et.__file__).read_text(encoding="utf-8")
    assert "import telfhash" not in src and "from telfhash" not in src  # c4
    assert "ctx.http" not in src  # c1: no network call at all
