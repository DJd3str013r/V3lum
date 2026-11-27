"""archive_listing (P365): listing with limits, unsafe names, encryption, MotW containers, rule 3, extraction.

Fixtures (c8) are generated in tests by tests/modules/test_p1_g12_1.py: zip/tar/tar.gz/ISO/CAB/RAR5/7z/VHD/VHDX
plus path-traversal, symlink, bomb, nested, encrypted (ZipCrypto/AES), WinRAR-trap, lure and stealer-bundle-like
samples (members are synthetic placeholders: no credential, cookie or wallet content exists anywhere). The four
tests/fixtures/archive_listing/*_real.rar files are rarfile's ISC-licensed test archives (notice
rarfile_test_archives). Offline module: the HTTP failure cases of networked modules map to corrupt containers,
limits, deadlines and oversized inputs here.
"""

from __future__ import annotations

import hashlib
import importlib.machinery
import json
import os
import stat
import sys
import tarfile
import types
from pathlib import Path

import pytest

from tests.fakes import FakeClock, FakeHttp, run_module
from tests.modules import test_p1_g12_1 as B
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.file_analysis import archive_listing as al
from v3lum.modules.file_analysis import file_type_sniff as fts
from v3lum.modules.file_analysis.archive_listing import ArchiveListing

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "archive_listing"


def run(tmp_path, name, data, **kw):
    http = FakeHttp()
    res = run_module(ArchiveListing, Entity.make(T.FILE, B.write(tmp_path, name, data)), http, **kw)
    assert http.calls == [] and res.requests == 0
    return res


def titles(res):
    return {f.title: f for f in res.findings}


def members(res):
    return {m["name"]: m for m in res.attributes.get("archive_members") or []}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hashes(res):
    return {p.entity.value for p in res.pivots if p.entity.type is T.SHA256 and p.relation == "contains"}


# ------------------------------------------------------------------ contract (c1, c5)
def test_contract_metadata():
    cls = ArchiveListing
    assert (cls.disclosure, cls.hosts, cls.provider, cls.terms, cls.access_model) == ("none", (), "", "open", "offline")
    assert cls.trust_tier == "n/a" and cls.max_tlp.value_str == "red" and cls.default_enabled is True
    assert set(cls.settings) == {"archive_listing_extract", "archive_listing_password", "archive_listing_sample_passwords"}
    assert cls.settings["archive_listing_extract"].default is False and cls.settings["archive_listing_sample_passwords"].default is False
    assert cls.requires_packages == () and cls.max_pivots == 50  # py7zr is an optional dynamic import, never required


def test_limits_are_the_approved_ones():
    lim = fts.LIMITS
    assert (lim["archive_total"], lim["archive_ratio"], lim["archive_members"], lim["archive_depth"]) == (500 << 20, 100, 10_000, 3)
    assert lim["hash_members_per_archive"] == 50


# ------------------------------------------------------------------ listing and hash pivots (c1, c7)
def test_zip_listing_and_member_hashes(tmp_path):
    res = run(tmp_path, "pacote.zip", B.zip_ok())
    assert res.status is Status.OK
    assert [f.severity.label for f in res.findings] == ["info"] and res.findings[0].title == "Archive listed: ZIP archive"
    listed = members(res)
    assert set(listed) == {"leia-me.txt", "docs/", "docs/relatorio.pdf", "nested.zip"}
    assert listed["leia-me.txt"]["sha256"] == sha(b"Conteudo de exemplo.\n") and listed["docs/relatorio.pdf"]["kind"] == "pdf"
    summary = res.attributes["archive_summary"]
    assert summary["counts"]["members"] == 4 and summary["nested"] == [{"name": "nested.zip", "kind": "zip", "members": 1}]
    assert sha(b"hello from the inner archive\n") in hashes(res)  # nested member hashed in memory (depth 1)
    assert all(p.expand and p.confidence == 1.0 for p in res.pivots)


def test_tar_and_compressed_tar(tmp_path):
    for name, data in (("a.tar", B.tar_bytes(B.TAR_MEMBERS)), ("a.tar.gz", B.tar_bytes(B.TAR_MEMBERS, mode="w:gz")),
                       ("a.tar.bz2", B.tar_bytes(B.TAR_MEMBERS, mode="w:bz2")), ("a.tar.xz", B.tar_bytes(B.TAR_MEMBERS, mode="w:xz"))):
        res = run(tmp_path, name, data)
        assert res.status is Status.OK, (name, res.error)
        assert set(members(res)) == {"leia-me.txt", "bin/tool.sh", "data/payload.bin"}, name
        assert sha(bytes(range(256))) in hashes(res)
        assert "builder" not in json.dumps([res.raw, res.attributes], default=str)  # tar owner names are dropped (personal data)
        assert titles(res)["Executables or scripts inside the archive"].severity.label == "medium"  # tool.sh


def test_iso_listing_with_joliet_names(tmp_path):
    res = run(tmp_path, "docs.iso", B.iso_ok())
    assert {"README.TXT", "docs/manual.pdf"} <= set(members(res))
    assert res.attributes["archive_summary"]["volume"]["volume_id"] == "DOCS_2026"
    assert not [f for f in res.findings if "Mark-of-the-Web" in f.title]


def test_gzip_single_stream(tmp_path):
    res = run(tmp_path, "run.sh.gz", B.gzip_named(b"#!/bin/sh\necho hi\n", "run.sh"))
    assert set(members(res)) == {"run.sh"} and sha(b"#!/bin/sh\necho hi\n") in hashes(res)


def test_at_most_50_hash_pivots(tmp_path):
    many = B.zip_bytes([{"name": f"f{i:03d}.txt", "data": f"file {i}\n".encode()} for i in range(80)])
    res = run(tmp_path, "many.zip", many)
    assert len(hashes(res)) == 50 and res.attributes["archive_summary"]["counts"]["members"] == 80


# ------------------------------------------------------------------ c2: unsafe names, links and devices
def test_path_traversal_absolute_and_drive_letter(tmp_path):
    res = run(tmp_path, "trav.zip", B.zip_traversal())
    f = titles(res)["Members with unsafe paths (never extracted)"]
    assert f.severity.label == "medium" and "unsafe_path" in f.tags
    assert set(f.data["reasons"]) == {"parent_traversal", "absolute_path", "drive_letter", "backslash_separator"}
    assert members(res)["../../etc/cron.d/evil"]["flags"] == ["parent_traversal"]


def test_zip_symlink_member(tmp_path):
    res = run(tmp_path, "sym.zip", B.zip_symlink())
    assert members(res)["link_to_hosts"]["flags"] == ["symlink"] and "sha256" not in members(res)["link_to_hosts"]


def test_tar_links_devices_and_setuid(tmp_path):
    data = B.tar_bytes([{"name": "sym", "type": tarfile.SYMTYPE, "link": "../../outside"}, {"name": "hard", "type": tarfile.LNKTYPE, "link": "x"},
                        {"name": "dev", "type": tarfile.CHRTYPE}, {"name": "fifo", "type": tarfile.FIFOTYPE},
                        {"name": "suid", "data": b"x", "mode": 0o4755}, {"name": "ok.txt", "data": b"ok"}])
    res = run(tmp_path, "links.tar", data)
    flags = {n: m["flags"] for n, m in members(res).items()}
    assert flags == {"sym": ["symlink", "link_target_escapes"], "hard": ["hardlink"], "dev": ["device_or_fifo"], "fifo": ["device_or_fifo"],
                     "suid": ["setuid_setgid"], "ok.txt": []}
    assert titles(res)["Members with unsafe paths (never extracted)"].data["reasons"]


@pytest.mark.parametrize("name,expected", [
    ("../../a", ["parent_traversal"]), ("/etc/x", ["absolute_path"]), ("C:\\x\\y", ["drive_letter", "backslash_separator"]),
    ("a\u202ecod.exe", ["rtlo_character"]), ("ok/x.txt", []), ("dir/./x", []),
])
def test_member_name_flags(name, expected):
    assert al.member_name_flags(name) == expected
    assert al.member_name_flags("l", is_symlink=True, link_target="../../etc/hostname") == ["symlink", "link_target_escapes"]


# ------------------------------------------------------------------ c2: bombs, member cap, depth
def test_ratio_bomb_member_is_not_read(tmp_path):
    res = run(tmp_path, "zeros.zip", B.zip_bomb_ratio())
    f = titles(res)["Possible decompression bomb: zeros.bin"]
    assert f.severity.label == "medium" and "archive_bomb" in f.tags and not hashes(res)


def test_declared_total_above_cap(tmp_path):
    res = run(tmp_path, "huge.zip", B.zip_declared_oversize())
    assert titles(res)["Declared uncompressed size above the 500 MB cap"].severity.label == "medium"


def test_tar_gz_bomb_stops_streaming(tmp_path):
    res = run(tmp_path, "bomb.tar.gz", B.tar_bytes([{"name": "zeros.bin", "data": b"\x00" * (8 << 20)}], mode="w:gz"))
    assert titles(res)["Possible decompression bomb: compressed stream stopped at a limit"].severity.label == "medium"
    assert res.attributes["archive_summary"]["stop"] == "ratio"


def test_member_cap(tmp_path):
    entries = [{"name": f"d/{i:05d}", "data": b"", "method": 0} for i in range(10_001)]
    res = run(tmp_path, "cap.zip", B.zip_bytes(entries))
    assert titles(res)["More than 10,000 members: listing truncated"].severity.label == "medium"
    assert len(res.attributes["archive_members"]) == al.MEMBERS_SHOWN


def test_nesting_depth_cap(tmp_path):
    res = run(tmp_path, "deep.zip", B.zip_nested_depth(4))
    found = [f for f in res.findings if f.title.startswith("Nested container beyond depth 3 not listed")]
    assert found and found[0].severity.label == "info"
    assert sha(b"deepest level\n") not in hashes(res)


def test_overlapping_entries_anomaly(tmp_path):
    res = run(tmp_path, "overlap.zip", B.zip_overlap())
    f = titles(res)["Archive structure anomalies"]
    assert f.severity.label == "medium" and "overlapping_entries" in f.data["anomalies"]


# ------------------------------------------------------------------ c4: encryption (analyst password only)
def test_encrypted_member_listed_not_decrypted(tmp_path):
    res = run(tmp_path, "amostra.zip", B.zip_encrypted_zipcrypto())
    f = titles(res)["Encrypted members listed"]
    assert f.severity.label == "info" and "analyst's archive password setting" in f.description
    assert members(res)["amostra.exe"]["encrypted"] is True and "sha256" not in members(res)["amostra.exe"]
    assert sha(B.pe32_exe()) not in hashes(res)  # never guessed: 'infected' is not tried by default


def test_analyst_password_decrypts(tmp_path):
    res = run(tmp_path, "amostra.zip", B.zip_encrypted_zipcrypto(b"s3nha-do-caso"), settings={"archive_listing_password": "s3nha-do-caso"})
    assert sha(B.pe32_exe()) in hashes(res) and members(res)["amostra.exe"]["kind"] == "pe-exe"
    assert "s3nha-do-caso" not in json.dumps([res.raw, res.attributes, [f.description for f in res.findings]], default=str)


def test_wrong_password_is_reported(tmp_path):
    res = run(tmp_path, "amostra.zip", B.zip_encrypted_zipcrypto(b"correta"), settings={"archive_listing_password": "errada"})
    assert titles(res)["Encrypted member not decrypted: amostra.exe"].severity.label == "low"
    assert sha(B.pe32_exe()) not in hashes(res)


def test_sample_passwords_only_as_explicit_option(tmp_path):
    data = B.zip_encrypted_zipcrypto(b"infected")
    assert sha(B.pe32_exe()) not in hashes(run(tmp_path, "a.zip", data))
    assert sha(B.pe32_exe()) in hashes(run(tmp_path, "b.zip", data, settings={"archive_listing_sample_passwords": True}))


def test_aes_members_are_never_decrypted(tmp_path):
    res = run(tmp_path, "aes.zip", B.zip_aes_flag(), settings={"archive_listing_password": "x"})
    assert members(res)["secret.docx"]["encryption"] == "aes" and not hashes(res)


def test_zipcrypto_checks_the_password_before_decrypting():
    blob = B.zipcrypto_encrypt(b"x" * 100, b"right", 0x42)
    with pytest.raises(fts.ArchiveLimit, match="bad_password"):
        fts.zipcrypto_decrypt(blob, b"wrong", 0x42)
    assert fts.zipcrypto_decrypt(blob, b"right", 0x42) == b"x" * 100


# ------------------------------------------------------------------ c6: rule 3 (stealer-log bundles)
def test_stealer_bundle_is_names_sizes_counts_only(tmp_path):
    res = run(tmp_path, "logs.zip", B.zip_stealer_bundle(), settings={"archive_listing_extract": True, "archive_listing_password": "x"})
    f = titles(res)["Archive looks like an infostealer log bundle (metadata only)"]
    assert f.severity.label == "medium" and "infostealer" in f.tags
    assert set(f.data["categories"]) == {"saved_logins", "browser_sessions", "form_data", "system_info", "wallets", "screenshots"}
    assert res.findings[0].title == "Archive listed: stealer-log bundle (names only)"
    assert res.pivots == [] and all("sha256" not in m for m in res.attributes["archive_members"])
    dumped = json.dumps([res.raw, res.attributes, [x.description for x in res.findings]], default=str)
    assert "SYNTHETIC PLACEHOLDER" not in dumped  # nothing read
    assert "203.0.113.9" not in dumped and "user@example.com" not in dumped and "DESKTOP-AB12CD3" not in dumped  # masked names
    assert "BR[[ip]][[host]]_2026_11_20/Passwords.txt" in members(res)
    assert res.attributes["archive_summary"]["extraction"]["written"] == 0  # never extracted, even with the flag


def test_stealer_check_threshold_and_redaction():
    assert not al.stealer_bundle_check(["Passwords.txt", "Cookies/a.txt"])["is_bundle"]
    assert al.stealer_bundle_check(["x/Passwords.txt", "x/Cookies/a.txt", "x/Wallets/a"])["is_bundle"]
    assert al.redact_member_name("BR[2001:db8::1][DESKTOP-AB12CD3]/{0f8fad5b-d9cb-469f-a165-70867728950e}/a.txt") == "BR[[ip]][[host]]/{[id]}/a.txt"


# ------------------------------------------------------------------ c7: MotW containers, executables, double extensions
def test_iso_with_lnk_defeats_mark_of_the_web(tmp_path):
    res = run(tmp_path, "Fatura.iso", B.iso_lnk_motw())
    f = titles(res)["Suspicious iso9660 image holding executable content (Mark-of-the-Web bypass)"]
    assert f.severity.label == "high" and "T1553.005" in f.attack and {"suspicious", "motw_bypass"} <= set(f.tags)
    assert f.data["hidden_members"] == ["payload.dll"] and "Fatura 2026.pdf.lnk" in f.data["payloads"]
    assert titles(res)["Suspicious double extension inside the archive"].severity.label == "high"


@pytest.mark.parametrize("name,builder", [("disco.vhd", B.vhd_fixed), ("disco.vhdx", B.vhdx_header)])
def test_disk_images_are_reported_never_mounted(tmp_path, name, builder):
    res = run(tmp_path, name, builder())
    kind = name.rsplit(".", 1)[1].upper()
    f = titles(res)[f"{kind} disk image (bypasses Mark-of-the-Web; never mounted)"]
    assert f.severity.label == "medium" and f.confidence <= 0.4 and res.status is Status.OK


def test_lure_zip(tmp_path):
    res = run(tmp_path, "Fatura_Novembro.zip", B.zip_lure_br())
    found = titles(res)
    assert found["Suspicious double extension inside the archive"].data["members"] == ["Fatura_Novembro_2026.pdf.exe"]
    assert set(found["Executables or scripts inside the archive"].data["members"]) == {"boleto.js", "comprovante.vbs", "nota.pdf"}
    mismatch = found["Extension mismatch: claimed .pdf, actually PE32 executable (GUI) Intel 80386 (member nota.pdf)"]
    assert mismatch.severity.label == "high"


def test_winrar_trailing_space_trap(tmp_path):
    res = run(tmp_path, "documento.zip", B.zip_winrar_trap())
    assert titles(res)["Suspicious trailing-space file and folder pair (CVE-2023-38831 pattern)"].severity.label == "high"


# ------------------------------------------------------------------ c3: extraction only with the flag, 0700 dir deleted
def test_extraction_needs_the_flag_and_cleans_up(tmp_path, monkeypatch):
    created = []
    real_mkdtemp = al.tempfile.mkdtemp

    def spy(*args, **kwargs):
        path = real_mkdtemp(*args, **kwargs)
        created.append((path, stat.S_IMODE(os.stat(path).st_mode)))
        return path

    monkeypatch.setattr(al.tempfile, "mkdtemp", spy)
    plain = run(tmp_path, "a.zip", B.zip_traversal())
    assert created == [] and "extraction" not in plain.attributes["archive_summary"]
    res = run(tmp_path, "b.zip", B.zip_traversal(), settings={"archive_listing_extract": True})
    assert len(created) == 1 and created[0][1] == 0o700 and not os.path.exists(created[0][0])
    extraction = res.attributes["archive_summary"]["extraction"]
    assert extraction == {"written": 1, "refused": 3, "temp_dir_removed": True}  # only ok.txt; unsafe names refused
    assert not (tmp_path.parent / "etc").exists() and not Path("/abs/path.txt").exists()


def test_safe_target_never_escapes_the_root(tmp_path):
    root = str(tmp_path)
    assert al._safe_target(root, "a/b.txt") == os.path.join(root, "a", "b.txt")
    assert al._safe_target(root, "/etc/x") == os.path.join(root, "etc", "x")  # re-rooted (the plan refuses it earlier anyway)
    for bad in ("../x", "a/../../x", "C:/x", "", "a/\x01b"):
        assert al._safe_target(root, bad) is None
    (tmp_path / "out").symlink_to("/")
    assert al._safe_target(root, "out/etc/passwd") is None  # a symlinked parent cannot lead outside


# ------------------------------------------------------------------ c5: RAR/CAB headers, 7z/UDF through optional extras
def test_real_rar_archives():
    def go(name):
        return run_module(ArchiveListing, Entity.make(T.FILE, str(FIXTURES / name)), FakeHttp())

    comment = go("rar4_comment_real.rar")
    assert set(members(comment)) == {"file1.txt", "file2.txt"} and comment.attributes["archive_summary"]["version"] == 4
    uni = go("rar4_unicode_real.rar")
    assert "уииоотивл.txt" in members(uni)
    enc = go("rar5_header_encrypted_real.rar")
    assert enc.status is Status.OK and titles(enc)["Archive headers are encrypted: member names not listable"].severity.label == "info"
    sym = go("rar5_symlink_real.rar")
    assert members(sym)["data_link"]["flags"] == ["symlink"] and members(sym)["data_link"]["link_target"] == "data.txt"
    assert "link_target_escapes" in members(sym)["random_link"]["flags"]


def test_built_rar5_and_cab(tmp_path):
    rar = run(tmp_path, "a.rar", B.rar5_bytes([("a.txt", b"hello"), ("b/c.exe", B.pe32_exe())]))
    assert set(members(rar)) == {"a.txt", "b/c.exe"} and titles(rar)["Executables or scripts inside the archive"]
    cab = run(tmp_path, "a.cab", B.cab_bytes([("..\\..\\evil.dll", b"MZ" + b"\x00" * 62), ("ok.txt", b"ok")]))
    assert members(cab)["..\\..\\evil.dll"]["flags"] == ["parent_traversal", "backslash_separator"]


def test_7z_without_and_with_the_optional_extra(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "py7zr", None)  # import fails: not installed
    res = run(tmp_path, "a.7z", B.sevenzip_bytes())
    assert titles(res)["7z: member listing needs the optional py7zr extra"].severity.label == "info" and res.status is Status.OK

    class Info:
        def __init__(self, name, size):
            self.filename, self.uncompressed, self.compressed, self.is_directory, self.creationtime = name, size, size // 2, False, None

    class SevenZipFile:
        def __init__(self, fh, mode="r", password=None):
            self.password = password

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def list(self):
            return [Info("Fatura.pdf.exe", 2048), Info("../fora.txt", 10)]

    fake = types.ModuleType("py7zr")
    fake.__spec__ = importlib.machinery.ModuleSpec("py7zr", None)
    fake.SevenZipFile = SevenZipFile
    monkeypatch.setitem(sys.modules, "py7zr", fake)
    res = run(tmp_path, "b.7z", B.sevenzip_bytes())
    assert set(members(res)) == {"Fatura.pdf.exe", "../fora.txt"}
    assert titles(res)["Suspicious double extension inside the archive"].severity.label == "high"
    assert titles(res)["Members with unsafe paths (never extracted)"]


def test_udf_only_image_needs_the_optional_extra(tmp_path):
    res = run(tmp_path, "udf.iso", B.udf_only())
    assert titles(res)["udf: member listing needs the optional pycdlib extra"].severity.label == "info"


# ------------------------------------------------------------------ corrupt input, deadline, oversized input, applicability
def test_corrupt_zip_is_an_error_not_empty(tmp_path):
    res = run(tmp_path, "quebrado.zip", b"PK\x03\x04" + b"\xff" * 200)
    assert res.status is Status.ERROR and res.error.startswith("could not list the zip container")


def test_deadline_between_members(tmp_path):
    clock = FakeClock()
    res = run(tmp_path, "a.zip", B.zip_ok(), clock=clock, deadline=clock.monotonic() - 1)
    assert res.status is Status.ERROR and res.reason_code == "timeout"


def test_zip_above_the_memory_cap_is_listed_from_the_central_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(al, "ARCHIVE_READ_CAP", 4096)
    data = B.zip_bytes([{"name": "grande.bin", "data": os.urandom(16384), "method": 0}, {"name": "leia.txt", "data": b"x"}])
    res = run(tmp_path, "grande.zip", data)
    assert titles(res)["Archive larger than the in-memory listing cap: listing partial"].severity.label == "info"
    assert set(members(res)) == {"grande.bin", "leia.txt"} and not hashes(res)
    assert "listed_from_central_directory" in res.attributes["archive_summary"]["anomalies"]


def test_not_an_archive(tmp_path):
    res = run(tmp_path, "a.pdf", B.pdf_no_metadata())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert run(tmp_path, "a.apk", B.apk_ok_v1v2v3()).reason_code == "not_applicable"  # APKs go to apk_triage
