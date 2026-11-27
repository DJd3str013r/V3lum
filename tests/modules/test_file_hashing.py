"""file_hashing (P267): regular files only, 1 MiB streaming, cancel/deadline, optional ssdeep, identification.

Fixtures in tests/fixtures/file_hashing/: a synthetic benign binary with its hashlib digests, the
EICAR reference vectors reported by CIRCL hashlookup and YARAify (the EICAR string is stored
REVERSED and only reversed in memory: no test ever writes an AV test file to disk) and the expected
identification of 25 inputs (synthetic: digests of the constant 'v3lum', format-valid crypt strings
that are not hashes of any password, the public EICAR ssdeep/TLSH).
"""

from __future__ import annotations

import hashlib
import io
import os
import types
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.file_analysis import file_hashing as mod
from v3lum.modules.file_analysis.file_hashing import FileHashing

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "file_hashing"
SHA256_HEX = "24e83223784cc48161c336b28ed8d285b0ccb1a9cd1e6c802442efe60014937d"


def fx(name):
    return module_fixture(FileHashing, name)


def file_entity(path: Path) -> Entity:
    return Entity.make(T.FILE, str(path))


def pivots(res):
    return {(p.entity.type.value, p.entity.value): p for p in res.pivots}


# ------------------------------------------------------------------ metadata
def test_contract_metadata():
    cls = FileHashing
    assert (cls.disclosure, cls.hosts, cls.provider, cls.sources, cls.terms) == ("none", (), "", (), "open")
    assert cls.trust_tier == "n/a" and cls.max_tlp.value_str == "red" and cls.default_enabled is True
    assert cls.requires_packages == ()  # ppdeep is optional: the digests never depend on it


# ------------------------------------------------------------------ FC1: a regular file
def test_regular_file_hashing_matches_expected(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes((FIXTURES / "regular_sample.bin").read_bytes())
    expected = fx("regular_sample.expected.json")
    http = FakeHttp()
    res = run_module(FileHashing, file_entity(sample), http)
    assert res.status is Status.OK
    for name in ("md5", "sha1", "sha256", "sha512"):
        assert res.attributes[name] == expected[name]
    assert res.attributes["file_size"] == expected["size"]
    [finding] = res.findings
    assert finding.severity.label == "info" and finding.data["chunks"] == expected["chunks_at_1MiB"]
    found = pivots(res)
    assert found[("sha256", expected["sha256"])].relation == "has_hash" and found[("sha256", expected["sha256"])].expand is True
    assert found[("md5", expected["md5"])].expand is True and found[("sha1", expected["sha1"])].expand is True
    assert found[("sha512", expected["sha512"])].expand is False
    assert http.calls == [] and res.requests == 0  # offline: the file never leaves the machine


def test_eicar_reference_vectors_in_memory_only():
    ref = fx("eicar_reference.json")
    eicar = ref["reversed_eicar"][::-1].encode()  # reversed in memory, never written to disk
    out = mod.hash_chunks(mod.iter_chunks(io.BytesIO(eicar).read))
    circl = ref["circl_hashlookup"]
    assert out["hashes"]["md5"] == circl["MD5"].lower() and out["hashes"]["sha1"] == circl["SHA-1"].lower()
    assert out["hashes"]["sha256"] == circl["SHA-256"].lower() and out["hashes"]["sha512"] == circl["SHA-512"].lower()
    assert out["size"] == ref["size"] == 68


# ------------------------------------------------------------------ FC1: FIFOs, devices and sockets are refused
def test_fifo_is_refused_without_opening(tmp_path):
    path = tmp_path / "pipe"
    path.write_bytes(b"x")
    entity = file_entity(path)  # a regular file when the entity was built...
    path.unlink()
    os.mkfifo(path)  # ...replaced by a FIFO before the run: opening it would block forever
    res = run_module(FileHashing, entity, FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert "refused FIFO" in res.error and not res.attributes


@pytest.mark.parametrize(("path", "kind"), [("/dev/zero", "character device"), ("/", "directory")])
def test_devices_and_directories_are_refused(path, kind):
    if not os.path.exists(path):
        pytest.skip(f"{path} not available")
    res = run_module(FileHashing, Entity(T.FILE, path), FakeHttp())
    assert res.status is Status.SKIPPED and f"refused {kind}" in res.error


def test_path_swapped_after_the_check_is_refused(tmp_path, monkeypatch):
    fifo = tmp_path / "swapped"
    os.mkfifo(fifo)
    regular = os.stat(FIXTURES / "regular_sample.bin")
    real_os = mod.os
    proxy = types.SimpleNamespace(**{n: getattr(real_os, n) for n in dir(real_os) if not n.startswith("__")})
    proxy.stat = lambda p: regular  # the pre-open check sees a regular file
    monkeypatch.setattr(mod, "os", proxy)
    res = run_module(FileHashing, Entity(T.FILE, str(fifo)), FakeHttp())
    assert res.status is Status.SKIPPED and "refused FIFO" in res.error  # fstat after the non-blocking open


def test_vanished_file_is_not_applicable(tmp_path):
    path = tmp_path / "gone.bin"
    path.write_bytes(b"x")
    entity = file_entity(path)
    path.unlink()
    res = run_module(FileHashing, entity, FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_mode_refusal_helper():
    import stat

    assert mod.file_mode_refusal(stat.S_IFREG | 0o644) is None
    assert "FIFO" in mod.file_mode_refusal(stat.S_IFIFO | 0o644)
    assert "socket" in mod.file_mode_refusal(stat.S_IFSOCK | 0o644)
    assert "block device" in mod.file_mode_refusal(stat.S_IFBLK | 0o644)
    assert mod.file_mode_refusal(None) == "no stat information"


# ------------------------------------------------------------------ FC1: large files stream in 1 MiB chunks
def test_large_file_is_streamed_in_1mib_chunks(tmp_path):
    data = os.urandom(3 * mod.CHUNK_SIZE + 12345)
    path = tmp_path / "large.bin"
    path.write_bytes(data)
    res = run_module(FileHashing, file_entity(path), FakeHttp())
    assert res.status is Status.OK
    assert res.findings[0].data["chunks"] == 4
    assert res.attributes["sha256"] == hashlib.sha256(data).hexdigest()
    reads = []
    stream = io.BytesIO(data)

    def read(n):
        reads.append(n)
        return stream.read(n)

    out = mod.hash_chunks(mod.iter_chunks(read))
    assert set(reads) == {mod.CHUNK_SIZE} and out["chunks"] == 4 and out["content"] is None  # nothing kept by default


def test_cancel_stops_hashing_and_emits_no_digest(tmp_path):
    path = tmp_path / "file.bin"
    path.write_bytes(b"a" * 4096)
    rt = make_runtime(FakeHttp())
    rt.cancel("cancelled")
    res = run_module(FileHashing, file_entity(path), runtime=rt)
    assert res.partial and res.stop_reason == "cancelled"
    assert not res.attributes and not res.pivots and not res.findings


def test_deadline_stops_hashing_and_emits_no_digest(tmp_path):
    path = tmp_path / "file.bin"
    path.write_bytes(b"a" * 4096)
    rt = make_runtime(FakeHttp())
    res = run_module(FileHashing, file_entity(path), runtime=rt, deadline=rt.clock.monotonic() - 5)
    assert res.status is Status.ERROR and res.reason_code == "timeout"
    assert not res.attributes and not res.pivots


# ------------------------------------------------------------------ FC2: ssdeep through the optional ppdeep
def test_without_ppdeep_the_digests_are_still_computed(tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "load_ppdeep", lambda: None)
    path = tmp_path / "file.bin"
    path.write_bytes(b"benign content " * 100)
    res = run_module(FileHashing, file_entity(path), FakeHttp())
    assert res.status is Status.OK and "similarity_hashes" not in res.attributes
    assert "ppdeep is not installed" in res.findings[0].data["ssdeep_note"]
    assert res.findings[0].data["tlsh"].startswith("not computed")


def test_with_ppdeep_ssdeep_is_added_for_small_files(tmp_path, monkeypatch):
    seen = []
    fake = types.SimpleNamespace(hash=lambda content: seen.append(len(content)) or "3:a+JraNvsgzsVqSwHq9:tJuOgzsko")
    monkeypatch.setattr(mod, "load_ppdeep", lambda: fake)
    path = tmp_path / "file.bin"
    path.write_bytes(b"benign content " * 100)
    res = run_module(FileHashing, file_entity(path), FakeHttp())
    assert res.attributes["similarity_hashes"] == {"ssdeep": "3:a+JraNvsgzsVqSwHq9:tJuOgzsko"}
    assert seen == [1500]
    ss = pivots(res)[("ssdeep", "3:a+JraNvsgzsVqSwHq9:tJuOgzsko")]
    assert ss.relation == "has_hash" and ss.expand is False


def test_ssdeep_only_up_to_the_size_limit(tmp_path, monkeypatch):
    fake = types.SimpleNamespace(hash=lambda content: pytest.fail("ppdeep must not run above the limit"))
    monkeypatch.setattr(mod, "load_ppdeep", lambda: fake)
    monkeypatch.setattr(mod, "SSDEEP_MAX_BYTES", 1000)
    path = tmp_path / "file.bin"
    path.write_bytes(b"x" * 1001)
    res = run_module(FileHashing, file_entity(path), FakeHttp())
    assert res.status is Status.OK and "similarity_hashes" not in res.attributes
    assert "larger than" in res.findings[0].data["ssdeep_note"]


def test_real_ppdeep_reference_vector():
    ppdeep = pytest.importorskip("ppdeep")
    ref = fx("eicar_reference.json")
    assert ppdeep.hash(ref["reversed_eicar"][::-1].encode()) == ref["circl_hashlookup"]["SSDEEP"]


def test_tlsh_and_ssdeep_helpers():
    assert mod.normalize_tlsh("t141a022003b0eee2ba20b00200032e8b00808020e2ce00a3820a020b8c83308803ec228").startswith("T141A0")
    assert mod.normalize_tlsh("TNULL") is None
    assert mod.parse_ssdeep("3:a+JraNvsgzsVqSwHq9:tJuOgzsko")["blocksize"] == 3
    assert mod.parse_ssdeep("5:abc:def") is None


# ------------------------------------------------------------------ FC3: identification, ambiguity, no cracking
def test_identify_hash_cases():
    for case in fx("identify_cases.json"):
        got = mod.identify_hash(case["input"])
        assert got["primary"] == case["primary"], case["input"]
        assert got["readings"] == case["readings"], case["input"]
        assert got["ambiguous"] == case["ambiguous"], case["input"]
        assert got["label_only"] == case["label_only"], case["input"]
        for key in ("alternatives", "value", "password_hash", "explicit"):
            if key in case:
                assert got[key] == case[key], (case["input"], key)


def test_password_formats_are_only_labelled():
    got = mod.identify_hash("$2b$12$stoKJyOnfioCPtjrU2p5S8Rf2F89J2WCdOP3N/G4mUUwihzfKfSgt")
    assert got["password_hash"] == "bcrypt" and got["readings"] == [] and "no cracking" in got["note"]


def test_ambiguity_tries_both_readings_non_tty_and_lets_tty_choose():
    ident = mod.identify_hash(SHA256_HEX)
    assert ident["ambiguous"] and ident["readings"] == ["sha256", "cert_fingerprint"]
    assert mod.hash_readings(ident)["emit"] == ["sha256", "cert_fingerprint"]
    assert mod.hash_readings(ident, interactive=True) == {"emit": [], "ask": True, "options": ["sha256", "cert_fingerprint"]}
    assert mod.hash_readings(ident, interactive=True, choice="cert_fingerprint")["emit"] == ["cert_fingerprint"]
    assert mod.identify_hash("a" * 40, sha1_cert_reading=True)["readings"] == ["sha1", "cert_fingerprint"]


def test_module_tries_the_other_reading_of_an_ambiguous_seed():
    http = FakeHttp()
    res = run_module(FileHashing, f"sha256:{SHA256_HEX}", http)
    assert res.status is Status.OK
    ident = res.attributes["hash_identification"]
    assert ident["ambiguous"] is True and ident["readings"] == ["sha256", "cert_fingerprint"]
    [alt] = res.pivots
    assert (alt.entity.type, alt.entity.value, alt.relation) == (T.CERT_FP, SHA256_HEX, "alternate_reading")
    assert alt.expand is True and alt.confidence == 0.5 and alt.confidence_label.value == "possible"  # tried, still 'possible'
    assert "no cracking and no plaintext lookup" in res.findings[0].description
    assert http.calls == []


def test_unambiguous_values_are_labelled_without_pivots():
    res = run_module(FileHashing, "md5:c05d3d3710a689ffeca944d8b7b66fb3", FakeHttp())
    assert res.pivots == [] and res.attributes["hash_identification"]["alternatives"] == ["ntlm", "imphash"]
    res2 = run_module(FileHashing, "ssdeep:3:a+JraNvsgzsVqSwHq9:tJuOgzsko", FakeHttp())
    assert "block size 3" in res2.findings[0].description


def test_pivot_digests_are_not_re_identified():
    res = run_module(FileHashing, f"sha256:{SHA256_HEX}", FakeHttp(), is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_plaintext_lookup_services_are_refused_by_the_lint(tmp_path):
    # FC3: hashes.com, CrackStation and ntlm.pw are excluded (v3lum/data/lint/p1_g07_2.json adds ntlm.pw)
    from v3lum.core import lint

    assert {"hashes.com", "crackstation.net", "ntlm.pw"} <= set(lint.CRACKING_HOSTS)
    probe = tmp_path / "probe_module.py"
    probe.write_text('API = "https://ntlm.pw/api/lookup/nt/{h}"\n')
    assert [i.rule_id for i in lint.lint_module_source(probe)] == ["LINT-08"]
    assert lint.lint_module_source(Path(mod.__file__)) == []
