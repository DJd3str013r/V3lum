"""``v3lum cases verify`` engine (P324 cond 6-7, 9; A10): verify_case recomputes every evidence and
report hash and the audit and ledger chains offline.

An untouched case verifies; every single-byte change of an evidence file, the evidence index, the
audit rows (case DB and mirror) and the request ledger is detected; removed lines are caught by the
heads the case_end row recorded; the purge removes every evidence version and keeps the tombstone,
and a purged LIGHT/ACTIVE case still verifies its minimal engagement audit and ledger.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from tests.fakes import FakeClock, FakeHttp, add_dns, define_module, make_runtime
from v3lum.core import audit as audit_mod
from v3lum.core import evidence as ev
from v3lum.core.audit import AuditHook, CaseAudit, VerifyReport, verify_case
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec
from v3lum.core.store import Store

SEED = Entity.make("domain", "example.org")


@pytest.fixture()
def registry(clean_registry):
    clean_registry.clear()
    return clean_registry


@pytest.fixture()
def store():
    db = Store()
    yield db
    db.close()


def light_case(store: Store, *, clock: FakeClock | None = None, raw: dict | None = None, requests: tuple[str, ...] = ("/",), case_id: str | None = None):
    """A saved LIGHT case with evidence, its audit record and its request ledger."""
    http = FakeHttp()
    add_dns(http, "example.org", "A", ["93.184.216.34"])
    add_dns(http, "example.org", "AAAA", [])
    for p in requests:
        http.add("GET", f"https://example.org{p}", text="hello")

    def run(self, entity, ctx):
        for p in requests:
            ctx.http.get(f"https://{entity.value}{p}")
        res = self.result(entity)
        res.raw = raw if raw is not None else {"status": 200, "title": "hello"}
        res.finding("homepage reachable", "info", criterion="synthetic light check")
        return res

    if "t_verify_light" not in __import__("v3lum.core.module", fromlist=["REGISTRY"]).REGISTRY:
        define_module("t_verify_light", [T.DOMAIN], run, opsec=Opsec.LIGHT)
    rt = make_runtime(http, clock=clock)
    AuditHook(store, analyst="analyst-1").attach(rt)
    case = Engine(rt, ScanOptions(include={"t_verify_light"}, mode=Opsec.LIGHT)).investigate([SEED], case_id=case_id)
    store.save_case(case.to_dict())
    return case


def flip(data: bytes, index: int) -> bytes:
    out = bytearray(data)
    out[index] ^= 0x01
    return bytes(out)


def problems(store: Store, case_id: str) -> list[str]:
    report = verify_case(store, case_id)
    assert report.ok is (not report.problems)
    return report.problems


# --------------------------------------------------------------------------------------
# the untouched case
# --------------------------------------------------------------------------------------


def test_an_untouched_case_verifies(registry, store):
    case = light_case(store)
    report = verify_case(store, case.case_id)
    assert isinstance(report, VerifyReport) and report.ok and report.problems == []
    assert report.checked == {"audit_rows": 2, "evidence_files": 1, "reports": 0, "ledger_lines": 1}
    assert report.summary().startswith(f"PASS {case.case_id}") and report.lines()[0] == report.summary()
    assert report.to_dict()["ok"] is True and not report.purged


def test_an_unknown_case_fails():
    with Store() as db:
        report = verify_case(db, "20261126-000000-dead")
    assert not report.ok and report.problems == ["case 20261126-000000-dead not found"] and report.summary().startswith("FAIL")


# --------------------------------------------------------------------------------------
# tamper detection
# --------------------------------------------------------------------------------------


def test_an_edited_evidence_file_is_detected(registry, store):
    case = light_case(store)
    path = Path(case.results[0].evidence)
    os.chmod(path, 0o600)
    path.write_bytes(path.read_bytes().replace(b'"hello"', b'"hellO"'))
    assert any(path.name in p and "does not match the recorded" in p for p in problems(store, case.case_id))


def test_a_broken_audit_chain_is_detected(registry, store):
    case = light_case(store)
    with store.connection() as conn:
        conn.execute("UPDATE audit SET prev_hash = ? WHERE case_id = ? AND seq = 2", ("f" * 64, case.case_id))
    found = problems(store, case.case_id)
    assert any("audit row 2" in p and "chain broken" in p for p in found)
    assert any("audit.jsonl" in p and "differs from audit row 2" in p for p in found)


def test_an_edited_audit_payload_is_detected_even_when_it_parses_the_same(registry, store):
    case = light_case(store)
    with store.connection() as conn:
        text = conn.execute("SELECT payload FROM audit WHERE case_id = ? AND seq = 1", (case.case_id,)).fetchone()[0]
        conn.execute("UPDATE audit SET payload = ? WHERE case_id = ? AND seq = 1", (text.replace(",", ", ", 1), case.case_id))
    assert any("audit row 1" in p and "canonical form" in p for p in problems(store, case.case_id))


def test_a_deleted_audit_row_is_detected(registry, store):
    case = light_case(store)
    with store.connection() as conn:
        conn.execute("DELETE FROM audit WHERE case_id = ? AND seq = 2", (case.case_id,))
    assert any("missing from the case DB" in p for p in problems(store, case.case_id))
    with store.connection() as conn:
        conn.execute("DELETE FROM audit WHERE case_id = ?", (case.case_id,))
    found = problems(store, case.case_id)
    assert any("without its audit record" in p for p in found) and any("missing from the case DB" in p for p in found)


def test_an_edited_ledger_line_is_detected(registry, store):
    case = light_case(store, requests=("/", "/a"))
    ledger = Path(case.case_dir) / audit_mod.LEDGER_FILE
    ledger.write_text(ledger.read_text(encoding="utf-8").replace('"status":200', '"status":404', 1), encoding="utf-8")
    assert any("ledger.jsonl line 1" in p and "hash mismatch" in p for p in problems(store, case.case_id))


def test_removed_lines_are_caught_by_the_heads_of_the_case_end_row(registry, store):
    case = light_case(store, requests=("/", "/a", "/b"))
    base = Path(case.case_dir)
    ledger = base / audit_mod.LEDGER_FILE
    original = ledger.read_bytes()
    ledger.write_bytes(b"".join(original.splitlines(keepends=True)[:2]))  # a well-formed but shorter chain
    assert ev.verify_chain(ledger).ok
    assert any("the audit recorded 3 at case end" in p for p in problems(store, case.case_id))
    ledger.unlink()
    assert any("ledger.jsonl missing" in p for p in problems(store, case.case_id))
    ledger.write_bytes(original)
    index = base / ev.EVIDENCE_INDEX
    index.write_bytes(b"")
    found = problems(store, case.case_id)
    assert any("the audit recorded 1 at case end" in p for p in found)
    assert any("not listed in evidence.jsonl" in p for p in found)


def test_rows_removed_from_the_end_of_every_chain_are_detected(registry, store):
    """Removing the case_end row from the case DB and the mirror takes the case_end anchors with it
    and leaves well-formed, shorter chains: the head the stored case recorded catches it, and so do
    the missing case_end row and the ledger head of the stored engagement summary."""
    case = light_case(store, requests=("/", "/a", "/b"))
    base = Path(case.case_dir)
    with store.connection() as conn:
        last = conn.execute("SELECT max(seq) FROM audit WHERE case_id = ?", (case.case_id,)).fetchone()[0]
        conn.execute("DELETE FROM audit WHERE case_id = ? AND seq = ?", (case.case_id, last))
    mirror = base / audit_mod.AUDIT_MIRROR
    mirror.write_bytes(b"".join(mirror.read_bytes().splitlines(keepends=True)[:-1]))
    ledger = base / audit_mod.LEDGER_FILE
    ledger.write_bytes(b"".join(ledger.read_bytes().splitlines(keepends=True)[:1]))
    assert ev.verify_chain(mirror).ok and ev.verify_chain(ledger).ok  # each chain is well formed on its own
    found = problems(store, case.case_id)
    assert any("the stored case recorded 2 at case end (rows removed" in p for p in found)
    assert any("has no case_end row" in p for p in found)
    assert any("ledger.jsonl has 1 line(s), the stored case recorded 3" in p for p in found)


def test_deleting_the_whole_audit_of_a_saved_case_is_detected(registry, store):
    def run(self, entity, ctx):
        res = self.result(entity)
        res.raw = {"x": 1}
        return res

    define_module("t_passive_audited", [T.DOMAIN], run)
    rt = make_runtime(FakeHttp())
    AuditHook(store).attach(rt)
    case = Engine(rt, ScanOptions(include={"t_passive_audited"})).investigate([SEED])
    store.save_case(case.to_dict())
    assert verify_case(store, case.case_id).ok
    with store.connection() as conn:
        conn.execute("DELETE FROM audit WHERE case_id = ?", (case.case_id,))
    (Path(case.case_dir) / audit_mod.AUDIT_MIRROR).unlink()
    report = verify_case(store, case.case_id)
    assert not report.ok and any("the audit has 0 row(s), the stored case recorded 2" in p for p in report.problems)
    assert not any("without the audit hook" in w for w in report.warnings)


def test_a_run_whose_case_end_row_could_not_be_written_is_a_warning_not_a_tamper(registry, store):
    case = light_case(store)
    with store.connection() as conn:
        last = conn.execute("SELECT max(seq) FROM audit WHERE case_id = ?", (case.case_id,)).fetchone()[0]
        conn.execute("DELETE FROM audit WHERE case_id = ? AND seq = ?", (case.case_id, last))
    mirror = Path(case.case_dir) / audit_mod.AUDIT_MIRROR
    mirror.write_bytes(b"".join(mirror.read_bytes().splitlines(keepends=True)[:-1]))
    data = case.to_dict()
    data["meta"].pop(audit_mod.STORED_ANCHOR_KEY)  # the hook sets it only once case_end is written
    data["notes"].append(f"{audit_mod.CASE_END_MISSING_NOTE} (OperationalError: disk I/O error)")
    store.save_case(data)
    report = verify_case(store, case.case_id)
    assert report.ok and any("could not write it" in w for w in report.warnings)
    data["notes"].pop()
    store.save_case(data)
    assert any("has no case_end row (audit rows removed" in p for p in problems(store, case.case_id))


def test_a_later_run_that_did_not_finish_is_a_warning(registry, store):
    case = light_case(store)
    CaseAudit(store, case.case_id, case.case_dir).append("case_start", {"mode": "light", "resumed_into_same_case": True})
    report = verify_case(store, case.case_id)
    assert report.ok and any("a later run" in w and "did not finish" in w for w in report.warnings)


def test_evidence_version_metadata_in_the_case_db_is_checked(registry, store):
    case = light_case(store)
    for column, value in (("collected_at", "2020-01-01T00:00:00+00:00"), ("fetched_at", "2020-01-01T00:00:00+00:00"), ("diff_summary", "{}")):
        with store.connection() as conn:
            original = conn.execute(f"SELECT {column} FROM evidence_versions WHERE case_id = ?", (case.case_id,)).fetchone()[0]
            conn.execute(f"UPDATE evidence_versions SET {column} = ? WHERE case_id = ?", (value, case.case_id))
        assert any("the case DB row differs" in p for p in problems(store, case.case_id)), column
        with store.connection() as conn:
            conn.execute(f"UPDATE evidence_versions SET {column} = ? WHERE case_id = ?", (original, case.case_id))
        assert verify_case(store, case.case_id).ok


def test_evidence_indexed_after_the_last_case_end_is_flagged(registry, store):
    from v3lum.core.models import ModuleResult

    case = light_case(store)
    res = ModuleResult("t_verify_light", SEED)
    res.raw = {"status": 500}
    ev.EvidenceStore(case.case_dir, store=store, case_id=case.case_id).save(res)
    report = verify_case(store, case.case_id)
    assert report.ok and any("indexed after the last case_end row" in w for w in report.warnings)


def test_a_torn_line_inside_the_anchored_range_is_reported_not_raised(registry, store):
    case = light_case(store, requests=("/", "/a", "/b"))
    base = Path(case.case_dir)
    for name in (audit_mod.LEDGER_FILE, ev.EVIDENCE_INDEX):
        path = base / name
        original = path.read_bytes()
        lines = original.splitlines(keepends=True)
        path.write_bytes(b"".join([b"{torn\n", *lines[1:]]))  # line 1 unparsable: the head line shifts
        found = problems(store, case.case_id)
        assert any(f"{name} line 1" in p and "not valid JSON" in p for p in found)
        path.write_bytes(original)
    lines = (base / audit_mod.LEDGER_FILE).read_bytes().splitlines(keepends=True)
    (base / audit_mod.LEDGER_FILE).write_bytes(b"".join([*lines[:2], b"{torn\n"]))  # the anchored head line itself
    assert any("line 3 does not match the head recorded" in p for p in problems(store, case.case_id))


def test_every_single_byte_tamper_is_detected(registry, store):
    """Acceptance (P324 cond 9): flip every byte of the evidence file, the evidence index, the audit
    mirror and the request ledger, and change every character of every audit row in the case DB:
    verify_case reports each change and passes again once it is undone."""
    case = light_case(store, raw={"k": "v"}, requests=("/", "/a"))
    base = Path(case.case_dir)
    files = [Path(case.results[0].evidence), base / ev.EVIDENCE_INDEX, base / audit_mod.AUDIT_MIRROR, base / audit_mod.LEDGER_FILE]
    assert verify_case(store, case.case_id).ok
    missed: list[str] = []
    for path in files:
        original = path.read_bytes()
        os.chmod(path, 0o600)
        fd = os.open(path, os.O_RDWR)  # flip one byte in place (no rewrite of the whole file per flip)
        try:
            for i in range(len(original)):
                os.pwrite(fd, bytes([original[i] ^ 0x01]), i)
                if verify_case(store, case.case_id).ok:
                    missed.append(f"{path.name}[{i}]")
                os.pwrite(fd, original[i:i + 1], i)
        finally:
            os.close(fd)
        assert path.read_bytes() == original
    with store.connection() as conn:
        rows = [dict(r) for r in conn.execute("SELECT seq, ts, kind, payload, prev_hash, hash FROM audit WHERE case_id = ?", (case.case_id,))]
    for row in rows:
        for column in ("ts", "kind", "payload", "prev_hash", "hash"):
            text = row[column]
            for i in range(len(text)):
                changed = text[:i] + chr(ord(text[i]) ^ 0x01) + text[i + 1:]
                with store.connection() as conn:
                    conn.execute(f"UPDATE audit SET {column} = ? WHERE case_id = ? AND seq = ?", (changed, case.case_id, row["seq"]))
                if verify_case(store, case.case_id).ok:
                    missed.append(f"audit[{row['seq']}].{column}[{i}]")
                with store.connection() as conn:
                    conn.execute(f"UPDATE audit SET {column} = ? WHERE case_id = ? AND seq = ?", (text, case.case_id, row["seq"]))
    assert missed == []
    assert verify_case(store, case.case_id).ok  # everything restored


def test_evidence_version_rows_are_checked_against_the_index(registry, store):
    case = light_case(store)
    with store.connection() as conn:
        conn.execute("UPDATE evidence_versions SET sha256 = ? WHERE case_id = ?", ("0" * 64, case.case_id))
    assert any("the case DB row differs" in p for p in problems(store, case.case_id))
    with store.connection() as conn:
        conn.execute("DELETE FROM evidence_versions WHERE case_id = ?", (case.case_id,))
        conn.execute(
            "INSERT INTO evidence_versions (case_id, record_key, version, sha256, path) VALUES (?, 'ghost|0', 1, ?, 'evidence/ghost.json')",
            (case.case_id, "1" * 64),
        )
    found = problems(store, case.case_id)
    assert any("in the case DB but not in evidence.jsonl" in p for p in found) and any("not in the case DB" in p for p in found)


def test_report_hashes_and_sidecars_are_checked(registry, store):
    case = light_case(store)
    report_path = Path(case.case_dir) / f"v3lum-{case.case_id}.md"
    report_path.write_text("# report\n", encoding="utf-8")
    digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
    store.record_report_hashes(case.case_id, {str(report_path): digest})
    Path(str(report_path) + ".sha256").write_text(f"{digest}  {report_path.name}\n", encoding="utf-8")
    report = verify_case(store, case.case_id)
    assert report.ok and report.checked["reports"] == 1
    report_path.write_text("# report (edited)\n", encoding="utf-8")
    found = problems(store, case.case_id)
    assert any("hash recorded when it was written" in p for p in found) and any(".sha256 sidecar" in p for p in found)
    report_path.write_text("# report\n", encoding="utf-8")
    Path(str(report_path) + ".sha256").write_text("0" * 64, encoding="utf-8")
    assert [p for p in problems(store, case.case_id) if "sidecar" in p]
    report_path.unlink()
    Path(str(report_path) + ".sha256").unlink()
    report = verify_case(store, case.case_id)
    assert report.ok and any("not found (moved or deleted)" in w for w in report.warnings)


def test_a_deleted_mirror_or_ledger_of_an_engagement_is_detected(registry, store):
    case = light_case(store)
    (Path(case.case_dir) / audit_mod.AUDIT_MIRROR).unlink()
    assert any("audit.jsonl missing" in p for p in problems(store, case.case_id))


def test_store_native_hold_rows_are_accepted_and_mirrored_by_the_next_audit_row(registry, store):
    case = light_case(store)
    store.hold(case.case_id, "litigation", "legal department")
    report = verify_case(store, case.case_id)
    assert report.ok and any("hold" in w and "not mirrored" in w for w in report.warnings)
    CaseAudit(store, case.case_id, case.case_dir).append("override", {"finding_id": "x", "label": "confirmed"})
    report = verify_case(store, case.case_id)
    assert report.ok and not [w for w in report.warnings if "not mirrored" in w]


def test_a_case_scanned_without_the_hook_verifies_its_evidence_with_warnings(registry, store):
    def run(self, entity, ctx):
        res = self.result(entity)
        res.raw = {"x": 1}
        return res

    define_module("t_plain", [T.DOMAIN], run)
    case = Engine(make_runtime(FakeHttp()), ScanOptions(include={"t_plain"})).investigate([SEED])
    store.save_case(case.to_dict())
    report = verify_case(store, case.case_id)
    assert report.ok and report.checked["evidence_files"] == 1
    assert any("without the audit hook" in w for w in report.warnings) and any("not recorded in the case DB" in w for w in report.warnings)


# --------------------------------------------------------------------------------------
# purge (A10) and the minimal engagement audit
# --------------------------------------------------------------------------------------


def test_purge_removes_every_version_and_keeps_the_tombstone(registry, store):
    state = {"n": 0}

    def run(self, entity, ctx):
        res = self.result(entity)
        res.raw = {"collection": state["n"]}
        return res

    define_module("t_versions", [T.DOMAIN], run)
    clock = FakeClock("2026-11-26T10:00:00+00:00")
    rt = make_runtime(FakeHttp(), clock=clock)
    AuditHook(store).attach(rt)
    case_id = "20261126-100000-ab12"
    case = Engine(rt, ScanOptions(include={"t_versions"})).investigate([SEED], case_id=case_id)
    clock.advance(3600)
    state["n"] = 1
    Engine(rt, ScanOptions(include={"t_versions"})).investigate([SEED], case_id=case_id)  # a re-collection: version 2
    store.save_case(case.to_dict())
    evidence_dir = Path(case.case_dir) / "evidence"
    assert len(list(evidence_dir.iterdir())) == 2
    with store.connection() as conn:
        assert [r[0] for r in conn.execute("SELECT version FROM evidence_versions WHERE case_id = ? ORDER BY version", (case_id,))] == [1, 2]
    assert verify_case(store, case_id).ok
    report = store.purge_case(case_id, by="test")
    assert report.purged and report.counts["evidence_versions"] == 2
    assert not evidence_dir.exists() and not Path(case.case_dir).exists()
    with store.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM evidence_versions WHERE case_id = ?", (case_id,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit WHERE case_id = ?", (case_id,)).fetchone()[0] == 0
    tomb = store.tombstone(case_id)
    assert tomb is not None and tomb["purged_by"] == "test"
    after = verify_case(store, case_id)
    assert after.ok and after.purged and any("purged" in w for w in after.warnings)


def test_a_purged_engagement_keeps_a_verifiable_minimal_audit_and_ledger(registry, store):
    case = light_case(store, requests=("/", "/a"))
    ledger = Path(case.case_dir) / audit_mod.LEDGER_FILE
    report = store.purge_case(case.case_id, by="retention")
    assert report.purged and report.audit_until
    assert ledger.exists() and not (Path(case.case_dir) / audit_mod.AUDIT_MIRROR).exists() and not (Path(case.case_dir) / "evidence").exists()
    kinds = [r["kind"] for r in store.audit_rows(case.case_id)]
    assert kinds[-1] == "purge" and kinds[0] == "case_start"
    minimal_start = store.audit_rows(case.case_id)[0]["payload"]
    assert "purpose" not in minimal_start and minimal_start["mode"] == "light"  # minimal engagement audit only
    after = verify_case(store, case.case_id)
    assert after.ok and after.purged and after.checked["ledger_lines"] == 2
    ledger.write_bytes(flip(ledger.read_bytes(), 10))
    assert not verify_case(store, case.case_id).ok


def test_verify_accepts_an_explicit_case_directory(registry, store, tmp_path):
    case = light_case(store)
    moved = tmp_path / "moved"
    os.rename(case.case_dir, moved)
    assert not verify_case(store, case.case_id).ok  # the directory is gone from the home
    report = verify_case(store, case.case_id, case_dir=moved)
    assert report.ok and json.loads((moved / audit_mod.LEDGER_FILE).read_text().splitlines()[0])["host"] == "example.org"
