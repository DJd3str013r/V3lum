"""One purge routine (A10, AR04; WP10), end to end on a temporary home: a case with evidence, a
report under -o, sightings, votes, overrides, feedback, audit, deferred lookups and HTTP-cache
rows -> everything gone, a value-free tombstone, secure delete + VACUUM (the value is no longer in
the database files); legal hold exempts; dry runs change nothing; the minimal engagement audit
follows audit_retention_days; retention listing and the once-a-day reminder."""

from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3

import pytest

from tests.fakes import FakeClock
from v3lum import paths
from v3lum.core.cache import HttpCache
from v3lum.core.http import Response
from v3lum.core.quota import QuotaBook
from v3lum.core.store import ENGAGEMENT_AUDIT_FILES, PURGE_AUDIT_KIND, Store

NOW = dt.datetime(2026, 11, 26, 12, 0, 0, tzinfo=dt.timezone.utc)
SECRET_VALUE = "alice.purge@corp.example"  # appears only in the purged case


def ts(days_ago: float) -> str:
    return (NOW - dt.timedelta(days=days_ago)).isoformat(timespec="seconds")


def make_case(case_id: str, *, days_ago: float = 1.0, mode: str = "passive", seeds=None, findings=("f-own", "f-shared")) -> dict:
    seeds = list(seeds or [f"email:{SECRET_VALUE}", "domain:purge-evil.example"])
    return {
        "schema": "v3lum.case/1",
        "case_id": case_id,
        "created": ts(days_ago),
        "tlp": "amber",
        "seeds": seeds,
        "options": {"mode": mode, "purpose": "incident response", "ticket": "INC-1", "legal_basis": "LI", "licence_profile": "corporate"},
        "summary": {"risk_score": 40.0, "risk_level": "medium", "findings": len(findings), "entities": len(seeds)},
        "entities": [{"key": s} for s in seeds],
        "findings": [{"id": f, "title": "t", "severity": "low"} for f in findings],
        "correlations": [],
        "case_dir": str(paths.cases_dir() / case_id),
    }


@pytest.fixture()
def clock():
    return FakeClock(NOW)


@pytest.fixture()
def store(clock):
    s = Store(settings={"retention_days": 180, "audit_retention_days": 0}, clock=clock)
    yield s
    s.close()


def populate(store: Store, case_id: str, tmp_path, *, mode: str = "passive", days_ago: float = 1.0) -> dict:
    """A realistic case: rows in every case table, evidence + reports + ledger in the case
    directory, a report written under -o, cache rows and deferred quota lookups."""
    case = make_case(case_id, days_ago=days_ago, mode=mode)
    case_dir = paths.case_dir(case_id)
    evidence = paths.sub(f"cases/{case_id}/evidence")
    (evidence / "mod__email__0123456789ab__abcdef0123.json").write_text(json.dumps({"data": SECRET_VALUE}))
    (evidence / "mod__email__0123456789ab__fedcba3210.json").write_text("{}")  # a second version
    (case_dir / f"v3lum-{case_id}.html").write_text(f"<p>{SECRET_VALUE}</p>")
    (case_dir / "audit.jsonl").write_text('{"seq": 1, "kind": "case_start", "payload": {"purpose": "incident response"}}\n')  # WP15 mirror
    (case_dir / "ledger.jsonl").write_text('{"seq": 1, "host": "purge-evil.example", "path": "/[redacted]"}\n')  # WP15 ledger
    out = tmp_path / "analyst_reports"
    out.mkdir(exist_ok=True)
    outside = out / f"v3lum-{case_id}.md"
    outside.write_text(SECRET_VALUE)
    (out / f"v3lum-{case_id}.md.sha256").write_text("00" * 32)
    case["reports"] = {"html": str(case_dir / f"v3lum-{case_id}.html"), "md": str(outside)}
    store.save_case(case)
    store.record_report_hashes(case_id, {str(outside): "11" * 32})
    store.add_feedback(case_id, "partial", f"note about {SECRET_VALUE}")
    store.flag_finding(case_id, "f-own", "t_mod", False)
    with store.connection() as conn:
        conn.execute(
            "INSERT INTO finding_votes (case_id, finding_id, analyst, vote, reason, source_id, rule_id, created) VALUES (?, 'f-own', 'ana', 'wrong', 'homonym', 'src.a', '', ?)",
            (case_id, ts(0)),
        )
        conn.execute("INSERT OR REPLACE INTO source_stats (source_id, alpha, beta, votes, updated) VALUES ('src.a', 2, 3, 5, ?)", (ts(0),))
        conn.execute("INSERT OR REPLACE INTO rule_stats (rule_id, alpha, beta, votes, updated) VALUES ('young_domain', 4, 1, 5, ?)", (ts(0),))
        conn.execute("INSERT OR REPLACE INTO overrides (finding_id, analyst, label, note, created) VALUES ('f-own', 'ana', 'possible', ?, ?)", (f"about {SECRET_VALUE}", ts(0)))
        conn.execute("INSERT OR REPLACE INTO overrides (finding_id, analyst, label, note, created) VALUES ('f-shared', 'ana', 'confirmed', 'shared', ?)", (ts(0),))
        conn.execute(
            "INSERT INTO sightings (entity_key, entity_hmac, entity_type, case_id, case_tlp, engagement, created, verdict) VALUES ('domain:purge-evil.example', '', 'domain', ?, 'amber', 0, ?, 'malicious')",
            (case_id, ts(0)),
        )
        conn.execute(
            "INSERT INTO evidence_versions (case_id, record_key, version, sha256, path, collected_at) VALUES (?, 'mod|0123', 1, 'aa', 'evidence/x.json', ?)",
            (case_id, ts(0)),
        )
        conn.execute("INSERT INTO alerts (id, rule_id, ts, payload, case_id) VALUES (?, 'brand', ?, '{}', ?)", (f"a-{case_id}", ts(0), case_id))
        conn.execute("INSERT INTO watch_first_seen (rule_id, registrable_domain, cert_serial, first_seen, case_id) VALUES ('brand', ?, '01', ?, ?)", (f"{case_id}.example", ts(0), case_id))
    store.append_audit(case_id, "case_start", {"mode": mode, "authorization_ref": "REF-1"})
    cache = HttpCache(str(paths.cache_file()))
    for key in ("ck1", "ck2"):
        cache.put(key, Response(200, f"https://api.example.test/{key}", {}, f"cached {SECRET_VALUE}".encode()))
    cache.put("unrelated", Response(200, "https://api.example.test/other", {}, b"other case"))
    cache.close()
    store.record_cache_keys(case_id, ["ck1", "ck2"])
    book = QuotaBook()
    book.defer(case_id, "t_mod", f"email:{SECRET_VALUE}", "quota", provider="hackertarget")
    book.close()
    return case


def case_rows(store: Store, case_id: str) -> dict[str, int]:
    out = {}
    with store.connection() as conn:
        for table in ("feedback", "finding_feedback", "finding_votes", "sightings", "evidence_versions", "report_hashes", "alerts", "watch_first_seen", "case_cache_keys", "case_findings", "audit"):
            out[table] = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE case_id = ?", (case_id,)).fetchone()[0]
        out["cases"] = conn.execute("SELECT COUNT(*) FROM cases WHERE id = ?", (case_id,)).fetchone()[0]
    return out


def file_bytes(*files) -> bytes:
    data = b""
    for f in files:
        if os.path.exists(f):
            with open(f, "rb") as fh:
                data += fh.read()
    return data


def test_purge_removes_every_artefact_and_keeps_a_value_free_tombstone(store, tmp_path):
    cid = "20261125-120000-aaaa"
    case = populate(store, cid, tmp_path)
    other = make_case("20261125-130000-bbbb", seeds=["domain:other.example"], findings=("f-shared",))
    store.save_case(other)
    outside = tmp_path / "analyst_reports" / f"v3lum-{cid}.md"

    report = store.purge_case(cid, by="analyst-cli")

    assert report.found and report.purged and report.complete and not report.held
    assert report.counts["cases"] == 1 and report.counts["files"] == 5 and report.counts["report_files"] == 2
    assert report.counts["cache_rows"] == 2 and report.counts["deferred"] == 1 and report.counts["overrides"] == 1
    assert set(case_rows(store, cid).values()) == {0}
    assert not (paths.cases_dir() / cid).exists()
    assert not outside.exists() and not outside.with_name(outside.name + ".sha256").exists()
    with store.connection() as conn:
        overrides = {r[0] for r in conn.execute("SELECT finding_id FROM overrides")}
        assert overrides == {"f-shared"}  # still part of another stored case
        assert conn.execute("SELECT COUNT(*) FROM source_stats").fetchone()[0] == 1  # aggregates survive (A10)
        assert conn.execute("SELECT COUNT(*) FROM rule_stats").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM module_stats").fetchone()[0] == 1
    assert store.get_case(other["case_id"]) is not None
    cache = HttpCache(str(paths.cache_file()))
    assert cache.get("ck1", ttl=10**9) is None and cache.get("unrelated", ttl=10**9) is not None
    cache.close()
    book = QuotaBook()
    assert book.deferred(cid) == []
    book.close()

    tomb = store.tombstone(cid)
    assert tomb is not None and tomb["created"] == case["created"] and tomb["purged_by"] == "analyst-cli"
    assert tomb["purged_at"] == NOW.isoformat(timespec="seconds") and tomb["audit_until"] is None
    assert tomb["counts"]["cases"] == 1 and tomb["counts"]["files"] == 5
    assert SECRET_VALUE not in json.dumps(tomb) and "purge-evil" not in json.dumps(tomb)
    # secure delete + VACUUM: the value is gone from every database file (case DB, cache, quota)
    db = paths.db_file()
    cache_db = paths.cache_file()
    blob = file_bytes(db, f"{db}-journal", f"{db}-wal", cache_db, f"{cache_db}-wal", paths.home() / "quota.db")
    assert SECRET_VALUE.encode() not in blob
    assert store.list_cases(search=f"{SECRET_VALUE}") == []


def test_purge_counts_without_a_dry_run_side_effect(store, tmp_path):
    cid = "20261125-120000-dddd"
    populate(store, cid, tmp_path)
    before_rows = case_rows(store, cid)
    before_files = sorted(str(p) for p in (paths.cases_dir() / cid).rglob("*"))
    db_bytes = paths.db_file().read_bytes()

    dry = store.purge_case(cid, by="test", dry_run=True)

    assert dry.dry_run and not dry.purged and dry.found
    assert dry.counts["files"] == 5 and dry.counts["cache_rows"] == 2 and dry.counts["deferred"] == 1
    assert len(dry.files) == 7 and "would remove" in dry.line()
    assert case_rows(store, cid) == before_rows
    assert sorted(str(p) for p in (paths.cases_dir() / cid).rglob("*")) == before_files
    assert (tmp_path / "analyst_reports" / f"v3lum-{cid}.md").exists()
    assert store.tombstone(cid) is None and paths.db_file().read_bytes() == db_bytes
    real = store.purge_case(cid, by="test")
    assert real.counts == dry.counts  # the dry run announced exactly what the purge removed


def test_legal_hold_exempts_a_case_from_every_purge(store, tmp_path):
    cid = "20250101-120000-aaaa"  # far past retention
    populate(store, cid, tmp_path, days_ago=400)
    assert store.hold(cid, "court order 12", "Legal")
    held = store.purge_case(cid, by="cli")
    assert held.held and not held.purged and held.reason == "court order 12" and "legal hold" in held.line()
    assert not store.delete_case(cid)
    assert store.get_case(cid) is not None and (paths.cases_dir() / cid).exists()
    assert store.cases_past_retention() == []  # held cases are exempt, not overdue
    reports = store.purge_older_than(by="retention")
    assert [(r.case_id, r.held) for r in reports] == [(cid, True)]  # skipped and listed
    assert store.get_case(cid) is not None
    assert store.unhold(cid, by="Legal")
    assert [c["id"] for c in store.cases_past_retention()] == [cid]
    purged = store.purge_older_than(by="retention")
    assert [(r.case_id, r.purged) for r in purged] == [(cid, True)]
    assert store.get_case(cid) is None and store.tombstone(cid)["purged_by"] == "retention"


def test_purge_older_than_uses_retention_days_and_vacuums_once(store, tmp_path, monkeypatch):
    old_id, young_id = "20260101-000000-0001", "20261120-000000-0002"
    store.save_case(make_case(old_id, days_ago=200, seeds=["domain:old.example"]))
    store.save_case(make_case(young_id, days_ago=6, seeds=["domain:young.example"]))
    calls = []
    original = store.vacuum
    monkeypatch.setattr(store, "vacuum", lambda: (calls.append(1), original())[1])
    reports = store.purge_older_than(dry_run=True)
    assert [r.case_id for r in reports] == [old_id] and not calls and store.get_case(old_id)
    reports = store.purge_older_than()
    assert [r.case_id for r in reports] == [old_id] and calls == [1]
    assert store.get_case(young_id) is not None and store.get_case(old_id) is None
    assert [r.case_id for r in store.purge_older_than(5)] == [young_id]
    with pytest.raises(ValueError):
        store.purge_older_than(-1)
    disabled = Store(settings={"retention_days": 0})
    assert disabled.purge_older_than() == [] and disabled.cases_past_retention() == []
    disabled.close()


def test_engagement_audit_is_kept_until_audit_retention_days(clock, tmp_path):
    store = Store(settings={"retention_days": 30, "audit_retention_days": 365}, clock=clock)
    cid = "20261116-120000-e0e0"
    populate(store, cid, tmp_path, mode="light", days_ago=10)
    report = store.delete_case(cid)  # explicit deletion of an engagement case on day 10
    assert report is True
    tomb = store.tombstone(cid)
    assert tomb["audit_until"] == (NOW - dt.timedelta(days=10) + dt.timedelta(days=365)).isoformat(timespec="seconds")
    case_dir = paths.cases_dir() / cid
    assert ENGAGEMENT_AUDIT_FILES == ("ledger.jsonl",)
    assert sorted(p.name for p in case_dir.iterdir()) == ["ledger.jsonl"]  # the request ledger; the audit mirror went with the case
    rows = store.audit_rows(cid)
    assert [r["kind"] for r in rows] == ["case_start", PURGE_AUDIT_KIND] and store.verify_audit_chain(cid) == []
    assert rows[0]["payload"] == {"mode": "light", "authorization_ref": "REF-1"}  # already minimal: kept as it was
    assert rows[1]["payload"]["minimised_rows"] == 0 and rows[1]["payload"]["previous_chain_intact"] is True
    assert store.get_case(cid) is None and case_rows(store, cid)["feedback"] == 0
    again = store.purge_case(cid, by="cli")  # nothing left to do inside the audit retention
    assert not again.purged and again.line().startswith(f"{cid}: already purged (") and "engagement audit kept until" in again.line()
    assert store.purge_older_than(dry_run=True) == []  # the audit is still within its retention
    clock.advance(356 * 86400)  # audit_retention_days after the case creation
    reports = store.purge_older_than()
    assert [r.case_id for r in reports] == [cid] and reports[0].purged
    assert not case_dir.exists() and store.audit_rows(cid) == []
    final = store.tombstone(cid)
    assert final["audit_until"] is None and final["counts"]["audit"] == 2 and final["counts"]["cases"] == 1
    store.close()


def test_engagement_audit_keeps_only_the_minimal_fields_in_a_resealed_chain(clock, tmp_path):
    """A10 BR3: after the purge only authorization reference, scope SHA-256, window, analyst, mode,
    egress and targets survive; purpose, ticket, legal basis and hold reasons go with the case."""
    store = Store(settings={"retention_days": 30, "audit_retention_days": 365}, clock=clock)
    cid = "20261120-120000-a11d"
    store.save_case(make_case(cid, days_ago=6, mode="active", seeds=["domain:target.example"]))
    store.append_audit(cid, "case_start", {
        "purpose": f"phishing kit reported by {SECRET_VALUE}", "ticket": "INC-77", "legal_basis": "legitimate_interest",
        "analyst": "ana", "mode": "active", "authorization_ref": "PT-2026-14", "scope_sha256": "ab" * 32,
        "window": {"start": "2026-11-20T00:00:00+00:00", "end": "2026-11-21T00:00:00+00:00"},
        "engagement": {"mode": "active", "targets_touched": {"target.example": 3}, "purpose": "nested purpose"},
    })
    store.hold(cid, f"court order naming {SECRET_VALUE}", "Legal")
    store.unhold(cid, by="Legal")
    head = store.audit_rows(cid)[-1]["hash"]
    dry = store.purge_case(cid, by="cli", dry_run=True)
    assert dry.counts["audit_minimised"] == 3 and len(store.audit_rows(cid)) == 3  # counted, nothing changed

    report = store.purge_case(cid, by="cli")

    assert report.purged and report.counts["audit_minimised"] == 3 and "audit" not in report.counts
    rows = store.audit_rows(cid)
    assert [r["kind"] for r in rows] == ["case_start", "hold", "unhold", PURGE_AUDIT_KIND]
    assert rows[0]["payload"] == {
        "analyst": "ana", "mode": "active", "authorization_ref": "PT-2026-14", "scope_sha256": "ab" * 32,
        "window": {"start": "2026-11-20T00:00:00+00:00", "end": "2026-11-21T00:00:00+00:00"},
        "engagement": {"mode": "active", "targets_touched": {"target.example": 3}},
    }
    assert rows[1]["payload"] == {} and rows[2]["payload"] == {}  # the hold happened; its reason went with the case
    assert rows[3]["payload"] == {"by": "cli", "rows": 3, "minimised_rows": 3, "previous_head": head, "previous_chain_intact": True}
    assert store.verify_audit_chain(cid) == []  # re-sealed: later tampering is still detected
    with store.connection() as conn:
        conn.execute("UPDATE audit SET payload = ? WHERE case_id = ? AND seq = 1", ('{"authorization_ref":"forged"}', cid))
    assert any("hash mismatch" in p for p in store.verify_audit_chain(cid))
    blob = file_bytes(paths.db_file(), f"{paths.db_file()}-journal")
    assert SECRET_VALUE.encode() not in blob and b"INC-77" not in blob and b"nested purpose" not in blob
    store.close()


def test_a_chain_broken_before_the_purge_stays_on_record(clock, tmp_path):
    store = Store(settings={"retention_days": 30, "audit_retention_days": 365}, clock=clock)
    cid = "20261120-120000-b0b0"
    store.save_case(make_case(cid, days_ago=6, mode="light", seeds=["domain:target.example"]))
    store.append_audit(cid, "case_start", {"authorization_ref": "PT-1", "purpose": "p"})
    with store.connection() as conn:  # someone edited the row before the purge
        conn.execute("UPDATE audit SET payload = ? WHERE case_id = ? AND seq = 1", ('{"authorization_ref":"PT-2","purpose":"p"}', cid))
    store.purge_case(cid, by="cli")
    closing = store.audit_rows(cid)[-1]
    assert closing["kind"] == PURGE_AUDIT_KIND and closing["payload"]["previous_chain_intact"] is False
    store.close()


def test_audit_retention_defaults_to_retention_days(clock, tmp_path):
    store = Store(settings={"retention_days": 20, "audit_retention_days": 0}, clock=clock)
    assert store.audit_retention_days() == 20
    cid = "20261124-120000-e1e1"
    populate(store, cid, tmp_path, mode="active", days_ago=2)
    rep = store.purge_case(cid, by="cli")
    assert rep.audit_until == (NOW - dt.timedelta(days=2) + dt.timedelta(days=20)).isoformat(timespec="seconds")
    passive = "20261124-120000-e2e2"
    populate(store, passive, tmp_path, mode="passive", days_ago=2)
    rep2 = store.purge_case(passive, by="cli")
    assert rep2.audit_until == "" and rep2.counts["audit"] == 1 and store.audit_rows(passive) == []  # not an engagement
    store.close()


def test_purge_never_deletes_files_that_do_not_name_the_case(store, tmp_path):
    cid = "20261125-120000-ffff"
    unrelated = tmp_path / "important.txt"
    unrelated.write_text("keep")
    store.save_case(make_case(cid, seeds=["domain:x.example"]))
    store.record_report_paths(cid, [str(unrelated)])  # a damaged or forged record
    report = store.purge_case(cid, by="cli")
    assert unrelated.exists() and report.purged and not report.complete
    assert any("does not contain the case id" in e for e in report.errors)


def test_unknown_case_and_leftovers(store):
    missing = store.purge_case("20261126-000000-0000", by="cli")
    assert not missing.found and not missing.purged and missing.line().endswith("not found")
    assert store.tombstone("20261126-000000-0000") is None
    assert store.purge_case("", by="cli").reason == "empty case id"
    leftover = "20261126-000000-1111"  # an evidence directory whose case was never saved (crash)
    (paths.sub(f"cases/{leftover}/evidence") / "x.json").write_text("{}")
    rep = store.purge_case(leftover, by="cli")
    assert not rep.found and rep.purged and rep.counts == {"files": 1}
    assert not (paths.cases_dir() / leftover).exists() and store.tombstone(leftover)["counts"] == {"files": 1}
    weird = store.purge_case("../../etc", by="cli")  # never a path outside the cases directory
    assert not weird.purged


def test_case_directory_links_are_removed_not_followed(store, tmp_path):
    cid = "20261125-120000-1234"
    target_dir = tmp_path / "precious"
    target_dir.mkdir()
    (target_dir / "keep.txt").write_text("keep")
    case_dir = paths.case_dir(cid)
    (case_dir / "linked").symlink_to(target_dir, target_is_directory=True)
    (case_dir / "file-link.txt").symlink_to(target_dir / "keep.txt")
    store.save_case(make_case(cid, seeds=["domain:x.example"]))
    report = store.purge_case(cid, by="cli")
    assert report.purged and report.complete and not case_dir.exists()
    assert (target_dir / "keep.txt").read_text() == "keep"


def test_retention_reminder_at_most_once_per_day(store, clock):
    store.save_case(make_case("20250101-000000-0001", days_ago=400, seeds=["domain:a.example"]))
    store.save_case(make_case("20250101-000000-0002", days_ago=200, seeds=["domain:b.example"]))
    store.save_case(make_case("20261120-000000-0003", days_ago=6, seeds=["domain:c.example"]))
    due = store.cases_past_retention()
    assert [c["id"] for c in due] == ["20250101-000000-0001", "20250101-000000-0002"] and due[0]["age_days"] == 400
    assert store.retention_reminder() == "2 cases older than 180 days: v3lum cases purge"
    assert store.retention_reminder() == ""  # once per day
    assert os.stat(paths.reminder_file()).st_mode & 0o777 == 0o600
    clock.advance(86400)
    assert store.retention_reminder().startswith("2 cases older than 180 days")
    store.purge_older_than()
    clock.advance(86400)
    assert store.retention_reminder() == ""  # nothing due


def test_tables_added_by_later_migrations_are_purged_too(store):
    """A later package adds a table with a case_id column (no edit of the purge needed)."""
    cid = "20261125-120000-7ab1"
    store.save_case(make_case(cid, seeds=["domain:x.example"]))
    with store.connection() as conn:
        conn.execute("CREATE TABLE verdicts (case_id TEXT NOT NULL, analyst TEXT, verdict TEXT)")
        conn.execute("INSERT INTO verdicts VALUES (?, 'ana', 'yes')", (cid,))
        conn.execute("INSERT INTO verdicts VALUES ('20261125-130000-0ther', 'ana', 'no')")
    dry = store.purge_case(cid, by="cli", dry_run=True)
    assert dry.counts["verdicts"] == 1
    store.purge_case(cid, by="cli")
    with store.connection() as conn:
        assert [r[0] for r in conn.execute("SELECT case_id FROM verdicts")] == ["20261125-130000-0ther"]
    assert store.tombstone(cid)["counts"]["verdicts"] == 1


def test_retention_sweeps_abandoned_case_directories(store, clock, tmp_path):
    """A crashed scan (or a v1 `cases delete`) leaves evidence without a case row: the retention purge
    removes it once it is older than retention_days; other names and young directories stay."""
    old = "20260101-000000-dead"  # 329 days old, never saved
    young = "20261120-000000-beef"  # 6 days old: maybe a scan still running
    for cid in (old, young):
        (paths.sub(f"cases/{cid}/evidence") / "m__email__0123456789ab__abcdef0123.json").write_text(SECRET_VALUE)
    other = paths.sub("cases/org-profile")  # not a generated case id: never swept
    (other / "audit.jsonl").write_text("{}\n")
    engaged = "20260102-000000-ac7e"  # an abandoned LIGHT run: its ledger follows audit_retention_days
    (paths.sub(f"cases/{engaged}/evidence") / "x.json").write_text("{}")
    (paths.case_dir(engaged) / "ledger.jsonl").write_text('{"host": "t.example"}\n')

    dry = store.purge_older_than(dry_run=True)
    assert sorted(r.case_id for r in dry) == [old, engaged] and (paths.cases_dir() / old).exists()

    store_settings = Store(settings={"retention_days": 180, "audit_retention_days": 400}, clock=clock)
    reports = store_settings.purge_older_than()
    assert sorted(r.case_id for r in reports) == [old, engaged] and all(r.purged for r in reports)
    assert not (paths.cases_dir() / old).exists() and (paths.cases_dir() / young).exists() and other.exists()
    assert sorted(p.name for p in paths.case_dir(engaged).iterdir()) == ["ledger.jsonl"]
    assert store_settings.tombstone(old)["counts"] == {"files": 1} and store_settings.tombstone(old)["created"] == "2026-01-01T00:00:00+00:00"
    assert store_settings.tombstone(engaged)["audit_until"] == "2027-02-06T00:00:00+00:00"
    assert store_settings.purge_older_than() == []  # nothing left to report
    store_settings.close()
    elsewhere = Store(tmp_path / "other.db", settings={"retention_days": 1}, clock=clock)
    assert elsewhere.purge_older_than() == [] and (paths.cases_dir() / young).exists()  # another DB never sweeps the home
    elsewhere.close()


def test_an_unreadable_cache_is_reported_not_ignored(store, monkeypatch):
    cid = "20261125-120000-cace"
    store.save_case(make_case(cid, seeds=["domain:x.example"]))
    store.record_cache_keys(cid, ["k1"])
    cache = HttpCache(str(paths.cache_file()))
    cache.close()
    import v3lum.core.cache as cache_mod

    def broken(*_a, **_kw):
        raise sqlite3.DatabaseError("file is not a database")

    monkeypatch.setattr(cache_mod, "HttpCache", broken)
    report = store.purge_case(cid, by="cli")
    assert report.purged and not report.complete and any("HTTP cache" in e for e in report.errors)


# --------------------------------------------------------------------------------------
# HTTP cache retention (A10: cache_max_age_days, default 30)
# --------------------------------------------------------------------------------------


def test_cache_prunes_old_rows_at_most_once_a_day_and_shows_the_oldest(clock):
    path = str(paths.cache_file())
    cache = HttpCache(path, clock=clock)
    day = 86400.0
    now = clock.now().timestamp()
    cache.put("old", Response(200, "https://a.example.test/old", {}, b"old"), now=now - 40 * day)
    cache.put("mid", Response(200, "https://a.example.test/mid", {}, b"mid"), now=now - 10 * day)
    cache.put("new", Response(200, "https://a.example.test/new", {}, b"new"), now=now)
    assert cache.stats()["oldest"] == dt.datetime.fromtimestamp(now - 40 * day, dt.timezone.utc).isoformat(timespec="seconds")
    assert cache.stats()["last_prune"] == ""
    cache.close()
    pruned = HttpCache(path, max_age_days=30, clock=clock)  # opening prunes (A10 start-up maintenance)
    assert pruned.stats()["entries"] == 2 and pruned.last_prune() == NOW.isoformat(timespec="seconds")
    pruned.put("old2", Response(200, "https://a.example.test/old2", {}, b"x"), now=now - 45 * day)
    pruned.close()
    again = HttpCache(path, max_age_days=30, clock=clock)  # same UTC day: no second prune
    assert again.stats()["entries"] == 3
    again.close()
    clock.advance(day)
    tomorrow = HttpCache(path, max_age_days=30, clock=clock)
    assert tomorrow.stats()["entries"] == 2
    assert tomorrow.prune(5) == 1  # maintenance with an explicit age (the 10-day row goes)
    assert tomorrow.prune() == 0  # default 30 days
    assert tomorrow.count_keys(["new", "mid", "nope"]) == 1
    assert tomorrow.delete_many(["new"]) == 1 and tomorrow.stats()["entries"] == 0
    tomorrow.vacuum()
    tomorrow.close()


def test_cached_rows_keep_fetched_at_and_the_redacted_url(clock):
    cache = HttpCache(str(paths.cache_file()), clock=clock)
    cache.put("k", Response(200, "https://a.example.test/x?apikey=SECRET123456789", {}, b"b"))
    clock.advance(120)
    hit = cache.get("k", ttl=3600)
    assert hit is not None and hit.from_cache and hit.fetched_at == NOW.isoformat(timespec="seconds")
    assert "SECRET123456789" not in hit.url
    cache.close()


def test_cache_never_serves_a_row_older_than_max_age_days(clock):
    """Between two daily prunes a row can outlive cache_max_age_days: get() refuses it anyway."""
    cache = HttpCache(str(paths.cache_file()), max_age_days=30, clock=clock)
    now = clock.now().timestamp()
    cache.put("aging", Response(200, "https://a.example.test/aging", {}, b"x"), now=now - 29.9 * 86400)
    assert cache.get("aging", ttl=10**9) is not None
    clock.advance(0.2 * 86400)  # same UTC day: no new prune, the row is now 30.1 days old
    assert cache.get("aging", ttl=10**9) is None
    cache.close()
    plain = HttpCache(str(paths.cache_file()), clock=clock)  # without max_age_days the caller's ttl rules
    assert plain.get("aging", ttl=10**9) is not None
    plain.close()
