"""Schema migrations (AR04, WP10): an empty DB reaches the latest version; a v1 case DB built from the
old SCHEMA string upgrades in place with its rows (personal seeds pseudonymised, A4); re-runs are
idempotent; the cache and quota DBs migrate too; a failing step rolls back. Also the Store v2
bookkeeping: report paths/hashes, cache keys, the hash-chained audit, legal hold and the search
index that matches personal values only exactly."""

from __future__ import annotations

import json
import sqlite3
import threading

import pytest

from v3lum.core import hmacid, migrations
from v3lum.core.cache import HttpCache
from v3lum.core.migrations import MIGRATIONS, Migration, MigrationError, latest_version, migrate, user_version
from v3lum.core.store import SCHEMA, Store, audit_hash, case_columns

V2_TABLES = {
    "cases", "feedback", "finding_feedback", "module_stats", "tombstones", "case_cache_keys", "case_findings",
    "finding_votes", "source_stats", "rule_stats", "overrides", "sightings", "evidence_versions", "audit",
    "report_hashes", "watch_first_seen", "watch_mutes", "alerts",
}
V2_CASE_COLUMNS = {
    "tlp", "legal_hold", "hold_reason", "hold_requester", "held_at", "purpose", "ticket", "legal_basis",
    "licence_profile", "report_paths", "engagement",
}


def tables(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'") if not r[0].startswith("sqlite_")}


def columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def case_dict(case_id: str, *, seeds=("domain:evil.example",), mode="passive", created="2026-11-20T10:00:00+00:00", findings=(), **extra) -> dict:
    return {
        "schema": "v3lum.case/1",
        "case_id": case_id,
        "created": created,
        "tlp": extra.pop("tlp", "amber"),
        "seeds": list(seeds),
        "options": {"mode": mode, "purpose": extra.pop("purpose", ""), "ticket": "", "legal_basis": "", "licence_profile": "corporate"},
        "summary": {"risk_score": 12.0, "risk_level": "low", "findings": len(findings), "entities": len(seeds)},
        "entities": [{"key": s} for s in seeds],
        "findings": [{"id": fid, "title": "t", "severity": "low"} for fid in findings],
        "correlations": [],
        **extra,
    }


# --------------------------------------------------------------------------------------
# migrate()
# --------------------------------------------------------------------------------------


def test_empty_database_reaches_the_latest_version(tmp_path):
    store = Store(tmp_path / "v3lum.db")
    assert store.version == latest_version("cases") == 2
    with store.connection() as conn:
        assert user_version(conn) == 2
        assert tables(conn) >= V2_TABLES
        assert columns(conn, "cases") >= V2_CASE_COLUMNS
        assert "analyst" in columns(conn, "feedback")
    store.close()


def test_v1_database_upgrades_in_place_with_rows_preserved(tmp_path):
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.executescript(SCHEMA)  # the schema V3LUM shipped before migrations
    old_case = case_dict("20261101-100000-abcd", seeds=["email:alice@corp.example", "domain:evil.example"], findings=["f1", "f2"])
    old_case["reports"] = {"json": str(tmp_path / "v3lum-20261101-100000-abcd.json")}
    con.execute(
        "INSERT INTO cases (id, created, seeds, risk_score, risk_level, findings, entities, data) VALUES (?,?,?,?,?,?,?,?)",
        (old_case["case_id"], old_case["created"], json.dumps(old_case["seeds"]), 12.0, "low", 2, 2, json.dumps(old_case)),
    )
    con.execute("INSERT INTO feedback (case_id, verdict, notes, created) VALUES (?, 'partial', 'n', '2026-11-02T00:00:00+00:00')", (old_case["case_id"],))
    con.execute("INSERT INTO finding_feedback (case_id, finding_id, module, correct, created) VALUES (?, 'f1', 'm1', 0, 'x')", (old_case["case_id"],))
    con.execute("INSERT INTO module_stats (module, correct, wrong) VALUES ('m1', 3, 1)")
    con.commit()
    assert user_version(con) == 0
    con.close()

    store = Store(db)
    assert store.version == 2
    assert store.get_case(old_case["case_id"]) == old_case  # the case JSON (plain values) is untouched
    assert store.feedback_for(old_case["case_id"])[0]["verdict"] == "partial"
    assert store.reliability() == {"m1": pytest.approx(5 / 6)}
    with store.connection() as conn:
        row = conn.execute("SELECT seeds, tlp, engagement, licence_profile, report_paths FROM cases").fetchone()
        seeds = json.loads(row["seeds"])
        assert seeds == [hmacid.pseudonymize_key("email:alice@corp.example"), "domain:evil.example"]  # A4: no plain e-mail in the index
        assert row["tlp"] == "amber" and row["engagement"] == 0 and row["licence_profile"] == "corporate"
        assert json.loads(row["report_paths"]) == [old_case["reports"]["json"]]
        assert {r[0] for r in conn.execute("SELECT finding_id FROM case_findings")} == {"f1", "f2"}
        assert conn.execute("SELECT COUNT(*) FROM finding_feedback").fetchone()[0] == 1
    listed = store.list_cases()
    assert listed[0]["id"] == old_case["case_id"] and listed[0]["seeds"] == ["email:alice@corp.example", "domain:evil.example"]
    store.close()


def test_migrations_are_idempotent(tmp_path):
    db = tmp_path / "v3lum.db"
    Store(db).close()
    con = sqlite3.connect(db)
    schema_before = sorted(con.execute("SELECT type, name, sql FROM sqlite_master").fetchall())
    assert migrate(con, "cases") == 2
    assert migrate(con, "cases") == 2
    assert sorted(con.execute("SELECT type, name, sql FROM sqlite_master").fetchall()) == schema_before
    con.close()
    again = Store(db)
    assert again.version == 2
    again.close()


def test_an_unversioned_v1_database_is_detected_not_recreated(tmp_path):
    con = sqlite3.connect(tmp_path / "q.db")
    con.executescript(migrations.QUOTA_V1_SCHEMA)
    con.execute("INSERT INTO quota VALUES ('m', '2026-11-26', 3)")
    con.commit()
    assert MIGRATIONS["quota"][0].detect(con)
    assert migrate(con, "quota") == 2
    assert con.execute("SELECT used FROM quota").fetchone()[0] == 3
    assert {"windows", "signals", "deferred"} <= tables(con)


def test_cache_database_migrates_and_keeps_rows(tmp_path):
    db = tmp_path / "http_cache.db"
    con = sqlite3.connect(db)
    con.executescript(migrations.CACHE_V1_SCHEMA)
    con.execute(
        "INSERT INTO cache (key, url, host, status, headers, body, ts, history) VALUES ('k1', 'https://a.example.test/x', 'a.example.test', 200, '{}', X'6869', 1764158400.0, '[]')"
    )
    con.commit()
    con.close()
    cache = HttpCache(str(db))
    assert cache.version == 2
    hit = cache.get("k1", ttl=10**12, now=1764158400.0 + 10)
    assert hit is not None and hit.content == b"hi" and hit.fetched_at == "2025-11-26T12:00:00+00:00"
    con = sqlite3.connect(db)
    assert "fetched_at" in columns(con, "cache") and "meta" in tables(con) and user_version(con) == 2
    cache.close()


def test_newer_database_is_never_downgraded(tmp_path):
    con = sqlite3.connect(tmp_path / "future.db")
    con.execute("PRAGMA user_version = 99")
    assert migrate(con, "cache") == 99
    with pytest.raises(ValueError):
        migrate(con, "nope")


def test_a_failing_step_rolls_everything_back(tmp_path, monkeypatch):
    def broken(conn):
        conn.execute("CREATE TABLE half (x)")
        raise RuntimeError("boom")

    monkeypatch.setitem(
        MIGRATIONS, "t_kind", [Migration(1, "first", "CREATE TABLE first_t (x); -- a comment; with semicolons\n"), Migration(2, "broken", broken)]
    )
    con = sqlite3.connect(tmp_path / "t.db")
    with pytest.raises(MigrationError, match="t_kind migration 2"):
        migrate(con, "t_kind")
    assert user_version(con) == 0 and tables(con) == set()
    monkeypatch.setitem(MIGRATIONS, "t_kind", [Migration(1, "first", "CREATE TABLE first_t (x);")])
    assert migrate(con, "t_kind") == 1 and tables(con) == {"first_t"}


def test_concurrent_first_opens_migrate_once(tmp_path):
    db = tmp_path / "race.db"
    errors: list[BaseException] = []
    stores: list[Store] = []
    lock = threading.Lock()

    def open_store() -> None:
        try:
            s = Store(db)
            with lock:
                stores.append(s)
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=open_store) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert not errors and len(stores) == 6 and {s.version for s in stores} == {2}
    for s in stores:
        s.close()


# --------------------------------------------------------------------------------------
# Store v2 bookkeeping
# --------------------------------------------------------------------------------------


def test_record_report_hashes_round_trip_and_removal_by_purge(tmp_path):
    store = Store(tmp_path / "v3lum.db", settings={"retention_days": 180})
    cid = "20261126-120000-beef"
    out = tmp_path / "out"
    out.mkdir()
    html = out / f"v3lum-{cid}.html"
    md = out / f"v3lum-{cid}.md"
    html.write_text("<html></html>")
    md.write_text("# r")
    # recorded before the case row exists (write_reports runs before save_case)
    assert store.record_report_paths(cid, {"md": str(md)}) == 1
    assert store.record_report_hashes(cid, {str(html): "AB" * 32}) == 1
    store.save_case(case_dict(cid, reports={"html": str(html)}))
    assert store.report_hashes(cid) == {str(html): "ab" * 32}  # only rows with a hash
    assert set(store.report_paths(cid)) == {str(html), str(md)}
    assert set(store.case_info(cid)["report_paths"]) == {str(html), str(md)}
    store.record_report_hashes(cid, {str(html): "cd" * 32})  # a rewritten report replaces its hash
    assert store.report_hashes(cid) == {str(html): "cd" * 32}
    report = store.purge_case(cid, by="test")
    assert report.purged and report.counts["report_hashes"] == 2 and report.counts["report_files"] == 2
    assert store.report_hashes(cid) == {} and store.report_paths(cid) == []
    assert not html.exists() and not md.exists()
    store.close()


def test_cache_keys_are_recorded_per_case(tmp_path):
    store = Store(tmp_path / "v3lum.db")
    assert store.record_cache_keys("c1", ["k2", "k1", "k1", ""]) == 2
    assert store.record_cache_keys("c1", ["k1"]) == 0
    assert store.cache_keys("c1") == ["k1", "k2"] and store.cache_keys("c2") == []
    store.close()


def test_audit_chain_hold_and_unhold(tmp_path):
    store = Store(tmp_path / "v3lum.db")
    cid = "20261126-120000-c0de"
    store.save_case(case_dict(cid))
    with pytest.raises(ValueError):
        store.hold(cid, "", "legal")
    assert not store.hold("missing-case", "litigation", "legal")
    assert store.hold(cid, "litigation hold 42", "Legal team")
    info = store.case_info(cid)
    assert info["legal_hold"] and info["hold_reason"] == "litigation hold 42" and info["hold_requester"] == "Legal team"
    assert [c["id"] for c in store.held_cases()] == [cid]
    store.save_case(case_dict(cid, tlp="red"))  # re-saving keeps the hold
    assert store.case_info(cid)["legal_hold"] and store.case_info(cid)["tlp"] == "red"
    assert store.list_cases()[0]["legal_hold"] is True
    assert store.unhold(cid, by="analyst")
    assert not store.unhold(cid)  # not held any more
    rows = store.audit_rows(cid)
    assert [r["kind"] for r in rows] == ["hold", "unhold"] and [r["seq"] for r in rows] == [1, 2]
    assert rows[0]["payload"] == {"reason": "litigation hold 42", "requester": "Legal team"}
    assert rows[1]["prev_hash"] == rows[0]["hash"]
    assert rows[0]["hash"] == audit_hash("0" * 64, rows[0])
    assert store.verify_audit_chain(cid) == []
    with store.connection() as conn:
        conn.execute("UPDATE audit SET payload = ? WHERE case_id = ? AND seq = 1", ('{"reason":"edited","requester":"x"}', cid))
    assert any("hash mismatch" in p for p in store.verify_audit_chain(cid))
    store.close()


def test_search_matches_personal_values_only_exactly(tmp_path):
    store = Store(tmp_path / "v3lum.db")
    store.save_case(case_dict("20261126-120000-0001", seeds=["email:alice@corp.example"], created="2026-11-26T12:00:01+00:00"))
    store.save_case(case_dict("20261126-120000-0002", seeds=["domain:alice-corp.example"], created="2026-11-26T12:00:02+00:00"))
    store.save_case(case_dict("20261126-120000-0003", seeds=["cpf:52998224725"], created="2026-11-26T12:00:03+00:00"))
    ids = lambda q: sorted(c["id"] for c in store.list_cases(search=q))  # noqa: E731
    assert ids("alice") == ["20261126-120000-0002"]  # substring: IOC seeds only, never the e-mail (no people search)
    assert ids("alice@corp.example") == ["20261126-120000-0001"]  # the exact value is hashed and found
    assert ids("Alice@Corp.Example") == ["20261126-120000-0001"]  # normalized first
    assert ids("email:alice@corp.example") == ["20261126-120000-0001"]
    assert ids("529.982.247-25") == ["20261126-120000-0003"]
    assert ids("52998") == []
    assert ids("0003") == ["20261126-120000-0003"]  # case ids still match by substring
    assert ids("100%_") == []
    with store.connection() as conn:
        raw = " ".join(r[0] for r in conn.execute("SELECT seeds FROM cases"))
    assert "alice@corp.example" not in raw and "52998224725" not in raw
    shown = {c["id"]: c["seeds"] for c in store.list_cases()}
    assert shown["20261126-120000-0003"] == ["cpf:***.982.247-**"]  # display masks the CPF
    assert shown["20261126-120000-0001"] == ["email:alice@corp.example"]
    store.close()


def test_case_columns_derive_engagement_and_metadata():
    cols = case_columns(case_dict("x", mode="light", purpose="incident 7", seeds=["username:octocat"]))
    assert cols["engagement"] == 1 and cols["purpose"] == "incident 7"
    assert json.loads(cols["seeds"]) == [hmacid.pseudonymize_key("username:octocat")]
    assert case_columns({"seeds": [], "engagement": {"mode": "active"}})["engagement"] == 1
    assert case_columns({"seeds": []})["engagement"] == 0


def test_contract_additions_names_resolve():
    """Every name docs/contract_additions/WP10.md documents (``v3lum.*``, ``store.X``, ``Store.method``,
    ``quota.X``...) exists: the document and the code cannot drift apart."""
    import importlib
    import re
    from pathlib import Path

    doc = (Path(__file__).resolve().parent.parent / "docs" / "contract_additions" / "WP10.md").read_text(encoding="utf-8")
    roots = {
        "store": "v3lum.core.store", "quota": "v3lum.core.quota", "limiter": "v3lum.core.limiter", "cache": "v3lum.core.cache",
        "hmacid": "v3lum.core.hmacid", "migrations": "v3lum.core.migrations", "paths": "v3lum.paths",
        "Store": "v3lum.core.store.Store", "QuotaBook": "v3lum.core.quota.QuotaBook", "HttpCache": "v3lum.core.cache.HttpCache",
        "HostLimiter": "v3lum.core.limiter.HostLimiter", "PurgeReport": "v3lum.core.store.PurgeReport",
    }
    pattern = re.compile(r"(?<![\w./~-])((?:v3lum|" + "|".join(roots) + r")(?:\.[A-Za-z_][A-Za-z0-9_]*)+)")
    names = sorted({m.group(1) for span in re.findall(r"`([^`]+)`", doc) for m in pattern.finditer(span)})

    def resolve(dotted: str) -> bool:
        head, *rest = dotted.split(".")
        full = (roots.get(head, head) + ("." + ".".join(rest) if rest else "")).split(".")
        for cut in range(len(full), 0, -1):
            try:
                obj = importlib.import_module(".".join(full[:cut]))
            except ImportError:
                continue
            for attr in full[cut:]:
                fields = getattr(obj, "__dataclass_fields__", {})
                if not hasattr(obj, attr) and attr not in fields:
                    return False
                obj = getattr(obj, attr, None)
            return True
        return False

    missing = [n for n in names if not resolve(n)]
    assert len(names) > 40 and not missing, missing
