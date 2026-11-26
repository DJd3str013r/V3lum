"""Ordered SQLite schema migrations (AR04) for the case DB, the HTTP cache and the quota DB.

Every V3LUM database records its schema version in ``PRAGMA user_version``. :func:`migrate` applies
the pending steps of :data:`MIGRATIONS` in order, inside one ``BEGIN IMMEDIATE`` transaction (safe
when two processes open the same database: the second one re-reads the version under the lock), and
returns the version reached. A failing step rolls everything back (:class:`MigrationError`).

Version 1 of each kind is the schema V3LUM shipped before migrations existed. An unversioned
database that already holds those tables is *detected* as version 1 (nothing is re-created), so old
databases upgrade in place with their rows; an empty database starts at 0 and gets every step.

Kinds:

* ``'cases'`` (``~/.v3lum/v3lum.db``, :class:`v3lum.core.store.Store`): v2 adds the case columns
  (tlp, legal hold, purpose/ticket/legal basis, licence profile, recorded report paths, engagement
  flag), tombstones, per-case cache keys and finding ids, idempotent finding votes and Beta
  statistics per source/rule (P325), analyst overrides (P322), cross-case sightings (P375),
  evidence versions, the hash-chained audit table and report hashes (P324), watch state (P030), and
  pseudonymises the personal seeds of existing cases (A4).
* ``'cache'`` (``~/.v3lum/cache/http_cache.db``, :class:`v3lum.core.cache.HttpCache`): v2 adds
  ``fetched_at`` and the maintenance ``meta`` table (A10 prune state).
* ``'quota'`` (``~/.v3lum/quota.db`` or setting ``quota_db_path``, :class:`v3lum.core.quota.QuotaBook`):
  v2 adds provider ``windows``, provider ``signals`` and the ``deferred`` lookups (P334); the v1
  per-module ``quota`` table is kept (Module.daily_quota fallback).

Later packages never edit a shipped step: they append a new :class:`Migration` to the list of their
kind (an architect-approved change to this file).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

__all__ = [
    "CACHE_V1_SCHEMA",
    "CASES_V1_SCHEMA",
    "KINDS",
    "MIGRATIONS",
    "QUOTA_V1_SCHEMA",
    "Migration",
    "MigrationError",
    "describe",
    "latest_version",
    "migrate",
    "user_version",
]


@dataclass(frozen=True)
class Migration:
    """One schema step: ``apply`` is SQL text (statements separated by ';') or ``callable(conn)``.

    Steps run inside the migration transaction: they must not COMMIT, VACUUM or change the journal
    mode. ``detect`` (version 1 only) recognises an unversioned database that already has this
    schema, so it is marked as migrated without re-running the step.
    """

    version: int
    description: str
    apply: str | Callable[[sqlite3.Connection], None]
    detect: Callable[[sqlite3.Connection], bool] | None = None


class MigrationError(RuntimeError):
    """A migration step failed; the database was rolled back to its previous version."""


# ======================================================================================
# helpers
# ======================================================================================


def user_version(conn: sqlite3.Connection) -> int:
    """The ``PRAGMA user_version`` of ``conn``'s main database."""
    row = conn.execute("PRAGMA user_version").fetchone()
    return int(row[0]) if row else 0


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _add_columns(conn: sqlite3.Connection, table: str, columns: list[tuple[str, str]]) -> None:
    """ALTER TABLE ADD COLUMN for every missing column (idempotent)."""
    have = _columns(conn, table)
    for name, decl in columns:
        if name not in have:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def _statements(sql: str) -> list[str]:
    """Split SQL text into complete statements (semicolons inside strings/comments are safe)."""
    out: list[str] = []
    buf = ""
    for line in sql.splitlines(keepends=True):
        buf += line
        if sqlite3.complete_statement(buf):
            if buf.strip():
                out.append(buf.strip())
            buf = ""
    if buf.strip() and not all(part.strip().startswith("--") for part in buf.strip().splitlines()):
        out.append(buf.strip())
    return out


def _run(conn: sqlite3.Connection, step: Migration) -> None:
    if callable(step.apply):
        step.apply(conn)
        return
    for statement in _statements(step.apply):
        conn.execute(statement)


def _has_tables(*names: str) -> Callable[[sqlite3.Connection], bool]:
    def detect(conn: sqlite3.Connection) -> bool:
        return set(names) <= _tables(conn)

    return detect


# ======================================================================================
# 'cases' (v3lum.db)
# ======================================================================================

#: The case-DB schema V3LUM shipped before migrations (v1; kept verbatim).
CASES_V1_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    created TEXT NOT NULL,
    seeds TEXT NOT NULL,
    risk_score REAL,
    risk_level TEXT,
    findings INTEGER,
    entities INTEGER,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    verdict TEXT NOT NULL,          -- yes | partial | no
    notes TEXT,
    created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS finding_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    module TEXT NOT NULL,
    correct INTEGER NOT NULL,       -- 1 right, 0 wrong
    created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS module_stats (
    module TEXT PRIMARY KEY,
    correct INTEGER NOT NULL DEFAULT 0,
    wrong INTEGER NOT NULL DEFAULT 0
);
"""

_CASES_V2_TABLES = """
CREATE TABLE IF NOT EXISTS tombstones (
    case_id TEXT PRIMARY KEY,
    created TEXT,                   -- creation time of the purged case (no value of it survives)
    purged_at TEXT NOT NULL,
    purged_by TEXT NOT NULL,
    counts TEXT NOT NULL,           -- JSON {artefact: count}, value-free
    audit_until TEXT                -- engagement audit kept until this UTC time (NULL = nothing kept)
);
CREATE TABLE IF NOT EXISTS case_cache_keys (
    case_id TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    PRIMARY KEY (case_id, cache_key)
);
CREATE TABLE IF NOT EXISTS case_findings (
    case_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    PRIMARY KEY (case_id, finding_id)
);
CREATE INDEX IF NOT EXISTS case_findings_finding ON case_findings(finding_id);
CREATE TABLE IF NOT EXISTS finding_votes (
    case_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    analyst TEXT NOT NULL DEFAULT '',
    vote TEXT NOT NULL CHECK (vote IN ('right', 'wrong', 'partly')),
    reason TEXT,
    source_id TEXT NOT NULL DEFAULT '',
    rule_id TEXT NOT NULL DEFAULT '',
    created TEXT NOT NULL,
    UNIQUE (case_id, finding_id, analyst)
);
CREATE TABLE IF NOT EXISTS source_stats (
    source_id TEXT PRIMARY KEY,
    alpha REAL NOT NULL DEFAULT 0,
    beta REAL NOT NULL DEFAULT 0,
    votes INTEGER NOT NULL DEFAULT 0,
    updated TEXT
);
CREATE TABLE IF NOT EXISTS rule_stats (
    rule_id TEXT PRIMARY KEY,
    alpha REAL NOT NULL DEFAULT 0,
    beta REAL NOT NULL DEFAULT 0,
    votes INTEGER NOT NULL DEFAULT 0,
    updated TEXT
);
CREATE TABLE IF NOT EXISTS overrides (
    finding_id TEXT NOT NULL,
    analyst TEXT NOT NULL DEFAULT '',
    label TEXT,
    severity TEXT,
    verdict TEXT,
    note TEXT,
    created TEXT NOT NULL,
    PRIMARY KEY (finding_id, analyst)
);
CREATE TABLE IF NOT EXISTS sightings (
    entity_key TEXT NOT NULL DEFAULT '',     -- '' for PERSONAL_TYPES (HMAC only, A4)
    entity_hmac TEXT NOT NULL DEFAULT '',
    entity_type TEXT NOT NULL,
    case_id TEXT NOT NULL,
    case_tlp TEXT,
    engagement INTEGER NOT NULL DEFAULT 0,
    created TEXT NOT NULL,
    verdict TEXT,
    PRIMARY KEY (entity_key, entity_hmac, case_id)
);
CREATE INDEX IF NOT EXISTS sightings_case ON sightings(case_id);
CREATE INDEX IF NOT EXISTS sightings_hmac ON sightings(entity_hmac);
CREATE TABLE IF NOT EXISTS evidence_versions (
    case_id TEXT NOT NULL,
    record_key TEXT NOT NULL,
    version INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    path TEXT,
    collected_at TEXT,
    fetched_at TEXT,
    diff_summary TEXT,
    PRIMARY KEY (case_id, record_key, version)
);
CREATE TABLE IF NOT EXISTS audit (
    case_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    PRIMARY KEY (case_id, seq)
);
CREATE TABLE IF NOT EXISTS report_hashes (
    case_id TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT,                    -- NULL while only the path is recorded
    created TEXT NOT NULL,
    PRIMARY KEY (case_id, path)
);
CREATE TABLE IF NOT EXISTS watch_first_seen (
    rule_id TEXT NOT NULL,
    registrable_domain TEXT NOT NULL,
    cert_serial TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    case_id TEXT,
    PRIMARY KEY (rule_id, registrable_domain, cert_serial)
);
CREATE INDEX IF NOT EXISTS watch_first_seen_case ON watch_first_seen(case_id);
CREATE TABLE IF NOT EXISTS watch_mutes (
    rule_id TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    created TEXT NOT NULL,
    PRIMARY KEY (rule_id, domain)
);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    payload TEXT NOT NULL,
    case_id TEXT
);
CREATE INDEX IF NOT EXISTS alerts_case ON alerts(case_id);
CREATE INDEX IF NOT EXISTS alerts_rule_ts ON alerts(rule_id, ts);
CREATE INDEX IF NOT EXISTS cases_created ON cases(created);
CREATE INDEX IF NOT EXISTS feedback_case ON feedback(case_id);
CREATE INDEX IF NOT EXISTS finding_feedback_case ON finding_feedback(case_id);
"""

_CASES_V2_COLUMNS: list[tuple[str, str]] = [
    ("tlp", "TEXT"),
    ("legal_hold", "INTEGER NOT NULL DEFAULT 0"),
    ("hold_reason", "TEXT"),
    ("hold_requester", "TEXT"),
    ("held_at", "TEXT"),
    ("purpose", "TEXT"),
    ("ticket", "TEXT"),
    ("legal_basis", "TEXT"),
    ("licence_profile", "TEXT"),
    ("report_paths", "TEXT"),  # JSON list of every report path written for the case (-o included)
    ("engagement", "INTEGER NOT NULL DEFAULT 0"),  # LIGHT/ACTIVE case (A7 minimal audit retention)
]


def _cases_v2(conn: sqlite3.Connection) -> None:
    _add_columns(conn, "cases", _CASES_V2_COLUMNS)
    _add_columns(conn, "feedback", [("analyst", "TEXT NOT NULL DEFAULT ''")])
    for statement in _statements(_CASES_V2_TABLES):
        conn.execute(statement)
    # existing cases: derived columns, finding index and pseudonymised personal seeds (A4)
    from v3lum.core.store import case_columns  # late import: store imports this module

    rows = conn.execute("SELECT id, seeds, data FROM cases").fetchall()
    for case_id, seeds, data in rows:
        try:
            case = json.loads(data or "{}")
        except ValueError:
            case = {}
        if not isinstance(case, dict):
            case = {}
        if not case.get("seeds"):
            try:
                stored = json.loads(seeds or "[]")
            except ValueError:
                stored = []
            case = {**case, "seeds": stored if isinstance(stored, list) else []}
        cols = case_columns(case)
        conn.execute(
            "UPDATE cases SET seeds = ?, tlp = ?, purpose = ?, ticket = ?, legal_basis = ?, licence_profile = ?,"
            " report_paths = ?, engagement = ? WHERE id = ?",
            (
                cols["seeds"], cols["tlp"], cols["purpose"], cols["ticket"], cols["legal_basis"],
                cols["licence_profile"], cols["report_paths"], cols["engagement"], case_id,
            ),
        )
        conn.executemany(
            "INSERT OR IGNORE INTO case_findings (case_id, finding_id) VALUES (?, ?)",
            [(case_id, fid) for fid in cols["finding_ids"]],
        )


# ======================================================================================
# 'cache' (http_cache.db)
# ======================================================================================

#: The HTTP-cache schema shipped before migrations (v1).
CACHE_V1_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, url TEXT, host TEXT, status INTEGER,
    headers TEXT, body BLOB, ts REAL, history TEXT);
CREATE INDEX IF NOT EXISTS cache_host ON cache(host);
"""


def _cache_v2(conn: sqlite3.Connection) -> None:
    _add_columns(conn, "cache", [("fetched_at", "TEXT")])
    conn.execute(
        "UPDATE cache SET fetched_at = strftime('%Y-%m-%dT%H:%M:%S+00:00', ts, 'unixepoch')"
        " WHERE fetched_at IS NULL AND ts IS NOT NULL"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS cache_ts ON cache(ts)")
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")


# ======================================================================================
# 'quota' (quota.db)
# ======================================================================================

#: The quota-DB schema shipped before migrations (v1: per-module daily counters).
QUOTA_V1_SCHEMA = """
CREATE TABLE IF NOT EXISTS quota (module TEXT, day TEXT, used INTEGER, PRIMARY KEY (module, day));
"""

_QUOTA_V2 = """
CREATE TABLE IF NOT EXISTS windows (
    provider TEXT NOT NULL,
    scope_key TEXT NOT NULL,
    window TEXT NOT NULL CHECK (window IN ('hour', 'day', 'month')),
    window_start TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (provider, scope_key, window, window_start)
);
CREATE TABLE IF NOT EXISTS signals (
    provider TEXT NOT NULL,
    scope_key TEXT NOT NULL,
    exhausted_until TEXT NOT NULL,
    reason TEXT,
    PRIMARY KEY (provider, scope_key)
);
CREATE TABLE IF NOT EXISTS deferred (
    case_id TEXT NOT NULL,
    module TEXT NOT NULL,
    entity_key TEXT NOT NULL,       -- pseudonymised for personal types (A4)
    reason TEXT,
    created TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (case_id, module, entity_key)
);
"""

# ======================================================================================
# registry
# ======================================================================================

MIGRATIONS: dict[str, list[Migration]] = {
    "cases": [
        Migration(1, "v1 case DB: cases, feedback, finding_feedback, module_stats", CASES_V1_SCHEMA,
                  detect=_has_tables("cases", "feedback", "finding_feedback", "module_stats")),
        Migration(2, "storage v2: case columns, tombstones, cache keys, votes, Beta stats, overrides, sightings, "
                     "evidence versions, audit, report hashes, watch state; personal seeds pseudonymised", _cases_v2),
    ],
    "cache": [
        Migration(1, "v1 HTTP cache table", CACHE_V1_SCHEMA, detect=_has_tables("cache")),
        Migration(2, "fetched_at column, ts index and the maintenance meta table", _cache_v2),
    ],
    "quota": [
        Migration(1, "v1 per-module daily counters", QUOTA_V1_SCHEMA, detect=_has_tables("quota")),
        Migration(2, "provider windows, provider signals and deferred lookups (P334)", _QUOTA_V2),
    ],
}

#: The database kinds known to :func:`migrate`.
KINDS: tuple[str, ...] = tuple(MIGRATIONS)


def latest_version(kind: str) -> int:
    """The newest schema version of ``kind``."""
    try:
        return MIGRATIONS[kind][-1].version
    except KeyError:
        raise ValueError(f"unknown database kind {kind!r} (expected one of {', '.join(MIGRATIONS)})") from None


def migrate(conn: sqlite3.Connection, kind: str) -> int:
    """Apply the pending migrations of ``kind`` to ``conn`` in one transaction; return the version.

    Idempotent: an up-to-date database is left untouched (a database newer than this code is never
    downgraded). An unversioned database that already holds the v1 tables is detected as version 1.
    Raises :class:`MigrationError` (after a rollback) when a step fails.
    """
    steps = sorted(MIGRATIONS.get(kind) or (), key=lambda m: m.version)
    if not steps:
        raise ValueError(f"unknown database kind {kind!r} (expected one of {', '.join(MIGRATIONS)})")
    target = steps[-1].version
    if user_version(conn) >= target:
        return user_version(conn)
    previous = conn.isolation_level
    if conn.in_transaction:
        conn.commit()
    conn.isolation_level = None  # explicit BEGIN/COMMIT below (Python's implicit transactions off)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            version = user_version(conn)  # re-read under the write lock: another process may have migrated
            if version == 0 and steps[0].detect is not None and steps[0].detect(conn):
                version = steps[0].version
                conn.execute(f"PRAGMA user_version = {int(version)}")
            for step in steps:
                if step.version <= version:
                    continue
                try:
                    _run(conn, step)
                except Exception as exc:
                    raise MigrationError(f"{kind} migration {step.version} ({step.description}) failed: {exc}") from exc
                conn.execute(f"PRAGMA user_version = {int(step.version)}")
                version = step.version
            conn.execute("COMMIT")
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:  # pragma: no cover - nothing to roll back
                pass
            raise
    finally:
        conn.isolation_level = previous
    return version


def describe(kind: str) -> list[dict[str, Any]]:
    """``[{version, description}]`` of the steps of ``kind`` (doctor, docs)."""
    latest_version(kind)
    return [{"version": m.version, "description": m.description} for m in MIGRATIONS[kind]]
