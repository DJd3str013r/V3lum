"""Case storage (SQLite), retention and purge, legal hold, analyst feedback and module reliability.

The case DB (``~/.v3lum/v3lum.db``, 0600) is versioned by :mod:`v3lum.core.migrations` (kind
``'cases'``); :class:`Store` migrates it when it opens it, so databases written by older versions
upgrade in place.

* ``cases``: one row per investigation with the full case JSON (the only place, with the 0600 report
  files, where plain investigated values live) plus derived columns: case TLP, legal hold, purpose,
  ticket, legal basis, licence profile, recorded report paths and the LIGHT/ACTIVE engagement flag.
  The ``seeds`` column is a **search index**: PERSONAL_TYPES seeds (and free-text/file inputs) are
  stored as the keyed pseudonym ``'<type>:#<hmac12>'`` (A4), so ``list_cases(search=...)`` matches a
  personal value only when the exact value is typed (the query is hashed); substrings of personal
  values never match (no people search over past cases).
* ``feedback`` / ``finding_feedback`` / ``module_stats``: the v1 analyst feedback loop (kept); the
  per-source/per-rule Beta statistics, idempotent votes, overrides and sightings tables exist for
  the case-DB v2 package (WP16), the audit/evidence tables for the evidence store (WP15) and the
  watch tables for ``v3lum watch`` (WP26). Siblings use :meth:`Store.connection`.
* One purge routine (A10, AR04) for ``cases delete`` and ``cases purge``: :meth:`Store.purge_case`
  removes the case rows and every table row of the case (every table with a ``case_id`` column,
  tables added by later migrations included), the case directory (evidence, reports, audit mirror),
  every recorded report path (``-o`` included), the HTTP-cache rows fetched during the case and its
  deferred quota lookups, then runs ``PRAGMA secure_delete`` + ``VACUUM`` and keeps a value-free
  tombstone (case id, created, purged_at, purged_by, counts). Cases under legal hold are never
  purged. A LIGHT/ACTIVE case keeps only its **minimal engagement audit** until
  ``audit_retention_days`` after the case was created (0 = ``retention_days``): the audit rows reduced
  to :data:`ENGAGEMENT_AUDIT_FIELDS` (authorization reference, scope SHA-256, window, analyst, mode,
  egress, targets and request counts - purpose, ticket, hold reasons and every other field go with
  the case), re-sealed into a fresh hash chain closed by a ``purge`` row that names the previous
  chain head, plus the request ledger file (``ledger.jsonl``: no bodies, paths redacted); a later
  purge run removes them. :meth:`Store.purge_older_than` also sweeps case directories left without
  a case row (a crashed scan, a v1 ``cases delete``) once they are older than the retention.
  Aggregated per-source/per-rule/per-module counters survive (they hold no values).
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from v3lum import paths
from v3lum.core import hmacid
from v3lum.core.clock import SYSTEM_CLOCK, Clock
from v3lum.core.migrations import CASES_V1_SCHEMA, migrate

__all__ = [
    "AUDIT_GENESIS",
    "ENGAGEMENT_AUDIT_FIELDS",
    "ENGAGEMENT_AUDIT_FILES",
    "ENGAGEMENT_MODES",
    "PURGE_AUDIT_KIND",
    "SCHEMA",
    "PurgeReport",
    "Store",
    "audit_hash",
    "canonical_json",
    "case_columns",
    "minimal_audit_payload",
    "reliability_from",
]

#: The v1 schema (kept for compatibility); the live schema is ``migrations.MIGRATIONS['cases']``.
SCHEMA = CASES_V1_SCHEMA
#: Scan modes that make a case a LIGHT/ACTIVE engagement (A7 audit, A10 audit retention).
ENGAGEMENT_MODES = frozenset({"light", "active"})
#: Files of the minimal engagement audit kept in the case directory until audit_retention_days: the
#: request ledger (no bodies, paths redacted; P324 cond 5/7). The full audit mirror (``audit.jsonl``)
#: is case data and goes with the case; the minimal audit stays in the (minimised) audit rows.
ENGAGEMENT_AUDIT_FILES: tuple[str, ...] = ("ledger.jsonl",)
#: Audit payload fields of the minimal LIGHT/ACTIVE engagement audit (A10 BR3 and the A7 audit
#: record): the only audit content kept once the case is purged, until audit_retention_days. Purpose,
#: ticket, legal basis, TLP changes, hold reasons, overrides and every other field follow
#: retention_days. A nested ``engagement`` object is reduced to the same fields.
ENGAGEMENT_AUDIT_FIELDS: frozenset[str] = frozenset({
    "analyst", "os_user", "authorization_ref", "scope_sha256", "window", "window_start", "window_end",
    "mode", "opsec", "egress", "egress_profile", "egress_ip", "targets", "targets_touched", "modules",
    "request_count", "requests", "started", "ended", "engagement",
})
#: Kind of the audit row that closes a minimised engagement audit (who purged, how many rows were
#: minimised, the previous chain head and whether that chain was intact).
PURGE_AUDIT_KIND = "purge"
#: ``prev_hash`` of the first audit row of a case.
AUDIT_GENESIS = "0" * 64

_CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
#: Case ids the engine generates (``YYYYmmdd-HHMMSS-<hex>``): the only directory names the retention
#: sweep treats as abandoned case directories (other names under cases/ are never swept).
_GENERATED_ID_RE = re.compile(r"^(\d{8})-(\d{6})-[0-9a-f]{2,32}$")
_VERDICTS = ("yes", "partial", "no")
#: Tables whose rows belong to one case (``case_id`` column) and go with it. :func:`_case_tables` adds
#: every other table with a ``case_id`` column (tables of later migrations are purged too).
_CASE_TABLES: tuple[str, ...] = (
    "feedback",
    "finding_feedback",
    "finding_votes",
    "sightings",
    "evidence_versions",
    "report_hashes",
    "alerts",
    "watch_first_seen",
    "case_cache_keys",
    "case_findings",
)
#: Tables with a ``case_id`` column that the purge handles itself (never bulk-deleted).
_SPECIAL_TABLES = frozenset({"tombstones", "audit"})


# ======================================================================================
# helpers
# ======================================================================================


def canonical_json(obj: Any) -> str:
    """Canonical JSON (sorted keys, no spaces, UTF-8 kept): the hashed form of audit rows."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def audit_hash(prev_hash: str, record: Mapping[str, Any]) -> str:
    """Hash of one audit row: ``sha256(prev_hash + canonical_json(record))`` where ``record`` is
    ``{case_id, seq, ts, kind, payload}`` (payload as an object). The first row of a case chains to
    :data:`AUDIT_GENESIS`."""
    body = {k: record.get(k) for k in ("case_id", "seq", "ts", "kind", "payload")}
    return hashlib.sha256((str(prev_hash) + canonical_json(body)).encode("utf-8")).hexdigest()


def _iso(dt: _dt.datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc).isoformat(timespec="seconds")


def _parse_iso(text: Any) -> _dt.datetime | None:
    if not text:
        return None
    raw = str(text).strip().replace("Z", "+00:00")
    try:
        dt = _dt.datetime.fromisoformat(raw)
    except ValueError:
        try:
            dt = _dt.datetime.fromisoformat(raw[:10])
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt


def _json_list(text: Any) -> list[str]:
    if not text:
        return []
    try:
        data = json.loads(text) if isinstance(text, str) else text
    except ValueError:
        return []
    return [str(x) for x in data if x] if isinstance(data, list) else []


def _report_paths_of(case: Mapping[str, Any]) -> list[str]:
    reports = case.get("reports")
    if isinstance(reports, Mapping):
        values: Iterable[Any] = reports.values()
    elif isinstance(reports, (list, tuple)):
        values = reports
    else:
        values = ()
    return _unique_paths(values)


def _unique_paths(*groups: Iterable[Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for item in group or ():
            if not item or not isinstance(item, (str, os.PathLike)):
                continue
            text = os.path.abspath(os.fspath(item))
            if text not in seen:
                seen.add(text)
                out.append(text)
    return out


def case_columns(case: Mapping[str, Any]) -> dict[str, Any]:
    """Derived case-row columns of a case dict (also used by the v2 migration for old rows):
    ``seeds`` (JSON search index, personal seeds pseudonymised), ``tlp``, ``purpose``, ``ticket``,
    ``legal_basis``, ``licence_profile``, ``report_paths`` (JSON), ``engagement`` (0/1) and
    ``finding_ids`` (finding and correlation ids, for the override clean-up)."""
    options = case.get("options") if isinstance(case.get("options"), Mapping) else {}
    seeds = [str(s) for s in (case.get("seeds") or []) if s]
    mode = str(options.get("mode") or case.get("mode") or "").strip().lower()
    engagement = 1 if (mode in ENGAGEMENT_MODES or case.get("engagement")) else 0
    ids: set[str] = set()
    for group in ("findings", "correlations"):
        for item in case.get(group) or ():
            if isinstance(item, Mapping) and item.get("id"):
                ids.add(str(item["id"]))
    return {
        "seeds": json.dumps([hmacid.pseudonymize_key(k) for k in seeds], ensure_ascii=False),
        "tlp": str(case.get("tlp") or options.get("tlp") or ""),
        "purpose": str(options.get("purpose") or case.get("purpose") or ""),
        "ticket": str(options.get("ticket") or case.get("ticket") or ""),
        "legal_basis": str(options.get("legal_basis") or case.get("legal_basis") or ""),
        "licence_profile": str(case.get("licence_profile") or options.get("licence_profile") or ""),
        "report_paths": json.dumps(_report_paths_of(case), ensure_ascii=False),
        "engagement": engagement,
        "finding_ids": sorted(ids),
    }


def _display_seed(key: str) -> str:
    """'type:value' with the value masked for display (CPF, VIN, secrets...)."""
    etype_name, sep, value = str(key).partition(":")
    if not sep:
        return str(key)
    try:
        from v3lum.core.entities import EntityType, display_value

        return f"{etype_name}:{display_value(EntityType.parse(etype_name), value)}"
    except Exception:  # an unreadable seed is shown as stored
        return str(key)


def _like(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def minimal_audit_payload(payload: Any) -> dict[str, Any]:
    """An audit payload reduced to the minimal engagement audit (:data:`ENGAGEMENT_AUDIT_FIELDS`;
    a nested ``engagement`` object is reduced the same way). Anything that is not an object gives {}."""
    if not isinstance(payload, Mapping):
        return {}
    out: dict[str, Any] = {}
    for key, value in payload.items():
        if key not in ENGAGEMENT_AUDIT_FIELDS:
            continue
        out[key] = minimal_audit_payload(value) if key == "engagement" else value
    return out


def _parse_payload(text: Any) -> Any:
    try:
        return json.loads(text) if isinstance(text, str) else text
    except ValueError:
        return text


def _quote_ident(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _case_tables(conn: sqlite3.Connection) -> list[str]:
    """Every table whose rows belong to one case: :data:`_CASE_TABLES` plus any other table with a
    ``case_id`` column (added by a later migration), except the tombstones and the audit."""
    found = list(_CASE_TABLES)
    for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").fetchall():
        name = str(name)
        if name in _SPECIAL_TABLES or name in found or name.startswith("sqlite_"):
            continue
        if "case_id" in {r[1] for r in conn.execute(f"PRAGMA table_info({_quote_ident(name)})")}:
            found.append(name)
    present = {str(r[0]) for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    return [t for t in found if t in present]


def _created_from_id(case_id: str) -> str:
    """Creation time encoded in a generated case id ('' for other ids)."""
    m = _GENERATED_ID_RE.match(case_id or "")
    if not m:
        return ""
    try:
        when = _dt.datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S").replace(tzinfo=_dt.timezone.utc)
    except ValueError:
        return ""
    return _iso(when)


def _row_payload(row: Mapping[str, Any]) -> Any:
    return _parse_payload(row["payload"])


def _minimisable(rows: Iterable[Mapping[str, Any]]) -> int:
    """How many audit rows carry more than the minimal engagement audit (purge rows excluded)."""
    count = 0
    for r in rows:
        if r["kind"] == PURGE_AUDIT_KIND:
            continue
        payload = _row_payload(r)
        if minimal_audit_payload(payload) != payload:
            count += 1
    return count


def _minimise_audit(conn: sqlite3.Connection, case_id: str, rows: list[Any], *, by: str, stamp: str) -> int:
    """Reduce the audit rows of a purged engagement case to :data:`ENGAGEMENT_AUDIT_FIELDS`, re-seal
    them into a fresh hash chain (the old hashes covered fields that no longer exist) and close it
    with a :data:`PURGE_AUDIT_KIND` row naming the purger, the rows minimised, the previous chain head
    and whether the previous chain verified (a chain broken before the purge stays on record).
    Runs inside the caller's transaction; returns the number of rows minimised."""
    prev_stored = AUDIT_GENESIS
    intact = True
    for index, r in enumerate(rows, 1):
        payload = _row_payload(r)
        record = {"case_id": case_id, "seq": r["seq"], "ts": r["ts"], "kind": r["kind"], "payload": payload}
        if int(r["seq"]) != index or r["prev_hash"] != prev_stored or audit_hash(r["prev_hash"], record) != r["hash"]:
            intact = False
        prev_stored = r["hash"]
    prev = AUDIT_GENESIS
    changed = 0
    updates: list[tuple[str, str, str, str, int]] = []
    last_seq = 0
    for r in rows:
        payload = _row_payload(r)
        minimal = payload if r["kind"] == PURGE_AUDIT_KIND else minimal_audit_payload(payload)
        if minimal != payload:
            changed += 1
        record = {"case_id": case_id, "seq": int(r["seq"]), "ts": r["ts"], "kind": r["kind"], "payload": minimal}
        digest = audit_hash(prev, record)
        updates.append((canonical_json(minimal), prev, digest, case_id, int(r["seq"])))
        prev = digest
        last_seq = max(last_seq, int(r["seq"]))
    conn.executemany("UPDATE audit SET payload = ?, prev_hash = ?, hash = ? WHERE case_id = ? AND seq = ?", updates)
    closing = {"by": by, "rows": len(rows), "minimised_rows": changed, "previous_head": prev_stored, "previous_chain_intact": intact}
    record = {"case_id": case_id, "seq": last_seq + 1, "ts": stamp, "kind": PURGE_AUDIT_KIND, "payload": closing}
    conn.execute(
        "INSERT INTO audit (case_id, seq, ts, kind, payload, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (case_id, last_seq + 1, stamp, PURGE_AUDIT_KIND, canonical_json(closing), prev, audit_hash(prev, record)),
    )
    return changed


# ======================================================================================
# purge report
# ======================================================================================


@dataclass
class PurgeReport:
    """Outcome of :meth:`Store.purge_case` (one case).

    ``found``: a case row existed. ``purged``: artefacts were removed (False on a dry run, for a held
    case and when nothing was found). ``held``: legal hold, nothing touched. ``counts``: artefact ->
    number removed (or that a dry run would remove; ``audit_minimised`` = engagement audit rows
    reduced to the minimal audit). ``files``: the file paths removed (in memory only, never stored).
    ``audit_until``: the engagement audit is kept until this UTC time ('' when nothing is kept).
    ``previously_purged``: purged_at of the tombstone when the case had been purged before.
    ``errors``: what could not be removed (the purge is then incomplete).
    """

    case_id: str
    found: bool = False
    purged: bool = False
    dry_run: bool = False
    held: bool = False
    reason: str = ""
    counts: dict[str, int] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)
    audit_until: str = ""
    errors: list[str] = field(default_factory=list)
    previously_purged: str = ""

    @property
    def total(self) -> int:
        """Number of artefacts removed (or that would be)."""
        return sum(int(v) for v in self.counts.values())

    @property
    def complete(self) -> bool:
        """True when nothing that should have been removed was left behind."""
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def line(self) -> str:
        """One human line for the CLI."""
        if self.held:
            return f"{self.case_id}: kept (legal hold{': ' + self.reason if self.reason else ''})"
        if not self.found and not self.total:
            if self.previously_purged:
                text = f"{self.case_id}: already purged ({self.previously_purged})"
                return text + (f"; engagement audit kept until {self.audit_until}" if self.audit_until else "")
            return f"{self.case_id}: not found"
        verb = "would remove" if self.dry_run else "removed"
        parts = [f"{name.replace('_', ' ')} {n}" for name, n in sorted(self.counts.items()) if n]
        text = f"{self.case_id}: {verb} {', '.join(parts) if parts else 'nothing'}"
        if self.audit_until:
            text += f"; engagement audit kept until {self.audit_until}"
        if self.errors:
            text += f"; {len(self.errors)} problem(s): {self.errors[0]}"
        return text


# ======================================================================================
# store
# ======================================================================================


class Store:
    """The case DB. ``Store(path=None, *, settings=None, clock=None, cache_path=None, quota_path=None)``.

    ``path`` defaults to ``paths.db_file()``; ``settings`` (Config or mapping; default
    ``Config.load()`` on first use) provides retention_days, audit_retention_days and
    quota_db_path; ``clock`` stamps rows and drives retention; ``cache_path``/``quota_path`` override
    the HTTP-cache and quota DBs the purge cleans (defaults: ``paths.cache_file()`` and the quota
    DB of the settings). Thread-safe (one connection behind a re-entrant lock).
    """

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        settings: Any = None,
        clock: Clock | None = None,
        cache_path: str | Path | None = None,
        quota_path: str | Path | None = None,
    ) -> None:
        self.path = str(path or paths.db_file())
        self.clock: Clock = clock or SYSTEM_CLOCK
        self._settings = settings
        self._cache_path = cache_path
        self._quota_path = quota_path
        self._lock = threading.RLock()
        paths.restrict_file(self.path, create=True)  # never exists with a looser mode (AR03)
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA secure_delete = ON")
        #: schema version after the migrations ran
        self.version = migrate(self._conn, "cases")
        paths.restrict_file(self.path)

    # ------------------------------------------------------------------ plumbing
    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @contextlib.contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """The case-DB connection for sibling packages (audit, feedback, sightings, watch), held
        under the store lock for the block: committed on success, rolled back on an exception."""
        with self._lock:
            try:
                yield self._conn
            except BaseException:
                self._conn.rollback()
                raise
            else:
                self._conn.commit()

    def _now(self, now: _dt.datetime | None = None) -> _dt.datetime:
        current = now or self.clock.now()
        return current if current.tzinfo else current.replace(tzinfo=_dt.timezone.utc)

    def setting(self, name: str, default: Any = None) -> Any:
        """A setting from the injected settings, else the loaded Config (cached per store)."""
        settings = self._settings
        if settings is None:
            try:
                from v3lum.config import Config

                settings = self._settings = Config.load()
            except Exception:  # pragma: no cover - a broken config never breaks the store
                return default
        try:
            getter = getattr(settings, "get", None)
            value = getter(name, default) if callable(getter) else getattr(settings, name, default)
        except Exception:  # pragma: no cover
            return default
        return default if value is None else value

    def _int_setting(self, name: str, default: int) -> int:
        try:
            return int(float(self.setting(name, default)))
        except (TypeError, ValueError):
            return default

    def retention_days(self) -> int:
        """Setting retention_days (A10; 0 = no automatic retention purge)."""
        return max(0, self._int_setting("retention_days", 180))

    def audit_retention_days(self) -> int:
        """Setting audit_retention_days (0 = retention_days), the minimal engagement audit's retention."""
        days = max(0, self._int_setting("audit_retention_days", 0))
        return days or self.retention_days()

    # ------------------------------------------------------------------ cases
    def save_case(self, case: Mapping[str, Any]) -> None:
        """Insert or update a case (the legal hold and earlier recorded report paths are kept)."""
        summary = case.get("summary", {}) or {}
        cols = case_columns(case)
        case_id = str(case["case_id"])
        created = str(case.get("created") or _iso(self._now()))
        data = json.dumps(case, ensure_ascii=False, default=str)
        with self.connection() as conn:
            row = conn.execute("SELECT report_paths FROM cases WHERE id = ?", (case_id,)).fetchone()
            recorded = [r[0] for r in conn.execute("SELECT path FROM report_hashes WHERE case_id = ?", (case_id,))]
            merged = _unique_paths(_json_list(row["report_paths"]) if row else [], _json_list(cols["report_paths"]), recorded)
            conn.execute(
                "INSERT INTO cases (id, created, seeds, risk_score, risk_level, findings, entities, data, tlp, purpose,"
                " ticket, legal_basis, licence_profile, report_paths, engagement) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET created = excluded.created, seeds = excluded.seeds,"
                " risk_score = excluded.risk_score, risk_level = excluded.risk_level, findings = excluded.findings,"
                " entities = excluded.entities, data = excluded.data, tlp = excluded.tlp, purpose = excluded.purpose,"
                " ticket = excluded.ticket, legal_basis = excluded.legal_basis,"
                " licence_profile = excluded.licence_profile, report_paths = excluded.report_paths,"
                " engagement = MAX(cases.engagement, excluded.engagement)",
                (
                    case_id,
                    created,
                    cols["seeds"],
                    summary.get("risk_score", 0.0),
                    summary.get("risk_level", "clean"),
                    summary.get("findings", 0),
                    summary.get("entities", 0),
                    data,
                    cols["tlp"],
                    cols["purpose"],
                    cols["ticket"],
                    cols["legal_basis"],
                    cols["licence_profile"],
                    json.dumps(merged, ensure_ascii=False),
                    cols["engagement"],
                ),
            )
            conn.execute("DELETE FROM case_findings WHERE case_id = ?", (case_id,))
            conn.executemany(
                "INSERT OR IGNORE INTO case_findings (case_id, finding_id) VALUES (?, ?)",
                [(case_id, fid) for fid in cols["finding_ids"]],
            )

    def _search_patterns(self, search: str) -> list[str]:
        """LIKE patterns for the seeds index: the text itself (non-personal values match by
        substring) plus the pseudonym of every personal type the exact query parses as (A4 BR8)."""
        query = search.strip()
        patterns = [_like(query)]
        try:
            from v3lum.core.entities import Entity, EntityType
        except ImportError:  # pragma: no cover
            return patterns
        candidates: list[tuple[Any, str]] = []
        etype_name, sep, value = query.partition(":")
        if sep:
            try:
                candidates.append((EntityType.parse(etype_name), value))
            except ValueError:
                pass
        candidates.extend((t, query) for t in sorted(hmacid.PSEUDONYMISED_TYPES, key=lambda t: t.value))
        for etype, raw in candidates:
            if etype not in hmacid.PSEUDONYMISED_TYPES:
                continue
            entity = Entity.try_make(etype, raw)
            if entity is not None:
                pattern = _like(f'"{hmacid.pseudonym(entity.type, entity.value)}"')
                if pattern not in patterns:
                    patterns.append(pattern)
        return patterns

    def list_cases(self, limit: int = 30, search: str = "") -> list[dict[str, Any]]:
        """Newest cases first: id, created, seeds (display form, sensitive values masked), risk,
        counts, tlp, legal_hold, engagement. ``search`` matches the case id, non-personal seeds by
        substring and personal seeds only by their exact value (hashed before matching)."""
        sql = (
            "SELECT id, created, seeds, risk_score, risk_level, findings, entities, tlp, legal_hold, engagement,"
            " json_extract(data, '$.seeds') AS display_seeds FROM cases"
        )
        params: list[Any] = []
        if search and search.strip():
            patterns = self._search_patterns(search)
            clauses = ["id LIKE ? ESCAPE '\\'"] + ["seeds LIKE ? ESCAPE '\\'"] * len(patterns)
            sql += " WHERE " + " OR ".join(clauses)
            params += [_like(search.strip()), *patterns]
        sql += " ORDER BY created DESC LIMIT ?"
        params.append(int(limit))
        with self._lock:
            try:
                rows = self._conn.execute(sql, params).fetchall()
            except sqlite3.OperationalError:  # SQLite without JSON1: parse the case JSON in Python
                rows = self._conn.execute(sql.replace("json_extract(data, '$.seeds')", "data"), params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            raw = d.pop("display_seeds", None)
            seeds: list[str] = []
            try:
                parsed = json.loads(raw) if raw else []
                if isinstance(parsed, dict):
                    parsed = parsed.get("seeds") or []
                seeds = [str(s) for s in parsed] if isinstance(parsed, list) else []
            except ValueError:
                seeds = []
            if not seeds:
                seeds = _json_list(d.get("seeds"))
            d["seeds"] = [_display_seed(s) if not hmacid.is_pseudonym(s) else s for s in seeds]
            d["legal_hold"] = bool(d.get("legal_hold"))
            d["engagement"] = bool(d.get("engagement"))
            out.append(d)
        return out

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        """The stored case dict: exact id, 'last'/'latest', or a unique id prefix."""
        with self._lock:
            row = self._conn.execute("SELECT data FROM cases WHERE id = ?", (case_id,)).fetchone()
            if row is None and case_id in ("last", "latest"):
                row = self._conn.execute("SELECT data FROM cases ORDER BY created DESC LIMIT 1").fetchone()
            if row is None:
                rows = self._conn.execute(
                    "SELECT data FROM cases WHERE id LIKE ? ESCAPE '\\' ORDER BY created DESC", (_like(case_id)[1:],)
                ).fetchall()
                row = rows[0] if len(rows) == 1 else None
        return json.loads(row["data"]) if row else None

    def case_info(self, case_id: str) -> dict[str, Any] | None:
        """The case row without its JSON: created, tlp, legal hold fields, purpose, ticket,
        legal_basis, licence_profile, report_paths (list), engagement. None when unknown."""
        with self._lock:
            row = self._conn.execute(
                "SELECT id, created, tlp, legal_hold, hold_reason, hold_requester, held_at, purpose, ticket, legal_basis,"
                " licence_profile, report_paths, engagement, risk_score, risk_level, findings, entities FROM cases WHERE id = ?",
                (case_id,),
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["report_paths"] = _json_list(d.get("report_paths"))
        d["legal_hold"] = bool(d.get("legal_hold"))
        d["engagement"] = bool(d.get("engagement"))
        return d

    def delete_case(self, case_id: str) -> bool:
        """v1 entry point, now the A10 purge: ``purge_case(case_id, by='cli')``. True when the case
        existed and was purged (False for an unknown case or one under legal hold)."""
        report = self.purge_case(case_id, by="cli")
        return report.found and report.purged

    # ------------------------------------------------------------------ recorded artefacts
    def record_report_paths(self, case_id: str, report_paths: Mapping[str, Any] | Iterable[Any]) -> int:
        """Remember report files written for a case (any directory, ``-o`` included) so the purge
        removes them. Works before the case row exists. Returns the number of new paths."""
        values = report_paths.values() if isinstance(report_paths, Mapping) else report_paths
        items = _unique_paths(values)
        if not items:
            return 0
        stamp = _iso(self._now())
        with self.connection() as conn:
            before = conn.total_changes
            conn.executemany(
                "INSERT OR IGNORE INTO report_hashes (case_id, path, sha256, created) VALUES (?, ?, NULL, ?)",
                [(case_id, p, stamp) for p in items],
            )
            added = conn.total_changes - before
            self._merge_report_paths(conn, case_id, items)
        return added

    def record_report_hashes(self, case_id: str, hashes: Mapping[str, str]) -> int:
        """Record ``{path: sha256}`` of written reports (WP20 writes them, WP15's verify reads them);
        the paths are also recorded for the purge. Returns the number of rows written."""
        rows = [(os.path.abspath(os.fspath(p)), str(h or "").lower() or None) for p, h in (hashes or {}).items() if p]
        if not rows:
            return 0
        stamp = _iso(self._now())
        with self.connection() as conn:
            conn.executemany(
                "INSERT INTO report_hashes (case_id, path, sha256, created) VALUES (?, ?, ?, ?)"
                " ON CONFLICT(case_id, path) DO UPDATE SET sha256 = excluded.sha256, created = excluded.created",
                [(case_id, p, h, stamp) for p, h in rows],
            )
            self._merge_report_paths(conn, case_id, [p for p, _ in rows])
        return len(rows)

    def report_hashes(self, case_id: str) -> dict[str, str]:
        """``{path: sha256}`` of the reports recorded with a hash for ``case_id``."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT path, sha256 FROM report_hashes WHERE case_id = ? AND sha256 IS NOT NULL AND sha256 != '' ORDER BY path",
                (case_id,),
            ).fetchall()
        return {r["path"]: r["sha256"] for r in rows}

    def report_paths(self, case_id: str) -> list[str]:
        """Every report path recorded for ``case_id`` (case row, recorded paths and hashes)."""
        with self._lock:
            row = self._conn.execute("SELECT report_paths FROM cases WHERE id = ?", (case_id,)).fetchone()
            recorded = [r[0] for r in self._conn.execute("SELECT path FROM report_hashes WHERE case_id = ? ORDER BY path", (case_id,))]
        return _unique_paths(_json_list(row["report_paths"]) if row else [], recorded)

    @staticmethod
    def _merge_report_paths(conn: sqlite3.Connection, case_id: str, items: list[str]) -> None:
        row = conn.execute("SELECT report_paths FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            return
        merged = _unique_paths(_json_list(row["report_paths"]), items)
        conn.execute("UPDATE cases SET report_paths = ? WHERE id = ?", (json.dumps(merged, ensure_ascii=False), case_id))

    def record_cache_keys(self, case_id: str, keys: Iterable[str]) -> int:
        """Remember the HTTP-cache keys written or served during a case (HttpClient cache_key_sink)
        so the purge removes those cache rows (A10). Returns the number of new keys."""
        items = sorted({str(k) for k in (keys or ()) if k})
        if not items:
            return 0
        with self.connection() as conn:
            before = conn.total_changes
            conn.executemany("INSERT OR IGNORE INTO case_cache_keys (case_id, cache_key) VALUES (?, ?)", [(case_id, k) for k in items])
            return conn.total_changes - before

    def cache_keys(self, case_id: str) -> list[str]:
        """The cache keys recorded for ``case_id``."""
        with self._lock:
            return [r[0] for r in self._conn.execute("SELECT cache_key FROM case_cache_keys WHERE case_id = ? ORDER BY cache_key", (case_id,))]

    # ------------------------------------------------------------------ audit (hash chain)
    def append_audit(self, case_id: str, kind: str, payload: Mapping[str, Any] | None = None, *, ts: str | None = None) -> dict[str, Any]:
        """Append one hash-chained audit row (``seq`` 1, 2, ...; ``hash`` = :func:`audit_hash`) and
        return it. Payloads hold metadata only (no bodies, no secrets); they are stored as
        canonical JSON."""
        body = dict(payload or {})
        with self.connection() as conn:
            if not conn.in_transaction:  # take the write lock before reading the chain head (other processes)
                conn.execute("BEGIN IMMEDIATE")
            last = conn.execute("SELECT seq, hash FROM audit WHERE case_id = ? ORDER BY seq DESC LIMIT 1", (case_id,)).fetchone()
            seq = int(last["seq"]) + 1 if last else 1
            prev = str(last["hash"]) if last else AUDIT_GENESIS
            stamp = ts or _iso(self._now())
            record = {"case_id": case_id, "seq": seq, "ts": stamp, "kind": str(kind), "payload": body}
            digest = audit_hash(prev, record)
            conn.execute(
                "INSERT INTO audit (case_id, seq, ts, kind, payload, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (case_id, seq, stamp, str(kind), canonical_json(body), prev, digest),
            )
        return {**record, "prev_hash": prev, "hash": digest}

    def audit_rows(self, case_id: str) -> list[dict[str, Any]]:
        """The audit rows of ``case_id`` in order (payload parsed)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT case_id, seq, ts, kind, payload, prev_hash, hash FROM audit WHERE case_id = ? ORDER BY seq", (case_id,)
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["payload"] = json.loads(d["payload"])
            except ValueError:
                pass
            out.append(d)
        return out

    def verify_audit_chain(self, case_id: str) -> list[str]:
        """Problems of the audit chain of ``case_id`` (empty list = intact)."""
        problems: list[str] = []
        prev = AUDIT_GENESIS
        for index, row in enumerate(self.audit_rows(case_id), 1):
            if int(row["seq"]) != index:
                problems.append(f"audit row {row['seq']}: expected sequence number {index}")
            if row["prev_hash"] != prev:
                problems.append(f"audit row {row['seq']}: prev_hash does not match the previous row")
            if audit_hash(row["prev_hash"], row) != row["hash"]:
                problems.append(f"audit row {row['seq']}: hash mismatch (row edited)")
            prev = row["hash"]
        return problems

    # ------------------------------------------------------------------ legal hold
    def hold(self, case_id: str, reason: str, requester: str, *, now: _dt.datetime | None = None) -> bool:
        """Put a case under legal hold (exempt from every purge, A10); writes an audit row 'hold'.
        Reason and requester are required. False when the case does not exist."""
        reason, requester = str(reason or "").strip(), str(requester or "").strip()
        if not reason or not requester:
            raise ValueError("a legal hold needs a reason and a requester")
        stamp = _iso(self._now(now))
        with self.connection() as conn:
            cur = conn.execute(
                "UPDATE cases SET legal_hold = 1, hold_reason = ?, hold_requester = ?, held_at = ? WHERE id = ?",
                (reason, requester, stamp, case_id),
            )
            if cur.rowcount == 0:
                return False
            self.append_audit(case_id, "hold", {"reason": reason, "requester": requester}, ts=stamp)
        return True

    def unhold(self, case_id: str, *, by: str = "", now: _dt.datetime | None = None) -> bool:
        """Release a legal hold; writes an audit row 'unhold'. False when the case is unknown or not held."""
        stamp = _iso(self._now(now))
        with self.connection() as conn:
            row = conn.execute("SELECT legal_hold, hold_reason, hold_requester FROM cases WHERE id = ?", (case_id,)).fetchone()
            if row is None or not row["legal_hold"]:
                return False
            conn.execute("UPDATE cases SET legal_hold = 0, hold_reason = NULL, hold_requester = NULL, held_at = NULL WHERE id = ?", (case_id,))
            payload = {"previous_reason": row["hold_reason"] or "", "previous_requester": row["hold_requester"] or ""}
            if by:
                payload["by"] = str(by)
            self.append_audit(case_id, "unhold", payload, ts=stamp)
        return True

    def held_cases(self) -> list[dict[str, Any]]:
        """Cases under legal hold: id, created, hold_reason, hold_requester, held_at."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, created, hold_reason, hold_requester, held_at FROM cases WHERE legal_hold = 1 ORDER BY created"
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ retention
    def cases_past_retention(self, now: _dt.datetime | None = None) -> list[dict[str, Any]]:
        """Cases older than retention_days that are not held (startup reminder, ``cases purge``):
        ``[{id, created, age_days}]`` oldest first; [] when retention_days is 0."""
        days = self.retention_days()
        if days <= 0:
            return []
        current = self._now(now)
        cutoff = current - _dt.timedelta(days=days)
        with self._lock:
            rows = self._conn.execute("SELECT id, created FROM cases WHERE legal_hold = 0 ORDER BY created").fetchall()
        out = []
        for r in rows:
            created = _parse_iso(r["created"])
            if created is not None and created < cutoff:
                out.append({"id": r["id"], "created": r["created"], "age_days": (current - created).days})
        return out

    def retention_reminder(self, now: _dt.datetime | None = None) -> str:
        """The startup reminder line ('3 cases older than 180 days: v3lum cases purge'), at most once
        per day (state in ``paths.reminder_file()``); '' when nothing is due or it was shown today."""
        current = self._now(now)
        today = current.date().isoformat()
        state_path = paths.reminder_file()
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            state = {}
        if isinstance(state, dict) and state.get("last") == today:
            return ""
        due = self.cases_past_retention(current)
        if not due:
            return ""
        try:
            paths.secure_write_text(state_path, json.dumps({"last": today}))
        except OSError:  # pragma: no cover - a read-only home shows the line again tomorrow too
            pass
        n = len(due)
        return f"{n} case{'s' if n != 1 else ''} older than {self.retention_days()} days: v3lum cases purge"

    # ------------------------------------------------------------------ purge (A10)
    def tombstone(self, case_id: str) -> dict[str, Any] | None:
        """The value-free tombstone of a purged case (counts parsed) or None."""
        with self._lock:
            row = self._conn.execute(
                "SELECT case_id, created, purged_at, purged_by, counts, audit_until FROM tombstones WHERE case_id = ?", (case_id,)
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        try:
            d["counts"] = json.loads(d["counts"] or "{}")
        except ValueError:
            d["counts"] = {}
        return d

    def tombstones(self) -> list[dict[str, Any]]:
        """Every tombstone, newest purge first."""
        with self._lock:
            ids = [r[0] for r in self._conn.execute("SELECT case_id FROM tombstones ORDER BY purged_at DESC, case_id")]
        return [t for t in (self.tombstone(i) for i in ids) if t is not None]

    def purge_case(self, case_id: str, *, by: str, dry_run: bool = False, now: _dt.datetime | None = None, vacuum: bool = True) -> PurgeReport:
        """THE purge routine (A10/AR04) behind ``cases delete`` and ``cases purge``.

        Removes the case row and its rows in every case table (feedback, votes, sightings, evidence
        versions, report hashes, alerts, watch first-seen state, cache keys and any table a later
        migration adds with a ``case_id`` column), the analyst overrides of its finding ids that no
        other stored case still contains, the case directory (evidence, reports, the audit mirror),
        every recorded report file outside it whose name contains the case id (and its ``.sha256``
        sidecar), the HTTP-cache rows recorded for the case and its deferred quota lookups; then
        ``PRAGMA secure_delete`` + ``VACUUM`` of the case DB and the cache (``vacuum=False`` defers
        both to the caller) and writes a value-free tombstone. A case under legal hold is left
        untouched (``held=True``).

        For a LIGHT/ACTIVE engagement only the minimal engagement audit stays until
        audit_retention_days after the case creation: the audit rows reduced to
        :data:`ENGAGEMENT_AUDIT_FIELDS` and re-sealed into a fresh hash chain closed by a
        :data:`PURGE_AUDIT_KIND` row (purged by, rows minimised, the previous chain head and whether
        it was intact), and the :data:`ENGAGEMENT_AUDIT_FILES` (the request ledger). Purging again
        after that date removes them. A directory left without a case row is purged too (its
        ledger, if any, follows the same audit retention). ``dry_run`` only counts.
        """
        case_id = str(case_id or "").strip()
        report = PurgeReport(case_id=case_id, dry_run=bool(dry_run))
        if not case_id:
            report.reason = "empty case id"
            return report
        current = self._now(now)
        with self._lock:
            conn = self._conn
            row = conn.execute(
                "SELECT id, created, legal_hold, hold_reason, engagement, report_paths FROM cases WHERE id = ?", (case_id,)
            ).fetchone()
            tomb = self.tombstone(case_id)
            report.found = row is not None
            report.previously_purged = str((tomb or {}).get("purged_at") or "")
            if row is not None and row["legal_hold"]:
                report.held = True
                report.reason = str(row["hold_reason"] or "")
                return report
            directory = paths.cases_dir() / case_id if _CASE_ID_RE.match(case_id) else None
            created = (row["created"] if row is not None else (tomb or {}).get("created")) or _created_from_id(case_id)
            if row is not None:
                engagement = bool(row["engagement"])
            elif tomb is not None:
                engagement = bool(tomb.get("audit_until"))
            else:  # a directory without a case row: a request ledger means LIGHT/ACTIVE contact happened
                engagement = directory is not None and any(os.path.lexists(directory / n) for n in ENGAGEMENT_AUDIT_FILES)
            keep_until = ""
            if engagement:
                base = _parse_iso(created) or current
                until = base + _dt.timedelta(days=self.audit_retention_days())
                if until > current:
                    keep_until = _iso(until)
            report.audit_until = keep_until
            counts: dict[str, int] = {}
            tables = _case_tables(conn)

            # -- database rows (counted first; removed below unless dry run)
            counts["cases"] = 1 if row is not None else 0
            for table in tables:
                counts[table] = int(conn.execute(f"SELECT COUNT(*) FROM {_quote_ident(table)} WHERE case_id = ?", (case_id,)).fetchone()[0])
            override_sql = (
                " FROM overrides WHERE finding_id IN (SELECT finding_id FROM case_findings WHERE case_id = ?)"
                " AND finding_id NOT IN (SELECT finding_id FROM case_findings WHERE case_id != ?)"
            )
            counts["overrides"] = int(conn.execute("SELECT COUNT(*)" + override_sql, (case_id, case_id)).fetchone()[0])
            audit = conn.execute("SELECT seq, ts, kind, payload, prev_hash, hash FROM audit WHERE case_id = ? ORDER BY seq", (case_id,)).fetchall()
            minimise = bool(keep_until and audit and row is not None)  # minimised once, when the case itself goes
            counts["audit"] = 0 if keep_until else len(audit)
            counts["audit_minimised"] = _minimisable(audit) if minimise else 0
            cache_keys = [r[0] for r in conn.execute("SELECT cache_key FROM case_cache_keys WHERE case_id = ?", (case_id,))]
            report_files = _unique_paths(
                _json_list(row["report_paths"]) if row is not None else [],
                [r[0] for r in conn.execute("SELECT path FROM report_hashes WHERE case_id = ?", (case_id,))],
            )

            # -- files
            keep_names = set(ENGAGEMENT_AUDIT_FILES) if keep_until else set()
            dir_files = _case_dir_files(directory, keep_names) if directory is not None else []
            outside, skipped = _report_files(report_files, case_id, directory)
            report.errors.extend(skipped)
            counts["files"] = len(dir_files)
            counts["report_files"] = len(outside)
            report.files = [str(p) for p in dir_files + outside]

            # -- HTTP cache rows and deferred quota lookups (other databases)
            cache = self._open_cache(report.errors) if cache_keys else None
            try:
                counts["cache_rows"] = cache.count_keys(cache_keys) if (cache is not None and cache_keys) else 0
                quota = self._open_quota(report.errors)
                try:
                    counts["deferred"] = quota.forget_case(case_id, dry_run=True) if quota is not None else 0
                    nothing = not any(counts.values()) and not (tomb and tomb.get("audit_until") and not keep_until)
                    if dry_run or nothing:
                        report.counts = {k: v for k, v in counts.items() if v}
                        if nothing and not report.found:
                            report.reason = "already purged" if tomb is not None else "not found"
                        return report

                    # -- remove: files first (a crash leaves rows that a new purge finishes), then rows
                    for p in dir_files + outside:
                        try:
                            os.unlink(p)
                        except FileNotFoundError:
                            pass
                        except OSError as exc:
                            report.errors.append(f"{p}: {exc.strerror or exc}")
                    if directory is not None:
                        _remove_empty_dirs(directory, report.errors)
                    if cache is not None and cache_keys:
                        try:
                            cache.delete_many(cache_keys)
                            if vacuum:
                                cache.vacuum()
                        except sqlite3.Error as exc:  # pragma: no cover - cache I/O problems are reported
                            report.errors.append(f"HTTP cache: {exc}")
                    if quota is not None and counts["deferred"]:
                        try:
                            quota.forget_case(case_id)
                        except sqlite3.Error as exc:  # pragma: no cover
                            report.errors.append(f"quota DB: {exc}")
                finally:
                    if quota is not None:
                        quota.close()
            finally:
                if cache is not None:
                    cache.close()

            with self.connection() as c:
                c.execute("DELETE" + override_sql, (case_id, case_id))
                for table in tables:
                    c.execute(f"DELETE FROM {_quote_ident(table)} WHERE case_id = ?", (case_id,))
                if not keep_until:
                    c.execute("DELETE FROM audit WHERE case_id = ?", (case_id,))
                elif minimise:
                    _minimise_audit(c, case_id, audit, by=str(by or "unknown"), stamp=_iso(current))
                c.execute("DELETE FROM cases WHERE id = ?", (case_id,))
                previous = (tomb or {}).get("counts") or {}
                merged = {k: int(previous.get(k, 0)) + int(counts.get(k, 0)) for k in sorted(set(previous) | set(counts))}
                merged = {k: v for k, v in merged.items() if v}
                if tomb is None:
                    c.execute(
                        "INSERT INTO tombstones (case_id, created, purged_at, purged_by, counts, audit_until) VALUES (?, ?, ?, ?, ?, ?)",
                        (case_id, created or None, _iso(current), str(by or "unknown"), json.dumps(merged, sort_keys=True), keep_until or None),
                    )
                else:
                    c.execute(
                        "UPDATE tombstones SET counts = ?, audit_until = ? WHERE case_id = ?",
                        (json.dumps(merged, sort_keys=True), keep_until or None, case_id),
                    )
            if vacuum:
                self.vacuum()
            report.counts = {k: v for k, v in counts.items() if v}
            report.purged = True
            return report

    def purge_older_than(
        self, days: float | None = None, *, by: str = "retention", dry_run: bool = False, now: _dt.datetime | None = None
    ) -> list[PurgeReport]:
        """Purge every case created more than ``days`` ago (default: setting retention_days; with the
        setting at 0 nothing is purged) through :meth:`purge_case`. Held cases are skipped and listed
        (``held=True``); engagement audits whose retention ended are removed too, and so are case
        directories older than ``days`` that have no case row (a crashed scan, a v1 delete) - only
        directories named like generated case ids, and only for the home's own case DB. One VACUUM
        at the end. Returns one report per case considered (abandoned directories only when there
        was something to remove)."""
        if days is None:
            days = self.retention_days()
            if days <= 0:
                return []
        if float(days) < 0:
            raise ValueError("days must be >= 0")
        current = self._now(now)
        cutoff = current - _dt.timedelta(days=float(days))
        with self._lock:
            rows = self._conn.execute("SELECT id, created, legal_hold, hold_reason FROM cases ORDER BY created").fetchall()
            expired_audits = [
                r[0]
                for r in self._conn.execute("SELECT case_id, audit_until FROM tombstones WHERE audit_until IS NOT NULL").fetchall()
                if (_parse_iso(r[1]) or current) <= current
            ]
        reports: list[PurgeReport] = []
        for r in rows:
            created = _parse_iso(r["created"])
            if created is None or created >= cutoff:
                continue
            if r["legal_hold"]:
                reports.append(PurgeReport(case_id=r["id"], found=True, dry_run=dry_run, held=True, reason=str(r["hold_reason"] or "")))
                continue
            reports.append(self.purge_case(r["id"], by=by, dry_run=dry_run, now=current, vacuum=False))
        done = {rep.case_id for rep in reports}
        for case_id in expired_audits:
            if case_id not in done:
                reports.append(self.purge_case(case_id, by=by, dry_run=dry_run, now=current, vacuum=False))
                done.add(case_id)
        for case_id in self._abandoned_case_dirs(cutoff):
            if case_id in done:
                continue
            rep = self.purge_case(case_id, by=by, dry_run=dry_run, now=current, vacuum=False)
            if rep.purged or rep.counts:
                reports.append(rep)
        if not dry_run and any(rep.purged for rep in reports):
            self.vacuum()
            if any(rep.counts.get("cache_rows") for rep in reports):
                cache = self._open_cache([])
                if cache is not None:
                    try:
                        cache.vacuum()
                    except sqlite3.Error:  # pragma: no cover - the rows are deleted (secure delete) already
                        pass
                    finally:
                        cache.close()
        return reports

    def _abandoned_case_dirs(self, cutoff: _dt.datetime) -> list[str]:
        """Case directories (named like generated case ids) created before ``cutoff`` that have no
        case row. Only for the home's own case DB: a store on another file never sweeps the home."""
        try:
            if os.path.realpath(self.path) != os.path.realpath(paths.db_file()):
                return []
            names = sorted(os.listdir(paths.cases_dir()))
        except OSError:
            return []
        with self._lock:
            known = {str(r[0]) for r in self._conn.execute("SELECT id FROM cases")}
        out: list[str] = []
        for name in names:
            if name in known:
                continue
            created = _parse_iso(_created_from_id(name))
            if created is not None and created < cutoff:
                out.append(name)
        return out

    def vacuum(self) -> None:
        """``PRAGMA secure_delete = ON`` + ``VACUUM`` (deleted case data is overwritten and the file
        rebuilt without free pages)."""
        with self._lock:
            if self._conn.in_transaction:
                self._conn.commit()
            self._conn.execute("PRAGMA secure_delete = ON")
            self._conn.execute("VACUUM")
        paths.restrict_file(self.path)

    def _open_cache(self, errors: list[str]) -> Any:
        """The HTTP cache the purge cleans (None when it does not exist; a cache that cannot be
        opened is reported in ``errors``: its rows of the case stay until cache_max_age_days)."""
        target = Path(self._cache_path) if self._cache_path else paths.cache_file()
        if not target.exists():
            return None
        from v3lum.core.cache import HttpCache

        try:
            return HttpCache(str(target))
        except (sqlite3.Error, OSError) as exc:
            errors.append(f"HTTP cache {target}: {exc} (the case's cache rows expire with cache_max_age_days)")
            return None

    def _open_quota(self, errors: list[str]) -> Any:
        """The quota DB holding the case's deferred lookups (None when it does not exist; a DB that
        cannot be opened is reported in ``errors``)."""
        from v3lum.core import quota as quota_mod

        target = Path(self._quota_path) if self._quota_path else quota_mod.default_path(self._settings_or_none())
        if not target.exists():
            return None
        try:
            return quota_mod.QuotaBook(target)
        except (sqlite3.Error, OSError) as exc:
            errors.append(f"quota DB {target}: {exc} (deferred lookups of the case not removed)")
            return None

    def _settings_or_none(self) -> Any:
        if self._settings is None:
            self.setting("retention_days")  # loads the Config once
        return self._settings

    # ------------------------------------------------------------------ feedback (v1, kept)
    def add_feedback(self, case_id: str, verdict: str, notes: str = "", *, analyst: str = "") -> None:
        verdict = verdict.lower()
        if verdict not in _VERDICTS:
            raise ValueError("verdict must be yes, partial or no")
        with self.connection() as conn:
            conn.execute(
                "INSERT INTO feedback (case_id, verdict, notes, created, analyst) VALUES (?,?,?,?,?)",
                (case_id, verdict, notes, _iso(self._now()), str(analyst or "")),
            )

    def flag_finding(self, case_id: str, finding_id: str, module: str, correct: bool) -> None:
        with self.connection() as conn:
            conn.execute(
                "INSERT INTO finding_feedback (case_id, finding_id, module, correct, created) VALUES (?,?,?,?,?)",
                (case_id, finding_id, module, 1 if correct else 0, _iso(self._now())),
            )
            col = "correct" if correct else "wrong"
            conn.execute(f"INSERT INTO module_stats (module, {col}) VALUES (?, 1) ON CONFLICT(module) DO UPDATE SET {col} = {col} + 1", (module,))

    def feedback_for(self, case_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT verdict, notes, created FROM feedback WHERE case_id = ? ORDER BY id", (case_id,)).fetchall()
        return [dict(r) for r in rows]

    def feedback_summary(self) -> dict[str, Any]:
        with self._lock:
            verdicts = dict(self._conn.execute("SELECT verdict, COUNT(*) FROM feedback GROUP BY verdict").fetchall())
            mods = [dict(r) for r in self._conn.execute("SELECT module, correct, wrong FROM module_stats ORDER BY wrong DESC, module").fetchall()]
        for m in mods:
            m["reliability"] = round(reliability_from(m["correct"], m["wrong"]), 3)
        return {"verdicts": verdicts, "modules": mods}

    def reliability(self) -> dict[str, float]:
        with self._lock:
            rows = self._conn.execute("SELECT module, correct, wrong FROM module_stats").fetchall()
        return {r["module"]: reliability_from(r["correct"], r["wrong"]) for r in rows}


def reliability_from(correct: int, wrong: int) -> float:
    """Laplace-smoothed precision, scaled so an unknown module weighs 1.0 and a bad one ~0.3."""
    precision = (correct + 2) / (correct + wrong + 2)  # starts at 1.0 with no data
    return max(0.3, min(1.0, precision))


# ======================================================================================
# file helpers of the purge
# ======================================================================================


def _case_dir_files(directory: Path, keep: set[str]) -> list[Path]:
    """Every file and symbolic link under the case directory (links are never followed), except
    the top-level ``keep`` names. A case directory that is itself a link counts as one entry."""
    if not os.path.lexists(directory):
        return []
    if os.path.islink(directory):
        return [directory]
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(directory, followlinks=False):
        here = Path(dirpath)
        for name in filenames:
            if here == directory and name in keep:
                continue
            out.append(here / name)
        for name in dirnames:
            candidate = here / name
            if os.path.islink(candidate):  # a linked directory: remove the link, never its target
                out.append(candidate)
    return sorted(out)


def _remove_empty_dirs(directory: Path, errors: list[str]) -> None:
    if not os.path.isdir(directory) or os.path.islink(directory):
        return
    for dirpath, _dirnames, _filenames in os.walk(directory, topdown=False, followlinks=False):
        try:
            os.rmdir(dirpath)
        except FileNotFoundError:
            pass
        except OSError as exc:
            if os.listdir(dirpath):
                continue  # kept engagement audit files (or a file that could not be removed)
            errors.append(f"{dirpath}: {exc.strerror or exc}")


def _report_files(report_paths: list[str], case_id: str, directory: Path | None) -> tuple[list[Path], list[str]]:
    """Recorded report files outside the case directory to remove (and their ``.sha256``
    sidecars). Only regular files or links whose name contains the case id are removed: a damaged
    or forged record can never point the purge at an unrelated file."""
    inside = os.path.realpath(directory) if directory is not None else None
    out: list[Path] = []
    skipped: list[str] = []
    for text in report_paths:
        p = Path(text)
        candidates = [p, Path(text + ".sha256")]
        for candidate in candidates:
            if not os.path.lexists(candidate):
                continue
            if inside is not None and os.path.realpath(candidate.parent).startswith(inside + os.sep):
                continue  # removed with the case directory
            if inside is not None and os.path.realpath(candidate.parent) == inside:
                continue
            if case_id not in candidate.name:
                skipped.append(f"{candidate}: recorded for the case but its name does not contain the case id (not removed)")
                continue
            try:
                mode = os.lstat(candidate).st_mode
            except OSError:
                continue
            if stat.S_ISREG(mode) or stat.S_ISLNK(mode):
                out.append(candidate)
            else:
                skipped.append(f"{candidate}: not a regular file (not removed)")
    unique: list[Path] = []
    seen: set[str] = set()
    for item in out:
        if str(item) not in seen:
            seen.add(str(item))
            unique.append(item)
    return unique, skipped
