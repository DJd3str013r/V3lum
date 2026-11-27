"""Local SQLite name index for large leak/sanctions datasets (batch p3-G10-1, P221 and P222).

The ICIJ Offshore Leaks bulk CSV (~800k entities) and the licensed OpenSanctions targets file are far too
large for the in-memory blocking index of ``company_org.namematch`` (P219). This helper keeps the same
matcher - ``namematch.name_tokens`` normalisation, ``namematch.token_set_jw`` scoring, threshold 0.90, at
most 5 candidates, persons only compared with persons - over an SQLite file built once by the dataset
manager (``v3lum data update icij``) or an explicit import, never during a scan:

* :class:`NameIndexWriter` builds the file under a temporary name (bulk inserts, no journal), creates the
  indexes and the per-key document frequencies, records ``meta`` and installs it atomically (0600);
* :class:`NameIndexReader` opens it read-only; :meth:`NameIndexReader.match` gathers candidates from the
  rarest blocking keys of the query (exact tokens and 3-character prefixes, so a typo in the rarest token
  still finds the alias), ranks them by token overlap, scores at most ``max_scored`` of them and returns the
  best alias per entry. Identifiers (wallets, registration numbers) are exact lookups (:meth:`by_ident`).

Callers may add their own tables through :attr:`NameIndexWriter.conn` (ICIJ keeps officer/intermediary
nodes and relationships there). Nothing here touches the network.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from v3lum.modules.company_org import namematch as nm

__all__ = ["INDEX_SCHEMA", "NameIndexError", "NameIndexReader", "NameIndexWriter", "blocking_keys"]

INDEX_SCHEMA = "v3lum.name_index/1"
#: rows fetched for one blocking key (the rarest keys are used first)
PER_KEY_LIMIT = 20000
#: at most this many aliases are scored per query (ranked by token overlap first)
MAX_SCORED = 600
#: aliases kept per entry (a sanctions record may carry dozens of transliterations)
MAX_ALIASES = 20
_BATCH = 5000

_DDL = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE entry (id INTEGER PRIMARY KEY, entry_id TEXT NOT NULL, kind TEXT NOT NULL, name TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE alias (id INTEGER PRIMARY KEY, entry_rowid INTEGER NOT NULL, name TEXT NOT NULL, tokens TEXT NOT NULL,
                    kind TEXT NOT NULL, alias_type TEXT NOT NULL);
CREATE TABLE block (key TEXT NOT NULL, alias_id INTEGER NOT NULL);
CREATE TABLE ident (kind TEXT NOT NULL, value TEXT NOT NULL, entry_rowid INTEGER NOT NULL);
CREATE TABLE key_df (key TEXT PRIMARY KEY, n INTEGER NOT NULL);
"""
_INDEXES = (
    "CREATE UNIQUE INDEX entry_eid ON entry(entry_id)",
    "CREATE INDEX block_key ON block(key)",
    "CREATE INDEX ident_kv ON ident(kind, value)",
)


class NameIndexError(Exception):
    """The index file is missing, unreadable or of another schema."""


def blocking_keys(tokens: Iterable[str]) -> set[str]:
    """'t:<token>' and 'p:<first 3 characters>' for every token of 2+ characters."""
    keys: set[str] = set()
    for tok in tokens:
        if len(tok) >= 2:
            keys.add("t:" + tok)
            keys.add("p:" + tok[:3])
    return keys


def _kind(value: Any) -> str:
    if value in ("person", "individual"):
        return "person"
    if value in ("vessel", "aircraft"):
        return str(value)
    return "entity"


class NameIndexWriter:
    """Build a name index at ``path`` (atomic install on :meth:`finish`, removed on :meth:`abort`)."""

    def __init__(self, path: str | os.PathLike[str], *, meta: dict[str, Any] | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.building")
        if self.tmp.exists():
            self.tmp.unlink()
        self.conn = sqlite3.connect(str(self.tmp))
        self.conn.execute("PRAGMA journal_mode=OFF")
        self.conn.execute("PRAGMA synchronous=OFF")
        self.conn.executescript(_DDL)
        self.meta: dict[str, str] = {"schema": INDEX_SCHEMA, **{str(k): str(v) for k, v in (meta or {}).items()}}
        self.entries = 0
        self.aliases = 0
        self._alias_rows: list[tuple[Any, ...]] = []
        self._block_rows: list[tuple[str, int]] = []
        self._ident_rows: list[tuple[str, str, int]] = []
        self._next_alias = 1

    def add(self, entry_id: str, kind: str, names: Iterable[tuple[str, str]], data: dict[str, Any]) -> int | None:
        """Add one entry with its names ``[(name, alias_type)]``; returns its rowid (None when no name survives)."""
        k = _kind(kind)
        seen: set[tuple[str, ...]] = set()
        kept: list[tuple[str, tuple[str, ...], str]] = []
        for name, alias_type in names:
            if not isinstance(name, str) or not name.strip():
                continue
            toks = nm.name_tokens(name, k)
            if not toks or toks in seen:
                continue
            seen.add(toks)
            kept.append((name.strip(), toks, str(alias_type or "alias")))
            if len(kept) >= MAX_ALIASES:
                break
        if not kept:
            return None
        cur = self.conn.execute(
            "INSERT INTO entry (entry_id, kind, name, data) VALUES (?, ?, ?, ?)",
            (str(entry_id), k, kept[0][0], json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str)),
        )
        rowid = int(cur.lastrowid or 0)
        for name, toks, alias_type in kept:
            aid = self._next_alias
            self._next_alias += 1
            self._alias_rows.append((aid, rowid, name, " ".join(toks), k, alias_type))
            self._block_rows.extend((key, aid) for key in blocking_keys(toks))
        self.entries += 1
        self.aliases += len(kept)
        if len(self._block_rows) >= _BATCH * 4 or len(self._alias_rows) >= _BATCH:
            self._flush()
        return rowid

    def add_ident(self, kind: str, value: str, rowid: int) -> None:
        if value:
            self._ident_rows.append((str(kind), str(value), int(rowid)))
            if len(self._ident_rows) >= _BATCH:
                self._flush()

    def _flush(self) -> None:
        if self._alias_rows:
            self.conn.executemany("INSERT INTO alias VALUES (?, ?, ?, ?, ?, ?)", self._alias_rows)
            self._alias_rows = []
        if self._block_rows:
            self.conn.executemany("INSERT INTO block VALUES (?, ?)", self._block_rows)
            self._block_rows = []
        if self._ident_rows:
            self.conn.executemany("INSERT INTO ident VALUES (?, ?, ?)", self._ident_rows)
            self._ident_rows = []

    def finish(self) -> Path:
        """Create indexes and frequencies, record meta, install the file atomically (0600)."""
        self._flush()
        for stmt in _INDEXES:
            self.conn.execute(stmt)
        self.conn.execute("INSERT INTO key_df SELECT key, COUNT(*) FROM block GROUP BY key")
        self.meta.update({"entries": str(self.entries), "aliases": str(self.aliases)})
        self.conn.executemany("INSERT OR REPLACE INTO meta VALUES (?, ?)", sorted(self.meta.items()))
        self.conn.commit()
        self.conn.close()
        os.chmod(self.tmp, 0o600)
        os.replace(self.tmp, self.path)
        return self.path

    def abort(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:  # pragma: no cover - best effort
            pass
        try:
            self.tmp.unlink()
        except OSError:
            pass


class NameIndexReader:
    """Read-only access to a name index built by :class:`NameIndexWriter`."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        if not self.path.is_file():
            raise NameIndexError(f"name index not found: {self.path.name}")
        try:
            self.conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, check_same_thread=False)
            rows = self.conn.execute("SELECT key, value FROM meta").fetchall()
        except sqlite3.Error as exc:
            raise NameIndexError(f"unreadable name index {self.path.name}: {exc}") from exc
        self._meta = {str(k): str(v) for k, v in rows}
        if self._meta.get("schema") != INDEX_SCHEMA:
            self.close()
            raise NameIndexError(f"name index {self.path.name} has schema {self._meta.get('schema')!r}, expected {INDEX_SCHEMA}")

    def __enter__(self) -> NameIndexReader:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        try:
            self.conn.close()
        except (sqlite3.Error, AttributeError):  # pragma: no cover - best effort
            pass

    def meta(self) -> dict[str, str]:
        return dict(self._meta)

    def entry(self, rowid: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT id, entry_id, kind, name, data FROM entry WHERE id = ?", (int(rowid),)).fetchone()
        if row is None:
            return None
        try:
            data = json.loads(row[4])
        except ValueError:
            data = {}
        return {"rowid": row[0], "entry_id": row[1], "kind": row[2], "name": row[3], "data": data if isinstance(data, dict) else {}}

    def entry_by_id(self, entry_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT id FROM entry WHERE entry_id = ?", (str(entry_id),)).fetchone()
        return self.entry(row[0]) if row else None

    def by_ident(self, kind: str, value: str) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT DISTINCT entry_rowid FROM ident WHERE kind = ? AND value = ? LIMIT 20", (kind, value)).fetchall()
        return [e for e in (self.entry(r[0]) for r in rows) if e is not None]

    def match(
        self,
        query: Any,
        *,
        kind: str = "entity",
        threshold: float = nm.NAME_MATCH_THRESHOLD,
        limit: int = nm.MAX_CANDIDATES,
        max_scored: int = MAX_SCORED,
    ) -> list[dict[str, Any]]:
        """At most ``limit`` entries whose best alias scores >= ``threshold`` (token-set Jaro-Winkler of the
        P219 matcher): [{rowid, entry_id, name, matched_alias, alias_type, score}], best first."""
        if not isinstance(query, str) or not query.strip():
            return []
        want = _kind(kind)
        q = nm.name_tokens(query, want)
        keys = sorted(blocking_keys(q))
        if not keys:
            return []
        marks = ",".join("?" * len(keys))
        df = {k: n for k, n in self.conn.execute(f"SELECT key, n FROM key_df WHERE key IN ({marks})", keys)}  # noqa: S608 - placeholders only
        present = [k for k in keys if df.get(k)]
        if not present:
            return []
        t_keys = sorted((k for k in present if k.startswith("t:")), key=lambda k: (df[k], k))[:2]
        p_keys = sorted((k for k in present if k.startswith("p:")), key=lambda k: (df[k], k))[:1]
        cand: set[int] = set()
        for key in t_keys + p_keys:
            cand.update(r[0] for r in self.conn.execute("SELECT alias_id FROM block WHERE key = ? LIMIT ?", (key, PER_KEY_LIMIT)))
        if not cand:
            return []
        q_set = set(q)
        q_pre = {t[:3] for t in q if len(t) >= 2}
        ranked: list[tuple[int, int, tuple[Any, ...]]] = []
        ids = sorted(cand)
        for start in range(0, len(ids), 900):
            chunk = ids[start:start + 900]
            sql = f"SELECT id, entry_rowid, name, tokens, kind, alias_type FROM alias WHERE id IN ({','.join('?' * len(chunk))})"  # noqa: S608
            for row in self.conn.execute(sql, chunk):
                if row[4] != want:
                    continue
                toks = row[3].split()
                pts = sum(2 for t in toks if t in q_set) + sum(1 for t in toks if t not in q_set and t[:3] in q_pre)
                ranked.append((pts, row[0], row))
        ranked.sort(key=lambda x: (-x[0], x[1]))
        best: dict[int, dict[str, Any]] = {}
        for _pts, _aid, row in ranked[: max(1, int(max_scored))]:
            score = nm.token_set_jw(q, row[3].split())
            if score < threshold:
                continue
            prev = best.get(row[1])
            if prev is None or score > prev["score"]:
                best[row[1]] = {"rowid": row[1], "matched_alias": row[2], "alias_type": row[5], "score": round(score, 4)}
        out = []
        for hit in best.values():
            ent = self.entry(hit["rowid"])
            if ent is None:
                continue
            out.append({**hit, "entry_id": ent["entry_id"], "name": ent["name"], "kind": ent["kind"], "data": ent["data"]})
        out.sort(key=lambda r: (-r["score"], str(r["entry_id"])))
        return out[: max(0, int(limit))]
