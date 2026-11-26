"""SQLite HTTP response cache shared by every module run (``~/.v3lum/cache/http_cache.db``).

Rules enforced here as a second line of defence (the HTTP client applies them first):

* only :data:`CACHEABLE_STATUS` answers are stored (2xx, redirects, 404/410 - a 404 is information);
  401/403/429/5xx never are;
* truncated bodies and responses classified as blocked/rate-limited/quota/error-in-200 (P321) are
  never stored;
* the ``url`` and ``history`` columns hold redacted URLs (AR01) - lookups use the cache key, a
  SHA-256 of the real request, so redaction does not affect hits; every row keeps ``fetched_at``
  (ISO UTC fetch time; served responses report it, P324 cond 2);
* ``Set-Cookie`` headers are dropped and other header values redacted before storage;
* the database and its ``-wal``/``-shm`` files are owner-only (0600) whatever the process umask;
* retention (A10): rows older than ``cache_max_age_days`` (default 30) are deleted by :meth:`prune`,
  which runs when the cache is opened with ``max_age_days`` (at most once per day; the last run is
  kept in the ``meta`` table) and on maintenance; ``stats()['oldest']`` shows the oldest row; the
  case purge removes a case's rows through :meth:`delete_many` + :meth:`vacuum` (secure delete).

The schema is versioned by :mod:`v3lum.core.migrations` (kind ``'cache'``); caches written by older
versions upgrade in place. ``HttpCache`` moved here from ``v3lum.core.http`` (which re-exports it).
"""

from __future__ import annotations

import datetime as _dt
import json
import sqlite3
import threading
import time
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from v3lum import paths
from v3lum.core.migrations import migrate
from v3lum.core.redact import redact_text, redact_url

if TYPE_CHECKING:  # pragma: no cover
    from v3lum.core.clock import Clock
    from v3lum.core.http import Response

__all__ = ["CACHEABLE_STATUS", "DEFAULT_MAX_AGE_DAYS", "HttpCache"]

#: Statuses whose answers may be cached (2xx, 3xx and the informative 404/410).
CACHEABLE_STATUS = frozenset({200, 201, 202, 203, 204, 206, 300, 301, 302, 303, 307, 308, 404, 410})
#: Default of setting cache_max_age_days (A10): no cache row lives longer.
DEFAULT_MAX_AGE_DAYS = 30
_DROPPED_HEADERS = frozenset({"set-cookie", "set-cookie2"})
_PRUNE_KEY = "last_prune"
_SQL_CHUNK = 500


def _iso(ts: float) -> str:
    return _dt.datetime.fromtimestamp(float(ts), _dt.timezone.utc).isoformat(timespec="seconds")


class HttpCache:
    """Tiny thread-safe SQLite response cache.

    ``HttpCache(path, *, max_age_days=None, clock=None)``: with ``max_age_days`` the cache prunes
    rows older than that when opened (at most once per UTC day). ``get(key, ttl)`` returns a
    :class:`~v3lum.core.http.Response` (``from_cache=True``, ``fetched_at`` = the row time) or None;
    ``put(key, resp)`` stores a cacheable response; ``delete(key)`` / ``delete_many(keys)`` remove
    rows (``ScopedHttp.evict``, the A10 purge); ``prune(max_age_days)``; ``clear(host=None,
    older_than=None)``; ``stats()``; ``vacuum()``; ``close()``. ``now`` arguments (epoch seconds)
    let a client with a fake clock control ages; ``clock`` sets the default time source.
    """

    def __init__(self, path: str, *, max_age_days: float | None = None, clock: Clock | None = None) -> None:
        self.path = str(path)
        self.clock = clock
        self._lock = threading.Lock()
        self._restrict()  # before SQLite creates the -wal/-shm files, which copy the DB file's mode
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA secure_delete=ON")
        #: schema version after the migrations ran
        self.version = migrate(self._conn, "cache")
        self._restrict()
        self.max_age_days = float(max_age_days) if max_age_days else None
        if self.max_age_days:
            self._prune_daily(self.max_age_days)

    def _restrict(self) -> None:
        """The cache holds provider answers: the DB and its -wal/-shm/-journal files are owner-only
        (0600, A10/AR03), whatever the process umask. In-memory databases are left alone."""
        paths.restrict_file(self.path, create=True)

    def _epoch(self, now: float | None = None) -> float:
        if now is not None:
            return float(now)
        if self.clock is not None:
            return self.clock.now().timestamp()
        return time.time()

    # ------------------------------------------------------------------ read
    def get(self, key: str, ttl: float, *, now: float | None = None) -> Response | None:
        """The cached response for ``key`` when younger than ``ttl`` seconds, else None. A cache
        opened with ``max_age_days`` never serves a row older than that, whatever ``ttl`` says (the
        daily prune may not have removed it yet; A10)."""
        if ttl is None or ttl <= 0:
            return None
        if self.max_age_days:
            ttl = min(float(ttl), self.max_age_days * 86400.0)
        with self._lock:
            row = self._conn.execute(
                "SELECT url, status, headers, body, ts, history, fetched_at FROM cache WHERE key=?", (key,)
            ).fetchone()
        if not row:
            return None
        url, status, headers, body, ts, history, fetched_at = row
        current = self._epoch(now)
        if current - float(ts or 0) > ttl:
            return None
        from v3lum.core.http import Response  # late import: http.py imports this module

        try:
            hdrs = json.loads(headers or "{}")
            hist = json.loads(history or "[]")
        except ValueError:
            return None
        resp = Response(
            status=int(status),
            url=url or "",
            headers=hdrs if isinstance(hdrs, dict) else {},
            content=body or b"",
            from_cache=True,
            history=list(hist) if isinstance(hist, list) else [],
            fetched_at=fetched_at or _iso(ts or 0),
            host=urlsplit(url or "").hostname or "",
        )
        resp.cache_key = key
        return resp

    # ------------------------------------------------------------------ write
    def put(self, key: str, resp: Response, *, now: float | None = None) -> bool:
        """Store ``resp`` under ``key``; returns False (nothing stored) when it is not cacheable."""
        if resp.status not in CACHEABLE_STATUS or resp.truncated:
            return False
        if getattr(resp, "classification", None) is not None:
            return False
        url = redact_url(resp.url)
        host = (urlsplit(resp.url).hostname or "").lower()
        headers = {k: redact_text(v) for k, v in (resp.headers or {}).items() if str(k).lower() not in _DROPPED_HEADERS}
        history = [redact_url(h) for h in (resp.history or [])]
        stamp = self._epoch(now)
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO cache (key, url, host, status, headers, body, ts, history, fetched_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (key, url, host, int(resp.status), json.dumps(headers), resp.content, stamp, json.dumps(history), _iso(stamp)),
            )
            self._conn.commit()
        return True

    def delete(self, key: str) -> bool:
        """Remove the row of one cache key; True when a row existed."""
        if not key:
            return False
        with self._lock:
            cur = self._conn.execute("DELETE FROM cache WHERE key = ?", (key,))
            self._conn.commit()
            return cur.rowcount > 0

    def delete_many(self, keys: Iterable[str]) -> int:
        """Remove the rows of several cache keys (the case purge); returns the rows removed."""
        items = sorted({str(k) for k in keys or () if k})
        removed = 0
        with self._lock:
            for start in range(0, len(items), _SQL_CHUNK):
                chunk = items[start : start + _SQL_CHUNK]
                cur = self._conn.execute(f"DELETE FROM cache WHERE key IN ({','.join('?' * len(chunk))})", chunk)
                removed += max(0, cur.rowcount)
            self._conn.commit()
        return removed

    def count_keys(self, keys: Iterable[str]) -> int:
        """How many of ``keys`` have a row (purge dry runs)."""
        items = sorted({str(k) for k in keys or () if k})
        found = 0
        with self._lock:
            for start in range(0, len(items), _SQL_CHUNK):
                chunk = items[start : start + _SQL_CHUNK]
                found += int(self._conn.execute(f"SELECT COUNT(*) FROM cache WHERE key IN ({','.join('?' * len(chunk))})", chunk).fetchone()[0])
        return found

    def clear(self, host: str | None = None, older_than: float | None = None) -> int:
        """Delete rows (all, of a host and its subdomains, and/or older than ``older_than`` seconds)."""
        clauses, params = [], []
        if host:
            clauses.append("(host = ? OR host LIKE ?)")
            params += [host, f"%.{host}"]
        if older_than:
            clauses.append("ts < ?")
            params.append(self._epoch() - older_than)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            cur = self._conn.execute(f"DELETE FROM cache{where}", params)
            self._conn.commit()
            if not clauses:
                self._conn.execute("VACUUM")
            return cur.rowcount

    # ------------------------------------------------------------------ retention (A10)
    def prune(self, max_age_days: float | None = None, *, now: float | None = None) -> int:
        """Delete rows older than ``max_age_days`` (default :data:`DEFAULT_MAX_AGE_DAYS`, the setting
        cache_max_age_days); records the run in ``meta``. Returns the rows removed."""
        days = float(max_age_days) if max_age_days else float(DEFAULT_MAX_AGE_DAYS)
        current = self._epoch(now)
        with self._lock:
            cur = self._conn.execute("DELETE FROM cache WHERE ts < ?", (current - days * 86400,))
            removed = max(0, cur.rowcount)
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (_PRUNE_KEY, _iso(current)),
            )
            self._conn.commit()
        return removed

    def _prune_daily(self, max_age_days: float) -> int:
        """:meth:`prune` unless it already ran today (UTC); a broken cache never blocks opening."""
        current = self._epoch()
        today = _iso(current)[:10]
        try:
            with self._lock:
                row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (_PRUNE_KEY,)).fetchone()
            if row and str(row[0] or "")[:10] == today:
                return 0
            return self.prune(max_age_days, now=current)
        except sqlite3.Error:  # pragma: no cover - reported by doctor, never fatal here
            return 0

    def last_prune(self) -> str:
        """ISO UTC time of the last prune ('' when never)."""
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (_PRUNE_KEY,)).fetchone()
        return str(row[0]) if row and row[0] else ""

    def vacuum(self) -> None:
        """Rebuild the file without the deleted rows (secure delete is on) and truncate the WAL."""
        with self._lock:
            self._conn.commit()
            self._conn.execute("VACUUM")
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:  # pragma: no cover - another connection holds the WAL
                pass
        self._restrict()

    # ------------------------------------------------------------------ info
    def stats(self) -> dict[str, Any]:
        """Entries, body bytes, top hosts, oldest row (ISO UTC or ''), last prune and the DB path."""
        with self._lock:
            total, size, oldest = self._conn.execute("SELECT COUNT(*), COALESCE(SUM(LENGTH(body)),0), MIN(ts) FROM cache").fetchone()
            hosts = self._conn.execute("SELECT host, COUNT(*) c FROM cache GROUP BY host ORDER BY c DESC LIMIT 15").fetchall()
            row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (_PRUNE_KEY,)).fetchone()
        return {
            "entries": total,
            "bytes": size,
            "top_hosts": hosts,
            "oldest": _iso(oldest) if oldest else "",
            "last_prune": str(row[0]) if row and row[0] else "",
            "path": self.path,
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()
