"""SQLite HTTP response cache shared by every module run (``~/.v3lum/cache/http_cache.db``).

Rules enforced here as a second line of defence (the HTTP client applies them first):

* only :data:`CACHEABLE_STATUS` answers are stored (2xx, redirects, 404/410 - a 404 is information);
  401/403/429/5xx never are;
* truncated bodies and responses classified as blocked/rate-limited/quota/error-in-200 (P321) are
  never stored;
* the ``url`` and ``history`` columns hold redacted URLs (AR01) - lookups use the cache key, a
  SHA-256 of the real request, so redaction does not affect hits;
* ``Set-Cookie`` headers are dropped and other header values redacted before storage;
* the database and its ``-wal``/``-shm`` files are owner-only (0600) whatever the process umask.

``HttpCache`` moved here from ``v3lum.core.http`` (which still re-exports it).
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import sqlite3
import threading
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from v3lum.core.redact import redact_text, redact_url

if TYPE_CHECKING:  # pragma: no cover
    from v3lum.core.http import Response

__all__ = ["CACHEABLE_STATUS", "HttpCache"]

#: Statuses whose answers may be cached (2xx, 3xx and the informative 404/410).
CACHEABLE_STATUS = frozenset({200, 201, 202, 203, 204, 206, 300, 301, 302, 303, 307, 308, 404, 410})
_DROPPED_HEADERS = frozenset({"set-cookie", "set-cookie2"})


def _iso(ts: float) -> str:
    return _dt.datetime.fromtimestamp(float(ts), _dt.timezone.utc).isoformat(timespec="seconds")


class HttpCache:
    """Tiny thread-safe SQLite response cache.

    ``get(key, ttl)`` returns a :class:`~v3lum.core.http.Response` (``from_cache=True``, ``fetched_at``
    = the row time) or None; ``put(key, resp)`` stores a cacheable response; ``delete(key)`` removes
    one row (``ScopedHttp.evict``, the A10 purge); ``clear(host=None, older_than=None)``; ``stats()``;
    ``close()``. ``now`` arguments (epoch seconds) let a client with a fake clock control ages.
    """

    def __init__(self, path: str, *, max_age_days: float | None = None) -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        self._restrict()  # before SQLite creates the -wal/-shm files, which copy the DB file's mode
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, url TEXT, host TEXT, status INTEGER,"
            " headers TEXT, body BLOB, ts REAL, history TEXT)"
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS cache_host ON cache(host)")
        self._conn.commit()
        self._restrict()
        if max_age_days:
            self.clear(older_than=float(max_age_days) * 86400)

    def _restrict(self) -> None:
        """The cache holds provider answers: the DB and its -wal/-shm/-journal files are owner-only
        (0600, A10/AR03), whatever the process umask. In-memory databases are left alone."""
        if not self.path or self.path == ":memory:" or self.path.startswith("file:"):
            return
        try:
            if not os.path.exists(self.path):
                os.close(os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600))
        except OSError:  # pragma: no cover - read-only or exotic filesystems: SQLite reports it
            return
        for name in (self.path, self.path + "-wal", self.path + "-shm", self.path + "-journal"):
            try:
                if os.path.exists(name) and (os.stat(name).st_mode & 0o077):
                    os.chmod(name, 0o600)
            except OSError:  # pragma: no cover - not our file or exotic filesystems
                pass

    # ------------------------------------------------------------------ read
    def get(self, key: str, ttl: float, *, now: float | None = None) -> Response | None:
        """The cached response for ``key`` when younger than ``ttl`` seconds, else None."""
        if ttl is None or ttl <= 0:
            return None
        with self._lock:
            row = self._conn.execute("SELECT url, status, headers, body, ts, history FROM cache WHERE key=?", (key,)).fetchone()
        if not row:
            return None
        url, status, headers, body, ts, history = row
        current = time.time() if now is None else float(now)
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
            fetched_at=_iso(ts or 0),
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
        stamp = time.time() if now is None else float(now)
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO cache (key, url, host, status, headers, body, ts, history) VALUES (?,?,?,?,?,?,?,?)",
                (key, url, host, int(resp.status), json.dumps(headers), resp.content, stamp, json.dumps(history)),
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

    def clear(self, host: str | None = None, older_than: float | None = None) -> int:
        """Delete rows (all, of a host and its subdomains, and/or older than ``older_than`` seconds)."""
        clauses, params = [], []
        if host:
            clauses.append("(host = ? OR host LIKE ?)")
            params += [host, f"%.{host}"]
        if older_than:
            clauses.append("ts < ?")
            params.append(time.time() - older_than)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            cur = self._conn.execute(f"DELETE FROM cache{where}", params)
            self._conn.commit()
            if not clauses:
                self._conn.execute("VACUUM")
            return cur.rowcount

    # ------------------------------------------------------------------ info
    def stats(self) -> dict[str, Any]:
        """Entries, body bytes, top hosts, oldest row (ISO UTC or '') and the DB path."""
        with self._lock:
            total, size, oldest = self._conn.execute("SELECT COUNT(*), COALESCE(SUM(LENGTH(body)),0), MIN(ts) FROM cache").fetchone()
            hosts = self._conn.execute("SELECT host, COUNT(*) c FROM cache GROUP BY host ORDER BY c DESC LIMIT 15").fetchall()
        return {"entries": total, "bytes": size, "top_hosts": hosts, "oldest": _iso(oldest) if oldest else "", "path": self.path}

    def close(self) -> None:
        with self._lock:
            self._conn.close()
