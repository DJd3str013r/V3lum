"""Per-source daily request quotas.

Free tiers are usually counted per egress IP (a whole team behind one corporate NAT shares
them: HackerTarget 50/day, GreyNoise community, Maltiverse...). Modules declare
``daily_quota``; the engine stops scheduling a module once its quota for the day is used,
instead of burning requests on errors. Counters live in ``~/.v3lum/quota.db``.
"""

from __future__ import annotations

import datetime as _dt
import sqlite3
import threading
from pathlib import Path


class QuotaBook:
    def __init__(self, path: str | Path) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
        self._conn.execute("CREATE TABLE IF NOT EXISTS quota (module TEXT, day TEXT, used INTEGER, PRIMARY KEY (module, day))")
        self._conn.commit()

    @staticmethod
    def today(now: _dt.datetime | None = None) -> str:
        return (now or _dt.datetime.now(_dt.timezone.utc)).strftime("%Y-%m-%d")

    def used(self, module: str, day: str | None = None) -> int:
        with self._lock:
            row = self._conn.execute("SELECT used FROM quota WHERE module = ? AND day = ?", (module, day or self.today())).fetchone()
        return int(row[0]) if row else 0

    def add(self, module: str, n: int, day: str | None = None) -> None:
        if n <= 0:
            return
        with self._lock:
            self._conn.execute(
                "INSERT INTO quota (module, day, used) VALUES (?, ?, ?) ON CONFLICT(module, day) DO UPDATE SET used = used + ?",
                (module, day or self.today(), n, n),
            )
            self._conn.commit()

    def exhausted(self, module: str, limit: int | None, day: str | None = None) -> bool:
        return bool(limit) and self.used(module, day) >= int(limit or 0)

    def summary(self, day: str | None = None) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute("SELECT module, used FROM quota WHERE day = ?", (day or self.today(),)).fetchall()
        return {m: u for m, u in rows}

    def reset(self, module: str | None = None) -> None:
        with self._lock:
            if module:
                self._conn.execute("DELETE FROM quota WHERE module = ?", (module,))
            else:
                self._conn.execute("DELETE FROM quota")
            self._conn.commit()
