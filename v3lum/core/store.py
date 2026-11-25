"""Case storage (SQLite) + analyst feedback + module reliability.

* ``cases``: one row per investigation with the full report model as JSON.
* ``feedback``: the analyst's verdict ("did this make sense?") and notes.
* ``finding_feedback``: per-finding right/wrong flags; they update ``module_stats``,
  from which a reliability weight per module is derived (Laplace-smoothed precision).
  Reliability feeds the risk score, so noisy sources lose weight over time.
"""

from __future__ import annotations

import datetime as _dt
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from v3lum import paths

SCHEMA = """
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


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = str(path or paths.db_file())
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ cases
    def save_case(self, case: dict[str, Any]) -> None:
        summary = case.get("summary", {})
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO cases (id, created, seeds, risk_score, risk_level, findings, entities, data)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (
                    case["case_id"],
                    case.get("created", _now()),
                    json.dumps(case.get("seeds", [])),
                    summary.get("risk_score", 0.0),
                    summary.get("risk_level", "clean"),
                    summary.get("findings", 0),
                    summary.get("entities", 0),
                    json.dumps(case, ensure_ascii=False, default=str),
                ),
            )
            self._conn.commit()

    def list_cases(self, limit: int = 30, search: str = "") -> list[dict[str, Any]]:
        sql = "SELECT id, created, seeds, risk_score, risk_level, findings, entities FROM cases"
        params: list[Any] = []
        if search:
            sql += " WHERE seeds LIKE ? OR id LIKE ?"
            params += [f"%{search}%", f"%{search}%"]
        sql += " ORDER BY created DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["seeds"] = json.loads(d["seeds"])
            out.append(d)
        return out

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT data FROM cases WHERE id = ?", (case_id,)).fetchone()
            if row is None and case_id in ("last", "latest"):
                row = self._conn.execute("SELECT data FROM cases ORDER BY created DESC LIMIT 1").fetchone()
            if row is None:
                rows = self._conn.execute("SELECT data FROM cases WHERE id LIKE ? ORDER BY created DESC", (f"{case_id}%",)).fetchall()
                row = rows[0] if len(rows) == 1 else None
        return json.loads(row["data"]) if row else None

    def delete_case(self, case_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
            self._conn.execute("DELETE FROM feedback WHERE case_id = ?", (case_id,))
            self._conn.execute("DELETE FROM finding_feedback WHERE case_id = ?", (case_id,))
            self._conn.commit()
            return cur.rowcount > 0

    # ------------------------------------------------------------------ feedback
    def add_feedback(self, case_id: str, verdict: str, notes: str = "") -> None:
        verdict = verdict.lower()
        if verdict not in ("yes", "partial", "no"):
            raise ValueError("verdict must be yes, partial or no")
        with self._lock:
            self._conn.execute(
                "INSERT INTO feedback (case_id, verdict, notes, created) VALUES (?,?,?,?)", (case_id, verdict, notes, _now())
            )
            self._conn.commit()

    def flag_finding(self, case_id: str, finding_id: str, module: str, correct: bool) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO finding_feedback (case_id, finding_id, module, correct, created) VALUES (?,?,?,?,?)",
                (case_id, finding_id, module, 1 if correct else 0, _now()),
            )
            col = "correct" if correct else "wrong"
            self._conn.execute(f"INSERT INTO module_stats (module, {col}) VALUES (?, 1) ON CONFLICT(module) DO UPDATE SET {col} = {col} + 1", (module,))
            self._conn.commit()

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
