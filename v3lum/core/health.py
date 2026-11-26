"""Measured source health and A3 demotion (``~/.v3lum/health.json``, 0600).

A default module leaves the effective default set (policy rule POL-01, reason_code 'demoted') while
any of the A3 conditions holds, and returns as soon as the condition clears:

* its measured p50 latency is above 10 s over at least 20 recorded runs (rolling window of the last
  50 runs that reached the source);
* more than 30% of its findings were marked wrong after at least 10 votes (feedback totals);
* its health check failed on 3 consecutive ``v3lum doctor --sources`` runs;
* it ended BLOCKED on 5 consecutive runs (an ok/empty run resets the streak).

Explicit selection (``-M``) still runs a demoted module. Doctor shows :meth:`HealthState.notices`.
P331 declarative specs whose health checks fail on 7 consecutive days are auto-disabled through
:meth:`HealthState.auto_disabled`.

The engine records every executed run (``record_run``), the feedback loop records vote totals
(``record_votes``) and doctor records health-check results (``record_check``). The file stores only
module names, durations, statuses and counts - never entity values. Loading tolerates a missing or
corrupt file (an empty state with ``errors``); saving never raises (problems go to ``errors``).

Concurrency: an instance is thread-safe (the engine records from its worker threads). With
``autosave`` every record is a read-modify-write of the file under an exclusive lock on
``health.json.lock`` (POSIX ``flock``, best effort): the instance first adopts records another
writer (another process, or another instance on the same file) saved since it last read or
wrote the file, so concurrent writers never drop each other's records.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import json
import math
import os
import statistics
import tempfile
import threading
import time
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from v3lum import paths

try:  # POSIX advisory locks between processes (best effort elsewhere)
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - non-POSIX
    _fcntl = None  # type: ignore[assignment]

__all__ = [
    "BLOCKED_STREAK",
    "CHECK_FAILURES",
    "DURATION_WINDOW",
    "HEALTH_FILE",
    "HEALTH_SCHEMA",
    "HealthState",
    "LOCK_WAIT",
    "MIN_VOTES",
    "NEUTRAL_BLOCKED_CODES",
    "P50_LIMIT",
    "P50_MIN_RUNS",
    "SPEC_DISABLE_DAYS",
    "WRONG_RATIO",
]

HEALTH_FILE = "health.json"
HEALTH_SCHEMA = "v3lum.health/1"
#: A3 demotion thresholds.
P50_LIMIT = 10.0
P50_MIN_RUNS = 20
DURATION_WINDOW = 50
WRONG_RATIO = 0.30
MIN_VOTES = 10
CHECK_FAILURES = 3
BLOCKED_STREAK = 5
#: P331: specs failing their health checks on this many consecutive days are auto-disabled.
SPEC_DISABLE_DAYS = 7
#: Health-check results kept per module.
CHECK_HISTORY = 30

#: Seconds a writer waits for another process holding the file lock before writing without it.
LOCK_WAIT = 2.0

#: Run statuses that reached the source (their duration counts for the p50).
_TIMED = frozenset({"ok", "empty", "error", "blocked", "rate_limited", "quota"})
#: Run statuses that prove the source answers (they reset the BLOCKED streak).
_PASSING = frozenset({"ok", "empty"})
#: BLOCKED reason codes that say nothing about the source: the host was already short-circuited in
#: this run ('circuit') or the contact guard refused a redirect ('hostile_host'). Such runs never
#: reached the source: they neither extend the BLOCKED streak nor add a duration.
NEUTRAL_BLOCKED_CODES: frozenset[str] = frozenset({"circuit", "hostile_host"})
#: Health-check results that count as failures / successes; others (quota, needs_key...) are neutral.
_CHECK_FAILED = frozenset({"dead", "blocked", "error", "failed", "invalid", "timeout"})
_CHECK_OK = frozenset({"ok"})


def _status(value: Any) -> str:
    raw = getattr(value, "status", value) if not isinstance(value, (str, bool)) else value
    raw = getattr(raw, "value", raw)
    if isinstance(raw, bool):
        return "ok" if raw else "dead"
    return str(raw or "").strip().lower()


def _iso(now: Any) -> str:
    if isinstance(now, _dt.datetime):
        moment = now if now.tzinfo else now.replace(tzinfo=_dt.timezone.utc)
    else:
        moment = _dt.datetime.now(_dt.timezone.utc)
    return moment.astimezone(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _date_of(stamp: Any) -> _dt.date | None:
    text = str(stamp or "")
    try:
        return _dt.date.fromisoformat(text[:10])
    except ValueError:
        return None


def _name(module: Any) -> str:
    name = str(getattr(module, "name", module) or "").strip()
    if not name:
        raise ValueError("module name is empty")
    return name


def _clean_entry(raw: Any) -> dict[str, Any] | None:
    """A validated per-module record (malformed parts dropped); None when unusable."""
    if not isinstance(raw, dict):
        return None
    durations = [float(d) for d in raw.get("durations") or [] if isinstance(d, (int, float)) and not isinstance(d, bool) and math.isfinite(d) and d >= 0]
    votes = raw.get("votes") if isinstance(raw.get("votes"), dict) else {}
    wrong, total = votes.get("wrong"), votes.get("total")
    checks = [
        {"at": str(c.get("at") or ""), "result": _status(c.get("result")), "detail": str(c.get("detail") or "")[:200]}
        for c in raw.get("checks") or []
        if isinstance(c, dict) and c.get("result") is not None
    ]

    def count(key: str) -> int:
        value = raw.get(key)
        return int(value) if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0

    entry: dict[str, Any] = {
        "durations": durations[-DURATION_WINDOW:],
        "runs": count("runs"),
        "blocked_streak": count("blocked_streak"),
        "last_status": str(raw.get("last_status") or ""),
        "checks": checks[-CHECK_HISTORY:],
        "check_fail_streak": count("check_fail_streak"),
        "updated": str(raw.get("updated") or ""),
    }
    if isinstance(wrong, int) and isinstance(total, int) and not isinstance(wrong, bool) and 0 <= wrong <= total:
        entry["votes"] = {"wrong": wrong, "total": total, "at": str(votes.get("at") or "")}
    return entry


class HealthState:
    """Per-module health record behind the A3 demotion rules (thread-safe).

    ``HealthState.load()`` reads ``~/.v3lum/health.json`` (or ``path``); with ``autosave`` (default)
    every ``record_*``/``reset`` call writes the file atomically with mode 0600.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None, *, autosave: bool = True) -> None:
        self.path = Path(path).expanduser() if path else paths.home() / HEALTH_FILE
        self.autosave = autosave
        self.errors: list[str] = []
        #: (inode, mtime_ns, size) of the file as last read or written by this instance (None: no
        #: file). Every save replaces the file by a new inode, so each write changes the stamp.
        self.stamp: tuple[int, int, int] | None = None
        self._lock = threading.RLock()
        self._data: dict[str, dict[str, Any]] = {}
        self._dirty = False  # changes not saved yet (never dropped by a refresh)
        self._touched: set[str] = set()  # modules changed since the last save (merged over newer files)
        self._cleared = False  # reset() of every record since the last save

    # ---- persistence --------------------------------------------------------------------------
    @staticmethod
    def file_stamp(path: str | os.PathLike[str]) -> tuple[int, int, int] | None:
        """(inode, mtime_ns, size) of a state file, None when it does not exist."""
        try:
            st = os.stat(path)
        except OSError:
            return None
        return (st.st_ino, st.st_mtime_ns, st.st_size)

    def _read_file(self) -> dict[str, dict[str, Any]] | None:
        """The validated records of the file (None when it is missing, unreadable or corrupt; the
        problem goes to ``errors``)."""
        if not self.path.is_file():
            return None
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            self.errors.append(f"{self.path.name} is unreadable or corrupt ({type(exc).__name__}): starting from an empty health state")
            return None
        modules = data.get("modules") if isinstance(data, dict) else None
        if not isinstance(modules, dict):
            self.errors.append(f"{self.path.name} has no 'modules' object: starting from an empty health state")
            return None
        out: dict[str, dict[str, Any]] = {}
        for name, raw in modules.items():
            entry = _clean_entry(raw)
            if isinstance(name, str) and name and entry is not None:
                out[name] = entry
            else:
                self.errors.append(f"{self.path.name}: dropped a malformed record for {str(name)[:64]!r}")
        return out

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None, *, autosave: bool = True) -> HealthState:
        """Read the state file; a missing file gives an empty state, a corrupt one an empty state
        with an error (it is overwritten by the next save). Never raises."""
        state = cls(path, autosave=autosave)
        state.stamp = cls.file_stamp(state.path)
        data = state._read_file()
        if data is not None:
            state._data = data
        return state

    def _refresh_locked(self) -> bool:
        """Adopt the file's records when another writer saved it since this instance last read or
        wrote it (caller holds ``_lock``). Unsaved local changes are never dropped. True when the
        records were re-read."""
        if self._dirty:
            return False
        current = self.file_stamp(self.path)
        if current == self.stamp:
            return False
        data = self._read_file() if current is not None else None
        self._data = data if data is not None else ({} if current is None else self._data)
        self.stamp = current
        return True

    def refresh(self) -> bool:
        """Re-read the file when another writer (another process, or another instance on the same
        file) changed it; a no-op while this instance holds unsaved changes. True when re-read."""
        with self._lock:
            return self._refresh_locked()

    @contextlib.contextmanager
    def _file_lock(self) -> Iterator[None]:
        """Exclusive cross-process lock on ``<file>.lock`` (0600) for a read-modify-write; best effort:
        without fcntl, without autosave or after LOCK_WAIT seconds the write goes ahead unlocked."""
        if _fcntl is None or not self.autosave:
            yield
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(f"{self.path}.lock", os.O_RDWR | os.O_CREAT, 0o600)
        except OSError:
            yield
            return
        locked = False
        try:
            deadline = time.monotonic() + LOCK_WAIT
            while True:
                try:
                    _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
                    locked = True
                    break
                except OSError:  # held by another writer right now
                    if time.monotonic() >= deadline:
                        self.errors.append(f"{self.path.name}.lock held for more than {LOCK_WAIT:.0f} s: saved without the lock")
                        break
                    time.sleep(0.01)
            yield
        finally:
            if locked:
                with contextlib.suppress(OSError):
                    _fcntl.flock(fd, _fcntl.LOCK_UN)
            os.close(fd)

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {"schema": HEALTH_SCHEMA, "modules": json.loads(json.dumps(self._data))}

    def save(self) -> bool:
        """Write the file atomically (0600). False (and an entry in ``errors``) when it fails."""
        with self._lock, self._file_lock():
            return self._save_locked()

    def _merge_newer_locked(self) -> None:
        """Before writing: when another writer saved the file since this instance last read or wrote
        it (an instance without autosave, or a lock that timed out), keep its records for every
        module this instance did not change - only the changed modules are taken from memory."""
        current = self.file_stamp(self.path)
        if current is None or current == self.stamp or self._cleared:
            return
        disk = self._read_file()
        if disk is None:
            return
        for name in self._touched:
            if name in self._data:
                disk[name] = self._data[name]
            else:
                disk.pop(name, None)  # reset of that module
        self._data = disk

    def _save_locked(self) -> bool:
        self._merge_newer_locked()
        payload = json.dumps(self.to_dict(), indent=1, sort_keys=True)
        directory = self.path.parent
        tmp = ""
        try:
            directory.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".health-", suffix=".tmp", dir=str(directory))
            try:
                os.fchmod(fd, 0o600)
            except (AttributeError, OSError):  # pragma: no cover - non-POSIX
                pass
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(tmp, self.path)
            tmp = ""
            try:
                os.chmod(self.path, 0o600)
            except OSError:  # pragma: no cover - best effort
                pass
            self.stamp = self.file_stamp(self.path)
            self._dirty = False
            self._touched.clear()
            self._cleared = False
            return True
        except OSError as exc:
            self.errors.append(f"cannot save {self.path.name}: {exc}")
            return False
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:  # pragma: no cover - best effort
                    pass

    @contextlib.contextmanager
    def _update(self) -> Iterator[None]:
        """One record: lock, adopt newer records from the file, change, save (with autosave)."""
        with self._lock, self._file_lock():
            if self.autosave:
                self._refresh_locked()
            yield
            self._dirty = True
            if self.autosave:
                self._save_locked()

    def _entry(self, name: str) -> dict[str, Any]:
        """The module's record for a change (marks it touched; caller holds the lock)."""
        self._touched.add(name)
        entry = self._data.get(name)
        if entry is None:
            entry = _clean_entry({}) or {}
            self._data[name] = entry
        return entry

    # ---- recording ----------------------------------------------------------------------------
    def record_run(self, module: Any, duration: float, status: Any, *, now: Any = None, reason_code: str = "") -> None:
        """Record one executed run: its duration (when it reached the source) and its status.

        BLOCKED extends the blocked streak, ok/empty resets it, other statuses leave it unchanged.
        ``reason_code`` (or ``status.reason_code`` when a ModuleResult is passed): a BLOCKED run
        with a code of :data:`NEUTRAL_BLOCKED_CODES` ('circuit', 'hostile_host') never reached the
        source - it is counted as a run but neither extends the streak nor adds a duration.
        """
        name = _name(module)
        st = _status(status)
        code = str(reason_code or (getattr(status, "reason_code", "") if not isinstance(status, str) else "") or "").strip().lower()
        neutral = st == "blocked" and code in NEUTRAL_BLOCKED_CODES
        with self._update():
            entry = self._entry(name)
            entry["runs"] = int(entry.get("runs", 0)) + 1
            entry["last_status"] = st
            timed = st in _TIMED and not neutral
            if timed and isinstance(duration, (int, float)) and not isinstance(duration, bool) and math.isfinite(duration) and duration >= 0:
                entry["durations"] = (list(entry.get("durations") or []) + [round(float(duration), 3)])[-DURATION_WINDOW:]
            if st == "blocked" and not neutral:
                entry["blocked_streak"] = int(entry.get("blocked_streak", 0)) + 1
            elif st in _PASSING:
                entry["blocked_streak"] = 0
            entry["updated"] = _iso(now)

    def record_votes(self, module: Any, wrong: int, total: int, *, now: Any = None) -> None:
        """Record the module's current feedback totals (wrong out of total votes; replaces earlier totals)."""
        name = _name(module)
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in (wrong, total)) or not 0 <= wrong <= total:
            raise ValueError(f"votes must be integers with 0 <= wrong <= total (got wrong={wrong!r}, total={total!r})")
        with self._update():
            entry = self._entry(name)
            entry["votes"] = {"wrong": wrong, "total": total, "at": _iso(now)}
            entry["updated"] = _iso(now)

    def record_check(self, module: Any, result: Any, *, now: Any = None, detail: str = "") -> None:
        """Record one ``doctor --sources`` health-check result.

        ``result`` is a HealthResult, a status string ('ok' | 'blocked' | 'quota' | 'needs_key' |
        'dead') or a bool. ok resets the failure streak; dead/blocked/error extend it; quota and
        needs_key are neutral (the source was not judged).
        """
        name = _name(module)
        st = _status(result)
        if not st:
            raise ValueError("health-check result is empty")
        text = detail or str(getattr(result, "detail", "") or "")
        with self._update():
            entry = self._entry(name)
            checks = list(entry.get("checks") or [])
            checks.append({"at": _iso(now), "result": st, "detail": text[:200]})
            entry["checks"] = checks[-CHECK_HISTORY:]
            if st in _CHECK_OK:
                entry["check_fail_streak"] = 0
            elif st in _CHECK_FAILED:
                entry["check_fail_streak"] = int(entry.get("check_fail_streak", 0)) + 1
            entry["updated"] = _iso(now)

    def reset(self, module: Any = None) -> None:
        """Forget one module's record (or every record when ``module`` is None)."""
        with self._update():
            if module is None:
                self._data.clear()
                self._cleared = True
            else:
                name = _name(module)
                self._touched.add(name)
                self._data.pop(name, None)

    # ---- queries ------------------------------------------------------------------------------
    def modules(self) -> list[str]:
        with self._lock:
            return sorted(self._data)

    def stats(self, module: Any) -> dict[str, Any]:
        """A copy of the module's record plus its p50 (empty dict when nothing was recorded)."""
        with self._lock:
            entry = self._data.get(_name(module))
            if entry is None:
                return {}
            out = json.loads(json.dumps(entry))
        out["p50"] = self.p50(module)
        return out

    def last_checks(self, module: Any, n: int = 5) -> list[dict[str, str]]:
        """The ``n`` most recent health-check results (oldest first): {at, result, detail}."""
        with self._lock:
            entry = self._data.get(_name(module)) or {}
            checks = list(entry.get("checks") or [])
        return [dict(c) for c in checks[-max(0, int(n)):]] if n else []

    def p50(self, module: Any) -> float | None:
        """Median duration of the recorded window (None without runs)."""
        with self._lock:
            durations = list((self._data.get(_name(module)) or {}).get("durations") or [])
        return round(statistics.median(durations), 3) if durations else None

    def demotion_reasons(self, module: Any) -> list[str]:
        """Why the module is demoted right now (empty when it is not)."""
        name = _name(module)
        with self._lock:
            entry = self._data.get(name)
            if entry is None:
                return []
            durations = list(entry.get("durations") or [])
            votes = dict(entry.get("votes") or {})
            check_streak = int(entry.get("check_fail_streak", 0))
            blocked = int(entry.get("blocked_streak", 0))
        reasons: list[str] = []
        if len(durations) >= P50_MIN_RUNS:
            p50 = statistics.median(durations)
            if p50 > P50_LIMIT:
                reasons.append(f"p50 {p50:.1f} s over {len(durations)} runs (> {P50_LIMIT:.0f} s)")
        total, wrong = int(votes.get("total", 0)), int(votes.get("wrong", 0))
        if total >= MIN_VOTES and wrong / total > WRONG_RATIO:
            reasons.append(f"{wrong}/{total} findings marked wrong (> {WRONG_RATIO:.0%} after >= {MIN_VOTES} votes)")
        if check_streak >= CHECK_FAILURES:
            reasons.append(f"health check failed on {check_streak} consecutive doctor --sources runs")
        if blocked >= BLOCKED_STREAK:
            reasons.append(f"BLOCKED on {blocked} consecutive runs")
        return reasons

    def is_demoted(self, module: Any) -> bool:
        """Does any A3 demotion condition hold for the module right now?"""
        return bool(self.demotion_reasons(module))

    def consecutive_failed_days(self, module: Any) -> int:
        """Length of the run of consecutive calendar days with failed checks that ends at the latest
        failure, counted since the last successful check (0 when the last check passed)."""
        with self._lock:
            checks = list((self._data.get(_name(module)) or {}).get("checks") or [])
        days: set[_dt.date] = set()
        for check in reversed(checks):
            if check.get("result") in _CHECK_OK:
                break
            if check.get("result") in _CHECK_FAILED:
                day = _date_of(check.get("at"))
                if day is not None:
                    days.add(day)
        if not days:
            return 0
        day, count = max(days), 0
        while day in days:
            count += 1
            day -= _dt.timedelta(days=1)
        return count

    def auto_disabled(self, module: Any, *, days: int = SPEC_DISABLE_DAYS) -> bool:
        """P331: health checks failed on ``days`` consecutive days (lifts with the next passing check)."""
        return self.consecutive_failed_days(module) >= int(days)

    def notices(self, modules: Iterable[str] | None = None) -> list[str]:
        """Doctor notices: demoted modules (A3) and auto-disabled ones (P331), one line each."""
        names = sorted(modules) if modules is not None else self.modules()
        out: list[str] = []
        for name in names:
            reasons = self.demotion_reasons(name)
            if reasons:
                out.append(f"{name}: left the default set ({'; '.join(reasons)}) - it still runs with -M and returns once it passes again (A3)")
            failed_days = self.consecutive_failed_days(name)
            if failed_days >= SPEC_DISABLE_DAYS:
                out.append(f"{name}: health checks failed on {failed_days} consecutive days - auto-disabled until a check passes again (P331)")
        return out
