"""Provider quotas (P334) and the v1 per-module daily counters.

Budgets are keyed by **provider** (the registry ``quota`` block), not by module: every endpoint of a
provider shares one counter and only requests to that provider's hosts count. The HTTP client
reserves before sending (``HttpClient`` calls :meth:`QuotaBook.reserve` for every hop to a
registered provider host) and forwards the provider's own quota/rate-limit markers to
:meth:`QuotaBook.signal`.

* windows: hour / day / month UTC windows at ``floor(limit x safety_margin)`` of the published
  limit (``QuotaSpec.budget``, at most 80%); a reservation is one ``BEGIN IMMEDIATE`` transaction on
  the quota DB, so concurrent threads and processes never overshoot a budget;
* scope: ``egress_ip`` budgets are global per installation and egress - never multiplied by keys,
  proxies or Tor (A13); ``key`` plans are counted per key name (``scope_key='key:<name>'``);
* seeds first: 20% of every window (:data:`SEED_RESERVE`) is kept for analyst-typed seeds; priority
  ``'pivot2'`` (pivots at depth >= 2) never consumes it;
* token bucket: ``rate_per_second``/``burst`` of the block (in memory, per process), at
  ``rate_per_second x safety_margin`` like the window budgets (P334 cond 3: at most 80% of the
  published limit): :meth:`QuotaBook.reserve` takes the provider's next slot and **returns** the
  seconds the caller must wait before sending (it never sleeps itself: the HTTP client waits on its
  own clock and run deadline; :data:`RATE_WAIT_MAX` is the longest wait it should accept,
  :meth:`rate_interval` the provider's interval for the per-host limiter);
* provider signal wins (P334 cond 8): a quota marker stops every request of the run to that provider
  until its window resets and is recorded in the quota DB, where it stops the pivots of other runs
  and processes (an analyst-typed seed keeps one attempt: the provider's latest answer is the
  truth); a rate-limit marker backs the provider off for the rest of the run (memory only); a
  signal never lasts longer than :data:`MAX_SIGNAL_DAYS` (a hostile or broken ``Retry-After`` cannot
  block a provider for years);
* DoH resolvers are never charged; exhaustion never triggers a LIGHT/ACTIVE alternative, another
  account or another egress - the lookup is deferred (:meth:`defer`) and reported
  (:meth:`quota_lines`: 'HackerTarget: 40/40 today, 12 lookups deferred');
* the quota DB is ``~/.v3lum/quota.db`` or setting ``quota_db_path`` (a team-shared DB for analysts
  behind one NAT); it holds counters and pseudonymised deferrals only - never an investigated value
  (the deferral reason is scrubbed of the entity value, and deleted rows are overwritten:
  ``PRAGMA secure_delete``).

The v1 API (``used``/``add``/``exhausted``/``summary``/``reset``, per-module daily counters behind
``Module.daily_quota``, the fallback for providers without a quota block) is kept.
"""

from __future__ import annotations

import datetime as _dt
import math
import sqlite3
import threading
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from v3lum import paths
from v3lum.core.clock import SYSTEM_CLOCK, Clock
from v3lum.core.http import QuotaExceeded, RateLimited
from v3lum.core.migrations import migrate

__all__ = [
    "DOH_PROVIDERS",
    "MAX_SIGNAL_DAYS",
    "PRIORITIES",
    "RATE_WAIT_MAX",
    "SEED_RESERVE",
    "WINDOWS",
    "QuotaBook",
    "default_path",
    "deferral_key",
    "window_end",
    "window_start",
]

#: Budget windows, shortest first.
WINDOWS: tuple[str, ...] = ("hour", "day", "month")
#: Share of every window kept for analyst-typed seeds (P334 cond 6).
SEED_RESERVE = 0.2
#: Reservation priorities: 'seed' (depth 0), 'pivot' (depth 1), 'pivot2' (depth >= 2).
PRIORITIES: tuple[str, ...] = ("seed", "pivot", "pivot2")
#: Registry ids of the DoH resolvers: never charged (P029 cond 11, P334 cond 1).
DOH_PROVIDERS = frozenset({"core_doh", "google_public_dns", "cloudflare_dns", "quad9", "internal_doh"})
#: Longest token-bucket wait the HTTP client should accept for one request (seconds); a longer wait
#: means 'could not verify now' (RateLimited) rather than a blocked worker thread.
RATE_WAIT_MAX = 15.0
#: Longest a provider signal (quota marker, rate-limit backoff) is honoured, whatever ``until`` or
#: ``Retry-After`` says: one month window plus a day.
MAX_SIGNAL_DAYS = 32
_WINDOW_LABEL = {"hour": "this hour", "day": "today", "month": "this month"}
_WINDOW_KEEP_DAYS = {"hour": 3, "day": 62, "month": 400}
_REASON_MAX = 200


# ======================================================================================
# helpers
# ======================================================================================


def default_path(settings: Any = None) -> Path:
    """The quota DB: setting ``quota_db_path`` when set (a team-shared DB), else ``~/.v3lum/quota.db``."""
    configured = ""
    if settings is not None:
        try:
            getter = getattr(settings, "get", None)
            configured = str((getter("quota_db_path", "") if callable(getter) else getattr(settings, "quota_db_path", "")) or "")
        except Exception:  # pragma: no cover - a broken settings object falls back to the default
            configured = ""
    configured = configured.strip()
    return Path(configured).expanduser() if configured else paths.quota_file()


def _utc(now: _dt.datetime) -> _dt.datetime:
    if now.tzinfo is None:
        return now.replace(tzinfo=_dt.timezone.utc)
    return now.astimezone(_dt.timezone.utc)


def window_start(window: str, now: _dt.datetime) -> str:
    """Key of the UTC window containing ``now``: 'YYYY-MM-DDTHH' (hour), 'YYYY-MM-DD' (day), 'YYYY-MM' (month)."""
    now = _utc(now)
    if window == "hour":
        return now.strftime("%Y-%m-%dT%H")
    if window == "day":
        return now.strftime("%Y-%m-%d")
    if window == "month":
        return now.strftime("%Y-%m")
    raise ValueError(f"unknown quota window {window!r}")


def window_end(window: str, now: _dt.datetime) -> _dt.datetime:
    """When the UTC window containing ``now`` resets."""
    now = _utc(now)
    if window == "hour":
        return now.replace(minute=0, second=0, microsecond=0) + _dt.timedelta(hours=1)
    if window == "day":
        return now.replace(hour=0, minute=0, second=0, microsecond=0) + _dt.timedelta(days=1)
    if window == "month":
        first = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        return (first + _dt.timedelta(days=32)).replace(day=1)
    raise ValueError(f"unknown quota window {window!r}")


def deferral_key(entity_key: str) -> str:
    """The form an entity key takes in the deferred list: the keyed pseudonym ``'<type>:#<hmac12>'``
    for every type (the quota DB may be team-shared: it never holds an investigated value)."""
    from v3lum.core import hmacid

    text = str(entity_key or "")
    if hmacid.is_pseudonym(text):
        return text
    etype, sep, value = text.partition(":")
    if not sep:
        return hmacid.pseudonym("unknown", text)
    return hmacid.pseudonym(etype, value)


def _parse_iso(text: Any) -> _dt.datetime | None:
    if not text:
        return None
    try:
        dt = _dt.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=_dt.timezone.utc)


def _until(value: Any) -> _dt.datetime | None:
    """A signal end given as a datetime or an ISO string, in UTC (stored ends compare as text), else None."""
    if isinstance(value, _dt.datetime):
        return _utc(value)
    if isinstance(value, str):
        parsed = _parse_iso(value)
        return _utc(parsed) if parsed is not None else None
    return None


def _scrub_reason(reason: Any, entity_key: str) -> str:
    """A deferral reason fit for a (possibly team-shared) quota DB: the entity's value - an e-mail,
    a username... that a module or provider message may quote - is replaced by its pseudonym, and the
    text is capped."""
    text = " ".join(str(reason or "").split())
    _etype, sep, value = str(entity_key or "").partition(":")
    value = value.strip()
    if sep and len(value) >= 3 and text:
        lowered, needle = text.lower(), value.lower()
        if needle in lowered:
            replacement = deferral_key(entity_key)
            out, start = [], 0
            while True:
                index = lowered.find(needle, start)
                if index < 0:
                    break
                out.append(text[start:index])
                out.append(replacement)
                start = index + len(needle)
            out.append(text[start:])
            text = "".join(out)
    return text[:_REASON_MAX]


def _effective_rate(spec: Any) -> float:
    """Requests per second the token bucket allows: ``rate_per_second x safety_margin`` (the same
    margin as the window budgets, P334 cond 3); 0.0 when the block declares no rate."""
    try:
        rate = float(getattr(spec, "rate_per_second", None) or 0.0)
        margin = float(getattr(spec, "safety_margin", 0.8) or 0.8)
    except (TypeError, ValueError):
        return 0.0
    if rate <= 0 or not math.isfinite(rate):
        return 0.0
    margin = min(1.0, margin) if math.isfinite(margin) and margin > 0 else 0.8
    return rate * margin


def _seed_limit(budget: int, priority: str) -> int:
    """Budget usable at ``priority``: the whole window for seeds and depth-1 pivots, the window
    minus the seed reserve for 'pivot2' (and unknown priorities, fail safe)."""
    if priority in ("seed", "pivot"):
        return budget
    return max(0, budget - math.ceil(budget * SEED_RESERVE))


class _Refused(Exception):
    def __init__(self, window: str, used: int, budget: int, limit: int) -> None:
        super().__init__(window)
        self.window, self.used, self.budget, self.limit = window, used, budget, limit


# ======================================================================================
# quota book
# ======================================================================================


class QuotaBook:
    """Provider budgets, provider signals, deferred lookups and the v1 per-module counters.

    ``QuotaBook(path=None, *, clock=None, providers=None, settings=None)``: ``path`` defaults to
    :func:`default_path` (setting ``quota_db_path``); ``clock`` drives the UTC windows and the token
    bucket (``SYSTEM_CLOCK`` by default; a fake clock in tests); ``providers`` is the provider
    registry (or a callable returning it; default ``providers.registry()``). Safe across threads
    (one connection behind a lock) and processes (``BEGIN IMMEDIATE`` reservations).
    """

    def __init__(self, path: str | Path | None = None, *, clock: Clock | None = None, providers: Any = None, settings: Any = None) -> None:
        self.path = str(path or default_path(settings))
        self.clock: Clock = clock or SYSTEM_CLOCK
        self._providers = providers
        self._lock = threading.Lock()
        self._mem_lock = threading.Lock()
        #: provider -> backoff end (epoch seconds; None = the rest of the run), never persisted
        self._backoff: dict[str, float | None] = {}
        #: (provider, scope_key) -> theoretical arrival time on the monotonic clock (token bucket)
        self._tat: dict[tuple[str, str], float] = {}
        #: provider -> lookups deferred through this book (this run)
        self._deferred_run: Counter[str] = Counter()
        #: (provider, scope_key) -> end of a quota signal received by this book (this run)
        self._signals: dict[tuple[str, str], _dt.datetime] = {}
        private = paths.inside_home(self.path)
        if private:  # a team-shared quota_db_path keeps the mode its administrator gave it
            paths.restrict_file(self.path, create=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30, isolation_level=None)
        self._conn.execute("PRAGMA secure_delete = ON")  # purged deferrals are overwritten, not just unlinked
        #: schema version after the migrations ran
        self.version = migrate(self._conn, "quota")
        if private:
            paths.restrict_file(self.path)
        self._prune_windows()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ plumbing
    def _now(self) -> _dt.datetime:
        return _utc(self.clock.now())

    def _registry(self) -> Any:
        reg = self._providers
        if reg is not None:
            return reg() if callable(reg) and not hasattr(reg, "get") else reg
        try:
            from v3lum.core import providers as providers_mod

            return providers_mod.registry()
        except Exception:  # pragma: no cover - a registry bug must not break requests
            return None

    def _provider(self, pid: str) -> Any:
        reg = self._registry()
        try:
            return reg.get(pid) if reg is not None else None
        except Exception:  # pragma: no cover
            return None

    @staticmethod
    def _name(prov: Any, pid: str) -> str:
        return str(getattr(prov, "name", "") or pid)

    @staticmethod
    def _scope(prov: Any, spec: Any, scope_key: str) -> str:
        """'egress' for keyless/egress-IP budgets; 'key:<name>' for key-scoped plans (one key per
        provider, never multiplied)."""
        if scope_key and scope_key != "egress":
            return str(scope_key)
        if spec is not None and getattr(spec, "scope", "") == "key":
            keys = sorted((getattr(prov, "keys", None) or {}).keys())
            if keys:
                return f"key:{keys[0]}"
        return "egress"

    @staticmethod
    def _is_doh(pid: str, host: str = "") -> bool:
        if pid in DOH_PROVIDERS:
            return True
        if host:
            try:
                from v3lum.core.dns import is_public_doh_host

                return bool(is_public_doh_host(host))
            except Exception:  # pragma: no cover
                return False
        return False

    def _write(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                cur = self._conn.execute(sql, params)
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            return max(0, cur.rowcount)

    def _prune_windows(self) -> None:
        """Drop window rows long past (hours after 3 days, days after 62, months after 400)."""
        now = self._now()
        try:
            with self._lock:
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    for window, keep in _WINDOW_KEEP_DAYS.items():
                        cutoff = window_start(window, now - _dt.timedelta(days=keep))
                        self._conn.execute("DELETE FROM windows WHERE window = ? AND window_start < ?", (window, cutoff))
                    self._conn.execute("DELETE FROM signals WHERE exhausted_until < ?", ((now - _dt.timedelta(days=1)).isoformat(timespec="seconds"),))
                    self._conn.execute("COMMIT")
                except BaseException:
                    self._conn.execute("ROLLBACK")
                    raise
        except sqlite3.Error:  # pragma: no cover - a busy shared DB: next time
            pass

    # ------------------------------------------------------------------ v1 per-module counters
    @staticmethod
    def today(now: _dt.datetime | None = None) -> str:
        return (now or _dt.datetime.now(_dt.timezone.utc)).strftime("%Y-%m-%d")

    def _today(self) -> str:
        return window_start("day", self._now())

    def used(self, module: str, day: str | None = None) -> int:
        """Requests recorded today (or on ``day``) for a module (v1 counter) or a provider (the
        larger of its v1 counter and the provider's day window, all scopes)."""
        day = day or self._today()
        with self._lock:
            row = self._conn.execute("SELECT used FROM quota WHERE module = ? AND day = ?", (module, day)).fetchone()
            win = self._conn.execute(
                "SELECT COALESCE(SUM(used), 0) FROM windows WHERE provider = ? AND window = 'day' AND window_start = ?", (module, day)
            ).fetchone()
        return max(int(row[0]) if row else 0, int(win[0]) if win else 0)

    def add(self, module: str, n: int, day: str | None = None) -> None:
        """v1: count ``n`` requests of a module with a ``daily_quota`` (the engine, after the run)."""
        if n <= 0:
            return
        self._write(
            "INSERT INTO quota (module, day, used) VALUES (?, ?, ?) ON CONFLICT(module, day) DO UPDATE SET used = used + ?",
            (module, day or self._today(), int(n), int(n)),
        )

    def exhausted(self, module: str, limit: int | None, day: str | None = None) -> bool:
        """v1: True when ``limit`` (a module's daily_quota) is used up today."""
        return bool(limit) and self.used(module, day) >= int(limit or 0)

    def summary(self, day: str | None = None) -> dict[str, int]:
        """v1: {module: used} of the per-module counters of ``day`` (today by default)."""
        with self._lock:
            rows = self._conn.execute("SELECT module, used FROM quota WHERE day = ?", (day or self._today(),)).fetchall()
        return {m: u for m, u in rows}

    def reset(self, module: str | None = None) -> None:
        """Forget counters: of one module/provider (v1 rows, provider windows and signals) or all
        of them. Deferred lookups (case data) are kept; the in-memory backoff is cleared."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if module:
                    self._conn.execute("DELETE FROM quota WHERE module = ?", (module,))
                    self._conn.execute("DELETE FROM windows WHERE provider = ?", (module,))
                    self._conn.execute("DELETE FROM signals WHERE provider = ?", (module,))
                else:
                    for table in ("quota", "windows", "signals"):
                        self._conn.execute(f"DELETE FROM {table}")
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
        with self._mem_lock:
            if module:
                self._backoff.pop(module, None)
                for key in [k for k in self._signals if k[0] == module]:
                    del self._signals[key]
            else:
                self._backoff.clear()
                self._signals.clear()

    # ------------------------------------------------------------------ provider budgets (P334)
    def reserve(
        self, provider_id: str, host: str = "", *, scope_key: str = "egress", priority: str = "seed", n: int = 1
    ) -> float:
        """Reserve ``n`` requests to ``provider_id`` before sending; returns the seconds the caller
        must wait before sending to respect the provider's token bucket (0.0 when free; the book
        never sleeps - the HTTP client waits on its clock, bounded by the run deadline and
        :data:`RATE_WAIT_MAX`).

        Raises QuotaExceeded (Status.QUOTA, 'could not verify') when the provider signalled its
        quota or a window budget is used up at this priority, and RateLimited while the provider is
        backing off after a rate-limit marker. Refused requests take no bucket slot. DoH resolvers
        and providers without a quota block are never charged. Atomic across threads and processes
        (``BEGIN IMMEDIATE``).
        """
        pid = str(provider_id or "")
        n = int(n or 0)
        if not pid or n <= 0 or self._is_doh(pid, host):
            return 0.0
        prov = self._provider(pid)
        name = self._name(prov, pid)
        self._check_backoff(pid, name)
        spec = getattr(prov, "quota", None)
        scope = self._scope(prov, spec, scope_key)
        now = self._now()
        until = self._signal_until(pid, scope, now, priority=priority)
        if until is not None:
            raise QuotaExceeded(
                f"{name}: the provider reported its quota exhausted; could not verify until {until:%Y-%m-%d %H:%M} UTC"
                " (lookups are deferred, never sent through another account or egress)"
            )
        if spec is None:
            return 0.0
        try:
            self._charge(pid, scope, spec, priority, n, now)
        except _Refused as ref:
            label = _WINDOW_LABEL.get(ref.window, ref.window)
            if ref.limit < ref.budget and ref.used < ref.budget:
                msg = (
                    f"{name}: {ref.used}/{ref.budget} {label}; the last {ref.budget - ref.limit} lookups are kept for"
                    " analyst-typed seeds - this pivot is deferred (could not verify)"
                )
            else:
                reset = window_end(ref.window, now)
                msg = f"{name}: quota used up ({ref.used}/{ref.budget} {label}); could not verify until {reset:%Y-%m-%d %H:%M} UTC"
            raise QuotaExceeded(msg) from None
        return self._bucket(pid, scope, spec, n)

    def _bucket(self, pid: str, scope: str, spec: Any, n: int) -> float:
        """Token bucket (GCRA, in memory) at ``rate_per_second x safety_margin``: takes the
        provider's next slot and returns the seconds to wait before sending (0.0 when free). Only
        charged requests take a slot."""
        rate = _effective_rate(spec)
        if not rate:
            return 0.0
        interval = 1.0 / rate
        tolerance = max(0, int(getattr(spec, "burst", 1) or 1) - 1) * interval
        with self._mem_lock:
            now = self.clock.monotonic()
            tat = self._tat.get((pid, scope), now)
            start = max(now, tat - tolerance)
            self._tat[(pid, scope)] = max(tat, start) + n * interval
        return max(0.0, start - now)

    def rate_interval(self, provider: str) -> float:
        """Seconds between two requests to ``provider`` at its budgeted rate (``1 / (rate_per_second
        x safety_margin)`` of the quota block; 0.0 when it declares none): the interval the per-host
        limiter applies to the provider's hosts."""
        spec = getattr(self._provider(str(provider or "")), "quota", None)
        rate = _effective_rate(spec) if spec is not None else 0.0
        return 1.0 / rate if rate else 0.0

    def _charge(self, pid: str, scope: str, spec: Any, priority: str, n: int, now: _dt.datetime) -> None:
        windows = [(w, spec.budget(w)) for w in WINDOWS if spec.budget(w) is not None]
        if not windows:
            return
        with self._lock:
            conn = self._conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                keys = []
                for window, budget in windows:
                    start = window_start(window, now)
                    row = conn.execute(
                        "SELECT used FROM windows WHERE provider = ? AND scope_key = ? AND window = ? AND window_start = ?",
                        (pid, scope, window, start),
                    ).fetchone()
                    used = int(row[0]) if row else 0
                    limit = _seed_limit(int(budget), priority)
                    if used + n > limit:
                        raise _Refused(window, used, int(budget), limit)
                    keys.append((window, start))
                for window, start in keys:
                    conn.execute(
                        "INSERT INTO windows (provider, scope_key, window, window_start, used) VALUES (?, ?, ?, ?, ?)"
                        " ON CONFLICT(provider, scope_key, window, window_start) DO UPDATE SET used = used + ?",
                        (pid, scope, window, start, n, n),
                    )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def _window_used(self, pid: str, scope: str, window: str, now: _dt.datetime) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT used FROM windows WHERE provider = ? AND scope_key = ? AND window = ? AND window_start = ?",
                (pid, scope, window, window_start(window, now)),
            ).fetchone()
        return int(row[0]) if row else 0

    def usage(self, provider: str, *, scope_key: str = "egress") -> dict[str, dict[str, int]]:
        """``{window: {used, budget}}`` of a provider with a quota block ({} otherwise)."""
        prov = self._provider(provider)
        spec = getattr(prov, "quota", None)
        if spec is None:
            return {}
        scope = self._scope(prov, spec, scope_key)
        now = self._now()
        out = {}
        for window in WINDOWS:
            budget = spec.budget(window)
            if budget is not None:
                out[window] = {"used": self._window_used(provider, scope, window, now), "budget": int(budget)}
        return out

    def remaining(self, provider: str, *, priority: str = "seed", scope_key: str = "egress") -> int | None:
        """Requests still available to ``provider`` now (the tightest window at ``priority``); 0 while
        the provider's own signal holds; None when it has no quota block (or is a DoH resolver)."""
        pid = str(provider or "")
        if not pid or self._is_doh(pid):
            return None
        prov = self._provider(pid)
        spec = getattr(prov, "quota", None)
        scope = self._scope(prov, spec, scope_key)
        now = self._now()
        if self._signal_until(pid, scope, now, priority=priority) is not None:
            return 0
        if spec is None:
            return None
        left: list[int] = []
        for window in WINDOWS:
            budget = spec.budget(window)
            if budget is None:
                continue
            left.append(max(0, _seed_limit(int(budget), priority) - self._window_used(pid, scope, window, now)))
        return min(left) if left else None

    def exhausted_provider(self, provider: str, *, priority: str = "seed", scope_key: str = "egress") -> bool:
        """True while ``provider`` cannot take a request at ``priority``: its own quota signal holds
        or a window budget is used up (policy gate POL-15 -> QUOTA 'quota')."""
        left = self.remaining(provider, priority=priority, scope_key=scope_key)
        return left is not None and left <= 0

    # ------------------------------------------------------------------ provider signals
    def _persisted_signal(self, pid: str, scope: str, now: _dt.datetime) -> _dt.datetime | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT exhausted_until FROM signals WHERE provider = ? AND scope_key IN (?, 'egress') ORDER BY exhausted_until DESC LIMIT 1",
                (pid, scope),
            ).fetchone()
        until = _parse_iso(row[0]) if row else None
        return until if until is not None and until > now else None

    def _signal_until(self, pid: str, scope: str, now: _dt.datetime, *, priority: str | None = None) -> _dt.datetime | None:
        """End of the provider quota signal that applies at ``priority`` (None = none applies).

        A signal received in this run (this book) stops every request until the window resets. A
        signal recorded by another run or process (the quota DB, shared by a team behind one NAT)
        stops pivots; an analyst-typed seed (``priority='seed'``) still gets its one honest attempt,
        because the provider's latest answer is the truth (it re-signals when still exhausted).
        ``priority=None`` reports any recorded signal (reports, doctor)."""
        with self._mem_lock:
            mine = [end for (p, sc), end in self._signals.items() if p == pid and sc in (scope, "egress") and end > now]
        if mine:
            return max(mine)
        if priority == "seed":
            return None
        return self._persisted_signal(pid, scope, now)

    def mark_exhausted(
        self, provider: str, until: _dt.datetime | str | None = None, *, scope_key: str = "egress", reason: str = ""
    ) -> _dt.datetime:
        """Record that ``provider`` reported its quota exhausted: every request of this run is refused
        until ``until``, and the signal is recorded in the quota DB, where it stops the pivots of
        other runs and processes (seeds keep one attempt, see :meth:`_signal_until`). ``until``
        defaults to the reset of the provider's shortest budget window (the UTC day for providers
        without a quota block). An earlier ``until`` never shortens a later one. Returns the
        effective end."""
        pid = str(provider or "")
        now = self._now()
        prov = self._provider(pid)
        spec = getattr(prov, "quota", None)
        scope = self._scope(prov, spec, scope_key)
        end = _until(until)
        if end is None:
            windows = [w for w in WINDOWS if spec is not None and spec.limit(w) is not None] or ["day"]
            end = window_end(windows[0], now)
        end = min(end, now + _dt.timedelta(days=MAX_SIGNAL_DAYS))  # never years, whatever the provider says
        stamp = end.isoformat(timespec="seconds")
        with self._mem_lock:
            previous = self._signals.get((pid, scope))
            self._signals[(pid, scope)] = max(end, previous) if previous is not None else end
        self._write(
            "INSERT INTO signals (provider, scope_key, exhausted_until, reason) VALUES (?, ?, ?, ?)"
            " ON CONFLICT(provider, scope_key) DO UPDATE SET"
            " exhausted_until = MAX(signals.exhausted_until, excluded.exhausted_until), reason = excluded.reason",
            (pid, scope, stamp, str(reason or "")),
        )
        current = self._signal_until(pid, scope, now)
        return current or end

    def signal(self, provider_id: str, *, kind: str, until: _dt.datetime | str | None = None, scope_key: str = "egress", reason: str = "") -> None:
        """The HTTP client's quota protocol (WP03): ``kind='quota'`` (a provider quota marker) marks
        the provider exhausted until ``until`` or the window reset - the provider's own signal wins
        over the counters; ``kind='rate_limited'`` backs the provider off in memory until ``until``
        or for the rest of the run (never persisted). Other kinds are ignored."""
        pid = str(provider_id or "")
        if not pid or self._is_doh(pid):
            return
        if kind == "quota":
            self.mark_exhausted(pid, until, scope_key=scope_key, reason=reason or "provider quota marker")
        elif kind == "rate_limited":
            end = _until(until)
            if end is not None:
                end = min(end, self._now() + _dt.timedelta(days=MAX_SIGNAL_DAYS))
            with self._mem_lock:
                self._backoff[pid] = end.timestamp() if end is not None else None

    def _check_backoff(self, pid: str, name: str) -> None:
        with self._mem_lock:
            if pid not in self._backoff:
                return
            end = self._backoff[pid]
        if end is not None and self._now().timestamp() >= end:
            with self._mem_lock:
                self._backoff.pop(pid, None)
            return
        when = "for the rest of this run" if end is None else f"until {_dt.datetime.fromtimestamp(end, _dt.timezone.utc):%H:%M:%S} UTC"
        raise RateLimited(f"{name}: the provider rate-limited us; backing off {when} (could not verify)")

    def backing_off(self, provider: str) -> bool:
        """True while ``provider`` is in its in-memory rate-limit backoff."""
        try:
            self._check_backoff(str(provider or ""), str(provider or ""))
        except RateLimited:
            return True
        return False

    def reset_run(self) -> None:
        """Start a new run: forget the in-memory backoffs, token buckets, per-run deferral counts and
        this run's provider signals (persisted counters and recorded signals stay)."""
        with self._mem_lock:
            self._backoff.clear()
            self._tat.clear()
            self._deferred_run.clear()
            self._signals.clear()

    # ------------------------------------------------------------------ deferred lookups (P334 cond 6-7)
    def defer(self, case_id: str, module: str, entity_key: str, reason: str = "", *, provider: str = "") -> None:
        """Record a (module, entity) lookup deferred by a quota for ``cases resume``. The entity is
        stored as its keyed pseudonym (:func:`deferral_key`) and the reason without the entity's
        value (capped at 200 characters); ``provider`` defaults to the module's."""
        pid = str(provider or "") or self._module_provider(module)
        key = deferral_key(entity_key)
        stamp = self._now().isoformat(timespec="seconds")
        self._write(
            "INSERT INTO deferred (case_id, module, entity_key, reason, created, provider) VALUES (?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(case_id, module, entity_key) DO UPDATE SET reason = excluded.reason, created = excluded.created,"
            " provider = excluded.provider",
            (str(case_id or ""), str(module or ""), key, _scrub_reason(reason, entity_key), stamp, pid),
        )
        with self._mem_lock:
            self._deferred_run[pid or str(module or "")] += 1

    @staticmethod
    def _module_provider(module: str) -> str:
        try:
            from v3lum.core.module import get_module

            return str(getattr(get_module(module), "provider", "") or "")
        except Exception:  # unknown module: deferral still recorded, grouped under the module name
            return ""

    def deferred(self, case_id: str, *, case: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        """Deferred lookups of a case: ``[{case_id, module, entity_key, reason, created, provider}]``.
        ``entity_key`` is the stored pseudonym; pass the stored ``case`` dict to get the real entity
        keys back (matched against its seeds and entities; unmatched rows keep the pseudonym)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT case_id, module, entity_key, reason, created, provider FROM deferred WHERE case_id = ? ORDER BY module, entity_key",
                (str(case_id or ""),),
            ).fetchall()
        names = ("case_id", "module", "entity_key", "reason", "created", "provider")
        out = [dict(zip(names, r)) for r in rows]
        if case is not None:
            keys: list[str] = [str(k) for k in case.get("seeds") or () if k]
            keys += [str(e.get("key")) for e in case.get("entities") or () if isinstance(e, Mapping) and e.get("key")]
            lookup = {deferral_key(k): k for k in keys}
            for row in out:
                row["entity_key"] = lookup.get(row["entity_key"], row["entity_key"])
        return out

    def forget_case(self, case_id: str, *, dry_run: bool = False) -> int:
        """Remove (or count, ``dry_run``) the deferred lookups of a case (the A10 purge)."""
        if dry_run:
            with self._lock:
                row = self._conn.execute("SELECT COUNT(*) FROM deferred WHERE case_id = ?", (str(case_id or ""),)).fetchone()
            return int(row[0]) if row else 0
        return self._write("DELETE FROM deferred WHERE case_id = ?", (str(case_id or ""),))

    # ------------------------------------------------------------------ report lines (P334 cond 7)
    def quota_lines(self, case_id: str | None = None) -> list[str]:
        """One line per provider that is exhausted (budget or provider signal) or has deferred
        lookups, e.g. 'HackerTarget: 40/40 today, 12 lookups deferred'. Deferred counts come from
        the case's rows when ``case_id`` is given, else from this run's :meth:`defer` calls."""
        now = self._now()
        deferred: Counter[str] = Counter()
        if case_id:
            with self._lock:
                for pid, module, count in self._conn.execute(
                    "SELECT provider, module, COUNT(*) FROM deferred WHERE case_id = ? GROUP BY provider, module", (case_id,)
                ):
                    deferred[pid or module] += int(count)
        else:
            with self._mem_lock:
                deferred.update(self._deferred_run)
        with self._lock:
            signalled = {
                r[0]
                for r in self._conn.execute("SELECT provider, exhausted_until FROM signals").fetchall()
                if (_parse_iso(r[1]) or now) > now
            }
        with self._mem_lock:
            signalled |= {p for (p, _scope), end in self._signals.items() if end > now}
        candidates = set(deferred) | signalled
        reg = self._registry()
        try:
            budgeted = [p for p in (reg.providers() if reg is not None else []) if getattr(p, "quota", None) is not None]
        except Exception:  # pragma: no cover
            budgeted = []
        for prov in budgeted:
            if self.exhausted_provider(prov.id):
                candidates.add(prov.id)
        lines: list[tuple[str, str]] = []
        for pid in sorted(c for c in candidates if c):
            prov = self._provider(pid)
            name = self._name(prov, pid)
            spec = getattr(prov, "quota", None)
            scope = self._scope(prov, spec, "egress")
            until = self._signal_until(pid, scope, now)
            usage = self.usage(pid) if spec is not None else {}
            if until is not None:
                text = f"{name}: quota exhausted (provider signal) until {until:%Y-%m-%d %H:%M} UTC"
            elif usage:
                window, info = max(usage.items(), key=lambda kv: (kv[1]["used"] / max(1, kv[1]["budget"]), -WINDOWS.index(kv[0])))
                text = f"{name}: {info['used']}/{info['budget']} {_WINDOW_LABEL[window]}"
            else:  # no quota block, or a block with a rate only (no window to report)
                text = name
            count = deferred.get(pid, 0)
            if count:
                text += f", {count} lookup{'s' if count != 1 else ''} deferred"
            lines.append((name.lower(), text))
        return [text for _key, text in sorted(lines)]

    def provider_summary(self) -> dict[str, dict[str, Any]]:
        """{provider: {window: {used, budget}}, 'signal_until': ISO|''} for providers with a quota
        block or an active signal (doctor)."""
        now = self._now()
        reg = self._registry()
        out: dict[str, dict[str, Any]] = {}
        try:
            provs = list(reg.providers()) if reg is not None else []
        except Exception:  # pragma: no cover
            provs = []
        for prov in provs:
            spec = getattr(prov, "quota", None)
            until = self._signal_until(prov.id, self._scope(prov, spec, "egress"), now)
            if spec is None and until is None:
                continue
            entry: dict[str, Any] = dict(self.usage(prov.id))
            entry["signal_until"] = until.isoformat(timespec="seconds") if until else ""
            out[prov.id] = entry
        return out
