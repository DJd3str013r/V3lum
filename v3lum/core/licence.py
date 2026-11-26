"""Licence profile and legal allow-list (A1, P377): which registry sources may run, and on what basis.

Every registry source carries a terms class (``providers.<pid>.sources.<sid>.terms.class``):
``open`` < ``key-terms`` < ``license`` < ``noncommercial`` < ``unknown``. The licence profile
(setting ``licence_profile``, per run ``ScanOptions.licence_profile``) decides which of them run:

* ``corporate`` (default, the only profile usable without a recorded legal basis):
  ``open`` runs; ``key-terms`` runs only when the source's ``free_plan_business_use`` is true or the
  module's key has the plan ``business`` (setting ``key_plans``, ``v3lum keys set <name> --plan
  business``); ``noncommercial`` and ``license`` run only through an active licence_allow entry;
  ``unknown`` never runs.
* ``research``: selectable only when the allow-list file records a ``research_basis`` (a provider
  grant or written permission); it additionally covers the ``noncommercial``/``license`` sources
  named by the basis scope. ``unknown`` sources stay disabled in every profile.

The allow-list is a legal-maintained JSON file (setting ``licence_allow_path``, default
``~/.v3lum/licence_allow.json``, 0600; it may point to a team-shared read-only file)::

    {
      "schema": "v3lum.licence_allow/1",
      "entries": [
        {"source_id": "sans_isc.api", "basis": "terms_clause",
         "scope": "own-network defence only, no resale", "legal_ref": "LEGAL-2026-014",
         "approver": "legal (DPO office)", "decided_at": "2026-11-26", "review_by": "2027-05-26",
         "evidence_url": "https://isc.sans.edu/api/", "quote": "ok to use this data ... to protect your own network"}
      ],
      "research_basis": {"legal_ref": "LEGAL-2026-020", "approver": "legal", "date": "2026-11-26",
                         "scope": ["shodan.internetdb", "abusech"]}
    }

Fail closed everywhere: an entry is active only while ``decided_at <= today <= review_by`` and
``review_by`` is at most 12 months after ``decided_at``; malformed entries (dates included: only
``YYYY-MM-DD`` or a full ISO date-time) are dropped (listed in ``errors``); a file writable by other
users is ignored (anyone could have added entries). The research basis follows the same 12-month
review rule (``review_by`` optional, default ``date + 12 months``) and covers only the source ids
(``pid.sid``), provider ids (``pid.*``, or a bare ``pid`` that is a registered provider) or ``*``
listed in its scope. A scope with any other word is prose and covers nothing: 'research on all
phishing kits' or 'everything except shodan' never unlock a source.

Enforcement lives only in ``v3lum.core.policy`` (rule POL-04); this module evaluates single sources:
``evaluate_source()`` (verdict with the licence basis recorded in the case) and the thin
``source_allowed()`` wrapper ``(allowed, reason)``.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import stat
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from v3lum import paths

__all__ = [
    "ALLOW_BASES",
    "AllowEntry",
    "LICENCE_ALLOW_FILE",
    "LICENCE_ALLOW_SCHEMA",
    "LicenceError",
    "LicenceState",
    "PROFILES",
    "RESEARCH_REFUSAL",
    "REVIEW_MONTHS",
    "ResearchBasis",
    "SourceVerdict",
    "add_months",
    "evaluate_source",
    "key_plan_lookup",
    "resolve_profile",
    "source_allowed",
]

#: Licence profiles (A1): corporate is the default and the only one usable without a legal basis.
PROFILES: tuple[str, ...] = ("corporate", "research")
#: Allowed values of AllowEntry.basis.
ALLOW_BASES: tuple[str, ...] = ("licence", "provider_grant", "terms_clause")
#: Maximum months between decided_at and review_by (A1 BR5).
REVIEW_MONTHS = 12
LICENCE_ALLOW_SCHEMA = "v3lum.licence_allow/1"
LICENCE_ALLOW_FILE = "licence_allow.json"
#: The refusal the CLI prints when research is asked for without a recorded legal basis (A1 BR4).
RESEARCH_REFUSAL = "licence_profile=research needs a recorded legal basis (docs/LEGAL.md)"

#: Terms classes, least to most restrictive (same table as providers.TERMS_ORDER).
_TERMS = ("open", "key-terms", "license", "noncommercial", "unknown")
_SOURCE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}\.[a-z][a-z0-9_]{0,63}$")
#: research-basis scope tokens: '*', 'pid', 'pid.*' or 'pid.sid' ('all' is a word, never a wildcard).
_SCOPE_TOKEN_RE = re.compile(r"^(?:\*|[a-z][a-z0-9_]{1,63}(?:\.(?:\*|[a-z][a-z0-9_]{0,63}))?)$")
_DATE_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_ENTRY_KEYS = frozenset({"source_id", "basis", "scope", "legal_ref", "approver", "decided_at", "review_by", "evidence_url", "quote", "notes"})
_RESEARCH_KEYS = frozenset({"legal_ref", "approver", "date", "scope", "review_by", "notes"})


class LicenceError(ValueError):
    """The requested licence profile cannot be used (e.g. research without a recorded legal basis)."""


# --------------------------------------------------------------------------------------
# dates
# --------------------------------------------------------------------------------------


def add_months(day: _dt.date, months: int) -> _dt.date:
    """``day`` plus ``months`` calendar months, clamped to the month end (2028-02-29 + 12 -> 2029-02-28)."""
    index = day.year * 12 + (day.month - 1) + int(months)
    year, month = divmod(index, 12)
    month += 1
    for candidate in (day.day, 30, 29, 28):
        try:
            return _dt.date(year, month, min(day.day, candidate))
        except ValueError:
            continue
    raise ValueError(f"cannot add {months} months to {day}")  # pragma: no cover - unreachable


def _parse_date(value: Any) -> _dt.date | None:
    """A calendar date from exactly 'YYYY-MM-DD' or a full ISO date-time ('2026-11-26T10:00:00Z' keeps
    its date part); None for anything else ('2026-11-26garbage' is invalid, not 2026-11-26)."""
    if isinstance(value, _dt.datetime):
        return value.date()
    if isinstance(value, _dt.date):
        return value
    text = str(value or "").strip()
    if _DATE_ONLY_RE.match(text):
        try:
            return _dt.date.fromisoformat(text)
        except ValueError:
            return None
    if len(text) > 10 and text[10] in "Tt " and _DATE_ONLY_RE.match(text[:10]):
        try:
            return _dt.datetime.fromisoformat(text[:-1] + "+00:00" if text[-1] in "Zz" else text).date()
        except ValueError:
            return None
    return None


def _today(now: Any = None) -> _dt.date:
    if now is None:
        return _dt.datetime.now(_dt.timezone.utc).date()
    if isinstance(now, _dt.datetime):
        if now.tzinfo is not None:
            now = now.astimezone(_dt.timezone.utc)
        return now.date()
    if isinstance(now, _dt.date):
        return now
    parsed = _parse_date(now)
    if parsed is None:
        raise ValueError(f"invalid date/time {now!r}")
    return parsed


def _registered_provider(pid: str) -> bool:
    """Is ``pid`` a provider of the live registry? (a registry problem never widens a scope)"""
    try:
        from v3lum.core import providers as _providers

        return _providers.registry().get(pid) is not None
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------------------
# entries
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class AllowEntry:
    """One legal decision allowing a ``noncommercial``/``license`` source (A1 BR5).

    ``basis``: 'licence' (a bought licence/subscription), 'provider_grant' (written permission of
    the provider) or 'terms_clause' (a clause of the published terms, e.g. SANS ISC 'protect your
    own network'). ``scope`` states the limits of use in words ('own-network defence only, no
    resale'). Dates are 'YYYY-MM-DD'.
    """

    source_id: str
    basis: str
    scope: str
    legal_ref: str
    approver: str
    decided_at: str
    review_by: str
    evidence_url: str = ""
    quote: str = ""

    @property
    def decided_date(self) -> _dt.date | None:
        return _parse_date(self.decided_at)

    @property
    def review_date(self) -> _dt.date | None:
        return _parse_date(self.review_by)

    @property
    def review_cap(self) -> _dt.date | None:
        """The latest allowed review_by: decided_at + 12 months."""
        decided = self.decided_date
        return add_months(decided, REVIEW_MONTHS) if decided else None

    @property
    def within_cap(self) -> bool:
        """review_by is set, not before decided_at and at most 12 months after it."""
        decided, review, cap = self.decided_date, self.review_date, self.review_cap
        return bool(decided and review and cap and decided <= review <= cap)

    def is_active(self, now: Any = None) -> bool:
        """Active on ``now``'s date: decided_at <= today <= review_by <= decided_at + 12 months."""
        if not self.within_cap:
            return False
        today = _today(now)
        return bool(self.decided_date and self.review_date and self.decided_date <= today <= self.review_date)

    def to_dict(self) -> dict[str, str]:
        return {
            "source_id": self.source_id,
            "basis": self.basis,
            "scope": self.scope,
            "legal_ref": self.legal_ref,
            "approver": self.approver,
            "decided_at": self.decided_at,
            "review_by": self.review_by,
            "evidence_url": self.evidence_url,
            "quote": self.quote,
        }


@dataclass(frozen=True)
class ResearchBasis:
    """The recorded legal basis that unlocks the research profile (A1 BR4).

    ``scope`` names what it covers: registry source ids ('shodan.internetdb'), provider ids
    ('abusech.*', or a bare 'abusech' that is a registered provider) or '*' (every
    noncommercial/license source), as a list or a comma/space separated string. A scope holding
    any other word is prose and covers nothing (fail closed): 'research on all phishing kits' does
    not mean '*', and 'everything except shodan' does not cover shodan. ``review_by`` is optional
    and defaults to ``date + 12 months``.
    """

    legal_ref: str
    approver: str
    date: str
    scope: str = ""
    review_by: str = ""

    @property
    def decided_date(self) -> _dt.date | None:
        return _parse_date(self.date)

    @property
    def review_date(self) -> _dt.date | None:
        """review_by, or date + 12 months when not given."""
        decided = self.decided_date
        if self.review_by:
            return _parse_date(self.review_by)
        return add_months(decided, REVIEW_MONTHS) if decided else None

    @property
    def targets(self) -> frozenset[str]:
        """The source/provider ids the scope names ('*', 'pid.sid', 'pid.*' or a registered 'pid').

        Empty when the scope is prose: one word that is neither such an id nor a registered provider
        voids the whole scope (an exclusion such as 'except shodan' must never read as an inclusion).
        """
        out: set[str] = set()
        for token in re.split(r"[\s,;]+", str(self.scope or "").strip().lower()):
            if not token:
                continue
            if token != "*" and (not _SCOPE_TOKEN_RE.match(token) or ("." not in token and not _registered_provider(token))):
                return frozenset()
            out.add(token)
        return frozenset(out)

    def is_active(self, now: Any = None) -> bool:
        """Recorded completely and inside its review window (at most 12 months after its date)."""
        decided, review = self.decided_date, self.review_date
        if not (self.legal_ref.strip() and self.approver.strip() and decided and review):
            return False
        if review < decided or review > add_months(decided, REVIEW_MONTHS):
            return False
        return decided <= _today(now) <= review

    def covers(self, source_id: str) -> bool:
        """Does the scope name this source (exactly, through its provider, or with '*')?"""
        targets = self.targets
        if "*" in targets:
            return True
        pid = source_id.split(".", 1)[0]
        return source_id in targets or pid in targets or f"{pid}.*" in targets

    def to_dict(self) -> dict[str, str]:
        out = {"legal_ref": self.legal_ref, "approver": self.approver, "date": self.date, "scope": self.scope}
        if self.review_by:
            out["review_by"] = self.review_by
        return out


# --------------------------------------------------------------------------------------
# the allow-list state
# --------------------------------------------------------------------------------------


def _access_problem(path: Path) -> tuple[str, bool]:
    """(warning, untrusted) for the file mode: world/group-writable files are untrusted (fail closed);
    other access by group/world is a warning for the copy in the V3LUM home (0600 expected)."""
    if os.name != "posix":  # pragma: no cover - POSIX modes only
        return "", False
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return "", False
    if mode & 0o002:
        return f"{path.name} is writable by every user (mode {mode:04o}): its entries are ignored until it is chmod 600 (A1)", True
    try:
        in_home = path.resolve().is_relative_to(paths.home().resolve())
    except (OSError, ValueError):
        in_home = False
    if in_home and mode & 0o020:
        return f"{path.name} is writable by the group (mode {mode:04o}): its entries are ignored until it is chmod 600 (A1)", True
    if in_home and mode & 0o077:
        return f"{path.name} is looser than 0600 (mode {mode:04o}): chmod 600 (A10)", False
    return "", False


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v).strip() for v in value if str(v).strip())
    return str(value).strip()


def _parse_entry(item: Any, where: str, errors: list[str]) -> AllowEntry | None:
    if not isinstance(item, Mapping):
        errors.append(f"{where}: an entry must be an object")
        return None
    unknown = sorted(set(item) - _ENTRY_KEYS)
    if unknown:
        errors.append(f"{where}: unknown keys {unknown}")
    problems: list[str] = []
    source_id = _text(item.get("source_id")).lower()
    if not _SOURCE_ID_RE.match(source_id):
        problems.append("source_id must be a registry source id 'provider.source'")
    basis = _text(item.get("basis"))
    if basis not in ALLOW_BASES:
        problems.append(f"basis must be one of {', '.join(ALLOW_BASES)}")
    for name in ("scope", "legal_ref", "approver"):
        if not _text(item.get(name)):
            problems.append(f"{name} is required")
    decided, review = _parse_date(item.get("decided_at")), _parse_date(item.get("review_by"))
    if decided is None:
        problems.append("decided_at must be a date YYYY-MM-DD")
    if review is None:
        problems.append("review_by must be a date YYYY-MM-DD")
    if problems:
        errors.append(f"{where} ({source_id or '?'}): entry dropped: " + "; ".join(problems))
        return None
    entry = AllowEntry(
        source_id=source_id,
        basis=basis,
        scope=_text(item.get("scope")),
        legal_ref=_text(item.get("legal_ref")),
        approver=_text(item.get("approver")),
        decided_at=decided.isoformat(),  # type: ignore[union-attr]
        review_by=review.isoformat(),  # type: ignore[union-attr]
        evidence_url=_text(item.get("evidence_url")),
        quote=_text(item.get("quote")),
    )
    if not entry.within_cap:
        errors.append(
            f"{where} ({source_id}): review_by {entry.review_by} must fall between decided_at {entry.decided_at} and "
            f"{entry.review_cap} (at most {REVIEW_MONTHS} months): the entry is never active"
        )
    if not entry.evidence_url or not entry.quote:
        errors.append(f"{where} ({source_id}): evidence_url and quote should record the terms evidence")
    return entry


def _parse_research(item: Any, errors: list[str]) -> ResearchBasis | None:
    if item is None or item == {}:
        return None
    if not isinstance(item, Mapping):
        errors.append("research_basis: must be an object {legal_ref, approver, date, scope}")
        return None
    unknown = sorted(set(item) - _RESEARCH_KEYS)
    if unknown:
        errors.append(f"research_basis: unknown keys {unknown}")
    decided, review = _parse_date(item.get("date")), _parse_date(item.get("review_by"))
    if item.get("review_by") and review is None:
        errors.append("research_basis: review_by must be a date YYYY-MM-DD")
    basis = ResearchBasis(
        legal_ref=_text(item.get("legal_ref")),
        approver=_text(item.get("approver")),
        date=decided.isoformat() if decided else "",
        scope=_text(item.get("scope")),
        # an unreadable review_by stays as written: the basis is then never active (it must not
        # silently become the 12-month default)
        review_by=review.isoformat() if review else _text(item.get("review_by")),
    )
    missing = [n for n in ("legal_ref", "approver", "date") if not getattr(basis, n)]
    if missing:
        errors.append(f"research_basis: {', '.join(missing)} missing or invalid: the research profile stays unavailable")
    elif not basis.targets:
        errors.append(
            "research_basis: the scope must list only source ids ('pid.sid'), provider ids ('pid.*' or a registered 'pid') "
            "or '*' (every noncommercial/license source); prose covers nothing"
        )
    return basis


@dataclass
class LicenceState:
    """The loaded licence_allow file: allow entries, the research basis and load problems.

    ``warnings`` are file-mode problems (doctor shows them); ``errors`` are schema problems (dropped
    entries, review dates beyond the 12-month cap). Build it with :meth:`load` or :meth:`from_dict`.
    """

    entries: tuple[AllowEntry, ...] = ()
    research_basis: ResearchBasis | None = None
    path: str = ""
    sha256: str = ""
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # ---- construction -------------------------------------------------------------------------
    @classmethod
    def empty(cls, path: str = "") -> LicenceState:
        """No allow entries and no research basis (nothing licence-restricted runs)."""
        return cls(path=str(path))

    @staticmethod
    def configured_path(config: Any = None) -> str:
        """The value of setting ``licence_allow_path`` ('' when unset)."""
        getter = getattr(config, "get", None)
        return str(getter("licence_allow_path", "") or "").strip() if callable(getter) else ""

    @classmethod
    def default_path(cls, config: Any = None) -> Path:
        """Setting ``licence_allow_path`` ('' = ~/.v3lum/licence_allow.json)."""
        configured = cls.configured_path(config)
        if configured:
            return Path(configured).expanduser()
        return paths.home() / LICENCE_ALLOW_FILE

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None, *, config: Any = None) -> LicenceState:
        """Load the allow-list (``path``, else setting ``licence_allow_path``, else the home default).

        A missing file gives an empty state (with a warning when the path was given or configured);
        unreadable or invalid JSON gives an empty state with an error; a file writable by other users
        gives an empty state with a warning (fail closed). Never raises.
        """
        if not path and config is None:
            try:  # honour setting licence_allow_path when the caller passes no config
                from v3lum.config import Config

                config = Config.load()
            except Exception:  # noqa: BLE001 - an unreadable config falls back to the home default
                config = None
        explicit = bool(path) or bool(cls.configured_path(config))
        p = Path(path).expanduser() if path else cls.default_path(config)
        if not p.is_file():
            state = cls.empty(str(p))
            if explicit:
                state.warnings.append(f"licence_allow file {str(p)[:200]!r} is not a readable file: no allow entries are active")
            return state
        try:
            raw = p.read_bytes()
        except OSError as exc:
            state = cls.empty(str(p))
            state.errors.append(f"cannot read {p.name}: {exc}")
            return state
        warning, untrusted = _access_problem(p)
        sha = hashlib.sha256(raw).hexdigest()
        if untrusted:
            state = cls(path=str(p), sha256=sha)
            state.warnings.append(warning)
            return state
        try:
            data = json.loads(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, ValueError) as exc:
            state = cls(path=str(p), sha256=sha)
            state.errors.append(f"invalid JSON in {p.name}: {exc}")
            return state
        state = cls.from_dict(data, path=str(p), sha256=sha)
        if warning:
            state.warnings.append(warning)
        return state

    @classmethod
    def from_dict(cls, data: Any, *, path: str = "", sha256: str = "") -> LicenceState:
        """Validate parsed allow-list data (an object with 'entries'/'research_basis', or a bare entry list)."""
        errors: list[str] = []
        if isinstance(data, list):
            data = {"entries": data}
        if data is None:
            data = {}
        if not isinstance(data, Mapping):
            state = cls(path=path, sha256=sha256)
            state.errors.append("the licence_allow file must be an object {schema, entries, research_basis}")
            return state
        schema = data.get("schema")
        if schema not in (None, LICENCE_ALLOW_SCHEMA):
            errors.append(f"schema must be {LICENCE_ALLOW_SCHEMA!r} (got {schema!r})")
        unknown = sorted(set(data) - {"schema", "entries", "research_basis", "notes"})
        if unknown:
            errors.append(f"unknown top-level keys {unknown}")
        raw_entries = data.get("entries") or []
        if not isinstance(raw_entries, list):
            errors.append("entries must be a list")
            raw_entries = []
        entries = [e for i, item in enumerate(raw_entries) if (e := _parse_entry(item, f"entries[{i}]", errors)) is not None]
        research = _parse_research(data.get("research_basis"), errors)
        if not sha256:
            sha256 = hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        return cls(entries=tuple(entries), research_basis=research, path=path, sha256=sha256, errors=errors)

    # ---- queries ------------------------------------------------------------------------------
    def entries_for(self, source_id: str) -> list[AllowEntry]:
        """Every entry recorded for a source (active or not)."""
        return [e for e in self.entries if e.source_id == source_id]

    def entry_for(self, source_id: str, now: Any = None) -> AllowEntry | None:
        """The active entry with the latest review_by for a source, or None."""
        active = [e for e in self.entries_for(source_id) if e.is_active(now)]
        return max(active, key=lambda e: e.review_by) if active else None

    def active(self, source_id: str, now: Any = None) -> bool:
        """Is there an active entry for the source? (fail closed: decided_at <= today <= review_by,
        review_by at most 12 months after decided_at)."""
        return self.entry_for(source_id, now) is not None

    def active_entries(self, now: Any = None) -> list[AllowEntry]:
        """Every active entry (``v3lum info`` and the report coverage section show them)."""
        return [e for e in self.entries if e.is_active(now)]

    def expiring(self, now: Any = None, days: int = 30) -> list[AllowEntry]:
        """Active entries whose review_by falls within ``days`` (doctor warns 30 days ahead)."""
        today = _today(now)
        horizon = today + _dt.timedelta(days=int(days))
        return sorted(
            (e for e in self.entries if e.is_active(now) and e.review_date is not None and e.review_date <= horizon),
            key=lambda e: (e.review_by, e.source_id),
        )

    def expired(self, now: Any = None) -> list[AllowEntry]:
        """Entries that are not active on ``now`` (past review_by, beyond the 12-month cap or not yet decided)."""
        return [e for e in self.entries if not e.is_active(now)]

    def research_allowed(self, now: Any = None) -> bool:
        """Is a complete, unexpired research basis recorded? (the research profile needs one)."""
        return self.research_basis is not None and self.research_basis.is_active(now)

    def research_covers(self, source_id: str, now: Any = None) -> bool:
        """Does the active research basis cover the source?"""
        return self.research_allowed(now) and self.research_basis is not None and self.research_basis.covers(source_id)

    def source_allowed(
        self, source: Any, provider: Any = None, *, key_plan: Any = None, profile: str = "corporate", now: Any = None, keys: Iterable[str] = (), module_keys_only: bool = False
    ) -> tuple[bool, str]:
        """``source_allowed()`` evaluated against this allow-list."""
        return source_allowed(source, provider, key_plan=key_plan, profile=profile, now=now, state=self, keys=keys, module_keys_only=module_keys_only)


# --------------------------------------------------------------------------------------
# profile resolution and per-source evaluation
# --------------------------------------------------------------------------------------


def resolve_profile(config: Any = None, options: Any = None, *, state: LicenceState | None = None, now: Any = None) -> str:
    """The licence profile of a run: ``options.licence_profile``, else setting ``licence_profile``,
    else 'corporate'. Raises LicenceError for an unknown profile and for 'research' without an
    active research basis ('licence_profile=research needs a recorded legal basis (docs/LEGAL.md)').
    """
    requested = str(getattr(options, "licence_profile", "") or "").strip().lower()
    if not requested:
        getter = getattr(config, "get", None)
        requested = str(getter("licence_profile", "corporate") if callable(getter) else "corporate").strip().lower() or "corporate"
    if requested not in PROFILES:
        raise LicenceError(f"unknown licence profile {requested!r} (expected {' or '.join(PROFILES)})")
    if requested == "research":
        state = state if state is not None else LicenceState.load(config=config)
        if not state.research_allowed(now):
            raise LicenceError(RESEARCH_REFUSAL)
    return requested


@dataclass(frozen=True)
class SourceVerdict:
    """Outcome of one source under a licence profile.

    ``basis`` (allowed sources only): 'open' | 'business_plan:<key>' | 'allow:<legal_ref>' |
    'research:<legal_ref>' - copied into the case ('licence_used') for the report licence banner.
    ``reason`` is readable ('skipped: noncommercial terms (licence profile corporate)' when blocked);
    ``remedy`` says how the source could be cleared.
    """

    source_id: str
    terms_class: str
    allowed: bool
    basis: str = ""
    reason: str = ""
    remedy: str = ""


def _plan_for(key_plan: Any, name: str) -> str:
    if key_plan is None:
        return ""
    if isinstance(key_plan, str):
        return key_plan.strip().lower()
    if isinstance(key_plan, Mapping):
        return str(key_plan.get(name, "") or "").strip().lower()
    if callable(key_plan):
        try:
            return str(key_plan(name) or "").strip().lower()
        except Exception:  # noqa: BLE001 - a broken plan lookup never unlocks a source
            return ""
    return ""


def _candidate_keys(source: Any, provider: Any, keys: Iterable[str], *, module_keys_only: bool = False) -> list[str]:
    """The key names whose plan decides a key-terms source.

    The keys of ``keys`` that belong to the source's provider (declared by its fragment or recorded
    with that provider in the key registry); for a provider that declares no key, the legacy keys
    of ``keys`` that have no recorded provider. Without such a key: every key the provider declares
    - unless ``module_keys_only`` (a module's request to that provider then carries none of them:
    it is keyless use, which only ``free_plan_business_use`` can allow).
    """
    pid = str(getattr(source, "provider", "") or getattr(provider, "id", "") or "")
    declared = list(getattr(provider, "keys", {}) or {})
    keys = [str(k) for k in keys]
    owned = [k for k in keys if k in declared or (pid and _key_provider(k) == pid)]
    if owned:
        return owned
    legacy = [] if declared else [k for k in keys if not _key_provider(k)]
    if legacy:
        return legacy
    return [] if module_keys_only else declared


def _key_provider(name: str) -> str:
    try:
        from v3lum import config as _config

        spec = _config.key_registry().get(name)
    except Exception:  # noqa: BLE001 - registry problems never unlock a source
        return ""
    return str(getattr(spec, "provider", "") or "")


def evaluate_source(
    source: Any,
    provider: Any = None,
    *,
    profile: str = "corporate",
    now: Any = None,
    state: LicenceState | None = None,
    key_plan: Any = None,
    keys: Iterable[str] = (),
    source_id: str = "",
    module_keys_only: bool = False,
) -> SourceVerdict:
    """Evaluate one registry source (``providers.Source``; None = unregistered -> 'unknown').

    ``key_plan`` is a plan string ('business' | 'free'), a mapping key name -> plan or a callable
    ``(key_name) -> plan`` (``Config.key_plan``); ``keys`` are the module's key names (the plan of
    one of them must be 'business' for a key-terms source). ``module_keys_only`` (the policy gate):
    only ``keys`` can carry a business plan - when none of them belongs to the source's provider the
    module's requests are keyless and the provider's other keys do not count. ``state`` None means
    no allow entries and no research basis (fail closed).
    """
    sid = str(getattr(source, "id", "") or source_id or "?")
    terms = getattr(source, "terms", None)
    cls = str(getattr(terms, "class_", "") or "unknown") if source is not None else "unknown"
    if cls not in _TERMS:
        cls = "unknown"
    profile = (profile or "corporate").strip().lower()
    if profile not in PROFILES:
        profile = "corporate"
    blocked = f"skipped: {cls} terms (licence profile {profile})"
    if cls == "open":
        return SourceVerdict(sid, cls, True, "open", "allowed: open terms")
    if cls == "unknown":
        return SourceVerdict(sid, cls, False, reason=blocked, remedy="terms not reviewed: legal records a class in the provider registry (doctor --licences review queue)")
    if cls == "key-terms":
        if getattr(terms, "free_plan_business_use", None) is True:
            return SourceVerdict(sid, cls, True, "open", "allowed: key-terms source whose free plan allows business use")
        candidates = _candidate_keys(source, provider, keys, module_keys_only=module_keys_only)
        for name in candidates:
            if _plan_for(key_plan, name) == "business":
                return SourceVerdict(sid, cls, True, f"business_plan:{name}", f"allowed: key {name!r} recorded with a business plan")
        hint = candidates[0] if candidates else (next(iter(getattr(provider, "keys", {}) or {}), "") or "<key>")
        return SourceVerdict(sid, cls, False, reason=blocked, remedy=f"record a business plan: v3lum keys set {hint} --plan business")
    # license / noncommercial
    state = state or LicenceState.empty()
    entry = state.entry_for(sid, now)
    if entry is not None:
        return SourceVerdict(sid, cls, True, f"allow:{entry.legal_ref}", f"allowed: licence_allow {entry.legal_ref} (review by {entry.review_by})")
    if profile == "research" and state.research_covers(sid, now):
        basis = state.research_basis
        ref = basis.legal_ref if basis is not None else "?"
        return SourceVerdict(sid, cls, True, f"research:{ref}", f"allowed: research basis {ref}")
    alternative = str(getattr(source, "licensed_alternative", "") or "")
    remedy = alternative or "a licence or written permission recorded as a licence_allow entry (docs/LEGAL.md)"
    if profile == "research" and state.research_allowed(now):
        blocked += " - outside the research basis scope"
    return SourceVerdict(sid, cls, False, reason=blocked, remedy=remedy)


def source_allowed(
    source: Any,
    provider: Any = None,
    *,
    key_plan: Any = None,
    profile: str = "corporate",
    now: Any = None,
    state: LicenceState | None = None,
    keys: Iterable[str] = (),
    module_keys_only: bool = False,
) -> tuple[bool, str]:
    """(allowed, reason) for one source under a profile (see :func:`evaluate_source`)."""
    verdict = evaluate_source(source, provider, profile=profile, now=now, state=state, key_plan=key_plan, keys=keys, module_keys_only=module_keys_only)
    return verdict.allowed, verdict.reason


def key_plan_lookup(config: Any) -> Callable[[str], str]:
    """A ``(key_name) -> plan`` callable over a Config (``Config.key_plan``) or a key_plans mapping."""
    method = getattr(config, "key_plan", None)
    if callable(method):
        return method
    getter = getattr(config, "get", None)
    plans = getter("key_plans") if callable(getter) else None
    plans = plans if isinstance(plans, Mapping) else {}
    return lambda name: str(plans.get(name, "") or "")
