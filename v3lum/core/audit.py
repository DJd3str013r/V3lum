"""Case audit trail, hash-chained request ledger, the engine audit hook and ``cases verify`` (P324).

* :class:`CaseAudit` - ``CaseAudit(store, case_id, case_dir=None, *, now=None).append(kind,
  payload)`` writes one hash-chained row to the case DB's ``audit`` table through
  :meth:`v3lum.core.store.Store.append_audit` (``hash = sha256(prev_hash + canonical_json({case_id,
  seq, ts, kind, payload}))``, first ``prev_hash`` 64 zeros, ``seq`` from 1, ``ts`` UTC) and mirrors
  it byte for byte to ``<case_dir>/audit.jsonl`` (0600). Rows the store wrote without a mirror
  (``cases hold``/``unhold``) are mirrored before the next row. Payloads are metadata (no bodies,
  no secrets: every string passes the central redactor, AR01). Kinds: :data:`AUDIT_KINDS`.
* :class:`RequestLedger` - ``RequestLedger(case_dir).append(info)`` appends one hash-chained JSON
  line per LIGHT/ACTIVE request or connection to ``<case_dir>/ledger.jsonl`` (0600): UTC time,
  module, method, host, resolved IP, port, redacted path (secrets, query values and
  identifier-like path segments masked), status, bytes, egress profile, opsec. It is written
  whatever ``--no-evidence`` says (A7 BR13) and is the file the A10 purge keeps for
  ``audit_retention_days`` (:data:`v3lum.core.store.ENGAGEMENT_AUDIT_FILES`).
* :class:`AuditHook` - ``AuditHook(store, *, analyst=None, runtime=None)``, installed with
  ``hook.attach(runtime)`` (``runtime.case_hooks`` + the ``http_request`` events). ``on_case_start``
  writes the ``case_start`` row (purpose, legal basis, ticket, analyst, OS user, mode,
  authorization reference, scope SHA-256, window, egress profile with its last known public IP,
  TLP and TLP lowering, overrides, org profile SHA-256, licence profile, pseudonymised targets) and
  fails closed (an audit that cannot be written aborts the scan). Every LIGHT/ACTIVE request or
  CONNECT/EXEC record reaches the ledger as it happens (a ledger that cannot be written stops target
  contact). ``on_case_end`` completes the ledger from the run logs, writes one ``policy_violation``
  row per run that ended SKIPPED 'policy' after an undeclared-host or disclosure violation (P327
  cond 5, A8 BR9), records the evidence versions in the case DB, sets ``case['engagement']`` (mode,
  authorization reference, scope SHA-256, window, egress, egress override, targets touched, request
  count, out-of-scope refusals) for LIGHT/ACTIVE cases and ``case['since_last_run']`` (new /
  resolved findings) on a re-collection - also as a report header line in
  ``case.meta['header_notes']`` (P324 cond 8) - and writes the ``case_end`` row with the counts and
  the heads of the ledger and the evidence index (the anchors :func:`verify_case` checks); the head
  of the audit chain at that row goes to ``case.meta['audit']`` (:data:`STORED_ANCHOR_KEY`), so the
  stored case anchors the audit itself.
* :func:`verify_case` - ``verify_case(store, case_id) -> VerifyReport(ok, problems)``: recomputes,
  offline, every evidence hash (files vs the evidence index vs ``evidence_versions``, metadata
  columns included), every report hash (``report_hashes`` and ``<report>.sha256`` sidecars), the
  audit chain (byte for byte, DB and mirror) and the ledger chain, against the anchors of the last
  ``case_end`` row and of the stored case (audit head, engagement ledger head): rows or lines removed
  from the end of every chain at once are detected. A purged case (value-free tombstone, its minimal
  engagement audit re-sealed and closed by a ``purge`` row) verifies what is left.
"""

from __future__ import annotations

import copy
import datetime as _dt
import getpass
import json
import logging
import os
import re
import threading
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from v3lum import __version__, paths
from v3lum.core.evidence import (
    CHAIN_GENESIS,
    EVIDENCE_INDEX,
    ChainCheck,
    ChainedLog,
    append_new_lines,
    canonical_json,
    json_safe,
    sha256_file,
    sync_versions,
    verify_chain,
    verify_evidence,
)
from v3lum.core.store import AUDIT_GENESIS, ENGAGEMENT_MODES, PURGE_AUDIT_KIND, audit_hash

log = logging.getLogger("v3lum.audit")

__all__ = [
    "AUDIT_KINDS",
    "AUDIT_MIRROR",
    "CASE_END_MISSING_NOTE",
    "CONTACT_OPSEC",
    "EGRESS_CHECK_FILE",
    "LEDGER_FILE",
    "LIFTED_KEYS",
    "REFUSAL_CODES",
    "STORED_ANCHOR_KEY",
    "STORE_NATIVE_KINDS",
    "AuditHook",
    "CaseAudit",
    "RequestLedger",
    "VerifyReport",
    "clean_payload",
    "engagement_of",
    "is_contact_request",
    "ledger_entry",
    "ledger_path",
    "mirror_audit",
    "since_last_run_line",
    "since_last_run_of",
    "verify_case",
]

#: Mirror of the case's audit rows at the top of the case directory (removed with the case).
AUDIT_MIRROR = "audit.jsonl"
#: The request ledger at the top of the case directory (kept until audit_retention_days).
LEDGER_FILE = "ledger.jsonl"
#: ``~/.v3lum/egress_check.json`` - ``{profile: {ip, checked_at}}`` written by ``doctor --egress``.
EGRESS_CHECK_FILE = "egress_check.json"
#: Audit row kinds (``purge`` rows are written by the store's purge routine).
AUDIT_KINDS: tuple[str, ...] = (
    "case_start", "case_end", "tlp_change", "profile_change", "hold", "unhold", "policy_violation", "override", PURGE_AUDIT_KIND,
)
#: Kinds the store writes itself (without the mirror): accepted at the end of the mirror's gap.
STORE_NATIVE_KINDS = frozenset({"hold", "unhold", PURGE_AUDIT_KIND})
#: Request opsec labels that make a request target contact (ledger lines).
CONTACT_OPSEC = frozenset({"light", "active"})
#: Coverage reason codes of LIGHT/ACTIVE modules listed as refusals in the engagement summary.
REFUSAL_CODES: tuple[str, ...] = ("scope", "hostile_host", "policy")
#: Case keys the hook adds (``to_dict()`` of the case carries them at the top level).
LIFTED_KEYS: tuple[str, ...] = ("engagement", "since_last_run")
#: ``case['meta'][STORED_ANCHOR_KEY]`` = ``{rows, head}``: the audit chain head at case end, kept in
#: the stored case so rows removed from the end of the chain are detected by :func:`verify_case`.
STORED_ANCHOR_KEY = "audit"
#: Start of the case note written when the ``case_end`` row could not be written.
CASE_END_MISSING_NOTE = "audit: case_end row not written"
#: Mask of redacted ledger path parts.
_MASK = "***"
#: Refusals listed in an engagement summary (the rest are counted).
_MAX_REFUSALS = 200
_HOST_VIOLATION = re.compile(r"host (\S+) is not declared in Module\.hosts")
_DISCLOSURE_VIOLATION = re.compile(
    r"offline module \(disclosure 'none'\)|raw sockets are only for target-contact|a PASSIVE module may not open sockets"
)
_TOKEN_SEGMENT = re.compile(r"^[A-Za-z0-9_.~-]{16,}$")
_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


# ======================================================================================
# helpers
# ======================================================================================


def _redact(text: Any) -> str:
    try:
        from v3lum.core import redact
    except ImportError:  # pragma: no cover
        return str(text or "")
    return str(redact.redact_text(str(text or "")))


def _redact_strings(value: Any) -> Any:
    if isinstance(value, str):
        return _redact(value)
    if isinstance(value, dict):
        return {k: _redact_strings(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_strings(v) for v in value]
    return value


def clean_payload(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    """An audit payload as stored: plain JSON data (:func:`v3lum.core.evidence.json_safe`) with every
    string passed through the central redactor (AR01: no configured key value in the audit)."""
    if payload is None:
        return {}
    if not isinstance(payload, Mapping):
        raise TypeError("an audit payload is a mapping")
    return _redact_strings(json_safe(dict(payload)))


def _iso(dt: _dt.datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc).isoformat(timespec="seconds")


def _get(obj: Any, name: str, default: Any = None) -> Any:
    """``obj.name`` or ``obj[name]`` (a CaseResult, a case dict, ScanOptions or its dict view)."""
    if obj is None:
        return default
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _opsec_label(value: Any) -> str:
    label = getattr(value, "label", None)
    if isinstance(label, str):
        return label.lower()
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return {0: "passive", 1: "light", 2: "active"}.get(value, "")
    return str(value or "").strip().lower()


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _os_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no user name (containers): recorded as unknown
        return "unknown"


def _as_mapping(info: Any) -> dict[str, Any] | None:
    if isinstance(info, Mapping):
        return dict(info)
    to_dict = getattr(info, "to_dict", None)
    if callable(to_dict):
        try:
            data = to_dict()
        except Exception:  # noqa: BLE001
            return None
        return dict(data) if isinstance(data, Mapping) else None
    return None


def _utc(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        dt = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc).isoformat()


def _pseudonymize(key: str) -> str:
    try:
        from v3lum.core import hmacid

        return str(hmacid.pseudonymize_key(str(key)))
    except Exception:  # noqa: BLE001 - fail closed: a value that cannot be pseudonymised is not written
        etype = str(key).partition(":")[0]
        return f"{etype}:#unavailable"


def _persisted_key(entity: Any) -> str:
    """An entity key as the case dict writes it (SECRET_TYPES values redacted)."""
    if isinstance(entity, str):
        return entity
    key = str(getattr(entity, "key", "") or "")
    try:
        from v3lum.core import entities as _entities

        if getattr(entity, "type", None) in _entities.SECRET_TYPES:
            return f"{entity.type.value}:{_entities.redacted_value(entity.type, entity.value)}"
    except Exception:  # noqa: BLE001 - never write a raw secret
        return f"{str(getattr(getattr(entity, 'type', None), 'value', 'secret'))}:[redacted]"
    return key


def is_contact_request(info: Any) -> bool:
    """True for a LIGHT/ACTIVE network send or connection (a ``RequestInfo`` or dict with opsec
    'light'/'active' that was not served from the cache): a line of the request ledger."""
    data = _as_mapping(info)
    if not data:
        return False
    if bool(data.get("from_cache", data.get("cached", False))):
        return False
    return _opsec_label(data.get("opsec")) in CONTACT_OPSEC


def ledger_path(path: Any) -> str:
    """The request path as the ledger keeps it (A10 'paths redacted'): configured secrets and
    key-like parameters masked (AR01), every query value masked (parameter names kept), and path
    segments that look like identifiers - an e-mail address, an opaque token of 16+ characters
    mixing letters and digits - masked. No fragment."""
    text = _redact(path)
    raw, _sep, query = text.partition("?")
    raw = raw.split("#", 1)[0]
    query = query.split("#", 1)[0]
    segments = []
    for seg in raw.split("/"):
        plain = unquote(seg)
        if "@" in plain or (_TOKEN_SEGMENT.match(plain) and any(c.isdigit() for c in plain) and any(c.isalpha() for c in plain)):
            segments.append(_MASK)
        else:
            segments.append(seg)
    out = "/".join(segments) or "/"
    if query:
        names = []
        for part in query.split("&"):
            name = part.split("=", 1)[0]
            if not name:
                continue
            plain = unquote(name)
            if "@" in plain or _TOKEN_SEGMENT.match(plain):
                name = _MASK
            names.append(f"{name}={_MASK}")
        if names:
            out += "?" + "&".join(names)
    return out


def _scope_facts(options: Any) -> tuple[str, dict[str, str] | None, str]:
    """``(scope_sha256, window {start, end} or None, authorization_ref)`` of the scan options (a
    loaded scope object, or the SHA-256 string of a stored case's options)."""
    scope = _get(options, "scope")
    sha = ""
    window: dict[str, str] | None = None
    if isinstance(scope, str):
        sha = scope
    elif scope is not None:
        sha = str(_get(scope, "sha256") or "")
        start, end = _get(scope, "window_start"), _get(scope, "window_end")
        if start or end:
            window = {
                "start": _iso(start) if isinstance(start, _dt.datetime) else str(start or ""),
                "end": _iso(end) if isinstance(end, _dt.datetime) else str(end or ""),
            }
    authorization = str(_get(options, "authorization_ref") or (_get(scope, "authorization_ref") if scope is not None and not isinstance(scope, str) else "") or "")
    return sha, window, authorization


def _default_port(scheme: str) -> int:
    return {"https": 443, "http": 80}.get(scheme.lower(), 0)


def ledger_entry(info: Any) -> dict[str, Any] | None:
    """The ledger fields of one request record (``RequestInfo`` or dict): ts (UTC), module, method,
    host, resolved_ip, port, path (:func:`ledger_path`; '' for CONNECT/EXEC records), status,
    bytes, egress_profile, opsec, error (and ``tool`` for EXEC records). None for anything else."""
    data = _as_mapping(info)
    if data is None:
        return None
    url = str(data.get("url") or "")
    try:
        parts = urlsplit(url)
    except ValueError:
        parts = urlsplit("")
    method = str(data.get("method") or "GET").upper()
    host = str(data.get("host") or parts.hostname or "").lower()
    port = _int(data.get("port"))
    if not port:
        try:
            port = parts.port or _default_port(parts.scheme or "")
        except ValueError:
            port = _default_port(parts.scheme or "")
    raw_path = data.get("path")
    if raw_path is None:
        raw_path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    entry: dict[str, Any] = {
        "ts": _utc(data.get("ts")) or _iso(_dt.datetime.now(_dt.timezone.utc)),
        "module": str(data.get("module") or ""),
        "method": method,
        "host": host,
        "resolved_ip": str(data.get("resolved_ip") or ""),
        "port": port,
        "path": "" if method in ("CONNECT", "EXEC") else ledger_path(raw_path),
        "status": _int(data.get("status")),
        "bytes": _int(data.get("bytes")),
        "egress_profile": str(data.get("egress_profile") or "default"),
        "opsec": _opsec_label(data.get("opsec")),
        "error": _redact(data.get("error") or "")[:160],
    }
    if method == "EXEC":
        entry["tool"] = _redact(parts.netloc or "")[:64]
    return entry


# ======================================================================================
# case audit
# ======================================================================================


def _row_record(row: Mapping[str, Any]) -> dict[str, Any]:
    return {k: row.get(k) for k in ("case_id", "seq", "ts", "kind", "payload", "prev_hash", "hash")}


def mirror_audit(store: Any, case_id: str, case_dir: str | os.PathLike[str]) -> int:
    """Append to ``<case_dir>/audit.jsonl`` the audit rows of ``case_id`` it does not hold yet
    (rows written by the store itself, such as ``cases hold``/``unhold``, or after a failed mirror
    write); returns the number of lines added."""
    rows = [(int(row["seq"]), canonical_json(_row_record(row))) for row in store.audit_rows(case_id)]
    return append_new_lines(Path(case_dir) / AUDIT_MIRROR, rows) if rows else 0


class CaseAudit:
    """The audit trail of one case (see the module docstring).

    ``CaseAudit(store, case_id, case_dir=None, *, now=None)``: ``case_dir`` None writes no mirror
    (e.g. the ``org-profile`` trail); ``now`` stamps the rows (default: the store's clock).
    """

    def __init__(self, store: Any, case_id: str, case_dir: str | os.PathLike[str] | None = None, *, now: Callable[[], _dt.datetime] | None = None) -> None:
        if not str(case_id or "").strip():
            raise ValueError("an audit trail needs a case id")
        self.store = store
        self.case_id = str(case_id)
        self.case_dir = Path(case_dir) if case_dir else None
        self._now = now

    @property
    def mirror_path(self) -> Path | None:
        """``<case_dir>/audit.jsonl`` (None without a case directory)."""
        return self.case_dir / AUDIT_MIRROR if self.case_dir is not None else None

    def _stamp(self) -> str | None:
        if self._now is None:
            return None
        try:
            now = self._now()
        except Exception:  # noqa: BLE001 - the store's clock stamps the row instead
            return None
        return _iso(now) if isinstance(now, _dt.datetime) else None

    def append(self, kind: str, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Append one row (``kind``, ``payload``) and mirror it; returns the row
        ``{case_id, seq, ts, kind, payload, prev_hash, hash}``. Raises when the row or its mirror
        cannot be written (an audit failure is never silent)."""
        name = str(kind or "").strip()
        if not name:
            raise ValueError("an audit row needs a kind")
        body = clean_payload(payload)
        with self.store.connection():  # the store lock: DB rows and mirror lines in the same order
            row = self.store.append_audit(self.case_id, name, body, ts=self._stamp())
            if self.case_dir is not None:
                # this row and any row the store wrote without a mirror (hold/unhold), in seq order,
                # each at most once (the file lock covers writers of other processes)
                mirror_audit(self.store, self.case_id, self.case_dir)
        return row

    def rows(self) -> list[dict[str, Any]]:
        """The audit rows of the case (payload parsed), in order."""
        return list(self.store.audit_rows(self.case_id))


# ======================================================================================
# request ledger
# ======================================================================================


class RequestLedger:
    """The hash-chained request ledger of one case: ``<case_dir>/ledger.jsonl`` (see the module
    docstring). ``append`` records whatever it is given; :meth:`wants` says what belongs there."""

    def __init__(self, case_dir: str | os.PathLike[str]) -> None:
        self.case_dir = Path(case_dir)
        self.path = self.case_dir / LEDGER_FILE
        self._log = ChainedLog(self.path)

    @staticmethod
    def wants(info: Any) -> bool:
        """True for a LIGHT/ACTIVE request or connection (:func:`is_contact_request`)."""
        return is_contact_request(info)

    def create(self) -> Path:
        """Create the (empty) ledger 0600 in a 0700 case directory when missing."""
        return self._log.create()

    def append(self, info: Any) -> dict[str, Any]:
        """Append the ledger line of one request record (:func:`ledger_entry`) and return it."""
        entry = ledger_entry(info)
        if entry is None:
            raise TypeError("not a request record")
        return self._log.append(entry)

    def entries(self) -> list[dict[str, Any]]:
        return self._log.entries()

    def head(self) -> tuple[int, str]:
        """``(lines, hash of the last line)``."""
        return self._log.head()

    def verify(self) -> ChainCheck:
        return verify_chain(self.path, label=LEDGER_FILE)


# ======================================================================================
# the engine hook
# ======================================================================================


@dataclass
class _CaseState:
    case_id: str
    case_dir: Path
    audit: CaseAudit
    ledger: RequestLedger
    mode: str
    engagement: bool
    started: str
    tlp_start: str
    egress: dict[str, Any] = field(default_factory=dict)
    previous: dict[str, Any] | None = None
    seen: set[int] = field(default_factory=set)
    refs: list[Any] = field(default_factory=list)
    targets: Counter[str] = field(default_factory=Counter)
    modules: set[str] = field(default_factory=set)
    request_count: int = 0
    late: int = 0
    ended: bool = False
    errors: list[str] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def counts(self) -> tuple[dict[str, int], int, set[str]]:
        """``(targets_touched, request_count, modules)`` read under the lock: runs abandoned at a
        deadline may still record requests while the case ends."""
        with self.lock:
            return dict(sorted(self.targets.items())), self.request_count, set(self.modules)


def _install_lift(case: Any) -> None:
    """Make ``case.to_dict()`` carry :data:`LIFTED_KEYS` from ``case.meta`` at the top level (the
    engine's case dict has no slot for hook data; existing keys are never replaced)."""
    current = getattr(case, "to_dict", None)
    if not callable(current) or getattr(current, "_v3lum_audit_lift", False):
        return

    def to_dict(*args: Any, **kwargs: Any) -> Any:
        data = current(*args, **kwargs)
        # lift from the dict's own (already secret-redacted) meta, never from the live object
        meta = data.get("meta") if isinstance(data, dict) else None
        if not isinstance(meta, Mapping):
            meta = getattr(case, "meta", None)
        if isinstance(data, dict) and isinstance(meta, Mapping):
            for key in LIFTED_KEYS:
                if key not in data and meta.get(key) is not None:
                    data[key] = copy.deepcopy(meta[key])
        return data

    to_dict._v3lum_audit_lift = True  # type: ignore[attr-defined]
    try:
        case.to_dict = to_dict
    except (AttributeError, TypeError):  # pragma: no cover - a frozen case keeps the meta copy only
        pass


def _set_case_value(case: Any, key: str, value: Any) -> None:
    if isinstance(case, dict):
        case[key] = value
        meta = case.get("meta")
        if isinstance(meta, dict):
            meta[key] = value
        return
    meta = getattr(case, "meta", None)
    if not isinstance(meta, dict):
        meta = {}
        try:
            case.meta = meta
        except (AttributeError, TypeError):  # pragma: no cover
            return
    meta[key] = value
    _install_lift(case)


def _case_meta(case: Any) -> dict[str, Any] | None:
    """The case's ``meta`` dict (created when missing; None for a case that cannot hold one)."""
    if isinstance(case, dict):
        meta = case.get("meta")
        if not isinstance(meta, dict):
            meta = case["meta"] = {}
        return meta
    meta = getattr(case, "meta", None)
    if not isinstance(meta, dict):
        meta = {}
        try:
            case.meta = meta
        except (AttributeError, TypeError):  # pragma: no cover
            return None
    return meta


def _set_meta_value(case: Any, key: str, value: Any) -> None:
    """``case.meta[key] = value`` (never lifted to the top level of the case dict)."""
    meta = _case_meta(case)
    if meta is not None:
        meta[key] = value


def _add_header_note(case: Any, line: str) -> None:
    """Append ``line`` to ``case.meta['header_notes']`` (the report header renders every one)."""
    meta = _case_meta(case)
    if meta is None or not line:
        return
    notes = meta.get("header_notes")
    if not isinstance(notes, list):
        notes = meta["header_notes"] = []
    if line not in notes:
        notes.append(line)


def since_last_run_line(since: Mapping[str, Any] | None) -> str:
    """The report header line of a re-collection (P324 cond 8): ``'since last run (case <id>): N new
    findings, M resolved'`` (plus ``K not re-checked`` when some earlier findings' sources did not
    answer this time); '' without a previous run."""
    if not isinstance(since, Mapping):
        return ""
    new, resolved, stale = _int(since.get("new")), _int(since.get("resolved")), _int(since.get("not_rechecked"))
    previous = str(since.get("previous_case") or "")
    head = f"since last run (case {previous})" if previous else "since last run"
    line = f"{head}: {new} new finding{'s' if new != 1 else ''}, {resolved} resolved"
    if stale:
        line += f", {stale} not re-checked (source did not answer)"
    return line


def engagement_of(case: Any) -> dict[str, Any] | None:
    """The engagement summary of a case (``case['engagement']``, else ``case['meta']['engagement']``;
    a CaseResult's ``meta``); None for a passive case."""
    return _lifted(case, "engagement")


def since_last_run_of(case: Any) -> dict[str, Any] | None:
    """``{previous_case, previous_created, new, resolved, unchanged, not_rechecked}`` of a
    re-collected case (``case['since_last_run']`` or its ``meta`` copy); None otherwise."""
    return _lifted(case, "since_last_run")


def _lifted(case: Any, key: str) -> dict[str, Any] | None:
    value = case.get(key) if isinstance(case, Mapping) else None
    if isinstance(value, dict):
        return value
    meta = _get(case, "meta")
    value = meta.get(key) if isinstance(meta, Mapping) else None
    return value if isinstance(value, dict) else None


class AuditHook:
    """The engine case hook of the audit trail and the request ledger (see the module docstring).

    ``AuditHook(store, *, analyst=None, runtime=None)``; ``attach(runtime)`` adds the hook to
    ``runtime.case_hooks`` and subscribes it to the runtime's ``http_request`` events (idempotent).
    ``analyst`` defaults to the setting ``analyst``, then the OS user. Without :meth:`attach` the
    ledger is written at case end from the run logs (``res._request_log``) only.
    """

    def __init__(self, store: Any, *, analyst: str | None = None, runtime: Any = None) -> None:
        if store is None:
            raise ValueError("the audit hook needs the case store")
        self.store = store
        self.analyst = str(analyst or "").strip() or None
        self.runtime: Any = None
        self._lock = threading.RLock()
        self._state: _CaseState | None = None
        self._config: Any = None
        if runtime is not None:
            self.attach(runtime)

    # ------------------------------------------------------------------ wiring
    def attach(self, runtime: Any) -> AuditHook:
        """Install on ``runtime``: ``runtime.case_hooks`` and the ``http_request`` events."""
        with self._lock:
            hooks = getattr(runtime, "case_hooks", None)
            if isinstance(hooks, list) and not any(h is self for h in hooks):
                hooks.append(self)
            if self.runtime is not runtime:
                self._unsubscribe()
                events = getattr(runtime, "events", None)
                subscribe = getattr(events, "subscribe", None)
                if callable(subscribe):
                    subscribe(self.on_event)
                self.runtime = runtime
        return self

    def detach(self) -> None:
        """Remove the hook from its runtime (hooks and events)."""
        with self._lock:
            runtime = self.runtime
            self._unsubscribe()
            hooks = getattr(runtime, "case_hooks", None)
            if isinstance(hooks, list):
                hooks[:] = [h for h in hooks if h is not self]
            self.runtime = None

    def _unsubscribe(self) -> None:
        events = getattr(self.runtime, "events", None)
        unsubscribe = getattr(events, "unsubscribe", None)
        if callable(unsubscribe):
            try:
                unsubscribe(self.on_event)
            except Exception:  # noqa: BLE001 - a listener that is already gone
                pass

    @property
    def state(self) -> dict[str, Any] | None:
        """Facts of the current (or last) case: case_id, mode, engagement, request_count,
        targets_touched, ended, late, errors."""
        st = self._state
        if st is None:
            return None
        targets, count, _modules = st.counts()
        return {
            "case_id": st.case_id, "mode": st.mode, "engagement": st.engagement or count > 0, "request_count": count,
            "targets_touched": targets, "ended": st.ended, "late": st.late, "errors": list(st.errors),
        }

    # ------------------------------------------------------------------ settings and clock
    def _settings(self) -> Any:
        config = getattr(self.runtime, "config", None)
        if config is not None:
            return config
        if self._config is None:
            try:
                from v3lum.config import Config

                self._config = Config.load()
            except Exception:  # noqa: BLE001 - defaults
                self._config = {}
        return self._config

    def _setting(self, name: str, default: Any = None) -> Any:
        settings = self._settings()
        getter = getattr(settings, "get", None)
        try:
            value = getter(name, default) if callable(getter) else default
        except Exception:  # noqa: BLE001
            value = default
        return default if value is None else value

    def _now(self) -> _dt.datetime:
        rt_now = getattr(self.runtime, "now", None)
        if callable(rt_now):
            try:
                return rt_now()
            except Exception:  # noqa: BLE001
                pass
        clock = getattr(self.store, "clock", None)
        now = getattr(clock, "now", None)
        if callable(now):
            return now()
        return _dt.datetime.now(_dt.timezone.utc)

    def _analyst(self) -> str:
        return self.analyst or str(self._setting("analyst", "") or "").strip() or _os_user()

    # ------------------------------------------------------------------ case start
    def on_case_start(self, case: Any) -> None:
        """Write the ``case_start`` row (and the TLP lowering); create the ledger of a LIGHT/ACTIVE
        case. Exceptions propagate: the engine aborts the scan (fail closed)."""
        case_id = str(_get(case, "case_id") or "")
        case_dir = Path(str(_get(case, "case_dir") or "") or (paths.cases_dir() / case_id))
        options = _get(case, "options")
        mode = _opsec_label(_get(options, "mode")) or "passive"
        now = self._now()
        stamp = _iso(now)
        state = _CaseState(
            case_id=case_id, case_dir=case_dir, audit=CaseAudit(self.store, case_id, case_dir, now=self._now),
            ledger=RequestLedger(case_dir), mode=mode, engagement=mode in ENGAGEMENT_MODES, started=stamp,
            tlp_start=str(_get(case, "tlp") or _get(options, "tlp") or ""),
        )
        state.egress = self._egress(mode)
        try:
            state.previous = self._stored(case_id)
        except Exception as exc:  # noqa: BLE001 - the comparison is a convenience; the audit is not
            log.warning("previous run of %s unavailable: %s", case_id, type(exc).__name__)
        payload, lowered = self._start_payload(case, options, state, stamp)
        with self._lock:
            self._state = state
        try:
            state.audit.append("case_start", payload)
            if state.engagement:
                state.ledger.create()  # A7 BR13: the ledger exists for every LIGHT/ACTIVE case
            if lowered:
                state.audit.append("tlp_change", {**lowered, "phase": "start"})
        except BaseException:
            with self._lock:
                if self._state is state:
                    self._state = None
            raise

    def _stored(self, case_id: str) -> dict[str, Any] | None:
        """The stored case of this id (a re-collection into an existing case), else None."""
        if not case_id or self.store.case_info(case_id) is None:
            return None
        data = self.store.get_case(case_id)
        return data if isinstance(data, dict) and data.get("case_id") == case_id else None

    def _egress(self, mode: str) -> dict[str, Any]:
        """Egress profile of the mode's target contact and its last known public IP (``doctor
        --egress``, WP25) with the time of that check."""
        profile = "default"
        if mode in ENGAGEMENT_MODES:
            try:
                from v3lum.core.net import EgressProfiles

                profile = EgressProfiles(self._settings()).profile_for(mode)
            except Exception:  # noqa: BLE001 - an unreadable profile setting: the route is not known
                profile = "default"
        out: dict[str, Any] = {"profile": profile, "ip": "", "checked_at": ""}
        try:
            data = json.loads((paths.home() / EGRESS_CHECK_FILE).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return out
        entry = data.get(profile) if isinstance(data, dict) else None
        if isinstance(entry, dict):
            out["ip"] = str(entry.get("ip") or "")
            out["checked_at"] = str(entry.get("checked_at") or "")
        return out

    def _start_payload(self, case: Any, options: Any, state: _CaseState, stamp: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
        scope_sha, window, authorization = _scope_facts(options)
        analyst = self._analyst()
        tlp = state.tlp_start
        default_tlp = str(self._setting("tlp", "amber") or "amber")
        lowered = self._tlp_lowered(options, tlp, default_tlp, analyst, stamp)
        overrides: dict[str, Any] = {}
        if _get(options, "egress_override"):
            overrides["egress_override"] = str(_get(options, "egress_override"))
        if str(_get(options, "breach_scope") or "own") == "all":
            overrides["breach_scope"] = "all"
        for flag in ("show_personal", "allow_unknown", "expand_personal"):
            if _get(options, flag):
                overrides[flag] = True
        seeds = [str(getattr(s, "key", s)) for s in (_get(case, "seeds") or ())]
        roles = _get(options, "subject_roles") or {}
        confirmed = _get(options, "confirmed_urls") or ()
        payload: dict[str, Any] = {
            "started": stamp,
            "tool_version": __version__,
            "analyst": analyst,
            "os_user": _os_user(),
            "purpose": str(_get(options, "purpose") or ""),
            "legal_basis": str(_get(options, "legal_basis") or ""),
            "ticket": str(_get(options, "ticket") or ""),
            "mode": state.mode,
            "authorization_ref": authorization,
            "scope_sha256": scope_sha,
            "window": window,
            "egress": dict(state.egress),
            "egress_profile": state.egress.get("profile", "default"),
            "egress_ip": state.egress.get("ip", ""),
            "tlp": tlp,
            "tlp_default": default_tlp,
            "tlp_lowered": lowered,
            "overrides": overrides,
            "org_profile_sha256": str(_get(case, "org_profile_sha256") or ""),
            "licence_profile": str(_get(case, "licence_profile") or _get(options, "licence_profile") or ""),
            "targets": [_pseudonymize(k) for k in seeds],
            "modules": sorted(str(m) for m in (_get(options, "include") or ())),
            "preset": str(_get(options, "preset") or ""),
        }
        if isinstance(roles, Mapping) and roles:
            payload["subject_roles"] = {_pseudonymize(str(k)): str(v) for k, v in sorted(roles.items())}
        if confirmed:
            import hashlib

            payload["confirmed_urls_sha256"] = sorted(hashlib.sha256(str(u).encode("utf-8")).hexdigest() for u in confirmed)
        meta = getattr(self.runtime, "meta", None)
        if isinstance(meta, Mapping) and meta.get("resumed_from"):
            payload["resumed_from"] = str(meta["resumed_from"])
        return payload, lowered

    @staticmethod
    def _tlp_lowered(options: Any, tlp: str, default_tlp: str, analyst: str, stamp: str) -> dict[str, Any] | None:
        recorded = _get(options, "tlp_lowered") or _get(options, "tlp_change")
        if isinstance(recorded, Mapping) and recorded:
            return {str(k): v for k, v in recorded.items()}
        try:
            from v3lum.core import tlp as _tlp

            requested = str(_get(options, "tlp") or tlp or "")
            if requested and _tlp.parse(requested) < _tlp.parse(default_tlp):
                return {"from": default_tlp, "to": requested, "by": analyst, "at": stamp}
        except (ValueError, TypeError):
            return None
        return None

    # ------------------------------------------------------------------ requests
    def on_event(self, kind: str, payload: Mapping[str, Any]) -> None:
        """Runtime event listener: every LIGHT/ACTIVE ``http_request`` record reaches the ledger."""
        if kind != "http_request":
            return
        state = self._state
        info = payload.get("info") if isinstance(payload, Mapping) else None
        if state is None or info is None or not is_contact_request(info):
            return
        self._record(state, info)

    def _record(self, state: _CaseState, info: Any) -> None:
        with state.lock:
            key = id(info)
            if key in state.seen:
                return
            state.seen.add(key)
            state.refs.append(info)  # keeps the id unique while the case lives
            try:
                entry = state.ledger.append(info)
            except Exception as exc:  # noqa: BLE001 - fail closed below
                state.errors.append(f"request ledger not written ({type(exc).__name__}: {_redact(exc)[:120]}): target contact stopped (A7)")
                cancel = getattr(self.runtime, "cancel", None)
                if callable(cancel):
                    try:
                        cancel("cancelled")
                    except Exception:  # noqa: BLE001
                        pass
                return
            state.targets[str(entry.get("host") or "?")] += 1
            state.request_count += 1
            if entry.get("module"):
                state.modules.add(str(entry["module"]))
            if state.ended:
                state.late += 1

    # ------------------------------------------------------------------ case end
    def on_case_end(self, case: Any) -> None:
        """Complete the ledger, record policy violations and evidence versions, set the engagement
        summary and the since-last-run counts on the case and write the ``case_end`` row."""
        case_id = str(_get(case, "case_id") or "")
        state = self._state
        notes: list[str] = []
        if state is None or state.case_id != case_id:
            case_dir = Path(str(_get(case, "case_dir") or "") or (paths.cases_dir() / case_id))
            mode = _opsec_label(_get(_get(case, "options"), "mode")) or "passive"
            state = _CaseState(
                case_id=case_id, case_dir=case_dir, audit=CaseAudit(self.store, case_id, case_dir, now=self._now), ledger=RequestLedger(case_dir),
                mode=mode, engagement=mode in ENGAGEMENT_MODES, started="", tlp_start=str(_get(case, "tlp") or ""), egress=self._egress(mode),
            )
            with self._lock:
                self._state = state
            notes.append("audit hook was not active when the case started: no case_start row")
        results = list(_get(case, "results") or ())
        violations: list[dict[str, Any]] = []
        summary: dict[str, Any] | None = None
        since: dict[str, Any] | None = None
        evidence_anchor: dict[str, Any] | None = None

        def backfill() -> None:
            for res in results:
                for info in list(getattr(res, "_request_log", None) or ()):
                    if is_contact_request(info):
                        self._record(state, info)

        def policy() -> None:
            violations.extend(self._violations(results))
            for row in violations:
                state.audit.append("policy_violation", row)

        def engagement() -> None:
            nonlocal summary
            if state.engagement or state.counts()[1] > 0:
                summary = self._engagement_summary(state, case)
                _set_case_value(case, "engagement", summary)

        def since_last() -> None:
            nonlocal since
            since = self._since_last_run(state, case)
            if since is not None:
                _set_case_value(case, "since_last_run", since)
                _add_header_note(case, since_last_run_line(since))  # P324 cond 8: the report header line

        def evidence() -> None:
            nonlocal evidence_anchor
            index = ChainedLog(state.case_dir / EVIDENCE_INDEX)
            if index.path.exists():
                sync_versions(self.store, state.case_id, state.case_dir)
                count, head = index.head()
                evidence_anchor = {"versions": count, "index_head": head}

        steps: list[tuple[str, Callable[[], None]]] = [
            ("ledger", backfill), ("policy violations", policy), ("engagement summary", engagement), ("since last run", since_last),
            ("evidence versions", evidence),
        ]
        for label, fn in steps:
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - one failing step never skips the case_end row
                notes.append(f"audit: {label} failed ({type(exc).__name__}: {_redact(exc)[:120]})")
        notes.extend(state.errors)
        final_tlp = str(_get(case, "tlp") or "")
        try:
            if state.tlp_start and final_tlp and final_tlp != state.tlp_start:
                state.audit.append("tlp_change", {"from": state.tlp_start, "to": final_tlp, "phase": "end", "reason": "platform markings or the LIGHT/ACTIVE minimum (A2)"})
            end_row = state.audit.append("case_end", self._end_payload(state, case, results, violations, summary, since, evidence_anchor, notes))
        except Exception as exc:
            notes.append(f"{CASE_END_MISSING_NOTE} ({type(exc).__name__}: {_redact(exc)[:120]})")
            self._notes(case, notes)
            raise
        state.ended = True
        # the stored case keeps the head of its audit chain at case end: rows removed from the end
        # of the chain (case_end included, in the case DB and the mirror alike) are detected by
        # verify_case even though the shortened chain is well formed
        _set_meta_value(case, STORED_ANCHOR_KEY, {"rows": int(end_row["seq"]), "head": str(end_row["hash"])})
        self._notes(case, notes)

    @staticmethod
    def _notes(case: Any, notes: list[str]) -> None:
        if not notes:
            return
        target = _get(case, "notes")
        if isinstance(target, list):
            for note in notes:
                text = _redact(note)
                if text not in target:
                    target.append(text)

    def _violations(self, results: Iterable[Any]) -> list[dict[str, Any]]:
        """One row per run that ended SKIPPED 'policy' after an undeclared-host or disclosure
        violation (P327 cond 5, A8 BR9): module, attempted host, reason."""
        out = []
        for res in results:
            status = _get(res, "status")
            status = str(getattr(status, "value", status) or "")
            if status != "skipped" or str(_get(res, "reason_code") or "") != "policy":
                continue
            text = str(_get(res, "error") or "")
            match = _HOST_VIOLATION.search(text)
            if match:
                host, kind = match.group(1).strip("'\".,;()"), "undeclared_host"
                host = "" if host == "?" else host
            elif _DISCLOSURE_VIOLATION.search(text):
                host, kind = "", "disclosure"
            else:
                continue
            module = str(_get(res, "module") or "")
            entity = _get(res, "entity")
            etype = getattr(getattr(entity, "type", None), "value", None) or (str(entity).partition(":")[0] if isinstance(entity, str) else "")
            cls = _module_class(module)
            out.append({
                "module": module,
                "host": host.lower(),
                "violation": kind,
                "reason_code": "policy",
                "reason": _redact(text)[:300],
                "entity_type": str(etype or ""),
                "disclosure": str(getattr(cls, "disclosure", "") or ""),
                "opsec": _opsec_label(getattr(cls, "opsec", "")),
            })
        return out

    def _engagement_summary(self, state: _CaseState, case: Any) -> dict[str, Any]:
        options = _get(case, "options")
        scope_sha, window, authorization = _scope_facts(options)
        refusals = _refusals(_get(case, "coverage") or {})
        lines, head = state.ledger.head() if state.ledger.path.exists() else (0, CHAIN_GENESIS)
        targets, count, _modules = state.counts()
        summary: dict[str, Any] = {
            "mode": state.mode,
            "authorization_ref": authorization,
            "scope_sha256": scope_sha,
            "window": window,
            "egress": dict(state.egress),
            "egress_override": str(_get(options, "egress_override") or ""),
            "targets_touched": targets,
            "request_count": count,
            "refusals": refusals[:_MAX_REFUSALS],
            "ledger": {"file": LEDGER_FILE, "lines": lines, "head": head},
        }
        if len(refusals) > _MAX_REFUSALS:
            summary["refusals_omitted"] = len(refusals) - _MAX_REFUSALS
        return summary

    def _since_last_run(self, state: _CaseState, case: Any) -> dict[str, Any] | None:
        previous = state.previous or self._previous_by_seeds(case)
        if not previous:
            return None
        prev = [f for f in (previous.get("findings") or ()) if isinstance(f, Mapping) and f.get("id")]
        current_ids = set()
        for f in _get(case, "findings") or ():
            fid = _get(f, "id")
            if fid:
                current_ids.add(str(fid))
        answered = set()
        for res in _get(case, "results") or ():
            status = _get(res, "status")
            status = str(getattr(status, "value", status) or "")
            if status in ("ok", "empty") and not _get(res, "partial"):
                answered.add((str(_get(res, "module") or ""), _persisted_key(_get(res, "entity"))))
        prev_ids = {str(f["id"]) for f in prev}
        resolved = not_rechecked = 0
        for f in prev:
            if str(f["id"]) in current_ids:
                continue
            if (str(f.get("module") or ""), str(f.get("entity") or "")) in answered:
                resolved += 1
            else:
                not_rechecked += 1
        return {
            "previous_case": str(previous.get("case_id") or ""),
            "previous_created": str(previous.get("created") or ""),
            "new": len(current_ids - prev_ids),
            "resolved": resolved,
            "unchanged": len(current_ids & prev_ids),
            "not_rechecked": not_rechecked,
        }

    def _previous_by_seeds(self, case: Any) -> dict[str, Any] | None:
        """The newest earlier case with the same (pseudonymised) seed set whose TLP is not above
        this case's: never let a more restrictive case speak in a less restrictive report."""
        case_id = str(_get(case, "case_id") or "")
        seeds = sorted(_pseudonymize(str(getattr(s, "key", s))) for s in (_get(case, "seeds") or ()))
        if not seeds:
            return None
        created = _parse_time(_get(case, "created"))
        try:
            from v3lum.core import tlp as _tlp

            current = _tlp.parse(str(_get(case, "tlp") or "amber"))
        except (ValueError, TypeError):
            return None
        with self.store.connection() as conn:
            rows = conn.execute("SELECT id, created, seeds, tlp FROM cases WHERE id != ? ORDER BY created DESC", (case_id,)).fetchall()
        for row in rows:
            try:
                stored = sorted(str(s) for s in json.loads(row["seeds"] or "[]"))
            except (TypeError, ValueError):
                continue
            if stored != seeds:
                continue
            when = _parse_time(row["created"])
            if created is not None and when is not None and when >= created:
                continue
            try:
                if _tlp.parse(str(row["tlp"] or "red")) > current:
                    continue
            except (ValueError, TypeError):
                continue
            data = self.store.get_case(str(row["id"]))
            if isinstance(data, dict) and data.get("case_id") == row["id"]:
                return data
        return None

    def _end_payload(
        self,
        state: _CaseState,
        case: Any,
        results: list[Any],
        violations: list[dict[str, Any]],
        summary: dict[str, Any] | None,
        since: dict[str, Any] | None,
        evidence_anchor: dict[str, Any] | None,
        notes: list[str],
    ) -> dict[str, Any]:
        statuses: Counter[str] = Counter()
        targets, count, contact_modules = state.counts()
        for res in results:
            status = _get(res, "status")
            statuses[str(getattr(status, "value", status) or "")] += 1
            cls = _module_class(str(_get(res, "module") or ""))
            if cls is not None and _opsec_label(getattr(cls, "opsec", "")) in CONTACT_OPSEC and str(getattr(status, "value", status)) != "skipped":
                contact_modules.add(str(_get(res, "module")))
        findings = _get(case, "findings") or ()
        partial = _get(case, "partial") or {}
        ledger = None
        if state.ledger.path.exists():
            lines, head = state.ledger.head()
            ledger = {"ledger_lines": lines, "ledger_head": head}
        payload: dict[str, Any] = {
            "ended": _iso(self._now()),
            "duration": round(float(_get(case, "duration") or 0.0), 3),
            "findings": len(list(findings)),
            "correlations": len(list(_get(case, "correlations") or ())),
            "module_runs": len(results),
            "status": dict(sorted(statuses.items())),
            "partial": sorted(str(k) for k, v in dict(partial).items() if v) if isinstance(partial, Mapping) else [],
            "interrupted": bool(_get(case, "interrupted")),
            "tlp": str(_get(case, "tlp") or ""),
            "mode": state.mode,
            "request_count": count,
            "targets_touched": targets,
            "modules": sorted(contact_modules),
            "requests": ledger,
            "evidence": evidence_anchor,
            "policy_violations": len(violations),
            "engagement": _audit_copy(summary),
            "since_last_run": since,
        }
        if notes:
            payload["notes"] = [_redact(n)[:300] for n in notes]
        return payload


def _audit_copy(summary: dict[str, Any] | None) -> dict[str, Any] | None:
    """The engagement summary as the audit keeps it: refusal targets of personal types pseudonymised
    (the case dict and the report keep the persisted key)."""
    if summary is None:
        return None
    out = dict(summary)
    out["refusals"] = [{**r, "target": _pseudonymize(str(r.get("target") or ""))} for r in summary.get("refusals") or ()]
    return out


def _module_class(name: str) -> Any:
    if not name:
        return None
    try:
        from v3lum.core.module import REGISTRY
    except ImportError:  # pragma: no cover
        return None
    return REGISTRY.get(name)


def _refusals(coverage: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Out-of-scope and guard refusals of LIGHT/ACTIVE modules from the coverage entries (A7 BR14):
    ``[{target, module, reason_code, reason}]``."""
    out: list[dict[str, Any]] = []
    for module in sorted(coverage or {}):
        cov = coverage[module]
        if not isinstance(cov, Mapping):
            continue
        cls = _module_class(str(module))
        if cls is None or _opsec_label(getattr(cls, "opsec", "")) not in CONTACT_OPSEC:
            continue
        rows = cov.get("entities") or {}
        if not isinstance(rows, Mapping):
            continue
        for target in sorted(rows):
            row = rows[target]
            if isinstance(row, Mapping) and str(row.get("reason_code") or "") in REFUSAL_CODES:
                out.append({"target": str(target), "module": str(module), "reason_code": str(row["reason_code"]), "reason": _redact(row.get("reason") or "")[:300]})
    return out


def _parse_time(value: Any) -> _dt.datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        dt = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=_dt.timezone.utc)


# ======================================================================================
# verification
# ======================================================================================


@dataclass
class VerifyReport:
    """Outcome of :func:`verify_case`: ``ok`` (no problem), ``problems`` (each a tamper sign or a
    missing artefact), ``warnings`` (what could not be checked), ``checked`` (counts per artefact)
    and ``purged`` (the case was purged: only its minimal engagement audit is left)."""

    ok: bool
    problems: list[str] = field(default_factory=list)
    case_id: str = ""
    warnings: list[str] = field(default_factory=list)
    checked: dict[str, int] = field(default_factory=dict)
    purged: bool = False

    def summary(self) -> str:
        """One line: PASS/FAIL with what was verified."""
        parts = [f"{n} {name.replace('_', ' ')}" for name, n in self.checked.items() if n]
        what = ", ".join(parts) if parts else "nothing left to check"
        if self.ok:
            if self.purged and not parts:
                return f"PASS {self.case_id}: purged; only its value-free tombstone is left"
            state = " (purged; minimal engagement audit only)" if self.purged else ""
            return f"PASS {self.case_id}: {what} verified{state}"
        return f"FAIL {self.case_id}: {len(self.problems)} problem(s); {what} checked"

    def lines(self) -> list[str]:
        """The summary, then one line per problem and warning (for the CLI)."""
        return [self.summary()] + [f"  problem: {p}" for p in self.problems] + [f"  warning: {w}" for w in self.warnings]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _raw_audit_rows(store: Any, case_id: str) -> list[dict[str, Any]]:
    with store.connection() as conn:
        rows = conn.execute(
            "SELECT case_id, seq, ts, kind, payload, prev_hash, hash FROM audit WHERE case_id = ? ORDER BY seq", (case_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def _verify_audit(rows: list[dict[str, Any]], report: VerifyReport) -> list[dict[str, Any]]:
    """Check the DB chain byte for byte; returns the rows with their payload parsed."""
    prev = AUDIT_GENESIS
    parsed = []
    for index, row in enumerate(rows, 1):
        seq = row["seq"]
        label = f"audit row {seq} ({row['kind']})"
        if seq != index:
            report.problems.append(f"{label}: sequence number out of order (expected {index}: a row was removed or inserted)")
        if row["prev_hash"] != prev:
            report.problems.append(f"{label}: prev_hash does not match the previous row (chain broken)")
        text = row["payload"]
        try:
            payload = json.loads(text) if isinstance(text, str) else text
        except ValueError:
            report.problems.append(f"{label}: payload is not valid JSON (edited)")
            payload = text
        else:
            if not isinstance(text, str) or canonical_json(payload) != text:
                report.problems.append(f"{label}: payload is not in canonical form (edited)")
        record = {"case_id": row["case_id"], "seq": seq, "ts": row["ts"], "kind": row["kind"], "payload": payload}
        if audit_hash(row["prev_hash"], record) != row["hash"]:
            report.problems.append(f"{label}: hash mismatch (row edited)")
        prev = row["hash"]
        parsed.append({**record, "prev_hash": row["prev_hash"], "hash": row["hash"]})
    return parsed


def _verify_mirror(parsed: list[dict[str, Any]], mirror: Path, report: VerifyReport, *, expected: bool) -> None:
    check = verify_chain(mirror, label=AUDIT_MIRROR)
    if not check.exists:
        if expected:
            report.problems.append(f"{AUDIT_MIRROR} missing (the audit rows of the case DB have no mirror)")
        return
    report.problems.extend(check.problems)
    by_seq = {int(r["seq"]): r for r in parsed if isinstance(r.get("seq"), int)}
    mirrored: set[int] = set()
    for number, entry in enumerate(check.entries, 1):
        seq = entry.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            continue
        mirrored.add(seq)
        row = by_seq.get(seq)
        if row is None:
            report.problems.append(f"{AUDIT_MIRROR} line {number}: audit row {seq} is missing from the case DB (row deleted)")
        elif canonical_json(row) != canonical_json(entry):
            report.problems.append(f"{AUDIT_MIRROR} line {number}: differs from audit row {seq} of the case DB (edited)")
    top = max(mirrored) if mirrored else 0
    for seq, row in sorted(by_seq.items()):
        if seq in mirrored:
            continue
        if seq < top:
            report.problems.append(f"audit row {seq} ({row['kind']}) is missing from {AUDIT_MIRROR} (line removed)")
        elif row["kind"] in STORE_NATIVE_KINDS:
            report.warnings.append(f"audit row {seq} ({row['kind']}) is not mirrored in {AUDIT_MIRROR} yet (written by the store)")
        else:
            report.problems.append(f"audit row {seq} ({row['kind']}) is missing from {AUDIT_MIRROR} (lines removed from its end)")


def _anchor(parsed: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    for row in reversed(parsed):
        if row.get("kind") != "case_end" or not isinstance(row.get("payload"), Mapping):
            continue
        value = row["payload"].get(name)
        return value if isinstance(value, Mapping) else None
    return None


def _stored_case(store: Any, case_id: str) -> dict[str, Any] | None:
    """The stored case dict of exactly ``case_id`` (never a prefix match), None when unreadable."""
    try:
        data = store.get_case(case_id)
    except Exception:  # noqa: BLE001 - an unreadable case JSON leaves the anchors unchecked (reported)
        return None
    return data if isinstance(data, dict) and data.get("case_id") == case_id else None


def _verify_completion(parsed: list[dict[str, Any]], stored: Mapping[str, Any] | None, saved: bool, report: VerifyReport) -> None:
    """Rows removed from the END of the audit chain leave a well-formed, shorter chain (and take the
    case_end anchors with them). Two checks catch it: the audit head the stored case recorded at case
    end (``meta[STORED_ANCHOR_KEY]``) must still be in the chain, and the last run (``case_start``) of
    a saved case must have its ``case_end`` row."""
    meta = stored.get("meta") if isinstance(stored, Mapping) else None
    anchor = meta.get(STORED_ANCHOR_KEY) if isinstance(meta, Mapping) else None
    anchored = 0  # seq of the case_end row the stored case recorded, when it is intact
    if isinstance(anchor, Mapping) and "rows" in anchor:
        count, head = _int(anchor.get("rows")), str(anchor.get("head") or "")
        row = next((r for r in parsed if r.get("seq") == count), None)
        if row is None:
            report.problems.append(f"the audit has {len(parsed)} row(s), the stored case recorded {count} at case end (rows removed from its end)")
        elif str(row.get("hash") or "") != head:
            report.problems.append(f"audit row {count} does not match the head the stored case recorded at case end")
        else:
            anchored = count
    starts = [i for i, r in enumerate(parsed) if r.get("kind") == "case_start"]
    if not starts or any(r.get("kind") == "case_end" for r in parsed[starts[-1]:]):
        return
    notes = [str(n) for n in ((stored or {}).get("notes") or ()) if isinstance(n, str)]
    if anchored and _int(parsed[starts[-1]].get("seq")) > anchored:
        report.warnings.append(f"a later run (audit row {parsed[starts[-1]].get('seq')}) has no case_end row: it did not finish")
    elif not saved:
        report.warnings.append("the last run has no case_end row (the scan did not finish or the case was not saved)")
    elif any(n.startswith(CASE_END_MISSING_NOTE) for n in notes):
        report.warnings.append("the last run has no case_end row (the audit hook could not write it: see the case notes); removed lines cannot be detected")
    else:
        report.problems.append("the last run of the case has no case_end row (audit rows removed from the end of the chain)")


def _check_ledger_anchor(check: ChainCheck, count: int, head: str, source: str, report: VerifyReport, *, late: bool) -> None:
    """Compare the request ledger with a head recorded at case end (``count`` lines, last hash)."""
    if not check.exists:
        if count > 0:
            report.problems.append(f"{LEDGER_FILE} missing ({source} recorded {count} line(s) at case end)")
    elif check.lines < count:
        report.problems.append(f"{LEDGER_FILE} has {check.lines} line(s), {source} recorded {count} at case end (lines removed)")
    elif count > 0 and check.hash_at(count) != head:  # physical line (a torn line hashes '')
        report.problems.append(f"{LEDGER_FILE} line {count} does not match the head recorded by {source} at case end")
    elif late and check.lines > count:
        report.warnings.append(f"{check.lines - count} ledger line(s) written after the case_end row (requests in flight when the case ended)")


def _sidecar_hash(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    match = re.search(r"\b([0-9a-fA-F]{64})\b", text)
    return match.group(1).lower() if match else ""


def _verify_reports(store: Any, case_id: str, directory: Path | None, report: VerifyReport) -> int:
    recorded = {os.path.abspath(p): str(h).lower() for p, h in (store.report_hashes(case_id) or {}).items()}
    candidates = set(recorded) | {os.path.abspath(p) for p in (store.report_paths(case_id) or ())}
    if directory is not None and directory.is_dir():
        for sidecar in directory.glob("*.sha256"):
            candidates.add(os.path.abspath(str(sidecar)[: -len(".sha256")]))
    checked = 0
    for text in sorted(candidates):
        path = Path(text)
        sidecar = Path(text + ".sha256")
        try:
            actual = sha256_file(path)
        except FileNotFoundError:
            if text in recorded or sidecar.exists():
                report.warnings.append(f"report {path.name} not found (moved or deleted): its hash cannot be checked")
            continue
        except OSError as exc:
            report.problems.append(f"report {path.name}: {exc}")
            continue
        checked += 1
        if text in recorded and recorded[text] and recorded[text] != actual:
            report.problems.append(f"report {path.name}: SHA-256 differs from the hash recorded when it was written (edited)")
        expected = _sidecar_hash(sidecar) if sidecar.exists() else None
        if expected is not None and expected != actual:
            report.problems.append(f"report {path.name}: does not match its .sha256 sidecar (edited)")
        if text not in recorded and expected is None:
            report.warnings.append(f"report {path.name}: no recorded hash (path recorded only)")
    return checked


def _case_directory(store: Any, case_id: str, info: Mapping[str, Any] | None, case_dir: str | os.PathLike[str] | None) -> Path | None:
    """The case directory: the explicit one, else ``~/.v3lum/cases/<id>``, else the directory the
    stored case names (a case written under another home)."""
    if case_dir is not None:
        return Path(case_dir)
    directory = paths.cases_dir() / case_id if _CASE_ID.match(case_id) else None
    if directory is not None and directory.is_dir():
        return directory
    stored = store.get_case(case_id) if info is not None else None
    alt = str(stored.get("case_dir") or "") if isinstance(stored, dict) else ""
    if alt and Path(alt).is_dir():
        return Path(alt)
    return directory


def verify_case(store: Any, case_id: str, *, case_dir: str | os.PathLike[str] | None = None) -> VerifyReport:
    """Verify a case offline (``v3lum cases verify <id>``): every evidence hash, every report hash,
    the audit chain (case DB rows byte for byte and their ``audit.jsonl`` mirror) and the request
    ledger chain, against the heads the last ``case_end`` row recorded. ``ok`` is True when no
    problem was found. A purged case verifies what is left of it: the re-sealed minimal engagement
    audit (closed by a ``purge`` row) and the request ledger."""
    case_id = str(case_id or "").strip()
    report = VerifyReport(ok=False, case_id=case_id)
    if not case_id:
        report.problems.append("no case id")
        return report
    info = store.case_info(case_id)
    tomb = store.tombstone(case_id)
    rows = _raw_audit_rows(store, case_id)
    directory = _case_directory(store, case_id, info, case_dir)
    exists = directory is not None and directory.is_dir()
    with store.connection() as conn:
        ev_rows = [dict(r) for r in conn.execute(
            "SELECT record_key, version, sha256, path, collected_at, fetched_at, diff_summary FROM evidence_versions"
            " WHERE case_id = ? ORDER BY record_key, version",
            (case_id,),
        ).fetchall()]
    if info is None and tomb is None and not rows and not exists and not ev_rows:
        report.problems.append(f"case {case_id} not found")
        return report
    report.purged = info is None and tomb is not None
    engagement = bool(info.get("engagement")) if info is not None else bool((tomb or {}).get("audit_until"))

    # -- audit: the case DB chain byte for byte, then its mirror
    parsed = _verify_audit(rows, report)
    report.checked["audit_rows"] = len(parsed)
    purge_rows = [r for r in parsed if r.get("kind") == PURGE_AUDIT_KIND]
    for r in purge_rows:
        payload = r.get("payload") if isinstance(r.get("payload"), Mapping) else {}
        if payload.get("previous_chain_intact") is False:
            report.warnings.append("the audit chain was already broken when the case was purged (recorded by the purge row)")
    hooked = any(r.get("kind") == "case_start" for r in parsed)
    if exists and not purge_rows:
        _verify_mirror(parsed, directory / AUDIT_MIRROR, report, expected=hooked)  # type: ignore[operator]
    stored = _stored_case(store, case_id) if info is not None else None
    stored_meta = stored.get("meta") if isinstance(stored, Mapping) else None
    audited = isinstance(stored_meta, Mapping) and isinstance(stored_meta.get(STORED_ANCHOR_KEY), Mapping)
    if engagement and not hooked:
        report.problems.append("LIGHT/ACTIVE case without its audit record (no case_start row)")
    elif not hooked and info is not None and not audited:
        report.warnings.append("no audit record for this case (it was scanned without the audit hook)")
    if not purge_rows:
        _verify_completion(parsed, stored, info is not None, report)

    # -- evidence and reports (removed with a purged case)
    if not report.purged:
        anchor = _anchor(parsed, "evidence")
        if exists:
            check = verify_evidence(directory, rows=ev_rows, anchor=anchor)  # type: ignore[arg-type]
            report.problems.extend(check.problems)
            report.warnings.extend(check.warnings)
            report.checked["evidence_files"] = check.files
        elif ev_rows or (anchor and _int(anchor.get("versions")) > 0):
            report.problems.append("the case directory is missing: its evidence files cannot be found")
        report.checked["reports"] = _verify_reports(store, case_id, directory if exists else None, report)

    # -- request ledger: its chain, then the heads recorded at case end (the case_end row, and the
    # engagement summary of the stored case)
    ledger_anchor = _anchor(parsed, "requests")
    check_ledger = verify_chain(directory / LEDGER_FILE, label=LEDGER_FILE) if exists else ChainCheck(path="")  # type: ignore[operator]
    report.problems.extend(check_ledger.problems)
    report.checked["ledger_lines"] = check_ledger.lines
    if ledger_anchor:
        _check_ledger_anchor(
            check_ledger, _int(ledger_anchor.get("ledger_lines")), str(ledger_anchor.get("ledger_head") or ""), "the audit", report, late=True,
        )
    summary_ledger = (engagement_of(stored) or {}).get("ledger") if stored is not None else None
    if isinstance(summary_ledger, Mapping) and "lines" in summary_ledger:
        _check_ledger_anchor(check_ledger, _int(summary_ledger.get("lines")), str(summary_ledger.get("head") or ""), "the stored case", report, late=False)
    if engagement and not check_ledger.exists and not (ledger_anchor and _int(ledger_anchor.get("ledger_lines")) > 0):
        report.problems.append(f"LIGHT/ACTIVE case without its request ledger ({LEDGER_FILE} missing)")
    if report.purged:
        when = str((tomb or {}).get("purged_at") or "")
        left = "the minimal engagement audit left is verified" if (parsed or check_ledger.exists) else "nothing else is left"
        report.warnings.append(f"case purged {when}: evidence and reports were removed; {left}".replace("  ", " "))
    report.ok = not report.problems
    return report
