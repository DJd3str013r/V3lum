"""Evidence store v2 (P324): content-addressed, write-once evidence files with re-collection
versions, the request context of every run and an append-only, hash-chained evidence index.

``EvidenceStore(case_dir, *, now=None, store=None, case_id=None, max_file_bytes=None,
max_case_bytes=None, settings=None).save(res, *, requests=()) -> (path, sha256)`` is the entry
point the engine calls for every result with a raw payload. It writes one :class:`EvidenceRecord`
to ``<case_dir>/evidence/<module>__<type>__<hmac12>__<sha10>.json`` (``.json.gz`` above 64 KB):

* **record** (schema ``v3lum.evidence/2``): module, entity_type, entity_hmac (the keyed HMAC of
  the installation, A4 - never the investigated value), record_key (``module|entity_hmac``),
  version, previous_sha256 and diff_summary (re-collections), case_id, collected_at (the runtime
  clock), fetched_at (the oldest answer the run used: the cache row time for answers served from
  the cache, never now()), status, requests (method, redacted URL, final URL and redirect chain,
  status, response headers date/content-type/server when recorded, UA, egress profile, from_cache,
  fetched_at; AR01), datasets (name + SHA-256 citations), redacted_fields (P145) and data (the
  sanitized raw payload). Configured key values and key-like URL parameters are masked (AR01) and
  raw SECRET_TYPES values of the run are written in their persisted form before anything is hashed.
* **content addressing, write-once**: the name ends with the first 10 hex characters of the
  SHA-256 of the stored bytes (what ``save`` returns). Files are 0600 in a 0700 directory, created
  through a hard-linked temporary file: an existing name is never replaced, a symbolic link planted
  at a name is never followed (OSError), a name holding other bytes is refused (OSError).
* **re-collection**: the same (module, entity) collected again in the case gets a new version with
  a diff summary (added/removed top-level keys, changed leaf count) and never overwrites the older
  one; a payload identical to the latest version is not stored twice (that version is returned).
* **caps**: settings ``evidence_max_file_bytes`` (default 5 MB) and ``evidence_max_case_bytes``
  (200 MB; 0 = no cap) bound the stored bytes. A payload that does not fit keeps a prefix of its
  JSON text and a ``truncated`` marker (reason, limit, original size and SHA-256); once the case cap
  is spent only the record without data is written.
* **index**: every stored version appends one hash-chained line to ``<case_dir>/evidence.jsonl``
  (:class:`ChainedLog`: seq, file, sha256, record_key, version, collected_at, fetched_at, bytes,
  data_sha256, diff_summary...). It is the source of :func:`manifest` and of the case DB's
  ``evidence_versions`` rows (written at once with ``store=``/``case_id=``, otherwise by
  :func:`sync_versions`, which the audit hook runs at the end of every case).

Also here: :func:`manifest` (``[(file, sha256)]``), :func:`read_evidence`, :func:`verify_evidence`
(the offline evidence part of ``v3lum cases verify``), :func:`request_record` /
:func:`request_records`, :func:`diff_summary`, :func:`evidence_name`, and the append-only JSONL hash
chain shared with the request ledger and the audit mirror (:class:`ChainedLog`,
:func:`verify_chain`, :func:`chain_hash`, :func:`canonical_json`).
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import enum
import gzip
import hashlib
import io
import json
import logging
import math
import os
import re
import secrets
import sqlite3
import stat
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:  # POSIX advisory locks serialise appends of several processes; threads use a lock anyway
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows
    _fcntl = None  # type: ignore[assignment]

log = logging.getLogger("v3lum.evidence")

__all__ = [
    "CHAIN_GENESIS",
    "DEFAULT_MAX_CASE_BYTES",
    "DEFAULT_MAX_FILE_BYTES",
    "EVIDENCE_DIR",
    "EVIDENCE_INDEX",
    "GZIP_THRESHOLD",
    "SCHEMA",
    "SELECTED_HEADERS",
    "ChainCheck",
    "ChainedLog",
    "EvidenceCheck",
    "EvidenceRecord",
    "EvidenceStore",
    "append_line",
    "append_new_lines",
    "canonical_json",
    "chain_hash",
    "diff_summary",
    "evidence_name",
    "json_safe",
    "manifest",
    "read_evidence",
    "request_record",
    "request_records",
    "sha256_file",
    "sync_versions",
    "verify_chain",
    "verify_evidence",
]

#: Sub-directory of a case directory holding the evidence files.
EVIDENCE_DIR = "evidence"
#: The append-only, hash-chained evidence index at the top of the case directory.
EVIDENCE_INDEX = "evidence.jsonl"
#: Schema of an evidence record.
SCHEMA = "v3lum.evidence/2"
#: Records whose JSON is larger than this are stored gzip-compressed (``.json.gz``).
GZIP_THRESHOLD = 64 * 1024
#: Defaults of the settings ``evidence_max_file_bytes`` / ``evidence_max_case_bytes``.
DEFAULT_MAX_FILE_BYTES = 5_000_000
DEFAULT_MAX_CASE_BYTES = 200_000_000
#: ``prev_hash`` of the first line of a hash chain (the audit table uses the same genesis).
CHAIN_GENESIS = "0" * 64
#: Response headers kept in the request context of an evidence record (when recorded).
SELECTED_HEADERS = ("date", "content-type", "server")

_DIR_MODE = 0o700
_FILE_MODE = 0o600
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
_HEX = re.compile(r"^[0-9a-f]{64}$")
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
#: top-level keys named in a diff summary (plain field names only: a key that is itself a value - an
#: e-mail address, a domain, an id - is counted, never written)
_FIELD_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
#: leaves compared per side by :func:`diff_summary` (bounded work on huge payloads)
_MAX_LEAVES = 200_000
#: decompressed size accepted when an evidence file is read back (own files; a bomb is refused)
_MAX_READ_BYTES = 256 * 1024 * 1024
#: fields of a request record (RequestInfo names; v1 dicts with the same keys are accepted)
_REQUEST_FIELDS = (
    "ts", "method", "url", "host", "path", "status", "bytes", "elapsed", "error", "module", "provider",
    "source", "opsec", "egress_profile", "resolved_ip", "port", "user_agent",
)
#: a stored evidence record without data needs about this much room (the cap of a nearly full case)
_STUB_ROOM = 4096


# ======================================================================================
# canonical JSON and hash chains (evidence index, request ledger, audit mirror)
# ======================================================================================


def canonical_json(obj: Any) -> str:
    """Canonical JSON (sorted keys, no spaces, UTF-8 kept) - the hashed form of chain lines and of
    the audit rows (the same function as :func:`v3lum.core.store.canonical_json`)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def chain_hash(prev_hash: str, body: Mapping[str, Any]) -> str:
    """``sha256(prev_hash + canonical_json(body))`` where ``body`` is a chain line without its
    ``prev_hash`` and ``hash`` fields (for an audit row: ``{case_id, seq, ts, kind, payload}``, the
    rule of :func:`v3lum.core.store.audit_hash`)."""
    clean = {k: v for k, v in body.items() if k not in ("prev_hash", "hash")}
    return hashlib.sha256((str(prev_hash) + canonical_json(clean)).encode("utf-8", errors="surrogatepass")).hexdigest()


def json_safe(obj: Any, _depth: int = 0) -> Any:
    """``obj`` as plain JSON data whose canonical form is stable: dicts with string keys, lists,
    strings (lone surrogates replaced), ints, finite floats, booleans and None; anything else is
    written as ``str(obj)`` (datetimes as ISO text)."""
    if _depth > 64:
        return str(obj)
    if isinstance(obj, enum.Enum):
        return json_safe(obj.value, _depth + 1)
    if obj is None or isinstance(obj, bool):
        return obj
    if isinstance(obj, int):
        return int(obj)
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else str(obj)
    if isinstance(obj, str):
        text = str.__str__(obj)
        return text.encode("utf-8", errors="replace").decode("utf-8") if _has_surrogate(text) else text
    if isinstance(obj, _dt.datetime):
        return obj.isoformat()
    if isinstance(obj, Mapping):
        return {str(json_safe(k, _depth + 1)): json_safe(v, _depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        items = list(obj)
        if isinstance(obj, (set, frozenset)):
            items = sorted(items, key=lambda x: canonical_json(json_safe(x, _depth + 1)))
        return [json_safe(v, _depth + 1) for v in items]
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        to_dict = getattr(obj, "to_dict", None)
        return json_safe(to_dict() if callable(to_dict) else dataclasses.asdict(obj), _depth + 1)
    return str(obj)


def _has_surrogate(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return True
    return False


@dataclass
class ChainCheck:
    """Outcome of :func:`verify_chain`: the parsed lines, the problems found, and the head
    (``lines`` = number of lines, ``head`` = hash of the last line, :data:`CHAIN_GENESIS` when empty)."""

    path: str
    exists: bool = False
    entries: list[dict[str, Any]] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    lines: int = 0
    head: str = CHAIN_GENESIS
    #: the ``hash`` field of every physical line, in order ('' for a line that does not parse)
    hashes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    def hash_at(self, line: int) -> str:
        """The ``hash`` recorded on physical line ``line`` (1-based); '' when there is no such line
        or it does not parse (the anchors of the audit's ``case_end`` row are compared with it)."""
        return self.hashes[line - 1] if 0 < line <= len(self.hashes) else ""


def _read_regular(path: Path, *, limit: int | None = None) -> bytes:
    """The bytes of a regular file, never through a symbolic link (OSError for a link or another
    kind of file; FileNotFoundError when missing)."""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise OSError(f"{path} is a symbolic link (refused)")
    if not stat.S_ISREG(st.st_mode):
        raise OSError(f"{path} is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as fh:
        return fh.read() if limit is None else fh.read(limit)


def verify_chain(path: str | os.PathLike[str], *, label: str = "") -> ChainCheck:
    """Check a hash-chained JSONL file byte for byte (offline).

    Every line must be newline-terminated canonical JSON (:func:`canonical_json`) holding ``seq``
    (1, 2, ...), ``prev_hash`` (the previous line's ``hash``; :data:`CHAIN_GENESIS` first) and
    ``hash`` = :func:`chain_hash` of the rest of the line. Any edited, inserted, removed or reordered
    line and any changed byte is reported; a missing file gives ``exists=False`` and no problem (the
    caller decides whether the file was required). Removing lines from the end is only visible
    against an anchor recorded elsewhere (the audit's ``case_end`` row)."""
    p = Path(path)
    name = label or p.name
    check = ChainCheck(path=str(p))
    try:
        data = _read_regular(p)
    except FileNotFoundError:
        return check
    except OSError as exc:
        check.exists = True
        check.problems.append(f"{name}: cannot be read ({exc})")
        return check
    check.exists = True
    if not data:
        return check
    if not data.endswith(b"\n"):
        check.problems.append(f"{name}: the last line is not newline-terminated (truncated or edited)")
    raw_lines = data.split(b"\n")
    if raw_lines and raw_lines[-1] == b"":
        raw_lines.pop()
    prev: str | None = CHAIN_GENESIS
    expect = 1
    for number, raw in enumerate(raw_lines, 1):
        check.lines = number
        try:
            text = raw.decode("utf-8")
            entry = json.loads(text)
        except (UnicodeDecodeError, ValueError):
            check.problems.append(f"{name} line {number}: not valid JSON (edited or torn)")
            check.hashes.append("")
            prev = None
            expect += 1
            continue
        if not isinstance(entry, dict):
            check.problems.append(f"{name} line {number}: not a JSON object")
            check.hashes.append("")
            prev = None
            expect += 1
            continue
        if canonical_json(entry) != text:
            check.problems.append(f"{name} line {number}: not in canonical form (edited)")
        seq = entry.get("seq")
        if seq != expect or isinstance(seq, bool):
            check.problems.append(f"{name} line {number}: sequence number {seq!r}, expected {expect}")
        if prev is not None and entry.get("prev_hash") != prev:
            check.problems.append(f"{name} line {number}: prev_hash does not match the previous line (chain broken)")
        stored = entry.get("hash")
        if not isinstance(stored, str) or chain_hash(str(entry.get("prev_hash") or ""), entry) != stored:
            check.problems.append(f"{name} line {number}: hash mismatch (line edited)")
        prev = stored if isinstance(stored, str) else None
        expect = (seq + 1) if isinstance(seq, int) and not isinstance(seq, bool) else expect + 1
        check.entries.append(entry)
        check.hashes.append(stored if isinstance(stored, str) else "")
        check.head = stored if isinstance(stored, str) else ""
    return check


def _tail_entry(fd: int) -> tuple[dict[str, Any] | None, bool]:
    """The last parsable line of the file open as ``fd`` and whether the file ends with a newline
    (True for an empty file)."""
    size = os.fstat(fd).st_size
    if size <= 0:
        return None, True
    chunk = 65536
    while True:
        start = max(0, size - chunk)
        os.lseek(fd, start, os.SEEK_SET)
        data = b""
        while len(data) < size - start:
            part = os.read(fd, size - start - len(data))
            if not part:
                break
            data += part
        ends_newline = data.endswith(b"\n")
        lines = data.split(b"\n")
        if start > 0:
            lines = lines[1:]  # the first piece may be cut
        for raw in reversed(lines):
            if not raw.strip():
                continue
            try:
                entry = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                continue
            if isinstance(entry, dict):
                return entry, ends_newline
        if start == 0:
            return None, ends_newline
        chunk *= 4


def _open_append(path: Path) -> int:
    """An O_APPEND descriptor of ``path`` (created 0600, never through a symbolic link)."""
    flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, _FILE_MODE)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"{path} is not a regular file")
        if os.name == "posix" and stat.S_IMODE(st.st_mode) != _FILE_MODE:
            os.fchmod(fd, _FILE_MODE)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _ensure_dir(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    try:
        if os.name == "posix" and stat.S_IMODE(directory.stat().st_mode) & 0o077:
            os.chmod(directory, _DIR_MODE)
    except OSError:  # pragma: no cover - a foreign-owned directory: the 0600 files still protect it
        pass


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def append_line(path: str | os.PathLike[str], text: str) -> None:
    """Append one line (``text`` + newline) to ``path`` (0600, O_APPEND, never through a link,
    fsynced). A file whose last line lacks its newline (a torn write) is closed first."""
    p = Path(path)
    _ensure_dir(p.parent)
    with _ChainLock(p):
        fd = _open_append(p)
        try:
            if _fcntl is not None:
                _fcntl.flock(fd, _fcntl.LOCK_EX)
            _tail, ends_newline = _tail_entry(fd)
            payload = ("" if ends_newline else "\n") + text + "\n"
            _write_all(fd, payload.encode("utf-8", errors="surrogatepass"))
            os.fsync(fd)
        finally:
            os.close(fd)  # closing releases the flock


def append_new_lines(path: str | os.PathLike[str], lines: Iterable[tuple[int, str]]) -> int:
    """Append, in ``seq`` order, the ``(seq, text)`` lines whose ``seq`` is above the ``seq`` of the
    file's last line, all under the file lock (threads and, with ``flock``, processes): writers that
    race to mirror the same rows never write one twice. Returns the number of lines added."""
    p = Path(path)
    _ensure_dir(p.parent)
    with _ChainLock(p):
        fd = _open_append(p)
        try:
            if _fcntl is not None:
                _fcntl.flock(fd, _fcntl.LOCK_EX)
            tail, ends_newline = _tail_entry(fd)
            last = tail.get("seq") if tail is not None else 0
            last = last if isinstance(last, int) and not isinstance(last, bool) else 0
            new = [text for seq, text in sorted(lines, key=lambda item: item[0]) if seq > last]
            if not new:
                return 0
            payload = ("" if ends_newline else "\n") + "\n".join(new) + "\n"
            _write_all(fd, payload.encode("utf-8", errors="surrogatepass"))
            os.fsync(fd)
            return len(new)
        finally:
            os.close(fd)


_PATH_LOCKS: dict[str, threading.Lock] = {}
_PATH_LOCKS_GUARD = threading.Lock()


class _ChainLock:
    """Process-wide lock per file path (threads of one process; ``flock`` covers processes)."""

    def __init__(self, path: Path) -> None:
        key = os.path.abspath(str(path))
        with _PATH_LOCKS_GUARD:
            self._lock = _PATH_LOCKS.setdefault(key, threading.Lock())

    def __enter__(self) -> None:
        self._lock.acquire()

    def __exit__(self, *exc: Any) -> None:
        self._lock.release()


class ChainedLog:
    """An append-only, hash-chained JSONL file (0600, never written through a symbolic link).

    Each line is ``canonical_json({**body, 'seq': n, 'prev_hash': p, 'hash': h})`` with
    ``h = chain_hash(p, {**body, 'seq': n})``, ``p`` the previous line's hash (:data:`CHAIN_GENESIS`
    first) and ``seq`` counting from 1. The head is re-read from the file under a lock (and
    ``flock`` on POSIX) before every append, so several writers never fork the chain. A torn last
    line is closed with a newline and left in place (:func:`verify_chain` reports it).
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    def create(self) -> Path:
        """Create the (empty) file 0600 when missing; the parent directory is created 0700."""
        _ensure_dir(self.path.parent)
        with _ChainLock(self.path):
            os.close(_open_append(self.path))
        return self.path

    def append(self, body: Mapping[str, Any]) -> dict[str, Any]:
        """Append ``body`` (JSON data; ``seq``/``prev_hash``/``hash`` are set here) and return the
        full line as written."""
        clean = {str(k): json_safe(v) for k, v in body.items() if k not in ("seq", "prev_hash", "hash")}
        _ensure_dir(self.path.parent)
        with _ChainLock(self.path):
            fd = _open_append(self.path)
            try:
                if _fcntl is not None:
                    _fcntl.flock(fd, _fcntl.LOCK_EX)
                tail, ends_newline = _tail_entry(fd)
                seq = 1
                prev = CHAIN_GENESIS
                if tail is not None:
                    last = tail.get("seq")
                    seq = (last + 1) if isinstance(last, int) and not isinstance(last, bool) else 1
                    prev = str(tail.get("hash") or CHAIN_GENESIS)
                entry = {**clean, "seq": seq}
                entry["prev_hash"] = prev
                entry["hash"] = chain_hash(prev, entry)
                text = ("" if ends_newline else "\n") + canonical_json(entry) + "\n"
                _write_all(fd, text.encode("utf-8", errors="surrogatepass"))
                os.fsync(fd)
            finally:
                os.close(fd)
        return entry

    def entries(self) -> list[dict[str, Any]]:
        """The parsable lines (no verification; :func:`verify_chain` checks them)."""
        try:
            data = _read_regular(self.path)
        except OSError:
            return []
        out: list[dict[str, Any]] = []
        for raw in data.split(b"\n"):
            if not raw.strip():
                continue
            try:
                entry = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                continue
            if isinstance(entry, dict):
                out.append(entry)
        return out

    def head(self) -> tuple[int, str]:
        """``(lines, hash of the last line)``; ``(0, CHAIN_GENESIS)`` for a missing or empty file."""
        items = self.entries()
        if not items:
            return 0, CHAIN_GENESIS
        last = items[-1]
        seq = last.get("seq")
        return (int(seq) if isinstance(seq, int) else len(items)), str(last.get("hash") or "")

    def verify(self) -> ChainCheck:
        return verify_chain(self.path)


# ======================================================================================
# helpers
# ======================================================================================


def _redact(text: str) -> str:
    try:
        from v3lum.core import redact
    except ImportError:  # pragma: no cover - redactor not installed
        return text
    return str(redact.redact_text(text))


def _redact_url(url: Any) -> str:
    try:
        from v3lum.core import redact
    except ImportError:  # pragma: no cover
        return str(url or "")
    return str(redact.redact_url(str(url or "")))


def _name_part(entity: Any) -> tuple[str, str]:
    """``(entity_hmac, name part)``: the keyed HMAC of the entity value (A4 BR7) and its first 12 hex
    characters for the file name. When the installation secret is unavailable the HMAC is '' and the
    name part random: a plain hash of the value could be tested against guessed values (an e-mail
    address, a phone number), which is what the keyed HMAC prevents."""
    try:
        from v3lum.core import hmacid

        part = str(hmacid.hmac12(entity.type, entity.value))
        full = str(hmacid.hmac_hex(entity.type, entity.value))
        if not full.startswith(part):
            full = ""
        return full, part
    except Exception:  # noqa: BLE001 - the name only needs to be value-free; never fail the evidence
        return "", secrets.token_hex(6)


def _pseudonym(entity: Any) -> str:
    """Keyed HMAC (12 hex) of the entity value, random when the installation secret is unavailable."""
    return _name_part(entity)[1]


def _etype_name(entity: Any) -> str:
    return str(getattr(getattr(entity, "type", None), "value", "") or getattr(entity, "type", "") or "")


def _file_name(module: str, etype: str, part: str, digest: str, *, compressed: bool = False) -> str:
    mod = _SAFE.sub("_", str(module or ""))[:64] or "module"
    kind = _SAFE.sub("_", str(etype or ""))[:32] or "entity"
    tag = _SAFE.sub("_", str(part or ""))[:12] or "0" * 12
    return f"{mod}__{kind}__{tag}__{digest[:10]}.json" + (".gz" if compressed else "")


def evidence_name(module: str, entity: Any, digest: str, *, compressed: bool = False) -> str:
    """``<module>__<type>__<hmac12>__<sha10>.json`` (``.json.gz`` for compressed records): no
    investigated value in the name."""
    return _file_name(module, _etype_name(entity), _pseudonym(entity), digest, compressed=compressed)


def _secret_map(res: Any) -> dict[str, str]:
    try:
        from v3lum.core.graph import secret_value_map
    except ImportError:  # pragma: no cover - the graph is part of the core
        return {}
    entities = [getattr(res, "entity", None)] + [getattr(p, "entity", None) for p in (getattr(res, "pivots", None) or ())]
    return secret_value_map([e for e in entities if e is not None])


def _without_raw_secrets(value: Any, secret_map: Mapping[str, str]) -> Any:
    """``value`` with every raw SECRET_TYPES value of the run replaced by its persisted form."""
    if not secret_map:
        return value
    from v3lum.core.graph import redact_secret_values

    return redact_secret_values(value, dict(secret_map))


def _as_mapping(info: Any) -> dict[str, Any] | None:
    if isinstance(info, Mapping):
        return dict(info)
    to_dict = getattr(info, "to_dict", None)
    if callable(to_dict):
        try:
            data = to_dict()
        except Exception:  # noqa: BLE001 - a broken record is skipped
            return None
        out = dict(data) if isinstance(data, Mapping) else None
        if out is not None:  # attributes a newer RequestInfo may carry beyond to_dict()
            for name in ("fetched_at", "final_url", "redirect_chain", "history", "headers", "from_cache"):
                if name not in out and hasattr(info, name):
                    out[name] = getattr(info, name)
        return out
    return None


def _utc_iso(value: Any) -> str:
    """An ISO timestamp normalised to UTC ('' when unreadable)."""
    if isinstance(value, _dt.datetime):
        dt = value
    else:
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


def request_record(info: Any) -> dict[str, Any] | None:
    """The request context of one ``RequestInfo`` (or a dict with the same keys) as written in an
    evidence record: method, redacted URL, host, status, bytes, egress profile, opsec, UA,
    ``from_cache``, ``fetched_at`` (the cache row time for an answer served from the cache - None
    when the record does not carry it, never the replay time), ``final_url`` / ``redirect_chain``
    and the response ``headers`` date/content-type/server when recorded, and the P321
    classification. None for anything that is not a request record."""
    data = _as_mapping(info)
    if data is None:
        return None
    out: dict[str, Any] = {k: data[k] for k in _REQUEST_FIELDS if k in data}
    if "url" in out:
        out["url"] = _redact_url(out["url"])
    if "path" in out:
        out["path"] = _redact(str(out["path"] or ""))
    if "user_agent" in out:
        out["user_agent"] = _redact(str(out["user_agent"] or ""))
    if "error" in out:
        out["error"] = _redact(str(out["error"] or ""))
    cached = bool(data.get("from_cache", data.get("cached", False)))
    out["from_cache"] = cached
    fetched = data.get("fetched_at")
    if fetched:
        out["fetched_at"] = _utc_iso(fetched)
    else:
        out["fetched_at"] = None if cached else (_utc_iso(data.get("ts")) or None)
    if data.get("final_url"):
        out["final_url"] = _redact_url(data["final_url"])
    chain = data.get("redirect_chain")
    if chain is None and isinstance(data.get("history"), (list, tuple)):
        chain = data["history"]
    if isinstance(chain, (list, tuple)):
        out["redirect_chain"] = [_redact_url(u) for u in chain if u]
    headers = data.get("headers") or data.get("response_headers")
    if isinstance(headers, Mapping):
        lower = {str(k).lower(): v for k, v in headers.items()}
        picked = {h: _redact(str(lower[h])) for h in SELECTED_HEADERS if lower.get(h) not in (None, "")}
        if picked:
            out["headers"] = picked
    classification = data.get("classification")
    if isinstance(classification, Mapping):
        out["classification"] = {k: classification.get(k) for k in ("status", "reason_code", "marker_id") if k in classification}
    return json_safe(out)


def request_records(infos: Iterable[Any]) -> list[dict[str, Any]]:
    """:func:`request_record` for every record, with the redirect chains filled in where the records
    do not carry them: the answer that ends a run of 3xx hops gets ``redirect_chain`` (the hop URLs,
    in order) and ``final_url`` (its own URL); the hops themselves are marked ``redirect_hop``.

    Hops are matched per requesting module (and source): records of other requesters logged in
    between - the DoH lookups that pin each hop's target (module ``egress_resolver``), another
    module's requests - never inherit a chain that is not theirs."""
    out = [r for r in (request_record(i) for i in (infos or ())) if r]
    pending: dict[tuple[str, str], list[str]] = {}
    for rec in out:
        who = (str(rec.get("module") or ""), str(rec.get("source") or ""))
        if "redirect_chain" in rec and "final_url" in rec:
            pending.pop(who, None)
            continue
        method = str(rec.get("method") or "").upper()
        status = rec.get("status") if isinstance(rec.get("status"), int) else 0
        if method in ("CONNECT", "EXEC"):
            pending.pop(who, None)
            continue
        if status in _REDIRECT_STATUSES and not rec.get("error") and not rec.get("from_cache"):
            rec["redirect_hop"] = True
            pending.setdefault(who, []).append(str(rec.get("url") or ""))
            continue
        rec.setdefault("final_url", rec.get("url"))
        rec.setdefault("redirect_chain", pending.pop(who, []))
    return out


def _leaves(value: Any, prefix: tuple[Any, ...], out: dict[tuple[Any, ...], tuple[str, Any]]) -> bool:
    """Flatten ``value`` into ``out`` (path -> (type, value)); False when the leaf budget is spent."""
    if len(out) > _MAX_LEAVES:
        return False
    if isinstance(value, Mapping):
        if not value:
            out[prefix] = ("dict", None)
        return all(_leaves(v, prefix + (str(k),), out) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        if not value:
            out[prefix] = ("list", None)
        return all(_leaves(v, prefix + (i,), out) for i, v in enumerate(value))
    out[prefix] = (type(value).__name__, value)
    return True


def diff_summary(old: Any, new: Any) -> dict[str, Any]:
    """What changed between two collections of the same record: ``added`` / ``removed`` top-level
    keys (plain field names only; keys that are values - an e-mail address, a domain - are counted
    in ``added_count`` / ``removed_count`` but never written) and ``changed_leaves`` (leaf values
    added, removed or modified anywhere in the payload; None for very large payloads)."""
    old_keys = {str(k) for k in old} if isinstance(old, Mapping) else set()
    new_keys = {str(k) for k in new} if isinstance(new, Mapping) else set()
    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    before: dict[tuple[Any, ...], tuple[str, Any]] = {}
    after: dict[tuple[Any, ...], tuple[str, Any]] = {}
    complete = _leaves(old, (), before) and _leaves(new, (), after)
    changed: int | None = None
    if complete:
        changed = sum(1 for p in set(before) | set(after) if before.get(p) != after.get(p))
    return {
        "added": [k for k in added if _FIELD_NAME.match(k)],
        "removed": [k for k in removed if _FIELD_NAME.match(k)],
        "added_count": len(added),
        "removed_count": len(removed),
        "changed_leaves": changed,
    }


def _encode_json(content: Mapping[str, Any]) -> bytes:
    """The evidence record as stored before compression: indented JSON passed through the central
    redactor (AR01: configured key values and key-like URL parameters never reach a file)."""
    text = json.dumps(content, ensure_ascii=False, indent=1, default=str)
    try:
        return _redact(text).encode("utf-8")
    except UnicodeEncodeError:  # lone surrogates: the escaped (ASCII) form is still valid JSON
        return _redact(json.dumps(content, ensure_ascii=True, indent=1, default=str)).encode("utf-8")


def _data_digest(data: Any) -> str:
    text = _redact(json.dumps(data, ensure_ascii=False, sort_keys=True, default=str))
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def read_evidence(path: str | os.PathLike[str], *, max_bytes: int = _MAX_READ_BYTES) -> dict[str, Any]:
    """An evidence record read back (gzip-compressed files are decompressed, at most ``max_bytes``).
    Never follows a symbolic link; raises OSError/ValueError for an unreadable record."""
    data = _read_regular(Path(path))
    if data[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            data = gz.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"{path}: decompressed record larger than {max_bytes} bytes")
    record = json.loads(data.decode("utf-8"))
    if not isinstance(record, dict):
        raise ValueError(f"{path}: not an evidence record")
    return record


def sha256_file(path: str | os.PathLike[str]) -> str:
    """SHA-256 of a regular file, read in chunks (never through a symbolic link: OSError)."""
    path = Path(path)
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise OSError(f"{path} is a symbolic link")
    if not stat.S_ISREG(st.st_mode):
        raise OSError(f"{path} is not a regular file")
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_once(path: Path, data: bytes, digest: str) -> None:
    """Create ``path`` with ``data`` (0600) unless it exists. An existing regular file with the same
    bytes is accepted (content addressing: same name, same bytes); a symbolic link or a file with
    other bytes raises OSError. The bytes are written to a temporary file first and hard-linked into
    place, so a crash never leaves a partial file under a content-addressed name."""
    tmp = path.parent / f".{path.name}.{os.getpid()}.{threading.get_ident()}.{secrets.token_hex(4)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, _FILE_MODE)
    try:
        try:
            if os.name == "posix":
                os.fchmod(fd, _FILE_MODE)
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(tmp, path)
        except FileExistsError:
            _accept_existing(path, digest)
        except OSError:  # no hard links on this filesystem: exclusive create of the name itself
            try:
                fd2 = os.open(path, flags, _FILE_MODE)
            except FileExistsError:
                _accept_existing(path, digest)
                return
            try:
                if os.name == "posix":
                    os.fchmod(fd2, _FILE_MODE)
                _write_all(fd2, data)
                os.fsync(fd2)
            finally:
                os.close(fd2)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _accept_existing(path: Path, digest: str) -> None:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise OSError(f"{path} is a symbolic link: evidence is never written through a link")
    if not stat.S_ISREG(st.st_mode):
        raise OSError(f"{path} exists and is not a regular file")
    if sha256_file(path) != digest:
        raise OSError(f"{path} exists with other bytes: evidence files are write-once (tampered?)")


# ======================================================================================
# evidence record
# ======================================================================================


@dataclass
class EvidenceRecord:
    """One stored evidence version (the file content is :meth:`to_dict`).

    Content: ``module``, ``entity_type``, ``entity_hmac`` (keyed HMAC, '' when the installation
    secret is unavailable), ``record_key`` (``module|entity_hmac``), ``version``,
    ``previous_sha256``, ``diff_summary``, ``case_id``, ``collected_at``, ``fetched_at``,
    ``status``, ``partial``, ``requests``, ``datasets``, ``redacted_fields``, ``truncated`` and
    ``data``. Facts of the stored file (never part of the content): ``path``, ``file`` (relative
    to the case directory), ``sha256``, ``size`` (stored bytes), ``compressed``, ``data_sha256``.
    """

    module: str
    entity_type: str
    entity_hmac: str = ""
    record_key: str = ""
    version: int = 1
    collected_at: str = ""
    fetched_at: str = ""
    case_id: str = ""
    status: str = ""
    partial: bool = False
    requests: list[dict[str, Any]] = field(default_factory=list)
    datasets: list[dict[str, Any]] = field(default_factory=list)
    redacted_fields: list[str] = field(default_factory=list)
    data: Any = None
    previous_sha256: str = ""
    diff_summary: dict[str, Any] | None = None
    truncated: dict[str, Any] | None = None
    # ---- facts of the stored file (filled by EvidenceStore.save_record) --------------------
    path: str = ""
    file: str = ""
    sha256: str = ""
    size: int = 0
    compressed: bool = False
    data_sha256: str = ""
    name_part: str = field(default="", repr=False)

    def to_dict(self) -> dict[str, Any]:
        """The stored content (schema ``v3lum.evidence/2``)."""
        return {
            "schema": SCHEMA,
            "case_id": self.case_id,
            "module": self.module,
            "entity_type": self.entity_type,
            "entity_hmac": self.entity_hmac,
            "record_key": self.record_key,
            "version": int(self.version),
            "previous_sha256": self.previous_sha256 or None,
            "collected_at": self.collected_at,
            "fetched_at": self.fetched_at or None,
            "status": self.status,
            "partial": bool(self.partial),
            "requests": list(self.requests),
            "datasets": list(self.datasets),
            "redacted_fields": list(self.redacted_fields),
            "diff_summary": self.diff_summary,
            "truncated": self.truncated,
            "data": self.data,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, path: str = "", sha256: str = "") -> EvidenceRecord:
        """A record read back from a file (unknown keys ignored)."""
        names = {f.name for f in dataclasses.fields(cls)}
        values = {k: v for k, v in data.items() if k in names and k not in ("path", "sha256")}
        values.setdefault("module", "")
        values.setdefault("entity_type", "")
        return cls(**values, path=path, sha256=sha256)

    @classmethod
    def from_result(cls, res: Any, *, requests: Iterable[Any] = (), collected_at: str = "", case_id: str = "") -> EvidenceRecord:
        """The record of one module run: its sanitized raw payload, the run's request records and
        dataset citations; raw SECRET_TYPES values of the run (entity and pivots) are replaced by
        their persisted form everywhere (defence in depth behind the sanitizer)."""
        entity = getattr(res, "entity", None)
        module = str(getattr(res, "module", "") or "")
        full, part = _name_part(entity) if entity is not None else ("", secrets.token_hex(6))
        secret_map = _secret_map(res)
        reqs = _without_raw_secrets(request_records(requests or ()), secret_map)
        fetched = sorted(str(r["fetched_at"]) for r in reqs if r.get("fetched_at"))
        status = getattr(res, "status", "")
        datasets = [json_safe(dict(d)) for d in (getattr(res, "datasets", None) or ()) if isinstance(d, Mapping)]
        return cls(
            module=module,
            entity_type=_etype_name(entity),
            entity_hmac=full,
            record_key=f"{module}|{full}" if full else f"{module}|~{part}",
            collected_at=collected_at,
            fetched_at=fetched[0] if fetched else "",
            case_id=case_id,
            status=str(getattr(status, "value", status) or ""),
            partial=bool(getattr(res, "partial", False)),
            requests=reqs,
            datasets=_without_raw_secrets(datasets, secret_map),
            redacted_fields=[str(f) for f in (getattr(res, "redacted_fields", None) or [])],
            data=_without_raw_secrets(getattr(res, "raw", None), secret_map),
            name_part=part,
        )


# ======================================================================================
# store
# ======================================================================================


def _setting_value(settings: Any, name: str) -> Any:
    if settings is None:
        return None
    getter = getattr(settings, "get", None)
    try:
        return getter(name) if callable(getter) else getattr(settings, name, None)
    except Exception:  # noqa: BLE001 - a broken settings object means the default
        return None


def _int_or(value: Any, default: int) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


class EvidenceStore:
    """Writes the evidence of one case (see the module docstring).

    ``EvidenceStore(case_dir, *, now=None, store=None, case_id=None, max_file_bytes=None,
    max_case_bytes=None, settings=None)``: ``now`` is the clock of ``collected_at`` (the runtime's);
    ``store`` + ``case_id`` (default: the directory name) also write each version to the case DB's
    ``evidence_versions`` table at once; the caps default to the settings (``settings`` or the
    loaded Config) ``evidence_max_file_bytes`` / ``evidence_max_case_bytes`` (0 = no cap).
    """

    def __init__(
        self,
        case_dir: str | Path,
        *,
        now: Callable[[], _dt.datetime] | None = None,
        store: Any = None,
        case_id: str | None = None,
        max_file_bytes: int | None = None,
        max_case_bytes: int | None = None,
        settings: Any = None,
    ) -> None:
        self.case_dir = Path(case_dir)
        self._now = now
        self.store = store
        self.case_id = str(case_id or self.case_dir.name)
        self._settings = settings
        self._max_file = max_file_bytes
        self._max_case = max_case_bytes
        self._lock = threading.RLock()
        self._index = ChainedLog(self.case_dir / EVIDENCE_INDEX)
        self._latest: dict[str, dict[str, Any]] = {}
        self._case_bytes = 0
        self._index_sig: tuple[int, int] | None = None
        #: the last record stored or returned by :meth:`save` / :meth:`save_record`
        self.last: EvidenceRecord | None = None

    # ------------------------------------------------------------------ layout
    @property
    def directory(self) -> Path:
        return self.case_dir / EVIDENCE_DIR

    @property
    def index_path(self) -> Path:
        return self._index.path

    def _now_iso(self) -> str:
        now = self._now() if self._now is not None else _dt.datetime.now(_dt.timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=_dt.timezone.utc)
        return now.astimezone(_dt.timezone.utc).isoformat(timespec="seconds")

    def ensure_dirs(self) -> Path:
        """Create the case and evidence directories owner-only (0700)."""
        for directory in (self.case_dir, self.directory):
            _ensure_dir(directory)
        return self.directory

    def caps(self) -> tuple[int, int]:
        """``(max_file_bytes, max_case_bytes)``; 0 = no cap."""
        settings = self._settings
        if settings is None and (self._max_file is None or self._max_case is None):
            try:
                from v3lum.config import Config

                settings = self._settings = Config.load()
            except Exception:  # noqa: BLE001 - a broken config means the defaults
                settings = None
        file_cap = self._max_file if self._max_file is not None else _setting_value(settings, "evidence_max_file_bytes")
        case_cap = self._max_case if self._max_case is not None else _setting_value(settings, "evidence_max_case_bytes")
        return max(0, _int_or(file_cap, DEFAULT_MAX_FILE_BYTES)), max(0, _int_or(case_cap, DEFAULT_MAX_CASE_BYTES))

    # ------------------------------------------------------------------ index state
    def _load_index(self) -> None:
        """(Re)load the latest version per record key and the stored bytes from the index when the
        index file changed (another writer, a new store over an existing case)."""
        try:
            st = os.lstat(self.index_path)
            sig: tuple[int, int] | None = (st.st_size, st.st_mtime_ns)
        except FileNotFoundError:
            sig = None
        if sig == self._index_sig and (sig is not None or self._latest):
            return
        latest: dict[str, dict[str, Any]] = {}
        total = 0
        entries = self._index.entries()
        for entry in entries:
            key = str(entry.get("record_key") or "")
            if key:
                old = latest.get(key)
                if old is None or int(entry.get("version") or 0) >= int(old.get("version") or 0):
                    latest[key] = entry
            total += _int_or(entry.get("bytes"), 0)
        if not entries and self.directory.is_dir():  # a v1 case directory: count what is there
            for item in self.directory.iterdir():
                try:
                    st2 = os.lstat(item)
                except OSError:
                    continue
                if stat.S_ISREG(st2.st_mode):
                    total += st2.st_size
        self._latest, self._case_bytes, self._index_sig = latest, total, sig

    def versions(self, record_key: str | None = None) -> list[dict[str, Any]]:
        """Index entries (every stored version, or those of one record key), oldest first."""
        items = self._index.entries()
        return [e for e in items if record_key is None or e.get("record_key") == record_key]

    def latest(self, record_key: str) -> dict[str, Any] | None:
        """The index entry of the newest version of ``record_key`` (None when never stored)."""
        with self._lock:
            self._load_index()
            entry = self._latest.get(record_key)
            return dict(entry) if entry is not None else None

    # ------------------------------------------------------------------ writing
    def save(self, res: Any, *, requests: Iterable[Any] = ()) -> tuple[str, str]:
        """Write the evidence of ``res`` (a ModuleResult); returns ``(path, sha256)`` of the stored
        version (the existing one when the payload did not change).

        Raises OSError/TypeError/ValueError when the file cannot be written (the caller keeps the
        result and notes the failure; a payload nested too deeply to encode is a ValueError, never
        an exception that would stop the scan).
        """
        try:
            record = EvidenceRecord.from_result(res, requests=requests, collected_at=self._now_iso(), case_id=self.case_id)
            stored = self.save_record(record)
        except RecursionError as exc:
            raise ValueError("evidence payload nested too deeply to be stored") from exc
        return stored.path, stored.sha256

    def save_record(self, record: EvidenceRecord) -> EvidenceRecord:
        """Store ``record`` as a new version of its record key (or return the newest version when its
        data is unchanged and that file is intact); returns the record with the file facts set."""
        with self._lock:
            self._load_index()
            record.data_sha256 = _data_digest(record.data)
            previous = self._latest.get(record.record_key) if record.record_key else None
            if previous is not None and previous.get("data_sha256") == record.data_sha256 and not previous.get("truncated"):
                existing = self._intact(previous)
                if existing is not None:
                    self.last = existing
                    return existing
            if previous is not None:
                record.version = _int_or(previous.get("version"), 0) + 1
                record.previous_sha256 = str(previous.get("sha256") or "")
                record.diff_summary = self._diff_against(previous, record.data)
            else:
                record.version = max(1, int(record.version or 1))
            stored, compressed = self._fit(record)
            digest = hashlib.sha256(stored).hexdigest()
            name = _file_name(record.module, record.entity_type, record.name_part, digest, compressed=compressed)
            path = self.ensure_dirs() / name
            # evidence can hold provider data about people: owner-only from creation (A10/AR03),
            # write-once, never through a link planted at the name
            _write_once(path, stored, digest)
            record.path, record.file, record.sha256 = str(path), f"{EVIDENCE_DIR}/{name}", digest
            record.size, record.compressed = len(stored), compressed
            entry = {
                "file": record.file,
                "sha256": digest,
                "record_key": record.record_key,
                "version": record.version,
                "module": record.module,
                "entity_type": record.entity_type,
                "collected_at": record.collected_at,
                "fetched_at": record.fetched_at or None,
                "bytes": record.size,
                "compressed": compressed,
                "truncated": bool(record.truncated),
                "data_sha256": record.data_sha256,
                "previous_sha256": record.previous_sha256 or None,
                "diff_summary": record.diff_summary,
            }
            try:
                written = self._index.append(entry)
            except BaseException:
                try:  # not indexed = not evidence: never leave an unlisted file behind
                    os.unlink(path)
                except OSError:
                    pass
                raise
            self._latest[record.record_key] = written
            self._case_bytes += record.size
            try:
                self._index_sig = (os.lstat(self.index_path).st_size, os.lstat(self.index_path).st_mtime_ns)
            except OSError:  # pragma: no cover
                self._index_sig = None
            if self.store is not None:
                try:
                    sync_versions(self.store, self.case_id, self.case_dir, entries=[written])
                except (sqlite3.Error, OSError) as exc:  # the index is authoritative; the hook syncs later
                    log.warning("evidence version not recorded in the case DB: %s", type(exc).__name__)
            self.last = record
            return record

    def _intact(self, entry: Mapping[str, Any]) -> EvidenceRecord | None:
        """The stored version ``entry`` as a record when its file is intact; None when it is missing
        or was changed (a new version is then written); OSError for a planted symbolic link."""
        rel = str(entry.get("file") or "")
        if not _safe_relpath(rel):
            return None
        path = self.case_dir / rel
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(st.st_mode):
            raise OSError(f"{path} is a symbolic link: evidence is never read or written through a link")
        try:
            if sha256_file(path) != entry.get("sha256"):
                return None
        except OSError:
            return None
        rec = EvidenceRecord(
            module=str(entry.get("module") or ""), entity_type=str(entry.get("entity_type") or ""), record_key=str(entry.get("record_key") or ""),
            version=_int_or(entry.get("version"), 1), collected_at=str(entry.get("collected_at") or ""), fetched_at=str(entry.get("fetched_at") or ""),
            case_id=self.case_id, path=str(path), file=rel, sha256=str(entry.get("sha256") or ""), size=_int_or(entry.get("bytes"), 0),
            compressed=bool(entry.get("compressed")), data_sha256=str(entry.get("data_sha256") or ""),
        )
        return rec

    def _diff_against(self, previous: Mapping[str, Any], data: Any) -> dict[str, Any]:
        rel = str(previous.get("file") or "")
        summary_base = {"previous_version": _int_or(previous.get("version"), 0)}
        if previous.get("truncated"):
            return {**summary_base, "previous_truncated": True, **diff_summary(None, data)}
        try:
            if not _safe_relpath(rel):
                raise ValueError("invalid path")
            old = read_evidence(self.case_dir / rel).get("data")
        except (OSError, ValueError) as exc:
            log.warning("previous evidence version unreadable: %s", type(exc).__name__)
            return {**summary_base, "previous_unreadable": True, **diff_summary(None, data)}
        return {**summary_base, **diff_summary(old, data)}

    def _fit(self, record: EvidenceRecord) -> tuple[bytes, bool]:
        """The stored bytes of ``record`` within the caps (``record.data``/``truncated`` are changed
        when the payload must be cut); returns ``(bytes, compressed)``."""
        file_cap, case_cap = self.caps()
        remaining = max(0, case_cap - self._case_bytes) if case_cap > 0 else None
        limits = [cap for cap in (file_cap if file_cap > 0 else None, remaining) if cap is not None]
        stored, compressed = _store_bytes(record.to_dict())
        if not limits or len(stored) <= min(limits):
            return stored, compressed
        limit = min(limits)
        by_case = remaining is not None and (file_cap <= 0 or remaining < file_cap)
        reason = "evidence_max_case_bytes" if by_case else "evidence_max_file_bytes"
        text = _redact(json.dumps(record.data, ensure_ascii=False, default=str))
        original = text.encode("utf-8", errors="surrogatepass")
        marker = {"reason": reason, "limit": limit, "original_bytes": len(original), "original_sha256": hashlib.sha256(original).hexdigest()}
        keep = len(text)
        while keep > 0 and limit > _STUB_ROOM:
            ratio = min(0.9, limit / max(1, len(stored)))
            keep = int(keep * ratio)
            record.data = text[:keep]
            record.truncated = {**marker, "kept_chars": keep, "note": "data cut: a prefix of its JSON text is kept"}
            stored, compressed = _store_bytes(record.to_dict())
            if len(stored) <= limit:
                return stored, compressed
        record.data = None
        record.truncated = {**marker, "kept_chars": 0, "note": "data dropped: the evidence cap leaves no room (request context kept)"}
        return _store_bytes(record.to_dict())


def _store_bytes(content: Mapping[str, Any]) -> tuple[bytes, bool]:
    raw = _encode_json(content)
    if len(raw) > GZIP_THRESHOLD:
        return gzip.compress(raw, compresslevel=6, mtime=0), True
    return raw, False


def _safe_relpath(rel: str) -> bool:
    """A path inside the evidence directory (``evidence/<name>``): no absolute path, no '..'."""
    if not rel or rel.startswith(("/", "\\")):
        return False
    parts = rel.replace("\\", "/").split("/")
    return len(parts) == 2 and parts[0] == EVIDENCE_DIR and parts[1] not in ("", ".", "..")


# ======================================================================================
# manifest, case DB rows, verification
# ======================================================================================


def manifest(case_dir: str | os.PathLike[str]) -> list[tuple[str, str]]:
    """``[(file, sha256)]`` of the case's evidence (``file`` relative to the case directory), in the
    order of the evidence index. A case directory without an index (written before evidence v2)
    lists its evidence files with their current SHA-256."""
    base = Path(case_dir)
    entries = ChainedLog(base / EVIDENCE_INDEX).entries()
    if entries:
        return [(str(e.get("file") or ""), str(e.get("sha256") or "")) for e in entries if e.get("file")]
    directory = base / EVIDENCE_DIR
    out: list[tuple[str, str]] = []
    if directory.is_dir():
        for item in sorted(directory.iterdir()):
            if item.name.startswith("."):
                continue
            try:
                out.append((f"{EVIDENCE_DIR}/{item.name}", sha256_file(item)))
            except OSError:
                continue
    return out


def sync_versions(store: Any, case_id: str, case_dir: str | os.PathLike[str], *, entries: Iterable[Mapping[str, Any]] | None = None) -> int:
    """Write the evidence index entries of a case to the case DB's append-only ``evidence_versions``
    table (``INSERT OR IGNORE``: an existing version row is never changed). Returns the rows added."""
    items = list(entries) if entries is not None else ChainedLog(Path(case_dir) / EVIDENCE_INDEX).entries()
    rows = []
    for e in items:
        key, version, digest = str(e.get("record_key") or ""), e.get("version"), str(e.get("sha256") or "")
        if not key or not isinstance(version, int) or not digest:
            continue
        diff = e.get("diff_summary")
        rows.append((
            str(case_id), key, int(version), digest, str(e.get("file") or ""), str(e.get("collected_at") or "") or None,
            str(e.get("fetched_at") or "") or None, canonical_json(diff) if diff is not None else None,
        ))
    if not rows:
        return 0
    with store.connection() as conn:
        before = conn.total_changes
        conn.executemany(
            "INSERT OR IGNORE INTO evidence_versions (case_id, record_key, version, sha256, path, collected_at, fetched_at, diff_summary)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        return conn.total_changes - before


@dataclass
class EvidenceCheck:
    """Outcome of :func:`verify_evidence`."""

    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    files: int = 0
    versions: int = 0
    index: ChainCheck | None = None


def _sha10_of(name: str) -> str:
    stem = name[:-8] if name.endswith(".json.gz") else (name[:-5] if name.endswith(".json") else name)
    return stem.rsplit("__", 1)[-1] if "__" in stem else ""


def verify_evidence(
    case_dir: str | os.PathLike[str],
    *,
    rows: Iterable[Mapping[str, Any]] | None = None,
    anchor: Mapping[str, Any] | None = None,
) -> EvidenceCheck:
    """Recompute every evidence hash of a case offline.

    Checks the evidence index chain (:func:`verify_chain`), every listed file against its recorded
    SHA-256 and against the hash in its name, files in the evidence directory that the index does
    not list, the case DB rows ``rows`` (``evidence_versions``: record_key, version, sha256, path)
    against the index, and the index head against ``anchor`` (``{'versions': n, 'index_head': h}``
    recorded by the audit's ``case_end`` row). A directory written before evidence v2 (no index) is
    checked through the hashes in the file names."""
    base = Path(case_dir)
    out = EvidenceCheck()
    directory = base / EVIDENCE_DIR
    chain = verify_chain(base / EVIDENCE_INDEX, label=EVIDENCE_INDEX)
    out.index = chain
    out.problems.extend(chain.problems)
    entries = chain.entries
    listed: dict[str, str] = {}
    for number, e in enumerate(entries, 1):
        rel, digest = str(e.get("file") or ""), str(e.get("sha256") or "")
        if not _safe_relpath(rel) or not _HEX.match(digest):
            out.problems.append(f"{EVIDENCE_INDEX} line {number}: invalid file name or SHA-256")
            continue
        if rel in listed and listed[rel] != digest:
            out.problems.append(f"{rel}: listed twice with different hashes")
        listed[rel] = digest
        out.versions += 1
        try:
            actual = sha256_file(base / rel)
        except FileNotFoundError:
            out.problems.append(f"{rel}: evidence file missing (listed in {EVIDENCE_INDEX})")
            continue
        except OSError as exc:
            out.problems.append(f"{rel}: {exc}")
            continue
        out.files += 1
        if actual != digest:
            out.problems.append(f"{rel}: SHA-256 {actual[:16]}... does not match the recorded {digest[:16]}... (file changed)")
        if _sha10_of(rel.split("/", 1)[1]) != digest[:10]:
            out.problems.append(f"{rel}: the hash in the file name does not match the recorded SHA-256 (renamed)")
    if directory.is_dir():
        for item in sorted(directory.iterdir()):
            rel = f"{EVIDENCE_DIR}/{item.name}"
            if rel in listed:
                continue
            if item.name.startswith(".") and item.name.endswith(".tmp"):
                out.warnings.append(f"{rel}: leftover temporary file of an interrupted write")
                continue
            if chain.exists:
                out.problems.append(f"{rel}: evidence file not listed in {EVIDENCE_INDEX} (added or renamed)")
                continue
            try:  # evidence v1 directory: the name carries the content hash
                actual = sha256_file(item)
            except OSError as exc:
                out.problems.append(f"{rel}: {exc}")
                continue
            out.files += 1
            if _sha10_of(item.name) != actual[:10]:
                out.problems.append(f"{rel}: SHA-256 {actual[:16]}... does not match the hash in its name (file changed)")
        if not chain.exists and out.files:
            out.warnings.append(f"no {EVIDENCE_INDEX} (evidence written before v2): files checked against the hashes in their names")
    db_rows = [dict(r) for r in (rows or ())]
    if db_rows:
        by_version = {(str(e.get("record_key") or ""), e.get("version")): e for e in entries}
        seen: set[tuple[str, Any]] = set()
        for r in db_rows:
            key = (str(r.get("record_key") or ""), r.get("version"))
            seen.add(key)
            e = by_version.get(key)
            if e is None:
                out.problems.append(f"evidence version {key[1]} of {key[0].split('|', 1)[0]} is in the case DB but not in {EVIDENCE_INDEX}")
            elif _row_differs(r, e):
                out.problems.append(f"evidence version {key[1]} of {key[0].split('|', 1)[0]}: the case DB row differs from {EVIDENCE_INDEX}")
        for e in entries:
            key = (str(e.get("record_key") or ""), e.get("version"))
            if key not in seen:
                out.problems.append(f"evidence version {key[1]} of {key[0].split('|', 1)[0]} is in {EVIDENCE_INDEX} but not in the case DB")
    elif entries:
        out.warnings.append("evidence versions are not recorded in the case DB (no audit hook ran): checked against the index only")
    if anchor:
        count = _int_or(anchor.get("versions"), -1)
        head = str(anchor.get("index_head") or "")
        if count >= 0:
            if chain.lines < count:
                out.problems.append(f"{EVIDENCE_INDEX} has {chain.lines} lines, the audit recorded {count} at case end (lines removed)")
            elif count > 0 and chain.hash_at(count) != head:  # physical line (a torn line hashes '')
                out.problems.append(f"{EVIDENCE_INDEX} line {count} does not match the head recorded by the audit at case end")
            elif count == 0 and head and head != CHAIN_GENESIS:
                out.problems.append(f"{EVIDENCE_INDEX}: the audit recorded an unexpected empty head")
            if chain.lines > count and not out.problems:
                out.warnings.append(f"{chain.lines - count} evidence version(s) indexed after the last case_end row (not anchored by the audit)")
    return out


def _row_differs(row: Mapping[str, Any], entry: Mapping[str, Any]) -> bool:
    """True when an ``evidence_versions`` row does not say what its index line says: sha256 and
    path always; collected_at, fetched_at and diff_summary when the row carries those columns (the
    rows :func:`sync_versions` writes)."""
    if str(row.get("sha256") or "") != str(entry.get("sha256") or "") or str(row.get("path") or "") != str(entry.get("file") or ""):
        return True
    for column in ("collected_at", "fetched_at"):
        if column in row and (str(row.get(column) or "") or None) != (str(entry.get(column) or "") or None):
            return True
    if "diff_summary" in row:
        diff = entry.get("diff_summary")
        if (row.get("diff_summary") or None) != (canonical_json(diff) if diff is not None else None):
            return True
    return False
