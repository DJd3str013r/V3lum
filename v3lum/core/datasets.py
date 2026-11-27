"""Bundled and downloadable datasets: the dataset manager v2 (AR10, module-author contract v2 s.9).

* ``bundled_*``: files shipped in ``v3lum/data`` (TLDs, PSL, site lists...). Only permissive data
  is bundled (MIT/BSD/Apache-2.0/CC0/CC BY 4.0, IANA public data, the unmodified PSL); GPL, CC BY-SA
  and non-commercial data is downloaded at runtime only (A6).
* Downloadable datasets are registered at import time by the module file that uses them::

      from v3lum.core.datasets import register_dataset
      KEV = register_dataset(
          "cisa_kev.json", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
          ttl=86400, licence="CC0-1.0", terms_class="open", provider="cisa", source="cisa.kev",
          expect="json", min_bytes=1000, max_bytes=5_000_000, description="CISA KEV catalogue")

  and read through ``ctx.data`` (a :class:`DataView`): ``fetch/fetch_text/fetch_json/fetch_lines(name)``,
  ``index(name).contains(value)``, ``info(name)``. ``v3lum data update`` refreshes them ahead of time.

Download path (fail closed, the previous copy always survives a bad refresh): through the runtime
HTTP client with a dataset scope (provider/source of the registration, host allow-list = the URL
host plus the provider's hosts) -> conditional GET (``If-None-Match``/``If-Modified-Since`` from the
MANIFEST) -> body written to a unique temp file in the datasets directory -> P321 classification
(challenge/quota/error pages are failures) -> ``min_bytes`` -> HTML sniff and the ``expect`` parse
check -> archive extraction (:func:`safe_extract`) -> ``pinned_sha256`` / active pin -> the
``validate(path)`` callback -> only then ``os.replace``. On failure the previous copy is kept and
:class:`DatasetError` is raised, or the stale copy is returned by ``fetch``.

Ad-hoc downloads (the v1 form ``ctx.data.fetch(name, url)`` with an unregistered name) are not
datasets of the registry: :class:`DataView` sends them through the calling module's own HTTP scope
(``ctx.http``: its declared hosts, disclosure, request cap, deadline, run/scope binding and egress
profile), never through a dataset scope (P327 cond 5, A7). The download is then refused exactly
like ``ctx.http`` would refuse it: the ``PolicyError`` propagates (SKIPPED 'policy' for an
undeclared host or a disclosure-'none' module, SKIPPED 'scope' outside an ACTIVE scope) and no stale
copy masks the refusal. A dataset registered after the run started (registrations happen at import
time; one made during the run is not reviewed) is routed the same way: every registration carries a
sequence number and the view, built when the run starts, knows which existed then. The module scope
must be a module ``ScopedHttp`` (a raw client or a core scope is refused). During a scan such a
download without a module scope (the store reached around ``ctx.data``), or a ``DataStore.update``
of a dataset registered after the scan started (``Runtime.scan_dataset_seq``), is refused as well.
Registered datasets keep their reviewed dataset scope.

During a scan (``Runtime.in_scan``) datasets that are large (``large=True``, a declared
``max_bytes`` above 5 MB, or a known size above 5 MB) are never downloaded: an existing copy is
served at once (marked stale when old) and a missing one raises :class:`DatasetUnavailable`
(UNAVAILABLE, reason_code 'dataset': 'run v3lum data update <name>'). Other downloads during a scan
are capped at 5 MB (A6 BR9).

Datasets that drive LIGHT/ACTIVE behaviour (``active=True``) are installed only by ``update()``
and served only while their SHA-256 matches a pin: the bundled ``v3lum/data/active_locks/<name>.json``
(schema ``v3lum.active_lock/1``) or the analyst-accepted ``~/.v3lum/datasets/active.lock``. A changed
active dataset is accepted only with ``update(name, accept_new=True)`` after its diff summary.

``~/.v3lum/datasets/MANIFEST.json`` records per dataset: url (redacted), fetched_at, sha256, bytes,
etag, last_modified, licence, terms_class, attribution, provider, source and stale. Modules cite
what they used through ``ctx.data.used`` (name, sha256, fetched_at, licence).
"""

from __future__ import annotations

import bz2
import csv
import functools
import gzip
import hashlib
import inspect
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import tempfile
import threading
import time
import zipfile
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from v3lum import paths
from v3lum.core import http as _http

if TYPE_CHECKING:  # pragma: no cover
    from v3lum.core.context import Runtime

__all__ = [
    "ACTIVE_LOCK_SCHEMA",
    "DATASETS",
    "DATASET_NAME_RE",
    "DataStore",
    "DataView",
    "DatasetError",
    "DatasetIndex",
    "DatasetInfo",
    "DatasetUnavailable",
    "INDEX_MEMORY_LIMIT",
    "LARGE_BYTES",
    "UpdateResult",
    "check_name",
    "dataset_errors",
    "register_dataset",
    "safe_extract",
    "unregister_dataset",
]

DATASET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
#: Names that collide with the manager's own files in the datasets directory.
RESERVED_NAMES = frozenset({"manifest.json", "active.lock"})
EXPECTS = ("bytes", "json", "lines", "csv", "text")
ARCHIVES = ("gz", "bz2", "zip")
TERMS_CLASSES = ("open", "key-terms", "license", "noncommercial", "unknown")
DEFAULT_TTL = 86400.0
DEFAULT_MAX_BYTES = 200 * 1024 * 1024
#: Datasets above this size are never downloaded during a scan (A6 BR9).
LARGE_BYTES = 5 * 1024 * 1024
#: Above this many entries ``index()`` builds a SQLite index instead of an in-memory frozenset.
INDEX_MEMORY_LIMIT = 1_000_000
DOWNLOAD_TIMEOUT = 120.0
MANIFEST_FILE = "MANIFEST.json"
USER_LOCK_FILE = "active.lock"
MANIFEST_SCHEMA = "v3lum.datasets_manifest/1"
ACTIVE_LOCK_SCHEMA = "v3lum.active_lock/1"
USER_LOCK_SCHEMA = "v3lum.active_lock_user/1"
#: Licences of the bundled core files (citations of bundled data).
BUNDLED_LICENCES: dict[str, str] = {"iana_tlds.txt": "IANA public data", "public_suffix_list.dat": "MPL-2.0"}

_RATIO_FLOOR = 1024 * 1024  # compression-ratio checks start above 1 MiB of expanded data
_KEY_PARAMS = ("key", "apikey", "api_key", "api-key", "token", "access_token", "auth", "auth_key", "sig", "signature", "password", "secret")

# Registry of downloadable datasets (modules register theirs at import time) so that
# ``v3lum data update`` can refresh everything ahead of an offline engagement.
DATASETS: dict[str, dict[str, Any]] = {}
_REG_LOCK = threading.Lock()
#: registration sequence: every registration gets the next number (``DATASETS[name]['seq']``). A
#: dataset registered after a run started (``DataView``) or a scan started (``Runtime.in_scan``) is not
#: a reviewed, import-time registration: its downloads go through the calling module's own scope.
_REG_SEQ = 0


def _registration_seq() -> int:
    """The sequence number of the latest registration (0 before any)."""
    with _REG_LOCK:
        return _REG_SEQ


def _seq_of(reg: dict[str, Any] | None) -> int:
    try:
        return int((reg or {}).get("seq") or 0)
    except (TypeError, ValueError):
        return 0


# --------------------------------------------------------------------------------------
# errors and results
# --------------------------------------------------------------------------------------


class DatasetError(Exception):
    """A dataset could not be downloaded, validated or read (``reason_code`` names why)."""

    def __init__(self, message: str = "", *, reason_code: str = "error", name: str = "") -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.name = name


class DatasetUnavailable(DatasetError):
    """No usable copy of a dataset right now (the engine maps it to UNAVAILABLE / 'dataset').

    Raised during scans for large datasets that were never downloaded, for active datasets
    without a matching pin, and offline: the message says what to run (``v3lum data update <name>``).
    """

    def __init__(self, name: str, message: str = "", reason_code: str = "dataset") -> None:
        super().__init__(message or f"dataset {name} is not available: run v3lum data update {name}", reason_code=reason_code, name=name)
        self.message = str(self)


@dataclass(frozen=True)
class DatasetInfo:
    """What is known about the local copy of a dataset (``present`` False when never downloaded)."""

    name: str
    sha256: str = ""
    fetched_at: str = ""
    bytes: int = 0
    licence: str = ""
    terms_class: str = "unknown"
    attribution: str = ""
    age_hours: float | None = None
    stale: bool = False
    provider: str = ""
    source: str = ""
    present: bool = False
    url: str = ""  # redacted


@dataclass(frozen=True)
class UpdateResult:
    """Outcome of ``update(name)``: status 'updated' | 'unchanged' | 'needs_accept' | 'failed'."""

    name: str
    status: str
    old_sha256: str = ""
    new_sha256: str = ""
    diff_summary: str = ""
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.status in ("updated", "unchanged")


@dataclass
class _Candidate:
    """A downloaded and validated copy waiting to replace the current one."""

    path: Path
    sha256: str
    body_sha256: str
    bytes: int
    etag: str = ""
    last_modified: str = ""
    url: str = ""
    temps: list[Path] = field(default_factory=list)

    def cleanup(self) -> None:
        for tmp in self.temps:
            try:
                if tmp.is_dir():
                    shutil.rmtree(tmp, ignore_errors=True)
                elif tmp.exists():
                    tmp.unlink()
            except OSError:  # pragma: no cover - best effort
                pass


# --------------------------------------------------------------------------------------
# registration
# --------------------------------------------------------------------------------------


def check_name(name: str) -> str:
    """Validate a dataset name (``^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$``, no path separators). Raises ValueError."""
    if not isinstance(name, str) or not DATASET_NAME_RE.match(name):
        raise ValueError(f"invalid dataset name {name!r}: use letters, digits, '.', '_' and '-' only (no path separators)")
    if name.lower() in RESERVED_NAMES:
        raise ValueError(f"dataset name {name!r} is reserved by the dataset manager")
    return name


def register_dataset(
    name: str,
    url: str,
    *,
    ttl: float = DEFAULT_TTL,
    description: str = "",
    licence: str = "",
    terms_class: str = "unknown",
    attribution: str = "",
    provider: str = "",
    source: str = "",
    validate: Callable[[Path], Any] | None = None,
    min_bytes: int = 1,
    expect: str = "bytes",
    pinned_sha256: str = "",
    max_bytes: int | None = None,
    large: bool | None = None,
    essential: bool = False,
    active: bool = False,
    archive: str | None = None,
    member: str = "",
) -> str:
    """Register a downloadable dataset (call at import time in the module file). Returns ``name``.

    ``source`` is the registry source id ('provider.source') the dataset belongs to; ``licence``,
    ``terms_class`` and ``attribution`` feed the notices and the citations. ``validate(path)`` may
    return False or raise to reject a download. ``expect`` selects the parse check ('bytes' | 'json' |
    'lines' | 'csv' | 'text'). ``max_bytes`` defaults to 200 MB (a declared value above 5 MB marks the
    dataset large); ``large`` forces the classification. ``essential`` datasets are fetched by
    ``v3lum data update --essential``; ``active`` datasets drive LIGHT/ACTIVE behaviour and must match
    a pin. ``archive`` ('gz' | 'bz2' | 'zip') with ``member`` extracts the stored file.

    Raises ValueError for an invalid name or field, and when the name is already registered with a
    different URL. Each registration gets the next sequence number (an identical re-registration keeps
    its number): a dataset registered after a run started is not a reviewed registration and
    ``ctx.data`` downloads it through the module's own scope (``ctx.http``), like an ad-hoc URL.
    """
    check_name(name)
    url = str(url or "").strip()
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError(f"dataset {name}: an http(s) URL is required")
    if active and parts.scheme != "https":
        raise ValueError(f"dataset {name}: active datasets are fetched over https only")
    if expect not in EXPECTS:
        raise ValueError(f"dataset {name}: expect must be one of {', '.join(EXPECTS)}")
    if archive is not None and archive not in ARCHIVES:
        raise ValueError(f"dataset {name}: archive must be one of {', '.join(ARCHIVES)} or None")
    if terms_class not in TERMS_CLASSES:
        raise ValueError(f"dataset {name}: terms_class must be one of {', '.join(TERMS_CLASSES)}")
    if pinned_sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", pinned_sha256):
        raise ValueError(f"dataset {name}: pinned_sha256 must be 64 hex characters")
    if validate is not None and not callable(validate):
        raise ValueError(f"dataset {name}: validate must be callable(path)")
    if source and "." not in source:
        raise ValueError(f"dataset {name}: source must be a registry source id 'provider.source'")
    if source and provider and source.split(".", 1)[0] != provider:
        raise ValueError(f"dataset {name}: source {source!r} does not belong to provider {provider!r}")
    if float(ttl) < 0 or int(min_bytes) < 0:
        raise ValueError(f"dataset {name}: ttl and min_bytes must be >= 0")
    effective_max = DEFAULT_MAX_BYTES if max_bytes is None else int(max_bytes)
    if effective_max <= 0:
        raise ValueError(f"dataset {name}: max_bytes must be > 0")
    entry = {
        # v1 keys
        "url": url,
        "ttl": float(ttl),
        "description": description,
        "max_bytes": effective_max,
        # v2 keys
        "licence": licence,
        "terms_class": terms_class,
        "attribution": attribution,
        "provider": provider or (source.split(".", 1)[0] if source else ""),
        "source": source,
        "validate": validate,
        "min_bytes": int(min_bytes),
        "expect": expect,
        "pinned_sha256": pinned_sha256.lower(),
        "large": large,
        "essential": bool(essential),
        "active": bool(active),
        "archive": archive,
        "member": member,
        "max_bytes_declared": max_bytes is not None,
    }
    global _REG_SEQ
    with _REG_LOCK:
        existing = DATASETS.get(name)
        if existing is not None and existing["url"] != url:
            raise ValueError(f"dataset {name!r} is already registered with another URL ({_redact_url(existing['url'])}): pick another name")
        same = existing is not None and {k: v for k, v in existing.items() if k not in ("seq", "validate")} == \
            {k: v for k, v in entry.items() if k != "validate"}
        if same and _seq_of(existing):
            entry["seq"] = _seq_of(existing)  # the same registration again (a re-import): still the reviewed one
        else:
            _REG_SEQ += 1
            entry["seq"] = _REG_SEQ  # a new or changed registration
        DATASETS[name] = entry
    return name


def unregister_dataset(name: str) -> bool:
    """Remove a registration (tests and plugins). Returns True when it existed."""
    with _REG_LOCK:
        return DATASETS.pop(name, None) is not None


def dataset_errors(registry: Any = None) -> list[str]:
    """Registration problems for the registry contract test: unregistered or mismatched sources,
    missing licences, terms classes that differ from the registry evidence."""
    if registry is None:
        try:
            from v3lum.core import providers

            registry = providers.registry()
        except ImportError:  # pragma: no cover - wave-1 transition
            registry = None
    out: list[str] = []
    for name, reg in sorted(DATASETS.items()):
        if not reg.get("licence"):
            out.append(f"dataset {name}: no licence")
        sid = reg.get("source") or ""
        if not sid:
            out.append(f"dataset {name}: no registry source (source='provider.source')")
            continue
        src = registry.source(sid) if registry is not None else None
        if src is None:
            out.append(f"dataset {name}: source {sid!r} is not in the provider registry")
            continue
        cls = getattr(getattr(src, "terms", None), "class_", None)
        if cls and cls != reg.get("terms_class"):
            out.append(f"dataset {name}: terms_class {reg.get('terms_class')!r} differs from the registry class {cls!r} of {sid}")
    return out


# --------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------


def _redact_url(url: str) -> str:
    try:
        from v3lum.core.redact import redact_url
    except ImportError:  # pragma: no cover - wave-1 transition
        redact_url = None
    if redact_url is not None:
        try:
            return str(redact_url(url))
        except Exception:  # noqa: BLE001 - redaction must never break the manager
            pass
    parts = urlsplit(str(url))
    query = [(k, "***" if k.lower() in _KEY_PARAMS else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc.rsplit("@", 1)[-1], parts.path, urlencode(query), ""))


def _redact_text(text: str) -> str:
    try:
        from v3lum.core.redact import redact_text
    except ImportError:  # pragma: no cover
        return text
    try:
        return str(redact_text(text))
    except Exception:  # noqa: BLE001
        return text


def _exc_types(*names: str) -> tuple[type[BaseException], ...]:
    out = []
    for name in names:
        obj = getattr(_http, name, None)
        if isinstance(obj, type) and issubclass(obj, BaseException):
            out.append(obj)
    return tuple(out)


_PROPAGATE = _exc_types("Cancelled", "DeadlineExceeded", "RequestCapReached")
_OFFLINE = _exc_types("OfflineError")
#: a refusal of the calling module's own HTTP scope (ad-hoc downloads): propagated as is
_POLICY = _exc_types("PolicyError")
_HTTP_FAILURES = _exc_types("HttpError", "NetworkError", "PolicyError", "ConfigError")


def _check_module_scope(http: Any) -> None:
    """Raise PolicyError unless ``http`` is a module's own ScopedHttp (``ctx.http``): a raw client
    (``ctx.http.client``, the runtime client) or a core scope (``ctx.doh``) has no module host list,
    disclosure, run/scope binding or request cap, so a download through it is refused (fail closed)."""
    scoped_cls = getattr(_http, "ScopedHttp", None)
    if scoped_cls is None or not isinstance(http, scoped_cls) or getattr(http, "core", False):
        raise _http.PolicyError(
            "policy", f"datasets: http= must be the calling module's own scope (ctx.http), not {type(http).__name__}: "
                      "a raw client or a core scope has no host, scope or egress binding",
        )


def _short(exc: BaseException | str, limit: int = 200) -> str:
    """One-line, bounded error text."""
    text = " ".join(str(exc).split()) or type(exc).__name__
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_SHA_MEMO: dict[str, tuple[tuple[int, int, int, int], str]] = {}
_SHA_LOCK = threading.Lock()


def _stamp(path: Path) -> tuple[int, int, int, int]:
    """Change stamp of a file: inode (os.replace gives a new one), size, mtime and ctime."""
    st = path.stat()
    return (st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _sha256_file(path: Path) -> str:
    stamp = _stamp(path)
    key = str(path)
    with _SHA_LOCK:
        hit = _SHA_MEMO.get(key)
    if hit and hit[0] == stamp:
        return hit[1]
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    digest = h.hexdigest()
    with _SHA_LOCK:
        _SHA_MEMO[key] = (stamp, digest)
    return digest


def _bundled_ref(name: str) -> Any:
    """``v3lum/data/<name>``: a relative path inside the package data (absolute paths, drive
    letters, '..' components and NUL bytes are refused with ValueError)."""
    text = str(name or "").replace("\\", "/")
    if not text or "\x00" in text or text.startswith("/") or re.match(r"^[A-Za-z]:", text) or ".." in PurePosixPath(text).parts:
        raise ValueError(f"invalid bundled data name {str(name)[:80]!r}: a relative path inside v3lum/data is required")
    return resources.files("v3lum.data").joinpath(text)


def _write_private(path: Path, data: bytes) -> None:
    """Atomic 0600 write (temp file in the same directory + os.replace)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".tmp-{path.name}-{secrets.token_hex(4)}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def _status_reason(status: int) -> str:
    if status == 429:
        return "rate_limited"
    if status in (401, 403, 430):
        return "challenge"
    if status == 451:
        return "geo_block"
    return "error"


def _classified(resp: Any) -> tuple[str, str] | None:
    """(reason_code, reason) when the response is a challenge/quota/error page (P321)."""
    found = getattr(resp, "classification", None)
    if found is None:
        classify = getattr(_http, "classify", None)
        if callable(classify):
            try:
                found = classify(resp)
            except Exception:  # noqa: BLE001 - classification must never break the manager
                found = None
    if found is not None:
        return str(getattr(found, "reason_code", "") or getattr(found, "status", "") or "error"), str(getattr(found, "reason", "") or "classified page")
    try:
        legacy = getattr(resp, "blocked", None)
    except Exception:  # noqa: BLE001
        legacy = None
    return ("challenge", str(legacy)) if legacy else None


def _looks_like_html(head: bytes) -> bool:
    text = head[:2048].lstrip().lower()
    return text.startswith((b"<!doctype html", b"<html", b"<head", b"<body")) or b"<html" in text[:512]


def _check_expect(path: Path, expect: str) -> None:
    """The parse check of ``expect``; raises DatasetError."""
    if expect == "bytes":
        return
    with open(path, "rb") as fh:
        head = fh.read(4096)
    if _looks_like_html(head):  # json/lines/csv/text datasets are never HTML ('bytes' opts out)
        raise DatasetError("an HTML page came back instead of the dataset (challenge or error page?)", reason_code="challenge")
    if expect == "json":
        try:
            json.loads(path.read_text(encoding="utf-8-sig"))
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise DatasetError(f"not valid JSON: {_short(exc)}") from exc
        return
    if expect == "csv":
        try:
            with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
                rows = sum(1 for _row, _ in zip(csv.reader(fh), range(1000)) if _row)
        except csv.Error as exc:
            raise DatasetError(f"not valid CSV: {exc}") from exc
        if rows == 0:
            raise DatasetError("CSV without rows")
        return
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if expect == "text" and line:
                return
            if line and not line.startswith(("#", ";", "//")):
                return
    raise DatasetError("no data lines" if expect == "lines" else "empty text")


# --------------------------------------------------------------------------------------
# archives
# --------------------------------------------------------------------------------------


def _member_problem(info: zipfile.ZipInfo) -> str:
    name = info.filename
    if not name or "\x00" in name:
        return "empty or NUL member name"
    norm = name.replace("\\", "/")
    if norm.startswith("/") or re.match(r"^[A-Za-z]:", norm):
        return f"absolute path {name!r}"
    if ".." in PurePosixPath(norm).parts:
        return f"parent directory reference in {name!r}"
    mode = (info.external_attr >> 16) & 0xFFFF
    kind = stat.S_IFMT(mode)
    if kind == stat.S_IFLNK:
        return f"symlink member {name!r}"
    if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
        return f"special file member {name!r}"
    return ""


def safe_extract(
    path: str | Path,
    kind: str,
    dest: str | Path,
    *,
    max_total: int = 500 * 1024 * 1024,
    max_ratio: int = 100,
    max_members: int = 10000,
    member: str | None = None,
) -> Path:
    """Extract a gz/bz2/zip archive into ``dest`` with hard limits; returns the extracted file
    (gz/bz2, or zip with ``member``) or ``dest`` (whole zip).

    Rejected (DatasetError): absolute paths, '..' components, symlinks and special files, more than
    ``max_members`` members, more than ``max_total`` expanded bytes, and compression ratios above
    ``max_ratio`` (zip bombs; checked above 1 MiB of expanded data). Partial output is removed.
    """
    src = Path(path)
    out_dir = Path(dest)
    out_dir.mkdir(parents=True, exist_ok=True)
    kind = (kind or "").lower()
    compressed = max(src.stat().st_size, 1)
    if kind in ("gz", "gzip", "bz2"):
        opener = gzip.open if kind != "bz2" else bz2.open
        name = member or (src.name[: -len(src.suffix)] if src.suffix else src.name + ".out") or "data"
        problem = _member_problem(zipfile.ZipInfo(name))
        if problem or "/" in name.replace("\\", "/"):
            raise DatasetError(f"unsafe output name for {kind} archive: {problem or name}")
        out = out_dir / name
        total = 0
        try:
            with opener(src, "rb") as fin, open(out, "wb") as fout:
                for chunk in iter(lambda: fin.read(1 << 16), b""):
                    total += len(chunk)
                    if total > max_total:
                        raise DatasetError(f"{kind} archive expands beyond {max_total} bytes")
                    if total > _RATIO_FLOOR and total > compressed * max_ratio:
                        raise DatasetError(f"{kind} archive compression ratio above {max_ratio} (decompression bomb?)")
                    fout.write(chunk)
        except (OSError, EOFError, ValueError) as exc:
            out.unlink(missing_ok=True)
            raise DatasetError(f"corrupt {kind} archive: {exc}") from exc
        except DatasetError:
            out.unlink(missing_ok=True)
            raise
        return out
    if kind != "zip":
        raise ValueError(f"unsupported archive kind {kind!r} (gz, bz2, zip)")
    try:
        zf = zipfile.ZipFile(src)
    except (zipfile.BadZipFile, OSError) as exc:
        raise DatasetError(f"corrupt zip archive: {exc}") from exc
    created: list[Path] = []
    try:
        with zf:
            infos = zf.infolist()
            if len(infos) > max_members:
                raise DatasetError(f"zip archive has {len(infos)} members (limit {max_members})")
            declared = 0
            for info in infos:
                problem = _member_problem(info)
                if problem:
                    raise DatasetError(f"unsafe zip archive: {problem}")
                if info.is_dir():
                    continue
                declared += info.file_size
                if declared > max_total:
                    raise DatasetError(f"zip archive expands beyond {max_total} bytes")
                if info.file_size > _RATIO_FLOOR and info.file_size > max(info.compress_size, 1) * max_ratio:
                    raise DatasetError(f"zip member {info.filename!r} compression ratio above {max_ratio} (zip bomb?)")
            if declared > _RATIO_FLOOR and declared > compressed * max_ratio:
                raise DatasetError(f"zip archive compression ratio above {max_ratio} (zip bomb?)")
            wanted = [i for i in infos if not i.is_dir()]
            if member is not None:
                wanted = [i for i in wanted if i.filename.replace("\\", "/") == member.replace("\\", "/")]
                if not wanted:
                    raise DatasetError(f"zip archive has no member {member!r}")
            root = out_dir.resolve()
            total = 0
            for info in wanted:
                target = out_dir.joinpath(*PurePosixPath(info.filename.replace("\\", "/")).parts)
                if root not in target.resolve().parents and target.resolve() != root:
                    raise DatasetError(f"unsafe zip archive: {info.filename!r} escapes the destination")
                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with zf.open(info) as fin, open(target, "wb") as fout:
                    created.append(target)
                    for chunk in iter(lambda: fin.read(1 << 16), b""):
                        written += len(chunk)
                        total += len(chunk)
                        if written > info.file_size or total > max_total:
                            raise DatasetError(f"zip member {info.filename!r} is larger than declared")
                        fout.write(chunk)
    except (zipfile.BadZipFile, OSError, EOFError) as exc:
        for p in created:
            p.unlink(missing_ok=True)
        raise DatasetError(f"corrupt zip archive: {exc}") from exc
    except DatasetError:
        for p in created:
            p.unlink(missing_ok=True)
        raise
    if member is not None:
        return out_dir.joinpath(*PurePosixPath(member.replace("\\", "/")).parts)
    return out_dir


# --------------------------------------------------------------------------------------
# manifest and pins
# --------------------------------------------------------------------------------------

_MANIFEST_LOCK = threading.RLock()
_MANIFEST_CACHE: dict[str, tuple[int, int, dict[str, Any]]] = {}


def _manifest_path() -> Path:
    return paths.datasets_dir() / MANIFEST_FILE


def _read_manifest() -> dict[str, dict[str, Any]]:
    path = _manifest_path()
    with _MANIFEST_LOCK:
        try:
            st = path.stat()
        except FileNotFoundError:
            return {}
        hit = _MANIFEST_CACHE.get(str(path))
        if hit and hit[0] == st.st_mtime_ns and hit[1] == st.st_size:
            return {k: dict(v) for k, v in hit[2].items()}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        entries = data.get("datasets") if isinstance(data, dict) else None
        entries = {str(k): dict(v) for k, v in (entries or {}).items() if isinstance(v, dict)}
        _MANIFEST_CACHE[str(path)] = (st.st_mtime_ns, st.st_size, entries)
        return {k: dict(v) for k, v in entries.items()}


def _write_manifest(entries: dict[str, dict[str, Any]]) -> None:
    payload = {"schema": MANIFEST_SCHEMA, "datasets": {k: entries[k] for k in sorted(entries)}}
    with _MANIFEST_LOCK:
        _write_private(_manifest_path(), (json.dumps(payload, indent=1, sort_keys=True) + "\n").encode("utf-8"))


def _manifest_update(name: str, fn: Callable[[dict[str, Any] | None], dict[str, Any] | None]) -> None:
    with _MANIFEST_LOCK:
        entries = _read_manifest()
        new = fn(entries.get(name))
        if new is None:
            entries.pop(name, None)
        else:
            entries[name] = new
        _write_manifest(entries)


def _bundled_pin(name: str) -> dict[str, Any] | None:
    try:
        ref = resources.files("v3lum.data").joinpath("active_locks").joinpath(f"{name}.json")
        if not ref.is_file():
            return None
        data = json.loads(ref.read_text(encoding="utf-8"))
    except (OSError, ValueError, ModuleNotFoundError):
        return None
    if not isinstance(data, dict) or data.get("schema") != ACTIVE_LOCK_SCHEMA or data.get("name") != name:
        return None
    return data


def _user_lock_path() -> Path:
    return paths.datasets_dir() / USER_LOCK_FILE


def _read_user_lock() -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(_user_lock_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or data.get("schema") != USER_LOCK_SCHEMA:
        return {}
    return {str(k): dict(v) for k, v in (data.get("datasets") or {}).items() if isinstance(v, dict)}


def pins_for(name: str) -> dict[str, str]:
    """Accepted SHA-256 pins of an active dataset: {'bundled': sha, 'user': sha} (present ones only)."""
    out: dict[str, str] = {}
    bundled = _bundled_pin(name)
    if bundled and isinstance(bundled.get("sha256"), str):
        out["bundled"] = bundled["sha256"].lower()
    user = _read_user_lock().get(name)
    if user and isinstance(user.get("sha256"), str):
        out["user"] = user["sha256"].lower()
    return out


def _diff_summary(old: Path | None, new: Path, expect: str, old_sha: str, new_sha: str) -> str:
    head = f"sha256 {old_sha[:12] or '-'} -> {new_sha[:12]}"
    try:
        size_new = new.stat().st_size
        if old is None or not old.is_file():
            return f"{head}: new dataset ({size_new} bytes)"
        size_old = old.stat().st_size
        if max(size_old, size_new) > 50 * 1024 * 1024:
            return f"{head}: {size_old} -> {size_new} bytes"
        if expect == "json":
            a = json.loads(old.read_text(encoding="utf-8-sig"))
            b = json.loads(new.read_text(encoding="utf-8-sig"))
            if isinstance(a, dict) and isinstance(b, dict):
                added, removed = len(set(b) - set(a)), len(set(a) - set(b))
                return f"{head}: keys +{added} / -{removed} ({len(a)} -> {len(b)})"
            if isinstance(a, list) and isinstance(b, list):
                return f"{head}: entries {len(a)} -> {len(b)}"
            return f"{head}: {size_old} -> {size_new} bytes"
        if expect in ("lines", "csv", "text"):
            a_lines = {ln.strip() for ln in old.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()}
            b_lines = {ln.strip() for ln in new.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()}
            return f"{head}: +{len(b_lines - a_lines)} / -{len(a_lines - b_lines)} lines ({len(a_lines)} -> {len(b_lines)})"
        return f"{head}: {size_old} -> {size_new} bytes"
    except (OSError, ValueError) as exc:
        return f"{head}: diff unavailable ({exc})"


# --------------------------------------------------------------------------------------
# index
# --------------------------------------------------------------------------------------


class DatasetIndex:
    """Membership index over one dataset version. Values are stripped and lower-cased.

    Up to ``INDEX_MEMORY_LIMIT`` entries live in a frozenset; above that a SQLite index under
    ``datasets/.index/<sha256>.sqlite`` is built once per dataset version and reused.
    """

    def __init__(self, name: str, sha256: str, *, values: frozenset[str] | None = None, db_path: Path | None = None, count: int = 0) -> None:
        self.name = name
        self.sha256 = sha256
        self._values = values
        self.db_path = db_path
        self._count = len(values) if values is not None else count
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    @staticmethod
    def normalise(value: Any) -> str:
        return str(value).strip().lower()

    @property
    def in_memory(self) -> bool:
        return self._values is not None

    def contains(self, value: Any) -> bool:
        key = self.normalise(value)
        if not key:
            return False
        if self._values is not None:
            return key in self._values
        with self._lock:
            if self._conn is None:
                self._conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, check_same_thread=False)
            row = self._conn.execute("SELECT 1 FROM entries WHERE value = ? LIMIT 1", (key,)).fetchone()
        return row is not None

    __contains__ = contains

    def __len__(self) -> int:
        return self._count

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def __repr__(self) -> str:  # pragma: no cover - trivial
        where = "memory" if self.in_memory else str(self.db_path)
        return f"DatasetIndex({self.name!r}, {self._count} entries, {where})"


def _dig(data: Any, column: str) -> Any:
    for part in str(column).split("."):
        if not isinstance(data, dict):
            return None
        data = data.get(part)
    return data


def _scalars(value: Any) -> Iterator[str]:
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        yield str(value)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (str, int, float)) and not isinstance(item, bool):
                yield str(item)
    elif isinstance(value, dict):
        yield from (str(k) for k in value)


def _iter_values(path: Path, fmt: str, column: Any) -> Iterator[str]:
    if fmt == "json":
        data = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
        if column is None:
            yield from _scalars(data)
        elif isinstance(data, list):
            for item in data:
                yield from _scalars(_dig(item, column))
        else:
            yield from _scalars(_dig(data, column))
        return
    if fmt == "csv":
        with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
            reader = csv.reader(fh)
            idx = 0
            if column is not None:
                if isinstance(column, int) or str(column).isdigit():
                    idx = int(column)
                else:
                    header = next(reader, [])
                    try:
                        idx = [h.strip() for h in header].index(str(column))
                    except ValueError as exc:
                        raise DatasetError(f"CSV has no column {column!r}") from exc
            for row in reader:
                if row and not row[0].lstrip().startswith("#") and len(row) > idx:
                    yield row[idx]
        return
    with open(path, encoding="utf-8", errors="replace") as fh:
        idx = int(column) if column is not None else 0
        for line in fh:
            line = line.strip()
            if not line or line.startswith(("#", ";", "//")):
                continue
            parts = line.split()
            if len(parts) > idx:
                yield parts[idx]


def _build_index(name: str, sha: str, path: Path, fmt: str, column: Any) -> DatasetIndex:
    index_dir = paths.datasets_dir() / ".index"
    # one file per dataset version and reader (format + column): a lines index never serves json
    plain = fmt == "lines" and column is None
    suffix = "" if plain else "-" + hashlib.sha256(f"{fmt}:{column}".encode()).hexdigest()[:8]
    db_path = index_dir / f"{sha}{suffix}.sqlite"
    if db_path.is_file():
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            try:
                row = conn.execute("SELECT v FROM meta WHERE k = 'count'").fetchone()
            finally:
                conn.close()
            return DatasetIndex(name, sha, db_path=db_path, count=int(row[0]) if row else 0)
        except (sqlite3.Error, ValueError, TypeError):
            db_path.unlink(missing_ok=True)
    limit = INDEX_MEMORY_LIMIT
    values: set[str] = set()
    it = (DatasetIndex.normalise(v) for v in _iter_values(path, fmt, column))
    for value in it:
        if value:
            values.add(value)
            if len(values) > limit:
                break
    else:
        return DatasetIndex(name, sha, values=frozenset(values))
    index_dir.mkdir(parents=True, exist_ok=True)
    tmp = index_dir / f".tmp-{sha}-{secrets.token_hex(4)}.sqlite"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # private from the first byte
    os.close(fd)
    conn = sqlite3.connect(tmp)
    try:
        conn.execute("CREATE TABLE entries (value TEXT PRIMARY KEY) WITHOUT ROWID")
        conn.execute("CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT)")
        conn.executemany("INSERT OR IGNORE INTO entries VALUES (?)", ((v,) for v in values))
        values.clear()
        batch: list[tuple[str]] = []
        for value in it:
            if value:
                batch.append((value,))
                if len(batch) >= 50000:
                    conn.executemany("INSERT OR IGNORE INTO entries VALUES (?)", batch)
                    batch.clear()
        if batch:
            conn.executemany("INSERT OR IGNORE INTO entries VALUES (?)", batch)
        count = conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        conn.executemany("INSERT INTO meta VALUES (?, ?)", [("name", name), ("column", str(column)), ("sha256", sha), ("count", str(count))])
        conn.commit()
    except BaseException:
        conn.close()
        tmp.unlink(missing_ok=True)  # no half-built index survives a failure
        raise
    conn.close()
    os.chmod(tmp, 0o600)
    os.replace(tmp, db_path)
    return DatasetIndex(name, sha, db_path=db_path, count=int(count))


# --------------------------------------------------------------------------------------
# DataStore
# --------------------------------------------------------------------------------------


class DataStore:
    """Datasets of one runtime: bundled files and downloadable datasets in ``~/.v3lum/datasets``.

    ``runtime`` provides ``http`` (downloads), ``in_scan`` and ``now()``; ``DataStore(None)`` only
    reads local copies (never downloads).
    """

    def __init__(self, runtime: Runtime | Any = None) -> None:
        self.runtime = runtime
        self._lock = threading.Lock()
        self._locks: dict[str, threading.RLock] = {}
        self._memo: dict[str, tuple[tuple[int, int, int, int], Any]] = {}
        self._indexes: dict[tuple[str, str, str], DatasetIndex] = {}

    # ------------------------------------------------------------------ bundled
    @staticmethod
    def bundled_path(name: str) -> Path:
        return Path(str(_bundled_ref(name)))

    @staticmethod
    def bundled_exists(name: str) -> bool:
        try:
            return _bundled_ref(name).is_file()
        except (FileNotFoundError, OSError, ValueError):
            return False

    @staticmethod
    @functools.lru_cache(maxsize=64)
    def bundled_text(name: str) -> str:
        return _bundled_ref(name).read_text(encoding="utf-8")

    @staticmethod
    @functools.lru_cache(maxsize=64)
    def bundled_json(name: str) -> Any:
        return json.loads(DataStore.bundled_text(name))

    @staticmethod
    @functools.lru_cache(maxsize=64)
    def bundled_lines(name: str) -> frozenset[str]:
        lines = DataStore.bundled_text(name).splitlines()
        return frozenset(ln.strip().lower() for ln in lines if ln.strip() and not ln.lstrip().startswith(("#", "//")))

    @staticmethod
    @functools.lru_cache(maxsize=64)
    def bundled_sha256(name: str) -> str:
        return _sha256_bytes(_bundled_ref(name).read_bytes())

    # ------------------------------------------------------------------ plumbing
    def path(self, name: str) -> Path:
        """Local path of a downloadable dataset (it may not exist yet)."""
        return paths.datasets_dir() / check_name(name)

    def _lock_for(self, name: str) -> threading.RLock:
        with self._lock:
            if name not in self._locks:
                self._locks[name] = threading.RLock()
            return self._locks[name]

    def _now(self) -> datetime:
        fn = getattr(self.runtime, "now", None) if self.runtime is not None else None
        if callable(fn):
            try:
                value = fn()
                if isinstance(value, datetime):
                    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
            except Exception:  # noqa: BLE001 - a broken clock must not break datasets
                pass
        return datetime.now(timezone.utc)

    def _in_scan(self) -> bool:
        return bool(getattr(self.runtime, "in_scan", False)) if self.runtime is not None else False

    def _unreviewed(self, reg: dict[str, Any] | None, registered_before: int | None, in_scan: bool) -> bool:
        """True when a download of this registration is not a reviewed (import-time) dataset: no
        registration (the v1 ad-hoc ``fetch(name, url)``), or one made after ``registered_before`` (the
        run's view) or, during a scan, after the scan started (``Runtime.scan_dataset_seq``)."""
        if reg is None:
            return True
        seq = _seq_of(reg)
        if seq <= 0:
            return True  # an entry written into DATASETS directly, not by register_dataset: never reviewed
        if registered_before is not None and seq > int(registered_before):
            return True
        scan_seq = getattr(self.runtime, "scan_dataset_seq", None) if in_scan and self.runtime is not None else None
        return isinstance(scan_seq, int) and not isinstance(scan_seq, bool) and seq > scan_seq

    def _client(self) -> Any:
        return getattr(self.runtime, "http", None) if self.runtime is not None else None

    def _age_seconds(self, target: Path, entry: dict[str, Any] | None) -> float:
        fetched = _parse_iso((entry or {}).get("fetched_at"))
        if fetched is None:
            return max(0.0, time.time() - target.stat().st_mtime)
        return (self._now() - fetched).total_seconds()

    def _fresh(self, target: Path, entry: dict[str, Any] | None, ttl: float) -> bool:
        return ttl > 0 and self._age_seconds(target, entry) < ttl

    @staticmethod
    def _is_large(reg: dict[str, Any] | None, entry: dict[str, Any] | None, max_bytes: int | None) -> bool:
        if reg and reg.get("large") is True:
            return True
        if entry:
            size = max(int(entry.get("bytes") or 0), int(entry.get("size_hint") or 0))
            if size > LARGE_BYTES:
                return True
        if reg and reg.get("large") is False:
            return False
        declared = max_bytes if max_bytes is not None else (reg["max_bytes"] if reg and reg.get("max_bytes_declared") else None)
        return declared is not None and int(declared) > LARGE_BYTES

    def _meta_fields(self, name: str, reg: dict[str, Any] | None) -> dict[str, Any]:
        reg = reg or {}
        return {
            "licence": reg.get("licence", ""),
            "terms_class": reg.get("terms_class", "unknown"),
            "attribution": reg.get("attribution", ""),
            "provider": reg.get("provider", ""),
            "source": reg.get("source", ""),
        }

    def _mark_stale(self, name: str, reg: dict[str, Any] | None, stale: bool) -> None:
        """Record the served copy as stale (adopting a v1 copy without MANIFEST entry)."""
        target = self.path(name)
        current = _read_manifest().get(name) or {}
        if current.get("sha256") and bool(current.get("stale")) == stale:
            return

        def change(entry: dict[str, Any] | None) -> dict[str, Any] | None:
            entry = dict(entry or {})
            if not entry.get("sha256"):
                if not target.is_file():
                    return entry or None
                st = target.stat()
                entry.update(
                    {
                        "url": _redact_url((reg or {}).get("url", "")),
                        "fetched_at": _iso(datetime.fromtimestamp(st.st_mtime, timezone.utc)),
                        "sha256": _sha256_file(target),
                        "bytes": st.st_size,
                        "etag": "",
                        "last_modified": "",
                        **self._meta_fields(name, reg),
                    }
                )
            entry["stale"] = bool(stale)
            return entry

        _manifest_update(name, change)

    def _touch(self, name: str, reg: dict[str, Any] | None, cand: _Candidate | None = None, resp_headers: dict[str, str] | None = None) -> None:
        now = _iso(self._now())

        def change(entry: dict[str, Any] | None) -> dict[str, Any] | None:
            entry = dict(entry or {})
            entry["fetched_at"] = now
            entry["stale"] = False
            if cand is not None:
                entry["etag"] = cand.etag or entry.get("etag", "")
                entry["last_modified"] = cand.last_modified or entry.get("last_modified", "")
            if resp_headers:
                entry["etag"] = resp_headers.get("etag", "") or entry.get("etag", "")
                entry["last_modified"] = resp_headers.get("last-modified", "") or entry.get("last_modified", "")
            if not entry.get("sha256"):
                target = self.path(name)
                if target.is_file():
                    entry["sha256"] = _sha256_file(target)
                    entry["bytes"] = target.stat().st_size
                    entry.setdefault("url", _redact_url((reg or {}).get("url", "")))
                    entry.update(self._meta_fields(name, reg))
            return entry

        _manifest_update(name, change)

    def _dataset_http(self, reg: dict[str, Any] | None, url: str) -> Any:
        """A dataset scope over the runtime client (host allow-list = URL host + provider hosts)."""
        client = self._client()
        scoped_cls = getattr(_http, "ScopedHttp", None)
        if client is None or scoped_cls is None:
            return client
        try:
            params = inspect.signature(scoped_cls).parameters
        except (TypeError, ValueError):  # pragma: no cover
            return client
        if "allowed_hosts" not in params:
            return client  # pre-v2 HTTP contract: the client itself
        reg = reg or {}
        hosts = {(urlsplit(url).hostname or "").lower()}
        provider = str(reg.get("provider") or "")
        if provider:
            hosts |= set(self._provider_hosts(provider))
        kwargs: dict[str, Any] = {
            "module": "datasets",
            "provider": provider,
            "sources": (reg["source"],) if reg.get("source") else (),
            "allowed_hosts": tuple(sorted(h for h in hosts if h)),
            "disclosure": "third_party",
            "cancel_event": getattr(self.runtime, "cancel_event", None),
            "clock": getattr(self.runtime, "clock", None),
        }
        try:
            return scoped_cls(client, **{k: v for k, v in kwargs.items() if k in params})
        except TypeError:  # pragma: no cover - unexpected signature
            return client

    def _provider_hosts(self, provider: str) -> tuple[str, ...]:
        registry = getattr(self.runtime, "providers", None)
        if registry is None:
            try:
                from v3lum.core import providers

                registry = providers.registry()
            except ImportError:  # pragma: no cover
                return ()
        try:
            return tuple(h.lower() for h in registry.hosts_for(provider, getattr(self.runtime, "config", None)))
        except Exception:  # noqa: BLE001 - an unknown provider simply adds nothing
            return ()

    # ------------------------------------------------------------------ download
    def _download(
        self,
        name: str,
        reg: dict[str, Any] | None,
        url: str,
        *,
        headers: dict[str, str] | None,
        max_bytes: int | None,
        cap: int | None,
        entry: dict[str, Any] | None,
        http: Any = None,
    ) -> _Candidate | None:
        """Download and validate into temp files. None = 304 Not Modified. Raises DatasetError.

        ``http`` is the calling module's own scope (``ctx.http``, ad-hoc downloads through
        :class:`DataView`): the request goes through it and its ``PolicyError`` propagates as is (the
        module is refused exactly like ``ctx.http`` refuses it). Without it the dataset scope of the
        registration is used (:meth:`_dataset_http`).
        """
        scoped = http is not None
        reg = reg or {}
        host = urlsplit(url).hostname or "?"
        effective_max = int(max_bytes or reg.get("max_bytes") or DEFAULT_MAX_BYTES)
        request_max = min(effective_max, cap) if cap else effective_max
        hdrs = dict(headers or {})
        if entry:
            if entry.get("etag"):
                hdrs.setdefault("If-None-Match", str(entry["etag"]))
            if entry.get("last_modified"):
                hdrs.setdefault("If-Modified-Since", str(entry["last_modified"]))
        if not scoped:
            http = self._dataset_http(reg, url)
        if http is None:
            raise DatasetUnavailable(name, f"dataset {name}: no HTTP client (offline): run v3lum data update {name}")
        try:
            resp = http.request("GET", url, headers=hdrs, ttl=0, max_bytes=request_max, timeout=DOWNLOAD_TIMEOUT)
        except _PROPAGATE:
            raise
        except _OFFLINE as exc:
            raise DatasetUnavailable(name, f"dataset {name} not downloaded (offline mode): run v3lum data update {name}", reason_code="offline") from exc
        except _HTTP_FAILURES as exc:
            if scoped and isinstance(exc, _POLICY):
                # the module's own host/disclosure/scope/egress binding refused it: SKIPPED exactly like
                # ctx.http, never a dataset error (and no stale copy masks the refusal)
                raise
            code = str(getattr(exc, "reason_code", "") or "error")
            raise DatasetError(f"download of {name} from {host} failed: {_redact_text(str(exc))}", reason_code=code, name=name) from exc
        status = int(getattr(resp, "status", 0) or 0)
        if status == 304 and entry:
            return None
        if status != 200:
            found = _classified(resp)
            detail = f" ({found[1]})" if found else ""
            raise DatasetError(f"download of {name} from {host} failed: HTTP {status}{detail}", reason_code=_status_reason(status), name=name)
        if getattr(resp, "truncated", False):
            if cap and effective_max > cap:
                _manifest_update(name, lambda e: {**(e or {}), "size_hint": LARGE_BYTES + 1})
                raise DatasetUnavailable(name, f"dataset {name} is larger than 5 MB and is not downloaded during a scan: run v3lum data update {name}")
            raise DatasetError(f"download of {name} exceeded max_bytes ({effective_max} bytes)", reason_code="error", name=name)
        found = _classified(resp)
        if found:
            raise DatasetError(f"download of {name} from {host} rejected: {found[1]}", reason_code=found[0], name=name)
        content = bytes(getattr(resp, "content", b"") or b"")
        resp_headers = {str(k).lower(): str(v) for k, v in (getattr(resp, "headers", {}) or {}).items()}
        directory = paths.datasets_dir()
        try:
            fd, tmp_name = tempfile.mkstemp(prefix=f".tmp-{name}-", dir=str(directory))
        except OSError as exc:
            raise DatasetError(f"dataset {name}: cannot create a temporary file in {directory}: {_short(exc)}", name=name) from exc
        cand = _Candidate(Path(tmp_name), "", _sha256_bytes(content), len(content), resp_headers.get("etag", ""), resp_headers.get("last-modified", ""), url)
        cand.temps.append(Path(tmp_name))
        try:
            with os.fdopen(fd, "wb") as fh:
                for i in range(0, len(content), 1 << 20):
                    fh.write(content[i : i + (1 << 20)])
            final = Path(tmp_name)
            archive = reg.get("archive")
            if archive:
                xdir = Path(tempfile.mkdtemp(prefix=f".tmp-{name}-x-", dir=str(directory)))
                cand.temps.append(xdir)
                member = reg.get("member") or None
                if archive == "zip" and member is None:
                    try:
                        with zipfile.ZipFile(final) as zf:
                            files = [i.filename for i in zf.infolist() if not i.is_dir()]
                    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, EOFError, ValueError) as exc:
                        raise DatasetError(f"corrupt zip archive: {_short(exc)}", name=name) from exc
                    if len(files) != 1:
                        raise DatasetError(f"zip archive of {name} has {len(files)} files: register member=", name=name)
                    member = files[0]
                final = safe_extract(final, archive, xdir, max_total=effective_max, member=member)
            self._validate(name, reg, final, cand.body_sha256)
            cand.path = final
            cand.bytes = final.stat().st_size
            cand.sha256 = _sha256_file(final)
            return cand
        except DatasetError as exc:
            cand.cleanup()
            if not exc.name:
                exc.name = name
            raise DatasetError(f"dataset {name} rejected: {exc}", reason_code=exc.reason_code, name=name) from exc
        except (OSError, EOFError, ValueError, RecursionError, UnicodeError, csv.Error, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            # disk full, unreadable temp file, odd archive...: the refresh failed, the previous copy stays
            cand.cleanup()
            raise DatasetError(f"dataset {name} rejected: {type(exc).__name__}: {_short(exc)}", name=name) from exc
        except BaseException:
            cand.cleanup()
            raise

    def _validate(self, name: str, reg: dict[str, Any], path: Path, body_sha: str) -> None:
        size = path.stat().st_size
        min_bytes = int(reg.get("min_bytes", 1))
        if size < min_bytes:
            raise DatasetError(f"short body ({size} bytes, min_bytes {min_bytes})")
        _check_expect(path, str(reg.get("expect") or "bytes"))
        pinned = str(reg.get("pinned_sha256") or "")
        if pinned and pinned not in (body_sha, _sha256_file(path)):
            raise DatasetError(f"SHA-256 does not match the pinned value ({pinned[:12]}...)", reason_code="error")
        validate = reg.get("validate")
        if validate is not None:
            try:
                ok = validate(path)
            except Exception as exc:  # noqa: BLE001 - any validator failure rejects the copy
                raise DatasetError(f"validator rejected the download: {exc}") from exc
            if ok is False:
                raise DatasetError("validator rejected the download")

    def _install(self, name: str, reg: dict[str, Any] | None, cand: _Candidate) -> None:
        target = self.path(name)
        os.replace(cand.path, target)
        try:
            os.chmod(target, 0o600)
        except OSError:  # pragma: no cover - Windows
            pass
        meta = self._meta_fields(name, reg)
        now = _iso(self._now())

        def change(entry: dict[str, Any] | None) -> dict[str, Any]:
            new = {
                "url": _redact_url(cand.url),
                "fetched_at": now,
                "sha256": cand.sha256,
                "bytes": cand.bytes,
                "etag": cand.etag,
                "last_modified": cand.last_modified,
                **meta,
                "stale": False,
            }
            if (reg or {}).get("archive"):
                new.update({"archive": reg["archive"], "member": reg.get("member", ""), "body_sha256": cand.body_sha256})
            return new

        _manifest_update(name, change)
        with self._lock:
            self._indexes = {k: v for k, v in self._indexes.items() if k[0] != name}

    def _pinned(self, name: str, hashes: Iterable[str]) -> bool:
        accepted = set(pins_for(name).values())
        return any(h and h.lower() in accepted for h in hashes)

    # ------------------------------------------------------------------ read API
    def fetch(
        self,
        name: str,
        url: str | None = None,
        *,
        ttl: float | None = None,
        headers: dict[str, str] | None = None,
        max_bytes: int | None = None,
        http: Any = None,
        registered_before: int | None = None,
    ) -> Path:
        """Local path of the dataset, downloading/refreshing it when older than ``ttl``.

        ``url``/``ttl`` default to the registration (v1 positional calls keep working). A failed
        refresh returns the previous (stale) copy; without one DatasetError/DatasetUnavailable is
        raised. During a scan large datasets are never downloaded (see the module docstring).

        ``http`` is the calling module's own scope (``ctx.http``; :class:`DataView` passes it). Every
        download that is not a reviewed registration goes through it instead of a dataset scope: an
        unregistered name with a URL (the v1 ad-hoc form) and a dataset registered after
        ``registered_before`` (the registration sequence when the run started) or, during a scan,
        after the scan started (``Runtime.scan_dataset_seq``) - registrations happen at import time.
        Its refusal (``PolicyError``: undeclared host, disclosure 'none', outside the ACTIVE scope,
        egress) propagates and is never masked by a stale copy. ``http`` must be a module
        ``ScopedHttp``: a raw client or a core scope is refused with ``PolicyError``. During a scan
        such a download without a module scope is refused with ``PolicyError`` (P327 cond 5, A7).
        Reviewed registrations keep their dataset scope.
        """
        check_name(name)
        if http is not None:
            _check_module_scope(http)
        reg = DATASETS.get(name)  # read once: the URL, the routing and the download use this registration
        if url is None:
            if reg is None:
                raise DatasetError(f"dataset {name!r} is not registered (register_dataset) and no URL was given", name=name)
            url = reg["url"]
        elif reg is not None and str(url).strip() != reg["url"]:
            # one name, one source: its licence, terms and pins belong to the registered URL
            raise DatasetError(f"dataset {name!r} is registered with another URL ({_redact_url(reg['url'])}): fetch it by name", name=name)
        ttl_s = float(ttl if ttl is not None else (reg["ttl"] if reg else DEFAULT_TTL))
        target = self.path(name)
        with self._lock_for(name):
            entry = _read_manifest().get(name)
            exists = target.is_file()
            if reg and reg.get("active"):
                return self._serve_active(name, reg, target, entry, exists, ttl_s)
            if exists and self._fresh(target, entry, ttl_s):
                return target
            in_scan = self._in_scan()
            if in_scan and self._is_large(reg, entry, max_bytes):
                if exists:
                    self._mark_stale(name, reg, True)
                    return target
                raise DatasetUnavailable(name, f"dataset {name} is large (> 5 MB) and is never downloaded during a scan: run v3lum data update {name}")
            # the module's own scope carries every download that is not a reviewed registration
            route = http if self._unreviewed(reg, registered_before, in_scan) else None
            if (route if route is not None else self._client()) is None:
                if exists:
                    self._mark_stale(name, reg, True)
                    return target
                raise DatasetUnavailable(name, f"dataset {name} is not downloaded: run v3lum data update {name}")
            if route is None and in_scan and self._unreviewed(reg, registered_before, in_scan):
                # fail closed: mid-scan, an ad-hoc URL (or a dataset registered during the run) is downloaded only
                # through the calling module's own scope (ctx.data -> ctx.http); the store reached around ctx.data
                # has no host/scope binding
                raise _http.PolicyError(
                    "policy", f"dataset {name}: ad-hoc download (unregistered name + URL, or a dataset registered during the "
                              "run) refused during a scan outside the module's ctx.data: it goes through the module's ctx.http "
                              "(host, scope and egress checks)",
                )
            try:
                cand = self._download(name, reg, url, headers=headers, max_bytes=max_bytes, cap=LARGE_BYTES if in_scan else None,
                                      entry=entry if exists else None, http=route)
            except DatasetError:
                if exists:
                    self._mark_stale(name, reg, True)
                    return target
                raise
            if cand is None:
                self._touch(name, reg)
                return target
            try:
                self._install(name, reg, cand)
            finally:
                cand.cleanup()
            return target

    def _serve_active(self, name: str, reg: dict[str, Any], target: Path, entry: dict[str, Any] | None, exists: bool, ttl: float) -> Path:
        if not exists:
            raise DatasetUnavailable(name, f"active dataset {name} is installed only by `v3lum data update {name}` (pinned, never mid-engagement)")
        sha = _sha256_file(target)
        if not self._pinned(name, {sha, str((entry or {}).get("body_sha256") or "")}):
            raise DatasetUnavailable(name, f"active dataset {name} ({sha[:12]}) does not match its pin: run v3lum data update {name}")
        if not self._fresh(target, entry, ttl):
            self._mark_stale(name, reg, True)
        return target

    def fetch_text(self, name: str, url: str | None = None, *, ttl: float | None = None, **kw: Any) -> str:
        path = self.fetch(name, url, ttl=ttl, **kw)
        return self._memoized(path, "text", lambda p: p.read_text(encoding="utf-8", errors="replace"))

    def fetch_json(self, name: str, url: str | None = None, *, ttl: float | None = None, **kw: Any) -> Any:
        path = self.fetch(name, url, ttl=ttl, **kw)

        def parse(p: Path) -> Any:
            try:
                return json.loads(p.read_text(encoding="utf-8-sig", errors="replace"))
            except (ValueError, RecursionError) as exc:
                raise DatasetError(f"dataset {name}: the local copy is not valid JSON ({_short(exc)}): run v3lum data update {name}", name=name) from exc

        return self._memoized(path, "json", parse)

    def fetch_lines(self, name: str, url: str | None = None, *, ttl: float | None = None, **kw: Any) -> frozenset[str]:
        path = self.fetch(name, url, ttl=ttl, **kw)

        def parse(p: Path) -> frozenset[str]:
            out = set()
            for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
                ln = ln.strip()
                if ln and not ln.startswith(("#", ";", "//")):
                    out.add(ln.split()[0].lower())
            return frozenset(out)

        return self._memoized(path, "lines", parse)

    def _memoized(self, path: Path, kind: str, loader: Callable[[Path], Any]) -> Any:
        """Parsed value of ``path`` per reader kind (text/json/lines never share an entry), reused
        while the file is unchanged (inode, size, mtime and ctime)."""
        key = f"{kind}:{path}"
        stamp = _stamp(path)
        with self._lock:
            hit = self._memo.get(key)
            if hit and hit[0] == stamp:
                return hit[1]
        value = loader(path)
        with self._lock:
            self._memo[key] = (stamp, value)
        return value

    def index(self, name: str, *, column: str | int | None = None, fmt: str | None = None, http: Any = None,
              registered_before: int | None = None) -> DatasetIndex:
        """Membership index of a dataset (``contains(value)``, ``len``). ``column`` selects a JSON
        key path, a CSV column (header name or position) or a whitespace field of a line; ``fmt``
        ('json' | 'csv' | 'lines') overrides the registration's ``expect``. ``http`` and
        ``registered_before`` route the download like :meth:`fetch`."""
        path = self.fetch(name, http=http, registered_before=registered_before)
        reg = DATASETS.get(name) or {}
        kind = fmt or {"json": "json", "csv": "csv"}.get(str(reg.get("expect")), "")
        if not kind:
            kind = {".json": "json", ".csv": "csv"}.get(path.suffix.lower(), "lines")
        sha = _sha256_file(path)
        key = (name, f"{kind}:{column}", sha)
        with self._lock:
            hit = self._indexes.get(key)
        if hit is not None:
            return hit
        try:
            built = _build_index(name, sha, path, kind, column)
        except (ValueError, OSError, sqlite3.Error, csv.Error, RecursionError, UnicodeError) as exc:
            raise DatasetError(f"cannot index dataset {name}: {_short(exc)}", name=name) from exc
        with self._lock:
            self._indexes[key] = built
        return built

    def info(self, name: str) -> DatasetInfo:
        """Metadata of the local copy (MANIFEST + registration); ``present`` False when missing."""
        check_name(name)
        reg = DATASETS.get(name) or {}
        entry = _read_manifest().get(name) or {}
        target = self.path(name)
        present = target.is_file()
        meta = {**self._meta_fields(name, reg), **{k: entry[k] for k in ("licence", "terms_class", "attribution", "provider", "source") if entry.get(k)}}
        if not present:
            return DatasetInfo(name=name, url=_redact_url(reg.get("url", "")), **meta)
        fetched = entry.get("fetched_at") or _iso(datetime.fromtimestamp(target.stat().st_mtime, timezone.utc))
        age = self._age_seconds(target, {"fetched_at": fetched})
        ttl = float(reg.get("ttl", DEFAULT_TTL))
        return DatasetInfo(
            name=name,
            sha256=str(entry.get("sha256") or _sha256_file(target)),
            fetched_at=fetched,
            bytes=int(entry.get("bytes") or target.stat().st_size),
            age_hours=round(age / 3600, 1),
            stale=bool(entry.get("stale")) or (ttl > 0 and age >= ttl),
            present=True,
            url=str(entry.get("url") or _redact_url(reg.get("url", ""))),
            **meta,
        )

    def scoped(self, *, http: Any = None) -> DataView:
        """A per-run view with the same read API that records the datasets used (``.used``).

        ``http`` is the module's own HTTP scope (``ctx.http``): ad-hoc downloads of the view
        (unregistered name + URL) go through it (host, disclosure, request cap, run/scope binding,
        egress profile); registered datasets keep their dataset scope.
        """
        return DataView(self, http=http)

    # ------------------------------------------------------------------ maintenance
    def update(self, name: str, *, accept_new: bool = False, expect_sha256: str = "") -> UpdateResult:
        """Refresh one dataset now (conditional GET, full validation, atomic replace).

        Active datasets whose hash is not pinned are staged and returned as 'needs_accept' with a
        diff summary; ``accept_new=True`` (optionally with the reviewed ``expect_sha256``) then
        installs exactly the staged copy and records it in ``~/.v3lum/datasets/active.lock``. A
        change is never accepted blind: without a staged copy ``accept_new`` stages it first and
        returns 'needs_accept', unless the reviewed ``expect_sha256`` matches the download.
        """
        try:
            check_name(name)
        except ValueError as exc:
            return UpdateResult(name, "failed", reason=str(exc))
        reg = DATASETS.get(name)
        if reg is None:
            return UpdateResult(name, "failed", reason="not registered")
        if reg.get("active") and self._in_scan():
            return UpdateResult(name, "failed", reason="active datasets are refreshed only by `v3lum data update`, never mid-scan")
        if self._in_scan() and self._unreviewed(reg, None, True):
            # registered during the scan (not at import time): no reviewed dataset scope to download it through
            return UpdateResult(name, "failed", reason="registered during the scan (registrations happen at import time): not refreshed mid-scan")
        target = self.path(name)
        with self._lock_for(name):
            entry = _read_manifest().get(name) or {}
            exists = target.is_file()
            old_sha = _sha256_file(target) if exists else ""
            pending = entry.get("pending")
            pending_path = self._pending_path(name)
            if reg.get("active") and accept_new and pending and pending_path.is_file():
                return self._accept_pending(name, reg, pending, pending_path, old_sha, expect_sha256)
            if self._client() is None:
                return UpdateResult(name, "failed", old_sha, old_sha, reason="no network runtime")
            try:
                cand = self._download(name, reg, reg["url"], headers=None, max_bytes=None, cap=None, entry=entry if exists else None)
            except DatasetError as exc:
                return UpdateResult(name, "failed", old_sha, old_sha, reason=str(exc))
            if cand is None:
                self._touch(name, reg)
                return UpdateResult(name, "unchanged", old_sha, old_sha)
            try:
                if exists and cand.sha256 == old_sha:
                    self._touch(name, reg, cand)
                    return UpdateResult(name, "unchanged", old_sha, old_sha)
                diff = _diff_summary(target if exists else None, cand.path, str(reg.get("expect")), old_sha, cand.sha256)
                if reg.get("active") and not self._pinned(name, {cand.sha256, cand.body_sha256}):
                    if expect_sha256 and expect_sha256.lower() not in (cand.sha256, cand.body_sha256):
                        return UpdateResult(name, "failed", old_sha, cand.sha256, diff, reason="downloaded copy differs from the reviewed hash")
                    if not (accept_new and expect_sha256):
                        # accepted only after the diff summary was shown: stage it, accept the staged bytes next
                        self._stage_pending(name, reg, cand, diff)
                        return UpdateResult(
                            name, "needs_accept", old_sha, cand.sha256, diff,
                            reason=f"active dataset changed: review the diff summary, then accept the staged copy (v3lum data update {name} --accept-new)",
                        )
                    self._install(name, reg, cand)
                    self._record_user_pin(name, cand.sha256, cand.url, old_sha, diff)
                    return UpdateResult(name, "updated", old_sha, cand.sha256, diff)
                self._install(name, reg, cand)
                return UpdateResult(name, "updated", old_sha, cand.sha256, diff)
            finally:
                cand.cleanup()

    def _pending_path(self, name: str) -> Path:
        return paths.datasets_dir() / ".pending" / name

    def _stage_pending(self, name: str, reg: dict[str, Any], cand: _Candidate, diff: str) -> None:
        pending_path = self._pending_path(name)
        pending_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(pending_path.parent, 0o700)
        except OSError:  # pragma: no cover
            pass
        os.replace(cand.path, pending_path)
        info = {
            "sha256": cand.sha256,
            "body_sha256": cand.body_sha256,
            "bytes": cand.bytes,
            "etag": cand.etag,
            "last_modified": cand.last_modified,
            "url": _redact_url(cand.url),
            "fetched_at": _iso(self._now()),
            "diff_summary": diff,
        }
        _manifest_update(name, lambda e: {**(e or {}), "pending": info})

    def _accept_pending(self, name: str, reg: dict[str, Any], pending: dict[str, Any], path: Path, old_sha: str, expect_sha256: str) -> UpdateResult:
        sha = _sha256_file(path)
        if sha != pending.get("sha256"):
            return UpdateResult(name, "failed", old_sha, sha, reason="staged copy changed on disk: run the update again")
        if expect_sha256 and expect_sha256.lower() not in (sha, str(pending.get("body_sha256") or "")):
            return UpdateResult(name, "failed", old_sha, sha, str(pending.get("diff_summary") or ""), reason="staged copy differs from the reviewed hash")
        try:
            self._validate(name, reg, path, str(pending.get("body_sha256") or ""))
        except DatasetError as exc:
            return UpdateResult(name, "failed", old_sha, sha, reason=f"staged copy rejected: {exc}")
        cand = _Candidate(path, sha, str(pending.get("body_sha256") or sha), int(pending.get("bytes") or path.stat().st_size),
                          str(pending.get("etag") or ""), str(pending.get("last_modified") or ""), str(reg.get("url") or ""))
        self._install(name, reg, cand)
        diff = str(pending.get("diff_summary") or "")
        self._record_user_pin(name, sha, cand.url, old_sha, diff)
        return UpdateResult(name, "updated", old_sha, sha, diff)

    def _record_user_pin(self, name: str, sha: str, url: str, old_sha: str, diff: str) -> None:
        with _MANIFEST_LOCK:
            pins = _read_user_lock()
            pins[name] = {"sha256": sha, "url": _redact_url(url), "accepted_at": _iso(self._now()), "previous_sha256": old_sha, "diff_summary": diff}
            payload = {"schema": USER_LOCK_SCHEMA, "datasets": {k: pins[k] for k in sorted(pins)}}
            _write_private(_user_lock_path(), (json.dumps(payload, indent=1) + "\n").encode("utf-8"))

    def update_all(self, *, essential_only: bool = False) -> list[UpdateResult]:
        """``update()`` every registered dataset (only the essential ones with ``essential_only``)."""
        return [self.update(name) for name in sorted(DATASETS) if not essential_only or DATASETS[name].get("essential")]

    def first_run_hint(self) -> str | None:
        """One hint line when essential datasets were never downloaded (None otherwise)."""
        missing = sorted(n for n, reg in DATASETS.items() if reg.get("essential") and not (paths.datasets_dir() / n).is_file())
        if not missing:
            return None
        shown = ", ".join(missing[:5]) + (", ..." if len(missing) > 5 else "")
        return f"{len(missing)} essential dataset(s) not downloaded yet ({shown}): run v3lum data update --essential"

    def cached_info(self) -> list[dict[str, Any]]:
        """Downloaded files in the datasets directory: name, bytes, age_hours (v1 format)."""
        out = []
        for p in sorted(paths.datasets_dir().glob("*")):
            if not p.is_file() or p.name.startswith(".") or p.name in (MANIFEST_FILE, USER_LOCK_FILE) or p.name.endswith(".part"):
                continue
            st = p.stat()
            out.append({"name": p.name, "bytes": st.st_size, "age_hours": round((time.time() - st.st_mtime) / 3600, 1)})
        return out


# --------------------------------------------------------------------------------------
# DataView (ctx.data)
# --------------------------------------------------------------------------------------


class DataView:
    """``ctx.data``: the read API of a DataStore that records citations of the datasets used.

    ``used`` lists one ``{name, sha256, fetched_at, licence}`` per dataset (bundled files carry
    ``fetched_at='bundled'``); the engine copies it into ``ModuleResult.datasets``.

    ``http`` is the module's own scope (``ctx.http``, set by ``Context``). The v1 ad-hoc form
    ``fetch*(name, url)`` with an unregistered name downloads through it, never through a dataset
    scope: it is refused exactly like ``ctx.http`` refuses the URL (``PolicyError`` -> SKIPPED
    'policy' for an undeclared host or disclosure 'none', the ACTIVE scope binding, the egress
    profile). So does a dataset registered after the view was built (registrations happen at import
    time: one made during the run is not reviewed). Registered datasets keep their reviewed dataset
    scope. The binding is the view's: ``http=`` / ``registered_before=`` keywords of the caller are
    ignored.
    """

    def __init__(self, store: DataStore, *, http: Any = None) -> None:
        self._store = store
        # set once: the view is shared by the threads of one run, never rebound
        self._http = http
        #: registrations up to this sequence number existed when the run started (reviewed, import time)
        self._registered_before = _registration_seq()
        self.used: list[dict[str, str]] = []
        self._lock = threading.Lock()

    @property
    def store(self) -> DataStore:
        return self._store

    @property
    def runtime(self) -> Any:
        return self._store.runtime

    def _record(self, citation: dict[str, str]) -> None:
        with self._lock:
            for i, item in enumerate(self.used):
                if item["name"] == citation["name"]:
                    self.used[i] = citation
                    return
            self.used.append(citation)

    def _cite(self, name: str) -> None:
        try:
            info = self._store.info(name)
        except (ValueError, OSError):  # pragma: no cover - citation is best effort
            return
        self._record({"name": name, "sha256": info.sha256, "fetched_at": info.fetched_at, "licence": info.licence})

    def _cite_bundled(self, name: str) -> None:
        try:
            sha = DataStore.bundled_sha256(name)
        except (OSError, FileNotFoundError):  # pragma: no cover
            sha = ""
        self._record({"name": name, "sha256": sha, "fetched_at": "bundled", "licence": BUNDLED_LICENCES.get(name, "")})

    # ---- downloadable datasets
    def _bound(self, kw: dict[str, Any]) -> dict[str, Any]:
        """The store keywords of one call: the view's binding (the module's own scope and the registration
        sequence of the run), never a caller's ``http=`` / ``registered_before=``. The store decides the
        route under its per-name lock from one read of the registry: an ad-hoc download (unregistered
        name + URL) or a dataset registered during the run goes through the module's scope, a reviewed
        registration through its dataset scope."""
        kw = dict(kw)
        kw.pop("http", None)
        kw.pop("registered_before", None)
        if self._http is not None:
            kw["http"] = self._http
            kw["registered_before"] = self._registered_before
        return kw

    def fetch(self, name: str, url: str | None = None, **kw: Any) -> Path:
        path = self._store.fetch(name, url, **self._bound(kw))
        self._cite(name)
        return path

    def fetch_text(self, name: str, url: str | None = None, **kw: Any) -> str:
        value = self._store.fetch_text(name, url, **self._bound(kw))
        self._cite(name)
        return value

    def fetch_json(self, name: str, url: str | None = None, **kw: Any) -> Any:
        value = self._store.fetch_json(name, url, **self._bound(kw))
        self._cite(name)
        return value

    def fetch_lines(self, name: str, url: str | None = None, **kw: Any) -> frozenset[str]:
        value = self._store.fetch_lines(name, url, **self._bound(kw))
        self._cite(name)
        return value

    def index(self, name: str, **kw: Any) -> DatasetIndex:
        value = self._store.index(name, **self._bound(kw))
        self._cite(name)
        return value

    def info(self, name: str) -> DatasetInfo:
        return self._store.info(name)

    def first_run_hint(self) -> str | None:
        return self._store.first_run_hint()

    # ---- bundled files
    def bundled_path(self, name: str) -> Path:
        path = DataStore.bundled_path(name)
        self._cite_bundled(name)
        return path

    def bundled_exists(self, name: str) -> bool:
        return DataStore.bundled_exists(name)

    def bundled_text(self, name: str) -> str:
        value = DataStore.bundled_text(name)
        self._cite_bundled(name)
        return value

    def bundled_json(self, name: str) -> Any:
        value = DataStore.bundled_json(name)
        self._cite_bundled(name)
        return value

    def bundled_lines(self, name: str) -> frozenset[str]:
        value = DataStore.bundled_lines(name)
        self._cite_bundled(name)
        return value
