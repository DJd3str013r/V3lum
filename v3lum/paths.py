"""Where V3LUM keeps its data (config, cache, cases, feeds, plugins) and how it protects it.

Default: ``~/.v3lum``. Override with the ``V3LUM_HOME`` environment variable
(tests always point it to a temporary directory).

Permissions (AR03, A10): case data, keys and counters are private to the OS user.

* :func:`home` and :func:`sub` create the home and every subdirectory **0700** and tighten an
  existing directory that is looser (never a shared sticky directory such as ``/tmp``, the user's
  own home or ``/``, and never a directory owned by someone else);
* files holding case data, keys or counters are **0600**: :func:`secure_write_bytes` /
  :func:`secure_write_text` write them through ``os.open(..., 0o600)`` plus an atomic replace (no
  chmod-after-write window); :func:`restrict_file` creates/tightens SQLite databases and their
  ``-wal``/``-shm``/``-journal`` companions;
* :func:`check_permissions` lists looser modes under the home (``v3lum doctor``) and
  :func:`insecure_reasons` vets directories V3LUM loads code or rules from (plugins, specs, rules:
  owned by the current user, not group/world-writable; AR12/P331/P301).

On platforms without POSIX modes (Windows) the mode helpers are no-ops and the checks return no
findings; OS full-disk encryption stays the documented baseline (A10).
"""

from __future__ import annotations

import os
import re
import secrets
import stat
import tempfile
import threading
from pathlib import Path

__all__ = [
    "DIR_MODE",
    "FILE_MODE",
    "cache_file",
    "case_dir",
    "cases_dir",
    "check_permissions",
    "config_file",
    "datasets_dir",
    "db_file",
    "feeds_dir",
    "home",
    "insecure_reasons",
    "inside_home",
    "plugins_dir",
    "private_dir",
    "quota_file",
    "reminder_file",
    "restrict_file",
    "secret_key_file",
    "secure_write_bytes",
    "secure_write_text",
    "sub",
]

#: Mode of the home and of every directory under it (AR03).
DIR_MODE = 0o700
#: Mode of every file holding case data, keys or counters (AR03).
FILE_MODE = 0o600

#: Case ids name a directory under :func:`cases_dir`: no separators, no '..' (same rule as the engine).
_CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
#: SQLite companion files that copy the database's content.
_SQLITE_COMPANIONS = ("-wal", "-shm", "-journal")
_POSIX = os.name == "posix" and hasattr(os, "getuid")


# --------------------------------------------------------------------------------------
# mode helpers
# --------------------------------------------------------------------------------------


def _uid() -> int | None:
    return os.getuid() if _POSIX else None


def _protected_dirs() -> set[str]:
    """Directories never chmodded even when V3LUM_HOME points at them by mistake."""
    out = {os.path.realpath(os.sep)}
    for candidate in (os.path.expanduser("~"), tempfile.gettempdir(), "/tmp", "/var/tmp", "/home", "/Users"):
        try:
            out.add(os.path.realpath(candidate))
        except (OSError, ValueError):  # pragma: no cover - exotic platforms
            continue
    return out


def _tighten_dir(path: str | os.PathLike[str]) -> None:
    """chmod 0700 a looser directory we own (never a sticky shared dir, the user's home or '/')."""
    if not _POSIX:
        return
    try:
        st = os.stat(path)
    except OSError:
        return
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != _uid():
        return
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077 == 0:
        return
    if st.st_mode & stat.S_ISVTX:  # /tmp-like shared directory: never ours to lock down
        return
    if os.path.realpath(path) in _protected_dirs():
        return
    try:
        os.chmod(path, DIR_MODE)
    except OSError:  # pragma: no cover - read-only filesystem: check_permissions reports it
        pass


def _tighten_file(path: str | os.PathLike[str]) -> None:
    """chmod 0600 a looser regular file we own."""
    if not _POSIX:
        return
    try:
        st = os.stat(path)
    except OSError:
        return
    if not stat.S_ISREG(st.st_mode) or st.st_uid != _uid():
        return
    if stat.S_IMODE(st.st_mode) & 0o077:
        try:
            os.chmod(path, FILE_MODE)
        except OSError:  # pragma: no cover - read-only filesystem
            pass


def _mkdir_private(path: Path) -> None:
    """Create ``path`` (and missing parents) with 0700; tighten ``path`` when it already exists."""
    if not path.is_dir():
        missing: list[Path] = []
        probe = path
        while not probe.exists() and probe != probe.parent:
            missing.append(probe)
            probe = probe.parent
        for directory in reversed(missing):
            try:
                directory.mkdir(mode=DIR_MODE)
            except FileExistsError:  # created concurrently; a file in the way is an error
                if not directory.is_dir():
                    raise
            _tighten_dir(directory)
    _tighten_dir(path)


# --------------------------------------------------------------------------------------
# the home and its directories (v1 names kept)
# --------------------------------------------------------------------------------------


def _home_path() -> Path:
    base = os.environ.get("V3LUM_HOME") or os.path.join(os.path.expanduser("~"), ".v3lum")
    return Path(base)


def home() -> Path:
    """The V3LUM home (``$V3LUM_HOME`` or ``~/.v3lum``), created 0700 and tightened when looser."""
    path = _home_path()
    if not path.is_dir():
        path.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    _tighten_dir(path)
    return path


def _relative_parts(name: str) -> tuple[str, ...]:
    parts = tuple(p for p in Path(str(name)).parts if p not in ("", "."))
    if not parts or Path(str(name)).is_absolute() or any(p == ".." for p in parts):
        raise ValueError(f"invalid V3LUM home subdirectory {name!r} (relative path without '..' expected)")
    return parts


def sub(name: str) -> Path:
    """A directory under the home (nested names like ``'cases/<id>/evidence'`` allowed), every
    component created 0700 and tightened when it already exists with a looser mode."""
    path = home()
    for part in _relative_parts(name):
        path = path / part
        if not path.is_dir():
            try:
                path.mkdir(mode=DIR_MODE)
            except FileExistsError:  # created concurrently; a file in the way is an error
                if not path.is_dir():
                    raise
        _tighten_dir(path)
    return path


def private_dir(path: str | os.PathLike[str]) -> Path:
    """Create ``path`` with 0700 for every missing component. Existing directories are tightened
    only inside the V3LUM home (a report directory chosen with ``-o`` elsewhere keeps its mode; the
    files written there are 0600 anyway)."""
    target = Path(path)
    inside = inside_home(target)
    if not target.is_dir():
        _mkdir_private(target)
    elif inside:
        _tighten_dir(target)
    return target


def inside_home(path: str | os.PathLike[str]) -> bool:
    """True when ``path`` (resolved) lies inside the V3LUM home (without creating anything)."""
    try:
        return Path(os.path.realpath(path)).is_relative_to(os.path.realpath(_home_path()))
    except (OSError, ValueError):  # pragma: no cover - exotic paths
        return False


def config_file() -> Path:
    return home() / "config.json"


def db_file() -> Path:
    return home() / "v3lum.db"


def cache_file() -> Path:
    return sub("cache") / "http_cache.db"


def quota_file() -> Path:
    """Default provider quota DB (``~/.v3lum/quota.db``; setting ``quota_db_path`` may override it)."""
    return home() / "quota.db"


def secret_key_file() -> Path:
    """The installation secret of the keyed HMAC pseudonyms (A4): ``~/.v3lum/secret.key`` (0600)."""
    return home() / "secret.key"


def reminder_file() -> Path:
    """State of the once-a-day retention reminder (A10): ``~/.v3lum/reminder.json`` (0600)."""
    return home() / "reminder.json"


def cases_dir() -> Path:
    return sub("cases")


def case_dir(case_id: str) -> Path:
    """The 0700 directory of one case (``cases/<case_id>``); the id must be a plain name."""
    if not _CASE_ID_RE.match(str(case_id or "")):
        raise ValueError(f"invalid case id {case_id!r}")
    return sub(f"cases/{case_id}")


def feeds_dir() -> Path:
    return sub("feeds")


def datasets_dir() -> Path:
    return sub("datasets")


def plugins_dir() -> Path:
    return sub("plugins")


# --------------------------------------------------------------------------------------
# private files
# --------------------------------------------------------------------------------------


def restrict_file(path: str | os.PathLike[str], *, create: bool = False, companions: bool = True) -> Path:
    """Make ``path`` owner-only (0600): created empty with 0600 when ``create`` and missing (so a
    SQLite database never exists with a looser mode), tightened when looser, together with its
    ``-wal``/``-shm``/``-journal`` companions. ``':memory:'`` and ``file:`` URIs are left alone."""
    text = str(path)
    p = Path(text)
    if not text or text == ":memory:" or text.startswith("file:"):
        return p
    if create and not p.exists():
        try:
            os.close(os.open(text, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE))
        except FileExistsError:
            pass
        except OSError:  # pragma: no cover - read-only filesystem: SQLite reports it
            return p
    _tighten_file(text)
    if companions:
        for suffix in _SQLITE_COMPANIONS:
            _tighten_file(text + suffix)
    return p


def secure_write_bytes(path: str | os.PathLike[str], data: bytes, *, mode: int = FILE_MODE) -> Path:
    """Write ``data`` to ``path`` atomically with an owner-only mode (default 0600).

    The bytes go to a fresh temporary file in the same directory created through
    ``os.open(O_WRONLY | O_CREAT | O_EXCL, mode)`` (never through a pre-existing file or symlink),
    are flushed and fsynced, then ``os.replace`` puts the file in place. A missing parent directory
    is created 0700. Returns the path.
    """
    target = Path(path)
    parent = target.parent
    if not parent.is_dir():
        private_dir(parent)
    tmp = parent / f".{target.name}.{os.getpid()}.{threading.get_ident()}.{secrets.token_hex(4)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, mode)
    try:
        if _POSIX:
            try:
                os.fchmod(fd, mode)  # exact mode whatever the process umask
            except OSError:  # pragma: no cover - exotic filesystems
                pass
        with os.fdopen(fd, "wb") as fh:
            fd = -1
            fh.write(bytes(data))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return target


def secure_write_text(path: str | os.PathLike[str], text: str, *, encoding: str = "utf-8", mode: int = FILE_MODE) -> Path:
    """:func:`secure_write_bytes` for text (UTF-8 by default)."""
    return secure_write_bytes(path, str(text).encode(encoding), mode=mode)


# --------------------------------------------------------------------------------------
# checks (doctor, plugin/spec/rule loaders)
# --------------------------------------------------------------------------------------


def check_permissions(root: str | os.PathLike[str] | None = None, *, limit: int = 200) -> list[str]:
    """Looser modes under the home (default) or ``root``: directories that are not 0700, regular
    files readable or writable by group/others, entries owned by another user. Symbolic links are
    not followed. Nothing is changed; at most ``limit`` lines (then a '... and N more' line)."""
    if not _POSIX:
        return []
    base = Path(root) if root is not None else _home_path()
    if not base.exists():
        return []
    uid = _uid()
    problems: list[str] = []

    def check(path: str, is_dir: bool) -> None:
        try:
            st = os.lstat(path)
        except OSError:
            return
        if stat.S_ISLNK(st.st_mode):
            return
        mode = stat.S_IMODE(st.st_mode)
        if st.st_uid != uid:
            problems.append(f"{path}: owned by uid {st.st_uid}, not the current user (uid {uid})")
        if is_dir and stat.S_ISDIR(st.st_mode) and mode & 0o077:
            problems.append(f"{path}: directory mode {mode:04o}, expected 0700 (chmod 700)")
        elif not is_dir and stat.S_ISREG(st.st_mode) and mode & 0o077:
            problems.append(f"{path}: file mode {mode:04o}, expected 0600 (chmod 600)")

    check(str(base), True)
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        for name in sorted(dirnames):
            check(os.path.join(dirpath, name), True)
        for name in sorted(filenames):
            check(os.path.join(dirpath, name), False)
    if len(problems) > limit:
        extra = len(problems) - limit
        problems = problems[:limit] + [f"... and {extra} more"]
    return problems


def insecure_reasons(path: str | os.PathLike[str]) -> list[str]:
    """Why V3LUM must not load code, specs or rules from ``path`` (AR12, P331, P301): owned by
    another user, group-writable or world-writable (symbolic links are followed: the target is
    checked). Empty list = acceptable (a missing path has nothing to load and gives [])."""
    if not _POSIX:
        return []
    p = Path(path)
    try:
        st = os.stat(p)
    except FileNotFoundError:
        return []
    except OSError as exc:
        return [f"{p}: cannot be checked ({exc.strerror or exc})"]
    reasons: list[str] = []
    uid = _uid()
    if st.st_uid != uid:
        reasons.append(f"{p}: owned by uid {st.st_uid}, not the current user (uid {uid})")
    mode = stat.S_IMODE(st.st_mode)
    if mode & stat.S_IWGRP:
        reasons.append(f"{p}: group-writable (mode {mode:04o})")
    if mode & stat.S_IWOTH:
        reasons.append(f"{p}: world-writable (mode {mode:04o})")
    return reasons
