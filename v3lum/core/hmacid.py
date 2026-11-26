"""Keyed HMAC pseudonyms of entity values (A4).

V3LUM never puts an investigated value (e-mail, phone, CPF, username...) in a file name or a search
index. It uses a keyed HMAC instead:

* :func:`installation_secret` - 32 random bytes in ``~/.v3lum/secret.key`` (0600, created on first
  use, never exported); the same secret for the whole installation, so pseudonyms are stable;
* :func:`hmac_hex` - ``HMAC-SHA256(secret, f'{etype}:{normalized_value}')`` as 64 hex characters;
* :func:`hmac12` - its first 12 hex characters (evidence file names
  ``<module>__<type>__<hmac12>__<sha10>.json``, the case search column, the org verification token);
* :func:`pseudonym` / :func:`pseudonymize_key` - the search-index form ``'<type>:#<hmac12>'`` used
  for :data:`PSEUDONYMISED_TYPES` (PERSONAL_TYPES, the detect-only SECRET_TYPES and free text and
  file inputs, which can carry personal identifiers); other entity keys stay as they are.

Without the secret file nobody can test a guessed value against a pseudonym (unlike a plain
SHA-256 of an e-mail address). A secret file owned by another user is refused (it could have been
planted to make the pseudonyms reversible). Values are expected normalized (``Entity.value``); the
type may be an ``EntityType`` or its value string.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
from typing import Any

from v3lum import paths
from v3lum.core.entities import PERSONAL_TYPES, SECRET_TYPES, EntityType

__all__ = [
    "PSEUDONYMISED_TYPES",
    "SECRET_BYTES",
    "entity_hmac",
    "hmac12",
    "hmac_hex",
    "installation_secret",
    "is_pseudonym",
    "pseudonym",
    "pseudonymize_key",
]

#: Size of a newly created installation secret.
SECRET_BYTES = 32
#: Entity types whose values appear in search indexes only as pseudonyms: PERSONAL_TYPES (A4/A8), the
#: detect-only SECRET_TYPES (a token or card number never sits in an index in clear, even when a
#: caller forgot to redact it) and free text and file inputs, which can carry personal identifiers.
PSEUDONYMISED_TYPES: frozenset[EntityType] = frozenset(PERSONAL_TYPES | SECRET_TYPES | {EntityType.TEXT, EntityType.FILE})
#: Shortest secret accepted from an existing secret.key (a hand-provisioned team key may differ).
_MIN_SECRET_BYTES = 16

_LOCK = threading.Lock()
#: realpath of secret.key -> ((device, inode, mtime_ns, size, mode), secret)
_CACHE: dict[str, tuple[tuple[int, int, int, int, int], bytes]] = {}


def _type_name(etype: Any) -> str:
    value = getattr(etype, "value", etype)
    return str(value or "").strip()


def _signature(st: os.stat_result) -> tuple[int, int, int, int, int]:
    return (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size, st.st_mode)


def _create(path: str) -> None:
    """Create the secret atomically: a complete 0600 temp file hard-linked into place (no reader
    ever sees a partial key; when two processes race, the first link wins)."""
    data = secrets.token_bytes(SECRET_BYTES)
    tmp = paths.secure_write_bytes(f"{path}.{os.getpid()}.{threading.get_ident()}.new", data)
    try:
        try:
            os.link(tmp, path)
        except FileExistsError:
            pass
        except OSError:  # no hard links on this filesystem: exclusive create instead
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, paths.FILE_MODE)
            except FileExistsError:
                return
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _check_owner(path: str, st: os.stat_result) -> None:
    """Refuse a secret owned by someone else: whoever planted it knows it (POSIX only)."""
    getuid = getattr(os, "getuid", None)
    if os.name == "posix" and callable(getuid) and st.st_uid != getuid():
        raise RuntimeError(
            f"{path} is owned by uid {st.st_uid}, not by the current user (uid {getuid()}): refusing it as the "
            "installation secret (whoever wrote it could reverse the pseudonyms); check the V3LUM home"
        )


def installation_secret() -> bytes:
    """The installation secret (``paths.secret_key_file()``), created with 32 random bytes and mode
    0600 on first use; a looser mode is tightened. Raises RuntimeError for a damaged key file
    (shorter than 16 bytes) instead of silently changing every pseudonym, and for a key file owned by
    another user."""
    path = str(paths.secret_key_file())
    with _LOCK:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            st = None
        if st is not None and st.st_size == 0:  # a crash left an empty file: nothing was ever derived from it
            _check_owner(path, st)
            try:
                os.unlink(path)
            except OSError:
                pass
            st = None
        if st is None:
            _create(path)
            st = os.stat(path)
        _check_owner(path, st)
        key = os.path.realpath(path)
        cached = _CACHE.get(key)
        if cached is not None and cached[0] == _signature(st):
            return cached[1]
        paths.restrict_file(path, companions=False)
        with open(path, "rb") as fh:
            secret = fh.read(4096)
        if len(secret) < _MIN_SECRET_BYTES:
            raise RuntimeError(
                f"{path} is damaged ({len(secret)} bytes): restore it from a backup, or delete it to start "
                "new pseudonyms (existing evidence names and search indexes then stop matching)"
            )
        _CACHE[key] = (_signature(os.stat(path)), secret)
        return secret


def hmac_hex(etype: Any, normalized_value: str) -> str:
    """HMAC-SHA256(installation secret, ``f'{etype}:{normalized_value}'``) as lowercase hex."""
    message = f"{_type_name(etype)}:{normalized_value}".encode("utf-8", errors="surrogatepass")
    return hmac.new(installation_secret(), message, hashlib.sha256).hexdigest()


def hmac12(etype: Any, normalized_value: str) -> str:
    """The first 12 hex characters of :func:`hmac_hex` (file names, search columns, tokens)."""
    return hmac_hex(etype, normalized_value)[:12]


def entity_hmac(entity: Any) -> str:
    """:func:`hmac_hex` of an ``Entity`` (its type and normalized value)."""
    return hmac_hex(entity.type, entity.value)


def pseudonym(etype: Any, normalized_value: str) -> str:
    """Search-index form of a value: ``'<type>:#<hmac12>'``."""
    return f"{_type_name(etype)}:#{hmac12(etype, normalized_value)}"


def is_pseudonym(key: str) -> bool:
    """True for a ``'<type>:#<12 hex>'`` pseudonym."""
    _etype, sep, rest = str(key or "").partition(":")
    return bool(sep) and len(rest) == 13 and rest.startswith("#") and all(c in "0123456789abcdef" for c in rest[1:])


def pseudonymize_key(key: str) -> str:
    """An entity key ``'type:value'`` as it may appear in a search index: :func:`pseudonym` for
    :data:`PSEUDONYMISED_TYPES` (PERSONAL_TYPES, SECRET_TYPES, free text, file inputs), unchanged for
    other types.
    A key of an unknown type is pseudonymised (fail closed: it might be personal); a pseudonym is
    returned unchanged."""
    text = str(key or "")
    if is_pseudonym(text):
        return text
    etype_name, sep, value = text.partition(":")
    if not sep:
        return text
    try:
        etype = EntityType.parse(etype_name)
    except ValueError:
        return pseudonym(etype_name, value)
    if etype in PSEUDONYMISED_TYPES:
        return pseudonym(etype, value)
    return text
