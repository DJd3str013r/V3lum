"""Central secret redaction (AR01): nothing that leaves the core carries a key.

Every configured key value is registered here (``config`` registers loaded/set keys, ``Runtime``
registers the keys of a session) and every URL or message that is cached, emitted, logged, raised or
persisted passes :func:`redact_url` / :func:`redact_text` first:

* registered secrets are masked anywhere (path, query, fragment, free text) - abuse.ch v2 export URLs
  embed the Auth-Key in the path - in their raw and URL-encoded forms;
* values of key-like query parameters (:data:`KEY_PARAMS`) are masked even when unregistered;
* ``user:password@host`` URL credentials keep the user and lose the password;
* :func:`redact_headers` masks credential headers (Authorization, Cookie, X-Api-Key, ...) and any
  header carrying a registered secret.

Values shorter than 6 characters are ignored (they would mask ordinary text). The registry is
process-wide and thread-safe; tests reset it with :func:`clear`.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote, quote_plus

__all__ = [
    "CREDENTIAL_HEADERS",
    "KEY_PARAMS",
    "MASK",
    "MIN_SECRET_LENGTH",
    "clear",
    "has_secret",
    "is_credential_header",
    "redact_headers",
    "redact_text",
    "redact_url",
    "register_secret",
    "registered_count",
]

#: Replacement for every masked value.
MASK = "***"
#: Shorter values are not registered (they would mask ordinary words).
MIN_SECRET_LENGTH = 6
#: Query/fragment parameter names whose values are always masked (case-insensitive).
KEY_PARAMS: tuple[str, ...] = (
    "key",
    "apikey",
    "api_key",
    "api-key",
    "token",
    "access_token",
    "auth",
    "auth_key",
    "sig",
    "signature",
    "password",
    "passwd",
    "secret",
    "client_secret",
)
#: Request/response headers that carry credentials (lower case).
CREDENTIAL_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "auth-key",
        "key",
        "x-auth-token",
        "token",
    }
)

#: a key-like parameter in a URL query/fragment, or at the start of a form body / free-text token
#: ('apikey=...' in an echoed request body or an error message)
_PARAM_RE = re.compile(
    r"(?i)((?:(?<=[?&;#\s\"'(,])|^)(?:" + "|".join(re.escape(p) for p in sorted(KEY_PARAMS, key=len, reverse=True)) + r")=)([^&#\s\"'<>]*)"
)
_USERINFO_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@?#]+):([^@\s/?#]+)@")

_LOCK = threading.Lock()
_LABELS: dict[str, str] = {}
#: raw + URL-encoded forms of every registered secret, longest first (replaced atomically).
_VARIANTS: tuple[str, ...] = ()


def _rebuild() -> None:
    global _VARIANTS
    variants: set[str] = set()
    for secret in _LABELS:
        variants.add(secret)
        variants.add(quote(secret, safe=""))
        variants.add(quote_plus(secret))
        variants.add(quote(secret, safe="/:"))
    _VARIANTS = tuple(sorted((v for v in variants if len(v) >= MIN_SECRET_LENGTH), key=len, reverse=True))


def register_secret(value: Any, label: str = "") -> bool:
    """Register a secret value (an API key, token, password) to be masked everywhere.

    Values shorter than :data:`MIN_SECRET_LENGTH` characters (after stripping) are ignored.
    Returns True when the value is (now) registered. Thread-safe; the value is never logged.
    """
    if value is None:
        return False
    text = str(value).strip()
    if len(text) < MIN_SECRET_LENGTH:
        return False
    with _LOCK:
        if text not in _LABELS:
            _LABELS[text] = str(label or "")
            _rebuild()
    return True


def registered_count() -> int:
    """How many distinct secrets are registered (never the values)."""
    with _LOCK:
        return len(_LABELS)


def clear() -> None:
    """Forget every registered secret (tests)."""
    global _VARIANTS
    with _LOCK:
        _LABELS.clear()
        _VARIANTS = ()


def has_secret(text: Any) -> bool:
    """True when ``text`` contains a registered secret (raw or URL-encoded)."""
    if not text:
        return False
    value = text if isinstance(text, str) else str(text)
    return any(v in value for v in _VARIANTS)


def _mask_secrets(text: str) -> str:
    for variant in _VARIANTS:
        if variant in text:
            text = text.replace(variant, MASK)
    return text


def _mask_param(match: re.Match[str]) -> str:
    return match.group(1) + (MASK if match.group(2) else "")


def redact_text(text: Any) -> str:
    """Mask registered secrets, key-like URL parameters and URL passwords inside free text."""
    if text is None:
        return ""
    value = text if isinstance(text, str) else str(text)
    if not value:
        return value
    value = _mask_secrets(value)
    value = _PARAM_RE.sub(_mask_param, value)
    return _USERINFO_RE.sub(lambda m: f"{m.group(1)}:{MASK}@", value)


def redact_url(url: Any) -> str:
    """Redacted form of a URL: key-like parameter values, URL passwords and every registered
    secret (path, query or fragment) replaced by :data:`MASK`. The rest of the URL is unchanged."""
    return redact_text(url)


def is_credential_header(name: str, value: Any = "") -> bool:
    """True for a credential header name, or a header whose value carries a registered secret."""
    return str(name).strip().lower() in CREDENTIAL_HEADERS or has_secret(value)


def redact_headers(headers: Mapping[str, Any] | None) -> dict[str, str]:
    """Copy of ``headers`` with credential headers (and values holding a secret) masked."""
    out: dict[str, str] = {}
    for name, value in (headers or {}).items():
        text = "" if value is None else str(value)
        out[name] = MASK if is_credential_header(name, text) else redact_text(text)
    return out
