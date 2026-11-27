"""HIBP Pwned Passwords k-anonymity check for credential findings of the secret scanner (P141).

**Not a registered module** (cond 1, architect floor): this file defines no Module class, accepts no
entity type and is reachable from no analyst input, CLI argument or text_blob path - there is no way to
type a password into it. It is the staged implementation of the core helper ``v3lum/core/pwned.py``
that the council placed in the core so that only ``secret_scanner`` (P312) calls it, for
credential-type findings, and only when setting ``secret_scanner_pwned_check`` is true (default false).
Batch p3-G04-2 may not edit the core or secret_scanner, so the helper lives here with an injected
transport (no network code of its own) and the wiring is a core request (docs/backlog/p3-G04-2.md):
move/re-export it as ``v3lum.core.pwned``, give it a core-scoped HTTP client for the provider
``pwnedpasswords`` (``api.pwnedpasswords.com``, keyless, neutral UA, no-store) and call it from
secret_scanner with the in-memory value before masking.

Guarantees (tests: tests/modules/test_pwned_passwords_internal.py):

* cond 2: the SHA-1 is computed in memory (uppercase hex); only the 5-character prefix goes to
  ``https://api.pwnedpasswords.com/range/{prefix}`` with ``Add-Padding: true``; the 35-character suffix
  is compared in memory (padding rows, count 0, never match). :func:`range_url` accepts exactly five hex
  characters, so a plaintext, a full hash or a suffix can never reach a URL.
* cond 3: the plaintext, the full hash and the suffix live only inside :func:`lookup` and are never
  logged, cached, returned, put in ``res.raw`` or evidence; :class:`PwnedResult` holds only the count, the
  note, a reason and the attribution. Only the public range body may be cached (the provider is flagged
  sensitive and the body is plain text, so the core never caches it; :func:`http_fetch` asks for
  no-store anyway).
* cond 4: the result goes onto the already-masked finding as 'appears N times in public breach corpora'
  (:func:`annotate`); a range lookup is k-anonymity only and never validates a credential against its
  service. A failed lookup (transport error, 4xx/5xx, challenge, malformed or truncated body) is
  'could not verify', never 0.
* cond 5: attribution to Have I Been Pwned (CC BY 4.0) on every result that carries a count.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

__all__ = [
    "ATTRIBUTION",
    "ATTRIBUTION_URL",
    "CREDENTIAL_KINDS",
    "HEADERS",
    "RANGE_URL",
    "SETTING",
    "SOURCE",
    "PwnedResult",
    "annotate",
    "check_enabled",
    "count_in_range",
    "http_fetch",
    "lookup",
    "note_for",
    "parse_range",
    "range_problem",
    "range_url",
    "sha1_prefix_suffix",
]

SOURCE = "pwnedpasswords.range"
RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
HEADERS = {"Add-Padding": "true"}
SETTING = "secret_scanner_pwned_check"
ATTRIBUTION = "Have I Been Pwned - Pwned Passwords (CC BY 4.0)"
ATTRIBUTION_URL = "https://haveibeenpwned.com/Passwords"
#: credential-type finding kinds of secret_scanner (P312) that may be checked: passwords only - API keys,
#: tokens and private keys are not passwords and are never sent anywhere (A8 SECRET_TYPES)
CREDENTIAL_KINDS = frozenset({
    "password", "db_password", "smtp_password", "ftp_password", "basic_auth", "url_credentials",
    "connection_string_password",
})
_PREFIX = re.compile(r"^[0-9A-Fa-f]{5}$")
_SUFFIX = re.compile(r"^[0-9A-Fa-f]{35}$")
_LINE = re.compile(r"^([0-9A-F]{35}):(\d{1,12})$")
_CHALLENGE = re.compile(r"(?i)<html|cf-chl|just a moment|captcha|access denied")


@dataclass(frozen=True)
class PwnedResult:
    """What a lookup returns: never the secret, the hash, the prefix or the suffix (cond 3)."""

    count: int | None
    note: str | None
    reason: str | None
    attribution: str | None

    @property
    def verified(self) -> bool:
        """True when the range answer was usable (the count is known, 0 included)."""
        return self.count is not None


def sha1_prefix_suffix(secret: str | bytes) -> tuple[str, str]:
    """(prefix5, suffix35) of the uppercase SHA-1 hex, in memory (cond 2). ValueError for an empty or
    non-text secret. Callers keep the suffix only for the comparison and never store it (cond 3)."""
    if isinstance(secret, str):
        data = secret.encode("utf-8")
    elif isinstance(secret, (bytes, bytearray)):
        data = bytes(secret)
    else:
        raise ValueError("secret must be str or bytes")
    if not data:
        raise ValueError("empty secret")
    digest = hashlib.sha1(data).hexdigest().upper()  # noqa: S324 - the k-anonymity range API is defined over SHA-1
    return digest[:5], digest[5:]


def range_url(prefix: Any) -> str:
    """The range URL for exactly five hex characters (uppercased); ValueError for anything else (cond 2)."""
    if not isinstance(prefix, str) or not _PREFIX.match(prefix):
        raise ValueError("Pwned Passwords range prefix must be exactly 5 hex characters (P141 cond 2)")
    return RANGE_URL.format(prefix=prefix.upper())


def _text(body: Any) -> str | None:
    if isinstance(body, (bytes, bytearray)):
        try:
            return bytes(body).decode("ascii")
        except UnicodeDecodeError:
            return None
    return body if isinstance(body, str) else None


def parse_range(body: Any) -> dict[str, Any] | None:
    """Range body -> {'counts': {suffix: count > 0}, 'rows', 'padding_rows'}, or None when unusable.

    CRLF or LF, blank lines ignored; every other line must be 'SUFFIX35:COUNT' (uppercase hex). Padding
    rows (count 0) are counted, never matched. One malformed line (HTML, a truncated transfer) makes the
    whole body unusable: 'could not verify', never 'not found' (rule 5)."""
    text = _text(body)
    if text is None:
        return None
    counts: dict[str, int] = {}
    rows = padding = 0
    for raw in text.split("\n"):
        line = raw.rstrip("\r").strip()
        if not line:
            continue
        m = _LINE.match(line)
        if not m:
            return None
        rows += 1
        count = int(m.group(2))
        if count == 0:
            padding += 1
        else:
            counts[m.group(1)] = count
    return {"counts": counts, "rows": rows, "padding_rows": padding} if rows else None


def count_in_range(body: Any, suffix: Any) -> int | None:
    """Breach-corpus count of a 35-character suffix (0 when absent or a padding row); None if unusable."""
    if not isinstance(suffix, str) or not _SUFFIX.match(suffix):
        return None
    parsed = parse_range(body)
    if parsed is None:
        return None
    return parsed["counts"].get(suffix.upper(), 0)


def range_problem(status: Any, body: Any, headers: Mapping[str, Any] | None = None) -> str | None:
    """Why a range answer is unusable ('could not verify'), or None for a usable 200 body (P321, rule 5)."""
    try:
        st = int(status)
    except (TypeError, ValueError):
        return "Pwned Passwords: no HTTP status (could not verify)"
    text = _text(body) or ""
    if st == 400:
        return "Pwned Passwords rejected the prefix (HTTP 400): could not verify"
    if st == 429:
        return "Pwned Passwords rate limited the lookup (HTTP 429): could not verify"
    if st in (401, 403, 407, 430, 451, 999) or _CHALLENGE.search(text[:4096]):
        return f"Pwned Passwords refused or challenged the lookup (HTTP {st}): could not verify"
    if st >= 500:
        return f"Pwned Passwords server error (HTTP {st}): could not verify"
    if st != 200:
        return f"Pwned Passwords answered HTTP {st}: could not verify"
    if parse_range(body) is None:
        return "Pwned Passwords range body malformed or truncated: could not verify"
    return None


def note_for(count: Any) -> str | None:
    """'appears N times in public breach corpora' (cond 4); None when the count is unknown."""
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        return None
    return f"appears {count} time{'' if count == 1 else 's'} in public breach corpora"


Fetch = Callable[[str, dict[str, str]], tuple[Any, Any, Any]]


def lookup(secret: str | bytes, fetch_range: Fetch, *, finding_kind: str, enabled: bool = False) -> PwnedResult:
    """The k-anonymity flow (cond 1-5). ``fetch_range(url, headers) -> (status, headers, body)`` is the
    injected transport. Off unless ``enabled`` (setting ``secret_scanner_pwned_check``); credential-type
    findings only (:data:`CREDENTIAL_KINDS`, ValueError otherwise). Only the 5-character prefix leaves
    this function; the suffix is compared in memory and every local reference is dropped before return."""
    if not enabled:
        return PwnedResult(None, None, f"disabled ({SETTING} is false)", None)
    if finding_kind not in CREDENTIAL_KINDS:
        raise ValueError("Pwned Passwords checks credential-type findings only (P141 cond 1)")
    prefix, suffix = sha1_prefix_suffix(secret)
    problem: str | None = None
    count: int | None = None
    try:
        url = range_url(prefix)
        try:
            status, headers, body = fetch_range(url, dict(HEADERS))
        except Exception as exc:  # noqa: BLE001 - any transport failure means 'could not verify' (rule 5)
            problem = f"Pwned Passwords request failed ({type(exc).__name__}): could not verify"
        else:
            problem = range_problem(status, body, headers if isinstance(headers, Mapping) else None)
            if problem is None:
                count = count_in_range(body, suffix)
                if count is None:
                    problem = "Pwned Passwords range body unusable: could not verify"
            body = None
    finally:
        prefix = suffix = url = ""  # drop the references as soon as the comparison is done (cond 3)
        secret = b""
    if problem is not None:
        return PwnedResult(None, None, problem, None)
    return PwnedResult(count, note_for(count), None, ATTRIBUTION)


def check_enabled(ctx: Any) -> bool:
    """Setting ``secret_scanner_pwned_check`` (default false: unregistered or unset reads as off)."""
    setting = getattr(ctx, "setting", None)
    if not callable(setting):
        return False
    try:
        return setting(SETTING, False) is True
    except Exception:  # noqa: BLE001 - an unreadable setting keeps the check off
        return False


def http_fetch(http: Any) -> Fetch:
    """Adapter from a scoped HTTP client (``.get(url, headers=, source=, ttl=, allow_redirects=)``, the
    core client the wiring provides) to ``fetch_range``: no-store, no redirects, source
    ``pwnedpasswords.range``."""

    def fetch(url: str, headers: dict[str, str]) -> tuple[Any, Any, Any]:
        resp = http.get(url, headers=headers, source=SOURCE, ttl=0, allow_redirects=False)
        return getattr(resp, "status", 0), dict(getattr(resp, "headers", None) or {}), getattr(resp, "content", b"")

    return fetch


def annotate(finding_data: Mapping[str, Any] | None, result: PwnedResult) -> dict[str, Any]:
    """Copy of an already-masked finding's data with the cond 4 note (count, note, attribution) or the
    'could not verify' reason - never anything about the secret itself."""
    out = dict(finding_data or {})
    if result.count is not None:
        out["pwned_count"] = result.count
        out["pwned_note"] = result.note
        out["pwned_attribution"] = f"{result.attribution} - {ATTRIBUTION_URL}"
        out["pwned_note_scope"] = "k-anonymity range lookup: never validates the credential against its service"
    elif result.reason:
        out["pwned_check"] = result.reason
    return out
