"""Data-minimisation sanitizer (P145, A4): allow-list schemas, a second-net denylist, value detectors.

The engine runs :func:`sanitize_result` on every module result right after ``Module.run``
returns (modules cannot opt out) and fails closed: an exception drops what the module produced
and the run ends ERROR with reason_code 'sanitizer'. The HTTP client calls :func:`sanitize_body`
before caching (and before handing over) bodies of providers flagged sensitive: no schema, a
non-JSON body or any failure gives None ('do not cache').

Stages of :func:`sanitize_result` (P145 complete, WP09):

(0) **JSON shape** - sets become sorted lists, bytes text, non-string keys strings and any other object
    its ``str()`` when that text carries something to remove (always for sensitive modules), so no
    value escapes the string passes below (the stores serialise unknown objects with ``default=str``).
(a) **category scoping** - sensitive modules (``Module.sensitive``: category breach_leak or a
    provider flagged sensitive) keep only each source's allow-list schema in ``res.raw``; then the
    second net (:data:`SECOND_NET_FIELDS`, case-insensitive, nested) drops passwords, hashes, salts,
    masked hints, cookies, sessions, tokens, autofill, computer names, infected-host IPs, malware
    paths, leaked file contents and combo lines from raw, attributes and finding data whatever the
    schema says. Their free text (titles, descriptions, criteria, references, pivot notes, link
    labels, errors) loses 'name: value' pairs of second-net fields, every value the module read
    from a second-net field, masked tokens ('p***2'), IP addresses other than the investigated
    one, file paths and default Windows computer names; pivots and links that carry such a value
    are dropped. Modules of :data:`HASH_EXEMPT_CATEGORIES` (malware_hash, threat_intel_ioc) are
    exempt from the 'hash' rule and keep their sha256/md5/'hash' fields (P145 cond 6).
(b) **value detectors** for every module: email:password and user:pass@host combos (URL-encoded
    forms included) are dropped from every string (a pasted combo keeps only the e-mail); inside
    sensitive payloads password hashes (bcrypt, argon2, crypt formats...) are dropped anywhere and
    MD5/SHA-1/SHA-256/SHA-512 hex values next to a credential (a dict with an account or password
    key, a string with an e-mail or a credential word) too.
(c) **secrets** (:data:`SECRET_PATTERNS`: cloud/API keys, tokens, private-key blocks, JWTs,
    connection-string keys, .env/config assignments; HTTP Basic credentials are dropped) become
    :func:`mask_secret`-shaped dicts (type + preview + SHA-256; the preview follows
    ``entities.secret_preview``, first 4/last 4 from 16 characters) when a whole value is a secret, and the fingerprint
    ``'<kind>:<first4>…<last4>:<sha16>'`` (the SECRET entity value) inside text; labelled
    passwords are dropped, never hashed (a SHA-256 of a password is a crackable hash). A value under
    a password key ('db_password') is dropped and one under a secret key ('api_token') masked, like
    the same assignment in text; links and references carrying a secret are dropped.
(d) every string passes ``redact.redact_text`` (AR01; pivot values only lose registered secrets,
    as in the engine's own pass).
(e) ``res.redacted_fields`` lists every dropped or masked path (``'raw.stealers[].ip'``) and each
    area where values were removed from text (``'findings:combo'``, ``'raw:secret'``,
    ``'pivots:second_net'``...); evidence records it.
(f) the password FORM survives only as the kept field ``password_form`` (:func:`is_password_form`:
    'plaintext' | 'hashed: <algorithm>' | 'hashed' | 'unknown'); any other value is dropped. In
    sensitive payloads a provider field that carries the form under another name ('password_risk':
    'easytocrack') is renamed ``password_form`` with the normalised value
    (:func:`normalize_password_form`), and schemas keep ``password_form`` next to any kept field.

:func:`scrub_text` applies the detectors to text and file inputs before extraction (combos,
tab/comma combo lines, password hashes, masked hints, secrets).

Allow-list schemas are registered per registry source, either at import time in the module file::

    from v3lum.core import sanitize
    sanitize.register_schema("hudsonrock.cavalier", keep=["stealers[].date_compromised",
                             "stealers[].stealer_family", "total_corporate_services"])

or in the provider fragment (``providers.<pid>.sources.<sid>.sanitizer = {"keep": [...]}``).
Keep paths are dotted keys with ``[]`` for list elements and ``*`` for any key. Modules record
the password FORM in a kept field ``password_form`` ('plaintext' | 'hashed: <algorithm>') and
never keep passwords, hashes, salts, masked hints, cookies, tokens, computer names,
infected-host IPs, malware paths or combo lines.
"""

from __future__ import annotations

import base64
import copy
import functools
import hashlib
import ipaddress
import json
import re
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NamedTuple
from urllib.parse import unquote

from v3lum.core import redact as _redact

if TYPE_CHECKING:  # pragma: no cover
    from v3lum.core.models import ModuleResult


class SanitizerError(RuntimeError):
    """The sanitizer could not process a result (the engine fails closed: ERROR 'sanitizer')."""


@dataclass(frozen=True)
class SanitizerSchema:
    """Allow-list of the metadata kept from one registry source's payloads."""

    source_id: str
    keep: tuple[str, ...]
    notes: str = ""


#: P145 cond 4 / A4: field names dropped (case-insensitive, nested) from sensitive payloads,
#: attributes and finding data, whatever the schema says.
SECOND_NET_FIELDS: frozenset[str] = frozenset({
    "password", "passwords", "passwd", "pass", "pwd", "pswd", "pw", "senha", "senhas", "passwort", "contrasena",
    "hash", "hashes", "password_hash", "passwordhash", "hashed_password", "salt",
    "top_passwords", "top_logins", "login", "logins", "username", "usernames", "user_name", "credential", "credentials",
    "cred", "creds", "cleartext",
    "masked_password", "password_masked", "masked", "hint", "password_hint", "hints",
    "cookie", "cookies", "session", "sessions", "session_id", "session_token", "session_cookie",
    "token", "tokens", "access_token", "refresh_token", "auth_token",
    "autofill", "autofills", "credit_cards", "credit_card", "card_number", "cvv",
    "secret", "secrets", "api_key", "apikey", "private_key", "auth_key", "authorization",
    "computer_name", "computername", "pc_name", "machine_name", "machine_id", "device_name", "hwid", "infected_machine",
    "ip", "ip_address", "infected_ip", "victim_ip", "infected_host_ip",
    "malware_path", "combo", "combos", "line", "lines", "combo_line",
    "content", "contents", "file_content", "file_contents", "leaked_content", "paste_content",
    # wave-2 review: other credential names (codes, passphrases, MFA seeds, recovery answers, languages)
    "passcode", "passphrase", "pin", "pincode", "pin_code", "otp", "totp", "otp_secret", "mfa_secret", "security_answer",
    "secret_answer", "kennwort", "wachtwoord", "mot_de_passe", "motdepasse",
})
#: Substrings that make a key sensitive anywhere in its (normalised) name.
_SECOND_NET_SUBSTRINGS = (
    "password", "passwd", "senha", "passwort", "cookie", "token", "session", "autofill", "combo", "computer_name", "malware_path",
    "secret", "api_key", "apikey", "private_key", "credit_card", "credential", "file_content", "passcode", "passphrase",
)
#: Single words that make a key sensitive when they appear as a '_'-separated token.
_SECOND_NET_TOKENS = frozenset({
    "pass", "pwd", "pswd", "hash", "hashes", "salt", "hint", "hints", "masked", "login", "logins", "ip", "line", "lines",
    "cvv", "hwid", "cred", "creds", "pin", "otp", "totp",
})
#: Keys starting with these words are masked values or hints ('maskedEmail', 'hintText').
_SECOND_NET_PREFIXES = ("masked", "hint")
#: Kept even though they look sensitive (the password FORM is metadata, A4).
_SECOND_NET_ALLOW = frozenset({"password_form"})
#: The 'hash' rule of the second net: names malware/hash modules keep (P145 cond 6).
_HASH_RULE_NAMES = frozenset({"hash", "hashes"})
#: Module categories exempt from the 'hash' rule and from the hex-hash value detector: their
#: sha256/md5/'hash' fields are indicators, not credentials (P145 cond 6).
HASH_EXEMPT_CATEGORIES: frozenset[str] = frozenset({"malware_hash", "threat_intel_ioc"})

_SCHEMAS: dict[str, SanitizerSchema] = {}
_LOCK = threading.Lock()
_PATH_SEGMENT = re.compile(r"^(?:\*|[^.\[\]]+)?(?:\[\])*$")
#: sentinel returned by leaf rewriters: remove this leaf
_DROP = object()
#: replacement for values read from second-net fields that a module copied into free text
_REDACTED = "[redacted]"


# ----------------------------------------------------------------------------------------
# Schema registry
# ----------------------------------------------------------------------------------------


def _tokens(path: str) -> list[str]:
    """'breaches[].Name' -> ['breaches', '[]', 'Name']; '[].a' -> ['[]', 'a']; 'rows[][]' -> ['rows', '[]', '[]']."""
    out: list[str] = []
    for seg in path.split("."):
        if not seg or not _PATH_SEGMENT.match(seg):
            raise ValueError(f"invalid keep path {path!r} (dotted keys, '[]' for list elements, '*' for any key)")
        name = seg
        lists = 0
        while name.endswith("[]"):
            name = name[:-2]
            lists += 1
        if name:
            out.append(name)
        out.extend(["[]"] * lists)
    return out


def register_schema(source_id: str, *, keep: Iterable[str], notes: str = "") -> SanitizerSchema:
    """Register the allow-list for ``source_id`` ('provider.source'). Same keep list again is a no-op."""
    if not isinstance(source_id, str) or not source_id.strip():
        raise ValueError("register_schema needs a registry source id ('provider.source')")
    if isinstance(keep, str):
        keep = [keep]
    paths = tuple(dict.fromkeys(str(p).strip() for p in keep))
    if not paths or any(not p for p in paths):
        raise ValueError(f"{source_id}: keep must list at least one non-empty path")
    for p in paths:
        _tokens(p)
    schema = SanitizerSchema(source_id.strip(), paths, notes)
    with _LOCK:
        existing = _SCHEMAS.get(schema.source_id)
        if existing is not None and set(existing.keep) != set(paths):
            raise ValueError(f"{source_id}: a different sanitizer schema is already registered")
        _SCHEMAS[schema.source_id] = existing or schema
        return _SCHEMAS[schema.source_id]


def unregister_schema(source_id: str) -> None:
    """Remove a registered schema (tests, plugins)."""
    with _LOCK:
        _SCHEMAS.pop(source_id, None)


def schema_for(source_id: str) -> SanitizerSchema | None:
    """Registered schema first, else the provider registry's ``sources.<sid>.sanitizer``."""
    if not source_id:
        return None
    with _LOCK:
        found = _SCHEMAS.get(source_id)
    if found is not None:
        return found
    try:
        from v3lum.core import providers  # lazy: providers may import this module
    except ImportError:  # pragma: no cover - registry not installed
        return None
    try:
        src = providers.registry().source(source_id)
    except Exception:
        return None
    spec = getattr(src, "sanitizer", None) if src is not None else None
    if not isinstance(spec, dict) or not spec.get("keep"):
        return None
    keep = spec.get("keep")
    if isinstance(keep, str):
        keep = [keep]
    try:
        paths = tuple(str(p) for p in keep)
        for p in paths:
            _tokens(p)
    except (TypeError, ValueError):
        return None
    return SanitizerSchema(source_id, paths, str(spec.get("notes") or ""))


# ----------------------------------------------------------------------------------------
# Allow-list application
# ----------------------------------------------------------------------------------------


def _matches(pattern: list[str], concrete: list[str]) -> bool:
    if len(pattern) < len(concrete):
        return False
    for p, c in zip(pattern, concrete):
        if p == c:
            continue
        if p == "*" and c != "[]":
            continue
        return False
    return True


def _render(tokens: list[str]) -> str:
    out = ""
    for tok in tokens:
        if tok == "[]":
            out += "[]"
        else:
            out += ("." if out else "") + tok
    return out or "$"


def _with_forms(schema: SanitizerSchema) -> SanitizerSchema:
    """The schema plus 'password_form' next to every kept field: the password FORM is metadata kept
    under that one name (its values are validated by the sanitizer, stage f)."""
    extra = []
    for path in schema.keep:
        tokens = _tokens(path)
        parent = tokens[:-1] if tokens and tokens[-1] != "[]" else tokens
        extra.append(_render([*parent, "password_form"]) if parent else "password_form")
    keep = tuple(dict.fromkeys((*schema.keep, *extra)))
    return SanitizerSchema(schema.source_id, keep, schema.notes)


def apply_schema(obj: Any, schema: SanitizerSchema) -> tuple[Any, list[str]]:
    """Keep only the schema's paths. Returns (kept copy, sorted dropped paths in pattern form)."""
    patterns = [_tokens(p) for p in schema.keep]
    dropped: set[str] = set()

    def walk(value: Any, path: list[str]) -> tuple[bool, Any]:
        if path and any(len(p) == len(path) and _matches(p, path) for p in patterns):
            return True, copy.deepcopy(value)
        if not any(len(p) > len(path) and _matches(p, path) for p in patterns):
            dropped.add(_render(path))
            return False, None
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            for k, v in value.items():
                keep, kept = walk(v, [*path, str(k)])
                if keep:
                    out[k] = kept
            return True, out
        if isinstance(value, list):
            items = []
            for v in value:
                keep, kept = walk(v, [*path, "[]"])
                if keep:
                    items.append(kept)
            return True, items
        dropped.add(_render(path))
        return False, None

    keep, kept = walk(obj, [])
    return (kept if keep else None), sorted(dropped)


# ----------------------------------------------------------------------------------------
# Second net
# ----------------------------------------------------------------------------------------


def _normalise_key(key: Any) -> str:
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(key))
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def is_second_net_field(key: Any, *, hash_rule: bool = True) -> bool:
    """True when a field name belongs to the P145 second net (passwords, hashes, cookies, ...).

    ``hash_rule=False`` (malware/hash modules, :data:`HASH_EXEMPT_CATEGORIES`) keeps 'hash',
    'hashes' and names such as 'sha256_hash'; 'password_hash' stays a second-net field.
    """
    norm = _normalise_key(key)
    if not norm or norm in _SECOND_NET_ALLOW:
        return False
    if norm in SECOND_NET_FIELDS:
        return hash_rule or norm not in _HASH_RULE_NAMES
    if any(s in norm for s in _SECOND_NET_SUBSTRINGS):
        return True
    if norm.startswith(_SECOND_NET_PREFIXES):
        return True
    return any(tok in _SECOND_NET_TOKENS and (hash_rule or tok not in _HASH_RULE_NAMES) for tok in norm.split("_"))


def drop_second_net(obj: Any, prefix: str = "", *, hash_rule: bool = True) -> tuple[Any, list[str]]:
    """Copy of ``obj`` without second-net keys (nested, case-insensitive); returns (copy, dropped paths)."""
    dropped: list[str] = []

    def walk(value: Any, path: str) -> Any:
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                sub = f"{path}.{k}" if path else str(k)
                if is_second_net_field(k, hash_rule=hash_rule):
                    dropped.append(sub)
                    continue
                out[k] = walk(v, sub)
            return out
        if isinstance(value, list):
            return [walk(v, f"{path}[]") for v in value]
        if isinstance(value, tuple):
            return tuple(walk(v, f"{path}[]") for v in value)
        return value

    return walk(obj, prefix), dropped


# ----------------------------------------------------------------------------------------
# Combos (value detector, every module)
# ----------------------------------------------------------------------------------------

# Every pattern below runs over every string of every module result, hostile pages included: they
# are written to stay linear (bounded scheme/label lengths, no backtracking across '@').
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
_EMAIL = rf"[A-Za-z0-9._%+\-]+@{_LABEL}(?:\.{_LABEL})+"
_EMAIL_COMBO = re.compile(rf"(?<![A-Za-z0-9._%+\-])({_EMAIL})[:;|](?!//)(\S+)")
#: 'a@x.com|b@y.com', 'a@x.com;b@y.com' are address lists, not combos.
_EMAIL_LIST = re.compile(rf"^{_EMAIL}(?:[;|,:]\s*{_EMAIL})*$")
#: scp-like git remotes ('git@github.com:org/repo.git') are not combos.
_SCP_PATH = re.compile(r"^[A-Za-z0-9_.\-~]+(?:/[A-Za-z0-9_.\-~]+)+/?$")
#: scheme://[user]:password@ (an empty user included: 'redis://:pw@host'); the password may hold '@'.
_URL_USERINFO = re.compile(r"(?<![A-Za-z0-9+.\-])([A-Za-z][A-Za-z0-9+.\-]{0,31}://)[^\s/?#@:]*:[^\s/?#]*@")
_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_HOST = rf"(?:{_IPV4}|localhost|{_LABEL}(?:\.{_LABEL})*\.[A-Za-z]{{2,63}})(?![A-Za-z0-9\-])"
_IPV4_HOST = re.compile(rf"^(?:{_IPV4}|localhost)$", re.IGNORECASE)
#: '@host' of a possible user:password@host (no scheme); the user:password part is found backwards.
_AT_HOST = re.compile(rf"@({_HOST})")
#: the user of user:password inside the token before '@' (not preceded by a user character or ':').
_BARE_USER = re.compile(r"(?<![A-Za-z0-9._%+\-:])([A-Za-z0-9._%+\-]{1,128}):")
#: longest user:password token considered before an '@host'.
_MAX_USERINFO = 512
#: 'label:address@domain' reads as a label plus an e-mail, not as user:password@host.
_LABEL_PREFIXES = frozenset({
    "mailto", "email", "e-mail", "mail", "contact", "contato", "from", "to", "cc", "bcc", "reply-to", "sender", "user", "login",
    "account", "abuse", "security", "support", "suporte", "registrant", "owner", "tech", "billing", "noc", "by", "de", "para",
})
#: URL-encoded e-mail combos ('alice%40corp.example%3Ahunter2'), e.g. inside query strings.
_ENC_EMAIL_COMBO = re.compile(
    r"(?i)(?<![A-Za-z0-9._%+\-])((?:[A-Za-z0-9._+\-]|%[0-9A-F]{2}){1,128}(?:%40|@)" + _LABEL + r"(?:\." + _LABEL + r"){1,10})"
    r"(%3A|%3B|%7C)((?:[A-Za-z0-9._~!*'()+\-]|%[0-9A-F]{2}){1,512})"
)


def _drop_bare_userinfo(text: str) -> str:
    """'u:p@host' -> 'host' (the password may hold '@': the last '@' before a host wins)."""
    parts: list[str] = []
    last = 0
    for m in _AT_HOST.finditer(text):
        at = m.start()
        start, floor = at, max(last, at - _MAX_USERINFO)
        while start > floor and not text[start - 1].isspace() and text[start - 1] != "/":
            start -= 1
        if start > floor and text[start - 1] == "/":
            continue  # a URL path segment ('https://x.example/a:b@c.example'), not credentials
        um = _BARE_USER.search(text, start, at)
        if um is None or um.end() >= at:
            continue
        user, password, host = um.group(1), text[um.end():at], m.group(1)
        if user.lower() in _LABEL_PREFIXES and "@" not in password and not _IPV4_HOST.match(host):
            continue  # 'contact:alice@corp.example' is a label and an address
        parts.append(text[last:um.start(1)])
        last = at + 1  # drop 'user:password@', keep the host
    if not parts:
        return text
    parts.append(text[last:])
    return "".join(parts)


def _drop_encoded_combos(text: str) -> str:
    """'alice%40corp.example%3Ahunter2' -> 'alice%40corp.example' (address lists are kept)."""
    if "%" not in text:
        return text

    def repl(m: re.Match[str]) -> str:
        password = unquote(m.group(3))
        if password.startswith("//") or _EMAIL_LIST.match(password.rstrip(".,;)")):
            return m.group(0)  # 'x%3A//' is a URL, 'a%40x.com%3Bb%40y.com' an address list
        return m.group(1)

    return _ENC_EMAIL_COMBO.sub(repl, text)


def drop_combos(text: str) -> str:
    """Remove credential combos, never mask them: 'a@b.com:pw' -> 'a@b.com'; 'u:p@host' -> 'host'.

    URL credentials are dropped too ('https://u:p@host/x' -> 'https://host/x', 'redis://:p@host' ->
    'redis://host'); URLs with a user but no password ('ssh://git@host:22/x') are left alone.
    URL-encoded combos ('alice%40corp.example%3Ahunter2') keep only the encoded address.
    """
    if not isinstance(text, str) or ("@" not in text and "%40" not in text):
        return text
    out = _URL_USERINFO.sub(r"\1", text)

    def email_combo(m: re.Match[str]) -> str:
        start = m.start(1)
        if m.string[max(0, start - 3):start] == "://":  # URL userinfo without a password: not a combo
            return m.group(0)
        if _EMAIL_LIST.match(m.group(2).rstrip(".,;)")):  # an address list, not a combo
            return m.group(0)
        if m.group(1).lower().startswith("git@") and _SCP_PATH.match(m.group(2)):  # git@host:org/repo.git
            return m.group(0)
        return m.group(1)

    out = _EMAIL_COMBO.sub(email_combo, out)
    out = _drop_bare_userinfo(out)
    return _drop_encoded_combos(out)


#: Two-field dump lines of pasted text: 'alice@corp.example<TAB>hunter2', 'alice@corp.example,hunter2'.
_LINE_COMBO = re.compile(rf"(?m)^([ \t]*{_EMAIL})[ \t]*[,\t][ \t]*([^\s,]{{1,256}})[ \t]*(?=\r?$)")
_DOMAIN_LIKE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*\.[A-Za-z]{{2,63}}\.?$")


def _ioc_like(token: str) -> bool:
    """A second field that is an indicator (or a small count) is kept on a two-field line."""
    t = token.strip().strip("\"'")
    if not t:
        return True
    if re.fullmatch(r"\d{1,3}", t) or "://" in t or re.fullmatch(_EMAIL, t) or _DOMAIN_LIKE.match(t):
        return True
    try:
        ipaddress.ip_address(t.strip("[]"))
        return True
    except ValueError:
        return False


def _drop_line_combos(text: str) -> str:
    """Dump lines 'email<TAB|,>secret' keep the e-mail only (the second field is not an indicator)."""
    if "@" not in text or ("," not in text and "\t" not in text):
        return text

    def repl(m: re.Match[str]) -> str:
        return m.group(0) if _ioc_like(m.group(2)) else m.group(1)

    return _LINE_COMBO.sub(repl, text)


# ----------------------------------------------------------------------------------------
# Password hashes, masked tokens, infected-host values (sensitive payloads)
# ----------------------------------------------------------------------------------------

#: Password-hash formats: never file hashes, dropped from sensitive payloads and pasted text.
_PASSWORD_HASH = re.compile(
    r"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}"  # bcrypt
    r"|\$argon2(?:id|i|d)\$v=\d{1,3}\$m=\d{1,10},t=\d{1,10},p=\d{1,3}\$[A-Za-z0-9+/=]{4,128}\$[A-Za-z0-9+/=]{4,512}"  # argon2
    r"|\$scrypt\$[^\s$]{1,128}\$[A-Za-z0-9+/=]{4,256}\$[A-Za-z0-9+/=]{4,512}"  # scrypt (passlib)
    r"|\$(?:7|y|gy)\$[./A-Za-z0-9]{1,64}\$[./A-Za-z0-9]{0,86}\$?[./A-Za-z0-9]{22,86}"  # scrypt/yescrypt (crypt)
    r"|\$[56]\$(?:rounds=\d{1,9}\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43,86}"  # sha256/sha512-crypt
    r"|\$(?:1|apr1)\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}"  # md5-crypt
    r"|\$[PH]\$[./A-Za-z0-9]{31}"  # phpass
    r"|pbkdf2_sha(?:1|256|512)\$\d{1,9}\$[A-Za-z0-9./+=]{1,128}\$[A-Za-z0-9./+=]{16,256}"  # Django PBKDF2
    r"|\$pbkdf2(?:-sha(?:1|256|512))?\$\d{1,9}\$[./A-Za-z0-9+=]{1,128}\$[./A-Za-z0-9+=]{16,256}"  # passlib PBKDF2
    r"|(?<![A-Za-z0-9*])\*[0-9A-F]{40}(?![0-9A-Fa-f])"  # MySQL 4.1+
)
#: MD5 / SHA-1 / SHA-256 / SHA-512 hex values (dropped only next to a credential).
_HEX_HASH = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{128}|[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])")
#: Words that put a hex value of the same string next to a credential.
_CREDENTIAL_WORDS = re.compile(r"(?i)pass|pwd|(?<![a-z])pw(?![a-z])|senha|hash|login|user|combo|credential|secret|" + _EMAIL)
#: Dict keys that make a record a credential record (hex values next to them are password hashes).
_ACCOUNT_KEYS = frozenset({
    "email", "e_mail", "mail", "email_address", "username", "user_name", "user", "login", "account", "account_name",
    "userid", "user_id", "uid", "nick", "nickname", "handle", "phone", "msisdn",
})
_MASK_RUN = re.compile(r"\*{2,}|•{2,}|●{2,}")
_TOKEN_EDGES = ",.;:!?()[]{}\"'<>"
_IPV4_TEXT = re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?!\d)(?!\.\d)")
_IPV6_TEXT = re.compile(r"(?<![0-9A-Za-z:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Za-z:])")
#: Windows ('C:\\Users\\x\\AppData\\a.exe'), UNC and home-directory paths (malware paths, A4).
_FILE_PATH = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z]:\\(?:[^\\\r\n\"'<>|*?:]{1,128}\\){0,32}[^\s\\\"'<>|*?:]{0,128}"
    r"|\\\\[A-Za-z0-9._$\-]{1,64}\\[^\s\"'<>|*?]{1,260}"
    r"|(?<![\w/])/(?:home|Users|root)/[^\s/\"'<>]{1,64}(?:/[^\s\"'<>]{0,200})?"
)
#: Default Windows computer names ('DESKTOP-4F2K9QZ', 'WIN-1ABC2DEF3GH').
_WIN_HOSTNAME = re.compile(r"(?<![A-Za-z0-9\-])(?:DESKTOP|LAPTOP|WIN|PC|USER-PC|WORKSTATION)-[A-Z0-9]{4,15}(?![A-Za-z0-9\-])")
#: 'name: value' / 'name=value' pairs in free text (both sides bounded): the label head, then its value
_LABEL_HEAD = re.compile(r"(?<![A-Za-z0-9_.\-])([\"']?)([A-Za-z_][A-Za-z0-9_.\-]{0,95})\1[ \t]{0,3}[:=][ \t]{0,3}")
_LABEL_VALUE = re.compile(r"\"[^\"\r\n]{0,4096}\"|'[^'\r\n]{0,4096}'|\[[^\]\r\n]{0,4096}\]|[^\s,;'\"<>{}\[\]()&#]{1,4096}")
#: Values that never count as a secret or a dropped second-net value (forms, placeholders, booleans).
_NOT_A_VALUE = frozenset({
    "", "none", "null", "nil", "true", "false", "yes", "no", "n/a", "na", "unknown", "redacted", "[redacted]", "<redacted>",
    "plaintext", "plain", "plain text", "hashed", "hidden", "masked", "not found", "notfound", "-", "--", "required",
    "optional", "string", "str", "bool", "int", "integer", "number", "object", "array", "list", "dict", "value",
})
_PLACEHOLDER = re.compile(r"^(?:\$\{[^}]*\}|\{\{[^}]*\}\}|<[^>]*>|%\([^)]*\)s|\*+|x+|\.{3}|…|\$[A-Z_][A-Z0-9_]*)$", re.I)
_PROPAGATE_MIN = 4
_PROPAGATE_MAX = 1000


def _is_form_word(value: str) -> bool:
    v = value.strip().strip("\"'").lower()
    return v in ("plaintext", "plain text", "hashed", "unknown", "none", "yes", "no") or v.startswith("hashed")


def _not_a_value(value: str) -> bool:
    v = value.strip().strip("\"'")
    return v.lower() in _NOT_A_VALUE or bool(_PLACEHOLDER.match(v)) or "…" in v


def _is_mask_token(token: str) -> bool:
    """'p***2', '58.10.**.***', 'a***@corp.example', '****1234' (markdown '**bold**' is not a mask)."""
    core = token.strip(_TOKEN_EDGES)
    if not core or not any(c.isalnum() for c in core) or not _MASK_RUN.search(core):
        return False
    bold = core.startswith("**") and core.endswith("**") and len(core) > 4 and "**" not in core[2:-2]
    return not bold


def _drop_masked_tokens(text: str) -> str:
    """Whitespace-delimited tokens holding masked characters are removed (masked hints, A4)."""
    if not _MASK_RUN.search(text):
        return text
    parts = re.split(r"(\s+)", text)
    return "".join("" if (i % 2 == 0 and _is_mask_token(p)) else p for i, p in enumerate(parts))


def _drop_password_hashes(text: str) -> str:
    return _PASSWORD_HASH.sub("", text) if "$" in text or "*" in text else text


def _ip_literals(text: str) -> list[tuple[int, int, str]]:
    out = [(m.start(), m.end(), m.group(0)) for m in _IPV4_TEXT.finditer(text)]
    if text.count(":") >= 2:
        for m in _IPV6_TEXT.finditer(text):
            cand = m.group(0)
            if cand.count(":") < 2 or not any(c.isalnum() for c in cand):
                continue
            try:
                ipaddress.IPv6Address(cand)
            except ValueError:
                continue
            out.append((m.start(), m.end(), cand))
    return out


class _SensitiveText:
    """Free-text pass for sensitive results (second-net pairs, propagated values, masks, IPs, paths)."""

    def __init__(self, entity_value: str = "", *, hash_rule: bool = True) -> None:
        self.keep_ips: set[str] = set()
        ev = str(entity_value or "").strip()
        try:
            self.keep_ips.add(str(ipaddress.ip_address(ev)))
        except ValueError:
            pass
        self.entity_value = ev.lower()
        self.hash_rule = hash_rule
        self.values: list[str] = []
        self._seen: set[str] = set()

    # -- collection of the values a module read from second-net fields ---------------------
    def collect(self, obj: Any, under: bool = False) -> None:
        if len(self.values) >= _PROPAGATE_MAX:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                self.collect(v, under or is_second_net_field(k, hash_rule=self.hash_rule))
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                self.collect(v, under)
        elif under and isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
            value = str(obj).strip()
            low = value.lower()
            if (
                len(value) >= _PROPAGATE_MIN
                and low not in self._seen
                and low != self.entity_value
                and not _not_a_value(value)
                and not (value.isdigit() and len(value) < 6)
            ):
                self._seen.add(low)
                self.values.append(value)

    def _propagated(self, text: str) -> str:
        if not self.values:
            return text
        low = text.lower()
        for value in sorted(self.values, key=len, reverse=True):
            if value.lower() in low:
                text = re.sub(re.escape(value), _REDACTED, text, flags=re.I)
                low = text.lower()
        return text

    def _pairs(self, text: str) -> str:
        """Drop 'name: value' pairs of second-net names; other values are scanned for nested pairs
        (a JSON dump: '"result": [{"password": ...}]')."""
        if ":" not in text and "=" not in text:
            return text
        out: list[str] = []
        pos = last = 0
        while True:
            m = _LABEL_HEAD.search(text, pos)
            if m is None:
                break
            pos = m.end()
            if not is_second_net_field(m.group(2), hash_rule=self.hash_rule):
                continue
            value = _LABEL_VALUE.match(text, m.end())
            if value is None or _is_form_word(value.group(0)):
                continue  # 'passwords: plaintext' is the password FORM (metadata)
            out.append(text[last:m.start()])
            last = pos = value.end()
        if not out:
            return text
        out.append(text[last:])
        return "".join(out)

    def _ips(self, text: str) -> str:
        if "." not in text and ":" not in text:
            return text
        found = _ip_literals(text)
        if not found:
            return text
        out, last = [], 0
        for start, end, ip in sorted(found):
            if start < last:
                continue
            try:
                norm = str(ipaddress.ip_address(ip))
            except ValueError:
                continue
            if norm in self.keep_ips:
                continue
            out.append(text[last:start])
            last = end
        out.append(text[last:])
        return "".join(out)

    def _hashes(self, text: str) -> str:
        text = _drop_password_hashes(text)
        if self.hash_rule and _HEX_HASH.search(text) and _CREDENTIAL_WORDS.search(text):
            text = _HEX_HASH.sub("", text)
        return text

    def text(self, text: str) -> str:
        """``text`` without second-net pairs, propagated values, masked tokens, hashes, IPs and paths."""
        if not isinstance(text, str) or not text:
            return text
        out = self._pairs(text)
        out = self._propagated(out)
        out = _drop_masked_tokens(out)
        out = self._hashes(out)
        out = self._ips(out)
        out = _FILE_PATH.sub("", out) if ("\\" in out or "/" in out) else out
        return _WIN_HOSTNAME.sub("", out)

    def tainted(self, value: str) -> bool:
        """True when ``value`` (a URL, a pivot value) carries something the text pass would remove."""
        if not isinstance(value, str) or not value:
            return False
        low = value.lower()
        if any(v.lower() in low for v in self.values):
            return True
        if _drop_masked_tokens(value) != value or _drop_password_hashes(value) != value:
            return True
        return any(_norm_ip(ip) not in self.keep_ips for _, _, ip in _ip_literals(value))


def _norm_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip


def _credential_record(d: dict[Any, Any]) -> bool:
    for k in d:
        norm = _normalise_key(k)
        if norm in _ACCOUNT_KEYS or norm.endswith(("_email", "_username", "_login")) or "password" in norm or "passwd" in norm:
            return True
        if norm in ("pass", "pwd", "hash", "salt", "senha"):
            return True
    return False


def _whole_hash(value: str, hex_rule: bool) -> bool:
    v = value.strip()
    return bool(_PASSWORD_HASH.fullmatch(v) or (hex_rule and _HEX_HASH.fullmatch(v)))


# ----------------------------------------------------------------------------------------
# Password FORM (f)
# ----------------------------------------------------------------------------------------

_FORM = re.compile(r"^(?:plaintext|unknown|hashed(?::[ ]?[A-Za-z0-9][A-Za-z0-9 ._+\-()/]{0,31})?)$", re.I)
#: provider words for how passwords were stored -> the canonical FORM
_FORM_WORDS = {
    "plaintext": "plaintext", "plain text": "plaintext", "plain": "plaintext", "cleartext": "plaintext", "clear text": "plaintext",
    "hashed": "hashed", "hash": "hashed", "encrypted": "hashed", "salted": "hashed",
    "easytocrack": "hashed: weak", "easy to crack": "hashed: weak", "weak": "hashed: weak", "weakhash": "hashed: weak",
    "weak hash": "hashed: weak", "hardtocrack": "hashed: strong", "hard to crack": "hashed: strong", "strong": "hashed: strong",
    "stronghash": "hashed: strong", "strong hash": "hashed: strong", "unknown": "unknown",
}
_FORM_ALGORITHM = re.compile(
    r"^(?:bcrypt|md5|sha-?1|sha-?224|sha-?256|sha-?384|sha-?512|argon2(?:id|i|d)?|scrypt|yescrypt|pbkdf2(?:[-_ ]sha(?:1|256|512))?|ntlm|"
    r"mysql\d?|des|crypt|(?:md5|sha-?256|sha-?512|des|bsdi)-?crypt|phpass|vbulletin|ipb|smf|drupal7|wordpress)(?: ?\(?salted\)?)?$", re.I)
#: second-net names that may carry the password FORM (a provider's 'password_risk', 'hash_type'...)
_FORM_CARRIER = re.compile(r"password|passwd|senha|(?:^|_)pass(?:_|$)|(?:^|_)pwd(?:_|$)|(?:^|_)hash(?:_|$)|hash_?type|hash_?algorithm")


def normalize_password_form(value: Any) -> str | None:
    """The canonical password FORM ('plaintext', 'hashed', 'hashed: <algorithm>', 'unknown') for a
    provider's wording ('PlainText', 'easytocrack', 'bcrypt', 'hashed: SHA-1'...), else None.

    A value that is not a recognised form word (a password, a hash, a masked hint) gives None.
    """
    if not isinstance(value, str):
        return None
    v = re.sub(r"\s+", " ", value.strip().lower())
    if not v or len(v) > 48:
        return None
    if v in _FORM_WORDS:
        return _FORM_WORDS[v]
    m = re.match(r"^hashed ?[:\-] ?(.+)$", v)
    if m and is_password_form(f"hashed: {m.group(1)}"):
        return f"hashed: {m.group(1)}"
    if _FORM_ALGORITHM.match(v):
        return f"hashed: {v}"
    return None


def _keep_password_forms(obj: Any, prefix: str, redacted: list[str]) -> Any:
    """Rename password-related fields whose value is a FORM word to ``password_form`` (normalised):
    the form is metadata (A4) and must survive the second net under its one kept name (f)."""

    def walk(value: Any, path: str) -> Any:
        if isinstance(value, dict):
            out: dict[Any, Any] = {}
            forms: list[str] = []
            for k, v in value.items():
                sub = f"{path}.{k}" if path else str(k)
                norm = _normalise_key(k)
                if norm != "password_form" and _FORM_CARRIER.search(norm) and isinstance(v, str):
                    form = normalize_password_form(v)
                    if form is not None:
                        forms.append(form)
                        redacted.append(f"{sub}:password_form")
                        continue
                out[k] = walk(v, sub)
            if forms and "password_form" not in out:
                out["password_form"] = forms[0] if len(set(forms)) == 1 else sorted(set(forms))
            return out
        if isinstance(value, list):
            return [walk(v, f"{path}[]") for v in value]
        if isinstance(value, tuple):
            return tuple(walk(v, f"{path}[]") for v in value)
        return value

    return walk(obj, prefix)


#: what may follow 'hashed: ' besides an algorithm name (provider strength wording, normalised)
_FORM_QUALIFIERS = frozenset({"weak", "strong", "salted", "unsalted", "unknown", "mixed", "encrypted"})
#: separators of several algorithms in one form ('hashed: md5/sha1', 'hashed: sha256 + salt')
_FORM_SEPARATOR = re.compile(r"\s*(?:/|,|\+|&|\band\b)\s*")


def _known_algorithms(text: str) -> bool:
    parts = [p for p in _FORM_SEPARATOR.split(text) if p]
    return bool(parts) and len(parts) <= 6 and all(
        p in _FORM_QUALIFIERS or p in ("salt", "pepper") or _FORM_ALGORITHM.match(p) for p in parts)


def is_password_form(value: Any) -> bool:
    """True for a valid ``password_form`` value: 'plaintext', 'hashed', 'hashed: <algorithm>' or
    'unknown' (a list of such values is valid too). The algorithm must be a known hash or crypt name
    ('bcrypt', 'sha-1', 'md5 (salted)'...) or a strength word ('weak', 'strong'): free text after
    'hashed:' could carry the password itself ('hashed: hunter2'). Anything holding a '$', an '@' or a
    hex run of 16+ characters is refused."""
    if isinstance(value, (list, tuple)):
        return bool(value) and all(is_password_form(v) for v in value)
    if not isinstance(value, str):
        return False
    v = value.strip()
    if not _FORM.match(v) or "$" in v or "@" in v or re.search(r"[0-9A-Fa-f]{16}", v):
        return False
    head, sep, algorithm = v.partition(":")
    if not sep:
        return True  # 'plaintext' | 'hashed' | 'unknown'
    return _known_algorithms(re.sub(r"\s+", " ", algorithm.strip().lower()))


# ----------------------------------------------------------------------------------------
# Secrets (c)
# ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SecretPattern:
    """One secret detector.

    ``group`` names the regex group(s) holding the secret (the first one that matched); ``action``
    is 'mask' (type + first 4/last 4 + SHA-256) or 'drop' (passwords: removed, never hashed).
    Patterns with ``label_group`` classify the label ('DB_PASSWORD', 'api_key'): password labels
    drop the value, secret labels mask it, other labels are not secrets. ``hints`` are literal
    substrings (lower-case compare) one of which must occur before the regex runs; ``distinctive``
    patterns (a fixed prefix or structure) also run over pivot values. ``validator`` (optional) must
    accept the matched secret for the hit to count (e.g. base64 that decodes to 'user:password').
    """

    kind: str
    regex: re.Pattern[str]
    group: int | tuple[int, ...] = 0
    action: str = "mask"
    hints: tuple[str, ...] = ()
    distinctive: bool = True
    description: str = ""
    label_group: int | None = None
    validator: Callable[[str], bool] | None = None


class SecretHit(NamedTuple):
    """One secret found by :func:`find_secrets` (``start``/``end`` delimit the secret itself)."""

    kind: str
    start: int
    end: int
    action: str
    value: str


def _sp(kind: str, pattern: str, *, group: int | tuple[int, ...] = 1, action: str = "mask", hints: Iterable[str] = (),
        distinctive: bool = True, description: str = "", label_group: int | None = None, flags: int = 0,
        validator: Callable[[str], bool] | None = None) -> SecretPattern:
    return SecretPattern(kind, re.compile(pattern, flags), group, action, tuple(h.lower() for h in hints), distinctive, description,
                         label_group, validator)


def _basic_credentials(token: str) -> bool:
    """True when ``token`` is base64 of printable 'user:password' (an HTTP Basic credential)."""
    raw = token.strip()
    if len(raw) < 6 or len(raw) > 4096:
        return False
    try:
        decoded = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
        text = decoded.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return False
    user, sep, password = text.partition(":")
    return bool(sep) and bool(password) and len(user) <= 256 and text.isprintable()


_PW_LABEL = re.compile(
    r"(?i)(?:^|[^a-z])(?:passwords?|passwd|passphrase|passcode|pwd|pass|pswd|senhas?|passwort|kennwort|wachtwoord|"
    r"mot[_\-. ]?de[_\-. ]?passe|contrase(?:n|ñ)as?)(?:$|[^a-z])"
)
_SECRET_LABEL = re.compile(
    r"(?i)secret|token|api[_\-.]?key|apikey|access[_\-.]?key|private[_\-.]?key|master[_\-.]?key|app[_\-.]?key|"
    r"account[_\-.]?key|signing[_\-.]?key|encryption[_\-.]?key|auth[_\-.]?key|license[_\-.]?key|credential|"
    r"authorization|webhook|bearer|session[_\-.]?(?:id|key)|cookie|(?:^|[^a-z])salt(?:$|[^a-z])"
)

#: Secret detectors (P145 cond 8, P323 cond 6). Distinctive formats first; the last pattern classifies
#: 'name: value' / 'NAME=value' assignments (.env files, config dumps, JSON/YAML) by their label.
SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    _sp("private_key", r"(-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----(?:[^-]|-(?!----END)){0,16384}"
        r"(?:-----END (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----)?)", hints=("PRIVATE KEY",),
        description="PEM/OpenSSH/PGP private-key block"),
    _sp("aws_access_key_id", r"(?<![A-Z0-9])((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16})(?![A-Z0-9])",
        hints=("AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ABIA", "ACCA"), description="AWS access key id"),
    _sp("aws_secret_access_key", r"(?i)aws_?secret_?access_?key[\"']?[ \t]{0,3}[:=][ \t]{0,3}[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
        hints=("secret",), description="AWS secret access key (labelled)"),
    _sp("github_token", r"(?<![A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{22,251})(?![A-Za-z0-9_])",
        hints=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"), description="GitHub token"),
    _sp("gitlab_token", r"(?<![A-Za-z0-9_])(glpat-[A-Za-z0-9_\-]{20,64})(?![A-Za-z0-9_\-])", hints=("glpat-",), description="GitLab token"),
    _sp("slack_token", r"(?<![A-Za-z0-9])(xox[abposr]-[A-Za-z0-9\-]{10,200})(?![A-Za-z0-9\-])", hints=("xox",), description="Slack token"),
    _sp("slack_webhook", r"(https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9_/\-]{8,200})",
        hints=("hooks.slack.com",), description="Slack incoming webhook URL"),
    _sp("discord_webhook", r"(https://(?:(?:canary|ptb)\.)?discord(?:app)?\.com/api/webhooks/\d{5,30}/[A-Za-z0-9_\-]{20,200})",
        hints=("/api/webhooks/",), description="Discord webhook URL"),
    _sp("stripe_secret_key", r"(?<![A-Za-z0-9])((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,247})(?![A-Za-z0-9])",
        hints=("k_live_", "k_test_"), description="Stripe secret/restricted key"),
    _sp("google_api_key", r"(?<![A-Za-z0-9_\-])(AIza[0-9A-Za-z_\-]{35})(?![A-Za-z0-9_\-])", hints=("AIza",), description="Google API key"),
    _sp("google_oauth_secret", r"(?<![A-Za-z0-9_\-])(GOCSPX-[A-Za-z0-9_\-]{28})(?![A-Za-z0-9_\-])", hints=("GOCSPX-",),
        description="Google OAuth client secret"),
    _sp("openai_api_key", r"(?<![A-Za-z0-9_\-])(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,300}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})(?![A-Za-z0-9_\-])",
        hints=("sk-",), description="OpenAI API key"),
    _sp("anthropic_api_key", r"(?<![A-Za-z0-9_\-])(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,120})(?![A-Za-z0-9_\-])",
        hints=("sk-ant-",), description="Anthropic API key"),
    _sp("huggingface_token", r"(?<![A-Za-z0-9_])(hf_[A-Za-z0-9]{34,40})(?![A-Za-z0-9_])", hints=("hf_",), description="Hugging Face token"),
    _sp("sendgrid_api_key", r"(?<![A-Za-z0-9_\-.])(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})(?![A-Za-z0-9_\-])", hints=("SG.",),
        description="SendGrid API key"),
    _sp("mailgun_api_key", r"(?<![A-Za-z0-9_\-])(key-[0-9a-f]{32})(?![0-9a-f])", hints=("key-",), description="Mailgun API key"),
    _sp("npm_token", r"(?<![A-Za-z0-9_])(npm_[A-Za-z0-9]{36})(?![A-Za-z0-9])", hints=("npm_",), description="npm access token"),
    _sp("pypi_token", r"(?<![A-Za-z0-9_\-])(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,300})", hints=("pypi-",), description="PyPI API token"),
    _sp("shopify_token", r"(?<![A-Za-z0-9_])(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})(?![A-Za-z0-9])", hints=("shpat_", "shpca_", "shppa_", "shpss_"),
        description="Shopify access token"),
    _sp("digitalocean_token", r"(?<![A-Za-z0-9_])(do[opr]_v1_[a-f0-9]{64})(?![a-f0-9])", hints=("_v1_",), description="DigitalOcean token"),
    _sp("telegram_bot_token", r"(?<![A-Za-z0-9:_\-])(\d{8,10}:AA[A-Za-z0-9_\-]{33})(?![A-Za-z0-9_\-])", hints=(":aa",),
        description="Telegram bot token"),
    _sp("discord_bot_token", r"(?<![A-Za-z0-9_\-.])([MNO][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38})(?![A-Za-z0-9_\-.])",
        hints=("m", "n", "o"), description="Discord bot token"),
    _sp("jwt", r"(?<![A-Za-z0-9_\-])(eyJ[A-Za-z0-9_\-]{8,4096}\.eyJ[A-Za-z0-9_\-]{8,8192}\.[A-Za-z0-9_\-]{8,1024})(?![A-Za-z0-9_\-])",
        hints=("eyJ",), description="JSON Web Token"),
    _sp("bearer_token", r"(?i)(?<![A-Za-z0-9])bearer[ \t]{1,3}([A-Za-z0-9._~+/\-]{16,4096}=*)", hints=("bearer",),
        description="HTTP bearer token"),
    _sp("basic_auth", r"(?i)(?<![A-Za-z0-9])basic[ \t]{1,3}([A-Za-z0-9+/]{6,4096}={0,2})(?![A-Za-z0-9+/=])", action="drop",
        hints=("basic",), validator=_basic_credentials,
        description="HTTP Basic credentials (base64 of user:password): dropped like a password, never hashed"),
    _sp("assignment", r"(?<![A-Za-z0-9_.\-])([\"']?)([A-Za-z_][A-Za-z0-9_.\-]{0,95})\1[ \t]{0,3}[:=][ \t]{0,3}"
        r"(?:\"([^\"\r\n]{1,4096})\"|'([^'\r\n]{1,4096})'|([^\s,;'\"<>{}\[\]()&#]{1,4096}))",
        group=(3, 4, 5), hints=(":", "="), distinctive=False, label_group=2,
        description=".env/config/JSON/YAML assignment: password labels drop the value, secret labels mask it"),
)


def _classify_label(label: str) -> tuple[str, str] | None:
    """(kind, action) for an assignment label, or None when the label names no secret."""
    if _PW_LABEL.search(label) and "form" not in label.lower():
        return "password", "drop"
    if _SECRET_LABEL.search(label):
        return "secret", "mask"
    return None


@functools.lru_cache(maxsize=256)
def _hint_regex(hints: tuple[str, ...]) -> re.Pattern[str] | None:
    """One compiled alternation per hint tuple (a C-level search instead of a Python loop per string)."""
    return re.compile("|".join(re.escape(h) for h in hints)) if hints else None


def _hinted(text: str, low: str, pattern: SecretPattern) -> bool:
    rx = _hint_regex(pattern.hints)
    return rx is None or rx.search(low) is not None


def find_secrets(text: str, *, distinctive_only: bool = False) -> list[SecretHit]:
    """Non-overlapping secrets in ``text``, in order (distinctive formats win over assignments).

    ``distinctive_only`` skips the label-classified assignment pattern (used for pivot values,
    whose key-like URL parameters stay part of the indicator, AR01).
    """
    if not isinstance(text, str) or len(text) < 4:
        return []
    low = text.lower()
    hits: list[tuple[int, int, int, SecretHit]] = []
    for rank, pattern in enumerate(SECRET_PATTERNS):
        if distinctive_only and not pattern.distinctive:
            continue
        if not _hinted(text, low, pattern):
            continue
        groups = pattern.group if isinstance(pattern.group, tuple) else (pattern.group,)
        for m in pattern.regex.finditer(text):
            g = next((g for g in groups if m.group(g) is not None), None)
            if g is None:
                continue
            secret = m.group(g)
            kind, action = pattern.kind, pattern.action
            if pattern.label_group is not None:
                found = _classify_label(m.group(pattern.label_group) or "")
                if found is None:
                    continue
                kind, action = found
                if _not_a_value(secret) or _is_form_word(secret):
                    continue
                if action == "mask" and (len(secret.strip()) < 8 or secret.strip().isdigit()):
                    continue
            if not secret.strip():
                continue
            if pattern.validator is not None and not pattern.validator(secret):
                continue
            hits.append((m.start(g), rank, -(m.end(g) - m.start(g)), SecretHit(kind, m.start(g), m.end(g), action, secret)))
    hits.sort(key=lambda h: (h[0], h[1], h[2]))
    out: list[SecretHit] = []
    end = -1
    for start, _rank, _neg, hit in hits:
        if start < end:
            continue
        out.append(hit)
        end = hit.end
    return out


def mask_secret(raw: str, kind: str = "") -> dict[str, str]:
    """Fingerprint of a secret: {'type', 'preview' (first 4 + '…' + last 4, '****' under 12 chars), 'sha256'}."""
    value = raw if isinstance(raw, str) else str(raw)
    preview = f"{value[:4]}…{value[-4:]}" if len(value) >= 12 else "****"
    return {"type": kind or "secret", "preview": preview, "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest()}


def _fingerprint(kind: str, raw: str) -> str:
    try:
        from v3lum.core.entities import secret_fingerprint
    except ImportError:  # pragma: no cover - entities always present
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        return f"{kind or 'secret'}:…:{digest}"
    return secret_fingerprint(kind or "secret", raw)


def _mask_text(text: str, *, distinctive_only: bool = False, hits: list[SecretHit] | None = None,
               found: list[SecretHit] | None = None) -> str:
    """``text`` with secrets replaced inline: fingerprints for masks, nothing for dropped passwords
    (``found``: the hits of :func:`find_secrets` when the caller already has them)."""
    if found is None:
        found = find_secrets(text, distinctive_only=distinctive_only)
    if not found:
        return text
    out, last = [], 0
    for hit in found:
        out.append(text[last:hit.start])
        out.append(_fingerprint(hit.kind, hit.value) if hit.action == "mask" else "")
        last = hit.end
        if hits is not None:
            hits.append(hit)
    out.append(text[last:])
    return "".join(out)


# ----------------------------------------------------------------------------------------
# Free text inputs
# ----------------------------------------------------------------------------------------


def scrub_text(text: str, *, hits: list[dict[str, str]] | None = None) -> str:
    """Scrub free text (a pasted text_blob, a text file) before anything is stored or extracted.

    Drops credential combos ('alice@corp.example:hunter2' -> 'alice@corp.example', URL userinfo,
    URL-encoded combos, 'email<TAB|,>password' dump lines), password hashes (bcrypt, argon2, crypt
    formats; never file hashes), masked hints ('p***2') and labelled passwords ('DB_PASSWORD=...',
    'password: ...'); replaces every other secret of :data:`SECRET_PATTERNS` with its fingerprint
    ``'<kind>:<first4>…<last4>:<sha16>'`` (the value of a SECRET entity). Indicators (URLs,
    domains, IPs, file hashes, the e-mail of a combo) are kept. ``hits`` (optional list) receives
    one ``{'kind', 'action', 'value'}`` dict per removal ('value' is the fingerprint of a masked
    secret, '' for drops) so callers can report 'sensitive data in pasted text'.
    """
    if not isinstance(text, str) or not text:
        return text
    report: list[dict[str, str]] = []
    out = drop_combos(text)
    out = _drop_line_combos(out)
    if out != text:
        report.append({"kind": "combo", "action": "drop", "value": ""})
    step = _drop_password_hashes(out)
    if step != out:
        report.append({"kind": "password_hash", "action": "drop", "value": ""})
    out = step
    step = _drop_masked_tokens(out)
    if step != out:
        report.append({"kind": "masked", "action": "drop", "value": ""})
    out = step
    found: list[SecretHit] = []
    out = _mask_text(out, hits=found)
    for hit in found:
        report.append({"kind": hit.kind, "action": hit.action, "value": _fingerprint(hit.kind, hit.value) if hit.action == "mask" else ""})
    if hits is not None:
        hits.extend(report)
    return out


# ----------------------------------------------------------------------------------------
# Structured walkers
# ----------------------------------------------------------------------------------------


def _scrub_strings(value: Any, counter: list[int]) -> Any:
    """Copy of ``value`` with :func:`drop_combos` applied to every string (dict keys included)."""
    if isinstance(value, str):
        new = drop_combos(value)
        if new != value:
            counter[0] += 1
        return new
    if isinstance(value, dict):
        return {(_scrub_strings(k, counter) if isinstance(k, str) else k): _scrub_strings(v, counter) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_strings(v, counter) for v in value]
    if isinstance(value, tuple):
        return tuple(_scrub_strings(v, counter) for v in value)
    return value


def _map_leaves(value: Any, path: str, leaf: Callable[[str, str], Any], key: Callable[[str], str] | None = None) -> Any:
    """Copy of ``value`` where ``leaf(text, path)`` rewrites every string leaf (``_DROP`` removes it)
    and ``key(text)`` every string dict key."""
    if isinstance(value, str):
        return leaf(value, path)
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for k, v in value.items():
            sub = f"{path}.{k}" if path else str(k)
            new = _map_leaves(v, sub, leaf, key)
            if new is _DROP:
                continue
            out[key(k) if (key is not None and isinstance(k, str)) else k] = new
        return out
    if isinstance(value, (list, tuple)):
        items = [_map_leaves(v, f"{path}[]", leaf, key) for v in value]
        kept = [v for v in items if v is not _DROP]
        return tuple(kept) if isinstance(value, tuple) else kept
    return value


def _top(value: Any) -> Any:
    return None if value is _DROP else value


_PLAIN_SCALARS = (str, int, float, bool, type(None))


def _plain_key(key: Any) -> Any:
    if isinstance(key, _PLAIN_SCALARS):
        return key
    if isinstance(key, (bytes, bytearray, memoryview)):
        return bytes(key).decode("utf-8", errors="replace")
    return str(key)


def _sort_key(value: Any) -> tuple[str, str]:
    return type(value).__name__, json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def _plain(value: Any, sensitive: bool) -> Any:
    """JSON-shaped copy of what a module produced, so every later pass sees every string: sets become
    sorted lists, bytes become text (UTF-8, invalid bytes replaced), non-string keys strings, and any
    other object its ``str()`` - always for sensitive modules, else when that text carries something a
    pass would remove (a combo, a secret, a key). The stores serialise unknown objects with
    ``default=str``: without this a combo or a token inside a set, bytes or a custom object would
    reach the case JSON, evidence and reports untouched."""
    if isinstance(value, _PLAIN_SCALARS):
        return value
    if isinstance(value, dict):
        return {_plain_key(k): _plain(v, sensitive) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v, sensitive) for v in value]
    if isinstance(value, tuple):
        return tuple(_plain(v, sensitive) for v in value)
    if isinstance(value, (set, frozenset)):
        return sorted((_plain(v, sensitive) for v in value), key=_sort_key)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("utf-8", errors="replace")
    text = str(value)
    if sensitive or scrub_text(text) != text or _redact.redact_text(text) != text:
        return text
    return value  # a datetime, a Decimal...: nothing to remove, the object stays as the module built it


def _area(path: str) -> str:
    head = path.split(".", 1)[0].split("[", 1)[0]
    return "findings" if head == "findings" else head


_COOKIE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$")


def _label_of(path: str) -> str:
    """The dict key a leaf sits under ('raw.config.db_password' -> 'db_password'; list items: the list's key)."""
    last = path.replace("[]", "").rsplit(".", 1)[-1]
    return last if last not in ("raw", "attributes", "data", "") else ""


def _mask(raw: str, kind: str) -> dict[str, str]:
    """The structured mask of a secret found by the sanitizer: ``mask_secret()``'s {type, preview, sha256}
    with the preview of the SECRET fingerprint (:func:`v3lum.core.entities.secret_preview`: first 4/last 4
    from 16 characters, 2/2 from 12, none below), so the same secret never shows more characters in
    one output than in another."""
    out = mask_secret(raw, kind)
    try:
        from v3lum.core.entities import secret_preview
    except ImportError:  # pragma: no cover - entities always present
        return out
    out["preview"] = secret_preview(raw)
    return out


def _secret_leaves(value: Any, path: str, redacted: list[str]) -> Any:
    """Structured secret pass: a value that is entirely a secret becomes a mask dict ``{type, preview,
    sha256}`` (or is dropped for passwords); secrets inside longer text become fingerprints inline. A
    value under a password key ('db_password') is dropped and one under a secret key ('api_token')
    masked, like the same assignment in text. Detector results are memoised for the duration of this
    call only (repeated values and keys of large payloads are scanned once; nothing outlives the call)."""
    inline = [0]
    found_memo: dict[str, list[SecretHit]] = {}
    key_memo: dict[str, str] = {}
    label_memo: dict[str, tuple[str, str] | None] = {}

    def secrets_in(text: str) -> list[SecretHit]:
        hits = found_memo.get(text)
        if hits is None:
            hits = find_secrets(text)
            if len(found_memo) < 65536:
                found_memo[text] = hits
        return hits

    def leaf(text: str, where: str) -> Any:
        label = _label_of(where) if where else ""
        if label not in label_memo:
            label_memo[label] = _classify_label(label) if label else None
        labelled = label_memo[label]
        if labelled is not None and "cookie" in label.lower() and _COOKIE_NAME.match(text.strip()):
            labelled = None  # a cookie name ('PHPSESSID') is a fingerprint signal, not a session value
        found = secrets_in(text)
        if labelled is not None and not found and not _not_a_value(text) and not _is_form_word(text):
            kind, action = labelled
            if action == "drop":
                redacted.append(where)
                return _DROP
            if len(text.strip()) >= 8 and not text.strip().isdigit():
                redacted.append(where)
                return _mask(text.strip(), kind)
        if not found:
            return text
        stripped = text.strip()
        if len(found) == 1 and found[0].value.strip() == stripped:
            hit = found[0]
            redacted.append(where)
            return _mask(hit.value, hit.kind) if hit.action == "mask" else _DROP
        inline[0] += 1
        return _mask_text(text, found=found)

    def key(text: str) -> str:
        new = key_memo.get(text)
        if new is None:
            new = _mask_text(text, found=secrets_in(text))
            key_memo[text] = new
        if new != text:
            inline[0] += 1
        return new

    out = _map_leaves(value, path, leaf, key)
    if inline[0]:
        redacted.append(f"{_area(path)}:secret")
    return out


def _form_leaves(value: Any, path: str, redacted: list[str]) -> Any:
    """Drop every ``password_form`` field whose value is not a password FORM (f)."""

    def walk(obj: Any, where: str) -> Any:
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                sub = f"{where}.{k}" if where else str(k)
                if isinstance(k, str) and "form" in k.lower() and _normalise_key(k) == "password_form" and not is_password_form(v):
                    redacted.append(sub)
                    continue
                out[k] = walk(v, sub)
            return out
        if isinstance(obj, list):
            return [walk(v, f"{where}[]") for v in obj]
        if isinstance(obj, tuple):
            return tuple(walk(v, f"{where}[]") for v in obj)
        return obj

    return walk(value, path)


def _sensitive_leaves(value: Any, path: str, scrub: _SensitiveText, redacted: list[str]) -> Any:
    """Sensitive payload pass: password hashes next to credentials, then the free-text pass on every
    string leaf; a leaf left empty is dropped (its path recorded). Everything nested under a credential
    record (a dict with an account or password key) is 'next to the credential': its hex values go too."""
    hex_rule = scrub.hash_rule
    touched = [0]

    def walk(obj: Any, where: str, credential: bool) -> Any:
        if isinstance(obj, dict):
            record = credential or _credential_record(obj)
            out: dict[Any, Any] = {}
            for k, v in obj.items():
                sub = f"{where}.{k}" if where else str(k)
                if isinstance(v, str) and record and _whole_hash(v, hex_rule):
                    redacted.append(sub)
                    continue
                new = walk(v, sub, record)
                if new is _DROP:
                    redacted.append(sub)
                    continue
                nk = scrub.text(k) if isinstance(k, str) else k
                if nk != k:
                    touched[0] += 1
                out[nk or _REDACTED] = new
            return out
        if isinstance(obj, (list, tuple)):
            items = []
            for v in obj:
                if isinstance(v, str) and credential and _whole_hash(v, hex_rule):
                    redacted.append(f"{where}[]")
                    continue
                new = walk(v, f"{where}[]", credential)
                if new is _DROP:
                    redacted.append(f"{where}[]")
                    continue
                items.append(new)
            return tuple(items) if isinstance(obj, tuple) else items
        if isinstance(obj, str):
            if _whole_hash(obj, False):
                return _DROP
            new = scrub.text(obj)
            if new != obj:
                if not new.strip(" \t\r\n,;:|-=") and obj.strip():
                    return _DROP
                touched[0] += 1
            return new
        return obj

    out = walk(value, path, False)
    if touched[0]:
        redacted.append(f"{_area(path)}:second_net")
    return None if out is _DROP else out


# ----------------------------------------------------------------------------------------
# HTTP cache hook and the engine stage
# ----------------------------------------------------------------------------------------


def _redact_strings(value: Any) -> Any:
    if isinstance(value, str):
        return _redact.redact_text(value)
    if isinstance(value, dict):
        return {(_redact.redact_text(k) if isinstance(k, str) else k): _redact_strings(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_strings(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_redact_strings(v) for v in value)
    return value


def sanitize_body(source_id: str, content: bytes, content_type: str) -> bytes | None:
    """Sanitized JSON body for the cache of a sensitive provider, or None ('do not cache').

    JSON bodies (``application/json``, ``text/plain`` or no content type, as long as they parse)
    keep only the source schema's paths, then lose second-net fields, password hashes next to
    credentials, masked tokens, IP addresses, file paths, values copied from dropped fields,
    combos and secrets (``redact.redact_text`` last). HTML/XML or other bodies, sources without a
    schema and any failure give None: the response is fetched no-store.
    """
    try:
        schema = schema_for(source_id)
        if schema is None:
            return None
        ctype = (content_type or "").lower()
        if "html" in ctype or "xml" in ctype:
            return None
        if "json" not in ctype and ctype not in ("", "text/plain") and not ctype.startswith("text/plain"):
            return None
        text = content.decode("utf-8") if isinstance(content, (bytes, bytearray)) else str(content)
        data = json.loads(text)
        scrub = _SensitiveText()
        scrub.collect(data)
        kept, _ = apply_schema(data, _with_forms(schema))
        sink: list[str] = []
        kept = _keep_password_forms(kept, "", sink)
        kept, _ = drop_second_net(kept)
        kept = _sensitive_leaves(kept, "", scrub, sink)
        kept = _form_leaves(kept, "", sink)
        kept = _scrub_strings(kept, [0])
        kept = _top(_secret_leaves(kept, "", sink))
        kept = _redact_strings(kept)
        # ASCII-only JSON: the response keeps the provider's content-type, so the stored body must decode
        # the same under any declared (ASCII-compatible) charset
        return json.dumps(kept, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    except Exception:
        return None


def is_sensitive(module_cls: Any) -> bool:
    """Sensitive modules: the derived ``sensitive`` flag, or category breach_leak."""
    return bool(getattr(module_cls, "sensitive", False)) or getattr(module_cls, "category", "") == "breach_leak"


def _schemas_for_module(module_cls: Any) -> tuple[dict[str, SanitizerSchema], list[str]]:
    found: dict[str, SanitizerSchema] = {}
    missing: list[str] = []
    for sid in tuple(getattr(module_cls, "sources", ()) or ()):
        schema = schema_for(sid)
        if schema is None:
            missing.append(sid)
        else:
            found[sid] = schema
    return found, missing


def _sanitize_raw_sensitive(raw: Any, module_cls: Any, redacted: list[str]) -> Any:
    if raw is None:
        return None
    schemas, missing = _schemas_for_module(module_cls)
    if missing or not schemas or not isinstance(raw, (dict, list)):
        redacted.append("raw")  # fail closed: no schema for a source, or a non-JSON payload
        return None
    schemas = {sid: _with_forms(schema) for sid, schema in schemas.items()}
    if len(schemas) == 1:
        schema = next(iter(schemas.values()))
        kept, dropped = apply_schema(raw, schema)
        redacted.extend(f"raw.{p}" if p != "$" else "raw" for p in dropped)
        return kept
    # several sources: raw keyed by source id (full 'pid.sid' or short 'sid'), else the union
    if isinstance(raw, dict) and raw and all(any(k in (sid, sid.split(".", 1)[-1]) for sid in schemas) for k in raw):
        out = {}
        for k, v in raw.items():
            sid = next(s for s in schemas if k in (s, s.split(".", 1)[-1]))
            kept, dropped = apply_schema(v, schemas[sid])
            redacted.extend(f"raw.{k}.{p}" if p != "$" else f"raw.{k}" for p in dropped)
            if kept is not None:
                out[k] = kept
        return out
    union = SanitizerSchema("+".join(schemas), tuple(p for s in schemas.values() for p in s.keep))
    kept, dropped = apply_schema(raw, union)
    redacted.extend(f"raw.{p}" if p != "$" else "raw" for p in dropped)
    return kept


def _sensitive_stage(res: ModuleResult, module_cls: Any, redacted: list[str]) -> None:
    """(a)/(b) for sensitive modules: schema, second net, hashes, masks, IPs, paths, tainted pivots/links."""
    hash_rule = getattr(module_cls, "category", "") not in HASH_EXEMPT_CATEGORIES
    entity_value = str(getattr(getattr(res, "entity", None), "value", "") or "")
    scrub = _SensitiveText(entity_value, hash_rule=hash_rule)
    scrub.collect(res.raw)
    scrub.collect(res.attributes)
    for f in res.findings:
        scrub.collect(f.data)
    res.raw = _sanitize_raw_sensitive(res.raw, module_cls, redacted)
    res.raw = _keep_password_forms(res.raw, "raw", redacted)
    res.raw, dropped = drop_second_net(res.raw, "raw", hash_rule=hash_rule)
    redacted.extend(dropped)
    res.attributes = _keep_password_forms(res.attributes, "attributes", redacted)
    res.attributes, dropped = drop_second_net(res.attributes, "attributes", hash_rule=hash_rule)
    redacted.extend(dropped)
    for f in res.findings:
        f.data = _keep_password_forms(f.data, "findings.data", redacted)
        f.data, dropped = drop_second_net(f.data, "findings.data", hash_rule=hash_rule)
        redacted.extend(dropped)
    res.raw = _sensitive_leaves(res.raw, "raw", scrub, redacted)
    res.attributes = _sensitive_leaves(res.attributes, "attributes", scrub, redacted) or {}
    text_changed = False

    def text(value: str) -> str:
        nonlocal text_changed
        new = scrub.text(value)
        if new != value:
            text_changed = True
        return new

    for f in res.findings:
        f.data = _sensitive_leaves(f.data, "findings.data", scrub, redacted) or {}
        f.title = text(f.title) or "Finding (details removed by the P145 sanitizer)"
        f.description = text(f.description)
        f.criterion = text(f.criterion) or (f.criterion and "unspecified")
        f.key = text(f.key)
        for name in ("observed_first", "observed_last"):
            value = getattr(f, name, None)
            if isinstance(value, str):
                setattr(f, name, text(value) or None)
        refs = [r for r in f.references if not scrub.tainted(r)]
        if len(refs) != len(f.references):
            text_changed = True
        f.references = refs
    if text_changed:
        redacted.append("findings:second_net")
    kept_pivots = []
    tainted = False
    for p in res.pivots:
        etype = getattr(getattr(p.entity, "type", None), "value", "")
        value = str(getattr(p.entity, "value", "") or "")
        if scrub.tainted(value) or (etype in ("ipv4", "ipv6") and _norm_ip(value) not in scrub.keep_ips):
            tainted = True
            continue
        new_note = scrub.text(p.note)
        tainted = tainted or new_note != p.note
        p.note = new_note
        kept_pivots.append(p)
    res.pivots = kept_pivots
    if tainted:
        redacted.append("pivots:second_net")
    kept_links = []
    tainted = False
    for label, url in res.links:
        if scrub.tainted(url):
            tainted = True
            continue
        new_label = scrub.text(label)
        tainted = tainted or new_label != label
        kept_links.append((new_label, url))
    res.links = kept_links
    if tainted:
        redacted.append("links:second_net")
    new_error = scrub.text(res.error)
    statuses = getattr(res, "source_statuses", None)
    changed = new_error != res.error
    res.error = new_error
    if isinstance(statuses, dict):
        new_statuses = {k: ({kk: (scrub.text(vv) if isinstance(vv, str) else vv) for kk, vv in v.items()} if isinstance(v, dict) else v)
                        for k, v in statuses.items()}
        changed = changed or new_statuses != statuses
        res.source_statuses = new_statuses
    if changed:
        redacted.append("error:second_net")


def _secret_stage(res: ModuleResult, redacted: list[str]) -> None:
    """(c) for every module: structured masks in raw/attributes/data, inline fingerprints elsewhere."""
    from v3lum.core.entities import SECRET_TYPES, Entity  # lazy: entities is heavy

    res.raw = _top(_secret_leaves(res.raw, "raw", redacted))
    res.attributes = _top(_secret_leaves(res.attributes, "attributes", redacted)) or {}
    changed = False

    def text(value: Any, *, distinctive_only: bool = False) -> Any:
        nonlocal changed
        if not isinstance(value, str):
            return value
        new = _mask_text(value, distinctive_only=distinctive_only)
        if new != value:
            changed = True
        return new

    for f in res.findings:
        f.data = _top(_secret_leaves(f.data, "findings.data", redacted)) or {}
        f.title, f.description, f.criterion, f.key = text(f.title), text(f.description), text(f.criterion), text(f.key)
        f.observed_first, f.observed_last = text(f.observed_first), text(f.observed_last)
        refs = [r for r in f.references if not find_secrets(r, distinctive_only=True)]  # a URL carrying a secret is dropped
        changed = changed or len(refs) != len(f.references)
        f.references = refs
    if changed:
        redacted.append("findings:secret")
    changed = False
    kept = []
    for p in res.pivots:
        p.note = text(p.note)
        value = getattr(p.entity, "value", None)
        if isinstance(value, str) and p.entity.type not in SECRET_TYPES:
            clean = _mask_text(value, distinctive_only=True)
            if clean != value:  # an indicator carrying a secret is rebuilt from the masked value or dropped
                changed = True
                rebuilt = Entity.try_make(p.entity.type, clean)
                if rebuilt is None:
                    continue
                p.entity = rebuilt
        kept.append(p)
    res.pivots = kept
    if changed:
        redacted.append("pivots:secret")
    changed = False
    links = []
    for label, url in res.links:
        if find_secrets(url, distinctive_only=True):  # a webhook or a token in the URL: the link is dropped
            changed = True
            continue
        links.append((text(label), url))
    res.links = links
    if changed:
        redacted.append("links:secret")
    changed = False
    res.error = text(res.error)
    statuses = getattr(res, "source_statuses", None)
    if isinstance(statuses, dict):
        res.source_statuses = {k: ({kk: text(vv) for kk, vv in v.items()} if isinstance(v, dict) else v) for k, v in statuses.items()}
    if changed:
        redacted.append("error:secret")


def _redact_stage(res: ModuleResult) -> None:
    """(d) AR01 over every string (pivot values only lose registered secrets, like the engine's pass)."""
    from v3lum.core.entities import Entity

    res.raw = _redact_strings(res.raw)
    res.attributes = _redact_strings(res.attributes)
    for f in res.findings:
        f.title, f.description = _redact.redact_text(f.title), _redact.redact_text(f.description)
        f.criterion, f.key = _redact.redact_text(f.criterion), _redact.redact_text(f.key)
        f.observed_first, f.observed_last = _redact_strings(f.observed_first), _redact_strings(f.observed_last)
        f.references = [_redact.redact_text(r) for r in f.references]
        f.data = _redact_strings(f.data)
    kept = []
    for p in res.pivots:
        p.note = _redact.redact_text(p.note)
        value = getattr(p.entity, "value", None)
        if isinstance(value, str) and _redact.has_secret(value):
            rebuilt = Entity.try_make(p.entity.type, _redact.redact_text(value))
            if rebuilt is None:
                continue
            p.entity = rebuilt
        kept.append(p)
    res.pivots = kept
    res.links = [(_redact.redact_text(label), _redact.redact_text(url)) for label, url in res.links]
    res.error = _redact.redact_text(res.error)
    statuses = getattr(res, "source_statuses", None)
    if isinstance(statuses, dict):
        res.source_statuses = _redact_strings(statuses)


def sanitize_result(res: ModuleResult, module_cls: Any) -> ModuleResult:
    """Engine stage (P145): the mandatory, fail-closed sanitizer every module result passes.

    Sensitive modules get their source schemas, the second net and the sensitive value detectors
    (stage a/b of the module docstring); every module loses combos, has its secrets masked
    (fingerprints, never raw) and its strings redacted (AR01), and keeps ``password_form`` only
    with a valid FORM. Covers res.raw, attributes, findings (data and text), pivot notes and values,
    links, errors and per-feed reasons, and records what was removed in ``res.redacted_fields``.
    Raises SanitizerError on internal failure (the engine then drops the result: ERROR 'sanitizer').
    """
    try:
        redacted: list[str] = list(getattr(res, "redacted_fields", []) or [])
        sensitive = is_sensitive(module_cls)
        res.raw = _plain(res.raw, sensitive)
        res.attributes = _plain(res.attributes, sensitive)
        for f in res.findings:
            f.data = _plain(f.data, sensitive)
            f.references = _plain(list(f.references or []), sensitive)
            f.observed_first = _plain(getattr(f, "observed_first", None), True)
            f.observed_last = _plain(getattr(f, "observed_last", None), True)
        statuses = getattr(res, "source_statuses", None)
        if isinstance(statuses, dict):
            res.source_statuses = _plain(statuses, sensitive)
        if sensitive:
            _sensitive_stage(res, module_cls, redacted)
        counter = [0]
        res.raw = _scrub_strings(res.raw, counter)
        if counter[0]:
            redacted.append("raw:combo")
        counter = [0]
        res.attributes = _scrub_strings(res.attributes, counter)
        if counter[0]:
            redacted.append("attributes:combo")
        counter = [0]
        for f in res.findings:
            f.data = _scrub_strings(f.data, counter)
            f.title = _scrub_strings(f.title, counter)
            f.description = _scrub_strings(f.description, counter)
            f.criterion = _scrub_strings(f.criterion, counter)
            f.key = _scrub_strings(f.key, counter)
            f.references = _scrub_strings(list(f.references), counter)
            f.observed_first = _scrub_strings(f.observed_first, counter)
            f.observed_last = _scrub_strings(f.observed_last, counter)
        if counter[0]:
            redacted.append("findings:combo")
        counter = [0]
        kept_pivots = []
        for p in res.pivots:
            p.note = _scrub_strings(p.note, counter)
            value = getattr(p.entity, "value", None)
            clean = drop_combos(value) if isinstance(value, str) else value
            if clean != value:  # any entity type: a combo never survives as an entity value
                from v3lum.core.entities import Entity

                counter[0] += 1
                rebuilt = Entity.try_make(p.entity.type, clean) if clean else None
                if rebuilt is None:
                    continue  # nothing valid is left once the credential is gone: drop the pivot
                p.entity = rebuilt
            kept_pivots.append(p)
        res.pivots = kept_pivots
        if counter[0]:
            redacted.append("pivots:combo")
        counter = [0]
        res.links = [(_scrub_strings(lbl, counter), _scrub_strings(url, counter)) for lbl, url in res.links]
        if counter[0]:
            redacted.append("links:combo")
        counter = [0]
        res.error = _scrub_strings(res.error, counter)
        statuses = getattr(res, "source_statuses", None)
        if isinstance(statuses, dict):
            res.source_statuses = _scrub_strings(statuses, counter)
        if counter[0]:
            redacted.append("error:combo")
        res.raw = _form_leaves(res.raw, "raw", redacted)
        res.attributes = _form_leaves(res.attributes, "attributes", redacted)
        for f in res.findings:
            f.data = _form_leaves(f.data, "findings.data", redacted)
        _secret_stage(res, redacted)
        _redact_stage(res)
        res.redacted_fields = sorted(dict.fromkeys(redacted))
        return res
    except SanitizerError:
        raise
    except Exception as exc:
        raise SanitizerError(f"sanitizer failed: {type(exc).__name__}: {exc}") from exc
