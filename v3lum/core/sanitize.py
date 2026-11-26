"""Data-minimisation sanitizer (P145, A4): allow-list schemas, a second-net denylist, combo removal.

The engine runs :func:`sanitize_result` on every module result right after ``Module.run``
returns (modules cannot opt out) and fails closed: an exception drops what the module produced
and the run ends ERROR with reason_code 'sanitizer'. The HTTP client calls :func:`sanitize_body`
before caching bodies of providers flagged sensitive (no schema -> not cached).

Allow-list schemas are registered per registry source, either at import time in the module file::

    from v3lum.core import sanitize
    sanitize.register_schema("hudsonrock.cavalier", keep=["stealers[].date_compromised",
                             "stealers[].stealer_family", "total_corporate_services"])

or in the provider fragment (``providers.<pid>.sources.<sid>.sanitizer = {"keep": [...]}``).
Keep paths are dotted keys with ``[]`` for list elements and ``*`` for any key. Modules record
the password FORM in a kept field ``password_form`` ('plaintext' | 'hashed: <algorithm>') and
never keep passwords, hashes, salts, masked hints, cookies, tokens, computer names,
infected-host IPs, malware paths or combo lines.

This is the wave-1 thin version; WP09 completes the stage (scrub_text, hash-next-to-credential
detection, golden tests) without renaming anything here.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

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
    "password", "passwords", "passwd", "pass", "pwd", "senha", "senhas",
    "hash", "hashes", "password_hash", "passwordhash", "hashed_password", "salt",
    "top_passwords", "top_logins", "login", "logins",
    "masked_password", "password_masked", "masked", "hint", "password_hint", "hints",
    "cookie", "cookies", "session", "sessions", "session_id", "session_token",
    "token", "tokens", "access_token", "refresh_token", "auth_token",
    "autofill", "autofills", "credit_cards", "credit_card", "card_number", "cvv",
    "secret", "secrets", "api_key", "apikey", "private_key", "auth_key", "authorization",
    "computer_name", "computername", "pc_name", "machine_name",
    "ip", "ip_address", "infected_ip", "victim_ip", "infected_host_ip",
    "malware_path", "combo", "combos", "line", "lines", "combo_line",
})
#: Substrings that make a key sensitive anywhere in its (normalised) name.
_SECOND_NET_SUBSTRINGS = (
    "password", "passwd", "senha", "cookie", "token", "session", "autofill", "combo", "computer_name", "malware_path",
    "secret", "api_key", "apikey", "private_key", "credit_card",
)
#: Single words that make a key sensitive when they appear as a '_'-separated token.
_SECOND_NET_TOKENS = frozenset({"pass", "pwd", "hash", "hashes", "salt", "hint", "hints", "masked", "login", "logins", "ip", "line", "lines", "cvv"})
#: Kept even though they look sensitive (the password FORM is metadata, A4).
_SECOND_NET_ALLOW = frozenset({"password_form"})

_SCHEMAS: dict[str, SanitizerSchema] = {}
_LOCK = threading.Lock()
_PATH_SEGMENT = re.compile(r"^(?:\*|[^.\[\]]+)?(?:\[\])*$")


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
# Second net and value detectors
# ----------------------------------------------------------------------------------------


def _normalise_key(key: Any) -> str:
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(key))
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def is_second_net_field(key: Any) -> bool:
    """True when a field name belongs to the P145 second net (passwords, hashes, cookies, ...)."""
    norm = _normalise_key(key)
    if not norm or norm in _SECOND_NET_ALLOW:
        return False
    if norm in SECOND_NET_FIELDS:
        return True
    if any(s in norm for s in _SECOND_NET_SUBSTRINGS):
        return True
    return any(tok in _SECOND_NET_TOKENS for tok in norm.split("_"))


def drop_second_net(obj: Any, prefix: str = "") -> tuple[Any, list[str]]:
    """Copy of ``obj`` without second-net keys (nested, case-insensitive); returns (copy, dropped paths)."""
    dropped: list[str] = []

    def walk(value: Any, path: str) -> Any:
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                sub = f"{path}.{k}" if path else str(k)
                if is_second_net_field(k):
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


def drop_combos(text: str) -> str:
    """Remove credential combos, never mask them: 'a@b.com:pw' -> 'a@b.com'; 'u:p@host' -> 'host'.

    URL credentials are dropped too ('https://u:p@host/x' -> 'https://host/x', 'redis://:p@host' ->
    'redis://host'); URLs with a user but no password ('ssh://git@host:22/x') are left alone.
    """
    if not isinstance(text, str) or "@" not in text:
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
    return _drop_bare_userinfo(out)


def mask_secret(raw: str, kind: str = "") -> dict[str, str]:
    """Fingerprint of a secret: {'type', 'preview' (first 4 + '…' + last 4, '****' under 12 chars), 'sha256'}."""
    value = raw if isinstance(raw, str) else str(raw)
    preview = f"{value[:4]}…{value[-4:]}" if len(value) >= 12 else "****"
    return {"type": kind or "secret", "preview": preview, "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest()}


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


# ----------------------------------------------------------------------------------------
# HTTP cache hook and the engine stage
# ----------------------------------------------------------------------------------------


def sanitize_body(source_id: str, content: bytes, content_type: str) -> bytes | None:
    """Sanitized JSON body for the cache of a sensitive provider, or None ('do not cache').

    JSON bodies are filtered by the source schema, then the second net and combo removal run;
    non-JSON bodies, sources without a schema and any failure give None.
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
        kept, _ = apply_schema(data, schema)
        kept, _ = drop_second_net(kept)
        kept = _scrub_strings(kept, [0])
        return json.dumps(kept, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
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


def sanitize_result(res: ModuleResult, module_cls: Any) -> ModuleResult:
    """Engine stage (P145): sensitive modules get schemas + the second net; every module loses combos.

    Covers res.raw, attributes, findings (data and text), pivot notes, URL pivots and links, and
    records what was removed in ``res.redacted_fields``. Raises SanitizerError on internal failure.
    """
    try:
        redacted: list[str] = list(getattr(res, "redacted_fields", []) or [])
        sensitive = is_sensitive(module_cls)
        if sensitive:
            res.raw = _sanitize_raw_sensitive(res.raw, module_cls, redacted)
            res.raw, dropped = drop_second_net(res.raw, "raw")
            redacted.extend(dropped)
            res.attributes, dropped = drop_second_net(res.attributes, "attributes")
            redacted.extend(dropped)
            for f in res.findings:
                f.data, dropped = drop_second_net(f.data, "findings.data")
                redacted.extend(dropped)
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
        res.redacted_fields = sorted(dict.fromkeys(redacted))
        return res
    except SanitizerError:
        raise
    except Exception as exc:
        raise SanitizerError(f"sanitizer failed: {type(exc).__name__}: {exc}") from exc
