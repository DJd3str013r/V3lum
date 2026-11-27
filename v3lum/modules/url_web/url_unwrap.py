"""URL rewrite unwrapping and Unfurl-style decoding, strictly offline (P064, batch p1-G03-1).

Recovers the real destination behind link-protection and redirect wrappers found in pasted e-mails
and chats - Microsoft SafeLinks (``url=``), Proofpoint URL Defense v1/v2 (``u=``) and v3
(``__<url>__;<b64>``), Google ``/url?q=`` and ``/amp/s/``, Mimecast (destination domain only),
Barracuda, LinkedIn, Facebook/Messenger, Instagram, Slack and YouTube redirectors - nested wrappers
included (bounded at 5 levels), and decodes Unfurl-style values of the final URL (Unix timestamps,
.NET ticks, UUID v1/v7, Twitter/X, Discord, TikTok and LinkedIn snowflake ids, base64 text/URLs).

Final conditions implemented (P064):

* c1/c2 - no redirect is ever followed and nothing is fetched: ``disclosure='none'``, no HTTP code at
  all in this file. No automated call to dfir.blog / Unfurl (the manual pivot link of the
  ``url_unwrap`` pack is the only Unfurl path). No Unfurl code was ported: the decoders below are
  written from the public format definitions (Unfurl's Apache-2.0 LICENSE was re-checked on
  2026-11-26; porting code from it would need an attribution header and a notice fragment).
* c3 - the module file is the single unwrapping helper of V3LUM: :func:`unwrap_url`,
  :func:`unwrap_text`, :func:`extract_urls`, :func:`redact_url_values`, :func:`is_wrapper_host` and
  :func:`personal_pivot_from_url` are the public API used by email_header_analyzer (P085), the P172
  text extraction and urlscan_search (P066).
* c4 - wrapped -> unwrapped is kept as a relation (``unwraps_to``); wrapper hosts are noise (the
  ``url_wrappers`` noise fragment): they are never pivoted, never IOCs, never reputation-checked.
* c5 - recipient identifiers embedded in wrapper parameters (SafeLinks ``data``/``sdata`` with the
  recipient e-mail and tenant id, Proofpoint ``r``/``d``/``c``/``m``/``s`` and the v3
  ``!customer!token`` tail, Mimecast tokens, LinkedIn thread URNs, e-mails in plain, ``%40`` and base64
  forms, click ids and opaque tokens) are redacted before anything is stored: results, evidence and
  reports only see redacted URLs. Fields named ``*_unredacted`` exist in memory only (local list
  matching by other helpers) and never reach ``res``.
* c6 - ``wa.me/<digits>`` and ``api.whatsapp.com/send?phone=`` decode to phone entities (E.164, BR
  default region for 10/11-digit national numbers); ``t.me/<name>`` to telegram_handle and
  ``t.me/+code`` / ``joinchat`` to telegram_invite: PERSONAL_TYPES pivoted with ``expand=False`` for
  analyst selection (AR07), never followed.
* c7 - unwrapped URLs are passive pivots (the engine never runs LIGHT/ACTIVE on pivots and gives
  them the case TLP); URLs carrying recipient tokens are tagged ``recipient_token``, pivoted only in
  redacted form and with ``expand=False`` (A7: never fetched automatically).
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import ipaddress
import math
import re
import urllib.parse
import uuid as _uuid
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

__all__ = [
    "MAX_DEPTH",
    "RECIPIENT_SENSITIVE_KINDS",
    "WRAPPER_HOST_SUFFIXES",
    "UrlUnwrap",
    "decode_url_params",
    "extract_urls",
    "is_wrapper_host",
    "match_wrapper",
    "normalise_phone_e164",
    "personal_pivot_from_url",
    "redact_url_values",
    "storage_view",
    "unwrap_text",
    "unwrap_url",
]

#: P064 c1: nesting bound (a wrapper of a wrapper ... at most 5 levels are unwrapped).
MAX_DEPTH = 5
#: URLs read from one text blob (P172 owns full extraction; this is the unwrapping view).
MAX_TEXT_URLS = 500

UTC = _dt.timezone.utc
REDACTED = "REDACTED"
REDACTED_EMAIL = "REDACTED_EMAIL"
REDACTED_B64_EMAIL = "REDACTED_B64_EMAIL"
REDACTED_TOKEN = "REDACTED_TOKEN"

#: recipient-token kinds that make a URL 'recipient bound' (A7: never fetched automatically)
RECIPIENT_SENSITIVE_KINDS = frozenset({
    "recipient_email", "tenant_id", "recipient_hash", "recipient_token", "opaque_token", "email", "base64_email",
    "message_id", "customer_id",
})

# =============================================================================================
# small helpers
# =============================================================================================


def _text(raw: Any) -> str:
    """bytes/str/None -> str (UTF-8 with replacement, BOM stripped). Never raises."""
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        value = bytes(raw).decode("utf-8", errors="replace")
    elif isinstance(raw, str):
        value = raw
    else:
        value = str(raw)
    return value.lstrip("﻿")


def _iso(value: _dt.datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z") if isinstance(value, _dt.datetime) else None


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$")


def normalise_host(host: Any) -> str | None:
    """Lower-case, strip brackets/trailing dot, IDNA -> punycode; an IP literal is kept. None if invalid."""
    if not host or not isinstance(host, str):
        return None
    h = host.strip().strip("[]").rstrip(".").lower()
    if not h:
        return None
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    if any(ord(c) > 127 for c in h):
        try:
            h = h.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return h if _HOST_RE.match(h) else None


def split_url(url: Any) -> dict[str, Any] | None:
    """urlsplit that tolerates a missing scheme and junk: {scheme, host, port, path, query, fragment} or None."""
    if not url or not isinstance(url, str):
        return None
    u = url.strip()
    had_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u))
    if not had_scheme:
        u = ("http:" + u) if u.startswith("//") else ("http://" + u)
    try:
        parts = urllib.parse.urlsplit(u)
        port = parts.port
    except ValueError:
        return None
    host = normalise_host(parts.hostname or "")
    if host is None:
        return None
    return {"scheme": parts.scheme.lower() if had_scheme else None, "host": host, "port": port, "path": parts.path or "",
            "query": parts.query, "fragment": parts.fragment}


def _under(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith("." + suffix)


def _qs_raw(query: str) -> list[tuple[str, str]]:
    """Split a query string WITHOUT decoding ('+' stays '+'): [(name, raw_value)]."""
    out = []
    for part in (query or "").split("&"):
        if not part:
            continue
        name, _, value = part.partition("=")
        out.append((name, value))
    return out


def _unq(value: str) -> str:
    return urllib.parse.unquote(value or "", errors="replace")


def _param(pairs: list[tuple[str, str]], *names: str) -> str | None:
    wanted = [n.lower() for n in names]
    for name, value in pairs:
        if _unq(name).lower() in wanted and value != "":
            return value
    return None


# =============================================================================================
# recipient / token redaction (c5, c7; also used by urlscan_search, P066 c5)
# =============================================================================================
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}(?:@|%40|%2540)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}", re.I)
_EMAIL_STRICT = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/_-]{12,}={0,2}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_TOKEN_CHARS = re.compile(r"^[A-Za-z0-9_\-.~+/=%]{16,}$")

#: per-recipient marketing / mail tracking parameters (A7: never auto-fetched)
RECIPIENT_TOKEN_PARAMS = frozenset({
    "mkt_tok", "mc_eid", "_hsenc", "_hsmi", "vero_id", "oly_enc_id", "oly_anon_id", "sc_eh", "ml_subscriber",
    "ml_subscriber_hash", "trk_contact", "ecid", "elqtrackid", "elq", "s_eid",
})
CLICK_ID_PARAMS = frozenset({"fbclid", "gclid", "msclkid", "dclid", "twclid", "ttclid", "li_fat_id", "igshid", "yclid", "wbraid", "gbraid"})


def _b64_text(value: Any) -> str | None:
    """Decode std/urlsafe base64 to printable UTF-8 text, or None."""
    if not isinstance(value, str) or not _B64_RE.match(value):
        return None
    v = value.rstrip("=")
    if v.isdigit() or v.isalpha():
        return None
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            raw = decoder(v + "=" * (-len(v) % 4))
        except (binascii.Error, ValueError):
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(text) >= 4 and sum(ch.isprintable() for ch in text) / len(text) >= 0.95:
            return text
    return None


def _token_like(value: Any) -> bool:
    """A7: an opaque token of >= 16 chars (letters AND digits, high entropy) or a UUID."""
    if not isinstance(value, str):
        return False
    if _UUID_RE.match(value):
        return True
    if not _TOKEN_CHARS.match(value) or value.startswith(("http:", "https:")):
        return False
    if not (re.search(r"[A-Za-z]", value) and re.search(r"\d", value)):
        return False
    return _entropy(value) >= 3.5


def redact_url_values(url: Any, redact_tokens: bool = True) -> tuple[Any, list[str]]:
    """Redact e-mails (plain, %40, %2540, base64), per-recipient/click tokens and opaque tokens (>= 16
    chars) in the path, query and fragment of ``url``; URL userinfo is always dropped.

    Returns ``(redacted_url, kinds)``: ``kinds`` names what was redacted, never the values. Callers
    still pass stored URLs through the core redactor (``v3lum.core.redact.redact_url``, API keys).
    """
    if not isinstance(url, str) or not url:
        return url, []
    kinds: list[str] = []
    try:
        parts = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return _EMAIL_RE.sub(REDACTED_EMAIL, url), ["unparsable"]
    netloc = parts.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
        kinds.append("userinfo")

    def fix(name: str, raw: str) -> str:
        decoded = _unq(raw)
        lname = _unq(name).lower()
        if lname in RECIPIENT_TOKEN_PARAMS:
            kinds.append(f"recipient_param:{lname}")
            return REDACTED_TOKEN
        if lname in CLICK_ID_PARAMS:
            kinds.append(f"click_id:{lname}")
            return REDACTED_TOKEN
        if _EMAIL_STRICT.match(decoded):
            kinds.append("email")
            return REDACTED_EMAIL
        if _EMAIL_RE.search(raw):
            kinds.append("email")
            return _EMAIL_RE.sub(REDACTED_EMAIL, raw)
        b64 = _b64_text(decoded)
        if b64 and _EMAIL_RE.search(b64):
            kinds.append("base64_email")
            return REDACTED_B64_EMAIL
        if redact_tokens and _token_like(decoded) and not (b64 and b64.startswith(("http://", "https://"))):
            kinds.append("opaque_token")
            return REDACTED_TOKEN
        return raw

    path = "/".join(fix("", seg) if seg else seg for seg in parts.path.split("/"))
    qparts = []
    for part in (parts.query or "").split("&"):
        if not part:
            continue
        if "=" in part:
            name, value = part.split("=", 1)
            qparts.append(f"{name}={fix(name, value)}")
        else:  # a bare value such as '?ICmAGsqM%2F'
            qparts.append(fix("", part))
    fragment = _EMAIL_RE.sub(REDACTED_EMAIL, parts.fragment) if parts.fragment else ""
    if fragment != parts.fragment:
        kinds.append("email")
    out = urllib.parse.urlunsplit((parts.scheme, netloc, path, "&".join(qparts), fragment))
    return out, sorted(set(kinds))


# =============================================================================================
# wrapper handlers (c1)
# =============================================================================================
_V3_RUN = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_V3_RE = re.compile(r"^https?://(?:www\.)?urldefense(?:\.proofpoint)?\.(?:com|us)/v3/__(?P<url>.+?)__;(?P<enc>[A-Za-z0-9_-]*)(?P<rest>!.*)?$", re.S)
_GOOGLE_HOST = re.compile(r"^(?:www\.)?google\.(?:com|[a-z]{2,3}|com?\.[a-z]{2})$")
_TS_MIN, _TS_MAX = 946684800, 2208988800  # 2000-01-01 .. 2040-01-01


def _epoch_iso(n: int) -> str | None:
    for div in (1, 1000, 1_000_000, 1_000_000_000):
        v = n / div
        if _TS_MIN <= v <= _TS_MAX:
            return _iso(_dt.datetime.fromtimestamp(v, tz=UTC))
    return None


def _dotnet_ticks_iso(value: Any) -> str | None:
    try:
        ticks = int(value)
    except (TypeError, ValueError):
        return None
    sec = (ticks - 621355968000000000) / 10_000_000
    if not (_TS_MIN <= sec <= _TS_MAX):
        return None
    return _iso(_dt.datetime.fromtimestamp(sec, tz=UTC))


def _rebuild(parts: Any, pairs: list[tuple[str, str]], *, keep: tuple[str, ...] = (), dest_param: str | None = None,
             dest_value: str | None = None, redact_all_others: bool = True) -> str:
    out = []
    for name, value in pairs:
        lname = _unq(name).lower()
        if dest_param and lname == dest_param:
            out.append(f"{name}={urllib.parse.quote(dest_value, safe='') if dest_value is not None else value}")
        elif lname in keep or not redact_all_others:
            out.append(f"{name}={value}")
        else:
            out.append(f"{name}={REDACTED}")
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(out), ""))


def _h_safelinks(parts: Any, pairs: list[tuple[str, str]]) -> dict[str, Any]:
    """Microsoft Defender SafeLinks: ?url=<dest>&data=05|02|<recipient>|<msg>|<tenant>|...|<ticks>|...&sdata=..."""
    tokens: list[str] = []
    facts: dict[str, Any] = {}
    data = _param(pairs, "data")
    if data is not None:
        fields = _unq(data).split("|")
        if len(fields) > 2 and "@" in fields[2]:
            tokens.append("recipient_email")
        if len(fields) > 4 and re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F-]{36}", fields[4] or ""):
            tokens.append("tenant_id")
        if len(fields) > 3 and re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F-]{36}", fields[3] or ""):
            tokens.append("message_id")
        if len(fields) > 7:
            ts = _dotnet_ticks_iso(fields[7])
            if ts:
                facts["safelinks_time"] = ts
    if _param(pairs, "sdata") is not None:
        tokens.append("signature")
    dest = _param(pairs, "url")
    inner = _unq(dest) if dest else None
    return {"inner": inner, "tokens": tokens, "facts": facts, "error": None if inner else "safelinks without url parameter",
            "dest_param": "url", "keep": ("reserved",)}


def _h_teams_safelinks(parts: Any, pairs: list[tuple[str, str]]) -> dict[str, Any]:
    dest = _param(pairs, "url")
    return {"inner": _unq(dest) if dest else None, "tokens": ["wrapper_token"] if len(pairs) > 1 else [], "facts": {},
            "error": None if dest else "teams safelinks without url parameter", "dest_param": "url", "keep": ("locale",)}


def _h_proofpoint_v1(parts: Any, pairs: list[tuple[str, str]]) -> dict[str, Any]:
    dest = _param(pairs, "u")
    return {"inner": _unq(dest) if dest else None, "tokens": ["recipient_hash"] if _param(pairs, "r") else [],
            "facts": {"proofpoint_version": 1}, "error": None if dest else "proofpoint v1 without u parameter",
            "dest_param": "u", "keep": ()}


def _h_proofpoint_v2(parts: Any, pairs: list[tuple[str, str]]) -> dict[str, Any]:
    dest = _param(pairs, "u")
    inner = urllib.parse.unquote(dest.replace("-", "%").replace("_", "/"), errors="replace") if dest else None
    return {"inner": inner, "tokens": ["recipient_hash"] if _param(pairs, "r") else [],
            "facts": {"proofpoint_version": 2}, "error": None if dest else "proofpoint v2 without u parameter",
            "dest_param": "u", "keep": ()}


def decode_proofpoint_v3(url: Any) -> tuple[str | None, str | None]:
    """Proofpoint URL Defense v3 ``__<url>__;<b64 replaced chars>!<customer>!<token>$``: a ``*`` takes
    one replaced character, ``**X`` takes (index of X in A-Za-z0-9-_) + 2. Returns (url, error)."""
    m = _V3_RE.match(url.strip()) if isinstance(url, str) else None
    if not m:
        return None, "not a proofpoint v3 url"
    body, enc = m.group("url"), m.group("enc") or ""
    single = re.match(r"^([a-z][a-z0-9+.-]*:/)([^/].*)$", body, re.I)
    if single:  # 'https:/host' -> 'https://host'
        body = single.group(1) + "/" + single.group(2)
    try:
        repl = base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4)).decode("utf-8") if enc else ""
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None, "proofpoint v3: bad replacement bytes"
    out: list[str] = []
    i = pos = 0
    while i < len(body):
        ch = body[i]
        if ch != "*":
            out.append(ch)
            i += 1
            continue
        if body.startswith("**", i) and i + 2 < len(body):
            n = _V3_RUN.find(body[i + 2]) + 2
            if n < 2:
                return None, "proofpoint v3: bad run marker"
            i += 3
        else:
            n = 1
            i += 1
        if pos + n > len(repl):
            return None, "proofpoint v3: replacement bytes exhausted"
        out.append(repl[pos:pos + n])
        pos += n
    return "".join(out), None


def _h_proofpoint_v3(parts: Any, pairs: list[tuple[str, str]], url: str) -> dict[str, Any]:
    inner, err = decode_proofpoint_v3(url)
    m = _V3_RE.match(url.strip())
    redacted = None
    if m:
        redacted = (_EMAIL_RE.sub(REDACTED_EMAIL, url[: m.start("enc")]) + (m.group("enc") or "")
                    + ("!REDACTED!REDACTED$" if m.group("rest") else ""))
    return {"inner": inner, "tokens": ["customer_id", "recipient_token"] if (m and m.group("rest")) else [],
            "facts": {"proofpoint_version": 3}, "error": err, "redacted_override": redacted}


def _h_google(parts: Any, pairs: list[tuple[str, str]]) -> dict[str, Any]:
    dest = _param(pairs, "q") or _param(pairs, "url")
    inner = _unq(dest) if dest else None
    if inner and not re.match(r"^https?://", inner, re.I):
        inner = None
    facts: dict[str, Any] = {}
    ust = _param(pairs, "ust")
    if ust and ust.isdigit():
        facts["google_ust"] = _epoch_iso(int(ust))
    return {"inner": inner, "tokens": [], "facts": facts, "error": None if inner else "google redirect without url",
            "dest_param": "q" if _param(pairs, "q") else "url",
            "keep": ("sa", "source", "ust", "usg", "rct", "esrc", "cd", "ved", "q", "url"), "redact_all_others": False}


def _h_google_amp(parts: Any, pairs: list[tuple[str, str]]) -> dict[str, Any]:
    m = re.match(r"^/amp/(s/)?(.+)$", parts.path)
    inner = (("https://" if m.group(1) else "http://") + m.group(2)) if m else None
    return {"inner": inner, "tokens": [], "facts": {}, "error": None if inner else "bad amp path", "keep": (), "redact_all_others": False}


def _h_mimecast(parts: Any, pairs: list[tuple[str, str]]) -> dict[str, Any]:
    dom = _param(pairs, "domain")
    host = normalise_host(_unq(dom)) if dom else None
    red = urllib.parse.urlunsplit((parts.scheme, parts.netloc, "/s/" + REDACTED, f"domain={host or ''}", ""))
    return {"inner": None, "partial": True, "tokens": ["opaque_token"], "facts": {"destination_domain": host},
            "error": None if host else "mimecast link without domain", "redacted_override": red}


def _h_simple(param: str, token_names: tuple[str, ...] = ()) -> Any:
    def handler(parts: Any, pairs: list[tuple[str, str]]) -> dict[str, Any]:
        dest = _param(pairs, param)
        toks = sorted({"wrapper_token" for n in token_names if _param(pairs, n)})
        return {"inner": _unq(dest) if dest else None, "tokens": toks, "facts": {},
                "error": None if dest else f"wrapper without {param} parameter", "dest_param": param, "keep": ("trk",)}
    return handler


def _h_linkedin(parts: Any, pairs: list[tuple[str, str]]) -> dict[str, Any]:
    out = _h_simple("url", ())(parts, pairs)
    if _param(pairs, "messageThreadUrn"):
        out["tokens"] = ["recipient_token"]
    return out


#: (name, host/path predicate, handler); the proofpoint_v3 handler needs the whole URL (special-cased)
WRAPPERS: list[tuple[str, Any, Any]] = [
    ("safelinks", lambda h, p: ".safelinks.protection." in "." + h, _h_safelinks),
    ("teams_safelinks", lambda h, p: h == "statics.teams.cdn.office.net" and "/safelinks/" in p, _h_teams_safelinks),
    ("proofpoint_v3", lambda h, p: h in ("urldefense.com", "www.urldefense.com", "urldefense.us", "urldefense.proofpoint.com") and p.startswith("/v3/"), None),
    ("proofpoint_v2", lambda h, p: (h == "urldefense.proofpoint.com" or h.endswith(".proofpoint.com") or h == "urldefense.us") and p.startswith("/v2/url"), _h_proofpoint_v2),
    ("proofpoint_v1", lambda h, p: (h == "urldefense.proofpoint.com" or h.endswith(".proofpoint.com")) and p.startswith("/v1/url"), _h_proofpoint_v1),
    ("google_redirect", lambda h, p: bool(_GOOGLE_HOST.match(h)) and p == "/url", _h_google),
    ("google_amp", lambda h, p: bool(_GOOGLE_HOST.match(h)) and p.startswith("/amp/"), _h_google_amp),
    ("mimecast", lambda h, p: (h.endswith(".mimecast.com") or h.endswith(".mimecastprotect.com")) and p.startswith("/s/"), _h_mimecast),
    ("barracuda", lambda h, p: h == "linkprotect.cudasvc.com" and p.startswith("/url"), _h_simple("a", ("c", "p", "s"))),
    ("linkedin", lambda h, p: _under(h, "linkedin.com") and p in ("/redir/redirect", "/safety/go", "/redir/general-malware-page", "/redir/suspicious-page"), _h_linkedin),
    ("facebook", lambda h, p: h in ("l.facebook.com", "lm.facebook.com", "l.messenger.com") and p == "/l.php", _h_simple("u", ("h",))),
    ("instagram", lambda h, p: h == "l.instagram.com" and p in ("", "/"), _h_simple("u", ("e",))),
    ("slack", lambda h, p: h == "slack-redir.net" and p == "/link", _h_simple("url")),
    ("youtube", lambda h, p: _under(h, "youtube.com") and p == "/redirect", _h_simple("q", ("redir_token",))),
]
_HANDLERS = {name: handler for name, _pred, handler in WRAPPERS}

#: c4: dedicated rewriter hosts - noise, never IOCs, never reputation-checked (Google is a wrapper
#: only on its /url and /amp paths, so google.com itself is not listed here).
WRAPPER_HOST_SUFFIXES: tuple[str, ...] = (
    "safelinks.protection.outlook.com", "safelinks.protection.office365.us", "urldefense.com", "urldefense.us",
    "urldefense.proofpoint.com", "mimecast.com", "mimecastprotect.com", "linkprotect.cudasvc.com", "slack-redir.net",
    "l.facebook.com", "lm.facebook.com", "l.messenger.com", "l.instagram.com", "statics.teams.cdn.office.net",
)


def is_wrapper_host(host: Any) -> bool:
    """True for dedicated link-rewriting hosts (noise: never IOCs, never reputation-checked)."""
    h = normalise_host(host) if isinstance(host, str) else None
    return bool(h) and any(_under(h, s) for s in WRAPPER_HOST_SUFFIXES)


def match_wrapper(url: Any) -> str | None:
    """The wrapper name of ``url`` (host + path rule), or None."""
    s = split_url(url) if isinstance(url, str) else None
    if not s:
        return None
    for name, predicate, _handler in WRAPPERS:
        try:
            if predicate(s["host"], s["path"]):
                return name
        except Exception:  # noqa: BLE001 - predicates never raise on odd input
            continue
    return None


def _redact_for_chain(url: Any, depth: int = 0) -> Any:
    """Storage-safe form of a URL that may itself be a wrapper (wrappers redacted recursively, bounded)."""
    if not url:
        return url
    if depth > MAX_DEPTH + 1:
        return REDACTED
    if match_wrapper(url):
        step = unwrap_once(url, _depth=depth + 1)
        if step:
            return step["wrapped_redacted"]
    return redact_url_values(url)[0]


def unwrap_once(url: Any, _depth: int = 0) -> dict[str, Any] | None:
    """Unwrap one layer. None when ``url`` is not a wrapper, else a step dict
    ``{wrapper, wrapper_host, inner_unredacted, partial, tokens, facts, error, wrapped_redacted}``."""
    name = match_wrapper(url)
    if not name:
        return None
    try:
        parts = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return {"wrapper": name, "wrapper_host": None, "inner_unredacted": None, "partial": False, "tokens": [],
                "facts": {}, "error": "unparsable url", "wrapped_redacted": REDACTED}
    pairs = _qs_raw(parts.query)
    step = _h_proofpoint_v3(parts, pairs, url) if name == "proofpoint_v3" else _HANDLERS[name](parts, pairs)
    inner = step.get("inner")
    if inner is not None:
        inner = inner.strip()
        if not re.match(r"^[a-z][a-z0-9+.-]*://", inner, re.I):
            step["error"] = step.get("error") or "unwrapped value is not an absolute url"
            inner = None
    if step.get("redacted_override") is not None:
        wrapped_red = step["redacted_override"]
    else:
        inner_red = _redact_for_chain(inner, _depth) if inner else None
        wrapped_red = _rebuild(parts, pairs, keep=step.get("keep", ()), dest_param=step.get("dest_param"), dest_value=inner_red,
                               redact_all_others=step.get("redact_all_others", True))
        if step.get("redact_all_others") is False:
            wrapped_red = redact_url_values(wrapped_red, redact_tokens=False)[0]
    return {"wrapper": name, "wrapper_host": normalise_host(parts.hostname or ""), "inner_unredacted": inner,
            "partial": bool(step.get("partial")), "tokens": list(step.get("tokens", [])), "facts": dict(step.get("facts", {})),
            "error": step.get("error"), "wrapped_redacted": wrapped_red}


def unwrap_url(url: Any, max_depth: int = MAX_DEPTH) -> dict[str, Any]:
    """Unwrap nested rewriters (bounded at ``max_depth``, default 5) WITHOUT any network access.

    Storage-safe keys: ``input_redacted``, ``wrapped``, ``depth``, ``truncated``, ``chain`` (list of
    ``{wrapper, wrapper_host, wrapped_redacted, unwrapped_redacted, partial, tokens, facts, error}``),
    ``relations`` (``{from, to, relation: 'unwraps_to'}``), ``wrapper_hosts`` (noise), ``final_url``
    (redacted), ``final_host``, ``final_domain_only`` (Mimecast), ``recipient_tokens`` (kinds only),
    ``recipient_token_flag`` (A7: never fetch automatically), ``decoded`` (Unfurl-style),
    ``personal_pivots`` (expand=False hand-offs) and ``errors``. ``final_url_unredacted`` is set only
    when redaction changed the final URL: in-memory use for local matching, never stored.
    """
    res: dict[str, Any] = {"input_redacted": None, "wrapped": False, "depth": 0, "truncated": False, "chain": [], "relations": [],
                           "wrapper_hosts": [], "final_url": None, "final_url_unredacted": None, "final_host": None,
                           "final_domain_only": None, "recipient_tokens": [], "recipient_token_flag": False, "decoded": [],
                           "personal_pivots": [], "errors": []}
    if not isinstance(url, str) or not url.strip():
        res["errors"].append("empty input")
        return res
    current: str | None = url.strip()
    res["input_redacted"] = redact_url_values(current)[0]
    hosts: set[str] = set()
    for _ in range(max(0, int(max_depth))):
        step = unwrap_once(current)
        if step is None:
            break
        res["wrapped"] = True
        if step["wrapper_host"]:
            hosts.add(step["wrapper_host"])
        inner = step["inner_unredacted"]
        inner_red = _redact_for_chain(inner) if inner else None
        res["chain"].append({"wrapper": step["wrapper"], "wrapper_host": step["wrapper_host"], "wrapped_redacted": step["wrapped_redacted"],
                             "unwrapped_redacted": inner_red, "partial": step["partial"], "tokens": step["tokens"],
                             "facts": step["facts"], "error": step["error"]})
        for kind in step["tokens"]:
            res["recipient_tokens"].append({"wrapper": step["wrapper"], "kind": kind})
        if step["error"]:
            res["errors"].append(f"{step['wrapper']}: {step['error']}")
        if inner_red:
            res["relations"].append({"from": step["wrapped_redacted"], "to": inner_red, "relation": "unwraps_to"})
        if step["partial"]:
            res["final_domain_only"] = step["facts"].get("destination_domain")
            current = None
            break
        if inner is None:
            current = None
            break
        current = inner
    else:
        if current and match_wrapper(current):
            res["truncated"] = True
            res["errors"].append(f"nesting deeper than {max_depth} levels: stopped")
    res["depth"] = len(res["chain"])
    res["wrapper_hosts"] = sorted(hosts)
    if res["chain"]:
        res["input_redacted"] = res["chain"][0]["wrapped_redacted"]
    if current:
        red, kinds = redact_url_values(current)
        res["final_url"] = red
        if red != current:
            res["final_url_unredacted"] = current
        s = split_url(current)
        res["final_host"] = s["host"] if s else None
        for kind in kinds:
            res["recipient_tokens"].append({"wrapper": None, "kind": kind})
        res["decoded"] = decode_url_params(current)
        piv = personal_pivot_from_url(current)
        if piv:
            res["personal_pivots"].append(piv)
    elif res["final_domain_only"]:
        res["final_host"] = res["final_domain_only"]
    res["recipient_token_flag"] = any(_sensitive_kind(t["kind"]) for t in res["recipient_tokens"])
    return res


def _sensitive_kind(kind: str) -> bool:
    return kind in RECIPIENT_SENSITIVE_KINDS or kind.startswith(("recipient_param", "click_id"))


_URL_IN_TEXT = re.compile(r"(?i)\b(?:https?://|www\.|(?:wa\.me|t\.me|telegram\.me|telegram\.dog)/)[^\s<>\"'`]+")


def extract_urls(text: Any, limit: int = MAX_TEXT_URLS) -> list[str]:
    """URLs in a text blob (trailing punctuation trimmed, a Proofpoint v3 '$' terminator kept, HTML
    '&amp;' unescaped). P172 owns full IOC extraction; this is the minimal view for unwrapping."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _URL_IN_TEXT.finditer(_text(text)):
        u = m.group(0).replace("&amp;", "&")
        while u and u[-1] in ".,;:!?)]}>":
            if u[-1] == ")" and u.count("(") >= u.count(")"):
                break
            u = u[:-1]
        if not re.match(r"(?i)^https?://", u):
            u = "https://" + u
        if u not in seen:
            seen.add(u)
            out.append(u)
        if len(out) >= limit:
            break
    return out


def unwrap_text(text: Any, max_depth: int = MAX_DEPTH, limit: int = MAX_TEXT_URLS) -> list[dict[str, Any]]:
    """Extract URLs from a text blob and unwrap each (the shared helper of P085 and P172)."""
    return [unwrap_url(u, max_depth=max_depth) for u in extract_urls(text, limit=limit)]


# =============================================================================================
# Unfurl-style decoders (original implementations of public formats; nothing is fetched)
# =============================================================================================
_NOT_TIME_PARAM = re.compile(r"(?i)phone|tel|whats|celular|mobile|msisdn|cpf|cnpj|cep|zip|number|^num$|^n$")
_TIME_PARAM = re.compile(r"(?i)^(?:ust|t|ts|tm|time|timestamp|date|expires?|exp|iat|nbf|since|until|ct|created|sent|_)$|time|stamp")


def epoch_kind(value: Any, time_named: bool = False) -> tuple[str, str] | None:
    """10/13-digit Unix timestamps (s/ms) within 2000-2040 -> (kind, iso); 16/19-digit (us/ns) only
    for time-named parameters (snowflake-like ids would otherwise read as plausible dates)."""
    if not isinstance(value, str) or not value.isdigit():
        return None
    kinds = {10: ("unix_seconds", 1), 13: ("unix_ms", 1000)}
    if time_named:
        kinds.update({16: ("unix_us", 1_000_000), 19: ("unix_ns", 1_000_000_000)})
    if len(value) not in kinds:
        return None
    kind, div = kinds[len(value)]
    v = int(value) / div
    if _TS_MIN <= v <= _TS_MAX:
        return kind, _iso(_dt.datetime.fromtimestamp(v, tz=UTC)) or ""
    return None


def _snowflake_iso(value: Any, shift: int, epoch_ms: int) -> str | None:
    try:
        ms = (int(value) >> shift) + epoch_ms
    except (TypeError, ValueError):
        return None
    return _iso(_dt.datetime.fromtimestamp(ms / 1000, tz=UTC)) if _TS_MIN * 1000 <= ms <= _TS_MAX * 1000 else None


def twitter_snowflake_iso(value: Any) -> str | None:
    return _snowflake_iso(value, 22, 1288834974657)


def discord_snowflake_iso(value: Any) -> str | None:
    return _snowflake_iso(value, 22, 1420070400000)


def linkedin_id_iso(value: Any) -> str | None:
    return _snowflake_iso(value, 22, 0)


def tiktok_id_iso(value: Any) -> str | None:
    try:
        sec = int(value) >> 32
    except (TypeError, ValueError):
        return None
    return _iso(_dt.datetime.fromtimestamp(sec, tz=UTC)) if _TS_MIN <= sec <= _TS_MAX else None


def uuid_time(value: Any) -> tuple[str, str] | None:
    """UUID v1 (100-ns intervals since 1582-10-15) and v7 (Unix ms in the top 48 bits) -> (kind, iso)."""
    try:
        u = _uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None
    if u.version == 1:
        sec = (u.time - 0x01B21DD213814000) / 10_000_000
        return ("uuid_v1", _iso(_dt.datetime.fromtimestamp(sec, tz=UTC)) or "") if _TS_MIN <= sec <= _TS_MAX else None
    if u.version == 7:
        ms = u.int >> 80
        return ("uuid_v7", _iso(_dt.datetime.fromtimestamp(ms / 1000, tz=UTC)) or "") if _TS_MIN * 1000 <= ms <= _TS_MAX * 1000 else None
    return None


def decode_url_params(url: Any) -> list[dict[str, Any]]:
    """Unfurl-style decoding of one URL: ``[{where, kind, value?, iso?, redacted?}]`` for timestamps,
    .NET ticks, UUID v1/v7, Twitter/X, Discord, TikTok and LinkedIn ids, base64 text/URLs and
    embedded URLs. E-mails (plain or base64) and opaque tokens are reported as ``redacted: True``
    without a value (c5). Never fetches anything."""
    out: list[dict[str, Any]] = []
    s = split_url(url) if isinstance(url, str) else None
    if not s:
        return out
    host, path = s["host"], s["path"]
    segs = [x for x in path.split("/") if x]
    if _under(host, "twitter.com") or _under(host, "x.com"):
        for i, seg in enumerate(segs[:-1]):
            if seg == "status" and segs[i + 1].isdigit():
                ts = twitter_snowflake_iso(segs[i + 1])
                if ts:
                    out.append({"where": "path:status", "kind": "twitter_snowflake", "value": segs[i + 1], "iso": ts})
    if host.split(".")[-2:] in (["discord", "com"], ["discordapp", "com"], ["discordapp", "net"]):
        names = {"channels": ("guild", "channel", "message"), "attachments": ("channel", "attachment")}
        for i, seg in enumerate(segs):
            if seg in names:
                for label, val in zip(names[seg], segs[i + 1:]):
                    if val.isdigit():
                        ts = discord_snowflake_iso(val)
                        if ts:
                            out.append({"where": f"path:{label}", "kind": "discord_snowflake", "value": val, "iso": ts})
    if _under(host, "tiktok.com"):
        for i, seg in enumerate(segs[:-1]):
            if seg in ("video", "photo", "v") and segs[i + 1].split(".")[0].isdigit():
                val = segs[i + 1].split(".")[0]
                ts = tiktok_id_iso(val)
                if ts:
                    out.append({"where": "path:video", "kind": "tiktok_id", "value": val, "iso": ts})
    if _under(host, "linkedin.com"):
        for m in re.finditer(r"(?:activity|share|ugcPost)[:-](\d{18,20})", _unq(path + "?" + (s["query"] or ""))):
            ts = linkedin_id_iso(m.group(1))
            if ts:
                out.append({"where": "linkedin_urn", "kind": "linkedin_activity", "value": m.group(1), "iso": ts})

    def check(where: str, raw: str) -> None:
        val = _unq(raw)
        if not val:
            return
        pname = where[6:] if where.startswith("query:") else None
        found = None
        if pname is not None and not _NOT_TIME_PARAM.search(pname):
            found = epoch_kind(val, time_named=bool(_TIME_PARAM.search(pname)))
        if found:
            out.append({"where": where, "kind": found[0], "value": val, "iso": found[1],
                        "confidence": "probable" if pname is not None and _TIME_PARAM.search(pname) else "possible"})
            return
        if val.isdigit() and len(val) == 18:
            ts = _dotnet_ticks_iso(val)
            if ts:
                out.append({"where": where, "kind": "dotnet_ticks", "value": val, "iso": ts})
                return
        ut = uuid_time(val)
        if ut:
            out.append({"where": where, "kind": ut[0], "value": val, "iso": ut[1]})
            return
        if _EMAIL_STRICT.match(val) or _EMAIL_RE.search(raw):
            out.append({"where": where, "kind": "email", "redacted": True})
            return
        if re.match(r"(?i)^https?://", val):
            out.append({"where": where, "kind": "embedded_url", "value": redact_url_values(val)[0]})
            return
        b64 = _b64_text(val)
        if b64:
            if _EMAIL_RE.search(b64):
                out.append({"where": where, "kind": "base64_email", "redacted": True})
            elif re.match(r"(?i)^https?://", b64):
                out.append({"where": where, "kind": "base64_url", "value": redact_url_values(b64)[0]})
            elif len(val) >= 16:
                out.append({"where": where, "kind": "base64_text", "value": _EMAIL_RE.sub(REDACTED_EMAIL, b64)[:200]})
            return
        if _token_like(val):
            out.append({"where": where, "kind": "opaque_token", "redacted": True})

    for name, value in _qs_raw(s["query"]):
        check(f"query:{_unq(name)}", value)
    if not out or all(not o["where"].startswith("path") for o in out):
        for seg in segs:
            check("path", seg)
    return out


# =============================================================================================
# WhatsApp / Telegram hand-offs (c6)
# =============================================================================================
BR_DDD = frozenset(list(range(11, 20)) + [21, 22, 24, 27, 28, 31, 32, 33, 34, 35, 37, 38] + list(range(41, 50))
                   + [51, 53, 54, 55] + list(range(61, 70)) + [71, 73, 74, 75, 77, 79] + list(range(81, 90))
                   + list(range(91, 100)))


def normalise_phone_e164(raw: Any, default_region: str = "BR") -> dict[str, Any] | None:
    """Phone digits -> ``{'e164', 'region_assumed'}`` or None. A number with a country code is kept as
    given; a 10/11-digit Brazilian national number with a valid DDD (mobile 9xxxx / landline 2-5xxx)
    and no '+' gets +55 (BR default region, ``region_assumed`` True)."""
    if raw is None:
        return None
    s = str(raw).strip()
    had_plus = s.startswith("+")
    digits = re.sub(r"\D", "", s)
    if digits.startswith("00"):
        digits, had_plus = digits[2:], True
    if not digits or digits.startswith("0"):
        return None
    if len(digits) in (12, 13) and digits.startswith("55") and int(digits[2:4]) in BR_DDD:
        return {"e164": "+" + digits, "region_assumed": False}
    national = (len(digits) == 11 and digits[2:3] == "9") or (len(digits) == 10 and digits[2:3] in ("2", "3", "4", "5"))
    if default_region == "BR" and not had_plus and national and int(digits[:2]) in BR_DDD:
        return {"e164": "+55" + digits, "region_assumed": True}
    if 8 <= len(digits) <= 15:
        return {"e164": "+" + digits, "region_assumed": False}
    return None


_TG_RESERVED = frozenset({"share", "addstickers", "addemoji", "addtheme", "proxy", "socks", "iv", "login", "setlanguage",
                          "bg", "invoice", "boost", "contact", "confirmphone", "addlist", "m", "c", "k", "a", "z"})
_TG_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{3,31}")


def _phone_pivot(raw: str) -> dict[str, Any] | None:
    n = normalise_phone_e164(_unq(raw)) if raw else None
    return {"type": "phone", "value": n["e164"], "region_assumed": n["region_assumed"], "source": "whatsapp", "expand": False} if n else None


def personal_pivot_from_url(url: Any) -> dict[str, Any] | None:
    """wa.me/<digits>, api.whatsapp.com/send?phone=, whatsapp:// -> phone (E.164); t.me/<name>, t.me/s/<name>,
    tg://resolve -> telegram_handle; t.me/+code, t.me/joinchat/code -> telegram_invite. PERSONAL_TYPES:
    ``expand`` is always False and nothing is ever followed (c6, AR07)."""
    if not isinstance(url, str):
        return None
    u = url.strip()
    low = u.lower()
    if low.startswith("whatsapp://"):
        try:
            query = urllib.parse.urlsplit(u).query
        except ValueError:
            return None
        return _phone_pivot(_param(_qs_raw(query), "phone") or "")
    if low.startswith("tg://"):
        try:
            query = urllib.parse.urlsplit(u).query
        except ValueError:
            return None
        dom = _param(_qs_raw(query), "domain")
        if dom and _TG_NAME.fullmatch(_unq(dom)):
            return {"type": "telegram_handle", "value": "@" + _unq(dom), "source": "telegram", "expand": False}
        return None
    s = split_url(u)
    if not s:
        return None
    host = s["host"][4:] if s["host"].startswith("www.") else s["host"]
    segs = [x for x in s["path"].split("/") if x]
    if host == "wa.me" and segs and segs[0] != "message":
        return _phone_pivot(segs[0])
    if host in ("api.whatsapp.com", "web.whatsapp.com", "whatsapp.com") and s["path"].rstrip("/") == "/send":
        return _phone_pivot(_param(_qs_raw(s["query"]), "phone") or "")
    if host in ("t.me", "telegram.me", "telegram.dog") and segs:
        first = _unq(segs[0])
        if first.startswith("+") and len(first) > 6:
            return {"type": "telegram_invite", "value": "t.me/" + first, "source": "telegram", "expand": False}
        if first == "joinchat" and len(segs) > 1:
            return {"type": "telegram_invite", "value": "t.me/joinchat/" + segs[1], "source": "telegram", "expand": False}
        if first == "s" and len(segs) > 1:
            first = segs[1]
        elif first.lower() in _TG_RESERVED:
            return None
        if _TG_NAME.fullmatch(first):
            return {"type": "telegram_handle", "value": "@" + first, "source": "telegram", "expand": False}
    return None


# =============================================================================================
# the module
# =============================================================================================
PERSONAL_NOTE = "personal identifier decoded from a link hand-off: analyst selection required (never followed)"
_PIVOT_TYPES = {"phone": T.PHONE, "telegram_handle": T.TELEGRAM_HANDLE, "telegram_invite": T.TELEGRAM_INVITE}


def _step_view(step: dict[str, Any]) -> dict[str, Any]:
    """The storage-safe chain step (redacted URLs, token kinds only)."""
    return {
        "wrapper": step["wrapper"],
        "wrapper_host": step["wrapper_host"],
        "wrapped": step["wrapped_redacted"],
        "unwrapped": step["unwrapped_redacted"],
        "partial": step["partial"],
        "recipient_kinds": sorted(set(step["tokens"])),
        "facts": step["facts"],
        "error": step["error"],
    }


def storage_view(r: dict[str, Any]) -> dict[str, Any]:
    """Storage-safe view of one :func:`unwrap_url` result for ``res.raw``/attributes: redacted URLs and
    recipient kinds only (``*_unredacted`` fields are never copied; key names avoid the words the core
    sanitizer reads as secret labels). Callers (P085, P172) store this view, never the raw result."""
    return {
        "input": r["input_redacted"],
        "wrapped": r["wrapped"],
        "depth": r["depth"],
        "truncated": r["truncated"],
        "chain": [_step_view(s) for s in r["chain"]],
        "final_url": r["final_url"],
        "final_host": r["final_host"],
        "final_domain_only": r["final_domain_only"],
        "recipient_kinds": sorted({t["kind"] for t in r["recipient_tokens"]}),
        "recipient_bound": r["recipient_token_flag"],
        "decoded": r["decoded"],
        "errors": r["errors"],
    }


@register
class UrlUnwrap(Module):
    name = "url_unwrap"
    title = "URL unwrapper (SafeLinks, Proofpoint, Google, Mimecast...)"
    description = (
        "Offline unwrapping of link-protection and redirect wrappers (SafeLinks, Proofpoint v1-v3, Google /url, Mimecast, "
        "LinkedIn/Facebook/Instagram/Slack/YouTube redirectors; nested, bounded at 5) and Unfurl-style decoding of URL values; "
        "recipient identifiers are redacted and nothing is ever fetched."
    )
    category = "url_web"
    accepts = {T.URL, T.TEXT}
    produces = {T.URL, T.DOMAIN, T.PHONE, T.TELEGRAM_HANDLE, T.TELEGRAM_INVITE}
    terms = "open"  # own code, no registry source (P064: tier n/a, terms open)
    opsec = Opsec.PASSIVE
    disclosure = "none"  # strictly offline: no redirect is followed, nothing is fetched (c1/c2)
    hosts = ()
    access_model = "offline"
    tags = {"offline", "core"}
    default_enabled = True
    max_pivots = 200
    manual_link = "url_unwrap:unfurl"
    reference = "https://github.com/obsidianforensics/unfurl"
    notice = (
        "Offline only: wrappers are decoded locally and never followed. The Unfurl manual link sends the URL to dfir.blog's "
        "service when opened (shown as non-clickable text at TLP:AMBER and above)."
    )

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type is T.URL:
            return self._run_url(res, entity.value)
        return self._run_text(res, entity.value)

    # ------------------------------------------------------------------ URL input
    def _run_url(self, res: ModuleResult, url: str) -> ModuleResult:
        r = unwrap_url(url, max_depth=MAX_DEPTH)
        summary = storage_view(r)
        res.raw = {"input": summary["input"], "result": summary}
        if not r["wrapped"]:
            # not a wrapper: Unfurl-style decoding of the URL itself and a possible chat hand-off
            res.attr("url_decoded_params", r["decoded"])
            if r["recipient_token_flag"]:
                res.attr("recipient_identifiers", summary["recipient_kinds"])
            self._personal(res, r)
            if r["recipient_token_flag"]:
                self._recipient_finding(res, [summary])
            return res if res.has_data else res.mark("empty")
        self._wrapped(res, r, summary, relation="unwraps_to")
        if r["final_url"] is None and not r["final_domain_only"]:
            # a wrapper we recognise but cannot decode: never read as 'nothing behind it'
            return res.mark("error", "wrapper could not be decoded: " + ("; ".join(r["errors"]) or "no destination parameter"))
        return res

    # ------------------------------------------------------------------ text input
    def _run_text(self, res: ModuleResult, text: str) -> ModuleResult:
        results = unwrap_text(text, max_depth=MAX_DEPTH, limit=MAX_TEXT_URLS)
        kept = [r for r in results if r["wrapped"] or r["personal_pivots"]]
        summaries = [storage_view(r) for r in kept]
        res.raw = {"urls_seen": len(results), "results": summaries}
        undecoded = 0
        for r, summary in zip(kept, summaries):
            if r["wrapped"]:
                self._wrapped(res, r, summary, relation="mentions")
                if r["final_url"] is None and not r["final_domain_only"]:
                    undecoded += 1
            else:
                self._personal(res, r)
        if any(s["recipient_bound"] for s in summaries):
            self._recipient_finding(res, [s for s in summaries if s["recipient_bound"]])
        if not kept:
            return res.mark("empty")
        if undecoded and undecoded == sum(1 for r in kept if r["wrapped"]) and not res.pivots:
            return res.mark("error", f"{undecoded} wrapper(s) could not be decoded")
        return res

    # ------------------------------------------------------------------ helpers
    def _wrapped(self, res: ModuleResult, r: dict[str, Any], summary: dict[str, Any], *, relation: str) -> None:
        chains = list(res.attributes.get("unwrap_chain") or [])
        chains.append({"input": summary["input"], "depth": summary["depth"], "truncated": summary["truncated"], "steps": summary["chain"],
                       "final_url": summary["final_url"], "final_domain_only": summary["final_domain_only"]})
        res.attr("unwrap_chain", chains)
        hosts = sorted(set(res.attributes.get("wrapper_hosts") or []) | set(r["wrapper_hosts"]))
        res.attr("wrapper_hosts", hosts)
        finals = list(res.attributes.get("unwrapped_url") or [])
        if r["final_url"] and r["final_url"] not in finals:
            finals.append(r["final_url"])
        res.attr("unwrapped_url", finals)
        if r["decoded"]:
            decoded = list(res.attributes.get("url_decoded_params") or [])
            decoded.extend(d for d in r["decoded"] if d not in decoded)
            res.attr("url_decoded_params", decoded)
        kinds = sorted(set(res.attributes.get("recipient_identifiers") or []) | set(summary["recipient_kinds"]))
        if kinds:
            res.attr("recipient_identifiers", kinds)
        # A7: the destination is recipient bound only when the DESTINATION itself carries identifiers (the
        # wrapper's own recipient parameters are gone once unwrapped); it is then pivoted redacted, not expanded
        recipient_bound = any(t["wrapper"] is None and _sensitive_kind(t["kind"]) for t in r["recipient_tokens"])
        if r["final_url"]:
            note = "unwrapped offline from " + ", ".join(dict.fromkeys(s["wrapper"] for s in summary["chain"]))
            if recipient_bound:
                note += "; recipient identifiers redacted: never fetched automatically (A7)"
            res.pivot(T.URL, r["final_url"], relation, confidence=0.95, expand=not recipient_bound, note=note)
        host = r["final_host"]
        if host and not is_wrapper_host(host):
            note = "destination domain only (Mimecast hides the URL)" if r["final_domain_only"] else "host of the unwrapped destination"
            res.pivot(T.IPV4 if _is_ipv4(host) else (T.IPV6 if ":" in host else T.DOMAIN), host, "url_host", confidence=0.95, note=note)
        self._personal(res, r)
        wrappers = " > ".join(s["wrapper"] for s in summary["chain"])
        desc = f"{summary['depth']} wrapper layer(s) ({wrappers}) decoded offline; destination: "
        desc += summary["final_url"] or (f"domain {summary['final_domain_only']} (Mimecast reveals the domain only)" if summary["final_domain_only"] else "not decodable")
        if summary["truncated"]:
            desc += f". Nesting deeper than {MAX_DEPTH} levels: unwrapping stopped (the last URL is still a wrapper)."
        res.finding(
            "URL unwrapped from a link-protection wrapper",
            "info",
            desc,
            confidence="confirmed" if summary["final_url"] else "possible",
            data={"chain": summary["chain"], "wrapper_hosts": r["wrapper_hosts"], "final_url": summary["final_url"],
                  "final_domain_only": summary["final_domain_only"], "truncated": summary["truncated"], "errors": summary["errors"]},
            tags=["info"],
            key=summary["input"] or "",
        )

    @staticmethod
    def _personal(res: ModuleResult, r: dict[str, Any]) -> None:
        for piv in r["personal_pivots"]:
            etype = _PIVOT_TYPES.get(piv.get("type", ""))
            if etype is None:
                continue
            note = PERSONAL_NOTE
            if piv.get("region_assumed"):
                note += " (BR region assumed for a national number)"
            res.pivot(etype, piv["value"], "mentions", confidence=0.9, expand=False, note=note)

    @staticmethod
    def _recipient_finding(res: ModuleResult, summaries: list[dict[str, Any]]) -> None:
        kinds = sorted({k for s in summaries for k in s["recipient_kinds"]})
        res.finding(
            "Recipient identifiers in a wrapped or tracked URL (redacted)",
            "info",
            "The URL carries per-recipient identifiers (" + ", ".join(kinds) + "). They were redacted from every stored value; "
            "such URLs are never fetched automatically (A7) and should not be shared as IOCs as-is.",
            data={"kinds": kinds, "urls": [s["final_url"] or s["input"] for s in summaries][:20]},
            tags=["recipient_token", "privacy"],
        )


def _is_ipv4(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).version == 4
    except ValueError:
        return False
