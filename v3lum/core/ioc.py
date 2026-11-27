"""IOC extraction engine: the one implementation behind ``detect.extract_iocs`` and the
``ioc_extract`` module (P172, P323, P333, P217, AR24, AR18).

``extract(text)`` -> :class:`ExtractionResult` with :class:`ExtractedIOC` items (entity, span, line,
confidence, defanged, flags). Stage order (P172 cond 1):

1. **scrub** - :func:`scrub`: ``sanitize.scrub_text`` (combos and password hashes dropped, secrets
   replaced by fingerprints) plus the pattern-DB secrets it does not know and payment-card numbers
   (replaced by ``BIN6…last4``, PCI DSS); PIX BR Codes are left intact. Spans refer to this scrubbed text.
2. **decode layers** (depth <= 3, decoded output <= 2x input and <= 20 MB): quoted-printable and
   HTML entities are decoded in place (offsets are mapped back); plausible base64 blocks and
   hex-encoded ``http`` runs become decoded segments whose IOCs carry the span of the encoded block;
   percent-encoded URLs nested in other URLs are decoded inside the URL stage. Binary blocks
   (archives, executables) are never decoded, let alone decompressed.
3. **refang** - ``hxxp``, ``[.]``, ``(dot)``, ``[@]``, ``[:]``, ``[://]``, ``\\.``, fullwidth dots...
4. **span-masked extraction** - secrets (fingerprints), cards, CPF and IBAN first (masked, never
   re-read), PIX BR Codes, recipient header lines, then URLs (with the typed accounts they name:
   ``t.me/...``, ``wa.me/...``, ``discord.gg/...``, social profile URLs), e-mails (and leading-@
   fediverse handles), onions, domains outside URL/e-mail spans, IPs/CIDRs, Brazilian and
   international phones, hashes (plus TLSH and ssdeep), CVE/ATT&CK ids, checksummed crypto
   addresses, analytics ids, CNPJ, MAC, ASN and finally known malware/actor aliases.
5. **validation** - ``ipaddress``; IANA TLD + PSL; P217 checksums (an MD5-looking string is never
   BTC); ATT&CK ids against :mod:`v3lum.core.attack`; CVE years 1999..next year; bogon and private
   IPs kept but flagged; file-extension TLDs (``.zip .mov .py .sh .md``...) low confidence unless
   defanged or seen with a scheme (resolution is never attempted: extraction is offline).
6. **annotation** - noise kinds and warninglists (:mod:`v3lum.core.noise`), org-profile ownership,
   recipient-token URLs (:func:`v3lum.core.policy.recipient_token`), personal and secret types.

Privacy (P172 cond 7-10, P323 cond 5-7, AR24): CPFs never become entities (counted with a masked
``***.456.789-**`` preview in :attr:`ExtractionResult.masked`), IBANs likewise; card numbers become
``payment_card`` entities (``BIN6…last4``); secrets become ``secret``/``telegram_bot_token``
entities holding fingerprints only, reported once as 'sensitive data in pasted text'.
PERSONAL_TYPES are flagged ``personal`` and never auto-expanded. Everything here is static and
offline (no DNS, no fetch, no rendering).

Refang and URL-unwrapping ideas are adapted from ninoseki/ioc-extractor (MIT, Copyright (c) 2018
Manabu Niseki, https://github.com/ninoseki/ioc-extractor, ``src/aux/regexes.ts``) and ioc-fanger
(MIT, Floyd Hightower, https://pypi.org/project/ioc-fanger/ 5.1.1 fang patterns); notices
``v3lum/data/notices/ioc_extractor.json`` and ``ioc_fanger.json``. InQuest iocextract (GPL-2) and
ioc-finder (LGPL-3) were study material only: no code was copied (A6).

Alias index (AR18): fragments ``v3lum/data/aliases/*.json`` (schema ``'v3lum.aliases/1'``,
``{kind: 'malware_family'|'threat_actor', source, licence, names: {alias: canonical}}``) are merged
by :func:`alias_index`; :func:`alias_lookup` serves ``detect()`` and the alias stage here.
"""

from __future__ import annotations

import base64
import binascii
import bisect
import datetime as _dt
import html
import ipaddress
import json
import re
import threading
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from v3lum.core import attack as _attack
from v3lum.core import patterns as _patterns
from v3lum.core import psl
from v3lum.core import sanitize as _sanitize
from v3lum.core import validators as val
from v3lum.core.entities import (
    ELLIPSIS,
    IOC_TYPES,
    PERSONAL_TYPES,
    SECRET_TYPES,
    Entity,
    EntityType,
    mask_cpf,
    normalize_domain,
    normalize_email_headers,
    platform_for_url,
    platforms,
    url_host,
)

__all__ = [
    "ALIASES_DIR",
    "ALIASES_SCHEMA",
    "DEFAULT_LIMIT",
    "FILE_EXTENSION_TLDS",
    "FLAGS",
    "LOW_CONFIDENCE",
    "MAX_DECODE_DEPTH",
    "MAX_DECODED_CHARS",
    "NO_EXPAND_FLAGS",
    "ExtractedIOC",
    "ExtractionResult",
    "alias_errors",
    "alias_index",
    "alias_lookup",
    "extract",
    "preview_line",
    "refang_text",
    "reload_aliases",
    "scrub",
    "url_typed_entities",
]

T = EntityType

#: Default maximum number of distinct IOCs per extraction (reported when hit).
DEFAULT_LIMIT = 5000
#: Nested decode layers (base64 in base64...).
MAX_DECODE_DEPTH = 3
#: Absolute cap on decoded output (characters); the relative cap is 2x the input.
MAX_DECODED_CHARS = 20 * 1024 * 1024
DECODE_RATIO = 2
#: Input beyond this many characters is not extracted (reported in the notes).
MAX_TEXT_CHARS = 64 * 1024 * 1024
#: Below this confidence an IOC counts as low-confidence in previews (same threshold as the console).
LOW_CONFIDENCE = 0.75

#: Every flag an :class:`ExtractedIOC` can carry. The first eight are the P172 set; 'decoded',
#: 'unverified_attack_id' and 'from_url' are WP17 additions.
FLAGS: frozenset[str] = frozenset({
    "bogon", "private", "low_confidence_tld", "warninglisted", "org_domain", "recipient_token", "personal", "secret",
    "decoded", "unverified_attack_id", "from_url",
})
#: Flags that keep an IOC from being auto-expanded (listed for the analyst, never investigated
#: automatically): P172 cond 7 and 10, AR07.
NO_EXPAND_FLAGS: frozenset[str] = frozenset({
    "bogon", "private", "low_confidence_tld", "warninglisted", "org_domain", "recipient_token", "personal", "secret",
    "unverified_attack_id",
})

#: TLDs that are also common file extensions: low confidence unless defanged or seen with a scheme.
FILE_EXTENSION_TLDS: frozenset[str] = frozenset({
    "zip", "mov", "py", "sh", "md", "rs", "pl", "sc", "ps", "ms", "so", "pm", "java", "cab", "one", "app", "bat", "exe",
    "msi", "dll", "lnk", "scr", "hta", "jar", "apk", "doc", "docx", "xls", "xlsx", "pdf", "txt", "log", "csv", "json",
    "xml", "yml", "yaml", "ini", "cfg", "tmp", "bak", "iso", "img", "vbs", "js", "ts", "cs", "php", "rb", "go",
})
#: First labels that make a two-label "domain" look like code (``self.name``, ``os.path``, ``obj.id``).
_CODE_LABELS: frozenset[str] = frozenset({
    "self", "this", "obj", "os", "sys", "re", "np", "pd", "plt", "json", "math", "console", "window", "document",
    "request", "response", "req", "res", "ctx", "args", "kwargs", "config", "settings", "item", "data", "event",
    "e", "el", "err", "error", "node", "string", "str", "list", "dict", "model", "module", "result", "value",
    "target", "parent", "child", "root", "logger", "log", "main", "index", "setup", "utils", "util", "lib", "src",
    "foo", "bar", "baz", "user", "file", "path", "app", "page", "form", "field", "row", "col", "self_", "cls",
    "object", "array", "process", "location", "navigator", "element", "params", "options", "opts", "state", "props",
})
#: Hosts whose URLs name accounts/invites rather than infrastructure: their host is not listed as a
#: domain IOC (pivoting on t.me or instagram.com adds nothing).
_ACCOUNT_HOSTS: frozenset[str] = frozenset({
    "wa.me", "api.whatsapp.com", "chat.whatsapp.com", "web.whatsapp.com", "t.me", "telegram.me", "telegram.dog",
    "discord.gg", "discord.com", "discordapp.com", "bsky.app", "steamcommunity.com",
})

_HEADER_RECIPIENTS = ("to", "cc", "bcc", "delivered-to", "x-original-to", "envelope-to", "x-envelope-to", "resent-to",
                      "resent-cc", "resent-bcc", "x-forwarded-to", "apparently-to", "x-rcpt-to", "x-apparently-to")
_ARCHIVE_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b", b"7z\xbc\xaf", b"Rar!", b"MZ", b"\x7fELF", b"%PDF", b"BZh",
                  b"\xfd7zXZ", b"\xd0\xcf\x11\xe0", b"MSCF", b"\x89PNG", b"\xff\xd8\xff", b"GIF8")


# ======================================================================================
# Result types
# ======================================================================================


@dataclass(eq=False)
class ExtractedIOC:
    """One distinct indicator found in the text.

    ``span`` (start, end) and ``line`` (1-based) locate the first occurrence in the scrubbed text
    (:func:`scrub`; for a value found inside a decoded block, the span of the encoded block);
    ``confidence`` 0..1; ``defanged`` True when the text wrote it defanged (``hxxp``, ``[.]``...);
    ``flags`` from :data:`FLAGS`; ``occurrences`` counts repeats; ``source`` is 'text', 'url' (typed
    from or derived out of a URL), 'base64', 'hex', 'url_encoding' or 'headers'; ``note`` explains
    the typing ('TRON (Base58Check)', 'alias of Sofacy'...); ``noise`` names the noise kinds and
    warninglists that matched.
    """

    entity: Entity
    span: tuple[int, int]
    line: int
    confidence: float
    defanged: bool = False
    flags: frozenset[str] = frozenset()
    occurrences: int = 1
    source: str = "text"
    note: str = ""
    noise: tuple[str, ...] = ()

    @property
    def expand(self) -> bool:
        """May the engine investigate it automatically? Only IOC_TYPES without a NO_EXPAND flag."""
        return self.entity.type in IOC_TYPES and not (self.flags & NO_EXPAND_FLAGS)

    @property
    def low_confidence(self) -> bool:
        return self.confidence < LOW_CONFIDENCE or "low_confidence_tld" in self.flags

    @property
    def provenance(self) -> str:
        """'line 3, chars 120-135' (+ ', defanged' / ', from base64')."""
        out = f"line {self.line}, chars {self.span[0]}-{self.span[1]}"
        if self.defanged:
            out += ", defanged"
        if self.source in ("base64", "hex", "url_encoding"):
            out += f", from {self.source.replace('_', ' ')}"
        return out

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (the entity key holds fingerprints / masked values only for secrets)."""
        return {
            "entity": self.entity.key, "type": self.entity.type.value, "value": self.entity.value,
            "span": list(self.span), "line": self.line, "confidence": round(self.confidence, 3),
            "defanged": self.defanged, "flags": sorted(self.flags), "occurrences": self.occurrences,
            "source": self.source, "note": self.note, "noise": list(self.noise), "expand": self.expand,
        }


#: Preview groups: entity type -> (singular, plural).
_PREVIEW_GROUPS: dict[str, tuple[str, str]] = {
    "domain": ("domain", "domains"), "ipv4": ("IP", "IPs"), "ipv6": ("IP", "IPs"), "cidr": ("network", "networks"),
    "url": ("URL", "URLs"), "email": ("e-mail", "e-mails"), "md5": ("hash", "hashes"), "sha1": ("hash", "hashes"),
    "sha256": ("hash", "hashes"), "sha512": ("hash", "hashes"), "ssdeep": ("hash", "hashes"), "tlsh": ("hash", "hashes"),
    "cve": ("CVE", "CVEs"), "mitre_technique": ("ATT&CK id", "ATT&CK ids"), "phone": ("phone", "phones"),
    "btc_address": ("wallet", "wallets"), "eth_address": ("wallet", "wallets"), "xmr_address": ("wallet", "wallets"),
    "other_crypto_address": ("wallet", "wallets"), "secret": ("secret", "secrets"),
    "telegram_bot_token": ("secret", "secrets"), "payment_card": ("card", "cards"),
}


def preview_line(items: Iterable[ExtractedIOC]) -> str:
    """'37 IOCs: 12 domains, 5 IPs, 4 low-confidence' (largest groups first)."""
    items = list(items)
    groups: Counter[tuple[str, str]] = Counter()
    for item in items:
        name = item.entity.type.value
        groups[_PREVIEW_GROUPS.get(name, (name.replace("_", " "), name.replace("_", " ")))] += 1
    total = len(items)
    line = f"{total} IOC{'s' if total != 1 else ''}"
    parts = ", ".join(f"{n} {one if n == 1 else many}" for (one, many), n in groups.most_common())
    if parts:
        line += f": {parts}"
    low = sum(1 for i in items if i.low_confidence)
    if low:
        line += f", {low} low-confidence"
    return line


@dataclass
class ExtractionResult:
    """What :func:`extract` found.

    ``entities`` in reading order; ``counts`` per entity type value plus the masked kinds ('cpf',
    'iban') that never become entities; ``limit_hit`` True when the IOC limit stopped extraction;
    ``notes`` human-readable lines (the 'sensitive data in pasted text' line among them);
    ``masked`` ``{kind: {'count', 'previews'}}`` for CPF/IBAN (previews masked); ``sensitive`` the
    scrub report rows ``{'kind', 'action'}`` (no values); ``decoded`` layer -> blocks decoded.
    """

    entities: list[ExtractedIOC] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    limit_hit: bool = False
    notes: list[str] = field(default_factory=list)
    masked: dict[str, dict[str, Any]] = field(default_factory=dict)
    sensitive: list[dict[str, str]] = field(default_factory=list)
    decoded: dict[str, int] = field(default_factory=dict)
    source_type: str = "text"
    limit: int = DEFAULT_LIMIT

    def __len__(self) -> int:
        return len(self.entities)

    def __iter__(self):
        return iter(self.entities)

    @property
    def low_confidence(self) -> int:
        return sum(1 for i in self.entities if i.low_confidence)

    def preview(self) -> str:
        """The one-line preview '37 IOCs: 12 domains, 5 IPs, 4 low-confidence' (P172 cond 11)."""
        return preview_line(self.entities)

    def by_type(self) -> dict[str, list[ExtractedIOC]]:
        out: dict[str, list[ExtractedIOC]] = {}
        for item in self.entities:
            out.setdefault(item.entity.type.value, []).append(item)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "entities": [i.to_dict() for i in self.entities], "counts": dict(self.counts), "limit_hit": self.limit_hit,
            "limit": self.limit, "notes": list(self.notes), "masked": json.loads(json.dumps(self.masked)),
            "sensitive": [dict(r) for r in self.sensitive], "decoded": dict(self.decoded), "source_type": self.source_type,
            "preview": self.preview(),
        }


# ======================================================================================
# Offset maps (every rewrite keeps a way back to the scrubbed text)
# ======================================================================================


class _Map:
    """Regions a rewrite replaced: new ``[ns, ne)`` came from old ``[os, oe)`` (sorted, disjoint)."""

    __slots__ = ("ne", "ns", "oe", "os")

    def __init__(self) -> None:
        self.ns: list[int] = []
        self.ne: list[int] = []
        self.os: list[int] = []
        self.oe: list[int] = []

    def __bool__(self) -> bool:
        return bool(self.ns)

    def to_old(self, pos: int) -> int:
        i = bisect.bisect_right(self.ns, pos) - 1
        if i < 0:
            return pos
        ns, ne, os_, oe = self.ns[i], self.ne[i], self.os[i], self.oe[i]
        if pos == ns:
            return os_
        if pos < ne:
            return oe  # inside a replaced region: widen to the whole original
        return oe + (pos - ne)

    def span_to_old(self, start: int, end: int) -> tuple[int, int]:
        s = self.to_old(start)
        i = bisect.bisect_right(self.ns, end - 1) - 1 if end > 0 else -1
        if i >= 0 and self.ns[i] < end < self.ne[i]:
            e = self.oe[i]
        else:
            e = self.to_old(end)
        return s, max(s, e)

    def touches(self, start: int, end: int) -> bool:
        """Does any replaced region overlap new ``[start, end)``?"""
        j = bisect.bisect_right(self.ne, start)
        return j < len(self.ns) and self.ns[j] < end


def _rewrite(text: str, regex: re.Pattern[str], repl: Callable[[re.Match[str]], str]) -> tuple[str, _Map]:
    """``regex.sub(repl, text)`` that also returns the offset map."""
    out: list[str] = []
    mp = _Map()
    last = 0
    shift = 0
    for m in regex.finditer(text):
        s, e = m.span()
        new = repl(m)
        if new == m.group(0):
            continue
        out.append(text[last:s])
        ns = s + shift
        mp.ns.append(ns)
        mp.ne.append(ns + len(new))
        mp.os.append(s)
        mp.oe.append(e)
        out.append(new)
        shift += len(new) - (e - s)
        last = e
    if not mp:
        return text, mp
    out.append(text[last:])
    return "".join(out), mp


# ======================================================================================
# Refang (ideas from ninoseki/ioc-extractor and ioc-fanger, MIT)
# ======================================================================================

_BRACKETED = r"[\[\(\{][ \t]{0,3}(?:\.|dot|DOT|Dot|@|at|AT|At|://|:|/)[ \t]{0,3}[\]\)\}]"
#: Refang rules: each regex starts with a literal or a character class (no leading look-behind) so
#: the engine skips ahead quickly; they run separately and their hits are merged (one combined
#: alternation would test every position). Context checks a look-behind would do run in _refang_repl.
_REFANG_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("spb", re.compile(rf" {_BRACKETED} ?")),
    ("b", re.compile(_BRACKETED)),
    ("halfopen", re.compile(r"[\[\(\{]\.(?=[^\W_])")),
    ("halfclose", re.compile(r"\.[\]\)\}](?=[^\W_])")),
    ("bsdot", re.compile(r"\\\.(?=[^\W_])")),
    ("spdot", re.compile(r" \. (?=[a-z0-9])")),
    ("http", re.compile(r"[hH](?:xx|XX|Xx|xX|\*\*|\[xx\]|\[XX\])[pP](?=[sS]?(?:://|\[:|\[://|\(:|:\\\\))")),
    ("ftp", re.compile(r"[fF][xX][pP](?=[sS]?(?:://|\[:|\[://))")),
    ("backsl", re.compile(r":\\\\(?=[^\W_])")),
    ("uni", re.compile(r"[．。｡・](?=[^\W_])")),
)
_BRACKET_TO = {".": ".", "dot": ".", "@": "@", "at": "@", "://": "://", ":": ":", "/": "/"}


def _refang_repl(kind: str, raw: str, before: str) -> str:
    if kind in ("spb", "b"):
        token = raw.strip().strip("[](){}").strip().lower()
        return _BRACKET_TO.get(token, raw)
    if kind in ("halfopen", "halfclose", "bsdot", "uni"):
        return "." if before.isalnum() else raw
    if kind == "spdot":
        return "." if before.isascii() and before.isalnum() else raw
    if kind == "http":
        return "http" if not (before.isalnum() or before == "_") else raw
    if kind == "ftp":
        return "ftp" if not (before.isalnum() or before == "_") else raw
    if kind == "backsl":
        return "://" if before.isalpha() else raw
    return raw


_REFANG_HINT = re.compile(r"[\[\(\{\\．。｡・]| \. |[hH](?:xx|XX|Xx|xX|\*\*)[pP]|[fF][xX][pP]")


def _apply(text: str, edits: list[tuple[int, int, str]]) -> tuple[str, _Map]:
    """Apply sorted, non-overlapping ``(start, end, replacement)`` edits; return the offset map."""
    if not edits:
        return text, _Map()
    out: list[str] = []
    mp = _Map()
    last = 0
    shift = 0
    for s, e, new in edits:
        out.append(text[last:s])
        ns = s + shift
        mp.ns.append(ns)
        mp.ne.append(ns + len(new))
        mp.os.append(s)
        mp.oe.append(e)
        out.append(new)
        shift += len(new) - (e - s)
        last = e
    out.append(text[last:])
    return "".join(out), mp


def _refang(text: str) -> tuple[str, _Map]:
    if not _REFANG_HINT.search(text):
        return text, _Map()
    found: list[tuple[int, int, str, str]] = []
    for kind, rx in _REFANG_RULES:
        for m in rx.finditer(text):
            found.append((m.start(), -(m.end() - m.start()), kind, m.group(0)))
    found.sort()
    edits: list[tuple[int, int, str]] = []
    last = -1
    for start, neg, kind, raw in found:
        if start < last:
            continue
        new = _refang_repl(kind, raw, text[start - 1] if start > 0 else "")
        if new == raw:
            continue
        edits.append((start, start - neg, new))
        last = start - neg
    return _apply(text, edits)


def refang_text(text: str) -> str:
    """Refang free text: ``hxxps://evil[.]com`` -> ``https://evil.com``, ``a[at]b(dot)com`` -> ``a@b.com``."""
    return _refang(str(text or ""))[0]


# ======================================================================================
# Inline decoders (quoted-printable, HTML entities) and block decoders (base64, hex)
# ======================================================================================

_QP_SOFT = re.compile(r"=\r?\n")
_QP_RE = re.compile(r"=\r?\n|(?:=[0-9A-F]{2})+")
_QP_ESC = re.compile(r"=(?:3D|20|2E|40|3A|2F|0A|0D|C3|E2)")
_HTML_HINT = re.compile(r"&(?:#\d|#[xX][0-9A-Fa-f]|[A-Za-z][A-Za-z0-9]{1,31};)")
_HTML_RE = re.compile(r"&(?:#[0-9]{1,7};?|#[xX][0-9A-Fa-f]{1,6};?|[A-Za-z][A-Za-z0-9]{1,31};)")


def _qp_plausible(text: str) -> bool:
    if _QP_SOFT.search(text) and _QP_ESC.search(text):
        return True
    return len(_QP_ESC.findall(text[:200_000])) >= 3 and "=3D" in text


def _qp_repl(m: re.Match[str]) -> str:
    raw = m.group(0)
    if raw[1:2] in ("\r", "\n"):
        return ""
    try:
        return bytes.fromhex(raw.replace("=", "")).decode("utf-8", "replace")
    except ValueError:
        return raw


def _inline_decode(text: str, layers: list[str]) -> tuple[str, list[_Map]]:
    maps: list[_Map] = []
    if "=" in text and _qp_plausible(text):
        text, mp = _rewrite(text, _QP_RE, _qp_repl)
        if mp:
            maps.append(mp)
            layers.append("quoted_printable")
    if "&" in text and _HTML_HINT.search(text):
        text, mp = _rewrite(text, _HTML_RE, lambda m: html.unescape(m.group(0)))
        if mp:
            maps.append(mp)
            layers.append("html_entities")
    return text, maps


_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{20,}={0,2})(?![A-Za-z0-9+/=_-])")
_B64_MIME_RE = re.compile(r"(?m)^[A-Za-z0-9+/]{40,100}\r?\n(?:[A-Za-z0-9+/]{40,100}\r?\n){0,100000}[A-Za-z0-9+/]{0,100}={0,2}[ \t]*$")
_HEX_HTTP_RE = re.compile(r"(?<![0-9A-Fa-f])((?:68747470|66747020|667470733a|687474703a)(?:[0-9A-Fa-f]{2}){6,2048})(?![0-9A-Fa-f])")
_HEXONLY = re.compile(r"^[0-9A-Fa-f]+$")


def _printable(text: str) -> bool:
    if not text:
        return False
    bad = sum(1 for c in text if not (c.isprintable() or c in "\r\n\t"))
    return bad <= len(text) * 0.03


def _b64_candidate(run: str) -> bool:
    core = run.rstrip("=")
    if len(core) < 20 or _HEXONLY.match(core) or core.isdigit():
        return False
    if core.isalpha() and (core.islower() or core.isupper()):
        return False  # a word, not base64
    has_digit = any(c.isdigit() for c in core)
    mixed = any(c.islower() for c in core) and any(c.isupper() for c in core)
    return mixed and (has_digit or "+" in core or "/" in core or len(core) >= 24)


def _b64_decode(run: str) -> bytes | None:
    core = run.replace("\r", "").replace("\n", "").strip().rstrip("=")
    alt = b"-_" if ("-" in core or "_" in core) else None
    if alt and ("+" in core or "/" in core):
        return None
    try:
        return base64.b64decode(core + "=" * (-len(core) % 4), altchars=alt, validate=True)
    except (binascii.Error, ValueError):
        return None


# ======================================================================================
# Scrub (sanitize.scrub_text + the pattern-DB secrets and card numbers)
# ======================================================================================


@dataclass
class _Local:
    """A sensitive hit found while scrubbing (span in the scrubbed text)."""

    kind: str
    start: int
    end: int
    value: str  # masked value: 'BIN6…last4' for cards


def _brcode_spans(text: str) -> list[tuple[int, int]]:
    """Spans of valid PIX BR Codes (CRC16 checked)."""
    spans: list[tuple[int, int]] = []
    if "000201" not in text or "6304" not in text:
        return spans
    pos = 0
    for m in _PIX_START.finditer(text):
        if m.start() < pos:
            continue
        window = text[m.start(): m.start() + val.PIX_BRCODE_MAX]
        for i in re.finditer("6304", window):
            cand = window[: i.end() + 4]
            if val.pix_brcode_valid(cand):
                spans.append((m.start(), m.start() + len(cand)))
                pos = m.start() + len(cand)
                break
    return spans


def _scrub_text(text: str, report: list[dict[str, str]]) -> str:
    """``sanitize.scrub_text`` around PIX BR Codes, which it must not touch: their default txid
    '***' looks like a masked hint and would be dropped, breaking the CRC."""
    spans = _brcode_spans(text)
    if not spans:
        return _sanitize.scrub_text(text, hits=report)
    pieces: list[str] = []
    last = 0
    for s, e in spans:
        pieces.append(_sanitize.scrub_text(text[last:s], hits=report) if s > last else "")
        pieces.append(text[s:e])
        last = e
    pieces.append(_sanitize.scrub_text(text[last:], hits=report) if last < len(text) else "")
    return "".join(pieces)


def _scrub(text: str, report: list[dict[str, str]]) -> tuple[str, list[_Local]]:
    out = _scrub_text(text, report)
    if not isinstance(out, str) or not out:
        return out or "", []
    hits = [h for h in _patterns.match_patterns(out, kinds=("secret", "financial")) if h.name != "iban"]
    if not hits:
        return out, []
    pieces: list[str] = []
    local: list[_Local] = []
    last = 0
    shift = 0
    for h in hits:
        if h.start < last:
            continue
        if h.name == "payment_card" and len(re.sub(r"\D", "", h.value)) == 14 and val.cnpj_valid(re.sub(r"\D", "", h.value)):
            continue  # a 14-digit CNPJ with a Luhn-valid tail is a company id, not a card
        pieces.append(out[last:h.start])
        if h.kind == "financial":
            masked_text = h.masked  # 'BIN6…last4': no '*' run (sanitize would drop it as a masked hint)
            local.append(_Local("payment_card", h.start + shift, h.start + shift + len(masked_text), h.masked))
            report.append({"kind": "payment_card", "action": "mask", "value": h.masked})
        else:
            masked_text = h.masked  # the fingerprint
            report.append({"kind": h.name, "action": "mask", "value": h.masked})
        pieces.append(masked_text)
        shift += len(masked_text) - (h.end - h.start)
        last = h.end
    pieces.append(out[last:])
    return "".join(pieces), local


def scrub(text: str, *, hits: list[dict[str, str]] | None = None) -> str:
    """The text with credentials and card data neutralised before it is stored or extracted.

    ``sanitize.scrub_text`` (combos, password hashes, masked hints, labelled passwords dropped;
    known secrets fingerprinted) plus the P323 pattern-DB secrets ``scrub_text`` does not know
    (fingerprinted) and payment-card numbers (Luhn + brand IIN; replaced by ``BIN6…last4``, PCI DSS).
    PIX BR Codes are left intact. CPF and IBAN are left in place (masked in every output instead).
    Idempotent. ``hits`` receives one ``{'kind', 'action', 'value'}`` row per change ('value' is a
    fingerprint or ``BIN6…last4``, never the raw value).
    """
    if not isinstance(text, str) or not text:
        return text
    report: list[dict[str, str]] = []
    out, _ = _scrub(text, report)
    if hits is not None:
        hits.extend(report)
    return out


# ======================================================================================
# Alias index (AR18): v3lum/data/aliases/*.json
# ======================================================================================

ALIASES_SCHEMA = "v3lum.aliases/1"
ALIASES_DIR: Path = Path(__file__).resolve().parent.parent / "data" / "aliases"
_LEGACY_ALIAS_FILES = (("malware_families.json", T.MALWARE), ("threat_actors.json", T.THREAT_ACTOR))
_ALIAS_KINDS = {"malware_family": T.MALWARE, "threat_actor": T.THREAT_ACTOR}
_COPYLEFT = re.compile(r"(?i)\b(?:a?gpl|lgpl|by-sa|sharealike|share-alike|cc-by-nc|non-?commercial|\bnc\b)")


@dataclass
class _AliasIndex:
    names: dict[str, list[tuple[EntityType, str, str]]] = field(default_factory=dict)
    first: dict[str, list[tuple[int, str]]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    matchers: dict[str, re.Pattern[str]] = field(default_factory=dict)


_ALIAS_LOCK = threading.Lock()
_ALIASES: _AliasIndex | None = None
_ALIAS_EXTRA_DIRS: tuple[str, ...] = ()


def _add_alias(idx: _AliasIndex, alias: str, etype: EntityType, canonical: str) -> None:
    original = " ".join(str(alias).split())
    canonical = " ".join(str(canonical).split())
    if len(original) < 3 or len(original) > 64 or not canonical or len(canonical) > 200:
        return
    low = original.lower()
    hits = idx.names.setdefault(low, [])
    if any(h[0] is etype and h[1] == canonical for h in hits):
        return
    hits.append((etype, canonical, original))
    words = low.split(" ")
    entry = (len(words), low)
    bucket = idx.first.setdefault(words[0], [])
    if entry not in bucket:
        bucket.append(entry)
        bucket.sort(key=lambda x: -x[0])


def _load_alias_fragment(idx: _AliasIndex, data: Any, origin: str) -> None:
    if not isinstance(data, dict) or data.get("schema") != ALIASES_SCHEMA:
        idx.errors.append(f"{origin}: expected an object with schema {ALIASES_SCHEMA!r}")
        return
    etype = _ALIAS_KINDS.get(str(data.get("kind") or ""))
    if etype is None:
        idx.errors.append(f"{origin}: kind must be 'malware_family' or 'threat_actor'")
        return
    licence = str(data.get("licence") or data.get("license") or "")
    if not licence or not str(data.get("source") or ""):
        idx.errors.append(f"{origin}: 'source' and 'licence' are required")
        return
    if _COPYLEFT.search(licence) and not re.search(r"(?i)\bor\b", licence):
        idx.errors.append(f"{origin}: copyleft or non-commercial data cannot be bundled (A6): {licence!r}")
        return
    names = data.get("names")
    if not isinstance(names, dict):
        idx.errors.append(f"{origin}: 'names' must be an object alias -> canonical name")
        return
    for alias, canonical in names.items():
        if isinstance(alias, str) and isinstance(canonical, str):
            _add_alias(idx, alias, etype, canonical)
    for canonical in set(names.values()):  # canonical names are known names too
        if isinstance(canonical, str):
            _add_alias(idx, canonical, etype, canonical)
    idx.files.append(origin)


def _build_aliases(extra_dirs: Iterable[str]) -> _AliasIndex:
    idx = _AliasIndex()
    dirs = [ALIASES_DIR, *(Path(d) for d in extra_dirs)]
    for directory in dirs:
        if not directory.is_dir():
            continue
        for path in sorted(p for p in directory.iterdir() if p.suffix == ".json" and p.is_file()):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                idx.errors.append(f"{path.name}: unreadable aliases fragment ({type(exc).__name__})")
                continue
            _load_alias_fragment(idx, data, path.name)
    legacy_dir = ALIASES_DIR.parent
    for fname, etype in _LEGACY_ALIAS_FILES:  # pre-v2 bundled indexes ({items: [{name, aliases}]})
        path = legacy_dir / fname
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            idx.errors.append(f"{fname}: unreadable legacy alias file")
            continue
        items = data.get("items", data) if isinstance(data, dict) else data
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            for alias in [name, *(item.get("aliases") or [])] if name else []:
                _add_alias(idx, str(alias), etype, name)
    return idx


def alias_index() -> _AliasIndex:
    """The merged alias index (built once; :func:`reload_aliases` rebuilds it)."""
    global _ALIASES
    idx = _ALIASES
    if idx is not None:
        return idx
    with _ALIAS_LOCK:
        if _ALIASES is None:
            _ALIASES = _build_aliases(_ALIAS_EXTRA_DIRS)
        return _ALIASES


def reload_aliases(extra_dirs: Iterable[str | Path] = ()) -> None:
    """Re-read the alias fragments (plus ``extra_dirs``, e.g. a test's tmp directory);
    ``reload_aliases()`` restores the bundled set."""
    global _ALIASES, _ALIAS_EXTRA_DIRS
    with _ALIAS_LOCK:
        _ALIAS_EXTRA_DIRS = tuple(str(d) for d in extra_dirs)
        _ALIASES = _build_aliases(_ALIAS_EXTRA_DIRS)


def alias_errors() -> list[str]:
    """Problems found while merging alias fragments (empty for the shipped tree)."""
    return list(alias_index().errors)


def alias_lookup(name: str) -> list[tuple[EntityType, str]]:
    """``[(EntityType.MALWARE | THREAT_ACTOR, canonical name), ...]`` for a known alias
    (case-insensitive, whitespace collapsed), or ``[]``."""
    key = " ".join(str(name or "").split()).lower()
    return [(etype, canonical) for etype, canonical, _orig in alias_index().names.get(key, [])]


# ======================================================================================
# URL typing (P333 / P172 cond 6)
# ======================================================================================

_WA_PHONE = re.compile(r"^/(\d{8,15})/?$")


def _platform_hosts() -> tuple[str, ...]:
    hosts: set[str] = set()
    for plat in platforms().values():
        for pattern in plat.profile_url_patterns:
            m = re.match(r"^https?://([a-z0-9.-]+)/", pattern)
            if m:
                host = m.group(1)
                for prefix in ("www.", "m.", "mobile.", "web."):
                    if host.startswith(prefix) and host.count(".") >= 2:
                        host = host[len(prefix):]
                hosts.add(host)
    return tuple(sorted(hosts))


_SPECIAL_CACHE: dict[tuple[str, ...], re.Pattern[str]] = {}


def _platform_names() -> frozenset[str]:
    names: set[str] = set()
    for plat in platforms().values():
        names.add(plat.name)
        names.update(plat.aliases)
        names.add(plat.title.lower())
    return frozenset(names)


def _special_url_re() -> re.Pattern[str]:
    hosts = _platform_hosts()
    cached = _SPECIAL_CACHE.get(hosts)
    if cached is not None:
        return cached
    fixed = [r"wa\.me", r"api\.whatsapp\.com/send", r"chat\.whatsapp\.com", r"t\.me", r"telegram\.me", r"telegram\.dog",
             r"discord\.gg", r"discord(?:app)?\.com/invite", r"bsky\.app/profile", r"steamcommunity\.com/(?:id|profiles)"]
    alts = fixed + [re.escape(h) for h in sorted(hosts, key=len, reverse=True)]
    regex = re.compile(
        r"(?<![\w.@/:%-])(?:(?:www|m|mobile|web)\.)?(?:" + "|".join(alts) + r")(?:/|\?)[^\s<>\"'`{}|\\^]{1,1024}",
        re.I,
    )
    _SPECIAL_CACHE.clear()
    _SPECIAL_CACHE[hosts] = regex
    return regex


def url_typed_entities(url: str) -> list[tuple[Entity, str]]:
    """Typed accounts a URL names (offline, static): ``t.me/<name>`` -> telegram_handle,
    ``t.me/+<code>`` / ``t.me/joinchat/<code>`` -> telegram_invite, ``discord.gg/<code>`` ->
    discord_invite, ``wa.me/<digits>`` and ``api.whatsapp.com/send?phone=`` -> phone,
    ``bsky.app/profile/<h>`` -> bsky_handle, ``steamcommunity.com/id|profiles/..`` -> steam_profile,
    profile URLs of the merged platforms -> social_account. Returns ``[(entity, note)]``."""
    out: list[tuple[Entity, str]] = []
    raw = str(url or "").strip()
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parts = urlsplit(raw)
    except ValueError:
        return out
    host = (parts.hostname or "").lower().rstrip(".")
    for prefix in ("www.", "m.", "mobile.", "web."):
        if host.startswith(prefix) and host.count(".") >= 2:
            host = host[len(prefix):]
            break
    path = parts.path or "/"

    def add(etype: EntityType, value: str, note: str) -> None:
        ent = Entity.try_make(etype, value)
        if ent is not None and all(ent != e for e, _ in out):
            out.append((ent, note))

    if host in ("t.me", "telegram.me", "telegram.dog"):
        segs = [s for s in path.split("/") if s]
        if segs and (segs[0].startswith("+") or segs[0].lower() == "joinchat"):
            add(T.TELEGRAM_INVITE, raw, "Telegram invite link (preview only, never joined)")
        elif segs:
            add(T.TELEGRAM_HANDLE, raw, "Telegram username from a t.me link")
    elif host == "wa.me":
        m = _WA_PHONE.match(path)
        if m:
            add(T.PHONE, "+" + m.group(1), "WhatsApp number from a wa.me link")
    elif host == "api.whatsapp.com":
        m = re.search(r"(?:^|&)phone=\+?(\d{8,15})(?:&|$)", parts.query or "")
        if m:
            add(T.PHONE, "+" + m.group(1), "WhatsApp number from an api.whatsapp.com link")
    elif host in ("discord.gg", "discord.com", "discordapp.com"):
        add(T.DISCORD_INVITE, raw, "Discord invite (preview only, never joined)")
    elif host == "bsky.app":
        add(T.BSKY_HANDLE, raw, "Bluesky handle from a profile URL")
    elif host == "steamcommunity.com":
        add(T.STEAM_PROFILE, raw, "Steam profile URL")
    else:
        hit = platform_for_url(raw)
        if hit is not None:
            add(T.SOCIAL_ACCOUNT, f"{hit[0]}:{hit[1]}", f"{hit[0]} profile URL")
    return out


# ======================================================================================
# Stage regexes (all bounded and anchored on token boundaries: linear on pathological input)
# ======================================================================================

_FINGERPRINT_RE = re.compile(r"(?<![A-Za-z0-9_])([a-z][a-z0-9_]{0,31}):([A-Za-z0-9_\-+/=.*]{0,4}…[A-Za-z0-9_\-+/=.*]{0,4}):([0-9a-f]{16})(?![0-9a-f])")
_URL_RE = re.compile(
    r"(?:[hH][tT][tT][pP][sS]?|[fF][tT][pP][sS]?|[sS][fF][tT][pP]|[wW][sS][sS]?)://"
    r"(?:\[[0-9A-Fa-f:.]{2,45}\]|[^\s/?#<>\"'`\[\]{}|\\^]{1,255})"
    r"(?:[/?#][^\s<>\"'`{}|\\^]{0,4096})?"
)
_URL_BEFORE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+.-")
_NESTED_SCHEME = re.compile(r"(?:https?|ftp)(?::|%3[Aa])(?://|%2[Ff]%2[Ff])")
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+'-])([A-Za-z0-9._%+'-]{1,64})@((?:[^\W_](?:[\w-]{0,61}[^\W_])?\.){1,10}(?:[^\W\d_]{2,24}|xn--[A-Za-z0-9-]{1,59}))"
    r"(?![\w-]|\.[^\W_])"
)
_ONION_RE = re.compile(r"(?<![\w.-])((?:[a-z0-9-]{1,63}\.)?[a-z2-7]{56}\.onion)(?![\w-])", re.I)
_DOMAIN_RE = re.compile(
    r"(?<![\w.@/\\%-])((?:[^\W_](?:[\w-]{0,61}[^\W_])?\.){1,20}(?:[^\W\d_]{2,24}|xn--[A-Za-z0-9-]{1,59}))(?![\w-]|\.[^\W_])"
)
_IPV4_RE = re.compile(
    r"(?<![\w.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?:/(3[0-2]|[12]?\d)(?!\d))?(?![\w]|\.\d)"
)
_IPV6_RE = re.compile(
    r"(?<![\w:.%])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:(?<=:)(?:\d{1,3}\.){3}\d{1,3})?)(?:/(12[0-8]|1[01]\d|[1-9]?\d)(?!\d))?(?![\w:]|\.\w)"
)
_VERSION_BEFORE = re.compile(r"(?i)(?:\bversion|\bver\.?|\bv\.?|\bbuild|\brelease|\bfirmware)[ \t:]*$")
_BR_PHONE_RE = re.compile(
    r"(?<![\w+(/.,-])(?:\((\d{2})\)[ \t]?|(\d{2})([ \t.-]))(9[ \t]?\d{4}|[2-5]\d{3})([ \t.-]?)(\d{4})(?![\w-]|[.,/]\d)"
)
#: '+' then digits with single separators: one flat character class (no nested quantifiers, so a
#: long digit run backtracks at most 30 steps per '+'); the separator layout is checked in code.
_INTL_PHONE_RE = re.compile(r"(?<![\w+])\+\d[\d \t().-]{6,30}\d(?![\w-]|[.,]\d)")
_PHONE_BAD_SEP = re.compile(r"[ \t.-][ \t.-]|\(\(|\)\)|\(\)|\d\(")
_NONGEO_RE = re.compile(r"(?<![\w+])0(800|300|303|500|900)[ \t.-]?(\d{3})[ \t.-]?(\d{4})(?![\w-]|[.,]\d)")
_HEX_RUN = re.compile(r"[0-9A-Fa-f]{32,}")
_HASH_TYPES = {32: T.MD5, 40: T.SHA1, 64: T.SHA256, 128: T.SHA512}


def _word_char(c: str) -> bool:
    return c.isalnum() or c in "_$"

_TLSH_RE = re.compile(r"(T(?<![\w]T)1[0-9A-Fa-f]{70})(?![\w])")
_SSDEEP_RE = re.compile(r"(?<![\w:/+])(\d{1,10}):([A-Za-z0-9/+]{3,64}):([A-Za-z0-9/+]{3,64})(?![\w/+:])")
_CVE_RE = re.compile(r"[cC](?<![\w-][cC])[vV][eE][-_ ]?((?:19|20)\d{2})[-_ ](\d{4,7})(?![\w-])")
_ATTACK_RE = re.compile(r"(T(?<![\w.-]T)(?:\d{4}(?:\.\d{3})?|A\d{4}))(?![\w-]|\.\d)")
_MAC_RE = re.compile(r"(?<![\w:-])((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2})(?![\w:-])")
_ASN_RE = re.compile(r"(?<![\w-])(?:AS|ASN)[ ]?(\d{2,10})(?![\w-])")
_PIX_START = re.compile(r"000201")
_ALNUM_RUN = re.compile(r"[0-9A-Za-z]{25,}")
_PHONE_HINT = re.compile(r"\d{4}[ \t.-]\d{4}|\)[ \t]?9?\d{4}|\+\d")
_DOT_LETTER = re.compile(r"\.[^\W\d_]")
_DIGIT_DOT = re.compile(r"\d\.\d")
_COLON_HEX = re.compile(r":[0-9A-Fa-f]{0,4}:")
_SCHEME_SEP = re.compile(r"://")
_AT = re.compile(r"@")
_WS_RE = re.compile(r"\s")


def _windows(work: str, hint: re.Pattern[str], before: int, after: int, cap: int = 5000) -> list[tuple[int, int]]:
    """Merged regions around ``hint`` matches, widened to whitespace (or ``cap`` characters) on both
    sides, so a stage regex run with pos/endpos sees the same token boundaries as on the whole text."""
    out: list[tuple[int, int]] = []
    n = len(work)
    for m in hint.finditer(work):
        a = max(0, m.start() - before)
        b = min(n, m.end() + after)
        if out and a <= out[-1][1]:
            if b <= out[-1][1]:
                continue  # already covered: no new boundary search (linear on dense input)
            a = out[-1][0]
        else:
            lo = max(0, a - cap)
            cut = max(work.rfind(" ", lo, a), work.rfind("\n", lo, a), work.rfind("\t", lo, a))
            a = cut + 1 if cut >= 0 else lo
        ws = _WS_RE.search(work, b, min(n, b + cap))
        b = ws.start() if ws else min(n, b + cap)
        if out and a <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def _finditer(rx: re.Pattern[str], work: str, windows: list[tuple[int, int]]):
    for a, b in windows:
        yield from rx.finditer(work, a, b)
_DIGIT = re.compile(r"\d")
_CVE_HINT = re.compile(r"(?i)cve")
_TOKEN_RE = re.compile(r"\S+")
_ALIAS_CUE = re.compile(
    r"(?i)\b(?:malware|ransomware|trojan|rat|loader|stealer|infostealer|botnet|backdoor|worm|implant|spyware|wiper|dropper|"
    r"downloader|banker|keylogger|rootkit|apt|gang|family|variant|strain|c2|beacon|crypter|cryptominer|"
    r"fam[ií]lia|variante)\b"
)
#: Ordinary product, platform and tech words that are also malware/actor aliases somewhere: never
#: typed from free text (``detect()`` of the bare word still consults the index).
_ALIAS_STOPWORDS: frozenset[str] = frozenset({
    "telegram", "whatsapp", "discord", "signal", "google", "chrome", "windows", "android", "linux", "python", "java",
    "office", "outlook", "teams", "zoom", "slack", "adobe", "update", "agent", "admin", "ghost", "cobalt", "payment",
    "invoice", "august", "comet", "atom", "arena", "alien", "aurora", "phoenix", "spark", "storm", "shadow", "dragon",
    "eagle", "falcon", "tiger", "lion", "bear", "panda", "spider", "kitten", "chollima", "typhoon", "blizzard", "sleet",
    "tempest", "dust", "sandstorm", "hazel", "rain", "flood", "gust", "creepy", "spook", "nuke", "rush", "zeus",
})
_TRAIL = ".,;:!?'\")]}>*\u201d\u2019\u00bb\u3001\u3002\uff09\uff0c\uff1e"


def _trim_url(u: str) -> str:
    while u and u[-1] in _TRAIL:
        c = u[-1]
        if c == ")" and u.count("(") >= u.count(")"):
            break
        if c == "]" and u.count("[") >= u.count("]"):
            break
        u = u[:-1]
    return u


def _cve_year_ok(year: int) -> bool:
    return 1999 <= year <= _dt.datetime.now(_dt.timezone.utc).year + 1


def _ip_flags(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> frozenset[str]:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_link_local:
        return frozenset({"private"})
    if isinstance(ip, ipaddress.IPv4Address):
        if any(ip in n for n in _RFC1918):
            return frozenset({"private"})
    elif ip in _ULA:
        return frozenset({"private"})
    if not ip.is_global or ip.is_multicast:
        return frozenset({"bogon"})
    return frozenset()


_RFC1918 = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16"))
_ULA = ipaddress.ip_network("fc00::/7")


def _net_flags(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> frozenset[str]:
    flags = _ip_flags(net.network_address)
    if flags:
        return flags
    if not net.is_global:
        return frozenset({"bogon"})
    return frozenset()


# ======================================================================================
# The extraction run
# ======================================================================================


class _LimitReached(Exception):
    pass


@dataclass
class _Segment:
    text: str  # refanged, inline-decoded text the stages run on
    maps: list[_Map]  # innermost last: refang map, inline maps (to the segment's base text)
    refang: _Map
    block: tuple[int, int] | None  # span (in the scrubbed text) of the encoded block this came from
    source: str
    depth: int
    base: str = ""  # the scrubbed base text with sensitive spans blanked (block decoding reads it)


class _Run:
    def __init__(self, clean: str, *, limit: int, org: Any, own_domains: Iterable[str], aliases: bool) -> None:
        self.clean = clean
        self.limit = max(0, int(limit))
        self.org = org
        self.own_domains = tuple(d.lower().strip(".") for d in own_domains if d)
        self.aliases = aliases
        self.found: dict[str, ExtractedIOC] = {}
        self.limit_hit = False
        self.notes: list[str] = []
        self.masked: dict[str, dict[str, Any]] = {}
        self.decoded: Counter[str] = Counter()
        self.decode_budget = min(MAX_DECODED_CHARS, DECODE_RATIO * len(clean))
        self.decode_used = 0
        self.archives = 0
        self.recipients = 0
        self.sensitive: list[dict[str, str]] = []
        self.cache: dict[tuple[EntityType, str], Entity | None] = {}
        self._newlines: list[int] | None = None
        self.domains: dict[str, Entity | None] = {}
        self.platform_hosts: frozenset[str] = frozenset(_platform_hosts())
        self.clean_components: set[str] = set()  # decoded URL components the guard found clean
        self.special_re = _special_url_re()

    # ---- bookkeeping ----------------------------------------------------------------------
    def line_of(self, pos: int) -> int:
        if self._newlines is None:
            nl: list[int] = []
            find = self.clean.find
            i = find("\n")
            while i != -1:
                nl.append(i)
                i = find("\n", i + 1)
            self._newlines = nl
        return bisect.bisect_left(self._newlines, pos) + 1

    def make(self, etype: EntityType, raw: str) -> Entity | None:
        key = (etype, raw)
        if key in self.cache:
            return self.cache[key]
        ent = Entity.try_make(etype, raw)
        if len(self.cache) < 200_000:
            self.cache[key] = ent
        return ent

    def to_clean(self, seg: _Segment, start: int, end: int) -> tuple[int, int]:
        if seg.block is not None:
            return seg.block
        s, e = start, end
        for mp in reversed(seg.maps):
            if mp:
                s, e = mp.span_to_old(s, e)
        return s, e

    def add(self, seg: _Segment, entity: Entity | None, start: int, end: int, confidence: float, *,
            flags: Iterable[str] = (), source: str = "", note: str = "", defanged: bool | None = None) -> bool:
        """Record ``entity`` found at ``[start, end)`` of ``seg.text``. False when invalid."""
        if entity is None:
            return False
        key = entity.key
        if defanged is None:
            defanged = bool(seg.refang) and seg.refang.touches(start, end)
        existing = self.found.get(key)
        if existing is not None:
            existing.occurrences += 1
            if confidence > existing.confidence:
                existing.confidence = confidence
                if "low_confidence_tld" in existing.flags and "low_confidence_tld" not in set(flags):
                    existing.flags = existing.flags - {"low_confidence_tld"}
            existing.defanged = existing.defanged or defanged
            return True
        if len(self.found) >= self.limit:
            self.limit_hit = True
            raise _LimitReached
        s, e = self.to_clean(seg, start, end)
        fl = set(flags)
        if seg.source in ("base64", "hex"):
            fl.add("decoded")
        self.found[key] = ExtractedIOC(
            entity=entity, span=(s, e), line=self.line_of(s), confidence=round(min(max(confidence, 0.0), 1.0), 3),
            defanged=defanged, flags=frozenset(fl), source=source or (seg.source if seg.source != "text" else "text"), note=note,
        )
        return True

    def mask_count(self, kind: str, preview: str) -> None:
        slot = self.masked.setdefault(kind, {"count": 0, "previews": []})
        slot["count"] += 1
        if len(slot["previews"]) < 5 and preview not in slot["previews"]:
            slot["previews"].append(preview)


def _mask(text: str, spans: list[tuple[int, int]]) -> str:
    """``text`` with ``spans`` blanked (same length: offsets are kept)."""
    if not spans:
        return text
    spans.sort()
    out: list[str] = []
    last = 0
    for s, e in spans:
        if e <= last:
            continue
        s = max(s, last)
        out.append(text[last:s])
        out.append(" " * (e - s))
        last = e
    out.append(text[last:])
    return "".join(out)


# ---- stage helpers --------------------------------------------------------------------------


def _stage_sensitive(run: _Run, seg: _Segment, work: str, local: list[_Local]) -> str:
    """Secrets (fingerprints), cards, CPF and IBAN: recorded masked, their spans blanked."""
    spans: list[tuple[int, int]] = []
    if ELLIPSIS in work:
        for m in _FINGERPRINT_RE.finditer(work):
            fp = m.group(0)
            etype = T.TELEGRAM_BOT_TOKEN if m.group(1) == "telegram_bot_token" else T.SECRET
            run.add(seg, run.make(etype, fp), m.start(), m.end(), 0.95, flags=("secret",), note=m.group(1), defanged=False)
            spans.append(m.span())
    for hit in local:
        run.add(seg, run.make(T.PAYMENT_CARD, hit.value), hit.start, hit.end, 0.95, flags=("secret",),
                note="payment card (BIN6…last4; the full number is never kept)", defanged=False)
        spans.append((hit.start, hit.end))
    for h in _patterns.match_patterns(work, names=("cpf_formatted", "cpf_labelled", "iban")):
        if h.name == "iban":
            run.mask_count("iban", h.masked)
        else:
            run.mask_count("cpf", mask_cpf(h.value))
        spans.append((h.start, h.end))
    return _mask(work, spans)


def _stage_pix(run: _Run, seg: _Segment, work: str) -> str:
    spans = _brcode_spans(work)
    for s, e in spans:
        run.add(seg, run.make(T.PIX_BRCODE, work[s:e]), s, e, 0.99, flags=("personal",),
                note="PIX BR Code (CRC16 valid; handed to the PIX modules)", defanged=False)
    return _mask(work, spans)


_MSGID_LINE_RE = re.compile(r"(?im)^(?:message-id|in-reply-to|references|resent-message-id)[ \t]*:[^\n]*(?:\n[ \t]+[^\n]*)*")
_MSGID_RE = re.compile(r"<([^<>@\s]{1,256})@([A-Za-z0-9.-]{1,253})>")
_HEADER_LINE_RE = re.compile(r"(?im)^(" + "|".join(re.escape(h) for h in _HEADER_RECIPIENTS) + r")[ \t]*:[^\n]*(?:\n[ \t]+[^\n]*)*")


def _stage_headers(run: _Run, seg: _Segment, work: str) -> str:
    """E-mail header blocks: the block becomes an email_headers entity (static, never fetched) and
    recipient header lines are never listed (P333 cond 8)."""
    if ":" not in work:
        return work
    spans: list[tuple[int, int]] = []
    head = work.lstrip()
    if seg.depth == 0 and re.match(r"(?i)(?:from |received:|return-path:|delivered-to:|from:|message-id:|subject:|date:|x-[\w-]+:)", head):
        offset = len(work) - len(head)
        cut = re.search(r"\r?\n[ \t]*\r?\n", head)
        block = head[: cut.start()] if cut else head
        try:
            value = normalize_email_headers(block[:300_000])
        except ValueError:
            value = ""
        if value:
            run.add(seg, run.make(T.EMAIL_HEADERS, value), offset, offset + len(block), 0.9, flags=("personal",),
                    source="headers", note="e-mail header block (parsed statically; nothing is fetched)", defanged=False)
    for m in _HEADER_LINE_RE.finditer(work):
        if "@" in m.group(0):
            run.recipients += len(_EMAIL_RE.findall(m.group(0)))
            spans.append(m.span())
    for m in _MSGID_LINE_RE.finditer(work):  # message ids are not mailboxes: keep only their domain
        for ref in _MSGID_RE.finditer(m.group(0)):
            start = m.start() + ref.start(2)
            run.add(seg, _domain_entity(run, ref.group(2)), start, start + len(ref.group(2)), 0.6, source="headers",
                    note="domain of a Message-ID/References header")
        spans.append(m.span())
    return _mask(work, spans)


def _domain_entity(run: _Run, raw: str) -> Entity | None:
    key = raw.lower()
    if key in run.domains:
        return run.domains[key]
    ent: Entity | None = None
    try:
        d = normalize_domain(raw)
    except ValueError:
        d = ""
    if d and psl.is_known_tld(d.rsplit(".", 1)[-1]) and psl.registrable_domain(d) is not None:
        ent = run.make(T.DOMAIN, d)
    if len(run.domains) < 200_000:
        run.domains[key] = ent
    return ent


def _under(host: str, hosts: frozenset[str]) -> bool:
    """``host`` or one of its parent domains is in ``hosts``."""
    labels = host.split(".")
    return any(".".join(labels[i:]) in hosts for i in range(len(labels) - 1))


#: A URL tail worth inspecting for encoded values: a percent escape or a base64-looking run.
_URL_GUARD_HINT = re.compile(r"%[0-9A-Fa-f]{2}|[A-Za-z0-9+/_-]{20,}")
#: A decoded component worth scrubbing: a long digit run (card, CPF, IBAN), a token-like run, a
#: credential label or 'user:pass@' (anything else passes the scrubbers unchanged).
_GUARD_SUSPECT = re.compile(
    r"\d(?:[ .\-/]?\d){10,}|[A-Za-z0-9_\-+/=.:]{20,}|:[^/@\s]{0,256}@|@[^\s:/@]{1,253}:\S"
    r"|(?i:pass|senha|pwd|secret|token|key|auth|cpf|iban|BEGIN)"
)


def _b64_component(comp: str) -> str | None:
    """The printable text a base64-looking URL component decodes to (None when it is not one)."""
    if len(comp) < 20 or len(comp) > 8192 or not _b64_candidate(comp):
        return None
    raw = _b64_decode(comp)
    if not raw or raw.startswith(_ARCHIVE_MAGIC):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if _printable(text) else None


def _guard_component(run: _Run, seg: _Segment, text: str, start: int, end: int) -> str | None:
    """``text`` (a percent- or base64-decoded URL component) with secrets, card numbers, CPFs and
    IBANs blanked, or None when it holds none. Plain forms were masked before the URL stage; these
    hid behind an encoding. Hits become the same masked entities and counts as in plain text, at
    ``[start, end)`` (the URL) of the segment, and are reported as sensitive data."""
    if not _GUARD_SUSPECT.search(text) or text in run.clean_components:
        return None  # nothing card-, CPF-, token- or credential-shaped: the scrubbers would not change it
    report: list[dict[str, str]] = []
    try:
        scrubbed, local = _scrub(text, report)
    except Exception:  # noqa: BLE001 - fail closed: an unscrubbable component is treated as sensitive
        run.sensitive.append({"kind": "unscrubbable_url_component", "action": "drop"})
        return ""
    ids = _patterns.match_patterns(scrubbed, names=("cpf_formatted", "cpf_labelled", "iban"))
    if not report and not local and not ids:
        if len(run.clean_components) < 50_000:
            run.clean_components.add(text)
        return None
    spans: list[tuple[int, int]] = []
    if ELLIPSIS in scrubbed:
        for m in _FINGERPRINT_RE.finditer(scrubbed):
            etype = T.TELEGRAM_BOT_TOKEN if m.group(1) == "telegram_bot_token" else T.SECRET
            run.add(seg, run.make(etype, m.group(0)), start, end, 0.95, flags=("secret",), note=m.group(1), defanged=False)
            spans.append(m.span())
    for hit in local:
        run.add(seg, run.make(T.PAYMENT_CARD, hit.value), start, end, 0.95, flags=("secret",),
                note="payment card (BIN6…last4; the full number is never kept)", defanged=False)
        spans.append((hit.start, hit.end))
    for h in ids:
        run.mask_count("iban" if h.name == "iban" else "cpf", h.masked if h.name == "iban" else mask_cpf(h.value))
        spans.append((h.start, h.end))
    run.sensitive.extend({"kind": str(r.get("kind") or "secret"), "action": str(r.get("action") or "")} for r in report)
    return _mask(scrubbed, spans)


def _take_url(run: _Run, seg: _Segment, raw: str, start: int, *, conf: float = 0.95) -> None:
    full = raw
    tail_from = raw.find("://") + 3 if "://" in raw else 0
    nested = bool(_NESTED_SCHEME.search(raw, tail_from))
    comps = _url_components(raw[tail_from:]) if nested or _URL_GUARD_HINT.search(raw, tail_from) else []
    # A secret, card number or CPF hidden behind percent- or base64-encoding in a path segment, a
    # query value or the fragment: masked like its plain form, and the URL is cut before it (the
    # plain form's span is blanked too), so no entity value carries it (P323 cond 5-7, AR24).
    cut = len(raw)
    for i, (off, comp, layered) in enumerate(comps):
        if not layered and "://" in comp:
            continue  # an unencoded nested URL: guarded when it is taken below
        decoded = comp if layered else _b64_component(comp)
        if decoded is None:
            continue
        clean = _guard_component(run, seg, decoded, start, start + len(full))
        if clean is not None:
            cut = min(cut, tail_from + off)
            comps[i] = (off, clean if layered else "", layered)
    if cut < len(raw):
        raw = raw[:cut]
    ent = run.make(T.URL, raw)
    if ent is None:
        return
    seen = ent.key in run.found
    run.add(seg, ent, start, start + len(raw), conf)
    if seen:
        return  # host, typed accounts and nested URLs were taken at the first occurrence
    host = url_host(ent.value)
    if host:
        offset = raw.lower().find(host)
        hs, he = (start + offset, start + offset + len(host)) if offset >= 0 else (start, start + len(raw))
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None:
            run.add(seg, run.make(T.IPV4 if ip.version == 4 else T.IPV6, host), hs, he, 0.9, flags=("from_url",), source="url")
        elif host.endswith(".onion"):
            run.add(seg, run.make(T.ONION, host), hs, he, 0.95, flags=("from_url",), source="url")
        else:
            bare = host[4:] if host.startswith("www.") else host
            if bare not in _ACCOUNT_HOSTS and not _under(bare, run.platform_hosts):
                run.add(seg, _domain_entity(run, host), hs, he, 0.9, flags=("from_url",), source="url")
    for typed, note in url_typed_entities(ent.value):
        run.add(seg, typed, start, start + len(raw), 0.9, source="url", note=note)
    # URLs nested in this one (redirectors, safelinks): in a path segment, a query value or the
    # fragment, raw or percent-encoded up to 3 times (sensitive values already blanked above)
    if nested:
        for _off, component, layered in comps:
            for m in _URL_RE.finditer(component):
                inner = _trim_url(m.group(0))
                pos = full.find(inner, tail_from) if not layered else -1
                if pos >= 0:
                    _take_url(run, seg, inner, start + pos)
                    continue
                ient = run.make(T.URL, inner)
                if ient is None:
                    continue
                src = "url_encoding" if layered else "url"
                run.add(seg, ient, start, start + len(full), 0.85, source=src, note="URL nested in another URL")
                ihost = url_host(ient.value)
                try:
                    ipaddress.ip_address(ihost)
                except ValueError:
                    if ihost and not _under(ihost[4:] if ihost.startswith("www.") else ihost, run.platform_hosts | _ACCOUNT_HOSTS):
                        run.add(seg, _domain_entity(run, ihost), start, start + len(full), 0.85, flags=("from_url",), source=src)


def _unquote3(text: str) -> tuple[str, bool]:
    out, changed = text, False
    for _ in range(3):
        new = unquote(out)
        if new == out:
            break
        out, changed = new, True
    return out, changed


def _url_components(tail: str) -> list[tuple[int, str, bool]]:
    """(offset in ``tail``, component, percent-decoded?) for the path segments, query values and
    fragment of a URL tail (everything after 'scheme://'): where nested URLs and encoded values live."""
    out: list[tuple[int, str, bool]] = []
    cut = re.search(r"[?#]", tail)
    path_end = cut.start() if cut else len(tail)
    slash = tail.find("/", 0, path_end)
    if slash >= 0:
        raw_path = tail[slash + 1: path_end]
        if "://" in raw_path:
            out.append((slash + 1, raw_path, False))  # an unencoded nested URL spans several path segments
        else:
            pos = slash + 1
            for part in raw_path.split("/"):
                if part:
                    out.append((pos, *_unquote3(part)))
                pos += len(part) + 1
    if cut is None:
        return out
    frag_at = path_end
    if tail[path_end] == "?":
        hash_at = tail.find("#", path_end + 1)
        q_end = hash_at if hash_at >= 0 else len(tail)
        pos = path_end + 1
        for pair in re.split(r"[&;]", tail[path_end + 1: q_end]):
            if pair:
                key, _eq, value = pair.partition("=")
                off, comp = (pos + len(key) + 1, value) if value else (pos, pair)
                out.append((off, *_unquote3(comp)))
            pos += len(pair) + 1
        frag_at = hash_at
    if frag_at >= 0 and frag_at + 1 < len(tail):
        out.append((frag_at + 1, *_unquote3(tail[frag_at + 1:])))
    return out


def _stage_urls(run: _Run, seg: _Segment, work: str) -> str:
    spans: list[tuple[int, int]] = []
    if "://" in work:
        for m in _finditer(_URL_RE, work, _windows(work, _SCHEME_SEP, 8, 0)):
            if m.start() and work[m.start() - 1] in _URL_BEFORE:
                continue
            raw = _trim_url(m.group(0))
            if len(raw) <= raw.find("://") + 3:
                continue
            _take_url(run, seg, raw, m.start())
            spans.append((m.start(), m.start() + len(raw)))
        work = _mask(work, spans)
        spans = []
    if "/" in work:  # scheme-less account/invite/profile links: the typed account only
        for m in run.special_re.finditer(work):
            raw = _trim_url(m.group(0))
            typed = url_typed_entities(raw)
            for ent, note in typed:
                run.add(seg, ent, m.start(), m.start() + len(raw), 0.9, source="url", note=note)
            if typed:
                spans.append((m.start(), m.start() + len(raw)))
        work = _mask(work, spans)
    return work


def _stage_emails(run: _Run, seg: _Segment, work: str) -> str:
    if "@" not in work:
        return work
    spans: list[tuple[int, int]] = []
    for m in _finditer(_EMAIL_RE, work, _windows(work, _AT, 80, 260)):
        s, e = m.span()
        local, domain = m.group(1), m.group(2)
        if local.startswith(".") or local.endswith(".") or ".." in local:
            continue
        tld = domain.rsplit(".", 1)[-1]
        if not psl.is_known_tld(tld):
            continue
        if s >= 1 and work[s - 1] == "@" and (s == 1 or not (work[s - 2].isalnum() or work[s - 2] in "._%+-@")):
            ent = run.make(T.FEDIVERSE_HANDLE, "@" + m.group(0))
            if run.add(seg, ent, s - 1, e, 0.85, flags=("personal",), note="fediverse handle (@user@instance; no WebFinger lookup)"):
                spans.append((s - 1, e))
                continue
        if run.add(seg, run.make(T.EMAIL, m.group(0)), s, e, 0.9, flags=("personal",)):
            spans.append((s, e))
    return _mask(work, spans)


def _stage_onions(run: _Run, seg: _Segment, work: str) -> str:
    if ".onion" not in work.lower():
        return work
    spans: list[tuple[int, int]] = []
    for m in _ONION_RE.finditer(work):
        if run.add(seg, run.make(T.ONION, m.group(1)), m.start(), m.end(), 0.98):
            spans.append(m.span())
    return _mask(work, spans)


def _stage_domains(run: _Run, seg: _Segment, work: str) -> str:
    if "." not in work:
        return work
    spans: list[tuple[int, int]] = []
    for m in _finditer(_DOMAIN_RE, work, _windows(work, _DOT_LETTER, 256, 64)):
        raw = m.group(1)
        ent = _domain_entity(run, raw)
        if ent is None:
            continue
        s, e = m.span(1)
        defanged = bool(seg.refang) and seg.refang.touches(s, e)
        labels = raw.split(".")
        tld_raw = labels[-1]
        conf, flags, note = 0.85, [], ""
        if defanged:
            conf = 0.95
        elif tld_raw.lower() in FILE_EXTENSION_TLDS:
            conf, note = 0.3, f"'.{tld_raw.lower()}' is also a file extension: probably a file name"
            flags.append("low_confidence_tld")
        elif len(labels) == 2 and labels[0].lower() in _CODE_LABELS:
            conf, note = 0.3, "looks like a code identifier"
            flags.append("low_confidence_tld")
        elif tld_raw[:1].isupper() and not tld_raw.isupper() and labels[-2][:1].isupper() and len(labels) >= 2:
            conf, note = 0.4, "capitalised dotted name (namespace or code?)"
            flags.append("low_confidence_tld")
        if run.add(seg, ent, s, e, conf, flags=flags, note=note, defanged=defanged):
            spans.append((s, e))
    return _mask(work, spans)


def _stage_ips(run: _Run, seg: _Segment, work: str) -> str:
    spans: list[tuple[int, int]] = []
    if "." in work:
        for m in _finditer(_IPV4_RE, work, _windows(work, _DIGIT_DOT, 16, 24)):
            s, e = m.span()
            if _VERSION_BEFORE.search(work, max(0, s - 16), s):
                continue
            if m.group(2) is not None:
                try:
                    net = ipaddress.ip_network(m.group(0), strict=False)
                except ValueError:
                    continue
                ok = run.add(seg, run.make(T.CIDR, m.group(0)), s, e, 0.9, flags=_net_flags(net))
            else:
                ent = run.make(T.IPV4, m.group(1))
                if ent is None:
                    continue
                if ent.key in run.found:
                    ok = run.add(seg, ent, s, e, 0.95)
                else:
                    ok = run.add(seg, ent, s, e, 0.95, flags=_ip_flags(ipaddress.ip_address(m.group(1))))
            if ok:
                spans.append((s, e))
        work = _mask(work, spans)
        spans = []
    if ":" in work:
        for m in _finditer(_IPV6_RE, work, _windows(work, _COLON_HEX, 40, 50)):
            cand = m.group(1)
            if cand.count(":") < 2 or sum(c in "0123456789abcdefABCDEF" for c in cand) < 2:
                continue
            try:
                ip = ipaddress.IPv6Address(cand)
            except ValueError:
                continue
            s, e = m.span()
            if m.group(2) is not None:
                try:
                    net = ipaddress.ip_network(m.group(0), strict=False)
                except ValueError:
                    continue
                ok = run.add(seg, run.make(T.CIDR, m.group(0)), s, e, 0.9, flags=_net_flags(net))
            else:
                ok = run.add(seg, run.make(T.IPV6, cand), s, e, 0.95, flags=_ip_flags(ip))
            if ok:
                spans.append((s, e))
        work = _mask(work, spans)
    return work


_DDD: dict[str, str] | None = None


def _ddd() -> dict[str, str]:
    global _DDD
    if _DDD is None:
        try:
            data = json.loads((Path(__file__).resolve().parent.parent / "data" / "anatel_ddd.json").read_text(encoding="utf-8"))
            _DDD = {str(k): str(v) for k, v in (data.get("ddd") or {}).items()}
        except (OSError, ValueError, AttributeError):
            _DDD = {}
    return _DDD


def _br_number_ok(ddd: str, number: str) -> bool:
    if ddd not in _ddd():
        return False
    return (len(number) == 9 and number[0] == "9") or (len(number) == 8 and number[0] in "2345")


#: Characters a phone window reaches past its hint: longer than any phone match (an international
#: number is at most 39 characters), so a window never ends inside a number - ``finditer`` treats the
#: window end as the end of the text, and a number cut there would pass the trailing look-ahead.
_PHONE_REACH = 48


def _phone_windows(work: str) -> list[tuple[int, int]]:
    """Regions around '+d' and 'dddd[-. ]dddd' runs: the only places a phone number can be."""
    out: list[tuple[int, int]] = []
    for m in _PHONE_HINT.finditer(work):
        s, e = max(0, m.start() - 24), min(len(work), m.end() + _PHONE_REACH)
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], e)
        else:
            out.append((s, e))
    return out


def _stage_phones(run: _Run, seg: _Segment, work: str) -> str:
    windows = _phone_windows(work)
    nongeo = "0800" in work or "0300" in work or "0303" in work or "0500" in work or "0900" in work
    if not windows and not nongeo:
        return work
    spans: list[tuple[int, int]] = []
    plus = "+" in work
    for ws, we in windows:
        if plus:
            for m in _INTL_PHONE_RE.finditer(work, ws, we):
                cand = m.group(0)
                if _PHONE_BAD_SEP.search(cand) or cand.count("(") != cand.count(")"):
                    continue
                digits = re.sub(r"\D", "", cand)
                if not 8 <= len(digits) <= 15:
                    continue
                if digits.startswith("55") and len(digits) in (12, 13) and not _br_number_ok(digits[2:4], digits[4:]):
                    continue
                if run.add(seg, run.make(T.PHONE, m.group(0)), m.start(), m.end(), 0.8, flags=("personal",)):
                    spans.append(m.span())
    work = _mask(work, spans)
    spans = []
    for ws, we in windows:
        for m in _BR_PHONE_RE.finditer(work, ws, we):
            ddd = m.group(1) or m.group(2)
            number = re.sub(r"\D", "", m.group(4)) + m.group(6)
            if m.group(1) is None and not m.group(5):
                continue  # '11 987654321' without separators is too close to other digit runs
            if not _br_number_ok(ddd, number):
                continue
            if run.add(seg, run.make(T.PHONE, f"+55{ddd}{number}"), m.start(), m.end(), 0.7, flags=("personal",),
                       note=f"Brazilian number (DDD {ddd}, {_ddd().get(ddd, '')})"):
                spans.append(m.span())
    work = _mask(work, spans)
    spans = []
    if nongeo:
        for m in _NONGEO_RE.finditer(work):
            if run.add(seg, run.make(T.PHONE, m.group(0)), m.start(), m.end(), 0.7, flags=("personal",),
                       note=f"Brazilian non-geographic 0{m.group(1)} number"):
                spans.append(m.span())
        work = _mask(work, spans)
    return work


def _stage_hashes(run: _Run, seg: _Segment, work: str) -> str:
    spans: list[tuple[int, int]] = []
    if "T1" in work:
        for m in _TLSH_RE.finditer(work):
            if run.add(seg, run.make(T.TLSH, m.group(1)), m.start(), m.end(), 0.95, note="TLSH (T1 + 70 hex)"):
                spans.append(m.span())
        work = _mask(work, spans)
        spans = []
    for m in _HEX_RUN.finditer(work):
        h = m.group(0)
        etype = _HASH_TYPES.get(len(h))
        s, e = m.span()
        if etype is None or (s and _word_char(work[s - 1])) or (e < len(work) and _word_char(work[e])):
            continue
        if len(set(h.lower())) < 4 or h.isdigit():
            continue
        if run.add(seg, run.make(etype, h), s, e, 0.9):
            spans.append((s, e))
    work = _mask(work, spans)
    spans = []
    if ":" in work:
        for m in _SSDEEP_RE.finditer(work):
            bs = int(m.group(1))
            if bs < 3 or bs % 3 or (bs // 3) & (bs // 3 - 1) or len(m.group(2)) < 8:
                continue
            if run.add(seg, run.make(T.SSDEEP, m.group(0)), m.start(), m.end(), 0.9):
                spans.append(m.span())
        work = _mask(work, spans)
    return work


def _stage_cve_attack(run: _Run, seg: _Segment, work: str) -> str:
    spans: list[tuple[int, int]] = []
    if _CVE_HINT.search(work):
        for m in _CVE_RE.finditer(work):
            if not _cve_year_ok(int(m.group(1))):
                continue
            if run.add(seg, run.make(T.CVE, f"CVE-{m.group(1)}-{m.group(2)}"), m.start(), m.end(), 0.98):
                spans.append(m.span())
        work = _mask(work, spans)
        spans = []
    if "T" in work:
        for m in _ATTACK_RE.finditer(work):
            tid = m.group(1)
            if tid.startswith("TA"):
                ok = run.add(seg, run.make(T.MITRE, tid), m.start(), m.end(), 0.85, note="ATT&CK tactic id")
            else:
                tech = _attack.lookup(tid)
                if tech is not None and tech.usable:
                    ok = run.add(seg, run.make(T.MITRE, tid), m.start(), m.end(), 0.95, note=tech.name)
                elif tech is not None:
                    repl = _attack.canonical(tid)
                    ok = run.add(seg, run.make(T.MITRE, tid), m.start(), m.end(), 0.7,
                                 note=f"revoked/deprecated ATT&CK id{f' (now {repl})' if repl != tid else ''}")
                else:
                    ok = run.add(seg, run.make(T.MITRE, tid), m.start(), m.end(), 0.6, flags=("unverified_attack_id",),
                                 note="ATT&CK id not in the bundled index")
            if ok:
                spans.append(m.span())
        work = _mask(work, spans)
    return work


_CHAIN_NOTES = {"btc": "Bitcoin", "ltc": "Litecoin", "doge": "Dogecoin", "dash": "Dash", "tron": "TRON (USDT rail)", "eth": "EVM",
                "xmr": "Monero", "xrp": "XRP"}


_CRYPTO_PATTERNS: tuple[_patterns.Pattern, ...] = tuple(p for p in _patterns.PATTERNS if p.kind == "crypto" and p.emitted)
_CNPJ_HINT = re.compile(r"\d{14}|[0-9A-Z]{2}\.[0-9A-Z]{3}\.[0-9A-Z]{3}/")


def _stage_patterns(run: _Run, seg: _Segment, work: str) -> str:
    """Checksummed crypto addresses, analytics ids and CNPJ (pattern DB), then MAC and ASN."""
    spans: list[tuple[int, int]] = []
    hits: list[_patterns.PatternMatch] = []
    for m in _ALNUM_RUN.finditer(work):  # every crypto format is one alphanumeric run of 25+ characters
        token = m.group(0)
        if len(token) > 120:
            continue
        for p in _CRYPTO_PATTERNS:
            pm = p.regex.fullmatch(token)
            if pm is not None and p.check(token):
                hits.append(_patterns.PatternMatch(p.name, p.kind, m.start(), m.end(), token, token, p.confidence, p.entity_type))
                break
    hits += _patterns.match_patterns(work, kinds=("analytics",))
    if _CNPJ_HINT.search(work):
        hits += _patterns.match_patterns(work, names=("cnpj_formatted", "cnpj_bare"))
    for h in hits:
        if not h.entity_type:
            continue
        etype = EntityType(h.entity_type)
        conf, note = h.confidence, ""
        if h.kind == "crypto":
            info = val.crypto_address_info(h.value)
            if info is not None:
                conf = info.confidence
                note = f"{_CHAIN_NOTES.get(info.chain, info.chain)} {info.kind}".strip()
        elif etype is T.CNPJ:
            note = "CNPJ (valid check digits)"
        if run.add(seg, run.make(etype, h.value), h.start, h.end, conf, note=note, defanged=False):
            spans.append((h.start, h.end))
    work = _mask(work, spans)
    spans = []
    if ":" in work or "-" in work:
        for m in _MAC_RE.finditer(work):
            if run.add(seg, run.make(T.MAC, m.group(1)), m.start(), m.end(), 0.8):
                spans.append(m.span())
        work = _mask(work, spans)
        spans = []
    if "AS" in work:
        for m in _ASN_RE.finditer(work):
            if int(m.group(1)) > 4294967295:
                continue
            if run.add(seg, run.make(T.ASN, m.group(1)), m.start(), m.end(), 0.85):
                spans.append(m.span())
        work = _mask(work, spans)
    return work


_WORD_STRIP = "\"'([{<,.;:!?)]}>\u201c\u201d\u2018\u2019"


def _alias_ok(original: str, text_form: str, context: str) -> bool:
    """Free-text alias matches need a distinctive name or a CTI cue nearby (precision first)."""
    if text_form.lower() != original.lower() or original.lower() in _ALIAS_STOPWORDS:
        return False
    has_digit = any(c.isdigit() for c in original)
    letters = [c for c in original if c.isalpha()]
    if not letters:
        return False
    if original.isupper() and len(letters) >= 3:
        if not text_form.isupper():
            return False
        return has_digit or len(original) >= 5 or bool(_ALIAS_CUE.search(context))
    inner_caps = sum(1 for c in original[1:] if c.isupper())
    if " " in original:
        words = text_form.split(" ")
        if not all(w[:1].isupper() or w[:1].isdigit() for w in words):
            return False
        return len(original) >= 8 or bool(_ALIAS_CUE.search(context))
    if has_digit and len(original) >= 4 and any(c.isalpha() for c in original):
        return text_form[:1] == original[:1] or text_form.isupper()
    if inner_caps >= 1 and len(original) >= 6:
        return text_form == original or text_form.isupper()
    if len(original) < 4 or not text_form[:1].isupper():
        return False
    return bool(_ALIAS_CUE.search(context))


_ALIAS_WORD = re.compile(r"[\w$@'.-]+")
_STRIP_EDGE = "'.-"
_ALIAS_END = r"(?![\w$@-]|[.'][\w])"


def _alias_matcher(idx: _AliasIndex, first_word: str) -> re.Pattern[str]:
    rx = idx.matchers.get(first_word)
    if rx is None:
        alts = sorted((low for _n, low in idx.first[first_word]), key=len, reverse=True)
        rx = re.compile("(?:" + "|".join(re.escape(a) for a in alts) + ")" + _ALIAS_END)
        idx.matchers[first_word] = rx
    return rx


_SENTENCE_END = re.compile(r"[.!?;\n](?:\s|$)")


def _sentence(work: str, s: int, e: int, reach: int = 60) -> str:
    """The text around ``[s, e)`` within ``reach`` characters, cut at sentence boundaries."""
    lo = max(0, s - reach)
    left = work[lo:s]
    cuts = list(_SENTENCE_END.finditer(left))
    if cuts:
        lo += cuts[-1].end()
    right = work[e: e + reach]
    cut = _SENTENCE_END.search(right)
    return work[lo: e + (cut.start() if cut else len(right))]


def _stage_aliases(run: _Run, seg: _Segment, work: str) -> None:
    idx = alias_index()
    if not idx.first:
        return
    if len(work) > 4_000_000:
        run.notes.append("malware/actor alias matching ran on the first 4 MB only")
        work = work[:4_000_000]
    low = work.lower()
    first = idx.first
    names = idx.names
    platform_names = _platform_names()
    for m in _ALIAS_WORD.finditer(low):
        word = m.group(0)
        if word not in first:
            word = word.strip(_STRIP_EDGE)
            if word not in first:
                continue
        s = m.start() + (len(m.group(0)) - len(m.group(0).lstrip(_STRIP_EDGE)))
        if s and (low[s - 1].isalnum() or low[s - 1] in "_$@"):
            continue
        hit = _alias_matcher(idx, word).match(low, s)
        if hit is None:
            continue
        alias_low = hit.group(0)
        if alias_low in platform_names:
            continue
        e = hit.end()
        text_form = work[s:e]
        context = _sentence(work, s, e)
        for etype, canonical, original in names.get(alias_low, []):
            if not _alias_ok(original, text_form, context):
                continue
            note = f"known {'malware family' if etype is T.MALWARE else 'threat actor'} name" + (
                f" (alias of {canonical})" if canonical.lower() != alias_low else "")
            run.add(seg, run.make(etype, canonical), s, e, 0.8, note=note, defanged=False)


# ---- segments and decoding ------------------------------------------------------------------


def _stage_late_secrets(run: _Run, seg: _Segment, work: str) -> str:
    """Secrets, card numbers, CPFs and IBANs that only appear once QP/HTML decoding ran (blanked;
    secrets fingerprinted, cards truncated, CPF/IBAN counted masked)."""
    spans: list[tuple[int, int]] = []
    for hit in _sanitize.find_secrets(work):
        if hit.action == "mask":
            kind = hit.kind
            ent = Entity.try_make(T.TELEGRAM_BOT_TOKEN, hit.value) if kind == "telegram_bot_token" else None
            if ent is None:
                from v3lum.core.entities import secret_entity

                ent = secret_entity(kind, hit.value)
            run.add(seg, ent, hit.start, hit.end, 0.95, flags=("secret",), note=kind, defanged=False)
            run.sensitive.append({"kind": kind, "action": "mask"})
        else:
            run.sensitive.append({"kind": hit.kind, "action": "drop"})
        spans.append((hit.start, hit.end))
    work = _mask(work, spans)
    spans = []
    for h in _patterns.match_patterns(work, kinds=("secret", "financial")) + _patterns.match_patterns(
            work, names=("cpf_formatted", "cpf_labelled")):
        if h.name == "iban":
            run.mask_count("iban", h.masked)
        elif h.name.startswith("cpf"):
            run.mask_count("cpf", mask_cpf(h.value))  # a CPF written with HTML entities or QP escapes
        elif h.kind == "financial":
            run.add(seg, run.make(T.PAYMENT_CARD, h.masked), h.start, h.end, 0.95, flags=("secret",), defanged=False,
                    note="payment card (BIN6…last4; the full number is never kept)")
            run.sensitive.append({"kind": "payment_card", "action": "mask"})
        else:
            etype = T.TELEGRAM_BOT_TOKEN if h.entity_type == "telegram_bot_token" else T.SECRET
            run.add(seg, run.make(etype, h.masked), h.start, h.end, 0.95, flags=("secret",), note=h.name, defanged=False)
            run.sensitive.append({"kind": h.name, "action": "mask"})
        spans.append((h.start, h.end))
    return _mask(work, spans)


def _segment(run: _Run, base: str, local: list[_Local], *, block: tuple[int, int] | None, source: str, depth: int,
             layers: list[str]) -> _Segment:
    """Sensitive stage on the scrubbed ``base`` text, then inline decoding and refang."""
    base_seg = _Segment(base, [], _Map(), block, source, depth)
    masked = _stage_sensitive(run, base_seg, base, local)
    decoded, maps = _inline_decode(masked, layers)
    refanged, rmap = _refang(decoded)
    seg = _Segment(refanged, [*maps, rmap], rmap, block, source, depth, masked)
    if maps:
        seg.text = _stage_late_secrets(run, seg, refanged)
    return seg


def _decode_blocks(run: _Run, seg: _Segment, report: list[dict[str, str]], layers: list[str]) -> list[_Segment]:
    """Base64 / hex-http blocks of the segment's (masked) base text as new segments."""
    work = seg.base
    if seg.depth >= MAX_DECODE_DEPTH or run.decode_used >= run.decode_budget:
        return []
    out: list[_Segment] = []
    candidates: list[tuple[int, int, str, str]] = []
    seen: list[tuple[int, int]] = []
    for m in _B64_MIME_RE.finditer(work):
        candidates.append((m.start(), m.end(), m.group(0), "base64"))
        seen.append(m.span())
    for m in _B64_RE.finditer(work):
        if any(s <= m.start() < e for s, e in seen):
            continue
        candidates.append((m.start(1), m.end(1), m.group(1), "base64"))
    if "687474" in work or "667470" in work:
        for m in _HEX_HTTP_RE.finditer(work):
            candidates.append((m.start(1), m.end(1), m.group(1), "hex"))
    budget_note = "decode budget reached (decoded output is capped at 2x the input and 20 MB)"
    for start, end, run_text, kind in candidates:
        if run.decode_used >= run.decode_budget:
            if budget_note not in run.notes:
                run.notes.append(budget_note)
            break
        if kind == "base64":
            if not _b64_candidate(run_text.replace("\n", "").replace("\r", "")):
                continue
            raw = _b64_decode(run_text)
        else:
            try:
                raw = bytes.fromhex(run_text)
            except ValueError:
                raw = None
        if not raw or len(raw) < 6:
            continue
        if raw.startswith(_ARCHIVE_MAGIC):
            run.archives += 1
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        nested = seg.depth + 1 < MAX_DECODE_DEPTH and _b64_candidate(text.strip())
        if not _printable(text) or not (nested or any(c in text for c in ".:@/")):
            continue
        if run.decode_used + len(text) > run.decode_budget:  # the cap holds for the block that would cross it
            if budget_note not in run.notes:
                run.notes.append(budget_note)
            continue
        run.decode_used += len(text)
        run.decoded[kind] += 1
        clean, local = _scrub(text, report)
        block = seg.block if seg.block is not None else (start, end)
        out.append(_segment(run, clean, local, block=block, source=kind, depth=seg.depth + 1, layers=layers))
    return out


def _extract_segment(run: _Run, seg: _Segment, report: list[dict[str, str]], layers: list[str]) -> None:
    work = seg.text
    work = _stage_pix(run, seg, work)
    work = _stage_headers(run, seg, work)
    work = _stage_urls(run, seg, work)
    work = _stage_emails(run, seg, work)
    work = _stage_onions(run, seg, work)
    work = _stage_domains(run, seg, work)
    work = _stage_ips(run, seg, work)
    work = _stage_phones(run, seg, work)
    work = _stage_hashes(run, seg, work)
    work = _stage_cve_attack(run, seg, work)
    work = _stage_patterns(run, seg, work)
    if run.aliases:
        _stage_aliases(run, seg, work)
    for sub in _decode_blocks(run, seg, report, layers):
        _extract_segment(run, sub, report, layers)


# ---- annotation -------------------------------------------------------------------------------


def _own_by_list(host: str, own: tuple[str, ...]) -> bool:
    return any(host == d or host.endswith("." + d) for d in own)


def _annotate(run: _Run, items: list[ExtractedIOC]) -> None:
    try:
        from v3lum.core import noise as _noise
    except Exception:  # noqa: BLE001 - annotation is best effort
        _noise = None  # type: ignore[assignment]
    recipient: Callable[[str, Any], bool] | None
    try:
        from v3lum.core.policy import recipient_token as recipient
    except Exception:  # noqa: BLE001
        recipient = None
    for item in items:
        ent = item.entity
        flags = set(item.flags)
        etype = ent.type
        if etype in PERSONAL_TYPES:
            flags.add("personal")
        if etype in SECRET_TYPES:
            flags.add("secret")
        if etype in (T.DOMAIN, T.URL, T.EMAIL, T.IPV4, T.IPV6, T.CIDR) and _noise is not None:
            try:
                kinds = set(_noise.noise_kinds(ent)) - {"private"}
                lists = _noise.warninglists(ent)
            except Exception:  # noqa: BLE001
                kinds, lists = set(), []
            if kinds or lists:
                flags.add("warninglisted")
                item.noise = tuple(sorted(kinds)) + tuple(lists)
        if run.org is not None and etype in (T.DOMAIN, T.URL, T.EMAIL, T.IPV4, T.IPV6, T.CIDR, T.ASN):
            try:
                if run.org.owns(ent).own:
                    flags.add("org_domain")
            except Exception:  # noqa: BLE001
                pass
        if run.own_domains and etype in (T.DOMAIN, T.URL, T.EMAIL):
            host = ent.value.rsplit("@", 1)[-1] if etype is T.EMAIL else (url_host(ent.value) if etype is T.URL else ent.value)
            if _own_by_list(host, run.own_domains):
                flags.add("org_domain")
        if etype is T.URL and recipient is not None:
            try:
                if recipient(ent.value, run.org):
                    flags.add("recipient_token")
            except Exception:  # noqa: BLE001
                pass
        item.flags = frozenset(flags)


# ---- the public entry point -------------------------------------------------------------------


def extract(
    text: str,
    *,
    limit: int = DEFAULT_LIMIT,
    source_type: str = "text",
    org: Any = None,
    own_domains: Iterable[str] = (),
    aliases: bool = True,
    annotate: bool = True,
) -> ExtractionResult:
    """Extract indicators from ``text`` (static and offline; never raises on odd input).

    ``limit`` caps distinct IOCs (``limit_hit`` and a note when reached); ``source_type`` ('text',
    'file', 'email', 'html'...) is recorded; ``org`` (an :class:`~v3lum.core.orgprofile.OrgProfile`)
    flags own assets 'org_domain' and recipient-token URLs; ``own_domains`` adds domains treated
    the same way (e.g. the sender's own domain); ``aliases`` enables the malware/actor alias stage;
    ``annotate`` adds noise/warninglist/org/recipient flags (skip it for raw counts).
    """
    result = ExtractionResult(source_type=str(source_type or "text"), limit=int(limit))
    if not isinstance(text, str) or not text.strip():
        return result
    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS]
        result.notes.append(f"only the first {MAX_TEXT_CHARS // (1024 * 1024)} MB of the text were extracted")
    report: list[dict[str, str]] = []
    try:
        clean, local = _scrub(text, report)
    except Exception as exc:  # noqa: BLE001 - fail closed: nothing is extracted from unscrubbed text
        result.notes.append(f"extraction skipped: the text could not be scrubbed ({type(exc).__name__})")
        return result
    run = _Run(clean, limit=limit, org=org, own_domains=own_domains, aliases=aliases)
    layers: list[str] = []
    try:
        seg = _segment(run, clean, local, block=None, source="text", depth=0, layers=layers)
        _extract_segment(run, seg, report, layers)
    except _LimitReached:
        pass
    items = sorted(run.found.values(), key=lambda i: (i.span[0], -(i.span[1] - i.span[0])))
    if annotate:
        _annotate(run, items)
    result.entities = items
    counts: Counter[str] = Counter(i.entity.type.value for i in items)
    for kind, slot in run.masked.items():
        counts[kind] += int(slot["count"])
    result.counts = dict(counts)
    result.limit_hit = run.limit_hit
    result.masked = run.masked
    report = [*report, *run.sensitive]
    result.sensitive = [{"kind": str(r.get("kind") or "secret"), "action": str(r.get("action") or "")} for r in report]
    for layer in layers:
        run.decoded[layer] += 1
    result.decoded = dict(run.decoded)
    notes = result.notes
    if report:
        kinds = Counter(str(r.get("kind") or "secret") for r in report)
        detail = ", ".join(f"{n} {k.replace('_', ' ')}" for k, n in sorted(kinds.items()))
        notes.append(f"sensitive data in pasted text: {detail} removed or masked (never investigated or sent)")
    if "cpf" in run.masked:
        notes.append(f"CPF found in the text: {run.masked['cpf']['count']} (masked, never an entity, never investigated)")
    if "iban" in run.masked:
        notes.append(f"IBAN found in the text: {run.masked['iban']['count']} (masked, never an entity)")
    if run.recipients:
        notes.append(f"{run.recipients} recipient address(es) in e-mail header lines were not listed (P333 cond 8)")
    if run.archives:
        notes.append(f"{run.archives} encoded binary/archive block(s) were not decoded or decompressed")
    notes.extend(n for n in run.notes if n not in notes)
    if run.limit_hit:
        notes.append(f"IOC limit reached: only the first {run.limit} distinct indicators were extracted")
    return result
