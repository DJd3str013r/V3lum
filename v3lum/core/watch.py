"""Watch mode (P030, A14): ``v3lum watch`` - a foreground, bounded brand/domain watch over the org profile.

``v3lum watch`` is a separate command, never part of a scan, and runs in the foreground only (``--once``
for cron/systemd timers, ``--max-runtime`` (default 8 h), ``--max-alerts``); there is no daemon or service
management. Everything here is local except two kinds of traffic:

* **Phase 1 - polling** (:meth:`Watcher.poll_cycle`): every ``watch_interval`` seconds the registered
  modules tagged ``watch_source`` (CT deltas for org domains such as crt.sh / Cert Spotter, NRD feeds,
  P357's Telegram channel watch...) run as normal PASSIVE module runs through the policy gate
  (``policy.make_context(..., path='watch')`` + ``policy.decide``) on the rule entities: the org's own
  domains and its brand keywords. A brand keyword is only ever handed to a source with disclosure
  ``none``/``internal``: keywords never leave the machine. Sources report candidate names in the attribute
  ``watch_hits`` (``{name, registrable_domain, serial, cert_sha256, issuer, not_before, source}``);
  first_seen diffing is persisted in the case DB (``watch_first_seen``, AR04 migration).
* **CertStream** (optional extra ``v3lum[watch]``, package ``websocket-client``): a WebSocket consumer of
  setting ``certstream_url`` (a self-hosted certstream-server-go first - disclosure 'internal' when it
  is in the org's network -, otherwise the community-tier best-effort ``wss://certstream.calidog.io/``,
  provider fragment ``certstream.json``). The consumer sends nothing (filtering is local): a keyword /
  permutation prefilter runs before a bounded queue (drop and count), dedupe uses an LRU, reconnects use
  exponential backoff with jitter and a maximum reconnect rate, and memory is capped (message size,
  queue items and bytes, LRU size). Without the extra the consumer is reported unavailable - never an
  error. Direct RFC 6962 / static-ct-api log polling is not implemented (BACKLOG).

Rules (:func:`rules_from_profile`) come only from the org profile's brands, domains, CNPJ roots, card
BINs and suppliers (plus the IOC types each rule applies to); executives and anything that looks like a
natural person (names of opted-in executives, e-mail addresses, phone numbers, @handles) never become a
rule - the only address rule is the domain-wide 'own addresses' rule of verified own domains
(infostealer exposure). Matching (:class:`Matcher`) is local after IDNA->Unicode, accent folding,
homoglyph folding and the typosquat permutation set (:func:`permutations`: omission, repetition,
transposition, homoglyph, TLD swap, hyphenation). A hit name that is no host name, http(s) URL or
address at a verified own domain (a third-party e-mail address, a phone number, CPF-like digits, a
bare IP, free text) is dropped before anything is recorded (``WatchReport.rejected``).

Alerts (:class:`Alert`) fire only for NEW registrable domains (first_seen per rule), deduplicated by
registrable domain + certificate serial: one terminal line each with the reason it matched (above 200
alerts per hour one summary line replaces the rest), a JSONL record in ``~/.v3lum/watch/alerts-<date>.jsonl``
(0600) and an ``alerts`` row linked to the day's watch case (``watch-YYYYMMDD``: the alerts are its
correlations, so ``v3lum watch vote`` / P325 votes give per-rule precision and the A10 purge and legal
hold apply). Certificate metadata only. Mutes exist per rule and per registrable domain
(``watch_mutes``). Hits only enqueue capped passive enrichment through the policy gate (setting
``watch_enrich_per_hour``, default 30; the rest is listed for the analyst); watch never makes automatic
LIGHT/ACTIVE contact. :meth:`Watcher.prune` (run at start) drops alert files, alert rows, first_seen
rows and watch cases older than ``retention_days`` (rows linked to held cases are kept). TLP: the watch
TLP (``--tlp``, default setting ``tlp`` = AMBER) marks every alert, gates every polling source and the
enrichment scans, and gates the CertStream endpoint by its disclosure/tier ceiling.

Public API: :class:`Watcher`, :class:`WatchRule`, :class:`Alert`, :func:`rules_from_profile`,
:func:`permutations`, :func:`health`; helpers :class:`Matcher`, :class:`CertStreamConsumer`,
:class:`WebSocketTransport`, :func:`parse_certstream`, :func:`certstream_endpoint`,
:func:`certstream_available`, :func:`mute`, :func:`unmute`, :func:`mutes`, :func:`recent_alerts`,
:func:`vote_alert`.
"""

from __future__ import annotations

import base64
import binascii
import collections
import dataclasses
import datetime as _dt
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import ssl
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from v3lum import paths
from v3lum.core import psl
from v3lum.core import tlp as _tlp
from v3lum.core.clock import SYSTEM_CLOCK, Clock
from v3lum.core.entities import Entity, EntityType
from v3lum.core.orgprofile import fold as _fold

log = logging.getLogger("v3lum.watch")

__all__ = [
    "ALERTS_PER_HOUR_LINES",
    "BACKOFF_BASE",
    "BACKOFF_CAP",
    "CERTSTREAM_PROVIDER",
    "DEFAULT_ENRICH_PER_HOUR",
    "DEFAULT_INTERVAL",
    "DEFAULT_MAX_RUNTIME",
    "LRU_SIZE",
    "MAX_RECONNECTS_PER_WINDOW",
    "MESSAGE_MAX_BYTES",
    "MIN_INTERVAL",
    "PUBLIC_CERTSTREAM_URL",
    "QUEUE_MAX_BYTES",
    "QUEUE_MAX_ITEMS",
    "RECONNECT_WINDOW",
    "TECHNIQUES",
    "Alert",
    "CertEvent",
    "CertStreamConsumer",
    "Match",
    "Matcher",
    "NameMatch",
    "StreamStats",
    "WatchReport",
    "WatchRule",
    "Watcher",
    "WebSocketTransport",
    "certstream_available",
    "certstream_endpoint",
    "health",
    "mute",
    "mutes",
    "parse_certstream",
    "permutations",
    "recent_alerts",
    "rules_from_profile",
    "unmute",
    "vote_alert",
    "watch_case_id",
]

# ======================================================================================
# constants
# ======================================================================================

#: Above this many alerts in one clock hour, one summary line replaces the remaining terminal lines.
ALERTS_PER_HOUR_LINES = 200
#: Default of setting watch_enrich_per_hour (capped passive enrichments per hour).
DEFAULT_ENRICH_PER_HOUR = 30
#: Default of setting watch_interval (seconds between polling cycles) and its floor.
DEFAULT_INTERVAL = 3600
MIN_INTERVAL = 300
#: Default of setting watch_max_runtime (8 h) and the absolute ceiling of a foreground run (30 days).
DEFAULT_MAX_RUNTIME = 8 * 3600
MAX_RUNTIME_CAP = 30 * 24 * 3600
#: Provider fragment id of the CertStream endpoints and the public community instance.
CERTSTREAM_PROVIDER = "certstream"
PUBLIC_CERTSTREAM_URL = "wss://certstream.calidog.io/"
PUBLIC_CERTSTREAM_HOST = "certstream.calidog.io"

#: CertStream bounds (P030 cond 6): message size, queue items and bytes, names per certificate.
MESSAGE_MAX_BYTES = 1024 * 1024
QUEUE_MAX_ITEMS = 5000
QUEUE_MAX_BYTES = 4 * 1024 * 1024
NAMES_PER_CERT = 200
#: Entries of the in-memory (registrable domain, serial) dedupe LRU.
LRU_SIZE = 50_000
#: Reconnect policy: exponential backoff with jitter (seconds), healthy-connection reset, and the
#: maximum reconnect rate (connections per rolling window).
BACKOFF_BASE = 1.0
BACKOFF_CAP = 300.0
HEALTHY_AFTER = 60.0
RECONNECT_WINDOW = 3600.0
MAX_RECONNECTS_PER_WINDOW = 30
CONNECT_TIMEOUT = 15.0
READ_TIMEOUT = 1.0
IDLE_TIMEOUT = 120.0
#: Main-loop tick while the stream is consumed (seconds).
TICK = 0.5

#: Hits read per polling-source run; permutations per name.
MAX_HITS_PER_RUN = 1000
PERMUTATION_LIMIT = 5000
#: Terms shorter than this match only as a whole token (a label or a '-'/'_' part), never as a substring.
SUBSTRING_MIN = 4
MIN_TERM = 3
#: Labels/keywords shorter than this get no cross-TLD label permutations (only same-suffix and TLD-swap
#: permutations of own domains): 'acme' -> 'acne' everywhere would flood the analyst.
LABEL_PERM_MIN = 5
#: Correlations and entity nodes kept in the day's watch case JSON (every alert stays in the alerts
#: table and the JSONL file; the nodes feed the cross-case sightings index).
CASE_ALERTS_MAX = 2000
CASE_ENTITIES_MAX = 500
#: While the stream runs, the day's watch case is rewritten at most this often (seconds); alert rows,
#: first_seen rows and JSONL lines are written as they happen (rows in batches of ROW_FLUSH).
CASE_FLUSH_INTERVAL = 60.0
ROW_FLUSH = 200
#: Remaining runtime below which no enrichment scan starts (seconds).
ENRICH_MIN_REMAINING = 30.0
#: Domains listed for the analyst (not enriched) kept by name in one report; the rest are counted.
ENRICH_LISTED_MAX = 1000
#: While the stream runs, mutes added by `v3lum watch mute` in another terminal apply within this
#: many seconds (they are re-read from the case DB).
MUTE_RELOAD = 60.0
#: Backoff step a refused handshake (HTTP 403/429/5xx) jumps to at least: 2**6 s nominal, so a
#: provider that refuses or throttles us is never hammered (its limits are respected).
REFUSED_BACKOFF_ATTEMPT = 6
#: Ransomware victim feeds and the key a watch source over them must require (P030 cond 9, A14:
#: ransomware victim watch only with the ransomware.live PRO key; a feed mapped to None is never a
#: watch source).
VICTIM_FEED_KEYS: dict[str, str | None] = {"ransomware_live": "ransomwarelive", "ransomlook": None, "ransomfeed": None}

#: Permutation techniques (``permutations``) and the reasons of a match.
TECHNIQUES: tuple[str, ...] = ("omission", "repetition", "transposition", "homoglyph", "tld_swap", "hyphenation")
#: TLDs used by the TLD-swap permutation.
TLD_SWAPS: tuple[str, ...] = (
    "com", "net", "org", "info", "biz", "co", "io", "app", "online", "site", "store", "shop", "xyz", "top", "live",
    "click", "link", "vip", "cloud", "me", "tech", "support", "services", "br", "com.br", "net.br", "org.br", "app.br",
)
#: IOC types each rule kind applies to (A14 'plus IOC types').
RULE_IOC_TYPES: dict[str, tuple[str, ...]] = {
    "brand": ("domain", "url"),
    "domain": ("domain", "url"),
    "supplier": ("domain", "url"),
    "cnpj_root": ("cnpj",),
    "card_bin": ("card_bin",),
    "own_addresses": ("email",),
}
_KIND_ORDER = {"domain": 0, "brand": 1, "supplier": 2, "own_addresses": 3, "cnpj_root": 4, "card_bin": 5}
_CRIT_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_REASON_ORDER = {"permutation": 0, "keyword": 1, "homoglyph": 2, "address": 3, "source": 4}

# ======================================================================================
# folding
# ======================================================================================

#: Confusable characters folded for matching (Cyrillic/Greek look-alikes, digits, ligatures).
_CONFUSABLES = str.maketrans({
    "0": "o", "1": "l", "i": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "l", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "ο": "o", "α": "a", "ν": "v", "ι": "l", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ε": "e",
    "ɑ": "a", "ɡ": "g", "ı": "l", "ł": "l", "ø": "o", "đ": "d", "ħ": "h", "ŀ": "l", "ß": "ss", "æ": "ae", "œ": "oe",
})
_SEQUENCES = (("rn", "m"), ("vv", "w"), ("cl", "d"))
#: Single-character look-alikes used by the homoglyph permutation.
_GLYPHS: dict[str, tuple[str, ...]] = {
    "a": ("4", "à", "á", "а"), "b": ("8", "d"), "c": ("e", "с"), "d": ("cl", "b"), "e": ("3", "é", "е"),
    "g": ("q", "9"), "h": ("lh",), "i": ("1", "l", "í", "і"), "k": ("lk",), "l": ("1", "i"), "m": ("rn", "nn"),
    "n": ("m", "r"), "o": ("0", "ó", "о"), "p": ("р",), "q": ("g",), "s": ("5",), "t": ("7",),
    "u": ("v", "ú"), "v": ("u",), "w": ("vv",), "y": ("у",), "z": ("2",),
}
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
#: A real top-level label: letters only, or an IDN TLD (never digits: '123.456.789-09' is a CPF and
#: '203.0.113.5' an address, not host names).
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩﻿]")
_TOKEN_SPLIT = re.compile(r"[.\-_]+")


def _unicode_label(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            return label
    return label


def _ascii_label(label: str) -> str | None:
    """The IDNA (punycode) form of one label, or None when it cannot be encoded."""
    if not label:
        return None
    if label.isascii():
        text = label.lower()
    else:
        try:
            text = label.encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError):
            return None
    return text if _LABEL_RE.match(text) else None


def _to_ascii(name: str) -> str | None:
    """The IDNA form of a dotted name (None when a label cannot be encoded)."""
    labels = [lb for lb in str(name or "").strip().lower().rstrip(".").split(".")]
    if not labels or any(not lb for lb in labels):
        return None
    out = []
    for lb in labels:
        enc = _ascii_label(lb)
        if enc is None:
            return None
        out.append(enc)
    return ".".join(out)


def _unicode_name(name: str) -> str:
    return ".".join(_unicode_label(lb) for lb in str(name or "").split("."))


def _hostname_ok(ascii_name: str) -> bool:
    """An IDNA host name with at least two labels and a real top-level label (see ``_TLD_RE``)."""
    return "." in ascii_name and bool(_TLD_RE.match(ascii_name.rsplit(".", 1)[1]))


def _valid_host(host: str) -> bool:
    text = str(host or "").strip().lower().rstrip(".").strip("[]")
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        pass
    ascii_name = _to_ascii(text)
    return bool(ascii_name) and _hostname_ok(ascii_name or "")


def _display_url(url: Any) -> str:
    """A URL for terminal/doctor output: no user info, query or fragment (a self-hosted endpoint's
    credentials or token never reach a screen, a log or a report)."""
    text = str(url or "").strip()
    try:
        parts = urlsplit(text)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return _clean(text.split("?", 1)[0].split("#", 1)[0].rpartition("@")[2], 160)
    if not parts.scheme or not host:
        return _clean(text.split("?", 1)[0].split("#", 1)[0].rpartition("@")[2], 160)
    netloc = (f"[{host}]" if ":" in host else host) + (f":{port}" if port else "")
    return _clean(f"{parts.scheme}://{netloc}{parts.path}" + ("?..." if parts.query else ""), 160)


def _hit_kind(name: Any) -> tuple[str, str, str]:
    """``(kind, name, host)`` of a watch-hit / certificate name: kind 'domain' (a host name with a real
    TLD, wildcards allowed), 'url' (http/https with a valid host; user info removed - credentials are
    never kept) or 'email' (an address with a valid domain); ``('', '', '')`` for anything else (phone
    numbers, CPF/CNPJ-like digits, bare IPs, free text): such values are never watched (A14)."""
    text = _clean(name, 2048).strip()
    if not text or any(ch.isspace() for ch in text):
        return "", "", ""
    low = text.lower()
    scheme = re.match(r"^([a-z][a-z0-9+.-]*)://", low)
    if scheme is not None or ("/" in text and "@" not in text.split("/", 1)[0]):
        candidate = text if scheme is not None else f"http://{text}"
        if scheme is not None and scheme.group(1) not in ("http", "https"):
            return "", "", ""
        try:
            parts = urlsplit(candidate)
            host = (parts.hostname or "").rstrip(".")
            port = parts.port
        except ValueError:
            return "", "", ""
        if not host or not _valid_host(host):
            return "", "", ""
        if parts.username is not None or parts.password is not None:  # only with an explicit scheme
            netloc = (f"[{host}]" if ":" in host else host) + (f":{port}" if port else "")
            text = parts._replace(netloc=netloc).geturl()
        return "url", text, host.lower()
    if "@" in text:
        local, _, dom = text.rpartition("@")
        ascii_dom = _to_ascii(dom)
        if not local or "@" in local or not ascii_dom or not _hostname_ok(ascii_dom):
            return "", "", ""
        return "email", text, ascii_dom
    bare = low
    while bare.startswith("*."):
        bare = bare[2:]
    ascii_name = _to_ascii(bare)
    if not ascii_name or not _hostname_ok(ascii_name):
        return "", "", ""
    return "domain", text, ascii_name


def fold_name(text: Any) -> str:
    """Comparison form: IDNA labels decoded to Unicode, accents removed, lower-case (no homoglyphs)."""
    return _fold(_unicode_name(str(text or "").strip().lower()))


def skeleton(text: Any) -> str:
    """:func:`fold_name` plus homoglyph folding (0->o, 1/i->l, rn->m, Cyrillic/Greek look-alikes)."""
    out = fold_name(text).translate(_CONFUSABLES)
    for seq, repl in _SEQUENCES:
        out = out.replace(seq, repl)
    return out


def _clean(value: Any, limit: int = 300) -> str:
    text = _CTRL_RE.sub("", str(value if value is not None else ""))
    return text[:limit]


def _iso(moment: _dt.datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=_dt.timezone.utc)
    return moment.astimezone(_dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_iso(text: Any) -> _dt.datetime | None:
    if not text:
        return None
    try:
        value = _dt.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=_dt.timezone.utc)


# ======================================================================================
# permutations (local generator; P012 modules may supply richer sets later)
# ======================================================================================


def _split_registrable(name: str) -> tuple[str, str] | None:
    """(registrable label in Unicode, public suffix) of an ASCII/IDN domain; None when it has none."""
    ascii_name = _to_ascii(name)
    if not ascii_name or "." not in ascii_name:
        return None
    reg = psl.registrable_domain(ascii_name)
    if not reg:
        return None
    suffix = psl.public_suffix(reg)
    label = reg[: -len(suffix) - 1] if suffix and reg.endswith("." + suffix) else reg.split(".")[0]
    return _unicode_label(label), suffix


def permutations(name: str, *, tlds: Iterable[str] | None = None, limit: int = PERMUTATION_LIMIT) -> dict[str, str]:
    """Typosquat permutations of a domain or a bare brand label -> the technique that produced each.

    ``name`` is a domain (``'acme.com.br'``: the registrable label is permuted and the public suffix kept,
    plus TLD swaps over ``tlds`` (default :data:`TLD_SWAPS`)) or a bare label / keyword (``'acme'``,
    spaces and underscores removed: labels only, no TLD swap). Techniques: omission, repetition,
    transposition, homoglyph (ASCII and Cyrillic look-alikes; IDN results in punycode), tld_swap and
    hyphenation (:data:`TECHNIQUES`). Results are IDNA (ASCII) names, never the input itself, at most
    ``limit`` entries; invalid labels are skipped. Local only: nothing is sent anywhere.
    """
    raw = str(name or "").strip().lower().rstrip(".")
    if not raw:
        return {}
    split = _split_registrable(raw) if "." in raw else None
    if split is not None:
        label, suffix = split
    else:
        label, suffix = re.sub(r"[\s_]+", "", fold_name(raw)), ""
        if "." in label:
            return {}
    if not label:
        return {}
    base_label = _ascii_label(label)
    base = f"{base_label}.{suffix}" if suffix and base_label else (base_label or "")
    out: dict[str, str] = {}

    def add(candidate: str, technique: str) -> None:
        if len(out) >= limit:
            return
        lb = candidate.strip("-")
        if not lb or lb == label or len(lb) < 2:
            return
        enc = _ascii_label(lb)
        if enc is None:
            return
        full = f"{enc}.{suffix}" if suffix else enc
        if full != base and full not in out:
            out[full] = technique

    for i in range(len(label)):
        add(label[:i] + label[i + 1 :], "omission")
    for i, ch in enumerate(label):
        if ch != "-":
            add(label[:i] + ch + label[i:], "repetition")
    for i in range(len(label) - 1):
        if label[i] != label[i + 1]:
            add(label[:i] + label[i + 1] + label[i] + label[i + 2 :], "transposition")
    for i, ch in enumerate(label):
        for glyph in _GLYPHS.get(ch, ()):
            add(label[:i] + glyph + label[i + 1 :], "homoglyph")
    for i in range(1, len(label)):
        if label[i - 1] != "-" and label[i] != "-":
            add(label[:i] + "-" + label[i:], "hyphenation")
    if suffix and base_label:
        for tld in tlds if tlds is not None else TLD_SWAPS:
            tld = str(tld or "").strip(".").lower()
            if not tld or tld == suffix:
                continue
            candidate = f"{base_label}.{tld}"
            if len(out) < limit and candidate not in out and candidate != base:
                out[candidate] = "tld_swap"
    return out


# ======================================================================================
# rules
# ======================================================================================


@dataclass(frozen=True)
class WatchRule:
    """One watch rule derived from the org profile (never from a natural person).

    ``id`` is readable and stable (``'brand:acme'``, ``'domain:acme.com.br'``, ``'supplier:<slug>'``,
    ``'cnpj_root:12345678'``, ``'card_bin:412345'``, ``'own_addresses:acme.com.br'``) - mutes and votes use
    it. ``terms`` are folded keywords matched locally; ``domains`` the registrable domains the rule
    protects (never alerted themselves); ``permutations`` maps typosquat names (domains for domain/supplier
    rules, labels for brand keywords) to their technique; ``ioc_types`` the observation types the rule
    applies to (:data:`RULE_IOC_TYPES`); ``keyword`` the brand keyword (original spelling) used as the
    polling entity of brand rules.
    """

    id: str
    kind: str
    label: str
    terms: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    ioc_types: tuple[str, ...] = ()
    criticality: str = "medium"
    keyword: str = ""
    permutations: Mapping[str, str] = field(default_factory=dict, compare=False, repr=False)

    @property
    def entities(self) -> tuple[Entity, ...]:
        """Polling entities of the rule (A14: org domains and brand keywords only)."""
        if self.kind == "domain":
            return tuple(Entity.make(EntityType.DOMAIN, d) for d in self.domains)
        if self.kind == "brand" and self.keyword:
            try:
                return (Entity.make(EntityType.KEYWORD, self.keyword),)
            except ValueError:
                return ()
        return ()

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe view (``watch rules``; permutations counted, not listed)."""
        return {
            "id": self.id, "kind": self.kind, "label": self.label, "terms": list(self.terms), "domains": list(self.domains),
            "ioc_types": list(self.ioc_types), "criticality": self.criticality, "permutations": len(self.permutations),
        }


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^\+?[\d\s().\-]{7,}$")
_HANDLE_RE = re.compile(r"^@[\w.]{2,}$")
_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slug(text: str) -> str:
    return _SLUG_RE.sub("-", fold_name(text)).strip("-")[:48] or hashlib.sha256(str(text).encode()).hexdigest()[:8]


def _person_like(term: str, people: frozenset[str]) -> str:
    """Why ``term`` would target a natural person ('' when it does not)."""
    text = str(term or "").strip()
    folded = " ".join(fold_name(text).split())
    if "@" in text and (_EMAIL_RE.match(text) or _HANDLE_RE.match(text)):
        return "an e-mail address or @handle"
    if _PHONE_RE.match(text) and sum(ch.isdigit() for ch in text) >= 7:
        return "a phone number"
    # also the compact form: a domain label or keyword such as 'joanaexemplo' / 'joana-exemplo' is the
    # executive 'Joana Exemplo' (a full name of 8+ letters, so short given names never drop a brand)
    compact = re.sub(r"[\s.\-_]+", "", folded)
    for p in people:
        cp = p.replace(" ", "")
        if folded == p or compact == cp or (len(p) >= 5 and p in folded) or (" " in p and len(cp) >= 8 and cp in compact):
            return "the name of a person (executive entry)"
    return ""


def _term_ok(term: str) -> bool:
    return len(term.replace(" ", "")) >= MIN_TERM


def _field(obj: Any, name: str, default: Any = None) -> Any:
    return obj.get(name, default) if isinstance(obj, Mapping) else getattr(obj, name, default)


def _items(org: Any, name: str) -> list[Any]:
    value = org.get(name) if isinstance(org, Mapping) else getattr(org, name, None)
    return list(value or [])


def rules_from_profile(org: Any, *, problems: list[str] | None = None) -> list[WatchRule]:
    """The watch rules of an org profile (:class:`v3lum.core.orgprofile.OrgProfile` or the same keys as a
    mapping) - A14 / P030 cond 2.

    One rule per brand (keyword + variants), own domain (registrable domain: its label as a term and its
    typosquat permutations), supplier (brands, domains, permutations), CNPJ root and own card BIN, plus a
    domain-wide ``own_addresses`` rule per txt_verified/attested domain (infostealer exposure, the only
    address rule). Executives never produce a rule, and a term that looks like a natural person (an
    opted-in executive's name, an e-mail address, a phone number, an @handle) is dropped with a note in
    ``problems``. Terms shorter than 3 characters are dropped. Sorted by kind, criticality and id.
    """
    notes = problems if problems is not None else []
    if org is None:
        return []
    people = frozenset(" ".join(fold_name(_field(e, "name", "")).split()) for e in _items(org, "executives") if _field(e, "name", ""))
    people = frozenset(p for p in people if p)
    rules: dict[str, WatchRule] = {}

    def add(rule: WatchRule) -> None:
        if rule.id not in rules:
            rules[rule.id] = rule

    def terms_of(values: Iterable[Any], where: str) -> list[str]:
        out: list[str] = []
        for raw in values:
            text = str(raw or "").strip()
            if not text:
                continue
            why = _person_like(text, people)
            if why:
                notes.append(f"{where}: a term was dropped - {why} is never a watch rule (natural persons are not watched)")
                continue
            folded = " ".join(fold_name(text).split())
            if not _term_ok(folded):
                notes.append(f"{where}: a term shorter than {MIN_TERM} characters was dropped")
                continue
            if folded not in out:
                out.append(folded)
        return out

    own: list[tuple[str, Any]] = []
    for i, entry in enumerate(_items(org, "domains")):
        name = _field(entry, "name") if not isinstance(entry, str) else entry
        ascii_name = _to_ascii(str(name or ""))
        reg = psl.registrable_domain(ascii_name) if ascii_name else None
        if not reg:
            notes.append(f"domains[{i}]: not a registrable domain (no rule)")
            continue
        own.append((reg, entry))
    for reg, entry in own:
        crit = str(_field(entry, "criticality", "medium") or "medium") if not isinstance(entry, str) else "medium"
        split = _split_registrable(reg)
        label = fold_name(split[0]) if split else reg.split(".")[0]
        if _person_like(label, people):
            # the domain stays protected (never alerted) and polled, but its label - a person's name -
            # never becomes a keyword or a permutation set (A14: natural persons are not watched)
            notes.append(f"domain:{reg}: its label is the name of a person (executive entry) - no keyword or permutation rule")
            add(WatchRule(f"domain:{reg}", "domain", reg, (), (reg,), RULE_IOC_TYPES["domain"], crit, "", {}))
        else:
            terms = [label] if _term_ok(label) else []
            perms = permutations(reg)
            if split and len(split[0]) >= LABEL_PERM_MIN:  # cross-TLD label permutations only for longer labels (noise)
                perms.update({k: v for k, v in permutations(split[0], tlds=()).items() if k not in perms and len(k) >= SUBSTRING_MIN})
            add(WatchRule(f"domain:{reg}", "domain", reg, tuple(terms), (reg,), RULE_IOC_TYPES["domain"], crit, "", perms))
        verified = False if isinstance(entry, str) else bool(
            _field(entry, "verified", False) or str(_field(entry, "verification", "") or "") in ("txt_verified", "attested")
        )
        if verified:
            add(WatchRule(f"own_addresses:{reg}", "own_addresses", f"addresses @{reg} (infostealer exposure)", (), (reg,),
                          RULE_IOC_TYPES["own_addresses"], crit))
    own_regs = tuple(sorted({reg for reg, _ in own}))
    for i, entry in enumerate(_items(org, "brands")):
        keyword = entry if isinstance(entry, str) else (_field(entry, "keyword") or _field(entry, "name") or "")
        variants = () if isinstance(entry, str) else tuple(_field(entry, "variants", ()) or ())
        crit = "medium" if isinstance(entry, str) else str(_field(entry, "criticality", "medium") or "medium")
        terms = terms_of([keyword, *variants], f"brands[{i}]")
        if not terms:
            continue
        perms: dict[str, str] = {}
        for term in terms:
            compact = re.sub(r"[\s_]+", "", term)
            if len(compact) >= LABEL_PERM_MIN:
                for k, v in permutations(compact).items():
                    if len(k) >= SUBSTRING_MIN:
                        perms.setdefault(k, v)
        keyword_text = str(keyword).strip() if not _person_like(str(keyword), people) else terms[0]
        add(WatchRule(f"brand:{_slug(terms[0])}", "brand", terms[0], tuple(terms), own_regs, RULE_IOC_TYPES["brand"], crit,
                      keyword_text, perms))
    for i, entry in enumerate(_items(org, "suppliers")):
        name = str(_field(entry, "name", "") or "").strip()
        if not name:
            continue
        sdomains: list[str] = []
        for raw in _field(entry, "domains", ()) or ():
            ascii_name = _to_ascii(str(raw or ""))
            reg = psl.registrable_domain(ascii_name) if ascii_name else None
            if reg and reg not in sdomains:
                sdomains.append(reg)
        terms = terms_of(_field(entry, "brands", ()) or (), f"suppliers[{i}].brands")
        perms = {}
        for reg in sdomains:
            split = _split_registrable(reg)
            label = fold_name(split[0]) if split else ""
            if label and _person_like(label, people):
                notes.append(f"suppliers[{i}]: the label of {reg} is the name of a person (executive entry) - protected only, never a keyword")
                continue
            if _term_ok(label) and label not in terms:
                terms.append(label)
            for k, v in permutations(reg).items():
                perms.setdefault(k, v)
        if not terms and not sdomains:
            continue
        add(WatchRule(f"supplier:{_slug(name)}", "supplier", name, tuple(terms), tuple(sdomains), RULE_IOC_TYPES["supplier"], "medium", "", perms))
    for root in _items(org, "cnpj_roots"):
        text = re.sub(r"[^0-9A-Za-z]", "", str(root or "")).upper()[:8]
        if len(text) == 8:
            add(WatchRule(f"cnpj_root:{text}", "cnpj_root", text, (text.lower(),), (), RULE_IOC_TYPES["cnpj_root"]))
    for value in _items(org, "card_bins"):
        digits = re.sub(r"[\s-]", "", str(value or ""))
        if digits.isdigit() and 6 <= len(digits) <= 8:
            add(WatchRule(f"card_bin:{digits}", "card_bin", digits, (digits,), (), RULE_IOC_TYPES["card_bin"]))
    return sorted(rules.values(), key=lambda r: (_KIND_ORDER.get(r.kind, 9), _CRIT_ORDER.get(r.criticality, 9), r.id))


# ======================================================================================
# matching
# ======================================================================================


@dataclass(frozen=True)
class Match:
    """One rule matching a name: ``reason`` (one line, why), ``kind`` (permutation | keyword | homoglyph |
    address | source), ``technique`` (permutation technique or '')."""

    rule: WatchRule
    reason: str
    kind: str
    technique: str = ""


@dataclass(frozen=True)
class NameMatch:
    """The outcome of :meth:`Matcher.match` for one name."""

    name: str
    registrable_domain: str
    matches: tuple[Match, ...] = ()
    #: the rule whose own/supplier domain this is ('' when none): such names never alert
    protected_by: str = ""


@dataclass(frozen=True)
class _Prepared:
    ascii: str
    registrable: str
    owner_folded: str
    owner_skeleton: str
    reg_label: str


class Matcher:
    """Local matcher over the rules that apply to domains (IDNA->Unicode, accents, homoglyphs, permutations).

    ``prefilter(name)`` is the cheap check the CertStream reader runs before queueing (keyword substrings,
    homoglyph skeletons, permutation labels, IDN names); ``match(name)`` the full decision.
    """

    def __init__(self, rules: Iterable[WatchRule]) -> None:
        self.rules = tuple(r for r in rules if "domain" in r.ioc_types)
        self._protected: dict[str, str] = {}
        self._domain_perms: dict[str, list[tuple[WatchRule, str, str]]] = {}
        self._label_perms: dict[str, list[tuple[WatchRule, str, str]]] = {}
        self._terms: list[tuple[str, str, WatchRule]] = []
        for rule in self.rules:
            for reg in rule.domains if rule.kind != "brand" else ():
                self._protected.setdefault(reg, rule.id)
            for term in rule.terms:
                compact = term.replace(" ", "")
                self._terms.append((compact, skeleton(compact), rule))
            for name, technique in rule.permutations.items():
                if "." in name:
                    base = rule.domains[0] if rule.domains else rule.label
                    self._domain_perms.setdefault(name, []).append((rule, technique, base))
                else:
                    self._label_perms.setdefault(name, []).append((rule, technique, rule.label))
        for rule in rules:
            if rule.kind == "brand":
                for reg in rule.domains:
                    self._protected.setdefault(reg, f"domain:{reg}")
        self._ascii_terms = tuple(sorted({t for t, _s, _r in self._terms if t.isascii()}))
        self._skeleton_terms = tuple(sorted({s for _t, s, _r in self._terms if s}))
        self._perm_labels = frozenset(n.split(".")[0] for n in self._domain_perms) | frozenset(self._label_perms)

    @property
    def empty(self) -> bool:
        return not self.rules

    # -- prefilter -----------------------------------------------------------------------
    def prefilter(self, name: Any) -> bool:
        """Cheap pre-queue check: could ``name`` match any rule? (False positives allowed, no false
        negatives for the matcher's rules.)"""
        text = str(name or "").lower()
        if not text or not self.rules:
            return False
        if "xn--" in text or not text.isascii():
            return True
        flat = text.replace("-", "").replace("_", "")
        for term in self._ascii_terms:
            if term in text or term in flat:
                return True
        if any(lb in self._perm_labels for lb in text.split(".")):
            return True
        for form in (text, flat):
            skel = form.translate(_CONFUSABLES)
            for seq, repl in _SEQUENCES:
                skel = skel.replace(seq, repl)
            if any(term in skel for term in self._skeleton_terms):
                return True
        return False

    # -- full match ----------------------------------------------------------------------
    @staticmethod
    def _prepare(name: Any) -> _Prepared | None:
        text = str(name or "").strip().lower().rstrip(".")
        while text.startswith("*."):
            text = text[2:]
        if not text or len(text) > 253 or any(ch in text for ch in " /:@\\"):
            return None
        ascii_name = _to_ascii(text)
        if not ascii_name or not _hostname_ok(ascii_name):
            return None
        reg = psl.registrable_domain(ascii_name)
        if not reg:
            return None
        suffix = psl.public_suffix(ascii_name)
        owner = ascii_name[: -len(suffix) - 1] if suffix and ascii_name.endswith("." + suffix) else ascii_name
        folded = fold_name(owner)
        return _Prepared(ascii_name, reg, folded, skeleton(owner), reg[: -len(psl.public_suffix(reg)) - 1] if "." in reg else reg)

    def match(self, name: Any) -> NameMatch | None:
        """Every rule matching ``name`` (best first), or None when ``name`` is not a domain name."""
        prep = self._prepare(name)
        if prep is None:
            return None
        protected = self._protected.get(prep.registrable, "")
        if protected:
            return NameMatch(prep.ascii, prep.registrable, (), protected)
        found: dict[str, Match] = {}

        def put(m: Match) -> None:
            old = found.get(m.rule.id)
            if old is None or _REASON_ORDER[m.kind] < _REASON_ORDER[old.kind]:
                found[m.rule.id] = m

        for rule, technique, base in self._domain_perms.get(prep.registrable, ()):
            put(Match(rule, f"typosquat of {base} ({technique})", "permutation", technique))
        for rule, technique, base in self._label_perms.get(prep.reg_label, ()):
            put(Match(rule, f"typosquat of '{base}' ({technique})", "permutation", technique))
        tokens = set(_TOKEN_SPLIT.split(prep.owner_folded))
        skel_tokens = set(_TOKEN_SPLIT.split(prep.owner_skeleton))
        compact = prep.owner_folded.replace("-", "").replace("_", "")
        for term, skel, rule in self._terms:
            if len(term) < SUBSTRING_MIN:
                if term in tokens:
                    put(Match(rule, f"contains the keyword '{term}'", "keyword"))
                elif skel in skel_tokens:
                    put(Match(rule, f"contains '{term}' after homoglyph folding", "homoglyph", "homoglyph"))
                continue
            if term in prep.owner_folded or term in compact:
                put(Match(rule, f"contains the keyword '{term}'", "keyword"))
            elif skel and (skel in prep.owner_skeleton or skel in prep.owner_skeleton.replace("-", "")):
                put(Match(rule, f"contains '{term}' after homoglyph folding", "homoglyph", "homoglyph"))
        ordered = sorted(found.values(), key=lambda m: (_REASON_ORDER[m.kind], _KIND_ORDER.get(m.rule.kind, 9),
                                                        _CRIT_ORDER.get(m.rule.criticality, 9), m.rule.id))
        return NameMatch(prep.ascii, prep.registrable, tuple(ordered), "")


# ======================================================================================
# alerts
# ======================================================================================


def watch_case_id(moment: _dt.datetime) -> str:
    """The case id of the day's watch case (``watch-YYYYMMDD``, UTC)."""
    return "watch-" + moment.astimezone(_dt.timezone.utc).strftime("%Y%m%d")


def _alert_id(rule_id: str, key: str, serial: str) -> str:
    from v3lum.core.models import correlation_id

    return correlation_id(rule_id, [key if ("/" in key or "@" in key) else f"domain:{key}"], serial or "")


@dataclass
class Alert:
    """One watch alert (certificate metadata only).

    The JSONL record (:meth:`to_record`) holds the timestamp, rule id, matched name, registrable domain,
    reason, cert sha256, issuer and not_before (P030 cond 7), plus the alert id, serial, source, TLP,
    technique and the day's watch case id.
    """

    id: str
    ts: str
    rule_id: str
    name: str
    registrable_domain: str
    reason: str
    cert_sha256: str = ""
    issuer: str = ""
    not_before: str = ""
    serial: str = ""
    source: str = ""
    tlp: str = "amber"
    technique: str = ""
    case_id: str = ""
    also: tuple[str, ...] = ()

    def to_record(self) -> dict[str, Any]:
        return {
            "timestamp": self.ts, "rule_id": self.rule_id, "matched_name": self.name, "registrable_domain": self.registrable_domain,
            "reason": self.reason, "cert_sha256": self.cert_sha256, "issuer": self.issuer, "not_before": self.not_before,
            "id": self.id, "serial": self.serial, "source": self.source, "tlp": self.tlp, "technique": self.technique,
            "case_id": self.case_id, "also_rules": list(self.also),
        }

    @classmethod
    def from_record(cls, data: Mapping[str, Any]) -> Alert:
        return cls(
            id=str(data.get("id") or ""), ts=str(data.get("timestamp") or ""), rule_id=str(data.get("rule_id") or ""),
            name=str(data.get("matched_name") or ""), registrable_domain=str(data.get("registrable_domain") or ""),
            reason=str(data.get("reason") or ""), cert_sha256=str(data.get("cert_sha256") or ""), issuer=str(data.get("issuer") or ""),
            not_before=str(data.get("not_before") or ""), serial=str(data.get("serial") or ""), source=str(data.get("source") or ""),
            tlp=str(data.get("tlp") or "amber"), technique=str(data.get("technique") or ""), case_id=str(data.get("case_id") or ""),
            also=tuple(str(x) for x in data.get("also_rules") or ()),
        )

    def line(self) -> str:
        """The one terminal line (the matched name defanged: the alert is a suspected lookalike)."""
        from v3lum.core.entities import defang

        shown = defang(_mask_address(self.name)) if self.name else ""
        bits = [f"[!] {self.ts}", f"TLP:{self.tlp.upper()}", self.rule_id, shown, f"- {self.reason}"]
        if self.source:
            bits.append(f"[{self.source}]")
        return _clean(" ".join(b for b in bits if b), 600)

    def correlation(self) -> dict[str, Any]:
        """The alert as a correlation of the day's watch case (P325 votes give per-rule precision)."""
        hostname = "/" not in self.registrable_domain and "@" not in self.registrable_domain
        return {
            "id": self.id, "rule": self.rule_id, "title": f"watch alert: {self.registrable_domain}", "severity": "medium",
            "description": f"{_mask_address(self.name)}: {self.reason}", "entities": [f"domain:{self.registrable_domain}"] if hostname else [],
            "confidence": 0.5, "evidence": [f"source {self.source}"] + ([f"cert sha256 {self.cert_sha256}"] if self.cert_sha256 else []),
            "recommendation": "Review the lookalike; vote with `v3lum watch vote <alert id> right|wrong`.",
            "tags": ["typosquat"] if self.technique else ["brand_abuse"], "criterion": f"local org-profile rule match: {self.reason}",
            "confidence_label": "possible", "attack": [], "references": [], "version": "1", "why": self.reason, "key": self.serial,
            "suppressed_by": [], "watch": self.to_record(),
        }


def _mask_address(name: str) -> str:
    """An e-mail address with its local part masked (own-address alerts on the terminal)."""
    if "@" in name and "/" not in name:
        local, _, dom = name.rpartition("@")
        return (local[:1] + "***@" + dom) if local else name
    return name


# ======================================================================================
# CertStream
# ======================================================================================


@dataclass(frozen=True)
class CertEvent:
    """Certificate metadata of one CertStream message (never the certificate itself)."""

    names: tuple[str, ...]
    serial: str = ""
    cert_sha256: str = ""
    issuer: str = ""
    not_before: str = ""
    source: str = ""


def _hexnorm(value: Any) -> str:
    text = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))
    return text.upper()


def _epoch_iso(value: Any) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return _iso(_dt.datetime.fromtimestamp(float(value), tz=_dt.timezone.utc))
        except (OverflowError, OSError, ValueError):
            return ""
    return _clean(value, 40) if value else ""


def _issuer_text(issuer: Any) -> str:
    if isinstance(issuer, Mapping):
        agg = issuer.get("aggregated")
        if agg:
            return _clean(agg, 200)
        parts = [f"{k}={issuer[k]}" for k in ("C", "O", "CN") if issuer.get(k)]
        return _clean("/" + "/".join(parts), 200) if parts else ""
    return _clean(issuer, 200) if issuer else ""


def parse_certstream(raw: Any) -> tuple[str, CertEvent | None]:
    """Parse one CertStream message (calidog full stream, certstream-server-go full / domains-only).

    Returns ``(kind, event)``: ``('certificate', CertEvent)`` for ``certificate_update`` (and
    ``dns_entries`` names-only) messages, ``('heartbeat', None)``, ``('other', None)`` for any other
    message type and ``('malformed', None)`` for unreadable input. Only metadata is kept: names
    (``leaf_cert.all_domains``), serial, SHA-256 (``leaf_cert.sha256`` or computed from ``as_der``),
    issuer, not_before and the CT log name.
    """
    try:
        text = raw.decode("utf-8", errors="replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
        doc = json.loads(text)
    except (ValueError, TypeError):
        return "malformed", None
    if not isinstance(doc, Mapping):
        return "malformed", None
    mtype = str(doc.get("message_type") or "")
    if mtype == "heartbeat":
        return "heartbeat", None
    data = doc.get("data")
    if mtype == "dns_entries" and isinstance(data, list):
        names = tuple(_clean(n, 253) for n in data if isinstance(n, str) and n)
        return ("certificate", CertEvent(names)) if names else ("malformed", None)
    if mtype != "certificate_update":
        return "other", None
    if not isinstance(data, Mapping) or not isinstance(data.get("leaf_cert"), Mapping):
        return "malformed", None
    leaf = data["leaf_cert"]
    names = tuple(_clean(n, 253) for n in (leaf.get("all_domains") or ()) if isinstance(n, str) and n)
    if not names:
        return "malformed", None
    sha256 = _hexnorm(leaf.get("sha256")).lower()
    if len(sha256) != 64:
        sha256 = ""
        der = leaf.get("as_der")
        if isinstance(der, str) and der:
            try:
                sha256 = hashlib.sha256(base64.b64decode(der, validate=False)).hexdigest()
            except (binascii.Error, ValueError):
                sha256 = ""
    source = data.get("source") if isinstance(data.get("source"), Mapping) else {}
    return "certificate", CertEvent(
        names=names,
        serial=_hexnorm(leaf.get("serial_number"))[:128],
        cert_sha256=sha256,
        issuer=_issuer_text(leaf.get("issuer")),
        not_before=_epoch_iso(leaf.get("not_before")),
        source=_clean(source.get("name") or "", 120),
    )


class StreamConnection(Protocol):
    """One open stream: ``recv(timeout)`` returns a message, None when nothing arrived within ``timeout``,
    and raises (EOFError/OSError) when the connection is closed; ``close()`` closes it."""

    def recv(self, timeout: float) -> str | bytes | None: ...

    def close(self) -> None: ...


class StreamTransport(Protocol):
    """Opens stream connections (the default is :class:`WebSocketTransport`; tests inject a replay)."""

    def connect(self, url: str, *, timeout: float) -> StreamConnection: ...


def certstream_available() -> bool:
    """True when the optional extra ``v3lum[watch]`` (package websocket-client) is installed."""
    from v3lum.core.module import package_available

    return package_available("websocket")


class _WsConnection:
    def __init__(self, ws: Any, closed_errors: tuple[type[BaseException], ...], timeout_errors: tuple[type[BaseException], ...]) -> None:
        self.ws = ws
        self._closed = closed_errors
        self._timeouts = timeout_errors

    def recv(self, timeout: float) -> str | bytes | None:
        try:
            self.ws.settimeout(max(0.05, float(timeout)))
            return self.ws.recv()
        except self._timeouts:
            return None
        except self._closed as exc:
            raise EOFError(f"stream closed: {type(exc).__name__}") from exc

    def close(self) -> None:
        try:
            self.ws.close()
        except Exception:  # noqa: BLE001 - closing a dead socket never fails the watch
            pass


class WebSocketTransport:
    """The real CertStream transport over websocket-client (optional extra ``v3lum[watch]``).

    TLS certificates are always verified (setting ``ca_bundle`` adds an internal CA); the default route
    (setting ``proxy``, an HTTP CONNECT proxy) is used like every third-party data source (A13). The
    handshake carries only the configured URL and a neutral User-Agent; nothing else is ever sent (pong
    replies to server pings echo the server's own payload).
    """

    def __init__(self, config: Any = None) -> None:
        self.config = config

    def _setting(self, name: str) -> str:
        getter = getattr(self.config, "get", None)
        try:
            return str((getter(name, "") if callable(getter) else "") or "").strip()
        except Exception:  # noqa: BLE001
            return ""

    def options(self, url: str, timeout: float) -> dict[str, Any]:
        """The keyword arguments handed to ``websocket.create_connection`` (TLS verification on)."""
        from v3lum import __version__

        ssl_opts: dict[str, Any] = {"cert_reqs": ssl.CERT_REQUIRED, "check_hostname": True}
        bundle = self._setting("ca_bundle")
        if bundle:
            ssl_opts["ca_certs"] = os.path.expanduser(bundle)
        kw: dict[str, Any] = {"timeout": float(timeout), "header": [f"User-Agent: V3LUM/{__version__}"], "enable_multithread": True}
        if url.startswith("wss://"):
            kw["sslopt"] = ssl_opts
        proxy = self._setting("proxy")
        if proxy:
            parts = urlsplit(proxy if "://" in proxy else f"http://{proxy}")
            if parts.hostname:
                kw["http_proxy_host"] = parts.hostname
                kw["http_proxy_port"] = parts.port or (1080 if parts.scheme.startswith("socks") else 8080)
                kw["proxy_type"] = {"socks5": "socks5h", "socks5h": "socks5h", "socks4": "socks4a", "socks4a": "socks4a"}.get(parts.scheme, "http")
                if parts.username:
                    kw["http_proxy_auth"] = (parts.username, parts.password or "")
        return kw

    def connect(self, url: str, *, timeout: float) -> _WsConnection:
        import websocket  # optional extra v3lum[watch]

        ws = websocket.create_connection(url, **self.options(url, timeout))
        closed = tuple(t for t in (getattr(websocket, "WebSocketConnectionClosedException", None), OSError, EOFError) if isinstance(t, type))
        timeouts = tuple(t for t in (getattr(websocket, "WebSocketTimeoutException", None), TimeoutError) if isinstance(t, type))
        return _WsConnection(ws, closed, timeouts)


def _internal_host(host: str, org: Any = None) -> bool:
    """A host in the organisation's network: a private/loopback IP, an internal-only name, or an own
    domain / own network of the org profile."""
    text = str(host or "").strip().lower().strip("[]")
    if not text:
        return False
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
    elif "." not in text or text.endswith((".internal", ".local", ".lan", ".corp", ".home.arpa", ".intranet")):
        return True
    owns = getattr(org, "owns", None)
    if callable(owns):
        try:
            etype = EntityType.IPV6 if ip is not None and ip.version == 6 else (EntityType.IPV4 if ip is not None else EntityType.DOMAIN)
            return bool(owns(Entity.make(etype, text)).own)
        except Exception:  # noqa: BLE001 - an unreadable host is not internal
            return False
    return False


def certstream_endpoint(config: Any = None, org: Any = None) -> dict[str, Any]:
    """The CertStream endpoint watch would use: ``{url, kind ('self-hosted' | 'public'), disclosure
    ('internal' | 'third_party'), tier, max_tlp, problem}``.

    Setting ``certstream_url`` (a self-hosted certstream-server-go) comes first; it is disclosure
    'internal' when its host is in the organisation's network (private address, internal name, own
    domain/network), otherwise a third-party endpoint of tier 'unknown'. Without the setting the public
    community-tier ``wss://certstream.calidog.io/`` is used (provider ``certstream``). ``problem`` is set
    for an unusable URL (only ws:// and wss://; ws:// - no TLS - only for internal hosts).
    """
    getter = getattr(config, "get", None)
    try:
        configured = str((getter("certstream_url", "") if callable(getter) else "") or "").strip()
    except Exception:  # noqa: BLE001
        configured = ""
    url = configured or PUBLIC_CERTSTREAM_URL
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    out: dict[str, Any] = {"url": url, "host": host, "kind": "self-hosted" if configured else "public", "problem": ""}
    if parts.scheme not in ("ws", "wss") or not host:
        out.update(disclosure="third_party", tier="unknown", max_tlp=_tlp.TLP.GREEN.value_str,
                   problem=f"certstream_url must be a ws:// or wss:// URL, got {_display_url(url)!r}")
        return out
    internal = bool(configured) and _internal_host(host, org)
    if internal:
        disclosure, tier = "internal", "trusted"
    else:
        disclosure, tier = "third_party", "unknown"
        try:
            from v3lum.core import providers as _providers

            prov = _providers.registry().get(CERTSTREAM_PROVIDER)
        except Exception:  # noqa: BLE001 - registry problems: unknown tier (fail closed)
            prov = None
        if prov is not None and any(host == h for h in getattr(prov, "hosts", ()) or ()):
            tier = str(getattr(prov, "tier", "unknown") or "unknown")
        elif host == PUBLIC_CERTSTREAM_HOST:
            tier = "community"
    if parts.scheme == "ws" and not internal:
        out["problem"] = "ws:// (no TLS) is accepted only for a self-hosted server in the organisation's network: use wss://"
    ceiling = _tlp.max_tlp(disclosure, tier, publishes_queries=False, reuses_queries=False)
    out.update(disclosure=disclosure, tier=tier, max_tlp=(ceiling or _tlp.TLP.CLEAR).value_str)
    return out


@dataclass
class StreamStats:
    """Counters of the CertStream consumer (P030 cond 6: nothing is dropped silently)."""

    received: int = 0
    heartbeats: int = 0
    malformed: int = 0
    other: int = 0
    oversize: int = 0
    prefiltered: int = 0
    queued: int = 0
    dropped_queue: int = 0
    connects: int = 0
    connect_errors: int = 0
    disconnects: int = 0
    rate_capped: int = 0
    #: handshakes the server refused or throttled (HTTP 403/429/5xx): could not verify, long backoff
    refused: int = 0
    backoffs: list[float] = field(default_factory=list)
    last_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        data["backoffs"] = [round(b, 3) for b in self.backoffs[-20:]]
        return data


@dataclass(frozen=True)
class _Candidate:
    event: CertEvent
    cost: int


class CertStreamConsumer:
    """Bounded CertStream consumer: reader (``run``) -> prefilter -> bounded queue -> ``drain``.

    ``transport`` opens connections (default :class:`WebSocketTransport`), ``clock`` drives waits and the
    reconnect window, ``rng`` the backoff jitter. Bounds: messages above :data:`MESSAGE_MAX_BYTES` are
    dropped (``oversize``), certificates whose names fail :meth:`Matcher.prefilter` are dropped
    (``prefiltered``), the queue holds at most ``max_items`` candidates and ``max_bytes`` estimated bytes
    (beyond: ``dropped_queue``). Reconnects back off exponentially from :data:`BACKOFF_BASE` to
    :data:`BACKOFF_CAP` with jitter (half fixed, half random), reset after a connection that stayed up
    :data:`HEALTHY_AFTER` seconds, and at most ``max_reconnects`` connections per :data:`RECONNECT_WINDOW`
    (beyond: the reader waits, ``rate_capped``). Nothing is ever sent on the connection.
    """

    def __init__(
        self,
        url: str,
        matcher: Matcher,
        *,
        transport: Any = None,
        clock: Clock | None = None,
        rng: random.Random | None = None,
        max_items: int = QUEUE_MAX_ITEMS,
        max_bytes: int = QUEUE_MAX_BYTES,
        max_reconnects: int = MAX_RECONNECTS_PER_WINDOW,
        config: Any = None,
    ) -> None:
        self.url = url
        self.matcher = matcher
        self.transport = transport if transport is not None else WebSocketTransport(config)
        self.clock: Clock = clock or SYSTEM_CLOCK
        self.rng = rng or random.Random()
        self.max_items = max(1, int(max_items))
        self.max_bytes = max(1024, int(max_bytes))
        self.max_reconnects = max(1, int(max_reconnects))
        self.stats = StreamStats()
        self._queue: collections.deque[_Candidate] = collections.deque()
        self._bytes = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._connects: collections.deque[float] = collections.deque()
        self._attempt = 0

    # -- messages ------------------------------------------------------------------------
    def handle_message(self, raw: Any) -> bool:
        """Parse, prefilter and enqueue one message; True when a candidate was queued."""
        size = len(raw) if isinstance(raw, (str, bytes, bytearray)) else 0
        with self._lock:
            self.stats.received += 1
        if size > MESSAGE_MAX_BYTES:
            with self._lock:
                self.stats.oversize += 1
            return False
        kind, event = parse_certstream(raw)
        if kind != "certificate" or event is None:
            with self._lock:
                if kind == "heartbeat":
                    self.stats.heartbeats += 1
                elif kind == "other":
                    self.stats.other += 1
                else:
                    self.stats.malformed += 1
            return False
        names = tuple(n for n in event.names[:NAMES_PER_CERT] if self.matcher.prefilter(n))
        if not names:
            with self._lock:
                self.stats.prefiltered += 1
            return False
        cand_event = dataclasses.replace(event, names=names)
        cost = 256 + sum(len(n) for n in names) + len(cand_event.issuer) + len(cand_event.source)
        with self._lock:
            if len(self._queue) >= self.max_items or self._bytes + cost > self.max_bytes:
                self.stats.dropped_queue += 1
                return False
            self._queue.append(_Candidate(cand_event, cost))
            self._bytes += cost
            self.stats.queued += 1
        return True

    def drain(self, limit: int = 1000) -> list[CertEvent]:
        """Up to ``limit`` queued candidates, oldest first."""
        out: list[CertEvent] = []
        with self._lock:
            while self._queue and len(out) < limit:
                cand = self._queue.popleft()
                self._bytes -= cand.cost
                out.append(cand.event)
        return out

    @property
    def queued(self) -> int:
        with self._lock:
            return len(self._queue)

    # -- connection management ---------------------------------------------------------
    def _error_text(self, exc: BaseException) -> str:
        """The error of a connection for stats/state/doctor: redacted, the endpoint URL shown without
        user info or query (a self-hosted endpoint's token never reaches a screen or state.json)."""
        text = f"{type(exc).__name__}: {exc}"
        if self.url:
            text = text.replace(self.url, _display_url(self.url))
        return _redact(text)

    def backoff(self, attempt: int) -> float:
        """The wait before reconnect ``attempt`` (0-based): min(cap, base * 2**attempt), half of it
        fixed and half random (jitter)."""
        delay = min(BACKOFF_CAP, BACKOFF_BASE * (2 ** max(0, min(int(attempt), 30))))
        return delay / 2 + self.rng.uniform(0, delay / 2)

    def _wait(self, seconds: float) -> None:
        remaining = max(0.0, float(seconds))
        while remaining > 0 and not self._stop.is_set():
            step = min(remaining, 0.5)
            self.clock.sleep(step)
            remaining -= step

    def _reserve_connect(self) -> bool:
        """Record a connection attempt within the reconnect-rate cap; False (after waiting) when capped."""
        now = self.clock.monotonic()
        while self._connects and now - self._connects[0] >= RECONNECT_WINDOW:
            self._connects.popleft()
        if len(self._connects) >= self.max_reconnects:
            with self._lock:
                self.stats.rate_capped += 1
            self._wait(RECONNECT_WINDOW - (now - self._connects[0]) + 0.001)
            return False
        self._connects.append(now)
        return True

    def read(self, conn: Any) -> None:
        """Read messages from an open connection until it closes, goes idle or the consumer stops."""
        last = self.clock.monotonic()
        while not self._stop.is_set():
            try:
                raw = conn.recv(READ_TIMEOUT)
            except Exception as exc:  # noqa: BLE001 - closed / reset: reconnect
                with self._lock:
                    self.stats.last_error = self._error_text(exc)
                return
            now = self.clock.monotonic()
            if raw is None or (isinstance(raw, (str, bytes, bytearray)) and not raw):  # nothing (or a close frame's '')
                if now - last >= IDLE_TIMEOUT:
                    with self._lock:
                        self.stats.last_error = f"no message for {int(IDLE_TIMEOUT)} s: reconnecting"
                    return
                continue
            last = now
            self.handle_message(raw)

    def run(self, *, max_connections: int | None = None) -> None:
        """The reader loop (thread target): connect, read, back off, reconnect - until :meth:`stop`
        (or ``max_connections`` attempts, for tests)."""
        attempts = 0
        while not self._stop.is_set():
            if max_connections is not None and attempts >= max_connections:
                return
            if not self._reserve_connect():
                continue
            attempts += 1
            try:
                conn = self.transport.connect(self.url, timeout=CONNECT_TIMEOUT)
            except Exception as exc:  # noqa: BLE001 - refused, DNS, TLS: could not connect
                status = _http_status(exc)
                with self._lock:
                    self.stats.connect_errors += 1
                    self.stats.last_error = self._error_text(exc)
                    if status is not None and (status in (403, 429) or status >= 500):
                        self.stats.refused += 1
                if status is not None and (status in (403, 429) or status >= 500):
                    # the server refused or throttled the handshake: respect it with a long wait
                    self._attempt = max(self._attempt, REFUSED_BACKOFF_ATTEMPT)
                delay = self.backoff(self._attempt)
                self._attempt += 1
                with self._lock:
                    self.stats.backoffs.append(delay)
                self._wait(delay)
                continue
            with self._lock:
                self.stats.connects += 1
            started = self.clock.monotonic()
            try:
                self.read(conn)
            finally:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
            if self._stop.is_set():
                return
            with self._lock:
                self.stats.disconnects += 1
            if self.clock.monotonic() - started >= HEALTHY_AFTER:
                self._attempt = 0
            delay = self.backoff(self._attempt)
            self._attempt += 1
            with self._lock:
                self.stats.backoffs.append(delay)
            self._wait(delay)

    def start(self) -> None:
        """Run the reader in a daemon thread (stopped by :meth:`stop`)."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self.run, name="v3lum-certstream", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout)


def _redact(text: str) -> str:
    text = re.sub(r"(?i)\b(wss?|https?)://[^/\s@]*@", r"\1://", str(text or ""))  # user info of any URL
    try:
        from v3lum.core.redact import redact_text

        return _clean(redact_text(text), 200)
    except Exception:  # noqa: BLE001
        return _clean(text, 200)


def _merge_states(states: list[dict[str, str]]) -> dict[str, str]:
    """One polling source's status over its entity runs of a cycle: any run that could not verify
    (error, rate limited, blocked, quota, needs key, unavailable...) wins over ok/empty - a failure on
    one entity is never hidden by an answer on another (rule 5); else ok, else empty, else the skip."""
    if not states:
        return {"status": "skipped", "reason_code": "not_applicable", "reason": "no accepted rule entity"}
    bad = [s for s in states if s.get("status") not in ("ok", "empty", "skipped")]
    if bad:
        out = dict(bad[0])
        if len(states) > 1:
            out["reason"] = _clean(f"{out.get('reason') or 'could not verify'} ({len(bad)} of {len(states)} entity runs could not verify)", 240)
        return out
    for wanted in ("ok", "empty"):
        for s in states:
            if s.get("status") == wanted:
                return dict(s)
    return dict(states[0])


def _http_status(exc: BaseException) -> int | None:
    """The HTTP status of a refused WebSocket handshake (websocket-client's
    WebSocketBadStatusException.status_code), else None."""
    for value in (getattr(exc, "status_code", None), getattr(getattr(exc, "response", None), "status_code", None)):
        if isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599:
            return value
    return None


# ======================================================================================
# mutes, alerts listing, votes (case DB through Store.connection)
# ======================================================================================


def _registrable(target: str) -> str:
    text = str(target or "").strip().lower().rstrip(".")
    ascii_name = _to_ascii(text)
    if not ascii_name or not _hostname_ok(ascii_name):
        return ""
    return psl.registrable_domain(ascii_name) or ""


def _resolve_mute(target: str, rules: Iterable[WatchRule] | None) -> tuple[str, str]:
    text = str(target or "").strip()
    if not text:
        raise ValueError("give a rule id (v3lum watch rules) or a domain to mute")
    ids = {r.id for r in rules or ()}
    if text in ids or (":" in text and not rules):
        return text, ""
    reg = _registrable(text)
    if not reg:
        raise ValueError(f"{_clean(text, 80)!r} is neither a watch rule id (v3lum watch rules) nor a registrable domain")
    return "", reg


def mute(store: Any, target: str, *, rules: Iterable[WatchRule] | None = None, now: _dt.datetime | None = None) -> tuple[str, str]:
    """Mute a rule (``target`` = a rule id) or a registrable domain (``target`` = a domain): a row in
    ``watch_mutes``. Returns ``(rule_id, domain)``; ValueError for anything else."""
    rule_id, domain = _resolve_mute(target, list(rules) if rules is not None else None)
    stamp = _iso(now or _dt.datetime.now(_dt.timezone.utc))
    with store.connection() as conn:
        conn.execute("INSERT OR IGNORE INTO watch_mutes (rule_id, domain, created) VALUES (?, ?, ?)", (rule_id, domain, stamp))
    return rule_id, domain


def unmute(store: Any, target: str, *, rules: Iterable[WatchRule] | None = None) -> bool:
    """Remove a mute added by :func:`mute`; True when one existed."""
    rule_id, domain = _resolve_mute(target, list(rules) if rules is not None else None)
    with store.connection() as conn:
        cur = conn.execute("DELETE FROM watch_mutes WHERE rule_id = ? AND domain = ?", (rule_id, domain))
        return bool(cur.rowcount)


def mutes(store: Any) -> list[dict[str, str]]:
    """Every mute: ``[{rule_id, domain, created}]`` ('' rule_id = a domain mute and vice versa)."""
    with store.connection() as conn:
        rows = conn.execute("SELECT rule_id, domain, created FROM watch_mutes ORDER BY created, rule_id, domain").fetchall()
    return [{"rule_id": str(r[0] or ""), "domain": str(r[1] or ""), "created": str(r[2] or "")} for r in rows]


def recent_alerts(store: Any, *, limit: int = 50, rule_id: str = "") -> list[Alert]:
    """The most recent alerts of the ``alerts`` table (newest first)."""
    sql = "SELECT payload FROM alerts" + (" WHERE rule_id = ?" if rule_id else "") + " ORDER BY ts DESC, id LIMIT ?"
    params: tuple[Any, ...] = ((rule_id, int(limit)) if rule_id else (int(limit),))
    with store.connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    out = []
    for row in rows:
        try:
            out.append(Alert.from_record(json.loads(row[0])))
        except (ValueError, TypeError):
            continue
    return out


def vote_alert(store: Any, alert_id: str, vote: str, *, analyst: str, reason: str | None = None) -> dict[str, Any]:
    """Record a P325 vote on an alert (its watch case's correlation): the rule's precision follows
    (``Store.rule_precision``). ValueError for an unknown alert or an invalid vote."""
    with store.connection() as conn:
        row = conn.execute("SELECT case_id, rule_id FROM alerts WHERE id = ?", (str(alert_id or "").strip(),)).fetchone()
    if row is None or not row[0]:
        raise ValueError(f"unknown watch alert {str(alert_id)[:40]!r} (v3lum watch alerts lists them)")
    return store.vote(str(row[0]), str(alert_id).strip(), analyst=analyst, vote=vote, reason=reason, rule_id=str(row[1] or ""))


# ======================================================================================
# the watcher
# ======================================================================================


@dataclass
class WatchReport:
    """What one :meth:`Watcher.run` did (the command prints it)."""

    started: str = ""
    finished: str = ""
    tlp: str = "amber"
    stop_reason: str = ""
    cycles: int = 0
    alerts: int = 0
    summarized: int = 0
    muted: int = 0
    duplicates: int = 0
    known: int = 0
    own: int = 0
    unmatched: int = 0
    #: hit names that are no host name, http(s) URL or verified own-domain address (third-party
    #: e-mail addresses, phone numbers, CPF-like digits, bare IPs, free text): never watched (A14)
    rejected: int = 0
    enriched: list[dict[str, str]] = field(default_factory=list)
    enrich_listed: list[str] = field(default_factory=list)
    #: domains listed for the analyst beyond ENRICH_LISTED_MAX (counted, not kept by name)
    enrich_listed_more: int = 0
    sources: dict[str, dict[str, str]] = field(default_factory=dict)
    keywords_kept_local: int = 0
    certstream: dict[str, Any] = field(default_factory=dict)
    stream: dict[str, Any] = field(default_factory=dict)
    pruned: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    case_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


class _WatchEngineMixin:
    policy_path = "watch"

    def policy_context(self, *, graph: Any = None, path: str = "scan", explicit: Iterable[str] | None = None) -> Any:
        return super().policy_context(graph=graph, path="watch" if path == "scan" else path, explicit=explicit)  # type: ignore[misc]


_ENGINE_CLASS: Any = None


def _watch_engine(runtime: Any, options: Any) -> Any:
    """An Engine whose investigations and listings build their PolicyContext on path 'watch'."""
    global _ENGINE_CLASS
    if _ENGINE_CLASS is None:
        from v3lum.core.engine import Engine

        _ENGINE_CLASS = type("_WatchEngine", (_WatchEngineMixin, Engine), {"__module__": __name__})
    return _ENGINE_CLASS(runtime, options)


class Watcher:
    """The watch loop of ``v3lum watch`` (see the module docstring).

    ``Watcher(runtime, store, org, *, clock=None, transport=None, ...)``: ``runtime`` is a
    :class:`v3lum.core.context.Runtime` (polling runs and enrichment scans use it), ``store`` the case DB
    (:class:`v3lum.core.store.Store`; watch tables through ``Store.connection``), ``org`` the org profile,
    ``clock`` the time source (default the runtime's), ``transport`` the CertStream transport (default
    :class:`WebSocketTransport` when the extra is installed). Keyword-only extras: ``tlp`` (default
    setting tlp, AMBER), ``out(text, style)`` for terminal lines, ``sources`` (restrict the polling
    sources to these module names), ``enrich_modules`` (restrict the enrichment scan's modules),
    ``enricher(domain, alert) -> case_id`` (replace the default passive scan), ``certstream`` (False:
    polling only), ``rng`` (backoff jitter), ``settings`` (default ``runtime.config``).
    """

    def __init__(
        self,
        runtime: Any,
        store: Any,
        org: Any,
        *,
        clock: Clock | None = None,
        transport: Any = None,
        tlp: Any = None,
        out: Callable[[str, str], None] | None = None,
        sources: Iterable[str] | None = None,
        enrich_modules: Iterable[str] | None = None,
        enricher: Callable[[str, Alert], str | None] | None = None,
        certstream: bool = True,
        rng: random.Random | None = None,
        settings: Any = None,
        tlp_change: Mapping[str, Any] | None = None,
    ) -> None:
        self.runtime = runtime
        #: A2: a watch TLP below the configured default ({os_user, analyst, at, from, to}); recorded
        #: once per run in the audit of the watch case and handed to every enrichment scan
        self.tlp_change: dict[str, Any] | None = dict(tlp_change) if tlp_change else None
        self._tlp_change_recorded: set[str] = set()
        self._mutes_loaded = float("-inf")
        self.store = store
        self.org = org
        self.clock: Clock = clock or getattr(runtime, "clock", None) or SYSTEM_CLOCK
        self.transport = transport
        self.settings = settings if settings is not None else getattr(runtime, "config", None)
        try:
            self.tlp = _tlp.parse(tlp if tlp not in (None, "") else (self._setting("tlp", "amber") or "amber"))
        except ValueError:
            self.tlp = _tlp.TLP.AMBER
        self.out = out
        self.source_filter = {s.strip() for s in sources or () if str(s).strip()} or None
        self.enrich_modules = {s.strip() for s in enrich_modules or () if str(s).strip()} or None
        self.enricher = enricher
        self.certstream_enabled = bool(certstream)
        self.rng = rng or random.Random()
        self.problems: list[str] = []
        self.rules = rules_from_profile(org, problems=self.problems)
        self.rules_by_id = {r.id: r for r in self.rules}
        self.matcher = Matcher(self.rules)
        self.consumer: CertStreamConsumer | None = None
        self.report = WatchReport(tlp=self.tlp.value_str)
        self._lru: collections.OrderedDict[tuple[str, str], None] = collections.OrderedDict()
        self._mutes: tuple[frozenset[str], frozenset[str]] = (frozenset(), frozenset())
        self._hour = ""
        self._hour_count = 0
        self._hour_hidden = 0
        self._enrich_queue: collections.deque[tuple[str, Alert]] = collections.deque()
        self._enrich_seen: set[str] = set()
        #: wall-clock times of the enrichments of the last hour (persisted in state.json: the cap holds
        #: across `--once` runs started by a timer)
        self._enrich_times: collections.deque[_dt.datetime] = collections.deque()
        self._enrich_loaded = False
        self._pending_case: list[Alert] = []
        self._rows: list[tuple[str, tuple[Any, ...]]] = []
        self._seen_pending: set[tuple[str, str]] = set()
        self._last_case_flush = self.clock.monotonic()
        self._cache_keys: set[str] = set()
        self._stop_reason = ""
        self._max_alerts = 0
        self._engine: Any = None
        self._lock = threading.RLock()

    # -- settings ------------------------------------------------------------------------
    def _setting(self, name: str, default: Any = None) -> Any:
        getter = getattr(self.settings, "get", None)
        if not callable(getter):
            return default
        try:
            value = getter(name, default)
        except Exception:  # noqa: BLE001
            return default
        return default if value is None else value

    def _int_setting(self, name: str, default: int) -> int:
        try:
            return int(float(self._setting(name, default)))
        except (TypeError, ValueError):
            return default

    def _emit(self, text: str, style: str = "v.text") -> None:
        if self.out is not None:
            try:
                self.out(_clean(text, 2000), style)
            except Exception as exc:  # noqa: BLE001 - a broken terminal never stops the watch
                log.debug("watch output failed: %s", type(exc).__name__)

    def _now(self) -> _dt.datetime:
        now = self.clock.now()
        return now if now.tzinfo else now.replace(tzinfo=_dt.timezone.utc)

    def watch_dir(self) -> Path:
        """``~/.v3lum/watch`` (0700)."""
        return paths.sub("watch")

    # -- sources ---------------------------------------------------------------------------
    def watch_sources(self) -> list[type]:
        """The registered PASSIVE modules tagged ``watch_source`` (restricted by ``sources``), by name.
        LIGHT/ACTIVE sources are never run (watch makes no automatic target contact)."""
        from v3lum.core.models import Opsec
        from v3lum.core.module import REGISTRY

        out = []
        for name in sorted(REGISTRY):
            cls = REGISTRY[name]
            if "watch_source" not in (getattr(cls, "tags", ()) or ()):
                continue
            if self.source_filter is not None and name not in self.source_filter:
                continue
            try:
                opsec = Opsec.parse(getattr(cls, "opsec", Opsec.PASSIVE))
            except (KeyError, ValueError):
                opsec = Opsec.ACTIVE
            if opsec >= Opsec.LIGHT:
                self.report.sources[name] = {"status": "skipped", "reason_code": "opsec", "reason": "LIGHT/ACTIVE source: watch never contacts targets"}
                continue
            provider = str(getattr(cls, "provider", "") or "")
            if provider in VICTIM_FEED_KEYS:
                key = VICTIM_FEED_KEYS[provider]
                if key is None or key not in (getattr(cls, "requires_keys", ()) or ()):
                    # P030 cond 9 / A14: ransomware victim watch only through the ransomware.live PRO key
                    self.report.sources[name] = {
                        "status": "skipped", "reason_code": "policy",
                        "reason": "ransomware victim watch runs only with the ransomware.live PRO key (P030 cond 9): "
                                  + (f"declare requires_keys = ('{key}',)" if key else f"{provider} is never a watch source"),
                    }
                    continue
            out.append(cls)
        return out

    def rule_entities(self) -> list[tuple[Entity, WatchRule]]:
        """The polling entities: own registrable domains (domain rules) and brand keywords (brand rules)."""
        out: list[tuple[Entity, WatchRule]] = []
        seen: set[str] = set()
        for rule in self.rules:
            for ent in rule.entities:
                if ent.key not in seen:
                    seen.add(ent.key)
                    out.append((ent, rule))
        return out

    def _options(self, include: Iterable[str]) -> Any:
        from v3lum.core.context import ScanOptions
        from v3lum.core.models import Opsec

        return ScanOptions(
            mode=Opsec.PASSIVE, depth=0, max_entities=50, threads=1, include=set(include), tlp=self.tlp.value_str,
            save_evidence=False, purpose="v3lum watch: org-profile brand and domain monitoring (P030)",
            offline=bool(getattr(self.runtime, "offline", False)),
        )

    def poll_cycle(self, *, deadline: float | None = None) -> dict[str, dict[str, str]]:
        """One polling cycle (phase 1): every watch source on every accepted rule entity, through the
        policy gate on path 'watch'; ``watch_hits`` go through first_seen diffing. Returns the source
        statuses of the cycle."""
        from v3lum.core import policy
        from v3lum.core.context import RunInfo
        from v3lum.core.models import Status

        self._load_mutes()
        sources = self.watch_sources()
        names = [c.name for c in sources]
        statuses: dict[str, dict[str, str]] = {}
        runs: dict[str, list[dict[str, str]]] = {}
        self.report.cycles += 1
        if not sources:
            self._emit("[i] no polling source available (modules tagged watch_source): this cycle checked nothing", "v.dim")
            return statuses
        options = self._options(names)
        if self._engine is None:
            self._engine = _watch_engine(self.runtime, options)
        engine = self._engine
        engine.options = options
        rt = self.runtime
        previous_scan = bool(getattr(rt, "in_scan", False))
        previous_keys = getattr(rt, "cache_key_collector", None)
        rt.in_scan = True  # AR10: no large dataset downloads inside a watch cycle
        rt.cache_key_collector = self._cache_keys
        try:
            pctx = engine.policy_context(path="watch", explicit=names)
            for cls in sources:
                for entity, rule in self.rule_entities():
                    if self._stop_reason or (deadline is not None and self.clock.monotonic() >= deadline):
                        break
                    if entity.type not in (getattr(cls, "accepts", ()) or ()):
                        continue
                    if entity.type is EntityType.KEYWORD and getattr(cls, "disclosure", "") not in ("none", "internal"):
                        self.report.keywords_kept_local += 1  # keywords never leave the machine (A14)
                        continue
                    run = RunInfo(entity=entity, is_seed=True, depth=0, tlp=self.tlp.value_str, case_id=self.case_id)
                    try:
                        decision = policy.decide(cls, entity, pctx, run=run) if pctx is not None else None
                    except Exception as exc:  # noqa: BLE001 - fail closed
                        runs.setdefault(cls.name, []).append({"status": "skipped", "reason_code": "policy", "reason": f"policy error ({type(exc).__name__})"})
                        continue
                    if decision is None or not getattr(decision, "allowed", False):
                        status = getattr(getattr(decision, "status", None), "value", "skipped")
                        runs.setdefault(cls.name, []).append({
                            "status": str(status), "reason_code": str(getattr(decision, "reason_code", "") or "policy"),
                            "reason": _clean(getattr(decision, "reason", "") or "policy gate unavailable (fail closed)", 200),
                        })
                        continue
                    res = engine.run_module(cls, entity, run=run, decision=decision)
                    state = {"status": res.status.value, "reason_code": res.reason_code, "reason": _clean(res.error, 200)}
                    if res.status not in (Status.OK, Status.EMPTY):
                        state["reason"] = state["reason"] or "could not verify"
                    runs.setdefault(cls.name, []).append(state)
                    hits = res.attributes.get("watch_hits") if isinstance(res.attributes, Mapping) else None
                    for hit in list(hits or ())[:MAX_HITS_PER_RUN]:
                        if self._halted:
                            break
                        if isinstance(hit, Mapping):
                            self._ingest_hit(hit, cls.name, rule)
        finally:
            rt.in_scan = previous_scan
            rt.cache_key_collector = previous_keys
            self._flush_rows()
        stamp = _iso(self._now())
        for name, states in runs.items():
            statuses[name] = _merge_states(states)
        for name, state in statuses.items():
            self.report.sources[name] = dict(state, at=stamp)
        self._save_state(last_cycle=stamp)
        return statuses

    # -- ingest ----------------------------------------------------------------------------
    def _load_mutes(self) -> None:
        self._mutes_loaded = self.clock.monotonic()
        try:
            rows = mutes(self.store)
        except Exception as exc:  # noqa: BLE001 - mute table unavailable: nothing muted
            log.warning("watch mutes unavailable: %s", type(exc).__name__)
            rows = []
        self._mutes = (frozenset(r["rule_id"] for r in rows if r["rule_id"]), frozenset(r["domain"] for r in rows if r["domain"]))

    def _muted(self, rule_id: str, *domains: str) -> bool:
        rules, muted_domains = self._mutes
        return rule_id in rules or any(d and d in muted_domains for d in domains)

    def _ingest_hit(self, hit: Mapping[str, Any], module: str, rule: WatchRule) -> Alert | None:
        name = _clean(hit.get("name"), 2048).strip()
        if not name:
            return None
        hinted = self.rules_by_id.get(str(hit.get("rule_id") or ""))
        kind = _hit_kind(name)[0]
        # a source may name the rule it matched, but only a rule that applies to the hit's IOC type
        # (a post URL may cite a CNPJ root or BIN rule; a host name needs a domain-type rule)
        if hinted is not None and (kind in hinted.ioc_types or (kind == "url" and hinted.kind in ("cnpj_root", "card_bin"))):
            hint = hinted
        else:
            hint = rule
        source = _clean(hit.get("source") or module, 120)
        return self._observe(
            name, serial=_hexnorm(hit.get("serial"))[:128], cert_sha256=_hexnorm(hit.get("cert_sha256")).lower()[:64],
            issuer=_clean(hit.get("issuer"), 200), not_before=_clean(hit.get("not_before"), 40), source=f"{module}:{source}" if source != module else module,
            hint=hint, registrable=str(hit.get("registrable_domain") or "").strip().lower(),
        )

    @property
    def _halted(self) -> bool:
        """No more ingestion: the alert budget is spent or the analyst interrupted (a run that ends by
        --once or --max-runtime still processes what was already queued)."""
        return self._stop_reason in ("max_alerts", "interrupted")

    def ingest_event(self, event: CertEvent) -> list[Alert]:
        """First_seen diffing of one CertStream certificate (every name of it)."""
        out = []
        for name in event.names:
            if self._halted:
                break
            alert = self._observe(name, serial=event.serial, cert_sha256=event.cert_sha256, issuer=event.issuer,
                                  not_before=event.not_before, source="certstream" + (f":{event.source}" if event.source else ""))
            if alert is not None:
                out.append(alert)
        return out

    def _observe(
        self, name: str, *, serial: str = "", cert_sha256: str = "", issuer: str = "", not_before: str = "", source: str = "",
        hint: WatchRule | None = None, registrable: str = "",
    ) -> Alert | None:
        if self._halted:
            return None
        rep = self.report
        kind, name, host = _hit_kind(name)
        if not kind:
            # not a host name, an http(s) URL or an address: phone numbers, CPF/CNPJ-like digits, bare
            # IPs and free text are never watched (A14) - nothing is recorded
            rep.rejected += 1
            return None
        matches: tuple[Match, ...] = ()
        key = ""
        if kind == "email":
            matches, key = self._address_match(name)
            if not matches:
                # an address outside the verified own domains belongs to a natural person: never
                # watched, never recorded (A14: only own-domain addresses for infostealer exposure)
                rep.rejected += 1
                return None
        else:
            nm = self.matcher.match(host)
            if nm is not None:
                if nm.protected_by:
                    rep.own += 1
                    return None
                matches, key = nm.matches, nm.registrable_domain
        if not matches:
            if hint is None:
                rep.unmatched += 1
                return None
            # the source matched with its own logic: keyed by the registrable domain it reported, else the
            # name itself (a URL or post id is never collapsed into its host)
            matches = (Match(hint, f"reported by {source or 'a watch source'}", "source"),)
            reported = _registrable(registrable) if registrable and "/" not in registrable and "@" not in registrable else ""
            if kind == "url":
                key = name
            else:  # the host's own registrable domain wins over what the source reported
                key = _registrable(host) or reported or host
        key = key[:512]
        # domain mutes apply to the key and to the registrable domain of a URL's host / address's domain
        mute_domain = _registrable(host) if kind in ("url", "email") else ""
        lru_key = (key, serial)
        with self._lock:
            if lru_key in self._lru:
                self._lru.move_to_end(lru_key)
                rep.duplicates += 1
                return None
            self._lru[lru_key] = None
            while len(self._lru) > LRU_SIZE:
                self._lru.popitem(last=False)
        if self._muted("", key, mute_domain):
            rep.muted += 1
            self._record_seen(matches[0].rule.id, key, serial)
            return None
        unmuted = [m for m in matches if not self._muted(m.rule.id)]
        if not unmuted:
            rep.muted += 1
            self._record_seen(matches[0].rule.id, key, serial)
            return None
        primary = unmuted[0]
        new_domain = self._record_seen(primary.rule.id, key, serial)
        if not new_domain:
            rep.known += 1
            return None
        now = self._now()
        alert = Alert(
            id=_alert_id(primary.rule.id, key, serial), ts=_iso(now), rule_id=primary.rule.id, name=_clean(name, 512),
            registrable_domain=key, reason=primary.reason, cert_sha256=cert_sha256, issuer=issuer, not_before=not_before,
            serial=serial, source=source, tlp=self.tlp.value_str, technique=primary.technique, case_id=self.case_id,
            also=tuple(m.rule.id for m in unmuted[1:4]),
        )
        self._record_alert(alert, now)
        return alert

    def _address_match(self, address: str) -> tuple[tuple[Match, ...], str]:
        local, _, dom = address.rpartition("@")
        reg = _registrable(dom)
        if not local or not reg:
            return (), ""
        found = tuple(Match(r, f"address at the verified own domain {reg} (infostealer exposure)", "address")
                      for r in self.rules if r.kind == "own_addresses" and reg in r.domains)
        return found, address.lower()[:320]

    def _record_seen(self, rule_id: str, key: str, serial: str) -> bool:
        """Record first_seen (written with the next row batch); True when ``key`` is a new registrable
        domain for ``rule_id`` (neither in the case DB nor earlier in this batch)."""
        pk = (rule_id, key)
        if pk in self._seen_pending:
            known = True
        else:
            with self.store.connection() as conn:
                known = conn.execute("SELECT 1 FROM watch_first_seen WHERE rule_id = ? AND registrable_domain = ? LIMIT 1", pk).fetchone() is not None
        self._seen_pending.add(pk)
        self._rows.append((
            "INSERT OR IGNORE INTO watch_first_seen (rule_id, registrable_domain, cert_serial, first_seen, case_id) VALUES (?, ?, ?, ?, ?)",
            (rule_id, key, serial or "", _iso(self._now()), self.case_id),
        ))
        if len(self._rows) >= ROW_FLUSH:
            self._flush_rows()
        return not known

    def _flush_rows(self) -> None:
        """Write the pending alert and first_seen rows in one transaction."""
        if not self._rows:
            return
        rows, self._rows = self._rows, []
        with self.store.connection() as conn:
            for sql, params in rows:
                conn.execute(sql, params)
        self._seen_pending.clear()

    def _record_alert(self, alert: Alert, now: _dt.datetime) -> None:
        rep = self.report
        record = alert.to_record()
        self._rows.append(("INSERT OR IGNORE INTO alerts (id, rule_id, ts, payload, case_id) VALUES (?, ?, ?, ?, ?)",
                           (alert.id, alert.rule_id, alert.ts, json.dumps(record, ensure_ascii=False, sort_keys=True), alert.case_id)))
        self._append_jsonl(record, now)
        rep.alerts += 1
        self._pending_case.append(alert)
        hour = now.strftime("%Y-%m-%dT%H")
        if hour != self._hour:
            self._flush_hour_summary()
            self._hour, self._hour_count = hour, 0
        self._hour_count += 1
        if self._hour_count <= ALERTS_PER_HOUR_LINES:
            self._emit(alert.line(), "v.warn")
        else:
            self._hour_hidden += 1
            rep.summarized += 1
        if "/" not in alert.registrable_domain and "@" not in alert.registrable_domain and alert.registrable_domain not in self._enrich_seen:
            if len(self._enrich_seen) >= LRU_SIZE:  # memory cap (a re-queued domain is still capped per hour)
                self._enrich_seen.clear()
            self._enrich_seen.add(alert.registrable_domain)
            self._enrich_queue.append((alert.registrable_domain, alert))
        if self._max_alerts and rep.alerts >= self._max_alerts:
            self._stop_reason = "max_alerts"

    def _flush_hour_summary(self) -> None:
        if self._hour_hidden:
            self._emit(
                f"[!] {self._hour_hidden} more alert(s) in hour {self._hour}Z not shown individually (more than "
                f"{ALERTS_PER_HOUR_LINES} per hour): see ~/.v3lum/watch/alerts-*.jsonl or `v3lum watch alerts`; mute noisy rules with `v3lum watch mute`",
                "v.warn",
            )
            self._hour_hidden = 0

    def _append_jsonl(self, record: Mapping[str, Any], now: _dt.datetime) -> None:
        path = self.watch_dir() / f"alerts-{now.astimezone(_dt.timezone.utc):%Y-%m-%d}.jsonl"
        line = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            try:
                os.fchmod(fd, 0o600)
            except (AttributeError, OSError):  # pragma: no cover - non-POSIX
                pass
            os.write(fd, line)
        finally:
            os.close(fd)

    # -- the day's watch case ----------------------------------------------------------
    @property
    def case_id(self) -> str:
        return watch_case_id(self._now())

    def _flush_case(self, *, force: bool = True) -> None:
        """Write the pending rows, then the pending alerts into their day's watch case (correlations +
        entities); without ``force`` the case is rewritten at most every CASE_FLUSH_INTERVAL seconds."""
        self._flush_rows()
        if not self._pending_case and not self._cache_keys:
            return
        now_m = self.clock.monotonic()
        if not force and now_m - self._last_case_flush < CASE_FLUSH_INTERVAL:
            return
        self._last_case_flush = now_m
        pending, self._pending_case = self._pending_case, []
        by_case: dict[str, list[Alert]] = {}
        for alert in pending:
            by_case.setdefault(alert.case_id or self.case_id, []).append(alert)
        for case_id, alerts in by_case.items():
            try:
                self._save_case(case_id, alerts)
            except Exception as exc:  # noqa: BLE001 - the alert rows and JSONL are written already
                log.warning("watch case %s not updated: %s", case_id, type(exc).__name__)
                self.report.notes.append(f"watch case {case_id} not updated ({type(exc).__name__}): alerts are in the alerts table and JSONL")
        if self._cache_keys:
            keys, self._cache_keys = set(self._cache_keys), set()
            try:
                # recorded only for an existing watch case (its purge removes them); otherwise the HTTP
                # cache cap (cache_max_age_days) applies like for any cached response
                if self.store.case_info(self.case_id) is not None:
                    self.store.record_cache_keys(self.case_id, keys)
            except Exception as exc:  # noqa: BLE001
                log.debug("watch cache keys not recorded: %s", type(exc).__name__)
        self.report.case_id = self.case_id

    def _save_case(self, case_id: str, alerts: list[Alert]) -> None:
        from v3lum import __version__
        from v3lum.core import scoring

        case = self.store.get_case(case_id) if hasattr(self.store, "get_case") else None
        if not isinstance(case, dict) or case.get("case_id") != case_id:
            created = min(a.ts for a in alerts) if alerts else _iso(self._now())
            case = {
                "schema": "v3lum.case/2", "tool": {"name": "V3LUM", "version": __version__}, "case_id": case_id,
                "created": created, "kind": "watch", "tlp": self.tlp.value_str, "seeds": [],
                "options": {"tlp": self.tlp.value_str, "mode": "passive", "purpose": "v3lum watch: org-profile brand and domain monitoring (P030)"},
                "summary": {}, "risk": {}, "entities": [], "edges": [], "findings": [], "correlations": [], "modules": [],
                "coverage": {}, "notes": [
                    "v3lum watch case: one correlation per alert (certificate metadata only); every alert is also in the alerts table "
                    "and ~/.v3lum/watch/alerts-<date>.jsonl. Vote with `v3lum watch vote <alert id> right|wrong`.",
                ],
                "watch": {"alerts": 0, "rules": []},
            }
        try:
            case["tlp"] = _tlp.highest(case.get("tlp") or "", self.tlp).value_str
        except ValueError:
            case["tlp"] = self.tlp.value_str
        options = case.setdefault("options", {})
        if isinstance(options, dict):
            options["tlp"] = case["tlp"]
        corrs = [c for c in case.get("correlations") or [] if isinstance(c, dict)]
        have = {c.get("id") for c in corrs}
        nodes = [n for n in case.get("entities") or [] if isinstance(n, dict)]
        node_keys = {n.get("key") for n in nodes}
        watch_meta = case.setdefault("watch", {"alerts": 0, "rules": []})
        rules = set(watch_meta.get("rules") or [])
        added = 0
        for alert in alerts:
            if alert.id in have:
                continue
            have.add(alert.id)
            rules.add(alert.rule_id)
            added += 1
            if len(corrs) < CASE_ALERTS_MAX:
                corrs.append(alert.correlation())
            key = f"domain:{alert.registrable_domain}"
            if "/" not in alert.registrable_domain and "@" not in alert.registrable_domain and key not in node_keys and len(nodes) < CASE_ENTITIES_MAX:
                node_keys.add(key)
                nodes.append({"key": key, "type": "domain", "value": alert.registrable_domain, "tags": ["typosquat" if alert.technique else "brand_abuse"],
                              "tlp": alert.tlp, "depth": 0, "seed": False, "first_seen": alert.ts})
        watch_meta["alerts"] = int(watch_meta.get("alerts") or 0) + added
        watch_meta["rules"] = sorted(rules)
        if watch_meta["alerts"] > len(corrs):
            note = f"{watch_meta['alerts'] - len(corrs)} more alert(s) of this day are in the alerts table and the JSONL file only"
            case["notes"] = [n for n in case.get("notes") or [] if "more alert(s) of this day" not in str(n)] + [note]
        case["correlations"] = corrs
        case["entities"] = nodes
        score = 40.0 if corrs else 0.0
        case["summary"] = {
            "risk_score": score, "risk_level": scoring.level(score), "entities": len(nodes), "findings": 0,
            "correlations": len(corrs), "alerts": watch_meta["alerts"],
        }
        self.store.save_case(case)
        if self.tlp_change and case_id not in self._tlp_change_recorded:
            self._tlp_change_recorded.add(case_id)
            try:  # A2: a watch TLP below the configured default is recorded in the watch case's audit
                self.store.append_audit(case_id, "tlp_change", dict(self.tlp_change, path="watch"))
            except Exception as exc:  # noqa: BLE001 - reported, the alerts are stored already
                log.warning("watch case %s: tlp_change not audited: %s", case_id, type(exc).__name__)
                self.report.notes.append(f"the lowered TLP could not be recorded in the audit of {case_id} ({type(exc).__name__})")

    # -- enrichment ----------------------------------------------------------------------
    def _load_enrich_times(self) -> None:
        if self._enrich_loaded:
            return
        self._enrich_loaded = True
        stamps = sorted(t for t in (_parse_iso(x) for x in _state().get("enrich_times") or ()) if t is not None)
        self._enrich_times = collections.deque(stamps[-1000:])

    def _enrich_allowed(self) -> bool:
        self._load_enrich_times()
        per_hour = max(0, self._int_setting("watch_enrich_per_hour", DEFAULT_ENRICH_PER_HOUR))
        now = self._now()
        while self._enrich_times and now - self._enrich_times[0] >= _dt.timedelta(hours=1):
            self._enrich_times.popleft()
        return len(self._enrich_times) < per_hour

    def _list_for_analyst(self, domain: str) -> None:
        """A hit not enriched automatically: listed by name up to ENRICH_LISTED_MAX, then counted."""
        rep = self.report
        if len(rep.enrich_listed) < ENRICH_LISTED_MAX:
            rep.enrich_listed.append(domain)
        else:
            rep.enrich_listed_more += 1

    def enrich_pending(self, *, deadline: float | None = None) -> None:
        """Run the capped passive enrichment of queued hits (setting watch_enrich_per_hour per rolling
        hour); hits beyond the cap (or without time left) are listed for the analyst."""
        rep = self.report
        while self._enrich_queue:
            domain, alert = self._enrich_queue.popleft()
            if self._stop_reason == "interrupted":
                self._list_for_analyst(domain)
                continue
            if deadline is not None and deadline - self.clock.monotonic() < ENRICH_MIN_REMAINING:
                self._list_for_analyst(domain)
                continue
            if not self._enrich_allowed():
                self._list_for_analyst(domain)
                continue
            self._enrich_times.append(self._now())
            try:
                fn = self.enricher or self._default_enrich
                case_id = fn(domain, alert) or ""
                rep.enriched.append({"domain": domain, "alert": alert.id, "case_id": str(case_id)})
            except KeyboardInterrupt:
                raise
            except Exception as exc:  # noqa: BLE001 - one failed enrichment never stops the watch
                rep.enriched.append({"domain": domain, "alert": alert.id, "case_id": "", "error": _redact(f"{type(exc).__name__}: {exc}")})

    def _default_enrich(self, domain: str, alert: Alert) -> str:
        """A normal PASSIVE scan of the hit through the policy gate (depth 0, the watch TLP, watch
        sources excluded); the case is saved like any scan."""
        from v3lum.core.context import ScanOptions
        from v3lum.core.models import Opsec
        from v3lum.core.module import REGISTRY

        entity = Entity.make(EntityType.DOMAIN, domain)
        watch_only = {n for n, c in REGISTRY.items() if {"watch_only", "watch_source"} & set(getattr(c, "tags", ()) or ())}
        options = ScanOptions(
            mode=Opsec.PASSIVE, depth=0, max_entities=25, threads=4, include=set(self.enrich_modules or ()), exclude=watch_only,
            tlp=self.tlp.value_str, seed_tlp={entity.key: self.tlp.value_str}, offline=bool(getattr(self.runtime, "offline", False)),
            purpose=f"v3lum watch: passive enrichment of alert {alert.id} ({alert.rule_id})",
        )
        if self.tlp_change:  # A2: a TLP below the default is recorded in each enrichment case's audit
            options.tlp_change = dict(self.tlp_change)  # type: ignore[attr-defined] - read by the case audit (WP13)
        engine = _watch_engine(self.runtime, options)
        case = engine.investigate([entity])
        data = case.to_dict()
        data.setdefault("notes", []).append(f"passive enrichment of watch alert {alert.id} (rule {alert.rule_id}: {alert.reason})")
        self.store.save_case(data)
        try:
            self.store.record_cache_keys(case.case_id, getattr(case, "cache_keys", None) or ())
        except Exception as exc:  # noqa: BLE001
            log.debug("enrichment cache keys not recorded: %s", type(exc).__name__)
        return case.case_id

    # -- CertStream ------------------------------------------------------------------------
    def certstream_status(self, *, once: bool = False) -> dict[str, Any]:
        """Whether the CertStream consumer runs: ``{state ('running' | 'unavailable' | 'off'), detail,
        url, kind, disclosure, tier}``."""
        endpoint = certstream_endpoint(self.settings, self.org)
        base = {k: endpoint.get(k) for k in ("url", "kind", "disclosure", "tier")}
        base["url"] = _display_url(endpoint.get("url"))  # reports and screens never carry the endpoint's secret
        if not self.certstream_enabled:
            return dict(base, state="off", detail="disabled for this run (--no-certstream)")
        if self.transport is None and not certstream_available():
            return dict(base, state="unavailable", detail="optional extra not installed: pip install 'v3lum[watch]' (websocket-client); polling still runs")
        if once:
            return dict(base, state="off", detail="not consumed with --once (polling cycle only)")
        if bool(getattr(self.runtime, "offline", False)):
            return dict(base, state="unavailable", detail="offline mode")
        if endpoint.get("problem"):
            return dict(base, state="unavailable", detail=str(endpoint["problem"]))
        ceiling = _tlp.parse(endpoint.get("max_tlp") or "clear")
        if self.tlp > ceiling:
            return dict(base, state="unavailable",
                        detail=f"refused at {self.tlp.label}: the {endpoint['kind']} endpoint ({endpoint['disclosure']}, tier {endpoint['tier']}) is allowed up to {ceiling.label}")
        if self.matcher.empty:
            return dict(base, state="unavailable", detail="no rule applies to certificate names")
        return dict(base, state="running", detail="consumer started (local filtering; nothing is sent)")

    def _start_stream(self, status: Mapping[str, Any]) -> None:
        url = str(certstream_endpoint(self.settings, self.org).get("url") or status.get("url"))  # the full URL, only here
        self.consumer = CertStreamConsumer(url, self.matcher, transport=self.transport, clock=self.clock,
                                           rng=self.rng, config=self.settings)
        self.consumer.start()

    def drain_stream(self, limit: int = 2000) -> int:
        """Process up to ``limit`` queued certificates; returns how many were processed."""
        if self.consumer is None:
            return 0
        events = self.consumer.drain(limit)
        for event in events:
            if self._halted:
                break
            self.ingest_event(event)
        self._flush_rows()
        return len(events)

    # -- retention -------------------------------------------------------------------------
    def prune(self, now: _dt.datetime | None = None) -> dict[str, int]:
        """Delete what is older than ``retention_days`` (A10 BR1, P030 cond 10, A14 BR8): alert JSONL
        files, ``alerts`` rows, ``watch_first_seen`` rows and expired watch cases (through
        ``Store.purge_case``). Rows linked to held cases (and the alert files of held watch-case days)
        are kept. Returns the counts."""
        current = now or self._now()
        if current.tzinfo is None:
            current = current.replace(tzinfo=_dt.timezone.utc)
        try:
            days = int(self.store.retention_days())
        except Exception:  # noqa: BLE001
            days = self._int_setting("retention_days", 180)
        counts = {"files": 0, "alerts": 0, "first_seen": 0, "cases": 0}
        if days <= 0:
            return counts
        cutoff = current - _dt.timedelta(days=days)
        cutoff_iso = _iso(cutoff)
        try:
            held = {str(r.get("id")) for r in self.store.held_cases()}
        except Exception:  # noqa: BLE001
            held = set()
        held_list = sorted(held)
        marks = ",".join("?" for _ in held_list)
        exempt = f" AND (case_id IS NULL OR case_id NOT IN ({marks}))" if held_list else ""
        with self.store.connection() as conn:
            cur = conn.execute(f"DELETE FROM alerts WHERE ts < ?{exempt}", (cutoff_iso, *held_list))
            counts["alerts"] = max(0, cur.rowcount or 0)
            cur = conn.execute(f"DELETE FROM watch_first_seen WHERE first_seen < ?{exempt}", (cutoff_iso, *held_list))
            counts["first_seen"] = max(0, cur.rowcount or 0)
            expired = [r[0] for r in conn.execute("SELECT id, created FROM cases WHERE id LIKE 'watch-%' AND legal_hold = 0").fetchall()
                       if (_parse_iso(r[1]) or current) < cutoff]
        for case_id in expired:
            try:
                rep = self.store.purge_case(case_id, by="v3lum watch (retention)", now=current, vacuum=False)
                if getattr(rep, "found", False) and not getattr(rep, "held", False):
                    counts["cases"] += 1
            except Exception as exc:  # noqa: BLE001 - reported, never fatal
                log.warning("watch case %s not purged: %s", case_id, type(exc).__name__)
        held_days = {h[len("watch-"):] for h in held if h.startswith("watch-")}
        directory = paths.home() / "watch"
        if directory.is_dir():
            for path in directory.glob("alerts-*.jsonl"):
                match = re.match(r"^alerts-(\d{4})-(\d{2})-(\d{2})\.jsonl$", path.name)
                if not match:
                    continue
                day = _dt.datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)), tzinfo=_dt.timezone.utc)
                if day + _dt.timedelta(days=1) <= cutoff and "".join(match.groups()) not in held_days:
                    try:
                        path.unlink()
                        counts["files"] += 1
                    except OSError as exc:
                        log.warning("watch alert file %s not removed: %s", path.name, type(exc).__name__)
        if counts["cases"]:
            try:
                self.store.vacuum()
            except Exception:  # noqa: BLE001
                pass
        return counts

    # -- state -------------------------------------------------------------------------------
    def _save_state(self, **extra: Any) -> None:
        path = paths.home() / "watch" / "state.json"
        try:
            state = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        except (OSError, ValueError):
            state = {}
        if not isinstance(state, dict):
            state = {}
        state.update(extra)
        state["sources"] = {**(state.get("sources") or {}), **self.report.sources}
        if self._enrich_loaded:
            state["enrich_times"] = [_iso(t) for t in self._enrich_times]
        if self._hour:  # the 200-lines-per-hour budget holds across `--once` runs of the same hour
            state["alert_hour"], state["alert_hour_count"] = self._hour, int(self._hour_count)
        if self.consumer is not None:
            state["certstream"] = {"stats": self.consumer.stats.to_dict(), "at": _iso(self._now())}
        try:
            paths.secure_write_text(self.watch_dir() / "state.json", json.dumps(state, sort_keys=True, default=str))
        except OSError as exc:  # pragma: no cover - read-only home
            log.warning("watch state not saved: %s", type(exc).__name__)

    # -- the loop --------------------------------------------------------------------------
    def stop(self, reason: str = "interrupted") -> None:
        """Ask the loop to stop at the next check (Ctrl+C, a caller's own bound)."""
        self._stop_reason = reason or "interrupted"

    def run(
        self,
        *,
        once: bool = False,
        max_runtime: float | None = None,
        max_alerts: int | None = None,
        interval: float | None = None,
    ) -> WatchReport:
        """The foreground watch loop: prune, then polling cycles every ``interval`` seconds (setting
        watch_interval, at least :data:`MIN_INTERVAL`) with the CertStream queue drained in between,
        until ``once`` (one bounded cycle), ``max_runtime`` seconds (setting watch_max_runtime, 8 h),
        ``max_alerts`` alerts (setting watch_max_alerts, 0 = unlimited) or Ctrl+C. Never a daemon."""
        rep = self.report = WatchReport(tlp=self.tlp.value_str, started=_iso(self._now()))
        self._stop_reason = ""
        self._max_alerts = max(0, int(max_alerts if max_alerts is not None else self._int_setting("watch_max_alerts", 0)))
        runtime_s = float(max_runtime) if max_runtime not in (None, 0) else float(self._int_setting("watch_max_runtime", DEFAULT_MAX_RUNTIME))
        if runtime_s <= 0:
            runtime_s = float(DEFAULT_MAX_RUNTIME)
        runtime_s = min(runtime_s, float(MAX_RUNTIME_CAP))
        interval_s = float(interval) if interval else float(self._int_setting("watch_interval", DEFAULT_INTERVAL))
        interval_s = max(float(MIN_INTERVAL), interval_s)
        rep.notes.extend(self.problems)
        try:
            rep.pruned = self.prune()
        except Exception as exc:  # noqa: BLE001 - retention problems are reported, the watch goes on
            rep.notes.append(f"retention prune failed ({type(exc).__name__})")
        if not self.rules:
            rep.stop_reason = "no_rules"
            rep.finished = _iso(self._now())
            return rep
        saved = _state()
        if saved.get("alert_hour") == self._now().strftime("%Y-%m-%dT%H"):  # same clock hour as an earlier run
            self._hour = str(saved["alert_hour"])
            try:
                self._hour_count = max(self._hour_count, int(saved.get("alert_hour_count") or 0))
            except (TypeError, ValueError):
                pass
        rep.certstream = self.certstream_status(once=once)
        start = self.clock.monotonic()
        end = start + runtime_s
        try:
            if rep.certstream.get("state") == "running":
                self._start_stream(rep.certstream)
            next_cycle = start
            while True:
                if self._stop_reason:
                    break
                now_m = self.clock.monotonic()
                if now_m >= end:
                    self._stop_reason = "max_runtime"
                    break
                if now_m >= next_cycle:
                    cycle_start = now_m
                    self.poll_cycle(deadline=end)
                    next_cycle = cycle_start + interval_s
                if self.clock.monotonic() - self._mutes_loaded >= MUTE_RELOAD:
                    self._load_mutes()  # `v3lum watch mute` from another terminal applies within a minute
                self.drain_stream()
                self.enrich_pending(deadline=end)
                self._flush_case(force=self.consumer is None)
                if once and not self._stop_reason:
                    self._stop_reason = "once"
                if self._stop_reason:
                    break
                wait = min(next_cycle, end) - self.clock.monotonic()
                if wait > 0:
                    self._sleep(min(wait, TICK) if self.consumer is not None else wait)
        except KeyboardInterrupt:
            self._stop_reason = "interrupted"
        finally:
            if self.consumer is not None:
                self.consumer.stop()
                if self._stop_reason != "interrupted":
                    self.drain_stream(limit=QUEUE_MAX_ITEMS)
                rep.stream = self.consumer.stats.to_dict()
            if self._enrich_queue and self._stop_reason in ("interrupted", "max_alerts", "max_runtime"):
                for domain, _alert in self._enrich_queue:
                    self._list_for_analyst(domain)
                self._enrich_queue.clear()
            self._flush_hour_summary()
            try:
                self._flush_case()
            except Exception as exc:  # noqa: BLE001
                rep.notes.append(f"watch case not saved ({type(exc).__name__})")
            self._save_state(last_run=_iso(self._now()), last_stop=self._stop_reason)
            rep.stop_reason = self._stop_reason
            rep.finished = _iso(self._now())
            ran = [s for s in rep.sources.values() if s.get("reason_code") != "opsec"]
            if rep.cycles and ran and not any(s.get("status") in ("ok", "empty") for s in ran):
                rep.notes.append("no polling source answered in this run: could not verify (no alert does not mean nothing new)")
        return rep

    def _sleep(self, seconds: float) -> None:
        remaining = max(0.0, float(seconds))
        while remaining > 0 and not self._stop_reason:
            step = min(remaining, 1.0)
            self.clock.sleep(step)
            remaining -= step


# ======================================================================================
# health (doctor, `v3lum watch status`)
# ======================================================================================


def _state() -> dict[str, Any]:
    path = paths.home() / "watch" / "state.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except (OSError, ValueError):
        data = {}
    return data if isinstance(data, dict) else {}


def health(
    config: Any = None,
    *,
    org: Any = None,
    transport: Any = None,
    probe: bool = False,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Watch-mode health for doctor and ``v3lum watch status`` (P030 cond 11).

    ``{'certstream': {available, extra, url, kind, disclosure, tier, max_tlp, reachable, detail},
    'polling_sources': [{module, title, disclosure, ready, reason, last_status, last_reason, last_at}],
    'rules': int | None, 'last_cycle': str, 'last_run': str}``. ``reachable`` is None unless ``probe``:
    then one connection is opened and closed at once (nothing is sent) with ``timeout`` seconds -
    True / False ('could not verify' with the error class, never 'absent'). Without the optional extra
    the consumer is reported unavailable (``available`` False), not an error.
    """
    from v3lum.core.models import Opsec
    from v3lum.core.module import REGISTRY, readiness_check

    if config is None:
        try:
            from v3lum.config import Config

            config = Config.load()
        except Exception:  # noqa: BLE001
            config = None
    state = _state()
    endpoint = certstream_endpoint(config, org)
    available = certstream_available()
    cs: dict[str, Any] = dict(endpoint, available=available, extra="watch", package="websocket-client", reachable=None)
    cs["url"] = _display_url(endpoint.get("url"))  # never a configured endpoint's credentials or token
    if not available and transport is None:
        cs["detail"] = "optional extra not installed: pip install 'v3lum[watch]' - the CertStream consumer is unavailable (polling still works)"
    elif endpoint.get("problem"):
        cs["detail"] = str(endpoint["problem"])
    elif probe:
        conn = None
        try:
            conn = (transport or WebSocketTransport(config)).connect(str(endpoint["url"]), timeout=float(timeout))
            cs["reachable"], cs["detail"] = True, "handshake ok (connection closed at once; nothing sent)"
        except Exception as exc:  # noqa: BLE001 - could not verify, never 'absent'
            text = f"could not connect: {type(exc).__name__}: {exc}".replace(str(endpoint["url"]), str(cs["url"]))
            status = _http_status(exc)
            cs["reachable"], cs["detail"] = False, _redact(text + (f" (HTTP {status}: could not verify)" if status else ""))
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
    else:
        cs["detail"] = "not probed (doctor probes with one handshake)"
    last_stats = (state.get("certstream") or {}).get("stats") if isinstance(state.get("certstream"), dict) else None
    if last_stats:
        cs["last_stats"] = last_stats
    keys: Mapping[str, str] = {}
    keys_fn = getattr(config, "keys", None)
    if callable(keys_fn):
        try:
            keys = keys_fn() or {}
        except Exception:  # noqa: BLE001
            keys = {}
    seen_sources = state.get("sources") if isinstance(state.get("sources"), dict) else {}
    sources = []
    for name in sorted(REGISTRY):
        cls = REGISTRY[name]
        if "watch_source" not in (getattr(cls, "tags", ()) or ()):
            continue
        try:
            ready = readiness_check(cls, keys, Opsec.PASSIVE)
            is_ready, reason = bool(ready.ready), str(ready.reason or "")
        except Exception as exc:  # noqa: BLE001
            is_ready, reason = False, f"readiness check failed ({type(exc).__name__})"
        last = seen_sources.get(name) if isinstance(seen_sources.get(name), dict) else {}
        sources.append({
            "module": name, "title": str(getattr(cls, "title", "") or ""), "disclosure": str(getattr(cls, "disclosure", "") or ""),
            "watch_only": "watch_only" in (getattr(cls, "tags", ()) or ()), "ready": is_ready, "reason": reason,
            "last_status": str(last.get("status") or ""), "last_reason": str(last.get("reason") or ""), "last_at": str(last.get("at") or ""),
        })
    rules = len(rules_from_profile(org)) if org is not None else None
    return {
        "certstream": cs, "polling_sources": sources, "rules": rules,
        "last_cycle": str(state.get("last_cycle") or ""), "last_run": str(state.get("last_run") or ""),
        "last_stop": str(state.get("last_stop") or ""),
    }
