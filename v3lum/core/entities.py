"""Entity types, canonical normalization, privacy type sets and masking (module contract v2, section 20).

An :class:`Entity` is an observable (email, domain, IP, hash...) identified by its type and its
*normalized* value, so the same thing found by two modules collapses into one node of the investigation
graph. ``normalize()`` raises ``ValueError`` for invalid values and never stores a raw secret or a full
card number: ``telegram_bot_token`` and ``secret`` are stored as fingerprints
``'<kind>:<first4>…<last4>:<sha256[:16]>'`` and ``payment_card`` as ``'<BIN6>…<last4>'``.

Type sets (A8): :data:`PERSONAL_TYPES` (never auto-expanded from text, never sent to unknown-tier
providers), :data:`IOC_TYPES`, :data:`SECRET_TYPES` (detect-only, never sent or exported),
:data:`NO_AUTO_EXPAND` and :data:`COMPANY_ID_TYPES` (CNPJ, EU VAT: treated like personal data for
unknown-tier providers, A8 BR4). :data:`STIX_SCO` maps every type to its STIX 2.1 cyber-observable type
(None = no STIX object).

Masking (AR24): :func:`display_value` masks CPF (``***.456.789-**``), VIN (first 11 + ``******``) and
secrets (previews) unless ``show_personal=True`` (secrets are never shown); :func:`redacted_value` is the
persist/export-safe form (same masks regardless of show_personal; secrets as fingerprints).

Social platforms: :data:`SOCIAL_PLATFORMS` is the core set merged with fragments
``v3lum/data/platforms/<name>.json`` (schema ``'v3lum.platforms/1'``), live-updated by
:func:`reload_platforms`; :func:`platform_for_url` maps a profile URL to ``(platform, handle)``.
"""

from __future__ import annotations

import enum
import hashlib
import ipaddress
import json
import os
import re
import threading
from collections.abc import Iterable, Iterator, Set
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from v3lum.core import validators as val


class EntityType(str, enum.Enum):
    """Every kind of datum V3LUM understands. Values are stable identifiers."""

    EMAIL = "email"
    DOMAIN = "domain"
    URL = "url"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    ASN = "asn"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    SSDEEP = "ssdeep"
    PHONE = "phone"
    USERNAME = "username"
    PERSON = "person_name"
    ORG = "company_name"
    CNPJ = "cnpj"
    CPF = "cpf"
    CEP = "cep"
    BTC = "btc_address"
    ETH = "eth_address"
    XMR = "xmr_address"
    CRYPTO = "other_crypto_address"
    CVE = "cve"
    MITRE = "mitre_technique"
    THREAT_ACTOR = "threat_actor"
    MALWARE = "malware_family"
    MAC = "mac_address"
    FILE = "file"
    ONION = "onion"
    PLATE_BR = "plate_br"
    PIX = "pix_key"
    BOLETO = "boleto"
    KEYWORD = "keyword"
    USER_AGENT = "user_agent"
    JWT = "jwt"
    ANALYTICS_ID = "analytics_id"
    CARD_BIN = "card_bin"
    COORDINATES = "coordinates"
    IMEI = "imei"
    FAVICON_HASH = "favicon_hash"
    CERT_FP = "cert_fingerprint"
    TEXT = "text_blob"
    # ---- contract v2 (P333 first and second wave)
    EMAIL_HEADERS = "email_headers"
    TELEGRAM_HANDLE = "telegram_handle"
    TELEGRAM_INVITE = "telegram_invite"
    DISCORD_INVITE = "discord_invite"
    SOCIAL_ACCOUNT = "social_account"
    PIX_BRCODE = "pix_brcode"
    IMPHASH = "imphash"
    TLSH = "tlsh"
    TELFHASH = "telfhash"
    GIMPHASH = "gimphash"
    AUTHENTIHASH = "authentihash"
    ICON_DHASH = "icon_dhash"
    CODE_SIGNING_CERT = "code_signing_cert"
    PGP_FINGERPRINT = "pgp_fingerprint"
    FEDIVERSE_HANDLE = "fediverse_handle"
    BSKY_HANDLE = "bsky_handle"
    STEAM_PROFILE = "steam_profile"
    PORT_SERVICE = "port_service"
    VIN = "vin"
    TELEGRAM_BOT_TOKEN = "telegram_bot_token"
    SECRET = "secret"
    PAYMENT_CARD = "payment_card"
    # ---- P333 P3 slip types (team-lead scope extension 2026-11-26)
    EU_VAT = "eu_vat"
    TIKTOK_VIDEO_ID = "tiktok_video_id"
    SNOWFLAKE_ID = "snowflake_id"

    @property
    def label(self) -> str:
        return TYPE_LABELS.get(self, self.value)

    @classmethod
    def parse(cls, name: str) -> EntityType:
        """Accept a value ('ipv4'), a member name ('IPV4') or a friendly alias ('ip')."""
        key = (name or "").strip().lower().replace("-", "_")
        if key in _ALIASES:
            return _ALIASES[key]
        for member in cls:
            if member.value == key or member.name.lower() == key:
                return member
        raise ValueError(f"unknown entity type: {name!r}")


TYPE_LABELS: dict[EntityType, str] = {
    EntityType.EMAIL: "Email address",
    EntityType.DOMAIN: "Domain",
    EntityType.URL: "URL",
    EntityType.IPV4: "IPv4 address",
    EntityType.IPV6: "IPv6 address",
    EntityType.CIDR: "Network range (CIDR)",
    EntityType.ASN: "Autonomous System",
    EntityType.MD5: "MD5 hash",
    EntityType.SHA1: "SHA-1 hash",
    EntityType.SHA256: "SHA-256 hash",
    EntityType.SHA512: "SHA-512 hash",
    EntityType.SSDEEP: "ssdeep fuzzy hash",
    EntityType.PHONE: "Phone number",
    EntityType.USERNAME: "Username / handle",
    EntityType.PERSON: "Person name",
    EntityType.ORG: "Company / organization",
    EntityType.CNPJ: "CNPJ (BR company id)",
    EntityType.CPF: "CPF (BR taxpayer id)",
    EntityType.CEP: "CEP (BR postal code)",
    EntityType.BTC: "Bitcoin address",
    EntityType.ETH: "Ethereum/EVM address",
    EntityType.XMR: "Monero address",
    EntityType.CRYPTO: "Crypto address (other chain)",
    EntityType.CVE: "CVE identifier",
    EntityType.MITRE: "MITRE ATT&CK technique",
    EntityType.THREAT_ACTOR: "Threat actor",
    EntityType.MALWARE: "Malware family",
    EntityType.MAC: "MAC address",
    EntityType.FILE: "Local file",
    EntityType.ONION: "Tor onion service",
    EntityType.PLATE_BR: "BR vehicle plate",
    EntityType.PIX: "PIX key (EVP)",
    EntityType.BOLETO: "Boleto (linha digitavel)",
    EntityType.KEYWORD: "Keyword",
    EntityType.USER_AGENT: "User-Agent string",
    EntityType.JWT: "JSON Web Token",
    EntityType.ANALYTICS_ID: "Analytics / ads tracking id",
    EntityType.CARD_BIN: "Payment card BIN",
    EntityType.COORDINATES: "GPS coordinates",
    EntityType.IMEI: "IMEI",
    EntityType.FAVICON_HASH: "Favicon hash (mmh3)",
    EntityType.CERT_FP: "Certificate fingerprint",
    EntityType.TEXT: "Free text (IOC extraction)",
    EntityType.EMAIL_HEADERS: "Email header block",
    EntityType.TELEGRAM_HANDLE: "Telegram username",
    EntityType.TELEGRAM_INVITE: "Telegram invite code",
    EntityType.DISCORD_INVITE: "Discord invite code",
    EntityType.SOCIAL_ACCOUNT: "Social media account (platform:handle)",
    EntityType.PIX_BRCODE: "PIX BR Code (QR payload)",
    EntityType.IMPHASH: "PE import hash (imphash)",
    EntityType.TLSH: "TLSH fuzzy hash",
    EntityType.TELFHASH: "telfhash (ELF symbol TLSH)",
    EntityType.GIMPHASH: "Go import hash (gimphash)",
    EntityType.AUTHENTIHASH: "Authenticode hash (authentihash)",
    EntityType.ICON_DHASH: "Icon dHash",
    EntityType.CODE_SIGNING_CERT: "Code-signing certificate",
    EntityType.PGP_FINGERPRINT: "OpenPGP key fingerprint",
    EntityType.FEDIVERSE_HANDLE: "Fediverse handle (user@instance)",
    EntityType.BSKY_HANDLE: "Bluesky handle",
    EntityType.STEAM_PROFILE: "Steam profile",
    EntityType.PORT_SERVICE: "Network service (host:port/proto)",
    EntityType.VIN: "Vehicle identification number (VIN)",
    EntityType.TELEGRAM_BOT_TOKEN: "Telegram bot token (masked)",
    EntityType.SECRET: "Secret / credential (masked)",
    EntityType.PAYMENT_CARD: "Payment card (BIN + last 4)",
    EntityType.EU_VAT: "EU VAT number",
    EntityType.TIKTOK_VIDEO_ID: "TikTok video id",
    EntityType.SNOWFLAKE_ID: "Snowflake id (Discord/X)",
}

_ALIASES: dict[str, EntityType] = {
    "ip": EntityType.IPV4,
    "ipv4": EntityType.IPV4,
    "ipv6": EntityType.IPV6,
    "net": EntityType.CIDR,
    "range": EntityType.CIDR,
    "as": EntityType.ASN,
    "host": EntityType.DOMAIN,
    "hostname": EntityType.DOMAIN,
    "subdomain": EntityType.DOMAIN,
    "mail": EntityType.EMAIL,
    "e_mail": EntityType.EMAIL,
    "user": EntityType.USERNAME,
    "handle": EntityType.USERNAME,
    "nick": EntityType.USERNAME,
    "name": EntityType.PERSON,
    "person": EntityType.PERSON,
    "company": EntityType.ORG,
    "org": EntityType.ORG,
    "organization": EntityType.ORG,
    "tel": EntityType.PHONE,
    "telephone": EntityType.PHONE,
    "mobile": EntityType.PHONE,
    "btc": EntityType.BTC,
    "bitcoin": EntityType.BTC,
    "eth": EntityType.ETH,
    "ethereum": EntityType.ETH,
    "xmr": EntityType.XMR,
    "monero": EntityType.XMR,
    "wallet": EntityType.CRYPTO,
    "hash": EntityType.SHA256,
    "mitre": EntityType.MITRE,
    "technique": EntityType.MITRE,
    "attack": EntityType.MITRE,
    "actor": EntityType.THREAT_ACTOR,
    "apt": EntityType.THREAT_ACTOR,
    "malware": EntityType.MALWARE,
    "family": EntityType.MALWARE,
    "mac": EntityType.MAC,
    "path": EntityType.FILE,
    "plate": EntityType.PLATE_BR,
    "placa": EntityType.PLATE_BR,
    "pix": EntityType.PIX,
    "ua": EntityType.USER_AGENT,
    "useragent": EntityType.USER_AGENT,
    "bin": EntityType.CARD_BIN,
    "gps": EntityType.COORDINATES,
    "coords": EntityType.COORDINATES,
    "geo": EntityType.COORDINATES,
    "text": EntityType.TEXT,
    "blob": EntityType.TEXT,
    "kw": EntityType.KEYWORD,
    "keyword": EntityType.KEYWORD,
    "favicon": EntityType.FAVICON_HASH,
    "cert": EntityType.CERT_FP,
    # contract v2
    "headers": EntityType.EMAIL_HEADERS,
    "telegram": EntityType.TELEGRAM_HANDLE,
    "tg": EntityType.TELEGRAM_HANDLE,
    "discord": EntityType.DISCORD_INVITE,
    "social": EntityType.SOCIAL_ACCOUNT,
    "brcode": EntityType.PIX_BRCODE,
    "pgp": EntityType.PGP_FINGERPRINT,
    "gpg": EntityType.PGP_FINGERPRINT,
    "fediverse": EntityType.FEDIVERSE_HANDLE,
    "mastodon": EntityType.FEDIVERSE_HANDLE,
    "bsky": EntityType.BSKY_HANDLE,
    "bluesky": EntityType.BSKY_HANDLE,
    "steam": EntityType.STEAM_PROFILE,
    "port": EntityType.PORT_SERVICE,
    "service": EntityType.PORT_SERVICE,
    "vin": EntityType.VIN,
    "card": EntityType.PAYMENT_CARD,
    "vat": EntityType.EU_VAT,
    "snowflake": EntityType.SNOWFLAKE_ID,
}


@dataclass(frozen=True, order=True)
class Entity:
    """An observable identified by (type, normalized value).

    Build entities with :meth:`make`/:meth:`try_make` (normalized and validated); raw secrets go through
    :func:`secret_entity`. As a last line of defence a SECRET/TELEGRAM_BOT_TOKEN/PAYMENT_CARD entity built
    directly from a raw value is coerced to its fingerprint / ``BIN6…last4`` form, so no Entity ever holds
    a raw secret or a full card number (P323 cond 5-6).
    """

    type: EntityType
    value: str

    def __post_init__(self) -> None:
        if self.type in _COERCED_TYPES:
            safe = _coerce_secret_value(self.type, self.value)
            if safe != self.value:
                object.__setattr__(self, "value", safe)

    @property
    def key(self) -> str:
        return f"{self.type.value}:{self.value}"

    @property
    def display(self) -> str:
        """Masked human-friendly form (CPF/VIN/secrets masked): see :func:`display_value`."""
        return display_value(self.type, self.value)

    @property
    def redacted(self) -> str:
        """Persist/export-safe form: see :func:`redacted_value`."""
        return redacted_value(self.type, self.value)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.display

    @classmethod
    def make(cls, etype: EntityType | str, raw: str) -> Entity:
        """Build an entity, normalizing (and validating) the raw value. Raises ValueError."""
        if not isinstance(etype, EntityType):
            etype = EntityType.parse(str(etype))
        return cls(etype, normalize(etype, raw))

    @classmethod
    def try_make(cls, etype: EntityType | str, raw: str) -> Entity | None:
        try:
            return cls.make(etype, raw)
        except (ValueError, TypeError):
            return None


# --------------------------------------------------------------------------------------
# Type sets (A8) and the STIX mapping
# --------------------------------------------------------------------------------------

_T = EntityType

#: Personal identifiers (A8, P333 cond 5): never auto-expanded from text/file inputs, excluded from
#: cross-case sightings by default, never sent to unknown-tier providers.
PERSONAL_TYPES: frozenset[EntityType] = frozenset({
    _T.EMAIL, _T.PHONE, _T.USERNAME, _T.PERSON, _T.CPF, _T.PIX, _T.PLATE_BR, _T.IMEI, _T.COORDINATES,
    _T.SOCIAL_ACCOUNT, _T.TELEGRAM_HANDLE, _T.TELEGRAM_INVITE, _T.DISCORD_INVITE, _T.FEDIVERSE_HANDLE,
    _T.BSKY_HANDLE, _T.STEAM_PROFILE, _T.VIN, _T.EMAIL_HEADERS, _T.PIX_BRCODE, _T.PGP_FINGERPRINT,
})

#: Indicator types (A8): the only values unknown-tier providers may receive, and the only types that
#: auto-expand from text/file inputs.
IOC_TYPES: frozenset[EntityType] = frozenset({
    _T.DOMAIN, _T.URL, _T.IPV4, _T.IPV6, _T.CIDR, _T.ASN, _T.MD5, _T.SHA1, _T.SHA256, _T.SHA512, _T.SSDEEP,
    _T.CVE, _T.MITRE, _T.ONION, _T.BTC, _T.ETH, _T.XMR, _T.CRYPTO, _T.FAVICON_HASH, _T.CERT_FP,
    _T.ANALYTICS_ID, _T.IMPHASH, _T.TLSH, _T.TELFHASH, _T.GIMPHASH, _T.AUTHENTIHASH, _T.ICON_DHASH,
    _T.CODE_SIGNING_CERT, _T.PORT_SERVICE,
})

#: Detect-only secrets (P333 cond 7, P323 cond 6): masked, never validated/used, never sent or exported.
SECRET_TYPES: frozenset[EntityType] = frozenset({_T.JWT, _T.TELEGRAM_BOT_TOKEN, _T.SECRET, _T.PAYMENT_CARD})

#: Never investigated automatically (the analyst decides): privacy and blast radius.
NO_AUTO_EXPAND: frozenset[EntityType] = frozenset({
    _T.TEXT, _T.FILE, _T.KEYWORD, _T.PERSON, _T.USER_AGENT, _T.CPF, _T.COORDINATES, _T.CARD_BIN, _T.IMEI,
    _T.EMAIL_HEADERS, _T.PORT_SERVICE, _T.PIX_BRCODE,
}) | SECRET_TYPES

#: Company identifiers: like PERSONAL_TYPES they never reach unknown-tier providers or links (A8 BR4).
COMPANY_ID_TYPES: frozenset[EntityType] = frozenset({_T.CNPJ, _T.EU_VAT})

_HASH_TYPES = (
    _T.MD5, _T.SHA1, _T.SHA256, _T.SHA512, _T.SSDEEP, _T.IMPHASH, _T.TLSH, _T.TELFHASH, _T.GIMPHASH,
    _T.AUTHENTIHASH, _T.ICON_DHASH, _T.FAVICON_HASH,
)
_ACCOUNT_TYPES = (_T.USERNAME, _T.SOCIAL_ACCOUNT, _T.TELEGRAM_HANDLE, _T.FEDIVERSE_HANDLE, _T.BSKY_HANDLE, _T.STEAM_PROFILE)

#: STIX 2.1 cyber-observable type per entity type (None = no STIX object). CIDR maps to 'ipv4-addr'
#: (an IPv6 block is 'ipv6-addr': use :func:`stix_sco_type` for the per-value answer). Secrets are never
#: exported. CVE, ATT&CK, actors and malware are SDOs, not SCOs (None here).
STIX_SCO: dict[EntityType, str | None] = {member: None for member in EntityType}
STIX_SCO.update({
    _T.DOMAIN: "domain-name",
    _T.ONION: "domain-name",
    _T.URL: "url",
    _T.IPV4: "ipv4-addr",
    _T.IPV6: "ipv6-addr",
    _T.CIDR: "ipv4-addr",
    _T.EMAIL: "email-addr",
    _T.ASN: "autonomous-system",
    _T.MAC: "mac-addr",
    _T.FILE: "file",
    _T.CERT_FP: "x509-certificate",
    _T.CODE_SIGNING_CERT: "x509-certificate",
    _T.EMAIL_HEADERS: "email-message",
})
STIX_SCO.update({t: "file" for t in _HASH_TYPES})
STIX_SCO.update({t: "user-account" for t in _ACCOUNT_TYPES})


def _as_type(etype: EntityType | Entity | str) -> EntityType | None:
    if isinstance(etype, Entity):
        return etype.type
    if isinstance(etype, EntityType):
        return etype
    try:
        return EntityType.parse(str(etype))
    except ValueError:
        return None


def is_personal(etype: EntityType | Entity | str) -> bool:
    """True for PERSONAL_TYPES (accepts a type, a type name or an Entity)."""
    return _as_type(etype) in PERSONAL_TYPES


def is_ioc(etype: EntityType | Entity | str) -> bool:
    """True for IOC_TYPES (accepts a type, a type name or an Entity)."""
    return _as_type(etype) in IOC_TYPES


def is_secret(etype: EntityType | Entity | str) -> bool:
    """True for SECRET_TYPES (accepts a type, a type name or an Entity)."""
    return _as_type(etype) in SECRET_TYPES


def is_company_id(etype: EntityType | Entity | str) -> bool:
    """True for COMPANY_ID_TYPES (CNPJ, EU VAT)."""
    return _as_type(etype) in COMPANY_ID_TYPES


def stix_sco_type(etype: EntityType, value: str = "") -> str | None:
    """STIX SCO type for one value (an IPv6 CIDR is 'ipv6-addr'); None when there is no STIX object."""
    if etype is EntityType.CIDR and ":" in (value or ""):
        return "ipv6-addr"
    return STIX_SCO.get(etype)


# --------------------------------------------------------------------------------------
# Defang / refang
# --------------------------------------------------------------------------------------

_REFANG_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}"), "."),
    (re.compile(r"\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}", re.I), "."),
    # (?<!\s): a match only starts at the beginning of a whitespace run (same result as r"\s+dot\s+",
    # but linear: the unanchored \s+ was quadratic on long whitespace runs in pasted text).
    (re.compile(r"(?<!\s)\s+dot\s+", re.I), "."),
    (re.compile(r"\[\s*@\s*\]|\(\s*@\s*\)|\{\s*@\s*\}"), "@"),
    (re.compile(r"\[\s*at\s*\]|\(\s*at\s*\)|\{\s*at\s*\}", re.I), "@"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
    (re.compile(r"\bhxxp(s?)", re.I), r"http\1"),
    (re.compile(r"\bh\*\*p(s?)", re.I), r"http\1"),
    (re.compile(r"\bfxp\b", re.I), "ftp"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\\\."), "."),
]


def refang(text: str) -> str:
    """Undo common defanging: ``hxxp://evil[.]com`` -> ``http://evil.com``."""
    out = text
    for pat, rep in _REFANG_RULES:
        out = pat.sub(rep, out)
    return out


_RE_SCHEME = re.compile(r"^([a-z][a-z0-9+.-]{0,31})://(.*)$", re.I | re.S)


def _defang_host(part: str) -> str:
    return part.replace(".", "[.]").replace("@", "[@]")


def defang(value: str) -> str:
    """Make an IOC safe to paste in tickets/chats and non-clickable (AR13).

    ``http://evil.com/x`` -> ``hxxp://evil[.]com/x``; ``ftp://`` -> ``fxp://``; other schemes get
    ``[://]``; dots and '@' of the host part (domains, IPs, e-mails) are bracketed while paths stay
    readable. Idempotent: an already defanged value is refanged first.
    """
    v = refang(str(value))
    m = _RE_SCHEME.match(v)
    if m:
        scheme, rest = m.group(1), m.group(2)
        low = scheme.lower()
        if low in ("http", "https"):
            prefix = "hxxps://" if low == "https" else "hxxp://"
        elif low == "ftp":
            prefix = "fxp://"
        else:
            prefix = scheme + "[://]"
        cut = re.search(r"[/?#]", rest)
        netloc, tail = (rest[: cut.start()], rest[cut.start() :]) if cut else (rest, "")
        return prefix + _defang_host(netloc) + tail
    cut = re.search(r"[/?#]", v)
    head, tail = (v[: cut.start()], v[cut.start() :]) if cut else (v, "")
    return _defang_host(head) + tail


# --------------------------------------------------------------------------------------
# Normalization helpers
# --------------------------------------------------------------------------------------

_WS = re.compile(r"\s+")
_HEX = re.compile(r"^[0-9a-f]+$")
_HASH_LEN = {EntityType.MD5: 32, EntityType.SHA1: 40, EntityType.SHA256: 64, EntityType.SHA512: 128}
_DOMAIN_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
#: 'lat,lon' / 'lat; lon' / 'lat lon': the separator is ',' or ';' with optional whitespace, or a
#: whitespace run containing a space (linear rewrite of r"\s*[,; ]\s*").
_RE_COORDINATES = re.compile(r"^\s*(-?\d{1,2}(?:\.\d+)?)(?:\s*[,;]\s*|[^\S ]* \s*)(-?\d{1,3}(?:\.\d+)?)\s*$")


def _collapse(raw: str) -> str:
    return _WS.sub(" ", raw).strip()


def normalize_domain(raw: str) -> str:
    v = refang(raw).strip().strip("'\"<>()[]{},;").lower()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)  # tolerate a scheme
    v = v.split("/")[0].split("?")[0].split("#")[0]
    if "@" in v:
        v = v.rsplit("@", 1)[1]
    v = re.sub(r":\d+$", "", v)
    v = v.rstrip(".")
    if not v or "." not in v:
        raise ValueError("not a domain")
    try:
        v = v.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        pass
    labels = v.split(".")
    if len(v) > 253 or not all(_DOMAIN_LABEL.match(lbl) for lbl in labels):
        raise ValueError("invalid domain")
    if labels[-1].isdigit():
        raise ValueError("looks like an IP address")
    return v


def normalize_url(raw: str) -> str:
    v = refang(raw).strip().strip("'\"<>")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", v, flags=re.I):
        v = "http://" + v
    m = re.match(r"^([a-z][a-z0-9+.-]*)://([^/?#]+)(.*)$", v, flags=re.I)
    if not m:
        raise ValueError("invalid URL")
    scheme, netloc, rest = m.group(1).lower(), m.group(2), m.group(3)
    userinfo = ""
    if "@" in netloc:
        userinfo, netloc = netloc.rsplit("@", 1)
        userinfo += "@"
    host, port = netloc, ""
    if netloc.startswith("["):  # IPv6 literal
        end = netloc.find("]")
        host, port = netloc[: end + 1], netloc[end + 1 :]
    elif ":" in netloc:
        host, port = netloc.rsplit(":", 1)
        port = ":" + port
    host = host.lower().rstrip(".")
    if not host:
        raise ValueError("URL without host")
    if (scheme == "http" and port == ":80") or (scheme == "https" and port == ":443"):
        port = ""
    if not host.startswith("["):
        try:
            host = host.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            pass
    return f"{scheme}://{userinfo}{host}{port}{rest or '/'}"


def url_host(url: str) -> str:
    """Host part of a normalized URL (no port, no brackets for IPv6)."""
    m = re.match(r"^[a-z][a-z0-9+.-]*://(?:[^@/]*@)?(\[[^\]]+\]|[^:/?#]+)", url, flags=re.I)
    if not m:
        return ""
    return m.group(1).strip("[]").lower()


def normalize_phone(raw: str, default_region: str | None = None) -> str:
    region = default_region or os.environ.get("V3LUM_DEFAULT_REGION", "BR")
    v = raw.strip()
    try:
        import phonenumbers  # optional dependency

        num = phonenumbers.parse(v, None if v.startswith("+") else region)
        if not phonenumbers.is_possible_number(num):
            raise ValueError("impossible phone number")
        return phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    except ImportError:
        pass
    except Exception as exc:  # phonenumbers.NumberParseException and friends
        raise ValueError(f"invalid phone number: {exc}") from exc
    digits = re.sub(r"\D", "", v)
    if v.startswith("+"):
        if not 8 <= len(digits) <= 15:
            raise ValueError("invalid phone number")
        return "+" + digits
    if region == "BR" and len(digits) in (10, 11):
        return "+55" + digits
    if 8 <= len(digits) <= 15:
        return "+" + digits
    raise ValueError("invalid phone number")


def _url_parts(raw: str, *, strip_prefixes: bool = True) -> tuple[str, str] | None:
    """(host, path) of an http(s) URL-ish string, or None; by default the host loses a leading
    www./m./mobile./web. label (platform matching), never for fediverse instances."""
    u = refang(raw).strip().strip("'\"<>")
    if not u or any(c.isspace() for c in u):
        return None
    if not re.match(r"^[a-z][a-z0-9+.-]*://", u, flags=re.I):
        if "/" not in u:
            return None
        u = "https://" + u
    try:
        parts = urlsplit(u)
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    host = parts.hostname.lower().rstrip(".")
    for prefix in ("www.", "m.", "mobile.", "web.") if strip_prefixes else ():
        if host.startswith(prefix) and host.count(".") >= 2:
            host = host[len(prefix) :]
            break
    return host, parts.path or "/"


# ---- e-mail header blocks ------------------------------------------------------------

EMAIL_HEADERS_MAX_BYTES = 256 * 1024
_HEADER_LINE = re.compile(r"^([!-9;-~]{1,128}):(.*)$")
_HEADER_KEY_FIELDS = frozenset({"from", "received", "message-id", "subject"})


def normalize_email_headers(raw: str) -> str:
    """A raw RFC 5322 header block: >= 2 'Name: value' fields incl. one of From/Received/Message-ID/Subject.

    CRLF -> LF; a leading mbox 'From ' line and anything after the first blank line (the body) are
    dropped; <= 256 KB. Parsing is static: nothing in the headers is ever fetched (P333 cond 8).
    """
    text = str(raw).replace("\r\n", "\n").replace("\r", "\n").lstrip("﻿")
    if len(text.encode("utf-8", "replace")) > EMAIL_HEADERS_MAX_BYTES:
        raise ValueError("header block larger than 256 KB")
    out: list[str] = []
    names: list[str] = []
    for line in text.split("\n"):
        if not line.strip():
            if out:
                break  # end of the header section: the body is never kept
            continue
        if line[0] in " \t":
            if not out:
                raise ValueError("continuation line before the first header field")
            out.append(line.rstrip())
            continue
        if not out and line.startswith("From "):
            continue  # mbox separator
        m = _HEADER_LINE.match(line)
        if not m:
            raise ValueError("not an RFC 5322 header line")
        names.append(m.group(1).lower())
        out.append(line.rstrip())
    if len(names) < 2 or not _HEADER_KEY_FIELDS.intersection(names):
        raise ValueError("not an e-mail header block (needs From/Received/Message-ID/Subject)")
    return "\n".join(out)


def email_header_fields(block: str) -> list[tuple[str, str]]:
    """Unfolded (name, value) pairs of a normalized header block (static parsing, no decoding)."""
    fields: list[tuple[str, str]] = []
    for line in block.split("\n"):
        if line[:1] in (" ", "\t") and fields:
            name, value = fields[-1]
            fields[-1] = (name, value + " " + line.strip())
            continue
        m = _HEADER_LINE.match(line)
        if m:
            fields.append((m.group(1), m.group(2).strip()))
    return fields


# ---- secrets ---------------------------------------------------------------------------

_PREVIEW_OK = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-+/=.")
_RE_FINGERPRINT = re.compile(
    r"^(?P<kind>[a-z][a-z0-9_]{0,31}):(?P<preview>[A-Za-z0-9_\-+/=.*]{0,4}…[A-Za-z0-9_\-+/=.*]{0,4}):(?P<sha>[0-9a-f]{16})$"
)
_RE_TG_BOT_TOKEN = re.compile(r"^(?:bot)?(\d{8,10}:[A-Za-z0-9_-]{35})$")
ELLIPSIS = "…"


def _secret_kind(kind: str) -> str:
    k = re.sub(r"[^a-z0-9_]+", "_", str(kind or "").strip().lower()).strip("_")[:32]
    return k if re.match(r"^[a-z][a-z0-9_]{0,31}$", k) else "secret"


def secret_preview(raw: str) -> str:
    """Masked preview of a secret: first 4 … last 4 (2 … 2 under 16 chars, … only under 12 chars);
    characters outside [A-Za-z0-9_-+/=.] become '*'."""
    raw = str(raw)
    n = len(raw)
    k = 4 if n >= 16 else 2 if n >= 12 else 0
    if not k:
        return ELLIPSIS

    def clean(part: str) -> str:
        return "".join(c if c in _PREVIEW_OK else "*" for c in part)

    return f"{clean(raw[:k])}{ELLIPSIS}{clean(raw[-k:])}"


def secret_fingerprint(kind: str, raw: str) -> str:
    """'<kind>:<first4>…<last4>:<sha256[:16]>' for a raw secret (the raw value is never kept).

    ``kind`` is cleaned to ``^[a-z][a-z0-9_]{0,31}$`` ('secret' when unusable). Raises ValueError for an
    empty secret.
    """
    raw = "" if raw is None else str(raw)
    if not raw.strip():
        raise ValueError("empty secret")
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"{_secret_kind(kind)}:{secret_preview(raw)}:{digest}"


def secret_entity(kind: str, raw: str) -> Entity:
    """Entity(SECRET, fingerprint) for a raw secret found in text or a payload (P323 cond 6)."""
    return Entity(EntityType.SECRET, secret_fingerprint(kind, raw))


def parse_fingerprint(value: str) -> tuple[str, str, str] | None:
    """(kind, preview, sha16) of a secret fingerprint, or None."""
    m = _RE_FINGERPRINT.match(str(value or "").strip())
    return (m.group("kind"), m.group("preview"), m.group("sha")) if m else None


def _normalize_card(v: str) -> str:
    compact = re.sub(r"[\s-]", "", v)
    if re.match(r"^\d{13,19}$", compact):
        if not val.pan_valid(compact):
            raise ValueError("not a valid payment card number")
        return f"{compact[:6]}{ELLIPSIS}{compact[-4:]}"
    m = re.match(r"^(\d{6})\d{0,2}(?:…|\.{2,3}|[*xX•#]{2,13})(\d{4})$", compact)
    if m:
        return f"{m.group(1)}{ELLIPSIS}{m.group(2)}"
    raise ValueError("not a payment card number (13-19 digits with Luhn, or BIN6…last4)")


#: Types whose Entity value is always a fingerprint or a truncated card (enforced in Entity.__post_init__).
_COERCED_TYPES: frozenset[EntityType] = frozenset({EntityType.SECRET, EntityType.TELEGRAM_BOT_TOKEN, EntityType.PAYMENT_CARD})
_RE_MASKED_PAN = re.compile(r"^\d{6}…\d{4}$")


def _coerce_secret_value(etype: EntityType | str, value: Any) -> str:
    """Safe stored form for a secret-like Entity built without :func:`normalize` (never raises)."""
    etype = EntityType(etype)
    v = "" if value is None else str(value)
    if etype is EntityType.PAYMENT_CARD:
        if _RE_MASKED_PAN.match(v):
            return v
        try:
            return _normalize_card(v.strip())
        except ValueError:
            return _mask_card_fallback(v)
    if parse_fingerprint(v) is not None:
        return v.strip()  # a fingerprint holds no raw secret
    raw = v.strip()
    kind = "secret"
    if etype is EntityType.TELEGRAM_BOT_TOKEN:
        kind = "telegram_bot_token"
        m = _RE_TG_BOT_TOKEN.match(raw)
        raw = m.group(1) if m else raw
    digest = hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    return f"{kind}:{secret_preview(raw)}:{digest}"


# ---- handles, invites and accounts ------------------------------------------------------

_TG_RESERVED = frozenset({
    "joinchat", "addstickers", "addemoji", "addtheme", "addlist", "share", "proxy", "socks", "iv", "login",
    "setlanguage", "confirmphone", "invoice", "boost", "giftcode", "contact", "s", "c", "k", "a", "z",
})
_RE_TG_HANDLE = re.compile(r"^[a-z][a-z0-9_]{4,31}$")
_RE_INVITE_CODE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
_RE_DISCORD_CODE = re.compile(r"^[A-Za-z0-9-]{2,32}$")
_RE_HANDLE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _normalize_telegram_handle(v: str) -> str:
    s = refang(v).strip()
    m = re.match(r"^tg://resolve\?domain=([A-Za-z0-9_]+)", s, flags=re.I)
    if m:
        s = m.group(1)
    else:
        parts = _url_parts(s) if "/" in s else None
        if parts is not None:
            host, path = parts
            if host not in ("t.me", "telegram.me", "telegram.dog"):
                raise ValueError("not a Telegram URL")
            segs = [p for p in path.split("/") if p]
            if segs and segs[0].lower() == "s" and len(segs) >= 2:
                segs = segs[1:]  # t.me/s/<channel> public preview
            if not segs or segs[0].startswith("+") or segs[0].lower() in _TG_RESERVED:
                raise ValueError("not a Telegram username URL (invites use telegram_invite)")
            s = segs[0]
    s = s.lstrip("@").lower()
    if s.startswith("+") or not _RE_TG_HANDLE.match(s):
        raise ValueError("invalid Telegram username")
    return s


def _normalize_telegram_invite(v: str) -> str:
    s = refang(v).strip()
    m = re.match(r"^tg://join\?invite=([A-Za-z0-9_-]+)", s, flags=re.I)
    if m:
        s = m.group(1)
    else:
        parts = _url_parts(s) if "/" in s else None
        if parts is not None:
            host, path = parts
            if host not in ("t.me", "telegram.me", "telegram.dog"):
                raise ValueError("not a Telegram URL")
            segs = [p for p in path.split("/") if p]
            if segs and segs[0].lower() == "joinchat" and len(segs) >= 2:
                s = segs[1]
            elif segs and segs[0].startswith("+"):
                s = segs[0]
            else:
                raise ValueError("not a Telegram invite URL")
    s = s[1:] if s.startswith("+") else s
    if not _RE_INVITE_CODE.match(s):
        raise ValueError("invalid Telegram invite code")
    return s


def _normalize_discord_invite(v: str) -> str:
    s = refang(v).strip()
    parts = _url_parts(s) if "/" in s else None
    if parts is not None:
        host, path = parts
        segs = [p for p in path.split("/") if p]
        if host in ("discord.gg",) and segs:
            s = segs[0]
        elif host in ("discord.com", "discordapp.com") and len(segs) >= 2 and segs[0].lower() == "invite":
            s = segs[1]
        else:
            raise ValueError("not a Discord invite URL")
    if not _RE_DISCORD_CODE.match(s):
        raise ValueError("invalid Discord invite code")
    return s


def _normalize_social_account(v: str) -> str:
    s = v.strip()
    if "/" in s or s.lower().startswith(("http:", "https:")):
        hit = platform_for_url(s)
        if hit is None:
            raise ValueError("not a profile URL of a known social platform")
        return f"{hit[0]}:{hit[1]}"
    if ":" not in s:
        raise ValueError("social_account needs '<platform>:<handle>'")
    platform, handle = s.split(":", 1)
    name = resolve_platform(platform)
    if name is None:
        raise ValueError(f"unknown social platform {platform.strip()!r} (see SOCIAL_PLATFORMS)")
    handle = handle.strip().lstrip("@")
    if not _RE_HANDLE.match(handle) or not handle.strip("._-"):
        raise ValueError("invalid handle (letters/digits needed; [A-Za-z0-9_.-]{1,64})")
    return f"{name}:{handle.lower()}"


def _normalize_fediverse(v: str) -> str:
    s = refang(v).strip()
    if s.lower().startswith("acct:"):
        s = s[5:]
    if "/" in s:
        parts = _url_parts(s, strip_prefixes=False)  # the instance host is exact (m.cmx.im is an instance)
        if parts is None:
            raise ValueError("invalid fediverse profile URL")
        host, path = parts
        m = re.match(r"^/@([A-Za-z0-9_.-]{1,64})/?$", path) or re.match(r"^/users/([A-Za-z0-9_.-]{1,64})/?$", path)
        if not m:
            raise ValueError("not a fediverse profile URL (https://<instance>/@<user>)")
        user, instance = m.group(1), host
    else:
        m = re.match(r"^@?([A-Za-z0-9_.-]{1,64})@([^@\s]+)$", s)
        if not m:
            raise ValueError("fediverse handle is @user@instance")
        user, instance = m.group(1), m.group(2)
    return f"{user.lower()}@{normalize_domain(instance)}"


def _normalize_bsky(v: str) -> str:
    s = refang(v).strip()
    if "/" in s:
        parts = _url_parts(s)
        if parts is None:
            raise ValueError("invalid Bluesky profile URL")
        host, path = parts
        m = re.match(r"^/profile/([^/]+)(?:/post/[A-Za-z0-9]{1,32})?/?$", path)  # a post URL names its author
        if host != "bsky.app" or not m:
            raise ValueError("not a Bluesky profile URL (https://bsky.app/profile/<handle>)")
        s = m.group(1)
    s = s.lstrip("@")
    if s.lower().startswith("did:"):
        raise ValueError("a DID is not a handle")
    return normalize_domain(s)


def _normalize_steam(v: str) -> str:
    s = refang(v).strip()
    if "/" in s:
        parts = _url_parts(s)
        if parts is None or parts[0] != "steamcommunity.com":
            raise ValueError("not a Steam community profile URL")
        segs = [p for p in parts[1].split("/") if p]
        if len(segs) < 2 or segs[0].lower() not in ("id", "profiles"):
            raise ValueError("not a Steam profile URL (/id/<vanity> or /profiles/<steamid64>)")
        s = f"{segs[0].lower()}:{segs[1]}"
    kind, _, ident = s.partition(":") if ":" in s else ("", "", s)
    kind = kind.lower()
    if kind in ("", "profiles") and val.steamid64_valid(ident):
        return f"profiles:{ident}"
    if kind == "profiles":
        raise ValueError("invalid SteamID64")
    if kind in ("", "id") and re.match(r"^[A-Za-z0-9_-]{2,32}$", ident) and not ident.isdigit():
        return f"id:{ident.lower()}"
    raise ValueError("steam_profile is 'id:<vanity>' or 'profiles:<17-digit steamid64>'")


def _normalize_port_service(v: str) -> str:
    # The host is an IP or a bare domain: no userinfo ('@'), path, brackets or whitespace.
    m = re.match(r"^(\[[0-9A-Fa-f:.]+\]|[^:/@\s\[\]]+):(\d{1,5})(?:/([A-Za-z]{3}))?$", refang(v).strip())
    if not m:
        raise ValueError("port_service is '<host>:<port>/<tcp|udp>' (IPv6 in brackets)")
    host_raw, port, proto = m.group(1), int(m.group(2)), (m.group(3) or "tcp").lower()
    if proto not in ("tcp", "udp") or not 1 <= port <= 65535:
        raise ValueError("invalid port or protocol")
    if host_raw.startswith("["):
        ip = ipaddress.ip_address(host_raw[1:-1])
        if ip.version != 6:
            raise ValueError("brackets are for IPv6 only")
        host = f"[{ip.compressed}]"
    else:
        try:
            ip4 = ipaddress.ip_address(host_raw)
        except ValueError:
            host = normalize_domain(host_raw)
        else:
            if ip4.version != 4:
                raise ValueError("IPv6 hosts need brackets")
            host = str(ip4)
    return f"{host}:{port}/{proto}"


def _normalize_code_signing(v: str) -> str:
    s = v.strip()
    if re.match(r"^(?:serial|issuer)\s*:", s, flags=re.I):
        fields: dict[str, str] = {}
        for part in re.split(r";\s*(?=(?:serial|issuer)\s*:)", s, flags=re.I):
            name, _, value = part.partition(":")
            fields[name.strip().lower()] = value.strip()
        serial = re.sub(r"[\s:]", "", fields.get("serial", "")).lower()
        issuer = _collapse(fields.get("issuer", ""))
        if not re.match(r"^[0-9a-f]{1,64}$", serial) or not issuer or len(issuer) > 512 or _CTRL.search(issuer):
            raise ValueError("code_signing_cert is 'serial:<hex>;issuer:<text>' or a 40/64-hex thumbprint")
        return f"serial:{serial};issuer:{issuer}"
    h = re.sub(r"[\s:]", "", s).lower()
    if len(h) not in (40, 64) or not _HEX.match(h):
        raise ValueError("invalid code-signing certificate thumbprint")
    return h


def _normalize_tiktok_video(v: str) -> str:
    s = refang(v).strip()
    if "/" in s:
        parts = _url_parts(s)
        m = re.match(r"^/@[A-Za-z0-9_.-]{1,64}/video/(\d{1,20})/?$", parts[1]) if parts and parts[0] == "tiktok.com" else None
        if not m:
            raise ValueError("not a TikTok video URL (tiktok.com/@user/video/<id>)")
        s = m.group(1)
    # No leading zero: the canonical form must normalize to itself (ids are 64-bit, 15-20 digits).
    if not re.match(r"^[1-9]\d{14,19}$", s) or not int(s) < 2**64:
        raise ValueError("invalid TikTok video id")
    return s


def _normalize_snowflake(v: str) -> str:
    s = v.strip()
    if not re.match(r"^[1-9]\d{14,19}$", s) or not int(s) < 2**64:
        raise ValueError("invalid snowflake id (64-bit, explicit snowflake_id: prefix only)")
    return s


# --------------------------------------------------------------------------------------
# normalize()
# --------------------------------------------------------------------------------------


def normalize(etype: EntityType, raw: str) -> str:
    """Return the canonical string for ``raw`` as ``etype``. Raises ValueError if invalid."""
    if raw is None:
        raise ValueError("empty value")
    raw = str(raw)
    if etype is EntityType.TEXT:
        if not raw.strip():
            raise ValueError("empty text")
        return raw
    if etype is EntityType.EMAIL_HEADERS:
        return normalize_email_headers(raw)
    v = raw.strip()
    if not v:
        raise ValueError("empty value")

    if etype is EntityType.EMAIL:
        v = refang(v).strip().strip("<>\"'").lower()
        if v.startswith("mailto:"):
            v = v[7:]
        if not re.match(r"^[a-z0-9!#$%&'*+/=?^_`{|}~.-]+@[a-z0-9.-]+\.[a-z0-9-]{2,}$", v):
            raise ValueError("invalid email")
        local, domain = v.rsplit("@", 1)
        return f"{local}@{normalize_domain(domain)}"
    if etype is EntityType.DOMAIN:
        return normalize_domain(v)
    if etype is EntityType.URL:
        return normalize_url(v)
    if etype is EntityType.IPV4:
        ip = ipaddress.ip_address(refang(v).strip("[]"))
        if ip.version != 4:
            raise ValueError("not IPv4")
        return str(ip)
    if etype is EntityType.IPV6:
        ip = ipaddress.ip_address(refang(v).strip("[]"))
        if ip.version != 6:
            raise ValueError("not IPv6")
        return ip.compressed
    if etype is EntityType.CIDR:
        return str(ipaddress.ip_network(refang(v), strict=False))
    if etype is EntityType.ASN:
        m = re.match(r"^(?:as|asn)?\s*(\d{1,10})$", v, flags=re.I)
        if not m or int(m.group(1)) > 4294967295:
            raise ValueError("invalid ASN")
        return f"AS{int(m.group(1))}"
    if etype in _HASH_LEN:
        h = v.lower()
        if len(h) != _HASH_LEN[etype] or not _HEX.match(h):
            raise ValueError(f"invalid {etype.value}")
        return h
    if etype is EntityType.SSDEEP:
        if not re.match(r"^\d+:[A-Za-z0-9/+]+:[A-Za-z0-9/+]+(,\".*\")?$", v):
            raise ValueError("invalid ssdeep")
        return v
    if etype is EntityType.PHONE:
        return normalize_phone(v)
    if etype is EntityType.USERNAME:
        u = v.lstrip("@").strip()
        if not re.match(r"^[A-Za-z0-9_.\-]{1,64}$", u):
            raise ValueError("invalid username")
        return u.lower()
    if etype in (EntityType.PERSON, EntityType.ORG, EntityType.KEYWORD, EntityType.THREAT_ACTOR, EntityType.MALWARE):
        c = _collapse(v)
        if len(c) > 200:
            raise ValueError("too long")
        return c
    if etype is EntityType.CNPJ:
        c = re.sub(r"[^0-9A-Za-z]", "", v).upper()
        if not val.cnpj_valid(c):
            raise ValueError("invalid CNPJ")
        return c
    if etype is EntityType.CPF:
        c = re.sub(r"\D", "", v)
        if not val.cpf_valid(c):
            raise ValueError("invalid CPF")
        return c
    if etype is EntityType.CEP:
        c = re.sub(r"\D", "", v)
        if len(c) != 8:
            raise ValueError("invalid CEP")
        return c
    if etype is EntityType.BTC:
        if not val.btc_address_valid(v):
            raise ValueError("invalid BTC address")
        return v if not v.lower().startswith(("bc1", "tb1")) else v.lower()
    if etype is EntityType.ETH:
        if not re.match(r"^0x[0-9a-fA-F]{40}$", v):
            raise ValueError("invalid EVM address")
        return v.lower()
    if etype is EntityType.XMR:
        if not re.match(r"^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$", v):
            raise ValueError("invalid Monero address")
        return v
    if etype is EntityType.CRYPTO:
        if not re.match(r"^[A-Za-z0-9:]{20,120}$", v):
            raise ValueError("invalid crypto address")
        return v
    if etype is EntityType.CVE:
        m = re.match(r"^cve[-_ ]?(\d{4})[-_ ](\d{4,7})$", v, flags=re.I)
        if not m:
            raise ValueError("invalid CVE")
        return f"CVE-{m.group(1)}-{m.group(2)}"
    if etype is EntityType.MITRE:
        m = re.match(r"^(T\d{4}(?:\.\d{3})?|TA\d{4}|M\d{4}|DS\d{4})$", v.upper())
        if not m:
            raise ValueError("invalid ATT&CK id")
        return m.group(1)
    if etype is EntityType.MAC:
        hexd = re.sub(r"[^0-9A-Fa-f]", "", v)
        if len(hexd) != 12:
            raise ValueError("invalid MAC")
        return ":".join(hexd[i : i + 2] for i in range(0, 12, 2)).upper()
    if etype is EntityType.FILE:
        path = os.path.abspath(os.path.expanduser(v))
        if not os.path.isfile(path):
            raise ValueError("file not found")
        return path
    if etype is EntityType.ONION:
        o = refang(v).lower().strip()
        o = re.sub(r"^https?://", "", o).split("/")[0]
        if not o.endswith(".onion"):
            o += ".onion"
        if not val.onion_valid(o):
            raise ValueError("invalid onion address")
        return o
    if etype is EntityType.PLATE_BR:
        p = re.sub(r"[^A-Za-z0-9]", "", v).upper()
        if not val.plate_br_valid(p):
            raise ValueError("invalid BR plate")
        return p
    if etype is EntityType.PIX:
        p = v.lower()
        if not re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", p):
            raise ValueError("invalid PIX EVP key")
        return p
    if etype is EntityType.BOLETO:
        d = re.sub(r"\D", "", v)
        if len(d) not in (44, 47, 48):
            raise ValueError("invalid boleto line")
        return d
    if etype is EntityType.USER_AGENT:
        return _collapse(v)
    if etype is EntityType.JWT:
        if not re.match(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$", v):
            raise ValueError("invalid JWT")
        return v
    if etype is EntityType.ANALYTICS_ID:
        a = v.strip()
        if not re.match(r"^(UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{6,12}|GTM-[A-Z0-9]{4,10}|(ca-)?pub-\d{10,20}|AW-\d{6,12}|\d{15,16})$", a, flags=re.I):
            raise ValueError("invalid analytics id")
        return a.upper() if not a.lower().startswith(("pub-", "ca-pub-")) else a.lower()
    if etype is EntityType.CARD_BIN:
        d = re.sub(r"\D", "", v)
        if not 6 <= len(d) <= 8:
            raise ValueError("a BIN is the first 6-8 digits only (never enter full card numbers)")
        return d
    if etype is EntityType.COORDINATES:
        # Same language as r"\s*[,; ]\s*" between the numbers, without its quadratic backtracking.
        m = _RE_COORDINATES.match(v)
        if not m:
            raise ValueError("invalid coordinates")
        lat, lon = float(m.group(1)), float(m.group(2))
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            raise ValueError("coordinates out of range")
        return f"{lat:.6f},{lon:.6f}"
    if etype is EntityType.IMEI:
        d = re.sub(r"\D", "", v)
        if len(d) != 15 or not val.luhn_valid(d):
            raise ValueError("invalid IMEI")
        return d
    if etype is EntityType.FAVICON_HASH:
        if not re.match(r"^-?\d{1,11}$", v):
            raise ValueError("invalid favicon mmh3 hash")
        return str(int(v))
    if etype is EntityType.CERT_FP:
        h = re.sub(r"[^0-9a-fA-F]", "", v).lower()
        if len(h) not in (40, 64):
            raise ValueError("invalid certificate fingerprint")
        return h
    return _normalize_v2(etype, v)


def _normalize_v2(etype: EntityType, v: str) -> str:
    """Normalizers of the contract-v2 types (P333)."""
    if etype is EntityType.TELEGRAM_HANDLE:
        return _normalize_telegram_handle(v)
    if etype is EntityType.TELEGRAM_INVITE:
        return _normalize_telegram_invite(v)
    if etype is EntityType.DISCORD_INVITE:
        return _normalize_discord_invite(v)
    if etype is EntityType.SOCIAL_ACCOUNT:
        return _normalize_social_account(v)
    if etype is EntityType.PIX_BRCODE:
        if not val.pix_brcode_valid(v):
            raise ValueError("invalid PIX BR Code (EMV '000201'... '6304' + CRC16)")
        return v[:-4] + v[-4:].upper()
    if etype in (EntityType.IMPHASH, EntityType.GIMPHASH, EntityType.AUTHENTIHASH, EntityType.ICON_DHASH):
        size = {EntityType.IMPHASH: 32, EntityType.ICON_DHASH: 16}.get(etype, 64)
        h = v.lower()
        if len(h) != size or not _HEX.match(h):
            raise ValueError(f"invalid {etype.value} ({size} hex)")
        return h
    if etype in (EntityType.TLSH, EntityType.TELFHASH):
        if not re.match(r"^[Tt]1[0-9A-Fa-f]{70}$", v):
            raise ValueError(f"invalid {etype.value} ('T1' + 70 hex)")
        return "T1" + v[2:].upper()
    if etype is EntityType.CODE_SIGNING_CERT:
        return _normalize_code_signing(v)
    if etype is EntityType.PGP_FINGERPRINT:
        h = re.sub(r"\s", "", v)
        h = h[2:] if h[:2].lower() == "0x" else h
        if not re.match(r"^[0-9A-Fa-f]{40}$", h):
            raise ValueError("invalid OpenPGP fingerprint (40 hex)")
        return h.upper()
    if etype is EntityType.FEDIVERSE_HANDLE:
        return _normalize_fediverse(v)
    if etype is EntityType.BSKY_HANDLE:
        return _normalize_bsky(v)
    if etype is EntityType.STEAM_PROFILE:
        return _normalize_steam(v)
    if etype is EntityType.PORT_SERVICE:
        return _normalize_port_service(v)
    if etype is EntityType.VIN:
        p = re.sub(r"[\s-]", "", v).upper()
        if not val.vin_valid(p):
            raise ValueError("invalid VIN (17 chars, no I/O/Q)")
        return p
    if etype is EntityType.TELEGRAM_BOT_TOKEN:
        fp = parse_fingerprint(v)
        if fp is not None:
            if fp[0] != "telegram_bot_token":
                raise ValueError("fingerprint of another secret kind")
            return v
        m = _RE_TG_BOT_TOKEN.match(v)
        if not m:
            raise ValueError("not a Telegram bot token")
        return secret_fingerprint("telegram_bot_token", m.group(1))
    if etype is EntityType.SECRET:
        if parse_fingerprint(v) is None:
            raise ValueError("secret entities hold only fingerprints '<kind>:<first4>…<last4>:<sha16>' (use secret_entity())")
        return v
    if etype is EntityType.PAYMENT_CARD:
        return _normalize_card(v)
    if etype is EntityType.EU_VAT:
        return val.eu_vat_normalize(v)
    if etype is EntityType.TIKTOK_VIDEO_ID:
        return _normalize_tiktok_video(v)
    if etype is EntityType.SNOWFLAKE_ID:
        return _normalize_snowflake(v)
    raise ValueError(f"no normalizer for {etype}")


def snowflake_timestamp(value: str | int, epoch: str = "discord"):
    """Creation time (aware UTC datetime) of a Discord ('discord') or X/Twitter ('twitter') snowflake."""
    return val.snowflake_timestamp(value, epoch)


# --------------------------------------------------------------------------------------
# Social platforms (core set + v3lum/data/platforms fragments)
# --------------------------------------------------------------------------------------

PLATFORMS_SCHEMA = "v3lum.platforms/1"
PLATFORMS_DIR = Path(__file__).resolve().parent.parent / "data" / "platforms"
#: The 14 core platforms (always present; titles, aliases and URL patterns come from core.json).
CORE_PLATFORMS: tuple[str, ...] = (
    "instagram", "tiktok", "x", "facebook", "linkedin", "youtube", "github", "gitlab", "reddit", "threads",
    "pinterest", "twitch", "kwai", "snapchat",
)
#: Platform names (1-32 chars: the core platform 'x' is a single letter).
_RE_PLATFORM_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_RE_ALIAS = re.compile(r"^[a-z][a-z0-9_.-]{0,31}$")
#: Path words that are never profile handles on any platform.
_GLOBAL_RESERVED = frozenset({
    "about", "account", "accounts", "api", "auth", "blog", "contact", "developer", "developers", "download",
    "explore", "help", "home", "intent", "jobs", "legal", "login", "logout", "notifications", "oauth",
    "policies", "policy", "privacy", "search", "security", "settings", "share", "sharer", "signin", "signup",
    "static", "status", "support", "terms", "tos",
})


@dataclass(frozen=True)
class Platform:
    """One social platform: canonical name, title, aliases, profile URL patterns ('https://host/{handle}')."""

    name: str
    title: str
    aliases: tuple[str, ...] = ()
    profile_url_patterns: tuple[str, ...] = ()
    reserved_handles: frozenset[str] = frozenset()
    origin: str = ""


@dataclass
class _PlatformRegistry:
    platforms: dict[str, Platform] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)
    matchers: list[tuple[str, str, re.Pattern[str]]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    redeclared: list[str] = field(default_factory=list)


def _compile_profile_pattern(pattern: str) -> tuple[str, re.Pattern[str]] | str:
    """(host, path regex) for 'https://host/prefix{handle}suffix', or an error message."""
    if not isinstance(pattern, str) or pattern.count("{handle}") != 1 or len(pattern) > 200:
        return "pattern must be a string with exactly one {handle}"
    m = re.match(r"^https?://([a-z0-9.-]+)(/[^?#{}]*)\{handle\}([^?#{}]*)$", pattern)
    if not m:
        return "pattern must look like https://<host>/<path>{handle}"
    host = m.group(1).rstrip(".")
    for prefix in ("www.", "m.", "mobile.", "web."):
        if host.startswith(prefix) and host.count(".") >= 2:
            host = host[len(prefix) :]
            break
    try:
        normalize_domain(host)
    except ValueError:
        return f"invalid host {host!r}"
    suffix = m.group(3).rstrip("/")
    regex = re.compile("^" + re.escape(m.group(2)) + r"(?P<handle>[A-Za-z0-9_.-]{1,64})" + re.escape(suffix) + "/?$", re.I)
    return host, regex


def _add_platform(reg: _PlatformRegistry, name: str, spec: Any, origin: str) -> None:
    where = f"{origin}: platform {name!r}"
    if not isinstance(name, str) or not _RE_PLATFORM_NAME.match(name):
        reg.errors.append(f"{origin}: invalid platform name {name!r} (^[a-z][a-z0-9_]{{0,31}}$)")
        return
    if not isinstance(spec, dict):
        reg.errors.append(f"{where}: expected an object")
        return
    unknown = set(spec) - {"title", "aliases", "profile_url_patterns", "reserved_handles", "notes"}
    if unknown:
        reg.errors.append(f"{where}: unknown fields {sorted(unknown)}")
    title = spec.get("title") or name
    aliases_in = spec.get("aliases") or []
    patterns_in = spec.get("profile_url_patterns") or []
    reserved_in = spec.get("reserved_handles") or []
    if not isinstance(title, str) or not all(isinstance(x, list) for x in (aliases_in, patterns_in, reserved_in)):
        reg.errors.append(f"{where}: title must be a string; aliases/profile_url_patterns/reserved_handles lists")
        return
    if name in reg.aliases:
        reg.errors.append(f"{where}: name already used as an alias of {reg.aliases[name]!r}")
        return
    existing = reg.platforms.get(name)
    aliases: list[str] = list(existing.aliases) if existing else []
    for alias in aliases_in:
        a = str(alias).strip().lower()
        owner = reg.aliases.get(a) or (a if a in reg.platforms else None)
        if not _RE_ALIAS.match(a):
            reg.errors.append(f"{where}: invalid alias {alias!r}")
        elif a == name or owner == name:
            continue
        elif owner is not None:
            reg.errors.append(f"{where}: alias {a!r} already belongs to platform {owner!r}")
        else:
            reg.aliases[a] = name
            aliases.append(a)
    patterns: list[str] = list(existing.profile_url_patterns) if existing else []
    for pattern in patterns_in:
        compiled = _compile_profile_pattern(pattern)
        if isinstance(compiled, str):
            reg.errors.append(f"{where}: {compiled} ({pattern!r})")
            continue
        if pattern not in patterns:
            patterns.append(pattern)
            reg.matchers.append((name, compiled[0], compiled[1]))
    reserved = frozenset(str(x).lower() for x in reserved_in) | (existing.reserved_handles if existing else frozenset())
    if existing is not None:
        reg.redeclared.append(f"{origin}: {name}")
    reg.platforms[name] = Platform(
        name=name,
        title=existing.title if existing else title,
        aliases=tuple(aliases),
        profile_url_patterns=tuple(patterns),
        reserved_handles=reserved,
        origin=existing.origin if existing else origin,
    )


def _load_fragment(reg: _PlatformRegistry, data: Any, origin: str) -> None:
    if not isinstance(data, dict) or data.get("schema") != PLATFORMS_SCHEMA:
        reg.errors.append(f"{origin}: expected an object with schema {PLATFORMS_SCHEMA!r}")
        return
    platforms = data.get("platforms")
    if not isinstance(platforms, dict):
        reg.errors.append(f"{origin}: 'platforms' must be an object name -> spec")
        return
    for name, spec in platforms.items():
        _add_platform(reg, name, spec, origin)


def _fragment_files(dirs: Iterable[Path]) -> list[Path]:
    files: list[Path] = []
    for directory in dirs:
        if not directory.is_dir():
            continue
        found = sorted(p for p in directory.iterdir() if p.suffix == ".json" and p.is_file())
        files.extend(sorted(found, key=lambda p: (p.name != "core.json", p.name)))
    return files


def _build_platforms(extra_dirs: Iterable[str | os.PathLike[str]] = ()) -> _PlatformRegistry:
    reg = _PlatformRegistry()
    for path in _fragment_files([PLATFORMS_DIR, *(Path(d) for d in extra_dirs)]):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            reg.errors.append(f"{path.name}: unreadable platform fragment ({exc})")
            continue
        _load_fragment(reg, data, path.name)
    for name in CORE_PLATFORMS:  # the core set exists even if core.json is damaged
        if name not in reg.platforms:
            reg.errors.append(f"core platform {name!r} missing from platforms/core.json")
            _add_platform(reg, name, {"title": name.title(), "aliases": ["twitter"] if name == "x" else []}, "builtin")
    return reg


_PLATFORM_LOCK = threading.Lock()
_PLATFORMS: _PlatformRegistry | None = None
_PLATFORM_EXTRA_DIRS: tuple[str, ...] = ()


def _platform_registry() -> _PlatformRegistry:
    global _PLATFORMS
    reg = _PLATFORMS
    if reg is not None:
        return reg
    with _PLATFORM_LOCK:
        if _PLATFORMS is None:
            _PLATFORMS = _build_platforms(_PLATFORM_EXTRA_DIRS)
        return _PLATFORMS


def reload_platforms(extra_dirs: Iterable[str | os.PathLike[str]] = ()) -> None:
    """Re-read the platform fragments (plus ``extra_dirs``, e.g. a test's tmp directory).

    ``reload_platforms()`` without arguments restores the bundled set.
    """
    global _PLATFORMS, _PLATFORM_EXTRA_DIRS
    with _PLATFORM_LOCK:
        _PLATFORM_EXTRA_DIRS = tuple(str(d) for d in extra_dirs)
        _PLATFORMS = _build_platforms(_PLATFORM_EXTRA_DIRS)


def register_platforms(fragment: dict[str, Any], *, origin: str = "programmatic") -> list[str]:
    """Merge a 'v3lum.platforms/1' fragment at runtime (plugins/tests); returns its errors (also kept in
    :func:`platform_errors`). Undone by :func:`reload_platforms`."""
    global _PLATFORMS
    with _PLATFORM_LOCK:
        current = _PLATFORMS if _PLATFORMS is not None else _build_platforms(_PLATFORM_EXTRA_DIRS)
        merged = _PlatformRegistry(  # copy-on-write: readers keep a consistent snapshot
            platforms=dict(current.platforms),
            aliases=dict(current.aliases),
            matchers=list(current.matchers),
            errors=list(current.errors),
            redeclared=list(current.redeclared),
        )
        before = len(merged.errors)
        _load_fragment(merged, fragment, origin)
        _PLATFORMS = merged
        return merged.errors[before:]


def platforms() -> dict[str, Platform]:
    """Every merged platform by canonical name."""
    return dict(_platform_registry().platforms)


def platform_errors() -> list[str]:
    """Problems found while merging platform fragments (empty for the shipped tree)."""
    return list(_platform_registry().errors)


def resolve_platform(name: str) -> str | None:
    """Canonical platform name for a name or alias ('twitter' -> 'x'), or None when unknown."""
    key = str(name or "").strip().lower()
    reg = _platform_registry()
    if key in reg.platforms:
        return key
    return reg.aliases.get(key)


class _PlatformNames(Set):
    """Live, read-only set of the merged platform names (core set + fragments)."""

    def __contains__(self, item: object) -> bool:
        return isinstance(item, str) and item in _platform_registry().platforms

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(_platform_registry().platforms))

    def __len__(self) -> int:
        return len(_platform_registry().platforms)

    @classmethod
    def _from_iterable(cls, it: Iterable[str]) -> frozenset[str]:
        return frozenset(it)

    def __repr__(self) -> str:
        return f"SOCIAL_PLATFORMS({sorted(self)!r})"


#: Canonical social platform names: the core set merged with v3lum/data/platforms fragments (live view).
SOCIAL_PLATFORMS: Set = _PlatformNames()


def platform_for_url(url: str) -> tuple[str, str] | None:
    """(platform, handle) for a profile URL of a merged platform, e.g.
    ``'https://www.instagram.com/John.Doe/'`` -> ``('instagram', 'john.doe')``; None otherwise.

    Offline and static: the URL is only parsed (query and fragment ignored), never fetched.
    """
    parts = _url_parts(str(url or ""))
    if parts is None:
        return None
    host, path = parts
    reg = _platform_registry()
    for name, phost, regex in reg.matchers:
        if phost != host:
            continue
        m = regex.match(path)
        if not m:
            continue
        handle = m.group("handle").lower()
        if handle in _GLOBAL_RESERVED or handle in reg.platforms[name].reserved_handles or handle.strip(".-_") == "":
            continue
        return name, handle
    return None


# --------------------------------------------------------------------------------------
# Generic / role / test addresses (A4 BR6)
# --------------------------------------------------------------------------------------

GENERIC_ADDRESSES_PATH = Path(__file__).resolve().parent.parent / "data" / "generic_addresses.json"
_GENERIC_DEFAULTS: dict[str, Any] = {
    "local_parts": ["test", "info", "contato", "contact", "sac", "admin", "noreply", "no-reply", "suporte",
                    "support", "vendas", "financeiro", "rh", "webmaster", "postmaster", "abuse"],
    "test_local_parts": ["test", "teste", "testing", "tester", "dummy", "fake", "foo", "bar", "foobar", "example",
                         "sample", "someone", "nobody"],
    "domains": ["example.com", "example.net", "example.org"],
    "domain_suffixes": [".example", ".test", ".invalid", ".localhost"],
}
_GENERIC_LOCK = threading.Lock()
_GENERIC: dict[str, frozenset[str]] | None = None


def _generic_lists() -> dict[str, frozenset[str]]:
    global _GENERIC
    if _GENERIC is not None:
        return _GENERIC
    with _GENERIC_LOCK:
        if _GENERIC is None:
            data: dict[str, Any] = dict(_GENERIC_DEFAULTS)
            try:
                loaded = json.loads(GENERIC_ADDRESSES_PATH.read_text(encoding="utf-8"))
                if isinstance(loaded, dict) and loaded.get("schema") == "v3lum.generic_addresses/1":
                    for key in _GENERIC_DEFAULTS:
                        if isinstance(loaded.get(key), list):
                            data[key] = loaded[key]
            except (OSError, ValueError):
                pass  # fail safe: the built-in lists still flag the common generic addresses
            _GENERIC = {k: frozenset(str(x).strip().lower() for x in v) for k, v in data.items()}
        return _GENERIC


def generic_address_kind(email: str | Entity) -> str | None:
    """'example_domain' (IANA example/test domains), 'test' (test local parts) or 'role' (role mailboxes
    such as contato@, noreply@, abuse@) for a generic address; None for an ordinary address or a non-email.

    Generic addresses are flagged, capped at POSSIBLE and never scored as exposure (A4).
    """
    value = email.value if isinstance(email, Entity) else str(email or "")
    try:
        norm = normalize(EntityType.EMAIL, value)
    except ValueError:
        return None
    local, domain = norm.rsplit("@", 1)
    lists = _generic_lists()
    if any(domain == d or domain.endswith("." + d) for d in lists["domains"]) or any(
        domain.endswith(s) or domain == s.lstrip(".") for s in lists["domain_suffixes"]
    ):
        return "example_domain"
    base = local.split("+", 1)[0]
    if base in lists["test_local_parts"] or re.match(r"^(?:test|teste|testing)[._-]?\d*$", base):
        return "test"
    if base in lists["local_parts"] or base.replace("_", "-") in lists["local_parts"]:
        return "role"
    return None


# --------------------------------------------------------------------------------------
# Display and redaction (AR24)
# --------------------------------------------------------------------------------------


def mask_cpf(value: str) -> str:
    """Government pattern ``***.456.789-**`` (digits 4-9 kept); '***' for anything that is not 11 digits."""
    d = re.sub(r"\D", "", str(value or ""))
    return f"***.{d[3:6]}.{d[6:9]}-**" if len(d) == 11 else "***"


def mask_vin(value: str) -> str:
    """First 11 VIN characters + '******' (the serial part is personal)."""
    v = str(value or "")
    return v[:11] + "******" if len(v) == 17 else "*" * min(len(v), 17)


def _secret_display(etype: EntityType, value: str) -> str:
    if etype is EntityType.PAYMENT_CARD:
        return value if ELLIPSIS in value else _mask_card_fallback(value)
    if etype is EntityType.JWT:
        return f"{secret_preview(value)} (jwt)"
    fp = parse_fingerprint(value)
    if fp is not None:
        return f"{fp[1]} ({fp[0]})"
    return f"{ELLIPSIS} ({etype.value})"


def _mask_card_fallback(value: str) -> str:
    d = re.sub(r"\D", "", str(value or ""))
    return f"{d[:6]}{ELLIPSIS}{d[-4:]}" if len(d) >= 10 else ELLIPSIS


def _brcode_masked(value: str) -> str:
    """The BR Code with a CPF PIX key masked in place (same length; the CRC no longer matches).

    Every occurrence of the CPF digits is masked (the key field and any copy, e.g. in a txid)."""
    fields = val.pix_brcode_fields(value)
    key = (fields or {}).get("key", "")
    if not key or not (len(key) == 11 and key.isdigit() and val.cpf_valid(key)):
        return value
    return value.replace(key, "***" + key[3:9] + "**")


def _brcode_display(value: str, show_personal: bool) -> str:
    fields = val.pix_brcode_fields(value)
    if fields is None:
        return _short(value, 60)
    key = fields["key"]
    if key and len(key) == 11 and key.isdigit() and val.cpf_valid(key) and not show_personal:
        key = mask_cpf(key)
    parts = [f"key {key}" if key else (f"url {fields['url']}" if fields["url"] else "")]
    parts += [fields["merchant_name"], fields["merchant_city"]]
    if fields["amount"]:
        parts.append(f"amount {fields['amount']}")
    return _short("PIX BR Code: " + ", ".join(p for p in parts if p), 120)


def _short(text: str, limit: int) -> str:
    clean = _collapse(_CTRL.sub(" ", text))
    return clean if len(clean) <= limit else clean[: limit - 3] + "..."


def _headers_display(value: str) -> str:
    fields = email_header_fields(value)
    names = {n.lower(): v for n, v in fields}
    subject = names.get("subject") or names.get("message-id") or ""
    if subject and "=?" in subject:
        try:
            from email.header import decode_header, make_header

            subject = str(make_header(decode_header(subject)))
        except Exception:  # noqa: BLE001 - display only
            pass
    label = f"Email headers ({len(fields)} fields)"
    return _short(f"{label}: {subject}" if subject else label, 100)


def display_value(etype: EntityType, value: str, *, show_personal: bool = False) -> str:
    """Human-friendly, masked rendering (never used as identity).

    CPF ``***.456.789-**`` and VIN first 11 + ``******`` unless ``show_personal`` (recorded in the case
    audit by the caller); SECRET_TYPES always as previews (``eyJh…xyz4 (jwt)``, ``AKIA…MPLE (aws_key)``;
    payment_card is already ``BIN6…last4``); CNPJ/CEP punctuated; long blobs shortened.
    """
    if etype is EntityType.CNPJ and len(value) == 14:
        return f"{value[:2]}.{value[2:5]}.{value[5:8]}/{value[8:12]}-{value[12:]}"
    if etype is EntityType.CPF:
        if show_personal and len(value) == 11:
            return f"{value[:3]}.{value[3:6]}.{value[6:9]}-{value[9:]}"
        return mask_cpf(value)
    if etype is EntityType.CEP and len(value) == 8:
        return f"{value[:5]}-{value[5:]}"
    if etype is EntityType.TEXT:
        short = _collapse(value)
        return short if len(short) <= 60 else short[:57] + "..."
    if etype is EntityType.FILE:
        return os.path.basename(value) or value
    if etype in SECRET_TYPES:
        return _secret_display(etype, value)
    if etype is EntityType.VIN:
        return value if show_personal else mask_vin(value)
    if etype is EntityType.PIX_BRCODE:
        return _brcode_display(value, show_personal)
    if etype is EntityType.EMAIL_HEADERS:
        return _headers_display(value)
    if etype in (EntityType.TELEGRAM_HANDLE, EntityType.FEDIVERSE_HANDLE, EntityType.BSKY_HANDLE):
        return "@" + value
    return value


def redacted_value(etype: EntityType, value: str) -> str:
    """Persist/export-safe value: the display masks regardless of show_personal (CPF, VIN, the CPF key
    of a BR Code) and fingerprints for SECRET_TYPES; every other type unchanged. Never raises."""
    if etype is EntityType.CPF:
        return mask_cpf(value)
    if etype is EntityType.VIN:
        return mask_vin(value)
    if etype is EntityType.JWT:
        return secret_fingerprint("jwt", value) if str(value or "").strip() else ""
    if etype in (EntityType.SECRET, EntityType.TELEGRAM_BOT_TOKEN):
        return _coerce_secret_value(etype, value)  # fingerprints unchanged; a raw value is fingerprinted
    if etype is EntityType.PAYMENT_CARD:
        return value if re.match(r"^\d{6}…\d{4}$", value) else _mask_card_fallback(value)
    if etype is EntityType.PIX_BRCODE:
        return _brcode_masked(value)
    return value
