"""Validated identification patterns for text blobs (P323): secrets, financial data, identifiers,
crypto addresses, analytics ids, SRV names and odd HTTP headers.

The pattern DB serves text_blob/file extraction (:mod:`v3lum.core.ioc`) and typing suggestions in
:func:`v3lum.core.detect.detect`. It never changes how a single typed value is detected otherwise
(P323 cond 1) and it never sends anything anywhere: matching is offline and static.

Rules (P323 conditions 2-9, A6, A8, AR24):

* only patterns with a validator or a distinctive prefix/checksum are imported; generic patterns
  (phone numbers, dates, UUIDs, timestamps...) are kept in the catalogue **disabled**;
* a pattern without a validator never exceeds confidence 0.5 (enforced by :class:`Pattern`);
* every pattern ships positive and negative vectors (``vectors_ok`` / ``vectors_bad``) and every
  regex is linear on pathological input (a negative look-behind of the token alphabet stops the
  engine from restarting inside long runs; ``tests/test_patterns.py`` runs each one over 1 MB of
  dots, hyphens, digits and alphabet runs);
* a pattern is *emitted* (returned by :func:`match_patterns` by default) only when it has a
  consumer (a module or core stage) or a masking need (secrets, financial data, CPF);
* financial and secret hits are local-only: they become masked values (``PatternMatch.masked``:
  the ``'<kind>:<first4>…<last4>:<sha16>'`` fingerprint of a secret, ``BIN6…last4`` for a card, a
  same-length mask for an IBAN or a CPF) and never pivots; the raw ``PatternMatch.value`` must
  never be stored, logged, rendered or sent (rule 1, PCI DSS for card numbers).

Sources (adapted with attribution, A6; notices ``v3lum/data/notices/lemmeknow.json`` and
``v3lum/data/notices/spiderfoot_extractors.json``):

* lemmeknow ``src/data/regex.json`` (https://github.com/swanandx/lemmeknow, commit
  1ed4a6b75540bae403d834857a0ddc371f1ac2f9, MIT, Copyright (c) 2021 Swanand Mulay; the data derives
  from pyWhat, MIT, Copyright (c) 2021 Bee-san): cloud/API key, token, webhook, card-brand and
  crypto-wallet formats. The regexes were rewritten for Python ``re``, made linear and given
  validators; unsafe or generic entries (AWS 20-char keys, phone, SSN, dates, UUID...) are disabled.
* SpiderFoot offline extractors (https://github.com/smicallef/spiderfoot, commit
  0f815a203afebf05c98b605dba5cf0475a0ee5fd, MIT, Copyright 2022 Steve Micallef):
  ``SpiderFootHelpers.extractIbansFromText`` (IBAN country lengths + mod-97),
  ``extractCreditCardsFromText`` (Luhn), ``sfp_webanalytics`` (UA-/pub-/GTM- ids),
  ``sfp_dnscommonsrv`` (the 25 common SRV names) and ``sfp_strangeheaders`` (standard header list).
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import NamedTuple

from v3lum.core import validators as val

__all__ = [
    "CARD_BRANDS",
    "IBAN_LENGTHS",
    "KINDS",
    "PATTERNS",
    "SRV_NAMES",
    "STANDARD_HEADERS",
    "Pattern",
    "PatternMatch",
    "card_brand",
    "emitted",
    "iban_valid",
    "mask_cpf_inplace",
    "mask_iban",
    "mask_pan",
    "match_patterns",
    "odd_headers",
    "pattern",
]

#: Pattern kinds (P323).
KINDS: tuple[str, ...] = ("secret", "financial", "identifier", "crypto", "analytics", "srv", "header")
#: Highest confidence of a pattern without a validator (P323 cond 3).
NO_VALIDATOR_MAX_CONFIDENCE = 0.5
#: Masking / consuming stage names used in ``Pattern.consumer``.
CORE_MASKING = "core:ioc masking (local-only, never sent)"


@dataclass(frozen=True)
class Pattern:
    """One identification pattern of the DB.

    ``regex`` group ``group`` (0 = whole match) holds the value; ``validator(value) -> bool`` must
    accept it (None = no validator, then ``confidence <= 0.5``); ``enabled`` False keeps a generic
    pattern in the catalogue without ever matching by default; ``consumer`` names the module or core
    stage that uses the hits ('' = none) and ``mask`` marks a masking need (secret, financial or
    national-id data): a pattern without both is not emitted. ``entity_type`` is the
    :class:`~v3lum.core.entities.EntityType` value the extraction engine creates ('' = no entity:
    counted/masked only). ``hints`` are lower-case literal substrings one of which must occur before
    the regex runs (fast path). ``vectors_ok``/``vectors_bad`` are the positive/negative test
    vectors (each positive vector matches in full).
    """

    name: str
    kind: str
    regex: re.Pattern[str]
    validator: Callable[[str], bool] | None
    confidence: float
    enabled: bool = True
    consumer: str = ""
    vectors_ok: tuple[str, ...] = ()
    vectors_bad: tuple[str, ...] = ()
    group: int = 0
    entity_type: str = ""
    mask: bool = False
    hints: tuple[str, ...] = ()
    source: str = ""
    description: str = ""

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"pattern {self.name!r}: kind must be one of {KINDS}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"pattern {self.name!r}: confidence must be within 0..1")
        if self.validator is None and self.confidence > NO_VALIDATOR_MAX_CONFIDENCE:
            raise ValueError(f"pattern {self.name!r}: a pattern without a validator cannot exceed confidence {NO_VALIDATOR_MAX_CONFIDENCE} (P323 cond 3)")
        if self.enabled and (self.vectors_ok == () or self.vectors_bad == ()):
            raise ValueError(f"pattern {self.name!r}: enabled patterns need positive and negative vectors (P323 cond 4)")

    @property
    def emitted(self) -> bool:
        """Enabled and with a consumer or a masking need (P323 cond 4)."""
        return self.enabled and bool(self.consumer or self.mask)

    def check(self, value: str) -> bool:
        """The validator verdict (True when the pattern has none)."""
        if self.validator is None:
            return True
        try:
            return bool(self.validator(value))
        except (ValueError, TypeError, UnicodeError, binascii.Error):
            return False


class PatternMatch(NamedTuple):
    """One validated hit. ``value`` is the raw text (NEVER store, log or send it for ``mask``
    patterns); ``masked`` is the safe form (fingerprint, ``BIN6…last4``, masked IBAN/CPF, or the
    value itself for non-sensitive patterns)."""

    name: str
    kind: str
    start: int
    end: int
    value: str
    masked: str
    confidence: float
    entity_type: str


# --------------------------------------------------------------------------------------
# validators
# --------------------------------------------------------------------------------------

_B32 = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def _distinct(value: str, minimum: int = 4) -> bool:
    return len(set(value)) >= minimum


def _aws_key_id(value: str) -> bool:
    # AKIA/ASIA... + 16 base32 characters (the id encodes the account; never all one character)
    return len(value) == 20 and set(value[4:]) <= _B32 and _distinct(value[4:])


def _length(*sizes: int, skip: int = 0) -> Callable[[str], bool]:
    """Exact length and a varied body (the part after a ``skip``-character prefix)."""

    def check(value: str) -> bool:
        return len(value) in sizes and _distinct(value[skip:], 6)

    return check


def _min_length(size: int, skip: int = 0) -> Callable[[str], bool]:
    """Minimum length and a varied body (the part after a ``skip``-character prefix)."""

    def check(value: str) -> bool:
        return len(value) >= size and _distinct(value[skip:], 6)

    return check


def _b64_bytes(size: int) -> Callable[[str], bool]:
    """Base64 of exactly ``size`` bytes with a varied alphabet (not a run of one character)."""

    def check(value: str) -> bool:
        return len(base64.b64decode(value, validate=True)) == size and _distinct(value, 8)

    return check


def _b64url_json(segment: str) -> dict | None:
    raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    data = json.loads(raw.decode("utf-8"))
    return data if isinstance(data, dict) else None


def _jwt(value: str) -> bool:
    """Structural JWT check: the header is base64url JSON naming an algorithm (never verified)."""
    parts = value.split(".")
    if len(parts) != 3:
        return False
    header = _b64url_json(parts[0])
    return bool(header) and isinstance(header.get("alg"), str) and isinstance(_b64url_json(parts[1]), dict)


def _slack_token(value: str) -> bool:
    groups = value.split("-")
    return len(groups) >= 3 and groups[1].isdigit() and _distinct(value)


def _discord_bot_token(value: str) -> bool:
    # the first segment is base64 of the bot's numeric user id (a snowflake)
    first = value.split(".")[0]
    decoded = base64.b64decode(first + "=" * (-len(first) % 4)).decode("ascii")
    return decoded.isdigit() and 17 <= len(decoded) <= 20


def _telegram_bot_token(value: str) -> bool:
    bot_id, _, rest = value.partition(":")
    return bot_id.isdigit() and int(bot_id) > 0 and len(rest) == 35 and _distinct(rest)


def _webhook_path(min_segments: int) -> Callable[[str], bool]:
    def check(value: str) -> bool:
        path = value.split("://", 1)[-1].split("/", 1)[-1]
        segs = [s for s in path.split("/") if s]
        return len(segs) >= min_segments and _distinct(value)

    return check


def _mailchimp(value: str) -> bool:
    key, _, dc = value.partition("-us")
    return len(key) == 32 and dc.isdigit() and 1 <= int(dc) <= 99 and _distinct(key)


def _totp(value: str) -> bool:
    return bool(re.search(r"[?&]secret=[A-Z2-7]{8,128}", value, re.I))


def _private_key(value: str) -> bool:
    return "PRIVATE KEY" in value and "-----END" in value


# ---- financial --------------------------------------------------------------------------

#: (brand, IIN prefix ranges, accepted lengths). Ranges are inclusive and compared on the first
#: len(start) digits; Brazilian brands (Elo, Hipercard) first, so they win over Visa/Discover.
CARD_BRANDS: tuple[tuple[str, tuple[tuple[str, str], ...], tuple[int, ...]], ...] = (
    ("elo", (("401178", "401179"), ("431274", "431274"), ("438935", "438935"), ("451416", "451416"),
             ("457393", "457393"), ("457631", "457632"), ("504175", "504175"), ("506699", "506778"),
             ("509000", "509999"), ("627780", "627780"), ("636297", "636297"), ("636368", "636368"),
             ("650031", "650033"), ("650035", "650051"), ("650405", "650439"), ("650485", "650538"),
             ("650541", "650598"), ("650700", "650718"), ("650720", "650727"), ("650901", "650978"),
             ("651652", "651679"), ("655000", "655019"), ("655021", "655058")), (16,)),
    ("hipercard", (("606282", "606282"), ("384100", "384100"), ("384140", "384140"), ("384160", "384160")), (13, 16, 19)),
    ("amex", (("34", "34"), ("37", "37")), (15,)),
    ("diners", (("300", "305"), ("36", "36"), ("38", "39")), (14, 15, 16, 17, 18, 19)),
    ("jcb", (("3528", "3589"),), (16, 17, 18, 19)),
    ("visa", (("4", "4"),), (13, 16, 19)),
    ("mastercard", (("51", "55"), ("2221", "2720")), (16,)),
    ("discover", (("6011", "6011"), ("644", "649"), ("65", "65")), (16, 17, 18, 19)),
    ("unionpay", (("62", "62"),), (16, 17, 18, 19)),
    ("maestro", (("50", "50"), ("56", "58"), ("6", "6")), (12, 13, 14, 15, 16, 17, 18, 19)),
)


def card_brand(pan: str) -> str | None:
    """Card brand of a 12-19 digit PAN with a valid Luhn digit and a known IIN/length, else None."""
    digits = re.sub(r"[ -]", "", pan or "")
    if not digits.isdigit() or not 12 <= len(digits) <= 19 or not val.luhn_valid(digits) or len(set(digits)) < 2:
        return None
    for brand, ranges, lengths in CARD_BRANDS:
        if len(digits) not in lengths:
            continue
        for low, high in ranges:
            head = digits[: len(low)]
            if low <= head <= high:
                return brand
    return None


#: Accepted digit groupings of a printed PAN (no separator, or one of these layouts).
_PAN_LAYOUTS = frozenset({(4, 4, 4, 4), (4, 6, 5), (4, 6, 4), (4, 4, 4, 4, 3), (4, 4, 4, 3), (4, 4, 4, 1), (4, 4, 5), (4, 4, 4, 2)})


def _payment_card(value: str) -> bool:
    groups = re.split(r"[ -]", value)
    if len(groups) > 1 and (len({c for c in value if c in " -"}) != 1 or tuple(len(g) for g in groups) not in _PAN_LAYOUTS):
        return False
    return card_brand(value) is not None


def mask_pan(value: str) -> str:
    """Same-length mask keeping BIN6 and the last 4 digits ('4111 11** **** 1111')."""
    digits_seen = 0
    total = sum(c.isdigit() for c in value)
    out = []
    for c in value:
        if c.isdigit():
            digits_seen += 1
            out.append(c if digits_seen <= 6 or digits_seen > total - 4 else "*")
        else:
            out.append(c)
    return "".join(out)


#: IBAN lengths per country (SpiderFoot ``extractIbansFromText``, MIT).
IBAN_LENGTHS: dict[str, int] = {
    "AL": 28, "AD": 24, "AT": 20, "AZ": 28, "ME": 22, "BH": 22, "BY": 28, "BE": 16, "BA": 20, "BR": 29, "BG": 22,
    "CR": 22, "HR": 21, "CY": 28, "CZ": 24, "DK": 18, "DO": 28, "EG": 29, "SV": 28, "FO": 18, "FI": 18, "FR": 27,
    "GE": 22, "DE": 22, "GI": 23, "GR": 27, "GL": 18, "GT": 28, "VA": 22, "HU": 28, "IS": 26, "IQ": 23, "IE": 22,
    "IL": 23, "JO": 30, "KZ": 20, "XK": 20, "KW": 30, "LV": 21, "LB": 28, "LI": 21, "LT": 20, "LU": 20, "MT": 31,
    "MR": 27, "MU": 30, "MD": 24, "MC": 27, "DZ": 24, "AO": 25, "BJ": 28, "VG": 24, "BF": 27, "BI": 16, "CM": 27,
    "CV": 25, "CG": 27, "EE": 20, "GA": 27, "GG": 22, "IR": 26, "IM": 22, "IT": 27, "CI": 28, "JE": 22, "MK": 19,
    "MG": 27, "ML": 28, "MZ": 25, "NL": 18, "NO": 15, "PK": 24, "PS": 29, "PL": 28, "PT": 25, "QA": 29, "RO": 24,
    "LC": 32, "SM": 27, "ST": 25, "SA": 24, "SN": 28, "RS": 22, "SC": 31, "SK": 24, "SI": 19, "ES": 24, "CH": 21,
    "TL": 23, "TN": 24, "TR": 26, "UA": 29, "AE": 23, "GB": 22, "SE": 24,
}


def iban_valid(value: str) -> bool:
    """Country length (SpiderFoot table) and the ISO 13616 mod-97 check."""
    iban = re.sub(r"\s", "", value or "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", iban) or IBAN_LENGTHS.get(iban[:2]) != len(iban):
        return False
    moved = iban[4:] + iban[:4]
    return int("".join(str(int(c, 36)) for c in moved)) % 97 == 1


def mask_iban(value: str) -> str:
    """Same-length mask keeping the country, the check digits and the last 4 characters."""
    alnum_total = sum(c.isalnum() for c in value)
    seen = 0
    out = []
    for c in value:
        if c.isalnum():
            seen += 1
            out.append(c if seen <= 4 or seen > alnum_total - 4 else "*")
        else:
            out.append(c)
    return "".join(out)


def mask_cpf_inplace(value: str) -> str:
    """Same-length government mask of a CPF ('***.456.789-**', '***456789**'): digits 4-9 kept."""
    seen = 0
    out = []
    for c in value:
        if c.isdigit():
            seen += 1
            out.append(c if 4 <= seen <= 9 else "*")
        else:
            out.append(c)
    return "".join(out)


def _cpf(value: str) -> bool:
    return val.cpf_valid(value)


def _cnpj(value: str) -> bool:
    return val.cnpj_valid(value)


# ---- crypto -------------------------------------------------------------------------------


def _chain(*chains: str) -> Callable[[str], bool]:
    def check(value: str) -> bool:
        info = val.crypto_address_info(value)
        return info is not None and info.chain in chains and info.checksum_ok is True

    return check


def _eth(value: str) -> bool:
    return val.eth_checksum_state(value) != "invalid"


# ---- analytics ----------------------------------------------------------------------------


def _ga_ua(value: str) -> bool:
    _, account, profile = value.split("-")
    return int(account) > 0 and 0 < int(profile) < 10000


def _ga4(value: str) -> bool:
    body = value[2:]
    return sum(c.isdigit() for c in body) >= 2 and sum(c.isalpha() for c in body) >= 2


def _gtm(value: str) -> bool:
    body = value[4:]
    return any(c.isalpha() for c in body) and any(c.isdigit() for c in body)


def _adsense(value: str) -> bool:
    digits = value.rsplit("-", 1)[-1]
    return len(digits) == 16 and int(digits) > 0


def _meta_pixel(value: str) -> bool:
    return value.isdigit() and 15 <= len(value) <= 16 and _distinct(value, 3)


# ---- SRV names and headers (SpiderFoot sfp_dnscommonsrv / sfp_strangeheaders) ---------------

#: The 25 common SRV service names of SpiderFoot ``sfp_dnscommonsrv`` (MIT).
SRV_NAMES: frozenset[str] = frozenset({
    "_ldap._tcp", "_gc._msdcs", "_ldap._tcp.pdc._msdcs", "_ldap._tcp.gc._msdcs", "_kerberos._tcp.dc._msdcs",
    "_kerberos._tcp", "_kerberos._udp", "_kerberos-master._tcp", "_kerberos-master._udp", "_kpasswd._tcp",
    "_kpasswd._udp", "_ntp._udp", "_sip._tcp", "_sip._udp", "_sip._tls", "_sips._tcp", "_stun._tcp", "_stun._udp",
    "_stuns._tcp", "_turn._tcp", "_turn._udp", "_turns._tcp", "_jabber._tcp", "_xmpp-client._tcp", "_xmpp-server._tcp",
})


def _srv(value: str) -> bool:
    low = value.lower()
    return any(low == name or low.startswith(name + ".") for name in SRV_NAMES)


#: Standard HTTP response headers (SpiderFoot ``sfp_strangeheaders``, MIT); anything else is "odd".
STANDARD_HEADERS: frozenset[str] = frozenset({
    "accept-patch", "accept-ranges", "access-control-allow-credentials", "access-control-allow-headers",
    "access-control-allow-methods", "access-control-allow-origin", "access-control-expose-headers",
    "access-control-max-age", "age", "allow", "alt-svc", "cache-control", "connection", "content-disposition",
    "content-encoding", "content-language", "content-length", "content-location", "content-md5", "content-range",
    "content-security-policy", "content-type", "date", "delta-base", "etag", "expires", "im", "last-modified", "link",
    "location", "p3p", "pragma", "proxy-authenticate", "public-key-pins", "refresh", "retry-after", "server",
    "set-cookie", "status", "strict-transport-security", "timing-allow-origin", "tk", "trailer", "transfer-encoding",
    "upgrade", "vary", "via", "warning", "www-authenticate", "x-content-duration", "x-content-security-policy",
    "x-content-type-options", "x-correlation-id", "x-frame-options", "x-powered-by", "x-request-id",
    "x-ua-compatible", "x-webkit-csp", "x-xss-protection",
})


def _odd_header(value: str) -> bool:
    name = value.split(":", 1)[0].strip().lower()
    return name.startswith("x-") and name not in STANDARD_HEADERS


# --------------------------------------------------------------------------------------
# the DB
# --------------------------------------------------------------------------------------


def _v(*parts: str) -> str:
    """Join vector parts (secret-looking vectors are built from pieces so no literal token sits in
    the source tree; every vector is synthetic or a documented example value)."""
    return "".join(parts)


def _p(name: str, kind: str, regex: str, validator: Callable[[str], bool] | None, confidence: float, *,
       ok: Iterable[str] = (), bad: Iterable[str] = (), group: int = 1, flags: int = 0, enabled: bool = True,
       consumer: str = "", entity_type: str = "", mask: bool = False, hints: Iterable[str] = (), source: str = "",
       description: str = "") -> Pattern:
    return Pattern(name, kind, re.compile(regex, flags), validator, confidence, enabled, consumer, tuple(ok), tuple(bad),
                   group, entity_type, mask, tuple(h.lower() for h in hints), source, description)


_LK = "lemmeknow regex.json (MIT)"
_SF = "SpiderFoot (MIT)"
_V3 = "V3LUM"
_AWS_PREFIXES = ("AKIA", "ASIA", "ABIA", "ACCA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA")
_JWT_OK = _v("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", ".", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", ".", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")

#: The pattern DB (P323). Read-only; the extraction engine and detect() consume it.
PATTERNS: tuple[Pattern, ...] = (
    # ---------------------------------------------------------------- secrets (masked, never sent)
    _p("aws_access_key_id", "secret", r"(?<![A-Z0-9])((?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z2-7]{16})(?![A-Z0-9])",
       _aws_key_id, 0.95, ok=("AKIAIOSFODNN7EXAMPLE",), bad=("AKIAIOSFODNN7EXAMPL", "AKIA" + "Q" * 16, "AKIA1111111111111111"),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=_AWS_PREFIXES, source=_LK, description="AWS access key id"),
    _p("gcp_api_key", "secret", r"(?<![A-Za-z0-9_-])(AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9_-])", _length(39, skip=4), 0.9,
       ok=(_v("AIza", "SyV3lumSyntheticGoogleKey0000000000"),), bad=(_v("AIza", "Short0000"), _v("AIza", "x" * 35)),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("AIza",), source=_LK, description="Google Cloud / Maps API key"),
    _p("google_oauth_access_token", "secret", r"(?<![A-Za-z0-9_.-])(ya29\.[0-9A-Za-z_-]{30,2048})(?![A-Za-z0-9_-])", _min_length(35, skip=5), 0.85,
       ok=(_v("ya29", ".", "a0V3lumSyntheticOAuthAccessToken0123456789"),), bad=(_v("ya29", ".", "short"), _v("ya29", ".", "a" * 40)),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("ya29.",), source=_LK, description="Google OAuth access token"),
    _p("google_oauth_client_secret", "secret", r"(?<![A-Za-z0-9_-])(GOCSPX-[A-Za-z0-9_-]{28})(?![A-Za-z0-9_-])", _length(35, skip=7), 0.95,
       ok=(_v("GOCSPX", "-", "V3lumSyntheticClientSecret00"),), bad=(_v("GOCSPX", "-", "tooShort"), _v("GOCSPX", "-", "a" * 28)),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("GOCSPX-",), source=_V3, description="Google OAuth client secret"),
    _p("azure_storage_account_key", "secret", r"AccountKey=([A-Za-z0-9+/]{86}==)", _b64_bytes(64), 0.95,
       ok=(_v("AccountKey=", base64.b64encode(bytes(range(64))).decode()),), bad=(_v("AccountKey=", "A" * 86, "=="),),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("accountkey=",), source=_V3, description="Azure storage account key (connection string)"),
    _p("github_token", "secret", r"(?<![A-Za-z0-9_])((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})(?![A-Za-z0-9_])",
       _length(40, 93, skip=4), 0.95, ok=(_v("ghp", "_", "V3lumSyntheticTokenForTests0123456789"[:36]),), bad=(_v("ghp", "_", "short0"), _v("ghp", "_", "A" * 36)),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"), source=_LK,
       description="GitHub personal/OAuth/app token"),
    _p("gitlab_token", "secret", r"(?<![A-Za-z0-9_])(glpat-[A-Za-z0-9_-]{20})(?![A-Za-z0-9_-])", _length(26, skip=6), 0.95,
       ok=(_v("glpat", "-", "V3lumSyntheticTok3n0"),), bad=(_v("glpat", "-", "short"), _v("glpat", "-", "a" * 20)),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("glpat-",), source=_V3, description="GitLab personal access token"),
    _p("slack_token", "secret", r"(?<![A-Za-z0-9])(xox[abposr]-\d{6,13}-[A-Za-z0-9-]{8,200})(?![A-Za-z0-9-])", _slack_token, 0.9,
       ok=(_v("xox", "b-", "123456789012-", "1234567890123-", "V3lumSyntheticSlackToken0"),), bad=(_v("xox", "b-", "short"), _v("xox", "q-", "123456-abcdefgh")),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("xox",), source=_LK, description="Slack token"),
    _p("slack_webhook", "secret", r"(https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24})(?![A-Za-z0-9])", _webhook_path(4), 0.95,
       ok=(_v("https://hooks.slack.com/services/", "T00000000/", "B00000000/", "V3lumSyntheticWebhook000"),), bad=("https://hooks.slack.com/services/T0/B0/short",),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("hooks.slack.com",), source=_LK, description="Slack incoming webhook URL"),
    _p("stripe_secret_key", "secret", r"(?<![A-Za-z0-9])((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,247})(?![A-Za-z0-9])", _min_length(32, skip=8), 0.95,
       ok=(_v("sk", "_live_", "V3lumSyntheticStripeKey0"),), bad=(_v("sk", "_live_", "short"), _v("pk", "_live_", "V3lumSyntheticStripeKey0")),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("k_live_", "k_test_"), source=_LK, description="Stripe secret/restricted key"),
    _p("jwt", "secret", r"(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{2,4096}\.eyJ[A-Za-z0-9_-]{2,16384}\.[A-Za-z0-9_-]{0,2048})(?![A-Za-z0-9_-])", _jwt, 0.95,
       ok=(_JWT_OK, _v("eyJhbGciOiJub25lIn0", ".", "eyJzdWIiOiJ4In0", ".")), bad=(_v("eyJub3RqdyI6MX0", ".", "eyJzdWIiOiJ4In0", ".", "abc"), "eyJxx.eyJyy.zz"),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("eyj",), source=_LK, description="JSON Web Token (header with an alg, never verified)"),
    _p("telegram_bot_token", "secret", r"(?<![A-Za-z0-9:_-])(\d{8,10}:AA[A-Za-z0-9_-]{33})(?![A-Za-z0-9_-])", _telegram_bot_token, 0.9,
       ok=(_v("123456789", ":AA", "V3lumSyntheticBotTokenForTests0000"[:33]),), bad=(_v("123456789", ":AA", "short"), _v("123456789", ":AA", "a" * 33)),
       consumer=CORE_MASKING, entity_type="telegram_bot_token", mask=True, hints=(":aa",), source=_V3, description="Telegram bot token"),
    _p("discord_webhook", "secret", r"(https://(?:(?:canary|ptb)\.)?discord(?:app)?\.com/api(?:/v\d{1,2})?/webhooks/\d{17,20}/[A-Za-z0-9_-]{60,80})(?![A-Za-z0-9_-])",
       _webhook_path(4), 0.95, ok=(_v("https://discord.com/api/webhooks/", "123456789012345678/", ("V3lumSyntheticDiscordWebhookToken" * 3)[:68]),),
       bad=("https://discord.com/api/webhooks/12/short",), consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("/webhooks/",), source=_LK,
       description="Discord webhook URL"),
    _p("discord_bot_token", "secret", r"([MNO](?<![A-Za-z0-9_.-][MNO])[A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})(?![A-Za-z0-9_.-])",
       _discord_bot_token, 0.9, ok=(_v(base64.b64encode(b"123456789012345678").decode().rstrip("="), ".", "GV3lum", ".", "V3lumSyntheticDiscordBotToken00"),),
       bad=(_v("MTIzNDU2Nzg5MDEyMzQ1Njc4", "x", ".", "GV3lum", ".", "V3lumSyntheticDiscordBotToken00"), _v("N" * 24, ".", "abcdef", ".", "b" * 27)),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("m", "n", "o"), source=_LK, description="Discord bot token (user id checked)"),
    _p("private_key_block", "secret", r"(-----BEGIN ((?:[A-Z0-9]+ ){0,3})PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,16384}?-----END \2PRIVATE KEY(?: BLOCK)?-----)",
       _private_key, 0.99, ok=(_v("-----BEGIN ", "RSA PRIVATE KEY-----\nMIIBV3lumSyntheticBody\n-----END RSA ", "PRIVATE KEY-----"),),
       bad=(_v("-----BEGIN ", "PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----"),), consumer=CORE_MASKING, entity_type="secret", mask=True,
       hints=("private key",), source=_LK, description="PEM/OpenSSH/PGP private-key block"),
    _p("sendgrid_api_key", "secret", r"(?<![A-Za-z0-9_.-])(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])", _length(69, skip=3), 0.95,
       ok=(_v("SG", ".", "V3lumSyntheticSendGrid", ".", ("V3lumSyntheticSendGridSecretPart" * 2)[:43]),), bad=(_v("SG", ".", "short", ".", "short"), _v("SG", ".", "a" * 22, ".", "a" * 43)),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("sg.",), source=_LK, description="SendGrid API key"),
    _p("mailgun_api_key", "secret", r"(?<![A-Za-z0-9_-])(key-[0-9a-f]{32})(?![0-9a-f])", _length(36, skip=4), 0.8,
       ok=(_v("key", "-", "0123456789abcdef0123456789abcdef"),), bad=(_v("key", "-", "0" * 32), _v("key", "-", "0123")),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("key-",), source=_LK, description="Mailgun API key"),
    _p("square_token", "secret", r"(?<![A-Za-z0-9_-])((?:sq0atp|sq0csp|sandbox-sq0csp)-[0-9A-Za-z_-]{22,43}|EAAA[A-Za-z0-9_-]{60})(?![A-Za-z0-9_-])",
       _min_length(29, skip=7), 0.85, ok=(_v("sq0atp", "-", "V3lumSyntheticSquare00"),), bad=(_v("sq0atp", "-", "short"), _v("sq0atp", "-", "a" * 22)),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("sq0", "eaaa"), source=_LK, description="Square access token / OAuth secret"),
    _p("paypal_braintree_token", "secret", r"(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})", _min_length(60, skip=24), 0.95,
       ok=(_v("access_token$production$", "v3lumsynthetic00", "$", "0123456789abcdef0123456789abcdef"),), bad=("access_token$production$short$00",),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("access_token$production$",), source=_LK, description="PayPal Braintree access token"),
    _p("amazon_mws_token", "secret", r"(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", _min_length(45, skip=9), 0.95,
       ok=(_v("amzn", ".mws.", "01234567-89ab-cdef-0123-456789abcdef"),), bad=(_v("amzn", ".mws.", "0123"),),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("amzn.mws.",), source=_LK, description="Amazon MWS auth token"),
    _p("npm_token", "secret", r"(?<![A-Za-z0-9_])(npm_[A-Za-z0-9]{36})(?![A-Za-z0-9])", _length(40, skip=4), 0.95,
       ok=(_v("npm", "_", "V3lumSyntheticNpmTokenForTests000000"),), bad=(_v("npm", "_", "short"), _v("npm", "_", "a" * 36)),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("npm_",), source=_LK, description="npm access token"),
    _p("pypi_token", "secret", r"(?<![A-Za-z0-9_-])(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,300})(?![A-Za-z0-9_-])", _min_length(70, skip=19), 0.99,
       ok=(_v("pypi", "-AgEIcHlwaS5vcmc", ("V3lumSyntheticPyPIUploadToken" * 3)[:60]),), bad=(_v("pypi", "-AgEIcHlwaS5vcmc", "short"),),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("pypi-",), source=_LK, description="PyPI upload token"),
    _p("nuget_api_key", "secret", r"(?<![a-z0-9])(oy2[a-z0-9]{43})(?![a-z0-9])", lambda s: _distinct(s, 8) and any(c.isdigit() for c in s[3:]), 0.8,
       ok=(_v("oy2", "v3lumsyntheticnugetkey0123456789abcdefghijk"),), bad=(_v("oy2", "a" * 43), _v("oy2", "short")),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("oy2",), source=_LK, description="NuGet API key"),
    _p("dynatrace_token", "secret", r"(?<![A-Za-z0-9])(dt0[a-zA-Z][0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64})(?![A-Za-z0-9])", _length(96, skip=7), 0.95,
       ok=(_v("dt0c01", ".", "V3LUMSYNTHETICDYNATRACE0", ".", ("V3LUMSYNTHETICDYNATRACESECRET0" * 3)[:64]),), bad=(_v("dt0c01", ".", "SHORT", ".", "SHORT"),),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("dt0",), source=_LK, description="Dynatrace API token"),
    _p("new_relic_key", "secret", r"(?<![A-Za-z0-9])(NRAK-[A-Z0-9]{27}|NRAA-[a-f0-9]{27}|NRRA-[a-f0-9]{42}|NRI[IQ]-[A-Za-z0-9_-]{32})(?![A-Za-z0-9_-])",
       _min_length(32, skip=5), 0.9, ok=(_v("NRAK", "-", "V3LUMSYNTHETICNEWRELICKEY00"),), bad=(_v("NRAK", "-", "SHORT"), _v("NRAK", "-", "A" * 27)),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("nrak-", "nraa-", "nrra-", "nrii-", "nriq-"), source=_LK, description="New Relic API key"),
    _p("shopify_token", "secret", r"(?<![A-Za-z0-9_])(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})(?![A-Za-z0-9])", _length(38, skip=6), 0.95,
       ok=(_v("shpat", "_", "0123456789abcdef0123456789abcdef"),), bad=(_v("shpat", "_", "0" * 32), _v("shpat", "_", "0123")),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("shpat_", "shpca_", "shppa_", "shpss_"), source=_LK, description="Shopify access token / shared secret"),
    _p("digitalocean_token", "secret", r"(?<![A-Za-z0-9_])(do[opr]_v1_[a-f0-9]{64})(?![a-f0-9])", _length(71, skip=7), 0.95,
       ok=(_v("dop", "_v1_", "0123456789abcdef" * 4),), bad=(_v("dop", "_v1_", "0" * 64), _v("dop", "_v1_", "0123")),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("_v1_",), source=_V3, description="DigitalOcean token"),
    _p("openai_api_key", "secret", r"(?<![A-Za-z0-9_-])(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,300})(?![A-Za-z0-9_-])", _min_length(28, skip=8), 0.9,
       ok=(_v("sk", "-proj-", "V3lumSyntheticOpenAIKey0123"),), bad=(_v("sk", "-proj-", "short"), _v("sk", "-proj-", "a" * 30)),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("sk-proj-", "sk-svcacct-", "sk-admin-"), source=_V3, description="OpenAI API key"),
    _p("anthropic_api_key", "secret", r"(?<![A-Za-z0-9_-])(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,120})(?![A-Za-z0-9_-])", _min_length(90, skip=14), 0.95,
       ok=(_v("sk", "-ant-api03-", ("V3lumSyntheticAnthropicKey" * 4)[:90]),), bad=(_v("sk", "-ant-api03-", "short"),),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("sk-ant-",), source=_V3, description="Anthropic API key"),
    _p("huggingface_token", "secret", r"(?<![A-Za-z0-9_])(hf_[A-Za-z0-9]{34,40})(?![A-Za-z0-9])", _min_length(37, skip=3), 0.9,
       ok=(_v("hf", "_", "V3lumSyntheticHuggingFaceToken0000"),), bad=(_v("hf", "_", "short"), _v("hf", "_", "a" * 34)),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("hf_",), source=_V3, description="Hugging Face token"),
    _p("google_fcm_server_key", "secret", r"(?<![A-Za-z0-9_-])(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})(?![A-Za-z0-9_-])", _length(152, skip=12), 0.9,
       ok=(_v("AAAA", "V3lumSy", ":", ("V3lumSyntheticFirebaseCloudMessagingServerKey" * 4)[:140]),), bad=(_v("AAAA", "V3lumSy", ":", "short"),),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("aaaa",), source=_LK, description="Firebase Cloud Messaging server key"),
    _p("notion_token", "secret", r"(?<![A-Za-z0-9_])(secret_[A-Za-z0-9]{43})(?![A-Za-z0-9])", _length(50, skip=7), 0.8,
       ok=(_v("secret", "_", "V3lumSyntheticNotionIntegrationToken0123456"),), bad=(_v("secret", "_", "short"), _v("secret", "_", "a" * 43)),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("secret_",), source=_LK, description="Notion integration token"),
    _p("mailchimp_api_key", "secret", r"(?<![0-9a-f])([0-9a-f]{32}-us\d{1,2})(?![0-9A-Za-z])", _mailchimp, 0.9,
       ok=(_v("0123456789abcdef0123456789abcdef", "-us", "21"),), bad=(_v("0" * 32, "-us", "21"), _v("0123456789abcdef0123456789abcdef", "-us", "0")),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("-us",), source=_LK, description="Mailchimp API key"),
    _p("totp_uri", "secret", r"(otpauth://[th]otp/[^\s\"'<>]{1,1000})", _totp, 0.95,
       ok=("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example",), bad=("otpauth://totp/Example:alice?issuer=Example",),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("otpauth://",), source=_LK, description="TOTP/HOTP provisioning URI (holds the seed)"),
    _p("cloudinary_url", "secret", r"(cloudinary://\d{6,20}:[A-Za-z0-9_-]{16,64}@[A-Za-z0-9_.-]{1,64})", _min_length(30, skip=13), 0.95,
       ok=(_v("cloudinary://", "123456789012345:", "V3lumSyntheticCloudSecret@democloud"),), bad=("cloudinary://123:short@x",),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("cloudinary://",), source=_LK, description="Cloudinary credentials URL"),
    _p("ms_teams_webhook", "secret", r"(https://(?:[A-Za-z0-9-]{1,63}\.webhook\.office\.com/webhookb2|outlook\.office\.com/webhook)/[A-Za-z0-9@/_-]{40,400})",
       _webhook_path(4), 0.9, ok=(_v("https://example.webhook.office.com/webhookb2/", "0" * 36, "@", "1" * 36, "/IncomingWebhook/", "a" * 32, "/", "b" * 36),),
       bad=("https://example.webhook.office.com/webhookb2/short",), consumer=CORE_MASKING, entity_type="secret", mask=True,
       hints=("webhook.office.com", "outlook.office.com/webhook"), source=_LK, description="Microsoft Teams incoming webhook URL"),
    _p("zapier_webhook", "secret", r"(https://hooks\.zapier\.com/hooks/catch/\d{3,12}/[a-z0-9]{4,12}/?)(?![A-Za-z0-9])", _webhook_path(4), 0.85,
       ok=("https://hooks.zapier.com/hooks/catch/123456/abcd12/",), bad=("https://hooks.zapier.com/hooks/catch/12/a/",),
       consumer=CORE_MASKING, entity_type="secret", mask=True, hints=("hooks.zapier.com",), source=_LK, description="Zapier catch-hook URL"),
    _p("facebook_access_token", "secret", r"(?<![A-Za-z0-9])(EAA[A-Za-z0-9]{90,400})(?![A-Za-z0-9])", None, 0.5, enabled=False,
       entity_type="secret", mask=True, hints=("eaa",), source=_LK, description="Facebook access token (no validator: disabled)"),
    # ---------------------------------------------------------------- financial (masked, never sent)
    _p("payment_card", "financial", r"(\d(?<![0-9A-Za-z]\d)(?:[ -]?\d){11,18})(?![0-9A-Za-z])", _payment_card, 0.95,
       ok=("4111111111111111", "4111 1111 1111 1111", "5555555555554444", "378282246310005", "6362970000457013", "3782 822463 10005"),
       bad=("4111111111111112", "1234567812345670", "4111 11111111 1111", "0000000000000000"),
       consumer=CORE_MASKING, entity_type="payment_card", mask=True, source=_SF + " + " + _LK,
       description="payment card number (Luhn + brand IIN/length; truncated to BIN6…last4 at detection)"),
    _p("iban", "financial", r"([A-Z](?<![A-Za-z0-9][A-Z])[A-Z]\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?)(?![A-Za-z0-9])", iban_valid, 0.95,
       ok=("DE89 3704 0044 0532 0130 00", "GB82WEST12345698765432", "BR97 0036 0305 0000 1000 9795 493P 1"),
       bad=("DE89 3704 0044 0532 0130 01", "XX00 0000 0000 0000", "GB82WEST1234569876543"),
       consumer=CORE_MASKING, mask=True, source=_SF, description="IBAN (country length + mod-97); masked, never an entity"),
    # ---------------------------------------------------------------- identifiers
    _p("cpf_formatted", "identifier", r"(\d(?<![0-9.]\d)\d{2}\.\d{3}\.\d{3}-\d{2})(?![0-9])", _cpf, 0.95,
       ok=("111.444.777-35", "529.982.247-25"), bad=("111.444.777-36", "000.000.000-00"),
       consumer=CORE_MASKING, mask=True, source=_V3, description="CPF (validated offline only; masked, counted, never an entity)"),
    _p("cpf_labelled", "identifier", r"(?i)C(?<![A-Za-z0-9]C)PF(?:\s*(?:n[º°o.]?|number|numero|número))?[\s:=#.-]{0,4}(\d{11})(?![0-9])", _cpf, 0.9,
       ok=("CPF 11144477735", "cpf: 52998224725"), bad=("CPF 11144477736", "CPF 1114447773"),
       consumer=CORE_MASKING, mask=True, source=_V3, description="bare 11-digit CPF after a 'CPF' label (never typed from bare digits)"),
    _p("cnpj_formatted", "identifier", r"([0-9A-Z](?<![0-9A-Za-z][0-9A-Z])[0-9A-Z]\.[0-9A-Z]{3}\.[0-9A-Z]{3}/[0-9A-Z]{4}-\d{2})(?![0-9A-Za-z])", _cnpj, 0.95,
       ok=("11.222.333/0001-81", "00.000.000/0001-91", "12.ABC.345/01DE-35"), bad=("11.222.333/0001-82", "00.000.000/0000-00"),
       consumer="cnpj_lookup", entity_type="cnpj", hints=("/",), source=_V3, description="CNPJ with valid check digits (alphanumeric CNPJ included)"),
    _p("cnpj_bare", "identifier", r"(\d(?<![0-9A-Za-z.,/-]\d)\d{13})(?![0-9A-Za-z])", _cnpj, 0.75,
       ok=("11222333000181",), bad=("11222333000182", "00000000000000"),
       consumer="cnpj_lookup", entity_type="cnpj", source=_V3, description="14-digit CNPJ with a valid DV"),
    _p("uuid", "identifier", r"(?<![0-9A-Fa-f-])([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12})(?![0-9A-Fa-f-])",
       None, 0.3, enabled=False, source=_LK, description="UUID (generic: disabled)"),
    _p("ulid", "identifier", r"(?<![0-9A-Z])([0-9A-HJKMNP-TV-Z]{26})(?![0-9A-Z])", None, 0.1, enabled=False, source=_LK, description="ULID (generic: disabled)"),
    _p("phone_generic", "identifier", r"(?<![0-9])(\+?\d{1,3}[-. (]{0,2}\d{3}[-. )]{0,2}\d{3}[-. ]?\d{4})(?![0-9])", None, 0.3, enabled=False,
       source=_LK, description="generic phone number (disabled: BR national formats are validated by the extraction engine)"),
    _p("date_of_birth", "identifier", r"(?<![0-9])((?:[1-9]|[12]\d|3[01])[/.-](?:0[1-9]|1[0-2])[/.-](?:19\d{2}|20\d{2}))(?![0-9])", None, 0.2, enabled=False,
       source=_LK, description="date (generic: disabled)"),
    _p("ssn_us", "identifier", r"(?<![0-9])(\d{3}-\d{2}-\d{4})(?![0-9])", None, 0.3, enabled=False, mask=True, source=_LK,
       description="US social security number (generic: disabled)"),
    _p("unix_timestamp", "identifier", r"(?<![0-9])(1\d{9})(?![0-9])", None, 0.1, enabled=False, source=_LK, description="Unix timestamp (generic: disabled)"),
    _p("aws_arn", "identifier", r"(arn:aws[a-z-]{0,20}:[a-z0-9-]{1,40}:[a-z0-9-]{0,30}:\d{0,12}:[^\s\"'<>]{1,512})", None, 0.4, enabled=False,
       source=_LK, description="AWS ARN (no validator: disabled)"),
    # ---------------------------------------------------------------- crypto (checksummed only)
    _p("btc_base58", "crypto", r"([13](?<![A-Za-z0-9][13])[1-9A-HJ-NP-Za-km-z]{25,34})(?![A-Za-z0-9])", val.btc_address_valid, 0.99,
       ok=("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"), bad=("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", "1" * 30),
       consumer="crypto_sanctions_offline", entity_type="btc_address", source=_LK, description="Bitcoin P2PKH/P2SH (Base58Check)"),
    _p("btc_bech32", "crypto", r"(?<![A-Za-z0-9])((?:bc|tb)1[02-9ac-hj-np-z]{11,71}|(?:BC|TB)1[02-9AC-HJ-NP-Z]{11,71})(?![A-Za-z0-9])", val.btc_address_valid, 0.99,
       ok=("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",), bad=("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdr", "bc1qqqqqqqqqqqqq"),
       consumer="crypto_sanctions_offline", entity_type="btc_address", hints=("bc1", "tb1"), source=_LK, description="Bitcoin segwit (Bech32/Bech32m checksum)"),
    _p("eth", "crypto", r"(?<![A-Za-z0-9])(0x[0-9a-fA-F]{40})(?![0-9A-Za-z])", _eth, 0.9,
       ok=("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe", "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"), bad=("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAE",),
       consumer="crypto_sanctions_offline", entity_type="eth_address", hints=("0x",), source=_LK, description="EVM address (an EIP-55 mixed-case mismatch is refused)"),
    _p("xmr", "crypto", r"([48](?<![A-Za-z0-9][48])[0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?:[1-9A-HJ-NP-Za-km-z]{11})?)(?![A-Za-z0-9])", val.xmr_address_valid, 0.98,
       ok=("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",),
       bad=("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3B",),
       consumer="crypto_sanctions_offline", entity_type="xmr_address", source=_LK, description="Monero (block base58 + Keccak checksum)"),
    _p("ltc", "crypto", r"([LM](?<![A-Za-z0-9][LM])[1-9A-HJ-NP-Za-km-z]{26,33})(?![A-Za-z0-9])", _chain("ltc"), 0.95,
       ok=("LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1",), bad=("LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc2",),
       consumer="crypto_sanctions_offline", entity_type="other_crypto_address", source=_LK, description="Litecoin (Base58Check)"),
    _p("doge", "crypto", r"(D(?<![A-Za-z0-9]D)[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32})(?![A-Za-z0-9])", _chain("doge"), 0.95,
       ok=("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L",), bad=("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7M",),
       consumer="crypto_sanctions_offline", entity_type="other_crypto_address", source=_LK, description="Dogecoin (Base58Check)"),
    _p("dash", "crypto", r"(X(?<![A-Za-z0-9]X)[1-9A-HJ-NP-Za-km-z]{33})(?![A-Za-z0-9])", _chain("dash"), 0.95,
       ok=("XpESxaUmonkq8RaLLp46Brx2K39ggQe226",), bad=("XpESxaUmonkq8RaLLp46Brx2K39ggQe227",),
       consumer="crypto_sanctions_offline", entity_type="other_crypto_address", source=_V3, description="Dash (Base58Check)"),
    _p("tron", "crypto", r"(T(?<![A-Za-z0-9]T)[1-9A-HJ-NP-Za-km-z]{33})(?![A-Za-z0-9])", _chain("tron"), 0.98,
       ok=("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",), bad=("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u",),
       consumer="tron_explorer", entity_type="other_crypto_address", source=_V3, description="TRON (Base58Check, version 0x41: USDT rail of BR scams)"),
    _p("xrp", "crypto", r"(r(?<![A-Za-z0-9]r)[1-9A-HJ-NP-Za-km-z]{24,34})(?![A-Za-z0-9])", _chain("xrp"), 0.95,
       ok=("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",), bad=("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTi",),
       consumer="crypto_sanctions_offline", entity_type="other_crypto_address", source=_LK, description="XRP classic address (ripple alphabet)"),
    _p("bch_cashaddr", "crypto", r"(?<![A-Za-z0-9])((?:bitcoincash:)?[qp][a-z0-9]{41})(?![A-Za-z0-9])", None, 0.3, enabled=False,
       source=_LK, description="Bitcoin Cash cashaddr (no validator here: disabled)"),
    _p("nano", "crypto", r"(?<![A-Za-z0-9_])((?:nano|xrb)_[13][13-9a-km-uw-z]{59})(?![A-Za-z0-9])", None, 0.3, enabled=False,
       source=_LK, description="Nano (no validator here: disabled)"),
    _p("solana", "crypto", r"(?<![A-Za-z0-9])([1-9A-HJ-NP-Za-km-z]{32,44})(?![A-Za-z0-9])", val.sol_address_plausible, 0.4, enabled=False,
       source=_V3, description="Solana (no checksum: low confidence, never typed from free text, P217 cond 2)"),
    # ---------------------------------------------------------------- analytics ids (SpiderFoot sfp_webanalytics)
    _p("ga_universal", "analytics", r"(?<![A-Za-z0-9-])(UA-\d{4,10}-\d{1,4})(?![0-9A-Za-z-])", _ga_ua, 0.9,
       ok=("UA-12345678-1",), bad=("UA-00000000-0", "UA-123-1"),
       consumer="hostio", entity_type="analytics_id", hints=("ua-",), source=_SF, description="Google Analytics (universal) tracking id"),
    _p("ga4_measurement_id", "analytics", r"(?<![A-Za-z0-9-])(G-[A-Z0-9]{10})(?![A-Za-z0-9-])", _ga4, 0.7,
       ok=("G-7XKPWT2Z1M",), bad=("G-ABCDEFGHIJ", "G-1234567890"),
       consumer="hostio", entity_type="analytics_id", hints=("g-",), source=_V3, description="Google Analytics 4 measurement id"),
    _p("gtm_container", "analytics", r"(?<![A-Za-z0-9-])(GTM-[A-Z0-9]{6,8})(?![A-Za-z0-9-])", _gtm, 0.85,
       ok=("GTM-K9XQ7P2",), bad=("GTM-ABCDEFG", "GTM-1234567"),
       consumer="hostio", entity_type="analytics_id", hints=("gtm-",), source=_SF, description="Google Tag Manager container id"),
    _p("adsense_publisher", "analytics", r"(?<![A-Za-z0-9-])((?:ca-)?pub-\d{16})(?![0-9])", _adsense, 0.9,
       ok=("ca-pub-1234567890123456", "pub-1234567890123456"), bad=("pub-0000000000000000", "pub-12345"),
       consumer="hostio", entity_type="analytics_id", hints=("pub-",), source=_SF, description="Google AdSense publisher id"),
    _p("meta_pixel", "analytics", r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{15,16})['\"]", _meta_pixel, 0.9,
       ok=("fbq('init', '123456789012345')",), bad=("fbq('init', '000000000000000')", "fbq('init', '1234')"),
       consumer="hostio", entity_type="analytics_id", hints=("fbq(",), source=_V3, description="Meta (Facebook) pixel id"),
    # ---------------------------------------------------------------- SRV names / odd headers (catalogue: no consumer, not emitted)
    _p("srv_name", "srv", r"(?<![\w.-])(_(?:ldap|gc|kerberos|kerberos-master|kpasswd|ntp|sip|sips|stun|stuns|turn|turns|jabber|xmpp-client|xmpp-server)"
       r"\._(?:tcp|udp|tls|msdcs)(?:\.[A-Za-z0-9_-]{1,63}){0,8})", _srv, 0.9,
       ok=("_ldap._tcp.dc._msdcs.example.com", "_sip._tls.example.com"), bad=("_foo._tcp.example.com", "_ntp._tcp.example.com"),
       hints=("._tcp", "._udp", "._tls", "._msdcs"), source=_SF,
       description="common SRV service names (sfp_dnscommonsrv); SRV lookups obey the TLP gate (P323 cond 8)"),
    _p("odd_header", "header", r"(?m)^(X-[A-Za-z0-9-]{1,62}:[ \t]{0,8}[^\r\n]{1,512})$", _odd_header, 0.6,
       ok=("X-Backend-Server: app-07.internal",), bad=("X-Frame-Options: DENY",),
       source=_SF, description="non-standard X- HTTP response header (sfp_strangeheaders allow-list)"),
)

_BY_NAME: dict[str, Pattern] = {p.name: p for p in PATTERNS}
if len(_BY_NAME) != len(PATTERNS):  # pragma: no cover - guarded by tests
    raise RuntimeError("duplicate pattern names in PATTERNS")


def pattern(name: str) -> Pattern:
    """The pattern called ``name`` (KeyError when unknown)."""
    return _BY_NAME[name]


def emitted() -> list[Pattern]:
    """The patterns :func:`match_patterns` runs by default (enabled + consumer or masking need)."""
    return [p for p in PATTERNS if p.emitted]


def _masked(p: Pattern, value: str) -> str:
    if p.kind == "secret":
        from v3lum.core.entities import secret_fingerprint

        kind = "telegram_bot_token" if p.entity_type == "telegram_bot_token" else p.name
        return secret_fingerprint(kind, value)
    if p.name == "payment_card":
        digits = re.sub(r"\D", "", value)
        return f"{digits[:6]}…{digits[-4:]}"
    if p.name == "iban":
        return mask_iban(value)
    if p.name.startswith("cpf"):
        return mask_cpf_inplace(value)
    if p.mask:
        return "*" * len(value)
    return value


def match_patterns(
    text: str,
    *,
    kinds: Iterable[str] | None = None,
    names: Iterable[str] | None = None,
    include_disabled: bool = False,
    include_unconsumed: bool = False,
    overlapping: bool = False,
) -> list[PatternMatch]:
    """Validated pattern hits in ``text``, in order.

    By default only emitted patterns run (enabled, with a consumer or a masking need);
    ``include_unconsumed`` adds enabled catalogue entries without a consumer (SRV names, odd headers)
    and ``include_disabled`` the generic ones. ``kinds``/``names`` restrict the set. Hits do not
    overlap unless ``overlapping``: an earlier start wins, then the longer match, then the higher
    confidence. Never raises on odd input.
    """
    if not isinstance(text, str) or not text:
        return []
    want_kinds = frozenset(kinds) if kinds is not None else None
    want_names = frozenset(names) if names is not None else None
    low: str | None = None
    hits: list[PatternMatch] = []
    for p in PATTERNS:
        if want_kinds is not None and p.kind not in want_kinds:
            continue
        if want_names is not None and p.name not in want_names:
            continue
        if not p.enabled and not include_disabled:
            continue
        if p.enabled and not p.emitted and not (include_unconsumed or want_names is not None):
            continue
        if p.hints:
            if low is None:
                low = text.lower()
            if not any(h in low for h in p.hints):
                continue
        for m in p.regex.finditer(text):
            value = m.group(p.group)
            if value is None or not p.check(value):
                continue
            start, end = m.span(p.group)
            hits.append(PatternMatch(p.name, p.kind, start, end, value, _masked(p, value), p.confidence, p.entity_type))
    hits.sort(key=lambda h: (h.start, -(h.end - h.start), -h.confidence))
    if overlapping:
        return hits
    out: list[PatternMatch] = []
    last_end = -1
    for hit in hits:
        if hit.start < last_end:
            continue
        out.append(hit)
        last_end = hit.end
    return out


def odd_headers(text: str) -> list[str]:
    """Non-standard ``X-`` response headers in a pasted header dump ('X-Backend-Server: ...')."""
    return [h.value for h in match_patterns(text, names=("odd_header",))]
