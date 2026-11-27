"""Automatic recognition of what the analyst typed, plus IOC extraction from free text.

``detect("john@acme.com")`` -> [Detection(EMAIL, 'john@acme.com', 0.98, ...)]
``detect("11987654321")``   -> CPF (if check digits match) and PHONE alternatives
``extract_iocs(text)``      -> every IOC found in a blob: a thin wrapper over the P172 engine
                               :func:`v3lum.core.ioc.extract` (defanged indicators included)

Forcing a type: ``email:foo@bar.com``, ``user:johndoe``, ``name:Jane Doe``...

Detection v2 (P333 cond 4, P323 cond 1, P217 cond 5, AR18): today's precedence is kept, so a typed
username or phone is never re-typed. The contract-v2 types are detected only from an explicit
``TYPE:value`` prefix, a URL pattern (``t.me/``, ``discord.gg/``, ``discord.com/invite/``,
``bsky.app/profile/``, ``steamcommunity.com/``, ``wa.me/``, profile URLs of the merged social
platforms) or an unambiguous structure (an e-mail header block, ``T1`` + 70 hex for TLSH, a
leading ``@user@instance`` fediverse handle, a PIX BR Code with a valid CRC16) - never from bare
hex or digit length. Checksummed formats are typed only with a passing checksum (an EIP-55
mixed-case mismatch, a Monero or Base58Check failure is not typed; with an explicit prefix it gets
low confidence). Known malware/actor names from the alias index (``v3lum/data/aliases``) are typed
malware_family/threat_actor (confidence 0.8) instead of username. Detection is offline: nothing
is resolved, fetched or looked up (no WebFinger).
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass

from v3lum.core import ioc as _ioc
from v3lum.core import patterns as _patterns
from v3lum.core import psl
from v3lum.core import sanitize as _sanitize
from v3lum.core import validators as val
from v3lum.core.entities import ELLIPSIS, Entity, EntityType, normalize, parse_fingerprint, refang, secret_fingerprint


@dataclass(frozen=True)
class Detection:
    type: EntityType
    value: str
    confidence: float
    reason: str

    @property
    def entity(self) -> Entity:
        return Entity(self.type, self.value)


# Corporate suffixes that make a phrase look like a company name.
_ORG_HINTS = re.compile(
    r"\b(ltda|s\.?/?a\.?|eireli|epp|mei|inc\.?|llc|ltd\.?|limited|gmbh|ag|corp\.?|corporation|company|co\.|plc|"
    r"holding|holdings|group|grupo|banco|bank|foundation|fundacao|fundação|associação|associacao|instituto|"
    r"technologies|tecnologia|consultoria|servicos|serviços|comercio|comércio|industria|indústria|participacoes|"
    r"participações|sociedade|cooperativa)\b",
    re.I,
)

# Lower-case particles that do not need capitals in person names (pt/es/fr/nl/de/it).
_NAME_PARTICLES = frozenset({"da", "de", "do", "das", "dos", "e", "di", "del", "della", "la", "le", "van", "von", "der", "den", "du", "y"})

# TLDs that collide with common file extensions; only trusted from free text with extra context.
_AMBIGUOUS_TLDS = frozenset({"zip", "mov", "py", "sh", "md", "rs", "pl", "sc", "ps", "so", "pm", "ms", "cs", "ts", "js", "go"})

_RE_URL = re.compile(r"^[a-z][a-z0-9+.-]*://\S+$", re.I)
_RE_EMAIL = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9.-]+\.[A-Za-z0-9-]{2,}$")
_RE_HEX = re.compile(r"^[0-9a-fA-F]+$")
_RE_ASN = re.compile(r"^(?:AS|ASN)\s?\d{1,10}$", re.I)
_RE_CVE = re.compile(r"^CVE[-_ ]?\d{4}[-_ ]\d{4,7}$", re.I)
_RE_MITRE = re.compile(r"^(T\d{4}(?:\.\d{3})?|TA\d{4}|M\d{4}|DS\d{4})$", re.I)
_RE_MITRE_GROUP = re.compile(r"^G\d{4}$", re.I)
_RE_MITRE_SOFTWARE = re.compile(r"^S\d{4}$", re.I)
_RE_ETH = re.compile(r"^0x[0-9a-fA-F]{40}$")
_RE_XMR = re.compile(r"^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$")
_RE_LTC = re.compile(r"^(?:[LM][a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1[a-z0-9]{39,59})$")
_RE_TRX = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
_RE_DOGE = re.compile(r"^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$")
_RE_SOL = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{43,44}$")
_RE_MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$|^(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$")
_RE_JWT = re.compile(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
_RE_ANALYTICS = re.compile(r"^(UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{8,12}|GTM-[A-Z0-9]{4,10}|(?:ca-)?pub-\d{10,20}|AW-\d{6,12})$", re.I)
_RE_COORDS = re.compile(r"^\s*-?\d{1,2}\.\d{2,}\s*[,; ]\s*-?\d{1,3}\.\d{2,}\s*$")
_RE_UA = re.compile(r"^(Mozilla|Opera|curl|Wget|python-requests|Go-http-client|okhttp|Dalvik|Java)/\S+", re.I)
_RE_SSDEEP = re.compile(r"^\d+:[A-Za-z0-9/+]+:[A-Za-z0-9/+]+$")
_RE_PLATE = re.compile(r"^[A-Za-z]{3}-?[0-9][A-Za-z0-9][0-9]{2}$")
_RE_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_RE_CEP = re.compile(r"^\d{5}-?\d{3}$")
_RE_CPF_FMT = re.compile(r"^\d{3}\.\d{3}\.\d{3}-\d{2}$")
_RE_CNPJ_FMT = re.compile(r"^[0-9A-Za-z]{2}\.[0-9A-Za-z]{3}\.[0-9A-Za-z]{3}/[0-9A-Za-z]{4}-\d{2}$")
_RE_PHONE_FMT = re.compile(r"^\+?[\d\s().-]{8,22}$")
_RE_USERNAME = re.compile(r"^@?[A-Za-z0-9_.\-]{2,40}$")
_RE_PERSON_WORD = re.compile(r"^[A-Za-zÀ-ÖØ-öø-ÿ'’.-]+$")
_RE_ONION = re.compile(r"^(?:https?://)?(?:[a-z0-9-]+\.)*[a-z2-7]{56}\.onion(?:/.*)?$", re.I)


_RE_TLSH = re.compile(r"^[Tt]1[0-9A-Fa-f]{70}$")
_RE_URL_USERINFO = re.compile(r"^[a-z][a-z0-9+.-]*://[^/?#\s@]*@", re.I)
_RE_FEDIVERSE = re.compile(r"^@[A-Za-z0-9_.-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")
_RE_HEADER_START = re.compile(r"^(?:From |Received:|Return-Path:|Delivered-To:|From:|Message-ID:|Subject:|Date:|X-[\w-]+:)", re.I)
#: URL hosts whose links name an account or invite (P333 cond 4).
_ACCOUNT_URL = re.compile(
    r"^(?:https?://)?(?:(?:www|m|mobile|web)\.)?(?:t\.me|telegram\.me|telegram\.dog|discord\.gg|discord(?:app)?\.com/invite|"
    r"bsky\.app/profile|steamcommunity\.com/(?:id|profiles)|wa\.me|api\.whatsapp\.com/send)[/?]",
    re.I,
)


def _named(raw: str) -> list[tuple[EntityType, str]]:
    """Known threat-actor / malware names (alias index, ``v3lum.core.ioc.alias_lookup``)."""
    try:
        return _ioc.alias_lookup(raw)
    except Exception:  # noqa: BLE001 - a damaged alias fragment never breaks detection
        return []


def _typed_url(s_ref: str) -> list[tuple[Entity, str]]:
    """Typed accounts named by an account/invite URL or a social-platform profile URL."""
    if not (_ACCOUNT_URL.match(s_ref) or "/" in s_ref):
        return []
    try:
        return _ioc.url_typed_entities(s_ref)
    except Exception:  # noqa: BLE001
        return []


#: A single value longer than this is never checked as one whole secret (a pasted text instead).
_SENSITIVE_MAX = 20000


def _sensitive_single(s: str) -> list[Detection] | None:
    """A single value that IS a secret, a payment card or an IBAN (P323 cond 5-7, AR24).

    Returns the only interpretation (secret fingerprint / ``BIN6…last4``), ``[]`` for an IBAN (no
    entity type: masked everywhere, never investigated) or None for anything else, so a raw key,
    token or card number never becomes a username/keyword/URL seed that modules would receive.
    JWTs keep their own (structure-gated) detection below.
    """
    if not s or len(s) > _SENSITIVE_MAX:
        return None
    if ELLIPSIS in s:
        fp = parse_fingerprint(s)
        if fp is not None:  # a value scrubbed earlier (sanitize.scrub_text / ioc.scrub)
            etype = EntityType.TELEGRAM_BOT_TOKEN if fp[0] == "telegram_bot_token" else EntityType.SECRET
            return [Detection(etype, s, 0.95, f"secret fingerprint ({fp[0]}): masked, never used or sent")]
        m = re.fullmatch(r"(\d{6})…(\d{4})", s)
        if m:
            return [Detection(EntityType.PAYMENT_CARD, s, 0.9, "truncated payment card (BIN6…last4): never investigated")]
    for hit in _patterns.match_patterns(s, kinds=("secret", "financial")):
        if hit.start != 0 or hit.end != len(s) or hit.name == "jwt":
            continue
        if hit.name == "iban":
            return []
        if hit.kind == "financial":
            digits = re.sub(r"\D", "", s)
            if len(digits) == 14 and val.cnpj_valid(digits):
                return None  # a CNPJ whose digits also pass Luhn
            brand = _patterns.card_brand(digits) or "card"
            if len(digits) == 15 and brand not in ("amex", "diners"):
                return None  # 15 digits: an IMEI as often as a (Maestro) card - today's IMEI reading stays
            return [Detection(EntityType.PAYMENT_CARD, hit.masked, 0.9,
                              f"{brand} card number (Luhn): truncated to BIN6…last4, never investigated")]
        etype = EntityType.TELEGRAM_BOT_TOKEN if hit.entity_type == "telegram_bot_token" else EntityType.SECRET
        return [Detection(etype, hit.masked, 0.95, f"{hit.name.replace('_', ' ')}: fingerprint only, never used or sent")]
    for hit in _sanitize.find_secrets(s, distinctive_only=True):
        if hit.action == "mask" and hit.start == 0 and hit.end == len(s):
            etype = EntityType.TELEGRAM_BOT_TOKEN if hit.kind == "telegram_bot_token" else EntityType.SECRET
            return [Detection(etype, secret_fingerprint(hit.kind, hit.value), 0.95,
                              f"{hit.kind.replace('_', ' ')}: fingerprint only, never used or sent")]
    return None


def _domain_ok(v: str, from_text: bool = False, had_defang: bool = False) -> str | None:
    try:
        d = normalize(EntityType.DOMAIN, v)
    except ValueError:
        return None
    tld = d.rsplit(".", 1)[-1]
    if not psl.is_known_tld(tld):
        return None
    if from_text and tld in _AMBIGUOUS_TLDS and not had_defang and d.count(".") < 2:
        return None
    return d


def _scrubbed(text: str) -> str:
    """A pasted text as it may be stored (:func:`v3lum.core.ioc.scrub`; spans of a later
    extraction refer to it). Fails closed: an unscrubbable text keeps only a placeholder."""
    try:
        return _ioc.scrub(text)
    except Exception:  # noqa: BLE001
        return "[text withheld: it could not be scrubbed]"


def _try(etype: EntityType, raw: str) -> str | None:
    try:
        return normalize(etype, raw)
    except (ValueError, TypeError):
        return None


def _split_prefix(raw: str) -> tuple[EntityType | None, str]:
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_-]{0,20}):(?!//)(.+)$", raw.strip(), flags=re.S)
    if not m:
        return None, raw
    try:
        return EntityType.parse(m.group(1)), m.group(2).strip()
    except ValueError:
        return None, raw


def detect(raw: str, explicit: EntityType | None = None) -> list[Detection]:
    """Return plausible interpretations of ``raw``, best first."""
    if raw is None:
        return []
    text = str(raw)
    forced, rest = _split_prefix(text) if explicit is None else (explicit, text)
    if forced is not None:
        value = _try(forced, rest)
        if value is None:
            return []
        if forced is EntityType.TEXT:
            value = _scrubbed(value)
        weak = _forced_weakness(forced, rest.strip())
        if weak:
            return [Detection(forced, value, 0.4, f"forced as {forced.value}, but {weak}")]
        return [Detection(forced, value, 1.0, f"forced as {forced.value}")]

    s = text.strip()
    if not s:
        return []
    out: list[Detection] = []

    def add(etype: EntityType, value: str | None, conf: float, reason: str) -> None:
        if value is not None and not any(d.type == etype and d.value == value for d in out):
            out.append(Detection(etype, value, conf, reason))

    # A value that is itself a secret, a card number or an IBAN (P323 cond 5-7): masked, alone.
    sensitive = _sensitive_single(s)
    if sensitive is not None:
        return sensitive

    # An e-mail header block (P333): header-only blocks are email_headers; a pasted .eml (headers +
    # body) stays free text with email_headers as an alternative. Text values are stored scrubbed
    # (ioc.scrub: combos and password hashes dropped, secrets fingerprinted, cards truncated).
    if "\n" in s and _RE_HEADER_START.match(s):
        headers = _try(EntityType.EMAIL_HEADERS, _scrubbed(s))
        if headers:
            body = re.search(r"\r?\n[ \t]*\r?\n\s*\S", s) is not None
            if body:
                add(EntityType.TEXT, _scrubbed(s), 0.95, "e-mail (headers + body): IOC extraction")
                add(EntityType.EMAIL_HEADERS, headers, 0.7, "e-mail header block (parsed statically)")
            else:
                add(EntityType.EMAIL_HEADERS, headers, 0.95, "e-mail header block (parsed statically; nothing is fetched)")
                add(EntityType.TEXT, _scrubbed(s), 0.7, "or free text: IOC extraction")
            return _sorted(out)

    # A PIX BR Code (EMV '000201'...'6304' + CRC16): unambiguous structure, may hold spaces.
    if "\n" not in s and s.startswith("000201") and val.pix_brcode_valid(s):
        add(EntityType.PIX_BRCODE, _try(EntityType.PIX_BRCODE, s), 0.99, "PIX BR Code (valid CRC16)")
        return _sorted(out)

    # Multi-line / long blobs are free text to mine for IOCs.
    if "\n" in s or (len(s) > 300 and " " in s):
        add(EntityType.TEXT, _scrubbed(s), 0.95, "multi-line text: IOC extraction")
        return out

    # Local file path.
    expanded = os.path.expanduser(s)
    if len(s) < 4096 and os.path.isfile(expanded):
        add(EntityType.FILE, os.path.abspath(expanded), 0.99, "existing local file")
        return out

    had_defang = refang(s) != s
    s_ref = refang(s)
    if "@" in s_ref and _RE_URL_USERINFO.match(s_ref):
        s_ref = _sanitize.scrub_text(s_ref)  # 'https://user:pass@host/' -> 'https://host/' (P145 cond 5)

    if _RE_ONION.match(s_ref):
        onion = _try(EntityType.ONION, s_ref)
        if onion:
            add(EntityType.ONION, onion, 0.99, "valid v3 .onion checksum")
            if "/" in re.sub(r"^https?://", "", s_ref):
                add(EntityType.URL, _try(EntityType.URL, s_ref), 0.7, "onion URL")
            return _sorted(out)

    if _RE_FEDIVERSE.match(s_ref):
        add(EntityType.FEDIVERSE_HANDLE, _try(EntityType.FEDIVERSE_HANDLE, s_ref), 0.95, "@user@instance (fediverse handle; no WebFinger lookup)")
        add(EntityType.EMAIL, _try(EntityType.EMAIL, s_ref[1:]), 0.4, "could be an e-mail address")
        return _sorted(out)

    if _RE_TLSH.match(s_ref):
        add(EntityType.TLSH, _try(EntityType.TLSH, s_ref), 0.95, "T1 + 70 hex (TLSH)")
        return _sorted(out)

    if " " not in s_ref:
        typed = _typed_url(s_ref)
        if typed:
            schemed = bool(_RE_URL.match(s_ref))
            if schemed:  # today's precedence: a URL stays a URL; the account is an alternative
                add(EntityType.URL, _try(EntityType.URL, s_ref), 0.98, "has a URL scheme")
            for ent, note in typed:
                add(ent.type, ent.value, 0.7 if schemed else 0.95, note)
            if not schemed:
                add(EntityType.URL, _try(EntityType.URL, s_ref), 0.7, "link without a scheme")
            return _sorted(out)

    if _RE_URL.match(s_ref):
        add(EntityType.URL, _try(EntityType.URL, s_ref), 0.98, "has a URL scheme")
        return _sorted(out)

    if _RE_EMAIL.match(s_ref.removeprefix("mailto:")):
        add(EntityType.EMAIL, _try(EntityType.EMAIL, s_ref), 0.98, "email syntax")
        return _sorted(out)

    # IP addresses / networks.
    candidate_ip = s_ref.strip("[]")
    try:
        ip = ipaddress.ip_address(candidate_ip)
        add(EntityType.IPV4 if ip.version == 4 else EntityType.IPV6, str(ip) if ip.version == 4 else ip.compressed, 0.99, "IP address")
        return _sorted(out)
    except ValueError:
        pass
    if "/" in s_ref and re.match(r"^[0-9a-fA-F:.]+/\d{1,3}$", s_ref):
        add(EntityType.CIDR, _try(EntityType.CIDR, s_ref), 0.98, "CIDR network")
        return _sorted(out)

    compact = s_ref.replace(" ", "")
    if _RE_ASN.match(s_ref):
        add(EntityType.ASN, _try(EntityType.ASN, s_ref), 0.97, "AS number")
    if _RE_CVE.match(s_ref):
        add(EntityType.CVE, _try(EntityType.CVE, s_ref), 0.99, "CVE identifier")
    if _RE_MITRE.match(s_ref):
        add(EntityType.MITRE, _try(EntityType.MITRE, s_ref), 0.95, "MITRE ATT&CK id")
    if _RE_MITRE_GROUP.match(s_ref):
        add(EntityType.THREAT_ACTOR, s_ref.upper(), 0.9, "MITRE ATT&CK group id")
    if _RE_MITRE_SOFTWARE.match(s_ref):
        add(EntityType.MALWARE, s_ref.upper(), 0.85, "MITRE ATT&CK software id")

    # Hashes (hex of a known length).
    if _RE_HEX.match(compact):
        n = len(compact)
        if n == 32:
            add(EntityType.MD5, compact.lower(), 0.95, "32 hex chars (MD5; could also be NTLM)")
        elif n == 40:
            add(EntityType.SHA1, compact.lower(), 0.95, "40 hex chars (SHA-1)")
            add(EntityType.CERT_FP, compact.lower(), 0.3, "could be a SHA-1 certificate fingerprint")
        elif n == 64:
            add(EntityType.SHA256, compact.lower(), 0.95, "64 hex chars (SHA-256)")
            add(EntityType.CERT_FP, compact.lower(), 0.35, "could be a SHA-256 certificate fingerprint")
        elif n == 128:
            add(EntityType.SHA512, compact.lower(), 0.95, "128 hex chars (SHA-512)")
    if ":" in compact and re.match(r"^(?:[0-9A-Fa-f]{2}:){19}[0-9A-Fa-f]{2}$|^(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$", compact):
        add(EntityType.CERT_FP, _try(EntityType.CERT_FP, compact), 0.9, "colon-separated certificate fingerprint")
    if _RE_SSDEEP.match(s_ref):
        add(EntityType.SSDEEP, s_ref, 0.9, "ssdeep fuzzy hash")

    # Crypto addresses.
    if val.btc_address_valid(s_ref):
        info = val.btc_address_info(s_ref) or {}
        add(EntityType.BTC, _try(EntityType.BTC, s_ref), 0.99, f"valid Bitcoin {info.get('type', '')} checksum".strip())
    if _RE_ETH.match(s_ref) and val.eth_checksum_state(s_ref) != "invalid":  # an EIP-55 mismatch is not typed
        add(EntityType.ETH, s_ref.lower(), 0.97, "0x + 40 hex (Ethereum/EVM)")
    if _RE_XMR.match(s_ref) and val.xmr_address_valid(s_ref):
        add(EntityType.XMR, s_ref, 0.95, "Monero address (checksum valid)")
    if (_RE_LTC.match(s_ref) or _RE_TRX.match(s_ref) or _RE_DOGE.match(s_ref) or s_ref[:1] in ("X", "r")) and not out:
        info = val.crypto_address_info(s_ref)
        if info is not None and info.checksum_ok and info.chain in ("ltc", "tron", "doge", "dash", "xrp"):
            label = {"ltc": "Litecoin", "tron": "TRON", "doge": "Dogecoin", "dash": "Dash", "xrp": "XRP"}[info.chain]
            add(EntityType.CRYPTO, s_ref, 0.95, f"{label} address (checksum valid)")

    if _RE_MAC.match(s_ref):
        add(EntityType.MAC, _try(EntityType.MAC, s_ref), 0.95, "MAC address")
    if _RE_JWT.match(s_ref):
        add(EntityType.JWT, s_ref, 0.98, "JSON Web Token")
    if _RE_ANALYTICS.match(s_ref):
        add(EntityType.ANALYTICS_ID, _try(EntityType.ANALYTICS_ID, s_ref), 0.95, "analytics/ads tracking id")
    if _RE_COORDS.match(s_ref):
        add(EntityType.COORDINATES, _try(EntityType.COORDINATES, s_ref), 0.9, "latitude,longitude")
    if _RE_UA.match(s_ref):
        add(EntityType.USER_AGENT, _try(EntityType.USER_AGENT, s_ref), 0.95, "User-Agent string")
    if _RE_UUID.match(s_ref):
        add(EntityType.PIX, s_ref.lower(), 0.6, "UUID (random PIX key / EVP?)")

    # Brazilian identifiers and numbers.
    digits = re.sub(r"\D", "", s_ref)
    if (_RE_CNPJ_FMT.match(s_ref) or re.match(r"^[0-9A-Za-z]{14}$", compact)) and val.cnpj_valid(s_ref):
        add(EntityType.CNPJ, _try(EntityType.CNPJ, s_ref), 0.97, "valid CNPJ check digits")
    if (_RE_CPF_FMT.match(s_ref) or re.match(r"^\d{11}$", compact)) and val.cpf_valid(s_ref):
        add(EntityType.CPF, _try(EntityType.CPF, s_ref), 0.9 if _RE_CPF_FMT.match(s_ref) else 0.8, "valid CPF check digits")
    if _RE_CEP.match(s_ref) and len(digits) == 8:
        add(EntityType.CEP, digits, 0.95 if "-" in s_ref else 0.6, "Brazilian postal code (CEP)")
    if re.match(r"^[\d\s.]+$", s_ref) and len(digits) in (44, 47, 48):
        add(EntityType.BOLETO, digits, 0.85, f"{len(digits)} digits: boleto / barcode line")
    if re.match(r"^\d{15}$", compact) and val.luhn_valid(compact):
        add(EntityType.IMEI, compact, 0.6, "15 digits with valid Luhn (IMEI?)")
    if _RE_PLATE.match(s_ref):
        add(EntityType.PLATE_BR, _try(EntityType.PLATE_BR, s_ref), 0.75, "Brazilian vehicle plate format")

    # Phone numbers (never when the text is clearly a formatted CPF/CNPJ/CEP/boleto).
    blocked = (EntityType.CNPJ, EntityType.BOLETO)
    formatted_doc = bool(_RE_CPF_FMT.match(s_ref) or (_RE_CEP.match(s_ref) and "-" in s_ref) or len(digits) == 8)
    if (
        _RE_PHONE_FMT.match(s_ref)
        and 8 <= len(digits) <= 15
        and not formatted_doc
        and not any(d.type in blocked for d in out)
    ):
        phone = _try(EntityType.PHONE, s_ref)
        if phone:
            if s_ref.startswith("+"):
                conf = 0.95
            elif re.match(r"^\(?\d{2}\)?\s?9?\d{4}-?\d{4}$", s_ref) and any(c in s_ref for c in "()-"):
                conf = 0.85  # (11) 98765-4321 style
            elif any(c in s_ref for c in "()- "):
                conf = 0.6
            else:
                conf = 0.5
            add(EntityType.PHONE, phone, conf, "phone number pattern")

    # Domains.
    if "." in s_ref and " " not in s_ref and not out:
        dom = _domain_ok(s_ref, had_defang=had_defang)
        if dom:
            add(EntityType.DOMAIN, dom, 0.97, "hostname with a valid TLD")

    # Named threat actors / malware families (alias index, AR18): typed instead of username.
    if not out and len(s) <= 64 and not s.startswith("@"):
        for etype, canonical in _named(s):
            known = "malware family" if etype is EntityType.MALWARE else "threat actor"
            alias = "" if canonical.lower() == s.lower() else f" (alias of {canonical})"
            add(etype, canonical, 0.8, f"known {known} name{alias}")
        if out:
            add(EntityType.KEYWORD, _try(EntityType.KEYWORD, s), 0.3, "or a plain keyword")
            return _sorted(out)

    # Words: username, person, company, keyword.
    if not any(d.confidence >= 0.9 for d in out):
        words = s.split()
        if s.startswith("@") and _RE_USERNAME.match(s):
            add(EntityType.USERNAME, _try(EntityType.USERNAME, s), 0.95, "@handle")
        elif len(words) == 1 and _RE_USERNAME.match(s) and re.search(r"[A-Za-z]", s) and not out:
            add(EntityType.USERNAME, _try(EntityType.USERNAME, s), 0.6, "single token: username?")
            add(EntityType.KEYWORD, _try(EntityType.KEYWORD, s), 0.3, "single token: keyword?")
        elif len(words) >= 2:
            if _ORG_HINTS.search(s):
                add(EntityType.ORG, _try(EntityType.ORG, s), 0.8, "corporate suffix")
            elif len(words) <= 6 and all(_RE_PERSON_WORD.match(w) for w in words):
                significant = [w for w in words if w.lower() not in _NAME_PARTICLES]
                capitalized = bool(significant) and all(w[:1].isupper() for w in significant)
                if capitalized:
                    add(EntityType.PERSON, _try(EntityType.PERSON, s), 0.65, "capitalized 2-6 words: person name?")
                    add(EntityType.ORG, _try(EntityType.ORG, s), 0.3, "could be an organization")
                else:
                    add(EntityType.KEYWORD, _try(EntityType.KEYWORD, s), 0.45, "lower-case phrase: keyword?")
                    add(EntityType.PERSON, _try(EntityType.PERSON, s), 0.4, "could be a person name")
            add(EntityType.KEYWORD, _try(EntityType.KEYWORD, s), 0.25, "free keyword")
    if not out:
        add(EntityType.KEYWORD, _try(EntityType.KEYWORD, s), 0.2, "unrecognized: treated as keyword")
    return _sorted(out)


def _sorted(items: list[Detection]) -> list[Detection]:
    return sorted(items, key=lambda d: -d.confidence)


def best(raw: str) -> Detection | None:
    found = detect(raw)
    return found[0] if found else None


def primary(detections: list[Detection], threshold: float = 0.75) -> list[Detection]:
    """Interpretations to investigate automatically: all >= threshold, else the single best."""
    if not detections:
        return []
    strong = [d for d in detections if d.confidence >= threshold]
    return strong or detections[:1]


def _forced_weakness(forced: EntityType, raw: str) -> str:
    """Why an explicitly typed value is structurally doubtful ('' when it is fine): failing
    checksums and non-JWT structures get low confidence instead of 1.0 (P217 cond 5)."""
    if forced is EntityType.JWT and not _RE_JWT.match(raw):
        return "it has no JWT structure (eyJ...eyJ...)"
    if forced is EntityType.ETH and val.eth_checksum_state(raw) == "invalid":
        return "its EIP-55 checksum does not match"
    if forced is EntityType.XMR and not val.xmr_address_valid(raw):
        return "its Monero checksum does not match"
    if forced is EntityType.CRYPTO:
        info = val.crypto_address_info(raw)
        if info is None or info.checksum_ok is False:
            return "no known chain checksum validates it"
    return ""


# --------------------------------------------------------------------------------------
# IOC extraction from free text: the P172 engine
# --------------------------------------------------------------------------------------


def extract_iocs(text: str, limit: int = 5000) -> list[Entity]:
    """Every indicator found in ``text`` (defanged forms understood), de-duplicated, in reading order.

    Thin wrapper over :func:`v3lum.core.ioc.extract`: ``[e.entity for e in extract(text).entities]``,
    leaving out names whose TLD is also a file extension and that were not defanged or written with
    a scheme (``invoice.zip``: low confidence, a file name). CPFs never appear (masked and counted
    by the engine), card numbers appear as ``payment_card`` ``BIN6…last4`` and secrets as
    fingerprints (``secret`` / ``telegram_bot_token``).
    """
    result = _ioc.extract(text, limit=limit)
    return [e.entity for e in result.entities if "low_confidence_tld" not in e.flags]
