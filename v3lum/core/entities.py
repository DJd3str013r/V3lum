"""Entity types and canonical normalization.

An :class:`Entity` is an observable (email, domain, IP, hash...) identified by its
type and its *normalized* value, so the same thing found by two modules collapses
into one node of the investigation graph.
"""

from __future__ import annotations

import enum
import ipaddress
import os
import re
from dataclasses import dataclass


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
}


@dataclass(frozen=True, order=True)
class Entity:
    """An observable identified by (type, normalized value)."""

    type: EntityType
    value: str

    @property
    def key(self) -> str:
        return f"{self.type.value}:{self.value}"

    @property
    def display(self) -> str:
        return display_value(self.type, self.value)

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
# Defang / refang
# --------------------------------------------------------------------------------------

_REFANG_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}"), "."),
    (re.compile(r"\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}", re.I), "."),
    (re.compile(r"\s+dot\s+", re.I), "."),
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


def defang(value: str) -> str:
    """Make an IOC safe to paste in tickets/chats: ``http://evil.com`` -> ``hxxp://evil[.]com``."""
    out = re.sub(r"^http", "hxxp", value, flags=re.I)
    out = out.replace("://", "[://]") if out.lower().startswith("ftp") else out
    # Defang only the dots of the host part (keep paths readable).
    m = re.match(r"^([a-z]+\[?://\]?)?([^/]+)(.*)$", out, flags=re.I)
    if not m:
        return out.replace(".", "[.]")
    scheme, host, rest = m.group(1) or "", m.group(2), m.group(3)
    host = host.replace(".", "[.]").replace("@", "[@]")
    return scheme + host + rest


# --------------------------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------------------------

_WS = re.compile(r"\s+")
_HEX = re.compile(r"^[0-9a-f]+$")
_HASH_LEN = {EntityType.MD5: 32, EntityType.SHA1: 40, EntityType.SHA256: 64, EntityType.SHA512: 128}
_DOMAIN_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


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


def normalize(etype: EntityType, raw: str) -> str:
    """Return the canonical string for ``raw`` as ``etype``. Raises ValueError if invalid."""
    from v3lum.core import validators as val  # local import to avoid cycles

    if raw is None:
        raise ValueError("empty value")
    raw = str(raw)
    if etype is EntityType.TEXT:
        if not raw.strip():
            raise ValueError("empty text")
        return raw
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
        m = re.match(r"^\s*(-?\d{1,2}(?:\.\d+)?)\s*[,; ]\s*(-?\d{1,3}(?:\.\d+)?)\s*$", v)
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
    raise ValueError(f"no normalizer for {etype}")


def display_value(etype: EntityType, value: str) -> str:
    """Human-friendly rendering (e.g. CNPJ punctuation). Never used as identity."""
    if etype is EntityType.CNPJ and len(value) == 14:
        return f"{value[:2]}.{value[2:5]}.{value[5:8]}/{value[8:12]}-{value[12:]}"
    if etype is EntityType.CPF and len(value) == 11:
        return f"{value[:3]}.{value[3:6]}.{value[6:9]}-{value[9:]}"
    if etype is EntityType.CEP and len(value) == 8:
        return f"{value[:5]}-{value[5:]}"
    if etype is EntityType.TEXT:
        short = _collapse(value)
        return short if len(short) <= 60 else short[:57] + "..."
    if etype is EntityType.FILE:
        return os.path.basename(value) or value
    return value
