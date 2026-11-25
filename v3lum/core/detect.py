"""Automatic recognition of what the analyst typed, plus IOC extraction from free text.

``detect("john@acme.com")`` -> [Detection(EMAIL, 'john@acme.com', 0.98, ...)]
``detect("11987654321")``   -> CPF (if check digits match) and PHONE alternatives
``extract_iocs(text)``      -> every IOC found in a blob (defanged indicators included)

Forcing a type: ``email:foo@bar.com``, ``user:johndoe``, ``name:Jane Doe``...
"""

from __future__ import annotations

import functools
import ipaddress
import json
import os
import re
from dataclasses import dataclass
from importlib import resources

from v3lum.core import psl
from v3lum.core import validators as val
from v3lum.core.entities import Entity, EntityType, normalize, refang


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


@functools.lru_cache(maxsize=1)
def _named_index() -> dict[str, tuple[EntityType, str]]:
    """Known threat-actor / malware names (lower-case alias -> (type, canonical name)).

    Loaded from bundled ``data/threat_actors.json`` / ``data/malware_families.json`` when present.
    """
    index: dict[str, tuple[EntityType, str]] = {}
    for fname, etype in (("malware_families.json", EntityType.MALWARE), ("threat_actors.json", EntityType.THREAT_ACTOR)):
        try:
            raw = resources.files("v3lum.data").joinpath(fname).read_text(encoding="utf-8")
        except (FileNotFoundError, OSError):
            continue
        try:
            data = json.loads(raw)
        except ValueError:
            continue
        items = data.get("items", data) if isinstance(data, dict) else data
        for item in items if isinstance(items, list) else []:
            name = (item.get("name") or "").strip()
            if not name:
                continue
            for alias in [name, *(item.get("aliases") or [])]:
                a = str(alias).strip().lower()
                if len(a) >= 3:
                    index[a] = (etype, name)
    return index


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
        return [Detection(forced, value, 1.0, f"forced as {forced.value}")]

    s = text.strip()
    if not s:
        return []
    out: list[Detection] = []

    def add(etype: EntityType, value: str | None, conf: float, reason: str) -> None:
        if value is not None and not any(d.type == etype and d.value == value for d in out):
            out.append(Detection(etype, value, conf, reason))

    # Multi-line / long blobs are free text to mine for IOCs.
    if "\n" in s or (len(s) > 300 and " " in s):
        add(EntityType.TEXT, s, 0.95, "multi-line text: IOC extraction")
        return out

    # Local file path.
    expanded = os.path.expanduser(s)
    if len(s) < 4096 and os.path.isfile(expanded):
        add(EntityType.FILE, os.path.abspath(expanded), 0.99, "existing local file")
        return out

    had_defang = refang(s) != s
    s_ref = refang(s)

    if _RE_ONION.match(s_ref):
        onion = _try(EntityType.ONION, s_ref)
        if onion:
            add(EntityType.ONION, onion, 0.99, "valid v3 .onion checksum")
            if "/" in re.sub(r"^https?://", "", s_ref):
                add(EntityType.URL, _try(EntityType.URL, s_ref), 0.7, "onion URL")
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
    if _RE_ETH.match(s_ref):
        add(EntityType.ETH, s_ref.lower(), 0.97, "0x + 40 hex (Ethereum/EVM)")
    if _RE_XMR.match(s_ref):
        add(EntityType.XMR, s_ref, 0.9, "Monero address format")
    if _RE_LTC.match(s_ref) and not out:
        add(EntityType.CRYPTO, s_ref, 0.7, "Litecoin address format")
    if _RE_TRX.match(s_ref) and not out:
        add(EntityType.CRYPTO, s_ref, 0.7, "TRON address format")
    if _RE_DOGE.match(s_ref) and not out:
        add(EntityType.CRYPTO, s_ref, 0.6, "Dogecoin address format")

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

    # Named threat actors / malware families (bundled indexes).
    if not out and len(s) <= 64:
        hit = _named_index().get(s.lower())
        if hit:
            add(hit[0], hit[1], 0.9, f"known {hit[0].label.lower()} name/alias")

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


# --------------------------------------------------------------------------------------
# IOC extraction from free text
# --------------------------------------------------------------------------------------

_X_URL = re.compile(r"\b(?:https?|hxxps?|ftp|fxp)(?:\[?:\]?)//[^\s<>\"'`)\]]+", re.I)
_X_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+(?:@|\[@\]|\(@\)|\[at\]|\(at\))[A-Za-z0-9.-]+(?:\.|\[\.\]|\(\.\)|\[dot\])[A-Za-z]{2,}\b", re.I)
_X_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.|\[\.\]|\(\.\))){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_X_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}(?![0-9A-Fa-f:])|(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4})?")
_X_DOMAIN = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.|\[\.\]|\(\.\)|\[dot\]))+[A-Za-z]{2,24}\b")
_X_HASH = re.compile(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{128}\b")
_X_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_X_MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_X_BTC = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_X_ETH = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
_X_XMR = re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
_X_ONION = re.compile(r"\b[a-z2-7]{56}\.onion\b", re.I)
_X_ASN = re.compile(r"\bAS\d{2,10}\b")
_X_CPF = re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b")
_X_CNPJ = re.compile(r"\b[0-9A-Z]{2}\.[0-9A-Z]{3}\.[0-9A-Z]{3}/[0-9A-Z]{4}-\d{2}\b")
_X_PHONE = re.compile(r"(?<![\w+])\+\d[\d\s().-]{7,18}\d")
_X_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_X_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_X_ANALYTICS = re.compile(r"\b(?:UA-\d{4,10}-\d{1,4}|GTM-[A-Z0-9]{4,10}|ca-pub-\d{10,20})\b")


def extract_iocs(text: str, limit: int = 5000) -> list[Entity]:
    """Every indicator found in ``text`` (defanged forms understood), de-duplicated, in order."""
    found: list[Entity] = []
    seen: set[str] = set()
    email_spans: list[tuple[int, int]] = []
    url_hosts: set[str] = set()

    # Domains written defanged in the original text are trusted even with file-like TLDs.
    defanged_domains: set[str] = set()
    for m in _X_DOMAIN.finditer(text):
        raw = m.group(0)
        if refang(raw) != raw:
            defanged_domains.add(refang(raw).lower())
    text = refang(text)

    def push(etype: EntityType, raw: str) -> None:
        if len(found) >= limit:
            return
        ent = Entity.try_make(etype, raw)
        if ent and ent.key not in seen:
            seen.add(ent.key)
            found.append(ent)

    for m in _X_URL.finditer(text):
        url = refang(m.group(0)).rstrip(".,;:!?")
        push(EntityType.URL, url)
        ent = Entity.try_make(EntityType.URL, url)
        if ent:
            from v3lum.core.entities import url_host

            url_hosts.add(url_host(ent.value))
    for m in _X_EMAIL.finditer(text):
        email_spans.append(m.span())
        push(EntityType.EMAIL, refang(m.group(0)))
    for m in _X_IPV4.finditer(text):
        push(EntityType.IPV4, refang(m.group(0)))
    for m in _X_IPV6.finditer(text):
        cand = m.group(0)
        if cand.count(":") >= 2:
            try:
                ipaddress.IPv6Address(cand)
                push(EntityType.IPV6, cand)
            except ValueError:
                pass
    for m in _X_ONION.finditer(text):
        push(EntityType.ONION, m.group(0))
    for m in _X_DOMAIN.finditer(text):
        start, end = m.span()
        if any(s <= start and end <= e for s, e in email_spans):
            continue
        raw = m.group(0)
        dom = _domain_ok(raw, from_text=True, had_defang=raw.lower() in defanged_domains)
        if dom and not dom.endswith(".onion"):
            push(EntityType.DOMAIN, dom)
    for host in url_hosts:
        dom = _domain_ok(host)
        if dom:
            push(EntityType.DOMAIN, dom)
    for m in _X_HASH.finditer(text):
        h = m.group(0)
        if len(set(h.lower())) < 4:
            continue
        etype = {32: EntityType.MD5, 40: EntityType.SHA1, 64: EntityType.SHA256, 128: EntityType.SHA512}[len(h)]
        push(etype, h)
    for m in _X_CVE.finditer(text):
        push(EntityType.CVE, m.group(0))
    for m in _X_MITRE.finditer(text):
        push(EntityType.MITRE, m.group(0))
    for m in _X_BTC.finditer(text):
        if val.btc_address_valid(m.group(0)):
            push(EntityType.BTC, m.group(0))
    for m in _X_ETH.finditer(text):
        push(EntityType.ETH, m.group(0))
    for m in _X_XMR.finditer(text):
        push(EntityType.XMR, m.group(0))
    for m in _X_ASN.finditer(text):
        push(EntityType.ASN, m.group(0))
    for m in _X_CPF.finditer(text):
        push(EntityType.CPF, m.group(0))
    for m in _X_CNPJ.finditer(text):
        push(EntityType.CNPJ, m.group(0))
    for m in _X_PHONE.finditer(text):
        push(EntityType.PHONE, m.group(0))
    for m in _X_MAC.finditer(text):
        push(EntityType.MAC, m.group(0))
    for m in _X_JWT.finditer(text):
        push(EntityType.JWT, m.group(0))
    for m in _X_ANALYTICS.finditer(text):
        push(EntityType.ANALYTICS_ID, m.group(0))
    return found
