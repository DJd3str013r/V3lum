"""Crypto address attribution labels (P358, batch p2-G09-3): GraphSense public TagPacks, analyst-imported
exchange proof-of-reserves (PoR) files and the team-curated label file, merged side by side.

Final conditions (binding) and where they live:

* FC1 - offline module (disclosure ``none``: the address never leaves the machine, TLP:RED-safe). The
  GraphSense public TagPacks (MIT; tags from public sources, no PII by repository rule) are the
  registered dataset :data:`GS_DATASET`, fetched **weekly** by the dataset manager (``v3lum data
  update``, never during a scan: ``large=True``) as **one repository archive**
  (github.com archive -> codeload.github.com, both owned by the ``github`` provider). The archive is
  read **in memory, without extraction**, through the shared safe ZIP reader
  (``file_type_sniff.zip_scan``/``zip_read``: central-directory checks, bounded inflate, ratio and
  size caps, CRC check) with this module's caps (:data:`ARCHIVE_LIMITS`); member names are never used
  as file paths (:func:`tagpack_archive_members`). YAML is parsed with ``yaml.safe_load`` **only**
  (PyYAML, optional extra ``yaml``; :func:`check_yaml_loader` refuses any other loader, and a
  pre-parse guard refuses HTML/JSON error bodies, NUL bytes, ``!!python`` tags and anchors/aliases).
  Without PyYAML the GraphSense index cannot be built: the source reports UNAVAILABLE ``package``
  (PoR imports and the team file still answer).
* FC2 - every tag is indexed into SQLite (:func:`build_index`, at refresh time, by the dataset
  validator) with its source URL, category/abuse, confidence (GraphSense taxonomy id and level) and
  pack/tag date (``lastmod``, else the archive commit date, with ``date_source``), plus the commit and
  pack URL as provenance. Exchange PoR files are **imported manually by the analyst** with exchange,
  PoR date and source URL (:func:`import_por_file`, or the drop folder with a provenance sidecar,
  :data:`POR_SIDECAR_SCHEMA`); the PoR pages are JS/bot-protected and are never fetched (no host is
  declared; HTML/interstitial bodies offered as a PoR file are refused, :func:`por_input_problem`).
  OKX rows carrying the signed 'I am an OKX address' message are CONFIRMED ('high'); unsigned PoR rows
  PROBABLE. Every PoR-derived label (imported files and the GraphSense ``exchange-wallets-*`` /
  ``service-wallets-*`` snapshot packs) loses one confidence step once it is 12 months old
  (:func:`effective_confidence`).
* FC3 - the team-curated label file (bundled ``v3lum/data/crypto_address_labels/crypto_labels.json``:
  Brazilian exchanges; plus the local file of setting ``crypto_address_labels_team_file`` for addresses
  confirmed in past cases) is validated with mandatory provenance (source, reference, date);
  personal-data keys are dropped and reported (:func:`parse_team_labels`). Merged labels keep their
  per-source provenance and conflicting identities are shown **side by side** (attribute
  ``label_conflict``, tag ``conflict``): no label silently overrides another (:func:`summarize_address`).
* FC4 - exchange (and custodial/mixer/bridge/pool/service/DeFi, and OFAC-listed) labels are stop-nodes
  for graph expansion (attribute ``stop_node_hint``, P213; company pivots use ``expand=False``) and
  exchange/custodial labels name the institution a legal request can be sent to (attribute
  ``court_order_target``, only when exactly one institution is named; wording 'label = lead for a
  legal request to X, not proof of who holds the funds'). Risk categories raise the severity: OFAC
  CRITICAL (exact wallet match, AR08), ransomware HIGH, scam/phishing MEDIUM (also terrorism HIGH, hack
  and issuer blacklist MEDIUM, extremism LOW). 'No label' is EMPTY with a coverage-aware note that never
  says 'unhosted' or 'self-custodied' (TRON exchange coverage is thin: computed from the index, not
  hard-coded; :func:`no_label_note`).

The prep-batch parsers (stdlib, live-verified against commit 507756d2 of graphsense-tagpacks) are ported
here. The confidence taxonomy :data:`CONFIDENCE_LEVELS` comes from graphsense-lib (MIT, notice
``graphsense_lib_confidence``).
"""

from __future__ import annotations

import collections
import csv
import datetime as dt
import hashlib
import io
import json
import os
import re
import sqlite3
import tempfile
import threading
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from v3lum import paths
from v3lum.config import SettingSpec
from v3lum.core.datasets import DataStore, DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, HealthResult, Module, register
from v3lum.modules.file_analysis.file_type_sniff import ArchiveLimit, Budget, zip_read, zip_scan

MODULE = "crypto_address_labels"
GS_SOURCE = "github.crypto_address_labels_graphsense_tagpacks"
GS_DATASET = "crypto_address_labels.graphsense_tagpacks"
GRAPHSENSE_REPO_URL = "https://github.com/graphsense/graphsense-tagpacks"
GRAPHSENSE_ARCHIVE_URL = GRAPHSENSE_REPO_URL + "/archive/refs/heads/master.zip"
GRAPHSENSE_ATTRIBUTION = "GraphSense public TagPacks (MIT, Iknaio Cryptoasset Analytics GmbH)"
GRAPHSENSE_LICENCE = "MIT (Copyright (c) 2022 Iknaio Cryptoasset Analytics GmbH, (c) 2018-2022 AIT Austrian Institute of Technology)"
WEEK = 7 * 86400
#: the dataset copy is flagged after this many days (weekly refresh, one missed week tolerated)
STALE_DAYS = 14
#: never refresh during a run: the archive is installed only by `v3lum data update`
NO_REFRESH_TTL = 10.0**12
ARCHIVE_MAX_BYTES = 64 * 1024 * 1024
#: measured on commit 507756d2 (2026-11-18): 104 members, 32.3 MB uncompressed, largest 4.1 MB, ratio <= 6x
ARCHIVE_LIMITS = {
    "max_members": 2000,
    "max_total_uncompressed": 200 * 1024 * 1024,
    "max_member_uncompressed": 16 * 1024 * 1024,
    "max_ratio": 100,
}
INDEX_VERSION = "1"
INDEX_PREFIX = f"{MODULE}-v{INDEX_VERSION}-"
INDEX_SUFFIX = ".sqlite"
TEAM_BUNDLED = "crypto_address_labels/crypto_labels.json"
TEAM_FILE_SETTING = "crypto_address_labels_team_file"
POR_DIR_SETTING = "crypto_address_labels_por_dir"
TEAM_FILE_DEFAULT = "crypto_labels.json"  # under the V3LUM home
POR_DIR_DEFAULT = "crypto_labels/por"  # under the V3LUM home
POR_SIDECAR_SUFFIX = ".provenance.json"
POR_SIDECAR_SCHEMA = "v3lum.crypto_por_import/1"
POR_MAX_FILE_BYTES = 64 * 1024 * 1024
POR_MAX_FILES = 200
TEAM_MAX_BYTES = 16 * 1024 * 1024
#: labels shown in the attribute (all of them stay in the evidence up to RAW_MAX_LABELS)
MAX_LABELS_SHOWN = 40
RAW_MAX_LABELS = 200
#: manual-only PoR pages (bot/JS walls: links for the analyst, never fetched) per GraphSense actor id
POR_PAGES = {
    "okex": ("OKX proof-of-reserves files (manual download, then import with provenance)", "https://www.okx.com/en-br/proof-of-reserves"),
    "binance": ("Binance proof-of-reserves (manual download, then import with provenance)", "https://www.binance.com/en/proof-of-reserves"),
}

# ------------------------------------------------------------------------------------- taxonomy

#: graphsense-lib develop @ aca7c6f3 (2026-11-25) src/graphsenselib/tagpack/db/confidence.csv (MIT)
CONFIDENCE_LEVELS = {
    "override": 100, "ownership": 100, "ledger_immanent": 100, "manual_transaction": 90,
    "service_api": 70, "forensic_investigation": 70, "authority_data": 60, "trusted_provider": 50,
    "service_data": 50, "forensic": 50, "untrusted_transaction": 40, "web_crawl": 20,
    "heuristic": 10, "unknown": 5,
}
CONFIDENCE_RANK = {"POSSIBLE": 0, "PROBABLE": 1, "CONFIRMED": 2}
POR_MAX_AGE_MONTHS = 12

#: tag category/abuse/concept values (DW-VA taxonomy used by the public packs) -> entity class
ENTITY_CLASS_BY_CATEGORY = {
    "exchange": "exchange",
    "mixing_service": "mixer", "coinjoin": "mixer", "mixer": "mixer",
    "defi_bridge": "bridge", "bridge": "bridge",
    "miner": "pool", "mining_service": "pool", "mining_pool": "pool", "pool": "pool",
    "wallet_service": "custodial_service", "payment_processor": "custodial_service", "custodian": "custodial_service",
    "market": "service", "gambling": "service", "service": "service", "faucet": "service",
    "defi": "defi", "defi_dex": "defi", "defi_lending": "defi", "defi_derivative": "defi", "index": "defi",
    "organization": "organization",
}
RISK_CLASS_BY_VALUE = {
    "sanction": "ofac", "sanctions": "ofac", "ofac": "ofac",
    "ransomware": "ransomware",
    "scam": "scam", "phishing": "scam", "ponzi_scheme": "scam", "pyramid_scheme": "scam",
    "investment_fraud": "scam", "sextortion": "scam", "social_engineering": "scam",
    "service_hack": "hack", "hacking": "hack",
    "terrorism": "terrorism", "extremism": "extremism",
    "black_list": "issuer_blacklist",
}
#: FC4 / P213: these classes end graph expansion. exchange, mixer, bridge and pool are P213's literal
#: list; service/custodial_service/defi follow P208 ('service' labels are stop-nodes) and P213's hub rule.
STOP_NODE_CLASSES = ("exchange", "custodial_service", "mixer", "bridge", "pool", "service", "defi")
COURT_ORDER_CLASSES = frozenset({"exchange", "custodial_service"})
#: FC4 requires ofac/ransomware/scam to raise severity; the other rows follow the same scale.
SEVERITY_BY_RISK = {
    "ofac": "critical", "ransomware": "high", "terrorism": "high", "scam": "medium",
    "hack": "medium", "issuer_blacklist": "medium", "extremism": "low",
}
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
RISK_FINDINGS: dict[str, tuple[str, list[str], str]] = {
    "ofac": ("Address labelled as OFAC-sanctioned by a label source", ["sanctions"], "sanctions-list label"),
    "ransomware": ("Address labelled as ransomware-related", ["ransomware"], "ransomware label"),
    "terrorism": ("Address labelled as terrorism financing", ["malicious"], "terrorism-financing label"),
    "scam": ("Address labelled as scam or phishing", ["crypto_scam", "fraud"], "scam/phishing label"),
    "hack": ("Address labelled as hack proceeds or hacker wallet", ["malicious"], "hack label"),
    "issuer_blacklist": ("Address blacklisted by a stablecoin issuer (label)", ["issuer_freeze"], "issuer blacklist label"),
    "extremism": ("Address labelled as extremism funding", [], "extremism-funding label"),
}
CLASS_WORDS = {
    "exchange": "exchange", "custodial_service": "custodial service", "mixer": "mixer", "bridge": "bridge",
    "pool": "mining pool", "service": "service", "defi": "DeFi contract", "organization": "organization",
}
FAMILY_NAMES = {
    "btc": "Bitcoin", "evm": "Ethereum/EVM", "tron": "TRON", "ltc": "Litecoin", "bch": "Bitcoin Cash",
    "bsv": "Bitcoin SV", "doge": "Dogecoin", "xrp": "XRP", "ton": "TON", "sol": "Solana", "ada": "Cardano",
    "bnb_beacon": "BNB Beacon Chain (BEP2)", "xmr": "Monero", "avax": "Avalanche X/P-chain",
}
CHAIN_NAMES = {"btc": "bitcoin", "evm": "evm", "tron": "tron", "ltc": "litecoin", "bch": "bitcoin_cash", "bsv": "bitcoin_sv",
               "doge": "dogecoin", "xrp": "xrp", "ton": "ton", "sol": "solana", "ada": "cardano", "bnb_beacon": "bnb_beacon"}
THIN_COVERAGE_THRESHOLD = 1000

# ------------------------------------------------------------------------------------- address shapes

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

RE_EVM = re.compile(r"^0x[0-9a-fA-F]{40}$")
RE_EVM_VALIDATOR_KEY = re.compile(r"^0x[0-9a-fA-F]{96}$")
RE_HEX64 = re.compile(r"^0x[0-9a-fA-F]{64}$")
RE_TRON = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
RE_TRON_HEX = re.compile(r"^41[0-9a-fA-F]{40}$")
RE_BTC_B58 = re.compile(r"^[13][1-9A-HJ-NP-Za-km-z]{25,34}$")
RE_BTC_BECH32 = re.compile(r"^bc1[02-9ac-hj-np-z]{11,71}$")
RE_LTC = re.compile(r"^(?:[LM3][1-9A-HJ-NP-Za-km-z]{26,33}|ltc1[02-9ac-hj-np-z]{11,71})$")
RE_DOGE = re.compile(r"^[DA9][1-9A-HJ-NP-Za-km-z]{25,34}$")
RE_BCH = re.compile(r"^(?:(?:bitcoincash:)?[qp][02-9ac-hj-np-z]{41}|[13][1-9A-HJ-NP-Za-km-z]{25,34})$")
RE_XRP = re.compile(r"^r[1-9A-HJ-NP-Za-km-z]{24,34}$")
RE_TON = re.compile(r"^(?:[EUk0][Qf][A-Za-z0-9_-]{46}|-?\d:[0-9a-fA-F]{64})$")
RE_ADA = re.compile(r"^(?:addr1[02-9ac-hj-np-z]{50,120}|DdzFF[1-9A-HJ-NP-Za-km-z]{50,120}|Ae2[1-9A-HJ-NP-Za-km-z]{50,70})$")
RE_BNB_BEACON = re.compile(r"^bnb1[02-9ac-hj-np-z]{38}$")
RE_GENERIC = re.compile(r"^(?=(?:[^A-Za-z0-9]*[A-Za-z0-9]){3})[A-Za-z0-9:_.\-]{3,130}$")
RE_AVAX_XP = re.compile(r"^[XPC]-avax1[02-9ac-hj-np-z]{38}$")

SHAPE_BY_FAMILY = {
    "evm": RE_EVM, "tron": RE_TRON, "btc": re.compile(RE_BTC_B58.pattern + "|" + RE_BTC_BECH32.pattern),
    "ltc": RE_LTC, "doge": RE_DOGE, "bch": RE_BCH, "bsv": RE_BCH, "xrp": RE_XRP, "ton": RE_TON,
    "avax": RE_AVAX_XP, "ada": RE_ADA, "bnb_beacon": RE_BNB_BEACON, "aptos": RE_HEX64, "sui": RE_HEX64,
}
CURRENCY_FAMILY = {
    "BTC": "btc", "LTC": "ltc", "BCH": "bch", "BSV": "bsv", "BTG": "btg", "DOGE": "doge", "DASH": "dash",
    "ZEC": "zec", "XVG": "xvg",
    "ETH": "evm", "ETC": "evm", "BSC": "evm", "BEP20": "evm", "BNB_BSC": "evm", "MATIC": "evm",
    "POLYGON": "evm", "AVAXC": "evm", "ARB": "evm", "ARBITRUM": "evm", "OP": "evm",
    "OPTIMISM": "evm", "BASE": "evm", "FTM": "evm", "KCS": "evm", "ERC20": "evm", "EVM": "evm",
    "TRX": "tron", "TRON": "tron", "TRC20": "tron",
    "BEP2": "bnb_beacon", "XRP": "xrp", "RIPPLE": "xrp", "XMR": "xmr", "ADA": "ada", "SOL": "sol",
    "TON": "ton", "APTOS": "aptos", "APT": "aptos", "SUI": "sui", "DOT": "dot", "KSM": "ksm",
    "ATOM": "cosmos", "ALGO": "algo", "EOS": "eos", "FIL": "fil", "NEO": "neo",
}
TOKEN_CURRENCIES = frozenset({"USDT", "USDC", "DAI", "BUSD", "TUSD", "USDP", "FDUSD", "PYUSD", "RLUSD"})
#: currencies whose chain depends on the address shape (BNB: BEP2 bnb1... or BSC 0x...; AVAX: X/P or C-chain)
AMBIGUOUS_CURRENCIES = frozenset({"BNB", "AVAX"})
CHAIN_ALIASES = {
    "bitcoin": "btc", "btc": "btc", "eth": "evm", "ethereum": "evm", "evm": "evm", "bsc": "evm",
    "polygon": "evm", "tron": "tron", "trx": "tron", "litecoin": "ltc", "ltc": "ltc", "bch": "bch",
    "doge": "doge", "xrp": "xrp", "ton": "ton", "sol": "sol", "solana": "sol", "ada": "ada",
}
_SPECIAL_EVM = frozenset({
    "0x000000000000000000000000000000000000dead", "0xdead000000000000000042069420694206942069",
    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "0xffffffffffffffffffffffffffffffffffffffff",
})
TAG_FIELDS = frozenset({
    "label", "source", "currency", "network", "context", "confidence", "is_cluster_definer", "lastmod",
    "category", "abuse", "address", "tx_hash", "actor", "concepts", "tag_type", "address_validation",
})
_PERSON_LABEL_RES = (
    re.compile(r"^[A-Z][a-z]+(?: [A-Z][a-z'\-]+){1,3}$"),
    re.compile(r"^[A-Z'\-]+(?: [A-Z'\-]+)?, [A-Z][A-Za-z' \-]+$"),
)
PERSON_LABEL_WITHHELD = "natural person on a sanctions list (name withheld: see the source list)"

_BUILD_LOCK = threading.Lock()
_MEMO_LOCK = threading.Lock()
_INDEX_MEMO: dict[str, LabelIndex] = {}
_TEAM_MEMO: dict[str, tuple[Any, dict[str, Any]]] = {}
_POR_MEMO: dict[str, tuple[Any, dict[str, Any]]] = {}


class PackageMissing(ValueError):
    """The optional PyYAML package (extra 'yaml') is not installed: the GraphSense index cannot be built."""


# ======================================================================================== small helpers


def _text(value: Any) -> str:
    """A stripped str for str/int/float values, '' otherwise."""
    if isinstance(value, bool) or value is None:
        return ""
    if isinstance(value, (str, int, float)):
        return str(value).strip()
    return ""


def _to_text(data: Any) -> str:
    if isinstance(data, (bytes, bytearray)):
        return bytes(data).decode("utf-8-sig", "replace")
    return data if isinstance(data, str) else ""


def looks_like_html(data: Any) -> bool:
    """True when a body that should be YAML/CSV/zip is an HTML page (FC1/FC2 guards)."""
    head = _to_text(data[:2048] if isinstance(data, (bytes, bytearray, str)) else b"").lstrip().lower()
    return head.startswith(("<!doctype html", "<html", "<head", "<body")) or "<html" in head[:512]


def iso_date(value: Any) -> str | None:
    """A YAML/CSV date (date, datetime, 'YYYY-MM-DD[...]', YYYYMMDD) as 'YYYY-MM-DD' (FC2 pack date)."""
    if isinstance(value, dt.datetime):
        return value.date().isoformat()
    if isinstance(value, dt.date):
        return value.isoformat()
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str):
        return None
    text = value.strip()
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})(?:[T ].*)?$", text) or re.match(r"^(\d{4})(\d{2})(\d{2})$", text)
    if not m:
        return None
    try:
        return dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3))).isoformat()
    except ValueError:
        return None


def por_date_from_filename(filename: Any) -> str | None:
    """A PoR date (YYYYMMDD or YYYY-MM-DD) out of a downloaded file name (FC2 provenance helper)."""
    m = re.search(r"(20\d{2})[-_]?(\d{2})[-_]?(\d{2})", _text(filename))
    return iso_date("-".join(m.groups())) if m else None


def months_between(start_iso: Any, as_of: Any) -> int | None:
    """Whole calendar months from ``start_iso`` to ``as_of`` (date or ISO str); None when undated."""
    start = iso_date(start_iso)
    end = iso_date(as_of)
    if not start or not end:
        return None
    s, e = dt.date.fromisoformat(start), dt.date.fromisoformat(end)
    months = (e.year - s.year) * 12 + (e.month - s.month)
    if e.day < s.day:
        months -= 1
    return months


def confidence_label_for_level(level: Any) -> str:
    """GraphSense confidence level (0-100) -> CONFIRMED (>= 90), PROBABLE (>= 50), else POSSIBLE (FC2)."""
    if not isinstance(level, (int, float)) or isinstance(level, bool):
        return "POSSIBLE"
    if level >= 90:
        return "CONFIRMED"
    if level >= 50:
        return "PROBABLE"
    return "POSSIBLE"


def downgrade(label: str, steps: int = 1) -> str:
    """Steps down the CONFIRMED > PROBABLE > POSSIBLE ladder (floor POSSIBLE)."""
    order = ["POSSIBLE", "PROBABLE", "CONFIRMED"]
    idx = order.index(label) if label in order else 0
    return order[max(0, idx - steps)]


def effective_confidence(record: Mapping[str, Any], as_of: Any = None, max_age_months: int = POR_MAX_AGE_MONTHS) -> tuple[str, bool, int | None]:
    """FC2: PoR-derived labels (``record['por_snapshot']``) lose one confidence step once 12 months old.

    Returns (label, downgraded, age in months or None). Other labels keep ``confidence_base``.
    """
    base = record.get("confidence_base") or "POSSIBLE"
    age = months_between(record.get("label_date"), as_of) if as_of is not None else None
    if record.get("por_snapshot") and age is not None and age >= max_age_months:
        return downgrade(base), True, age
    return base, False, age


def label_looks_personal(label: Any) -> bool:
    """A label shaped like a natural person's name ('Firstname Lastname' / 'SURNAME, Given').

    GraphSense forbids PII, but SDN packs name sanctioned individuals: such labels never become person
    pivots and are withheld from the output (LGPD minimisation; the source list keeps the name).
    """
    text = _text(label)
    return bool(text) and any(rx.match(text) for rx in _PERSON_LABEL_RES)


def _norm_name(text: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", _text(text).lower())


def _slug(text: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", _text(text).lower()).strip("_") or "unknown"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _http_url(value: Any) -> str | None:
    text = _text(value)
    if not text:
        return None
    try:
        parts = urlsplit(text)
    except ValueError:
        return None
    return text if parts.scheme in ("http", "https") and parts.netloc else None


# ======================================================================================== address normalisation


def _b58decode(text: str) -> bytes | None:
    num = 0
    for ch in text:
        if ch not in _B58_INDEX:
            return None
        num = num * 58 + _B58_INDEX[ch]
    pad = len(text) - len(text.lstrip("1"))
    return b"\0" * pad + (num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b"")


def base58check_payload(text: str) -> bytes | None:
    """Decoded Base58Check payload (without the checksum) or None when the checksum fails."""
    raw = _b58decode(text)
    if raw is None or len(raw) < 5:
        return None
    payload, chk = raw[:-4], raw[-4:]
    return payload if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == chk else None


def _b58encode(raw: bytes) -> str:
    num = int.from_bytes(raw, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = _B58[rem] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def tron_hex_to_base58(hex_address: Any) -> str | None:
    """'41' + 40 hex -> TRON base58 'T...' address (TRON APIs return both forms)."""
    if not RE_TRON_HEX.match(_text(hex_address)):
        return None
    payload = bytes.fromhex(hex_address)
    return _b58encode(payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4])


def _bech32_polymod(values: Iterable[int]) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def bech32_ok(address: Any) -> bool:
    """BIP-173/BIP-350 checksum (bech32 or bech32m) of bc1/ltc1/bnb1 strings."""
    text = _text(address)
    if text.lower() != text and text.upper() != text:
        return False
    text = text.lower()
    pos = text.rfind("1")
    if pos < 1 or pos + 7 > len(text) or len(text) > 90:
        return False
    data = [_BECH32_CHARSET.find(c) for c in text[pos + 1:]]
    if -1 in data:
        return False
    hrp = text[:pos]
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data
    return _bech32_polymod(values) in (1, 0x2BC830A3)


def _currency_hint(currency: Any, network: Any) -> str:
    """The most specific family hint: network first, then currency ('USDT-TON' -> TON, 'RLUSD_ERC20' ->
    ERC20); an unknown network ('OMNI') falls back to a known currency."""
    fallback = ""
    for raw in (network, currency):
        text = _text(raw).upper()
        if not text:
            continue
        if text in CURRENCY_FAMILY or text in TOKEN_CURRENCIES or text in AMBIGUOUS_CURRENCIES:
            return text
        parts = re.split(r"[-_ /]", text)
        if len(parts) >= 2 and parts[0] in TOKEN_CURRENCIES and parts[-1] in CURRENCY_FAMILY:
            return parts[-1]  # '<TOKEN>-<NETWORK>' only: 'L-BTC' (Liquid) is not Bitcoin
        fallback = fallback or text
    return fallback


def infer_family(address: Any) -> str:
    """The address family from its shape alone (inputs without a currency)."""
    text = _text(address)
    low = text.lower()
    if RE_EVM.match(text):
        return "evm"
    if RE_TRON.match(text) or RE_TRON_HEX.match(text):
        return "tron"
    if RE_BTC_BECH32.match(low) or RE_BTC_B58.match(text):
        return "btc"
    if low.startswith("ltc1") or re.match(r"^[LM][1-9A-HJ-NP-Za-km-z]{26,33}$", text):
        return "ltc"
    if low.startswith("bitcoincash:") or re.match(r"^[qp][02-9ac-hj-np-z]{41}$", low):
        return "bch"
    if RE_XRP.match(text):
        return "xrp"
    if RE_BNB_BEACON.match(low):
        return "bnb_beacon"
    if RE_TON.match(text):
        return "ton"
    if RE_AVAX_XP.match(text):
        return "avax"
    if low.startswith("addr1"):
        return "ada"
    if RE_DOGE.match(text) and text.startswith("D"):
        return "doge"
    return "unknown"


def normalize_address(address: Any, currency: Any = None, network: Any = None) -> dict[str, Any] | None:
    """(family, key) of an address for the label index (FC2/FC4 lookups).

    None for non-string/empty input, else ``{family, key, address, hint, shape_ok, checksum_ok,
    special}``: the key lower-cases EVM/bech32/cashaddr, converts TRON hex to base58 and keeps the others
    verbatim; tokens (USDT/USDC...) take the family of the address shape (USDT on TRON, ERC20 or
    Omni/BTC); ``special`` marks the EVM zero/burn/precompile addresses.
    """
    if isinstance(address, int) and not isinstance(address, bool):
        address = str(address)
    if not isinstance(address, str):
        return None
    text = address.strip().strip("'\"").strip()
    if not text:
        return None
    hint = _currency_hint(currency, network)
    if hint in CURRENCY_FAMILY:
        family = CURRENCY_FAMILY[hint]
    elif hint in TOKEN_CURRENCIES or hint in AMBIGUOUS_CURRENCIES or not hint:
        family = infer_family(text)
    else:
        family = hint.lower()
    key = text
    shape = SHAPE_BY_FAMILY.get(family, RE_GENERIC)
    if family == "tron" and RE_TRON_HEX.match(text):
        key = tron_hex_to_base58(text) or text
    elif family == "evm" or (family in ("btc", "ltc", "bnb_beacon", "ada") and text.lower().startswith(("bc1", "ltc1", "bnb1", "addr1"))):
        key = text.lower()
    elif family in ("bch", "bsv") and (text.lower().startswith("bitcoincash:") or re.match(r"^[qp][02-9ac-hj-np-z]{41}$", text.lower())):
        key = text.lower().split(":", 1)[-1]
    elif family in ("aptos", "sui"):
        key = text.lower()
    shape_ok = bool(shape.match(key if family in ("btc", "ltc", "bnb_beacon", "bch", "bsv") else text)) or (
        family == "tron" and bool(RE_TRON.match(key)))
    checksum_ok: bool | None = None
    if shape_ok and family == "tron":
        payload = base58check_payload(key)
        checksum_ok = bool(payload) and len(payload or b"") == 21 and (payload or b"\0")[0] == 0x41
    elif shape_ok and family in ("btc", "bsv", "bch") and RE_BTC_B58.match(key):
        payload = base58check_payload(key)
        checksum_ok = bool(payload) and len(payload or b"") == 21 and (payload or b"\xff")[0] in (0x00, 0x05)
    elif shape_ok and family in ("btc", "ltc", "bnb_beacon") and key.startswith(("bc1", "ltc1", "bnb1")):
        checksum_ok = bech32_ok(key)
    special = family == "evm" and (key in _SPECIAL_EVM or key[2:38] == "0" * 36)
    return {"family": family, "key": key, "address": text, "hint": hint, "shape_ok": shape_ok,
            "checksum_ok": checksum_ok, "special": special}


# ======================================================================================== FC1: YAML and archive safety


def yaml_safe_load() -> Callable[[str], Any] | None:
    """``yaml.safe_load`` of the optional PyYAML extra, or None when the package is missing (FC1)."""
    try:
        import yaml  # optional extra 'yaml'; safe_load only (never yaml.load)
    except ImportError:
        return None
    return yaml.safe_load


def check_yaml_loader(loader: Any) -> bool:
    """FC1: refuse any loader other than PyYAML's ``yaml.safe_load`` (never load/full_load/unsafe_load)."""
    name = getattr(loader, "__name__", "")
    module = getattr(loader, "__module__", "") or ""
    if name != "safe_load" or module.split(".")[0] != "yaml":
        raise ValueError(f"TagPacks must be parsed with yaml.safe_load only (got {module}.{name})")
    return True


_ANCHOR_ALIAS_RE = re.compile(r"(?m)(?:^[ \t]*(?:-[ \t]+)*|:[ \t]+)[&*][A-Za-z0-9_.\-]+(?=[ \t]*$|[ \t]+\S)")


def yaml_text_problem(data: Any, max_bytes: int = ARCHIVE_LIMITS["max_member_uncompressed"]) -> str | None:
    """FC1 pre-parse guard of one pack: a short reason or None.

    'empty', 'too_large', 'nul_bytes', 'html_instead_of_yaml', 'json_error_body', 'yaml_python_tag',
    'yaml_anchor_alias' (TagPacks never use anchors/aliases: refusing them avoids alias-expansion bombs).
    """
    if data is None:
        return "empty"
    size = len(data)
    if size == 0 or not _to_text(data).strip():
        return "empty"
    if size > max_bytes:
        return "too_large"
    text = _to_text(data)
    if "\x00" in text:
        return "nul_bytes"
    if looks_like_html(text):
        return "html_instead_of_yaml"
    if text.lstrip().startswith('{"message"'):
        return "json_error_body"
    if "!!python" in text or re.search(r"(?m)(?:^|[\s:\-])!<", text):
        return "yaml_python_tag"
    if _ANCHOR_ALIAS_RE.search(text):
        return "yaml_anchor_alias"
    return None


def load_pack_text(data: Any, loader: Callable[[str], Any], max_bytes: int = ARCHIVE_LIMITS["max_member_uncompressed"]) -> tuple[Any, str | None]:
    """FC1: guard + parse one pack with ``yaml.safe_load``. Returns (document, problem)."""
    check_yaml_loader(loader)
    problem = yaml_text_problem(data, max_bytes=max_bytes)
    if problem:
        return None, problem
    try:
        doc = loader(_to_text(data))
    except Exception as exc:  # noqa: BLE001 - YAMLError, RecursionError, decode errors: reported, never raised
        first = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
        return None, f"yaml_error: {first[:160]}"
    if not isinstance(doc, dict):
        return None, "not_a_mapping"
    return doc, None


def archive_listing_problem(entries: Iterable[tuple[str, int, int]], limits: Mapping[str, int] | None = None) -> str | None:
    """FC1 caps over (name, file_size, compress_size) entries: None or 'too_many_members' / 'too_large' /
    'member_too_large:<name>' / 'ratio:<name>'."""
    lim = dict(ARCHIVE_LIMITS, **(limits or {}))
    items = list(entries)
    if len(items) > lim["max_members"]:
        return "too_many_members"
    total = 0
    for name, size, csize in items:
        total += size
        if size > lim["max_member_uncompressed"]:
            return f"member_too_large:{name}"
        if size and size / max(csize, 1) > lim["max_ratio"]:
            return f"ratio:{name}"
    if total > lim["max_total_uncompressed"]:
        return "too_large"
    return None


def archive_commit_from_comment(comment: Any) -> str | None:
    """git archive / codeload zips carry the commit id as the zip comment (FC2 provenance per tag)."""
    text = _to_text(comment).strip()
    return text.lower() if re.fullmatch(r"[0-9a-fA-F]{40}", text) else None


def tagpack_archive_members(names: Iterable[Any]) -> dict[str, Any]:
    """FC1: TagPack/ActorPack members of a repository-archive listing (names only, nothing extracted).

    Expects one top-level folder 'graphsense-tagpacks-<ref>/'. Returns ``{prefix, tagpacks: [(member,
    rel_path)], actorpacks: [(member, rel_path)], ignored, rejected: [member]}``; rejected names are
    absolute, contain '..', backslashes, NUL or empty components, or sit outside the prefix. Member names
    are never used as file paths.
    """
    names = [n for n in names if isinstance(n, str)]
    tops = {n.split("/", 1)[0] for n in names if n and "/" in n}
    prefix = None
    candidates = sorted(t for t in tops if t.startswith("graphsense-tagpacks"))
    if len(candidates) == 1:
        prefix = candidates[0] + "/"
    out: dict[str, Any] = {"prefix": prefix, "tagpacks": [], "actorpacks": [], "ignored": 0, "rejected": []}
    for name in names:
        parts = name.split("/")
        if (name.startswith("/") or "\\" in name or "\x00" in name or re.match(r"^[A-Za-z]:", name)
                or any(p in ("..", ".") for p in parts) or (prefix and not name.startswith(prefix))
                or "" in parts[:-1]):
            out["rejected"].append(name)
            continue
        if name.endswith("/"):
            continue
        rel = name[len(prefix):] if prefix else name
        if rel.startswith("packs/") and rel.endswith((".yaml", ".yml")):
            out["tagpacks"].append((name, rel))
        elif rel.startswith("actors/") and rel.count("/") == 1 and rel.endswith((".yaml", ".yml")):
            out["actorpacks"].append((name, rel))
        else:
            out["ignored"] += 1
    return out


# ======================================================================================== FC2/FC4: TagPack parsing


def _is_ofac_source(source_url: Any, title: Any) -> bool:
    if "ofac" in _text(title).lower():
        return True
    url = _text(source_url)
    if not url:
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    path = parts.path.lower()
    return host.endswith("treasury.gov") and bool(re.search(r"/ofac/downloads/(?:sdn|sdnlist|cons|consolidated)[^/]*$", path))


def classify(category: Any = None, abuse: Any = None, concepts: Any = (), source_url: Any = None, title: Any = None) -> tuple[str | None, str | None]:
    """FC4: (entity_class, risk_class) of a tag.

    The entity class comes from the category or the concepts; the risk class from the abuse value, a
    risk category (sanction -> 'ofac', black_list -> 'issuer_blacklist') or an OFAC SDN-list
    source/title. A tag with an abuse value is a perpetrator tag: it never gets an exchange class from
    its concepts.
    """
    cat = _text(category).lower() or None
    abu = _text(abuse).lower() or None
    conc = [_text(x).lower() for x in concepts if _text(x)] if isinstance(concepts, (list, tuple, set, frozenset)) else []
    entity = ENTITY_CLASS_BY_CATEGORY.get(cat) if cat else None
    if entity is None and not abu:
        for concept in conc:
            if concept in ENTITY_CLASS_BY_CATEGORY:
                entity = ENTITY_CLASS_BY_CATEGORY[concept]
                break
    risk = None
    for value in (abu, cat, *conc):
        if value and value in RISK_CLASS_BY_VALUE:
            risk = RISK_CLASS_BY_VALUE[value]
            break
    if risk is None and _is_ofac_source(source_url, title):
        risk = "ofac"
    return entity, risk


def is_por_pack(pack_path: Any, title: Any) -> bool:
    """GraphSense packs that are exchange/custodian proof-of-reserves snapshots (dated, FC2 downgrade)."""
    base = _text(pack_path).rsplit("/", 1)[-1].lower()
    return base.startswith(("exchange-wallets-", "service-wallets-")) or "reserve" in _text(title).lower()


def pack_url(pack_path: str, commit: str | None) -> str:
    return f"{GRAPHSENSE_REPO_URL}/blob/{commit or 'master'}/{quote(pack_path)}"


def parse_tagpack(doc: Any, *, pack_path: str, commit: str | None = None, commit_date: Any = None) -> dict[str, Any]:
    """FC2: one TagPack document (from ``yaml.safe_load``) -> label rows with provenance.

    Header fields other than title/creator/description/owner/is_public/tags are inherited by every tag
    unless the tag overrides them (GraphSense rule). Each row carries family, address_key, currency,
    network, label, category, abuse, concepts, actor, entity_class, risk_class, confidence_id,
    confidence_level, confidence_base, confidence_inferred (a missing confidence on a tag sourced from
    the OFAC SDN list -> authority_data), label_date (tag/header lastmod, else the commit date) and
    date_source, por_snapshot, currency_mismatch, label_personal_hint and source_url. Tags that are not
    addresses (tx_hash, address_validation: skip values failing the shape check), addresses failing their
    Base58Check/bech32 checksum, special EVM addresses and bad types are skipped and counted; a tag whose declared currency contradicts an unambiguous
    shape (EVM 0x+40 hex, checksum-valid TRON) is kept under the shape's family with
    ``currency_mismatch`` (counted in 'rescued'). Returns ``{pack, tags, skipped, rescued, problems}``.
    """
    problems: list[str] = []
    skipped: collections.Counter[str] = collections.Counter()
    if not isinstance(doc, dict):
        return {"pack": None, "tags": [], "skipped": {}, "rescued": 0, "problems": ["not_a_mapping"]}
    header = {k: v for k, v in doc.items() if k != "tags"}
    title, creator = _text(header.get("title")), _text(header.get("creator"))
    if not title:
        problems.append("missing_title")
    if not creator:
        problems.append("missing_creator")
    if header.get("is_public") is False:
        return {"pack": None, "tags": [], "skipped": {}, "rescued": 0, "problems": problems + ["pack_not_public"]}
    tags = doc.get("tags")
    if tags is None:
        problems.append("missing_tags")
        tags = []
    elif not isinstance(tags, list):
        problems.append("tags_not_a_list")
        tags = []
    por = is_por_pack(pack_path, title)
    pack = {
        "path": pack_path, "title": title or None, "creator": creator or None, "url": pack_url(pack_path, commit),
        "commit": commit, "lastmod": iso_date(header.get("lastmod")), "n_tags_raw": len(tags), "por_snapshot": por,
    }
    inherited = {k: v for k, v in header.items() if k in TAG_FIELDS}
    unknown_conf: set[str] = set()
    rows: list[dict[str, Any]] = []
    rescued = 0
    for tag in tags:
        if not isinstance(tag, dict):
            skipped["tag_not_a_mapping"] += 1
            continue
        eff = dict(inherited)
        eff.update({k: v for k, v in tag.items() if k in TAG_FIELDS})
        address = eff.get("address")
        if address is None:
            skipped["tx_hash_tag" if eff.get("tx_hash") else "missing_address"] += 1
            continue
        currency = _text(eff.get("currency")).upper()
        network = _text(eff.get("network")).upper() or currency
        norm = normalize_address(address, currency=currency, network=network)
        if norm is None:
            skipped["bad_address_type"] += 1
            continue
        mismatch = False
        if not norm["shape_ok"]:
            alt = normalize_address(address)  # declared currency wrong? rescue only unambiguous shapes
            if alt and alt["shape_ok"] and (alt["family"] == "evm" or (alt["family"] == "tron" and alt["checksum_ok"])):
                norm, mismatch = alt, True
            else:
                skipped["address_validation_skip" if eff.get("address_validation") == "skip" else "invalid_address"] += 1
                continue
        if norm["special"]:
            skipped["special_address"] += 1
            continue
        if norm["checksum_ok"] is False:  # a typo in the source (e.g. plustoken.yaml): it can never match a real address
            skipped["checksum_failed"] += 1
            continue
        if mismatch:
            rescued += 1
        source_url = _text(eff.get("source")) or None
        conf_id = _text(eff.get("confidence")).lower() or "unknown"
        conf_inferred = False
        if not _text(eff.get("confidence")) and _is_ofac_source(source_url, None):
            conf_id, conf_inferred = "authority_data", True  # copied from the authority's own list
        level = CONFIDENCE_LEVELS.get(conf_id)
        if level is None:
            unknown_conf.add(conf_id)
            level = CONFIDENCE_LEVELS["unknown"]
        raw_concepts = eff.get("concepts")
        concepts = [_text(c).lower() for c in raw_concepts if _text(c)] if isinstance(raw_concepts, list) else []
        entity, risk = classify(eff.get("category"), eff.get("abuse"), concepts, source_url, title)
        label_date, date_source = iso_date(eff.get("lastmod")), "lastmod"
        if not label_date and commit_date:
            label_date, date_source = iso_date(commit_date), "commit"
        label = _text(eff.get("label")) or None
        rows.append({
            "family": norm["family"], "address_key": norm["key"], "currency": currency or None, "network": network or None,
            "currency_mismatch": mismatch, "label": label, "category": _text(eff.get("category")).lower() or None,
            "abuse": _text(eff.get("abuse")).lower() or None, "concepts": concepts, "actor": _text(eff.get("actor")) or None,
            "entity_class": entity, "risk_class": risk, "confidence_id": conf_id, "confidence_level": level,
            "confidence_base": confidence_label_for_level(level), "confidence_inferred": conf_inferred,
            "label_date": label_date, "date_source": date_source if label_date else None, "por_snapshot": por,
            "label_personal_hint": label_looks_personal(label), "source": "graphsense", "source_url": source_url,
        })
    problems.extend(f"unknown_confidence:{c}" for c in sorted(unknown_conf))
    return {"pack": pack, "tags": rows, "skipped": dict(skipped), "rescued": rescued, "problems": problems}


def parse_actorpack(doc: Any) -> dict[str, Any]:
    """FC4: ActorPack -> institutions to name for legal requests.

    ``{lastmod, actors: {id: {id, label, uri, categories, jurisdictions, aliases, legal_name, same_as,
    active, is_exchange}}, problems}``; context may be a mapping or JSON text.
    """
    out: dict[str, Any] = {"lastmod": None, "actors": {}, "problems": []}
    if not isinstance(doc, dict):
        out["problems"].append("not_a_mapping")
        return out
    out["lastmod"] = iso_date(doc.get("lastmod"))
    actors = doc.get("actors")
    if not isinstance(actors, list):
        out["problems"].append("actors_not_a_list")
        return out
    bad = 0

    def strlist(value: Any) -> list[str]:
        return [_text(v) for v in value if _text(v)] if isinstance(value, list) else []

    for actor in actors:
        if not isinstance(actor, dict) or not _text(actor.get("id")):
            bad += 1
            continue
        aid = _text(actor.get("id"))
        ctx = _parse_context(actor.get("context")) or {}
        categories = [c.lower() for c in strlist(actor.get("categories"))]
        out["actors"][aid] = {
            "id": aid, "label": _text(actor.get("label")) or aid, "uri": _text(actor.get("uri")) or None,
            "categories": categories, "jurisdictions": [j.upper() for j in strlist(actor.get("jurisdictions"))],
            "aliases": strlist(actor.get("aliases")) or strlist(ctx.get("aliases")),
            "legal_name": _text(ctx.get("legal_name")) or None, "same_as": strlist(ctx.get("same_as")),
            "active": ctx.get("active") if isinstance(ctx.get("active"), bool) else None,
            "is_exchange": "exchange" in categories,
        }
    if bad:
        out["problems"].append(f"bad_actor_entries:{bad}")
    return out


def _parse_context(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip().startswith("{") and len(value) <= 20000:
        try:
            parsed = json.loads(value)
        except ValueError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def actor_directory(actors: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """``{actors, alias_index, canonical}``: name/alias lookups and one canonical id per same_as group
    (rebrands and duplicates never look like conflicts)."""
    index: dict[str, str] = {}
    for aid, info in actors.items():
        for name in (aid, info.get("label"), *(info.get("aliases") or [])):
            key = _norm_name(name)
            if key:
                index.setdefault(key, aid)
    parent = {aid: aid for aid in actors}

    def find(x: str) -> str:
        while parent.get(x, x) != x:
            x = parent[x]
        return x

    for aid, info in actors.items():
        for other in info.get("same_as") or []:
            if other in parent:
                a, b = sorted((find(aid), find(other)))
                parent[b] = a
    return {"actors": dict(actors), "alias_index": index, "canonical": {aid: find(aid) for aid in actors}}


def resolve_actor(name: Any, directory: Mapping[str, Any] | None) -> str | None:
    """An exchange name/alias ('OKX', 'Mercado Bitcoin', 'binance.com') -> actor id, else None."""
    if not directory or not _text(name):
        return None
    index = directory.get("alias_index") or {}
    key = _norm_name(name)
    if key in index:
        return index[key]
    stripped = _norm_name(re.sub(r"\.(com|io|net|org)(\.br)?$", "", _text(name).lower()))
    return index.get(stripped)


# ======================================================================================== FC2: SQLite index of the archive

_DDL = """
CREATE TABLE packs(id INTEGER PRIMARY KEY, path TEXT NOT NULL, title TEXT, creator TEXT, url TEXT, lastmod TEXT,
                   por_snapshot INTEGER NOT NULL, tags INTEGER NOT NULL, skipped TEXT, problems TEXT);
CREATE TABLE labels(family TEXT NOT NULL, address_key TEXT NOT NULL, currency TEXT, network TEXT, label TEXT,
                    category TEXT, abuse TEXT, concepts TEXT, actor TEXT, entity_class TEXT, risk_class TEXT,
                    confidence_id TEXT, confidence_level INTEGER, confidence_inferred INTEGER NOT NULL,
                    label_date TEXT, date_source TEXT, por_snapshot INTEGER NOT NULL, currency_mismatch INTEGER NOT NULL,
                    personal_hint INTEGER NOT NULL, source_url TEXT, pack_id INTEGER NOT NULL);
CREATE TABLE actors(id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
"""
_LABEL_COLUMNS = ("family", "address_key", "currency", "network", "label", "category", "abuse", "concepts", "actor",
                  "entity_class", "risk_class", "confidence_id", "confidence_level", "confidence_inferred", "label_date",
                  "date_source", "por_snapshot", "currency_mismatch", "personal_hint", "source_url", "pack_id")
_INSERT_LABEL = f"INSERT INTO labels({', '.join(_LABEL_COLUMNS)}) VALUES({', '.join('?' * len(_LABEL_COLUMNS))})"


def index_dir() -> Path:
    """Directory of the on-disk indexes (next to the core dataset indexes)."""
    return paths.datasets_dir() / ".index"


def index_path(sha256: str) -> Path:
    """Index file of one archive version (keyed by the SHA-256 of the downloaded archive)."""
    if not re.fullmatch(r"[0-9a-f]{64}", str(sha256 or "")):
        raise ValueError("crypto label index: a SHA-256 hex digest is required")
    return index_dir() / f"{INDEX_PREFIX}{sha256}{INDEX_SUFFIX}"


def _row_tuple(row: Mapping[str, Any], pack_id: int) -> tuple[Any, ...]:
    return (
        row["family"], row["address_key"], row.get("currency"), row.get("network"), row.get("label"), row.get("category"),
        row.get("abuse"), json.dumps(row["concepts"]) if row.get("concepts") else None, row.get("actor"),
        row.get("entity_class"), row.get("risk_class"), row.get("confidence_id"), row.get("confidence_level"),
        int(bool(row.get("confidence_inferred"))), row.get("label_date"), row.get("date_source"),
        int(bool(row.get("por_snapshot"))), int(bool(row.get("currency_mismatch"))),
        int(bool(row.get("label_personal_hint"))), row.get("source_url"), pack_id,
    )


def read_archive(data: bytes, *, loader: Callable[[str], Any]) -> dict[str, Any]:
    """FC1: list and read a GraphSense repository archive **in memory** through the safe ZIP reader.

    Returns ``{commit, commit_date, members: [(kind, rel_path, text)], ignored, anomalies}``; raises
    ValueError for an unsafe or over-limit archive (nothing is extracted, member names are never paths).
    """
    check_yaml_loader(loader)
    if not isinstance(data, (bytes, bytearray)) or len(data) > ARCHIVE_MAX_BYTES:
        raise ValueError("GraphSense archive missing or larger than the cap")
    if bytes(data[:4]) not in (b"PK\x03\x04", b"PK\x05\x06"):
        raise ValueError("not a zip archive (" + ("HTML page" if looks_like_html(data) else "unknown body") + ")")
    scan = zip_scan(bytes(data), max_members=ARCHIVE_LIMITS["max_members"] + 1)
    if not scan.get("ok"):
        raise ValueError("unreadable zip archive")
    if scan.get("anomalies"):
        raise ValueError("unsafe zip archive: " + ", ".join(scan["anomalies"][:5]))
    entries = [e for e in scan["entries"] if not e.get("is_dir")]
    if any(e.get("is_symlink") or e.get("encrypted") for e in entries):
        raise ValueError("unsafe zip archive: symlink or encrypted member")
    problem = archive_listing_problem((e["name"], int(e["file_size"]), int(e["compressed_size"])) for e in entries)
    if problem:
        raise ValueError(f"zip archive over the safe-archive limits: {problem}")
    selected = tagpack_archive_members([e["name"] for e in scan["entries"]])
    if selected["rejected"]:
        raise ValueError(f"unsafe zip member names: {selected['rejected'][:3]}")
    if not selected["prefix"] or not selected["tagpacks"]:
        raise ValueError("not a graphsense-tagpacks archive (no top folder or no packs/*.yaml)")
    by_name = {e["name"]: e for e in entries}
    budget = Budget(ARCHIVE_LIMITS["max_total_uncompressed"])
    members: list[tuple[str, str, str]] = []
    mtimes = sorted(str(e.get("mtime")) for e in entries if e.get("mtime"))
    for kind, items in (("actorpack", selected["actorpacks"]), ("tagpack", selected["tagpacks"])):
        for member, rel in sorted(items, key=lambda x: x[1]):
            entry = by_name[member]
            try:
                raw = zip_read(bytes(data), entry, max_out=ARCHIVE_LIMITS["max_member_uncompressed"], ratio=ARCHIVE_LIMITS["max_ratio"], budget=budget)
            except ArchiveLimit as exc:
                raise ValueError(f"zip member {rel} refused by the safe reader: {exc.args[0] if exc.args else 'limit'}") from None
            if entry.get("crc_mismatch"):
                raise ValueError(f"zip member {rel} fails its CRC (truncated or corrupt download)")
            members.append((kind, rel, raw.decode("utf-8-sig", "replace")))
    return {
        "commit": archive_commit_from_comment(scan.get("comment")),
        "commit_date": iso_date((mtimes[-1] if mtimes else "")[:10]),
        "members": members,
        "ignored": selected["ignored"],
        "anomalies": scan.get("anomalies") or [],
    }


def build_index(archive_path: Path | str, sha256: str = "", *, loader: Callable[[str], Any] | None = None, keep: Iterable[str] = ()) -> Path:
    """FC1/FC2: parse a downloaded GraphSense archive and build its SQLite label index (temp file + atomic
    rename, 0600). Raises :class:`PackageMissing` without PyYAML and ValueError for an unsafe, empty or
    unparsable archive (the dataset manager then keeps the previous copy). Indexes of other archive
    versions are pruned except ``keep``."""
    loader = loader or yaml_safe_load()
    if loader is None:
        raise PackageMissing("PyYAML (optional extra 'yaml') is required to index the GraphSense TagPacks: pip install 'v3lum[yaml]', then v3lum data update " + GS_DATASET)
    check_yaml_loader(loader)
    src = Path(archive_path)
    if src.stat().st_size > ARCHIVE_MAX_BYTES:
        raise ValueError("GraphSense archive larger than the cap")
    data = src.read_bytes()
    sha = sha256 or hashlib.sha256(data).hexdigest()
    archive = read_archive(data, loader=loader)
    target = index_path(sha)
    directory = paths.private_dir(index_dir())
    fd, tmp_name = tempfile.mkstemp(prefix=f".{INDEX_PREFIX}", suffix=INDEX_SUFFIX, dir=str(directory))
    os.close(fd)
    tmp = Path(tmp_name)
    problems: list[str] = []
    totals: collections.Counter[str] = collections.Counter()
    try:
        con = sqlite3.connect(str(tmp))
        try:
            con.execute("PRAGMA journal_mode=OFF")
            con.execute("PRAGMA synchronous=OFF")
            con.executescript(_DDL)
            actors_seen = 0
            for kind, rel, text in archive["members"]:
                doc, problem = load_pack_text(text, loader)
                if problem:
                    problems.append(f"{rel}: {problem}")
                    totals["packs_refused"] += 1
                    continue
                if kind == "actorpack":
                    parsed = parse_actorpack(doc)
                    problems.extend(f"{rel}: {p}" for p in parsed["problems"])
                    con.executemany("INSERT OR REPLACE INTO actors(id, data) VALUES(?, ?)",
                                    [(aid, json.dumps(info, ensure_ascii=False)) for aid, info in parsed["actors"].items()])
                    actors_seen += len(parsed["actors"])
                    if parsed["lastmod"]:
                        con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('actorpack_lastmod', ?)", (parsed["lastmod"],))
                    continue
                parsed = parse_tagpack(doc, pack_path=rel, commit=archive["commit"], commit_date=archive["commit_date"])
                problems.extend(f"{rel}: {p}" for p in parsed["problems"])
                pack = parsed["pack"]
                if pack is None:
                    totals["packs_refused"] += 1
                    continue
                cur = con.execute(
                    "INSERT INTO packs(path, title, creator, url, lastmod, por_snapshot, tags, skipped, problems) VALUES(?,?,?,?,?,?,?,?,?)",
                    (rel, pack["title"], pack["creator"], pack["url"], pack["lastmod"], int(pack["por_snapshot"]),
                     len(parsed["tags"]), json.dumps(parsed["skipped"]), json.dumps(parsed["problems"])))
                pack_id = int(cur.lastrowid or 0)
                con.executemany(_INSERT_LABEL, [_row_tuple(r, pack_id) for r in parsed["tags"]])
                totals["packs"] += 1
                totals["tags"] += len(parsed["tags"])
                totals["skipped"] += sum(parsed["skipped"].values())
                totals["rescued"] += parsed["rescued"]
            if not totals["tags"]:
                raise ValueError("no address tag could be parsed from the GraphSense archive")
            con.execute("CREATE INDEX labels_key ON labels(address_key)")
            coverage = _sql_coverage(con)
            meta = {
                "sha256": sha, "commit": archive["commit"] or "", "commit_date": archive["commit_date"] or "",
                "built_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
                "index_version": INDEX_VERSION, "packs": str(totals["packs"]), "tags": str(totals["tags"]),
                "skipped": str(totals["skipped"]), "rescued": str(totals["rescued"]), "packs_refused": str(totals["packs_refused"]),
                "actors": str(actors_seen), "coverage": json.dumps(coverage), "problems": json.dumps(problems[:200]),
            }
            con.executemany("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", list(meta.items()))
            con.commit()
        finally:
            con.close()
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    _prune({sha, *[k for k in keep if k]})
    return target


def _sql_coverage(con: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    """FC4: per-family label coverage of the index (distinct addresses, exchange addresses, newest date)."""
    out: dict[str, dict[str, Any]] = {}
    for family, labelled in con.execute("SELECT family, COUNT(DISTINCT address_key) FROM labels GROUP BY family"):
        out[str(family)] = {"labelled_addresses": int(labelled), "exchange_addresses": 0, "newest_exchange_date": None}
    for family, count, newest in con.execute(
            "SELECT family, COUNT(DISTINCT address_key), MAX(label_date) FROM labels WHERE entity_class = 'exchange' GROUP BY family"):
        out.setdefault(str(family), {"labelled_addresses": 0})
        out[str(family)].update({"exchange_addresses": int(count), "newest_exchange_date": newest})
    return out


def _prune(keep: set[str]) -> None:
    """Remove indexes of archive versions that are neither new nor installed (best effort)."""
    try:
        for path in index_dir().glob(f"{MODULE}-v*{INDEX_SUFFIX}"):
            sha = path.name[:-len(INDEX_SUFFIX)].rsplit("-", 1)[-1]
            if sha not in keep or not path.name.startswith(INDEX_PREFIX):
                path.unlink(missing_ok=True)
    except OSError:  # pragma: no cover - pruning never fails a refresh
        pass


def validate_archive(path: Path) -> bool:
    """Dataset validator of :data:`GS_DATASET` (runs at refresh time on the downloaded archive, before the
    previous copy is replaced): safe in-memory read, ``yaml.safe_load`` parse and SQLite index (FC1/FC2)."""
    try:
        installed = DataStore(None).info(GS_DATASET).sha256
    except (ValueError, OSError):
        installed = ""
    build_index(path, keep=(installed,))
    return True


register_dataset(
    GS_DATASET,
    GRAPHSENSE_ARCHIVE_URL,
    ttl=WEEK,
    description="GraphSense public TagPacks (packs/**/*.yaml + actorpack) as one repository archive, refreshed weekly, "
                "read in memory and indexed into SQLite at refresh time (P358)",
    licence=GRAPHSENSE_LICENCE,
    terms_class="open",
    attribution=GRAPHSENSE_ATTRIBUTION,
    provider="github",
    source=GS_SOURCE,
    validate=validate_archive,
    min_bytes=1024,
    expect="bytes",
    max_bytes=ARCHIVE_MAX_BYTES,
    large=True,
    essential=True,
)


class LabelIndex:
    """Read-only access to one archive index (one indexed SELECT per lookup)."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        uri = "file:" + quote(str(self.path.resolve())) + "?mode=ro"
        self._con = sqlite3.connect(uri, uri=True, check_same_thread=False)
        self._lock = threading.Lock()
        self._meta: dict[str, str] | None = None
        self._directory: dict[str, Any] | None = None

    def meta(self) -> dict[str, str]:
        if self._meta is None:
            with self._lock:
                self._meta = {str(k): str(v) for k, v in self._con.execute("SELECT key, value FROM meta")}
        return self._meta

    def coverage(self) -> dict[str, Any]:
        try:
            value = json.loads(self.meta().get("coverage") or "{}")
        except ValueError:
            return {}
        return value if isinstance(value, dict) else {}

    def directory(self) -> dict[str, Any]:
        """The ActorPack as an actor directory (memoised for the life of the index)."""
        if self._directory is None:
            actors: dict[str, Any] = {}
            with self._lock:
                rows = self._con.execute("SELECT id, data FROM actors").fetchall()
            for aid, data in rows:
                try:
                    info = json.loads(data)
                except ValueError:
                    continue
                if isinstance(info, dict):
                    actors[str(aid)] = info
            self._directory = actor_directory(actors)
        return self._directory

    def lookup(self, key: str) -> list[dict[str, Any]]:
        """Every GraphSense label of one address key, with pack provenance."""
        cols = ", ".join(f"l.{c}" for c in _LABEL_COLUMNS[:-1])
        sql = (f"SELECT {cols}, p.path, p.title, p.creator, p.url FROM labels l JOIN packs p ON p.id = l.pack_id "
               "WHERE l.address_key = ? LIMIT 1000")
        with self._lock:
            rows = self._con.execute(sql, (key,)).fetchall()
        meta = self.meta()
        out = []
        for row in rows:
            rec = dict(zip(_LABEL_COLUMNS[:-1], row[:len(_LABEL_COLUMNS) - 1]))
            path_, title, creator, url = row[len(_LABEL_COLUMNS) - 1:]
            try:
                rec["concepts"] = json.loads(rec["concepts"]) if rec.get("concepts") else []
            except ValueError:
                rec["concepts"] = []
            for flag in ("confidence_inferred", "por_snapshot", "currency_mismatch"):
                rec[flag] = bool(rec.get(flag))
            rec["label_personal_hint"] = bool(rec.pop("personal_hint", 0))
            rec["confidence_base"] = confidence_label_for_level(rec.get("confidence_level"))
            rec["source"] = "graphsense"
            rec["provenance"] = {"dataset": GS_DATASET, "commit": meta.get("commit") or None, "pack_path": path_,
                                 "pack_url": url, "pack_title": title, "creator": creator, "attribution": GRAPHSENSE_ATTRIBUTION}
            out.append(rec)
        return out

    def close(self) -> None:
        self._con.close()


def open_index(archive_path: Path, sha256: str, *, loader: Callable[[str], Any] | None = None) -> LabelIndex:
    """The index of the installed archive, built now when it is missing (a copy installed before this
    index version existed, or an index removed by hand): a one-off cost."""
    target = index_path(sha256)
    with _MEMO_LOCK:
        hit = _INDEX_MEMO.get(str(target))
    if hit is not None and target.is_file():
        return hit
    if not target.is_file():
        with _BUILD_LOCK:
            if not target.is_file():
                build_index(archive_path, sha256, loader=loader)
    index = LabelIndex(target)
    try:
        tags = int(index.meta().get("tags") or 0)
    except (sqlite3.Error, ValueError):
        index.close()
        raise
    if tags <= 0:
        index.close()
        raise ValueError("the crypto label index is empty")
    with _MEMO_LOCK:
        _INDEX_MEMO[str(target)] = index
    return index


# ======================================================================================== FC2: manual PoR imports

_CHALLENGE_MARKERS = ("just a moment", "cf-chl", "challenge-platform", "captcha", "awswaf",
                      "attention required", "access denied", "enable javascript and cookies")


def por_input_problem(data: Any, *, status: int | None = None, headers: Mapping[str, str] | None = None) -> str | None:
    """FC2: classify something offered as a PoR file (or an observed PoR page response).

    None (looks like CSV data) or 'bot_interstitial' (e.g. Binance 202 with an empty body),
    'bot_challenge' (Cloudflare/AWS WAF challenge), 'empty', 'html_page_not_por_file' (e.g. the OKX PoR
    page saved instead of the address file), 'json_not_csv', 'not_csv'. V3LUM never fetches PoR pages:
    the analyst downloads the file in a browser and imports it.
    """
    hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    text = _to_text(data or b"")
    if status == 202 and not text.strip():
        return "bot_interstitial"
    if hdrs.get("cf-mitigated", "").lower() == "challenge" or "x-amzn-waf-action" in hdrs:
        return "bot_challenge"
    if not text.strip():
        return "empty"
    if looks_like_html(text):
        low = text[:20000].lower()
        return "bot_challenge" if any(m in low for m in _CHALLENGE_MARKERS) else "html_page_not_por_file"
    first = text.lstrip().splitlines()[0] if text.strip() else ""
    if first.startswith(("{", "[")):
        return "json_not_csv"
    if not any(sep in first for sep in (",", ";", "\t")):
        return "not_csv"
    return None


_POR_COLUMNS = {
    "address": ("address", "wallet address", "wallet_address", "walletaddress", "addr"),
    "coin": ("coin", "asset", "currency", "token", "symbol"),
    "network": ("network", "chain", "blockchain"),
    "type": ("type", "wallet type"),
    "snapshot_height": ("snapshot height", "snapshot_height", "block height", "block_height", "height"),
    "message": ("message", "signed message", "signed_message"),
    "signature1": ("signature1", "signature", "signature 1"),
    "signature2": ("signature2", "signature 2"),
    "eoa1": ("eoa1",), "eoa2": ("eoa2",),
    "exchange": ("exchange", "institution", "vasp"),
    "por_date": ("por_date", "por date", "snapshot_date", "snapshot date", "date"),
    "source_url": ("source_url", "source url", "source", "url"),
}
OKX_SIGNED_MESSAGE = "I am an OKX address"


def _column_map(header: list[str]) -> dict[str, int]:
    norm = [re.sub(r"\s+", " ", _text(h).lower()) for h in header]
    out: dict[str, int] = {}
    for field, names in _POR_COLUMNS.items():
        for i, h in enumerate(norm):
            if h in names and field not in out:
                out[field] = i
    return out


def parse_por_csv(data: Any, *, exchange: Any, por_date: Any, source_url: Any, imported_by: Any = None,
                  imported_at: Any = None, directory: Mapping[str, Any] | None = None,
                  signature_verified: bool = False, file_name: str = "") -> dict[str, Any]:
    """FC2: an analyst-imported PoR address file -> exchange label records (provenance and date mandatory).

    Accepts the OKX two-section CSV ('coin,amount' totals, blank line, then 'coin,Type,Network,Snapshot
    Height,address,amount,message,signature1,signature2,redeem script/ public key,EOA1,EOA2') and a
    generic one-section CSV (tolerant header names; per-row exchange/por_date/source_url override the
    arguments). Rows with message + signature1 are 'signed' -> CONFIRMED (FC2 'high'); unsigned rows
    PROBABLE. 0x+96-hex staking validator keys are not addresses: their EOA1/EOA2 become 'staking_eoa'
    rows. Invalid shapes are skipped and counted. Returns ``{format, exchange, por_date, summary,
    labels, skipped, problems}``.
    """
    result: dict[str, Any] = {"format": None, "exchange": _text(exchange) or None, "por_date": iso_date(por_date),
                              "summary": {}, "labels": [], "skipped": {}, "problems": []}
    problem = por_input_problem(data)
    if problem:
        result["problems"].append(problem)
        return result
    text = _to_text(data)
    sections = [s for s in re.split(r"\n\s*\n", text.replace("\r\n", "\n")) if s.strip()]
    addr_rows: list[list[str]] | None = None
    cmap: dict[str, int] = {}
    for section in sections:
        try:
            rows = list(csv.reader(io.StringIO(section)))
        except csv.Error:
            result["problems"].append("csv_error")
            return result
        if not rows:
            continue
        cols = _column_map(rows[0])
        if "address" in cols:
            addr_rows, cmap = rows, cols
        elif [h.strip().lower() for h in rows[0]] == ["coin", "amount"]:
            result["summary"] = {r[0].strip(): r[1].strip() for r in rows[1:] if len(r) >= 2 and r[0].strip()}
    if addr_rows is None:
        result["problems"].append("no_address_column")
        return result
    result["format"] = "okx" if {"message", "signature1", "snapshot_height"} <= set(cmap) else "generic"
    if not result["exchange"] and "exchange" not in cmap:
        result["problems"].append("missing_exchange")
    if not result["por_date"] and "por_date" not in cmap:
        result["problems"].append("missing_por_date")
    if not _http_url(source_url) and "source_url" not in cmap:
        result["problems"].append("missing_source_url")
    if result["problems"]:
        return result  # FC2: no import without provenance and date
    skipped: collections.Counter[str] = collections.Counter()
    seen: set[tuple[str, str, str]] = set()
    imported = iso_date(imported_at) if imported_at else None

    def cell(row: list[str], field: str) -> str:
        idx = cmap.get(field)
        return row[idx].strip() if idx is not None and idx < len(row) else ""

    for row in addr_rows[1:]:
        if not any(c.strip() for c in row):
            continue
        ex_name = cell(row, "exchange") or result["exchange"]
        row_date = iso_date(cell(row, "por_date")) or result["por_date"]
        row_src = _http_url(cell(row, "source_url")) or _http_url(source_url)
        if not ex_name or not row_date or not row_src:
            skipped["missing_provenance"] += 1
            continue
        coin, network = cell(row, "coin").upper(), cell(row, "network").upper()
        message, sig1 = cell(row, "message"), cell(row, "signature1")
        signed = bool(message and sig1)
        height = cell(row, "snapshot_height")
        address = cell(row, "address")
        if RE_EVM_VALIDATOR_KEY.match(address):
            skipped["validator_pubkey"] += 1
            targets = [(cell(row, f), "staking_eoa") for f in ("eoa1", "eoa2") if cell(row, f)]
        else:
            targets = [(address, "reserve")]
        actor = resolve_actor(ex_name, directory)
        for addr, role in targets:
            norm = normalize_address(addr, currency=coin, network=network)
            if norm is None or not norm["shape_ok"]:
                skipped["invalid_address"] += 1
                continue
            if norm["special"]:
                skipped["special_address"] += 1
                continue
            dedupe = (norm["family"], norm["key"], _slug(ex_name))
            if dedupe in seen:
                skipped["duplicate"] += 1
                continue
            seen.add(dedupe)
            conf_id = "ownership" if signed else "service_data"
            result["labels"].append({
                "family": norm["family"], "address_key": norm["key"], "currency": coin or None,
                "network": network or coin or None, "currency_mismatch": False,
                "label": f"{ex_name} proof-of-reserves address ({coin or '?'}/{network or '?'})",
                "category": "exchange", "abuse": None, "concepts": [], "actor": actor,
                "entity_class": "exchange", "risk_class": None, "confidence_id": conf_id,
                "confidence_level": CONFIDENCE_LEVELS[conf_id], "confidence_base": "CONFIRMED" if signed else "PROBABLE",
                "confidence_inferred": False, "label_date": row_date, "date_source": "por_date", "por_snapshot": True,
                "source": f"por:{_slug(ex_name)}", "source_url": row_src, "role": role, "signed": signed,
                "okx_canonical_message": message == OKX_SIGNED_MESSAGE,
                "signature_verified": bool(signature_verified and signed),
                "snapshot_height": int(height) if height.isdigit() else None,
                "institution_name": ex_name, "label_personal_hint": False,
                "provenance": {"dataset": "exchange_por_manual", "exchange": ex_name, "source_url": row_src,
                               "por_date": row_date, "imported_by": _text(imported_by) or None, "imported_at": imported,
                               "format": result["format"], "file": file_name or None},
            })
    result["skipped"] = dict(skipped)
    return result


def _por_directory(ctx: Any) -> Path:
    configured = _text(ctx.setting(POR_DIR_SETTING, "") if ctx is not None else "")
    return Path(configured).expanduser() if configured else paths.home() / POR_DIR_DEFAULT


def import_por_file(src: Path | str, *, exchange: str, por_date: str, source_url: str, imported_by: str,
                    signature_verified: bool = False, directory: Path | str | None = None,
                    now: dt.datetime | None = None) -> dict[str, Any]:
    """FC2: import an analyst-downloaded PoR address file with provenance (the API behind a future
    ``v3lum data import-por`` command).

    The file is checked (size cap, no HTML/interstitial/JSON body, mandatory exchange/PoR date/source
    URL, at least one valid address) and copied with a provenance sidecar (``<name>.provenance.json``,
    schema :data:`POR_SIDECAR_SCHEMA`) into the PoR folder (setting ``crypto_address_labels_por_dir``,
    default ``<V3LUM home>/crypto_labels/por``), both 0600. Raises ValueError with the refusal reason.
    """
    path = Path(src)
    if not path.is_file():
        raise ValueError(f"PoR file not found: {path}")
    if path.stat().st_size > POR_MAX_FILE_BYTES:
        raise ValueError("PoR file larger than the import cap")
    data = path.read_bytes()
    if not iso_date(por_date):
        raise ValueError("the PoR date (YYYY-MM-DD) is mandatory")
    if not _http_url(source_url):
        raise ValueError("the PoR source URL (http/https page the file was downloaded from) is mandatory")
    if not _text(exchange) or not _text(imported_by):
        raise ValueError("the exchange name and the importing analyst are mandatory")
    parsed = parse_por_csv(data, exchange=exchange, por_date=por_date, source_url=source_url, imported_by=imported_by)
    if parsed["problems"]:
        raise ValueError("PoR file refused: " + ", ".join(parsed["problems"]))
    if not parsed["labels"]:
        raise ValueError("PoR file refused: no valid address")
    sha = hashlib.sha256(data).hexdigest()
    folder = paths.private_dir(Path(directory) if directory else paths.home() / POR_DIR_DEFAULT)
    stem = f"{_slug(exchange)}_{iso_date(por_date)}_{sha[:12]}"
    when = (now or dt.datetime.now(dt.timezone.utc)).date().isoformat()
    sidecar = {
        "schema": POR_SIDECAR_SCHEMA, "file": f"{stem}.csv", "file_sha256": sha, "exchange": _text(exchange),
        "por_date": iso_date(por_date), "source_url": _http_url(source_url), "imported_by": _text(imported_by),
        "imported_at": when, "signature_verified": bool(signature_verified), "original_name": path.name[:200],
        "format": parsed["format"],
    }
    paths.secure_write_bytes(folder / f"{stem}.csv", data)
    paths.secure_write_text(folder / f"{stem}{POR_SIDECAR_SUFFIX}", json.dumps(sidecar, indent=1, ensure_ascii=False))
    return {"path": str(folder / f"{stem}.csv"), "labels": len(parsed["labels"]), "skipped": parsed["skipped"],
            "format": parsed["format"], "sidecar": sidecar}


def load_por_labels(folder: Path, directory: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """FC2: every imported PoR file of the folder (sidecar provenance mandatory, SHA-256 checked) as
    ``{by_key: {key: [records]}, imports: [...], problems: [...], coverage: {family: {...}}}``; memoised
    on the folder listing (names, sizes, mtimes)."""
    empty: dict[str, Any] = {"by_key": {}, "imports": [], "problems": [], "coverage": {}}
    try:
        sidecars = sorted(p for p in folder.glob(f"*{POR_SIDECAR_SUFFIX}") if p.is_file())[:POR_MAX_FILES]
    except OSError:
        return empty
    if not sidecars:
        return empty
    stamp: list[Any] = [id(directory) if directory else 0]
    for p in sorted(folder.iterdir()):
        try:
            st = p.stat()
        except OSError:
            continue
        stamp.append((p.name, st.st_size, st.st_mtime_ns))
    key = str(folder.resolve())
    with _MEMO_LOCK:
        hit = _POR_MEMO.get(key)
    if hit is not None and hit[0] == stamp:
        return hit[1]
    out: dict[str, Any] = {"by_key": collections.defaultdict(list), "imports": [], "problems": [], "coverage": {}}
    for side in sidecars:
        try:
            if side.stat().st_size > 65536:
                raise ValueError("sidecar too large")
            meta = json.loads(side.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            out["problems"].append(f"{side.name}: unreadable provenance ({str(exc)[:80]})")
            continue
        if not isinstance(meta, dict) or meta.get("schema") != POR_SIDECAR_SCHEMA:
            out["problems"].append(f"{side.name}: not a {POR_SIDECAR_SCHEMA} provenance file")
            continue
        fname = _text(meta.get("file"))
        if not fname or "/" in fname or "\\" in fname or fname.startswith("."):
            out["problems"].append(f"{side.name}: bad file name")
            continue
        missing = [k for k in ("exchange", "por_date", "source_url", "imported_by") if not _text(meta.get(k))]
        if missing or not iso_date(meta.get("por_date")) or not _http_url(meta.get("source_url")):
            out["problems"].append(f"{side.name}: provenance incomplete ({', '.join(missing) or 'date/url'})")
            continue
        csv_path = folder / fname
        try:
            if csv_path.stat().st_size > POR_MAX_FILE_BYTES:
                raise ValueError("file larger than the import cap")
            data = csv_path.read_bytes()
        except (OSError, ValueError) as exc:
            out["problems"].append(f"{fname}: unreadable ({str(exc)[:80]})")
            continue
        sha = hashlib.sha256(data).hexdigest()
        if _text(meta.get("file_sha256")) and _text(meta.get("file_sha256")).lower() != sha:
            out["problems"].append(f"{fname}: SHA-256 differs from its provenance record (file changed after import)")
            continue
        parsed = parse_por_csv(data, exchange=meta.get("exchange"), por_date=meta.get("por_date"),
                               source_url=meta.get("source_url"), imported_by=meta.get("imported_by"),
                               imported_at=meta.get("imported_at"), directory=directory,
                               signature_verified=meta.get("signature_verified") is True, file_name=fname)
        if parsed["problems"]:
            out["problems"].append(f"{fname}: refused ({', '.join(parsed['problems'])})")
            continue
        for rec in parsed["labels"]:
            rec["provenance"]["file_sha256"] = sha
            out["by_key"][rec["address_key"]].append(rec)
        out["imports"].append({"file": fname, "exchange": _text(meta.get("exchange")), "por_date": iso_date(meta.get("por_date")),
                               "source_url": _http_url(meta.get("source_url")), "labels": len(parsed["labels"]),
                               "format": parsed["format"], "sha256": sha})
    out["by_key"] = dict(out["by_key"])
    out["coverage"] = _records_coverage(r for recs in out["by_key"].values() for r in recs)
    with _MEMO_LOCK:
        _POR_MEMO[key] = (stamp, out)
    return out


def _records_coverage(records: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    labelled: dict[str, set[str]] = collections.defaultdict(set)
    exchange: dict[str, set[str]] = collections.defaultdict(set)
    newest: dict[str, str] = {}
    for rec in records:
        fam, key = rec["family"], rec["address_key"]
        labelled[fam].add(key)
        if rec.get("entity_class") == "exchange":
            exchange[fam].add(key)
            if rec.get("label_date") and rec["label_date"] > newest.get(fam, ""):
                newest[fam] = rec["label_date"]
    return {fam: {"labelled_addresses": len(labelled[fam]), "exchange_addresses": len(exchange[fam]),
                  "newest_exchange_date": newest.get(fam)} for fam in labelled}


# ======================================================================================== FC3: team label file

TEAM_SCHEMA_PREFIX = "v3lum.crypto_labels/"
TEAM_LABEL_KEYS = frozenset({"address", "chain", "network", "label", "category", "abuse", "institution",
                             "confidence", "provenance", "notes", "expires"})
TEAM_INSTITUTION_KEYS = frozenset({"name", "legal_name", "kind", "country", "cnpj", "legal_contact",
                                   "graphsense_actor", "notes", "uri", "provenance"})
PERSONAL_KEYS = frozenset({
    "cpf", "rg", "owner", "owner_name", "holder", "holder_name", "customer", "customer_name", "person",
    "person_name", "name_of_person", "phone", "telefone", "celular", "email", "e-mail", "birth",
    "birthdate", "nascimento", "data_nascimento", "endereco", "postal_address", "mother", "mae",
    "pix_key", "chave_pix", "titular", "nome",
})
PROVENANCE_REQUIRED = ("source", "reference", "date")


def parse_team_labels(doc: Any, *, origin: str = "team_file", known_institutions: Mapping[str, Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """FC3: validate a team label file and turn it into label records with per-entry provenance.

    Schema ``v3lum.crypto_labels/1``: ``{schema, updated, institutions: {id: {name, legal_name, kind,
    country, cnpj, legal_contact (role contact), graphsense_actor, uri, provenance}}, labels: [{address,
    chain, network, label, category, abuse, institution, confidence (CONFIRMED|PROBABLE|POSSIBLE),
    provenance {source, reference, date, added_by}}]}``. Personal-data keys (cpf, owner_name, email,
    phone...) are dropped and reported; entries without full provenance or with an invalid address are
    skipped; an unknown confidence becomes POSSIBLE. Labels may name an institution of this file or of
    ``known_institutions`` (the bundled table). Returns ``{schema, updated, institutions, labels,
    problems}``.
    """
    out: dict[str, Any] = {"schema": None, "updated": None, "institutions": {}, "labels": [], "problems": []}
    if not isinstance(doc, dict):
        out["problems"].append("not_a_mapping")
        return out
    schema = _text(doc.get("schema"))
    out["schema"], out["updated"] = schema or None, iso_date(doc.get("updated"))
    if not schema.startswith(TEAM_SCHEMA_PREFIX):
        out["problems"].append("bad_schema")
        return out
    insts = doc.get("institutions") if isinstance(doc.get("institutions"), dict) else {}
    for iid, info in insts.items():
        if not isinstance(info, dict) or not _text(info.get("name")):
            out["problems"].append(f"bad_institution:{iid}")
            continue
        for k in info:
            if str(k).lower() in PERSONAL_KEYS:
                out["problems"].append(f"personal_field_dropped:{k}@institution:{iid}")
        kept = {k: info.get(k) for k in TEAM_INSTITUTION_KEYS if k in info and str(k).lower() not in PERSONAL_KEYS}
        kept["id"] = str(iid)
        out["institutions"][str(iid)] = kept
    raw_labels = doc.get("labels")
    if not isinstance(raw_labels, list):
        out["problems"].append("labels_not_a_list")
        raw_labels = []
    for i, entry in enumerate(raw_labels):
        if not isinstance(entry, dict):
            out["problems"].append(f"not_a_mapping@{i}")
            continue
        for k in entry:
            if str(k).lower() in PERSONAL_KEYS:
                out["problems"].append(f"personal_field_dropped:{k}@{i}")
            elif k not in TEAM_LABEL_KEYS:
                out["problems"].append(f"unknown_field:{k}@{i}")
        prov = entry.get("provenance") if isinstance(entry.get("provenance"), dict) else {}
        missing = [k for k in PROVENANCE_REQUIRED if not _text(prov.get(k))]
        if missing:
            out["problems"].append(f"missing_provenance:{'+'.join(missing)}@{i}")
            continue
        prov_date = iso_date(prov.get("date"))
        if not prov_date:
            out["problems"].append(f"bad_provenance_date@{i}")
            continue
        chain = CHAIN_ALIASES.get(_text(entry.get("chain")).lower())
        if not chain:
            out["problems"].append(f"unknown_chain:{_text(entry.get('chain'))}@{i}")
            continue
        hint = _text(entry.get("network")) or {"evm": "ETH", "tron": "TRX", "btc": "BTC"}.get(chain, chain.upper())
        norm = normalize_address(entry.get("address"), currency=hint)
        if norm is None or not norm["shape_ok"] or norm["family"] != chain or norm["checksum_ok"] is False:
            out["problems"].append(f"invalid_address@{i}")
            continue
        confidence = _text(entry.get("confidence")).upper()
        if confidence not in CONFIDENCE_RANK:
            out["problems"].append(f"bad_confidence:{confidence or '-'}@{i}")
            confidence = "POSSIBLE"
        entity, risk = classify(entry.get("category"), entry.get("abuse"))
        iid = _text(entry.get("institution")) or None
        inst = (out["institutions"].get(iid) or (known_institutions or {}).get(iid)) if iid else None
        if iid and inst is None:
            out["problems"].append(f"unknown_institution:{iid}@{i}")
        if entity in COURT_ORDER_CLASSES and inst is None:
            out["problems"].append(f"exchange_without_institution@{i}")
        out["labels"].append({
            "family": norm["family"], "address_key": norm["key"], "currency": hint.upper(), "network": hint.upper(),
            "currency_mismatch": False, "label": _text(entry.get("label")) or None,
            "category": _text(entry.get("category")).lower() or None, "abuse": _text(entry.get("abuse")).lower() or None,
            "concepts": [], "actor": _text((inst or {}).get("graphsense_actor")) or None, "entity_class": entity,
            "risk_class": risk, "confidence_id": "team", "confidence_level": None, "confidence_base": confidence,
            "confidence_inferred": False, "label_date": prov_date, "date_source": "provenance", "por_snapshot": False,
            "source": "team", "source_url": _http_url(prov.get("reference")), "institution_id": iid if inst else None,
            "institution_name": _text((inst or {}).get("name")) or None, "label_personal_hint": False,
            "provenance": {"dataset": origin, "source": _text(prov.get("source")), "reference": _text(prov.get("reference"))[:300],
                           "date": prov_date, "added_by": _text(prov.get("added_by")) or None},
        })
    return out


def _team_file_path(ctx: Any) -> Path:
    configured = _text(ctx.setting(TEAM_FILE_SETTING, "") if ctx is not None else "")
    return Path(configured).expanduser() if configured else paths.home() / TEAM_FILE_DEFAULT


def load_team_labels(ctx: Any) -> dict[str, Any]:
    """FC3: the bundled team file merged with the local one (local institutions with the same id replace
    the bundled entry, reported); ``{by_key, institutions, by_actor, problems, coverage, files}``."""
    parts: list[tuple[str, Any]] = []
    problems: list[str] = []
    try:
        parts.append(("team_file_bundled", ctx.data.bundled_json(TEAM_BUNDLED)))
    except (OSError, ValueError) as exc:
        problems.append(f"bundled team file unreadable ({str(exc)[:80]})")
    local = _team_file_path(ctx)
    local_doc = _read_local_team(local, problems)
    if local_doc is not None:
        parts.append(("team_file_local", local_doc))
    institutions: dict[str, dict[str, Any]] = {}
    by_key: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    files = []
    for origin, doc in parts:
        parsed = parse_team_labels(doc, origin=origin, known_institutions=institutions)
        problems.extend(f"{origin}: {p}" for p in parsed["problems"])
        for iid, info in parsed["institutions"].items():
            if iid in institutions:
                problems.append(f"{origin}: institution {iid} replaces the bundled entry")
            institutions[iid] = dict(info, origin=origin)
        for rec in parsed["labels"]:
            by_key[rec["address_key"]].append(rec)
        files.append({"origin": origin, "updated": parsed["updated"], "labels": len(parsed["labels"]),
                      "institutions": len(parsed["institutions"])})
    by_actor = {}
    for info in institutions.values():
        actor = _text(info.get("graphsense_actor"))
        if actor:
            by_actor.setdefault(actor, info)
    return {"by_key": dict(by_key), "institutions": institutions, "by_actor": by_actor, "problems": problems,
            "coverage": _records_coverage(r for recs in by_key.values() for r in recs), "files": files}


def _read_local_team(path: Path, problems: list[str]) -> Any:
    try:
        st = path.stat()
    except OSError:
        return None
    stamp = (st.st_size, st.st_mtime_ns)
    with _MEMO_LOCK:
        hit = _TEAM_MEMO.get(str(path))
    if hit is not None and hit[0] == stamp:
        return hit[1]
    if st.st_size > TEAM_MAX_BYTES:
        problems.append("local team file larger than 16 MB: ignored")
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        problems.append(f"local team file unreadable ({str(exc)[:80]})")
        return None
    with _MEMO_LOCK:
        _TEAM_MEMO[str(path)] = (stamp, doc)
    return doc


# ======================================================================================== FC3/FC4: merge


def _source_rank(source: Any) -> int:
    return {"team": 0, "por": 1, "graphsense": 2}.get(_text(source).split(":", 1)[0], 3)


def _identity(record: Mapping[str, Any], directory: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """Who a label says controls the address (FC3 conflict detection), as (identity, display name).

    GraphSense actor (canonical over same_as) -> actor resolved from an institution name or from the
    label of an exchange-type label -> team institution id -> PoR/team institution name. Labels without
    a resolvable identity give (None, None): shown, never a conflict or a legal-request target (e.g.
    Etherscan word-cloud token contracts).
    """
    actor = record.get("actor") or resolve_actor(record.get("institution_name"), directory)
    if not actor and record.get("entity_class") in COURT_ORDER_CLASSES and record.get("source") != "graphsense":
        actor = resolve_actor(record.get("label"), directory)
    if actor:
        canonical = (directory.get("canonical") or {}).get(actor, actor)
        actors = directory.get("actors") or {}
        info = actors.get(canonical) or actors.get(actor)
        return "actor:" + canonical, (info or {}).get("label") or record.get("institution_name") or actor
    if record.get("institution_id"):
        return "team:" + record["institution_id"], record.get("institution_name")
    if record.get("institution_name"):
        return "name:" + _norm_name(record["institution_name"]), record["institution_name"]
    return None, None


def summarize_address(records: Iterable[Mapping[str, Any]], *, as_of: Any = None, directory: Mapping[str, Any] | None = None,
                      team_institutions: Mapping[str, Mapping[str, Any]] | None = None,
                      team_by_actor: Mapping[str, Mapping[str, Any]] | None = None) -> dict[str, Any] | None:
    """FC3/FC4: merge every label of one address, keeping each source side by side.

    None without records, else ``{family, address_key, labels (effective confidence, downgraded,
    age_months), sources, entity_classes, risk_classes, stop_node, stop_class, institutions,
    court_order_target (only when exactly one institution), conflict, conflicting_identities, severity,
    severity_reasons, company_names, notes}``. No label overrides another: conflicts are reported.
    """
    directory = directory or {}
    team_institutions = team_institutions or {}
    team_by_actor = team_by_actor or {}
    actors = directory.get("actors") or {}
    labels: list[dict[str, Any]] = []
    seen: set[Any] = set()
    for rec in records:
        prov = rec.get("provenance") or {}
        dedupe = (rec.get("source"), prov.get("pack_path") or prov.get("reference") or prov.get("file"),
                  rec.get("label"), rec.get("network"))
        if dedupe in seen:
            continue
        seen.add(dedupe)
        conf, downgraded, age = effective_confidence(rec, as_of)
        labels.append(dict(rec, confidence=conf, downgraded=downgraded, age_months=age))
    if not labels:
        return None
    labels.sort(key=lambda r: (-CONFIDENCE_RANK.get(r["confidence"], 0), _source_rank(r.get("source")), _text(r.get("label"))))
    entity_classes = sorted({r["entity_class"] for r in labels if r.get("entity_class")})
    risk_classes = sorted({r["risk_class"] for r in labels if r.get("risk_class")})
    identities: dict[str, str | None] = collections.OrderedDict()
    institutions: dict[str, dict[str, Any]] = collections.OrderedDict()
    unresolved_exchange = False
    for rec in labels:
        ident, name = _identity(rec, directory)
        rec["identity"] = ident
        if not ident:
            unresolved_exchange = unresolved_exchange or rec.get("entity_class") in COURT_ORDER_CLASSES
            continue
        identities.setdefault(ident, name)
        if rec.get("entity_class") not in COURT_ORDER_CLASSES:
            continue
        actor_id = ident.split(":", 1)[1] if ident.startswith("actor:") else None
        actor_info = actors.get(actor_id) if actor_id else None
        team_info = (team_institutions.get(rec["institution_id"]) if rec.get("institution_id") else None) or (
            team_by_actor.get(actor_id) if actor_id else None)
        inst = institutions.get(ident)
        if inst is None:
            inst = institutions[ident] = {
                "identity": ident, "name": None, "legal_name": None, "actor": actor_id, "jurisdictions": [],
                "uri": None, "cnpj": None, "legal_contact": None, "entity_class": rec["entity_class"], "sources": [],
                "best_confidence": rec["confidence"], "newest_date": rec.get("label_date"),
            }
        for info in (team_info, actor_info):
            if not info:
                continue
            inst["name"] = inst["name"] or _text(info.get("name")) or _text(info.get("label")) or None
            inst["legal_name"] = inst["legal_name"] or _text(info.get("legal_name")) or None
            inst["uri"] = inst["uri"] or _text(info.get("uri")) or None
            inst["cnpj"] = inst["cnpj"] or _text(info.get("cnpj")) or None
            inst["legal_contact"] = inst["legal_contact"] or _text(info.get("legal_contact")) or None
            for j in info.get("jurisdictions") or ([info["country"]] if info.get("country") else []):
                if j and j not in inst["jurisdictions"]:
                    inst["jurisdictions"].append(j)
        inst["name"] = inst["name"] or name
        if rec.get("source") not in inst["sources"]:
            inst["sources"].append(rec.get("source"))
        if CONFIDENCE_RANK.get(rec["confidence"], 0) > CONFIDENCE_RANK.get(inst["best_confidence"], 0):
            inst["best_confidence"] = rec["confidence"]
        if rec.get("label_date") and (not inst["newest_date"] or rec["label_date"] > inst["newest_date"]):
            inst["newest_date"] = rec["label_date"]
    conflict = len(identities) > 1
    severity_reasons = [rc for rc in risk_classes if rc in SEVERITY_BY_RISK]
    severity = max((SEVERITY_BY_RISK[rc] for rc in severity_reasons), key=SEVERITY_ORDER.index) if severity_reasons else "info"
    inst_list = list(institutions.values())
    notes = []
    if conflict:
        notes.append("conflicting attributions: " + " vs ".join(_text(n) or i for i, n in identities.items())
                     + " - shown side by side, no automatic choice")
    if any(r["downgraded"] for r in labels):
        notes.append(f"proof-of-reserves snapshot older than {POR_MAX_AGE_MONTHS} months: confidence lowered one step")
    if "ofac" in risk_classes:
        dates = sorted(r["label_date"] for r in labels if r.get("risk_class") == "ofac" and r.get("label_date"))
        notes.append("sanctions-list label as of " + (dates[-1] if dates else "unknown date")
                     + ": confirm the current status with crypto_sanctions_offline (OFAC lists) before acting")
    if inst_list:
        notes.append("label = lead for a legal request to " + ", ".join(_text(i["name"]) for i in inst_list)
                     + ", not proof of who holds the funds")
    if unresolved_exchange:
        notes.append("exchange-type label without an identified institution: shown, not used as a legal-request target")
    company_names: list[str] = []
    for inst in inst_list:
        for value in (inst["name"], inst.get("legal_name")):
            if value and value not in company_names:
                company_names.append(value)
    stop_class = next((c for c in STOP_NODE_CLASSES if c in entity_classes), None) or ("sanctioned" if "ofac" in risk_classes else None)
    return {
        "family": labels[0]["family"], "address_key": labels[0]["address_key"], "labels": labels,
        "sources": sorted({r["source"] for r in labels}, key=_source_rank), "entity_classes": entity_classes,
        "risk_classes": risk_classes, "stop_node": stop_class is not None, "stop_class": stop_class,
        "institutions": inst_list, "court_order_target": inst_list[0] if len(inst_list) == 1 and not conflict else None,
        "conflict": conflict, "conflicting_identities": [n or i for i, n in identities.items()] if conflict else [],
        "severity": severity, "severity_reasons": severity_reasons, "company_names": company_names, "notes": notes,
    }


def merge_coverage(*parts: tuple[str, Mapping[str, Any]], family: str) -> dict[str, Any]:
    """FC4: the label coverage of one family across sources (counts per source; the total may count an
    address once per source)."""
    sources: dict[str, int] = {}
    labelled = 0
    exchange = 0
    newest = None
    for name, cov in parts:
        info = cov.get(family) if isinstance(cov, Mapping) else None
        if not isinstance(info, Mapping):
            continue
        sources[name] = int(info.get("exchange_addresses") or 0)
        labelled += int(info.get("labelled_addresses") or 0)
        exchange += int(info.get("exchange_addresses") or 0)
        date = info.get("newest_exchange_date")
        if date and (newest is None or str(date) > newest):
            newest = str(date)
    return {"family": family, "labelled_addresses": labelled, "exchange_addresses": exchange,
            "newest_exchange_date": newest, "sources": sources,
            "thin": family == "tron" or exchange < THIN_COVERAGE_THRESHOLD}


def no_label_note(family: str, coverage: Mapping[str, Any] | None = None) -> str:
    """FC4: wording for an address without any label; never says 'unhosted' or 'self-custodied'."""
    name = FAMILY_NAMES.get(family, family)
    note = ("No label in the local sources (GraphSense TagPacks, imported exchange proof-of-reserves files, team label file). "
            "'No label' does not mean the address is unhosted or self-custodied.")
    info = coverage or {}
    count = int(info.get("exchange_addresses") or 0)
    if family == "tron" or count < THIN_COVERAGE_THRESHOLD:
        newest = info.get("newest_exchange_date") or "n/a"
        note += f" Exchange coverage for {name} is thin: {count} exchange-labelled addresses (newest label {newest})."
    return note


def label_view(rec: Mapping[str, Any]) -> dict[str, Any]:
    """One label as shown side by side (attribute ``crypto_labels``); natural-person labels withheld."""
    label = rec.get("label")
    withheld = bool(rec.get("label_personal_hint"))
    view = {
        "source": rec.get("source"), "label": PERSON_LABEL_WITHHELD if withheld else label,
        "label_withheld": withheld or None, "category": rec.get("category"), "abuse": rec.get("abuse"),
        "entity_class": rec.get("entity_class"), "risk_class": rec.get("risk_class"),
        "confidence": rec.get("confidence"), "confidence_base": rec.get("confidence_base"),
        "confidence_id": rec.get("confidence_id"), "confidence_inferred": rec.get("confidence_inferred") or None,
        "downgraded": rec.get("downgraded") or None, "age_months": rec.get("age_months"),
        "label_date": rec.get("label_date"), "date_source": rec.get("date_source"),
        "source_url": _http_url(rec.get("source_url")), "actor": rec.get("actor"),
        "institution": rec.get("institution_name"), "currency": rec.get("currency"), "network": rec.get("network"),
        "currency_mismatch": rec.get("currency_mismatch") or None, "signed": rec.get("signed"),
        "signature_verified": rec.get("signature_verified"), "role": rec.get("role"),
        "provenance": {k: v for k, v in (rec.get("provenance") or {}).items() if v not in (None, "", [], {})},
    }
    return {k: v for k, v in view.items() if v not in (None, "", [], {})}


# ======================================================================================== module


def _selftest(ctx: Any) -> HealthResult:
    """doctor: the archive is downloaded, indexed and at most 14 days old; PyYAML present for refreshes."""
    try:
        info = ctx.data.info(GS_DATASET)
    except (ValueError, OSError):
        info = None
    if info is None or not info.present:
        why = "PyYAML missing (pip install 'v3lum[yaml]') and " if yaml_safe_load() is None else ""
        return HealthResult("dead", f"{why}GraphSense TagPacks not downloaded: run v3lum data update {GS_DATASET}")
    if not index_path(info.sha256).is_file():
        return HealthResult("dead", "GraphSense label index missing: it is rebuilt at the next lookup (needs PyYAML)")
    if info.age_hours is not None and info.age_hours > STALE_DAYS * 24:
        return HealthResult("dead", f"GraphSense TagPacks older than {STALE_DAYS} days: run v3lum data update {GS_DATASET}")
    return HealthResult("ok", "GraphSense label index present and fresh")


@register
class CryptoAddressLabels(Module):
    name = MODULE
    title = "Crypto address attribution labels (offline)"
    description = (
        "Offline attribution of a wallet address from the local GraphSense public TagPacks (weekly, MIT), analyst-imported "
        "exchange proof-of-reserves files and the team label file: labels side by side with provenance, the exchange a "
        "legal request can be sent to, and severity from ransomware/OFAC/scam labels. The address never leaves the machine."
    )
    category = "crypto"
    accepts = {T.BTC, T.ETH, T.CRYPTO}
    produces = {T.ORG}
    tags = {"offline", "free"}
    reference = "https://github.com/graphsense/graphsense-tagpacks"
    notice = (
        f"{GRAPHSENSE_ATTRIBUTION}; exchange proof-of-reserves files are imported manually by the analyst (never fetched: "
        "bot-protected pages) with exchange, date and source URL. A label is a lead for a legal request to the named "
        "institution, not proof of who holds the funds; 'no label' never means unhosted or self-custodied. Refresh the "
        f"TagPacks with v3lum data update {GS_DATASET} (needs the optional extra 'yaml')."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    provider = ""
    sources = (GS_SOURCE,)
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.1
    timeout = 180.0  # one-off index rebuild when the installed archive has no index yet
    default_enabled = True
    settings = {
        TEAM_FILE_SETTING: SettingSpec("", "Path of the local team crypto label file (schema v3lum.crypto_labels/1); empty = <V3LUM home>/crypto_labels.json"),
        POR_DIR_SETTING: SettingSpec("", "Folder of the analyst-imported proof-of-reserves files and their provenance sidecars; empty = <V3LUM home>/crypto_labels/por"),
    }

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=True, selftest=_selftest)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return normalize_address(str(entity.value)) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        hint = {T.BTC: "BTC", T.ETH: "ETH"}.get(entity.type)
        norm = normalize_address(str(entity.value), currency=hint)
        if norm is None:
            return res.mark("skipped", "not an address", reason_code="not_applicable")
        family, key = norm["family"], norm["key"]
        as_of = ctx.now().date()
        gs_index, gs_state, gs_reason = self._graphsense(ctx)
        directory = gs_index.directory() if gs_index is not None else {}
        team = load_team_labels(ctx)
        por = load_por_labels(_por_directory(ctx), directory)
        for problem in (team["problems"] + por["problems"])[:10]:
            ctx.log(f"crypto labels: {problem}", "warning")
        records: list[dict[str, Any]] = []
        if gs_index is not None:
            records += gs_index.lookup(key)
        records += por["by_key"].get(key, [])
        records += team["by_key"].get(key, [])
        records = [r for r in records if family == "unknown" or r.get("family") == family]
        gs_cov = gs_index.coverage() if gs_index is not None else {}
        coverage = merge_coverage(("graphsense", gs_cov), ("por", por["coverage"]), ("team", team["coverage"]), family=family)
        res.raw = {
            "query": {"family": family, "address_key": key, "checksum_ok": norm["checksum_ok"]},
            "sources": {"graphsense": self._gs_raw(gs_index, gs_state, gs_reason), "por": por["imports"][:50],
                        "team": team["files"], "problems": (team["problems"] + por["problems"])[:50]},
            "coverage": coverage,
        }
        if gs_state != "ok":
            status = Status.ERROR if gs_state == "error" else Status.UNAVAILABLE
            res.source_status(GS_SOURCE, status, reason_code=gs_state, reason=gs_reason)
        if family in CHAIN_NAMES:
            res.attr("chain", CHAIN_NAMES[family])
        summary = summarize_address(records, as_of=as_of, directory=directory, team_institutions=team["institutions"],
                                    team_by_actor=team["by_actor"])
        if summary is None:
            if gs_state != "ok":  # rule 5: the main source did not answer - could not verify, never 'no label'
                code = gs_state if gs_state in ("dataset", "package") else "error"
                return res.mark("unavailable" if code != "error" else "error",
                                f"could not verify: {gs_reason} (no label in the PoR imports or the team file)", reason_code=code)
            note = no_label_note(family, coverage)
            res.attr("crypto_label_status", note)
            res.attr("crypto_label_coverage", coverage)
            res.raw["match"] = False
            return res.mark("empty")
        self._emit(res, entity, summary, coverage, gs_index, gs_state)
        return res

    # ---------------------------------------------------------------------------------- internals
    @staticmethod
    def _graphsense(ctx: Any) -> tuple[LabelIndex | None, str, str]:
        """(index, state, reason): state 'ok' | 'dataset' | 'package' | 'error'."""
        try:
            info = ctx.data.info(GS_DATASET)
        except (ValueError, OSError) as exc:
            return None, "error", f"GraphSense dataset state unreadable ({str(exc)[:100]})"
        if not info.present:
            if yaml_safe_load() is None:
                return None, "package", ("GraphSense TagPacks not indexed: PyYAML missing (pip install 'v3lum[yaml]'), then "
                                         f"v3lum data update {GS_DATASET}")
            return None, "dataset", f"GraphSense TagPacks not downloaded: run v3lum data update {GS_DATASET}"
        try:
            path = Path(ctx.data.fetch(GS_DATASET, ttl=NO_REFRESH_TTL))
            index = open_index(path, info.sha256 or _sha256_file(path))
        except PackageMissing as exc:
            return None, "package", str(exc)
        except DatasetUnavailable as exc:
            return None, "dataset", str(exc)
        except (DatasetError, OSError, sqlite3.Error, ValueError) as exc:
            return None, "error", f"GraphSense label index unusable ({str(exc)[:160]})"
        if info.age_hours is not None and info.age_hours > STALE_DAYS * 24:
            ctx.log(f"GraphSense TagPacks are {info.age_hours / 24:.0f} days old: run v3lum data update {GS_DATASET}", "warning")
        return index, "ok", ""

    @staticmethod
    def _gs_raw(index: LabelIndex | None, state: str, reason: str) -> dict[str, Any]:
        if index is None:
            return {"state": state, "reason": reason}
        meta = index.meta()
        return {"state": state, "sha256": meta.get("sha256"), "commit": meta.get("commit") or None,
                "commit_date": meta.get("commit_date") or None, "built_at": meta.get("built_at"),
                "packs": meta.get("packs"), "tags": meta.get("tags"), "actorpack_lastmod": meta.get("actorpack_lastmod")}

    def _emit(self, res: ModuleResult, entity: Entity, summary: dict[str, Any], coverage: dict[str, Any],
              gs_index: LabelIndex | None, gs_state: str) -> None:
        labels = summary["labels"]
        views = [label_view(r) for r in labels]
        has_gs = any(r.get("source") == "graphsense" for r in labels)
        res.attr("crypto_labels", views[:MAX_LABELS_SHOWN])
        classes = [CLASS_WORDS.get(c, c) for c in summary["entity_classes"]] + [RISK_FINDINGS[r][2] for r in summary["risk_classes"] if r in RISK_FINDINGS]
        names = ", ".join(_text(i["name"]) for i in summary["institutions"] if i.get("name"))
        status = (f"{len(labels)} label(s) from {', '.join(summary['sources'])}: " + (", ".join(classes) or "unclassified labels")
                  + (f" ({names})" if names else "") + ("; conflicting attributions shown side by side" if summary["conflict"] else "")
                  + ("; graph expansion stops here (stop-node)" if summary["stop_node"] else ""))
        if len(labels) > MAX_LABELS_SHOWN:
            status += f"; {MAX_LABELS_SHOWN} of {len(labels)} labels shown"
        res.attr("crypto_label_status", status)
        res.attr("crypto_label_coverage", coverage)
        if summary["stop_class"]:
            res.attr("stop_node_hint", summary["stop_class"])
        target = summary["court_order_target"]
        if target:
            res.attr("court_order_target", {
                **{k: v for k, v in target.items() if k != "identity" and v not in (None, "", [])},
                "wording": f"label = lead for a legal request to {target['name']}, not proof of who holds the funds",
            })
        if summary["conflict"]:
            res.attr("label_conflict", summary["conflicting_identities"])
        if has_gs:
            res.attr("data_attribution", GRAPHSENSE_ATTRIBUTION)
        self._risk_findings(res, summary)
        self._institution_finding(res, summary)
        self._class_finding(res, summary)
        for inst in summary["institutions"]:
            conf = str(inst.get("best_confidence") or "POSSIBLE").lower()
            for value in (inst.get("name"), inst.get("legal_name")):
                if value:
                    res.pivot(T.ORG, value, "label_attributed_to", confidence=conf, expand=False,
                              note="named by a wallet label: a lead for a legal request, not proof of ownership")
            page = POR_PAGES.get(_text(inst.get("actor")))
            if page:
                res.link(*page)
        urls = []
        for rec in labels:
            prov = rec.get("provenance") or {}
            url = _http_url(prov.get("pack_url"))
            if url and url not in urls:
                urls.append(url)
        for url in urls[:5]:
            res.link("GraphSense TagPack (label source)", url)
        res.raw["match"] = True
        res.raw["labels"] = views[:RAW_MAX_LABELS]
        res.raw["notes"] = summary["notes"]

    @staticmethod
    def _criterion(recs: list[Mapping[str, Any]]) -> str:
        sources = sorted({_text(r.get("source")) for r in recs}, key=_source_rank)
        return f"exact address match in local label source(s) {', '.join(sources)} ({len(recs)} label(s))"

    @staticmethod
    def _best(recs: list[Mapping[str, Any]]) -> str:
        return max((r["confidence"] for r in recs), key=lambda c: CONFIDENCE_RANK.get(c, 0)).lower()

    @staticmethod
    def _newest(recs: list[Mapping[str, Any]]) -> str | None:
        dates = sorted(r["label_date"] for r in recs if r.get("label_date"))
        return f"{dates[-1]}T00:00:00+00:00" if dates else None

    def _risk_findings(self, res: ModuleResult, summary: Mapping[str, Any]) -> None:
        for risk in summary["risk_classes"]:
            if risk not in RISK_FINDINGS:
                continue
            title, tags, words = RISK_FINDINGS[risk]
            recs = [r for r in summary["labels"] if r.get("risk_class") == risk]
            shown = "; ".join(
                f"{label_view(r).get('label') or '(no label text)'} [{r.get('source')}, {r['confidence']}, {r.get('label_date') or 'undated'}]"
                for r in recs[:5])
            extra = ""
            if risk == "ofac":
                extra = (" The label is dated: confirm the current sanctions status with crypto_sanctions_offline (OFAC lists) "
                         "before acting; a label is not a sanctions determination.")
            res.finding(
                title, SEVERITY_BY_RISK[risk],
                f"{len(recs)} {words}(s) for this exact address: {shown}.{extra}",
                confidence=self._best(recs),
                criterion=self._criterion(recs) + f": {words} raises severity to {SEVERITY_BY_RISK[risk]} (P358 cond 4)",
                data={"risk_class": risk, "labels": [label_view(r) for r in recs[:20]]},
                tags=tags,
                references=[u for u in {_http_url(r.get("source_url")) for r in recs} if u][:5],
                source=GS_SOURCE if any(r.get("source") == "graphsense" for r in recs) else "",
                observed_last=self._newest(recs),
                key=risk,
            )

    def _institution_finding(self, res: ModuleResult, summary: Mapping[str, Any]) -> None:
        insts = summary["institutions"]
        if not insts:
            return
        recs = [r for r in summary["labels"] if r.get("entity_class") in COURT_ORDER_CLASSES and r.get("identity")]
        if len(insts) == 1 and not summary["conflict"]:
            inst = insts[0]
            juris = ", ".join(inst.get("jurisdictions") or []) or "jurisdiction unknown"
            legal = f" ({inst['legal_name']})" if inst.get("legal_name") else ""
            desc = (f"Labels attribute this address to {inst['name']}{legal}, {juris}, from {', '.join(inst['sources'])} "
                    f"(best confidence {inst['best_confidence']}, newest label {inst.get('newest_date') or 'undated'}). "
                    f"Label = lead for a legal request to {inst['name']}, not proof of who holds the funds.")
        elif len(insts) > 1:
            desc = ("Labels name several institutions for this address: "
                    + " vs ".join(f"{i['name']} ({', '.join(i['sources'])}, {i['best_confidence']})" for i in insts)
                    + ". Shown side by side: no legal-request target is picked automatically.")
        else:
            inst = insts[0]
            others = [n for n in summary["conflicting_identities"] if n != inst["name"]]
            desc = (f"Labels attribute this address to {inst['name']} ({', '.join(inst['sources'])}, {inst['best_confidence']}), "
                    f"but other labels name {', '.join(others) or 'another actor'}. Shown side by side: no legal-request "
                    "target is picked automatically.")
        res.finding(
            "Address attributed to an exchange or custodial service (legal-request lead)", "info", desc,
            confidence=self._best(recs) if recs else "possible",
            criterion=self._criterion(recs or summary["labels"]) + ": exchange/custodial label naming an institution (P358 cond 4)",
            data={"institutions": [{k: v for k, v in i.items() if k != "identity" and v not in (None, "", [])} for i in insts],
                  "conflict": summary["conflict"]},
            tags=["conflict"] if summary["conflict"] else [],
            source=GS_SOURCE if any(r.get("source") == "graphsense" for r in recs) else "",
            observed_last=self._newest(recs),
            key="institution",
        )

    def _class_finding(self, res: ModuleResult, summary: Mapping[str, Any]) -> None:
        if summary["conflict"] and not summary["institutions"]:
            res.finding(
                "Conflicting attribution labels (shown side by side)", "info",
                "Labels of this address name different actors: " + " vs ".join(summary["conflicting_identities"])
                + ". No label overrides another.",
                confidence="possible", criterion=self._criterion(summary["labels"]), tags=["conflict"],
                data={"identities": summary["conflicting_identities"]}, key="conflict",
            )
        other = [c for c in summary["entity_classes"] if c in STOP_NODE_CLASSES and c not in COURT_ORDER_CLASSES]
        if not other:
            return
        recs = [r for r in summary["labels"] if r.get("entity_class") in other]
        res.finding(
            f"Address labelled as {', '.join(CLASS_WORDS.get(c, c) for c in other)} (stop-node)", "info",
            f"{len(recs)} label(s): " + "; ".join(f"{label_view(r).get('label') or '(no label text)'} [{r.get('source')}]" for r in recs[:5])
            + ". Service/hub addresses end automatic graph expansion (P213).",
            confidence=self._best(recs), criterion=self._criterion(recs),
            data={"classes": other, "labels": [label_view(r) for r in recs[:20]]},
            source=GS_SOURCE if any(r.get("source") == "graphsense" for r in recs) else "",
            observed_last=self._newest(recs), key="service",
        )


__all__ = [
    "ARCHIVE_LIMITS",
    "CONFIDENCE_LEVELS",
    "CryptoAddressLabels",
    "GS_DATASET",
    "GS_SOURCE",
    "LabelIndex",
    "build_index",
    "check_yaml_loader",
    "classify",
    "effective_confidence",
    "import_por_file",
    "load_por_labels",
    "load_team_labels",
    "no_label_note",
    "normalize_address",
    "open_index",
    "parse_actorpack",
    "parse_por_csv",
    "parse_tagpack",
    "parse_team_labels",
    "por_input_problem",
    "read_archive",
    "summarize_address",
    "tagpack_archive_members",
    "validate_archive",
    "yaml_text_problem",
]
