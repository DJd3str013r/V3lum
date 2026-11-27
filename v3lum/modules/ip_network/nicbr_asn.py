"""nicbr_asn: NIC.br ASN block list - IP/ASN -> owner CNPJ and CNPJ -> its networks (P038).

Batch p1-G02-1. Offline matching (disclosure 'none', allowed at TLP:RED): the investigated value never
leaves the machine; only the dataset manager downloads the public list.

* **Dataset** (cond 1): https://ftp.registro.br/pub/numeracao/origin/nicbr-asn-blk-latest.txt
  (``ASN|OrgName|OrgID|prefix|prefix...``, UTF-8 per the 00README), daily TTL. A download is
  validated (size, HTML/challenge pages, >= 5,000 records, >= 95% valid data lines) before it
  replaces the index; a failed refresh keeps the last good copy. The tolerant line parser accepts a
  BOM, CRLF, cp1252 bytes, comment lines and garbage. A missing dataset gives UNAVAILABLE ('could not
  verify'), never 'no Brazilian owner'.
* **Shared index** (cond 2): prefixes load into the shared IP-range index
  (:class:`v3lum.modules.ip_network.cloud_ranges.RangeIndex`, P034).
* **Pivots** (cond 3-5): IP/ASN -> owner CNPJ (relation registrant); CNPJ -> its ASNs and prefixes
  (relation owns_network: candidate own netblocks for ``org seed``, analyst-confirmed, passive
  modules only, never an ACTIVE scope), at most 50 pivots, expand=False beyond the engine's per-type
  expansion cap. When the owner is an ISP/hosting/telecom provider (bundled list
  ``v3lum/data/nicbr_asn/br_network_providers.json`` or owner-name keywords; the PeeringDB network
  type arrives with P033 asn_context) the relation from an IP is ``network_provider`` and no
  CNPJ/QSA pivot is created; a provider ASN reached as a pivot does not expand its CNPJ.
* **Rule 4** (cond 6): owner ids are CNPJs; a value that is not a valid CNPJ is discarded and never
  pivoted; an 11-digit (CPF-shaped) id also drops the owner name (an individual). CPF-like numbers
  inside owner names are masked. LGPD minimisation beyond the conditions: a registrant CNPJ whose
  owner name looks like an individual entrepreneur (MEI) is listed but not auto-expanded.
"""

from __future__ import annotations

import ipaddress
import re
import threading
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NamedTuple

from v3lum.core import validators
from v3lum.core.datasets import DataStore, DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.ip_network.cloud_ranges import RangeIndex, as_ip, as_network, is_public_address

DATASET = "nicbr_asn_blk.txt"
DATASET_URL = "https://ftp.registro.br/pub/numeracao/origin/nicbr-asn-blk-latest.txt"
SOURCE = "registrobr.asn_blocks"
PROVIDERS_FILE = "nicbr_asn/br_network_providers.json"
#: Validation (cond 1): ~35% of the 866,167 bytes / 9,153 lines observed on 2026-11-26.
MIN_BYTES = 300_000
MIN_RECORDS = 5000
MIN_VALID_RATIO = 0.95
#: cond 3: at most 50 pivots for CNPJ -> ASNs/prefixes and ASN -> prefixes.
PIVOT_CAP = 50
#: fallback of the engine's per-type expansion cap (v3lum.core.engine.EXPAND_CAP)
_EXPAND_CAP_FALLBACK = {T.ASN: 3, T.CIDR: 2}
#: blocks broader than this are corruption, never a real assignment (the list's shortest are /13 and /28)
MIN_PREFIXLEN = {4: 8, 6: 19}
CANDIDATE_NOTE = "candidate own netblock (org seed, analyst-confirmed, passive modules only): never joins an ACTIVE scope automatically"
PROVIDER_NOTE = "ISP/hosting/telecom customer space: the provider is not the user of the address, no company pivot (P038)"

#: Owner-name keywords of network providers (accent-folded, upper case). Conservative by design: a
#: false 'provider' only loses a pivot; a false 'registrant' would pivot a phishing IP into an ISP's
#: company and partners.
PROVIDER_KEYWORDS: tuple[str, ...] = (
    "TELECOM", "TELECOMUNICAC", "INTERNET", "PROVEDOR", "FIBRA", "FIBER", "WIRELESS", "COMUNICAC", "TELEFON", "MULTIMIDIA",
    "DATACENTER", "DATA CENTER", "HOSTING", "HOSPEDAGEM", "CLOUD", "BANDA LARGA", "CONECT", "CONNECT", "NETWORK", "WIFI",
    "WI-FI",
)
_PROVIDER_TOKENS = re.compile(r"\b(NET|NETS|LINK|TELE)\b")
#: PeeringDB network types of network providers (used once P033 asn_context supplies them).
PEERINGDB_PROVIDER_TYPES = frozenset({"nsp", "cable/dsl/isp", "content", "network services", "route server"})

_ASN_FIELD = re.compile(r"^AS(\d{1,10})$", re.I)
_CPF_IN_TEXT = re.compile(r"(?<!\d)(?:\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11})(?!\d)")
CPF_MASK = "***.***.***-**"
#: MEI legal names start with the CNPJ root ('12.345.678 NAME') or end with MEI: an individual.
_MEI_NAME = re.compile(r"^\s*\d{2}\.?\d{3}\.?\d{3}\s+\S|\bMEI\b")


def fold(text: Any) -> str:
    """Upper-case, accent-free form used for keyword matching."""
    if not isinstance(text, str):
        return ""
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c)).upper()


def format_cnpj(value: str) -> str:
    """'00000000000191' -> '00.000.000/0001-91' (also for alphanumeric CNPJs)."""
    c = re.sub(r"[^0-9A-Za-z]", "", value or "").upper()
    return f"{c[:2]}.{c[2:5]}.{c[5:8]}/{c[8:12]}-{c[12:]}" if len(c) == 14 else value


def mask_cpf_like(text: str) -> str:
    """Mask CPF-shaped numbers inside owner names (individual entrepreneurs) before they are indexed."""
    return _CPF_IN_TEXT.sub(CPF_MASK, text) if isinstance(text, str) else text


def looks_individual(owner: str) -> bool:
    """True when an owner name looks like an individual entrepreneur (MEI) or carried a CPF."""
    return bool(owner) and (CPF_MASK in owner or bool(_MEI_NAME.search(fold(owner))))


# ======================================================================================
# Parser (cond 1, 6)
# ======================================================================================


class NicbrRecord(NamedTuple):
    asn: int
    owner: str  # '' when dropped (CPF-identified individual)
    cnpj: str  # 14 characters, '' when missing or discarded
    owner_id_status: str  # cnpj | discarded_cpf | discarded_invalid | missing
    prefixes: tuple[str, ...]

    @property
    def cnpj_root(self) -> str:
        return self.cnpj[:8] if self.cnpj else ""


@dataclass
class ParsedList:
    records: list[NicbrRecord] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    error: str = ""


_HTML_START = re.compile(r"^\s*(?:<!doctype\s+html|<html\b|<head\b|<body\b|<\?xml\b|<title\b)", re.I)


def _decode(raw: Any, stats: dict[str, Any]) -> str | None:
    if isinstance(raw, Path):
        try:
            raw = raw.read_bytes()
        except OSError:
            return None
    if isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
        stats["bom"] = data.startswith(b"\xef\xbb\xbf")
        try:
            text = data.decode("utf-8-sig")
            stats["encoding"] = "utf-8"
        except UnicodeDecodeError:
            text = data.decode("cp1252", errors="replace")  # tolerated: a mis-encoded copy still parses
            stats["encoding"] = "cp1252"
        return text
    if isinstance(raw, str):
        stats["bom"] = raw.startswith("﻿")
        stats["encoding"] = "str"
        return raw.lstrip("﻿")
    return None


def parse_nicbr_asn_blk(raw: Any) -> ParsedList:
    """Tolerant parser of 'ASN|OrgName|OrgID|prefix|prefix...' lines.

    Comment lines (#, ;, %, //), blanks, garbage, malformed ASNs, invalid prefixes and blocks broader
    than /8 (IPv4) or /19 (IPv6) are skipped and counted. Owner ids: a valid CNPJ is kept; an
    11-digit (CPF-shaped) id is discarded together with the owner name; any other invalid id is
    discarded and the organisation name kept. Discarded ids are never matched or pivoted (rule 4)."""
    stats: dict[str, Any] = {
        "encoding": None, "bom": False, "lines": 0, "data_lines": 0, "comments": 0, "blank": 0, "malformed_lines": 0,
        "records": 0, "invalid_prefixes": 0, "too_broad": 0, "discarded_cpf": 0, "discarded_invalid": 0, "masked_names": 0,
    }
    out = ParsedList(stats=stats)
    text = _decode(raw, stats)
    if text is None:
        out.error = "NIC.br ASN list: unsupported body"
        return out
    if _HTML_START.match(text[:1024]):
        out.error = "NIC.br ASN list: an HTML page came back instead of the list"
        return out
    seen: set[int] = set()
    for line in text.splitlines():
        stats["lines"] += 1
        s = line.strip()
        if not s:
            stats["blank"] += 1
            continue
        if s[0] in "#;%" or s.startswith("//"):
            stats["comments"] += 1
            continue
        stats["data_lines"] += 1
        fields = [f.strip() for f in s.split("|")]
        m = _ASN_FIELD.match(fields[0]) if fields else None
        asn = int(m.group(1)) if m else 0
        if len(fields) < 3 or not m or not 0 < asn < 4294967296:
            stats["malformed_lines"] += 1
            continue
        owner, owner_id = fields[1], fields[2]
        cnpj, status = "", "missing"
        if owner_id:
            compact = re.sub(r"[^0-9A-Za-z]", "", owner_id).upper()
            digits = re.sub(r"\D", "", owner_id)
            if len(compact) == 14 and validators.cnpj_valid(compact):
                cnpj, status = compact, "cnpj"
            elif len(digits) == 11 and len(compact) == 11:
                status, owner = "discarded_cpf", ""  # an individual: neither the id nor the name is kept
                stats["discarded_cpf"] += 1
            else:
                status = "discarded_invalid"
                stats["discarded_invalid"] += 1
        if owner:
            masked = mask_cpf_like(owner)
            if masked != owner:
                stats["masked_names"] += 1
            owner = masked
        prefixes: list[str] = []
        for raw_prefix in fields[3:]:
            if not raw_prefix:
                continue
            net = as_network(raw_prefix)
            if net is None:
                stats["invalid_prefixes"] += 1
                continue
            if net.prefixlen < MIN_PREFIXLEN[net.version]:
                stats["too_broad"] += 1
                continue
            text_prefix = str(net)
            if text_prefix not in prefixes:
                prefixes.append(text_prefix)
        if asn in seen:  # one line per ASN (00README): a duplicate keeps the first
            stats["malformed_lines"] += 1
            continue
        seen.add(asn)
        out.records.append(NicbrRecord(asn, owner, cnpj, status, tuple(prefixes)))
    stats["records"] = len(out.records)
    return out


def validate_list(parsed: ParsedList, *, min_records: int = MIN_RECORDS, min_valid_ratio: float = MIN_VALID_RATIO) -> str:
    """Why a parsed download must not replace the index ('' = acceptable)."""
    if parsed.error:
        return parsed.error
    stats = parsed.stats
    if len(parsed.records) < min_records:
        return f"NIC.br ASN list: too few records ({len(parsed.records)} < {min_records})"
    data_lines = int(stats.get("data_lines") or 0)
    if data_lines:
        good = data_lines - int(stats.get("malformed_lines") or 0)
        if good / data_lines < min_valid_ratio:
            return f"NIC.br ASN list: too many malformed lines ({stats.get('malformed_lines')} of {data_lines})"
    return ""


def _validate_download(path: Path) -> bool:
    problem = validate_list(parse_nicbr_asn_blk(Path(path)))
    if problem:
        raise ValueError(problem)
    return True


register_dataset(
    DATASET, DATASET_URL, ttl=86400, description="nicbr_asn: NIC.br ASN block list (AS -> owner -> CNPJ -> prefixes)",
    licence="NIC.br public registry data (registro.br terms of use; runtime download, never redistributed)", terms_class="open",
    attribution="NIC.br ASN block list (https://ftp.registro.br/pub/numeracao/origin/), Nucleo de Informacao e Coordenacao do Ponto BR",
    source=SOURCE, validate=_validate_download, min_bytes=MIN_BYTES, expect="lines", essential=True,
)


# ======================================================================================
# Index (cond 2) and owner classification (cond 4)
# ======================================================================================


@dataclass(frozen=True)
class NicbrIndex:
    by_asn: dict[int, NicbrRecord]
    by_cnpj: dict[str, tuple[NicbrRecord, ...]]
    by_root: dict[str, tuple[NicbrRecord, ...]]
    ranges: RangeIndex  # payload: (prefix, record)
    stats: dict[str, Any]


def build_index(parsed: ParsedList) -> NicbrIndex:
    by_asn: dict[int, NicbrRecord] = {}
    by_cnpj: dict[str, list[NicbrRecord]] = {}
    by_root: dict[str, list[NicbrRecord]] = {}
    for rec in parsed.records:
        by_asn.setdefault(rec.asn, rec)
        if rec.cnpj:
            by_cnpj.setdefault(rec.cnpj, []).append(rec)
            by_root.setdefault(rec.cnpj_root, []).append(rec)
    ranges = RangeIndex((prefix, (prefix, rec)) for rec in parsed.records for prefix in rec.prefixes)
    return NicbrIndex(by_asn, {k: tuple(v) for k, v in by_cnpj.items()}, {k: tuple(v) for k, v in by_root.items()}, ranges, dict(parsed.stats))


@dataclass(frozen=True)
class ProviderList:
    asns: frozenset[int] = frozenset()
    cnpj_roots: frozenset[str] = frozenset()


def provider_list(doc: Any) -> ProviderList:
    """The bundled provider list (schema v3lum.nicbr_providers/1) as lookup sets; a malformed file
    gives an empty list (the keyword rule still applies)."""
    asns: set[int] = set()
    roots: set[str] = set()
    for item in doc.get("providers", []) if isinstance(doc, dict) else []:
        if not isinstance(item, dict):
            continue
        for asn in item.get("asns", []) if isinstance(item.get("asns"), list) else []:
            if isinstance(asn, int) and not isinstance(asn, bool):
                asns.add(asn)
        for root in item.get("cnpj_roots", []) if isinstance(item.get("cnpj_roots"), list) else []:
            if isinstance(root, str) and re.fullmatch(r"[0-9A-Z]{8}", root):
                roots.add(root)
    return ProviderList(frozenset(asns), frozenset(roots))


def classify_owner(rec: NicbrRecord, providers: ProviderList, peeringdb_type: str = "") -> tuple[str, str]:
    """('network_provider' | 'registrant', basis). Order: bundled list (ASN, then CNPJ root), the
    PeeringDB network type (when P033 supplies it), owner-name keywords; otherwise registrant."""
    if rec.asn in providers.asns:
        return "network_provider", "bundled provider list (ASN)"
    if rec.cnpj_root and rec.cnpj_root in providers.cnpj_roots:
        return "network_provider", "bundled provider list (CNPJ root)"
    if peeringdb_type and peeringdb_type.strip().lower() in PEERINGDB_PROVIDER_TYPES:
        return "network_provider", f"PeeringDB network type {peeringdb_type.strip()}"
    name = fold(rec.owner)
    for keyword in PROVIDER_KEYWORDS:
        if keyword in name:
            return "network_provider", f"owner-name keyword {keyword}"
    token = _PROVIDER_TOKENS.search(name)
    if token:
        return "network_provider", f"owner-name keyword {token.group(1)}"
    return "registrant", "default (not a known network provider)"


_LOCK = threading.Lock()
_INDEXES: dict[str, NicbrIndex] = {}


def index_for(sha: str, path: Path) -> NicbrIndex:
    """The index of one dataset version (parsed once per sha256). Raises DatasetError when the local
    copy no longer parses (a corrupted file is never read as 'no Brazilian owner')."""
    with _LOCK:
        hit = _INDEXES.get(sha)
        if hit is not None:
            return hit
    parsed = parse_nicbr_asn_blk(Path(path))
    if parsed.error or not parsed.records:
        raise DatasetError(f"dataset {DATASET}: the local copy does not parse ({parsed.error or 'no records'}): run v3lum data update {DATASET}", name=DATASET)
    built = build_index(parsed)
    with _LOCK:
        _INDEXES.clear()  # one version at a time
        _INDEXES[sha] = built
    return built


def _expand_cap(etype: T) -> int:
    """The engine's per-parent expansion cap for a type ('expand=False beyond EXPAND_CAP', cond 3)."""
    try:
        from v3lum.core import engine as _engine

        caps = getattr(_engine, "EXPAND_CAP", {}) or {}
        return int(caps.get(etype, getattr(_engine, "DEFAULT_CAP", 5)))
    except Exception:  # noqa: BLE001 - a core refactor must not break the module: documented fallback
        return _EXPAND_CAP_FALLBACK.get(etype, 5)


def _sort_prefixes(prefixes: Iterable[str]) -> list[str]:
    def key(cidr: str) -> tuple[int, int, int]:
        net = ipaddress.ip_network(cidr, strict=False)
        return (net.version, net.prefixlen, int(net.network_address))

    return sorted(set(prefixes), key=key)


def _counts(prefixes: Iterable[str], pivoted: int) -> dict[str, Any]:
    items = list(prefixes)
    v4 = sum(1 for p in items if ":" not in p)
    return {"total": len(items), "ipv4": v4, "ipv6": len(items) - v4, "pivoted": pivoted, "capped": len(items) > pivoted}


# ======================================================================================
# The module
# ======================================================================================


@register
class NicbrAsn(Module):
    name = "nicbr_asn"
    title = "NIC.br ASN block list"
    description = (
        "Brazilian network ownership from the NIC.br ASN block list, matched offline: IP/ASN -> owner CNPJ and "
        "CNPJ -> its ASNs and prefixes (ISP/telecom customer space never pivots into the provider's company)."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6, T.CIDR, T.ASN, T.CNPJ}
    produces = {T.CNPJ, T.CIDR, T.ASN}
    tags = {"offline", "free", "brazil"}
    reference = "https://ftp.registro.br/pub/numeracao/origin/00README"
    notice = (
        "Public NIC.br registry data matched offline. Owner ids that are not valid CNPJs (e.g. CPFs) are discarded and "
        "never pivoted; ISP/hosting/telecom customer space never pivots into the provider's company and partners."
    )
    # ---- contract v2 declarations --------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (SOURCE,)
    expected_latency = 0.1
    timeout = 90.0  # a first run may download the list (< 1 MB) before matching
    max_pivots = 60
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type in (T.IPV4, T.IPV6):
            return is_public_address(entity.value)
        if entity.type is T.CIDR:
            net = as_network(entity.value)
            return net is not None and is_public_address(net.network_address)
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if SOURCE not in ctx.allowed_sources:
            return res.mark(Status.SKIPPED, "the NIC.br ASN list is not allowed in this run", reason_code="policy")
        try:
            path = Path(ctx.data.fetch(DATASET, headers={"Accept": "text/plain"}))
            info = ctx.data.info(DATASET)
            index = index_for(str(info.sha256 or ""), path)
        except DatasetUnavailable as exc:
            code = exc.reason_code if exc.reason_code in ("dataset", "offline") else "dataset"
            return res.mark(Status.UNAVAILABLE, f"NIC.br ASN list not available: could not verify ({exc})", reason_code=code)
        except DatasetError as exc:
            return res.mark(Status.UNAVAILABLE, f"NIC.br ASN list could not be downloaded or validated: could not verify ({exc})", reason_code="dataset")
        age = None if info.age_hours is None else round(float(info.age_hours) / 24.0, 2)
        if age is not None:
            res.attr("dataset_age_days", {DATASET: age})
        try:
            providers = provider_list(ctx.data.bundled_json(PROVIDERS_FILE))
        except (OSError, ValueError):
            providers = ProviderList()
        if entity.type in (T.IPV4, T.IPV6, T.CIDR):
            return self._network(res, entity, ctx, index, providers)
        if entity.type is T.ASN:
            return self._asn(res, entity, ctx, index, providers)
        return self._cnpj(res, entity, index)

    # ---- IP / CIDR -> owner (cond 1-4) ----------------------------------------------------
    def _network(self, res: ModuleResult, entity: Entity, ctx: Any, index: NicbrIndex, providers: ProviderList) -> ModuleResult:
        if entity.type is T.CIDR:
            chain = index.ranges.lookup_cidr(entity.value)
        else:
            ip = as_ip(entity.value)
            chain = index.ranges.lookup(ip) if ip is not None else ()
        if not chain:
            return res.mark(Status.EMPTY)  # the list answered: not in a NIC.br block (documented absence)
        prefix, rec = chain[0]
        kind, basis = classify_owner(rec, providers)
        provider = kind == "network_provider"
        res.attr("asn", f"AS{rec.asn}")
        res.attr("prefix", prefix)
        res.attr("as_org", rec.owner)
        res.attr("owner_kind", kind)
        res.attr("owner_basis", basis)
        if rec.cnpj:
            res.attr("owner_cnpj", format_cnpj(rec.cnpj))
        if provider:
            res.attr("isp", rec.owner)
            res.pivot(T.ASN, f"AS{rec.asn}", "network_provider", confidence="confirmed", expand=False, note=PROVIDER_NOTE)
            res.pivot(T.CIDR, prefix, "in_network", confidence="confirmed", expand=False, note=PROVIDER_NOTE)
            return res
        res.pivot(T.ASN, f"AS{rec.asn}", "belongs_to_asn", confidence="confirmed", expand=bool(ctx.is_seed))
        res.pivot(T.CIDR, prefix, "in_network", confidence="confirmed", expand=False)
        if rec.cnpj:
            self._registrant(res, rec)
        return res

    @staticmethod
    def _registrant(res: ModuleResult, rec: NicbrRecord, *, expand: bool = True, note: str = "") -> None:
        if looks_individual(rec.owner):
            expand, note = False, "owner looks like an individual entrepreneur (MEI): analyst selection required (LGPD minimisation)"
        res.pivot(T.CNPJ, rec.cnpj, "registrant", confidence="confirmed", expand=expand, note=note)

    # ---- ASN -> owner CNPJ + its prefixes (cond 3-4) ------------------------------------------
    def _asn(self, res: ModuleResult, entity: Entity, ctx: Any, index: NicbrIndex, providers: ProviderList) -> ModuleResult:
        digits = re.sub(r"\D", "", entity.value)
        rec = index.by_asn.get(int(digits)) if digits else None
        if rec is None:
            return res.mark(Status.EMPTY)
        kind, basis = classify_owner(rec, providers)
        provider = kind == "network_provider"
        res.attr("as_org", rec.owner)
        res.attr("owner_kind", kind)
        res.attr("owner_basis", basis)
        if rec.cnpj:
            res.attr("owner_cnpj", format_cnpj(rec.cnpj))
            if provider and not ctx.is_seed:
                # IP -> provider ASN -> CNPJ -> QSA is the path cond 4 forbids: list the CNPJ, never expand it
                self._registrant(res, rec, expand=False, note="ISP/telecom ASN reached as a pivot: company not expanded (P038)")
            else:
                self._registrant(res, rec)
        prefixes = _sort_prefixes(rec.prefixes)
        listed = prefixes[:PIVOT_CAP]
        cap = _expand_cap(T.CIDR)
        for i, prefix in enumerate(listed):
            expand = ctx.is_seed and not provider and i < cap
            res.pivot(T.CIDR, prefix, "announces", confidence="confirmed", expand=expand,
                      note=PROVIDER_NOTE if provider else ("" if expand else "listed: analyst selection"))
        res.attr("registered_prefix_counts", _counts(prefixes, len(listed)))
        return res

    # ---- CNPJ -> its ASNs and prefixes (cond 3, 5, 6) -----------------------------------------
    def _cnpj(self, res: ModuleResult, entity: Entity, index: NicbrIndex) -> ModuleResult:
        value = re.sub(r"[^0-9A-Za-z]", "", entity.value).upper()
        if not validators.cnpj_valid(value):
            return res.mark(Status.SKIPPED, "not a valid CNPJ: never matched or pivoted", reason_code="not_applicable")
        records = index.by_cnpj.get(value)
        match = "exact"
        if not records:
            records, match = index.by_root.get(value[:8]), "cnpj_root"
        if not records:
            return res.mark(Status.EMPTY)
        asns = sorted({r.asn for r in records})
        prefixes = _sort_prefixes(p for r in records for p in r.prefixes)
        items = [(T.ASN, f"AS{a}") for a in asns] + [(T.CIDR, p) for p in prefixes]
        listed = items[:PIVOT_CAP]
        confidence = "confirmed" if match == "exact" else "probable"
        expanded: dict[T, int] = {}
        for etype, value_ in listed:
            n = expanded.get(etype, 0)
            expand = n < _expand_cap(etype)
            expanded[etype] = n + 1
            res.pivot(etype, value_, "owns_network", confidence=confidence, expand=expand, note=CANDIDATE_NOTE)
        owner = next((r.owner for r in records if r.owner), "")
        res.attr("org", owner)
        res.attr("owned_networks", {
            "match": match, "owner": owner, "asns": [f"AS{a}" for a in asns], "prefixes": prefixes[: max(0, PIVOT_CAP - len(asns))],
            "total_asns": len(asns), "total_prefixes": len(prefixes), "capped": len(items) > PIVOT_CAP,
            "candidate_own_netblocks": True, "scope_eligible": False,
        })
        res.finding(
            "Networks registered to the company (NIC.br)",
            "info",
            f"{len(asns)} ASN(s) and {len(prefixes)} prefix(es) in the NIC.br ASN block list ({'exact CNPJ' if match == 'exact' else 'same CNPJ root'} match). "
            "Candidate own netblocks for `org seed` (analyst confirmation): passive modules only, never an ACTIVE scope.",
            confidence=confidence,
            data={"match": match, "total_asns": len(asns), "total_prefixes": len(prefixes), "pivoted": len(listed)},
            tags=["infrastructure"],
            source=SOURCE,
        )
        return res


def local_lookup(value: str) -> dict[str, Any] | None:
    """Owner record of an IP from the local copy only (no download): {asn, prefix, owner, cnpj,
    owner_kind} or None. A helper for core consumers (org seed, doctor)."""
    store = DataStore(None)
    try:
        path = store.fetch(DATASET)
        index = index_for(store.info(DATASET).sha256, path)
    except (DatasetError, OSError):
        return None
    chain = index.ranges.lookup(value)
    if not chain:
        return None
    prefix, rec = chain[0]
    providers = provider_list(DataStore.bundled_json(PROVIDERS_FILE)) if DataStore.bundled_exists(PROVIDERS_FILE) else ProviderList()
    kind, _basis = classify_owner(rec, providers)
    return {"asn": rec.asn, "prefix": prefix, "owner": rec.owner, "cnpj": rec.cnpj, "owner_kind": kind}
