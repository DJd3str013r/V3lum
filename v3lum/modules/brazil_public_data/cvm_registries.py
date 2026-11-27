"""Shared CVM cadastral loader and registry-copy helpers (P360 FC1, FC2, FC9; shared with P361 and P244).

Batch p1-G10-3. No Module class lives in this file: ``bcb_authorized_institutions`` (P360) and the
due-diligence module ``cvm_person_registry`` use it, and ``cnpj_name_resolver`` (P361) and
``br_cnpj_risk_lists`` (P244) are meant to import it instead of registering their own copies
("one CVM loader shared with P244/P361", P360 FC1).

* **Datasets** (FC1): the CVM cadastral registries are whole files downloaded by the dataset manager
  (``v3lum data update``), never during a scan: every registration is ``large=True`` (served from the
  local copy at once, never fetched mid-scan) and every reader here passes a TTL that serves the local
  copy whatever its age (:func:`local_path`). The zip archives hold several CSVs; only the member a
  registry needs is extracted (``member=``), so the people lists (``*_resp.csv``, ``*_diretor.csv``,
  ``*_socios.csv``, ``*_adm_resp.csv``) are never stored (rule 4, LGPD minimisation).
* **Validation** (FC2): :func:`copy_validator` rejects a fresh copy below the absolute floors or more
  than 10% smaller / 25% larger than the previous copy; the previous copy then stays installed. The
  relative check is skipped once the installed copy is older than ``ROW_CHECK_MAX_AGE_HOURS`` so that
  a lasting change of the source is accepted after a week (the floors still apply).
* **Parsing** (FC9, rule 4): ``;``-separated ISO-8859-1 CSVs with formatted CNPJs. Only identity and
  status columns are imported: contacts, addresses, phones, e-mails and net worth never leave the
  parser. Natural-person registries (portfolio managers, advisers) carry no CPF today; a CPF column
  would be kept only masked, CPF-shaped digits are stripped from names, and those rows are never
  indexed by CNPJ or used outside explicit due diligence (:func:`due_diligence_match`).

Attribution: Comissao de Valores Mobiliarios (dados.cvm.gov.br, Open Database License). ODbL
share-alike applies only if a derived database is redistributed: the index is never exported.
"""

from __future__ import annotations

import csv
import io
import re
import threading
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from v3lum.core import validators
from v3lum.core.datasets import DataStore, DatasetError, DatasetUnavailable, register_dataset

SOURCE = "cvm.cadastral"
#: registry source of the natural-person registries (provider extension cvm__p1-G10-3.json): a separate
#: source keeps them out of the datasets that gate bcb_authorized_institutions (policy POL-14).
SOURCE_PF = "cvm.cvm_person_registry_pf"
CVM_DATA = "https://dados.cvm.gov.br/dados/"
LICENCE = "ODbL-1.0 (CVM open data, dados.cvm.gov.br; share-alike only if a derived database is redistributed)"
ATTRIBUTION = "Comissao de Valores Mobiliarios - CVM (dados.cvm.gov.br, Open Database License)"
#: FC2: a fresh copy may not drop more than 10% or grow more than 25% against the previous copy ...
MAX_DROP = 0.10
MAX_GROWTH = 0.25
#: ... while the installed copy is younger than this (afterwards the floors alone apply).
ROW_CHECK_MAX_AGE_HOURS = 7 * 24.0
#: TTL that serves the local copy whatever its age: readers here never trigger a download (FC1).
SERVE_LOCAL_TTL = 100 * 365 * 86400.0
DATASET_MAX_BYTES = 20_000_000

# ======================================================================================
# text, CNPJ and CPF helpers (shared with the BCB module)
# ======================================================================================

_WS = re.compile(r"\s+")
_CNPJ_CHARS = re.compile(r"[^0-9A-Za-z]")
_CPF_RX = re.compile(r"(?<![0-9A-Za-z])(\d{3})\.?(\d{3})\.?(\d{3})-?(\d{2})(?![0-9A-Za-z])")
_LEGAL_FORMS = frozenset({"SA", "LTDA", "EIRELI", "ME", "EPP", "SLU", "SS", "EPE"})


def clean(value: Any) -> str:
    """str() of a scalar, whitespace collapsed and stripped; None and containers give ''."""
    if value is None or isinstance(value, (dict, list, tuple, set, bytes, bytearray)):
        return ""
    return _WS.sub(" ", str(value)).strip()


def fold(text: Any) -> str:
    """Accent-folded, upper-case, single-spaced text ('' for anything that is not text)."""
    s = unicodedata.normalize("NFKD", clean(text))
    return "".join(c for c in s if not unicodedata.combining(c)).upper()


def name_key(name: Any) -> str:
    """Exact-match key of a company name (FC9): accents, punctuation and the S.A./S/A spellings.

    'BB GESTAO DE RECURSOS DTVM S.A' and 'BB GESTÃO DE RECURSOS DTVM SA' give the same key. Used for
    exact matching only - never fuzzy, substring or prefix matching."""
    tokens = re.sub(r"[^\w&]+", " ", fold(name).replace("_", " ")).split()
    out: list[str] = []
    i = 0
    while i < len(tokens):
        if tokens[i] == "S" and i + 1 < len(tokens) and tokens[i + 1] in ("A", "S"):
            out.append("S" + tokens[i + 1])
            i += 2
            continue
        out.append(tokens[i])
        i += 1
    return " ".join(out)


def core_name_key(name: Any) -> str:
    """:func:`name_key` without trailing legal-form tokens (SA, LTDA, EIRELI, ME, EPP, SLU...)."""
    tokens = name_key(name).split()
    while tokens and tokens[-1] in _LEGAL_FORMS:
        tokens.pop()
    return " ".join(tokens)


def cnpj_normalize(value: Any) -> str | None:
    """14-character CNPJ (digits, or the alphanumeric form of IN RFB 2.229/2024) or None."""
    s = _CNPJ_CHARS.sub("", clean(value)).upper()
    return s if re.fullmatch(r"[0-9A-Z]{12}[0-9]{2}", s) else None


def cnpj_root(value: Any) -> str | None:
    """8-character CNPJ root from a root, a 14-character or a formatted CNPJ (None otherwise).

    Numeric roots that lost leading zeros on the way (1 to 7 digits) are zero-padded; an 11-digit
    value (CPF-shaped) is never a root (rule 4)."""
    s = _CNPJ_CHARS.sub("", clean(value)).upper()
    if re.fullmatch(r"[0-9A-Z]{8}", s):
        return s
    if re.fullmatch(r"[0-9]{1,7}", s):
        return s.zfill(8)
    if len(s) == 14 and re.fullmatch(r"[0-9A-Z]{12}[0-9]{2}", s):
        return s[:8]
    return None


def cnpj_valid(value: Any) -> bool:
    norm = cnpj_normalize(value)
    return bool(norm) and validators.cnpj_valid(norm or "")


def format_cnpj(value: Any) -> str | None:
    s = cnpj_normalize(value)
    return f"{s[:2]}.{s[2:5]}.{s[5:8]}/{s[8:12]}-{s[12:]}" if s else None


def head_office_cnpj(root: Any) -> str | None:
    """14-character head-office CNPJ (root + '0001' + check digits) of a CNPJ root.

    BCB publishes roots only; every CVM CNPJ whose root is a BCB institution used order 0001 on
    2026-11-26 (793/793), so the derived value is labelled 'derived' wherever it is shown."""
    r = cnpj_root(root)
    if not r:
        return None
    base = r + "0001"
    return base + validators.cnpj_check_digits(base)


def looks_like_cpf(value: Any) -> bool:
    return bool(_CPF_RX.fullmatch(clean(value)))


def mask_cpf(value: Any) -> str | None:
    """Government pattern ***.456.789-** (AR24); None when the value is not CPF-shaped."""
    m = _CPF_RX.fullmatch(clean(value))
    return f"***.{m.group(2)}.{m.group(3)}-**" if m else None


def strip_cpf_sequences(text: Any) -> str:
    """Remove CPF-shaped sequences (11-digit runs, formatted CPFs) from a name (rule 4, P361 FC4)."""
    return _WS.sub(" ", _CPF_RX.sub(" ", clean(text))).strip(" -")


def sentence_case(text: str) -> str:
    """'CORRETORAS' -> 'Corretoras' for all-caps source labels; mixed-case labels are kept."""
    return text[:1].upper() + text[1:].lower() if text and text == text.upper() else text


# ---- hosts ---------------------------------------------------------------------------

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def normalize_host(value: Any) -> str | None:
    """Lower-case ASCII (IDNA) host name, or None for anything that is not a plain DNS name
    (paths, userinfo, ports, IP literals, empty or over-long labels)."""
    if not isinstance(value, str):
        return None
    h = value.strip().strip(".").lower()
    if not h or len(h) > 253 or any(c in h for c in "/@:?#\\ \t[]%"):
        return None
    out: list[str] = []
    for label in h.split("."):
        if not label:
            return None
        if not label.isascii():
            try:
                label = label.encode("idna").decode("ascii")
            except UnicodeError:
                return None
        if len(label) > 63 or not _LABEL.fullmatch(label):
            return None
        out.append(label)
    if all(label.isdigit() for label in out):
        return None
    return ".".join(out)


def declared_hosts(value: Any) -> list[str]:
    """Hosts of a free-text website field (BCB Sedes SITIO_NA_INTERNET, CVM SITE_*).

    Repairs 'HTTPS: //X', 'WWW:/X', 'X. COM.BR', paths and several values in one field; drops e-mail
    addresses and words that are not hosts. Declared websites are never verified and never grant
    known_good (P360 FC4): callers pivot them with expand=False only."""
    v = clean(value)
    if not v:
        return []
    v = re.sub(r"\s*\.\s*", ".", v)
    v = re.sub(r"(?i)\b(https?)\s*:\s*/+\s*", r"\1://", v)
    v = re.sub(r"(?i)^www:/+", "http://", v)
    out: list[str] = []
    for token in v.split():
        if "@" in token and "/" not in token.split("@", 1)[0]:
            continue  # an e-mail address, never a website
        url = token if re.match(r"(?i)^[a-z][a-z0-9+.-]*://", token) else "http://" + token
        try:
            host = urlsplit(url).hostname
        except ValueError:
            continue
        h = normalize_host(host or "")
        if h and "." in h and h not in out:
            out.append(h)
    return out


# ======================================================================================
# dataset-copy validation (FC2), shared with the BCB datasets
# ======================================================================================


def validate_copy(name: str, rows: int, previous_rows: int | None = None, *, size_bytes: int | None = None, min_rows: int = 1,
                  min_bytes: int = 0, max_drop: float = MAX_DROP, max_growth: float = MAX_GROWTH) -> str:
    """FC2: why a fresh copy must NOT replace the installed one ('' = accept).

    Absolute floors first, then 'row count close to the previous one': more than ``max_drop`` fewer
    or ``max_growth`` more rows than the previous copy is rejected (a partial or broken export)."""
    if not isinstance(rows, int) or isinstance(rows, bool) or rows <= 0:
        return f"{name}: no rows"
    if rows < min_rows:
        return f"{name}: {rows} rows is below the floor of {min_rows}"
    if size_bytes is not None and size_bytes < min_bytes:
        return f"{name}: {size_bytes} bytes is below the floor of {min_bytes}"
    if previous_rows:
        if rows < previous_rows * (1 - max_drop):
            return f"{name}: {rows} rows is {100 * (1 - rows / previous_rows):.0f}% below the previous copy ({previous_rows})"
        if rows > previous_rows * (1 + max_growth):
            return f"{name}: {rows} rows is {100 * (rows / previous_rows - 1):.0f}% above the previous copy ({previous_rows})"
    return ""


def previous_rows(name: str, count: Callable[[bytes], tuple[int, str]]) -> int | None:
    """Row count of the installed copy of ``name`` for the relative check (None = skip it: no copy,
    an unreadable copy, or a copy older than ROW_CHECK_MAX_AGE_HOURS)."""
    store = DataStore(None)
    try:
        info = store.info(name)
        if not info.present:
            return None
        if info.age_hours is not None and float(info.age_hours) > ROW_CHECK_MAX_AGE_HOURS:
            return None
        rows, problem = count(store.path(name).read_bytes())
    except (OSError, ValueError, DatasetError):
        return None
    return rows if not problem and rows > 0 else None


def copy_validator(name: str, count: Callable[[bytes], tuple[int, str]], *, min_rows: int, min_bytes: int,
                   extra: Callable[[bytes], str] | None = None) -> Callable[[Path], bool]:
    """The ``validate(path)`` callback of a registry dataset (FC2): parse the candidate, apply the
    floors and the relative row check, then ``extra`` (e.g. a unique-domain floor). Raises
    ValueError with the reason, which the dataset manager reports while keeping the previous copy."""

    def validate(path: Path) -> bool:
        data = Path(path).read_bytes()
        rows, problem = count(data)
        if problem:
            raise ValueError(f"{name}: {problem}")
        reason = validate_copy(name, rows, previous_rows(name, count), size_bytes=len(data), min_rows=min_rows, min_bytes=min_bytes)
        if not reason and extra is not None:
            reason = extra(data)
        if reason:
            raise ValueError(reason)
        return True

    return validate


def local_path(data: Any, name: str) -> Path:
    """Path of the local copy of ``name`` through ``ctx.data`` (a DataView: the read is cited in
    ``res.datasets``) or a DataStore, without any refresh or download (FC1: never during a scan).
    Raises DatasetUnavailable when no copy is installed."""
    try:
        present = bool(data.info(name).present)
    except (ValueError, OSError):
        present = False
    if not present:
        raise DatasetUnavailable(name, f"dataset {name} is not downloaded: run v3lum data update {name}")
    return Path(data.fetch(name, ttl=SERVE_LOCAL_TTL))


def dataset_meta(data: Any, name: str, rows: int = 0) -> dict[str, Any]:
    """{name, sha256, fetched_at, date, age_hours, stale, rows} of a local copy (FC2: the dataset
    date goes into evidence and coverage). Olinda sends no Last-Modified, so the date of every copy
    is its download date."""
    info = data.info(name)
    fetched = str(info.fetched_at or "")
    return {
        "name": name,
        "sha256": str(info.sha256 or ""),
        "fetched_at": fetched,
        "date": fetched[:10] if re.match(r"^\d{4}-\d{2}-\d{2}", fetched) else "",
        "age_hours": info.age_hours,
        "stale": bool(info.stale),
        "rows": rows,
    }


# ======================================================================================
# CVM registries (FC1, FC9)
# ======================================================================================


@dataclass(frozen=True)
class CvmRegistry:
    """One CVM cadastral registry: the zip member it imports and the columns it keeps."""

    key: str
    dataset: str  # registered dataset name ('' = parse support only, e.g. cia_aberta for P244/P361)
    url: str
    member: str
    kind: str  # 'pj' (companies) | 'pf' (natural persons, due diligence only)
    segment: str
    required: tuple[str, ...]
    cnpj_col: str = "CNPJ"
    name_col: str = "DENOM_SOCIAL"
    segment_col: str = ""
    category_cols: tuple[str, ...] = ()
    site_col: str = ""
    min_rows: int = 1
    min_bytes: int = 0
    observed_rows: int = 0
    observed_bytes: int = 0

    @property
    def source(self) -> str:
        return SOURCE_PF if self.kind == "pf" else SOURCE


REGISTRIES: dict[str, CvmRegistry] = {
    reg.key: reg
    for reg in (
        CvmRegistry("intermed", "cvm_intermed.csv", CVM_DATA + "INTERMED/CAD/DADOS/cad_intermed.zip", "cad_intermed.csv", "pj",
                    "Participante intermediario", ("TP_PARTIC", "CNPJ", "DENOM_SOCIAL", "SIT"), segment_col="TP_PARTIC",
                    site_col="SITE_WEB", min_rows=1500, min_bytes=350_000, observed_rows=2354, observed_bytes=741_376),
        CvmRegistry("adm_cart_pj", "cvm_adm_cart_pj.csv", CVM_DATA + "ADM_CART/CAD/DADOS/cad_adm_cart.zip", "cad_adm_cart_pj.csv", "pj",
                    "Administrador de Carteira", ("CNPJ", "DENOM_SOCIAL", "SIT"), category_cols=("CATEG_REG", "SUBCATEG_REG"),
                    site_col="SITE_ADMIN", min_rows=2000, min_bytes=400_000, observed_rows=3077, observed_bytes=893_855),
        CvmRegistry("consultor_pj", "cvm_consultor_vlmob_pj.csv", CVM_DATA + "CONSULTOR_VLMOB/CAD/DADOS/cad_consultor_vlmob.zip",
                    "cad_consultor_vlmob_pj.csv", "pj", "Consultor de Valores Mobiliarios", ("CNPJ", "DENOM_SOCIAL", "SIT"),
                    site_col="SITE_ADMIN", min_rows=700, min_bytes=150_000, observed_rows=1096, observed_bytes=303_339),
        CvmRegistry("crowdfunding", "cvm_crowdfunding.csv", CVM_DATA + "CROWDFUNDING/CAD/DADOS/cad_crowdfunding.zip", "cad_crowdfunding.csv",
                    "pj", "Plataforma de Crowdfunding", ("CNPJ", "DENOM_SOCIAL", "SIT"), site_col="WEBSITE", min_rows=100,
                    min_bytes=15_000, observed_rows=156, observed_bytes=37_983),
        # natural-person registries: explicit due diligence only (FC9); the name is the only key, never a CPF
        CvmRegistry("adm_cart_pf", "cvm_adm_cart_pf.csv", CVM_DATA + "ADM_CART/CAD/DADOS/cad_adm_cart.zip", "cad_adm_cart_pf.csv", "pf",
                    "Administrador de Carteira (pessoa natural)", ("ADMIN", "SIT"), name_col="ADMIN", category_cols=("CATEG_REG",),
                    min_rows=4500, min_bytes=300_000, observed_rows=6892, observed_bytes=654_400),
        CvmRegistry("consultor_pf", "cvm_consultor_vlmob_pf.csv", CVM_DATA + "CONSULTOR_VLMOB/CAD/DADOS/cad_consultor_vlmob.zip",
                    "cad_consultor_vlmob_pf.csv", "pf", "Consultor de Valores Mobiliarios (pessoa natural)", ("NOME", "SIT"),
                    name_col="NOME", min_rows=2500, min_bytes=150_000, observed_rows=4022, observed_bytes=331_768),
        # parse support for P244/P361 (listed companies, 1.5 MB CSV): not registered here, see the module docstring
        CvmRegistry("cia_aberta", "", CVM_DATA + "CIA_ABERTA/CAD/DADOS/cad_cia_aberta.csv", "cad_cia_aberta.csv", "pj",
                    "Companhia aberta (emissor)", ("CNPJ_CIA", "DENOM_SOCIAL", "SIT"), cnpj_col="CNPJ_CIA", category_cols=("CATEG_REG",)),
    )
}
#: company registries that answer 'is this broker/adviser/platform registered with CVM?' (FC9)
PJ_REGISTRIES: tuple[str, ...] = ("intermed", "adm_cart_pj", "consultor_pj", "crowdfunding")
#: natural-person registries: never read outside explicit due diligence (FC9, rule 4)
PF_REGISTRIES: tuple[str, ...] = ("adm_cart_pf", "consultor_pf")
#: zip members that are people lists (officers, partners, directors): never imported
PEOPLE_MEMBER = re.compile(r"_(resp|diretor|socios|adm_resp)\.csv$", re.I)

_STATUS = (
    ("EM FUNCIONAMENTO NORMAL", "active"),
    ("CANCELAD", "cancelled"),
    ("LIQUIDACAO", "liquidation"),
    ("FALENCIA", "liquidation"),
    ("SUSPENS", "suspended"),
    ("AFASTADO", "suspended"),
    ("INTERVENTOR", "special"),
    ("SITUACAO ESPECIAL", "special"),
    ("EM ANALISE", "pending"),
    ("NAO CONCEDIDO", "denied"),
)
STATUSES = ("active", "cancelled", "liquidation", "suspended", "special", "pending", "denied", "unknown")


def cvm_status(sit: Any) -> str:
    """CVM SIT text -> active | cancelled | liquidation | suspended | special | pending | denied | unknown.
    Only 'active' (EM FUNCIONAMENTO NORMAL) counts as registered and operating."""
    s = fold(sit)
    if not s:
        return "unknown"
    for needle, label in _STATUS:
        if needle in s:
            return label
    return "unknown"


def decode_cvm_bytes(raw: Any) -> str:
    """CVM CSVs are ISO-8859-1 (no 0x80-0x9F bytes seen): a UTF-8 BOM or strict UTF-8 first, else latin-1."""
    if isinstance(raw, str):
        return raw.lstrip("﻿")
    data = bytes(raw or b"")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


_HTML = re.compile(r"^\s*(?:<!doctype\s+html|<html\b|<head\b|<body\b|<\?xml\b)", re.I)


@dataclass
class ParsedRegistry:
    registry: str
    rows: list[dict[str, Any]] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


def _trade_name(value: Any) -> str | None:
    text = strip_cpf_sequences(value)
    return None if not text or set(text) <= {"-", ".", " "} else text


def parse_cvm_csv(data: Any, registry: str) -> ParsedRegistry:
    """One CVM cadastral CSV -> minimised rows (FC1, FC9, rule 4). Fails closed (``error`` set) on
    HTML pages, schema drift and truncated or malformed files - never an empty registry.

    Company row: registry, segment, category, status, status_raw, status_since, registered_on,
    cancelled_on, cancel_reason, cnpj (formatted), cnpj_root, cnpj_valid, name, trade_name, cd_cvm,
    uf, municipality, declared_hosts. Natural-person row: registry, natural_person, name (CPF-shaped
    digits stripped), segment, category, status fields and cpf_masked only if a CPF column ever
    appears. Contacts, addresses, phones, e-mails and net worth are never kept."""
    spec = REGISTRIES.get(registry)
    out = ParsedRegistry(registry)
    if spec is None:
        out.error = f"unknown CVM registry {registry!r}"
        return out
    text = decode_cvm_bytes(data)
    if _HTML.match(text[:2048]):
        out.error = "an HTML page came back instead of the CSV (challenge or error page?)"
        return out
    try:
        table = list(csv.reader(io.StringIO(text, newline=""), delimiter=";"))
    except csv.Error as exc:
        out.error = f"not a valid CSV: {exc}"
        return out
    while table and not any(cell.strip() for cell in table[-1]):
        table.pop()
    if not table:
        out.error = "empty file"
        return out
    header = [h.strip().lstrip("﻿") for h in table[0]]
    out.columns = header
    missing = [c for c in spec.required if c not in header]
    if missing:
        out.error = f"schema drift: column(s) {', '.join(missing)} missing"
        return out
    body = table[1:]
    if body and len(body[-1]) < len(header):
        out.error = f"truncated or malformed CSV: the last row has {len(body[-1])} of {len(header)} fields (partial download)"
        return out
    bad = {i for i, row in enumerate(body) if len(row) != len(header)}
    if len(bad) > max(1, len(body) // 100):
        out.error = f"truncated or malformed CSV: {len(bad)} of {len(body)} rows have a wrong field count"
        return out
    cpf_cols = [c for c in header if fold(c) in ("CPF", "NR_CPF", "CPF_CNPJ", "NUM_CPF")]
    for i, row in enumerate(body):
        if i in bad:
            continue
        d = dict(zip(header, row))
        cats = [clean(d.get(c)) for c in spec.category_cols if clean(d.get(c))]
        item: dict[str, Any] = {
            "registry": registry,
            "segment": sentence_case(clean(d.get(spec.segment_col))) if spec.segment_col else spec.segment,
            "category": " / ".join(cats) or None,
            "status": cvm_status(d.get("SIT")),
            "status_raw": clean(d.get("SIT")) or None,
            "status_since": clean(d.get("DT_INI_SIT")) or None,
            "registered_on": clean(d.get("DT_REG")) or None,
            "cancelled_on": clean(d.get("DT_CANCEL")) or None,
            "cancel_reason": clean(d.get("MOTIVO_CANCEL")) or None,
        }
        if spec.kind == "pf":
            item["natural_person"] = True
            item["name"] = strip_cpf_sequences(d.get(spec.name_col)) or None
            if cpf_cols:
                item["cpf_masked"] = mask_cpf(d.get(cpf_cols[0]))
        else:
            raw_cnpj = d.get(spec.cnpj_col)
            item.update({
                "natural_person": False,
                "cnpj": format_cnpj(raw_cnpj),
                "cnpj_root": cnpj_root(raw_cnpj) if cnpj_normalize(raw_cnpj) else None,
                "cnpj_valid": cnpj_valid(raw_cnpj),
                "name": strip_cpf_sequences(d.get(spec.name_col)) or None,
                "trade_name": _trade_name(d.get("DENOM_COMERC")),
                "cd_cvm": clean(d.get("CD_CVM")) or None,
                "uf": clean(d.get("UF")) or None,
                "municipality": clean(d.get("MUN")) or None,
                "declared_hosts": declared_hosts(d.get(spec.site_col))[:5] if spec.site_col else [],
            })
        out.rows.append(item)
    stats: dict[str, Any] = {"rows": len(out.rows), "active": sum(1 for r in out.rows if r["status"] == "active")}
    if bad:
        stats["malformed_rows_skipped"] = len(bad)
    if spec.kind == "pj":
        stats["cnpjs"] = len({r["cnpj"] for r in out.rows if r.get("cnpj")})
        stats["invalid_cnpjs"] = sum(1 for r in out.rows if not r.get("cnpj_valid"))
    out.stats = stats
    return out


def count_rows(registry: str) -> Callable[[bytes], tuple[int, str]]:
    """Row counter of one registry for :func:`copy_validator`: (rows, problem)."""

    def count(data: bytes) -> tuple[int, str]:
        parsed = parse_cvm_csv(data, registry)
        return len(parsed.rows), parsed.error

    return count


def _register(reg: CvmRegistry) -> None:
    kind = "natural-person registry, explicit due diligence only" if reg.kind == "pf" else "company registry"
    register_dataset(
        reg.dataset, reg.url, ttl=86400,
        description=f"CVM cadastral registry {reg.key} ({reg.member} of the CVM zip; {kind}; refreshed by v3lum data update, never during a scan)",
        licence=LICENCE, terms_class="open", attribution=ATTRIBUTION, source=reg.source,
        validate=copy_validator(reg.dataset, count_rows(reg.key), min_rows=reg.min_rows, min_bytes=reg.min_bytes),
        min_bytes=reg.min_bytes, expect="csv", max_bytes=DATASET_MAX_BYTES, large=True,
        essential=reg.kind == "pj", archive="zip", member=reg.member,
    )


for _reg in REGISTRIES.values():
    if _reg.dataset:
        _register(_reg)


# ======================================================================================
# index and local loading (never downloads)
# ======================================================================================

#: fields of a company registration carried into results
REGISTRATION_FIELDS = ("registry", "segment", "category", "status", "status_since", "cnpj", "name", "trade_name",
                       "registered_on", "cancelled_on", "cancel_reason", "declared_hosts")
#: name-index tables in lookup order, with the match label each one gives (FC9: never fuzzy)
NAME_TABLES = (("legal", "exact_name"), ("legal_core", "name_without_legal_form"), ("trade", "trade_name"),
               ("trade_core", "trade_name_without_legal_form"))


class NameIndex:
    """Exact company-name keys -> CNPJ roots (FC9): the normalised legal name (razao social), the same
    without its legal-form suffix, and the trade name (nome fantasia). Exact keys only: never fuzzy,
    substring or prefix matching, and never natural persons."""

    def __init__(self) -> None:
        self.tables: dict[str, dict[str, set[str]]] = {kind: {} for kind, _label in NAME_TABLES}

    def add(self, name: Any, root: str, *, trade: bool = False) -> None:
        if not root:
            return
        for kind, key in (("trade" if trade else "legal", name_key(name)), ("trade_core" if trade else "legal_core", core_name_key(name))):
            if key:
                self.tables[kind].setdefault(key, set()).add(root)

    def find(self, name: Any, *others: NameIndex) -> tuple[list[str], str]:
        """Roots of the first table level that matches in this index or ``others`` (sorted roots,
        match label); ([], '') when nothing matches exactly."""
        keys = {"legal": name_key(name), "legal_core": core_name_key(name), "trade": name_key(name), "trade_core": core_name_key(name)}
        for kind, label in NAME_TABLES:
            key = keys[kind]
            if not key:
                continue
            roots: set[str] = set()
            for idx in (self, *others):
                roots |= idx.tables.get(kind, {}).get(key, set())
            if roots:
                return sorted(roots), label
        return [], ""


@dataclass(frozen=True)
class CvmIndex:
    """CNPJ root -> company registrations and exact-name keys -> roots (FC9). Natural-person rows are
    never indexed here (they live only in :func:`load_people` results)."""

    by_root: Mapping[str, tuple[dict[str, Any], ...]] = field(default_factory=dict)
    names: NameIndex = field(default_factory=NameIndex)
    datasets: tuple[dict[str, Any], ...] = ()
    missing: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    @property
    def present(self) -> bool:
        return bool(self.datasets)


def build_index(parsed: Iterable[ParsedRegistry], *, datasets: Iterable[dict[str, Any]] = (), missing: Iterable[str] = (),
                errors: Iterable[str] = ()) -> CvmIndex:
    by_root: dict[str, list[dict[str, Any]]] = {}
    names = NameIndex()
    for p in parsed:
        for row in p.rows:
            if row.get("natural_person") or not row.get("cnpj_valid") or not row.get("cnpj_root"):
                continue  # placeholders such as 00.999.999/9999-99 and every natural person stay out
            root = row["cnpj_root"]
            by_root.setdefault(root, []).append({k: row.get(k) for k in REGISTRATION_FIELDS})
            names.add(row.get("name"), root)
            names.add(row.get("trade_name"), root, trade=True)
    return CvmIndex({k: tuple(v) for k, v in by_root.items()}, names, tuple(datasets), tuple(missing), tuple(errors))


_LOCK = threading.Lock()
_PARSED: dict[str, tuple[str, ParsedRegistry]] = {}  # dataset name -> (sha256, parsed copy)
_INDEXES: dict[tuple[tuple[str, str], ...], CvmIndex] = {}


def parsed_copy(data: Any, key: str) -> tuple[ParsedRegistry, dict[str, Any]]:
    """The parsed local copy of one registry and its dataset meta (parsed once per sha256).
    Raises DatasetUnavailable when no copy is installed; a copy that no longer parses comes back with
    ``error`` set (never as an empty registry)."""
    reg = REGISTRIES[key]
    path = local_path(data, reg.dataset)
    meta = dataset_meta(data, reg.dataset)
    sha = meta["sha256"]
    with _LOCK:
        hit = _PARSED.get(reg.dataset)
        if hit is not None and hit[0] == sha and sha:
            meta["rows"] = len(hit[1].rows)
            return hit[1], meta
    try:
        parsed = parse_cvm_csv(path.read_bytes(), key)
    except OSError as exc:
        parsed = ParsedRegistry(key, error=f"cannot read the local copy: {exc}")
    with _LOCK:
        _PARSED[reg.dataset] = (sha, parsed)
    meta["rows"] = len(parsed.rows)
    return parsed, meta


def load_companies(data: Any, registries: Iterable[str] = PJ_REGISTRIES) -> CvmIndex:
    """The company-registry index from the local copies only (FC1: never downloads). ``data`` is
    ``ctx.data`` (citations recorded) or a ``DataStore(None)``. Missing copies are listed in
    ``missing`` and copies that no longer parse in ``errors``; neither is ever read as 'not registered'."""
    parsed: list[ParsedRegistry] = []
    metas: list[dict[str, Any]] = []
    missing: list[str] = []
    errors: list[str] = []
    for key in registries:
        reg = REGISTRIES[key]
        if reg.kind != "pj" or not reg.dataset:
            continue
        try:
            p, meta = parsed_copy(data, key)
        except DatasetUnavailable:
            missing.append(reg.dataset)
            continue
        if not p.ok:
            errors.append(f"{reg.dataset}: {p.error} (run v3lum data update {reg.dataset})")
            continue
        parsed.append(p)
        metas.append(meta)
    signature = tuple((m["name"], m["sha256"]) for m in metas)
    with _LOCK:
        hit = _INDEXES.get(signature)
    if hit is not None and signature:
        return CvmIndex(hit.by_root, hit.names, tuple(metas), tuple(missing), tuple(errors))
    index = build_index(parsed, datasets=metas, missing=missing, errors=errors)
    if signature:
        with _LOCK:
            _INDEXES.clear()  # one version at a time
            _INDEXES[signature] = index
    return index


def load_people(data: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Natural-person rows of the PF registries (local copies only) for explicit due diligence
    (FC9): (rows, dataset metas, missing dataset names). Never used to answer CNPJ or company-name
    queries and never indexed by CNPJ."""
    rows: list[dict[str, Any]] = []
    metas: list[dict[str, Any]] = []
    missing: list[str] = []
    for key in PF_REGISTRIES:
        try:
            p, meta = parsed_copy(data, key)
        except DatasetUnavailable:
            missing.append(REGISTRIES[key].dataset)
            continue
        if not p.ok:
            raise DatasetError(f"{REGISTRIES[key].dataset}: {p.error} (run v3lum data update {REGISTRIES[key].dataset})",
                               name=REGISTRIES[key].dataset)
        rows.extend(p.rows)
        metas.append(meta)
    return rows, metas, missing


def due_diligence_match(name: Any, rows: Iterable[dict[str, Any]], *, purpose: str) -> dict[str, Any]:
    """FC9: natural-person registries only in explicit due diligence with a recorded purpose; the
    exact normalised name is the only key (a CPF never is); every hit is POSSIBLE ('same name does
    not prove identity')."""
    if not clean(purpose):
        return {"ok": False, "matches": [], "error": "natural-person registries need explicit due diligence (a recorded --purpose)"}
    text = clean(name)
    if looks_like_cpf(text) or _CPF_RX.search(text) or re.search(r"\d{3}\D?\d{3}\D?\d{3}", text):
        return {"ok": False, "matches": [], "error": "a CPF is never a lookup key (rule 4)"}
    key = name_key(text)
    if len(key.split()) < 2:
        return {"ok": False, "matches": [], "error": "give the full name (at least two words): a single word is never matched"}
    hits = [dict(row) for row in rows if row.get("natural_person") and key and name_key(row.get("name")) == key]
    return {"ok": True, "matches": hits, "error": ""}
