"""P240 ``cgu_sanctions_bulk`` - offline screening against the CGU bulk sanctions files (CEIS, CNEP, CEPIM,
leniency agreements) and the monthly PEP file.

Council P240 final conditions, as implemented here:

1. Datasets through the dataset manager only: one registered dataset per list
   (``cgu_sanctions_bulk.<list>``), downloaded from portaldatransparencia.gov.br/download-de-dados/
   {ceis|cnep|cepim|acordos-leniencia}/{YYYYMMDD} (PEP /pep/{YYYYMM}) - the portal redirects to the CGU
   S3 host - and never during a scan (``large=True``; the module itself has no network). The import-time
   registration names the newest file known to be published; ``update_lists()`` walks back at most 7
   days (PEP: by month, prep H5) when a file is missing: 404, or S3 '403 AccessDenied' for a file not
   published yet (provider marker ``cgu_sanctions_bulk_not_published``, prep H2). Each download is
   validated before it replaces the previous copy (``build_store``: exact member set, ';' cp1252 CSV
   with the required columns, minimum rows) and the replaced copy is gone (atomic replace).
2. Zips go through the core safe archive helper (``safe_extract``: no absolute/'..' paths, links or
   special files, member and size caps, ratio cap 30:1); the CSV is parsed streaming into an indexed
   SQLite store (CNPJ, CNPJ root, normalised name and a name block) that *is* the installed dataset: the
   raw zip is never kept. Matching is local (disclosure 'none'); names are scored by the shared P219
   matcher (token-set Jaro-Winkler of ``v3lum.modules.company_org.namematch``, the stand-in of
   core/namematch.py published by batch p1-G10-1) over a first/last-token block of the store; a local
   token-sort similarity is the fallback only while that stand-in is absent.
3. CNPJ: an exact 14-digit match with a sanction in force is HIGH (tag sanctions; list, sanction type,
   sanctioning body, start/end dates, link); a match on the 8-digit root of another establishment is
   MEDIUM 'related establishment' (match type always stated); expired sanctions are INFO 'formerly
   sanctioned (<end date>)'.
4. ``data['dedup_key']`` = '<list>|<cnpj>|<sanction id>' is shared with P237/P239: one listing is one
   finding (correlation rule ``g10_sanction_dedup``).
5. Person names are screened only for analyst-typed subjects or QSA partners (pivot relation
   ``partner_of``) in a case with a recorded purpose, never for other pivots (SKIPPED 'privacy');
   matches are 'possible match' (score >= 0.90, confidence <= 0.5) lowered by the P252 homonym score.
6. Person rows keep only the name and the CPF masked at ingestion (the CEIS/CNEP files publish full
   CPFs, prep H1; the masked form is ***.456.789-**): never a lookup key, never joined with QSA CPF
   fragments, and only matched rows enter the case.
7. PEP matches are INFO 'PEP (possible match)' context (tags pep, context_only), never risk.
8. A missing dataset, or one older than 3 days (PEP: 40 days from its publication), is
   'not screened against <list> (<date>)' (UNAVAILABLE 'dataset' per list; the whole run when no list
   is usable), never 'not sanctioned'. The file date appears in every finding.
"""

from __future__ import annotations

import csv
import difflib
import json
import os
import re
import secrets
import shutil
import sqlite3
import tempfile
import unicodedata
import zipfile
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from v3lum.core.datasets import DataStore, UpdateResult, register_dataset, safe_extract, unregister_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.person_name.ibge_name_frequency import apply_homonym_curve, homonym_risk, offline_table

try:  # the shared P219 matcher (stand-in for core/namematch.py, batch p1-G10-1; P240 cond 2)
    from v3lum.modules.company_org.namematch import name_tokens as _shared_tokens
    from v3lum.modules.company_org.namematch import token_set_jw as _shared_jw
except ImportError:  # pragma: no cover - the stand-in moved: the local token-sort similarity below
    _shared_tokens = _shared_jw = None

PORTAL_URL = "https://portaldatransparencia.gov.br/download-de-dados/{slug}/{d}"
STORE_SCHEMA = "v3lum.cgu_sanctions/1"
LICENCE = "Dados abertos do Governo Federal (CGU, Portal da Transparencia) - open government data"
ATTRIBUTION = "Controladoria-Geral da Uniao (CGU), Portal da Transparencia - bulk download files"
MB = 1024 * 1024
#: P240 cond 2: compression ratio cap (real files are 5-10:1)
MAX_RATIO = 30
#: P240 cond 1: walk back at most 7 days (PEP: the two previous months)
MAX_BACK_DAYS = 7
MAX_BACK_MONTHS = 2
#: P240 cond 8: freshness limits
STALE_DAYS = 3
STALE_DAYS_MONTHLY = 40
#: P240 cond 5 / P219 cond 8: name-only matches need this similarity
MIN_NAME_SCORE = 0.90
#: the scorer named in every name-match criterion
MATCHER = "token-set Jaro-Winkler (shared P219 matcher)" if _shared_jw is not None else "token-sort similarity"
NAME_CONFIDENCE_CAP = 0.5
MAX_NAME_CANDIDATES = 5
MAX_BLOCK_ROWS = 2000


@dataclass(frozen=True)
class ListSpec:
    key: str
    short: str
    slug: str
    label: str
    members: tuple[str, ...]
    member_re: str
    cadence: str
    lag_days: int
    min_rows: int
    max_member_bytes: int
    required: tuple[str, ...]
    link: str
    persons: bool
    companies: bool
    required_second: tuple[str, ...] = ()

    @property
    def dataset(self) -> str:
        return f"cgu_sanctions_bulk.{self.key}"

    @property
    def source(self) -> str:
        return f"transparencia.cgu_sanctions_bulk_{self.short}"


_SANCTION_REQUIRED = ("CADASTRO", "CODIGO DA SANCAO", "TIPO DE PESSOA", "CPF OU CNPJ DO SANCIONADO", "NOME DO SANCIONADO",
                      "CATEGORIA DA SANCAO", "DATA INICIO SANCAO", "DATA FINAL SANCAO", "ORGAO SANCIONADOR")
LISTS: dict[str, ListSpec] = {
    "ceis": ListSpec("ceis", "ceis", "ceis", "CEIS", ("{d}_CEIS.csv",), r"^(\d{8})_CEIS\.csv$", "daily", 1, 10000, 200 * MB,
                     _SANCTION_REQUIRED, "https://portaldatransparencia.gov.br/sancoes/ceis", True, True),
    "cnep": ListSpec("cnep", "cnep", "cnep", "CNEP", ("{d}_CNEP.csv",), r"^(\d{8})_CNEP\.csv$", "daily", 1, 800, 50 * MB,
                     (*_SANCTION_REQUIRED, "VALOR DA MULTA"), "https://portaldatransparencia.gov.br/sancoes/cnep", True, True),
    "cepim": ListSpec("cepim", "cepim", "cepim", "CEPIM", ("{d}_CEPIM.csv",), r"^(\d{8})_CEPIM\.csv$", "daily", 2, 1500, 20 * MB,
                      ("CNPJ ENTIDADE", "NOME ENTIDADE", "NUMERO CONVENIO", "ORGAO CONCEDENTE", "MOTIVO DO IMPEDIMENTO"),
                      "https://portaldatransparencia.gov.br/sancoes/cepim", False, True),
    "acordos_leniencia": ListSpec(
        "acordos_leniencia", "leniencia", "acordos-leniencia", "Acordos de Leniencia", ("{d}_Acordos.csv", "{d}_Efeitos.csv"),
        r"^(\d{8})_(?:Acordos|Efeitos)\.csv$", "daily", 1, 50, 10 * MB,
        ("ID DO ACORDO", "CNPJ DO SANCIONADO", "RAZAO SOCIAL - CADASTRO RECEITA", "DATA DE INICIO DO ACORDO", "DATA DE FIM DO ACORDO",
         "SITUACAO DO ACORDO DE LENIENCIA", "ORGAO SANCIONADOR"),
        "https://portaldatransparencia.gov.br/sancoes/acordos-leniencia", False, True,
        required_second=("ID DO ACORDO", "EFEITO DO ACORDO DE LENIENCIA"),
    ),
    "pep": ListSpec("pep", "pep", "pep", "PEP", ("{d}_PEP.csv",), r"^(\d{6})_PEP\.csv$", "monthly", 0, 50000, 150 * MB,
                    ("CPF", "NOME_PEP", "SIGLA_FUNCAO", "DESCRICAO_FUNCAO", "NOME_ORGAO", "DATA_INICIO_EXERCICIO", "DATA_FIM_EXERCICIO",
                     "DATA_FIM_CARENCIA"), "https://portaldatransparencia.gov.br/pep", True, False),
}
LIST_ORDER = ("ceis", "cnep", "cepim", "acordos_leniencia", "pep")
COMPANY_LISTS = ("ceis", "cnep", "cepim", "acordos_leniencia")
PERSON_LISTS = ("ceis", "cnep", "pep")
#: minimum rows per list; tests lower them for trimmed fixtures (production values: about 40-50% of today's rows)
MIN_ROWS: dict[str, int] = {k: v.min_rows for k, v in LISTS.items()}

_HEADER_FIX = {"ABRAGENCIA": "ABRANGENCIA", "LENIENICA": "LENIENCIA"}
SANCTION_COLS = {
    "CADASTRO": "cadastro", "CODIGO DA SANCAO": "sanction_id", "TIPO DE PESSOA": "person_type", "CPF OU CNPJ DO SANCIONADO": "doc",
    "NOME DO SANCIONADO": "name", "NOME INFORMADO PELO ORGAO SANCIONADOR": "name_informed", "RAZAO SOCIAL - CADASTRO RECEITA": "rfb_name",
    "NOME FANTASIA - CADASTRO RECEITA": "rfb_trade_name", "NUMERO DO PROCESSO": "process", "CATEGORIA DA SANCAO": "category",
    "VALOR DA MULTA": "fine", "DATA INICIO SANCAO": "start", "DATA FINAL SANCAO": "end", "DATA PUBLICACAO": "published",
    "DATA DO TRANSITO EM JULGADO": "res_judicata", "ABRANGENCIA DA SANCAO": "scope", "ORGAO SANCIONADOR": "organ",
    "UF ORGAO SANCIONADOR": "organ_uf", "ESFERA ORGAO SANCIONADOR": "sphere", "FUNDAMENTACAO LEGAL": "legal_basis",
}
CEPIM_COLS = {"CNPJ ENTIDADE": "doc", "NOME ENTIDADE": "name", "NUMERO CONVENIO": "agreement", "ORGAO CONCEDENTE": "organ",
              "MOTIVO DO IMPEDIMENTO": "reason"}
LENIENCIA_COLS = {"ID DO ACORDO": "agreement_id", "CNPJ DO SANCIONADO": "doc", "RAZAO SOCIAL - CADASTRO RECEITA": "name",
                  "NOME FANTASIA - CADASTRO RECEITA": "trade_name", "DATA DE INICIO DO ACORDO": "start", "DATA DE FIM DO ACORDO": "end",
                  "SITUACAO DO ACORDO DE LENIENCIA": "situation", "NUMERO DO PROCESSO": "process", "ORGAO SANCIONADOR": "organ"}
EFEITOS_COLS = {"ID DO ACORDO": "agreement_id", "EFEITO DO ACORDO DE LENIENCIA": "effect", "COMPLEMENTO": "complement"}
PEP_COLS = {"CPF": "cpf", "NOME_PEP": "name", "SIGLA_FUNCAO": "role_code", "DESCRICAO_FUNCAO": "role", "NIVEL_FUNCAO": "level",
            "NOME_ORGAO": "organ", "DATA_INICIO_EXERCICIO": "start", "DATA_FIM_EXERCICIO": "end", "DATA_FIM_CARENCIA": "grace_end"}

# --------------------------------------------------------------------------------------
# normalisation helpers
# --------------------------------------------------------------------------------------


def fold(text: Any) -> str:
    t = str(text if text is not None else "").replace("–", "-").replace("—", "-")
    t = unicodedata.normalize("NFKD", t)
    t = "".join(c for c in t if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", t).strip().upper()


def header_key(h: Any) -> str:
    """CSV header -> canonical key: accent-folded, en dash -> '-', the two published typos fixed."""
    k = fold(h).strip('"')
    for bad, good in _HEADER_FIX.items():
        k = k.replace(bad, good)
    return k


def iso_date(value: Any) -> str | None:
    v = str(value or "").strip()
    m = re.match(r"^(\d{2})/(\d{2})/(\d{4})$", v) or re.match(r"^(\d{4})-(\d{2})-(\d{2})", v)
    if not m:
        return None
    a, b, c = m.groups()
    y, mo, d = (c, b, a) if len(a) == 2 else (a, b, c)
    try:
        return date(int(y), int(mo), int(d)).isoformat()
    except ValueError:
        return None


def _money(v: Any) -> float | None:
    t = str(v or "").replace("R$", "").replace(" ", "")
    if not t:
        return None
    if "," in t:
        t = t.replace(".", "").replace(",", ".")
    try:
        return float(t)
    except ValueError:
        return None


def cnpj_check_digits(base12: str) -> str:
    vals = [ord(c) - 48 for c in base12]
    for n in (12, 13):
        total = sum(v * (((n - 1 - i) % 8) + 2) for i, v in enumerate(vals[:n]))
        r = total % 11
        vals.append(0 if r < 2 else 11 - r)
    return f"{vals[12]}{vals[13]}"


def normalize_cnpj(value: Any) -> str | None:
    s = re.sub(r"[\s./\-]", "", str(value or "")).upper()
    if not re.fullmatch(r"[0-9A-Z]{12}[0-9]{2}", s) or len(set(s)) == 1:
        return None
    return s if cnpj_check_digits(s[:12]) == s[12:] else None


def format_cnpj(c: str | None) -> str:
    return f"{c[:2]}.{c[2:5]}.{c[5:8]}/{c[8:12]}-{c[12:]}" if c and len(c) == 14 else (c or "")


_MASKED_CPF = re.compile(r"^\*{3}\.?\d{3}\.?\d{3}-?\*{2}$")


def mask_cpf(value: Any) -> str | None:
    """Full CPF -> ***.456.789-** (AR24); an already masked value is kept as published; else None."""
    v = str(value or "").strip()
    if _MASKED_CPF.fullmatch(v):
        return v
    d = re.sub(r"\D", "", v)
    return f"***.{d[3:6]}.{d[6:9]}-**" if len(d) == 11 else None


LEGAL_SUFFIXES = frozenset({
    "LTDA", "LIMITADA", "EIRELI", "ME", "EPP", "MEI", "CIA", "COMPANHIA", "LTD", "LLC", "INC", "GMBH", "CORP", "CORPORATION", "LIMITED",
    "SA", "SAS", "SPA", "SRL", "PLC", "BV", "NV", "AG",
})
NAME_PARTICLES = frozenset({"DA", "DE", "DO", "DAS", "DOS", "E", "D"})


def name_key(name: Any, *, company: bool) -> str:
    """Normalised matching key: folded, punctuation-free; companies also lose trailing legal suffixes
    (LTDA, S.A., EIRELI, ME, EPP...)."""
    toks = re.sub(r"[^A-Z0-9 ]", " ", fold(name)).split()
    if company:
        while toks:
            if toks[-1] in LEGAL_SUFFIXES:
                toks.pop()
            elif len(toks) >= 2 and toks[-2:] == ["S", "A"]:
                del toks[-2:]
            else:
                break
    return " ".join(toks)


def block_key(key: str) -> str:
    """Candidate block of a name key: first and last significant tokens."""
    toks = [t for t in key.split() if t not in NAME_PARTICLES] or key.split()
    return f"{toks[0]}|{toks[-1]}" if toks else ""


def name_score(a: str, b: str, *, person: bool = True) -> float:
    """Similarity in [0, 1] of two name keys: the shared P219 token-set Jaro-Winkler (persons compared as
    persons, companies as organisations); a token-sort ratio only while the shared matcher is absent."""
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    if _shared_jw is not None and _shared_tokens is not None:
        kind = "person" if person else "entity"
        return round(float(_shared_jw(_shared_tokens(a, kind), _shared_tokens(b, kind))), 3)
    return round(difflib.SequenceMatcher(None, " ".join(sorted(a.split())), " ".join(sorted(b.split()))).ratio(), 3)


# --------------------------------------------------------------------------------------
# rows (P240 cond 6: persons = name + masked CPF + sanction facts)
# --------------------------------------------------------------------------------------


def _sanction_row(list_key: str, rec: dict[str, str], file_date: str) -> dict[str, Any]:
    digits = re.sub(r"\D", "", rec.get("doc", ""))
    ptype = rec.get("person_type", "").strip().upper()
    if ptype not in ("F", "J"):
        ptype = "F" if len(digits) == 11 else "J" if len(digits) == 14 else ""
    base: dict[str, Any] = {
        "list": list_key, "sanction_id": rec.get("sanction_id") or None, "person_type": ptype, "category": rec.get("category") or None,
        "start": iso_date(rec.get("start")), "end": iso_date(rec.get("end")), "organ": rec.get("organ") or None,
        "organ_uf": rec.get("organ_uf") or None, "sphere": rec.get("sphere") or None, "scope": rec.get("scope") or None,
        "file_date": file_date,
    }
    if ptype == "F":
        base.update({"cpf_masked": mask_cpf(digits) if len(digits) == 11 else None, "name": rec.get("name") or rec.get("name_informed") or None,
                     "cnpj": None, "cnpj_root": None})
    else:
        cnpj = normalize_cnpj(digits) if len(digits) == 14 else None
        base.update({
            "cnpj": cnpj, "cnpj_root": cnpj[:8] if cnpj else None, "id_malformed": bool(digits) and not cnpj,
            "name": rec.get("rfb_name") or rec.get("name") or rec.get("name_informed") or None, "process": rec.get("process") or None,
            "published": iso_date(rec.get("published")), "res_judicata": iso_date(rec.get("res_judicata")),
            "legal_basis": (rec.get("legal_basis") or "")[:300] or None,
        })
        if "fine" in rec:
            base["fine"] = _money(rec.get("fine"))
    return base


def _rows(path: Path, cols: dict[str, str], required: tuple[str, ...]) -> Any:
    """Stream the rows of one extracted ';' cp1252 CSV as {canonical key: value}. Raises ValueError when
    required columns are missing."""
    with open(path, encoding="cp1252", errors="replace", newline="") as fh:
        reader = csv.reader(fh, delimiter=";", quotechar='"')
        try:
            header = [header_key(h) for h in next(reader)]
        except StopIteration:
            raise ValueError(f"{path.name} is empty") from None
        missing = [c for c in required if c not in header]
        if missing:
            raise ValueError(f"{path.name} lacks the columns {missing[:4]}")
        keys = [cols.get(h) for h in header]
        for row in reader:
            if not any(c.strip() for c in row):
                continue
            if len(row) != len(keys):
                continue  # a broken line is skipped, never guessed
            yield {k: v.strip() for k, v in zip(keys, row) if k}


def iter_rows(list_key: str, files: dict[str, Path], file_label: str) -> Any:
    """Normalised rows of one validated list (``files``: member name -> extracted path)."""
    spec = LISTS[list_key]
    fd = iso_date(f"{file_label[6:8]}/{file_label[4:6]}/{file_label[:4]}") if len(file_label) == 8 else f"{file_label[:4]}-{file_label[4:6]}"
    members = [m.format(d=file_label) for m in spec.members]
    first = files[members[0]]
    if list_key in ("ceis", "cnep"):
        for rec in _rows(first, SANCTION_COLS, spec.required):
            yield _sanction_row(list_key, rec, fd or file_label)
    elif list_key == "cepim":
        for rec in _rows(first, CEPIM_COLS, spec.required):
            digits = re.sub(r"\D", "", rec.get("doc", ""))
            cnpj = normalize_cnpj(digits) if len(digits) == 14 else None
            yield {"list": "cepim", "sanction_id": rec.get("agreement") or None, "person_type": "J", "cnpj": cnpj,
                   "cnpj_root": cnpj[:8] if cnpj else None, "id_malformed": bool(digits) and not cnpj, "name": rec.get("name") or None,
                   "category": "Impedimento (CEPIM)", "reason": rec.get("reason") or None, "organ": rec.get("organ") or None,
                   "start": None, "end": None, "file_date": fd}
    elif list_key == "acordos_leniencia":
        effects: dict[str, list[dict[str, Any]]] = {}
        for rec in _rows(files[members[1]], EFEITOS_COLS, spec.required_second):
            effects.setdefault(rec.get("agreement_id") or "", []).append({"effect": rec.get("effect") or None,
                                                                          "complement": rec.get("complement") or None})
        for rec in _rows(first, LENIENCIA_COLS, spec.required):
            doc = rec.get("doc", "")
            digits = re.sub(r"\D", "", doc)
            cnpj = normalize_cnpj(digits) if len(digits) == 14 else None
            yield {"list": "acordos_leniencia", "sanction_id": rec.get("agreement_id") or None, "person_type": "J", "cnpj": cnpj,
                   "cnpj_root": cnpj[:8] if cnpj else None,
                   "foreign_token": doc if (not cnpj and re.fullmatch(r"EX[A-Za-z0-9]+", doc)) else None, "name": rec.get("name") or None,
                   "category": "Acordo de leniencia", "situation": rec.get("situation") or None, "start": iso_date(rec.get("start")),
                   "end": iso_date(rec.get("end")), "organ": rec.get("organ") or None, "process": rec.get("process") or None,
                   "effects": effects.get(rec.get("agreement_id") or "", [])[:10], "file_date": fd}
    elif list_key == "pep":
        for rec in _rows(first, PEP_COLS, spec.required):
            yield {"list": "pep", "person_type": "F", "cpf_masked": mask_cpf(rec.get("cpf")), "name": rec.get("name") or None,
                   "role_code": rec.get("role_code") or None, "role": rec.get("role") or None, "level": rec.get("level") or None,
                   "organ": rec.get("organ") or None, "start": iso_date(rec.get("start")), "end": iso_date(rec.get("end")),
                   "grace_end": iso_date(rec.get("grace_end")), "file_date": fd}


# --------------------------------------------------------------------------------------
# validation + indexed store (the dataset manager's validate hook)
# --------------------------------------------------------------------------------------

_SCHEMA_SQL = (
    "CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT)",
    "CREATE TABLE rows (id INTEGER PRIMARY KEY, person_type TEXT, cnpj TEXT, cnpj_root TEXT, name_key TEXT, block TEXT, row_json TEXT NOT NULL)",
)
_INDEX_SQL = (
    "CREATE INDEX ix_rows_cnpj ON rows(cnpj)",
    "CREATE INDEX ix_rows_root ON rows(cnpj_root)",
    "CREATE INDEX ix_rows_name ON rows(name_key)",
    "CREATE INDEX ix_rows_block ON rows(block)",
)


def _zip_members(list_key: str, path: Path) -> tuple[str, list[zipfile.ZipInfo]]:
    """The file label and member infos of a downloaded zip; ValueError unless the member set is exactly
    the expected one for that file date (P240 cond 2, prep H3)."""
    spec = LISTS[list_key]
    with open(path, "rb") as fh:
        if fh.read(4) != b"PK\x03\x04":
            raise ValueError("not a zip archive (an HTML page or a truncated download?)")
    try:
        with zipfile.ZipFile(path) as zf:
            infos = [i for i in zf.infolist() if not i.is_dir()]
    except (zipfile.BadZipFile, OSError, EOFError) as exc:
        raise ValueError(f"unreadable zip archive: {type(exc).__name__}") from None
    labels = {m.group(1) for m in (re.match(spec.member_re, i.filename) for i in infos) if m}
    if len(labels) != 1:
        raise ValueError(f"unexpected members {sorted(i.filename for i in infos)[:5]} for {spec.label}")
    label = labels.pop()
    expected = sorted(m.format(d=label) for m in spec.members)
    if sorted(i.filename for i in infos) != expected:
        raise ValueError(f"unexpected members {sorted(i.filename for i in infos)[:5]} (expected {expected})")
    for i in infos:
        if i.file_size > spec.max_member_bytes:
            raise ValueError(f"member {i.filename} larger than {spec.max_member_bytes} bytes")
        if i.file_size > MB and i.file_size > max(i.compress_size, 1) * MAX_RATIO:
            raise ValueError(f"member {i.filename} compression ratio above {MAX_RATIO}:1 (zip bomb?)")
    return label, infos


def _published(infos: list[zipfile.ZipInfo]) -> str | None:
    try:
        y, m, d = infos[0].date_time[:3]
        return date(y, m, d).isoformat()
    except (IndexError, ValueError):
        return None


def build_store(list_key: str, path: Path, *, min_rows: int | None = None) -> dict[str, Any]:
    """Validate a downloaded list zip at ``path`` and replace it, in place, with the indexed SQLite store
    (the dataset copy the module reads). Fail closed: any problem raises ValueError and the dataset
    manager keeps the previous copy. Returns the store metadata."""
    spec = LISTS[list_key]
    path = Path(path)
    label, infos = _zip_members(list_key, path)
    work = Path(tempfile.mkdtemp(prefix=".cgu-x-", dir=str(path.parent)))
    db_tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.sqlite")
    try:
        safe_extract(path, "zip", work, max_total=spec.max_member_bytes * len(spec.members), max_ratio=MAX_RATIO,
                     max_members=len(spec.members))
        files = {i.filename: work / i.filename for i in infos}
        fd = os.open(db_tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        conn = sqlite3.connect(str(db_tmp))
        try:
            for sql in _SCHEMA_SQL:
                conn.execute(sql)
            count = 0
            batch: list[tuple[Any, ...]] = []
            company = spec.companies
            for row in iter_rows(list_key, files, label):
                is_company = row.get("person_type") == "J" or (company and not spec.persons)
                key = name_key(row.get("name"), company=is_company)
                batch.append((row.get("person_type"), row.get("cnpj"), row.get("cnpj_root"), key or None, block_key(key) or None,
                              json.dumps(row, ensure_ascii=False)))
                count += 1
                if len(batch) >= 5000:
                    conn.executemany("INSERT INTO rows (person_type, cnpj, cnpj_root, name_key, block, row_json) VALUES (?,?,?,?,?,?)", batch)
                    batch.clear()
            if batch:
                conn.executemany("INSERT INTO rows (person_type, cnpj, cnpj_root, name_key, block, row_json) VALUES (?,?,?,?,?,?)", batch)
            needed = MIN_ROWS.get(list_key, spec.min_rows) if min_rows is None else min_rows
            if count < needed:
                raise ValueError(f"{spec.label}: {count} rows (< {needed}): incomplete or unexpected file")
            for sql in _INDEX_SQL:
                conn.execute(sql)
            meta = {
                "schema": STORE_SCHEMA, "list": list_key, "file_label": label,
                "file_date": iso_date(f"{label[6:8]}/{label[4:6]}/{label[:4]}") if len(label) == 8 else f"{label[:4]}-{label[4:6]}",
                "published": _published(infos), "rows": str(count), "members": ",".join(sorted(files)),
                "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            conn.executemany("INSERT INTO meta (k, v) VALUES (?, ?)", list(meta.items()))
            conn.commit()
        finally:
            conn.close()
        os.replace(db_tmp, path)
        return meta
    except (csv.Error, UnicodeError, sqlite3.Error, OSError) as exc:
        raise ValueError(f"{spec.label}: {type(exc).__name__}: {str(exc)[:160]}") from None
    finally:
        shutil.rmtree(work, ignore_errors=True)
        if db_tmp.exists():
            db_tmp.unlink()


def _validator(list_key: str) -> Any:
    def validate(path: Path) -> bool:
        build_store(list_key, path)
        return True

    validate.__name__ = f"build_{list_key}_store"
    return validate


# --------------------------------------------------------------------------------------
# dataset registration and the walk-back updater (P240 cond 1)
# --------------------------------------------------------------------------------------


def candidate_labels(list_key: str, today: date) -> list[str]:
    """File labels to try, newest first: daily lists today .. today-7 (YYYYMMDD); PEP this month and
    the two before (YYYYMM: a 7-day walk never reaches last month's file, prep H5)."""
    spec = LISTS[list_key]
    if spec.cadence == "monthly":
        y, m, out = today.year, today.month, []
        for _ in range(MAX_BACK_MONTHS + 1):
            out.append(f"{y:04d}{m:02d}")
            m -= 1
            if m == 0:
                y, m = y - 1, 12
        return out
    return [(today - timedelta(days=i)).strftime("%Y%m%d") for i in range(MAX_BACK_DAYS + 1)]


def default_label(list_key: str, now: datetime) -> str:
    """The newest file known to be published at ``now`` (prep publication times: CEIS, CNEP and the
    leniency agreements at ~21:18 UTC of their date, CEPIM the next day, PEP mid next month)."""
    spec = LISTS[list_key]
    today = now.astimezone(timezone.utc).date()
    if spec.cadence == "monthly":
        y, m = today.year, today.month - (1 if today.day >= 20 else 2)
        while m <= 0:
            y, m = y - 1, m + 12
        return f"{y:04d}{m:02d}"
    return (today - timedelta(days=spec.lag_days)).strftime("%Y%m%d")


def dataset_url(list_key: str, label: str) -> str:
    return PORTAL_URL.format(slug=LISTS[list_key].slug, d=label)


def register_list(list_key: str, label: str) -> str:
    """(Re-)register the dataset of one list for one file label."""
    spec = LISTS[list_key]
    unregister_dataset(spec.dataset)
    return register_dataset(
        spec.dataset, dataset_url(list_key, label), ttl=(30 if spec.cadence == "monthly" else 1) * 86400,
        description=f"CGU {spec.label} bulk file (indexed locally; refreshed by `v3lum data update`, never during a scan)",
        licence=LICENCE, terms_class="open", attribution=ATTRIBUTION, provider="transparencia", source=spec.source,
        validate=_validator(list_key), min_bytes=200, expect="bytes", max_bytes=64 * MB, large=True,
    )


_NOW = datetime.now(timezone.utc)
for _key in LIST_ORDER:
    register_list(_key, default_label(_key, _NOW))


def _missing(reason: str) -> bool:
    text = str(reason or "")
    return "HTTP 404" in text or "not published" in text


def update_lists(store: DataStore, lists: tuple[str, ...] | None = None, *, now: datetime | None = None) -> list[UpdateResult]:
    """``v3lum data update cgu``: refresh each list through the dataset manager, walking back from today
    (daily lists: at most 7 days; PEP: two months) while the file is not published (404, or S3 403
    AccessDenied). Any other failure stops the walk and keeps the previous copy."""
    when = now or datetime.now(timezone.utc)
    out: list[UpdateResult] = []
    for key in lists or LIST_ORDER:
        if key not in LISTS:
            out.append(UpdateResult(f"cgu_sanctions_bulk.{key}", "failed", reason="unknown CGU list"))
            continue
        result: UpdateResult | None = None
        for label in candidate_labels(key, when.astimezone(timezone.utc).date()):
            register_list(key, label)
            result = store.update(LISTS[key].dataset)
            if result.ok or not _missing(result.reason):
                break
        if result is not None:
            out.append(result)
    return out


# --------------------------------------------------------------------------------------
# reading the local stores (never downloads)
# --------------------------------------------------------------------------------------


class ListStore:
    """Read-only view of one installed list store."""

    def __init__(self, path: Path) -> None:
        self.conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
        self.meta = dict(self.conn.execute("SELECT k, v FROM meta").fetchall())

    def close(self) -> None:
        self.conn.close()

    def by_cnpj(self, cnpj: str) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT row_json FROM rows WHERE cnpj = ? OR cnpj_root = ? LIMIT 200", (cnpj, cnpj[:8])).fetchall()
        return [json.loads(r[0]) for r in rows]

    def by_name(self, key: str, *, person: bool) -> list[dict[str, Any]]:
        ptype = "F" if person else "J"
        rows = self.conn.execute(
            "SELECT row_json, name_key FROM rows WHERE (name_key = ? OR block = ?) AND person_type = ? LIMIT ?",
            (key, block_key(key), ptype, MAX_BLOCK_ROWS),
        ).fetchall()
        out = []
        for raw, cand in rows:
            score = name_score(key, cand or "", person=person)
            if score >= MIN_NAME_SCORE:
                row = json.loads(raw)
                row["_score"] = score
                out.append(row)
        out.sort(key=lambda r: -r["_score"])
        return out[:MAX_NAME_CANDIDATES]


def open_list(ctx: Any, list_key: str) -> tuple[ListStore | None, str]:
    """The installed store of a list (never downloads) or (None, why it is not screened)."""
    spec = LISTS[list_key]
    hint = f"run v3lum data update {spec.dataset}"
    try:
        info = ctx.data.info(spec.dataset)
    except (ValueError, OSError):
        return None, f"not screened against {spec.label} (dataset unreadable: {hint})"
    if not getattr(info, "present", False):
        return None, f"not screened against {spec.label} (dataset missing: {hint})"
    path = ctx.data.store.path(spec.dataset)
    try:
        store = ListStore(path)
    except sqlite3.Error:
        return None, f"not screened against {spec.label} (local copy unreadable: {hint})"
    if store.meta.get("schema") != STORE_SCHEMA or store.meta.get("list") != list_key:
        store.close()
        return None, f"not screened against {spec.label} (local copy is not an indexed CGU store: {hint})"
    used = getattr(ctx.data, "used", None)
    if isinstance(used, list) and not any(isinstance(c, dict) and c.get("name") == spec.dataset for c in used):
        used.append({"name": spec.dataset, "sha256": getattr(info, "sha256", ""), "fetched_at": getattr(info, "fetched_at", ""),
                     "licence": getattr(info, "licence", "")})
    return store, ""


def staleness(list_key: str, meta: dict[str, str], today: date) -> str | None:
    """P240 cond 8: 'not screened against <list> (<date>)' when the copy is older than 3 days (PEP: 40
    days from its publication date), else None."""
    spec = LISTS[list_key]
    label = meta.get("file_date") or meta.get("file_label") or "unknown date"
    if spec.cadence == "monthly":
        ref = iso_date(meta.get("published")) or _month_end_plus(meta.get("file_label", ""), 16)
        limit = STALE_DAYS_MONTHLY
    else:
        ref = iso_date(meta.get("file_date"))
        limit = STALE_DAYS
    if not ref:
        return f"not screened against {spec.label} (file date unknown)"
    if (today - date.fromisoformat(ref)).days > limit:
        return f"not screened against {spec.label} ({label})"
    return None


def _month_end_plus(label: str, days: int) -> str | None:
    if not re.fullmatch(r"\d{6}", label or ""):
        return None
    y, m = int(label[:4]), int(label[4:])
    first_next = date(y + (m == 12), m % 12 + 1, 1)
    return (first_next - timedelta(days=1) + timedelta(days=days)).isoformat()


def sanction_status(row: dict[str, Any], today: date) -> str:
    """in_force | expired. No end date = in force (indefinite); CEPIM rows are in force while listed;
    leniency agreements 'Cumprido' or past their end are expired."""
    if row.get("list") == "cepim":
        return "in_force"
    if row.get("list") == "acordos_leniencia" and fold(row.get("situation")) == "CUMPRIDO":
        return "expired"
    end = iso_date(row.get("end"))
    if not end:
        return "in_force"
    return "in_force" if date.fromisoformat(end) >= today else "expired"


def dedup_key(list_key: str, cnpj: str | None, sanction_id: str | None) -> str:
    return f"{list_key}|{cnpj or ''}|{sanction_id or ''}"


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class CguSanctionsBulk(Module):
    name = "cgu_sanctions_bulk"
    title = "CGU sanctions lists (offline: CEIS, CNEP, CEPIM, leniency, PEP)"
    description = (
        "Local screening against the CGU bulk files (CEIS, CNEP, CEPIM, leniency agreements; PEP for purpose-bound person "
        "checks) downloaded by `v3lum data update`: exact CNPJ, CNPJ root and name matches, with the file date in every finding."
    )
    category = "brazil_public_data"
    accepts = {T.CNPJ, T.ORG, T.PERSON}
    produces: set[Any] = set()
    tags = {"brazil", "offline", "free"}
    reference = "https://portaldatransparencia.gov.br/download-de-dados"
    notice = (
        "Offline matching (nothing is sent). Person names are screened only for analyst-typed subjects or QSA partners in a "
        "case with a recorded purpose, as 'possible match' lowered by the homonym score; CPFs are masked at ingestion and "
        "never used as keys. A missing or stale list reads 'not screened against <list>', never 'not sanctioned'."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = tuple(LISTS[k].source for k in LIST_ORDER)
    access_model = "offline"
    expected_latency = 0.2  # indexed local SQLite lookups (CNPJ, root and name blocks), no network
    timeout = 30.0
    max_pivots = 0
    default_enabled = True  # A3: CGU sanctions bulk lists matched locally are default-on by decision

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        today = ctx.now().date()
        if entity.type is T.PERSON:
            refusal = self._person_refusal(ctx)
            if refusal:
                return res.mark(Status.SKIPPED, refusal, reason_code="privacy")
            lists = PERSON_LISTS
        else:
            lists = COMPANY_LISTS
        screening: dict[str, dict[str, Any]] = {}
        matches_raw: list[dict[str, Any]] = []
        usable = 0
        homonym_cache: dict[str, Any] = {}
        for key in lists:
            spec = LISTS[key]
            store, problem = open_list(ctx, key)
            if store is None:
                screening[key] = {"state": "not_screened", "file_date": None, "reason": problem}
                res.source_status(spec.source, Status.UNAVAILABLE, reason_code="dataset", reason=problem)
                continue
            usable += 1
            try:
                meta = store.meta
                stale = staleness(key, meta, today)
                if entity.type is T.CNPJ:
                    found = self._cnpj(res, entity.value, key, store, today, stale)
                elif entity.type is T.ORG:
                    found = self._names(res, ctx, str(entity.value), key, store, person=False, stale=stale, cache=homonym_cache)
                else:
                    found = self._names(res, ctx, str(entity.value), key, store, person=True, stale=stale, cache=homonym_cache)
            except (sqlite3.Error, ValueError) as exc:
                store.close()
                reason = f"not screened against {spec.label} (local copy unreadable: {type(exc).__name__})"
                screening[key] = {"state": "not_screened", "file_date": meta.get("file_date"), "reason": reason}
                res.source_status(spec.source, Status.ERROR, reason=reason)
                continue
            store.close()
            matches_raw.extend(found)
            file_date = meta.get("file_date")
            if found:
                screening[key] = {"state": "listed", "file_date": file_date, "reason": stale or ""}
                res.source_status(spec.source, Status.OK, reason=f"{len(found)} listing(s) in {spec.label} as of {file_date}")
            elif stale:
                screening[key] = {"state": "not_screened", "file_date": file_date, "reason": stale}
                res.source_status(spec.source, Status.UNAVAILABLE, reason_code="dataset", reason=stale)
            else:
                screening[key] = {"state": "no_record", "file_date": file_date, "reason": f"no record in {spec.label} as of {file_date}"}
                res.source_status(spec.source, Status.EMPTY, reason=f"no record in {spec.label} as of {file_date}")
        res.attr("sanctions_screening", screening)
        res.raw = {"screening": screening, "matches": matches_raw}  # only matched rows enter the case (cond 6)
        if not usable:
            return res.mark(Status.UNAVAILABLE, "not screened: the CGU lists were never downloaded - run v3lum data update "
                            "(cgu_sanctions_bulk.*); never read as 'not sanctioned'", reason_code="dataset")
        return res

    # ------------------------------------------------------------------ gates
    @staticmethod
    def _person_refusal(ctx: Any) -> str:
        """P240 cond 5 legal floor: analyst-typed subjects or QSA partners, in a case with a recorded purpose."""
        if not str(getattr(ctx, "purpose", "") or "").strip():
            return "person-name screening runs only in a case with a recorded purpose (due diligence, --purpose)"
        if getattr(ctx, "is_seed", False):
            return ""
        prov = tuple(getattr(ctx, "provenance", ()) or ())
        last = prov[-1] if prov else ()
        if len(last) >= 2 and last[1] == "partner_of":
            return ""
        return "person names found as pivots are never screened automatically (only analyst-typed subjects or QSA partners)"

    # ------------------------------------------------------------------ CNPJ (cond 3)
    def _cnpj(self, res: ModuleResult, cnpj: str, key: str, store: ListStore, today: date, stale: str | None) -> list[dict[str, Any]]:
        spec = LISTS[key]
        found: list[dict[str, Any]] = []
        for row in store.by_cnpj(cnpj):
            if row.get("person_type") == "F" or not row.get("cnpj"):
                continue
            exact = row["cnpj"] == cnpj
            status = sanction_status(row, today)
            what = row.get("category") or spec.label
            file_date = row.get("file_date")
            dates = f"start {row.get('start') or 'not stated'}, end {row.get('end') or 'none (indefinite)'}"
            if exact and status == "in_force":
                title, sev, conf = f"Listed in {spec.label} (in force)", "high", "confirmed"
            elif exact:
                title, sev, conf = f"Formerly listed in {spec.label}", "info", "confirmed"
            elif status == "in_force":
                title, sev, conf = f"Related establishment listed in {spec.label} (in force)", "medium", "probable"
            else:
                title, sev, conf = f"Related establishment formerly listed in {spec.label}", "info", "probable"
            match_type = "exact_cnpj" if exact else "cnpj_root"
            subject = "this CNPJ" if exact else f"another establishment of the same company ({format_cnpj(row['cnpj'])}, same CNPJ root)"
            state = "formerly sanctioned ({})".format(row.get("end") or "end date not stated") if status == "expired" else "sanction in force"
            desc = (f"{spec.label} lists {subject}: {what}" + (f" by {row['organ']}" if row.get("organ") else "") + f" ({dates}); {state}. "
                    f"Match type: {match_type}. List as of {file_date}.")
            if key == "acordos_leniencia":
                desc += f" Agreement situation: {row.get('situation') or 'not stated'} (a leniency agreement, not a penalty by itself)."
            res.finding(
                title, sev, desc,
                confidence=conf,
                criterion=f"{'exact 14-character' if exact else '8-character root'} CNPJ match in the CGU {spec.label} file of "
                          f"{file_date}; {state}",
                data={"list": key, "match_type": match_type, "matched_cnpj": row["cnpj"], "sanction_id": row.get("sanction_id"),
                      "sanction_type": what, "organ": row.get("organ"), "start": row.get("start"), "end": row.get("end"), "status": status,
                      "file_date": file_date, "stale_list": bool(stale), "link": spec.link,
                      "dedup_key": dedup_key(key, row["cnpj"], row.get("sanction_id")), "fine": row.get("fine"),
                      "situation": row.get("situation"), "effects": row.get("effects")},
                tags=["sanctions"],
                references=[spec.link],
                source=spec.source,
                observed_first=row.get("start"),
                observed_last=file_date,
                key=f"{key}:{row.get('sanction_id') or ''}:{row['cnpj']}",
            )
            if exact and status == "in_force":
                res.attr("sanctioned", True)
            found.append({k: v for k, v in row.items() if k != "legal_basis"})
        return found

    # ------------------------------------------------------------------ names (cond 5-7)
    def _names(self, res: ModuleResult, ctx: Any, name: str, key: str, store: ListStore, *, person: bool, stale: str | None,
               cache: dict[str, Any]) -> list[dict[str, Any]]:
        spec = LISTS[key]
        qkey = name_key(name, company=not person)
        if not qkey:
            return []
        rows = store.by_name(qkey, person=person)
        if not rows:
            return []
        h = None
        if person:
            if "h" not in cache:
                cache["h"] = homonym_risk(name, table=offline_table(ctx.data.store, used=ctx.data.used))
            h = cache["h"]
        found: list[dict[str, Any]] = []
        for i, row in enumerate(rows):
            score = float(row.pop("_score", 0.0))
            base = min(NAME_CONFIDENCE_CAP, NAME_CONFIDENCE_CAP * score)
            conf = apply_homonym_curve(base, h) if h else round(base, 3)
            file_date = row.get("file_date")
            data: dict[str, Any] = {
                "list": key, "match_type": "name_only", "matched_name": row.get("name"), "score": score, "file_date": file_date,
                "stale_list": bool(stale), "link": spec.link, "name_type": "person_name" if person else "company_name",
            }
            if h:
                data.update(homonym={k: h[k] for k in ("risk", "factor", "phrase")}, homonym_applied=True)
            homonym_text = f"; homonym risk {h['risk']} ({h['phrase']})" if h else ""
            if key == "pep":
                data.update(cpf_as_published=row.get("cpf_masked"), role=row.get("role"), organ=row.get("organ"), start=row.get("start"),
                            end=row.get("end"), grace_end=row.get("grace_end"))
                res.finding(
                    "PEP (possible match)", "info",
                    f"The CGU PEP file of {file_date} lists '{row.get('name')}' ({row.get('role') or 'role not stated'}, "
                    f"{row.get('organ') or 'organ not stated'}): a name-only possible match, context only - never a risk by itself. "
                    f"CPF as published: {row.get('cpf_masked') or 'not stated'}.",
                    confidence=conf,
                    criterion=f"name-only match ({MATCHER} {score:.2f} >= {MIN_NAME_SCORE}) against the CGU PEP file of "
                              f"{file_date}; no identifier compared{homonym_text}",
                    data=data, tags=["pep", "name_only_match", "context_only", "privacy"], references=[spec.link], source=spec.source,
                    observed_last=file_date, key=f"pep:{i}",
                )
            else:
                status = sanction_status(row, ctx.now().date())
                data.update(sanction_id=row.get("sanction_id"), sanction_type=row.get("category"), organ=row.get("organ"),
                            start=row.get("start"), end=row.get("end"), status=status,
                            dedup_key=dedup_key(key, row.get("cnpj"), row.get("sanction_id")))
                if person:
                    data["cpf_as_published"] = row.get("cpf_masked")
                else:
                    data["matched_cnpj"] = row.get("cnpj")
                severity = "info" if (h and h.get("risk") == "high") or status == "expired" else "medium"
                who = "person" if person else "company"
                ident = (f" CPF as published (masked): {row.get('cpf_masked') or 'not stated'}." if person
                         else f" Listed CNPJ: {format_cnpj(row.get('cnpj')) or 'not stated'} - compare identifiers.")
                res.finding(
                    f"Possible match in {spec.label} ({who} name only)", severity,
                    f"{spec.label} (file of {file_date}) lists '{row.get('name')}': {row.get('category') or spec.label}"
                    + (f" by {row['organ']}" if row.get("organ") else "") + f", {status.replace('_', ' ')}. Possible match - verify "
                    f"identifiers before relying on it.{ident}",
                    confidence=conf,
                    criterion=f"name-only match ({MATCHER} {score:.2f} >= {MIN_NAME_SCORE}) against the CGU {spec.label} "
                              f"file of {file_date}; no identifier compared{homonym_text}",
                    data=data, tags=["sanctions", "name_only_match"] + (["privacy"] if person else []), references=[spec.link],
                    source=spec.source, observed_last=file_date, key=f"{key}:{row.get('sanction_id') or i}",
                )
            found.append({k: v for k, v in row.items() if k not in ("legal_basis", "process")})
        return found


__all__ = [
    "LISTS",
    "LIST_ORDER",
    "MIN_ROWS",
    "CguSanctionsBulk",
    "build_store",
    "candidate_labels",
    "default_label",
    "name_key",
    "name_score",
    "register_list",
    "sanction_status",
    "staleness",
    "update_lists",
]
