"""P244 ``br_cnpj_risk_lists`` - BR offline risk lists by CNPJ or company name.

Batch p3-G10-2. Lists (each its own dataset and refresh, fetched only by ``v3lum data update``, never mid-scan;
matched locally, disclosure 'none'):

* **MTE 'lista suja'** (Cadastro de Empregadores, www.gov.br, weekly, ';' ISO-8859-1): dataset
  ``mte_lista_suja.csv`` - HIGH (labour/ESG).
* **CVM** through the one CVM loader shared with P360/P361 (``cvm_registries``): the company registries
  (intermediaries, portfolio managers, advisers, crowdfunding platforms; registered by P360), the listed-company
  register ``cvm_cia_aberta.csv`` (registered by P361) and the sanctioning proceedings
  ``cvm_processo_sancionador.zip`` (registered here, daily) - a proceeding is MEDIUM.
* **BrasilAPI CVM brokers** list ``brasilapi_cvm_corretoras.json`` (daily, tier community).
* **PGFN divida ativa** - opt-in, imported separately by ``pgfn_import`` (multi-GB quarterly zips streamed into
  an on-disk SQLite index keyed by CNPJ root, never in memory, not part of the default update set) - LOW context.

Council P244 final conditions, as implemented here:

1. One dataset per list with its own TTL; every reader uses the local copy only (:func:`_local_copy` never
   downloads), so nothing is fetched during a scan. The CAPTCHA-protected listadevedores.pgfn.gov.br application
   is never used and CVM stop orders (HTML news) are not automated.
2. PGFN: see ``pgfn_import`` (opt-in, streamed, on-disk index keyed by CNPJ root).
3. Structural minimisation: natural-person rows (CPF employers, CPF debtors, CVM accused persons - the accused
   file has no document column, so a legal-form heuristic decides and fails closed) are dropped when a copy is
   parsed unless setting ``br_cnpj_risk_lists_include_persons`` is set (recorded in every result). With it, an
   analyst-typed PERSON seed with a recorded purpose is matched by NAME only (possible match, P252 homonym
   score); a CPF is never a lookup key, is shown masked and is never pivoted. MEI rows keep the CNPJ but never the
   entrepreneur's name.
4. Matching is local through the shared name matcher (``company_org.namematch``); exact CNPJ (or root, stated)
   and exact-name matches produce findings with list, amount band and date; only matched rows enter the case.
5. Severity table (documented and tested, :data:`SEVERITY`): MTE lista suja HIGH; CVM sanction proceeding MEDIUM;
   PGFN divida ativa LOW context with debt nature, amount band and situation; CVM registrations INFO.
6. The CVM registries and the BrasilAPI broker list answer 'is this broker/adviser/platform authorised?' by CNPJ
   or exact name (attribute ``cvm_authorisation``); absence reads 'not found in CVM registries as of <date>',
   never fraud.
7. A missing or stale copy reads 'not screened against <list> (<date>)' (per-source UNAVAILABLE reason_code
   'dataset'), never 'clean'; with no list screened at all the run is UNAVAILABLE 'dataset'. Tiers: PGFN, MTE and
   CVM trusted, BrasilAPI community; CVM ODbL share-alike applies only if redistributed (nothing is exported).
8. Fixtures: real headers/encodings/member names with synthetic identities (tests/fixtures/br_cnpj_risk_lists/).
"""

from __future__ import annotations

import csv
import io
import json
import re
import threading
import unicodedata
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from v3lum.core import validators
from v3lum.core.datasets import DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.brazil_public_data import cvm_registries as cvm
from v3lum.modules.brazil_public_data import pgfn_import as pgfn
from v3lum.modules.company_org import namematch

MODULE = "br_cnpj_risk_lists"
SOURCE_MTE = "govbr.br_cnpj_risk_lists_mte"
SOURCE_CVM = cvm.SOURCE  # cvm.cadastral: the shared CVM loader (P360)
SOURCE_CVM_CIA = "cvm.cnpj_name_resolver_cia_aberta"  # listed-company register (registered by P361 cnpj_name_resolver)
SOURCE_SANCTIONS = "cvm.sanctions"
SOURCE_BROKERS = "brasilapi.cvm_brokers"
SOURCE_PGFN = pgfn.SOURCE

MTE_DATASET = "mte_lista_suja.csv"
MTE_URL = ("https://www.gov.br/trabalho-e-emprego/pt-br/assuntos/inspecao-do-trabalho/areas-de-atuacao/"
           "cadastro_de_empregadores.csv")
SANCTIONS_DATASET = "cvm_processo_sancionador.zip"
SANCTIONS_URL = "https://dados.cvm.gov.br/dados/PROCESSO/SANCIONADOR/DADOS/processo_sancionador.zip"
BROKERS_DATASET = "brasilapi_cvm_corretoras.json"
BROKERS_URL = "https://brasilapi.com.br/api/cvm/corretoras/v1"
CIA_DATASET = "cvm_cia_aberta.csv"
SMALL_MAX_BYTES = 5 * 1024 * 1024
SERVE_LOCAL_TTL = 100 * 365 * 86400.0

#: FC5 severity table (documented and tested)
SEVERITY = {
    "mte_lista_suja": "high",
    "cvm_sancionador": "medium",
    "pgfn_divida_ativa": "low",
    "cvm_registries": "info",
    "cvm_cia_aberta": "info",
    "brasilapi_corretoras": "info",
}
LIST_LABELS = {
    "mte_lista_suja": "MTE lista suja (Cadastro de Empregadores)",
    "cvm_sancionador": "CVM processos sancionadores",
    "pgfn_divida_ativa": "PGFN divida ativa",
    "cvm_registries": "CVM registries (intermediaries, managers, advisers, crowdfunding)",
    "cvm_cia_aberta": "CVM listed companies (companhias abertas)",
    "brasilapi_corretoras": "CVM brokers (BrasilAPI)",
}
LIST_SOURCES = {
    "mte_lista_suja": SOURCE_MTE, "cvm_sancionador": SOURCE_SANCTIONS, "pgfn_divida_ativa": SOURCE_PGFN,
    "cvm_registries": SOURCE_CVM, "cvm_cia_aberta": SOURCE_CVM_CIA, "brasilapi_corretoras": SOURCE_BROKERS,
}
#: a copy older than this many hours is stale: 'not screened against <list> (<date>)' when nothing matched (FC7)
MAX_AGE_HOURS = {
    "mte_lista_suja": 14 * 24, "cvm_sancionador": 3 * 24, "cvm_registries": 3 * 24, "cvm_cia_aberta": 3 * 24,
    "brasilapi_corretoras": 3 * 24, "pgfn_divida_ativa": 100 * 24,
}
MAX_ROWS_SHOWN = 20

_WS = re.compile(r"\s+")
_HTML = re.compile(r"^\s*(?:<!doctype\s+html|<html\b|<head\b|<body\b|<\?xml\b)", re.I)
_FOOTNOTE = re.compile(r"\s*\((\*\d+)\)\s*$")
_MEI_NAME = re.compile(r"^\d{2}\.?\d{3}\.?\d{3}\s+\S")  # 'NN.NNN.NNN FULL NAME': individual entrepreneur (MEI)
_CPF_SHAPED = re.compile(r"^\s*\d{3}\.?\d{3}\.?\d{3}-?\d{2}\s*$")
_MTE_COLS = {"id": "id", "ano da acao fiscal": "year", "uf": "uf", "empregador": "name", "cnpj/cpf": "doc",
             "estabelecimento": "establishment", "trabalhadores envolvidos": "workers", "cnae": "cnae",
             "decisao administrativa de procedencia": "decision", "inclusao no cadastro de empregadores": "inclusion"}
_ENTITY_HINT = re.compile(
    r"(\bS\s*[./]\s*A\b|\bS\s*/\s*S\b)|\b(LTDA|EIRELI|EPP|CIA|COMPANHIA|BANCO|CORRETORA|DISTRIBUIDORA|DTVM|CCTVM|CTVM|CCVM|"
    r"ASSET|GESTORA|GESTAO|INVESTIMENTOS?|PARTICIPACOES|CAPITAL|FUNDOS?|FIDC|FII|FIP|FIA|HOLDING|AUDITORES|AUDITORIA|CONSULTORIA|"
    r"SECURITIZADORA|ADMINISTRADORA|ASSOCIACAO|COOPERATIVA|INC|LLC|LTD|LIMITED|CORP|CORPORATION|GROUP|GRUPO|PARTNERS|TRUST|"
    r"SOCIEDADE|INSTITUTO|EMPREENDIMENTOS|SERVICOS|COMERCIO|INDUSTRIA|BOLSA|CAMBIO|VALORES)\b")


# ======================================================================================
# small helpers
# ======================================================================================


def clean(value: Any) -> str:
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return ""
    return _WS.sub(" ", str(value)).strip()


def fold(value: Any) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", clean(value)) if not unicodedata.combining(c))


def org_key(name: Any) -> str:
    return namematch.normalized_name(clean(name))


def person_key(name: Any) -> str:
    return namematch.normalized_name(clean(name), "person")


def cnpj_normalize(value: Any) -> str | None:
    s = re.sub(r"[\s./-]", "", clean(value)).upper()
    return s if re.fullmatch(r"[0-9A-Z]{12}[0-9]{2}", s) and not s.isalpha() else None


def mask_cpf(value: Any) -> str | None:
    digits = re.sub(r"\D", "", clean(value))
    return f"***.{digits[3:6]}.{digits[6:9]}-**" if len(digits) == 11 else None


def _decode(raw: Any) -> str:
    if isinstance(raw, str):
        return raw.lstrip("﻿")
    data = bytes(raw or b"")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def parse_br_date(value: Any) -> str | None:
    return pgfn.parse_br_date(value)


# ======================================================================================
# MTE lista suja (FC1, FC3, FC4)
# ======================================================================================


def _mte_header_map(header: list[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for i, h in enumerate(header):
        k = fold(h).casefold()
        if k in _MTE_COLS:
            out[_MTE_COLS[k]] = i
    return out


def parse_inclusion_periods(value: Any) -> tuple[list[dict[str, Any]], str | None]:
    """'05/04/2024 a 10/05/2024, 09/04/2025' -> ([{from, to}], current inclusion date). Earlier periods are
    suspended inclusions (e.g. by court order); the last bare date is the current inclusion."""
    periods: list[dict[str, Any]] = []
    current = None
    for part in [p.strip() for p in str(value or "").split(",") if p.strip()]:
        m = re.fullmatch(r"(\d{2}/\d{2}/\d{4})\s+a\s+(\d{2}/\d{2}/\d{4})", part)
        if m:
            periods.append({"from": parse_br_date(m.group(1)), "to": parse_br_date(m.group(2))})
            continue
        d = parse_br_date(part)
        if d:
            current = d
    return periods, current


def mte_problem(body: Any, *, min_rows: int = 100) -> str:
    """Why a downloaded MTE copy must not replace the installed one ('' = acceptable)."""
    text = _decode(body)
    if not text.strip():
        return "empty file"
    if _HTML.match(text[:2048]):
        return "an HTML page came back instead of the CSV (file moved or renamed?)"
    first = text.split("\n", 1)[0].rstrip("\r")
    cols = _mte_header_map(first.split(";"))
    if not {"name", "doc", "inclusion"} <= set(cols):
        return "unexpected header (schema drift)"
    rows = [ln for ln in text.splitlines()[1:] if ln.strip()]
    if len(rows) < min_rows:
        return f"too few rows ({len(rows)} < {min_rows})"
    return ""


def validate_mte(path: Path) -> bool:
    problem = mte_problem(Path(path).read_bytes())
    if problem:
        raise ValueError(f"{MTE_DATASET}: {problem}")
    return True


def parse_mte_lista_suja(body: Any, *, include_persons: bool = False) -> dict[str, Any]:
    """MTE 'lista suja' CSV -> company rows (FC3: persons dropped unless ``include_persons``).

    Establishment addresses are never kept; a footnote marker such as '(*1)' is stripped from the name and kept
    apart; MEI rows ('NN.NNN.NNN FULL NAME' with a CNPJ) stay as companies keyed by CNPJ but their name (the
    entrepreneur's own) is withheld. With ``include_persons`` a person row keeps only the name and the masked CPF
    (never a key, never pivoted). Returns ``{rows, dropped_persons, errors, header_ok}``."""
    text = _decode(body)
    out: dict[str, Any] = {"rows": [], "dropped_persons": 0, "errors": [], "header_ok": False}
    if _HTML.match(text[:2048]):
        out["errors"].append("an HTML page instead of the CSV")
        return out
    try:
        reader = csv.reader(io.StringIO(text, newline=""), delimiter=";")
        header = next(reader)
    except (StopIteration, csv.Error):
        out["errors"].append("empty or unreadable file")
        return out
    cols = _mte_header_map(header)
    if not {"name", "doc", "inclusion"} <= set(cols):
        out["errors"].append("unexpected header (schema drift)")
        return out
    out["header_ok"] = True

    def get(row: list[str], key: str) -> str:
        i = cols.get(key)
        return clean(row[i]) if i is not None and i < len(row) else ""

    try:
        for lineno, row in enumerate(reader, start=2):
            if not any(c.strip() for c in row):
                continue
            doc = get(row, "doc")
            name = get(row, "name")
            foot = _FOOTNOTE.search(name)
            if foot:
                name = name[: foot.start()].strip()
            periods, current = parse_inclusion_periods(get(row, "inclusion"))
            workers = get(row, "workers")
            base = {"list": "mte_lista_suja", "id": get(row, "id"), "year": get(row, "year") or None, "uf": get(row, "uf") or None,
                    "workers": int(workers) if workers.isdigit() else None, "cnae": get(row, "cnae") or None,
                    "decision_date": parse_br_date(get(row, "decision")), "inclusion_date": current,
                    "inclusion_periods": periods, "footnote": f"({foot.group(1)})" if foot else None}
            digits = re.sub(r"\D", "", doc)
            cnpj = cnpj_normalize(doc) if ("/" in doc or len(digits) == 14) else None
            if cnpj:
                mei = bool(_MEI_NAME.match(name))
                out["rows"].append(dict(base, kind="company", name=None if mei else name, mei=mei, cnpj=cnpj, cnpj_root=cnpj[:8],
                                        cnpj_valid=validators.cnpj_valid(cnpj)))
            elif len(digits) == 11:
                if include_persons:
                    out["rows"].append(dict(base, kind="person", name=name, cpf_masked=mask_cpf(doc)))
                else:
                    out["dropped_persons"] += 1
            else:
                out["errors"].append(f"line {lineno}: unrecognised document")
    except csv.Error as exc:
        out["errors"].append(f"malformed CSV: {exc}")
    return out


# ======================================================================================
# CVM sanctioning proceedings (FC1, FC3, FC5)
# ======================================================================================


def cvm_accused_kind(name: Any) -> str:
    """'entity' | 'person' for a CVM accused name (FC3). The accused file has NO document column, so the split
    is a legal-form/keyword heuristic that fails closed: unknown -> 'person' (never kept by mistake). A bare
    'SA' token is not a hint ('Sa' is a surname): only punctuated S.A. / S/A count."""
    s = fold(name).upper()
    return "entity" if s and _ENTITY_HINT.search(s) else "person"


def cvm_outcome(situacao: Any) -> str:
    """Accused 'Situacao' -> acquitted | convicted | settlement | settlement_proposed | extinguished | deceased |
    pending (context in the title; the severity stays MEDIUM per the table)."""
    s = fold(situacao).casefold()
    if "absolvicao" in s:
        return "acquitted"
    if "condena" in s or "multa" in s:
        return "convicted"
    if "termo de compromisso aceito" in s or "cumprimento do termo" in s:
        return "settlement"
    if "termo de compromisso" in s:
        return "settlement_proposed"
    if "extincao de punibilidade" in s:
        return "extinguished"
    if "falecido" in s:
        return "deceased"
    return "pending"


def sanctions_problem(raw: Any) -> str:
    data = bytes(raw or b"")
    if not data:
        return "empty file"
    if _HTML.match(data[:2048].decode("latin-1")):
        return "an HTML page came back instead of the zip"
    problem = pgfn.zip_problem(data)
    if problem:
        return problem
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = set(zf.namelist())
    if not {"processo_sancionador.csv", "processo_sancionador_acusado.csv"} <= names:
        return "missing members (processo_sancionador.csv / processo_sancionador_acusado.csv)"
    return ""


def validate_sanctions(path: Path) -> bool:
    problem = sanctions_problem(Path(path).read_bytes())
    if problem:
        raise ValueError(f"{SANCTIONS_DATASET}: {problem}")
    return True


def parse_cvm_sancionador_zip(raw: Any, *, include_persons: bool = False) -> dict[str, Any]:
    """processo_sancionador.zip -> proceedings + accused (FC1, FC3, FC5). Accused classified 'person' are dropped
    and counted unless ``include_persons``. Returns ``{proceedings, accused, dropped_persons, errors}``."""
    out: dict[str, Any] = {"proceedings": {}, "accused": [], "dropped_persons": 0, "errors": []}
    problem = sanctions_problem(raw)
    if problem:
        out["errors"].append(problem)
        return out
    try:
        with zipfile.ZipFile(io.BytesIO(bytes(raw))) as zf:
            ptxt = _decode(zf.read("processo_sancionador.csv"))
            atxt = _decode(zf.read("processo_sancionador_acusado.csv"))
        for rec in csv.DictReader(io.StringIO(ptxt, newline=""), delimiter=";"):
            nup = clean(rec.get("NUP"))
            if not nup:
                continue
            out["proceedings"][nup] = {
                "nup": nup, "subject": clean(rec.get("Objeto"))[:300] or None, "opened": parse_br_date(rec.get("Data_Abertura")),
                "unit": clean(rec.get("Componente_Organizacional_Instrucao")) or None, "phase": clean(rec.get("Fase_Atual")) or None,
                "subphase": clean(rec.get("Subfase_Atual")) or None, "last_movement": parse_br_date(rec.get("Data_Ultima_Movimentacao")),
            }
        for rec in csv.DictReader(io.StringIO(atxt, newline=""), delimiter=";"):
            name = clean(rec.get("Nome_Acusado"))
            if not name:
                continue
            kind = cvm_accused_kind(name)
            if kind == "person" and not include_persons:
                out["dropped_persons"] += 1
                continue
            nup = clean(rec.get("NUP"))
            out["accused"].append({"list": "cvm_sancionador", "nup": nup, "name": name, "kind": kind,
                                   "situation": clean(rec.get("Situacao")) or None, "outcome": cvm_outcome(rec.get("Situacao")),
                                   "date": parse_br_date(rec.get("Data_Situacao"))})
    except (zipfile.BadZipFile, csv.Error, KeyError, OSError) as exc:
        out["errors"].append(f"unreadable zip member ({type(exc).__name__})")
    return out


# ======================================================================================
# BrasilAPI CVM brokers (FC6)
# ======================================================================================


def _broker(rec: dict[str, Any]) -> dict[str, Any] | None:
    c = cnpj_normalize(rec.get("cnpj"))
    if not c:
        return None
    status_raw = clean(rec.get("status")).upper() or None
    return {"registry": "brasilapi_corretoras", "segment": clean(rec.get("type")).title() or "Corretora", "category": None,
            "cnpj": cvm.format_cnpj(c), "cnpj_digits": c, "cnpj_root": c[:8], "name": clean(rec.get("nome_social")) or None,
            "trade_name": clean(rec.get("nome_comercial")) or None, "status": cvm.cvm_status(status_raw), "status_raw": status_raw,
            "status_since": parse_br_date(rec.get("data_inicio_situacao")), "registered_on": parse_br_date(rec.get("data_registro")),
            "cd_cvm": clean(rec.get("codigo_cvm")) or None}


def brokers_problem(raw: Any) -> str:
    text = _decode(raw).strip()
    if not text:
        return "empty file"
    if _HTML.match(text[:2048]):
        return "an HTML page came back instead of JSON"
    try:
        data = json.loads(text)
    except ValueError:
        return "malformed JSON (truncated download?)"
    if not isinstance(data, list):
        return "unexpected shape (an error object instead of the list?)"
    if len(data) < 50:
        return f"too few brokers ({len(data)} < 50)"
    return ""


def validate_brokers(path: Path) -> bool:
    problem = brokers_problem(Path(path).read_bytes())
    if problem:
        raise ValueError(f"{BROKERS_DATASET}: {problem}")
    return True


def parse_brasilapi_corretoras(raw: Any) -> dict[str, Any]:
    """GET /api/cvm/corretoras/v1 -> ``{rows, error}``. E-mail, phone, address and net worth are never kept;
    duplicated CNPJs stay separate registrations."""
    text = _decode(raw).strip()
    if _HTML.match(text[:2048]):
        return {"rows": [], "error": "an HTML page instead of JSON"}
    try:
        data = json.loads(text)
    except ValueError:
        return {"rows": [], "error": "malformed JSON"}
    if not isinstance(data, list):
        return {"rows": [], "error": "unexpected shape"}
    rows = [r for r in (_broker(x) for x in data if isinstance(x, dict)) if r]
    return {"rows": rows, "error": None}


register_dataset(
    MTE_DATASET, MTE_URL, ttl=7 * 86400,
    description="MTE Cadastro de Empregadores ('lista suja': employers caught using slave-like labour; ~80 KB, weekly; refreshed by "
                "v3lum data update, never during a scan; person employers are dropped when parsed)",
    licence="Official public register (MTE, Portaria Interministerial MTPS/MMIRDH 4/2016)", terms_class="open",
    attribution="Ministerio do Trabalho e Emprego - Cadastro de Empregadores (www.gov.br/trabalho-e-emprego)",
    source=SOURCE_MTE, validate=validate_mte, min_bytes=1_000, expect="bytes", max_bytes=SMALL_MAX_BYTES, essential=True,
)
register_dataset(
    SANCTIONS_DATASET, SANCTIONS_URL, ttl=86400,
    description="CVM sanctioning proceedings (processo_sancionador.zip: proceedings + accused; ~130 KB, daily; refreshed by v3lum "
                "data update, never during a scan; accused persons are dropped when parsed)",
    licence=cvm.LICENCE, terms_class="open", attribution=cvm.ATTRIBUTION, source=SOURCE_SANCTIONS, validate=validate_sanctions,
    min_bytes=10_000, expect="bytes", max_bytes=SMALL_MAX_BYTES, essential=True,
)
register_dataset(
    BROKERS_DATASET, BROKERS_URL, ttl=86400,
    description="BrasilAPI CVM brokers list (/api/cvm/corretoras/v1, ~200 KB, daily; refreshed by v3lum data update, never during a "
                "scan); only identity, status and dates are read",
    licence="MIT code (BrasilAPI) over CVM open data (ODbL)", terms_class="open",
    attribution="BrasilAPI (MIT) relaying Comissao de Valores Mobiliarios open data", source=SOURCE_BROKERS, validate=validate_brokers,
    min_bytes=10_000, expect="json", max_bytes=SMALL_MAX_BYTES, essential=True,
)


# ======================================================================================
# local copies (never downloads: FC1, FC7)
# ======================================================================================


@dataclass
class ListState:
    key: str
    state: str = "missing"  # ok | missing | error | skipped
    as_of: str = ""
    stale: bool = False
    reason: str = ""
    rows: list[dict[str, Any]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return LIST_LABELS[self.key]

    @property
    def usable(self) -> bool:
        return self.state == "ok"


_LOCK = threading.Lock()
_MEMO: dict[tuple[str, str, bool], Any] = {}


def _local_copy(data: Any, name: str) -> tuple[Path, Any]:
    try:
        info = data.info(name)
        present = bool(info.present)
    except (ValueError, OSError):
        present = False
    if not present:
        raise DatasetUnavailable(name, f"run v3lum data update {name}")
    return Path(data.fetch(name, ttl=SERVE_LOCAL_TTL)), data.info(name)


def _as_of(info: Any) -> str:
    fetched = str(getattr(info, "fetched_at", "") or "")
    return fetched[:10] if re.match(r"^\d{4}-\d{2}-\d{2}", fetched) else "unknown date"


def _memo(key: tuple[str, str, bool], loader: Any) -> Any:
    with _LOCK:
        hit = _MEMO.get(key) if key[1] else None
    if hit is not None:
        return hit
    value = loader()
    if key[1]:
        with _LOCK:
            for k in [k for k in _MEMO if k[0] == key[0]]:
                del _MEMO[k]
            _MEMO[key] = value
    return value


def _load_file_list(data: Any, key: str, dataset: str, parser: Any, *, include_persons: bool = False) -> ListState:
    st = ListState(key)
    try:
        path, info = _local_copy(data, dataset)
    except DatasetUnavailable:
        st.reason = f"not screened against {st.label} (never downloaded: run v3lum data update {dataset})"
        return st
    except (OSError, DatasetError) as exc:
        st.state, st.reason = "error", f"not screened against {st.label} (local copy unreadable: {type(exc).__name__})"
        return st
    st.as_of = _as_of(info)
    st.stale = bool(getattr(info, "age_hours", None) is not None and float(info.age_hours) > MAX_AGE_HOURS[key])
    sha = str(getattr(info, "sha256", "") or "")
    try:
        parsed = _memo((dataset, sha, include_persons), lambda: parser(path.read_bytes(), include_persons=include_persons))
    except OSError as exc:
        st.state, st.reason = "error", f"not screened against {st.label} (local copy unreadable: {type(exc).__name__})"
        return st
    errors = parsed.get("errors") or ([parsed["error"]] if parsed.get("error") else [])
    rows = parsed.get("rows") if "rows" in parsed else parsed.get("accused")
    if not rows and errors:
        st.state, st.reason = "error", f"not screened against {st.label} ({errors[0]}: run v3lum data update {dataset})"
        return st
    st.state = "ok"
    st.rows = list(rows or [])
    st.extra = {"proceedings": parsed.get("proceedings") or {}, "dropped_persons": parsed.get("dropped_persons", 0)}
    return st


def load_mte(data: Any, *, include_persons: bool = False) -> ListState:
    return _load_file_list(data, "mte_lista_suja", MTE_DATASET, parse_mte_lista_suja, include_persons=include_persons)


def load_sanctions(data: Any, *, include_persons: bool = False) -> ListState:
    return _load_file_list(data, "cvm_sancionador", SANCTIONS_DATASET, parse_cvm_sancionador_zip, include_persons=include_persons)


def load_brokers(data: Any) -> ListState:
    return _load_file_list(data, "brasilapi_corretoras", BROKERS_DATASET, lambda raw, include_persons=False: parse_brasilapi_corretoras(raw))


def load_cia(data: Any) -> ListState:
    def parse(raw: bytes, include_persons: bool = False) -> dict[str, Any]:
        p = cvm.parse_cvm_csv(raw, "cia_aberta")
        rows = [dict(r, registry="cia_aberta", segment="Companhia aberta (emissor)", status=_cia_status(r)) for r in p.rows if r.get("cnpj_root")]
        return {"rows": rows, "errors": [p.error] if p.error else []}

    return _load_file_list(data, "cvm_cia_aberta", CIA_DATASET, parse)


def _cia_status(row: dict[str, Any]) -> str:
    """The listed-company register says 'ATIVO' for an active issuer (the intermediary vocabulary of the shared
    loader says 'EM FUNCIONAMENTO NORMAL')."""
    raw = fold(row.get("status_raw")).upper()
    return "active" if raw.startswith("ATIVO") else str(row.get("status") or "unknown")


def load_cvm_registries(data: Any) -> ListState:
    st = ListState("cvm_registries")
    try:
        index = cvm.load_companies(data)
    except (OSError, DatasetError) as exc:
        st.state, st.reason = "error", f"not screened against {st.label} ({type(exc).__name__})"
        return st
    if not index.present:
        why = "; ".join(index.errors) or "never downloaded: run v3lum data update " + " ".join(index.missing)
        st.state = "error" if index.errors else "missing"
        st.reason = f"not screened against {st.label} ({why})"
        return st
    dates = sorted(m.get("date") or "" for m in index.datasets if m.get("date"))
    st.state = "ok"
    st.as_of = dates[0] if dates else "unknown date"
    st.stale = any(m.get("age_hours") is not None and float(m["age_hours"]) > MAX_AGE_HOURS["cvm_registries"] for m in index.datasets)
    st.extra = {"index": index, "missing": list(index.missing)}
    return st


def load_pgfn(home: Path | None = None) -> ListState:
    st = ListState("pgfn_divida_ativa")
    idx, problem = pgfn.open_index(home)
    if idx is None:
        last = (pgfn.read_state(home).get("last_import") or {})
        extra = ""
        if last.get("status") and last.get("status") != "imported":
            extra = f"; last import {last.get('at', '?')}: {str(last.get('reason', ''))[:160]}"
        if problem == "missing":
            st.reason = f"not screened against {st.label} (opt-in import not done: {pgfn.IMPORT_HINT}{extra})"
        else:
            st.state, st.reason = "error", f"not screened against {st.label} (local index {problem}: re-import{extra})"
        return st
    st.state = "ok"
    st.as_of = str(idx.meta.get("imported_at") or "")[:10] or "unknown date"
    quarter = idx.meta.get("quarter") or ""
    st.extra = {"index": idx, "quarter": quarter, "include_persons": idx.include_persons}
    m = re.match(r"(\d{4})_trimestre_0([1-4])", quarter)
    if m:
        st.as_of = f"{st.as_of} (PGFN {m.group(1)} Q{m.group(2)})"
    return st


# ======================================================================================
# matching (FC4, FC6)
# ======================================================================================


def _cnpj_match(row_cnpj: Any, cnpj: str) -> str | None:
    c = cnpj_normalize(row_cnpj)
    if not c:
        return None
    if c == cnpj:
        return "exact"
    return "root" if c[:8] == cnpj[:8] else None


def match_rows_by_cnpj(rows: Iterable[dict[str, Any]], cnpj: str) -> list[dict[str, Any]]:
    out = []
    for r in rows:
        if r.get("kind") == "person":
            continue
        m = _cnpj_match(r.get("cnpj_digits") or r.get("cnpj"), cnpj)
        if m:
            out.append(dict(r, match=m))
    return sorted(out, key=lambda r: (r["match"] != "exact", str(r.get("id") or r.get("cnpj") or "")))


def match_rows_by_name(rows: Iterable[dict[str, Any]], name: Any, *, fields: tuple[str, ...] = ("name",)) -> list[dict[str, Any]]:
    key = org_key(name)
    if not key:
        return []
    out = []
    for r in rows:
        if r.get("kind") == "person":
            continue
        if any(r.get(f) and org_key(r.get(f)) == key for f in fields):
            out.append(dict(r, match="name_exact"))
    return out


def sanction_matches(accused: Iterable[dict[str, Any]], names: Iterable[Any]) -> list[dict[str, Any]]:
    """Entity accused whose normalised name equals one of ``names`` (FC4): the CVM file has no CNPJ, so every
    match is name-only - 'possible match, verify identifiers' (AR08), severity MEDIUM (FC5)."""
    keys = {org_key(n) for n in names if org_key(n)}
    out = []
    for a in accused:
        if a.get("kind") != "entity":
            continue
        if org_key(a.get("name")) in keys:
            out.append(dict(a, match="name_exact"))
    return out


def authorisation_answer(registrations: list[dict[str, Any]], as_of: str) -> dict[str, Any]:
    """FC6 one-line answer. Exact (CNPJ or exact name) active registrations -> 'registered with CVM: active';
    otherwise the states found (root matches stated); none -> 'not found in CVM registries as of <date>' (never
    fraud)."""
    if not registrations:
        return {"authorised": False, "line": f"not found in CVM registries as of {as_of}"}
    active = sorted({r["registry"] for r in registrations if r.get("status") == "active" and r.get("match") in ("exact", "name_exact")})
    if active:
        return {"authorised": True, "line": f"registered with CVM: active ({', '.join(active)}) as of {as_of}"}
    states = sorted({f"{r['registry']} {r.get('status') or 'unknown'}{' (CNPJ root match)' if r.get('match') == 'root' else ''}"
                     for r in registrations})
    return {"authorised": False, "line": f"no active CVM registration as of {as_of}: {'; '.join(states)}"}


# ======================================================================================
# the module
# ======================================================================================


def _confidence(match: str) -> str:
    return {"exact": "confirmed", "root": "probable"}.get(match, "possible")


def _match_text(match: str) -> str:
    return {"exact": "exact CNPJ", "root": "same CNPJ root (another establishment)", "name_exact": "exact company name (name only)"}.get(
        match, match)


@register
class BrCnpjRiskLists(Module):
    name = "br_cnpj_risk_lists"
    title = "BR risk lists by CNPJ (MTE lista suja, CVM, PGFN; offline)"
    description = (
        "Offline screening of a CNPJ or company name against Brazilian risk lists: MTE 'lista suja' (slave-like labour), CVM "
        "sanctioning proceedings and registries (is this broker/adviser authorised?), BrasilAPI CVM brokers and, opt-in, the PGFN "
        "divida ativa. Local copies only; a missing list reads 'not screened', never 'clean'."
    )
    category = "brazil_public_data"
    accepts = {T.CNPJ, T.ORG, T.PERSON}
    produces = frozenset()
    tags = {"brazil", "offline"}
    reference = "https://www.gov.br/trabalho-e-emprego/pt-br/assuntos/inspecao-do-trabalho/areas-de-atuacao/cadastro_de_empregadores.csv"
    notice = (
        "Official lists downloaded by `v3lum data update` (PGFN: opt-in import) and matched locally; nothing is sent during a scan. "
        "Natural persons are dropped when a list is parsed unless br_cnpj_risk_lists_include_persons is set; then only analyst-typed "
        "person names with a recorded purpose are matched, by name only (possible match), and a CPF is never a key or a pivot. "
        "Severity: MTE HIGH, CVM sanction MEDIUM, PGFN LOW context; absence is never 'clean' or 'fraud'."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (SOURCE_MTE, SOURCE_CVM, SOURCE_CVM_CIA, SOURCE_SANCTIONS, SOURCE_BROKERS, SOURCE_PGFN)
    access_model = "offline"
    expected_latency = 0.5
    timeout = 60.0
    max_pivots = 0
    default_enabled = True  # P244 council: default-enabled (PGFN stays opt-in through its separate import)
    settings = {
        "br_cnpj_risk_lists_include_persons": False,
        "br_cnpj_risk_lists_pgfn_chunk_mb": 16,
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.PERSON:
            return bool(ctx.setting("br_cnpj_risk_lists_include_persons", False)) and bool(getattr(ctx, "is_seed", False))
        if entity.type is T.ORG:
            return not _CPF_SHAPED.match(str(entity.value))  # a CPF is never a lookup key (rule 4)
        return True

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type is T.PERSON:
            return self._persons(res, ctx, str(entity.value))
        allowed = frozenset(getattr(ctx, "allowed_sources", None) or self.sources)
        lists = self._load(ctx, allowed, include_persons=False)
        screened = [s for s in lists.values() if s.usable]
        if not screened:
            return self._none_screened(res, lists)
        try:
            if entity.type is T.CNPJ:
                hits, registrations, pgfn_rows, names = self._by_cnpj(lists, str(entity.value))
            else:
                hits, registrations, pgfn_rows, names = self._by_name(lists, str(entity.value))
        except Exception:
            _close(lists)
            raise
        try:
            sanctions = lists["cvm_sancionador"]
            if sanctions.usable:
                hits["cvm_sancionador"] = sanction_matches(sanctions.rows, names)[:MAX_ROWS_SHOWN]
            self._report(res, ctx, entity, lists, hits, registrations, pgfn_rows)
        finally:
            _close(lists)
        return res

    def _load(self, ctx: Any, allowed: frozenset[str], *, include_persons: bool) -> dict[str, ListState]:
        loaders = {
            "mte_lista_suja": lambda: load_mte(ctx.data, include_persons=include_persons),
            "cvm_sancionador": lambda: load_sanctions(ctx.data, include_persons=include_persons),
            "cvm_registries": lambda: load_cvm_registries(ctx.data),
            "cvm_cia_aberta": lambda: load_cia(ctx.data),
            "brasilapi_corretoras": lambda: load_brokers(ctx.data),
            "pgfn_divida_ativa": lambda: load_pgfn(),
        }
        out: dict[str, ListState] = {}
        for key, loader in loaders.items():
            if LIST_SOURCES[key] not in allowed:
                out[key] = ListState(key, state="skipped", reason=f"not screened against {LIST_LABELS[key]} (not allowed in this run)")
                continue
            out[key] = loader()
        return out

    @staticmethod
    def _none_screened(res: ModuleResult, lists: dict[str, ListState]) -> ModuleResult:
        lines = "; ".join(s.reason for s in lists.values() if s.reason)
        for s in lists.values():
            BrCnpjRiskLists._coverage(res, s, matched=False)
        if any(s.state == "error" for s in lists.values()):
            return res.mark(Status.ERROR, f"no risk list could be read: {lines}; could not verify")
        return res.mark(Status.UNAVAILABLE, f"no risk list downloaded: {lines}; never read as 'clean'", reason_code="dataset")

    def _by_cnpj(self, lists: dict[str, ListState], cnpj: str) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]],
                                                                          list[dict[str, Any]], set[str]]:
        hits: dict[str, list[dict[str, Any]]] = {}
        names: set[str] = set()
        mte = lists["mte_lista_suja"]
        if mte.usable:
            hits["mte_lista_suja"] = match_rows_by_cnpj(mte.rows, cnpj)
            names |= {r["name"] for r in hits["mte_lista_suja"] if r.get("name") and r["match"] == "exact"}
        registrations: list[dict[str, Any]] = []
        reg = lists["cvm_registries"]
        if reg.usable:
            for row in reg.extra["index"].by_root.get(cnpj[:8], ()):
                m = _cnpj_match(row.get("cnpj"), cnpj)
                if m:
                    registrations.append(dict(row, match=m))
        for key in ("cvm_cia_aberta", "brasilapi_corretoras"):
            if lists[key].usable:
                registrations += match_rows_by_cnpj(lists[key].rows, cnpj)
        names |= {r["name"] for r in registrations if r.get("name") and r.get("match") == "exact"}
        pgfn_rows: list[dict[str, Any]] = []
        p = lists["pgfn_divida_ativa"]
        if p.usable:
            pgfn_rows = p.extra["index"].by_cnpj(cnpj)
            names |= {r["name"] for r in pgfn_rows if r.get("name") and r["match"] == "exact"}
        names |= _rfb_name(cnpj)
        return hits, registrations, pgfn_rows, names

    def _by_name(self, lists: dict[str, ListState], name: str) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]],
                                                                         list[dict[str, Any]], set[str]]:
        hits: dict[str, list[dict[str, Any]]] = {}
        mte = lists["mte_lista_suja"]
        if mte.usable:
            hits["mte_lista_suja"] = match_rows_by_name(mte.rows, name)
        registrations: list[dict[str, Any]] = []
        reg = lists["cvm_registries"]
        if reg.usable:
            index = reg.extra["index"]
            roots, label = index.names.find(name)
            if roots and len(roots) <= 5:  # an ambiguous name never becomes an answer
                for root in roots:
                    for row in index.by_root.get(root, ()):
                        registrations.append(dict(row, match="name_exact" if label in ("exact_name", "trade_name") else "name_possible"))
        for key in ("cvm_cia_aberta", "brasilapi_corretoras"):
            if lists[key].usable:
                registrations += match_rows_by_name(lists[key].rows, name, fields=("name", "trade_name"))
        pgfn_rows: list[dict[str, Any]] = []
        p = lists["pgfn_divida_ativa"]
        if p.usable:
            pgfn_rows = p.extra["index"].by_name(name)
        return hits, registrations, pgfn_rows, {name}

    # ------------------------------------------------------------------ output (FC4-FC7)
    @staticmethod
    def _coverage(res: ModuleResult, st: ListState, *, matched: bool) -> None:
        sid = LIST_SOURCES[st.key]
        if st.state == "skipped":
            res.source_status(sid, Status.SKIPPED, reason_code="licence", reason=st.reason[:300])
        elif st.state == "missing":
            res.source_status(sid, Status.UNAVAILABLE, reason_code="dataset", reason=st.reason[:300])
        elif st.state == "error":
            res.source_status(sid, Status.ERROR, reason=st.reason[:300])
        elif matched:
            res.source_status(sid, Status.OK, reason=f"{st.label} as of {st.as_of}")
        elif st.stale:
            res.source_status(sid, Status.UNAVAILABLE, reason_code="dataset", reason=f"not screened against {st.label} ({st.as_of}: stale copy)")
        else:
            res.source_status(sid, Status.EMPTY, reason=f"no record in {st.label} as of {st.as_of}")

    def _report(self, res: ModuleResult, ctx: Any, entity: Entity, lists: dict[str, ListState], hits: dict[str, list[dict[str, Any]]],
                registrations: list[dict[str, Any]], pgfn_rows: list[dict[str, Any]]) -> None:
        screening: dict[str, dict[str, Any]] = {}
        risk_rows: list[dict[str, Any]] = []
        stale_lines: list[str] = []
        matched_keys = {k for k, v in hits.items() if v} | ({"pgfn_divida_ativa"} if pgfn_rows else set())
        reg_keys = {"cvm_registries": [r for r in registrations if r.get("registry") not in ("cia_aberta", "brasilapi_corretoras")],
                    "cvm_cia_aberta": [r for r in registrations if r.get("registry") == "cia_aberta"],
                    "brasilapi_corretoras": [r for r in registrations if r.get("registry") == "brasilapi_corretoras"]}
        matched_keys |= {k for k, v in reg_keys.items() if v}
        for key, st in lists.items():
            matched = key in matched_keys
            self._coverage(res, st, matched=matched)
            if not st.usable:
                screening[key] = {"state": "not_screened", "as_of": st.as_of or None, "line": st.reason}
            elif matched:
                screening[key] = {"state": "listed", "as_of": st.as_of, "line": f"listed in {st.label} as of {st.as_of}"}
            elif st.stale:
                screening[key] = {"state": "not_screened", "as_of": st.as_of, "line": f"not screened against {st.label} ({st.as_of})"}
            else:
                screening[key] = {"state": "no_record", "as_of": st.as_of, "line": f"no record in {st.label} as of {st.as_of}"}
            if st.usable and st.stale:
                stale_lines.append(f"{st.label}, copy of {st.as_of} (older than {MAX_AGE_HOURS[key] // 24} days: run v3lum data update)")

        # MTE lista suja - HIGH (FC5)
        mte = lists["mte_lista_suja"]
        for row in hits.get("mte_lista_suja", [])[:MAX_ROWS_SHOWN]:
            title = "Listed in the MTE 'lista suja' (slave-like labour)"
            risk_rows.append(self._risk_row("mte_lista_suja", title, row.get("inclusion_date"), None, row["match"], mte.as_of))
            suspended = f"; earlier inclusion periods {', '.join(p['from'] + ' a ' + p['to'] for p in row['inclusion_periods'] if p.get('from') and p.get('to'))}" \
                if row.get("inclusion_periods") else ""
            res.finding(
                title, SEVERITY["mte_lista_suja"],
                f"{_match_text(row['match'])}: included {row.get('inclusion_date') or '?'}{suspended}; inspection year {row.get('year') or '?'}, "
                f"UF {row.get('uf') or '?'}, {row.get('workers') if row.get('workers') is not None else '?'} worker(s) involved, decision "
                f"{row.get('decision_date') or '?'}{', MEI (entrepreneur name withheld)' if row.get('mei') else ''} (MTE list as of {mte.as_of})",
                confidence=_confidence(row["match"]), source=SOURCE_MTE, key=f"mte:{row.get('id')}:{row.get('cnpj')}",
                tags=["esg_labour"] + (["name_only_match"] if row["match"] == "name_exact" else []),
                criterion=f"{_match_text(row['match'])} in the MTE Cadastro de Empregadores (employers caught using labour analogous to "
                          f"slavery): labour/ESG red flag, list as of {mte.as_of}",
                observed_first=row.get("inclusion_date"),
                data={"list": "mte_lista_suja", "id": row.get("id"), "cnpj": row.get("cnpj"), "match": row["match"], "uf": row.get("uf"),
                      "workers": row.get("workers"), "cnae": row.get("cnae"), "inclusion_date": row.get("inclusion_date"),
                      "inclusion_periods": row.get("inclusion_periods"), "decision_date": row.get("decision_date"),
                      "footnote": row.get("footnote"), "as_of": mte.as_of},
            )

        # CVM sanctioning proceedings - MEDIUM, name-only (FC4, FC5)
        sanc = lists["cvm_sancionador"]
        for a in hits.get("cvm_sancionador", []):
            proc = sanc.extra.get("proceedings", {}).get(a.get("nup")) or {}
            title = f"Named in a CVM sanction proceeding ({a.get('outcome')})"
            risk_rows.append(self._risk_row("cvm_sancionador", title, a.get("date"), None, "name_exact", sanc.as_of))
            res.finding(
                title, SEVERITY["cvm_sancionador"],
                f"PAS {a.get('nup')}: accused '{a.get('name')}' ({a.get('situation') or 'situation unknown'}, {a.get('date') or '?'}); "
                f"subject: {proc.get('subject') or '?'}; phase {proc.get('phase') or '?'}. Possible match - verify identifiers: the CVM file "
                f"has no CNPJ (list as of {sanc.as_of})",
                confidence="possible", source=SOURCE_SANCTIONS, key=f"pas:{a.get('nup')}:{org_key(a.get('name'))}",
                tags=["cvm_proceeding", "name_only_match"],
                criterion=f"same normalised name as an accused entity in CVM sanctioning proceeding {a.get('nup')} (name only: possible match)",
                observed_first=proc.get("opened"), observed_last=a.get("date"),
                data={"list": "cvm_sancionador", "nup": a.get("nup"), "accused": a.get("name"), "outcome": a.get("outcome"),
                      "situation": a.get("situation"), "date": a.get("date"), "opened": proc.get("opened"), "phase": proc.get("phase"),
                      "as_of": sanc.as_of},
            )

        # PGFN divida ativa - LOW context per debt nature (FC5)
        p = lists["pgfn_divida_ativa"]
        if pgfn_rows:
            debts = pgfn.summary(pgfn_rows)
            res.attr("pgfn_debts", debts)
            for d in debts:
                title = f"PGFN divida ativa: {d['nature']}"
                risk_rows.append(self._risk_row("pgfn_divida_ativa", title, d.get("latest"), d.get("total_band"), d["match"], p.as_of))
                res.finding(
                    title, SEVERITY["pgfn_divida_ativa"],
                    f"{d['count']} inscription(s), total {d.get('total_band') or '?'}, situation(s): {'; '.join(d['situations']) or '?'}"
                    f"{', judicial collection' if d['judicial'] else ''}; latest inscription {d.get('latest') or '?'}; {_match_text(d['match'])} "
                    f"(PGFN index {p.as_of}). Context: debt is common among legitimate companies",
                    confidence=_confidence(d["match"]), source=SOURCE_PGFN, key=f"pgfn:{d['nature']}", tags=["tax_debt"],
                    criterion=f"{_match_text(d['match'])} in the PGFN divida ativa open data ({d['nature']}): LOW context per the P244 table",
                    observed_last=d.get("latest"),
                    data={"list": "pgfn_divida_ativa", **{k: d.get(k) for k in ("nature", "count", "total_band", "situations", "judicial",
                                                                                "latest", "match", "ref_month")}, "as_of": p.as_of},
                )

        # CVM registries + BrasilAPI brokers - INFO; the 'authorised?' answer (FC6)
        reg_states = [lists[k] for k in ("cvm_registries", "cvm_cia_aberta", "brasilapi_corretoras")]
        if any(s.usable for s in reg_states):
            as_of = min((s.as_of for s in reg_states if s.usable and s.as_of), default="unknown date")
            answer = authorisation_answer(registrations, as_of)
            missing = [s.label for s in reg_states if not s.usable]
            line = answer["line"] + (f" (not screened: {', '.join(missing)})" if missing else "")
            res.attr("cvm_authorisation", line)
            shown = registrations[:MAX_ROWS_SHOWN]
            res.attr("cvm_registrations", [{k: r.get(k) for k in ("registry", "segment", "category", "status", "status_since", "cnpj", "name",
                                                                   "match")} for r in shown])
            if answer["authorised"]:
                exact_cnpj = any(r.get("match") == "exact" and r.get("status") == "active" for r in registrations)
                res.finding(
                    "Registered with CVM (active)", "info", line, source=SOURCE_CVM, confidence="confirmed" if exact_cnpj else "probable",
                    criterion="active registration in the CVM registries / BrasilAPI broker list by "
                              + ("exact CNPJ" if exact_cnpj else "exact company name (confirm the CNPJ)"),
                    data={"registries": sorted({r["registry"] for r in registrations if r.get("status") == "active"}), "as_of": as_of},
                )
        else:
            res.attr("cvm_authorisation", f"not screened against CVM registries ({lists['cvm_registries'].reason or 'no copy'})")

        res.attr("risk_lists", risk_rows)
        res.attr("risk_lists_screening", screening)
        if stale_lines:
            res.attr("dataset_age", stale_lines)
        res.raw = {"input": entity.type.value, "screening": screening, "risk_lists": risk_rows,
                   "registrations": len(registrations), "pgfn_rows": len(pgfn_rows),
                   "persons": "dropped at import (br_cnpj_risk_lists_include_persons off)"}

    @staticmethod
    def _risk_row(lst: str, title: str, when: Any, band: Any, match: str, as_of: str) -> dict[str, Any]:
        return {"list": lst, "severity": SEVERITY[lst], "title": title, "date": when, "amount_band": band, "match": match, "as_of": as_of}

    # ------------------------------------------------------------------ persons (FC3, explicit due diligence only)
    def _persons(self, res: ModuleResult, ctx: Any, name: str) -> ModuleResult:
        purpose = clean(getattr(ctx, "purpose", "") or getattr(getattr(ctx, "options", None), "purpose", "") or "")
        if not bool(ctx.setting("br_cnpj_risk_lists_include_persons", False)) or not getattr(ctx, "is_seed", False):
            return res.mark(Status.SKIPPED, "person names are matched only with br_cnpj_risk_lists_include_persons on analyst-typed seeds",
                            reason_code="privacy")
        if not purpose:
            return res.mark(Status.SKIPPED, "person due diligence needs a recorded purpose (--purpose)", reason_code="privacy")
        if re.search(r"\d{3}\D?\d{3}\D?\d{3}", name):
            return res.mark(Status.SKIPPED, "a CPF is never a lookup key (rule 4)", reason_code="privacy")
        key = person_key(name)
        if len(key.split()) < 2:
            return res.mark(Status.SKIPPED, "give the full name (at least two words): a single word is never matched", reason_code="privacy")
        allowed = frozenset(getattr(ctx, "allowed_sources", None) or self.sources)
        homonym = namematch.homonym_risk(name)
        hits: list[dict[str, Any]] = []
        answered = []
        for key_list, loader in (("mte_lista_suja", lambda: load_mte(ctx.data, include_persons=True)),
                                 ("cvm_sancionador", lambda: load_sanctions(ctx.data, include_persons=True))):
            if LIST_SOURCES[key_list] not in allowed:
                continue
            st = loader()
            if not st.usable:
                self._coverage(res, st, matched=False)
                continue
            answered.append(st.label)
            found = [r for r in st.rows if r.get("kind") == "person" and person_key(r.get("name")) == key]
            self._coverage(res, st, matched=bool(found))
            hits += [{"list": key_list, "name": r.get("name"), "cpf_masked": r.get("cpf_masked"), "as_of": st.as_of,
                      "detail": r.get("nup") or r.get("inclusion_date")} for r in found]
        if SOURCE_PGFN in allowed:
            st = load_pgfn()
            if st.usable and st.extra.get("include_persons"):
                answered.append(st.label)
                found = st.extra["index"].persons_by_name(name)
                self._coverage(res, st, matched=bool(found))
                hits += [{"list": "pgfn_divida_ativa", "name": r.get("name"), "cpf_masked": r.get("cpf_masked"), "as_of": st.as_of,
                          "detail": f"{r.get('nature')}, {r.get('amount_band')}"} for r in found]
            else:
                if st.usable:
                    _close({"pgfn_divida_ativa": st})
                    st = ListState("pgfn_divida_ativa", reason=f"not screened against {st.label} (imported without --include-persons)")
                self._coverage(res, st, matched=False)
            if st.usable:
                _close({"pgfn_divida_ativa": st})
        ctx.log(f"{MODULE}: person due diligence (include_persons on, purpose recorded): {len(hits)} possible name match(es)", "info")
        if not answered:
            return res.mark(Status.UNAVAILABLE, "no person-capable risk list downloaded; never read as 'clean'", reason_code="dataset")
        res.attr("homonym_risk", homonym)
        if not hits:
            return res.mark(Status.EMPTY, f"no natural person with this exact name in {', '.join(answered)}")
        rows = [{"list": h["list"], "name": h["name"], "cpf_masked": h["cpf_masked"], "match": "possible", "homonym_risk": homonym["risk"]}
                for h in hits[:MAX_ROWS_SHOWN]]
        res.attr("risk_lists_persons", rows)
        res.raw = {"persons": "included: br_cnpj_risk_lists_include_persons with a recorded purpose", "matches": rows}
        confidence = namematch.homonym_curve(0.4, homonym)
        for h in hits[:MAX_ROWS_SHOWN]:
            severity = "info" if homonym["risk"] == "high" else SEVERITY[h["list"]]
            res.finding(
                f"Possible name match in {LIST_LABELS[h['list']]} (natural person)", severity,
                f"'{h['name']}' (CPF {h['cpf_masked'] or 'not published'}) - name only, {homonym['phrase']}; {h.get('detail') or ''} "
                f"(list as of {h['as_of']})",
                confidence=confidence, source=LIST_SOURCES[h["list"]], key=f"{h['list']}:{h.get('detail')}:{h.get('cpf_masked')}",
                tags=["name_only_match"],
                criterion="same normalised full name as a natural person in the list (explicit due diligence with a recorded purpose); a "
                          "name-only possible match, never confirmed by CPF",
                data={"list": h["list"], "match": "possible", "homonym_risk": homonym["risk"], "as_of": h["as_of"]},
            )
        return res


def _close(lists: dict[str, ListState]) -> None:
    for st in lists.values():
        idx = st.extra.get("index") if st.extra else None
        if isinstance(idx, pgfn.PgfnIndex):
            idx.close()


def _rfb_name(cnpj: str) -> set[str]:
    """Razao social of the CNPJ from the local RFB index of P238 when it is installed (helps the name-only CVM
    sanction matching of a CNPJ seed); empty otherwise. Never downloads."""
    try:
        from v3lum.modules.brazil_public_data import rfb_cnpj_bulk

        name, _nature = rfb_cnpj_bulk.company_name_for(cnpj)
    except Exception:  # noqa: BLE001 - optional local index of another module
        return set()
    return {name} if name else set()


__all__ = [
    "BROKERS_DATASET", "BrCnpjRiskLists", "LIST_LABELS", "MTE_DATASET", "SANCTIONS_DATASET", "SEVERITY", "authorisation_answer",
    "brokers_problem", "cvm_accused_kind", "cvm_outcome", "load_brokers", "load_cia", "load_cvm_registries", "load_mte", "load_pgfn",
    "load_sanctions", "match_rows_by_cnpj", "match_rows_by_name", "mte_problem", "parse_brasilapi_corretoras",
    "parse_cvm_sancionador_zip", "parse_inclusion_periods", "parse_mte_lista_suja", "sanction_matches", "sanctions_problem",
]
