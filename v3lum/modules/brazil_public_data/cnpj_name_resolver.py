"""cnpj_name_resolver (P361): company name -> ranked 'possible CNPJ' hypotheses.

Batch p2-G10-3. Lets Brazilian due-diligence chains start from 'Empresa X Ltda' instead of a CNPJ.

* **FC1 two steps** - step 1 (shipped): the offline sector registries through the loaders shared with
  P360/P244 (``cvm_registries``: CVM cadastros, ';' ISO-8859-1 - the listed-company register
  ``cvm_cia_aberta.csv`` is registered here under its own source, the intermediary/adviser/manager/
  crowdfunding registries by P360; ``bcb_authorized_institutions.load_bcb``: BCB Sedes* and
  DominiosVerificados) plus the online GLEIF fallback through the client shared with P220
  (``company_org.gleif_client``) and the Wikidata fallback over the shared ``wikidata`` provider fragment
  (P224's client had not landed: a minimal P6204 search lives here). Step 2: the local RFB
  name index - this file ships its reader, its builder (:class:`NameIndexBuilder`) and the streaming RFB
  parsers; the ``v3lum data import-rfb --names`` command that drives them belongs to the shared P238
  importer (docs/backlog/p2-G10-3.md).
* **FC2** - the index is built only by that importer, never during a scan; a run only opens it
  read-only (setting ``cnpj_name_resolver_index_path``, default ``~/.v3lum/datasets/rfb_names/rfb_names.sqlite``).
* **FC3** - SQLite FTS5 is detected at run time (``PRAGMA compile_options``, then a probe) with a
  normalised-token table as fallback (identical answers); names are normalised by
  :func:`normalize_company_name` (accents; LTDA, S.A., S/A, EIRELI, ME, EPP, SLU; judicial-status suffixes
  kept apart) - the reference for the future core/namematch.py; active head offices rank first.
* **FC4** - CPF digit sequences are stripped from MEI/EI names before indexing (:func:`strip_cpf_sequences`);
  natural-person (MEI/EI) rows answer exact matches only; the module never accepts ``person_name`` and
  :func:`query_index` refuses person searches.
* **FC5** - ranked hypotheses with match evidence (similarity, normalised name, UF/city, situacao, head
  office, source, snapshot date) as CNPJ pivots with ``expand=False``; at most 5 are listed (and pivoted)
  with the exact follow-up command (``v3lum scan <cnpj>``); the rest are counted.
* **FC6** - the P236 chain starts automatically (``expand=True``) only on an exact unique match of the
  normalised razao social of an active head office from the RFB index or the CVM/BCB registries; nome
  fantasia matches, MEI/EI names and the online fallbacks never auto-chain; another company with the
  same exact name (legal or trade, active or not) blocks it. A name that came from a CNPJ record (parent
  entity a CNPJ) is never resolved.
* **FC7** - GLEIF (``filter[fulltext]`` + country BR, CC0) and Wikidata items with P6204 run only when the
  local index is absent or returns nothing, labelled 'large companies only'. The Wikidata fallback is the
  companion module ``cnpj_name_resolver_wikidata`` (same file): the Wikimedia User-Agent policy needs an
  identifying contact (setting ``contact_email``) and the policy gate skips a module whose provider needs
  one that is not configured - kept apart, a missing contact never silences the main resolver. Without the index the module says 'local name index not installed (v3lum data
  import-rfb --names, ~7 GB)'. 401/403/429, timeouts, 5xx and error-in-200 bodies are per-source 'could not
  verify' (never 'no match').
* **FC8** - hypotheses (and the BCB-verified or Wikidata websites of a hypothesis) are ``expand=False``
  pivots: they never become seeds, org-profile or scope entries without the analyst; CNPJs found in
  DOU/Querido Diario excerpts stay hypotheses in those modules.
* **FC9** - < 500 ms per query on a synthetic 200k-company index (test); fixtures: the GLEIF/Wikidata/
  CVM/BCB captures plus a synthetic RFB slice with an MEI name carrying CPF digits.
"""

from __future__ import annotations

import csv
import difflib
import io
import json
import os
import re
import sqlite3
import threading
import time
import unicodedata
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from v3lum import paths
from v3lum.config import SettingSpec
from v3lum.core import validators
from v3lum.core.datasets import DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    ConfigError,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    OfflineError,
    PolicyError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.brazil_public_data import bcb_authorized_institutions as bcb
from v3lum.modules.brazil_public_data import cvm_registries as cvm

try:  # the one GLEIF client of V3LUM (P220 cond 1, batch p2-G10-1), shared with P361 (FC1)
    from v3lum.modules.company_org import gleif_client as gc
except ImportError:  # pragma: no cover - the shared client is not installed: the local client below answers
    gc = None

SOURCE_INDEX = "rfb.cnpj_name_resolver_name_index"
SOURCE_CVM = cvm.SOURCE
#: the listed-company register: its own source (provider extension cvm__p2-G10-3.json) so the dataset never
#: gates bcb_authorized_institutions through the policy dataset gate (POL-14)
SOURCE_CVM_CIA = "cvm.cnpj_name_resolver_cia_aberta"
SOURCE_BCB = bcb.SOURCE
SOURCE_GLEIF = "gleif.lei_api"
SOURCE_WIKIDATA = "wikidata.wbapi"
GLEIF_URL = "https://api.gleif.org/api/v1/lei-records"
WIKIDATA_API = "https://www.wikidata.org/w/api.php"
INDEX_MISSING_TEXT = "local name index not installed (v3lum data import-rfb --names, ~7 GB)"
ONLINE_LABEL = "large companies only"
INDEX_SCHEMA = "v3lum.rfb_names/1"
INDEX_FILE = "rfb_names.sqlite"
MAX_LISTED = 5  # FC5: non-interactive scans list at most 5
MAX_HYPOTHESES = 20
MAX_DOMAIN_PIVOTS = 5
FUZZY_THRESHOLD = 0.75
REQUEST_TIMEOUT = 20.0
CIA_ABERTA_DATASET = "cvm_cia_aberta.csv"
AUTO_CHAIN_SOURCES = ("rfb", "cvm", "bcb")
_KIND_RANK = {"exact_razao": 0, "exact_fantasia": 1, "contains": 2, "fuzzy": 3}
_SOURCE_RANK = {"rfb": 0, "cvm": 1, "bcb": 2, "gleif": 3, "wikidata": 4}
#: natureza juridica 213-5 Empresario (Individual), MEI included: the razao social is a person's name
NATURE_NATURAL_PERSON = frozenset({"2135"})
RFB_SITUACAO = {"01": "NULA", "02": "ATIVA", "03": "SUSPENSA", "04": "INAPTA", "08": "BAIXADA"}

register_dataset(
    CIA_ABERTA_DATASET, cvm.CVM_DATA + "CIA_ABERTA/CAD/DADOS/cad_cia_aberta.csv", ttl=86400,
    description="CVM register of listed companies (cad_cia_aberta.csv: issuers' legal and trade names, CNPJ, status; officer and "
                "contact columns are never imported); refreshed by v3lum data update, never during a scan",
    licence=cvm.LICENCE, terms_class="open", attribution=cvm.ATTRIBUTION, source=SOURCE_CVM_CIA,
    validate=cvm.copy_validator(CIA_ABERTA_DATASET, cvm.count_rows("cia_aberta"), min_rows=1500, min_bytes=700_000),
    min_bytes=700_000, expect="csv", max_bytes=cvm.DATASET_MAX_BYTES, large=True, essential=True,
)

# ======================================================================================
# normalisation (FC3, FC4): reference for the future core/namematch.py
# ======================================================================================

LEGAL_FORM_TOKENS = frozenset({"LTDA", "LIMITADA", "SA", "EIRELI", "ME", "EPP", "SLU", "MEI"})
_LEGAL_PHRASES = ("SOCIEDADE ANONIMA", "SOCIEDADE LIMITADA UNIPESSOAL", "SOCIEDADE LIMITADA")
_STATUS_SUFFIX_RE = re.compile(
    r"\b(EM RECUPERACAO JUDICIAL|EM RECUPERACAO EXTRAJUDICIAL|EM LIQUIDACAO EXTRAJUDICIAL|EM LIQUIDACAO JUDICIAL|"
    r"EM LIQUIDACAO|MASSA FALIDA|FALIDA)\b.*$")
_CPF_FMT_RE = re.compile(r"(?<![0-9])\d{3}\.\d{3}\.\d{3}-\d{2}(?![0-9])")
_DIGITS11_RE = re.compile(r"(?<![0-9])\d{11}(?![0-9])")


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bool) or value is None:
        return ""
    return str(value) if isinstance(value, (int, float)) else ""


def _fold_upper(value: str) -> str:
    out = []
    for c in value:
        d = "".join(x for x in unicodedata.normalize("NFKD", c) if not unicodedata.combining(x))
        out.append(d if len(d) == 1 else c)
    return "".join(out).upper()


def strip_cpf_sequences(name: Any) -> tuple[str, int]:
    """FC4 (rule 4, legal floor): remove CPF digits embedded in a name before indexing.

    MEI razao social reads 'NOME DA PESSOA 12345678909'. Every standalone 11-digit run (valid CPF or not)
    and every formatted CPF is removed; digit runs of longer numbers (a 14-digit CNPJ such as
    'CNPJ:37115383000153') are kept. Returns (clean name, number removed)."""
    removed = 0

    def drop(_m: re.Match[str]) -> str:
        nonlocal removed
        removed += 1
        return " "

    t = _CPF_FMT_RE.sub(drop, _text(name))
    t = _DIGITS11_RE.sub(drop, t)
    return re.sub(r"\s+", " ", t).strip(" -,;"), removed


def normalize_company_name(name: Any) -> dict[str, Any]:
    """FC3: CPF digits stripped, accents folded, upper case, 'S/A' and 'S.A.' unified to SA, '&' -> E,
    punctuation removed, a trailing judicial-status suffix cut and kept apart; ``core`` also drops the
    legal-form tokens (LTDA, LIMITADA, SA, EIRELI, ME, EPP, SLU, MEI) and the phrases SOCIEDADE ANONIMA /
    SOCIEDADE LIMITADA. -> {display, normalized, core, tokens, legal_forms, status_suffix, cpf_removed}."""
    display, n_cpf = strip_cpf_sequences(name)
    t = _fold_upper(display)
    t = re.sub(r"\bS\s*/\s*A\b", " SA ", t)
    t = re.sub(r"\bS\s*\.\s*A\b\.?", " SA ", t)
    t = t.replace("&", " E ")
    t = re.sub(r"[^0-9A-Z]+", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    status_suffix = None
    m = _STATUS_SUFFIX_RE.search(t)
    if m and m.start() > 0:
        status_suffix = m.group(1)
        t = t[: m.start()].strip()
    core = f" {t} "
    for phrase in _LEGAL_PHRASES:
        core = core.replace(f" {phrase} ", " ")
    words = core.split()
    tokens = [w for w in words if w not in LEGAL_FORM_TOKENS]
    return {"display": display, "normalized": t, "core": " ".join(tokens), "tokens": tokens,
            "legal_forms": [w for w in words if w in LEGAL_FORM_TOKENS], "status_suffix": status_suffix, "cpf_removed": n_cpf}


def name_similarity(a_core: str, b_core: str) -> float:
    """0..1 similarity of two normalised cores: mean of the difflib ratio and the token Jaccard index."""
    if not a_core or not b_core:
        return 0.0
    if a_core == b_core:
        return 1.0
    ratio = difflib.SequenceMatcher(None, a_core, b_core).ratio()
    ta, tb = set(a_core.split()), set(b_core.split())
    jac = len(ta & tb) / float(len(ta | tb)) if ta | tb else 0.0
    return round((ratio + jac) / 2.0, 3)


def match_kind(query_core: str, cand_core: str, field: str) -> str | None:
    """exact_razao | exact_fantasia | contains (every query token in the candidate) | fuzzy
    (similarity >= 0.75) | None (FC5 evidence, FC6 gate)."""
    if not query_core or not cand_core:
        return None
    if query_core == cand_core:
        return "exact_fantasia" if field == "fantasia" else "exact_razao"
    q, c = set(query_core.split()), set(cand_core.split())
    if q and q <= c:
        return "contains"
    if name_similarity(query_core, cand_core) >= FUZZY_THRESHOLD:
        return "fuzzy"
    return None


# ======================================================================================
# CNPJ helpers
# ======================================================================================

_CNPJ14 = re.compile(r"^[0-9A-Z]{12}[0-9]{2}$")


def normalize_cnpj(value: Any) -> str | None:
    t = re.sub(r"[\s./-]", "", _text(value)).upper()
    return t if _CNPJ14.match(t) else None


def valid_cnpj(value: Any) -> str | None:
    """14-character CNPJ with valid check digits (numeric or alphanumeric), else None."""
    n = normalize_cnpj(value)
    return n if n and validators.cnpj_valid(n) else None


def format_cnpj(value: Any) -> str | None:
    n = normalize_cnpj(value)
    return f"{n[:2]}.{n[2:5]}.{n[5:8]}/{n[8:12]}-{n[12:]}" if n else None


def followup_command(cnpj: Any) -> str | None:
    """FC5: the exact follow-up command printed for non-interactive scans."""
    f = format_cnpj(cnpj)
    return f"v3lum scan {f}" if f else None


# ======================================================================================
# hypotheses, ranking, auto-chain gate (FC5, FC6)
# ======================================================================================


def hypothesis(cnpj: Any, name: Any, nn: Mapping[str, Any] | None, q_core: str, kind: str, *, source: str, snapshot: str | None = None,
               active: bool | None = None, head_office: bool | None = None, situacao: str | None = None, uf: str | None = None,
               city: str | None = None, natural_person: bool = False, cnpj_derived: bool = False, **extra: Any) -> dict[str, Any]:
    """One 'possible CNPJ' hypothesis with its match evidence (always ``expand: False`` here)."""
    n = normalize_cnpj(cnpj)
    sim = 1.0 if kind.startswith("exact") else name_similarity(q_core, (nn or {}).get("core", ""))
    out = {
        "cnpj": n, "cnpj_root": n[:8] if n else None, "name": (nn or {}).get("display") or _text(name),
        "normalized_name": (nn or {}).get("normalized"), "similarity": sim, "match_kind": kind, "source": source,
        "snapshot": snapshot, "active": active, "head_office": head_office, "situacao": situacao, "uf": uf, "city": city,
        "natural_person_name": bool(natural_person), "cnpj_derived": bool(cnpj_derived), "followup": followup_command(n),
        "expand": False, "hypothesis": True,
    }
    out.update({k: v for k, v in extra.items() if v not in (None, "", [], {})})
    return out


def rank_hypotheses(hyps: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """FC3/FC5: exact razao social > exact nome fantasia > contains > fuzzy; then active, then head office,
    then similarity, then source (rfb, cvm, bcb, gleif, wikidata). A CNPJ keeps its best-ranked entry."""
    def key(h: Mapping[str, Any]) -> tuple[Any, ...]:
        return (_KIND_RANK.get(str(h.get("match_kind")), 9), 0 if h.get("active") else 1, 0 if h.get("head_office") else 1,
                -float(h.get("similarity") or 0.0), _SOURCE_RANK.get(str(h.get("source")), 9), str(h.get("cnpj") or ""))

    out: list[dict[str, Any]] = []
    kept: dict[Any, dict[str, Any]] = {}
    for h in sorted(hyps, key=key):
        k = h.get("cnpj") or (h.get("source"), h.get("name"))
        first = kept.get(k)
        if first is not None:  # the same CNPJ from another source: keep its evidence on the best entry
            if h.get("source") != first.get("source") and h.get("source") not in first.setdefault("also_in", []):
                first["also_in"].append(h.get("source"))
            for extra in ("verified_domains", "websites"):
                for v in h.get(extra) or ():
                    if v not in first.setdefault(extra, []):
                        first[extra].append(v)
            for extra in ("lei", "qid"):
                if h.get(extra) and not first.get(extra):
                    first[extra] = h[extra]
            continue
        item = dict(h)
        kept[k] = item
        out.append(item)
    return out


def auto_chain_decision(hyps: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """FC6: {auto, cnpj, reason}. Auto only when exactly one company root has an exact name match (legal or
    trade, active or not), that match is the razao social of an active head office from rfb/cvm/bcb, and
    it is not an MEI/EI name. Nome fantasia and the online fallbacks never auto-chain."""
    items = [dict(h) for h in hyps]
    exact = [h for h in items if h.get("match_kind") == "exact_razao"]
    if not exact:
        return {"auto": False, "cnpj": None, "reason": "no exact razao social match: analyst confirmation required"}
    roots = {h.get("cnpj_root") or h.get("cnpj") for h in items if h.get("match_kind") in ("exact_razao", "exact_fantasia")}
    if len(roots) != 1:
        return {"auto": False, "cnpj": None, "reason": f"{len(roots)} companies share the exact name: analyst confirmation required"}
    h = exact[0]
    if h.get("source") not in AUTO_CHAIN_SOURCES:
        return {"auto": False, "cnpj": None, "reason": "online fallback hits (large companies only) need analyst confirmation"}
    if h.get("natural_person_name"):
        return {"auto": False, "cnpj": None, "reason": "MEI/EI name (natural person): analyst confirmation required"}
    if not (h.get("active") and h.get("head_office")):
        return {"auto": False, "cnpj": None, "reason": "the exact match is not an active head office: analyst confirmation required"}
    return {"auto": True, "cnpj": h.get("cnpj"), "reason": "exact unique razao social of an active head office"}


def hypotheses_listing(hyps: list[Mapping[str, Any]], limit: int = MAX_LISTED) -> list[str]:
    """FC5: at most ``limit`` 'possible CNPJ' lines with evidence and the follow-up command, plus a remainder line."""
    lines = []
    for i, h in enumerate(hyps[:limit], 1):
        where = "/".join(x for x in (h.get("uf"), h.get("city")) if x) or "-"
        flags = ", ".join(x for x in (h.get("situacao"), "matriz" if h.get("head_office") else None,
                                      "derived /0001" if h.get("cnpj_derived") else None,
                                      "MEI/EI" if h.get("natural_person_name") else None, h.get("label")) if x)
        snap = f" {h['snapshot']}" if h.get("snapshot") else ""
        lines.append(f"{i}. possible CNPJ {format_cnpj(h.get('cnpj')) or '?'} {h.get('name')} ({where}; {flags or '-'}) "
                     f"match={h.get('match_kind')} similarity={float(h.get('similarity') or 0.0):.2f} source={h.get('source')}{snap} "
                     f"-> {h.get('followup') or '-'}")
    if len(hyps) > limit:
        lines.append(f"... {len(hyps) - limit} more hypotheses not shown (run interactively to choose)")
    return lines


# ======================================================================================
# step 2: the local RFB name index (FC2-FC4, FC9)
# ======================================================================================

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS names(
  id INTEGER PRIMARY KEY, cnpj TEXT NOT NULL, cnpj_basico TEXT NOT NULL, field TEXT NOT NULL,
  name TEXT NOT NULL, norm TEXT NOT NULL, core TEXT NOT NULL, uf TEXT, city TEXT,
  situacao TEXT, active INTEGER, head_office INTEGER, natural_person INTEGER);
"""


def fts5_available(conn: sqlite3.Connection) -> tuple[bool, str]:
    """FC3 runtime detection -> (available, via 'compile_options' | 'probe' | 'absent')."""
    try:
        opts = {str(r[0]).upper() for r in conn.execute("PRAGMA compile_options")}
    except sqlite3.Error:
        opts = set()
    if "ENABLE_FTS5" in opts:
        return True, "compile_options"
    try:
        conn.execute("CREATE VIRTUAL TABLE temp.v3lum_fts5_probe USING fts5(x)")
        conn.execute("DROP TABLE temp.v3lum_fts5_probe")
        return True, "probe"
    except sqlite3.Error:
        return False, "absent"


def _csv_rows(data: Any, encoding: str = "latin-1") -> Iterator[list[str]]:
    if isinstance(data, (bytes, bytearray)):
        stream: Iterable[str] = io.StringIO(bytes(data).decode(encoding, errors="replace"), newline="")
    elif isinstance(data, str):
        stream = io.StringIO(data, newline="")
    else:
        stream = data  # an iterable of text lines (a streamed zip member)
    yield from csv.reader(stream, delimiter=";", quotechar='"')


def parse_rfb_empresas(data: Any) -> Iterator[dict[str, Any]]:
    """FC2/FC4: RFB Empresas rows (7 fields, no header, ';', quoted, ISO-8859-1) -> {cnpj_basico,
    razao_social (CPF digits stripped), cpf_removed, natureza, porte, natural_person}. Capital and the
    responsible's qualification are never kept; malformed rows are skipped."""
    for row in _csv_rows(data):
        if len(row) != 7 or not re.fullmatch(r"[0-9A-Z]{8}", row[0].strip()):
            continue
        name, removed = strip_cpf_sequences(row[1])
        nat = row[2].strip()
        yield {"cnpj_basico": row[0].strip(), "razao_social": name, "cpf_removed": removed, "natureza": nat,
               "porte": row[5].strip() or None, "natural_person": nat in NATURE_NATURAL_PERSON}


def parse_rfb_estabelecimentos(data: Any) -> Iterator[dict[str, Any]]:
    """FC2/FC3: RFB Estabelecimentos rows (30 fields) -> {cnpj, cnpj_basico, head_office, nome_fantasia
    (CPF digits stripped), situacao, active, uf, municipio_code, cnae}. Address, phone and e-mail columns
    are never read (minimisation); rows with invalid CNPJs are skipped."""
    for row in _csv_rows(data):
        if len(row) != 30:
            continue
        cnpj = valid_cnpj((row[0] + row[1] + row[2]).strip())
        if not cnpj:
            continue
        fantasia, removed = strip_cpf_sequences(row[4])
        code = row[5].strip().zfill(2)
        yield {"cnpj": cnpj, "cnpj_basico": cnpj[:8], "head_office": row[3].strip() == "1", "nome_fantasia": fantasia or None,
               "cpf_removed": removed, "situacao": RFB_SITUACAO.get(code, "DESCONHECIDA"), "active": code == "02",
               "uf": row[19].strip() or None, "municipio_code": row[20].strip() or None, "cnae": row[11].strip() or None}


def parse_rfb_municipios(data: Any) -> dict[str, str]:
    """RFB Municipios table -> {code: name}."""
    return {r[0].strip(): r[1].strip() for r in _csv_rows(data) if len(r) == 2}


def rfb_light_files(entries: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """FC2 (for the P238 importer): from the WebDAV month listing keep Empresas{0-9}.zip and
    Estabelecimentos{0-9}.zip (+ Municipios.zip) -> {month, files, total_bytes}. Socios and Simples are never
    part of the light import (QSA stays P238)."""
    files, total, month = [], 0, None
    for e in entries or ():
        href = _text(e.get("href")) if isinstance(e, Mapping) else ""
        m = re.search(r"/(\d{4}-\d{2})/((?:Empresas|Estabelecimentos)\d\.zip|Municipios\.zip)$", href)
        if not m:
            continue
        month = month or m.group(1)
        size = e.get("bytes") if isinstance(e.get("bytes"), int) and not isinstance(e.get("bytes"), bool) else 0
        files.append({"name": m.group(2), "bytes": size, "last_modified": e.get("last_modified")})
        total += size
    return {"month": month, "files": files, "total_bytes": total}


def disk_space_check(free_bytes: int, download_bytes: int, factor: int = 3) -> dict[str, Any]:
    """FC2 (shared with P238 FC1): refuse when free space < ``factor`` x the download."""
    need = int(download_bytes) * factor
    ok = int(free_bytes) >= need
    return {"ok": ok, "need_bytes": need, "free_bytes": int(free_bytes),
            "message": None if ok else f"not enough disk space: {free_bytes / 1e9:.1f} GB free, {need / 1e9:.1f} GB needed ({factor}x the download)"}


def default_index_path() -> Path:
    return paths.datasets_dir() / "rfb_names" / INDEX_FILE


class NameIndexBuilder:
    """FC2-FC4: streaming builder of the light RFB name index, for the shared P238 importer
    (``v3lum data import-rfb --names``); never used during a scan.

    Usage: ``b = NameIndexBuilder(path, snapshot='2026-11')``; ``b.add_empresas(parse_rfb_empresas(f))`` and
    ``b.add_estabelecimentos(parse_rfb_estabelecimentos(f))`` for each streamed file (any order, batched
    inserts, bounded memory); ``b.finish(municipios)``. The index is written to a temporary file and moved
    into place atomically (0600). One 'razao' row per company (joined to its head office, else its first
    establishment) and one 'fantasia' row per distinct trade name (head office preferred)."""

    def __init__(self, path: str | os.PathLike[str] | None = None, *, snapshot: str = "", force_fallback: bool = False,
                 batch: int = 50_000) -> None:
        self.path = Path(path) if path else default_index_path()
        self.tmp = self.path.with_name(self.path.name + ".building")
        self.snapshot = snapshot
        self.force_fallback = force_fallback
        self.batch = max(1, int(batch))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.tmp.exists():
            self.tmp.unlink()
        self.conn = sqlite3.connect(str(self.tmp))
        self.conn.executescript(
            "PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;"
            "CREATE TABLE emp(cnpj_basico TEXT PRIMARY KEY, name TEXT, norm TEXT, core TEXT, natural_person INTEGER);"
            "CREATE TABLE est(cnpj TEXT PRIMARY KEY, cnpj_basico TEXT, head_office INTEGER, fantasia TEXT, fnorm TEXT,"
            " fcore TEXT, situacao TEXT, active INTEGER, uf TEXT, municipio TEXT);"
            "CREATE TABLE mun(code TEXT PRIMARY KEY, name TEXT);"
        )
        self.counts = {"empresas": 0, "estabelecimentos": 0, "cpf_removed": 0}

    def _insert(self, sql: str, rows: Iterable[tuple[Any, ...]]) -> int:
        n = 0
        chunk: list[tuple[Any, ...]] = []
        for row in rows:
            chunk.append(row)
            if len(chunk) >= self.batch:
                self.conn.executemany(sql, chunk)
                n += len(chunk)
                chunk = []
        if chunk:
            self.conn.executemany(sql, chunk)
            n += len(chunk)
        self.conn.commit()
        return n

    def add_empresas(self, records: Iterable[Mapping[str, Any]]) -> int:
        def rows() -> Iterator[tuple[Any, ...]]:
            for r in records:
                nn = normalize_company_name(r.get("razao_social"))
                self.counts["cpf_removed"] += int(r.get("cpf_removed") or 0) + int(nn["cpf_removed"])
                yield (r["cnpj_basico"], nn["display"], nn["normalized"], nn["core"], int(bool(r.get("natural_person"))))

        n = self._insert("INSERT OR REPLACE INTO emp VALUES (?,?,?,?,?)", rows())
        self.counts["empresas"] += n
        return n

    def add_estabelecimentos(self, records: Iterable[Mapping[str, Any]]) -> int:
        def rows() -> Iterator[tuple[Any, ...]]:
            for r in records:
                fn = normalize_company_name(r.get("nome_fantasia")) if r.get("nome_fantasia") else None
                self.counts["cpf_removed"] += int(r.get("cpf_removed") or 0) + int(fn["cpf_removed"] if fn else 0)
                yield (r["cnpj"], r["cnpj_basico"], int(bool(r.get("head_office"))), fn["display"] if fn else None,
                       fn["normalized"] if fn else None, fn["core"] if fn else "", r.get("situacao"), int(bool(r.get("active"))),
                       r.get("uf"), r.get("municipio_code"))

        n = self._insert("INSERT OR REPLACE INTO est VALUES (?,?,?,?,?,?,?,?,?,?)", rows())
        self.counts["estabelecimentos"] += n
        return n

    def finish(self, municipios: Mapping[str, str] | None = None) -> dict[str, Any]:
        c = self.conn
        self._insert("INSERT OR REPLACE INTO mun VALUES (?,?)", ((str(k), str(v)) for k, v in (municipios or {}).items()))
        c.executescript("CREATE INDEX est_basico ON est(cnpj_basico, head_office DESC, cnpj);" + _SCHEMA)
        c.execute(
            "INSERT INTO names(cnpj, cnpj_basico, field, name, norm, core, uf, city, situacao, active, head_office, natural_person) "
            "SELECT e.cnpj, emp.cnpj_basico, 'razao', emp.name, emp.norm, emp.core, e.uf, COALESCE(m.name, e.municipio), e.situacao, "
            "e.active, e.head_office, emp.natural_person FROM emp "
            "JOIN est e ON e.rowid = (SELECT x.rowid FROM est x WHERE x.cnpj_basico = emp.cnpj_basico ORDER BY x.head_office DESC, x.cnpj LIMIT 1) "
            "LEFT JOIN mun m ON m.code = e.municipio WHERE emp.core != ''")
        c.execute(
            "INSERT INTO names(cnpj, cnpj_basico, field, name, norm, core, uf, city, situacao, active, head_office, natural_person) "
            "SELECT e.cnpj, e.cnpj_basico, 'fantasia', e.fantasia, e.fnorm, e.fcore, e.uf, COALESCE(m.name, e.municipio), e.situacao, "
            "e.active, e.head_office, emp.natural_person FROM est e JOIN emp ON emp.cnpj_basico = e.cnpj_basico "
            "LEFT JOIN mun m ON m.code = e.municipio WHERE e.fcore != '' AND e.fcore != emp.core AND e.rowid = "
            "(SELECT y.rowid FROM est y WHERE y.cnpj_basico = e.cnpj_basico AND y.fcore = e.fcore ORDER BY y.head_office DESC, y.cnpj LIMIT 1)")
        c.executescript("DROP TABLE emp; DROP TABLE est; DROP TABLE mun; CREATE INDEX names_core ON names(core);")
        fts, via = fts5_available(c)
        mode = "fts5" if fts and not self.force_fallback else "tokens"
        if mode == "fts5":
            c.execute("CREATE VIRTUAL TABLE names_fts USING fts5(core, content='names', content_rowid='id', tokenize='unicode61 remove_diacritics 2')")
            c.execute("INSERT INTO names_fts(rowid, core) SELECT id, core FROM names")
        else:
            c.execute("CREATE TABLE name_tokens(token TEXT NOT NULL, id INTEGER NOT NULL)")
            cur = c.execute("SELECT id, core FROM names")
            while True:
                part = cur.fetchmany(self.batch)
                if not part:
                    break
                c.executemany("INSERT INTO name_tokens(token, id) VALUES (?,?)", [(tok, rid) for rid, core in part for tok in set(core.split())])
            c.execute("CREATE INDEX name_tokens_tok ON name_tokens(token, id)")
        rows = c.execute("SELECT COUNT(*) FROM names").fetchone()[0]
        meta = {"schema": INDEX_SCHEMA, "mode": mode, "fts5_via": via, "snapshot": self.snapshot, "rows": str(rows),
                "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        c.executemany("INSERT OR REPLACE INTO meta(key, value) VALUES (?,?)", list(meta.items()))
        c.commit()
        c.close()
        os.replace(self.tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:  # pragma: no cover - best effort on exotic filesystems
            pass
        return {"path": str(self.path), "mode": mode, "rows": rows, **self.counts}


def build_index(path: str | os.PathLike[str], empresas: Iterable[Mapping[str, Any]], estabelecimentos: Iterable[Mapping[str, Any]],
                municipios: Mapping[str, str] | None = None, *, snapshot: str = "", force_fallback: bool = False) -> dict[str, Any]:
    """One-call build (tests and small slices): :class:`NameIndexBuilder` over parsed records."""
    b = NameIndexBuilder(path, snapshot=snapshot, force_fallback=force_fallback)
    b.add_empresas(empresas)
    b.add_estabelecimentos(estabelecimentos)
    return b.finish(municipios)


class NameIndexError(Exception):
    """The local index exists but cannot be read (corrupt, wrong schema): could not verify."""


def default_rfb_import_path() -> Path:
    """The SQLite written by the shared P238 importer (``rfb_import``: ``--tables names`` or more)."""
    return paths.datasets_dir() / "rfb_cnpj_bulk" / "rfb_cnpj.sqlite"


def build_from_rfb_import(source: str | os.PathLike[str] | None = None, out: str | os.PathLike[str] | None = None, *,
                          force_fallback: bool = False) -> dict[str, Any]:
    """FC1/FC2 bridge: build the light name index from the tables the shared P238 importer stored
    (``python -m v3lum.modules.brazil_public_data.rfb_import --names`` today, ``v3lum data import-rfb --names``
    once the core command is wired). Reads ``empresas`` and ``estabelecimentos`` (plus the ``municipios``
    lookup) read-only and streams them through :class:`NameIndexBuilder`; CPF digits are stripped again
    (FC4) whatever the importer did. Never called during a scan."""
    src = Path(source) if source else default_rfb_import_path()
    if not src.is_file():
        raise NameIndexError(f"RFB import not found at {src}: run the RFB importer with --tables names first")
    uri = "file:" + quote(str(src.resolve())) + "?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
        meta = dict(conn.execute("SELECT k, v FROM meta").fetchall())
        mun = {str(c): str(d) for c, d in conn.execute("SELECT codigo, descricao FROM lookups WHERE tbl = 'municipios'")}
    except sqlite3.Error as exc:
        raise NameIndexError(f"RFB import unreadable ({exc}): re-run the importer") from exc

    def empresas() -> Iterator[dict[str, Any]]:
        for basico, razao, natureza in conn.execute("SELECT cnpj_basico, razao_social, natureza FROM empresas"):
            name, removed = strip_cpf_sequences(razao)
            yield {"cnpj_basico": str(basico or "").upper(), "razao_social": name, "cpf_removed": removed,
                   "natural_person": str(natureza or "") in NATURE_NATURAL_PERSON}

    def estabelecimentos() -> Iterator[dict[str, Any]]:
        for cnpj, basico, matriz, fantasia, situacao, uf, municipio in conn.execute(
                "SELECT cnpj, cnpj_basico, matriz, nome_fantasia, situacao, uf, municipio FROM estabelecimentos"):
            n = valid_cnpj(cnpj)
            if not n:
                continue
            name, removed = strip_cpf_sequences(fantasia) if fantasia else ("", 0)
            yield {"cnpj": n, "cnpj_basico": str(basico or n[:8]).upper(), "head_office": bool(matriz), "nome_fantasia": name or None,
                   "cpf_removed": removed, "situacao": situacao or "DESCONHECIDA", "active": situacao == "ATIVA", "uf": uf,
                   "municipio_code": municipio}

    try:
        builder = NameIndexBuilder(out, snapshot=str(meta.get("snapshot") or ""), force_fallback=force_fallback)
        builder.add_empresas(empresas())
        builder.add_estabelecimentos(estabelecimentos())
        return builder.finish(mun)
    except sqlite3.Error as exc:
        raise NameIndexError(f"RFB import unreadable ({exc}): re-run the importer") from exc
    finally:
        conn.close()


class NameIndex:
    """Read-only view of the local RFB name index (FC2: a scan only opens it read-only)."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        uri = "file:" + quote(str(self.path.resolve())) + "?mode=ro"
        try:
            self.conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
            self.meta = dict(self.conn.execute("SELECT key, value FROM meta").fetchall())
        except sqlite3.Error as exc:
            raise NameIndexError(f"local name index unreadable: {exc}") from exc
        if self.meta.get("schema") != INDEX_SCHEMA or self.meta.get("mode") not in ("fts5", "tokens"):
            self.close()
            raise NameIndexError(f"local name index has an unknown schema ({self.meta.get('schema')!r}): rebuild it with v3lum data import-rfb --names")

    @property
    def mode(self) -> str:
        return str(self.meta.get("mode") or "")

    @property
    def snapshot(self) -> str | None:
        return self.meta.get("snapshot") or None

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:  # pragma: no cover
            pass

    def __enter__(self) -> NameIndex:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _candidates(self, core: str, cap: int) -> list[int]:
        ids = [r[0] for r in self.conn.execute("SELECT id FROM names WHERE core = ? LIMIT ?", (core, cap))]
        toks = sorted(set(core.split()))
        if self.mode == "fts5":
            expr = " AND ".join(f'"{t}"' for t in toks)
            ids += [r[0] for r in self.conn.execute("SELECT rowid FROM names_fts WHERE names_fts MATCH ? LIMIT ?", (expr, cap))]
        else:
            sql = (f"SELECT id FROM name_tokens WHERE token IN ({','.join('?' * len(toks))}) "
                   "GROUP BY id HAVING COUNT(DISTINCT token) = ? LIMIT ?")
            ids += [r[0] for r in self.conn.execute(sql, (*toks, len(toks), cap))]
        return list(dict.fromkeys(ids))


def query_index(index: NameIndex, name: Any, *, input_type: str = "company_name", limit: int = MAX_HYPOTHESES, cap: int = 500) -> list[dict[str, Any]]:
    """FC3-FC5: ranked hypotheses for a company name: exact core first, then every row holding all core
    tokens; active head offices rank first. Natural-person (MEI/EI) rows answer exact matches only. A
    person search is refused (FC4: the index serves company-name search only)."""
    if input_type not in ("company_name", "keyword"):
        raise ValueError("the RFB name index serves company-name search only (P361 FC4)")
    q = normalize_company_name(name)["core"]
    if not q:
        return []
    try:
        ids = index._candidates(q, cap)
        if not ids:
            return []
        rows = index.conn.execute(
            "SELECT cnpj, field, name, core, uf, city, situacao, active, head_office, natural_person FROM names "
            f"WHERE id IN ({','.join('?' * len(ids))})", ids).fetchall()
    except sqlite3.Error as exc:
        raise NameIndexError(f"local name index query failed: {exc}") from exc
    out = []
    for cnpj, field, disp, core, uf, city, sit, active, head, natural in rows:
        kind = match_kind(q, core, field)
        if not kind or (natural and not kind.startswith("exact")):
            continue
        nn = normalize_company_name(disp)
        out.append(hypothesis(cnpj, disp, nn, q, kind, source="rfb", snapshot=index.snapshot, active=bool(active), head_office=bool(head),
                              situacao=sit, uf=uf, city=city, natural_person=bool(natural), field=field))
    return rank_hypotheses(out)[:limit]


# ======================================================================================
# step 1: offline sector registries (CVM, BCB) through the shared loaders (FC1)
# ======================================================================================


def _cvm_active(row: Mapping[str, Any]) -> bool:
    return row.get("status") == "active" or cvm.fold(row.get("status_raw")) in ("ATIVO", "ATIVA")


def registry_rows(cvm_rows: Iterable[Mapping[str, Any]], bcb_institutions: Mapping[str, Mapping[str, Any]], *,
                  cvm_snapshot: str | None = None, bcb_snapshot: str | None = None) -> list[dict[str, Any]]:
    """Candidate names of the sector registries: CVM legal and trade names (formatted CNPJ, status, UF,
    city) and BCB institution names (head-office CNPJ derived from the root, labelled 'derived')."""
    out: list[dict[str, Any]] = []
    for r in cvm_rows:
        cnpj = valid_cnpj(r.get("cnpj"))
        if not cnpj or r.get("natural_person"):
            continue
        for field, name in (("razao", r.get("name")), ("fantasia", r.get("trade_name"))):
            if not name:
                continue
            nn = normalize_company_name(name)
            if not nn["core"]:
                continue
            out.append({"cnpj": cnpj, "field": field, "name": name, "nn": nn, "source": "cvm", "snapshot": cvm_snapshot,
                        "active": _cvm_active(r), "head_office": cnpj[8:12] == "0001", "uf": r.get("uf"), "city": r.get("municipality"),
                        "situacao": f"CVM {r.get('status_raw') or r.get('status') or '?'}", "registry": r.get("registry")})
    for root, inst in bcb_institutions.items():
        name = inst.get("name")
        cnpj = cvm.head_office_cnpj(root)
        nn = normalize_company_name(name) if name else None
        if not cnpj or not nn or not nn["core"]:
            continue
        out.append({"cnpj": cnpj, "field": "razao", "name": name, "nn": nn, "source": "bcb", "snapshot": bcb_snapshot, "active": True,
                    "head_office": True, "uf": inst.get("uf"), "city": None, "situacao": "em funcionamento (BCB)", "cnpj_derived": True,
                    "segments": list(inst.get("segments") or [])[:3], "verified_domains": list(inst.get("verified_domains") or [])})
    return out


class RegistryIndex:
    """Token-blocked candidate rows of the sector registries (built once per dataset version)."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.tokens: dict[str, list[int]] = {}
        for i, r in enumerate(rows):
            for tok in set(r["nn"]["core"].split()):
                self.tokens.setdefault(tok, []).append(i)

    def match(self, query: Any) -> list[dict[str, Any]]:
        q = normalize_company_name(query)["core"]
        if not q:
            return []
        cand: set[int] = set()
        for tok in set(q.split()):
            cand.update(self.tokens.get(tok, ()))
        out = []
        for i in sorted(cand):
            r = self.rows[i]
            kind = match_kind(q, r["nn"]["core"], r["field"])
            if not kind:
                continue
            extra = {k: r.get(k) for k in ("registry", "segments", "verified_domains", "field") if r.get(k)}
            out.append(hypothesis(r["cnpj"], r["name"], r["nn"], q, kind, source=r["source"], snapshot=r.get("snapshot"),
                                  active=r.get("active"), head_office=r.get("head_office"), situacao=r.get("situacao"), uf=r.get("uf"),
                                  city=r.get("city"), cnpj_derived=bool(r.get("cnpj_derived")), **extra))
        return rank_hypotheses(out)


_LOCK = threading.Lock()
_CIA: dict[str, tuple[str, cvm.ParsedRegistry]] = {}
_REG: dict[tuple[tuple[str, str], ...], RegistryIndex] = {}


def _cia_aberta(data: Any) -> tuple[cvm.ParsedRegistry, dict[str, Any]]:
    path = cvm.local_path(data, CIA_ABERTA_DATASET)
    meta = cvm.dataset_meta(data, CIA_ABERTA_DATASET)
    with _LOCK:
        hit = _CIA.get(CIA_ABERTA_DATASET)
    if hit is not None and meta["sha256"] and hit[0] == meta["sha256"]:
        parsed = hit[1]
    else:
        try:
            parsed = cvm.parse_cvm_csv(path.read_bytes(), "cia_aberta")
        except OSError as exc:
            parsed = cvm.ParsedRegistry("cia_aberta", error=f"cannot read the local copy: {exc}")
        with _LOCK:
            _CIA[CIA_ABERTA_DATASET] = (meta["sha256"], parsed)
    meta["rows"] = len(parsed.rows)
    return parsed, meta


def load_registries(data: Any, *, cia: bool = True, companies: bool = True, institutions: bool = True) -> dict[str, Any]:
    """The CVM and BCB registries from the local copies only (never downloads). -> {index, states {cia,
    pj, bcb: ok | missing | error}, datasets, missing, errors, cvm_date, bcb_date}. Missing or unparsable
    copies are listed, never read as 'no match'."""
    missing: list[str] = []
    errors: list[str] = []
    metas: list[dict[str, Any]] = []
    cvm_rows: list[dict[str, Any]] = []
    states = {"cia": "off", "pj": "off", "bcb": "off"}
    if cia:
        try:
            parsed, meta = _cia_aberta(data)
            if parsed.ok:
                cvm_rows.extend(parsed.rows)
                metas.append(meta)
                states["cia"] = "ok"
            else:
                errors.append(f"{CIA_ABERTA_DATASET}: {parsed.error} (run v3lum data update {CIA_ABERTA_DATASET})")
                states["cia"] = "error"
        except DatasetUnavailable:
            missing.append(CIA_ABERTA_DATASET)
            states["cia"] = "missing"
    if companies:
        index_cvm = cvm.load_companies(data)
        missing.extend(index_cvm.missing)
        errors.extend(index_cvm.errors)
        metas.extend(index_cvm.datasets)
        if index_cvm.present:
            states["pj"] = "ok"
            cvm_rows.extend(dict(reg, natural_person=False) for regs in index_cvm.by_root.values() for reg in regs)
        else:
            states["pj"] = "error" if index_cvm.errors else "missing"
    bcb_institutions: Mapping[str, Any] = {}
    bcb_date = None
    if institutions:
        index_bcb = bcb.load_bcb(data, sedes=True)
        missing.extend(index_bcb.missing)
        errors.extend(index_bcb.errors)
        metas.extend(index_bcb.datasets)
        bcb_institutions = index_bcb.institutions
        bcb_date = index_bcb.as_of or None
        states["bcb"] = "ok" if bcb_institutions else ("error" if index_bcb.errors else "missing")
    cvm_date = min((m.get("date") or "" for m in metas if str(m.get("name", "")).startswith("cvm_")), default="") or None
    signature = tuple(sorted((str(m.get("name")), str(m.get("sha256"))) for m in metas))
    with _LOCK:
        idx = _REG.get(signature) if signature else None
    if idx is None:
        idx = RegistryIndex(registry_rows(cvm_rows, bcb_institutions, cvm_snapshot=cvm_date, bcb_snapshot=bcb_date))
        if signature:
            with _LOCK:
                _REG.clear()
                _REG[signature] = idx
    return {"index": idx, "states": states, "datasets": metas, "missing": missing, "errors": errors, "cvm_date": cvm_date,
            "bcb_date": bcb_date}


# ======================================================================================
# online fallbacks (FC7): GLEIF and Wikidata P6204
# ======================================================================================


def gleif_url(name: str) -> str:
    """FC7: ``filter[fulltext]`` limited to Brazilian legal addresses, first page (<= 10 records)."""
    if gc is not None:
        return gc.fulltext_url(name, country="BR")
    return GLEIF_URL + "?" + urlencode({"filter[fulltext]": name, "filter[entity.legalAddress.country]": "BR", "page[size]": "10"})


def records_from_shared(doc: Any) -> dict[str, Any]:
    """The shared P220 parser (``gleif_client.parse_lei_records``) mapped onto the fields
    :func:`gleif_hypotheses` reads."""
    parsed = gc.parse_lei_records(doc)
    records = [{"lei": r.get("lei"), "legal_name": r.get("legal_name") or "", "other_names": list(r.get("other_names") or []),
                "registered_at": r.get("registered_at"), "registered_as": r.get("registered_as"), "cnpj": valid_cnpj(r.get("cnpj")),
                "category": r.get("category"), "entity_status": r.get("entity_status"),
                "registration_status": r.get("registration_status"), "last_update": r.get("last_update"),
                "city": (r.get("legal_address") or {}).get("city")} for r in parsed.get("records", ())]
    return {"total": parsed.get("total", len(records)), "records": records}


def _answer_exception(ans: Any) -> Exception:
    """A could-not-verify GleifAnswer of the shared client as the exception the resolver maps per source."""
    if ans.state == "rate_limited":
        return RateLimited(ans.reason, ans.status, ans.url)
    if ans.state == "quota":
        return QuotaExceeded(ans.reason, ans.status, ans.url)
    if ans.state == "blocked":
        return Blocked(ans.reason, ans.status, ans.url, reason_code=ans.reason_code or "challenge")
    if ans.reason_code == "timeout":
        return NetworkError(ans.reason, retryable=False, kind="timeout")
    return HttpError(ans.reason, ans.status, ans.url)


def gleif_error_in_200(body: Any) -> str | None:
    """JSON:API ``errors`` in a 2xx body, or a body without ``data``."""
    if isinstance(body, dict) and body.get("errors"):
        errs = body["errors"] if isinstance(body["errors"], list) else []
        first = errs[0] if errs and isinstance(errs[0], dict) else {}
        return f"GLEIF error {_text(first.get('status'))} {_text(first.get('title'))}".strip()
    if not isinstance(body, dict) or "data" not in body:
        return "GLEIF body without 'data'"
    return None


def parse_gleif_records(body: Any) -> dict[str, Any]:
    """GLEIF lei-records (list or single record) -> {total, records [lei, legal_name, other_names,
    registered_at, registered_as, cnpj (a valid CNPJ in registeredAs of a BR entity), category,
    entity_status, registration_status, last_update, city]}."""
    js = body if isinstance(body, dict) else {}
    data = js.get("data")
    recs = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
    out = []
    for r in recs:
        r = r if isinstance(r, dict) else {}
        a = r.get("attributes") if isinstance(r.get("attributes"), dict) else {}
        e = a.get("entity") if isinstance(a.get("entity"), dict) else {}
        reg = a.get("registration") if isinstance(a.get("registration"), dict) else {}
        ra = _text((e.get("registeredAt") or {}).get("id") if isinstance(e.get("registeredAt"), dict) else "")
        ras = _text(e.get("registeredAs")).strip() or None
        juris = _text(e.get("jurisdiction"))
        addr = e.get("legalAddress") if isinstance(e.get("legalAddress"), dict) else {}
        cnpj = valid_cnpj(ras) if ras and (ra == "RA000041" or juris == "BR" or _text(addr.get("country")) == "BR") else None
        legal = e.get("legalName") if isinstance(e.get("legalName"), dict) else {}
        others = e.get("otherNames") if isinstance(e.get("otherNames"), list) else []
        out.append({"lei": _text(a.get("lei")) or _text(r.get("id")) or None, "legal_name": _text(legal.get("name")).strip(),
                    "other_names": [_text(n.get("name")) for n in others if isinstance(n, dict) and _text(n.get("name"))],
                    "registered_at": ra or None, "registered_as": ras, "cnpj": cnpj, "category": _text(e.get("category")) or None,
                    "entity_status": _text(e.get("status")) or None, "registration_status": _text(reg.get("status")) or None,
                    "last_update": _text(reg.get("lastUpdateDate"))[:10] or None, "city": _text(addr.get("city")) or None})
    meta = js.get("meta") if isinstance(js.get("meta"), dict) else {}
    pag = meta.get("pagination") if isinstance(meta.get("pagination"), dict) else {}
    total = pag.get("total")
    return {"total": total if isinstance(total, int) and not isinstance(total, bool) else len(out), "records": out}


def gleif_hypotheses(parsed: Mapping[str, Any], query: Any) -> dict[str, Any]:
    """FC7: GLEIF hypotheses ('large companies only'). Dropped and counted: SOLE_PROPRIETOR (natural
    persons, rule 4), DUPLICATE/ANNULLED registrations, FUND entities and records without a valid CNPJ."""
    q = normalize_company_name(query)["core"]
    out, dropped = [], {"no_cnpj": 0, "sole_proprietor": 0, "duplicate_or_annulled": 0, "fund": 0}
    for r in parsed.get("records", ()):
        if r.get("category") == "SOLE_PROPRIETOR":
            dropped["sole_proprietor"] += 1
            continue
        if r.get("registration_status") in ("DUPLICATE", "ANNULLED"):
            dropped["duplicate_or_annulled"] += 1
            continue
        if r.get("category") == "FUND":
            dropped["fund"] += 1
            continue
        if not r.get("cnpj"):
            dropped["no_cnpj"] += 1
            continue
        best = None
        for field, name in [("razao", r.get("legal_name"))] + [("fantasia", n) for n in r.get("other_names", ())]:
            nn = normalize_company_name(name)
            kind = match_kind(q, nn["core"], field)
            if kind and (best is None or _KIND_RANK[kind] < _KIND_RANK[best[0]]):
                best = (kind, name, nn)
        if best is None:
            nn = normalize_company_name(r.get("legal_name"))
            best = ("fuzzy", r.get("legal_name"), nn)
        out.append(hypothesis(r["cnpj"], best[1], best[2], q, best[0], source="gleif", active=r.get("entity_status") == "ACTIVE",
                              head_office=r["cnpj"][8:12] == "0001",
                              situacao=f"GLEIF {r.get('entity_status') or '?'}/{r.get('registration_status') or '?'}", city=r.get("city"),
                              lei=r.get("lei"), label=ONLINE_LABEL))
    return {"hypotheses": rank_hypotheses(out), "dropped": dropped}


def wikidata_search_url(name: str) -> str:
    phrase = re.sub(r'["\\]', " ", _text(name)).strip()
    return WIKIDATA_API + "?" + urlencode({"action": "query", "list": "search", "srsearch": f'haswbstatement:P6204 "{phrase}"',
                                           "srlimit": "10", "format": "json"})


def wikidata_entities_url(qids: Iterable[str]) -> str:
    return WIKIDATA_API + "?" + urlencode({"action": "wbgetentities", "ids": "|".join(qids), "props": "labels|aliases|claims",
                                           "languages": "pt|en", "format": "json"})


def wikidata_error_in_200(body: Any) -> str | None:
    """MediaWiki API errors come with HTTP 200: {'error': {'code': ...}}."""
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        return f"Wikidata API error {_text(body['error'].get('code'))}"
    if not isinstance(body, dict):
        return "Wikidata answer is not a JSON object"
    return None


def parse_wikidata_search(body: Any) -> dict[str, Any]:
    """action=query&list=search -> {total, qids}."""
    q = body.get("query") if isinstance(body, dict) and isinstance(body.get("query"), dict) else {}
    search = q.get("search") if isinstance(q.get("search"), list) else []
    qids = [_text(s.get("title")) for s in search if isinstance(s, dict) and re.fullmatch(r"Q\d+", _text(s.get("title")))]
    info = q.get("searchinfo") if isinstance(q.get("searchinfo"), dict) else {}
    total = info.get("totalhits")
    return {"total": total if isinstance(total, int) and not isinstance(total, bool) else len(qids), "qids": qids[:10]}


def _claim_values(claims: Any, prop: str) -> list[str]:
    vals = []
    for c in (claims or {}).get(prop, []) if isinstance(claims, dict) and isinstance(claims.get(prop), list) else []:
        if not isinstance(c, dict) or c.get("rank") == "deprecated":
            continue
        snak = c.get("mainsnak") if isinstance(c.get("mainsnak"), dict) else {}
        if snak.get("snaktype") != "value":
            continue
        dv = snak.get("datavalue") if isinstance(snak.get("datavalue"), dict) else {}
        v = dv.get("value")
        if isinstance(v, dict) and v.get("id"):
            vals.append(_text(v["id"]))
        elif isinstance(v, str):
            vals.append(v)
    return vals


def parse_wbgetentities(body: Any) -> dict[str, dict[str, Any]]:
    """wbgetentities -> {qid: {missing, labels, aliases, cnpjs (valid P6204, deprecated ranks ignored), websites (P856)}}."""
    ents = body.get("entities") if isinstance(body, dict) and isinstance(body.get("entities"), dict) else {}
    out: dict[str, dict[str, Any]] = {}
    for qid, ent in ents.items():
        ent = ent if isinstance(ent, dict) else {}
        if "missing" in ent:
            out[str(qid)] = {"missing": True}
            continue
        claims = ent.get("claims")
        cnpjs: list[str] = []
        for v in _claim_values(claims, "P6204"):
            n = valid_cnpj(v)
            if n and n not in cnpjs:
                cnpjs.append(n)
        labels = ent.get("labels") if isinstance(ent.get("labels"), dict) else {}
        aliases = ent.get("aliases") if isinstance(ent.get("aliases"), dict) else {}
        out[str(qid)] = {
            "missing": False,
            "labels": {str(k): _text(v.get("value")) for k, v in labels.items() if isinstance(v, dict)},
            "aliases": [_text(a.get("value")) for v in aliases.values() if isinstance(v, list) for a in v if isinstance(a, dict)],
            "cnpjs": cnpjs,
            "websites": [w for w in _claim_values(claims, "P856") if re.match(r"^https?://", w)],
        }
    return out


def wikidata_hypotheses(entities: Mapping[str, Mapping[str, Any]], query: Any) -> list[dict[str, Any]]:
    """FC7: items carrying a valid P6204 CNPJ -> hypotheses ('large companies only')."""
    q = normalize_company_name(query)["core"]
    out = []
    for qid, ent in entities.items():
        if ent.get("missing") or not ent.get("cnpjs"):
            continue
        best = None
        for name in [*ent.get("labels", {}).values(), *ent.get("aliases", [])]:
            nn = normalize_company_name(name)
            kind = match_kind(q, nn["core"], "razao")
            if kind and (best is None or _KIND_RANK[kind] < _KIND_RANK[best[0]]):
                best = (kind, name, nn)
        if best is None:
            continue
        for c in ent["cnpjs"]:
            out.append(hypothesis(c, best[1], best[2], q, best[0], source="wikidata", head_office=c[8:12] == "0001", qid=qid,
                                  label=ONLINE_LABEL, websites=list(ent.get("websites") or [])[:3]))
    return rank_hypotheses(out)


def _exc_status(exc: BaseException) -> tuple[Status, str, str]:
    """(status, reason_code, short reason) of a per-source failure (rule 5: could not verify)."""
    if isinstance(exc, RateLimited):
        return Status.RATE_LIMITED, "rate_limited", "rate limited"
    if isinstance(exc, QuotaExceeded):
        return Status.QUOTA, "quota", "quota exhausted"
    if isinstance(exc, Blocked):
        code = getattr(exc, "reason_code", "") or "challenge"
        return Status.BLOCKED, code if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge", "blocked"
    if isinstance(exc, AuthRequired):
        return Status.BLOCKED, "challenge", "refused (HTTP 401/403)"
    if isinstance(exc, ConfigError):
        return Status.SKIPPED, "config", "needs setting contact_email (Wikimedia User-Agent policy)"
    if isinstance(exc, PolicyError):
        code = getattr(exc, "reason_code", "") or "policy"
        return Status.SKIPPED, code if code in ("policy", "tlp", "scope", "egress_country", "privacy", "tier", "licence") else "policy", "refused by policy"
    if isinstance(exc, OfflineError):
        return Status.UNAVAILABLE, "offline", "offline mode"
    if isinstance(exc, DeadlineExceeded) or "timeout" in str(getattr(exc, "kind", "") or "").lower() or \
            "timed out" in str(exc).lower() or "timeout" in str(exc).lower():
        return Status.ERROR, "timeout", "timeout"
    return Status.ERROR, "error", "error"


SOURCE_OF = {"rfb": SOURCE_INDEX, "cvm": SOURCE_CVM, "bcb": SOURCE_BCB, "gleif": SOURCE_GLEIF, "wikidata": SOURCE_WIKIDATA}


def _finding_source(top: Mapping[str, Any]) -> str:
    if top.get("source") == "cvm" and top.get("registry") == "cia_aberta":
        return SOURCE_CVM_CIA
    return SOURCE_OF.get(str(top.get("source")), "")
_ONLINE_ERRORS = (RateLimited, QuotaExceeded, Blocked, AuthRequired, ConfigError, PolicyError, HttpError, NetworkError)


# ======================================================================================
# the module
# ======================================================================================


@register
class CnpjNameResolver(Module):
    name = "cnpj_name_resolver"
    title = "Company name -> CNPJ resolver"
    description = (
        "Ranked 'possible CNPJ' hypotheses for a Brazilian company name: local RFB name index (when installed), CVM and BCB "
        "registries offline, GLEIF online fallback (large companies only; Wikidata P6204 in cnpj_name_resolver_wikidata); "
        "expand=False unless the exact unique razao social of an active head office."
    )
    category = "brazil_public_data"
    accepts = {T.ORG, T.KEYWORD}
    produces = {T.CNPJ, T.DOMAIN}
    tags = {"brazil", "free"}
    reference = "https://dados.gov.br/dados/conjuntos-dados/cadastro-nacional-da-pessoa-juridica---cnpj"
    notice = (
        "Company-name search only (never person search, LGPD): MEI/EI names are indexed without CPF digits and answer exact "
        "matches only. Hypotheses are never confirmed links: only the exact unique razao social of an active head office is "
        "investigated automatically. Online fallbacks (GLEIF CC0, Wikidata CC0) cover large companies only; CVM data ODbL, "
        "BCB and RFB open data."
    )
    # ---- declarations ------------------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # GLEIF receives the company name (online fallback only)
    hosts = ("api.gleif.org",)
    provider = "rfb"
    sources = (SOURCE_INDEX, SOURCE_CVM, SOURCE_CVM_CIA, SOURCE_BCB, SOURCE_GLEIF)
    access_model = "free_noauth_limited"
    max_requests = 1  # GLEIF fulltext (0 when the local index answers)
    expected_latency = 2.0
    timeout = 45.0
    min_interval = 1.0
    cache_ttl = 86400
    daily_quota = 500
    max_pivots = MAX_LISTED + MAX_DOMAIN_PIVOTS * 2
    default_enabled = True
    settings = {
        "cnpj_name_resolver_index_path": SettingSpec("", "cnpj_name_resolver: path of the local RFB name index built by "
                                                         "`v3lum data import-rfb --names` ('' = ~/.v3lum/datasets/rfb_names/rfb_names.sqlite)."),
    }

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        refused = _precheck(self, entity, ctx, res)
        if refused is not None:
            return refused
        query = " ".join(str(entity.value or "").split())
        nn = normalize_company_name(query)
        allowed = frozenset(getattr(ctx, "allowed_sources", None) or self.sources)
        hyps: list[dict[str, Any]] = []
        states: dict[str, str] = {}
        answered: list[str] = []
        failures: list[BaseException] = []

        # step 2: the local RFB name index (read-only, never built here)
        local = {"state": "not_installed", "line": INDEX_MISSING_TEXT}
        index_hits: list[dict[str, Any]] = []
        if SOURCE_INDEX in allowed:
            path = index_path(ctx)
            if path.is_file():
                try:
                    with NameIndex(path) as idx:
                        index_hits = query_index(idx, query, input_type=entity.type.value)
                        local = {"state": "installed", "snapshot": idx.snapshot, "mode": idx.mode, "rows": idx.meta.get("rows")}
                    res.source_status(SOURCE_INDEX, Status.OK if index_hits else Status.EMPTY)
                    answered.append("rfb_index")
                except NameIndexError as exc:
                    local = {"state": "error", "line": str(exc)}
                    res.source_status(SOURCE_INDEX, Status.ERROR, reason=str(exc))
                    failures.append(exc)
            else:
                res.source_status(SOURCE_INDEX, Status.UNAVAILABLE, reason_code="dataset", reason=INDEX_MISSING_TEXT)
            states["rfb_index"] = local["state"] if local["state"] != "installed" else ("match" if index_hits else "no_match")
        hyps.extend(index_hits)

        # step 1: CVM and BCB registries (local copies only)
        use = {"cia": SOURCE_CVM_CIA in allowed, "pj": SOURCE_CVM in allowed, "bcb": SOURCE_BCB in allowed}
        reg = None
        if any(use.values()):
            try:
                reg = load_registries(ctx.data, cia=use["cia"], companies=use["pj"], institutions=use["bcb"])
            except (DatasetError, OSError, ValueError) as exc:
                states["registries"] = "error"
                failures.append(DatasetError(f"registries unreadable: {exc}"))
        if reg is not None:
            reg_hits = reg["index"].match(query)
            hyps.extend(reg_hits)
            parts = (("cvm_cia_aberta", "cia", SOURCE_CVM_CIA, lambda h: h["source"] == "cvm" and h.get("registry") == "cia_aberta"),
                     ("cvm", "pj", SOURCE_CVM, lambda h: h["source"] == "cvm" and h.get("registry") != "cia_aberta"),
                     ("bcb", "bcb", SOURCE_BCB, lambda h: h["source"] == "bcb"))
            for label, key, sid, mine in parts:
                if not use[key]:
                    continue
                state = reg["states"][key]
                prefix = "cvm_cia_aberta" if key == "cia" else ("bcb_" if key == "bcb" else "cvm_")
                miss = [m for m in reg["missing"] if m.startswith(prefix) and (key != "pj" or m != CIA_ABERTA_DATASET)]
                errs = [e for e in reg["errors"] if e.startswith(prefix) and (key != "pj" or not e.startswith(CIA_ABERTA_DATASET))]
                hit = any(mine(h) for h in reg_hits)
                if state == "ok":
                    answered.append(label)
                    states[label] = "match" if hit else "no_match"
                    unscreened = miss + [e.split(":", 1)[0] for e in errs]
                    if unscreened:
                        states[label] += f" (not screened: {', '.join(unscreened)})"
                    res.source_status(sid, Status.OK if hit else Status.EMPTY,
                                      reason=f"not screened: {', '.join(unscreened)}" if unscreened else "")
                elif state == "error":
                    states[label] = "error"
                    res.source_status(sid, Status.ERROR, reason="; ".join(errs)[:300])
                else:
                    states[label] = "not_downloaded"
                    res.source_status(sid, Status.UNAVAILABLE, reason_code="dataset",
                                      reason=f"not screened: run v3lum data update ({', '.join(miss)})")

        # FC7: online fallbacks only when the local index is absent or returned nothing
        online = not index_hits
        if online:
            for label, sid, fn in (("gleif", SOURCE_GLEIF, self._gleif),):
                if sid not in allowed:
                    continue
                try:
                    found = fn(ctx, query)
                except _ONLINE_ERRORS as exc:
                    status, code, why = _exc_status(exc)
                    states[label] = f"could not verify ({why})" if status is not Status.SKIPPED else f"skipped ({why})"
                    res.source_status(sid, status, reason_code=code, reason=f"{label}: {why}")
                    if status is not Status.SKIPPED:
                        failures.append(exc)
                    continue
                answered.append(label)
                states[label] = "match" if found else "no_match"
                res.source_status(sid, Status.OK if found else Status.EMPTY)
                hyps.extend(found)

        ranked = rank_hypotheses(hyps)
        decision = auto_chain_decision(ranked)
        listing = hypotheses_listing(ranked)
        resolution = {
            "query": query, "normalized": nn["normalized"], "sources": states, "local_index": local, "online_fallback": online,
            "online_label": ONLINE_LABEL if online else None, "auto_chain": decision, "listing": listing,
            "more": max(0, len(ranked) - MAX_LISTED),
        }
        if not ranked:
            if not answered:
                if failures:
                    raise failures[0]  # rule 5: nothing answered - the online failure decides the status
                res.attr("name_resolution", resolution)
                why = "no source could answer: " + "; ".join(f"{k}: {v}" for k, v in states.items())
                if local["state"] == "not_installed":
                    why += f" - {INDEX_MISSING_TEXT}"
                if any(v == "error" for v in states.values()):
                    return res.mark(Status.ERROR, why, reason_code="error")
                return res.mark(Status.UNAVAILABLE, why, reason_code="dataset")
            res.attr("name_resolution", resolution)
            why = "no CNPJ hypothesis in " + ", ".join(answered)
            unverified = [k for k, v in states.items() if k not in answered and not v.startswith("skipped")]
            if unverified:
                why += "; could not verify: " + ", ".join(unverified)
            if local["state"] == "not_installed":
                why += f"; {INDEX_MISSING_TEXT}"
            return res.mark(Status.EMPTY, why)
        res.attr("name_resolution", resolution)
        res.attr("cnpj_hypotheses", ranked[:MAX_HYPOTHESES])
        notes = [INDEX_MISSING_TEXT] if local.get("state") == "not_installed" else []
        if online:
            notes.append(f"GLEIF fallback: {ONLINE_LABEL}")
        emit_hypotheses(res, query, ranked, decision, listing, notes)
        return res

    # ------------------------------------------------------------------ online sources
    def _gleif(self, ctx: Any, query: str) -> list[dict[str, Any]]:
        if gc is not None:  # FC1: the client shared with P220
            ans = gc.GleifClient(ctx).fetch(gleif_url(query), what="LEI record for the company name")
            if ans.state == "empty":
                return []
            if not ans.ok:
                raise _answer_exception(ans)
            return gleif_hypotheses(records_from_shared(ans.doc), query)["hypotheses"]
        resp = ctx.http.get(gleif_url(query), source=SOURCE_GLEIF, timeout=REQUEST_TIMEOUT, headers={"Accept": "application/vnd.api+json"},
                            cache_if=lambda r: _json_ok(r, gleif_error_in_200))
        ctx.http.check(resp)
        body = _json_body(resp)
        err = gleif_error_in_200(body)
        if err:
            ctx.http.evict(resp)
            raise HttpError(f"{err}: could not verify", resp.status, resp.url)
        return gleif_hypotheses(parse_gleif_records(body), query)["hypotheses"]


def _json_body(resp: Any) -> Any:
    try:
        return json.loads(resp.content)
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
        raise HttpError("malformed or truncated JSON answer: could not verify", getattr(resp, "status", 0) or 0, getattr(resp, "url", "") or "") from exc


def _json_ok(resp: Any, check: Any) -> bool:
    """``cache_if`` veto: only well-formed answers without an error-in-200 body enter the cache."""
    try:
        return check(json.loads(resp.content)) is None
    except (ValueError, TypeError, UnicodeDecodeError, AttributeError):
        return False


# ======================================================================================
# shared run helpers (both modules)
# ======================================================================================


def index_path(ctx: Any) -> Path:
    """The local RFB name index (setting ``cnpj_name_resolver_index_path``, else the default location)."""
    configured = str(ctx.setting("cnpj_name_resolver_index_path", "") or "").strip()
    return Path(configured).expanduser() if configured else default_index_path()


def from_cnpj_record(ctx: Any) -> bool:
    """FC6: a name that came from a CNPJ record (its parent entity is a CNPJ) is never resolved."""
    prov = getattr(ctx, "provenance", ()) or ()
    parent = prov[-1] if prov else ()
    key = str(parent[0]) if isinstance(parent, (tuple, list)) and parent else ""
    relation = str(parent[1]) if isinstance(parent, (tuple, list)) and len(parent) > 1 else ""
    return key.startswith("cnpj:") or relation in ("legal_name", "partner_of")


def _precheck(module: Module, entity: Entity, ctx: Any, res: ModuleResult) -> ModuleResult | None:
    """FC4/FC6 refusals shared by both modules (None = go ahead)."""
    if from_cnpj_record(ctx):
        return res.mark(Status.SKIPPED, "the resolver never runs on a name taken from a CNPJ record (P361 FC6)", reason_code="not_applicable")
    include = set(getattr(getattr(ctx, "options", None), "include", None) or ())
    if entity.type is T.KEYWORD and not include & {module.name, CnpjNameResolver.name}:
        return res.mark(Status.SKIPPED, f"keywords are resolved to CNPJs only on explicit request (-M {module.name})", reason_code="not_default")
    if len(normalize_company_name(entity.value)["core"].replace(" ", "")) < 3:
        return res.mark(Status.SKIPPED, "name too short to resolve after removing legal forms", reason_code="not_applicable")
    return None


def emit_hypotheses(res: ModuleResult, query: str, ranked: list[dict[str, Any]], decision: Mapping[str, Any], listing: list[str],
                    notes: list[str]) -> None:
    """FC5/FC6/FC8: one INFO finding with the listing, at most 5 CNPJ pivots (expand=False unless
    auto-chained) and the BCB-verified / Wikidata websites of those hypotheses as expand=False domains."""
    top = ranked[:MAX_LISTED]
    auto_cnpj = decision.get("cnpj") if decision.get("auto") else None
    sources = sorted({h["source"] for h in top}, key=lambda s: _SOURCE_RANK.get(s, 9))
    tail = list(notes) + ["auto-chained: " + str(decision.get("reason")) if auto_cnpj else "not chained: " + str(decision.get("reason"))]
    res.finding(
        "Possible CNPJ for company name",
        "info",
        f"{len(ranked)} hypothesis(es) for '{query}' ({', '.join(sources)}):\n" + "\n".join(listing) + "\n" + "; ".join(tail),
        confidence="probable" if auto_cnpj else "possible",
        criterion="normalised company-name match (exact razao social / nome fantasia, all tokens, or similarity >= 0.75): "
                  "a hypothesis, never a confirmed link - confirm the CNPJ before chaining",
        data={"hypotheses": top, "auto_chain": dict(decision), "more": max(0, len(ranked) - MAX_LISTED)},
        tags=["name_only_match", "context_only"],
        source=_finding_source(top[0]),
    )
    domains = 0
    wiki_domains = 0
    for h in top:
        cnpj = h.get("cnpj")
        if not cnpj:
            continue
        auto = cnpj == auto_cnpj
        evidence = (f"{h.get('match_kind')} match (similarity {float(h.get('similarity') or 0):.2f}) on '{h.get('name')}' from {h.get('source')}"
                    f"{' - ' + h['label'] if h.get('label') else ''}")
        if auto:
            note = f"{evidence}: exact unique razao social of an active head office - investigated automatically (P361 FC6)"
        else:
            note = f"hypothesis: {evidence}; confirm before chaining ({h.get('followup')})"
        res.pivot(T.CNPJ, cnpj, "possible_cnpj", confidence="probable" if auto or h.get("match_kind") == "exact_razao" else "possible",
                  expand=auto, note=note[:400])
        for d in h.get("verified_domains") or ():
            if domains < MAX_DOMAIN_PIVOTS and res.pivot(
                    T.DOMAIN, d, "bcb_verified_domain", confidence="possible", expand=False,
                    note=f"BCB-verified domain of the institution behind hypothesis {format_cnpj(cnpj)} (expand after confirming the CNPJ)") is not None:
                domains += 1
        for w in h.get("websites") or ():
            host = re.sub(r"^https?://", "", w).split("/", 1)[0].split(":", 1)[0].lower()
            if wiki_domains < MAX_DOMAIN_PIVOTS and res.pivot(
                    T.DOMAIN, host, "wikidata_website", confidence="possible", expand=False,
                    note=f"official website per Wikidata (community-edited) for hypothesis {format_cnpj(cnpj)}") is not None:
                wiki_domains += 1


# ======================================================================================
# the Wikidata P6204 fallback (separate module: the Wikimedia UA policy needs contact_email)
# ======================================================================================


@register
class CnpjNameResolverWikidata(Module):
    """FC7 online fallback over Wikidata items with a CNPJ (P6204). A separate module because the
    Wikimedia User-Agent policy requires an identifying contact (setting ``contact_email``): without it
    the policy gate skips this module (``config``) while ``cnpj_name_resolver`` keeps running."""

    name = "cnpj_name_resolver_wikidata"
    title = "Company name -> CNPJ via Wikidata P6204"
    description = (
        "Online fallback of cnpj_name_resolver: Wikidata items carrying a CNPJ (P6204) whose label or alias matches a company "
        "name (large companies only); runs only when the local RFB name index is absent or returns nothing."
    )
    category = "brazil_public_data"
    accepts = {T.ORG, T.KEYWORD}
    produces = {T.CNPJ, T.DOMAIN}
    tags = {"brazil", "free"}
    reference = "https://www.wikidata.org/wiki/Property:P6204"
    notice = (
        "Wikimedia User-Agent policy: needs setting contact_email (a role mailbox, never a personal one); without it the source is "
        "skipped (config). About 2,900 items carry a CNPJ: hypotheses only, never auto-chained; websites are community-edited."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # Wikidata receives the company name
    hosts = ("www.wikidata.org",)
    provider = "wikidata"
    sources = (SOURCE_WIKIDATA,)
    access_model = "free_noauth_limited"
    max_requests = 2  # list=search + wbgetentities
    expected_latency = 2.0
    timeout = 45.0
    min_interval = 1.0
    cache_ttl = 86400
    daily_quota = 300
    max_pivots = MAX_LISTED + MAX_DOMAIN_PIVOTS
    default_enabled = True
    error_markers = (
        {"id": "cnpj_name_resolver_wikidata_mediawiki_error", "statuses": [200], "json_path": None, "equals": None,
         "regex": r"\A\s*\{\s*\"error\"\s*:\s*\{", "final_url_regex": None, "maps_to": "error", "reason_code": "error",
         "reason": "Wikidata: MediaWiki API error body in an HTTP 200 answer (could not verify)"},
    )

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        refused = _precheck(self, entity, ctx, res)
        if refused is not None:
            return refused
        query = " ".join(str(entity.value or "").split())
        path = index_path(ctx)
        if path.is_file():
            try:
                with NameIndex(path) as idx:
                    answered = bool(query_index(idx, query, input_type=entity.type.value))
            except NameIndexError:
                answered = False  # an unreadable index counts as absent for the fallback (cnpj_name_resolver reports it)
            if answered:
                return res.mark(Status.SKIPPED, "the local RFB name index answered: online fallbacks run only when it is absent or "
                                                "returns nothing (P361 FC7)", reason_code="not_applicable")
        found = _wikidata(ctx, query)
        ranked = rank_hypotheses(found)
        resolution = {"query": query, "normalized": normalize_company_name(query)["normalized"],
                      "sources": {"wikidata": "match" if ranked else "no_match"}, "online_fallback": True, "online_label": ONLINE_LABEL,
                      "auto_chain": auto_chain_decision(ranked), "listing": hypotheses_listing(ranked), "more": max(0, len(ranked) - MAX_LISTED)}
        res.attr("name_resolution", resolution)
        if not ranked:
            return res.mark(Status.EMPTY, f"no Wikidata item carrying a CNPJ (P6204) matches '{query}' ({ONLINE_LABEL})")
        res.attr("cnpj_hypotheses", ranked[:MAX_HYPOTHESES])
        emit_hypotheses(res, query, ranked, resolution["auto_chain"], resolution["listing"], [f"Wikidata fallback: {ONLINE_LABEL}"])
        return res


def _wikidata(ctx: Any, query: str) -> list[dict[str, Any]]:
    resp = ctx.http.get(wikidata_search_url(query), source=SOURCE_WIKIDATA, timeout=REQUEST_TIMEOUT,
                        cache_if=lambda r: _json_ok(r, wikidata_error_in_200))
    ctx.http.check(resp)
    body = _json_body(resp)
    err = wikidata_error_in_200(body)
    if err:
        ctx.http.evict(resp)
        raise HttpError(f"{err}: could not verify", resp.status, resp.url)
    qids = parse_wikidata_search(body)["qids"]
    if not qids:
        return []
    resp = ctx.http.get(wikidata_entities_url(qids), source=SOURCE_WIKIDATA, timeout=REQUEST_TIMEOUT,
                        cache_if=lambda r: _json_ok(r, wikidata_error_in_200))
    ctx.http.check(resp)
    body = _json_body(resp)
    err = wikidata_error_in_200(body) or (None if isinstance(body.get("entities"), dict) else "Wikidata answer without 'entities'")
    if err:
        ctx.http.evict(resp)
        raise HttpError(f"{err}: could not verify", resp.status, resp.url)
    return wikidata_hypotheses(parse_wbgetentities(body), query)
