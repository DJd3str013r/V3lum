"""Opt-in PGFN divida ativa importer for ``br_cnpj_risk_lists`` (P244 cond 1-3; batch p3-G10-2).

No Module class lives here. The PGFN open data (https://dadosabertos.pgfn.gov.br/) is a set of quarterly zips
(``Dados_abertos_Sistema_SIDA.zip`` ~1.4 GB, ``Dados_abertos_Previdenciario.zip``, ``Dados_abertos_FGTS.zip``;
';' ISO-8859-1 CSV members ``arquivo_lai_{SIDA,PREV,FGTS}_{seq}_{YYYYMM}.csv``). P244 final conditions:

1. **Separate, opt-in import** - never part of ``v3lum data update`` (the PGFN files are not registered datasets),
   never during a scan: ``python -m v3lum.modules.brazil_public_data.pgfn_import`` (the core command
   ``v3lum data update pgfn`` is a core request). :func:`plan` shows the quarter, the files and their sizes
   (Range 0-0 requests read the Content-Range totals) and the free disk space required (3x the download).
2. **Streamed, never in memory** - :func:`PgfnSite.download` fetches each zip with resumable HTTP Range requests
   (``If-Range`` ETag, ``.part`` file + sidecar); :func:`iter_pgfn_zip` streams every member row by row
   (``zipfile`` + ``TextIOWrapper``) into an on-disk SQLite index keyed by CNPJ root (:func:`build_index`, batched
   inserts, built into a temporary file and installed atomically). Schema drift raises :class:`FormatChanged` and
   the previous index stays. The zips are deleted after the import. The CAPTCHA-protected
   listadevedores.pgfn.gov.br application is never used (team rule 1).
3. **Structural minimisation** - natural-person debtors (``TIPO_PESSOA`` fisica or a CPF-shaped document) are
   dropped while importing unless ``--include-persons`` is passed together with ``--purpose``; both are recorded in
   the index meta. With them, persons go to a separate ``persons`` table keyed by the normalised NAME only (masked
   CPF kept as published, never a lookup key, never pivoted).

Storage: ``~/.v3lum/datasets/br_cnpj_risk_lists/pgfn.sqlite`` (0600, directory 0700); never exported.
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import os
import re
import shutil
import sqlite3
import sys
import unicodedata
import zipfile
from collections.abc import Callable, Iterable, Iterator
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from v3lum import paths

BASE_URL = "https://dadosabertos.pgfn.gov.br/"
HOST = "dadosabertos.pgfn.gov.br"
SOURCE = "pgfn.divida_ativa"
PROVIDER = "pgfn"
MODULE = "br_cnpj_risk_lists"
INDEX_SCHEMA = "v3lum.pgfn_index/1"
INDEX_DIR = "br_cnpj_risk_lists"
INDEX_FILE = "pgfn.sqlite"
STATE_FILE = "pgfn_import_state.json"
DOWNLOADS = "pgfn_downloads"
IMPORT_HINT = "run python -m v3lum.modules.brazil_public_data.pgfn_import (opt-in; to be wired as `v3lum data update pgfn`)"
SPACE_FACTOR = 3
DEFAULT_CHUNK = 16 * 1024 * 1024
REQUEST_TIMEOUT = 120.0
BATCH = 5000
#: one quarter in the PGFN pages; the newest is chosen unless --quarter names another
QUARTER_RE = re.compile(r"^\d{4}_trimestre_0[1-4]$")
ZIP_RE = re.compile(r"^Dados_abertos_[A-Za-z_]+\.zip$")
KINDS = {"SIDA": "demais (nao previdenciaria)", "PREV": "previdenciaria", "FGTS": "FGTS"}
REQUIRED = ("CPF_CNPJ", "TIPO_PESSOA", "NOME_DEVEDOR", "SITUACAO_INSCRICAO", "VALOR_CONSOLIDADO")
_MEMBER = re.compile(r"^arquivo_lai_(SIDA|PREV|FGTS)_(-?\d+)_(\d{4})(\d{2})\.csv$", re.I)
_MASKED_CPF = re.compile(r"^(?:X{3}\d{3}\.\d{3}X{2}|\d{3}X{6}\d{2}|\*{3}\.\d{3}\.\d{3}-\*{2})$", re.I)
_WS = re.compile(r"\s+")
AMOUNT_BANDS = ((10_000, "< R$ 10 mil"), (100_000, "R$ 10 mil - 100 mil"), (1_000_000, "R$ 100 mil - 1 mi"),
                (10_000_000, "R$ 1 mi - 10 mi"), (100_000_000, "R$ 10 mi - 100 mi"))


class ImportError_(Exception):
    """A failed import; ``state`` goes into the state file the module reads."""

    state = "error"

    def __init__(self, message: str, *, hint: str = "") -> None:
        super().__init__(message)
        self.hint = hint


class FormatChanged(ImportError_):
    state = "format_changed"


class ImportUnavailable(ImportError_):
    state = "unavailable"


# ======================================================================================
# pure helpers
# ======================================================================================


def clean(value: Any) -> str:
    return "" if value is None else _WS.sub(" ", str(value)).strip()


def fold(value: Any) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", clean(value)) if not unicodedata.combining(c))


def name_key(name: Any) -> str:
    """Exact-match key of a debtor name: the shared matcher's normalised form (legal forms removed)."""
    from v3lum.modules.company_org import namematch

    return namematch.normalized_name(clean(name))


def person_key(name: Any) -> str:
    from v3lum.modules.company_org import namematch

    return namematch.normalized_name(clean(name), "person")


def cnpj_normalize(value: Any) -> str | None:
    s = re.sub(r"[\s./-]", "", clean(value)).upper()
    return s if re.fullmatch(r"[0-9A-Z]{12}[0-9]{2}", s) and not s.isalpha() else None


def looks_like_cpf(value: Any) -> bool:
    digits = re.sub(r"[\s.-]", "", clean(value))
    return bool(re.fullmatch(r"\d{11}", digits))


def is_masked_cpf(value: Any) -> bool:
    return bool(_MASKED_CPF.match(clean(value)))


def mask_cpf(value: Any) -> str | None:
    digits = re.sub(r"\D", "", clean(value))
    return f"***.{digits[3:6]}.{digits[6:9]}-**" if len(digits) == 11 else None


def parse_br_date(value: Any) -> str | None:
    """ISO date from dd/mm/yyyy (or yyyy-mm-dd); None for the 01/01/1000 sentinel and junk."""
    s = clean(value)
    m = re.fullmatch(r"(\d{2})/(\d{2})/(\d{4})", s)
    if m:
        d, mo, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
    else:
        m = re.match(r"(\d{4})-(\d{2})-(\d{2})", s)
        if not m:
            return None
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if y < 1900:
        return None
    try:
        return date(y, mo, d).isoformat()
    except ValueError:
        return None


def parse_amount(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = clean(value).replace("R$", "").strip()
    if not s:
        return None
    if re.fullmatch(r"-?\d{1,3}(\.\d{3})+(,\d+)?|-?\d+,\d+", s):
        s = s.replace(".", "").replace(",", ".")
    try:
        return float(s)
    except ValueError:
        return None


def amount_band(value: Any) -> str | None:
    """Amount band label (P244 cond 4-5: findings carry a band, never the exact debt)."""
    v = parse_amount(value)
    if v is None:
        return None
    for limit, label in AMOUNT_BANDS:
        if v < limit:
            return label
    return ">= R$ 100 mi"


def member_info(name: Any) -> dict[str, Any] | None:
    """'arquivo_lai_SIDA_1_202609.csv' -> {kind, nature, seq, ref_month '2026-09'}; None for other names."""
    m = _MEMBER.match(str(name or "").rsplit("/", 1)[-1])
    if not m:
        return None
    kind = m.group(1).upper()
    return {"kind": kind, "nature": KINDS[kind], "seq": int(m.group(2)), "ref_month": f"{m.group(3)}-{m.group(4)}"}


def parse_directory(body: Any) -> dict[str, Any]:
    """PGFN Apache index -> {quarters (sorted), zips, latest}. File names are discovered, never hard-coded (the
    non-previdenciario file is Dados_abertos_Sistema_SIDA.zip since 2026, no longer Nao_Previdenciario)."""
    text = body.decode("latin-1") if isinstance(body, (bytes, bytearray)) else str(body or "")
    hrefs = re.findall(r'href="([^"?#]+)"', text, re.I)
    quarters = sorted({h.strip("/") for h in hrefs if QUARTER_RE.fullmatch(h.strip("/"))})
    zips = sorted({h.rsplit("/", 1)[-1] for h in hrefs if ZIP_RE.fullmatch(h.rsplit("/", 1)[-1])})
    return {"quarters": quarters, "zips": zips, "latest": quarters[-1] if quarters else None}


def pgfn_row(rec: dict[str, Any], nature: str, *, include_persons: bool = False) -> dict[str, Any] | None:
    """One CSV row -> a company row, a person row (only with include_persons) or None (cond 3)."""
    def g(k: str) -> str:
        return clean(rec.get(k))

    tipo = fold(g("TIPO_PESSOA")).casefold()
    doc = g("CPF_CNPJ")
    cnpj = cnpj_normalize(doc)
    if "fisica" in tipo or (not cnpj and (is_masked_cpf(doc) or looks_like_cpf(doc))):
        if not include_persons:
            return None
        return {"kind": "person", "name": g("NOME_DEVEDOR") or None, "cpf_masked": doc if is_masked_cpf(doc) else mask_cpf(doc),
                "nature": nature, "situation": g("SITUACAO_INSCRICAO") or None, "amount_band": amount_band(g("VALOR_CONSOLIDADO"))}
    if not cnpj:
        return None
    return {
        "kind": "company", "cnpj": cnpj, "cnpj_root": cnpj[:8], "name": g("NOME_DEVEDOR") or None,
        "debtor_role": fold(g("TIPO_DEVEDOR")).casefold() or None, "uf": g("UF_DEVEDOR") or None,
        "inscription": g("NUMERO_INSCRICAO") or None, "situation_type": g("TIPO_SITUACAO_INSCRICAO") or None,
        "situation": g("SITUACAO_INSCRICAO") or None, "nature": nature, "revenue": g("RECEITA_PRINCIPAL") or g("TIPO_CREDITO") or None,
        "inscription_date": parse_br_date(g("DATA_INSCRICAO")), "judicial": g("INDICADOR_AJUIZADO").upper() == "SIM",
        "amount": parse_amount(g("VALOR_CONSOLIDADO")),
    }


def zip_problem(path: Path | bytes) -> str:
    """Why a downloaded file is not a complete PGFN zip ('' = fine): HTML, truncated, empty, unsafe names."""
    try:
        if isinstance(path, (bytes, bytearray)):
            head = bytes(path[:4096])
        else:
            with Path(path).open("rb") as fh:
                head = fh.read(4096)
    except OSError as exc:
        return f"unreadable ({exc})"
    if re.match(rb"\s*(<!doctype\s+html|<html|<head|<body)", head, re.I):
        return "an HTML page came back instead of the zip"
    if not head.startswith(b"PK\x03\x04"):
        return "not a zip"
    try:
        with zipfile.ZipFile(io.BytesIO(path) if isinstance(path, (bytes, bytearray)) else path) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return "truncated or corrupt zip (partial download?)"
    if not names:
        return "empty zip"
    for n in names:
        if n.startswith("/") or ".." in n.split("/") or "\\" in n or "\x00" in n:
            return "unsafe member name"
    return ""


def iter_pgfn_zip(source: Path | bytes, *, include_persons: bool = False, stats: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
    """Stream rows out of a PGFN zip, member by member, never loading a member in memory (cond 2).

    Yields normalised company rows (and person rows with ``include_persons``). ``stats`` receives members,
    rows_read, dropped_persons, skipped_members. Raises FormatChanged on schema drift (the import aborts and the
    previous index stays)."""
    st = stats if isinstance(stats, dict) else {}
    for k in ("members", "rows_read", "dropped_persons", "skipped_members"):
        st.setdefault(k, 0)
    problem = zip_problem(source)
    if problem:
        raise FormatChanged(f"PGFN zip: {problem}")
    src = io.BytesIO(source) if isinstance(source, (bytes, bytearray)) else source
    with zipfile.ZipFile(src) as zf:
        for info in zf.infolist():
            meta = member_info(info.filename)
            if meta is None or info.is_dir():
                st["skipped_members"] += 1
                continue
            st["members"] += 1
            with zf.open(info) as fh:
                text = io.TextIOWrapper(fh, encoding="latin-1", newline="")
                reader = csv.DictReader(text, delimiter=";")
                missing = [c for c in REQUIRED if c not in (reader.fieldnames or [])]
                if missing:
                    raise FormatChanged(f"schema drift: {info.filename} lacks {', '.join(missing)}")
                try:
                    for rec in reader:
                        st["rows_read"] += 1
                        row = pgfn_row(rec, meta["nature"], include_persons=include_persons)
                        if row is None:
                            st["dropped_persons"] += 1
                            continue
                        row["ref_month"] = meta["ref_month"]
                        yield row
                except (csv.Error, zipfile.BadZipFile, EOFError, OSError) as exc:
                    raise FormatChanged(f"{info.filename}: unreadable member ({type(exc).__name__}: {exc})") from None


# ======================================================================================
# the on-disk index (cond 2)
# ======================================================================================

_SCHEMA = """
CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE debts (cnpj_root TEXT NOT NULL, cnpj TEXT NOT NULL, name_key TEXT, name TEXT, nature TEXT, debtor_role TEXT,
  situation TEXT, situation_type TEXT, revenue TEXT, inscription TEXT, inscription_date TEXT, judicial INTEGER, amount REAL,
  uf TEXT, ref_month TEXT);
CREATE TABLE persons (name_key TEXT NOT NULL, name TEXT, cpf_masked TEXT, nature TEXT, situation TEXT, amount_band TEXT, ref_month TEXT);
"""
_INDEXES = """
CREATE INDEX debts_root ON debts(cnpj_root);
CREATE INDEX debts_name ON debts(name_key);
CREATE INDEX persons_name ON persons(name_key);
"""
DEBT_FIELDS = ("cnpj_root", "cnpj", "name_key", "name", "nature", "debtor_role", "situation", "situation_type", "revenue", "inscription",
               "inscription_date", "judicial", "amount", "uf", "ref_month")
PERSON_FIELDS = ("name_key", "name", "cpf_masked", "nature", "situation", "amount_band", "ref_month")


def dataset_dir(home: Path | None = None) -> Path:
    base = Path(home) if home is not None else paths.datasets_dir()
    return paths.private_dir(base / INDEX_DIR)


def index_path(home: Path | None = None) -> Path:
    base = Path(home) if home is not None else paths.datasets_dir()
    return base / INDEX_DIR / INDEX_FILE


def build_index(zips: Iterable[Path | bytes], out_path: Path, *, quarter: str, include_persons: bool = False, purpose: str = "",
                now: datetime | None = None, progress: Callable[[dict[str, Any]], None] | None = None) -> dict[str, Any]:
    """Stream the zips into a new SQLite index and install it atomically at ``out_path`` (cond 2).

    Persons go to the ``persons`` table only with ``include_persons`` and a recorded ``purpose`` (cond 3).
    Returns ``{rows, persons, dropped_persons, members, ref_months}``. On FormatChanged / sqlite errors the
    temporary file is removed and the previous index stays."""
    if include_persons and not clean(purpose):
        raise ImportError_("--include-persons needs a recorded --purpose (P244 cond 3)")
    out_path = Path(out_path)
    paths.private_dir(out_path.parent)
    tmp = out_path.with_name(out_path.name + ".building")
    tmp.unlink(missing_ok=True)
    stats: dict[str, Any] = {}
    rows = persons = 0
    months: set[str] = set()
    conn = sqlite3.connect(tmp)
    try:
        conn.executescript(_SCHEMA)
        debt_sql = f"INSERT INTO debts ({','.join(DEBT_FIELDS)}) VALUES ({','.join('?' * len(DEBT_FIELDS))})"
        person_sql = f"INSERT INTO persons ({','.join(PERSON_FIELDS)}) VALUES ({','.join('?' * len(PERSON_FIELDS))})"
        debts: list[tuple[Any, ...]] = []
        people: list[tuple[Any, ...]] = []
        for source in zips:
            for row in iter_pgfn_zip(source, include_persons=include_persons, stats=stats):
                months.add(row.get("ref_month") or "")
                if row["kind"] == "company":
                    row["name_key"] = name_key(row.get("name"))
                    debts.append(tuple(int(row["judicial"]) if f == "judicial" else row.get(f) for f in DEBT_FIELDS))
                else:
                    row["name_key"] = person_key(row.get("name"))
                    if row["name_key"]:
                        people.append(tuple(row.get(f) for f in PERSON_FIELDS))
                if len(debts) >= BATCH:
                    conn.executemany(debt_sql, debts)
                    rows += len(debts)
                    debts.clear()
                    if progress:
                        progress({"event": "loaded", "rows": rows})
                if len(people) >= BATCH:
                    conn.executemany(person_sql, people)
                    persons += len(people)
                    people.clear()
        if debts:
            conn.executemany(debt_sql, debts)
            rows += len(debts)
        if people:
            conn.executemany(person_sql, people)
            persons += len(people)
        conn.executescript(_INDEXES)
        when = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
        meta = {"schema": INDEX_SCHEMA, "quarter": quarter, "imported_at": when, "rows": str(rows), "persons": str(persons),
                "dropped_persons": str(stats.get("dropped_persons", 0)), "include_persons": "1" if include_persons else "0",
                "purpose": clean(purpose)[:300] if include_persons else "", "ref_months": ",".join(sorted(m for m in months if m))}
        conn.executemany("INSERT INTO meta (k, v) VALUES (?, ?)", list(meta.items()))
        conn.commit()
    except BaseException:
        conn.close()
        tmp.unlink(missing_ok=True)
        raise
    conn.close()
    os.replace(tmp, out_path)
    paths.restrict_file(out_path)
    return {"rows": rows, "persons": persons, "dropped_persons": stats.get("dropped_persons", 0), "members": stats.get("members", 0),
            "ref_months": sorted(m for m in months if m)}


class PgfnIndex:
    """Read-only view of the installed ``pgfn.sqlite`` (cond 4: exact CNPJ, or the root - stated)."""

    def __init__(self, path: Path) -> None:
        self.conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
        self.meta = dict(self.conn.execute("SELECT k, v FROM meta").fetchall())

    def close(self) -> None:
        self.conn.close()

    @property
    def include_persons(self) -> bool:
        return self.meta.get("include_persons") == "1"

    def _rows(self, sql: str, args: tuple[Any, ...], limit: int) -> list[dict[str, Any]]:
        cur = self.conn.execute(f"SELECT {','.join(DEBT_FIELDS)} FROM debts WHERE {sql} LIMIT ?", (*args, limit))
        out = []
        for row in cur.fetchall():
            d = dict(zip(DEBT_FIELDS, row, strict=True))
            d["judicial"] = bool(d["judicial"])
            d["amount_band"] = amount_band(d["amount"])
            out.append(d)
        return out

    def by_cnpj(self, cnpj: str, limit: int = 500) -> list[dict[str, Any]]:
        rows = self._rows("cnpj_root = ?", (cnpj[:8],), limit)
        for r in rows:
            r["match"] = "exact" if r["cnpj"] == cnpj else "root"
        return rows

    def by_name(self, name: Any, limit: int = 500) -> list[dict[str, Any]]:
        key = name_key(name)
        if not key:
            return []
        rows = self._rows("name_key = ?", (key,), limit)
        for r in rows:
            r["match"] = "name_exact"
        return rows

    def persons_by_name(self, name: Any, limit: int = 50) -> list[dict[str, Any]]:
        if not self.include_persons:
            return []
        key = person_key(name)
        if not key:
            return []
        cur = self.conn.execute(f"SELECT {','.join(PERSON_FIELDS)} FROM persons WHERE name_key = ? LIMIT ?", (key, limit))
        return [dict(zip(PERSON_FIELDS, r, strict=True)) for r in cur.fetchall()]


def open_index(home: Path | None = None) -> tuple[PgfnIndex | None, str]:
    """The installed index (never downloads) or (None, 'missing' | 'unreadable' | 'format')."""
    path = index_path(home)
    if not path.is_file():
        return None, "missing"
    try:
        idx = PgfnIndex(path)
    except sqlite3.Error:
        return None, "unreadable"
    if idx.meta.get("schema") != INDEX_SCHEMA:
        idx.close()
        return None, "format"
    return idx, ""


def summary(matches: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per debt nature (cond 5): count, total amount band, situations, judicial flag, latest inscription date and
    whether the exact establishment (or only the root) matched. Never the exact debt of an inscription."""
    by: dict[str, dict[str, Any]] = {}
    for m in matches:
        nature = m.get("nature") or "?"
        b = by.setdefault(nature, {"nature": nature, "count": 0, "total": 0.0, "situations": [], "judicial": False, "latest": None,
                                   "matches": set(), "ref_month": m.get("ref_month")})
        b["count"] += 1
        b["total"] += m.get("amount") or 0.0
        if m.get("situation") and m["situation"] not in b["situations"]:
            b["situations"].append(m["situation"])
        b["judicial"] = b["judicial"] or bool(m.get("judicial"))
        d = m.get("inscription_date")
        if d and (b["latest"] is None or d > b["latest"]):
            b["latest"] = d
        b["matches"].add(m.get("match") or "exact")
    out = []
    for b in sorted(by.values(), key=lambda x: x["nature"]):
        matches_set = b.pop("matches")
        b["total_band"] = amount_band(b.pop("total"))
        b["match"] = next((k for k in ("exact", "name_exact", "root") if k in matches_set), "root")
        b["situations"] = b["situations"][:5]
        out.append(b)
    return out


# ======================================================================================
# state (the module reads it: a failed import never reads as 'no debt')
# ======================================================================================


def read_state(home: Path | None = None) -> dict[str, Any]:
    path = (Path(home) if home is not None else paths.datasets_dir()) / INDEX_DIR / STATE_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_state(directory: Path, state: dict[str, Any]) -> None:
    paths.secure_write_text(directory / STATE_FILE, json.dumps(state, ensure_ascii=False, indent=1))


def _finish(directory: Path, result: dict[str, Any]) -> dict[str, Any]:
    state = read_state(directory.parent)
    state["last_import"] = {k: v for k, v in result.items() if k in ("status", "reason", "hint", "quarter", "at", "include_persons")}
    if result.get("status") == "imported":
        state["imported"] = state["last_import"]
    _write_state(directory, state)
    return result


# ======================================================================================
# downloads (outside any scan)
# ======================================================================================


def scoped_http(runtime: Any) -> Any:
    """A passive HTTP scope over the runtime client, limited to the PGFN open-data host (never during a scan)."""
    from v3lum.core.http import ScopedHttp

    return ScopedHttp(  # v3lum-lint: allow LINT-01 -- out-of-band PGFN bulk importer (opt-in, never during a scan), restricted to the PGFN open-data host
        runtime.http, module=MODULE, provider=PROVIDER, sources=(SOURCE,), allowed_hosts=(HOST,), disclosure="third_party",
        opsec="passive", max_requests=None, cancel_event=getattr(runtime, "cancel_event", None), clock=getattr(runtime, "clock", None),
    )


def _problem(resp: Any, what: str) -> None:
    status = int(resp.status)
    if getattr(resp, "classification", None) is not None or status in (401, 403, 407, 451):
        raise ImportUnavailable(f"{what}: blocked or refused (HTTP {status}): could not download; never 'no debt'")
    if status == 429:
        raise ImportUnavailable(f"{what}: rate limited (HTTP 429): try again later")
    if status >= 400:
        raise ImportError_(f"{what}: HTTP {status}")


class PgfnSite:
    """The PGFN open-data host through a passive scope (``http``: a ScopedHttp limited to HOST)."""

    def __init__(self, http: Any, *, chunk: int = DEFAULT_CHUNK) -> None:
        self.http = http
        self.chunk = max(64 * 1024, int(chunk))

    def _get(self, url: str, what: str, **kw: Any) -> Any:
        resp = self.http.request("GET", url, ttl=0, allow_redirects=False, timeout=REQUEST_TIMEOUT, source=SOURCE, **kw)
        _problem(resp, what)
        return resp

    def quarters(self) -> dict[str, Any]:
        resp = self._get(BASE_URL, "PGFN index")
        listing = parse_directory(resp.content)
        if not listing["quarters"]:
            raise FormatChanged("the PGFN index lists no YYYY_trimestre_0Q folder: layout change (never 'no debt')")
        return listing

    def quarter_files(self, quarter: str) -> list[str]:
        if not QUARTER_RE.fullmatch(quarter):
            raise ValueError(f"not a PGFN quarter folder: {quarter!r}")
        resp = self._get(f"{BASE_URL}{quarter}/", f"quarter {quarter}")
        zips = parse_directory(resp.content)["zips"]
        if not zips:
            raise FormatChanged(f"quarter {quarter} lists no Dados_abertos_*.zip: layout change (never 'no debt')")
        return zips

    def size(self, quarter: str, name: str) -> dict[str, Any]:
        """Size and ETag of one zip from a Range 0-0 request (the listing shows no size)."""
        resp = self._get(f"{BASE_URL}{quarter}/{name}", name, headers={"Range": "bytes=0-0"}, max_bytes=1024)
        m = re.match(r"bytes \d+-\d+/(\d+)", str((resp.headers or {}).get("content-range") or ""))
        total = int(m.group(1)) if m else int((resp.headers or {}).get("content-length") or 0) if int(resp.status) == 200 else 0
        if not total:
            raise FormatChanged(f"{name}: no size in the answer (Content-Range missing)")
        return {"name": name, "bytes": total, "etag": str((resp.headers or {}).get("etag") or "").strip('"'),
                "last_modified": str((resp.headers or {}).get("last-modified") or "")}

    def download(self, quarter: str, entry: dict[str, Any], dest: Path, progress: Callable[[dict[str, Any]], None] | None = None) -> Path:
        """Resumable Range download of one zip into ``dest`` (``.part`` + sidecar ETag; size checked)."""
        name, size, etag = entry["name"], int(entry["bytes"]), entry.get("etag") or ""
        final = dest / name
        if final.exists() and final.stat().st_size == size and _sidecar(final).get("etag") == etag:
            return final
        part = dest / f"{name}.part"
        side = _sidecar(part)
        have = part.stat().st_size if part.exists() and side.get("etag") == etag and side.get("size") == size else 0
        if have == 0:
            fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.close(fd)
            _write_sidecar(part, {"etag": etag, "size": size})
        url = f"{BASE_URL}{quarter}/{name}"
        while have < size:
            end = min(have + self.chunk, size) - 1
            headers = {"Range": f"bytes={have}-{end}"}
            if etag:
                headers["If-Range"] = f'"{etag}"'
            resp = self._get(url, name, headers=headers, max_bytes=self.chunk + 1)
            status = int(resp.status)
            body = bytes(resp.content or b"")
            if status == 206:
                m = re.match(r"bytes (\d+)-(\d+)/(\d+|\*)", str((resp.headers or {}).get("content-range") or ""))
                if not m or int(m.group(1)) != have or len(body) != int(m.group(2)) - int(m.group(1)) + 1:
                    raise ImportError_(f"{name}: unexpected Content-Range in a resumed download")
            elif status == 200:
                if have != 0 or len(body) != size or getattr(resp, "truncated", False):
                    part.unlink(missing_ok=True)
                    raise ImportError_(f"{name}: the server ignored the Range request (or the file changed): run the import again")
            else:
                raise ImportError_(f"{name}: HTTP {status}")
            with open(part, "ab") as fh:
                fh.write(body)
            have += len(body)
            if progress:
                progress({"event": "download", "file": name, "done": have, "total": size})
        if part.stat().st_size != size:
            part.unlink(missing_ok=True)
            raise ImportError_(f"{name}: size mismatch after the download")
        os.replace(part, final)
        paths.restrict_file(final)
        _write_sidecar(final, {"etag": etag, "size": size})
        _sidecar_path(part).unlink(missing_ok=True)
        return final


def _sidecar_path(path: Path) -> Path:
    return path.with_name(path.name + ".json")


def _sidecar(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(_sidecar_path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_sidecar(path: Path, data: dict[str, Any]) -> None:
    paths.secure_write_text(_sidecar_path(path), json.dumps(data))


def plan(runtime: Any, *, quarter: str | None = None, home: Path | None = None, site: PgfnSite | None = None) -> dict[str, Any]:
    """The download plan of one quarter (cond 1: sizes shown): files, total bytes, the free space required
    (3x the download: zips + index) and whether the import may proceed. Downloads nothing but Range 0-0 heads."""
    site = site or PgfnSite(scoped_http(runtime))
    listing = site.quarters()
    chosen = quarter or listing["latest"]
    if chosen not in listing["quarters"]:
        raise ImportUnavailable(f"quarter {chosen} is not listed by PGFN (listed: {', '.join(listing['quarters'][-4:])})")
    files = [site.size(chosen, name) for name in site.quarter_files(chosen)]
    total = sum(f["bytes"] for f in files)
    free = shutil.disk_usage(dataset_dir(home)).free
    need = total * SPACE_FACTOR
    ok = free >= need
    return {"quarter": chosen, "quarters": listing["quarters"], "files": files, "download_bytes": total, "required_free_bytes": need,
            "free_bytes": free, "ok": ok, "refusal": "" if ok else f"not enough free disk space ({_human(free)} free, {_human(need)} needed)"}


def import_pgfn(runtime: Any, *, quarter: str | None = None, include_persons: bool = False, purpose: str = "", home: Path | None = None,
                keep_downloads: bool = False, progress: Callable[[dict[str, Any]], None] | None = None,
                confirm: Callable[[dict[str, Any]], bool] | None = None, now: datetime | None = None,
                site: PgfnSite | None = None) -> dict[str, Any]:
    """The whole opt-in import: plan (sizes + 3x free space), resumable downloads, streamed index build, atomic
    install, deletion of the zips. Returns ``{status: imported | refused | unavailable | format_changed | error,
    reason, hint, ...}`` and records it in the state file the module reads."""
    directory = dataset_dir(home)
    when = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    result: dict[str, Any] = {"status": "error", "reason": "", "hint": "", "quarter": quarter, "at": when,
                              "include_persons": bool(include_persons)}
    try:
        if include_persons and not clean(purpose):
            raise ImportError_("--include-persons needs a recorded --purpose (P244 cond 3)")
        site = site or PgfnSite(scoped_http(runtime), chunk=_chunk(getattr(runtime, "config", None)))
        p = plan(runtime, quarter=quarter, home=home, site=site)
        result.update(quarter=p["quarter"], download_bytes=p["download_bytes"], required_free_bytes=p["required_free_bytes"])
        if progress:
            progress({"event": "plan", **{k: v for k, v in p.items() if k != "files"}, "files": len(p["files"])})
        if not p["ok"]:
            result.update(status="refused", reason=p["refusal"])
            return _finish(directory, result)
        if confirm is not None and not confirm(p):
            result.update(status="refused", reason="not confirmed by the analyst")
            return _finish(directory, result)
        dl = paths.private_dir(directory / DOWNLOADS / p["quarter"])
        files = [site.download(p["quarter"], entry, dl, progress) for entry in p["files"]]
        info = build_index(files, directory / INDEX_FILE, quarter=p["quarter"], include_persons=include_persons, purpose=purpose,
                           now=now, progress=progress)
        if not keep_downloads:
            shutil.rmtree(directory / DOWNLOADS, ignore_errors=True)
        result.update(status="imported", reason=f"PGFN {p['quarter']} imported: {info['rows']} company rows, "
                                                 f"{info['dropped_persons']} person rows dropped" + (" (persons kept: --include-persons)" if include_persons else ""),
                      rows=info["rows"])
    except ImportError_ as exc:
        result.update(status=exc.state, reason=str(exc), hint=exc.hint)
    except (OSError, sqlite3.Error) as exc:
        result.update(status="error", reason=f"{type(exc).__name__}: {str(exc)[:200]}")
    except Exception as exc:  # noqa: BLE001 - HTTP failures (blocked, network) end as a recorded failed import
        result.update(status="unavailable", reason=f"{type(exc).__name__}: {str(exc)[:200]}", hint="re-run the import later")
    return _finish(directory, result)


def _chunk(config: Any) -> int:
    try:
        mb = float((config.get("br_cnpj_risk_lists_pgfn_chunk_mb", 16) if config is not None else 16) or 16)
    except (TypeError, ValueError, AttributeError):
        mb = 16
    return int(max(0.0625, min(mb, 256)) * 1024 * 1024)


def _human(n: Any) -> str:
    try:
        v = float(n)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or unit == "TB":
            return f"{v:.1f} {unit}"
        v /= 1024
    return f"{v:.1f} TB"  # pragma: no cover


def main(argv: list[str] | None = None) -> int:
    import argparse

    from v3lum.app import App
    from v3lum.modules.brazil_public_data import br_cnpj_risk_lists  # noqa: F401 - registers the module settings

    parser = argparse.ArgumentParser(prog="python -m v3lum.modules.brazil_public_data.pgfn_import",
                                     description="Opt-in import of the PGFN divida ativa open data into the local br_cnpj_risk_lists index "
                                                 "(outside any scan; companies only unless --include-persons --purpose).")
    parser.add_argument("--plan", action="store_true", help="show the quarter, the files, their sizes and the free space needed")
    parser.add_argument("--quarter", default=None, help="YYYY_trimestre_0Q (default: the newest)")
    parser.add_argument("--include-persons", action="store_true", help="keep natural-person debtors (name-only due diligence; needs --purpose)")
    parser.add_argument("--purpose", default="", help="recorded due-diligence purpose (required with --include-persons)")
    parser.add_argument("--keep-downloads", action="store_true", help="keep the zips after the import")
    parser.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation after the plan")
    args = parser.parse_args(argv)
    with contextlib.suppress(AttributeError):
        os.umask(0o077)
    rt = App().runtime()

    def out(s: str) -> None:
        sys.stdout.write(s + "\n")

    if args.plan:
        try:
            p = plan(rt, quarter=args.quarter)
        except ImportError_ as exc:
            out(f"PGFN plan unavailable: {exc}")
            return 1
        for f in p["files"]:
            out(f"  {f['name']}: {_human(f['bytes'])}")
        out(f"quarter {p['quarter']}: download {_human(p['download_bytes'])}, needs {_human(p['required_free_bytes'])} free, "
            f"free {_human(p['free_bytes'])}" + (f"; REFUSED: {p['refusal']}" if not p["ok"] else ""))
        return 0 if p["ok"] else 1

    def confirm(p: dict[str, Any]) -> bool:
        if args.yes:
            return True
        if not sys.stdin.isatty():
            out("non-interactive: re-run with --yes after reviewing the plan (--plan)")
            return False
        return input(f"download {_human(p['download_bytes'])} from PGFN now? [y/N] ").strip().lower() in ("y", "yes")

    def progress(ev: dict[str, Any]) -> None:
        if ev.get("event") == "plan":
            out(f"quarter {ev.get('quarter')}: {ev.get('files')} files, {_human(ev.get('download_bytes'))}")
        elif ev.get("event") == "download" and ev["done"] == ev["total"]:
            out(f"  downloaded {ev['file']} ({_human(ev['total'])})")

    res = import_pgfn(rt, quarter=args.quarter, include_persons=args.include_persons, purpose=args.purpose,
                      keep_downloads=args.keep_downloads, progress=progress, confirm=confirm)
    out(f"{res['status']}: {res['reason']}" + (f"\n  hint: {res['hint']}" if res.get("hint") else ""))
    return 0 if res["status"] == "imported" else 1


if __name__ == "__main__":  # pragma: no cover - manual entry point
    raise SystemExit(main())


__all__ = [
    "FormatChanged", "ImportError_", "ImportUnavailable", "PgfnIndex", "PgfnSite", "amount_band", "build_index", "import_pgfn",
    "index_path", "iter_pgfn_zip", "member_info", "open_index", "parse_directory", "pgfn_row", "plan", "read_state", "summary",
    "zip_problem",
]
