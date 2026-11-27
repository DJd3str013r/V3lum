"""P248 ``anac_rab`` - ANAC RAB aircraft registry (Registro Aeronautico Brasileiro), matched offline.

Batch p3-G10-2. Council P248 final conditions, as implemented here:

1. **Dataset** - ANAC ``dados_aeronaves.csv`` (sistemas.anac.gov.br, ~24 MB, daily) is the registered dataset
   ``anac_rab_dados_aeronaves.csv`` refreshed by ``v3lum data update`` (never during a scan: > 5 MB) and parsed
   offline (disclosure 'none') after the UTF-8 BOM and the ``Atualizado em: YYYY-MM-DD`` preamble line (';'
   separated, quoted, owner/operator cells are JSON arrays). :func:`validate_anac_rab` checks the preamble,
   header, final newline and a row floor before a download replaces the previous copy; findings cite the
   dataset date.
2. **Minimisation at import** - :func:`anac_party` keeps an owner/operator only when it is a company identified
   by a CNPJ (14 digits, or 13 digits that become a DV-valid CNPJ once the lost leading zero is restored);
   natural persons (masked CPFs ``123XXXXXX45``), ``Indisponivel`` and short operator codes are dropped while
   parsing and only counted, so no person can be matched, shown or pivoted.
3. **Matching** - owner/operator CNPJ (exact, then root - stated), exact company name (shared normaliser of
   ``v3lum.modules.company_org.namematch``) and the aircraft registration mark with a strict pattern
   (``PP|PR|PS|PT|PU`` + 3 letters) through an explicit ``TYPE:value`` keyword (``mark:``, ``aircraft:``,
   ``rab:``, ``tail:``, ``cnpj:``, ``company:``); never from bare tokens and never by person name.
4. **Opt-in** - ``default_enabled = False``. Output: mark, model, owner/operator companies and registration
   status (registered / cancelled / reserved / provisional), lien text and the dataset date.
5. **Fixture** - the real BOM, preamble and 34-column header with synthetic rows (person rows included to
   prove they are dropped): tests/fixtures/anac_rab/.
"""

from __future__ import annotations

import csv
import io
import json
import re
import threading
import unicodedata
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from v3lum.core import validators
from v3lum.core.datasets import DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.company_org import namematch

SOURCE = "anac.rab"
DATASET = "anac_rab_dados_aeronaves.csv"
ANAC_URL = "https://sistemas.anac.gov.br/dadosabertos/Aeronaves/RAB/dados_aeronaves.csv"
LICENCE = "Dados abertos ANAC (open government data, Registro Aeronautico Brasileiro)"
ATTRIBUTION = "Agencia Nacional de Aviacao Civil (ANAC) - Registro Aeronautico Brasileiro, dados abertos"
#: the production file holds ~22,600 aircraft; far fewer rows means a cut or broken export
MIN_ROWS = 15_000
SERVE_LOCAL_TTL = 100 * 365 * 86400.0
STALE_DAYS = 7
MAX_AIRCRAFT = 50
REQUIRED = ("MARCAS", "PROPRIETARIOS", "OPERADORES", "DS_MODELO", "NM_FABRICANTE", "DT_CANC", "DS_GRAVAME")

_MARK_RX = re.compile(r"^(PP|PR|PS|PT|PU)-?([A-Z]{3})$")
_TYPED_RX = re.compile(r"^\s*(mark|aircraft|rab|tail|cnpj|company)\s*:\s*(.+?)\s*$", re.I)
_HTML_RX = re.compile(r"^\s*(<!doctype\s+html|<html|<head|<body|<\?xml)", re.I)
_WS = re.compile(r"\s+")


def _clean(value: Any) -> str:
    if value is None or isinstance(value, (dict, list)):
        return ""
    return _WS.sub(" ", str(value)).strip()


def _text(body: Any) -> str:
    if isinstance(body, str):
        text = body
    elif isinstance(body, (bytes, bytearray, memoryview)):
        raw = bytes(body)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")
    else:
        return ""
    return text[1:] if text.startswith("﻿") else text


def parse_br_date(value: Any) -> str | None:
    """ISO date from dd/mm/yyyy, yyyy-mm-dd[ hh:mm:ss], DDMMYYYY or DDMMYY; None for sentinels and junk."""
    s = _clean(value)
    m = re.fullmatch(r"(\d{2})/(\d{2})/(\d{4})", s)
    if m:
        d, mo, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
    elif (m := re.match(r"(\d{4})-(\d{2})-(\d{2})(?:[T ]\d{2}:\d{2}(?::\d{2})?)?$", s)):
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    elif re.fullmatch(r"\d{8}", s):
        d, mo, y = int(s[:2]), int(s[2:4]), int(s[4:])
    elif re.fullmatch(r"\d{6}", s):
        d, mo, yy = int(s[:2]), int(s[2:4]), int(s[4:])
        y = 2000 + yy if yy < 50 else 1900 + yy
    else:
        return None
    if y < 1900:
        return None
    try:
        return date(y, mo, d).isoformat()
    except ValueError:
        return None


# ======================================================================================
# typed queries (FC3)
# ======================================================================================


def normalize_aircraft_mark(value: Any) -> dict[str, str] | None:
    """Strict Brazilian registration mark: PP-/PR-/PS-/PT-/PU- + 3 letters (hyphen optional).
    -> ``{key: 'PTZZB', display: 'PT-ZZB'}`` or None."""
    s = _clean(value).upper().replace(" ", "")
    m = _MARK_RX.match(s)
    return {"key": m.group(1) + m.group(2), "display": f"{m.group(1)}-{m.group(2)}"} if m else None


def _cnpj14(value: Any) -> str | None:
    s = re.sub(r"[\s./-]", "", _clean(value)).upper()
    return s if re.fullmatch(r"[0-9A-Z]{12}[0-9]{2}", s) and validators.cnpj_valid(s) else None


def parse_typed_query(value: Any) -> tuple[str, str] | None:
    """Explicit ``TYPE:value`` keyword (FC3): mark/aircraft/rab/tail -> ('mark', key); cnpj -> ('cnpj', 14
    chars, DV-valid); company -> ('company', name). Bare tokens give None: a stray 'PTZZB' is never matched,
    and person names are never a query type."""
    m = _TYPED_RX.match(str(value or ""))
    if not m:
        return None
    kind, v = m.group(1).lower(), m.group(2)
    if kind in ("mark", "aircraft", "rab", "tail"):
        mk = normalize_aircraft_mark(v)
        return ("mark", mk["key"]) if mk else None
    if kind == "cnpj":
        c = _cnpj14(v)
        return ("cnpj", c) if c else None
    name = _clean(v)
    return ("company", name) if name else None


# ======================================================================================
# parsing and minimisation (FC1, FC2, FC4)
# ======================================================================================


def anac_party(entry: Any) -> dict[str, Any] | None:
    """One owner/operator JSON entry -> company dict, or None (FC2: persons are dropped at import).

    Kept only when DOCUMENTO is a 14-digit CNPJ, or 13 digits that become a DV-valid CNPJ once the lost
    leading zero is restored. Masked CPFs ('123XXXXXX09'), 'Indisponivel', short operator codes and anything
    else give None. The name is kept only for companies."""
    if not isinstance(entry, dict):
        return None
    doc = re.sub(r"\s", "", str(entry.get("DOCUMENTO") or ""))
    restored = False
    if re.fullmatch(r"\d{13}", doc) and validators.cnpj_valid("0" + doc):
        doc, restored = "0" + doc, True
    if not re.fullmatch(r"\d{14}", doc):
        return None
    return {"cnpj": doc, "cnpj_root": doc[:8], "cnpj_valid": validators.cnpj_valid(doc), "zero_restored": restored,
            "name": _clean(entry.get("NOME")) or None, "uf": _clean(entry.get("UF")) or None}


def anac_status(rec: dict[str, Any]) -> dict[str, Any]:
    """Registration status (FC4): cancelled (+ reason) | reserved | provisional | registered."""
    if _clean(rec.get("DT_CANC")):
        return {"status": "cancelled", "since": parse_br_date(rec.get("DT_CANC")), "reason": _clean(rec.get("DS_MOTIVO_CANC")) or None}
    folded = "".join(c for c in unicodedata.normalize("NFKD", _clean(rec.get("DS_GRAVAME")).upper()) if not unicodedata.combining(c))
    if folded.startswith("RESERVADAS AS MARCAS"):
        return {"status": "reserved", "since": None, "reason": None}
    if folded.startswith("MATRICULA EXPEDITA"):
        return {"status": "provisional", "since": None, "reason": "matricula sob analise"}
    return {"status": "registered", "since": parse_br_date(rec.get("DT_MATRICULA")), "reason": None}


def anac_problem(body: Any, *, min_rows: int = MIN_ROWS) -> str:
    """Why a downloaded copy must not replace the installed one ('' = acceptable): HTML instead of the CSV,
    a missing BOM/'Atualizado em' preamble, a cut download (no final newline), a header change or too few
    rows."""
    text = _text(body)
    if not text.strip():
        return "empty file"
    if _HTML_RX.match(text[:2048]):
        return "an HTML page came back instead of the CSV"
    if not text.startswith("Atualizado em"):
        return "missing 'Atualizado em' preamble"
    if not text.endswith("\n"):
        return "truncated (no final newline)"
    lines = text.split("\n", 2)
    if len(lines) < 3:
        return "no data"
    try:
        header = next(csv.reader([lines[1].rstrip("\r")], delimiter=";"))
    except (csv.Error, StopIteration):
        return "unreadable header"
    missing = [c for c in REQUIRED if c not in header]
    if missing:
        return f"schema drift: column(s) {', '.join(missing)} missing"
    rows = text.count("\n") - 2
    if rows < min_rows:
        return f"too few rows ({rows} < {min_rows})"
    return ""


def validate_anac_rab(path: Path) -> bool:
    """``validate(path)`` of the dataset (FC1): raises ValueError with the reason (the previous copy stays)."""
    problem = anac_problem(Path(path).read_bytes())
    if problem:
        raise ValueError(f"{DATASET}: {problem}")
    return True


def parse_anac_rab(body: Any) -> dict[str, Any]:
    """dados_aeronaves.csv -> aircraft rows with company owners/operators only (FC1, FC2, FC4).

    Returns ``{updated, rows, stats {rows, dropped_parties, kept_parties, bad_json, bad_mark}, errors}``. Per
    aircraft: mark, mark_display, model, manufacturer, icao_type, year, registration {status, since, reason},
    lien, owners[], operators[] (companies only). A missing preamble or a cut last row is reported in
    ``errors`` (the cut row is dropped); a header change returns no rows."""
    text = _text(body)
    out: dict[str, Any] = {"updated": None, "rows": [], "errors": [],
                           "stats": {"rows": 0, "dropped_parties": 0, "kept_parties": 0, "bad_json": 0, "bad_mark": 0}}
    if _HTML_RX.match(text[:2048]):
        out["errors"].append("an HTML page instead of the CSV")
        return out
    first, _, rest = text.partition("\n")
    m = re.match(r"Atualizado em:\s*(\d{4}-\d{2}-\d{2})", first.strip())
    if m:
        out["updated"] = m.group(1)
    else:
        rest = text
        out["errors"].append("missing 'Atualizado em' preamble")
    if not text.endswith("\n"):
        out["errors"].append("truncated (no final newline)")
        cut = rest.rfind("\n")
        rest = rest[: cut + 1] if cut >= 0 else ""
    try:
        reader = csv.DictReader(io.StringIO(rest, newline=""), delimiter=";")
        fields = reader.fieldnames or []
    except csv.Error as exc:
        out["errors"].append(f"unreadable CSV: {exc}")
        return out
    if any(c not in fields for c in REQUIRED):
        out["errors"].append("schema drift: unexpected header")
        return out
    st = out["stats"]
    try:
        for rec in reader:
            st["rows"] += 1
            mk = normalize_aircraft_mark(rec.get("MARCAS"))
            if not mk:
                st["bad_mark"] += 1
                continue
            parties: dict[str, list[dict[str, Any]]] = {}
            for col, key in (("PROPRIETARIOS", "owners"), ("OPERADORES", "operators")):
                try:
                    arr = json.loads(rec.get(col) or "[]")
                except ValueError:
                    st["bad_json"] += 1
                    arr = []
                kept: list[dict[str, Any]] = []
                for entry in arr if isinstance(arr, list) else []:
                    party = anac_party(entry)
                    if party is None:
                        st["dropped_parties"] += 1  # FC2: a person (or an unidentified party) never enters the index
                        continue
                    kept.append(party)
                    st["kept_parties"] += 1
                parties[key] = kept
            year = _clean(rec.get("NR_ANO_FABRICACAO"))
            out["rows"].append({
                "mark": mk["key"], "mark_display": mk["display"], "model": _clean(rec.get("DS_MODELO")) or None,
                "manufacturer": _clean(rec.get("NM_FABRICANTE")) or None, "icao_type": _clean(rec.get("CD_TIPO_ICAO")) or None,
                "year": int(year) if year.isdigit() else None, "registration": anac_status(rec),
                "lien": _clean(rec.get("DS_GRAVAME")) or None, "owners": parties["owners"], "operators": parties["operators"],
            })
    except csv.Error as exc:
        out["errors"].append(f"malformed CSV row: {exc}")
    return out


@dataclass
class AnacIndex:
    updated: str | None = None
    rows: list[dict[str, Any]] = field(default_factory=list)
    by_mark: dict[str, int] = field(default_factory=dict)
    by_cnpj: dict[str, set[int]] = field(default_factory=dict)
    by_root: dict[str, set[int]] = field(default_factory=dict)
    by_name: dict[str, set[int]] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)
    errors: tuple[str, ...] = ()


def build_anac_index(parsed: dict[str, Any]) -> AnacIndex:
    idx = AnacIndex(updated=parsed.get("updated"), rows=list(parsed.get("rows") or ()), stats=dict(parsed.get("stats") or {}),
                    errors=tuple(parsed.get("errors") or ()))
    for i, row in enumerate(idx.rows):
        idx.by_mark[row["mark"]] = i
        for role in ("owners", "operators"):
            for p in row.get(role) or ():
                idx.by_cnpj.setdefault(p["cnpj"], set()).add(i)
                idx.by_root.setdefault(p["cnpj_root"], set()).add(i)
                key = namematch.normalized_name(p.get("name") or "")
                if key:
                    idx.by_name.setdefault(key, set()).add(i)
    return idx


def lookup(index: AnacIndex, query: tuple[str, str]) -> list[dict[str, Any]]:
    """Typed query -> matched aircraft (FC3/FC4): mark, model, manufacturer, year, owner/operator company names
    and CNPJs, registration status, lien and the match kind ('mark' | 'cnpj' | 'root' | 'company_exact')."""
    kind, value = query
    hits: dict[int, str] = {}
    if kind == "mark":
        i = index.by_mark.get(value)
        if i is not None:
            hits[i] = "mark"
    elif kind == "cnpj":
        for i in index.by_cnpj.get(value, ()):
            hits[i] = "cnpj"
        for i in index.by_root.get(value[:8], ()):
            hits.setdefault(i, "root")
    elif kind == "company":
        key = namematch.normalized_name(value)
        for i in index.by_name.get(key, ()) if key else ():
            hits[i] = "company_exact"
    rank = {"mark": 0, "cnpj": 1, "company_exact": 1, "root": 2}
    out = []
    for i in sorted(hits, key=lambda j: (rank[hits[j]], index.rows[j]["mark"])):
        row = index.rows[i]
        reg = row["registration"]
        out.append({
            "mark": row["mark_display"], "model": row["model"], "manufacturer": row["manufacturer"], "year": row["year"],
            "owners": [p["name"] for p in row["owners"] if p.get("name")], "operators": [p["name"] for p in row["operators"] if p.get("name")],
            "owner_cnpjs": [p["cnpj"] for p in row["owners"]], "operator_cnpjs": [p["cnpj"] for p in row["operators"]],
            "registration": reg["status"], "since": reg.get("since"), "lien": row.get("lien"), "match": hits[i],
            "_row": i,
        })
    return out


def company_pivots(index: AnacIndex, hit: dict[str, Any]) -> list[tuple[str, str]]:
    """(CNPJ, relation) pivots for the companies of one aircraft (FC2/FC4): DV-valid CNPJs only, never persons."""
    row = index.rows[hit["_row"]]
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for role, relation in (("owners", "aircraft_owner"), ("operators", "aircraft_operator")):
        for p in row.get(role) or ():
            if p.get("cnpj_valid") and (p["cnpj"], relation) not in seen:
                seen.add((p["cnpj"], relation))
                out.append((p["cnpj"], relation))
    return out


# ======================================================================================
# local copy (never downloads)
# ======================================================================================

_LOCK = threading.Lock()
_MEMO: dict[str, AnacIndex] = {}


def load_index(data: Any) -> tuple[AnacIndex, dict[str, Any]]:
    """The parsed local RAB copy (parsed once per copy) and its citation meta; DatasetUnavailable when no
    copy is installed. Never downloads (FC1)."""
    try:
        present = bool(data.info(DATASET).present)
    except (ValueError, OSError):
        present = False
    if not present:
        raise DatasetUnavailable(DATASET, f"ANAC RAB not downloaded: run v3lum data update {DATASET}")
    path = Path(data.fetch(DATASET, ttl=SERVE_LOCAL_TTL))
    info = data.info(DATASET)
    sha = str(getattr(info, "sha256", "") or "")
    with _LOCK:
        idx = _MEMO.get(sha) if sha else None
    if idx is None:
        idx = build_anac_index(parse_anac_rab(path.read_bytes()))
        if sha:
            with _LOCK:
                _MEMO.clear()
                _MEMO[sha] = idx
    age = getattr(info, "age_hours", None)
    meta = {"dataset": DATASET, "updated": idx.updated, "fetched_at": str(getattr(info, "fetched_at", "") or ""),
            "aircraft": len(idx.rows), "stale": bool(age is not None and float(age) > STALE_DAYS * 24)}
    return idx, meta


register_dataset(
    DATASET, ANAC_URL, ttl=86400,
    description="ANAC RAB aircraft registry (dados_aeronaves.csv, ~24 MB, daily; refreshed by v3lum data update, never during a "
                "scan); natural-person owners/operators are dropped when the copy is parsed",
    licence=LICENCE, terms_class="open", attribution=ATTRIBUTION, source=SOURCE, validate=validate_anac_rab,
    min_bytes=1_000_000, expect="text", max_bytes=64 * 1024 * 1024, large=True,
)


# ======================================================================================
# the module
# ======================================================================================


@register
class AnacRab(Module):
    name = "anac_rab"
    title = "ANAC RAB aircraft registry (offline)"
    description = (
        "Offline lookups in the ANAC aircraft registry (RAB): aircraft owned or operated by a company (CNPJ or exact name) and "
        "the owner/operator companies of a registration mark (keyword 'mark:PT-XXX'). Company parties only."
    )
    category = "brazil_public_data"
    accepts = {T.CNPJ, T.ORG, T.KEYWORD}
    produces = {T.CNPJ}
    tags = {"brazil", "offline"}
    reference = "https://www.gov.br/anac/pt-br/assuntos/regulados/aeronaves/rab"
    notice = (
        "ANAC open data downloaded by `v3lum data update anac_rab_dados_aeronaves.csv` and matched locally. Natural-person "
        "owners and operators are dropped when the copy is parsed: only companies identified by a CNPJ are matched or shown. "
        "Marks are matched only from an explicit keyword such as 'mark:PT-ABC', never from bare tokens or person names."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (SOURCE,)
    access_model = "offline"
    expected_latency = 1.0
    timeout = 120.0
    max_pivots = 25
    default_enabled = False  # P248 cond 4: opt-in

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.KEYWORD:
            return parse_typed_query(entity.value) is not None  # FC3: explicit TYPE:value only
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type is T.CNPJ:
            query: tuple[str, str] | None = ("cnpj", str(entity.value))
        elif entity.type is T.ORG:
            query = ("company", str(entity.value))
        else:
            query = parse_typed_query(entity.value)
        if query is None:
            return res.mark(Status.SKIPPED, "not a typed RAB query (mark:/cnpj:/company:)", reason_code="not_applicable")
        try:
            index, meta = load_index(ctx.data)
        except DatasetUnavailable as exc:
            return res.mark(Status.UNAVAILABLE, f"{exc}; never read as 'no aircraft'", reason_code="dataset")
        except OSError as exc:
            return res.mark(Status.ERROR, f"local ANAC RAB copy unreadable ({type(exc).__name__}): could not verify")
        if not index.rows:
            why = "; ".join(index.errors) or "no aircraft row"
            return res.mark(Status.ERROR, f"local ANAC RAB copy unusable ({why}): run v3lum data update {DATASET}; could not verify")
        as_of = index.updated or str(meta.get("fetched_at") or "")[:10] or "unknown date"
        res.attr("anac_rab_date", as_of)
        if meta.get("stale"):
            res.attr("dataset_age", [f"{DATASET}, RAB as of {as_of} (older than {STALE_DAYS} days: run v3lum data update)"])
        hits = lookup(index, query)
        what = {"mark": "registration mark", "cnpj": "owner/operator CNPJ", "company": "exact company name"}[query[0]]
        if not hits:
            return res.mark(Status.EMPTY, f"no aircraft in the ANAC RAB for this {what} (RAB as of {as_of}; companies only)")
        shown = hits[:MAX_AIRCRAFT]
        res.attr("aircraft", [{k: v for k, v in h.items() if k not in ("_row", "owner_cnpjs", "operator_cnpjs")} for h in shown])
        res.raw = {"query": {"kind": query[0]}, "rab_updated": index.updated, "total": len(hits),
                   "aircraft": [{k: v for k, v in h.items() if k != "_row"} for h in shown]}
        by_status: dict[str, int] = {}
        for h in hits:
            by_status[h["registration"]] = by_status.get(h["registration"], 0) + 1
        summary = ", ".join(f"{n} {s}" for s, n in sorted(by_status.items()))
        if query[0] == "mark":
            h = hits[0]
            owners = ", ".join(h["owners"]) or "no company owner (person or undisclosed owner withheld)"
            res.finding(
                "Aircraft registration in the ANAC RAB", "info",
                f"{h['mark']}: {h['model'] or '?'} ({h['manufacturer'] or '?'}), {h['registration']}; owner(s): {owners} (RAB as of {as_of})",
                confidence="confirmed", source=SOURCE, data={"mark": h["mark"], "registration": h["registration"], "lien": h.get("lien")},
                criterion=f"registration mark {h['mark']} in the ANAC RAB copy dated {as_of}",
            )
        else:
            root_only = all(h["match"] == "root" for h in hits)
            res.finding(
                "Aircraft linked to this company in the ANAC RAB", "info",
                f"{len(hits)} aircraft ({summary}){' through the CNPJ root (other establishment)' if root_only else ''}, "
                f"first {len(shown)} listed (RAB as of {as_of})",
                confidence="possible" if root_only else "probable", source=SOURCE,
                data={"total": len(hits), "by_status": by_status, "marks": [h["mark"] for h in shown]},
                criterion=(f"company listed as owner/operator by {'CNPJ root' if root_only else what} in the ANAC RAB copy dated {as_of}"
                           + ("; a name match is exact after normalisation, confirm the CNPJ" if query[0] == "company" else "")),
            )
        for h in shown:
            for cnpj, relation in company_pivots(index, h):
                res.pivot(T.CNPJ, cnpj, relation, confidence="probable", expand=False,
                          note=f"{relation.replace('_', ' ')} of {h['mark']} in the ANAC RAB ({as_of}); company party, analyst selection required")
        return res


__all__ = [
    "DATASET", "AnacIndex", "AnacRab", "anac_party", "anac_problem", "anac_status", "build_anac_index", "company_pivots", "load_index",
    "lookup", "normalize_aircraft_mark", "parse_anac_rab", "parse_typed_query", "validate_anac_rab",
]
