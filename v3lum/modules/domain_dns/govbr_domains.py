"""Official gov.br domains (P009): the SISP list ``dominios_gov_br.csv`` matched locally.

Final conditions (council #1, P009) and where they live:

1. ``dominios_gov_br.csv`` (dominiosgovbr.sisp.gov.br) is a registered dataset (:data:`DATASET`): daily
   TTL, list date in provenance (``list_date`` = the latest ``ultima_atualizacao`` of the file, plus the
   local ``fetched_at``), the stale copy kept on failure (dataset manager). :func:`parse_csv` uses the
   csv module with a field-size limit, checks the exact header and a minimum row count
   (:data:`MIN_ROWS`) before a download may replace the cached copy (:func:`validate_dataset`), and
   normalises every name and CNPJ through ``Entity.try_make``. The column ``nome_contato`` (natural
   persons) is never kept.
2. Matching is local (disclosure ``none``, allowed at TLP:RED). An exact listed domain gets attribute
   ``official_gov_br`` and a ``cnpj`` pivot of the registrant (relation ``registrant``).
3. Official status marks only the exact listed domain (finding tags ``official_gov_br`` and
   ``known_good``): it never touches URL entities or subdomains (the module accepts no URL, and a
   subdomain only gets the context attribute ``govbr_parent_listed``), so URL-level findings on a
   compromised gov.br host are always reported. The domain-level reputation dampening itself is a core
   suppression stage (core request recorded in the batch manifest).
4. gov.br lookalike detection: :func:`protected_entries` exposes the list (state zones, ``www`` and
   labels shorter than 3 characters left out, plus a ``govbr`` brand entry) and :func:`protected_domains`
   merges it with the BCB DominiosVerificados list (P360) - one shared protected-domains helper for the
   typosquat engine (P012), separate from org_profile brands (P028 rules unchanged).
5. A missing or failed dataset gives UNAVAILABLE ``dataset`` ('could not verify'), never 'not an
   official gov.br domain'; a miss reads 'not in the SISP gov.br list'.
6. Tests: the trimmed real CSV (``tests/fixtures/govbr_domains/``): exact match, URL-level
   non-suppression and the unavailable path.
"""

from __future__ import annotations

import csv
import io
import re
import threading
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from v3lum.core import validators
from v3lum.core.datasets import DatasetError, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

SOURCE = "sisp.dominios_gov_br"
URL = "https://dominiosgovbr.sisp.gov.br/dados/dominios_gov_br.csv"
DATASET = "govbr_domains.csv"
HEADER = ("dominio", "documento", "nome", "nome_contato", "data_cadastro", "ultima_atualizacao")
#: cond 1: a download with fewer rows never replaces the cached copy (1,280 rows on 2026-11-26)
MIN_ROWS = 1000
#: cond 1: csv field-size limit (the longest real field is 50 characters)
FIELD_LIMIT = 1024
#: the 27 state zones under gov.br are public suffixes: x.sp.gov.br is not covered by the list
STATE_ZONES = frozenset(f"{uf}.gov.br" for uf in (
    "ac", "al", "am", "ap", "ba", "ce", "df", "es", "go", "ma", "mg", "ms", "mt", "pa", "pb", "pe", "pi",
    "pr", "rj", "rn", "ro", "rr", "rs", "sc", "se", "sp", "to"))
MISS_WORDING = "not in the SISP gov.br list (federal registrations under gov.br only)"
UNAVAILABLE_WORDING = "gov.br domain list (SISP) not available: could not verify"
ATTRIBUTION = "Lista de dominios gov.br, SISP - Governo Federal (dados abertos, Decreto 8.777/2016)"

_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?: \d{2}:\d{2}:\d{2})?$")
_INDEX_LOCK = threading.Lock()
_INDEX: dict[str, tuple[str, dict[str, Any]]] = {}
#: TTL passed when only the local copy may be read (the shared helper): any present copy is 'fresh'
_LOCAL_ONLY_TTL = 10 * 365 * 86400


def _clean(value: Any, limit: int = 120) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", " ", _CTRL_RE.sub("", value)).strip()[:limit]


def cnpj_digits(value: Any) -> str | None:
    """'033.683.111/0001-07' (the list's zero-padded 15-digit mask) or a CNPJ -> 14 digits when valid."""
    if not isinstance(value, str):
        return None
    digits = re.sub(r"\D", "", value)
    if len(digits) == 15 and digits.startswith("0"):
        digits = digits[1:]
    return digits if len(digits) == 14 and validators.cnpj_valid(digits) else None


def parse_csv(raw: bytes | str, *, min_rows: int | None = None) -> dict[str, Any]:
    """``dominios_gov_br.csv`` -> ``{rows, row_count, skipped, max_updated, error}`` (cond 1).

    Rows are ``{domain, cnpj, registrant, created, updated, zone}``; ``nome_contato`` is never read.
    ``error`` names why the file must not replace the cached copy (bad header, csv error, too few rows,
    HTML/XML instead of CSV). Never raises on junk input."""
    floor = MIN_ROWS if min_rows is None else int(min_rows)
    res: dict[str, Any] = {"rows": [], "row_count": 0, "skipped": 0, "max_updated": None, "error": None}
    if isinstance(raw, (bytes, bytearray)):
        try:
            text = bytes(raw).decode("utf-8-sig")
        except UnicodeDecodeError:
            text = bytes(raw).decode("iso-8859-1")
    elif isinstance(raw, str):
        text = raw.lstrip("﻿")
    else:
        res["error"] = "not a CSV body"
        return res
    head = text.lstrip()[:512].lower()
    if not head:
        res["error"] = "empty body"
        return res
    if head.startswith(("<!doctype", "<html", "<?xml", "<error")) or "<html" in head:
        res["error"] = "HTML/XML page instead of the CSV"
        return res
    old_limit = csv.field_size_limit()
    try:
        csv.field_size_limit(FIELD_LIMIT)
        reader = csv.reader(io.StringIO(text), delimiter=";")
        try:
            header = next(reader)
        except (StopIteration, csv.Error):
            res["error"] = "bad header"
            return res
        if tuple(h.strip().lower() for h in header) != HEADER:
            res["error"] = "bad header (expected " + ";".join(HEADER) + ")"
            return res
        seen: set[str] = set()
        try:
            for row in reader:
                if len(row) != len(HEADER):
                    res["skipped"] += 1
                    continue
                ent = Entity.try_make(T.DOMAIN, row[0].strip())
                cnpj = cnpj_digits(row[1])
                name = str(ent.value) if ent is not None else ""
                if not name or not (name == "gov.br" or name.endswith(".gov.br")) or cnpj is None or name in seen:
                    res["skipped"] += 1
                    continue
                seen.add(name)
                updated = row[5].strip() if _TS_RE.match(row[5].strip()) else None
                created = row[4].strip() if _TS_RE.match(row[4].strip()) else None
                res["rows"].append({
                    "domain": name, "cnpj": cnpj, "registrant": _clean(row[2]),
                    "created": created[:10] if created else None, "updated": updated[:10] if updated else None,
                    "zone": name in STATE_ZONES,
                })
                if updated and (res["max_updated"] is None or updated > res["max_updated"]):
                    res["max_updated"] = updated
        except csv.Error as exc:
            res["error"] = f"csv error: {_clean(str(exc), 120)}"
            return res
    finally:
        csv.field_size_limit(old_limit)
    res["row_count"] = len(res["rows"])
    if res["row_count"] < floor:
        res["error"] = f"too few rows ({res['row_count']} < {floor})"
    return res


def validate_dataset(path: Path) -> bool:
    """``register_dataset(validate=)`` hook (cond 1): header and minimum rows before the copy is replaced."""
    parsed = parse_csv(Path(path).read_bytes())
    if parsed["error"]:
        raise ValueError(f"dominios_gov_br.csv rejected: {parsed['error']}")
    return True


register_dataset(
    DATASET,
    URL,
    ttl=86400,
    description="SISP official list of gov.br domains with the registrant CNPJ (dominios_gov_br.csv, regenerated daily)",
    licence="Open government data (Decreto 8.777/2016)",
    terms_class="open",
    attribution=ATTRIBUTION,
    provider="sisp",
    source=SOURCE,
    validate=validate_dataset,
    min_bytes=1000,
    expect="csv",
    max_bytes=5 * 1024 * 1024,
)


# --------------------------------------------------------------------------------------
# index and lookups (pure, unit-tested)
# --------------------------------------------------------------------------------------


def build_index(parsed: Mapping[str, Any]) -> dict[str, Any]:
    """``{rows: {domain: row}, by_cnpj: {cnpj: [domains]}, max_updated}`` of a parse without error."""
    rows = {r["domain"]: r for r in parsed.get("rows") or []} if not parsed.get("error") else {}
    by_cnpj: dict[str, list[str]] = {}
    for dom, row in sorted(rows.items()):
        by_cnpj.setdefault(row["cnpj"], []).append(dom)
    return {"rows": rows, "by_cnpj": by_cnpj, "max_updated": parsed.get("max_updated")}


def lookup(host: str, index: Mapping[str, Any]) -> dict[str, Any]:
    """Local match (cond 2): ``{official, row, parent_listed, state_zone}``.

    Only an EXACT listed name is official; a subdomain of a listed name reports ``parent_listed``
    (context, no official status); a name under a state zone (x.sp.gov.br) is another registrable
    domain the list does not cover (``state_zone``)."""
    rows = index.get("rows") or {}
    out: dict[str, Any] = {"official": False, "row": None, "parent_listed": None, "state_zone": None}
    row = rows.get(host)
    if row is not None:
        out.update(official=True, row=row, state_zone=host if row.get("zone") else None)
        return out
    labels = host.split(".")
    for i in range(1, len(labels) - 1):
        parent = ".".join(labels[i:])
        if parent in STATE_ZONES:
            out["state_zone"] = parent
            break
        if parent in rows:
            out["parent_listed"] = parent
            break
    return out


def dampener_applies(entity: Entity, match: Mapping[str, Any]) -> bool:
    """cond 3: the known_good dampener covers the exact listed DOMAIN only - never a URL, never a
    subdomain of a listed name."""
    return entity.type is T.DOMAIN and bool(match.get("official")) and match.get("row", {}).get("domain") == entity.value


def protected_from_index(index: Mapping[str, Any], *, min_label: int = 3, stop_labels: Iterable[str] = ("www",)) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(domains, brands) protected entries of the gov.br list for ``build_protected_index`` (cond 4).

    State zones, labels shorter than ``min_label`` and ``stop_labels`` are left out; ``gov.br`` itself is
    one brand entry ('govbr') for gov-br/govbr lookalikes. Source 'govbr' (matched strictly by P012)."""
    stop = set(stop_labels)
    domains: list[dict[str, Any]] = []
    for dom, row in sorted((index.get("rows") or {}).items()):
        if row.get("zone") or dom == "gov.br":
            continue
        label = dom[: -len(".gov.br")]
        if "." in label or len(label) < min_label or label in stop:
            continue
        domains.append({"domain": dom, "source": "govbr", "cnpj_root": row["cnpj"][:8], "registrant": row.get("registrant")})
    brands = [{"keyword": "govbr", "source": "govbr"}] if domains else []
    return domains, brands


def merge_protected(*entry_lists: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Merge protected-domain entries of several lists by domain, keeping every source and CNPJ root
    (cond 4: gov.br + BCB DominiosVerificados in one helper)."""
    merged: dict[str, dict[str, Any]] = {}
    for entries in entry_lists:
        for e in entries or ():
            if not isinstance(e, Mapping):
                continue
            ent = Entity.try_make(T.DOMAIN, str(e.get("domain") or ""))
            if ent is None:
                continue
            m = merged.setdefault(ent.value, {"domain": ent.value, "source": e.get("source"), "sources": [], "cnpj_roots": []})
            if e.get("source") and e["source"] not in m["sources"]:
                m["sources"].append(e["source"])
            if e.get("cnpj_root") and e["cnpj_root"] not in m["cnpj_roots"]:
                m["cnpj_roots"].append(e["cnpj_root"])
    return [merged[k] for k in sorted(merged)]


# --------------------------------------------------------------------------------------
# dataset access (local copy; the shared helper never downloads)
# --------------------------------------------------------------------------------------


def _load_index(path: Path, sha256: str) -> dict[str, Any]:
    key = str(path)
    with _INDEX_LOCK:
        hit = _INDEX.get(key)
        if hit is not None and hit[0] == sha256 and sha256:
            return hit[1]
    parsed = parse_csv(Path(path).read_bytes(), min_rows=0)
    index = build_index(parsed)
    index["parse_error"] = parsed.get("error")
    with _INDEX_LOCK:
        _INDEX.clear()  # one list: keep only the current copy
        _INDEX[key] = (sha256, index)
    return index


def load_index(ctx: Any, *, download: bool = True) -> tuple[dict[str, Any] | None, Any, str]:
    """(index, DatasetInfo, problem). ``download=False`` reads the local copy only (the shared helper)."""
    try:
        if not download:
            info = ctx.data.info(DATASET)
            if not getattr(info, "present", False):
                return None, info, f"{DATASET} not downloaded: run v3lum data update {DATASET}"
            path = ctx.data.fetch(DATASET, ttl=_LOCAL_ONLY_TTL)  # a present copy is served as is: no refresh
        else:
            path = ctx.data.fetch(DATASET)
        info = ctx.data.info(DATASET)
    except DatasetError as exc:  # DatasetUnavailable included: never 'not official'
        return None, None, _clean(str(exc), 200) or UNAVAILABLE_WORDING
    except OSError as exc:
        return None, None, f"local copy of {DATASET} unreadable ({type(exc).__name__})"
    index = _load_index(Path(path), str(getattr(info, "sha256", "") or ""))
    if not index["rows"]:
        return None, info, f"local copy of {DATASET} is unusable ({index.get('parse_error') or 'no rows'})"
    return index, info, ""


def protected_entries(ctx: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
    """(domains, brands, note): the gov.br protected entries from the LOCAL copy (cond 4; never
    downloads during a scan). ``note`` says why the list is not applied ('' when it is)."""
    index, _info, problem = load_index(ctx, download=False)
    if index is None:
        return [], [], problem
    domains, brands = protected_from_index(index)
    return domains, brands, ""


def protected_domains(ctx: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str]]:
    """The shared protected-domains helper (cond 4) for the typosquat engine (P012): gov.br list +
    BCB DominiosVerificados (P360, read through the typosquat reader of its local copy).

    Returns ``(domain entries, brand entries, notes {list: why it is not applied})``; the entries are
    in the ``build_protected_index`` format and never mix with org_profile brands (P028 unchanged)."""
    notes: dict[str, str] = {}
    gov_domains, gov_brands, note = protected_entries(ctx)
    if note:
        notes["govbr"] = note
    bcb_rows: list[dict[str, Any]] = []
    try:
        from v3lum.modules.domain_dns import typosquat as _typosquat

        reader = getattr(_typosquat, "_bcb_dataset", None)
        if callable(reader):
            bcb_rows, bcb_note = reader(ctx)
            if bcb_note:
                notes["bcb"] = bcb_note
    except Exception as exc:  # noqa: BLE001 - the BCB list is optional here: never break the caller
        notes["bcb"] = f"BCB DominiosVerificados not applied ({type(exc).__name__})"
    return gov_domains + [dict(r) for r in bcb_rows], gov_brands, notes


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class GovbrDomains(Module):
    name = "govbr_domains"
    title = "Official gov.br domain list (SISP)"
    description = (
        "Local match of a gov.br domain against the SISP official list dominios_gov_br.csv: official status of the "
        "exact listed name and the registrant CNPJ; for a CNPJ, the gov.br names it registered."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN, T.CNPJ}
    produces = {T.CNPJ}
    tags = {"offline", "brazil"}
    reference = "https://dominiosgovbr.sisp.gov.br/dados/dominios_gov_br.csv"
    notice = (
        "Official status covers the exact listed name only: URLs and subdomains on a gov.br host keep every finding "
        "(compromised agency hosts serve phishing). The registrant CNPJ is often the IT operator (SERPRO, DATAPREV)."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (SOURCE,)
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.1
    max_pivots = 5
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.DOMAIN:
            return entity.value == "gov.br" or entity.value.endswith(".gov.br")
        return entity.type is T.CNPJ

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        index, info, problem = load_index(ctx)
        if index is None:
            return res.mark("unavailable", f"{UNAVAILABLE_WORDING} ({problem})", reason_code="dataset")
        provenance = {
            "list_date": (index.get("max_updated") or "")[:10] or None,
            "fetched_at": getattr(info, "fetched_at", "") or None,
            "stale": bool(getattr(info, "stale", False)),
        }
        if entity.type is T.CNPJ:
            domains = index["by_cnpj"].get(entity.value) or []
            if not domains:
                return res.mark("empty", f"no gov.br domain registered by this CNPJ in the SISP list (list date {provenance['list_date'] or '?'})")
            res.attr("govbr_domains", domains[:200])
            return res
        match = lookup(entity.value, index)
        if match["official"]:
            row = match["row"]
            res.attr("official_gov_br", {
                "domain": row["domain"], "registrant_cnpj": row["cnpj"], "registrant": row["registrant"],
                "created": row["created"], "updated": row["updated"], **provenance,
            })
            res.finding(
                "Official gov.br domain (SISP list)",
                "info",
                f"{entity.display} is listed in the SISP official gov.br domain list (registrant {row['registrant'] or '?'}, "
                f"CNPJ {row['cnpj']}; list date {provenance['list_date'] or '?'}). Official status covers this exact name only: "
                "findings on URLs and subdomains of the host still stand.",
                confidence="confirmed",
                tags=["official_gov_br", "known_good"] if dampener_applies(entity, match) else ["official_gov_br"],
                data={"registrant_cnpj": row["cnpj"], "state_zone": bool(row.get("zone")), **provenance},
                source=SOURCE,
            )
            res.pivot(T.CNPJ, row["cnpj"], "registrant", confidence="confirmed",
                      note="registrant of the gov.br domain in the SISP list (often the IT operator, not the agency)")
            return res
        if match["parent_listed"]:
            res.attr("govbr_parent_listed", match["parent_listed"])
            return res
        if match["state_zone"]:
            return res.mark("empty", f"under state zone {match['state_zone']}: not covered by the SISP gov.br list")
        return res.mark("empty", MISS_WORDING)
