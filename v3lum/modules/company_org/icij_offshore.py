"""P221 ICIJ Offshore Leaks: local bulk index first, reconciliation API fallback (batch p3-G10-1).

Two modules over the provider ``icij`` (council P221 final conditions):

* ``icij_offshore`` (disclosure ``none``): matches a company name against the local SQLite index built from
  the ICIJ bulk CSV (dataset ``icij``: ``v3lum data update icij`` downloads ``full-oldb.LATEST.zip`` through
  the dataset manager and its validator builds the index; never bundled, never downloaded during a scan,
  cond 3). Matching is local (no disclosure) with the shared P219 matcher (``namematch``: score >= 0.90,
  at most 5 candidates) over :mod:`offline_name_index`. Without the dataset it is UNAVAILABLE ``dataset``
  ('run v3lum data update icij'), never 'no match' (cond 4; the policy gate's POL-14 says the same).
* ``icij_offshore_api`` (disclosure ``third_party``): the reconciliation API fallback (one POST per entity,
  entity-typed, at most 5 candidates, cond 4). It runs only when the local index is not installed and only
  at TLP:CLEAR/GREEN or when the analyst selects it explicitly (``-M icij_offshore_api`` or
  ``v3lum run icij_offshore_api``); otherwise it is UNAVAILABLE ``dataset`` too. Two modules because one
  module has one disclosure class: the local path keeps working at TLP:RED, and a registered large dataset
  makes the policy gate (POL-14) refuse every module declaring its source - the API fallback must not.

Both:

1. **Entities only** (cond 1): only ``company_name`` values (analyst-typed names, razao social / nome
   fantasia resolved from a seed CNPJ, PJ partners of a seed CNPJ); ``person_name`` is not accepted
   (person-name search over leaked data is people-search, rule 4). Candidates of other node types
   (officers, intermediaries, addresses) are never matched.
2. Officers and intermediaries appear only as named nodes linked to a matched entity (local index); they
   are never pivoted or expanded, and no address is imported (the ``nodes-addresses.csv`` member and every
   address relationship are dropped at import) or displayed.
3. Opt-in (``default_enabled=False``; ``-M`` or ``--preset deep``), only on seeds and CNPJ-resolved names
   (one hop from a seed CNPJ through ``legal_name`` / ``partner_of``), never on other pivoted names (cond 5).
4. Findings are POSSIBLE matches at INFO, tags ``offshore_leaks``, ``name_only_match`` and ``context_only``
   (never scored, never 'malicious', no pivots at all), with node id, leak, jurisdiction, intermediaries,
   dates and the manual node link, worded 'appears in ICIJ Offshore Leaks - not evidence of wrongdoing'
   plus ICIJ's disclaimer and the ODbL / CC BY-SA attribution (cond 6, 7). The reconcile API returns only
   id, name, leak and score: the other fields are on the linked node page.
5. No leaked document text exists in either source and nothing beyond node metadata is stored; the web
   search page (202 + WAF JS challenge) is never fetched (cond 7).
6. Rule 5 (cond 8): 401/403/429, timeouts, 5xx and error-in-200 or truncated bodies are BLOCKED /
   RATE_LIMITED / QUOTA / ERROR (raised by ``ctx.http``), never EMPTY; only well-formed reconcile answers
   enter the HTTP cache (``cache_if``).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import sqlite3
import sys
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote

from v3lum import paths
from v3lum.core.datasets import DatasetError, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import HttpError
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.company_org import namematch as nm
from v3lum.modules.company_org import offline_name_index as oni
from v3lum.modules.company_org.registry_text import as_dict, as_float, as_list, iso_date, text

# --------------------------------------------------------------------------------------
# constants
# --------------------------------------------------------------------------------------

RECONCILE_URL = "https://offshoreleaks.icij.org/api/v1/reconcile"
BULK_URL = "https://offshoreleaks-data.icij.org/offshoreleaks/csv/full-oldb.LATEST.zip"
NODE_URL = "https://offshoreleaks.icij.org/nodes/{id}"
TYPE_BASE = "https://offshoreleaks.icij.org/schema/oldb/"
ENTITY_TYPE = TYPE_BASE + "entity"
SOURCE_BULK = "icij.bulk"
SOURCE_API = "icij.reconcile"
DATASET = "icij"
UPDATE_HINT = "run v3lum data update icij"
THRESHOLD = nm.NAME_MATCH_THRESHOLD  # cond 3: 0.90
MAX_CANDIDATES = nm.MAX_CANDIDATES  # cond 3/4: at most 5
LINK_CAP = 10
MAX_QUERY_CHARS = 200
API_TLPS = ("clear", "green")  # cond 4
CACHE_TTL = 7 * 86400  # data generated a few times a year
DAY = 86400
WORDING = "appears in ICIJ Offshore Leaks - not evidence of wrongdoing"
DISCLAIMER = (
    "There are legitimate uses for offshore companies and trusts. We do not intend to suggest or imply that any people, "
    "companies or other entities included in the ICIJ Offshore Leaks Database have broken the law or otherwise acted "
    "improperly. Many people and entities have the same or similar names. We suggest you confirm the identities of any "
    "individuals or entities located in the database based on addresses or other identifiable information."
)
ATTRIBUTION = (
    "Contains information from the ICIJ Offshore Leaks Database (International Consortium of Investigative Journalists), "
    "made available under the Open Database License (ODbL); database contents under Creative Commons Attribution-ShareAlike "
    "(CC BY-SA)."
)
KNOWN_LEAKS = ("Pandora Papers", "Paradise Papers", "Panama Papers", "Bahamas Leaks", "Offshore Leaks")
NOTICE = (
    "Leak-derived data: a match means the name appears in ICIJ Offshore Leaks - not evidence of wrongdoing; homonyms are "
    "common. Company names only (person-name search over leaked data is people-search, rule 4). Opt-in (-M icij_offshore, "
    "--preset deep). ODbL database / CC BY-SA contents: attribution travels with every result."
)

# --------------------------------------------------------------------------------------
# bulk CSV import (dataset manager validator; never during a scan)
# --------------------------------------------------------------------------------------

MEMBERS = {
    "entities": "nodes-entities.csv",
    "officers": "nodes-officers.csv",
    "intermediaries": "nodes-intermediaries.csv",
    "relationships": "relationships.csv",
}
REQUIRED_COLUMNS = {
    "entities": ("node_id", "name", "jurisdiction_description", "incorporation_date", "sourceID"),
    "officers": ("node_id", "name", "sourceID"),
    "intermediaries": ("node_id", "name", "sourceID"),
    "relationships": ("node_id_start", "node_id_end", "rel_type"),
}
#: relationship types kept by the importer -> display kind; address links are never imported (cond 2)
LINK_KINDS = {
    "officer_of": "officer",
    "intermediary_of": "intermediary",
    "same_as": "related",
    "same_name_as": "related",
    "same_company_as": "related",
    "same_id_as": "related",
    "similar": "related",
    "similar_company_as": "related",
    "connected_to": "related",
    "underlying": "related",
}
MEMBER_MAX_BYTES = 1_500_000_000
MAX_RATIO = 200
_EXTRA_DDL = """
CREATE TABLE node (node_id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL, source TEXT);
CREATE TABLE rel (entity_id TEXT NOT NULL, other_id TEXT NOT NULL, kind TEXT NOT NULL, rel_type TEXT NOT NULL,
                  link TEXT, start_date TEXT, end_date TEXT);
"""


class IcijImportError(Exception):
    """The ICIJ archive cannot be imported (missing member, changed header, unsafe archive)."""


def leak_of(value: Any) -> dict[str, str | None]:
    """'Entity node extracted from the Paradise Papers - Bahamas corporate registry data.' or a bulk sourceID
    ('Pandora Papers - Alcogal') -> {'leak': 'Paradise Papers', 'detail': 'Bahamas corporate registry'}."""
    s = text(value)
    m = re.match(r"^\s*(?:Entity|Officer|Intermediary|Address|Other|Node)\s+node extracted from the\s+(.+?)\s+data\.?\s*$", s, re.I)
    src = m.group(1) if m else s
    leak = next((name for name in KNOWN_LEAKS if name.lower() in src.lower()), None)
    detail = None
    if " - " in src:
        head, _, tail = src.partition(" - ")
        if leak and leak.lower() in head.lower():
            detail = tail.strip() or None
    if not leak and src:
        leak = src.strip()[:80]
    return {"leak": leak, "detail": detail}


def node_url(node_id: Any) -> str | None:
    """Manual node link (digits only, else None)."""
    nid = text(node_id)
    return NODE_URL.format(id=quote(nid, safe="")) if re.fullmatch(r"\d{1,12}", nid) else None


def _member_infos(zf: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    infos = {i.filename.rsplit("/", 1)[-1]: i for i in zf.infolist() if not i.is_dir()}
    missing = [m for m in MEMBERS.values() if m not in infos]
    if missing:
        raise IcijImportError(f"ICIJ archive without {', '.join(missing)}")
    for member in MEMBERS.values():
        info = infos[member]
        if info.flag_bits & 0x1:
            raise IcijImportError(f"{member}: encrypted member refused")
        if info.file_size > MEMBER_MAX_BYTES:
            raise IcijImportError(f"{member}: {info.file_size} bytes exceed the {MEMBER_MAX_BYTES} cap")
        if info.compress_size and info.file_size / max(1, info.compress_size) > MAX_RATIO:
            raise IcijImportError(f"{member}: compression ratio above {MAX_RATIO} refused")
    return infos


def generated_on(zf: zipfile.ZipFile) -> str | None:
    for name in zf.namelist():
        m = re.search(r"GENERATED_ON_(\d{4})(\d{2})(\d{2})\.txt$", name)
        if m:
            return iso_date("-".join(m.groups()))
    return None


class _Capped(io.RawIOBase):
    """A read-only byte stream that refuses to yield more than ``cap`` bytes (zip-bomb guard)."""

    def __init__(self, raw: Any, cap: int) -> None:
        self.raw, self.cap, self.seen = raw, cap, 0

    def readable(self) -> bool:
        return True

    def readinto(self, buf: Any) -> int:
        data = self.raw.read(len(buf))
        self.seen += len(data)
        if self.seen > self.cap:
            raise IcijImportError("member longer than declared: refused")
        buf[: len(data)] = data
        return len(data)


def _rows(zf: zipfile.ZipFile, info: zipfile.ZipInfo, kind: str) -> Iterator[dict[str, str]]:
    csv.field_size_limit(max(csv.field_size_limit(), 1 << 24))
    with zf.open(info) as raw:
        stream = io.TextIOWrapper(io.BufferedReader(_Capped(raw, info.file_size + 1024)), encoding="utf-8", errors="replace", newline="")
        reader = csv.DictReader(stream)
        missing = [c for c in REQUIRED_COLUMNS[kind] if c not in (reader.fieldnames or [])]
        if missing:
            raise IcijImportError(f"{info.filename}: header changed (missing {', '.join(missing)})")
        yield from reader


def entity_record(row: dict[str, Any]) -> dict[str, Any] | None:
    """One entity CSV row -> index data (addresses, internal ids and registry numbers dropped)."""
    nid, name = text(row.get("node_id")), text(row.get("name"))
    if not nid or not name:
        return None
    leak = leak_of(row.get("sourceID"))
    return {
        "node_id": nid,
        "name": name,
        "names": [(name, "primary"), (text(row.get("former_name")), "former"), (text(row.get("original_name")), "original")],
        "data": {
            "jurisdiction": text(row.get("jurisdiction")) or None,
            "jurisdiction_description": text(row.get("jurisdiction_description")) or None,
            "status": text(row.get("status")) or None,
            "incorporation_date": iso_date(row.get("incorporation_date")),
            "inactivation_date": iso_date(row.get("inactivation_date")),
            "struck_off_date": iso_date(row.get("struck_off_date")),
            "service_provider": text(row.get("service_provider")) or None,
            "country_codes": [c for c in re.split(r"[;,]\s*", text(row.get("country_codes"))) if c][:5],
            "leak": leak["leak"],
            "leak_detail": leak["detail"],
        },
    }


def build_index(zip_path: str | Path, out_path: str | Path) -> dict[str, Any]:
    """Import entities, linked officer/intermediary names and their relationships from the ICIJ zip into a
    name index at ``out_path`` (addresses never imported). Returns a summary; raises IcijImportError."""
    writer: oni.NameIndexWriter | None = None
    try:
        with zipfile.ZipFile(zip_path) as zf:
            infos = _member_infos(zf)
            gen = generated_on(zf)
            writer = oni.NameIndexWriter(out_path, meta={"source": "icij", "generated_on": gen or ""})
            writer.conn.executescript(_EXTRA_DDL)
            entity_ids: set[str] = set()
            for row in _rows(zf, infos[MEMBERS["entities"]], "entities"):
                rec = entity_record(row)
                if rec and rec["node_id"] not in entity_ids and writer.add(rec["node_id"], "entity", rec["names"], rec["data"]) is not None:
                    entity_ids.add(rec["node_id"])
            needed: set[str] = set()
            batch: list[tuple[Any, ...]] = []
            links = 0
            for row in _rows(zf, infos[MEMBERS["relationships"]], "relationships"):
                start, end, rel_type = text(row.get("node_id_start")), text(row.get("node_id_end")), text(row.get("rel_type"))
                kind = LINK_KINDS.get(rel_type)
                if not kind or not start or not end:
                    continue
                extra = (text(row.get("link")) or None, iso_date(row.get("start_date")), iso_date(row.get("end_date")))
                pairs = []
                if kind in ("officer", "intermediary"):
                    if end in entity_ids:
                        pairs.append((end, start))
                        needed.add(start)
                else:
                    if start in entity_ids:
                        pairs.append((start, end))
                    if end in entity_ids:
                        pairs.append((end, start))
                for ent, other in pairs:
                    batch.append((ent, other, kind, rel_type, *extra))
                if len(batch) >= 5000:
                    writer.conn.executemany("INSERT INTO rel VALUES (?, ?, ?, ?, ?, ?, ?)", batch)
                    links += len(batch)
                    batch = []
            if batch:
                writer.conn.executemany("INSERT INTO rel VALUES (?, ?, ?, ?, ?, ?, ?)", batch)
                links += len(batch)
            nodes = 0
            for kind, member in (("officer", MEMBERS["officers"]), ("intermediary", MEMBERS["intermediaries"])):
                rows = []
                for row in _rows(zf, infos[member], kind + "s" if kind == "officer" else "intermediaries"):
                    nid, name = text(row.get("node_id")), text(row.get("name"))
                    if nid in needed and name:
                        rows.append((nid, kind, name[:200], text(row.get("sourceID"))[:120] or None))
                    if len(rows) >= 5000:
                        writer.conn.executemany("INSERT OR IGNORE INTO node VALUES (?, ?, ?, ?)", rows)
                        nodes += len(rows)
                        rows = []
                writer.conn.executemany("INSERT OR IGNORE INTO node VALUES (?, ?, ?, ?)", rows)
                nodes += len(rows)
            writer.conn.execute("CREATE INDEX rel_entity ON rel(entity_id)")
            writer.meta.update({"links": str(links), "linked_nodes": str(nodes)})
            writer.finish()
            return {"generated_on": gen, "entities": writer.entries, "aliases": writer.aliases, "links": links, "linked_nodes": nodes}
    except (zipfile.BadZipFile, OSError, sqlite3.Error, csv.Error, UnicodeError, ValueError) as exc:
        if writer is not None:
            writer.abort()
        raise IcijImportError(f"ICIJ import failed: {type(exc).__name__}: {str(exc)[:200]}") from exc
    except BaseException:
        if writer is not None:
            writer.abort()
        raise


def index_dir() -> Path:
    return paths.private_dir(paths.datasets_dir() / "icij_offshore")


def index_path_for(sha256: str) -> Path:
    """The local index built from the dataset copy with this SHA-256."""
    sha = re.sub(r"[^0-9a-f]", "", str(sha256 or "").lower())[:16]
    return index_dir() / f"index-{sha or 'unknown'}.sqlite"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_and_index(path: Path) -> bool:
    """Dataset validator: the download is accepted only when its index builds (cond 3). Keeps the newest
    two index files (the current copy's stays usable if installing the new one fails)."""
    path = Path(path)
    target = index_path_for(_sha256(path))
    build_index(path, target)
    olds = sorted((p for p in index_dir().glob("index-*.sqlite") if p != target), key=lambda p: p.stat().st_mtime, reverse=True)
    for stale in olds[1:]:
        try:
            stale.unlink()
        except OSError:  # pragma: no cover - best effort
            pass
    return True


register_dataset(
    DATASET,
    BULK_URL,
    ttl=30 * DAY,
    description="ICIJ Offshore Leaks bulk CSV (entities, officers, intermediaries, relationships) imported into a local "
    "name index for icij_offshore (P221); addresses are never imported",
    licence="ODbL-1.0 (database) + CC-BY-SA (contents)",
    terms_class="open",
    attribution=ATTRIBUTION,
    provider="icij",
    source=SOURCE_BULK,
    validate=validate_and_index,
    min_bytes=20_000_000,
    expect="bytes",
    max_bytes=250_000_000,
    large=True,
)

# --------------------------------------------------------------------------------------
# reconcile API (fallback)
# --------------------------------------------------------------------------------------


def reconcile_body(name: str, limit: int = MAX_CANDIDATES) -> dict[str, Any]:
    """Cond 4: one entity-typed query, at most 5 candidates (the name only in the JSON body)."""
    q = re.sub(r"\s+", " ", text(name))
    if not q:
        raise ValueError("empty company name")
    if len(q) > MAX_QUERY_CHARS:
        raise ValueError("company name too long for reconcile")
    return {"queries": {"q0": {"query": q, "type": ENTITY_TYPE, "limit": max(1, min(int(limit), MAX_CANDIDATES))}}}


def node_type(types: Any) -> str | None:
    for t in as_list(types):
        tid = text(as_dict(t).get("id"))
        if tid.startswith(TYPE_BASE):
            return tid[len(TYPE_BASE):] or None
        label = text(as_dict(t).get("name")).lower()
        if label:
            return label.split()[0]
    return None


def parse_reconcile(body: Any, qid: str = "q0") -> list[dict[str, Any]]:
    """Reconcile answer -> candidates [{node_id, name, node_type, leak, leak_detail, icij_score, node_url}].
    Raises ValueError for an unexpected shape (could not verify)."""
    if not isinstance(body, dict):
        raise ValueError("ICIJ reconcile answer is not a JSON object")
    block = body.get(qid)
    if not isinstance(block, dict) or not isinstance(block.get("result"), list):
        raise ValueError(f"ICIJ reconcile answer without {qid}.result")
    out = []
    for r in block["result"]:
        if not isinstance(r, dict):
            continue
        nid, name = text(r.get("id")), text(r.get("name"))
        if not nid or not name:
            continue
        leak = leak_of(r.get("description"))
        out.append({"node_id": nid, "name": name, "node_type": node_type(r.get("types")), "leak": leak["leak"],
                    "leak_detail": leak["detail"], "icij_score": as_float(r.get("score")), "node_url": node_url(nid)})
    return out


def select_candidates(query: str, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Cond 1/3/4: Entity nodes whose name scores >= 0.90 with the P219 matcher (ICIJ's own 0-100 score is
    informative only), best first, at most 5."""
    q = nm.name_tokens(query, "entity")
    kept = []
    for c in candidates:
        if c.get("node_type") != "entity":
            continue
        score = nm.token_set_jw(q, nm.name_tokens(c.get("name") or "", "entity"))
        if score >= THRESHOLD:
            kept.append({**c, "score": round(score, 4), "matched_alias": c.get("name")})
    kept.sort(key=lambda c: (-c["score"], c.get("node_id") or ""))
    return kept[:MAX_CANDIDATES]


def _reconcile_ok(resp: Any) -> bool:
    """``cache_if``: only well-formed reconcile answers are cached (cond 8)."""
    try:
        parse_reconcile(json.loads(resp.content))
        return True
    except (ValueError, TypeError, UnicodeDecodeError, AttributeError):
        return False


# --------------------------------------------------------------------------------------
# shared run helpers
# --------------------------------------------------------------------------------------


def input_refusal(entity: Entity, ctx: Any) -> str | None:
    """Cond 1/5: None when the name may be searched, else the reason (SKIPPED not_applicable)."""
    if entity.type is not T.ORG:
        return "ICIJ Offshore Leaks is searched for company names only (person names over leaked data are people-search, rule 4)"
    if len(re.sub(r"\s+", "", text(entity.value))) < 3:
        return "company name too short to search"
    options = getattr(ctx, "options", None)
    unconfirmed = set(getattr(options, "unconfirmed_seeds", None) or ())
    if bool(getattr(ctx, "is_seed", False)) and int(getattr(ctx, "depth", 0) or 0) == 0 and entity.key not in unconfirmed:
        return None
    prov = tuple(getattr(ctx, "provenance", ()) or ())
    if len(prov) == 1 and len(prov[0]) >= 2 and str(prov[0][0]).startswith("cnpj:") and str(prov[0][1]) in ("legal_name", "partner_of"):
        return None
    return ("ICIJ Offshore Leaks runs only on analyst-typed company names and names resolved from a seed CNPJ (razao social, "
            "nome fantasia, PJ partners), never on other pivoted names (P221 cond 5)")


def local_index(ctx: Any) -> tuple[Path | None, Any, str]:
    """(index path or None, DatasetInfo or None, reason when unusable). Never downloads."""
    try:
        info = ctx.data.info(DATASET)
    except (ValueError, OSError) as exc:
        return None, None, f"ICIJ dataset unreadable ({exc}): {UPDATE_HINT}"
    if not getattr(info, "present", False):
        return None, info, f"ICIJ Offshore Leaks index not installed: {UPDATE_HINT}"
    path = index_path_for(getattr(info, "sha256", "") or "")
    if not path.is_file():
        return None, info, (f"ICIJ local index missing for the installed copy: {UPDATE_HINT} (or rebuild it with "
                            "python -m v3lum.modules.company_org.icij_offshore --rebuild-index)")
    return path, info, ""


def explicitly_selected(module_name: str, ctx: Any) -> bool:
    """-M <module> in a scan, or a single analyst run (``v3lum run``) outside a scan."""
    options = getattr(ctx, "options", None)
    if module_name in set(getattr(options, "include", ()) or ()):
        return True
    runtime = getattr(ctx, "runtime", None)
    return not bool(getattr(runtime, "in_scan", False))


def _finding(res: ModuleResult, match: dict[str, Any], query: str, source: str) -> None:
    title = "Possible match: appears in ICIJ Offshore Leaks - not evidence of wrongdoing"
    parts = [f"'{query}' possibly matches ICIJ node {match.get('node_id')} '{match.get('name')}' (score {match.get('score')})"]
    if match.get("leak"):
        parts.append(f"leak: {match['leak']}" + (f" - {match['leak_detail']}" if match.get("leak_detail") else ""))
    if match.get("jurisdiction"):
        parts.append(f"jurisdiction: {match['jurisdiction']}")
    for label, key in (("incorporated", "incorporation_date"), ("inactivated", "inactivation_date"), ("struck off", "struck_off_date")):
        if match.get(key):
            parts.append(f"{label} {match[key]}")
    if match.get("intermediaries"):
        parts.append("intermediary: " + ", ".join(match["intermediaries"][:3]))
    if source == "api":
        parts.append("jurisdiction, intermediary and dates: open the node page (the reconcile API returns no details)")
    description = "; ".join(parts) + f". {WORDING[0].upper()}{WORDING[1:]}. ICIJ disclaimer: {DISCLAIMER} {ATTRIBUTION}"
    res.finding(
        title,
        "info",
        description,
        confidence="possible",
        criterion="company-name match (P219 matcher, score >= 0.90) against ICIJ Offshore Leaks entities: homonyms are common; "
                  "presence in the leaks is not evidence of wrongdoing (P221 cond 6)",
        data={k: match.get(k) for k in ("node_id", "name", "matched_alias", "score", "leak", "leak_detail", "jurisdiction", "status",
                                        "incorporation_date", "inactivation_date", "struck_off_date", "intermediaries",
                                        "linked_officers", "related_entities", "node_url", "icij_score")}
        | {"source": source, "disclaimer": DISCLAIMER, "attribution": ATTRIBUTION},
        tags=["offshore_leaks", "name_only_match", "context_only"],
        references=[u for u in (match.get("node_url"),) if u],
        source=SOURCE_BULK if source == "local" else SOURCE_API,
        key=str(match.get("node_id") or ""),
    )
    if match.get("node_url"):
        res.link(f"ICIJ Offshore Leaks node {match.get('node_id')}", match["node_url"])


def _links_of(reader: oni.NameIndexReader, entity_id: str) -> dict[str, list[Any]]:
    """Cond 2: officers / intermediaries / related entities linked to ONE matched entity (display only)."""
    out: dict[str, list[Any]] = {"officers": [], "intermediaries": [], "related": []}
    try:
        rows = reader.conn.execute(
            "SELECT r.other_id, r.kind, r.link, r.start_date, r.end_date, n.name FROM rel r LEFT JOIN node n ON n.node_id = r.other_id "
            "WHERE r.entity_id = ? LIMIT 200", (entity_id,)).fetchall()
    except sqlite3.Error:
        return out
    for other, kind, link, start, end, name in rows:
        if kind in ("officer", "intermediary"):
            bucket = "officers" if kind == "officer" else "intermediaries"
            if len(out[bucket]) < LINK_CAP and name:
                out[bucket].append({"name": str(name), "role": link, "start_date": start, "end_date": end})
        elif len(out["related"]) < LINK_CAP:
            ent = reader.entry_by_id(str(other))
            out["related"].append({"node_id": str(other), "name": ent["name"] if ent else None, "relation": link or "related",
                                   "node_url": node_url(other)})
    return out


# --------------------------------------------------------------------------------------
# modules
# --------------------------------------------------------------------------------------


@register
class IcijOffshore(Module):
    name = "icij_offshore"
    title = "ICIJ Offshore Leaks (local index)"
    description = (
        "Matches an analyst-typed or CNPJ-resolved company name against the local index of the ICIJ Offshore Leaks bulk CSV "
        "(Panama, Paradise, Pandora Papers...): possible matches with leak, jurisdiction, intermediaries, dates and the node "
        "link; nothing leaves the machine."
    )
    category = "company_org"
    accepts = {T.ORG}
    produces = frozenset()
    tags = {"offline", "free"}
    reference = "https://offshoreleaks.icij.org/pages/database"
    notice = NOTICE
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # cond 3: local matching, no disclosure (allowed at TLP:RED)
    hosts = ()
    provider = ""
    sources = (SOURCE_BULK,)
    access_model = "offline"
    expected_latency = 0.5
    timeout = 60.0
    max_pivots = 0  # cond 2: nothing is pivoted
    default_enabled = False  # cond 5: opt-in (-M icij_offshore, --preset deep)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        refusal = input_refusal(entity, ctx)
        if refusal:
            return res.mark(Status.SKIPPED, refusal, reason_code="not_applicable")
        query = " ".join(text(entity.value).split())
        path, info, why = local_index(ctx)
        if path is None:
            res.attr("offshore_leaks_screening", {"state": "not_screened", "source": "local", "reason": why})
            return res.mark(Status.UNAVAILABLE, f"{why}; the online fallback is -M icij_offshore_api (sends the name to ICIJ)",
                            reason_code="dataset")
        try:
            ctx.data.fetch(DATASET, ttl=float(10 * 365 * DAY))  # citation only: a present copy is never refreshed here
        except (DatasetError, OSError, ValueError):
            pass
        try:
            with oni.NameIndexReader(path) as reader:
                meta = reader.meta()
                hits = reader.match(query, kind="entity", threshold=THRESHOLD, limit=MAX_CANDIDATES)
                matches = []
                for h in hits:
                    data = h["data"]
                    links = _links_of(reader, h["entry_id"])
                    intermediaries = [i["name"] for i in links["intermediaries"]] or ([data["service_provider"]] if data.get("service_provider") else [])
                    matches.append({
                        "node_id": h["entry_id"], "name": h["name"], "matched_alias": h["matched_alias"], "score": h["score"],
                        "leak": data.get("leak"), "leak_detail": data.get("leak_detail"),
                        "jurisdiction": data.get("jurisdiction_description") or data.get("jurisdiction"), "status": data.get("status"),
                        "incorporation_date": data.get("incorporation_date"), "inactivation_date": data.get("inactivation_date"),
                        "struck_off_date": data.get("struck_off_date"), "intermediaries": intermediaries,
                        "linked_officers": [{"name": o["name"], "role": o["role"], "start_date": o["start_date"], "end_date": o["end_date"]}
                                            for o in links["officers"]],
                        "related_entities": links["related"], "node_url": node_url(h["entry_id"]), "source": "local",
                    })
        except oni.NameIndexError as exc:
            return res.mark(Status.UNAVAILABLE, f"ICIJ local index unusable ({exc}): {UPDATE_HINT}", reason_code="dataset")
        except sqlite3.Error as exc:
            return res.mark(Status.ERROR, f"ICIJ local index read failed ({type(exc).__name__}): could not verify")
        generated = meta.get("generated_on") or None
        res.attr("data_attribution", [ATTRIBUTION])
        res.attr("offshore_leaks_screening", {"state": "matched" if matches else "no_match", "source": "local",
                                              "index_generated_on": generated, "threshold": THRESHOLD, "reason": ""})
        res.raw = {"query": query, "matches": matches, "index_generated_on": generated, "entries": meta.get("entries")}
        if not matches:
            return res.mark(Status.EMPTY, f"no ICIJ Offshore Leaks entity scored >= {THRESHOLD:.2f} for '{query}' "
                                          f"(local index generated {generated or 'unknown'})")
        res.attr("offshore_leaks_matches", matches)
        for m in matches:
            _finding(res, m, query, "local")
        return res


@register
class IcijOffshoreApi(Module):
    name = "icij_offshore_api"
    title = "ICIJ Offshore Leaks (reconcile API fallback)"
    description = (
        "Online fallback of icij_offshore when the local index is not installed: one entity-typed POST to the ICIJ "
        "reconciliation API, re-scored locally (>= 0.90, at most 5); only at TLP:CLEAR/GREEN or on explicit selection."
    )
    category = "company_org"
    accepts = {T.ORG}
    produces = frozenset()
    tags = {"free"}
    reference = "https://offshoreleaks.icij.org/docs/reconciliation"
    notice = NOTICE + " The fallback sends the company name to ICIJ: only at TLP:CLEAR/GREEN or with -M icij_offshore_api."
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # ICIJ receives the company name
    hosts = ("offshoreleaks.icij.org",)
    provider = "icij"
    sources = (SOURCE_API,)
    access_model = "free_noauth_limited"
    max_requests = 1  # cond 4: one POST per entity
    expected_latency = 1.0  # measured 0.29-0.38 s, paced at 2 s per request
    timeout = 30.0
    min_interval = 2.0
    cache_ttl = CACHE_TTL
    max_pivots = 0
    default_enabled = False

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        refusal = input_refusal(entity, ctx)
        if refusal:
            return res.mark(Status.SKIPPED, refusal, reason_code="not_applicable")
        path, _info, why = local_index(ctx)
        if path is not None:
            return res.mark(Status.SKIPPED, "the local ICIJ index is installed: icij_offshore answers without disclosure (P221 cond 3)",
                            reason_code="not_applicable")
        tlp = str(getattr(ctx, "tlp", "") or "").lower()
        if tlp not in API_TLPS and not explicitly_selected(self.name, ctx):
            res.attr("offshore_leaks_screening", {"state": "not_screened", "source": "api", "reason": why})
            return res.mark(Status.UNAVAILABLE, f"{why}; the online fallback runs only at TLP:CLEAR/GREEN or with -M icij_offshore_api "
                                                f"(P221 cond 4)", reason_code="dataset")
        query = " ".join(text(entity.value).split())
        try:
            body = reconcile_body(query)
        except ValueError as exc:
            return res.mark(Status.SKIPPED, f"{exc}: not sent", reason_code="not_applicable")
        data = ctx.http.post_json(RECONCILE_URL, json_body=body, ttl=CACHE_TTL, cache_if=_reconcile_ok, source=SOURCE_API)
        try:
            candidates = parse_reconcile(data)
        except ValueError as exc:
            raise HttpError(f"{exc}: could not verify", 200, RECONCILE_URL) from exc
        matches = select_candidates(query, candidates)
        res.attr("data_attribution", [ATTRIBUTION])
        res.attr("offshore_leaks_screening", {"state": "matched" if matches else "no_match", "source": "api", "index_generated_on": None,
                                              "threshold": THRESHOLD, "reason": ""})
        res.raw = {"query": query, "candidates": candidates[:MAX_CANDIDATES], "matches": matches}
        if not matches:
            return res.mark(Status.EMPTY, f"no ICIJ Offshore Leaks entity scored >= {THRESHOLD:.2f} for '{query}' (reconcile API; "
                                          f"{len(candidates)} weak candidate(s) re-scored)")
        out = [{**m, "source": "api"} for m in matches]
        res.attr("offshore_leaks_matches", out)
        for m in out:
            _finding(res, m, query, "api")
        return res


# --------------------------------------------------------------------------------------
# command line: rebuild the local index from the installed dataset copy
# --------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m v3lum.modules.company_org.icij_offshore",
                                     description="Rebuild the icij_offshore local index from the installed dataset copy (v3lum data update icij).")
    parser.add_argument("--rebuild-index", action="store_true", help="build the index for the installed icij dataset")
    args = parser.parse_args(argv)
    if not args.rebuild_index:
        parser.print_help()
        return 2
    from v3lum.core.datasets import DataStore

    store = DataStore(None)
    info = store.info(DATASET)
    if not info.present:
        print(f"icij dataset not installed: {UPDATE_HINT}", file=sys.stderr)
        return 1
    try:
        summary = build_index(store.path(DATASET), index_path_for(info.sha256))
    except IcijImportError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
