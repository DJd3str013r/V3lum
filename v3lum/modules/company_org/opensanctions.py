"""P222 OpenSanctions: licensed bulk data matched locally, or the licensed Screening API (batch p3-G10-1).

OpenSanctions data is CC BY-NC 4.0 (class ``noncommercial``); V3LUM uses only the business-licensed paths,
registered as class ``license`` in the seed provider ``opensanctions`` (sources ``bulk_licensed`` and
``screening_api``). The policy gate runs a ``license`` source only with an active licence_allow entry, so
without the company's OpenSanctions licence both modules are SKIPPED ``licence`` under the corporate
profile (cond 1, 2). Two modules because the paths have different disclosure classes:

* ``opensanctions`` (disclosure ``none``, source ``opensanctions.bulk_licensed``): the preferred path with
  a bulk data licence (cond 3). The licensed ``targets.simple.csv`` is imported into a local SQLite index
  (:func:`import_targets`; command ``python -m v3lum.modules.company_org.opensanctions import FILE``), which
  refuses to run without an active licence_allow entry for ``opensanctions.bulk_licensed`` - V3LUM never
  downloads the bulk files itself (the dataset manager has no licence gate yet: core request), so they are
  never fetched without the licence. Matching is local with the P219 matcher (score >= 0.90, at most 5).
  Phones, e-mails, addresses and birth dates are dropped at import.
* ``opensanctions_api`` (disclosure ``third_party``, source ``opensanctions.screening_api``): the /match API
  when only a Screening licence exists (cond 4): ``requires_keys=('opensanctions',)`` (401 without a key ->
  NEEDS_KEY), the key only in the ``Authorization: ApiKey`` header, values only in the POST body, a monthly
  query budget in config (setting ``opensanctions_api_monthly_budget``, unset -> SKIPPED ``config``) with a
  hard stop (QUOTA) and no automatic credit purchase. It steps aside when the licensed bulk index is installed.

Both (cond 5-8):

* default_enabled False: an explicit due-diligence run (``-M``, ``--preset deep``) on seed companies and
  persons and, with setting ``opensanctions_due_diligence_partners``, on QSA partners of a seed CNPJ; never
  automatically on every partner, on other pivots or on names extracted from text.
* Person names only for subjects the analyst typed with a recorded purpose (SKIPPED ``privacy`` otherwise).
  Results are 'possible match' with score, threshold, datasets and entity id; person confidence is lowered by
  the P252 homonym score (``sanctions_lists.person_homonym``); PEP hits are INFO context; a natural person
  never gets the 'sanctioned' label or tag without analyst confirmation.
* Crypto addresses are matched exactly after the P219 normalisation (``sanctions_data.normalize_wallet``).
  The opensanctions.org website stays a manual link (P231 pack ``company_org``).
* Rule 5: 401/403/429, timeouts, 5xx and error-in-200 bodies (a per-query status other than 200 inside
  ``responses``) are NEEDS_KEY / BLOCKED / RATE_LIMITED / QUOTA / ERROR, never EMPTY, and never cached.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sqlite3
import sys
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from v3lum import paths
from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import HttpError
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.company_org import namematch as nm
from v3lum.modules.company_org import offline_name_index as oni
from v3lum.modules.company_org import sanctions_data as sd
from v3lum.modules.company_org import sanctions_lists as p219
from v3lum.modules.company_org.registry_text import as_dict, as_float, as_int, as_list, text

SOURCE_BULK = "opensanctions.bulk_licensed"
SOURCE_API = "opensanctions.screening_api"
MATCH_URL = "https://api.opensanctions.org/match/default"
ENTITY_URL = "https://www.opensanctions.org/entities/{id}/"
API_THRESHOLD = 0.70  # yente's default for match=true; recorded per finding (calibrate with the licence)
LOCAL_THRESHOLD = nm.NAME_MATCH_THRESHOLD
MAX_CANDIDATES = nm.MAX_CANDIDATES
API_CACHE_TTL = 12 * 3600  # data republished about four times a day
SETTING_DD_PARTNERS = "opensanctions_due_diligence_partners"
SETTING_BUDGET = "opensanctions_api_monthly_budget"
IMPORT_HINT = "python -m v3lum.modules.company_org.opensanctions import <targets.simple.csv> (licensed bulk data only)"
ATTRIBUTION = "OpenSanctions (opensanctions.org), CC BY-NC 4.0 data used under the company's OpenSanctions commercial licence"
WALLET_TYPES = frozenset({T.BTC, T.ETH, T.XMR, T.CRYPTO})
CSV_REQUIRED = ("id", "schema", "name", "aliases", "identifiers", "dataset")
NOTICE = (
    "OpenSanctions data is CC BY-NC 4.0: only the company's licensed paths are used (bulk data licence or Screening API "
    "licence recorded in licence_allow); otherwise skipped under the corporate profile (licence). Matches are possible "
    "matches to confirm, never a sanctions determination; person names only for due-diligence subjects with a purpose."
)

# --------------------------------------------------------------------------------------
# subjects (cond 5, 6)
# --------------------------------------------------------------------------------------


def _typed_seed(entity: Entity, ctx: Any) -> bool:
    options = getattr(ctx, "options", None)
    unconfirmed = set(getattr(options, "unconfirmed_seeds", None) or ())
    return bool(getattr(ctx, "is_seed", False)) and int(getattr(ctx, "depth", 0) or 0) == 0 and entity.key not in unconfirmed


def subject_refusal(entity: Entity, ctx: Any, *, local: bool) -> tuple[str, str] | None:
    """None when the entity may be screened, else (reason_code, reason) for SKIPPED."""
    seed = _typed_seed(entity, ctx)
    prov = tuple(getattr(ctx, "provenance", ()) or ())
    hop = prov[0] if len(prov) == 1 and len(prov[0]) >= 2 and str(prov[0][0]).startswith("cnpj:") else None
    relation = str(hop[1]) if hop else ""
    purpose = str(getattr(ctx, "purpose", "") or "").strip()
    partners = bool(ctx.setting(SETTING_DD_PARTNERS, False))
    if entity.type is T.PERSON:
        if seed:
            return None if purpose else ("privacy", "person-name screening needs a due-diligence case with a recorded purpose (--purpose)")
        if relation == "partner_of":
            if not partners:
                return ("privacy", f"QSA partners are screened only with the due-diligence option ({SETTING_DD_PARTNERS})")
            return None if purpose else ("privacy", "QSA partner screening needs a recorded purpose (--purpose)")
        return ("privacy", "person names are screened only for due-diligence subjects typed by the analyst, never names from pivots or text")
    if entity.type in WALLET_TYPES:
        return None if (seed or local) else ("not_applicable", "wallets reach the Screening API only as analyst-typed seeds")
    if seed or relation == "legal_name" or (relation == "partner_of" and partners and entity.type is T.ORG):
        return None
    return ("not_applicable", "OpenSanctions screens seed companies and, with the due-diligence option, QSA partners of a seed CNPJ - "
                              "never names from other pivots or text (P222 cond 5)")


def listing_of(topics: Any = (), *, sanctioned: bool | None = None, datasets: Any = ()) -> str:
    """'sanction' | 'pep' | 'other' from API topics or from the bulk sanctions/dataset columns."""
    tops = {text(t) for t in as_list(list(topics) if not isinstance(topics, list) else topics)}
    if sanctioned or "sanction" in tops:
        return "sanction"
    if any(t.startswith("role.pep") or t == "role.rca" for t in tops):
        return "pep"
    if any(re.search(r"\bPEP\b|politically exposed", text(d), re.I) for d in as_list(list(datasets))):
        return "pep"
    return "other"


# --------------------------------------------------------------------------------------
# results (shared by both paths)
# --------------------------------------------------------------------------------------


def _emit(res: ModuleResult, ctx: Any, entity: Entity, hits: list[dict[str, Any]], *, path: str, threshold: float) -> None:
    source = SOURCE_BULK if path == "bulk" else SOURCE_API
    person = entity.type is T.PERSON
    homonym = p219.person_homonym(ctx, str(entity.value)) if person else None
    if homonym:
        res.attr("homonym_risk", {k: homonym.get(k) for k in ("risk", "factor", "phrase", "first_name_tier", "common_surname")})
    for h in hits:
        exact = h.get("match_type") == "exact_wallet"
        natural_person = h.get("schema") == "Person" or person
        listing = h.get("listing") or "other"
        if exact:
            title = "OpenSanctions exact wallet match"
            severity, confidence = ("high", "confirmed") if listing == "sanction" else ("medium", "confirmed")
            tags = ["sanctions"] if listing == "sanction" else ["context_only"]
            criterion = "exact normalised wallet address (P219 normalisation) listed by OpenSanctions"
        else:
            verdict = p219.name_verdict(float(h.get("score") or 0.0), person=natural_person, homonym=homonym)
            confidence = verdict["confidence"]
            tags = ["name_only_match"]
            if listing == "pep":
                title, severity = "OpenSanctions possible match - politically exposed person (context)", "info"
                tags = ["pep", "name_only_match", "context_only"]
            elif listing == "sanction":
                severity = verdict["severity"]  # medium, INFO on a very common person name
                if natural_person:  # cond 6: no 'sanctioned' label or tag on a natural person without analyst confirmation
                    title = "OpenSanctions possible match on a listed natural person - confirm identity (not a sanctions determination)"
                else:
                    title = "OpenSanctions possible match - confirm identity"
                    tags.insert(0, "sanctions")
                if severity == "info":
                    tags.append("context_only")
            else:
                title, severity = "OpenSanctions possible match - other watchlist (context)", "info"
                tags.append("context_only")
            method = "P219 matcher on the licensed bulk data" if path == "bulk" else "OpenSanctions logic-v1"
            criterion = (f"name match score {h.get('score')} >= threshold {threshold} ({method}) - a candidate to confirm with a second "
                         "identifier, never a sanctions determination")
        res.finding(
            title,
            severity,
            f"{h.get('caption')} ({h.get('schema')}) - OpenSanctions entity {h.get('entity_id')}, listing: {listing}, datasets: "
            f"{', '.join((h.get('datasets') or [])[:6]) or 'n/a'}; score {h.get('score')} (threshold {threshold}). {ATTRIBUTION}.",
            confidence=confidence,
            criterion=criterion,
            data={k: h.get(k) for k in ("entity_id", "caption", "schema", "score", "datasets", "listing", "countries", "url", "match_type")}
            | {"threshold": threshold, "path": path, "homonym": homonym},
            tags=tags,
            references=[u for u in (h.get("url"),) if u],
            source=source,
            key=str(h.get("entity_id") or ""),
        )


def _screening(state: str, *, path: str, version: str | None = None, threshold: float, reason: str = "") -> dict[str, Any]:
    return {"state": state, "path": path, "version": version, "threshold": threshold, "reason": reason}


# --------------------------------------------------------------------------------------
# licensed bulk data: import (outside scans) and local index
# --------------------------------------------------------------------------------------


def index_path() -> Path:
    return paths.private_dir(paths.datasets_dir() / "opensanctions") / "targets.sqlite"


def parse_index(doc: Any) -> dict[str, Any] | None:
    """The dataset index.json -> {version, updated_at, target_count, resources {name: {url, size, sha1}}} or None."""
    if not isinstance(doc, dict) or not isinstance(doc.get("resources"), list):
        return None
    resources = {}
    for r in doc["resources"]:
        r = as_dict(r)
        name, url = text(r.get("name")), text(r.get("url"))
        if name and url.startswith("https://data.opensanctions.org/"):
            resources[name] = {"url": url, "size": as_int(r.get("size")), "sha1": text(r.get("checksum")) or None}
    return {"version": text(doc.get("version")) or None, "updated_at": text(doc.get("updated_at")) or None,
            "target_count": as_int(doc.get("target_count")), "resources": resources}


def _semis(value: Any) -> list[str]:
    return [x.strip() for x in text(value).split(";") if x.strip()]


_KIND = {"Person": "person", "Vessel": "vessel", "Airplane": "aircraft"}


def target_records(rows: Iterator[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """targets.simple.csv rows -> index records. Phones, e-mails, addresses and birth dates are dropped."""
    for r in rows:
        tid, schema, name = text(r.get("id")), text(r.get("schema")), text(r.get("name"))
        if not tid or not name:
            continue
        datasets = _semis(r.get("dataset"))[:10]
        wallets = []
        if schema == "CryptoWallet":
            for cand in [name, *_semis(r.get("identifiers"))]:
                norm = sd.normalize_wallet(cand)
                if norm.get("valid_shape"):
                    wallets.append(norm["normalized"])
        yield {
            "id": tid,
            "kind": _KIND.get(schema, "entity"),
            "names": [] if schema == "CryptoWallet" else [(name, "primary"), *((a, "alias") for a in _semis(r.get("aliases")))],
            "wallets": sorted(set(wallets)),
            "data": {"schema": schema, "caption": name[:200], "countries": _semis(r.get("countries"))[:10], "datasets": datasets,
                     "program_ids": _semis(r.get("program_ids"))[:10],
                     "listing": listing_of(sanctioned=bool(text(r.get("sanctions"))), datasets=datasets),
                     "first_seen": text(r.get("first_seen")) or None, "last_seen": text(r.get("last_seen")) or None},
        }


class OpenSanctionsImportError(Exception):
    """The licensed bulk file cannot be imported (no licence, changed header, bad checksum)."""


def _sha(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def licence_active(now: Any = None, state: Any = None) -> bool:
    """Is there an active licence_allow entry for the licensed bulk source? (cond 2/3)."""
    if state is None:
        from v3lum.core.licence import LicenceState

        state = LicenceState.load()
    try:
        return bool(state.active(SOURCE_BULK, now))
    except Exception:  # noqa: BLE001 - an unreadable allow-list never grants a licence
        return False


def import_targets(csv_path: str | Path, out: str | Path | None = None, *, index_doc: Any = None, licence_state: Any = None,
                   now: Any = None) -> dict[str, Any]:
    """Import the licensed ``targets.simple.csv`` into the local index (never during a scan). Refuses without
    an active licence_allow entry for ``opensanctions.bulk_licensed``; checks the SHA-1 of index.json when given."""
    if not licence_active(now, licence_state):
        raise OpenSanctionsImportError(f"no active licence_allow entry for {SOURCE_BULK}: the bulk data (CC BY-NC 4.0) is imported only "
                                       "under the company's OpenSanctions bulk data licence (P222 cond 2/3)")
    src = Path(csv_path)
    meta = {"source": "opensanctions", "file_sha256": _sha(src, "sha256"),
            "imported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    info = parse_index(index_doc) if index_doc is not None else None
    if info is not None:
        expected = as_dict(info["resources"].get("targets.simple.csv")).get("sha1")
        if expected and expected.lower() != _sha(src, "sha1"):
            raise OpenSanctionsImportError("targets.simple.csv does not match the SHA-1 of index.json")
        meta.update({"version": info.get("version") or "", "updated_at": info.get("updated_at") or ""})
    writer = oni.NameIndexWriter(out or index_path(), meta=meta)
    wallets = 0
    try:
        csv.field_size_limit(max(csv.field_size_limit(), 1 << 24))
        with open(src, encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            missing = [c for c in CSV_REQUIRED if c not in (reader.fieldnames or [])]
            if missing:
                raise OpenSanctionsImportError(f"targets.simple.csv header changed (missing {', '.join(missing)})")
            for rec in target_records(reader):
                if rec["names"]:
                    rowid = writer.add(rec["id"], rec["kind"], rec["names"], rec["data"])
                else:
                    writer.conn.execute("INSERT INTO entry (entry_id, kind, name, data) VALUES (?, ?, ?, ?)",
                                        (rec["id"], "wallet", rec["data"]["caption"], json.dumps(rec["data"])))
                    rowid = int(writer.conn.execute("SELECT last_insert_rowid()").fetchone()[0])
                for w in rec["wallets"]:
                    if rowid:
                        writer.add_ident("wallet", w, rowid)
                        wallets += 1
        writer.meta["wallets"] = str(wallets)
        writer.finish()
    except BaseException:
        writer.abort()
        raise
    return {"entries": writer.entries, "aliases": writer.aliases, "wallets": wallets, "version": meta.get("version")}


def _local_hit(h: dict[str, Any], match_type: str) -> dict[str, Any]:
    data = h.get("data") or {}
    eid = h.get("entry_id")
    return {"entity_id": eid, "caption": data.get("caption") or h.get("name"), "schema": data.get("schema"), "score": h.get("score", 1.0),
            "datasets": data.get("datasets") or [], "listing": data.get("listing") or "other", "countries": data.get("countries") or [],
            "url": ENTITY_URL.format(id=quote(str(eid), safe="")), "match_type": match_type, "matched_alias": h.get("matched_alias")}


# --------------------------------------------------------------------------------------
# Screening API
# --------------------------------------------------------------------------------------


def match_request(entity: Entity, *, threshold: float = API_THRESHOLD, limit: int = MAX_CANDIDATES) -> tuple[str, dict[str, Any]]:
    """(url, json body): the value travels only in the POST body (cond 4, 7)."""
    value = text(entity.value)
    if not value:
        raise ValueError("empty value")
    if entity.type in WALLET_TYPES:
        schema, props = "CryptoWallet", {"publicKey": [sd.normalize_wallet(value)["normalized"]]}
    else:
        schema = {T.PERSON: "Person", T.ORG: "Company"}.get(entity.type, "LegalEntity")
        props = {"name": [value]}
    params = urlencode({"algorithm": "logic-v1", "threshold": f"{float(threshold):.2f}", "limit": str(max(1, min(int(limit), MAX_CANDIDATES)))})
    return f"{MATCH_URL}?{params}", {"queries": {"q0": {"schema": schema, "properties": props}}}


_KEPT_PROPS = ("topics", "country", "nationality", "jurisdiction")


def parse_match(body: Any, qid: str = "q0") -> list[dict[str, Any]]:
    """yente /match answer -> results (personal properties never read). Raises ValueError for an
    unexpected shape or a failed query inside an HTTP 200 body (could not verify)."""
    if not isinstance(body, dict):
        raise ValueError("OpenSanctions answer is not a JSON object")
    resp = as_dict(as_dict(body.get("responses")).get(qid))
    if not resp:
        raise ValueError(f"OpenSanctions answer without responses.{qid}")
    status = as_int(resp.get("status"))
    if status is not None and status != 200:
        raise ValueError(f"OpenSanctions query {qid} failed inside the answer (status {status})")
    if not isinstance(resp.get("results"), list):
        raise ValueError("OpenSanctions answer without a results list")
    out = []
    for r in resp["results"]:
        if not isinstance(r, dict) or not text(r.get("id")):
            continue
        props = as_dict(r.get("properties"))
        kept = {k: [text(x) for x in as_list(props.get(k)) if text(x)] for k in _KEPT_PROPS}
        datasets = [text(d) for d in as_list(r.get("datasets")) if text(d)][:10]
        out.append({"entity_id": text(r.get("id")), "caption": text(r.get("caption")) or None, "schema": text(r.get("schema")) or None,
                    "score": as_float(r.get("score")), "match": r.get("match") is True, "datasets": datasets,
                    "listing": listing_of(kept["topics"], datasets=datasets),
                    "countries": sorted(set(kept["country"] + kept["nationality"] + kept["jurisdiction"]))[:10],
                    "url": ENTITY_URL.format(id=quote(text(r.get("id")), safe="")), "match_type": "exact_wallet" if text(r.get("schema")) == "CryptoWallet" else "name"})
    return out


def _match_ok(resp: Any) -> bool:
    try:
        parse_match(json.loads(resp.content))
        return True
    except (ValueError, TypeError, UnicodeDecodeError, AttributeError):
        return False


# --------------------------------------------------------------------------------------
# modules
# --------------------------------------------------------------------------------------


@register
class OpenSanctions(Module):
    name = "opensanctions"
    title = "OpenSanctions (licensed bulk data, local)"
    description = (
        "Screens seed companies, due-diligence persons and wallets against the licensed OpenSanctions targets imported locally "
        "(P219 matcher, score >= 0.90, at most 5; wallets exact). Needs the company's bulk data licence; nothing leaves the machine."
    )
    category = "company_org"
    accepts = {T.ORG, T.PERSON, T.KEYWORD} | WALLET_TYPES
    produces = frozenset()
    tags = {"offline"}
    reference = "https://www.opensanctions.org/licensing/"
    notice = NOTICE
    terms = "license"  # cond 1: the business-licensed path only
    opsec = Opsec.PASSIVE
    disclosure = "none"  # cond 3: local matching
    hosts = ()
    provider = ""
    sources = (SOURCE_BULK,)
    access_model = "offline"
    expected_latency = 0.5
    timeout = 60.0
    max_pivots = 0
    default_enabled = False  # cond 5
    settings = {
        SETTING_DD_PARTNERS: SettingSpec(
            False, "opensanctions / opensanctions_api: also screen QSA partners pivoted from an analyst-typed CNPJ under due diligence "
                   "(persons need a recorded purpose; P222 cond 5)"),
    }

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        refusal = subject_refusal(entity, ctx, local=True)
        if refusal:
            return res.mark(Status.SKIPPED, refusal[1], reason_code=refusal[0])
        path = index_path()
        if not path.is_file():
            why = f"licensed OpenSanctions bulk data not imported: {IMPORT_HINT}"
            res.attr("opensanctions_screening", _screening("not_screened", path="bulk", threshold=LOCAL_THRESHOLD, reason=why))
            return res.mark(Status.UNAVAILABLE, why, reason_code="dataset")
        try:
            with oni.NameIndexReader(path) as reader:
                meta = reader.meta()
                if entity.type in WALLET_TYPES:
                    norm = sd.normalize_wallet(entity.value)["normalized"]
                    hits = [_local_hit({**e, "score": 1.0}, "exact_wallet") for e in reader.by_ident("wallet", norm)]
                else:
                    kind = "person" if entity.type is T.PERSON else "entity"
                    hits = [_local_hit(h, "name") for h in reader.match(str(entity.value), kind=kind, threshold=LOCAL_THRESHOLD, limit=MAX_CANDIDATES)]
        except oni.NameIndexError as exc:
            return res.mark(Status.UNAVAILABLE, f"OpenSanctions local index unusable ({exc}): {IMPORT_HINT}", reason_code="dataset")
        except sqlite3.Error as exc:
            return res.mark(Status.ERROR, f"OpenSanctions local index read failed ({type(exc).__name__}): could not verify")
        version = meta.get("version") or meta.get("imported_at")
        res.attr("data_attribution", [ATTRIBUTION])
        res.attr("opensanctions_screening", _screening("matched" if hits else "no_match", path="bulk", version=version, threshold=LOCAL_THRESHOLD))
        res.raw = {"hits": hits, "version": version}
        if not hits:
            return res.mark(Status.EMPTY, f"no OpenSanctions target scored >= {LOCAL_THRESHOLD:.2f} (licensed bulk data, version {version or 'unknown'})")
        res.attr("opensanctions_matches", hits)
        _emit(res, ctx, entity, hits, path="bulk", threshold=LOCAL_THRESHOLD)
        return res


@register
class OpenSanctionsApi(Module):
    name = "opensanctions_api"
    title = "OpenSanctions Screening API (licensed)"
    description = (
        "One /match query per due-diligence subject to the OpenSanctions API under the company's Screening licence (key in the "
        "Authorization header, monthly budget with a hard stop); possible matches with score, threshold, datasets and entity id."
    )
    category = "company_org"
    accepts = {T.ORG, T.PERSON, T.KEYWORD} | WALLET_TYPES
    produces = frozenset()
    tags = frozenset()
    reference = "https://www.opensanctions.org/docs/api/"
    notice = NOTICE + " Each query spends a credit of the company's plan: setting opensanctions_api_monthly_budget is a hard stop."
    terms = "license"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # OpenSanctions receives the name or wallet
    hosts = ("api.opensanctions.org",)
    provider = "opensanctions"
    sources = (SOURCE_API,)
    access_model = "commercial_only"
    requires_keys = ("opensanctions",)  # cond 4
    max_requests = 1
    expected_latency = 1.0
    timeout = 30.0
    min_interval = 1.0
    cache_ttl = API_CACHE_TTL
    max_pivots = 0
    default_enabled = False
    error_markers = (
        {"id": "opensanctions_api_quota", "statuses": [402, 403, 429], "json_path": "detail", "equals": None,
         "regex": "(?i)quota|credit|budget|limit exceeded|payment", "final_url_regex": None, "maps_to": "quota", "reason_code": "quota",
         "reason": "OpenSanctions: plan quota or credits exhausted - hard stop, no automatic credit purchase"},
    )
    settings = {
        SETTING_BUDGET: SettingSpec(0, "opensanctions_api: monthly /match query budget of the company's Screening licence (hard stop; 0 = not "
                                       "configured: the module does not run)"),
    }

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        refusal = subject_refusal(entity, ctx, local=False)
        if refusal:
            return res.mark(Status.SKIPPED, refusal[1], reason_code=refusal[0])
        if index_path().is_file():
            return res.mark(Status.SKIPPED, "the licensed bulk data is imported: opensanctions answers locally (preferred path, P222 cond 3)",
                            reason_code="not_applicable")
        if not ctx.has_key("opensanctions"):
            return res.mark(Status.NEEDS_KEY, "OpenSanctions API key not configured (v3lum keys set opensanctions; the company's Screening licence)",
                            reason_code="needs_key")
        budget = as_int(ctx.setting(SETTING_BUDGET, 0)) or 0
        if budget <= 0:
            return res.mark(Status.SKIPPED, f"needs a monthly query budget: v3lum config set {SETTING_BUDGET} <queries of the licensed plan>",
                            reason_code="config")
        month = ctx.now().strftime("%Y-%m")
        usage = as_dict(ctx.state.get("usage", {}))
        used = (as_int(usage.get("used")) or 0) if usage.get("month") == month else 0
        if used >= budget:
            res.attr("opensanctions_screening", _screening("not_screened", path="api", threshold=API_THRESHOLD,
                                                           reason=f"monthly budget of {budget} queries reached"))
            return res.mark(Status.QUOTA, f"OpenSanctions monthly budget of {budget} queries reached: hard stop (no automatic credit purchase)",
                            reason_code="quota")
        try:
            url, body = match_request(entity)
        except ValueError as exc:
            return res.mark(Status.SKIPPED, f"{exc}: not sent", reason_code="not_applicable")
        ctx.state.set("usage", {"month": month, "used": used + 1})
        data = ctx.http.post_json(url, json_body=body, headers={"Authorization": f"ApiKey {ctx.key('opensanctions')}"},
                                  ttl=API_CACHE_TTL, cache_if=_match_ok, source=SOURCE_API)
        try:
            results = parse_match(data)
        except ValueError as exc:
            raise HttpError(f"{exc}: could not verify", 200, MATCH_URL) from exc
        hits = [h for h in results if (h.get("score") or 0.0) >= API_THRESHOLD][:MAX_CANDIDATES]
        res.attr("data_attribution", [ATTRIBUTION])
        res.attr("opensanctions_screening", _screening("matched" if hits else "no_match", path="api", threshold=API_THRESHOLD))
        res.raw = {"hits": hits, "budget": {"month": month, "used": used + 1, "limit": budget}}
        if not hits:
            return res.mark(Status.EMPTY, f"no OpenSanctions candidate scored >= {API_THRESHOLD:.2f} (Screening API)")
        res.attr("opensanctions_matches", hits)
        _emit(res, ctx, entity, hits, path="api", threshold=API_THRESHOLD)
        return res


# --------------------------------------------------------------------------------------
# command line: import the licensed bulk file
# --------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m v3lum.modules.company_org.opensanctions",
                                     description="Import the licensed OpenSanctions targets.simple.csv into the local index (bulk data licence only).")
    sub = parser.add_subparsers(dest="cmd")
    imp = sub.add_parser("import", help="import targets.simple.csv")
    imp.add_argument("csv", help="path of the licensed targets.simple.csv")
    imp.add_argument("--index", help="path of the matching index.json (records the version and checks the SHA-1)")
    args = parser.parse_args(argv)
    if args.cmd != "import":
        parser.print_help()
        return 2
    try:
        doc = json.loads(Path(args.index).read_text(encoding="utf-8")) if args.index else None
        summary = import_targets(args.csv, index_doc=doc)
    except (OpenSanctionsImportError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
