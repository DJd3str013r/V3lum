"""Offline sanctions screening against OFAC SDN, the UN consolidated list and EU FSF (P219).

* sources (cond 1, 2): OFAC SDN exports of the Sanctions List Service (US government work, public
  domain), the UN Security Council consolidated XML (UN public information) and the EU Financial
  Sanctions Files CSV (EU open data, reuse with attribution); providers ofac_sls, unsc_sanctions and
  eu_fsf, all trusted. OpenSanctions (CC BY-NC) is not used here (it belongs to P222).
* datasets (cond 3): only through the dataset manager (`v3lum data update sanctions`; TTL 24 h for
  OFAC and UN, 3 days for EU FSF), each validated (format and minimum rows) before it replaces the
  previous copy; registered ``large`` so a scan never downloads them; the MANIFEST keeps fetched_at
  and sha256, and the source date (UN dateGenerated, EU fileGenerationDate) is read from the file.
* coverage (cond 4): matching is local (disclosure 'none', allowed at TLP:RED). A missing list gives
  UNAVAILABLE 'dataset' ('run v3lum data update sanctions'); a list fetched more than 7 days ago is
  reported 'could not screen against <list> (dated <date>)'; neither case ever reads 'no match'.
* parsing (cond 5): UN XML through the safe XML helper; EU FSF ';' + BOM; OFAC 'Digital Currency
  Address' remarks indexed per chain (remarks completed from SDN_COMMENTS.CSV).
* matching (cond 6-9): the shared matcher (``namematch``); exact normalised wallets and CNPJs (OFAC
  Brazilian Tax IDs) give CRITICAL 'sanctioned' findings, CONFIRMED, with programme, SDN uid and list
  date - 'sanctioned' is used only for exact identifier matches; names scoring >= 0.90 give 'possible
  match - confirm identity', POSSIBLE (<= 0.6), at most MEDIUM (HIGH only with a second identifier),
  never CRITICAL; person hits are lowered by the homonym score and very common names stay INFO; at
  most 5 candidates per list with list, programme, listing date, matched alias and score.
* legal floor (cond 10): person names are screened only for subjects the analyst typed with a
  recorded purpose (a due-diligence case), or QSA partners of a CNPJ under that due diligence when the
  setting sanctions_lists_due_diligence_partners is on; never names from pivots or free text
  (SKIPPED 'privacy'); a natural person never gets a 'sanctioned' verdict.
* threat actors (cond 11): resolved through the P295 alias index (``v3lum/data/aliases``) and matched
  against the listed organisation names: an exact alias match shows '<lists> designated (<date>) -
  payments may be prohibited, escalate to legal'. Company names and wallets from any source are screened.
* history (cond 12): only matched entries are kept in the result (A10); the UN/EU attribution lines
  and each list's date are attributes. The dataset manager replaces a copy in place, so the module
  keeps a compact snapshot of the previous version in ctx.state (digests of exact identifiers and of
  organisation names, never a natural person's name): wallets, CNPJs and organisation names that left
  the list read 'formerly listed (<date>)' (core request: keep the previous copy in the dataset manager).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core.datasets import DatasetError, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, HealthResult, Module, register
from v3lum.modules.company_org import namematch as nm
from v3lum.modules.company_org import sanctions_data as sd

try:  # the P252 homonym score (batch p1-G10-2, backed by the IBGE ranking dataset) when installed
    from v3lum.modules.person_name import ibge_name_frequency as _p252
except ImportError:  # pragma: no cover - the interim mirror in namematch keeps cond 9
    _p252 = None

# --------------------------------------------------------------------------------------
# datasets (cond 3): `v3lum data update sanctions`, never during a scan
# --------------------------------------------------------------------------------------

OFAC_EXPORTS = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/"
UN_URL = "https://scsanctions.un.org/resources/xml/en/consolidated.xml"
#: The Commission's public token for the FSF file URLs (base64 of 'token-2017'), a published constant
#: (cond 1: a configuration value; templated dataset URLs from settings are a core request).
EU_FSF_PUBLIC_TOKEN = "dG9rZW4tMjAxNw"
EU_URL = f"https://webgate.ec.europa.eu/fsd/fsf/public/files/csvFullSanctionsList_1_1/content?token={EU_FSF_PUBLIC_TOKEN}"

DS_OFAC_SDN = "sanctions_ofac_sdn"
DS_OFAC_COMMENTS = "sanctions_ofac_sdn_comments"
DS_OFAC_ALT = "sanctions_ofac_alt"
DS_OFAC_ADD = "sanctions_ofac_add"
DS_UN = "sanctions_un_consolidated"
DS_EU = "sanctions_eu_fsf"
SRC_OFAC = "ofac_sls.sdn"
SRC_UN = "unsc_sanctions.consolidated"
SRC_EU = "eu_fsf.fsf_csv"
SANCTIONS_DATASETS = (DS_OFAC_SDN, DS_OFAC_COMMENTS, DS_OFAC_ALT, DS_OFAC_ADD, DS_UN, DS_EU)
UPDATE_HINT = "run v3lum data update sanctions"
#: Until the CLI selects dataset groups, the explicit names work today.
UPDATE_NAMES = "v3lum data update " + " ".join(SANCTIONS_DATASETS)
#: cond 4: a list fetched more than this many days ago cannot support 'no match'.
STALE_LIST_DAYS = 7
DAY = 86400


def _validator(parse: Any, check: Any) -> Any:
    def validate(path: Path) -> bool:
        reason = check(parse(Path(path).read_bytes()))
        if reason:
            raise ValueError(reason)
        return True

    return validate


def _validate_eu(path: Path) -> bool:
    reason = sd.validate_eu_fsf(sd.parse_eu_fsf_csv(Path(path)))
    if reason:
        raise ValueError(reason)
    return True


_OFAC_LICENCE = "U.S. Government work (public domain)"
_UN_LICENCE = "UN public information (United Nations Security Council Consolidated List)"
_EU_LICENCE = "European Commission reuse notice (Commission Decision 2011/833/EU; reuse with attribution)"
for _name, _file, _min, _max, _check in (
    (DS_OFAC_SDN, "SDN.CSV", 1_000_000, 64 * 1024 * 1024, sd.validate_ofac_sdn),
    (DS_OFAC_COMMENTS, "SDN_COMMENTS.CSV", 1_000, 16 * 1024 * 1024,
     lambda p: sd.validate_ofac_side(p, what="SDN_COMMENTS.CSV", min_rows=5)),
    (DS_OFAC_ALT, "ALT.CSV", 100_000, 32 * 1024 * 1024, lambda p: sd.validate_ofac_side(p, what="ALT.CSV", min_rows=sd.OFAC_ALT_MIN_ROWS)),
    (DS_OFAC_ADD, "ADD.CSV", 100_000, 32 * 1024 * 1024, lambda p: sd.validate_ofac_side(p, what="ADD.CSV", min_rows=sd.OFAC_ADD_MIN_ROWS)),
):
    _parse = {DS_OFAC_SDN: sd.parse_ofac_sdn_csv, DS_OFAC_COMMENTS: sd.parse_ofac_comments_csv, DS_OFAC_ALT: sd.parse_ofac_alt_csv,
              DS_OFAC_ADD: sd.parse_ofac_add_csv}[_name]
    register_dataset(
        _name, OFAC_EXPORTS + _file, ttl=DAY, description=f"OFAC SDN list export {_file} (Sanctions List Service) for sanctions_lists (P219)",
        licence=_OFAC_LICENCE, terms_class="open", attribution=sd.ATTRIBUTION[sd.OFAC_LIST], provider="ofac_sls", source=SRC_OFAC,
        validate=_validator(_parse, _check), min_bytes=_min, expect="csv", max_bytes=_max, large=True, essential=True,
    )
register_dataset(
    DS_UN, UN_URL, ttl=DAY, description="UN Security Council Consolidated List (XML) for sanctions_lists (P219)", licence=_UN_LICENCE,
    terms_class="open", attribution=sd.ATTRIBUTION[sd.UN_LIST], provider="unsc_sanctions", source=SRC_UN,
    validate=_validator(sd.parse_un_consolidated, sd.validate_un), min_bytes=200_000, expect="text", max_bytes=sd.UN_XML_MAX_BYTES,
    large=True, essential=True,
)
register_dataset(
    DS_EU, EU_URL, ttl=3 * DAY, description="EU Financial Sanctions Files, full CSV 1.1 (';' + BOM) for sanctions_lists (P219)",
    licence=_EU_LICENCE, terms_class="open", attribution=sd.ATTRIBUTION[sd.EU_LIST], provider="eu_fsf", source=SRC_EU, validate=_validate_eu,
    min_bytes=1_000_000, expect="csv", max_bytes=200 * 1024 * 1024, large=True, essential=True,
)

#: A present local copy is read with this TTL: the module never refreshes a list itself (cond 3).
_NEVER_REFRESH = float(10 * 365 * DAY)


# --------------------------------------------------------------------------------------
# loaded lists (parsed once per list version, cond 6)
# --------------------------------------------------------------------------------------


@dataclass
class LoadedList:
    """One parsed list version: compact entries, the name blocking index and the exact identifiers."""

    key: str
    label: str
    source: str
    entries: dict[Any, dict[str, Any]]
    name_index: dict[str, Any]
    ids: dict[str, dict[str, list[dict[str, Any]]]] = field(default_factory=dict)
    source_date: str | None = None
    notes: list[str] = field(default_factory=list)


class ListLoadError(Exception):
    """The local copy of a list could not be read or parsed."""


LIST_SPECS: dict[str, dict[str, Any]] = {
    "ofac": {"label": sd.OFAC_LIST, "source": SRC_OFAC, "datasets": (DS_OFAC_SDN, DS_OFAC_COMMENTS, DS_OFAC_ALT, DS_OFAC_ADD)},
    "un": {"label": sd.UN_LIST, "source": SRC_UN, "datasets": (DS_UN,)},
    "eu": {"label": sd.EU_LIST, "source": SRC_EU, "datasets": (DS_EU,)},
}
_MEMO: dict[str, tuple[tuple[Any, ...], LoadedList]] = {}
_LOCKS = {key: threading.Lock() for key in LIST_SPECS}


def _stamp(path: Path) -> tuple[str, int, int, int]:
    st = Path(path).stat()
    return (str(path), st.st_ino, st.st_size, st.st_mtime_ns)


def _records(entries: dict[Any, dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for uid, e in entries.items():
        if e.get("name"):
            out.append({"entry_id": uid, "name": e["name"], "kind": e["kind"], "alias_type": "primary"})
        for alias in e.get("aliases") or ():
            out.append({"entry_id": uid, "name": alias["name"], "kind": e["kind"], "alias_type": alias.get("type") or "alias"})
    return out


def build_ofac(sdn_raw: bytes, comments_raw: bytes | None = None, alt_raw: bytes | None = None, add_raw: bytes | None = None) -> LoadedList:
    """Parse the OFAC exports into a LoadedList (remarks completed, wallets/identifiers indexed)."""
    sdn = sd.parse_ofac_sdn_csv(sdn_raw)
    if not sdn.get("ok"):
        raise ListLoadError(sdn.get("error") or "SDN.CSV unreadable")
    notes: list[str] = []
    comments: dict[int, str] = {}
    if comments_raw is not None:
        parsed = sd.parse_ofac_comments_csv(comments_raw)
        if parsed.get("ok"):
            comments = parsed["comments"]
        else:
            notes.append(f"SDN_COMMENTS.CSV unreadable ({parsed.get('error')})")
    cut = sum(1 for e in sdn["entries"] if e.get("remarks_truncated"))
    if comments_raw is None and cut:
        notes.append(f"SDN_COMMENTS.CSV not downloaded: identifiers after the 1000-character cut of {cut} remarks are not indexed")
    alt = sd.parse_ofac_alt_csv(alt_raw) if alt_raw is not None else {"ok": False, "aliases": {}}
    add = sd.parse_ofac_add_csv(add_raw) if add_raw is not None else {"ok": False, "addresses": {}}
    if alt_raw is None:
        notes.append("ALT.CSV not downloaded: OFAC aliases come from the remarks only")
    entries: dict[Any, dict[str, Any]] = {}
    ids: dict[str, dict[str, list[dict[str, Any]]]] = {"wallet": {}, "cnpj": {}, "imo": {}, "registration": {}, "lei": {}}
    for e in sd.merge_ofac_remarks(sdn["entries"], comments):
        facts = sd.parse_ofac_remarks(e.get("remarks"), truncated=bool(e.get("remarks_truncated")))
        uid = e["uid"]
        aliases = [{"name": a["name"], "type": a["type"]} for a in facts["aliases"]]
        aliases += [{"name": a["name"], "type": a["type"]} for a in (alt.get("aliases") or {}).get(uid, [])]
        countries = sorted({a["country"] for a in (add.get("addresses") or {}).get(uid, []) if a.get("country")})
        entries[uid] = {
            "list": sd.OFAC_LIST, "uid": uid, "name": e["name"], "kind": e["kind"], "programs": e["programs"], "aliases": aliases,
            "dob": facts["dob"], "nationality": facts["nationality"] + facts["citizen"], "countries": countries,
            "listing_date": facts["listing_dates"][0]["date"] if facts["listing_dates"] else None,
        }
        base = {"uid": uid}
        for w in facts["wallets"]:
            if w.get("normalized"):
                ids["wallet"].setdefault(w["normalized"], []).append({**base, "chain": w["chain"], "valid_shape": w.get("valid_shape")})
        for value in facts["cnpjs"]:
            ids["cnpj"].setdefault(value, []).append(dict(base))
        for value in facts["imo"]:
            ids["imo"].setdefault(value, []).append(dict(base))
        for value in facts["lei"]:
            ids["lei"].setdefault(value.upper(), []).append(dict(base))
        for reg in facts["registrations"]:
            k = re.sub(r"[^0-9A-Za-z]", "", reg["number"]).upper()
            if k:
                ids["registration"].setdefault(k, []).append({**base, "scheme": reg["scheme"], "country": reg["country"]})
    return LoadedList("ofac", sd.OFAC_LIST, SRC_OFAC, entries, nm.build_name_index(_records(entries)), ids, None, notes)


def build_un(raw: bytes) -> LoadedList:
    parsed = sd.parse_un_consolidated(raw)
    if not parsed.get("ok"):
        raise ListLoadError(parsed.get("error") or "UN list unreadable")
    entries: dict[Any, dict[str, Any]] = {}
    for e in parsed["entries"]:
        aliases = [{"name": a["name"].strip().strip('"').strip(), "type": "low" if (a.get("quality") or "").lower() == "low" else "aka"}
                   for a in e.get("aliases") or () if a.get("name")]
        entries[e["uid"]] = {
            "list": sd.UN_LIST, "uid": e["uid"], "name": e["name"], "kind": e["kind"], "programs": e["programs"], "aliases": aliases,
            "dob": e.get("dates_of_birth") or [], "nationality": e.get("nationalities") or [], "countries": e.get("countries") or [],
            "listing_date": e.get("listed_on"), "reference": (e.get("reference_number") or "").strip() or None,
        }
    date = (parsed.get("date_generated") or "")[:10] or None
    return LoadedList("un", sd.UN_LIST, SRC_UN, entries, nm.build_name_index(_records(entries)), {}, date, [])


def build_eu(source: Any) -> LoadedList:
    parsed = sd.parse_eu_fsf_csv(source)
    if not parsed.get("ok"):
        raise ListLoadError(parsed.get("error") or "EU FSF unreadable")
    entries: dict[Any, dict[str, Any]] = {}
    for e in parsed["entries"]:
        entries[e["uid"]] = {
            "list": sd.EU_LIST, "uid": e["uid"], "name": e.get("name"), "kind": e["kind"], "programs": e["programs"],
            "aliases": [{"name": a["name"], "type": "aka"} for a in e.get("aliases") or () if a.get("name")],
            "dob": e.get("birth_dates") or [], "nationality": e.get("citizenships") or [], "countries": e.get("countries") or [],
            "listing_date": e.get("designation_date") or e.get("publication_date"), "reference": e.get("eu_reference"),
        }
    notes = ["EU FSF CSV ends with an incomplete row"] if parsed.get("truncated") else []
    return LoadedList("eu", sd.EU_LIST, SRC_EU, entries, nm.build_name_index(_records(entries)), {}, parsed.get("file_generation_date"), notes)


def _build(key: str, paths: dict[str, Path]) -> LoadedList:
    if key == "ofac":
        def read(name: str) -> bytes | None:
            return Path(paths[name]).read_bytes() if name in paths else None

        return build_ofac(read(DS_OFAC_SDN) or b"", read(DS_OFAC_COMMENTS), read(DS_OFAC_ALT), read(DS_OFAC_ADD))
    if key == "un":
        return build_un(Path(paths[DS_UN]).read_bytes())
    return build_eu(Path(paths[DS_EU]))


def load_list(ctx: Any, key: str) -> tuple[LoadedList | None, dict[str, Any]]:
    """(LoadedList or None, screening state {state, file_date, reason, fetched_at, stale}) of one list.
    Never downloads: a missing primary dataset gives state not_screened with the update hint."""
    spec = LIST_SPECS[key]
    label = spec["label"]
    primary = spec["datasets"][0]
    missing = {"state": "not_screened", "file_date": None, "reason": f"{label} list not downloaded: {UPDATE_HINT}", "fetched_at": None, "stale": True}
    try:
        info = ctx.data.info(primary)
    except (ValueError, OSError):
        return None, missing
    if not info.present:
        return None, missing
    paths: dict[str, Path] = {}
    try:
        for name in spec["datasets"]:
            if name == primary or ctx.data.info(name).present:
                paths[name] = ctx.data.fetch(name, ttl=_NEVER_REFRESH)
    except (DatasetError, OSError, ValueError) as exc:
        return None, {**missing, "reason": f"{label} local copy unavailable ({str(exc)[:120]}): {UPDATE_HINT}"}
    stamp = tuple(sorted((name, _stamp(p)) for name, p in paths.items()))
    with _LOCKS[key]:
        hit = _MEMO.get(key)
        if hit and hit[0] == stamp:
            lst = hit[1]
        else:
            try:
                lst = _build(key, paths)
            except (ListLoadError, OSError, ValueError, RecursionError) as exc:
                return None, {**missing, "reason": f"{label} local copy unreadable ({str(exc)[:120]}): {UPDATE_HINT}"}
            _MEMO[key] = (stamp, lst)
    fetched = sd.as_date(info.fetched_at)
    file_date = lst.source_date or (fetched.isoformat() if fetched else None)
    today = ctx.now().date()
    stale = fetched is None or (today - fetched).days > STALE_LIST_DAYS
    state = {"state": "no_record", "file_date": file_date, "reason": "", "fetched_at": info.fetched_at or None, "stale": stale,
             "version": str(info.sha256 or "")[:16] or "|".join(str(v) for v in _stamp(paths[primary])[1:])}
    if stale:
        state["reason"] = f"could not screen against {label} (dated {file_date or 'unknown'})"
        state["state"] = "not_screened"
    return lst, state


# --------------------------------------------------------------------------------------
# delisting history (cond 12): a compact snapshot of the previous list version in ctx.state
# --------------------------------------------------------------------------------------
#
# The dataset manager replaces a list copy in place (no previous version is kept: core request), so
# the module keeps, per list, a compact snapshot of the last version it screened against in its
# ctx.state: digests of the normalised primary names of non-individual entries (organisations,
# vessels, aircraft) and of the exact identifiers (wallets, CNPJs), plus name/programmes of the
# entries those identifiers belong to (never the name of a natural person). When a newer version is
# first used, everything that disappeared becomes a delisting record and later matches read
# 'formerly listed (<date of the last list that carried it>)'. Digests are base32 (digits 2-7 only),
# so no stored value can look like a CPF. Matching history: exact identifiers and exact normalised
# organisation names (aliases and person names are not kept).

HISTORY_ID_KINDS = ("wallet", "cnpj")
#: at most this many delisting records per list and kind (the oldest removals are dropped first)
HISTORY_MAX_RECORDS = 3000
_HISTORY_LOCK = threading.Lock()
#: (state file, list key) -> (version synced, delisting records); avoids re-reading the state per run
_HISTORY_MEMO: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}


def history_digest(value: Any) -> str | None:
    """Short base32 digest of an identifier or normalised name (12 characters, 60 bits)."""
    text = str(value or "")
    if not text:
        return None
    return base64.b32encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")[:12].lower()


def name_digest(name: Any) -> str | None:
    """Digest of the normalised organisation form of ``name`` (legal suffixes removed)."""
    return history_digest(nm.normalized_name(name, "entity"))


def wallet_digest(address: Any) -> str | None:
    return history_digest(sd.normalize_wallet(address).get("normalized"))


def list_snapshot(lst: LoadedList) -> dict[str, Any]:
    """The compact history snapshot of one list version (no natural-person name is ever kept)."""
    names: dict[str, Any] = {}
    for uid, e in lst.entries.items():
        if e.get("kind") == "individual" or not e.get("name"):
            continue
        digest = name_digest(e["name"])
        if digest:
            names.setdefault(digest, uid)
    ids: dict[str, dict[str, Any]] = {}
    for kind in HISTORY_ID_KINDS:
        for value, refs in (lst.ids.get(kind) or {}).items():
            digest = history_digest(value)
            if digest and refs:
                ids.setdefault(kind, {}).setdefault(digest, refs[0]["uid"])
    meta: dict[str, Any] = {}
    for uid in {u for values in ids.values() for u in values.values()}:
        e = lst.entries.get(uid) or {}
        meta[str(uid)] = {"name": None if e.get("kind") == "individual" else e.get("name"), "kind": e.get("kind"),
                          "programmes": list(e.get("programs") or [])}
    return {"names": names, "ids": ids, "meta": meta}


def _cap(records: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    if len(records) <= HISTORY_MAX_RECORDS:
        return records
    ranked = sorted(records.items(), key=lambda kv: str(kv[1].get("removed_by") or ""), reverse=True)[:HISTORY_MAX_RECORDS]
    return dict(ranked)


def delisting_diff(previous: dict[str, Any], current: dict[str, Any], current_uids: set[str], records: dict[str, Any],
                   removed_by: str | None) -> dict[str, Any]:
    """Fold the entries of ``previous`` missing from ``current`` into the delisting ``records``
    ({names: {digest: rec}, ids: {kind: {digest: rec}}}); re-listed values leave the history."""
    last_listed = previous.get("date")
    names = dict(records.get("names") or {})
    ids = {k: dict(v) for k, v in (records.get("ids") or {}).items() if isinstance(v, dict)}
    for digest, uid in (previous.get("names") or {}).items():
        if str(uid) not in current_uids and digest not in (current.get("names") or {}):
            names[digest] = {"uid": uid, "last_listed": last_listed, "removed_by": removed_by}
    meta = previous.get("meta") or {}
    for kind, values in (previous.get("ids") or {}).items():
        if not isinstance(values, dict):
            continue
        now = (current.get("ids") or {}).get(kind) or {}
        for digest, uid in values.items():
            if digest not in now:
                m = meta.get(str(uid)) or {}
                ids.setdefault(kind, {})[digest] = {"uid": uid, "name": m.get("name"), "kind": m.get("kind"),
                                                    "programmes": m.get("programmes") or [], "last_listed": last_listed, "removed_by": removed_by}
    for digest in [d for d in names if d in (current.get("names") or {})]:
        del names[digest]
    for kind, values in ids.items():
        now = (current.get("ids") or {}).get(kind) or {}
        for digest in [d for d in values if d in now]:
            del values[digest]
    return {"names": _cap(names), "ids": {k: _cap(v) for k, v in ids.items() if v}}


def sync_history(ctx: Any, lst: LoadedList, state: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    """(delisting records of this list, note) after folding in a list version change. Never raises:
    a state that cannot be written keeps the records computed in memory for this process and the
    note says the history was not saved."""
    store = getattr(ctx, "state", None)
    version = str(state.get("version") or "")
    if store is None or not version:
        return {}, None
    try:
        memo_key = (str(store.path), lst.key)
    except Exception:  # noqa: BLE001 - a state without a file: no history
        return {}, None
    with _HISTORY_LOCK:
        hit = _HISTORY_MEMO.get(memo_key)
        if hit and hit[0] == version:
            return hit[1], None
        note = None
        records: dict[str, Any] = {}
        try:
            previous = store.get(f"snapshot_{lst.key}")
            stored = store.get(f"delisted_{lst.key}")
            records = stored if isinstance(stored, dict) else {}
            if not isinstance(previous, dict) or previous.get("v") != version:
                current = list_snapshot(lst)
                if isinstance(previous, dict) and previous.get("v"):
                    records = delisting_diff(previous, current, {str(u) for u in lst.entries}, records, state.get("file_date"))
                    store.set(f"delisted_{lst.key}", records)
                store.set(f"snapshot_{lst.key}", {"v": version, "date": state.get("file_date"), **current})
        except Exception as exc:  # noqa: BLE001 - StateError (size cap, refused value) or an unreadable file
            note = f"{lst.label} delisting history not saved ({str(exc)[:120]})"
        _HISTORY_MEMO[memo_key] = (version, records)
        return records, note


def formerly_listed(records: dict[str, Any], kind: str, digest: str | None) -> dict[str, Any] | None:
    if not digest or not records:
        return None
    pool = records.get("names") if kind == "name" else (records.get("ids") or {}).get(kind)
    rec = (pool or {}).get(digest)
    return rec if isinstance(rec, dict) else None


# --------------------------------------------------------------------------------------
# legal floor for person names (cond 10)
# --------------------------------------------------------------------------------------

SETTING_DD_PARTNERS = "sanctions_lists_due_diligence_partners"
QSA_RELATIONS = frozenset({"partner", "partner_of"})


def person_screening_refusal(ctx: Any, entity: Entity) -> str | None:
    """None when this person name may be screened, else the privacy reason (SKIPPED 'privacy').

    Allowed: a subject the analyst typed (a confirmed seed) in a case with a recorded purpose, or a QSA
    partner pivoted directly from an analyst-typed CNPJ when the due-diligence option (setting
    sanctions_lists_due_diligence_partners) is on and a purpose is recorded. Never names from other
    pivots or free text."""
    purpose = str(getattr(ctx, "purpose", "") or "").strip()
    options = getattr(ctx, "options", None)
    unconfirmed = set(getattr(options, "unconfirmed_seeds", None) or ())
    if bool(getattr(ctx, "is_seed", False)) and entity.key not in unconfirmed:
        if purpose:
            return None
        return "person-name screening needs a due-diligence case with a recorded purpose (--purpose): name not screened"
    prov = tuple(getattr(ctx, "provenance", ()) or ())
    if len(prov) == 1 and len(prov[0]) >= 2:
        parent_key, relation = str(prov[0][0]), str(prov[0][1])
        if relation in QSA_RELATIONS and parent_key.startswith("cnpj:"):
            if not ctx.setting(SETTING_DD_PARTNERS, False):
                return f"QSA partners are screened only with the due-diligence option ({SETTING_DD_PARTNERS}): name not screened"
            if not purpose:
                return "QSA partner screening needs a recorded purpose (--purpose): name not screened"
            return None
    return "person names are screened only for due-diligence subjects typed by the analyst, never names from pivots or free text"


# --------------------------------------------------------------------------------------
# threat actors (cond 11): the P295 alias index (v3lum/data/aliases, kind threat_actor)
# --------------------------------------------------------------------------------------

_ALIAS_MEMO: dict[str, Any] = {}
_ALIAS_LOCK = threading.Lock()
MAX_ACTOR_NAMES = 20


def _fold(text: Any) -> str:
    return " ".join(nm.strip_accents(text).casefold().split())


def _actor_alias_map(ctx: Any) -> dict[str, list[str]]:
    """canonical (folded) -> [names]; folded alias -> canonical (folded), from the bundled fragments."""
    with _ALIAS_LOCK:
        if "map" in _ALIAS_MEMO:
            return _ALIAS_MEMO["map"]
    groups: dict[str, list[str]] = {}
    lookup: dict[str, str] = {}
    try:
        base = ctx.data.bundled_path("aliases")
        files = sorted(p for p in base.iterdir() if p.name.endswith(".json")) if base.is_dir() else []
    except (OSError, ValueError):
        files = []
    for path in files:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(doc, dict) or doc.get("kind") != "threat_actor" or not isinstance(doc.get("names"), dict):
            continue
        for alias, canonical in doc["names"].items():
            if not isinstance(alias, str) or not isinstance(canonical, str):
                continue
            key = _fold(canonical)
            groups.setdefault(key, [])
            for name in (canonical, alias):
                if name not in groups[key]:
                    groups[key].append(name)
            lookup.setdefault(_fold(alias), key)
            lookup.setdefault(key, key)
    result = {"groups": groups, "lookup": lookup}
    with _ALIAS_LOCK:
        _ALIAS_MEMO["map"] = result
    return result


def actor_names(ctx: Any, value: str) -> list[str]:
    """The actor name plus its canonical name and aliases from the P295 alias index (at most 20)."""
    names = [value]
    amap = _actor_alias_map(ctx)
    canonical = amap.get("lookup", {}).get(_fold(value))
    if canonical:
        for name in amap["groups"].get(canonical, []):
            if _fold(name) not in {_fold(n) for n in names}:
                names.append(name)
    return names[:MAX_ACTOR_NAMES]


# --------------------------------------------------------------------------------------
# verdicts
# --------------------------------------------------------------------------------------

#: Homonym risk level at which a person hit stays INFO (cond 9).
_HOMONYM_INFO = nm.COMMON_NAME_RISK


def person_homonym(ctx: Any, name: str) -> dict[str, Any]:
    """The homonym score of a person name (cond 9): the P252 helper with its offline IBGE table when
    available, else the interim mirror of the same curve (``namematch.homonym_risk``). Shape {risk,
    factor, phrase, first_name_tier, common_surname, scorer}."""
    if _p252 is not None:
        try:
            table = _p252.offline_table(ctx.data.store, used=ctx.data.used)
            h = _p252.homonym_risk(name, table=table)
            floor = nm.first_name_floor(name)
            if h.get("first_name_tier") == "unknown" and floor:
                h = _p252.homonym_risk(name, frequency=floor)  # IBGE table not downloaded: the embedded top 20
            return {**{k: h.get(k) for k in ("risk", "factor", "phrase", "first_name_tier", "common_surname")}, "scorer": "p252"}
        except Exception:  # noqa: BLE001 - a sibling helper failing must never break screening
            pass
    return {**nm.homonym_risk(name), "scorer": "namematch"}
#: cond 8: a name-only match is POSSIBLE (<= 0.6); 0.5 keeps the label POSSIBLE (the label table maps
#: >= 0.55 to PROBABLE) and matches the sibling P240 'confidence <= 0.5'.
NAME_ONLY_MAX_CONFIDENCE = 0.5


def name_verdict(score: float, *, person: bool, homonym: dict[str, Any] | None, second_identifiers: tuple[str, ...] = (),
                 low_quality_alias: bool = False) -> dict[str, Any]:
    """P219 cond 8/9: severity, confidence and title of a name match (never CRITICAL, never 'sanctioned')."""
    second = sorted(set(s for s in second_identifiers if s))
    confidence = min(NAME_ONLY_MAX_CONFIDENCE, round(float(score) * NAME_ONLY_MAX_CONFIDENCE, 4))
    severity = "medium"
    title = "possible match - confirm identity"
    if second:
        confidence = min(0.8, round(0.6 + 0.1 * len(second), 4))
        severity = "high"
        title = "probable match - confirm identity (" + ", ".join(second) + " also match)"
    if person and homonym:
        confidence = min(confidence, nm.homonym_curve(confidence, homonym))
        if homonym.get("risk") == _HOMONYM_INFO and not second:
            severity = "info"
            title = "possible match on a very common name - name-only matches are unreliable"
    if low_quality_alias and not second:
        severity = "info"
        title = "possible match on a low-quality alias - confirm identity"
    return {"severity": severity, "confidence": round(confidence, 4), "title": title, "second_identifiers": second}


def _candidate(lst: LoadedList, hit: dict[str, Any], list_date: str | None) -> dict[str, Any]:
    e = lst.entries.get(hit["entry_id"]) or {}
    return {
        "list": lst.label, "entry_id": hit["entry_id"], "listed_name": e.get("name"), "kind": e.get("kind"), "matched_alias": hit.get("matched_alias"),
        "alias_type": hit.get("alias_type"), "score": hit.get("score"), "match_type": "name", "programmes": e.get("programs") or [],
        "listing_date": e.get("listing_date"), "list_date": list_date, "reference": e.get("reference"),
        "countries": e.get("countries") or [], "nationality": e.get("nationality") or [],
    }


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------

_WALLET_TYPES = frozenset({T.BTC, T.ETH, T.XMR, T.CRYPTO})
_NAME_TYPES = frozenset({T.ORG, T.PERSON, T.THREAT_ACTOR})
_STATE_FIELDS = ("state", "file_date", "reason", "fetched_at", "stale")


def _selftest(ctx: Any) -> HealthResult:
    """doctor: every list present and fetched at most 7 days ago (cond 4)."""
    problems = []
    for spec in LIST_SPECS.values():
        try:
            info = ctx.data.info(spec["datasets"][0])
        except (ValueError, OSError) as exc:
            return HealthResult("dead", f"{spec['label']} dataset unreadable: {exc}")
        if not info.present:
            problems.append(f"{spec['label']} not downloaded")
        elif info.age_hours is None or info.age_hours > STALE_LIST_DAYS * 24:
            problems.append(f"{spec['label']} older than {STALE_LIST_DAYS} days")
    if problems:
        return HealthResult("dead", "; ".join(problems) + f": {UPDATE_HINT}")
    return HealthResult("ok", "OFAC SDN, UN and EU FSF lists present and fresh")


@register
class SanctionsLists(Module):
    name = "sanctions_lists"
    title = "Sanctions screening: OFAC SDN, UN, EU FSF (offline)"
    description = (
        "Local screening of wallets (exact), CNPJs (exact, OFAC Brazilian Tax IDs), company names, threat actors and purpose-gated "
        "person names against the OFAC SDN, UN consolidated and EU FSF lists downloaded by `v3lum data update sanctions`. Name hits "
        "are possible matches to confirm; nothing is sent anywhere."
    )
    category = "company_org"
    accepts = {T.ORG, T.PERSON, T.THREAT_ACTOR, T.BTC, T.ETH, T.XMR, T.CRYPTO, T.CNPJ}
    produces = frozenset()
    tags = {"offline", "free"}
    reference = "https://ofac.treasury.gov/sanctions-list-service"
    notice = (
        f"{sd.ATTRIBUTION[sd.UN_LIST]}; {sd.ATTRIBUTION[sd.EU_LIST]}; {sd.ATTRIBUTION[sd.OFAC_LIST]}. Name matches are possible matches "
        "to confirm with a second identifier, never a sanctions determination; person names are screened only for due-diligence "
        "subjects with a recorded purpose. A list match is not a legal determination: escalate to compliance/legal."
    )
    terms = "open"  # OFAC public domain, UN public information, EU reuse notice
    opsec = Opsec.PASSIVE
    disclosure = "none"  # local matching: nothing leaves the machine; allowed at TLP:RED
    hosts = ()
    provider = ""
    sources = (SRC_OFAC, SRC_UN, SRC_EU)
    access_model = "offline"
    expected_latency = 0.5
    timeout = 180.0  # the first run after an update parses the lists (EU FSF is 25 MB)
    max_pivots = 0
    default_enabled = True
    settings = {
        SETTING_DD_PARTNERS: SettingSpec(
            False,
            "sanctions_lists: also screen QSA partners pivoted from an analyst-typed CNPJ under due diligence (needs a recorded purpose; P219 cond 10)",
        ),
    }

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=True, selftest=_selftest)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        etype = entity.type
        if etype is T.PERSON:
            refusal = person_screening_refusal(ctx, entity)
            if refusal:
                return res.mark("skipped", refusal, reason_code="privacy")
        keys = ("ofac",) if etype in _WALLET_TYPES or etype is T.CNPJ else ("ofac", "un", "eu")
        loaded: dict[str, LoadedList] = {}
        states: dict[str, dict[str, Any]] = {}
        for key in keys:
            lst, state = load_list(ctx, key)
            states[key] = state
            if lst is not None:
                loaded[key] = lst
        if etype in _WALLET_TYPES or etype is T.CNPJ:
            for key, spec in LIST_SPECS.items():
                if key not in keys:
                    what = "wallet addresses" if etype in _WALLET_TYPES else "Brazilian Tax IDs (CNPJ)"
                    res.source_status(spec["source"], "skipped", reason_code="not_applicable", reason=f"{spec['label']} lists no {what}")
        if not loaded:
            reasons = "; ".join(s["reason"] for s in states.values())
            self._coverage(res, states)
            return res.mark("unavailable", f"{reasons} (until dataset groups land: {UPDATE_NAMES})", reason_code="dataset")
        if etype in _WALLET_TYPES:
            hits = self._wallet(res, entity, loaded, states)
        elif etype is T.CNPJ:
            hits = self._cnpj(res, entity, loaded, states)
        elif etype is T.THREAT_ACTOR:
            hits = self._actor(res, entity, ctx, loaded, states)
        else:
            hits = self._names(res, entity, ctx, loaded, states, person=etype is T.PERSON)
        notes = [n for lst in loaded.values() for n in lst.notes]
        history = self._history(res, entity, ctx, loaded, states, hits, notes)
        for key, lst in loaded.items():
            if any(h["list"] == lst.label for h in hits):
                state = states[key]
                state["state"] = "listed"
                state["reason"] = f"{lst.label} list dated {state['file_date'] or 'unknown'} is older than {STALE_LIST_DAYS} days" if state["stale"] else ""
        self._coverage(res, states)
        self._attribution(res, states)
        if hits:
            res.attr("sanctions_matches", hits)
        if history:
            res.attr("sanctions_history", history)
        res.raw = {"matches": hits, "history": history, "lists": {LIST_SPECS[k]["label"]: {f: s.get(f) for f in _STATE_FIELDS} for k, s in states.items()},
                   "notes": notes, "matcher": nm.accelerator_name()}
        fresh = [k for k, s in states.items() if k in loaded and not s["stale"]]
        if not hits and not fresh:
            # cond 4: stale or missing lists never read 'no match'
            reasons = "; ".join(s["reason"] for s in states.values() if s["reason"])
            return res.mark("unavailable", f"{reasons} ({UPDATE_HINT})", reason_code="dataset")
        return res

    # ------------------------------------------------------------------ coverage
    @staticmethod
    def _coverage(res: ModuleResult, states: dict[str, dict[str, Any]]) -> None:
        screening = {}
        for key, state in states.items():
            spec = LIST_SPECS[key]
            screening[spec["label"]] = {"state": state["state"], "file_date": state["file_date"], "reason": state["reason"]}
            if state["state"] == "not_screened" and state["reason"]:
                res.source_status(spec["source"], "unavailable", reason_code="dataset", reason=state["reason"])
            else:
                res.source_status(spec["source"], "ok")
        res.attr("sanctions_screening", screening)

    @staticmethod
    def _attribution(res: ModuleResult, states: dict[str, dict[str, Any]]) -> None:
        lines, ages = [], []
        for key, state in states.items():
            label = LIST_SPECS[key]["label"]
            if state.get("file_date"):
                lines.append(f"{sd.ATTRIBUTION[label]} - list dated {state['file_date']}")
                ages.append(f"{label}, fetched {str(state.get('fetched_at') or '')[:10] or 'unknown'}")
        res.attr("data_attribution", lines)
        res.attr("dataset_age", ages)

    # ------------------------------------------------------------------ delisting history (cond 12)
    def _history(self, res: ModuleResult, entity: Entity, ctx: Any, loaded: dict[str, LoadedList], states: dict[str, dict[str, Any]],
                 hits: list[dict[str, Any]], notes: list[str]) -> list[dict[str, Any]]:
        """'formerly listed (<date>)' for values a previous list version carried and the current one
        does not: exact identifiers (LOW, confirmed) and exact normalised organisation names (INFO,
        possible). Person names have no history (no natural-person name is ever kept)."""
        etype = entity.type
        if etype is T.PERSON:
            return []
        out: list[dict[str, Any]] = []
        for key, lst in loaded.items():
            records, note = sync_history(ctx, lst, states[key])
            if note:
                notes.append(note)
            if not records:
                continue
            listed_now = {h["entry_id"] for h in hits if h["list"] == lst.label}
            if etype in _WALLET_TYPES or etype is T.CNPJ:
                kind = "wallet" if etype in _WALLET_TYPES else "cnpj"
                digest = wallet_digest(entity.value) if kind == "wallet" else history_digest(entity.value)
                rec = formerly_listed(records, kind, digest)
                if rec and not listed_now:
                    out.append(self._formerly_identifier(res, entity, lst, kind, rec))
                continue
            queries = actor_names(ctx, entity.value) if etype is T.THREAT_ACTOR else [entity.value]
            for query in queries:
                rec = formerly_listed(records, "name", name_digest(query))
                if rec and rec.get("uid") not in listed_now:
                    out.append(self._formerly_name(res, entity, lst, query, rec))
                    break
        return out

    @staticmethod
    def _formerly_identifier(res: ModuleResult, entity: Entity, lst: LoadedList, kind: str, rec: dict[str, Any]) -> dict[str, Any]:
        label = {"wallet": "wallet", "cnpj": "CNPJ"}[kind]
        line = sd.formerly_listed_line(rec.get("last_listed"))
        owner = rec.get("name") or ("a listed individual" if rec.get("kind") == "individual" else "a listed party")
        programmes = ", ".join(rec.get("programmes") or []) or "n/a"
        item = {"list": lst.label, "match_type": f"formerly_{kind}", "entry_id": rec.get("uid"), "listed_name": rec.get("name"),
                "programmes": rec.get("programmes") or [], "last_listed": rec.get("last_listed"), "removed_by": rec.get("removed_by"), "line": line}
        res.finding(
            f"Formerly listed {label} on {lst.label} - not on the current list",
            "low",
            f"{line.capitalize()}: {entity.value} was listed for {owner} ({lst.label} uid {rec.get('uid')}, programme {programmes}) in the "
            f"list dated {rec.get('last_listed') or 'unknown'} and is absent from the list dated {rec.get('removed_by') or 'unknown'}. "
            "A delisting ends the designation from that date; dealings while it was listed may still need compliance review.",
            confidence="confirmed",
            criterion=f"exact normalised {label} present in the previous local {lst.label} version and absent from the current one",
            data=item,
            tags=["formerly_listed", "context_only"],
            source=lst.source,
            key=f"formerly:{rec.get('uid')}",
        )
        return item

    @staticmethod
    def _formerly_name(res: ModuleResult, entity: Entity, lst: LoadedList, query: str, rec: dict[str, Any]) -> dict[str, Any]:
        line = sd.formerly_listed_line(rec.get("last_listed"))
        item = {"list": lst.label, "match_type": "formerly_name", "entry_id": rec.get("uid"), "query": query, "last_listed": rec.get("last_listed"),
                "removed_by": rec.get("removed_by"), "line": line}
        res.finding(
            f"Name formerly listed on {lst.label} - not on the current list",
            "info",
            f"{line.capitalize()}: an organisation named like '{query}' (exact normalised name, {lst.label} uid {rec.get('uid')}) was on the "
            f"list dated {rec.get('last_listed') or 'unknown'} and is absent from the list dated {rec.get('removed_by') or 'unknown'}. "
            "Name only: confirm it is the same organisation before relying on it.",
            confidence=NAME_ONLY_MAX_CONFIDENCE,
            criterion=f"exact normalised organisation name present in the previous local {lst.label} version and absent from the current one",
            data=item,
            tags=["formerly_listed", "name_only_match", "context_only"],
            source=lst.source,
            key=f"formerly:{rec.get('uid')}",
        )
        return item

    # ------------------------------------------------------------------ exact identifiers (cond 7)
    def _exact(self, res: ModuleResult, entity: Entity, lst: LoadedList, kind: str, value: str, states: dict[str, dict[str, Any]],
               *, extra: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        hits = []
        list_date = states[lst.key]["file_date"]
        for ref in lst.ids.get(kind, {}).get(value, []):
            e = lst.entries.get(ref["uid"]) or {}
            programmes = ", ".join(e.get("programs") or []) or "n/a"
            label = {"wallet": "wallet", "cnpj": "CNPJ"}.get(kind, kind)
            hit = {"list": lst.label, "entry_id": ref["uid"], "listed_name": e.get("name"), "kind": e.get("kind"), "matched_alias": None,
                   "score": 1.0, "match_type": f"exact_{kind}", "programmes": e.get("programs") or [], "listing_date": e.get("listing_date"),
                   "list_date": list_date, **(extra or {}), **({"chain": ref.get("chain")} if ref.get("chain") else {})}
            hits.append(hit)
            stale = " (local list older than 7 days)" if states[lst.key]["stale"] else ""
            person_note = " The listed party is a natural person: the identifier match does not establish who controls it today." if e.get("kind") == "individual" else ""
            res.finding(
                f"Sanctioned {label}: exact match on {lst.label}",
                "critical",
                f"{entity.value} is listed for {e.get('name')} ({lst.label} uid {ref['uid']}, programme {programmes}, list dated "
                f"{list_date or 'unknown'}{stale}).{person_note} Stop transactions and escalate to compliance/legal.",
                confidence="confirmed",
                criterion=f"exact normalised {label} in the official {lst.label} list ({'Digital Currency Address' if kind == 'wallet' else 'Tax ID No.'} remark)",
                data=hit,
                tags=["sanctions"],
                references=["https://ofac.treasury.gov/sanctions-list-service"],
                source=lst.source,
                key=str(ref["uid"]),
            )
        return hits

    def _wallet(self, res: ModuleResult, entity: Entity, loaded: dict[str, LoadedList], states: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        lst = loaded.get("ofac")
        if lst is None:
            return []
        norm = sd.normalize_wallet(entity.value)
        hits = self._exact(res, entity, lst, "wallet", norm["normalized"], states)
        if hits:
            res.attr("sanctioned", True)
        return hits

    def _cnpj(self, res: ModuleResult, entity: Entity, loaded: dict[str, LoadedList], states: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        lst = loaded.get("ofac")
        if lst is None:
            return []
        hits = self._exact(res, entity, lst, "cnpj", entity.value, states)
        if hits:
            res.attr("sanctioned", True)
        return hits

    # ------------------------------------------------------------------ names (cond 8, 9)
    def _match(self, loaded: dict[str, LoadedList], names: list[str], kind: str, states: dict[str, dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        """Best candidates per list (at most 5) over every query name."""
        per_list: dict[str, list[dict[str, Any]]] = {}
        for key, lst in loaded.items():
            best: dict[Any, dict[str, Any]] = {}
            for name in names:
                for hit in nm.match_name(name, lst.name_index, kind=kind):
                    prev = best.get(hit["entry_id"])
                    if prev is None or hit["score"] > prev["score"]:
                        best[hit["entry_id"]] = {**hit, "query": name}
            ranked = sorted(best.values(), key=lambda h: (-h["score"], str(h["entry_id"])))[: nm.MAX_CANDIDATES]
            if ranked:
                per_list[key] = [{**_candidate(lst, h, states[key]["file_date"]), "query": h["query"]} for h in ranked]
        return per_list

    def _names(self, res: ModuleResult, entity: Entity, res_ctx: Any, loaded: dict[str, LoadedList], states: dict[str, dict[str, Any]], *,
               person: bool) -> list[dict[str, Any]]:
        kind = "person" if person else "entity"
        homonym = person_homonym(res_ctx, entity.value) if person else None
        if homonym is not None:
            res.attr("homonym_risk", {k: homonym[k] for k in ("risk", "factor", "phrase", "first_name_tier", "common_surname")})
        per_list = self._match(loaded, [entity.value], kind, states)
        hits: list[dict[str, Any]] = []
        for key, candidates in per_list.items():
            lst = loaded[key]
            hits.extend(candidates)
            best = candidates[0]
            verdict = name_verdict(best["score"], person=person, homonym=homonym, low_quality_alias=best.get("alias_type") == "low")
            stale = " The local list is older than 7 days." if states[key]["stale"] else ""
            subject = "person" if person else "organisation"
            desc = (f"{verdict['title'].capitalize()}: '{entity.value}' resembles '{best['listed_name']}' (alias '{best['matched_alias']}', "
                    f"score {best['score']:.2f}, programme {', '.join(best['programmes']) or 'n/a'}, listed {best['listing_date'] or 'date not published'}) "
                    f"on {lst.label} dated {states[key]['file_date'] or 'unknown'}; {len(candidates)} candidate(s).{stale} A name match alone is "
                    f"not a sanctions determination: confirm the identity with a second identifier (DOB, nationality, document, registration).")
            if person:
                desc += f" Homonym risk: {homonym['phrase']}."
            res.finding(
                f"Possible sanctions match on {lst.label} - confirm identity",
                verdict["severity"],
                desc,
                confidence=verdict["confidence"],
                criterion=f"{subject} name similarity >= {nm.NAME_MATCH_THRESHOLD:.2f} (token-set Jaro-Winkler on normalised names) against {lst.label}; "
                          "name only, no identifier matched",
                data={"match_type": "name", "subject_kind": subject, "list": lst.label, "candidates": candidates,
                      "homonym_risk": homonym, "homonym_applied": bool(person and homonym), "analyst_confirmation_required": person,
                      "verdict": verdict["title"]},
                tags=["sanctions", "name_only_match"] + (["context_only"] if verdict["severity"] == "info" else []),
                source=lst.source,
                key=key,
            )
        return hits

    def _actor(self, res: ModuleResult, entity: Entity, ctx: Any, loaded: dict[str, LoadedList], states: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        names = actor_names(ctx, entity.value)
        per_list = self._match(loaded, names, "entity", states)
        hits: list[dict[str, Any]] = []
        designations = []
        for key, candidates in per_list.items():
            lst = loaded[key]
            hits.extend(candidates)
            best = candidates[0]
            exact = nm.normalized_name(best["query"]) == nm.normalized_name(best["matched_alias"] or "")
            when = best.get("listing_date") or states[key]["file_date"]
            if exact:
                designations.append((lst.label.split(" ")[0], when))
            verdict = name_verdict(best["score"], person=False, homonym=None)
            res.finding(
                f"Possible sanctions designation of the threat actor on {lst.label}",
                verdict["severity"],
                (f"'{best['query']}' ({'alias of ' + entity.value if best['query'] != entity.value else 'the actor name'}) "
                 f"{'equals' if exact else 'resembles'} '{best['matched_alias']}' listed as '{best['listed_name']}' (programme "
                 f"{', '.join(best['programmes']) or 'n/a'}, listed {best['listing_date'] or 'date not published'}) on {lst.label} dated "
                 f"{states[key]['file_date'] or 'unknown'}. Alias equivalences are vendor assessments: confirm before acting; payments to a "
                 "designated party may be prohibited - escalate to legal."),
                confidence=verdict["confidence"],
                criterion=f"threat-actor name or P295 alias similarity >= {nm.NAME_MATCH_THRESHOLD:.2f} against the organisation names of {lst.label}; "
                          "name only, no identifier matched",
                data={"match_type": "name", "subject_kind": "threat_actor", "list": lst.label, "candidates": candidates, "exact_alias": exact,
                      "aliases_used": names},
                tags=["sanctions", "name_only_match"],
                source=lst.source,
                key=key,
            )
        line = sd.actor_designation_line(designations)
        if line:
            res.attr("sanctions_designation", line)
        return hits
