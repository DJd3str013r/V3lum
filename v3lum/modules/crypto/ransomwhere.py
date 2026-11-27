"""Ransomwhere ransomware payment addresses (P210): offline match of a BTC address against the export.

Final conditions (P210, council-1):

* cond 1 - offline module ``crypto/ransomwhere`` (disclosure none: the address never leaves the machine).
  ``https://api.ransomwhe.re/export`` is registered with the dataset manager as ``ransomwhere_export`` (live check
  2026-11-26: ~5.6 MB JSON, 11,186 BTC addresses, last update 2024-10-29), refreshed weekly by
  ``v3lum data update`` (above 5 MB: ``large=True``, never mid-scan - a missing copy is UNAVAILABLE 'dataset') and
  loaded into a dict at refresh: the validator parses the download once and the parsed index is kept for the
  installed file (keyed by size + mtime), so a scan only looks up a dict.
* cond 2 - a match gives the ransomware family and the payment amounts, with ``attributed_to`` threat-actor pivots
  (``expand=False``, one per alias: 'REvil / Sodinokibi' -> REvil, Sodinokibi; 'Unlabeled' gives none). Findings
  are labelled historical (dataset stale since 2024-10, crowdsourced and skewed to older families); a miss means
  nothing (EMPTY with that wording, never 'clean').
* cond 3 - the Ransomwhere Zenodo dataset is cited in THIRD_PARTY_NOTICES (``v3lum/data/notices/
  ransomwhere_dataset.json``, CC BY 4.0) and in every hit (``data_attribution``). The trimmed fixture is cut from
  the live export (8 rows, <= 3 transactions each).

Family strings have near-duplicates (AvosLocker / 'Avos Locker', LockBit / 'LockBit 2.0'...): they are reported as
given; alias folding belongs to actor_alias_index (P295).
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import threading
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from v3lum.core.datasets import DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, HealthResult, Module, register

SOURCE = "ransomwhere.export"
DATASET = "ransomwhere_export"
EXPORT_URL = "https://api.ransomwhe.re/export"
SITE = "https://ransomwhe.re/"
CITATION = ("Cable, Jack. (2024). Ransomwhere: A Crowdsourced Ransomware Payment Dataset (1.1.0) [Data set]. Zenodo. "
            "https://doi.org/10.5281/zenodo.6512122")
LICENCE = "CC-BY-4.0"
ATTRIBUTION = f"Ransomwhere (ransomwhe.re), CC BY 4.0 - {CITATION}"
MIN_ROWS = 1000
MAX_TX_KEPT = 5
WEEK = 7 * 86400
SATS_PER_BTC = Decimal(100_000_000)
HISTORICAL = ("historical: Ransomwhere is a crowdsourced dataset, stale since {date} and skewed to older ransomware "
              "families")
MISS = ("not in the Ransomwhere dataset (dataset last updated {date}); a miss means nothing: the data is crowdsourced, "
        "stale and incomplete")
TITLE = "Ransomware payment address (Ransomwhere, historical)"

_BASE58_RE = re.compile(r"^[13][1-9A-HJ-NP-Za-km-z]{25,34}$")
_BECH32_RE = re.compile(r"^bc1[02-9ac-hj-np-z]{11,71}$")
_TXID_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


# --------------------------------------------------------------------------------------
# parsing and index (pure)
# --------------------------------------------------------------------------------------


def normalize_btc(value: Any) -> str | None:
    """Matching key of a BTC address: bech32 (bc1...) lower case, base58 case-kept; None when not BTC-shaped.

    Format check only (the entity normalizer already validated the checksum of the investigated address)."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text[:3].lower() == "bc1":
        text = text.lower()
        return text if _BECH32_RE.match(text) else None
    return text if _BASE58_RE.match(text) else None


def _clean(value: Any, limit: int = 80) -> str | None:
    if not isinstance(value, str):
        return None
    text = re.sub(r"\s+", " ", _CONTROL_RE.sub("", value)).strip()
    return text[:limit] or None


def family_names(raw: Any) -> dict[str, Any]:
    """'REvil / Sodinokibi' -> names [REvil, Sodinokibi]; 'Netwalker (Mailto)' -> Netwalker + variant Mailto.

    'Unlabeled' rows (from 'Showing the Receipts' without a confident family) are labelled False: no names, so no
    attributed_to pivot (cond 2)."""
    text = _clean(raw) or ""
    if not text or text.lower() in ("unlabeled", "unlabelled", "unknown"):
        return {"raw": text or None, "labelled": False, "names": [], "variant": None}
    variant = None
    match = re.match(r"^(.*?)\s*\(([^)]*)\)\s*$", text)
    if match:
        text, variant = match.group(1).strip(), (match.group(2).strip() or None)
    names = [part.strip() for part in re.split(r"\s*/\s*", text) if part.strip()][:5]
    return {"raw": _clean(raw), "labelled": bool(names), "names": names, "variant": variant}


def _sats(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        number = Decimal(str(value))
    except InvalidOperation:
        return None
    if not number.is_finite() or number < 0:
        return None
    return int(number)


def _usd(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return round(float(value), 2) if value == value and value >= 0 else None


def btc(sats: int | None) -> str | None:
    """Satoshis -> '1.23456789' (8 decimals, exact)."""
    if not isinstance(sats, int) or sats < 0:
        return None
    return format((Decimal(sats) / SATS_PER_BTC).quantize(Decimal("0.00000001")), "f")


def _iso(epoch: Any) -> str | None:
    if isinstance(epoch, bool) or not isinstance(epoch, int) or not 0 < epoch < 32503680000:
        return None
    return _dt.datetime.fromtimestamp(epoch, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: Any) -> _dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=_dt.timezone.utc)


def validate_export(data: Any, min_rows: int | None = None) -> str | None:
    """None when the export is usable, else the reason (the previous copy is kept). ``min_rows`` defaults to
    :data:`MIN_ROWS` (read at call time)."""
    min_rows = MIN_ROWS if min_rows is None else min_rows
    if not isinstance(data, dict):
        return "ransomwhere export is not a JSON object (truncated, HTML or error page)"
    rows = data.get("result")
    if not isinstance(rows, list):
        message = _clean(data.get("message"))
        return "ransomwhere export has no result list" + (f" ({message})" if message else "")
    if len(rows) < min_rows:
        return f"ransomwhere export has {len(rows)} rows (< {min_rows})"
    good = sum(1 for r in rows if isinstance(r, dict) and normalize_btc(r.get("address")) and isinstance(r.get("family"), str))
    if good < 0.95 * len(rows):
        return f"only {good} of {len(rows)} rows have a BTC address and a family"
    return None


def build_index(data: Any) -> dict[str, Any]:
    """Export JSON -> {'index': {address: row}, 'rows', 'skipped', 'families', 'last_updated', 'last_payment'}.

    Rows keep family, balance (sats), createdAt, updatedAt and the transactions as (hash, epoch, sats, usd); exact
    duplicate transaction entries (same hash and amount, present in the 2024-10 export) are counted once."""
    rows = data.get("result") if isinstance(data, dict) else None
    out: dict[str, Any] = {"index": {}, "rows": 0, "skipped": 0, "families": 0, "last_updated": None, "last_payment": None}
    if not isinstance(rows, list):
        return out
    families: set[str] = set()
    last_updated: _dt.datetime | None = None
    last_tx = 0
    for row in rows:
        if not isinstance(row, dict):
            out["skipped"] += 1
            continue
        address = normalize_btc(row.get("address"))
        chain = row.get("blockchain") if isinstance(row.get("blockchain"), str) else "bitcoin"
        if not address or chain.lower() != "bitcoin":
            out["skipped"] += 1
            continue
        txs: list[tuple[str, int | None, int, float | None]] = []
        seen: set[tuple[str, int]] = set()
        for tx in row.get("transactions") if isinstance(row.get("transactions"), list) else []:
            if not isinstance(tx, dict):
                continue
            sats = _sats(tx.get("amount"))
            tx_hash = tx.get("hash") if isinstance(tx.get("hash"), str) and _TXID_RE.match(tx.get("hash")) else None
            if sats is None or tx_hash is None or (tx_hash, sats) in seen:
                continue
            seen.add((tx_hash, sats))
            when = tx.get("time") if isinstance(tx.get("time"), int) and not isinstance(tx.get("time"), bool) else None
            txs.append((tx_hash, when, sats, _usd(tx.get("amountUSD"))))
            if when:
                last_tx = max(last_tx, when)
        family = row.get("family") if isinstance(row.get("family"), str) else "Unlabeled"
        families.add(family)
        created = row.get("createdAt") if isinstance(row.get("createdAt"), str) else None
        updated = row.get("updatedAt") if isinstance(row.get("updatedAt"), str) else None
        for stamp in (created, updated):
            parsed = _parse_iso(stamp)
            if parsed and (last_updated is None or parsed > last_updated):
                last_updated = parsed
        previous = out["index"].get(address)
        if previous:  # duplicate rows: merge their transactions
            known = {(t[0], t[2]) for t in previous["transactions"]}
            previous["transactions"].extend(t for t in txs if (t[0], t[2]) not in known)
        else:
            out["index"][address] = {"family": family, "balance": _sats(row.get("balance")), "createdAt": created,
                                     "updatedAt": updated, "transactions": txs}
        out["rows"] += 1
    out["families"] = len(families)
    out["last_updated"] = last_updated.strftime("%Y-%m-%dT%H:%M:%SZ") if last_updated else None
    out["last_payment"] = _iso(last_tx) if last_tx else None
    return out


def lookup(index: dict[str, Any], address: str) -> dict[str, Any]:
    """Match one BTC address (cond 2): status found | empty | invalid, with the historical label and pivots."""
    date = (index.get("last_updated") or "")[:10] or "unknown"
    key = normalize_btc(address)
    if key is None:
        return {"status": "invalid", "reason": "not a BTC address"}
    row = (index.get("index") or {}).get(key)
    if row is None:
        return {"status": "empty", "address": key, "reason": MISS.format(date=date), "dataset_date": date}
    family = family_names(row.get("family"))
    txs = sorted(row.get("transactions") or [], key=lambda t: (t[1] or 0, t[0]), reverse=True)
    times = [t[1] for t in txs if t[1]]
    usd = [t[3] for t in txs if t[3] is not None]
    pivots = [{"value": name, "relation": "attributed_to", "expand": False, "confidence": "probable",
               "note": f"ransomware family per Ransomwhere (historical, crowdsourced; dataset last updated {date})"}
              for name in family["names"]]
    return {
        "status": "found", "address": key, "family": family["raw"], "family_names": family["names"],
        "family_variant": family["variant"], "labelled": family["labelled"],
        "tx_count": len(txs), "total_btc": btc(sum(t[2] for t in txs)),
        "total_usd": round(sum(usd), 2) if usd else None,
        "first_payment": _iso(min(times)) if times else None, "last_payment": _iso(max(times)) if times else None,
        "balance_btc": btc(row.get("balance")) if isinstance(row.get("balance"), int) else None,
        "reported_at": row.get("createdAt"), "updated_at": row.get("updatedAt"),
        "transactions": [{"hash": t[0], "time": _iso(t[1]), "btc": btc(t[2]), "usd": t[3]} for t in txs[:MAX_TX_KEPT]],
        "labels": ["historical", "crowdsourced"] + ([] if family["labelled"] else ["family_unknown"]),
        "label_text": HISTORICAL.format(date=date), "pivots": pivots, "dataset_date": date,
    }


# --------------------------------------------------------------------------------------
# dataset registration and the in-memory index (cond 1)
# --------------------------------------------------------------------------------------

_MEMO: dict[str, Any] = {}
_LOCK = threading.Lock()


def _stamp(path: Path) -> tuple[int, int]:
    st = Path(path).stat()
    return (st.st_size, st.st_mtime_ns)


def _load(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))


def _validate(path: Path) -> bool:
    """register_dataset(validate=): refuse truncated, empty or error answers; build the index at refresh."""
    data = _load(path)
    problem = validate_export(data)
    if problem:
        raise ValueError(problem)
    index = build_index(data)
    with _LOCK:
        _MEMO.clear()
        _MEMO["stamp"] = _stamp(path)  # the install renames this file: size and mtime stay the same
        _MEMO["index"] = index
    return True


def load_index(path: Path) -> dict[str, Any]:
    """The parsed index of the installed copy, built once per file version."""
    stamp = _stamp(path)
    with _LOCK:
        if _MEMO.get("stamp") == stamp and isinstance(_MEMO.get("index"), dict):
            return _MEMO["index"]
    data = _load(path)
    problem = validate_export(data, min_rows=1)
    if problem:
        raise ValueError(problem)
    index = build_index(data)
    with _LOCK:
        _MEMO.clear()
        _MEMO["stamp"] = stamp
        _MEMO["index"] = index
    return index


register_dataset(
    DATASET,
    EXPORT_URL,
    ttl=WEEK,
    description="Ransomwhere ransomware payment addresses, full export (~5.6 MB JSON, weekly; P210 cond 1)",
    licence=LICENCE,
    terms_class="open",
    attribution=ATTRIBUTION,
    provider="ransomwhere",
    source=SOURCE,
    validate=_validate,
    min_bytes=1_000_000,
    expect="json",
    max_bytes=50_000_000,
    large=True,
)


def _selftest(ctx: Any) -> HealthResult:
    """doctor: the export is present locally (it is stale by nature: the upstream stopped in 2024-10)."""
    try:
        info = ctx.data.info(DATASET)
    except (ValueError, OSError):
        info = None
    if info is None or not getattr(info, "present", False):
        return HealthResult("dead", f"Ransomwhere export not downloaded - run v3lum data update {DATASET}")
    return HealthResult("ok", f"Ransomwhere export present (fetched {str(getattr(info, 'fetched_at', '') or '')[:10] or 'unknown'})")


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class Ransomwhere(Module):
    name = "ransomwhere"
    title = "Ransomwhere ransomware payment addresses (offline)"
    description = (
        "Offline match of a Bitcoin address against the Ransomwhere export (crowdsourced ransomware payment addresses): "
        "family, payments and amounts; historical data (stale since 2024-10), a miss means nothing."
    )
    category = "crypto"
    accepts = {T.BTC}
    produces = {T.THREAT_ACTOR}
    tags = {"offline", "free"}
    reference = SITE
    notice = (
        f"{ATTRIBUTION}. Historical and crowdsourced: the dataset stopped in 2024-10 and is skewed to older families; "
        "a hit is a lead (ransomware payments reached this address), a miss means nothing. Refresh weekly with "
        f"v3lum data update {DATASET} (5.6 MB, never downloaded during a scan)."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    provider = ""
    sources = (SOURCE,)
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.05
    timeout = 60.0
    max_pivots = 10
    default_enabled = True

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=True, selftest=_selftest)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        address = normalize_btc(str(entity.value))
        if address is None:
            return res.mark("skipped", "not a Bitcoin mainnet address", reason_code="not_applicable")
        try:
            path = ctx.data.fetch(DATASET)
        except DatasetUnavailable:
            raise  # never downloaded (5.6 MB, not mid-scan): UNAVAILABLE 'dataset' - run v3lum data update
        except DatasetError as exc:
            return res.mark("error", f"Ransomwhere export unavailable ({str(exc)[:120]}): could not verify")
        try:
            index = load_index(path)
        except (OSError, ValueError) as exc:
            return res.mark("error", f"Ransomwhere export unreadable ({str(exc)[:120]}): could not verify - run v3lum data update {DATASET}")
        hit = lookup(index, address)
        info = _info(ctx)
        fetched = str(getattr(info, "fetched_at", "") or "")[:10] or None
        res.attr("dataset_age", {"dataset": DATASET, "last_updated": index.get("last_updated"), "last_payment": index.get("last_payment"),
                                 "fetched_at": fetched, "rows": index.get("rows")})
        if hit["status"] == "empty":
            res.attr("ransomwhere_status", hit["reason"])
            res.raw = {"match": False, "dataset_last_updated": index.get("last_updated"), "rows": index.get("rows")}
            return res.mark("empty")
        if hit["status"] != "found":
            return res.mark("error", f"{hit.get('reason') or 'unexpected lookup result'}: could not verify")
        self._report(res, hit)
        return res

    @staticmethod
    def _report(res: ModuleResult, hit: dict[str, Any]) -> None:
        family = hit["family"] or "Unlabeled"
        payments = {k: hit[k] for k in ("family", "family_variant", "tx_count", "total_btc", "total_usd", "first_payment",
                                        "last_payment", "balance_btc", "reported_at", "transactions")}
        res.attr("ransomware_payments", payments)
        res.attr("ransomwhere_status", f"in the Ransomwhere dataset as a {family} payment address ({hit['label_text']})")
        res.attr("data_attribution", ATTRIBUTION)
        usd = f" (~USD {hit['total_usd']:,.2f} at the time of payment)" if hit["total_usd"] is not None else ""
        window = (f" between {hit['first_payment'][:10]} and {hit['last_payment'][:10]}" if hit["first_payment"] and hit["last_payment"] else "")
        family_text = (f"family {family}" if hit["labelled"]
                       else "family not labelled (payment from the 'Showing the Receipts' study)")
        res.finding(
            TITLE,
            "high",
            f"Ransomwhere lists this address as a ransomware payment address: {family_text}; {hit['tx_count']} payment(s) "
            f"totalling {hit['total_btc']} BTC{usd}{window}. {hit['label_text'].capitalize()}; a lead, not attribution of "
            f"the current owner. Source: {CITATION}",
            confidence="probable",
            criterion=(f"exact address match in the Ransomwhere export (crowdsourced, dataset last updated {hit['dataset_date']}; "
                       "historical, skewed to older families)"),
            data={"family": hit["family"], "family_names": hit["family_names"], "variant": hit["family_variant"],
                  "tx_count": hit["tx_count"], "total_btc": hit["total_btc"], "total_usd": hit["total_usd"],
                  "first_payment": hit["first_payment"], "last_payment": hit["last_payment"], "labels": hit["labels"],
                  "dataset_last_updated": hit["dataset_date"], "attribution": ATTRIBUTION},
            tags=["ransomware", "historical", "crowdsourced"],
            references=[SITE, "https://doi.org/10.5281/zenodo.6512122"],
            source=SOURCE,
            observed_first=hit["first_payment"],
            observed_last=hit["last_payment"],
        )
        for pv in hit["pivots"]:
            res.pivot(T.THREAT_ACTOR, pv["value"], pv["relation"], confidence=pv["confidence"], expand=pv["expand"], note=pv["note"])
        res.raw = {"match": True, "address": hit["address"], "family": hit["family"], "tx_count": hit["tx_count"],
                   "total_btc": hit["total_btc"], "dataset_last_updated": hit["dataset_date"]}


def _info(ctx: Any) -> Any:
    try:
        return ctx.data.info(DATASET)
    except (ValueError, OSError):
        return None


__all__ = [
    "ATTRIBUTION",
    "CITATION",
    "DATASET",
    "Ransomwhere",
    "btc",
    "build_index",
    "family_names",
    "load_index",
    "lookup",
    "normalize_btc",
    "validate_export",
]
