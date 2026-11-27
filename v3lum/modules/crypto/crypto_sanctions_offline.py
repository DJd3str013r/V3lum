"""Offline OFAC sanctioned-address lists (P205, the disclosure-'none' half of crypto_sanctions).

Final conditions (P205):

* cond 1 - ``crypto_sanctions_offline`` has disclosure ``none`` (TLP:RED-safe: the wallet never leaves
  the machine). The 0xB10C OFAC sanctioned-address lists (MIT lists over US public-domain OFAC SDN
  data) are registered datasets, one per asset (18 lists, ~41 KB in total), refreshed daily by the
  dataset manager. Matching is by address FORMAT, not by list name (the USDT list mixes EVM, TRON and
  Omni addresses): EVM lowercase, bech32/cashaddr lowercase, base58 (BTC, TRON, LTC, ...) exact. Every
  match keeps the list date (the local copy's fetch date) and the list SHA-256; the upstream commit
  is not served by raw.githubusercontent.com (backlog p1-G09-1).
* cond 5 - a hit: tag ``sanctions``, CRITICAL, 'address on the OFAC SDN list (US)' with the list date
  and 'stop transactions and escalate to compliance'. The 0xB10C lists carry addresses only: the SDN
  entity and programme are cited when the OFAC SDN data is ingested (needs the core to redact the
  presigned S3 redirect of the OFAC download, backlog p1-G09-1); meanwhile the finding links OFAC
  Sanctions List Search for the analyst.
* cond 6 - a list match is not a legal determination (escalate to compliance/legal, no automated
  adverse action against natural persons, LGPD art. 20); lists older than 3 days are flagged
  (``ofac_list_stale``); a miss reads 'not on OFAC lists as of <date>' - never 'not sanctioned' - and
  a list that could not be read makes a miss 'could not verify'. GoPlus 'sanctioned' flags are not
  authoritative: the correlation rule ``g09_sanctions_non_authoritative`` labels them.
* cond 7 - terms 'open' (the lists are MIT over public-domain data; registry source
  ``github.crypto_sanctions_offline_ofac_lists``).
"""

from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Any

from v3lum.core.datasets import DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, HealthResult, Module, register

SOURCE = "github.crypto_sanctions_offline_ofac_lists"
LIST_URL = "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_{asset}.txt"
#: the 18 lists published on 2026-11-26 (DOGE answers 404 and is not published)
ASSETS: tuple[str, ...] = ("XBT", "ETH", "XMR", "LTC", "ZEC", "DASH", "BTG", "ETC", "BSV", "BCH", "XVG", "USDC", "USDT", "XRP", "TRX", "ARB", "BSC", "SOL")
ATTRIBUTION = (
    "OFAC SDN digital-currency addresses (U.S. Department of the Treasury, public domain) as extracted by "
    "0xB10C/ofac-sanctioned-digital-currency-addresses (MIT)"
)
OFAC_SEARCH = "https://sanctionssearch.ofac.treas.gov/"
#: the lists are rebuilt nightly upstream; a local copy older than this is flagged (cond 6)
STALE_HOURS = 72
TITLE = "Address on the OFAC SDN list (US)"
COMPLIANCE_NOTE = (
    "A list match is not a legal determination: stop transactions and escalate to compliance/legal; take no automated "
    "adverse action against natural persons (LGPD art. 20)."
)

_EVM_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BECH32_RE = re.compile(r"^(?:bc|ltc|tb|bcrt|bnb|tbnb)1[02-9ac-hj-np-z]{8,87}$")
_CASHADDR_RE = re.compile(r"^(?:bitcoincash:)?[qp][02-9ac-hj-np-z]{41}$")
_LINE_RE = re.compile(r"^[A-Za-z0-9:]{20,120}$")


def dataset_name(asset: str) -> str:
    return f"ofac_sanctioned_{asset.lower()}"


def address_family(value: str) -> str:
    """'evm' | 'bech32' | 'cashaddr' | 'base58' (everything else: BTC legacy, TRON, LTC, DASH, ZEC t-addresses,
    SOL, XRP, XMR...)."""
    text = (value or "").strip()
    if _EVM_RE.match(text):
        return "evm"
    low = text.lower()
    if _BECH32_RE.match(low):
        return "bech32"
    if (text in (low, text.upper()) or low.startswith("bitcoincash:")) and _CASHADDR_RE.match(low):  # one case only
        return "cashaddr"
    return "base58"


def match_key(value: str) -> str:
    """P205 cond 1 matching key: EVM lowercase, bech32/cashaddr lowercase (cashaddr without its prefix),
    base58 exact."""
    text = (value or "").strip()
    family = address_family(text)
    if family in ("evm", "bech32"):
        return text.lower()
    if family == "cashaddr":
        low = text.lower()
        return low[len("bitcoincash:"):] if low.startswith("bitcoincash:") else low
    return text


def parse_list(text: str) -> list[str]:
    """One list file -> its address lines (blank, comment and non-address lines skipped)."""
    out = []
    for line in (text or "").splitlines():
        item = line.strip()
        if item and not item.startswith("#") and _LINE_RE.match(item):
            out.append(item)
    return out


def _validate(path: Path) -> bool:
    """register_dataset(validate=): a text list with at least one address line and nothing HTML-like."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    if "<" in text[:2048] or not parse_list(text):
        raise ValueError("not an OFAC address list (no address line, or HTML)")
    return True


for _asset in ASSETS:
    register_dataset(
        dataset_name(_asset),
        LIST_URL.format(asset=_asset),
        ttl=86400,
        description=f"OFAC SDN '{_asset}' digital-currency addresses (0xB10C extraction, daily; P205 cond 1)",
        licence="MIT (list extraction) over U.S. Government public-domain OFAC data",
        terms_class="open",
        attribution=ATTRIBUTION,
        provider="github",
        source=SOURCE,
        validate=_validate,
        min_bytes=20,
        expect="lines",
        max_bytes=2_000_000,
        large=False,
        essential=True,
    )

_MEMO: dict[str, tuple[Any, frozenset[str]]] = {}
_LOCK = threading.Lock()


def _keys(path: Path) -> frozenset[str]:
    """Matching keys of one local list, parsed once per file version."""
    st = Path(path).stat()
    stamp = (st.st_mtime_ns, st.st_size)
    with _LOCK:
        cached = _MEMO.get(str(path))
        if cached is None or cached[0] != stamp:
            keys = frozenset(match_key(a) for a in parse_list(Path(path).read_text(encoding="utf-8", errors="replace")))
            _MEMO[str(path)] = (stamp, keys)
            return keys
        return cached[1]


def _selftest(ctx: Any) -> HealthResult:
    """doctor: every list is present locally and at most 72 h old."""
    missing, stale = [], []
    for asset in ASSETS:
        try:
            info = ctx.data.info(dataset_name(asset))
        except (ValueError, OSError):
            missing.append(asset)
            continue
        if not info.present:
            missing.append(asset)
        elif info.age_hours is None or info.age_hours > STALE_HOURS:
            stale.append(asset)
    if missing:
        return HealthResult("dead", f"OFAC lists not downloaded: {', '.join(missing)} - run v3lum data update")
    if stale:
        return HealthResult("dead", f"OFAC lists older than {STALE_HOURS} h: {', '.join(stale)} - run v3lum data update")
    return HealthResult("ok", f"{len(ASSETS)} OFAC lists present and fresh")


@register
class CryptoSanctionsOffline(Module):
    name = "crypto_sanctions_offline"
    title = "OFAC sanctioned crypto addresses (offline lists)"
    description = (
        "Offline match of a wallet against the OFAC SDN digital-currency address lists (0xB10C daily extraction, one list "
        "per asset): the address never leaves the machine (TLP:RED-safe). A miss reads 'not on OFAC lists as of <date>'."
    )
    category = "crypto"
    accepts = {T.BTC, T.ETH, T.CRYPTO, T.XMR}
    produces = frozenset()
    tags = {"offline", "free"}
    reference = "https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses"
    notice = (
        f"{ATTRIBUTION}. A list match is not a legal determination: escalate to compliance/legal and take no automated "
        "adverse action against natural persons (LGPD art. 20). A miss is 'not on OFAC lists as of <date>', never 'not "
        "sanctioned'; lists older than 3 days are flagged (v3lum data update)."
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
    default_enabled = True

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=True, selftest=_selftest)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = match_key(str(entity.value))
        hits: list[dict[str, Any]] = []
        failed: list[str] = []
        unavailable: list[DatasetUnavailable] = []
        dates: list[str] = []
        stale: list[str] = []
        for asset in ASSETS:
            name = dataset_name(asset)
            try:
                path = ctx.data.fetch(name)
                keys = _keys(path)
            except DatasetUnavailable as exc:
                unavailable.append(exc)
                failed.append(asset)
                continue
            except (DatasetError, OSError) as exc:
                ctx.log(f"OFAC list {asset} unavailable ({str(exc)[:120]})", "warning")
                failed.append(asset)
                continue
            info = _info(ctx, name)
            list_date = str(getattr(info, "fetched_at", "") or "")[:10] or None
            if list_date:
                dates.append(list_date)
            age = getattr(info, "age_hours", None)
            if age is None or age > STALE_HOURS:
                stale.append(f"{name} ({'unknown age' if age is None else f'{age:.0f} h old'})")
            if key in keys:
                hits.append({"asset": asset, "list_date": list_date, "list_sha256": getattr(info, "sha256", None) or None, "dataset": name})
        if len(unavailable) == len(ASSETS):
            raise unavailable[0]  # never downloaded and offline: UNAVAILABLE 'dataset' ('run v3lum data update')
        as_of = min(dates) if dates else ctx.now().date().isoformat()
        if stale:
            res.attr("ofac_list_stale", stale)
            ctx.log(f"{len(stale)} OFAC list(s) older than {STALE_HOURS} h: run v3lum data update", "warning")
        if hits:
            return self._hit(res, entity, hits, as_of, failed, stale)
        if failed:
            return res.mark("error", f"could not verify: OFAC lists unavailable ({', '.join(failed)}) - run v3lum data update")
        res.attr("sanctions_status", f"not on OFAC lists as of {as_of}" + (" (stale lists: run v3lum data update)" if stale else ""))
        res.raw = {"lists_checked": len(ASSETS), "as_of": as_of, "match": False}
        return res.mark("empty")  # the lists answered: no entry - which is never 'not sanctioned'

    @staticmethod
    def _hit(res: ModuleResult, entity: Entity, hits: list[dict[str, Any]], as_of: str, failed: list[str], stale: list[str]) -> ModuleResult:
        lists = sorted({h["asset"] for h in hits})
        latest = max((h["list_date"] for h in hits if h["list_date"]), default=as_of)
        res.attr("sanctioned", True)
        res.attr("sanctions_status", f"on the OFAC SDN list (US) as of {latest}")
        res.attr("ofac_list_hits", hits)
        res.attr("data_attribution", ATTRIBUTION)
        stale_note = f" Some local lists are stale ({len(stale)}): refresh with v3lum data update." if stale else ""
        res.finding(
            TITLE,
            "critical",
            f"Address on the OFAC SDN list (US) - OFAC digital-currency address list(s) {', '.join(lists)}, list date {latest}. "
            "The SDN entity and programme behind the address are not part of these lists: look the address up in OFAC Sanctions "
            f"List Search. Stop transactions and escalate to compliance. {COMPLIANCE_NOTE}{stale_note}",
            confidence="confirmed",
            criterion=f"exact address match ({address_family(str(entity.value))} rule) in the OFAC sanctioned-address list(s) "
            f"{', '.join(lists)} (0xB10C extraction of OFAC SDN data, list date {latest})",
            data={"lists": lists, "list_date": latest, "hits": hits, "lists_unavailable": failed, "attribution": ATTRIBUTION},
            tags=["sanctions"],
            references=[OFAC_SEARCH],
            source=SOURCE,
            observed_last=f"{latest}T00:00:00+00:00" if latest else None,
        )
        res.link("OFAC Sanctions List Search (SDN entity and programme)", OFAC_SEARCH)
        res.raw = {"lists_checked": len(ASSETS) - len(failed), "as_of": as_of, "match": True, "hits": hits}
        return res


def _info(ctx: Any, name: str) -> Any:
    try:
        return ctx.data.info(name)
    except (ValueError, OSError):
        return None


__all__ = [
    "ASSETS",
    "CryptoSanctionsOffline",
    "address_family",
    "dataset_name",
    "match_key",
    "parse_list",
]
