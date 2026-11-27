"""Bitcoin/Litecoin/Dogecoin/Dash explorers with sequential failover (P211).

Two modules, one per disclosure class (A8 BR7):

* ``btc_explorers`` (disclosure ``third_party``): a configured self-hosted Esplora
  (settings ``btc_explorers_esplora_url`` for BTC, ``btc_explorers_esplora_ltc_url`` for LTC) is always
  tried first, then the public explorers in a fixed order.
* ``btc_esplora_internal`` (disclosure ``internal``): the self-hosted Esplora only, never a public
  failover, for TLP:AMBER+STRICT and RED cases (at lower TLPs btc_explorers covers it).

Final conditions (council #1, P211) and where they live:

1. One Esplora parser for Blockstream, mempool.space and litecoinspace.org (:func:`parse_esplora_address`:
   balance = funded_txo_sum - spent_txo_sum, in base units; :func:`parse_esplora_txs`); the self-hosted
   Esplora goes first (:func:`utxo_failover_plan`) and is the only adapter of ``btc_esplora_internal``.
2. Fallbacks of this build: Blockchain.com ``rawaddr`` (summary + full transactions; ``multiaddr``/``balance``
   batch parsers with the ``%7C`` separator, :func:`multiaddr_active_param`) and BlockCypher (LTC/DOGE/DASH,
   optional token ``blockcypher`` sent as ``?token=`` and redacted by AR01). Bitaps and SoChain are dropped.
   Blockchair only with the commercial key ``blockchair`` (the registry marker maps its HTTP 430 to RATE_LIMITED).
3. Failover is sequential and only on a failure (:func:`should_failover`): the first provider that answers
   (ok or empty) wins; the explorer budget is :data:`EXPLORER_BUDGET_S` (15 s) per address (each request gets
   ``min(5 s, what is left)``); the answering provider, the order and every provider's status are recorded in
   attribute ``explorer_failover`` (and per feed with ``res.source_status``); attribute ``disclosed_to`` lists
   the public explorers that received the address (empty when only the self-hosted instance answered).
4. Per-host P334 politeness and quotas live in the provider fragments (blockstream 0.5 s, mempool 1 s,
   litecoinspace 1 s, blockchain.info 10 s, BlockCypher quota 100 req/h per IP, Blockchair 2 s). A 429/430 is
   RATE_LIMITED for that provider - never empty - and the host is short-circuited for the rest of the run
   (:func:`short_circuit`, in memory per HTTP client: 15 min, Blockchair 430 six hours). The chain and the
   provider come from the core validator (P217 ``crypto_address_info``: checksummed formats only, mainnet
   only); transaction pages are capped at :data:`MAX_TX_PAGES` (2).
5. Summary: balance, transaction count, first/last activity (exact only when every transaction was read or
   the provider gives it) and data freshness (provider tip height, blocks since the latest transaction);
   the top 10 counterparties by value become ``transacted_with`` pivots with ``expand=False`` (P213 decides
   expansion) noted 'counterparty (role unknown)'. Counterparties' own balances and histories are never
   fetched; evidence keeps the summary and transaction ids only.
6. Per-adapter terms and tiers (:data:`UTXO_PROVIDERS`, the registry fragments): Esplora, mempool,
   litecoinspace and Blockchain.com 'open'; BlockCypher and Blockchair 'key-terms' (module terms
   'key-terms'); Blockstream, Blockchain.com, BlockCypher and Blockchair trusted, mempool.space and
   litecoinspace community. The policy gate narrows ``ctx.allowed_sources`` (licence profile) and only
   allowed adapters are queried.

Providers disagree on some addresses (Esplora does not index the unspendable genesis coinbase, so it reports
57.72 BTC where Blockchain.com reports 107.73 BTC for 1A1zP1...): the summary always names the answering
provider and balances are never compared across providers.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import threading
import time
import weakref
from typing import Any
from urllib.parse import quote, urlsplit

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, HttpError, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, Module, register
from v3lum.core.validators import crypto_address_info

# ======================================================================================
# constants (P211 cond 3-6)
# ======================================================================================

SRC_INTERNAL = "internal_esplora.esplora"
SRC_BLOCKSTREAM = "blockstream.esplora_api"
SRC_MEMPOOL = "mempool_space.esplora_api"
SRC_LITECOINSPACE = "litecoinspace.esplora_api"
SRC_BLOCKCHAIN = "blockchain_com.data_api"
SRC_BLOCKCYPHER = "blockcypher.api"
SRC_BLOCKCHAIR = "blockchair.api"
KEY_BLOCKCYPHER = "blockcypher"
KEY_BLOCKCHAIR = "blockchair"
SETTING_ESPLORA_BTC = "btc_explorers_esplora_url"
SETTING_ESPLORA_LTC = "btc_explorers_esplora_ltc_url"

EXPLORER_BUDGET_S = 15.0  # P211 cond 3 / P212 cond 4
REQUEST_TIMEOUT_S = 5.0
MAX_TX_PAGES = 2  # P211 cond 4
TOP_COUNTERPARTIES = 10  # P211 cond 5
COUNTERPARTY_LABEL = "counterparty (role unknown)"
TIP_TTL = 60
RATE_LIMIT_PAUSE_S = 900.0  # a 429 short-circuits the host for 15 min of this run
BLOCKCHAIR_430_PAUSE_S = 6 * 3600.0  # 'IP temporarily blacklisted': back off for hours

#: chain -> (display name, ticker, decimals)
CHAINS = {
    "btc": ("bitcoin", "BTC", 8),
    "ltc": ("litecoin", "LTC", 8),
    "doge": ("dogecoin", "DOGE", 8),
    "dash": ("dash", "DASH", 8),
}

#: Per-adapter facts (P211 cond 6: terms; A8 tiers as recorded in the provider registry).
UTXO_PROVIDERS: dict[str, dict[str, Any]] = {
    "esplora_internal": {"source": SRC_INTERNAL, "host": "", "terms": "open", "tier": "n/a", "public": False, "chains": ("btc", "ltc")},
    "blockstream": {"source": SRC_BLOCKSTREAM, "host": "blockstream.info", "terms": "open", "tier": "trusted", "public": True,
                    "chains": ("btc",), "base": "https://blockstream.info/api"},
    "mempool": {"source": SRC_MEMPOOL, "host": "mempool.space", "terms": "open", "tier": "community", "public": True,
                "chains": ("btc",), "base": "https://mempool.space/api"},
    "litecoinspace": {"source": SRC_LITECOINSPACE, "host": "litecoinspace.org", "terms": "open", "tier": "community", "public": True,
                      "chains": ("ltc",), "base": "https://litecoinspace.org/api"},
    "blockchain_com": {"source": SRC_BLOCKCHAIN, "host": "blockchain.info", "terms": "open", "tier": "trusted", "public": True,
                       "chains": ("btc",)},
    "blockcypher": {"source": SRC_BLOCKCYPHER, "host": "api.blockcypher.com", "terms": "key-terms", "tier": "trusted", "public": True,
                    "chains": ("ltc", "doge", "dash"), "key": KEY_BLOCKCYPHER, "key_optional": True},
    "blockchair": {"source": SRC_BLOCKCHAIR, "host": "api.blockchair.com", "terms": "key-terms", "tier": "trusted", "public": True,
                   "chains": ("btc", "ltc", "doge", "dash"), "key": KEY_BLOCKCHAIR, "key_optional": False},
}
PUBLIC_UTXO_ORDER = {
    "btc": ("blockstream", "mempool", "blockchain_com"),
    "ltc": ("litecoinspace", "blockcypher"),
    "doge": ("blockcypher",),
    "dash": ("blockcypher",),
}
BLOCKCYPHER_COIN = {"btc": "btc", "ltc": "ltc", "doge": "doge", "dash": "dash"}
BLOCKCHAIR_CHAIN = {"btc": "bitcoin", "ltc": "litecoin", "doge": "dogecoin", "dash": "dash"}
EXPLORER_PAGES = {
    "btc": ("mempool.space address page", "https://mempool.space/address/{a}"),
    "ltc": ("litecoinspace.org address page", "https://litecoinspace.org/address/{a}"),
    "doge": ("Blockchair address page", "https://blockchair.com/dogecoin/address/{a}"),
    "dash": ("Blockchair address page", "https://blockchair.com/dash/address/{a}"),
}
#: statuses that move the failover to the next provider (ok/empty answers stop it)
FAILOVER_ON = frozenset({"error", "timeout", "rate_limited", "quota", "blocked", "needs_key", "skipped"})
_STATUS_PRIORITY = ("rate_limited", "quota", "blocked", "needs_key", "error")


# ======================================================================================
# pure helpers (shared with evm_explorers)
# ======================================================================================


def to_int(value: Any) -> int | None:
    """int from an int or a decimal string; None for bools, fractional floats and junk."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    if isinstance(value, str) and re.fullmatch(r"\s*-?\d{1,40}\s*", value):
        return int(value)
    return None


def units_str(amount: Any, decimals: int) -> str | None:
    """Exact decimal string of an amount in base units: ``units_str(5772103060, 8) -> '57.72103060'``."""
    amt = to_int(amount)
    if amt is None:
        return None
    sign = "-" if amt < 0 else ""
    q, r = divmod(abs(amt), 10 ** decimals)
    return f"{sign}{q}.{r:0{decimals}d}" if decimals else f"{sign}{q}"


def iso_utc(ts: Any) -> str | None:
    """Unix seconds (or milliseconds above 1e12) -> 'YYYY-MM-DDTHH:MM:SSZ'."""
    t = int(ts) if isinstance(ts, float) and ts == ts else to_int(ts)
    if t is None or t <= 0:
        return None
    if t > 10 ** 12:
        t //= 1000
    try:
        return _dt.datetime.fromtimestamp(t, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def norm_time(value: Any) -> str | None:
    """Provider timestamps (unix, ISO with Z/offset/fraction, 'YYYY-MM-DD HH:MM:SS' UTC) -> ISO UTC."""
    if value is None or value == "" or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return iso_utc(value)
    s = str(value).strip()
    if re.fullmatch(r"\d{9,13}", s):
        return iso_utc(int(s))
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?", s)
    if not m:
        return None
    try:
        base = _dt.datetime.strptime(m.group(1) + " " + m.group(2), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    tz = m.group(4)
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        base -= sign * _dt.timedelta(hours=int(tz[1:3]), minutes=int(tz[-2:]))
    return base.strftime("%Y-%m-%dT%H:%M:%SZ")


def clean_text(text: Any, limit: int | None = None) -> str | None:
    """Strip control characters (AR13) and optionally cap the length."""
    if not isinstance(text, str):
        return None
    s = "".join(ch for ch in text if ch in "\n\t" or (ord(ch) >= 32 and not 0x7F <= ord(ch) < 0xA0)).strip()
    return s[:limit] if limit else s


def addr_key(addr: Any) -> str | None:
    """Comparison key: bech32 and EVM addresses are case-insensitive, base58 is not."""
    if not isinstance(addr, str):
        return None
    low = addr.lower()
    return low if low.startswith(("bc1", "ltc1", "tb1", "0x")) else addr


def load_json(raw: Any) -> tuple[Any, str | None]:
    """(object, None) or (None, reason) for bytes/str/parsed input; HTML or junk is never 'empty' (rule 5)."""
    if isinstance(raw, (dict, list)):
        return raw, None
    if raw is None:
        return None, "empty body"
    text = bytes(raw).decode("utf-8", errors="replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    body = text.lstrip("﻿ \t\r\n")
    if not body:
        return None, "empty body"
    if body.startswith("<"):
        return None, "HTML page instead of JSON"
    try:
        return json.loads(body), None
    except (ValueError, RecursionError):
        return None, "body is not valid JSON"


def direction_of(n_in: int, n_out: int) -> str:
    """'in' = the counterparty only sent funds to the investigated address (P213 'possible victim' input)."""
    return "both" if n_in and n_out else "in" if n_in else "out"


def should_failover(status: str) -> bool:
    """Sequential failover only on error-like outcomes; ok/empty answers stop the chain (P211 cond 3)."""
    return status in FAILOVER_ON


def failover_report(attempts: list[dict[str, Any]], budget_s: float = EXPLORER_BUDGET_S, internal: tuple[str, ...] = ("esplora_internal",)) -> dict[str, Any]:
    """Per-address failover summary (P211 cond 3, P212 cond 4).

    ``attempts``: ``[{provider, source, status, reason, elapsed_s, sent}]`` in the order tried. Returns
    ``answered_by``, ``order``, ``per_provider``, ``disclosed_to`` (public providers that received the value:
    every attempt whose request left the machine), ``elapsed_s``, ``over_budget`` and ``budget_s``.
    """
    answered = None
    disclosed: list[str] = []
    total = 0.0
    for att in attempts:
        total += float(att.get("elapsed_s") or 0.0)
        prov = att.get("provider")
        if att.get("sent") and prov not in internal and prov not in disclosed:
            disclosed.append(prov)
        if answered is None and att.get("status") in ("ok", "empty"):
            answered = prov
    return {
        "answered_by": answered,
        "order": [a.get("provider") for a in attempts],
        "per_provider": [{k: a.get(k) for k in ("provider", "source", "status", "reason", "elapsed_s", "sent")} for a in attempts],
        "disclosed_to": disclosed,
        "elapsed_s": round(total, 3),
        "over_budget": total > budget_s,
        "budget_s": budget_s,
    }


def worst_status(statuses: list[str]) -> str:
    """The status reported when no provider answered: rate limits and quotas first (rule 5)."""
    for st in _STATUS_PRIORITY:
        if st in statuses:
            return st
    return "error"


# ======================================================================================
# chain detection (P217) and the failover plan (cond 1-3)
# ======================================================================================


def address_chain(value: Any) -> str | None:
    """'btc' | 'ltc' | 'doge' | 'dash' for a checksummed mainnet address (core P217 validator), else None."""
    if not isinstance(value, str):
        return None
    info = crypto_address_info(value.strip())
    if info is None or info.network != "mainnet" or info.checksum_ok is not True or info.chain not in CHAINS:
        return None
    return info.chain


def utxo_failover_plan(chain: str, esplora_urls: dict[str, str] | None = None, keys: tuple[str, ...] | set[str] = (),
                       internal_only: bool = False, allowed: Any = None) -> list[str]:
    """Ordered adapter ids for one address (P211 cond 1-3).

    ``esplora_urls``: ``{'btc': 'https://esplora.internal/api', ...}`` (self-hosted, always first);
    ``internal_only``: the btc_esplora_internal class (no public failover); ``keys``: configured key names
    (Blockchair only with its commercial key); ``allowed``: ``ctx.allowed_sources`` (licence gate per adapter).
    """
    plan: list[str] = []
    if esplora_urls and esplora_urls.get(chain):
        plan.append("esplora_internal")
    if not internal_only:
        plan += list(PUBLIC_UTXO_ORDER.get(chain, ()))
        if KEY_BLOCKCHAIR in set(keys or ()) and chain in BLOCKCHAIR_CHAIN:
            plan.append("blockchair")
    if allowed is not None:
        ok = set(allowed)
        plan = [p for p in plan if UTXO_PROVIDERS[p]["source"] in ok]
    return plan


# ======================================================================================
# Esplora (Blockstream, mempool.space, litecoinspace, self-hosted) - cond 1
# ======================================================================================


def esplora_paths(address: str, last_seen_txid: str | None = None) -> dict[str, str]:
    """Paths under an Esplora base URL (the base already ends with /api for the public instances)."""
    a = quote(address, safe="")
    p = {"address": f"/address/{a}", "tip": "/blocks/tip/height"}
    p["txs"] = f"/address/{a}/txs" if not last_seen_txid else f"/address/{a}/txs/chain/{quote(last_seen_txid, safe='')}"
    return p


def parse_esplora_address(raw: Any) -> dict[str, Any] | None:
    """GET {base}/address/{a} -> summary; balance = funded_txo_sum - spent_txo_sum in base units (cond 1)."""
    obj, err = load_json(raw)
    if err or not isinstance(obj, dict) or not isinstance(obj.get("chain_stats"), dict):
        return None
    cs = obj["chain_stats"]
    ms = obj.get("mempool_stats") if isinstance(obj.get("mempool_stats"), dict) else {}
    funded, spent = to_int(cs.get("funded_txo_sum")), to_int(cs.get("spent_txo_sum"))
    if funded is None or spent is None:
        return None
    ctx_n = to_int(cs.get("tx_count")) or 0
    mtx = to_int(ms.get("tx_count")) or 0
    return {
        "address": obj.get("address") if isinstance(obj.get("address"), str) else None,
        "balance": funded - spent,
        "unconfirmed_delta": (to_int(ms.get("funded_txo_sum")) or 0) - (to_int(ms.get("spent_txo_sum")) or 0),
        "total_received": funded,
        "total_sent": spent,
        "tx_count": ctx_n + mtx,
        "confirmed_tx_count": ctx_n,
        "mempool_tx_count": mtx,
        "is_empty": ctx_n + mtx == 0,
    }


def _norm_tx(txid: str, confirmed: Any, height: int | None, ts: int | None, fee: int | None, coinbase: bool,
             inputs: list[dict[str, Any]], outputs: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    out = {"txid": txid, "confirmed": bool(confirmed), "block_height": height, "timestamp": ts,
           "time": iso_utc(ts) if ts else None, "fee": fee, "coinbase": coinbase, "inputs": inputs, "outputs": outputs}
    out.update(extra)
    return out


def parse_esplora_txs(raw: Any) -> list[dict[str, Any]] | None:
    """GET {base}/address/{a}/txs[/chain/{last_txid}] -> normalised transactions (newest first)."""
    obj, err = load_json(raw)
    if err or not isinstance(obj, list):
        return None
    txs = []
    for tx in obj:
        if not isinstance(tx, dict) or not isinstance(tx.get("txid"), str):
            continue
        st = tx.get("status") if isinstance(tx.get("status"), dict) else {}
        inputs, coinbase = [], False
        for v in tx.get("vin") or []:
            if not isinstance(v, dict):
                continue
            if v.get("is_coinbase"):
                coinbase = True
                continue
            p = v.get("prevout") if isinstance(v.get("prevout"), dict) else None
            if p is None:
                continue
            a = p.get("scriptpubkey_address")
            inputs.append({"address": a if isinstance(a, str) else None, "value": to_int(p.get("value")) or 0})
        outputs = []
        for o in tx.get("vout") or []:
            if isinstance(o, dict):
                a = o.get("scriptpubkey_address")
                outputs.append({"address": a if isinstance(a, str) else None, "value": to_int(o.get("value")) or 0})
        txs.append(_norm_tx(tx["txid"], st.get("confirmed"), to_int(st.get("block_height")), to_int(st.get("block_time")),
                            to_int(tx.get("fee")), coinbase, inputs, outputs))
    return txs


def esplora_next_txid(txs: list[dict[str, Any]], tx_count: int | None, fetched: int) -> str | None:
    """``last_seen_txid`` for ``/txs/chain/{txid}`` when the address has more transactions than were read."""
    if tx_count is None or fetched >= tx_count:
        return None
    confirmed = [t for t in txs or [] if t.get("confirmed")]
    return confirmed[-1]["txid"] if confirmed else None


def parse_esplora_tip_height(raw: Any) -> int | None:
    """GET {base}/blocks/tip/height -> int (a text body)."""
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
    if isinstance(text, str) and re.fullmatch(r"\s*\d{1,9}\s*", text):
        return int(text)
    return None


# ======================================================================================
# Blockchain.com (cond 2)
# ======================================================================================


def _bci_tx(t: Any, outputs_filtered: bool = False) -> dict[str, Any] | None:
    if not isinstance(t, dict) or not isinstance(t.get("hash"), str):
        return None
    inputs, coinbase = [], False
    for i in t.get("inputs") or []:
        p = i.get("prev_out") if isinstance(i, dict) else None
        if not isinstance(p, dict):
            coinbase = True
            continue
        a = p.get("addr")
        inputs.append({"address": a if isinstance(a, str) else None, "value": to_int(p.get("value")) or 0})
    outputs = []
    for o in t.get("out") or []:
        if isinstance(o, dict):
            a = o.get("addr")
            outputs.append({"address": a if isinstance(a, str) else None, "value": to_int(o.get("value")) or 0})
    height = to_int(t.get("block_height"))
    return _norm_tx(t["hash"], height is not None, height, to_int(t.get("time")), to_int(t.get("fee")), coinbase, inputs,
                    outputs, outputs_filtered=outputs_filtered)


def parse_blockchain_rawaddr(raw: Any) -> dict[str, Any] | None:
    """GET blockchain.info/rawaddr/{a}?limit=50&offset=k -> {summary, txs} (full inputs/outputs)."""
    obj, err = load_json(raw)
    if err or not isinstance(obj, dict) or "final_balance" not in obj:
        return None
    n_tx, bal = to_int(obj.get("n_tx")), to_int(obj.get("final_balance"))
    if bal is None:
        return None
    summary = {
        "address": obj.get("address") if isinstance(obj.get("address"), str) else None,
        "balance": bal, "total_received": to_int(obj.get("total_received")), "total_sent": to_int(obj.get("total_sent")),
        "tx_count": n_tx, "unspent_outputs": to_int(obj.get("n_unredeemed")), "is_empty": n_tx == 0,
    }
    return {"summary": summary, "txs": [x for x in (_bci_tx(t) for t in obj.get("txs") or []) if x]}


def parse_blockchain_multiaddr(raw: Any) -> dict[str, Any] | None:
    """GET blockchain.info/multiaddr?active=a1%7Ca2 -> per-address summaries + chain tip.

    Its transactions carry only the queried wallet's outputs (observed live: vout_sz 2, out 1): they are
    flagged ``outputs_filtered`` and never feed counterparty ranking (batch summaries only).
    """
    obj, err = load_json(raw)
    if err or not isinstance(obj, dict) or not isinstance(obj.get("addresses"), list):
        return None
    per = {}
    for a in obj["addresses"]:
        if isinstance(a, dict) and isinstance(a.get("address"), str):
            per[a["address"]] = {"balance": to_int(a.get("final_balance")), "tx_count": to_int(a.get("n_tx")),
                                 "total_received": to_int(a.get("total_received")), "total_sent": to_int(a.get("total_sent")),
                                 "is_empty": to_int(a.get("n_tx")) == 0}
    info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
    lb = info.get("latest_block") if isinstance(info.get("latest_block"), dict) else {}
    return {"addresses": per, "tip_height": to_int(lb.get("height")), "tip_time": iso_utc(lb.get("time")),
            "txs": [x for x in (_bci_tx(t, True) for t in obj.get("txs") or []) if x]}


def multiaddr_active_param(addresses: list[str]) -> str:
    """'a1%7Ca2': the separator must be URL-encoded (a raw '|' returned an error, research C0481)."""
    return "%7C".join(a for a in addresses if isinstance(a, str) and re.fullmatch(r"[A-Za-z0-9]{14,90}", a))


def parse_blockchain_balance(raw: Any) -> dict[str, Any] | None:
    """GET blockchain.info/balance?active=a -> {address: summary}."""
    obj, err = load_json(raw)
    if err or not isinstance(obj, dict) or not obj:
        return None
    out = {}
    for addr, v in obj.items():
        if not isinstance(v, dict) or "final_balance" not in v:
            return None
        out[addr] = {"balance": to_int(v.get("final_balance")), "tx_count": to_int(v.get("n_tx")),
                     "total_received": to_int(v.get("total_received")), "is_empty": to_int(v.get("n_tx")) == 0}
    return out


def blockchain_error(raw: Any) -> str | None:
    """Blockchain.com ``{'error', 'message'}`` body -> short reason, else None."""
    obj, _ = load_json(raw)
    if isinstance(obj, dict) and obj.get("error"):
        return f"{clean_text(str(obj.get('error')), 60)} ({clean_text(str(obj.get('message') or ''), 100)})"
    return None


# ======================================================================================
# BlockCypher (cond 2)
# ======================================================================================


def _bcy_summary(obj: dict[str, Any]) -> dict[str, Any]:
    n = to_int(obj.get("final_n_tx"))
    if n is None:
        n = to_int(obj.get("n_tx"))
    bal = to_int(obj.get("final_balance"))
    if bal is None:
        bal = to_int(obj.get("balance"))
    return {"address": obj.get("address") if isinstance(obj.get("address"), str) else None, "balance": bal,
            "total_received": to_int(obj.get("total_received")), "total_sent": to_int(obj.get("total_sent")),
            "tx_count": n, "is_empty": n == 0, "has_more": bool(obj.get("hasMore"))}


def parse_blockcypher_full(raw: Any) -> dict[str, Any] | None:
    """GET /v1/{coin}/main/addrs/{a}/full?limit=N -> {summary, txs} with input/output addresses."""
    obj, err = load_json(raw)
    if err or not isinstance(obj, dict) or ("final_balance" not in obj and "balance" not in obj):
        return None
    txs = []
    for t in obj.get("txs") or []:
        if not isinstance(t, dict) or not isinstance(t.get("hash"), str):
            continue
        inputs, coinbase = [], False
        for i in t.get("inputs") or []:
            if not isinstance(i, dict):
                continue
            addrs = i.get("addresses") if isinstance(i.get("addresses"), list) else []
            if to_int(i.get("output_index")) == -1 or (i.get("script_type") == "empty" and not addrs):
                coinbase = True
                continue
            inputs.append({"address": addrs[0] if len(addrs) == 1 and isinstance(addrs[0], str) else None,
                           "value": to_int(i.get("output_value")) or 0})
        outputs = []
        for o in t.get("outputs") or []:
            if isinstance(o, dict):
                addrs = o.get("addresses") if isinstance(o.get("addresses"), list) else []
                outputs.append({"address": addrs[0] if len(addrs) == 1 and isinstance(addrs[0], str) else None,
                                "value": to_int(o.get("value")) or 0})
        when = norm_time(t.get("confirmed")) or norm_time(t.get("received"))
        ts = int(_dt.datetime.strptime(when, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc).timestamp()) if when else None
        height = to_int(t.get("block_height"))
        txs.append(_norm_tx(t["hash"], height is not None and height > 0, height, ts, to_int(t.get("fees")), coinbase, inputs, outputs))
    return {"summary": _bcy_summary(obj), "txs": txs}


def blockcypher_next_before(parsed_full: dict[str, Any] | None) -> int | None:
    """``before=<height>`` for the next /full page while ``hasMore``, else None."""
    if not parsed_full or not parsed_full["summary"].get("has_more") or not parsed_full["txs"]:
        return None
    heights = [t["block_height"] for t in parsed_full["txs"] if t.get("block_height")]
    return min(heights) if heights else None


def parse_blockcypher_chain(raw: Any) -> dict[str, Any] | None:
    """GET /v1/{coin}/main -> {name, height, time} (chain tip for freshness)."""
    obj, err = load_json(raw)
    if err or not isinstance(obj, dict) or to_int(obj.get("height")) is None:
        return None
    return {"name": obj.get("name"), "height": to_int(obj.get("height")), "time": norm_time(obj.get("time"))}


def blockcypher_error(raw: Any) -> str | None:
    obj, _ = load_json(raw)
    if isinstance(obj, dict) and obj.get("error"):
        return clean_text(str(obj.get("error")), 160)
    return None


# ======================================================================================
# Blockchair (cond 2: commercial key only)
# ======================================================================================


def blockchair_status(raw: Any, http_status: int = 200) -> tuple[str, str] | None:
    """Blockchair error codes (body ``context.code`` or HTTP status) -> (status, reason), else None.

    430 'IP temporarily blacklisted' (observed) and 429/435 -> rate_limited; 402 -> quota; 434 -> blocked;
    401/403 -> needs_key; other 4xx/5xx -> error."""
    obj, _ = load_json(raw)
    ctx = obj.get("context") if isinstance(obj, dict) and isinstance(obj.get("context"), dict) else {}
    code = to_int(ctx.get("code")) or to_int(http_status) or 0
    text = clean_text(str(ctx.get("error") or ""), 140) or ""
    if code == 430:
        return "rate_limited", "Blockchair HTTP 430 (IP temporarily blacklisted; back off for hours)"
    if code in (429, 435):
        return "rate_limited", f"Blockchair HTTP {code}"
    if code == 402:
        return "quota", "Blockchair HTTP 402 (key request limit exhausted)"
    if code == 434:
        return "blocked", "Blockchair HTTP 434 (IP banned)"
    if code in (401, 403):
        return "needs_key", f"Blockchair HTTP {code} (key missing or invalid)"
    if code >= 400:
        return "error", f"Blockchair HTTP {code} {text}".strip()
    if isinstance(obj, dict) and obj.get("data") is None and ctx.get("error"):
        return "error", "Blockchair: " + text
    return None


def parse_blockchair_dashboard(raw: Any, address: str | None = None) -> dict[str, Any] | None:
    """GET api.blockchair.com/{chain}/dashboards/address/{a}?limit=10&key=... -> {summary, txids, context}."""
    obj, err = load_json(raw)
    if err or not isinstance(obj, dict) or not isinstance(obj.get("data"), dict) or not obj["data"]:
        return None
    data = obj["data"]
    entry = data.get(address) if address in data else (next(iter(data.values())) if len(data) == 1 else None)
    if entry is None and address:
        for k, v in data.items():
            if addr_key(k) == addr_key(address):
                entry = v
    if not isinstance(entry, dict) or not isinstance(entry.get("address"), dict):
        return None
    a = entry["address"]
    firsts = [t for t in (norm_time(a.get("first_seen_receiving")), norm_time(a.get("first_seen_spending"))) if t]
    lasts = [t for t in (norm_time(a.get("last_seen_receiving")), norm_time(a.get("last_seen_spending"))) if t]
    n = to_int(a.get("transaction_count"))
    bal = to_int(a.get("balance"))
    if bal is None:
        return None
    ctx = obj.get("context") if isinstance(obj.get("context"), dict) else {}
    cache = ctx.get("cache") if isinstance(ctx.get("cache"), dict) else {}
    return {
        "summary": {"address": address or next(iter(data)), "balance": bal, "total_received": to_int(a.get("received")),
                    "total_sent": to_int(a.get("spent")), "tx_count": n, "is_empty": n == 0,
                    "first_seen": min(firsts) if firsts else None, "last_seen": max(lasts) if lasts else None,
                    "script_type": clean_text(a.get("type"), 40)},
        "txids": [t for t in entry.get("transactions") or [] if isinstance(t, str)][:50],
        "context": {"tip_height": to_int(ctx.get("state")), "cache_since": norm_time(cache.get("since")),
                    "request_cost": ctx.get("request_cost") if isinstance(ctx.get("request_cost"), (int, float)) else None},
    }


# ======================================================================================
# counterparties and the summary (cond 5)
# ======================================================================================


def utxo_counterparties(txs: list[dict[str, Any]], address: str) -> list[dict[str, Any]]:
    """Depth-1 counterparties of ``address`` over normalised transactions (cond 5; direction for P213).

    Incoming transaction (the address only among outputs): each other input address is a sender and the
    amount received is split among senders by their input value. Outgoing transaction (the address among
    inputs): each output to another address is a recipient, weighted by the address's share of the inputs.
    Co-inputs, change back to the address and provider-filtered transactions (multiaddr) are skipped.
    """
    me = addr_key(address)
    agg: dict[str, dict[str, Any]] = {}

    def add(addr: str, tx: dict[str, Any], role: str, value: int) -> None:
        rec = agg.setdefault(addr_key(addr) or addr, {"address": addr, "received_from": 0, "sent_to": 0, "tx_count": 0,
                                                      "in_tx_count": 0, "out_tx_count": 0, "first_seen": None, "last_seen": None,
                                                      "_txids": set(), "_in": set(), "_out": set()})
        bucket, counter, key = ("_in", "in_tx_count", "received_from") if role == "in" else ("_out", "out_tx_count", "sent_to")
        rec[key] += value
        if tx["txid"] not in rec[bucket]:
            rec[bucket].add(tx["txid"])
            rec[counter] += 1
        if tx["txid"] not in rec["_txids"]:
            rec["_txids"].add(tx["txid"])
            rec["tx_count"] += 1
        t = tx.get("time")
        if t:
            rec["first_seen"] = min(x for x in (rec["first_seen"], t) if x)
            rec["last_seen"] = max(x for x in (rec["last_seen"], t) if x)

    for tx in txs or []:
        if tx.get("outputs_filtered"):
            continue
        ins = [i for i in tx.get("inputs") or [] if i.get("address")]
        outs = [o for o in tx.get("outputs") or [] if o.get("address")]
        total_in = sum(i.get("value") or 0 for i in tx.get("inputs") or [])
        my_in = sum(i["value"] for i in ins if addr_key(i["address"]) == me)
        my_out = sum(o["value"] for o in outs if addr_key(o["address"]) == me)
        if my_in > 0:
            den = total_in or my_in
            for o in outs:
                if addr_key(o["address"]) != me:
                    add(o["address"], tx, "out", o["value"] * my_in // den)
        elif my_out > 0:
            senders: dict[str, int] = {}
            for i in ins:
                if addr_key(i["address"]) != me:
                    senders[i["address"]] = senders.get(i["address"], 0) + i["value"]
            tot = sum(senders.values())
            for a, v in senders.items():
                add(a, tx, "in", (my_out * v // tot) if tot else 0)
    out = []
    for rec in agg.values():
        for k in ("_txids", "_in", "_out"):
            rec.pop(k)
        rec["total"] = rec["received_from"] + rec["sent_to"]
        rec["direction"] = direction_of(rec["in_tx_count"], rec["out_tx_count"])
        out.append(rec)
    return out


def top_counterparties(records: list[dict[str, Any]], n: int = TOP_COUNTERPARTIES, value_key: str = "total") -> list[dict[str, Any]]:
    """Top-N by value, then transaction count, then address (deterministic)."""
    ranked = sorted(records, key=lambda r: (-(r.get(value_key) or 0), -(r.get("tx_count") or 0), str(r.get("address"))))
    return [dict(r, label=COUNTERPARTY_LABEL) for r in ranked[:n]]


def activity_window(txs: list[dict[str, Any]], tx_count: int | None = None) -> dict[str, Any]:
    """First/last activity from the transactions read; first is exact only when every one was read."""
    times = sorted(t["time"] for t in txs or [] if t.get("time"))
    if not times:
        return {"first_seen": None, "last_seen": None, "first_seen_exact": False, "txs_examined": len(txs or [])}
    exact = tx_count is not None and len(txs) >= tx_count
    return {"first_seen": times[0], "last_seen": times[-1], "first_seen_exact": exact, "txs_examined": len(txs)}


def build_utxo_summary(chain: str, provider: str, summary: dict[str, Any], txs: list[dict[str, Any]] | None = None,
                       tip_height: int | None = None, fetched_at: str | None = None, address: str | None = None,
                       top_n: int = TOP_COUNTERPARTIES) -> dict[str, Any]:
    """Analyst summary for one address (cond 5): balance, transaction count, first/last, freshness, top counterparties."""
    txs = txs or []
    window = activity_window(txs, summary.get("tx_count"))
    if summary.get("first_seen"):  # Blockchair reports exact first/last activity
        window.update({"first_seen": summary["first_seen"], "last_seen": summary.get("last_seen") or window["last_seen"],
                       "first_seen_exact": True})
    heights = [t["block_height"] for t in txs if t.get("block_height")]
    latest = max(heights) if heights else None
    addr = address or summary.get("address")
    cps = top_counterparties(utxo_counterparties(txs, addr), top_n) if addr else []
    return {
        "chain": chain, "provider": provider, "address": addr, "balance": summary.get("balance"),
        "total_received": summary.get("total_received"), "total_sent": summary.get("total_sent"),
        "tx_count": summary.get("tx_count"), "is_empty": bool(summary.get("is_empty")), **window,
        "freshness": {"provider": provider, "provider_tip_height": tip_height, "latest_tx_height": latest,
                      "blocks_since_latest_tx": (tip_height - latest) if tip_height and latest else None, "fetched_at": fetched_at},
        "counterparties": cps,
    }


# ======================================================================================
# per-run host short-circuit (cond 4) - in memory, per HTTP client
# ======================================================================================

_CIRCUITS: weakref.WeakKeyDictionary[Any, dict[str, tuple[float, str]]] = weakref.WeakKeyDictionary()
_CIRCUITS_LOCK = threading.RLock()
_FALLBACK_CIRCUITS: dict[str, tuple[float, str]] = {}


def _circuit_table(ctx: Any) -> dict[str, tuple[float, str]]:
    owner = getattr(getattr(ctx, "http", None), "client", None)  # v3lum-lint: allow LINT-01 -- identity key of the per-client circuit table only; no request goes through it
    try:
        with _CIRCUITS_LOCK:
            table = _CIRCUITS.get(owner)
            if table is None:
                table = {}
                _CIRCUITS[owner] = table
            return table
    except TypeError:  # an owner that cannot be weakly referenced: a process-wide table
        return _FALLBACK_CIRCUITS


def _now_ts(ctx: Any) -> float:
    try:
        return float(ctx.now().timestamp())
    except Exception:  # noqa: BLE001 - a context without a clock: wall time
        return time.time()


def short_circuit(ctx: Any, host: str, reason: str, seconds: float = RATE_LIMIT_PAUSE_S) -> None:
    """Skip ``host`` for the rest of the run after a rate limit (P211 cond 4; never cached across runs)."""
    if host:
        with _CIRCUITS_LOCK:
            _circuit_table(ctx)[host] = (_now_ts(ctx) + seconds, reason)


def circuit_reason(ctx: Any, host: str) -> str | None:
    """Why ``host`` is short-circuited in this run, or None."""
    with _CIRCUITS_LOCK:
        hit = _circuit_table(ctx).get(host)
    if not hit:
        return None
    if hit[0] < _now_ts(ctx):
        with _CIRCUITS_LOCK:
            _circuit_table(ctx).pop(host, None)
        return None
    return hit[1]


# ======================================================================================
# HTTP plumbing
# ======================================================================================


class ExplorerBudget:
    """The explorer budget of one address (cond 3), read from the run clock (``ctx.remaining``) when the
    run has a deadline, else from the monotonic clock."""

    def __init__(self, ctx: Any, total: float = EXPLORER_BUDGET_S) -> None:
        self.ctx = ctx
        self.total = total
        self.start = self._mark()

    def _mark(self) -> float:
        rem = self.ctx.remaining() if callable(getattr(self.ctx, "remaining", None)) else None
        return -float(rem) if rem is not None else time.monotonic()

    def used(self) -> float:
        return max(0.0, self._mark() - self.start)

    def left(self) -> float:
        return self.total - self.used()

    def timeout(self) -> float:
        return max(1.0, min(REQUEST_TIMEOUT_S, self.left()))


class AdapterFailure(Exception):
    """One adapter could not answer: ``status`` in rate_limited | quota | blocked | needs_key | error."""

    def __init__(self, status: str, reason: str, *, code: str = "") -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.code = code or {"rate_limited": "rate_limited", "quota": "quota", "blocked": "challenge",
                             "needs_key": "needs_key"}.get(status, "error")


def classify_exception(exc: Exception) -> tuple[str, str]:
    """Core HTTP exception -> (status, reason_code) - every one means 'could not verify' (rule 5)."""
    if isinstance(exc, RateLimited):
        return "rate_limited", "rate_limited"
    if isinstance(exc, QuotaExceeded):
        return "quota", "quota"
    if isinstance(exc, Blocked):
        code = str(getattr(exc, "reason_code", "") or "")
        return "blocked", code if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge"
    if isinstance(exc, AuthRequired):
        return "needs_key", "needs_key"
    text = str(exc).lower()
    return "error", "timeout" if "timed out" in text or "timeout" in text else "error"


def http_get(ctx: Any, url: str, *, source: str, budget: ExplorerBudget, ttl: int | None = None, params: dict[str, Any] | None = None,
             body_reason: Any = None, rate_hosts_pause: float = RATE_LIMIT_PAUSE_S) -> Any:
    """GET + classify for one adapter request. Returns the Response; raises :class:`AdapterFailure` for every
    answer that is not a usable 2xx (the reason is read from the body when ``body_reason(raw)`` gives one).
    Request caps, cancellation and the run deadline propagate (the engine keeps what was built)."""
    host = (urlsplit(url).hostname or "").lower()
    why = circuit_reason(ctx, host)
    if why:
        raise AdapterFailure("rate_limited", f"{host} short-circuited for this run ({why})")
    if budget.left() <= 0.5:
        raise AdapterFailure("error", f"explorer budget of {budget.total:.0f} s used up", code="timeout")
    kw: dict[str, Any] = {"source": source, "timeout": budget.timeout(), "headers": {"Accept": "application/json"}}
    if ttl is not None:
        kw["ttl"] = ttl
    if params:
        kw["params"] = params
    try:
        resp = ctx.http.get(url, **kw)
    except (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError) as exc:
        status, code = classify_exception(exc)
        if status == "rate_limited":
            short_circuit(ctx, host, "HTTP 429", rate_hosts_pause)
        raise AdapterFailure(status, str(exc)[:160], code=code) from None
    try:
        ctx.http.check(resp)
    except (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError) as exc:
        status, code = classify_exception(exc)
        detail = body_reason(resp.content) if callable(body_reason) else None
        if int(getattr(resp, "status", 0) or 0) in (429, 430) or status == "rate_limited":
            status, code = "rate_limited", "rate_limited"
            short_circuit(ctx, host, f"HTTP {resp.status}", BLOCKCHAIR_430_PAUSE_S if int(resp.status) == 430 else rate_hosts_pause)
        raise AdapterFailure(status, (f"HTTP {resp.status}: {detail}" if detail else str(exc))[:200], code=code) from None
    return resp


# ======================================================================================
# adapters (one call each: summary + up to 2 transaction pages + tip)
# ======================================================================================


def _esplora_error(raw: Any) -> str | None:
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else (raw if isinstance(raw, str) else "")
    obj, err = load_json(raw)
    if err is None and isinstance(obj, dict) and obj.get("error"):
        return clean_text(str(obj.get("error")), 80)
    return clean_text(text, 80) if text and not text.lstrip().startswith("<") else None


def run_esplora(ctx: Any, base: str, address: str, *, source: str, budget: ExplorerBudget, cache_ttl: int | None, cap: int) -> dict[str, Any]:
    """Esplora adapter: address stats, <= 2 transaction pages, chain tip. Returns the raw parts."""
    base = base.rstrip("/")
    paths = esplora_paths(address)
    resp = http_get(ctx, base + paths["address"], source=source, budget=budget, ttl=cache_ttl, body_reason=_esplora_error)
    summary = parse_esplora_address(resp.content)
    if summary is None:
        raise AdapterFailure("error", "unexpected Esplora address answer: could not verify")
    out: dict[str, Any] = {"summary": summary, "txs": [], "tip": None, "pages": 0, "fetched_at": fetched_at_iso(resp),
                           "from_cache": bool(getattr(resp, "from_cache", False))}
    if summary["is_empty"]:
        return out
    last: str | None = None
    for _page in range(MAX_TX_PAGES):
        if ctx.http.requests >= cap - 1 or budget.left() < 2.0:
            break
        resp = http_get(ctx, base + esplora_paths(address, last)["txs"], source=source, budget=budget, ttl=cache_ttl,
                        body_reason=_esplora_error)
        page = parse_esplora_txs(resp.content)
        if page is None:
            raise AdapterFailure("error", "unexpected Esplora transaction list: could not verify")
        out["txs"].extend(page)
        out["pages"] += 1
        last = esplora_next_txid(page, summary["tx_count"], len(out["txs"]))
        if not last or not page:
            break
    if ctx.http.requests < cap and budget.left() >= 1.5:
        try:
            resp = http_get(ctx, base + paths["tip"], source=source, budget=budget, ttl=TIP_TTL)
            out["tip"] = parse_esplora_tip_height(resp.content)
        except AdapterFailure:
            out["tip"] = None  # freshness is best effort: the address answer stands
    return out


def run_blockchain_com(ctx: Any, address: str, *, budget: ExplorerBudget, cache_ttl: int | None, cap: int) -> dict[str, Any]:
    """Blockchain.com adapter: rawaddr (summary + 50 full transactions), a second page when the budget allows."""
    url = f"https://blockchain.info/rawaddr/{quote(address, safe='')}"
    resp = http_get(ctx, url, source=SRC_BLOCKCHAIN, budget=budget, ttl=cache_ttl, params={"limit": 50, "offset": 0},
                    body_reason=blockchain_error)
    parsed = parse_blockchain_rawaddr(resp.content)
    if parsed is None:
        raise AdapterFailure("error", "unexpected Blockchain.com rawaddr answer: could not verify")
    out = {"summary": parsed["summary"], "txs": list(parsed["txs"]), "tip": None, "pages": 1, "fetched_at": fetched_at_iso(resp),
           "from_cache": bool(getattr(resp, "from_cache", False))}
    n_tx = parsed["summary"].get("tx_count") or 0
    # 1 request / 10 s sustained: a second page only when the budget still has room for the wait
    if n_tx > len(out["txs"]) and parsed["txs"] and ctx.http.requests < cap and budget.left() >= 12.0:
        try:
            resp = http_get(ctx, url, source=SRC_BLOCKCHAIN, budget=budget, ttl=cache_ttl, params={"limit": 50, "offset": 50},
                            body_reason=blockchain_error)
            more = parse_blockchain_rawaddr(resp.content)
            if more:
                out["txs"].extend(more["txs"])
                out["pages"] = 2
        except AdapterFailure:
            pass  # the first page answered: keep it
    return out


def run_blockcypher(ctx: Any, chain: str, address: str, *, budget: ExplorerBudget, cache_ttl: int | None, cap: int) -> dict[str, Any]:
    """BlockCypher adapter: /full (inputs/outputs), <= 2 pages (before=<height>), chain tip."""
    coin = BLOCKCYPHER_COIN[chain]
    token = str(ctx.key(KEY_BLOCKCYPHER) or "").strip()
    params: dict[str, Any] = {"limit": 50}
    if token:
        params["token"] = token  # redacted by AR01 (key-like parameter and registered key value)
    url = f"https://api.blockcypher.com/v1/{coin}/main/addrs/{quote(address, safe='')}/full"
    resp = http_get(ctx, url, source=SRC_BLOCKCYPHER, budget=budget, ttl=cache_ttl, params=params, body_reason=blockcypher_error)
    parsed = parse_blockcypher_full(resp.content)
    if parsed is None:
        raise AdapterFailure("error", "unexpected BlockCypher answer: could not verify")
    out = {"summary": parsed["summary"], "txs": list(parsed["txs"]), "tip": None, "pages": 1, "fetched_at": fetched_at_iso(resp),
           "from_cache": bool(getattr(resp, "from_cache", False))}
    if parsed["summary"].get("is_empty"):
        return out
    before = blockcypher_next_before(parsed)
    if before and ctx.http.requests < cap - 1 and budget.left() >= 2.0:
        try:
            resp = http_get(ctx, url, source=SRC_BLOCKCYPHER, budget=budget, ttl=cache_ttl, params=dict(params, before=before),
                            body_reason=blockcypher_error)
            more = parse_blockcypher_full(resp.content)
            if more:
                seen = {t["txid"] for t in out["txs"]}
                out["txs"].extend(t for t in more["txs"] if t["txid"] not in seen)
                out["pages"] = 2
        except AdapterFailure:
            pass
    if ctx.http.requests < cap and budget.left() >= 1.5:
        try:
            tip_params = {"token": token} if token else None
            resp = http_get(ctx, f"https://api.blockcypher.com/v1/{coin}/main", source=SRC_BLOCKCYPHER, budget=budget, ttl=TIP_TTL,
                            params=tip_params)
            chain_info = parse_blockcypher_chain(resp.content)
            out["tip"] = chain_info["height"] if chain_info else None
        except AdapterFailure:
            out["tip"] = None
    return out


def run_blockchair(ctx: Any, chain: str, address: str, *, budget: ExplorerBudget, cache_ttl: int | None) -> dict[str, Any]:
    """Blockchair adapter (commercial key only): address dashboard with exact first/last activity."""
    key = str(ctx.key(KEY_BLOCKCHAIR) or "").strip()
    if not key:
        raise AdapterFailure("needs_key", "Blockchair runs only with the commercial key 'blockchair'")
    url = f"https://api.blockchair.com/{BLOCKCHAIR_CHAIN[chain]}/dashboards/address/{quote(address, safe='')}"
    resp = http_get(ctx, url, source=SRC_BLOCKCHAIR, budget=budget, ttl=cache_ttl, params={"limit": 10, "key": key},
                    body_reason=lambda raw: (blockchair_status(raw) or (None, None))[1], rate_hosts_pause=BLOCKCHAIR_430_PAUSE_S)
    problem = blockchair_status(resp.content, int(getattr(resp, "status", 200) or 200))
    if problem:
        if problem[0] == "rate_limited":
            short_circuit(ctx, "api.blockchair.com", problem[1], BLOCKCHAIR_430_PAUSE_S)
        raise AdapterFailure(problem[0], problem[1])
    parsed = parse_blockchair_dashboard(resp.content, address)
    if parsed is None:
        raise AdapterFailure("error", "unexpected Blockchair dashboard: could not verify")
    return {"summary": parsed["summary"], "txs": [], "txids": parsed["txids"], "tip": parsed["context"]["tip_height"], "pages": 1,
            "fetched_at": fetched_at_iso(resp), "from_cache": bool(getattr(resp, "from_cache", False))}


def fetched_at_iso(resp: Any) -> str | None:
    value = getattr(resp, "fetched_at", None)
    if isinstance(value, _dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=_dt.timezone.utc)
        return value.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return norm_time(value) if value else None


def esplora_base_urls(ctx: Any) -> dict[str, str]:
    """The configured self-hosted Esplora base URLs per chain (https only; anything else is ignored)."""
    out: dict[str, str] = {}
    for chain, setting in (("btc", SETTING_ESPLORA_BTC), ("ltc", SETTING_ESPLORA_LTC)):
        value = str(ctx.setting(setting, "") or "").strip()
        if not value:
            continue
        try:
            parts = urlsplit(value)
        except ValueError:
            continue
        if parts.scheme == "https" and parts.hostname and not parts.username and not parts.query and not parts.fragment:
            out[chain] = value.rstrip("/")
    return out


# ======================================================================================
# the shared run (both classes)
# ======================================================================================


def explore(module: Module, entity: Entity, ctx: Any, *, internal_only: bool) -> ModuleResult:
    res = module.result(entity)
    address = str(entity.value).strip()
    chain = address_chain(address)
    if chain is None:
        return res.mark("skipped", "not a checksummed mainnet BTC/LTC/DOGE/DASH address (core P217 validator): never sent",
                        reason_code="not_applicable")
    name, ticker, decimals = CHAINS[chain]
    urls = esplora_base_urls(ctx)
    keys = {k for k in (KEY_BLOCKCHAIR,) if str(ctx.key(k) or "").strip()}
    allowed = ctx.allowed_sources
    full_plan = utxo_failover_plan(chain, urls, keys, internal_only=internal_only)
    plan = utxo_failover_plan(chain, urls, keys, internal_only=internal_only, allowed=allowed)
    res.attr("chain", name)
    if not plan:
        return _no_plan(res, chain, full_plan, internal_only)
    # adapters outside ctx.allowed_sources are reported by the engine as coverage rows 'licence' (wave 2)
    budget = ExplorerBudget(ctx)
    cap = int(getattr(module, "max_requests", 10) or 10)
    attempts: list[dict[str, Any]] = []
    answer: dict[str, Any] | None = None
    answered_by = ""
    for prov in plan:
        spec = UTXO_PROVIDERS[prov]
        before = ctx.http.requests
        start = budget.used()
        try:
            if prov == "esplora_internal":
                data = run_esplora(ctx, urls[chain], address, source=spec["source"], budget=budget, cache_ttl=module.cache_ttl, cap=cap)
            elif prov in ("blockstream", "mempool", "litecoinspace"):
                data = run_esplora(ctx, spec["base"], address, source=spec["source"], budget=budget, cache_ttl=module.cache_ttl, cap=cap)
            elif prov == "blockchain_com":
                data = run_blockchain_com(ctx, address, budget=budget, cache_ttl=module.cache_ttl, cap=cap)
            elif prov == "blockcypher":
                data = run_blockcypher(ctx, chain, address, budget=budget, cache_ttl=module.cache_ttl, cap=cap)
            else:
                data = run_blockchair(ctx, chain, address, budget=budget, cache_ttl=module.cache_ttl)
        except AdapterFailure as exc:
            attempts.append({"provider": prov, "source": spec["source"], "status": exc.status, "reason": exc.reason,
                             "elapsed_s": round(budget.used() - start, 3), "sent": ctx.http.requests > before or _sent_any(ctx, spec)})
            res.source_status(spec["source"], _STATUS[exc.status], reason_code=exc.code, reason=f"{prov}: {exc.reason}"[:240])
            if budget.left() <= 0.5:
                break
            continue
        status = "empty" if data["summary"].get("is_empty") else "ok"
        attempts.append({"provider": prov, "source": spec["source"], "status": status, "reason": None,
                         "elapsed_s": round(budget.used() - start, 3), "sent": ctx.http.requests > before})
        answer, answered_by = data, prov
        break
    report = failover_report(attempts)
    res.attr("explorer_failover", report)
    res.attr("disclosed_to", report["disclosed_to"])
    if answer is None:
        statuses = [a["status"] for a in attempts]
        st = worst_status(statuses)
        detail = "; ".join(f"{a['provider']}: {a['reason']}" for a in attempts)[:400]
        code = next((c for c in (_code_of(a) for a in attempts if a["status"] == st) if c), "error")
        return res.mark(_STATUS[st], f"no explorer answered: could not verify ({detail})", reason_code=code)
    return _summarise(module, res, chain, answered_by, answer, address, ticker, decimals, ctx)


_STATUS = {"rate_limited": Status.RATE_LIMITED, "quota": Status.QUOTA, "blocked": Status.BLOCKED, "needs_key": Status.NEEDS_KEY,
           "error": Status.ERROR, "skipped": Status.SKIPPED}


def _code_of(attempt: dict[str, Any]) -> str:
    st = attempt.get("status")
    if st == "error" and "budget" in str(attempt.get("reason") or ""):
        return "timeout"
    return {"rate_limited": "rate_limited", "quota": "quota", "blocked": "challenge", "needs_key": "needs_key"}.get(str(st), "error")


def _sent_any(ctx: Any, spec: dict[str, Any]) -> bool:
    host = spec.get("host")
    if not host:
        return False
    hosts = getattr(ctx.http, "hosts", None)
    try:
        return bool(hosts and hosts.get(host))
    except AttributeError:
        return False


def _no_plan(res: ModuleResult, chain: str, full_plan: list[str], internal_only: bool) -> ModuleResult:
    if internal_only:
        return res.mark("skipped", f"no self-hosted Esplora configured for {chain.upper()} (set {SETTING_ESPLORA_BTC if chain == 'btc' else SETTING_ESPLORA_LTC}, https)",
                        reason_code="config" if chain in ("btc", "ltc") else "not_applicable")
    if full_plan:
        names = ", ".join(full_plan)
        return res.mark("skipped", f"no explorer for {chain.upper()} is allowed by the licence profile ({names}: key-terms sources need "
                                   "a business key plan in key_plans, e.g. `v3lum keys set blockcypher --plan business`)", reason_code="licence")
    return res.mark("skipped", f"no explorer configured for {chain.upper()} in this build", reason_code="not_applicable")


def _summarise(module: Module, res: ModuleResult, chain: str, provider: str, data: dict[str, Any], address: str, ticker: str,
               decimals: int, ctx: Any) -> ModuleResult:
    summ = build_utxo_summary(chain, provider, data["summary"], data.get("txs"), data.get("tip"), data.get("fetched_at"), address=address)
    as_of = ctx.now().date().isoformat()
    balance = summ["balance"]
    res.attr("balance", f"{units_str(balance, decimals)} {ticker}" if balance is not None else None)
    res.attr("balance_base_units", str(balance) if balance is not None else None)
    for key in ("total_received", "total_sent"):
        v = summ.get(key)
        res.attr(key, f"{units_str(v, decimals)} {ticker}" if v is not None else None)
    if summ["tx_count"] is not None:
        res.attr("tx_count", summ["tx_count"])
    window = {k: summ[k] for k in ("first_seen", "last_seen", "first_seen_exact", "txs_examined")}
    res.attr("activity_window", window)
    if summ["first_seen"] and summ["first_seen_exact"]:
        res.attr("first_seen", summ["first_seen"])
    if summ["last_seen"]:
        res.attr("last_seen", summ["last_seen"])
    fresh = dict(summ["freshness"], from_cache=bool(data.get("from_cache")))
    res.attr("data_freshness", fresh)
    label, page = EXPLORER_PAGES[chain]
    res.link(label, page.format(a=quote(address, safe="")))
    res.raw = {"provider": provider, "source": UTXO_PROVIDERS[provider]["source"], "summary": data["summary"],
               "txids": [t["txid"] for t in data.get("txs") or []][:100] or list(data.get("txids") or [])[:50],
               "pages": data.get("pages"), "tip_height": data.get("tip")}
    if summ["is_empty"]:
        res.attr("wallet_status", f"no transactions on-chain per {provider} (as of {as_of})")
        return res.mark("empty")
    tops = []
    ptype = T.BTC if chain == "btc" else T.CRYPTO
    for cp in summ["counterparties"]:
        tops.append({"address": cp["address"], "direction": cp["direction"],
                     "received_from": f"{units_str(cp['received_from'], decimals)} {ticker}",
                     "sent_to": f"{units_str(cp['sent_to'], decimals)} {ticker}", "tx_count": cp["tx_count"],
                     "in_tx_count": cp["in_tx_count"], "out_tx_count": cp["out_tx_count"],
                     "first_seen": cp["first_seen"], "last_seen": cp["last_seen"], "label": cp["label"]})
        res.pivot(ptype, cp["address"], "transacted_with", confidence="probable", expand=False,
                  note=f"{COUNTERPARTY_LABEL}: direction {cp['direction']}, {cp['tx_count']} tx in the {summ['txs_examined']} newest read (P213 decides expansion)")
    res.attr("top_counterparties", tops)
    examined = summ["txs_examined"]
    sample = (f"Only the {examined} newest transactions were read (<= {MAX_TX_PAGES} pages): counterparties and the first "
              "activity are a sample." if examined and summ["tx_count"] and examined < summ["tx_count"] else "")
    res.finding(
        f"On-chain summary from {provider}",
        "info",
        (f"{CHAINS[chain][0].title()} address: balance {res.attributes.get('balance')}, {summ['tx_count']} transactions, "
         f"last activity {summ['last_seen'] or 'unknown'} (provider {provider}, tip {summ['freshness']['provider_tip_height']}). "
         f"{sample} Balances are never compared across providers (indexers differ, e.g. the genesis coinbase).").strip(),
        confidence="confirmed",
        source=UTXO_PROVIDERS[provider]["source"],
        data={"provider": provider, "tx_count": summ["tx_count"], "txs_examined": examined},
        observed_first=summ["first_seen"] if summ["first_seen_exact"] else None,
        observed_last=summ["last_seen"],
    )
    return res


# ======================================================================================
# the modules
# ======================================================================================


@register
class BtcExplorers(Module):
    name = "btc_explorers"
    title = "Bitcoin/Litecoin/Dogecoin/Dash explorers (Esplora, Blockchain.com, BlockCypher, Blockchair)"
    description = (
        "Balance, transaction count, first/last activity, data freshness and the top 10 counterparties of a BTC/LTC/DOGE/DASH "
        "address from one explorer at a time: a self-hosted Esplora first, then Blockstream, mempool.space/litecoinspace, "
        "Blockchain.com, BlockCypher and (commercial key) Blockchair - sequential failover only on errors."
    )
    category = "crypto"
    accepts = {T.BTC, T.CRYPTO}
    produces = {T.BTC, T.CRYPTO}
    tags = {"free"}
    reference = "https://github.com/Blockstream/esplora/blob/master/API.md"
    notice = (
        "Explorer operators see which addresses you look up: configure a self-hosted Esplora (btc_explorers_esplora_url) for "
        "sensitive cases (btc_esplora_internal covers TLP:AMBER+STRICT and RED). Only one public explorer receives the address "
        "unless it fails; attribute disclosed_to lists them. BlockCypher and Blockchair are key-terms sources (company plans "
        "recorded in key_plans); Blockchair runs only with its commercial key. Counterparties are listed, never expanded "
        "automatically, and their own histories are never fetched."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "blockstream"
    sources = (SRC_INTERNAL, SRC_BLOCKSTREAM, SRC_MEMPOOL, SRC_LITECOINSPACE, SRC_BLOCKCHAIN, SRC_BLOCKCYPHER, SRC_BLOCKCHAIR)
    hosts = ("blockstream.info", "mempool.space", "litecoinspace.org", "blockchain.info", "api.blockcypher.com", "api.blockchair.com")
    access_model = "free_noauth_limited"
    optional_keys = (KEY_BLOCKCYPHER, KEY_BLOCKCHAIR)
    max_requests = 10
    expected_latency = 1.5
    timeout = 25.0
    cache_ttl = 3600
    max_pivots = TOP_COUNTERPARTIES
    default_enabled = True
    settings = {
        SETTING_ESPLORA_BTC: SettingSpec("", "Self-hosted Esplora base URL for Bitcoin (https, e.g. https://esplora.corp.example/api): "
                                             "always tried first by btc_explorers, the only source of btc_esplora_internal"),
        SETTING_ESPLORA_LTC: SettingSpec("", "Self-hosted Esplora base URL for Litecoin (https): tried first for LTC addresses"),
    }

    @classmethod
    def health_check(cls) -> HealthCheck:
        # the genesis-block address: public, benign, always answered (verified live 2026-11-26)
        return HealthCheck(T.BTC, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return address_chain(entity.value) is not None  # cond 4: an invalid or non-UTXO address is never sent

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        return explore(self, entity, ctx, internal_only=False)


@register
class BtcEsploraInternal(Module):
    name = "btc_esplora_internal"
    title = "Self-hosted Esplora (BTC/LTC) for restricted cases"
    description = (
        "The organisation's own Esplora/electrs instance only (no public failover): balance, transactions, first/last activity "
        "and counterparties of a BTC/LTC address for TLP:AMBER+STRICT and RED cases."
    )
    category = "crypto"
    accepts = {T.BTC, T.CRYPTO}
    produces = {T.BTC, T.CRYPTO}
    tags = {"free"}
    reference = "https://github.com/Blockstream/esplora/blob/master/API.md"
    notice = (
        "Runs only at TLP:AMBER+STRICT and RED (btc_explorers tries the same self-hosted instance first at lower TLPs). Needs "
        "the https setting btc_explorers_esplora_url (BTC) and/or btc_explorers_esplora_ltc_url (LTC); never falls back to a "
        "public explorer."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "internal"
    provider = "internal_esplora"
    sources = (SRC_INTERNAL,)
    hosts = ()
    access_model = "internal"
    max_requests = 4
    expected_latency = 0.5
    timeout = 20.0
    cache_ttl = 3600
    max_pivots = TOP_COUNTERPARTIES
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        chain = address_chain(entity.value)
        return chain in ("btc", "ltc") and str(getattr(ctx, "tlp", "red") or "red") in ("amber+strict", "red")

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        return explore(self, entity, ctx, internal_only=True)


__all__ = [
    "BtcEsploraInternal",
    "BtcExplorers",
    "EXPLORER_BUDGET_S",
    "UTXO_PROVIDERS",
    "address_chain",
    "build_utxo_summary",
    "failover_report",
    "multiaddr_active_param",
    "parse_blockchain_balance",
    "parse_blockchain_multiaddr",
    "parse_blockchain_rawaddr",
    "parse_blockchair_dashboard",
    "parse_blockcypher_chain",
    "parse_blockcypher_full",
    "parse_esplora_address",
    "parse_esplora_tip_height",
    "parse_esplora_txs",
    "should_failover",
    "top_counterparties",
    "units_str",
    "utxo_counterparties",
    "utxo_failover_plan",
]
