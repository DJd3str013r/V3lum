"""EVM explorers with sequential failover (P212): Blockscout v2, Etherscan V2, Ethplorer, PublicNode JSON-RPC.

Final conditions (council #1, P212) and where they live:

1. Blockscout v2 (eth.blockscout.com; keyless; ``is_scam``, public tags, ENS, ``/search?q=`` for ``name.eth``)
   first; Etherscan V2 (``chainid=1``) only with key ``etherscan``; Ethplorer only with the team's own key
   ``ethplorer`` - the shared ``freekey`` test key is refused even when configured; OKLink only with key
   ``oklink`` **and** a recorded success fixture: none exists yet (keyless answers 401), so the adapter is not
   shipped (:data:`OKLINK_READY` False, docs/backlog/p2-G09-2.md). :func:`evm_failover_plan`.
2. Balance and code (contract vs EOA) from PublicNode or the configured ``eth_rpc`` setting through the ONE
   EVM JSON-RPC helper shared with crypto_sanctions (P205: :class:`~v3lum.modules.crypto.crypto_sanctions_onchain.JsonRpc`,
   read-only methods, batch with an ``eth_chainId`` guard). EIP-55 display through the core P217 pure-Python
   Keccak-256 (``v3lum.core.validators.eip55_checksum``; ``hashlib.sha3_256`` is not Keccak); a mixed-case
   address whose EIP-55 checksum fails is a typo and is never sent.
3. Etherscan HTTP 200 with status '0' ('NOTOK', 'Missing/Invalid API Key', rate limits, credits) is ERROR,
   RATE_LIMITED or QUOTA through the P321 markers of the registry fragment (``evm_explorers_etherscan_*``)
   and :func:`etherscan_problem` - never empty, except Etherscan's documented 'No transactions found' with an
   empty result. Keys travel in query strings only after AR01 redaction (``apikey=``, ``apiKey=`` are
   key-like parameters and the configured values are registered secrets). Per-provider status in
   ``explorer_failover`` / ``res.source_status``; per-host P334 politeness in the provider fragments.
4. The first explorer that answers wins (sequential, only on failure), within the 15 s budget per address
   (:data:`~v3lum.modules.crypto.btc_explorers.EXPLORER_BUDGET_S`). Summary: balance, top 5 token holdings by
   fiat value, transaction count, first/last activity, contract vs EOA; Blockscout ``is_scam``/reputation and
   suspicious public tags become findings naming the source (fraud high / suspicious medium); counterparties
   are ``transacted_with`` pivots with ``expand=False`` (P213 decides expansion) and a contract's creator is
   an ``eth_address`` pivot (``contract_creator``) with ``expand=False``.
5. Per-adapter classes (A1 BR3): Blockscout keyless and the PublicNode RPC 'open'; Etherscan, Ethplorer and
   OKLink 'key-terms' (module terms 'key-terms'); tiers Etherscan, OKLink and PublicNode trusted, Blockscout
   and Ethplorer community (module tier community). The policy gate narrows ``ctx.allowed_sources``.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote, urlsplit

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, HttpError, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, Module, register
from v3lum.core.validators import crypto_address_info, eip55_checksum, keccak256
from v3lum.modules.crypto.btc_explorers import (
    COUNTERPARTY_LABEL,
    EXPLORER_BUDGET_S,
    TOP_COUNTERPARTIES,
    AdapterFailure,
    ExplorerBudget,
    addr_key,
    classify_exception,
    clean_text,
    direction_of,
    failover_report,
    fetched_at_iso,
    http_get,
    iso_utc,
    load_json,
    norm_time,
    to_int,
    units_str,
    worst_status,
)
from v3lum.modules.crypto.crypto_sanctions_onchain import DEFAULT_ETH_RPC, JsonRpc, rpc_error

SRC_BLOCKSCOUT = "blockscout.api_v2"
SRC_RPC = "publicnode.ethereum_rpc"
SRC_ETHERSCAN = "etherscan.api"
SRC_ETHPLORER = "ethplorer.api"
KEY_ETHERSCAN = "etherscan"
KEY_ETHPLORER = "ethplorer"
KEY_OKLINK = "oklink"
BLOCKSCOUT = "https://eth.blockscout.com/api/v2"
ETHERSCAN = "https://api.etherscan.io/v2/api"
ETHPLORER = "https://api.ethplorer.io/getAddressInfo/{address}"
ETH_CHAIN_ID = 1
TOP_TOKENS = 5
SHARED_TEST_KEYS = frozenset({"freekey"})  # Ethplorer's public test key: never used (P212 cond 1)
#: OKLink ships only with a recorded keyed success fixture (P212 cond 1): none exists in this build.
OKLINK_READY = False

#: P212 cond 5 (terms) and the registry tiers.
EVM_PROVIDERS: dict[str, dict[str, Any]] = {
    "blockscout": {"source": SRC_BLOCKSCOUT, "host": "eth.blockscout.com", "terms": "open", "tier": "community", "key": None},
    "eth_rpc": {"source": SRC_RPC, "host": "ethereum-rpc.publicnode.com", "terms": "open", "tier": "trusted", "key": None},
    "etherscan": {"source": SRC_ETHERSCAN, "host": "api.etherscan.io", "terms": "key-terms", "tier": "trusted", "key": KEY_ETHERSCAN},
    "ethplorer": {"source": SRC_ETHPLORER, "host": "api.ethplorer.io", "terms": "key-terms", "tier": "community", "key": KEY_ETHPLORER},
    "oklink": {"source": "", "host": "www.oklink.com", "terms": "key-terms", "tier": "trusted", "key": KEY_OKLINK},
}
SUSPICIOUS_TAG_RE = re.compile(r"phish|hack|exploit|scam|fraud|drainer|heist|fake|ponzi|rug|spam", re.I)
EXCHANGE_TAG_RE = re.compile(r"exchange|binance|coinbase|kraken|okx|bybit|bitfinex|huobi|htx|kucoin|gate\.io|bitso|mercado ?bitcoin|\bcex\b", re.I)
MIXER_TAG_RE = re.compile(r"mixer|tornado|coinjoin|blender|sinbad", re.I)
SANCTION_TAG_RE = re.compile(r"sanction|ofac|\bsdn\b", re.I)
ETHERSCAN_EMPTY = re.compile(r"^no (transactions|records|token transfers|internal transactions)( found)?\.?$", re.I)
ENS_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+eth$")


# ======================================================================================
# plan, addresses, ENS (cond 1, 2)
# ======================================================================================


def evm_failover_plan(keys: Any = (), allowed: Any = None, oklink_ready: bool = OKLINK_READY) -> list[str]:
    """Explorer order (cond 1): Blockscout keyless first, then Etherscan/Ethplorer with their keys; OKLink
    only with its key AND a recorded success fixture. The JSON-RPC call is complementary, not a step."""
    keys = set(keys or ())
    plan = ["blockscout"]
    if KEY_ETHERSCAN in keys:
        plan.append("etherscan")
    if KEY_ETHPLORER in keys:
        plan.append("ethplorer")
    if KEY_OKLINK in keys and oklink_ready:
        plan.append("oklink")
    if allowed is not None:
        ok = set(allowed)
        plan = [p for p in plan if EVM_PROVIDERS[p]["source"] in ok]
    return plan


def evm_address(value: Any) -> str | None:
    """The lower-case address of a valid EVM value; None for junk or a mixed-case EIP-55 mismatch (a typo:
    never sent)."""
    if not isinstance(value, str):
        return None
    info = crypto_address_info(value.strip())
    if info is None or info.chain != "eth" or info.checksum_ok is False:
        return None
    return value.strip().lower()


def eip55(address: str) -> str:
    """EIP-55 display form with the core pure-Python Keccak-256 (P217)."""
    try:
        return eip55_checksum(address)
    except (ValueError, TypeError):
        return address


def ens_name(value: Any) -> str | None:
    """A syntactically valid ``*.eth`` ENS name (lower case), else None."""
    if not isinstance(value, str):
        return None
    v = value.strip().lower().rstrip(".")
    return v if len(v) <= 255 and ENS_RE.fullmatch(v) else None


def keccak_is_not_sha3(sample: bytes = b"") -> bool:
    """Self-check used by tests: Keccak-256('') = c5d2...a470, NIST SHA3-256('') differs."""
    import hashlib

    return keccak256(sample).hex() != hashlib.sha3_256(sample).hexdigest()


# ======================================================================================
# Blockscout v2 (cond 1, 4)
# ======================================================================================


def _bs_tags(obj: dict[str, Any]) -> list[dict[str, Any]]:
    tags = []
    for t in obj.get("public_tags") or []:
        if isinstance(t, dict):
            label = t.get("display_name") or t.get("label") or t.get("name")
            if label:
                tags.append({"label": clean_text(str(label), 80), "slug": clean_text(str(t.get("label") or label), 80),
                             "kind": "public_tag", "source": "public_tags"})
    meta = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
    for t in meta.get("tags") or []:
        if isinstance(t, dict) and t.get("name"):
            tags.append({"label": clean_text(str(t["name"]), 80), "slug": clean_text(str(t.get("slug") or ""), 80),
                         "kind": clean_text(str(t.get("tagType") or "tag"), 30), "source": "metadata"})
    return tags


def parse_blockscout_address(raw: Any) -> dict[str, Any] | None:
    """GET /api/v2/addresses/{a} -> facts. ``known`` False when Blockscout never saw the address (HTTP 200 with
    null balance/creation fields and no logs/tokens, observed live) - an absence, not an error."""
    obj, err = load_json(raw)
    if err or not isinstance(obj, dict) or not isinstance(obj.get("hash"), str):
        return None
    tok = obj.get("token") if isinstance(obj.get("token"), dict) else None
    known = any([obj.get("coin_balance") is not None, obj.get("creation_status") is not None, bool(obj.get("has_logs")),
                 bool(obj.get("has_tokens")), bool(obj.get("has_token_transfers")), bool(obj.get("is_contract")),
                 obj.get("block_number_balance_updated_at") is not None])
    creator = obj.get("creator_address_hash")
    return {
        "address": obj["hash"], "known": known, "balance_wei": to_int(obj.get("coin_balance")),
        "is_contract": bool(obj.get("is_contract")), "is_verified": bool(obj.get("is_verified")),
        "is_scam": bool(obj.get("is_scam")), "reputation": clean_text(obj.get("reputation"), 30),
        "ens_name": clean_text(obj.get("ens_domain_name"), 255), "name": clean_text(obj.get("name"), 120),
        "creator_address": creator if isinstance(creator, str) else None,
        "creation_tx": obj.get("creation_transaction_hash") if isinstance(obj.get("creation_transaction_hash"), str) else None,
        "tags": _bs_tags(obj),
        "token": {k: clean_text(str(tok.get(k)), 60) for k in ("symbol", "name", "type") if tok.get(k) is not None} if tok else None,
        "balance_block": to_int(obj.get("block_number_balance_updated_at")),
    }


def blockscout_findings(addr: dict[str, Any] | None) -> dict[str, Any]:
    """is_scam / reputation / public tags -> findings naming the source (cond 4) and plain labels.

    Sanctions-looking labels stay informational (the sanctions tag belongs to crypto_sanctions, P205);
    exchange/mixer labels are returned as a stop-node hint for P213."""
    if not addr:
        return {"findings": [], "labels": [], "stop_node": None}
    findings, labels, stop = [], [], None
    if addr.get("is_scam") or str(addr.get("reputation") or "").lower() == "scam":
        findings.append({"kind": "scam", "severity": "high", "tags": ["fraud", "crypto_scam"],
                         "title": "Blockscout flags this address as a scam",
                         "evidence": {"is_scam": bool(addr.get("is_scam")), "reputation": addr.get("reputation")}})
    for t in addr.get("tags") or []:
        text = f"{t.get('label') or ''} {t.get('slug') or ''}"
        if t.get("label") and t["label"] not in labels:
            labels.append(t["label"])
        if SANCTION_TAG_RE.search(text):
            findings.append({"kind": "sanctions_label", "severity": "info", "tags": ["context_only"],
                             "title": "Blockscout label mentions sanctions (not authoritative)", "label": t["label"]})
        elif SUSPICIOUS_TAG_RE.search(text):
            findings.append({"kind": "suspicious_label", "severity": "medium", "tags": ["suspicious"],
                             "title": "Blockscout public tag marks the address as suspicious", "label": t["label"]})
        elif MIXER_TAG_RE.search(text):
            stop = stop or "mixer"
        elif EXCHANGE_TAG_RE.search(text):
            stop = stop or "exchange"
    return {"findings": findings, "labels": labels, "stop_node": stop}


def _bs_party(p: Any) -> tuple[str | None, dict[str, Any]]:
    if not isinstance(p, dict):
        return None, {}
    h = p.get("hash")
    return (h if isinstance(h, str) else None), {"labels": [t["label"] for t in _bs_tags(p) if t.get("label")],
                                                 "is_contract": bool(p.get("is_contract")), "is_scam": bool(p.get("is_scam"))}


def parse_blockscout_txs(raw: Any) -> dict[str, Any] | None:
    """GET /api/v2/addresses/{a}/transactions -> {txs, next_page_params} (50 per page observed)."""
    obj, err = load_json(raw)
    if err or not isinstance(obj, dict) or not isinstance(obj.get("items"), list):
        return None
    txs = []
    for it in obj["items"]:
        if not isinstance(it, dict) or not isinstance(it.get("hash"), str):
            continue
        frm, finfo = _bs_party(it.get("from"))
        to, tinfo = _bs_party(it.get("to"))
        created = it.get("created_contract")
        txs.append({"hash": it["hash"], "time": norm_time(it.get("timestamp")), "block": to_int(it.get("block_number")),
                    "from": frm, "to": to, "value_wei": to_int(it.get("value")) or 0, "ok": it.get("status") == "ok",
                    "method": clean_text(it.get("method"), 60),
                    "created_contract": created.get("hash") if isinstance(created, dict) else None,
                    "from_info": finfo, "to_info": tinfo})
    npp = obj.get("next_page_params")
    return {"txs": txs, "next_page_params": npp if isinstance(npp, dict) else None}


def parse_blockscout_search(raw: Any, query: str) -> dict[str, Any] | None:
    """GET /api/v2/search?q=name.eth -> exact ENS resolution only (token hits named like the query are not)."""
    obj, err = load_json(raw)
    if err or not isinstance(obj, dict) or not isinstance(obj.get("items"), list) or not isinstance(query, str):
        return None
    q = query.strip().lower()
    for it in obj["items"]:
        if not isinstance(it, dict) or it.get("type") != "ens_domain":
            continue
        ens = it.get("ens_info") if isinstance(it.get("ens_info"), dict) else {}
        name = str(ens.get("name") or it.get("name") or "").lower()
        if name == q:
            return {"query": query, "ens_name": ens.get("name"), "address": ens.get("address_hash") or it.get("address_hash"),
                    "names_count": to_int(ens.get("names_count")), "expiry": norm_time(ens.get("expiry_date")),
                    "is_contract": bool(it.get("is_smart_contract_address"))}
    return {"query": query, "ens_name": None, "address": None}


def _to_float(v: Any) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if f == f and f not in (float("inf"), float("-inf")) else None


def parse_blockscout_token_balances(raw: Any) -> list[dict[str, Any]] | None:
    """GET /api/v2/addresses/{a}/token-balances -> holdings (documented schema; live call timed out, prep notes)."""
    obj, err = load_json(raw)
    if err or not isinstance(obj, list):
        return None
    out = []
    for it in obj:
        tok = it.get("token") if isinstance(it, dict) and isinstance(it.get("token"), dict) else None
        if tok is None:
            continue
        dec, val, rate = to_int(tok.get("decimals")), to_int(it.get("value")), _to_float(tok.get("exchange_rate"))
        fiat = (val / 10 ** dec * rate) if (val is not None and dec is not None and rate is not None) else None
        out.append({"token_address": tok.get("address_hash") or tok.get("address"), "symbol": clean_text(tok.get("symbol"), 20),
                    "name": clean_text(str(tok.get("name") or ""), 80), "type": clean_text(tok.get("type") or tok.get("token_type"), 20),
                    "amount": units_str(val, dec) if (val is not None and dec is not None) else None,
                    "fiat_value": round(fiat, 2) if fiat is not None else None})
    return out


def parse_blockscout_counters(raw: Any) -> dict[str, Any] | None:
    """GET /api/v2/addresses/{a}/counters -> transaction count (counts are strings in Blockscout v2)."""
    obj, err = load_json(raw)
    if err or not isinstance(obj, dict) or "transactions_count" not in obj:
        return None
    return {"tx_count": to_int(obj.get("transactions_count")), "token_transfers_count": to_int(obj.get("token_transfers_count"))}


def top_token_holdings(holdings: list[dict[str, Any]] | None, n: int = TOP_TOKENS) -> list[dict[str, Any]]:
    """Top-N holdings by fiat value; unpriced tokens (often airdropped spam) rank last (cond 4)."""
    ranked = sorted(holdings or [], key=lambda h: (h.get("fiat_value") is None, -(h.get("fiat_value") or 0),
                                                   0 if h.get("type") == "ERC-20" else 1, str(h.get("symbol"))))
    return ranked[:n]


def labels_from_txs(txs: list[dict[str, Any]], address: str) -> list[str]:
    """The address's own Blockscout labels as seen in transaction party objects (the address endpoint returned
    metadata=null for the EF multisig while its transaction items carried 'Ethereum Foundation')."""
    me = addr_key(address)
    labels: list[str] = []
    for tx in txs or []:
        for side, info in (("from", tx.get("from_info") or {}), ("to", tx.get("to_info") or {})):
            if addr_key(tx.get(side)) == me:
                for lab in info.get("labels") or []:
                    if lab not in labels:
                        labels.append(lab)
    return labels


def evm_counterparties(txs: list[dict[str, Any]], address: str) -> list[dict[str, Any]]:
    """Depth-1 counterparties (native value; a failed transaction counts as an interaction with 0 value)."""
    me = addr_key(address)
    agg: dict[str, dict[str, Any]] = {}
    for tx in txs or []:
        frm, to = addr_key(tx.get("from")), addr_key(tx.get("to"))
        if frm == me and to and to != me:
            other, info, direction = tx.get("to"), tx.get("to_info") or {}, "out"
        elif to == me and frm and frm != me:
            other, info, direction = tx.get("from"), tx.get("from_info") or {}, "in"
        else:
            continue
        value = (tx.get("value_wei") or 0) if tx.get("ok", True) else 0
        rec = agg.setdefault(addr_key(other) or str(other), {"address": other, "received_from_wei": 0, "sent_to_wei": 0, "tx_count": 0,
                                                             "in_tx_count": 0, "out_tx_count": 0, "first_seen": None, "last_seen": None,
                                                             "labels": [], "is_contract": False, "is_scam": False})
        if direction == "in":
            rec["received_from_wei"] += value
            rec["in_tx_count"] += 1
        else:
            rec["sent_to_wei"] += value
            rec["out_tx_count"] += 1
        rec["tx_count"] += 1
        for lab in info.get("labels") or []:
            if lab not in rec["labels"]:
                rec["labels"].append(lab)
        rec["is_contract"] = rec["is_contract"] or bool(info.get("is_contract"))
        rec["is_scam"] = rec["is_scam"] or bool(info.get("is_scam"))
        t = tx.get("time")
        if t:
            rec["first_seen"] = min(x for x in (rec["first_seen"], t) if x)
            rec["last_seen"] = max(x for x in (rec["last_seen"], t) if x)
    out = []
    for rec in agg.values():
        rec["total_wei"] = rec["received_from_wei"] + rec["sent_to_wei"]
        rec["direction"] = direction_of(rec["in_tx_count"], rec["out_tx_count"])
        out.append(rec)
    return sorted(out, key=lambda r: (-r["total_wei"], -r["tx_count"], str(r["address"])))


# ======================================================================================
# Etherscan V2 (cond 3), Ethplorer (cond 1), JSON-RPC (cond 2)
# ======================================================================================


def etherscan_problem(raw: Any) -> tuple[str, str] | None:
    """Etherscan error-in-200 (cond 3): status '0' -> (rate_limited | quota | error, reason), never empty -
    except the documented 'No transactions found' family with an empty result (a genuine empty list)."""
    obj, err = load_json(raw)
    if err:
        return "error", f"Etherscan: {err}"
    if not isinstance(obj, dict) or "status" not in obj:
        return "error", "Etherscan: unexpected body"
    st, msg, res = str(obj.get("status")), str(obj.get("message") or ""), obj.get("result")
    if st == "1":
        return None
    if ETHERSCAN_EMPTY.match(msg.strip()) and res in ([], "", None):
        return None
    detail = clean_text(res if isinstance(res, str) and res else msg, 140) or "status 0"
    low = f"{detail} {msg}".lower()
    if "rate limit" in low or "max calls per" in low or "too many" in low:
        return "rate_limited", "Etherscan: " + detail
    if "daily" in low or "credit" in low or "quota" in low or "plan limit" in low:
        return "quota", "Etherscan: " + detail
    return "error", "Etherscan: " + detail


def parse_etherscan_balance(raw: Any) -> int | None:
    obj, err = load_json(raw)
    if err or not isinstance(obj, dict) or str(obj.get("status")) != "1":
        return None
    return to_int(obj.get("result"))


def parse_etherscan_txlist(raw: Any) -> list[dict[str, Any]] | None:
    """module=account&action=txlist -> normalised transactions ([] for 'No transactions found')."""
    obj, err = load_json(raw)
    if err or not isinstance(obj, dict) or etherscan_problem(obj):
        return None
    out = []
    for t in obj.get("result") or []:
        if not isinstance(t, dict) or not isinstance(t.get("hash"), str):
            continue
        out.append({"hash": t["hash"], "time": iso_utc(t.get("timeStamp")), "block": to_int(t.get("blockNumber")),
                    "from": t.get("from") or None, "to": t.get("to") or None, "value_wei": to_int(t.get("value")) or 0,
                    "ok": str(t.get("isError", "0")) == "0", "method": clean_text(t.get("functionName") or t.get("methodId") or "", 60) or None,
                    "created_contract": t.get("contractAddress") or None, "from_info": {}, "to_info": {}})
    return out


def parse_etherscan_contract_creation(raw: Any) -> list[dict[str, Any]] | None:
    obj, err = load_json(raw)
    if err or not isinstance(obj, dict) or str(obj.get("status")) != "1" or not isinstance(obj.get("result"), list):
        return None
    return [{"contract": r.get("contractAddress"), "creator": r.get("contractCreator"), "tx_hash": r.get("txHash")}
            for r in obj["result"] if isinstance(r, dict)]


def parse_ethplorer_address(raw: Any) -> dict[str, Any] | None:
    """GET getAddressInfo/{a}?apiKey=<team key> -> balance, tokens with prices, contract creator, countTxs."""
    obj, err = load_json(raw)
    if err or not isinstance(obj, dict) or not isinstance(obj.get("address"), str):
        return None
    eth = obj.get("ETH") if isinstance(obj.get("ETH"), dict) else {}
    tokens = []
    for t in obj.get("tokens") or []:
        ti = t.get("tokenInfo") if isinstance(t, dict) and isinstance(t.get("tokenInfo"), dict) else None
        if ti is None:
            continue
        dec, raw_val = to_int(ti.get("decimals")), to_int(t.get("rawBalance"))
        price = ti.get("price") if isinstance(ti.get("price"), dict) else None
        rate = _to_float(price.get("rate")) if price else None
        fiat = raw_val / 10 ** dec * rate if (raw_val is not None and dec is not None and rate is not None) else None
        tokens.append({"token_address": ti.get("address"), "symbol": clean_text(ti.get("symbol"), 20),
                       "name": clean_text(str(ti.get("name") or ""), 80), "type": "ERC-20",
                       "amount": units_str(raw_val, dec) if raw_val is not None and dec is not None else None,
                       "fiat_value": round(fiat, 2) if fiat is not None else None})
    ci = obj.get("contractInfo") if isinstance(obj.get("contractInfo"), dict) else None
    return {"address": obj["address"], "balance_wei": to_int(eth.get("rawBalance")), "tx_count": to_int(obj.get("countTxs")),
            "is_contract": ci is not None, "creator_address": ci.get("creatorAddress") if ci else None,
            "creation_tx": ci.get("creationTransactionHash") if ci else None,
            "creation_time": iso_utc(ci.get("creationTimestamp")) if ci else None, "tokens": tokens}


def eth_rpc_batch(address: str) -> list[dict[str, Any]]:
    """JSON-RPC batch: balance, nonce, code and the chain-id guard (read-only methods of the shared helper)."""
    return [{"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [address, "latest"]},
            {"jsonrpc": "2.0", "id": 2, "method": "eth_getTransactionCount", "params": [address, "latest"]},
            {"jsonrpc": "2.0", "id": 3, "method": "eth_getCode", "params": [address, "latest"]},
            {"jsonrpc": "2.0", "id": 4, "method": "eth_chainId", "params": []}]


def _hex_int(value: Any) -> int | None:
    if isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{1,80}", value.strip()):
        return int(value.strip(), 16)
    return None


def parse_eth_rpc_answers(answers: dict[Any, Any]) -> tuple[dict[str, Any] | None, str]:
    """{id: response} of :func:`eth_rpc_batch` -> (balance, nonce, contract-vs-EOA, chain id) or (None, why).
    Any JSON-RPC error object (also inside HTTP 200) or a missing answer is 'could not verify' (rule 5)."""
    for rid in (1, 2, 3, 4):
        err = rpc_error(answers.get(rid))
        if err:
            return None, err
        if not isinstance(answers.get(rid), dict) or "result" not in answers[rid]:
            return None, f"JSON-RPC answer {rid} missing"
    chain = _hex_int(answers[4].get("result"))
    if chain != ETH_CHAIN_ID:
        return None, f"RPC answered chain {chain} (expected Ethereum mainnet {ETH_CHAIN_ID})"
    code = answers[3].get("result")
    if not isinstance(code, str) or not code.startswith("0x"):
        return None, "unexpected eth_getCode result"
    balance, nonce = _hex_int(answers[1].get("result")), _hex_int(answers[2].get("result"))
    if balance is None or nonce is None:
        return None, "unexpected eth_getBalance/eth_getTransactionCount result"
    return {"balance_wei": balance, "nonce": nonce, "is_contract": code not in ("0x", "0x0"),
            "code_size": max(0, (len(code) - 2) // 2), "chain_id": chain}, ""


# ======================================================================================
# adapters
# ======================================================================================


def run_rpc(ctx: Any, address: str, hosts: tuple[str, ...], budget: ExplorerBudget) -> dict[str, Any]:
    """The complementary JSON-RPC call (cond 2) through the helper shared with crypto_sanctions (P205)."""
    url = str(ctx.setting("eth_rpc", DEFAULT_ETH_RPC) or DEFAULT_ETH_RPC).strip()
    try:
        parts = urlsplit(url)
    except ValueError:
        raise AdapterFailure("skipped", "eth_rpc is not a URL", code="config") from None
    if parts.scheme != "https" or (parts.hostname or "").lower() not in hosts:
        raise AdapterFailure("skipped", "eth_rpc must be an https URL of a registered provider (default PublicNode)", code="config")
    if budget.left() <= 0.5:
        raise AdapterFailure("error", "explorer budget used up", code="timeout")
    try:
        answers = JsonRpc(ctx, url, source=SRC_RPC, ttl=600).batch(eth_rpc_batch(address))
    except (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError) as exc:
        status, code = classify_exception(exc)
        if status == "needs_key":  # a keyless public RPC refusing is never 'needs a key'
            status, code = "blocked", "challenge"
        raise AdapterFailure(status, str(exc)[:160], code=code) from None
    parsed, why = parse_eth_rpc_answers(answers)
    if parsed is None:
        raise AdapterFailure("error", why)
    return parsed


def run_blockscout(ctx: Any, address: str, budget: ExplorerBudget, cache_ttl: int | None, cap: int) -> dict[str, Any]:
    """Blockscout: address facts, newest transactions, token balances, counters. The address endpoint hangs for
    some heavy addresses (prep live check): when it fails, the transaction list still answers for Blockscout."""
    base = f"{BLOCKSCOUT}/addresses/{quote(address, safe='')}"
    out: dict[str, Any] = {"address": None, "txs": [], "has_more": False, "holdings": None, "counters": None, "problems": []}
    try:
        resp = http_get(ctx, base, source=SRC_BLOCKSCOUT, budget=budget, ttl=cache_ttl)
        out["address"] = parse_blockscout_address(resp.content)
        if out["address"] is None:
            raise AdapterFailure("error", "unexpected Blockscout address answer: could not verify")
        out["fetched_at"] = fetched_at_iso(resp)
    except AdapterFailure as exc:
        # only a slow address endpoint (timeout / 504, seen live for heavy addresses) is worked around through
        # the transaction list; a refusal, a rate limit or a dead host fails Blockscout over at once
        if not (exc.code == "timeout" or "504" in exc.reason or "timed out" in exc.reason.lower()):
            raise
        out["problems"].append(f"address endpoint: {exc.reason}")
    if out["address"] is not None and not out["address"]["known"]:
        return out
    resp = http_get(ctx, f"{base}/transactions", source=SRC_BLOCKSCOUT, budget=budget, ttl=cache_ttl)
    page = parse_blockscout_txs(resp.content)
    if page is None:
        raise AdapterFailure("error", "unexpected Blockscout transaction list: could not verify")
    out["txs"], out["has_more"] = page["txs"], bool(page["next_page_params"])
    out.setdefault("fetched_at", fetched_at_iso(resp))
    # problem labels avoid secret-like words ('token: ...' reads as a credential assignment to the P145 scrubber)
    for path, key, label, parser in (("token-balances", "holdings", "holdings endpoint", parse_blockscout_token_balances),
                                     ("counters", "counters", "counters endpoint", parse_blockscout_counters)):
        if ctx.http.requests >= cap or budget.left() < 1.5:
            out["problems"].append(f"{label} skipped (request cap or explorer budget)")
            continue
        try:
            resp = http_get(ctx, f"{base}/{path}", source=SRC_BLOCKSCOUT, budget=budget, ttl=cache_ttl)
        except AdapterFailure as exc:
            out["problems"].append(f"{label} failed ({exc.reason})")
            continue
        out[key] = parser(resp.content)
        if out[key] is None:
            out["problems"].append(f"{label}: unexpected answer")
    return out


def _etherscan_get(ctx: Any, params: dict[str, Any], key: str, budget: ExplorerBudget, cache_ttl: int | None) -> Any:
    resp = http_get(ctx, ETHERSCAN, source=SRC_ETHERSCAN, budget=budget, ttl=cache_ttl,
                    params={"chainid": ETH_CHAIN_ID, **params, "apikey": key})
    problem = etherscan_problem(resp.content)
    if problem:
        raise AdapterFailure(problem[0], problem[1])
    return resp


def run_etherscan(ctx: Any, address: str, budget: ExplorerBudget, cache_ttl: int | None, cap: int, is_contract: bool | None) -> dict[str, Any]:
    """Etherscan V2 (key only): balance, newest 50 transactions, contract creation for contracts."""
    key = str(ctx.key(KEY_ETHERSCAN) or "").strip()
    if not key:
        raise AdapterFailure("needs_key", "Etherscan runs only with key 'etherscan'")
    resp = _etherscan_get(ctx, {"module": "account", "action": "balance", "address": address, "tag": "latest"}, key, budget, cache_ttl)
    balance = parse_etherscan_balance(resp.content)
    if balance is None:
        raise AdapterFailure("error", "unexpected Etherscan balance answer: could not verify")
    out: dict[str, Any] = {"balance_wei": balance, "txs": [], "creator": None, "fetched_at": fetched_at_iso(resp), "problems": []}
    try:
        resp = _etherscan_get(ctx, {"module": "account", "action": "txlist", "address": address, "page": 1, "offset": 50, "sort": "desc"},
                              key, budget, cache_ttl)
        txs = parse_etherscan_txlist(resp.content)
        out["txs"] = txs or []
        out["has_more"] = bool(txs) and len(txs) >= 50
    except AdapterFailure as exc:
        if exc.status in ("rate_limited", "quota"):
            raise
        out["problems"].append(f"txlist: {exc.reason}")
    if is_contract and ctx.http.requests < cap and budget.left() >= 1.5:
        try:
            resp = _etherscan_get(ctx, {"module": "contract", "action": "getcontractcreation", "contractaddresses": address}, key, budget, cache_ttl)
            rows = parse_etherscan_contract_creation(resp.content) or []
            out["creator"] = next((r.get("creator") for r in rows if addr_key(r.get("contract")) == addr_key(address)), None)
        except AdapterFailure as exc:
            out["problems"].append(f"getcontractcreation: {exc.reason}")
    return out


def run_ethplorer(ctx: Any, address: str, budget: ExplorerBudget, cache_ttl: int | None) -> dict[str, Any]:
    """Ethplorer (the team's own key only; the shared 'freekey' is refused)."""
    key = str(ctx.key(KEY_ETHPLORER) or "").strip()
    if not key or key.lower() in SHARED_TEST_KEYS:
        raise AdapterFailure("needs_key", "Ethplorer runs only with the team's own key 'ethplorer' (never the shared public test key)")
    resp = http_get(ctx, ETHPLORER.format(address=quote(address, safe="")), source=SRC_ETHPLORER, budget=budget, ttl=cache_ttl,
                    params={"apiKey": key}, body_reason=_ethplorer_error)
    parsed = parse_ethplorer_address(resp.content)
    if parsed is None:
        why = _ethplorer_error(resp.content)
        raise AdapterFailure("error", f"Ethplorer: {why}" if why else "unexpected Ethplorer answer: could not verify")
    parsed["fetched_at"] = fetched_at_iso(resp)
    return parsed


def _ethplorer_error(raw: Any) -> str | None:
    obj, _ = load_json(raw)
    e = obj.get("error") if isinstance(obj, dict) else None
    if isinstance(e, dict):
        return f"{clean_text(str(e.get('message') or ''), 120)} (code {e.get('code')})"
    return clean_text(e, 120) if isinstance(e, str) else None


# ======================================================================================
# the module
# ======================================================================================


@register
class EvmExplorers(Module):
    name = "evm_explorers"
    title = "EVM explorers (Blockscout, Etherscan V2, Ethplorer, PublicNode RPC)"
    description = (
        "Ethereum address summary: balance, contract vs EOA, transaction count, first/last activity, top 5 token holdings, "
        "Blockscout scam flags and public tags, ENS name and the top counterparties - Blockscout keyless first, Etherscan and "
        "Ethplorer only with the team's keys, balance and code from the PublicNode (or configured) JSON-RPC; sequential failover."
    )
    category = "crypto"
    accepts = {T.ETH, T.DOMAIN, T.KEYWORD}
    produces = {T.ETH}
    tags = {"free"}
    reference = "https://docs.blockscout.com/devs/apis/rest"
    notice = (
        "Explorer operators see which addresses you look up: only one explorer receives the address unless it fails "
        "(attribute disclosed_to). Etherscan and Ethplorer are key-terms sources (company keys, plans recorded in key_plans); "
        "the shared Ethplorer 'freekey' is never used; OKLink waits for a keyed success fixture. Blockscout labels and scam "
        "flags are the explorer's curation, not a verdict; sanctions come only from crypto_sanctions. Counterparties and "
        "contract creators are listed, never expanded automatically. ENS names (name.eth typed as a domain or keyword) are "
        "resolved through Blockscout search."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "blockscout"
    sources = (SRC_BLOCKSCOUT, SRC_RPC, SRC_ETHERSCAN, SRC_ETHPLORER)
    hosts = ("eth.blockscout.com", "ethereum-rpc.publicnode.com", "api.etherscan.io", "api.ethplorer.io")
    access_model = "free_noauth_limited"
    optional_keys = (KEY_ETHERSCAN, KEY_ETHPLORER)
    max_requests = 10
    expected_latency = 2.5
    timeout = 25.0
    cache_ttl = 3600
    max_pivots = TOP_COUNTERPARTIES + 1
    default_enabled = True

    @classmethod
    def health_check(cls) -> HealthCheck:
        # the Ethereum Foundation multisig: public, labelled, benign (verified live 2026-11-26)
        return HealthCheck(T.ETH, "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae")

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.ETH:
            return evm_address(entity.value) is not None  # an EIP-55 typo is never sent (cond 2)
        return ens_name(entity.value) is not None  # domain/keyword inputs: ENS names (name.eth) only

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        if entity.type is not T.ETH:
            return self._resolve_ens(entity, ctx)
        res = self.result(entity)
        address = evm_address(entity.value)
        if address is None:
            return res.mark("skipped", "not a valid Ethereum address (EIP-55 checksum mismatch or junk): never sent",
                            reason_code="not_applicable")
        allowed = ctx.allowed_sources
        keys = {k for k in (KEY_ETHERSCAN, KEY_ETHPLORER) if str(ctx.key(k) or "").strip()}
        plan = evm_failover_plan(keys, allowed)
        budget = ExplorerBudget(ctx)
        cap = int(self.max_requests)
        res.attr("chain", "ethereum")
        attempts: list[dict[str, Any]] = []
        rpc: dict[str, Any] | None = None
        if SRC_RPC in allowed:
            before, start = ctx.http.requests, budget.used()
            try:
                rpc = run_rpc(ctx, address, self.hosts, budget)
                attempts.append({"provider": "eth_rpc", "source": SRC_RPC, "status": "ok", "reason": None,
                                 "elapsed_s": round(budget.used() - start, 3), "sent": ctx.http.requests > before})
            except AdapterFailure as exc:
                attempts.append({"provider": "eth_rpc", "source": SRC_RPC, "status": exc.status, "reason": exc.reason,
                                 "elapsed_s": round(budget.used() - start, 3), "sent": ctx.http.requests > before})
                res.source_status(SRC_RPC, _STATUS[exc.status], reason_code=exc.code, reason=f"Ethereum RPC: {exc.reason}"[:240])
        answer: dict[str, Any] | None = None
        provider = ""
        for prov in plan:
            spec = EVM_PROVIDERS[prov]
            before, start = ctx.http.requests, budget.used()
            try:
                if prov == "blockscout":
                    data = run_blockscout(ctx, address, budget, self.cache_ttl, cap)
                elif prov == "etherscan":
                    data = run_etherscan(ctx, address, budget, self.cache_ttl, cap, (rpc or {}).get("is_contract"))
                else:
                    data = run_ethplorer(ctx, address, budget, self.cache_ttl)
            except AdapterFailure as exc:
                attempts.append({"provider": prov, "source": spec["source"], "status": exc.status, "reason": exc.reason,
                                 "elapsed_s": round(budget.used() - start, 3), "sent": ctx.http.requests > before})
                res.source_status(spec["source"], _STATUS[exc.status], reason_code=exc.code, reason=f"{prov}: {exc.reason}"[:240])
                if budget.left() <= 0.5:
                    break
                continue
            known = not (prov == "blockscout" and data.get("address") is not None and not data["address"]["known"])
            attempts.append({"provider": prov, "source": spec["source"], "status": "ok" if known else "empty",
                             "reason": "; ".join(data.get("problems") or []) or None,
                             "elapsed_s": round(budget.used() - start, 3), "sent": ctx.http.requests > before})
            answer, provider = data, prov
            break
        report = failover_report(attempts, internal=())
        report["answered_by"] = provider or None
        res.attr("explorer_failover", report)
        res.attr("disclosed_to", report["disclosed_to"])
        if answer is None and rpc is None:
            failed = [a for a in attempts if a["status"] not in ("ok", "empty")]
            if not failed:
                return res.mark("skipped", "no EVM source is allowed by the licence profile", reason_code="licence")
            st = worst_status([a["status"] for a in failed])
            detail = "; ".join(f"{a['provider']}: {a['reason']}" for a in failed)[:400]
            code = next((c for c in (_CODE.get(a["status"], "error") for a in failed if a["status"] == st)), "error")
            return res.mark(_STATUS[st], f"no explorer answered: could not verify ({detail})", reason_code=code)
        return self._summarise(res, ctx, address, provider, answer, rpc)

    # ------------------------------------------------------------------ summary (cond 4)
    def _summarise(self, res: ModuleResult, ctx: Any, address: str, provider: str, data: dict[str, Any] | None,
                   rpc: dict[str, Any] | None) -> ModuleResult:
        data = data or {}
        bs_addr = data.get("address") if provider == "blockscout" else None
        txs = data.get("txs") or []
        balance = (rpc or {}).get("balance_wei")
        if balance is None:
            balance = (bs_addr or {}).get("balance_wei") if provider == "blockscout" else data.get("balance_wei")
        is_contract = (rpc or {}).get("is_contract")
        if is_contract is None:
            is_contract = (bs_addr or {}).get("is_contract") if provider == "blockscout" else data.get("is_contract")
        unknown = provider == "blockscout" and bs_addr is not None and not bs_addr["known"]
        as_of = ctx.now().date().isoformat()
        display = eip55(address)
        res.attr("balance", f"{units_str(balance, 18)} ETH" if balance is not None else None)
        res.attr("balance_base_units", str(balance) if balance is not None else None)
        if is_contract is not None:
            res.attr("is_contract", bool(is_contract))
        tx_count = None
        if provider == "blockscout" and isinstance(data.get("counters"), dict):
            tx_count = data["counters"].get("tx_count")
        elif provider == "ethplorer":
            tx_count = data.get("tx_count")
        if tx_count is not None:
            res.attr("tx_count", tx_count)
        times = sorted(t["time"] for t in txs if t.get("time"))
        has_more = bool(data.get("has_more"))
        creation_time = data.get("creation_time") if provider == "ethplorer" else None
        first = creation_time or (times[0] if times and not has_more else None)
        window = {"first_seen": creation_time or (times[0] if times else None), "last_seen": times[-1] if times else None,
                  "first_seen_exact": bool(creation_time) or (bool(times) and not has_more), "txs_examined": len(txs)}
        if window["first_seen"] or window["last_seen"]:
            res.attr("activity_window", window)
        if first:
            res.attr("first_seen", first)
        if window["last_seen"]:
            res.attr("last_seen", window["last_seen"])
        holdings = data.get("holdings") if provider == "blockscout" else (data.get("tokens") if provider == "ethplorer" else None)
        tops = top_token_holdings(holdings or [])
        if tops:
            res.attr("top_token_holdings", tops)
        if bs_addr and bs_addr.get("ens_name"):
            res.attr("ens_name", bs_addr["ens_name"])
        res.attr("data_freshness", {"provider": provider or "eth_rpc", "fetched_at": data.get("fetched_at"),
                                    "balance_block": (bs_addr or {}).get("balance_block"), "balance_from": "eth_rpc" if rpc else provider})
        res.link("Blockscout address page", f"https://eth.blockscout.com/address/{display}")
        # Blockscout labels and findings (cond 4)
        if provider == "blockscout":
            info = dict(bs_addr or {})
            if not info.get("tags"):
                info["tags"] = [{"label": lab, "slug": "", "kind": "tx_party", "source": "tx_items"} for lab in labels_from_txs(txs, address)]
            bf = blockscout_findings(info)
            res.attr("wallet_labels", bf["labels"])
            res.attr("stop_node_hint", bf["stop_node"])
            self._blockscout_findings(res, bf, display)
        # creator pivot (contracts only, expand=False)
        creator = None
        if is_contract:
            creator = (bs_addr or {}).get("creator_address") if provider == "blockscout" else (
                data.get("creator") if provider == "etherscan" else data.get("creator_address"))
            if isinstance(creator, str) and evm_address(creator):
                res.pivot(T.ETH, creator.lower(), "contract_creator", confidence="confirmed", expand=False,
                          note=f"deployer of contract {display} per {provider} (a lead, never expanded automatically)")
        # counterparties (expand=False, P213 decides)
        cps = []
        for c in evm_counterparties(txs, address)[:TOP_COUNTERPARTIES]:
            if not evm_address(str(c["address"] or "")):
                continue
            cps.append({"address": eip55(str(c["address"]).lower()), "direction": c["direction"],
                        "received_from": f"{units_str(c['received_from_wei'], 18)} ETH", "sent_to": f"{units_str(c['sent_to_wei'], 18)} ETH",
                        "tx_count": c["tx_count"], "first_seen": c["first_seen"], "last_seen": c["last_seen"],
                        "labels": c["labels"][:5], "is_contract": c["is_contract"], "is_scam": c["is_scam"], "label": COUNTERPARTY_LABEL})
            res.pivot(T.ETH, str(c["address"]).lower(), "transacted_with", confidence="probable", expand=False,
                      note=f"{COUNTERPARTY_LABEL}: direction {c['direction']}, {c['tx_count']} tx in the {len(txs)} newest read (P213 decides expansion)")
        res.attr("top_counterparties", cps)
        res.raw = {"provider": provider or None, "rpc": rpc, "address": bs_addr if provider == "blockscout" else None,
                   "tx_hashes": [t["hash"] for t in txs][:100], "counters": data.get("counters"), "problems": data.get("problems")}
        quiet = (rpc is not None and rpc["balance_wei"] == 0 and rpc["nonce"] == 0 and not rpc["is_contract"])
        if unknown and (rpc is None or quiet):
            res.attr("wallet_status", f"never seen by Blockscout (no balance, transactions or tokens as of {as_of})")
            return res.mark("empty")
        if provider == "":
            res.attr("wallet_status", "explorers could not answer: balance and code from the JSON-RPC only")
        kind = "contract" if is_contract else "externally owned account" if is_contract is False else "address"
        res.finding(
            f"Ethereum {kind} summary",
            "info",
            (f"{display}: balance {res.attributes.get('balance') or 'unknown'}, {tx_count if tx_count is not None else 'unknown'} "
             f"transactions, last activity {window['last_seen'] or 'unknown'} (explorer {provider or 'none'}; balance and code from "
             f"{'the JSON-RPC' if rpc else provider}). Labels and scam flags are the explorer's curation, not a verdict."),
            confidence="confirmed",
            source=EVM_PROVIDERS[provider]["source"] if provider else SRC_RPC,
            data={"explorer": provider or None, "is_contract": is_contract, "txs_examined": len(txs)},
            observed_first=first,
            observed_last=window["last_seen"],
            key="summary",
        )
        return res

    @staticmethod
    def _blockscout_findings(res: ModuleResult, bf: dict[str, Any], display: str) -> None:
        for f in bf["findings"]:
            if f["kind"] == "scam":
                res.finding(f["title"], "high",
                            f"Blockscout marks {display} as a scam (is_scam={f['evidence']['is_scam']}, reputation "
                            f"{f['evidence']['reputation']!r}). Explorer curation: confirm before acting.",
                            confidence="probable", criterion="Blockscout v2 address is_scam=true or reputation 'scam'",
                            tags=f["tags"], source=SRC_BLOCKSCOUT, data=f["evidence"], key="is_scam")
            elif f["kind"] == "suspicious_label":
                res.finding(f["title"], "medium", f"Blockscout public tag {f['label']!r} on {display}.",
                            confidence="possible", criterion="Blockscout public/metadata tag matching phish|hack|exploit|scam|fraud|drainer|fake|ponzi|rug|spam",
                            tags=f["tags"], source=SRC_BLOCKSCOUT, data={"label": f["label"]}, key=f"tag:{f['label']}")
            else:
                res.finding(f["title"], "info", f"Blockscout label {f['label']!r} on {display}: sanctions screening is crypto_sanctions' "
                            "(P205) - this label is not authoritative.", confidence="possible", tags=f["tags"], source=SRC_BLOCKSCOUT,
                            data={"label": f["label"]}, key=f"sanctions:{f['label']}")

    # ------------------------------------------------------------------ ENS (cond 1)
    def _resolve_ens(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        name = ens_name(entity.value)
        if name is None:
            return res.mark("skipped", "not an ENS name (name.eth)", reason_code="not_applicable")
        if SRC_BLOCKSCOUT not in ctx.allowed_sources:
            return res.mark("skipped", "Blockscout is not allowed by the licence profile", reason_code="licence")
        budget = ExplorerBudget(ctx)
        try:
            resp = http_get(ctx, f"{BLOCKSCOUT}/search", source=SRC_BLOCKSCOUT, budget=budget, ttl=self.cache_ttl, params={"q": name})
        except AdapterFailure as exc:
            return res.mark(_STATUS[exc.status], f"Blockscout search: {exc.reason} - could not verify", reason_code=exc.code)
        found = parse_blockscout_search(resp.content, name)
        if found is None:
            return res.mark("error", "unexpected Blockscout search answer: could not verify")
        res.raw = {"query": name, "resolution": found}
        target = evm_address(str(found.get("address") or ""))
        if not target:
            res.attr("wallet_status", f"no ENS record named {name} in Blockscout search (as of {ctx.now().date().isoformat()})")
            return res.mark("empty")
        res.attr("chain", "ethereum")
        res.attr("ens_name", found.get("ens_name") or name)
        res.pivot(T.ETH, target, "ens_resolves_to", confidence="probable",
                  note=f"ENS {name} resolves to {eip55(target)} per Blockscout (records can change; expiry {found.get('expiry') or 'unknown'})")
        res.finding(f"ENS name resolves to {eip55(target)}", "info", f"{name} -> {eip55(target)} (Blockscout search, exact ENS match).",
                    confidence="probable", source=SRC_BLOCKSCOUT, data={"ens_name": name, "address": eip55(target)}, key="ens")
        return res


_STATUS = {"rate_limited": Status.RATE_LIMITED, "quota": Status.QUOTA, "blocked": Status.BLOCKED, "needs_key": Status.NEEDS_KEY,
           "error": Status.ERROR, "skipped": Status.SKIPPED}
_CODE = {"rate_limited": "rate_limited", "quota": "quota", "blocked": "challenge", "needs_key": "needs_key", "skipped": "config"}

__all__ = [
    "EVM_PROVIDERS",
    "EXPLORER_BUDGET_S",
    "OKLINK_READY",
    "EvmExplorers",
    "blockscout_findings",
    "eip55",
    "ens_name",
    "eth_rpc_batch",
    "etherscan_problem",
    "evm_address",
    "evm_counterparties",
    "evm_failover_plan",
    "keccak_is_not_sha3",
    "labels_from_txs",
    "parse_blockscout_address",
    "parse_blockscout_counters",
    "parse_blockscout_search",
    "parse_blockscout_token_balances",
    "parse_blockscout_txs",
    "parse_eth_rpc_answers",
    "parse_etherscan_balance",
    "parse_etherscan_contract_creation",
    "parse_etherscan_txlist",
    "parse_ethplorer_address",
    "top_token_holdings",
]
