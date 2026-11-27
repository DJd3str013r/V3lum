"""TRON wallet explorer (P207): TronGrid account + TRC-20 transfers, Tronscan labels with a key.

Also the ONE TronGrid client of V3LUM (:class:`TronGrid`), shared with the USDT-TRC20 freeze check of
crypto_sanctions_onchain (P205 cond 3).

Final conditions (P207):

* cond 1 - TronGrid ``/v1/accounts/{addr}`` and ``/v1/accounts/{addr}/transactions/trc20`` (limit 50,
  at most 2 pages, newest first; the next page is rebuilt from ``meta.fingerprint`` - the
  server-supplied ``links.next`` URL is never followed); key ``trongrid`` is sent as the
  ``TRON-PRO-API-KEY`` header, never in the query; keyless works but is throttled.
* cond 2 - the address is validated with the core base58check validator (T prefix, version byte
  0x41, P217 ``crypto_address_info``) before any call: an invalid value is never sent. Amounts are
  converted from sun/decimals with ``Decimal`` and shown with units; ``{'success': false}`` bodies
  are ERROR through the provider marker (P321); throttling (429 or the frequency-limit marker) is
  RATE_LIMITED (could not verify).
* cond 3 - summary: TRX/USDT balances, first/last activity, the transfers read (TronGrid v1 has no
  total transaction count: the exact count comes from Tronscan with its key) and the top 5
  counterparties by USDT value; counterparties are ``transacted_with`` pivots with ``expand=False``
  (expansion is decided by P213) and carry no label here (labels come from crypto_address_labels,
  P358). USDT is recognised by its contract address only: look-alike symbols ('UDST', 'QSDT', a fake
  'USDT') of other contracts are address-poisoning spam and are counted apart.
* cond 4 - Tronscan (apilist.tronscanapi.com) only with key ``tronscan`` (401 without): without that
  key there is no Tronscan row at all.
* cond 5 - key-terms: keys from a company/team account on a business-compatible plan recorded in
  key_plans; registry providers ``trongrid`` and ``tronscan`` (TRON DAO): tier trusted.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from decimal import Decimal, InvalidOperation
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, Module, register
from v3lum.core.validators import base58check_decode, base58check_encode, crypto_address_info

SOURCE_TRONGRID = "trongrid.api"
SOURCE_TRONSCAN = "tronscan.api"
TRONGRID = "https://api.trongrid.io"
ACCOUNT_URL = TRONGRID + "/v1/accounts/{address}"
TRC20_URL = TRONGRID + "/v1/accounts/{address}/transactions/trc20"
TRIGGER_URL = TRONGRID + "/wallet/triggerconstantcontract"
TRONSCAN_URL = "https://apilist.tronscanapi.com/api/accountv2"
TRONSCAN_ADDRESS_PAGE = "https://tronscan.org/#/address/{address}"
TRC20_PAGE_SIZE = 50
TRC20_MAX_PAGES = 2
TOP_COUNTERPARTIES = 5
#: USDT-TRC20 (Tether) - research C0480/C0488; recognised by contract, never by symbol
USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
USDT_DECIMALS = 6
SUN_PER_TRX = Decimal(1_000_000)
#: base58check(0x41 + 20 zero bytes): the owner of read-only constant calls
TRON_ZERO_ADDRESS = "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb"
KEY_TRONGRID = "trongrid"
KEY_TRONSCAN = "tronscan"


# --------------------------------------------------------------------------------------
# address helpers (P217 core validator; conversions for the hex 41... form TronGrid returns)
# --------------------------------------------------------------------------------------


def is_tron_address(value: Any) -> bool:
    """T-prefixed base58check with version byte 0x41 and a 20-byte body (core validator, P217)."""
    if not isinstance(value, str):
        return False
    info = crypto_address_info(value.strip())
    return info is not None and info.chain == "tron" and info.checksum_ok is True


def tron_hex_to_base58(hex_address: Any) -> str | None:
    """'41a614f8...' (TronGrid's account address) -> 'TR7NH...'; None when not a 0x41 address."""
    text = hex_address.strip().lower() if isinstance(hex_address, str) else ""
    if text.startswith("0x"):
        text = "41" + text[2:]
    if not re.fullmatch(r"41[0-9a-f]{40}", text):
        return None
    return base58check_encode(bytes.fromhex(text))


def tron_base58_to_hex(address: Any) -> str | None:
    """'T...' -> '41...' hex (None unless a valid 0x41 base58check address)."""
    if not is_tron_address(address):
        return None
    try:
        payload = base58check_decode(str(address).strip())
    except ValueError:
        return None
    return payload.hex() if len(payload) == 21 and payload[0] == 0x41 else None


def abi_address_word(address: str) -> str:
    """32-byte ABI word of an address argument: an EVM 0x address or a TRON T... address. ValueError otherwise."""
    text = (address or "").strip()
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", text):
        return "0" * 24 + text[2:].lower()
    hexed = tron_base58_to_hex(text)
    if hexed:
        return "0" * 24 + hexed[2:]
    raise ValueError("not an EVM or TRON address")


def decode_abi_bool(result: Any) -> bool | None:
    """Exactly 0x..00 -> False, 0x..01 -> True; any other value -> None (could not verify, P205 cond 4)."""
    text = result.strip().lower() if isinstance(result, str) else ""
    if text.startswith("0x"):
        text = text[2:]
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        return None
    return {0: False, 1: True}.get(int(text, 16))


def amount(raw: Any, decimals: Any) -> Decimal | None:
    """An integer token amount scaled by ``decimals`` (Decimal, exact); None for odd values."""
    if isinstance(raw, bool) or isinstance(decimals, bool) or not isinstance(decimals, int) or not 0 <= decimals <= 36:
        return None
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    if value < 0:
        return None
    return Decimal(value).scaleb(-decimals)


def format_amount(value: Decimal | None, unit: str) -> str | None:
    """Plain notation with the unit (P207 cond 2: amounts are shown with units)."""
    if value is None:
        return None
    try:
        text = format(value.normalize(), "f") if value != 0 else "0"
    except InvalidOperation:  # pragma: no cover - Decimal from ints never fails here
        return None
    return f"{text} {unit}"


def _iso_ms(value: Any) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        return None
    try:
        return _dt.datetime.fromtimestamp(value / 1000.0, tz=_dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _osa_le1(a: str, b: str) -> bool:
    """a and b differ by at most one edit (insertion, deletion, substitution or adjacent transposition)."""
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return any(long_[:i] + long_[i + 1:] == short for i in range(len(long_)))


# --------------------------------------------------------------------------------------
# parsers (pure; never raise)
# --------------------------------------------------------------------------------------


def parse_account(doc: Any) -> dict[str, Any] | None:
    """/v1/accounts/{addr} -> balances and activity; ``{'activated': False}`` for ``data: []`` (never
    activated on chain); None when the answer is not an account answer."""
    if not isinstance(doc, dict) or not isinstance(doc.get("data"), list):
        return None
    if not doc["data"]:
        return {"activated": False}
    acc = doc["data"][0] if isinstance(doc["data"][0], dict) else {}
    sun = acc.get("balance") if isinstance(acc.get("balance"), int) and not isinstance(acc.get("balance"), bool) else 0
    usdt_raw: Any = None
    tokens = 0
    for entry in acc.get("trc20") if isinstance(acc.get("trc20"), list) else []:
        if not isinstance(entry, dict):
            continue
        for contract, raw in entry.items():
            if contract == USDT_CONTRACT:
                usdt_raw = raw
            else:
                tokens += 1
    usdt = amount(usdt_raw, USDT_DECIMALS) if usdt_raw is not None else Decimal(0)
    name = acc.get("account_name")
    if isinstance(name, str) and re.fullmatch(r"(?:[0-9a-f]{2}){1,64}", name):
        try:
            decoded = bytes.fromhex(name).decode("utf-8")
            name = decoded if decoded.isprintable() else name
        except (ValueError, UnicodeDecodeError):
            pass
    return {
        "activated": True,
        "address": tron_hex_to_base58(acc.get("address")),
        "type": acc.get("type") if isinstance(acc.get("type"), str) else "Normal",
        "account_name": name if isinstance(name, str) and name else None,
        "trx_balance": format_amount(Decimal(sun) / SUN_PER_TRX, "TRX"),
        "usdt_balance": format_amount(usdt, "USDT"),
        "other_tokens": tokens,
        "created_at": _iso_ms(acc.get("create_time")),
        "last_operation_at": _iso_ms(acc.get("latest_opration_time") or acc.get("latest_operation_time")),
    }


def parse_trc20_page(doc: Any) -> dict[str, Any] | None:
    """/transactions/trc20 -> transfers (newest first) and the next fingerprint; None when not a page."""
    if not isinstance(doc, dict) or not isinstance(doc.get("data"), list):
        return None
    transfers = []
    for row in doc["data"]:
        if not isinstance(row, dict):
            continue
        token = row.get("token_info") if isinstance(row.get("token_info"), dict) else {}
        contract = token.get("address") if isinstance(token.get("address"), str) else None
        symbol = token.get("symbol") if isinstance(token.get("symbol"), str) else ""
        is_usdt = contract == USDT_CONTRACT
        clean = re.sub(r"[^A-Z]", "", symbol.upper())
        transfers.append({
            "tx": row.get("transaction_id") if isinstance(row.get("transaction_id"), str) else None,
            "from": row.get("from") if isinstance(row.get("from"), str) else None,
            "to": row.get("to") if isinstance(row.get("to"), str) else None,
            "contract": contract,
            "symbol": symbol[:20],
            "value_raw": str(row.get("value")) if isinstance(row.get("value"), (str, int)) and not isinstance(row.get("value"), bool) else "",
            "amount": amount(row.get("value"), token.get("decimals")),
            "is_usdt": is_usdt,
            "lookalike": bool(not is_usdt and clean and _osa_le1(clean, "USDT")),
            "at": _iso_ms(row.get("block_timestamp")),
        })
    meta = doc.get("meta") if isinstance(doc.get("meta"), dict) else {}
    fingerprint = meta.get("fingerprint") if isinstance(meta.get("fingerprint"), str) and re.fullmatch(r"[A-Za-z0-9_-]{8,1024}", meta.get("fingerprint") or "") else None
    return {"transfers": transfers, "next_fingerprint": fingerprint}


def summarize(address: str, account: dict[str, Any] | None, pages: list[dict[str, Any]], top_n: int = TOP_COUNTERPARTIES) -> dict[str, Any]:
    """P207 cond 3 summary. One transaction can carry several TRC-20 transfers with the same id, so
    duplicates are removed on (tx, from, to, value, contract), never on the tx id alone."""
    seen: set[tuple[Any, ...]] = set()
    transfers = []
    for page in pages[:TRC20_MAX_PAGES]:
        for tr in page.get("transfers", []):
            key = (tr["tx"], tr["from"], tr["to"], tr["value_raw"], tr["contract"])
            if key not in seen:
                seen.add(key)
                transfers.append(tr)
    stats: dict[str, dict[str, Any]] = {}
    for tr in transfers:
        if not tr["is_usdt"] or tr["amount"] is None:
            continue
        if tr["from"] == address and tr["to"] != address:
            cp, direction = tr["to"], "out"
        elif tr["to"] == address and tr["from"] != address:
            cp, direction = tr["from"], "in"
        else:
            continue
        if not is_tron_address(cp):
            continue
        entry = stats.setdefault(cp, {"address": cp, "in": Decimal(0), "out": Decimal(0), "transfers": 0})
        entry[direction] += tr["amount"]
        entry["transfers"] += 1
    ranked = sorted(stats.values(), key=lambda e: (-(e["in"] + e["out"]), -e["transfers"], e["address"]))[:top_n]
    times = [t["at"] for t in transfers if t["at"]]
    firsts = [t for t in ((account or {}).get("created_at"), min(times) if times else None) if t]
    lasts = [t for t in ((account or {}).get("last_operation_at"), max(times) if times else None) if t]
    return {
        "first_activity": min(firsts) if firsts else None,
        "last_activity": max(lasts) if lasts else None,
        "transfers_seen": len(transfers),
        "more_available": bool(pages and pages[-1].get("next_fingerprint")) and len(pages) >= TRC20_MAX_PAGES,
        "lookalike_transfers": sum(1 for t in transfers if t["lookalike"]),
        "counterparties": [{
            "address": e["address"],
            "usdt_in": format_amount(e["in"], "USDT"),
            "usdt_out": format_amount(e["out"], "USDT"),
            "transfers": e["transfers"],
            "label": None,  # labels come from crypto_address_labels (P358)
        } for e in ranked],
    }


def parse_tronscan(doc: Any) -> dict[str, Any] | None:
    """Tronscan /api/accountv2 (with the key) -> labels and the transaction count; None when not an
    account answer. Field names from the Tronscan API documentation; success fixtures are captured with
    the team key (backlog p1-G09-1)."""
    if not isinstance(doc, dict):
        return None
    labels = []
    for field in ("publicTag", "blueTag", "greyTag", "redTag", "addressTag"):
        value = doc.get(field)
        if isinstance(value, str) and value.strip() and value.strip() not in labels:
            labels.append(f"{field}: {value.strip()[:80]}")
    count = doc.get("totalTransactionCount")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        count = None
    red = doc.get("redTag") if isinstance(doc.get("redTag"), str) and doc["redTag"].strip() else None
    return {"labels": labels, "tx_count": count, "red_tag": red, "feedback_risk": doc.get("feedbackRisk") is True}


# --------------------------------------------------------------------------------------
# the shared TronGrid client (P205 cond 3)
# --------------------------------------------------------------------------------------


class TronGrid:
    """TronGrid over ``ctx.http``: the key goes in the TRON-PRO-API-KEY header (never in a URL), every
    call names the registry source, answers are classified by the core (provider markers: success=false
    -> ERROR, frequency limit -> RATE_LIMITED; 429 -> RATE_LIMITED)."""

    def __init__(self, ctx: Any, *, source: str = SOURCE_TRONGRID, ttl: int | None = None) -> None:
        self.ctx = ctx
        self.source = source
        self.ttl = ttl
        key = ctx.key(KEY_TRONGRID) if callable(getattr(ctx, "key", None)) else ""
        self.headers = {"Accept": "application/json", **({"TRON-PRO-API-KEY": key} if key else {})}

    def _get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        kw: dict[str, Any] = {"source": self.source, "headers": dict(self.headers)}
        if params:
            kw["params"] = params
        if self.ttl is not None:
            kw["ttl"] = self.ttl
        resp = self.ctx.http.get(url, **kw)
        self.ctx.http.check(resp)
        return _json(resp.content)

    def account(self, address: str) -> Any:
        return self._get(ACCOUNT_URL.format(address=address))

    def trc20_page(self, address: str, fingerprint: str | None = None) -> Any:
        params: dict[str, Any] = {"limit": TRC20_PAGE_SIZE, "only_confirmed": "true"}
        if fingerprint:
            params["fingerprint"] = fingerprint
        return self._get(TRC20_URL.format(address=address), params)

    def constant_call(self, contract: str, function_selector: str, parameter: str, *, owner: str = TRON_ZERO_ADDRESS) -> Any:
        """Read-only ``/wallet/triggerconstantcontract`` (no transaction is broadcast)."""
        body = {"owner_address": owner, "contract_address": contract, "function_selector": function_selector,
                "parameter": parameter, "visible": True}
        kw: dict[str, Any] = {"source": self.source, "headers": dict(self.headers), "json_body": body}
        if self.ttl is not None:
            kw["ttl"] = self.ttl
        resp = self.ctx.http.post(TRIGGER_URL, **kw)
        self.ctx.http.check(resp)
        return _json(resp.content)


def parse_constant_bool(doc: Any) -> tuple[bool | None, str]:
    """A triggerconstantcontract answer -> (value, reason). ``result.result`` must be true and
    ``constant_result[0]`` exactly a 32-byte 0/1 word; anything else is (None, why) = could not verify."""
    if not isinstance(doc, dict):
        return None, "TronGrid constant call: not a JSON object"
    result = doc.get("result") if isinstance(doc.get("result"), dict) else {}
    if result.get("result") is not True:
        message = result.get("message") if isinstance(result.get("message"), str) else ""
        try:
            message = bytes.fromhex(message).decode("utf-8", "replace")
        except ValueError:
            pass
        return None, f"TronGrid constant call failed {str(result.get('code') or '')} {message[:80]}".strip()
    constant = doc.get("constant_result")
    value = decode_abi_bool(constant[0]) if isinstance(constant, list) and constant and isinstance(constant[0], str) else None
    if value is None:
        return None, "unexpected constant_result (not a 0/1 word)"
    return value, ""


def _json(content: bytes) -> Any:
    try:
        return json.loads(content.decode("utf-8", errors="replace"))
    except (ValueError, RecursionError):
        return None


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class TronExplorer(Module):
    name = "tron_explorer"
    title = "TRON wallet explorer (TronGrid, Tronscan)"
    description = (
        "TRON wallet summary from TronGrid: TRX/USDT balances, first/last activity, recent TRC-20 transfers and the top "
        "USDT counterparties (pivots, never expanded automatically); Tronscan labels and transaction count with a key."
    )
    category = "crypto"
    accepts = {T.CRYPTO}
    produces = {T.CRYPTO}
    tags = {"free"}
    reference = "https://developers.tron.network/reference/get-account-info-by-address"
    notice = (
        "TronGrid/Tronscan (TRON DAO) are key-terms sources: keys from a company/team account on a plan recorded as "
        "business in key_plans (never personal free accounts). Keyless TronGrid works but is throttled (could not verify "
        "when throttled). Counterparties are listed, never expanded automatically; their labels come from "
        "crypto_address_labels (P358)."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "trongrid"
    sources = (SOURCE_TRONGRID, SOURCE_TRONSCAN)
    hosts = ("api.trongrid.io", "apilist.tronscanapi.com")
    access_model = "free_noauth_limited"
    optional_keys = (KEY_TRONGRID, KEY_TRONSCAN)
    max_requests = 4
    expected_latency = 0.8
    timeout = 60.0
    min_interval = 1.0
    daily_quota = 1000
    cache_ttl = 3600
    max_pivots = 10
    default_enabled = True

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(T.CRYPTO, USDT_CONTRACT)  # the USDT-TRC20 contract account (benign, public)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return is_tron_address(entity.value)  # P207 cond 2: an invalid address is never sent

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        address = str(entity.value).strip()
        if not is_tron_address(address):
            return res.mark("skipped", "not a valid TRON address (base58check, version byte 0x41)", reason_code="not_applicable")
        allowed = ctx.allowed_sources
        if SOURCE_TRONGRID not in allowed:
            return res.mark("skipped", "TronGrid not allowed by the licence profile (key-terms: record key_plans.trongrid)", reason_code="licence")
        grid = TronGrid(ctx, ttl=self.cache_ttl)
        account = parse_account(grid.account(address))
        if account is None:
            return res.mark("error", "unexpected TronGrid account answer: could not verify")
        as_of = ctx.now().date().isoformat()
        if not account["activated"]:
            res.attr("chain", "tron")
            res.attr("wallet_status", f"not activated on-chain (TronGrid has no account record, as of {as_of})")
            res.raw = {"account": {"activated": False}}
            return res.mark("empty")
        pages: list[dict[str, Any]] = []
        fingerprint = None
        for _ in range(TRC20_MAX_PAGES):
            page = parse_trc20_page(grid.trc20_page(address, fingerprint))
            if page is None:
                return res.mark("error", "unexpected TronGrid TRC-20 answer: could not verify")
            pages.append(page)
            fingerprint = page["next_fingerprint"]
            if not fingerprint or not page["transfers"]:
                break
        summary = summarize(address, account, pages)
        self._report(res, address, account, summary, as_of)
        if SOURCE_TRONSCAN in allowed and ctx.key(KEY_TRONSCAN):
            self._tronscan(ctx, res, address)
        res.raw = {"account": {k: v for k, v in account.items() if k != "account_name"},
                   "summary": {k: v for k, v in summary.items() if k != "counterparties"},
                   "counterparties": summary["counterparties"]}
        return res

    def _report(self, res: ModuleResult, address: str, account: dict[str, Any], summary: dict[str, Any], as_of: str) -> None:
        res.attr("chain", "tron")
        res.attr("balance", account["trx_balance"])
        res.attr("token_balances", {"USDT": account["usdt_balance"]} if account.get("usdt_balance") else {})
        res.attr("account_type", account.get("type"))
        res.attr("first_seen", summary["first_activity"])
        res.attr("last_activity", summary["last_activity"])
        res.attr("transfers_seen", summary["transfers_seen"])
        if summary["lookalike_transfers"]:
            res.attr("lookalike_token_transfers", summary["lookalike_transfers"])
        res.attr("top_counterparties", summary["counterparties"])
        more = " (more on chain: only the 2 newest pages were read)" if summary["more_available"] else ""
        res.finding(
            "TRON wallet activity (TronGrid)",
            "info",
            f"TRX {account['trx_balance']}, USDT {account['usdt_balance']} (USDT recognised by contract); first activity "
            f"{summary['first_activity'] or 'unknown'}, last {summary['last_activity'] or 'unknown'}; {summary['transfers_seen']} "
            f"TRC-20 transfers read{more}; top counterparties by USDT: {len(summary['counterparties'])}"
            + (f"; {summary['lookalike_transfers']} look-alike token transfers (address-poisoning spam)" if summary["lookalike_transfers"] else "")
            + f". Data as of {as_of}.",
            confidence="confirmed",
            data={"trx_balance": account["trx_balance"], "usdt_balance": account["usdt_balance"], "transfers_seen": summary["transfers_seen"],
                  "more_available": summary["more_available"], "counterparties": summary["counterparties"]},
            source=SOURCE_TRONGRID,
            observed_first=summary["first_activity"],
            observed_last=summary["last_activity"],
        )
        for cp in summary["counterparties"]:
            res.pivot(T.CRYPTO, cp["address"], "transacted_with", confidence="confirmed", expand=False,
                      note=f"TRON USDT counterparty: in {cp['usdt_in']}, out {cp['usdt_out']}, {cp['transfers']} transfer(s); expansion decided by P213")
        res.link("Tronscan address page", TRONSCAN_ADDRESS_PAGE.format(address=address))

    @staticmethod
    def _tronscan(ctx: Any, res: ModuleResult, address: str) -> None:
        """Tronscan labels and the exact transaction count (key 'tronscan' only, cond 4)."""
        from v3lum.core.http import AuthRequired, Blocked, HttpError, NetworkError, QuotaExceeded, RateLimited

        try:
            resp = ctx.http.get(TRONSCAN_URL, params={"address": address}, source=SOURCE_TRONSCAN,
                                headers={"TRON-PRO-API-KEY": ctx.key(KEY_TRONSCAN), "Accept": "application/json"})
            ctx.http.check(resp)
        except AuthRequired as exc:
            res.source_status(SOURCE_TRONSCAN, Status.NEEDS_KEY, reason_code="needs_key", reason=f"Tronscan refused the key: {str(exc)[:120]}")
            return
        except RateLimited as exc:
            res.source_status(SOURCE_TRONSCAN, Status.RATE_LIMITED, reason_code="rate_limited", reason=f"Tronscan: {str(exc)[:120]}")
            return
        except QuotaExceeded as exc:
            res.source_status(SOURCE_TRONSCAN, Status.QUOTA, reason_code="quota", reason=f"Tronscan: {str(exc)[:120]}")
            return
        except Blocked as exc:
            res.source_status(SOURCE_TRONSCAN, Status.BLOCKED, reason_code="challenge", reason=f"Tronscan: {str(exc)[:120]}")
            return
        except (HttpError, NetworkError) as exc:
            res.source_status(SOURCE_TRONSCAN, Status.ERROR, reason_code="error", reason=f"Tronscan: {str(exc)[:120]}")
            return
        info = parse_tronscan(_json(resp.content))
        if info is None:
            res.source_status(SOURCE_TRONSCAN, Status.ERROR, reason_code="error", reason="unexpected Tronscan answer: could not verify")
            return
        res.attr("wallet_labels", info["labels"])
        if info["tx_count"] is not None:
            res.attr("tx_count", info["tx_count"])
        if info["red_tag"]:
            res.finding(
                "Wallet labelled as risky by Tronscan",
                "medium",
                f"Tronscan red tag: {info['red_tag']}. The label is the explorer's own curation.",
                confidence="probable",
                criterion="Tronscan 'redTag' (explorer risk/scam label) on the address",
                data={"labels": info["labels"]},
                tags=["fraud"],
                source=SOURCE_TRONSCAN,
            )


__all__ = [
    "TronExplorer",
    "TronGrid",
    "USDT_CONTRACT",
    "abi_address_word",
    "decode_abi_bool",
    "format_amount",
    "is_tron_address",
    "parse_account",
    "parse_constant_bool",
    "parse_trc20_page",
    "parse_tronscan",
    "summarize",
    "tron_base58_to_hex",
    "tron_hex_to_base58",
]
