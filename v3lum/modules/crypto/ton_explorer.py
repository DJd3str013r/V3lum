"""TON explorer through Toncenter v3 (P214): wallet state and counterparties, and the owner wallet of Telegram
collectibles (+888 anonymous numbers, collectible usernames).

Final conditions (P214, council-1):

* cond 1 - Toncenter v3 at 1 request/s keyless (key ``toncenter`` sent as the ``X-API-Key`` header raises it to
  10/s: politeness 1.1 s keyless, 0.11 s keyed). User-friendly TON addresses are decoded here (base64url, 36 bytes:
  flags, workchain, 32-byte account id, CRC16-XMODEM; :func:`decode_ton_address`, tests in
  tests/modules/test_ton_explorer.py) - the core validator is a core request (batches cannot edit
  v3lum/core/validators.py). default_enabled False (opt-in).
* cond 2 - phone input applies only to +888 anonymous numbers and username input only to the collectible format
  (:func:`ton_phone_gate`, :func:`ton_username_gate`); the lookup runs only for analyst-typed seeds that the case
  records as fraud/threat subjects (``ScanOptions.subject_roles``) with a recorded purpose - never ordinary phone
  numbers, never pivots or auto-expanded values, one token per run (``limit=1``, no ranges, no enumeration).
* cond 3 - +888 number or collectible username -> NFT item (``nft/items`` with index = int(sha256(token)), the
  Telemint ``string_hash``) -> current owner wallet, reported as 'current NFT owner wallet of the collectible
  number/username (ownership can change; transfer date shown)': a PROBABLE lead with ``expand=False``, never
  identity proof. The flow is the a_TON_of_privacy idea (https://github.com/aaarghhh/a_TON_of_privacy, commit
  8e3ff7a9b79a0843611c5d60e5121bda7bfba8ef, MIT, Copyright (c) 2023 Giacomo Giallombardo; notice
  ``a_ton_of_privacy``), rebuilt on Toncenter: none of its code, third-party endpoints, header spoofing or TLS
  shortcuts is used (A9).
* cond 4 - on-chain resolution through Toncenter only; tonapi.io and api.getgems.io are held until legal records
  their terms and tier (registered as unknown-tier review-queue entries, never declared here). Fixtures for the
  address and NFT endpoints were captured live on 2026-11-26. Registry provider toncenter: tier community, terms open.

Counterparties are ``transacted_with`` pivots with ``expand=False`` (P213 decides expansion). Transaction comments
are untrusted free text that may hold exchange deposit memos: they are counted, never stored or pivoted.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import re
from decimal import Decimal, InvalidOperation
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import HttpError
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, Module, register

SOURCE = "toncenter.api_v3"
BASE = "https://toncenter.com/api/v3/"
KEY = "toncenter"
KEY_HEADER = "X-API-Key"
KEYLESS_INTERVAL = 1.1  # 1 request/s keyless (cond 1)
KEYED_INTERVAL = 0.11  # 10 requests/s with the key
TX_LIMIT = 20
TOP_COUNTERPARTIES = 5
TRANSFER_LIMIT = 3
TONVIEWER = "https://tonviewer.com/{address}"
TELEGRAM_USERNAMES_COLLECTION = "EQCA14o1-VWhS2efqoh_9M1b_A9DtKTuoqfmkn83AbJzwnPi"
TELEGRAM_USERNAMES_RAW = "0:80D78A35F955A14B679FAA887FF4CD5BFC0F43B4A4EEA2A7E6927F3701B273C2"
ANONYMOUS_NUMBERS_COLLECTION = "EQAOQdwdw8kGftJCSFgOErM1mBjYPe4DBPq8-AhF6vr9si5N"
ANONYMOUS_NUMBERS_RAW = "0:0E41DC1DC3C9067ED24248580E12B3359818D83DEE0304FABCF80845EAFAFDB2"
#: TON Foundation wallet (public organisation wallet, verified live 2026-11-26): the health-check probe
TON_FOUNDATION_RAW = "0:83DFD552E63729B472FCBCC8C45EBCC6691702558B68EC7527E1BA403A0F31A8"
OWNER_LABEL = ("current NFT owner wallet of the collectible number/username (ownership can change; transfer date "
               "shown)")
COUNTERPARTY_LABEL = "counterparty (role unknown)"
SUBJECT_ROLES = frozenset({"fraud", "threat"})
NANO_PER_TON = Decimal(1_000_000_000)

_RAW_RE = re.compile(r"^(-1|0):([0-9a-fA-F]{64})$")
_FRIENDLY_RE = re.compile(r"^[A-Za-z0-9+/_-]{48}$")
_FLAG_BOUNCEABLE = 0x11
_FLAG_NON_BOUNCEABLE = 0x51
_FLAG_TESTNET = 0x80
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


# --------------------------------------------------------------------------------------
# TON address codec (cond 1)
# --------------------------------------------------------------------------------------


def crc16_xmodem(data: bytes) -> int:
    """CRC-16/XMODEM (poly 0x1021, init 0): the checksum of TON user-friendly addresses (check value 0x31C3)."""
    crc = 0
    for byte in bytes(data):
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def decode_ton_address(text: Any) -> dict[str, Any] | None:
    """Raw 'wc:hex' or user-friendly 48-character base64/base64url -> dict, or None.

    Friendly form = base64(flags, workchain int8, 32-byte account id, CRC16-XMODEM big-endian); flags 0x11
    bounceable / 0x51 non-bounceable, +0x80 testnet; workchain 0 or -1. A string mixing both base64 alphabets is
    refused. Returns {'raw' ('wc:UPPERHEX'), 'workchain', 'form', 'bounceable', 'testnet'}.
    """
    if not isinstance(text, str):
        return None
    value = text.strip()
    match = _RAW_RE.match(value)
    if match:
        return {"raw": f"{match.group(1)}:{match.group(2).upper()}", "workchain": int(match.group(1)), "form": "raw",
                "bounceable": None, "testnet": None}
    if not _FRIENDLY_RE.match(value):
        return None
    if ("-" in value or "_" in value) and ("+" in value or "/" in value):
        return None
    try:
        data = base64.b64decode(value.replace("-", "+").replace("_", "/"), validate=True)
    except ValueError:
        return None
    if len(data) != 36:
        return None
    flags, workchain = data[0], data[1]
    tag = flags & ~_FLAG_TESTNET
    if tag not in (_FLAG_BOUNCEABLE, _FLAG_NON_BOUNCEABLE):
        return None
    workchain = workchain - 256 if workchain > 127 else workchain
    if workchain not in (0, -1) or crc16_xmodem(data[:34]) != int.from_bytes(data[34:], "big"):
        return None
    return {"raw": f"{workchain}:{data[2:34].hex().upper()}", "workchain": workchain, "form": "friendly",
            "bounceable": tag == _FLAG_BOUNCEABLE, "testnet": bool(flags & _FLAG_TESTNET)}


def encode_ton_address(raw: Any, *, bounceable: bool = True, testnet: bool = False, url_safe: bool = True) -> str | None:
    """'0:HEX' -> user-friendly form (EQ... bounceable / UQ... non-bounceable on mainnet), or None."""
    match = _RAW_RE.match(raw.strip()) if isinstance(raw, str) else None
    if not match:
        return None
    flags = (_FLAG_BOUNCEABLE if bounceable else _FLAG_NON_BOUNCEABLE) | (_FLAG_TESTNET if testnet else 0)
    body = bytes([flags, int(match.group(1)) & 0xFF]) + bytes.fromhex(match.group(2))
    body += crc16_xmodem(body).to_bytes(2, "big")
    out = base64.b64encode(body).decode("ascii")
    return out.replace("+", "-").replace("/", "_") if url_safe else out


def ton_raw(value: Any) -> str | None:
    """Any TON address form -> 'wc:UPPERHEX', or None."""
    info = decode_ton_address(value)
    return info["raw"] if info else None


def address_forms(raw: str) -> dict[str, Any]:
    return {"raw": raw, "bounceable": encode_ton_address(raw, bounceable=True),
            "non_bounceable": encode_ton_address(raw, bounceable=False), "workchain": int(raw.split(":", 1)[0])}


# --------------------------------------------------------------------------------------
# gates (cond 2)
# --------------------------------------------------------------------------------------


def ton_phone_gate(value: Any) -> str | None:
    """+888 anonymous number -> token '888XXXXXXXX' (or '888XXXX'); any other phone number -> None."""
    if not isinstance(value, str):
        return None
    digits = re.sub(r"[\s().-]", "", value.strip())
    digits = digits[1:] if digits.startswith("+") else digits
    if not digits.isdigit() or not digits.startswith("888") or len(digits) not in (7, 11):
        return None
    return digits


def ton_username_gate(value: Any) -> str | None:
    """Collectible-format Telegram username -> lower-case token, else None.

    Accepts '@name', 'name', 't.me/name', 'https://t.me/name', 'name.t.me'. Collectible (Fragment) usernames have
    4-32 characters [a-z0-9_], start with a letter, no trailing '_' and no '__'. Whether it IS collectible is only
    known from the lookup (EMPTY 'not a collectible username').
    """
    if not isinstance(value, str):
        return None
    text = re.sub(r"^(?:https?://)?(?:t\.me|telegram\.me)/", "", value.strip(), flags=re.I)
    text = re.sub(r"\.t\.me$", "", text, flags=re.I).lstrip("@").lower()
    if not re.fullmatch(r"[a-z][a-z0-9_]{3,31}", text) or text.endswith("_") or "__" in text:
        return None
    return text


def collectible_token(entity: Entity) -> tuple[str, str] | None:
    """('number' | 'username', token) for a gated phone/username entity, else None."""
    if entity.type is T.PHONE:
        token = ton_phone_gate(entity.value)
        return ("number", token) if token else None
    if entity.type in (T.USERNAME, T.TELEGRAM_HANDLE):
        token = ton_username_gate(entity.value)
        return ("username", token) if token else None
    return None


def subject_gate(entity: Entity, ctx: Any) -> str | None:
    """Cond 2 privacy gate -> None when allowed, else the refusal reason (SKIPPED 'privacy')."""
    if not getattr(ctx, "is_seed", False) or int(getattr(ctx, "depth", 0) or 0) > 0:
        return "collectible lookups run only on analyst-typed seeds (never on pivots or auto-expanded values)"
    options = getattr(ctx, "options", None)
    roles = getattr(options, "subject_roles", None) or {}
    role = str(roles.get(entity.key, "") or "").strip().lower() if isinstance(roles, dict) else ""
    if role not in SUBJECT_ROLES:
        return "the value must already be a fraud/threat subject of the case (subject role 'fraud' or 'threat')"
    if not str(getattr(ctx, "purpose", "") or "").strip():
        return "purpose not recorded (--purpose)"
    return None


# --------------------------------------------------------------------------------------
# Toncenter parsers (untrusted JSON)
# --------------------------------------------------------------------------------------


def nft_index(token: str) -> int:
    """Telegram collectible item index = int(sha256(token)) (Telemint string_hash; verified live for usernames)."""
    return int.from_bytes(hashlib.sha256(token.encode("utf-8")).digest(), "big")


def nft_request(kind: str, token: str) -> tuple[dict[str, str], dict[str, str]]:
    """(params, expected) for GET nft/items of one token (limit 1: never a range)."""
    collection = TELEGRAM_USERNAMES_COLLECTION if kind == "username" else ANONYMOUS_NUMBERS_COLLECTION
    index = str(nft_index(token))
    return ({"collection_address": collection, "index": index, "limit": "1", "offset": "0"},
            {"kind": kind, "token": token, "index": index})


def _clean(value: Any, limit: int = 128) -> str | None:
    if not isinstance(value, str):
        return None
    text = re.sub(r"\s+", " ", _CONTROL_RE.sub("", value)).strip()
    return text[:limit] or None


def nano_to_ton(value: Any) -> str | None:
    """Nanotons (int or numeric string) -> '1.5' TON string, or None."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = Decimal(str(value).strip())
    except InvalidOperation:
        return None
    if not number.is_finite() or number < 0 or number != number.to_integral_value():
        return None
    text = format((number / NANO_PER_TON).quantize(Decimal("0.000000001")), "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def _iso(epoch: Any) -> str | None:
    try:
        value = int(str(epoch).strip())
    except (TypeError, ValueError):
        return None
    if isinstance(epoch, bool) or not 0 < value < 32503680000:
        return None
    return _dt.datetime.fromtimestamp(value, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _book(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    book: dict[str, dict[str, Any]] = {}
    raw_book = data.get("address_book")
    if isinstance(raw_book, dict):
        for key, entry in list(raw_book.items())[:500]:
            raw = ton_raw(key)
            if raw and isinstance(entry, dict):
                friendly = entry.get("user_friendly") if isinstance(entry.get("user_friendly"), str) else None
                interfaces = entry.get("interfaces") if isinstance(entry.get("interfaces"), list) else []
                book[raw] = {"friendly": friendly if friendly and ton_raw(friendly) == raw else None,
                             "interfaces": [str(i)[:32] for i in interfaces[:10] if isinstance(i, str)]}
    return book


def _friendly(raw: str | None, book: dict[str, dict[str, Any]], bounceable: bool = False) -> str | None:
    entry = book.get(raw or "")
    if entry and entry.get("friendly"):
        return entry["friendly"]
    return encode_ton_address(raw, bounceable=bounceable) if raw else None


def _collection_kind(raw: str | None) -> str:
    return {TELEGRAM_USERNAMES_RAW: "username", ANONYMOUS_NUMBERS_RAW: "number"}.get(raw or "", "other")


def parse_nft_items(data: Any, expected: dict[str, str]) -> dict[str, Any]:
    """GET nft/items -> {'status' found|empty|error, 'item', 'reason'} (cond 3).

    The item is re-checked against the request: collection, index and token (``content.domain == '<name>.t.me'``
    or the metadata name '@name'; numbers: uri '/number/<digits>.json' or name '+888 ...'). A mismatch is EMPTY,
    never a wrong owner. When the item is on sale ``owner_address`` is the sale contract: the owner is
    ``real_owner`` and the sale contract is reported apart.
    """
    if not isinstance(data, dict) or not isinstance(data.get("nft_items"), list):
        reason = _clean(data.get("error"), 160) if isinstance(data, dict) else None
        return {"status": "error", "item": None, "reason": reason or "no nft_items list in the Toncenter answer"}
    book = _book(data)
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    items = [i for i in data["nft_items"][:5] if isinstance(i, dict)]
    if not items:
        return {"status": "empty", "item": None, "reason": f"no NFT item for this index: not a collectible {expected['kind']}"}
    for raw_item in items:
        address = ton_raw(raw_item.get("address"))
        collection = ton_raw(raw_item.get("collection_address"))
        owner = ton_raw(raw_item.get("owner_address"))
        real_owner = ton_raw(raw_item.get("real_owner"))
        on_sale = raw_item.get("on_sale") is True
        current = real_owner or owner
        content = raw_item.get("content") if isinstance(raw_item.get("content"), dict) else {}
        meta = metadata.get(raw_item.get("address")) if isinstance(raw_item.get("address"), str) else None
        name = None
        if isinstance(meta, dict) and isinstance(meta.get("token_info"), list):
            for info in meta["token_info"][:3]:
                if isinstance(info, dict) and isinstance(info.get("name"), str):
                    name = _clean(info["name"], 64)
                    break
        item = {"address": address, "address_friendly": _friendly(address, book, bounceable=True),
                "index": str(raw_item.get("index")) if raw_item.get("index") is not None else None,
                "collection": collection, "kind": _collection_kind(collection),
                "domain": _clean(content.get("domain")), "uri": _clean(content.get("uri"), 256), "name": name,
                "owner": current, "owner_friendly": _friendly(current, book),
                "owner_interfaces": (book.get(current or "") or {}).get("interfaces", []),
                "on_sale": on_sale, "sale_contract": owner if (on_sale and owner and owner != current) else None}
        if _matches(expected, item):
            if not item["owner"]:
                return {"status": "error", "item": item, "reason": "NFT item without an owner address"}
            return {"status": "found", "item": item, "reason": None}
    return {"status": "empty", "item": None,
            "reason": f"the answer is for another NFT item (index/token mismatch): not a collectible {expected['kind']}"}


def _matches(expected: dict[str, str], item: dict[str, Any]) -> bool:
    if item["index"] != expected["index"]:
        return False
    token = expected["token"]
    if expected["kind"] == "username":
        return item["kind"] == "username" and ((item["domain"] or "").lower() == f"{token}.t.me"
                                               or (item["name"] or "").lower() == f"@{token}")
    return item["kind"] == "number" and ((item["uri"] or "").endswith(f"/{token}.json")
                                         or (item["name"] or "").replace(" ", "") == f"+{token}")


def parse_nft_transfers(data: Any) -> dict[str, Any]:
    """GET nft/transfers?sort=desc -> {'status', 'latest' (newest non-aborted transfer)}."""
    if not isinstance(data, dict) or not isinstance(data.get("nft_transfers"), list):
        return {"status": "error", "latest": None, "count": 0}
    transfers = []
    for raw in data["nft_transfers"][:20]:
        if not isinstance(raw, dict):
            continue
        epoch = raw.get("transaction_now")
        transfers.append({"time": _iso(epoch), "epoch": epoch if isinstance(epoch, int) and not isinstance(epoch, bool) else 0,
                          "new_owner": ton_raw(raw.get("new_owner")), "aborted": raw.get("transaction_aborted") is True})
    transfers.sort(key=lambda t: t["epoch"], reverse=True)
    latest = next((t for t in transfers if not t["aborted"] and t["new_owner"]), None)
    return {"status": "found" if transfers else "empty", "latest": latest, "count": len(transfers)}


def owner_lead(item: dict[str, Any], transfers: dict[str, Any] | None) -> dict[str, Any]:
    """The PROBABLE, expand=False owner-wallet lead of cond 3 with its transfer date (or why none is shown)."""
    latest = (transfers or {}).get("latest")
    date, note = None, None
    if latest and latest.get("new_owner") == item["owner"]:
        date = latest.get("time")
    elif latest:
        note = "the latest indexed transfer went to another wallet (sale contract or index lag): date not shown"
    elif transfers is None:
        note = "transfer history could not be read: date not shown"
    else:
        note = "no transfer indexed (minted directly to this wallet, or an index gap)"
    if item["kind"] == "username":
        token = item["name"] or (("@" + item["domain"][:-5]) if (item["domain"] or "").endswith(".t.me") else None)
    else:
        token = item["name"]
    return {"raw": item["owner"], "friendly": item["owner_friendly"], "token": token, "kind": item["kind"],
            "nft_item": item["address_friendly"], "on_sale": item["on_sale"], "sale_contract": item["sale_contract"],
            "owner_interfaces": item["owner_interfaces"], "transfer_date": date, "transfer_date_note": note,
            "label": OWNER_LABEL, "identity_proof": False}


def parse_wallet_information(data: Any, status: int) -> dict[str, Any]:
    """GET walletInformation -> status found | not_wallet (409) | invalid (422/400) | error."""
    message = _clean(data.get("error"), 160) if isinstance(data, dict) else None
    if status == 409 or (message and "not a wallet" in message.lower()):
        return {"status": "not_wallet", "reason": message or "not a wallet"}
    if status in (400, 422):
        return {"status": "invalid", "reason": message or f"HTTP {status}"}
    if not isinstance(data, dict) or status != 200 or message:
        return {"status": "error", "reason": message or "unexpected Toncenter walletInformation answer"}
    balance = nano_to_ton(data.get("balance"))
    state = data.get("status") if isinstance(data.get("status"), str) else None
    if balance is None and state is None:
        return {"status": "error", "reason": "walletInformation without balance and status"}
    seqno = data.get("seqno")
    return {"status": "found", "balance_ton": balance, "wallet_type": _clean(data.get("wallet_type"), 40),
            "seqno": seqno if isinstance(seqno, int) and not isinstance(seqno, bool) else None,
            "account_status": _clean(state, 20),
            "last_transaction_lt": str(data.get("last_transaction_lt"))[:24] if data.get("last_transaction_lt") else None}


def _message(msg: Any) -> dict[str, Any] | None:
    if not isinstance(msg, dict):
        return None
    content = msg.get("message_content") if isinstance(msg.get("message_content"), dict) else {}
    decoded = content.get("decoded") if isinstance(content.get("decoded"), dict) else {}
    return {"source": ton_raw(msg.get("source")), "destination": ton_raw(msg.get("destination")),
            "value": nano_to_ton(msg.get("value")), "has_comment": decoded.get("type") == "text_comment"}


def parse_transactions(data: Any, account: str) -> dict[str, Any] | None:
    """GET transactions?account=..&sort=desc -> {'transactions': [...]} or None for an odd answer.

    Each transaction: hash, epoch, aborted, in (source, value) and out [(destination, value)]. Comment texts are
    never kept (deposit memos can be personal); only their presence is counted."""
    if not isinstance(data, dict) or not isinstance(data.get("transactions"), list):
        return None
    out = []
    for raw in data["transactions"][: TX_LIMIT * 2]:
        if not isinstance(raw, dict) or ton_raw(raw.get("account")) != account:
            continue
        description = raw.get("description") if isinstance(raw.get("description"), dict) else {}
        outs = raw.get("out_msgs") if isinstance(raw.get("out_msgs"), list) else []
        now = raw.get("now")
        out.append({"hash": raw.get("hash") if isinstance(raw.get("hash"), str) else None,
                    "epoch": now if isinstance(now, int) and not isinstance(now, bool) else None,
                    "aborted": description.get("aborted") is True, "in": _message(raw.get("in_msg")),
                    "out": [m for m in (_message(x) for x in outs[:50]) if m]})
    return {"transactions": out}


def summarize_transactions(account: str, txs: list[dict[str, Any]]) -> dict[str, Any]:
    """Counterparties (value-carrying internal messages of non-aborted transactions), activity window."""
    agg: dict[str, dict[str, Any]] = {}
    times = [t["epoch"] for t in txs if t["epoch"]]
    comments = 0

    def add(addr: str, side: str, value: str, epoch: int | None) -> None:
        rec = agg.setdefault(addr, {"address": addr, "received_from": Decimal(0), "sent_to": Decimal(0), "tx_count": 0,
                                    "in_tx_count": 0, "out_tx_count": 0, "first": None, "last": None})
        rec["received_from" if side == "in" else "sent_to"] += Decimal(value)
        rec["in_tx_count" if side == "in" else "out_tx_count"] += 1
        rec["tx_count"] += 1
        if epoch:
            rec["first"] = epoch if rec["first"] is None else min(rec["first"], epoch)
            rec["last"] = epoch if rec["last"] is None else max(rec["last"], epoch)

    for tx in txs:
        incoming = tx["in"]
        comments += sum(1 for m in [incoming, *tx["out"]] if m and m["has_comment"])
        if tx["aborted"]:
            continue
        if incoming and incoming["source"] and incoming["source"] != account and incoming["value"] not in (None, "0"):
            add(incoming["source"], "in", incoming["value"], tx["epoch"])
        for msg in tx["out"]:
            if msg["destination"] and msg["destination"] != account and msg["value"] not in (None, "0"):
                add(msg["destination"], "out", msg["value"], tx["epoch"])
    ranked = sorted(agg.values(), key=lambda r: (-(r["received_from"] + r["sent_to"]), -r["tx_count"], r["address"]))
    cps = []
    for rec in ranked[:TOP_COUNTERPARTIES]:
        direction = "both" if rec["in_tx_count"] and rec["out_tx_count"] else ("out" if rec["out_tx_count"] else "in")
        cps.append({"address": rec["address"], "direction": direction,
                    "received_from": f"{_dec(rec['received_from'])} TON", "sent_to": f"{_dec(rec['sent_to'])} TON",
                    "tx_count": rec["tx_count"], "in_tx_count": rec["in_tx_count"], "out_tx_count": rec["out_tx_count"],
                    "first_seen": _iso(rec["first"]), "last_seen": _iso(rec["last"]), "label": COUNTERPARTY_LABEL})
    return {"transactions_read": len(txs), "counterparties": cps, "counterparties_total": len(agg),
            "first_seen": _iso(min(times)) if times else None, "last_seen": _iso(max(times)) if times else None,
            "comments_seen": comments}


def _dec(value: Decimal) -> str:
    text = format(value.normalize(), "f") if value != 0 else "0"
    return text


def _json(content: bytes) -> Any:
    try:
        return json.loads(content.decode("utf-8", "replace"))
    except ValueError:
        return None


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class TonExplorer(Module):
    name = "ton_explorer"
    title = "TON explorer and Telegram collectible owner (Toncenter)"
    description = (
        "TON wallet state and top counterparties from Toncenter v3; for +888 anonymous numbers and collectible Telegram "
        "usernames of fraud/threat case subjects, the current owner wallet of the collectible NFT (a dated lead)."
    )
    category = "crypto"
    accepts = {T.CRYPTO, T.PHONE, T.USERNAME, T.TELEGRAM_HANDLE}
    produces = {T.CRYPTO}
    tags = {"free"}
    reference = "https://toncenter.com/api/v3/index.html"
    notice = (
        "Toncenter receives the TON address, or the sha256 index of a +888 number / collectible username (trivially "
        "reversible: treat it as the identifier). Collectible lookups run only for analyst-typed fraud/threat subjects "
        "with a recorded purpose (P214 cond 2). The owner wallet is the CURRENT NFT owner - ownership can change - and a "
        "lead, never identity proof. Flow idea from a_TON_of_privacy (MIT); tonapi.io and getgems.io are not used."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "toncenter"
    sources = (SOURCE,)
    hosts = ("toncenter.com",)
    access_model = "free_noauth_limited"
    optional_keys = (KEY,)
    max_requests = 3
    expected_latency = 1.5
    timeout = 30.0
    min_interval = KEYED_INTERVAL  # keyless runs ask for KEYLESS_INTERVAL per call (1 request/s)
    daily_quota = 500
    cache_ttl = 3600
    max_pivots = TOP_COUNTERPARTIES + 1
    default_enabled = False

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(T.CRYPTO, TON_FOUNDATION_RAW)  # the TON Foundation wallet (public organisation wallet)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.CRYPTO:
            info = decode_ton_address(entity.value)
            return info is not None and not info["testnet"]  # cond 1: only valid mainnet TON addresses are sent
        return collectible_token(entity) is not None  # cond 2: +888 numbers / collectible-format usernames only

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type is T.CRYPTO:
            info = decode_ton_address(entity.value)
            if info is None or info["testnet"]:
                return res.mark("skipped", "not a valid mainnet TON address: never sent", reason_code="not_applicable")
            return self._address(res, info["raw"], ctx)
        token = collectible_token(entity)
        if token is None:
            return res.mark("skipped", "only +888 anonymous numbers and collectible-format Telegram usernames apply",
                            reason_code="not_applicable")
        refusal = subject_gate(entity, ctx)
        if refusal:
            return res.mark("skipped", f"collectible owner lookup refused: {refusal} (P214 cond 2)", reason_code="privacy")
        return self._collectible(res, token[0], token[1], ctx)

    # ------------------------------------------------------------------ HTTP
    def _get(self, ctx: Any, path: str, params: dict[str, str], handled: tuple[int, ...] = ()) -> Any:
        headers = {"Accept": "application/json"}
        key = str(ctx.key(KEY) or "").strip()
        kw: dict[str, Any] = {}
        if key:
            headers[KEY_HEADER] = key
        else:
            kw["min_interval"] = KEYLESS_INTERVAL
        resp = ctx.http.get(BASE + path, params=params, headers=headers, source=SOURCE, ttl=self.cache_ttl, **kw)
        if resp.status in handled:
            try:
                ctx.http.check(resp)  # a challenge page or a marker still raises (could not verify)
            except HttpError:
                if resp.classification is not None:
                    raise
            return resp
        ctx.http.check(resp)
        return resp

    # ------------------------------------------------------------------ address lookups
    def _address(self, res: ModuleResult, raw: str, ctx: Any) -> ModuleResult:
        as_of = ctx.now().date().isoformat()
        resp = self._get(ctx, "walletInformation", {"address": raw, "use_v2": "false"}, handled=(400, 409, 422))
        wallet = parse_wallet_information(_json(resp.content), resp.status)
        if wallet["status"] == "invalid":
            return res.mark("error", f"Toncenter rejected the address ({wallet['reason']}): could not verify")
        if wallet["status"] == "error":
            return res.mark("error", f"{wallet['reason']}: could not verify")
        res.attr("chain", "ton")  # recorded only once Toncenter answered (a stop never turns into ok)
        res.attr("ton_address_forms", address_forms(raw))
        if wallet["status"] == "not_wallet":
            res.attr("account_type", "contract (not a wallet)")
        else:
            res.attr("ton_wallet", {k: wallet[k] for k in ("balance_ton", "wallet_type", "seqno", "account_status", "last_transaction_lt")})
            res.attr("balance", f"{wallet['balance_ton']} TON" if wallet["balance_ton"] is not None else None)
            res.attr("account_type", wallet["wallet_type"])
            if wallet["account_status"] in ("uninit", "nonexist") and wallet["balance_ton"] in (None, "0") and not wallet["last_transaction_lt"]:
                res.attr("wallet_status", f"no on-chain activity (status {wallet['account_status']}, as of {as_of})")
                res.raw = {"wallet": wallet}
                return res.mark("empty")
        resp = self._get(ctx, "transactions", {"account": raw, "limit": str(TX_LIMIT), "offset": "0", "sort": "desc"})
        parsed = parse_transactions(_json(resp.content), raw)
        if parsed is None:
            return res.mark("error", "unexpected Toncenter transactions answer: could not verify")
        summary = summarize_transactions(raw, parsed["transactions"])
        res.attr("transfers_seen", summary["transactions_read"])
        res.attr("first_seen", summary["first_seen"])
        res.attr("last_activity", summary["last_seen"])
        res.attr("top_counterparties", summary["counterparties"])
        kind = "contract" if wallet["status"] == "not_wallet" else f"wallet ({wallet.get('wallet_type') or 'unknown type'})"
        balance = f", balance {wallet['balance_ton']} TON" if wallet.get("balance_ton") is not None else ""
        res.finding(
            "TON account activity (Toncenter)",
            "info",
            f"TON {kind}{balance}; {summary['transactions_read']} newest transaction(s) read (at most {TX_LIMIT}), first "
            f"{summary['first_seen'] or 'unknown'}, last {summary['last_seen'] or 'unknown'}; {summary['counterparties_total']} "
            f"counterparties, top {len(summary['counterparties'])} listed (never expanded automatically: P213); "
            f"{summary['comments_seen']} message comment(s) not stored. Data as of {as_of}.",
            confidence="confirmed",
            data={"wallet": wallet, "transactions_read": summary["transactions_read"],
                  "counterparties": summary["counterparties"], "counterparties_total": summary["counterparties_total"]},
            source=SOURCE,
            observed_first=summary["first_seen"],
            observed_last=summary["last_seen"],
        )
        for cp in summary["counterparties"]:
            res.pivot(T.CRYPTO, cp["address"], "transacted_with", confidence="probable", expand=False,
                      note=(f"{COUNTERPARTY_LABEL}: TON, direction {cp['direction']}, in {cp['received_from']}, out "
                            f"{cp['sent_to']}, {cp['tx_count']} tx in the {summary['transactions_read']} newest read "
                            "(P213 decides expansion)"))
        res.link("Tonviewer address page", TONVIEWER.format(address=encode_ton_address(raw, bounceable=False) or raw))
        res.raw = {"wallet": wallet, "summary": {k: v for k, v in summary.items() if k != "counterparties"},
                   "tx_hashes": [t["hash"] for t in parsed["transactions"] if t["hash"]][:TX_LIMIT]}
        return res

    # ------------------------------------------------------------------ collectible owner (cond 3)
    def _collectible(self, res: ModuleResult, kind: str, token: str, ctx: Any) -> ModuleResult:
        as_of = ctx.now().date().isoformat()
        params, expected = nft_request(kind, token)
        resp = self._get(ctx, "nft/items", params)
        items = parse_nft_items(_json(resp.content), expected)
        what = "anonymous number" if kind == "number" else "collectible username"
        res.raw = {"kind": kind, "nft_index": expected["index"], "status": items["status"]}
        if items["status"] == "empty":
            res.attr("wallet_status", f"not a Telegram {what}: {items['reason']} (Toncenter, as of {as_of})")
            return res.mark("empty")
        if items["status"] != "found":
            return res.mark("error", f"{items['reason']}: could not verify")
        item = items["item"]
        transfers: dict[str, Any] | None = None
        try:
            tresp = self._get(ctx, "nft/transfers", {"item_address": item["address"], "limit": str(TRANSFER_LIMIT),
                                                     "offset": "0", "sort": "desc"})
            transfers = parse_nft_transfers(_json(tresp.content))
            if transfers["status"] == "error":
                transfers = None
        except HttpError as exc:  # the owner stands; only the date is missing (could not verify the transfers)
            ctx.log(f"Toncenter nft/transfers failed ({str(exc)[:80]}): transfer date not shown", "warning")
        lead = owner_lead(item, transfers)
        res.attr("chain", "ton")
        res.attr("ton_collectible", {"kind": kind, "token": lead["token"], "nft_item": lead["nft_item"],
                                     "collection": item["collection"], "on_sale": lead["on_sale"],
                                     "sale_contract": encode_ton_address(lead["sale_contract"]) if lead["sale_contract"] else None,
                                     "owner": lead["friendly"] or lead["raw"], "transfer_date": lead["transfer_date"],
                                     "transfer_date_note": lead["transfer_date_note"], "label": OWNER_LABEL})
        when = (f"transferred to this wallet on {lead['transfer_date'][:10]}" if lead["transfer_date"]
                else lead["transfer_date_note"])
        sale = " The NFT is currently listed for sale (owner = the seller)." if lead["on_sale"] else ""
        res.finding(
            "Current NFT owner wallet of a Telegram collectible",
            "info",
            f"The Telegram {what} {lead['token'] or ''} is an NFT (item {lead['nft_item']}); its {OWNER_LABEL}: "
            f"{lead['friendly'] or lead['raw']} ({when}).{sale} A lead for the investigation of this case subject, never "
            f"identity proof: ownership can change and the wallet may be a custodial or marketplace wallet. As of {as_of}.",
            confidence="probable",
            data={"kind": kind, "owner": lead["friendly"] or lead["raw"], "owner_raw": lead["raw"], "nft_item": lead["nft_item"],
                  "on_sale": lead["on_sale"], "transfer_date": lead["transfer_date"], "transfer_date_note": lead["transfer_date_note"],
                  "owner_interfaces": lead["owner_interfaces"], "identity_proof": False},
            tags=["collectible_owner"],
            source=SOURCE,
            observed_last=lead["transfer_date"],
        )
        if lead["raw"].startswith("0:"):
            res.pivot(T.CRYPTO, lead["raw"], "current_nft_owner", confidence="probable", expand=False,
                      note=f"{OWNER_LABEL}; {when}; TON {lead['friendly'] or lead['raw']} (never identity proof)")
        res.raw.update({"nft_item": lead["nft_item"], "owner": lead["raw"], "transfer_date": lead["transfer_date"]})
        return res


__all__ = [
    "OWNER_LABEL",
    "TonExplorer",
    "address_forms",
    "collectible_token",
    "crc16_xmodem",
    "decode_ton_address",
    "encode_ton_address",
    "nano_to_ton",
    "nft_index",
    "nft_request",
    "owner_lead",
    "parse_nft_items",
    "parse_nft_transfers",
    "parse_transactions",
    "parse_wallet_information",
    "subject_gate",
    "summarize_transactions",
    "ton_phone_gate",
    "ton_raw",
    "ton_username_gate",
]
