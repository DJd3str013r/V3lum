"""pivots_crypto: chain-aware blockchain explorer links, manual only (P216, batch p2-G14-2).

Disclosure ``none``: the module only builds URLs; V3LUM never requests the explorer pages (P216 cond 1). The
pack is ``v3lum/data/pivot_links/crypto.json``:

* Bitcoin (``btc_address``) and EVM (``eth_address``) links are core pack links, rendered by the engine and by
  ``v3lum links`` in the curated order of P216 cond 6 (BTC: mempool.space, Blockchair, WalletExplorer,
  BitcoinWhosWho, Blockchain.com, bitref; EVM: Ethplorer, Blockchair, Blockchain.com, then the challenge-walled
  Etherscan, BscScan and Arkham, shipped unverified with antibot=true, P216 cond 9). EVM values are the
  lower-case form in URLs (matching, P219) and the EIP-55 form for display.
* ``other_crypto_address`` values are routed here by chain (P216 cond 8): the P217 validators
  (``validators.crypto_address_info``: base58check with the chain's version byte, TRON 'T' base58check;
  ``validators.segwit_decode('ltc', ...)`` for Litecoin bech32) and a cashaddr checksum for Bitcoin Cash select
  the ``x_module_links`` entry of that chain only (Blockchair Litecoin/Dogecoin/Bitcoin Cash, Tronscan), so an
  analyst never lands on an 'invalid address' page: Blockchair answers 200 with an empty dashboard for a BTC
  address on its Litecoin route. A value that is really a Bitcoin or EVM address gets the pack's links for that
  type; an unsupported chain gets no link (EMPTY).
* cond 10 - BitcoinWhosWho reports are in this pack; Chainabuse address reports (an SPA) belong to the
  unverified pack of P304; the batch lint refuses wallet-connect, payment, swap and donation pages.
* A2 - at TLP:AMBER and above every label carries 'opening sends <value> to <host>'; at RED nothing is emitted.
"""

from __future__ import annotations

import re
from typing import Any

from v3lum.core import links as _links
from v3lum.core import validators as val
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.utility import pivot_pack_render as pr

PACK = "crypto"
#: chain -> (resolver placeholder, x_module_links id)
CHAIN_LINKS: dict[str, tuple[str, str]] = {
    "ltc": ("ltc", "blockchair_ltc"),
    "doge": ("doge", "blockchair_doge"),
    "bch": ("bch", "blockchair_bch"),
    "tron": ("tron", "tronscan_address"),
}
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _cashaddr_polymod(values: list[int]) -> int:
    c = 1
    for d in values:
        c0 = c >> 35
        c = ((c & 0x07FFFFFFFF) << 5) ^ d
        for bit, g in ((1, 0x98F2BC8E61), (2, 0x79B76D99E2), (4, 0xF33E5FB3C4), (8, 0xAE2EABE2A8), (16, 0x1E4F43E470)):
            if c0 & bit:
                c ^= g
    return c ^ 1


def _convertbits(data: list[int], frombits: int, tobits: int) -> list[int] | None:
    acc = bits = 0
    out: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or value >> frombits:
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return out


def cashaddr_payload(value: Any) -> str | None:
    """Bitcoin Cash cashaddr ('bitcoincash:q...' or without the prefix, one letter case) -> the lower-case
    payload without the prefix when the BCH checksum and the 160-bit P2PKH/P2SH payload validate; else None.
    (Spec: github.com/bitcoincashorg/bitcoincash.org spec/cashaddr.md.)"""
    if not isinstance(value, str) or not 30 <= len(value) <= 120 or (value.lower() != value and value.upper() != value):
        return None
    a = value.lower()
    prefix, _, payload = a.rpartition(":")
    prefix = prefix or "bitcoincash"
    if prefix != "bitcoincash" or not payload or payload[0] not in "qp":
        return None
    data = [_BECH32.find(ch) for ch in payload]
    if any(i < 0 for i in data) or _cashaddr_polymod([ord(c) & 0x1F for c in prefix] + [0] + data) != 0:
        return None
    raw = _convertbits(data[:-8], 5, 8)
    if not raw or len(raw) != 21 or raw[0] not in (0, 8):
        return None
    return payload


def chain_of(value: str) -> tuple[str, str] | None:
    """(chain, canonical URL value) of an address, validated offline; None when no supported chain matches.
    Chains: btc (mainnet only), evm, ltc, doge, bch, tron."""
    if not isinstance(value, str) or _CTRL.search(value):
        return None
    v = value.strip()
    if not v or len(v) > 120 or any(c.isspace() for c in v):
        return None
    payload = cashaddr_payload(v)
    if payload is not None:
        return "bch", payload
    if v.lower().startswith("ltc1"):
        try:
            ok = val.segwit_decode("ltc", v.lower()) is not None if v.lower() == v or v.upper() == v else False
        except (ValueError, TypeError):
            ok = False
        return ("ltc", v.lower()) if ok else None
    info = val.crypto_address_info(v)
    if info is None or (info.chain == "eth" and info.checksum_ok is False):  # a wrong EIP-55 mixed case: no link
        return None
    if info.chain == "btc":
        return ("btc", info.normalized) if info.network == "mainnet" else None
    if info.chain == "eth":
        return "evm", v.lower()
    if info.chain in ("ltc", "doge", "tron") and info.network == "mainnet" and info.checksum_ok:
        return info.chain, info.normalized
    return None


def eip55(address: str) -> str:
    """EIP-55 display form of an EVM address ('' when it is not one)."""
    try:
        return val.eip55_checksum(address)
    except (ValueError, TypeError):
        return ""


@register
class PivotsCrypto(Module):
    name = "pivots_crypto"
    title = "Blockchain explorer links, chain-aware (manual)"
    description = (
        "Chain-aware explorer links for addresses typed as 'other crypto address' (Blockchair Litecoin, Dogecoin and "
        "Bitcoin Cash, Tronscan), selected by the P217 validators so an explorer never gets another chain's address. "
        "Bitcoin and EVM addresses get the crypto pack links (mempool.space, Blockchair, WalletExplorer, BitcoinWhosWho, "
        "Blockchain.com, bitref, Ethplorer, Etherscan, BscScan, Arkham). V3LUM never fetches them."
    )
    category = "crypto"
    accepts = {T.CRYPTO}
    produces = frozenset()
    reference = "https://blockchair.com/"
    tags = {"offline"}
    notice = (
        "Manual links only (never fetched). Explorer pages and labels are leads for the analyst, never proof of "
        "ownership. Tronscan opens in the browser and may require a challenge; no wallet-connect, payment, swap or "
        "donation page is ever linked."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # the module only builds URLs
    hosts = ()
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.01
    timeout = 10.0
    default_enabled = True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        level = pr.tlp_level(ctx)
        red = pr.hidden_reason(None, level)
        if red:
            return res.mark(Status.SKIPPED, red, reason_code="tlp")
        found = chain_of(entity.value)
        if found is None:
            res.raw = {"tlp": level.value_str, "chain": None, "links": [], "hidden": []}
            return res.mark(Status.EMPTY, "no supported chain validates this address (btc mainnet, evm, ltc, doge, bch, tron)")
        chain, url_value = found
        shown: list[dict[str, Any]] = []
        hidden: list[dict[str, str]] = []
        if chain in ("btc", "evm"):
            # a BTC/EVM address typed as 'other': the pack links of its real type (rendered by the core)
            typed = Entity.make("btc_address" if chain == "btc" else "eth_address", url_value)
            display = eip55(url_value) if chain == "evm" else ""
            for rendered in _links.pivot_links_for(typed, categories=("crypto",)):
                shown.append(pr.emit(res, typed, level, rendered, note=f"EIP-55 {display}" if display else ""))
        else:
            placeholder, link_id = CHAIN_LINKS[chain]
            ml = pr.module_links(PACK).get(link_id)
            rendered = pr.render(ml, entity, {placeholder: url_value}) if ml is not None else None
            if rendered is None:
                hidden.append({"id": link_id, "reason": "did not render (lint, tier or value)"})
            else:
                shown.append(pr.emit(res, entity, level, rendered, ml=ml, sent=url_value))
        res.raw = {"tlp": level.value_str, "chain": chain, "links": shown, "hidden": hidden}
        if not shown:
            return res.mark(Status.EMPTY)
        return res
