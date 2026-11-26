"""P217: offline crypto-address and onion validators (stdlib only), positive and negative vectors.

Vectors come from the council research samples (caipora_apis_cti offline validators, live_osint
self-test), BIP-173/350, EIP-55 and the Tor rend-spec; constructed vectors use small test-local encoders
so the version/witness rules are checked independently of remembered strings.
"""

from __future__ import annotations

import hashlib

import pytest

from v3lum.core import validators as v
from v3lum.core.detect import detect
from v3lum.core.entities import EntityType

KECCAK_EMPTY = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
SHA3_EMPTY = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
XMR_GENERAL_FUND = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
XRP_GENESIS = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
TRON_USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
DOGE_SAMPLE = "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"
BTC_GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
ONION_TORPROJECT = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
ONION_DDG = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"


# ---------------------------------------------------------------- test-local encoders


def bech32_encode(hrp: str, witver: int, program: bytes, encoding: str) -> str:
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    data = [witver] + v._convertbits(list(program), 8, 5, True)
    const = 1 if encoding == "bech32" else 0x2BC830A3
    values = v._bech32_hrp_expand(hrp) + data
    polymod = v._bech32_polymod(values + [0] * 6) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(charset[d] for d in data + checksum)


def xmr_encode(raw: bytes) -> str:
    full = {8: 11, 5: 7}
    out = []
    for i in range(0, len(raw), 8):
        block = raw[i : i + 8]
        n = int.from_bytes(block, "big")
        chars = []
        for _ in range(full[len(block)]):
            n, rem = divmod(n, 58)
            chars.append(v.B58_ALPHABET[rem])
        out.append("".join(reversed(chars)))
    return "".join(out)


def xmr_address(netbyte: int, body: bytes = bytes(range(64))) -> str:
    payload = bytes([netbyte]) + body
    return xmr_encode(payload + v.keccak256(payload)[:4])


# ---------------------------------------------------------------- Keccak / EIP-55


def test_keccak256_is_not_nist_sha3():
    assert v.keccak256(b"").hex() == KECCAK_EMPTY
    assert hashlib.sha3_256(b"").hexdigest() == SHA3_EMPTY != KECCAK_EMPTY
    assert v.keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    assert v.keccak256(b"The quick brown fox jumps over the lazy dog").hex() == (
        "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
    )
    assert v.keccak256("abc") == v.keccak256(b"abc")


def _sha3_with_our_permutation(data: bytes) -> bytes:
    """SHA3-256 = the same sponge with the 0x06 domain padding: proves the permutation and multi-block
    absorption against hashlib (Keccak-256 differs only by its 0x01 padding byte)."""
    rate = 136
    msg = bytearray(data) + b"\x06"
    while len(msg) % rate:
        msg.append(0)
    msg[-1] |= 0x80
    lanes = [0] * 25
    for off in range(0, len(msg), rate):
        for i in range(rate // 8):
            lanes[i] ^= int.from_bytes(msg[off + 8 * i : off + 8 * i + 8], "little")
        lanes = v._keccak_f1600(lanes)
    return b"".join(lanes[i].to_bytes(8, "little") for i in range(4))


@pytest.mark.parametrize("size", [0, 1, 135, 136, 137, 271, 272, 273, 1000])
def test_keccak_permutation_and_multiblock_absorption(size):
    data = bytes((i * 7 + 3) % 256 for i in range(size))
    assert _sha3_with_our_permutation(data) == hashlib.sha3_256(data).digest()
    assert v.keccak256(data) != hashlib.sha3_256(data).digest()  # the padding byte differs


@pytest.mark.parametrize(
    "addr",
    [
        "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    ],
)
def test_eip55_valid_vectors(addr):
    assert v.eip55_checksum(addr.lower()) == addr
    assert v.eip55_checksum(addr) == addr
    assert v.eth_checksum_state(addr) == "valid"


def test_eip55_invalid_and_no_checksum():
    bad = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"  # last letter case flipped
    assert v.eth_checksum_state(bad) == "invalid"
    assert v.eip55_checksum(bad) == "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    assert v.eth_checksum_state("0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae") == "none"
    assert v.eth_checksum_state("0xDE0B295669A9FD93D5F28D9EC85E40F4CB697BAE") == "none"
    for malformed in ("0x123", "0xZZ0B295669a9FD93d5F28D9Ec85E40f4cb697BAe", "", "hello"):
        with pytest.raises(ValueError):
            v.eth_checksum_state(malformed)
        with pytest.raises(ValueError):
            v.eip55_checksum(malformed)


# ---------------------------------------------------------------- Base58Check version tables


def test_base58check_research_vectors():
    assert v.base58check_decode(BTC_GENESIS)[0] == 0x00
    assert v.base58check_decode(TRON_USDT)[0] == 0x41
    assert v.base58check_decode(DOGE_SAMPLE)[0] == 0x1E
    with pytest.raises(ValueError):
        v.base58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")  # bad checksum
    with pytest.raises(ValueError):
        v.b58decode("0OIl")  # characters outside the alphabet


@pytest.mark.parametrize(
    "version,chain,kind,first",
    [
        (0x00, "btc", "p2pkh", "1"),
        (0x05, "btc", "p2sh", "3"),
        (0x6F, "btc", "p2pkh", None),
        (0xC4, "btc", "p2sh", "2"),
        (0x30, "ltc", "p2pkh", "L"),
        (0x32, "ltc", "p2sh", "M"),
        (0x1E, "doge", "p2pkh", "D"),
        (0x16, "doge", "p2sh", None),
        (0x4C, "dash", "p2pkh", "X"),
        (0x10, "dash", "p2sh", "7"),
        (0x41, "tron", "account", "T"),
    ],
)
def test_base58check_version_table(version, chain, kind, first):
    addr = v.base58check_encode(bytes([version]) + bytes(range(1, 21)))
    if first:
        assert addr[0] == first
    info = v.crypto_address_info(addr)
    assert info is not None and (info.chain, info.kind, info.checksum_ok) == (chain, kind, True)
    assert info.confidence >= 0.9
    broken = addr[:-1] + ("2" if addr[-1] != "2" else "3")
    assert v.crypto_address_info(broken) is None  # checksum required


def test_unknown_base58_version_is_not_typed():
    addr = v.base58check_encode(bytes([0x99]) + bytes(range(1, 21)))
    assert v.crypto_address_info(addr) is None


def test_research_sample_chains():
    assert v.crypto_address_info(TRON_USDT).chain == "tron"
    assert v.crypto_address_info(DOGE_SAMPLE).chain == "doge"
    btc = v.crypto_address_info(BTC_GENESIS)
    assert (btc.chain, btc.kind, btc.network, btc.entity_type) == ("btc", "p2pkh", "mainnet", "btc_address")
    assert v.crypto_address_info("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").kind == "p2sh"


# ---------------------------------------------------------------- Bech32 vs Bech32m


def test_bech32_bip_vectors():
    v0 = v.crypto_address_info("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")
    assert (v0.chain, v0.kind, v0.normalized) == ("btc", "p2wpkh", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    v1 = v.crypto_address_info("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")
    assert (v1.chain, v1.kind) == ("btc", "p2tr")
    assert v.crypto_address_info("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5") is None  # bad checksum
    assert v.crypto_address_info("bc1qW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") is None  # mixed case


@pytest.mark.parametrize("hrp,chain", [("bc", "btc"), ("tb", "btc"), ("ltc", "ltc")])
def test_witness_version_selects_the_checksum(hrp, chain):
    prog20, prog32 = bytes(range(20)), bytes(range(32))
    good_v0 = bech32_encode(hrp, 0, prog20, "bech32")
    good_v1 = bech32_encode(hrp, 1, prog32, "bech32m")
    wrong_v0 = bech32_encode(hrp, 0, prog20, "bech32m")  # checksum fine, wrong scheme for v0
    wrong_v1 = bech32_encode(hrp, 1, prog32, "bech32")  # checksum fine, wrong scheme for v1+
    assert v.bech32_decode(wrong_v0)[2] == "bech32m" and v.bech32_decode(wrong_v1)[2] == "bech32"
    assert v.crypto_address_info(good_v0).chain == chain and v.crypto_address_info(good_v0).kind == "p2wpkh"
    assert v.crypto_address_info(good_v1).kind == "p2tr"
    assert v.crypto_address_info(wrong_v0) is None
    assert v.crypto_address_info(wrong_v1) is None
    if chain == "btc":
        assert v.btc_address_valid(good_v0) and not v.btc_address_valid(wrong_v0) and not v.btc_address_valid(wrong_v1)


def test_bech32_program_length_rules():
    assert v.crypto_address_info(bech32_encode("bc", 0, bytes(25), "bech32")) is None  # v0 needs 20/32 bytes
    assert v.crypto_address_info(bech32_encode("bc", 0, bytes(32), "bech32")).kind == "p2wsh"
    assert v.crypto_address_info(bech32_encode("bc", 2, bytes(16), "bech32m")).kind == "segwit_v2"


def test_btc_address_info_outputs_unchanged():
    assert v.btc_address_info(BTC_GENESIS) == {"network": "mainnet", "type": "P2PKH (legacy)"}
    assert v.btc_address_info("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297") == {
        "network": "mainnet",
        "type": "P2TR (taproot)",
    }
    assert v.btc_address_info(TRON_USDT) is None  # other chains are not Bitcoin


# ---------------------------------------------------------------- EVM via crypto_address_info


def test_evm_confidence_by_checksum_state():
    ok = v.crypto_address_info("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe")
    assert (ok.chain, ok.checksum_ok, ok.entity_type) == ("eth", True, "eth_address") and ok.confidence >= 0.95
    none = v.crypto_address_info("0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae")
    assert none.checksum_ok is None and none.normalized == "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
    bad = v.crypto_address_info("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD")
    assert bad.checksum_ok is False and bad.confidence <= 0.3


# ---------------------------------------------------------------- Monero


def test_monero_research_vector_and_mutations():
    assert v.xmr_address_valid(XMR_GENERAL_FUND)
    assert v.xmr_address_info(XMR_GENERAL_FUND) == {"network": "mainnet", "type": "standard"}
    assert not v.xmr_address_valid(XMR_GENERAL_FUND[:-1] + "B")  # checksum
    assert not v.xmr_address_valid(XMR_GENERAL_FUND[:50] + "1" + XMR_GENERAL_FUND[51:])
    assert not v.xmr_address_valid(XMR_GENERAL_FUND[:-1])  # length
    info = v.crypto_address_info(XMR_GENERAL_FUND)
    assert (info.chain, info.kind, info.checksum_ok, info.entity_type) == ("xmr", "standard", True, "xmr_address")


def test_monero_network_bytes():
    sub = xmr_address(42)
    assert sub.startswith("8") and len(sub) == 95 and v.xmr_address_info(sub)["type"] == "subaddress"
    std = xmr_address(18)
    assert std.startswith("4") and v.xmr_address_valid(std)
    integrated = xmr_encode(bytes([19]) + bytes(range(72)) + v.keccak256(bytes([19]) + bytes(range(72)))[:4])
    assert len(integrated) == 106 and v.xmr_address_info(integrated)["type"] == "integrated"
    assert not v.xmr_address_valid(xmr_address(53))  # testnet byte: not a mainnet address
    assert not v.xmr_address_valid(xmr_address(19))  # integrated byte on a 69-byte payload


def test_keccak_checksum_differs_from_sha3():
    payload = bytes([18]) + bytes(range(64))
    wrong = xmr_encode(payload + hashlib.sha3_256(payload).digest()[:4])
    assert not v.xmr_address_valid(wrong)


# ---------------------------------------------------------------- XRP and Solana


def test_xrp_ripple_alphabet():
    assert v.xrp_address_valid(XRP_GENESIS)
    assert not v.xrp_address_valid(XRP_GENESIS[:-1] + ("j" if XRP_GENESIS[-1] != "j" else "k"))
    assert not v.xrp_address_valid(BTC_GENESIS)  # Bitcoin alphabet, no 'r'
    info = v.crypto_address_info(XRP_GENESIS)
    assert (info.chain, info.kind, info.checksum_ok) == ("xrp", "account", True)


def test_solana_is_plausibility_only():
    for addr in ("So11111111111111111111111111111111111111112", "11111111111111111111111111111111",
                 "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"):
        assert v.sol_address_plausible(addr)
        info = v.crypto_address_info(addr)
        assert info.chain == "sol" and info.checksum_ok is None and info.confidence <= 0.5
    assert not v.sol_address_plausible("1111")
    assert not v.sol_address_plausible("0" * 44)  # '0' is not base58
    assert not v.sol_address_plausible(v.b58encode(bytes(range(1, 34))))  # 33 bytes


# ---------------------------------------------------------------- MD5-looking strings never BTC


@pytest.mark.parametrize(
    "value",
    ["44d88612fea8a8f36de82e1278abb02f", "a" * 32, "d41d8cd98f1b4e98ecf8427eabcdefab", "ABCDEF1234567891ABCDEF1234567891"],
)
def test_md5_looking_string_is_never_btc(value):
    assert v.crypto_address_info(value) is None
    assert not v.btc_address_valid(value)
    assert all(d.type is not EntityType.BTC for d in detect(value))


def test_crypto_address_info_rejects_noise():
    for value in ("", "   ", "hello world", "x" * 200, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa extra"):
        assert v.crypto_address_info(value) is None


# ---------------------------------------------------------------- Tor onion v3


def test_onion_v3_vectors():
    assert v.onion_valid(ONION_TORPROJECT)
    assert v.onion_valid(ONION_DDG)
    assert v.onion_valid("www." + ONION_DDG)  # subdomains allowed
    assert not v.onion_valid(ONION_DDG.replace("zczad", "zczaa"))  # 1-char mutation
    assert not v.onion_valid("3g2upl4pq6kufc4m.onion")  # v2 is obsolete
    assert not v.onion_valid("a" * 56 + ".onion")
    assert v.onion_pubkey(ONION_TORPROJECT).hex() == "d1b38b83a83b3ed918c5bb69dd444ad56bc8d5835a914de73447474e5f02591b"
    assert v.onion_pubkey(ONION_DDG).hex() == "1d04a1d04a338c6e6ae970bfabee49049d6702250984ca950c01673f4ec034ad"
    assert v.onion_pubkey("3g2upl4pq6kufc4m.onion") is None


def test_validators_are_offline(monkeypatch):
    import socket

    def no_network(*args, **kwargs):  # pragma: no cover - would fail the test
        raise AssertionError("validators must not touch the network")

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    for value in (BTC_GENESIS, XMR_GENERAL_FUND, XRP_GENESIS, TRON_USDT, "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"):
        assert v.crypto_address_info(value) is not None
    assert v.onion_valid(ONION_DDG)
