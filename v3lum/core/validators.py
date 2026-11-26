"""Offline validators and check-digit algorithms used by detection and modules.

Everything here is pure Python, stdlib only and network-free (disclosure 'none'):

* Brazil: CPF/CNPJ (including the alphanumeric CNPJ in force since July 2026), plates, the PIX BR Code
  (EMV TLV + CRC16-CCITT);
* Luhn (cards, IMEI);
* crypto addresses (P217): Base58Check version tables for BTC/LTC/DOGE/DASH/TRON, Bech32 vs Bech32m
  enforced by witness version (BIP-173/350), EIP-55 with a pure-Python Keccak-256 (``hashlib.sha3_256``
  is NIST SHA-3, *not* Keccak), Monero block-base58 + Keccak checksum, XRP (ripple alphabet), Solana
  (plausibility only: no checksum) and :func:`crypto_address_info` that ties them together;
* Tor v3 onion checksums;
* EU VAT numbers (prefix + national format, checksum where the country publishes one);
* snowflake / TikTok id timestamps, VIN, SteamID64.

Ported from the council research prototype (own implementation of the public specs); the test vectors
live in ``tests/test_crypto_validators.py`` and ``tests/test_validators.py``.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import re
from dataclasses import dataclass

# --------------------------------------------------------------------------------------
# Brazil: CPF / CNPJ
# --------------------------------------------------------------------------------------

CPF_REGIONS: dict[str, str] = {
    "0": "RS",
    "1": "DF, GO, MS, MT, TO",
    "2": "AC, AM, AP, PA, RO, RR",
    "3": "CE, MA, PI",
    "4": "AL, PB, PE, RN",
    "5": "BA, SE",
    "6": "MG",
    "7": "ES, RJ",
    "8": "SP",
    "9": "PR, SC",
}


def cpf_check_digits(first9: str) -> str:
    """Return the two CPF check digits for the 9 base digits."""
    digits = [int(c) for c in first9]
    for size in (9, 10):
        total = sum(d * w for d, w in zip(digits[:size], range(size + 1, 1, -1)))
        rem = total % 11
        digits.append(0 if rem < 2 else 11 - rem)
    return f"{digits[9]}{digits[10]}"


def cpf_valid(value: str) -> bool:
    d = re.sub(r"\D", "", value or "")
    if len(d) != 11 or d == d[0] * 11:
        return False
    return cpf_check_digits(d[:9]) == d[9:]


def cpf_region(value: str) -> str:
    """States where the CPF was issued (9th digit = fiscal region)."""
    d = re.sub(r"\D", "", value or "")
    return CPF_REGIONS.get(d[8], "") if len(d) == 11 else ""


_CNPJ_W1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
_CNPJ_W2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]


def _cnpj_char_value(c: str) -> int:
    # Alphanumeric CNPJ (IN RFB 2.229/2024): value = ASCII code - 48 ('0'->0 ... 'A'->17 ... 'Z'->42).
    return ord(c) - 48


def cnpj_check_digits(first12: str) -> str:
    """Return the two check digits for a 12-character (numeric or alphanumeric) CNPJ base."""
    base = first12.upper()
    vals = [_cnpj_char_value(c) for c in base]
    r1 = sum(v * w for v, w in zip(vals, _CNPJ_W1)) % 11
    dv1 = 0 if r1 < 2 else 11 - r1
    vals.append(dv1)
    r2 = sum(v * w for v, w in zip(vals, _CNPJ_W2)) % 11
    dv2 = 0 if r2 < 2 else 11 - r2
    return f"{dv1}{dv2}"


def cnpj_valid(value: str) -> bool:
    """Validate numeric or alphanumeric CNPJ (12 alnum chars + 2 numeric check digits)."""
    c = re.sub(r"[^0-9A-Za-z]", "", value or "").upper()
    if not re.match(r"^[0-9A-Z]{12}[0-9]{2}$", c):
        return False
    if c == c[0] * 14:
        return False
    return cnpj_check_digits(c[:12]) == c[12:]


def cnpj_is_alphanumeric(value: str) -> bool:
    c = re.sub(r"[^0-9A-Za-z]", "", value or "")
    return bool(re.search(r"[A-Za-z]", c))


def cnpj_headquarters(value: str) -> str:
    """CNPJ of the head office (branch 0001) for the same root, with recomputed check digits."""
    c = re.sub(r"[^0-9A-Za-z]", "", value or "").upper()
    base = c[:8] + "0001"
    return base + cnpj_check_digits(base)


# --------------------------------------------------------------------------------------
# Luhn (cards, IMEI)
# --------------------------------------------------------------------------------------


def luhn_valid(number: str) -> bool:
    d = re.sub(r"\D", "", number or "")
    if not d:
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def pan_valid(number: str) -> bool:
    """A plausible payment-card PAN: 13-19 digits (spaces/hyphens allowed) with a valid Luhn digit.

    Used only to *recognise and truncate* card numbers (BIN6 + last 4, P323 cond 5); a full PAN is never
    stored, logged or sent anywhere.
    """
    raw = number or ""
    if re.search(r"[^\d \-]", raw):
        return False
    d = re.sub(r"\D", "", raw)
    return 13 <= len(d) <= 19 and d != d[0] * len(d) and luhn_valid(d)


# --------------------------------------------------------------------------------------
# Keccak-256 (original Keccak padding 0x01 - NOT NIST SHA3-256, whose padding is 0x06)
# --------------------------------------------------------------------------------------

_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
# Rotation offsets r[x][y] of the rho step.
_KECCAK_ROT = ((0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61), (28, 55, 25, 21, 56), (27, 20, 39, 8, 14))
_M64 = (1 << 64) - 1
# rho+pi as flat (source lane, destination lane, rotation) triples; lane index = x + 5*y.
_KECCAK_PI = tuple(
    (x + 5 * y, y + 5 * ((2 * x + 3 * y) % 5), _KECCAK_ROT[x][y]) for x in range(5) for y in range(5)
)


def _keccak_f1600(lanes: list[int]) -> list[int]:
    a = lanes
    for rc in _KECCAK_RC:
        # theta
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M64) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        # rho + pi
        b = [0] * 25
        for src, dst, rot in _KECCAK_PI:
            v = a[src]
            b[dst] = ((v << rot) | (v >> (64 - rot))) & _M64 if rot else v
        # chi
        a = [b[i] ^ ((~b[(i % 5 + 1) % 5 + 5 * (i // 5)]) & b[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        # iota
        a[0] ^= rc
    return a


def keccak256(data: bytes | bytearray | memoryview | str) -> bytes:
    """Keccak-256 digest (Ethereum/Monero flavour) in pure Python; ``str`` input is UTF-8 encoded.

    ``keccak256(b'').hex() == 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'``
    (``hashlib.sha3_256(b'')`` gives ``a7ffc6f8...``: different padding, never use it for EIP-55/Monero).
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    rate = 136
    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % rate:
        msg.append(0)
    msg[-1] |= 0x80
    lanes = [0] * 25
    for off in range(0, len(msg), rate):
        block = msg[off : off + rate]
        for i in range(rate // 8):
            lanes[i] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
        lanes = _keccak_f1600(lanes)
    return b"".join(lanes[i].to_bytes(8, "little") for i in range(4))


# --------------------------------------------------------------------------------------
# Base58 / Base58Check (Bitcoin and Ripple alphabets)
# --------------------------------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
#: Ripple (XRP) base58 alphabet.
XRP_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
#: Bitcoin base58 alphabet.
B58_ALPHABET = _B58


def b58decode(s: str, alphabet: str = _B58) -> bytes:
    """Decode base58 (Bitcoin alphabet by default). Raises ValueError on a character outside it."""
    num = 0
    for ch in s:
        idx = alphabet.find(ch)
        if idx < 0:
            raise ValueError("invalid base58 character")
        num = num * 58 + idx
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip(alphabet[0]))
    return b"\x00" * pad + raw


def b58encode(data: bytes, alphabet: str = _B58) -> str:
    """Encode bytes as base58 (Bitcoin alphabet by default)."""
    num = int.from_bytes(data, "big")
    out = []
    while num:
        num, rem = divmod(num, 58)
        out.append(alphabet[rem])
    pad = len(data) - len(data.lstrip(b"\x00"))
    return alphabet[0] * pad + "".join(reversed(out))


def base58check_decode(s: str, alphabet: str = _B58) -> bytes:
    """Decode Base58Check and verify the double-SHA256 checksum; returns version byte(s) + payload."""
    data = b58decode(s, alphabet)
    if len(data) < 5:
        raise ValueError("too short")
    payload, checksum = data[:-4], data[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        raise ValueError("bad checksum")
    return payload


def base58check_encode(payload: bytes, alphabet: str = _B58) -> str:
    """Encode version byte(s) + payload as Base58Check (used to build test vectors)."""
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + checksum, alphabet)


#: Base58Check version byte -> (chain, kind, network) for 21-byte payloads (P217 cond 1, 3).
#: 0x05 is shared by Bitcoin P2SH and the legacy Litecoin P2SH ('3...'); it is reported as Bitcoin.
BASE58_VERSIONS: dict[int, tuple[str, str, str]] = {
    0x00: ("btc", "p2pkh", "mainnet"),
    0x05: ("btc", "p2sh", "mainnet"),
    0x6F: ("btc", "p2pkh", "testnet"),
    0xC4: ("btc", "p2sh", "testnet"),
    0x30: ("ltc", "p2pkh", "mainnet"),
    0x32: ("ltc", "p2sh", "mainnet"),
    0x1E: ("doge", "p2pkh", "mainnet"),
    0x16: ("doge", "p2sh", "mainnet"),
    0x4C: ("dash", "p2pkh", "mainnet"),
    0x10: ("dash", "p2sh", "mainnet"),
    0x41: ("tron", "account", "mainnet"),
}


# --------------------------------------------------------------------------------------
# Bitcoin: Base58Check + Bech32/Bech32m (BIP-173 / BIP-350)
# --------------------------------------------------------------------------------------

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M_CONST = 0x2BC830A3


def _bech32_polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_decode(addr: str) -> tuple[str, list[int], str] | None:
    """Return (hrp, data, encoding['bech32'|'bech32m']) or None."""
    if any(ord(x) < 33 or ord(x) > 126 for x in addr):
        return None
    if addr.lower() != addr and addr.upper() != addr:
        return None
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        return None
    hrp = addr[:pos]
    if not all(x in _BECH32_CHARSET for x in addr[pos + 1 :]):
        return None
    data = [_BECH32_CHARSET.find(x) for x in addr[pos + 1 :]]
    const = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if const == 1:
        return hrp, data[:-6], "bech32"
    if const == _BECH32M_CONST:
        return hrp, data[:-6], "bech32m"
    return None


def _convertbits(data: list[int], frombits: int, tobits: int, pad: bool = True) -> list[int] | None:
    acc = bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def segwit_decode(hrp: str, addr: str) -> tuple[int, bytes] | None:
    """Decode a segwit address for ``hrp``: (witness version, program) or None.

    Bech32 vs Bech32m is enforced by witness version (v0 -> bech32, v1+ -> bech32m, BIP-350).
    """
    dec = bech32_decode(addr)
    if dec is None or dec[0] != hrp:
        return None
    _, data, enc = dec
    if not data:
        return None
    witver = data[0]
    prog = _convertbits(data[1:], 5, 8, False)
    if prog is None or not 2 <= len(prog) <= 40 or witver > 16:
        return None
    if witver == 0 and len(prog) not in (20, 32):
        return None
    if (witver == 0 and enc != "bech32") or (witver != 0 and enc != "bech32m"):
        return None
    return witver, bytes(prog)


def btc_address_info(addr: str) -> dict[str, str] | None:
    """Classify a Bitcoin address. Returns {'network','type'} or None if invalid."""
    a = addr.strip()
    low = a.lower()
    for hrp, net in (("bc", "mainnet"), ("tb", "testnet"), ("bcrt", "regtest")):
        if low.startswith(hrp + "1"):
            res = segwit_decode(hrp, a)
            if res is None:
                return None
            ver, prog = res
            if ver == 0:
                kind = "P2WPKH (native segwit)" if len(prog) == 20 else "P2WSH (native segwit script)"
            elif ver == 1 and len(prog) == 32:
                kind = "P2TR (taproot)"
            else:
                kind = f"segwit v{ver}"
            return {"network": net, "type": kind}
    if not re.match(r"^[13mn2][1-9A-HJ-NP-Za-km-z]{25,34}$", a):
        return None
    try:
        payload = base58check_decode(a)
    except ValueError:
        return None
    if len(payload) != 21:
        return None
    version = payload[0]
    kinds = {
        0x00: ("mainnet", "P2PKH (legacy)"),
        0x05: ("mainnet", "P2SH (script)"),
        0x6F: ("testnet", "P2PKH (legacy)"),
        0xC4: ("testnet", "P2SH (script)"),
    }
    if version not in kinds:
        return None
    net, kind = kinds[version]
    return {"network": net, "type": kind}


def btc_address_valid(addr: str) -> bool:
    return btc_address_info(addr) is not None


# --------------------------------------------------------------------------------------
# Ethereum / EVM: EIP-55 mixed-case checksum
# --------------------------------------------------------------------------------------

_RE_EVM = re.compile(r"^(?:0[xX])?([0-9a-fA-F]{40})$")


def _evm_hex(addr: str) -> str:
    m = _RE_EVM.match((addr or "").strip())
    if not m:
        raise ValueError("not an EVM address (0x + 40 hex)")
    return m.group(1)


def eip55_checksum(addr: str) -> str:
    """The EIP-55 checksummed form ``0x...`` of an EVM address (any case in). Raises ValueError."""
    h = _evm_hex(addr).lower()
    digest = keccak256(h.encode("ascii")).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(digest[i], 16) >= 8 else c for i, c in enumerate(h))


def eth_checksum_state(addr: str) -> str:
    """'valid' (mixed case matching EIP-55), 'invalid' (mixed case not matching) or 'none'.

    All-lower and all-upper addresses carry no checksum ('none'). Raises ValueError when ``addr`` is not
    ``0x`` + 40 hex.
    """
    h = _evm_hex(addr)
    if h == h.lower() or h == h.upper():
        return "none"
    return "valid" if eip55_checksum(h)[2:] == h else "invalid"


# --------------------------------------------------------------------------------------
# Monero: block base58 + Keccak-256 checksum
# --------------------------------------------------------------------------------------

_XMR_BLOCK_BYTES = {0: 0, 2: 1, 3: 2, 5: 3, 6: 4, 7: 5, 9: 6, 10: 7, 11: 8}  # encoded chars -> bytes
#: Monero mainnet network bytes: 18 standard ('4...', 95 chars), 42 subaddress ('8...'), 19 integrated (106).
XMR_NETWORK_BYTES: dict[int, str] = {18: "standard", 42: "subaddress", 19: "integrated"}


def xmr_b58decode(s: str) -> bytes | None:
    """Decode Monero block base58 (11-char blocks -> 8 bytes); None when malformed."""
    out = bytearray()
    for i in range(0, len(s), 11):
        chunk = s[i : i + 11]
        size = _XMR_BLOCK_BYTES.get(len(chunk))
        if size is None:
            return None
        n = 0
        for ch in chunk:
            j = _B58.find(ch)
            if j < 0:
                return None
            n = n * 58 + j
        if n >= 1 << (8 * size):
            return None
        out += n.to_bytes(size, "big")
    return bytes(out)


def xmr_address_info(addr: str) -> dict[str, str] | None:
    """{'network': 'mainnet', 'type': standard|subaddress|integrated} for a valid Monero address, else None."""
    a = (addr or "").strip()
    if len(a) not in (95, 106):
        return None
    raw = xmr_b58decode(a)
    if raw is None or len(raw) not in (69, 77):
        return None
    kind = XMR_NETWORK_BYTES.get(raw[0])
    if kind is None or (len(raw) == 77) != (kind == "integrated"):
        return None
    if keccak256(raw[:-4])[:4] != raw[-4:]:
        return None
    return {"network": "mainnet", "type": kind}


def xmr_address_valid(addr: str) -> bool:
    """Monero mainnet address with a valid Keccak-256 checksum (network bytes 18/42/19)."""
    return xmr_address_info(addr) is not None


# --------------------------------------------------------------------------------------
# XRP (ripple alphabet + double-SHA256 checksum) and Solana (plausibility only)
# --------------------------------------------------------------------------------------


def xrp_address_valid(addr: str) -> bool:
    """Classic XRP Ledger account address ('r...', ripple alphabet, version 0x00, 20-byte account id)."""
    a = (addr or "").strip()
    if not re.match(r"^r[1-9A-HJ-NP-Za-km-z]{24,34}$", a):
        return False
    try:
        payload = base58check_decode(a, XRP_ALPHABET)
    except ValueError:
        return False
    return len(payload) == 21 and payload[0] == 0x00


def sol_address_plausible(addr: str) -> bool:
    """Base58 string of 32-44 chars decoding to exactly 32 bytes (an ed25519 key).

    Solana addresses carry **no checksum**: this is plausibility only, so any typing based on it must
    stay at confidence <= 0.5 (P217 cond 2).
    """
    a = (addr or "").strip()
    if not 32 <= len(a) <= 44:
        return False
    try:
        raw = b58decode(a)
    except ValueError:
        return False
    return len(raw) == 32


# --------------------------------------------------------------------------------------
# crypto_address_info: one entry point for detection and pivot routing (P217 cond 3, 5)
# --------------------------------------------------------------------------------------

#: chain -> entity type value used by core/entities.py.
CHAIN_ENTITY_TYPES: dict[str, str] = {
    "btc": "btc_address",
    "eth": "eth_address",
    "xmr": "xmr_address",
    "ltc": "other_crypto_address",
    "doge": "other_crypto_address",
    "dash": "other_crypto_address",
    "tron": "other_crypto_address",
    "xrp": "other_crypto_address",
    "sol": "other_crypto_address",
}


@dataclass(frozen=True)
class CryptoInfo:
    """What :func:`crypto_address_info` recognised.

    chain: 'btc'|'ltc'|'doge'|'dash'|'tron'|'eth'|'xmr'|'xrp'|'sol'; kind: p2pkh, p2sh, p2wpkh, p2wsh, p2tr,
    segwit_v<n>, account, standard, subaddress, integrated; network: mainnet|testnet|regtest|unknown;
    checksum_ok: True (verified), False (only for an EIP-55 mixed-case mismatch) or None (the format has
    no checksum: all-lower/upper EVM, Solana); confidence 0-1 (<= 0.5 without a checksum).
    """

    chain: str
    kind: str
    network: str
    checksum_ok: bool | None
    confidence: float
    normalized: str = ""

    @property
    def entity_type(self) -> str:
        """The entity type value for this chain (btc_address, eth_address, xmr_address, other_crypto_address)."""
        return CHAIN_ENTITY_TYPES.get(self.chain, "other_crypto_address")


def _segwit_kind(ver: int, prog: bytes) -> str:
    if ver == 0:
        return "p2wpkh" if len(prog) == 20 else "p2wsh"
    if ver == 1 and len(prog) == 32:
        return "p2tr"
    return f"segwit_v{ver}"


_SEGWIT_HRPS: tuple[tuple[str, str, str], ...] = (
    ("bc", "btc", "mainnet"),
    ("tb", "btc", "testnet"),
    ("bcrt", "btc", "regtest"),
    ("ltc", "ltc", "mainnet"),
    ("tltc", "ltc", "testnet"),
)


def crypto_address_info(value: str) -> CryptoInfo | None:
    """Recognise a crypto address offline, or None.

    Checksum-bearing formats are typed only with a passing checksum, so an MD5-looking string is never a
    Bitcoin address (P217 cond 2). EVM addresses: mixed case is EIP-55-checked (a mismatch is reported
    with ``checksum_ok=False`` and confidence 0.2); all-lower/upper carry no checksum (confidence 0.85).
    Solana is plausibility only (confidence 0.4).
    """
    a = (value or "").strip()
    if not a or len(a) > 120 or any(c.isspace() for c in a):
        return None
    low = a.lower()
    # Bech32 / Bech32m segwit (bc1 / tb1 / bcrt1 / ltc1 / tltc1).
    for hrp, chain, net in _SEGWIT_HRPS:
        if low.startswith(hrp + "1"):
            res = segwit_decode(hrp, a)
            if res is not None:
                ver, prog = res
                return CryptoInfo(chain, _segwit_kind(ver, prog), net, True, 0.99, low)
    # EVM 0x + 40 hex.
    if _RE_EVM.match(a) and a[:2] in ("0x", "0X"):
        state = eth_checksum_state(a)
        if state == "valid":
            return CryptoInfo("eth", "account", "mainnet", True, 0.99, eip55_checksum(a))
        if state == "invalid":
            return CryptoInfo("eth", "account", "mainnet", False, 0.2, eip55_checksum(a))
        return CryptoInfo("eth", "account", "mainnet", None, 0.85, eip55_checksum(a))
    # Monero (95/106 chars, block base58 + Keccak).
    info = xmr_address_info(a)
    if info is not None:
        return CryptoInfo("xmr", info["type"], "mainnet", True, 0.98, a)
    # XRP classic address (ripple alphabet).
    if a.startswith("r") and xrp_address_valid(a):
        return CryptoInfo("xrp", "account", "mainnet", True, 0.97, a)
    # Base58Check version tables (BTC/LTC/DOGE/DASH/TRON).
    if re.match(r"^[1-9A-HJ-NP-Za-km-z]{25,36}$", a):
        try:
            payload = base58check_decode(a)
        except ValueError:
            payload = b""
        if len(payload) == 21 and payload[0] in BASE58_VERSIONS:
            chain, kind, net = BASE58_VERSIONS[payload[0]]
            conf = 0.95 if payload[0] == 0x05 else 0.98  # 0x05 is shared with legacy Litecoin P2SH
            return CryptoInfo(chain, kind, net, True, conf, a)
    # Solana: 32-byte base58, no checksum.
    if sol_address_plausible(a):
        return CryptoInfo("sol", "account", "unknown", None, 0.4, a)
    return None


# --------------------------------------------------------------------------------------
# Tor v3 onion addresses
# --------------------------------------------------------------------------------------


def onion_valid(host: str) -> bool:
    """Validate a v3 onion address checksum (v2 addresses are obsolete and rejected)."""
    h = host.lower().strip()
    if h.endswith(".onion"):
        h = h[: -len(".onion")]
    h = h.split(".")[-1]  # allow subdomain.xxx.onion
    if not re.match(r"^[a-z2-7]{56}$", h):
        return False
    try:
        raw = base64.b32decode(h.upper())
    except (ValueError, TypeError):
        return False
    pubkey, checksum, version = raw[:32], raw[32:34], raw[34:35]
    if version != b"\x03":
        return False
    digest = hashlib.sha3_256(b".onion checksum" + pubkey + version).digest()
    return digest[:2] == checksum


def onion_pubkey(host: str) -> bytes | None:
    """The ed25519 public key embedded in a valid v3 onion address (None when invalid)."""
    if not onion_valid(host):
        return None
    label = host.lower().strip().removesuffix(".onion").split(".")[-1]
    return base64.b32decode(label.upper())[:32]


# --------------------------------------------------------------------------------------
# Brazilian vehicle plates
# --------------------------------------------------------------------------------------

_MERCOSUL_LETTER = "ABCDEFGHIJ"


def plate_br_valid(plate: str) -> bool:
    p = re.sub(r"[^A-Za-z0-9]", "", plate or "").upper()
    return bool(re.match(r"^[A-Z]{3}[0-9][A-Z0-9][0-9]{2}$", p))


def plate_br_convert(plate: str) -> dict[str, str]:
    """Return both the old (ABC1234) and Mercosul (ABC1C34) forms of a plate."""
    p = re.sub(r"[^A-Za-z0-9]", "", plate or "").upper()
    if not plate_br_valid(p):
        raise ValueError("invalid plate")
    fifth = p[4]
    if fifth.isdigit():
        old = p
        mercosul = p[:4] + _MERCOSUL_LETTER[int(fifth)] + p[5:]
        fmt = "old"
    else:
        mercosul = p
        idx = _MERCOSUL_LETTER.find(fifth)
        old = p[:4] + str(idx) + p[5:] if idx >= 0 else ""
        fmt = "mercosul"
    return {"format": fmt, "old": old, "mercosul": mercosul}


# --------------------------------------------------------------------------------------
# PIX BR Code (EMV merchant-presented QR payload, BCB manual): TLV + CRC16-CCITT
# --------------------------------------------------------------------------------------

#: Longest BR Code accepted (characters).
PIX_BRCODE_MAX = 512


def crc16_ccitt(data: bytes) -> int:
    """CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF), the BR Code checksum. ``b'123456789'`` -> 0x29B1."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def emv_tlv_parse(payload: str) -> list[tuple[str, str]]:
    """Split an EMV QR payload into (id, value) pairs (2-digit id, 2-digit length). Raises ValueError."""
    out: list[tuple[str, str]] = []
    i = 0
    while i < len(payload):
        tag, length = payload[i : i + 2], payload[i + 2 : i + 4]
        if len(tag) != 2 or not tag.isdigit() or len(length) != 2 or not length.isdigit():
            raise ValueError("malformed EMV TLV field")
        n = int(length)
        value = payload[i + 4 : i + 4 + n]
        if len(value) != n:
            raise ValueError("truncated EMV TLV field")
        out.append((tag, value))
        i += 4 + n
    return out


def pix_brcode_valid(value: str) -> bool:
    """A PIX BR Code: EMV TLV payload starting '000201', ending with field 63 (len 04) holding a valid
    CRC16-CCITT over everything before the CRC digits; <= 512 characters, single line.

    Spaces are allowed inside fields (merchant names); line breaks, tabs and control characters are not.
    """
    s = (value or "").strip()
    if not s.startswith("000201") or len(s) > PIX_BRCODE_MAX or any(ord(c) < 32 or ord(c) == 127 for c in s):
        return False
    try:
        fields = emv_tlv_parse(s)
    except ValueError:
        return False
    if len(fields) < 3 or fields[0] != ("00", "01") or fields[-1][0] != "63" or len(fields[-1][1]) != 4:
        return False
    crc = fields[-1][1].upper()
    if not re.match(r"^[0-9A-F]{4}$", crc):
        return False
    return format(crc16_ccitt(s[:-4].encode("utf-8")), "04X") == crc


def pix_brcode_fields(value: str) -> dict[str, str] | None:
    """Main fields of a valid BR Code: gui, key (static QR) or url (dynamic QR), merchant_name,
    merchant_city, amount, txid, currency, country (missing fields are ''). None when invalid."""
    if not pix_brcode_valid(value):
        return None
    fields = dict(emv_tlv_parse(value.strip()))
    out = {"gui": "", "key": "", "url": "", "merchant_name": fields.get("59", ""), "merchant_city": fields.get("60", ""),
           "amount": fields.get("54", ""), "currency": fields.get("53", ""), "country": fields.get("58", ""), "txid": ""}
    for tag in (f"{n:02d}" for n in range(26, 52)):
        if tag not in fields:
            continue
        try:
            sub = dict(emv_tlv_parse(fields[tag]))
        except ValueError:
            continue
        if sub.get("00", "").lower() == "br.gov.bcb.pix":
            out["gui"] = sub.get("00", "")
            out["key"] = sub.get("01", "")
            out["url"] = sub.get("25", "")
            break
    if "62" in fields:
        try:
            out["txid"] = dict(emv_tlv_parse(fields["62"])).get("05", "")
        except ValueError:
            pass
    return out


# --------------------------------------------------------------------------------------
# EU VAT numbers (VIES prefixes; checksum where the country publishes one)
# --------------------------------------------------------------------------------------


def _mod11_10(digits: str) -> int:
    """ISO 7064 MOD 11,10 check digit (DE, HR)."""
    p = 10
    for ch in digits:
        s = (int(ch) + p) % 10 or 10
        p = (2 * s) % 11
    return (11 - p) % 10


def _wsum(weights: tuple[int, ...] | range, digits: str) -> int:
    return sum(w * int(c) for w, c in zip(weights, digits))


def _vat_at(n: str) -> bool | None:
    s = 0
    for i, ch in enumerate(n[1:8]):
        v = int(ch) * (2 if i % 2 else 1)
        s += v // 10 + v % 10
    return (6 - s) % 10 == int(n[8])


def _vat_be(n: str) -> bool | None:
    return 97 - int(n[:8]) % 97 == int(n[8:])


def _vat_bg(n: str) -> bool | None:
    if len(n) == 10:
        return None  # personal/foreigner numbers (EGN/PNF): format only
    s = _wsum(range(1, 9), n[:8]) % 11
    if s == 10:
        s = _wsum(range(3, 11), n[:8]) % 11
    return (0 if s == 10 else s) == int(n[8])


_CY_ODD = {0: 1, 1: 0, 2: 5, 3: 7, 4: 9, 5: 13, 6: 15, 7: 17, 8: 19, 9: 21}


def _vat_cy(n: str) -> bool | None:
    if n[:2] == "12":
        return False
    s = sum(_CY_ODD[int(c)] if i % 2 == 0 else int(c) for i, c in enumerate(n[:8]))
    return chr(ord("A") + s % 26) == n[8]


def _vat_cz(n: str) -> bool | None:
    if len(n) == 8:
        if n[0] == "9":
            return False
        c = (11 - _wsum((8, 7, 6, 5, 4, 3, 2), n[:7])) % 11
        return str((c or 1) % 10) == n[7]
    if len(n) == 10:  # birth number of an individual: divisible by 11 (historic exception: mod 10 -> 0)
        return int(n) % 11 == 0 or (int(n[:9]) % 11 == 10 and n[9] == "0")
    return None  # 9 digits: pre-1954 birth numbers / special individuals, no checksum


def _vat_de(n: str) -> bool | None:
    return _mod11_10(n[:8]) == int(n[8])


def _vat_dk(n: str) -> bool | None:
    return n[0] != "0" and _wsum((2, 7, 6, 5, 4, 3, 2, 1), n) % 11 == 0


def _vat_ee(n: str) -> bool | None:
    return n.startswith("10") and _wsum((3, 7, 1, 3, 7, 1, 3, 7, 1), n) % 10 == 0


def _vat_el(n: str) -> bool | None:
    return sum(int(c) * 2 ** (8 - i) for i, c in enumerate(n[:8])) % 11 % 10 == int(n[8])


_ES_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def _vat_es(n: str) -> bool | None:
    first = n[0]
    if first.isdigit():  # DNI
        return n[:8].isdigit() and _ES_LETTERS[int(n[:8]) % 23] == n[8]
    if first in "XYZ":  # NIE
        return n[1:8].isdigit() and _ES_LETTERS[int(str("XYZ".index(first)) + n[1:8]) % 23] == n[8]
    if first in "KLM":  # special NIF
        return n[1:8].isdigit() and _ES_LETTERS[int(n[1:8]) % 23] == n[8]
    if first not in "ABCDEFGHJNPQRSUVW" or not n[1:8].isdigit():
        return False
    digits = n[1:8]
    s = sum(int(c) for c in digits[1::2])
    for c in digits[0::2]:
        v = int(c) * 2
        s += v // 10 + v % 10
    c = (10 - s % 10) % 10
    if first in "ABEH":
        return n[8] == str(c)
    if first in "NPQRSW":
        return n[8] == "JABCDEFGHI"[c]
    return n[8] in (str(c), "JABCDEFGHI"[c])


def _vat_fi(n: str) -> bool | None:
    return _wsum((7, 9, 10, 5, 8, 4, 2, 1), n) % 11 == 0


def _vat_fr(n: str) -> bool | None:
    key, siren = n[:2], n[2:]
    if not siren.startswith("000") and not luhn_valid(siren):
        return False
    if key.isdigit():
        return int(key) == (12 + 3 * (int(siren) % 97)) % 97
    return None  # alphanumeric keys: format only


def _vat_hr(n: str) -> bool | None:
    return _mod11_10(n[:10]) == int(n[10])


def _vat_hu(n: str) -> bool | None:
    return _wsum((9, 7, 3, 1, 9, 7, 3, 1), n) % 10 == 0


def _vat_ie(n: str) -> bool | None:
    if not n[1].isdigit():  # old format: digit, letter/+/*, 5 digits, check letter
        n = "0" + n[2:7] + n[0] + n[7:]
    s = _wsum((8, 7, 6, 5, 4, 3, 2), n[:7])
    if len(n) == 9:
        s += 9 * "WABCDEFGHI".index(n[8])
    return "WABCDEFGHIJKLMNOPQRSTUV"[s % 23] == n[7]


def _vat_it(n: str) -> bool | None:
    return int(n[:7]) != 0 and luhn_valid(n)


def _vat_lt(n: str) -> bool | None:
    if len(n) == 9:
        if n[7] != "1":
            return False
        w1: tuple[int, ...] = (1, 2, 3, 4, 5, 6, 7, 8)
        w2: tuple[int, ...] = (3, 4, 5, 6, 7, 8, 9, 1)
        body, chk = n[:8], n[8]
    else:
        if n[10] != "1":
            return False
        w1, w2 = (1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2), (3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4)
        body, chk = n[:11], n[11]
    s = _wsum(w1, body) % 11
    if s == 10:
        s = _wsum(w2, body) % 11
    return (0 if s == 10 else s) == int(chk)


def _vat_lu(n: str) -> bool | None:
    return int(n[:6]) % 89 == int(n[6:])


def _vat_lv(n: str) -> bool | None:
    if n[0] > "3":  # legal entity
        return _wsum((9, 1, 4, 8, 3, 10, 2, 5, 7, 6, 1), n) % 11 == 3
    return None  # personal codes (some without checksum since 2017): format only


def _vat_mt(n: str) -> bool | None:
    return n[0] != "0" and 37 - _wsum((3, 4, 6, 7, 8, 9), n[:6]) % 37 == int(n[6:])


def _vat_nl(n: str) -> bool | None:
    if int(n[10:]) == 0:
        return False
    if _wsum((9, 8, 7, 6, 5, 4, 3, 2, -1), n[:9]) % 11 == 0:
        return True
    converted = "".join(str(ord(c) - 55) if c.isalpha() else c for c in "NL" + n)  # mod 97 (2020+ numbers)
    return int(converted) % 97 == 1


def _vat_pl(n: str) -> bool | None:
    return _wsum((6, 5, 7, 2, 3, 4, 5, 6, 7), n[:9]) % 11 == int(n[9])


def _vat_pt(n: str) -> bool | None:
    c = 11 - _wsum((9, 8, 7, 6, 5, 4, 3, 2), n[:8]) % 11
    return (0 if c >= 10 else c) == int(n[8])


def _vat_ro(n: str) -> bool | None:
    p = n.zfill(10)
    return _wsum((7, 5, 3, 2, 1, 7, 5, 3, 2), p[:9]) * 10 % 11 % 10 == int(p[9])


def _vat_se(n: str) -> bool | None:
    return luhn_valid(n[:10]) and 1 <= int(n[10:]) <= 94


def _vat_si(n: str) -> bool | None:
    if n[0] == "0":
        return False
    c = 11 - _wsum((8, 7, 6, 5, 4, 3, 2), n[:7]) % 11
    return str(0 if c == 10 else c) == n[7]


def _vat_sk(n: str) -> bool | None:
    return n[0] != "0" and n[2] in "234789" and int(n) % 11 == 0


def _vat_xi(n: str) -> bool | None:
    if n[:2] in ("GD", "HA"):
        return None  # government departments / health authorities: format only
    s = _wsum((8, 7, 6, 5, 4, 3, 2), n[:7]) + int(n[7:9])
    return s % 97 == 0 or (s + 55) % 97 == 0


#: country prefix (VIES) -> (national format regex, checksum function returning True/False, or None when
#: that form has no published checksum). Greece uses 'EL' ('GR' input is accepted and converted).
_EU_VAT_RULES: dict[str, tuple[re.Pattern[str], object]] = {
    "AT": (re.compile(r"^U\d{8}$"), _vat_at),
    "BE": (re.compile(r"^[01]\d{9}$"), _vat_be),
    "BG": (re.compile(r"^\d{9,10}$"), _vat_bg),
    "CY": (re.compile(r"^[013459]\d{7}[A-Z]$"), _vat_cy),
    "CZ": (re.compile(r"^\d{8,10}$"), _vat_cz),
    "DE": (re.compile(r"^\d{9}$"), _vat_de),
    "DK": (re.compile(r"^\d{8}$"), _vat_dk),
    "EE": (re.compile(r"^\d{9}$"), _vat_ee),
    "EL": (re.compile(r"^\d{9}$"), _vat_el),
    "ES": (re.compile(r"^[0-9A-Z]\d{7}[0-9A-Z]$"), _vat_es),
    "FI": (re.compile(r"^\d{8}$"), _vat_fi),
    "FR": (re.compile(r"^[0-9A-HJ-NP-Z]{2}\d{9}$"), _vat_fr),
    "HR": (re.compile(r"^\d{11}$"), _vat_hr),
    "HU": (re.compile(r"^\d{8}$"), _vat_hu),
    "IE": (re.compile(r"^(?:\d{7}[A-W][A-IW]?|\d[A-Z+*]\d{5}[A-W])$"), _vat_ie),
    "IT": (re.compile(r"^\d{11}$"), _vat_it),
    "LT": (re.compile(r"^(?:\d{9}|\d{12})$"), _vat_lt),
    "LU": (re.compile(r"^\d{8}$"), _vat_lu),
    "LV": (re.compile(r"^\d{11}$"), _vat_lv),
    "MT": (re.compile(r"^\d{8}$"), _vat_mt),
    "NL": (re.compile(r"^\d{9}B\d{2}$"), _vat_nl),
    "PL": (re.compile(r"^\d{10}$"), _vat_pl),
    "PT": (re.compile(r"^\d{9}$"), _vat_pt),
    "RO": (re.compile(r"^[1-9]\d{1,9}$"), _vat_ro),
    "SE": (re.compile(r"^\d{12}$"), _vat_se),
    "SI": (re.compile(r"^\d{8}$"), _vat_si),
    "SK": (re.compile(r"^\d{10}$"), _vat_sk),
    "XI": (re.compile(r"^(?:\d{9}|\d{12}|GD\d{3}|HA\d{3})$"), _vat_xi),
}

#: VIES country prefixes accepted for EU VAT numbers (27 member states as 'EL' for Greece, plus 'XI').
EU_VAT_COUNTRIES: frozenset[str] = frozenset(_EU_VAT_RULES)

_RE_VAT_CONTEXT = re.compile(r"^(?:vat\s*(?:no|nr|number|id|reg)\b\.?|vatin|vat|ust-?id(?:nr)?\.?|tva|iva|btw)\s*[:#]?\s*", re.I)


def eu_vat_normalize(value: str) -> str:
    """Canonical EU VAT number ('DE136695976'): country prefix + national format, checksum where the
    country publishes one (BG/CZ/LV personal numbers, FR alphanumeric keys and XI GD/HA are format-only).

    Accepts spaces, dots and hyphens, a leading 'VAT'/'VAT no:'-style label and 'GR' for Greece.
    Raises ValueError. Never inferred from bare digits: callers type it explicitly (P333 cond 4).
    """
    v = _RE_VAT_CONTEXT.sub("", (value or "").strip())
    v = re.sub(r"[\s.\-/]", "", v).upper()
    if len(v) < 4 or len(v) > 16:
        raise ValueError("invalid EU VAT number")
    country, number = v[:2], v[2:]
    if country == "GR":
        country = "EL"
    rule = _EU_VAT_RULES.get(country)
    if rule is None:
        raise ValueError(f"not an EU VAT country prefix: {country!r}")
    if country == "BE" and re.match(r"^\d{9}$", number):
        number = "0" + number  # old 9-digit Belgian numbers
    if country == "EL" and re.match(r"^\d{8}$", number):
        number = "0" + number
    pattern, check = rule
    if not pattern.match(number):
        raise ValueError(f"invalid {country} VAT number format")
    if callable(check) and check(number) is False:
        raise ValueError(f"invalid {country} VAT number checksum")
    return country + number


def eu_vat_valid(value: str) -> bool:
    try:
        eu_vat_normalize(value)
    except ValueError:
        return False
    return True


# --------------------------------------------------------------------------------------
# Snowflake / TikTok ids, VIN, SteamID64
# --------------------------------------------------------------------------------------

#: Snowflake epochs in milliseconds since the Unix epoch.
SNOWFLAKE_EPOCHS: dict[str, int] = {"discord": 1420070400000, "twitter": 1288834974657, "x": 1288834974657}


def _id_int(value: str | int) -> int:
    if isinstance(value, bool):
        raise ValueError("not an id")
    if isinstance(value, int):
        n = value
    else:
        text = str(value or "").strip()
        if not re.match(r"^\d{1,20}$", text):
            raise ValueError("not a numeric 64-bit id")
        n = int(text)
    if not 0 < n < 2**64:
        raise ValueError("id out of the 64-bit range")
    return n


def snowflake_timestamp(value: str | int, epoch: str = "discord") -> _dt.datetime:
    """Creation time (aware UTC) of a Discord or X/Twitter snowflake id: (id >> 22) ms after the epoch."""
    key = (epoch or "").lower()
    if key not in SNOWFLAKE_EPOCHS:
        raise ValueError(f"unknown snowflake epoch {epoch!r} (use 'discord' or 'twitter')")
    ms = (_id_int(value) >> 22) + SNOWFLAKE_EPOCHS[key]
    return _dt.datetime.fromtimestamp(ms / 1000, tz=_dt.timezone.utc)


def tiktok_id_timestamp(value: str | int) -> _dt.datetime:
    """Creation time (aware UTC) of a TikTok video id: its upper 32 bits are Unix seconds."""
    return _dt.datetime.fromtimestamp(_id_int(value) >> 32, tz=_dt.timezone.utc)


def vin_valid(value: str) -> bool:
    """17 characters of [A-HJ-NPR-Z0-9] (I, O and Q are never used in a VIN)."""
    return bool(re.match(r"^[A-HJ-NPR-Z0-9]{17}$", (value or "").strip().upper()))


#: SteamID64 range of individual accounts (universe 1, type 1, instance 1).
STEAMID64_BASE = 76561197960265728


def steamid64_valid(value: str) -> bool:
    """A 17-digit SteamID64 of an individual account."""
    v = (value or "").strip()
    return bool(re.match(r"^\d{17}$", v)) and STEAMID64_BASE <= int(v) < STEAMID64_BASE + 2**32


# --------------------------------------------------------------------------------------
# Misc
# --------------------------------------------------------------------------------------


def is_uuid(value: str) -> bool:
    return bool(re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", (value or "").lower()))


def jwt_decode_unverified(token: str) -> tuple[dict, dict]:
    """Decode header and payload of a JWT WITHOUT verifying the signature."""
    import json

    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT")

    def _b64(seg: str) -> dict:
        pad = "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg + pad).decode("utf-8"))

    return _b64(parts[0]), _b64(parts[1])
