"""Offline validators and check-digit algorithms used by detection and modules.

Everything here is pure Python and network-free: CPF/CNPJ (including the
alphanumeric CNPJ in force since July 2026), Luhn, Base58Check, Bech32/Bech32m,
Tor v3 onion checksums, Brazilian plates.
"""

from __future__ import annotations

import base64
import hashlib
import re

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


# --------------------------------------------------------------------------------------
# Bitcoin: Base58Check + Bech32/Bech32m (BIP-173 / BIP-350)
# --------------------------------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    num = 0
    for ch in s:
        idx = _B58.find(ch)
        if idx < 0:
            raise ValueError("invalid base58 character")
        num = num * 58 + idx
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def base58check_decode(s: str) -> bytes:
    data = b58decode(s)
    if len(data) < 5:
        raise ValueError("too short")
    payload, checksum = data[:-4], data[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        raise ValueError("bad checksum")
    return payload


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
