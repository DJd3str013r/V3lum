"""OpenPGP keys published on public keyservers (P091): keyserver.ubuntu.com HKP index + keys.openpgp.org VKS.

* **Sources** (cond 1): the Ubuntu keyserver machine-readable HKP index
  (``/pks/lookup?op=index&options=mr&search=...``; ``info:``/``pub:``/``uid:`` lines, uid %-escaped) and
  the keys.openpgp.org VKS API (``/vks/v1/by-email/``, ``/by-fingerprint/``, ``/by-keyid/``; only
  e-mail-verified UIDs are published). pgp.mit.edu (timed out) and keyserver.pgp.com (redundant) are not
  used: :func:`hkp_index_url` and :func:`vks_url` build nothing else.
* **HKP first** (cond 2) for fingerprints, creation dates and UIDs. VKS armored keys are read only by
  the bounded minimal OpenPGP packet reader below (public-key and user-ID packets only, strict length
  checks, partial/indeterminate lengths refused, 1 MB cap); when it cannot read a complete key, VKS
  records existence only.
* **Confidence** (cond 3): a VKS verified address is a PROBABLE identity link; Ubuntu HKP UIDs are an
  'unverified self-published claim' (anyone can upload any UID): confidence 0.3, no pivots, never
  auto-expanded.
* **Minimisation at ingestion** (cond 4): fingerprints, creation dates and the UIDs tied to the
  investigated address, domain or key are kept (comments and raw UID strings dropped); every other UID
  becomes a count. The raw keyserver answers are never cached (``cache_ttl=0``): a search answer holds
  other people's UIDs. Fixtures carry no real UIDs.
* **Domain-wide searches** (cond 5) run only for org-profile domains, or for the case company's domain
  typed as a seed inside a case with a recorded purpose; anything else is SKIPPED ``privacy``.
* **E-mail lookups** (cond 6) run on analyst-typed seeds and org-profile domain addresses; the module
  enters the default set only once personal_data_review is recorded (A3 BR8, policy gate). The
  fingerprint is an attribute and - now that the ``pgp_fingerprint`` type exists - a non-expanded pivot of
  verified (VKS) keys only, for the darkweb vendor-key cross-references of G09.
* **Rule 5** (cond 7): timeouts, 403/429 and 5xx are could-not-verify per keyserver
  (``res.source_status``); an empty answer reads 'no key published on <keyserver>', never 'no such person
  or address'. Tests use the recorded HKP index fixtures plus malformed packet cases (cond 8).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, unquote, urlencode

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, DeadlineExceeded, HttpError, NetworkError, OfflineError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

HKP_HOST = "keyserver.ubuntu.com"
VKS_HOST = "keys.openpgp.org"
SRC_HKP = "ubuntu_keyserver.hkp_index"
SRC_VKS = "openpgp.vks"
MAX_BYTES = 1_048_576  # cond 2: 1 MB cap on every answer and on the armored key
MAX_PACKETS = 10_000
MAX_UID_BYTES = 4096
MAX_KEYS = 25
HKP_RESULT_CAP = 100  # Hockeypuck answers 'info:1:100' at most
HKP_CLAIM = "unverified self-published claim"
VKS_CLAIM = "address verified by keys.openpgp.org"
HKP_CONFIDENCE = 0.3
ALGOS = {1: "RSA", 2: "RSA (encrypt-only)", 3: "RSA (sign-only)", 16: "Elgamal", 17: "DSA", 18: "ECDH", 19: "ECDSA",
         20: "Elgamal (legacy)", 22: "EdDSA (legacy)", 25: "X25519", 26: "X448", 27: "Ed25519", 28: "Ed448"}
CURVE_OIDS = {"2b06010401da470f01": "Ed25519", "2b060104019755010501": "Curve25519", "2a8648ce3d030107": "NIST P-256",
              "2b81040022": "NIST P-384", "2b81040023": "NIST P-521", "2b2403030208010107": "brainpoolP256r1",
              "2b240303020801010b": "brainpoolP384r1", "2b240303020801010d": "brainpoolP512r1", "2b8104000a": "secp256k1"}
CURVE_BITS = {"Ed25519": 255, "Curve25519": 255, "X25519": 255, "X448": 448, "Ed448": 448, "NIST P-256": 256,
              "NIST P-384": 384, "NIST P-521": 521, "secp256k1": 256, "brainpoolP256r1": 256, "brainpoolP384r1": 384,
              "brainpoolP512r1": 512}
_FPR = re.compile(r"^(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$")
_KEYID = re.compile(r"^(?:[0-9A-Fa-f]{16})$")
_SHORT_ID = re.compile(r"^(?:[0-9A-Fa-f]{8})$")
_EMAIL = re.compile(r"^[A-Za-z0-9.!#$%&'*+=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
_UID = re.compile(r"^\s*(?P<name>[^<>()]*?)\s*(?:\((?P<comment>[^()]*)\))?\s*(?:<(?P<email>[^<>\s]+)>)?\s*$")
ARMOR_BEGIN = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
ARMOR_END = "-----END PGP PUBLIC KEY BLOCK-----"
_ARMOR_HEADER = re.compile(r"^[A-Za-z][A-Za-z0-9-]*: ")


class PgpError(ValueError):
    """Bounded-reader refusal (truncated, oversized, partial length...); recorded, never raised to the engine."""


# ------------------------------------------------------------------------------------------ values
def normalise_email(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip()
    if v.lower().startswith("mailto:"):
        v = v[7:]
    return v.lower() if _EMAIL.match(v) and ".." not in v else None


def normalise_domain(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    host = value.strip().rstrip(".").lower()
    if not host or any(c in host for c in "/@ :"):
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return host if "." in host else None


def _within(domain: str | None, base: str | None) -> bool:
    return bool(domain and base and (domain == base or domain.endswith("." + base)))


def key_term(value: Any) -> str | None:
    """HKP/VKS term for a fingerprint or key id typed as hex ('0x' + upper hex); free text -> None (name
    searches are person lookups, never default)."""
    text = str(value or "").strip().replace(" ", "")
    if text.lower().startswith("0x"):
        text = text[2:]
    if _FPR.match(text) or _KEYID.match(text) or _SHORT_ID.match(text):
        return text.upper()
    return None


def _epoch_iso(value: Any) -> str | None:
    try:
        epoch = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if epoch <= 0 or epoch > 253402300799:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------------------------------------ URLs (cond 1)
def hkp_index_url(term: str) -> str:
    """The machine-readable HKP index of keyserver.ubuntu.com - the only HKP request this module builds."""
    if not isinstance(term, str) or not term.strip() or len(term) > 256:
        raise ValueError("pgp: empty or oversized search term")
    return f"https://{HKP_HOST}/pks/lookup?" + urlencode({"op": "index", "options": "mr", "search": term.strip()})


def vks_url(kind: str, value: str) -> str:
    """keys.openpgp.org VKS lookup: kind 'by-email' | 'by-fingerprint' | 'by-keyid' (ValueError otherwise)."""
    if kind == "by-email":
        addr = normalise_email(value)
        if addr is None:
            raise ValueError("pgp: not an e-mail address")
        return f"https://{VKS_HOST}/vks/v1/by-email/{quote(addr, safe='')}"
    term = key_term(value)
    if kind == "by-fingerprint" and term and _FPR.match(term):
        return f"https://{VKS_HOST}/vks/v1/by-fingerprint/{term}"
    if kind == "by-keyid" and term and _KEYID.match(term):
        return f"https://{VKS_HOST}/vks/v1/by-keyid/{term}"
    raise ValueError(f"pgp: VKS lookup {kind!r} not allowed for this value")


# ------------------------------------------------------------------------------------------ HKP index
def split_uid(uid: Any) -> dict[str, Any]:
    """'Name (Comment) <email>' -> {name, comment, email}; a bare address becomes the email."""
    text = uid if isinstance(uid, str) else ""
    text = "".join(ch for ch in text if ch == "\t" or ord(ch) >= 32)[:MAX_UID_BYTES]
    m = _UID.match(text)
    name = comment = email = None
    if m:
        name = (m.group("name") or "").strip() or None
        comment = (m.group("comment") or "").strip() or None
        email = normalise_email(m.group("email")) if m.group("email") else None
    if email is None:
        bare = normalise_email(text.strip())
        if bare:
            email, name = bare, None
    if name and email and normalise_email(name) == email:
        name = None
    return {"name": name[:120] if name else None, "comment": comment, "email": email}


def _flags(text: str) -> dict[str, bool]:
    return {"revoked": "r" in text, "disabled": "d" in text, "expired": "e" in text}


def parse_hkp_index(body: bytes | str, *, max_bytes: int = MAX_BYTES) -> dict[str, Any]:
    """HKP machine-readable index -> {is_index, declared, listed, capped, count_mismatch, truncated,
    malformed_lines, keys: [{fingerprint, keyid, algorithm, bits, created, expires, revoked, expired,
    uids: [{name, comment, email, created, revoked, expired}]}]}. CRLF tolerated; never raises."""
    raw = body.encode("utf-8", "replace") if isinstance(body, str) else bytes(body or b"")
    out: dict[str, Any] = {"is_index": False, "declared": None, "listed": 0, "capped": False, "count_mismatch": False,
                           "truncated": len(raw) > max_bytes, "malformed_lines": 0, "keys": []}
    current: dict[str, Any] | None = None
    for line in raw[:max_bytes].decode("utf-8", "replace").splitlines():
        line = line.strip("\r\n\t ")
        if not line:
            continue
        if line.startswith("info:"):
            parts = line.split(":")
            out["is_index"] = True
            try:
                out["declared"] = int(parts[2]) if len(parts) > 2 else None
            except ValueError:
                out["declared"] = None
        elif line.startswith("pub:"):
            parts = line.split(":")
            ident = parts[1].strip() if len(parts) > 1 else ""
            ident = ident[2:] if ident.lower().startswith("0x") else ident
            if not (_FPR.match(ident) or _KEYID.match(ident) or _SHORT_ID.match(ident)):
                out["malformed_lines"] += 1
                current = None
                continue
            out["is_index"] = True
            try:
                algo = int(parts[2]) if len(parts) > 2 and parts[2] else None
            except ValueError:
                algo = None
            try:
                bits = int(parts[3]) if len(parts) > 3 and parts[3] else None
            except ValueError:
                bits = None
            flags = _flags(parts[6] if len(parts) > 6 else "")
            is_fpr = bool(_FPR.match(ident))
            current = {
                "fingerprint": ident.upper() if is_fpr else None,
                "keyid": (ident[-16:] if len(ident) == 40 else ident[:16] if len(ident) == 64 else ident).upper(),
                "algorithm": ALGOS.get(algo) if algo is not None else None,
                "bits": bits if bits and bits > 0 else None,
                "created": _epoch_iso(parts[4]) if len(parts) > 4 else None,
                "expires": _epoch_iso(parts[5]) if len(parts) > 5 else None,
                "revoked": flags["revoked"], "expired": flags["expired"], "uids": [],
            }
            out["keys"].append(current)
        elif line.startswith("uid:"):
            if current is None:
                out["malformed_lines"] += 1
                continue
            rest = line[4:].rsplit(":", 3)
            rest += [""] * (4 - len(rest))
            uid = split_uid(unquote(rest[0], errors="replace"))
            flags = _flags(rest[3])
            uid.update(created=_epoch_iso(rest[1]), revoked=flags["revoked"], expired=flags["expired"])
            current["uids"].append(uid)
        elif out["is_index"]:
            out["malformed_lines"] += 1
    out["listed"] = len(out["keys"])
    if out["declared"] is not None:
        out["count_mismatch"] = out["declared"] != out["listed"]
        out["capped"] = out["declared"] >= HKP_RESULT_CAP
    return out


# ------------------------------------------------------------------------------------------ bounded OpenPGP reader (cond 2)
def crc24(data: bytes) -> int:
    """OpenPGP armor CRC-24 (RFC 4880 s6.1)."""
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def dearmor(body: bytes | str, *, max_bytes: int = MAX_BYTES) -> tuple[bytes, bool | None]:
    """Decode one ASCII-armored public key block -> (binary, crc_ok). Armor headers are ignored, never
    trusted; a CRC mismatch is reported, not fatal (RFC 9580). PgpError on anything else."""
    raw = body.encode("utf-8", "replace") if isinstance(body, str) else bytes(body or b"")
    if len(raw) > max_bytes:
        raise PgpError(f"oversized: {len(raw)} bytes > {max_bytes} byte cap")
    text = raw.decode("ascii", "replace")
    begin = text.find(ARMOR_BEGIN)
    end = text.find(ARMOR_END, begin + 1) if begin >= 0 else -1
    if begin < 0 or end < 0:
        raise PgpError("no_armor: no complete public key block")
    data_lines: list[str] = []
    crc_text = None
    in_headers = True
    for line in text[begin + len(ARMOR_BEGIN):end].splitlines()[1:]:
        s = line.strip()
        if in_headers:
            if _ARMOR_HEADER.match(s):
                continue
            in_headers = False
        if not s:
            continue
        if s.startswith("=") and len(s) == 5:
            crc_text = s[1:]
            continue
        data_lines.append(s)
    b64 = "".join(data_lines)
    if not b64 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", b64):
        raise PgpError("bad_base64: armor body is not base64")
    try:
        data = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise PgpError("bad_base64: armor body does not decode") from None
    if not data:
        raise PgpError("empty: armor body is empty")
    crc_ok = None
    if crc_text:
        try:
            crc_ok = int.from_bytes(base64.b64decode(crc_text, validate=True), "big") == crc24(data)
        except (binascii.Error, ValueError):
            crc_ok = False
    return data, crc_ok


def packets(data: bytes, *, max_packets: int = MAX_PACKETS, max_len: int = MAX_BYTES) -> Iterator[tuple[int, bytes]]:
    """(tag, body) of each OpenPGP packet with strict length checks: old and new headers; partial and
    indeterminate lengths refused; truncation, oversized packets and packet floods raise PgpError."""
    data = bytes(data)
    pos, total, count = 0, len(data), 0
    while pos < total:
        count += 1
        if count > max_packets:
            raise PgpError(f"too_many_packets: more than {max_packets}")
        ctb = data[pos]
        if not ctb & 0x80:
            raise PgpError(f"bad_header: invalid packet tag byte at offset {pos}")
        start = pos
        pos += 1
        if ctb & 0x40:  # new format
            tag = ctb & 0x3F
            if pos >= total:
                raise PgpError(f"truncated: packet header at offset {start}")
            first = data[pos]
            if first < 192:
                length, pos = first, pos + 1
            elif first < 224:
                if pos + 2 > total:
                    raise PgpError(f"truncated: packet header at offset {start}")
                length, pos = ((first - 192) << 8) + data[pos + 1] + 192, pos + 2
            elif first == 255:
                if pos + 5 > total:
                    raise PgpError(f"truncated: packet header at offset {start}")
                length, pos = int.from_bytes(data[pos + 1:pos + 5], "big"), pos + 5
            else:
                raise PgpError(f"partial_length: partial body length for packet tag {tag} at offset {start}")
        else:  # old format
            tag = (ctb >> 2) & 0x0F
            ltype = ctb & 0x03
            if ltype == 3:
                raise PgpError(f"indeterminate_length: old-format packet tag {tag} at offset {start}")
            size = (1, 2, 4)[ltype]
            if pos + size > total:
                raise PgpError(f"truncated: packet header at offset {start}")
            length, pos = int.from_bytes(data[pos:pos + size], "big"), pos + size
        if length > max_len:
            raise PgpError(f"oversized_packet: tag {tag} declares {length} bytes")
        if pos + length > total:
            raise PgpError(f"truncated: packet tag {tag} needs {length} bytes, {total - pos} left")
        yield tag, data[pos:pos + length]
        pos += length


def _key_size(algo: int, material: bytes) -> tuple[int | None, str | None]:
    if algo in (1, 2, 3, 16, 17, 20):
        return (int.from_bytes(material[:2], "big") or None, None) if len(material) >= 2 else (None, None)
    if algo in (18, 19, 22):
        if not material or material[0] in (0, 0xFF) or len(material) < 1 + material[0]:
            return None, None
        oid = material[1:1 + material[0]].hex()
        curve = CURVE_OIDS.get(oid, "oid:" + oid)
        return CURVE_BITS.get(curve), curve
    if algo in (25, 26, 27, 28):
        curve = {25: "X25519", 26: "X448", 27: "Ed25519", 28: "Ed448"}[algo]
        return CURVE_BITS[curve], curve
    return None, None


def public_key_info(body: bytes) -> dict[str, Any]:
    """Facts of one public-key packet: v4 SHA-1 fingerprint, v5/v6 SHA-256; v3 has none. PgpError if cut."""
    body = bytes(body)
    if len(body) < 6:
        raise PgpError(f"truncated: public-key packet of {len(body)} bytes")
    version = body[0]
    fpr = keyid = None
    if version in (4, 5, 6):
        created, algo, material = int.from_bytes(body[1:5], "big"), body[5], body[6:]
        if version in (5, 6):
            if len(body) < 10:
                raise PgpError(f"truncated: v{version} public-key packet")
            material = body[10:]
            prefix = b"\x9b" if version == 6 else b"\x9a"
            fpr = hashlib.sha256(prefix + len(body).to_bytes(4, "big") + body).hexdigest().upper()
            keyid = fpr[:16]
        else:
            if len(body) > 0xFFFF:
                raise PgpError("oversized_packet: v4 key packet above 65535 bytes")
            fpr = hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body, usedforsecurity=False).hexdigest().upper()
            keyid = fpr[-16:]
    elif version in (2, 3):
        if len(body) < 8:
            raise PgpError("truncated: v3 public-key packet")
        created, algo, material = int.from_bytes(body[1:5], "big"), body[7], body[8:]
    else:
        raise PgpError(f"unsupported: public-key packet version {version}")
    bits, curve = _key_size(algo, material)
    return {"version": version, "fingerprint": fpr, "keyid": keyid, "algorithm": ALGOS.get(algo), "bits": bits,
            "curve": curve, "created": _epoch_iso(created)}


def parse_openpgp_key(body: bytes | str, *, max_bytes: int = MAX_BYTES) -> dict[str, Any]:
    """Bounded reader for VKS answers: only public-key (6) and user-ID (13) packets are read, public
    subkeys (14) counted, every other packet skipped by its length. Accepts armored text or binary.
    Returns {keys, packet_count, crc_ok, errors, partial}; never raises."""
    result: dict[str, Any] = {"keys": [], "packet_count": 0, "crc_ok": None, "errors": [], "partial": False}
    raw = body.encode("utf-8", "replace") if isinstance(body, str) else bytes(body or b"")
    try:
        if len(raw) > max_bytes:
            raise PgpError(f"oversized: {len(raw)} bytes > {max_bytes} byte cap")
        if raw[:1] and raw[0] & 0x80:
            data = raw
        else:
            data, result["crc_ok"] = dearmor(raw, max_bytes=max_bytes)
    except PgpError as exc:
        result["errors"].append(str(exc))
        return result
    current: dict[str, Any] | None = None
    try:
        for tag, pbody in packets(data, max_len=max_bytes):
            result["packet_count"] += 1
            if tag == 6:
                current = dict(public_key_info(pbody), uids=[], subkeys=0)
                result["keys"].append(current)
            elif tag == 14 and current is not None:
                current["subkeys"] += 1
            elif tag == 13:
                if current is None:
                    raise PgpError("bad_order: user-ID packet before any public-key packet")
                if len(pbody) > MAX_UID_BYTES:
                    raise PgpError(f"oversized_packet: user-ID of {len(pbody)} bytes")
                current["uids"].append(split_uid(pbody.decode("utf-8", "replace")))
    except PgpError as exc:
        result["errors"].append(str(exc))
        result["partial"] = True
    if not result["keys"] and not result["errors"]:
        result["errors"].append("no_key: no public-key packet")
    return result


# ------------------------------------------------------------------------------------------ minimisation (cond 4)
def minimise(keys: list[dict[str, Any]], *, keyserver: str, email: str | None = None, domain: str | None = None,
             whole_key: bool = False, same_key_uids: bool = False) -> list[dict[str, Any]]:
    """Keep fingerprints, dates and the UIDs tied to the investigated value; every other UID becomes a count.

    ``email``: UIDs with exactly that address (plus, with ``same_key_uids`` - VKS verified keys - the other
    verified addresses of a key that carries it). ``domain``: UIDs at the domain or a subdomain.
    ``whole_key``: the key itself is the investigated value (fingerprint lookups). Comments and raw UID
    strings are never kept."""
    claim = VKS_CLAIM if keyserver == VKS_HOST else HKP_CLAIM
    out = []
    for key in keys[:MAX_KEYS]:
        uids = [u for u in key.get("uids") or [] if isinstance(u, dict)]

        def tied(uid: dict[str, Any]) -> bool:
            addr = uid.get("email")
            if not addr:
                return False
            if email and addr == email:
                return True
            return bool(domain and _within(addr.rsplit("@", 1)[1], domain))

        tied_any = any(tied(u) for u in uids)
        kept, dropped = [], 0
        for uid in uids:
            keep = whole_key and bool(uid.get("email") or uid.get("name"))
            keep = keep or tied(uid) or bool(same_key_uids and tied_any and uid.get("email"))
            if keep:
                kept.append({"email": uid.get("email"), "name": uid.get("name"), "created": uid.get("created")})
            else:
                dropped += 1
        out.append({
            "keyserver": keyserver, "fingerprint": key.get("fingerprint"), "keyid": key.get("keyid"),
            "algorithm": key.get("algorithm"), "bits": key.get("bits"), "created": key.get("created"),
            "expires": key.get("expires"), "revoked": bool(key.get("revoked")), "expired": bool(key.get("expired")),
            "uids": kept, "uids_dropped": dropped,
            "address_match": (tied_any if uids else None) if not whole_key else True,
            "claim": claim, "expiry_checked": keyserver != VKS_HOST,
        })
    return out


# ------------------------------------------------------------------------------------------ the module
def _failure(exc: Exception) -> tuple[Status, str, str]:
    """Could-not-verify outcome of one keyserver request (rule 5, cond 7)."""
    if isinstance(exc, RateLimited):
        return Status.RATE_LIMITED, "rate_limited", "rate limited: could not verify"
    if isinstance(exc, QuotaExceeded):
        return Status.QUOTA, "quota", "quota exhausted: could not verify"
    if isinstance(exc, Blocked):
        code = getattr(exc, "reason_code", "") or "challenge"
        return Status.BLOCKED, code if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge", "blocked: could not verify"
    if isinstance(exc, AuthRequired):
        return Status.BLOCKED, "challenge", "HTTP 401/403: could not verify"
    if isinstance(exc, NetworkError):
        return Status.ERROR, "timeout" if "timeout" in str(exc).lower() or "timed out" in str(exc).lower() else "error", "network error: could not verify"
    return Status.ERROR, "error", f"{str(exc)[:120]}: could not verify"


@register
class PgpKeyservers(Module):
    name = "pgp_keyservers"
    title = "OpenPGP keys on public keyservers"
    description = (
        "OpenPGP keys published for an address, an org domain or a fingerprint on keyserver.ubuntu.com (HKP index, "
        "unverified UIDs) and keys.openpgp.org (verified addresses): fingerprints, creation dates, tied UIDs."
    )
    category = "email"
    accepts = {T.EMAIL, T.DOMAIN, T.KEYWORD, T.PGP_FINGERPRINT}
    produces = {T.EMAIL, T.PGP_FINGERPRINT}
    run_on = "any"  # cond 5/6 gates are value-specific: enforced in run()
    reference = "https://keys.openpgp.org/about/api"
    notice = (
        "Keyserver UIDs are personal data: only the UIDs tied to the investigated address, org domain or key are kept. "
        "Ubuntu keyserver UIDs are unverified claims (anyone can upload any UID); keys.openpgp.org publishes only "
        "addresses the key owner confirmed. Domain-wide searches only for org-profile domains or the case company's "
        "domain with a recorded purpose."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "ubuntu_keyserver"
    sources = (SRC_HKP, SRC_VKS)
    hosts = (HKP_HOST, VKS_HOST)
    access_model = "free_noauth_limited"
    max_requests = 2
    expected_latency = 1.5
    timeout = 30.0
    min_interval = 1.0
    cache_ttl = 0  # cond 4: raw keyserver answers hold other people's UIDs
    max_pivots = 25
    manual_link = "email_keys_calendar:ubuntu_hkp_search"
    default_enabled = True  # effective default only after personal_data_review (policy gate, cond 6)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.KEYWORD:
            return key_term(entity.value) is not None
        if entity.type is T.EMAIL:
            return normalise_email(entity.value) is not None
        if entity.type is T.DOMAIN:
            return normalise_domain(entity.value) is not None
        return key_term(entity.value) is not None

    # ---- gates (cond 5/6) ------------------------------------------------------------------------
    @staticmethod
    def _own(ctx: Any, entity: Entity) -> bool:
        org = getattr(ctx, "org", None)
        try:
            return bool(org is not None and org.owns(entity).own)
        except Exception:  # noqa: BLE001 - a broken profile never widens a gate
            return False

    def _gate(self, entity: Entity, ctx: Any) -> str:
        typed = bool(getattr(ctx, "is_seed", False)) and int(getattr(ctx, "depth", 0) or 0) == 0
        if entity.type is T.EMAIL:
            if typed or self._own(ctx, entity):
                return ""
            return "keyserver e-mail lookups run on analyst-typed seeds and org-profile addresses only"
        if entity.type is T.DOMAIN:
            if self._own(ctx, entity):
                return ""
            if typed and str(getattr(ctx, "purpose", "") or "").strip():
                return ""  # the case company's domain, typed by the analyst, with a recorded purpose
            return ("domain-wide keyserver searches run only for org-profile domains, or the case company's domain typed "
                    "as a seed with a recorded purpose")
        return ""

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        refused = self._gate(entity, ctx)
        if refused:
            return res.mark(Status.SKIPPED, refused, reason_code="privacy")
        plan = self._plan(entity)
        results: dict[str, dict[str, Any]] = {}
        keys: list[dict[str, Any]] = []
        failures: list[tuple[str, Status, str, str]] = []
        for host, source, url, handler in plan:
            try:
                state, found, info = handler(ctx, url, source, entity)
            except (DeadlineExceeded, OfflineError):
                raise
            except (HttpError, NetworkError) as exc:
                status, code, why = _failure(exc)
                failures.append((source, status, code, f"{host}: {why}"))
                results[host] = {"state": "could_not_verify", "reason": why}
                continue
            if state == "error":
                failures.append((source, Status.ERROR, "error", f"{host}: {info.get('reason', 'could not verify')}"))
                results[host] = {"state": "could_not_verify", **info}
                continue
            results[host] = {"state": state, **info}
            keys.extend(found)
        for source, status, code, why in failures:
            res.source_status(source, status, reason_code=code, reason=why)
        res.raw = {"results": results, "keys": keys}
        res.attr("pgp_keyserver_results", results)
        answered = [h for h, r in results.items() if r["state"] != "could_not_verify"]
        if not answered:
            _source, status, code, why = failures[0]
            return res.mark(status, "; ".join(f[3] for f in failures), reason_code=code)
        existence = [h for h in answered if results[h]["state"] == "published" and results[h].get("existence_only")]
        if not keys and existence:
            res.finding(
                "OpenPGP key published (existence only)",
                "info",
                f"{', '.join(existence)} serves a key for the value, but the bounded OpenPGP reader could not read it completely "
                "(truncated, oversized or unusual packets): only its existence is recorded.",
                confidence="possible",
                criterion="the keyserver answered with an armored key the bounded reader refused (P091 cond 2)",
                data={"reader_errors": results[existence[0]].get("reader_errors", [])},
                source=SRC_VKS,
            )
            if failures:
                res.error = "; ".join(f[3] for f in failures)
            return res
        if not keys:
            res.error = "; ".join(
                [f"no key published on {h}" for h in answered] + [f[3] for f in failures]
            )
            return res.mark(Status.EMPTY)
        res.attr("pgp_keyserver_keys", keys)
        self._report(res, entity, keys, results)
        if failures:
            res.error = "; ".join(f[3] for f in failures)
        return res

    # ---- requests --------------------------------------------------------------------------------
    def _plan(self, entity: Entity) -> list[tuple[str, str, str, Any]]:
        if entity.type is T.EMAIL:
            addr = normalise_email(entity.value) or ""
            return [(HKP_HOST, SRC_HKP, hkp_index_url(addr), self._hkp), (VKS_HOST, SRC_VKS, vks_url("by-email", addr), self._vks)]
        if entity.type is T.DOMAIN:
            return [(HKP_HOST, SRC_HKP, hkp_index_url(normalise_domain(entity.value) or ""), self._hkp)]
        term = key_term(entity.value) or ""
        plan = [(HKP_HOST, SRC_HKP, hkp_index_url("0x" + term), self._hkp)]
        if _FPR.match(term):
            plan.append((VKS_HOST, SRC_VKS, vks_url("by-fingerprint", term), self._vks))
        elif _KEYID.match(term):
            plan.append((VKS_HOST, SRC_VKS, vks_url("by-keyid", term), self._vks))
        return plan

    @staticmethod
    def _scope(entity: Entity) -> dict[str, Any]:
        if entity.type is T.EMAIL:
            return {"email": normalise_email(entity.value)}
        if entity.type is T.DOMAIN:
            return {"domain": normalise_domain(entity.value)}
        return {"whole_key": True}

    def _get(self, ctx: Any, url: str, source: str) -> Any:
        resp = ctx.http.get(url, source=source, max_bytes=MAX_BYTES, ttl=0)
        if resp.status == 404 and getattr(resp, "classification", None) is None:
            return None  # declared absence: 'no key published on <keyserver>' (cond 7)
        ctx.http.check(resp)  # 403/429/5xx/challenges raise: could not verify
        return resp

    def _hkp(self, ctx: Any, url: str, source: str, entity: Entity) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
        resp = self._get(ctx, url, source)
        if resp is None:
            return "none", [], {}
        ctype = str(resp.headers.get("content-type", "")).lower()
        if "html" in ctype:
            return "error", [], {"reason": "HTML instead of a machine-readable index: could not verify"}
        idx = parse_hkp_index(resp.content)
        info = {"declared": idx["declared"], "listed": idx["listed"], "capped": idx["capped"] or bool(getattr(resp, "truncated", False)),
                "truncated": idx["truncated"] or bool(getattr(resp, "truncated", False))}
        if not idx["is_index"]:
            return "error", [], {"reason": "not a machine-readable HKP index: could not verify", **info}
        if not idx["keys"]:
            if idx["malformed_lines"]:
                return "error", [], {"reason": "malformed HKP index: could not verify", **info}
            return "none", [], info
        keys = minimise(idx["keys"], keyserver=HKP_HOST, **self._scope(entity))
        if entity.type is T.EMAIL:  # an e-mail search can return keys whose listed UIDs do not carry the address
            keys = [k for k in keys if k["address_match"] is not False] or []
        return ("published" if keys else "none"), keys, info

    def _vks(self, ctx: Any, url: str, source: str, entity: Entity) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
        resp = self._get(ctx, url, source)
        if resp is None:
            return "none", [], {}
        if getattr(resp, "truncated", False):
            return "published", [], {"existence_only": True, "reader_errors": ["oversized: answer above the 1 MB cap"]}
        text = resp.content.decode("ascii", "replace") if isinstance(resp.content, (bytes, bytearray)) else str(resp.content)
        if ARMOR_BEGIN not in text:
            return "error", [], {"reason": "answer holds no armored key: could not verify"}
        parsed = parse_openpgp_key(resp.content)
        usable = [k for k in parsed["keys"] if k.get("fingerprint")]
        if parsed["errors"] or not usable:
            # cond 2: a key the bounded reader cannot read completely records existence only
            return "published", [], {"existence_only": True, "reader_errors": parsed["errors"][:3]}
        scope = self._scope(entity)
        keys = minimise(usable, keyserver=VKS_HOST, same_key_uids=True, **scope)
        return "published", keys, {"existence_only": False, "crc_ok": parsed["crc_ok"]}

    # ---- findings and pivots -----------------------------------------------------------------------
    def _report(self, res: ModuleResult, entity: Entity, keys: list[dict[str, Any]], results: dict[str, Any]) -> None:
        vks = [k for k in keys if k["keyserver"] == VKS_HOST]
        hkp = [k for k in keys if k["keyserver"] == HKP_HOST]
        investigated = normalise_email(entity.value) if entity.type is T.EMAIL else None
        for key in vks:
            if key["fingerprint"]:
                res.pivot(T.PGP_FINGERPRINT, key["fingerprint"], "pgp_key", confidence="probable", expand=False,
                          note=f"OpenPGP key with an address verified by {VKS_HOST}")
            for uid in key["uids"]:
                if uid["email"] and uid["email"] != investigated:
                    res.pivot(T.EMAIL, uid["email"], "same_person", confidence="probable", expand=False,
                              note=f"another verified address on the same OpenPGP key ({VKS_HOST}): PROBABLE identity link")
        if vks:
            first = min((k["created"] for k in vks if k["created"]), default=None)
            res.finding(
                "OpenPGP key with a verified address (keys.openpgp.org)",
                "info",
                f"{len(vks)} key(s) on {VKS_HOST}, where only addresses the key owner confirmed are published"
                + (f"; created {first[:10]}" if first else "") + ". Expiry is not checked for keys read from VKS.",
                confidence="probable",
                criterion="keys.openpgp.org publishes only user IDs whose e-mail address the key owner verified",
                data={"fingerprints": [k["fingerprint"] for k in vks], "verified_addresses": sorted({u["email"] for k in vks for u in k["uids"] if u["email"]})},
                tags=["identity"],
                source=SRC_VKS,
                observed_first=first,
            )
        if hkp:
            info = results.get(HKP_HOST, {})
            first = min((k["created"] for k in hkp if k["created"]), default=None)
            addresses = sorted({u["email"] for k in hkp for u in k["uids"] if u["email"]})
            capped = " Results are capped by the keyserver: the list may be incomplete." if info.get("capped") else ""
            what = (f"{len(addresses)} address(es) at the domain" if entity.type is T.DOMAIN else "the investigated value")
            res.finding(
                "OpenPGP keys listed on keyserver.ubuntu.com (unverified claims)",
                "info",
                f"{len(hkp)} key(s) on {HKP_HOST} list {what}. Anyone can upload a key with any user ID: these are "
                f"unverified self-published claims (confidence 0.3), never identity proof.{capped}",
                confidence=HKP_CONFIDENCE,
                criterion=f"{HKP_CLAIM}: HKP machine-readable index of {HKP_HOST}",
                data={"keys": len(hkp), "revoked": sum(1 for k in hkp if k["revoked"]), "addresses": addresses[:25],
                      "capped": bool(info.get("capped")), "uids_dropped": sum(k["uids_dropped"] for k in hkp)},
                tags=["weak_signal"] + (["privacy"] if entity.type is T.DOMAIN else []),
                source=SRC_HKP,
                observed_first=first,
            )
