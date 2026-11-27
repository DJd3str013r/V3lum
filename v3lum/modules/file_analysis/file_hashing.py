"""Local file hashing and hash-type identification (P267) - offline, disclosure 'none'.

Final conditions of P267 implemented here:

* FC1 regular files only: ``os.stat`` must be S_ISREG before anything is opened (FIFOs, devices,
  sockets and directories are refused, so ``/dev/zero`` or a FIFO cannot hang a run), the file is
  opened non-blocking and re-checked with ``fstat`` (a path swapped after the check is refused too),
  then streamed in 1 MiB chunks with ``ctx.cancelled()`` and the run deadline checked before every
  chunk; MD5, SHA-1, SHA-256 and SHA-512 always. A cancelled or overdue run emits no digest.
* FC2 ssdeep through ppdeep (pure Python, Apache-2.0, the optional extra ``v3lum/data/extras/
  ppdeep.json``) only for files <= 50 MB; without ppdeep the digests are still computed and the
  result says why ssdeep is missing. TLSH is not computed in this build (py-tlsh ships no wheels);
  TLSH values returned by providers stay attributes of their modules.
* FC3 :func:`identify_hash` is the shared identification helper (core detection can call it):
  ambiguity is flagged (a bare 64-hex value is a SHA-256 or a SHA-256 certificate fingerprint).
  Modules never prompt: a run tries every reading (the non-TTY rule) by pivoting the other reading
  of an analyst-typed value; :func:`hash_readings` lets an interactive caller (TTY) offer the
  choice instead. Identification only: no cracking and no plaintext lookup (hashes.com,
  CrackStation, ntlm.pw are excluded); password-hash formats are only labelled.
* FC4 the digests of a file are ``has_hash`` pivots that feed the hash chain (CIRCL hashlookup
  first when the engine orders the chain).
"""

from __future__ import annotations

import hashlib
import importlib
import os
import re
import stat as _stat
from collections.abc import Callable, Iterable, Iterator
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import Cancelled, DeadlineExceeded
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, package_available, register

CHUNK_SIZE = 1 << 20  # FC1: 1 MiB chunks
SSDEEP_MAX_BYTES = 50 * 1024 * 1024  # FC2: ppdeep only for files <= 50 MB
#: rough pure-Python ppdeep speed used to skip ssdeep when the run deadline is too close
PPDEEP_BYTES_PER_SECOND = 1 << 20
ALGORITHMS = ("md5", "sha1", "sha256", "sha512")
IDENTIFICATION_NOTE = "identification only: no cracking and no plaintext lookup"
#: confidence of the other reading of an ambiguous seed: the engine's min_expand_confidence (0.5), so it is tried
ALTERNATE_READING_CONFIDENCE = 0.5

_SSDEEP = re.compile(r'^(\d{1,10}):([A-Za-z0-9/+]{1,64}):([A-Za-z0-9/+]{0,64})(?:,"?([^"]*)"?)?$')
_SEPARATED_HEX = re.compile(r"^[0-9A-Fa-f]{2}(?:[:\s\-][0-9A-Fa-f]{2})+$")
_EXPLICIT_TYPES = {
    "md5": "md5", "sha1": "sha1", "sha-1": "sha1", "sha256": "sha256", "sha-256": "sha256", "sha512": "sha512",
    "sha-512": "sha512", "ssdeep": "ssdeep", "tlsh": "tlsh", "imphash": "imphash", "authentihash": "authentihash",
    "telfhash": "telfhash", "gimphash": "gimphash", "icon_dhash": "icon_dhash", "dhash_icon": "icon_dhash",
    "cert": "cert_fingerprint", "cert_fingerprint": "cert_fingerprint", "thumbprint": "cert_fingerprint",
}
_EXPLICIT_HEX_LEN = {"md5": 32, "imphash": 32, "sha1": 40, "sha256": 64, "authentihash": 64, "gimphash": 64, "sha512": 128, "icon_dhash": 16}
#: password-hash formats: labelled, never routed anywhere (FC3)
_PASSWORD_FORMATS = (
    ("bcrypt", re.compile(r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$")),
    ("md5crypt", re.compile(r"^\$1\$[^$]{1,8}\$[./A-Za-z0-9]{22}$")),
    ("apr1", re.compile(r"^\$apr1\$[^$]{1,8}\$[./A-Za-z0-9]{22}$")),
    ("sha256crypt", re.compile(r"^\$5\$(?:rounds=\d+\$)?[^$]{1,16}\$[./A-Za-z0-9]{43}$")),
    ("sha512crypt", re.compile(r"^\$6\$(?:rounds=\d+\$)?[^$]{1,16}\$[./A-Za-z0-9]{86}$")),
    ("yescrypt", re.compile(r"^\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]*\$[./A-Za-z0-9]{43}$")),
    ("scrypt", re.compile(r"^\$7\$")),
    ("argon2", re.compile(r"^\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/.]+\$[A-Za-z0-9+/.]+$")),
    ("phpass", re.compile(r"^\$[PH]\$[./A-Za-z0-9]{31}$")),
    ("cisco_type8_9", re.compile(r"^\$(?:8|9)\$")),
    ("kerberos", re.compile(r"^\$krb5(?:tgs|asrep|pa)\$", re.I)),
    ("django_pbkdf2", re.compile(r"^pbkdf2_sha(?:1|256)\$\d+\$")),
    ("pbkdf2", re.compile(r"^\$pbkdf2(?:-sha(?:1|256|512))?\$")),
    ("ldap_hash", re.compile(r"^\{(?:SSHA|SHA|SMD5|MD5|SSHA256|SSHA512|CRYPT|PBKDF2[-A-Z0-9]*)\}", re.I)),
    ("mysql41", re.compile(r"^\*[0-9A-Fa-f]{40}$")),
    ("mssql", re.compile(r"^0x0[12]00[0-9A-Fa-f]{48,}$", re.I)),
    ("pwdump", re.compile(r"^[^:\s]+:\d+:[0-9A-Fa-f]{32}:[0-9A-Fa-f]{32}:::")),
    ("netntlm", re.compile(r"^[^:\s]+::[^:\s]*:[0-9A-Fa-f]{16}:[0-9A-Fa-f]{32,48}:[0-9A-Fa-f]*$")),
    ("crypt_other", re.compile(r"^\$[0-9a-z]{1,10}\$")),
)
_TYPE_LABEL = {
    "md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512", "ssdeep": "ssdeep", "tlsh": "TLSH",
    "cert_fingerprint": "certificate fingerprint", "telfhash": "telfhash", "imphash": "imphash",
}
_ENTITY_OF = {"md5": T.MD5, "sha1": T.SHA1, "sha256": T.SHA256, "sha512": T.SHA512, "ssdeep": T.SSDEEP, "cert_fingerprint": T.CERT_FP}


# --------------------------------------------------------------------------------------
# FC1: regular files only, streamed
# --------------------------------------------------------------------------------------


def file_mode_refusal(st_mode: Any) -> str | None:
    """None for a regular file; else why the file is refused (checked BEFORE opening it)."""
    if not isinstance(st_mode, int) or isinstance(st_mode, bool):
        return "no stat information"
    if _stat.S_ISREG(st_mode):
        return None
    for test, kind in (
        (_stat.S_ISFIFO, "FIFO"), (_stat.S_ISCHR, "character device"), (_stat.S_ISBLK, "block device"),
        (_stat.S_ISSOCK, "socket"), (_stat.S_ISDIR, "directory"), (_stat.S_ISLNK, "symbolic link"),
    ):
        if test(st_mode):
            return f"refused {kind}: only regular files are hashed"
    return "refused special file: only regular files are hashed"


def iter_chunks(read: Callable[[int], bytes], chunk_size: int = CHUNK_SIZE) -> Iterator[bytes]:
    """Chunks of at most ``chunk_size`` bytes from ``read(n)`` until it returns nothing."""
    size = max(1, int(chunk_size))
    while True:
        block = read(size)
        if not block:
            return
        yield block


def _new_hash(name: str) -> Any:
    try:
        return hashlib.new(name, usedforsecurity=False)  # FIPS builds refuse MD5/SHA-1 otherwise
    except TypeError:  # pragma: no cover - Python builds without the keyword
        return hashlib.new(name)


def hash_chunks(chunks: Iterable[bytes], *, check: Callable[[], None] | None = None, keep_upto: int = 0) -> dict[str, Any]:
    """Stream MD5/SHA-1/SHA-256/SHA-512 over ``chunks``. ``check()`` runs before every chunk and
    raises to stop (cancel/deadline: no digest is ever returned for a partial read). When
    ``keep_upto`` > 0 the content is kept in memory while it stays within that size (for ssdeep)."""
    hashes = {name: _new_hash(name) for name in ALGORITHMS}
    size = count = 0
    kept: bytearray | None = bytearray() if keep_upto > 0 else None
    for chunk in chunks:
        if check is not None:
            check()
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise TypeError("hash_chunks expects bytes chunks")
        for h in hashes.values():
            h.update(chunk)
        size += len(chunk)
        count += 1
        if kept is not None:
            if size <= keep_upto:
                kept += chunk
            else:
                kept = None
    return {"size": size, "chunks": count, "hashes": {n: h.hexdigest() for n, h in hashes.items()}, "content": bytes(kept) if kept is not None else None}


# --------------------------------------------------------------------------------------
# FC2: ssdeep (optional ppdeep) and provider TLSH
# --------------------------------------------------------------------------------------


def parse_ssdeep(value: Any) -> dict[str, Any] | None:
    """'blocksize:h1:h2[,"name"]' -> {'value', 'blocksize'}; the block size must be 3*2^n."""
    if not isinstance(value, str):
        return None
    m = _SSDEEP.match(value.strip())
    if not m:
        return None
    bs = int(m.group(1))
    q, r = divmod(bs, 3)
    if bs < 3 or r or (q & (q - 1)):
        return None
    return {"value": f"{bs}:{m.group(2)}:{m.group(3)}", "blocksize": bs}


def normalize_tlsh(value: Any) -> str | None:
    """'T1' + 70 hex (upper-cased); TNULL, the legacy 70-hex form and junk -> None."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    return "T1" + v[2:].upper() if re.fullmatch(r"[Tt]1[0-9A-Fa-f]{70}", v) else None


def ssdeep_eligible(size: Any) -> bool:
    return isinstance(size, int) and not isinstance(size, bool) and 0 <= size <= SSDEEP_MAX_BYTES


def load_ppdeep() -> Any:
    """The optional ppdeep module, or None when the extra is not installed."""
    if not package_available("ppdeep"):
        return None
    try:
        return importlib.import_module("ppdeep")
    except Exception:  # a broken optional package never breaks hashing
        return None


# --------------------------------------------------------------------------------------
# FC3: shared hash-type identification helper
# --------------------------------------------------------------------------------------


def _ident(raw: str, value: str | None, primary: str | None, readings: Iterable[str], alternatives: Iterable[str] = (), *,
           label_only: bool = False, password: str | None = None, explicit: bool = False, note: str | None = None) -> dict[str, Any]:
    readings = list(readings)
    return {
        "input": raw,
        "value": value,
        "primary": primary,
        "readings": readings,
        "alternatives": list(alternatives),
        "ambiguous": len(readings) > 1,
        "label_only": label_only,
        "password_hash": password,
        "explicit": explicit,
        "note": note or (IDENTIFICATION_NOTE if password else None),
    }


def identify_hash(value: Any, *, sha1_cert_reading: bool = False) -> dict[str, Any]:
    """Identify the hash type(s) of ``value`` (identification only).

    ``readings`` are the entity types a non-interactive run tries (both when ambiguous: a bare
    64-hex value is read as ``sha256`` AND ``cert_fingerprint``; colon-separated hex as a certificate
    fingerprint first); ``alternatives`` are label-only look-alikes (NTLM, imphash, RIPEMD-160...).
    imphash, authentihash, gimphash and icon_dhash are typed only with an explicit ``TYPE:`` prefix.
    Password-hash formats are labelled (``password_hash``) and never get a reading.
    ``sha1_cert_reading=True`` adds the SHA-1 thumbprint reading of a bare 40-hex value (off by
    default: only the SHA-256 case is named by P267 FC3).
    """
    raw = value if isinstance(value, str) else ""
    v = raw.strip()
    if not v:
        return _ident(raw, None, None, [])
    for name, rx in _PASSWORD_FORMATS:
        if rx.match(v):
            return _ident(raw, None, name, [], label_only=True, password=name)
    m = re.match(r"^([A-Za-z0-9_\-]{2,20}):(.+)$", v)
    if m and m.group(1).lower() in _EXPLICIT_TYPES:
        kind = _EXPLICIT_TYPES[m.group(1).lower()]
        body = m.group(2).strip()
        norm: str | None = None
        if kind in _EXPLICIT_HEX_LEN:
            norm = body.lower() if re.fullmatch(f"[0-9a-fA-F]{{{_EXPLICIT_HEX_LEN[kind]}}}", body) else None
        elif kind == "ssdeep":
            parsed = parse_ssdeep(body)
            norm = parsed["value"] if parsed else None
        elif kind == "tlsh":
            norm = normalize_tlsh(body)
        elif kind == "telfhash":
            norm = body.lower() if re.fullmatch(r"[tT]1[0-9a-fA-F]{70}", body) else None
        elif kind == "cert_fingerprint":
            hx = re.sub(r"[:\s\-]", "", body).lower()
            norm = hx if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", hx) else None
        if norm is None:
            return _ident(raw, None, None, [], explicit=True, note=f"invalid {kind} value")
        return _ident(raw, norm, kind, [kind], explicit=True)
    parsed = parse_ssdeep(v)
    if parsed:
        return _ident(raw, parsed["value"], "ssdeep", ["ssdeep"])
    if re.fullmatch(r"T1[0-9A-Fa-f]{70}", v):
        return _ident(raw, normalize_tlsh(v), "tlsh", ["tlsh"], ["telfhash"])
    if re.fullmatch(r"t1[0-9a-f]{70}", v):
        return _ident(raw, v, "telfhash", ["telfhash", "tlsh"])
    if _SEPARATED_HEX.match(v):
        hx = re.sub(r"[:\s\-]", "", v).lower()
        if len(hx) == 64:
            return _ident(raw, hx, "cert_fingerprint", ["cert_fingerprint", "sha256"])
        if len(hx) == 40:
            return _ident(raw, hx, "cert_fingerprint", ["cert_fingerprint", "sha1"])
        if len(hx) == 32:
            return _ident(raw, hx, "md5_fingerprint", [], ["ssh_md5_fingerprint"], label_only=True)
        return _ident(raw, None, None, [])
    if not re.fullmatch(r"[0-9A-Fa-f]+", v):
        return _ident(raw, None, None, [])
    hx = v.lower()
    n = len(hx)
    if n == 32:
        return _ident(raw, hx, "md5", ["md5"], ["ntlm", "imphash"])
    if n == 40:
        if sha1_cert_reading:
            return _ident(raw, hx, "sha1", ["sha1", "cert_fingerprint"], ["ripemd160"])
        return _ident(raw, hx, "sha1", ["sha1"], ["cert_fingerprint", "ripemd160"])
    if n == 64:
        return _ident(raw, hx, "sha256", ["sha256", "cert_fingerprint"], ["authentihash", "gimphash", "sha3_256"])
    if n == 128:
        return _ident(raw, hx, "sha512", ["sha512"], ["sha3_512", "blake2b_512", "whirlpool"])
    if n == 96:
        return _ident(raw, hx, "sha384", [], ["sha3_384"], label_only=True)
    if n == 56:
        return _ident(raw, hx, "sha224", [], ["sha3_224"], label_only=True)
    if n == 70:
        return _ident(raw, hx, "tlsh_legacy", [], label_only=True)
    if n == 16:
        return _ident(raw, hx, None, [], ["icon_dhash", "mysql323", "crc64"], label_only=True)
    if n == 8:
        return _ident(raw, hx, "crc32", [], label_only=True)
    return _ident(raw, None, None, [])


def hash_readings(ident: dict[str, Any] | None, *, interactive: bool = False, choice: str | None = None) -> dict[str, Any]:
    """Which readings to emit. Non-interactive (non-TTY): every reading (try both). Interactive
    (TTY): the analyst's ``choice``, or ``ask=True`` with the options when none was given."""
    readings = list((ident or {}).get("readings") or [])
    if not readings:
        return {"emit": [], "ask": False, "options": []}
    if len(readings) == 1:
        return {"emit": readings, "ask": False, "options": readings}
    if interactive:
        if choice in readings:
            return {"emit": [choice], "ask": False, "options": readings}
        return {"emit": [], "ask": True, "options": readings}
    return {"emit": readings, "ask": False, "options": readings, "note": "ambiguous: every reading is tried (non-interactive run)"}


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class FileHashing(Module):
    name = "file_hashing"
    title = "Local file hashing and hash identification"
    description = (
        "Streams a local regular file through MD5/SHA-1/SHA-256/SHA-512 (ssdeep with the optional ppdeep extra) "
        "and identifies hash types with ambiguity flagged; identification only, never cracking or plaintext lookup."
    )
    category = "file_analysis"
    accepts = {T.FILE, T.MD5, T.SHA1, T.SHA256, T.SHA512, T.SSDEEP}
    produces = {T.MD5, T.SHA1, T.SHA256, T.SHA512, T.SSDEEP, T.CERT_FP}
    run_on = "seeds"  # analyst-typed files and values; computed digests feed the chain as pivots
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # the file and the values never leave the machine
    hosts = ()
    access_model = "offline"
    expected_latency = 0.5
    timeout = 300.0  # large files stream at disk speed; ppdeep is pure Python
    max_pivots = 10
    tags = {"offline"}
    notice = "Hash-type identification only: no cracking and no plaintext lookup of hashes."

    def applies(self, entity: Entity, ctx: Any) -> bool:
        # digests of pivots are typed by their source: identification is for analyst-typed values
        return entity.type is T.FILE or ctx.is_seed

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type is T.FILE:
            return self._hash_file(entity, ctx, res)
        return self._identify(entity, ctx, res)

    # ---- files ---------------------------------------------------------------------------
    def _hash_file(self, entity: Entity, ctx: Any, res: ModuleResult) -> ModuleResult:
        path = entity.value
        try:
            st = os.stat(path)
        except FileNotFoundError:
            return res.mark("skipped", "the file no longer exists", reason_code="not_applicable")
        except OSError as exc:
            return res.mark("error", f"cannot stat the file: {exc.strerror or type(exc).__name__}")
        refusal = file_mode_refusal(st.st_mode)
        if refusal:
            return res.mark("skipped", refusal, reason_code="not_applicable")
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_BINARY", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            return res.mark("error", f"cannot open the file: {exc.strerror or type(exc).__name__}")
        with os.fdopen(fd, "rb", buffering=0) as fh:
            fst = os.fstat(fh.fileno())
            refusal = file_mode_refusal(fst.st_mode)
            if refusal:  # the path changed between the check and the open: never read it
                return res.mark("skipped", refusal, reason_code="not_applicable")
            ppdeep = load_ppdeep() if ssdeep_eligible(fst.st_size) else None
            keep = SSDEEP_MAX_BYTES if ppdeep is not None else 0
            out = hash_chunks(iter_chunks(fh.read), check=lambda: _check_live(ctx), keep_upto=keep)
        hashes = out["hashes"]
        ssdeep, ssdeep_note = self._ssdeep(ctx, ppdeep, out, fst.st_size)
        changed = out["size"] != fst.st_size
        for name in ALGORITHMS:
            res.attr(name, hashes[name])
        res.attr("file_size", out["size"])
        if ssdeep:
            res.attr("similarity_hashes", {"ssdeep": ssdeep})
        description = f"{out['size']} bytes in {out['chunks']} chunk(s) of at most 1 MiB; SHA-256 {hashes['sha256']}; ssdeep: {ssdeep or ssdeep_note}."
        if changed:
            description += " The file changed size while it was read: hash it again once it is stable."
        res.finding(
            "File hashed locally",
            "info",
            description,
            data={"size": out["size"], "chunks": out["chunks"], **hashes, "ssdeep": ssdeep, "ssdeep_note": ssdeep_note, "changed_while_reading": changed, "tlsh": "not computed in this build (py-tlsh ships no wheels)"},
            tags=["info"],
        )
        for name in ("sha256", "sha1", "md5"):
            res.pivot(_ENTITY_OF[name], hashes[name], "has_hash", confidence="confirmed", note="computed locally from the file content")
        res.pivot(T.SHA512, hashes["sha512"], "has_hash", confidence="confirmed", expand=False, note="computed locally (few sources accept SHA-512)")
        if ssdeep:
            res.pivot(T.SSDEEP, ssdeep, "has_hash", confidence="confirmed", expand=False, note="fuzzy hash computed locally: similarity pivots are analyst-selected")
        res.raw = {"path_kind": "regular file", "size": out["size"], "chunks": out["chunks"], "hashes": hashes, "ssdeep": ssdeep}
        return res

    def _ssdeep(self, ctx: Any, ppdeep: Any, out: dict[str, Any], size: int) -> tuple[str | None, str]:
        if not ssdeep_eligible(size):
            return None, f"not computed: the file is larger than {SSDEEP_MAX_BYTES // (1024 * 1024)} MB"
        if ppdeep is None:
            return None, "not computed: the optional extra ppdeep is not installed (pip install 'v3lum[full]')"
        content = out.get("content")
        if content is None:
            return None, "not computed: the file grew beyond the ssdeep limit while it was read"
        remaining = ctx.remaining()
        if remaining is not None and remaining < 1.0 + len(content) / PPDEEP_BYTES_PER_SECOND:
            return None, "not computed: not enough time left before the run deadline"
        try:
            value = ppdeep.hash(content)
        except Exception as exc:  # optional package: a failure never hides the digests
            return None, f"not computed: ppdeep failed ({type(exc).__name__})"
        parsed = parse_ssdeep(value) if isinstance(value, str) else None
        return (parsed["value"], "") if parsed else (None, "not computed: ppdeep returned an invalid value")

    # ---- values (FC3) ----------------------------------------------------------------------
    def _identify(self, entity: Entity, ctx: Any, res: ModuleResult) -> ModuleResult:
        ident = identify_hash(entity.value)
        plan = hash_readings(ident, interactive=False)
        primary = ident["primary"] or entity.type.value
        label = _TYPE_LABEL.get(primary, primary)
        others = [r for r in plan["emit"] if r != entity.type.value]
        res.attr("hash_identification", {
            "primary": primary,
            "readings": ident["readings"],
            "alternatives": ident["alternatives"],
            "ambiguous": ident["ambiguous"],
            "note": IDENTIFICATION_NOTE,
        })
        if ident["ambiguous"]:
            readings = " or ".join(_TYPE_LABEL.get(r, r) for r in ident["readings"])
            description = f"Ambiguous value: {readings}. Every reading is tried (non-interactive run)."
        else:
            description = f"{label}."
        if ident["alternatives"]:
            description += f" Look-alike formats (labels only): {', '.join(ident['alternatives'])}."
        if entity.type is T.SSDEEP:
            parsed = parse_ssdeep(entity.value)
            if parsed:
                description += f" ssdeep block size {parsed['blocksize']}."
        description += f" {IDENTIFICATION_NOTE.capitalize()}."
        res.finding("Hash type identified", "info", description, data={"identification": {k: ident[k] for k in ("primary", "readings", "alternatives", "ambiguous")}}, tags=["info"])
        for reading in others:
            etype = _ENTITY_OF.get(reading)
            if etype is not None:
                # 0.5 = the engine's min_expand_confidence: the other reading is investigated too (FC3,
                # non-interactive 'try both'), while its label stays POSSIBLE
                res.pivot(etype, entity.value, "alternate_reading", confidence=ALTERNATE_READING_CONFIDENCE, note=f"ambiguous input also read as a {_TYPE_LABEL.get(reading, reading)} (every reading is tried)")
        return res


def _check_live(ctx: Any) -> None:
    """Kill switch and run deadline, checked before every chunk: a stopped run emits no digest."""
    if ctx.cancelled():
        raise Cancelled("cancelled while hashing: no digest emitted")
    remaining = ctx.remaining()
    if remaining is not None and remaining <= 0:
        raise DeadlineExceeded("run deadline reached while hashing: no digest emitted")
