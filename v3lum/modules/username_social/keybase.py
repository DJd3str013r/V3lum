"""Keybase user lookup (P104): identity proofs, PGP keys and account dates of a Keybase account.

* One endpoint (cond 1): ``keybase.io/_/api/1.0/user/lookup.json?<kind>=<value>&fields=basics,proofs_summary,
  public_keys`` with kind ``usernames`` (Keybase usernames, ``keybase:`` social accounts and keybase.io profile
  URLs) or the reverse lookups ``github=`` / ``twitter=`` / ``reddit=`` (social-account seeds and profile URLs of
  those platforms) and ``domain=`` (domain seeds). Those three fields only: the sigchain is never downloaded.
* Status (cond 2): status.code 0 with ``them=[null]`` = ABSENT (presence absent, EMPTY); a reverse lookup
  answering ``them=[]`` = EMPTY ('no Keybase user has proven this account or domain'); code 100 (input error,
  e.g. a name longer than 16 characters) = SKIPPED ``not_applicable``, never absent - names outside the Keybase
  syntax are refused locally with the same outcome and no request; any other code = ERROR. 429, 5xx, challenge
  pages and HTML instead of JSON are 'could not verify' (core classification).
* Confidence (cond 3): an OK proof (proof_state/state 1) is PROBABLE, worded 'Keybase-verified proof, signed
  <date>'. The lookup answer carries no per-proof signature date, so the account's last identity change (an
  upper bound for every signature) is used: 'signed on or before <date>'. A proof becomes CONFIRMED only when
  another module of the case corroborates it - the correlation rule ``p3g051_keybase_proof_corroborated``
  (same PGP fingerprint, the linked account linking back to Keybase, or the keybase-site-verification TXT
  record) - never on the Keybase answer alone.
* Revoked or broken proofs (cond 4) are historical claims (POSSIBLE, expand=False) with their date; proofs older
  than 3 years are labelled 'historical'. PGP UIDs are e-mails asserted by the key owner: POSSIBLE,
  expand=False. dns/https proofs give domain/URL pivots (pivots only ever reach passive modules: LIGHT/ACTIVE
  modules run on analyst-typed seeds only, POL-10). BTC addresses would become crypto pivots with expand=False,
  but cond 1's three fields never return ``cryptocurrency_addresses`` (backlog).
* Every result carries 'Keybase is in maintenance mode: historical, self-asserted evidence' and the data age
  (cond 5); account dates are attributes only.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Any
from urllib.parse import urlencode

from v3lum.core.entities import Entity, platform_for_url
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, Module, register
from v3lum.modules.username_social.p3g051_common import (
    age_days,
    day,
    extract_emails,
    host_of,
    iso,
    json_body,
    normalise_host,
    parse_dt,
    safe_url,
    to_int,
    to_str,
)

SOURCE = "keybase.user_lookup"
API = "https://keybase.io/_/api/1.0/user/lookup.json"
FIELDS = "basics,proofs_summary,public_keys"  # cond 1: these three fields only, never the sigchain
BANNER = "Keybase is in maintenance mode: historical, self-asserted evidence"
HISTORICAL_DAYS = 3 * 365
MAX_USERS = 5
MAX_PROOFS = 100
PROOF_STATES = {0: "none", 1: "ok", 2: "temp_failure", 3: "perm_failure", 4: "looking", 5: "superseded", 6: "posted",
                7: "revoked", 8: "deleted", 9: "unknown_type", 10: "sig_hint_missing", 11: "unchecked"}
REVOKED_STATES = frozenset({5, 7, 8})
WEB_TYPES = frozenset({"generic_web_site", "web", "https", "http"})
#: proof_type -> V3LUM social platform (social_account '<platform>:<handle>'); others pivot as a plain username
PLATFORMS = {"github": "github", "twitter": "x", "reddit": "reddit", "facebook": "facebook"}
#: social-account platform -> reverse-lookup parameter (cond 1)
REVERSE = {"github": "github", "x": "twitter", "reddit": "reddit"}
_KB_USER_RE = re.compile(r"^(?=.{2,16}$)[A-Za-z0-9](?:_?[A-Za-z0-9])*_?$")
_CHECKS = {
    "github": re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$"),
    "twitter": re.compile(r"^[A-Za-z0-9_]{1,15}$"),
    "reddit": re.compile(r"^[A-Za-z0-9_-]{3,20}$"),
}
_BTC_RE = re.compile(r"^(?:[13][1-9A-HJ-NP-Za-km-z]{25,34}|bc1[02-9ac-hj-np-z]{11,71})$")
_FPR_RE = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")


# ---------------------------------------------------------------------------------------------- request plan
def keybase_username_ok(value: Any) -> bool:
    """Keybase usernames: 2-16 characters of letters, digits and single underscores (longer names answer code 100)."""
    return isinstance(value, str) and bool(_KB_USER_RE.match(value.strip().lstrip("@")))


def lookup_url(kind: str, value: Any) -> str | None:
    """cond 1 lookup URL (commas of ``fields`` kept literal, as verified live), or None for an invalid value."""
    if not isinstance(value, str):
        return None
    v = value.strip().lstrip("@")
    if kind == "domain":
        v = normalise_host(v) or ""
    elif kind == "usernames":
        v = v.lower() if keybase_username_ok(v) else ""
    elif kind in _CHECKS:
        v = v if _CHECKS[kind].match(v) else ""
    else:
        return None
    if not v:
        return None
    return API + "?" + urlencode({kind: v, "fields": FIELDS}, safe=",")


def request_plan(entity: Entity) -> tuple[str, str] | tuple[None, str]:
    """(kind, value) of the single lookup for this entity, or (None, reason) when not applicable."""
    if entity.type is T.DOMAIN:
        return ("domain", entity.value) if normalise_host(entity.value) else (None, "not a public DNS name")
    platform, handle = None, None
    if entity.type is T.USERNAME:
        platform, handle = "keybase", entity.value
    elif entity.type is T.SOCIAL_ACCOUNT:
        platform, _, handle = entity.value.partition(":")
    elif entity.type is T.URL:
        hit = platform_for_url(entity.value)
        if hit:
            platform, handle = hit
    if platform == "keybase":
        if keybase_username_ok(handle):
            return "usernames", str(handle)
        return None, "not a Keybase username (2-16 letters, digits or single underscores): Keybase answers code 100, not applicable"
    if platform in REVERSE and handle:
        kind = REVERSE[platform]
        if _CHECKS[kind].match(handle):
            return kind, handle
        return None, f"not a valid {platform} handle"
    return None, "not a Keybase username, a GitHub/X/Reddit account or a domain"


# ---------------------------------------------------------------------------------------------- answer status
def lookup_status(data: Any) -> tuple[str, str, str]:
    """cond 2: (state, reason_code, reason) with state ok | empty | absent | skipped | rate_limited | error."""
    if not isinstance(data, dict) or not isinstance(data.get("status"), dict):
        return "error", "error", "no Keybase status object: could not verify"
    sobj = data["status"]
    code = to_int(sobj.get("code"))
    name = to_str(sobj.get("name"), 40) or ""
    desc = to_str(sobj.get("desc"), 120) or ""
    detail = f"{name}{': ' + desc if desc else ''}"
    if code is None:
        return "error", "error", "Keybase status without a code: could not verify"
    if code == 100:
        return "skipped", "not_applicable", f"Keybase input error (code 100 {detail}): not applicable, never an absence"
    if code != 0:
        if "RATE" in name.upper() or "THROTTL" in name.upper():
            return "rate_limited", "rate_limited", f"Keybase status {code} {detail}: could not verify now"
        return "error", "error", f"Keybase status {code} {detail}: could not verify"
    them = data.get("them")
    if not isinstance(them, list):
        return "error", "error", "Keybase answer without them[]: could not verify"
    if not them:
        return "empty", "", "no Keybase user has proven this account or domain"
    if all(u is None for u in them):
        return "absent", "", "no Keybase user with this name"
    return "ok", "", ""


# ---------------------------------------------------------------------------------------------- OpenPGP
_ARMOR_RE = re.compile(r"-----BEGIN PGP PUBLIC KEY BLOCK-----(.{1,200000}?)-----END PGP PUBLIC KEY BLOCK-----", re.S)


def _crc24(data: bytes) -> int:
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def _dearmor(block: str) -> tuple[bytes | None, str | None]:
    body: list[str] = []
    checksum = None
    in_headers = True
    for ln in (x.strip() for x in block.strip().splitlines()):
        if in_headers:
            if not ln:
                in_headers = False
                continue
            if ":" in ln and not re.fullmatch(r"[A-Za-z0-9+/=]+", ln):
                continue
            in_headers = False
        if not ln:
            continue
        if ln.startswith("=") and len(ln) == 5:
            checksum = ln[1:]
            continue
        body.append(ln)
    try:
        data = base64.b64decode("".join(body), validate=True)
    except (binascii.Error, ValueError):
        return None, "bad base64"
    if checksum:
        try:
            want = int.from_bytes(base64.b64decode(checksum), "big")
        except (binascii.Error, ValueError):
            return None, "bad checksum line"
        if _crc24(data) != want:
            return None, "CRC24 mismatch"
    return data, None


def _packets(data: bytes, limit: int = 2000) -> list[tuple[int, bytes]]:
    """OpenPGP packets (tag, body), new and old formats; stops at the first malformed header."""
    out: list[tuple[int, bytes]] = []
    i, n = 0, len(data)
    while i < n and len(out) < limit:
        b = data[i]
        if not b & 0x80:
            break
        if b & 0x40:
            tag = b & 0x3F
            i += 1
            body = b""
            while True:
                if i >= n:
                    return out
                o1 = data[i]
                partial = False
                if o1 < 192:
                    ln, i = o1, i + 1
                elif o1 < 224:
                    if i + 1 >= n:
                        return out
                    ln, i = ((o1 - 192) << 8) + data[i + 1] + 192, i + 2
                elif o1 == 255:
                    if i + 4 >= n:
                        return out
                    ln, i = int.from_bytes(data[i + 1:i + 5], "big"), i + 5
                else:
                    ln, i, partial = 1 << (o1 & 0x1F), i + 1, True
                body += data[i:i + ln]
                i += ln
                if not partial:
                    break
            out.append((tag, body))
        else:
            tag = (b >> 2) & 0x0F
            ltype = b & 3
            i += 1
            if ltype == 3:
                ln = n - i
            else:
                size = (1, 2, 4)[ltype]
                if i + size > n:
                    break
                ln = int.from_bytes(data[i:i + size], "big")
                i += size
            out.append((tag, data[i:i + ln]))
            i += ln
    return out


def _key_info(body: bytes) -> dict[str, Any]:
    info: dict[str, Any] = {"fingerprint": None, "created": None}
    if not body:
        return info
    version = body[0]
    if version in (4, 5, 6) and len(body) >= 6:
        info["created"] = iso(int.from_bytes(body[1:5], "big"))
    if version == 4:
        info["fingerprint"] = hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper()  # noqa: S324 - the OpenPGP v4 fingerprint is SHA-1 by definition
    elif version in (5, 6):
        prefix = b"\x9a" if version == 5 else b"\x9b"
        info["fingerprint"] = hashlib.sha256(prefix + len(body).to_bytes(4, "big") + body).hexdigest().upper()
    return info


def parse_pgp_bundle(text: Any, max_keys: int = 10) -> list[dict[str, Any]]:
    """Armored OpenPGP public keys -> [{fingerprint, created, uids, emails}] (UIDs capped at 256 characters)."""
    out: list[dict[str, Any]] = []
    if not isinstance(text, str):
        return out
    for m in _ARMOR_RE.finditer(text[:400000]):
        if len(out) >= max_keys:
            break
        data, err = _dearmor(m.group(1))
        if err or data is None:
            continue
        key: dict[str, Any] | None = None
        for tag, body in _packets(data):
            if tag == 6:
                if key and key.get("fingerprint"):
                    out.append(key)
                key = {**_key_info(body), "uids": [], "emails": []}
            elif tag == 13 and key is not None and len(key["uids"]) < 20:
                uid = body.decode("utf-8", errors="replace").strip()
                if uid:
                    key["uids"].append(uid[:256])
                    for e in extract_emails(uid):
                        if e not in key["emails"]:
                            key["emails"].append(e)
        if key and key.get("fingerprint"):
            out.append(key)
    return out


# ---------------------------------------------------------------------------------------------- proofs
def _proof_state(proof: dict[str, Any]) -> tuple[int | None, str]:
    raw = proof.get("proof_state", proof.get("state"))
    code = to_int(raw)
    if code is None and isinstance(raw, str):
        name = raw.strip().lower()
        for k, v in PROOF_STATES.items():
            if v == name:
                return k, v
        return None, name[:30] or "unknown"
    return code, PROOF_STATES.get(code, "unknown") if code is not None else "unknown"


def assess_proof(proof: Any, last_id_change: Any, now: Any) -> dict[str, Any] | None:
    """cond 3/4 reading of one proofs_summary.all[] entry."""
    if not isinstance(proof, dict):
        return None
    code, name = _proof_state(proof)
    signed = None
    for key in ("sig_ctime", "ctime", "proof_ctime"):
        signed = parse_dt(proof.get(key))
        if signed:
            break
    bound = None if signed else parse_dt(last_id_change)
    ref = signed or bound
    age = age_days(ref, now) if ref else None
    if age is not None and age > HISTORICAL_DAYS:
        label = "historical"
    elif signed:
        label = "current"
    else:
        label = "date unknown"
    when = (f"signed {day(signed)}" if signed else f"signed on or before {day(bound)}" if bound
            else "signature date not in the lookup answer")
    ok = code == 1
    if ok:
        confidence = "probable"
        wording = f"Keybase-verified proof, {when}"
    else:
        kind = "revoked" if code in REVOKED_STATES else "broken"
        confidence = "possible"
        wording = f"historical claim: Keybase proof {kind} ({name}), {when}"
    if label == "historical":
        wording += " (historical)"
    ptype = (to_str(proof.get("proof_type"), 40) or "unknown").lower()
    service = safe_url(proof.get("service_url"))
    return {
        "proof_type": ptype,
        "nametag": to_str(proof.get("nametag"), 256),
        "state": code,
        "state_name": name,
        "ok": ok,
        "service_url": service,
        "proof_url": safe_url(proof.get("proof_url")) or safe_url(proof.get("human_url")),
        "signed_at": iso(signed) if signed else None,
        "signed_on_or_before": iso(bound) if bound else None,
        "age_days": age,
        "label": label,
        "confidence": confidence,
        "wording": wording,
    }


def parse_user(user: Any, now: Any) -> dict[str, Any] | None:
    """One them[] entry -> account facts, assessed proofs, PGP keys (fingerprints, UID e-mails) and claims."""
    if not isinstance(user, dict):
        return None
    basics = user.get("basics") if isinstance(user.get("basics"), dict) else {}
    username = to_str(basics.get("username"), 32)
    if not username or not keybase_username_ok(username):
        return None
    username = username.lower()
    created = parse_dt(basics.get("ctime"))
    last_change = parse_dt(basics.get("last_id_change"))
    modified = parse_dt(basics.get("mtime"))
    ps = user.get("proofs_summary") if isinstance(user.get("proofs_summary"), dict) else {}
    raw_proofs = [p for p in (ps.get("all") if isinstance(ps.get("all"), list) else []) if isinstance(p, dict)]
    proofs = [a for a in (assess_proof(p, basics.get("last_id_change"), now) for p in raw_proofs[:MAX_PROOFS]) if a]
    pk = user.get("public_keys") if isinstance(user.get("public_keys"), dict) else {}
    primary = pk.get("primary") if isinstance(pk.get("primary"), dict) else {}
    fingerprints: list[str] = []
    for fpr in (primary.get("key_fingerprint"), pk.get("eldest_key_fingerprint")):
        if isinstance(fpr, str) and _FPR_RE.match(fpr) and fpr.upper() not in fingerprints:
            fingerprints.append(fpr.upper())
    bundles: list[str] = []
    for b in [*(pk.get("pgp_public_keys") if isinstance(pk.get("pgp_public_keys"), list) else [])[:10], primary.get("bundle")]:
        if isinstance(b, str) and "BEGIN PGP PUBLIC KEY BLOCK" in b and b not in bundles:
            bundles.append(b)
    keys: list[dict[str, Any]] = []
    for b in bundles:
        for k in parse_pgp_bundle(b):
            if all(k["fingerprint"] != x["fingerprint"] for x in keys):
                keys.append(k)
                if k["fingerprint"] not in fingerprints:
                    fingerprints.append(k["fingerprint"])
    emails: list[tuple[str, str]] = []
    for k in keys:
        for e in k["emails"]:
            if all(e != x for x, _ in emails):
                emails.append((e, k["fingerprint"]))
    crypto: list[dict[str, str]] = []
    cc = user.get("cryptocurrency_addresses")
    for coin, entries in (cc.items() if isinstance(cc, dict) else []):
        for ent in entries if isinstance(entries, list) else []:
            addr = to_str(ent.get("address"), 120) if isinstance(ent, dict) else None
            if addr and len(crypto) < 10:
                crypto.append({"coin": str(coin)[:20], "address": addr})
    eldest = to_int(basics.get("eldest_seqno")) or 0
    has_sigchain = bool(eldest > 0 or proofs or fingerprints)
    newest = max([d for d in (last_change, modified, created) if d], default=None)
    age = age_days(newest, now)
    data_age = {
        "as_of": iso(newest),
        "age_days": age,
        "wording": (f"account created {day(created) or 'unknown'}; last identity change {day(last_change) or 'unknown'}"
                    + (f"; data last modified {age} days ago" if age is not None else "")),
    }
    return {
        "username": username,
        "uid": to_str(user.get("id"), 40),
        "created": iso(created),
        "last_identity_change": iso(last_change),
        "last_modified": iso(modified),
        "has_sigchain": has_sigchain,
        "proofs": proofs,
        "pgp_fingerprints": fingerprints[:10],
        "pgp_keys": [{"fingerprint": k["fingerprint"], "created": k["created"], "uid_count": len(k["uids"])} for k in keys],
        "pgp_emails": emails[:10],
        "crypto": crypto,
        "data_age": data_age,
    }


# ---------------------------------------------------------------------------------------------- module
@register
class Keybase(Module):
    name = "keybase"
    title = "Keybase identity proofs, PGP keys and account dates"
    description = (
        "Keybase user lookup (keybase.io, keyless): signed identity proofs (GitHub, X, Reddit, domains, websites), PGP "
        "fingerprints and UID e-mails, account dates; reverse lookups for GitHub/X/Reddit accounts and domains. Keybase is "
        "in maintenance mode: every fact is historical and self-asserted."
    )
    category = "username_social"
    accepts = frozenset({T.USERNAME, T.DOMAIN, T.SOCIAL_ACCOUNT, T.URL})
    produces = frozenset({T.USERNAME, T.DOMAIN, T.URL, T.SOCIAL_ACCOUNT, T.EMAIL, T.PGP_FINGERPRINT, T.BTC})
    run_on = "seeds"  # usernames are PERSONAL_TYPES (A5: username lookups on analyst-typed seeds)
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "keybase"
    sources = (SOURCE,)
    hosts = ("keybase.io",)
    access_model = "free_noauth_limited"
    max_requests = 1  # one lookup per entity (cond 1)
    expected_latency = 0.5
    timeout = 20.0
    min_interval = 1.0
    cache_ttl = 86400  # the service is frozen; capped by the provider profile ttl (1 day)
    daily_quota = 1000  # no published limit: soft daily ceiling
    max_pivots = 60
    default_enabled = True
    reference = "https://keybase.io/docs/api/1.0/call/user/lookup"
    tags = frozenset({"free"})
    notice = (
        "Keybase is in maintenance mode: historical, self-asserted evidence. An OK proof is PROBABLE on Keybase alone and "
        "CONFIRMED only when another module corroborates it (rule p3g051_keybase_proof_corroborated). Usernames are personal "
        "data: personal_data_review comes before default use (A3 BR8)."
    )

    @classmethod
    def health_check(cls) -> HealthCheck | None:
        return HealthCheck(T.DOMAIN, "example.com", expect="empty")  # domain= reverse lookup: nobody proved example.com

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.URL:
            hit = platform_for_url(entity.value)
            return bool(hit and (hit[0] == "keybase" or hit[0] in REVERSE))
        if entity.type is T.SOCIAL_ACCOUNT:
            return entity.value.partition(":")[0] in ("keybase", *REVERSE)
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        kind, value = request_plan(entity)
        if kind is None:
            return res.mark("skipped", value, reason_code="not_applicable")
        url = lookup_url(kind, value)
        if url is None:
            return res.mark("skipped", "value outside the Keybase lookup syntax: not applicable", reason_code="not_applicable")
        data, why = json_body(ctx.http.get_json(url, source=SOURCE))
        if why:
            return res.mark("error", f"unexpected Keybase answer ({why}): could not verify")
        state, code, reason = lookup_status(data)
        if state == "skipped":
            return res.mark("skipped", reason, reason_code=code)
        if state in ("error", "rate_limited"):
            return res.mark(state, reason, reason_code=code)
        res.attr("data_notices", [BANNER])
        if state == "absent":
            res.presence("absent", marker="status.code 0 with them=[null] from user/lookup.json", url=f"https://keybase.io/{value.lower()}",
                         checked_at=ctx.now(), source=SOURCE)
            res.error = reason
            return res.mark("empty")
        if state == "empty":
            res.error = reason + f" ({kind}={value})"
            return res.mark("empty")
        now = ctx.now()
        users = [u for u in (parse_user(u, now) for u in data["them"][:MAX_USERS]) if u]
        if not users:
            return res.mark("error", "Keybase answer without a usable user record: could not verify")
        self._emit(res, ctx, entity, kind, value, users)
        return res

    # ------------------------------------------------------------------------------------------ results
    def _emit(self, res: ModuleResult, ctx: Any, entity: Entity, kind: str, value: str, users: list[dict[str, Any]]) -> None:
        reverse = kind != "usernames"
        newest = max((u["data_age"]["as_of"] or "" for u in users), default="")
        res.raw = {"lookup": kind, "users": [{k: u[k] for k in ("username", "uid", "created", "last_identity_change", "last_modified",
                                                                "has_sigchain", "pgp_fingerprints")}
                                             | {"proofs": [{k: p[k] for k in ("proof_type", "nametag", "state", "ok")} for p in u["proofs"]]}
                                             for u in users]}
        profiles: list[dict[str, Any]] = []
        proofs_attr: list[dict[str, Any]] = []
        for u in users:
            profiles.append({"username": u["username"], "uid": u["uid"], "created": u["created"], "last_identity_change": u["last_identity_change"],
                             "last_modified": u["last_modified"], "has_sigchain": u["has_sigchain"], "proof_count": len(u["proofs"]),
                             "pgp_fingerprints": u["pgp_fingerprints"], "banner": BANNER})
            for p in u["proofs"]:
                proofs_attr.append({"username": u["username"], **p})
        res.attr("keybase_profile", profiles)
        res.attr("keybase_proofs", proofs_attr)
        wording = "; ".join(f"{u['username']}: {u['data_age']['wording']}" for u in users)
        res.attr("data_age", {"as_of": newest or None, "age_days": users[0]["data_age"]["age_days"] if len(users) == 1 else None,
                              "wording": wording})
        res.attr("data_notices", [BANNER, "data age: " + wording])
        if not reverse:
            u = users[0]
            res.attr("created", u["created"])
            res.attr("profile_url", f"https://keybase.io/{u['username']}")
            res.presence("found", marker="user/lookup.json returned the account", url=f"https://keybase.io/{u['username']}",
                         checked_at=ctx.now(), source=SOURCE)
        for u in users:
            self._user_pivots(res, u, reverse)
            self._user_findings(res, u, reverse, kind, value)

    def _user_pivots(self, res: ModuleResult, u: dict[str, Any], reverse: bool) -> None:
        name = u["username"]
        if reverse:
            res.pivot(T.SOCIAL_ACCOUNT, f"keybase:{name}", "keybase_prover", confidence="probable", expand=False,
                      note=f"Keybase user {name} signed a proof for this value ({BANNER}); run keybase on it only after analyst review")
        else:
            res.pivot(T.SOCIAL_ACCOUNT, f"keybase:{name}", "has_account", confidence="confirmed", expand=False,
                      note=f"Keybase account (exists in the lookup answer); {BANNER}")
        res.pivot(T.URL, f"https://keybase.io/{name}", "has_account", confidence="confirmed", expand=False, note=f"Keybase profile of {name}")
        if reverse:
            return  # the prover's other proofs are listed in keybase_proofs; they are not links of the investigated value
        for p in u["proofs"]:
            self._proof_pivot(res, p)
        for fpr in u["pgp_fingerprints"]:
            res.pivot(T.PGP_FINGERPRINT, fpr, "pgp_key", confidence="probable", expand=False,
                      note=f"PGP key in the Keybase account {name} (historical): corroborates proofs when another source shows it")
        for email, fpr in u["pgp_emails"]:
            res.pivot(T.EMAIL, email, "gpg_uid_email", confidence="possible", expand=False,
                      note=f"e-mail asserted by the key owner in a PGP UID of key {fpr[-16:]} (self-asserted): analyst selection required")
        for c in u["crypto"]:
            if c["coin"] == "bitcoin" and _BTC_RE.match(c["address"]):
                res.pivot(T.BTC, c["address"], "keybase_proof", confidence="possible", expand=False,
                          note="bitcoin address signed into the Keybase sigchain (self-asserted)")

    def _proof_pivot(self, res: ModuleResult, p: dict[str, Any]) -> None:
        ok = p["ok"]
        conf = p["confidence"]
        note = p["wording"] + "; " + BANNER
        tag = p["nametag"] or ""
        ptype = p["proof_type"]
        if ptype == "dns":
            host = normalise_host(tag)
            if host:
                res.pivot(T.DOMAIN, host, "keybase_proof", confidence=conf, expand=ok, note=note + " (passive modules only)")
            return
        if ptype in WEB_TYPES:
            url = p["service_url"] or (safe_url("https://" + tag) if tag else None)
            host = normalise_host(host_of(url) or "") if url else None
            if url:
                res.pivot(T.URL, url, "keybase_proof", confidence=conf, expand=False, note=note)
            if host:
                res.pivot(T.DOMAIN, host, "keybase_proof", confidence=conf, expand=ok, note=note + " (passive modules only)")
            return
        if not tag:
            return
        platform = PLATFORMS.get(ptype)
        if platform and res.pivot(T.SOCIAL_ACCOUNT, f"{platform}:{tag}", "keybase_proof", confidence=conf, expand=ok, note=note):
            return
        res.pivot(T.USERNAME, tag, "keybase_proof", confidence=conf, expand=False, note=f"{ptype} account: {note}")

    def _user_findings(self, res: ModuleResult, u: dict[str, Any], reverse: bool, kind: str, value: str) -> None:
        name = u["username"]
        ok = [p for p in u["proofs"] if p["ok"]]
        broken = [p for p in u["proofs"] if not p["ok"]]
        status_line = ("account exists but has no sigchain, keys or proofs (reserved or never activated)" if not u["has_sigchain"]
                       else f"{len(ok)} OK proof(s), {len(broken)} revoked or broken, {len(u['pgp_fingerprints'])} PGP key(s)")
        lead = (f"Keybase user {name} signed a proof for {kind}={value}" if reverse else f"Keybase account {name}")
        res.finding(
            "Keybase account" if not reverse else "Keybase user proved this value",
            "info",
            f"{lead}: {status_line}. {u['data_age']['wording']}. {BANNER}.",
            confidence="probable" if reverse else "confirmed",
            criterion=("reverse lookup answered with this user (a signed, self-asserted proof)" if reverse
                       else "user/lookup.json returned the account (status code 0)"),
            data={"username": name, "has_sigchain": u["has_sigchain"], "data_age": u["data_age"]},
            tags=["account", "historical"],
            references=[f"https://keybase.io/{name}"],
            source=SOURCE,
            observed_last=u["last_identity_change"] or u["last_modified"],
            key=name,
        )
        if reverse:
            return
        if ok:
            res.finding(
                "Keybase-verified identity proofs",
                "info",
                "; ".join(f"{p['proof_type']} {p['nametag']}: {p['wording']}" for p in ok[:20])
                + f". PROBABLE on Keybase alone: CONFIRMED only when another source corroborates the link. {BANNER}.",
                confidence="probable",
                criterion="proofs_summary entries with proof state OK (1); the service is frozen and remote posts may be gone",
                data={"proofs": [{k: p[k] for k in ("proof_type", "nametag", "label", "signed_on_or_before", "signed_at")} for p in ok[:50]]},
                tags=["identity", "historical"],
                source=SOURCE,
                key=name,
            )
        if broken:
            res.finding(
                "Revoked or broken Keybase proofs (historical claims)",
                "info",
                "; ".join(f"{p['proof_type']} {p['nametag']}: {p['wording']}" for p in broken[:20]) + ".",
                confidence="possible",
                criterion="proofs_summary entries whose state is revoked, superseded, deleted or failing",
                data={"proofs": [{k: p[k] for k in ("proof_type", "nametag", "state_name", "label")} for p in broken[:50]]},
                tags=["historical", "weak_signal"],
                source=SOURCE,
                key=name,
            )
