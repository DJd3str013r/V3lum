"""JWT decode and weak-configuration analysis (P316, batch p2-G12-2), fully offline.

c1: disclosure 'none' (ctx.http refuses every request), terms 'open', tier n/a, allowed at TLP:RED. JWTs are
SECRET_TYPES (A8): a token is never sent to jwt.io or any online decoder, never replayed, forged or verified
against its issuer. Decoding is base64url + JSON only.

c2 (redaction): every output carries the redacted form only - the signature is replaced by its length and
SHA-256, sensitive claim values are masked (names, e-mails, phones, CPFs, subject ids) and the token itself
is represented by its SHA-256 (``jwt_redacted``). The full token exists only in memory during the run.

c3 (structural checks, any token): alg=none (CRITICAL), missing exp, excessive lifetime (setting
``jwt_analysis_max_lifetime_s``, default one day), kid/jku/x5u pointing to external URLs, embedded jwk, kid
path/injection characters and personal-data claims (claim NAMES only). jku/x5u/kid and iss URLs become
url/domain pivots with expand=False: they are never fetched. Findings map to ATT&CK T1606 (forging) and
T1528 (token exposure) and feed the CR22 rule ``jwt_weak_configuration`` through the ``jwt_header`` and
``jwt_claims`` attributes (exp/iat/nbf as epoch seconds).

c4-c5 (known-default check - a misconfiguration test, not cracking, A7 BR8): only HS256/384/512 tokens whose
issuer or audience host is an org-profile asset or an in-scope target, against the bundled list
``v3lum/data/jwt_analysis/known_default_hmac_keys.json`` (<= 100 publicly documented values, each with its
public source; no generated candidates, no wordlists). Third-party tokens and RS/ES/PS/none tokens are never
tested. A match is reported as 'signed with a publicly known default secret (list entry n)': the value is
never printed, stored or exported.

c6 (text blobs): candidate tokens are runs of [A-Za-z0-9_.-] full-matched against the binding regex
``^eyJ[\\w-]+\\.eyJ[\\w-]+\\.[\\w-]*$`` (ASCII \\w). The core P172 extractor (``v3lum.core.ioc``) turns JWTs
into masked secret fingerprints before anything else sees them, so the module applies the same regex to the
text itself, keeps the tokens in memory only and never pivots them (SECRET_TYPES).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlsplit

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

UTC = timezone.utc

#: P316 c6 verbatim, with re.ASCII (Python's \w is Unicode otherwise)
JWT_TEXT_RE = re.compile(r"^eyJ[\w-]+\.eyJ[\w-]+\.[\w-]*$", re.ASCII)
_JWT_RUN_RE = re.compile(r"[A-Za-z0-9_.\-]{12,}")
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]*")
JWT_MAX_LEN = 16384
MAX_TEXT_CHARS = 5 * 1024 * 1024
MAX_TOKENS = 20
JWT_HMAC = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
KNOWN_DEFAULTS_FILE = "jwt_analysis/known_default_hmac_keys.json"
KNOWN_DEFAULTS_MAX = 100  # c4
DEFAULT_MAX_LIFETIME_S = 86400
JWT_PII_CLAIMS = frozenset({
    "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username", "email", "phone_number",
    "address", "birthdate", "gender", "picture", "upn", "unique_name", "cpf", "rg", "nome", "telefone", "celular",
    "data_nascimento", "ssn",
})
JWT_SENSITIVE_CLAIMS = JWT_PII_CLAIMS | {"sub", "oid", "email_verified_address", "login", "user", "username"}
#: code -> (severity, ATT&CK ids, finding tags)
ISSUES: dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {
    "alg_none": ("critical", ("T1606",), ("misconfiguration",)),
    "alg_missing": ("high", ("T1606",), ("misconfiguration",)),
    "external_key_url": ("high", ("T1606",), ("misconfiguration",)),
    "embedded_jwk": ("medium", ("T1606",), ("misconfiguration",)),
    "kid_injection_hint": ("medium", ("T1606",), ("misconfiguration",)),
    "missing_exp": ("medium", ("T1528",), ("misconfiguration",)),
    "excessive_lifetime": ("medium", ("T1528",), ("misconfiguration",)),
    "pii_claims": ("low", ("T1528",), ("privacy",)),
    "expired": ("info", (), ("info",)),
}
CRITERIA = {
    "alg_none": "decoded header alg is 'none' in any letter case: the token carries no signature (static decode only)",
    "alg_missing": "decoded header has no alg member: the verifier must pin the algorithm itself",
    "external_key_url": "decoded header jku/x5u (or a URL-shaped kid) names a key location: a verifier that follows it accepts attacker keys (never fetched)",
    "embedded_jwk": "decoded header embeds its own jwk: key-confusion hint if the verifier trusts header keys",
    "kid_injection_hint": "decoded kid contains path traversal or shell/SQL metacharacters",
    "missing_exp": "decoded payload has no numeric exp claim: the token never expires",
    "excessive_lifetime": "exp - iat (else exp - now) exceeds the configured jwt_analysis_max_lifetime_s",
    "pii_claims": "decoded payload carries personal-data claim names (values masked, never kept)",
}
DEFAULT_MATCH_CRITERION = (
    "HS* signature recomputed offline with an entry of the bundled list of publicly documented defaults "
    "(<= 100 entries) matches; checked only because iss/aud is an org-profile asset or in-scope target"
)


# ---------------------------------------------------------------------------------- decoding
def find_jwts(text: Any, limit: int = MAX_TOKENS) -> list[str]:
    """c6: candidate tokens of a text blob, each full-matched against the anchored c6 regex (linear tokeniser;
    'Bearer x', 'token=x&' and JSON strings work, a trailing sentence dot is tolerated)."""
    t = text if isinstance(text, str) else ""
    out: list[str] = []
    for m in _JWT_RUN_RE.finditer(t[:MAX_TEXT_CHARS]):
        tok = m.group(0)
        if len(tok) > JWT_MAX_LEN:
            continue
        cand = tok if JWT_TEXT_RE.match(tok) else (tok[:-1] if tok.endswith(".") and JWT_TEXT_RE.match(tok[:-1]) else None)
        if cand and cand not in out:
            out.append(cand)
            if len(out) >= limit:
                break
    return out


def b64url_decode(seg: Any) -> bytes | None:
    """Strict base64url (padding optional); None on any invalid input."""
    if not isinstance(seg, str) or not _B64URL_RE.fullmatch(seg) or len(seg) % 4 == 1:
        return None
    try:
        return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
    except (binascii.Error, ValueError):
        return None


def decode_jwt(token: Any) -> dict[str, Any]:
    """c1/c3: offline decode, never verified. {'ok', 'error', 'header', 'payload', 'payload_kind', 'alg',
    'signature_b64_len', 'segments'}; errors: not_a_string | too_long | jwe_not_supported |
    not_three_segments | header_not_base64url | header_not_json | header_not_object | payload_not_base64url."""
    out: dict[str, Any] = {"ok": False, "error": None, "header": None, "payload": None, "payload_kind": None, "alg": None,
                           "signature_b64_len": 0, "segments": 0}
    if not isinstance(token, str):
        out["error"] = "not_a_string"
        return out
    t = token.strip()
    if len(t) > JWT_MAX_LEN:
        out["error"] = "too_long"
        return out
    parts = t.split(".")
    out["segments"] = len(parts)
    if len(parts) == 5:
        out["error"] = "jwe_not_supported"
        return out
    if len(parts) != 3:
        out["error"] = "not_three_segments"
        return out
    hb = b64url_decode(parts[0])
    if hb is None:
        out["error"] = "header_not_base64url"
        return out
    try:
        header = json.loads(hb.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        out["error"] = "header_not_json"
        return out
    if not isinstance(header, dict):
        out["error"] = "header_not_object"
        return out
    pb = b64url_decode(parts[1])
    if pb is None:
        out["error"] = "payload_not_base64url"
        return out
    try:
        payload = json.loads(pb.decode("utf-8"))
        kind = "object" if isinstance(payload, dict) else "json_non_object"
    except (UnicodeDecodeError, ValueError, RecursionError):
        payload, kind = None, "not_json"
    alg = header.get("alg")
    out.update(ok=True, header=header, payload=payload if isinstance(payload, dict) else None, payload_kind=kind,
               alg=alg if isinstance(alg, str) else None, signature_b64_len=len(parts[2]))
    return out


def _num(v: Any) -> float | None:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _is_http_url(v: Any) -> bool:
    if not isinstance(v, str) or len(v) > 2048:
        return False
    try:
        u = urlsplit(v.strip())
    except ValueError:
        return False
    return u.scheme in ("http", "https") and bool(u.hostname)


def _url_like(v: Any) -> bool:
    return isinstance(v, str) and bool(re.match(r"[A-Za-z][A-Za-z0-9+.-]{0,15}://", v))


_HOST_RE = re.compile(r"(?:[a-z0-9-]{1,63}\.){1,10}[a-z]{2,24}")


# ---------------------------------------------------------------------------------- checks
def jwt_issues(decoded: dict[str, Any], *, now: float, max_lifetime_s: int = DEFAULT_MAX_LIFETIME_S) -> list[dict[str, Any]]:
    """c3: structural checks for any token -> [{'code', 'severity', 'title', 'detail', 'attack'}]."""
    if not isinstance(decoded, dict) or not decoded.get("ok"):
        return []
    header = decoded.get("header") or {}
    payload = decoded.get("payload") or {}
    out: list[dict[str, Any]] = []

    def add(code: str, title: str, detail: str = "") -> None:
        sev, attack, _tags = ISSUES[code]
        out.append({"code": code, "severity": sev, "title": title, "detail": detail, "attack": list(attack)})

    alg = header.get("alg")
    if isinstance(alg, str) and alg.strip().lower() == "none":
        add("alg_none", "JWT uses alg=none (unsigned token)", f"alg={alg[:20]!r}; signature length {decoded.get('signature_b64_len', 0)}")
    elif "alg" not in header:
        add("alg_missing", "JWT header has no alg")
    exp, iat = _num(payload.get("exp")), _num(payload.get("iat"))
    if exp is None:
        add("missing_exp", "JWT has no exp claim (non-expiring token)")
    else:
        if exp < now:
            shown = datetime.fromtimestamp(max(0.0, min(exp, 32503680000.0)), UTC)
            add("expired", "JWT is expired", f"exp {shown:%Y-%m-%d %H:%M} UTC")
        start = iat if iat is not None else now
        lifetime = exp - start
        if lifetime > max_lifetime_s:
            add("excessive_lifetime", "JWT lifetime exceeds the configured maximum",
                f"lifetime {int(lifetime)} s > {max_lifetime_s} s ({'exp-iat' if iat is not None else 'exp-now'})")
    for field in ("jku", "x5u"):
        if field in header and _url_like(header.get(field)):
            add("external_key_url", f"JWT header {field} points to an external URL",
                "key-injection hint: the verifier must ignore or allow-list it (never fetched)")
    kid = header.get("kid")
    if isinstance(kid, str):
        if _url_like(kid):
            add("external_key_url", "JWT header kid is a URL", "key-injection hint: the verifier must not dereference kid (never fetched)")
        elif "../" in kid or "..\\" in kid or re.search(r"['\";|`$]", kid):
            add("kid_injection_hint", "JWT kid contains path or injection characters")
    if isinstance(header.get("jwk"), dict):
        add("embedded_jwk", "JWT header embeds its own jwk (key-confusion hint)")
    pii = sorted(k for k in payload if isinstance(k, str) and k.lower() in JWT_PII_CLAIMS)
    if pii:
        add("pii_claims", "JWT payload carries personal-data claims", "claims: " + ", ".join(pii[:20]))
    return out


def jwt_pivots(decoded: dict[str, Any]) -> list[dict[str, Any]]:
    """c3: jku/x5u/kid URLs (relation jwt_key_url) and the iss URL/host (jwt_issuer) as url/domain pivots, all
    expand=False and never fetched. Only http(s) URLs and well-formed host names are kept."""
    if not isinstance(decoded, dict) or not decoded.get("ok"):
        return []
    header = decoded.get("header") or {}
    payload = decoded.get("payload") or {}
    out: list[dict[str, Any]] = []

    def add(etype: str, value: str, relation: str, field: str) -> None:
        item = {"type": etype, "value": value, "relation": relation, "field": field}
        if item not in out:
            out.append(item)

    for field in ("jku", "x5u", "kid"):
        v = header.get(field)
        if _is_http_url(v):
            add("url", v.strip(), "jwt_key_url", field)
            add("domain", (urlsplit(v.strip()).hostname or "").lower(), "jwt_key_url", field)
    iss = payload.get("iss")
    if _is_http_url(iss):
        add("url", iss.strip(), "jwt_issuer", "iss")
        add("domain", (urlsplit(iss.strip()).hostname or "").lower(), "jwt_issuer", "iss")
    elif isinstance(iss, str) and _HOST_RE.fullmatch(iss.strip().lower()):
        add("domain", iss.strip().lower(), "jwt_issuer", "iss")
    return out


def jwt_scope_hosts(decoded: dict[str, Any]) -> list[str]:
    """c4: hosts named by iss/aud (URL or bare host) for the org-profile / in-scope decision."""
    if not isinstance(decoded, dict) or not decoded.get("ok"):
        return []
    payload = decoded.get("payload") or {}
    vals: list[Any] = [payload.get("iss")]
    aud = payload.get("aud")
    vals.extend(aud[:10] if isinstance(aud, list) else [aud])
    hosts: list[str] = []
    for v in vals:
        h = None
        if _is_http_url(v):
            h = urlsplit(v.strip()).hostname
        elif isinstance(v, str) and _HOST_RE.fullmatch(v.strip().lower()):
            h = v.strip().lower()
        if h and h.lower() not in hosts:
            hosts.append(h.lower())
    return hosts


def known_default_hmac_check(token: str, decoded: dict[str, Any], *, in_scope: bool, entries: Sequence[Any]) -> dict[str, Any]:
    """c4-c5: the known-default test (NOT cracking). Only HS256/384/512, only in scope, list <= 100.
    Returns {'status': 'matched', 'entry': n} | {'status': 'not_matched', 'checked': k} | {'status': 'skipped',
    'reason': ...}; the matched value is never part of the result."""
    if not isinstance(decoded, dict) or not decoded.get("ok") or not isinstance(token, str):
        return {"status": "skipped", "reason": "malformed"}
    alg = decoded.get("alg")
    if alg not in JWT_HMAC:
        return {"status": "skipped", "reason": "not_hmac"}
    if not in_scope:
        return {"status": "skipped", "reason": "third_party"}
    if len(entries) > KNOWN_DEFAULTS_MAX:
        return {"status": "skipped", "reason": "list_too_long"}
    parts = token.strip().split(".")
    sig = b64url_decode(parts[2]) if len(parts) == 3 else None
    if not sig:
        return {"status": "skipped", "reason": "no_signature"}
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    digestmod = JWT_HMAC[alg]
    for i, entry in enumerate(entries, start=1):
        value = entry.get("value") if isinstance(entry, dict) else entry
        if not isinstance(value, str):
            continue
        mac = hmac.new(value.encode("utf-8"), signing_input, digestmod).digest()
        if hmac.compare_digest(mac, sig):
            return {"status": "matched", "entry": i}
    return {"status": "not_matched", "checked": len(entries)}


# ---------------------------------------------------------------------------------- redaction
_EMAIL_VALUE_RE = re.compile(r"[^@\s]{1,64}@([A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24})")
_CPF_VALUE_RE = re.compile(r"\d{3}\.?\d{3}\.?\d{3}-?\d{2}")
_PHONE_VALUE_RE = re.compile(r"\+?\d[\d ()-]{7,18}\d")


def _mask_cpf(value: str) -> str:
    d = re.sub(r"\D", "", value)
    return f"***.{d[3:6]}.{d[6:9]}-**" if len(d) == 11 else "***"


def _mask_value(v: Any) -> Any:
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, (int, float)):
        return "***"
    if isinstance(v, str):
        s = v.strip()
        m = _EMAIL_VALUE_RE.fullmatch(s)
        if m:
            return s[0] + "***@" + m.group(1).lower()
        if _CPF_VALUE_RE.fullmatch(s):
            return _mask_cpf(s)
        return f"*** ({len(s)} chars)" if s else ""
    if isinstance(v, list):
        return [_mask_value(x) for x in v[:20]]
    if isinstance(v, dict):
        return {str(k)[:64]: _mask_value(x) for k, x in list(v.items())[:50]}
    return "***"


def _looks_personal(v: Any) -> bool:
    if not isinstance(v, str):
        return False
    s = v.strip()
    return bool(_EMAIL_VALUE_RE.fullmatch(s) or _CPF_VALUE_RE.fullmatch(s) or _PHONE_VALUE_RE.fullmatch(s))


def mask_claims(payload: Any, depth: int = 0) -> Any:
    """c2: sensitive claim values masked (names, e-mails, phones, CPFs, subject ids); other claims kept."""
    if not isinstance(payload, dict) or depth > 4:
        return {} if depth == 0 else "***"
    out: dict[str, Any] = {}
    for k, v in list(payload.items())[:100]:
        key = str(k)[:64]
        if key.lower() in JWT_SENSITIVE_CLAIMS or _looks_personal(v):
            out[key] = _mask_value(v)
        elif isinstance(v, dict):
            out[key] = mask_claims(v, depth + 1)
        elif isinstance(v, list):
            out[key] = [(_mask_value(x) if _looks_personal(x) else (mask_claims(x, depth + 1) if isinstance(x, dict) else x)) for x in v[:50]]
        elif isinstance(v, str) and len(v) > 512:
            out[key] = v[:64] + f"... ({len(v)} chars)"
        else:
            out[key] = v
    return out


def redact_jwt(token: str, decoded: dict[str, Any] | None = None) -> dict[str, Any]:
    """c2: the only persisted form of a JWT: signature stripped (length + SHA-256), sensitive claims masked,
    the token as its SHA-256 (exports carry only this and the findings)."""
    t = token.strip() if isinstance(token, str) else ""
    d = decoded if isinstance(decoded, dict) else decode_jwt(t)
    parts = t.split(".")
    sig = parts[2] if len(parts) == 3 else ""
    tok_sha = hashlib.sha256(t.encode("utf-8", "replace")).hexdigest()
    sig_sha = hashlib.sha256(sig.encode("ascii", "replace")).hexdigest() if sig else None
    alg = d.get("alg") or "?"
    display = (f"jwt alg={alg[:20]} claims={len(d.get('payload') or {})} sig[{len(sig)}]"
               + (f"#{sig_sha[:12]}" if sig_sha else "") + f" sha256:{tok_sha[:16]}")
    return {
        "kind": "jwt", "sha256": tok_sha, "alg": alg[:20],
        "header": mask_claims(d.get("header")) if d.get("ok") else None,
        "claims": mask_claims(d.get("payload")) if d.get("ok") else None,
        "signature": {"present": bool(sig), "b64_length": len(sig), "sha256": sig_sha},
        "display": display, "error": d.get("error"),
    }


def header_attr(decoded: dict[str, Any]) -> dict[str, Any]:
    """The CR22 ``jwt_header`` view: alg/typ/cty/kid (strings, capped), jku/x5u URLs, jwk presence."""
    header = decoded.get("header") or {}
    out: dict[str, Any] = {}
    for k in ("alg", "typ", "cty", "kid", "jku", "x5u"):
        v = header.get(k)
        if isinstance(v, str) and v:
            out[k] = v[:300] if k in ("jku", "x5u") else v[:100]
    if "jwk" in header:
        out["jwk"] = True
    return out


def claims_attr(decoded: dict[str, Any]) -> dict[str, Any]:
    """The CR22 ``jwt_claims`` view: non-personal claims iss/aud and exp/iat/nbf as epoch seconds, plus presence
    flags of personal claims (values never kept)."""
    payload = decoded.get("payload") or {}
    out: dict[str, Any] = {}
    iss = payload.get("iss")
    if isinstance(iss, str) and not _looks_personal(iss):
        out["iss"] = iss[:200]
    aud = payload.get("aud")
    if isinstance(aud, str) and not _looks_personal(aud):
        out["aud"] = aud[:200]
    elif isinstance(aud, list):
        out["aud"] = [a[:200] for a in aud[:5] if isinstance(a, str) and not _looks_personal(a)]
    for k in ("exp", "iat", "nbf"):
        v = _num(payload.get(k))
        if v is not None and 0 <= v < 32503680000:
            out[k] = int(v)
    out["has_sub"], out["has_email"], out["has_name"] = "sub" in payload, "email" in payload, "name" in payload
    return out


@register
class JwtAnalysis(Module):
    name = "jwt_analysis"
    title = "JWT decode and weak-configuration analysis"
    description = (
        "Offline decode of JSON Web Tokens (never verified, replayed or sent anywhere): alg none, missing or long "
        "expiry, external jku/x5u/kid keys, personal claims and, for own/in-scope HS* tokens only, a bounded check "
        "against publicly documented default signing values."
    )
    category = "utility"
    accepts = {T.JWT, T.TEXT}
    produces = {T.URL, T.DOMAIN}
    tags = {"offline", "free"}
    reference = "https://datatracker.ietf.org/doc/html/rfc8725"
    notice = (
        "JWTs are secrets (A8): decoded offline only; outputs carry the redacted form (signature length and hash, masked "
        "claims, token SHA-256). The known-default check runs only for org-profile or in-scope HS* tokens and never "
        "reveals the value it matched."
    )
    # ---- contract v2 declarations ---------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # c1
    hosts = ()
    access_model = "offline"
    expected_latency = 0.01
    max_pivots = 40
    default_enabled = True
    settings = {
        "jwt_analysis_max_lifetime_s": SettingSpec(
            DEFAULT_MAX_LIFETIME_S, "JWT lifetime (exp - iat, else exp - now) above which jwt_analysis reports 'excessive lifetime' (seconds)"),
    }

    # ---- helpers ----------------------------------------------------------------------------
    @staticmethod
    def _known_defaults(ctx: Any) -> list[Any]:
        try:
            data = ctx.data.bundled_json(KNOWN_DEFAULTS_FILE)
        except (OSError, ValueError):
            return []
        entries = data.get("entries") if isinstance(data, dict) else None
        return list(entries) if isinstance(entries, list) else []

    @staticmethod
    def _scope_of(ctx: Any, hosts: list[str]) -> str:
        """'own_asset' (org profile), 'in_scope' (scope file) or 'third_party' for the iss/aud hosts (c4)."""
        org = getattr(ctx, "org", None)
        scope = getattr(getattr(ctx, "options", None), "scope", None)
        for host in hosts:
            ent = Entity.try_make(T.DOMAIN, host)
            if ent is None:
                continue
            try:
                if org is not None and org.owns(ent).own:
                    return "own_asset"
            except Exception:  # noqa: BLE001 - a broken org profile never widens the check
                pass
            try:
                if scope is not None and scope.matches_host(host):
                    return "in_scope"
            except Exception:  # noqa: BLE001
                pass
        return "third_party"

    def _analyse(self, res: ModuleResult, token: str, ctx: Any, *, single: bool, entries: list[Any]) -> dict[str, Any]:
        decoded = decode_jwt(token)
        red = redact_jwt(token, decoded)
        key = red["sha256"][:16]
        if not decoded["ok"]:
            return {"redacted": red, "error": decoded["error"]}
        max_life = int(ctx.setting("jwt_analysis_max_lifetime_s", DEFAULT_MAX_LIFETIME_S) or DEFAULT_MAX_LIFETIME_S)
        issues = jwt_issues(decoded, now=ctx.now().timestamp(), max_lifetime_s=max_life)
        hosts = jwt_scope_hosts(decoded)
        scoping = self._scope_of(ctx, hosts)
        check = known_default_hmac_check(token, decoded, in_scope=scoping != "third_party", entries=entries)
        ownership_tag = "third_party" if scoping == "third_party" else ("own_asset" if scoping == "own_asset" else "in_scope")
        where = "" if single else f" ({red['display']})"
        for issue in issues:
            sev, attack, tags = ISSUES[issue["code"]]
            res.finding(
                issue["title"],
                sev,
                (f"Token {red['display']}: {issue['detail']}." if issue["detail"] else f"Token {red['display']}.")
                + " Static analysis of the decoded header and claims; the token was never verified, replayed or sent anywhere.",
                confidence="possible" if issue["code"] == "kid_injection_hint" else "probable" if issue["code"] == "external_key_url" else "confirmed",
                criterion=CRITERIA.get(issue["code"], "") if sev != "info" else "",
                data={"code": issue["code"], "token_display": red["display"], "rule": "CR22", "scope": scoping},
                tags=[*tags, ownership_tag] if sev != "info" else list(tags),
                attack=attack,
                key=issue["code"] + ("" if single else ":" + key),
            )
        if check["status"] == "matched":
            n = check["entry"]
            res.finding(
                "JWT signed with a publicly known default secret",
                "high",
                f"Token {red['display']}: signed with a publicly known default secret (list entry {n}). Rotate the signing "
                "key; the value itself is never printed, stored or exported.",
                confidence="confirmed",
                criterion=DEFAULT_MATCH_CRITERION,
                data={"code": "known_default", "entry": n, "token_display": red["display"], "rule": "CR22", "scope": scoping},
                tags=["credential_exposure", "misconfiguration", ownership_tag],
                attack=("T1606",),
                key="known_default" + ("" if single else ":" + key),
            )
        for p in jwt_pivots(decoded):
            etype = T.URL if p["type"] == "url" else T.DOMAIN
            res.pivot(etype, p["value"], p["relation"], confidence="probable", expand=False,
                      note=f"named by the JWT {p['field']}{where}: listed for the analyst, never fetched")
        return {"redacted": red, "decoded": decoded, "issues": issues, "check": check, "scope": scoping}

    # ---- run ----------------------------------------------------------------------------------
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        entries = self._known_defaults(ctx)
        if entity.type is T.JWT:
            out = self._analyse(res, entity.value, ctx, single=True, entries=entries)
            red = out["redacted"]
            if out.get("error"):
                res.raw = {"redacted": red}
                return res.mark("error", f"JWT could not be decoded ({out['error']}): not analysed")
            decoded = out["decoded"]
            res.attr("jwt_redacted", red)
            res.attr("jwt_header", header_attr(decoded))
            res.attr("jwt_claims", claims_attr(decoded))
            res.attr("jwt_issues", [{k: i[k] for k in ("code", "severity", "title", "attack")} for i in out["issues"]])
            res.attr("jwt_known_default_check", out["check"])
            res.finding(
                "JWT decoded offline (signature not verified)",
                "info",
                f"Token {red['display']}: alg {red['alg']}, {len(out['issues'])} structural issue(s), known-default check "
                f"{out['check']['status']} ({out['check'].get('reason', '') or 'bundled list'}); iss/aud scope: {out['scope']}.",
                data={"redacted": red},
                tags=["info"],
            )
            res.raw = {"redacted": red, "issues": out["issues"], "check": out["check"], "scope": out["scope"]}
            return res
        tokens = find_jwts(entity.value or "")
        if not tokens:
            res.error = "no JWT-shaped token (eyJ...eyJ...) in the text"
            return res.mark("empty")
        summaries: list[dict[str, Any]] = []
        for token in tokens:
            out = self._analyse(res, token, ctx, single=False, entries=entries)
            summaries.append({"redacted": out["redacted"], "error": out.get("error"), "issues": [i["code"] for i in out.get("issues", [])],
                              "check": out.get("check"), "scope": out.get("scope")})
        res.attr("jwt_redacted", [s["redacted"] for s in summaries])
        res.attr("jwt_issues", [{"token": s["redacted"]["display"], "codes": s["issues"]} for s in summaries if s["issues"]])
        res.finding(
            "JWTs found in the text (not pivoted)",
            "info",
            f"{len(tokens)} JWT(s) decoded offline: " + "; ".join(s["redacted"]["display"] for s in summaries[:10])
            + ". Tokens are secrets: never pivoted, sent or exported.",
            data={"count": len(tokens), "tokens": [s["redacted"]["display"] for s in summaries]},
            tags=["info"],
        )
        res.raw = {"tokens": summaries}
        return res
