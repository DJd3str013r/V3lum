"""ENS resolution through ENSData (P209): name.eth -> wallet, 0xaddress -> primary name, text records.

Final conditions (P209, council-1):

* cond 1 - ``crypto/ens_resolver``: ``https://api.ensdata.net/{name}.eth`` or ``/{address}``. Only ``.eth`` names
  (typed as a domain or a keyword) and 0x addresses are sent - an ordinary DNS domain never reaches ENSData. A 404
  ('Unable to resolve ... not registered') is EMPTY: for an address it means 'no reverse record (no ENS primary
  name)', never an absent wallet; for a name it means 'not registered or not linked to an address'.
* cond 2 - text records (twitter, github, url, email, ...) are self-asserted by the ENS owner: every pivot built from
  them is POSSIBLE and labelled 'self-asserted by the ENS owner'. The upgrade to PROBABLE happens only when the
  linked profile (found by another module in the case) points back to the ENS name or wallet: correlation rule
  ``p3g091_ens_claim_linked_back`` (v3lum/correlations/p3_g09_1.py, helper :func:`ens_claim_confidence`).
* cond 3 - URL, domain and e-mail pivots from text records are attacker-controllable: the module is PASSIVE (pivots
  never inherit LIGHT/ACTIVE: A7), the notes carry the defanged form, and personal identifiers (usernames, e-mails)
  pivot with ``expand=False``; URLs/domains stay POSSIBLE so AR07's ``min_expand_confidence`` keeps them from
  auto-expansion. Registry provider ``ensdata``: tier community, terms open. Fixtures: name, address and 404.

The parsers are ported from the batch prep (``prep/p3-G09-1/code/parsers.py``, live-verified 2026-11-26) and adapted
to contract v2. Every field of the answer is untrusted: types are checked, text is cleaned (no control characters,
capped), and odd answers are 'could not verify' (ERROR), never EMPTY.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any
from urllib.parse import quote, urlsplit

from v3lum.core.entities import Entity, defang
from v3lum.core.entities import EntityType as T
from v3lum.core.http import HttpError
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, Module, register
from v3lum.core.validators import btc_address_valid, eip55_checksum

SOURCE = "ensdata.api"
API = "https://api.ensdata.net/"
APP_PAGE = "https://app.ens.domains/{name}"
SELF_ASSERTED = "self-asserted by the ENS owner"
WALLET_CLAIM = "address record set by the ENS owner (not verified by the wallet owner)"
MAX_TEXT = 300
MAX_NAME = 255
#: the health-check probe: the ENS DAO's own name (public organisation record, verified live 2026-11-26)
BENIGN_NAME = "ens.eth"

_ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BAD_NAME_CHARS = re.compile(r"[\s/\\?#%@:<>\"'`,;()\[\]{}|^]|[\x00-\x1f\x7f-\x9f]")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_WS_RE = re.compile(r"\s+")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&*+=?^_{|}~'-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

#: text record key -> (kind, platform). ENSData flattens com.twitter -> twitter; both spellings are read.
TEXT_RECORDS: dict[str, tuple[str, str | None]] = {
    "twitter": ("username", "twitter"), "com.twitter": ("username", "twitter"),
    "x": ("username", "twitter"), "com.x": ("username", "twitter"),
    "github": ("username", "github"), "com.github": ("username", "github"),
    "telegram": ("username", "telegram"), "org.telegram": ("username", "telegram"),
    "discord": ("username", "discord"), "com.discord": ("username", "discord"),
    "reddit": ("username", "reddit"), "com.reddit": ("username", "reddit"),
    "linkedin": ("username", "linkedin"), "com.linkedin": ("username", "linkedin"),
    "url": ("url", None),
    "email": ("email", None),
}
#: descriptive records kept as profile facts (never pivots)
PROFILE_KEYS = ("description", "avatar", "header", "pgp", "snapshot", "location", "notice", "keywords", "name",
                "contentHash", "resolverAddress")
_HANDLE_RULES = {
    "twitter": re.compile(r"^[A-Za-z0-9_]{1,15}$"),
    "github": re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$"),
    "telegram": re.compile(r"^[A-Za-z][A-Za-z0-9_]{3,31}$"),
    "discord": re.compile(r"^[a-z0-9_.]{2,32}$"),
    "reddit": re.compile(r"^[A-Za-z0-9_-]{3,20}$"),
    "linkedin": re.compile(r"^[A-Za-z0-9-]{3,64}$"),
}
_PROFILE_HOSTS = {
    "twitter": ("twitter.com", "www.twitter.com", "x.com", "www.x.com", "mobile.twitter.com"),
    "github": ("github.com", "www.github.com"),
    "telegram": ("t.me", "telegram.me"),
    "reddit": ("reddit.com", "www.reddit.com", "old.reddit.com"),
    "linkedin": ("linkedin.com", "www.linkedin.com"),
}


# --------------------------------------------------------------------------------------
# helpers (pure, untrusted input)
# --------------------------------------------------------------------------------------


def clean_text(value: Any, limit: int = MAX_TEXT) -> str | None:
    """Untrusted provider text -> one line without C0/C1 controls, capped; None for non-strings/blank."""
    if not isinstance(value, str):
        return None
    text = _WS_RE.sub(" ", _CONTROL_RE.sub("", unicodedata.normalize("NFC", value))).strip()
    if not text:
        return None
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def normalize_ens_name(value: Any) -> str | None:
    """'Vitalik.ETH ' -> 'vitalik.eth' for syntactically sane ``.eth`` names, else None (cond 1 input gate).

    A basic ENSIP-15 subset: NFC + lower case, no empty labels, '_' only as a leading run, no ASCII '--' at label
    positions 3-4, no URL/control characters. The provider normalises the rest (its 400 'Invalid ENS name' is ERROR).
    """
    if not isinstance(value, str):
        return None
    name = unicodedata.normalize("NFC", value.strip()).lower().rstrip(".")
    if not name or len(name) > MAX_NAME or _BAD_NAME_CHARS.search(name) or not name.endswith(".eth"):
        return None
    labels = name.split(".")
    if len(labels) < 2:
        return None
    for label in labels:
        if not label or "_" in label.lstrip("_"):
            return None
        if label.isascii() and len(label) >= 4 and label[2:4] == "--":
            return None
    return name


def ens_query(entity: Entity) -> tuple[str, str] | None:
    """What the module sends for an entity: ('address', '0x..lower') | ('name', 'x.eth') | None (cond 1)."""
    value = str(entity.value or "").strip()
    if entity.type is T.ETH:
        return ("address", value.lower()) if _ETH_RE.match(value) else None
    if entity.type in (T.DOMAIN, T.KEYWORD):
        name = normalize_ens_name(value)
        return ("name", name) if name else None
    return None


def ensdata_url(kind: str, value: str) -> str:
    """https://api.ensdata.net/{name} (percent-encoded UTF-8) or /{0xaddress}."""
    if kind == "address":
        return API + value.lower()
    return API + quote(value, safe=".")


def _eip55(address: str) -> str:
    try:
        return eip55_checksum(address)
    except (ValueError, TypeError):
        return address


def _handle_from(platform: str, value: str) -> str | None:
    text = value.strip()
    hosts = _PROFILE_HOSTS.get(platform, ())
    if "://" in text or any(text.lower().startswith(h + "/") for h in hosts):
        try:
            parts = urlsplit(text if "://" in text else "https://" + text)
            host = (parts.hostname or "").lower()
        except ValueError:
            return None
        if host not in hosts or parts.username or parts.password:
            return None  # a profile URL on a foreign host is not a handle of this platform
        segments = [s for s in parts.path.split("/") if s]
        if platform == "reddit" and len(segments) >= 2 and segments[0] in ("u", "user"):
            segments = segments[1:]
        if platform == "linkedin" and len(segments) >= 2 and segments[0] == "in":
            segments = segments[1:]
        if not segments:
            return None
        text = segments[0]
    text = text.lstrip("@")
    if platform == "discord":
        text = text.lower()
    rule = _HANDLE_RULES.get(platform)
    return text if rule is not None and rule.match(text) else None


def _http_url(value: str) -> tuple[str, str] | None:
    text = value.strip()
    if any(c.isspace() for c in text):
        return None
    try:
        parts = urlsplit(text)
        host = (parts.hostname or "").lower().rstrip(".")
        _ = parts.port  # raises ValueError on a malformed port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host or parts.username or parts.password:
        return None
    return text, host


def _claim(kind: str, value: str, record: str, *, platform: str | None = None, expand: bool = False) -> dict[str, Any]:
    return {"type": kind, "value": value, "platform": platform, "record": record, "relation": "ens_text_record",
            "confidence": "possible", "label": SELF_ASSERTED, "expand": expand, "passive_only": True,
            "display": defang(value) if kind in ("url", "domain", "email") else value}


def text_record_claims(records: Any) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Text records -> (claims, rejected) (cond 2 + cond 3).

    Every claim is POSSIBLE 'self-asserted by the ENS owner', passive only, with a defanged display for
    url/domain/email; usernames and e-mails have ``expand=False``. ``rejected`` lists records that are not usable
    identifiers (javascript: URLs, invalid handles, non-strings, foreign-host profile URLs, userinfo URLs).
    """
    claims: list[dict[str, Any]] = []
    rejected: list[dict[str, str]] = []
    seen: set[tuple[str, str | None, str]] = set()
    if not isinstance(records, dict):
        return claims, rejected
    for key in sorted(records, key=str):
        mapping = TEXT_RECORDS.get(key)
        if mapping is None:
            continue
        raw = records[key]
        if not isinstance(raw, str) or not raw.strip() or len(raw) > 2048:
            rejected.append({"record": key, "reason": "not a usable string"})
            continue
        kind, platform = mapping
        found: list[dict[str, Any]] = []
        if kind == "username":
            handle = _handle_from(platform or "", raw)
            if handle is None:
                rejected.append({"record": key, "reason": f"not a valid {platform} handle"})
                continue
            found.append(_claim("username", handle, key, platform=platform))
        elif kind == "email":
            text = raw.strip()
            if text.lower().startswith("mailto:"):
                text = text[7:]
            if not _EMAIL_RE.match(text):
                rejected.append({"record": key, "reason": "not an e-mail address"})
                continue
            local, domain = text.rsplit("@", 1)
            found.append(_claim("email", f"{local}@{domain.lower()}", key))
        else:
            parts = _http_url(raw)
            if parts is None:
                bare = raw.strip().lower().rstrip("/")
                if _HOST_RE.match(bare):
                    found.append(_claim("domain", bare, key, expand=True))
                else:
                    rejected.append({"record": key, "reason": "not an http(s) URL"})
                    continue
            else:
                url, host = parts
                found.append(_claim("url", url, key, expand=True))
                if _HOST_RE.match(host) and not _IPV4_RE.match(host):
                    found.append(_claim("domain", host, key, expand=True))
        for claim in found:
            ident = (claim["type"], claim["platform"], claim["value"].lower())
            if ident not in seen:
                seen.add(ident)
                claims.append(claim)
    return claims, rejected


def _wallet_type(chain: str, value: str) -> T | None:
    if chain == "eth":
        return T.ETH if _ETH_RE.match(value) else None
    if chain == "btc":
        return T.BTC if btc_address_valid(value) else None
    return T.CRYPTO


def parse_ensdata(data: Any, kind: str, sent: str) -> dict[str, Any]:
    """ENSData JSON answer (already HTTP 200 or a handled 400/404) -> normalised resolution (cond 1-3).

    ``status``: found | empty | invalid | rate_limited | error. Keys: name, primary_name, address, reverse_verified,
    wallets {chain: address}, records {key: text}, profile {key: text}, claims [...], wallet_pivots [...],
    rejected [...], reason, error_in_200.
    """
    out: dict[str, Any] = {"status": "error", "kind": kind, "reason": None, "error_in_200": False, "name": None,
                           "primary_name": None, "address": None, "reverse_verified": False, "wallets": {},
                           "records": {}, "profile": {}, "claims": [], "wallet_pivots": [], "rejected": []}
    if not isinstance(data, dict):
        out["reason"] = "unexpected ENSData answer (not a JSON object)"
        return out
    if data.get("error") is True or "error" in data and not data.get("address") and not data.get("ens"):
        status = data.get("status")
        message = clean_text(data.get("message"), 200) or ""
        out["error_in_200"] = True
        if status == 404:
            out["status"] = "empty"
            out["reason"] = ("no reverse record: no ENS primary name is set for this address (says nothing about the wallet)"
                             if kind == "address" else "name not registered on ENS or not linked to an address")
            return out
        if status == 429:
            out["status"] = "rate_limited"
            out["reason"] = "ENSData rate limit (error-in-200 status 429): could not verify"
            return out
        if status == 400:
            out["status"] = "invalid"
            out["reason"] = message or "ENSData rejected the name as invalid"
            return out
        out["reason"] = f"ENSData error {status if isinstance(status, int) else ''}: {message or 'no message'}".replace("  ", " ")
        return out
    address = data.get("address")
    address = address if isinstance(address, str) and _ETH_RE.match(address) else None
    name = normalize_ens_name(data.get("ens")) if isinstance(data.get("ens"), str) else None
    if address is None and name is None:
        out["reason"] = "ENSData answer without an address or a name: could not verify"
        return out
    out["status"] = "found"
    out["address"] = address.lower() if address else None
    out["name"] = name
    out["primary_name"] = normalize_ens_name(data.get("ens_primary")) if isinstance(data.get("ens_primary"), str) else None
    wallets = data.get("wallets") if isinstance(data.get("wallets"), dict) else {}
    for chain, value in sorted(wallets.items(), key=lambda kv: str(kv[0])):
        if isinstance(chain, str) and isinstance(value, str) and value.strip() and len(out["wallets"]) < 20:
            ckey = re.sub(r"[^a-z0-9_]", "", chain.lower())[:16]
            if ckey:
                out["wallets"][ckey] = value.strip()[:128]
    eth = (out["wallets"].get("eth") or out["address"] or "").lower() or None
    if kind == "name":
        out["reverse_verified"] = bool(out["primary_name"] and name and out["primary_name"] == name and eth
                                       and out["address"] and eth == out["address"])
    else:
        out["reverse_verified"] = bool(out["address"] and out["address"] == sent.lower() and (not eth or eth == sent.lower()))
    records = {k: data[k] for k in data if isinstance(k, str) and k in TEXT_RECORDS}
    for key, value in records.items():
        text = clean_text(value) if isinstance(value, str) else None
        if text:
            out["records"][key] = text
    for key in PROFILE_KEYS:
        text = clean_text(data.get(key))
        if text:
            out["profile"][key] = text
    out["claims"], out["rejected"] = text_record_claims(records)
    if kind == "name" and out["address"]:
        out["wallet_pivots"].append({
            "type": T.ETH, "value": out["address"], "chain": "eth", "relation": "ens_resolves_to",
            "confidence": "confirmed" if out["reverse_verified"] else "probable", "expand": True,
            "label": ("ENS name and the address's primary name agree" if out["reverse_verified"]
                      else "forward ENS record only (the wallet has not set this name as its primary name)"),
        })
    for chain, value in out["wallets"].items():
        if chain == "eth" and out["address"] and value.lower() == out["address"]:
            continue
        etype = _wallet_type(chain, value)
        if etype is None:
            out["rejected"].append({"record": f"wallets.{chain}", "reason": "address does not match the chain format"})
            continue
        out["wallet_pivots"].append({"type": etype, "value": value, "chain": chain, "relation": "ens_address_record",
                                     "confidence": "possible", "expand": False, "label": WALLET_CLAIM})
    return out


def ens_claim_confidence(linked_texts: Any, ens_name: str | None = None, wallets: Any = ()) -> tuple[str, str | None]:
    """Cond 2: 'possible' unless a profile found by ANOTHER module points back to the ENS name or a wallet.

    ``linked_texts``: strings another module extracted from the claimed profile (bio, website, links...). Returns
    ('probable', evidence) when one of them contains the ENS name as a whole token or one of the wallets
    (case-insensitive), else ('possible', None).
    """
    needles: list[re.Pattern[str]] = []
    if isinstance(ens_name, str) and ens_name.strip():
        needles.append(re.compile(r"(?<![a-z0-9.-])" + re.escape(ens_name.strip().lower()) + r"(?![a-z0-9-])"))
    for wallet in wallets or ():
        if isinstance(wallet, str) and len(wallet.strip()) >= 26:
            needles.append(re.compile(re.escape(wallet.strip().lower())))
    for text in linked_texts or ():
        if not isinstance(text, str):
            continue
        low = text.lower()[:20000]
        for needle in needles:
            match = needle.search(low)
            if match:
                return "probable", f"linked profile points back: {match.group(0)}"
    return "possible", None


def _json(content: bytes) -> Any:
    try:
        return json.loads(content.decode("utf-8", "replace"))
    except ValueError:
        return None


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class EnsResolver(Module):
    name = "ens_resolver"
    title = "ENS name resolution (ENSData)"
    description = (
        "Resolves an ENS name (name.eth typed as a domain or keyword) to its wallet, or an Ethereum address to its ENS "
        "primary name, through ENSData; text records (twitter, github, url, email...) become self-asserted POSSIBLE leads."
    )
    category = "crypto"
    accepts = {T.DOMAIN, T.KEYWORD, T.ETH}
    produces = {T.ETH, T.BTC, T.CRYPTO, T.URL, T.DOMAIN, T.USERNAME, T.EMAIL}
    tags = {"free"}
    reference = "https://ensdata.net/"
    notice = (
        "ENSData receives the .eth name or the 0x address (never an ordinary DNS domain). ENS text records are "
        "self-asserted by the name owner: social handles, URLs and e-mails found there are POSSIBLE leads (never "
        "identity proof) until the linked profile points back to the ENS name or wallet. A 404 for an address means "
        "'no ENS primary name', never that the wallet does not exist."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "ensdata"
    sources = (SOURCE,)
    hosts = ("api.ensdata.net",)
    access_model = "free_noauth_limited"
    absent_statuses = frozenset({404})  # documented: name not registered / no reverse record (cond 1)
    max_requests = 1
    expected_latency = 1.0
    timeout = 25.0
    min_interval = 1.0
    daily_quota = 1000
    cache_ttl = 86400
    max_pivots = 30
    default_enabled = True

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(T.KEYWORD, BENIGN_NAME)  # a keyword .eth name: example.com (the DOMAIN probe) is never sent

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return ens_query(entity) is not None  # cond 1: only .eth names and 0x addresses are ever sent

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        query = ens_query(entity)
        if query is None:
            return res.mark("skipped", "not an ENS name (name.eth) or an Ethereum address: never sent", reason_code="not_applicable")
        kind, value = query
        resp = ctx.http.get(ensdata_url(kind, value), source=SOURCE, ttl=self.cache_ttl)
        if resp.status in (400, 404):
            try:
                ctx.http.check(resp)  # a challenge page or a marker still raises (could not verify)
            except HttpError:
                if resp.classification is not None:
                    raise
        else:
            ctx.http.check(resp)
        data = _json(resp.content)
        if resp.status in (400, 404) and not (isinstance(data, dict) and data.get("status") == resp.status):
            # only ENSData's own JSON error document is the documented absence/refusal (rule 5)
            return res.mark("error", f"unexpected ENSData HTTP {resp.status} answer (not its JSON error document): could not verify")
        parsed = parse_ensdata(data, kind, value)
        res.raw = {"query": value, "kind": kind, "http_status": resp.status,
                   "answer": {k: v for k, v in (data or {}).items() if k != "message"} if isinstance(data, dict) else None}
        as_of = ctx.now().date().isoformat()
        status = parsed["status"]
        if status == "empty":
            if kind == "address":
                res.attr("ens_reverse_record", f"no ENS primary name set for this address (as of {as_of}); says nothing about the wallet")
            else:
                res.attr("wallet_status", f"ENS name {value} not registered or not linked to an address (ENSData, as of {as_of})")
            return res.mark("empty", parsed["reason"])
        if status == "rate_limited":
            return res.mark("rate_limited", parsed["reason"])
        if status == "invalid":
            return res.mark("error", f"ENSData rejected the name ({parsed['reason']}): could not verify")
        if status != "found":
            return res.mark("error", f"{parsed['reason'] or 'unexpected ENSData answer'}: could not verify")
        self._report(res, entity, kind, value, parsed, as_of)
        return res

    def _report(self, res: ModuleResult, entity: Entity, kind: str, value: str, parsed: dict[str, Any], as_of: str) -> None:
        res.attr("chain", "ethereum")
        name = parsed["name"] if kind == "address" else value
        if name:
            res.attr("ens_name", name)
        res.attr("ens_primary_name", parsed["primary_name"])
        res.attr("ens_reverse_verified", bool(parsed["reverse_verified"]))
        res.attr("ens_wallets", dict(parsed["wallets"]))
        res.attr("ens_text_records", dict(parsed["records"]))
        res.attr("ens_profile", dict(parsed["profile"]))
        res.attr("ens_rejected_records", list(parsed["rejected"])[:20])
        address = parsed["address"]
        if kind == "name":
            summary = (f"{value} resolves to {_eip55(address)}" if address else f"{value} has no ETH address record")
            summary += (" (forward and reverse records agree)." if parsed["reverse_verified"]
                        else (f"; the address's primary name is {parsed['primary_name']}." if parsed["primary_name"]
                              else "; the address has not set it as its primary name."))
        else:
            summary = (f"{_eip55(value)} has the ENS primary name {name}"
                       + (" (verified both ways)." if parsed["reverse_verified"] else " (reverse record only)."))
        claims = parsed["claims"]
        if claims:
            summary += (f" {len(claims)} text-record lead(s) {SELF_ASSERTED}: "
                        + ", ".join(f"{c['record']}={c['display']}" for c in claims[:8]) + ".")
        res.finding(
            "ENS resolution (ENSData)",
            "info",
            summary + f" Records can change; as of {as_of}.",
            confidence="confirmed" if parsed["reverse_verified"] else "probable",
            data={"ens_name": name, "address": _eip55(address) if address else None, "primary_name": parsed["primary_name"],
                  "reverse_verified": parsed["reverse_verified"], "wallets": parsed["wallets"],
                  "claims": [{k: c[k] for k in ("type", "display", "record", "platform", "label")} for c in claims[:20]]},
            source=SOURCE,
            key=kind,
        )
        for pv in parsed["wallet_pivots"]:
            res.pivot(pv["type"], pv["value"], pv["relation"], confidence=pv["confidence"], expand=pv["expand"],
                      note=f"{pv['label']} ({pv['chain']} record of {name or value}, ENSData as of {as_of})")
        etypes = {"username": T.USERNAME, "email": T.EMAIL, "url": T.URL, "domain": T.DOMAIN}
        for claim in claims:
            platform = f" on {claim['platform']}" if claim["platform"] else ""
            res.pivot(etypes[claim["type"]], claim["value"], "ens_text_record", confidence="possible", expand=claim["expand"],
                      note=(f"{claim['display']}{platform}: ENS text record '{claim['record']}' of {name or value}, "
                            f"{SELF_ASSERTED} (unverified, attacker-controllable; passive lookups only)"))
        if name:
            res.link("ENS app page", APP_PAGE.format(name=quote(name, safe=".")))


__all__ = [
    "EnsResolver",
    "SELF_ASSERTED",
    "clean_text",
    "ens_claim_confidence",
    "ens_query",
    "ensdata_url",
    "normalize_ens_name",
    "parse_ensdata",
    "text_record_claims",
]
