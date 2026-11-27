"""GoPlus address/token security and phishing-site checks; Honeypot.is behind its registry review (P206).

Final conditions (P206):

* cond 1 - GoPlus ``address_security/{addr}?chain_id=`` for EVM addresses (chain ids from setting
  ``goplus_security_evm_chains``, default Ethereum '1') and TRON (``chain_id=tron``); ``token_security``
  (answer keyed by the lowercase contract) only for EVM addresses address_security marks as contracts;
  ``phishing_site`` only for URLs/domains with crypto context in the case (tags wallet/token/drainer/
  crypto_scam on the node, a crypto-address parent in the provenance, or the analyst's setting
  ``goplus_security_crypto_context``) - never for every URL. Honeypot.is only for token contracts
  (404 'No pairs found' = not applicable, no row) - see cond 5.
* cond 2 - GET lookups only (the optional key's token exchange is the API's own authentication); no
  report or submission endpoint. URLs sent to phishing_site lose query string, fragment and userinfo
  (and a path that carries an e-mail or an opaque >= 16-character token) unless the analyst opts in for
  that URL (setting ``goplus_security_full_url``).
* cond 3 - responses ``{'code':1,'message':'ok','result':{...}}``: code != 1 is ERROR (4029 'request
  limit reached' is the provider's rate_limited marker); string flags '0'/'1' are cast to bool; every
  positive flag is a named finding with its data_source; phishing_activities, stealing_attack,
  cybercrime, money_laundering and blackmail_activities give tags (phishing, theft, cybercrime,
  money_laundering, extortion); doubt flags (blacklist_doubt) are low. An unsupported chain answers
  'ok' with every flag '0' and contract_address '-1': 'not evaluated' (could not verify), never clean.
* cond 4 - GoPlus 'sanctioned' is not authoritative: an info finding without the 'sanctions' tag and the
  attribute ``sanctioned=True``, which the rule ``g09_sanctions_non_authoritative`` labels; the sanctions
  tag comes only from crypto_sanctions_* (P205). One vote in consensus.
* cond 5 - terms 'key-terms' (unverified, JS-only docs): under corporate only after legal records the
  terms or a business key plan; optional key ``goplus`` ('app_key:app_secret' of a company account).
  Honeypot.is is queried only when its registry review records tier community or higher: the review of
  2026-11-26 records 'unknown' (anonymous operator), so its source is not declared and no request is
  made (:func:`honeypot_allowed`, parser kept for the day the tier changes).
* cond 6 - registry: GoPlus tier community; fixtures for address_security, token_security,
  phishing_site and the Honeypot.is 404.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import ConfigError
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, Module, register
from v3lum.core.redact import register_secret
from v3lum.core.validators import crypto_address_info
from v3lum.modules.darkweb_ransomware.deepdarkcti_index import safe_plain

try:  # SettingSpec gives the settings a description (v3lum config show)
    from v3lum.config import SettingSpec
except ImportError:  # pragma: no cover - contract v2 always has it
    SettingSpec = None  # type: ignore[assignment,misc]

SOURCE_ADDRESS = "gopluslabs.address_security"
SOURCE_TOKEN = "gopluslabs.token_security"
SOURCE_PHISHING = "gopluslabs.phishing_site"
HONEYPOT_SOURCE = "honeypot_is.is_honeypot"
KEY = "goplus"
API = "https://api.gopluslabs.io/api/v1"
ADDRESS_URL = API + "/address_security/{address}"
TOKEN_URL = API + "/token_security/{chain_id}"
PHISHING_URL = API + "/phishing_site"
AUTH_URL = API + "/token"
HONEYPOT_URL = "https://api.honeypot.is/v2/IsHoneypot"
#: the Ethereum Foundation wallet (public organisation address): the benign health-check value
EF_WALLET = "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"
MAX_CHAINS = 3
EVM_CHAIN_IDS = frozenset({"1", "10", "56", "100", "137", "250", "324", "8453", "42161", "43114", "59144", "534352"})
CRYPTO_CONTEXT_TAGS = ("wallet", "token", "drainer", "crypto_scam")
CRYPTO_TYPES = frozenset({T.ETH, T.BTC, T.CRYPTO, T.XMR})

#: flag -> (finding title, severity, tag or None). 'sanctioned' never becomes a sanctions tag (cond 4).
ADDRESS_FLAGS: dict[str, tuple[str, str, str | None]] = {
    "phishing_activities": ("GoPlus: phishing activities", "medium", "phishing"),
    "stealing_attack": ("GoPlus: stealing attack (theft)", "medium", "theft"),
    "cybercrime": ("GoPlus: cybercrime", "medium", "cybercrime"),
    "money_laundering": ("GoPlus: money laundering", "medium", "money_laundering"),
    "blackmail_activities": ("GoPlus: blackmail activities", "medium", "extortion"),
    "financial_crime": ("GoPlus: financial crime", "medium", None),
    "darkweb_transactions": ("GoPlus: dark-web transactions", "medium", None),
    "fake_kyc": ("GoPlus: fake KYC", "medium", None),
    "malicious_mining_activities": ("GoPlus: malicious mining activities", "medium", None),
    "honeypot_related_address": ("GoPlus: honeypot-related address", "medium", None),
    "fake_token": ("GoPlus: fake token", "medium", None),
    "fake_standard_interface": ("GoPlus: fake standard interface", "medium", None),
    "mixer": ("GoPlus: mixer usage", "low", "mixer"),
    "gas_abuse": ("GoPlus: gas abuse", "low", None),
    "reinit": ("GoPlus: re-initialisable contract", "low", None),
    "blacklist_doubt": ("GoPlus: blacklist doubt (unconfirmed)", "low", None),
    "sanctioned": ("GoPlus reports 'sanctioned' (not authoritative)", "info", None),
}
_NON_FLAGS = frozenset({"data_source", "contract_address", "number_of_malicious_contracts_created"})
#: token_security flags that are findings; the controllable-contract features stay attributes
CONTRACT_RISKS: dict[str, tuple[str, str]] = {
    "is_honeypot": ("GoPlus: token is a honeypot (cannot be sold)", "medium"),
    "honeypot_with_same_creator": ("GoPlus: creator deployed other honeypots", "medium"),
    "cannot_sell_all": ("GoPlus: holders cannot sell all tokens", "medium"),
    "is_airdrop_scam": ("GoPlus: airdrop scam", "medium"),
    "fake_token": ("GoPlus: fake token", "medium"),
    "cannot_buy": ("GoPlus: token cannot be bought", "low"),
    "hidden_owner": ("GoPlus: hidden owner", "low"),
    "can_take_back_ownership": ("GoPlus: ownership can be taken back", "low"),
    "selfdestruct": ("GoPlus: contract can self-destruct", "low"),
}
CONTRACT_FEATURES = (
    "is_open_source", "is_proxy", "is_mintable", "owner_change_balance", "external_call", "transfer_pausable", "is_blacklisted",
    "is_whitelisted", "slippage_modifiable", "personal_slippage_modifiable", "trading_cooldown", "is_anti_whale", "anti_whale_modifiable",
    "is_in_dex", "trust_list",
)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_OPAQUE_RE = re.compile(r"[A-Za-z0-9_\-]{16,}")
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$|^T[1-9A-HJ-NP-Za-km-z]{33}$")


def _setting(default: Any, description: str) -> Any:
    return SettingSpec(default, description) if SettingSpec is not None else default


# ------------------------------------------------------------------ parsing
def cast_flag(value: Any) -> bool | None:
    """GoPlus flag -> True/False/None: '1'/1/true -> True, '0'/0/false -> False, ''/'-1'/junk -> None."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return True if value == 1 else (False if value == 0 else None)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("1", "true", "yes"):
            return True
        if text in ("0", "false", "no"):
            return False
    return None


def _to_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"\s*-?\d+\s*", value):
        return int(value)
    return None


def _to_float(value: Any) -> float | None:
    if isinstance(value, bool) or value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def envelope(doc: Any) -> tuple[dict[str, Any] | None, str]:
    """{'code': 1, 'message': 'ok', 'result': {...}} -> (result, '') or (None, reason) (cond 3)."""
    if not isinstance(doc, dict):
        return None, "GoPlus answered an unexpected JSON type: could not verify"
    if _to_int(doc.get("code")) != 1:
        message = safe_plain(doc.get("message"), 120)
        return None, f"GoPlus code {safe_plain(doc.get('code'), 12)}" + (f" ({message})" if message else "") + ": could not verify"
    result = doc.get("result")
    if not isinstance(result, dict):
        return None, "GoPlus answer has no result object: could not verify"
    return result, ""


def parse_address_security(doc: Any) -> dict[str, Any]:
    """address_security answer -> {'status': 'found'|'empty'|'not_evaluated'|'error', 'flags', 'positive',
    'data_sources', 'is_contract', 'malicious_contracts', 'reason'} (cond 1, 3, 4)."""
    out: dict[str, Any] = {"status": "error", "flags": {}, "positive": [], "data_sources": [], "is_contract": None,
                           "malicious_contracts": None, "reason": ""}
    result, reason = envelope(doc)
    if result is None:
        out["reason"] = reason
        return out
    contract = result.get("contract_address")
    if isinstance(contract, str) and contract.strip() == "-1":
        out["status"] = "not_evaluated"
        out["reason"] = "GoPlus did not evaluate the address on this chain (contract_address -1): not a clean answer"
        return out
    out["is_contract"] = cast_flag(contract)
    sources = result.get("data_source")
    if isinstance(sources, str):
        out["data_sources"] = [safe_plain(s, 60) for s in sources.split(",") if s.strip()]
    out["malicious_contracts"] = _to_int(result.get("number_of_malicious_contracts_created"))
    for name, value in result.items():
        if not isinstance(name, str) or name in _NON_FLAGS or not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", name):
            continue
        flag = cast_flag(value)
        if flag is None:
            continue
        out["flags"][name] = flag
        if flag:
            out["positive"].append(name)
    out["status"] = "found" if (out["positive"] or out["malicious_contracts"]) else "empty"
    return out


def parse_token_security(doc: Any, contract: str) -> dict[str, Any]:
    """token_security answer keyed by the lowercase contract (cond 1). A non-token answers empty name/symbol
    and holder_count '0' (live 2026-11-26) -> 'not_applicable' (no row)."""
    out: dict[str, Any] = {"status": "error", "facts": {}, "risks": [], "reason": ""}
    result, reason = envelope(doc)
    if result is None:
        out["reason"] = reason
        return out
    record = result.get(str(contract or "").lower())
    if record is None and len(result) == 1:
        record = next(iter(result.values()))
    if not isinstance(record, dict):
        out["status"] = "not_applicable"
        return out
    name = safe_plain(record.get("token_name"), 80) or None
    symbol = safe_plain(record.get("token_symbol"), 30) or None
    holders = _to_int(record.get("holder_count"))
    if not name and not symbol and not holders:
        out["status"] = "not_applicable"
        return out
    facts: dict[str, Any] = {"name": name, "symbol": symbol, "holders": holders}
    for tax in ("buy_tax", "sell_tax", "transfer_tax"):
        facts[tax] = _to_float(record.get(tax))
    for field, label in (("owner_address", "owner"), ("creator_address", "creator")):
        value = record.get(field)
        if isinstance(value, str) and _ADDRESS_RE.match(value):
            facts[label] = value.lower() if value.startswith("0x") else value
    cex = record.get("is_in_cex")
    if isinstance(cex, dict) and isinstance(cex.get("cex_list"), list):
        facts["cex_list"] = [safe_plain(x, 40) for x in cex["cex_list"] if isinstance(x, str)][:20]
    holders_list = record.get("holders") if isinstance(record.get("holders"), list) else []
    percents = [p for p in (_to_float(h.get("percent")) for h in holders_list[:10] if isinstance(h, dict)) if p is not None]
    if percents:
        facts["top_holders_percent"] = round(sum(percents) * 100, 2)
    features = {f: cast_flag(record.get(f)) for f in CONTRACT_FEATURES if cast_flag(record.get(f)) is not None}
    facts["trusted_listing"] = features.pop("trust_list", None)
    facts["features"] = features
    out["facts"] = {k: v for k, v in facts.items() if v not in (None, [], {})}
    for flag, (title, severity) in CONTRACT_RISKS.items():
        if cast_flag(record.get(flag)):
            out["risks"].append({"flag": flag, "title": title, "severity": severity})
    for tax in ("buy_tax", "sell_tax"):
        value = facts.get(tax)
        if value is not None and value >= 0.5:
            out["risks"].append({"flag": tax, "title": f"GoPlus: {tax.replace('_', ' ')} of at least 50%", "severity": "medium"})
    out["status"] = "found" if out["risks"] else "empty"
    return out


def parse_phishing_site(doc: Any) -> dict[str, Any]:
    """phishing_site answer: an integer 0/1 here (unlike the string flags elsewhere) (cond 1)."""
    out: dict[str, Any] = {"status": "error", "flagged": None, "contracts": 0, "reason": ""}
    result, reason = envelope(doc)
    if result is None:
        out["reason"] = reason
        return out
    flag = cast_flag(result.get("phishing_site"))
    if flag is None:
        out["reason"] = "GoPlus phishing_site answer has no 0/1 flag: could not verify"
        return out
    contracts = result.get("website_contract_security")
    out.update(flagged=flag, contracts=len(contracts) if isinstance(contracts, list) else 0, status="found" if flag else "empty")
    return out


def parse_honeypot_is(doc: Any, http_status: int = 200) -> dict[str, Any]:
    """Honeypot.is /v2/IsHoneypot answer (kept for cond 5; not queried while the tier is 'unknown').
    404 {'code':404,'error':'No pairs found'} for a wallet or a malformed address -> 'not_applicable';
    simulationSuccess false or no honeypotResult -> 'error' (could not simulate, not clean)."""
    out: dict[str, Any] = {"status": "error", "is_honeypot": None, "risk": None, "buy_tax": None, "sell_tax": None, "reason": ""}
    if http_status == 404 and isinstance(doc, dict) and "no pairs" in str(doc.get("error", "")).lower():
        out["status"] = "not_applicable"
        return out
    if not isinstance(doc, dict) or (doc.get("error") and not doc.get("token")):
        out["reason"] = "Honeypot.is answered an error or an unexpected body: could not verify"
        return out
    summary = doc.get("summary") if isinstance(doc.get("summary"), dict) else {}
    sim = doc.get("simulationResult") if isinstance(doc.get("simulationResult"), dict) else {}
    out.update(risk=safe_plain(summary.get("risk"), 30) or None, buy_tax=_to_float(sim.get("buyTax")), sell_tax=_to_float(sim.get("sellTax")))
    if cast_flag(doc.get("simulationSuccess")) is False:
        out["reason"] = "Honeypot.is could not simulate a trade: could not verify"
        return out
    result = doc.get("honeypotResult") if isinstance(doc.get("honeypotResult"), dict) else {}
    out["is_honeypot"] = cast_flag(result.get("isHoneypot"))
    if out["is_honeypot"] is None:
        out["reason"] = "Honeypot.is answer has no honeypotResult: could not verify"
        return out
    out["status"] = "found" if out["is_honeypot"] else "empty"
    return out


def honeypot_allowed(registry: Any = None, declared: tuple[str, ...] = ()) -> bool:
    """cond 5: Honeypot.is only when its registry review records tier community or higher AND the module
    declares its source (an unknown-tier source would also take the module out of the default set)."""
    if HONEYPOT_SOURCE not in declared:
        return False
    try:
        if registry is None:
            from v3lum.core import providers

            registry = providers.registry()
        prov = registry.get("honeypot_is")
    except Exception:  # noqa: BLE001 - fail closed
        return False
    return prov is not None and str(getattr(prov, "tier", "")) in ("community", "trusted")


# ------------------------------------------------------------------ URL minimisation (cond 2)
def phishing_url(url: str, *, opt_in: bool = False) -> dict[str, Any] | None:
    """The URL sent to phishing_site: query string, fragment and userinfo removed unless the analyst opted in
    for this URL; a path holding an e-mail (also %40) or an opaque >= 16-character letters+digits token is cut
    to '/' (per-recipient tokens, A7). Returns {'url', 'removed'}; None for a non-http(s) value."""
    text = str(url or "").strip()
    if opt_in:
        return {"url": text, "removed": []}
    if "://" not in text:
        text = "http://" + text
    try:
        parts = urlsplit(text)
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host:
        return None
    removed = []
    if parts.username or parts.password:
        removed.append("userinfo")
    if parts.query:
        removed.append("query")
    if parts.fragment:
        removed.append("fragment")
    path = parts.path or "/"
    if _EMAIL_RE.search(path) or "%40" in path.lower() or any(
        re.search(r"\d", tok) and re.search(r"[A-Za-z]", tok) for tok in _OPAQUE_RE.findall(path)
    ):
        removed.append("path")
        path = "/"
    netloc = host + (f":{port}" if port else "")
    return {"url": urlunsplit((parts.scheme.lower(), netloc, path, "", "")), "removed": removed}


def _norm(value: Any) -> str:
    return str(value or "").strip().rstrip("/").lower()


@register
class GoplusSecurity(Module):
    name = "goplus_security"
    title = "GoPlus address, token and phishing-site security"
    description = (
        "Malicious-address flags (EVM, TRON), token-contract risks and crypto phishing-site checks from GoPlus Security, "
        "each flag a named finding with its reporting source; phishing_site only for URLs/domains with crypto context."
    )
    category = "crypto"
    accepts = {T.ETH, T.CRYPTO, T.DOMAIN, T.URL}
    tags = {"reputation"}
    reference = "https://docs.gopluslabs.io/reference/api-overview"
    notice = (
        "GoPlus terms could not be verified (key-terms): under the corporate profile it runs only after legal records the "
        "terms or a business key plan. GoPlus labels are third-party claims (one consensus vote); 'sanctioned' is not "
        "authoritative. Honeypot.is is not queried (registry tier unknown)."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # GoPlus receives the address or the (stripped) URL
    provider = "gopluslabs"
    sources = (SOURCE_ADDRESS, SOURCE_TOKEN, SOURCE_PHISHING)
    hosts = ("api.gopluslabs.io",)
    access_model = "free_noauth_limited"
    optional_keys = (KEY,)
    max_requests = 6  # key exchange + up to 3 chains + token_security (+ Honeypot.is once reviewed)
    expected_latency = 1.5
    timeout = 20.0
    min_interval = 2.0
    daily_quota = 500
    cache_ttl = 21600
    default_enabled = True
    settings = {
        "goplus_security_evm_chains": _setting(["1"], "GoPlus chain ids queried for an EVM address (1 Ethereum, 56 BSC, 137 Polygon, 8453 Base...; at most 3)"),
        "goplus_security_crypto_context": _setting([], "URLs/domains the analyst marks as crypto context (wallet, token or drainer), so phishing_site may be queried for them"),
        "goplus_security_full_url": _setting([], "URLs the analyst opts in to send to phishing_site in full (query, fragment and userinfo kept)"),
    }

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(T.ETH, EF_WALLET)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.ETH:
            return True
        if entity.type is T.CRYPTO:
            info = crypto_address_info(str(entity.value).strip())
            return info is not None and info.chain == "tron"
        return self.crypto_context(entity, ctx)

    # ------------------------------------------------------------------ crypto context (cond 1)
    @staticmethod
    def crypto_context(entity: Entity, ctx: Any) -> bool:
        """True when the case gives this URL/domain crypto context: the analyst listed it, it was found from a
        crypto address (provenance), or its case node carries a wallet/token/drainer/crypto_scam tag or links
        to a crypto address."""
        listed = {_norm(v) for v in (ctx.setting("goplus_security_crypto_context") or []) if isinstance(v, str)}
        if _norm(entity.value) in listed:
            return True
        for step in ctx.provenance or ():
            parent = str(step[0]) if step else ""
            if parent.split(":", 1)[0] in {t.value for t in CRYPTO_TYPES}:
                return True
        graph = getattr(getattr(getattr(ctx, "runtime", None), "policy_context", None), "graph", None)
        node = graph.get(entity) if graph is not None else None
        if node is None:
            return False
        if node.tagged(*CRYPTO_CONTEXT_TAGS):
            return True
        return any(n.entity.type in CRYPTO_TYPES for n in graph.neighbors(node.entity.key, direction="both"))

    # ------------------------------------------------------------------ auth (optional key, cond 5)
    @staticmethod
    def _auth_headers(ctx: Any) -> dict[str, str]:
        key = ctx.key(KEY)
        if not key:
            return {}
        app_key, _, secret = key.partition(":")
        if not app_key or not secret:
            raise ConfigError("goplus key must be 'app_key:app_secret' (V3LUM_GOPLUS_KEY)")
        now = int(ctx.now().timestamp())
        sign = hashlib.sha1(f"{app_key}{now}{secret}".encode(), usedforsecurity=False).hexdigest()
        doc = ctx.http.post_json(AUTH_URL, json_body={"app_key": app_key, "time": now, "sign": sign}, source=SOURCE_ADDRESS, allow_redirects=False)
        result, reason = envelope(doc)
        access = result.get("access_token") if result else None
        if not isinstance(access, str) or not access.strip():
            raise ConfigError(f"GoPlus key exchange failed ({reason or 'no access_token'})")
        register_secret(access, "goplus access token")
        return {"Authorization": access}

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        allowed = ctx.allowed_sources
        if entity.type in (T.DOMAIN, T.URL):
            if not self.crypto_context(entity, ctx):
                return res.mark("skipped", "phishing_site only for URLs/domains with crypto context in the case", reason_code="not_applicable")
            if SOURCE_PHISHING not in allowed:
                return res.mark("skipped", "GoPlus phishing_site not allowed by the licence profile (key-terms)", reason_code="licence")
            return self._phishing(res, entity, ctx, self._auth_headers(ctx))
        if SOURCE_ADDRESS not in allowed:
            return res.mark("skipped", "GoPlus address_security not allowed by the licence profile (key-terms)", reason_code="licence")
        value = str(entity.value).strip()
        info = crypto_address_info(value)
        if entity.type is T.CRYPTO:
            if info is None or info.chain != "tron":
                return res.mark("skipped", "GoPlus covers EVM and TRON addresses only", reason_code="not_applicable")
            chains = ["tron"]
        else:
            if info is None or info.chain != "eth":
                return res.mark("skipped", "not a valid EVM address (core validators): never sent", reason_code="not_applicable")
            value = value.lower()
            chains = self._evm_chains(ctx)
        return self._address(res, value, chains, ctx, self._auth_headers(ctx))

    @staticmethod
    def _evm_chains(ctx: Any) -> list[str]:
        wanted = ctx.setting("goplus_security_evm_chains") or ["1"]
        chains = [str(c).strip() for c in (wanted if isinstance(wanted, list) else [wanted]) if str(c).strip() in EVM_CHAIN_IDS]
        return list(dict.fromkeys(chains))[:MAX_CHAINS] or ["1"]

    # ------------------------------------------------------------------ addresses
    def _address(self, res: ModuleResult, address: str, chains: list[str], ctx: Any, headers: dict[str, str]) -> ModuleResult:
        flags_by_chain: dict[str, dict[str, bool]] = {}
        sources: list[str] = []
        not_evaluated: list[str] = []
        contract_chain = None
        positives = 0
        for chain in chains:
            doc = ctx.http.get_json(ADDRESS_URL.format(address=address), params={"chain_id": chain}, headers=headers, source=SOURCE_ADDRESS)
            parsed = parse_address_security(doc)
            if parsed["status"] == "error":
                return res.mark("error", parsed["reason"])
            if parsed["status"] == "not_evaluated":
                not_evaluated.append(chain)
                continue
            flags_by_chain[chain] = parsed["flags"]
            sources.extend(s for s in parsed["data_sources"] if s not in sources)
            if parsed["is_contract"] and chain != "tron" and contract_chain is None:
                contract_chain = chain  # TRON contract detection is unreliable (USDT-TRC20 answers '0')
            for flag in parsed["positive"]:
                positives += 1
                self._flag_finding(res, flag, chain, parsed["data_sources"])
            if parsed["malicious_contracts"]:
                positives += 1
                res.finding(
                    "GoPlus: creator of malicious contracts",
                    "medium",
                    f"GoPlus counts {parsed['malicious_contracts']} malicious contract(s) created by this address (chain {chain}).",
                    confidence="possible",
                    criterion="GoPlus number_of_malicious_contracts_created > 0",
                    data={"chain_id": chain, "count": parsed["malicious_contracts"], "data_sources": parsed["data_sources"]},
                    source=SOURCE_ADDRESS,
                    key=chain,
                )
            if parsed["flags"].get("sanctioned"):
                res.attr("sanctioned", True)  # labelled 'not authoritative' by g09_sanctions_non_authoritative (P205 cond 6)
            if chain != "tron" and parsed["is_contract"] is not None:
                res.attr("is_contract", parsed["is_contract"])
        if not flags_by_chain:
            return res.mark("error", f"GoPlus did not evaluate this address on chain(s) {', '.join(not_evaluated)} (contract_address -1): could not verify")
        res.attr("chain", "tron" if chains == ["tron"] else "ethereum" if chains == ["1"] else "evm")
        res.attr("goplus_flags", flags_by_chain)
        res.attr("goplus_data_sources", sources)
        if contract_chain is not None and SOURCE_TOKEN in ctx.allowed_sources:
            positives += self._contract(res, address, contract_chain, ctx, headers)
        res.raw = {"flags": flags_by_chain, "data_sources": sources, "not_evaluated": not_evaluated}
        if not_evaluated:
            res.raw["note"] = f"not evaluated on chain(s) {', '.join(not_evaluated)} (contract_address -1): could not verify there"
        return res if positives else res.mark("empty")

    @staticmethod
    def _flag_finding(res: ModuleResult, flag: str, chain: str, data_sources: list[str]) -> None:
        title, severity, tag = ADDRESS_FLAGS.get(flag, (f"GoPlus: {flag.replace('_', ' ')}", "low", None))
        by = ", ".join(data_sources) or "not named"
        if flag == "sanctioned":
            res.finding(
                title,
                "info",
                f"GoPlus marks the address 'sanctioned' (chain {chain}; data source: {by}). Not a sanctions determination: "
                "the sanctions label comes only from the OFAC lists and Chainalysis checks (crypto_sanctions_offline/onchain).",
                confidence="possible",
                data={"flag": flag, "chain_id": chain, "data_sources": data_sources},
                source=SOURCE_ADDRESS,
                key=f"{chain}:{flag}",
            )
            return
        doubt = flag.endswith("_doubt")
        res.finding(
            title,
            severity,
            f"GoPlus address_security flag '{flag}' is set (chain {chain}; data source: {by}). A third-party label: "
            "one consensus vote, corroborate before acting.",
            confidence="possible" if doubt or not data_sources else "probable",
            criterion=f"GoPlus address_security '{flag}' = 1" + (" (doubt flag: unconfirmed listing)" if doubt else f" reported by {by}"),
            data={"flag": flag, "chain_id": chain, "data_sources": data_sources},
            tags=[tag] if tag else [],
            source=SOURCE_ADDRESS,
            key=f"{chain}:{flag}",
        )

    def _contract(self, res: ModuleResult, address: str, chain: str, ctx: Any, headers: dict[str, str]) -> int:
        doc = ctx.http.get_json(TOKEN_URL.format(chain_id=chain), params={"contract_addresses": address}, headers=headers, source=SOURCE_TOKEN)
        parsed = parse_token_security(doc, address)
        if parsed["status"] == "error":
            res.source_status(SOURCE_TOKEN, Status.ERROR, reason_code="error", reason=parsed["reason"])
            return 0
        if parsed["status"] == "not_applicable":
            return 0
        res.attr("goplus_contract", {"chain_id": chain, **parsed["facts"]})
        for risk in parsed["risks"]:
            res.finding(
                risk["title"],
                risk["severity"],
                f"GoPlus token_security on chain {chain}: {risk['title'].removeprefix('GoPlus: ')}. Third-party analysis of the "
                "contract: one consensus vote.",
                confidence="probable",
                criterion=f"GoPlus token_security '{risk['flag']}' set for the contract",
                data={"flag": risk["flag"], "chain_id": chain},
                tags=["crypto_scam"] if risk["severity"] == "medium" else [],
                source=SOURCE_TOKEN,
                key=f"{chain}:contract:{risk['flag']}",
            )
        return len(parsed["risks"])

    # ------------------------------------------------------------------ phishing sites
    def _phishing(self, res: ModuleResult, entity: Entity, ctx: Any, headers: dict[str, str]) -> ModuleResult:
        opted = {_norm(v) for v in (ctx.setting("goplus_security_full_url") or []) if isinstance(v, str)}
        if entity.type is T.DOMAIN:
            sent = {"url": str(entity.value), "removed": []}
        else:
            sent = phishing_url(str(entity.value), opt_in=_norm(entity.value) in opted)
            if sent is None:
                return res.mark("skipped", "not an http(s) URL", reason_code="not_applicable")
        doc = ctx.http.get_json(PHISHING_URL, params={"url": sent["url"]}, headers=headers, source=SOURCE_PHISHING)
        parsed = parse_phishing_site(doc)
        if parsed["status"] == "error":
            return res.mark("error", parsed["reason"])
        res.attr("goplus_phishing_site", {"flagged": parsed["flagged"], "url_sent": sent["url"], "removed": sent["removed"],
                                          "website_contracts": parsed["contracts"]})
        res.raw = {"flagged": parsed["flagged"], "removed": sent["removed"]}
        if not parsed["flagged"]:
            return res.mark("empty")
        res.finding(
            "GoPlus: crypto phishing site",
            "medium",
            "GoPlus phishing_site flags this site (crypto phishing or wallet drainer). A third-party label: one consensus "
            "vote. Never visit it from the corporate egress.",
            confidence="probable",
            criterion="GoPlus phishing_site = 1 for the (stripped) URL",
            data={"removed": sent["removed"]},
            tags=["phishing", "crypto_scam"],
            source=SOURCE_PHISHING,
        )
        return res


__all__ = [
    "ADDRESS_FLAGS",
    "EF_WALLET",
    "GoplusSecurity",
    "cast_flag",
    "envelope",
    "honeypot_allowed",
    "parse_address_security",
    "parse_honeypot_is",
    "parse_phishing_site",
    "parse_token_security",
    "phishing_url",
]
