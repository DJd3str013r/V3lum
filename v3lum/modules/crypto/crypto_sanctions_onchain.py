"""On-chain sanctions and issuer-freeze checks (P205, the third-party half of crypto_sanctions).

Also the ONE EVM JSON-RPC helper of V3LUM (:class:`JsonRpc`, :func:`eth_call_request`), shared with
evm_explorers (P212); the TronGrid client is tron_explorer's (P207).

Final conditions (P205):

* cond 2 - disclosure ``third_party``: the Chainalysis sanctions oracle ``isSanctioned(address)``
  (selector 0xdf592f7d), USDT ``isBlackListed`` (0xe47d6060) and USDC ``isBlacklisted`` (0xfe575a87) as
  ``eth_call`` on the configurable ``eth_rpc`` setting (default PublicNode; env ``V3LUM_ETH_RPC``),
  plus TronGrid ``triggerconstantcontract`` on the USDT-TRC20 contract, all in the first build. The
  three EVM calls and an ``eth_chainId`` guard travel in one JSON-RPC batch (one request).
* cond 3 - per-chain oracle/contract addresses live in ``v3lum/data/crypto_sanctions_onchain/
  contracts.json`` with their source; selectors are recomputed from the signatures with the core
  pure-Python Keccak-256 (P217) and must match; ABI encoding is unit-tested.
* cond 4 - a result other than 0x..00/0x..01, a JSON-RPC error (also inside HTTP 200, provider marker
  ``crypto_sanctions_onchain_jsonrpc_error``) or a timeout is ERROR 'could not verify', never 'not
  sanctioned'. Chainalysis REST (key ``chainalysis``) is the second check and covers non-EVM chains;
  its 403 HTML 'IP not on the Chainalysis Allowed IPs List' is BLOCKED (marker
  ``chainalysis_ip_allowlist``) and without a key the check is NEEDS_KEY.
* cond 5 - a Chainalysis oracle/REST hit: tag ``sanctions``, CRITICAL, 'address on the OFAC SDN list (US)'
  (the oracle mirrors OFAC SDN designations; the REST identification names the entity and programme)
  with 'stop transactions and escalate to compliance'; a USDT/USDC issuer blacklist hit: tag
  ``issuer_freeze``, HIGH, 'frozen by issuer (Tether/Circle)', never 'sanctioned'.
* cond 6 - a list match is not a legal determination: escalate to compliance/legal, no automated adverse
  action against natural persons (LGPD art. 20); misses read 'not listed by the Chainalysis sanctions
  oracle as of <date>' - never 'not sanctioned'.
* cond 7 - terms: oracle and stablecoin calls 'open' (publicnode.ethereum_rpc), TronGrid and Chainalysis
  REST 'key-terms' (module = key-terms); tiers PublicNode, TronGrid and Chainalysis trusted. Under the
  corporate profile the policy gate narrows ``ctx.allowed_sources`` and only allowed sources are queried.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote, urlsplit

from v3lum.config import SettingSpec
from v3lum.core import redact
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, HttpError, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, Module, register
from v3lum.core.validators import crypto_address_info, keccak256
from v3lum.modules.crypto.tron_explorer import TronGrid, abi_address_word, decode_abi_bool, is_tron_address, parse_constant_bool

SOURCE_RPC = "publicnode.ethereum_rpc"
SOURCE_TRONGRID = "trongrid.api"
SOURCE_CHAINALYSIS = "chainalysis.sanctions_api"
DEFAULT_ETH_RPC = "https://ethereum-rpc.publicnode.com"
CHAINALYSIS_URL = "https://public.chainalysis.com/api/v1/address/{address}"
CONTRACTS_DATA = "crypto_sanctions_onchain/contracts.json"
KEY_CHAINALYSIS = "chainalysis"
KEY_TRONGRID = "trongrid"
SANCTIONS_TITLE = "Address on the OFAC SDN list (US)"
FREEZE_TITLE = "Frozen by a stablecoin issuer (not a sanctions determination)"
COMPLIANCE_NOTE = (
    "A list match is not a legal determination: stop transactions and escalate to compliance/legal; take no automated "
    "adverse action against natural persons (LGPD art. 20)."
)
OFAC_SEARCH = "https://sanctionssearch.ofac.treas.gov/"


# --------------------------------------------------------------------------------------
# ABI and JSON-RPC (shared with evm_explorers, P212)
# --------------------------------------------------------------------------------------


def function_selector(signature: str) -> str:
    """'isSanctioned(address)' -> 'df592f7d' (Keccak-256 of the signature, first 4 bytes; core P217 Keccak)."""
    return keccak256(signature.encode("ascii"))[:4].hex()


def eth_call_request(contract: str, selector: str, address: str, request_id: int, block: str = "latest") -> dict[str, Any]:
    """The JSON-RPC ``eth_call`` object for ``selector(address)``."""
    return {"jsonrpc": "2.0", "id": request_id, "method": "eth_call",
            "params": [{"to": contract, "data": "0x" + selector + abi_address_word(address)}, block]}


def rpc_error(obj: Any) -> str | None:
    """'JSON-RPC <code> <message>' for an error object, else None."""
    if isinstance(obj, dict) and obj.get("error") is not None:
        err = obj["error"] if isinstance(obj["error"], dict) else {"message": obj["error"]}
        return f"JSON-RPC error {err.get('code', '?')}: {str(err.get('message', ''))[:80]}"
    return None


def parse_bool_response(obj: Any) -> tuple[bool | None, str]:
    """One eth_call response -> (value, reason): exactly 0/1 words only; an error object or any other
    result is (None, why) = could not verify (P205 cond 4)."""
    if not isinstance(obj, dict):
        return None, "JSON-RPC response is not an object"
    err = rpc_error(obj)
    if err:
        return None, err
    value = decode_abi_bool(obj.get("result"))
    if value is None:
        return None, f"unexpected eth_call result {str(obj.get('result'))[:24]!r}"
    return value, ""


def parse_chain_id(obj: Any) -> int | None:
    """The eth_chainId answer as an int (None for an error or a non-hex result)."""
    if not isinstance(obj, dict) or rpc_error(obj) or not isinstance(obj.get("result"), str):
        return None
    try:
        return int(obj["result"], 16)
    except ValueError:
        return None


class JsonRpc:
    """A JSON-RPC client over ``ctx.http`` (POST, read-only methods only: eth_chainId, eth_call...).

    Requests name the registry source; answers pass the core classifier (provider markers turn an error
    object inside HTTP 200 into ERROR); POST answers are cached only when ``ttl`` is given (read calls
    against current chain state)."""

    READ_ONLY = frozenset({"eth_chainId", "eth_call", "eth_getCode", "eth_getBalance", "eth_blockNumber", "eth_getTransactionCount"})

    def __init__(self, ctx: Any, url: str, *, source: str, ttl: int | None = None) -> None:
        self.ctx = ctx
        self.url = url
        self.source = source
        self.ttl = ttl

    def batch(self, calls: list[dict[str, Any]]) -> dict[Any, Any]:
        """Send a batch; returns {id: response object}. Raises the core HTTP exceptions; a body that is
        not a JSON-RPC answer raises HttpError (could not verify)."""
        for call in calls:
            if call.get("method") not in self.READ_ONLY:
                raise ValueError(f"JSON-RPC method {call.get('method')!r} is not a read-only method")
        kw: dict[str, Any] = {"source": self.source, "json_body": calls, "headers": {"Accept": "application/json"}}
        if self.ttl is not None:
            kw["ttl"] = self.ttl
        resp = self.ctx.http.post(self.url, **kw)
        self.ctx.http.check(resp)
        try:
            doc = json.loads(resp.content.decode("utf-8", errors="replace"))
        except (ValueError, RecursionError):
            raise HttpError("JSON-RPC answer is not JSON: could not verify", resp.status, resp.url, b"") from None
        if isinstance(doc, dict):
            doc = [doc]
        if not isinstance(doc, list):
            raise HttpError("JSON-RPC answer is not a batch: could not verify", resp.status, resp.url, b"")
        out: dict[Any, Any] = {}
        for item in doc:
            if isinstance(item, dict):
                out[item.get("id")] = item
        return out


# --------------------------------------------------------------------------------------
# per-chain contract data (cond 3)
# --------------------------------------------------------------------------------------


def load_contracts(doc: Any) -> dict[str, Any]:
    """Validate the bundled contract table: every selector must equal Keccak(signature)[:4]. Raises
    ValueError on a mismatch or a malformed table (the module then fails closed: could not verify)."""
    if not isinstance(doc, dict) or not isinstance(doc.get("evm"), dict):
        raise ValueError("contracts.json: no 'evm' table")
    entries = []
    for chain, spec in doc["evm"].items():
        if not isinstance(spec, dict) or not isinstance(spec.get("chain_id"), int) or not isinstance(spec.get("contracts"), dict):
            raise ValueError(f"contracts.json: malformed chain {chain!r}")
        entries.extend(spec["contracts"].values())
    entries.extend((doc.get("tron") or {}).values())
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("source"):
            raise ValueError("contracts.json: every contract needs an address, a signature, a selector and a source")
        if function_selector(str(entry.get("signature"))) != entry.get("selector"):
            raise ValueError(f"contracts.json: selector of {entry.get('signature')!r} does not match its Keccak-256")
    return doc


def _rpc_url_problem(url: str, hosts: tuple[str, ...]) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return "eth_rpc is not a URL"
    if parts.scheme != "https" or not parts.hostname:
        return "eth_rpc must be an https URL"
    if parts.hostname.lower() not in hosts:
        return (f"eth_rpc host {parts.hostname!r} has no provider entry: every RPC operator needs its own registry "
                "fragment (tier, terms) - use the default PublicNode RPC or add a provider (backlog p1-G09-1)")
    return ""


def _could_not_verify(exc: Exception) -> tuple[Status, str]:
    if isinstance(exc, RateLimited):
        return Status.RATE_LIMITED, "rate_limited"
    if isinstance(exc, QuotaExceeded):
        return Status.QUOTA, "quota"
    if isinstance(exc, Blocked):
        code = str(getattr(exc, "reason_code", "") or "")
        return Status.BLOCKED, code if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge"
    if isinstance(exc, AuthRequired):
        return Status.NEEDS_KEY, "needs_key"
    return Status.ERROR, "timeout" if "timed out" in str(exc).lower() or "timeout" in str(exc).lower() else "error"


@register
class CryptoSanctionsOnchain(Module):
    name = "crypto_sanctions_onchain"
    title = "Crypto sanctions and issuer freezes (on-chain oracle, USDT/USDC, Chainalysis)"
    description = (
        "Sanctions and stablecoin-freeze checks for a wallet: the Chainalysis sanctions oracle and the USDT/USDC "
        "blacklists by eth_call (PublicNode RPC), the USDT-TRC20 blacklist through TronGrid, and Chainalysis REST "
        "(any chain) with a key. Anything but a 0/1 answer is 'could not verify', never 'not sanctioned'."
    )
    category = "crypto"
    accepts = {T.ETH, T.BTC, T.CRYPTO, T.XMR}
    produces = frozenset()
    tags = {"free"}
    reference = "https://go.chainalysis.com/chainalysis-oracle-docs.html"
    notice = (
        "A sanctions-list match is not a legal determination: stop transactions, escalate to compliance/legal and take no "
        "automated adverse action against natural persons (LGPD art. 20). Issuer freezes (Tether/Circle) are not "
        "sanctions. TronGrid and Chainalysis REST are key-terms sources (company accounts, plans recorded in key_plans); "
        "the RPC is the 'eth_rpc' setting (default PublicNode)."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "publicnode"
    sources = (SOURCE_RPC, SOURCE_TRONGRID, SOURCE_CHAINALYSIS)
    hosts = ("ethereum-rpc.publicnode.com", "api.trongrid.io", "public.chainalysis.com")
    access_model = "free_noauth_limited"
    optional_keys = (KEY_TRONGRID, KEY_CHAINALYSIS)
    max_requests = 2
    expected_latency = 0.5
    timeout = 45.0
    min_interval = 1.0
    daily_quota = 2000
    cache_ttl = 3600
    default_enabled = True
    settings = {
        "eth_rpc": SettingSpec(
            DEFAULT_ETH_RPC,
            "Ethereum JSON-RPC URL for the sanctions-oracle and USDT/USDC freeze checks (https; the host needs a provider "
            "entry - default PublicNode; env V3LUM_ETH_RPC)",
        ),
    }

    @classmethod
    def health_check(cls) -> HealthCheck:
        # the Ethereum Foundation address: not sanctioned, not frozen (verified live 2026-11-26)
        return HealthCheck(T.ETH, "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae", expect="empty")

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        try:
            contracts = load_contracts(ctx.data.bundled_json(CONTRACTS_DATA))
        except (ValueError, OSError) as exc:
            return res.mark("error", f"per-chain contract table unusable ({str(exc)[:120]}): could not verify")
        allowed = ctx.allowed_sources
        address = str(entity.value).strip()
        checks: dict[str, str] = {}
        failures: list[tuple[str, Status, str, str]] = []  # (check, status, code, reason)
        hits: list[str] = []
        ran = False
        info = crypto_address_info(address)
        evm = entity.type is T.ETH or (info is not None and info.chain == "eth")
        tron = entity.type is T.CRYPTO and is_tron_address(address)
        if evm and SOURCE_RPC in allowed:
            ran = True
            self._evm(ctx, res, address, contracts, checks, failures, hits)
        if tron and SOURCE_TRONGRID in allowed:
            ran = True
            self._tron(ctx, res, address, contracts, checks, failures, hits)
        key = ctx.key(KEY_CHAINALYSIS)
        if SOURCE_CHAINALYSIS in allowed and key:
            ran = True
            self._chainalysis(ctx, res, address, key, checks, failures, hits)
        as_of = ctx.now().date().isoformat()
        if not ran:
            return self._not_run(res, entity, allowed, bool(key), evm, tron)
        res.attr("onchain_checks", checks)
        primary_ran = (evm and SOURCE_RPC in allowed) or (tron and SOURCE_TRONGRID in allowed)
        # Chainalysis REST is the second check when an on-chain path ran: its refusal alone is reported per
        # feed (source_status) while the on-chain answers stand; any other failure is 'could not verify'
        blocking = [f for f in failures if not (primary_ran and f[0] == "chainalysis_rest")]
        if blocking and not hits:
            _check, status, code, _reason = blocking[0]
            detail = "; ".join(f"{c}: {r}" for c, _s, _k, r in blocking)
            return res.mark(status if len(blocking) == 1 else Status.ERROR, f"could not verify ({detail})",
                            reason_code=code if len(blocking) == 1 else ("timeout" if code == "timeout" else "error"))
        if any(c in hits for c in ("chainalysis_oracle", "chainalysis_rest")):
            res.attr("sanctioned", True)
            res.attr("sanctions_status", f"on the OFAC SDN list (US) per Chainalysis, as of {as_of}")
        elif "chainalysis_oracle" in checks or "chainalysis_rest" in checks:
            res.attr("sanctions_status", f"not listed by the Chainalysis sanctions checks as of {as_of}")
        if not hits:
            return res.mark("empty")
        return res

    # ------------------------------------------------------------------ EVM (cond 2-4)
    def _evm(self, ctx: Any, res: ModuleResult, address: str, contracts: dict[str, Any], checks: dict[str, str],
             failures: list[tuple[str, Status, str, str]], hits: list[str]) -> None:
        url = str(ctx.setting("eth_rpc", DEFAULT_ETH_RPC) or DEFAULT_ETH_RPC).strip()
        problem = _rpc_url_problem(url, self.hosts)
        if problem:
            for name in ("chainalysis_oracle", "usdt_freeze", "usdc_freeze"):
                checks[name] = f"could not verify ({problem})"
            failures.append(("eth_rpc", Status.SKIPPED, "config", problem))
            return
        _register_path_secret(url)
        chain = contracts["evm"]["ethereum"]
        table = chain["contracts"]
        calls = [{"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}]
        plan = [("chainalysis_oracle", "chainalysis_oracle"), ("usdt_freeze", "usdt"), ("usdc_freeze", "usdc")]
        for i, (_check, contract) in enumerate(plan, start=2):
            spec = table[contract]
            calls.append(eth_call_request(spec["address"], spec["selector"], address, i))
        try:
            answers = JsonRpc(ctx, url, source=SOURCE_RPC, ttl=self.cache_ttl).batch(calls)
        except (RateLimited, Blocked, QuotaExceeded, AuthRequired, HttpError, NetworkError) as exc:
            status, code = _could_not_verify(exc)
            if status is Status.NEEDS_KEY:  # a keyless public RPC refusing: never 'needs a key'
                status, code = Status.BLOCKED, "challenge"
            for check, _c in plan:
                checks[check] = f"could not verify ({str(exc)[:80]})"
            failures.append(("eth_rpc", status, code, str(exc)[:160]))
            res.source_status(SOURCE_RPC, status, reason_code=code, reason=f"Ethereum RPC: {str(exc)[:160]}")
            return
        chain_id = parse_chain_id(answers.get(1))
        if chain_id != chain["chain_id"]:
            why = f"RPC answered chain {chain_id} - the contract data is for chain {chain['chain_id']}" if chain_id else "eth_chainId failed"
            for check, _c in plan:
                checks[check] = f"could not verify ({why})"
            failures.append(("eth_rpc", Status.ERROR, "error", why))
            return
        for i, (check, contract) in enumerate(plan, start=2):
            value, why = parse_bool_response(answers.get(i))
            spec = table[contract]
            if value is None:
                checks[check] = f"could not verify ({why or 'no answer'})"
                failures.append((check, Status.ERROR, "error", why or "no answer"))
                continue
            if spec["kind"] == "sanctions":
                checks[check] = "listed" if value else "not listed"
                if value:
                    hits.append(check)
                    self._sanctions_finding(res, f"listed by the Chainalysis sanctions oracle on Ethereum ({spec['address']})",
                                            source=SOURCE_RPC, data={"check": "chainalysis_oracle", "contract": spec["address"],
                                                                     "selector": "0x" + spec["selector"]})
            else:
                checks[check] = "frozen" if value else "not frozen"
                if value:
                    hits.append(check)
                    self._freeze_finding(res, spec, check, source=SOURCE_RPC)

    # ------------------------------------------------------------------ TRON (cond 2)
    def _tron(self, ctx: Any, res: ModuleResult, address: str, contracts: dict[str, Any], checks: dict[str, str],
              failures: list[tuple[str, Status, str, str]], hits: list[str]) -> None:
        spec = (contracts.get("tron") or {}).get("usdt_trc20")
        if not isinstance(spec, dict):
            failures.append(("tron_usdt_freeze", Status.ERROR, "error", "no USDT-TRC20 contract data"))
            return
        try:
            doc = TronGrid(ctx, ttl=self.cache_ttl).constant_call(spec["address"], spec["signature"], abi_address_word(address))
        except (RateLimited, Blocked, QuotaExceeded, AuthRequired, HttpError, NetworkError) as exc:
            status, code = _could_not_verify(exc)
            checks["tron_usdt_freeze"] = f"could not verify ({str(exc)[:80]})"
            failures.append(("tron_usdt_freeze", status, code, str(exc)[:160]))
            res.source_status(SOURCE_TRONGRID, status, reason_code=code, reason=f"TronGrid: {str(exc)[:160]}")
            return
        value, why = parse_constant_bool(doc)
        if value is None:
            checks["tron_usdt_freeze"] = f"could not verify ({why})"
            failures.append(("tron_usdt_freeze", Status.ERROR, "error", why))
            return
        checks["tron_usdt_freeze"] = "frozen" if value else "not frozen"
        if value:
            hits.append("tron_usdt_freeze")
            self._freeze_finding(res, spec, "tron_usdt_freeze", source=SOURCE_TRONGRID)

    # ------------------------------------------------------------------ Chainalysis REST (cond 4)
    def _chainalysis(self, ctx: Any, res: ModuleResult, address: str, key: str, checks: dict[str, str],
                     failures: list[tuple[str, Status, str, str]], hits: list[str]) -> None:
        try:
            resp = ctx.http.get(CHAINALYSIS_URL.format(address=quote(address, safe="")), source=SOURCE_CHAINALYSIS,
                                headers={"X-API-Key": key, "Accept": "application/json"})
            ctx.http.check(resp)
        except (RateLimited, Blocked, QuotaExceeded, AuthRequired, HttpError, NetworkError) as exc:
            status, code = _could_not_verify(exc)
            checks["chainalysis_rest"] = f"could not verify ({str(exc)[:80]})"
            failures.append(("chainalysis_rest", status, code, str(exc)[:160]))
            res.source_status(SOURCE_CHAINALYSIS, status, reason_code=code, reason=f"Chainalysis REST: {str(exc)[:160]}")
            return
        idents = parse_identifications(_loads(resp.content))
        if idents is None:
            checks["chainalysis_rest"] = "could not verify (unexpected answer)"
            failures.append(("chainalysis_rest", Status.ERROR, "error", "unexpected Chainalysis REST answer"))
            return
        sanctions = [i for i in idents if str(i.get("category") or "").lower() == "sanctions"]
        res.attr("chainalysis_identifications", idents)
        checks["chainalysis_rest"] = "listed" if sanctions else "not listed"
        if sanctions:
            hits.append("chainalysis_rest")
            names = "; ".join(str(i.get("name") or "?")[:120] for i in sanctions)
            self._sanctions_finding(res, f"Chainalysis identification: {names}", source=SOURCE_CHAINALYSIS,
                                    data={"check": "chainalysis_rest", "identifications": sanctions},
                                    references=[i["url"] for i in sanctions if isinstance(i.get("url"), str) and i["url"].startswith("https://")])

    # ------------------------------------------------------------------ findings (cond 5-6)
    @staticmethod
    def _sanctions_finding(res: ModuleResult, detail: str, *, source: str, data: dict[str, Any], references: list[str] | None = None) -> None:
        res.finding(
            SANCTIONS_TITLE,
            "critical",
            f"Address on the OFAC SDN list (US): {detail}. Stop transactions and escalate to compliance. {COMPLIANCE_NOTE}",
            confidence="confirmed",
            criterion="the Chainalysis sanctions oracle/API answers 'sanctioned' for the exact address (OFAC SDN-derived list)",
            data=data,
            tags=["sanctions"],
            references=references or [OFAC_SEARCH],
            source=source,
            key=str(data.get("check") or ""),
        )

    @staticmethod
    def _freeze_finding(res: ModuleResult, spec: dict[str, Any], check: str, *, source: str) -> None:
        issuer = str(spec.get("issuer") or "issuer")
        res.finding(
            FREEZE_TITLE,
            "high",
            f"Frozen by issuer ({issuer}): the stablecoin contract {spec['address']} blacklists this address. An issuer freeze "
            "is a strong signal of sanctioned or stolen funds but is not a sanctions determination.",
            confidence="confirmed",
            criterion=f"{spec['signature']} on {spec['address']} returns true for the exact address",
            data={"check": check, "issuer": issuer, "contract": spec["address"], "selector": "0x" + spec["selector"]},
            tags=["issuer_freeze"],
            source=source,
            key=check,
        )
        frozen = list(res.attributes.get("issuer_frozen") or [])
        if issuer not in frozen:
            frozen.append(issuer)
        res.attr("issuer_frozen", frozen)

    def _not_run(self, res: ModuleResult, entity: Entity, allowed: frozenset[str], key: bool, evm: bool, tron: bool) -> ModuleResult:
        if (evm and SOURCE_RPC not in allowed) or (tron and SOURCE_TRONGRID not in allowed):
            return res.mark("skipped", "the on-chain source is not allowed by the licence profile (key-terms sources need a "
                                       "business key plan in key_plans)", reason_code="licence")
        if SOURCE_CHAINALYSIS in allowed and not key:
            return res.mark("needs_key", f"{entity.type.value}: no on-chain check exists for this chain (EVM and TRON only); "
                                         "Chainalysis REST needs a key (V3LUM_CHAINALYSIS_KEY) with the team egress IP allow-listed",
                            reason_code="needs_key")
        return res.mark("skipped", "Chainalysis REST is not allowed by the licence profile (key-terms: record key_plans.chainalysis)",
                        reason_code="licence")


def parse_identifications(doc: Any) -> list[dict[str, Any]] | None:
    """{'identifications': [{category, name, description, url}]} (research C0490) -> clean list; None
    when the answer is not that object. Descriptions are cut to 300 characters."""
    if not isinstance(doc, dict) or not isinstance(doc.get("identifications"), list):
        return None
    out = []
    for item in doc["identifications"]:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        out.append({
            "category": str(item.get("category") or "")[:40] or None,
            "name": str(item.get("name") or "")[:200] or None,
            "description": str(item.get("description") or "")[:300] or None,
            "url": url if isinstance(url, str) and url.startswith(("https://", "http://")) else None,
        })
    return out


def _loads(content: bytes) -> Any:
    try:
        return json.loads(content.decode("utf-8", errors="replace"))
    except (ValueError, RecursionError):
        return None


def _register_path_secret(url: str) -> None:
    """A custom RPC URL may embed an API key in its path (provider/v3/<key>): register opaque segments
    of 16+ characters with the central redactor so the URL never leaves the client unredacted (AR01)."""
    try:
        path = urlsplit(url).path
    except ValueError:
        return
    for segment in path.split("/"):
        if len(segment) >= 16 and re.fullmatch(r"[A-Za-z0-9_-]+", segment) and re.search(r"\d", segment) and re.search(r"[A-Za-z]", segment):
            redact.register_secret(segment)


__all__ = [
    "CryptoSanctionsOnchain",
    "JsonRpc",
    "eth_call_request",
    "function_selector",
    "load_contracts",
    "parse_bool_response",
    "parse_chain_id",
    "parse_identifications",
    "rpc_error",
]
