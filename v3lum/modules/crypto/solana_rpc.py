"""Solana JSON-RPC (P215): balance and recent signatures of an explicitly typed Solana address.

Final conditions (P215, binding):

* FC1 - ``getBalance`` and ``getSignaturesForAddress`` (limit <= 25, one page) on a configurable
  Solana RPC: the public ``api.mainnet-beta.solana.com`` (provider ``solana_foundation``) by default,
  or the https URL in setting ``solana_rpc_url`` (an RPC node the organisation operates or contracts,
  provider ``internal_solana_rpc``; used exclusively, never with a public failover). The public RPC
  limits go through the provider quota block (P334: 1 request/s x 0.8 for the whole provider, the
  observed getSignaturesForAddress method limit of 10 per window is the binding figure) plus
  ``min_interval``; the provider's own ``x-ratelimit-*`` headers are read after the first call and an
  exhausted request bucket stops the run before the second call (partial, ``rate_limited``).
  ``default_enabled`` is False.
* FC2 - runs only on explicitly typed Solana inputs: a ``sol:``/``solana:`` prefix in the value
  (``wallet:sol:<address>`` or ``other_crypto_address:sol:<address>``: the core has no Solana entity
  type, the chain rides in the value), or a bare 32-byte base58 key typed by the analyst who selected
  this module explicitly (``-M solana_rpc`` / ``v3lum run solana_rpc``: the analyst's confirmation of
  the chain), or a pivot emitted by a Solana-specific source (:data:`SOLANA_SPECIFIC_SOURCES`; none in
  this build). A bare base58 string is never treated as Solana on its own: it has no checksum, so an
  arbitrary token would be sent to the RPC. Everything else ends SKIPPED ``not_applicable`` before any
  request.
* FC3 - output is the balance and the recent signatures only: no pivots (``max_pivots = 0``), no
  counterparties, token accounts or transaction details, and the free-text ``memo`` of each signature
  is dropped at parse time. Registry provider ``solana_foundation``: tier trusted, terms open (public
  RPC, best effort, no SLA).

Rule 5: JSON-RPC errors arrive inside HTTP 200; rate limits (429), egress blocks (403) and disabled
calls (410) are provider error markers, every other JSON-RPC error, a malformed or HTML body and an
unexpected result shape end ERROR (could not verify). A zero balance with no signatures is EMPTY with
hedged wording: the public RPC answered a valid-looking 0/[] for an account that certainly exists from
a datacenter egress (prep notes, 2026-11-26), so empty answers are never cached and never read as
'unused'. The health check probes a public organisation account (Circle's USDC mint) that can never
hold fewer than 1,461,600 lamports: a lower answer marks the source unhealthy without sending any
investigated value.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    Cancelled,
    ConfigError,
    OfflineError,
    PolicyError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, HealthResult, Module, register
from v3lum.core.validators import b58decode, sol_address_plausible

SOURCE_PUBLIC = "solana_foundation.rpc"
SOURCE_INTERNAL = "internal_solana_rpc.rpc"
DEFAULT_RPC_HOST = "api.mainnet-beta.solana.com"
DEFAULT_RPC_URL = "https://" + DEFAULT_RPC_HOST
SETTING_RPC_URL = "solana_rpc_url"
ALLOWED_METHODS = ("getBalance", "getSignaturesForAddress")
MAX_SIGNATURES = 25
REQUEST_ID = 1
LAMPORTS_PER_SOL = 1_000_000_000
U64_MAX = 2**64 - 1
EXPLICIT_PREFIXES = ("sol:", "solana:")
#: modules whose pivots are Solana-specific by construction (FC2). No approved module of this build
#: emits Solana pivots (P215 itself produces nothing); a future Solana source adds its name here.
SOLANA_SPECIFIC_SOURCES: frozenset[str] = frozenset()
CONFIRMATION_STATUSES = frozenset({"processed", "confirmed", "finalized"})
#: health-check canary: Circle's USDC mint, a public organisation account that exists on mainnet and,
#: as an 82-byte rent-exempt mint, never holds fewer than 1,461,600 lamports (prep notes warning 1).
CANARY_ACCOUNT = "EPjFWdd5AufqSVkPXiFi6wNahqaJYMH1cP2t1vbRJxcJ"
CANARY_MIN_LAMPORTS = 1_461_600
#: query parameters and path tokens that carry a credential in keyed commercial RPC URLs
CREDENTIAL_PARAMS = frozenset({"api-key", "api_key", "apikey", "key", "token", "access_token", "auth", "x-api-key", "secret"})
_CREDENTIAL_SEGMENT = re.compile(r"(?=[A-Za-z0-9_-]*[0-9])(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{20,}")
_RATELIMIT_HEADER = re.compile(r"x-ratelimit-([a-z]+)-(limit|remaining)")
_INT_TEXT = re.compile(r"-?[0-9]{1,20}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
#: request buckets that stop the second call when exhausted; the per-method bucket of the first call
#: does not bind the second (another method), the websocket 'pubsub' bucket and 'unlimited' ones never
_GLOBAL_BUCKETS = ("rps", "conn", "connrate")
_JSONRPC_ERRORS = {
    -32700: "parse error",
    -32600: "invalid request",
    -32601: "method not available on this RPC",
    -32602: "invalid param",
    -32603: "internal error",
    -32005: "node unhealthy or behind",
    -32011: "transaction history not available on this RPC",
}


# --------------------------------------------------------------------------------------
# input typing (FC2)
# --------------------------------------------------------------------------------------


def is_solana_pubkey(text: Any) -> bool:
    """32-44 base58 characters decoding to exactly 32 bytes (core P217 plausibility check).

    Plausibility only: Solana keys carry no checksum, so this never types a value as Solana by itself."""
    return isinstance(text, str) and text == text.strip() and bool(text) and sol_address_plausible(text)


def is_solana_signature(text: Any) -> bool:
    """A transaction signature: 64-88 base58 characters decoding to exactly 64 bytes."""
    if not isinstance(text, str) or not 64 <= len(text) <= 88:
        return False
    try:
        return len(b58decode(text)) == 64
    except ValueError:
        return False


def parse_solana_input(value: Any) -> tuple[str | None, bool]:
    """(address, explicit) of an entity value.

    ``sol:<key>`` / ``solana:<key>`` (any case) -> (key, True) when the key is a 32-byte base58 public
    key; a bare 32-byte key -> (key, False); anything else -> (None, False)."""
    if not isinstance(value, str):
        return None, False
    text = value.strip()
    low = text.lower()
    for prefix in EXPLICIT_PREFIXES:
        if low.startswith(prefix):
            rest = text[len(prefix):].split("?", 1)[0].strip()  # a Solana Pay URI keeps only its recipient
            return (rest, True) if is_solana_pubkey(rest) else (None, False)
    return (text, False) if is_solana_pubkey(text) else (None, False)


def solana_input_gate(
    value: Any,
    *,
    is_seed: bool,
    explicitly_selected: bool,
    parent_module: str = "",
    solana_sources: frozenset[str] = SOLANA_SPECIFIC_SOURCES,
) -> dict[str, Any]:
    """FC2 decision for one entity: ``{run, address, basis, reason}``.

    basis: ``prefix`` (an analyst-typed ``sol:``/``solana:`` value), ``analyst_selected`` (a bare key
    typed by the analyst who selected this module explicitly) or ``solana_pivot`` (a pivot from a
    Solana-specific source). A pivot from any other source - a multi-chain list labelling an address
    'SOL' included - never runs: only explicit analyst input or Solana-specific sources (FC2)."""
    address, explicit = parse_solana_input(value)
    out: dict[str, Any] = {"run": False, "address": address, "basis": None, "reason": ""}
    if address is None:
        out["reason"] = "not a Solana public key (32-byte base58, optionally prefixed sol:)"
        return out
    if not is_seed:
        if parent_module and parent_module in solana_sources:
            out.update(run=True, basis="solana_pivot")
        else:
            out["reason"] = (
                f"pivot from {parent_module or 'another source'}: Solana lookups run only on analyst-typed Solana inputs "
                "or pivots of a Solana-specific source (P215 FC2)"
            )
        return out
    if explicit:
        out.update(run=True, basis="prefix")
    elif explicitly_selected:
        out.update(run=True, basis="analyst_selected")
    else:
        out["reason"] = (
            "bare base58 string: Solana not confirmed (no checksum, never auto-detected); type sol:<address> "
            "(e.g. wallet:sol:<address>) or select the module explicitly (-M solana_rpc / v3lum run solana_rpc)"
        )
    return out


# --------------------------------------------------------------------------------------
# requests and endpoint (FC1)
# --------------------------------------------------------------------------------------


def clamp_limit(limit: Any) -> int:
    """getSignaturesForAddress page size bounded to 1..25 (FC1); non-integers give 25."""
    if isinstance(limit, bool) or not isinstance(limit, int):
        return MAX_SIGNATURES
    return max(1, min(MAX_SIGNATURES, limit))


def build_rpc_request(method: str, address: str, *, limit: int = MAX_SIGNATURES) -> dict[str, Any]:
    """JSON-RPC 2.0 body of one of the two FC1 methods; ValueError for any other method or a value that
    is not a 32-byte base58 key (an invalid value is never sent)."""
    if method not in ALLOWED_METHODS:
        raise ValueError(f"method {method!r} is not allowed (P215 FC1: {', '.join(ALLOWED_METHODS)} only)")
    if not is_solana_pubkey(address):
        raise ValueError("not a 32-byte base58 Solana public key")
    params: list[Any] = [address]
    if method == "getSignaturesForAddress":
        params.append({"limit": clamp_limit(limit)})
    return {"jsonrpc": "2.0", "id": REQUEST_ID, "method": method, "params": params}


def rpc_endpoint(configured: Any) -> dict[str, Any]:
    """The RPC to use: ``{ok, url, host, source, internal, reason}``.

    Empty setting -> the public default (source solana_foundation.rpc). A configured URL must be https
    with a public host name (no userinfo, fragment, IP literal or single label), point at mainnet (no
    devnet/testnet host) and carry no credential (api-key query parameters, long path tokens of keyed
    commercial RPCs: those need their own provider, backlog p3-G09-2). Its host is then the
    organisation's node (source internal_solana_rpc.rpc), unless it is the public default host."""
    public = {"ok": True, "url": DEFAULT_RPC_URL, "host": DEFAULT_RPC_HOST, "source": SOURCE_PUBLIC, "internal": False, "reason": ""}
    text = configured.strip() if isinstance(configured, str) else ""
    if not text:
        return public
    refused = {"ok": False, "url": "", "host": "", "source": "", "internal": False}
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return {**refused, "reason": f"setting {SETTING_RPC_URL} is not a valid URL"}
    host = (parts.hostname or "").lower().rstrip(".")
    reason = ""
    if parts.scheme != "https":
        reason = "must be an https URL"
    elif parts.username or parts.password:
        reason = "must not carry credentials in the URL"
    elif parts.fragment:
        reason = "must not carry a fragment"
    elif re.fullmatch(r"[0-9.]+", host) or ":" in host:
        reason = "must name the node by host name, not by IP literal"
    elif not host or "." not in host:
        reason = "needs a fully qualified host name"
    elif re.search(r"(^|[.-])(devnet|testnet)([.-]|$)", host):
        reason = "points at a devnet/testnet cluster: investigations need mainnet"
    else:
        query = parse_qsl(parts.query, keep_blank_values=True)
        segments = [s for s in parts.path.split("/") if s]
        if any(k.lower() in CREDENTIAL_PARAMS for k, _v in query) or any(_CREDENTIAL_SEGMENT.fullmatch(s) for s in segments):
            reason = "carries a credential (keyed commercial RPC URLs are not supported in this build: see docs/backlog/p3-G09-2.md)"
    if reason:
        return {**refused, "reason": f"setting {SETTING_RPC_URL} {reason}"}
    if host == DEFAULT_RPC_HOST and port in (None, 443):
        return {**public, "url": text}
    return {"ok": True, "url": text, "host": host, "source": SOURCE_INTERNAL, "internal": True, "reason": ""}


# --------------------------------------------------------------------------------------
# answers (FC1, FC3, rule 5)
# --------------------------------------------------------------------------------------


def _clean(text: Any, limit: int = 160) -> str:
    return _CONTROL.sub(" ", text).strip()[:limit] if isinstance(text, str) else ""


def _int(value: Any) -> int | None:
    """A non-negative JSON integer (bools and floats refused)."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def parse_jsonrpc_envelope(body: Any, expected_id: Any = REQUEST_ID) -> dict[str, Any]:
    """Split one JSON-RPC 2.0 answer: ``{kind result|error|html|malformed, result, code, message, detail}``.

    A batch array, a missing result, a wrong jsonrpc version or an id mismatch is malformed."""
    out: dict[str, Any] = {"kind": "malformed", "result": None, "code": None, "message": "", "detail": ""}
    if isinstance(body, (bytes, bytearray)):
        text = bytes(body).decode("utf-8", "replace")
    elif isinstance(body, str):
        text = body
    else:
        out["detail"] = "no body"
        return out
    stripped = text.lstrip("﻿ \t\r\n")
    if not stripped:
        out["detail"] = "empty body"
        return out
    if stripped[:1] == "<":
        out.update(kind="html", detail="HTML instead of JSON-RPC")
        return out
    try:
        obj = json.loads(stripped)
    except (ValueError, RecursionError):
        out["detail"] = "not valid JSON (truncated or garbled)"
        return out
    if not isinstance(obj, dict):
        out["detail"] = "batch array where one answer was expected" if isinstance(obj, list) else "JSON is not an object"
        return out
    if "jsonrpc" in obj and obj.get("jsonrpc") != "2.0":
        out["detail"] = "not a JSON-RPC 2.0 answer"
        return out
    error = obj.get("error")
    if error is not None:
        if isinstance(error, dict):
            code = error.get("code")
            out.update(kind="error", code=code if isinstance(code, int) and not isinstance(code, bool) else None, message=_clean(error.get("message")))
        else:
            out.update(kind="error", message=_clean(str(error)))
        return out
    if "result" not in obj:
        out["detail"] = "neither result nor error"
        return out
    if expected_id is not None and obj.get("id") != expected_id:
        out["detail"] = f"answer id {str(obj.get('id'))[:20]!r} does not match the request id {expected_id!r}"
        return out
    out.update(kind="result", result=obj["result"])
    return out


def jsonrpc_error_reason(code: Any, message: str, host: str) -> str:
    """Readable 'could not verify' text of a JSON-RPC error the provider markers did not classify."""
    label = _JSONRPC_ERRORS.get(code, "JSON-RPC error") if isinstance(code, int) else "JSON-RPC error"
    quoted = f" {message!r}" if message else ""
    return f"{host}: {label} (JSON-RPC {code}){quoted}: could not verify"


def format_sol(lamports: Any) -> str | None:
    """Exact SOL decimal string of integer lamports (1 -> '0.000000001'); None for bad input."""
    value = _int(lamports)
    if value is None:
        return None
    whole, frac = divmod(value, LAMPORTS_PER_SOL)
    return str(whole) if not frac else f"{whole}.{frac:09d}".rstrip("0")


def _iso(epoch: Any) -> str | None:
    value = _int(epoch)
    if value is None or value == 0:
        return None
    try:
        return _dt.datetime.fromtimestamp(value, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def parse_get_balance(result: Any) -> dict[str, Any] | None:
    """getBalance result -> ``{lamports, sol, slot, api_version}``; None for an unexpected shape
    (not an object, a value that is not a u64 integer)."""
    if not isinstance(result, dict):
        return None
    value = _int(result.get("value"))
    if value is None or value > U64_MAX:
        return None
    context = result.get("context") if isinstance(result.get("context"), dict) else {}
    api_version = context.get("apiVersion")
    return {
        "lamports": value,
        "sol": format_sol(value),
        "slot": _int(context.get("slot")),
        "api_version": (_clean(api_version, 32) or None) if isinstance(api_version, str) else None,
    }


def parse_signatures(result: Any, limit: int = MAX_SIGNATURES) -> dict[str, Any] | None:
    """getSignaturesForAddress result -> recent signatures only (FC1 limit <= 25, FC3).

    Each entry: signature, slot, block_time (ISO UTC or None), failed (err is not null) and
    confirmation_status. ``memo`` is dropped on purpose (free text that may carry personal data), and
    so are error details. Invalid entries are skipped and counted; more entries than the limit (an RPC
    ignoring 'limit') are cut. ``page_full``: older signatures may exist. None for an unexpected shape
    (not a list, or a non-empty list without one valid entry)."""
    if not isinstance(result, list):
        return None
    cap = clamp_limit(limit)
    entries: list[dict[str, Any]] = []
    skipped = 0
    for item in result[:cap]:
        if not isinstance(item, dict) or not is_solana_signature(item.get("signature")):
            skipped += 1
            continue
        confirmation = item.get("confirmationStatus")
        entries.append({
            "signature": item["signature"],
            "slot": _int(item.get("slot")),
            "block_time": _iso(item.get("blockTime")),
            "failed": item.get("err") is not None,
            "confirmation_status": confirmation if confirmation in CONFIRMATION_STATUSES else None,
        })
    if result and not entries:
        return None
    times = sorted(e["block_time"] for e in entries if e["block_time"])
    return {
        "signatures": entries,
        "count": len(entries),
        "skipped": skipped,
        "failed_count": sum(1 for e in entries if e["failed"]),
        "page_full": len(result) >= cap,
        "cut_to_limit": len(result) > cap,
        "newest": times[-1] if times else None,
        "oldest": times[0] if times else None,
    }


def parse_ratelimit_headers(headers: Any) -> dict[str, Any]:
    """The provider's own quota signal: ``{tier, node, buckets {name: {limit, remaining, unlimited}}}``
    from x-ratelimit-tier, x-rpc-node and every x-ratelimit-<bucket>-limit/-remaining pair."""
    hdrs = {str(k).strip().lower(): str(v).strip() for k, v in (headers.items() if isinstance(headers, dict) else ())}
    out: dict[str, Any] = {"tier": _clean(hdrs.get("x-ratelimit-tier"), 32) or None, "node": _clean(hdrs.get("x-rpc-node"), 64) or None, "buckets": {}}
    for name, value in hdrs.items():
        match = _RATELIMIT_HEADER.fullmatch(name)
        if not match:
            continue
        bucket = out["buckets"].setdefault(match.group(1), {"limit": None, "remaining": None, "unlimited": False})
        if match.group(2) == "limit" and value.lower() == "unlimited":
            bucket["unlimited"] = True
        elif _INT_TEXT.fullmatch(value):
            bucket[match.group(2)] = int(value)
    return out


def ratelimit_exhausted(headers: Any, host: str = DEFAULT_RPC_HOST) -> str:
    """'' unless a finite request bucket shared by every method (rps, conn, connrate) reports
    remaining <= 0. Unlimited buckets ('endpoint' answers 'unlimited' with a NEGATIVE remaining) and the
    websocket 'pubsub' bucket never count."""
    info = parse_ratelimit_headers(headers)
    for name in _GLOBAL_BUCKETS:
        bucket = info["buckets"].get(name)
        if not bucket or bucket["unlimited"] or bucket["limit"] is None or bucket["remaining"] is None:
            continue
        if bucket["remaining"] <= 0:
            return f"{host}: {name} request budget exhausted (x-ratelimit-{name}-remaining {bucket['remaining']} of {bucket['limit']})"
    return ""


def cacheable_answer(resp: Any) -> bool:
    """``cache_if`` veto: only a JSON-RPC result with data is cached. Errors inside HTTP 200 never are,
    and neither are zero balances or empty signature lists (the public RPC served false empties)."""
    try:
        env = parse_jsonrpc_envelope(getattr(resp, "content", b""))
    except Exception:  # noqa: BLE001 - a veto never raises
        return False
    if env["kind"] != "result":
        return False
    result = env["result"]
    if isinstance(result, list):
        return bool(result)
    if isinstance(result, dict):
        return bool(_int(result.get("value")))
    return False


# --------------------------------------------------------------------------------------
# the RPC call (shared by run() and the health self-test)
# --------------------------------------------------------------------------------------


def _rpc_call(ctx: Any, endpoint: dict[str, Any], method: str, address: str, *, ttl: int | None) -> tuple[dict[str, Any], Any]:
    """POST one read-only call through ctx.http and classify it (markers, 429, keyless 403, challenge
    pages raise); returns (envelope, response)."""
    kw: dict[str, Any] = {"json_body": build_rpc_request(method, address), "source": endpoint["source"], "cache_if": cacheable_answer}
    if ttl is not None:
        kw["ttl"] = ttl
    resp = ctx.http.post(endpoint["url"], **kw)
    ctx.http.check(resp)
    return parse_jsonrpc_envelope(resp.content), resp


def _parent_module(ctx: Any) -> str:
    provenance = getattr(ctx, "provenance", ()) or ()
    try:
        last = tuple(provenance)[-1]
        return str(last[2]) if len(last) > 2 else ""
    except (IndexError, TypeError):
        return ""


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class SolanaRpc(Module):
    name = "solana_rpc"
    title = "Solana JSON-RPC (balance and recent signatures)"
    description = (
        "Balance and the 25 newest transaction signatures of an explicitly typed Solana address (sol:<address>) from "
        "the public mainnet-beta JSON-RPC or the organisation's own node (setting solana_rpc_url)."
    )
    category = "crypto"
    accepts = {T.CRYPTO}
    produces: frozenset[T] = frozenset()
    tags = {"free"}
    reference = "https://solana.com/docs/references/clusters"
    notice = (
        "Runs only on explicitly typed Solana inputs: type sol:<address> (e.g. wallet:sol:<address>) or select the module "
        "explicitly for a bare address; a bare base58 string is never sent (no checksum). The public RPC is best effort "
        "(no SLA, not meant for production) and has answered 0 lamports with no signatures for existing accounts from "
        "datacenter egress: an empty answer is not proof that the address was never used. Set solana_rpc_url only to a "
        "mainnet RPC node the organisation operates or contracts (https, no credential in the URL); it is then used "
        "instead of the public RPC, never with a public failover."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "solana_foundation"
    sources = (SOURCE_PUBLIC, SOURCE_INTERNAL)
    hosts = (DEFAULT_RPC_HOST,)
    access_model = "free_noauth_limited"
    max_requests = 2
    expected_latency = 2.0
    timeout = 20.0
    min_interval = 1.0
    daily_quota = 1000
    cache_ttl = 3600
    max_pivots = 0
    default_enabled = False
    settings = {
        SETTING_RPC_URL: SettingSpec(
            "",
            "https URL of a Solana mainnet RPC node the organisation operates or contracts (no credential in the URL); "
            "empty = the public api.mainnet-beta.solana.com",
        ),
    }

    @classmethod
    def health_check(cls) -> HealthCheck:
        # a public organisation account (USDC mint): a probe never sends an investigated value
        return HealthCheck(T.CRYPTO, "sol:" + CANARY_ACCOUNT, expect="ok", selftest=cls._canary_selftest)

    @classmethod
    def _canary_selftest(cls, ctx: Any) -> HealthResult:
        """getBalance of the canary account (one request, never cached). Fewer lamports than the
        account's rent-exempt minimum means the RPC serves degraded state from this egress (the public
        RPC's false empties): 'dead' with the reason. Environment refusals propagate (doctor)."""
        endpoint = rpc_endpoint(ctx.setting(SETTING_RPC_URL, ""))
        if not endpoint["ok"]:
            raise ConfigError(endpoint["reason"])
        try:
            env, _resp = _rpc_call(ctx, endpoint, "getBalance", CANARY_ACCOUNT, ttl=0)
        except (Cancelled, PolicyError, ConfigError, OfflineError):
            raise
        except (QuotaExceeded, RateLimited) as exc:
            return HealthResult("quota", str(exc)[:200])
        except (Blocked, AuthRequired) as exc:
            return HealthResult("blocked", str(exc)[:200])
        except Exception as exc:  # noqa: BLE001 - every other failure is a dead source for doctor
            return HealthResult("dead", f"{type(exc).__name__}: {str(exc)[:160]}")
        if env["kind"] == "error":
            return HealthResult("dead", jsonrpc_error_reason(env["code"], env["message"], endpoint["host"]))
        balance = parse_get_balance(env["result"]) if env["kind"] == "result" else None
        if balance is None:
            return HealthResult("dead", f"{endpoint['host']}: unexpected getBalance answer ({env['detail'] or 'bad result'})")
        if balance["lamports"] < CANARY_MIN_LAMPORTS:
            return HealthResult(
                "dead",
                f"{endpoint['host']} answered {balance['lamports']} lamports for canary account {CANARY_ACCOUNT} (expected >= "
                f"{CANARY_MIN_LAMPORTS}): balances and signatures from this RPC are not reliable from this egress",
            )
        return HealthResult("ok", f"{endpoint['host']}: canary balance {balance['sol']} SOL")

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return parse_solana_input(entity.value)[0] is not None  # not a 32-byte base58 key: never a Solana lookup

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        options = getattr(ctx, "options", None)
        gate = solana_input_gate(
            entity.value,
            is_seed=bool(getattr(ctx, "is_seed", False)),
            explicitly_selected=self.name in (getattr(options, "include", None) or ()),
            parent_module=_parent_module(ctx),
        )
        if not gate["run"]:
            return res.mark("skipped", gate["reason"], reason_code="not_applicable")
        endpoint = rpc_endpoint(ctx.setting(SETTING_RPC_URL, ""))
        if not endpoint["ok"]:
            return res.mark("skipped", endpoint["reason"], reason_code="config")
        if endpoint["source"] not in ctx.allowed_sources:
            return res.mark("skipped", f"{endpoint['source']} is not allowed in this run (licence profile)", reason_code="licence")
        address = gate["address"]
        host = endpoint["host"]
        res.raw = {"rpc": {"host": host, "internal": endpoint["internal"], "source": endpoint["source"], "basis": gate["basis"]}}

        # 1. getBalance (rate limits, blocks and challenge pages raise: could not verify)
        env, resp = _rpc_call(ctx, endpoint, "getBalance", address, ttl=self.cache_ttl)
        if env["kind"] == "error":
            return res.mark("error", jsonrpc_error_reason(env["code"], env["message"], host))
        if env["kind"] != "result":
            return res.mark("error", f"{host}: malformed getBalance answer ({env['detail']}): could not verify")
        balance = parse_get_balance(env["result"])
        if balance is None:
            return res.mark("error", f"{host}: unexpected getBalance result: could not verify")
        limits = parse_ratelimit_headers(getattr(resp, "headers", {}) if not getattr(resp, "from_cache", False) else {})
        self._report_balance(res, balance, endpoint, limits)

        # the provider's own budget signal wins: no second call into an exhausted bucket (P334)
        exhausted = "" if getattr(resp, "from_cache", False) else ratelimit_exhausted(getattr(resp, "headers", {}), host)
        if exhausted:
            res.error = f"recent signatures not requested: {exhausted} (could not verify)"
            return res.stop("rate_limited")

        # 2. getSignaturesForAddress, one page of at most 25 (a mid-run rate limit keeps the balance: partial)
        env2, _resp2 = _rpc_call(ctx, endpoint, "getSignaturesForAddress", address, ttl=self.cache_ttl)
        if env2["kind"] == "error":
            return res.mark("error", "balance read; recent signatures " + jsonrpc_error_reason(env2["code"], env2["message"], host))
        sigs = parse_signatures(env2["result"]) if env2["kind"] == "result" else None
        if sigs is None:
            detail = env2["detail"] or "unexpected result"
            return res.mark("error", f"balance read; recent signatures: {host}: malformed getSignaturesForAddress answer ({detail}): could not verify")
        res.raw["signatures"] = {k: v for k, v in sigs.items() if k != "signatures"}
        res.raw["signatures"]["entries"] = sigs["signatures"]
        if balance["lamports"] == 0 and not sigs["signatures"]:
            res.attr(
                "wallet_status",
                f"no balance and no signatures returned by {host} as of {ctx.now().date().isoformat()} (public RPC, best effort: "
                "not proof that the address was never used)" if not endpoint["internal"] else
                f"no balance and no signatures returned by the configured node {host} as of {ctx.now().date().isoformat()}",
            )
            return res.mark("empty")
        self._report_activity(res, address, balance, sigs, endpoint)
        return res

    @staticmethod
    def _report_balance(res: ModuleResult, balance: dict[str, Any], endpoint: dict[str, Any], limits: dict[str, Any]) -> None:
        res.attr("chain", "solana")
        res.attr("balance", f"{balance['sol']} SOL")
        res.attr("balance_base_units", str(balance["lamports"]))
        res.attr("rpc_context", {
            "host": endpoint["host"],
            "internal": endpoint["internal"],
            "slot": balance["slot"],
            "api_version": balance["api_version"],
            "node": limits.get("node"),
            "ratelimit_tier": limits.get("tier"),
        })
        res.attr("disclosed_to", [] if endpoint["internal"] else [endpoint["host"]])
        res.raw["balance"] = dict(balance)
        if limits.get("buckets"):
            res.raw["ratelimit"] = limits

    @staticmethod
    def _report_activity(res: ModuleResult, address: str, balance: dict[str, Any], sigs: dict[str, Any], endpoint: dict[str, Any]) -> None:
        entries = sigs["signatures"]
        res.attr("recent_signatures", entries)
        res.attr("more_history", sigs["page_full"])
        if sigs["newest"]:
            res.attr("last_activity", sigs["newest"])
            res.attr("activity_window", {
                "first_seen": sigs["oldest"],
                "last_seen": sigs["newest"],
                "first_seen_exact": not sigs["page_full"],
                "txs_examined": sigs["count"],
            })
        where = "the organisation's Solana node" if endpoint["internal"] else "the public Solana RPC (best effort)"
        more = "; older history exists (only the newest page of 25 was read)" if sigs["page_full"] else ""
        failed = f", {sigs['failed_count']} failed" if sigs["failed_count"] else ""
        window = f"; newest {sigs['newest']}, oldest read {sigs['oldest']}" if sigs["newest"] else ""
        res.finding(
            "Solana wallet balance and recent signatures",
            "info",
            f"{balance['sol']} SOL ({balance['lamports']} lamport(s)) at slot {balance['slot']}; {sigs['count']} recent "
            f"signature(s){failed}{window}{more}. Source: {where}.",
            confidence="probable",
            criterion="getBalance and getSignaturesForAddress (limit 25) answers of the Solana JSON-RPC for the typed address",
            data={"lamports": balance["lamports"], "sol": balance["sol"], "signatures": sigs["count"],
                  "failed": sigs["failed_count"], "more_history": sigs["page_full"]},
            source=endpoint["source"],
            observed_first=None if sigs["page_full"] else sigs["oldest"],
            observed_last=sigs["newest"],
        )


__all__ = [
    "CANARY_ACCOUNT",
    "DEFAULT_RPC_URL",
    "MAX_SIGNATURES",
    "SOLANA_SPECIFIC_SOURCES",
    "SolanaRpc",
    "build_rpc_request",
    "cacheable_answer",
    "clamp_limit",
    "format_sol",
    "is_solana_pubkey",
    "is_solana_signature",
    "jsonrpc_error_reason",
    "parse_get_balance",
    "parse_jsonrpc_envelope",
    "parse_ratelimit_headers",
    "parse_signatures",
    "parse_solana_input",
    "ratelimit_exhausted",
    "rpc_endpoint",
    "solana_input_gate",
]
