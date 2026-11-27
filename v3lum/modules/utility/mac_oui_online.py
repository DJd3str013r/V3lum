"""Opt-in online MAC prefix relay for prefixes missing from the IEEE index (P315 c3-c4, batch p2-G12-2).

The separate opt-in module the architect asked for (c3): ``default_enabled`` False, used only when the offline
``mac_oui`` index (the IEEE listings) has no entry for the prefix (status unknown, or an IEEE RA parent whose
MA-M/MA-S sub-block is missing locally). Random/locally administered, multicast and null MACs are never sent
(c2: SKIPPED not_applicable).

Privacy (c4, legal floor): only the registry prefix leaves the machine - 6, 7 or 9 hex digits for MA-L, MA-M
and MA-S blocks (``mac_oui.lookup_vendor()['fallback_prefix']``) - never the full MAC, which is a device
identifier. The request URL is built from that prefix alone.

Providers (both relay the IEEE registry, upstream family ieee_ra):

* api.maclookup.app ``/v2/macs/{prefix}`` (provider ``maclookup``; optional legacy key ``maclookup`` sent as the
  apiKey query parameter, masked by the central redactor): 200 found=true, 200 found=false for an unknown
  prefix (an absence), 400 for malformed input (never sent: the prefix is validated first);
* api.macvendors.com ``/{prefix}`` keyless (provider ``macvendors``; 1 request/s and 1,000/day): 200 text/plain
  vendor, 404 JSON ``{"errors": {"detail": "Not Found"}}`` = unknown prefix (c3: '404 = unknown OUI'),
  429 = RATE_LIMITED.

With the maclookup key configured (the team account of c3) maclookup.app is asked first, else macvendors.com;
the second provider is asked only when the first could not answer (rate limit, block, error), and that
failure is reported per source. Both providers need a recorded community tier before this module runs (A8):
they are registered with tier 'unknown' until the reviewer records it, so the policy gate keeps the module
away at AMBER and above (and it never runs by default).
"""

from __future__ import annotations

import json
import re
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    OfflineError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec, Status, valid_reason
from v3lum.core.module import Module, register
from v3lum.modules.utility import mac_oui as _oui

SRC_MACLOOKUP = "maclookup.macs_v2"
SRC_MACVENDORS = "macvendors.lookup"
MACLOOKUP_URL = "https://api.maclookup.app/v2/macs/{prefix}"
MACVENDORS_URL = "https://api.macvendors.com/{prefix}"
KEY = "maclookup"
_PREFIX_RE = re.compile(r"[0-9A-F]{6}|[0-9A-F]{7}|[0-9A-F]{9}")
_HTML_HEAD_RE = re.compile(r"\s{0,200}(?:<!doctype\s{1,20}html|<html|<head|<body|<title|<meta\s)", re.I)
#: the per-source failures that let the other provider answer (deadline, cap and cancel always propagate)
_SOURCE_FAILURES = (RateLimited, Blocked, QuotaExceeded, AuthRequired, HttpError, NetworkError)


def failure_status(exc: BaseException, *, keyed: bool) -> tuple[Status, str]:
    """(status, canonical reason code) of one provider's failure, reported with ``res.source_status``."""
    if isinstance(exc, RateLimited):
        return Status.RATE_LIMITED, "rate_limited"
    if isinstance(exc, QuotaExceeded):
        return Status.QUOTA, "quota"
    if isinstance(exc, AuthRequired):
        return (Status.NEEDS_KEY, "needs_key") if keyed else (Status.BLOCKED, "challenge")
    if isinstance(exc, Blocked):
        code = str(getattr(exc, "reason_code", "") or "challenge")
        return Status.BLOCKED, code if valid_reason(Status.BLOCKED, code) else "challenge"
    return Status.ERROR, "error"


def prefix_urls(prefix: Any) -> dict[str, str] | None:
    """c3-c4: request URLs for a 6/7/9-hex registry prefix; None for anything else (a full MAC is refused)."""
    if not isinstance(prefix, str) or not _PREFIX_RE.fullmatch(prefix.upper()):
        return None
    p = prefix.upper()
    return {SRC_MACLOOKUP: MACLOOKUP_URL.format(prefix=p), SRC_MACVENDORS: MACVENDORS_URL.format(prefix=p)}


def _clean(s: Any) -> str:
    return " ".join(str(s or "").split())[:200]


def parse_maclookup(data: Any) -> dict[str, Any]:
    """maclookup.app v2 JSON -> {'status': 'found'|'not_found'|'error', ...} (success=false is also an error
    marker of the provider, so a 200 carrying it never reaches here)."""
    if not isinstance(data, dict):
        return {"status": "error", "reason": "unexpected maclookup.app answer (not a JSON object)"}
    if data.get("success") is not True:
        return {"status": "error", "reason": _clean(data.get("error") or "success=false")}
    if data.get("found") is not True:
        return {"status": "not_found"}
    org = _clean(data.get("company"))
    if not org:
        return {"status": "error", "reason": "maclookup.app found=true without a company"}
    size = data.get("blockSize")
    return {"status": "found", "org": org, "prefix": _clean(data.get("macPrefix")).upper(),
            "country": _clean(data.get("country")) or None, "block_type": _clean(data.get("blockType")) or None,
            "block_size": size if isinstance(size, int) and not isinstance(size, bool) else None,
            "updated": _clean(data.get("updated")) or None}


def parse_macvendors(status: int, text: str) -> dict[str, Any]:
    """api.macvendors.com keyless: 200 text/plain vendor; 404 JSON errors = unknown prefix."""
    body = (text or "").strip()
    if body.startswith("{"):
        try:
            data = json.loads(body)
        except ValueError:
            data = None
        if isinstance(data, dict) and "errors" in data:
            errors = data.get("errors")
            detail = _clean(errors.get("detail") if isinstance(errors, dict) else errors)
            if status == 404 or detail.lower() == "not found":
                return {"status": "not_found", "detail": detail}
            return {"status": "error", "reason": f"macvendors.com error: {detail}"}
    if status == 200 and body and not _HTML_HEAD_RE.match(body[:4096]) and len(body) <= 300:
        return {"status": "found", "org": _clean(body)}
    return {"status": "error", "reason": f"unexpected macvendors.com answer (HTTP {status})"}


@register
class MacOuiOnline(Module):
    name = "mac_oui_online"
    title = "MAC vendor online fallback (maclookup.app, macvendors.com; prefix only)"
    description = (
        "Opt-in: asks maclookup.app or macvendors.com about a MAC prefix missing from the offline IEEE index, "
        "sending only the 6/7/9-hex registry prefix (never the full MAC)."
    )
    category = "utility"
    accepts = {T.MAC}
    produces = frozenset()
    tags = {"free"}
    reference = "https://macvendors.com/api"
    notice = (
        "Sends only the registry prefix (never the full MAC, a device identifier) and only for prefixes missing from "
        "the IEEE listings. Both relays are tier 'unknown' until the A8 reviewer records them (P315 c3)."
    )
    # ---- contract v2 declarations ---------------------------------------------------------
    terms = "unknown"  # = macvendors.lookup (legal review pending); maclookup.macs_v2 is 'open'
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "maclookup"
    sources = (SRC_MACLOOKUP, SRC_MACVENDORS, _oui.SOURCE)
    hosts = ("api.maclookup.app", "api.macvendors.com")
    access_model = "free_noauth_limited"
    optional_keys = (KEY,)
    absent_statuses = frozenset({404})  # macvendors.com: 'No vendor has registered that prefix' (documented)
    max_requests = 2  # one per provider at most, stop at the first answer
    expected_latency = 0.5
    min_interval = 1.0  # macvendors.com: 1 request/s keyless
    cache_ttl = 30 * 86400
    timeout = 30.0
    default_enabled = False  # c3: opt-in; unknown terms/tier (A3)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return bool(_oui.mac_flags(entity.value).get("lookup_allowed"))  # c2: random/local/multicast MACs never leave

    def _ask(self, src: str, url: str, ctx: Any) -> dict[str, Any]:
        if src == SRC_MACLOOKUP:
            key = ctx.key(KEY)
            try:
                data = ctx.http.get_json(url, source=src, params={"apiKey": key} if key else None)
            except ValueError:  # a 200 that is not JSON: could not verify, never 'unknown'
                return {"status": "error", "reason": "maclookup.app answer is not JSON"}
            return parse_maclookup(data)
        resp = ctx.http.get(url, source=src)
        if resp.status == 404:
            parsed = parse_macvendors(404, resp.text)
            if parsed["status"] == "not_found":
                return parsed
        ctx.http.check(resp)  # classification (challenge pages, 429, markers) and non-2xx -> exceptions
        return parse_macvendors(resp.status, resp.text)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        index, info = _oui.load_index(ctx)  # c3: only prefixes missing from the IEEE index
        hit = _oui.lookup_vendor(index, entity.value)
        if hit["status"] == "found":
            return res.mark(Status.SKIPPED, f"prefix {hit['prefix']} is in the IEEE index: mac_oui answers it offline",
                            reason_code="not_applicable")
        if info["missing"]:
            return res.mark(Status.UNAVAILABLE, "IEEE listings " + ", ".join(sorted(info["missing"])) + " unavailable: the "
                            "fallback runs only for prefixes known to be missing (run v3lum data update)", reason_code="dataset")
        prefix = hit.get("fallback_prefix")
        urls = prefix_urls(prefix)
        if urls is None:
            return res.mark(Status.SKIPPED, hit.get("reason") or "no registry prefix may be sent for this MAC",
                            reason_code="not_applicable")
        order = [SRC_MACLOOKUP, SRC_MACVENDORS] if ctx.has_key(KEY) else [SRC_MACVENDORS, SRC_MACLOOKUP]
        order = [s for s in order if s in ctx.allowed_sources] or order
        first_failure: tuple[Status, str, str] | None = None
        for src in order:
            try:
                out = self._ask(src, urls[src], ctx)
            except (DeadlineExceeded, OfflineError):
                raise  # the run deadline and --offline end the run, they are not a provider failure
            except _SOURCE_FAILURES as exc:
                status, code = failure_status(exc, keyed=src == SRC_MACLOOKUP and ctx.has_key(KEY))
                reason = f"could not verify: {str(exc)[:160]}"
                res.source_status(src, status, reason_code=code, reason=reason)
                first_failure = first_failure or (status, code, f"{src.split('.')[0]}: {reason}")
                continue
            if out["status"] == "error":
                res.source_status(src, Status.ERROR, reason=out["reason"])
                first_failure = first_failure or (Status.ERROR, "error", f"{src.split('.')[0]}: {out['reason']} (could not verify)")
                continue
            res.raw = {"source": src, "prefix_sent": prefix, "answer": out, "ieee_status": hit["status"]}
            if out["status"] == "not_found":
                res.error = f"prefix {prefix} unknown to {src.split('.')[0]} as well (the IEEE listings do not have it either)"
                return res.mark(Status.EMPTY)
            res.attr("mac_vendor", out["org"])
            res.attr("mac_online_lookup", {k: v for k, v in {"source": src, "prefix_sent": prefix, "block_type": out.get("block_type"),
                                                             "block_size": out.get("block_size"), "country": out.get("country"),
                                                             "updated": out.get("updated")}.items() if v is not None})
            res.finding(
                "MAC vendor (online relay of the IEEE registry)",
                "info",
                f"Prefix {prefix} is assigned to {out['org']} according to {src.split('.')[0]} (the prefix is missing from the "
                "local IEEE listings; only the prefix was sent, never the full MAC).",
                confidence="probable",
                data={"prefix_sent": prefix, "org": out["org"], "source": src},
                tags=["info"],
                source=src,
            )
            return res
        # every provider failed: 'could not verify' with the first failure's status (rule 5, never an absence)
        status, code, reason = first_failure or (Status.ERROR, "error", "no MAC prefix relay answered (could not verify)")
        return res.mark(status, reason, reason_code=code)
