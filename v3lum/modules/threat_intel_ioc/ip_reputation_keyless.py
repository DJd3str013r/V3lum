"""ip_reputation_keyless: keyless IP/domain compromise checks (IPGuardian, NetAPI) (P150).

Batch p3-G02-2, proposal P150. Final conditions implemented here:

* FC1 - IPGuardian and NetAPI are terms 'unknown' and tier unknown: the licence gate keeps the
  module disabled in every profile until legal records their terms; then it stays
  ``default_enabled=False``, excluded at AMBER and above, ``--allow-unknown`` at CLEAR/GREEN, and
  receives IOC_TYPES only (ipv4, domain, URL host - never a URL path or query).
* FC2 - local first: NetAPI's downloadable feeds are matched locally by ``netapi_compromised_feeds``
  (disclosure 'none'); this module calls the NetAPI per-value check only when no local copy of the
  matching feed exists (the source is reported SKIPPED 'not_applicable' otherwise). Once their terms
  are recorded the feeds become P149 feeds instead of per-IP calls.
* FC3 - the IPGuardian ``/api/check`` adapter has its own per-source status, terms label (registry
  source ``ipguardian.check``) and fixture. The blocklist names it returns are deduplicated against
  the P149 feeds (``ip_blocklists.FEEDS``); bogon/geolocation/organisation lists are ignored and
  anonymizer lists are context. The module counts as ONE vote and never raises severity above LOW.
* FC4 - one-source hits are 'suspicious', never 'malicious'. The NetAPI check is a plain GET JSON
  lookup a P331 spec could express, but IPGuardian needs a POST JSON body and the vote combines
  both sources with the local-first decision, which a spec cannot express: kept in Python.
* FC5 - tests with the recorded IPGuardian check, NetAPI check and NetAPI feed fixtures.
"""

from __future__ import annotations

import re
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.ip_network.ip_geolocation import (
    bogon_reason,
    country_code,
    error_message,
    failure_of,
    flag,
    json_ok,
    normalize_ip,
    parse_asn,
    text,
)
from v3lum.modules.threat_intel_ioc.netapi_compromised_feeds import DOMAIN_FEED, IP_FEED, host_of

SRC_IPG = "ipguardian.check"
SRC_NETAPI = "netapi.check"
IPGUARDIAN_URL = "https://ipguardian.net/api/check"
NETAPI_URL = "https://netapi.com/api-json/"
IGNORED_CATEGORIES = frozenset({"unroutable", "geolocation", "organizations"})
CONTEXT_CATEGORIES = frozenset({"anonymizers"})
#: P149 feed ids when ip_blocklists is not installed (kept in sync with its FEEDS table)
_P149_FALLBACK = frozenset({"spamhaus_drop_v4", "spamhaus_drop_v6", "spamhaus_asndrop", "feodo", "sslbl", "ipsum", "firehol_level1",
                            "blocklist_de", "cins", "et_compromised", "greensnow", "binarydefense", "dataplane_sshclient", "voipbl"})


def p149_feeds() -> frozenset[str]:
    """Feed ids matched locally by P149 (``ip_blocklists``), used to deduplicate IPGuardian's lists."""
    try:
        from v3lum.modules.threat_intel_ioc.ip_blocklists import FEEDS
    except ImportError:  # P149 not installed: the static list
        return _P149_FALLBACK
    return frozenset(str(k).lower() for k in FEEDS) | _P149_FALLBACK


def list_stem(name: Any) -> str:
    """'firehol_level1.netset' -> 'firehol_level1' (lower case, extension dropped)."""
    v = (text(name) or "").lower().rsplit("/", 1)[-1]
    return re.sub(r"\.(netset|ipset|txt|csv|list|lst)$", "", v)


def parse_ipguardian(doc: Any) -> dict[str, Any] | None:
    """IPGuardian /api/check answer -> {ip, found, lists, delisted, network}; None when not a success."""
    if not isinstance(doc, dict) or doc.get("success") is not True:
        return None
    res = doc.get("results")
    if isinstance(res, list):
        res = res[0] if res and isinstance(res[0], dict) else None
    if not isinstance(res, dict) or flag(res.get("found")) is None:
        return None
    lists = []
    for src in res.get("sources") or []:
        if not isinstance(src, dict):
            continue
        fname = text(src.get("filename")) or text(src.get("name"))
        if fname:
            lists.append({"list": list_stem(fname), "category": (text(src.get("category")) or "").lower() or None,
                          "maintainer": text(src.get("maintainer")), "listed_since": text(src.get("listed_since"))})
    net = res.get("network") if isinstance(res.get("network"), dict) else {}
    asn = parse_asn(net.get("asn"))
    return {"ip": normalize_ip(res.get("ip")), "found": flag(res.get("found")), "lists": lists,
            "delisted": [list_stem(d.get("filename") if isinstance(d, dict) else d) for d in res.get("delisted") or [] if d],
            "network": {"asn": f"AS{asn}" if asn else None, "org": text(net.get("org")), "country": country_code(net.get("country")),
                        "type": text(net.get("type"))}}


def ipguardian_vote(parsed: dict[str, Any], covered: frozenset[str]) -> dict[str, Any]:
    """FC3: lists not already matched locally by P149 -> one 'suspicious' vote (LOW)."""
    new, dup, context, ignored = [], [], [], []
    for item in parsed.get("lists") or []:
        cat = item.get("category") or ""
        if cat in IGNORED_CATEGORIES:
            ignored.append(item["list"])
        elif cat in CONTEXT_CATEGORIES:
            context.append(item["list"])
        elif item["list"] in covered:
            dup.append(item["list"])
        else:
            new.append(item["list"])
    return {"new_lists": new, "covered_by_p149": dup, "context_lists": context, "ignored_lists": ignored,
            "network_type": (parsed.get("network") or {}).get("type"), "vote": bool(new)}


def parse_netapi(doc: Any) -> dict[str, Any] | None:
    """NetAPI compromised-check answer; None when it is not a check record."""
    if not isinstance(doc, dict) or "listed_now" not in doc or flag(doc.get("listed_now")) is None:
        return None
    source_text = text(doc.get("source"))
    licence = re.search(r"\b(CC[ -]BY(?:-SA|-NC)?[ -]\d\.\d|CC0|ODbL)\b", source_text or "", re.I)
    return {"value": text(doc.get("value")), "listed_now": flag(doc.get("listed_now")), "listed_ever": flag(doc.get("listed_ever")) is True,
            "first_seen": text(doc.get("first_seen")), "last_seen": text(doc.get("last_seen")), "threat_type": text(doc.get("threat_type")),
            "block_reason": text(doc.get("block_reason")), "via": "check API",
            "licence_hint": licence.group(1).upper() if licence else None}


@register
class IpReputationKeyless(Module):
    name = "ip_reputation_keyless"
    title = "Keyless compromise checks (IPGuardian, NetAPI)"
    description = (
        "Blocklist names IPGuardian aggregates for a public IPv4 (deduplicated against the local P149 feeds) and "
        "NetAPI's compromised-check for an IPv4/domain/URL host when no local NetAPI feed copy exists; one vote."
    )
    category = "threat_intel_ioc"
    accepts = {T.IPV4, T.DOMAIN, T.URL}
    produces = frozenset()
    tags = {"reputation", "free"}
    reference = "https://ipguardian.net/"
    notice = (
        "IPGuardian and NetAPI have unknown terms and tier (P150 FC1): disabled in every profile until legal records "
        "them; afterwards opt-in, excluded at TLP:AMBER and above, --allow-unknown at CLEAR/GREEN. Local NetAPI feeds "
        "answer first. The module is ONE vote, never above LOW, never 'malicious'."
    )
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "ipguardian"
    sources = (SRC_IPG, SRC_NETAPI)
    hosts = ("ipguardian.net", "netapi.com")
    access_model = "free_noauth_limited"
    max_requests = 2
    expected_latency = 2.0
    timeout = 30.0
    min_interval = 2.0
    cache_ttl = 86400
    max_pivots = 0
    default_enabled = False  # FC1: unknown terms and tier (A3)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        target = host_of(entity)
        if target is None:
            return False
        return target[0] == "domain" or bogon_reason(target[1]) is None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        kind, value = host_of(entity) or ("", "")
        allowed = ctx.allowed_sources
        ipg: dict[str, Any] | None = None
        netapi: dict[str, Any] | None = None
        failures: list[tuple[Status, str, str]] = []
        answered = 0
        if kind == "ip" and SRC_IPG in allowed:
            out = self._ipguardian(ctx, value)
            if isinstance(out, tuple):
                failures.append(out)
                res.source_status(SRC_IPG, out[0], reason_code=out[1], reason=out[2])
            else:
                ipg = ipguardian_vote(out, p149_feeds())
                answered += 1
                res.source_status(SRC_IPG, Status.OK)
        if SRC_NETAPI in allowed:
            local = IP_FEED if kind == "ip" else DOMAIN_FEED
            if self._local_copy(ctx, local):
                res.source_status(SRC_NETAPI, Status.SKIPPED, reason_code="not_applicable",
                                  reason="answered locally by netapi_compromised_feeds (local first, P150 FC2)")
            else:
                out = self._netapi(ctx, kind, value)
                if isinstance(out, tuple):
                    failures.append(out)
                    res.source_status(SRC_NETAPI, out[0], reason_code=out[1], reason=out[2])
                else:
                    netapi = out
                    answered += 1
                    res.source_status(SRC_NETAPI, Status.OK)
        if not answered:
            if failures:
                status, code, reason = failures[0]
                return res.mark(status, f"no keyless reputation source answered: {'; '.join(f[2] for f in failures)}", reason_code=code)
            return res.mark(Status.SKIPPED, "no source to query (NetAPI answered by its local feed; IPGuardian checks IPs only)",
                            reason_code="not_applicable")
        return self._verdict(res, value, ipg, netapi)

    # ---------------------------------------------------------------------------- sources
    @staticmethod
    def _local_copy(ctx: Any, name: str) -> bool:
        try:
            return bool(getattr(ctx.data.info(name), "present", False))
        except Exception:  # noqa: BLE001 - an unreadable manifest means no local copy
            return False

    def _ipguardian(self, ctx: Any, ip: str) -> dict[str, Any] | tuple[Status, str, str]:
        try:
            doc = ctx.http.post_json(IPGUARDIAN_URL, json_body={"ip": ip}, ttl=self.cache_ttl, source=SRC_IPG,
                                     cache_if=json_ok(lambda d: isinstance(d, dict) and d.get("success") is True))
        except Exception as exc:  # noqa: BLE001 - per-source rule 5, the rest propagates
            mapped = failure_of(exc)
            if mapped is None:
                raise
            msg = error_message(exc)
            return mapped[0], mapped[1], f"IPGuardian: {msg or str(exc)[:160] or type(exc).__name__}"
        parsed = parse_ipguardian(doc)
        if parsed is None:
            return Status.ERROR, "error", "IPGuardian: unexpected answer: could not verify"
        return parsed

    def _netapi(self, ctx: Any, kind: str, value: str) -> dict[str, Any] | tuple[Status, str, str]:
        try:
            doc = ctx.http.get_json(NETAPI_URL, params={"method": "compromised-check", "value": value}, source=SRC_NETAPI,
                                    cache_if=json_ok(lambda d: isinstance(d, dict) and "listed_now" in d))
        except Exception as exc:  # noqa: BLE001 - per-source rule 5, the rest propagates
            mapped = failure_of(exc)
            if mapped is None:
                raise
            msg = error_message(exc)
            return mapped[0], mapped[1], f"NetAPI: {msg or str(exc)[:160] or type(exc).__name__}"
        parsed = parse_netapi(doc)
        if parsed is None:
            return Status.ERROR, "error", "NetAPI: unexpected answer: could not verify"
        return parsed

    # ---------------------------------------------------------------------------- one vote
    def _verdict(self, res: ModuleResult, value: str, ipg: dict[str, Any] | None, netapi: dict[str, Any] | None) -> ModuleResult:
        if ipg is not None and any(ipg[k] for k in ("new_lists", "covered_by_p149", "context_lists", "ignored_lists")):
            res.attr("ipguardian_lists", ipg)
            if ipg["new_lists"]:
                res.attr("blocklists", ipg["new_lists"])
        if netapi is not None and (netapi["listed_now"] or netapi["listed_ever"]):
            res.attr("netapi_compromised", netapi)
        res.raw = {"ipguardian": ipg, "netapi": netapi}
        reasons = []
        sources = []
        if ipg and ipg["vote"]:
            reasons.append(f"IPGuardian lists not already matched locally: {', '.join(ipg['new_lists'][:10])}")
            sources.append(SRC_IPG)
        if netapi and netapi["listed_now"]:
            reasons.append(f"listed now in NetAPI's compromised feed ({netapi['first_seen'] or '?'}..{netapi['last_seen'] or '?'})")
            sources.append(SRC_NETAPI)
        if reasons:
            res.finding(
                "Listed by keyless reputation aggregators (one vote)",
                "low",
                f"{value}: " + "; ".join(reasons) + ". These aggregators re-publish public lists: one 'suspicious' vote, "
                "never 'malicious' on its own.",
                confidence="possible",
                criterion="IPGuardian blocklist not covered by the local P149 feeds and/or NetAPI listed_now; the module is ONE vote, "
                          "never above LOW, never 'malicious' (P150 FC3/FC4)",
                data={"ipguardian_new_lists": (ipg or {}).get("new_lists"), "netapi_listed_now": (netapi or {}).get("listed_now")},
                tags=["suspicious"],
                source=sources[0],
                observed_last=(netapi or {}).get("last_seen") if netapi and netapi["listed_now"] else None,
            )
            return res
        context = []
        if ipg and ipg["covered_by_p149"]:
            context.append(f"lists already matched locally by P149: {', '.join(ipg['covered_by_p149'])}")
        if ipg and ipg["context_lists"]:
            context.append(f"anonymizer lists: {', '.join(ipg['context_lists'])}")
        if netapi and netapi["listed_ever"]:
            context.append("previously listed in NetAPI's compromised feed")
        if context:
            res.finding("Keyless reputation context (no extra vote)", "info", f"{value}: " + "; ".join(context), confidence="possible",
                        tags=["context_only"], source=SRC_IPG if ipg else SRC_NETAPI)
            return res
        return res.mark(Status.EMPTY, "not listed by IPGuardian or NetAPI (sources that answered)")

