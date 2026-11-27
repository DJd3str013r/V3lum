"""Tor relay details from Onionoo, only for IPs that matched the local Tor lists (P040).

Batch p1-G02-2, proposal P040 ``tor_relays`` (the third-party half of the architect's split).
Final conditions implemented here:

* c1 - Onionoo ``details?search=``, disclosure 'third_party' (excluded at TLP:RED by the gate).
* c2 - non-Tor IPs never leave the machine: the IP is sent only when it matched the local bulk
  exit list or the locally matched running-relay summary (``tor_exit_local.local_match``); when
  those lists cannot be verified nothing is sent either. ``search=`` matches prefixes, so only
  relays whose OR or exit address equals the IP are kept. The ``contact`` field (operator e-mails
  and names) is never requested (fixed ``fields=`` list) and never kept: the relay records are
  rebuilt from a field whitelist before anything is stored.
* c6 - an exit is LOW context (tag ``anonymizer``, never malicious, T1090.003); a relay is info.
* c7 - Onionoo answers are cached for an hour (the service publishes hourly); the running-relay
  summary dataset is refreshed with If-Modified-Since by the dataset manager.
"""

from __future__ import annotations

from typing import Any

from v3lum.core.datasets import DatasetError
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.ip_network.ip_offline_db import age_text, dataset_failure, special_purpose
from v3lum.modules.ip_network.tor_exit_local import (
    EXIT_SOURCE,
    ONIONOO_SOURCE,
    TOR_EXIT_NOTE,
    StaleList,
    _norm_ip,
    exonerator_link,
    local_match,
)

DETAILS = "https://onionoo.torproject.org/details"
#: Fixed field list: 'contact' (operator e-mails and names) is never requested (P040 c2).
FIELDS = "nickname,fingerprint,or_addresses,exit_addresses,flags,running,first_seen,last_seen,as,as_name,country"
_HEX = set("0123456789ABCDEF")


def _asn(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str):
        text = value.strip().upper().removeprefix("AS")
        return int(text) if text.isdigit() and int(text) > 0 else None
    return None


def _addresses(values: Any) -> list[str]:
    out: list[str] = []
    for value in values if isinstance(values, list) else []:
        ip = _norm_ip(value) if isinstance(value, str) else None
        if ip and ip not in out:
            out.append(ip)
    return out


def parse_details(doc: Any, query_ip: str) -> tuple[list[dict[str, Any]], int, str]:
    """(relays matching ``query_ip`` exactly, prefix matches dropped, relays_published).

    Each relay is rebuilt from a whitelist of fields: unknown fields and the operator ``contact``
    are dropped at ingestion. Raises ValueError for a document that is not an Onionoo answer."""
    if not isinstance(doc, dict) or not isinstance(doc.get("relays"), list):
        raise ValueError("not an Onionoo details document (no 'relays' list)")
    relays: list[dict[str, Any]] = []
    dropped = 0
    for relay in doc["relays"]:
        if not isinstance(relay, dict):
            continue
        or_ips = _addresses(relay.get("or_addresses"))
        exit_ips = _addresses(relay.get("exit_addresses"))
        if query_ip not in or_ips and query_ip not in exit_ips:
            dropped += 1  # search= matched a prefix (203.0.113.1 also returns .10, .100, .153...)
            continue
        flags = sorted({f for f in relay.get("flags") or [] if isinstance(f, str) and f.isalnum()})
        exits_from_ip = query_ip in exit_ips
        is_exit = exits_from_ip or ("Exit" in flags and query_ip in or_ips)
        fp = relay.get("fingerprint") if isinstance(relay.get("fingerprint"), str) else ""
        fp = fp.upper() if len(fp) == 40 and set(fp.upper()) <= _HEX else ""
        country = relay.get("country") if isinstance(relay.get("country"), str) else ""
        relays.append({
            "nickname": (relay.get("nickname") if isinstance(relay.get("nickname"), str) else "")[:64],
            "fingerprint": fp,
            "flags": flags,
            "running": relay.get("running") if isinstance(relay.get("running"), bool) else None,
            "first_seen": relay.get("first_seen") if isinstance(relay.get("first_seen"), str) else "",
            "last_seen": relay.get("last_seen") if isinstance(relay.get("last_seen"), str) else "",
            "asn": _asn(relay.get("as")),
            "as_name": (relay.get("as_name") if isinstance(relay.get("as_name"), str) else "")[:120],
            "country": country.upper() if len(country) == 2 and country.isalpha() else "",
            "exit": is_exit,
            "matched_as": "exit_address" if exits_from_ip else "or_address",
        })
    published = doc.get("relays_published") if isinstance(doc.get("relays_published"), str) else ""
    return relays, dropped, published


@register
class TorOnionoo(Module):
    name = "tor_onionoo"
    title = "Tor relay details (Onionoo)"
    description = (
        "Relay nickname, flags, first/last seen, AS and country from Onionoo for an IP that matched the local "
        "Tor exit list or running-relay summary; any other IP is never sent."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6}
    produces = {T.ASN}
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "torproject"
    sources = (ONIONOO_SOURCE, EXIT_SOURCE)
    hosts = ("onionoo.torproject.org",)
    access_model = "free_noauth_limited"
    max_requests = 1
    expected_latency = 0.5
    min_interval = 1.0
    cache_ttl = 3600
    reference = "https://metrics.torproject.org/onionoo.html"
    notice = (
        "Only IPs already matched by the local Tor lists are sent to Onionoo (onionoo.torproject.org); operator "
        f"contact fields are never requested or kept. {TOR_EXIT_NOTE}."
    )
    manual_link = "tor_relays:exonerator"
    tags = {"free"}
    max_pivots = 5

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return special_purpose(entity.value) is None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        ip = _norm_ip(entity.value) or entity.value
        try:
            match = local_match(ctx, ip)
        except StaleList as exc:
            return res.mark(Status.UNAVAILABLE, f"local Tor exit list: {exc}: nothing sent to Onionoo (could not verify)", reason_code="dataset")
        except DatasetError as exc:
            status, code = dataset_failure(exc)
            return res.mark(status, f"local Tor exit list unavailable ({exc}): nothing sent to Onionoo (could not verify)", reason_code=code)
        except (OSError, ValueError) as exc:
            return res.mark(Status.ERROR, f"local Tor exit list unreadable ({type(exc).__name__}): nothing sent (could not verify)", reason_code="error")
        if not match.matched:
            if ":" in ip and (ONIONOO_SOURCE in match.failures or ONIONOO_SOURCE not in ctx.allowed_sources):
                return res.mark(Status.UNAVAILABLE, "IPv6: the running-relay summary is unavailable, so the address cannot be matched locally: nothing sent (could not verify)", reason_code="dataset")
            return res.mark(
                Status.SKIPPED,
                "not in the local Tor exit list or running-relay summary: nothing sent to Onionoo (non-Tor IPs never leave the machine)",
                reason_code="not_applicable",
            )
        search = f"[{ip}]" if ":" in ip else ip
        doc = ctx.http.get_json(DETAILS, params={"search": search, "fields": FIELDS}, source=ONIONOO_SOURCE)
        try:
            relays, dropped, published = parse_details(doc, ip)
        except ValueError as exc:
            return res.mark(Status.ERROR, f"unexpected Onionoo answer ({exc}): could not verify", reason_code="error")
        res.raw = {"relays_published": published, "relays": relays, "prefix_matches_dropped": dropped,
                   "local_match": match.state, "exit_list_age": age_text(match.exit_age)}
        if not relays:
            # the IP matched locally but Onionoo has no relay with exactly this address now
            return res.mark("empty")
        is_exit = any(r["exit"] for r in relays)
        res.attr("is_tor_relay", True)
        if is_exit or ":" not in ip:
            res.attr("is_tor_exit", is_exit)
        res.attr("tor_relay", relays[:10])
        firsts = sorted(r["first_seen"] for r in relays if r["first_seen"])
        lasts = sorted(r["last_seen"] for r in relays if r["last_seen"])
        res.attr("first_seen", firsts[0] if firsts else None)
        res.attr("last_seen", lasts[-1] if lasts else None)
        primary = relays[0]
        if primary["asn"]:
            res.attr("asn", f"AS{primary['asn']}")
            res.attr("as_org", primary["as_name"])
            res.pivot(T.ASN, f"AS{primary['asn']}", "belongs_to_asn", confidence=0.7, expand=False, note="AS of the Tor relay (Onionoo)")
        res.attr("country", primary["country"])
        names = ", ".join(sorted({r["nickname"] for r in relays if r["nickname"]})) or "unnamed relay"
        summary = {"relays": [{k: r[k] for k in ("nickname", "fingerprint", "flags", "first_seen", "last_seen", "exit")} for r in relays[:10]]}
        if is_exit:
            res.finding(
                "Tor exit relay (Onionoo)",
                "low",
                f"{TOR_EXIT_NOTE}. Onionoo lists {names} with this exit address (flags and history in the data). "
                "Context only: never malicious on its own and never higher without other evidence (CR28).",
                confidence="confirmed",
                criterion="Onionoo relay record with this exact exit/OR address and the Exit flag (exact-IP match, prefix matches dropped)",
                data=summary,
                tags=["anonymizer", "tor", "context_only"],
                references=["https://metrics.torproject.org/rs.html"],
                source=ONIONOO_SOURCE,
                observed_first=firsts[0] if firsts else None,
                observed_last=lasts[-1] if lasts else None,
                attack=["T1090.003"],
            )
        else:
            res.finding(
                "Tor relay (Onionoo)",
                "info",
                f"Onionoo lists {names} on this address without exit traffic from it. Relays forward encrypted traffic; "
                "they do not originate it.",
                confidence="confirmed",
                data=summary,
                tags=["tor", "context_only"],
                references=["https://metrics.torproject.org/rs.html"],
                source=ONIONOO_SOURCE,
                observed_first=firsts[0] if firsts else None,
                observed_last=lasts[-1] if lasts else None,
            )
        res.link("ExoneraTor (Tor Metrics)", exonerator_link(ip))
        return res
