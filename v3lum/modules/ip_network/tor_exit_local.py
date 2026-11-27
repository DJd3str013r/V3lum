"""Local Tor exit check: the Tor Project bulk exit list and running-relay summary, matched offline (P040).

Batch p1-G02-2, proposal P040 ``tor_relays`` (architect's floor: the local check is split from the
Onionoo lookup). Final conditions implemented here:

* c1 - check.torproject.org/torbulkexitlist is a 1 h dataset matched locally (disclosure 'none',
  allowed at TLP:RED); the shared range index is not needed for exact addresses (a set).
* c2 - non-Tor IPs never leave the machine: this module sends nothing; ``tor_onionoo`` queries
  Onionoo only for IPs matched here (:func:`local_match` is shared with it). The Onionoo
  running-relay summary is a dataset too, so non-exit relays still show (info).
* c6 - a current exit is LOW context with tag ``anonymizer`` and the note 'Tor exit: traffic from
  many users, no attribution possible', never malicious (tag ``context_only``: never scored on
  its own, CR28 combines it with other evidence); ATT&CK T1090.003. Non-exit relays are info.
* c7 - the list's age is shown; the dataset refreshes hourly and a copy older than 6 h (a failed
  refresh) is 'could not verify', never 'not an exit'. Onionoo uses If-Modified-Since (the dataset
  manager's conditional GET). ExoneraTor is a manual pivot link (pack ``tor_relays``).

TorDNSEL measures IPv4 exits only: an IPv6 address is judged from the relay summary (OR addresses)
and is never reported 'not an exit'.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from v3lum.core.datasets import DatasetError, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.ip_network.ip_offline_db import (
    DatasetMemo,
    age_text,
    dataset_age_line,
    dataset_failure,
    parse_ts,
    special_purpose,
)

TOR_EXIT_NOTE = "Tor exit: traffic from many users, no attribution possible"
TOR_ATTRIBUTION = "Tor network data from The Tor Project (Tor Metrics: https://metrics.torproject.org/, CC0)"
EXIT_SOURCE = "torproject.exit_list"
ONIONOO_SOURCE = "torproject.onionoo"
EXONERATOR = "https://metrics.torproject.org/exonerator.html?ip={ip}&lang=en"
#: P040 c7: older than this the copy is 'could not verify' (the dataset itself refreshes hourly).
MAX_LIST_AGE = 6 * 3600
#: Validation floors of a download (the real list has ~1,250 exits, the summary ~9,500 relays);
#: the offline tests lower them for the minimised fixtures.
MIN_EXITS = 100
MIN_RELAYS = 1000


def _norm_ip(value: Any) -> str | None:
    """Canonical IP string ('[2001:db8::1]:443', '192.0.2.1:9001' and IPv4-mapped forms accepted)."""
    text = str(value or "").strip()
    if not text or len(text) > 64:
        return None
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            return None
        text = text[1:end]
    elif text.count(":") == 1 and "." in text:
        text = text.split(":", 1)[0]
    try:
        ip = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def parse_bulk_exit_list(text: str) -> tuple[frozenset[str], int]:
    """(exit IPs, invalid line count) of the TorDNSEL bulk exit list (one IP per line)."""
    ips: set[str] = set()
    invalid = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ip = _norm_ip(line) if "/" not in line else None
        if ip is None:
            invalid += 1
        else:
            ips.add(ip)
    return frozenset(ips), invalid


def parse_relay_summary(doc: Any) -> dict[str, list[dict[str, Any]]]:
    """Onionoo summary document -> {ip: [{nickname, fingerprint, running}]} (relays only; bridges
    ignored). Only the summary fields n/f/a/r are read: no contact data exists in a summary."""
    out: dict[str, list[dict[str, Any]]] = {}
    relays = doc.get("relays") if isinstance(doc, dict) else None
    if not isinstance(relays, list):
        raise ValueError("not an Onionoo summary document (no 'relays' list)")
    for relay in relays:
        if not isinstance(relay, dict):
            continue
        fp = relay.get("f") if isinstance(relay.get("f"), str) else ""
        fp = fp.upper() if len(fp) == 40 and all(c in "0123456789abcdefABCDEF" for c in fp) else ""
        nick = relay.get("n") if isinstance(relay.get("n"), str) else ""
        running = relay.get("r") is True
        for addr in relay.get("a") or []:
            ip = _norm_ip(addr) if isinstance(addr, str) else None
            if ip:
                out.setdefault(ip, []).append({"nickname": nick[:64], "fingerprint": fp, "running": running})
    return out


def _validate_bulk(path: Path) -> bool:
    ips, invalid = parse_bulk_exit_list(path.read_text(encoding="utf-8", errors="replace"))
    if invalid > max(5, len(ips) // 100):
        raise ValueError(f"{invalid} lines are not IP addresses (not a TorDNSEL exit list)")
    if len(ips) < MIN_EXITS:
        raise ValueError(f"too few exit addresses ({len(ips)} < {MIN_EXITS})")
    return True


def _validate_summary(path: Path) -> bool:
    doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    index = parse_relay_summary(doc)
    relays = doc.get("relays") or []
    if len(relays) < MIN_RELAYS or not index:
        raise ValueError(f"too few relays in the Onionoo summary ({len(relays)} < {MIN_RELAYS})")
    return True


BULK_EXIT_LIST = register_dataset(
    "tor_exit_local.torbulkexitlist.txt",
    "https://check.torproject.org/torbulkexitlist",
    ttl=3600,
    description="TorDNSEL bulk exit list (current Tor exit IPv4 addresses, one per line), refreshed hourly",
    licence="CC0-1.0",
    terms_class="open",
    attribution=TOR_ATTRIBUTION,
    provider="torproject",
    source=EXIT_SOURCE,
    validate=_validate_bulk,
    min_bytes=1000,
    expect="lines",
    max_bytes=2 * 1024 * 1024,
    large=False,
    essential=True,
)
RUNNING_RELAYS = register_dataset(
    "tor_exit_local.onionoo_running_relays.json",
    "https://onionoo.torproject.org/summary?type=relay&running=true",
    ttl=3600,
    description="Onionoo summary of running Tor relays (nickname, fingerprint, OR addresses), refreshed hourly with If-Modified-Since",
    licence="CC0-1.0",
    terms_class="open",
    attribution=TOR_ATTRIBUTION,
    provider="torproject",
    source=ONIONOO_SOURCE,
    validate=_validate_summary,
    min_bytes=1000,
    expect="json",
    max_bytes=4 * 1024 * 1024 + 512 * 1024,
    large=False,
    essential=True,
)

_MEMO = DatasetMemo()


class StaleList(Exception):
    """A local Tor list is older than MAX_LIST_AGE and could not be refreshed (could not verify)."""

    def __init__(self, name: str, age: float | None) -> None:
        super().__init__(f"{name} is {age_text(age)} old and could not be refreshed (run v3lum data update {name})")
        self.name = name
        self.age = age


def _age(info: Any, now: Any) -> float | None:
    fetched = parse_ts(getattr(info, "fetched_at", "") or "")
    return None if fetched is None else max(0.0, (now - fetched).total_seconds())


def load_exit_list(ctx: Any) -> tuple[frozenset[str], Any, float | None]:
    """(exit IPs, DatasetInfo, age seconds). The dataset manager refreshes the copy when it is
    older than 1 h; a failed refresh serves the previous copy, which is used up to 6 h old and is
    'could not verify' beyond (StaleList). DatasetError when there is no copy at all."""
    path = Path(ctx.data.fetch(BULK_EXIT_LIST))
    info = ctx.data.info(BULK_EXIT_LIST)
    age = _age(info, ctx.now())
    if age is None or age > MAX_LIST_AGE:
        raise StaleList(BULK_EXIT_LIST, age)
    exits = _MEMO.get(BULK_EXIT_LIST, info.sha256, lambda: parse_bulk_exit_list(path.read_text(encoding="utf-8", errors="replace"))[0])
    return exits, info, age


def load_relays(ctx: Any) -> tuple[dict[str, list[dict[str, Any]]], Any, float | None]:
    """({ip: relays}, DatasetInfo, age seconds) of the running-relay summary (same freshness rule)."""
    path = Path(ctx.data.fetch(RUNNING_RELAYS))
    info = ctx.data.info(RUNNING_RELAYS)
    age = _age(info, ctx.now())
    if age is None or age > MAX_LIST_AGE:
        raise StaleList(RUNNING_RELAYS, age)

    def build() -> dict[str, list[dict[str, Any]]]:
        return parse_relay_summary(json.loads(path.read_text(encoding="utf-8", errors="replace")))

    return _MEMO.get(RUNNING_RELAYS, info.sha256, build), info, age


class LocalMatch:
    """Outcome of the local check of one IP: ``state`` 'exit' | 'relay' | 'none'."""

    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.state = "none"
        self.relays: list[dict[str, Any]] = []
        self.exit_info: Any = None
        self.exit_age: float | None = None
        self.relay_info: Any = None
        self.relay_age: float | None = None
        #: source id -> (Status, reason_code, reason) of a local list that could not be read.
        self.failures: dict[str, tuple[Status, str, str]] = {}

    @property
    def matched(self) -> bool:
        return self.state in ("exit", "relay")


def local_match(ctx: Any, ip: str) -> LocalMatch:
    """Match ``ip`` against the local exit list and running-relay summary (P040 c2): nothing is sent.

    Raises DatasetError / StaleList when the exit list cannot be verified (the caller reports
    'could not verify'); a relay-summary failure is recorded in ``failures`` and the exit check
    still stands.
    """
    match = LocalMatch(ip)
    exits, match.exit_info, match.exit_age = load_exit_list(ctx)
    relays: dict[str, list[dict[str, Any]]] | None = None
    if ONIONOO_SOURCE in ctx.allowed_sources:
        try:
            relays, match.relay_info, match.relay_age = load_relays(ctx)
        except StaleList as exc:
            match.failures[ONIONOO_SOURCE] = (Status.UNAVAILABLE, "dataset", f"running-relay summary: {exc} (could not verify)")
        except (DatasetError, OSError, ValueError) as exc:
            status, code = dataset_failure(exc) if isinstance(exc, DatasetError) else (Status.ERROR, "error")
            match.failures[ONIONOO_SOURCE] = (status, code, f"running-relay summary: {exc} (could not verify)")
    match.relays = list((relays or {}).get(ip, []))
    if ip in exits:
        match.state = "exit"
    elif match.relays:
        match.state = "relay"
    return match


def exonerator_link(ip: str, day: str = "") -> str:
    """ExoneraTor manual pivot (never fetched); with ``day`` the page opens on that date."""
    url = EXONERATOR.format(ip=quote(ip, safe=":"))
    return url + (f"&timestamp={day}" if day else "")


@register
class TorExitLocal(Module):
    name = "tor_exit_local"
    title = "Tor exit list (local match)"
    description = (
        "Is the IP a current Tor exit or relay? Matched locally against the Tor Project bulk exit list "
        "(check.torproject.org, hourly) and the Onionoo running-relay summary; nothing is sent to anyone."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6}
    produces = frozenset()
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (EXIT_SOURCE, ONIONOO_SOURCE)
    reference = "https://metrics.torproject.org/"
    notice = f"{TOR_EXIT_NOTE}: a Tor exit is context (tag anonymizer), never malicious on its own. Tor Metrics data (CC0)."
    manual_link = "tor_relays:exonerator"
    tags = {"offline", "free"}
    max_pivots = 0

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return special_purpose(entity.value) is None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        ip = _norm_ip(entity.value) or entity.value
        try:
            match = local_match(ctx, ip)
        except StaleList as exc:
            return res.mark(Status.UNAVAILABLE, f"Tor bulk exit list: {exc}: could not verify, never 'not an exit'", reason_code="dataset")
        except DatasetError as exc:
            status, code = dataset_failure(exc)
            return res.mark(status, f"Tor bulk exit list unavailable ({exc}): could not verify", reason_code=code)
        except (OSError, ValueError) as exc:
            return res.mark(Status.ERROR, f"Tor bulk exit list unreadable ({type(exc).__name__}): could not verify", reason_code="error")
        now = ctx.now()
        ages = [dataset_age_line("Tor bulk exit list", match.exit_info, now)]
        if match.relay_info is not None:
            ages.append(dataset_age_line("Onionoo running-relay summary", match.relay_info, now))
        for sid, (status, code, reason) in match.failures.items():
            res.source_status(sid, status, reason_code=code, reason=reason)
        res.raw = {
            "exit_list": {"sha256": match.exit_info.sha256, "fetched_at": match.exit_info.fetched_at, "age": age_text(match.exit_age)},
            "relay_summary": None if match.relay_info is None else {"sha256": match.relay_info.sha256, "fetched_at": match.relay_info.fetched_at},
            "state": match.state,
        }
        relays = [{"nickname": r["nickname"], "fingerprint": r["fingerprint"], "running": r["running"]} for r in match.relays[:10]]
        age_phrase = f"bulk exit list fetched {age_text(match.exit_age)} ago"
        if match.state == "exit":
            res.attr("is_tor_exit", True)
            res.attr("is_tor_relay", True)
            res.attr("tor_relay", relays)
            res.attr("dataset_age", ages)
            res.finding(
                "Tor exit node",
                "low",
                f"{TOR_EXIT_NOTE}. Listed in the Tor Project bulk exit list (check.torproject.org, {age_phrase}). "
                "Context only: never malicious on its own and never higher without other evidence (CR28).",
                confidence="confirmed",
                criterion=f"listed in the TorDNSEL bulk exit list (check.torproject.org/torbulkexitlist), {age_phrase}",
                data={"list_age": age_text(match.exit_age), "list_fetched_at": match.exit_info.fetched_at, "relays": relays},
                tags=["anonymizer", "tor", "context_only"],
                references=["https://metrics.torproject.org/"],
                source=EXIT_SOURCE,
                observed_last=match.exit_info.fetched_at or None,
                attack=["T1090.003"],
            )
            res.link("ExoneraTor (Tor Metrics)", exonerator_link(ip))
            return res
        if match.state == "relay":
            if ":" not in ip:  # TorDNSEL covers IPv4 exits: 'not an exit' only for IPv4
                res.attr("is_tor_exit", False)
            res.attr("is_tor_relay", True)
            res.attr("tor_relay", relays)
            res.attr("dataset_age", ages)
            res.finding(
                "Tor relay (not in the exit list)",
                "info",
                f"The address is an OR address of a running Tor relay (Onionoo summary) and is not in the current bulk exit "
                f"list ({age_phrase}). Relays forward encrypted traffic; they do not originate it.",
                confidence="confirmed",
                data={"relays": relays},
                tags=["tor", "context_only"],
                references=["https://metrics.torproject.org/"],
                source=ONIONOO_SOURCE,
                observed_last=match.relay_info.fetched_at if match.relay_info is not None else None,
            )
            res.link("ExoneraTor (Tor Metrics)", exonerator_link(ip))
            return res
        if ":" in ip:
            # TorDNSEL lists IPv4 exits only: an unmatched IPv6 address is never 'not an exit'.
            res.source_status(EXIT_SOURCE, Status.SKIPPED, reason_code="not_applicable", reason="the bulk exit list covers IPv4 exit addresses only")
            if ONIONOO_SOURCE in match.failures or ONIONOO_SOURCE not in ctx.allowed_sources:
                return res.mark(Status.UNAVAILABLE, "IPv6: the bulk exit list has IPv4 exits only and the running-relay summary is unavailable: could not verify", reason_code="dataset")
        return res.mark("empty")
