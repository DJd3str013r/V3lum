"""netapi_compromised_feeds: NetAPI compromised IP and domain feeds matched locally (P150 FC2).

Batch p3-G02-2, proposal P150 (``ip_reputation_keyless``), local-first part. Final conditions
implemented here:

* FC1 - NetAPI's terms and tier are 'unknown' until legal records them: terms 'unknown'
  (disabled in every profile by the licence gate), ``default_enabled=False``. Disclosure 'none':
  the investigated value never leaves the machine; only the feeds are downloaded.
* FC2 - local first: the daily/hourly feeds are registered datasets matched locally through the core
  dataset index (``ctx.data.index``: the shared membership index, SQLite above 1M entries). The IP
  feed (~650 KB) is fetched by the dataset manager; the domain feed (~20 MB) is large and fetched
  only by ``v3lum data update`` (UNAVAILABLE 'dataset' until then, never mid-scan). Once legal
  records the terms these feeds become feeds of P149 (``ip_blocklists``) instead of per-IP calls;
  ``ip_reputation_keyless`` skips its NetAPI per-value check whenever a local copy is present.
* FC3/FC4 - a hit is ONE 'suspicious' vote at most (LOW, never 'malicious'); 'sinkhole-*' domain
  rows are sinkholed names (INFO, tag ``sinkholed``, context only). Domain matching is EXACT on the
  fully qualified name: rows on shared platforms (``*.pages.dev``...) never flag the platform.
* FC5 - tests with the recorded NetAPI IP and domain feed slices (victim IPs and domains scrubbed
  to documentation values).
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from v3lum.core.datasets import DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.ip_network.ip_geolocation import normalize_domain, normalize_ip

SRC_IP = "netapi.compromised_ip"
SRC_DOMAINS = "netapi.compromised_domains"
IP_FEED_URL = "https://netapi.com/api2/?method=compromised&dataset_type=ip&header=0"
DOMAIN_FEED_URL = "https://netapi.com/api2/?method=compromised&dataset_type=url&header=0&format=csv"
DOMAIN_COLUMNS = ("domain", "threat_type", "evidence", "first_seen", "last_seen")
LICENCE = "CC-BY-4.0 (stated by NetAPI in its API answers; terms not yet reviewed by legal)"
ATTRIBUTION = "NetAPI compromised feeds (https://netapi.com/), CC BY 4.0 as stated by the provider"
MIN_IP_ROWS = 100
MIN_DOMAIN_ROWS = 100


def _looks_like_html(head: str) -> bool:
    return head.lstrip()[:15].lower().startswith(("<!doctype", "<html", "<head", "<body"))


def parse_ip_feed(raw: str) -> tuple[frozenset[str], int]:
    """(valid IPs, invalid lines) of the IP feed: one address per line, '#' comments skipped."""
    ips: set[str] = set()
    invalid = 0
    for line in (raw or "").splitlines():
        value = line.split("#", 1)[0].strip().strip(",")
        if not value:
            continue
        ip = normalize_ip(value)
        if ip is None:
            invalid += 1
        else:
            ips.add(ip)
    return frozenset(ips), invalid


def parse_domain_rows(raw: str) -> tuple[list[dict[str, Any]], int]:
    """(rows, invalid) of the domain feed CSV (the header row is present even with header=0)."""
    rows: list[dict[str, Any]] = []
    invalid = 0
    for i, row in enumerate(csv.reader(io.StringIO(raw or ""))):
        if not row or (len(row) == 1 and not row[0].strip()):
            continue
        if i == 0 and row[0].strip().lower() == "domain":
            continue
        rec = row_record(row)
        if rec is None:
            invalid += 1
        else:
            rows.append(rec)
    return rows, invalid


def row_record(row: list[str]) -> dict[str, Any] | None:
    if len(row) != len(DOMAIN_COLUMNS):
        return None
    rec = dict(zip(DOMAIN_COLUMNS, (c.strip() for c in row), strict=True))
    name = normalize_domain(rec["domain"])
    if not name:
        return None
    threat = (rec["threat_type"] or "").lower() or None
    return {"domain": name, "threat_type": threat, "evidence": rec["evidence"] or None, "first_seen": rec["first_seen"] or None,
            "last_seen": rec["last_seen"] or None, "sinkholed": bool(threat and threat.startswith("sinkhole"))}


def _validate_ip_feed(path: Path) -> bool:
    raw = path.read_text(encoding="utf-8", errors="replace")
    if _looks_like_html(raw[:200]):
        raise ValueError("NetAPI IP feed: HTML instead of an address list")
    ips, _invalid = parse_ip_feed(raw)
    if len(ips) < MIN_IP_ROWS:
        raise ValueError(f"NetAPI IP feed: only {len(ips)} valid addresses (expected >= {MIN_IP_ROWS})")
    return True


def _validate_domain_feed(path: Path) -> bool:
    with open(path, encoding="utf-8", errors="replace") as fh:
        head = fh.read(4096)
        if _looks_like_html(head):
            raise ValueError("NetAPI domain feed: HTML instead of CSV")
        fh.seek(0)
        count = sum(1 for row in csv.reader(fh) if row_record(row) is not None)
    if count < MIN_DOMAIN_ROWS:
        raise ValueError(f"NetAPI domain feed: only {count} valid rows (expected >= {MIN_DOMAIN_ROWS})")
    return True


IP_FEED = register_dataset(
    "netapi_compromised_feeds.compromised_ip.txt",
    IP_FEED_URL,
    ttl=6 * 3600,
    description="NetAPI compromised IP feed (one IPv4 per line, updated hourly), matched locally (P150 FC2)",
    licence=LICENCE,
    terms_class="unknown",
    attribution=ATTRIBUTION,
    provider="netapi",
    source=SRC_IP,
    validate=_validate_ip_feed,
    min_bytes=1000,
    expect="lines",
    max_bytes=5_000_000,
)
DOMAIN_FEED = register_dataset(
    "netapi_compromised_feeds.compromised_domains.csv",
    DOMAIN_FEED_URL,
    ttl=86400,
    description="NetAPI compromised domain feed (CSV, ~20 MB, daily): fetched only by `v3lum data update` (P150 FC2)",
    licence=LICENCE,
    terms_class="unknown",
    attribution=ATTRIBUTION,
    provider="netapi",
    source=SRC_DOMAINS,
    validate=_validate_domain_feed,
    min_bytes=10_000,
    expect="csv",
    max_bytes=100_000_000,
    large=True,
)


def host_of(entity: Entity) -> tuple[str, str] | None:
    """('ip' | 'domain', value) for an IPv4, a domain or a URL's host; None otherwise."""
    if entity.type == T.IPV4:
        ip = normalize_ip(entity.value)
        return ("ip", ip) if ip else None
    if entity.type == T.DOMAIN:
        name = normalize_domain(entity.value)
        return ("domain", name) if name else None
    host = urlsplit(entity.value).hostname or ""
    ip = normalize_ip(host)
    if ip:
        return ("ip", ip) if ":" not in ip else None
    name = normalize_domain(host)
    return ("domain", name) if name else None


def find_domain_row(path: Path, name: str) -> dict[str, Any] | None:
    """The feed row of ``name`` (exact FQDN), streaming the CSV once (only after an index hit)."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for row in csv.reader(fh):
            if row and row[0].strip().lower().rstrip(".") == name:
                rec = row_record(row)
                if rec is not None and rec["domain"] == name:
                    return rec
    return None


@register
class NetapiCompromisedFeeds(Module):
    name = "netapi_compromised_feeds"
    title = "NetAPI compromised feeds (local)"
    description = (
        "Local membership test of an IPv4, domain or URL host in NetAPI's downloadable compromised IP and domain "
        "feeds (exact match; the value never leaves the machine)."
    )
    category = "threat_intel_ioc"
    accepts = {T.IPV4, T.DOMAIN, T.URL}
    produces = frozenset()
    tags = {"offline", "reputation"}
    reference = "https://netapi.com/compromised-ips/"
    notice = (
        "NetAPI's terms are not reviewed yet (P150 FC1): disabled in every profile until legal records them. Feeds "
        "are matched locally; the ~20 MB domain feed is fetched only by `v3lum data update`. A hit is one "
        "'suspicious' vote (LOW), never 'malicious'; sinkholed names are context."
    )
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (SRC_IP, SRC_DOMAINS)
    access_model = "offline"
    default_enabled = False  # FC1: unknown terms (A3)
    max_pivots = 0

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return host_of(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        kind, value = host_of(entity) or ("", "")
        if kind == "ip":
            if SRC_IP not in ctx.allowed_sources:
                return res.mark(Status.SKIPPED, f"{SRC_IP} not allowed in this run", reason_code="licence")
            if not ctx.data.index(IP_FEED).contains(value):
                return res.mark(Status.EMPTY, "not in the local NetAPI compromised IP feed")
            info = ctx.data.info(IP_FEED)
            hit = {"listed_now": True, "via": "local feed", "feed": IP_FEED, "fetched_at": getattr(info, "fetched_at", None)}
            res.attr("netapi_compromised", hit)
            res.finding(
                "Listed in NetAPI's compromised IP feed (one vote)",
                "low",
                f"{value} is in the NetAPI compromised IP feed (honeypot-sensor based, updated hourly; local copy fetched "
                f"{hit['fetched_at'] or '?'}). One source: 'suspicious', never 'malicious' on its own.",
                confidence="possible",
                criterion="exact address match in the local NetAPI compromised IP feed; one-source hits are 'suspicious' (P150 FC4)",
                data=hit,
                tags=["suspicious"],
                source=SRC_IP,
            )
            return res
        if SRC_DOMAINS not in ctx.allowed_sources:
            return res.mark(Status.SKIPPED, f"{SRC_DOMAINS} not allowed in this run", reason_code="licence")
        if not getattr(ctx.data.info(DOMAIN_FEED), "present", False):  # large: `v3lum data update` only, never mid-run
            raise DatasetUnavailable(DOMAIN_FEED, f"dataset {DOMAIN_FEED} is not downloaded: run v3lum data update {DOMAIN_FEED}")
        if not ctx.data.index(DOMAIN_FEED, column="domain").contains(value):
            return res.mark(Status.EMPTY, "not in the local NetAPI compromised domain feed (exact name)")
        row = find_domain_row(Path(ctx.data.fetch(DOMAIN_FEED)), value)
        if row is None:
            return res.mark(Status.ERROR, "NetAPI domain feed index and file disagree: could not verify", reason_code="error")
        hit = {"listed_now": True, "via": "local feed", "feed": DOMAIN_FEED, **{k: row[k] for k in ("threat_type", "evidence", "first_seen", "last_seen")}}
        res.attr("netapi_compromised", hit)
        if row["sinkholed"]:
            res.finding(
                "Sinkholed name in NetAPI's domain feed (context)",
                "info",
                f"{value}: NetAPI lists it as {row['threat_type']} ({row['evidence'] or 'no evidence text'}); a sinkholed name "
                "is neutralised infrastructure: hits are infected clients, not the attacker.",
                confidence="possible",
                data=hit,
                tags=["sinkholed", "context_only"],
                source=SRC_DOMAINS,
                observed_first=row["first_seen"],
                observed_last=row["last_seen"],
            )
            return res
        res.finding(
            "Listed in NetAPI's compromised domain feed (one vote)",
            "low",
            f"{value}: NetAPI threat type {row['threat_type'] or '?'} ({row['first_seen'] or '?'}..{row['last_seen'] or '?'}). "
            "One source: 'suspicious', never 'malicious' on its own.",
            confidence="possible",
            criterion="exact name match in the local NetAPI compromised domain feed; one-source hits are 'suspicious' (P150 FC4)",
            data=hit,
            tags=["suspicious"],
            source=SRC_DOMAINS,
            observed_first=row["first_seen"],
            observed_last=row["last_seen"],
        )
        return res
