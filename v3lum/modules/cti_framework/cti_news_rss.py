"""cti_news_rss: CTI news / advisory feed watcher with offline matching (P298, batch p2-G11-1).

Final conditions (FC) of P298 and where they are met:

* **FC1 feed list.** The team-curated ``v3lum/data/cti_news_rss/cti_feeds.json`` (schema
  ``v3lum.cti_feeds/1``) holds one entry per feed with its registry source, terms note, tier, health and
  last_ok: The Record, BleepingComputer, DFIR Report, Krebs, Help Net Security, Dark Reading, CyberScoop,
  Schneier, DarkFeed, Dark Web Informer, ICHI, DataBreaches.net and CERT.br. :func:`validate_feed_list`
  is the CI check (tests/modules/test_cti_news_rss.py).
* **FC2 pending / excluded.** CTIR Gov and CAIS/RNP sit under ``pending`` (re-verify from the team network:
  maintenance page and unreachable from the research egress); The Hack (stale since 2022) and CISO Advisor
  (Cloudflare challenge) under ``excluded``. Neither list is ever fetched.
* **FC3 licence.** Every feed's terms class is 'unknown' (provider registry): the module's ``terms`` is
  'unknown', ``default_enabled = False`` and the licence gate keeps it out of every profile. Each feed
  also carries ``enabled: false`` and ``legal_decision: null`` until legal records the feed-reader decision
  (poll <= hourly; headline + link + date only; no full text; no redistribution): with no enabled feed and
  no explicit ``cti_news_rss_feeds`` selection the run is SKIPPED ``licence``.
* **FC4 fetching.** One registered dataset per feed (``cti_news_rss.<feed>``, TTL 3600 s, conditional GET
  by the dataset manager, 2 MiB cap): one fetch per feed per hour whatever the number of entities. A run
  refreshes stale feeds within a 10 s budget (``cti_news_rss_refresh_budget``); feeds left over are
  served from their local copy. Challenge pages are rejected by the dataset manager (never bypassed) and
  a feed the curated list marks ``blocked`` is not fetched at all (A9: manual link).
* **FC5 parsing and storage.** XML goes through the shared safe XML helper (DOCTYPE/entities refused), at
  most 200 items per feed; items keep only (date, title, link, CVE ids read in memory from the
  description) in ``ctx.state`` with 180-day retention: no article content is stored or scraped. The core
  offers no module-scoped SQLite store, so the JSON state (1 MB cap) holds at most
  :data:`STORE_ITEMS_PER_FEED` items per feed (core request in the batch manifest).
* **FC6 matching.** Offline (disclosure 'none'): accent folding, word boundaries, exact CVE ids
  (``CVE-2021-44228`` never matches ``CVE-2021-442281``). Terms come from the run entity (company, actor,
  malware, CVE, keyword) and, for a company/keyword that names an org-profile brand or supplier, its
  variants and domains.
* **FC7 ambiguous names.** Brand names under 5 characters or on :data:`COMMON_WORD_BRANDS` (Claro, Oi,
  Vivo, Natura, Inter...) match only with a context term within 3 tokens (company suffix, 'operadora',
  'banco'...), a brand domain or another non-ambiguous alias; common-word actor names (Play, Royal...)
  need a threat context word ('ransomware', 'gang'...). 'Ficou claro que...' never matches.
* **FC8 findings.** INFO (context) or LOW (own organisation in news), never raising risk alone; a
  dark-web-news or DataBreaches.net item naming the own organisation is MEDIUM 'reported claim - verify'
  (never 'breach confirmed') with the shared dedupe key (:func:`claim_dedupe_key`) for the
  ransomware-victim trackers. The 5 most recent headlines are links (terminal).
* **FC9 health.** Per feed ok / stale (> 90 days) / blocked / error / missing in ``cti_feed_health`` and as
  ``res.source_status``; tiers come from the registry (CERT.br and The Record trusted; anonymous feeds
  unknown, labelled 'unverified source'). Disclosure 'none' gives the derived tier 'n/a' for the TLP gate.
* **FC10 merge gate.** Trimmed real feeds in tests/fixtures/cti_news_rss/ (the complete ICHI feed
  re-fetched; the truncated research sample is the malformed case), FakeHttp, contract test, P327 lint.
"""

from __future__ import annotations

import email.utils
import hashlib
import html
import logging
import re
import time
import unicodedata
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from v3lum.config import SettingSpec
from v3lum.core.context import StateError
from v3lum.core.datasets import DataStore, DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, HealthResult, Module, register
from v3lum.modules.file_analysis.file_type_sniff import UnsafeXML, safe_xml_parse

log = logging.getLogger(__name__)

FEEDS_FILE = "cti_news_rss/cti_feeds.json"
FEEDS_SCHEMA = "v3lum.cti_feeds/1"
DATASET_PREFIX = "cti_news_rss."
FEED_MAX_BYTES = 2 * 1024 * 1024  # FC5
FEED_MAX_ITEMS = 200  # FC5
FEED_STALE_DAYS = 90  # FC9
FEED_MIN_INTERVAL_S = 3600  # FC4: at most hourly
FEED_RETENTION_DAYS = 180  # FC5
REFRESH_BUDGET_S = 10.0  # FC4: scan-start refresh budget
STORE_ITEMS_PER_FEED = 200  # ctx.state is JSON with a 1 MB cap: newest items per feed
TERMINAL_HEADLINES = 5  # FC8
MAX_MENTIONS = 50
MAX_FINDINGS = 10
MAX_URL_PIVOTS = 10
FEED_KINDS = frozenset({"news", "darkweb_news", "breach_news", "advisory", "cert"})
CLAIM_KINDS = frozenset({"darkweb_news", "breach_news"})  # FC8: MEDIUM 'reported claim - verify'
TERM_CLASSES = ("open", "key-terms", "license", "noncommercial", "unknown")
TIERS = frozenset({"trusted", "community", "unknown"})
HEALTH_STATES = frozenset({"ok", "stale", "blocked", "error", "pending"})

_WS = re.compile(r"\s+")
_TAG = re.compile(r"<[^<>]{0,2000}>")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_DASHES = re.compile("[‐‑‒–—―−]")
_RE_CVE = re.compile(r"(?<![A-Za-z0-9])CVE-\d{4}-\d{4,7}(?!\d)", re.I)
_TOKEN = re.compile(r"[0-9a-z]+")
_EMAILISH = re.compile(r"[^\s@]+@[^\s@]+\.[a-z]{2,}", re.I)
_ATOM = "{http://www.w3.org/2005/Atom}"
_RDF = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}"
_RSS1 = "{http://purl.org/rss/1.0/}"
_DC = "{http://purl.org/dc/elements/1.1/}"
_CONTENT = "{http://purl.org/rss/1.0/modules/content/}encoded"


# ------------------------------------------------------------------------------------------ text helpers


def _s(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return str(value)


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dedupe(seq: Any) -> list[Any]:
    seen: set[Any] = set()
    out = []
    for item in seq:
        key = fold_text(item) if isinstance(item, str) else item
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def clean_text(value: Any, max_len: int = 300) -> str:
    """Untrusted text -> one safe line (entities decoded, tags/control characters removed, truncated)."""
    text = html.unescape(_s(value))
    text = _TAG.sub(" ", text)
    text = _CTRL.sub(" ", text)
    text = _WS.sub(" ", text).strip()
    if max_len and len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text


def fold_text(value: Any) -> str:
    """Accent folding + casefold (FC6)."""
    text = unicodedata.normalize("NFKD", _s(value))
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return _DASHES.sub("-", text).casefold()


def safe_http_url(value: Any) -> str | None:
    text = _s(value).strip().replace(" ", "%20")
    if not text or len(text) > 2048 or any(ch in text for ch in "\r\n\t\x00"):
        return None
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host:
        return None
    return text


def parse_date(value: Any) -> datetime | None:
    """RFC 2822 (RSS), ISO 8601 (Atom) or a leading YYYY-MM-DD -> aware UTC datetime (None if junk or < 1971)."""
    text = _s(value).strip()
    if not text or len(text) > 64:
        return None
    dt = None
    if re.match(r"^[A-Za-z]{3},|^\d{1,2} [A-Za-z]{3} \d{4}", text):
        try:
            dt = email.utils.parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            dt = None
    if dt is None:
        iso = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        m = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(\.\d+)?(.*)$", iso)
        if m:
            frac = (m.group(2) or "")[:7].ljust(7, "0") if m.group(2) else ""
            iso = m.group(1) + frac + m.group(3)
        try:
            dt = datetime.fromisoformat(iso)
        except ValueError:
            m = re.match(r"^(\d{4})[-/](\d{2})[-/](\d{2})", text)
            if not m:
                return None
            try:
                dt = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            except ValueError:
                return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return None if dt.year < 1971 else dt


def iso_utc(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt is not None else None


def looks_like_html(body: Any) -> bool:
    head = _s(body[:4096] if isinstance(body, (bytes, bytearray)) else _s(body)[:4096]).lstrip("﻿ \t\r\n").lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or bool(re.search(r"<html[\s>]|<head[\s>]|<body[\s>]", head[:1024]))


def _html_title(text: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    return clean_text(m.group(1), 120) if m else ""


# ------------------------------------------------------------------------------------------ feed parsing (FC5)


def _local(tag: Any) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _child_text(el: Any, *names: str) -> str:
    if el is None:
        return ""
    for name in names:
        child = el.find(name)
        if child is not None:
            text = "".join(child.itertext()).strip()
            if text:
                return text
    return ""


def _atom_link(entry: Any) -> str:
    fallback = ""
    for link in entry.findall(_ATOM + "link"):
        rel = (link.get("rel") or "alternate").strip().lower()
        href = link.get("href") or ""
        if rel == "alternate" and href:
            return href
        if not fallback and href:
            fallback = href
    return fallback


def _item_cves(node: Any) -> list[str]:
    """CVE ids read in memory from description/summary/content (facts); the text itself is discarded."""
    texts = []
    for name in ("description", _CONTENT, _ATOM + "summary", _ATOM + "content", _RSS1 + "description"):
        child = node.find(name)
        if child is not None:
            texts.append("".join(child.itertext())[:20000])
    return _dedupe(m.upper() for m in _RE_CVE.findall(" ".join(texts)))


def parse_feed(raw: Any, feed_id: str, *, max_items: int = FEED_MAX_ITEMS, max_bytes: int = FEED_MAX_BYTES) -> dict[str, Any]:
    """FC5: RSS 2.0 / Atom 1.0 / RSS 1.0 (RDF) -> headline items only.

    Returns {status ok|empty|error, reason, feed_id, kind, title, updated, items, item_count, truncated};
    each item {feed_id, title, link, published, guid, cves}. Descriptions and content are never returned.
    HTML pages (maintenance, challenge), oversize bodies, DOCTYPE/ENTITY declarations and malformed XML are
    'error'."""
    base: dict[str, Any] = {"feed_id": feed_id, "kind": None, "title": None, "updated": None, "items": [], "item_count": 0, "truncated": False}
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if not isinstance(raw, (bytes, bytearray)):
        return dict(base, status="error", reason="feed body is not bytes")
    if len(raw) > max_bytes:
        return dict(base, status="error", reason=f"feed larger than {max_bytes} bytes (cap)")
    if looks_like_html(raw):
        title = _html_title(_s(bytes(raw[:30000])))
        return dict(base, status="error", reason=f"HTML page instead of a feed ({title or 'untitled'})")
    try:
        root = safe_xml_parse(bytes(raw).lstrip(b"\xef\xbb\xbf").lstrip(), max_bytes=max_bytes)
    except UnsafeXML as exc:
        return dict(base, status="error", reason=f"unsafe XML refused ({exc.args[0] if exc.args else 'unsafe'})")
    except ValueError as exc:
        return dict(base, status="error", reason=f"malformed XML ({str(exc)[:80]})")
    rtag = _local(root.tag).lower()
    if rtag == "rss":
        channel = root.find("channel")
        if channel is None:
            return dict(base, status="error", reason="RSS without channel")
        kind, ftitle = "rss", _child_text(channel, "title")
        updated = _child_text(channel, "lastBuildDate", "pubDate", _DC + "date")
        nodes = channel.findall("item")
    elif root.tag == _ATOM + "feed":
        kind, ftitle = "atom", _child_text(root, _ATOM + "title")
        updated = _child_text(root, _ATOM + "updated")
        nodes = root.findall(_ATOM + "entry")
    elif root.tag == _RDF + "RDF":
        channel = root.find(_RSS1 + "channel")
        kind, ftitle = "rdf", _child_text(channel, _RSS1 + "title")
        updated = _child_text(channel, _DC + "date")
        nodes = root.findall(_RSS1 + "item")
    else:
        return dict(base, status="error", reason=f"not a feed (root element {rtag[:40]})")
    items = []
    for node in nodes[:max_items]:
        if kind == "rss":
            title, link = _child_text(node, "title"), _child_text(node, "link")
            guid_el = node.find("guid")
            guid = (guid_el.text or "").strip() if guid_el is not None else ""
            if not link and guid_el is not None and (guid_el.get("isPermaLink") or "true").lower() != "false":
                link = guid
            published = _child_text(node, "pubDate", _DC + "date")
        elif kind == "atom":
            title, link = _child_text(node, _ATOM + "title"), _atom_link(node)
            guid = _child_text(node, _ATOM + "id")
            published = _child_text(node, _ATOM + "published", _ATOM + "updated")
        else:
            title, link = _child_text(node, _RSS1 + "title"), _child_text(node, _RSS1 + "link")
            guid = node.get(_RDF + "about") or link
            published = _child_text(node, _DC + "date")
        title = clean_text(title, 300)
        link = safe_http_url(link)
        if not title or not link:
            continue
        cves = _dedupe([m.upper() for m in _RE_CVE.findall(title)] + _item_cves(node))
        items.append({"feed_id": feed_id, "title": title, "link": link, "published": iso_utc(parse_date(published)),
                      "guid": clean_text(guid, 300) or link, "cves": cves})
    return dict(base, status="ok" if items else "empty", reason=None, kind=kind, title=clean_text(ftitle, 200) or None,
                updated=iso_utc(parse_date(updated)), items=items, item_count=len(nodes), truncated=len(nodes) > max_items)


def feed_health(result: dict[str, Any], now: datetime, stale_days: int = FEED_STALE_DAYS) -> dict[str, Any]:
    """FC9: {state ok|stale|error, reason, newest_item, age_days}; item dates win over a fresh channel date."""
    if result.get("status") == "error":
        return {"state": "error", "reason": result.get("reason"), "newest_item": None, "age_days": None}
    dates = [d for d in (parse_date(i.get("published")) for i in _list(result.get("items")) if isinstance(i, dict)) if d]
    if not dates:
        upd = parse_date(result.get("updated"))
        if upd is None:
            return {"state": "error", "reason": "no dated items", "newest_item": None, "age_days": None}
        dates = [upd]
    newest = max(dates)
    age = (now - newest).days
    state = "stale" if age > stale_days else "ok"
    return {"state": state, "reason": f"stale: newest item {age} days old (> {stale_days})" if state == "stale" else None,
            "newest_item": iso_utc(newest), "age_days": age}


def prune_items(items: list[dict[str, Any]], now: datetime, retention_days: int = FEED_RETENTION_DAYS) -> list[dict[str, Any]]:
    """FC5: 180-day retention (undated items count from their first_seen)."""
    out = []
    for item in items:
        dt = parse_date(item.get("published")) or parse_date(item.get("first_seen"))
        if dt is not None and (now - dt).days <= retention_days:
            out.append(item)
    return out


def recent_headlines(items: list[dict[str, Any]], limit: int = TERMINAL_HEADLINES) -> list[dict[str, Any]]:
    """FC8: most recent headlines first."""
    rows = [i for i in items if isinstance(i, dict) and i.get("title") and i.get("link")]
    rows.sort(key=lambda i: (i.get("published") or i.get("first_seen") or "", i.get("title") or ""), reverse=True)
    return rows[: max(0, int(limit))]


# ------------------------------------------------------------------------------------------ feed list (FC1)


def validate_feed_list(doc: Any) -> list[str]:
    """FC1/FC3/FC9 CI validation of the curated feed list ([] = valid)."""
    problems: list[str] = []
    if not isinstance(doc, dict) or not isinstance(doc.get("feeds"), list):
        return ["root must be an object with a 'feeds' list"]
    if doc.get("schema") != FEEDS_SCHEMA:
        problems.append(f"schema must be {FEEDS_SCHEMA!r}")
    seen: set[str] = set()
    for i, feed in enumerate(doc["feeds"]):
        where = f"feeds[{i}]"
        if not isinstance(feed, dict):
            problems.append(f"{where}: not an object")
            continue
        fid = feed.get("id")
        if not isinstance(fid, str) or not re.fullmatch(r"[a-z0-9_]{2,40}", fid):
            problems.append(f"{where}: id must match [a-z0-9_]{{2,40}}")
        elif fid in seen:
            problems.append(f"{where}: duplicate id {fid}")
        seen.add(str(fid))
        if not isinstance(feed.get("source"), str) or not re.fullmatch(r"[a-z][a-z0-9_]{1,63}\.[a-z][a-z0-9_]{0,63}", feed["source"]):
            problems.append(f"{where}: source must be a registry source id 'provider.source'")
        url, host = feed.get("url"), None
        if isinstance(url, str):
            try:
                parts = urlsplit(url)
                host = parts.hostname if parts.scheme == "https" else None
            except ValueError:
                host = None
        if not host:
            problems.append(f"{where}: url must be an https URL")
        hosts = feed.get("hosts")
        if not isinstance(hosts, list) or not hosts or not all(isinstance(h, str) and h for h in hosts):
            problems.append(f"{where}: hosts must be a non-empty list of exact host names")
        elif host and host not in hosts:
            problems.append(f"{where}: hosts must include the url host {host}")
        if feed.get("kind") not in FEED_KINDS:
            problems.append(f"{where}: kind must be one of {sorted(FEED_KINDS)}")
        if feed.get("format") not in ("rss", "atom", "rdf"):
            problems.append(f"{where}: format must be rss|atom|rdf")
        tier = feed.get("tier")
        if tier not in TIERS:
            problems.append(f"{where}: tier must be trusted|community|unknown")
        elif tier == "unknown" and feed.get("label") != "unverified source":
            problems.append(f"{where}: unknown-tier feeds carry label 'unverified source' (FC9)")
        terms = feed.get("terms")
        if not isinstance(terms, dict) or terms.get("class") not in TERM_CLASSES or not _s(terms.get("note")).strip():
            problems.append(f"{where}: terms {{class, note}} required (A1)")
        else:
            if terms.get("class") == "unknown" and feed.get("enabled") is not False:
                problems.append(f"{where}: unknown-terms feeds must be enabled=false until legal review (A1, FC3)")
            if "legal_decision" not in terms:
                problems.append(f"{where}: terms.legal_decision required (null until recorded, FC3)")
        health = feed.get("health")
        if not isinstance(health, dict) or health.get("state") not in HEALTH_STATES or "last_ok" not in health:
            problems.append(f"{where}: health {{state, last_ok}} required (FC9)")
        if not isinstance(feed.get("min_interval_s"), int) or feed["min_interval_s"] < FEED_MIN_INTERVAL_S:
            problems.append(f"{where}: min_interval_s must be an int >= 3600 (FC4)")
        if not isinstance(feed.get("max_items"), int) or not 0 < feed["max_items"] <= FEED_MAX_ITEMS:
            problems.append(f"{where}: max_items must be 1..200 (FC5)")
        if not isinstance(feed.get("max_bytes"), int) or not 0 < feed["max_bytes"] <= FEED_MAX_BYTES:
            problems.append(f"{where}: max_bytes must be 1..2097152 (FC5)")
        if not isinstance(feed.get("enabled"), bool):
            problems.append(f"{where}: enabled must be a boolean")
        if not isinstance(feed.get("context", []), list):
            problems.append(f"{where}: context must be a list of words")
    return problems


def load_feed_list() -> dict[str, Any]:
    try:
        doc = DataStore.bundled_json(FEEDS_FILE)
    except (OSError, ValueError) as exc:  # pragma: no cover - the file ships with the module
        log.warning("cti_news_rss: feed list unreadable: %s", exc)
        return {"schema": FEEDS_SCHEMA, "feeds": []}
    return doc if isinstance(doc, dict) else {"schema": FEEDS_SCHEMA, "feeds": []}


FEED_LIST = load_feed_list()
FEED_LIST_PROBLEMS = validate_feed_list(FEED_LIST)
FEEDS: dict[str, dict[str, Any]] = {}
for _feed in _list(FEED_LIST.get("feeds")):
    if isinstance(_feed, dict) and not validate_feed_list({"schema": FEEDS_SCHEMA, "feeds": [_feed]}):
        FEEDS[_feed["id"]] = _feed
FEED_SOURCES: tuple[str, ...] = tuple(sorted({f["source"] for f in FEEDS.values()}))


def dataset_name(feed_id: str) -> str:
    return DATASET_PREFIX + feed_id


def _validator(feed_id: str) -> Any:
    def check(path: Any) -> bool:
        with open(path, "rb") as fh:
            parsed = parse_feed(fh.read(FEED_MAX_BYTES + 1), feed_id)
        if parsed["status"] == "error":
            raise ValueError(parsed["reason"])
        return True
    return check


for _fid, _feed in FEEDS.items():
    register_dataset(
        dataset_name(_fid),
        _feed["url"],
        ttl=float(_feed["min_interval_s"]),
        description=f"{_feed.get('name') or _fid} feed (P298 cti_news_rss: headline + link + date only)",
        licence=f"publisher feed, terms not reviewed: {clean_text(_feed['terms']['note'], 160)}",
        terms_class=_feed["terms"]["class"],
        attribution=_feed.get("name") or _fid,
        source=_feed["source"],
        validate=_validator(_fid),
        min_bytes=64,
        expect="bytes",
        max_bytes=int(_feed["max_bytes"]),
        large=False,
    )


# ------------------------------------------------------------------------------------------ matching (FC6/FC7)

#: FC7 starter list (accent-folded) of brand names that are also common words.
COMMON_WORD_BRANDS = frozenset({
    "claro", "oi", "vivo", "natura", "inter", "tim", "gol", "azul", "elo", "rede", "via", "next", "neon", "pan", "safra",
    "original", "positivo", "americanas", "porto", "stone", "will", "sol", "extra", "casa", "agora", "modal", "genial",
    "c6", "bv", "xp", "pague menos", "magalu",
})
#: Ransomware/actor names that are also common words.
COMMON_WORD_ACTORS = frozenset({
    "play", "royal", "cuba", "hive", "medusa", "everest", "chaos", "cactus", "fog", "ghost", "hello", "vice", "underground",
    "beast", "interlock", "lynx", "kraken", "quantum", "embargo", "money message", "the gentlemen", "nova", "inception",
    "warlock", "fiction", "akira",
})
COMPANY_CONTEXT = (("operadora",), ("banco",), ("bank",), ("telecom",), ("telecomunicacoes",), ("empresa",), ("companhia",),
                   ("cia",), ("ltda",), ("sa",), ("s", "a"), ("inc",), ("corp",), ("grupo",), ("group",), ("holding",),
                   ("fintech",), ("seguradora",), ("varejista",), ("cooperativa",), ("co",), ("brasil",))
THREAT_CONTEXT = (("ransomware",), ("gang",), ("grupo",), ("group",), ("apt",), ("hackers",), ("malware",), ("botnet",),
                  ("stealer",), ("loader",), ("trojan",), ("backdoor",), ("operators",), ("operadores",), ("affiliate",),
                  ("afiliados",), ("extortion",), ("extorsao",), ("leak",), ("vazamento",))
_KINDS = {T.ORG: "company", T.KEYWORD: "keyword", T.THREAT_ACTOR: "actor", T.MALWARE: "malware", T.CVE: "cve"}


def _phrase_regex(folded_phrase: str) -> re.Pattern[str] | None:
    toks = _TOKEN.findall(folded_phrase)
    if not toks:
        return None
    return re.compile(r"(?<![0-9a-z])" + r"[^0-9a-z]{0,3}".join(re.escape(t) for t in toks) + r"(?![0-9a-z])")


def _term(name: str, kind: str, own: bool, domains: list[str], context: list[str], group: str) -> dict[str, Any]:
    fn = fold_text(name)
    ntok = len(_TOKEN.findall(fn))
    if kind in ("actor", "malware"):
        ambiguous = len(fn) < 5 or fn in COMMON_WORD_ACTORS
    else:
        ambiguous = (len(fn.replace(" ", "")) < 5 or fn in COMMON_WORD_BRANDS) and ntok < 2
    return {"term": name, "kind": kind, "own": own, "ambiguous": ambiguous, "domains": domains, "context": context, "group": group}


def watch_terms(entity: Entity, org: Any = None) -> list[dict[str, Any]]:
    """FC6 terms for one entity: the value itself plus, for a company/keyword naming an org-profile brand
    (own) or supplier, its variants and domains (a domain or a multi-token alias is the 'second token')."""
    kind = _KINDS.get(entity.type)
    value = clean_text(entity.value, 200)
    if not kind or not value:
        return []
    if kind == "cve":
        cve = value.upper()
        return [{"term": cve, "kind": "cve", "own": False, "ambiguous": False, "domains": [], "context": [], "group": "seed"}]
    names, domains, own, term_kind = [value], [], False, kind
    if kind in ("company", "keyword") and org is not None and not getattr(org, "is_empty", True):
        fv = fold_text(value)
        own_domains = [fold_text(getattr(d, "name", "")).lstrip("*.") for d in getattr(org, "domains", ()) if getattr(d, "name", "")]
        org_name = _s(getattr(org, "name", ""))
        for brand in getattr(org, "brands", ()):
            group = [_s(getattr(brand, "keyword", ""))] + [_s(v) for v in getattr(brand, "variants", ())]
            if fv in {fold_text(n) for n in group if n}:
                own, term_kind = True, "brand"
                names += [n for n in group if n]
        if org_name and fold_text(org_name) == fv:
            own, term_kind = True, "brand"
        if own:
            domains = own_domains
        else:
            for sup in getattr(org, "suppliers", ()):
                group = [_s(getattr(sup, "name", ""))] + [_s(b) for b in getattr(sup, "brands", ())]
                if fv in {fold_text(n) for n in group if n}:
                    term_kind = "supplier"
                    names += [n for n in group if n]
                    domains += [fold_text(d).lstrip("*.") for d in getattr(sup, "domains", ()) if d]
    terms = [_term(n, term_kind, own, domains, [], "seed") for n in _dedupe(names)]
    terms += [{"term": d, "kind": "domain", "own": own, "ambiguous": False, "domains": [], "context": [], "group": "seed"} for d in _dedupe(domains) if d]
    return terms


def _context_near(tokens: list[str], start: int, end: int, contexts: Any, window: int = 3) -> str | None:
    lo, hi = max(0, start - window), min(len(tokens), end + window)
    for ctx in contexts:
        n = len(ctx)
        for i in range(lo, hi - n + 1):
            if i < end and i + n > start:  # overlapping the hit itself
                continue
            if tuple(tokens[i:i + n]) == tuple(ctx):
                return " ".join(ctx)
    return None


def match_title(title: Any, terms: list[dict[str, Any]], feed_context: Any = ()) -> dict[str, Any] | None:
    """FC6/FC7: the best match of the terms in one headline ({term, kind, own, matched, why}) or None.

    CVE ids match exactly with a digit boundary; other terms accent-folded with word boundaries. Ambiguous
    terms need a context term within 3 tokens, a brand domain, another non-ambiguous alias of the group
    ('second_token') or the feed's own context words (DarkFeed titles are bare group names)."""
    folded = fold_text(title)
    upper = _DASHES.sub("-", _s(title)).upper()
    spans = [(m.group(0), m.start(), m.end()) for m in _TOKEN.finditer(folded)]
    tokens = [s[0] for s in spans]
    strong: dict[str, Any] | None = None
    pending = []
    for term in terms:
        if term.get("kind") == "cve":
            cve = _s(term.get("term")).upper()
            if re.search(r"(?<![0-9A-Z])" + re.escape(cve) + r"(?![0-9])", upper):
                return {"term": cve, "kind": "cve", "own": False, "matched": cve, "why": "cve_exact"}
            continue
        rx = _phrase_regex(fold_text(term.get("term")))
        m = rx.search(folded) if rx else None
        if not m:
            continue
        if not term.get("ambiguous"):
            hit = {"term": term["term"], "kind": term["kind"], "own": bool(term.get("own")), "matched": m.group(0),
                   "why": "domain" if term["kind"] == "domain" else "word"}
            if strong is None or (strong["kind"] == "domain" and hit["kind"] != "domain"):
                strong = hit
        else:
            pending.append((term, m))
    if strong is not None:
        return strong
    feed_words = [tuple(_TOKEN.findall(fold_text(c))) for c in _list(list(feed_context)) if _s(c).strip()]
    for term, m in pending:
        idx = [k for k, sp in enumerate(spans) if sp[1] >= m.start() and sp[2] <= m.end()]
        if not idx:
            continue
        contexts = THREAT_CONTEXT if term.get("kind") in ("actor", "malware") else COMPANY_CONTEXT
        why = None
        fc = next((w for w in feed_words if w in contexts), None)
        if fc:
            why = "feed_context:" + " ".join(fc)
        else:
            near = _context_near(tokens, idx[0], idx[-1] + 1, contexts)
            if near:
                why = "context:" + near
            else:
                for dom in _list(term.get("domains")):
                    if dom and re.search(r"(?<![0-9a-z.-])" + re.escape(dom) + r"(?![0-9a-z-])", folded):
                        why = "domain:" + dom
                        break
        if why:
            return {"term": term["term"], "kind": term["kind"], "own": bool(term.get("own")), "matched": m.group(0), "why": why}
    return None


def match_item(item: dict[str, Any], terms: list[dict[str, Any]], feed_context: Any = ()) -> dict[str, Any] | None:
    """match_title over the headline, plus exact CVE matching against the CVE ids read at ingest."""
    hit = match_title(item.get("title"), terms, feed_context)
    if hit:
        return hit
    cves = {_s(c).upper() for c in _list(item.get("cves"))}
    for term in terms:
        if term.get("kind") == "cve" and _s(term.get("term")).upper() in cves:
            cve = _s(term["term"]).upper()
            return {"term": cve, "kind": "cve", "own": False, "matched": cve, "why": "cve_exact:item"}
    return None


def classify_match(feed_kind: str, match: dict[str, Any]) -> dict[str, Any]:
    """FC8: INFO/LOW context, never raising risk alone; own organisation in dark-web/breach news is
    MEDIUM 'reported claim - verify', deduplicated against the ransomware-victim trackers."""
    own = bool(match.get("own"))
    if own and feed_kind in CLAIM_KINDS:
        return {"severity": "medium", "label": "reported claim - verify", "raises_risk": False, "dedupe_against": "ransomware_victim_trackers"}
    if own:
        return {"severity": "low", "label": "own organisation mentioned in news - context", "raises_risk": False, "dedupe_against": None}
    return {"severity": "info", "label": "mentioned in CTI news - context", "raises_risk": False, "dedupe_against": None}


_COMPANY_SUFFIX_TOKENS = frozenset({"sa", "ltda", "me", "eireli", "inc", "corp", "corporation", "llc", "ltd", "plc", "gmbh", "ag",
                                    "group", "grupo", "holding", "co", "cia", "company", "companhia"})


def claim_dedupe_key(name_or_domain: Any) -> str:
    """FC8 dedupe key shared with the ransomware-victim trackers: a domain -> host without 'www.'; a name ->
    accent-folded tokens without company suffixes ('S.A.', 'Ltda', 'Inc', 'Grupo'...) and punctuation."""
    text = fold_text(name_or_domain).strip()
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,24}", text):
        return text[4:] if text.startswith("www.") else text
    toks = _TOKEN.findall(text)
    out, i = [], 0
    while i < len(toks):
        if toks[i] == "s" and i + 1 < len(toks) and toks[i + 1] == "a":
            i += 2
            continue
        if toks[i] not in _COMPANY_SUFFIX_TOKENS:
            out.append(toks[i])
        i += 1
    return " ".join(out)


# ------------------------------------------------------------------------------------------ item store (FC5)


def _storable(item: dict[str, Any]) -> bool:
    """ctx.state refuses personal identifiers: headlines quoting an e-mail address are not kept."""
    return not _EMAILISH.search(_s(item.get("title")))


def merge_items(stored: list[dict[str, Any]], fresh: list[dict[str, Any]], now: datetime) -> list[dict[str, Any]]:
    """Union by link (fresh wins), undated items get first_seen=now, 180-day retention, newest N kept."""
    by_link: dict[str, dict[str, Any]] = {}
    for item in stored:
        if isinstance(item, dict) and item.get("link"):
            by_link[item["link"]] = item
    stamp = iso_utc(now)
    for item in fresh:
        old = by_link.get(item["link"], {})
        row = {"title": item["title"], "link": item["link"], "published": item.get("published"), "cves": item.get("cves") or []}
        if not row["published"]:
            row["first_seen"] = old.get("first_seen") or stamp
        by_link[item["link"]] = row
    kept = prune_items([i for i in by_link.values() if _storable(i)], now)
    return recent_headlines(kept, STORE_ITEMS_PER_FEED)


def doctor_health(ctx: Any) -> dict[str, dict[str, Any]]:
    """FC9 per-feed health for doctor/coverage from local data only: curated state, local copy, newest stored item."""
    now = ctx.now()
    out: dict[str, dict[str, Any]] = {}
    for fid, feed in FEEDS.items():
        row: dict[str, Any] = {"tier": feed.get("tier"), "label": feed.get("label") or feed.get("tier")}
        if (feed.get("health") or {}).get("state") == "blocked":
            out[fid] = dict(row, state="blocked", reason="anti-bot challenge recorded in the curated list (never fetched)")
            continue
        info = ctx.data.info(dataset_name(fid))
        if not info.present:
            out[fid] = dict(row, state="missing", reason=f"not downloaded: run v3lum data update {dataset_name(fid)}")
            continue
        try:
            stored = ctx.state.get(f"feed_{fid}") or {}
        except StateError:
            stored = {}
        items = [i for i in _list(stored.get("items") if isinstance(stored, dict) else None) if isinstance(i, dict)]
        health = feed_health({"status": "ok", "items": items}, now) if items else {"state": "ok", "newest_item": None, "age_days": None}
        out[fid] = dict(row, **health, copy_age_hours=info.age_hours, copy_stale=bool(info.stale))
    return out


def _feeds_selftest(ctx: Any) -> HealthResult:
    rows = doctor_health(ctx)
    present = [f for f, r in rows.items() if r["state"] not in ("missing", "blocked")]
    if not present:
        return HealthResult("dead", "no CTI feed copy is present: run v3lum data update (feeds stay disabled until legal review)")
    summary = ", ".join(f"{f}={r['state']}" for f, r in sorted(rows.items()))
    return HealthResult("ok", f"{len(present)}/{len(rows)} feeds present: {summary}")


# ------------------------------------------------------------------------------------------ module


@register
class CtiNewsRss(Module):
    name = "cti_news_rss"
    title = "CTI news / advisory feed watcher"
    description = (
        "Headline-only, offline matching of a company, actor, malware family, CVE or keyword against a local cache of "
        "curated security-news, dark-web-news, breach-news and CERT advisory feeds (The Record, BleepingComputer, DFIR "
        "Report, Krebs, Help Net Security, Dark Reading, CyberScoop, Schneier, DarkFeed, Dark Web Informer, ICHI, "
        "DataBreaches.net, CERT.br). No watched name leaves the machine."
    )
    category = "cti_framework"
    accepts = {T.ORG, T.THREAT_ACTOR, T.MALWARE, T.CVE, T.KEYWORD}
    produces = {T.URL}
    tags = {"offline", "free"}
    reference = "https://therecord.media/feed"
    notice = (
        "Feed terms are unknown until legal records the feed-reader decision (A1): off in every profile and every feed "
        "disabled in v3lum/data/cti_news_rss/cti_feeds.json. Headline + link + date only; no article text is stored. "
        "Matches are context, never a confirmed incident."
    )
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    provider = ""
    sources = FEED_SOURCES
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.05
    timeout = 60.0
    max_pivots = MAX_URL_PIVOTS
    default_enabled = False
    settings = {
        "cti_news_rss_feeds": SettingSpec(
            [], "feed ids of v3lum/data/cti_news_rss/cti_feeds.json to read; empty = the feeds the list enables (P298 cond 3)"
        ),
        "cti_news_rss_refresh_budget": SettingSpec(REFRESH_BUDGET_S, "seconds a run may spend refreshing stale feeds (P298 cond 4)"),
    }

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=True, selftest=_feeds_selftest)

    # ---- feed selection -----------------------------------------------------------------------------
    @staticmethod
    def selected_feeds(ctx: Any) -> list[dict[str, Any]]:
        wanted = ctx.setting("cti_news_rss_feeds", []) or []
        if isinstance(wanted, str):
            wanted = [w.strip() for w in wanted.split(",") if w.strip()]
        if wanted:
            return [FEEDS[f] for f in wanted if f in FEEDS]
        return [f for f in FEEDS.values() if f.get("enabled") is True]

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        feeds = self.selected_feeds(ctx)
        if not feeds:
            return res.mark(
                "skipped",
                "no CTI feed is enabled: feed terms are unknown until legal records the feed-reader decision (P298 cond 3); "
                "select feeds explicitly with setting cti_news_rss_feeds",
                reason_code="licence",
            )
        terms = watch_terms(entity, getattr(ctx, "org", None))
        if not terms:
            return res.mark("skipped", "nothing to match for this value", reason_code="not_applicable")
        allowed = getattr(ctx, "allowed_sources", None)
        now = ctx.now()
        try:
            budget = max(0.0, float(ctx.setting("cti_news_rss_refresh_budget", REFRESH_BUDGET_S)))
        except (TypeError, ValueError):
            budget = REFRESH_BUDGET_S
        started = time.monotonic()
        health: dict[str, dict[str, Any]] = {}
        corpus: list[tuple[dict[str, Any], dict[str, Any]]] = []
        answered = 0
        failures: list[str] = []
        for feed in feeds:
            if allowed is not None and feed["source"] not in allowed:
                continue  # the policy gate reports these (reason licence)
            row = {"tier": feed.get("tier"), "label": feed.get("label") or feed.get("tier"), "kind": feed.get("kind")}
            items, problem = self._feed_items(feed, ctx, now, refresh=time.monotonic() - started <= budget)
            if problem is not None:
                state, code, reason = problem
                row.update(state=state, reason=reason)
                health[feed["id"]] = row
                status = Status.BLOCKED if state == "blocked" else (Status.UNAVAILABLE if state in ("missing", "not_refreshed") else Status.ERROR)
                res.source_status(feed["source"], status, reason_code=code, reason=f"{feed['id']}: {reason}: could not verify")
                failures.append(state)
                continue
            answered += 1
            row.update(feed_health({"status": "ok", "items": items}, now) if items else {"state": "ok", "newest_item": None, "age_days": None})
            row["items"] = len(items)
            health[feed["id"]] = row
            corpus.extend((feed, item) for item in items)
        res.attr("cti_feed_health", health)
        if answered == 0:
            if failures and all(f == "blocked" for f in failures):
                return res.mark("blocked", "every selected CTI feed was blocked (challenge): could not verify", reason_code="challenge")
            if failures and all(f in ("missing", "not_refreshed") for f in failures):
                return res.mark("unavailable", "no local copy of the selected CTI feeds: run v3lum data update", reason_code="dataset")
            return res.mark("error", "no selected CTI feed could be read: could not verify")
        mentions = []
        for feed, item in corpus:
            hit = match_item(item, terms, feed.get("context") or ())
            if hit:
                mentions.append((feed, item, hit))
        mentions.sort(key=lambda m: (m[1].get("published") or m[1].get("first_seen") or "", m[1]["title"]), reverse=True)
        res.raw = {"terms": [t["term"] for t in terms], "feeds_read": answered, "items_scanned": len(corpus), "matches": len(mentions)}
        if not mentions:
            return res.mark("empty", f"no headline of the {answered} feed(s) read names {clean_text(entity.value, 80)} (headline-only matching)")
        rows = []
        for feed, item, hit in mentions[:MAX_MENTIONS]:
            cls = classify_match(feed.get("kind"), hit)
            rows.append({k: v for k, v in {
                "feed": feed["id"], "source": feed["source"], "title": item["title"], "link": item["link"],
                "published": item.get("published") or item.get("first_seen"), "matched": hit["matched"], "why": hit["why"],
                "kind": feed.get("kind"), "label": feed.get("label"), "severity": cls["severity"],
            }.items() if v})
        res.attr("cti_news_mentions", rows)
        for feed, item, _hit in mentions[:TERMINAL_HEADLINES]:
            res.link(f"{(item.get('published') or item.get('first_seen') or '')[:10]} {feed.get('name') or feed['id']}: {clean_text(item['title'], 120)}", item["link"])
        for _feed, item, _hit in mentions[:MAX_URL_PIVOTS]:
            res.pivot(T.URL, item["link"], "mentioned_in_news", confidence="possible", expand=False,
                      note="news headline naming the value: article not fetched, not investigated")
        ranked = sorted(mentions, key=lambda m: {"medium": 0, "low": 1, "info": 2}[classify_match(m[0].get("kind"), m[2])["severity"]])
        for feed, item, hit in ranked[:MAX_FINDINGS]:
            self._finding(res, entity, feed, item, hit)
        return res

    # ---- per-feed items -----------------------------------------------------------------------------
    def _feed_items(self, feed: dict[str, Any], ctx: Any, now: datetime, *, refresh: bool) -> tuple[list[dict[str, Any]], tuple[str, str, str] | None]:
        """Items of one feed from the local store, refreshed from its dataset; or (state, reason_code, reason)."""
        fid = feed["id"]
        if (feed.get("health") or {}).get("state") == "blocked":
            return [], ("blocked", "challenge", "anti-bot challenge recorded in the curated feed list: never fetched (rule 1, A9); manual link only")
        name = dataset_name(fid)
        try:
            if refresh:
                path = ctx.data.fetch(name)
            else:
                info = ctx.data.info(name)
                if not info.present:
                    return [], ("not_refreshed", "dataset", f"not refreshed within the {REFRESH_BUDGET_S:.0f} s budget and no local copy")
                path = ctx.data.fetch(name, ttl=10 ** 9)  # serve the local copy as it is
            info = ctx.data.info(name)
        except DatasetUnavailable as exc:
            return [], ("missing", "dataset", str(exc)[:200])
        except DatasetError as exc:
            code = str(getattr(exc, "reason_code", "") or "error")
            if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host"):
                return [], ("blocked", code, str(exc)[:200])
            return [], ("error", "timeout" if code == "timeout" else "error", str(exc)[:200])
        key = f"feed_{fid}"
        try:
            stored = ctx.state.get(key) or {}
        except StateError:
            stored = {}
        stored = stored if isinstance(stored, dict) else {}
        items = [i for i in _list(stored.get("items")) if isinstance(i, dict)]
        if stored.get("sha") != info.sha256:
            try:
                with open(path, "rb") as fh:
                    parsed = parse_feed(fh.read(FEED_MAX_BYTES + 1), fid, max_items=int(feed.get("max_items") or FEED_MAX_ITEMS))
            except OSError as exc:
                return [], ("error", "error", f"local copy unreadable ({str(exc)[:80]})")
            if parsed["status"] == "error":
                return [], ("error", "error", parsed["reason"] or "unparseable feed")
            items = merge_items(items, parsed["items"], now)
            try:
                ctx.state.set(key, {"sha": info.sha256, "items": items})
            except StateError as exc:  # keep working from memory: the next run re-parses the copy
                ctx.log(f"cti_news_rss: item store for {fid} not saved ({str(exc)[:100]})", "warning")
        else:
            items = prune_items(items, now)
        return items, None

    def _finding(self, res: ModuleResult, entity: Entity, feed: dict[str, Any], item: dict[str, Any], hit: dict[str, Any]) -> None:
        cls = classify_match(feed.get("kind"), hit)
        tags = ["reported_claim"] if cls["severity"] == "medium" else ["context_only"]
        if feed.get("tier") == "unknown":
            tags.append("unverified_source")
        published = item.get("published") or item.get("first_seen")
        title = "Reported claim names the organisation in dark-web/breach news - verify" if cls["severity"] == "medium" else (
            "Own organisation named in a CTI news headline" if cls["severity"] == "low" else "Named in a CTI news headline")
        description = (f"{feed.get('name') or feed['id']} ({feed.get('label') or feed.get('tier')}): '{clean_text(item['title'], 200)}' "
                       f"({(published or 'undated')[:10]}; matched '{hit['matched']}' by {hit['why']}). {cls['label']}: headline only, "
                       "never a confirmed incident.")
        res.finding(
            title,
            cls["severity"],
            description,
            confidence="possible",
            criterion=(f"headline match ({hit['why']}) in feed {feed['id']} of kind {feed.get('kind')}: {cls['label']}"
                       if cls["severity"] != "info" else ""),
            tags=tags,
            references=[item["link"]],
            source=feed["source"],
            observed_last=published,
            key=hashlib.sha256(item["link"].encode("utf-8")).hexdigest()[:16],
            data={"feed": feed["id"], "why": hit["why"], "raises_risk": False, "dedupe_against": cls["dedupe_against"],
                  "claim_key": claim_dedupe_key(entity.value) if cls["dedupe_against"] else None},
        )
