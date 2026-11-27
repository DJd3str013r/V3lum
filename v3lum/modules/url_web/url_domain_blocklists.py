"""Downloadable phishing / malicious domain and URL lists matched locally (P071, batch p1-G03-1).

Feeds (one registry source each, terms per feed - P071 cond 2-5):

=====================  ==========================================  ==============  =================
feed                   source (provider.source)                    terms           category
=====================  ==========================================  ==============  =================
CERT.PL Hole           cert_pl.hole_domains                        open (trusted)  phishing
Phishing.Database      github.url_domain_blocklists_phishing_*     open (MIT)      phishing
OpenPhish community    openphish.community_feed                    noncommercial   phishing
Phishing Army          phishing_army.blocklist                     noncommercial   phishing
HaGeZi TIF             github.url_domain_blocklists_hagezi_tif     open (GPL-3.0)  aggregate (tag)
StevenBlack hosts      github.url_domain_blocklists_stevenblack    open (MIT)      ads_tracking (tag)
Botvrij.eu             botvrij.blocklist_full                      open            malicious
ScamSniffer            github.url_domain_blocklists_scamsniffer    open (GPL-3.0)  crypto_scam
MetaMask config        github.url_domain_blocklists_metamask       open (DBAD)     crypto_scam
spmedia                github.url_domain_blocklists_spmedia        open (MIT)      crypto_scam
PhishTank dump         phishtank.online_valid                      open            phishing (off)
Procon-SP              procon_sp.evite_sites                       open (trusted)  fraud_store
CyberCrime-Tracker     cybercrime_tracker.panel_list               open            c2 (module
                                                                                   url_domain_blocklists_c2)
=====================  ==========================================  ==============  =================

The module's terms are the most restrictive class, ``noncommercial`` (OpenPhish and Phishing Army):
under the corporate profile the policy gate removes those two sources from ``ctx.allowed_sources``
(the module uses only allowed feeds) and the others run. OpenPhish additionally needs setting
``url_domain_blocklists_openphish_consent_ref`` (the legal reference of OpenPhish's written consent or
paid feed) under EVERY profile (cond 3). CyberCrime-Tracker's provider is tier ``unknown``: its feed
lives in the separate, non-default class ``url_domain_blocklists_c2`` (A3) until a community
promotion is recorded.

Index (cond 1): one on-disk SQLite index ``<datasets>/.index/url_domain_blocklists.v1.sqlite`` maps
host / FQDN keys (table ``dom``), exact normalised URL keys (``url``) and hosts of URL entries
(``urlhost``) to a per-feed bitmask, with per-entry listing data (``info``), removal history from
snapshot diffs (``removed``), MetaMask white/fuzzy lists (``aux``) and per-dataset provenance
(``feed_meta``: sha256, count, built_at). It is (re)built by each dataset's validator when
``v3lum data update`` installs a new copy (every feed is registered ``large=True``: never fetched
mid-scan, A6); a lookup reads a handful of keys and never loads a list into memory. A copy whose index
is missing or outdated (upgrade, deleted index) is re-indexed from the local file: synchronously below
5 MB, in a background thread above (that feed reads 'not checked' until it is done).

Verdict scope (cond 6): URL-list entries match the exact normalised URL; they flag the host only when
it is not a shared platform (path-based platforms such as sites.google.com, docs.google.com,
*.sharepoint.com, file sharing and shorteners; PSL private-suffix tenants; protected popular domains)
and never its parents. Domain lists match the FQDN and its parents up to the registrable domain (PSL,
private suffixes included), never a public suffix, never a protected parent, and never at all for
hosts on path-based platforms. Fidelity (cond 7): phishing MEDIUM for one list, HIGH with CERT.PL or
>= 2 independent upstream families (P171: own family + embeds); c2 HIGH; crypto_scam MEDIUM;
ads/tracking and aggregate lists LOW, tag only, never 'phishing'. Hits carry the list name, the listing
date when the feed has one and the copy's fetch date; listings older than 30 days, removed entries and
frozen lists (Botvrij) are historical (cond 8). Missing, stale or unindexed lists read 'not checked'
(UNAVAILABLE 'dataset' per feed), never 'not listed'. Matching is local: ``disclosure='none'``,
allowed at TLP:RED (cond 10).
"""

from __future__ import annotations

import csv
import functools
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import threading
import urllib.parse
from importlib import resources
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from v3lum import paths
from v3lum.core import noise as _noise
from v3lum.core import psl as _psl
from v3lum.core.datasets import DataStore, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

__all__ = [
    "FEEDS",
    "INDEX_FILE",
    "PATH_PLATFORMS",
    "BlocklistIndex",
    "UrlDomainBlocklists",
    "UrlDomainBlocklistsC2",
    "domain_lookup_keys",
    "host_scope",
    "index_part",
    "url_key",
]

INDEX_SCHEMA = 1
INDEX_FILE = f"url_domain_blocklists.v{INDEX_SCHEMA}.sqlite"
#: datasets at or below this size are re-indexed synchronously during a scan; larger ones in the background
SYNC_REINDEX_BYTES = 5 * 1024 * 1024
#: listings older than this are historical (cond 8)
HISTORICAL_DAYS = 30
#: removal history kept from snapshot diffs
REMOVED_KEEP_DAYS = 180
MAX_HITS_SHOWN = 50
PROCON_MANUAL_URL = "https://sistemas.procon.sp.gov.br/evitesite/list/evitesites.php"
UTC = timezone.utc

# =============================================================================================
# feed catalogue
# =============================================================================================


@dataclass(frozen=True)
class Part:
    """One downloadable dataset of a feed (a feed may have a domain list and a URL list)."""

    dataset: str
    url: str
    parser: str  # domains | hosts | hagezi | phishing_army | certpl_csv | botvrij | scamsniffer | metamask | spmedia | urls | cybercrime | procon
    tables: tuple[str, ...]  # index tables this part writes ('dom', 'url'+'urlhost')
    licence: str
    attribution: str
    expect: str = "text"
    min_bytes: int = 1
    max_bytes: int = 64 * 1024 * 1024
    ttl_h: float = 12.0
    source: str = ""  # registry source of this dataset when it differs from the feed's primary source
    essential: bool = False  # fetched by `v3lum data update --essential`


@dataclass(frozen=True)
class Feed:
    id: str
    bit: int
    list_name: str
    source: str
    category: str  # phishing | c2 | crypto_scam | fraud_store | malicious | ads_tracking | aggregate
    parts: tuple[Part, ...]
    stale_h: float | None  # beyond this age the feed reads 'not checked' (None: never stale)
    module: str = "main"  # 'main' (url_domain_blocklists) or 'c2' (url_domain_blocklists_c2)
    frozen: bool = False  # the list stopped changing: every hit is historical
    track_removals: bool = False  # keep removal history from snapshot diffs (CERT.PL)
    needs_consent: bool = False  # OpenPhish (cond 3)
    disabled_reason: str = ""  # PhishTank (cond 5): disabled in this build
    manual_url: str = ""


_GH = "https://raw.githubusercontent.com/"
_ATTR_MIT = "MIT licence; attribution in the notice fragment of the feed"

FEEDS: dict[str, Feed] = {f.id: f for f in (
    Feed("certpl", 0, "CERT.PL warning list", "cert_pl.hole_domains", "phishing", (
        Part("url_domain_blocklists.certpl.csv", "https://hole.cert.pl/domains/v2/domains.csv", "certpl_csv", ("dom",),
             "CERT Polska public warning list (any use incl. commercial, attribution)", "CERT Polska (NASK) - Lista Ostrzezen, hole.cert.pl",
             min_bytes=200_000, ttl_h=6, essential=True),), stale_h=72, track_removals=True),
    Feed("phishing_database", 1, "Phishing.Database", "github.url_domain_blocklists_phishing_database_domains", "phishing", (
        Part("url_domain_blocklists.phishing_database.domains.txt", _GH + "Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
             "domains", ("dom",), "MIT", "Phishing.Database (Mitchell Krog and the Phishing.Database safekeepers), MIT", min_bytes=500_000,
             essential=True),
        Part("url_domain_blocklists.phishing_database.links.txt", _GH + "Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt",
             "urls", ("url", "urlhost"), "MIT", "Phishing.Database (Mitchell Krog and the Phishing.Database safekeepers), MIT",
             min_bytes=1_000_000, max_bytes=256 * 1024 * 1024, source="github.url_domain_blocklists_phishing_database_links"),
    ), stale_h=72),
    Feed("openphish", 2, "OpenPhish community feed", "openphish.community_feed", "phishing", (
        Part("url_domain_blocklists.openphish.txt", _GH + "openphish/public_feed/refs/heads/main/feed.txt", "urls", ("url", "urlhost"),
             "OpenPhish Community Feed terms (non-commercial; organisational use needs OpenPhish's written consent)",
             "OpenPhish community feed (openphish.com)", min_bytes=1_000),), stale_h=48, needs_consent=True),
    Feed("phishing_army", 3, "Phishing Army", "phishing_army.blocklist", "phishing", (
        Part("url_domain_blocklists.phishing_army.txt", "https://phishing.army/download/phishing_army_blocklist.txt", "phishing_army", ("dom",),
             "CC BY-NC 4.0 (non-commercial; runtime download only)", "Phishing Army (phishing.army), CC BY-NC 4.0", min_bytes=50_000, ttl_h=6),),
         stale_h=48),
    Feed("hagezi_tif", 4, "HaGeZi Threat Intelligence Feeds", "github.url_domain_blocklists_hagezi_tif", "aggregate", (
        Part("url_domain_blocklists.hagezi_tif.txt", _GH + "hagezi/dns-blocklists/main/wildcard/tif.txt", "hagezi", ("dom",),
             "GPL-3.0 (runtime download only, never bundled)", "HaGeZi DNS blocklists - Threat Intelligence Feeds, GPL-3.0",
             min_bytes=1_000_000),), stale_h=168),
    Feed("stevenblack", 5, "StevenBlack unified hosts", "github.url_domain_blocklists_stevenblack", "ads_tracking", (
        Part("url_domain_blocklists.stevenblack.hosts", _GH + "StevenBlack/hosts/master/hosts", "hosts", ("dom",), "MIT",
             "StevenBlack/hosts unified hosts file, MIT (aggregated sources keep their licences)", min_bytes=200_000),), stale_h=168),
    Feed("botvrij", 6, "Botvrij.eu blocklist", "botvrij.blocklist_full", "malicious", (
        Part("url_domain_blocklists.botvrij.csv", "https://www.botvrij.eu/data/blocklist/blocklist_full.csv", "botvrij", ("dom",),
             "Botvrij.eu public blocklist (free, attribution)", "Botvrij.eu blocklist (botvrij.eu)", min_bytes=50_000, ttl_h=12),),
         stale_h=None, frozen=True),
    Feed("cybercrime_tracker", 7, "CyberCrime-Tracker", "cybercrime_tracker.panel_list", "c2", (
        Part("url_domain_blocklists.cybercrime_tracker.txt", "https://cybercrime-tracker.net/all.php", "cybercrime", ("url", "urlhost"),
             "CyberCrime-Tracker public list (free, attribution)", "CyberCrime-Tracker (cybercrime-tracker.net)", min_bytes=20_000),),
         stale_h=72, module="c2"),
    Feed("scamsniffer", 8, "ScamSniffer scam database", "github.url_domain_blocklists_scamsniffer", "crypto_scam", (
        Part("url_domain_blocklists.scamsniffer.domains.json", _GH + "scamsniffer/scam-database/main/blacklist/domains.json", "scamsniffer", ("dom",),
             "GPL-3.0 (runtime download only, never bundled)", "ScamSniffer scam-database (domains.json), GPL-3.0", expect="json",
             min_bytes=500_000),), stale_h=240),
    Feed("metamask", 9, "MetaMask eth-phishing-detect", "github.url_domain_blocklists_metamask", "crypto_scam", (
        Part("url_domain_blocklists.metamask.config.json", _GH + "MetaMask/eth-phishing-detect/main/src/config.json", "metamask", ("dom",),
             "Don't Be A Dick Public License (permissive)", "MetaMask eth-phishing-detect configuration (DBAD licence)", expect="json",
             min_bytes=100_000, essential=True),), stale_h=168),
    Feed("spmedia", 10, "spmedia crypto scam feed", "github.url_domain_blocklists_spmedia", "crypto_scam", (
        Part("url_domain_blocklists.spmedia.txt", _GH + "spmedia/Crypto-Scam-and-Crypto-Phishing-Threat-Intel-Feed/main/detected_urls.txt", "spmedia",
             ("dom",), "MIT", "spmedia Crypto Scam and Crypto Phishing Threat Intel Feed, MIT", min_bytes=2_000, essential=True),), stale_h=168),
    Feed("phishtank", 11, "PhishTank verified phishes", "phishtank.online_valid", "phishing", (), stale_h=48,
         disabled_reason="PhishTank dump disabled: keyless downloads are unavailable (302 -> signed CDN URL -> 404, 2026-11-26), app-key "
                         "registration is closed and the dataset manager has no key-templated dataset URL yet (backlog)"),
    Feed("procon_sp", 12, "Procon-SP 'Evite estes sites'", "procon_sp.evite_sites", "fraud_store", (
        Part("url_domain_blocklists.procon_sp.json",
             "https://sistemas.procon.sp.gov.br/evitesite/list/evitesite.php?action=list&jtStartIndex=0&jtPageSize=1000", "procon", ("dom",),
             "Procon-SP public consumer-protection notice (attribution)", "Fundacao Procon-SP - 'Evite estes sites'", min_bytes=10, ttl_h=12),),
         stale_h=24 * 30, manual_url=PROCON_MANUAL_URL),
)}
PARTS: dict[str, tuple[Feed, Part]] = {p.dataset: (f, p) for f in FEEDS.values() for p in f.parts}
_BITS = {f.bit for f in FEEDS.values()}
assert len(_BITS) == len(FEEDS), "feed bits must be unique"


# =============================================================================================
# normalisation and scope (cond 6)
# =============================================================================================
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$")


def normalise_host(host: Any) -> str | None:
    """Lower-case, strip brackets/trailing dot, IDNA -> punycode; IP literals kept; None if invalid."""
    if not host or not isinstance(host, str):
        return None
    h = host.strip().strip("[]").rstrip(".").lower()
    if not h:
        return None
    try:
        return ipaddress.ip_address(h).compressed
    except ValueError:
        pass
    if any(ord(c) > 127 for c in h):
        try:
            h = h.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return h if _HOST_RE.match(h) else None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _split(url: Any) -> dict[str, Any] | None:
    if not url or not isinstance(url, str):
        return None
    u = url.strip().replace("&amp;", "&")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        u = ("http:" + u) if u.startswith("//") else ("http://" + u)
    try:
        parts = urllib.parse.urlsplit(u)
        port = parts.port
    except ValueError:
        return None
    host = normalise_host(parts.hostname or "")
    if host is None:
        return None
    return {"host": host, "port": port, "path": parts.path or "", "query": parts.query}


def url_key(url: Any) -> str | None:
    """Normalised, scheme-less match key ``host[:port]/path[?query]`` for exact URL matching: lower-case
    host, no userinfo, no default port, no fragment, no bare trailing '/'; path and query keep their
    case; one level of HTML '&amp;' is unescaped."""
    s = _split(url) if isinstance(url, str) else None
    if s is None:
        return None
    port = s["port"] if s["port"] not in (80, 443) else None
    host = f"[{s['host']}]" if ":" in s["host"] else s["host"]
    key = host + (f":{port}" if port else "") + (s["path"] or "/")
    if s["query"]:
        key += "?" + s["query"]
    if key.endswith("/") and key.count("/") == 1:
        key = key[:-1]
    return key


#: path-based shared platforms: one host serves many unrelated users (sites, documents, forms, files,
#: short links). A listing there is URL-level only: no host or domain verdict, ever (cond 6). Each
#: entry also covers its subdomains (79.docs.google.com, <tenant>.sharepoint.com).
PATH_PLATFORMS: frozenset[str] = frozenset({
    "sites.google.com", "docs.google.com", "drive.google.com", "script.google.com", "forms.gle", "storage.googleapis.com",
    "storage.cloud.google.com", "firebasestorage.googleapis.com", "plus.google.com", "appengine.google.com", "translate.goog",
    "sharepoint.com", "sharepoint-df.com", "onedrive.live.com", "1drv.ms", "forms.office.com", "forms.microsoft.com", "sway.office.com",
    "sway.cloud.microsoft", "dropbox.com", "dl.dropboxusercontent.com", "github.com", "gist.github.com", "raw.githubusercontent.com",
    "objects.githubusercontent.com", "gitlab.com", "bitbucket.org", "canva.com", "linktr.ee", "wetransfer.com", "we.tl", "mega.nz",
    "mediafire.com", "ipfs.io", "cloudflare-ipfs.com", "dweb.link", "s3.amazonaws.com", "cdn.discordapp.com", "media.discordapp.net",
    "telegra.ph", "bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "rebrand.ly", "ow.ly", "goo.gl", "rb.gy", "shorturl.at", "s.id",
    "t.ly", "tiny.cc", "notion.site", "jotform.com", "typeform.com", "wix.com", "weebly.com", "google.com", "microsoft.com",
    "live.com", "office.com", "outlook.com", "apple.com", "amazon.com", "facebook.com", "instagram.com", "linkedin.com",
    "youtube.com", "twitter.com", "x.com", "whatsapp.com", "yahoo.com", "baidu.com", "wikipedia.org", "cloudflare.com",
})
_PROTECTED_LIST_RE = re.compile(r"(?i)tranco|top.?1?0+k|top.?1m|alexa|majestic|umbrella|cisco.?top|cloudflare.?(?:top|radar)|crux")


def _label_suffix(host: str, entries: Iterable[str]) -> bool:
    return any(host == e or host.endswith("." + e) for e in entries)


#: generic second-level labels of ICANN country suffixes (fallback heuristic only, see _private_tenant)
_GENERIC_SLD = frozenset({
    "com", "net", "org", "gov", "edu", "co", "ac", "ne", "or", "go", "mil", "gob", "nic", "int", "info", "biz", "ltd", "plc", "nom",
    "sch", "web", "ind", "firm", "gen", "art", "pro", "med", "law", "eco", "tv", "in", "res", "ed", "lg", "gr", "ad", "nhs", "police",
    "mod", "school", "k12", "lib", "blog", "tur", "adv", "eng", "agr", "jus", "leg", "mus", "ong", "ngo", "per", "rec", "store",
})


def _ascii_rule(rule: str) -> str:
    out = []
    for label in rule.split("."):
        if label == "*":
            out.append(label)
            continue
        try:
            out.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            out.append(label)
    return ".".join(out).lower()


@functools.lru_cache(maxsize=1)
def _psl_private() -> tuple[frozenset[str], frozenset[str]]:
    """(exact, wildcard) rules of the PSL PRIVATE section of the bundled list. The bundled copy is stripped
    of comments, so the ===BEGIN PRIVATE DOMAINS=== marker is gone: the PSL lists the ICANN section first
    and ends it with the single-label gTLDs, so the private section is every rule after the last
    single-label rule (the marker is used when present)."""
    try:
        text = resources.files("v3lum.data").joinpath("public_suffix_list.dat").read_text(encoding="utf-8")
    except (OSError, ModuleNotFoundError):
        return frozenset(), frozenset()
    lines = [ln.strip() for ln in text.splitlines()]
    start = next((i + 1 for i, ln in enumerate(lines) if "===BEGIN PRIVATE DOMAINS===" in ln), None)
    if start is None:
        singles = [i for i, ln in enumerate(lines) if ln and not ln.startswith("//") and "." not in ln]
        if not singles:
            return frozenset(), frozenset()
        start = singles[-1] + 1
    exact: set[str] = set()
    wild: set[str] = set()
    for ln in lines[start:]:
        if "===END PRIVATE DOMAINS===" in ln:
            break
        if not ln or ln.startswith(("//", "!")):
            continue
        rule = _ascii_rule(ln)
        if rule.startswith("*."):
            wild.add(rule[2:])
        else:
            exact.add(rule)
    return frozenset(exact), frozenset(wild)


def _private_tenant(host: str) -> bool:
    """True when ``host`` sits under a suffix of the PSL PRIVATE section (pages.dev, github.io,
    *.r.appspot.com...): a platform tenant, not an ICANN registration (com.br, k12.ca.us, sp.gov.br stay
    ordinary). Without a usable private section, a multi-label suffix under a gTLD or with a
    non-generic label counts as private (heuristic fallback)."""
    if _is_ip(host):
        return False
    suffix = _psl.public_suffix(host)
    if host == suffix or "." not in suffix:
        return False
    exact, wild = _psl_private()
    if exact or wild:
        return suffix in exact or suffix.split(".", 1)[1] in wild
    labels = suffix.split(".")
    if len(labels[-1]) > 2:
        return True
    return any(label not in _GENERIC_SLD for label in labels[:-1])


@functools.lru_cache(maxsize=1)
def _extra_shared() -> frozenset[str]:
    """Hosts of P010's data/shared_platforms.json when present (free hosting, dynamic DNS, shorteners...)."""
    if not DataStore.bundled_exists("shared_platforms.json"):
        return frozenset()
    try:
        data = DataStore.bundled_json("shared_platforms.json")
    except (OSError, ValueError):
        return frozenset()
    out: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, str):
            h = normalise_host(value.lstrip("*."))
            if h:
                out.add(h)
        elif isinstance(value, dict):
            for v in value.values():
                walk(v)
        elif isinstance(value, list):
            for v in value:
                walk(v)

    walk(data)
    return frozenset(out)


def _protected(domain: str, extra: Iterable[str] = ()) -> bool:
    """A popular domain whose parents never inherit a listing (core noise lists, top-site warninglists)."""
    if _label_suffix(domain, extra):
        return True
    ent = Entity.try_make(T.DOMAIN, domain)
    if ent is None:
        return False
    try:
        if _noise.is_noise(ent):
            return True
        return any(_PROTECTED_LIST_RE.search(name) for name in _noise.warninglists(ent))
    except Exception:  # noqa: BLE001 - noise data problems never break matching
        return False


def host_scope(host: str, extra_protected: Iterable[str] = ()) -> str:
    """'platform' (path-based shared platform: URL-level verdicts only), 'tenant' (PSL private suffix or a
    shared-hosting list entry: URL listings never propagate to the host), 'protected' (popular domain)
    or '' (an ordinary host)."""
    h = normalise_host(host) or ""
    if not h:
        return "platform"
    if _label_suffix(h, PATH_PLATFORMS):
        return "platform"
    if _private_tenant(h) or _label_suffix(h, _extra_shared()):
        return "tenant"
    reg = h if _is_ip(h) else (_psl.registrable_domain(h) or h)
    if _protected(reg, extra_protected):
        return "protected"
    return ""


def domain_lookup_keys(host: str, extra_protected: Iterable[str] = ()) -> list[str]:
    """Keys to look up in DOMAIN lists: the FQDN and its parents up to the registrable domain (PSL with
    private suffixes), never a public suffix, never a protected parent, nothing for path platforms."""
    h = normalise_host(host)
    if not h:
        return []
    if _is_ip(h):
        return [h]
    if _label_suffix(h, PATH_PLATFORMS):
        return []
    reg = _psl.registrable_domain(h)
    if reg is None:
        return []
    labels = h.split(".")
    keys: list[str] = []
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if i > 0 and _protected(cand, extra_protected):
            break
        keys.append(cand)
        if cand == reg:
            break
    return keys


# =============================================================================================
# feed parsers (streaming; each yields (kind, key, host, info) with kind 'dom' | 'url')
# =============================================================================================
Entry = tuple[str, str, str, "dict[str, Any] | None"]
_PHISHING_ARMY_TEST = frozenset({"amiprotected.it", "www.amiprotected.it"})
_HOSTS_SKIP = frozenset({"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
                         "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0"})
CC_PATH_HINTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)/fre\.php$"), "LokiBot-style gate (fre.php)"),
    (re.compile(r"(?i)/PvqDq929BSx_A_D_M1n_a\.php$"), "LokiBot panel admin page"),
    (re.compile(r"(?i)/gate\.php$"), "bot gate (gate.php)"),
    (re.compile(r"(?i)/panel/"), "c2 panel path (/panel/)"),
    (re.compile(r"(?i)/(?:admin|login)\.php$"), "panel login page"),
    (re.compile(r"(?i)/auth/login/?$"), "panel login page"),
    (re.compile(r"(?i)/wp-content/plugins/[^/]+/[^/]+\.php$"), "kit/panel inside a compromised WordPress plugin directory"),
)
_PHP_WARNING = re.compile(r"<b>\s*(?:Warning|Fatal error|Notice|Parse error)\s*</b>:", re.I)


def _lines(path: Path) -> Iterator[str]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            s = line.strip()
            if s and not s.startswith(("#", "!", ";", "//")):
                yield s


def _iso_date(value: Any) -> str | None:
    if value in (None, ""):
        return None
    s = str(value).strip()
    m = re.fullmatch(r"(\d{2})/(\d{2})/(\d{4})", s)
    try:
        if m:
            dt = datetime(int(m.group(3)), int(m.group(2)), int(m.group(1)), tzinfo=UTC)
        else:
            dt = datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith("Z") else s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
    except ValueError:
        return None
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _dom(host: Any, info: dict[str, Any] | None = None) -> Entry | None:
    h = normalise_host(host) if isinstance(host, str) else None
    return ("dom", h, h, info) if h else None


def _domain_token(token: str) -> str | None:
    if "/" in token or "://" in token:
        s = _split(token)
        return s["host"] if s else None
    return normalise_host(token)


def parse_domains(path: Path) -> Iterator[Entry]:
    for s in _lines(path):
        e = _dom(_domain_token(s.split()[0]))
        if e:
            yield e


def parse_hosts(path: Path) -> Iterator[Entry]:
    for s in _lines(path):
        tokens = s.split("#", 1)[0].split()
        if len(tokens) < 2 or tokens[0] not in ("0.0.0.0", "127.0.0.1", "::", "::1"):
            continue
        for name in tokens[1:]:
            h = normalise_host(name)
            if h and h not in _HOSTS_SKIP:
                yield ("dom", h, h, None)


def parse_hagezi(path: Path) -> Iterator[Entry]:
    for s in _lines(path):
        tok = s
        if tok.startswith("||"):
            tok = tok[2:].split("^", 1)[0]
        if tok.startswith("*."):
            tok = tok[2:]
        e = _dom(tok)
        if e:
            yield e


def parse_phishing_army(path: Path) -> Iterator[Entry]:
    for e in parse_domains(path):
        if e[1] not in _PHISHING_ARMY_TEST:
            yield e


def parse_certpl_csv(path: Path) -> Iterator[Entry]:
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.reader(fh, delimiter="\t")
        header = next(reader, None)
        if not header or "AdresDomeny" not in [h.strip().lstrip("﻿") for h in header]:
            raise ValueError("unexpected CERT.PL CSV header")
        cols = [h.strip().lstrip("﻿") for h in header]
        idx = {name: cols.index(name) for name in ("PozycjaRejestru", "AdresDomeny", "DataWpisu", "DataWykreslenia") if name in cols}
        for row in reader:
            if len(row) <= idx["AdresDomeny"]:
                continue

            def col(name: str, row: list[str] = row) -> str:
                i = idx.get(name)
                return row[i].strip() if i is not None and i < len(row) else ""

            e = _dom(col("AdresDomeny"), {"listed_at": _iso_date(col("DataWpisu")), "deleted_at": _iso_date(col("DataWykreslenia")),
                                          "register_id": col("PozycjaRejestru") or None})
            if e:
                yield e


def parse_botvrij(path: Path) -> Iterator[Entry]:
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or "value" not in reader.fieldnames:
            raise ValueError("unexpected Botvrij CSV header")
        for row in reader:
            e = _dom(row.get("value") or "", {"value_type": (row.get("value_type") or "")[:20], "event_id": (row.get("event_id") or "")[:12],
                                              "event_info": (row.get("event_info") or "")[:200]})
            if e:
                yield e


def parse_scamsniffer(path: Path) -> Iterator[Entry]:
    data = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
    if not isinstance(data, list):
        raise ValueError("ScamSniffer domains.json is not a JSON array")
    for item in data:
        e = _dom(item) if isinstance(item, str) else None
        if e:
            yield e


def parse_metamask(path: Path) -> Iterator[Entry]:
    data = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
    if not isinstance(data, dict) or not isinstance(data.get("blacklist"), list):
        raise ValueError("MetaMask config.json without a blacklist")
    tol = data.get("tolerance")
    yield ("meta", "tolerance", "", {"tolerance": tol if isinstance(tol, int) and not isinstance(tol, bool) and 0 <= tol <= 5 else 0})
    for listname in ("whitelist", "fuzzylist"):
        for item in data.get(listname) or []:
            h = normalise_host(item) if isinstance(item, str) else None
            if h:
                yield ("aux", h, listname, None)
    for item in data["blacklist"]:
        e = _dom(item) if isinstance(item, str) else None
        if e:
            yield e


def parse_urls(path: Path) -> Iterator[Entry]:
    for s in _lines(path):
        key = url_key(s.split()[0])
        sp = _split(s.split()[0])
        if key and sp:
            yield ("url", key, sp["host"], None)


def parse_cybercrime(path: Path) -> Iterator[Entry]:
    for s in _lines(path):
        token = s.split()[0]
        sp = _split(token)
        key = url_key(token)
        if not sp or not key:
            continue
        hints = [h for rx, h in CC_PATH_HINTS if rx.search(sp["path"] or "")]
        yield ("url", key, sp["host"], {"hints": hints, "port": sp["port"]})


def _cnpj_ok(digits: str) -> bool:
    if len(digits) != 14 or len(set(digits)) == 1:
        return False

    def dv(base: str, weights: list[int]) -> str:
        s = sum(int(x) * w for x, w in zip(base, weights)) % 11
        return "0" if s < 2 else str(11 - s)

    w1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    return digits[12] == dv(digits[:12], w1) and digits[13] == dv(digits[:13], [6] + w1)


def procon_error(text: str) -> str | None:
    """Error-in-200 detection for the Procon-SP list (cond 5): a PHP warning before the JSON, a non-OK
    Result, or no records while TotalRecordCount > 0. None when the body looks healthy."""
    obj: Any = None
    j = text.find("{")
    if j >= 0:
        try:
            obj = json.loads(text[j:])
        except ValueError:
            obj = None
    total = None
    records = None
    if isinstance(obj, dict):
        try:
            total = int(str(obj.get("TotalRecordCount") or "0"))
        except ValueError:
            total = None
        records = obj.get("Records")
    if _PHP_WARNING.search(text):
        return f"backend error inside HTTP 200 (PHP warning); records {len(records) if isinstance(records, list) else '?'} of {total}"
    if not isinstance(obj, dict):
        return "no JSON list in the answer"
    if obj.get("Result") not in (None, "OK"):
        return f"backend error: Result={str(obj.get('Result'))[:20]}"
    if not isinstance(records, list):
        return "no Records list in the answer"
    if not records and total:
        return f"backend error inside HTTP 200: 0 of {total} records"
    return None


def scrub_procon(path: Path) -> None:
    """Rewrite a Procon-SP download keeping only what the index needs: site, CNPJ (natural-person CPFs
    are masked, AR24, and their names dropped), status and inclusion date. Runs in the validator,
    before the copy is installed, so no full CPF or person's name is ever stored."""
    text = path.read_text(encoding="utf-8", errors="replace")
    obj = json.loads(text[text.find("{"):])
    records = []
    for r in obj.get("Records") or []:
        if not isinstance(r, dict):
            continue
        doc = re.sub(r"\D", "", str(r.get("strCNPJ") or ""))
        is_cnpj = len(doc) == 14
        records.append({
            "strSite": str(r.get("strSite") or "")[:300],
            "strCNPJ": doc if is_cnpj and _cnpj_ok(doc) else (f"***.{doc[3:6]}.{doc[6:9]}-**" if len(doc) == 11 else ""),
            "strEmpresa": str(r.get("strEmpresa") or "")[:120] if is_cnpj else "",
            "strSituacao": str(r.get("strSituacao") or "")[:2],
            "dtInclusao": str(r.get("dtInclusao") or "")[:25],
        })
    clean = {"Result": "OK", "TotalRecordCount": str(len(records)), "Records": records, "_v3lum": "scrubbed by url_domain_blocklists (AR24)"}
    fd = os.open(path, os.O_WRONLY | os.O_TRUNC)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(clean, fh, ensure_ascii=False)


def parse_procon(path: Path) -> Iterator[Entry]:
    text = path.read_text(encoding="utf-8", errors="replace")
    problem = procon_error(text)
    if problem:
        raise ValueError(f"Procon-SP: {problem}")
    obj = json.loads(text[text.find("{"):])
    for r in obj.get("Records") or []:
        if not isinstance(r, dict):
            continue
        sp = _split(str(r.get("strSite") or ""))
        if not sp:
            continue
        host = sp["host"][4:] if sp["host"].startswith("www.") and sp["host"].count(".") >= 2 else sp["host"]
        doc = str(r.get("strCNPJ") or "")
        info = {"listed_at": _iso_date(r.get("dtInclusao")),
                "status": {"1": "NO AR", "0": "FORA DO AR"}.get(str(r.get("strSituacao")), ""),
                "cnpj": doc if re.fullmatch(r"\d{14}", doc) else "", "company": str(r.get("strEmpresa") or "")[:120]}
        e = _dom(host, info)
        if e:
            yield e


PARSERS: dict[str, Callable[[Path], Iterator[Entry]]] = {
    "domains": parse_domains, "spmedia": parse_domains, "hosts": parse_hosts, "hagezi": parse_hagezi,
    "phishing_army": parse_phishing_army, "certpl_csv": parse_certpl_csv, "botvrij": parse_botvrij, "scamsniffer": parse_scamsniffer,
    "metamask": parse_metamask, "urls": parse_urls, "cybercrime": parse_cybercrime, "procon": parse_procon,
}


# =============================================================================================
# the on-disk index (cond 1)
# =============================================================================================
_SCHEMA_SQL = (
    "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)",
    "CREATE TABLE IF NOT EXISTS feed_meta (dataset TEXT PRIMARY KEY, feed TEXT, bit INTEGER, sha256 TEXT, count INTEGER, built_at TEXT, extra TEXT)",
    "CREATE TABLE IF NOT EXISTS dom (key TEXT PRIMARY KEY, feeds INTEGER NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS url (key TEXT PRIMARY KEY, feeds INTEGER NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS urlhost (key TEXT PRIMARY KEY, feeds INTEGER NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS info (dataset TEXT, kind TEXT, key TEXT, host TEXT, listed_at TEXT, deleted_at TEXT, extra TEXT, "
    "PRIMARY KEY (dataset, kind, key)) WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS info_host ON info (dataset, host)",
    "CREATE TABLE IF NOT EXISTS removed (feed TEXT, key TEXT, listed_at TEXT, deleted_at TEXT, PRIMARY KEY (feed, key)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS aux (dataset TEXT, list TEXT, key TEXT, PRIMARY KEY (dataset, list, key)) WITHOUT ROWID",
)
_WRITE_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()
_BACKGROUND: dict[tuple[str, str], threading.Thread] = {}


def index_path() -> Path:
    return paths.datasets_dir() / ".index" / INDEX_FILE


def _write_lock(path: Path) -> threading.Lock:
    with _LOCKS_GUARD:
        return _WRITE_LOCKS.setdefault(str(path), threading.Lock())


def _connect_rw(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:  # pragma: no cover - not ours to tighten
        pass
    if not path.exists():
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))  # private from the first byte
    conn = sqlite3.connect(str(path), timeout=60, check_same_thread=False)
    conn.execute("PRAGMA busy_timeout = 60000")
    conn.execute("BEGIN IMMEDIATE")  # readers see the whole schema or none of it
    try:
        for sql in _SCHEMA_SQL:
            conn.execute(sql)
        conn.execute("INSERT OR IGNORE INTO meta VALUES ('schema', ?)", (str(INDEX_SCHEMA),))
        conn.commit()
    except BaseException:
        conn.rollback()
        conn.close()
        raise
    for suffix in ("-journal", "-wal", "-shm"):
        companion = Path(str(path) + suffix)
        if companion.exists():
            try:
                os.chmod(companion, 0o600)
            except OSError:  # pragma: no cover
                pass
    return conn


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def index_part(dataset: str, file_path: Path | str, *, index_file: Path | None = None) -> int:
    """(Re)build the index rows of one dataset from ``file_path`` (the candidate download or the local
    copy). Raises ValueError when the content is unusable (HTML, error-in-200, no entries): the dataset
    manager then keeps the previous copy. Returns the number of entries indexed."""
    feed, part = PARTS[dataset]
    path = Path(file_path)
    if feed.needs_consent and not openphish_consent():
        # cond 3: `v3lum data update` is not licence-aware yet (core request): never install the feed without consent
        raise ValueError("OpenPhish community terms forbid organisational security use without its written consent: record the legal "
                         "reference in setting url_domain_blocklists_openphish_consent_ref first")
    if part.parser == "procon":
        problem = procon_error(path.read_text(encoding="utf-8", errors="replace"))
        if problem:
            raise ValueError(f"Procon-SP list rejected: {problem}")
        scrub_procon(path)
    with open(path, "rb") as fh:
        head = fh.read(512).lstrip().lower()
    if head.startswith((b"<!doctype html", b"<html", b"<head", b"<body")) or b"<html" in head:
        raise ValueError(f"{dataset}: an HTML page instead of the list")
    sha = _file_sha256(path)
    ipath = index_file or index_path()
    with _write_lock(ipath):
        conn = _connect_rw(ipath)
        try:
            row = conn.execute("SELECT sha256 FROM feed_meta WHERE dataset = ?", (dataset,)).fetchone()
            if row and row[0] == sha:
                return int(conn.execute("SELECT count FROM feed_meta WHERE dataset = ?", (dataset,)).fetchone()[0] or 0)
            return _write_part(conn, feed, part, path, sha)
        finally:
            conn.close()


def _write_part(conn: sqlite3.Connection, feed: Feed, part: Part, path: Path, sha: str) -> int:
    bit = 1 << feed.bit
    now = _now_iso()
    count = 0
    extra: dict[str, Any] = {}
    batches: dict[str, list[tuple[Any, ...]]] = {"dom": [], "url": [], "urlhost": [], "info": [], "aux": [], "newkeys": []}

    def flush(force: bool = False) -> None:
        for name, rows in batches.items():
            if not rows or (not force and len(rows) < 20000):
                continue
            if name in ("dom", "url", "urlhost"):
                conn.executemany(f"INSERT INTO {name} (key, feeds) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET feeds = feeds | excluded.feeds", rows)
            elif name == "info":
                conn.executemany("INSERT OR REPLACE INTO info VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
            elif name == "aux":
                conn.executemany("INSERT OR IGNORE INTO aux VALUES (?, ?, ?)", rows)
            else:
                conn.executemany("INSERT OR IGNORE INTO temp.newkeys VALUES (?)", rows)
            rows.clear()

    conn.execute("BEGIN IMMEDIATE")
    try:
        for table in part.tables:
            conn.execute(f"UPDATE {table} SET feeds = feeds & ~? WHERE feeds & ?", (bit, bit))
            conn.execute(f"DELETE FROM {table} WHERE feeds = 0")
        conn.execute("CREATE TEMP TABLE IF NOT EXISTS newkeys (key TEXT PRIMARY KEY) WITHOUT ROWID")
        conn.execute("DELETE FROM temp.newkeys")
        conn.execute("DELETE FROM aux WHERE dataset = ?", (part.dataset,))
        if not feed.track_removals:
            conn.execute("DELETE FROM info WHERE dataset = ?", (part.dataset,))
        for kind, key, host, info in PARSERS[part.parser](path):
            if kind == "meta":
                extra.update(info or {})
                continue
            if kind == "aux":
                batches["aux"].append((part.dataset, host, key))
                continue
            count += 1
            if kind == "dom":
                batches["dom"].append((key, bit))
            else:
                batches["url"].append((key, bit))
                batches["urlhost"].append((host, bit))
            if feed.track_removals:
                batches["newkeys"].append((key,))
            if info:
                listed, deleted = info.get("listed_at"), info.get("deleted_at")
                rest = {k: v for k, v in info.items() if k not in ("listed_at", "deleted_at") and v not in (None, "", [])}
                batches["info"].append((part.dataset, kind, key, host, listed, deleted, json.dumps(rest, ensure_ascii=False) if rest else None))
            flush()
        flush(force=True)
        if count == 0:
            raise ValueError(f"{part.dataset}: no entries parsed")
        if feed.track_removals:
            conn.execute(
                "INSERT OR REPLACE INTO removed (feed, key, listed_at, deleted_at) SELECT ?, i.key, i.listed_at, ? FROM info i "
                "WHERE i.dataset = ? AND NOT EXISTS (SELECT 1 FROM temp.newkeys n WHERE n.key = i.key)",
                (feed.id, now, part.dataset),
            )
            conn.execute("DELETE FROM removed WHERE feed = ? AND key IN (SELECT key FROM temp.newkeys)", (feed.id,))
            cutoff = (datetime.now(UTC) - timedelta(days=REMOVED_KEEP_DAYS)).isoformat().replace("+00:00", "Z")
            conn.execute("DELETE FROM removed WHERE feed = ? AND deleted_at < ?", (feed.id, cutoff))
            conn.execute("DELETE FROM info WHERE dataset = ? AND key NOT IN (SELECT key FROM temp.newkeys)", (part.dataset,))
        conn.execute("INSERT OR REPLACE INTO feed_meta VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (part.dataset, feed.id, feed.bit, sha, count, now, json.dumps(extra) if extra else None))
        conn.execute("DELETE FROM temp.newkeys")
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return count


def openphish_consent() -> str:
    """The legal reference of OpenPhish's written consent / paid feed (setting
    ``url_domain_blocklists_openphish_consent_ref``), read when a download is validated (no run context
    exists there); '' (fail closed) when it is not recorded or the configuration cannot be read."""
    try:
        from v3lum.config import Config

        return str(Config.load().settings.get("url_domain_blocklists_openphish_consent_ref") or "").strip()
    except Exception:  # noqa: BLE001 - an unreadable configuration means 'no consent recorded'
        return ""


def _validator(dataset: str) -> Callable[[Path], bool]:
    def validate(path: Path) -> bool:
        index_part(dataset, path)
        return True

    validate.__name__ = f"index_{dataset.replace('.', '_')}"
    return validate


#: terms class of each feed's registry source (the registry contract test checks they agree)
_TERMS = {"openphish": "noncommercial", "phishing_army": "noncommercial"}


def part_source(feed: Feed, part: Part) -> str:
    return part.source or feed.source


for _feed in FEEDS.values():
    for _part in _feed.parts:
        register_dataset(
            _part.dataset, _part.url, ttl=_part.ttl_h * 3600, description=f"{_feed.list_name} ({_part.parser})",
            licence=_part.licence, terms_class=_TERMS.get(_feed.id, "open"), attribution=_part.attribution,
            source=part_source(_feed, _part), validate=_validator(_part.dataset), min_bytes=_part.min_bytes, expect=_part.expect,
            max_bytes=_part.max_bytes, large=True, essential=_part.essential,
        )


class BlocklistIndex:
    """Read side of the index: a read-only connection used for one module run."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.conn: sqlite3.Connection | None = None
        if path.exists():
            try:
                self.conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30, check_same_thread=False)
                self.conn.execute("PRAGMA busy_timeout = 30000")
            except sqlite3.Error:
                self.conn = None

    def close(self) -> None:
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def feed_meta(self) -> dict[str, dict[str, Any]]:
        if self.conn is None:
            return {}
        try:
            rows = self.conn.execute("SELECT dataset, feed, sha256, count, built_at, extra FROM feed_meta").fetchall()
        except sqlite3.Error:
            return {}
        return {r[0]: {"feed": r[1], "sha256": r[2], "count": r[3], "built_at": r[4], "extra": json.loads(r[5]) if r[5] else {}} for r in rows}

    def _rows(self, sql: str, params: Any = ()) -> list[Any]:
        """Rows of a read query; none while the index is missing or still being created by a rebuild."""
        if self.conn is None:
            return []
        try:
            return self.conn.execute(sql, params).fetchall()
        except sqlite3.Error:
            return []

    def _bits(self, table: str, keys: list[str]) -> dict[str, int]:
        if not keys:
            return {}
        marks = ",".join("?" * len(keys))
        return {k: int(v) for k, v in self._rows(f"SELECT key, feeds FROM {table} WHERE key IN ({marks})", keys)}

    def dom(self, keys: list[str]) -> dict[str, int]:
        return self._bits("dom", keys)

    def url(self, key: str | None) -> int:
        return self._bits("url", [key]).get(key, 0) if key else 0

    def urlhost(self, host: str | None) -> int:
        return self._bits("urlhost", [host]).get(host, 0) if host else 0

    def info(self, dataset: str, kind: str, key: str) -> dict[str, Any] | None:
        rows = self._rows("SELECT listed_at, deleted_at, extra FROM info WHERE dataset = ? AND kind = ? AND key = ? LIMIT 1", (dataset, kind, key))
        if not rows:
            return None
        row = rows[0]
        return {"listed_at": row[0], "deleted_at": row[1], **(json.loads(row[2]) if row[2] else {})}

    def urls_for_host(self, dataset: str, host: str, limit: int = 20) -> list[tuple[str, dict[str, Any]]]:
        rows = self._rows("SELECT key, extra FROM info WHERE dataset = ? AND host = ? LIMIT ?", (dataset, host, limit))
        return [(r[0], json.loads(r[1]) if r[1] else {}) for r in rows]

    def removed(self, feed: str, keys: list[str]) -> list[dict[str, Any]]:
        if not keys:
            return []
        marks = ",".join("?" * len(keys))
        rows = self._rows(f"SELECT key, listed_at, deleted_at FROM removed WHERE feed = ? AND key IN ({marks})", [feed, *keys])
        return [{"key": r[0], "listed_at": r[1], "deleted_at": r[2]} for r in rows]

    def aux(self, dataset: str, listname: str, keys: list[str] | None = None) -> list[str]:
        if keys is None:
            rows = self._rows("SELECT key FROM aux WHERE dataset = ? AND list = ? LIMIT 1000", (dataset, listname))
        else:
            if not keys:
                return []
            marks = ",".join("?" * len(keys))
            rows = self._rows(f"SELECT key FROM aux WHERE dataset = ? AND list = ? AND key IN ({marks})", [dataset, listname, *keys])
        return [r[0] for r in rows]


def _reindex(dataset: str, local: Path, expected_sha: str) -> None:
    try:
        index_part(dataset, local)
    except Exception:  # noqa: BLE001 - a failed background rebuild leaves the feed 'not checked'
        pass


def ensure_indexed(dataset: str, local: Path, expected_sha: str, meta: dict[str, dict[str, Any]]) -> str:
    """'ok' when the index holds this copy; else re-index it: synchronously up to SYNC_REINDEX_BYTES ('ok'),
    in a background thread above ('indexing'), 'error: ...' when the local copy is unusable."""
    if meta.get(dataset, {}).get("sha256") == expected_sha:
        return "ok"
    try:
        size = local.stat().st_size
    except OSError as exc:
        return f"error: {exc.strerror or type(exc).__name__}"
    if size <= SYNC_REINDEX_BYTES:
        try:
            index_part(dataset, local)
        except (ValueError, OSError, sqlite3.Error, UnicodeError, csv.Error) as exc:
            return f"error: {str(exc)[:160]}"
        return "ok"
    key = (str(index_path()), dataset)
    with _LOCKS_GUARD:
        thread = _BACKGROUND.get(key)
        if thread is None or not thread.is_alive():
            thread = threading.Thread(target=_reindex, args=(dataset, local, expected_sha), name=f"v3lum-index-{dataset}", daemon=True)
            _BACKGROUND[key] = thread
            thread.start()
    return "indexing"


# =============================================================================================
# verdicts (cond 6-8)
# =============================================================================================
_CATEGORY_TAGS = {
    "c2": ["c2", "malicious"], "phishing": ["phishing"], "crypto_scam": ["crypto_scam", "fraud"], "fraud_store": ["fraud"],
    "malicious": ["malicious"], "ads_tracking": ["ads_tracking", "weak_signal"], "aggregate": ["aggregate_list", "weak_signal"],
}
_CATEGORY_TITLES = {
    "c2": "Listed as C2 infrastructure (CyberCrime-Tracker)",
    "phishing": "Listed on phishing blocklist(s)",
    "crypto_scam": "Listed on crypto-scam blocklist(s)",
    "fraud_store": "Listed by Procon-SP as a fraudulent store",
    "malicious": "Listed on a malicious-domain blocklist",
    "ads_tracking": "Listed on ad/tracking blocklists (tag only)",
    "aggregate": "Listed on an aggregated threat blocklist (tag only)",
}
_SEVERITY_DOWN = {"high": "medium", "medium": "low", "low": "low", "info": "info"}


def _families(source_id: str) -> frozenset[str]:
    try:
        from v3lum.core import providers

        src = providers.registry().source(source_id)
    except Exception:  # noqa: BLE001
        src = None
    if src is None:
        return frozenset({source_id})
    fams = set(getattr(src, "families", ()) or ())
    if not fams:
        fams.add(str(getattr(src, "upstream_family", "") or source_id))
    return frozenset(fams)


def _independent(family_sets: list[frozenset[str]]) -> int:
    chosen: list[frozenset[str]] = []
    for fs in sorted(family_sets, key=len):
        if all(not (fs & c) for c in chosen):
            chosen.append(fs)
    return len(chosen)


def _age_days(iso: str | None, now: datetime) -> float | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso[:-1] + "+00:00" if iso.endswith("Z") else iso)
    except ValueError:
        return None
    return (now - (dt if dt.tzinfo else dt.replace(tzinfo=UTC))).total_seconds() / 86400


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


@dataclass
class _State:
    feed: Feed
    usable: dict[str, dict[str, Any]] = field(default_factory=dict)  # dataset -> {sha256, fetched_at, age_h, due}
    not_checked: list[str] = field(default_factory=list)


# =============================================================================================
# the modules
# =============================================================================================
class _BlocklistBase(Module):
    """Shared lookup logic (not registered itself)."""

    _feed_module = "main"

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        now = ctx.now() if callable(getattr(ctx, "now", None)) else datetime.now(UTC)
        probe = BlocklistIndex(index_path())
        try:
            meta = probe.feed_meta()
        finally:
            probe.close()
        states = self._feed_states(res, ctx, meta)  # may re-index a copy whose index is missing or outdated
        idx = BlocklistIndex(index_path())
        try:
            return self._lookup(res, entity, ctx, idx, states, now)
        finally:
            idx.close()

    # ------------------------------------------------------------------ feed states (cond 1, 3-5, 8)
    def _feed_states(self, res: ModuleResult, ctx: Any, meta: dict[str, dict[str, Any]]) -> dict[str, _State]:
        allowed = getattr(ctx, "allowed_sources", None)
        disabled = set(_list_setting(ctx, "url_domain_blocklists_disabled_feeds"))
        states: dict[str, _State] = {}
        for feed in FEEDS.values():
            if feed.module != self._feed_module:
                continue
            st = _State(feed)
            states[feed.id] = st
            sources = list(dict.fromkeys([feed.source, *(part_source(feed, p) for p in feed.parts)]))
            if allowed is not None and not any(s in allowed for s in sources):
                st.not_checked.append("not allowed by the policy gate for this run (licence/TLP/tier)")
                continue  # the engine reports sources outside ctx.allowed_sources (coverage, reason 'licence')
            if feed.id in disabled:
                st.not_checked.append("disabled by setting url_domain_blocklists_disabled_feeds")
                for src in sources:
                    res.source_status(src, Status.SKIPPED, reason_code="config", reason=f"{feed.list_name}: disabled by configuration")
                continue
            if feed.needs_consent and not str(ctx.setting("url_domain_blocklists_openphish_consent_ref", "") or "").strip():
                st.not_checked.append("skipped: OpenPhish community terms exclude organisational security use without written consent")
                res.source_status(feed.source, Status.SKIPPED, reason_code="licence",
                                  reason="skipped: OpenPhish terms forbid organisational security use without its written consent (P071 cond 3)")
                continue
            if feed.disabled_reason:
                has_key = bool(ctx.has_key("phishtank")) if callable(getattr(ctx, "has_key", None)) else False
                if has_key:
                    st.not_checked.append(feed.disabled_reason)
                    res.source_status(feed.source, Status.UNAVAILABLE, reason_code="dataset", reason=feed.disabled_reason)
                else:
                    st.not_checked.append("needs the team's own PhishTank app key (and reachable dumps)")
                    res.source_status(feed.source, Status.NEEDS_KEY, reason_code="needs_key", reason=feed.disabled_reason)
                continue
            for part in feed.parts:
                src = part_source(feed, part)
                if allowed is not None and src not in allowed:
                    st.not_checked.append(f"{part.dataset}: not allowed by the policy gate for this run")
                    continue
                problem = self._part_problem(ctx, feed, part, meta, st)
                if problem:
                    st.not_checked.append(problem)
                    res.source_status(src, Status.UNAVAILABLE, reason_code="dataset", reason=f"not checked: {feed.list_name}: {problem}"[:400])
        return states

    @staticmethod
    def _part_problem(ctx: Any, feed: Feed, part: Part, meta: dict[str, dict[str, Any]], st: _State) -> str:
        """'' when the part is usable (recorded in ``st.usable``), else why it is not checked."""
        info = ctx.data.info(part.dataset)
        if not info.present:
            return f"{part.dataset} not downloaded: run v3lum data update {part.dataset}"
        age_h = float(info.age_hours or 0.0)
        if feed.stale_h is not None and age_h > feed.stale_h:
            return f"{part.dataset} is {age_h:.0f} h old (> {feed.stale_h:.0f} h): run v3lum data update {part.dataset}"
        store = getattr(ctx.data, "store", None)
        local = store.path(part.dataset) if store is not None else paths.datasets_dir() / part.dataset
        state = ensure_indexed(part.dataset, Path(local), info.sha256, meta)
        if state != "ok":
            return f"{part.dataset}: index {'being rebuilt in the background' if state == 'indexing' else state}"
        try:
            ctx.data.fetch(part.dataset, ttl=10 ** 12)  # cite the local copy: never a download (fresh for this ttl, the file exists)
        except Exception:  # noqa: BLE001 - a citation problem never hides a usable feed
            pass
        st.usable[part.dataset] = {"sha256": info.sha256, "fetched_at": info.fetched_at, "age_h": round(age_h, 1), "due": age_h > part.ttl_h}
        return ""

    # ------------------------------------------------------------------ lookup
    def _lookup(self, res: ModuleResult, entity: Entity, ctx: Any, idx: BlocklistIndex, states: dict[str, _State], now: datetime) -> ModuleResult:
        extra_protected = [normalise_host(x) or "" for x in _list_setting(ctx, "url_domain_blocklists_protected_domains")]
        if entity.type is T.URL:
            u_key = url_key(entity.value)
            host = (_split(entity.value) or {}).get("host")
        else:
            u_key, host = None, normalise_host(entity.value)
        scope = host_scope(host, extra_protected) if host else "platform"
        dom_keys = domain_lookup_keys(host, extra_protected) if host else []
        hits: list[dict[str, Any]] = []
        usable_by_table: dict[str, int] = {"dom": 0, "url": 0, "urlhost": 0}
        dataset_of: dict[tuple[int, str], str] = {}
        for st in states.values():
            for dataset in st.usable:
                _feed, part = PARTS[dataset]
                for table in part.tables:
                    usable_by_table[table] |= 1 << st.feed.bit
                    dataset_of[(st.feed.bit, table)] = dataset
        by_bit = {f.bit: f for f in FEEDS.values()}

        def add(bits: int, table: str, match: str, key: str) -> None:
            bits &= usable_by_table.get(table, 0)
            for bit, feed in by_bit.items():
                if bits & (1 << bit):
                    dataset = dataset_of[(bit, table)]
                    info = None if table == "urlhost" else idx.info(dataset, "url" if table == "url" else "dom", key)
                    hits.append(self._hit(feed, dataset, match, key, info, states[feed.id].usable[dataset], now))

        url_bits = 0
        if u_key and usable_by_table["url"]:
            url_bits = idx.url(u_key) & usable_by_table["url"]
            add(url_bits, "url", "url", u_key)
        if host and scope == "" and usable_by_table["urlhost"]:
            # a feed that already listed this exact URL is not reported again for its host
            add(idx.urlhost(host) & ~url_bits, "urlhost", "host", host)
        if dom_keys and usable_by_table["dom"]:
            found = idx.dom(dom_keys)
            for i, key in enumerate(dom_keys):
                if key in found:
                    add(found[key], "dom", "domain" if i == 0 else "parent", key)
        # removal history from snapshot diffs (CERT.PL): historical hits only
        for st in states.values():
            if st.feed.track_removals and st.usable and dom_keys:
                dataset = next(iter(st.usable))
                for row in idx.removed(st.feed.id, dom_keys):
                    hit = self._hit(st.feed, dataset, "domain" if row["key"] == dom_keys[0] else "parent", row["key"],
                                    {"listed_at": row["listed_at"], "deleted_at": row["deleted_at"]}, st.usable[dataset], now)
                    hits.append(hit)
        self._extra_checks(res, entity, ctx, idx, states, host, scope, hits, now)
        return self._report(res, states, hits, host, scope)

    def _extra_checks(self, res: ModuleResult, entity: Entity, ctx: Any, idx: BlocklistIndex, states: dict[str, _State], host: str | None,
                      scope: str, hits: list[dict[str, Any]], now: datetime) -> None:
        """MetaMask look-alike check (main module only)."""
        mm = states.get("metamask")
        if not mm or not mm.usable or not host or _is_ip(host) or scope == "platform":
            return
        dataset = next(iter(mm.usable))
        labels = host.split(".")
        parents = [".".join(labels[i:]) for i in range(len(labels) - 1)]
        if idx.aux(dataset, "whitelist", parents):
            # MetaMask's algorithm: a whitelisted host (or parent) is never a blacklist or look-alike hit
            hits[:] = [h for h in hits if h["feed"] != "metamask"]
            return
        if any(h["feed"] == "metamask" for h in hits):
            return
        tolerance = int((idx.feed_meta().get(dataset, {}).get("extra") or {}).get("tolerance") or 0)
        if tolerance <= 0:
            return
        form = ".".join(labels[:-1])
        if form.startswith("www."):
            form = form[4:]
        for target in idx.aux(dataset, "fuzzylist"):
            tform = ".".join(target.split(".")[:-1])
            if form and tform and form != tform and _levenshtein(form, tform) <= tolerance:
                hit = self._hit(FEEDS["metamask"], dataset, "fuzzy", host, {"brand": target}, mm.usable[dataset], now)
                hit["lookalike_of"] = target
                hits.append(hit)
                break

    @staticmethod
    def _hit(feed: Feed, dataset: str, match: str, key: str, info: dict[str, Any] | None, usable: dict[str, Any], now: datetime) -> dict[str, Any]:
        info = dict(info or {})
        listed_at = info.pop("listed_at", None)
        deleted_at = info.pop("deleted_at", None)
        age = _age_days(listed_at, now)
        historical = bool(deleted_at) or feed.frozen or (age is not None and age > HISTORICAL_DAYS)
        hit = {"list": feed.list_name, "feed": feed.id, "source": feed.source, "category": feed.category, "match": match, "key": key,
               "listed_at": listed_at, "deleted_at": deleted_at, "historical": historical, "terms": _terms_label(feed.source),
               "dataset": dataset, "dataset_sha256": usable.get("sha256", ""), "fetched_at": usable.get("fetched_at", "")}
        if info:
            hit["context"] = {k: v for k, v in info.items() if k in ("event_info", "event_id", "hints", "status", "cnpj", "company", "brand", "register_id")}
        return hit

    # ------------------------------------------------------------------ report
    def _report(self, res: ModuleResult, states: dict[str, _State], hits: list[dict[str, Any]], host: str | None, scope: str) -> ModuleResult:
        checked = sorted(st.feed.list_name for st in states.values() if st.usable)
        not_checked = [{"list": st.feed.list_name, "reason": "; ".join(st.not_checked)[:300]} for st in states.values() if st.not_checked]
        for st in states.values():  # cond 5: a source whose backend errored emits its manual pivot link
            if not st.usable and st.feed.manual_url:
                res.link(f"{st.feed.list_name} (manual check)", st.feed.manual_url)
        res.raw = {"checked": checked, "not_checked": not_checked, "scope": scope or "ordinary", "hits": hits[:MAX_HITS_SHOWN], "hit_count": len(hits)}
        if not checked:
            reasons = "; ".join(f"{n['list']}: {n['reason']}" for n in not_checked) or "no feed selected"
            return res.mark("unavailable", f"not checked: no blocklist available ({reasons})"[:500], reason_code="dataset")
        if not hits:
            # an absence on the lists that WERE checked (never 'not listed' for the others: raw + source statuses)
            return res.mark("empty")
        hits.sort(key=lambda h: (h["historical"], h["category"], h["feed"]))
        res.attr("blocklist_hits", hits[:MAX_HITS_SHOWN])
        res.attr("blocklists", sorted({h["list"] for h in hits}))
        res.attr("blocklists_not_checked", not_checked)
        by_cat: dict[str, list[dict[str, Any]]] = {}
        for h in hits:
            by_cat.setdefault(h["category"], []).append(h)
        any_current_high = False
        for cat, chits in by_cat.items():
            current = [h for h in chits if not h["historical"]]
            pool = current or chits
            fidelity = self._fidelity(cat, pool)
            severity = {"HIGH": "high", "MEDIUM": "medium", "LOW": "info"}[fidelity]
            confidence = "probable" if fidelity == "HIGH" else "possible"
            if not current:
                severity = _SEVERITY_DOWN[severity]
            any_current_high |= bool(current) and fidelity == "HIGH" and cat in ("phishing", "c2")
            lists = sorted({h["list"] for h in pool})
            tags = list(_CATEGORY_TAGS.get(cat, []))
            if fidelity == "HIGH" and cat == "phishing":
                tags.append("malicious")
            if not current:
                tags.append("historical")
            if any(h["match"] == "fuzzy" for h in pool):
                tags.append("typosquat")
            when = [f"{h['list']}: listed {h['listed_at'][:10]}" if h["listed_at"] else f"{h['list']}: in the copy of {str(h['fetched_at'])[:10]}"
                    for h in pool[:6]]
            desc = (f"{len(pool)} hit(s) on {', '.join(lists)} ({'; '.join(when)})."
                    + ("" if current else " Historical only (listed more than 30 days ago, removed or a frozen list): not current state.")
                    + (f" Not checked: {', '.join(n['list'] for n in not_checked)}." if not_checked else ""))
            res.finding(
                _CATEGORY_TITLES[cat], severity, desc, confidence=confidence, criterion=self._criterion(cat, fidelity, pool, current),
                data={"category": cat, "fidelity": fidelity, "current": bool(current), "hits": pool[:20], "lists": lists},
                tags=tags, source=pool[0]["source"], observed_first=min((h["listed_at"] for h in pool if h["listed_at"]), default=None),
                key=cat,
            )
        if any_current_high:
            res.attr("malicious", True)
        elif any(not h["historical"] and h["category"] in ("phishing", "c2", "crypto_scam", "fraud_store", "malicious") for h in hits):
            res.attr("suspicious", True)
        return res

    @staticmethod
    def _fidelity(category: str, pool: list[dict[str, Any]]) -> str:
        if category == "c2":
            return "HIGH"
        if category in ("ads_tracking", "aggregate"):
            return "LOW"
        if category == "phishing":
            feeds = {h["feed"] for h in pool}
            if "certpl" in feeds:
                return "HIGH"
            fams = [_families(FEEDS[f].source) for f in feeds]
            return "HIGH" if _independent(fams) >= 2 else "MEDIUM"
        return "MEDIUM"

    @staticmethod
    def _criterion(category: str, fidelity: str, pool: list[dict[str, Any]], current: list[dict[str, Any]]) -> str:
        lists = ", ".join(sorted({h["list"] for h in pool}))
        matches = ", ".join(sorted({h["match"] for h in pool}))
        base = f"local match ({matches}) on {lists}"
        if category == "phishing":
            base += "; HIGH with CERT.PL or >= 2 independent upstream families, else MEDIUM (P071 cond 7)"
        elif category == "c2":
            base += "; CyberCrime-Tracker C2 panel listing = HIGH (P071 cond 7)"
        elif category in ("ads_tracking", "aggregate"):
            base += "; ad/tracking and aggregated lists are LOW, tag only, never phishing (P071 cond 7)"
        else:
            base += f"; {category} lists = MEDIUM (P071 cond 7)"
        if not current:
            base += "; historical listing only"
        return base


def _terms_label(source_id: str) -> str:
    try:
        from v3lum.core import providers

        src = providers.registry().source(source_id)
        return str(getattr(getattr(src, "terms", None), "class_", "") or "")
    except Exception:  # noqa: BLE001
        return ""


def _list_setting(ctx: Any, name: str) -> list[str]:
    value = ctx.setting(name, []) if callable(getattr(ctx, "setting", None)) else []
    if isinstance(value, str):
        value = [v.strip() for v in value.split(",")]
    return [str(v).strip() for v in value or [] if str(v).strip()]


_MAIN_SOURCES = tuple(dict.fromkeys(src for f in FEEDS.values() if f.module == "main" for src in [f.source, *(part_source(f, p) for p in f.parts)]))


@register
class UrlDomainBlocklists(_BlocklistBase):
    name = "url_domain_blocklists"
    title = "Phishing / malicious URL and domain blocklists (local)"
    description = (
        "Matches a domain or URL locally against downloaded lists: CERT.PL, Phishing.Database, OpenPhish, Phishing Army, HaGeZi TIF, "
        "StevenBlack, Botvrij, ScamSniffer, MetaMask (incl. look-alikes), spmedia, Procon-SP (PhishTank disabled); nothing is sent anywhere."
    )
    category = "url_web"
    accepts = {T.DOMAIN, T.URL}
    produces = set()
    terms = "noncommercial"  # most restrictive feed class: OpenPhish, Phishing Army (P071)
    opsec = Opsec.PASSIVE
    disclosure = "none"  # matching is local: allowed at TLP:RED (cond 10)
    hosts = ()
    sources = _MAIN_SOURCES
    access_model = "offline"
    optional_keys = ("phishtank",)
    tags = {"offline", "reputation"}
    default_enabled = True
    timeout = 120.0
    reference = "https://cert.pl/en/warning-list/"
    notice = (
        "Lists are downloaded by `v3lum data update` and matched locally. OpenPhish and Phishing Army are noncommercial: off under the "
        "corporate profile until licence-cleared (OpenPhish also needs its written consent recorded); HaGeZi and ScamSniffer are GPL-3.0 "
        "data, downloaded at runtime only."
    )
    settings = {
        "url_domain_blocklists_disabled_feeds": [],
        "url_domain_blocklists_openphish_consent_ref": "",
        "url_domain_blocklists_protected_domains": [],
    }

    _feed_module = "main"


@register
class UrlDomainBlocklistsC2(_BlocklistBase):
    name = "url_domain_blocklists_c2"
    title = "CyberCrime-Tracker C2 panel list (local)"
    description = (
        "Matches a domain, IP or URL locally against the CyberCrime-Tracker C2 panel list (host/IP and exact URL; panel paths give family "
        "hints); nothing is sent anywhere. Non-default: the list operator is of unknown tier."
    )
    category = "url_web"
    accepts = {T.DOMAIN, T.URL, T.IPV4}
    produces = {T.URL}
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = ("cybercrime_tracker.panel_list",)
    access_model = "offline"
    tags = {"offline", "reputation"}
    default_enabled = False  # A3: the provider (anonymous operator) is tier 'unknown' until a community promotion is recorded
    timeout = 120.0
    reference = "https://cybercrime-tracker.net/"
    notice = "CyberCrime-Tracker is run by an anonymous operator (tier unknown): opt-in only; panel paths are family hints, never attribution."

    _feed_module = "c2"

    def _lookup(self, res: ModuleResult, entity: Entity, ctx: Any, idx: BlocklistIndex, states: dict[str, _State], now: datetime) -> ModuleResult:
        if entity.type is T.IPV4:
            host: str | None = entity.value
            u_key = None
        elif entity.type is T.URL:
            u_key = url_key(entity.value)
            host = (_split(entity.value) or {}).get("host")
        else:
            host, u_key = normalise_host(entity.value), None
        st = states.get("cybercrime_tracker")
        if st is None or not st.usable:
            return self._report(res, states, [], host, "")
        dataset = next(iter(st.usable))
        extra_protected = [normalise_host(x) or "" for x in _list_setting(ctx, "url_domain_blocklists_protected_domains")]
        scope = host_scope(host, extra_protected) if host else "platform"
        hits: list[dict[str, Any]] = []
        bit = 1 << st.feed.bit
        if u_key and idx.url(u_key) & bit:
            hits.append(self._hit(st.feed, dataset, "url", u_key, idx.info(dataset, "url", u_key), st.usable[dataset], now))
        panels: list[tuple[str, dict[str, Any]]] = []
        if host and scope == "" and idx.urlhost(host) & bit:
            panels = idx.urls_for_host(dataset, host)
            hints = sorted({h for _k, extra in panels for h in extra.get("hints") or []})
            hit = self._hit(st.feed, dataset, "host", host, {"hints": hints}, st.usable[dataset], now)
            hits.append(hit)
            res.attr("c2_panel_hints", hints)
            for key, extra in panels[:10]:
                res.pivot(T.URL, "http://" + key, "related", confidence="possible", expand=False,
                          note="C2 panel URL listed by CyberCrime-Tracker (family hints: " + (", ".join(extra.get("hints") or []) or "none") + ")")
        return self._report(res, states, hits, host, scope)
