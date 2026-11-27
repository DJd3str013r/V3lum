"""warninglists: MISP warninglists compact bundle - false-positive suppression and context tags (P169).

Batch p1-G11-1. Offline matching (disclosure 'none'): the investigated value never leaves the machine.
Final conditions (FC) of P169 and where they are met:

* **FC1 bundle.** A compact build of the MISP warninglists (CC0-1.0; the X4BNet-derived vpn/datacenter
  lists keep their MIT notice) ships in ``v3lum/data/warninglists/misp_warninglists.json.gz``. It is made
  by the reproducible builder of this file (``python -m v3lum.modules.threat_intel_ioc.warninglists
  build --source <clone of github.com/MISP/misp-warninglists at the pinned commit>``: sorted keys, gzip
  mtime 0) from :data:`PIN_COMMIT`; only string, hostname and cidr lists and bounded substring lists
  (<= 20,000 host-name entries, matched label-aligned) are kept, regex lists never (Python ``re`` has no
  timeout); the CI budget is :data:`BUNDLE_GZIP_BUDGET` (3 MB gzip, tested). Refresh: every bundled list
  is also a registered dataset ``warninglists.<list>`` (raw GitHub, weekly TTL, never fetched during a
  scan); a downloaded copy that parses replaces the bundled list, so ``v3lum data update`` refreshes the
  lists and the dataset manager shows their age.
* **FC2 matching.** Offline and lazy: the index is built on first use (not at start-up) and cached per
  process. CIDR lists go into one sorted interval index (``(version, start, end, list)`` rows, bisect plus
  a prefix-maximum back-scan; nested ranges are always found); host names into sets bucketed by their
  ICANN registrable domain and matched by walking the queried name's parent labels (label-aligned: no
  string suffix matching, so ``notgoogle.com`` never matches ``google.com``). The core merge (AR06) is
  the set of bundled noise fragments ``v3lum/data/noise/misp_wl_*.json`` exported by the same builder:
  the SUPPRESS lists as named ``warninglist`` lists (the engine's SUP-warninglist stage lowers malicious
  verdicts on them to POSSIBLE and never auto-pivots them), sinkholes, parking IPs, benign scanners and
  pure-CDN ranges under their AR06 noise kinds.
* **FC3 outcomes.** SUPPRESS (infrastructure values only - bare IP, CIDR, domain, hash): reserved/RFC
  ranges, special-use names, public resolvers, empty-file hashes; shown as
  'likely benign because <list> (<version date>)'. TAG: cloud, CDN, datacenter, scanner, Tor, VPN,
  sinkhole, parking, dynamic DNS, URL shortener, disposable mail, user-content hosting and the other
  context lists. A list missing from the policy table gets the context tag only: it can never suppress.
* **FC4 top sites.** Tranco/Umbrella/Radar lists (and vendor domain inventories) only tag 'popular site'
  and down-weight the reputation of the registrable domain itself (``reputation_downweight``); they never
  suppress a URL, a subdomain or a hash.
* **FC5 user content.** User-content and dynamic-DNS parents (:data:`USER_CONTENT_PARENTS`, extended at
  run time by the lots-project, link-in-bio, public-ipfs-gateways and dynamic-dns lists) are never
  suppressed; a URL with a path or query on a listed domain is tagged ``hosted_on_legit_platform`` and is
  still investigated.
* **FC6 never silent or destructive.** The module never deletes or rewrites anything: it records the
  matches; SUPPRESS lowers confidence through the core suppression stage only, TAG lists add context, a
  malicious TI finding on the same entity stays visible next to the reason and analyst overrides win
  (core, P322).
* **FC7 sinkholes and test files.** A sinkhole match sets ``is_sinkhole`` ('hits = infected clients, not
  attacker infrastructure'); a domain resolving to a sinkhole is tagged sinkholed by the correlation rule
  ``g11_sinkholed_domain`` (v3lum/correlations/p1_g11_1.py); EICAR and test-file hashes are tagged
  ``test_file`` and shown.
* **FC8 display.** Each match keeps list slug, name, version and version date (HTML/JSON);
  :func:`suppressed_summary_line` gives the collapsed terminal line; cloud/CDN/scanner matches set
  ``third_party_hosted`` (P378) and :func:`active_probe_excluded` serves the A7 CDN exclusion.
* **FC9 licences.** Notices in ``v3lum/data/notices/misp_warninglists*.json``; heavy top-1M and
  known-good-hash lists (:data:`HEAVY_OPTIONAL`) are never bundled and never fetched mid-scan.
"""

from __future__ import annotations

import argparse
import bisect
import gzip
import hashlib
import ipaddress
import json
import re
import socket
import sys
import threading
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from v3lum import paths
from v3lum.core import psl as _psl
from v3lum.core.datasets import DATASETS, DatasetError, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

# ======================================================================================
# Constants: source, pin, budget
# ======================================================================================

REPO_URL = "https://github.com/MISP/misp-warninglists"
#: Commit the bundled build was made from (FC1 pin; equal to live 'main' on 2026-11-26).
PIN_COMMIT = "922dbb3e33f078a1b646eff702e7f77e76734b29"
PIN_DATE = "2026-11-23"
#: Raw list URL used by the weekly refresh (the default branch; the build records its commit).
RAW_URL = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/{slug}/list.json"
LIST_PAGE = "https://github.com/MISP/misp-warninglists/tree/main/lists/{slug}"
SOURCE = "github.warninglists_misp"
BUNDLE_FILE = "warninglists/misp_warninglists.json.gz"
#: Small manifest (list -> kind, name, licence) read at import time to register the refresh datasets:
#: the bundle itself is only read on first use (FC2 lazy loading).
MANIFEST_FILE = "warninglists/misp_warninglists.manifest.json"
BUNDLE_SCHEMA = "v3lum.misp_warninglists_bundle/1"
MANIFEST_SCHEMA = "v3lum.misp_warninglists_manifest/1"
DATASET_PREFIX = "warninglists."
REFRESH_TTL = 7 * 86400  # FC1 weekly
#: Declared above 5 MB on purpose: refreshes happen in `v3lum data update`, never during a scan.
DATASET_MAX_BYTES = 16 * 1024 * 1024
LICENCE = "CC0-1.0"
X4BNET_LICENCE = "MIT"
X4BNET_LISTS = frozenset({"vpn-ipv4", "vpn-ipv6", "datacenter-ipv4", "datacenter-ipv6"})
X4BNET_NOTICE_PATH = "doc/licenses/X4BNet-lists_vpn.txt"
ATTRIBUTION = "MISP warninglists (https://github.com/MISP/misp-warninglists), CC0 1.0 Universal (public domain dedication)."
X4BNET_ATTRIBUTION = (
    "X4BNet-derived VPN/datacenter lists of the MISP warninglists, MIT licence, Copyright (c) 2024 X4B "
    "(https://github.com/X4BNet/lists_vpn; notice in v3lum/data/notices/misp_warninglists_x4bnet.json)."
)
BUNDLE_TYPES = ("string", "hostname", "cidr")  # FC1
SUBSTRING_MAX_ENTRIES = 20000  # FC1 'substring lists only if bounded'
BUNDLE_GZIP_BUDGET = 3 * 1024 * 1024  # FC1 CI budget (<= 3 MB gzip)
HOST_MAX_LEN = 253
#: Seconds between two checks of the downloaded list copies (the index is rebuilt when they change).
RECHECK_SECONDS = 60.0

# ======================================================================================
# Policy (FC1, FC3, FC4, FC7, FC9)
# ======================================================================================

#: FC9: heavy lists are optional `v3lum data update` downloads, never bundled or fetched mid-scan
#: (backlog: the dataset manager has no 'optional' registration flag yet, so they are not registered).
HEAVY_OPTIONAL = frozenset({
    "cisco_top1m", "cisco_top20k", "cloudflare-top1m", "cloudflare-top500k", "cloudflare-top200k",
    "cloudflare-top100k", "cloudflare-top50k", "cloudflare-top20k", "tranco", "netapi-top1m",
    "google-chrome-crux-1million", "windows-binary-hashes", "nioc-filehash", "hetzner",
})
#: Optional too (FC1 size budget): top lists that are subsets of the bundled Tranco/Umbrella/Radar 10k
#: lists or redundant, CA fingerprint lists (not an input type) and the university inventory.
OPTIONAL_EXTRA = frozenset({
    "alexa", "cisco_top1000", "cisco_top5k", "cloudflare-top200", "cloudflare-top1k", "cloudflare-top2k",
    "cloudflare-top5k", "majestic_million", "netapi-top1k", "netapi-top10k", "moz-top500",
    "mozilla-CA", "mozilla-IntermediateCA", "university_domains",
})
#: Never bundled (regex lists, inventories that are not indicator lists, stale event lists).
EXCLUDED: dict[str, str] = {
    "common-contact-emails": "regex list (FC1: Python re has no timeout)",
    "phone_numbers": "regex list (FC1: Python re has no timeout)",
    "tlds": "TLD inventory, not an indicator list",
    "second-level-tlds": "PSL-like inventory, not an indicator list (the core PSL is used)",
    "microsoft-azure-appid": "application ids are not an input type of this module",
    "covid": "stale event list",
    "covid-19-cyber-threat-coalition-whitelist": "stale event list",
    "covid-19-krassi-whitelist": "stale event list",
    "dax30": "stale vendor list",
}
#: FC3 SUPPRESS lists -> category.
SUPPRESS: dict[str, str] = {
    "rfc1918": "reserved_range", "rfc3849": "reserved_range", "rfc5735": "reserved_range",
    "rfc6598": "reserved_range", "multicast": "reserved_range", "ipv6-linklocal": "reserved_range",
    "rfc6761": "special_use_domain",
    "public-dns-v4": "public_resolver", "public-dns-v6": "public_resolver", "public-dns-hostname": "public_resolver",
    "empty-hashes": "empty_file_hash",
}
#: FC4 top-site lists (Tranco, Umbrella = cisco, Radar = cloudflare and the other popularity lists).
TOP_SITE = frozenset({
    "alexa", "cisco_top1000", "cisco_top5k", "cisco_top10k", "cisco_top20k", "cisco_top1m",
    "cloudflare-top200", "cloudflare-top1k", "cloudflare-top2k", "cloudflare-top5k", "cloudflare-top10k",
    "cloudflare-top20k", "cloudflare-top50k", "cloudflare-top100k", "cloudflare-top200k", "cloudflare-top500k",
    "cloudflare-top1m", "tranco", "tranco10k", "majestic_million", "netapi-top1k", "netapi-top10k",
    "netapi-top1m", "moz-top500", "google-chrome-crux-1million",
})
#: Vendor domain inventories: same effect as TOP-SITE (tag + registrable-domain down-weight), never SUPPRESS
#: (the 'google' list holds docs/drive/forms.google.com and security-provider-blogpost sites.google.com).
VENDOR_DOMAIN = frozenset({
    "google", "microsoft", "apple-domains", "microsoft-office365", "security-provider-blogpost", "digitalside",
    "microsoft-win10-connection-endpoints", "microsoft-win11-connection-endpoints",
})
#: TAG lists -> category (FC3, FC7).
TAG_LISTS: dict[str, str] = {
    "cloudflare": "cdn", "akamai": "cdn", "fastly": "cdn", "bunny-net": "cdn", "gcore": "cdn", "cachefly": "cdn",
    "cdn77": "cdn", "imperva": "cdn", "sucuri": "cdn", "stackpath": "cdn", "wikimedia": "cdn",
    "amazon-aws": "cloud", "google-gcp": "cloud", "microsoft-azure": "cloud", "microsoft-azure-china": "cloud",
    "microsoft-azure-germany": "cloud", "microsoft-azure-us-gov": "cloud", "oracle-oci": "cloud",
    "digitalocean": "cloud", "linode": "cloud", "ovh-cluster": "cloud", "ibm-cloud": "cloud",
    "alibaba-cloud": "cloud", "tencent-cloud": "cloud", "huawei-cloud": "cloud", "vultr": "cloud",
    "leaseweb": "cloud", "scaleway": "cloud", "rackspace": "cloud", "godaddy": "cloud", "coreweave": "cloud",
    "github": "cloud", "salesforce": "cloud", "microsoft-office365-ip": "cloud", "microsoft-office365-cn": "cloud",
    "palo-alto-networks-cortex-cloud": "cloud", "hetzner": "cloud",
    "datacenter-ipv4": "datacenter", "datacenter-ipv6": "datacenter",
    "vpn-ipv4": "vpn", "vpn-ipv6": "vpn", "google-vpn": "vpn", "icloud-private-relay": "vpn",
    "tor-exit-nodes": "tor_exit", "sinkholes": "sinkhole",
    "parking-domain": "parked", "parking-domain-ns": "parked",
    "dynamic-dns": "dynamic_dns", "url-shortener": "url_shortener", "disposable-email": "disposable_mail",
    "lots-project": "user_content_hosting", "link-in-bio": "user_content_hosting",
    "public-ipfs-gateways": "user_content_hosting",
    "eicar.com": "test_file",  # FC7: tagged test_file and shown, never suppressed
    "ti-falsepositives": "known_fp", "common-ioc-false-positive": "known_fp",
    "smtp-sending-ips": "mail_infrastructure", "smtp-receiving-ips": "mail_infrastructure",
    "google-gmail-sending-ips": "mail_infrastructure", "personal-email-domains": "mail_infrastructure",
    "automated-malware-analysis": "malware_analysis_service", "microsoft-attack-simulator": "attack_simulation",
    "crl-hostname": "vendor_service", "crl-ip": "vendor_service", "captive-portals": "vendor_service",
    "whats-my-ip": "vendor_service", "findip-host": "vendor_service", "umbrella-blockpage-hostname": "vendor_service",
    "umbrella-blockpage-v4": "vendor_service", "umbrella-blockpage-v6": "vendor_service",
    "microsoft-mdca-proxy": "vendor_service", "zscaler": "vendor_service", "telegram-ips": "vendor_service",
    "apple": "vendor_service", "apple-ipv4": "vendor_service", "apple-ipv6": "vendor_service",
    "googlebot": "benign_scanner", "openai-gptbot": "benign_scanner", "check-host-net": "benign_scanner",
    "umich-cse-connection-attempts": "benign_scanner", "tenable-cloud-ipv4": "benign_scanner",
    "tenable-cloud-ipv6": "benign_scanner", "palo-alto-networks-cortex-xpanse": "benign_scanner",
    "shadowserver": "benign_scanner",
    "mozilla-CA": "ca_certificate", "mozilla-IntermediateCA": "ca_certificate",
    "bank-website": "bank_website", "university_domains": "university",
}
#: FC5 user-content / dynamic-DNS lists that extend :data:`USER_CONTENT_PARENTS` at run time.
UCP_LISTS = frozenset({"lots-project", "link-in-bio", "public-ipfs-gateways", "dynamic-dns"})
#: FC5 floor: user-content and dynamic-DNS parents that are never suppressed, even in a top or vendor list.
USER_CONTENT_PARENTS = frozenset({
    "docs.google.com", "sites.google.com", "drive.google.com", "forms.google.com", "forms.gle",
    "storage.googleapis.com", "firebasestorage.googleapis.com", "blob.core.windows.net", "web.core.windows.net",
    "sharepoint.com", "onedrive.live.com", "1drv.ms", "github.io", "raw.githubusercontent.com",
    "gist.githubusercontent.com", "blogspot.com", "firebaseapp.com", "web.app", "pages.dev", "workers.dev",
    "r2.dev", "ngrok.io", "ngrok-free.app", "ngrok.app", "duckdns.org", "appspot.com", "herokuapp.com",
    "netlify.app", "vercel.app", "glitch.me", "s3.amazonaws.com", "dl.dropboxusercontent.com",
    "notion.site", "wixsite.com", "weebly.com", "webflow.io", "telegra.ph", "ipfs.io",
})
#: FC3: the only entity types SUPPRESS may apply to (a URL never is).
SUPPRESSIBLE_TYPES = frozenset({T.IPV4, T.IPV6, T.CIDR, T.DOMAIN, T.MD5, T.SHA1, T.SHA256})
#: FC8: categories that feed P378 third_party_hosted / the A7 ACTIVE CDN exclusion.
THIRD_PARTY_CATEGORIES = frozenset({"cloud", "cdn", "benign_scanner"})
ACTIVE_EXCLUDED_CATEGORIES = frozenset({"cloud", "cdn"})


def list_policy(slug: Any) -> dict[str, Any]:
    """Outcome of one warninglist: ``{'outcome': suppress|tag|top_site|exclude, 'category', 'basis'}``.

    Lists not named by the policy get the context-only category ``listed``: they can never suppress."""
    if not isinstance(slug, str) or not slug:
        return {"outcome": "exclude", "category": None, "basis": "invalid list name"}
    if slug in EXCLUDED:
        return {"outcome": "exclude", "category": None, "basis": EXCLUDED[slug]}
    if slug in SUPPRESS:
        return {"outcome": "suppress", "category": SUPPRESS[slug], "basis": "FC3 suppress category"}
    if slug in TOP_SITE:
        return {"outcome": "top_site", "category": "popular_site", "basis": "FC4 top-site list"}
    if slug in VENDOR_DOMAIN:
        return {"outcome": "top_site", "category": "known_vendor_domain", "basis": "vendor domain inventory (FC4 treatment)"}
    if slug in TAG_LISTS:
        return {"outcome": "tag", "category": TAG_LISTS[slug], "basis": "FC3/FC7 tag category"}
    if slug.endswith(("-scanning", "-scanner")):
        return {"outcome": "tag", "category": "benign_scanner", "basis": "FC3 scanner list"}
    return {"outcome": "tag", "category": "listed", "basis": "not in the policy table: context tag only"}


# ======================================================================================
# Parsing (FC1)
# ======================================================================================

_HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{56}|[0-9a-f]{64}|[0-9a-f]{96}|[0-9a-f]{128})$")
_SSDEEP_RE = re.compile(r"^\d{1,10}:[A-Za-z0-9/+]{0,128}:[A-Za-z0-9/+]{0,128}$")
_HOST_RE = re.compile(r"[a-z0-9_-]{1,63}(?:\.[a-z0-9_-]{1,63})*")
_HTML_START = re.compile(r"^\s*(?:<!doctype\s+html|<html\b|<head\b|<body\b|<\?xml\b|<title\b)", re.I)
_VERSION_DATE = re.compile(r"^(\d{4})(\d{2})(\d{2})$")


def version_date(version: Any) -> str | None:
    """MISP YYYYMMDD version -> 'YYYY-MM-DD' (None for other formats, e.g. '26100813')."""
    if isinstance(version, bool) or not isinstance(version, (int, str)):
        return None
    m = _VERSION_DATE.match(str(version).strip())
    if not m:
        return None
    y, mo, d = (int(x) for x in m.groups())
    if not (1990 <= y <= 2100 and 1 <= mo <= 12 and 1 <= d <= 31):
        return None
    return f"{y:04d}-{mo:02d}-{d:02d}"


def normalise_host(value: Any) -> str | None:
    """Lower-case ASCII host name (trailing dot removed, IDN -> punycode); None when not a host name."""
    if not isinstance(value, str):
        return None
    h = value.strip().strip(".").lower()
    if not h or len(h) > HOST_MAX_LEN:
        return None
    if not h.isascii():
        try:
            h = h.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return h if _HOST_RE.fullmatch(h) else None


def _host_entry(entry: Any) -> tuple[str, bool] | None:
    """Hostname-list entry -> (host, subdomains_only); '.x.com' and '*.x.com' match subdomains only."""
    if not isinstance(entry, str):
        return None
    e = entry.strip().lower()
    sub_only = False
    if e.startswith("*."):
        e, sub_only = e[2:], True
    elif e.startswith("."):
        e, sub_only = e[1:], True
    host = normalise_host(e)
    return (host, sub_only) if host else None


def _cidr_entry(entry: Any) -> str | None:
    if not isinstance(entry, str):
        return None
    try:
        return str(ipaddress.ip_network(entry.strip(), strict=False))
    except ValueError:
        return None


def _as_text(raw: Any) -> str | None:
    if isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
        if data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("cp1252", errors="replace")
    if isinstance(raw, str):
        return raw[1:] if raw.startswith("﻿") else raw
    return None


def parse_json_body(raw: Any) -> tuple[Any, str | None]:
    """(obj, marker): JSON from bytes/str/parsed data; HTML, empty and truncated bodies give a marker
    ('error: ...' | 'unavailable: ...'), never an empty list."""
    if isinstance(raw, (dict, list)):
        return raw, None
    text = _as_text(raw)
    if text is None:
        return None, "error: no body"
    if not text.strip():
        return None, "error: empty body"
    if _HTML_START.match(text[:2048]):
        return None, "error: HTML instead of JSON"
    stripped = text.strip()
    if stripped in ("404: Not Found", "400: Invalid request"):
        return None, f"unavailable: {stripped}"
    try:
        return json.loads(text), None
    except (ValueError, RecursionError) as exc:
        return None, f"error: malformed JSON ({str(exc)[:80]})"


def parse_warninglist(raw: Any, slug: str | None = None) -> dict[str, Any]:
    """One MISP ``list.json`` -> normalised dict (never raises).

    Keys: slug, name, type, version, version_date, description, category, entries (normalised, de-duplicated),
    subdomain_only (hostname entries with a leading dot), invalid_count, kind (ip | host | hash | host_string),
    bounded, excluded_reason, marker, empty. CIDR entries accept bare IPs, '/32' and upper-case IPv6."""
    obj, marker = parse_json_body(raw)
    out: dict[str, Any] = {
        "slug": slug, "name": None, "type": None, "version": None, "version_date": None, "description": None,
        "category": None, "entries": [], "subdomain_only": set(), "invalid_count": 0, "kind": None, "bounded": True,
        "excluded_reason": None, "marker": marker, "empty": False,
    }
    if marker:
        return out
    if not isinstance(obj, dict):
        out["marker"] = "error: list.json is not a JSON object"
        return out
    out["name"] = obj["name"].strip() if isinstance(obj.get("name"), str) else None
    ltype = obj.get("type") if isinstance(obj.get("type"), str) else None
    out["type"] = ltype
    version = obj.get("version")
    out["version"] = version if isinstance(version, (int, str)) and not isinstance(version, bool) else None
    out["version_date"] = version_date(out["version"])
    out["description"] = obj.get("description") if isinstance(obj.get("description"), str) else None
    out["category"] = obj.get("category") if isinstance(obj.get("category"), str) else None
    entries = obj.get("list")
    if not isinstance(entries, list):
        out["marker"] = "error: 'list' missing or not an array"
        return out
    if ltype == "regex":
        out["excluded_reason"] = "regex list (FC1: Python re has no timeout)"
        return out
    if ltype not in (*BUNDLE_TYPES, "substring"):
        out["excluded_reason"] = f"unsupported list type {ltype!r}"
        return out
    seen: set[str] = set()
    norm: list[str] = []
    bad = 0
    for raw_entry in entries:
        value: str | None = None
        if ltype == "cidr":
            value = _cidr_entry(raw_entry)
        elif ltype in ("hostname", "substring"):
            parsed = _host_entry(raw_entry)
            if parsed:
                value = parsed[0]
                if parsed[1]:
                    out["subdomain_only"].add(value)
        elif isinstance(raw_entry, str) and raw_entry.strip():
            value = raw_entry.strip().lower()
        if value is None:
            bad += 1
            continue
        if value not in seen:
            seen.add(value)
            norm.append(value)
    out["entries"] = norm
    out["invalid_count"] = bad
    out["empty"] = not norm
    if ltype == "cidr":
        out["kind"] = "ip"
    elif ltype in ("hostname", "substring"):
        out["kind"] = "host"
    else:
        hashes = sum(1 for v in norm if _HASH_RE.match(v) or _SSDEEP_RE.match(v))
        out["kind"] = "hash" if norm and hashes >= 0.8 * len(norm) else "host_string"
    if ltype == "substring":
        # bounded = few entries, all of them host names: matched label-aligned, never as raw substrings
        out["bounded"] = len(entries) <= SUBSTRING_MAX_ENTRIES and bad == 0
        if not out["bounded"]:
            out["excluded_reason"] = "substring list not bounded (FC1)"
    return out


# ======================================================================================
# Compact bundle builder (FC1, FC9) - the reproducible dev script
# ======================================================================================


def build_compact_bundle(parsed: Mapping[str, dict[str, Any]], *, commit: str, built: str, source_dates: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Select and pack parsed lists into the compact bundle (deterministic for one input).

    Keeps string/hostname/cidr lists and bounded substring lists; drops heavy optional, optional-extra,
    regex, excluded, empty and unparsable lists and records why under ``excluded``."""
    lists: dict[str, dict[str, Any]] = {}
    excluded: dict[str, str] = {}
    for slug in sorted(parsed):
        p = parsed[slug]
        pol = list_policy(slug)
        reason = None
        if not isinstance(p, dict):
            reason = "not parsed"
        elif p.get("marker"):
            reason = str(p["marker"])
        elif p.get("excluded_reason"):
            reason = str(p["excluded_reason"])
        elif slug in HEAVY_OPTIONAL:
            reason = "heavy list: optional download, never bundled (FC9)"
        elif slug in OPTIONAL_EXTRA:
            reason = "redundant or off-scope list: optional download (FC1 size budget)"
        elif pol["outcome"] == "exclude":
            reason = str(pol["basis"])
        elif p.get("empty"):
            reason = "empty list"
        if reason:
            excluded[slug] = reason
            continue
        lists[slug] = {
            "name": p.get("name") or slug,
            "type": p.get("type"),
            "kind": p.get("kind"),
            "version": p.get("version"),
            "version_date": p.get("version_date"),
            "outcome": pol["outcome"],
            "category": pol["category"],
            "licence": X4BNET_LICENCE if slug in X4BNET_LISTS else LICENCE,
            "entries": sorted(p.get("entries") or []),
            "subdomain_only": sorted(p.get("subdomain_only") or ()),
        }
    meta = {
        "schema": BUNDLE_SCHEMA,
        "source": REPO_URL,
        "commit": commit,
        "commit_date": (source_dates or {}).get("commit_date", ""),
        "built": built,
        "licence": f"{LICENCE} (MISP warninglists); {X4BNET_LICENCE} for {', '.join(sorted(X4BNET_LISTS))} ({X4BNET_NOTICE_PATH})",
        "x4bnet_mit_lists": sorted(s for s in lists if s in X4BNET_LISTS),
        "list_count": len(lists),
        "entry_count": sum(len(v["entries"]) for v in lists.values()),
    }
    return {"_meta": meta, "lists": lists, "excluded": excluded}


def bundle_bytes(bundle: Mapping[str, Any]) -> bytes:
    """Reproducible gzip of the bundle (sorted keys, compact separators, mtime 0)."""
    raw = json.dumps(bundle, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode("utf-8")
    return gzip.compress(raw, compresslevel=9, mtime=0)


def bundle_manifest(bundle: Mapping[str, Any], bundle_sha256: str) -> dict[str, Any]:
    """The small manifest shipped next to the bundle: {list: {kind, name, licence, outcome, category}}."""
    meta = bundle.get("_meta") or {}
    return {
        "schema": MANIFEST_SCHEMA,
        "bundle": BUNDLE_FILE,
        "bundle_sha256": bundle_sha256,
        "commit": meta.get("commit"),
        "built": meta.get("built"),
        "lists": {
            slug: {k: lst.get(k) for k in ("kind", "name", "licence", "outcome", "category", "version_date")}
            for slug, lst in sorted((bundle.get("lists") or {}).items())
        },
    }


def bundle_size_report(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """``{'raw_bytes', 'gzip_bytes', 'within_budget', 'sha256_gzip'}`` (FC1 CI budget)."""
    raw = json.dumps(bundle, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode("utf-8")
    gz = bundle_bytes(bundle)
    return {"raw_bytes": len(raw), "gzip_bytes": len(gz), "within_budget": len(gz) <= BUNDLE_GZIP_BUDGET, "sha256_gzip": hashlib.sha256(gz).hexdigest()}


#: AR06 export: TAG categories that map onto core noise kinds (pure CDN edges, not whole clouds: rented
#: compute stays pivotable, P034) - sinkholes, parking IPs and benign scanners.
NOISE_KIND_EXPORT: dict[str, tuple[str, str, str]] = {
    # category: (noise kind, fragment stem, list name)
    "sinkhole": ("sinkhole", "misp_wl_sinkholes", "misp.sinkholes"),
    "benign_scanner": ("benign_scanner", "misp_wl_benign_scanners", "misp.benign-scanners"),
    "cdn": ("cdn", "misp_wl_cdn", "misp.cdn"),
}
#: Parking: only the IPs of parking services (the parking-domain-ns list holds registrar and hosting
#: name servers; the curated subset typosquat_parking_ns of batch p1-G01-2 covers parking NS).
NOISE_PARKING = ("parking-domain", "parked", "misp_wl_parking", "misp.parking-ips")
#: SUPPRESS lists exported to the core as named warninglists. rfc3849 (2001:db8::/32) and rfc6761
#: (example.*, test, localhost, invalid) are documentation/test values only: they stay module-level so
#: that the core keeps treating documentation values like real hosts (the team's fixtures must use them).
CORE_SUPPRESS_EXPORT = ("rfc1918", "rfc5735", "rfc6598", "multicast", "ipv6-linklocal", "public-dns-v4", "public-dns-v6", "public-dns-hostname")
#: Documentation ranges and reserved example names never exported to the core (RFC 5737, 3849, 2606).
DOC_NETS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))
RESERVED_NAMES = frozenset({"example", "example.com", "example.net", "example.org", "test", "invalid", "localhost"})


def _documentation_value(value: str) -> bool:
    """True for documentation ranges (RFC 5737/3849) and RFC 2606/6761 example names (label-aligned)."""
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return _under(value, RESERVED_NAMES)
    return any(net.version == d.version and net.overlaps(d) for d in DOC_NETS)


def _ucp_hosts(lists: Mapping[str, Mapping[str, Any]]) -> frozenset[str]:
    hosts = set(USER_CONTENT_PARENTS)
    for slug in UCP_LISTS:
        lst = lists.get(slug)
        if lst and lst.get("kind") == "host":
            hosts.update(lst.get("entries") or ())
    return frozenset(hosts)


def _under(host: str, parents: frozenset[str]) -> bool:
    labels = host.split(".")
    return any(".".join(labels[i:]) in parents for i in range(len(labels)))


def _noise_ok_domain(host: str) -> bool:
    """The host shape the core noise loader accepts (at least two labels, LDH/underscore labels)."""
    return "." in host and bool(re.fullmatch(r"(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*", host))


def _split_ip_entries(entries: Iterable[str]) -> tuple[list[str], list[str]]:
    ips: list[str] = []
    cidrs: list[str] = []
    for value in entries:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if net.prefixlen == net.max_prefixlen:
            ips.append(str(net.network_address))
        else:
            cidrs.append(str(net))
    return sorted(set(ips)), sorted(set(cidrs))


def noise_fragments(bundle: Mapping[str, Any], *, checked_at: str) -> dict[str, dict[str, Any]]:
    """AR06 merge into core/noise.py: ``{file stem: v3lum.noise/1 fragment}`` built from the bundle.

    SUPPRESS lists become named ``warninglist`` lists (hash lists excepted: noise fragments hold domains,
    IPs and CIDRs only - empty-file hashes stay module-level). Host entries under user-content or
    dynamic-DNS parents are left out (FC5) and so are names the noise loader would refuse."""
    lists = bundle.get("lists") or {}
    meta = bundle.get("_meta") or {}
    commit = str(meta.get("commit") or "")
    ucp = _ucp_hosts(lists)
    out: dict[str, dict[str, Any]] = {}

    def fragment(kind: str, name: str, slugs: list[str], description: str) -> dict[str, Any] | None:
        domains: set[str] = set()
        ip_values: list[str] = []
        versions: list[str] = []
        for slug in slugs:
            lst = lists[slug]
            versions.append(f"{slug} {lst.get('version_date') or lst.get('version')}")
            if lst.get("kind") == "ip":
                ip_values.extend(v for v in lst.get("entries") or () if not _documentation_value(v))
            elif lst.get("kind") in ("host", "host_string"):
                for host in lst.get("entries") or ():
                    if _noise_ok_domain(host) and not _under(host, ucp) and not _documentation_value(host):
                        domains.add(host)
        ips, cidrs = _split_ip_entries(ip_values)
        if not (domains or ips or cidrs):
            return None
        doc: dict[str, Any] = {
            "schema": "v3lum.noise/1",
            "kind": kind,
            "name": name,
            "source": f"{REPO_URL} lists/{', lists/'.join(slugs)} (commit {commit})",
            "licence": "CC0-1.0 (MISP warninglists)",
            "description": description,
            "version": "; ".join(versions),
            "checked_at": checked_at,
            "notes": "Generated by v3lum/modules/threat_intel_ioc/warninglists.py (batch p1-G11-1, P169) from the bundled build: do not edit by hand.",
        }
        if domains:
            doc["domains"] = sorted(domains)
        if ips:
            doc["ips"] = ips
        if cidrs:
            doc["cidrs"] = cidrs
        return doc

    for slug, lst in sorted(lists.items()):
        if slug not in CORE_SUPPRESS_EXPORT or lst.get("outcome") != "suppress" or lst.get("kind") not in ("ip", "host", "host_string"):
            continue
        doc = fragment("warninglist", f"misp.{slug}", [slug], f"MISP warninglist '{lst.get('name')}' (P169 SUPPRESS: likely benign)")
        if doc:
            out[f"misp_wl_{slug.replace('-', '_')}"] = doc
    for category, (kind, stem, name) in NOISE_KIND_EXPORT.items():
        slugs = sorted(s for s, lst in lists.items() if lst.get("category") == category and lst.get("kind") == "ip")
        if slugs:
            doc = fragment(kind, name, slugs, f"MISP warninglists of category '{category}' (P169 TAG, AR06 noise kind {kind})")
            if doc:
                out[stem] = doc
    slug, kind, stem, name = NOISE_PARKING
    if slug in lists and lists[slug].get("kind") == "ip":
        doc = fragment(kind, name, [slug], "IP addresses of domain-parking services (MISP warninglist parking-domain)")
        if doc:
            out[stem] = doc
    return out


def read_clone_lists(source: Path) -> dict[str, dict[str, Any]]:
    """Parse every ``lists/<slug>/list.json`` of a local clone (dev script input)."""
    parsed: dict[str, dict[str, Any]] = {}
    base = Path(source) / "lists"
    for path in sorted(base.glob("*/list.json")):
        slug = path.parent.name
        parsed[slug] = parse_warninglist(path.read_bytes(), slug)
    return parsed


def build_from_clone(source: Path, *, commit: str, built: str, commit_date: str = "") -> dict[str, Any]:
    return build_compact_bundle(read_clone_lists(source), commit=commit, built=built, source_dates={"commit_date": commit_date})


# ======================================================================================
# Registrable domain (FC2, FC4): the core's bundled, unmodified PSL
# ======================================================================================


def registrable_domain(host: Any) -> str | None:
    """eTLD+1 of ``host`` with the full PSL (the reputation unit: 'evil.github.io' is its own registrable
    domain); None when the name is itself a public suffix ('duckdns.org', 'github.io') or invalid."""
    h = normalise_host(host)
    if not h:
        return None
    return _psl.registrable_domain(h)


# ======================================================================================
# Index (FC2): shared IP interval index, PSL-bucketed host sets, exact strings
# ======================================================================================


def _ip_range(value: str) -> tuple[int, int, int] | None:
    """'a.b.c.d/nn' or 'v6::/nn' -> (version, start, end). socket.inet_pton is a pure converter here
    (several times faster than ipaddress on the ~220k bundled ranges); odd forms fall back to ipaddress."""
    addr, _, pfx = value.partition("/")
    try:
        if ":" in addr:
            n, width, version = int.from_bytes(socket.inet_pton(socket.AF_INET6, addr), "big"), 128, 6
        else:
            n, width, version = int.from_bytes(socket.inet_pton(socket.AF_INET, addr), "big"), 32, 4
        bits = int(pfx) if pfx else width
        if not 0 <= bits <= width:
            return None
    except (OSError, ValueError):
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
        return net.version, int(net.network_address), int(net.broadcast_address)
    host_mask = (1 << (width - bits)) - 1
    start = n & ~host_mask
    return version, start, start | host_mask


class IntervalIndex:
    """Sorted ``(start, end, label)`` rows per IP version with a prefix-maximum end: a lookup bisects on
    the start and scans back while the running maximum still covers the address, so nested and
    overlapping ranges are always found (no fixed back-scan window)."""

    __slots__ = ("_tables",)

    def __init__(self, rows: Iterable[tuple[int, int, int, Any]] = ()) -> None:
        per: dict[int, list[tuple[int, int, Any]]] = {4: [], 6: []}
        for version, start, end, label in rows:
            per[version].append((start, end, label))
        self._tables: dict[int, tuple[list[int], list[tuple[int, int, Any]], list[int]]] = {}
        for version, rs in per.items():
            rs.sort(key=lambda r: (r[0], r[1]))
            maxend: list[int] = []
            m = -1
            for _s, e, _l in rs:
                m = e if e > m else m
                maxend.append(m)
            self._tables[version] = ([r[0] for r in rs], rs, maxend)

    def __len__(self) -> int:
        return sum(len(t[1]) for t in self._tables.values())

    def lookup(self, value: Any) -> list[Any]:
        """Labels of every range containing the address (sorted, unique; [] for invalid input)."""
        try:
            ip = ipaddress.ip_address(str(value).strip().strip("[]"))
        except ValueError:
            return []
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        starts, rows, maxend = self._tables[ip.version]
        v = int(ip)
        i = bisect.bisect_right(starts, v) - 1
        out: set[Any] = set()
        while i >= 0 and maxend[i] >= v:
            s, e, label = rows[i]
            if s <= v <= e:
                out.add(label)
            i -= 1
        return sorted(out)

    def lookup_network(self, value: Any) -> tuple[list[Any], list[Any]]:
        """(contained_in, partial_overlaps) for a CIDR: ranges holding the whole network apply; ranges that
        only overlap it are shown, never applied."""
        try:
            net = ipaddress.ip_network(str(value).strip(), strict=False)
        except ValueError:
            return [], []
        starts, rows, maxend = self._tables[net.version]
        lo, hi = int(net.network_address), int(net.broadcast_address)
        contained: set[Any] = set()
        overlaps: set[Any] = set()
        i = bisect.bisect_right(starts, hi) - 1
        while i >= 0 and maxend[i] >= lo:
            s, e, label = rows[i]
            if s <= lo and e >= hi:
                contained.add(label)
            elif s <= hi and e >= lo:
                overlaps.add(label)
            i -= 1
        return sorted(contained), sorted(overlaps - contained)


@dataclass
class ListMeta:
    slug: str
    name: str
    version: Any
    version_date: str | None
    outcome: str
    category: str
    kind: str
    licence: str
    origin: str  # 'bundled' | 'downloaded'
    fetched_at: str = ""


@dataclass
class WarninglistIndex:
    """The lookup index of one bundle (+ downloaded list copies)."""

    meta: dict[str, Any]
    lists: dict[str, ListMeta]
    ip: IntervalIndex
    hosts: dict[str, list[tuple[str, bool]]]
    strings: dict[str, list[str]]
    ucp_hosts: frozenset[str]
    skipped_hosts: int = 0
    downloaded: list[str] = field(default_factory=list)
    bundle_sha256: str = ""
    build_seconds: float = 0.0

    # ---- lookups ---------------------------------------------------------------------
    def _match(self, slug: str, match: str, entry: str | None = None) -> dict[str, Any]:
        m = self.lists[slug]
        return {
            "list": slug, "name": m.name, "version": m.version, "version_date": m.version_date, "outcome": m.outcome,
            "category": m.category, "match": match, "entry": entry, "licence": m.licence, "origin": m.origin,
        }

    def host_matches(self, host: str) -> list[dict[str, Any]]:
        """Label-aligned matches of a host name (FC2): the name itself (exact) or one of its parent names
        down to two labels (subdomain) - never a raw string suffix, so 'notgoogle.com' never matches
        'google.com'. A parent above the name's PSL registrable domain (a public suffix such as
        duckdns.org or github.io) is flagged ``above_registrable``: it may tag, never suppress."""
        h = normalise_host(host)
        if not h:
            return []
        rd = _psl.registrable_domain(h)
        labels = h.split(".")
        out: list[dict[str, Any]] = []
        for i in range(0, max(0, len(labels) - 1)):
            cand = ".".join(labels[i:])
            hits = self.hosts.get(cand)
            if not hits:
                continue
            above = i > 0 and (rd is None or len(cand) < len(rd))
            for slug, sub_only in hits:
                if i == 0 and sub_only:
                    continue
                m = self._match(slug, "exact" if i == 0 else "subdomain", cand)
                m["above_registrable"] = above
                out.append(m)
        for slug in self.strings.get(h, ()):
            if self.lists[slug].kind == "host_string":
                out.append(self._match(slug, "exact", h))
        return out

    def lookup(self, etype: T, value: str) -> list[dict[str, Any]]:
        """Matches of one entity: [{list, name, version, version_date, outcome, category, match, entry, ...}],
        one per list, the most specific first (exact > subdomain > range)."""
        out: list[dict[str, Any]] = []
        v = str(value or "").strip()
        if etype is T.URL:
            parts = url_parts(v)
            host = parts["host"]
            if not host:
                return []
            try:
                ipaddress.ip_address(host)
            except ValueError:
                out = self.host_matches(host)
            else:
                out = [self._match(s, "ip_in_range", host) for s in self.ip.lookup(host)]
        elif etype in (T.IPV4, T.IPV6):
            out = [self._match(s, "ip_in_range", v) for s in self.ip.lookup(v)]
        elif etype is T.CIDR:
            contained, partial = self.ip.lookup_network(v)
            out = [self._match(s, "cidr_contained", v) for s in contained]
            out += [self._match(s, "cidr_partial_overlap", v) for s in partial]
        elif etype is T.DOMAIN:
            out = self.host_matches(v)
        elif etype in (T.MD5, T.SHA1, T.SHA256):
            key = v.lower()
            out = [self._match(s, "exact", key) for s in self.strings.get(key, ()) if self.lists[s].kind == "hash"]
        rank = {"exact": 0, "ip_in_range": 0, "cidr_contained": 0, "subdomain": 1, "cidr_partial_overlap": 2}
        best: dict[str, dict[str, Any]] = {}
        for m in out:
            cur = best.get(m["list"])
            if cur is None or (rank.get(m["match"], 3), -len(m.get("entry") or "")) < (rank.get(cur["match"], 3), -len(cur.get("entry") or "")):
                best[m["list"]] = m
        return sorted(best.values(), key=lambda m: m["list"])

    def build_info(self) -> dict[str, Any]:
        return {
            "source": "MISP warninglists",
            "commit": self.meta.get("commit"),
            "built": self.meta.get("built"),
            "bundle_sha256": self.bundle_sha256,
            "lists": len(self.lists),
            "downloaded_lists": len(self.downloaded),
        }


def build_index(bundle_lists: Mapping[str, Mapping[str, Any]], meta: Mapping[str, Any], *, overrides: Mapping[str, tuple[dict[str, Any], str]] | None = None) -> WarninglistIndex:
    """Index the bundle's lists; ``overrides`` = {slug: (parsed downloaded list, fetched_at)} replace them."""
    started = time.monotonic()
    overrides = overrides or {}
    lists: dict[str, ListMeta] = {}
    rows: list[tuple[int, int, int, str]] = []
    hosts: dict[str, list[tuple[str, bool]]] = {}
    strings: dict[str, list[str]] = {}
    skipped = 0
    downloaded: list[str] = []
    ucp = set(USER_CONTENT_PARENTS)
    for slug in sorted(bundle_lists):
        base = bundle_lists[slug]
        entries: Iterable[str] = base.get("entries") or ()
        sub_only = set(base.get("subdomain_only") or ())
        kind = str(base.get("kind") or "")
        version, vdate, origin, fetched = base.get("version"), base.get("version_date"), "bundled", ""
        override = overrides.get(slug)
        if override is not None:
            parsed, fetched = override
            if parsed.get("kind") == kind and not parsed.get("marker") and not parsed.get("excluded_reason") and parsed.get("entries"):
                entries, sub_only = parsed["entries"], set(parsed.get("subdomain_only") or ())
                version, vdate, origin = parsed.get("version"), parsed.get("version_date"), "downloaded"
                downloaded.append(slug)
        lists[slug] = ListMeta(
            slug=slug, name=str(base.get("name") or slug), version=version, version_date=vdate,
            outcome=str(base.get("outcome") or "tag"), category=str(base.get("category") or "listed"), kind=kind,
            licence=str(base.get("licence") or LICENCE), origin=origin, fetched_at=fetched,
        )
        if kind == "ip":
            for value in entries:
                r = _ip_range(value)
                if r is not None:
                    rows.append((r[0], r[1], r[2], slug))
        elif kind == "host":
            for host in entries:
                if "." not in host:  # single labels ('android', 'localhost'): never a host name match
                    skipped += 1
                    continue
                hosts.setdefault(host, []).append((slug, host in sub_only))
            if slug in UCP_LISTS:
                ucp.update(entries)
        else:  # hash / host_string: exact match only
            for value in entries:
                strings.setdefault(value, []).append(slug)
    index = WarninglistIndex(
        meta=dict(meta), lists=lists, ip=IntervalIndex(rows), hosts=hosts, strings=strings,
        ucp_hosts=frozenset(ucp), skipped_hosts=skipped, downloaded=downloaded,
    )
    index.build_seconds = round(time.monotonic() - started, 3)
    return index


# ======================================================================================
# Classification (FC3-FC8)
# ======================================================================================


#: Partial CIDR overlaps named in a note (the rest are counted).
PARTIAL_SHOWN = 10
#: Categories whose names are not legitimate platforms (FC5 hosted_on_legit_platform is not set for them).
NOT_PLATFORM_CATEGORIES = frozenset({"dynamic_dns", "sinkhole", "parked", "test_file", "known_fp", "benign_scanner", "tor_exit", "vpn"})


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def url_parts(url: Any) -> dict[str, Any]:
    """``{'host', 'has_path_or_query'}`` (bare host = no path beyond '/', no query or fragment)."""
    if not isinstance(url, str) or not url.strip():
        return {"host": None, "has_path_or_query": False}
    u = url.strip()
    if "://" not in u:
        u = "http://" + u
    try:
        parts = urlsplit(u)
        host = parts.hostname
    except ValueError:
        return {"host": None, "has_path_or_query": False}
    path = parts.path or ""
    return {"host": normalise_host(host) if host else None, "has_path_or_query": bool(path not in ("", "/") or parts.query or parts.fragment)}


def user_content_parent(host: Any, extra: Iterable[str] = ()) -> str | None:
    """The user-content / dynamic-DNS parent covering ``host`` (label-aligned), else None (FC5)."""
    h = normalise_host(host)
    if not h:
        return None
    parents = USER_CONTENT_PARENTS | frozenset(extra or ())
    labels = h.split(".")
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if cand in parents:
            return cand
    return None


def match_display(match: Mapping[str, Any]) -> str:
    """FC3 display text: 'likely benign because <list name> (<version date>)'."""
    name = match.get("name") or match.get("list") or "warninglist"
    when = match.get("version_date") or (str(match.get("version")) if match.get("version") else "undated")
    return f"likely benign because {name} ({when})"


def classify(etype: T, value: str, matches: list[dict[str, Any]], *, extra_parents: Iterable[str] = ()) -> dict[str, Any]:
    """Apply FC3-FC8 to one entity's matches; never deletes anything (FC6).

    Returns {'outcome' suppress|tag|none, 'suppressed', 'categories', 'suppress_matches', 'top_matches',
    'tag_matches', 'reasons', 'popular_site', 'downweight', 'hosted_on_legit_platform', 'user_content_parent',
    'never_suppress_reason', 'is_sinkhole', 'is_parked', 'third_party_hosted', 'active_probe_excluded', 'notes'}."""
    notes: list[str] = []
    host = None
    path_or_query = False
    if etype is T.URL:
        parts = url_parts(value)
        host, path_or_query = parts["host"], parts["has_path_or_query"]
    elif etype is T.DOMAIN:
        host = normalise_host(value)
    real = [m for m in matches if m.get("match") != "cidr_partial_overlap"]
    partial = [m for m in matches if m.get("match") == "cidr_partial_overlap"]
    if partial:
        shown = ", ".join(str(m.get("list")) for m in partial[:PARTIAL_SHOWN])
        more = f" and {len(partial) - PARTIAL_SHOWN} more" if len(partial) > PARTIAL_SHOWN else ""
        notes.append(f"partially overlaps {shown}{more} (never applied: look the addresses up one by one)")
    ucp_lists = sorted({m["list"] for m in real if m.get("list") in UCP_LISTS})
    ucp = user_content_parent(host, extra_parents) if host else None
    if not ucp and ucp_lists:
        ucp = "listed in " + ", ".join(ucp_lists)
    # a parent above the registrable domain (a public suffix: user-content or dynamic-DNS platform) never suppresses
    suppress_hits = [m for m in real if m.get("outcome") == "suppress" and not m.get("above_registrable")]
    for m in real:
        if m.get("outcome") == "suppress" and m.get("above_registrable"):
            notes.append(f"{m.get('entry')} is listed in {m.get('name') or m.get('list')} but is a public suffix above {host}: not applied")
    tag_hits = [m for m in real if m.get("outcome") == "tag"]
    categories: set[str] = {str(m["category"]) for m in tag_hits if m.get("category")}
    # FC4: a top-site/vendor list counts only when the listed entry is the host itself (or the entity is
    # not a host); a listed registrable domain or platform parent is a note, never a down-weight.
    rd_full = registrable_domain(host) if host else None
    top_scoped: list[dict[str, Any]] = []
    for m in real:
        if m.get("outcome") != "top_site":
            continue
        entry = m.get("entry") or host
        if host is None or entry == host:
            top_scoped.append(m)
        elif rd_full and entry == rd_full:
            notes.append(f"registrable domain {rd_full} is listed in {m.get('name') or m.get('list')}: context only, no down-weight for {host}")
        else:
            notes.append(f"parent {entry} is listed in {m.get('name') or m.get('list')}; {host} is judged on its own")
    popular = any(m.get("category") == "popular_site" for m in top_scoped)
    if popular:
        categories.add("popular_site")
    if any(m.get("category") == "known_vendor_domain" for m in top_scoped):
        categories.add("known_vendor_domain")
    if ucp and "dynamic_dns" not in categories:
        categories.add("user_content_hosting")
    # FC5: a URL with a path or query on a listed *domain* (not an IP, not a dynamic-DNS, sinkhole or parking
    # name: those are not legitimate platforms) is tagged and still investigated
    host_is_name = bool(host) and not _is_ip(host)
    platform_hits = [m for m in real if m.get("category") not in NOT_PLATFORM_CATEGORIES]
    hosted = bool(etype is T.URL and path_or_query and host_is_name and (platform_hits or ucp))
    if hosted:
        categories.add("hosted_on_legit_platform")
    never = None
    if etype not in SUPPRESSIBLE_TYPES:
        never = "not an infrastructure value (a URL is never suppressed, FC3)"
    elif ucp:
        never = f"user-content or dynamic-DNS parent {ucp} (FC5)"
    suppressed = bool(suppress_hits) and never is None
    if suppress_hits and never:
        notes.append(f"suppress list matched but not applied: {never}")
    downweight = None
    if top_scoped and etype is T.DOMAIN and host and rd_full == host and not ucp:
        downweight = "registrable_domain"
    if top_scoped and not downweight:
        notes.append("popular site: context only, no verdict down-weight (FC4)")
    if "sinkhole" in categories:
        notes.append("sinkhole: hits = infected clients, not attacker infrastructure")
    if "test_file" in categories:
        notes.append("antivirus test file: shown, never suppressed (FC7)")
    reasons = [match_display(m) for m in sorted(suppress_hits, key=lambda m: m.get("list") or "")] if suppressed else []
    outcome = "suppress" if suppressed else ("tag" if categories else "none")
    return {
        "outcome": outcome, "suppressed": suppressed, "categories": sorted(categories),
        "suppress_matches": suppress_hits if suppressed else [], "top_matches": top_scoped, "tag_matches": tag_hits,
        "reasons": reasons, "popular_site": popular, "downweight": downweight, "hosted_on_legit_platform": hosted,
        "user_content_parent": ucp, "never_suppress_reason": never if suppress_hits else None,
        "is_sinkhole": "sinkhole" in categories, "is_parked": "parked" in categories,
        "third_party_hosted": bool(categories & THIRD_PARTY_CATEGORIES),
        "active_probe_excluded": bool(categories & ACTIVE_EXCLUDED_CATEGORIES), "notes": notes,
    }


def suppressed_summary_line(classifications: Iterable[Mapping[str, Any]]) -> str | None:
    """FC8 terminal line: 'N indicators suppressed as known-benign (lists...)', None when N == 0."""
    sup = [c for c in classifications or () if isinstance(c, Mapping) and c.get("suppressed")]
    if not sup:
        return None
    names = sorted({str(m.get("list")) for c in sup for m in c.get("suppress_matches") or () if m.get("list")})
    return f"{len(sup)} indicator{'' if len(sup) == 1 else 's'} suppressed as known-benign ({', '.join(names)})"


# ======================================================================================
# Loading (lazy, per process; bundled build + downloaded list copies)
# ======================================================================================

_LOCK = threading.Lock()
_STATE: dict[str, Any] = {"key": None, "index": None, "checked": 0.0, "home": ""}


def _dataset_name(slug: str) -> str:
    return f"{DATASET_PREFIX}{slug}"


def bundle_path() -> Path:
    return Path(str(resources.files("v3lum.data").joinpath(BUNDLE_FILE)))


def manifest_path() -> Path:
    return Path(str(resources.files("v3lum.data").joinpath(MANIFEST_FILE)))


def load_manifest() -> dict[str, Any]:
    """The small list manifest (import time: dataset registration). {} when missing or invalid."""
    try:
        doc = json.loads(manifest_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(doc, dict) or doc.get("schema") != MANIFEST_SCHEMA or not isinstance(doc.get("lists"), dict):
        return {}
    return doc


def _bundle_stamp() -> tuple[str, int, int]:
    path = bundle_path()
    try:
        st = path.stat()
    except OSError as exc:
        raise DatasetError(f"bundled {BUNDLE_FILE} missing ({exc})", name=BUNDLE_FILE) from exc
    return str(path), st.st_size, st.st_mtime_ns


def load_bundle() -> tuple[dict[str, Any], str]:
    """(bundle, sha256) of the bundled build, read now (only to build the index). Raises DatasetError."""
    path = bundle_path()
    try:
        blob = path.read_bytes()
        data = json.loads(gzip.decompress(blob).decode("utf-8"))
    except (OSError, EOFError, ValueError) as exc:
        raise DatasetError(f"bundled {BUNDLE_FILE} unusable ({type(exc).__name__}: {exc})", name=BUNDLE_FILE) from exc
    if not isinstance(data, dict) or not isinstance(data.get("lists"), dict) or (data.get("_meta") or {}).get("schema") != BUNDLE_SCHEMA:
        raise DatasetError(f"bundled {BUNDLE_FILE} is not a {BUNDLE_SCHEMA} document", name=BUNDLE_FILE)
    return data, hashlib.sha256(blob).hexdigest()


def _downloaded_stamps(slugs: Iterable[str]) -> tuple[tuple[str, int, int], ...]:
    directory = paths.datasets_dir()
    out = []
    for slug in sorted(slugs):
        try:
            st = (directory / _dataset_name(slug)).stat()
        except OSError:
            continue
        out.append((slug, st.st_size, st.st_mtime_ns))
    return tuple(out)


def _parse_download(path: Path, slug: str) -> dict[str, Any]:
    try:
        return parse_warninglist(path.read_bytes(), slug)
    except OSError as exc:
        return {"marker": f"error: unreadable local copy ({exc})"}


def get_index(*, force: bool = False) -> WarninglistIndex:
    """The process-wide index, built lazily on first use and rebuilt when the bundle or a downloaded list
    copy changes (checked at most every :data:`RECHECK_SECONDS`). Local copies only: never a download.
    Raises DatasetError when the bundled build is missing or unusable."""
    now = time.monotonic()
    home = str(paths.datasets_dir())
    with _LOCK:
        cached = _STATE["index"]
        if cached is not None and not force and _STATE["home"] == home and now - _STATE["checked"] < RECHECK_SECONDS:
            return cached
        manifest_lists = (load_manifest().get("lists") or {}) if cached is None else {s: {} for s in cached.lists}
        stamps = _downloaded_stamps(manifest_lists)
        key = (_bundle_stamp(), home if stamps else "", stamps)  # without local copies every home shares the bundled index
        if cached is not None and not force and _STATE["key"] == key:
            _STATE.update(checked=now, home=home)
            return cached
        bundle, sha = load_bundle()
        lists = bundle["lists"]
        directory = paths.datasets_dir()
        overrides: dict[str, tuple[dict[str, Any], str]] = {}
        stamps = _downloaded_stamps(lists)
        for slug, _size, mtime_ns in stamps:
            parsed = _parse_download(directory / _dataset_name(slug), slug)
            overrides[slug] = (parsed, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime_ns / 1e9)))
        index = build_index(lists, bundle.get("_meta") or {}, overrides=overrides)
        index.bundle_sha256 = sha
        del bundle, lists  # the parsed bundle is not kept: the index holds what lookups need
        _STATE.update(key=(_bundle_stamp(), home if stamps else "", stamps), index=index, checked=now, home=home)
        return index


def reset_cache() -> None:
    """Drop the process-wide index (tests)."""
    with _LOCK:
        _STATE.update(key=None, index=None, checked=0.0, home="")


def local_classification(entity: Entity) -> dict[str, Any] | None:
    """Matches and FC3-FC8 classification of an entity from local data only (no network): the hook for
    the core (AR06 noise, P378 third_party_hosted, A7 ACTIVE exclusion). None when the bundle is unusable."""
    try:
        index = get_index()
    except DatasetError:
        return None
    matches = index.lookup(entity.type, entity.value)
    out = classify(entity.type, entity.value, matches, extra_parents=index.ucp_hosts)
    out["matches"] = matches
    return out


def active_probe_excluded(entity: Entity) -> bool:
    """FC8 / A7: True when the address or name is on a cloud or CDN warninglist (local data only)."""
    cls = local_classification(entity)
    return bool(cls and cls["active_probe_excluded"])


# ======================================================================================
# Dataset registrations (FC1 weekly refresh; never fetched during a scan)
# ======================================================================================


def _validator(slug: str, kind: str):
    def validate(path: Path) -> bool:
        parsed = parse_warninglist(Path(path).read_bytes(), slug)
        if parsed.get("marker"):
            raise ValueError(f"{slug}: {parsed['marker']}")
        if parsed.get("excluded_reason"):
            raise ValueError(f"{slug}: {parsed['excluded_reason']}")
        if parsed.get("kind") != kind:
            raise ValueError(f"{slug}: list kind changed upstream ({parsed.get('kind')!r} instead of {kind!r}): review the policy")
        if not parsed.get("entries"):
            raise ValueError(f"{slug}: empty list")
        return True

    validate.__name__ = f"validate_warninglist_{re.sub(r'[^a-z0-9_]', '_', slug.lower())}"
    return validate


def register_datasets(manifest: Mapping[str, Any] | None = None) -> list[str]:
    """Register ``warninglists.<list>`` for every bundled list (import time, from the small manifest)."""
    doc = manifest if manifest is not None else load_manifest()
    names = []
    for slug, lst in sorted((doc.get("lists") or {}).items()):
        if not isinstance(slug, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", slug) or not isinstance(lst, dict):
            continue
        name = _dataset_name(slug)
        x4b = slug in X4BNET_LISTS
        if name not in DATASETS:
            register_dataset(
                name,
                RAW_URL.format(slug=slug),
                ttl=REFRESH_TTL,
                description=f"MISP warninglist {slug}: {lst.get('name')}",
                licence=X4BNET_LICENCE if x4b else LICENCE,
                terms_class="open",
                attribution=X4BNET_ATTRIBUTION if x4b else ATTRIBUTION,
                provider="github",
                source=SOURCE,
                validate=_validator(slug, str(lst.get("kind"))),
                min_bytes=40,
                expect="json",
                max_bytes=DATASET_MAX_BYTES,
                large=True,
            )
        names.append(name)
    return names


DATASET_NAMES = register_datasets()


# ======================================================================================
# The module
# ======================================================================================

#: finding title, tags and description per category (titles are stable: finding ids depend on them).
CATEGORY_FINDINGS: dict[str, tuple[str, tuple[str, ...], str]] = {
    "cloud": ("Cloud provider address range (MISP warninglist)", ("infrastructure", "cloud"), "Address in a published cloud provider range: shared or rented infrastructure; reputation of the address still applies."),
    "cdn": ("CDN address range (MISP warninglist)", ("infrastructure", "cdn", "noise"), "Shared CDN edge: many unrelated sites sit behind the same addresses."),
    "datacenter": ("Datacenter or hosting range (MISP warninglist)", ("infrastructure", "datacenter"), "Hosting/datacenter network (X4BNet list, MIT licence)."),
    "vpn": ("VPN service range (MISP warninglist)", ("proxy", "vpn", "context_only"), "Commercial VPN or privacy-relay egress: many users, no attribution possible."),
    "tor_exit": ("Tor exit node (MISP warninglist)", ("tor", "anonymizer", "context_only"), "Tor exit relay: traffic from many users, no attribution possible."),
    "benign_scanner": ("Known benign internet scanner (MISP warninglist)", ("benign_scanner", "context_only"), "Research or commercial internet-scanning range: probes from here are expected background noise."),
    "sinkhole": ("Known sinkhole (MISP warninglist)", ("sinkhole", "context_only"), "Sinkhole operated by researchers or law enforcement: hits = infected clients, not attacker infrastructure."),
    "parked": ("Domain-parking infrastructure (MISP warninglist)", ("parked",), "Parking or for-sale lander infrastructure."),
    "dynamic_dns": ("Dynamic DNS service (MISP warninglist)", ("dynamic_dns",), "Dynamic DNS provider: anyone can create names under it; judged on the full name, never suppressed (FC5)."),
    "url_shortener": ("URL shortener (MISP warninglist)", ("url_shortener",), "URL shortener: the destination decides, investigate the expanded URL."),
    "disposable_mail": ("Disposable e-mail domain (MISP warninglist)", ("disposable_mail",), "Throw-away mailbox provider."),
    "user_content_hosting": ("User-content hosting platform (MISP warninglist)", ("user_content_hosting",), "Platform where anyone can publish content: never suppressed, URLs on it are investigated (FC5)."),
    "test_file": ("Antivirus test file (EICAR)", ("test_file", "context_only"), "Antivirus test file: detections are expected and not an incident; shown, never suppressed (FC7)."),
    "known_fp": ("Known false-positive indicator (MISP warninglist)", ("false_positive",), "Listed by MISP as a frequent false-positive indicator."),
    "mail_infrastructure": ("Mail service infrastructure (MISP warninglist)", ("infrastructure",), "Mail provider sending/receiving infrastructure."),
    "malware_analysis_service": ("Malware analysis service (MISP warninglist)", ("infrastructure",), "Sandbox or malware-analysis service endpoint."),
    "attack_simulation": ("Attack-simulation service (MISP warninglist)", ("infrastructure",), "Phishing/attack simulation service used for awareness campaigns."),
    "vendor_service": ("Vendor service endpoint (MISP warninglist)", ("infrastructure",), "Vendor infrastructure (CRL/OCSP, captive portal, what-is-my-IP, block page...)."),
    "bank_website": ("Bank website (MISP warninglist)", ("warninglist",), "Listed as a legitimate bank website."),
    "listed": ("Listed on a MISP context warninglist", ("warninglist",), "On a MISP warninglist used as context only."),
    "popular_site": ("Popular site (top-site list)", ("popular_site",), "Tranco/Umbrella/Radar top-10k site: context, down-weights the reputation of this registrable domain only (FC4)."),
    "known_vendor_domain": ("Known vendor domain (MISP warninglist)", ("known_vendor_domain",), "Domain of a major vendor inventory: context only (FC4)."),
    "hosted_on_legit_platform": ("URL on a listed legitimate platform", ("hosted_on_legit_platform",), "The host is on a warninglist but the URL has a path or query: it is investigated at URL level, never suppressed (FC5)."),
}
SUPPRESS_TITLE = "Likely benign: on a MISP warninglist"


@register
class Warninglists(Module):
    name = "warninglists"
    title = "MISP warninglists (known-benign and context lists)"
    description = (
        "Offline match of IPs, CIDRs, domains, URLs and hashes against a compact bundle of the MISP warninglists: "
        "known-benign infrastructure (likely benign, suppressed) and context tags (cloud, CDN, scanner, Tor, VPN, "
        "sinkhole, dynamic DNS, top sites...)."
    )
    category = "threat_intel_ioc"
    accepts = {T.IPV4, T.IPV6, T.CIDR, T.DOMAIN, T.URL, T.MD5, T.SHA1, T.SHA256}
    produces: frozenset[T] = frozenset()
    tags = {"offline", "free"}
    reference = REPO_URL
    notice = (
        "MISP warninglists (CC0-1.0); the X4BNet-derived vpn/datacenter lists keep their MIT notice. Offline match: the "
        "value never leaves the machine. A match never deletes or overrides a finding: suppression only lowers confidence."
    )
    # ---- contract v2 declarations ---------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # offline: the dataset manager alone downloads the lists (weekly), never per value
    hosts = ()
    sources = (SOURCE,)
    expected_latency = 0.2  # warm lookups take microseconds; the first use builds the index (~1-2 s)
    default_enabled = True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        try:
            index = get_index()
        except DatasetError as exc:
            return res.mark(Status.UNAVAILABLE, f"warninglists bundle unusable ({exc}): could not verify", reason_code="dataset")
        try:
            ctx.data.bundled_path(BUNDLE_FILE)  # citation of the bundled build (fetched_at 'bundled')
        except (OSError, ValueError):  # pragma: no cover - the bundle was just read
            pass
        matches = index.lookup(entity.type, entity.value)
        if not matches:
            return res.mark(Status.EMPTY)
        cls = classify(entity.type, entity.value, matches, extra_parents=index.ucp_hosts)
        self._cite_downloads(ctx, index, matches)
        self._record(res, entity, index, matches, cls)
        return res

    @staticmethod
    def _cite_downloads(ctx: Any, index: WarninglistIndex, matches: list[dict[str, Any]]) -> None:
        """Cite the downloaded list copies that answered (local copies only: they are present)."""
        for m in matches:
            if m.get("origin") != "downloaded":
                continue
            try:
                ctx.data.fetch(_dataset_name(m["list"]), ttl=10**12)
            except (DatasetError, OSError, ValueError):
                continue

    @staticmethod
    def _record(res: ModuleResult, entity: Entity, index: WarninglistIndex, matches: list[dict[str, Any]], cls: dict[str, Any]) -> None:
        shown = [
            {k: m.get(k) for k in ("list", "name", "version", "version_date", "outcome", "category", "match", "entry", "licence", "origin")}
            | {"url": LIST_PAGE.format(slug=m["list"])}
            for m in matches
        ]
        res.attr("warninglist_matches", shown)
        res.attr("warninglist_outcome", cls["outcome"])
        res.attr("warninglists_build", index.build_info())
        if cls["suppressed"]:
            res.attr("allowlisted", [f"MISP warninglist: {r[len('likely benign because '):]}" for r in cls["reasons"]])
        if cls["is_sinkhole"]:
            res.attr("is_sinkhole", True)
        if cls["is_parked"]:
            res.attr("is_parked", True)
        if cls["third_party_hosted"]:
            res.attr("third_party_hosted", True)
        cats = set(cls["categories"])
        ip_like = entity.type in (T.IPV4, T.IPV6, T.CIDR)
        if ip_like and "cdn" in cats:
            res.attr("is_cdn", True)
        if ip_like and ("cloud" in cats or "cdn" in cats):
            res.attr("is_cloud", True)
        if "tor_exit" in cats:
            res.attr("is_tor_exit", True)
        if "vpn" in cats:
            res.attr("is_vpn", True)
        if cls["popular_site"]:
            res.attr("popular_site", True)
        if cls["downweight"]:
            res.attr("reputation_downweight", cls["downweight"])
        if cls["user_content_parent"]:
            res.attr("user_content_parent", cls["user_content_parent"])
        if cls["suppressed"]:
            text = "; ".join(cls["reasons"])
            res.finding(
                SUPPRESS_TITLE,
                "info",
                f"{text}. Malicious verdicts from other sources on this value are lowered to POSSIBLE and shown next to "
                "this reason, never deleted; an analyst override wins.",
                confidence="probable",
                data={"outcome": "suppress", "lists": [m["list"] for m in cls["suppress_matches"]], "reasons": cls["reasons"]},
                tags=["warninglist", "known_good", "context_only"],
                source=SOURCE,
            )
        by_cat: dict[str, list[dict[str, Any]]] = {}
        for m in cls["tag_matches"] + cls["top_matches"]:
            by_cat.setdefault(str(m.get("category")), []).append(m)
        for cat in sorted(cats):
            title, tags, text = CATEGORY_FINDINGS.get(cat, CATEGORY_FINDINGS["listed"])
            hits = by_cat.get(cat, [])
            names = ", ".join(f"{m.get('name') or m['list']} ({m.get('version_date') or m.get('version') or 'undated'})" for m in hits)
            extra = [n for n in cls["notes"] if (cat == "sinkhole" and n.startswith("sinkhole")) or (cat == "test_file" and n.startswith("antivirus"))]
            desc = text + (f" Lists: {names}." if names else "") + (f" {extra[0]}." if extra and extra[0] not in text else "")
            if cat == "user_content_hosting" and cls["user_content_parent"]:
                desc += f" Parent: {cls['user_content_parent']}."
            res.finding(
                title,
                "info",
                desc,
                confidence="probable",
                data={"category": cat, "lists": [m["list"] for m in hits], "matches": [{k: m.get(k) for k in ("list", "match", "entry")} for m in hits]},
                tags=list(tags),
                source=SOURCE,
                key=cat,
            )
        if cls["notes"]:
            res.attr("warninglist_notes", cls["notes"])
        partial = [m for m in matches if m.get("match") == "cidr_partial_overlap"]
        if partial and cls["outcome"] == "none":
            res.finding(
                "Network partially overlaps MISP warninglists",
                "info",
                f"{entity.value} is not inside a listed range but overlaps {len(partial)} list(s): "
                f"{', '.join(str(m['list']) for m in partial[:PARTIAL_SHOWN])}{' ...' if len(partial) > PARTIAL_SHOWN else ''}. "
                "Nothing is applied to the whole network: look the addresses up one by one.",
                confidence="possible",
                data={"lists": [m["list"] for m in partial[:50]], "overlaps": len(partial)},
                tags=["warninglist"],
                source=SOURCE,
            )


# ======================================================================================
# Dev script: python -m v3lum.modules.threat_intel_ioc.warninglists build --source <clone>
# ======================================================================================


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - developer tool, exercised by hand
    parser = argparse.ArgumentParser(prog="python -m v3lum.modules.threat_intel_ioc.warninglists", description="Build the compact MISP warninglists bundle (P169 FC1).")
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="build the bundle and the AR06 noise fragments from a local clone")
    b.add_argument("--source", required=True, type=Path, help="local clone of github.com/MISP/misp-warninglists at --commit")
    b.add_argument("--commit", required=True, help="the cloned commit (40 hex)")
    b.add_argument("--commit-date", default="", help="commit date (YYYY-MM-DD)")
    b.add_argument("--built", required=True, help="build date (YYYY-MM-DD), recorded in the bundle")
    b.add_argument("--out", type=Path, default=Path("v3lum/data") / BUNDLE_FILE)
    b.add_argument("--noise-dir", type=Path, default=Path("v3lum/data/noise"))
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        parser.error("--commit must be a 40-hex commit id")
    bundle = build_from_clone(args.source, commit=args.commit, built=args.built, commit_date=args.commit_date)
    report = bundle_size_report(bundle)
    if not report["within_budget"]:
        sys.stderr.write(f"bundle is {report['gzip_bytes']} bytes gzip: over the {BUNDLE_GZIP_BUDGET} budget (FC1)\n")
        return 2
    blob = bundle_bytes(bundle)
    _write(args.out, blob)
    manifest = bundle_manifest(bundle, hashlib.sha256(blob).hexdigest())
    _write(args.out.with_name(Path(MANIFEST_FILE).name), (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode("utf-8"))
    for stem, doc in sorted(noise_fragments(bundle, checked_at=args.built).items()):
        _write(args.noise_dir / f"{stem}.json", (json.dumps(doc, indent=1, ensure_ascii=False) + "\n").encode("utf-8"))
    sys.stdout.write(json.dumps({"lists": bundle["_meta"]["list_count"], "entries": bundle["_meta"]["entry_count"], **report}, indent=1) + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
