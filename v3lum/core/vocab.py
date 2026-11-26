"""Shared vocabulary: attribute keys, finding tags and relation names (contract v2, section 14).

Modules MUST use these names so correlation rules and reports can cross-reference results
coming from different sources. The core names live in this file; packs and module batches add
their own names through *fragments* (``v3lum/data/vocab/<pack>.json``) instead of editing it::

    {
      "schema": "v3lum.vocab/1",
      "attributes": {"first_seen_breach": "ISO date of the oldest breach that lists the entity"},
      "tags": {"lookalike_brand": "domain imitates an org-profile brand"},
      "relations": {"same_tenant": "domain -> domain in the same SaaS tenant"},
      "timeline": {"first_seen_breach": "first seen in a breach"}
    }

Names match ``^[a-z][a-z0-9_]{0,63}$`` and need a non-empty description. Core names come first,
then fragments in file-name order; re-declaring a name is allowed (the first description wins)
and is listed by :func:`redeclarations` for review. Malformed files or entries never raise: they
are reported by :func:`errors` (the registry contract test requires none).

Strict contract mode (``V3LUM_STRICT=1``, always on in tests) turns unknown names into
:class:`UnknownVocab` errors; outside strict mode unknown names are kept and logged once.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger("v3lum.contract")

#: Schema id of vocabulary fragment files.
FRAGMENT_SCHEMA = "v3lum.vocab/1"
#: Directory scanned for fragments (tests monkeypatch it, then call :func:`reload`).
FRAGMENT_DIR: Path = Path(__file__).resolve().parent.parent / "data" / "vocab"
#: Allowed vocabulary names.
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
#: Vocabulary kinds accepted by :func:`check`.
KINDS = ("attribute", "tag", "relation")
_SECTIONS = {"attributes": "attribute", "tags": "tag", "relations": "relation"}
_META_KEYS = frozenset({"schema", "pack", "title", "description", "owner", "notes", "$comment", "timeline"})


class ContractViolation(ValueError):
    """A module broke the module-author contract (raised only in strict contract mode)."""


class UnknownVocab(ContractViolation):
    """An attribute, tag or relation name outside the merged vocabulary (strict mode only)."""

    def __init__(self, kind: str, name: str, message: str = "") -> None:
        self.kind = kind
        self.name = name
        super().__init__(
            message
            or f"unknown {kind} {name!r}: use a name from v3lum.core.vocab or declare it in a "
            f"v3lum/data/vocab/<pack>.json fragment (schema {FRAGMENT_SCHEMA})"
        )


# ----------------------------------------------------------------------------------------
# Attributes: facts about the subject entity, recorded with ModuleResult.attr(key, value).
# Values should be JSON-serializable (str/int/float/bool/list/dict). Dates are ISO-8601.
# ----------------------------------------------------------------------------------------
ATTRIBUTES: dict[str, str] = {
    # generic
    "country": "ISO-3166 alpha-2 country code (e.g. 'BR')",
    "city": "city name",
    "region": "state / region",
    "org": "organization / owner name as reported by the source",
    "first_seen": "ISO date the entity was first observed by the source",
    "last_seen": "ISO date the entity was last observed by the source",
    "created": "creation/registration date (ISO)",
    "updated": "last update date (ISO)",
    "expires": "expiry date (ISO)",
    "malicious": "bool: a reputable source flags it as malicious",
    "suspicious": "bool: flagged as suspicious / low reputation",
    "reputation": "dict {source: verdict/score}",
    "tags": "list of source-provided tags/labels",
    "names": "list of names/aliases associated with the entity",
    "presence": "tri-state existence check {state: found|absent|unknown, marker, url, checked_at, source}; absent only on positive evidence",
    "sightings": "cross-case sightings of the entity in the V3LUM case database (TLP-filtered summary)",
    "intercepted_by": "TLS interception detected on the egress path (issuer/product of the re-signing proxy)",
    "watch_hits": "list of {name, registrable_domain, serial, cert_sha256, issuer, not_before, source} new names reported by watch sources",
    # network
    "asn": "autonomous system number, e.g. 'AS15169'",
    "as_org": "AS owner name",
    "isp": "ISP / hosting provider",
    "prefix": "announced prefix (CIDR)",
    "rdns": "reverse DNS hostname(s)",
    "open_ports": "list[int] of open ports",
    "services": "list of service/banner descriptions",
    "cpes": "list of CPE strings",
    "vulns": "list of CVE ids affecting the host/software",
    "hostnames": "list of hostnames seen on the IP",
    "is_tor_exit": "bool",
    "is_proxy": "bool (open proxy / anonymizer)",
    "is_vpn": "bool",
    "is_hosting": "bool (datacenter / hosting range)",
    "is_cdn": "bool (CDN / shared edge)",
    "is_sinkhole": "bool: the address/name is a known sinkhole (research or law-enforcement takeover)",
    "is_parked": "bool: the domain is parked (parking provider page or nameservers)",
    "abuse_contact": "abuse email for the network",
    "blocklists": "list of blocklist names that list the entity",
    # domain / DNS / web
    "registrar": "domain registrar",
    "registrant": "registrant name/organization (if public)",
    "registrant_email": "registrant contact email (if public)",
    "registrant_doc": "registrant document id when public (e.g. masked CPF/CNPJ from registro.br)",
    "nameservers": "list of NS hostnames",
    "mx": "list of MX hostnames",
    "a_records": "list of IPv4 addresses",
    "aaaa_records": "list of IPv6 addresses",
    "txt": "list of TXT records",
    "spf": "SPF record text",
    "dmarc": "DMARC record text",
    "dmarc_policy": "none|quarantine|reject",
    "dnssec": "bool: the resolver's AD flag (DNSSEC validated by the resolver, never proof; P029 cond 8)",
    "domain_age_days": "int: days since registration",
    "subdomains": "list of discovered subdomains",
    "http_status": "HTTP status of the homepage",
    "title": "HTML <title>",
    "server": "Server header / software",
    "technologies": "list of detected technologies",
    "waf": "WAF/CDN name if detected",
    "favicon_mmh3": "Shodan-style favicon hash",
    "cert_issuer": "TLS certificate issuer",
    "cert_subject": "TLS certificate subject CN",
    "cert_sans": "list of SANs in the TLS certificate",
    "cert_not_after": "certificate expiry (ISO)",
    "cert_sha256": "certificate SHA-256 fingerprint",
    "analytics_ids": "list of tracking ids (UA-/G-/GTM-/pub-) found on the site",
    "security_headers_missing": "list of missing recommended HTTP security headers",
    "archive_first": "first Wayback snapshot date",
    "archive_count": "number of archived snapshots",
    # email / identity
    "disposable": "bool: disposable/temporary email provider",
    "free_provider": "bool: free webmail provider (gmail, outlook...)",
    "mx_valid": "bool: the email domain accepts mail (MX/A present)",
    "generic_address": "kind of generic address (role | test | example_domain): flagged, capped at POSSIBLE, never scored",
    "breach_count": "int: number of known breaches containing the entity",
    "breaches": "list of breach names",
    "breach_data_classes": "list of exposed data classes (never the data itself)",
    "infostealer": "bool: entity seen in infostealer logs",
    "gravatar": "bool: has a Gravatar profile/avatar",
    "profiles": "list of {platform, url} public profiles",
    "display_name": "public display name found on a profile",
    "avatar_url": "public avatar URL",
    "bio": "public bio/description",
    "followers": "follower count",
    "location": "self-declared location",
    # phone
    "carrier": "carrier/operator",
    "line_type": "mobile|fixed|voip|toll_free|...",
    "valid": "bool: passes validation for its type",
    "timezone": "list of time zones",
    # company / Brazil
    "legal_name": "registered legal name (razao social)",
    "trade_name": "trade name (nome fantasia)",
    "status": "registration status (e.g. ATIVA/BAIXADA)",
    "cnae": "main economic activity code + description",
    "partners": "list of partner/officer names (QSA)",
    "address": "registered address string",
    "capital": "share capital",
    "opened": "company opening date (ISO)",
    "sanctioned": "bool: appears on a sanctions list",
    "lei": "Legal Entity Identifier",
    # malware / vuln / crypto
    "malware_family": "malware family name(s)",
    "file_type": "file type / magic",
    "file_size": "size in bytes",
    "known_good": "bool: hash in a known-software set (e.g. NSRL)",
    "cvss": "CVSS base score (float)",
    "cvss_vector": "CVSS vector string",
    "epss": "EPSS probability (0-1)",
    "kev": "bool: in CISA Known Exploited Vulnerabilities",
    "exploit_available": "bool: public exploit/PoC exists",
    "balance": "crypto balance (string with unit)",
    "tx_count": "number of transactions",
    "total_received": "total received (string with unit)",
    "ransomware_group": "ransomware group name",
}

# ----------------------------------------------------------------------------------------
# Finding tags: semantic labels used by correlation rules and risk scoring.
# (The engine also sets some of them as entity-level tags on graph nodes: own_asset, ...)
# ----------------------------------------------------------------------------------------
TAGS: dict[str, str] = {
    "malicious": "confirmed malicious by a reputable source",
    "suspicious": "suspicious / low reputation",
    "phishing": "phishing infrastructure or lure",
    "malware": "malware sample or distribution",
    "c2": "command-and-control infrastructure",
    "botnet": "botnet-related",
    "spam": "spam source",
    "scanner": "internet scanner / mass exploitation noise",
    "tor": "Tor network related",
    "proxy": "proxy / VPN / anonymizer",
    "breach": "appears in a data breach",
    "infostealer": "appears in infostealer logs",
    "credential_exposure": "credentials or secrets exposed",
    "vulnerable": "affected by known vulnerabilities",
    "kev": "known exploited vulnerability",
    "exploit_available": "public exploit available",
    "exposure": "exposed service / data / admin interface",
    "misconfiguration": "security misconfiguration",
    "weak_email_security": "SPF/DMARC/DKIM weakness enabling spoofing",
    "typosquat": "lookalike / typosquatting domain",
    "newly_registered": "recently registered domain",
    "takeover": "possible subdomain takeover",
    "ransomware": "ransomware related (victim listing, group)",
    "darkweb": "found on dark web sources",
    "sanctions": "on a sanctions list",
    "pep": "politically exposed person",
    "fraud": "fraud indicator",
    "identity": "identity link (same person/org)",
    "account": "public account/profile found",
    "infrastructure": "infrastructure relationship",
    "known_good": "known benign / allow-listed",
    "noise": "common benign infrastructure (low pivot value)",
    "privacy": "personal data: handle with care (LGPD/GDPR)",
    "info": "informational",
    # contract v2 core tags
    "own_asset": "entity belongs to the organisation (org profile match)",
    "third_party": "entity belongs to a third party (supplier, hosting platform, unrelated org)",
    "hosted_on_legit_platform": "URL hosted on a big legitimate platform (Google Forms/Sites, OneDrive...): investigated at URL level",
    "sinkhole": "known sinkhole infrastructure (not attacker controlled)",
    "parked": "parked domain (parking provider page or nameservers)",
    "benign_scanner": "known benign internet scanner (research / search engine crawlers)",
    "recipient_token": "value carries a per-recipient tracking token (privacy: do not share as an IOC)",
    "version_inferred": "inferred from a software version banner (distro backports not considered): confirm on the host",
    "high_collision": "value collides often (short handle, dictionary word, common name): weak identity signal",
    "weak_signal": "weak signal: context for the analyst, not evidence on its own",
    "verified_fi": "verified financial institution (official authorised-institution list)",
    "unknown_operator": "source or link operated by an unknown-tier provider",
    "context_only": "shown as context, never scored as exposure (third-party breach context, generic/role/test addresses, anonymity-network membership)",
}

# ----------------------------------------------------------------------------------------
# Relations used in Pivot(relation=...). Read as: <subject> <relation> <pivot>.
# ----------------------------------------------------------------------------------------
RELATIONS: dict[str, str] = {
    "resolves_to": "domain -> IP (A/AAAA)",
    "reverse_dns": "IP -> hostname (PTR)",
    "hosted_domain": "IP -> domain observed on it (passive DNS/certs)",
    "cname_to": "domain -> canonical name",
    "mx_host": "domain -> mail exchanger",
    "nameserver": "domain -> NS",
    "subdomain": "domain -> subdomain",
    "parent_domain": "subdomain -> registrable domain",
    "email_domain": "email -> its domain",
    "contact_email": "domain/org -> contact email (WHOIS/security.txt/site)",
    "registrant": "domain -> registrant org/person",
    "belongs_to_asn": "IP -> ASN",
    "in_network": "IP -> CIDR",
    "announces": "ASN -> prefix",
    "cert_san": "domain/IP -> name found in a certificate SAN",
    "redirects_to": "URL -> URL",
    "url_host": "URL -> domain/IP",
    "links_to": "page -> external URL/domain",
    "archived_url": "domain -> historical URL",
    "same_analytics": "site -> tracking id / sites sharing it",
    "favicon": "site -> favicon hash",
    "has_account": "username/email -> profile URL or platform handle",
    "same_person": "identity link between person/username/email",
    "uses_username": "email/person -> username",
    "uses_email": "username/person -> email",
    "commit_email": "username -> email seen in public commits",
    "phone_of": "org/person -> phone",
    "partner": "company -> partner/officer (person/company)",
    "company_of": "person/domain -> company",
    "located_at": "entity -> CEP/coordinates/address",
    "drops": "malware hash -> URL/domain/IP contacted or dropped",
    "communicates_with": "malware -> C2",
    "family": "hash -> malware family",
    "attributed_to": "malware/campaign -> threat actor",
    "uses_technique": "actor/malware -> ATT&CK technique",
    "targets": "actor -> sector/country/org",
    "exploits": "actor/malware -> CVE",
    "has_vuln": "host/IP/domain/software -> CVE that affects it",
    "affects": "CVE -> product/CPE",
    "transacted_with": "wallet -> wallet",
    "victim_of": "org/domain -> ransomware group",
    "mentions": "document/text -> entity",
    "extracted_from": "file/text -> IOC",
    "lookalike": "brand domain -> typosquat candidate",
    "related": "generic relationship (use only if nothing else fits)",
    "similar_to": "entity -> similar entity (fuzzy hash, favicon/visual similarity, lookalike content)",
    "same_m365_tenant": "domain -> domain registered in the same Microsoft 365 tenant",
}

# ----------------------------------------------------------------------------------------
# Timeline: dated attributes put on the case timeline (attribute -> timeline label).
# Fragments add more through their optional "timeline" section.
# ----------------------------------------------------------------------------------------
CORE_TIMELINE: dict[str, str] = {
    "created": "registered/created",
    "updated": "updated",
    "expires": "expires",
    "first_seen": "first seen",
    "last_seen": "last seen",
    "opened": "company opened",
    "archive_first": "first web archive snapshot",
    "cert_not_after": "certificate expires",
}

_CORE = {"attribute": ATTRIBUTES, "tag": TAGS, "relation": RELATIONS}
#: The shipped core names (a fragment re-declaring one of them is a re-declaration; names a test adds
#: to the live tables with tests.fakes.allow_vocab never hide a fragment name).
_CORE_NAMES = {kind: frozenset(table) for kind, table in _CORE.items()}


class _State:
    """The fragment side of the vocabulary. ``merged`` holds only the names fragments add: the core
    tables are always read live (so tests.fakes.allow_vocab additions and removals take effect at
    once, whenever the fragments were loaded)."""

    def __init__(self) -> None:
        self.loaded = False
        self.merged: dict[str, dict[str, str]] = {"attribute": {}, "tag": {}, "relation": {}}
        self.timeline: dict[str, str] = {}
        self.errors: list[str] = []
        self.redeclarations: list[tuple[str, str, str]] = []
        self.files: list[str] = []


_STATE = _State()
_LOCK = threading.RLock()
_WARNED: set[tuple[str, str, str]] = set()
_WARN_LOCK = threading.Lock()


def _load() -> _State:
    st = _State()
    pending_timeline: list[tuple[str, str, str]] = []
    directory = Path(FRAGMENT_DIR)
    files = sorted(directory.glob("*.json")) if directory.is_dir() else []
    for path in files:
        fname = path.name
        st.files.append(fname)
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            st.errors.append(f"vocab fragment {fname}: unreadable or invalid JSON ({type(exc).__name__}: {exc})")
            continue
        if not isinstance(doc, dict):
            st.errors.append(f"vocab fragment {fname}: top level must be an object")
            continue
        if doc.get("schema") != FRAGMENT_SCHEMA:
            st.errors.append(f"vocab fragment {fname}: schema must be {FRAGMENT_SCHEMA!r} (got {doc.get('schema')!r})")
            continue
        for key in doc:
            if key not in _SECTIONS and key not in _META_KEYS:
                st.errors.append(f"vocab fragment {fname}: unknown top-level key {key!r}")
        for section, kind in _SECTIONS.items():
            entries = doc.get(section, {})
            if entries in (None, {}):
                continue
            if not isinstance(entries, dict):
                st.errors.append(f"vocab fragment {fname}: '{section}' must be an object of name -> description")
                continue
            for name, desc in entries.items():
                problem = _entry_problem(name, desc)
                if problem:
                    st.errors.append(f"vocab fragment {fname}: {kind} {name!r}: {problem}")
                    continue
                if name in _CORE_NAMES[kind] or name in st.merged[kind]:
                    st.redeclarations.append((kind, name, fname))
                    continue
                st.merged[kind][name] = desc.strip()
        timeline = doc.get("timeline", {})
        if timeline not in (None, {}):
            if not isinstance(timeline, dict):
                st.errors.append(f"vocab fragment {fname}: 'timeline' must be an object of attribute -> label")
            else:
                for name, label in timeline.items():
                    if not isinstance(name, str) or not isinstance(label, str) or not label.strip():
                        st.errors.append(f"vocab fragment {fname}: timeline entry {name!r} needs a non-empty label")
                        continue
                    pending_timeline.append((name, label.strip(), fname))
    st.timeline = dict(CORE_TIMELINE)
    for name, label, fname in pending_timeline:
        if name not in st.merged["attribute"] and name not in ATTRIBUTES:
            st.errors.append(f"vocab fragment {fname}: timeline attribute {name!r} is not in the merged vocabulary")
            continue
        st.timeline.setdefault(name, label)
    st.loaded = True
    return st


def _entry_problem(name: Any, desc: Any) -> str:
    if not isinstance(name, str) or not NAME_RE.match(name):
        return "name must match ^[a-z][a-z0-9_]{0,63}$"
    if not isinstance(desc, str) or not desc.strip():
        return "needs a non-empty description"
    return ""


def _state() -> _State:
    global _STATE
    if not _STATE.loaded:
        with _LOCK:
            if not _STATE.loaded:
                _STATE = _load()
    return _STATE


def reload() -> None:
    """Drop the cached merge and re-read the fragments (tests, plugins)."""
    global _STATE
    with _LOCK:
        _STATE = _load()
    with _WARN_LOCK:
        _WARNED.clear()


# ----------------------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------------------


def _merged(kind: str) -> dict[str, str]:
    """Core names (live table, first) then the fragment names; the first description wins."""
    merged = dict(_CORE[kind])
    for name, desc in _state().merged[kind].items():
        merged.setdefault(name, desc)
    return merged


def attributes() -> dict[str, str]:
    """Merged attribute vocabulary (core + fragments): name -> description."""
    return _merged("attribute")


def tags() -> dict[str, str]:
    """Merged finding/entity tag vocabulary (core + fragments): name -> description."""
    return _merged("tag")


def relations() -> dict[str, str]:
    """Merged relation vocabulary (core + fragments): name -> description."""
    return _merged("relation")


def timeline_attributes() -> dict[str, str]:
    """Dated attributes shown on the case timeline: core set merged with fragment ``timeline`` sections."""
    merged = dict(_state().timeline)
    for name, label in CORE_TIMELINE.items():
        merged.setdefault(name, label)
    return merged


def is_known_attribute(key: str) -> bool:
    return key in ATTRIBUTES or key in _state().merged["attribute"]


def is_known_tag(tag: str) -> bool:
    return tag in TAGS or tag in _state().merged["tag"]


def is_known_relation(rel: str) -> bool:
    return rel in RELATIONS or rel in _state().merged["relation"]


_KNOWN = {"attribute": is_known_attribute, "tag": is_known_tag, "relation": is_known_relation}


def strict_enabled() -> bool:
    """True when strict contract mode is on (env ``V3LUM_STRICT=1``; tests/conftest.py sets it)."""
    return os.environ.get("V3LUM_STRICT", "") == "1"


def check(kind: str, name: str, *, module: str = "") -> bool:
    """Is ``name`` a known ``kind`` ('attribute' | 'tag' | 'relation')?

    Unknown names raise :class:`UnknownVocab` in strict mode; otherwise they are logged once per
    (module, kind, name) on logger ``v3lum.contract`` and False is returned (callers keep them).
    """
    if kind not in _KNOWN:
        raise ValueError(f"unknown vocabulary kind {kind!r} (expected one of {', '.join(KINDS)})")
    if isinstance(name, str) and _KNOWN[kind](name):
        return True
    if strict_enabled():
        raise UnknownVocab(kind, str(name))
    warn_once(module, f"{kind}:{name}", f"{module or '?'}: unknown {kind} {name!r} kept (not in the merged vocabulary)")
    return False


def warn_once(module: str, name: str, message: str) -> None:
    """Log ``message`` once per (module, name) on logger ``v3lum.contract`` (non-strict contract gaps)."""
    key = (module or "", name, "")
    with _WARN_LOCK:
        if key in _WARNED:
            return
        _WARNED.add(key)
    log.warning("%s", message)


def errors() -> list[str]:
    """Problems found in vocabulary fragments (malformed files/entries, bad timeline names)."""
    return list(_state().errors)


def redeclarations() -> list[tuple[str, str, str]]:
    """Names declared again by a fragment: list of (kind, name, fragment file). First description wins."""
    return list(_state().redeclarations)


def fragment_files() -> list[str]:
    """File names of the fragments that were read (diagnostics)."""
    return list(_state().files)
