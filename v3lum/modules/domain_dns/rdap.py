"""RDAP registration data (P003 rdap): IANA bootstrap -> authoritative registry, rdap.org fallback,
registro.br for .br names and Brazilian IP/ASN space.

Final conditions (council #1, P003) and where they live:

1. The IANA bootstrap files (dns, ipv4, ipv6, asn) are registered datasets (24 h TTL, the stale copy is
   kept on a failed refresh) behind the shared helpers :func:`bootstrap_lookup` / :func:`tld_has_rdap`
   (whois_fallback, P343, imports them). The authoritative RDAP server is queried directly; rdap.org
   (community tier) is only a fallback (bootstrap unavailable or TLD absent from it), and its 302 is
   followed only to a declared registry host.
2. .br names always go to rdap.registro.br; BR IP/ASN space follows LACNIC's answer (LACNIC answers 307
   to rdap.registro.br for Brazilian resources, verified 2026-11-26; a country=BR answer without a
   redirect is followed explicitly). The registro.br provider profile sends the neutral non-browser UA
   and Accept application/rdap+json (PROFILE_REQUIREMENTS). 403/429/timeouts are BLOCKED/RATE_LIMITED/
   ERROR 'could not verify' (never cached, so the next scan retries) with the registro.br web whois as
   a manual link.
3. A 404 means 'not registered' only from the authoritative registry server, never from rdap.org or after
   an error; per-query lookups only, no bulk harvesting.
4-5. :func:`minimise_rdap` runs at ingestion, before ``res.raw`` and evidence: registrant organisation,
   CNPJ publicIds, roles, registrar (IANA id, abuse contact), events, status and nameservers are kept;
   natural-person names, personal e-mails and phones (legalRepresentative included) are dropped unless
   the entry is a role/abuse contact; ARIN POCs reduce to role/organisation (Whois-RWS is not queried).
6. CPF publicIds are discarded (never stored or pivoted); a CNPJ publicId becomes a ``cnpj`` pivot
   (relation registrant) and its 8-character root is recorded (``cnpj_roots``).
7. ``registrant_kind`` = org | individual | redacted; an individual-held .br name whose label holds an
   org_profile brand gets ``brand_match`` (feeds P028 typosquat scoring).
8. Privacy/proxy values (bundled list v3lum/data/rdap/privacy_proxy.json) set ``privacy_proxy`` and are
   never pivots or clustering keys; reports show 'redacted (privacy)' neutrally.
9. Events -> created/expires/updated and ``domain_age_days``; nameservers -> ``nameserver`` pivots
   (expand=False); registrar abuse contact and IANA id stay attributes (takedown packet, P345).

Host policy: PASSIVE modules reach only declared hosts. The registries listed in
v3lum/data/providers/_set_rdap_registries.json (+ arin, registrobr, rdap_org) are declared; an
authoritative server outside that list is reported SKIPPED 'policy' with a manual link (core request:
bootstrap-derived registry hosts).
"""

from __future__ import annotations

import ipaddress
import json
import re
import threading
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from v3lum.core import psl
from v3lum.core.datasets import DatasetError, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import REDIRECT_STATUS, AuthRequired, Blocked, HttpError, NetworkError, QuotaExceeded, RateLimited, host_allowed
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

SRC_IANA = "iana.tlds"
SRC_RDAP_ORG = "rdap_org.redirector"
SRC_REGISTROBR = "registrobr.rdap"
SRC_ARIN = "arin.rdap"
#: providers of _set_rdap_registries.json (one 'rdap' source each)
REGISTRY_PROVIDERS = (
    "rdap_ripe", "rdap_apnic", "rdap_lacnic", "rdap_afrinic", "rdap_verisign", "rdap_pir", "rdap_identity_digital",
    "rdap_centralnic", "rdap_radix", "rdap_google_registry", "rdap_nominet", "rdap_gmo_registry", "rdap_zdns",
    "rdap_afnic", "rdap_sidn", "rdap_auda", "rdap_cira", "rdap_nask", "rdap_cznic", "rdap_nic_ar", "rdap_godaddy_registry",
)
REGISTRY_HOSTS = (
    "rdap.arin.net", "rdap.registro.br", "rdap.db.ripe.net", "rdap.apnic.net", "rdap.lacnic.net", "rdap.afrinic.net",
    "rdap.verisign.com", "tld-rdap.verisign.com", "rdap.publicinterestregistry.org", "rdap.identitydigital.services",
    "rdap.centralnic.com", "rdap.centralnicregistry.com", "rdap.radix.host", "pubapi.registry.google", "rdap.nominet.uk",
    "rdap.gmoregistry.net", "rdap.zdnsgtld.com", "rdap.nic.fr", "rdap.sidn.nl", "rdap.cctld.au", "rdap.ca.fury.ca",
    "rdap.dns.pl", "rdap.nic.cz", "rdap.nic.ar", "rdap.nic.biz",
)
REGISTROBR_BASE = "https://rdap.registro.br/"
RDAP_ORG_BASE = "https://rdap.org/"
LACNIC_HOST = "rdap.lacnic.net"
REGISTROBR_HOST = "rdap.registro.br"
ACCEPT = {"Accept": "application/rdap+json"}
PRIVACY_FILE = "rdap/privacy_proxy.json"
WHOIS_WEB = "https://registro.br/tecnologia/ferramentas/whois/?search={value}"
NS_PIVOT_CAP = 13
CIDR_PIVOT_CAP = 10
CONTACT_CAP = 10

#: IANA RDAP bootstrap registries (RFC 9224): kind -> (dataset name, URL)
BOOTSTRAP: dict[str, tuple[str, str]] = {
    "dns": ("iana_rdap_dns.json", "https://data.iana.org/rdap/dns.json"),
    "ipv4": ("iana_rdap_ipv4.json", "https://data.iana.org/rdap/ipv4.json"),
    "ipv6": ("iana_rdap_ipv6.json", "https://data.iana.org/rdap/ipv6.json"),
    "asn": ("iana_rdap_asn.json", "https://data.iana.org/rdap/asn.json"),
}
#: entries a fresh bootstrap download must hold before it replaces the stale copy (P003 cond 1)
BOOTSTRAP_REQUIRED: dict[str, tuple[str, ...]] = {"dns": ("com", "br"), "ipv4": (), "ipv6": (), "asn": ()}
_PRIVATE_ASNS = ((0, 0), (23456, 23456), (64496, 65551), (4200000000, 4294967295))


# ======================================================================================
# IANA bootstrap (shared helper: whois_fallback, P343, imports these names)
# ======================================================================================


class BootstrapUnavailable(Exception):
    """The bootstrap dataset could not be read (no copy downloaded and the refresh failed)."""


def parse_bootstrap(data: Any, kind: str) -> list[tuple[list[str], list[str]]]:
    """Validate an RDAP bootstrap document -> ``[(keys, urls), ...]``; ValueError when unusable
    (HTML, truncated or not version 1.0; a dns.json without com and br)."""
    if not isinstance(data, dict) or not isinstance(data.get("services"), list):
        raise ValueError("not an RDAP bootstrap file (no services list)")
    if str(data.get("version")) != "1.0":
        raise ValueError(f"unexpected bootstrap version {data.get('version')!r}")
    services: list[tuple[list[str], list[str]]] = []
    for svc in data["services"]:
        if (isinstance(svc, list) and len(svc) >= 2 and isinstance(svc[0], list) and isinstance(svc[1], list)
                and svc[1] and all(isinstance(u, str) for u in svc[1])):
            keys = [k.strip().lower() for k in svc[0] if isinstance(k, str) and k.strip()]
            if keys:
                services.append((keys, list(svc[1])))
    if not services:
        raise ValueError("the bootstrap has no usable services")
    present = {k for keys, _ in services for k in keys}
    missing = [r for r in BOOTSTRAP_REQUIRED.get(kind, ()) if r not in present]
    if missing:
        raise ValueError(f"the bootstrap lacks required entries {', '.join(missing)}")
    return services


def _validator(kind: str) -> Any:
    def validate(path: Path) -> bool:
        parse_bootstrap(json.loads(Path(path).read_text(encoding="utf-8")), kind)
        return True

    return validate


for _kind, (_name, _url) in BOOTSTRAP.items():
    register_dataset(
        _name,
        _url,
        ttl=86400,
        description=f"IANA RDAP bootstrap registry ({_kind}): authoritative RDAP base URLs (RFC 9224)",
        licence="IANA public data",
        terms_class="open",
        attribution="Internet Assigned Numbers Authority (IANA), RDAP bootstrap service registries",
        provider="iana",
        source=SRC_IANA,
        validate=_validator(_kind),
        expect="json",
        max_bytes=2_000_000,
        essential=True,
    )


@dataclass(frozen=True)
class BootstrapMatch:
    """An RDAP service of the IANA bootstrap: the matched TLD / prefix / range and its https base URL."""

    kind: str
    match: str
    base: str | None  # None: the service publishes only http:// URLs (never used: no https->http)
    urls: tuple[str, ...]

    @property
    def http_only(self) -> bool:
        return self.base is None

    @property
    def host(self) -> str:
        return (urlsplit(self.base).hostname or "").lower() if self.base else ""


_PARSED: dict[tuple[str, int], tuple[Any, list[tuple[list[str], list[str]]]]] = {}
_PARSED_LOCK = threading.Lock()


def load_bootstrap(ctx: Any, kind: str) -> list[tuple[list[str], list[str]]]:
    """Parsed bootstrap services of ``kind`` through ``ctx.data`` (24 h TTL, stale copy on failure).
    Raises BootstrapUnavailable when no usable copy exists."""
    name, _url = BOOTSTRAP[kind]
    try:
        data = ctx.data.fetch_json(name)
    except DatasetError as exc:  # DatasetUnavailable included
        raise BootstrapUnavailable(f"IANA RDAP bootstrap {kind} unavailable: {exc}") from exc
    key = (kind, id(data))
    with _PARSED_LOCK:
        hit = _PARSED.get(key)
    if hit is not None and hit[0] is data:
        return hit[1]
    try:
        services = parse_bootstrap(data, kind)
    except ValueError as exc:
        raise BootstrapUnavailable(f"IANA RDAP bootstrap {kind} unusable: {exc}") from exc
    with _PARSED_LOCK:
        if len(_PARSED) > 16:
            _PARSED.clear()
        _PARSED[key] = (data, services)
    return services


def pick_base_url(urls: list[str] | tuple[str, ...]) -> str | None:
    """RFC 9224: prefer https; an http-only service gives None (https->http is never used)."""
    for url in urls:
        if isinstance(url, str) and url.lower().startswith("https://"):
            return url if url.endswith("/") else url + "/"
    return None


def match_domain(services: list[tuple[list[str], list[str]]], name: str) -> BootstrapMatch | None:
    """Longest-suffix match of a domain in dns.json."""
    labels = [lb for lb in name.strip().lower().rstrip(".").split(".") if lb]
    for i in range(len(labels)):
        suffix = ".".join(labels[i:])
        for keys, urls in services:
            if suffix in keys:
                return BootstrapMatch("dns", suffix, pick_base_url(urls), tuple(urls))
    return None


def match_ip(services: list[tuple[list[str], list[str]]], value: str, kind: str) -> BootstrapMatch | None:
    """Longest-prefix match of an IP or CIDR in ipv4.json/ipv6.json."""
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None
    best: tuple[Any, list[str]] | None = None
    for keys, urls in services:
        for k in keys:
            try:
                cand = ipaddress.ip_network(k, strict=False)
            except ValueError:
                continue
            if cand.version == net.version and net.subnet_of(cand) and (best is None or cand.prefixlen > best[0].prefixlen):  # type: ignore[arg-type]
                best = (cand, urls)
    if best is None:
        return None
    return BootstrapMatch(kind, str(best[0]), pick_base_url(best[1]), tuple(best[1]))


def match_asn(services: list[tuple[list[str], list[str]]], asn: int) -> BootstrapMatch | None:
    """Range match of an AS number in asn.json."""
    for keys, urls in services:
        for k in keys:
            lo, _, hi = k.partition("-")
            try:
                if int(lo) <= asn <= int(hi or lo):
                    return BootstrapMatch("asn", k, pick_base_url(urls), tuple(urls))
            except ValueError:
                continue
    return None


def bootstrap_lookup(ctx: Any, kind: str, value: Any) -> BootstrapMatch | None:
    """Shared bootstrap helper (P003 cond 1; reused by whois_fallback, P343).

    ``kind``: 'dns' (a domain), 'ipv4' / 'ipv6' (an address or CIDR) or 'asn' ('AS15169' or 15169).
    Returns the matching service, None when the bootstrap has no service for the value (e.g. .io, .de,
    reserved space), and raises BootstrapUnavailable when the bootstrap itself cannot be read.
    """
    services = load_bootstrap(ctx, kind)
    if kind == "dns":
        return match_domain(services, str(value))
    if kind in ("ipv4", "ipv6"):
        return match_ip(services, str(value), kind)
    if kind == "asn":
        try:
            number = int(str(value).upper().removeprefix("AS"))
        except ValueError:
            return None
        return match_asn(services, number)
    raise ValueError(f"unknown bootstrap kind {kind!r} (dns, ipv4, ipv6, asn)")


def tld_has_rdap(ctx: Any, domain: str) -> bool | None:
    """True when the IANA bootstrap names an https RDAP service for ``domain``'s TLD, False when it
    names none (or http only), None when the bootstrap could not be read (could not verify)."""
    try:
        match = bootstrap_lookup(ctx, "dns", domain)
    except BootstrapUnavailable:
        return None
    return bool(match is not None and match.base)


# ======================================================================================
# Minimisation at ingestion (P003 cond 4-9)
# ======================================================================================

_ISO_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?)?\s*(Z|[+-]\d{2}:?\d{2})?$", re.I)
_EVENT_MAP = {"registration": "created", "expiration": "expires", "last changed": "updated"}
_ROLE_LOCALS = frozenset({
    "abuse", "noc", "hostmaster", "postmaster", "security", "soc", "cert", "csirt", "dns", "domains", "domain", "admin",
    "administrator", "support", "suporte", "contato", "contact", "info", "network", "netops", "ipadmin", "ip-admin", "registry",
    "legal", "privacy", "dpo", "webmaster", "arin-contact", "network-abuse", "abuse-reports", "reports", "tech", "technical",
    "juridico", "ti", "helpdesk", "servicedesk", "ripe", "lacnic",
})
_CPF_DIGITS = re.compile(r"(?<!\d)\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?!\d)")


def parse_iso8601(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    m = _ISO_RE.match(value.strip())
    if not m:
        return None
    y, mo, d, hh, mi, ss, tz = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(hh or 0), int(mi or 0), int(ss or 0))
    except ValueError:
        return None
    if tz and tz.upper() != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        dt = dt - timedelta(minutes=sign * (int(digits[:2]) * 60 + int(digits[2:4])))
    return dt.replace(tzinfo=timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def events_summary(events: Any, now: datetime) -> dict[str, Any]:
    """registration/expiration/last changed -> created/expires/updated + domain_age_days ('last update
    of RDAP database' is database freshness, not 'updated')."""
    out: dict[str, Any] = {"created": None, "expires": None, "updated": None, "domain_age_days": None}
    for ev in events if isinstance(events, list) else []:
        if not isinstance(ev, dict):
            continue
        key = _EVENT_MAP.get(str(ev.get("eventAction", "")).strip().lower())
        dt = parse_iso8601(ev.get("eventDate"))
        if key and dt and out[key] is None:
            out[key] = _iso(dt)
    created = parse_iso8601(out["created"])
    if created is not None:
        out["domain_age_days"] = max(0, (now - created).days)
    return out


def parse_vcard(vcard_array: Any) -> dict[str, Any]:
    """jCard ['vcard', [[name, params, type, value], ...]] -> {kind, fn, org, emails, tels, country}."""
    out: dict[str, Any] = {"kind": None, "fn": None, "org": None, "emails": [], "tels": [], "country": None}
    if not (isinstance(vcard_array, list) and len(vcard_array) >= 2 and isinstance(vcard_array[1], list)):
        return out
    for prop in vcard_array[1]:
        if not (isinstance(prop, list) and len(prop) >= 4 and isinstance(prop[0], str)):
            continue
        name, params, value = prop[0].lower(), prop[1] if isinstance(prop[1], dict) else {}, prop[3]
        if name == "kind" and isinstance(value, str):
            out["kind"] = value.strip().lower()
        elif name == "fn" and isinstance(value, str):
            out["fn"] = value.strip() or None
        elif name == "org":
            v = value[0] if isinstance(value, list) and value else value
            out["org"] = v.strip() if isinstance(v, str) and v.strip() else None
        elif name == "email" and isinstance(value, str) and value.strip():
            out["emails"].append(value.strip())
        elif name == "tel" and isinstance(value, str) and value.strip():
            out["tels"].append(value.strip())
        elif name == "adr":
            if isinstance(value, list) and len(value) >= 7 and isinstance(value[6], str) and value[6].strip():
                out["country"] = value[6].strip()
            elif isinstance(params.get("cc"), str):
                out["country"] = params["cc"]
    return out


def is_role_mailbox(email: Any) -> bool:
    """Role/abuse mailbox (abuse@, noc@, hostmaster@...) as opposed to a personal address."""
    if not isinstance(email, str) or "@" not in email:
        return False
    local = email.split("@", 1)[0].lower().split("+", 1)[0]
    return local in _ROLE_LOCALS or local.startswith(("abuse", "noc"))


@dataclass(frozen=True)
class PrivacyList:
    """The bundled privacy/proxy registrant values (P003 cond 8)."""

    patterns: tuple[str, ...]
    email_domains: tuple[str, ...]

    def matches(self, value: Any) -> bool:
        if not isinstance(value, str) or not value.strip():
            return False
        v = value.strip().lower()
        if any(p in v for p in self.patterns):
            return True
        if "@" in v:
            dom = v.rsplit("@", 1)[1]
            return any(dom == d or dom.endswith("." + d) for d in self.email_domains)
        return False


def load_privacy_list(ctx: Any = None) -> PrivacyList:
    """Bundled list through ``ctx.data`` (cited in res.datasets) or the package data directly."""
    try:
        if ctx is not None:
            data = ctx.data.bundled_json(PRIVACY_FILE)
        else:
            from v3lum.core.datasets import DataStore

            data = DataStore.bundled_json(PRIVACY_FILE)
    except (OSError, ValueError):
        data = {}
    pats = tuple(str(p).strip().lower() for p in (data.get("patterns") or []) if isinstance(p, str) and p.strip()) if isinstance(data, dict) else ()
    doms = tuple(str(d).strip().lower() for d in (data.get("email_domains") or []) if isinstance(d, str) and d.strip()) if isinstance(data, dict) else ()
    return PrivacyList(pats, doms)


def _cnpj(identifier: Any) -> str | None:
    ent = Entity.try_make(T.CNPJ, str(identifier or "")) if identifier else None
    return str(ent.value) if ent is not None else None


def cnpj_fmt(digits: str) -> str:
    return f"{digits[:2]}.{digits[2:5]}.{digits[5:8]}/{digits[8:12]}-{digits[12:]}" if len(digits) == 14 else digits


def _walk_entities(entities: Any, depth: int = 0, skip_children_of: tuple[str, ...] = ("registrar",)):
    for ent in entities if isinstance(entities, list) else []:
        if isinstance(ent, dict):
            yield ent, depth
            roles = [r.lower() for r in ent.get("roles") or [] if isinstance(r, str)]
            if not any(r in skip_children_of for r in roles) and depth < 4:
                yield from _walk_entities(ent.get("entities"), depth + 1, skip_children_of)


def _no_cpf(value: Any) -> Any:
    """A kept string never carries a CPF-shaped number (team rule 4, LGPD)."""
    if isinstance(value, str) and _CPF_DIGITS.search(value):
        return None
    return value


def minimise_rdap(obj: Any, now: datetime, privacy: PrivacyList) -> dict[str, Any]:
    """Minimise an RDAP object at ingestion (P003 cond 4-9), before res.raw and evidence.

    Kept: registrant organisation, CNPJ publicIds (+8-character roots), roles, registrar (name, IANA id,
    abuse contact), events (+domain_age_days), status, nameservers, secureDNS, network/autnum ranges and
    country, role/abuse contacts (organisation, role mailbox, phone). Dropped: natural-person names,
    personal e-mails and phones (legalRepresentative included), every CPF publicId and the handles of
    natural persons. Only counters of what was dropped are returned, never the values.
    """
    out: dict[str, Any] = {
        "object": None, "handle": None, "ldh_name": None, "status": [], "events": {}, "nameservers": [], "secure_dns": None,
        "registrar": None, "registrant": None, "registrant_kind": None, "privacy_proxy": False, "contacts": [],
        "roles_present": [], "cnpj": [], "cnpj_roots": [], "network": None, "autnum": None, "country": None,
        "dropped": {"person_fields": 0, "cpf_ids": 0, "legal_representative": 0},
    }
    if not isinstance(obj, dict):
        return out
    oc = obj.get("objectClassName")
    out["object"] = oc if isinstance(oc, str) else None
    if isinstance(obj.get("ldhName"), str):
        out["ldh_name"] = obj["ldhName"].lower().rstrip(".")
    out["status"] = [s for s in obj.get("status") or [] if isinstance(s, str)][:20]
    out["events"] = events_summary(obj.get("events"), now)
    if isinstance(obj.get("country"), str):
        out["country"] = obj["country"].strip().upper()[:2] or None
    for ns in obj.get("nameservers") or []:
        if isinstance(ns, dict) and isinstance(ns.get("ldhName"), str):
            name = ns["ldhName"].lower().rstrip(".")
            if name and name not in out["nameservers"]:
                out["nameservers"].append(name)
    sd = obj.get("secureDNS")
    if isinstance(sd, dict):
        out["secure_dns"] = {
            "delegation_signed": sd.get("delegationSigned") if isinstance(sd.get("delegationSigned"), bool) else None,
            "ds_count": len(sd.get("dsData") or []) if isinstance(sd.get("dsData"), list) else 0,
        }
    handle = obj.get("handle") if isinstance(obj.get("handle"), str) else None
    out["handle"] = _no_cpf(handle)
    if oc == "ip network":
        cidrs: list[str] = []
        for c in obj.get("cidr0_cidrs") or []:
            if isinstance(c, dict):
                pfx = c.get("v4prefix") or c.get("v6prefix")
                if isinstance(pfx, str) and isinstance(c.get("length"), int):
                    try:
                        cidrs.append(str(ipaddress.ip_network(f"{pfx}/{c['length']}", strict=False)))
                    except ValueError:
                        continue
        if not cidrs and isinstance(handle, str) and "/" in handle:
            try:
                cidrs.append(str(ipaddress.ip_network(handle, strict=False)))
            except ValueError:
                pass
        origin = [a for a in obj.get("arin_originas0_originautnums") or [] if isinstance(a, int) and not isinstance(a, bool)]
        if isinstance(obj.get("nicbr_autnum"), int):
            origin.append(int(obj["nicbr_autnum"]))
        out["network"] = {
            "start": obj.get("startAddress") if isinstance(obj.get("startAddress"), str) else None,
            "end": obj.get("endAddress") if isinstance(obj.get("endAddress"), str) else None,
            "cidrs": cidrs[:CIDR_PIVOT_CAP],
            "name": obj.get("name") if isinstance(obj.get("name"), str) else None,
            "handle": out["handle"],
            "type": obj.get("type") if isinstance(obj.get("type"), str) else None,
            "parent_handle": obj.get("parentHandle") if isinstance(obj.get("parentHandle"), str) else None,
            "origin_asns": sorted(set(origin))[:10],
        }
    elif oc == "autnum":
        out["autnum"] = {
            "start": obj.get("startAutnum") if isinstance(obj.get("startAutnum"), int) else None,
            "end": obj.get("endAutnum") if isinstance(obj.get("endAutnum"), int) else None,
            "name": obj.get("name") if isinstance(obj.get("name"), str) else None,
            "handle": out["handle"],
            "type": obj.get("type") if isinstance(obj.get("type"), str) else None,
        }
    roles_present: set[str] = set()
    for ent, _depth in _walk_entities(obj.get("entities")):
        roles = [r.lower() for r in ent.get("roles") or [] if isinstance(r, str)]
        roles_present.update(roles)
        vc = parse_vcard(ent.get("vcardArray"))
        if "legalRepresentative" in ent:
            out["dropped"]["legal_representative"] += 1
        cnpjs: list[str] = []
        for pid in ent.get("publicIds") or []:
            if not isinstance(pid, dict):
                continue
            ptype = str(pid.get("type", "")).strip().lower()
            if ptype == "cpf":
                out["dropped"]["cpf_ids"] += 1  # never stored, never pivoted (P003 cond 6, team rule 4)
                continue
            if ptype == "cnpj":
                value = _cnpj(pid.get("identifier"))
                if value and value not in cnpjs:
                    cnpjs.append(value)
        if "registrar" in roles:
            iana = next((str(p.get("identifier")) for p in ent.get("publicIds") or []
                         if isinstance(p, dict) and "iana" in str(p.get("type", "")).lower() and p.get("identifier") is not None), None)
            abuse: dict[str, Any] | None = None
            for sub, _d in _walk_entities(ent.get("entities"), skip_children_of=()):
                if "abuse" in [r.lower() for r in sub.get("roles") or [] if isinstance(r, str)]:
                    sv = parse_vcard(sub.get("vcardArray"))
                    abuse = {"email": next((e for e in sv["emails"] if not privacy.matches(e)), None), "tel": sv["tels"][0] if sv["tels"] else None}
                    break
            out["registrar"] = {"name": _no_cpf(vc["fn"] or vc["org"]), "iana_id": iana, "abuse": abuse}
            continue
        is_registrant = "registrant" in roles
        natural = vc["kind"] == "individual" or (vc["kind"] is None and not vc["org"] and not cnpjs and not is_registrant and "abuse" not in roles)
        if is_registrant:
            name_val = vc["org"] or vc["fn"]
            proxy = any(privacy.matches(v) for v in [name_val, *vc["emails"]] if v)
            has_cpf = any(isinstance(p, dict) and str(p.get("type", "")).lower() == "cpf" for p in ent.get("publicIds") or [])
            if vc["kind"] == "individual" or (has_cpf and not cnpjs):
                kind = "individual"
            elif proxy:
                kind = "redacted"
            elif vc["org"] or cnpjs or (vc["kind"] == "org" and name_val):
                kind = "org"
            elif vc["fn"] and vc["kind"] is None:
                kind = "individual"  # a bare name without organisation is treated as a natural person
            else:
                kind = "redacted"
            out["registrant_kind"] = kind
            out["privacy_proxy"] = out["privacy_proxy"] or proxy
            out["registrant"] = {
                "kind": kind,
                "org": _no_cpf(name_val) if kind == "org" else None,
                "country": vc["country"],
                "cnpj": cnpjs if kind == "org" else [],
                "handle": _no_cpf(ent.get("handle")) if kind == "org" and isinstance(ent.get("handle"), str) else None,
            }
            out["dropped"]["person_fields"] += (sum(1 for v in [vc["fn"], *vc["emails"], *vc["tels"]] if v) if kind != "org"
                                                else len(vc["emails"]) + len(vc["tels"]))
            if kind == "org":
                for value in cnpjs:
                    if value not in out["cnpj"]:
                        out["cnpj"].append(value)
            continue
        contact: dict[str, Any] = {"roles": roles}
        if natural and "abuse" in roles:
            # an abuse channel of a natural person keeps only the abuse mailbox/phone: never a name or a pivot
            contact.update(natural_person=True, org=None, email=next((e for e in vc["emails"] if not privacy.matches(e)), None),
                           tel=vc["tels"][0] if vc["tels"] else None)
            out["dropped"]["person_fields"] += 1 if vc["fn"] else 0
        elif not natural and ("abuse" in roles or vc["kind"] in ("group", "org") or vc["org"]):
            keep = [e for e in vc["emails"] if not privacy.matches(e) and ("abuse" in roles or is_role_mailbox(e))]
            contact.update(org=_no_cpf(vc["org"] or vc["fn"]), email=keep[0] if keep else None, tel=vc["tels"][0] if vc["tels"] and keep else None)
            out["dropped"]["person_fields"] += len(vc["emails"]) - len(keep[:1])
        else:
            contact.update(org=_no_cpf(vc["org"]), email=None, tel=None)  # natural person: role names only
            out["dropped"]["person_fields"] += sum(1 for v in [vc["fn"], *vc["emails"], *vc["tels"]] if v)
        if len(out["contacts"]) < CONTACT_CAP:
            out["contacts"].append(contact)
    out["roles_present"] = sorted(roles_present)
    out["cnpj_roots"] = sorted({c[:8] for c in out["cnpj"]})
    return out


def answer_matches_query(obj: Any, query_name: str) -> str | None:
    """'exact' | 'parent' | 'other' | None for a domain answer vs. the queried name (rdap.registro.br
    answers a name below a registered domain with the parent object: never 'registered')."""
    if not isinstance(obj, dict) or not isinstance(obj.get("ldhName"), str):
        return None
    a = obj["ldhName"].lower().rstrip(".")
    q = query_name.strip().lower().rstrip(".")
    if a == q:
        return "exact"
    if q.endswith("." + a):
        return "parent"
    return "other"


def fold(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c)).lower()


def brand_label_match(domain: str, brands: list[str], min_len: int = 4) -> str | None:
    """P003 cond 7: the org_profile brand (accent-folded, >= 4 characters) contained in the label of a
    registrable domain, else None."""
    reg = psl.registrable_domain(domain) or domain
    label = fold(reg.split(".", 1)[0])
    flat = re.sub(r"[^a-z0-9]", "", label)
    for brand in brands:
        term = re.sub(r"[^a-z0-9-]", "", fold(str(brand)))
        if len(term) >= min_len and (term in label or term.replace("-", "") in flat):
            return term
    return None


# ======================================================================================
# The module
# ======================================================================================


def registrobr_failure(exc: Exception) -> tuple[str, str, str]:
    """(status, reason code, reason) of a registro.br refusal, rate limit or timeout: 'could not verify',
    never cached by the core, so the next scan retries (P003 cond 2)."""
    if isinstance(exc, RateLimited):
        return "rate_limited", "rate_limited", f"rdap.registro.br rate limited the query: could not verify ({exc}); retried on the next scan"
    if isinstance(exc, QuotaExceeded):
        return "quota", "quota", f"rdap.registro.br quota exhausted: could not verify ({exc})"
    if isinstance(exc, (Blocked, AuthRequired)):
        code = str(getattr(exc, "reason_code", "") or "challenge")
        code = code if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge"
        status = getattr(exc, "status", "") or 403
        return "blocked", code, f"rdap.registro.br refused the query (HTTP {status}): could not verify; retried on the next scan"
    kind = str(getattr(exc, "kind", "") or "").lower()
    timed_out = "timeout" in kind or "deadline" in type(exc).__name__.lower() or "timed out" in str(exc).lower()
    return "error", "timeout" if timed_out else "error", f"rdap.registro.br did not answer: could not verify ({exc})"


class Unverified(Exception):
    """The registry answered something that is not an RDAP object for the query: could not verify."""


@dataclass
class Answer:
    data: dict[str, Any] | None  # None: authoritative 404
    host: str
    url: str
    via_rdap_org: bool = False


def _source_for_host(host: str) -> str:
    from v3lum.core import providers

    prov = providers.registry().provider_for_host(host)
    if prov is None:
        return ""
    sid = "rdap" if "rdap" in prov.sources else "redirector" if "redirector" in prov.sources else ""
    return f"{prov.id}.{sid}" if sid else ""


@register
class Rdap(Module):
    name = "rdap"
    title = "RDAP registration data"
    description = "Registrar, dates, status, nameservers, registrant organisation (CNPJ for .br) and network/AS ownership from the authoritative RDAP registry (IANA bootstrap; rdap.org as fallback)."
    category = "domain_dns"
    accepts = {T.DOMAIN, T.IPV4, T.IPV6, T.CIDR, T.ASN}
    produces = {T.CNPJ, T.ORG, T.DOMAIN, T.ASN, T.CIDR}
    terms = "open"  # public registry data (P003)
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "iana"
    sources = (SRC_IANA, SRC_REGISTROBR, SRC_ARIN, SRC_RDAP_ORG, *(f"{pid}.rdap" for pid in REGISTRY_PROVIDERS))
    hosts = ("data.iana.org", "rdap.org", *REGISTRY_HOSTS)
    access_model = "free_noauth_limited"
    max_requests = 5  # authoritative 1 (redirect hops included) + registro.br after LACNIC 1 + rdap.org fallback 2 + 1 spare
    expected_latency = 1.5
    timeout = 45.0
    cache_ttl = 86400
    max_pivots = 30
    manual_link = "ct_rdap_lookups:rdap_org_domain"
    default_enabled = True  # registro.br RDAP is default-on by decision (A3 BR9)
    reference = "https://about.rdap.org/"
    tags = {"brazil", "free"}
    notice = (
        "Per-query registry lookups only, no bulk harvesting (NIC.br and ARIN RDAP terms). Natural-person contact data "
        "is dropped at ingestion; CPF is never stored or pivoted (LGPD). rdap.org (community tier) receives the value only "
        "as a fallback."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        value = str(entity.value)
        if entity.type is T.DOMAIN:
            return psl.is_known_tld(value.rsplit(".", 1)[-1]) and psl.registrable_domain(value) == value
        if entity.type in (T.IPV4, T.IPV6, T.CIDR):
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError:
                return False
            return bool(net.network_address.is_global and net.broadcast_address.is_global)
        if entity.type is T.ASN:
            try:
                number = int(value.upper().removeprefix("AS"))
            except ValueError:
                return False
            return not any(lo <= number <= hi for lo, hi in _PRIVATE_ASNS)
        return False

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        value = str(entity.value)
        try:
            if entity.type is T.DOMAIN:
                answer = self._domain(res, ctx, value)
            elif entity.type is T.ASN:
                answer = self._number(res, ctx, "asn", "autnum", value.upper().removeprefix("AS"))
            else:
                kind = "ipv6" if ":" in value else "ipv4"
                answer = self._number(res, ctx, kind, "ip", value)
        except Unverified as exc:
            return res.mark("error", f"could not verify: {exc}", reason_code="error")
        if answer is None:
            return res  # already marked (skipped / blocked / not applicable)
        self._emit(res, ctx, entity, answer)
        return res

    # ------------------------------------------------------------------ routing
    def _domain(self, res: ModuleResult, ctx: Any, name: str) -> Answer | None:
        if name.endswith(".br"):  # P003 cond 2: .br always goes to rdap.registro.br
            return self._query(res, ctx, REGISTROBR_BASE + "domain/" + name, name, br=True)
        try:
            match = bootstrap_lookup(ctx, "dns", name)
        except BootstrapUnavailable as exc:
            res.raw = {"bootstrap": str(exc)[:200]}
            return self._via_rdap_org(res, ctx, "domain", name, name)
        if match is None:
            return self._via_rdap_org(res, ctx, "domain", name, name)
        return self._authoritative(res, ctx, match, "domain/" + name, name)

    def _number(self, res: ModuleResult, ctx: Any, kind: str, segment: str, value: str) -> Answer | None:
        try:
            match = bootstrap_lookup(ctx, kind, value)
        except BootstrapUnavailable as exc:
            res.raw = {"bootstrap": str(exc)[:200]}
            return self._via_rdap_org(res, ctx, segment, value, value)
        if match is None:
            res.mark("skipped", f"{value} is not in the IANA RDAP bootstrap ({kind}): reserved or unallocated space", reason_code="not_applicable")
            return None
        answer = self._authoritative(res, ctx, match, f"{segment}/{value}", value)
        if answer is None or answer.data is None:
            return answer
        if answer.host == LACNIC_HOST and str(answer.data.get("country", "")).upper() == "BR":
            # P003 cond 2: Brazilian space answered by LACNIC without its usual 307 -> rdap.registro.br;
            # when registro.br cannot be verified the LACNIC answer stays and the source keeps its status
            br = self._query(res, ctx, REGISTROBR_BASE + f"{segment}/{value}", value, br=True, secondary=True)
            return br if br is not None else answer
        return answer

    def _authoritative(self, res: ModuleResult, ctx: Any, match: BootstrapMatch, path: str, value: str) -> Answer | None:
        if match.base is None:
            res.mark("skipped", f"the RDAP service for {match.match} publishes http:// URLs only (never used): WHOIS fallback (P343) applies",
                     reason_code="not_applicable")
            return None
        if not host_allowed(match.host, self.hosts):
            self._undeclared(res, match.host, path)
            return None
        return self._query(res, ctx, match.base + path, value, br=match.host == REGISTROBR_HOST)

    def _via_rdap_org(self, res: ModuleResult, ctx: Any, segment: str, value: str, display: str) -> Answer | None:
        """rdap.org fallback (community tier): its 302 is followed only to a declared registry host."""
        url = f"{RDAP_ORG_BASE}{segment}/{value}"
        resp = ctx.http.get(url, headers=ACCEPT, source=SRC_RDAP_ORG, allow_redirects=False)
        if resp.status in REDIRECT_STATUS:
            location = urljoin(url, resp.headers.get("location", "").strip())
            host = (urlsplit(location).hostname or "").lower()
            if not location or not location.lower().startswith("https://") or not host:
                raise Unverified(f"rdap.org answered {resp.status} without a usable https Location")
            if not host_allowed(host, self.hosts):
                self._undeclared(res, host, f"{segment}/{value}")
                return None
            answer = self._query(res, ctx, location, display, br=host == REGISTROBR_HOST)
            if answer is not None:
                answer.via_rdap_org = True
            return answer
        if resp.status == 404 and resp.classification is None:
            title = ""
            try:
                body = resp.json()
                title = str(body.get("title") or body.get("description") or "") if isinstance(body, dict) else ""
            except HttpError:
                title = ""
            if "no rdap service" in title.lower():
                res.mark("skipped", f"no RDAP service for {display} (IANA bootstrap and rdap.org): WHOIS fallback (P343) applies", reason_code="not_applicable")
                return None
            raise Unverified("rdap.org answered 404 (not authoritative: never 'not registered')")
        ctx.http.check(resp)  # refusals and failures raise (could not verify)
        data = _rdap_json(resp)
        return Answer(data, (resp.host or "rdap.org").lower(), resp.url or url, via_rdap_org=True)

    def _query(self, res: ModuleResult, ctx: Any, url: str, display: str, *, br: bool, secondary: bool = False) -> Answer | None:
        """One RDAP lookup (redirect hops followed by the core, declared hosts only). A registro.br
        refusal, rate limit or timeout is handled here (P003 cond 2); other failures propagate."""
        source = _source_for_host((urlsplit(url).hostname or "").lower()) or SRC_RDAP_ORG
        try:
            resp = ctx.http.get(url, headers=ACCEPT, source=source)
            if resp.status == 404 and resp.classification is None:
                return Answer(None, (resp.host or "").lower(), resp.url or url)
            ctx.http.check(resp)
        except (Blocked, RateLimited, QuotaExceeded, AuthRequired, NetworkError, HttpError) as exc:
            if not (br or REGISTROBR_HOST in str(getattr(exc, "url", "") or "")):
                raise
            status, code, reason = registrobr_failure(exc)
            res.link("Registro.br web whois (manual lookup)", WHOIS_WEB.format(value=display))
            if secondary:
                res.source_status(SRC_REGISTROBR, status, reason_code=code, reason=reason)
                res.error = reason
            else:
                res.mark(status, reason, reason_code=code)
            return None
        return Answer(_rdap_json(resp), (resp.host or "").lower(), resp.url or url)

    # ------------------------------------------------------------------ failures
    def _undeclared(self, res: ModuleResult, host: str, path: str) -> None:
        res.mark("skipped", f"the authoritative RDAP server {host} is not in V3LUM's registry list (passive host allow-list): could not verify",
                 reason_code="policy")
        res.link("rdap.org lookup (manual)", RDAP_ORG_BASE + path)

    # ------------------------------------------------------------------ output
    def _emit(self, res: ModuleResult, ctx: Any, entity: Entity, answer: Answer) -> None:
        value = str(entity.value)
        server = answer.host or "?"
        if answer.data is None:  # 404 from the authoritative registry server (P003 cond 3)
            res.raw = {"rdap_server": server, "outcome": "not_registered", "via_rdap_org": answer.via_rdap_org}
            res.attr("rdap_server", server)
            if entity.type is T.DOMAIN:
                res.attr("registered", False)
                res.finding(
                    "Not registered at the authoritative registry",
                    "info",
                    f"The authoritative RDAP server {server} has no registration for {value}.",
                    confidence="confirmed",
                    criterion=f"HTTP 404 from the authoritative RDAP server {server} (never from rdap.org or after an error)",
                    tags=["info"],
                    source=_source_for_host(server) or SRC_RDAP_ORG,
                )
            else:
                res.mark("empty", f"{server} holds no RDAP object for {value}")
            return
        data = answer.data
        if entity.type is T.DOMAIN:
            match = answer_matches_query(data, value)
            if match != "exact":
                raise_reason = f"the registry answered for {data.get('ldhName')!r} instead of {value}" if match else "the answer has no ldhName"
                res.mark("error", f"could not verify: {raise_reason}", reason_code="error")
                res.raw = {"rdap_server": server, "outcome": "unexpected_object"}
                return
        mini = minimise_rdap(data, ctx.now(), load_privacy_list(ctx))
        res.raw = {"rdap_server": server, "via_rdap_org": answer.via_rdap_org, "minimised": mini}
        res.attr("rdap_server", server)
        if entity.type is T.DOMAIN:
            self._domain_output(res, ctx, value, mini)
        else:
            self._number_output(res, entity, mini)
        self._registrant_output(res, mini)

    def _domain_output(self, res: ModuleResult, ctx: Any, name: str, mini: dict[str, Any]) -> None:
        res.attr("registered", True)
        ev = mini["events"]
        for key in ("created", "expires", "updated", "domain_age_days"):
            res.attr(key, ev.get(key))
        res.attr("status", mini["status"])
        res.attr("nameservers", mini["nameservers"])
        sd = mini["secure_dns"] or {}
        if sd.get("delegation_signed") is not None:
            res.attr("delegation_signed", sd["delegation_signed"])
        reg = mini["registrar"] or {}
        res.attr("registrar", reg.get("name"))
        res.attr("registrar_iana_id", reg.get("iana_id"))
        abuse = reg.get("abuse") or {}
        res.attr("abuse_contact", abuse.get("email"))
        res.attr("abuse_phone", abuse.get("tel"))
        for ns in mini["nameservers"][:NS_PIVOT_CAP]:
            res.pivot(T.DOMAIN, ns, "nameserver", confidence="confirmed", expand=False)
        if name.endswith(".br") and mini["registrant_kind"] == "individual":
            brands = list(getattr(ctx.org, "brand_terms", lambda: [])() or [])
            hit = brand_label_match(name, brands) if brands else None
            if hit:
                res.attr("brand_match", hit)
                res.finding(
                    "Org brand in an individual-held .br name",
                    "info",
                    "The registrant is a natural person (data withheld) and the name carries an org_profile brand keyword: "
                    "input for typosquat scoring (P028).",
                    confidence="possible",
                    criterion="registro.br registrant of kind individual and an org_profile brand (>= 4 characters) in the label",
                    data={"brand": hit},
                    tags=["info"],
                    source=SRC_REGISTROBR,
                )

    @staticmethod
    def _number_output(res: ModuleResult, entity: Entity, mini: dict[str, Any]) -> None:
        ev = mini["events"]
        res.attr("created", ev.get("created"))
        res.attr("updated", ev.get("updated"))
        res.attr("country", mini["country"])
        if mini["network"]:
            net = mini["network"]
            res.attr("rdap_network", {k: net[k] for k in ("start", "end", "cidrs", "name", "handle", "type", "parent_handle")})
            asns = [f"AS{a}" for a in net["origin_asns"]]
            if asns:
                res.attr("asn", asns[0])
            for cidr in net["cidrs"][:CIDR_PIVOT_CAP]:
                res.pivot(T.CIDR, cidr, "in_network", confidence="confirmed", expand=False)
            for asn in asns:
                res.pivot(T.ASN, asn, "belongs_to_asn", confidence="confirmed", expand=False)
        if mini["autnum"]:
            res.attr("rdap_autnum", mini["autnum"])
            reg = mini["registrant"] or {}
            res.attr("as_org", reg.get("org") or mini["autnum"].get("name"))
        abuse = next((c for c in mini["contacts"] if "abuse" in c.get("roles", []) and c.get("email")), None)
        if abuse:
            res.attr("abuse_contact", abuse["email"])
            res.attr("abuse_phone", abuse.get("tel"))

    @staticmethod
    def _registrant_output(res: ModuleResult, mini: dict[str, Any]) -> None:
        kind = mini["registrant_kind"]
        res.attr("registrant_kind", kind)
        if mini["privacy_proxy"]:
            res.attr("privacy_proxy", True)
        reg = mini["registrant"] or {}
        contacts = [{k: c.get(k) for k in ("roles", "org", "email", "tel")} for c in mini["contacts"] if c.get("org") or c.get("email")]
        res.attr("rdap_contacts", contacts)
        if kind != "org" or mini["privacy_proxy"]:
            return  # natural persons, redacted and privacy/proxy registrants: no pivots, no clustering (cond 5, 8)
        org = reg.get("org")
        if org:
            res.attr("registrant", org)
            res.attr("org", org)
            res.pivot(T.ORG, org, "registrant", confidence="probable", expand=False, note="registrant organisation (registry data)")
        if mini["cnpj"]:
            res.attr("registrant_doc", cnpj_fmt(mini["cnpj"][0]))
            res.attr("cnpj_roots", mini["cnpj_roots"])
            for value in mini["cnpj"]:
                res.pivot(T.CNPJ, value, "registrant", confidence="confirmed", note=f"registrant CNPJ (root {value[:8]}, registry publicIds)")


def _rdap_json(resp: Any) -> dict[str, Any]:
    """The RDAP object of an answer; errors inside HTTP 200 and odd bodies are 'could not verify'."""
    try:
        data = resp.json()
    except HttpError as exc:
        raise Unverified(f"{resp.host or 'registry'} answered something that is not JSON") from exc
    if not isinstance(data, dict):
        raise Unverified(f"{resp.host or 'registry'} answered a {type(data).__name__} instead of an RDAP object")
    if data.get("errorCode") is not None:
        raise Unverified(f"{resp.host or 'registry'} answered RDAP errorCode {str(data.get('errorCode'))[:10]} in HTTP {resp.status}")
    if not isinstance(data.get("objectClassName"), str):
        raise Unverified(f"{resp.host or 'registry'} answered JSON without objectClassName")
    return data
