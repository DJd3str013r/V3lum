"""ip_geolocation: keyless IP geolocation chain with a provider vote (P051).

Batch p3-G02-2, proposal P051. Final conditions implemented here:

* FC1 - offline first: ``ip_offline_db``/``ip_offline_geo`` (P047, disclosure 'none', default-on)
  answer country and ASN for every IP; this online chain is opt-in (``default_enabled=False``: it
  runs only with ``-M ip_geolocation`` or ``--preset deep``), runs only on analyst-typed seed IPs
  (``run_on='seeds'``, re-checked here: never pivots, text-extracted or unconfirmed IPs) and asks at
  most 2 providers per IP (``max_requests=2``).
* FC2 - bogon, RFC 1918, CGNAT, loopback, link-local, documentation and other special-purpose
  addresses are filtered before any call (:func:`bogon_reason`; ``applies`` False); addresses of the
  organisation's own networks (employees/customers) and analysed subjects get the offline data only
  (SKIPPED 'privacy').
* FC3 - wired now: ipwho.is (``success:false`` + message in a 200 body = ERROR through the provider
  error marker, HTTP 429 'Rate limit exceeded' = QUOTA; ``connection.domain`` becomes an
  ``operator_domain`` pivot with expand=False) and FreeIPAPI (the new host
  free.freeipapi.com/api/v1/json/{ip}; all-null 200 bodies = ERROR; ``isProxy`` only as a weak
  hint). Both community tier, terms open.
* FC4 - ip.guide, IP2Location.io keyless and GeoJS are NOT wired until legal records their terms and
  tier: their parsers are kept here (:func:`parse_ipguide` reads the JSON served as text/plain,
  :func:`parse_ip2location`, :func:`parse_geojs`) but no host, source or request exists for them.
  KeyCDN is never wired (:data:`NOT_WIRED`): its mandatory UA 'keycdn-tools:https://<site>' would
  disclose the company's website on every lookup.
* FC5 - ONE shared vote helper with P046 (``ip_anonymizer_consensus.vote_tally`` /
  ``format_value_votes`` with categories country/ASN and a strict majority of the answers):
  'BR - 2/2 providers', labelled approximate; the city only as '<city> - approximate (<provider>)'
  with disagreements listed.
* FC6 - context only: one INFO finding tagged ``context_only``; coordinates, postal codes and time
  zones are never kept; no ``located_at``/coordinates pivot; the plain ``country``/``city``
  attributes are not set (the approximate country lives in ``geo_votes`` with its votes).
* FC7 - 1 req/s per provider (``min_interval`` and the provider profiles), cache 24 h, a status per
  provider (``res.source_status``); tests use the recorded ipwho.is and FreeIPAPI answers and a live
  ``success:false`` body.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from v3lum.core import http as _http
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.ip_network.ip_anonymizer_consensus import answer, failed, format_value_votes, vote_tally

# --------------------------------------------------------------------------------------
# shared helpers (also used by the other p3-G02-2 modules)
# --------------------------------------------------------------------------------------

_NULLISH = {"", "-", "--", "nil", "null", "none", "n/a", "na", "unknown", "not available"}
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_DOC_NETS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "3fff::/20"))
_BENCH_NETS = tuple(ipaddress.ip_network(n) for n in ("198.18.0.0/15", "2001:2::/48"))
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+(?!-)[a-z0-9-]{2,63}(?<!-)$")


class EndpointRefused(ValueError):
    """A request a final condition forbids (never built, never sent)."""


def text(value: Any) -> str | None:
    """Stripped string, or None for null-ish placeholders ('nil', '-', 'N/A', 'Unknown', '')."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        value = str(value)
    if not isinstance(value, str):
        return None
    v = value.strip()
    return None if v.lower() in _NULLISH else v


def flag(value: Any) -> bool | None:
    """bool or None (accepts true/false strings and 0/1)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.strip().lower() in ("true", "false", "yes", "no", "1", "0"):
        return value.strip().lower() in ("true", "yes", "1")
    return None


def integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"\s*-?\d{1,18}\s*", value):
        return int(value)
    return None


def parse_asn(value: Any) -> int | None:
    """'AS15169' | '15169' | 15169 -> 15169. 0, AS_TRANS, private-use and reserved ASNs -> None
    (GeoJS answers 64512 'Unknown' for addresses it does not know)."""
    if isinstance(value, str):
        value = re.sub(r"^\s*as", "", value.strip(), flags=re.I).split(" ", 1)[0]
    n = integer(value)
    if n is None or n <= 0 or n >= 2**32:
        return None
    if n in (23456, 65535) or 64496 <= n <= 65551 or n >= 4200000000:
        return None
    return n


def country_code(value: Any) -> str | None:
    """Two-letter ISO code (upper case) or None (names, 3-letter codes and ZZ/XX/EU/AP -> None)."""
    v = text(value)
    if not v or not re.fullmatch(r"[A-Za-z]{2}", v):
        return None
    v = v.upper()
    return None if v in ("ZZ", "XX", "EU", "AP") else v


def bogon_reason(value: Any) -> str | None:
    """Why an address must never leave the machine, or None for a public (global) address (FC2).

    'invalid' | 'unspecified' | 'loopback' | 'link_local' | 'multicast' | 'cgnat' | 'documentation'
    | 'benchmarking' | 'reserved' | 'private' | 'not_global'. IPv4-mapped IPv6 is judged on its IPv4
    part."""
    try:
        ip = value if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(str(value).strip())
    except ValueError:
        return "invalid"
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    checks = (
        ("unspecified", ip.is_unspecified), ("loopback", ip.is_loopback), ("link_local", ip.is_link_local),
        ("multicast", ip.is_multicast), ("cgnat", ip.version == 4 and ip in _CGNAT),
        ("documentation", any(ip in n for n in _DOC_NETS if n.version == ip.version)),
        ("benchmarking", any(ip in n for n in _BENCH_NETS if n.version == ip.version)),
        ("reserved", ip.is_reserved), ("private", ip.is_private), ("not_global", not ip.is_global),
    )
    return next((name for name, hit in checks if hit), None)


def normalize_ip(value: Any) -> str | None:
    """Canonical text of an IP address (IPv4-mapped IPv6 -> IPv4), or None."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def normalize_domain(value: Any) -> str | None:
    """Lower-case ASCII (IDNA) host name, or None. Validates selectors before they reach a query
    language or a URL, so quotes, spaces or operators can never be injected."""
    v = text(value)
    if not v:
        return None
    v = v.rstrip(".").lower()
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return v if _HOST_RE.match(v) else None


def json_ok(predicate: Any) -> Any:
    """``cache_if`` factory: cache an answer only when its JSON body satisfies ``predicate``
    (error-in-200 bodies are never served from the cache)."""

    def check(resp: Any) -> bool:
        try:
            return bool(predicate(resp.json()))
        except Exception:  # noqa: BLE001 - an unreadable body is never cached
            return False

    return check


def error_message(exc: BaseException) -> str:
    """The provider's own message from an HttpError body (JSON 'message'/'error', else the text)."""
    body = str(getattr(exc, "body", "") or "")
    try:
        doc = json.loads(body)
    except ValueError:
        doc = None
    if isinstance(doc, dict):
        for key in ("message", "error", "description"):
            value = doc.get(key)
            if isinstance(value, dict):
                value = value.get("message") or value.get("code")
            if isinstance(value, str) and value.strip():
                return value.strip()[:200]
    found = re.search(r'"(?:message|error)"\s*:\s*"([^"]{1,200})', body)
    return found.group(1) if found else ""


def failure_of(exc: BaseException) -> tuple[Status, str] | None:
    """Per-source 'could not verify' status for a provider failure (rule 5); None for what must
    propagate (kill switch, request cap, run deadline, policy and configuration refusals)."""
    if isinstance(exc, (_http.RequestCapReached, _http.Cancelled, _http.DeadlineExceeded, _http.PolicyError, _http.ConfigError)):
        return None
    if isinstance(exc, _http.QuotaExceeded):
        return Status.QUOTA, "quota"
    if isinstance(exc, _http.RateLimited):
        return Status.RATE_LIMITED, "rate_limited"
    if isinstance(exc, _http.Blocked):
        code = str(getattr(exc, "reason_code", "") or "challenge")
        return Status.BLOCKED, code if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge"
    if isinstance(exc, _http.AuthRequired):
        return Status.NEEDS_KEY, "needs_key"
    if isinstance(exc, _http.OfflineError):
        return Status.UNAVAILABLE, "offline"
    if isinstance(exc, (_http.HttpError, _http.NetworkError, ValueError)):
        return Status.ERROR, "error"
    return None


def personal_reason(entity: Entity, ctx: Any) -> str:
    """FC2/P046 c3: own-network addresses (employees, customers) and analysed subjects are personal
    data: they never reach third-party lookups ('' when the address may be sent)."""
    org = getattr(ctx, "org", None)
    try:
        owned = org.owns(entity) if org is not None and not getattr(org, "is_empty", True) else None
    except Exception:  # noqa: BLE001 - an unreadable profile never sends a value out
        return "organisation profile unreadable"
    if owned is not None and getattr(owned, "own", False):
        return "address of the organisation's own network (employees/customers)"
    options = getattr(ctx, "options", None)
    roles = getattr(options, "subject_roles", None) or {}
    if isinstance(roles, dict) and (roles.get(entity.key) or roles.get(entity.value)):
        return "address of an analysed subject (customer/victim)"
    return ""


def seed_only_reason(entity: Entity, ctx: Any) -> str:
    """run_on='seeds' re-checked inside the module: pivots, text-extracted and unconfirmed values are
    never sent ('' for a confirmed analyst-typed seed)."""
    if not getattr(ctx, "is_seed", False) or getattr(ctx, "depth", 0) or getattr(ctx, "provenance", ()):
        return "run_on=seeds: only analyst-typed seed values are sent to this provider (pivots and extracted values never are)"
    unconfirmed = getattr(getattr(ctx, "options", None), "unconfirmed_seeds", None) or set()
    if entity.key in unconfirmed or entity.value in unconfirmed:
        return "run_on=seeds: the analyst did not confirm this value as a seed"
    return ""


# --------------------------------------------------------------------------------------
# provider records (untrusted answers: every field type-checked; FC6 fields never kept)
# --------------------------------------------------------------------------------------

#: Wired now (FC3).
WIRED: dict[str, dict[str, str]] = {
    "ipwhois": {"name": "ipwho.is", "source": "ipwhois.geo", "url": "https://ipwho.is/{ip}"},
    "freeipapi": {"name": "FreeIPAPI", "source": "freeipapi.geo", "url": "https://free.freeipapi.com/api/v1/json/{ip}"},
}
ASK_ORDER: tuple[str, ...] = ("ipwhois", "freeipapi")
MAX_PROVIDERS = 2  # FC1
#: Parsers ready, not wired until legal records terms and tier (FC4): no host, source or request.
PENDING: dict[str, dict[str, str]] = {
    "ipguide": {"name": "ip.guide", "host": "ip.guide", "url": "https://ip.guide/{ip}", "why": "terms not reviewed (FC4)"},
    "ip2location": {"name": "IP2Location.io", "host": "api.ip2location.io", "url": "https://api.ip2location.io/?ip={ip}",
                    "why": "terms and tier not recorded (FC4); optional key V3LUM_IP2LOCATION_KEY would travel only as 'Authorization: Bearer'"},
    "geojs": {"name": "GeoJS", "host": "get.geojs.io", "url": "https://get.geojs.io/v1/ip/geo/{ip}.json", "why": "terms not reviewed (FC4)"},
}
#: Never wired (FC4).
NOT_WIRED = {"keycdn": "KeyCDN requires User-Agent 'keycdn-tools:https://<site>' (HTTP 403 otherwise), which would "
                       "disclose the company website on every lookup (P051 FC4)"}
CONTEXT_NOTE = "approximate network geolocation (context only): not a risk factor and not the location of a person (P051 FC6)"


def geo_record(provider: str, **fields: Any) -> dict[str, Any]:
    keys = ("ip", "country", "country_name", "region", "city", "asn", "as_org", "isp", "operator_domain", "network",
            "rir", "as_country", "proxy_hint")
    rec = {k: fields.get(k) for k in keys}
    rec["provider"] = provider
    return rec


def parse_ipwhois(doc: Any) -> dict[str, Any] | None:
    """ipwho.is record (FC3); None for an answer that is not a successful geolocation object."""
    if not isinstance(doc, dict) or doc.get("success") is not True:
        return None
    conn = doc.get("connection") if isinstance(doc.get("connection"), dict) else {}
    return geo_record(
        "ipwhois", ip=normalize_ip(doc.get("ip")), country=country_code(doc.get("country_code")), country_name=text(doc.get("country")),
        region=text(doc.get("region")), city=text(doc.get("city")), asn=parse_asn(conn.get("asn")),
        as_org=text(conn.get("isp")) or text(conn.get("org")), isp=text(conn.get("isp")),
        network=None, operator_domain=normalize_domain(conn.get("domain")),
    )


def parse_freeipapi(doc: Any) -> dict[str, Any] | None:
    """FreeIPAPI record (FC3); None for the all-null body it returns for addresses it does not accept."""
    if not isinstance(doc, dict) or text(doc.get("ipAddress")) is None:
        return None
    return geo_record(
        "freeipapi", ip=normalize_ip(doc.get("ipAddress")), country=country_code(doc.get("countryCode")),
        country_name=text(doc.get("countryName")), region=text(doc.get("regionName")), city=text(doc.get("cityName")),
        asn=parse_asn(doc.get("asn")), as_org=text(doc.get("asnOrganization")), isp=text(doc.get("asnOrganization")),
        proxy_hint=flag(doc.get("isProxy")),
    )


#: ip.guide answers country NAMES only: a small table; unknown names simply do not vote.
COUNTRY_NAMES = {
    "argentina": "AR", "australia": "AU", "brazil": "BR", "brasil": "BR", "canada": "CA", "chile": "CL", "china": "CN",
    "colombia": "CO", "france": "FR", "germany": "DE", "india": "IN", "ireland": "IE", "italy": "IT", "japan": "JP",
    "mexico": "MX", "netherlands": "NL", "the netherlands": "NL", "paraguay": "PY", "peru": "PE", "portugal": "PT",
    "russia": "RU", "russian federation": "RU", "singapore": "SG", "spain": "ES", "sweden": "SE", "switzerland": "CH",
    "united kingdom": "GB", "united states": "US", "united states of america": "US", "uruguay": "UY",
}


def parse_ipguide(raw: Any) -> dict[str, Any] | None:
    """ip.guide /{ip} (FC4, not wired): JSON served as text/plain is parsed regardless of the header;
    gives network CIDR, AS and registration country (``as_country``, never a geolocation vote)."""
    doc = raw
    if isinstance(raw, (bytes, str)):
        try:
            doc = json.loads(raw)
        except ValueError:
            return None
    if not isinstance(doc, dict):
        return None
    net = doc.get("network") if isinstance(doc.get("network"), dict) else {}
    asys = net.get("autonomous_system") if isinstance(net.get("autonomous_system"), dict) else {}
    loc = doc.get("location") if isinstance(doc.get("location"), dict) else {}
    cname = text(loc.get("country"))
    try:
        cidr = str(ipaddress.ip_network(text(net.get("cidr")) or "", strict=False)) if text(net.get("cidr")) else None
    except ValueError:
        cidr = None
    return geo_record(
        "ipguide", ip=normalize_ip(doc.get("ip")), country=COUNTRY_NAMES.get((cname or "").casefold()), country_name=cname,
        city=text(loc.get("city")), asn=parse_asn(asys.get("asn")), as_org=text(asys.get("organization")) or text(asys.get("name")),
        isp=text(asys.get("name")), network=cidr, rir=text(asys.get("rir")), as_country=country_code(asys.get("country")),
    )


def parse_ip2location(doc: Any) -> dict[str, Any] | None:
    """IP2Location.io (FC4, not wired). The keyless 'message' is a notice; an ``error`` object is not a record."""
    if not isinstance(doc, dict) or isinstance(doc.get("error"), dict):
        return None
    return geo_record(
        "ip2location", ip=normalize_ip(doc.get("ip")), country=country_code(doc.get("country_code")),
        country_name=text(doc.get("country_name")), region=text(doc.get("region_name")), city=text(doc.get("city_name")),
        asn=parse_asn(doc.get("asn")), as_org=text(doc.get("as")), isp=text(doc.get("as")), proxy_hint=flag(doc.get("is_proxy")),
    )


def parse_geojs(doc: Any) -> dict[str, Any] | None:
    """GeoJS (FC4, not wired). Coordinates may be the string 'nil' (dropped anyway); ASN 64512 = unknown."""
    if isinstance(doc, list):
        doc = doc[0] if doc and isinstance(doc[0], dict) else None
    if not isinstance(doc, dict):
        return None
    org = text(doc.get("organization_name"))
    return geo_record(
        "geojs", ip=normalize_ip(doc.get("ip")), country=country_code(doc.get("country_code")), country_name=text(doc.get("country")),
        region=text(doc.get("region")), city=text(doc.get("city")), asn=parse_asn(doc.get("asn")), as_org=org, isp=org,
    )


PARSERS = {"ipwhois": parse_ipwhois, "freeipapi": parse_freeipapi}
_OK = {"ipwhois": lambda d: isinstance(d, dict) and d.get("success") is True,
       "freeipapi": lambda d: isinstance(d, dict) and text(d.get("ipAddress")) is not None}


def geo_answer(rec: dict[str, Any], name: str) -> dict[str, Any]:
    """A shared-vote-helper answer (P046 shape) for one provider record."""
    votes = {"country": rec.get("country"), "asn": f"AS{rec['asn']}" if rec.get("asn") else None}
    if not any(votes.values()):
        out = failed(rec["provider"], name, Status.ERROR, "error", f"{name}: no country or ASN in the answer: could not verify")
        out["record"] = rec
        return out
    return answer(rec["provider"], name, votes, record=rec)


def _city_key(city: str) -> str:
    return re.sub(r"\s*\(.*?\)\s*", "", city or "").strip().casefold()


def geo_vote(answers: list[dict[str, Any]]) -> dict[str, Any]:
    """FC5/FC6: one vote over the provider answers through the shared helper (strict majority of the
    providers that answered; a 1-1 split is 'disputed', never a verdict)."""
    answered = [a for a in answers if a.get("answered")]
    tally: dict[str, Any] = {"categories": {}}
    for cat in ("country", "asn"):  # strict majority of the providers that voted on the category
        voters = sum(1 for a in answered if (a.get("votes") or {}).get(cat) is not None)
        one = vote_tally(answers, categories=(cat,), need=max(1, voters // 2 + 1), labels={"country": "country", "asn": "ASN"})
        tally["categories"][cat] = one["categories"][cat]
        tally.update(providers=one["providers"], could_not_verify=one["could_not_verify"])
    records = [a.get("record") or {} for a in answered]
    out: dict[str, Any] = {"approximate": True, "providers": tally["providers"], "could_not_verify": tally["could_not_verify"],
                           "country": None, "country_votes": None, "asn": None, "asn_votes": None, "isp": None, "city": None}
    parts: list[str] = []
    country = tally["categories"]["country"]
    if country["verdict"] is not None:
        out["country"] = country["verdict"]
        out["country_votes"] = format_value_votes(tally, "country")
        parts.append(f"country: {out['country_votes']} (approximate)")
    elif country["voters"]:
        out["country_votes"] = "disputed: " + ", ".join(f"{r.get('country')} ({a.get('name')})" for a, r in zip(answered, records) if r.get("country"))
        parts.append(f"country: {out['country_votes']}")
    asn = tally["categories"]["asn"]
    if asn["verdict"] is not None:
        out["asn"] = asn["verdict"]
        names = [r.get("as_org") or r.get("isp") for r in records if r.get("asn") and f"AS{r['asn']}" == asn["verdict"]]
        out["isp"] = next((n for n in names if n), None)
        out["asn_votes"] = f"{asn['verdict']}{' ' + out['isp'] if out['isp'] else ''} - {len(asn['agreeing'])}/{asn['voters']} providers"
        out["asn_agreeing"] = len(asn["agreeing"])
        parts.append(f"ASN: {out['asn_votes']}")
    elif asn["voters"]:
        out["asn_votes"] = "disputed: " + ", ".join(f"AS{r.get('asn')} ({a.get('name')})" for a, r in zip(answered, records) if r.get("asn"))
        parts.append(f"ASN: {out['asn_votes']}")
    cities = [(a.get("name"), r.get("city")) for a, r in zip(answered, records) if r.get("city")]
    if cities:
        first_name, first_city = cities[0]
        line = f"{first_city} - approximate ({first_name})"
        others = [(n, c) for n, c in cities[1:] if _city_key(c) != _city_key(first_city)]
        if others:
            line += ", disagreement: " + ", ".join(f"{c} ({n})" for n, c in others)
        out["city"] = line
        parts.append(f"city: {line}")
    if any(r.get("proxy_hint") for r in records):
        out["proxy_hint"] = "weak hint: a provider flags the address as a proxy (isProxy)"
    if tally["could_not_verify"]:
        parts.append("could not verify: " + ", ".join(tally["could_not_verify"]))
    out["line"] = "; ".join(parts) if parts else "no geolocation data"
    return out


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class IpGeolocation(Module):
    name = "ip_geolocation"
    title = "IP geolocation vote (ipwho.is, FreeIPAPI)"
    description = (
        "Approximate country and ASN/ISP of an analyst-typed public IP voted by two keyless providers (ipwho.is, "
        "FreeIPAPI), with the agreeing sources ('BR - 2/2 providers'); context only, opt-in after the offline answer."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6}
    produces = {T.ASN, T.DOMAIN}
    run_on = "seeds"
    tags = {"free"}
    reference = "https://ipwhois.io/documentation"
    notice = (
        "Geolocation is approximate network context only (P051 FC6): never a risk factor, never a person's location. "
        "Opt-in after the offline answer (ip_offline_db); analyst-typed seed IPs only; bogon/private and own-network "
        "addresses are never sent. ip.guide, IP2Location.io and GeoJS wait for legal; KeyCDN is never used."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "ipwhois"
    sources = tuple(WIRED[p]["source"] for p in ASK_ORDER)
    hosts = ("ipwho.is", "free.freeipapi.com")
    access_model = "free_noauth_limited"
    max_requests = MAX_PROVIDERS
    expected_latency = 0.8
    timeout = 15.0
    min_interval = 1.0  # FC7: 1 req/s per provider
    cache_ttl = 86400  # FC7: 24 h
    max_pivots = 2
    default_enabled = False  # FC1: opt-in (-M ip_geolocation or --preset deep)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return bogon_reason(entity.value) is None  # FC2: filtered before any call

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        ip = normalize_ip(entity.value) or entity.value
        why = seed_only_reason(entity, ctx)
        if why:
            return res.mark(Status.SKIPPED, f"{why} (P051 FC1)", reason_code="privacy")
        why = personal_reason(entity, ctx)
        if why:
            return res.mark(Status.SKIPPED, f"{why}: offline data only (P051 FC2)", reason_code="privacy")
        order = [p for p in ASK_ORDER if WIRED[p]["source"] in ctx.allowed_sources][:MAX_PROVIDERS]
        if not order:
            return res.mark(Status.SKIPPED, "no geolocation provider allowed in this run", reason_code="licence")
        answers: list[dict[str, Any]] = []
        for pid in order:
            if ctx.cancelled():
                break
            ans = self._ask(ctx, pid, ip)
            answers.append(ans)
            spec = WIRED[pid]
            if ans.get("answered"):
                res.source_status(spec["source"], Status.OK)
            else:
                res.source_status(spec["source"], Status(ans["status"]), reason_code=ans["reason_code"], reason=str(ans["reason"])[:300])
        vote = geo_vote(answers)
        res.raw = {"line": vote["line"], "answers": [
            {**{k: v for k, v in (a.get("record") or {}).items() if v is not None},
             "provider": a.get("name"), "answered": bool(a.get("answered")), "reason": a.get("reason") or None}
            for a in answers]}
        answered = [a for a in answers if a.get("answered")]
        if not answered:
            first = next((a for a in answers if not a.get("answered")), None)
            status, code = (Status(first["status"]), first["reason_code"]) if first else (Status.ERROR, "error")
            return res.mark(status, f"no geolocation provider answered: {vote['line']}", reason_code=code or "error")
        res.attr("geo_votes", vote)
        if vote.get("asn"):
            res.attr("asn", vote["asn"])
            res.attr("as_org", vote.get("isp"))
            agreeing = int(vote.get("asn_agreeing") or 0)
            res.pivot(T.ASN, vote["asn"], "belongs_to_asn", confidence=0.8 if agreeing >= 2 else 0.6, expand=False,
                      note=f"geolocation providers agree: {vote['asn_votes']}")
        operator = next((a["record"].get("operator_domain") for a in answered if a.get("record", {}).get("operator_domain")), None)
        if operator:
            res.pivot(T.DOMAIN, operator, "operator_domain", confidence=0.5, expand=False,
                      note="ipwho.is connection.domain: the network operator's domain, not the host's own name")
        res.finding(
            "Approximate network geolocation (context only)",
            "info",
            vote["line"],
            confidence="possible",
            data={k: vote.get(k) for k in ("country_votes", "asn_votes", "city", "providers", "could_not_verify")},
            tags=["context_only"],
            source=WIRED[str(answered[0].get("provider"))]["source"],
        )
        return res

    def _ask(self, ctx: Any, pid: str, ip: str) -> dict[str, Any]:
        spec = WIRED[pid]
        name = spec["name"]
        try:
            doc = ctx.http.get_json(spec["url"].format(ip=ip), source=spec["source"], cache_if=json_ok(_OK[pid]))
        except Exception as exc:  # noqa: BLE001 - per-provider rule 5, the rest propagates
            mapped = failure_of(exc)
            if mapped is None:
                raise
            msg = error_message(exc)
            reason = f"{name}: {msg}" if msg else f"{name}: {str(exc)[:160] or type(exc).__name__}"
            return failed(pid, name, mapped[0], mapped[1], reason)
        rec = PARSERS[pid](doc)
        if rec is None:
            why = "all-null body (address not accepted)" if pid == "freeipapi" else "unexpected answer"
            return failed(pid, name, Status.ERROR, "error", f"{name}: {why}: could not verify")
        return geo_answer(rec, name)
