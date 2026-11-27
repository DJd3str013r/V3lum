"""networksdb: NetworksDB.io organisation -> IP ranges, keyed (P218).

Batch p3-G02-2, proposal P218. Final conditions implemented here:

* FC1 - key ``networksdb`` (alias ``V3LUM_NETWORKSDB_KEY``) sent only in the ``X-Api-Key`` header,
  never as the ``apikey`` query parameter (:func:`networksdb_request` refuses it). The missing-key
  answer (HTTP 400 ``{"error": "required header `X-Api-Key` ... missing"}``) gives NEEDS_KEY.
* FC2 - key-terms: a company/team account on a plan whose terms permit internal business use,
  recorded by legal (``key_plans.networksdb``); monthly quota (1,000 on the free plan) through the
  provider's P334 block; free keys return page 1 only, so no page parameter is ever sent.
* FC3 - the organisation search is fuzzy: names are ranked with :func:`org_match_score` (accents,
  punctuation and legal suffixes folded) and only the best one or two candidates above
  :data:`MIN_MATCH` are expanded; their ranges are ``candidate_netblock`` pivots with
  ``expand=False`` and confidence <= 0.4 (:data:`MAX_CONFIDENCE`) until rdap (P003) or nicbr_asn
  (P038) confirms them, and they never form an ACTIVE scope by themselves (``scope_eligible``
  False in ``network_candidates``).
* FC4 - the corptrace (AGPL) flow (org-search -> org-networks) is re-implemented from the vendor
  API documentation; no code was read or copied (A6). The success fixtures are documentation-shaped
  until a trimmed real capture made with the company key replaces them (merge precondition,
  docs/backlog/p3-G02-2.md); the missing-key fixture is the real research capture.

IPv4 inputs use ``/api/ip-info`` (owner organisation and network); domain inputs are resolved
through the core DoH resolver and the first public, non-CDN IPv4 address is looked up the same way
(NetworksDB's own DNS endpoints are not used: they would spend the monthly quota on what DoH
already answers). ``org-info`` (address/phone of the holder) is never called.
"""

from __future__ import annotations

import difflib
import ipaddress
import re
import unicodedata
from typing import Any
from urllib.parse import urlencode

from v3lum.core import http as _http
from v3lum.core import noise
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.ip_network.ip_geolocation import (
    EndpointRefused,
    bogon_reason,
    country_code,
    error_message,
    integer,
    json_ok,
    normalize_ip,
    parse_asn,
    text,
)

SOURCE = "networksdb.api"
BASE = "https://networksdb.io/api/"
ENDPOINTS = {
    "org-search": {"required": ("search",), "optional": ("country",)},
    "org-networks": {"required": ("id",), "optional": ("ipv6",)},
    "ip-info": {"required": ("ip",), "optional": ()},
}
MAX_CONFIDENCE = 0.4  # FC3
MIN_MATCH = 0.5
MAX_ORGS = 2  # org-networks calls per company name (FC3: best 1-2 candidates)
MAX_CIDRS = 50
#: ranges that are never pivots (documentation ranges stay: they never occur in real answers)
_PIVOT_DROP = frozenset({"invalid", "unspecified", "loopback", "link_local", "multicast", "cgnat", "private", "reserved"})
_LEGAL_SUFFIXES = frozenset({"sa", "ltda", "ltd", "limited", "inc", "incorporated", "llc", "corp", "corporation", "co", "company",
                             "gmbh", "ag", "bv", "plc", "me", "eireli", "epp", "srl", "sas", "spa", "sl", "pty", "oy", "ab", "nv", "the"})
_KEY_ERROR = re.compile(r"(?i)x-api-key|apikey|api key|\bkey\b.*\b(invalid|missing|unauthori[sz]ed)\b")


def networksdb_request(endpoint: str, **params: Any) -> str:
    """URL of one NetworksDB call (FC1): the key goes only in the X-Api-Key header, so an 'apikey'
    (or 'key') parameter raises :class:`EndpointRefused`, as do endpoints outside :data:`ENDPOINTS`
    (reverse DNS, mass reverse DNS, org-info) and paging (free keys: page 1 only)."""
    spec = ENDPOINTS.get(endpoint)
    if spec is None:
        raise EndpointRefused(f"NetworksDB endpoint {endpoint!r} is not wired")
    if any(str(k).lower() in ("apikey", "api_key", "key") for k in params):
        raise EndpointRefused("the NetworksDB key travels only in the X-Api-Key header, never as a parameter (P218 FC1)")
    unknown = set(params) - set(spec["required"]) - set(spec["optional"])
    if unknown:
        raise ValueError(f"unexpected NetworksDB parameter(s): {', '.join(sorted(unknown))}")
    for req in spec["required"]:
        if text(params.get(req)) is None:
            raise ValueError(f"NetworksDB {endpoint} needs {req!r}")
    if "ip" in params and bogon_reason(params["ip"]):
        raise ValueError(f"refusing {bogon_reason(params['ip'])} address for NetworksDB")
    clean = {k: ("true" if v is True else str(v)) for k, v in params.items() if v is not None}
    return BASE + endpoint + "?" + urlencode(clean)


def org_name_key(name: Any) -> str:
    """Accent-folded, lower-case organisation name without punctuation or legal suffixes."""
    v = unicodedata.normalize("NFKD", text(name) or "")
    v = "".join(c for c in v if not unicodedata.combining(c)).casefold()
    words = [w for w in re.sub(r"[^0-9a-z]+", " ", v).split() if w not in _LEGAL_SUFFIXES and len(w) > 1]
    return " ".join(words)


def org_match_score(query: Any, name: Any) -> float:
    """0..1 similarity between the analyst's company name and an organisation name (fuzzy, FC3)."""
    a, b = org_name_key(query), org_name_key(name)
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    ratio = difflib.SequenceMatcher(None, a, b).ratio()
    ta, tb = set(a.split()), set(b.split())
    overlap = len(ta & tb) / max(len(ta), 1)
    return round(min(1.0, 0.5 * ratio + 0.5 * overlap), 3)


def _cidrs(cidr: Any, first: Any, last: Any) -> list[str]:
    """CIDRs of a network row: 'cidr', or the first..last range summarised ('N/A' rows)."""
    value = text(cidr)
    if value and value.upper() != "N/A":
        try:
            return [str(ipaddress.ip_network(value, strict=False))]
        except ValueError:
            pass
    try:
        a, b = ipaddress.ip_address(str(first).strip()), ipaddress.ip_address(str(last).strip())
    except ValueError:
        return []
    if a.version != b.version or a > b:
        return []
    return [str(n) for n in ipaddress.summarize_address_range(a, b)]


def parse_org_search(doc: Any, query: str) -> list[dict[str, Any]] | None:
    """org-search answer -> organisations ranked by match score; None when the answer is unusable."""
    if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
        return None
    orgs = []
    for o in doc["results"]:
        if not isinstance(o, dict) or not text(o.get("id")):
            continue
        name = text(o.get("organization")) or text(o.get("organisation")) or text(o.get("name"))
        nets = o.get("networks") if isinstance(o.get("networks"), dict) else {}
        orgs.append({"org_id": text(o.get("id")), "org": name, "match_score": org_match_score(query, name),
                     "countries": [c for c in (o.get("countries") or []) if isinstance(c, str)][:10],
                     "networks_v4": integer(nets.get("ipv4")), "networks_v6": integer(nets.get("ipv6")),
                     "asns": [f"AS{a}" for a in (parse_asn(x) for x in (o.get("asns") or [])) if a][:20]})
    orgs.sort(key=lambda o: -o["match_score"])
    return orgs


def parse_org_networks(doc: Any) -> tuple[list[dict[str, Any]], int] | None:
    """org-networks answer -> (networks [{cidrs, netname, country}], invalid rows); None when unusable."""
    if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
        return None
    out, invalid = [], 0
    for n in doc["results"]:
        if not isinstance(n, dict):
            invalid += 1
            continue
        cidrs = _cidrs(n.get("cidr"), n.get("first_ip"), n.get("last_ip"))
        if not cidrs:
            invalid += 1
            continue
        out.append({"cidrs": cidrs, "netname": text(n.get("netname")), "country": country_code(n.get("countrycode"))})
    return out, invalid


def parse_ip_info(doc: Any) -> dict[str, Any] | None:
    """ip-info answer -> {ip, org, org_id, cidrs, netname}; None when unusable."""
    if not isinstance(doc, dict):
        return None
    org = doc.get("organization") if isinstance(doc.get("organization"), dict) else {}
    net = doc.get("network") if isinstance(doc.get("network"), dict) else {}
    cidrs = _cidrs(net.get("cidr"), net.get("first_ip"), net.get("last_ip")) if net else []
    if not (org or cidrs):
        return None
    return {"ip": normalize_ip(doc.get("ip")), "org": text(org.get("name")), "org_id": text(org.get("id")), "cidrs": cidrs,
            "netname": text(net.get("netname"))}


def pivotable(cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return bogon_reason(net.network_address) not in _PIVOT_DROP


@register
class NetworksDb(Module):
    name = "networksdb"
    title = "NetworksDB organisation networks"
    description = (
        "Candidate IP ranges registered to an organisation (fuzzy NetworksDB.io organisation search, then its "
        "networks), and the owner network of an IPv4 or of a domain's address; keyed, candidates only."
    )
    category = "company_org"
    accepts = {T.ORG, T.IPV4, T.DOMAIN}
    produces = {T.CIDR}
    reference = "https://networksdb.io/api/docs"
    notice = (
        "Keyed (key-terms): runs under the corporate profile only with a company/team key whose plan legal recorded "
        "(key_plans.networksdb). The organisation search is fuzzy: ranges are candidates (confidence <= 0.4, never "
        "expanded) until RDAP or NIC.br confirms them, and never an ACTIVE scope by themselves."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "networksdb"
    sources = (SOURCE,)
    hosts = ("networksdb.io",)
    access_model = "free_auth_limited"
    requires_keys = ("networksdb",)
    max_requests = 1 + MAX_ORGS
    expected_latency = 3.0
    timeout = 30.0
    min_interval = 1.0
    cache_ttl = 604800
    max_pivots = MAX_CIDRS
    default_enabled = False

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type == T.IPV4:
            return bogon_reason(entity.value) is None
        if entity.type == T.ORG:
            return len(org_name_key(entity.value)) >= 3
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = str(ctx.key("networksdb") or "").strip()
        if not key:
            return res.mark(Status.NEEDS_KEY, "NetworksDB needs the key 'networksdb' (V3LUM_NETWORKSDB_KEY)", reason_code="needs_key")
        try:
            if entity.type == T.ORG:
                return self._org(res, ctx, key, entity.value)
            if entity.type == T.IPV4:
                return self._ip(res, ctx, key, entity.value, via="")
            ip = self._domain_address(ctx, entity.value)
            if ip is None:
                return res.mark(Status.SKIPPED, "the domain has no public, non-CDN IPv4 address to look up (DoH)", reason_code="not_applicable")
            return self._ip(res, ctx, key, ip, via=entity.value)
        except _KeyMissing as exc:
            return res.mark(Status.NEEDS_KEY, f"NetworksDB: {exc}", reason_code="needs_key")

    # ---------------------------------------------------------------------------- calls
    def _get(self, ctx: Any, key: str, endpoint: str, **params: Any) -> Any:
        url = networksdb_request(endpoint, **params)
        try:
            return ctx.http.get_json(url, headers={"X-Api-Key": key}, source=SOURCE,
                                     cache_if=json_ok(lambda d: isinstance(d, dict) and "error" not in d))
        except (_http.QuotaExceeded, _http.RateLimited, _http.Blocked, _http.AuthRequired):
            raise
        except _http.HttpError as exc:
            msg = error_message(exc)
            if getattr(exc, "status", 0) in (400, 401) and _KEY_ERROR.search(msg):  # FC1: missing/invalid key body
                raise _KeyMissing(msg) from None
            raise

    def _org(self, res: ModuleResult, ctx: Any, key: str, name: str) -> ModuleResult:
        orgs = parse_org_search(self._get(ctx, key, "org-search", search=name), name)
        if orgs is None:
            return res.mark(Status.ERROR, "unexpected NetworksDB org-search answer: could not verify", reason_code="error")
        if not orgs:
            return res.mark(Status.EMPTY, f"NetworksDB knows no organisation matching {name!r}")
        chosen = [o for o in orgs if o["match_score"] >= MIN_MATCH][:MAX_ORGS]
        candidates = []
        invalid_rows = 0
        for org in chosen:
            if ctx.cancelled():
                break
            parsed = parse_org_networks(self._get(ctx, key, "org-networks", id=org["org_id"]))
            if parsed is None:
                res.source_status(SOURCE, Status.ERROR, reason_code="error", reason=f"unexpected org-networks answer for {org['org_id']}")
                continue
            networks, invalid = parsed
            invalid_rows += invalid
            confidence = round(max(0.05, min(MAX_CONFIDENCE, MAX_CONFIDENCE * org["match_score"])), 3)
            cidrs = []
            for net in networks:
                for cidr in net["cidrs"]:
                    if cidr not in cidrs and pivotable(cidr) and len(cidrs) < MAX_CIDRS:
                        cidrs.append(cidr)
                        res.pivot(T.CIDR, cidr, "candidate_netblock", confidence=confidence, expand=False,
                                  note=f"candidate only ({org['org']}, NetworksDB fuzzy match {org['match_score']}): confirm with rdap or nicbr_asn")
            candidates.append({**org, "cidrs": cidrs, "confidence": confidence})
        listed = candidates + [o for o in orgs[:5] if o not in chosen]
        res.raw = {"orgs": orgs[:10], "networks": candidates, "invalid_rows": invalid_rows}
        res.attr("network_candidates", {"query": name, "candidates": listed, "scope_eligible": False,
                                        "confirm_with": ["rdap", "nicbr_asn"], "source": "networksdb"})
        total = sum(len(c["cidrs"]) for c in candidates)
        res.finding(
            "Candidate networks of the organisation (fuzzy match)",
            "info",
            f"NetworksDB lists {len(orgs)} organisation(s) for {name!r}; {total} candidate range(s) from "
            f"{', '.join(c['org'] or c['org_id'] for c in candidates) or 'no close match'}. Candidates only: confirm the holder "
            "with RDAP/NIC.br before any use; never an ACTIVE scope by themselves.",
            confidence="possible",
            data={"organisations": len(orgs), "expanded": [c["org_id"] for c in candidates], "ranges": total},
            tags=["context_only"],
            source=SOURCE,
        )
        return res

    def _ip(self, res: ModuleResult, ctx: Any, key: str, ip: str, *, via: str) -> ModuleResult:
        parsed = parse_ip_info(self._get(ctx, key, "ip-info", ip=ip))
        if parsed is None:
            return res.mark(Status.ERROR, "unexpected NetworksDB ip-info answer: could not verify", reason_code="error")
        res.raw = {"ip_info": parsed, "via_domain": via or None}
        res.attr("org", parsed["org"])
        relation = "candidate_netblock" if via else "in_network"
        for cidr in parsed["cidrs"][:MAX_CIDRS]:
            if pivotable(cidr):
                res.pivot(T.CIDR, cidr, relation, confidence=MAX_CONFIDENCE, expand=False,
                          note=f"NetworksDB owner network of {ip}{' (resolved from ' + via + ')' if via else ''}: confirm with rdap")
        res.attr("network_candidates", {"query": via or ip, "candidates": [{"org": parsed["org"], "org_id": parsed["org_id"],
                                                                            "cidrs": parsed["cidrs"], "netname": parsed["netname"]}],
                                        "scope_eligible": False, "confirm_with": ["rdap", "nicbr_asn"], "source": "networksdb"})
        return res

    @staticmethod
    def _domain_address(ctx: Any, domain: str) -> str | None:
        """First public, non-CDN IPv4 of the domain through the core DoH resolver (not NetworksDB's DNS)."""
        answer = ctx.dns.query(domain, "A")
        for record in getattr(answer, "records", None) or []:
            ip = normalize_ip(record)
            if ip and ":" not in ip and bogon_reason(ip) is None and not noise.is_cdn(Entity.make(T.IPV4, ip)):
                return ip
        return None


class _KeyMissing(Exception):
    """The provider answered that the key is missing or invalid (NEEDS_KEY)."""
