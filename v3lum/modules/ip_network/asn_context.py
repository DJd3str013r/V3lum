"""asn_context: who operates an ASN and how 'dirty' its address space looks (P033).

Batch p2-G02-1, proposal P033 (approved, P2). Three free sources, each with its own status (c1), all
registry sources with terms 'open' and tier trusted (providers peeringdb, circl, shadowserver):

* **PeeringDB** (``www.peeringdb.com``; the bare host answers 301): ``GET /api/net?asn={n}&depth=2`` for
  the network record (name, network type NSP/Content/Enterprise..., peering policy, IXPs, facilities,
  IRR as-set, website) and ``GET /api/org/{id}?depth=0`` for the operator (organisation) name; a
  company name is searched with ``/api/net?name__contains=``. Answers are capped (IXP and facility
  lists, 2 MB body cap in the provider profile) and the anonymous throttle is respected
  (``min_interval`` 3.5 s in the provider profile); the optional key ``peeringdb`` travels only in
  ``Authorization: Api-Key`` (c2).
* PeeringDB AUP (c3): ``poc_set`` contact objects (names, e-mails, phones, URLs) and free-text notes
  are dropped at ingestion and never stored or reused; only the role names ('NOC', 'Abuse', ...) and
  the number of dropped contacts are kept.
* **CIRCL BGP Ranking** (``bgpranking-ng.circl.lu``): ``POST /json/asn`` (maliciousness rank of the AS)
  and ``GET /ipasn_history/?ip=`` (origin AS per date). Context only (c4): shown as 'rank X (higher =
  more malicious activity observed)' with an explanation, one INFO finding tagged ``context_only`` -
  never above INFO and never a consensus vote (P171); large clouds and hosters always rank high.
* **Shadowserver** public API (``api.shadowserver.org``, keyless, c5): ``GET /net/asn?origin=<IPv4>``
  (origin AS, AS name, prefix) and ``GET /net/asn?prefix=<asn>`` (announced prefixes). Failures are
  'could not verify'. The reports API (``transform.shadowserver.org``) is out of scope (c6): registering
  the company's own ASNs/netblocks for free reports is an institutional DPO/IT decision (docs/LEGAL.md).

One throttled or failing source never hides the others: each source's outcome is recorded with
``res.source_status``; the run is OK when any source answered with data, EMPTY when the sources that
answered found nothing, and takes the failure of the sources only when none of them answered.
Pivots: an ASN's operator becomes a ``company_name`` pivot (``operated_by``, ``expand=False``: a
self-declared, homonym-prone name); a company name lists candidate ASNs (``asn_candidate``, POSSIBLE,
``expand=False``). An IP gets context attributes only (the AS operator is not the user of the address).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    OfflineError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.core.noise import is_public_ip

SRC_PDB = "peeringdb.api"
SRC_CIRCL = "circl.bgpranking"
SRC_SS = "shadowserver.net_api"
SOURCES = (SRC_PDB, SRC_CIRCL, SRC_SS)
SOURCE_LABELS = {SRC_PDB: "PeeringDB", SRC_CIRCL: "CIRCL BGP Ranking", SRC_SS: "Shadowserver"}
PDB_API = "https://www.peeringdb.com/api"
CIRCL_API = "https://bgpranking-ng.circl.lu"
SS_API = "https://api.shadowserver.org/net/asn"
KEY = "peeringdb"
IX_CAP = 25
FAC_CAP = 25
PREFIX_CAP = 100
CANDIDATE_CAP = 10
HISTORY_CAP = 10
ATTRIBUTIONS = {
    SRC_PDB: "Network data: PeeringDB (https://www.peeringdb.com), used under the PeeringDB AUP for Internet operational purposes",
    SRC_CIRCL: "BGP Ranking and IPASN History: CIRCL (https://bgpranking-ng.circl.lu)",
    SRC_SS: "ASN and prefix data: The Shadowserver Foundation public API (https://www.shadowserver.org)",
}
RANK_EXPLANATION = (
    "CIRCL BGP Ranking scores an AS by how much of its announced address space appears in public abuse and blocklist "
    "feeds. Large clouds, hosters and access networks always rank high because abuse by their customers is attributed "
    "to the AS. Context only: never a verdict, never above INFO, never a consensus vote."
)
#: PeeringDB info_type -> coarse class (P033 c2: NSP / Content / Enterprise / hosting...).
NETWORK_CLASS = {
    "content": "content_hosting",
    "nsp": "transit_nsp",
    "cable/dsl/isp": "eyeball_isp",
    "enterprise": "enterprise",
    "educational/research": "education_research",
    "non-profit": "non_profit",
    "government": "government",
    "route server": "network_services",
    "route collector": "network_services",
    "network services": "network_services",
    "not disclosed": "undisclosed",
}
#: PeeringDB class -> the core attribute network_type ('eyeball' | 'hosting' | 'transit'); others are not mapped.
NETWORK_TYPE = {"content_hosting": "hosting", "transit_nsp": "transit", "eyeball_isp": "eyeball"}
#: Fields of a PeeringDB network record that hold contact data or free text: never kept (c3, PeeringDB AUP).
DROPPED_FIELDS = ("poc_set", "notes", "notes_private")
_ASN_RE = re.compile(r"^(?:AS)?\s*(\d{1,10})$", re.I)


# --------------------------------------------------------------------------------------
# small helpers (untrusted data: every field is type-checked)
# --------------------------------------------------------------------------------------


def asn_number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        n = value
    else:
        m = _ASN_RE.match(str(value or "").strip())
        if not m:
            return None
        n = int(m.group(1))
    return n if 0 <= n <= 4294967295 else None


def is_reserved_asn(n: int) -> bool:
    """AS0, AS_TRANS, documentation, private-use and last ASNs (RFC 6996/5398/7300): never queried."""
    return n in (0, 23456, 65535, 4294967295) or 64496 <= n <= 65534 or 65536 <= n <= 65551 or 4200000000 <= n <= 4294967294


def _text(value: Any, limit: int = 200) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"\d{1,12}", value.strip()):
        return int(value.strip())
    return None


def _float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if value == value else None


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _cidr(value: Any) -> str | None:
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None
    if net.prefixlen < (8 if net.version == 4 else 19):
        return None  # 0.0.0.0/0 ('not announced') and other implausibly broad blocks
    return str(net)


def _or_empty(body: Any) -> Any:
    """A documented PeeringDB 404 ('Entity not found', get_json returned None) reads as an empty data list."""
    return {"data": []} if body is None else body


class SourceFailure(Exception):
    """A source could not be verified (status + canonical reason code + reason)."""

    def __init__(self, status: Status, code: str, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.code = code
        self.reason = reason


# --------------------------------------------------------------------------------------
# PeeringDB (c2, c3)
# --------------------------------------------------------------------------------------


def peeringdb_net_url(asn: int) -> str:
    return f"{PDB_API}/net?asn={int(asn)}&depth=2"


def peeringdb_org_url(org_id: int) -> str:
    return f"{PDB_API}/org/{int(org_id)}?depth=0"


def peeringdb_search_url(name: str) -> str:
    return f"{PDB_API}/net?" + urlencode({"name__contains": name, "depth": 0, "limit": CANDIDATE_CAP})


def peeringdb_headers(key: str = "") -> dict[str, str]:
    """c2: the optional key travels only in the Authorization header ('Api-Key <key>')."""
    headers = {"Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Api-Key {key}"
    return headers


def peeringdb_records(body: Any) -> list[dict[str, Any]]:
    """The 'data' list of a PeeringDB answer ([] for 'Entity not found'); SourceFailure otherwise."""
    if not isinstance(body, dict):
        raise SourceFailure(Status.ERROR, "error", "PeeringDB answer is not a JSON object: could not verify")
    detail = _text(body.get("detail") or body.get("message"), 200)
    if "throttled" in detail.lower():
        raise SourceFailure(Status.RATE_LIMITED, "rate_limited", f"PeeringDB throttled the request ({detail[:80]})")
    meta_error = _text(_dict(body.get("meta")).get("error"), 200)
    if meta_error and "not found" in meta_error.lower():
        return []
    if meta_error:
        raise SourceFailure(Status.ERROR, "error", f"PeeringDB error: {meta_error[:120]}: could not verify")
    data = body.get("data")
    if not isinstance(data, list):
        raise SourceFailure(Status.ERROR, "error", "PeeringDB answer without a data list: could not verify")
    return [item for item in data if isinstance(item, dict)]


def network_class(info_type: Any, info_types: Any) -> str:
    values = [v for v in [info_type, *_list(info_types)] if isinstance(v, str) and v.strip()]
    for value in values:
        cls = NETWORK_CLASS.get(value.strip().lower())
        if cls:
            return cls
    return "other" if values else "undisclosed"


def parse_peeringdb_net(record: dict[str, Any], org_name: str = "") -> dict[str, Any]:
    """One PeeringDB network record -> the kept context (c2) with contacts dropped at ingestion (c3)."""
    pocs = record.get("poc_set")
    roles = sorted({_text(p.get("role"), 40) for p in _list(pocs) if isinstance(p, dict) and _text(p.get("role"), 40)})
    ix_all = [x for x in _list(record.get("netixlan_set")) if isinstance(x, dict)]
    fac_all = [x for x in _list(record.get("netfac_set")) if isinstance(x, dict)]
    ixps = []
    for item in ix_all[:IX_CAP]:
        name = _text(item.get("name"), 200)
        ixps.append({
            "name": name,
            "ix_id": _int(item.get("ix_id")),
            "speed_mbps": _int(item.get("speed")),
            "is_rs_peer": item.get("is_rs_peer") is True,
            "ix_br": name.lower().startswith("ix.br"),
        })
    facilities = [{"name": _text(item.get("name"), 200), "city": _text(item.get("city"), 100), "country": _text(item.get("country"), 2)}
                  for item in fac_all[:FAC_CAP]]
    ix_count = _int(record.get("ix_count"))
    fac_count = _int(record.get("fac_count"))
    cls = network_class(record.get("info_type"), record.get("info_types"))
    website = _text(record.get("website"), 300)
    return {
        "asn": _int(record.get("asn")),
        "name": _text(record.get("name")),
        "aka": _text(record.get("aka")),
        "operator": _text(org_name) or _text(record.get("name")),
        "org_id": _int(record.get("org_id")),
        "info_type": _text(record.get("info_type"), 60),
        "network_class": cls,
        "scope": _text(record.get("info_scope"), 60),
        "traffic": _text(record.get("info_traffic"), 60),
        "ratio": _text(record.get("info_ratio"), 60),
        "prefixes4": _int(record.get("info_prefixes4")),
        "prefixes6": _int(record.get("info_prefixes6")),
        "policy": {
            "general": _text(record.get("policy_general"), 60),
            "locations": _text(record.get("policy_locations"), 60),
            "ratio": record.get("policy_ratio") is True,
            "contracts": _text(record.get("policy_contracts"), 60),
            "url": _text(record.get("policy_url"), 300),
        },
        "ix_count": ix_count,
        "ixps": ixps,
        "fac_count": fac_count,
        "facilities": facilities,
        "truncated": {
            "ixps": len(ix_all) > len(ixps) or (ix_count or 0) > len(ix_all),
            "facilities": len(fac_all) > len(facilities) or (fac_count or 0) > len(fac_all),
        },
        "irr_as_set": _text(record.get("irr_as_set"), 200),
        "website": website if website.lower().startswith(("http://", "https://")) else "",
        "looking_glass": _text(record.get("looking_glass"), 300),
        "updated": _text(record.get("updated"), 40),
        "poc_roles": roles,
        "dropped_contacts": len(pocs) if isinstance(pocs, list) else 0,
    }


# --------------------------------------------------------------------------------------
# CIRCL BGP Ranking (c4)
# --------------------------------------------------------------------------------------


def circl_percentile(position: Any, total: Any) -> float | None:
    """Position 1 = the highest maliciousness score; 0-100 where higher = more malicious, else None."""
    p, t = _int(position), _int(total)
    if p is None or t is None or t <= 0 or p <= 0 or p > t:
        return None
    return round(100.0 * (t - p + 1) / t, 1)


def rank_text(percentile: float | None, position: int | None = None, total: int | None = None) -> str:
    """c4 display string: 'rank X (higher = more malicious activity observed; position p of N ranked ASNs)'."""
    if percentile is None:
        return "not ranked (no activity attributed to this AS in CIRCL's feeds that day; not a clean bill)"
    extra = f"; position {position} of {total} ranked ASNs" if position is not None and total is not None else ""
    return f"rank {percentile:.1f} (higher = more malicious activity observed{extra})"


def parse_circl_rank(body: Any, asn: int) -> dict[str, Any] | None:
    """CIRCL /json/asn -> context-only ranking; None when the AS is not ranked (EMPTY); SourceFailure for
    error shapes (an echoed invalid ASN has asn_description {} instead of a string)."""
    if not isinstance(body, dict) or not isinstance(body.get("response"), dict):
        raise SourceFailure(Status.ERROR, "error", "CIRCL BGP Ranking answer has no response object: could not verify")
    resp = body["response"]
    echoed = asn_number(_dict(body.get("meta")).get("asn"))
    desc = resp.get("asn_description")
    ranking = resp.get("ranking")
    if not isinstance(ranking, dict) or not isinstance(desc, str):
        raise SourceFailure(Status.ERROR, "error", "CIRCL BGP Ranking echoed an invalid query (no description/ranking): could not verify")
    if echoed is not None and echoed != asn:
        raise SourceFailure(Status.ERROR, "error", f"CIRCL BGP Ranking answered for AS{echoed}, asked AS{asn}: could not verify")
    position, total = _int(ranking.get("position")), _int(ranking.get("total_known_asns"))
    percentile = circl_percentile(position, total)
    if desc.strip().lower().startswith("-reserved as-") or percentile is None:
        return None
    return {
        "asn": f"AS{asn}",
        "description": _text(desc),
        "position": position,
        "total_known_asns": total,
        "percentile": percentile,
        "rank_score": _float(ranking.get("rank")),
        "text": rank_text(percentile, position, total),
        "explanation": RANK_EXPLANATION,
    }


def parse_ipasn_history(body: Any) -> list[dict[str, Any]]:
    """CIRCL /ipasn_history -> [{date, asn, prefix, source}] latest first; ASN 0 / 0.0.0.0/0 (not announced) dropped."""
    if not isinstance(body, dict) or not isinstance(body.get("response"), dict):
        raise SourceFailure(Status.ERROR, "error", "CIRCL IPASN History answer has no response object: could not verify")
    rows = []
    for date, rec in body["response"].items():
        if not isinstance(rec, dict):
            continue
        n = asn_number(rec.get("asn"))
        prefix = _cidr(rec.get("prefix"))
        if not n or prefix is None:
            continue
        rows.append({"date": _text(date, 40), "asn": f"AS{n}", "prefix": prefix, "source": _text(rec.get("source"), 40)})
    rows.sort(key=lambda r: r["date"], reverse=True)
    return rows[:HISTORY_CAP]


# --------------------------------------------------------------------------------------
# Shadowserver public API (c5)
# --------------------------------------------------------------------------------------


def shadowserver_origin_url(ip: str) -> str:
    return f"{SS_API}?" + urlencode({"origin": ip})


def shadowserver_prefix_url(asn: int) -> str:
    return f"{SS_API}?" + urlencode({"prefix": str(int(asn))})


def parse_shadowserver_origin(body: Any, ip: str) -> dict[str, Any] | None:
    """net/asn?origin= -> {asn, as_name, prefix} or None (no origin data). Unknown and invalid queries are
    both echoed as [{"ip": "<query>"}]: an echo that is not the queried address is an error in a 200 answer."""
    if isinstance(body, list):
        if not body:
            return None
        rec = body[0]
    else:
        rec = body
    if not isinstance(rec, dict):
        raise SourceFailure(Status.ERROR, "error", "Shadowserver origin answer has an unexpected shape: could not verify")
    echo = _text(rec.get("ip"), 64)
    try:
        same = ipaddress.ip_address(echo) == ipaddress.ip_address(ip)
    except ValueError:
        same = False
    if not same:
        raise SourceFailure(Status.ERROR, "error", f"Shadowserver echoed {echo[:40]!r} for {ip}: could not verify")
    n = asn_number(rec.get("asn"))
    if not n:
        return None
    return {"asn": f"AS{n}", "as_name": _text(rec.get("asn_name")), "prefix": _cidr(rec.get("prefix")) or ""}


def parse_shadowserver_prefixes(body: Any) -> list[str]:
    """net/asn?prefix=<asn> -> normalised, deduplicated, sorted prefixes (IPv4 first)."""
    if not isinstance(body, list):
        raise SourceFailure(Status.ERROR, "error", "Shadowserver prefix answer is not a list: could not verify")
    nets = {ipaddress.ip_network(c) for c in (_cidr(x) for x in body if isinstance(x, str)) if c}
    return [str(n) for n in sorted(nets, key=lambda n: (n.version, int(n.network_address), n.prefixlen))]


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@dataclass
class _Run:
    res: ModuleResult
    ctx: Any
    outcomes: dict[str, list[tuple[str, Status, str, str]]] = field(default_factory=dict)  # source -> [(call, status, code, reason)]
    stopped: str = ""

    def note(self, source: str, call: str, status: Status, code: str = "", reason: str = "") -> None:
        self.outcomes.setdefault(source, []).append((call, status, code, reason))


def _failure_of(exc: Exception, label: str, *, keyed: bool) -> SourceFailure:
    if isinstance(exc, SourceFailure):
        return exc
    if isinstance(exc, RateLimited):
        return SourceFailure(Status.RATE_LIMITED, "rate_limited", f"{label}: rate limited")
    if isinstance(exc, QuotaExceeded):
        return SourceFailure(Status.QUOTA, "quota", f"{label}: quota exhausted")
    if isinstance(exc, Blocked):
        code = getattr(exc, "reason_code", "challenge") or "challenge"
        return SourceFailure(Status.BLOCKED, code, f"{label}: blocked ({code}): could not verify")
    if isinstance(exc, AuthRequired):
        if keyed:
            return SourceFailure(Status.NEEDS_KEY, "needs_key", f"{label} rejected the API key (HTTP {exc.status}): invalid key")
        return SourceFailure(Status.BLOCKED, "challenge", f"{label}: HTTP {exc.status} (keyless request refused): could not verify")
    if isinstance(exc, DeadlineExceeded):
        return SourceFailure(Status.ERROR, "timeout", f"{label}: run deadline reached: could not verify")
    if isinstance(exc, OfflineError):
        return SourceFailure(Status.UNAVAILABLE, "offline", f"{label}: offline mode (no network): could not verify")
    if isinstance(exc, NetworkError):
        timeout = "timeout" in str(exc).lower() or "timed out" in str(exc).lower()
        return SourceFailure(Status.ERROR, "timeout" if timeout else "error", f"{label}: unreachable: could not verify")
    if isinstance(exc, HttpError):
        status = getattr(exc, "status", 0)
        return SourceFailure(Status.ERROR, "error", f"{label}: HTTP {status or 'error'}: could not verify")
    return SourceFailure(Status.ERROR, "error", f"{label}: {type(exc).__name__}: could not verify")


@register
class AsnContext(Module):
    name = "asn_context"
    title = "ASN context (PeeringDB, CIRCL BGP Ranking, Shadowserver)"
    description = (
        "Who operates an ASN (PeeringDB organisation, network type, peering policy, IXPs) and how much abuse its address "
        "space shows (CIRCL BGP Ranking, context only), plus the origin AS and prefixes of an IP (Shadowserver, CIRCL)."
    )
    category = "ip_network"
    accepts = {T.ASN, T.IPV4, T.ORG}
    produces = {T.ORG, T.ASN}
    tags = {"free"}
    reference = "https://www.peeringdb.com/apidocs/"
    notice = (
        "PeeringDB data is used under its AUP for Internet operational purposes: contact (poc) objects are dropped at "
        "ingestion and never stored. CIRCL BGP Ranking is context only (large clouds and hosters always rank high): never "
        "a verdict, never above INFO, never a consensus vote. Shadowserver's keyless public API only; registering the "
        "company's own netblocks for Shadowserver reports is an institutional DPO/IT decision (docs/LEGAL.md)."
    )
    # ---- contract v2 declarations --------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "peeringdb"
    sources = SOURCES
    hosts = ("www.peeringdb.com", "bgpranking-ng.circl.lu", "api.shadowserver.org")
    access_model = "free_noauth_limited"
    optional_keys = (KEY,)
    max_requests = 5  # IPv4: origin, ipasn history, PeeringDB net + org, rank; ASN: net, org, rank, prefixes
    expected_latency = 4.0
    min_interval = 1.0  # PeeringDB's anonymous throttle: 3.5 s in its provider profile (the larger value wins)
    timeout = 60.0
    cache_ttl = 86400
    manual_link = "https://www.peeringdb.com/asn/{asn_num}"
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.IPV4:
            return is_public_ip(entity.value)
        if entity.type is T.ASN:
            n = asn_number(entity.value)
            return n is not None and not is_reserved_asn(n)
        return len(entity.value.strip()) >= 3

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        run = _Run(self.result(entity), ctx)
        allowed = set(ctx.allowed_sources or SOURCES)
        if entity.type is T.IPV4:
            self._ip(run, entity.value, allowed)
        elif entity.type is T.ASN:
            n = asn_number(entity.value)
            if n is not None:
                self._asn(run, n, allowed, pivot_operator=True)
        else:
            self._company(run, entity.value, allowed)
        return self._finish(run)

    def _query(self, run: _Run, source: str, call: str, fn: Any) -> tuple[bool, Any]:
        """One request + parse of one source -> (answered, value). A failure becomes that source's
        status (noted), never the module's (c1); answered False means 'could not verify'."""
        if run.stopped:
            run.note(source, call, Status.ERROR, "timeout", f"{SOURCE_LABELS[source]}: not queried ({run.stopped})")
            return False, None
        try:
            return True, fn()
        except (SourceFailure, RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError) as exc:
            keyed = source == SRC_PDB and bool(run.ctx.key(KEY))
            failure = _failure_of(exc, SOURCE_LABELS[source], keyed=keyed)
            if isinstance(exc, DeadlineExceeded):
                run.stopped = "run deadline reached"
            run.note(source, call, failure.status, failure.code, failure.reason)
            return False, None

    # ------------------------------------------------------------------ IPv4
    def _ip(self, run: _Run, ip: str, allowed: set[str]) -> None:
        res, ctx = run.res, run.ctx
        origin = None
        history: list[dict[str, Any]] = []
        if SRC_SS in allowed:
            ok, origin = self._query(run, SRC_SS, "origin", lambda: parse_shadowserver_origin(
                ctx.http.get_json(shadowserver_origin_url(ip), source=SRC_SS), ip))
            if ok:
                run.note(SRC_SS, "origin", Status.OK if origin else Status.EMPTY, "", "" if origin else "Shadowserver: no origin AS for this address")
        if SRC_CIRCL in allowed:
            ok, history = self._query(run, SRC_CIRCL, "ipasn", lambda: parse_ipasn_history(
                ctx.http.get_json(f"{CIRCL_API}/ipasn_history/?" + urlencode({"ip": ip}), source=SRC_CIRCL)))
            history = history or []
            if ok:
                run.note(SRC_CIRCL, "ipasn", Status.OK if history else Status.EMPTY, "",
                         "" if history else "CIRCL IPASN History: address not announced")
        asn = asn_number(origin["asn"]) if origin else (asn_number(history[0]["asn"]) if history else None)
        if history:
            res.attr("ipasn_history", history)
        if origin:
            res.attr("asn", origin["asn"])
            res.attr("as_org", origin["as_name"])
            res.attr("prefix", origin["prefix"])
        elif history:
            res.attr("asn", history[0]["asn"])
            res.attr("prefix", history[0]["prefix"])
        if asn is not None and not is_reserved_asn(asn):
            self._asn(run, asn, allowed, pivot_operator=False)

    # ------------------------------------------------------------------ ASN
    def _asn(self, run: _Run, asn: int, allowed: set[str], *, pivot_operator: bool) -> None:
        res, ctx = run.res, run.ctx
        network = None
        if SRC_PDB in allowed:
            headers = peeringdb_headers(ctx.key(KEY))
            ok, records = self._query(run, SRC_PDB, "net", lambda: peeringdb_records(
                _or_empty(ctx.http.get_json(peeringdb_net_url(asn), absent={404}, headers=headers, source=SRC_PDB))))
            record = next((r for r in records or [] if _int(r.get("asn")) == asn), None)
            if ok and record is None:
                run.note(SRC_PDB, "net", Status.EMPTY, "", f"no PeeringDB record for AS{asn}")
            elif ok and record is not None:
                org_name = ""
                org_id = _int(record.get("org_id"))
                if org_id:
                    _ok, orgs = self._query(run, SRC_PDB, "org", lambda: peeringdb_records(
                        _or_empty(ctx.http.get_json(peeringdb_org_url(org_id), absent={404}, headers=headers, source=SRC_PDB))))
                    org_name = next((_text(o.get("name")) for o in orgs or [] if _int(o.get("id")) == org_id), "")
                network = parse_peeringdb_net(record, org_name)
                run.note(SRC_PDB, "net", Status.OK)
        if SRC_SS in allowed and pivot_operator:
            ok, prefixes = self._query(run, SRC_SS, "prefix", lambda: parse_shadowserver_prefixes(
                ctx.http.get_json(shadowserver_prefix_url(asn), source=SRC_SS)))
            if ok:
                run.note(SRC_SS, "prefix", Status.OK if prefixes else Status.EMPTY, "", "" if prefixes else "Shadowserver: no announced prefixes")
            if prefixes:
                v4 = sum(1 for p in prefixes if ":" not in p)
                res.attr("announced_prefixes", prefixes[:PREFIX_CAP])
                res.attr("announced_prefix_counts", {"total": len(prefixes), "ipv4": v4, "ipv6": len(prefixes) - v4, "pivoted": 0,
                                                     "capped": len(prefixes) > PREFIX_CAP, "truncated": False})
        rank = None
        if SRC_CIRCL in allowed:
            ok, rank = self._query(run, SRC_CIRCL, "rank", lambda: parse_circl_rank(
                ctx.http.post_json(f"{CIRCL_API}/json/asn", json_body={"asn": str(asn)}, ttl=self.cache_ttl, source=SRC_CIRCL), asn))
            if ok:
                run.note(SRC_CIRCL, "rank", Status.OK if rank else Status.EMPTY, "", "" if rank else f"CIRCL BGP Ranking: AS{asn} not ranked that day")
        if network is not None:
            self._network(run, asn, network, pivot_operator=pivot_operator)
        if rank is not None:
            self._rank(run, rank)

    def _network(self, run: _Run, asn: int, net: dict[str, Any], *, pivot_operator: bool) -> None:
        res = run.res
        res.attr("peeringdb_network", net)
        if pivot_operator:  # for an IP the AS operator is the network provider, not the user of the address
            res.attr("as_org", net["operator"])
        res.attr("network_type", NETWORK_TYPE.get(net["network_class"]))
        res.attr("website", net["website"])
        if pivot_operator and net["operator"]:
            res.pivot(T.ORG, net["operator"], "operated_by", confidence="probable", expand=False,
                      note="PeeringDB organisation of the AS (self-declared): free-text name, homonym-prone, not expanded")
        ixps = [i["name"].split(":")[0].strip() for i in net["ixps"] if i["name"]]
        ix_text = f"{net['ix_count'] or 0} IXP(s)" + (f" incl. {', '.join(sorted(set(ixps))[:5])}" if ixps else "")
        res.finding(
            "ASN operator and network type (PeeringDB)",
            "info",
            f"AS{asn} is operated by {net['operator'] or 'an unnamed organisation'} ({net['info_type'] or 'type not disclosed'}; "
            f"peering policy {net['policy']['general'] or 'not stated'}; {ix_text}; {net['fac_count'] or 0} facility(ies)). "
            "Self-declared by the network operator.",
            data={"asn": f"AS{asn}", "operator": net["operator"], "network_class": net["network_class"], "policy": net["policy"]["general"],
                  "ix_count": net["ix_count"], "fac_count": net["fac_count"]},
            tags=["infrastructure", "context_only"],
            source=SRC_PDB,
            observed_last=net["updated"] or None,
        )

    def _rank(self, run: _Run, rank: dict[str, Any]) -> None:
        res, ctx = run.res, run.ctx
        rank = dict(rank, checked_on=ctx.now().date().isoformat())
        res.attr("bgp_ranking", rank)
        res.finding(
            "ASN reputation context (CIRCL BGP Ranking)",
            "info",  # c4: never above INFO
            f"{rank['asn']}: {rank['text']} on {rank['checked_on']}. {RANK_EXPLANATION}",
            confidence="possible",
            data={k: rank[k] for k in ("asn", "percentile", "position", "total_known_asns", "rank_score", "checked_on")},
            tags=["context_only", "info"],  # c4: never a consensus vote (P171)
            source=SRC_CIRCL,
        )

    # ------------------------------------------------------------------ company name
    def _company(self, run: _Run, name: str, allowed: set[str]) -> None:
        res, ctx = run.res, run.ctx
        if SRC_PDB not in allowed:
            return
        headers = peeringdb_headers(ctx.key(KEY))
        ok, records = self._query(run, SRC_PDB, "search", lambda: peeringdb_records(
            _or_empty(ctx.http.get_json(peeringdb_search_url(name.strip()[:64]), absent={404}, headers=headers, source=SRC_PDB))))
        if not ok:
            return
        candidates = []
        for rec in records or []:
            n = asn_number(rec.get("asn"))
            if not n or is_reserved_asn(n):
                continue
            candidates.append({"asn": f"AS{n}", "name": _text(rec.get("name")), "aka": _text(rec.get("aka")),
                               "info_type": _text(rec.get("info_type"), 60),
                               "network_class": network_class(rec.get("info_type"), rec.get("info_types"))})
            if len(candidates) >= CANDIDATE_CAP:
                break
        if not candidates:
            run.note(SRC_PDB, "search", Status.EMPTY, "", "no PeeringDB network name contains it")
            return
        run.note(SRC_PDB, "search", Status.OK)
        res.attr("network_candidates", {"match": "name contains (PeeringDB)", "confidence": "possible", "candidates": candidates})
        for cand in candidates:
            res.pivot(T.ASN, cand["asn"], "asn_candidate", confidence="possible", expand=False,
                      note=f"PeeringDB network name '{cand['name'][:60]}' contains the company name: confirm the holder before use")

    # ------------------------------------------------------------------ outcome bookkeeping
    def _finish(self, run: _Run) -> ModuleResult:
        """c1: one status per source; the run is OK when any source gave data, EMPTY when the sources
        that answered found nothing, and takes the first failure only when no source answered."""
        res = run.res
        per_source: dict[str, tuple[Status, str, str]] = {}
        for source, items in run.outcomes.items():
            oks = [i for i in items if i[1] is Status.OK]
            fails = [i for i in items if i[1] not in (Status.OK, Status.EMPTY)]
            if oks:
                partial = f"answered; {fails[0][3]}" if fails else ""
                per_source[source] = (Status.OK, "", partial)
            elif fails:
                _call, status, code, reason = fails[0]
                per_source[source] = (status, code, reason)
            else:
                per_source[source] = (Status.EMPTY, "", next((i[3] for i in items if i[3]), ""))
        for source in SOURCES:
            if source in per_source:
                status, code, reason = per_source[source]
                res.source_status(source, status, reason_code=code, reason=reason or f"{SOURCE_LABELS[source]}: answered")
        used = [s for s, (st, _c, _r) in per_source.items() if st is Status.OK]
        if used:
            res.attr("data_attribution", "; ".join(ATTRIBUTIONS[s] for s in SOURCES if s in used))
        res.raw = {"sources": {s: {"status": st.value, "reason_code": c, "reason": r} for s, (st, c, r) in per_source.items()}}
        answered = [s for s, (st, _c, _r) in per_source.items() if st in (Status.OK, Status.EMPTY)]
        if run.stopped and answered:
            res.stop("deadline")
        if res.has_data:
            return res
        if answered:
            reasons = [r for s, (st, _c, r) in per_source.items() if st is Status.EMPTY and r]
            return res.mark(Status.EMPTY, "; ".join(reasons) or "no ASN context found")
        failures = [per_source[s] for s in SOURCES if s in per_source]
        if not failures:
            return res.mark(Status.SKIPPED, "no ASN context source allowed in this run", reason_code="policy")
        status, code, reason = failures[0]
        more = f" (+{len(failures) - 1} more source(s) could not verify)" if len(failures) > 1 else ""
        return res.mark(status, reason + more, reason_code=code)
