"""ip_anonymizer_consensus: VPN / proxy / hosting votes of independent keyless providers (P046).

Batch p2-G02-2, proposal P046. Final conditions implemented here:

* c1 - every provider (registry sources ``ipquery.api``, ``iplocate.api``, ``vpndetection.api``,
  ``proxycheck.api``) is terms 'unknown' and tier unknown until legal reviews it: the module is
  ``default_enabled=False`` (A3), the licence gate keeps 'unknown' sources disabled in every profile
  and the tier gate excludes it at AMBER and above (``--allow-unknown`` at CLEAR/GREEN).
* c2 - IPLogs is excluded (it advertises active probing of the queried IPs): never wired, no host.
* c3 - ``run_on='seeds'``: only analyst-typed seeds (never pivots or IPs extracted from text, logs
  or e-mails; the policy gate enforces it and the module re-checks); never bogon, CDN or cloud-range
  IPs (noise lists and the P034 local range files); org-network and subject IPs (personal data) get
  the offline datasets only.
* c4 - offline lists answer first (core noise lists, the P034 cloud ranges and the P040 Tor exit
  list, read from their local copies only): online votes are asked only when they are silent. At
  most 4 providers are wired (:data:`ASK_ORDER`), each with its own fixture, per-source status and
  1 req/s (``min_interval``); answers are cached 24 h; the optional keys ``iplocate`` and
  ``proxycheck`` are registered in their provider fragments (``config.key_registry``).
* c5 - ONE shared vote helper (:func:`vote_tally`, :func:`vote_should_stop`,
  :func:`dedupe_families`, :func:`format_value_votes`; also for ip_geolocation, P051). Providers are
  asked one at a time and asking stops once 3 agree or 3 agreeing answers become impossible;
  providers sharing a backend count once (:data:`FAMILIES`: VPNDetection and InternetData).
* c6 - a verdict needs >= 3 answered, agreeing, independent providers; fewer answers give the
  attribute ``anonymizer_votes``, status ok and the wording 'inconclusive (insufficient votes)',
  never 'not a VPN' or 'clean'; failed providers are listed as could not verify.
* c7 - ONE output line ('VPN: 3 of 4 providers (...); hosting: 4/4'); verdicts are context tags
  (``vpn``, ``proxy``, ``hosting``) for CR28, never ``malicious``.
* c8 - the P331 declarative collector: the four adapters are plain GET JSON lookups with a literal
  host (:data:`ADAPTERS`), so each maps onto a ``v3lum.spec/1`` request; the vote itself needs
  Python (one request per provider decided by the previous answers), which a spec cannot express.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from v3lum.core import http as _http
from v3lum.core import noise
from v3lum.core.datasets import DatasetError, DataStore
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

VOTE_CATEGORIES: tuple[str, ...] = ("vpn", "proxy", "hosting")  # verdict tags (c7); tor stays with the P040 lists
VOTE_NEED = 3  # c6
VOTE_LABELS = {"vpn": "VPN", "proxy": "proxy", "hosting": "hosting", "tor": "Tor"}
INCONCLUSIVE = "inconclusive (insufficient votes)"
#: c5: providers sharing a backend count once (InternetData is VPNDetection's sibling; not wired, c4).
FAMILIES = {"vpndetection": "vpndetection", "internetdata": "vpndetection", "ipquery": "ipquery", "iplocate": "iplocate",
            "ipapiis": "ipapiis", "proxycheck": "proxycheck"}
EXCLUDED = {"iplogs": "advertises active probing of queried IPs (response field 'probed'): excluded (P046 c2)"}
#: c3: noise kinds of shared infrastructure (CDN, cloud, hosting, SaaS edges, public resolvers).
SHARED_KINDS = frozenset({"cdn", "cloud", "hosting", "saas", "resolver"})


@dataclass(frozen=True)
class Adapter:
    """One wired provider (c4, c8): a GET JSON lookup with a literal host."""

    id: str
    name: str
    source: str
    url: str
    params: dict[str, str] = field(default_factory=dict)
    key_name: str = ""
    key_param: str = ""


ADAPTERS: dict[str, Adapter] = {
    "ipquery": Adapter("ipquery", "IPQuery", "ipquery.api", "https://api.ipquery.io/{ip}", {"format": "json"}),
    "iplocate": Adapter("iplocate", "IPLocate", "iplocate.api", "https://iplocate.io/api/lookup/{ip}", key_name="iplocate", key_param="apikey"),
    "vpndetection": Adapter("vpndetection", "VPNDetection", "vpndetection.api", "https://api.vpndetection.io/{ip}"),
    "proxycheck": Adapter("proxycheck", "proxycheck.io", "proxycheck.api", "https://proxycheck.io/v2/{ip}",
                          {"vpn": "1", "asn": "1", "risk": "1"}, key_name="proxycheck", key_param="key"),
}
ASK_ORDER: tuple[str, ...] = ("ipquery", "iplocate", "vpndetection", "proxycheck")  # c4: at most 4 wired

# --------------------------------------------------------------------------------------
# the shared vote helper (c5-c7; also used by ip_geolocation, P051)
# --------------------------------------------------------------------------------------


def answer(provider: str, name: str, votes: dict[str, Any], *, family: str = "", **details: Any) -> dict[str, Any]:
    """One provider's vote. ``votes`` maps category -> True/False (or a categorical value such as
    a country for P051); None = no opinion. An answer without any vote is not 'answered'."""
    out = {"provider": provider, "name": name, "family": family or FAMILIES.get(provider, provider), "answered": True,
           "votes": {k: v for k, v in votes.items()}, "reason": "", "status": Status.OK.value, "reason_code": ""}
    out.update(details)
    if not any(v is not None for v in out["votes"].values()):
        out.update(answered=False, status=Status.ERROR.value, reason_code="error", reason=out.get("reason") or f"{name}: no usable flags")
    return out


def failed(provider: str, name: str, status: Status, code: str, reason: str, *, family: str = "") -> dict[str, Any]:
    """A provider that could not be verified (listed as such, never as a 'no' vote, c6)."""
    return {"provider": provider, "name": name, "family": family or FAMILIES.get(provider, provider), "answered": False,
            "votes": {}, "reason": reason, "status": status.value, "reason_code": code}


def dedupe_families(answers: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Keep the first ANSWERED provider of each family (c5). Returns (kept, deduplicated names); a
    failed provider whose family answered through a sibling is not 'could not verify'."""
    seen: set[str] = set()
    kept: list[dict[str, Any]] = []
    dropped: list[str] = []
    for a in answers or []:
        if not isinstance(a, dict):
            continue
        fam = str(a.get("family") or a.get("provider"))
        if a.get("answered"):
            if fam in seen:
                dropped.append(str(a.get("name")))
                continue
            seen.add(fam)
        kept.append(a)
    kept = [a for a in kept if a.get("answered") or str(a.get("family") or a.get("provider")) not in seen]
    return kept, dropped


def vote_should_stop(answers: list[dict[str, Any]], remaining: int, categories: tuple[str, ...] = VOTE_CATEGORIES,
                     need: int = VOTE_NEED) -> bool:
    """Ask providers one at a time (c5): stop once every category has ``need`` agreeing answers or
    can no longer reach ``need`` with the ``remaining`` independent providers. Works for boolean
    votes (P046) and categorical ones (country/ASN, P051)."""
    kept, _ = dedupe_families(answers)
    for cat in categories:
        counts = Counter(a["votes"].get(cat) for a in kept if a.get("answered") and a.get("votes", {}).get(cat) is not None)
        best = max(counts.values(), default=0)
        if best >= need:
            continue
        if best + max(int(remaining or 0), 0) >= need:
            return False
    return True


def vote_tally(answers: list[dict[str, Any]], categories: tuple[str, ...] = VOTE_CATEGORIES, need: int = VOTE_NEED,
               labels: dict[str, str] | None = None) -> dict[str, Any]:
    """c5-c7: a verdict needs >= ``need`` answered, agreeing, independent providers; fewer answers give
    'inconclusive (insufficient votes)', never 'not a VPN' or 'clean'. Returns the tally (the
    attribute ``anonymizer_votes``) with its ONE output ``line`` and the verdict ``tags``."""
    labels = labels or VOTE_LABELS
    kept, deduped = dedupe_families(answers)
    answered = [a for a in kept if a.get("answered")]
    failures = [f"{a.get('name')} ({_short_reason(a)})" for a in kept if not a.get("answered")]
    out: dict[str, Any] = {
        "answered": len(answered), "asked": len(kept), "providers": [a.get("name") for a in answered],
        "could_not_verify": failures, "deduplicated": deduped, "need": need, "inconclusive": len(answered) < need,
        "categories": {}, "tags": [], "malicious": False,
    }
    for cat in categories:
        votes = [(a.get("name"), a["votes"].get(cat)) for a in answered if a.get("votes", {}).get(cat) is not None]
        counts = Counter(v for _, v in votes)
        value, best = counts.most_common(1)[0] if counts else (None, 0)
        verdict = value if best >= need and not out["inconclusive"] else None
        out["categories"][cat] = {
            "voters": len(votes), "values": {str(k): n for k, n in counts.items()},
            "agreeing": [n for n, v in votes if v == value] if verdict is not None else [],
            "true": [n for n, v in votes if v is True], "verdict": verdict,
        }
        if verdict is True:
            out["tags"].append(cat)
    out["line"] = format_vote_line(out, labels)
    return out


def format_vote_line(tally: dict[str, Any], labels: dict[str, str] | None = None) -> str:
    """ONE output line (c7), e.g. 'VPN: 3 of 4 providers (VPNDetection, IPQuery, IPLocate); proxy: 0/3; hosting: 4/4'."""
    labels = labels or VOTE_LABELS
    tail = f"; could not verify: {', '.join(tally['could_not_verify'])}" if tally.get("could_not_verify") else ""
    if tally.get("inconclusive"):
        return f"{INCONCLUSIVE}: {tally.get('answered', 0)} of {tally.get('asked', 0)} providers answered{tail}"
    parts = []
    for cat, c in (tally.get("categories") or {}).items():
        label = labels.get(cat, cat)
        if c["voters"] < tally.get("need", VOTE_NEED):
            parts.append(f"{label}: inconclusive ({c['voters']} votes)")
        elif c["verdict"] is True:
            parts.append(f"{label}: {len(c['true'])} of {c['voters']} providers ({', '.join(c['true'])})")
        else:
            parts.append(f"{label}: {len(c['true'])}/{c['voters']}")
    return "; ".join(parts) + tail


def format_value_votes(tally: dict[str, Any], category: str) -> str | None:
    """Categorical form for P051 (country/ASN): 'BR - 3/3 providers', or None without a verdict."""
    c = (tally or {}).get("categories", {}).get(category)
    if not c or c.get("verdict") is None:
        return None
    return f"{c['verdict']} - {len(c['agreeing'])}/{c['voters']} providers"


def _short_reason(a: dict[str, Any]) -> str:
    text = str(a.get("reason") or a.get("status") or "no answer")
    name = str(a.get("name") or "")
    if name and text.startswith(f"{name}: "):
        text = text[len(name) + 2:]
    return text[:160]


# --------------------------------------------------------------------------------------
# provider parsers (untrusted answers: every field type-checked)
# --------------------------------------------------------------------------------------


def _d(obj: Any, key: str) -> dict[str, Any]:
    value = obj.get(key) if isinstance(obj, dict) else None
    return value if isinstance(value, dict) else {}


def _b(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _s(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _asn(value: Any) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return f"AS{value}" if 0 < value < 2**32 else None
    if isinstance(value, str):
        text = value.strip().upper().split(" ", 1)[0]
        digits = text[2:] if text.startswith("AS") else text
        return f"AS{int(digits)}" if digits.isdigit() and 0 < int(digits) < 2**32 else None
    return None


def _norm_ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _hosting_from_asn_type(asn: dict[str, Any]) -> bool | None:
    kind = asn.get("type")
    return kind.strip().lower() == "hosting" if isinstance(kind, str) and kind.strip() else None


def parse_ipquery(doc: Any) -> dict[str, Any]:
    """IPQuery: risk.is_vpn / is_proxy / is_tor / is_datacenter (-> hosting)."""
    if not isinstance(doc, dict) or isinstance(doc.get("error"), (str, dict)):
        return failed("ipquery", "IPQuery", Status.ERROR, "error", f"IPQuery: {_error_text(doc)}")
    risk, isp = _d(doc, "risk"), _d(doc, "isp")
    return answer("ipquery", "IPQuery",
                  {"vpn": _b(risk.get("is_vpn")), "proxy": _b(risk.get("is_proxy")), "hosting": _b(risk.get("is_datacenter"))},
                  tor=_b(risk.get("is_tor")), asn=_asn(isp.get("asn")), as_org=_s(isp.get("org")),
                  country=_s(_d(doc, "location").get("country_code")))


def parse_iplocate(doc: Any) -> dict[str, Any]:
    """IPLocate: privacy.is_vpn / is_proxy / is_tor / is_hosting."""
    if not isinstance(doc, dict) or isinstance(doc.get("error"), (str, dict)):
        return failed("iplocate", "IPLocate", Status.ERROR, "error", f"IPLocate: {_error_text(doc)}")
    privacy, asn = _d(doc, "privacy"), _d(doc, "asn")
    if privacy.get("is_bogon") is True:
        return failed("iplocate", "IPLocate", Status.ERROR, "error", "IPLocate: answered 'bogon' for a public address: could not verify")
    return answer("iplocate", "IPLocate",
                  {"vpn": _b(privacy.get("is_vpn")), "proxy": _b(privacy.get("is_proxy")), "hosting": _b(privacy.get("is_hosting"))},
                  tor=_b(privacy.get("is_tor")), asn=_asn(asn.get("asn")), as_org=_s(asn.get("name")), country=_s(doc.get("country_code")))


def parse_vpndetection(doc: Any) -> dict[str, Any]:
    """VPNDetection: is_vpn, is_tor and asn.type == 'hosting' (no proxy flag on the free tier)."""
    if not isinstance(doc, dict) or isinstance(doc.get("error"), (str, dict)):
        return failed("vpndetection", "VPNDetection", Status.ERROR, "error", f"VPNDetection: {_error_text(doc)}")
    if doc.get("is_bogon") is True:
        return failed("vpndetection", "VPNDetection", Status.ERROR, "error", "VPNDetection: answered 'bogon' for a public address: could not verify")
    asn = _d(doc, "asn")
    return answer("vpndetection", "VPNDetection",
                  {"vpn": _b(doc.get("is_vpn")), "proxy": None, "hosting": _hosting_from_asn_type(asn)},
                  tor=_b(doc.get("is_tor")), asn=_asn(asn.get("asn")), as_org=_s(asn.get("name")),
                  country=_s(_d(doc, "location").get("country")))


_PC_VPN = frozenset({"vpn", "openvpn", "wireguard"})
_PC_TOR = frozenset({"tor"})
_PC_HOSTING = frozenset({"hosting", "data center", "datacenter"})
_PC_NOT_HOSTING = frozenset({"residential", "wireless", "business", "mobile"})


def parse_proxycheck(doc: Any, ip: str) -> dict[str, Any]:
    """proxycheck.io v2: the record is keyed by the IP as sent (matched by normalised IP); proxy
    yes/no plus type (VPN, TOR, SOCKS..., Hosting, Business, Residential). Errors inside HTTP 200
    bodies are classified by the provider's error markers before this runs."""
    if not isinstance(doc, dict):
        return failed("proxycheck", "proxycheck.io", Status.ERROR, "error", "proxycheck.io: unexpected answer")
    status = doc.get("status")
    if status not in ("ok", "warning"):
        return failed("proxycheck", "proxycheck.io", Status.ERROR, "error", f"proxycheck.io: status {str(status)[:40]!r} ({_error_text(doc)})")
    want = _norm_ip(ip)
    record = next((v for k, v in doc.items() if isinstance(v, dict) and _norm_ip(k) is not None and _norm_ip(k) == want), None)
    if record is None:
        return failed("proxycheck", "proxycheck.io", Status.ERROR, "error", "proxycheck.io: no record for the queried IP")
    proxy = record.get("proxy")
    kind = record.get("type").strip().lower() if isinstance(record.get("type"), str) else ""
    votes: dict[str, Any] = {"vpn": None, "proxy": None, "hosting": None}
    tor: bool | None = None
    if kind in _PC_HOSTING:
        votes["hosting"] = True
    elif kind in _PC_NOT_HOSTING:
        votes["hosting"] = False
    if proxy == "no":
        votes.update(vpn=False, proxy=False)
        tor = False
    elif proxy == "yes":
        votes["vpn"] = kind in _PC_VPN
        tor = kind in _PC_TOR
        votes["proxy"] = not (kind in _PC_VPN or kind in _PC_TOR)
    return answer("proxycheck", "proxycheck.io", votes, tor=tor, asn=_asn(record.get("asn")), as_org=_s(record.get("provider")),
                  country=_s(record.get("isocode")), type=_s(record.get("type")))


PARSERS = {"ipquery": parse_ipquery, "iplocate": parse_iplocate, "vpndetection": parse_vpndetection}


def _error_text(doc: Any) -> str:
    if isinstance(doc, dict):
        for key in ("error", "message"):
            value = doc.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()[:120]
            if isinstance(value, dict) and isinstance(value.get("message"), str):
                return str(value["message"])[:120]
    return f"unexpected answer ({type(doc).__name__})"


def _failure(exc: BaseException) -> tuple[Status, str] | None:
    """Per-provider 'could not verify' (rule 5); None for what must propagate (kill switch,
    request cap, run deadline, policy and configuration refusals)."""
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


# --------------------------------------------------------------------------------------
# offline answers first (c3, c4): local copies only, never a download
# --------------------------------------------------------------------------------------

_TOR_MEMO: dict[str, Any] = {"key": None, "exits": frozenset()}


def offline_answer(entity: Entity) -> str:
    """Why the offline lists already answer for this address ('' when they are silent).

    Shared CDN/cloud/hosting/resolver infrastructure (core noise lists and the P034 range files)
    and current Tor exits (P040 bulk list) are answered offline; the online providers never see
    those addresses (c3, c4). Only local copies are read (no download, no network)."""
    kinds = sorted(noise.noise_kinds(entity) & SHARED_KINDS)
    if kinds:
        return f"shared {'/'.join(kinds)} infrastructure (noise lists): offline answer only"
    label = _cloud_label(entity.value)
    if label:
        return f"CDN/cloud range ({label}, P034 range files): offline answer only"
    if _tor_exit(entity.value):
        return "current Tor exit (P040 bulk exit list): offline answer, online votes not asked"
    return ""


def _cloud_label(ip: str) -> str:
    try:
        from v3lum.modules.ip_network.cloud_ranges import local_classification
    except ImportError:  # the P034 module is not installed: the list is silent
        return ""
    try:
        found = local_classification(ip)
    except (DatasetError, OSError, ValueError, KeyError, TypeError):
        return ""
    if not isinstance(found, dict) or not found.get("is_cloud"):
        return ""
    return str(found.get("label") or found.get("provider") or "cloud provider")[:80]


def _tor_exit(ip: str) -> bool:
    try:
        from v3lum.modules.ip_network.tor_exit_local import BULK_EXIT_LIST, parse_bulk_exit_list
    except ImportError:
        return False
    try:
        path = Path(DataStore(None).scoped().fetch(BULK_EXIT_LIST))  # local copy only: no runtime, no download
        stat = path.stat()
    except (DatasetError, OSError, ValueError):
        return False
    key = (str(path), stat.st_mtime_ns, stat.st_size)
    if _TOR_MEMO["key"] != key:
        exits, _invalid = parse_bulk_exit_list(path.read_text(encoding="utf-8", errors="replace"))
        _TOR_MEMO.update(key=key, exits=exits)
    return ip in _TOR_MEMO["exits"]


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class IpAnonymizerConsensus(Module):
    name = "ip_anonymizer_consensus"
    title = "Anonymizer consensus (VPN/proxy/hosting votes)"
    description = (
        "VPN, proxy and hosting verdicts for an analyst-typed IP from up to four independent keyless providers "
        "(IPQuery, IPLocate, VPNDetection, proxycheck.io), asked one at a time; a verdict needs 3 agreeing answers."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6}
    produces = frozenset()
    run_on = "seeds"
    tags = {"free"}
    reference = "https://proxycheck.io/api/"
    notice = (
        "Every provider is terms 'unknown' and tier unknown until legal reviews it (P046 c1): disabled in every profile, "
        "excluded at TLP:AMBER and above. Analyst-typed seeds only; never bogon, CDN/cloud or org-network/subject IPs "
        "(offline datasets only). IPLogs is excluded (active probing). Verdicts are context tags, never 'malicious'; "
        "fewer than 3 agreeing answers read 'inconclusive (insufficient votes)'."
    )
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "ipquery"
    sources = tuple(ADAPTERS[p].source for p in ASK_ORDER)
    hosts = ("api.ipquery.io", "iplocate.io", "api.vpndetection.io", "proxycheck.io")
    access_model = "free_noauth_limited"
    optional_keys = ("iplocate", "proxycheck")
    max_requests = 4
    expected_latency = 2.0
    timeout = 30.0
    min_interval = 1.0  # c4: 1 req/s per provider host
    cache_ttl = 86400  # c4: 24 h
    max_pivots = 0
    default_enabled = False  # unknown terms and tier (A3)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return noise.is_public_ip(entity.value)  # bogons are never sent (c3)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        ip = _norm_ip(entity.value) or entity.value
        addr = ipaddress.ip_address(ip)
        if addr.version == 6 and addr.ipv4_mapped is not None:
            ip = str(addr.ipv4_mapped)
        if not ctx.is_seed or ctx.depth > 0 or ctx.provenance:
            return res.mark(Status.SKIPPED, "run_on=seeds: pivots and extracted IPs are never sent to these providers (P046 c3)", reason_code="policy")
        why_private = _personal(entity, ctx)
        if why_private:
            return res.mark(Status.SKIPPED, f"{why_private}: offline datasets only (P046 c3)", reason_code="privacy")
        offline = offline_answer(entity)
        if offline:
            return res.mark(Status.SKIPPED, offline, reason_code="not_applicable")
        order = [p for p in ASK_ORDER if ADAPTERS[p].source in ctx.allowed_sources]
        if not order:
            return res.mark(Status.SKIPPED, "no provider allowed under the licence profile (terms 'unknown' until legal records them)", reason_code="licence")
        answers: list[dict[str, Any]] = []
        for i, pid in enumerate(order):
            if answers and vote_should_stop(answers, remaining=len(order) - i):
                break  # c5: 3 agree on every category, or 3 agreeing answers became impossible
            if ctx.cancelled():
                break
            ans = self._ask(ctx, ADAPTERS[pid], ip)
            answers.append(ans)
            if ans.get("answered"):
                res.source_status(ADAPTERS[pid].source, Status.OK)
            else:
                res.source_status(ADAPTERS[pid].source, Status(ans["status"]), reason_code=ans["reason_code"], reason=ans["reason"][:300])
        tally = vote_tally(answers)
        tally["details"] = [{k: v for k, v in a.items() if k in ("name", "answered", "votes", "tor", "asn", "country", "type", "reason")}
                            for a in answers]
        res.raw = {"answers": tally["details"], "line": tally["line"]}
        if not tally["answered"]:
            first = next((a for a in answers if not a.get("answered")), None)
            status, code = (Status(first["status"]), first["reason_code"]) if first else (Status.ERROR, "error")
            res.attr("anonymizer_votes", tally)
            return res.mark(status, f"no provider answered: {tally['line']}", reason_code=code)
        res.attr("anonymizer_votes", tally)
        for cat, attr in (("vpn", "is_vpn"), ("proxy", "is_proxy"), ("hosting", "is_hosting")):
            if tally["categories"][cat]["verdict"] is True:
                res.attr(attr, True)
        verdict = bool(tally["tags"])
        tags = list(tally["tags"]) + (["anonymizer"] if {"vpn", "proxy"} & set(tally["tags"]) else []) + ["context_only"]
        res.finding(
            "Anonymizer votes (VPN/proxy/hosting)",
            "info",
            tally["line"],
            confidence="probable" if verdict else "possible",
            data={k: tally[k] for k in ("answered", "asked", "providers", "could_not_verify", "deduplicated", "need", "inconclusive", "categories")},
            tags=tags,
            source=ADAPTERS[order[0]].source,
        )
        return res

    def _ask(self, ctx: Any, adapter: Adapter, ip: str) -> dict[str, Any]:
        params = dict(adapter.params)
        if adapter.key_name and adapter.key_param:
            key = str(ctx.key(adapter.key_name) or "").strip()
            if key:
                params[adapter.key_param] = key
        url = adapter.url.format(ip=ip)
        try:
            doc = ctx.http.get_json(url, params=params or None, source=adapter.source)
        except Exception as exc:  # noqa: BLE001 - per-provider rule 5, the rest propagates
            mapped = _failure(exc)
            if mapped is None:
                raise
            return failed(adapter.id, adapter.name, mapped[0], mapped[1], f"{adapter.name}: {str(exc)[:160] or type(exc).__name__}")
        if adapter.id == "proxycheck":
            return parse_proxycheck(doc, ip)
        return PARSERS[adapter.id](doc)


def _personal(entity: Entity, ctx: Any) -> str:
    """c3: org-network addresses (employees) and analysed subjects (customers, victims) are personal
    data: they never reach these providers."""
    org = getattr(ctx, "org", None)
    try:
        owned = org.owns(entity) if org is not None and not getattr(org, "is_empty", True) else None
    except Exception:  # noqa: BLE001 - an unreadable profile never sends a value out
        return "organisation profile unreadable"
    if owned is not None and getattr(owned, "own", False):
        return "address of the organisation's own network (employees/customers)"
    roles = getattr(getattr(ctx, "options", None), "subject_roles", None) or {}
    if isinstance(roles, dict) and (roles.get(entity.key) or roles.get(entity.value)):
        return "address of an analysed subject (customer/victim)"
    return ""
