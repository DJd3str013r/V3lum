"""SecurityTrails (P006): current DNS, subdomains and A-record history of a seed domain (keyed).

Final conditions (council #1, P006) and where they live:

1. Key ``securitytrails`` (provider fragment ``securitytrails.json``), sent in the ``APIKEY`` header
   (:meth:`SecurityTrails._get`); without it NEEDS_KEY before the run.
2. Key-terms: under the corporate profile the licence gate runs it only with ``key_plans.securitytrails =
   'business'`` or a recorded ``free_plan_business_use`` (company/team account).
3. Endpoints: ``/v1/domain/{domain}``, ``/v1/domain/{domain}/subdomains`` and ``/v1/history/{domain}/dns/a``
   (:data:`BASE`). Subdomain labels come back without the apex: the apex is appended and every name goes
   through the shared P001 hostname sink (``ct_logs.HostnameSink``); ``*.x`` labels are wildcards, never
   names.
4. ``run_on='seeds'``; the monthly window is the provider quota block (P334, 80% of the plan); cache 7 days.
5. Every historical record keeps first_seen/last_seen (attribute ``dns_history_a``); old A records are
   never current infrastructure (relation ``historical_a_record``, ``expand=False``). Origin-IP hypotheses
   (historical non-CDN addresses of a CDN-fronted domain) stay INFO, tagged ``cdn_origin_hypothesis`` and
   unconfirmed; confirming them with Host-header requests is ACTIVE and not part of this module.
6. 429 and quota bodies give RATE_LIMITED / QUOTA (P321 markers, :attr:`SecurityTrails.error_markers`);
   401/403 give NEEDS_KEY 'invalid key'; never EMPTY.
7. The web UI is behind Cloudflare: manual pivot link only (``manual_link``), never fetched.
8. Fixtures: the real 401 answer; trimmed real /domain and /history answers captured with the team key are
   still owed (merge gate, docs/backlog/p2-G01-1.md).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any

from v3lum.core import noise
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.domain_dns.ct_logs import HostnameSink

SOURCE = "securitytrails.api"
HOST = "api.securitytrails.com"
BASE = "https://api.securitytrails.com/v1"
KEY_NAME = "securitytrails"
#: names kept in the attribute / pivoted per run
MAX_SUBDOMAINS = 500
MAX_SUBDOMAIN_PIVOTS = 50
MAX_HISTORY = 100
MAX_HISTORY_PIVOTS = 20
NOT_FOUND_RE = re.compile(r"(?i)not found|no (?:records|data)")

_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})")


class _Unusable(Exception):
    """An answer that is not the documented format: could not verify."""


class _Absent(Exception):
    """404 'not found': SecurityTrails has no record of the domain."""


def _text(value: Any, limit: int = 300) -> str:
    if value is None or isinstance(value, (dict, list, bool)):
        return ""
    return re.sub(r"\s+", " ", _CTRL_RE.sub("", str(value))).strip()[:limit]


def _date(value: Any) -> str | None:
    m = _DATE_RE.match(_text(value, 40))
    return m.group(1) if m else None


def _values(block: Any, key: str) -> list[str]:
    vals = block.get("values") if isinstance(block, Mapping) else None
    return [_text(v.get(key), 300) for v in vals if isinstance(v, Mapping) and _text(v.get(key), 300)] if isinstance(vals, list) else []


def _ip(value: str, version: int) -> str | None:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    return str(addr) if addr.version == version else None


def _host(value: str) -> str | None:
    ent = Entity.try_make(T.DOMAIN, value.strip().rstrip("."))
    return str(ent.value) if ent is not None and "." in str(ent.value) else None


def parse_domain(doc: Any) -> dict[str, Any] | None:
    """/v1/domain/{domain} -> {a, aaaa, mx, ns, txt, first_seen {type: date}, subdomain_count} or None.

    The SOA e-mail is never read (contact data the investigation does not need)."""
    if not isinstance(doc, Mapping) or not isinstance(doc.get("current_dns"), Mapping):
        return None
    cur = doc["current_dns"]
    out: dict[str, Any] = {
        "a": [ip for ip in (_ip(v, 4) for v in _values(cur.get("a"), "ip")) if ip],
        "aaaa": [ip for ip in (_ip(v, 6) for v in _values(cur.get("aaaa"), "ipv6")) if ip],
        "mx": [h for h in (_host(v) for v in _values(cur.get("mx"), "hostname")) if h],
        "ns": [h for h in (_host(v) for v in _values(cur.get("ns"), "nameserver")) if h],
        "txt": [v[:500] for v in _values(cur.get("txt"), "value")][:50],
        "first_seen": {},
        "subdomain_count": None,
    }
    for rtype in ("a", "aaaa", "mx", "ns", "txt"):
        block = cur.get(rtype)
        if isinstance(block, Mapping) and _date(block.get("first_seen")):
            out["first_seen"][rtype] = _date(block.get("first_seen"))
    count = doc.get("subdomain_count")
    out["subdomain_count"] = count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else None
    return out


def parse_subdomains(doc: Any, apex: str) -> dict[str, Any] | None:
    """/v1/domain/{domain}/subdomains -> {names, wildcards, rejected, limit_reached, subdomain_count} or None.

    Labels come without the apex (cond 3): the apex is appended and each name goes through the shared
    P001 hostname sink, which validates it and files '*.x' labels as wildcards."""
    if not isinstance(doc, Mapping) or not isinstance(doc.get("subdomains"), list):
        return None
    sink = HostnameSink(apex)
    for label in doc["subdomains"][:10000]:
        if not isinstance(label, str) or not label.strip():
            sink.rejected["invalid"] += 1
            continue
        lab = label.strip().lower().rstrip(".")
        sink.add(f"{lab}.{apex}", SOURCE)
    meta = doc.get("meta") if isinstance(doc.get("meta"), Mapping) else {}
    count = doc.get("subdomain_count")
    return {
        "names": sink.subdomains(),
        "wildcards": sink.wildcard_labels(),
        "rejected": sum(sink.rejected.values()) + len(sink.out_of_apex),
        "limit_reached": bool(meta.get("limit_reached")) if "limit_reached" in meta else None,
        "subdomain_count": count if isinstance(count, int) and not isinstance(count, bool) else None,
    }


def parse_history_a(doc: Any) -> dict[str, Any] | None:
    """/v1/history/{domain}/dns/a -> {records [{ip, first_seen, last_seen, organizations}], pages} or None.

    Every record keeps its first_seen/last_seen (cond 5); records are historical observations, never the
    current state."""
    if not isinstance(doc, Mapping) or not isinstance(doc.get("records"), list):
        return None
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None]] = set()
    for rec in doc["records"]:
        if not isinstance(rec, Mapping):
            continue
        orgs = [_text(o, 120) for o in rec.get("organizations") or [] if isinstance(o, str) and _text(o, 120)][:5] if isinstance(rec.get("organizations"), list) else []
        first, last = _date(rec.get("first_seen")), _date(rec.get("last_seen"))
        for ip in _values(rec, "ip"):
            addr = _ip(ip, 4)
            if addr is None or (addr, first) in seen:
                continue
            seen.add((addr, first))
            records.append({"ip": addr, "first_seen": first, "last_seen": last, "organizations": orgs})
    pages = doc.get("pages")
    return {"records": records, "pages": pages if isinstance(pages, int) and not isinstance(pages, bool) else None}


def origin_candidates(history: list[dict[str, Any]], current: list[str], is_cdn: Any) -> list[dict[str, Any]]:
    """Historical A addresses of a CDN-fronted domain that are not current and not CDN/shared ranges:
    origin-IP hypotheses (cond 5), unconfirmed. ``is_cdn(ip) -> bool`` comes from the core noise data."""
    cur = set(current)
    if not cur or not all(is_cdn(ip) for ip in cur):
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rec in sorted(history, key=lambda r: r.get("last_seen") or "", reverse=True):
        ip = rec["ip"]
        if ip in cur or ip in seen or is_cdn(ip) or not noise.is_public_ip(ip):
            continue
        seen.add(ip)
        out.append({"ip": ip, "first_seen": rec.get("first_seen"), "last_seen": rec.get("last_seen")})
    return out


def _is_cdn_ip(ip: str) -> bool:
    ent = Entity.try_make(T.IPV4, ip)
    try:
        return bool(ent is not None and noise.is_cdn(ent))
    except Exception:  # noqa: BLE001 - an unreadable noise list never makes an address CDN
        return False


@register
class SecurityTrails(Module):
    name = "securitytrails"
    title = "SecurityTrails DNS, subdomains and A-record history"
    description = (
        "SecurityTrails API (keyed): current DNS records, subdomains and the A-record history of a seed domain; "
        "historical addresses are never current infrastructure and origin-IP hypotheses stay unconfirmed."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN}
    produces = {T.DOMAIN, T.IPV4}
    run_on = "seeds"
    tags = {"free"}
    reference = "https://docs.securitytrails.com/reference"
    notice = (
        "SecurityTrails terms are 'key-terms': the free plan targets individuals, so under the corporate profile it runs "
        "only with a company/team key recorded as business (key_plans.securitytrails='business') or a recorded "
        "free_plan_business_use. The web UI is behind Cloudflare: manual links only."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "securitytrails"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,)
    max_requests = 3  # domain + subdomains + history page 1
    expected_latency = 1.5
    timeout = 45.0
    min_interval = 1.0
    cache_ttl = 604800  # cond 4: 7 days
    max_pivots = MAX_SUBDOMAIN_PIVOTS + MAX_HISTORY_PIVOTS + 10
    manual_link = "https://securitytrails.com/domain/{domain}/dns"
    default_enabled = True
    error_markers = (
        {"id": "securitytrails_quota", "statuses": [200, 403, 429], "json_path": "message",
         "regex": r"(?i)exceeded the usage limits|usage limit|quota|monthly (?:request )?limit",
         "maps_to": "quota", "reason_code": "quota", "reason": "SecurityTrails: plan usage limit exhausted (could not verify)"},
    )

    def _get(self, ctx: Any, url: str, key: str) -> Mapping[str, Any]:
        resp = ctx.http.get(url, headers={"APIKEY": key, "Accept": "application/json"}, allow_redirects=False, source=SOURCE)
        if resp.classification is None and resp.status == 404:
            try:
                doc = resp.json()
            except ValueError:
                doc = None
            message = _text(doc.get("message"), 200) if isinstance(doc, Mapping) else ""
            if NOT_FOUND_RE.search(message):
                raise _Absent(message)
        ctx.http.check(resp)  # markers (quota), challenges, 401/403 AuthRequired, 429 RateLimited, non-2xx
        if resp.truncated:
            raise _Unusable("SecurityTrails answer truncated at the size cap: not parsed (could not verify)")
        try:
            doc = resp.json()
        except ValueError:
            raise _Unusable("SecurityTrails answer is not JSON: could not verify") from None
        if not isinstance(doc, Mapping):
            raise _Unusable("SecurityTrails answer is not a JSON object: could not verify")
        return doc

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = ctx.key(KEY_NAME)
        if not key:
            return res.mark("needs_key", "needs the SecurityTrails API key (company/team account): v3lum keys setup", reason_code="needs_key")
        raw: dict[str, Any] = {}
        try:
            current = parse_domain(self._get(ctx, f"{BASE}/domain/{entity.value}", key))
        except AuthRequired as exc:
            return res.mark("needs_key", f"SecurityTrails rejected the API key (invalid key, HTTP {getattr(exc, 'status', '?')})", reason_code="needs_key")
        except _Absent:
            return res.mark("empty", "SecurityTrails has no record of this domain (404 not found)")
        except _Unusable as exc:
            return res.mark("error", _text(str(exc), 200))
        if current is None:
            return res.mark("error", "unexpected SecurityTrails /domain answer (no current_dns): could not verify")
        self._current(res, current)
        raw["current"] = current
        refused: list[str] = []
        for step in (self._subdomains, self._history):
            try:
                step(entity, ctx, res, key, current, raw)
            except AuthRequired as exc:  # the plan may not include an endpoint: keep what was collected
                refused.append(f"{step.__name__.strip('_')} (HTTP {getattr(exc, 'status', '?')})")
            except _Absent:
                continue
            except _Unusable as exc:
                res.raw = raw
                return res.mark("error", _text(str(exc), 200))
        res.raw = raw
        if refused:
            raw["refused"] = refused
            return res.mark("ok", "SecurityTrails refused " + ", ".join(refused) + " for this key: those parts could not be verified")
        return res

    @staticmethod
    def _current(res: ModuleResult, current: Mapping[str, Any]) -> None:
        res.attr("a_records", current["a"])
        res.attr("aaaa_records", current["aaaa"])
        res.attr("mx", current["mx"])
        res.attr("nameservers", current["ns"])
        res.attr("txt", current["txt"])
        res.attr("subdomain_count", current["subdomain_count"])

    def _subdomains(self, entity: Entity, ctx: Any, res: ModuleResult, key: str, current: Mapping[str, Any], raw: dict[str, Any]) -> None:
        domain = entity.value
        subs = parse_subdomains(self._get(ctx, f"{BASE}/domain/{domain}/subdomains?children_only=false", key), domain)
        if subs is None:
            raise _Unusable("unexpected SecurityTrails /subdomains answer (no subdomains list): could not verify")
        raw["subdomains"] = {**{k: v for k, v in subs.items() if k != "names"}, "names": subs["names"][:MAX_SUBDOMAINS]}
        res.attr("subdomains", subs["names"][:MAX_SUBDOMAINS])
        for name in subs["names"][:MAX_SUBDOMAIN_PIVOTS]:
            res.pivot(T.DOMAIN, name, "subdomain", confidence="probable", expand=False, note="subdomain known to SecurityTrails (may be historical)")

    def _history(self, entity: Entity, ctx: Any, res: ModuleResult, key: str, current: Mapping[str, Any], raw: dict[str, Any]) -> None:
        history = parse_history_a(self._get(ctx, f"{BASE}/history/{entity.value}/dns/a", key))
        if history is None:
            raise _Unusable("unexpected SecurityTrails /history/dns/a answer (no records list): could not verify")
        records = history["records"][:MAX_HISTORY]
        raw["history_a"] = {"records": records, "pages": history["pages"]}
        res.attr("dns_history_a", records)
        current_a = set(current["a"])
        pivoted = 0
        for rec in records:
            if pivoted >= MAX_HISTORY_PIVOTS:
                break
            if rec["ip"] in current_a or not noise.is_public_ip(rec["ip"]):
                continue
            if res.pivot(T.IPV4, rec["ip"], "historical_a_record", confidence="possible", expand=False,
                         note=f"historical A record {rec['first_seen'] or '?'} - {rec['last_seen'] or '?'}: not current infrastructure"):
                pivoted += 1
        candidates = origin_candidates(records, list(current["a"]), _is_cdn_ip)
        res.attr("origin_ip_candidates", candidates[:20])
        if candidates:
            shown = "; ".join(f"{c['ip']} ({c['first_seen'] or '?'} - {c['last_seen'] or '?'})" for c in candidates[:5])
            res.finding(
                "Origin-IP hypothesis from DNS history (unconfirmed)",
                "info",
                f"{entity.display} now resolves to CDN/shared addresses; earlier non-CDN A records may reveal the origin: {shown}. "
                "Historical records are not current infrastructure: confirm passively (the address presents the site's "
                "certificate or serves the site per a scan engine); Host-header checks are ACTIVE and need authorisation.",
                confidence="possible",
                tags=["cdn_origin_hypothesis", "historical"],
                data={"candidates": candidates[:20], "current_a": list(current["a"])},
                source=SOURCE,
                observed_first=min((c["first_seen"] for c in candidates if c["first_seen"]), default=None),
                observed_last=max((c["last_seen"] for c in candidates if c["last_seen"]), default=None),
            )
